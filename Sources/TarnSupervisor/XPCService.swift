import Foundation
import TarnCore

/// XPC service hosted by the supervisor system extension. Accepts
/// connections from the tarn CLI and handles session management.
/// Also supports bidirectional communication: the supervisor can
/// call back to the CLI for interactive prompts.
final class XPCService: NSObject, PromptService {
    static let shared = XPCService()

    private var listener: NSXPCListener?
    private var cliConnection: NSXPCConnection?
    public var currentProfilePath: String?

    private override init() {
        super.init()
    }

    func start() {
        listener = NSXPCListener(machServiceName: kTarnSupervisorMachServiceName)
        listener?.delegate = self
        listener?.resume()
        NSLog("tarn supervisor: XPC listener started on \(kTarnSupervisorMachServiceName)")
    }

    /// Send an asynchronous prompt request. Used by both ES (via
    /// es_retain_message + deferred response) and NE (via pauseVerdict
    /// + resumeFlow). Never blocks the caller.
    func asyncPrompt(_ message: PromptRequestMessage, reply: @escaping (PromptResponseMessage) -> Void) {
        guard let connection = cliConnection,
              let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
                  NSLog("tarn: XPC error during async prompt: \(error)")
                  reply(PromptResponseMessage(flowId: message.flowId, action: "deny", remember: false))
              }) as? TarnCLICallbackXPC else {
            reply(PromptResponseMessage(flowId: message.flowId, action: "deny", remember: false))
            return
        }

        let requestData = (try? JSONEncoder().encode(message)) ?? Data()
        proxy.handlePromptRequest(requestData) { responseData in
            let decoded = (try? JSONDecoder().decode(PromptResponseMessage.self, from: responseData))
                ?? PromptResponseMessage(flowId: message.flowId, action: "deny", remember: false)
            reply(decoded)
        }
    }
    /// Ask the CLI to persist a learned entry to the user's profile.
    /// The CLI does the actual file I/O as the user (INV-XPC-4).
    func asyncPersistEntry(request: AccessRequest, reply: @escaping (Bool) -> Void) {
        guard let connection = cliConnection,
              let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
                  NSLog("tarn: XPC error during persist: \(error)")
                  reply(false)
              }) as? TarnCLICallbackXPC else {
            reply(false)
            return
        }

        let mode: String
        let value: String
        switch request.kind {
        case .fileRead(let path):
            mode = "readonly"
            value = path
        case .fileWrite(let path):
            mode = "readwrite"
            value = path
        case .networkConnect(let domain):
            mode = "domain"
            value = domain
        }

        let persistReq = PersistEntryRequest(
            path: currentProfilePath ?? "",
            mode: mode,
            value: value
        )
        let data = (try? JSONEncoder().encode(persistReq)) ?? Data()
        proxy.persistEntry(data) { success in
            reply(success)
        }
    }
}

extension XPCService: NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        // Verify the connecting process is signed by the same team
        if !validateConnectionTeamID(connection) {
            NSLog("tarn supervisor: rejecting XPC connection — team ID mismatch")
            return false
        }

        // Set up bidirectional XPC
        connection.exportedInterface = NSXPCInterface(with: TarnSupervisorXPC.self)
        connection.exportedObject = self
        connection.remoteObjectInterface = NSXPCInterface(with: TarnCLICallbackXPC.self)

        connection.invalidationHandler = { [weak self] in
            self?.cliConnection = nil
            // Drain paused network flows so the agent doesn't hang (INV-XPC-2)
            NetworkFilter.current?.drainAllPausedFlows()
            DecisionEngine.shared.sessionCache.clear()
            NSLog("tarn supervisor: CLI disconnected; session state cleared")
        }

        connection.resume()
        cliConnection = connection
        NSLog("tarn supervisor: CLI connected")
        return true
    }

    /// Verify the connecting process is signed by the same team ID as
    /// the supervisor. Extracts the audit token from the connection,
    /// resolves via SecCode, and compares team identifiers.
    private func validateConnectionTeamID(_ connection: NSXPCConnection) -> Bool {
        // Get our own team ID
        var selfCode: SecCode?
        guard SecCodeCopySelf([], &selfCode) == errSecSuccess,
              let ownCode = selfCode else { return false }
        var selfInfo: CFDictionary?
        guard SecCodeCopySigningInformation(ownCode, [], &selfInfo) == errSecSuccess,
              let selfDict = selfInfo as? [String: Any],
              let selfTeam = selfDict[kSecCodeInfoTeamIdentifier as String] as? String else {
            // If we can't determine our own team ID (SIP-disabled dev),
            // allow all connections
            return true
        }

        // Get the peer's team ID via its audit token
        let peerToken = connection.auditToken
        let tokenData = withUnsafeBytes(of: peerToken) { Data($0) }
        let attrs: [String: Any] = [kSecGuestAttributeAudit as String: tokenData]
        var peerCode: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attrs as CFDictionary, [], &peerCode) == errSecSuccess,
              let peer = peerCode else { return false }
        var peerInfo: CFDictionary?
        guard SecCodeCopySigningInformation(peer, [], &peerInfo) == errSecSuccess,
              let peerDict = peerInfo as? [String: Any],
              let peerTeam = peerDict[kSecCodeInfoTeamIdentifier as String] as? String else {
            return false
        }

        return selfTeam == peerTeam
    }
}

extension XPCService: TarnSupervisorXPC {
    func startSession(_ configData: Data, reply: @escaping (Data?, NSError?) -> Void) {
        guard let request = try? JSONDecoder().decode(SessionStartRequest.self, from: configData) else {
            reply(nil, NSError(domain: "tarn", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid session request"]))
            return
        }

        do {
            // Parse profile from content sent by the CLI — the
            // supervisor never reads user files directly (INV-XPC-5).
            let userConfig = try Config.parse(toml: request.profileContent)
            let agentProfile = AgentProfile.from(name: request.agent)
            let stackProfiles: [StackProfile]
            if request.stacks.isEmpty {
                stackProfiles = ProfileResolver.detectStack(repoPath: request.repoPath)
            } else {
                stackProfiles = StackProfile.parse(request.stacks.joined(separator: ","))
            }

            var layers: [SecurityProfile] = [BaseProfile()]
            layers += stackProfiles.map { $0.profile }
            layers.append(agentProfile.profile)
            var config = ProfileResolver.resolve(profiles: layers, userConfig: userConfig)
            // Expand all tilde paths using the CLI user's home, not
            // root's home. Without this, the deny set is broken.
            config.expandAllPaths(userHome: request.userHome)

            DecisionEngine.shared.configure(config: config, repoPath: request.repoPath)
            currentProfilePath = request.profilePath

            let response = SessionStartResponse(
                sessionId: UUID().uuidString,
                stackNames: stackProfiles.map(\.name),
                allowCount: config.totalEntries,
                denyCount: config.deniedPaths.count
            )
            let data = try JSONEncoder().encode(response)
            reply(data, nil)
        } catch {
            reply(nil, error as NSError)
        }
    }

    func endSession(_ sessionId: String, reply: @escaping () -> Void) {
        NetworkFilter.current?.drainAllPausedFlows()
        DecisionEngine.shared.sessionCache.clear()
        DecisionEngine.shared.processTree.removeAll()
        reply()
    }

    func registerAgentRoot(_ sessionId: String, pid: Int32, reply: @escaping (NSError?) -> Void) {
        ESClient.shared.registerAgentPID(pid)
        reply(nil)
    }
}
