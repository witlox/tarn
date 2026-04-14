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

        // F9/F22: Always use the supervisor's stored profile path,
        // never accept a path from the request. This prevents the CLI
        // from being tricked into writing to an arbitrary file.
        guard let profilePath = currentProfilePath, !profilePath.isEmpty else {
            NSLog("tarn: persist rejected — no active profile path")
            reply(false)
            return
        }
        let persistReq = PersistEntryRequest(
            path: profilePath,
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
            self?.currentProfilePath = nil
            // Drain paused network flows so the agent doesn't hang (INV-XPC-2)
            NetworkFilter.current?.drainAllPausedFlows()
            // F5/F52: Full session teardown — clear cache, process tree,
            // and reset config to defaults so stale policy cannot persist.
            DecisionEngine.shared.sessionCache.clear()
            DecisionEngine.shared.processTree.removeAll()
            DecisionEngine.shared.configure(config: Config.defaults(), repoPath: "")
            NSLog("tarn supervisor: CLI disconnected; full session state reset")
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
        // Get our own team ID via SecStaticCode
        var selfCode: SecStaticCode?
        var dynamicCode: SecCode?
        guard SecCodeCopySelf([], &dynamicCode) == errSecSuccess,
              let dynCode = dynamicCode,
              SecCodeCopyStaticCode(dynCode, [], &selfCode) == errSecSuccess,
              let ownCode = selfCode else { return false }
        var selfInfo: CFDictionary?
        guard SecCodeCopySigningInformation(ownCode, SecCSFlags(rawValue: kSecCSSigningInformation), &selfInfo) == errSecSuccess,
              let selfDict = selfInfo as? [String: Any],
              let selfTeam = selfDict[kSecCodeInfoTeamIdentifier as String] as? String else {
            // Cannot determine our own team ID — deny by default.
            // On SIP-disabled dev machines, use `tarn --skip-team-check`
            // or sign the build with a team identity.
            NSLog("tarn supervisor: cannot determine own team ID; denying connection")
            return false
        }

        // Get the peer's team ID via its PID (auditToken is not
        // directly accessible; use processIdentifier instead)
        let peerPID = connection.processIdentifier
        var peerDynCode: SecCode?
        let pidAttrs: [String: Any] = [kSecGuestAttributePid as String: peerPID]
        guard SecCodeCopyGuestWithAttributes(nil, pidAttrs as CFDictionary, [], &peerDynCode) == errSecSuccess,
              let dynPeer = peerDynCode else { return false }
        var peerStaticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(dynPeer, [], &peerStaticCode) == errSecSuccess,
              let peer = peerStaticCode else { return false }
        var peerInfo: CFDictionary?
        guard SecCodeCopySigningInformation(peer, SecCSFlags(rawValue: kSecCSSigningInformation), &peerInfo) == errSecSuccess,
              let peerDict = peerInfo as? [String: Any] else {
            return false
        }

        guard let peerTeam = peerDict[kSecCodeInfoTeamIdentifier as String] as? String else {
            // Peer has no team ID (e.g., Apple-signed xctest).
            // Allow but log — the entitlement check on our side is
            // the primary security boundary, not the team ID match.
            NSLog("tarn supervisor: allowing connection from unsigned/Apple peer (PID %d)", peerPID)
            return true
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

        // F4/F27: Validate repoPath — must be absolute, not root, and
        // an existing directory.
        let fm = FileManager.default
        var isDir: ObjCBool = false
        guard request.repoPath.hasPrefix("/"),
              request.repoPath != "/",
              fm.fileExists(atPath: request.repoPath, isDirectory: &isDir),
              isDir.boolValue else {
            reply(nil, NSError(domain: "tarn", code: 4,
                               userInfo: [NSLocalizedDescriptionKey:
                                   "Invalid repoPath: must be an absolute path to an existing directory (not /)"]))
            return
        }

        // F4/F27: Validate userHome — must be absolute and under /Users/ or /var/root.
        guard request.userHome.hasPrefix("/Users/") || request.userHome == "/var/root" else {
            reply(nil, NSError(domain: "tarn", code: 4,
                               userInfo: [NSLocalizedDescriptionKey:
                                   "Invalid userHome: must start with /Users/ or be /var/root"]))
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
        // F3: Validate the PID actually exists before adding to the
        // process tree. kill(pid, 0) checks existence without sending
        // a signal.
        guard pid > 0, kill(pid, 0) == 0 else {
            let msg = "PID \(pid) does not exist or is invalid"
            NSLog("tarn supervisor: rejecting registerAgentRoot — %@", msg)
            reply(NSError(domain: "tarn", code: 3, userInfo: [NSLocalizedDescriptionKey: msg]))
            return
        }
        ESClient.shared.registerAgentPID(pid)
        reply(nil)
    }
}
