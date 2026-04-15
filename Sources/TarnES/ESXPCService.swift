import Foundation
import TarnCore

/// XPC service hosted by the ES system extension. Accepts connections
/// from the tarn CLI (session management, prompts, persist) and from
/// the NE extension (network flow evaluation). Replaces the old
/// unified XPCService that lived in TarnSupervisor.
///
/// Uses two XPC listeners:
/// - `kTarnESMachServiceName` for CLI connections (bidirectional)
/// - `kTarnSupervisorMachServiceName` for NE extension connections
///   (the NE extension connects here to forward flow evaluations)
final class ESXPCService: NSObject, PromptService {
    static let shared = ESXPCService()

    private var listener: NSXPCListener?
    fileprivate var cliConnection: NSXPCConnection?
    public var currentProfilePath: String?

    private override init() {
        super.init()
    }

    func start() {
        let serviceName = kTarnESMachServiceName
        let delegate = UnifiedListenerDelegate(service: self)
        listener = NSXPCListener(machServiceName: serviceName)
        listener?.delegate = delegate
        objc_setAssociatedObject(listener!, "delegate", delegate, .OBJC_ASSOCIATION_RETAIN)
        listener?.resume()
        NSLog("tarn-es: XPC listener started on %@", serviceName)
    }

    /// Send an asynchronous prompt request. Used by both ES (via
    /// es_retain_message + deferred response) and NE proxy (via
    /// evaluateFlow). Never blocks the caller.
    func asyncPrompt(_ message: PromptRequestMessage, reply: @escaping (PromptResponseMessage) -> Void) {
        guard let connection = cliConnection,
              let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
                  NSLog("tarn-es: XPC error during async prompt: \(error)")
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
                  NSLog("tarn-es: XPC error during persist: \(error)")
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
        // never accept a path from the request.
        guard let profilePath = currentProfilePath, !profilePath.isEmpty else {
            NSLog("tarn-es: persist rejected — no active profile path")
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

// MARK: - Unified Listener Delegate

/// Accepts both CLI and NE extension connections on the same Mach service.
/// CLI connections get both TarnSupervisorXPC + TarnCLICallbackXPC interfaces.
/// NE connections get TarnNetworkEvalXPC only.
/// Distinguished by audit token: the NE extension runs as root with a
/// different bundle ID than the CLI.
private final class UnifiedListenerDelegate: NSObject, NSXPCListenerDelegate {
    weak var service: ESXPCService?

    init(service: ESXPCService) {
        self.service = service
        super.init()
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard let service = service else { return false }

        if !validateConnectionTeamID(connection) {
            NSLog("tarn-es: rejecting XPC connection — team ID mismatch (pid %d)", connection.processIdentifier)
            return false
        }

        // Determine connection type: the NE extension runs as root (uid 0),
        // the CLI runs as the user. Use this to distinguish.
        let isNEExtension = connection.effectiveUserIdentifier == 0
            && connection.processIdentifier != getpid()

        if isNEExtension {
            // NE extension: flow evaluation only
            connection.exportedInterface = NSXPCInterface(with: TarnNetworkEvalXPC.self)
            connection.exportedObject = service
            connection.invalidationHandler = {
                NSLog("tarn-es: NE extension disconnected")
            }
            connection.resume()
            NSLog("tarn-es: NE extension connected (pid %d)", connection.processIdentifier)
        } else {
            // CLI: session management + bidirectional prompts
            connection.exportedInterface = NSXPCInterface(with: TarnSupervisorXPC.self)
            connection.exportedObject = service
            connection.remoteObjectInterface = NSXPCInterface(with: TarnCLICallbackXPC.self)
            connection.invalidationHandler = { [weak service] in
                guard let service = service else { return }
                if connection === service.cliConnection {
                    service.cliConnection = nil
                    service.currentProfilePath = nil
                    DecisionEngine.shared.sessionCache.clear()
                    DecisionEngine.shared.processTree.removeAll()
                    DecisionEngine.shared.configure(config: Config.defaults(), repoPath: "")
                    NSLog("tarn-es: CLI disconnected; full session state reset")
                }
            }
            connection.resume()
            service.cliConnection = connection
            NSLog("tarn-es: CLI connected (pid %d)", connection.processIdentifier)
        }

        return true
    }
}

// MARK: - Shared team ID validation

extension NSXPCListenerDelegate {
    func validateConnectionTeamID(_ connection: NSXPCConnection) -> Bool {
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
            NSLog("tarn-es: cannot determine own team ID; denying connection")
            return false
        }

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
            NSLog("tarn-es: allowing connection from unsigned/Apple peer (PID %d)", peerPID)
            return true
        }

        return selfTeam == peerTeam
    }
}

// MARK: - CLI XPC Protocol (TarnSupervisorXPC)

extension ESXPCService: TarnSupervisorXPC {
    func startSession(_ configData: Data, reply: @escaping (Data?, NSError?) -> Void) {
        guard let request = try? JSONDecoder().decode(SessionStartRequest.self, from: configData) else {
            reply(nil, NSError(domain: "tarn", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid session request"]))
            return
        }

        // F4/F27: Validate repoPath
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

        // F4/F27: Validate userHome
        guard request.userHome.hasPrefix("/Users/") || request.userHome == "/var/root" else {
            reply(nil, NSError(domain: "tarn", code: 4,
                               userInfo: [NSLocalizedDescriptionKey:
                                   "Invalid userHome: must start with /Users/ or be /var/root"]))
            return
        }

        do {
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
            config.expandAllPaths(userHome: request.userHome)

            let secProfile = agentProfile.profile
            let agentPaths = (secProfile.readonlyPaths + secProfile.readwritePaths).map { path in
                path.hasPrefix("~/") ? request.userHome + path.dropFirst(1) : path
            }
            DecisionEngine.shared.configure(config: config, repoPath: request.repoPath, agentPaths: agentPaths)
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
        DecisionEngine.shared.sessionCache.clear()
        DecisionEngine.shared.processTree.removeAll()
        reply()
    }

    func registerAgentRoot(_ sessionId: String, pid: Int32, reply: @escaping (NSError?) -> Void) {
        guard pid > 0, kill(pid, 0) == 0 else {
            let msg = "PID \(pid) does not exist or is invalid"
            NSLog("tarn-es: rejecting registerAgentRoot — %@", msg)
            reply(NSError(domain: "tarn", code: 3, userInfo: [NSLocalizedDescriptionKey: msg]))
            return
        }
        ESClient.shared.registerAgentPID(pid)
        reply(nil)
    }
}

// MARK: - Network Eval XPC Protocol (from NE extension)

extension ESXPCService: TarnNetworkEvalXPC {
    func evaluateFlow(_ requestData: Data, reply: @escaping (Data) -> Void) {
        guard let request = try? JSONDecoder().decode(NetworkFlowRequest.self, from: requestData) else {
            // Can't decode → fail-open
            let allow = NetworkFlowResponse(action: "allow")
            reply((try? JSONEncoder().encode(allow)) ?? Data())
            return
        }

        let tree = DecisionEngine.shared.processTree
        let engine = DecisionEngine.shared

        // Not supervised → allow (not supervised)
        guard tree.count > 0, tree.isSupervised(pid: request.pid) else {
            let allow = NetworkFlowResponse(action: "allow", supervised: false)
            reply((try? JSONEncoder().encode(allow)) ?? Data())
            return
        }

        let processPath = "pid:\(request.pid)"
        let accessRequest = AccessRequest(
            kind: .networkConnect(domain: request.hostname),
            pid: request.pid,
            processPath: processPath
        )

        // Quick decision (deny set, allow set, session cache)
        if let quick = engine.quickDecide(request: accessRequest) {
            let response = NetworkFlowResponse(action: quick == .allow ? "allow" : "deny", supervised: true)
            reply((try? JSONEncoder().encode(response)) ?? Data())
            return
        }

        // Full async decision with prompt
        engine.asyncDecide(request: accessRequest) { action in
            let response = NetworkFlowResponse(action: action == .allow ? "allow" : "deny", supervised: true)
            reply((try? JSONEncoder().encode(response)) ?? Data())
        }
    }
}
