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
    fileprivate var neConnection: NSXPCConnection?
    public var currentProfilePath: String?

    private override init() {
        super.init()
    }

    /// F-02: Push a supervised audit token to the NE extension.
    func notifyNE(addToken tokenData: Data) {
        guard let proxy = neConnection?.remoteObjectProxy as? TarnNECallbackXPC else { return }
        proxy.addSupervisedToken(tokenData)
    }

    /// F-02: Remove a supervised audit token from the NE extension.
    func notifyNE(removeToken tokenData: Data) {
        guard let proxy = neConnection?.remoteObjectProxy as? TarnNECallbackXPC else { return }
        proxy.removeSupervisedToken(tokenData)
    }

    /// Clear all supervised tokens in the NE extension.
    func notifyNEClearAll() {
        guard let proxy = neConnection?.remoteObjectProxy as? TarnNECallbackXPC else { return }
        proxy.clearSupervisedTokens()
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

        // F-16: Determine connection type by code signing identifier, not UID.
        // The NE extension has bundle ID containing "com.witlox.tarn.supervisor".
        let isNEExtension = peerSigningIdentifier(connection)?.contains("com.witlox.tarn.supervisor") ?? false

        if isNEExtension {
            // NE extension: flow evaluation + token callbacks (bidirectional)
            connection.exportedInterface = NSXPCInterface(with: TarnNetworkEvalXPC.self)
            connection.exportedObject = service
            connection.remoteObjectInterface = NSXPCInterface(with: TarnNECallbackXPC.self)
            connection.invalidationHandler = { [weak service] in
                service?.neConnection = nil
                NSLog("tarn-es: NE extension disconnected")
            }
            connection.resume()
            service.neConnection = connection
            NSLog("tarn-es: NE extension connected (pid %d)", connection.processIdentifier)
        } else {
            // F-09: Reject if a CLI connection is already active.
            if service.cliConnection != nil {
                NSLog("tarn-es: rejecting second CLI connection (pid %d) — session already active", connection.processIdentifier)
                return false
            }
            // CLI: session management + bidirectional prompts
            connection.exportedInterface = NSXPCInterface(with: TarnSupervisorXPC.self)
            connection.exportedObject = service
            connection.remoteObjectInterface = NSXPCInterface(with: TarnCLICallbackXPC.self)
            connection.invalidationHandler = { [weak service] in
                guard let service = service else { return }
                if connection === service.cliConnection {
                    service.cliConnection = nil
                    service.currentProfilePath = nil
                    // F-11: Clear pending state on CLI disconnect.
                    ESClient.shared.clearPendingState()
                    DecisionEngine.shared.sessionCache.clear()
                    DecisionEngine.shared.processTree.removeAll()
                    DecisionEngine.shared.configure(config: Config.defaults(), repoPath: "")
                    ESXPCService.shared.notifyNEClearAll()
                    NSLog("tarn-es: CLI disconnected; full session state reset")
                }
            }
            connection.resume()
            service.cliConnection = connection
            NSLog("tarn-es: CLI connected (pid %d)", connection.processIdentifier)
        }

        return true
    }

    /// F-16: Extract the code signing identifier from a peer connection.
    private func peerSigningIdentifier(_ connection: NSXPCConnection) -> String? {
        let peerPID = connection.processIdentifier
        var peerDynCode: SecCode?
        let pidAttrs: [String: Any] = [kSecGuestAttributePid as String: peerPID]
        guard SecCodeCopyGuestWithAttributes(nil, pidAttrs as CFDictionary, [], &peerDynCode) == errSecSuccess,
              let dynPeer = peerDynCode else { return nil }
        var peerStaticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(dynPeer, [], &peerStaticCode) == errSecSuccess,
              let peer = peerStaticCode else { return nil }
        var peerInfo: CFDictionary?
        guard SecCodeCopySigningInformation(peer, SecCSFlags(rawValue: kSecCSSigningInformation), &peerInfo) == errSecSuccess,
              let peerDict = peerInfo as? [String: Any] else { return nil }
        return peerDict[kSecCodeInfoIdentifier as String] as? String
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
            // F-03: Reject connections from unsigned/Apple peers.
            // No legitimate reason for an unsigned process to connect.
            NSLog("tarn-es: rejecting connection from unsigned/Apple peer (PID %d)", peerPID)
            return false
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

        // F4/F27: Validate and canonicalize repoPath
        let fm = FileManager.default
        var isDir: ObjCBool = false
        // F-27: Canonicalize to resolve ".." components
        let canonicalRepoPath = URL(fileURLWithPath: request.repoPath).standardizedFileURL.path
        guard canonicalRepoPath.hasPrefix("/"),
              canonicalRepoPath != "/",
              fm.fileExists(atPath: canonicalRepoPath, isDirectory: &isDir),
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
                stackProfiles = ProfileResolver.detectStack(repoPath: canonicalRepoPath)
            } else {
                stackProfiles = StackProfile.parse(request.stacks.joined(separator: ","))
            }

            var layers: [SecurityProfile] = [BaseProfile()]
            layers += stackProfiles.map { $0.profile }
            layers.append(agentProfile.profile)
            var config = ProfileResolver.resolve(profiles: layers, userConfig: userConfig)
            config.expandAllPaths(userHome: request.userHome)

            let secProfile = agentProfile.profile
            let expandHome: (String) -> String = { path in
                path.hasPrefix("~/") ? request.userHome + path.dropFirst(1) : path
            }
            let agentReadPaths = secProfile.readonlyPaths.map(expandHome)
            let agentWritePaths = secProfile.readwritePaths.map(expandHome)
            DecisionEngine.shared.configure(config: config, repoPath: canonicalRepoPath, agentPaths: agentReadPaths, agentWritePaths: agentWritePaths)
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
        // F-11: Clear pending agent state to prevent stale entries.
        ESClient.shared.clearPendingState()
        // G2-06: Clear pendingPrompts to prevent cross-session cache leak.
        DecisionEngine.shared.configure(config: Config.defaults(), repoPath: "")
        ESXPCService.shared.notifyNEClearAll()
        currentProfilePath = nil
        reply()
    }

    func prepareAgentLaunch(_ sessionId: String, cliPID: Int32, reply: @escaping () -> Void) {
        ESClient.shared.watchForAgentFork(cliPID: cliPID)
        reply()
    }

    func confirmAgentPID(_ sessionId: String, pid: Int32, reply: @escaping (NSError?) -> Void) {
        guard pid > 0, kill(pid, 0) == 0 else {
            let msg = "PID \(pid) does not exist or is invalid"
            NSLog("tarn-es: rejecting confirmAgentPID — %@", msg)
            reply(NSError(domain: "tarn", code: 3, userInfo: [NSLocalizedDescriptionKey: msg]))
            return
        }
        ESClient.shared.confirmAgentPID(pid)
        reply(nil)
    }
}

// MARK: - Network Eval XPC Protocol (from NE extension)

extension ESXPCService: TarnNetworkEvalXPC {
    /// F-05: Heartbeat endpoint for NE extension health checking.
    func heartbeat(reply: @escaping (Bool) -> Void) {
        reply(true)
    }

    func evaluateFlow(_ requestData: Data, reply: @escaping (Data) -> Void) {
        guard let request = try? JSONDecoder().decode(NetworkFlowRequest.self, from: requestData) else {
            // I-01: Can't decode → deny. Only the NE extension sends these,
            // so a malformed request is suspicious. Fail-closed here is safe
            // because the NE extension's own error paths already fail-open.
            let deny = NetworkFlowResponse(action: "deny")
            reply((try? JSONEncoder().encode(deny)) ?? Data())
            return
        }

        let tree = DecisionEngine.shared.processTree
        let engine = DecisionEngine.shared

        // Not supervised → allow (not supervised)
        guard !tree.isEmpty, tree.isSupervised(pid: request.pid) else {
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
