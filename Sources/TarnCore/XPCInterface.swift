import Foundation

/// Mach service name for the supervisor's XPC endpoint (NE filter).
/// Must match NEMachServiceName in TarnSupervisor-Info.plist.
/// The NE framework requires this to be prefixed by an app group
/// from the com.apple.security.application-groups entitlement.
/// Our app group is "group.com.witlox.tarn".
public let kTarnSupervisorMachServiceName = "group.com.witlox.tarn.supervisor"

/// Mach service name for the ES extension's XPC endpoint.
/// launchd auto-registers ES system extensions under
/// "<TeamID>.<BundleID>.xpc". Resolved at runtime since
/// we don't hardcode the team ID.
public var kTarnESMachServiceName: String {
    // The ES extension reads its own team ID
    if let team = resolveTeamID() {
        return "\(team).com.witlox.tarn.es.xpc"
    }
    // Fallback: try the app group prefix (won't work for ES sysext,
    // but allows unit tests to run)
    return "group.com.witlox.tarn.es"
}

/// Same Mach service — both CLI and NE bridge use the same endpoint.
/// The ESXPCService distinguishes connections by their exported interface.
public var kTarnESBridgeMachServiceName: String { kTarnESMachServiceName }

/// Resolve the team identifier at runtime from the code signature
/// of the running process, or from the installed Tarn.app bundle.
private func resolveTeamID() -> String? {
    // Path 1: own code signature
    var code: SecCode?
    if SecCodeCopySelf([], &code) == errSecSuccess, let code = code {
        var staticCode: SecStaticCode?
        if SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let sc = staticCode {
            var info: CFDictionary?
            if SecCodeCopySigningInformation(sc, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
               let dict = info as? [String: Any],
               let team = dict[kSecCodeInfoTeamIdentifier as String] as? String {
                return team
            }
        }
    }
    // Path 2: Tarn.app in /Applications
    let appPath = "/Applications/Tarn.app"
    if FileManager.default.fileExists(atPath: appPath) {
        var staticCode: SecStaticCode?
        let url = URL(fileURLWithPath: appPath) as CFURL
        if SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess, let sc = staticCode {
            var info: CFDictionary?
            if SecCodeCopySigningInformation(sc, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
               let dict = info as? [String: Any],
               let team = dict[kSecCodeInfoTeamIdentifier as String] as? String {
                return team
            }
        }
    }
    return nil
}

// MARK: - XPC protocols

/// Commands sent from the CLI to the supervisor.
@objc public protocol TarnSupervisorXPC {
    func startSession(_ configData: Data, reply: @escaping (Data?, NSError?) -> Void)
    func endSession(_ sessionId: String, reply: @escaping () -> Void)
    /// Called BEFORE spawn: tells ES extension to watch for next fork from cliPID.
    func prepareAgentLaunch(_ sessionId: String, cliPID: Int32, reply: @escaping () -> Void)
    /// Called AFTER spawn: confirms the agent PID and adds to process tree.
    func confirmAgentPID(_ sessionId: String, pid: Int32, reply: @escaping (NSError?) -> Void)
}

/// Callbacks sent from the supervisor to the CLI (bidirectional XPC).
@objc public protocol TarnCLICallbackXPC {
    func handlePromptRequest(_ requestData: Data, reply: @escaping (Data) -> Void)
    func persistEntry(_ entryData: Data, reply: @escaping (Bool) -> Void)
}

/// Codable message for a persist-entry request.
public struct PersistEntryRequest: Codable {
    public let path: String
    public let mode: String   // "readonly", "readwrite", or "domain"
    public let value: String  // the path or domain string

    public init(path: String, mode: String, value: String) {
        self.path = path
        self.mode = mode
        self.value = value
    }
}

// MARK: - Codable messages (serialized to Data for XPC transport)

/// Request to start a supervised session.
public struct SessionStartRequest: Codable {
    public let repoPath: String
    public let agent: String
    public let stacks: [String]
    public let profilePath: String
    public let userHome: String
    /// The profile TOML content, loaded by the CLI as the user.
    /// The supervisor never reads user files directly (INV-XPC-5).
    public let profileContent: String

    public init(repoPath: String, agent: String, stacks: [String],
                profilePath: String, userHome: String, profileContent: String) {
        self.repoPath = repoPath
        self.agent = agent
        self.stacks = stacks
        self.profilePath = profilePath
        self.userHome = userHome
        self.profileContent = profileContent
    }
}

/// Response from a successful session start.
public struct SessionStartResponse: Codable {
    public let sessionId: String
    public let stackNames: [String]
    public let allowCount: Int
    public let denyCount: Int

    public init(sessionId: String, stackNames: [String], allowCount: Int, denyCount: Int) {
        self.sessionId = sessionId
        self.stackNames = stackNames
        self.allowCount = allowCount
        self.denyCount = denyCount
    }
}

/// A prompt request pushed from the supervisor to the CLI.
public struct PromptRequestMessage: Codable {
    public let sessionId: String
    public let flowId: String
    public let description: String
    public let processPath: String
    public let pid: Int32
    public let canRemember: Bool

    public init(sessionId: String, flowId: String, description: String,
                processPath: String, pid: Int32, canRemember: Bool) {
        self.sessionId = sessionId
        self.flowId = flowId
        self.description = description
        self.processPath = processPath
        self.pid = pid
        self.canRemember = canRemember
    }
}

/// The CLI's response to a prompt request.
public struct PromptResponseMessage: Codable {
    public let flowId: String
    public let action: String   // "allow" or "deny"
    public let remember: Bool

    public init(flowId: String, action: String, remember: Bool) {
        self.flowId = flowId
        self.action = action
        self.remember = remember
    }
}

// MARK: - Network evaluation XPC (NE extension ↔ ES extension)

/// Protocol for the NE extension to forward flow evaluations to the
/// ES extension, which hosts the DecisionEngine and ProcessTree.
@objc public protocol TarnNetworkEvalXPC {
    func evaluateFlow(_ requestData: Data, reply: @escaping (Data) -> Void)
    /// F-05: Heartbeat from NE extension to verify ES extension is alive.
    func heartbeat(reply: @escaping (Bool) -> Void)
}

/// Callback protocol: ES extension → NE extension.
/// Pushes supervised token changes so the NE filter only intercepts
/// flows from supervised processes (same pattern as ES inverted muting).
/// F-02: Uses audit token Data instead of bare PIDs to prevent PID reuse.
@objc public protocol TarnNECallbackXPC {
    func addSupervisedToken(_ tokenData: Data)
    func removeSupervisedToken(_ tokenData: Data)
    func clearSupervisedTokens()
}

/// Request sent from the NE extension to the ES extension for flow evaluation.
public struct NetworkFlowRequest: Codable {
    public let pid: Int32
    public let hostname: String
    public let isUDP: Bool
    /// F-02: Full audit token data for PID-reuse-safe comparison.
    public let tokenData: Data?

    public init(pid: Int32, hostname: String, isUDP: Bool, tokenData: Data? = nil) {
        self.pid = pid
        self.hostname = hostname
        self.isUDP = isUDP
        self.tokenData = tokenData
    }
}

/// Response from the ES extension back to the NE extension.
public struct NetworkFlowResponse: Codable {
    public let action: String  // "allow" or "deny"
    /// Whether this PID was supervised. The NE extension uses this to
    /// build a local cache of supervised PIDs for fast-path filtering.
    public let supervised: Bool

    public init(action: String, supervised: Bool = false) {
        self.action = action
        self.supervised = supervised
    }
}
