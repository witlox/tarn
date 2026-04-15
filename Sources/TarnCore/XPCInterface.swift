import Foundation

/// Mach service name for the supervisor's XPC endpoint.
/// Must match NEMachServiceName in TarnSupervisor-Info.plist.
/// The NE framework requires this to be prefixed by an app group
/// from the com.apple.security.application-groups entitlement.
/// Our app group is "group.com.witlox.tarn".
public let kTarnSupervisorMachServiceName = "group.com.witlox.tarn.supervisor"

// MARK: - XPC protocols

/// Commands sent from the CLI to the supervisor.
@objc public protocol TarnSupervisorXPC {
    func startSession(_ configData: Data, reply: @escaping (Data?, NSError?) -> Void)
    func endSession(_ sessionId: String, reply: @escaping () -> Void)
    func registerAgentRoot(_ sessionId: String, pid: Int32, reply: @escaping (NSError?) -> Void)
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
