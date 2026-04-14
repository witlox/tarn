import Foundation

/// Mach service name for the supervisor's XPC endpoint.
/// Must match the system extension's Info.plist.
/// Base mach service name without the team ID prefix.
/// The NE framework requires the team-prefixed variant
/// (e.g. "TEAMID.com.witlox.tarn.supervisor") which is
/// resolved at runtime via the provisioning profile.
public let kTarnSupervisorMachServiceBase = "com.witlox.tarn.supervisor"

/// Resolved mach service name with team ID prefix.
/// NE-managed system extensions register their mach service under
/// "TEAMID.bundleid". This property resolves the team ID at runtime:
/// 1. From NEMachServiceName in the current bundle's Info.plist (supervisor)
/// 2. From the running process's code signature (signed CLI)
/// 3. From the Tarn.app bundle's provisioning profile (tests, unsigned CLI)
/// 4. Falls back to base name (unit tests without signing)
public var kTarnSupervisorMachServiceName: String {
    // Path 1: supervisor reads its own Info.plist
    if let name = Bundle.main.object(forInfoDictionaryKey: "NEMachServiceName") as? String,
       !name.isEmpty {
        return name
    }

    // Path 2: signed binary reads its own team ID
    if let team = ownTeamIdentifier() {
        return "\(team).\(kTarnSupervisorMachServiceBase)"
    }

    // Path 3: find Tarn.app in /Applications and read its profile
    if let team = teamFromInstalledApp() {
        return "\(team).\(kTarnSupervisorMachServiceBase)"
    }

    return kTarnSupervisorMachServiceBase
}

private func ownTeamIdentifier() -> String? {
    var code: SecCode?
    guard SecCodeCopySelf([], &code) == errSecSuccess, let code = code else { return nil }
    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let sc = staticCode else { return nil }
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(sc, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let dict = info as? [String: Any],
          let team = dict[kSecCodeInfoTeamIdentifier as String] as? String else { return nil }
    return team
}

private func teamFromInstalledApp() -> String? {
    let appPath = "/Applications/Tarn.app"
    guard FileManager.default.fileExists(atPath: appPath) else { return nil }
    var staticCode: SecStaticCode?
    let url = URL(fileURLWithPath: appPath) as CFURL
    guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess,
          let code = staticCode else { return nil }
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let dict = info as? [String: Any],
          let team = dict[kSecCodeInfoTeamIdentifier as String] as? String else { return nil }
    return team
}

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
