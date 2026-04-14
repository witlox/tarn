import XCTest
@testable import TarnCore

// MARK: - Configurable AutoResponder

/// Auto-responder for XPC prompt callbacks in integration tests.
/// By default, allows all prompts. Can be configured with a custom
/// response policy and/or a delay (for testing timeouts like the
/// UDP 8-second watchdog).
class AutoResponder: NSObject, TarnCLICallbackXPC {
    var receivedPrompts: [PromptRequestMessage] = []
    var receivedPersists: [Data] = []

    /// Custom response policy. If nil, defaults to "allow once".
    var responsePolicy: ((PromptRequestMessage) -> PromptResponseMessage)?

    /// Delay before responding, in seconds. Used to test timeout
    /// behavior (e.g., UDP watchdog auto-deny after 8 seconds).
    var responseDelay: TimeInterval = 0

    func handlePromptRequest(_ requestData: Data, reply: @escaping (Data) -> Void) {
        if let msg = try? JSONDecoder().decode(PromptRequestMessage.self, from: requestData) {
            receivedPrompts.append(msg)

            let response: PromptResponseMessage
            if let policy = responsePolicy {
                response = policy(msg)
            } else {
                response = PromptResponseMessage(flowId: msg.flowId, action: "allow", remember: false)
            }

            if responseDelay > 0 {
                DispatchQueue.global().asyncAfter(deadline: .now() + responseDelay) {
                    let data = (try? JSONEncoder().encode(response)) ?? Data()
                    reply(data)
                }
            } else {
                let data = (try? JSONEncoder().encode(response)) ?? Data()
                reply(data)
            }
        } else {
            let response = PromptResponseMessage(flowId: "", action: "deny", remember: false)
            let data = (try? JSONEncoder().encode(response)) ?? Data()
            reply(data)
        }
    }

    func persistEntry(_ entryData: Data, reply: @escaping (Bool) -> Void) {
        receivedPersists.append(entryData)
        reply(false) // don't persist in tests
    }
}

// MARK: - Integration Test Base

/// Shared helpers for integration tests that connect to the running
/// tarn supervisor via XPC. All tests skip gracefully if the
/// supervisor is not active (e.g., in CI).
class IntegrationTestBase: XCTestCase {

    var connection: NSXPCConnection!
    var proxy: TarnSupervisorXPC!
    var responder: AutoResponder!
    var sessionId: String?
    private var tempDirs: [String] = []

    /// Resolve the mach service name for tests. The supervisor
    /// registers under the team-prefixed NEMachServiceName. Since
    /// xctest isn't signed with our team ID, the runtime resolution
    /// in kTarnSupervisorMachServiceName falls back to the
    /// un-prefixed name. We try the known team-prefixed variant.
    private func resolvedMachServiceName() -> String {
        // Try the runtime resolution first (works for signed CLI)
        let resolved = kTarnSupervisorMachServiceName
        if resolved != kTarnSupervisorMachServiceBase {
            return resolved
        }
        // Fall back to the build-time injected name if available
        if let envName = ProcessInfo.processInfo.environment["TARN_MACH_SERVICE"] {
            return envName
        }
        // Last resort: try to find a running tarn supervisor and
        // extract the team ID from its code signature
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        task.arguments = ["-f", "com.witlox.tarn.supervisor"]
        let pipe = Pipe()
        task.standardOutput = pipe
        try? task.run()
        task.waitUntilExit()
        let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if let pidStr = output?.components(separatedBy: "\n").first,
           let pid = Int32(pidStr) {
            // Read the team ID from the running supervisor binary
            let attrs: [String: Any] = [kSecGuestAttributePid as String: pid]
            var guestCode: SecCode?
            if SecCodeCopyGuestWithAttributes(nil, attrs as CFDictionary, [], &guestCode) == errSecSuccess,
               let code = guestCode {
                var staticCode: SecStaticCode?
                if SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
                   let sc = staticCode {
                    var info: CFDictionary?
                    if SecCodeCopySigningInformation(sc, [], &info) == errSecSuccess,
                       let dict = info as? [String: Any],
                       let team = dict[kSecCodeInfoTeamIdentifier as String] as? String {
                        return "\(team).\(kTarnSupervisorMachServiceBase)"
                    }
                }
            }
        }
        return resolved
    }

    /// Connect to the tarn supervisor and verify it's actually
    /// responding. Returns false if the supervisor is not running.
    func connectToSupervisor() -> Bool {
        let resolved = resolvedMachServiceName()
        return tryConnect(machServiceName: resolved)
    }

    private func tryConnect(machServiceName: String) -> Bool {
        NSLog("tarn-test: connecting to %@", machServiceName)
        let conn = NSXPCConnection(machServiceName: machServiceName)
        conn.remoteObjectInterface = NSXPCInterface(with: TarnSupervisorXPC.self)
        conn.exportedInterface = NSXPCInterface(with: TarnCLICallbackXPC.self)
        responder = AutoResponder()
        conn.exportedObject = responder

        var connectionValid = true
        conn.invalidationHandler = {
            NSLog("tarn-test: XPC connection invalidated")
            connectionValid = false
        }
        conn.interruptionHandler = {
            NSLog("tarn-test: XPC connection interrupted")
        }

        conn.resume()
        connection = conn

        // Use remoteObjectProxyWithErrorHandler so XPC errors surface
        proxy = conn.remoteObjectProxyWithErrorHandler { error in
            NSLog("tarn-test: XPC proxy error: \(error)")
            connectionValid = false
        } as? TarnSupervisorXPC

        guard proxy != nil else { return false }

        // Ping the supervisor with a lightweight call to verify it's
        // actually running. endSession with a bogus ID is a no-op.
        let pingExp = XCTestExpectation(description: "ping")
        var pingSucceeded = false
        proxy.endSession("ping-\(UUID())") {
            pingSucceeded = true
            pingExp.fulfill()
        }
        // Short timeout — if the supervisor isn't running, the
        // invalidation handler fires almost immediately.
        let result = XCTWaiter.wait(for: [pingExp], timeout: 3.0)
        return result == .completed && pingSucceeded && connectionValid
    }

    /// Skip the test if the supervisor isn't running.
    func skipIfSupervisorUnavailable() throws {
        guard connectToSupervisor() else {
            throw XCTSkip("Supervisor not active — install and activate the system extension first")
        }
    }

    /// Start a test session with a temporary workspace directory.
    func startTestSession(
        agent: String = "test",
        stacks: [String] = [],
        profileContent: String = ""
    ) throws -> String {
        let repoPath = "/tmp/tarn-test-\(UUID())"
        try FileManager.default.createDirectory(atPath: repoPath, withIntermediateDirectories: true)
        tempDirs.append(repoPath)

        let profilePath = "/tmp/tarn-test-profile-\(UUID()).toml"
        tempDirs.append(profilePath)

        let request = SessionStartRequest(
            repoPath: repoPath,
            agent: agent,
            stacks: stacks,
            profilePath: profilePath,
            userHome: NSHomeDirectory(),
            profileContent: profileContent
        )

        let requestData = try JSONEncoder().encode(request)
        let expectation = XCTestExpectation(description: "startSession")
        var sid: String?
        var sessionError: NSError?

        NSLog("tarn-test: calling startSession with repoPath=%@", repoPath)
        proxy.startSession(requestData) { data, error in
            NSLog("tarn-test: startSession replied, data=%d bytes, error=%@",
                  data?.count ?? 0, error?.localizedDescription ?? "nil")
            if let data = data,
               let resp = try? JSONDecoder().decode(SessionStartResponse.self, from: data) {
                sid = resp.sessionId
            }
            sessionError = error as NSError?
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 10.0)

        if let error = sessionError {
            throw error
        }
        guard let sessionId = sid else {
            XCTFail("Failed to start session")
            throw NSError(domain: "tarn.test", code: 1, userInfo: [NSLocalizedDescriptionKey: "No session ID"])
        }

        self.sessionId = sessionId
        return sessionId
    }

    /// End the current test session.
    func endTestSession() {
        guard let sid = sessionId else { return }
        let expectation = XCTestExpectation(description: "endSession")
        proxy.endSession(sid) { expectation.fulfill() }
        wait(for: [expectation], timeout: 2.0)
        sessionId = nil
    }

    /// Spawn a child process and register it with the supervisor.
    /// The process is started but NOT waited on — the caller controls
    /// when to call waitUntilExit().
    func spawnAndRegister(
        executable: String,
        arguments: [String] = [],
        sessionId: String? = nil
    ) throws -> Process {
        let sid = sessionId ?? self.sessionId!
        let child = Process()
        child.executableURL = URL(fileURLWithPath: executable)
        child.arguments = arguments
        child.standardOutput = FileHandle.nullDevice
        child.standardError = FileHandle.nullDevice
        try child.run()

        let regExp = XCTestExpectation(description: "registerAgent")
        proxy.registerAgentRoot(sid, pid: child.processIdentifier) { _ in
            regExp.fulfill()
        }
        wait(for: [regExp], timeout: 2.0)

        return child
    }

    /// The workspace path of the current session's temp directory.
    var workspacePath: String {
        tempDirs.first ?? "/tmp"
    }

    override func tearDown() {
        endTestSession()
        connection?.invalidate()
        connection = nil
        proxy = nil

        for dir in tempDirs {
            try? FileManager.default.removeItem(atPath: dir)
        }
        tempDirs.removeAll()

        // Brief pause to let the supervisor clean up between tests
        Thread.sleep(forTimeInterval: 0.3)
        super.tearDown()
    }
}
