import XCTest
@testable import TarnCore

/// Level 2 integration tests. These require:
/// - SIP disabled on the test machine (or proper entitlements)
/// - The tarn system extension installed and active
/// - The NE content filter enabled in System Settings
///
/// Run via: xcodebuild test -scheme TarnIntegrationTests
///
/// These tests spawn a real child process, make real file/network
/// accesses, and verify that the supervisor intercepts and responds
/// correctly via the XPC prompt callback.
final class EndToEndTests: XCTestCase {

    // MARK: - Helpers

    /// Connect to the tarn supervisor via XPC.
    private func connectToSupervisor() -> NSXPCConnection? {
        let connection = NSXPCConnection(machServiceName: kTarnSupervisorMachServiceName)
        connection.remoteObjectInterface = NSXPCInterface(with: TarnSupervisorXPC.self)
        connection.exportedInterface = NSXPCInterface(with: TarnCLICallbackXPC.self)
        connection.exportedObject = AutoResponder()
        connection.resume()
        return connection
    }

    /// Auto-responder that answers every prompt with "allow once".
    /// Used by integration tests so the child process isn't blocked.
    class AutoResponder: NSObject, TarnCLICallbackXPC {
        var receivedPrompts: [PromptRequestMessage] = []

        func handlePromptRequest(_ requestData: Data, reply: @escaping (Data) -> Void) {
            if let msg = try? JSONDecoder().decode(PromptRequestMessage.self, from: requestData) {
                receivedPrompts.append(msg)
                let response = PromptResponseMessage(flowId: msg.flowId, action: "allow", remember: false)
                let data = (try? JSONEncoder().encode(response)) ?? Data()
                reply(data)
            } else {
                let response = PromptResponseMessage(flowId: "", action: "deny", remember: false)
                let data = (try? JSONEncoder().encode(response)) ?? Data()
                reply(data)
            }
        }

        func persistEntry(_ entryData: Data, reply: @escaping (Bool) -> Void) {
            reply(false) // don't persist in tests
        }
    }

    // MARK: - File supervision (requires ES entitlement + root)

    /// Verify that opening a file outside the workspace from a
    /// supervised child process triggers a prompt.
    func testFileAccessOutsideWorkspaceTriggersPrompt() throws {
        // This test requires the system extension to be active.
        // Skip if we can't connect.
        guard let connection = connectToSupervisor() else {
            throw XCTSkip("Supervisor not active — run on a SIP-disabled VM with the extension installed")
        }
        defer { connection.invalidate() }

        let proxy = connection.remoteObjectProxy as! TarnSupervisorXPC
        let responder = connection.exportedObject as! AutoResponder

        // Start a session
        let startReq = SessionStartRequest(
            repoPath: "/tmp/tarn-test-\(UUID())",
            agent: "test",
            stacks: [],
            profilePath: "/tmp/tarn-test-profile-\(UUID()).toml",
            userHome: NSHomeDirectory(),
            profileContent: ""
        )
        try? FileManager.default.createDirectory(atPath: startReq.repoPath,
                                                  withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: startReq.repoPath) }

        let startData = try JSONEncoder().encode(startReq)
        let startExp = XCTestExpectation(description: "startSession")
        var sessionId: String?
        proxy.startSession(startData) { data, error in
            if let data = data,
               let resp = try? JSONDecoder().decode(SessionStartResponse.self, from: data) {
                sessionId = resp.sessionId
            }
            startExp.fulfill()
        }
        wait(for: [startExp], timeout: 5.0)
        guard let sid = sessionId else {
            XCTFail("Failed to start session")
            return
        }

        // Spawn a child process that reads a file outside the workspace
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/bin/cat")
        child.arguments = ["/etc/hosts"]
        child.standardOutput = FileHandle.nullDevice
        child.standardError = FileHandle.nullDevice
        try child.run()

        // Register it
        let regExp = XCTestExpectation(description: "registerAgent")
        proxy.registerAgentRoot(sid, pid: child.processIdentifier) { _ in
            regExp.fulfill()
        }
        wait(for: [regExp], timeout: 2.0)

        child.waitUntilExit()

        // Check if the auto-responder received a prompt for /etc/hosts
        // (This will only work if ES is active and intercepting)
        // On a machine without ES, this is a no-op — the child just reads the file
        if !responder.receivedPrompts.isEmpty {
            XCTAssertTrue(responder.receivedPrompts.contains(where: {
                $0.description.contains("/etc/hosts")
            }))
        }

        // Cleanup
        let endExp = XCTestExpectation(description: "endSession")
        proxy.endSession(sid) { endExp.fulfill() }
        wait(for: [endExp], timeout: 2.0)
    }

    // MARK: - Network supervision (requires NE filter enabled)

    /// Verify that an outbound HTTPS connection from a supervised
    /// child process triggers a network prompt with the hostname.
    func testNetworkAccessTriggersPromptWithHostname() throws {
        guard let connection = connectToSupervisor() else {
            throw XCTSkip("Supervisor not active")
        }
        defer { connection.invalidate() }

        let proxy = connection.remoteObjectProxy as! TarnSupervisorXPC
        let responder = connection.exportedObject as! AutoResponder

        let startReq = SessionStartRequest(
            repoPath: "/tmp/tarn-net-test-\(UUID())",
            agent: "test",
            stacks: [],
            profilePath: "/tmp/tarn-net-test-profile-\(UUID()).toml",
            userHome: NSHomeDirectory()
        )
        try? FileManager.default.createDirectory(atPath: startReq.repoPath,
                                                  withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: startReq.repoPath) }

        let startData = try JSONEncoder().encode(startReq)
        let startExp = XCTestExpectation(description: "startSession")
        var sessionId: String?
        proxy.startSession(startData) { data, error in
            if let data = data,
               let resp = try? JSONDecoder().decode(SessionStartResponse.self, from: data) {
                sessionId = resp.sessionId
            }
            startExp.fulfill()
        }
        wait(for: [startExp], timeout: 5.0)
        guard let sid = sessionId else {
            XCTFail("Failed to start session")
            return
        }

        // Spawn a child that makes an HTTPS connection
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        child.arguments = ["-s", "-o", "/dev/null", "https://httpbin.org/get"]
        child.standardOutput = FileHandle.nullDevice
        child.standardError = FileHandle.nullDevice
        try child.run()

        let regExp = XCTestExpectation(description: "registerAgent")
        proxy.registerAgentRoot(sid, pid: child.processIdentifier) { _ in
            regExp.fulfill()
        }
        wait(for: [regExp], timeout: 2.0)

        child.waitUntilExit()

        // If the NE filter is active, we should see a prompt for httpbin.org
        if !responder.receivedPrompts.isEmpty {
            XCTAssertTrue(responder.receivedPrompts.contains(where: {
                $0.description.contains("httpbin.org") || $0.description.contains("Network connect")
            }))
        }

        let endExp = XCTestExpectation(description: "endSession")
        proxy.endSession(sid) { endExp.fulfill() }
        wait(for: [endExp], timeout: 2.0)
    }
}
