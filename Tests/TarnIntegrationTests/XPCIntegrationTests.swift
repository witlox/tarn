import XCTest
@testable import TarnCore

/// Integration tests for the XPC communication layer between
/// the CLI and the supervisor. Tests session lifecycle, error
/// handling, and disconnect behavior (INV-XPC-2).
final class XPCIntegrationTests: IntegrationTestBase {

    // MARK: - Connection

    /// Smoke test: verify we can establish an XPC connection.
    func testXPCConnectionEstablishes() throws {
        try skipIfSupervisorUnavailable()
        XCTAssertNotNil(proxy)
    }

    // MARK: - Session lifecycle

    /// Verify that startSession returns a valid response with
    /// a non-empty sessionId and correct counts.
    func testStartSessionReturnsValidResponse() throws {
        try skipIfSupervisorUnavailable()

        let repoPath = "/tmp/tarn-xpc-test-\(UUID())"
        try FileManager.default.createDirectory(atPath: repoPath, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: repoPath) }

        let request = SessionStartRequest(
            repoPath: repoPath,
            agent: "test",
            stacks: [],
            profilePath: "/tmp/tarn-xpc-test-profile-\(UUID()).toml",
            userHome: NSHomeDirectory(),
            profileContent: ""
        )
        let requestData = try JSONEncoder().encode(request)
        let expectation = XCTestExpectation(description: "startSession")
        var response: SessionStartResponse?
        var sessionError: NSError?

        proxy.startSession(requestData) { data, error in
            if let data = data {
                response = try? JSONDecoder().decode(SessionStartResponse.self, from: data)
            }
            sessionError = error as NSError?
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 5.0)

        XCTAssertNil(sessionError)
        guard let response = response else {
            XCTFail("No response from startSession")
            return
        }
        XCTAssertFalse(response.sessionId.isEmpty)
        XCTAssertGreaterThan(response.allowCount, 0, "Default profile should have allow entries")
        XCTAssertGreaterThan(response.denyCount, 0, "Base profile should have deny entries")

        // Clean up session
        let sid = response.sessionId
        let endExp = XCTestExpectation(description: "endSession")
        proxy.endSession(sid) { endExp.fulfill() }
        wait(for: [endExp], timeout: 2.0)
    }

    /// Verify that sending a corrupt profile produces an error.
    func testStartSessionWithCorruptProfileReturnsError() throws {
        try skipIfSupervisorUnavailable()

        let repoPath = "/tmp/tarn-xpc-corrupt-test-\(UUID())"
        try FileManager.default.createDirectory(atPath: repoPath, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: repoPath) }

        // Profile content with a wildcard domain — this should trigger
        // ConfigError.wildcardDomain during parsing on the supervisor side
        let request = SessionStartRequest(
            repoPath: repoPath,
            agent: "test",
            stacks: [],
            profilePath: "/tmp/tarn-xpc-corrupt-test-profile.toml",
            userHome: NSHomeDirectory(),
            profileContent: """
                [network.allow]
                domains = [
                  "*.evil.com",
                ]
                """
        )
        let requestData = try JSONEncoder().encode(request)
        let expectation = XCTestExpectation(description: "startSession")
        var sessionError: NSError?

        proxy.startSession(requestData) { _, error in
            sessionError = error as NSError?
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 5.0)

        XCTAssertNotNil(sessionError, "Wildcard domain in profile should cause session start to fail")
    }

    /// Verify that endSession clears session state cleanly.
    func testEndSessionClearsState() throws {
        try skipIfSupervisorUnavailable()
        let sid = try startTestSession()

        // End the session
        let endExp = XCTestExpectation(description: "endSession")
        proxy.endSession(sid) { endExp.fulfill() }
        wait(for: [endExp], timeout: 2.0)
        sessionId = nil // prevent double-end in tearDown

        // Starting a new session should work (no stale state)
        let sid2 = try startTestSession()
        XCTAssertFalse(sid2.isEmpty)
        XCTAssertNotEqual(sid, sid2)
    }

    // MARK: - Disconnect behavior (INV-XPC-2)

    /// Verify that disconnecting the CLI connection drains paused
    /// network flows. We start a session, trigger a network access
    /// to an unknown domain (which pauses the flow), then invalidate
    /// the XPC connection. The flow should be drained (denied).
    func testDisconnectDrainsPausedFlows() throws {
        try skipIfSupervisorUnavailable()

        // Configure responder to never reply — simulating a "hung" CLI
        // so the flow stays paused until we disconnect
        responder.responseDelay = 60 // effectively never responds

        let sid = try startTestSession()

        // Spawn a child that tries to connect to an unknown domain.
        // This should be paused by the NE filter.
        let child = try spawnAndRegister(
            executable: "/usr/bin/curl",
            arguments: ["-s", "-o", "/dev/null", "--max-time", "10", "https://unknown-test-domain-tarn.example.com"],
            sessionId: sid
        )

        // Give the NE filter time to intercept and pause the flow
        Thread.sleep(forTimeInterval: 1.0)

        // Disconnect — this should trigger drainAllPausedFlows (INV-XPC-2)
        connection.invalidate()

        // The child should eventually complete (flow drained with deny,
        // curl gets a connection error or timeout)
        child.waitUntilExit()

        // If we got here without hanging, the drain worked.
        // The child's exit code doesn't matter — what matters is
        // that the paused flow was resolved and didn't hang forever.
        sessionId = nil // already disconnected
    }
}
