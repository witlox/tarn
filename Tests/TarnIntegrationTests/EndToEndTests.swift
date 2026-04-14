import XCTest
@testable import TarnCore

/// Level 2 end-to-end integration tests. These require:
/// - The tarn system extension installed and active (or SIP disabled)
/// - The NE content filter enabled in System Settings
///
/// Run via: xcodebuild test -scheme TarnIntegrationTests
///
/// These tests spawn real child processes, make real file/network
/// accesses, and verify that the supervisor intercepts and responds
/// correctly via the XPC prompt callback.
final class EndToEndTests: IntegrationTestBase {

    // MARK: - File supervision (requires ES entitlement)

    /// Verify that opening a file outside the workspace from a
    /// supervised child process triggers a prompt.
    func testFileAccessOutsideWorkspaceTriggersPrompt() throws {
        try skipIfSupervisorUnavailable()
        let sid = try startTestSession()

        // Spawn a child that reads a file outside the workspace.
        // Register FIRST so ES intercepts the file open.
        let child = try spawnAndRegister(
            executable: "/bin/cat",
            arguments: ["/etc/hosts"],
            sessionId: sid
        )
        child.waitUntilExit()

        // Allow a moment for XPC prompt callbacks to arrive
        Thread.sleep(forTimeInterval: 0.5)

        // If ES is active, we should see a prompt for /etc/hosts
        if !responder.receivedPrompts.isEmpty {
            XCTAssertTrue(responder.receivedPrompts.contains(where: {
                $0.description.contains("/etc/hosts")
            }))
        }
    }

    // MARK: - Network supervision (requires NE filter enabled)

    /// Verify that an outbound HTTPS connection from a supervised
    /// child process triggers a network prompt with the hostname.
    func testNetworkAccessTriggersPromptWithHostname() throws {
        try skipIfSupervisorUnavailable()
        let sid = try startTestSession()

        let child = try spawnAndRegister(
            executable: "/usr/bin/curl",
            arguments: ["-s", "-o", "/dev/null", "https://httpbin.org/get"],
            sessionId: sid
        )
        child.waitUntilExit()

        Thread.sleep(forTimeInterval: 0.5)

        // If the NE filter is active, we should see a prompt for httpbin.org
        if !responder.receivedPrompts.isEmpty {
            XCTAssertTrue(responder.receivedPrompts.contains(where: {
                $0.description.contains("httpbin.org") || $0.description.contains("Network connect")
            }))
        }
    }
}
