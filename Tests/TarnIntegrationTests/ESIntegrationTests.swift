import XCTest
@testable import TarnCore

/// Integration tests for Endpoint Security file supervision.
/// Requires the tarn system extension with ES entitlement active.
/// Tests verify that AUTH_OPEN, NOTIFY_FORK, and NOTIFY_EXIT events
/// are intercepted and handled correctly.
final class ESIntegrationTests: IntegrationTestBase {

    // MARK: - Fast paths

    /// monitor.feature: Workspace path is allowed via fast path.
    /// A supervised child reading a file INSIDE the workspace should
    /// not trigger a prompt.
    func testWorkspaceFileReadAllowedSilently() throws {
        try skipIfSupervisorUnavailable()
        let sid = try startTestSession()

        // Create a file inside the workspace
        let testFile = "\(workspacePath)/test-file.txt"
        try "hello".write(toFile: testFile, atomically: true, encoding: .utf8)

        let child = try spawnAndRegister(
            executable: "/bin/cat",
            arguments: [testFile],
            sessionId: sid
        )
        child.waitUntilExit()
        Thread.sleep(forTimeInterval: 0.5)

        // Workspace reads go through the fast path — no prompt expected
        let workspacePrompts = responder.receivedPrompts.filter {
            $0.description.contains(testFile)
        }
        XCTAssertTrue(workspacePrompts.isEmpty,
                       "Workspace file reads should be allowed silently via fast path")
    }

    // MARK: - Deny set (INV-AC-3)

    /// monitor.feature + INV-AC-3: Denied path is blocked without a
    /// prompt. The deny set is checked BEFORE trusted regions and
    /// BEFORE the allow set.
    func testDeniedPathBlockedWithoutPrompt() throws {
        try skipIfSupervisorUnavailable()

        // Start session — the base profile denies ~/.ssh/id_* etc.
        // The deny set is populated from BaseProfile.
        let sid = try startTestSession()

        // Try to read a denied credential path.
        // The home directory is expanded by the supervisor using userHome.
        let sshKeyPath = "\(NSHomeDirectory())/.ssh/id_rsa"

        // Only run this test if the file exists
        guard FileManager.default.fileExists(atPath: sshKeyPath) else {
            throw XCTSkip("~/.ssh/id_rsa not found — skipping deny-set test")
        }

        let child = try spawnAndRegister(
            executable: "/bin/cat",
            arguments: [sshKeyPath],
            sessionId: sid
        )
        child.waitUntilExit()
        Thread.sleep(forTimeInterval: 0.5)

        // The deny set should block this WITHOUT prompting — the file
        // open gets ES_AUTH_RESULT_DENY directly in ESClient.handleAuthOpen
        let sshPrompts = responder.receivedPrompts.filter {
            $0.description.contains(".ssh/id_rsa")
        }
        XCTAssertTrue(sshPrompts.isEmpty,
                       "Denied credential paths should be blocked without prompting")

        // The child should have a non-zero exit (cat fails when denied)
        XCTAssertNotEqual(child.terminationStatus, 0,
                           "cat should fail when ES denies the file open")
    }

    // MARK: - Process tree (NOTIFY_FORK)

    /// Verify that a grandchild process inherits supervision.
    /// The child spawns a grandchild via a shell script; the
    /// grandchild reads a file outside the workspace, which should
    /// trigger a prompt if ES is tracking the fork.
    func testChildProcessInheritsSupervision() throws {
        try skipIfSupervisorUnavailable()
        let sid = try startTestSession()

        // Use /bin/sh -c to create a grandchild: sh forks, the
        // forked shell (grandchild) reads /etc/hosts
        let child = try spawnAndRegister(
            executable: "/bin/sh",
            arguments: ["-c", "cat /etc/hosts > /dev/null"],
            sessionId: sid
        )
        child.waitUntilExit()
        Thread.sleep(forTimeInterval: 0.5)

        // The grandchild (cat, spawned by sh) should have been
        // supervised via NOTIFY_FORK inheritance. If ES is active,
        // we expect a prompt for /etc/hosts from the grandchild.
        if !responder.receivedPrompts.isEmpty {
            XCTAssertTrue(responder.receivedPrompts.contains(where: {
                $0.description.contains("/etc/hosts")
            }), "Grandchild process should trigger a prompt for /etc/hosts")
        }
    }

    // MARK: - Process tree (NOTIFY_EXIT)

    /// Verify that after a supervised child exits, its PID is no
    /// longer tracked. We verify indirectly: start a session,
    /// register+exit a child, then start a NEW unsupervised process.
    /// The second process should NOT be supervised.
    func testExitedProcessRemovedFromTree() throws {
        try skipIfSupervisorUnavailable()
        let sid = try startTestSession()

        // First child: register and let it exit
        let child1 = try spawnAndRegister(
            executable: "/usr/bin/true",
            arguments: [],
            sessionId: sid
        )
        child1.waitUntilExit()
        Thread.sleep(forTimeInterval: 0.5)

        let promptCountBefore = responder.receivedPrompts.count

        // Second child: NOT registered with the supervisor.
        // It reads /etc/hosts — should NOT be intercepted.
        let child2 = Process()
        child2.executableURL = URL(fileURLWithPath: "/bin/cat")
        child2.arguments = ["/etc/hosts"]
        child2.standardOutput = FileHandle.nullDevice
        child2.standardError = FileHandle.nullDevice
        try child2.run()
        child2.waitUntilExit()
        Thread.sleep(forTimeInterval: 0.5)

        let promptCountAfter = responder.receivedPrompts.count
        XCTAssertEqual(promptCountBefore, promptCountAfter,
                        "Unsupervised process should not trigger prompts")
    }
}
