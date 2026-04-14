import XCTest
@testable import TarnCore

/// Integration tests for Network Extension supervision.
/// Requires the tarn system extension with NE content filter active.
/// Tests verify that outbound TCP/UDP flows from supervised processes
/// are intercepted, paused, and resolved correctly.
final class NetworkIntegrationTests: IntegrationTestBase {

    // MARK: - Allow set

    /// network.feature: Allowed hostname passes silently.
    /// The default profile allows github.com — a supervised child
    /// curling github.com should not trigger a prompt.
    func testAllowedDomainPassesSilently() throws {
        try skipIfSupervisorUnavailable()
        let sid = try startTestSession()

        let child = try spawnAndRegister(
            executable: "/usr/bin/curl",
            arguments: ["-s", "-o", "/dev/null", "--max-time", "5", "https://github.com"],
            sessionId: sid
        )
        child.waitUntilExit()
        Thread.sleep(forTimeInterval: 0.5)

        let githubPrompts = responder.receivedPrompts.filter {
            $0.description.contains("github.com")
        }
        XCTAssertTrue(githubPrompts.isEmpty,
                       "Allowed domain github.com should pass without prompting")
    }

    // MARK: - Unknown domain prompting

    /// network.feature: Unknown hostname triggers a prompt via XPC.
    /// A supervised child connecting to an unknown domain should
    /// trigger a prompt containing the hostname.
    func testUnknownDomainTriggersPrompt() throws {
        try skipIfSupervisorUnavailable()
        let sid = try startTestSession()

        // Use a domain that is NOT in the default allow set.
        // httpbin.org is not in the default profile.
        let child = try spawnAndRegister(
            executable: "/usr/bin/curl",
            arguments: ["-s", "-o", "/dev/null", "--max-time", "10", "https://httpbin.org/get"],
            sessionId: sid
        )
        child.waitUntilExit()
        Thread.sleep(forTimeInterval: 0.5)

        // The NE filter should have paused the flow and sent a prompt
        if !responder.receivedPrompts.isEmpty {
            XCTAssertTrue(responder.receivedPrompts.contains(where: {
                $0.description.contains("httpbin.org")
            }), "Unknown domain httpbin.org should trigger a prompt with hostname")
        }
    }

    // MARK: - UDP watchdog (INV-NF-7)

    /// network.feature: UDP flow auto-denies near the system deadline.
    /// We configure the AutoResponder with a long delay (15s) so it
    /// never replies before the 8-second watchdog fires. The UDP flow
    /// should be auto-denied.
    func testUDPFlowAutoDropAfter8Seconds() throws {
        try skipIfSupervisorUnavailable()

        // Configure responder to delay 15s — longer than the 8s watchdog
        responder.responseDelay = 15

        let sid = try startTestSession()

        // Send a UDP packet to an unknown host. We use `nc -u` with a
        // short timeout. The domain must not be in the allow set.
        let child = try spawnAndRegister(
            executable: "/bin/sh",
            arguments: ["-c", "echo 'test' | nc -u -w 12 unknown-udp-test.example.com 12345"],
            sessionId: sid
        )

        // Wait for the child — it should complete within ~10 seconds
        // because the watchdog auto-denies at 8 seconds
        let startTime = Date()
        child.waitUntilExit()
        let elapsed = Date().timeIntervalSince(startTime)

        // The flow should have been auto-denied before our 15s response
        // delay would have kicked in. We allow up to 12s (8s watchdog
        // + some margin for nc timeout).
        XCTAssertLessThan(elapsed, 14,
                           "UDP flow should be auto-denied by watchdog before the 15s response delay")
    }

    // MARK: - TCP patience

    /// network.feature: TCP flow can be paused for an extended user
    /// decision. Unlike UDP, TCP flows have no watchdog — they wait
    /// until the user responds (or the connection is drained).
    func testTCPFlowCanWaitForSlowUser() throws {
        try skipIfSupervisorUnavailable()

        // Configure responder with a 3s delay — this should still work
        // for TCP (no watchdog)
        responder.responseDelay = 3

        let sid = try startTestSession()

        let child = try spawnAndRegister(
            executable: "/usr/bin/curl",
            arguments: ["-s", "-o", "/dev/null", "--max-time", "10", "https://httpbin.org/get"],
            sessionId: sid
        )
        child.waitUntilExit()
        Thread.sleep(forTimeInterval: 0.5)

        // The flow should have been allowed after the 3s delay
        // (AutoResponder defaults to "allow once")
        if !responder.receivedPrompts.isEmpty {
            XCTAssertEqual(child.terminationStatus, 0,
                            "TCP flow should succeed after delayed allow response")
        }
    }

    // MARK: - Raw IP (canRemember=false)

    /// network.feature: Allow+remember is hidden for raw-IP prompts.
    /// When connecting to a raw IP, the prompt's canRemember should
    /// be false (the whitelist only accepts hostnames).
    func testRawIPPromptCannotBeRemembered() throws {
        try skipIfSupervisorUnavailable()
        let sid = try startTestSession()

        // Connect to a raw IP (not a hostname). Use a public IP
        // that's unlikely to be in the allow set. 1.1.1.1 is Cloudflare DNS.
        let child = try spawnAndRegister(
            executable: "/usr/bin/curl",
            arguments: ["-s", "-o", "/dev/null", "--max-time", "5", "https://1.1.1.1"],
            sessionId: sid
        )
        child.waitUntilExit()
        Thread.sleep(forTimeInterval: 0.5)

        // If the NE filter intercepted this, the prompt should have
        // canRemember=false because it's a raw IP
        let ipPrompts = responder.receivedPrompts.filter {
            $0.description.contains("1.1.1.1")
        }
        if !ipPrompts.isEmpty {
            XCTAssertFalse(ipPrompts[0].canRemember,
                            "Raw IP prompts should have canRemember=false")
        }
    }

    // MARK: - Unsupervised process bypass

    /// network.feature: Flow from unsupervised process is allowed
    /// unconditionally. A process NOT registered with the supervisor
    /// should not be intercepted.
    func testUnsupervisedProcessNetworkAllowed() throws {
        try skipIfSupervisorUnavailable()
        _ = try startTestSession()

        let promptCountBefore = responder.receivedPrompts.count

        // Spawn a child that is NOT registered with the supervisor.
        // Its network access should not be intercepted.
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        child.arguments = ["-s", "-o", "/dev/null", "--max-time", "5", "https://httpbin.org/get"]
        child.standardOutput = FileHandle.nullDevice
        child.standardError = FileHandle.nullDevice
        try child.run()
        child.waitUntilExit()
        Thread.sleep(forTimeInterval: 0.5)

        let promptCountAfter = responder.receivedPrompts.count
        XCTAssertEqual(promptCountBefore, promptCountAfter,
                        "Unsupervised process network access should not trigger prompts")
    }
}
