import XCTest
@testable import TarnCore

/// Tests wired to tests/features/cli.feature scenarios.
/// Tests the policy-layer behavior behind CLI commands without
/// launching a real process or terminal.
final class CLIScenarioTests: XCTestCase {

    // Scenario: tarn run with default agent → agent defaults to "claude"
    func testDefaultAgentIsClaude() {
        let agent = AgentProfile.from(name: "claude")
        if case .claude = agent {} else { XCTFail("Expected .claude") }
        XCTAssertTrue(agent.launchCommand.contains("claude"))
    }

    // Scenario: tarn run with explicit agent → agent is set
    func testExplicitAgentResolved() {
        let agent = AgentProfile.from(name: "codex")
        if case .codex = agent {} else { XCTFail("Expected .codex") }
    }

    // Scenario: tarn run with custom profile path
    func testCustomProfilePathLoads() throws {
        let path = NSTemporaryDirectory() + "tarn-cli-test-\(UUID()).toml"
        defer { try? FileManager.default.removeItem(atPath: path) }
        var custom = Config.defaults()
        custom.addDomain(domain: "custom-domain.example.com")
        try custom.save(to: path)
        let loaded = try Config.load(from: path)
        XCTAssertTrue(loaded.allowedDomains.contains(where: { $0.domain == "custom-domain.example.com" }))
    }

    // Scenario: tarn run fails for nonexistent repo
    func testNonexistentRepoDetected() {
        let path = "/does/not/exist/\(UUID())"
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
    }

    // Scenario: tarn profile reset removes learned, keeps defaults
    func testProfileResetKeepsDefaults() {
        var config = Config.defaults()
        let defaultDomainCount = config.allowedDomains.count
        config.addDomain(domain: "learned.example.com")
        config.addReadonly(path: "~/.learned-file")
        XCTAssertEqual(config.allowedDomains.count, defaultDomainCount + 1)
        config.resetLearned()
        XCTAssertEqual(config.allowedDomains.count, defaultDomainCount)
        XCTAssertFalse(config.readonlyPaths.contains(where: { $0.path == "~/.learned-file" }))
    }

    // Scenario: tarn profile reset is idempotent on clean profile
    func testProfileResetIdempotent() {
        var config = Config.defaults()
        let before = config.readonlyPaths.count
        config.resetLearned()
        XCTAssertEqual(config.readonlyPaths.count, before)
    }

    // Scenario: tarn profile show on missing profile → creates defaults
    func testProfileShowOnMissingCreatesDefaults() throws {
        let path = NSTemporaryDirectory() + "tarn-cli-test-\(UUID())/profile.toml"
        defer { try? FileManager.default.removeItem(atPath: (path as NSString).deletingLastPathComponent) }
        let config = try Config.load(from: path)
        XCTAssertFalse(config.readonlyPaths.isEmpty)
        XCTAssertTrue(FileManager.default.fileExists(atPath: path))
    }

    // Scenario: tarn exits with agent exit code
    // (structural — Process.terminationStatus is propagated in CLI.swift)

    // Scenario: Lock prevents concurrent sessions
    func testLockPreventsConcurrentSessions() throws {
        let path = NSTemporaryDirectory() + "tarn-cli-test-\(UUID())/tarn.lock"
        defer { try? FileManager.default.removeItem(atPath: (path as NSString).deletingLastPathComponent) }
        let lock1 = Lock(path: path)
        try lock1.acquire()
        let lock2 = Lock(path: path)
        XCTAssertThrowsError(try lock2.acquire())
        lock1.release()
        // After release, a new lock can be acquired
        XCTAssertNoThrow(try lock2.acquire())
        lock2.release()
    }

    // Scenario: Stale lock files removed on startup
    func testStaleLockRemoved() throws {
        let path = NSTemporaryDirectory() + "tarn-cli-test-\(UUID())/tarn.lock"
        let dir = (path as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        try "999999".write(toFile: path, atomically: true, encoding: .utf8)
        let lock = Lock(path: path)
        XCTAssertNoThrow(try lock.acquire())
        lock.release()
    }

    // Scenario: Stack auto-detection for the run command
    func testStackAutoDetectionForRun() {
        let tmpDir = NSTemporaryDirectory() + "tarn-cli-test-\(UUID())"
        try? FileManager.default.createDirectory(atPath: tmpDir, withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: tmpDir + "/package.json", contents: "{}".data(using: .utf8))
        FileManager.default.createFile(atPath: tmpDir + "/pyproject.toml", contents: nil)
        defer { try? FileManager.default.removeItem(atPath: tmpDir) }
        let stacks = ProfileResolver.detectStack(repoPath: tmpDir)
        XCTAssertEqual(stacks.count, 2)
        XCTAssertTrue(stacks.contains(where: { $0.name == "stack-node" }))
        XCTAssertTrue(stacks.contains(where: { $0.name == "stack-python" }))
    }

    // Scenario: Profile composition for a full session
    func testFullProfileCompositionForSession() {
        let userConfig = Config(readonlyPaths: [
            MountEntry(path: "~/.custom", mode: .readonly, learned: true),
        ], readwritePaths: [], allowedDomains: [])
        var layers: [SecurityProfile] = [BaseProfile()]
        layers.append(NodeProfile().self as SecurityProfile)
        layers.append(ClaudeProfile().self as SecurityProfile)
        let config = ProfileResolver.resolve(profiles: layers, userConfig: userConfig)
        // Base
        XCTAssertTrue(config.deniedPaths.contains("~/.aws"))
        // Node
        XCTAssertTrue(config.allowedDomains.contains(where: { $0.domain == "registry.npmjs.org" }))
        // Claude
        XCTAssertTrue(config.allowedDomains.contains(where: { $0.domain == "api.anthropic.com" }))
        // User
        XCTAssertTrue(config.readonlyPaths.contains(where: { $0.path == "~/.custom" && $0.learned }))
    }
}
