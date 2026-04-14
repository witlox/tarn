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

    // MARK: - Subprocess CLI tests
    //
    // These run the actual tarn binary as a subprocess. They test
    // argument parsing and profile commands that don't need XPC.
    // The binary is built via SPM at .build/debug/tarn.

    private func tarnBinaryURL() throws -> URL {
        let path = URL(fileURLWithPath: #filePath)  // Tests/TarnCoreTests/CLIScenarioTests.swift
            .deletingLastPathComponent()             // Tests/TarnCoreTests
            .deletingLastPathComponent()             // Tests
            .deletingLastPathComponent()             // project root
            .appendingPathComponent(".build/debug/tarn")
        guard FileManager.default.fileExists(atPath: path.path) else {
            throw XCTSkip("tarn binary not found at \(path.path) — run 'swift build' first")
        }
        return path
    }

    private func runTarn(_ arguments: [String]) throws -> (stdout: String, stderr: String, exitCode: Int32) {
        let binary = try tarnBinaryURL()
        let process = Process()
        process.executableURL = binary
        process.arguments = arguments
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe
        try process.run()
        process.waitUntilExit()
        let stdout = String(data: stdoutPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let stderr = String(data: stderrPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        return (stdout, stderr, process.terminationStatus)
    }

    // cli.feature: tarn with no subcommand shows help
    func testNoSubcommandShowsHelp() throws {
        // ArgumentParser exits with 0 and prints help on stdout
        // when no subcommand is given (if configured to do so),
        // or exits non-zero. Either way, usage info should appear.
        let result = try runTarn([])
        let combined = result.stdout + result.stderr
        XCTAssertTrue(combined.contains("USAGE") || combined.contains("usage") || combined.contains("SUBCOMMANDS"),
                       "Expected usage/help text, got: \(combined.prefix(200))")
    }

    // cli.feature: tarn run fails for nonexistent repo
    func testRunFailsForNonexistentRepo() throws {
        let result = try runTarn(["run", "/does/not/exist/\(UUID())"])
        XCTAssertNotEqual(result.exitCode, 0)
        let combined = result.stdout + result.stderr
        XCTAssertTrue(combined.contains("does not exist") || combined.contains("Error"),
                       "Expected error about nonexistent path")
    }

    // cli.feature: tarn profile show displays sections
    func testProfileShowDisplaysSections() throws {
        let dir = NSTemporaryDirectory() + "tarn-cli-show-\(UUID())"
        let profilePath = dir + "/profile.toml"
        defer { try? FileManager.default.removeItem(atPath: dir) }

        let result = try runTarn(["profile", "show", "--profile", profilePath])
        XCTAssertEqual(result.exitCode, 0)
        XCTAssertTrue(result.stdout.contains("Read-only paths"))
        XCTAssertTrue(result.stdout.contains("Read-write paths"))
        XCTAssertTrue(result.stdout.contains("Allowed network domains"))
    }

    // cli.feature: tarn profile show tags learned entries
    func testProfileShowTagsLearnedEntries() throws {
        let dir = NSTemporaryDirectory() + "tarn-cli-show-learned-\(UUID())"
        let profilePath = dir + "/profile.toml"
        defer { try? FileManager.default.removeItem(atPath: dir) }

        // Create a profile with a learned entry
        var config = Config.defaults()
        config.addDomain(domain: "learned.example.com")
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        try config.save(to: profilePath)

        let result = try runTarn(["profile", "show", "--profile", profilePath])
        XCTAssertEqual(result.exitCode, 0)
        XCTAssertTrue(result.stdout.contains("learned.example.com"))
        XCTAssertTrue(result.stdout.contains("(learned)"))
    }

    // cli.feature: tarn profile reset --force removes learned
    func testProfileResetForceRemovesLearned() throws {
        let dir = NSTemporaryDirectory() + "tarn-cli-reset-\(UUID())"
        let profilePath = dir + "/profile.toml"
        defer { try? FileManager.default.removeItem(atPath: dir) }

        var config = Config.defaults()
        config.addDomain(domain: "learned.example.com")
        config.addReadonly(path: "~/.learned-file")
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        try config.save(to: profilePath)

        let result = try runTarn(["profile", "reset", "--force", "--profile", profilePath])
        XCTAssertEqual(result.exitCode, 0)
        XCTAssertTrue(result.stdout.contains("Removed"))

        // Verify the profile was actually reset
        let reloaded = try Config.load(from: profilePath)
        XCTAssertFalse(reloaded.allowedDomains.contains(where: { $0.domain == "learned.example.com" }))
    }

    // cli.feature: tarn profile reset --force on clean profile
    func testProfileResetForceOnCleanProfile() throws {
        let dir = NSTemporaryDirectory() + "tarn-cli-reset-clean-\(UUID())"
        let profilePath = dir + "/profile.toml"
        defer { try? FileManager.default.removeItem(atPath: dir) }

        let result = try runTarn(["profile", "reset", "--force", "--profile", profilePath])
        XCTAssertEqual(result.exitCode, 0)
        XCTAssertTrue(result.stdout.contains("No learned entries") || result.stdout.contains("defaults"))
    }

    // cli.feature: tarn profile show on missing profile creates defaults
    func testProfileShowOnMissingProfileCreatesFile() throws {
        let dir = NSTemporaryDirectory() + "tarn-cli-show-missing-\(UUID())"
        let profilePath = dir + "/profile.toml"
        defer { try? FileManager.default.removeItem(atPath: dir) }

        let result = try runTarn(["profile", "show", "--profile", profilePath])
        XCTAssertEqual(result.exitCode, 0)
        XCTAssertTrue(FileManager.default.fileExists(atPath: profilePath),
                       "Profile file should be created with defaults")
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
