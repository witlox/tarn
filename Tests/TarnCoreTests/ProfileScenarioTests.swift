import XCTest
@testable import TarnCore

/// Tests wired to tests/features/profiles.feature scenarios.
final class ProfileScenarioTests: XCTestCase {

    // Scenario: Base profile provides system paths
    func testBaseProfileProvidesSystemPaths() {
        let base = BaseProfile()
        XCTAssertTrue(base.readonlyPaths.contains("/usr"))
        XCTAssertTrue(base.readonlyPaths.contains("/System"))
        XCTAssertTrue(base.readonlyPaths.contains("/opt/homebrew"))
    }

    // Scenario: Base profile denies credential paths
    func testBaseProfileDeniesCredentialPaths() {
        let base = BaseProfile()
        XCTAssertTrue(base.deniedPaths.contains("~/.aws"))
        XCTAssertTrue(base.deniedPaths.contains("~/.gnupg"))
        XCTAssertTrue(base.deniedPaths.contains(where: { $0.contains("~/.ssh/id_") }))
    }

    // Scenario: Denied paths block reads even if whitelisted elsewhere
    func testDeniedPathsBlockReadsEvenIfWhitelisted() {
        let userConfig = Config(
            readonlyPaths: [MountEntry(path: "/Users/test/.aws/config", mode: .readonly)],
            readwritePaths: [],
            allowedDomains: []
        )
        var config = ProfileResolver.resolve(profiles: [BaseProfile()], userConfig: userConfig)
        config.expandAllPaths(userHome: "/Users/test")
        let req = AccessRequest(kind: .fileRead(path: "/Users/test/.aws/config"), pid: 1, processPath: "/bin/cat")
        XCTAssertEqual(config.check(request: req), .deny)
    }

    // Scenario: Node stack is auto-detected from package.json
    func testNodeStackAutoDetected() {
        let tmpDir = NSTemporaryDirectory() + "tarn-test-\(UUID())"
        try? FileManager.default.createDirectory(atPath: tmpDir, withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: tmpDir + "/package.json", contents: "{}".data(using: .utf8))
        defer { try? FileManager.default.removeItem(atPath: tmpDir) }
        let detected = ProfileResolver.detectStack(repoPath: tmpDir)
        XCTAssertTrue(detected.contains(where: { $0.name == "stack-node" }))
    }

    // Scenario: Rust stack is auto-detected from Cargo.toml
    func testRustStackAutoDetected() {
        let tmpDir = NSTemporaryDirectory() + "tarn-test-\(UUID())"
        try? FileManager.default.createDirectory(atPath: tmpDir, withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: tmpDir + "/Cargo.toml", contents: nil)
        defer { try? FileManager.default.removeItem(atPath: tmpDir) }
        let detected = ProfileResolver.detectStack(repoPath: tmpDir)
        XCTAssertTrue(detected.contains(where: { $0.name == "stack-rust" }))
    }

    // Scenario: Multiple stacks detected simultaneously
    func testMultipleStacksDetected() {
        let tmpDir = NSTemporaryDirectory() + "tarn-test-\(UUID())"
        try? FileManager.default.createDirectory(atPath: tmpDir, withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: tmpDir + "/package.json", contents: "{}".data(using: .utf8))
        FileManager.default.createFile(atPath: tmpDir + "/pyproject.toml", contents: nil)
        defer { try? FileManager.default.removeItem(atPath: tmpDir) }
        let detected = ProfileResolver.detectStack(repoPath: tmpDir)
        XCTAssertEqual(detected.count, 2)
    }

    // Scenario: Explicit stack overrides auto-detection
    func testExplicitStackOverridesAutoDetection() {
        let stacks = StackProfile.parse("rust")
        XCTAssertEqual(stacks.count, 1)
        XCTAssertEqual(stacks[0].name, "stack-rust")
    }

    // Scenario: Stack aliases are recognized
    func testStackAliases() {
        let stacks = StackProfile.parse("js,py,golang,swift")
        XCTAssertEqual(stacks.count, 4)
        XCTAssertEqual(stacks[0].name, "stack-node")
        XCTAssertEqual(stacks[1].name, "stack-python")
        XCTAssertEqual(stacks[2].name, "stack-go")
        XCTAssertEqual(stacks[3].name, "stack-xcode")
    }

    // Scenario: Unknown stack names are ignored
    func testUnknownStackNamesIgnored() {
        let stacks = StackProfile.parse("node,cobol,rust")
        XCTAssertEqual(stacks.count, 2)
    }

    // Scenario: Claude agent profile includes Anthropic API
    func testClaudeProfileIncludesAnthropicAPI() {
        let profile = ClaudeProfile()
        XCTAssertTrue(profile.allowedDomains.contains("api.anthropic.com"))
        XCTAssertTrue(profile.readwritePaths.contains("~/.claude"))
    }

    // Scenario: Codex agent profile includes OpenAI API
    func testCodexProfileIncludesOpenAIAPI() {
        let profile = CodexProfile()
        XCTAssertTrue(profile.allowedDomains.contains("api.openai.com"))
    }

    // Scenario: Custom agent gets minimal profile
    func testCustomAgentGetsMinimalProfile() {
        let agent = AgentProfile.from(name: "my-custom-agent")
        if case .custom = agent {
            let profile = agent.profile
            XCTAssertEqual(profile.name, "agent-custom")
            XCTAssertTrue(profile.allowedDomains.isEmpty)
        } else {
            XCTFail("Expected .custom")
        }
    }

    // Scenario: User TOML entries layer on top of profiles
    func testUserTOMLLayersOnTop() {
        let userConfig = Config(readonlyPaths: [], readwritePaths: [], allowedDomains: [
            DomainEntry(domain: "custom.example.com", learned: true),
        ])
        let config = ProfileResolver.resolve(
            profiles: [BaseProfile(), NodeProfile()],
            userConfig: userConfig
        )
        XCTAssertTrue(config.allowedDomains.contains(where: { $0.domain == "registry.npmjs.org" }))
        XCTAssertTrue(config.allowedDomains.contains(where: { $0.domain == "custom.example.com" }))
    }

    // Scenario: Duplicate entries across layers are deduplicated
    func testDuplicateEntriesDeduplicated() {
        let userConfig = Config(readonlyPaths: [
            MountEntry(path: "/usr", mode: .readonly),
        ], readwritePaths: [], allowedDomains: [])
        let config = ProfileResolver.resolve(profiles: [BaseProfile()], userConfig: userConfig)
        let usrCount = config.readonlyPaths.filter { $0.path == "/usr" }.count
        XCTAssertEqual(usrCount, 1)
    }

    // Scenario: Agent launch command includes YOLO flags
    func testAgentLaunchCommandYOLO() {
        XCTAssertTrue(AgentProfile.claude.launchCommand.contains("--dangerously-skip-permissions"))
        XCTAssertTrue(AgentProfile.codex.launchCommand.contains("--dangerously-bypass-approvals-and-sandbox"))
    }

    // Scenario: Empty repo with no stack indicators
    func testEmptyRepoNoStacks() {
        let tmpDir = NSTemporaryDirectory() + "tarn-test-\(UUID())"
        try? FileManager.default.createDirectory(atPath: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmpDir) }
        let detected = ProfileResolver.detectStack(repoPath: tmpDir)
        XCTAssertTrue(detected.isEmpty)
    }
}
