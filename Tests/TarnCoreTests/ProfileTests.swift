import XCTest
@testable import TarnCore

final class ProfileTests: XCTestCase {

    // MARK: - Base Profile

    func testBaseProfileIncludesSystemPaths() {
        let base = BaseProfile()
        XCTAssertTrue(base.readonlyPaths.contains("/usr"))
        XCTAssertTrue(base.readonlyPaths.contains("/System"))
        XCTAssertTrue(base.readonlyPaths.contains("/opt/homebrew"))
    }

    func testBaseProfileDeniesCredentials() {
        let base = BaseProfile()
        XCTAssertTrue(base.deniedPaths.contains("~/.aws"))
        XCTAssertTrue(base.deniedPaths.contains("~/.gnupg"))
        XCTAssertTrue(base.deniedPaths.contains { $0.hasPrefix("~/.ssh/id_") })
    }

    // MARK: - Agent Profiles

    func testClaudeProfileAllowsAnthropicAPI() {
        let profile = ClaudeProfile()
        XCTAssertTrue(profile.allowedDomains.contains("api.anthropic.com"))
    }

    func testCodexProfileAllowsOpenAIAPI() {
        let profile = CodexProfile()
        XCTAssertTrue(profile.allowedDomains.contains("api.openai.com"))
    }

    func testAgentProfileFromName() {
        let claude = AgentProfile.from(name: "claude")
        if case .claude = claude {} else { XCTFail("Expected .claude") }

        let unknown = AgentProfile.from(name: "my-agent")
        if case .custom("my-agent") = unknown {} else { XCTFail("Expected .custom") }
    }

    func testAgentLaunchCommandIncludesYOLO() {
        let claude = AgentProfile.claude
        XCTAssertTrue(claude.launchCommand.contains("--dangerously-skip-permissions"))

        let codex = AgentProfile.codex
        XCTAssertTrue(codex.launchCommand.contains("--dangerously-bypass-approvals-and-sandbox"))
    }

    // MARK: - Stack Profiles

    func testNodeProfileIncludesNpmRegistry() {
        let profile = NodeProfile()
        XCTAssertTrue(profile.allowedDomains.contains("registry.npmjs.org"))
    }

    func testRustProfileIncludesCratesIO() {
        let profile = RustProfile()
        XCTAssertTrue(profile.allowedDomains.contains("crates.io"))
    }

    func testStackParse() {
        let stacks = StackProfile.parse("node,rust")
        XCTAssertEqual(stacks.count, 2)
        XCTAssertEqual(stacks[0].name, "stack-node")
        XCTAssertEqual(stacks[1].name, "stack-rust")
    }

    func testStackParseAliases() {
        let stacks = StackProfile.parse("js,py,golang,swift")
        XCTAssertEqual(stacks.count, 4)
        XCTAssertEqual(stacks[0].name, "stack-node")
        XCTAssertEqual(stacks[1].name, "stack-python")
        XCTAssertEqual(stacks[2].name, "stack-go")
        XCTAssertEqual(stacks[3].name, "stack-xcode")
    }

    func testStackParseIgnoresUnknown() {
        let stacks = StackProfile.parse("node,cobol,rust")
        XCTAssertEqual(stacks.count, 2)
    }

    // MARK: - Profile Resolution

    func testResolveLayersProfiles() {
        let userConfig = Config(readonlyPaths: [], readwritePaths: [], allowedDomains: [
            DomainEntry(domain: "custom.example.com", learned: true),
        ])

        let config = ProfileResolver.resolve(
            profiles: [BaseProfile(), NodeProfile(), ClaudeProfile()],
            userConfig: userConfig
        )

        // Base paths present
        XCTAssertTrue(config.readonlyPaths.contains(where: { $0.path == "/usr" }))
        // Node paths present
        XCTAssertTrue(config.readonlyPaths.contains(where: { $0.path == "~/.npmrc" }))
        // Claude domains present
        XCTAssertTrue(config.allowedDomains.contains(where: { $0.domain == "api.anthropic.com" }))
        // Node domains present
        XCTAssertTrue(config.allowedDomains.contains(where: { $0.domain == "registry.npmjs.org" }))
        // User config present
        XCTAssertTrue(config.allowedDomains.contains(where: { $0.domain == "custom.example.com" }))
        // Denied paths from base
        XCTAssertTrue(config.deniedPaths.contains("~/.aws"))
    }

    func testResolveDeduplicated() {
        let userConfig = Config(readonlyPaths: [
            MountEntry(path: "/usr", mode: .readonly, learned: false),
        ], readwritePaths: [], allowedDomains: [])

        let config = ProfileResolver.resolve(
            profiles: [BaseProfile()],
            userConfig: userConfig
        )

        let usrCount = config.readonlyPaths.filter { $0.path == "/usr" }.count
        XCTAssertEqual(usrCount, 1)
    }

    func testDeniedPathBlocksAccess() {
        let userConfig = Config(readonlyPaths: [], readwritePaths: [], allowedDomains: [])
        var config = ProfileResolver.resolve(
            profiles: [BaseProfile()],
            userConfig: userConfig
        )

        let homeDir = NSHomeDirectory()
        let awsPath = "\(homeDir)/.aws/credentials"
        let req = AccessRequest(kind: .fileRead(path: awsPath), pid: 1, processPath: "/usr/bin/cat")
        XCTAssertEqual(config.check(request: req), .deny)
    }

    // MARK: - Stack Detection

    func testDetectNodeStack() {
        let tmpDir = NSTemporaryDirectory() + "tarn-test-\(UUID())"
        try? FileManager.default.createDirectory(atPath: tmpDir, withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: tmpDir + "/package.json", contents: "{}".data(using: .utf8))
        defer { try? FileManager.default.removeItem(atPath: tmpDir) }

        let detected = ProfileResolver.detectStack(repoPath: tmpDir)
        XCTAssertTrue(detected.contains(where: { $0.name == "stack-node" }))
    }

    func testDetectRustStack() {
        let tmpDir = NSTemporaryDirectory() + "tarn-test-\(UUID())"
        try? FileManager.default.createDirectory(atPath: tmpDir, withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: tmpDir + "/Cargo.toml", contents: nil)
        defer { try? FileManager.default.removeItem(atPath: tmpDir) }

        let detected = ProfileResolver.detectStack(repoPath: tmpDir)
        XCTAssertTrue(detected.contains(where: { $0.name == "stack-rust" }))
    }

    func testDetectMultipleStacks() {
        let tmpDir = NSTemporaryDirectory() + "tarn-test-\(UUID())"
        try? FileManager.default.createDirectory(atPath: tmpDir, withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: tmpDir + "/package.json", contents: "{}".data(using: .utf8))
        FileManager.default.createFile(atPath: tmpDir + "/pyproject.toml", contents: nil)
        defer { try? FileManager.default.removeItem(atPath: tmpDir) }

        let detected = ProfileResolver.detectStack(repoPath: tmpDir)
        XCTAssertEqual(detected.count, 2)
    }

    func testDetectEmptyRepo() {
        let tmpDir = NSTemporaryDirectory() + "tarn-test-\(UUID())"
        try? FileManager.default.createDirectory(atPath: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmpDir) }

        let detected = ProfileResolver.detectStack(repoPath: tmpDir)
        XCTAssertTrue(detected.isEmpty)
    }
}
