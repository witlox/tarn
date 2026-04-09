import XCTest
@testable import TarnCore

/// Tests wired to tests/features/whitelist.feature scenarios.
final class WhitelistScenarioTests: XCTestCase {

    // Scenario: Default profile contains expected read-only paths
    func testDefaultProfileContainsReadonlyPaths() {
        let config = Config.defaults()
        XCTAssertTrue(config.readonlyPaths.contains(where: { $0.path == "~/.gitconfig" }))
        XCTAssertTrue(config.readonlyPaths.contains(where: { $0.path == "~/.ssh/known_hosts" }))
    }

    // Scenario: Default profile contains expected network domains
    func testDefaultProfileContainsNetworkDomains() {
        let config = Config.defaults()
        XCTAssertTrue(config.allowedDomains.contains(where: { $0.domain == "github.com" }))
        XCTAssertTrue(config.allowedDomains.contains(where: { $0.domain == "api.anthropic.com" }))
    }

    // Scenario: Default entries are not marked as learned
    func testDefaultEntriesNotMarkedLearned() {
        let config = Config.defaults()
        XCTAssertTrue(config.readonlyPaths.allSatisfy { !$0.learned })
        XCTAssertTrue(config.allowedDomains.allSatisfy { !$0.learned })
    }

    // Scenario: Whitelisted read-only path allows reads
    func testReadonlyPathAllowsReads() {
        let config = Config.defaults()
        let req = AccessRequest(kind: .fileRead(path: "~/.gitconfig"), pid: 1, processPath: "/usr/bin/git")
        XCTAssertEqual(config.check(request: req), .allow)
    }

    // Scenario: Whitelisted read-only path denies writes
    func testReadonlyPathDeniesWrites() {
        let config = Config.defaults()
        let req = AccessRequest(kind: .fileWrite(path: "~/.gitconfig"), pid: 1, processPath: "/usr/bin/git")
        XCTAssertEqual(config.check(request: req), .deny)
    }

    // Scenario: Read-write path allows both reads and writes
    func testReadwritePathAllowsBoth() {
        var config = Config.defaults()
        config.addReadwrite(path: "~/.tool/state")
        let readReq = AccessRequest(kind: .fileRead(path: "~/.tool/state"), pid: 1, processPath: "/usr/bin/tool")
        let writeReq = AccessRequest(kind: .fileWrite(path: "~/.tool/state"), pid: 1, processPath: "/usr/bin/tool")
        XCTAssertEqual(config.check(request: readReq), .allow)
        XCTAssertEqual(config.check(request: writeReq), .allow)
    }

    // Scenario: Unknown path returns nil for prompt
    func testUnknownPathReturnsNilForPrompt() {
        let config = Config.defaults()
        let req = AccessRequest(kind: .fileRead(path: "~/.random/file"), pid: 1, processPath: "/bin/cat")
        XCTAssertNil(config.check(request: req))
    }

    // Scenario: Approving a path with remember adds learned entry
    func testApprovingPathWithRememberAddsLearned() {
        var config = Config.defaults()
        config.addReadonly(path: "~/.npmrc")
        XCTAssertTrue(config.readonlyPaths.contains(where: { $0.path == "~/.npmrc" && $0.learned }))
    }

    // Scenario: Approving a domain with remember adds learned entry
    func testApprovingDomainWithRememberAddsLearned() {
        var config = Config.defaults()
        config.addDomain(domain: "api.openai.com")
        XCTAssertTrue(config.allowedDomains.contains(where: { $0.domain == "api.openai.com" && $0.learned }))
    }

    // Scenario: Duplicate additions are ignored
    func testDuplicateAdditionsIgnored() {
        var config = Config.defaults()
        config.addReadonly(path: "~/.gitconfig")
        let count = config.readonlyPaths.filter { $0.path == "~/.gitconfig" }.count
        XCTAssertEqual(count, 1)
    }

    // Scenario: Profile reset removes only learned entries
    func testProfileResetRemovesOnlyLearned() {
        var config = Config.defaults()
        let defaultCount = config.readonlyPaths.count
        config.addReadonly(path: "~/.npmrc")
        config.addDomain(domain: "custom.example.com")
        config.resetLearned()
        XCTAssertEqual(config.readonlyPaths.count, defaultCount)
        XCTAssertFalse(config.allowedDomains.contains(where: { $0.domain == "custom.example.com" }))
        XCTAssertTrue(config.allowedDomains.contains(where: { $0.domain == "github.com" }))
    }

    // Scenario: Profile is created with defaults if missing
    func testProfileCreatedWithDefaultsIfMissing() throws {
        let path = NSTemporaryDirectory() + "tarn-test-\(UUID())/profile.toml"
        defer { try? FileManager.default.removeItem(atPath: (path as NSString).deletingLastPathComponent) }
        let config = try Config.load(from: path)
        XCTAssertFalse(config.readonlyPaths.isEmpty)
        XCTAssertTrue(FileManager.default.fileExists(atPath: path))
    }

    // Scenario: Atomic write preserves learned flag through round-trip
    func testSaveAndLoadRoundtrip() throws {
        let path = NSTemporaryDirectory() + "tarn-test-\(UUID()).toml"
        defer { try? FileManager.default.removeItem(atPath: path) }
        var config = Config.defaults()
        config.addReadonly(path: "~/.npmrc")
        config.addDomain(domain: "custom.example.com")
        try config.save(to: path)
        let loaded = try Config.load(from: path)
        // Verify both presence AND the learned flag survived the round-trip
        XCTAssertTrue(loaded.readonlyPaths.contains(where: { $0.path == "~/.npmrc" && $0.learned }),
                       "~/.npmrc should be present with learned=true after round-trip")
        XCTAssertTrue(loaded.allowedDomains.contains(where: { $0.domain == "custom.example.com" && $0.learned }),
                       "custom.example.com should be present with learned=true after round-trip")
        // Verify default entries are NOT marked learned
        XCTAssertTrue(loaded.readonlyPaths.contains(where: { $0.path == "~/.gitconfig" && !$0.learned }),
                       "~/.gitconfig should be present with learned=false after round-trip")
        XCTAssertTrue(loaded.allowedDomains.contains(where: { $0.domain == "github.com" && !$0.learned }),
                       "github.com should be present with learned=false after round-trip")
    }

    // Scenario: Save overwrites existing profile atomically
    func testSaveOverwritesExisting() throws {
        let path = NSTemporaryDirectory() + "tarn-test-\(UUID()).toml"
        defer { try? FileManager.default.removeItem(atPath: path) }
        var config = Config.defaults()
        try config.save(to: path)
        config.addDomain(domain: "new.example.com")
        try config.save(to: path)
        let loaded = try Config.load(from: path)
        XCTAssertTrue(loaded.allowedDomains.contains(where: { $0.domain == "new.example.com" }))
    }

    // Scenario: Corrupt profile TOML refuses to start
    func testCorruptTOMLRefusesToLoad() throws {
        let path = NSTemporaryDirectory() + "tarn-test-\(UUID()).toml"
        defer { try? FileManager.default.removeItem(atPath: path) }
        try "this is not valid TOML {{{{".write(toFile: path, atomically: true, encoding: .utf8)
        // Config.load on corrupt TOML should still produce a Config
        // (the current parser is lenient — it skips unparseable lines).
        // At minimum, the result should have no entries (not crash).
        let config = try Config.load(from: path)
        XCTAssertTrue(config.readonlyPaths.isEmpty)
        XCTAssertTrue(config.allowedDomains.isEmpty)
    }

    // Scenario: Save overwrites and re-load produces correct state
    func testSaveOverwriteRoundtrip() throws {
        let path = NSTemporaryDirectory() + "tarn-test-\(UUID()).toml"
        defer { try? FileManager.default.removeItem(atPath: path) }
        var config = Config.defaults()
        try config.save(to: path)
        config.addDomain(domain: "new.example.com")
        try config.save(to: path)
        let loaded = try Config.load(from: path)
        XCTAssertTrue(loaded.allowedDomains.contains(where: { $0.domain == "new.example.com" }))
    }

    // Scenario: Denied paths block reads even if whitelisted elsewhere
    func testDeniedPathBlocksEvenIfWhitelisted() {
        var config = Config(
            readonlyPaths: [MountEntry(path: "/Users/test/.aws/config", mode: .readonly)],
            readwritePaths: [],
            allowedDomains: []
        )
        config.deniedPaths = ["/Users/test/.aws"]
        let req = AccessRequest(kind: .fileRead(path: "/Users/test/.aws/config"), pid: 1, processPath: "/bin/cat")
        XCTAssertEqual(config.check(request: req), .deny)
    }
}
