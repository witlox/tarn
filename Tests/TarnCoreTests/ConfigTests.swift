import XCTest
@testable import TarnCore

final class ConfigTests: XCTestCase {

    func testDefaultsContainExpectedPaths() {
        let config = Config.defaults()
        XCTAssertTrue(config.readonlyPaths.contains(where: { $0.path == "~/.gitconfig" }))
        XCTAssertTrue(config.readonlyPaths.contains(where: { $0.path == "~/.ssh/known_hosts" }))
        XCTAssertTrue(config.allowedDomains.contains(where: { $0.domain == "github.com" }))
    }

    func testDefaultsHaveNoLearnedEntries() {
        let config = Config.defaults()
        XCTAssertTrue(config.readonlyPaths.allSatisfy { !$0.learned })
        XCTAssertTrue(config.readwritePaths.allSatisfy { !$0.learned })
        XCTAssertTrue(config.allowedDomains.allSatisfy { !$0.learned })
    }

    func testCheckAllowsWhitelistedReadonlyPath() {
        let config = Config.defaults()
        let request = AccessRequest(kind: .fileRead(path: "~/.gitconfig"), pid: 1, processPath: "/usr/bin/git")
        XCTAssertEqual(config.check(request: request), .allow)
    }

    func testCheckDeniesWriteToReadonlyPath() {
        let config = Config.defaults()
        let request = AccessRequest(kind: .fileWrite(path: "~/.gitconfig"), pid: 1, processPath: "/usr/bin/git")
        XCTAssertEqual(config.check(request: request), .deny)
    }

    func testCheckReturnsNilForUnknownPath() {
        let config = Config.defaults()
        let request = AccessRequest(kind: .fileRead(path: "~/.aws/credentials"), pid: 1, processPath: "/bin/cat")
        XCTAssertNil(config.check(request: request))
    }

    func testCheckAllowsWhitelistedDomain() {
        let config = Config.defaults()
        let request = AccessRequest(kind: .networkConnect(domain: "github.com"), pid: 1, processPath: "/usr/bin/curl")
        XCTAssertEqual(config.check(request: request), .allow)
    }

    func testCheckReturnsNilForUnknownDomain() {
        let config = Config.defaults()
        let request = AccessRequest(kind: .networkConnect(domain: "evil.example.com"), pid: 1, processPath: "/usr/bin/curl")
        XCTAssertNil(config.check(request: request))
    }

    func testLearnFileReadAddsReadonly() {
        var config = Config.defaults()
        let request = AccessRequest(kind: .fileRead(path: "~/.npmrc"), pid: 1, processPath: "/usr/bin/node")
        config.learn(request: request)
        XCTAssertTrue(config.readonlyPaths.contains(where: { $0.path == "~/.npmrc" && $0.learned }))
    }

    func testLearnFileWriteAddsReadwrite() {
        var config = Config.defaults()
        let request = AccessRequest(kind: .fileWrite(path: "~/.local/share/tool"), pid: 1, processPath: "/usr/bin/tool")
        config.learn(request: request)
        XCTAssertTrue(config.readwritePaths.contains(where: { $0.path == "~/.local/share/tool" && $0.learned }))
    }

    func testLearnDomainAddsDomain() {
        var config = Config.defaults()
        let request = AccessRequest(kind: .networkConnect(domain: "api.openai.com"), pid: 1, processPath: "/usr/bin/curl")
        config.learn(request: request)
        XCTAssertTrue(config.allowedDomains.contains(where: { $0.domain == "api.openai.com" && $0.learned }))
    }

    func testLearnDuplicateIsIgnored() {
        var config = Config.defaults()
        let request = AccessRequest(kind: .networkConnect(domain: "github.com"), pid: 1, processPath: "/usr/bin/git")
        config.learn(request: request)
        let count = config.allowedDomains.filter { $0.domain == "github.com" }.count
        XCTAssertEqual(count, 1)
    }

    func testResetLearnedRemovesOnlyLearned() {
        var config = Config.defaults()
        let defaultCount = config.readonlyPaths.count
        config.addReadonly(path: "~/.npmrc")
        config.addDomain(domain: "custom.example.com")
        config.resetLearned()

        XCTAssertEqual(config.readonlyPaths.count, defaultCount)
        XCTAssertFalse(config.allowedDomains.contains(where: { $0.domain == "custom.example.com" }))
        XCTAssertTrue(config.allowedDomains.contains(where: { $0.domain == "github.com" }))
    }

    func testSaveAndLoadRoundtrip() throws {
        let tmpDir = NSTemporaryDirectory()
        let path = (tmpDir as NSString).appendingPathComponent("tarn-test-profile.toml")
        defer { try? FileManager.default.removeItem(atPath: path) }

        var original = Config.defaults()
        original.addReadonly(path: "~/.npmrc")
        original.addDomain(domain: "custom.example.com")
        try original.save(to: path)

        let loaded = try Config.load(from: path)
        XCTAssertTrue(loaded.readonlyPaths.contains(where: { $0.path == "~/.npmrc" }))
        XCTAssertTrue(loaded.allowedDomains.contains(where: { $0.domain == "custom.example.com" }))
    }

    func testLoadCreatesDefaultsIfMissing() throws {
        let tmpDir = NSTemporaryDirectory()
        let path = (tmpDir as NSString).appendingPathComponent("tarn-test-\(UUID())/profile.toml")
        defer {
            try? FileManager.default.removeItem(atPath: (path as NSString).deletingLastPathComponent)
        }

        let config = try Config.load(from: path)
        XCTAssertFalse(config.readonlyPaths.isEmpty)
        XCTAssertTrue(FileManager.default.fileExists(atPath: path))
    }

    func testTotalEntries() {
        let config = Config.defaults()
        XCTAssertEqual(config.totalEntries,
                       config.readonlyPaths.count + config.readwritePaths.count + config.allowedDomains.count)
    }
}
