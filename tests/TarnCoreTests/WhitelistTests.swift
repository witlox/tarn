import XCTest
@testable import TarnCore

final class WhitelistTests: XCTestCase {

    func testReadonlyPathAllowsRead() {
        let config = Config.defaults()
        let req = AccessRequest(kind: .fileRead(path: "~/.gitconfig"), pid: 1, processPath: "/usr/bin/git")
        XCTAssertEqual(config.check(request: req), .allow)
    }

    func testReadonlyPathDeniesWrite() {
        let config = Config.defaults()
        let req = AccessRequest(kind: .fileWrite(path: "~/.gitconfig"), pid: 1, processPath: "/usr/bin/git")
        XCTAssertEqual(config.check(request: req), .deny)
    }

    func testReadwritePathAllowsBoth() {
        var config = Config.defaults()
        config.addReadwrite(path: "~/.tool/state")
        let readReq = AccessRequest(kind: .fileRead(path: "~/.tool/state"), pid: 1, processPath: "/usr/bin/tool")
        let writeReq = AccessRequest(kind: .fileWrite(path: "~/.tool/state"), pid: 1, processPath: "/usr/bin/tool")
        XCTAssertEqual(config.check(request: readReq), .allow)
        XCTAssertEqual(config.check(request: writeReq), .allow)
    }

    func testUnknownPathReturnsNil() {
        let config = Config.defaults()
        let req = AccessRequest(kind: .fileRead(path: "~/.aws/credentials"), pid: 1, processPath: "/bin/cat")
        XCTAssertNil(config.check(request: req))
    }

    func testAllowedDomainPasses() {
        let config = Config.defaults()
        let req = AccessRequest(kind: .networkConnect(domain: "github.com"), pid: 1, processPath: "/usr/bin/git")
        XCTAssertEqual(config.check(request: req), .allow)
    }

    func testUnknownDomainReturnsNil() {
        let config = Config.defaults()
        let req = AccessRequest(kind: .networkConnect(domain: "evil.example.com"), pid: 1, processPath: "/usr/bin/curl")
        XCTAssertNil(config.check(request: req))
    }

    func testLearnedReadonlyThenCheckPasses() {
        var config = Config.defaults()
        config.addReadonly(path: "~/.npmrc")
        let req = AccessRequest(kind: .fileRead(path: "~/.npmrc"), pid: 1, processPath: "/usr/bin/node")
        XCTAssertEqual(config.check(request: req), .allow)
    }

    func testLearnedDomainThenCheckPasses() {
        var config = Config.defaults()
        config.addDomain(domain: "api.openai.com")
        let req = AccessRequest(kind: .networkConnect(domain: "api.openai.com"), pid: 1, processPath: "/usr/bin/curl")
        XCTAssertEqual(config.check(request: req), .allow)
    }

    func testResetPreservesDefaults() {
        var config = Config.defaults()
        let defaultDomains = config.allowedDomains.map { $0.domain }
        config.addDomain(domain: "learned.example.com")
        config.resetLearned()
        XCTAssertEqual(config.allowedDomains.map { $0.domain }, defaultDomains)
    }
}
