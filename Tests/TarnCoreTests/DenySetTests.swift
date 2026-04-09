import XCTest
@testable import TarnCore

/// Tests for the deny set logic: expandAllPaths, isDeniedExpanded,
/// isDeniedPath, deniedDomains, and the deny-before-allow invariant.
final class DenySetTests: XCTestCase {

    private let userHome = "/Users/testuser"

    // MARK: - expandAllPaths

    func testExpandAllPathsExpandsTildeInDeniedPaths() {
        var config = Config.defaults()
        config.deniedPaths = ["~/.aws", "~/.gnupg", "/etc/shadow"]
        config.expandAllPaths(userHome: userHome)
        XCTAssertTrue(config.deniedPaths.contains("/Users/testuser/.aws"))
        XCTAssertTrue(config.deniedPaths.contains("/Users/testuser/.gnupg"))
        XCTAssertTrue(config.deniedPaths.contains("/etc/shadow"))
    }

    func testExpandAllPathsExpandsTildeInReadonlyPaths() {
        var config = Config(
            readonlyPaths: [MountEntry(path: "~/.gitconfig", mode: .readonly)],
            readwritePaths: [],
            allowedDomains: []
        )
        config.expandAllPaths(userHome: userHome)
        XCTAssertEqual(config.readonlyPaths[0].path, "/Users/testuser/.gitconfig")
    }

    func testExpandAllPathsExpandsTildeInReadwritePaths() {
        var config = Config(
            readonlyPaths: [],
            readwritePaths: [MountEntry(path: "~/.cache/tool", mode: .readwrite)],
            allowedDomains: []
        )
        config.expandAllPaths(userHome: userHome)
        XCTAssertEqual(config.readwritePaths[0].path, "/Users/testuser/.cache/tool")
    }

    func testExpandAllPathsLeavesAbsolutePathsUnchanged() {
        var config = Config.defaults()
        config.deniedPaths = ["/etc/shadow"]
        config.expandAllPaths(userHome: userHome)
        XCTAssertTrue(config.deniedPaths.contains("/etc/shadow"))
    }

    func testExpandAllPathsExpandsGlobWithTilde() {
        var config = Config.defaults()
        config.deniedPaths = ["~/.ssh/id_*"]
        config.expandAllPaths(userHome: userHome)
        XCTAssertTrue(config.deniedPaths.contains("/Users/testuser/.ssh/id_*"))
    }

    // MARK: - isDeniedExpanded

    func testIsDeniedExpandedExactMatch() {
        var config = Config.defaults()
        config.deniedPaths = ["/Users/testuser/.aws"]
        XCTAssertTrue(config.isDeniedExpanded(path: "/Users/testuser/.aws"))
    }

    func testIsDeniedExpandedDirectoryPrefix() {
        var config = Config.defaults()
        config.deniedPaths = ["/Users/testuser/.aws"]
        XCTAssertTrue(config.isDeniedExpanded(path: "/Users/testuser/.aws/credentials"))
        XCTAssertTrue(config.isDeniedExpanded(path: "/Users/testuser/.aws/config"))
    }

    func testIsDeniedExpandedGlobSuffix() {
        var config = Config.defaults()
        config.deniedPaths = ["/Users/testuser/.ssh/id_*"]
        XCTAssertTrue(config.isDeniedExpanded(path: "/Users/testuser/.ssh/id_rsa"))
        XCTAssertTrue(config.isDeniedExpanded(path: "/Users/testuser/.ssh/id_ed25519"))
        XCTAssertFalse(config.isDeniedExpanded(path: "/Users/testuser/.ssh/known_hosts"))
    }

    func testIsDeniedExpandedNonMatchReturnsNil() {
        var config = Config.defaults()
        config.deniedPaths = ["/Users/testuser/.aws"]
        XCTAssertFalse(config.isDeniedExpanded(path: "/Users/testuser/.gitconfig"))
    }

    // MARK: - deniedDomains

    func testDeniedDomainBlocksNetworkConnect() {
        var config = Config.defaults()
        config.deniedDomains = ["evil.example.com"]
        let req = AccessRequest(kind: .networkConnect(domain: "evil.example.com"), pid: 1, processPath: "/usr/bin/curl")
        XCTAssertEqual(config.check(request: req), .deny)
    }

    func testDeniedDomainTakesPrecedenceOverAllowed() {
        var config = Config.defaults()
        config.deniedDomains = ["github.com"]
        // github.com is in allowedDomains by default, but deny wins
        let req = AccessRequest(kind: .networkConnect(domain: "github.com"), pid: 1, processPath: "/usr/bin/git")
        XCTAssertEqual(config.check(request: req), .deny)
    }

    func testNonDeniedDomainPassesThrough() {
        var config = Config.defaults()
        config.deniedDomains = ["evil.example.com"]
        let req = AccessRequest(kind: .networkConnect(domain: "github.com"), pid: 1, processPath: "/usr/bin/git")
        XCTAssertEqual(config.check(request: req), .allow)
    }

    // MARK: - Wildcard domain rejection (INV-NF-5)

    func testWildcardDomainRejectedByParser() {
        let toml = """
        [network.allow]
        domains = [
          "*.github.com",
        ]
        """
        XCTAssertThrowsError(try Config.parse(toml: toml)) { error in
            guard case ConfigError.wildcardDomain = error else {
                XCTFail("Expected wildcardDomain, got \(error)")
                return
            }
        }
    }

    func testExplicitDomainAcceptedByParser() throws {
        let toml = """
        [network.allow]
        domains = [
          "github.com",
        ]
        """
        let config = try Config.parse(toml: toml)
        XCTAssertTrue(config.allowedDomains.contains(where: { $0.domain == "github.com" }))
    }

    // MARK: - Full pipeline: deny set before allow set (INV-AC-3)

    func testDenySetBeforeAllowSetForPaths() {
        var config = Config(
            readonlyPaths: [MountEntry(path: "/Users/testuser/.aws/config", mode: .readonly)],
            readwritePaths: [],
            allowedDomains: []
        )
        config.deniedPaths = ["/Users/testuser/.aws"]
        // Even though ~/.aws/config is in the allow set, the deny set wins
        let req = AccessRequest(kind: .fileRead(path: "/Users/testuser/.aws/config"), pid: 1, processPath: "/bin/cat")
        XCTAssertEqual(config.check(request: req), .deny)
    }

    // MARK: - expandAllPaths + isDeniedExpanded end-to-end

    func testExpandThenDenyEndToEnd() {
        let userConfig = Config(readonlyPaths: [], readwritePaths: [], allowedDomains: [])
        var config = ProfileResolver.resolve(profiles: [BaseProfile()], userConfig: userConfig)
        // Simulate what the supervisor does: expand with the real user's home
        config.expandAllPaths(userHome: userHome)

        // ~/.aws/credentials should be denied after expansion
        XCTAssertTrue(config.isDeniedExpanded(path: "/Users/testuser/.aws/credentials"))
        // ~/.gnupg/secring.gpg should be denied
        XCTAssertTrue(config.isDeniedExpanded(path: "/Users/testuser/.gnupg/secring.gpg"))
        // ~/.ssh/id_rsa should be denied (glob pattern)
        XCTAssertTrue(config.isDeniedExpanded(path: "/Users/testuser/.ssh/id_rsa"))
        // ~/.ssh/known_hosts should NOT be denied
        XCTAssertFalse(config.isDeniedExpanded(path: "/Users/testuser/.ssh/known_hosts"))
        // ~/.gitconfig should NOT be denied
        XCTAssertFalse(config.isDeniedExpanded(path: "/Users/testuser/.gitconfig"))
    }
}
