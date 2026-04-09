import XCTest
@testable import TarnCore

/// Tests for trusted region logic, wired to process-tree.feature and
/// monitor.feature scenarios where applicable.
final class TrustedRegionTests: XCTestCase {

    let repo = "/Users/dev/myrepo"

    // -- monitor.feature: "Workspace path is allowed via fast path"
    func testWorkspaceReadIsTrusted() {
        XCTAssertTrue(TrustedRegions.isTrusted(path: "/Users/dev/myrepo/src/main.rs", repoPath: repo, isWrite: false))
    }

    func testWorkspaceWriteIsTrusted() {
        XCTAssertTrue(TrustedRegions.isTrusted(path: "/Users/dev/myrepo/src/main.rs", repoPath: repo, isWrite: true))
    }

    // -- monitor.feature: "Temp path is allowed via fast path"
    func testTmpReadIsTrusted() {
        XCTAssertTrue(TrustedRegions.isTrusted(path: "/tmp/build-output", repoPath: repo, isWrite: false))
    }

    func testTmpWriteIsTrusted() {
        XCTAssertTrue(TrustedRegions.isTrusted(path: "/tmp/build-output", repoPath: repo, isWrite: true))
    }

    func testVarTmpIsTrusted() {
        XCTAssertTrue(TrustedRegions.isTrusted(path: "/var/tmp/something", repoPath: repo, isWrite: false))
    }

    // -- monitor.feature: "System path is allowed via fast path"
    func testSystemPathReadIsTrusted() {
        XCTAssertTrue(TrustedRegions.isTrusted(path: "/usr/lib/libSystem.dylib", repoPath: repo, isWrite: false))
        XCTAssertTrue(TrustedRegions.isTrusted(path: "/System/Library/Frameworks/Foundation.framework", repoPath: repo, isWrite: false))
        XCTAssertTrue(TrustedRegions.isTrusted(path: "/Library/Preferences/SystemConfiguration", repoPath: repo, isWrite: false))
    }

    // -- Finding 10: system paths are read-only trusted regions
    func testSystemPathWriteIsNotTrusted() {
        XCTAssertFalse(TrustedRegions.isTrusted(path: "/Library/LaunchDaemons/evil.plist", repoPath: repo, isWrite: true))
        XCTAssertFalse(TrustedRegions.isTrusted(path: "/usr/local/bin/something", repoPath: repo, isWrite: true))
    }

    func testUnknownPathIsNotTrusted() {
        XCTAssertFalse(TrustedRegions.isTrusted(path: "/Users/dev/.aws/credentials", repoPath: repo, isWrite: false))
    }

    func testEmptyRepoPathDoesNotMatchEverything() {
        // If repoPath is empty, the workspace check should not match any path
        XCTAssertFalse(TrustedRegions.isTrusted(path: "/Users/dev/myrepo/file", repoPath: "", isWrite: false))
    }

    // MARK: - IP address detection

    func testIPv4Detected() {
        XCTAssertTrue(TrustedRegions.isIPAddress("192.168.1.1"))
        XCTAssertTrue(TrustedRegions.isIPAddress("203.0.113.42"))
    }

    func testIPv6Detected() {
        XCTAssertTrue(TrustedRegions.isIPAddress("::1"))
        XCTAssertTrue(TrustedRegions.isIPAddress("2001:db8::1"))
    }

    func testHostnameNotDetectedAsIP() {
        XCTAssertFalse(TrustedRegions.isIPAddress("github.com"))
        XCTAssertFalse(TrustedRegions.isIPAddress("api.anthropic.com"))
        XCTAssertFalse(TrustedRegions.isIPAddress(""))
    }
}
