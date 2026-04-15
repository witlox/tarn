import XCTest
@testable import TarnCore

// =============================================================================
// TDD tests for Gate 1 and Gate 2 findings.
// These tests are in the RED phase: they compile against the current interface
// but assert on behavior that is NOT yet implemented. They will FAIL until the
// corresponding fixes from the implementation plan are applied.
// =============================================================================

// MARK: - F-04: Cache Key Separation (CRITICAL)

/// F-04: The session cache currently uses the same key for fileRead and fileWrite
/// to the same path. A read-allow must NOT be reused for a write.
final class CacheKeySeparationTests: XCTestCase {

    var engine: DecisionEngine!
    var mock: MockPromptService!

    override func setUp() {
        super.setUp()
        engine = DecisionEngine()
        mock = MockPromptService()
        engine.promptService = mock

        var config = Config.defaults()
        config.deniedPaths = ["/Users/test/.aws"]
        config.expandAllPaths(userHome: "/Users/test")
        engine.configure(config: config, repoPath: "/Users/test/myrepo")
        engine.processTree.addRoot(pid: 100)
    }

    /// A read-allow cached decision must NOT apply to a write for the same path.
    /// Currently FAILS: cacheKey is the same for read and write, so the write
    /// hits the cache and returns .allow without prompting.
    func test_F04_readAllowDoesNotApplyToWrite() {
        let readReq = AccessRequest(kind: .fileRead(path: "/etc/npmrc"), pid: 100, processPath: "/usr/bin/node")
        let writeReq = AccessRequest(kind: .fileWrite(path: "/etc/npmrc"), pid: 100, processPath: "/usr/bin/node")

        // Cache a read-allow
        engine.sessionCache.record(key: readReq.cacheKey, action: .allow)

        // The write should NOT be decided by the cache -- it should return nil (needs prompt)
        // Currently FAILS: cacheKey for read and write are identical, so quickDecide returns .allow
        let writeResult = engine.quickDecide(request: writeReq)
        XCTAssertNil(writeResult, "F-04: Write to same path should NOT hit cache from a read-allow")
    }

    /// A write-allow cached decision must NOT apply to a read for the same path.
    /// (This direction is less security-critical, but the cache keys should still differ.)
    func test_F04_writeAllowDoesNotApplyToRead() {
        let readReq = AccessRequest(kind: .fileRead(path: "/etc/npmrc"), pid: 100, processPath: "/usr/bin/node")
        let writeReq = AccessRequest(kind: .fileWrite(path: "/etc/npmrc"), pid: 100, processPath: "/usr/bin/node")

        // Cache a write-allow
        engine.sessionCache.record(key: writeReq.cacheKey, action: .allow)

        // Read should NOT be decided by the cache -- different cache key
        // Currently FAILS: same key for both
        let readResult = engine.quickDecide(request: readReq)
        XCTAssertNil(readResult, "F-04: Read should NOT hit cache from a write-allow")
    }

    /// Verify that file and network cache keys never collide.
    func test_F04_networkCacheKeysSeparateFromFile() {
        let fileReq = AccessRequest(kind: .fileRead(path: "host:github.com"), pid: 100, processPath: "/usr/bin/tool")
        let netReq = AccessRequest(kind: .networkConnect(domain: "github.com"), pid: 100, processPath: "pid:100")

        // These must have different cache keys. The network key is "host:github.com",
        // and if the file path is literally "host:github.com" they could collide.
        // With the fix (prefix "r:" / "n:"), they will differ.
        XCTAssertNotEqual(fileReq.cacheKey, netReq.cacheKey,
                          "F-04: File and network cache keys must not collide")
    }

    /// The cache key for fileRead must differ from fileWrite.
    func test_F04_cacheKeyDiffersForReadAndWrite() {
        let readReq = AccessRequest(kind: .fileRead(path: "/etc/foo"), pid: 100, processPath: "/usr/bin/tool")
        let writeReq = AccessRequest(kind: .fileWrite(path: "/etc/foo"), pid: 100, processPath: "/usr/bin/tool")

        // Currently FAILS: both produce the same cacheKey
        XCTAssertNotEqual(readReq.cacheKey, writeReq.cacheKey,
                          "F-04: cacheKey must include access mode prefix")
    }

    /// End-to-end: user allows a READ, then a WRITE to the same path must still prompt.
    func test_F04_readAllowThenWriteStillPrompts() {
        let readReq = AccessRequest(kind: .fileRead(path: "/etc/special"), pid: 100, processPath: "/usr/bin/tool")
        let writeReq = AccessRequest(kind: .fileWrite(path: "/etc/special"), pid: 100, processPath: "/usr/bin/tool")

        // User allows the read
        mock.responses["/etc/special"] = PromptResponseMessage(flowId: "", action: "allow", remember: false)
        let exp1 = XCTestExpectation(description: "read")
        engine.asyncDecide(request: readReq) { action in
            XCTAssertEqual(action, .allow)
            exp1.fulfill()
        }
        wait(for: [exp1], timeout: 1.0)

        // Write should NOT hit cache, should prompt again
        // Currently FAILS: write hits the read's cache entry
        let writeQuick = engine.quickDecide(request: writeReq)
        XCTAssertNil(writeQuick, "F-04: Write must prompt even after read was allowed")
    }
}

// MARK: - F-17: Agent Read/Write Path Split (MEDIUM)

/// F-17: Agent paths in TrustedRegions currently allow both reads and writes.
/// After the fix, agentReadPaths should deny writes.
final class AgentReadWritePathSplitTests: XCTestCase {

    /// An agent readonly path must allow reads via TrustedRegions.
    func test_F17_agentReadonlyPathAllowsReads() {
        // Currently: agentPaths allows both read and write.
        // After fix: agentReadPaths allows reads only.
        // This test passes on current code (reads are always allowed for agentPaths).
        let result = TrustedRegions.isTrusted(
            path: "/Users/dev/.claude/settings.json",
            repoPath: "/Users/dev/myrepo",
            agentPaths: ["/Users/dev/.claude"],
            isWrite: false
        )
        XCTAssertTrue(result, "Agent readonly path should allow reads")
    }

    /// An agent readonly path must DENY writes via TrustedRegions.
    /// Currently FAILS: agentPaths allows writes too, bypassing the readonly restriction.
    func test_F17_agentReadonlyPathDeniesWrites() {
        // The current interface uses a single `agentPaths` array for all agent paths.
        // After the fix, this will be split into agentReadPaths and agentWritePaths.
        // For now, we test against the current interface and expect FAILURE:
        // writes to agent readonly paths should NOT be trusted.
        let result = TrustedRegions.isTrusted(
            path: "/Users/dev/.claude/settings.json",
            repoPath: "/Users/dev/myrepo",
            agentPaths: ["/Users/dev/.claude"],
            isWrite: true
        )
        // EXPECTED FAIL: currently returns true (agent paths allow writes)
        // After fix: should return false (readonly agent path denies writes)
        XCTAssertFalse(result,
                       "F-17: Agent readonly path must DENY writes via trusted region fast path")
    }

    /// An agent readwrite path must allow both reads and writes.
    func test_F17_agentReadwritePathAllowsBoth() {
        // F-17: agentWritePaths allow both reads and writes
        let readResult = TrustedRegions.isTrusted(
            path: "/Users/dev/.claude/projects/foo",
            repoPath: "/Users/dev/myrepo",
            agentWritePaths: ["/Users/dev/.claude/projects"],
            isWrite: false
        )
        let writeResult = TrustedRegions.isTrusted(
            path: "/Users/dev/.claude/projects/foo",
            repoPath: "/Users/dev/myrepo",
            agentWritePaths: ["/Users/dev/.claude/projects"],
            isWrite: true
        )
        XCTAssertTrue(readResult, "Agent readwrite path should allow reads")
        XCTAssertTrue(writeResult, "Agent readwrite path should allow writes")
    }

    /// End-to-end via DecisionEngine: write to agent readonly path should NOT be auto-allowed.
    /// Currently FAILS: isInTrustedRegion returns true for writes to agent paths.
    func test_F17_engineDeniesWriteToAgentReadonlyPath() {
        let engine = DecisionEngine()
        let config = Config.defaults()
        // Configure with Claude agent paths: ~/.claude is readonly
        engine.configure(
            config: config,
            repoPath: "/Users/dev/myrepo",
            agentPaths: ["/Users/dev/.claude"]
        )

        let result = engine.isInTrustedRegion(
            path: "/Users/dev/.claude/settings.json",
            isWrite: true
        )
        // EXPECTED FAIL: currently returns true
        XCTAssertFalse(result,
                       "F-17: DecisionEngine must not trust writes to agent readonly paths")
    }
}

// MARK: - F-18: Domain Suffix Matching (MEDIUM)

/// F-18: The allow set uses exact domain matching. Subdomain matching should
/// work so that allowing "github.com" also allows "api.github.com".
final class DomainSuffixMatchingTests: XCTestCase {

    /// Allowing "github.com" should also allow "api.github.com".
    /// Currently FAILS: exact match only.
    func test_F18_allowGithubComAlsoAllowsApiGithubCom() {
        let config = Config.defaults() // contains "github.com"
        let req = AccessRequest(
            kind: .networkConnect(domain: "api.github.com"),
            pid: 1, processPath: "/usr/bin/git"
        )
        // Currently FAILS: returns nil because api.github.com != github.com
        XCTAssertEqual(config.check(request: req), .allow,
                       "F-18: Allowing github.com should also allow api.github.com (suffix match)")
    }

    /// Allowing "github.com" must NOT allow "notgithub.com" (not a subdomain).
    func test_F18_allowGithubComDoesNotAllowNotGithubCom() {
        let config = Config.defaults() // contains "github.com"
        let req = AccessRequest(
            kind: .networkConnect(domain: "notgithub.com"),
            pid: 1, processPath: "/usr/bin/curl"
        )
        XCTAssertNil(config.check(request: req),
                     "F-18: github.com must NOT match notgithub.com")
    }

    /// Allowing "api.github.com" must NOT allow bare "github.com" (suffix, not substring).
    func test_F18_allowApiGithubComDoesNotAllowGithubCom() {
        var config = Config.defaults()
        config.addDomain(domain: "api.github.com")

        // Remove the default github.com entry to isolate the test
        config.allowedDomains.removeAll(where: { $0.domain == "github.com" })

        let req = AccessRequest(
            kind: .networkConnect(domain: "github.com"),
            pid: 1, processPath: "/usr/bin/git"
        )
        XCTAssertNil(config.check(request: req),
                     "F-18: api.github.com must NOT match bare github.com")
    }

    /// Allowing "github.com" should also allow "uploads.github.com".
    /// Currently FAILS: exact match only.
    func test_F18_allowGithubComAlsoAllowsUploadsGithubCom() {
        let config = Config.defaults()
        let req = AccessRequest(
            kind: .networkConnect(domain: "uploads.github.com"),
            pid: 1, processPath: "/usr/bin/git"
        )
        XCTAssertEqual(config.check(request: req), .allow,
                       "F-18: Allowing github.com should match uploads.github.com")
    }
}

// MARK: - F-19: Directory Prefix Matching (MEDIUM)

/// F-19: The allow set uses exact path matching. Directory prefix matching
/// should work so that allowing "~/.config/tool" also allows children.
final class DirectoryPrefixMatchingTests: XCTestCase {

    /// Allowing "~/.config/tool" should also allow "~/.config/tool/state.json".
    /// Currently FAILS: exact match only.
    func test_F19_allowDirectoryAlsoAllowsChildren() {
        var config = Config(readonlyPaths: [], readwritePaths: [], allowedDomains: [])
        config.addReadwrite(path: "~/.config/tool")

        let req = AccessRequest(
            kind: .fileWrite(path: "~/.config/tool/state.json"),
            pid: 1, processPath: "/usr/bin/tool"
        )
        // Currently FAILS: returns nil because exact match fails
        XCTAssertEqual(config.check(request: req), .allow,
                       "F-19: Allowing ~/.config/tool should also allow ~/.config/tool/state.json")
    }

    /// Allowing "~/.config/tool" must NOT allow "~/.config/toolbox/state.json".
    /// (Prefix must include trailing slash to prevent partial matches.)
    func test_F19_allowDirectoryDoesNotAllowSiblingPrefix() {
        var config = Config(readonlyPaths: [], readwritePaths: [], allowedDomains: [])
        config.addReadwrite(path: "~/.config/tool")

        let req = AccessRequest(
            kind: .fileWrite(path: "~/.config/toolbox/state.json"),
            pid: 1, processPath: "/usr/bin/tool"
        )
        XCTAssertNil(config.check(request: req),
                     "F-19: ~/.config/tool must NOT match ~/.config/toolbox/")
    }

    /// Readonly directory prefix: children should be readable.
    /// Currently FAILS: exact match only.
    func test_F19_readonlyDirectoryAllowsChildReads() {
        var config = Config(readonlyPaths: [], readwritePaths: [], allowedDomains: [])
        config.addReadonly(path: "~/.config/tool")

        let req = AccessRequest(
            kind: .fileRead(path: "~/.config/tool/config.json"),
            pid: 1, processPath: "/usr/bin/tool"
        )
        XCTAssertEqual(config.check(request: req), .allow,
                       "F-19: Readonly dir prefix should allow child reads")
    }

    /// Readonly directory prefix: children should NOT be writable.
    /// Currently FAILS: exact match only (returns nil instead of deny).
    func test_F19_readonlyDirectoryDeniesChildWrites() {
        var config = Config(readonlyPaths: [], readwritePaths: [], allowedDomains: [])
        config.addReadonly(path: "~/.config/tool")

        let req = AccessRequest(
            kind: .fileWrite(path: "~/.config/tool/config.json"),
            pid: 1, processPath: "/usr/bin/tool"
        )
        XCTAssertEqual(config.check(request: req), .deny,
                       "F-19: Readonly dir prefix should deny child writes")
    }
}

