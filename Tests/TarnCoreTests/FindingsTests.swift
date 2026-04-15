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
final class F04_CacheKeySeparationTests: XCTestCase {

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
final class F17_AgentReadWritePathSplitTests: XCTestCase {

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
final class F18_DomainSuffixMatchingTests: XCTestCase {

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
final class F19_DirectoryPrefixMatchingTests: XCTestCase {

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

// MARK: - F-26: Missing Deny Paths (LOW)

/// F-26: The deny set should cover additional credential managers.
final class F26_MissingDenyPathsTests: XCTestCase {

    private let userHome = "/Users/testuser"

    private func resolvedConfig() -> Config {
        let userConfig = Config(readonlyPaths: [], readwritePaths: [], allowedDomains: [])
        var config = ProfileResolver.resolve(profiles: [BaseProfile()], userConfig: userConfig)
        config.expandAllPaths(userHome: userHome)
        return config
    }

    /// ~/.config/op (1Password CLI) should be denied.
    /// Currently FAILS: not in BaseProfile.deniedPaths.
    func test_F26_1PasswordCLIIsDenied() {
        let config = resolvedConfig()
        XCTAssertTrue(config.isDeniedExpanded(path: "/Users/testuser/.config/op"),
                      "F-26: ~/.config/op (1Password CLI) should be denied")
    }

    /// ~/.config/op/config should also be denied (directory prefix).
    func test_F26_1PasswordCLISubdirIsDenied() {
        let config = resolvedConfig()
        XCTAssertTrue(config.isDeniedExpanded(path: "/Users/testuser/.config/op/config"),
                      "F-26: ~/.config/op/config should be denied")
    }

    /// ~/.password-store (pass) should be denied.
    /// Currently FAILS: not in BaseProfile.deniedPaths.
    func test_F26_passwordStoreIsDenied() {
        let config = resolvedConfig()
        XCTAssertTrue(config.isDeniedExpanded(path: "/Users/testuser/.password-store"),
                      "F-26: ~/.password-store should be denied")
    }

    /// ~/Library/Application Support/Firefox/Profiles should be denied.
    /// Currently FAILS: not in BaseProfile.deniedPaths.
    func test_F26_firefoxProfilesIsDenied() {
        let config = resolvedConfig()
        XCTAssertTrue(config.isDeniedExpanded(
            path: "/Users/testuser/Library/Application Support/Firefox/Profiles"),
                      "F-26: Firefox Profiles should be denied")
    }

    /// ~/Library/Application Support/Firefox/Profiles/xxxx/cookies.sqlite should be denied.
    func test_F26_firefoxCookiesIsDenied() {
        let config = resolvedConfig()
        XCTAssertTrue(config.isDeniedExpanded(
            path: "/Users/testuser/Library/Application Support/Firefox/Profiles/abc123/cookies.sqlite"),
                      "F-26: Firefox cookies.sqlite should be denied")
    }

    /// Verify existing deny paths still work after adding new ones.
    func test_F26_existingDenyPathsStillWork() {
        let config = resolvedConfig()
        XCTAssertTrue(config.isDeniedExpanded(path: "/Users/testuser/.aws/credentials"))
        XCTAssertTrue(config.isDeniedExpanded(path: "/Users/testuser/.ssh/id_rsa"))
        XCTAssertTrue(config.isDeniedExpanded(path: "/Users/testuser/.gnupg/secring.gpg"))
    }
}

// MARK: - F-27: repoPath Canonicalization (LOW)

/// F-27: repoPath with ".." components should be canonicalized before use.
final class F27_RepoPathCanonicalizationTests: XCTestCase {

    /// A path with ".." should be normalized for trusted region checks.
    /// Currently: TrustedRegions uses hasPrefix on the raw path, so "../"
    /// components are not resolved. After fix: repoPath is canonicalized.
    func test_F27_repoPathWithDotsNormalized() {
        // "/Users/dev/repo/../../../etc" should normalize to "/etc" (or similar)
        // and NOT be used as a workspace trusted region for "/etc/passwd".
        let maliciousRepo = "/Users/dev/repo/../../../etc"
        let normalized = URL(fileURLWithPath: maliciousRepo).standardized.path

        // The normalized path should NOT be "/Users/dev/repo/../../../etc"
        XCTAssertFalse(normalized.contains(".."),
                       "F-27: URL standardization should remove '..' components")

        // A file in /etc should NOT be trusted if the repo is /Users/dev/repo
        // (after canonicalization, the repo resolves to /etc, which should be rejected
        // by validation -- but at minimum the ".." should be resolved)
        let result = TrustedRegions.isTrusted(
            path: "/etc/passwd",
            repoPath: "/Users/dev/repo",
            isWrite: false
        )
        XCTAssertFalse(result, "F-27: /etc/passwd should not be trusted for repo /Users/dev/repo")
    }

    /// Verify that raw ".." in repoPath does not create a trusted region escape.
    /// Currently FAILS: hasPrefix on the raw string means "/Users/dev/repo/../../../etc/passwd"
    /// does NOT match "/Users/dev/repo/" prefix -- so this is safe for different reasons.
    /// But the issue is that the NORMALIZED path should be used for the comparison.
    func test_F27_normalizedPathUsedForTrustedRegionCheck() {
        // After canonicalization, "/Users/dev/repo/../file.txt" becomes "/Users/dev/file.txt"
        // This should NOT be in the workspace trusted region for "/Users/dev/repo"
        let filePath = URL(fileURLWithPath: "/Users/dev/repo/../file.txt").standardized.path
        let result = TrustedRegions.isTrusted(
            path: filePath,
            repoPath: "/Users/dev/repo",
            isWrite: false
        )
        XCTAssertFalse(result,
                       "F-27: Normalized path outside repo should not be trusted")
    }
}

// MARK: - G2-06: pendingPrompts Cleared on Configure (MEDIUM)

/// G2-06: After configure() is called, pending prompts from previous
/// session should be gone.
final class G206_PendingPromptsClearedTests: XCTestCase {

    /// When configure() is called (new session), all pending prompts
    /// from the previous session should be cleared.
    func test_G206_configureClears_pendingPrompts() {
        let engine = DecisionEngine()
        let mock = MockPromptService()
        engine.promptService = mock

        var config = Config.defaults()
        config.expandAllPaths(userHome: "/Users/test")
        engine.configure(config: config, repoPath: "/Users/test/repo")
        engine.processTree.addRoot(pid: 100)

        // Start a prompt that will never resolve (no mock response configured)
        // The mock's defaultResponse will fire, but let's use a slow path:
        // We set up a prompt, then call configure before it resolves.
        // Since MockPromptService resolves synchronously, we test the
        // state indirectly: after configure(), the session cache from
        // the old session should be empty.
        let req = AccessRequest(kind: .fileRead(path: "/etc/old-session-path"), pid: 100, processPath: "/usr/bin/tool")
        mock.defaultResponse = PromptResponseMessage(flowId: "", action: "allow", remember: false)

        let exp = XCTestExpectation(description: "old prompt")
        engine.asyncDecide(request: req) { _ in exp.fulfill() }
        wait(for: [exp], timeout: 1.0)

        // Now configure a new session -- old cache should be wiped
        engine.configure(config: Config.defaults(), repoPath: "/Users/test/newrepo")
        engine.processTree.addRoot(pid: 200)

        // The old session's cached allow should be gone
        XCTAssertNil(engine.sessionCache.lookup(key: req.cacheKey),
                     "G2-06: configure() must clear session cache from previous session")
    }

    /// Session cache is cleared on configure -- already tested in DecisionEngineTests,
    /// but this verifies that the process tree is also cleared.
    func test_G206_configureClears_processTree() {
        let engine = DecisionEngine()
        engine.configure(config: Config.defaults(), repoPath: "/Users/test/repo")
        engine.processTree.addRoot(pid: 100)
        engine.processTree.addChild(pid: 101, parentPID: 100)
        XCTAssertEqual(engine.processTree.count, 2)

        // configure() should clear the tree
        engine.configure(config: Config.defaults(), repoPath: "/Users/test/newrepo")
        XCTAssertEqual(engine.processTree.count, 0,
                       "G2-06: configure() must clear process tree")
        XCTAssertTrue(engine.processTree.isEmpty)
    }
}

// MARK: - F-11: ProcessTree + Pending State Cleanup (HIGH)

/// F-11: ProcessTree should support removeAll and isEmpty.
/// (These already exist in the current implementation -- these tests
/// verify the behavior and serve as regression tests.)
final class F11_ProcessTreeCleanupTests: XCTestCase {

    func test_F11_removeAllClearsTree() {
        let tree = ProcessTree()
        tree.addRoot(pid: 100)
        tree.addChild(pid: 101, parentPID: 100)
        tree.addChild(pid: 102, parentPID: 100)
        XCTAssertEqual(tree.count, 3)

        tree.removeAll()
        XCTAssertEqual(tree.count, 0)
        XCTAssertFalse(tree.isSupervised(pid: 100))
        XCTAssertFalse(tree.isSupervised(pid: 101))
        XCTAssertFalse(tree.isSupervised(pid: 102))
    }

    func test_F11_isEmptyProperty() {
        let tree = ProcessTree()
        XCTAssertTrue(tree.isEmpty)

        tree.addRoot(pid: 100)
        XCTAssertFalse(tree.isEmpty)

        tree.remove(pid: 100)
        XCTAssertTrue(tree.isEmpty)
    }

    /// After removeAll, onEmpty should NOT be called (removeAll is explicit teardown,
    /// not a process exit).
    func test_F11_removeAllDoesNotTriggerOnEmpty() {
        let tree = ProcessTree()
        tree.addRoot(pid: 100)

        var onEmptyCalled = false
        tree.onEmpty = { onEmptyCalled = true }

        tree.removeAll()
        // removeAll is an explicit teardown, different from individual process exits
        // The current implementation does NOT call onEmpty from removeAll -- verify this
        XCTAssertFalse(onEmptyCalled,
                       "F-11: removeAll should not trigger onEmpty (explicit teardown)")
    }

    /// After the last individual process exits, onEmpty IS called.
    func test_F11_individualRemovalTriggersOnEmpty() {
        let tree = ProcessTree()
        tree.addRoot(pid: 100)

        var onEmptyCalled = false
        tree.onEmpty = { onEmptyCalled = true }

        tree.remove(pid: 100)
        XCTAssertTrue(onEmptyCalled,
                      "F-11: Removing the last PID should trigger onEmpty")
    }
}

// MARK: - G2-04: Agent Readonly Paths Prompted for Write (HIGH)

/// G2-04: When a write to an agent readonly path falls through to the decision
/// pipeline, Config.check() should return .deny (not nil/prompt) because the
/// agent profile marks it as readonly.
final class G204_AgentReadonlyWriteDenyTests: XCTestCase {

    /// Write to an agent readonly path should be denied by Config.check(),
    /// not fall through to user prompt.
    /// Currently FAILS: Config.check() uses exact match, so writing to a child
    /// of a readonly path (e.g., ~/.claude/config.json where ~/.claude is readonly)
    /// returns nil instead of deny, allowing the user to be prompted.
    /// The agent can social-engineer "allow + remember" on the write prompt.
    func test_G204_writeToAgentReadonlyPathDeniedByConfig() {
        // Simulate what the supervisor does: resolve profiles, expand paths
        let claudeProfile = ClaudeProfile()
        let userConfig = Config.defaults()
        var config = ProfileResolver.resolve(
            profiles: [BaseProfile(), claudeProfile],
            userConfig: userConfig
        )
        config.expandAllPaths(userHome: "/Users/dev")

        // ~/.claude is in ClaudeProfile.readonlyPaths, but ~/.claude/config.json
        // is NOT explicitly listed. With exact matching, Config.check() returns nil.
        // With directory prefix matching (F-19 fix), it would return .deny.
        // This is the G2-04 attack: write falls through to prompt.
        let req = AccessRequest(
            kind: .fileWrite(path: "/Users/dev/.claude/config.json"),
            pid: 1, processPath: "/usr/bin/claude"
        )

        let result = config.check(request: req)
        // Currently FAILS: returns nil (prompts user) because exact match fails.
        // After fix (F-19 directory prefix matching applied to readonlyPaths):
        // should return .deny because ~/.claude is readonly.
        XCTAssertEqual(result, .deny,
                       "G2-04: Write to child of agent readonly dir should be denied, not prompted")
    }
}
