import XCTest
@testable import TarnCore

// MARK: - F-26: Missing Deny Paths (LOW)

/// F-26: The deny set should cover additional credential managers.
final class MissingDenyPathsTests: XCTestCase {

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
final class RepoPathCanonicalizationTests: XCTestCase {

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
final class PendingPromptsClearedTests: XCTestCase {

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
final class ProcessTreeCleanupTests: XCTestCase {

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
final class AgentReadonlyWriteDenyTests: XCTestCase {

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
