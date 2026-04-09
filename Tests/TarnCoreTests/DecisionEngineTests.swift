import XCTest
@testable import TarnCore

/// Integration tests for the full decision pipeline:
/// deny → allow → session cache → prompt → persist.
/// Wired to monitor.feature and network.feature scenarios.
final class DecisionEngineTests: XCTestCase {

    // swiftlint:disable implicitly_unwrapped_optional
    var engine: DecisionEngine!
    var mock: MockPromptService!
    // swiftlint:enable implicitly_unwrapped_optional

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

    // MARK: - monitor.feature: quickDecide paths

    // Scenario: Whitelisted path is allowed
    // Note: ES reports resolved paths, so we use the expanded form
    func testWhitelistedReadonlyPathAllowed() {
        let req = AccessRequest(kind: .fileRead(path: "/Users/test/.gitconfig"), pid: 100, processPath: "/usr/bin/git")
        XCTAssertEqual(engine.quickDecide(request: req), .allow)
    }

    // Scenario: Unknown path triggers prompt (returns nil from quickDecide)
    func testUnknownPathReturnsNil() {
        let req = AccessRequest(kind: .fileRead(path: "/etc/npmrc"), pid: 100, processPath: "/usr/bin/node")
        XCTAssertNil(engine.quickDecide(request: req))
    }

    // Scenario: User allows unknown path
    func testAsyncDecideAllowOnce() {
        let req = AccessRequest(kind: .fileRead(path: "/etc/npmrc"), pid: 100, processPath: "/usr/bin/node")
        mock.responses["/etc/npmrc"] = PromptResponseMessage(flowId: "", action: "allow", remember: false)

        let expectation = XCTestExpectation(description: "asyncDecide")
        engine.asyncDecide(request: req) { action in
            XCTAssertEqual(action, .allow)
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 1.0)

        // Verify it was cached
        XCTAssertEqual(engine.sessionCache.lookup(key: req.cacheKey), .allow)
        // Verify no persist request was sent
        XCTAssertTrue(mock.receivedPersists.isEmpty)
    }

    // Scenario: User denies unknown path
    func testAsyncDecideDeny() {
        let req = AccessRequest(kind: .fileRead(path: "/root/.bashrc"), pid: 100, processPath: "/bin/cat")
        mock.defaultResponse = PromptResponseMessage(flowId: "", action: "deny", remember: false)

        let expectation = XCTestExpectation(description: "asyncDecide")
        engine.asyncDecide(request: req) { action in
            XCTAssertEqual(action, .deny)
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 1.0)

        // Verify deny was cached (INV-AC-6)
        XCTAssertEqual(engine.sessionCache.lookup(key: req.cacheKey), .deny)
    }

    // Scenario: User allows and remembers
    func testAsyncDecideAllowAndRemember() {
        let req = AccessRequest(kind: .fileRead(path: "/etc/special"), pid: 100, processPath: "/usr/bin/tool")
        mock.responses["/etc/special"] = PromptResponseMessage(flowId: "", action: "allow", remember: true)
        mock.persistSucceeds = true

        let expectation = XCTestExpectation(description: "asyncDecide")
        engine.asyncDecide(request: req) { action in
            XCTAssertEqual(action, .allow)
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 1.0)

        // Verify persist was requested
        XCTAssertEqual(mock.receivedPersists.count, 1)
        // Verify the in-memory config was updated
        let check = engine.config.check(request: req)
        XCTAssertEqual(check, .allow)
    }

    // Scenario: Allow and remember degrades on persist failure (INV-PR-6)
    func testAsyncDecideRememberFallsBackToSessionCache() {
        let req = AccessRequest(kind: .fileRead(path: "/etc/other"), pid: 100, processPath: "/usr/bin/tool")
        mock.responses["/etc/other"] = PromptResponseMessage(flowId: "", action: "allow", remember: true)
        mock.persistSucceeds = false

        let expectation = XCTestExpectation(description: "asyncDecide")
        engine.asyncDecide(request: req) { action in
            XCTAssertEqual(action, .allow)
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 1.0)

        // Verify session cache has it (not the persistent config)
        XCTAssertEqual(engine.sessionCache.lookup(key: req.cacheKey), .allow)
        // Verify the config was NOT updated
        XCTAssertNil(engine.config.check(request: req))
    }

    // MARK: - monitor.feature: session cache scenarios

    // Scenario: Session cache prevents re-prompting after allow
    func testSessionCachePreventsRePromptingAllow() {
        let req = AccessRequest(kind: .fileRead(path: "/etc/npmrc"), pid: 100, processPath: "/usr/bin/node")
        engine.sessionCache.record(key: req.cacheKey, action: .allow)
        XCTAssertEqual(engine.quickDecide(request: req), .allow)
    }

    // Scenario: Session cache prevents re-prompting after deny
    func testSessionCachePreventsRePromptingDeny() {
        let req = AccessRequest(kind: .fileRead(path: "/etc/private"), pid: 100, processPath: "/bin/cat")
        engine.sessionCache.record(key: req.cacheKey, action: .deny)
        XCTAssertEqual(engine.quickDecide(request: req), .deny)
    }

    // Scenario: Session cache is cleared at session end
    func testSessionCacheClearedOnConfigure() {
        engine.sessionCache.record(key: "/etc/foo", action: .allow)
        engine.configure(config: Config.defaults(), repoPath: "/tmp/new")
        XCTAssertNil(engine.sessionCache.lookup(key: "/etc/foo"))
    }

    // MARK: - monitor.feature: no prompt service → deny

    func testNoPromptServiceDefaultsDeny() {
        engine.promptService = nil
        let req = AccessRequest(kind: .fileRead(path: "/etc/npmrc"), pid: 100, processPath: "/usr/bin/node")

        let expectation = XCTestExpectation(description: "asyncDecide")
        engine.asyncDecide(request: req) { action in
            XCTAssertEqual(action, .deny)
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 1.0)
    }

    // MARK: - network.feature scenarios

    // Scenario: Allowed domain passes silently
    func testAllowedDomainQuickDecide() {
        let req = AccessRequest(kind: .networkConnect(domain: "github.com"), pid: 100, processPath: "pid:100")
        XCTAssertEqual(engine.quickDecide(request: req), .allow)
    }

    // Scenario: Unknown hostname triggers prompt
    func testUnknownHostnameTriggersPrompt() {
        let req = AccessRequest(kind: .networkConnect(domain: "newdomain.example.com"), pid: 100, processPath: "pid:100")
        XCTAssertNil(engine.quickDecide(request: req))
    }

    // Scenario: User allows unknown hostname for the session
    func testAsyncDecideNetworkAllowOnce() {
        let req = AccessRequest(kind: .networkConnect(domain: "newdomain.example.com"), pid: 100, processPath: "pid:100")
        mock.responses["newdomain.example.com"] = PromptResponseMessage(flowId: "", action: "allow", remember: false)

        let expectation = XCTestExpectation(description: "asyncDecide")
        engine.asyncDecide(request: req) { action in
            XCTAssertEqual(action, .allow)
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 1.0)

        // Subsequent calls don't prompt
        XCTAssertEqual(engine.quickDecide(request: req), .allow)
        XCTAssertEqual(mock.receivedPrompts.count, 1) // only one prompt sent
    }

    // Scenario: User remembers a hostname
    func testAsyncDecideNetworkRememberHostname() {
        let req = AccessRequest(kind: .networkConnect(domain: "api.openai.com"), pid: 100, processPath: "pid:100")
        mock.responses["api.openai.com"] = PromptResponseMessage(flowId: "", action: "allow", remember: true)
        mock.persistSucceeds = true

        let expectation = XCTestExpectation(description: "asyncDecide")
        engine.asyncDecide(request: req) { action in
            XCTAssertEqual(action, .allow)
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 1.0)

        XCTAssertEqual(mock.receivedPersists.count, 1)
    }

    // Scenario: Raw IP cannot be remembered (canRemember = false)
    func testRawIPCannotBeRemembered() {
        let msg = engine.makePromptMessage(request: AccessRequest(
            kind: .networkConnect(domain: "203.0.113.42"),
            pid: 100, processPath: "pid:100"
        ))
        XCTAssertFalse(msg.canRemember)
    }

    // Scenario: Hostname CAN be remembered
    func testHostnameCanBeRemembered() {
        let msg = engine.makePromptMessage(request: AccessRequest(
            kind: .networkConnect(domain: "github.com"),
            pid: 100, processPath: "pid:100"
        ))
        XCTAssertTrue(msg.canRemember)
    }

    // Scenario: Denied domain is dropped
    func testDeniedDomainDropped() {
        var config = engine.config
        config.deniedDomains = ["evil.example.com"]
        engine.configure(config: config, repoPath: "/Users/test/myrepo")
        engine.processTree.addRoot(pid: 100)

        let req = AccessRequest(kind: .networkConnect(domain: "evil.example.com"), pid: 100, processPath: "pid:100")
        XCTAssertEqual(engine.quickDecide(request: req), .deny)
    }

    // MARK: - prompt.feature scenarios

    // Scenario: Empty input defaults to deny
    func testPromptDenyIsDefaultAction() {
        // The mock returns "deny" by default
        let req = AccessRequest(kind: .fileRead(path: "/unknown"), pid: 100, processPath: "/bin/x")

        let expectation = XCTestExpectation(description: "asyncDecide")
        engine.asyncDecide(request: req) { action in
            XCTAssertEqual(action, .deny)
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 1.0)
    }

    // Scenario: Prompt displays correct info
    func testPromptRequestContainsCorrectInfo() {
        let req = AccessRequest(kind: .fileRead(path: "/etc/npmrc"), pid: 100, processPath: "/usr/bin/node")
        mock.defaultResponse = PromptResponseMessage(flowId: "", action: "deny", remember: false)

        let expectation = XCTestExpectation(description: "asyncDecide")
        engine.asyncDecide(request: req) { _ in expectation.fulfill() }
        wait(for: [expectation], timeout: 1.0)

        XCTAssertEqual(mock.receivedPrompts.count, 1)
        let prompt = mock.receivedPrompts[0]
        XCTAssertTrue(prompt.description.contains("/etc/npmrc"))
        XCTAssertEqual(prompt.processPath, "/usr/bin/node")
        XCTAssertEqual(prompt.pid, 100)
        XCTAssertTrue(prompt.canRemember)
    }

    // MARK: - prompt.feature: message construction

    // Scenario: Prompt displays file write info
    func testPromptMessageFileWrite() {
        let msg = engine.makePromptMessage(request: AccessRequest(
            kind: .fileWrite(path: "/etc/foo"),
            pid: 100, processPath: "/usr/bin/tool"
        ))
        XCTAssertTrue(msg.description.contains("File write: /etc/foo"))
        XCTAssertTrue(msg.canRemember)
    }

    // Scenario: Prompt displays network connect info
    func testPromptMessageNetworkConnect() {
        let msg = engine.makePromptMessage(request: AccessRequest(
            kind: .networkConnect(domain: "api.openai.com"),
            pid: 100, processPath: "pid:100"
        ))
        XCTAssertTrue(msg.description.contains("Network connect: api.openai.com"))
        XCTAssertTrue(msg.canRemember) // hostname, not IP
    }

    // Scenario: File read prompt has correct metadata
    func testPromptMessageMetadata() {
        let msg = engine.makePromptMessage(request: AccessRequest(
            kind: .fileRead(path: "/etc/npmrc"),
            pid: 42, processPath: "/usr/bin/node"
        ))
        XCTAssertEqual(msg.pid, 42)
        XCTAssertEqual(msg.processPath, "/usr/bin/node")
        XCTAssertFalse(msg.flowId.isEmpty)
    }

    // MARK: - Trusted regions (via engine)

    func testWorkspaceIsTrustedRegion() {
        XCTAssertTrue(engine.isInTrustedRegion(path: "/Users/test/myrepo/src/main.swift", isWrite: false))
        XCTAssertTrue(engine.isInTrustedRegion(path: "/Users/test/myrepo/src/main.swift", isWrite: true))
    }

    func testSystemPathReadOnlyTrustedRegion() {
        XCTAssertTrue(engine.isInTrustedRegion(path: "/usr/lib/libSystem.dylib", isWrite: false))
        XCTAssertFalse(engine.isInTrustedRegion(path: "/usr/local/bin/evil", isWrite: true))
    }

    // MARK: - Full end-to-end scenario

    // Trace: supervised PID opens unknown file → quickDecide nil →
    // asyncDecide prompts → user allows once → cached → second
    // access hits cache → no second prompt
    func testFullFileAccessEndToEnd() {
        let req = AccessRequest(kind: .fileRead(path: "/etc/somefile"), pid: 100, processPath: "/usr/bin/tool")
        mock.responses["/etc/somefile"] = PromptResponseMessage(flowId: "", action: "allow", remember: false)

        // First access: unknown → prompt → allow → cached
        XCTAssertNil(engine.quickDecide(request: req))
        let exp1 = XCTestExpectation(description: "first")
        engine.asyncDecide(request: req) { action in
            XCTAssertEqual(action, .allow)
            exp1.fulfill()
        }
        wait(for: [exp1], timeout: 1.0)
        XCTAssertEqual(mock.receivedPrompts.count, 1)

        // Second access: cache hit → no prompt
        XCTAssertEqual(engine.quickDecide(request: req), .allow)
    }

    // Trace: supervised PID connects to unknown host → prompt →
    // user denies → cached → second connect denied silently
    func testFullNetworkDenyEndToEnd() {
        let req = AccessRequest(kind: .networkConnect(domain: "suspicious.com"), pid: 100, processPath: "pid:100")
        mock.responses["suspicious.com"] = PromptResponseMessage(flowId: "", action: "deny", remember: false)

        let exp1 = XCTestExpectation(description: "first")
        engine.asyncDecide(request: req) { action in
            XCTAssertEqual(action, .deny)
            exp1.fulfill()
        }
        wait(for: [exp1], timeout: 1.0)

        // Second access: cache hit → deny, no prompt
        XCTAssertEqual(engine.quickDecide(request: req), .deny)
        XCTAssertEqual(mock.receivedPrompts.count, 1)
    }
}
