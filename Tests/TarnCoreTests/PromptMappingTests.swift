import XCTest
@testable import TarnCore

/// Tests wired to tests/features/prompt.feature scenarios.
/// Exercises the pure input→response mapping extracted from PromptUI.
final class PromptMappingTests: XCTestCase {

    private func makeMessage(flowId: String = "test-flow", canRemember: Bool = true) -> PromptRequestMessage {
        PromptRequestMessage(
            sessionId: "test-session",
            flowId: flowId,
            description: "File read: /etc/hosts",
            processPath: "/usr/bin/cat",
            pid: 100,
            canRemember: canRemember
        )
    }

    // Scenario: User selects allow once
    func testAllowOnceInput() {
        let msg = makeMessage()
        let response = PromptMapping.mapInput("a", message: msg)
        XCTAssertEqual(response.action, "allow")
        XCTAssertFalse(response.remember)
        XCTAssertEqual(response.flowId, "test-flow")
    }

    // Scenario: User selects allow and remember
    func testAllowAndRememberInput() {
        let msg = makeMessage(canRemember: true)
        let response = PromptMapping.mapInput("A", message: msg)
        XCTAssertEqual(response.action, "allow")
        XCTAssertTrue(response.remember)
    }

    // Scenario: User selects deny
    func testDenyInput() {
        let msg = makeMessage()
        let response = PromptMapping.mapInput("d", message: msg)
        XCTAssertEqual(response.action, "deny")
        XCTAssertFalse(response.remember)
    }

    // Scenario: Empty input defaults to deny
    func testEmptyInputDefaultsDeny() {
        let msg = makeMessage()
        let response = PromptMapping.mapInput("", message: msg)
        XCTAssertEqual(response.action, "deny")
        XCTAssertFalse(response.remember)
    }

    // Scenario: EOF defaults to deny
    func testNilInputDefaultsDeny() {
        let msg = makeMessage()
        let response = PromptMapping.mapInput(nil, message: msg)
        XCTAssertEqual(response.action, "deny")
        XCTAssertFalse(response.remember)
    }

    // Scenario: Unknown input defaults to deny
    func testUnknownInputDefaultsDeny() {
        let msg = makeMessage()
        let response = PromptMapping.mapInput("x", message: msg)
        XCTAssertEqual(response.action, "deny")
        XCTAssertFalse(response.remember)
    }

    // Scenario: Allow and remember is hidden for raw-IP prompts
    // When canRemember=false, even "A" should not set remember=true
    func testRememberDisabledForRawIP() {
        let msg = makeMessage(canRemember: false)
        let response = PromptMapping.mapInput("A", message: msg)
        XCTAssertEqual(response.action, "allow")
        XCTAssertFalse(response.remember)
    }

    // Whitespace around input is trimmed
    func testWhitespaceAroundInputIsTrimmed() {
        let msg = makeMessage()
        let response = PromptMapping.mapInput("  a  ", message: msg)
        XCTAssertEqual(response.action, "allow")
        XCTAssertFalse(response.remember)
    }
}
