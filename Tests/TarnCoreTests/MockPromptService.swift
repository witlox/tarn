import Foundation
@testable import TarnCore

/// Mock prompt service for integration tests. Records prompt requests
/// and returns preconfigured responses. Simulates the XPC round-trip
/// between the supervisor and the CLI without needing actual XPC.
final class MockPromptService: PromptService {
    var currentProfilePath: String? = "/tmp/test-profile.toml"

    /// Pre-programmed responses keyed by the prompt description prefix.
    /// The test sets these before exercising the pipeline.
    var responses: [String: PromptResponseMessage] = [:]

    /// Default response when no match is found.
    var defaultResponse = PromptResponseMessage(flowId: "", action: "deny", remember: false)

    /// Every prompt request received, in order.
    var receivedPrompts: [PromptRequestMessage] = []

    /// Every persist request received, in order.
    var receivedPersists: [AccessRequest] = []

    /// Whether the next persist should succeed.
    var persistSucceeds = true

    func asyncPrompt(_ message: PromptRequestMessage,
                     reply: @escaping (PromptResponseMessage) -> Void) {
        receivedPrompts.append(message)
        // Find a matching response by description prefix
        for (prefix, response) in responses {
            if message.description.contains(prefix) {
                reply(PromptResponseMessage(flowId: message.flowId,
                                             action: response.action,
                                             remember: response.remember))
                return
            }
        }
        reply(PromptResponseMessage(flowId: message.flowId,
                                     action: defaultResponse.action,
                                     remember: defaultResponse.remember))
    }

    func asyncPersistEntry(request: AccessRequest,
                           reply: @escaping (Bool) -> Void) {
        receivedPersists.append(request)
        reply(persistSucceeds)
    }
}
