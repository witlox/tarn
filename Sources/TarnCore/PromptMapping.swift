import Foundation

/// Pure-logic mapping from user input to prompt response.
/// Extracted from PromptUI so it can be unit-tested without terminal I/O.
public struct PromptMapping {

    /// Map a raw input string (from readLine()) to a PromptResponseMessage.
    /// Returns deny for nil (EOF), empty, or unrecognized input.
    public static func mapInput(_ input: String?, message: PromptRequestMessage) -> PromptResponseMessage {
        guard let raw = input?.trimmingCharacters(in: .whitespaces) else {
            return PromptResponseMessage(flowId: message.flowId, action: "deny", remember: false)
        }

        switch raw {
        case "a":
            return PromptResponseMessage(flowId: message.flowId, action: "allow", remember: false)
        case "A":
            return PromptResponseMessage(flowId: message.flowId, action: "allow",
                                          remember: message.canRemember)
        case "d", "":
            return PromptResponseMessage(flowId: message.flowId, action: "deny", remember: false)
        default:
            return PromptResponseMessage(flowId: message.flowId, action: "deny", remember: false)
        }
    }
}
