import Foundation
import TarnCore

/// Presents access requests to the user in the terminal and collects
/// decisions. For network prompts where `canRemember` is false (raw IP,
/// no hostname to persist), the "Allow and remember" option is hidden.
public struct PromptUI {
    public static func prompt(message: PromptRequestMessage) -> PromptResponseMessage {
        print("")
        print("┌─ tarn ─────────────────────────────────")
        print("│ \(message.description)")
        print("│ Process: \(message.processPath) (PID \(message.pid))")
        print("├────────────────────────────────────────")
        print("│ [a] Allow once")
        if message.canRemember {
            print("│ [A] Allow and remember")
        }
        print("│ [d] Deny")
        if !message.canRemember {
            print("│ note: raw IP cannot be remembered;")
            print("│       add the domain to your whitelist instead")
        }
        print("└────────────────────────────────────────")
        let choices = message.canRemember ? "[a/A/d]" : "[a/d]"
        print("  Choice \(choices): ", terminator: "")

        guard let input = readLine()?.trimmingCharacters(in: .whitespaces) else {
            return PromptResponseMessage(flowId: message.flowId, action: "deny", remember: false)
        }

        switch input {
        case "a":
            return PromptResponseMessage(flowId: message.flowId, action: "allow", remember: false)
        case "A":
            return PromptResponseMessage(flowId: message.flowId, action: "allow",
                                          remember: message.canRemember)
        case "d", "":
            return PromptResponseMessage(flowId: message.flowId, action: "deny", remember: false)
        default:
            print("  Unknown choice, denying.")
            return PromptResponseMessage(flowId: message.flowId, action: "deny", remember: false)
        }
    }
}
