import Foundation
import TarnCore

/// Presents access requests to the user in the terminal and collects
/// decisions. For network prompts where `canRemember` is false (raw IP,
/// no hostname to persist), the "Allow and remember" option is hidden.
public struct PromptUI {
    // ANSI color codes
    private static let reset = "\u{1B}[0m"
    private static let bold = "\u{1B}[1m"
    private static let bgYellow = "\u{1B}[43m"
    private static let fgBlack = "\u{1B}[30m"
    private static let fgGreen = "\u{1B}[32m"
    private static let fgRed = "\u{1B}[31m"
    private static let fgCyan = "\u{1B}[36m"
    private static let tarn = "\(bold)\(bgYellow)\(fgBlack)"

    public static func prompt(message: PromptRequestMessage) -> PromptResponseMessage {
        print("")
        print("\(tarn) TARN \(reset)\(bold) Access Request \(reset)")
        print("\(tarn) >> \(reset) \(message.description)")
        print("\(tarn) >> \(reset) \(fgCyan)Process: \(message.processPath) (PID \(message.pid))\(reset)")
        print("")
        print("  \(fgGreen)\(bold)[a]\(reset) Allow once")
        if message.canRemember {
            print("  \(fgGreen)\(bold)[A]\(reset) Allow and remember")
        }
        print("  \(fgRed)\(bold)[d]\(reset) Deny")
        if !message.canRemember {
            print("  \(fgCyan)note: raw IP cannot be remembered\(reset)")
        }
        print("")
        let choices = message.canRemember ? "[a/A/d]" : "[a/d]"
        print("\(tarn) ? \(reset) \(choices): ", terminator: "")
        fflush(stdout)

        let input = readLine()
        let response = PromptMapping.mapInput(input, message: message)
        if response.action == "deny" && input != nil && input != "d" && input != "" {
            print("  \(fgRed)Unknown choice, denying.\(reset)")
        }
        return response
    }
}
