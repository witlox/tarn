import Foundation
import NetworkExtension

// Entry point for the NE provider system extension.
// Registers with the NE framework via startSystemExtensionMode(),
// then enters the dispatch event loop. The NE framework instantiates
// NetworkFilter (from NEProviderClasses in Info.plist) and calls
// startFilter(completionHandler:).
//
// All initialization (XPC, ES client) happens inside startFilter().
// Do NOT add initialization code here.

@main
enum SupervisorEntry {
    static func main() {
        autoreleasepool {
            NEProvider.startSystemExtensionMode()
        }
        dispatchMain()
    }
}
