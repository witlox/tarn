import Foundation
import TarnCore

@main
enum ESExtensionEntry {
    static func main() {
        DecisionEngine.shared.promptService = ESXPCService.shared
        ESXPCService.shared.start()
        do {
            try ESClient.shared.start()
        } catch {
            NSLog("tarn-es: ES client failed: %@", String(describing: error))
        }
        dispatchMain()
    }
}
