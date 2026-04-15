import Foundation
import os.log
import TarnCore

private let log = OSLog(subsystem: "com.witlox.tarn.es", category: "main")

@main
enum ESExtensionEntry {
    static func main() {
        os_log(.error, log: log, "tarn-es: starting")
        DecisionEngine.shared.promptService = ESXPCService.shared
        ESXPCService.shared.start()
        os_log(.error, log: log, "tarn-es: XPC started")
        do {
            try ESClient.shared.start()
            os_log(.error, log: log, "tarn-es: ES client started successfully")
        } catch {
            os_log(.error, log: log, "tarn-es: ES client FAILED: %{public}@", String(describing: error))
        }
        dispatchMain()
    }
}
