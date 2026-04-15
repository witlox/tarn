import Foundation
import NetworkExtension
import TarnCore

// DEV-ONLY standalone entry point for running the supervisor outside
// the system extension context (requires SIP disabled). Excluded from
// the Xcode TarnSupervisor target via project.yml.
//
// In production the NE framework provides the entry point: it
// instantiates NetworkFilter (declared in NEProviderClasses) and
// calls startFilter(). Having a main() in the sysext binary
// prevents the NE lifecycle from starting, causing nesessionmanager
// to timeout and crash-loop the extension.
//
// To use: swift build && sudo .build/debug/com.witlox.tarn.supervisor

autoreleasepool {
    // Wire the DecisionEngine to the XPC service so prompt requests
    // can reach the CLI. Without this, asyncDecide falls through to
    // deny for every unknown path (the promptService reference is nil).
    DecisionEngine.shared.promptService = XPCService.shared

    // Start the XPC listener for CLI connections
    let service = XPCService.shared
    service.start()

    // Start the ES client for file/process events
    // (Only when running as a system extension with the entitlement)
    if ESClient.shared.isAvailable {
        do {
            try ESClient.shared.start()
        } catch {
            NSLog("tarn supervisor: failed to start ES client: \(error)")
        }
    }

    // Keep the extension alive
    RunLoop.current.run()
}
