import Foundation
import NetworkExtension

// System extension entry point. The extension hosts both the Endpoint
// Security client (file/process supervision) and the NEFilterDataProvider
// (network supervision). It listens for XPC connections from the CLI and
// coordinates the supervised process tree, session cache, and profile
// across both subsystems.
//
// In production, this is launched by macOS as a launchd-managed daemon
// after the user approves the system extension in System Settings.
// For development on a SIP-disabled machine, it can be run directly.

// The NEProvider (NEFilterDataProvider) is instantiated by the NE
// framework; it does not need a manual `main` entry point in the
// typical NE hosting model. The extension's principal class is
// declared in Info.plist under NSExtension/NSExtensionPrincipalClass.
//
// For now, we provide a minimal entry point that keeps the process alive.
// The actual NEFilterDataProvider subclass is in NetworkFilter.swift.

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
