import Foundation
import NetworkExtension
import SystemExtensions

Darwin.write(2, "tarn: app starting\n", 19)

// MARK: - Emergency kill switch

if CommandLine.arguments.contains("--kill") {
    fputs("tarn: EMERGENCY KILL — removing NE filter config...\n", stderr)
    let sem = DispatchSemaphore(value: 0)
    NEFilterManager.shared().loadFromPreferences { _ in
        let mgr = NEFilterManager.shared()
        mgr.isEnabled = false
        mgr.removeFromPreferences { error in
            if let error = error {
                fputs("tarn: remove error: \(error.localizedDescription)\n", stderr)
                // Try just disabling as fallback
                mgr.isEnabled = false
                mgr.saveToPreferences { error2 in
                    fputs(error2 == nil ? "tarn: filter disabled\n" : "tarn: disable also failed: \(error2!)\n", stderr)
                    sem.signal()
                }
            } else {
                fputs("tarn: filter config removed. Internet should be restored.\n", stderr)
                sem.signal()
            }
        }
    }
    sem.wait()
    fputs("tarn: done. You may need to reboot if extensions are still misbehaving.\n", stderr)
    exit(0)
}

class Activator: NSObject, OSSystemExtensionRequestDelegate {

    private var isDeactivating = false
    private var activatingES = false

    func start() {
        if CommandLine.arguments.contains("--reset") {
            disableFilterThenActivate()
        } else {
            activateES()
        }
    }

    func disableFilterThenActivate() {
        fputs("tarn: disabling NE filter before replacement...\n", stderr)
        NEFilterManager.shared().loadFromPreferences { [self] error in
            if let error = error {
                fputs("tarn: load error: \(error), trying activation anyway...\n", stderr)
                activateES()
                return
            }
            let mgr = NEFilterManager.shared()
            mgr.isEnabled = false
            mgr.saveToPreferences { [self] error in
                if let error = error {
                    fputs("tarn: disable error: \(error), trying activation anyway...\n", stderr)
                } else {
                    fputs("tarn: filter disabled, waiting for cleanup...\n", stderr)
                }
                // Deactivate both extensions
                DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [self] in
                    activateES()
                }
            }
        }
    }

    /// Step 1: Activate the ES system extension
    func activateES() {
        isDeactivating = false
        activatingES = true
        fputs("tarn: submitting ES extension activation request...\n", stderr)
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: "com.witlox.tarn.es",
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Step 2: Activate the NE supervisor extension
    func activateNE() {
        isDeactivating = false
        activatingES = false
        fputs("tarn: submitting NE extension activation request...\n", stderr)
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: "com.witlox.tarn.supervisor",
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        fputs("tarn: replacing existing extension\n", stderr)
        return .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        fputs("tarn: user approval needed — check System Settings → General → Login Items & Extensions\n", stderr)
    }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        if isDeactivating {
            fputs("tarn: extension deactivated, now reactivating...\n", stderr)
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [self] in
                activateES()
            }
        } else if activatingES {
            fputs("tarn: ES system extension activated\n", stderr)
            // Now activate the NE extension
            activateNE()
        } else {
            fputs("tarn: NE system extension activated\n", stderr)
            enableFilter()
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        let nsError = error as NSError
        if isDeactivating {
            fputs("tarn: deactivation failed (code \(nsError.code)), trying activation...\n", stderr)
            activateES()
        } else if activatingES {
            // Code 1 = extension already activated — that's fine
            if nsError.code == 1 {
                fputs("tarn: ES extension already active, activating NE extension...\n", stderr)
                activateNE()
            } else {
                fputs("tarn: ES activation failed (code \(nsError.code)): \(nsError.localizedDescription)\n", stderr)
            }
        } else {
            // NE extension activation
            if nsError.code == 1 {
                fputs("tarn: NE extension already active, configuring filter...\n", stderr)
                enableFilter()
            } else {
                fputs("tarn: NE activation failed (code \(nsError.code)): \(nsError.localizedDescription)\n", stderr)
            }
        }
    }
}

func enableFilter() {
    NEFilterManager.shared().loadFromPreferences { error in
        if let error = error {
            fputs("tarn: load error: \(error.localizedDescription)\n", stderr)
        }

        let manager = NEFilterManager.shared()

        let config = NEFilterProviderConfiguration()
        config.filterBrowsers = false
        config.filterSockets = true

        manager.providerConfiguration = config
        manager.localizedDescription = "Tarn"
        manager.isEnabled = true

        manager.saveToPreferences { error in
            if let error = error {
                fputs("tarn: filter save error: \(error.localizedDescription)\n", stderr)
            } else {
                fputs("tarn: content filter enabled\n", stderr)
            }
        }
    }
}

let activator = Activator()
activator.start()
RunLoop.current.run()
