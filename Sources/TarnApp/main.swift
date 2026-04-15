import Foundation
import NetworkExtension
import SystemExtensions

Darwin.write(2, "tarn: app starting\n", 19)

class Activator: NSObject, OSSystemExtensionRequestDelegate {

    private var isDeactivating = false

    func start() {
        // If --reset flag is passed, disable filter, then replace extension
        if CommandLine.arguments.contains("--reset") {
            disableFilterThenActivate()
        } else {
            activate()
        }
    }

    func disableFilterThenActivate() {
        fputs("tarn: disabling NE filter before replacement...\n", stderr)
        NEFilterManager.shared().loadFromPreferences { [self] error in
            if let error = error {
                fputs("tarn: load error: \(error), trying activation anyway...\n", stderr)
                activate()
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
                // Give nesessionmanager time to stop the filter session
                DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [self] in
                    activate()
                }
            }
        }
    }

    func activate() {
        isDeactivating = false
        fputs("tarn: submitting activation request...\n", stderr)
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
            // Small delay to let the system clean up
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [self] in
                activate()
            }
        } else {
            fputs("tarn: system extension activated\n", stderr)
            enableFilter()
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        let nsError = error as NSError
        if isDeactivating {
            // Deactivation failed — try activating anyway
            fputs("tarn: deactivation failed (code \(nsError.code)), trying activation...\n", stderr)
            activate()
        } else {
            // Code 1 = extension already activated — that's fine
            if nsError.code == 1 {
                fputs("tarn: extension already active, configuring filter...\n", stderr)
                enableFilter()
            } else {
                fputs("tarn: activation failed (code \(nsError.code)): \(nsError.localizedDescription)\n", stderr)
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
