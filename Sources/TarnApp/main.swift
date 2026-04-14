import Foundation
import NetworkExtension
import SystemExtensions

Darwin.write(2, "tarn: app starting\n", 19)

class Activator: NSObject, OSSystemExtensionRequestDelegate {

    func activate() {
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
        fputs("tarn: system extension activated\n", stderr)
        enableFilter()
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        let nsError = error as NSError
        // Code 1 = extension already activated — that's fine
        if nsError.code == 1 {
            fputs("tarn: extension already active, configuring filter...\n", stderr)
            enableFilter()
        } else {
            fputs("tarn: activation failed (code \(nsError.code)): \(nsError.localizedDescription)\n", stderr)
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
activator.activate()
RunLoop.current.run()
