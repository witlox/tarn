import Foundation
import SystemExtensions

/// Minimal host app bundle for the tarn system extension.
/// LSUIElement=YES in Info.plist — no dock icon, no UI. Its only job
/// is to contain the system extension at
/// Contents/Library/SystemExtensions/ and to provide the activation
/// entry point via OSSystemExtensionRequest.
///
/// In production, the CLI (Contents/MacOS/tarn) is what the user
/// invokes. The CLI checks whether the extension is active and, if
/// not, launches this app briefly to trigger activation.

class ExtensionActivator: NSObject, OSSystemExtensionRequestDelegate {
    let semaphore = DispatchSemaphore(value: 0)
    var result: Result<Void, Error> = .success(())

    func activate() throws {
        let identifier = "com.witlox.tarn.supervisor"
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: identifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)

        // Wait for the delegate callback
        semaphore.wait()
        try result.get()
    }

    // MARK: - OSSystemExtensionRequestDelegate

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        print("Please approve the tarn system extension in System Settings → General → Login Items & Extensions.")
    }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        switch result {
        case .completed:
            self.result = .success(())
        case .willCompleteAfterReboot:
            self.result = .success(())
            print("System extension will be active after reboot.")
        @unknown default:
            self.result = .failure(NSError(domain: "tarn", code: 2,
                                           userInfo: [NSLocalizedDescriptionKey: "Unknown activation result"]))
        }
        semaphore.signal()
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        self.result = .failure(error)
        semaphore.signal()
    }
}

// Entry point — activate the extension if invoked directly
let activator = ExtensionActivator()
do {
    try activator.activate()
    print("tarn system extension activated.")
} catch {
    fputs("Failed to activate system extension: \(error)\n", stderr)
    exit(1)
}
