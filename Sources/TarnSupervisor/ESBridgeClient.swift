import Foundation
import TarnCore

/// XPC client that connects to the ES system extension and forwards
/// network flow evaluations. Also receives supervised PID notifications
/// from the ES extension so the NE filter only intercepts flows from
/// supervised processes — same pattern as ES inverted muting.
///
/// SAFETY: All error paths fail-open (.allow). The NE filter must NEVER
/// block traffic it cannot evaluate.
final class ESBridgeClient: NSObject {
    static let shared = ESBridgeClient()
    private var connection: NSXPCConnection?

    /// Timeout for ES extension responses. If exceeded, allow the flow.
    private let evaluateTimeout: TimeInterval = 2.0

    /// Supervised PIDs, pushed by the ES extension via TarnNECallbackXPC.
    /// Only flows from these PIDs are paused and forwarded for evaluation.
    private var supervisedPIDs: Set<Int32> = []
    private let pidLock = NSLock()

    /// Check if a PID is supervised. If not, the NE filter allows immediately.
    func isSupervised(pid: Int32) -> Bool {
        pidLock.lock()
        defer { pidLock.unlock() }
        return supervisedPIDs.contains(pid)
    }

    func connect() {
        let conn = NSXPCConnection(machServiceName: kTarnESMachServiceName)
        conn.remoteObjectInterface = NSXPCInterface(with: TarnNetworkEvalXPC.self)
        // Export callback interface so ES extension can push PID updates
        conn.exportedInterface = NSXPCInterface(with: TarnNECallbackXPC.self)
        conn.exportedObject = self
        conn.invalidationHandler = { [weak self] in
            self?.connection = nil
        }
        conn.resume()
        connection = conn
    }

    func evaluate(_ request: NetworkFlowRequest, reply: @escaping (AccessAction) -> Void) {
        if connection == nil {
            connect()
        }
        guard let proxy = connection?.remoteObjectProxyWithErrorHandler({ _ in
            reply(.allow)
        }) as? TarnNetworkEvalXPC else {
            reply(.allow)
            return
        }
        guard let data = try? JSONEncoder().encode(request) else {
            reply(.allow)
            return
        }

        // Track whether we've already replied (timeout vs response race)
        var replied = false
        let replyLock = NSLock()

        func safeReply(_ action: AccessAction) {
            replyLock.lock()
            defer { replyLock.unlock() }
            guard !replied else { return }
            replied = true
            reply(action)
        }

        // Timeout: fail-open if ES extension doesn't respond
        DispatchQueue.global().asyncAfter(deadline: .now() + evaluateTimeout) {
            safeReply(.allow)
        }

        proxy.evaluateFlow(data) { responseData in
            guard let response = try? JSONDecoder().decode(NetworkFlowResponse.self, from: responseData) else {
                safeReply(.allow)
                return
            }
            safeReply(response.action == "allow" ? .allow : .deny)
        }
    }
}

// MARK: - PID notifications from ES extension

extension ESBridgeClient: TarnNECallbackXPC {
    func addSupervisedPID(_ pid: Int32) {
        pidLock.lock()
        supervisedPIDs.insert(pid)
        pidLock.unlock()
    }

    func removeSupervisedPID(_ pid: Int32) {
        pidLock.lock()
        supervisedPIDs.remove(pid)
        pidLock.unlock()
    }

    func clearSupervisedPIDs() {
        pidLock.lock()
        supervisedPIDs.removeAll()
        pidLock.unlock()
    }
}
