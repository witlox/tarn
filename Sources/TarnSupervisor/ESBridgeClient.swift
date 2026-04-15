import Foundation
import TarnCore

/// XPC client that connects to the ES system extension and forwards
/// network flow evaluations. The NE filter uses this to delegate all
/// decision-making to the ES extension, which hosts the DecisionEngine,
/// ProcessTree, SessionCache, and Config.
///
/// SAFETY: All error paths fail-open (.allow). The NE filter must NEVER
/// block traffic it cannot evaluate. A timeout ensures we don't wait
/// forever if the ES extension hangs.
final class ESBridgeClient {
    static let shared = ESBridgeClient()
    private var connection: NSXPCConnection?

    /// Timeout for ES extension responses. If exceeded, allow the flow.
    private let evaluateTimeout: TimeInterval = 2.0

    /// Supervised PIDs, synchronized from ES extension responses.
    /// The NE filter checks this to skip XPC for non-supervised flows.
    private var supervisedPIDs: Set<Int32> = []
    private let pidLock = NSLock()

    /// Check if a PID might be supervised. If no session is active
    /// (empty set), returns false and the NE filter allows immediately.
    func isSupervised(pid: Int32) -> Bool {
        pidLock.lock()
        defer { pidLock.unlock() }
        return supervisedPIDs.contains(pid)
    }

    /// Register a PID as supervised (called when ES extension confirms).
    func addSupervisedPID(_ pid: Int32) {
        pidLock.lock()
        supervisedPIDs.insert(pid)
        pidLock.unlock()
    }

    /// Clear all supervised PIDs (session ended).
    func clearSupervisedPIDs() {
        pidLock.lock()
        supervisedPIDs.removeAll()
        pidLock.unlock()
    }

    /// Whether any session is active.
    var hasActiveSession: Bool {
        pidLock.lock()
        defer { pidLock.unlock() }
        return !supervisedPIDs.isEmpty
    }

    func connect() {
        let conn = NSXPCConnection(machServiceName: kTarnESBridgeMachServiceName)
        conn.remoteObjectInterface = NSXPCInterface(with: TarnNetworkEvalXPC.self)
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

        proxy.evaluateFlow(data) { [weak self] responseData in
            guard let response = try? JSONDecoder().decode(NetworkFlowResponse.self, from: responseData) else {
                safeReply(.allow)
                return
            }
            // Learn supervised PIDs from ES extension responses
            if response.supervised {
                self?.addSupervisedPID(request.pid)
            }
            safeReply(response.action == "allow" ? .allow : .deny)
        }
    }
}
