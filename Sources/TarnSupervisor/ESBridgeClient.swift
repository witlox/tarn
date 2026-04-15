import Foundation
import TarnCore

/// XPC client that connects to the ES system extension and forwards
/// network flow evaluations. Also receives supervised token notifications
/// from the ES extension so the NE filter only intercepts flows from
/// supervised processes — same pattern as ES inverted muting.
///
/// F-02: Uses audit token Data (not bare PIDs) to prevent PID reuse.
/// F-05: Periodic heartbeat detects ES extension crashes.
/// F-28: Lock around connection creation prevents double-connect race.
///
/// SAFETY: All error paths fail-open (.allow). The NE filter must NEVER
/// block traffic it cannot evaluate.
final class ESBridgeClient: NSObject {
    static let shared = ESBridgeClient()
    private var connection: NSXPCConnection?
    /// F-28: Lock to prevent double-connect race.
    private let connectLock = NSLock()

    /// I-02: Timeout for ES extension responses. Must be long enough for
    /// user prompts (30s). The ES deadline is 25s, so 30s covers both.
    /// If exceeded, allow the flow (fail-open safety net).
    private let evaluateTimeout: TimeInterval = 30.0

    /// F-02: Supervised audit tokens, pushed by the ES extension.
    /// Store full token data for PID-reuse-safe comparison.
    private var supervisedTokens: Set<Data> = []
    /// F-02: Also maintain PID set for fast PID-based lookup.
    private var supervisedPIDs: Set<Int32> = []
    private let pidLock = NSLock()

    /// F-05: Whether the ES extension is reachable.
    private var esAlive = true
    private var heartbeatFailCount = 0
    private var heartbeatTimer: DispatchSourceTimer?

    override init() {
        super.init()
        startHeartbeat()
    }

    /// Check if a PID is supervised (fast path).
    /// F-05: Returns false when ES extension is confirmed dead (fail-open).
    func isSupervised(pid: Int32) -> Bool {
        pidLock.lock()
        defer { pidLock.unlock() }
        guard esAlive else { return false }
        return supervisedPIDs.contains(pid)
    }

    /// F-02: Check if a full audit token is supervised (PID-reuse-safe).
    func isSupervised(tokenData: Data) -> Bool {
        pidLock.lock()
        defer { pidLock.unlock() }
        guard esAlive else { return false }
        return supervisedTokens.contains(tokenData)
    }

    func connect() {
        // F-28: Guard against double-connect race.
        connectLock.lock()
        defer { connectLock.unlock() }
        guard connection == nil else { return }

        let conn = NSXPCConnection(machServiceName: kTarnESMachServiceName)
        conn.remoteObjectInterface = NSXPCInterface(with: TarnNetworkEvalXPC.self)
        // Export callback interface so ES extension can push token updates
        conn.exportedInterface = NSXPCInterface(with: TarnNECallbackXPC.self)
        conn.exportedObject = self
        conn.invalidationHandler = { [weak self] in
            self?.connectLock.lock()
            self?.connection = nil
            self?.connectLock.unlock()
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

    // MARK: - F-05: Heartbeat

    private func startHeartbeat() {
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global())
        timer.schedule(deadline: .now() + 5, repeating: 5)
        timer.setEventHandler { [weak self] in
            self?.sendHeartbeat()
        }
        timer.resume()
        heartbeatTimer = timer
    }

    private func sendHeartbeat() {
        guard let proxy = connection?.remoteObjectProxyWithErrorHandler({ [weak self] _ in
            guard let self = self else { return }
            self.pidLock.lock()
            self.heartbeatFailCount += 1
            if self.heartbeatFailCount >= 3 {
                self.esAlive = false
                NSLog("tarn-ne: ES extension unreachable after 3 heartbeat failures — isSupervised returns false (fail-open)")
            }
            self.pidLock.unlock()
        }) as? TarnNetworkEvalXPC else {
            return
        }

        proxy.heartbeat { [weak self] alive in
            guard let self = self else { return }
            self.pidLock.lock()
            self.heartbeatFailCount = 0
            if !self.esAlive {
                NSLog("tarn-ne: ES extension recovered — resuming supervision")
            }
            self.esAlive = alive
            self.pidLock.unlock()
        }
    }

    /// Extract PID from audit token data.
    private static func pidFromTokenData(_ data: Data) -> Int32? {
        guard data.count == MemoryLayout<audit_token_t>.size else { return nil }
        return data.withUnsafeBytes { ptr in
            let token = ptr.load(as: audit_token_t.self)
            return audit_token_to_pid(token)
        }
    }
}

// MARK: - Token notifications from ES extension (F-02)

extension ESBridgeClient: TarnNECallbackXPC {
    func addSupervisedToken(_ tokenData: Data) {
        pidLock.lock()
        supervisedTokens.insert(tokenData)
        if let pid = ESBridgeClient.pidFromTokenData(tokenData) {
            supervisedPIDs.insert(pid)
        }
        pidLock.unlock()
    }

    func removeSupervisedToken(_ tokenData: Data) {
        pidLock.lock()
        supervisedTokens.remove(tokenData)
        if let pid = ESBridgeClient.pidFromTokenData(tokenData) {
            supervisedPIDs.remove(pid)
        }
        pidLock.unlock()
    }

    func clearSupervisedTokens() {
        pidLock.lock()
        supervisedTokens.removeAll()
        supervisedPIDs.removeAll()
        pidLock.unlock()
    }
}
