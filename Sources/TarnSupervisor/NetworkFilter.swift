import Foundation
import NetworkExtension
import TarnCore

/// NEFilterDataProvider subclass that intercepts outbound network flows
/// from supervised processes. Identifies the source process by audit
/// token, extracts the destination hostname (from remoteHostname, TLS
/// SNI, or raw IP fallback), and routes the decision through the shared
/// DecisionEngine.
///
/// Novel flows are paused via `pauseVerdict()` while the user is
/// prompted through XPC. TCP flows can be paused indefinitely; UDP
/// flows must be resolved within ~10 seconds or macOS auto-drops them,
/// so a watchdog timer auto-denies UDP flows after 8 seconds.
///
/// This provider does NOT use a synchronous semaphore wait inside
/// `handleNewFlow` — that pattern is a documented anti-pattern that
/// starves the provider thread pool.
class NetworkFilter: NEFilterDataProvider {

    /// Shared reference so XPCService invalidation handler can drain flows.
    static weak var current: NetworkFilter?

    /// Track paused flows for the resume callback.
    private var pausedFlows: [String: NEFilterFlow] = [:]
    private var pausedFlowOrder: [String] = []  // FIFO for eviction
    private let flowLock = NSLock()
    private let maxPausedFlows = 1000

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        NetworkFilter.current = self
        NSLog("tarn: network filter starting")

        // Wire the DecisionEngine to the XPC service
        DecisionEngine.shared.promptService = XPCService.shared

        // Start the XPC listener for CLI connections
        XPCService.shared.start()

        // Start the ES client for file/process events
        do {
            try ESClient.shared.start()
            NSLog("tarn: ES client started")
        } catch {
            NSLog("tarn: ES client failed (expected without entitlement): \(error)")
        }

        completionHandler(nil)
    }

    /// Resume all paused flows with drop. Called on CLI disconnect
    /// (INV-XPC-2) and on filter stop.
    func drainAllPausedFlows() {
        flowLock.lock()
        let flows = pausedFlows
        pausedFlows.removeAll()
        pausedFlowOrder.removeAll()
        flowLock.unlock()
        for (_, flow) in flows {
            resumeFlow(flow, with: NEFilterNewFlowVerdict.drop())
        }
        if !flows.isEmpty {
            NSLog("tarn: drained \(flows.count) paused flows with deny")
        }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        NSLog("tarn: network filter stopping (reason: \(reason.rawValue))")
        drainAllPausedFlows()
        NetworkFilter.current = nil
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow else {
            return .allow()
        }

        // F39: Extract source PID from audit token. If the token is
        // missing or malformed, drop — we cannot identify the source
        // process, so allowing would bypass supervision entirely.
        guard let tokenData = flow.sourceAppAuditToken,
              tokenData.count == MemoryLayout<audit_token_t>.size else {
            NSLog("tarn: dropping flow with missing/malformed audit token")
            return .drop()
        }
        let pid = tokenData.withUnsafeBytes { ptr -> pid_t in
            let token = ptr.load(as: audit_token_t.self)
            return audit_token_to_pid(token)
        }

        // Only supervise processes in the agent's tree
        guard DecisionEngine.shared.processTree.isSupervised(pid: pid) else {
            return .allow()
        }

        // Extract hostname
        let hostname: String
        if let remoteHost = socketFlow.remoteHostname, !remoteHost.isEmpty {
            hostname = remoteHost
        } else if let endpoint = socketFlow.remoteEndpoint as? NWHostEndpoint {
            // No hostname available — use the IP as identifier
            hostname = endpoint.hostname
        } else {
            // F40: No hostname and no remote endpoint — cannot identify
            // destination. Drop to prevent unidentifiable exfiltration.
            NSLog("tarn: dropping supervised flow with no identifiable destination (pid %d)", pid)
            return .drop()
        }

        // Build an AccessRequest for the decision engine
        // sourceAppIdentifier is iOS-only; on macOS use the audit token
        let processPath = "pid:\(pid)"
        let request = AccessRequest(
            kind: .networkConnect(domain: hostname),
            pid: pid,
            processPath: processPath
        )

        // Quick decision (deny set, allow set, session cache)
        if let quick = DecisionEngine.shared.quickDecide(request: request) {
            return quick == .allow ? .allow() : .drop()
        }

        // Need a prompt — pause the flow and ask via XPC
        let flowId = UUID().uuidString
        var evictedFlow: NEFilterFlow?
        flowLock.lock()
        // Evict oldest if at capacity — collect under lock, resume after
        if pausedFlows.count >= maxPausedFlows, let oldest = pausedFlowOrder.first {
            pausedFlowOrder.removeFirst()
            evictedFlow = pausedFlows.removeValue(forKey: oldest)
        }
        pausedFlows[flowId] = flow
        pausedFlowOrder.append(flowId)
        flowLock.unlock()
        // Resume evicted flow OUTSIDE the lock to avoid deadlock
        if let evicted = evictedFlow {
            resumeFlow(evicted, with: NEFilterNewFlowVerdict.drop())
        }

        // Route through the shared async decision engine (handles
        // prompt, persist-via-CLI, and session cache)
        DecisionEngine.shared.asyncDecide(request: request) { [weak self] action in
            guard let self = self else { return }
            self.flowLock.lock()
            guard let pausedFlow = self.pausedFlows.removeValue(forKey: flowId) else {
                self.flowLock.unlock()
                return
            }
            self.pausedFlowOrder.removeAll(where: { $0 == flowId })
            self.flowLock.unlock()

            let verdict: NEFilterNewFlowVerdict = action == .allow ? .allow() : .drop()
            self.resumeFlow(pausedFlow, with: verdict)
        }

        // Start UDP watchdog — auto-deny after 8 seconds
        if socketFlow.socketType == SOCK_DGRAM {
            DispatchQueue.global().asyncAfter(deadline: .now() + 8) { [weak self] in
                guard let self = self else { return }
                self.flowLock.lock()
                guard let udpFlow = self.pausedFlows.removeValue(forKey: flowId) else {
                    self.flowLock.unlock()
                    return
                }
                self.pausedFlowOrder.removeAll(where: { $0 == flowId })
                self.flowLock.unlock()
                let udpCacheKey = "udp-timeout:host:\(hostname)"
                DecisionEngine.shared.sessionCache.record(key: udpCacheKey, action: .deny)
                self.resumeFlow(udpFlow, with: NEFilterNewFlowVerdict.drop())
                NSLog("tarn: auto-denied UDP flow to \(hostname) due to 10s deadline")
            }
        }

        return .pause()
    }

}
