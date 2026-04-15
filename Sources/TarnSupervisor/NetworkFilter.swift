import Foundation
import NetworkExtension
import TarnCore

/// NEFilterDataProvider subclass that intercepts outbound network flows
/// from supervised processes. Extracts PID and hostname from each flow,
/// then forwards to the ES extension via XPC for the actual decision.
///
/// The NE extension is a thin proxy — all policy decisions (deny set,
/// allow set, session cache, user prompts) happen in the ES extension
/// which hosts the DecisionEngine, ProcessTree, and SessionCache.
///
/// Novel flows are paused via `pauseVerdict()` while the ES extension
/// evaluates them. TCP flows can be paused indefinitely; UDP flows must
/// be resolved within ~10 seconds or macOS auto-drops them, so a
/// watchdog timer auto-denies UDP flows after 8 seconds.
class NetworkFilter: NEFilterDataProvider {

    /// Shared reference so external code can drain flows if needed.
    static weak var current: NetworkFilter?

    /// Track paused flows for the resume callback.
    private var pausedFlows: [String: NEFilterFlow] = [:]
    private var pausedFlowOrder: [String] = []  // FIFO for eviction
    private let flowLock = NSLock()
    private let maxPausedFlows = 1000

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        NetworkFilter.current = self
        NSLog("tarn-ne: network filter starting")

        // Connect to the ES extension for flow evaluation
        ESBridgeClient.shared.connect()
        NSLog("tarn-ne: connected to ES extension")

        completionHandler(nil)
    }

    /// Resume all paused flows with ALLOW. Called on filter stop
    /// and session teardown. Fail-open: never block flows on shutdown.
    func drainAllPausedFlows() {
        flowLock.lock()
        let flows = pausedFlows
        pausedFlows.removeAll()
        pausedFlowOrder.removeAll()
        flowLock.unlock()
        for (_, flow) in flows {
            resumeFlow(flow, with: NEFilterNewFlowVerdict.allow())
        }
        if !flows.isEmpty {
            NSLog("tarn-ne: drained \(flows.count) paused flows with allow")
        }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        NSLog("tarn-ne: network filter stopping (reason: \(reason.rawValue))")
        drainAllPausedFlows()
        NetworkFilter.current = nil
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        // Fast path: no active session → allow everything instantly.
        // This ensures tarn NEVER affects non-supervised traffic.
        guard ESBridgeClient.shared.hasActiveSession else { return .allow() }

        guard let socketFlow = flow as? NEFilterSocketFlow else {
            return .allow()
        }

        // No audit token → not a user-space app → allow.
        guard let tokenData = flow.sourceAppAuditToken,
              tokenData.count == MemoryLayout<audit_token_t>.size else {
            return .allow()
        }
        let pid = tokenData.withUnsafeBytes { ptr -> pid_t in
            let token = ptr.load(as: audit_token_t.self)
            return audit_token_to_pid(token)
        }

        // Not supervised → allow immediately, no XPC needed.
        guard ESBridgeClient.shared.isSupervised(pid: pid) else {
            return .allow()
        }

        // Extract hostname
        let hostname: String
        if let remoteHost = socketFlow.remoteHostname, !remoteHost.isEmpty {
            hostname = remoteHost
        } else if let endpoint = socketFlow.remoteEndpoint as? NWHostEndpoint {
            hostname = endpoint.hostname
        } else {
            // No hostname and no remote endpoint — allow rather than
            // block. Fail-open: never block flows we can't evaluate.
            return .allow()
        }

        let isUDP = socketFlow.socketType == SOCK_DGRAM

        // Build request for the ES extension
        let request = NetworkFlowRequest(pid: pid, hostname: hostname, isUDP: isUDP)

        // Pause the flow and forward to ES extension via XPC
        let flowId = UUID().uuidString
        var evictedFlow: NEFilterFlow?
        flowLock.lock()
        // Evict oldest if at capacity
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

        // Forward to ES extension for decision
        ESBridgeClient.shared.evaluate(request) { [weak self] action in
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
        if isUDP {
            DispatchQueue.global().asyncAfter(deadline: .now() + 8) { [weak self] in
                guard let self = self else { return }
                self.flowLock.lock()
                guard let udpFlow = self.pausedFlows.removeValue(forKey: flowId) else {
                    self.flowLock.unlock()
                    return
                }
                self.pausedFlowOrder.removeAll(where: { $0 == flowId })
                self.flowLock.unlock()
                self.resumeFlow(udpFlow, with: NEFilterNewFlowVerdict.drop())
                NSLog("tarn-ne: auto-denied UDP flow to \(hostname) due to 10s deadline")
            }
        }

        return .pause()
    }

}
