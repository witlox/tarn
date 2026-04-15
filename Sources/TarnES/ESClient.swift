import EndpointSecurity
import Foundation
import TarnCore

/// Manages the Endpoint Security client for file and process
/// supervision. Uses inverted process muting so AUTH_OPEN only
/// fires for supervised PIDs — zero overhead for everything else.
///
/// Process tree tracking (NOTIFY_FORK/EXIT) is always active and
/// never muted. When a supervised parent forks, the child is
/// automatically unmuted using its audit token from the fork event.
final class ESClient {
    static let shared = ESClient()

    private var client: OpaquePointer?

    private init() {}

    func start() throws {
        var newClient: OpaquePointer?

        let result = es_new_client(&newClient) { [weak self] _, message in
            guard let self = self else {
                if message.pointee.event_type == ES_EVENT_TYPE_AUTH_OPEN, let client = newClient {
                    es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
                }
                return
            }
            self.handleEvent(message)
        }

        guard result == ES_NEW_CLIENT_RESULT_SUCCESS else {
            throw MonitorError.clientCreationFailed(result)
        }

        self.client = newClient

        // Invert process muting: all processes muted by default.
        // Only explicitly unmuted PIDs trigger AUTH_OPEN callbacks.
        // NOTIFY events are never affected by muting.
        es_invert_muting(newClient!, ES_MUTE_INVERSION_TYPE_PROCESS)

        // Subscribe to everything upfront. AUTH_OPEN only fires for
        // unmuted (supervised) processes. NOTIFY fires for all.
        let events: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_OPEN,
            ES_EVENT_TYPE_NOTIFY_FORK,
            ES_EVENT_TYPE_NOTIFY_EXIT,
        ]
        let subResult = es_subscribe(newClient!, events, UInt32(events.count))
        guard subResult == ES_RETURN_SUCCESS else {
            throw MonitorError.subscriptionFailed
        }
    }

    func stop() {
        if let client = client {
            es_unsubscribe_all(client)
            es_delete_client(client)
            self.client = nil
        }
    }

    /// Register a supervised PID and unmute it for AUTH_OPEN.
    /// The audit token is obtained via task_info.
    func registerAgentPID(_ pid: pid_t) {
        DecisionEngine.shared.processTree.addRoot(pid: pid)
        unmuteByPID(pid)
    }

    /// Unmute a PID so AUTH_OPEN events fire for it.
    private func unmuteByPID(_ pid: pid_t) {
        guard let client = client else { return }
        var token = audit_token_t()
        var taskPort: mach_port_t = 0
        guard task_for_pid(mach_task_self_, pid, &taskPort) == KERN_SUCCESS else {
            return
        }
        var info = mach_msg_type_number_t(
            MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size
        )
        withUnsafeMutablePointer(to: &token) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(info)) { intPtr in
                task_info(taskPort, task_flavor_t(TASK_AUDIT_TOKEN), intPtr, &info)
            }
        }
        mach_port_deallocate(mach_task_self_, taskPort)
        es_unmute_process(client, &token)
    }

    // MARK: - Event dispatch

    private func handleEvent(_ message: UnsafePointer<es_message_t>) {
        let msg = message.pointee
        switch msg.event_type {
        case ES_EVENT_TYPE_NOTIFY_FORK:
            handleFork(message)
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            handleExit(message)
        case ES_EVENT_TYPE_AUTH_OPEN:
            handleAuthOpen(message)
        default:
            break
        }
    }

    private func handleFork(_ message: UnsafePointer<es_message_t>) {
        let msg = message.pointee
        let parentPid = audit_token_to_pid(msg.process.pointee.audit_token)
        let childPid = audit_token_to_pid(msg.event.fork.child.pointee.audit_token)
        let tree = DecisionEngine.shared.processTree
        if tree.isSupervised(pid: parentPid) {
            tree.addChild(pid: childPid, parentPID: parentPid)
            // Unmute the child for ES AUTH_OPEN
            if let client = client {
                var childToken = msg.event.fork.child.pointee.audit_token
                es_unmute_process(client, &childToken)
            }
            // Push to NE extension for network flow filtering
            ESXPCService.shared.notifyNE(addPID: childPid)
        }
    }

    private func handleExit(_ message: UnsafePointer<es_message_t>) {
        let pid = audit_token_to_pid(message.pointee.process.pointee.audit_token)
        let wasSupervised = DecisionEngine.shared.processTree.isSupervised(pid: pid)
        DecisionEngine.shared.processTree.remove(pid: pid)
        if wasSupervised {
            ESXPCService.shared.notifyNE(removePID: pid)
        }
    }

    private func handleAuthOpen(_ message: UnsafePointer<es_message_t>) {
        guard let client = client else { return }
        let msg = message.pointee
        let pid = audit_token_to_pid(msg.process.pointee.audit_token)

        // With inverted muting, only unmuted (supervised) PIDs reach here.
        // Double-check as safety net.
        guard DecisionEngine.shared.processTree.isSupervised(pid: pid) else {
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
            return
        }

        let event = msg.event.open
        let path = String(cString: event.file.pointee.path.data)
        let flags = event.fflag
        let isWrite = (Int32(flags) & FWRITE) != 0
        let engine = DecisionEngine.shared

        if engine.config.isDeniedExpanded(path: path) {
            es_respond_auth_result(client, message, ES_AUTH_RESULT_DENY, false)
            return
        }

        if engine.isInTrustedRegion(path: path, isWrite: isWrite) {
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
            return
        }

        let processPath = String(cString: msg.process.pointee.executable.pointee.path.data)
        let kind: AccessRequest.Kind = isWrite ? .fileWrite(path: path) : .fileRead(path: path)
        let request = AccessRequest(kind: kind, pid: pid, processPath: processPath)

        es_retain_message(message)
        engine.asyncDecide(request: request) { [weak self] action in
            guard let currentClient = self?.client else {
                es_release_message(message)
                return
            }
            let result: es_auth_result_t = (action == .allow) ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
            es_respond_auth_result(currentClient, message, result, false)
            es_release_message(message)
        }
    }
}

enum MonitorError: Error, CustomStringConvertible {
    case clientCreationFailed(es_new_client_result_t)
    case subscriptionFailed

    var description: String {
        switch self {
        case .clientCreationFailed(let result):
            return "Failed to create ES client (result: \(result.rawValue)). " +
                   "Ensure the binary has the endpoint-security.client entitlement " +
                   "and is running as root."
        case .subscriptionFailed:
            return "Failed to subscribe to ES events."
        }
    }
}
