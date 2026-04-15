import EndpointSecurity
import Foundation
import TarnCore

/// Manages the Endpoint Security client for file and process
/// supervision. Subscribes to AUTH_OPEN for file access control and
/// NOTIFY_FORK/NOTIFY_EXIT for process tree maintenance.
///
/// Network supervision is NOT handled here — that is the
/// NetworkFilter (NEFilterDataProvider). Both share the same
/// ProcessTree and DecisionEngine.
final class ESClient {
    static let shared = ESClient()

    private var client: OpaquePointer?
    var isAvailable: Bool { true } // runtime check could go here

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

    func registerAgentPID(_ pid: pid_t) {
        DecisionEngine.shared.processTree.addRoot(pid: pid)
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
            // F20: Only AUTH events require a response. NOTIFY events
            // must NOT be responded to — calling es_respond_auth_result
            // on a NOTIFY message is undefined behaviour.
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
        }
    }

    private func handleExit(_ message: UnsafePointer<es_message_t>) {
        let pid = audit_token_to_pid(message.pointee.process.pointee.audit_token)
        DecisionEngine.shared.processTree.remove(pid: pid)
    }

    private func handleAuthOpen(_ message: UnsafePointer<es_message_t>) {
        guard let client = client else { return }

        // Fast path: no supervised session → allow everything instantly.
        let tree = DecisionEngine.shared.processTree
        guard !tree.isEmpty else {
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
            return
        }

        let msg = message.pointee
        let pid = audit_token_to_pid(msg.process.pointee.audit_token)

        guard tree.isSupervised(pid: pid) else {
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
            return
        }

        let event = msg.event.open
        let path = String(cString: event.file.pointee.path.data)
        let flags = event.fflag
        let isWrite = (Int32(flags) & FWRITE) != 0
        let engine = DecisionEngine.shared

        // Deny set is checked FIRST — before trusted regions.
        // A denied path is denied regardless of where it is.
        // Patterns are pre-expanded with the user's home (not root's).
        let currentConfig = engine.config
        if currentConfig.isDeniedExpanded(path: path) {
            es_respond_auth_result(client, message, ES_AUTH_RESULT_DENY, false)
            return
        }

        // Trusted regions — system paths are read-only; workspace and
        // /tmp allow reads and writes.
        if engine.isInTrustedRegion(path: path, isWrite: isWrite) {
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
            return
        }

        let processPath = String(cString: msg.process.pointee.executable.pointee.path.data)
        let kind: AccessRequest.Kind = isWrite ? .fileWrite(path: path) : .fileRead(path: path)
        let request = AccessRequest(kind: kind, pid: pid, processPath: processPath)

        // Async decision: retain the message, respond from the callback.
        // F18: The callback captures `self` (not the local `client`) so
        // that a stop() between retain and callback doesn't use a stale
        // pointer. If client is nil the message was already released by
        // es_delete_client.
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
