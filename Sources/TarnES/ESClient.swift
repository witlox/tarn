import EndpointSecurity
import Foundation
import os.log
import TarnCore

private let esLog = OSLog(subsystem: "com.witlox.tarn.es", category: "es")

/// Manages the Endpoint Security client for file and process supervision.
///
/// Architecture:
/// - Single ES client with target path muting for system directories
/// - Per-process muting for non-supervised PIDs (handleFork + handleAuthOpen)
/// - Session-scoped subscriptions (zero overhead when idle)
/// - AUTH_OPEN uses es_respond_flags_result (not es_respond_auth_result)
/// - File access: auto-deny unknown paths (no interactive prompts)
///   ES kernel deadline (~15s) is too short for user interaction.
///   Network prompts use the NE extension (30s timeout).
/// - Reads message.pointee.deadline for actual kernel deadline
final class ESClient {
    static let shared = ESClient()

    fileprivate var client: OpaquePointer?

    fileprivate var watchedCLIPIDs: Set<pid_t> = []
    fileprivate var unmutedAgentPIDs: Set<pid_t> = []
    fileprivate let pendingLock = NSLock()

    /// AUTH event types we mute for non-supervised processes.
    static let mutedAuthEvents: [es_event_type_t] = [
        ES_EVENT_TYPE_AUTH_OPEN,
        ES_EVENT_TYPE_AUTH_LINK,
        ES_EVENT_TYPE_AUTH_UNLINK,
        ES_EVENT_TYPE_AUTH_RENAME,
    ]

    private init() {}

    func start() throws {
        var newClient: OpaquePointer?

        let result = es_new_client(&newClient) { [weak self] _, message in
            guard let self = self else {
                // Self deallocated — respond to AUTH to avoid kernel deadline.
                let et = message.pointee.event_type
                if et == ES_EVENT_TYPE_AUTH_OPEN, let c = newClient {
                    es_respond_flags_result(c, message, 0, false)
                } else if et == ES_EVENT_TYPE_AUTH_LINK ||
                          et == ES_EVENT_TYPE_AUTH_UNLINK ||
                          et == ES_EVENT_TYPE_AUTH_RENAME,
                          let c = newClient {
                    es_respond_auth_result(c, message, ES_AUTH_RESULT_ALLOW, false)
                }
                return
            }
            self.handleEvent(message)
        }

        guard result == ES_NEW_CLIENT_RESULT_SUCCESS else {
            throw MonitorError.clientCreationFailed(result)
        }

        self.client = newClient
        // No subscriptions at startup. enableSubscriptions() on session start.
    }

    func stop() {
        if let c = client { es_unsubscribe_all(c); es_delete_client(c); client = nil }
    }

    /// Subscribe to ES events. Mutes system target paths first.
    func enableSubscriptions() {
        guard let client = client else { return }

        // Mute noisy target paths. These generate 99% of AUTH_OPEN.
        // Both supervised and non-supervised are muted — these are
        // always allowed via TrustedRegions anyway.
        let mutedPrefixes = [
            "/System", "/Library", "/usr", "/bin", "/sbin", "/dev",
            "/private/var/db", "/private/var/folders", "/private/var/run",
            "/private/etc", "/Applications", "/opt",
        ]
        for prefix in mutedPrefixes {
            es_mute_path(client, prefix, ES_MUTE_PATH_TYPE_TARGET_PREFIX)
        }
        // Mute "/" exactly — Node.js and other runtimes readdir("/")
        // during module resolution. It's a directory listing, not a
        // file content read. TARGET_LITERAL mutes only the exact path,
        // not its children.
        es_mute_path(client, "/", ES_MUTE_PATH_TYPE_TARGET_LITERAL)

        let events: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_OPEN,
            ES_EVENT_TYPE_AUTH_LINK,
            ES_EVENT_TYPE_AUTH_UNLINK,
            ES_EVENT_TYPE_AUTH_RENAME,
            ES_EVENT_TYPE_NOTIFY_FORK,
            ES_EVENT_TYPE_NOTIFY_EXIT,
        ]
        es_subscribe(client, events, UInt32(events.count))
        os_log(.error, log: esLog, "tarn-es: subscribed (path-muted %d prefixes)", mutedPrefixes.count)
    }

    func disableSubscriptions() {
        guard let client = client else { return }
        es_unsubscribe_all(client)
        os_log(.error, log: esLog, "tarn-es: unsubscribed")
    }

    func watchForAgentFork(cliPID: pid_t) {
        enableSubscriptions()
        pendingLock.lock()
        watchedCLIPIDs.insert(cliPID)
        pendingLock.unlock()
        os_log(.error, log: esLog, "tarn-es: watching for fork from CLI PID %d", cliPID)
    }

    func confirmAgentPID(_ pid: pid_t) {
        let tree = DecisionEngine.shared.processTree
        if !tree.isSupervised(pid: pid) {
            tree.addRoot(pid: pid)
        }

        // Wait for handleFork to process the NOTIFY_FORK.
        let deadline = Date().addingTimeInterval(5.0)
        var unmuted = false
        while Date() < deadline {
            pendingLock.lock()
            unmuted = unmutedAgentPIDs.contains(pid)
            pendingLock.unlock()
            if unmuted { break }
            usleep(10_000)
        }

        pendingLock.lock()
        unmutedAgentPIDs.remove(pid)
        pendingLock.unlock()

        os_log(.error, log: esLog, "tarn-es: confirmed agent PID %d, unmuted=%{public}@", pid, unmuted ? "yes" : "TIMEOUT")
    }

    func clearPendingState() {
        disableSubscriptions()
        pendingLock.lock()
        watchedCLIPIDs.removeAll()
        unmutedAgentPIDs.removeAll()
        pendingLock.unlock()
        os_log(.error, log: esLog, "tarn-es: cleared pending state")
    }
}

// MARK: - Event Handlers

extension ESClient {
    func handleEvent(_ message: UnsafePointer<es_message_t>) {
        switch message.pointee.event_type {
        case ES_EVENT_TYPE_NOTIFY_FORK:  handleFork(message)
        case ES_EVENT_TYPE_NOTIFY_EXIT:  handleExit(message)
        case ES_EVENT_TYPE_AUTH_OPEN:    handleAuthOpen(message)
        case ES_EVENT_TYPE_AUTH_LINK:    handleLink(message)
        case ES_EVENT_TYPE_AUTH_UNLINK:  handleUnlink(message)
        case ES_EVENT_TYPE_AUTH_RENAME:  handleRename(message)
        default: break
        }
    }

    func handleFork(_ message: UnsafePointer<es_message_t>) {
        let msg = message.pointee
        let parentPid = audit_token_to_pid(msg.process.pointee.audit_token)
        let childPid = audit_token_to_pid(msg.event.fork.child.pointee.audit_token)
        let tree = DecisionEngine.shared.processTree

        // Check if this fork is from a watched CLI PID (agent spawn)
        pendingLock.lock()
        let isWatchedCLI = watchedCLIPIDs.remove(parentPid) != nil
        if isWatchedCLI {
            unmutedAgentPIDs.insert(childPid)
        }
        pendingLock.unlock()

        if isWatchedCLI {
            tree.addRoot(pid: childPid)
            // Do NOT mute — supervised PID
            var childToken = msg.event.fork.child.pointee.audit_token
            let tokenData = Data(bytes: &childToken, count: MemoryLayout<audit_token_t>.size)
            ESXPCService.shared.notifyNE(addToken: tokenData)
            os_log(.error, log: esLog, "tarn-es: agent root PID %d from CLI %d", childPid, parentPid)
            return
        }

        if tree.isSupervised(pid: parentPid) {
            tree.addChild(pid: childPid, parentPID: parentPid)
            // Do NOT mute — supervised child
            var childToken = msg.event.fork.child.pointee.audit_token
            let tokenData = Data(bytes: &childToken, count: MemoryLayout<audit_token_t>.size)
            ESXPCService.shared.notifyNE(addToken: tokenData)
            return
        }

        // Non-supervised: mute AUTH events for this child.
        if let client = client {
            var childToken = msg.event.fork.child.pointee.audit_token
            var authEvents = ESClient.mutedAuthEvents
            es_mute_process_events(client, &childToken, &authEvents, authEvents.count)
        }
    }

    func handleExit(_ message: UnsafePointer<es_message_t>) {
        let pid = audit_token_to_pid(message.pointee.process.pointee.audit_token)
        let wasSupervised = DecisionEngine.shared.processTree.isSupervised(pid: pid)
        DecisionEngine.shared.processTree.remove(pid: pid)
        if wasSupervised {
            var token = message.pointee.process.pointee.audit_token
            let tokenData = Data(bytes: &token, count: MemoryLayout<audit_token_t>.size)
            ESXPCService.shared.notifyNE(removeToken: tokenData)
        }
    }

    func handleAuthOpen(_ message: UnsafePointer<es_message_t>) {
        guard let client = client else { return }
        let msg = message.pointee
        let pid = audit_token_to_pid(msg.process.pointee.audit_token)
        let requestedFlags = UInt32(msg.event.open.fflag)

        // Non-supervised PID: allow + mute for future.
        // G2-01/G2-02: Don't mute pending agent PIDs.
        if !DecisionEngine.shared.processTree.isSupervised(pid: pid) {
            pendingLock.lock()
            let isPending = unmutedAgentPIDs.contains(pid)
            pendingLock.unlock()
            if !isPending {
                es_respond_flags_result(client, message, requestedFlags, true)
                var token = msg.process.pointee.audit_token
                var authEvents = ESClient.mutedAuthEvents
                es_mute_process_events(client, &token, &authEvents, authEvents.count)
                return
            }
        }

        let path = String(cString: msg.event.open.file.pointee.path.data)
        let isWrite = (Int32(requestedFlags) & FWRITE) != 0
        let engine = DecisionEngine.shared

        // Deny set — always checked first.
        if engine.config.isDeniedExpanded(path: path) {
            // Deny: return 0 flags (no operations allowed)
            es_respond_flags_result(client, message, 0, false)
            os_log(.error, log: esLog, "tarn-es: DENIED %{public}@ (pid %d)", path, pid)
            return
        }

        // Trusted regions — workspace, system, agent config paths.
        if engine.isInTrustedRegion(path: path, isWrite: isWrite) {
            es_respond_flags_result(client, message, requestedFlags, true)
            return
        }

        // Check allow set (Config.check).
        let kind: AccessRequest.Kind = isWrite ? .fileWrite(path: path) : .fileRead(path: path)
        let request = AccessRequest(kind: kind, pid: pid,
            processPath: String(cString: msg.process.pointee.executable.pointee.path.data))

        if let quick = engine.quickDecide(request: request) {
            let flags: UInt32 = quick == .allow ? requestedFlags : 0
            es_respond_flags_result(client, message, flags, quick == .allow)
            return
        }

        // Unknown path not in deny set, trusted regions, or allow set.
        // ES kernel deadline (~15s) is too short for interactive prompts.
        //
        // Policy: reads are auto-allowed (the deny set already blocks
        // sensitive files). Writes are auto-denied (defense in depth).
        // This matches the Santa model: block specific dangerous ops,
        // allow everything else. Network flows use NE prompts (30s).
        if !isWrite {
            es_respond_flags_result(client, message, requestedFlags, true)
            return
        }
        engine.sessionCache.record(key: request.cacheKey, action: .deny)
        es_respond_flags_result(client, message, 0, false)
        os_log(.error, log: esLog, "tarn-es: auto-denied write to %{public}@ (pid %d)", path, pid)
    }

    func handleLink(_ message: UnsafePointer<es_message_t>) {
        guard let client = client else { return }
        let msg = message.pointee
        let pid = audit_token_to_pid(msg.process.pointee.audit_token)

        if !DecisionEngine.shared.processTree.isSupervised(pid: pid) {
            pendingLock.lock()
            let isPending = unmutedAgentPIDs.contains(pid)
            pendingLock.unlock()
            if !isPending {
                es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, true)
                return
            }
        }

        let sourcePath = String(cString: msg.event.link.source.pointee.path.data)
        if DecisionEngine.shared.config.isDeniedExpanded(path: sourcePath) {
            es_respond_auth_result(client, message, ES_AUTH_RESULT_DENY, false)
            os_log(.error, log: esLog, "tarn-es: DENIED hardlink from %{public}@ (pid %d)", sourcePath, pid)
            return
        }
        es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
    }

    func handleUnlink(_ message: UnsafePointer<es_message_t>) {
        guard let client = client else { return }
        let msg = message.pointee
        let pid = audit_token_to_pid(msg.process.pointee.audit_token)

        if !DecisionEngine.shared.processTree.isSupervised(pid: pid) {
            pendingLock.lock()
            let isPending = unmutedAgentPIDs.contains(pid)
            pendingLock.unlock()
            if !isPending {
                es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, true)
                return
            }
        }

        let path = String(cString: msg.event.unlink.target.pointee.path.data)
        if DecisionEngine.shared.config.isDeniedExpanded(path: path) {
            es_respond_auth_result(client, message, ES_AUTH_RESULT_DENY, false)
            return
        }
        es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
    }

    func handleRename(_ message: UnsafePointer<es_message_t>) {
        guard let client = client else { return }
        let msg = message.pointee
        let pid = audit_token_to_pid(msg.process.pointee.audit_token)

        if !DecisionEngine.shared.processTree.isSupervised(pid: pid) {
            pendingLock.lock()
            let isPending = unmutedAgentPIDs.contains(pid)
            pendingLock.unlock()
            if !isPending {
                es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, true)
                return
            }
        }

        let sourcePath = String(cString: msg.event.rename.source.pointee.path.data)
        if DecisionEngine.shared.config.isDeniedExpanded(path: sourcePath) {
            es_respond_auth_result(client, message, ES_AUTH_RESULT_DENY, false)
            return
        }

        if msg.event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
            let destPath = String(cString: msg.event.rename.destination.existing_file.pointee.path.data)
            if DecisionEngine.shared.config.isDeniedExpanded(path: destPath) {
                es_respond_auth_result(client, message, ES_AUTH_RESULT_DENY, false)
                return
            }
        }
        es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
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
