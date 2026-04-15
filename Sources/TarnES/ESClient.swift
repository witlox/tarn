import EndpointSecurity
import Foundation
import os.log
import TarnCore

private let esLog = OSLog(subsystem: "com.witlox.tarn.es", category: "es")

/// Manages the Endpoint Security client for file and process
/// supervision. NOTIFY_FORK/EXIT fire for all processes (tree tracking).
/// AUTH_OPEN/AUTH_LINK/AUTH_UNLINK/AUTH_RENAME fire for all processes but
/// non-supervised ones are muted per-process via es_mute_process_events
/// on first sight.
///
/// Supervised processes (agent + children) are never muted for AUTH events.
/// This gives us kernel-level filtering with zero overhead for the vast
/// majority of processes (they get muted on their first fork event).
final class ESClient {
    static let shared = ESClient()

    fileprivate var client: OpaquePointer?

    /// CLI PIDs we're watching for the next fork (agent spawn).
    fileprivate var watchedCLIPIDs: Set<pid_t> = []
    /// Agent PIDs that were unmuted by handleFork before confirmAgentPID.
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
                // Self deallocated — respond to AUTH events to avoid kernel deadline.
                let eventType = message.pointee.event_type
                if eventType == ES_EVENT_TYPE_AUTH_OPEN ||
                   eventType == ES_EVENT_TYPE_AUTH_LINK ||
                   eventType == ES_EVENT_TYPE_AUTH_UNLINK ||
                   eventType == ES_EVENT_TYPE_AUTH_RENAME,
                   let client = newClient {
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

        // Don't subscribe to any events at startup — zero overhead.
        // Events are subscribed when a session starts (enableSubscriptions)
        // and unsubscribed when the session ends (disableSubscriptions).
        // This ensures the ES client has zero impact on system performance
        // when no tarn session is active.
    }

    func stop() {
        if let client = client {
            es_unsubscribe_all(client)
            es_delete_client(client)
            self.client = nil
        }
    }

    /// Subscribe to all ES events. Called when a session starts.
    /// Mutes noisy target paths first to prevent the startup burst
    /// of AUTH callbacks that previously caused the kernel to SIGKILL
    /// us for not responding in time.
    func enableSubscriptions() {
        guard let client = client else { return }

        // Step 1: Mute noisy TARGET paths before subscribing.
        // These paths generate 99% of AUTH_OPEN events and are
        // always allowed (system libraries, frameworks, caches).
        // Supervised processes reading these paths are also allowed
        // (they're in TrustedRegions), so muting them loses nothing.
        let mutedTargetPrefixes = [
            "/System",
            "/Library",
            "/usr/lib",
            "/usr/bin",
            "/usr/sbin",
            "/usr/share",
            "/usr/libexec",
            "/bin",
            "/sbin",
            "/dev",
            "/private/var/db",
            "/private/var/folders",
            "/private/var/run",
            "/private/etc",
            "/Applications",
            "/opt",
        ]
        for prefix in mutedTargetPrefixes {
            es_mute_path(client, prefix, ES_MUTE_PATH_TYPE_TARGET_PREFIX)
        }

        // Step 2: Subscribe to all events. NOTIFY events are never
        // affected by path muting. AUTH events only fire for target
        // paths NOT in the muted set — mainly user home directories
        // and the workspace.
        let events: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_OPEN,
            ES_EVENT_TYPE_AUTH_LINK,
            ES_EVENT_TYPE_AUTH_UNLINK,
            ES_EVENT_TYPE_AUTH_RENAME,
            ES_EVENT_TYPE_NOTIFY_FORK,
            ES_EVENT_TYPE_NOTIFY_EXIT,
        ]
        es_subscribe(client, events, UInt32(events.count))

        os_log(.error, log: esLog, "tarn-es: subscribed to ES events (muted %d target path prefixes)", mutedTargetPrefixes.count)
    }

    /// Unsubscribe from all ES events. Called when session ends.
    func disableSubscriptions() {
        guard let client = client else { return }
        es_unsubscribe_all(client)
        os_log(.error, log: esLog, "tarn-es: unsubscribed from ES events")
    }

    /// Step 1: Called BEFORE posix_spawn. Watch for next fork from cliPID.
    func watchForAgentFork(cliPID: pid_t) {
        enableSubscriptions()
        pendingLock.lock()
        watchedCLIPIDs.insert(cliPID)
        pendingLock.unlock()
        os_log(.error, log: esLog, "tarn-es: watching for fork from CLI PID %d", cliPID)
    }

    /// Step 2: Called AFTER posix_spawn. Confirms PID in tree.
    func confirmAgentPID(_ pid: pid_t) {
        let tree = DecisionEngine.shared.processTree
        if !tree.isSupervised(pid: pid) {
            tree.addRoot(pid: pid)
        }
        pendingLock.lock()
        let wasUnmuted = unmutedAgentPIDs.remove(pid) != nil
        pendingLock.unlock()
        os_log(.error, log: esLog, "tarn-es: confirmed agent PID %d, unmuted=%{public}@", pid, wasUnmuted ? "yes" : "no")
    }

    /// F-11: Clear pending state on session end or CLI disconnect.
    func clearPendingState() {
        disableSubscriptions()
        pendingLock.lock()
        watchedCLIPIDs.removeAll()
        unmutedAgentPIDs.removeAll()
        pendingLock.unlock()
        os_log(.error, log: esLog, "tarn-es: cleared pending state (watchedCLIPIDs + unmutedAgentPIDs)")
    }

}

// MARK: - Event Handlers

extension ESClient {
    func handleEvent(_ message: UnsafePointer<es_message_t>) {
        let msg = message.pointee
        switch msg.event_type {
        case ES_EVENT_TYPE_NOTIFY_FORK:
            handleFork(message)
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            handleExit(message)
        case ES_EVENT_TYPE_AUTH_OPEN:
            handleAuthOpen(message)
        case ES_EVENT_TYPE_AUTH_LINK:
            handleLink(message)
        case ES_EVENT_TYPE_AUTH_UNLINK:
            handleUnlink(message)
        case ES_EVENT_TYPE_AUTH_RENAME:
            handleRename(message)
        default:
            break
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
            // CLI spawned the agent — add to tree, push to NE.
            // Do NOT mute AUTH events for this PID.
            tree.addRoot(pid: childPid)
            // F-02: Push audit token data to NE extension instead of bare PID.
            var childToken = msg.event.fork.child.pointee.audit_token
            let tokenData = Data(bytes: &childToken, count: MemoryLayout<audit_token_t>.size)
            ESXPCService.shared.notifyNE(addToken: tokenData)
            os_log(.error, log: esLog, "tarn-es: agent root PID %d from CLI %d", childPid, parentPid)
            return
        }

        // Supervised parent forked a child — track and don't mute
        if tree.isSupervised(pid: parentPid) {
            tree.addChild(pid: childPid, parentPID: parentPid)
            // F-02: Push audit token data to NE extension.
            var childToken = msg.event.fork.child.pointee.audit_token
            let tokenData = Data(bytes: &childToken, count: MemoryLayout<audit_token_t>.size)
            ESXPCService.shared.notifyNE(addToken: tokenData)
            return
        }

        // Non-supervised process: mute all AUTH events for this child
        // so the callbacks never fire for it. NOTIFY events stay unmuted.
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
            // F-02: Push audit token data removal to NE extension.
            var token = message.pointee.process.pointee.audit_token
            let tokenData = Data(bytes: &token, count: MemoryLayout<audit_token_t>.size)
            ESXPCService.shared.notifyNE(removeToken: tokenData)
        }
    }

    func handleAuthOpen(_ message: UnsafePointer<es_message_t>) {
        guard let client = client else { return }
        let msg = message.pointee
        let pid = audit_token_to_pid(msg.process.pointee.audit_token)

        // Non-supervised PID that hasn't been muted yet (e.g. process
        // that existed before the ES client started). Allow and mute
        // for future events.
        // G2-01/G2-02: Check unmutedAgentPIDs before muting — the agent
        // PID may arrive here before handleFork/confirmAgentPID adds it
        // to the tree. Muting it would permanently lose supervision.
        if !DecisionEngine.shared.processTree.isSupervised(pid: pid) {
            pendingLock.lock()
            let isPendingAgent = unmutedAgentPIDs.contains(pid)
            pendingLock.unlock()
            if !isPendingAgent {
                es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
                var token = msg.process.pointee.audit_token
                var authEvents = ESClient.mutedAuthEvents
                es_mute_process_events(client, &token, &authEvents, authEvents.count)
                return
            }
            // isPendingAgent: treat as supervised, fall through to decision pipeline.
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

    /// F-07: Handle AUTH_LINK — deny hardlink creation from deny-set paths.
    /// If a supervised PID creates a hardlink where the SOURCE path is
    /// in the deny set, DENY. This prevents bypassing the deny set via
    /// hardlinks (the hardlink target would be in the workspace trusted
    /// region, evading deny-set checks on subsequent opens).
    func handleLink(_ message: UnsafePointer<es_message_t>) {
        guard let client = client else { return }
        let msg = message.pointee
        let pid = audit_token_to_pid(msg.process.pointee.audit_token)

        // Non-supervised: allow (same as handleAuthOpen fast path)
        if !DecisionEngine.shared.processTree.isSupervised(pid: pid) {
            pendingLock.lock()
            let isPendingAgent = unmutedAgentPIDs.contains(pid)
            pendingLock.unlock()
            if !isPendingAgent {
                es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
                return
            }
            // Pending agent — fall through to deny-set check
        }

        let sourcePath = String(cString: msg.event.link.source.pointee.path.data)
        let engine = DecisionEngine.shared

        if engine.config.isDeniedExpanded(path: sourcePath) {
            os_log(.error, log: esLog, "tarn-es: denied hardlink from deny-set path: %{public}@", sourcePath)
            es_respond_auth_result(client, message, ES_AUTH_RESULT_DENY, false)
            return
        }

        es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
    }

    /// F-13: Handle AUTH_UNLINK — deny deletion of deny-set files.
    func handleUnlink(_ message: UnsafePointer<es_message_t>) {
        guard let client = client else { return }
        let msg = message.pointee
        let pid = audit_token_to_pid(msg.process.pointee.audit_token)

        if !DecisionEngine.shared.processTree.isSupervised(pid: pid) {
            pendingLock.lock()
            let isPendingAgent = unmutedAgentPIDs.contains(pid)
            pendingLock.unlock()
            if !isPendingAgent {
                es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
                return
            }
        }

        let targetPath = String(cString: msg.event.unlink.target.pointee.path.data)
        let engine = DecisionEngine.shared

        if engine.config.isDeniedExpanded(path: targetPath) {
            os_log(.error, log: esLog, "tarn-es: denied unlink of deny-set path: %{public}@", targetPath)
            es_respond_auth_result(client, message, ES_AUTH_RESULT_DENY, false)
            return
        }

        es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
    }

    /// F-13: Handle AUTH_RENAME — deny rename from/to deny-set paths.
    func handleRename(_ message: UnsafePointer<es_message_t>) {
        guard let client = client else { return }
        let msg = message.pointee
        let pid = audit_token_to_pid(msg.process.pointee.audit_token)

        if !DecisionEngine.shared.processTree.isSupervised(pid: pid) {
            pendingLock.lock()
            let isPendingAgent = unmutedAgentPIDs.contains(pid)
            pendingLock.unlock()
            if !isPendingAgent {
                es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
                return
            }
        }

        let sourcePath = String(cString: msg.event.rename.source.pointee.path.data)
        let engine = DecisionEngine.shared

        // Check source path against deny set
        if engine.config.isDeniedExpanded(path: sourcePath) {
            os_log(.error, log: esLog, "tarn-es: denied rename from deny-set path: %{public}@", sourcePath)
            es_respond_auth_result(client, message, ES_AUTH_RESULT_DENY, false)
            return
        }

        // Check destination path against deny set.
        // AUTH_RENAME destination is in a union — check the existing_file variant first.
        let destType = msg.event.rename.destination_type
        let destPath: String?
        if destType == ES_DESTINATION_TYPE_EXISTING_FILE {
            destPath = String(cString: msg.event.rename.destination.existing_file.pointee.path.data)
        } else if destType == ES_DESTINATION_TYPE_NEW_PATH {
            let dir = String(cString: msg.event.rename.destination.new_path.dir.pointee.path.data)
            let filename = String(cString: msg.event.rename.destination.new_path.filename.data)
            destPath = (dir as NSString).appendingPathComponent(filename)
        } else {
            destPath = nil
        }

        if let destPath = destPath, engine.config.isDeniedExpanded(path: destPath) {
            os_log(.error, log: esLog, "tarn-es: denied rename to deny-set path: %{public}@", destPath)
            es_respond_auth_result(client, message, ES_AUTH_RESULT_DENY, false)
            return
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
