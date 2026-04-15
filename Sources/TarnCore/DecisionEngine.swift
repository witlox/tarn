import Foundation

/// Shared decision pipeline used by both the ES client (file events)
/// and the NE filter (network events). Checks the deny set, allow set,
/// and session cache in order. When undecided, delegates to the
/// PromptService for an interactive user decision.
///
/// Lives in TarnCore (not TarnSupervisor) so the full pipeline can
/// be unit-tested via swift test with a MockPromptService, without
/// needing EndpointSecurity or NetworkExtension frameworks.
public final class DecisionEngine {
    public static let shared = DecisionEngine()

    public let processTree = ProcessTree()
    public let sessionCache = SessionCache()
    private var _config = Config.defaults()
    private var _repoPath: String = ""
    private var _agentPaths: [String] = []
    private var _agentWritePaths: [String] = []
    private let configLock = NSLock()

    /// Tracks in-flight prompt cache keys and waiting callbacks.
    /// When a prompt is already pending for a key, new callers
    /// piggyback on the same prompt instead of spawning duplicates.
    private var pendingPrompts: [String: [(AccessAction) -> Void]] = [:]
    private let pendingLock = NSLock()

    /// Deadline for ES AUTH event responses. ES kills the client if
    /// a response takes longer than ~30 s. We auto-deny at 25 s.
    /// ES kernel deadline varies by macOS version (~15-30s).
    /// Use 10s to be safe — auto-deny before the kernel kills us.
    public var esDeadlineSeconds: Double = 10.0

    /// Prompt service for interactive decisions and persistence.
    /// In production: XPCService. In tests: MockPromptService.
    public weak var promptService: PromptService?

    public init() {}

    // MARK: - Thread-safe config access

    public var config: Config {
        configLock.lock()
        defer { configLock.unlock() }
        return _config
    }

    public var repoPath: String {
        configLock.lock()
        defer { configLock.unlock() }
        return _repoPath
    }

    public var agentPaths: [String] {
        configLock.lock()
        defer { configLock.unlock() }
        return _agentPaths
    }

    public var agentWritePaths: [String] {
        configLock.lock()
        defer { configLock.unlock() }
        return _agentWritePaths
    }

    /// Configure the engine for a new session. Clears all prior state.
    /// F-17: agentPaths are readonly, agentWritePaths allow both reads and writes.
    public func configure(config: Config, repoPath: String, agentPaths: [String] = [], agentWritePaths: [String] = []) {
        configLock.lock()
        _config = config
        _repoPath = repoPath
        _agentPaths = agentPaths
        _agentWritePaths = agentWritePaths
        configLock.unlock()
        sessionCache.clear()
        processTree.removeAll()
        pendingLock.lock()
        pendingPrompts.removeAll()
        pendingLock.unlock()
    }

    /// Apply a learned entry to the in-memory config. Called only after
    /// the CLI has successfully persisted to disk.
    public func applyLearnedEntry(request: AccessRequest) {
        configLock.lock()
        _config.learn(request: request)
        configLock.unlock()
    }

    /// Check deny set → session cache → allow set. Returns nil if
    /// the request is undecided and needs a user prompt.
    ///
    /// The deny set is always checked first so that a cached .allow
    /// cannot override a deny-list entry added after the cache was
    /// populated.
    public func quickDecide(request: AccessRequest) -> AccessAction? {
        let currentConfig = config
        // Deny set takes absolute precedence.
        if currentConfig.isDenied(request: request) { return .deny }
        let cacheKey = request.cacheKey
        if let cached = sessionCache.lookup(key: cacheKey) { return cached }
        if let result = currentConfig.check(request: request) { return result }
        return nil
    }

    /// Request an asynchronous decision including a user prompt.
    /// The reply closure is called on an arbitrary thread with the
    /// final action.
    ///
    /// F15: A deadline timer auto-denies if the prompt hasn't resolved
    ///      within `esDeadlineSeconds` (default 25 s), preventing ES
    ///      from killing the client at ~30 s.
    /// F17: Duplicate prompts for the same cache key are coalesced —
    ///      only one prompt is sent, and all waiters share the result.
    public func asyncDecide(request: AccessRequest, reply: @escaping (AccessAction) -> Void) {
        if let quick = quickDecide(request: request) {
            reply(quick)
            return
        }

        guard let service = promptService else {
            reply(.deny)
            return
        }

        let cacheKey = request.cacheKey

        // F17: Coalesce duplicate prompts for the same cache key.
        pendingLock.lock()
        if pendingPrompts[cacheKey] != nil {
            // Another prompt is already in flight — piggyback.
            pendingPrompts[cacheKey]!.append(reply)
            pendingLock.unlock()
            return
        }
        pendingPrompts[cacheKey] = [reply]
        pendingLock.unlock()

        // Deliver the result to all coalesced waiters.
        let deliverResult: (AccessAction) -> Void = { [weak self] action in
            guard let self = self else { return }
            self.pendingLock.lock()
            let waiters = self.pendingPrompts.removeValue(forKey: cacheKey) ?? []
            self.pendingLock.unlock()
            for waiter in waiters { waiter(action) }
        }

        // F15: Deadline timer. Uses a flag to avoid double-delivery.
        let deadlineFired = NSLock()
        var resolved = false

        let deadlineItem = DispatchWorkItem { [weak self] in
            deadlineFired.lock()
            guard !resolved else { deadlineFired.unlock(); return }
            resolved = true
            deadlineFired.unlock()
            self?.sessionCache.record(key: cacheKey, action: .deny)
            deliverResult(.deny)
        }
        DispatchQueue.global().asyncAfter(
            deadline: .now() + esDeadlineSeconds,
            execute: deadlineItem
        )

        let message = makePromptMessage(request: request)

        service.asyncPrompt(message) { [weak self] response in
            deadlineFired.lock()
            guard !resolved else { deadlineFired.unlock(); return }
            resolved = true
            deadlineFired.unlock()
            deadlineItem.cancel()

            guard let self = self else { deliverResult(.deny); return }
            let action: AccessAction = response.action == "allow" ? .allow : .deny

            if action == .allow && response.remember {
                service.asyncPersistEntry(request: request) { success in
                    if success {
                        self.applyLearnedEntry(request: request)
                    } else {
                        self.sessionCache.record(key: cacheKey, action: .allow)
                    }
                    deliverResult(action)
                }
            } else {
                self.sessionCache.record(key: cacheKey, action: action)
                deliverResult(action)
            }
        }
    }

    /// Check if a path is in a trusted region.
    /// F-17: agentPaths are readonly, agentWritePaths allow both.
    public func isInTrustedRegion(path: String, isWrite: Bool) -> Bool {
        TrustedRegions.isTrusted(path: path, repoPath: repoPath, agentPaths: agentPaths, agentWritePaths: agentWritePaths, isWrite: isWrite)
    }

    public func makePromptMessage(request: AccessRequest) -> PromptRequestMessage {
        let description: String
        let canRemember: Bool
        switch request.kind {
        case .fileRead(let path):
            description = "File read: \(path)"
            canRemember = true
        case .fileWrite(let path):
            description = "File write: \(path)"
            canRemember = true
        case .networkConnect(let target):
            description = "Network connect: \(target)"
            canRemember = !TrustedRegions.isIPAddress(target)
        }
        return PromptRequestMessage(
            sessionId: "",
            flowId: UUID().uuidString,
            description: description,
            processPath: request.processPath,
            pid: request.pid,
            canRemember: canRemember
        )
    }
}
