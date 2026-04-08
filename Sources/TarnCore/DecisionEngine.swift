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
    private let configLock = NSLock()

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

    /// Configure the engine for a new session. Clears all prior state.
    public func configure(config: Config, repoPath: String) {
        configLock.lock()
        _config = config
        _repoPath = repoPath
        configLock.unlock()
        sessionCache.clear()
        processTree.removeAll()
    }

    /// Apply a learned entry to the in-memory config. Called only after
    /// the CLI has successfully persisted to disk.
    public func applyLearnedEntry(request: AccessRequest) {
        configLock.lock()
        _config.learn(request: request)
        configLock.unlock()
    }

    /// Check deny set → allow set → session cache. Returns nil if
    /// the request is undecided and needs a user prompt.
    public func quickDecide(request: AccessRequest) -> AccessAction? {
        let cacheKey = request.cacheKey
        if let cached = sessionCache.lookup(key: cacheKey) { return cached }
        let currentConfig = config
        if let result = currentConfig.check(request: request) { return result }
        return nil
    }

    /// Request an asynchronous decision including a user prompt.
    /// The reply closure is called on an arbitrary thread with the
    /// final action.
    public func asyncDecide(request: AccessRequest, reply: @escaping (AccessAction) -> Void) {
        if let quick = quickDecide(request: request) {
            reply(quick)
            return
        }

        guard let service = promptService else {
            reply(.deny)
            return
        }

        let message = makePromptMessage(request: request)
        let cacheKey = request.cacheKey

        service.asyncPrompt(message) { [weak self] response in
            guard let self = self else { reply(.deny); return }
            let action: AccessAction = response.action == "allow" ? .allow : .deny

            if action == .allow && response.remember {
                service.asyncPersistEntry(request: request) { success in
                    if success {
                        self.applyLearnedEntry(request: request)
                    } else {
                        self.sessionCache.record(key: cacheKey, action: .allow)
                    }
                    reply(action)
                }
            } else {
                self.sessionCache.record(key: cacheKey, action: action)
                reply(action)
            }
        }
    }

    /// Check if a path is in a trusted region.
    public func isInTrustedRegion(path: String, isWrite: Bool) -> Bool {
        TrustedRegions.isTrusted(path: path, repoPath: repoPath, isWrite: isWrite)
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
