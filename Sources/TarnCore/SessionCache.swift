import Foundation

/// In-memory cache of decisions made during one tarn session. Holds
/// both allows and denies — "deny once" is a session-scoped decision,
/// not a one-shot that re-prompts on every retry. Cleared when the
/// session ends; only "Allow and remember" responses are persisted to
/// the user's profile on disk.
///
/// Keyed by an opaque string the caller chooses (typically the
/// expanded path for file events, or `"ip:<address>"` for connect
/// events). Thread-safe; ES events arrive on multiple threads.
public final class SessionCache {
    private var entries: [String: AccessAction] = [:]
    private let lock = NSLock()

    public init() {}

    public func record(key: String, action: AccessAction) {
        lock.lock()
        defer { lock.unlock() }
        entries[key] = action
    }

    public func lookup(key: String) -> AccessAction? {
        lock.lock()
        defer { lock.unlock() }
        return entries[key]
    }

    public var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return entries.count
    }

    public func clear() {
        lock.lock()
        defer { lock.unlock() }
        entries.removeAll()
    }
}
