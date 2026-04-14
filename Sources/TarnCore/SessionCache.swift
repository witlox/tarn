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
    /// Insertion-ordered keys for LRU eviction. Most recently used at the end.
    private var order: [String] = []
    private let lock = NSLock()
    private let maxSize = 10_000

    public init() {}

    public func record(key: String, action: AccessAction) {
        let normalized = key.lowercased()
        lock.lock()
        defer { lock.unlock() }
        if entries[normalized] != nil {
            // Move to end (most recent)
            order.removeAll(where: { $0 == normalized })
        } else if entries.count >= maxSize {
            // Evict oldest entry
            if let oldest = order.first {
                order.removeFirst()
                entries.removeValue(forKey: oldest)
            }
        }
        entries[normalized] = action
        order.append(normalized)
    }

    public func lookup(key: String) -> AccessAction? {
        let normalized = key.lowercased()
        lock.lock()
        defer { lock.unlock() }
        guard let action = entries[normalized] else { return nil }
        // Move to end (most recently used)
        order.removeAll(where: { $0 == normalized })
        order.append(normalized)
        return action
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
        order.removeAll()
    }
}
