import Foundation

/// Tracks the process tree rooted at the agent process.
/// Only processes in this subtree are subject to Tarn's supervision.
/// All other system processes are allowed unconditionally.
public class ProcessTree {
    private var supervisedPIDs: Set<pid_t> = []
    private let lock = NSLock()
    private let maxSize = 10_000

    /// Called when the tree becomes empty after a removal.
    /// The session manager can use this to detect "all supervised
    /// processes have exited" and terminate the session (INV-PS-5).
    public var onEmpty: (() -> Void)?

    public init() {}

    /// Register a root PID (the agent process).
    public func addRoot(pid: pid_t) {
        lock.lock()
        defer { lock.unlock() }
        guard supervisedPIDs.count < maxSize else {
            NSLog("tarn: process tree at capacity (%d), refusing addRoot for pid %d", maxSize, pid)
            return
        }
        supervisedPIDs.insert(pid)
    }

    /// Register a child PID (forked from a supervised process).
    public func addChild(pid: pid_t, parentPID: pid_t) {
        lock.lock()
        defer { lock.unlock() }
        if supervisedPIDs.contains(parentPID) {
            guard supervisedPIDs.count < maxSize else {
                NSLog("tarn: process tree at capacity (%d), refusing addChild for pid %d", maxSize, pid)
                return
            }
            supervisedPIDs.insert(pid)
        }
    }

    /// Remove a PID (process exited). If the tree becomes empty
    /// AND the PID was actually supervised, calls `onEmpty`
    /// (INV-PS-5: session terminates when tree is empty).
    public func remove(pid: pid_t) {
        lock.lock()
        let wasPresent = supervisedPIDs.remove(pid) != nil
        let empty = wasPresent && supervisedPIDs.isEmpty
        lock.unlock()
        if empty { onEmpty?() }
    }

    /// Check if a PID is in the supervised subtree.
    public func isSupervised(pid: pid_t) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return supervisedPIDs.contains(pid)
    }

    /// Remove all PIDs (session teardown).
    public func removeAll() {
        lock.lock()
        defer { lock.unlock() }
        supervisedPIDs.removeAll()
    }

    /// Number of currently tracked PIDs.
    public var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return supervisedPIDs.count
    }
}
