import Foundation

/// Single-instance lock file. Refuses to acquire if another live tarn
/// process holds it; removes stale lock files (PID dead) and proceeds.
///
/// Two `tarn run` instances against the same user's profile would race
/// learned-entry writes; the lock prevents that. The lock file lives
/// in `~/Library/Application Support/tarn/tarn.lock` and contains the
/// holding PID as a decimal string.
public struct Lock {
    public let path: String

    public init(path: String) { self.path = path }

    /// Try to acquire the lock. Throws `TarnError.lockHeld` if another
    /// live tarn already holds it. Stale locks (PID dead) are removed
    /// and the new instance proceeds.
    public func acquire() throws {
        let fm = FileManager.default

        if fm.fileExists(atPath: path) {
            if let pid = try? readHoldingPID(), kill(pid, 0) == 0 {
                throw TarnError.lockHeld(path: path, pid: pid)
            }
            // Stale lock — best-effort remove and proceed.
            try? fm.removeItem(atPath: path)
        }

        let dir = (path as NSString).deletingLastPathComponent
        try fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let pidString = String(getpid()) + "\n"
        try pidString.write(toFile: path, atomically: true, encoding: .utf8)
    }

    /// Release the lock. Best effort; never throws. Caller normally
    /// invokes this from a `defer` so the lock is released on any exit
    /// path except SIGKILL.
    public func release() {
        try? FileManager.default.removeItem(atPath: path)
    }

    private func readHoldingPID() throws -> pid_t? {
        let content = try String(contentsOfFile: path, encoding: .utf8)
        let trimmed = content.trimmingCharacters(in: .whitespacesAndNewlines)
        return pid_t(trimmed)
    }
}
