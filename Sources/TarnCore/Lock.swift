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
    ///
    /// Uses `open(O_CREAT|O_EXCL)` for atomic file creation to prevent
    /// TOCTOU races between checking and writing the lock file.
    public func acquire() throws {
        let fm = FileManager.default
        let dir = (path as NSString).deletingLastPathComponent
        try fm.createDirectory(atPath: dir, withIntermediateDirectories: true)

        let pidString = String(getpid()) + "\n"

        // Attempt atomic exclusive creation first
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0o644)
        if fd >= 0 {
            // Successfully created — write our PID
            _ = pidString.withCString { ptr in
                Darwin.write(fd, ptr, strlen(ptr))
            }
            close(fd)
            return
        }

        // File already exists — check if the holder is still alive
        if let pid = try? readHoldingPID(), kill(pid, 0) == 0 {
            throw TarnError.lockHeld(path: path, pid: pid)
        }

        // Stale lock — remove and retry with exclusive create
        try? fm.removeItem(atPath: path)
        let fd2 = open(path, O_WRONLY | O_CREAT | O_EXCL, 0o644)
        guard fd2 >= 0 else {
            // Another process grabbed it between our remove and create
            throw TarnError.lockHeld(path: path, pid: 0)
        }
        _ = pidString.withCString { ptr in
            Darwin.write(fd2, ptr, strlen(ptr))
        }
        close(fd2)
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
