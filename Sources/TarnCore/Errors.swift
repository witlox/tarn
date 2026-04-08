import Foundation

/// Top-level errors raised by the tarn CLI and its decision pipeline.
/// Each case carries enough context for a clear, actionable terminal
/// error message.
public enum TarnError: Error, CustomStringConvertible {
    /// Tarn is running as root but `SUDO_USER` is not set in the
    /// environment. Direct root login plus `tarn run` is unsupported;
    /// the only supported invocation is `sudo tarn run ...` from a
    /// normal user account.
    case sudoUserMissing

    /// `SUDO_USER` is set but no such user exists on this system.
    case unknownSudoUser(String)

    /// Another tarn instance is already running. The recorded PID is
    /// alive, so this is not a stale lock.
    case lockHeld(path: String, pid: pid_t)

    /// The user's profile file could not be parsed. Tarn refuses to
    /// auto-overwrite a corrupt profile.
    case profileParseFailed(path: String, underlying: Error)

    /// The user's profile file could not be written. The current
    /// access is still allowed and held in the session cache only.
    case profileWriteFailed(path: String, underlying: Error)

    /// `~/Library/Application Support/` is missing or unwritable.
    /// Extremely unusual; tarn refuses to fall back to a different
    /// location.
    case applicationSupportMissing(String)

    public var description: String {
        switch self {
        case .sudoUserMissing:
            return """
                tarn must be invoked via sudo from a normal user account; \
                SUDO_USER is unset. Direct root login is not supported.
                """
        case .unknownSudoUser(let user):
            return "SUDO_USER is set to '\(user)' but no such user exists on this system."
        case .lockHeld(let path, let pid):
            return """
                another tarn instance is already running (PID \(pid)). \
                Lock file: \(path)
                """
        case .profileParseFailed(let path, let underlying):
            return "failed to parse profile at \(path): \(underlying)"
        case .profileWriteFailed(let path, let underlying):
            return "failed to write profile at \(path): \(underlying)"
        case .applicationSupportMissing(let path):
            return "Application Support directory does not exist or is not writable: \(path)"
        }
    }
}
