import Foundation

/// Pure-logic check for trusted regions. Extracted from the supervisor
/// into TarnCore so it can be unit tested via swift test.
public struct TrustedRegions {
    /// System paths that are always allowed for reads.
    public static let systemPrefixes = [
        "/usr", "/lib", "/bin", "/sbin", "/System", "/Library",
        "/Applications", "/private/var/db", "/dev",
    ]

    /// Check if a path is in a trusted region.
    /// Workspace and /tmp allow reads and writes.
    /// System paths allow reads only.
    public static func isTrusted(path: String, repoPath: String, isWrite: Bool) -> Bool {
        if !repoPath.isEmpty && path.hasPrefix(repoPath) { return true }
        if path.hasPrefix("/tmp") || path.hasPrefix("/var/tmp") { return true }
        if !isWrite {
            if systemPrefixes.contains(where: { path.hasPrefix($0) }) { return true }
        }
        return false
    }

    /// Check if a string is an IP address (v4 or v6).
    public static func isIPAddress(_ string: String) -> Bool {
        var addr = in_addr()
        var addr6 = in6_addr()
        return inet_pton(AF_INET, string, &addr) == 1 ||
               inet_pton(AF_INET6, string, &addr6) == 1
    }
}
