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
    /// Both sides lowercased for case-insensitive APFS.
    public static func isTrusted(path: String, repoPath: String, agentPaths: [String] = [], isWrite: Bool) -> Bool {
        let normalizedPath = path.lowercased()
        if !repoPath.isEmpty {
            let normalizedRepo = repoPath.lowercased()
            if normalizedPath == normalizedRepo || normalizedPath.hasPrefix(normalizedRepo + "/") { return true }
        }
        if normalizedPath == "/tmp" || normalizedPath.hasPrefix("/tmp/") ||
           normalizedPath == "/var/tmp" || normalizedPath.hasPrefix("/var/tmp/") { return true }
        if !isWrite {
            if systemPrefixes.contains(where: { normalizedPath == $0.lowercased() || normalizedPath.hasPrefix($0.lowercased() + "/") }) { return true }
        }
        // Agent-specific config paths (read+write). Each agent profile
        // declares which directories it needs (e.g. ~/.claude for Claude Code).
        for agentPath in agentPaths {
            let normalizedAgent = agentPath.lowercased()
            if normalizedPath == normalizedAgent || normalizedPath.hasPrefix(normalizedAgent + "/") { return true }
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
