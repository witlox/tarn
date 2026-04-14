import Foundation

/// Represents an access request from the ES monitor or NE filter.
public struct AccessRequest {
    public enum Kind {
        case fileRead(path: String)
        case fileWrite(path: String)
        case networkConnect(domain: String)
    }

    public let kind: Kind
    public let pid: pid_t
    public let processPath: String

    public init(kind: Kind, pid: pid_t, processPath: String) {
        self.kind = kind
        self.pid = pid
        self.processPath = processPath
    }

    /// Session-cache key. Tilde-expanded path for files, "host:<target>" for network.
    /// Normalized to lowercase so case variants hit the same entry (APFS is
    /// case-insensitive by default; DNS is case-insensitive per RFC 4343).
    public var cacheKey: String {
        switch kind {
        case .fileRead(let path), .fileWrite(let path):
            return NSString(string: path).expandingTildeInPath.lowercased()
        case .networkConnect(let target):
            return "host:\(target.lowercased())"
        }
    }
}

/// Represents a mount entry in the whitelist profile.
public struct MountEntry: Equatable {
    public let path: String
    public let mode: AccessMode
    public let learned: Bool

    public enum AccessMode: String {
        case readonly
        case readwrite
    }

    public init(path: String, mode: AccessMode, learned: Bool = false) {
        self.path = path
        self.mode = mode
        self.learned = learned
    }
}

/// Represents a network domain entry in the whitelist profile.
public struct DomainEntry: Equatable {
    public let domain: String
    public let learned: Bool

    public init(domain: String, learned: Bool = false) {
        self.domain = domain
        self.learned = learned
    }
}

/// The global tarn profile, loaded from and saved to TOML.
public struct Config {
    public var readonlyPaths: [MountEntry]
    public var readwritePaths: [MountEntry]
    public var allowedDomains: [DomainEntry]
    /// Paths that are always denied, set by profiles (not persisted to TOML).
    public var deniedPaths: Set<String> = []
    /// Domains that are always denied regardless of allow rules.
    /// Currently empty in v1; placeholder for future deny-by-hostname.
    public var deniedDomains: Set<String> = []

    public init(readonlyPaths: [MountEntry], readwritePaths: [MountEntry], allowedDomains: [DomainEntry]) {
        self.readonlyPaths = readonlyPaths
        self.readwritePaths = readwritePaths
        self.allowedDomains = allowedDomains
    }

    public var totalEntries: Int {
        readonlyPaths.count + readwritePaths.count + allowedDomains.count
    }

    /// Default profile with common safe paths.
    public static func defaults() -> Config {
        Config(
            readonlyPaths: [
                MountEntry(path: "~/.gitconfig", mode: .readonly),
                MountEntry(path: "~/.ssh/known_hosts", mode: .readonly),
            ],
            readwritePaths: [],
            allowedDomains: [
                DomainEntry(domain: "api.anthropic.com"),
                DomainEntry(domain: "github.com"),
                DomainEntry(domain: "registry.npmjs.org"),
                DomainEntry(domain: "pypi.org"),
                DomainEntry(domain: "crates.io"),
            ]
        )
    }

    /// Check an access request against the whitelist and deny list.
    /// Returns .deny for denied paths, .allow if whitelisted, nil if unknown (needs prompt).
    public func check(request: AccessRequest) -> AccessAction? {
        switch request.kind {
        case .fileRead(let path):
            let expanded = expandPath(path).lowercased()
            // Denied paths take precedence
            if isDenied(path: expanded) { return .deny }
            if readonlyPaths.contains(where: { expandPath($0.path).lowercased() == expanded }) ||
               readwritePaths.contains(where: { expandPath($0.path).lowercased() == expanded }) {
                return .allow
            }
            return nil

        case .fileWrite(let path):
            let expanded = expandPath(path).lowercased()
            if isDenied(path: expanded) { return .deny }
            if readwritePaths.contains(where: { expandPath($0.path).lowercased() == expanded }) {
                return .allow
            }
            // Read-only paths explicitly deny writes
            if readonlyPaths.contains(where: { expandPath($0.path).lowercased() == expanded }) {
                return .deny
            }
            return nil

        case .networkConnect(let domain):
            let normalizedDomain = domain.lowercased()
            // Deny set checked first (INV-AC-3)
            if deniedDomains.contains(where: { $0.lowercased() == normalizedDomain }) { return .deny }
            if allowedDomains.contains(where: { $0.domain.lowercased() == normalizedDomain }) {
                return .allow
            }
            return nil
        }
    }

    /// Check if an already-expanded path matches any denied pattern.
    /// Public so the ES handler can check denials before trusted regions.
    public func isDeniedPath(_ path: String) -> Bool {
        return isDenied(path: path)
    }

    /// Check if any access request is denied, regardless of kind.
    /// Used by DecisionEngine to enforce denials before the session cache.
    public func isDenied(request: AccessRequest) -> Bool {
        switch request.kind {
        case .fileRead(let path), .fileWrite(let path):
            return isDenied(path: expandPath(path).lowercased())
        case .networkConnect(let domain):
            let normalizedDomain = domain.lowercased()
            return deniedDomains.contains(where: { $0.lowercased() == normalizedDomain })
        }
    }

    /// Check if a path matches any denied pattern.
    /// Supports exact match, directory prefix, and simple glob (* suffix).
    /// Both sides are lowercased because APFS is case-insensitive by default.
    private func isDenied(path: String) -> Bool {
        let normalizedPath = path.lowercased()
        for pattern in deniedPaths {
            let expandedPattern = expandPath(pattern).lowercased()
            if expandedPattern.hasSuffix("*") {
                let prefix = String(expandedPattern.dropLast())
                if normalizedPath.hasPrefix(prefix) { return true }
            } else if normalizedPath == expandedPattern || normalizedPath.hasPrefix(expandedPattern + "/") {
                return true
            }
        }
        return false
    }

    /// Learn from an approved access request.
    /// Silently skips if the path/domain is in the deny set (F26).
    /// Normalizes to lowercase before storing to prevent case-variant duplicates.
    public mutating func learn(request: AccessRequest) {
        switch request.kind {
        case .fileRead(let path):
            let normalized = path.lowercased()
            let expanded = expandPath(normalized)
            guard !isDenied(path: expanded) else { return }
            addReadonly(path: normalized)
        case .fileWrite(let path):
            let normalized = path.lowercased()
            let expanded = expandPath(normalized)
            guard !isDenied(path: expanded) else { return }
            addReadwrite(path: normalized)
        case .networkConnect(let domain):
            let normalized = domain.lowercased()
            guard !deniedDomains.contains(where: { $0.lowercased() == normalized }) else { return }
            addDomain(domain: normalized)
        }
    }

    public mutating func addReadonly(path: String) {
        let normalized = path.lowercased()
        guard !readonlyPaths.contains(where: { $0.path.lowercased() == normalized }) else { return }
        readonlyPaths.append(MountEntry(path: path, mode: .readonly, learned: true))
    }

    public mutating func addReadwrite(path: String) {
        let normalized = path.lowercased()
        guard !readwritePaths.contains(where: { $0.path.lowercased() == normalized }) else { return }
        readwritePaths.append(MountEntry(path: path, mode: .readwrite, learned: true))
    }

    public mutating func addDomain(domain: String) {
        let normalized = domain.lowercased()
        guard !allowedDomains.contains(where: { $0.domain.lowercased() == normalized }) else { return }
        allowedDomains.append(DomainEntry(domain: domain, learned: true))
    }

    public mutating func resetLearned() {
        readonlyPaths.removeAll(where: { $0.learned })
        readwritePaths.removeAll(where: { $0.learned })
        allowedDomains.removeAll(where: { $0.learned })
    }

}

// MARK: - Config Persistence

extension Config {
    public static func load(from path: String) throws -> Config {
        let fileManager = FileManager.default
        let dir = (path as NSString).deletingLastPathComponent

        if !fileManager.fileExists(atPath: path) {
            try fileManager.createDirectory(atPath: dir, withIntermediateDirectories: true)
            let config = Config.defaults()
            try config.save(to: path)
            return config
        }

        let content = try String(contentsOfFile: path, encoding: .utf8)
        return try parse(toml: content)
    }

    public static func parse(toml: String) throws -> Config {
        var readonly: [MountEntry] = []
        var readwrite: [MountEntry] = []
        var domains: [DomainEntry] = []
        var currentSection = ""

        for line in toml.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }

            if trimmed.hasPrefix("[") {
                currentSection = trimmed.lowercased()
                continue
            }

            if trimmed.hasPrefix("\"") || trimmed.hasPrefix("{ ") {
                let isLearned = trimmed.contains("learned = true") || line.contains("# learned")
                if let firstQuote = trimmed.firstIndex(of: "\""),
                   let secondQuote = trimmed[trimmed.index(after: firstQuote)...].firstIndex(of: "\"") {
                    let value = String(trimmed[trimmed.index(after: firstQuote)..<secondQuote])

                    switch currentSection {
                    case "[paths.readonly]":
                        readonly.append(MountEntry(path: value, mode: .readonly, learned: isLearned))
                    case "[paths.readwrite]":
                        readwrite.append(MountEntry(path: value, mode: .readwrite, learned: isLearned))
                    case "[network.allow]":
                        // Reject wildcards — not supported in v1 (INV-NF-5)
                        guard !value.contains("*") else {
                            throw ConfigError.wildcardDomain(value)
                        }
                        domains.append(DomainEntry(domain: value, learned: isLearned))
                    default:
                        break
                    }
                }
            }
        }

        return Config(readonlyPaths: readonly, readwritePaths: readwrite, allowedDomains: domains)
    }

    public func save(to path: String) throws {
        var lines: [String] = []
        lines.append("# Tarn global profile")
        lines.append("# Learned entries are added when you approve access with 'remember'.")
        lines.append("")

        func escaped(_ value: String) -> String {
            value.replacingOccurrences(of: "\\", with: "\\\\")
                 .replacingOccurrences(of: "\"", with: "\\\"")
                 .replacingOccurrences(of: "\n", with: "\\n")
                 .replacingOccurrences(of: "\r", with: "\\r")
                 .replacingOccurrences(of: "\t", with: "\\t")
        }

        lines.append("[paths.readonly]")
        lines.append("paths = [")
        for entry in readonlyPaths {
            let suffix = entry.learned ? " # learned" : ""
            lines.append("  \"\(escaped(entry.path))\",\(suffix)")
        }
        lines.append("]")
        lines.append("")

        lines.append("[paths.readwrite]")
        lines.append("paths = [")
        for entry in readwritePaths {
            let suffix = entry.learned ? " # learned" : ""
            lines.append("  \"\(escaped(entry.path))\",\(suffix)")
        }
        lines.append("]")
        lines.append("")

        lines.append("[network.allow]")
        lines.append("domains = [")
        for entry in allowedDomains {
            let suffix = entry.learned ? " # learned" : ""
            lines.append("  \"\(escaped(entry.domain))\",\(suffix)")
        }
        lines.append("]")

        let content = lines.joined(separator: "\n") + "\n"

        // Atomic write: write to temp, then atomic replace.
        // replaceItemAt is Apple's blessed API for this — it never
        // leaves a window where neither file exists.
        let tmpURL = URL(fileURLWithPath: path + ".tmp.\(ProcessInfo.processInfo.processIdentifier)")
        try? FileManager.default.removeItem(at: tmpURL)
        try content.write(to: tmpURL, atomically: false, encoding: .utf8)
        let targetURL = URL(fileURLWithPath: path)
        if FileManager.default.fileExists(atPath: path) {
            _ = try FileManager.default.replaceItemAt(targetURL, withItemAt: tmpURL)
        } else {
            try FileManager.default.moveItem(at: tmpURL, to: targetURL)
        }
    }

    public func display() {
        print("Read-only paths:")
        for entry in readonlyPaths {
            let tag = entry.learned ? " (learned)" : ""
            print("  \(entry.path)\(tag)")
        }
        print("\nRead-write paths:")
        for entry in readwritePaths {
            let tag = entry.learned ? " (learned)" : ""
            print("  \(entry.path)\(tag)")
        }
        print("\nAllowed network domains:")
        for entry in allowedDomains {
            let tag = entry.learned ? " (learned)" : ""
            print("  \(entry.domain)\(tag)")
        }
    }

    private func expandPath(_ path: String) -> String {
        NSString(string: path).expandingTildeInPath
    }

    /// Expand all tilde-prefixed paths using a specific home directory
    /// instead of the current process's home. Call this in the
    /// supervisor (which runs as root) after receiving the user's home
    /// from the CLI via XPC. Without this, `~` expands to
    /// `/var/root/` and the deny set is silently broken.
    public mutating func expandAllPaths(userHome: String) {
        func expand(_ path: String) -> String {
            if path.hasPrefix("~/") {
                return userHome + String(path.dropFirst())
            } else if path == "~" {
                return userHome
            }
            return path
        }

        readonlyPaths = readonlyPaths.map {
            MountEntry(path: expand($0.path), mode: $0.mode, learned: $0.learned)
        }
        readwritePaths = readwritePaths.map {
            MountEntry(path: expand($0.path), mode: $0.mode, learned: $0.learned)
        }
        deniedPaths = Set(deniedPaths.map { expand($0) })
        deniedDomains = Set(deniedDomains.map { $0 }) // domains don't have tildes, but be consistent
    }

    /// Check if an already-expanded path matches any denied pattern.
    /// After `expandAllPaths`, the deny patterns are already expanded
    /// so no tilde expansion is needed at check time.
    /// Both sides lowercased for case-insensitive APFS.
    public func isDeniedExpanded(path: String) -> Bool {
        let normalizedPath = path.lowercased()
        for pattern in deniedPaths {
            let normalizedPattern = pattern.lowercased()
            if normalizedPattern.hasSuffix("*") {
                let prefix = String(normalizedPattern.dropLast())
                if normalizedPath.hasPrefix(prefix) { return true }
            } else if normalizedPath == normalizedPattern || normalizedPath.hasPrefix(normalizedPattern + "/") {
                return true
            }
        }
        return false
    }
}

public enum AccessAction: Equatable {
    case allow
    case deny
}

public enum ConfigError: Error, CustomStringConvertible {
    case wildcardDomain(String)

    public var description: String {
        switch self {
        case .wildcardDomain(let domain):
            return "Wildcard domains are not supported: '\(domain)'. List subdomains explicitly."
        }
    }
}
