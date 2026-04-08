import Foundation

/// A composable security profile that declares allowed paths and domains.
/// Profiles are layered: base → stack → agent → user TOML → session cache.
/// Later layers extend but never remove entries from earlier layers.
public protocol SecurityProfile {
    var name: String { get }
    var readonlyPaths: [String] { get }
    var readwritePaths: [String] { get }
    var allowedDomains: [String] { get }
    /// Paths that should be denied regardless of other rules.
    /// Takes precedence over allow rules in the same or lower layers.
    var deniedPaths: [String] { get }
}

public extension SecurityProfile {
    var deniedPaths: [String] { [] }
}

/// Merges multiple profiles into a single resolved configuration.
/// The merge is additive: each layer adds to the allow sets.
/// Denied paths are collected separately and take precedence at check time.
public struct ProfileResolver {
    /// Merge a stack of profiles into a Config.
    /// Order matters: later profiles extend earlier ones.
    public static func resolve(profiles: [SecurityProfile], userConfig: Config) -> Config {
        var readonly: [MountEntry] = []
        var readwrite: [MountEntry] = []
        var domains: [DomainEntry] = []
        var denied: Set<String> = []

        for profile in profiles {
            for path in profile.readonlyPaths {
                if !readonly.contains(where: { $0.path == path }) {
                    readonly.append(MountEntry(path: path, mode: .readonly, learned: false))
                }
            }
            for path in profile.readwritePaths {
                if !readwrite.contains(where: { $0.path == path }) {
                    readwrite.append(MountEntry(path: path, mode: .readwrite, learned: false))
                }
            }
            for domain in profile.allowedDomains {
                if !domains.contains(where: { $0.domain == domain }) {
                    domains.append(DomainEntry(domain: domain, learned: false))
                }
            }
            for path in profile.deniedPaths {
                denied.insert(path)
            }
        }

        // Layer user config on top (these include learned entries)
        for entry in userConfig.readonlyPaths {
            if !readonly.contains(where: { $0.path == entry.path }) {
                readonly.append(entry)
            }
        }
        for entry in userConfig.readwritePaths {
            if !readwrite.contains(where: { $0.path == entry.path }) {
                readwrite.append(entry)
            }
        }
        for entry in userConfig.allowedDomains {
            if !domains.contains(where: { $0.domain == entry.domain }) {
                domains.append(entry)
            }
        }

        var config = Config(
            readonlyPaths: readonly,
            readwritePaths: readwrite,
            allowedDomains: domains
        )
        config.deniedPaths = denied
        return config
    }

    /// Auto-detect which stack profile to activate based on repo contents.
    public static func detectStack(repoPath: String) -> [StackProfile] {
        let fm = FileManager.default
        var detected: [StackProfile] = []

        let indicators: [(file: String, profile: StackProfile)] = [
            ("package.json", .node),
            ("bun.lockb", .node),
            ("yarn.lock", .node),
            ("Cargo.toml", .rust),
            ("go.mod", .go),
            ("pyproject.toml", .python),
            ("requirements.txt", .python),
            ("Pipfile", .python),
            ("Package.swift", .xcode),
            ("*.xcodeproj", .xcode),
        ]

        for indicator in indicators {
            let path = (repoPath as NSString).appendingPathComponent(indicator.file)
            if indicator.file.contains("*") {
                // Glob: check if any matching file exists
                if let contents = try? fm.contentsOfDirectory(atPath: repoPath),
                   contents.contains(where: { $0.hasSuffix(String(indicator.file.dropFirst())) }) {
                    if !detected.contains(where: { $0.name == indicator.profile.name }) {
                        detected.append(indicator.profile)
                    }
                }
            } else if fm.fileExists(atPath: path) {
                if !detected.contains(where: { $0.name == indicator.profile.name }) {
                    detected.append(indicator.profile)
                }
            }
        }

        return detected
    }
}
