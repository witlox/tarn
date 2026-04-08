import Foundation

/// Base macOS profile. Every supervised process needs these paths
/// to function at all — system libraries, frameworks, devices, etc.
/// These correspond to Tarn's hardcoded fast paths in the monitor,
/// but expressed as a profile for composition and documentation.
public struct BaseProfile: SecurityProfile {
    public init() {}
    public let name = "base-macos"

    public let readonlyPaths: [String] = [
        "/System",
        "/Library",
        "/usr",
        "/bin",
        "/sbin",
        "/dev",
        "/private/etc",
        "/private/var/db",
        "/Applications",
        "/opt/homebrew",
        "/opt/homebrew/bin",
        "/opt/homebrew/lib",
        "/opt/homebrew/Cellar",
    ]

    public let readwritePaths: [String] = [
        "/dev/null",
        "/dev/tty",
        "/dev/urandom",
    ]

    public let allowedDomains: [String] = []

    /// Paths that are always denied regardless of other profiles.
    /// These represent sensitive credential and configuration locations
    /// that no agent should access.
    public let deniedPaths: [String] = [
        "~/.ssh/id_*",
        "~/.ssh/id_*.pub",
        "~/.aws",
        "~/.gnupg",
        "~/.config/gh",
        "~/.netrc",
        "~/.docker/config.json",
        "~/Library/Keychains",
        "~/Library/Cookies",
        "~/Library/Safari",
    ]
}
