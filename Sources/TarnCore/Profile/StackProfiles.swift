import Foundation

/// Development stack profiles. Activated automatically based on
/// repo contents (e.g., package.json → node) or explicitly via
/// --stack flag. Multiple stacks can be active simultaneously.
public enum StackProfile {
    case node
    case python
    case rust
    case go
    case xcode

    public var name: String {
        switch self {
        case .node: return "stack-node"
        case .python: return "stack-python"
        case .rust: return "stack-rust"
        case .go: return "stack-go"
        case .xcode: return "stack-xcode"
        }
    }

    public var profile: SecurityProfile {
        switch self {
        case .node: return NodeProfile()
        case .python: return PythonProfile()
        case .rust: return RustProfile()
        case .go: return GoProfile()
        case .xcode: return XcodeProfile()
        }
    }

    /// Parse a comma-separated stack string.
    public static func parse(_ input: String) -> [StackProfile] {
        input.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            .compactMap { name in
                switch name {
                case "node", "js", "javascript", "typescript": return .node
                case "python", "py": return .python
                case "rust", "rs": return .rust
                case "go", "golang": return .go
                case "xcode", "swift", "ios", "macos": return .xcode
                default: return nil
                }
            }
    }
}

// MARK: - Stack Profile Implementations

public struct NodeProfile: SecurityProfile {
    public let name = "stack-node"

    public let readonlyPaths: [String] = [
        "~/.npmrc",
        "~/.yarnrc",
        "~/.yarnrc.yml",
        "~/.bunfig.toml",
        "~/.nvm",
        "~/.volta",
        "~/.fnm",
        "/opt/homebrew/lib/node_modules",
    ]

    public let readwritePaths: [String] = [
        "~/.npm",
        "~/.yarn",
        "~/.bun/install",
        "~/.cache/yarn",
        "~/.cache/bun",
    ]

    public let allowedDomains: [String] = [
        "registry.npmjs.org",
        "registry.yarnpkg.com",
    ]
}

public struct PythonProfile: SecurityProfile {
    public let name = "stack-python"

    public let readonlyPaths: [String] = [
        "~/.pyenv",
        "~/.local/bin",
        "~/.config/pip",
        "/opt/homebrew/lib/python3*",
    ]

    public let readwritePaths: [String] = [
        "~/.cache/pip",
        "~/.cache/uv",
        "~/.local/share/virtualenvs",
    ]

    public let allowedDomains: [String] = [
        "pypi.org",
        "files.pythonhosted.org",
    ]
}

public struct RustProfile: SecurityProfile {
    public let name = "stack-rust"

    public let readonlyPaths: [String] = [
        "~/.rustup",
        "~/.cargo/bin",
        "~/.cargo/config.toml",
    ]

    public let readwritePaths: [String] = [
        "~/.cargo/registry",
        "~/.cargo/git",
        "~/.cargo/.package-cache",
    ]

    public let allowedDomains: [String] = [
        "crates.io",
        "static.crates.io",
        "index.crates.io",
    ]
}

public struct GoProfile: SecurityProfile {
    public let name = "stack-go"

    public let readonlyPaths: [String] = [
        "~/go/bin",
        "~/go/pkg/mod",
        "~/.config/go",
        "/usr/local/go",
        "/opt/homebrew/Cellar/go",
    ]

    public let readwritePaths: [String] = [
        "~/go/pkg/mod/cache",
    ]

    public let allowedDomains: [String] = [
        "proxy.golang.org",
        "sum.golang.org",
        "storage.googleapis.com",
    ]
}

public struct XcodeProfile: SecurityProfile {
    public let name = "stack-xcode"

    public let readonlyPaths: [String] = [
        "/Applications/Xcode.app",
        "/Library/Developer",
        "~/Library/Developer/Xcode",
        "~/Library/Developer/CoreSimulator",
    ]

    public let readwritePaths: [String] = [
        "~/Library/Developer/Xcode/DerivedData",
        "~/Library/Caches/org.swift.swiftpm",
    ]

    public let allowedDomains: [String] = [
        "developer.apple.com",
        "swiftpackageindex.com",
    ]
}
