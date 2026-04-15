import Foundation

/// Per-agent profiles. Each agent CLI needs access to its own
/// configuration directory and specific API endpoints.
public enum AgentProfile {
    case claude
    case codex
    case gemini
    case opencode
    case ghyll
    case custom(String)

    /// Resolve an agent name string to a profile.
    public static func from(name: String) -> AgentProfile {
        switch name.lowercased() {
        case "claude": return .claude
        case "codex": return .codex
        case "gemini": return .gemini
        case "opencode": return .opencode
        case "ghyll": return .ghyll
        default: return .custom(name)
        }
    }

    /// The command and arguments to launch this agent in YOLO mode.
    public var launchCommand: [String] {
        switch self {
        case .claude:
            return ["claude", "--dangerously-skip-permissions"]
        case .codex:
            return ["codex", "--dangerously-bypass-approvals-and-sandbox"]
        case .gemini:
            return ["gemini", "--yolo"]
        case .opencode:
            return ["opencode"]
        case .ghyll:
            return ["ghyll", "run", "."]
        case .custom(let cmd):
            return [cmd]
        }
    }

    /// The security profile for this agent.
    public var profile: SecurityProfile {
        switch self {
        case .claude: return ClaudeProfile()
        case .codex: return CodexProfile()
        case .gemini: return GeminiProfile()
        case .opencode: return OpenCodeProfile()
        case .ghyll: return GhyllProfile()
        case .custom: return MinimalAgentProfile()
        }
    }
}

// MARK: - Agent Profile Implementations

public struct ClaudeProfile: SecurityProfile {
    public let name = "agent-claude"

    public let readonlyPaths: [String] = [
        "~/.claude",
        "~/.config/claude",
        "~/.gitconfig",
        "~/.gitignore_global",
    ]

    public let readwritePaths: [String] = [
        "~/.claude/projects",
        "~/.claude/statsig",
        "~/.claude/memory",
        "~/.claude/settings.json",
        "~/.claude/todos",
    ]

    public let allowedDomains: [String] = [
        "api.anthropic.com",
        "cdn.anthropic.com",
        "statsig.anthropic.com",
        "sentry.io",
    ]
}

public struct CodexProfile: SecurityProfile {
    public let name = "agent-codex"

    public let readonlyPaths: [String] = [
        "~/.codex",
        "~/.config/codex",
        "~/.gitconfig",
        "~/.gitignore_global",
    ]

    public let readwritePaths: [String] = [
        "~/.codex/history",
        "~/.codex/cache",
    ]

    public let allowedDomains: [String] = [
        "api.openai.com",
        "cdn.openai.com",
    ]
}

public struct GeminiProfile: SecurityProfile {
    public let name = "agent-gemini"

    public let readonlyPaths: [String] = [
        "~/.gemini",
        "~/.config/gemini",
        "~/.gitconfig",
        "~/.gitignore_global",
    ]

    public let readwritePaths: [String] = [
        "~/.gemini/history",
        "~/.gemini/cache",
    ]

    public let allowedDomains: [String] = [
        "generativelanguage.googleapis.com",
        "aistudio.google.com",
        "alkalimakersuite-pa.clients6.google.com",
    ]
}

public struct OpenCodeProfile: SecurityProfile {
    public let name = "agent-opencode"

    public let readonlyPaths: [String] = [
        "~/.config/opencode",
        "~/.gitconfig",
        "~/.gitignore_global",
    ]

    public let readwritePaths: [String] = [
        "~/.config/opencode/history",
        "~/.config/opencode/cache",
    ]

    public let allowedDomains: [String] = [
        "api.anthropic.com",
        "api.openai.com",
        "generativelanguage.googleapis.com",
    ]
}

public struct GhyllProfile: SecurityProfile {
    public let name = "agent-ghyll"

    public let readonlyPaths: [String] = [
        "~/.ghyll",
        "~/.gitconfig",
        "~/.gitignore_global",
    ]

    public let readwritePaths: [String] = [
        "~/.ghyll/memory.db",
        "~/.ghyll/memory.db-wal",
        "~/.ghyll/memory.db-shm",
        "~/.ghyll/keys",
        "~/.ghyll/vault.db",
    ]

    // Ghyll connects to self-hosted model endpoints configured in
    // ~/.ghyll/config.toml. Domains are user-specific so we only
    // include the known defaults (embedding model, web search).
    public let allowedDomains: [String] = [
        "huggingface.co",
        "html.duckduckgo.com",
    ]
}

/// Minimal profile for unknown agents — no special paths, no domains.
public struct MinimalAgentProfile: SecurityProfile {
    public let name = "agent-custom"
    public let readonlyPaths: [String] = []
    public let readwritePaths: [String] = []
    public let allowedDomains: [String] = []
}
