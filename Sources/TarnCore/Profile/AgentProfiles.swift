import Foundation

/// Per-agent profiles. Each agent CLI needs access to its own
/// configuration directory and specific API endpoints.
public enum AgentProfile {
    case claude
    case codex
    case gemini
    case opencode
    case custom(String)

    /// Resolve an agent name string to a profile.
    public static func from(name: String) -> AgentProfile {
        switch name.lowercased() {
        case "claude": return .claude
        case "codex": return .codex
        case "gemini": return .gemini
        case "opencode": return .opencode
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
    ]

    public let readwritePaths: [String] = [
        "~/.claude/projects",
        "~/.claude/statsig",
    ]

    public let allowedDomains: [String] = [
        "api.anthropic.com",
        "statsig.anthropic.com",
        "sentry.io",
    ]
}

public struct CodexProfile: SecurityProfile {
    public let name = "agent-codex"

    public let readonlyPaths: [String] = [
        "~/.codex",
        "~/.config/codex",
    ]

    public let readwritePaths: [String] = [
        "~/.codex",
    ]

    public let allowedDomains: [String] = [
        "api.openai.com",
    ]
}

public struct GeminiProfile: SecurityProfile {
    public let name = "agent-gemini"

    public let readonlyPaths: [String] = [
        "~/.gemini",
        "~/.config/gemini",
    ]

    public let readwritePaths: [String] = [
        "~/.gemini",
    ]

    public let allowedDomains: [String] = [
        "generativelanguage.googleapis.com",
        "aistudio.google.com",
    ]
}

public struct OpenCodeProfile: SecurityProfile {
    public let name = "agent-opencode"

    public let readonlyPaths: [String] = [
        "~/.config/opencode",
    ]

    public let readwritePaths: [String] = [
        "~/.config/opencode",
    ]

    public let allowedDomains: [String] = [
        "api.anthropic.com",
        "api.openai.com",
        "generativelanguage.googleapis.com",
    ]
}

/// Minimal profile for unknown agents — no special paths, no domains.
public struct MinimalAgentProfile: SecurityProfile {
    public let name = "agent-custom"
    public let readonlyPaths: [String] = []
    public let readwritePaths: [String] = []
    public let allowedDomains: [String] = []
}
