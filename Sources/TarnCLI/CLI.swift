import ArgumentParser
import Foundation
import TarnCore

@main
struct Tarn: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "A macOS-native permission supervisor for AI coding agents",
        version: "0.1.0",
        subcommands: [Run.self, ProfileCmd.self]
    )
}

// MARK: - Helpers

func defaultProfilePath() -> String {
    "\(NSHomeDirectory())/Library/Application Support/tarn/profile.toml"
}

// MARK: - tarn run

struct Run: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Launch a supervised agent session for a repository"
    )

    @Argument(help: "Path to the repository (read-write workspace)")
    var repoPath: String

    @Option(name: .long, help: "Agent to run (e.g. claude, codex, gemini)")
    var agent: String = "claude"

    @Option(name: .long, help: "Development stacks (e.g. node,python). Auto-detected if omitted.")
    var stack: String?

    @Option(name: .long, help: "Path to profile file")
    var profile: String = ""

    func run() throws {
        let expandedRepo = NSString(string: repoPath).expandingTildeInPath
        guard FileManager.default.fileExists(atPath: expandedRepo) else {
            throw ValidationError("Repository path does not exist: \(expandedRepo)")
        }

        let profilePath = profile.isEmpty ? defaultProfilePath() : NSString(string: profile).expandingTildeInPath

        // Acquire single-instance lock
        let lockPath = "\((profilePath as NSString).deletingLastPathComponent)/tarn.lock"
        let lock = Lock(path: lockPath)
        try lock.acquire()
        defer { lock.release() }

        // Load profile content as the user (the supervisor never reads
        // user files — INV-XPC-5). Ensure the file exists first.
        _ = try Config.load(from: profilePath) // creates defaults if missing
        let profileContent = try String(contentsOfFile: profilePath, encoding: .utf8)

        // Resolve agent and stacks for the session summary
        let agentProfile = AgentProfile.from(name: agent)
        let stackProfiles: [StackProfile]
        if let explicit = stack {
            stackProfiles = StackProfile.parse(explicit)
        } else {
            stackProfiles = ProfileResolver.detectStack(repoPath: expandedRepo)
        }
        let stackNames = stackProfiles.isEmpty ? [] : stackProfiles.map(\.name)

        // Connect to the supervisor via XPC
        let client = XPCClient(profilePath: profilePath)
        guard client.connect() else {
            print("tarn: cannot connect to supervisor.")
            print("  The system extension may not be active.")
            print("  Open Tarn.app to activate it, or check:")
            print("  System Settings → General → Login Items & Extensions")
            throw ExitCode.failure
        }
        defer { client.disconnect() }

        // Start session — supervisor builds the composed profile
        let startRequest = SessionStartRequest(
            repoPath: expandedRepo,
            agent: agent,
            stacks: stackNames,
            profilePath: profilePath,
            userHome: NSHomeDirectory(),
            profileContent: profileContent
        )
        guard let session = client.startSession(request: startRequest) else {
            print("tarn: failed to start session with supervisor")
            throw ExitCode.failure
        }

        defer { client.endSession(sessionId: session.sessionId) }

        // Display session summary
        let displayStacks = session.stackNames.joined(separator: ", ")
        print("tarn session")
        print("  Agent:    \(agent) (\(agentProfile.profile.name))")
        print("  Stacks:   \(displayStacks.isEmpty ? "none" : displayStacks)")
        print("  Repo:     \(expandedRepo)")
        print("  Profile:  \(profilePath)")
        print("  Entries:  \(session.allowCount) allow, \(session.denyCount) deny")
        print("")

        // Launch agent using posix_spawn for proper TTY inheritance.
        // Swift's Process() can place the child in a new process group,
        // making it a background job that can't read from the terminal.
        // posix_spawn without POSIX_SPAWN_SETPGROUP keeps the child in
        // our process group (the foreground group), so interactive agents
        // like Claude Code can read/write the TTY normally.
        let agentCommand = agentProfile.launchCommand
        print("Launching: \(agentCommand.joined(separator: " "))")
        print("")

        let fullCommand = ["/usr/bin/env"] + agentCommand
        let argv: [UnsafeMutablePointer<CChar>?] = fullCommand.map { strdup($0) } + [nil]
        defer { argv.forEach { if let p = $0 { free(p) } } }

        let env = scrubbedEnvironment()
        let envp: [UnsafeMutablePointer<CChar>?] = env.map { strdup("\($0.key)=\($0.value)") } + [nil]
        defer { envp.forEach { if let p = $0 { free(p) } } }

        var fileActions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&fileActions)
        posix_spawn_file_actions_addchdir_np(&fileActions, expandedRepo)
        defer { posix_spawn_file_actions_destroy(&fileActions) }

        var attrs: posix_spawnattr_t?
        posix_spawnattr_init(&attrs)
        defer { posix_spawnattr_destroy(&attrs) }

        var agentPid: pid_t = 0
        let spawnResult = posix_spawnp(&agentPid, argv[0], &fileActions, &attrs, argv, envp)
        guard spawnResult == 0 else {
            print("tarn: failed to launch agent (errno \(spawnResult))")
            throw ExitCode.failure
        }

        // Register the agent root PID with the supervisor's process tree
        client.registerAgentRoot(sessionId: session.sessionId, pid: agentPid)

        // Give the agent the foreground terminal so it can do
        // interactive I/O (raw mode, cursor control, etc.)
        let savedPgrp = tcgetpgrp(STDIN_FILENO)
        if savedPgrp >= 0 {
            tcsetpgrp(STDIN_FILENO, agentPid)
        }

        // Wait for the agent to exit. Meanwhile, XPC callbacks for
        // prompts and persist requests arrive on background threads
        // and are handled by the XPCClient (which calls PromptUI for
        // prompts and Config.save for persists).
        var status: Int32 = 0
        waitpid(agentPid, &status, 0)

        // Reclaim the terminal foreground
        if savedPgrp >= 0 {
            tcsetpgrp(STDIN_FILENO, savedPgrp)
        }

        let exited = (status & 0x7F) == 0
        let exitCode = exited ? (status >> 8) & 0xFF : Int32(1)
        if exitCode != 0 {
            print("\nAgent exited with status \(exitCode)")
        }
        Foundation.exit(exitCode)
    }
}

// MARK: - Helpers

/// Remove sensitive environment variables before passing to the agent.
func scrubbedEnvironment() -> [String: String] {
    let sensitiveKeys: Set<String> = [
        "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "AWS_SESSION_TOKEN",
        "GITHUB_TOKEN", "GH_TOKEN",
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
        "SSH_AUTH_SOCK",
        "NPM_TOKEN", "PYPI_TOKEN",
    ]
    let sensitivePatterns = ["SECRET", "PASSWORD", "CREDENTIAL", "PRIVATE_KEY"]
    var env = ProcessInfo.processInfo.environment
    for key in env.keys {
        let upper = key.uppercased()
        if sensitiveKeys.contains(upper) || sensitivePatterns.contains(where: { upper.contains($0) }) {
            env.removeValue(forKey: key)
        }
    }
    return env
}

// MARK: - tarn profile

struct ProfileCmd: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "profile",
        abstract: "Manage the global whitelist profile",
        subcommands: [Show.self, Reset.self]
    )

    struct Show: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Display the current whitelist profile"
        )

        @Option(name: .long, help: "Path to profile file")
        var profile: String = ""

        func run() throws {
            let profilePath = profile.isEmpty ? defaultProfilePath() : NSString(string: profile).expandingTildeInPath
            let config = try Config.load(from: profilePath)
            config.display()
        }
    }

    struct Reset: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Reset learned entries, keeping defaults"
        )

        @Option(name: .long, help: "Path to profile file")
        var profile: String = ""

        @Flag(name: .long, help: "Skip confirmation prompt")
        var force: Bool = false

        func run() throws {
            let profilePath = profile.isEmpty ? defaultProfilePath() : NSString(string: profile).expandingTildeInPath

            var config = try Config.load(from: profilePath)
            let learnedCount = config.readonlyPaths.filter(\.learned).count +
                               config.readwritePaths.filter(\.learned).count +
                               config.allowedDomains.filter(\.learned).count

            if learnedCount == 0 {
                print("No learned entries to remove. Profile is at defaults.")
                return
            }

            if !force {
                print("This will remove \(learnedCount) learned entries. Continue? [y/N] ", terminator: "")
                guard readLine()?.lowercased() == "y" else {
                    print("Aborted.")
                    return
                }
            }

            config.resetLearned()
            try config.save(to: profilePath)
            print("Removed \(learnedCount) learned entries.")
        }
    }
}
