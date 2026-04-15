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

    @Argument(help: "Path to the repository (read-write workspace). Defaults to current directory.")
    var repoPath: String?

    @Option(name: .long, help: "Agent to run (e.g. claude, codex, gemini)")
    var agent: String = "claude"

    @Option(name: .long, help: "Development stacks (e.g. node,python). Auto-detected if omitted.")
    var stack: String?

    @Option(name: .long, help: "Path to profile file")
    var profile: String = ""

    @Flag(name: .long, help: "Resume the agent's last session")
    var resume: Bool = false

    func run() throws {
        let rawPath = repoPath ?? FileManager.default.currentDirectoryPath
        let expandedRepo = NSString(string: rawPath).expandingTildeInPath
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

        var agentCommand = agentProfile.launchCommand
        if resume { agentCommand.append("--resume") }
        print("Launching: \(agentCommand.joined(separator: " "))")
        print("")

        // Ignore SIGTTOU so our XPC callbacks can write to the
        // terminal even when the agent's process group is foreground.
        // Without this, the shell suspends tarn when it tries to
        // output the prompt.
        signal(SIGTTOU, SIG_IGN)

        // F-01: Register BEFORE spawn so the ES extension is watching for
        // the fork event. The ES extension watches for the next fork from
        // our PID and unmutes the child.
        client.prepareAgentLaunch(sessionId: session.sessionId)

        // F-01: Agent starts suspended (POSIX_SPAWN_START_SUSPENDED).
        // Confirm PID with ES extension, THEN send SIGCONT. This ensures
        // the agent is in the process tree before it can execute.
        let agentPid = try spawnAgent(command: agentCommand, workingDirectory: expandedRepo)
        client.agentPid = agentPid
        client.confirmAgentPID(sessionId: session.sessionId, pid: agentPid)

        // Give the agent the terminal foreground BEFORE resuming.
        // Otherwise it gets SIGTTIN (background read) and stops.
        tcsetpgrp(STDIN_FILENO, agentPid)

        // F-01: Resume the suspended agent now that it is registered
        // and has the terminal foreground.
        kill(agentPid, SIGCONT)

        let exitCode = waitForAgent(pid: agentPid)
        if exitCode != 0 {
            print("\nAgent exited with status \(exitCode)")
        }
        Foundation.exit(exitCode)
    }
}

// MARK: - Helpers

/// Launch the agent via posix_spawn in its own process group.
/// The agent gets its own PGID so we can SIGSTOP/SIGCONT the
/// entire tree (agent + child processes) during tarn prompts.
/// We then use tcsetpgrp() to make it the foreground group
/// so it can do interactive TTY I/O.
/// Resolve a command name to its full path by searching PATH.
func resolveCommand(_ name: String) -> String? {
    guard let pathEnv = ProcessInfo.processInfo.environment["PATH"] else { return nil }
    for dir in pathEnv.split(separator: ":") {
        let full = "\(dir)/\(name)"
        if FileManager.default.isExecutableFile(atPath: full) {
            return full
        }
    }
    return nil
}

func spawnAgent(command: [String], workingDirectory: String) throws -> pid_t {
    // Resolve the binary path ourselves instead of using /usr/bin/env.
    // env opens "/" to traverse PATH, which triggers an ES AUTH_OPEN
    // for the root directory under the supervised PID.
    guard let binaryPath = resolveCommand(command[0]) else {
        print("tarn: command not found: \(command[0])")
        throw ExitCode.failure
    }
    let fullCommand = [binaryPath] + Array(command.dropFirst())
    let argv: [UnsafeMutablePointer<CChar>?] = fullCommand.map { strdup($0) } + [nil]
    defer { argv.forEach { if let ptr = $0 { free(ptr) } } }

    let env = scrubbedEnvironment()
    let envp: [UnsafeMutablePointer<CChar>?] = env.map { strdup("\($0.key)=\($0.value)") } + [nil]
    defer { envp.forEach { if let ptr = $0 { free(ptr) } } }

    var fileActions: posix_spawn_file_actions_t?
    posix_spawn_file_actions_init(&fileActions)
    posix_spawn_file_actions_addchdir_np(&fileActions, workingDirectory)
    defer { posix_spawn_file_actions_destroy(&fileActions) }

    var attrs: posix_spawnattr_t?
    posix_spawnattr_init(&attrs)
    // Put agent in its own process group (PGID = its PID).
    // This lets us stop the entire tree with kill(-pid, SIGSTOP).
    // F-01: Start suspended so the agent cannot execute before
    // the ES extension registers it in the process tree.
    let flags: Int16 = Int16(POSIX_SPAWN_SETPGROUP) | Int16(0x0080) // 0x0080 = POSIX_SPAWN_START_SUSPENDED
    posix_spawnattr_setflags(&attrs, flags)
    posix_spawnattr_setpgroup(&attrs, 0)  // 0 = PGID equals child PID
    defer { posix_spawnattr_destroy(&attrs) }

    var pid: pid_t = 0
    let result = posix_spawn(&pid, binaryPath, &fileActions, &attrs, argv, envp)
    guard result == 0 else {
        print("tarn: failed to launch agent (errno \(result))")
        throw ExitCode.failure
    }
    return pid
}

/// Wait for the agent process to exit, managing terminal foreground.
/// Note: tcsetpgrp is called BEFORE SIGCONT in Run.run(), not here.
func waitForAgent(pid: pid_t) -> Int32 {
    let savedPgrp = tcgetpgrp(STDIN_FILENO)

    var status: Int32 = 0
    waitpid(pid, &status, 0)

    // Reclaim the terminal foreground
    if savedPgrp >= 0 {
        tcsetpgrp(STDIN_FILENO, savedPgrp)
    }

    let exited = (status & 0x7F) == 0
    return exited ? (status >> 8) & 0xFF : Int32(1)
}

/// Remove sensitive environment variables before passing to the agent.
func scrubbedEnvironment() -> [String: String] {
    let sensitiveKeys: Set<String> = [
        "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "AWS_SESSION_TOKEN",
        "GITHUB_TOKEN", "GH_TOKEN",
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
        "SSH_AUTH_SOCK",
        "NPM_TOKEN", "PYPI_TOKEN",
        // F-21: Additional sensitive variables
        "GOOGLE_APPLICATION_CREDENTIALS",
        "KUBECONFIG",
        "DOCKER_AUTH_CONFIG",
    ]
    // F-21: Added "TOKEN" to catch VAULT_TOKEN, CIRCLECI_TOKEN, etc.
    let sensitivePatterns = ["SECRET", "PASSWORD", "CREDENTIAL", "PRIVATE_KEY", "TOKEN"]
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
