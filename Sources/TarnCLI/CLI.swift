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

/// The CLI runs unprivileged (no sudo). The user's home directory is
/// simply NSHomeDirectory(). The supervisor runs as root via launchd
/// and never resolves user paths itself (INV-XPC-5).
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

        // Load user config
        let userConfig = try Config.load(from: profilePath)

        // Resolve profiles
        let agentProfile = AgentProfile.from(name: agent)
        let stackProfiles: [StackProfile]
        if let explicit = stack {
            stackProfiles = StackProfile.parse(explicit)
        } else {
            stackProfiles = ProfileResolver.detectStack(repoPath: expandedRepo)
        }

        // Compose profile chain
        var layers: [SecurityProfile] = [BaseProfile()]
        layers += stackProfiles.map { $0.profile }
        layers.append(agentProfile.profile)
        let config = ProfileResolver.resolve(profiles: layers, userConfig: userConfig)

        // Display session summary
        let stackNames = stackProfiles.map { $0.name }.joined(separator: ", ")
        print("tarn session")
        print("  Agent:    \(agent) (\(agentProfile.profile.name))")
        print("  Stacks:   \(stackNames.isEmpty ? "none" : stackNames)")
        print("  Repo:     \(expandedRepo)")
        print("  Profile:  \(profilePath)")
        print("  Entries:  \(config.totalEntries) allow, \(config.deniedPaths.count) deny")
        print("")

        // Launch agent
        let agentCommand = agentProfile.launchCommand
        print("Launching: \(agentCommand.joined(separator: " "))")
        print("")

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = agentCommand
        process.currentDirectoryURL = URL(fileURLWithPath: expandedRepo)
        process.standardInput = FileHandle.standardInput
        process.standardOutput = FileHandle.standardOutput
        process.standardError = FileHandle.standardError

        try process.run()
        process.waitUntilExit()

        if process.terminationStatus != 0 {
            print("Agent exited with status \(process.terminationStatus)")
        }
        Foundation.exit(process.terminationStatus)
    }
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
