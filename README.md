# Tarn

[![Test](https://github.com/witlox/tarn/actions/workflows/test.yml/badge.svg)](https://github.com/witlox/tarn/actions/workflows/test.yml)
[![Lint](https://github.com/witlox/tarn/actions/workflows/lint.yml/badge.svg)](https://github.com/witlox/tarn/actions/workflows/lint.yml)
[![codecov](https://codecov.io/gh/witlox/tarn/graph/badge.svg)](https://codecov.io/gh/witlox/tarn)
[![Swift 5.10](https://img.shields.io/badge/Swift-5.10-orange.svg)](https://swift.org)
[![macOS 14+](https://img.shields.io/badge/macOS-14%2B-blue.svg)](https://developer.apple.com/macos/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A macOS-native permission supervisor for AI coding agents.

Tarn intercepts file and network access from AI coding agents at the kernel level, prompts you for unknown access patterns, and learns a persistent whitelist as you approve. It uses Apple's Endpoint Security framework for file supervision and a Network Extension content filter for network supervision, both running inside a single signed system extension.

It works with Claude Code, Codex, Gemini CLI, opencode, or any terminal-based coding agent.

## How it works

When you run `tarn run ~/repos/my-project --agent claude`, tarn:

1. Launches the agent in "autonomous mode" (e.g., `claude --dangerously-skip-permissions`)
2. Supervises every file open and network connection from the agent and its child processes
3. Allows known-safe access silently (your workspace, system libraries, whitelisted paths and domains)
4. Prompts you in the terminal for anything unknown:

```
┌─ tarn ─────────────────────────────────
│ File read: /etc/npmrc
│ Process: /usr/bin/node (PID 1234)
├────────────────────────────────────────
│ [a] Allow once
│ [A] Allow and remember
│ [d] Deny
└────────────────────────────────────────
  Choice [a/A/d]:
```

"Allow and remember" adds the entry to your persistent whitelist. Over time, the prompts stop — the agent runs uninterrupted within the boundaries you've approved.

## What it supervises

**File access** — every file open by the agent or its subprocesses is checked against the deny set (credential locations like `~/.aws`, `~/.ssh/id_*`, `~/.gnupg`), the allow set (your whitelist), and the session cache. Writes to read-only paths are denied without prompting. The workspace directory and system paths are always allowed.

**Network access** — every outbound TCP/UDP connection is checked against the domain whitelist. The destination hostname is extracted from the connection metadata or the TLS ClientHello SNI. Prompts show the hostname, not a raw IP. Allowed domains like `api.anthropic.com`, `github.com`, and `registry.npmjs.org` are shipped as defaults; you add more as you work.

## What it does not do

- It is not a VM or container. The agent runs natively on your Mac.
- It is not a general-purpose firewall. It only supervises the agent's process tree; all other processes are unaffected.
- It does not protect against hostile code that deliberately attacks the supervisor. Use a VM for that.
- It does not intercept DNS. DNS-level filtering is better handled by tools like AdGuard.

See [docs/security.md](docs/security.md) for the full threat model.

## Installation

### Requirements

- macOS 14 (Sonoma) or later
- Xcode 16+ (for building)
- Apple Developer Program membership with Endpoint Security and Network Extension entitlements

### Build

```bash
xcodegen generate       # generate the Xcode project from project.yml
make build              # build TarnCore + CLI via SPM
make test               # run 190 unit + 17 integration tests
```

The system extension (ES client + NE content filter) requires `xcodebuild` with the full macOS SDK:

```bash
make release TEAM_ID=<your-team-id>   # signed Tarn.app for distribution
```

After building, notarize for distribution:

```bash
xcrun notarytool submit .build/release-app/Tarn.app.zip --keychain-profile "tarn" --wait
```

`CFBundleVersion` is derived automatically from the git commit count.

### Installation

Copy `Tarn.app` to `/Applications`:

```bash
cp -R .build/release-app/Tarn.app /Applications/
```

The app must live in `/Applications` for system extension activation to succeed.

### First run

```bash
tarn run ~/repos/my-project
```

On first run, macOS prompts you to approve the system extension in **System Settings → General → Login Items & Extensions**, then to enable the content filter in **System Settings → Network → Filters**. The content filter is activated via `NEFilterManager.saveToPreferences`. After that, the supervisor runs as a background daemon and the CLI talks to it via XPC. No `sudo` needed.

### Development without entitlements

Disable SIP on a test machine or VM. The CLI and the policy library (`TarnCore`) build and test on any machine via `swift test`. The system extension needs a SIP-disabled environment or proper code signing to actually run.

## Usage

```bash
tarn run ~/repos/my-project                     # auto-detect stacks
tarn run ~/repos/my-project --agent claude       # specify agent
tarn run ~/repos/my-project --agent codex        # works with any agent
tarn run ~/repos/my-project --stack node,python  # explicit stacks
tarn profile show                                # display current whitelist
tarn profile reset                               # clear learned entries
```

### Supported agents

| Agent | Launch command | API domains |
|---|---|---|
| Claude Code | `claude --dangerously-skip-permissions` | `api.anthropic.com` |
| Codex | `codex --dangerously-bypass-approvals-and-sandbox` | `api.openai.com` |
| Gemini CLI | `gemini --yolo` | `generativelanguage.googleapis.com` |
| opencode | `opencode` | `api.anthropic.com`, `api.openai.com` |
| Custom | `<name>` | (none — you approve via prompts) |

### Stack profiles

Tarn auto-detects development stacks from your repo and loads the appropriate toolchain paths and package-registry domains:

| Stack | Detection | Key paths | Key domains |
|---|---|---|---|
| Node | `package.json` | `~/.npm`, `~/.nvm` | `registry.npmjs.org` |
| Python | `pyproject.toml` | `~/.pyenv`, `~/.cache/pip` | `pypi.org` |
| Rust | `Cargo.toml` | `~/.cargo`, `~/.rustup` | `crates.io` |
| Go | `go.mod` | `~/go` | `proxy.golang.org` |
| Xcode/Swift | `Package.swift` | `~/Library/Developer` | `developer.apple.com` |

## Whitelist

The persistent whitelist lives at `~/Library/Application Support/tarn/profile.toml`. It is a plain TOML file you can edit by hand:

```toml
[paths.readonly]
paths = [
  "~/.gitconfig",
  "~/.ssh/known_hosts",
  "~/.npmrc", # learned
]

[paths.readwrite]
paths = []

[network.allow]
domains = [
  "api.anthropic.com",
  "github.com",
  "registry.npmjs.org",
]
```

Entries marked `# learned` were added by the "Allow and remember" prompt response. `tarn profile reset` removes only learned entries; your hand-edited defaults are preserved.

### Deny list

The compiled-in deny list protects sensitive credential locations regardless of any allow rule:

- `~/.aws` (AWS credentials)
- `~/.ssh/id_*` (SSH private keys, excluding `*.pub`)
- `~/.ssh/config` (SSH client configuration)
- `~/.gnupg` (GPG keyring)
- `~/.config/gh` (GitHub CLI tokens)
- `~/.config/gcloud` (Google Cloud credentials)
- `~/.azure` (Azure credentials)
- `~/.kube/config` (Kubernetes credentials)
- `~/.docker/config.json` (Docker credentials)
- `~/.npmrc` (npm auth tokens)
- `~/.pypirc` (PyPI auth tokens)
- `~/.netrc` (machine credentials)
- `~/Library/Keychains` (macOS Keychain)
- `~/Library/Cookies`, `~/Library/Safari`

The deny list cannot be overridden by learned entries or manual whitelist edits. It is the security floor.

## Compatibility

See [docs/compatibility.md](docs/compatibility.md) for details.

- **AdGuard**: compatible (different Network Extension slot)
- **Little Snitch 5+**: **not compatible** (same content filter slot)
- **LuLu**: **not compatible** (same content filter slot)
- **VPNs**: compatible (different Network Extension slot)

## Architecture

Tarn ships as a `.app` bundle containing:

- An unprivileged CLI (`Contents/MacOS/tarn`)
- A system extension (`Contents/Library/SystemExtensions/com.witlox.tarn.supervisor.systemextension`)

The system extension hosts both the Endpoint Security client (file/process events) and the `NEFilterDataProvider` (network flows). The CLI and the extension communicate via XPC. The CLI handles all user interaction; the extension handles all kernel-level interception.

See [docs/architecture/design.md](docs/architecture/design.md) for the full architecture, and [docs/decisions/](docs/decisions/) for the design decision records.

## Project structure

```
Tarn.xcodeproj/         Xcode project (generated from project.yml)
Package.swift           SPM manifest for TarnCore + TarnCLI + tests
project.yml             XcodeGen spec — source of truth for the Xcode project
Sources/
  TarnCore/             Shared library: policy, profiles, config, errors
  TarnCLI/              Unprivileged CLI
  TarnSupervisor/       System extension: ES client + NE filter + XPC service
  TarnApp/              Host app bundle (no UI)
Resources/              Info.plists and entitlements
Tests/TarnCoreTests/    190 unit tests
Tests/TarnIntegrationTests/ 17 integration tests
docs/                   Architecture, specs, decisions, analysis
```

## License

MIT. See [LICENSE](LICENSE).
