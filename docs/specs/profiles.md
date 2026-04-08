# Specification: Profile System

Tarn uses composable security profiles to define which paths and domains are accessible. Profiles are layered additively: each layer extends the set of allowed resources without removing entries from earlier layers. A separate deny list takes precedence over all allow rules.

## Profile Chain

The profile chain is evaluated in order. Later layers add entries; they cannot subtract entries from earlier layers. The deny list is collected from all layers and evaluated first during access checks.

1. **Base (base-macos)**: System paths every process needs — `/usr`, `/System`, `/Library`, `/bin`, `/dev`, Homebrew paths. Also declares the global credential deny list (`~/.aws`, `~/.ssh/id_*`, `~/.gnupg`, etc.).

2. **Stack(s)**: Development toolchain profiles. Zero or more, activated by `--stack` flag or auto-detected from repo contents. Each stack declares toolchain-specific read paths (e.g., `~/.rustup`), cache write paths (e.g., `~/.cargo/registry`), and package registry domains (e.g., `crates.io`).

3. **Agent**: Per-agent profile for the coding assistant. Declares the agent's config directory, session storage, and API domains. Activated by the `--agent` flag.

4. **User TOML**: The persistent `~/Library/Application Support/tarn/profile.toml`. Contains both default entries and learned entries. Learned entries are added when the user approves access with "remember."

5. **Session cache**: In-memory cache of per-session decisions. Not persisted. Cleared when tarn exits.

## Auto-Detection

When `--stack` is not provided, Tarn inspects the repo directory for indicator files and activates matching stack profiles. Multiple stacks can be active simultaneously (e.g., a repo with both `package.json` and `pyproject.toml`).

Detection indicators: `package.json` / `bun.lockb` / `yarn.lock` → node. `Cargo.toml` → rust. `go.mod` → go. `pyproject.toml` / `requirements.txt` / `Pipfile` → python. `Package.swift` / `*.xcodeproj` → xcode.

Explicit `--stack` always overrides auto-detection. The flag accepts comma-separated names with aliases (e.g., `js`, `py`, `golang`, `swift`).

## Deny List

The deny list is a set of path patterns (exact or glob with `*` suffix) that are always denied regardless of any allow rule. It is populated by profiles (primarily the base profile) and is not editable via the user TOML.

The deny list covers sensitive credential and configuration locations: SSH private keys, AWS credentials, GPG keyrings, GitHub CLI tokens, Docker credentials, macOS Keychain, browser cookies, and Safari data.

Denied paths are checked before any allow rule. A denied path cannot be overridden by a learned entry, a stack profile, or an agent profile. This ensures that even if a prompt injection tricks the user into approving access, the credential deny list holds.

## Built-In Profiles

Profiles are compiled into the tarn binary as Swift structs conforming to the `SecurityProfile` protocol. They are not external files. This eliminates file-not-found errors, registry dependencies, and supply chain risk from the profiles themselves.

Shipped profiles: base-macos, agent-claude, agent-codex, agent-gemini, agent-opencode, stack-node, stack-python, stack-rust, stack-go, stack-xcode.

## Session Summary

On startup, tarn displays a session summary showing the active agent, detected stacks, repo path, profile path, and the total count of allow and deny entries. This mirrors the "contract" pattern used by other sandbox tools, giving the user visibility into what the session permits before the agent starts.
