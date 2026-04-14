# Usage Guide

## Quick start

```bash
# First run — macOS will ask you to approve the system extension
tarn run ~/repos/my-project

# The agent starts, tarn supervises. Prompts appear inline:
#
# ┌─ tarn ─────────────────────────────────
# │ File read: /etc/npmrc
# │ Process: /usr/bin/node (PID 1234)
# ├────────────────────────────────────────
# │ [a] Allow once
# │ [A] Allow and remember
# │ [d] Deny
# └────────────────────────────────────────
#   Choice [a/A/d]:
```

Press `a` to allow for this session, `A` to allow and add to your whitelist permanently, or `d` (or just Enter) to deny.

## Commands

### tarn run

```bash
tarn run <repo-path> [options]
```

Launch a supervised agent session. The repo path is your working directory — everything inside it is automatically allowed for read and write access.

| Option | Default | Description |
|---|---|---|
| `--agent <name>` | `claude` | Which agent to launch. See [supported agents](#agents). |
| `--stack <stacks>` | auto-detect | Comma-separated stack names. Overrides auto-detection. |
| `--profile <path>` | `~/Library/Application Support/tarn/profile.toml` | Custom profile location. |

Examples:

```bash
# Auto-detect stacks from repo contents
tarn run ~/repos/my-project

# Use Claude Code explicitly
tarn run ~/repos/my-project --agent claude

# Use Codex
tarn run ~/repos/my-project --agent codex

# Force Node + Python stacks even if the repo also has Cargo.toml
tarn run ~/repos/my-project --stack node,python

# Use a project-specific profile (not the global one)
tarn run ~/repos/my-project --profile ~/repos/my-project/.tarn-profile.toml
```

On startup, tarn prints a session summary:

```
tarn session
  Agent:    claude (agent-claude)
  Stacks:   stack-node, stack-python
  Repo:     /Users/you/repos/my-project
  Profile:  /Users/you/Library/Application Support/tarn/profile.toml
  Entries:  42 allow, 11 deny

Launching: claude --dangerously-skip-permissions
```

### tarn profile show

```bash
tarn profile show [--profile <path>]
```

Display the current whitelist, grouped by section. Learned entries are tagged:

```
Read-only paths:
  ~/.gitconfig
  ~/.ssh/known_hosts
  ~/.npmrc (learned)

Read-write paths:
  (none)

Allowed network domains:
  api.anthropic.com
  github.com
  registry.npmjs.org
  api.openai.com (learned)
```

### tarn profile reset

```bash
tarn profile reset [--force] [--profile <path>]
```

Remove all learned entries from the whitelist. Default entries (shipped with tarn) and any entries you added by hand are preserved. Without `--force`, prompts for confirmation.

```
This will remove 7 learned entries. Continue? [y/N] y
Removed 7 learned entries.
```

## Agents

Tarn launches the agent in its most permissive mode (the agent's own sandbox is disabled; tarn replaces it):

| Agent | Flag | What it disables |
|---|---|---|
| Claude Code | `--dangerously-skip-permissions` | Claude's built-in permission checks |
| Codex | `--dangerously-bypass-approvals-and-sandbox` | Codex's sandbox and approval flow |
| Gemini CLI | `--yolo` | Gemini's confirmation prompts |
| opencode | *(none needed)* | opencode has no built-in sandbox |
| Custom | *(none)* | `tarn run --agent my-tool` launches `my-tool` directly |

For custom agents, the `--agent` value is the command name (must be in `$PATH`). Tarn does not add any flags for unknown agents.

## Stack profiles

Stacks are development toolchain profiles. Each stack allows the agent to read toolchain config files, write to cache directories, and connect to package registries.

### Auto-detection

When `--stack` is not provided, tarn inspects the repo directory for indicator files:

| File found | Stack activated |
|---|---|
| `package.json`, `bun.lockb`, `yarn.lock` | node |
| `Cargo.toml` | rust |
| `go.mod` | go |
| `pyproject.toml`, `requirements.txt`, `Pipfile` | python |
| `Package.swift`, `*.xcodeproj` | xcode |

Multiple stacks can be active simultaneously (e.g., a monorepo with both `package.json` and `pyproject.toml`).

### Aliases

The `--stack` flag accepts common aliases:

| Alias | Stack |
|---|---|
| `js`, `javascript`, `typescript` | node |
| `py` | python |
| `rs` | rust |
| `golang` | go |
| `swift`, `ios`, `macos` | xcode |

Unknown names are silently ignored: `--stack node,cobol,rust` activates node and rust.

## Prompt behavior

### Decision caching

Every decision is cached for the current session:

- **Allow once** → the same path/domain is allowed for the rest of the session without re-prompting
- **Deny** → the same path/domain is denied for the rest of the session without re-prompting
- **Allow and remember** → added to the persistent whitelist; survives across sessions

The session cache is cleared when tarn exits.

### Default-deny

If you don't answer (EOF, empty input, broken pipe, unknown character), the decision is **deny**. Tarn never defaults to allow.

### Network prompts

For network connections, the prompt shows the destination hostname when available:

```
┌─ tarn ─────────────────────────────────
│ Network connect: api.openai.com
│ Process: pid:5678
├────────────────────────────────────────
│ [a] Allow once
│ [A] Allow and remember
│ [d] Deny
└────────────────────────────────────────
```

When the hostname isn't available (raw TCP to an IP address), "Allow and remember" is hidden because the whitelist stores hostnames, not IPs:

```
┌─ tarn ─────────────────────────────────
│ Network connect: 203.0.113.42
│ Process: pid:5678
├────────────────────────────────────────
│ [a] Allow once
│ [d] Deny
│ note: raw IP cannot be remembered;
│       add the domain to your whitelist instead
└────────────────────────────────────────
```

### Timing

- **File prompts**: the ES framework has a response deadline. If you don't answer within 25 seconds, tarn auto-denies to avoid having macOS kill the ES client.
- **Network prompts (TCP)**: can be held indefinitely. Take your time.
- **Network prompts (UDP)**: auto-denied after 8 seconds (macOS drops paused UDP flows after ~10 seconds).

## Trusted regions

These access patterns are always allowed without prompting or whitelist lookup:

| Region | Read | Write | Rationale |
|---|---|---|---|
| Workspace (your repo) | yes | yes | The whole point is for the agent to work here |
| `/tmp`, `/var/tmp` | yes | yes | Build artifacts, temp files |
| `/usr`, `/bin`, `/sbin`, `/lib` | yes | **no** | System binaries (read-only) |
| `/System`, `/Library`, `/Applications` | yes | **no** | macOS system files (read-only) |
| `/dev` | yes | **no** | Device files |
| `/private/var/db` | yes | **no** | System databases |

Writes to system paths fall through to the normal decision pipeline (prompt or deny).

## Tips

### First session with a new stack

The first time you run tarn with a new toolchain, expect a burst of prompts as the agent's build tools access paths you haven't whitelisted yet. This is normal. Press `A` for paths you trust (e.g., `~/.config/pip/pip.conf`); they'll be remembered and the prompts stop.

### Reviewing what you've approved

```bash
tarn profile show | grep learned
```

### Starting fresh

```bash
tarn profile reset --force
```

This removes all learned entries but keeps the defaults. The next session will prompt again for everything.

### Using with a different profile per project

```bash
tarn run ~/repos/secret-project --profile ~/repos/secret-project/.tarn-profile.toml
```

This is useful if you want tighter rules for a sensitive repo. Each profile is independent.

### Running alongside AdGuard

No special configuration needed. AdGuard's DNS filtering and tarn's per-process content filtering operate in different Network Extension slots and don't interfere. If AdGuard blocks a domain at the DNS level, tarn never sees a connection to that domain — the agent's DNS lookup returns NXDOMAIN and no flow is created.

If you use AdGuard's "Network Extension mode" (transparent proxy), switch it to the default DNS-proxy mode to avoid a conflict with tarn's content filter.
