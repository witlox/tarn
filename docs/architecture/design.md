# Tarn Architecture

## Overview

Tarn is a single Swift binary that uses Apple's Endpoint Security framework to supervise AI coding agents at the kernel level. It intercepts file and network operations before they execute, checks them against a persistent whitelist, and prompts the user for unknown access patterns.

## Component Architecture

```
┌─────────────────────────────────────────────────────────┐
│ macOS                                                   │
│                                                         │
│  Tarn.app (Developer ID signed, notarized)              │
│  ├─ Contents/MacOS/tarn          unprivileged CLI       │
│  └─ Contents/Library/SystemExtensions/                  │
│         com.witlox.tarn.supervisor.systemextension      │
│                                                         │
│  ┌───────────── tarn CLI (user) ─────────────┐          │
│  │ argument parsing, agent launch, prompt UI │          │
│  │   │                                       │          │
│  │   └─ XPC client ─────────────────┐        │          │
│  └──────────────────────────────────┼────────┘          │
│                                     │                   │
│                                     ▼                   │
│  ┌───────── tarn supervisor (root, daemon) ─────────┐   │
│  │                                                  │   │
│  │  XPC service ◄── session: pid, profile, prompts  │   │
│  │     │                                            │   │
│  │     ├─ ProcessTree (supervised PID set)          │   │
│  │     ├─ Profile (composed allow/deny rules)       │   │
│  │     ├─ SessionCache (per-session decisions)      │   │
│  │     │                                            │   │
│  │  ┌──┴────────────┐  ┌────────────────────────┐   │   │
│  │  │ ES client     │  │ NEFilterDataProvider   │   │   │
│  │  │ AUTH_OPEN     │  │ handleNewFlow          │   │   │
│  │  │ NOTIFY_FORK   │  │ pauseVerdict / allow / │   │   │
│  │  │ NOTIFY_EXIT   │  │ drop                   │   │   │
│  │  └───────────────┘  └────────────────────────┘   │   │
│  │                                                  │   │
│  └──────────────────────────────────────────────────┘   │
│                                                         │
│  Agent process (claude, codex, etc.)                    │
│    └── subprocess tree (supervised by audit token)      │
│                                                         │
│  ~/Library/Application Support/tarn/profile.toml        │
└─────────────────────────────────────────────────────────┘
```

## Two Supervisors, One Extension

Tarn uses two complementary Apple frameworks for kernel-level supervision, both hosted inside a single system extension:

- **Endpoint Security** (`ES_EVENT_TYPE_AUTH_OPEN`, plus `NOTIFY_FORK` and `NOTIFY_EXIT` for the supervised process tree) handles file and process events.
- **Network Extension** (`NEFilterDataProvider`) handles outbound network flows.

Endpoint Security has no AUTH event for IP-level network connections; that surface lives exclusively in the Network Extension framework. The two frameworks share the same identity primitive (the BSM audit token), so the supervised process tree maintained from ES NOTIFY events is the same set of identities the NE filter checks.

### File event flow (Endpoint Security)

```
AUTH_OPEN received
  │
  ├─ PID not in supervised tree? → ALLOW (not our process)
  │
  ├─ Path in workspace or /tmp? → ALLOW (trusted region)
  ├─ Path in system dirs (/usr, /lib, etc.)? → ALLOW (trusted region)
  ├─ Path matches a deny rule? → DENY (deny set wins over allow set)
  ├─ Path matches an allow rule? → ALLOW
  ├─ Path in session cache? → ALLOW or DENY
  └─ Unknown → prompt user → ALLOW or DENY (and cache decision)
```

Tarn must respond with `ES_AUTH_RESULT_ALLOW` or `ES_AUTH_RESULT_DENY` before the system deadline. Trusted regions and the session cache absorb the high-volume cases so the prompt path only fires for genuinely novel access.

### Network flow (Network Extension)

```
handleNewFlow(flow) called
  │
  ├─ flow.sourceAppAuditToken → audit_token_to_pid → PID
  │
  ├─ PID not in supervised tree? → allowVerdict() (not our process)
  │
  ├─ flow.remoteHostname (set by URLSession / Network.framework /
  │   getaddrinfo path) populated?
  │     yes → use it directly
  │     no  → return filterDataVerdict to peek the first KB and
  │           parse the TLS ClientHello SNI; or fall through to
  │           the resolved destination IP
  │
  ├─ Hostname matches the deny set? → dropVerdict()
  ├─ Hostname matches the allow set? → allowVerdict()
  ├─ Hostname in session cache? → cached verdict
  └─ Unknown → pauseVerdict(); send XPC prompt request to the CLI;
              on response, resumeFlow(with: allow|drop)
```

`pauseVerdict` is the key primitive: it lets tarn hold the flow indefinitely (TCP) or up to ~10 seconds (UDP) while the user decides. Unlike Endpoint Security's sub-second AUTH deadline, the NE filter is comfortable with interactive timing.

## Process Tree Tracking

ES events fire for all processes system-wide. Tarn only supervises the agent's subprocess tree:

1. When `tarn run` launches the agent, its PID is registered as the root of the supervised tree.
2. Tarn subscribes to `NOTIFY_FORK` to track children and grandchildren as they are spawned, and to `NOTIFY_EXIT` to remove PIDs as they die. `NOTIFY_EXEC` is observed but does not change tree membership — a process that execs into a different binary keeps the same PID and stays supervised.
3. Removing the agent root from the tree (because it exited) does not cascade to its descendants. They remain supervised until they exit individually.
4. Only events from supervised PIDs go through the decision engine. All others are allowed immediately.

This ensures zero impact on the rest of the system. A process that escapes the tree by double-forking and reparenting to launchd is a known limitation; it is not in the threat model.

## Network Filtering and the AdGuard Story

The Network Extension framework distinguishes between several provider types — content filters (`NEFilterDataProvider`), DNS proxies (`NEDNSProxyProvider`), transparent proxies, app proxies, packet tunnels. macOS allows at most one *active* extension per type, but extensions of *different* types coexist. This is the key fact for tarn:

- Tarn uses the **content filter** slot via `NEFilterDataProvider`.
- AdGuard for Mac uses the **DNS proxy** slot via `NEDNSProxyProvider`.
- These are different slots. They do not fight.

In practice the flow looks like this when both are installed:

1. The supervised agent calls `getaddrinfo("example.com")`. The query is routed through AdGuard's DNS proxy. AdGuard may rewrite it to NXDOMAIN if blocked, in which case the agent never gets an IP and tarn never sees a flow.
2. If AdGuard returns an address, the agent calls `connect()`. The kernel intercepts the new socket and hands it to tarn's `NEFilterDataProvider.handleNewFlow(_:)`.
3. Tarn checks the flow's `sourceAppAuditToken` against the supervised process tree. Out-of-tree flows return `allowVerdict()` immediately.
4. For supervised flows, tarn matches the destination hostname (from `remoteHostname` or, when absent, from a TLS ClientHello SNI peek) against the user's allow/deny set. Known-good flows get `allowVerdict()`, known-bad get `dropVerdict()`, and novel flows get `pauseVerdict()` plus an XPC prompt request to the CLI for an interactive decision.

So AdGuard does what AdGuard does best (DNS-level blocking, host-wide), and tarn does what tarn does best (per-process, per-flow, interactive prompt-and-learn for the supervised agent only). They compose cleanly.

The one configuration to avoid: AdGuard's "Network Extension mode" is a transparent proxy, which *does* conflict with content filters at the kernel level. Users who want both tarn and AdGuard should keep AdGuard in its default DNS-proxy mode.

Tarn does conflict, by design, with other content-filter-based firewalls — Little Snitch 5+, LuLu, Radio Silence, and any commercial EDR using `NEFilterDataProvider`. macOS allows only one active content filter at a time. Users pick one.

## Whitelist Profile

Stored at `~/Library/Application Support/tarn/profile.toml`, the standard macOS location for per-user application data. The file is created on first run with a default set of entries; users can edit it freely. Three sections: read-only paths, read-write paths, and allowed network domains.

```toml
[paths.readonly]
paths = [
  "~/.gitconfig",
  "~/.ssh/known_hosts",
  "~/.npmrc",            # learned
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

Decision logic for file access:
- Read-only path + read flags → allow
- Read-only path + write flags → deny (explicit protection)
- Read-write path + any flags → allow
- Unknown path → prompt

## Fast Paths

To minimize prompt noise and meet ES response deadlines, several fast paths bypass the whitelist check entirely:

- **Workspace**: anything under the repo path passed to `tarn run` is always allowed (read + write)
- **Temp**: `/tmp` and `/var/tmp` are always allowed
- **System**: `/usr`, `/lib`, `/bin`, `/sbin`, `/System`, `/Library`, `/Applications`, `/dev` are always allowed for reads
- **Local sockets**: AF_UNIX connections are always allowed

These are hardcoded, not configurable — they represent access that any process needs to function.

## Session Cache

Within a single tarn session, every prompt response is cached in memory. The cache is keyed by path (for file events) or by hostname (for network events) and stores both allows and denies — "deny once" is a session-scoped decision, not a one-shot that re-prompts on every retry. The cache is cleared when tarn exits; only "Allow and remember" responses are persisted to the whitelist on disk.

This is what keeps prompt noise tolerable. Most repeat traffic from a long-running agent never reaches the prompt UI a second time.

## Persisting "Allow and Remember"

When the user picks "Allow and remember", Tarn writes the new entry to the whitelist file *before* responding to the kernel with ALLOW. This means a successful response is also a successfully-persisted response — there is no window where the user thinks an entry was remembered but a crash dropped it. The on-disk write is a temp-file-plus-rename in the same directory as the target, so it is atomic and cannot leave the file in a half-written state.

If the disk write fails (disk full, permission, read-only mount), Tarn still allows the access for the current request, falls back to the session cache, and prints a warning telling the user the entry will not survive the session. This honors the user's intent to allow without surprising them with a denial they did not ask for, and without silently claiming a persist that did not happen.

## Deadlines and Interactive Prompts

The two supervision frameworks have very different timing characteristics, and tarn's design exploits the difference.

**Endpoint Security** imposes a sub-second deadline on AUTH responses. If tarn doesn't respond in time, the system kills the ES client. The interactive prompt path is dangerous on its own at this timescale, so the file-event side relies heavily on:

- The session cache, which absorbs all repeat traffic — same path gets the same answer without re-prompting
- Trusted regions, which handle the high-volume system access (workspace, /tmp, /usr, etc.) without ever consulting the whitelist
- A bounded prompt queue: if the oldest pending file-event prompt approaches its ES deadline, it is denied (and the deny is added to the session cache to prevent an immediate retry storm) rather than risk the ES client being killed

**Network Extension** is much more forgiving. `pauseVerdict()` holds a TCP flow indefinitely, and a UDP flow up to ~10 seconds. The user can take their time on a network prompt. The same session cache and prompt-serialization logic apply, but the deadline-driven fallback is essentially never needed for TCP — the user always has time to answer.

## Packaging and Entitlements

Both Endpoint Security and the Network Extension content filter require Apple-restricted entitlements and signed system extensions. Tarn ships as a small `.app` bundle containing:

- `Contents/MacOS/tarn` — the unprivileged CLI binary
- `Contents/Library/SystemExtensions/com.witlox.tarn.supervisor.systemextension` — the supervisor system extension

The CLI is symlinked to `/usr/local/bin/tarn` so users can invoke it as a normal command. First run activates the system extension via `OSSystemExtensionRequest`, prompting the user to approve in System Settings → General → Login Items & Extensions. Once active, the supervisor runs as a system daemon and the CLI talks to it via XPC. There is no `sudo`.

Required entitlements on the supervisor:

- `com.apple.developer.endpoint-security.client`
- `com.apple.developer.networking.networkextension` with the `content-filter-provider-systemextension` value

Required entitlements on the host app:

- `com.apple.developer.system-extension.install`

Both ES and the NE content filter entitlement are Apple-restricted and granted by request to a Developer ID Application certificate (paid Apple Developer Program). The build is notarized via `notarytool` before distribution.

For development without notarization, SIP can be disabled on a test machine. This is the development path; not recommended for end users.

## Security Boundaries

**Hard boundary:** The XNU kernel's MACF framework, which Endpoint Security is built on. ES events are generated by the kernel and cannot be bypassed from userspace (short of a kernel exploit or SIP disable).

**Soft boundary:** Process tree tracking. A process that escapes the tree (reparenting to init) evades supervision. This is a known limitation.

**Out of scope:** Kernel exploits, SIP bypass, hardware attacks. Tarn is a usability tool for controlled access, not a hostile-code sandbox.
