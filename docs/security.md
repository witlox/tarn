# Security Model

## Threat model

Tarn protects against **accidental and prompt-injection-driven access** by AI coding agents to host resources they shouldn't touch. The agent is assumed to be well-intentioned but potentially manipulated — a tool that follows instructions, including malicious instructions injected via supply chain attacks, compromised dependencies, or adversarial prompts.

### What tarn protects against

- An agent reading your SSH private keys, AWS credentials, GPG keyring, or macOS Keychain — the compiled-in deny list blocks these regardless of any whitelist entry
- An agent writing to files outside its workspace without your knowledge
- An agent connecting to unexpected network destinations (data exfiltration, C2 callbacks)
- A compromised npm/pip/cargo package that tries to phone home during installation — the agent's entire subprocess tree is supervised, including build tools

### What tarn does NOT protect against

- **Hostile code that deliberately attacks the supervisor.** A sufficiently motivated agent (or malware running as the agent) could try to escape the process tree by double-forking and reparenting to launchd. This is a known limitation of PID-based process tree tracking. For hostile-code isolation, use a VM.
- **Kernel exploits or SIP bypass.** Tarn relies on macOS kernel frameworks (Endpoint Security, Network Extension). A kernel exploit could bypass them. This is out of scope.
- **Apple system daemons.** Some Apple processes bypass content filters in certain macOS versions (the `ContentFilterExclusionList`). This doesn't affect agent supervision — the excluded processes are Apple system daemons, not agent binaries.

## Trust boundaries

```
┌─────────────────────────────────────────────────────┐
│ XNU Kernel (trusted — tarn's security depends on it) │
│                                                     │
│  Endpoint Security   Network Extension              │
│  AUTH events         flow verdicts                   │
└──────────┬──────────────────┬────────────────────────┘
           │                  │
           ▼                  ▼
┌──────────────────────────────────────────────────────┐
│ Tarn Supervisor (root, system extension)              │
│ Trusts: kernel events, own code, XPC from same team  │
│ Does not trust: the agent, its children, profile     │
│                 content, any user-supplied paths      │
└──────────┬───────────────────────────────────────────┘
           │ XPC (team-ID validated)
           ▼
┌──────────────────────────────────────────────────────┐
│ Tarn CLI (user, unprivileged)                         │
│ Trusts: the supervisor, the user's keyboard input     │
│ Does not trust: the agent process                     │
└──────────┬───────────────────────────────────────────┘
           │ Process.run()
           ▼
┌──────────────────────────────────────────────────────┐
│ Agent + subprocess tree (untrusted from tarn's view)  │
│ Every file open and network connect is intercepted    │
└──────────────────────────────────────────────────────┘
```

## Key security properties

### Deny set is inviolable

The compiled-in deny list (credential paths) is checked before everything else — before the session cache, before trusted regions, before the allow set. A denied path is denied regardless of any whitelist entry, learned entry, or manual profile edit. The deny set is the security floor; it cannot be undermined by user mistakes or prompt injection tricking the user into approving access.

The deny set includes: `~/.aws`, `~/.ssh/id_*` (excluding `*.pub`), `~/.ssh/config`, `~/.gnupg`, `~/.config/gh`, `~/.config/gcloud`, `~/.azure`, `~/.kube/config`, `~/.docker/config.json`, `~/.npmrc`, `~/.pypirc`, `~/.netrc`, `~/Library/Keychains`, `~/Library/Cookies`, and `~/Library/Safari`. Public keys (`~/.ssh/id_*.pub`) are explicitly excluded from the deny set since they are not secrets.

### Deny by default

Every ambiguous input maps to deny. EOF on the prompt, empty input, unknown characters, broken pipe — all deny. The session cache holds both allows AND denies, so "deny once" is a session-scoped decision, not a one-shot that re-prompts on every retry. Fail-closed defaults apply throughout the system: a missing audit token causes the event to be dropped, and a connection with no extractable hostname is dropped.

### Identity is the audit token, not the PID

Both the ES supervisor and the NE filter identify processes by the BSM audit token, not the bare PID. PID reuse is real on busy systems; the audit token is the kernel-stable identity. Code-signing checks use `SecCodeCopyGuestWithAttributes` with the audit token, not PID-based lookup.

### Profile persistence flows through the unprivileged CLI

The supervisor (root) never writes to the user's home directory. When the user picks "Allow and remember", the supervisor sends the new entry to the CLI via XPC; the CLI writes to disk as the user. File ownership is always correct without chown hacks.

### Case-insensitive path and domain matching

All path and domain comparisons are case-insensitive. This prevents bypass via case variation on APFS, which is case-insensitive by default. An agent cannot read `~/.AWS/Credentials` to circumvent the deny set for `~/.aws/credentials`.

### ES deadline enforcement

Endpoint Security AUTH events must be answered within the kernel-imposed deadline. If a decision is not reached within 25 seconds, the supervisor auto-denies the event to prevent macOS from killing the ES client. This bounds the worst case for unattended prompts.

### Agent environment scrubbing

Before launching the agent subprocess, tarn scrubs the environment of known secret-bearing variables (API keys, tokens, credentials). The agent inherits a clean environment with only the variables needed for normal operation.

### XPC input validation

The supervisor validates all XPC inputs. The `repoPath` and `userHome` parameters are checked for path traversal and normalized before use.

### XPC connections are team-ID validated

The supervisor rejects XPC connections from processes not signed by the same Apple Developer Team ID. On SIP-disabled development machines where signing info is unavailable, all connections are accepted (graceful degradation for development; not shipped to end users).

## Assumptions

These are things tarn relies on that could invalidate its security properties if they turn out to be false:

1. **ES events are delivered in causal order.** A NOTIFY_FORK for a child process arrives before any AUTH event from that child. If false, newly-forked children have a brief window where their file access is allowed without checking. (Open verification item — needs testing against Apple's ES delivery semantics.)

2. **ES reports resolved real paths.** AUTH_OPEN events carry the kernel's resolved path with symlinks followed. If false, an agent could read `~/.aws/credentials` by opening a symlink at a non-denied path. (Open verification item — needs verification against Apple docs.)

3. **The agent uses the system resolver.** Both tarn and the agent see the same DNS view via mDNSResponder. If an agent ships its own DNS-over-HTTPS resolver, `flow.remoteHostname` may be nil — tarn falls back to TLS SNI or the raw IP. This is documented as a known limitation, not a security failure.

4. **The agent uses TLS with SNI for most connections.** If an agent uses plaintext HTTP or Encrypted Client Hello (ECH), hostname extraction fails and the user sees a raw-IP prompt. ECH is not yet widely deployed; if it becomes common, the TLS SNI fallback will need re-evaluation.

5. **The user is at the keyboard.** If the user walks away during a session, the first unknown file access blocks the agent until the ES deadline kills the ES client. Network prompts for TCP can wait indefinitely; UDP prompts auto-deny after 8 seconds.

## Limitations

- **One content filter at a time.** macOS allows only one active `NEFilterDataProvider`. Tarn conflicts with Little Snitch 5+, LuLu, Radio Silence, and similar tools. Users pick one.
- **No DNS filtering.** Tarn deliberately does not intercept DNS queries. DNS-level filtering is handled by AdGuard, Pi-hole, or similar tools, which coexist with tarn without conflict.
- **No wildcard domains in v1.** The whitelist accepts fully qualified domain names only (`github.com`, not `*.github.com`). The architecture supports wildcards (the hostname is available directly), but the v1 schema is exact-match for simplicity.
- **Apple app exclusion list.** Some Apple system daemons bypass content filters in certain macOS versions. This doesn't affect agent supervision.
