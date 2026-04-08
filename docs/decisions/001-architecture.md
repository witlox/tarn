# ADR-001: Tarn Architecture

Date: April 2026
Status: Accepted (revised — supersedes initial VM-based design)

## Context

AI coding agents require sandboxing to prevent accidental or prompt-injection-driven access to host resources. The initial design proposed Apple Container VMs with a seccomp-notify C guest daemon. During analysis, macOS's Endpoint Security framework was identified as providing equivalent kernel-level interception natively, eliminating the need for VMs, guest daemons, and cross-compilation.

## Decisions

### 1. Endpoint Security plus Network Extension over VM + seccomp-notify

**Decision:** Use Apple's Endpoint Security framework for file and process supervision, and the Network Extension content filter (`NEFilterDataProvider`) for network supervision. Both run inside a single macOS system extension hosted by the tarn `.app` bundle.

**Rationale:** ES provides pre-execution AUTH notifications for file operations — the same interception model as seccomp-notify, but native to macOS, with richer context (full paths, process executable, code signing info) and no Linux VM kernel. The Network Extension content filter provides the equivalent for outbound network flows, with the same identity primitive (the BSM audit token) so the supervised process tree maintained from ES NOTIFY events is the same set of identities the NE filter checks. Together they cover everything tarn needs without a guest OS, vsock, or seccomp.

**Important correction.** An earlier version of this ADR claimed "ES provides pre-execution AUTH notifications for file operations and network connections," and ADR-002 was built on the assumption that `ES_EVENT_TYPE_AUTH_CONNECT` exists. It does not. Endpoint Security has no AUTH event for IP-level network connections. Network supervision lives entirely in the Network Extension framework. ADR-002 has been rewritten to reflect the correct architecture; this is the analogous correction here.

**Trade-off:** Both frameworks operate within the shared macOS kernel. A kernel exploit could bypass them. For tarn's threat model (preventing accidental and prompt-injection-driven access, not hostile kernel exploits), this is acceptable. Users needing hostile-code isolation should use a VM. The combined entitlement requirement is a real cost: tarn needs both `com.apple.developer.endpoint-security.client` and `com.apple.developer.networking.networkextension` (with `content-filter-provider-systemextension`), both Apple-restricted and granted by request to a Developer ID Application certificate.

### 2. Endpoint Security over Seatbelt (sandbox-exec)

**Decision:** Use ES instead of sandbox-exec.

**Rationale:** sandbox-exec is deprecated by Apple. Its SBPL policy language is undocumented. ES is actively maintained, supported, and provides the interactive notification model (AUTH events with allow/deny response) that Seatbelt does not — Seatbelt is declarative (policy defined upfront), ES is interactive (decisions made per-event at runtime).

**Trade-off:** ES requires the com.apple.developer.endpoint-security.client entitlement and root privileges. Seatbelt can be used by unprivileged processes. For a security tool, running as root is expected.

### 3. Single Swift codebase, two binaries inside one .app bundle

**Decision:** Implement everything in Swift. The deliverable is a `.app` bundle containing two Swift binaries: an unprivileged CLI (`Contents/MacOS/tarn`) and a system extension supervisor (`Contents/Library/SystemExtensions/com.witlox.tarn.supervisor.systemextension`). They share a Swift library for the policy logic and communicate via XPC. No guest daemon, no C code, no vsock protocol, no cross-compilation.

**Rationale:** A Network Extension content filter must run in a system extension; that is the only Apple-supported deployment shape. The CLI cannot be a system extension itself (system extensions are activated by `OSSystemExtensionRequest` from inside an `.app` bundle, and they run as launchd-managed daemons, not as user-invoked binaries). Splitting the deliverable into a CLI and a supervisor — both Swift, both signed by the same Developer ID, both linking the same shared policy library — is the macOS-native shape and matches what every other production-grade content filter does (LuLu, Little Snitch, Apple's `SimpleFirewall` sample).

The earlier version of this ADR proposed "single Swift binary." That framing was downstream of the wrong assumption that ES could supervise network connections; if ES did everything, a single root-running CLI would have been sufficient. With network supervision living in Network Extension, the system extension shape becomes mandatory, not optional. The spirit of the original decision (single language, no cross-compile, no two-language split) is preserved; the literal binary count is not.

**Trade-off:** Two binaries instead of one. An XPC interface between them. An Xcode project (SPM cannot build `.systemextension` bundles). A first-run system extension activation flow that prompts the user to approve in System Settings. These are real costs but they are macOS-standard costs, paid by every production tool in this category.

### 4. Process tree scoping

**Decision:** Track the agent's process subtree and only supervise those PIDs.

**Rationale:** ES events fire for all processes system-wide. Without scoping, Tarn would intercept every file open on the machine, causing massive performance impact and prompt noise. By tracking the agent PID and its descendants, only the agent's operations are supervised.

**Trade-off:** A process that escapes the tree (e.g., by forking and reparenting to PID 1) would evade supervision. This is a known limitation of process-tree-based scoping and is acceptable for Tarn's threat model.

### 5. Global whitelist over per-project profiles

**Decision:** Single global whitelist for the user (path determined by ADR-003).

**Rationale:** Unchanged from initial design. The threat model is host-resource protection, which doesn't vary per project. A per-project whitelist would allow escalation across project boundaries.

### 6. Standalone project over contributing to agentsh

**Decision:** Build Tarn as a new project rather than contributing to agentsh.

**Rationale:** agentsh uses Go, has enterprise-oriented architecture (shell shimming, session management, MCP protection), its macOS ES support is Alpha, and it uses static policies. The interactive prompt-and-learn model is architecturally different enough that it would be a rewrite within agentsh rather than a contribution.

## Consequences

- Tarn is a Swift `.app` bundle containing a CLI and a system extension, macOS-only (Apple Silicon and Intel)
- Requires a paid Apple Developer Program membership and two Apple-restricted entitlements (ES + Network Extension content filter), granted by request to a Developer ID Application certificate
- The user invokes the CLI without `sudo`; the supervisor runs as a launchd-managed daemon after first-run activation
- First run prompts the user to approve the system extension in System Settings → General → Login Items & Extensions
- Agent-agnostic — supervises any terminal process the user launches under tarn
- The whitelist is human-readable TOML, version-controllable, and auditable
- ES AUTH events have a sub-second system-imposed response deadline — file-side decisions must be fast and rely on aggressive session caching
- Network flows have a much more forgiving deadline (TCP indefinite, UDP ~10s) — interactive prompts on the network side are timing-safe
- Tarn conflicts with other content filters (Little Snitch 5+, LuLu, Radio Silence). It coexists with DNS-level filters (AdGuard, NextDNS, Pi-hole) because they occupy a different Network Extension provider slot
