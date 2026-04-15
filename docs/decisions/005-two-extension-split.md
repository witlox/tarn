# ADR-005: Two-Extension Split (ES + NE)

Date: April 2026
Status: Accepted
Supersedes: Single-extension assumption in ADR-001 section 1

## Context

ADR-001 stated that both Endpoint Security and Network Extension would
run "inside a single macOS system extension." During implementation, we
discovered that macOS returns `ERR_NOT_PERMITTED` when `es_new_client`
is called from within a Network Extension provider process. The NE
sandbox profile blocks the ES entitlement check at the kernel level.
This is undocumented but consistent across macOS 14 and 15.

This means ES and NE cannot coexist in a single system extension process.

## Decision

Split the single system extension into two:

1. **TarnES** (`com.witlox.tarn.es`) -- Endpoint Security system extension.
   Hosts ESClient, ESXPCService, DecisionEngine, ProcessTree, SessionCache.
   Accepts XPC connections from both the CLI and the NE extension.

2. **TarnSupervisor** (`com.witlox.tarn.supervisor`) -- Network Extension
   system extension. Hosts NetworkFilter (NEFilterDataProvider) and
   ESBridgeClient. Acts as a thin proxy: intercepts flows, forwards to
   TarnES for evaluation, resumes with the verdict.

Both extensions are bundled in the same Tarn.app. The host app activates
them sequentially (ES first, then NE).

## Rationale

### Why not NE-only with a separate ES daemon?

The ES entitlement is only usable in a system extension or a root-running
process. A standalone daemon would work but would require a separate
LaunchDaemon plist, a separate code-signing identity, and would not
benefit from the system extension lifecycle (automatic activation,
user-visible in System Settings). Two system extensions is the
macOS-native shape.

### Why ES as the primary, NE as the proxy?

The ES extension has direct access to NOTIFY_FORK/EXIT events and can
maintain the ProcessTree authoritatively. Network flow evaluation needs
the ProcessTree and DecisionEngine. Rather than duplicating these in
the NE extension, the NE extension forwards flows to ES via XPC.

This also means all policy decisions (deny set, allow set, session cache,
user prompts) happen in one place. The NE extension only needs to know
which PIDs are supervised (pushed by ES) and how to forward flows.

### Why a single XPC listener for both CLI and NE?

Both the CLI and the NE extension connect to `kTarnESMachServiceName`.
The ESXPCService distinguishes them by effective UID: the NE extension
runs as root (UID 0), the CLI runs as the user. This avoids needing
two Mach service registrations for the ES extension.

## Consequences

### Positive

- Clean separation of concerns: ES extension owns policy, NE extension
  owns flow interception
- ProcessTree is authoritative (single writer: ES NOTIFY events)
- DecisionEngine is shared between file and network decisions
- NE extension is stateless (no policy state, no session cache) --
  simplifies reasoning about NE failure modes
- Fail-open NE design: every error path in ESBridgeClient returns allow

### Negative

- Two system extensions must be activated (sequential, user approves once)
- XPC latency between NE and ES for every novel flow (~ms, acceptable)
- PID synchronization between ES and NE: the NE extension maintains a
  local copy of supervised PIDs, pushed by ES. If the push is delayed,
  a flow from a newly-supervised PID might be allowed before the PID
  notification arrives. This is fail-open (safe direction).
- Two sets of entitlements, two Info.plists, more complex project.yml
- The NE extension connects to the ES extension's Mach service, which
  requires the ES extension to be running. If ES fails to start, NE
  allows all traffic (fail-open).

### Migration

- `Sources/TarnSupervisor/XPCService.swift` deleted (replaced by ESXPCService)
- `Sources/TarnSupervisor/ESClient.swift` moved to `Sources/TarnES/`
- `Sources/TarnSupervisor/NetworkFilter.swift` remains (NE-only now)
- New: `Sources/TarnES/ESXPCService.swift`
- New: `Sources/TarnSupervisor/ESBridgeClient.swift`
- `project.yml` updated with two system extension targets
- CLI XPC connects to `kTarnESMachServiceName` (was `kTarnSupervisorMachServiceName`)
