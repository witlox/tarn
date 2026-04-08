# Specification: Network Extension Content Filter

The Network Extension content filter is the network side of the tarn
supervisor system extension. It is a `NEFilterDataProvider` subclass
that authorizes outbound TCP/UDP flows opened by supervised
processes, applies the same allow/deny/session-cache logic as the
file-event side, and uses an asynchronous `pauseVerdict` plus XPC
prompt request for interactive decisions on novel flows.

It runs in the same system extension process as the Endpoint Security
supervisor (`es-monitor.md`) and shares the supervised process tree,
the session cache, and the composed profile.

## Provider type

The filter is a `NEFilterDataProvider`, not an `NEDNSProxyProvider`,
not a `NEPacketTunnelProvider`, not a `NETransparentProxyProvider`,
not an `NEAppProxyProvider`, not an `NEFilterPacketProvider`. The
choice and the rejected alternatives are documented in ADR-002.

The reason this matters at runtime: macOS allows one active network
extension per provider type. Tarn occupies the content filter slot.
AdGuard, NextDNS, Cloudflare WARP, Pi-hole client, and other DNS-level
filters occupy the DNS proxy slot. They are different slots and do
not conflict. Tarn does conflict with other content filters
(Little Snitch 5+, LuLu, Radio Silence, commercial EDRs that use
`NEFilterDataProvider`); the user picks one.

## Lifecycle

The filter is registered in the system extension's `Info.plist` under
`NSExtension`. It is instantiated by the framework when the user
enables the filter in System Settings → Network → Filters, and torn
down when the filter is disabled or the system extension is
uninstalled.

`startFilter(completionHandler:)` is called when the filter activates.
The provider does not need to do much here; the supervised process
tree and session cache are populated lazily as flows arrive.

`stopFilter(with:completionHandler:)` is called when the filter
deactivates. Pending paused flows are resumed with `dropVerdict()` so
they do not hang the agent.

## handleNewFlow

`handleNewFlow(_:)` is the hot path. It is called once per new
TCP or UDP flow opened by any process on the machine. The provider
returns a verdict.

```
handleNewFlow(flow):
  │
  ├─ Cast flow to NEFilterSocketFlow (we only handle socket flows;
  │   NEFilterBrowserFlow is iOS-only and never fires on macOS)
  │
  ├─ Extract sourceAppAuditToken from the flow
  │   Convert to pid_t via audit_token_to_pid for ProcessTree lookup
  │
  ├─ Is PID in the supervised process tree?
  │     no  → return allowVerdict()
  │     yes → continue
  │
  ├─ Determine the destination hostname:
  │     1. If flow.remoteHostname is non-nil, use it
  │     2. Otherwise, return filterDataVerdict(filterInbound: false,
  │        peekInboundBytes: 0, filterOutbound: true,
  │        peekOutboundBytes: 1024); the next callback parses the TLS
  │        ClientHello SNI from the peeked bytes
  │     3. Otherwise (non-TLS plaintext, non-SNI protocol), use the
  │        resolved destination IP as the identifier
  │
  ├─ Check the deny set for this hostname → dropVerdict() if matched
  ├─ Check the allow set for this hostname → allowVerdict() if matched
  ├─ Check the session cache (key: "host:<hostname>") → cached verdict
  │
  └─ Unknown:
        return pauseVerdict()
        send PromptRequest over XPC to the CLI
        when CLI replies, call resumeFlow(flow, with: allow|drop)
```

## Hostname extraction

`NEFilterSocketFlow.remoteHostname` is populated when the agent
initiated the connection through `URLSession`, `Network.framework`,
or hostname-taking `getaddrinfo` paths. This covers nearly everything
an AI coding agent does: `git clone https://github.com/...`, `npm
install`, `pip install`, `claude` API calls, `gh` commands, etc.

When `remoteHostname` is nil, the filter peeks the first kilobyte of
outbound data via `filterDataVerdict` and parses the TLS ClientHello.
The SNI extension carries the hostname the client is trying to reach.
This is a small, well-defined parser; tarn does not attempt to be a
TLS implementation, only to extract the SNI string.

When neither path produces a hostname (non-TLS plaintext HTTP, raw
TCP, certain QUIC variants), the filter uses the destination IP as
the identifier. The interactive prompt then displays the IP, and the
user can decide based on context. "Allow and remember" is hidden for
raw-IP prompts because the whitelist file does not store IPs.

## Verdicts

The filter returns one of:

- `allowVerdict()` — let the flow through, no further callbacks
- `dropVerdict()` — drop silently (TCP reset, UDP discard)
- `pauseVerdict()` — hold the flow, no further callbacks until
  `resumeFlow(_:with:)` is called from outside the handler
- `filterDataVerdict(...)` — request a peek of N inbound or outbound
  bytes; the next callback inspects them

The filter does not use `needRulesVerdict` (which would defer to a
paired control provider) or `URLAppendStringVerdict` /
`remediateVerdict` (which are web-content features).

## Asynchronous decisions and deadlines

`pauseVerdict()` is the key primitive for interactive decisions. The
provider returns immediately with `pauseVerdict()`, the supervisor
sends a prompt request to the CLI via XPC, and when the CLI replies
the supervisor calls `resumeFlow(flow, with: allowVerdict())` or
`resumeFlow(flow, with: dropVerdict())`.

Deadline behavior:

- **TCP flows can be paused indefinitely.** There is no system
  deadline. The user can take their time on the prompt.
- **UDP flows are auto-dropped if not resumed within ~10 seconds.**
  This includes QUIC, DNS-over-QUIC, WireGuard control packets, and
  other connectionless protocols. Tarn must produce a verdict on a
  UDP flow within the budget. If the prompt has been outstanding for
  more than 8 seconds (a safety margin), tarn auto-denies and adds
  the deny to the session cache.

This is dramatically more forgiving than Endpoint Security's
sub-second AUTH deadline. The interactive prompt model that is
risky on the file side (where session-cache misses must be answered
in milliseconds) is timing-safe on the network side for TCP.

The provider does NOT use a synchronous `DispatchSemaphore.wait()`
inside `handleNewFlow`. That pattern is documented as an anti-pattern
on the Apple Developer Forums and observed to starve the provider
thread pool under load (this is one of the known bugs in `agentsh`,
which tarn explicitly does not inherit). Tarn uses asynchronous
`pauseVerdict` + `resumeFlow` exclusively.

## Identity

The supervisor uses the BSM audit token from
`NEFilterFlow.sourceAppAuditToken` as the canonical identity for the
process that opened the flow. This is the same token the ES side
sees on file events. The supervised process tree, populated from ES
NOTIFY_FORK events, is queried with the token-derived PID.

For deeper identity (code-signing identifier, team ID, bundle
identifier), the audit token is fed to
`SecCodeCopyGuestWithAttributes(NULL, [kSecGuestAttributeAudit:
tokenData], ...)`. This is the kernel-verified, race-free path; PID
reuse cannot trick it.

## Coexistence

The filter is designed to coexist with DNS-level filters. AdGuard's
NXDOMAIN responses for blocked domains happen at the DNS layer,
before the agent ever calls `connect()`. The filter never sees a
flow for a blocked domain, because no flow is created. This is the
intended layering and tarn's design exploits it.

The filter is incompatible with other content filters
(`NEFilterDataProvider`-based tools) because macOS allows only one
active content filter at a time. The README documents this clearly.

## What This Component Does Not Do

- DNS interception or DNS-level blocking — that is AdGuard's job
- File or process supervision — handled by the ES side
  (`es-monitor.md`)
- Profile composition — handled by TarnCore
- The interactive prompt UI — handled by the CLI, reached via XPC

## Apple Content Filter Exclusion List

Some Apple system daemons (`trustd`, `apsd`, `nsurlsessiond`,
`mDNSResponder`, etc.) bypass content filters in some macOS versions
via the `ContentFilterExclusionList`. Tarn will not see flows from
these processes. For an agent supervision use case this is fine —
the supervised processes are `node`, `python`, `cargo`, `claude`,
etc., not Apple binaries. The README documents this as a known
limitation.
