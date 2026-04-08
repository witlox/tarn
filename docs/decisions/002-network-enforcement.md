# ADR-002: Network Filtering via NEFilterDataProvider

Date: April 2026
Status: Accepted (supersedes the initial draft of this ADR, which was based on a wrong assumption about the Endpoint Security event surface)

## Context

Tarn supervises an AI coding agent's outbound network access against a per-user whitelist. The whitelist is hostname-shaped (`github.com`, `registry.npmjs.org`, etc.) because that is how a human reasons about what an agent is allowed to talk to. Endpoint Security gives tarn file events; the question is what gives tarn network events with enough context to enforce a hostname-shaped policy.

The first draft of this document committed a substantive technical error: it assumed `ES_EVENT_TYPE_AUTH_CONNECT` exists and proposed a forward-resolved IP cache as the way to bridge sockaddrs to hostnames. **That ES event does not exist.** Endpoint Security has no AUTH event for IP-level network connections. Network supervision on macOS lives entirely in the Network Extension framework. The IP cache scheme was solving a problem that Apple solves in a much cleaner way one framework over.

This document records the corrected decision. The first draft is preserved in the git history of this file as a cautionary tale.

## Options Considered

### 1. Reverse DNS at connect time

For each connect event, call `getnameinfo()` on the destination sockaddr to recover a hostname.

**Why this fails.** Reverse DNS does not invert forward DNS. Modern web properties sit behind CDNs (Cloudflare, Fastly, Akamai, AWS) whose PTR records point at the CDN provider, not at the customer's domain. A reverse-DNS check against `github.com` returns something like `lb-140-82-121-4-iad.github.com`, which is fine, or `prod-cf-…cloudfront.net` which is not. Further, `getnameinfo` is a blocking call that runs on the hot path while the kernel holds the syscall.

This option also requires a network AUTH event from Endpoint Security, which does not exist.

### 2. IP cache built by forward-resolving the whitelist at session start

At session start, call `getaddrinfo()` on every whitelisted domain and cache the resulting IPs in memory. Match `connect()` events against the cache. Refresh periodically to handle CDN rotation.

**Why this fails.** Same primary reason: requires a network event from Endpoint Security that does not exist. Even if it did exist, the scheme would degrade poorly under CDN IP rotation, would not handle wildcard domains, and would conflict with an agent that uses a non-system DNS resolver. It is what the first draft of this ADR proposed; it is wrong.

### 3. NEDNSProxyProvider — Network Extension DNS proxy

Ship tarn with a `NEDNSProxyProvider` that intercepts every DNS query on the machine, sees the question, returns the answer itself, and remembers the IP-to-name mapping per process.

**Why this fails for tarn specifically.** macOS allows exactly one active `NEDNSProxyProvider` system-wide. AdGuard, NextDNS, Cloudflare WARP, Pi-hole client, and every other DNS-level adblocker takes that slot. Installing tarn's DNS proxy would fight whatever the user already runs. The user runs AdGuard, which makes this option a non-starter.

(`agentsh`, the closest comparable project, does ship a DNS proxy alongside its content filter and openly documents the resulting incompatibility. They have no mitigation. Tarn refuses to inherit that bug.)

### 4. NEFilterDataProvider — Network Extension content filter

Ship tarn with a `NEFilterDataProvider` system extension that authorizes every TCP/UDP flow opened by a supervised process. macOS hands the extension a `NEFilterFlow` carrying the source process's audit token and (when available) the destination hostname. The extension returns one of `allowVerdict()`, `dropVerdict()`, or `pauseVerdict()`. Paused flows can be resumed asynchronously after an out-of-band user prompt.

This is the option Apple supports for exactly this use case.

## Decision

**Use `NEFilterDataProvider` inside a system extension. Do not use a DNS proxy. Do not reverse-resolve. Do not maintain an IP cache.**

The supervisor system extension hosts both the Endpoint Security client (for file and process events) and the `NEFilterDataProvider` (for network flows). They share the same supervised process tree and the same composed profile, because they share the same identity primitive: the BSM audit token.

## Why this works

### Per-process identification

`NEFilterFlow.sourceAppAuditToken` (macOS 10.15+, macOS-only) returns an `audit_token_t` that names the process which opened the socket. This is the same token tarn already uses on the file side from `es_message_t.process.audit_token`. The supervised PID set is populated from ES `NOTIFY_FORK`/`NOTIFY_EXIT` events and queried from the NE `handleNewFlow(_:)` callback — one tree, two consumers.

Per the strong recommendation from Apple's Network Extension engineers (Quinn "The Eskimo!" on the Apple Developer Forums, repeatedly), tarn keys decisions on the audit token, not on the bare PID. PID reuse is real; the audit token is the kernel-stable identity. The token is fed to `SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit:)` to obtain a `SecCode` reference for code-signing checks when needed.

### Hostname without DNS interception

`NEFilterSocketFlow.remoteHostname` carries the hostname when the connection was initiated via `URLSession`, `Network.framework`, or hostname-taking `getaddrinfo` paths — i.e., everything an AI coding agent does. macOS populates this for free.

When the hostname isn't populated (raw `connect(2)` on an IP, or some lower-level networking libraries), the filter returns a `filterDataVerdict` that peeks the first kilobyte of outbound data and parses the TLS ClientHello SNI to recover the hostname that way. For non-TLS plaintext or non-SNI protocols, the filter falls back to the destination IP and prompts the user with the IP.

In all three cases the filter sees something the user can reason about, without ever calling reverse DNS or maintaining an IP cache.

### AdGuard coexistence

This is the part the first draft of this ADR got backwards. Network Extension uniqueness is per *provider type*, not global:

- Tarn occupies the **content filter** slot (`NEFilterDataProvider`)
- AdGuard occupies the **DNS proxy** slot (`NEDNSProxyProvider`)
- These are different slots; they do not conflict

When both are installed, the data flow is:

1. Agent calls `getaddrinfo("example.com")`
2. AdGuard's DNS proxy resolves it (or returns NXDOMAIN if blocked)
3. If resolved, the agent calls `connect()`
4. The kernel routes the socket to tarn's content filter via `handleNewFlow(_:)`
5. Tarn checks the audit token and the hostname against its policy

AdGuard's blocklist runs first, at the DNS layer. Tarn's per-process policy runs second, at the connect layer. Each sees only its own concern. Nothing tarn does disturbs AdGuard, and vice versa.

The one configuration the user must avoid: AdGuard's "Network Extension mode" is a transparent proxy, which Apple's documentation explicitly warns conflicts with content filters at the kernel level. Users keep AdGuard in DNS-proxy mode (its default).

### Hot path

`handleNewFlow(_:)` is called once per new flow, not per packet. The hot path is a hash lookup on the supervised PID set, a hash lookup on the hostname against the allow/deny set, a hash lookup on the session cache, and either a synchronous verdict or a `pauseVerdict()` plus an XPC message. The session cache absorbs all repeat traffic; only genuinely novel flows reach the prompt UI.

There is no `getaddrinfo` on the hot path. There is no reverse DNS on the hot path. There is no DNS interception of any kind. The DNS work was done by the OS resolver before tarn even saw the flow.

### Asynchronous decisions

The `pauseVerdict()` + `resumeFlow(with:)` pattern is Apple's documented way to defer a verdict for an interactive decision. TCP flows can be paused indefinitely; UDP flows must be resolved within ~10 seconds (tarn auto-denies on UDP timeout to avoid the flow being silently dropped by the system). This is dramatically more forgiving than Endpoint Security's sub-second AUTH deadline, and it makes the interactive prompt model safe for network events in a way it isn't quite safe for file events.

Tarn uses the asynchronous resume pattern, not a synchronous semaphore wait. This is a deliberate departure from `agentsh`, which uses a 100 ms semaphore wait inside `handleNewFlow` and fails open on timeout — a known anti-pattern that starves the provider thread pool under load.

## What it doesn't handle

- **Other content filter NEs.** Tarn conflicts with Little Snitch 5+, LuLu, Radio Silence, and any commercial EDR using `NEFilterDataProvider`. macOS allows only one content filter active at a time. Users pick. This is documented prominently in the README.
- **Apple's content filter exclusion list.** A handful of Apple system daemons (`trustd`, `apsd`, `nsurlsessiond`, etc.) bypass content filters in some macOS versions. For an agent-supervision use case this is fine — the supervised processes are `node`, `python`, `cargo`, `claude`, etc., not Apple binaries. Documented as a known limitation.
- **Wildcard whitelisting (`*.github.com`).** Hostnames are matched literally. A user who wants every github.com subdomain lists them or accepts the prompt for each one. The hook for wildcards exists (we see the hostname directly), but the v1 schema is exact-match; wildcard syntax can be added later without architectural change.
- **Agents that ship their own DNS-over-HTTPS resolver bypassing the OS.** Such an agent gets IPs that AdGuard never saw. Tarn still sees the flow and still has the audit token, but `remoteHostname` will be nil and SNI may be the only signal. Acceptable degradation.

## Consequences

- The supervisor is a system extension, not a CLI binary. Tarn ships as a `.app` bundle. See ADR-004 for the project-structure consequences.
- Tarn requires a paid Apple Developer Program membership and the `content-filter-provider-systemextension` entitlement granted by Apple. The Endpoint Security entitlement was already a requirement; this adds one more.
- The `Sources/Tarn/NetworkResolver.swift` file from the first draft is deleted. The IP cache, the periodic refresh, and the atomic swap are deleted with it.
- The TOML schema's `[network.allow]` section keeps domain-only entries with literal exact-match semantics. No wildcards in v1. No IP escape hatch.
- The CLI's interactive prompt for an unknown network flow shows the hostname (or, when none is available, the SNI-derived hostname, or, when none of those work, the raw IP). The user picks `a` (allow once), `A` (allow and remember the hostname), or `d` (deny). For raw-IP prompts, `A` is hidden — there is nowhere to remember an IP in a hostname-shaped whitelist.
- The threat model now explicitly includes the assumption that the supervised agent uses the system resolver or at least uses TLS with SNI. An adversarial agent that bypasses both is out of scope per ADR-001.
