# Compatibility

## macOS versions

Tarn requires macOS 14 (Sonoma) or later. The system extension model (`NEFilterDataProvider` + Endpoint Security in a system extension) is stable from macOS 10.15 onwards, but tarn's deployment target is 14.0 for access to the latest APIs (including `NEFilterSocketFlow.remoteHostname` improvements).

## Network filtering coexistence

macOS allows one active Network Extension per *provider type*. Different types coexist; same types conflict.

### Compatible

| Tool | Provider type | Notes |
|---|---|---|
| **AdGuard for Mac** | `NEDNSProxyProvider` | Different slot. AdGuard handles DNS-level blocking; tarn handles per-process flow filtering. They compose cleanly: AdGuard's NXDOMAIN responses prevent the agent from even getting an IP, so tarn never sees a flow for blocked domains. |
| **NextDNS** | `NEDNSProxyProvider` | Same as AdGuard — different slot. |
| **Cloudflare WARP** | `NEPacketTunnelProvider` | Different slot (packet tunnel, not content filter). |
| **Corporate VPNs** | `NEPacketTunnelProvider` | Different slot. |
| **Tailscale** | `NEPacketTunnelProvider` | Different slot. |

**Important:** AdGuard has an optional "Network Extension mode" (transparent proxy) which conflicts with content filters. Keep AdGuard in its default **DNS-proxy mode** when running tarn.

### Not compatible

| Tool | Provider type | Conflict |
|---|---|---|
| **Little Snitch 5+** | `NEFilterDataProvider` | Same content filter slot. macOS activates one at a time. |
| **LuLu** | `NEFilterDataProvider` | Same slot. |
| **Radio Silence** | `NEFilterDataProvider` | Same slot. |
| **Commercial EDR agents** using `NEFilterDataProvider` | Same slot. |

If you run one of these tools, you must disable it before enabling tarn's content filter. Tarn detects this at activation time and reports the conflict.

### Legacy tools (no conflict)

- **Little Snitch 4 and earlier** used a kernel extension (kext), not a Network Extension. They don't conflict with tarn but are not supported on modern macOS.
- **pf (Packet Filter)** is a BSD firewall configured via `/etc/pf.conf`. It operates at the IP layer, below Network Extension. No conflict.
- **Application Firewall** (built into macOS, System Settings → Network → Firewall) operates independently of Network Extension providers. No conflict.

## Endpoint Security coexistence

Multiple Endpoint Security clients can run simultaneously on macOS. Tarn's ES client coexists with:

- **Santa** (Google's binary authorization tool)
- **osquery**
- **CrowdStrike Falcon**
- **Any other ES-based EDR**

Each ES client receives its own copy of AUTH events and responds independently. All clients must allow an operation for it to proceed; if any client denies, the operation is denied. This means tarn's file deny decisions are additive with other ES tools — they can only make the policy stricter, never more permissive.

## Agent compatibility

Tarn is agent-agnostic. It supervises any process launched via `tarn run`. Tested with:

| Agent | Status | Notes |
|---|---|---|
| Claude Code | Tested | `--dangerously-skip-permissions` bypasses Claude's built-in sandbox; tarn provides the replacement |
| Codex | Expected to work | `--dangerously-bypass-approvals-and-sandbox` |
| Gemini CLI | Expected to work | `--yolo` mode |
| opencode | Expected to work | No special flags needed |
| Custom agents | Works | Pass the command name via `--agent` |

The agent must be reachable in `$PATH`. Tarn launches it via `/usr/bin/env <agent-name>`.

## Development stack compatibility

Tarn auto-detects stacks and loads appropriate profiles. Manual override is available via `--stack`.

All common build tools and package managers work under tarn supervision:

- **Node.js**: npm, yarn, pnpm, bun — registry access whitelisted, node_modules writable
- **Python**: pip, uv, poetry — PyPI whitelisted, virtualenvs writable
- **Rust**: cargo — crates.io whitelisted, ~/.cargo writable
- **Go**: go modules — proxy.golang.org whitelisted
- **Swift/Xcode**: SwiftPM — Xcode DerivedData writable, developer.apple.com whitelisted

## Hardware

Tarn runs on both Apple Silicon (arm64) and Intel (x86_64) Macs. The system extension is a universal binary.
