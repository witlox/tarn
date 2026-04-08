# Landscape Analysis: AI Agent Sandboxing on macOS

Date: April 2026
Status: Complete — decision to build standalone tool (Tarn) using Endpoint Security

## Context

AI coding agents run with broad filesystem and network access on developer machines. The March 2026 Claude Code source leak and concurrent axios supply chain attack demonstrated the threat is no longer theoretical: 512,000 lines of source were exposed, a critical permission bypass vulnerability was found (50+ subcommand skip), and trojanized packages appeared within hours.

## Existing Solutions Evaluated

Eight sandbox tools were evaluated across two rounds of analysis. The first round compared VM and container-based approaches; the second identified that macOS provides a kernel-level process supervision mechanism (Endpoint Security) that eliminates the need for VMs entirely.

### Round 1: VM and Container Approaches

| Tool | Runtime | Isolation | FS Policy | Network | Learning |
|---|---|---|---|---|---|
| Claude Code built-in | Seatbelt | Process | Static | allowedDomains | None |
| Safehouse | Seatbelt | Process | Static deny | None | None |
| CodeRunner | Apple Container | VM | Static mounts | Static | None |
| sandbox-claude | OrbStack+Incus | VM | Static mounts | Squid SNI | None |
| SandVault | User account | Process | Permissions | None | None |
| Docker Sandboxes | Docker microVM | VM | Static | Policy tiers | None |
| ai-jail | bwrap/Seatbelt | Process | tmpfs overlay | Static | None |
| agentsh | ES Framework | Kernel | Static rules | Network Extension | None |

### Key Finding from Round 1

No tool implements interactive prompt-and-learn at the access control level. All use static policy models defined before execution.

### Round 2: Kernel-Level Supervision

The initial design proposed Apple Container VMs with a seccomp-notify supervisor (C guest daemon communicating over vsock). During analysis, a simpler architecture was identified:

macOS XNU includes the Mandatory Access Control Framework (MACF), derived from TrustedBSD. Apple's Sandbox (Seatbelt) and SIP are both MACF policy modules. With kext deprecation, Apple replaced direct MACF access with the Endpoint Security (ES) framework — a userspace API that receives kernel-level AUTH notifications for file, process, and network operations, with the ability to allow or deny before execution.

This is architecturally identical to Linux's seccomp-notify but native to macOS, with richer semantic context (full paths, process info, code signing status) and no VM required.

**agentsh** was identified as the closest existing project — it uses ES on macOS for AI agent sandboxing. However, its macOS support is Alpha, it's written in Go, uses static policies, and is oriented toward enterprise security (MCP whitelisting, rate limiting, audit logging) rather than developer-facing interactive learning.

## Final Architecture Decision

Build Tarn as a single Swift binary using Endpoint Security:

- ES AUTH events for file opens (ES_EVENT_TYPE_AUTH_OPEN) and network connections (ES_EVENT_TYPE_AUTH_CONNECT)
- Process tree tracking to supervise only the agent's subprocess tree
- Interactive terminal prompt for unknown access patterns
- Persistent TOML whitelist that grows as the user approves
- No VMs, no containers, no guest daemons, no cross-compilation

## Technology Choice

- **Swift**: native ES framework bindings, ArgumentParser for CLI, Foundation for file I/O, single binary output
- **Endpoint Security**: kernel-enforced, pre-execution interception, not deprecated, Apple-supported
- **TOML**: human-readable whitelist, version-controllable, auditable
