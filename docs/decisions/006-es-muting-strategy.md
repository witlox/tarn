# ADR-006: ES Per-Event Muting Strategy

Date: April 2026
Status: Accepted
Related: ADR-005 (two-extension split), ESC-001 (escalation analysis)

## Context

The ES extension subscribes to AUTH_OPEN for supervised processes. Without
muting, AUTH_OPEN fires for every file open by every process on the system.
At ~10,000 file opens per second system-wide, this would give the ES
callback full visibility into all process activity and impose measurable
CPU overhead for no benefit.

We need AUTH_OPEN to fire only for supervised PIDs (the agent and its
children). All other processes should be muted at the kernel level so
the callback never fires.

Additionally, the agent root PID must be supervised from its very first
instruction. There must be no window where the agent can open files
unsupervised.

## Rejected Alternatives

### Inverted process muting

`es_invert_muting(ES_MUTE_INVERSION_TYPE_PROCESS)` mutes all event types
(AUTH and NOTIFY) for all processes by default, then selectively unmutes
specific processes. This was the initial approach.

**Why rejected:** Inverted muting mutes NOTIFY_FORK for all processes.
This means the ES extension cannot see the CLI's fork event when
spawning the agent, and cannot see a supervised process fork a child.
There is no way to invert muting for AUTH events only while keeping
NOTIFY events visible. This is a fundamental limitation of the
`es_invert_muting` API.

### Subscribe AUTH_OPEN only during active sessions

Subscribe to AUTH_OPEN when a session starts, unsubscribe when it ends.
During a session, all processes trigger AUTH_OPEN but non-supervised
PIDs hit a fast-path allow (~100ns Set.contains check).

**Why rejected:** This gives the ES callback visibility into all
file opens system-wide during active sessions. While the fast-path
is cheap, the principle of minimal authority says we should not
receive events we do not need. Also, the kernel dispatch overhead
for routing ~10k events/second to our callback is non-trivial even
if the callback returns immediately.

## Decision

Use **per-event muting** via `es_mute_process_events` combined with
**suspended spawn** for agent root PID registration.

### Per-event muting

1. Subscribe to AUTH_OPEN + NOTIFY_FORK + NOTIFY_EXIT at ES client start.
   These subscriptions are permanent (never unsubscribed until shutdown).

2. In `handleFork`: for every child whose parent is NOT supervised,
   immediately call `es_mute_process_events(client, &childToken, [AUTH_OPEN], 1)`.
   This mutes AUTH_OPEN for that child at the kernel level. NOTIFY_FORK
   and NOTIFY_EXIT remain unmuted (we need them for tree tracking).

3. In `handleAuthOpen`: if the PID is not supervised, respond ALLOW and
   then call `es_mute_process_events`. This handles pre-existing processes
   that were running before the ES client started -- they trigger one
   AUTH_OPEN each, then are muted forever.

4. Supervised processes (agent root + children) are never muted for
   AUTH_OPEN. Their fork events skip the muting call.

### Suspended spawn for root PID

1. CLI calls `prepareAgentLaunch(cliPID)` -- ES extension adds cliPID
   to a watch set.

2. CLI calls `posix_spawn` with `POSIX_SPAWN_START_SUSPENDED` -- the agent
   process exists but cannot execute any instructions.

3. NOTIFY_FORK fires (fork happened, even though child is suspended).
   ES extension sees cliPID in the watch set, gets the child's audit
   token from the event, does NOT mute AUTH_OPEN for the child, adds
   the child to the ProcessTree, pushes PID to NE extension.

4. CLI calls `confirmAgentPID(pid)` -- belt-and-suspenders confirmation.

5. CLI sends `SIGCONT` -- agent starts executing, fully supervised.

This guarantees the agent's very first file open is intercepted.

## Consequences

### Startup overhead

When the ES client starts, all pre-existing processes are unmuted for
AUTH_OPEN. Each triggers one AUTH_OPEN callback (which responds ALLOW
and mutes them). On a typical macOS system with ~500 running processes,
this produces a brief burst of ~500 callbacks over ~1 second. After
that, only newly forked non-supervised processes trigger one callback
each (in handleFork, before they can open any files).

This is the same approach used by commercial ES products (e.g., CrowdStrike,
SentinelOne). The thundering herd at startup is well-understood and brief.

### Zero steady-state overhead

After the initial burst, non-supervised processes are muted at the
kernel level. The ES callback fires only for:
- NOTIFY_FORK (all processes -- needed for tree tracking)
- NOTIFY_EXIT (all processes -- needed for tree cleanup)
- AUTH_OPEN (supervised PIDs only -- the actual work)

NOTIFY events are lightweight (no response required, no deadline).
AUTH_OPEN for supervised PIDs is the intended workload.

### No system-wide visibility when idle

When no session is active, the ProcessTree is empty. AUTH_OPEN still
fires for newly forked processes (one each, then muted), but the
handleAuthOpen fast-path (`guard isSupervised` check) returns
immediately. The effective overhead approaches zero.

### Child PID tracking is reliable

Because NOTIFY_FORK is never muted, we see every fork from every process.
When a supervised parent forks, we catch it immediately, add the child
to the tree, skip muting, and push the PID to NE. The child's first
file open is supervised.

### Limitations

- The ~1s startup burst is unavoidable with per-event muting. It is
  brief and bounded by the number of running processes.
- `es_mute_process_events` is per-audit-token, not per-PID. If a
  process's audit token changes (extremely rare outside of security
  research), the muting would need to be reapplied.
- NOTIFY_FORK fires for all processes system-wide. This is ~100-200
  forks/second on a typical system. The handleFork callback is fast
  (Set.contains + es_mute_process_events, both O(1)).
