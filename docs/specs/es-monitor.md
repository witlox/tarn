# Specification: Endpoint Security Supervisor

The Endpoint Security supervisor is the file and process side of the
tarn supervisor system extension. It manages an ES client, subscribes
to AUTH and NOTIFY events, applies trusted-region fast paths and
whitelist checks, and delegates unknown decisions to the prompt UI
via XPC.

The Network Extension content filter is a separate component, also
hosted in the same system extension; it is documented in
`ne-filter.md`. The two components share a process tree, a session
cache, and a profile, but operate on different ES/NE callbacks.

## ES Client Lifecycle

On `start()`, the supervisor creates an ES client via
`es_new_client()` and subscribes to:

- `ES_EVENT_TYPE_AUTH_OPEN`
- `ES_EVENT_TYPE_NOTIFY_FORK`
- `ES_EVENT_TYPE_NOTIFY_EXEC`
- `ES_EVENT_TYPE_NOTIFY_EXIT`

The NOTIFY events are required to maintain the supervised process
tree. They do not require an allow/deny response — they are
informational.

There is no `AUTH_CONNECT` or any other network event in the ES
subscription list. Endpoint Security has no AUTH event for IP-level
network connections; that surface lives in the Network Extension
framework. Network supervision is handled by the NE filter component.

On `stop()`, the supervisor unsubscribes from all events and deletes
the client.

If `es_new_client()` fails, the supervisor reports an error with
diagnostic guidance pointing at the most likely causes: missing
`com.apple.developer.endpoint-security.client` entitlement, system
extension not yet activated, or SIP enabled on a development build.

## Event Handling

Each AUTH event is handled synchronously. The handler:

1. Looks up the PID in the supervised process tree. If not supervised,
   responds `ES_AUTH_RESULT_ALLOW` immediately and returns.
2. Applies trusted-region fast paths (workspace, /tmp, system paths).
3. Checks the whitelist deny set, then the allow set.
4. Checks the session cache.
5. If still undecided, sends an XPC prompt request to the CLI and
   waits for the response.

Every AUTH event receives exactly one `es_respond_auth_result()` call,
and that call happens before the ES response deadline. Failure to
respond causes the system to kill the ES client.

NOTIFY events update the process tree:

- `NOTIFY_FORK` adds the child PID if the parent is supervised.
- `NOTIFY_EXEC` is observed but does not change tree membership; the
  PID is unchanged across exec and supervision follows the PID.
- `NOTIFY_EXIT` removes the PID from the tree.

## Trusted Regions

The following access patterns are allowed without whitelist lookup:

- File opens where the path starts with the workspace directory
- File opens where the path starts with `/tmp` or `/var/tmp`
- File opens for system paths: `/usr`, `/lib`, `/bin`, `/sbin`,
  `/System`, `/Library`, `/Applications`, `/private/var/db`, `/dev`

Trusted regions are evaluated before the whitelist and before any
prompt. They handle the vast majority of file events.

## Identity

The supervisor uses the BSM audit token (`audit_token_t`) extracted
from `es_message_t.process.audit_token` as the canonical identity for
a process. This is the same token the Network Extension content filter
sees on its side via `NEFilterFlow.sourceAppAuditToken`, so the
supervised process tree maintained from ES NOTIFY events is the same
set of identities the NE filter checks against.

For logging and process-tree bookkeeping, the audit token is converted
to a PID via `audit_token_to_pid()`. PIDs are not used as cache keys —
PID reuse is real, and the audit token is the kernel-stable identity.
Code-signing checks use `SecCodeCopyGuestWithAttributes()` with the
`kSecGuestAttributeAudit` attribute, again driven by the token.

## Process Tree Integration

The supervisor uses the ProcessTree component (defined in TarnCore) to
determine whether a PID is supervised. The tree is populated by
`NOTIFY_FORK` events for any fork from a PID already in the tree, and
by registering the agent's launched PID as the root at session start
(via an XPC call from the CLI immediately after `Process.run()`).

A periodic prune walks the supervised set and removes any PID that no
longer exists (verified via `kill(pid, 0)`). This guards against lost
`NOTIFY_EXIT` events leaving zombie entries that could grant
supervision to a reused PID.

## Session Cache

The session cache is shared with the NE filter. It holds both allows
and denies, keyed by an opaque string the producer chooses (typically
the expanded path for file events, or `"host:<hostname>"` for network
events). Decisions are cleared when the supervisor's session for a
given agent ends.

The session cache is critical for staying inside the ES response
deadline: the same path opened twice in a session does not re-prompt.
If a prompt would push the supervisor past its deadline budget, the
file-event side denies it and adds the deny to the cache to prevent
an immediate retry storm.

## What This Component Does Not Do

- Network supervision — handled by the NE filter (`ne-filter.md`)
- Profile composition — handled by TarnCore
- TOML parsing or persistence — handled by TarnCore
- The interactive prompt UI — handled by the CLI, reached via XPC
