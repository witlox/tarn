# Specification: CLI

The `tarn` CLI manages the Endpoint Security supervisor, the agent
process lifecycle, and the global whitelist profile.

## Commands

### `tarn run <repo-path>`

Starts the ES supervisor, registers AUTH and NOTIFY event subscriptions,
launches the agent process, and enters the event loop. The repo path is
always allowed for read-write access. The `--agent` flag selects the
agent CLI and its YOLO-mode flags. The `--stack` flag explicitly
selects toolchain profiles; if omitted, stacks are auto-detected from
the repo contents. The `--profile` flag overrides the default profile
location.

While the agent runs, Tarn handles ES events on a background thread.
When an unknown access pattern is detected, the prompt is displayed on
the main terminal interleaved with agent output. The kernel suspends
the agent's syscall until Tarn responds with an allow or deny decision.

The interactive prompt UI is serialized: at most one prompt is on
screen at a time. If multiple unknown access events arrive while a
prompt is pending, they queue in FIFO order. Events whose ES deadline
is approaching while still queued are denied (and added to the session
cache to prevent an immediate retry storm) rather than risk killing
the ES client.

On agent exit, the supervisor is stopped, any pending profile updates
are flushed, and the session summary is printed.

### `tarn profile show`

Displays the current whitelist grouped by section. Each entry is tagged
as default or learned.

### `tarn profile reset`

Removes learned entries; default entries are preserved. Prompts for
confirmation unless `--force` is given. Idempotent: running it on a
profile with no learned entries succeeds with a no-op message.

## Exit Behavior

Tarn exits with the agent's exit code. On `SIGINT` (Ctrl-C), Tarn
forwards the signal to the agent, drains any pending prompts (each
becomes a deny), flushes the profile, and exits. If the ES client is
killed by the system (response deadline exceeded), Tarn logs the error
with diagnostic guidance and exits with status 1.

## Root Requirement

Tarn requires root privileges for ES client creation. Users invoke it
via `sudo tarn run ...`. The profile file is owned by the real user,
not root — Tarn reads the `SUDO_USER` environment variable and resolves
the user's home directory from it.

If `SUDO_USER` is unset (for example, when tarn is invoked from a
direct root login rather than via `sudo`), Tarn refuses to start with
a clear error rather than silently creating a profile in
`/var/root/Library/Application Support/tarn/`. The supported invocation
is always `sudo tarn run ...` from a normal user account.

## Single-Instance Lock

Two `tarn run` instances against the same user's profile are not
supported in v1 — concurrent learned-entry writes would race and lose
updates. On startup, Tarn creates a lock file at
`~/Library/Application Support/tarn/tarn.lock` containing its PID. If
the lock file already exists and the recorded PID is alive, the second
invocation refuses to start with a clear error pointing at the lock
file. Stale lock files (PID dead) are removed and the new instance
proceeds.
