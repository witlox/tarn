# Specification: Process Tree Tracking

Tarn supervises only the agent's subprocess tree. All other system processes are allowed unconditionally. The ProcessTree component maintains a set of supervised PIDs and updates it as processes fork and exit.

## Root Registration

When `tarn run` launches the agent process, the agent's PID is registered as the root of the supervised tree. This is the only entry point — PIDs cannot be added to the tree externally.

## Child Tracking

Tarn subscribes to ES_EVENT_TYPE_NOTIFY_FORK and ES_EVENT_TYPE_NOTIFY_EXEC events. When a fork event fires and the parent PID is in the supervised set, the child PID is added. This captures the full subprocess tree regardless of depth.

NOTIFY events do not require an allow/deny response — they are informational. Tarn uses them solely for bookkeeping.

## Process Exit

When a supervised process exits (detected via ES_EVENT_TYPE_NOTIFY_EXIT), its PID is removed from the set. The tree shrinks over time as short-lived processes come and go.

## Scope Check

On every AUTH event, the Monitor calls `isSupervised(pid:)` before any other processing. If the PID is not in the set, the event is immediately allowed with no further work. This is the primary performance optimization — it ensures Tarn has zero impact on unsupervised processes.

## Thread Safety

The supervised PID set is accessed from the ES event handler callback, which may fire on multiple threads. All mutations are protected by a lock. The set operations (insert, remove, contains) are O(1) for a hash set, so lock contention is minimal.

## Limitations

A process that forks and then reparents itself to PID 1 (e.g., by double-forking and having the intermediate process exit) will leave the supervised tree. This is a known limitation of PID-based process tree tracking. It is not a concern for typical agent workflows where the agent runs a shell that spawns build tools and package managers — these remain in the tree.

A process that calls `exec()` retains its PID, so it remains supervised. This is correct behavior — an agent that execs into a different binary should still be supervised.
