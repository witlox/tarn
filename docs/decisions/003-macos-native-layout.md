# ADR-003: macOS-Native Filesystem Layout

Date: April 2026
Status: Accepted

## Context

Tarn needs a place on disk to store the user's whitelist profile, an
optional log file, and a single-instance lock file. The initial design
proposed `~/.tarn/profile.toml` — a Unix-tradition dot-directory in
the user's home. This works on macOS but is the choice an ex-Linux
developer would make. macOS has a long-standing convention for where
per-user application data lives, and Tarn is a macOS-native project.

## Decision

**Use the macOS-standard layout under `~/Library/`:**

- Whitelist profile: `~/Library/Application Support/tarn/profile.toml`
- Single-instance lock: `~/Library/Application Support/tarn/tarn.lock`
- Logs (when added): `~/Library/Logs/tarn/`

`~/.tarn/` is not used. Tarn does not migrate from it; users who
hand-created the old path will see Tarn create the new one and ignore
the old.

## Why

- **Consistency with the platform.** Every other Mac app stores per-user
  configuration under `~/Library/Application Support/`. A user looking
  for "where does Tarn keep its profile?" will find it where they look
  first.
- **Time Machine and migration.** `~/Library` is included in Time
  Machine backups by default and is preserved across macOS user
  migrations. `~/.tarn/` works but is the kind of thing power users
  exclude from backups by accident.
- **Spotlight and Finder.** `~/Library/Application Support/` is
  navigable; `~/.tarn/` is hidden by default and harder for non-technical
  users to find.
- **No reason not to.** The Unix tradition argument — "dot-directories
  are simpler" — does not survive contact with the macOS user base.
  Tarn is for developers on macOS, not for developers running macOS as
  if it were Linux.

## SUDO_USER resolution

Tarn requires root privileges and is invoked via `sudo`. The profile
file belongs to the user, not to root. Tarn reads the `SUDO_USER`
environment variable, looks up that user's home directory via
`getpwnam`, and uses it as the base for the `~/Library/...` paths.

If `SUDO_USER` is unset (for example, when tarn is run from a direct
root login), Tarn refuses to start with a clear error rather than
silently creating a profile in `/var/root/Library/Application Support/`.
The supported invocation is always `sudo tarn run ...` from a normal
user account.

## Consequences

- The CLI default for `--profile` is now
  `~/Library/Application Support/tarn/profile.toml` (resolved against
  `SUDO_USER`).
- The lock file lives in the same directory; one less thing to clean up
  on uninstall.
- All committed documentation, the README, and any user-facing help
  text reference the new path.
- The `Application Support/tarn/` directory is created on first run if
  it does not exist. If the parent (`Application Support/`) is missing
  or unwritable — extremely unusual — Tarn refuses to start with a
  clear error rather than falling back silently.
