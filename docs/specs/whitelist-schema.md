# Specification: Whitelist Schema

The whitelist profile is a TOML file at
`~/Library/Application Support/tarn/profile.toml`, the standard macOS
location for per-user application data. It defines which paths and
network domains the supervised agent is allowed to access beyond the
hardcoded fast paths and the compiled-in deny list.

## Schema

### `[paths.readonly]`

Paths the agent may read but not write. Tilde-expanded at runtime.
Writes to these paths are explicitly denied — not prompted, denied.
Promoting a read-only entry to read-write must be a deliberate user
edit, not a side effect of the agent attempting a write.

### `[paths.readwrite]`

Paths the agent may both read and write. Use sparingly.

### `[network.allow]`

Domain names the agent may connect to. Fully qualified domains only,
exact match. Subdomains must be listed separately. Wildcards
(`*.github.com`) are not supported in v1 — Tarn enforces the network
allowlist by forward-resolving these domains at session start, not by
intercepting the agent's DNS lookups, and so it cannot know which
specific subdomain a wildcard expansion was intended to match.

The whitelist file contains only domains, never IPs. Tarn maintains an
in-memory IP cache built from these domains via the system resolver,
but the cache is a runtime optimization and never appears in the file.

## Default Entries

When the file does not exist on first run, Tarn materializes it with a
small set of common-sense defaults:

- Read-only: `~/.gitconfig`, `~/.ssh/known_hosts`
- Read-write: none
- Network: `api.anthropic.com`, `github.com`, `registry.npmjs.org`,
  `pypi.org`, `crates.io`

These defaults live in the user's whitelist file, not in the compiled-in
base profile, so the user can edit or remove them and `tarn profile
reset` will not bring them back automatically. The base profile is
limited to macOS system paths (`/usr`, `/System`, `/Library`, etc.) and
the compiled-in credential deny list.

## Learned Entries

Approved-with-remember entries are appended with a `# learned` marker
after the value on the same line. The `tarn profile reset` command
removes only learned entries; default entries (and any user-added
entries that are not marked learned) are preserved.

## Validation

- Paths must be absolute after tilde expansion.
- Domains must be non-empty and may not contain `*` or other wildcard
  characters.
- Duplicates are deduplicated on load.
- Malformed TOML causes a descriptive error pointing at the offending
  line and column. Tarn refuses to start on a malformed profile rather
  than silently overwriting the user's file with defaults.

## Atomicity

Writes use a temp file plus rename pattern to prevent corruption from
interrupted writes. The temp file is created in the same directory as
the target so that the rename is atomic on the local filesystem and
cannot fail with `EXDEV`.

If the write fails for any reason (disk full, permission, read-only
mount), the in-flight access is still allowed for the current request,
the new entry is held in the session cache only, and a warning is
printed to the terminal so the user knows the entry will not survive
the session.
