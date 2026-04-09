# Contributing to Tarn

Thanks for your interest in contributing to tarn.

## Getting started

1. Fork the repository
2. Clone your fork
3. Install dependencies:
   - Xcode 16+
   - SwiftLint: `brew install swiftlint`
   - XcodeGen: `brew install xcodegen`

4. Build and test:
   ```bash
   swift build              # build TarnCore + CLI
   swift test               # run 172+ tests
   swiftlint lint --strict  # lint
   xcodegen generate        # regenerate Xcode project (if you changed project.yml)
   ```

## Project structure

- **TarnCore** — shared policy library (profiles, config, process tree, session cache). Pure Foundation, no system framework deps. This is where most logic lives and where most tests run.
- **TarnCLI** — the command-line tool. Argument parsing, prompt UI, XPC client.
- **TarnSupervisor** — the system extension. ES client, NE filter, XPC service. Requires Xcode to build (restricted frameworks).
- **TarnApp** — minimal host app for the system extension.

If your change is to policy logic (deny rules, profile composition, whitelist parsing), it goes in TarnCore and can be tested with `swift test` alone.

If your change touches ES or NE code, you need a SIP-disabled test machine or VM to verify at runtime.

## Testing

- All changes should include tests
- Tests go in `Tests/TarnCoreTests/`
- Name test methods after the behavior they verify, not the implementation
- The test suite should pass before submitting a PR: `swift test`
- BDD scenarios in `tests/features/*.feature` describe intended behavior — new features should have corresponding scenarios

## Code style

- Swift standard formatting
- No force unwraps (`!`) — use `guard let` or `if let`
- SwiftLint enforces the rules in `.swiftlint.yml`
- Keep functions under 60 lines
- Use domain language from the codebase (see `docs/specs/` for vocabulary)

## Commit messages

Keep them concise and descriptive. Focus on *what* and *why*, not *how*.

```
Add wildcard domain validation to Config parser

The TOML parser now rejects domain entries containing wildcards
(*.github.com) with a clear error message, since the v1 schema
only supports exact-match domains.
```

## Pull requests

- Keep PRs focused — one feature or fix per PR
- Fill in the PR template
- Make sure CI passes (build + test + lint)
- New features need documentation updates (README, usage guide, or relevant spec)

## Reporting security issues

If you find a security vulnerability, please do **not** open a public issue. Email the maintainer directly. See [docs/security.md](docs/security.md) for the threat model and known limitations.

## Development without entitlements

You don't need an Apple Developer account to work on TarnCore or the CLI. The policy library and its 172+ tests build and run on any Mac with Swift installed.

The system extension (TarnSupervisor) requires:
- Apple Developer Program membership ($99/yr)
- Endpoint Security entitlement (request from Apple)
- Network Extension content-filter entitlement (request from Apple)
- A SIP-disabled test machine for unsigned development builds

If you're contributing to the policy layer, you can develop and test without any of this.
