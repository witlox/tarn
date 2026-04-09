# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] — 2026-04-09

### Added
- Endpoint Security supervisor for file/process access control (AUTH_OPEN, NOTIFY_FORK/EXIT)
- Network Extension content filter (NEFilterDataProvider) for outbound flow control
- Interactive terminal prompt: allow once, allow and remember, deny (default)
- Composable security profiles: base macOS + per-stack (node, python, rust, go, xcode) + per-agent (claude, codex, gemini, opencode)
- Persistent TOML whitelist at `~/Library/Application Support/tarn/profile.toml`
- Compiled-in credential deny list (~/.aws, ~/.ssh/id_*, ~/.gnupg, etc.)
- Stack auto-detection from repo indicator files (package.json, Cargo.toml, etc.)
- Session cache for per-session allow/deny decisions (both cached, not just allows)
- Single-instance lock file preventing concurrent sessions
- XPC communication between unprivileged CLI and privileged system extension
- Team-ID validation on XPC connections
- Async decision pipeline: es_retain_message + deferred response for ES, pauseVerdict + resumeFlow for NE
- UDP flow watchdog (auto-deny after 8 seconds before macOS 10-second auto-drop)
- Wildcard domain rejection in whitelist parser
- 172 unit and integration tests
- Xcode project via xcodegen (project.yml)
- Documentation: README, usage guide, security model, compatibility guide, 4 ADRs, 6 component specs

### Architecture
- `.app` bundle with embedded system extension (ADR-001, ADR-004)
- ES for files, NEFilterDataProvider for network (ADR-002)
- macOS-native layout: ~/Library/Application Support/tarn/ (ADR-003)
- AdGuard-compatible: content filter and DNS proxy are different NE provider slots
- Profile persistence through CLI (not supervisor) — supervisor never writes user files
