# ADR-004: Project Structure and Build System

Date: April 2026
Status: Accepted

## Context

ADR-001 establishes that tarn is a `.app` bundle containing a CLI and system extensions. ADR-005 establishes that ES and NE run in separate system extensions (TarnES and TarnSupervisor). Neither of those decisions specifies how the project is laid out on disk or which build system produces the deliverable. This document does.

The constraint that drives everything: **Swift Package Manager cannot build `.systemextension` bundles or `.app` bundles.** SPM produces libraries and bare executables. Apple's system-extension and app-bundle targets are Xcode-only build product types. Any project that ships a system extension on macOS uses Xcode for at least the bundle targets. LuLu, Little Snitch, Apple's `SimpleFirewall` sample, and `agentsh` all use Xcode projects.

## Decision

**Use an Xcode project with four targets, one shared Swift library, and XPC code connecting them.**

### Targets

| Target | Type | Output | Role |
|---|---|---|---|
| **TarnCore** | Static library (Swift) | `libTarnCore.a` | Pure policy: Profile composition, ProcessTree, SessionCache, Config (TOML), DecisionEngine, errors, lock file, ubiquitous types. No system framework dependencies beyond Foundation. Linked by all other targets. |
| **tarn** | Command Line Tool (Swift) | `tarn` executable, embedded at `Tarn.app/Contents/MacOS/tarn` | The unprivileged CLI. Argument parsing (ArgumentParser), agent process launch (suspended spawn per ADR-006), terminal prompt UI, XPC client to TarnES. Symlinked to `/usr/local/bin/tarn` so users invoke it as a normal command. |
| **TarnES** | System Extension (Swift) | `com.witlox.tarn.es.systemextension`, embedded at `Tarn.app/Contents/Library/SystemExtensions/` | The Endpoint Security extension. Hosts ESClient (AUTH_OPEN, AUTH_LINK, AUTH_UNLINK, AUTH_RENAME, NOTIFY_FORK, NOTIFY_EXIT with per-event muting per ADR-006), ESXPCService, DecisionEngine, ProcessTree, and SessionCache. Accepts XPC connections from both the CLI and TarnSupervisor. See [ADR-005](005-two-extension-split.md). |
| **TarnSupervisor** | System Extension (Swift) | `com.witlox.tarn.supervisor.systemextension`, embedded at `Tarn.app/Contents/Library/SystemExtensions/` | The Network Extension extension. Hosts `NEFilterDataProvider` (NetworkFilter) and ESBridgeClient. Stateless thin proxy: intercepts outbound flows, forwards to TarnES via XPC for evaluation, resumes with the verdict. See [ADR-005](005-two-extension-split.md). |
| **Tarn** | macOS app (Swift, `LSUIElement=YES`) | `Tarn.app` | The host bundle. No UI; its only job is to embed the CLI binary and both system extensions, and provide the activation entry point. Activates TarnES first, then TarnSupervisor (via `NEFilterManager.saveToPreferences`). |

### Directory layout

```
tarn/
├── Tarn.xcodeproj/             ← single Xcode project, all targets
├── Package.swift               ← kept for the TarnCore library so unit
│                                  tests can run via swift test on a
│                                  SIP-disabled dev VM without launching
│                                  Xcode (TarnCore is pure policy and
│                                  has no system extension dependencies)
├── Sources/
│   ├── TarnCore/               ← shared library, also exposed via SPM
│   │   ├── Profile/
│   │   ├── ProcessTree.swift
│   │   ├── SessionCache.swift
│   │   ├── Config.swift
│   │   ├── Errors.swift
│   │   ├── Lock.swift
│   │   └── XPCInterface.swift  ← protocol shared with supervisor
│   ├── TarnCLI/                ← the command-line tool
│   │   ├── main.swift
│   │   ├── Commands/
│   │   ├── PromptUI.swift
│   │   └── XPCClient.swift
│   ├── TarnES/                 ← the ES system extension (ADR-005)
│   │   ├── main.swift
│   │   ├── ESClient.swift       ← AUTH_OPEN/LINK/UNLINK/RENAME, per-event muting
│   │   └── ESXPCService.swift   ← serves CLI + TarnSupervisor
│   ├── TarnSupervisor/         ← the NE system extension (ADR-005)
│   │   ├── main.swift
│   │   ├── NetworkFilter.swift  ← NEFilterDataProvider subclass
│   │   └── ESBridgeClient.swift ← XPC client to TarnES
│   └── TarnApp/                ← the host app bundle
│       ├── main.swift
│       └── ExtensionActivator.swift
├── Resources/
│   ├── TarnCLI-Info.plist
│   ├── TarnES-Info.plist
│   ├── TarnES.entitlements
│   ├── TarnSupervisor-Info.plist
│   ├── TarnApp-Info.plist
│   ├── TarnCLI.entitlements
│   ├── TarnSupervisor.entitlements
│   └── TarnApp.entitlements
├── Tests/
│   └── TarnCoreTests/          ← unit tests against TarnCore via SPM
├── tests/
│   └── features/               ← Gherkin BDD specs (unchanged)
├── docs/
└── Makefile                    ← convenience wrappers for xcodebuild
```

### Why both Xcode and SPM

`Tarn.xcodeproj` is the source of truth for builds — it produces `Tarn.app` with the CLI and both system extensions embedded correctly. `Package.swift` is kept solely so that `TarnCore` can be unit-tested via `swift test` without launching Xcode. The TarnCore library has no system framework dependencies beyond Foundation, so it builds and tests cleanly under SPM. The Xcode targets `tarn`, `TarnES`, `TarnSupervisor`, and `Tarn` reference the same source files but are built with their respective bundle product types.

This dual-build is a small maintenance cost (file lists in two places, kept in sync by `git diff`) but a meaningful productivity gain: most of the value of TarnCore is in fast iterative testing of the policy logic, and dropping into Xcode for every change to a profile rule would be a drag.

### Entitlements

**Tarn.app** (`TarnApp.entitlements`):

```xml
<key>com.apple.developer.system-extension.install</key><true/>
<key>com.apple.developer.networking.networkextension</key>
<array>
    <string>content-filter-provider-systemextension</string>
</array>
```

**TarnES** (`TarnES.entitlements`):

```xml
<key>com.apple.developer.endpoint-security.client</key><true/>
<key>com.apple.security.application-groups</key>
<array>
    <string>$(TeamIdentifierPrefix)com.witlox.tarn</string>
</array>
```

**TarnSupervisor** (`TarnSupervisor.entitlements`):

```xml
<key>com.apple.developer.networking.networkextension</key>
<array>
    <string>content-filter-provider-systemextension</string>
</array>
<key>com.apple.security.application-groups</key>
<array>
    <string>$(TeamIdentifierPrefix)com.witlox.tarn</string>
</array>
```

The CLI binary itself does not need any special entitlements — it is an unprivileged Mach-O that talks XPC.

Note: The ES entitlement is on TarnES only; the NE entitlement is on TarnSupervisor and Tarn.app (the host app needs it for `NEFilterManager` activation). Application groups are shared so both extensions can communicate via the same Mach service namespace.

### XPC interface

Three XPC relationships exist in the two-extension architecture ([ADR-005](005-two-extension-split.md)):

1. **CLI → TarnES** (`kTarnESMachServiceName`): session management, agent PID registration (suspended spawn per ADR-006), prompt responses.
2. **TarnES → CLI** (reverse XPC callback): prompt requests pushed from TarnES to the CLI's prompt handler.
3. **TarnSupervisor → TarnES** (`kTarnESMachServiceName`): network flow forwarding. TarnSupervisor's ESBridgeClient connects to TarnES's ESXPCService. TarnES also pushes supervised PID updates to TarnSupervisor.

Both the CLI and TarnSupervisor connect to the same Mach service on TarnES. The ESXPCService distinguishes them by effective UID (root vs. user).

The interfaces are defined as Swift protocols in `TarnCore/XPCInterface.swift` and conformed to in `TarnES/ESXPCService.swift`.

Prompts flow from TarnES to CLI (TarnES pauses the ES response or holds the NE flow, sends an XPC request to the CLI's prompt handler, waits for the response, then resumes/responds). For network flows, the chain is: TarnSupervisor pauses the flow → forwards to TarnES → TarnES prompts the CLI → CLI responds → TarnES returns verdict → TarnSupervisor resumes the flow.

### Build commands

Three convenience targets in the top-level `Makefile`:

```make
build:        ## Build Tarn.app via xcodebuild
test:         ## Run TarnCore unit tests via swift test
release:      ## Build, sign, and notarize Tarn.app for distribution
```

Plus the existing `swift build` / `swift test` for fast iteration on TarnCore.

## Why not pure SPM

Investigated and rejected. SPM 5.10 has no notion of:

- App bundles (`.app`)
- System extensions (`.systemextension`)
- Embedded executables/frameworks/extensions
- Info.plist generation for bundle products
- Code signing for bundle products

A pure-SPM build would require shell scripts that take SPM's bare executable output and manually wrap it in a bundle structure, embed the system extension, generate Info.plists, and run `codesign`. That is achievable but fragile, undocumented, and not what any other macOS system extension project does. The maintenance burden over time would exceed the cost of using Xcode.

## Why not Tuist or other project generators

Investigated. Tuist (and similar tools like XcodeGen) generate `.xcodeproj` files from a Swift or YAML manifest, which would let the project file be regenerable rather than checked in. For a single-developer project of this size, the additional dependency and the layer of indirection are not worth the benefit. The `.xcodeproj` is checked in directly. If the project grows or gets multiple maintainers, moving to Tuist becomes a five-line decision later.

## Consequences

- The repository has both `Tarn.xcodeproj/` and `Package.swift`. They reference overlapping source files. Anyone adding a new file to `Sources/TarnCore/` must add it to both.
- The macOS development requirement is Xcode 16+.
- Building requires `xcodebuild` for the `.app`; tests can still run via `swift test` for fast iteration on policy code.
- The CI pipeline (when added) needs `xcodebuild`, `notarytool`, and the Developer ID certificates configured as secrets.
- Distribution is a notarized `.dmg` or `.pkg` containing `Tarn.app`, with a post-install step that creates `/usr/local/bin/tarn` as a symlink into the bundle.
- Uninstall is the reverse: deactivate both system extensions via `systemextensionsctl uninstall`, delete `Tarn.app`, remove the symlink, optionally remove `~/Library/Application Support/tarn/`.
- Two system extension targets (TarnES, TarnSupervisor) means two Info.plists, two entitlements files, and a more complex `project.yml`. The trade-off is documented in [ADR-005](005-two-extension-split.md).
