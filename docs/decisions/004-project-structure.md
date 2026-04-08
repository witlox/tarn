# ADR-004: Project Structure and Build System

Date: April 2026
Status: Accepted

## Context

ADR-001 establishes that tarn is a `.app` bundle containing a CLI and a system extension. ADR-002 establishes that the system extension hosts both the Endpoint Security client and a `NEFilterDataProvider`. Neither of those decisions specifies how the project is laid out on disk or which build system produces the deliverable. This document does.

The constraint that drives everything: **Swift Package Manager cannot build `.systemextension` bundles or `.app` bundles.** SPM produces libraries and bare executables. Apple's system-extension and app-bundle targets are Xcode-only build product types. Any project that ships a system extension on macOS uses Xcode for at least the bundle targets. LuLu, Little Snitch, Apple's `SimpleFirewall` sample, and `agentsh` all use Xcode projects.

## Decision

**Use an Xcode project with three targets, one shared Swift library, and a small layer of XPC code on top.**

### Targets

| Target | Type | Output | Role |
|---|---|---|---|
| **TarnCore** | Static library (Swift) | `libTarnCore.a` | Pure policy: Profile composition, ProcessTree, SessionCache, Config (TOML), errors, lock file, ubiquitous types. No system framework dependencies beyond Foundation. Linked by both other targets. |
| **tarn** | Command Line Tool (Swift) | `tarn` executable, embedded at `Tarn.app/Contents/MacOS/tarn` | The unprivileged CLI. Argument parsing (ArgumentParser), agent process launch, terminal prompt UI, XPC client to the supervisor. Symlinked to `/usr/local/bin/tarn` so users invoke it as a normal command. |
| **TarnSupervisor** | System Extension (Swift) | `com.witlox.tarn.supervisor.systemextension`, embedded at `Tarn.app/Contents/Library/SystemExtensions/` | The privileged supervisor. Hosts the ES client (file/process events), the `NEFilterDataProvider` (network flows), the supervised process tree, and the XPC service that the CLI talks to. |
| **Tarn** | macOS app (Swift, `LSUIElement=YES`) | `Tarn.app` | The host bundle. No UI; its only job is to embed the CLI binary and the system extension and provide the activation entry point that calls `OSSystemExtensionRequest`. The CLI invokes activation lazily on first run if the extension is not already installed. |

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
│   ├── TarnSupervisor/         ← the system extension
│   │   ├── main.swift
│   │   ├── ESClient.swift
│   │   ├── NetworkFilter.swift  ← NEFilterDataProvider subclass
│   │   ├── XPCService.swift
│   │   └── DecisionEngine.swift
│   └── TarnApp/                ← the host app bundle
│       ├── main.swift
│       └── ExtensionActivator.swift
├── Resources/
│   ├── TarnCLI-Info.plist
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

`Tarn.xcodeproj` is the source of truth for builds — it produces `Tarn.app` with the CLI and system extension embedded correctly. `Package.swift` is kept solely so that `TarnCore` can be unit-tested via `swift test` without launching Xcode. The TarnCore library has no system framework dependencies beyond Foundation, so it builds and tests cleanly under SPM. The Xcode targets `tarn`, `TarnSupervisor`, and `Tarn` reference the same source files but are built with their respective bundle product types.

This dual-build is a small maintenance cost (file lists in two places, kept in sync by `git diff`) but a meaningful productivity gain: most of the value of TarnCore is in fast iterative testing of the policy logic, and dropping into Xcode for every change to a profile rule would be a drag.

### Entitlements

**Tarn.app** (`TarnApp.entitlements`):

```xml
<key>com.apple.developer.system-extension.install</key><true/>
```

**TarnSupervisor** (`TarnSupervisor.entitlements`):

```xml
<key>com.apple.developer.endpoint-security.client</key><true/>
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

### XPC interface

The CLI and the supervisor communicate via XPC, the macOS-native interprocess RPC mechanism. The interface is defined as a Swift protocol in `TarnCore/XPCInterface.swift` and conformed to on the supervisor side. Method signatures (sketch, will be refined in implementation):

```swift
@objc public protocol TarnSupervisorXPC {
    func startSession(repoPath: String,
                       agent: String,
                       stacks: [String],
                       reply: @escaping (UUID?, Error?) -> Void)
    func endSession(_ id: UUID, reply: @escaping () -> Void)
    func registerAgentRoot(session: UUID, pid: pid_t, reply: @escaping () -> Void)

    // Push: supervisor → CLI for interactive prompts
    func handlePromptRequest(_ request: PromptRequestData,
                              reply: @escaping (PromptResponseData) -> Void)
}
```

Prompts flow from supervisor to CLI (the supervisor pauses the flow or holds the file open, sends an XPC request to the CLI's prompt handler, waits for the response, then resumes/responds). The CLI also calls into the supervisor to start and end sessions.

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
- Uninstall is the reverse: deactivate the system extension via `systemextensionsctl uninstall`, delete `Tarn.app`, remove the symlink, optionally remove `~/Library/Application Support/tarn/`.
