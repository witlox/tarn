// swift-tools-version: 5.10

import PackageDescription

let package = Package(
    name: "Tarn",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(name: "TarnCore", targets: ["TarnCore"]),
        .executable(name: "tarn", targets: ["TarnCLI"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.3.0"),
    ],
    targets: [
        // Shared policy library: profiles, config, process tree, session
        // cache, errors, lock, XPC interface protocol. No system framework
        // dependencies beyond Foundation — builds and tests on any machine.
        .target(
            name: "TarnCore",
            path: "Sources/TarnCore"
        ),

        // Unprivileged CLI: argument parsing, agent launch, prompt UI,
        // XPC client to the supervisor.
        .executableTarget(
            name: "TarnCLI",
            dependencies: [
                "TarnCore",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            path: "Sources/TarnCLI"
        ),

        // Unit tests against TarnCore. Run via `swift test`.
        .testTarget(
            name: "TarnCoreTests",
            dependencies: ["TarnCore"],
            path: "Tests/TarnCoreTests"
        ),

        // NOTE: TarnSupervisor and TarnApp targets are NOT included in
        // the SPM manifest. They require restricted Apple frameworks
        // (EndpointSecurity, NetworkExtension, SystemExtensions) that
        // are only available through xcodebuild with the full macOS SDK.
        // These targets are defined in the Xcode project (Tarn.xcodeproj)
        // and reference the same source files under Sources/TarnSupervisor/
        // and Sources/TarnApp/. See ADR-004 for the full build story.
    ]
)
