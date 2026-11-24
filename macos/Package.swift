// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "ClaudeGuard",
    platforms: [.macOS(.v13)],
    targets: [
        // Shared model, IP/country checker, notification names, paths.
        .target(name: "ClaudeGuardCore"),
        // Root LaunchDaemon + CLI (daemon / check / status / refresh / hook / cleanup).
        .executableTarget(name: "claudeguardd", dependencies: ["ClaudeGuardCore"]),
        // Menu bar app (status, Refresh button, "you're in Iran" window).
        .executableTarget(name: "ClaudeGuard", dependencies: ["ClaudeGuardCore"]),
    ]
)
