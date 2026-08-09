// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "HermternalSwiftParity",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(
            name: "HermternalSwiftParity",
            targets: ["HermternalSwiftParity"]
        ),
        .executable(
            name: "hermternal-swift-parity",
            targets: ["HermternalSwiftParityCLI"]
        ),
    ],
    targets: [
        .target(name: "HermternalSwiftParity"),
        .executableTarget(
            name: "HermternalSwiftParityCLI",
            dependencies: ["HermternalSwiftParity"]
        ),
        .testTarget(
            name: "HermternalSwiftParityTests",
            dependencies: ["HermternalSwiftParity"]
        ),
    ]
)
