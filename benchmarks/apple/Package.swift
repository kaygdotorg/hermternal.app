// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AppleBenchmarkHarness",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(
            name: "AppleBenchmarkHarness",
            targets: ["AppleBenchmarkHarness"]
        ),
        .executable(
            name: "apple-benchmark",
            targets: ["apple-benchmark"]
        ),
    ],
    targets: [
        .target(
            name: "AppleBenchmarkHarness",
            resources: [
                .process("Resources"),
            ]
        ),
        .executableTarget(
            name: "apple-benchmark",
            dependencies: ["AppleBenchmarkHarness"]
        ),
        .testTarget(
            name: "AppleBenchmarkHarnessTests",
            dependencies: ["AppleBenchmarkHarness"]
        ),
    ]
)
