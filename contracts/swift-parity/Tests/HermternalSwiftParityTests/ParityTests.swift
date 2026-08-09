import Foundation
import XCTest
@testable import HermternalSwiftParity

final class ParityTests: XCTestCase {
    private let packageRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()

    private var repoRoot: URL {
        packageRoot
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    func testRunParityProvesRepresentativeOfflineSurface() throws {
        let report = try runParity(at: repoRoot)

        XCTAssertTrue(report.ok)
        XCTAssertEqual(report.contract, dashboardContract)
        XCTAssertEqual(report.hermesSourceSHA, hermesSourceSHA)
        XCTAssertTrue(report.syntheticOnly)
        XCTAssertFalse(report.liveClaim)
        XCTAssertEqual(report.networkCalls, 0)
        XCTAssertEqual(report.readyCaseCount, 11)
        XCTAssertEqual(report.cases.count, 17)
        XCTAssertTrue(report.blockedCoverageIDs.contains("chat-stream-and-completion"))
        XCTAssertTrue(report.blockedCoverageIDs.contains("connection-restoration"))
        XCTAssertFalse(report.compatibility.compatible)
        XCTAssertFalse(report.compatibility.liveRun)

        let families = Set(report.cases.map { $0.family.rawValue })
        XCTAssertEqual(
            families,
            Set(["auth", "connection", "session", "chat", "image", "pty", "deep-link", "compatibility"])
        )
        XCTAssertTrue(
            report.cases
                .filter { $0.family == .chat }
                .allSatisfy { $0.status == "blocked" && $0.webDecision == nil && $0.appleDecision == nil }
        )
        XCTAssertTrue(
            report.cases
                .filter { $0.family == .pty }
                .allSatisfy { $0.status == "proven" && $0.appleDecision == "blocked_platform" }
        )
    }

    func testRejectsUnknownFixtureCaseAndNonCanonicalCaseID() throws {
        let registry = try loadRegistry(at: repoRoot)

        assertInputCode(.unknownFixture) {
            _ = try loadCase(
                at: repoRoot,
                registry: registry,
                rootID: "not-a-fixture",
                caseID: "login-success"
            )
        }
        assertInputCode(.unknownCase) {
            _ = try loadCase(
                at: repoRoot,
                registry: registry,
                rootID: "deployment-security-browser-auth",
                caseID: "not-a-case"
            )
        }
        assertInputCode(.malformedInput) {
            _ = try loadCase(
                at: repoRoot,
                registry: registry,
                rootID: "deployment-security-browser-auth",
                caseID: " login-success"
            )
        }
    }

    func testDescriptorReadsRejectSymlinkFallbackAndBindArtifactIdentity() throws {
        let temporaryRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("hermternal-swift-c21-descriptor-\(UUID().uuidString)", isDirectory: true)
        let fixturesURL = temporaryRoot
            .appendingPathComponent("contracts", isDirectory: true)
            .appendingPathComponent("fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: fixturesURL, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: temporaryRoot) }

        try FileManager.default.createSymbolicLink(
            atPath: fixturesURL.appendingPathComponent("index.json").path,
            withDestinationPath: repoRoot.appendingPathComponent("contracts/fixtures/index.json").path
        )
        assertInputCode(.missingArtifact) {
            _ = try loadRegistry(at: temporaryRoot)
        }

        try FileManager.default.removeItem(at: fixturesURL.appendingPathComponent("index.json"))
        try FileManager.default.copyItem(
            at: repoRoot.appendingPathComponent("contracts/fixtures/index.json"),
            to: fixturesURL.appendingPathComponent("index.json")
        )
        let artifactURL = fixturesURL.appendingPathComponent(
            "deployment-security/browser-auth/cases.json"
        )
        try FileManager.default.createDirectory(
            at: artifactURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        var artifactData = try Data(contentsOf: repoRoot.appendingPathComponent(
            "contracts/fixtures/deployment-security/browser-auth/cases.json"
        ))
        artifactData[artifactData.startIndex] = artifactData[artifactData.startIndex] == 0x7B ? 0x5B : 0x7B
        try artifactData.write(to: artifactURL)
        let registry = try loadRegistry(at: temporaryRoot)
        assertInputCode(.artifactIntegrity) {
            _ = try loadCase(
                at: temporaryRoot,
                registry: registry,
                rootID: "deployment-security-browser-auth",
                caseID: "login-success"
            )
        }
    }

    func testRejectsMalformedIncompatibleAndUnsupportedRegistryInputs() throws {
        try withTemporaryIndex(Data("{\n".utf8)) { temporaryRoot in
            assertInputCode(.malformedJSON) {
                _ = try loadRegistry(at: temporaryRoot)
            }
        }

        try withMutatedIndex({ index in
            index["schema"] = "unknown.schema"
        }) { temporaryRoot in
            assertInputCode(.incompatibleInput) {
                _ = try loadRegistry(at: temporaryRoot)
            }
        }

        try withMutatedIndex({ index in
            var roots = try fixtureRoots(from: index)
            roots[0]["platforms"] = ["android"]
            index["fixture_roots"] = roots
        }) { temporaryRoot in
            assertInputCode(.unknownPlatform) {
                _ = try loadRegistry(at: temporaryRoot)
            }
        }

        try withMutatedIndex({ index in
            var roots = try fixtureRoots(from: index)
            roots[0]["path"] = "../outside"
            index["fixture_roots"] = roots
        }) { temporaryRoot in
            assertInputCode(.unsafePath) {
                _ = try loadRegistry(at: temporaryRoot)
            }
        }

        try withMutatedIndex({ index in
            var roots = try fixtureRoots(from: index)
            roots[0]["status"] = "unsupported"
            index["fixture_roots"] = roots
        }) { temporaryRoot in
            assertInputCode(.unknownStatus) {
                _ = try loadRegistry(at: temporaryRoot)
            }
        }
    }

    func testRejectsUnindexedRepresentativeArtifactBeforeReadingIt() throws {
        try withMutatedIndex({ index in
            var roots = try fixtureRoots(from: index)
            guard let position = roots.firstIndex(where: {
                ($0["id"] as? String) == "deployment-security-browser-auth"
            }) else {
                XCTFail("fixture root is missing from the checked-in registry")
                return
            }
            roots[position]["files"] = []
            index["fixture_roots"] = roots
        }) { temporaryRoot in
            let registry = try loadRegistry(at: temporaryRoot)
            assertInputCode(.unregisteredArtifact) {
                _ = try loadCase(
                    at: temporaryRoot,
                    registry: registry,
                    rootID: "deployment-security-browser-auth",
                    caseID: "login-success"
                )
            }
        }
    }

    func testNoNetworkCapableImportsInParitySource() throws {
        let sourceURL = packageRoot
            .appendingPathComponent("Sources", isDirectory: true)
            .appendingPathComponent("HermternalSwiftParity", isDirectory: true)
            .appendingPathComponent("Parity.swift")
        let source = try String(contentsOf: sourceURL, encoding: .utf8)
        XCTAssertNoThrow(try assertNoNetworkImports(source))
        assertInputCode(.networkBoundary) {
            let networkSource = "import Net" + "work\\nlet request = URL" + "Request(url: url)"
            try assertNoNetworkImports(networkSource)
        }
    }

    private func assertInputCode(
        _ expected: ContractInputCode,
        operation: () throws -> Void,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        do {
            try operation()
            XCTFail("expected \(expected.rawValue)", file: file, line: line)
        } catch let error as ContractInputError {
            XCTAssertEqual(error.code, expected, file: file, line: line)
        } catch {
            XCTFail("unexpected error: \(error)", file: file, line: line)
        }
    }

    private func withTemporaryIndex(
        _ data: Data,
        body: (URL) throws -> Void
    ) throws {
        let temporaryRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("hermternal-swift-c21-\(UUID().uuidString)", isDirectory: true)
        let fixturesURL = temporaryRoot
            .appendingPathComponent("contracts", isDirectory: true)
            .appendingPathComponent("fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: fixturesURL, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: temporaryRoot) }
        try data.write(to: fixturesURL.appendingPathComponent("index.json"), options: .atomic)
        try body(temporaryRoot)
    }

    private func withMutatedIndex(
        _ mutate: (inout [String: Any]) throws -> Void,
        body: (URL) throws -> Void
    ) throws {
        let source = try Data(contentsOf: repoRoot
            .appendingPathComponent("contracts", isDirectory: true)
            .appendingPathComponent("fixtures", isDirectory: true)
            .appendingPathComponent("index.json"))
        var index = try XCTUnwrap(
            JSONSerialization.jsonObject(with: source, options: [.mutableContainers]) as? [String: Any]
        )
        try mutate(&index)
        let data = try JSONSerialization.data(withJSONObject: index, options: [.sortedKeys])
        try withTemporaryIndex(data, body: body)
    }

    private func fixtureRoots(from index: [String: Any]) throws -> [[String: Any]] {
        try XCTUnwrap(index["fixture_roots"] as? [[String: Any]])
    }
}
