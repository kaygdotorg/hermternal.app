import Foundation
import XCTest
#if canImport(Darwin)
import Darwin
#endif
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
        let report = try runParityForTests(at: repoRoot)

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

    func testC19BlockedPreflightCannotProduceParityEvidence() throws {
        let report = try runParity(at: repoRoot)
        XCTAssertFalse(report.ok)
        XCTAssertEqual(report.status, "blocked")
        XCTAssertEqual(report.errorCode, "c19_validator_blocked")
        XCTAssertEqual(report.readyCaseCount, 0)
        XCTAssertTrue(report.cases.isEmpty)
        XCTAssertFalse(report.liveClaim)
    }

    func testPublicParityAPIOwnsC19Preflight() throws {
        let sourceURL = packageRoot
            .appendingPathComponent("Sources", isDirectory: true)
            .appendingPathComponent("HermternalSwiftParity", isDirectory: true)
            .appendingPathComponent("Parity.swift")
        let source = try String(contentsOf: sourceURL, encoding: .utf8)
        XCTAssertFalse(source.contains("public enum C19PreflightMode"))
        XCTAssertFalse(source.contains("public enum C19ValidatorStatus"))
        XCTAssertFalse(source.contains("public func runParity(\n    at repoRoot: URL,\n    preflight:"))
        XCTAssertTrue(source.contains("public func runParity(at repoRoot: URL)"))
        XCTAssertTrue(source.contains("switch runC19Preflight(at: repoRoot)"))
    }

    func testNeutralCoverageStatusesAndPendingValidatorAreRepresentable() throws {
        for status in ["pending", "empty", "failure", "cancelled", "unknown"] {
            try withMutatedIndex({ index in
                var coverage = try XCTUnwrap(index["coverage"] as? [[String: Any]])
                coverage[0]["status"] = status
                coverage[0]["fixture_ids"] = []
                index["coverage"] = coverage
            }) { temporaryRoot in
                let registry = try loadRegistry(at: temporaryRoot)
                XCTAssertEqual(registry.coverage[0].status.rawValue, status)
                XCTAssertTrue(registry.coverage[0].fixtureIDs.isEmpty)
            }
        }

        try withMutatedIndex({ index in
            var roots = try fixtureRoots(from: index)
            roots[0]["status"] = "pending"
            roots[0]["validator"] = NSNull()
            roots[0]["files"] = []
            index["fixture_roots"] = roots

            var coverage = try XCTUnwrap(index["coverage"] as? [[String: Any]])
            for position in coverage.indices {
                let fixtureIDs = (coverage[position]["fixture_ids"] as? [String]) ?? []
                if fixtureIDs.contains("attachment-policy") {
                    coverage[position]["status"] = "pending"
                    coverage[position]["fixture_ids"] = []
                }
            }
            index["coverage"] = coverage
        }) { temporaryRoot in
            let registry = try loadRegistry(at: temporaryRoot)
            XCTAssertNil(registry.fixtureRoots[0].validator)
            XCTAssertEqual(registry.fixtureRoots[0].status, .pending)
        }
    }

    func testWebAndAppleProjectionsDetectIndependentSemanticDivergence() throws {
        let registry = try loadRegistry(at: repoRoot)
        let fixtureCase = try loadCase(
            at: repoRoot,
            registry: registry,
            rootID: "deployment-security-browser-auth",
            caseID: "login-success"
        )
        let web = try project(family: .auth, platform: .web, fixtureCase: fixtureCase)
        let apple = try project(family: .auth, platform: .ios, fixtureCase: fixtureCase)
        XCTAssertEqual(web.decision, "authenticated")
        XCTAssertEqual(apple.decision, "authenticated")
        XCTAssertEqual(web.semantic, apple.semantic)

        var mutatedExpected = fixtureCase.expected
        mutatedExpected["state"] = .string("blocked")
        let mutatedCase = FixtureCase(
            id: fixtureCase.id,
            expected: mutatedExpected,
            raw: fixtureCase.raw
        )
        let mutatedWeb = try project(family: .auth, platform: .web, fixtureCase: mutatedCase)
        let mutatedApple = try project(family: .auth, platform: .ios, fixtureCase: mutatedCase)
        XCTAssertEqual(mutatedWeb.decision, "authenticated")
        XCTAssertEqual(mutatedApple.decision, "blocked")
        XCTAssertNotEqual(mutatedWeb.semantic, mutatedApple.semantic)
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

    #if os(macOS)
    func testHeldParentDescriptorSurvivesParentPathReplacement() throws {
        let temporaryRoot = try makeTemporaryFixtureRepository()
        defer { try? FileManager.default.removeItem(at: temporaryRoot) }
        let registry = try loadRegistry(at: temporaryRoot)
        let artifactURL = temporaryRoot
            .appendingPathComponent("contracts", isDirectory: true)
            .appendingPathComponent("fixtures", isDirectory: true)
            .appendingPathComponent("deployment-security", isDirectory: true)
            .appendingPathComponent("browser-auth", isDirectory: true)
            .appendingPathComponent("cases.json")
        let parentURL = artifactURL.deletingLastPathComponent()
        let renamedParentURL = parentURL
            .deletingLastPathComponent()
            .appendingPathComponent("browser-auth-held-\(UUID().uuidString)", isDirectory: true)

        let fixtureCase = try loadCaseForTests(
            at: temporaryRoot,
            registry: registry,
            rootID: "deployment-security-browser-auth",
            caseID: "login-success"
        ) {
            try FileManager.default.moveItem(at: parentURL, to: renamedParentURL)
            try FileManager.default.createDirectory(at: parentURL, withIntermediateDirectories: true)
            try Data("{\"cases\":[]}".utf8).write(
                to: parentURL.appendingPathComponent("cases.json"),
                options: .atomic
            )
        }
        XCTAssertEqual(fixtureCase.id, "login-success")
    }

    func testHeldParentDescriptorRejectsLeafReplacement() throws {
        let temporaryRoot = try makeTemporaryFixtureRepository()
        defer { try? FileManager.default.removeItem(at: temporaryRoot) }
        let registry = try loadRegistry(at: temporaryRoot)
        let artifactURL = temporaryRoot
            .appendingPathComponent("contracts", isDirectory: true)
            .appendingPathComponent("fixtures", isDirectory: true)
            .appendingPathComponent("deployment-security", isDirectory: true)
            .appendingPathComponent("browser-auth", isDirectory: true)
            .appendingPathComponent("cases.json")
        let displacedURL = artifactURL
            .deletingLastPathComponent()
            .appendingPathComponent("cases-original-\(UUID().uuidString).json")

        assertInputCode(.artifactIntegrity) {
            _ = try loadCaseForTests(
                at: temporaryRoot,
                registry: registry,
                rootID: "deployment-security-browser-auth",
                caseID: "login-success"
            ) {
                try FileManager.default.moveItem(at: artifactURL, to: displacedURL)
                try FileManager.default.copyItem(at: displacedURL, to: artifactURL)
            }
        }
    }

    func testRegistryFIFOSubprocessFailsClosedWithoutHanging() throws {
        let temporaryRoot = try makeTemporaryCLIRepository()
        defer { try? FileManager.default.removeItem(at: temporaryRoot) }
        try installPassingValidator(at: temporaryRoot)
        let indexURL = temporaryRoot
            .appendingPathComponent("contracts", isDirectory: true)
            .appendingPathComponent("fixtures", isDirectory: true)
            .appendingPathComponent("index.json")
        try FileManager.default.removeItem(at: indexURL)
        try makeFIFO(at: indexURL)

        let result = try runCLI(at: temporaryRoot, timeout: 2)
        XCTAssertFalse(result.timedOut)
        XCTAssertEqual(result.status, 1)
        XCTAssertTrue(result.stdout.isEmpty)
        XCTAssertTrue(result.stderr.contains("artifact_integrity"))
    }

    func testArtifactFIFOSubprocessFailsClosedWithoutHanging() throws {
        let temporaryRoot = try makeTemporaryCLIRepository()
        defer { try? FileManager.default.removeItem(at: temporaryRoot) }
        try installPassingValidator(at: temporaryRoot)
        let artifactURL = temporaryRoot
            .appendingPathComponent("contracts", isDirectory: true)
            .appendingPathComponent("fixtures", isDirectory: true)
            .appendingPathComponent("deployment-security", isDirectory: true)
            .appendingPathComponent("browser-auth", isDirectory: true)
            .appendingPathComponent("cases.json")
        try FileManager.default.removeItem(at: artifactURL)
        try makeFIFO(at: artifactURL)

        let result = try runCLI(at: temporaryRoot, timeout: 2)
        XCTAssertFalse(result.timedOut)
        XCTAssertEqual(result.status, 1)
        XCTAssertTrue(result.stdout.isEmpty)
        XCTAssertTrue(result.stderr.contains("artifact_integrity"))
    }

    #endif

    func testStrictJSONRejectsDuplicateKeysAndBoundsErrors() throws {
        try withTemporaryIndex(Data("{\"schema\":\"hermternal.fixture-index.v1\",\"schema\":\"hermternal.fixture-index.v1\"}".utf8)) { temporaryRoot in
            assertInputCode(.malformedJSON) {
                _ = try loadRegistry(at: temporaryRoot)
            }
        }

        let oversizedMessage = String(repeating: "x", count: ParityBounds.maxErrorMessageLength * 4)
        let error = ContractInputError(code: .malformedInput, message: oversizedMessage)
        XCTAssertLessThanOrEqual(error.message.count, ParityBounds.maxErrorMessageLength)

        let oversized = Data(("{\"value\":\"" + String(repeating: "x", count: ParityBounds.maxJSONStringLength + 1) + "\"}").utf8)
        try withTemporaryIndex(oversized) { temporaryRoot in
            assertInputCode(.malformedJSON) {
                _ = try loadRegistry(at: temporaryRoot)
            }
        }

        var nested = "0"
        for _ in 0..<(ParityBounds.maxJSONDepth + 2) { nested = "[" + nested + "]" }
        try withTemporaryIndex(Data(("{\"value\":\(nested)}").utf8)) { temporaryRoot in
            assertInputCode(.malformedInput) {
                _ = try loadRegistry(at: temporaryRoot)
            }
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

    func testParityReportOrderingIsCanonical() throws {
        let report = try runParityForTests(at: repoRoot)
        XCTAssertEqual(report.blockedCoverageIDs, report.blockedCoverageIDs.sorted())
        let caseKeys = report.cases.map { "\($0.family.rawValue)|\($0.coverageID)|\($0.caseID)" }
        XCTAssertEqual(caseKeys, caseKeys.sorted())
        for result in report.cases {
            XCTAssertEqual(result.platforms.map(\.rawValue), result.platforms.map(\.rawValue).sorted())
        }
    }

#if os(macOS)
    func testCLIBlockedStatusIsNonzeroAndOutputIsStable() throws {
        let first = try runCLI(at: repoRoot)
        let second = try runCLI(at: repoRoot)
        XCTAssertFalse(first.timedOut)
        XCTAssertFalse(second.timedOut)
        XCTAssertEqual(first.status, 1)
        XCTAssertEqual(second.status, 1)
        XCTAssertEqual(first.stdout, second.stdout)
        XCTAssertTrue(first.stderr.isEmpty)
        XCTAssertLessThanOrEqual(Data(first.stdout.utf8).count, ParityBounds.maxOutputBytes)
        let value = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(first.stdout.utf8), options: []) as? [String: Any])
        XCTAssertEqual(value["ok"] as? Bool, false)
        XCTAssertEqual(value["status"] as? String, "blocked")
        XCTAssertEqual(value["errorCode"] as? String, "c19_validator_blocked")
        XCTAssertEqual(value["readyCaseCount"] as? Int, 0)
        XCTAssertEqual(value["liveClaim"] as? Bool, false)
    }

    private func runCLI(
        at root: URL,
        timeout: TimeInterval = 5
    ) throws -> (status: Int32, stdout: String, stderr: String, timedOut: Bool) {
        let candidates = [
            packageRoot.appendingPathComponent(".build/debug/hermternal-swift-parity"),
            packageRoot.appendingPathComponent(".build/release/hermternal-swift-parity")
        ]
        guard let executable = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0.path) }) else {
            throw XCTSkip("HermternalSwiftParityCLI executable is not built")
        }
        let process = Process()
        process.executableURL = executable
        process.arguments = ["--repo-root", root.path]
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()

        let finished = DispatchSemaphore(value: 0)
        DispatchQueue.global(qos: .utility).async {
            process.waitUntilExit()
            finished.signal()
        }
        let timedOut = finished.wait(timeout: .now() + timeout) == .timedOut
        if timedOut {
            process.terminate()
            if process.isRunning {
                kill(process.processIdentifier, SIGKILL)
            }
            process.waitUntilExit()
        }
        return (
            process.terminationStatus,
            String(decoding: stdout.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self),
            String(decoding: stderr.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self),
            timedOut
        )
    }
#endif

    #if os(macOS)
    private func makeTemporaryRoot() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("hermternal-swift-c21-descriptor-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }

    private func makeFixturesDirectory(at root: URL) throws -> URL {
        let fixturesURL = root
            .appendingPathComponent("contracts", isDirectory: true)
            .appendingPathComponent("fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: fixturesURL, withIntermediateDirectories: true)
        return fixturesURL
    }

    private func makeTemporaryFixtureRepository(copyArtifact: Bool = true) throws -> URL {
        let root = try makeTemporaryRoot()
        let fixturesURL = try makeFixturesDirectory(at: root)
        try FileManager.default.copyItem(
            at: repoRoot.appendingPathComponent("contracts/fixtures/index.json"),
            to: fixturesURL.appendingPathComponent("index.json")
        )

        let artifactURL = fixturesURL
            .appendingPathComponent("deployment-security", isDirectory: true)
            .appendingPathComponent("browser-auth", isDirectory: true)
        try FileManager.default.createDirectory(at: artifactURL, withIntermediateDirectories: true)
        if copyArtifact {
            try FileManager.default.copyItem(
                at: repoRoot.appendingPathComponent("contracts/fixtures/deployment-security/browser-auth/cases.json"),
                to: artifactURL.appendingPathComponent("cases.json")
            )
        }
        return root
    }

    private func makeTemporaryCLIRepository() throws -> URL {
        let root = try makeTemporaryRoot()
        let contractsURL = root.appendingPathComponent("contracts", isDirectory: true)
        try FileManager.default.createDirectory(at: contractsURL, withIntermediateDirectories: true)
        try FileManager.default.copyItem(
            at: repoRoot.appendingPathComponent("contracts/fixtures", isDirectory: true),
            to: contractsURL.appendingPathComponent("fixtures", isDirectory: true)
        )
        return root
    }

    private func installPassingValidator(at root: URL) throws {
        let validatorURL = root
            .appendingPathComponent("contracts", isDirectory: true)
            .appendingPathComponent("fixtures", isDirectory: true)
            .appendingPathComponent("validator", isDirectory: true)
            .appendingPathComponent("validate.py")
        let source = """
        import json
        print(json.dumps({"ok": True, "evidence_status": "ready", "live_claim": False}))
        """
        try Data(source.utf8).write(to: validatorURL, options: .atomic)
    }

    private func makeFIFO(at url: URL) throws {
        guard Darwin.mkfifo(url.path, mode_t(S_IRUSR | S_IWUSR)) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
    }

    #endif

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
