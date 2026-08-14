import Foundation
import XCTest
@testable import AppleBenchmarkHarness

private final class TestClock: @unchecked Sendable {
    private var value: UInt64 = 0

    func next() -> UInt64 {
        value += 1_000_000
        return value
    }
}

final class AppleBenchmarkHarnessTests: XCTestCase {
    func testPinnedWorkloadLoadsAndHasExpectedOperations() throws {
        let loaded = try WorkloadFixtureLoader.load()

        XCTAssertEqual(loaded.fixture.schema, AppleWorkloadFixture.schema)
        XCTAssertEqual(loaded.fixture.seed, AppleWorkloadFixture.requiredSeed)
        XCTAssertEqual(loaded.fixture.operations.map(\.id), [
            "launch-setup-state",
            "streaming-batch-reduction",
            "transcript-diff-scroll",
            "scene-restoration-serialization",
            "dynamic-type-layout",
        ])
        XCTAssertEqual(
            BenchmarkHash.sha256(loaded.bytes),
            WorkloadFixtureLoader.expectedWorkloadSHA256
        )
    }

    func testWorkloadFixtureRejectsByteDriftAndUnknownKeys() throws {
        let loaded = try WorkloadFixtureLoader.load()
        var drifted = loaded.bytes
        drifted.append(0x20)
        XCTAssertThrowsError(try WorkloadFixtureLoader.load(from: drifted)) { error in
            XCTAssertEqual(error as? AppleBenchmarkError, .workloadDrift)
        }

        let unknownKey = Data("{\"schema\":\"hermternal.apple-benchmark-fixture.v1\",\"unknown\":true}".utf8)
        XCTAssertThrowsError(try BenchmarkJSON.decode(AppleWorkloadFixture.self, from: unknownKey))
    }

    func testDistributionUsesSharedR7Method() {
        let samples = (1...30).map(Double.init)
        let distribution = DistributionCalculator.calculate(samples)

        XCTAssertEqual(distribution.min, 1.0)
        XCTAssertEqual(distribution.p50, 15.5)
        XCTAssertEqual(distribution.p95, 28.55)
        XCTAssertEqual(distribution.p99, 29.71)
        XCTAssertEqual(distribution.max, 30.0)
        XCTAssertEqual(distribution.mean, 15.5)
    }

    func testSeededFixtureGeneratorIsRepeatable() {
        var first = SeededFixtureGenerator(seed: AppleWorkloadFixture.requiredSeed)
        var second = SeededFixtureGenerator(seed: AppleWorkloadFixture.requiredSeed)

        XCTAssertEqual(first.nextUInt64(), second.nextUInt64())
        XCTAssertEqual(first.nextInt(upperBound: 1000), second.nextInt(upperBound: 1000))
        XCTAssertEqual(first.nextText(length: 48), second.nextText(length: 48))
    }

    func testOnoneBuildNeverClaimsRelease() {
        if _isDebugAssertConfiguration() {
            XCTAssertEqual(ReleaseBuildMetadataFactory.current().mode, "debug")
            XCTAssertNotEqual(ReleaseBuildMetadataFactory.current().optimization, "swiftc -O")
        }
    }

    func testRunnerProducesAllColdAndWarmOperationLanes() throws {
        let loaded = try WorkloadFixtureLoader.load()
        let clock = TestClock()
        let runner = AppleBenchmarkRunner(enforceReleaseConfiguration: false, now: { clock.next() })
        let build = ReleaseBuildMetadata(
            mode: "release",
            optimization: "swiftc -O",
            compiler: "swiftc",
            sdk: "not_recorded",
            target: "apple-synthetic",
            metadataStatus: "scaffold_only"
        )

        let result = try runner.run(
            workload: loaded.fixture,
            workloadBytes: loaded.bytes,
            sourceCommitSHA: String(repeating: "a", count: 40),
            build: build
        )

        XCTAssertEqual(result.evidence.runs.count, 30)
        XCTAssertEqual(result.trace.runs.count, 30)
        XCTAssertEqual(result.evidence.runs.count, loaded.fixture.operations.count * 3 * 2)
        XCTAssertTrue(result.evidence.runs.allSatisfy { $0.repetitions == 30 })
        XCTAssertTrue(result.evidence.runs.allSatisfy { $0.rawSamples.allSatisfy { $0 > 0 } })
        XCTAssertTrue(result.evidence.runs.allSatisfy { $0.distribution == DistributionCalculator.calculate($0.rawSamples) })
        XCTAssertTrue(result.evidence.runs.allSatisfy { $0.environment.device == "not_claimed" })
        XCTAssertNil(result.evidence.threshold)
        XCTAssertNil(result.evidence.budget)
    }

    func testRunnerFailsClosedForNonMonotonicClockAndDebugBuild() throws {
        let loaded = try WorkloadFixtureLoader.load()
        let debugBuild = ReleaseBuildMetadata(
            mode: "debug",
            optimization: "debug",
            compiler: "swiftc",
            sdk: "not_recorded",
            target: "apple-synthetic",
            metadataStatus: "scaffold_only"
        )
        let runner = AppleBenchmarkRunner(enforceReleaseConfiguration: false, now: { 1 })

        XCTAssertThrowsError(
            try runner.run(
                workload: loaded.fixture,
                workloadBytes: loaded.bytes,
                sourceCommitSHA: String(repeating: "b", count: 40),
                build: debugBuild
            )
        ) { error in
            XCTAssertEqual(error as? AppleBenchmarkError, .releaseBuildRequired)
        }

        let releaseBuild = ReleaseBuildMetadata(
            mode: "release",
            optimization: "swiftc -O",
            compiler: "swiftc",
            sdk: "not_recorded",
            target: "apple-synthetic",
            metadataStatus: "scaffold_only"
        )
        XCTAssertThrowsError(
            try runner.run(
                workload: loaded.fixture,
                workloadBytes: loaded.bytes,
                sourceCommitSHA: String(repeating: "c", count: 40),
                build: releaseBuild
            )
        ) { error in
            XCTAssertEqual(error as? AppleBenchmarkError, .clockNotMonotonic)
        }
    }

    func testEvidenceRejectsDistributionAndRedactionDrift() throws {
        let loaded = try WorkloadFixtureLoader.load()
        let clock = TestClock()
        let runner = AppleBenchmarkRunner(enforceReleaseConfiguration: false, now: { clock.next() })
        let result = try runner.run(
            workload: loaded.fixture,
            workloadBytes: loaded.bytes,
            sourceCommitSHA: "not_collected",
            build: ReleaseBuildMetadata(
                mode: "release",
                optimization: "swiftc -O",
                compiler: "swiftc",
                sdk: "not_recorded",
                target: "apple-synthetic",
                metadataStatus: "scaffold_only"
            )
        )

        var changedRuns = result.evidence.runs
        let first = changedRuns[0]
        changedRuns[0] = EvidenceRun(
            id: first.id,
            operationID: first.operationID,
            platform: first.platform,
            environment: first.environment,
            state: first.state,
            buildMode: first.buildMode,
            optimization: first.optimization,
            command: first.command,
            repetitions: first.repetitions,
            rawSamples: first.rawSamples,
            sampleProvenanceSHA256: first.sampleProvenanceSHA256,
            distribution: Distribution(
                min: first.distribution.min,
                p50: first.distribution.p50 + 1,
                p95: first.distribution.p95,
                p99: first.distribution.p99,
                max: first.distribution.max,
                mean: first.distribution.mean
            )
        )
        let distributionDrift = AppleEvidenceDocument(
            schema: result.evidence.schema,
            protocolSchema: result.evidence.protocolSchema,
            evidenceID: result.evidence.evidenceID,
            revision: result.evidence.revision,
            metric: result.evidence.metric,
            method: result.evidence.method,
            build: result.evidence.build,
            runs: changedRuns,
            artifacts: result.evidence.artifacts,
            artifactManifestSHA256: result.evidence.artifactManifestSHA256,
            redaction: result.evidence.redaction,
            threshold: result.evidence.threshold,
            budget: result.evidence.budget
        )
        XCTAssertThrowsError(
            try EvidenceValidator.validate(
                distributionDrift,
                workload: loaded.fixture,
                fixtureSHA256: BenchmarkHash.sha256(loaded.bytes)
            )
        )

        var provenanceDriftRuns = result.evidence.runs
        provenanceDriftRuns[0] = EvidenceRun(
            id: provenanceDriftRuns[0].id,
            operationID: provenanceDriftRuns[0].operationID,
            platform: provenanceDriftRuns[0].platform,
            environment: provenanceDriftRuns[0].environment,
            state: provenanceDriftRuns[0].state,
            buildMode: provenanceDriftRuns[0].buildMode,
            optimization: provenanceDriftRuns[0].optimization,
            command: provenanceDriftRuns[0].command,
            repetitions: provenanceDriftRuns[0].repetitions,
            rawSamples: provenanceDriftRuns[0].rawSamples,
            sampleProvenanceSHA256: String(repeating: "0", count: 64),
            distribution: provenanceDriftRuns[0].distribution
        )
        let provenanceDrift = AppleEvidenceDocument(
            schema: result.evidence.schema,
            protocolSchema: result.evidence.protocolSchema,
            evidenceID: result.evidence.evidenceID,
            revision: result.evidence.revision,
            metric: result.evidence.metric,
            method: result.evidence.method,
            build: result.evidence.build,
            runs: provenanceDriftRuns,
            artifacts: result.evidence.artifacts,
            artifactManifestSHA256: result.evidence.artifactManifestSHA256,
            redaction: result.evidence.redaction,
            threshold: result.evidence.threshold,
            budget: result.evidence.budget
        )
        XCTAssertThrowsError(
            try EvidenceValidator.validate(
                provenanceDrift,
                workload: loaded.fixture,
                fixtureSHA256: BenchmarkHash.sha256(loaded.bytes)
            )
        )

        let redactionDrift = AppleEvidenceDocument(
            schema: result.evidence.schema,
            protocolSchema: result.evidence.protocolSchema,
            evidenceID: result.evidence.evidenceID,
            revision: result.evidence.revision,
            metric: result.evidence.metric,
            method: result.evidence.method,
            build: result.evidence.build,
            runs: result.evidence.runs,
            artifacts: result.evidence.artifacts,
            artifactManifestSHA256: result.evidence.artifactManifestSHA256,
            redaction: RedactionMetadata(
                policy: "semantic_only",
                syntheticOnly: true,
                containsCredentials: true,
                containsTokens: false,
                containsUserData: false,
                containsLiveHosts: false,
                containsTranscripts: false
            ),
            threshold: result.evidence.threshold,
            budget: result.evidence.budget
        )
        XCTAssertThrowsError(
            try EvidenceValidator.validate(
                redactionDrift,
                workload: loaded.fixture,
                fixtureSHA256: BenchmarkHash.sha256(loaded.bytes)
            )
        )
    }

    func testEvidenceRejectsForgedArtifactMetadata() throws {
        let loaded = try WorkloadFixtureLoader.load()
        let clock = TestClock()
        let result = try AppleBenchmarkRunner(enforceReleaseConfiguration: false, now: { clock.next() }).run(
            workload: loaded.fixture,
            workloadBytes: loaded.bytes,
            sourceCommitSHA: "not_collected",
            build: ReleaseBuildMetadata(
                mode: "release",
                optimization: "swiftc -O",
                compiler: "swiftc",
                sdk: "not_recorded",
                target: "apple-synthetic",
                metadataStatus: "scaffold_only"
            )
        )

        let first = result.evidence.artifacts[0]
        let forgedArtifacts: [[ArtifactMetadata]] = [
            [
                ArtifactMetadata(path: "../fixture/workload.json", bytes: first.bytes, sha256: first.sha256),
                result.evidence.artifacts[1],
            ],
            [
                ArtifactMetadata(path: "fixture\\\\workload.json", bytes: first.bytes, sha256: first.sha256),
                result.evidence.artifacts[1],
            ],
            [
                ArtifactMetadata(path: first.path, bytes: -1, sha256: first.sha256),
                result.evidence.artifacts[1],
            ],
            [first, first],
        ]

        for artifacts in forgedArtifacts {
            let forged = AppleEvidenceDocument(
                schema: result.evidence.schema,
                protocolSchema: result.evidence.protocolSchema,
                evidenceID: result.evidence.evidenceID,
                revision: result.evidence.revision,
                metric: result.evidence.metric,
                method: result.evidence.method,
                build: result.evidence.build,
                runs: result.evidence.runs,
                artifacts: artifacts,
                artifactManifestSHA256: EvidenceValidator.artifactManifestDigest(artifacts),
                redaction: result.evidence.redaction,
                threshold: result.evidence.threshold,
                budget: result.evidence.budget
            )
            XCTAssertThrowsError(
                try EvidenceValidator.validate(
                    forged,
                    workload: loaded.fixture,
                    fixtureSHA256: BenchmarkHash.sha256(loaded.bytes)
                )
            )
        }
    }

    func testEvidenceRoundTripsWithClosedSchema() throws {
        let loaded = try WorkloadFixtureLoader.load()
        let clock = TestClock()
        let result = try AppleBenchmarkRunner(enforceReleaseConfiguration: false, now: { clock.next() }).run(
            workload: loaded.fixture,
            workloadBytes: loaded.bytes,
            sourceCommitSHA: "not_collected",
            build: ReleaseBuildMetadata(
                mode: "release",
                optimization: "swiftc -O",
                compiler: "swiftc",
                sdk: "not_recorded",
                target: "apple-synthetic",
                metadataStatus: "scaffold_only"
            )
        )
        let data = try BenchmarkJSON.encode(result.evidence)
        let decoded = try BenchmarkJSON.decode(AppleEvidenceDocument.self, from: data)
        XCTAssertEqual(decoded, result.evidence)
    }
}
