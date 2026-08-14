import CryptoKit
import Foundation

public enum AppleBenchmarkError: Error, Equatable, Sendable {
    case workloadMalformed
    case workloadDrift
    case evidenceMalformed
    case evidenceDrift
    case sourceCommitMissing
    case releaseBuildRequired
    case clockNotMonotonic
    case insufficientSamples
    case outputWriteFailed
    case unsupportedArgument

    public var code: String {
        switch self {
        case .workloadMalformed: return "workload_malformed"
        case .workloadDrift: return "workload_drift"
        case .evidenceMalformed: return "evidence_malformed"
        case .evidenceDrift: return "evidence_drift"
        case .sourceCommitMissing: return "source_commit_missing"
        case .releaseBuildRequired: return "release_build_required"
        case .clockNotMonotonic: return "clock_not_monotonic"
        case .insufficientSamples: return "insufficient_samples"
        case .outputWriteFailed: return "output_write_failed"
        case .unsupportedArgument: return "unsupported_argument"
        }
    }
}

public enum BenchmarkJSON {
    public static func encode<T: Encodable>(_ value: T, pretty: Bool = true) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = pretty ? [.prettyPrinted, .sortedKeys] : [.sortedKeys]
        return try encoder.encode(value)
    }

    public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        try JSONDecoder().decode(type, from: data)
    }

    public static func canonicalData<T: Encodable>(_ value: T) throws -> Data {
        try encode(value, pretty: false)
    }
}

public enum BenchmarkHash {
    public static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

func isStrictLowerHexASCII(_ value: String, length: Int) -> Bool {
    let bytes = Array(value.utf8)
    guard bytes.count == length else {
        return false
    }
    return bytes.allSatisfy { byte in
        (byte >= 0x30 && byte <= 0x39) ||
        (byte >= 0x61 && byte <= 0x66)
    }
}

public enum WorkloadFixtureLoader {
    // This pins the bytes used by the scaffold. A changed fixture requires an
    // intentional review of the operation inventory, seed, and evidence shape.
    public static let expectedWorkloadSHA256 = "192b63346cf71e05f6955cfcdfcca398fbf85387c7adf3226fa61fdef59a907d"
    public static let expectedWorkloadByteCount = 1_308

    public static func load(from data: Data? = nil) throws -> (fixture: AppleWorkloadFixture, bytes: Data) {
        let bytes: Data
        if let data {
            bytes = data
        } else {
            guard let url = Bundle.module.url(forResource: "workload", withExtension: "json"),
                  let resource = try? Data(contentsOf: url)
            else {
                throw AppleBenchmarkError.workloadMalformed
            }
            bytes = resource
        }

        guard BenchmarkHash.sha256(bytes) == expectedWorkloadSHA256 else {
            throw AppleBenchmarkError.workloadDrift
        }
        guard let fixture = try? BenchmarkJSON.decode(AppleWorkloadFixture.self, from: bytes) else {
            throw AppleBenchmarkError.workloadMalformed
        }
        try WorkloadValidator.validate(fixture)
        return (fixture, bytes)
    }
}

public enum WorkloadValidator {
    public static func validate(_ fixture: AppleWorkloadFixture) throws {
        guard fixture.schema == AppleWorkloadFixture.schema,
              fixture.fixtureID == AppleWorkloadFixture.fixtureID,
              fixture.fixtureVersion == AppleWorkloadFixture.fixtureVersion,
              fixture.seed == AppleWorkloadFixture.requiredSeed,
              fixture.warmupRepetitions == 1,
              fixture.targetPlatforms == [.ios, .ipados, .macos],
              fixture.build.mode == "release",
              fixture.build.optimization == "swiftc -O",
              fixture.build.metadataStatus == "scaffold_only",
              fixture.repetitions.cold == AppleWorkloadFixture.minimumRepetitions,
              fixture.repetitions.warm == AppleWorkloadFixture.minimumRepetitions,
              fixture.repetitions.maximum >= fixture.repetitions.cold,
              fixture.repetitions.maximum >= fixture.repetitions.warm
        else {
            throw AppleBenchmarkError.workloadDrift
        }

        let expected: [WorkloadOperationSpec] = [
            .init(
                id: "launch-setup-state",
                kind: .launchSetupStateConstruction,
                itemCount: 96,
                batchSize: 1,
                textLength: 0
            ),
            .init(
                id: "streaming-batch-reduction",
                kind: .streamingBatchReduction,
                itemCount: 256,
                batchSize: 16,
                textLength: 32
            ),
            .init(
                id: "transcript-diff-scroll",
                kind: .transcriptDiffScrollModel,
                itemCount: 128,
                batchSize: 1,
                textLength: 48
            ),
            .init(
                id: "scene-restoration-serialization",
                kind: .sceneRestorationSerialization,
                itemCount: 32,
                batchSize: 1,
                textLength: 0
            ),
            .init(
                id: "dynamic-type-layout",
                kind: .dynamicTypeLayoutCalculation,
                itemCount: 192,
                batchSize: 1,
                textLength: 72
            ),
        ]
        guard fixture.operations == expected else {
            throw AppleBenchmarkError.workloadDrift
        }
    }
}

public enum EvidenceValidator {
    public static let pinnedHermesSourceSHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
    public static let maximumArtifactCount = 2
    public static let maximumArtifactBytes = 1_048_576
    public static let reviewedArtifactPaths = [
        "fixture/workload.json",
        "trace/raw-trace.json",
    ]

    public static func validate(
        _ evidence: AppleEvidenceDocument,
        workload: AppleWorkloadFixture,
        fixtureSHA256: String,
        workloadBytes: Data? = nil,
        traceBytes: Data? = nil
    ) throws {
        guard evidence.schema == AppleEvidenceDocument.schema,
              evidence.protocolSchema == AppleEvidenceDocument.protocolSchema,
              evidence.evidenceID == "apple-release-mock-workload",
              evidence.revision.fixtureID == workload.fixtureID,
              evidence.revision.fixtureVersion == workload.fixtureVersion,
              evidence.revision.fixtureSHA256 == fixtureSHA256,
              evidence.revision.hermesSourceSHA == pinnedHermesSourceSHA,
              evidence.metric.name == "operation_duration",
              evidence.metric.unit == "ms",
              evidence.metric.clock == "monotonic",
              evidence.method.percentileMethod == "inclusive_linear_interpolation_r7",
              evidence.method.positionFormula == "(n - 1) * q",
              evidence.method.rounding == "half_even_to_3_decimal_places",
              evidence.method.minimumRepetitions == AppleWorkloadFixture.minimumRepetitions,
              evidence.method.quantiles == ["p50": 0.5, "p95": 0.95, "p99": 0.99],
              evidence.build.mode == "release",
              evidence.build.optimization == "swiftc -O",
              evidence.threshold == nil,
              evidence.budget == nil,
              evidence.redaction.policy == "semantic_only",
              evidence.redaction.syntheticOnly,
              !evidence.redaction.containsCredentials,
              !evidence.redaction.containsTokens,
              !evidence.redaction.containsUserData,
              !evidence.redaction.containsLiveHosts,
              !evidence.redaction.containsTranscripts
        else {
            throw AppleBenchmarkError.evidenceDrift
        }

        guard isSHA256(evidence.revision.fixtureSHA256),
              isSHA256(evidence.artifactManifestSHA256),
              isCommitOrNotCollected(evidence.revision.sourceCommitSHA)
        else {
            throw AppleBenchmarkError.evidenceMalformed
        }
        try validateArtifacts(
            evidence.artifacts,
            artifactManifestSHA256: evidence.artifactManifestSHA256,
            fixtureSHA256: fixtureSHA256,
            workloadBytes: workloadBytes,
            traceBytes: traceBytes
        )

        let expectedRunCount = workload.operations.count * workload.targetPlatforms.count * 2
        guard evidence.runs.count == expectedRunCount else {
            throw AppleBenchmarkError.evidenceDrift
        }

        var seenIDs = Set<String>()
        for run in evidence.runs {
            guard seenIDs.insert(run.id).inserted,
                  workload.operations.contains(where: { $0.id == run.operationID }),
                  workload.targetPlatforms.contains(run.platform),
                  run.buildMode == "release",
                  run.optimization == "not_applicable",
                  run.repetitions == run.rawSamples.count,
                  run.repetitions >= AppleWorkloadFixture.minimumRepetitions,
                  run.rawSamples.allSatisfy({ $0.isFinite && $0 > 0 }),
                  isSHA256(run.sampleProvenanceSHA256),
                  run.distribution == DistributionCalculator.calculate(run.rawSamples),
                  run.distribution.min <= run.distribution.p50,
                  run.distribution.p50 <= run.distribution.p95,
                  run.distribution.p95 <= run.distribution.p99,
                  run.distribution.p99 <= run.distribution.max,
                  run.environment.device == "not_claimed",
                  run.environment.browser == "not_applicable",
                  (try? sampleProvenanceSHA256(for: run)) == run.sampleProvenanceSHA256
            else {
                throw AppleBenchmarkError.evidenceMalformed
            }
        }
    }

    public static func sampleProvenanceSHA256(for run: EvidenceRun) throws -> String {
        let payload = SampleProvenancePayload(run: run)
        return BenchmarkHash.sha256(try BenchmarkJSON.canonicalData(payload))
    }

    private static func validateArtifacts(
        _ artifacts: [ArtifactMetadata],
        artifactManifestSHA256: String,
        fixtureSHA256: String,
        workloadBytes: Data?,
        traceBytes: Data?
    ) throws {
        guard artifacts.count == reviewedArtifactPaths.count,
              artifacts.count <= maximumArtifactCount,
              artifactManifestSHA256 == artifactManifestDigest(artifacts),
              fixtureSHA256 == WorkloadFixtureLoader.expectedWorkloadSHA256,
              let workloadBytes,
              let traceBytes
        else {
            throw AppleBenchmarkError.evidenceMalformed
        }

        var seen = Set<String>()
        for (index, artifact) in artifacts.enumerated() {
            let expectedPath = reviewedArtifactPaths[index]
            guard artifact.path == expectedPath,
                  seen.insert(artifact.path).inserted,
                  isPortableRelativePath(artifact.path),
                  artifact.bytes > 0,
                  artifact.bytes <= maximumArtifactBytes,
                  isStrictLowerHexASCII(artifact.sha256, length: 64)
            else {
                throw AppleBenchmarkError.evidenceMalformed
            }

            switch artifact.path {
            case "fixture/workload.json":
                guard artifact.bytes == WorkloadFixtureLoader.expectedWorkloadByteCount,
                      artifact.sha256 == WorkloadFixtureLoader.expectedWorkloadSHA256,
                      workloadBytes.count == artifact.bytes,
                      BenchmarkHash.sha256(workloadBytes) == artifact.sha256
                else {
                    throw AppleBenchmarkError.evidenceMalformed
                }
            case "trace/raw-trace.json":
                guard traceBytes.count == artifact.bytes,
                      BenchmarkHash.sha256(traceBytes) == artifact.sha256
                else {
                    throw AppleBenchmarkError.evidenceMalformed
                }
            default:
                throw AppleBenchmarkError.evidenceMalformed
            }
        }
    }

    private static func isPortableRelativePath(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard !bytes.isEmpty,
              bytes.count <= 256,
              !value.hasPrefix("/"),
              !value.hasSuffix("/"),
              !bytes.contains(0x5C),
              !bytes.contains(where: { $0 < 0x20 || $0 > 0x7E }),
              !value.split(separator: "/", omittingEmptySubsequences: false).contains(where: {
                  $0.isEmpty || $0 == "." || $0 == ".."
              })
        else {
            return false
        }
        return bytes.allSatisfy { byte in
            (byte >= 0x30 && byte <= 0x39) ||
            (byte >= 0x41 && byte <= 0x5A) ||
            (byte >= 0x61 && byte <= 0x7A) ||
            byte == 0x2E || byte == 0x2F || byte == 0x2D || byte == 0x5F
        }
    }

    public static func artifactManifestDigest(_ artifacts: [ArtifactMetadata]) -> String {
        let payload = artifacts.map { "\($0.path)|\($0.bytes)|\($0.sha256)" }.joined(separator: "\n")
        return BenchmarkHash.sha256(Data(payload.utf8))
    }

    private static func isSHA256(_ value: String) -> Bool {
        isStrictLowerHexASCII(value, length: 64)
    }

    private static func isCommitOrNotCollected(_ value: String) -> Bool {
        value == "not_collected" || isStrictLowerHexASCII(value, length: 40)
    }
}

private struct SampleProvenancePayload: Encodable, Sendable {
    let id: String
    let operationID: String
    let platform: AppleTargetPlatform
    let environment: EnvironmentMetadata
    let state: BenchmarkState
    let buildMode: String
    let optimization: String
    let command: String
    let repetitions: Int
    let rawSamples: [Double]

    private enum CodingKeys: String, CodingKey {
        case id
        case operationID = "operation_id"
        case platform
        case environment
        case state
        case buildMode = "build_mode"
        case optimization
        case command
        case repetitions
        case rawSamples = "raw_samples"
    }

    init(run: EvidenceRun) {
        id = run.id
        operationID = run.operationID
        platform = run.platform
        environment = run.environment
        state = run.state
        buildMode = run.buildMode
        optimization = run.optimization
        command = run.command
        repetitions = run.repetitions
        rawSamples = run.rawSamples
    }
}

public enum DistributionCalculator {
    public static func calculate(_ samples: [Double]) -> Distribution {
        let ordered = samples.sorted()
        let p50 = percentile(ordered, quantile: 0.50)
        let p95 = percentile(ordered, quantile: 0.95)
        let p99 = percentile(ordered, quantile: 0.99)
        let mean = ordered.reduce(0, +) / Double(ordered.count)
        return Distribution(
            min: round3(ordered[0]),
            p50: p50,
            p95: p95,
            p99: p99,
            max: round3(ordered[ordered.count - 1]),
            mean: round3(mean)
        )
    }

    private static func percentile(_ ordered: [Double], quantile: Double) -> Double {
        let position = Double(ordered.count - 1) * quantile
        let lower = Int(position.rounded(.down))
        let upper = min(lower + 1, ordered.count - 1)
        let fraction = position - Double(lower)
        return round3(ordered[lower] + (ordered[upper] - ordered[lower]) * fraction)
    }

    private static func round3(_ value: Double) -> Double {
        var decimal = Decimal(value)
        var rounded = Decimal()
        NSDecimalRound(&rounded, &decimal, 3, .bankers)
        return NSDecimalNumber(decimal: rounded).doubleValue
    }
}

public enum ReleaseBuildConfiguration {
    /// `_isDebugAssertConfiguration()` catches an explicit `-Onone` even when
    /// SwiftPM did not define `DEBUG`; the harness must not trust a claimed
    /// release label over the compiler's actual assertion configuration.
    public static var debugAssertionsEnabled: Bool {
        #if DEBUG
        true
        #else
        _isDebugAssertConfiguration()
        #endif
    }
}

public enum ReleaseBuildMetadataFactory {
    public static func current() -> ReleaseBuildMetadata {
        let isDebug = ReleaseBuildConfiguration.debugAssertionsEnabled
        return ReleaseBuildMetadata(
            mode: isDebug ? "debug" : "release",
            optimization: isDebug ? "swiftc -Onone" : "swiftc -O",
            compiler: "swiftc",
            sdk: "not_recorded",
            target: "apple-synthetic",
            metadataStatus: "scaffold_only"
        )
    }
}

public enum EnvironmentMetadataFactory {
    public static func syntheticHost(for platform: AppleTargetPlatform) -> EnvironmentMetadata {
        #if arch(arm64)
        let architecture = "arm64"
        #elseif arch(x86_64)
        let architecture = "x86_64"
        #else
        let architecture = "not_recorded"
        #endif
        return EnvironmentMetadata(
            platform: "synthetic-\(platform.rawValue)",
            os: "Darwin",
            architecture: architecture,
            device: "not_claimed",
            runtime: "swift-foundation",
            browser: "not_applicable"
        )
    }
}
