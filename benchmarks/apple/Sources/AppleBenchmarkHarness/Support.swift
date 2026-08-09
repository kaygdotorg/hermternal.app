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
  case traceOutputRequired
  case outputPathCollision
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
    case .traceOutputRequired: return "trace_output_required"
    case .outputPathCollision: return "output_path_collision"
    case .unsupportedArgument: return "unsupported_argument"
    }
  }
}

public enum BenchmarkJSON {
  public static let maximumInputBytes = 1_048_576
  public static let maximumOutputBytes = 1_048_576

  public static func encode<T: Encodable>(_ value: T, pretty: Bool = true) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = pretty ? [.prettyPrinted, .sortedKeys] : [.sortedKeys]
    let data = try encoder.encode(value)
    guard data.count <= maximumOutputBytes else {
      throw AppleBenchmarkError.evidenceMalformed
    }
    return data
  }

  public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
    guard data.count <= maximumInputBytes else {
      throw AppleBenchmarkError.evidenceMalformed
    }
    var scanner = BoundedJSONScanner(data: data)
    try scanner.validate()
    return try JSONDecoder().decode(type, from: data)
  }

  public static func canonicalData<T: Encodable>(_ value: T) throws -> Data {
    try encode(value, pretty: false)
  }
}

private struct BoundedJSONScanner {
  private static let maximumDepth = 24
  private static let maximumNodes = 4_096
  private static let maximumObjectKeys = 64
  private static let maximumArrayElements = 256
  private static let maximumStrings = 4_096
  private static let maximumStringBytes = 16_384

  private let bytes: [UInt8]
  private var index = 0
  private var nodeCount = 0
  private var arrayCount = 0
  private var stringCount = 0

  init(data: Data) {
    bytes = Array(data)
  }

  mutating func validate() throws {
    skipWhitespace()
    try parseValue(depth: 0)
    skipWhitespace()
    guard index == bytes.count else {
      throw AppleBenchmarkError.evidenceMalformed
    }
  }

  private mutating func parseValue(depth: Int) throws {
    guard depth <= Self.maximumDepth,
      nodeCount < Self.maximumNodes,
      index < bytes.count
    else {
      throw AppleBenchmarkError.evidenceMalformed
    }
    nodeCount += 1
    switch bytes[index] {
    case 0x7B:
      try parseObject(depth: depth)
    case 0x5B:
      try parseArray(depth: depth)
    case 0x22:
      _ = try parseString()
    case 0x2D, 0x30...0x39:
      try parseNumber()
    case 0x66:
      try parseLiteral(Array("false".utf8))
    case 0x6E:
      try parseLiteral(Array("null".utf8))
    case 0x74:
      try parseLiteral(Array("true".utf8))
    default:
      throw AppleBenchmarkError.evidenceMalformed
    }
  }

  private mutating func parseObject(depth: Int) throws {
    index += 1
    skipWhitespace()
    if consume(0x7D) {
      return
    }
    var keys = Set<String>()
    var keyCount = 0
    while true {
      guard index < bytes.count, bytes[index] == 0x22 else {
        throw AppleBenchmarkError.evidenceMalformed
      }
      let key = try parseString()
      keyCount += 1
      guard keyCount <= Self.maximumObjectKeys, keys.insert(key).inserted else {
        throw AppleBenchmarkError.evidenceMalformed
      }
      skipWhitespace()
      guard consume(0x3A) else {
        throw AppleBenchmarkError.evidenceMalformed
      }
      skipWhitespace()
      try parseValue(depth: depth + 1)
      skipWhitespace()
      if consume(0x7D) {
        return
      }
      guard consume(0x2C) else {
        throw AppleBenchmarkError.evidenceMalformed
      }
      skipWhitespace()
    }
  }

  private mutating func parseArray(depth: Int) throws {
    index += 1
    arrayCount += 1
    guard arrayCount <= Self.maximumArrayElements else {
      throw AppleBenchmarkError.evidenceMalformed
    }
    skipWhitespace()
    if consume(0x5D) {
      return
    }
    var elementCount = 0
    while true {
      elementCount += 1
      guard elementCount <= Self.maximumArrayElements else {
        throw AppleBenchmarkError.evidenceMalformed
      }
      try parseValue(depth: depth + 1)
      skipWhitespace()
      if consume(0x5D) {
        return
      }
      guard consume(0x2C) else {
        throw AppleBenchmarkError.evidenceMalformed
      }
      skipWhitespace()
    }
  }

  private mutating func parseString() throws -> String {
    let start = index
    guard consume(0x22) else {
      throw AppleBenchmarkError.evidenceMalformed
    }
    stringCount += 1
    guard stringCount <= Self.maximumStrings else {
      throw AppleBenchmarkError.evidenceMalformed
    }
    while index < bytes.count {
      let byte = bytes[index]
      if byte == 0x22 {
        index += 1
        guard index - start <= Self.maximumStringBytes * 2 else {
          throw AppleBenchmarkError.evidenceMalformed
        }
        let raw = Data(bytes[start..<index])
        guard let value = try? JSONDecoder().decode(String.self, from: raw),
          value.utf8.count <= Self.maximumStringBytes
        else {
          throw AppleBenchmarkError.evidenceMalformed
        }
        return value
      }
      guard byte >= 0x20 else {
        throw AppleBenchmarkError.evidenceMalformed
      }
      if byte == 0x5C {
        index += 1
        guard index < bytes.count else {
          throw AppleBenchmarkError.evidenceMalformed
        }
        switch bytes[index] {
        case 0x22, 0x2F, 0x5C, 0x62, 0x66, 0x6E, 0x72, 0x74:
          index += 1
        case 0x75:
          guard index + 4 < bytes.count,
            bytes[(index + 1)...(index + 4)].allSatisfy(Self.isHexByte)
          else {
            throw AppleBenchmarkError.evidenceMalformed
          }
          index += 5
        default:
          throw AppleBenchmarkError.evidenceMalformed
        }
      } else {
        index += 1
      }
      guard index - start <= Self.maximumStringBytes * 2 else {
        throw AppleBenchmarkError.evidenceMalformed
      }
    }
    throw AppleBenchmarkError.evidenceMalformed
  }

  private mutating func parseNumber() throws {
    if consume(0x2D) && index >= bytes.count {
      throw AppleBenchmarkError.evidenceMalformed
    }
    if consume(0x30) {
      if index < bytes.count, bytes[index] >= 0x30, bytes[index] <= 0x39 {
        throw AppleBenchmarkError.evidenceMalformed
      }
    } else {
      guard consumeDigit(nonZero: true) else {
        throw AppleBenchmarkError.evidenceMalformed
      }
      while consumeDigit(nonZero: false) {}
    }
    if consume(0x2E) {
      guard consumeDigit(nonZero: false) else {
        throw AppleBenchmarkError.evidenceMalformed
      }
      while consumeDigit(nonZero: false) {}
    }
    if index < bytes.count, bytes[index] == 0x65 || bytes[index] == 0x45 {
      index += 1
      _ = consume(0x2B) || consume(0x2D)
      guard consumeDigit(nonZero: false) else {
        throw AppleBenchmarkError.evidenceMalformed
      }
      while consumeDigit(nonZero: false) {}
    }
  }

  private mutating func parseLiteral(_ literal: [UInt8]) throws {
    guard index + literal.count <= bytes.count,
      Array(bytes[index..<(index + literal.count)]) == literal
    else {
      throw AppleBenchmarkError.evidenceMalformed
    }
    index += literal.count
  }

  private mutating func consume(_ byte: UInt8) -> Bool {
    guard index < bytes.count, bytes[index] == byte else {
      return false
    }
    index += 1
    return true
  }

  private mutating func consumeDigit(nonZero: Bool) -> Bool {
    guard index < bytes.count else {
      return false
    }
    let byte = bytes[index]
    let valid = nonZero ? (byte >= 0x31 && byte <= 0x39) : (byte >= 0x30 && byte <= 0x39)
    if valid {
      index += 1
    }
    return valid
  }

  private mutating func skipWhitespace() {
    while index < bytes.count {
      switch bytes[index] {
      case 0x20, 0x09, 0x0A, 0x0D:
        index += 1
      default:
        return
      }
    }
  }

  private static func isHexByte(_ byte: UInt8) -> Bool {
    (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x46)
      || (byte >= 0x61 && byte <= 0x66)
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
    (byte >= 0x30 && byte <= 0x39) || (byte >= 0x61 && byte <= 0x66)
  }
}

public enum CLIOutputPolicy {
  public struct Destinations: Equatable, Sendable {
    public let evidence: URL?
    public let trace: URL

    public init(evidence: URL?, trace: URL) {
      self.evidence = evidence
      self.trace = trace
    }
  }

  /// Canonicalize both destinations before any write so an evidence file can
  /// never be replaced by its raw trace or attest to a path that was not
  /// actually emitted.
  public static func canonicalize(
    evidencePath: URL?,
    tracePath: URL?
  ) throws -> Destinations {
    guard let tracePath else {
      throw AppleBenchmarkError.traceOutputRequired
    }
    let canonicalTrace = tracePath.standardizedFileURL.resolvingSymlinksInPath()
    let canonicalEvidence = evidencePath?.standardizedFileURL.resolvingSymlinksInPath()
    if let canonicalEvidence, canonicalEvidence == canonicalTrace {
      throw AppleBenchmarkError.outputPathCollision
    }
    return Destinations(evidence: canonicalEvidence, trace: canonicalTrace)
  }
}

public enum WorkloadFixtureLoader {
  // This pins the bytes used by the scaffold. A changed fixture requires an
  // intentional review of the operation inventory, seed, and evidence shape.
  public static let expectedWorkloadSHA256 =
    "192b63346cf71e05f6955cfcdfcca398fbf85387c7adf3226fa61fdef59a907d"
  public static let expectedWorkloadByteCount = 1_308

  public static func load(from data: Data? = nil) throws -> (
    fixture: AppleWorkloadFixture, bytes: Data
  ) {
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
      fixture.repetitions.maximum == EvidenceValidator.requiredMaximumRepetitions
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
  public static let requiredMaximumRepetitions = 120
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
    try WorkloadValidator.validate(workload)
    guard evidence.schema == AppleEvidenceDocument.schema,
      evidence.protocolSchema == AppleEvidenceDocument.protocolSchema,
      evidence.evidenceID == "apple-release-mock-workload",
      evidence.revision.fixtureID == workload.fixtureID,
      evidence.revision.fixtureVersion == workload.fixtureVersion,
      fixtureSHA256 == WorkloadFixtureLoader.expectedWorkloadSHA256,
      evidence.revision.fixtureSHA256 == fixtureSHA256,
      evidence.revision.hermesSourceSHA == pinnedHermesSourceSHA,
      isStrictLowerHexASCII(evidence.revision.hermesSourceSHA, length: 40),
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
      evidence.build.compiler == "swiftc",
      evidence.build.sdk == "not_recorded",
      evidence.build.target == "apple-synthetic",
      evidence.build.metadataStatus == "scaffold_only",
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
    var expectedLanes:
      [String: (
        operationID: String, platform: AppleTargetPlatform, state: BenchmarkState, repetitions: Int
      )] = [:]
    for platform in workload.targetPlatforms {
      for operation in workload.operations {
        for state in [BenchmarkState.cold, .warm] {
          let id = "\(platform.rawValue)-\(state.rawValue)-\(operation.id)"
          expectedLanes[id] = (
            operationID: operation.id,
            platform: platform,
            state: state,
            repetitions: state == .cold ? workload.repetitions.cold : workload.repetitions.warm
          )
        }
      }
    }
    guard expectedLanes.count == expectedRunCount,
      evidence.runs.count == expectedRunCount
    else {
      throw AppleBenchmarkError.evidenceDrift
    }

    var seenIDs = Set<String>()
    for run in evidence.runs {
      guard let expected = expectedLanes[run.id],
        let operation = workload.operations.first(where: { $0.id == run.operationID }),
        seenIDs.insert(run.id).inserted,
        run.operationID == expected.operationID,
        run.platform == expected.platform,
        run.state == expected.state,
        run.buildMode == "release",
        run.optimization == "not_applicable",
        run.command == "offline apple mock workload \(operation.id)",
        run.repetitions == expected.repetitions,
        run.repetitions == run.rawSamples.count,
        run.repetitions >= AppleWorkloadFixture.minimumRepetitions,
        run.repetitions <= workload.repetitions.maximum,
        run.rawSamples.allSatisfy({ $0.isFinite && $0 > 0 }),
        isSHA256(run.sampleProvenanceSHA256),
        run.distribution.min.isFinite,
        run.distribution.p50.isFinite,
        run.distribution.p95.isFinite,
        run.distribution.p99.isFinite,
        run.distribution.max.isFinite,
        run.distribution.mean.isFinite,
        run.distribution.min > 0,
        run.distribution.min <= run.distribution.p50,
        run.distribution.p50 <= run.distribution.p95,
        run.distribution.p95 <= run.distribution.p99,
        run.distribution.p99 <= run.distribution.max,
        run.environment == EnvironmentMetadataFactory.syntheticHost(for: expected.platform),
        (try? sampleProvenanceSHA256(for: run)) == run.sampleProvenanceSHA256,
        let expectedDistribution = try? DistributionCalculator.calculate(run.rawSamples),
        run.distribution == expectedDistribution
      else {
        throw AppleBenchmarkError.evidenceMalformed
      }
    }
    guard seenIDs == Set(expectedLanes.keys),
      let traceBytes
    else {
      throw AppleBenchmarkError.evidenceDrift
    }
    let trace = try BenchmarkJSON.decode(RawTraceDocument.self, from: traceBytes)
    try validateTrace(trace, evidence: evidence, workload: workload, expectedLanes: expectedLanes)
  }

  private static func validateTrace(
    _ trace: RawTraceDocument,
    evidence: AppleEvidenceDocument,
    workload: AppleWorkloadFixture,
    expectedLanes: [String: (
      operationID: String, platform: AppleTargetPlatform, state: BenchmarkState, repetitions: Int
    )]
  ) throws {
    let expectedEnvironment = EnvironmentMetadata(
      platform: "synthetic-apple",
      os: "Darwin",
      architecture: EnvironmentMetadataFactory.syntheticHost(for: .macos).architecture,
      device: "not_claimed",
      runtime: "swift-foundation",
      browser: "not_applicable"
    )
    guard trace.schema == RawTraceDocument.schema,
      trace.fixtureID == workload.fixtureID,
      trace.fixtureVersion == workload.fixtureVersion,
      trace.revision == evidence.revision,
      trace.metric == evidence.metric,
      trace.build == evidence.build,
      trace.environment == expectedEnvironment,
      trace.runs.count == expectedLanes.count
    else {
      throw AppleBenchmarkError.evidenceDrift
    }

    var seenIDs = Set<String>()
    for traceRun in trace.runs {
      guard let expected = expectedLanes[traceRun.id],
        let evidenceRun = evidence.runs.first(where: { $0.id == traceRun.id }),
        seenIDs.insert(traceRun.id).inserted,
        traceRun.operationID == expected.operationID,
        traceRun.platform == expected.platform,
        traceRun.state == expected.state,
        traceRun.samples == evidenceRun.rawSamples,
        traceRun.samples.count == expected.repetitions,
        traceRun.samples.allSatisfy({ $0.isFinite && $0 > 0 }),
        traceRun.warmupSamples.count == (traceRun.state == .warm ? workload.warmupRepetitions : 0),
        traceRun.warmupSamples.allSatisfy({ $0.isFinite && $0 > 0 })
      else {
        throw AppleBenchmarkError.evidenceMalformed
      }
    }
    guard seenIDs == Set(expectedLanes.keys) else {
      throw AppleBenchmarkError.evidenceDrift
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
      (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5A)
        || (byte >= 0x61 && byte <= 0x7A) || byte == 0x2E || byte == 0x2F || byte == 0x2D
        || byte == 0x5F
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
  public static func calculate(_ samples: [Double]) throws -> Distribution {
    guard !samples.isEmpty,
      samples.allSatisfy({ $0.isFinite && $0 > 0 })
    else {
      throw AppleBenchmarkError.evidenceMalformed
    }
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
