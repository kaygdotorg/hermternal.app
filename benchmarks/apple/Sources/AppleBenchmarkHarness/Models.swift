import Foundation

// MARK: - Closed decoding helpers

private func requireExactKeys<K: CodingKey>(
    _ container: KeyedDecodingContainer<K>,
    _ expected: [String]
) throws {
    let actual = Set(container.allKeys.map(\.stringValue))
    guard actual == Set(expected) else {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: container.codingPath,
                debugDescription: "closed benchmark schema keys changed"
            )
        )
    }
}

private func corruption<K: CodingKey>(
    _ container: KeyedDecodingContainer<K>,
    _ message: String
) -> DecodingError {
    .dataCorrupted(
        .init(codingPath: container.codingPath, debugDescription: message)
    )
}

// MARK: - Workload contract

public enum AppleTargetPlatform: String, Codable, CaseIterable, Sendable {
    case ios
    case ipados
    case macos
}

public enum BenchmarkState: String, Codable, CaseIterable, Sendable {
    case cold
    case warm
}

public enum BenchmarkOperationKind: String, Codable, CaseIterable, Sendable {
    case launchSetupStateConstruction = "launch_setup_state_construction"
    case streamingBatchReduction = "streaming_batch_reduction"
    case transcriptDiffScrollModel = "transcript_diff_scroll_model"
    case sceneRestorationSerialization = "scene_restoration_serialization"
    case dynamicTypeLayoutCalculation = "dynamic_type_layout_calculation"
}

public struct RepetitionSpec: Codable, Equatable, Sendable {
    public let cold: Int
    public let warm: Int
    public let maximum: Int

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case cold
        case warm
        case maximum
    }

    public init(cold: Int, warm: Int, maximum: Int) {
        self.cold = cold
        self.warm = warm
        self.maximum = maximum
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try requireExactKeys(c, CodingKeys.allCases.map(\.rawValue))
        cold = try c.decode(Int.self, forKey: .cold)
        warm = try c.decode(Int.self, forKey: .warm)
        maximum = try c.decode(Int.self, forKey: .maximum)
    }
}

public struct WorkloadBuildSpec: Codable, Equatable, Sendable {
    public let mode: String
    public let optimization: String
    public let metadataStatus: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case mode
        case optimization
        case metadataStatus = "metadata_status"
    }

    public init(mode: String, optimization: String, metadataStatus: String) {
        self.mode = mode
        self.optimization = optimization
        self.metadataStatus = metadataStatus
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try requireExactKeys(c, CodingKeys.allCases.map(\.rawValue))
        mode = try c.decode(String.self, forKey: .mode)
        optimization = try c.decode(String.self, forKey: .optimization)
        metadataStatus = try c.decode(String.self, forKey: .metadataStatus)
    }
}

public struct WorkloadOperationSpec: Codable, Equatable, Sendable {
    public let id: String
    public let kind: BenchmarkOperationKind
    public let itemCount: Int
    public let batchSize: Int
    public let textLength: Int

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id
        case kind
        case itemCount = "item_count"
        case batchSize = "batch_size"
        case textLength = "text_length"
    }

    public init(
        id: String,
        kind: BenchmarkOperationKind,
        itemCount: Int,
        batchSize: Int,
        textLength: Int
    ) {
        self.id = id
        self.kind = kind
        self.itemCount = itemCount
        self.batchSize = batchSize
        self.textLength = textLength
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try requireExactKeys(c, CodingKeys.allCases.map(\.rawValue))
        id = try c.decode(String.self, forKey: .id)
        kind = try c.decode(BenchmarkOperationKind.self, forKey: .kind)
        itemCount = try c.decode(Int.self, forKey: .itemCount)
        batchSize = try c.decode(Int.self, forKey: .batchSize)
        textLength = try c.decode(Int.self, forKey: .textLength)
    }
}

public struct AppleWorkloadFixture: Codable, Equatable, Sendable {
    public static let schema = "hermternal.apple-benchmark-fixture.v1"
    public static let fixtureID = "apple-release-mock-workload"
    public static let fixtureVersion = "1.0.0"
    public static let requiredSeed: UInt64 = 1_080_427
    public static let minimumRepetitions = 30

    public let schema: String
    public let fixtureID: String
    public let fixtureVersion: String
    public let seed: UInt64
    public let repetitions: RepetitionSpec
    public let warmupRepetitions: Int
    public let targetPlatforms: [AppleTargetPlatform]
    public let build: WorkloadBuildSpec
    public let operations: [WorkloadOperationSpec]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schema
        case fixtureID = "fixture_id"
        case fixtureVersion = "fixture_version"
        case seed
        case repetitions
        case warmupRepetitions = "warmup_repetitions"
        case targetPlatforms = "target_platforms"
        case build
        case operations
    }

    public init(
        schema: String,
        fixtureID: String,
        fixtureVersion: String,
        seed: UInt64,
        repetitions: RepetitionSpec,
        warmupRepetitions: Int,
        targetPlatforms: [AppleTargetPlatform],
        build: WorkloadBuildSpec,
        operations: [WorkloadOperationSpec]
    ) {
        self.schema = schema
        self.fixtureID = fixtureID
        self.fixtureVersion = fixtureVersion
        self.seed = seed
        self.repetitions = repetitions
        self.warmupRepetitions = warmupRepetitions
        self.targetPlatforms = targetPlatforms
        self.build = build
        self.operations = operations
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try requireExactKeys(c, CodingKeys.allCases.map(\.rawValue))
        schema = try c.decode(String.self, forKey: .schema)
        fixtureID = try c.decode(String.self, forKey: .fixtureID)
        fixtureVersion = try c.decode(String.self, forKey: .fixtureVersion)
        seed = try c.decode(UInt64.self, forKey: .seed)
        repetitions = try c.decode(RepetitionSpec.self, forKey: .repetitions)
        warmupRepetitions = try c.decode(Int.self, forKey: .warmupRepetitions)
        targetPlatforms = try c.decode([AppleTargetPlatform].self, forKey: .targetPlatforms)
        build = try c.decode(WorkloadBuildSpec.self, forKey: .build)
        operations = try c.decode([WorkloadOperationSpec].self, forKey: .operations)
    }
}

// MARK: - Release-build and environment metadata

public struct ReleaseBuildMetadata: Codable, Equatable, Sendable {
    public let mode: String
    public let optimization: String
    public let compiler: String
    public let sdk: String
    public let target: String
    public let metadataStatus: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case mode
        case optimization
        case compiler
        case sdk
        case target
        case metadataStatus = "metadata_status"
    }

    public init(
        mode: String,
        optimization: String,
        compiler: String,
        sdk: String,
        target: String,
        metadataStatus: String
    ) {
        self.mode = mode
        self.optimization = optimization
        self.compiler = compiler
        self.sdk = sdk
        self.target = target
        self.metadataStatus = metadataStatus
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try requireExactKeys(c, CodingKeys.allCases.map(\.rawValue))
        mode = try c.decode(String.self, forKey: .mode)
        optimization = try c.decode(String.self, forKey: .optimization)
        compiler = try c.decode(String.self, forKey: .compiler)
        sdk = try c.decode(String.self, forKey: .sdk)
        target = try c.decode(String.self, forKey: .target)
        metadataStatus = try c.decode(String.self, forKey: .metadataStatus)
    }
}

public struct EnvironmentMetadata: Codable, Equatable, Sendable {
    public let platform: String
    public let os: String
    public let architecture: String
    public let device: String
    public let runtime: String
    public let browser: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case platform
        case os
        case architecture
        case device
        case runtime
        case browser
    }

    public init(
        platform: String,
        os: String,
        architecture: String,
        device: String,
        runtime: String,
        browser: String
    ) {
        self.platform = platform
        self.os = os
        self.architecture = architecture
        self.device = device
        self.runtime = runtime
        self.browser = browser
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try requireExactKeys(c, CodingKeys.allCases.map(\.rawValue))
        platform = try c.decode(String.self, forKey: .platform)
        os = try c.decode(String.self, forKey: .os)
        architecture = try c.decode(String.self, forKey: .architecture)
        device = try c.decode(String.self, forKey: .device)
        runtime = try c.decode(String.self, forKey: .runtime)
        browser = try c.decode(String.self, forKey: .browser)
    }
}

// MARK: - Evidence and trace records

public struct RevisionMetadata: Codable, Equatable, Sendable {
    public let sourceCommitSHA: String
    public let fixtureID: String
    public let fixtureVersion: String
    public let fixtureSHA256: String
    public let hermesSourceSHA: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case sourceCommitSHA = "source_commit_sha"
        case fixtureID = "fixture_id"
        case fixtureVersion = "fixture_version"
        case fixtureSHA256 = "fixture_sha256"
        case hermesSourceSHA = "hermes_source_sha"
    }

    public init(
        sourceCommitSHA: String,
        fixtureID: String,
        fixtureVersion: String,
        fixtureSHA256: String,
        hermesSourceSHA: String
    ) {
        self.sourceCommitSHA = sourceCommitSHA
        self.fixtureID = fixtureID
        self.fixtureVersion = fixtureVersion
        self.fixtureSHA256 = fixtureSHA256
        self.hermesSourceSHA = hermesSourceSHA
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try requireExactKeys(c, CodingKeys.allCases.map(\.rawValue))
        sourceCommitSHA = try c.decode(String.self, forKey: .sourceCommitSHA)
        fixtureID = try c.decode(String.self, forKey: .fixtureID)
        fixtureVersion = try c.decode(String.self, forKey: .fixtureVersion)
        fixtureSHA256 = try c.decode(String.self, forKey: .fixtureSHA256)
        hermesSourceSHA = try c.decode(String.self, forKey: .hermesSourceSHA)
    }
}

public struct MetricMetadata: Codable, Equatable, Sendable {
    public let name: String
    public let unit: String
    public let clock: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case name
        case unit
        case clock
    }

    public init(name: String, unit: String, clock: String) {
        self.name = name
        self.unit = unit
        self.clock = clock
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try requireExactKeys(c, CodingKeys.allCases.map(\.rawValue))
        name = try c.decode(String.self, forKey: .name)
        unit = try c.decode(String.self, forKey: .unit)
        clock = try c.decode(String.self, forKey: .clock)
    }
}

public struct MethodMetadata: Codable, Equatable, Sendable {
    public let percentileMethod: String
    public let positionFormula: String
    public let rounding: String
    public let quantiles: [String: Double]
    public let minimumRepetitions: Int

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case percentileMethod = "percentile_method"
        case positionFormula = "position_formula"
        case rounding
        case quantiles
        case minimumRepetitions = "minimum_repetitions"
    }

    public init(
        percentileMethod: String,
        positionFormula: String,
        rounding: String,
        quantiles: [String: Double],
        minimumRepetitions: Int
    ) {
        self.percentileMethod = percentileMethod
        self.positionFormula = positionFormula
        self.rounding = rounding
        self.quantiles = quantiles
        self.minimumRepetitions = minimumRepetitions
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try requireExactKeys(c, CodingKeys.allCases.map(\.rawValue))
        percentileMethod = try c.decode(String.self, forKey: .percentileMethod)
        positionFormula = try c.decode(String.self, forKey: .positionFormula)
        rounding = try c.decode(String.self, forKey: .rounding)
        quantiles = try c.decode([String: Double].self, forKey: .quantiles)
        minimumRepetitions = try c.decode(Int.self, forKey: .minimumRepetitions)
    }
}

public struct Distribution: Codable, Equatable, Sendable {
    public let min: Double
    public let p50: Double
    public let p95: Double
    public let p99: Double
    public let max: Double
    public let mean: Double

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case min
        case p50
        case p95
        case p99
        case max
        case mean
    }

    public init(min: Double, p50: Double, p95: Double, p99: Double, max: Double, mean: Double) {
        self.min = min
        self.p50 = p50
        self.p95 = p95
        self.p99 = p99
        self.max = max
        self.mean = mean
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try requireExactKeys(c, CodingKeys.allCases.map(\.rawValue))
        min = try c.decode(Double.self, forKey: .min)
        p50 = try c.decode(Double.self, forKey: .p50)
        p95 = try c.decode(Double.self, forKey: .p95)
        p99 = try c.decode(Double.self, forKey: .p99)
        max = try c.decode(Double.self, forKey: .max)
        mean = try c.decode(Double.self, forKey: .mean)
    }
}

public struct EvidenceRun: Codable, Equatable, Sendable {
    public let id: String
    public let operationID: String
    public let platform: AppleTargetPlatform
    public let environment: EnvironmentMetadata
    public let state: BenchmarkState
    public let buildMode: String
    public let optimization: String
    public let command: String
    public let repetitions: Int
    public let rawSamples: [Double]
    public let sampleProvenanceSHA256: String
    public let distribution: Distribution

    private enum CodingKeys: String, CodingKey, CaseIterable {
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
        case sampleProvenanceSHA256 = "sample_provenance_sha256"
        case distribution
    }

    public init(
        id: String,
        operationID: String,
        platform: AppleTargetPlatform,
        environment: EnvironmentMetadata,
        state: BenchmarkState,
        buildMode: String,
        optimization: String,
        command: String,
        repetitions: Int,
        rawSamples: [Double],
        sampleProvenanceSHA256: String,
        distribution: Distribution
    ) {
        self.id = id
        self.operationID = operationID
        self.platform = platform
        self.environment = environment
        self.state = state
        self.buildMode = buildMode
        self.optimization = optimization
        self.command = command
        self.repetitions = repetitions
        self.rawSamples = rawSamples
        self.sampleProvenanceSHA256 = sampleProvenanceSHA256
        self.distribution = distribution
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try requireExactKeys(c, CodingKeys.allCases.map(\.rawValue))
        id = try c.decode(String.self, forKey: .id)
        operationID = try c.decode(String.self, forKey: .operationID)
        platform = try c.decode(AppleTargetPlatform.self, forKey: .platform)
        environment = try c.decode(EnvironmentMetadata.self, forKey: .environment)
        state = try c.decode(BenchmarkState.self, forKey: .state)
        buildMode = try c.decode(String.self, forKey: .buildMode)
        optimization = try c.decode(String.self, forKey: .optimization)
        command = try c.decode(String.self, forKey: .command)
        repetitions = try c.decode(Int.self, forKey: .repetitions)
        rawSamples = try c.decode([Double].self, forKey: .rawSamples)
        sampleProvenanceSHA256 = try c.decode(String.self, forKey: .sampleProvenanceSHA256)
        distribution = try c.decode(Distribution.self, forKey: .distribution)
    }
}

public struct ArtifactMetadata: Codable, Equatable, Sendable {
    public let path: String
    public let bytes: Int
    public let sha256: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case path
        case bytes
        case sha256
    }

    public init(path: String, bytes: Int, sha256: String) {
        self.path = path
        self.bytes = bytes
        self.sha256 = sha256
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try requireExactKeys(c, CodingKeys.allCases.map(\.rawValue))
        path = try c.decode(String.self, forKey: .path)
        bytes = try c.decode(Int.self, forKey: .bytes)
        sha256 = try c.decode(String.self, forKey: .sha256)
    }
}

public struct RedactionMetadata: Codable, Equatable, Sendable {
    public let policy: String
    public let syntheticOnly: Bool
    public let containsCredentials: Bool
    public let containsTokens: Bool
    public let containsUserData: Bool
    public let containsLiveHosts: Bool
    public let containsTranscripts: Bool

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case policy
        case syntheticOnly = "synthetic_only"
        case containsCredentials = "contains_credentials"
        case containsTokens = "contains_tokens"
        case containsUserData = "contains_user_data"
        case containsLiveHosts = "contains_live_hosts"
        case containsTranscripts = "contains_transcripts"
    }

    public init(
        policy: String,
        syntheticOnly: Bool,
        containsCredentials: Bool,
        containsTokens: Bool,
        containsUserData: Bool,
        containsLiveHosts: Bool,
        containsTranscripts: Bool
    ) {
        self.policy = policy
        self.syntheticOnly = syntheticOnly
        self.containsCredentials = containsCredentials
        self.containsTokens = containsTokens
        self.containsUserData = containsUserData
        self.containsLiveHosts = containsLiveHosts
        self.containsTranscripts = containsTranscripts
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try requireExactKeys(c, CodingKeys.allCases.map(\.rawValue))
        policy = try c.decode(String.self, forKey: .policy)
        syntheticOnly = try c.decode(Bool.self, forKey: .syntheticOnly)
        containsCredentials = try c.decode(Bool.self, forKey: .containsCredentials)
        containsTokens = try c.decode(Bool.self, forKey: .containsTokens)
        containsUserData = try c.decode(Bool.self, forKey: .containsUserData)
        containsLiveHosts = try c.decode(Bool.self, forKey: .containsLiveHosts)
        containsTranscripts = try c.decode(Bool.self, forKey: .containsTranscripts)
    }
}

public struct AppleEvidenceDocument: Codable, Equatable, Sendable {
    public static let schema = "hermternal.apple-benchmark-evidence.v1"
    public static let protocolSchema = "hermternal.benchmark-evidence.v1"

    public let schema: String
    public let protocolSchema: String
    public let evidenceID: String
    public let revision: RevisionMetadata
    public let metric: MetricMetadata
    public let method: MethodMetadata
    public let build: ReleaseBuildMetadata
    public let runs: [EvidenceRun]
    public let artifacts: [ArtifactMetadata]
    public let artifactManifestSHA256: String
    public let redaction: RedactionMetadata
    public let threshold: Double?
    public let budget: Double?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schema
        case protocolSchema = "protocol_schema"
        case evidenceID = "evidence_id"
        case revision
        case metric
        case method
        case build
        case runs
        case artifacts
        case artifactManifestSHA256 = "artifact_manifest_sha256"
        case redaction
        case threshold
        case budget
    }

    public init(
        schema: String,
        protocolSchema: String,
        evidenceID: String,
        revision: RevisionMetadata,
        metric: MetricMetadata,
        method: MethodMetadata,
        build: ReleaseBuildMetadata,
        runs: [EvidenceRun],
        artifacts: [ArtifactMetadata],
        artifactManifestSHA256: String,
        redaction: RedactionMetadata,
        threshold: Double?,
        budget: Double?
    ) {
        self.schema = schema
        self.protocolSchema = protocolSchema
        self.evidenceID = evidenceID
        self.revision = revision
        self.metric = metric
        self.method = method
        self.build = build
        self.runs = runs
        self.artifacts = artifacts
        self.artifactManifestSHA256 = artifactManifestSHA256
        self.redaction = redaction
        self.threshold = threshold
        self.budget = budget
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try requireExactKeys(c, CodingKeys.allCases.map(\.rawValue))
        schema = try c.decode(String.self, forKey: .schema)
        protocolSchema = try c.decode(String.self, forKey: .protocolSchema)
        evidenceID = try c.decode(String.self, forKey: .evidenceID)
        revision = try c.decode(RevisionMetadata.self, forKey: .revision)
        metric = try c.decode(MetricMetadata.self, forKey: .metric)
        method = try c.decode(MethodMetadata.self, forKey: .method)
        build = try c.decode(ReleaseBuildMetadata.self, forKey: .build)
        runs = try c.decode([EvidenceRun].self, forKey: .runs)
        artifacts = try c.decode([ArtifactMetadata].self, forKey: .artifacts)
        artifactManifestSHA256 = try c.decode(String.self, forKey: .artifactManifestSHA256)
        redaction = try c.decode(RedactionMetadata.self, forKey: .redaction)
        threshold = try c.decodeIfPresent(Double.self, forKey: .threshold)
        budget = try c.decodeIfPresent(Double.self, forKey: .budget)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(schema, forKey: .schema)
        try c.encode(protocolSchema, forKey: .protocolSchema)
        try c.encode(evidenceID, forKey: .evidenceID)
        try c.encode(revision, forKey: .revision)
        try c.encode(metric, forKey: .metric)
        try c.encode(method, forKey: .method)
        try c.encode(build, forKey: .build)
        try c.encode(runs, forKey: .runs)
        try c.encode(artifacts, forKey: .artifacts)
        try c.encode(artifactManifestSHA256, forKey: .artifactManifestSHA256)
        try c.encode(redaction, forKey: .redaction)
        try c.encodeNil(forKey: .threshold)
        try c.encodeNil(forKey: .budget)
    }
}

public struct TraceRun: Codable, Equatable, Sendable {
    public let id: String
    public let operationID: String
    public let platform: AppleTargetPlatform
    public let state: BenchmarkState
    public let warmupSamples: [Double]
    public let samples: [Double]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id
        case operationID = "operation_id"
        case platform
        case state
        case warmupSamples = "warmup_samples"
        case samples
    }

    public init(
        id: String,
        operationID: String,
        platform: AppleTargetPlatform,
        state: BenchmarkState,
        warmupSamples: [Double],
        samples: [Double]
    ) {
        self.id = id
        self.operationID = operationID
        self.platform = platform
        self.state = state
        self.warmupSamples = warmupSamples
        self.samples = samples
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try requireExactKeys(c, CodingKeys.allCases.map(\.rawValue))
        id = try c.decode(String.self, forKey: .id)
        operationID = try c.decode(String.self, forKey: .operationID)
        platform = try c.decode(AppleTargetPlatform.self, forKey: .platform)
        state = try c.decode(BenchmarkState.self, forKey: .state)
        warmupSamples = try c.decode([Double].self, forKey: .warmupSamples)
        samples = try c.decode([Double].self, forKey: .samples)
    }
}

public struct RawTraceDocument: Codable, Equatable, Sendable {
    public static let schema = "hermternal.apple-benchmark-trace.v1"

    public let schema: String
    public let fixtureID: String
    public let fixtureVersion: String
    public let revision: RevisionMetadata
    public let metric: MetricMetadata
    public let build: ReleaseBuildMetadata
    public let environment: EnvironmentMetadata
    public let runs: [TraceRun]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schema
        case fixtureID = "fixture_id"
        case fixtureVersion = "fixture_version"
        case revision
        case metric
        case build
        case environment
        case runs
    }

    public init(
        schema: String,
        fixtureID: String,
        fixtureVersion: String,
        revision: RevisionMetadata,
        metric: MetricMetadata,
        build: ReleaseBuildMetadata,
        environment: EnvironmentMetadata,
        runs: [TraceRun]
    ) {
        self.schema = schema
        self.fixtureID = fixtureID
        self.fixtureVersion = fixtureVersion
        self.revision = revision
        self.metric = metric
        self.build = build
        self.environment = environment
        self.runs = runs
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try requireExactKeys(c, CodingKeys.allCases.map(\.rawValue))
        schema = try c.decode(String.self, forKey: .schema)
        fixtureID = try c.decode(String.self, forKey: .fixtureID)
        fixtureVersion = try c.decode(String.self, forKey: .fixtureVersion)
        revision = try c.decode(RevisionMetadata.self, forKey: .revision)
        metric = try c.decode(MetricMetadata.self, forKey: .metric)
        build = try c.decode(ReleaseBuildMetadata.self, forKey: .build)
        environment = try c.decode(EnvironmentMetadata.self, forKey: .environment)
        runs = try c.decode([TraceRun].self, forKey: .runs)
    }
}
