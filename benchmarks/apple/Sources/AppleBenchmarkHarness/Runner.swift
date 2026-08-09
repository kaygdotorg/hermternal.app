import Foundation

public struct BenchmarkRunResult: Sendable {
    public let evidence: AppleEvidenceDocument
    public let trace: RawTraceDocument
    public let traceBytes: Data

    public init(evidence: AppleEvidenceDocument, trace: RawTraceDocument, traceBytes: Data) {
        self.evidence = evidence
        self.trace = trace
        self.traceBytes = traceBytes
    }
}

public struct AppleBenchmarkRunner: Sendable {
    public typealias MonotonicNow = @Sendable () -> UInt64

    private let now: MonotonicNow
    private let enforceReleaseConfiguration: Bool

    public init(
        enforceReleaseConfiguration: Bool = true,
        now: @escaping MonotonicNow = { DispatchTime.now().uptimeNanoseconds }
    ) {
        self.enforceReleaseConfiguration = enforceReleaseConfiguration
        self.now = now
    }

    public func run(
        workload: AppleWorkloadFixture,
        workloadBytes: Data,
        sourceCommitSHA: String,
        build: ReleaseBuildMetadata = ReleaseBuildMetadataFactory.current()
    ) throws -> BenchmarkRunResult {
        try WorkloadValidator.validate(workload)
        guard workloadBytes.count == WorkloadFixtureLoader.expectedWorkloadByteCount,
              BenchmarkHash.sha256(workloadBytes) == WorkloadFixtureLoader.expectedWorkloadSHA256
        else {
            throw AppleBenchmarkError.workloadDrift
        }
        guard !enforceReleaseConfiguration || !ReleaseBuildConfiguration.debugAssertionsEnabled,
              build.mode == "release",
              build.optimization == "swiftc -O"
        else {
            throw AppleBenchmarkError.releaseBuildRequired
        }
        guard sourceCommitSHA == "not_collected" || isCommitSHA(sourceCommitSHA) else {
            throw AppleBenchmarkError.sourceCommitMissing
        }

        let fixtureSHA256 = BenchmarkHash.sha256(workloadBytes)
        let revision = RevisionMetadata(
            sourceCommitSHA: sourceCommitSHA,
            fixtureID: workload.fixtureID,
            fixtureVersion: workload.fixtureVersion,
            fixtureSHA256: fixtureSHA256,
            hermesSourceSHA: EvidenceValidator.pinnedHermesSourceSHA
        )
        let metric = MetricMetadata(name: "operation_duration", unit: "ms", clock: "monotonic")
        let method = MethodMetadata(
            percentileMethod: "inclusive_linear_interpolation_r7",
            positionFormula: "(n - 1) * q",
            rounding: "half_even_to_3_decimal_places",
            quantiles: ["p50": 0.5, "p95": 0.95, "p99": 0.99],
            minimumRepetitions: AppleWorkloadFixture.minimumRepetitions
        )
        let environment = EnvironmentMetadata(
            platform: "synthetic-apple",
            os: "Darwin",
            architecture: EnvironmentMetadataFactory.syntheticHost(for: .macos).architecture,
            device: "not_claimed",
            runtime: "swift-foundation",
            browser: "not_applicable"
        )

        var evidenceRuns: [EvidenceRun] = []
        var traceRuns: [TraceRun] = []
        evidenceRuns.reserveCapacity(workload.operations.count * workload.targetPlatforms.count * 2)
        traceRuns.reserveCapacity(evidenceRuns.capacity)

        var sequence = 0
        for platform in workload.targetPlatforms {
            let runEnvironment = EnvironmentMetadataFactory.syntheticHost(for: platform)
            for operation in workload.operations {
                for state in [BenchmarkState.cold, .warm] {
                    let runID = "\(platform.rawValue)-\(state.rawValue)-\(operation.id)"
                    let repetitions = state == .cold ? workload.repetitions.cold : workload.repetitions.warm
                    guard repetitions >= AppleWorkloadFixture.minimumRepetitions,
                          repetitions <= workload.repetitions.maximum
                    else {
                        throw AppleBenchmarkError.insufficientSamples
                    }

                    var warmupSamples: [Double] = []
                    if state == .warm {
                        warmupSamples = try measure(
                            operation: operation,
                            workload: workload,
                            iteration: sequence,
                            count: workload.warmupRepetitions
                        )
                        sequence += workload.warmupRepetitions
                    }
                    let samples = try measure(
                        operation: operation,
                        workload: workload,
                        iteration: sequence,
                        count: repetitions
                    )
                    sequence += repetitions

                    let distribution = DistributionCalculator.calculate(samples)
                    let command = "offline apple mock workload \(operation.id)"
                    let provisionalRun = EvidenceRun(
                        id: runID,
                        operationID: operation.id,
                        platform: platform,
                        environment: runEnvironment,
                        state: state,
                        buildMode: "release",
                        optimization: "not_applicable",
                        command: command,
                        repetitions: repetitions,
                        rawSamples: samples,
                        sampleProvenanceSHA256: String(repeating: "0", count: 64),
                        distribution: distribution
                    )
                    let provenanceSHA256 = try EvidenceValidator.sampleProvenanceSHA256(for: provisionalRun)
                    evidenceRuns.append(
                        EvidenceRun(
                            id: provisionalRun.id,
                            operationID: provisionalRun.operationID,
                            platform: provisionalRun.platform,
                            environment: provisionalRun.environment,
                            state: provisionalRun.state,
                            buildMode: provisionalRun.buildMode,
                            optimization: provisionalRun.optimization,
                            command: provisionalRun.command,
                            repetitions: provisionalRun.repetitions,
                            rawSamples: provisionalRun.rawSamples,
                            sampleProvenanceSHA256: provenanceSHA256,
                            distribution: provisionalRun.distribution
                        )
                    )
                    traceRuns.append(
                        TraceRun(
                            id: runID,
                            operationID: operation.id,
                            platform: platform,
                            state: state,
                            warmupSamples: warmupSamples,
                            samples: samples
                        )
                    )
                }
            }
        }

        let trace = RawTraceDocument(
            schema: RawTraceDocument.schema,
            fixtureID: workload.fixtureID,
            fixtureVersion: workload.fixtureVersion,
            revision: revision,
            metric: metric,
            build: build,
            environment: environment,
            runs: traceRuns
        )
        let traceBytes = try BenchmarkJSON.encode(trace)
        let artifacts = [
            ArtifactMetadata(
                path: "fixture/workload.json",
                bytes: workloadBytes.count,
                sha256: fixtureSHA256
            ),
            ArtifactMetadata(
                path: "trace/raw-trace.json",
                bytes: traceBytes.count,
                sha256: BenchmarkHash.sha256(traceBytes)
            ),
        ]
        let evidence = AppleEvidenceDocument(
            schema: AppleEvidenceDocument.schema,
            protocolSchema: AppleEvidenceDocument.protocolSchema,
            evidenceID: "apple-release-mock-workload",
            revision: revision,
            metric: metric,
            method: method,
            build: build,
            runs: evidenceRuns,
            artifacts: artifacts,
            artifactManifestSHA256: EvidenceValidator.artifactManifestDigest(artifacts),
            redaction: RedactionMetadata(
                policy: "semantic_only",
                syntheticOnly: true,
                containsCredentials: false,
                containsTokens: false,
                containsUserData: false,
                containsLiveHosts: false,
                containsTranscripts: false
            ),
            threshold: nil,
            budget: nil
        )
        try EvidenceValidator.validate(
            evidence,
            workload: workload,
            fixtureSHA256: fixtureSHA256,
            workloadBytes: workloadBytes,
            traceBytes: traceBytes
        )
        return BenchmarkRunResult(evidence: evidence, trace: trace, traceBytes: traceBytes)
    }

    private func measure(
        operation: WorkloadOperationSpec,
        workload: AppleWorkloadFixture,
        iteration: Int,
        count: Int
    ) throws -> [Double] {
        var samples: [Double] = []
        samples.reserveCapacity(count)
        for offset in 0..<count {
            let start = now()
            let result = try MockWorkloadExecutor.execute(
                operation: operation,
                fixture: workload,
                iteration: iteration + offset
            )
            consumeMockResult(result)
            let end = now()
            guard end > start else {
                throw AppleBenchmarkError.clockNotMonotonic
            }
            let milliseconds = Double(end - start) / 1_000_000.0
            guard milliseconds.isFinite, milliseconds > 0 else {
                throw AppleBenchmarkError.clockNotMonotonic
            }
            samples.append(milliseconds)
        }
        return samples
    }

    private func isCommitSHA(_ value: String) -> Bool {
        value.count == 40 && value.allSatisfy { $0.isHexDigit && $0.isLowercase || $0.isNumber }
    }
}
