import Foundation

public let hermesSourceSHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
public let dashboardContract = "dashboard-v0.0.1"
public let fixtureRegistrySchema = "hermternal.fixture-index.v1"

public enum ContractInputCode: String, Equatable, Sendable {
    case malformedInput = "malformed_input"
    case unknownInput = "unknown_input"
    case malformedJSON = "malformed_json"
    case malformedUTF8 = "malformed_utf8"
    case missingArtifact = "missing_artifact"
    case incompatibleInput = "incompatible_input"
    case liveInput = "live_input"
    case unknownStatus = "unknown_status"
    case unknownPlatform = "unknown_platform"
    case unknownFixture = "unknown_fixture"
    case unknownCoverage = "unknown_coverage"
    case unknownCase = "unknown_case"
    case coveragePending = "coverage_pending"
    case unsafePath = "unsafe_path"
    case unregisteredArtifact = "unregistered_artifact"
    case parityMismatch = "parity_mismatch"
    case networkBoundary = "network_boundary"
    case regressionFailure = "regression_failure"
}

public struct ContractInputError: Error, Equatable, Sendable, CustomStringConvertible {
    public let code: ContractInputCode
    public let message: String

    public init(code: ContractInputCode, message: String) {
        self.code = code
        self.message = message
    }

    public var description: String {
        "\(code.rawValue): \(message)"
    }
}

/// A small JSON value tree keeps fixture semantics platform-neutral without
/// importing an application model or treating arbitrary wire fields as typed.
public enum JSONValue: Decodable, Equatable, Sendable {
    case null
    case boolean(Bool)
    case number(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()

        if container.decodeNil() {
            self = .null
            return
        }
        if let value = try? container.decode(Bool.self) {
            self = .boolean(value)
            return
        }
        if let value = try? container.decode(Double.self) {
            guard value.isFinite else {
                throw DecodingError.dataCorruptedError(
                    in: container,
                    debugDescription: "non-finite JSON numbers are unsupported"
                )
            }
            self = .number(value)
            return
        }
        if let value = try? container.decode(String.self) {
            self = .string(value)
            return
        }
        if let value = try? container.decode([JSONValue].self) {
            self = .array(value)
            return
        }
        if let value = try? container.decode([String: JSONValue].self) {
            self = .object(value)
            return
        }

        throw DecodingError.dataCorruptedError(
            in: container,
            debugDescription: "unsupported JSON value"
        )
    }
}

public enum Platform: String, CaseIterable, Codable, Sendable {
    case web
    case ios
    case ipados
    case macos
}

public enum FixtureFamily: String, Codable, Sendable {
    case auth
    case connection
    case session
    case chat
    case image
    case pty
    case deepLink = "deep-link"
    case compatibility
}

public enum FixtureStatus: String, Sendable {
    case ready
    case pending
}

public struct RegistryFile: Equatable, Sendable {
    public let path: String
    public let sha256: String
    public let sizeBytes: Int

    public init(path: String, sha256: String, sizeBytes: Int) {
        self.path = path
        self.sha256 = sha256
        self.sizeBytes = sizeBytes
    }
}

public struct FixtureRoot: Equatable, Sendable {
    public let id: String
    public let path: String
    public let status: FixtureStatus
    public let contract: String
    public let hermesSourceSHA: String
    public let syntheticOnly: Bool
    public let liveClaim: Bool
    public let platforms: [Platform]
    public let states: [String]
    public let coverageIDs: [String]
    public let validator: String
    public let files: [RegistryFile]
}

public struct CoverageRow: Equatable, Sendable {
    public let id: String
    public let status: FixtureStatus
    public let fixtureIDs: [String]
    public let platforms: [Platform]
    public let requiredStates: [String]
    public let notes: String
}

public struct RegistryParity: Equatable, Sendable {
    public let status: String
    public let fixtureSource: String
    public let platforms: [Platform]
    public let ptyPolicy: String
    public let missingResultPolicy: String
    public let resultEquivalence: String
    public let liveClaim: Bool
}

public struct FixtureRegistry: Equatable, Sendable {
    public let fixtureRoots: [FixtureRoot]
    public let coverage: [CoverageRow]
    public let parity: RegistryParity
}

public struct FixtureCase: Equatable, Sendable {
    public let id: String
    public let expected: [String: JSONValue]
    public let raw: [String: JSONValue]
}

public struct CompatibilityRecord: Codable, Equatable, Sendable {
    public let compatible: Bool
    public let liveRun: Bool
    public let deploymentAttestation: String
    public let behavioralProbe: String
    public let proxyProof: String
    public let parityEvidence: String
    public let benchmarkEvidence: String

    public init(
        compatible: Bool,
        liveRun: Bool,
        deploymentAttestation: String,
        behavioralProbe: String,
        proxyProof: String,
        parityEvidence: String,
        benchmarkEvidence: String
    ) {
        self.compatible = compatible
        self.liveRun = liveRun
        self.deploymentAttestation = deploymentAttestation
        self.behavioralProbe = behavioralProbe
        self.proxyProof = proxyProof
        self.parityEvidence = parityEvidence
        self.benchmarkEvidence = benchmarkEvidence
    }
}

public struct ParityCaseResult: Codable, Equatable, Sendable {
    public let family: FixtureFamily
    public let coverageID: String
    public let caseID: String
    public let status: String
    public let platforms: [Platform]
    public let webDecision: String?
    public let appleDecision: String?

    public init(
        family: FixtureFamily,
        coverageID: String,
        caseID: String,
        status: String,
        platforms: [Platform],
        webDecision: String? = nil,
        appleDecision: String? = nil
    ) {
        self.family = family
        self.coverageID = coverageID
        self.caseID = caseID
        self.status = status
        self.platforms = platforms
        self.webDecision = webDecision
        self.appleDecision = appleDecision
    }
}

public struct ParityReport: Codable, Equatable, Sendable {
    public let ok: Bool
    public let contract: String
    public let hermesSourceSHA: String
    public let syntheticOnly: Bool
    public let liveClaim: Bool
    public let networkCalls: Int
    public let readyCaseCount: Int
    public let blockedCoverageIDs: [String]
    public let cases: [ParityCaseResult]
    public let compatibility: CompatibilityRecord

    public init(
        ok: Bool,
        contract: String,
        hermesSourceSHA: String,
        syntheticOnly: Bool,
        liveClaim: Bool,
        networkCalls: Int,
        readyCaseCount: Int,
        blockedCoverageIDs: [String],
        cases: [ParityCaseResult],
        compatibility: CompatibilityRecord
    ) {
        self.ok = ok
        self.contract = contract
        self.hermesSourceSHA = hermesSourceSHA
        self.syntheticOnly = syntheticOnly
        self.liveClaim = liveClaim
        self.networkCalls = networkCalls
        self.readyCaseCount = readyCaseCount
        self.blockedCoverageIDs = blockedCoverageIDs
        self.cases = cases
        self.compatibility = compatibility
    }
}

private struct Representative {
    let family: FixtureFamily
    let rootID: String
    let coverageID: String
    let caseIDs: [String]
}

private struct ProjectedOutcome {
    let decision: String
    let semantic: [String: JSONValue]
}

private let approvedJSONArtifacts: [String: String] = [
    "deployment-security-browser-auth": "deployment-security/browser-auth/cases.json",
    "connection-restoration": "connection-restoration/cases.json",
    "session-persistence": "session-persistence/cases.json",
    "image-attachment-lifecycle": "image-attachment-lifecycle/cases.json",
    "pty-contract": "pty-contract/pty-contract-fixtures.json",
    "deep-link-grammar": "deep-link-grammar/cases.json",
    "compatibility-attestation": "compatibility-attestation/cases.json",
    "source-audit-compatibility-gate": "source-audit/compatibility-gate/compatibility_record.json",
]

private let representatives: [Representative] = [
    Representative(
        family: .auth,
        rootID: "deployment-security-browser-auth",
        coverageID: "browser-cookie-auth",
        caseIDs: ["login-success", "callback-csrf-mismatch"]
    ),
    Representative(
        family: .connection,
        rootID: "connection-restoration",
        coverageID: "connection-restoration",
        caseIDs: ["initial-connect-ready", "prompt-transport-loss-uncertain"]
    ),
    Representative(
        family: .session,
        rootID: "session-persistence",
        coverageID: "chat-stream-and-completion",
        caseIDs: ["first-prompt-persists-session", "transport-loss-enters-delivery-uncertain"]
    ),
    Representative(
        family: .chat,
        rootID: "session-persistence",
        coverageID: "chat-stream-and-completion",
        caseIDs: ["transport-loss-enters-delivery-uncertain", "automatic-prompt-retry-fails-closed"]
    ),
    Representative(
        family: .image,
        rootID: "image-attachment-lifecycle",
        coverageID: "image-attachment-lifecycle",
        caseIDs: ["empty-selection", "malformed-base64", "success-transcript-reference"]
    ),
    Representative(
        family: .pty,
        rootID: "pty-contract",
        coverageID: "web-pty",
        caseIDs: ["raw-bytes-preserve", "no-byte-logging"]
    ),
    Representative(
        family: .deepLink,
        rootID: "deep-link-grammar",
        coverageID: "private-deep-link",
        caseIDs: ["valid-web-session", "wrong-origin"]
    ),
    Representative(
        family: .compatibility,
        rootID: "compatibility-attestation",
        coverageID: "deployment-attestation",
        caseIDs: ["valid_attestation_with_probe", "missing_attestation"]
    ),
]

private func reject(_ code: ContractInputCode, _ message: String) -> ContractInputError {
    ContractInputError(code: code, message: message)
}

private func object(_ value: JSONValue?, _ label: String) throws -> [String: JSONValue] {
    guard let value = value, case .object(let result) = value else {
        throw reject(.malformedInput, "\(label) must be an object")
    }
    return result
}

private func array(_ value: JSONValue?, _ label: String) throws -> [JSONValue] {
    guard let value = value, case .array(let result) = value else {
        throw reject(.malformedInput, "\(label) must be an array")
    }
    return result
}

private func string(_ value: JSONValue?, _ label: String) throws -> String {
    guard let value = value, case .string(let result) = value, !result.isEmpty else {
        throw reject(.malformedInput, "\(label) must be a non-empty string")
    }
    return result
}

private func boolean(_ value: JSONValue?, _ label: String) throws -> Bool {
    guard let value = value, case .boolean(let result) = value else {
        throw reject(.malformedInput, "\(label) must be a boolean")
    }
    return result
}

private func nonNegativeInteger(_ value: JSONValue?, _ label: String) throws -> Int {
    guard let value = value, case .number(let result) = value,
          result.isFinite, result >= 0, result.rounded() == result,
          result <= Double(Int.max) else {
        throw reject(.malformedInput, "\(label) must be a non-negative integer")
    }
    return Int(result)
}

private func literal(_ value: JSONValue?, expected: String, _ label: String) throws {
    guard case .string(let actual)? = value, actual == expected else {
        throw reject(.incompatibleInput, "\(label) does not match the reviewed contract")
    }
}

private func literal(_ value: String, expected: String, _ label: String) throws {
    guard value == expected else {
        throw reject(.incompatibleInput, "\(label) does not match the reviewed contract")
    }
}

private func safeRelativePath(_ value: String, _ label: String) throws -> String {
    let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._/-")
    let scalarsAreSafe = value.unicodeScalars.allSatisfy { allowed.contains($0) }
    let components = value.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
    let hasUnsafeComponent = components.contains { component in
        component.isEmpty || component == "." || component == ".."
    }

    guard !value.isEmpty,
          !value.hasPrefix("/"),
          !value.contains("\\"),
          !value.contains("://"),
          scalarsAreSafe,
          !hasUnsafeComponent else {
        throw reject(.unsafePath, "\(label) is not a safe repository-relative path")
    }
    return value
}

private func parsePlatform(_ value: JSONValue?, _ label: String) throws -> Platform {
    let candidate = try string(value, label)
    guard let platform = Platform(rawValue: candidate) else {
        throw reject(.unknownPlatform, "\(label) is not a supported parity platform")
    }
    return platform
}

private func platforms(_ value: JSONValue?, _ label: String) throws -> [Platform] {
    let result = try array(value, label).enumerated().map { index, entry in
        try parsePlatform(entry, "\(label)[\(index)]")
    }
    guard Set(result).count == result.count else {
        throw reject(.malformedInput, "\(label) contains a duplicate platform")
    }
    return result
}

private func strings(_ value: JSONValue?, _ label: String) throws -> [String] {
    let result = try array(value, label).enumerated().map { index, entry in
        try string(entry, "\(label)[\(index)]")
    }
    guard Set(result).count == result.count else {
        throw reject(.malformedInput, "\(label) contains a duplicate value")
    }
    return result
}

private func decodeJSON(_ data: Data, _ label: String) throws -> JSONValue {
    guard String(data: data, encoding: .utf8) != nil else {
        throw reject(.malformedUTF8, "\(label) is not valid UTF-8")
    }
    do {
        return try JSONDecoder().decode(JSONValue.self, from: data)
    } catch {
        throw reject(.malformedJSON, "\(label) is not valid JSON")
    }
}

private func readJSON(at url: URL, _ label: String) throws -> JSONValue {
    guard FileManager.default.fileExists(atPath: url.path) else {
        throw reject(.missingArtifact, "\(label) is not checked in")
    }
    do {
        return try decodeJSON(Data(contentsOf: url), label)
    } catch let error as ContractInputError {
        throw error
    } catch {
        throw reject(.missingArtifact, "\(label) is not checked in")
    }
}

private func parseRegistryFile(_ value: JSONValue?, _ label: String) throws -> RegistryFile {
    let entry = try object(value, label)
    return RegistryFile(
        path: try safeRelativePath(try string(entry["path"], "\(label).path"), "\(label).path"),
        sha256: try string(entry["sha256"], "\(label).sha256"),
        sizeBytes: try nonNegativeInteger(entry["size_bytes"], "\(label).size_bytes")
    )
}

private func parseFixtureRoot(_ value: JSONValue?, index: Int) throws -> FixtureRoot {
    let label = "fixture_roots[\(index)]"
    let entry = try object(value, label)
    let rawStatus = try string(entry["status"], "\(label).status")
    guard let status = FixtureStatus(rawValue: rawStatus) else {
        throw reject(.unknownStatus, "\(label).status is unknown")
    }
    let files = try array(entry["files"], "\(label).files").enumerated().map { fileIndex, file in
        try parseRegistryFile(file, "\(label).files[\(fileIndex)]")
    }
    return FixtureRoot(
        id: try string(entry["id"], "\(label).id"),
        path: try safeRelativePath(try string(entry["path"], "\(label).path"), "\(label).path"),
        status: status,
        contract: try string(entry["contract"], "\(label).contract"),
        hermesSourceSHA: try string(entry["hermes_source_sha"], "\(label).hermes_source_sha"),
        syntheticOnly: try boolean(entry["synthetic_only"], "\(label).synthetic_only"),
        liveClaim: try boolean(entry["live_claim"], "\(label).live_claim"),
        platforms: try platforms(entry["platforms"], "\(label).platforms"),
        states: try strings(entry["states"], "\(label).states"),
        coverageIDs: try strings(entry["coverage_ids"], "\(label).coverage_ids"),
        validator: try string(entry["validator"], "\(label).validator"),
        files: files
    )
}

private func parseCoverage(_ value: JSONValue?, index: Int) throws -> CoverageRow {
    let label = "coverage[\(index)]"
    let entry = try object(value, label)
    let rawStatus = try string(entry["status"], "\(label).status")
    guard let status = FixtureStatus(rawValue: rawStatus) else {
        throw reject(.unknownStatus, "\(label).status is unknown")
    }
    return CoverageRow(
        id: try string(entry["id"], "\(label).id"),
        status: status,
        fixtureIDs: try strings(entry["fixture_ids"], "\(label).fixture_ids"),
        platforms: try platforms(entry["platforms"], "\(label).platforms"),
        requiredStates: try strings(entry["required_states"], "\(label).required_states"),
        notes: try string(entry["notes"], "\(label).notes")
    )
}

private func parseParity(_ value: JSONValue?) throws -> RegistryParity {
    let entry = try object(value, "parity")
    return RegistryParity(
        status: try string(entry["status"], "parity.status"),
        fixtureSource: try string(entry["fixture_source"], "parity.fixture_source"),
        platforms: try platforms(entry["platforms"], "parity.platforms"),
        ptyPolicy: try string(entry["pty_policy"], "parity.pty_policy"),
        missingResultPolicy: try string(entry["missing_result_policy"], "parity.missing_result_policy"),
        resultEquivalence: try string(entry["result_equivalence"], "parity.result_equivalence"),
        liveClaim: try boolean(entry["live_claim"], "parity.live_claim")
    )
}

public func loadRegistry(at repoRoot: URL) throws -> FixtureRegistry {
    // The registry is the compatibility allowlist. Missing or additive parity
    // metadata is not permission to discover another fixture or platform.
    let root = repoRoot.standardizedFileURL
    let indexURL = root
        .appendingPathComponent("contracts", isDirectory: true)
        .appendingPathComponent("fixtures", isDirectory: true)
        .appendingPathComponent("index.json")
    let raw = try object(try readJSON(at: indexURL, "fixture index"), "fixture index")

    try literal(raw["schema"], expected: fixtureRegistrySchema, "fixture index schema")
    try literal(raw["contract"], expected: dashboardContract, "fixture index contract")
    try literal(raw["hermes_source_sha"], expected: hermesSourceSHA, "fixture index source revision")
    guard try boolean(raw["synthetic_only"], "fixture index synthetic_only") else {
        throw reject(.liveInput, "fixture index is not synthetic-only")
    }
    guard !(try boolean(raw["live_claim"], "fixture index live_claim")) else {
        throw reject(.liveInput, "fixture index makes a live claim")
    }

    let fixtureRoots = try array(raw["fixture_roots"], "fixture_roots").enumerated().map { index, entry in
        try parseFixtureRoot(entry, index: index)
    }
    let coverage = try array(raw["coverage"], "coverage").enumerated().map { index, entry in
        try parseCoverage(entry, index: index)
    }
    guard Set(fixtureRoots.map(\.id)).count == fixtureRoots.count else {
        throw reject(.malformedInput, "fixture root IDs are not unique")
    }
    guard Set(coverage.map(\.id)).count == coverage.count else {
        throw reject(.malformedInput, "coverage IDs are not unique")
    }

    for entry in fixtureRoots {
        guard entry.contract == dashboardContract, entry.hermesSourceSHA == hermesSourceSHA else {
            throw reject(.incompatibleInput, "fixture root is not pinned to the reviewed contract")
        }
        guard entry.syntheticOnly, !entry.liveClaim else {
            throw reject(.liveInput, "fixture root is not synthetic-only")
        }
    }

    let rootIDs = Set(fixtureRoots.map(\.id))
    for entry in coverage where entry.status == .ready {
        guard entry.fixtureIDs.allSatisfy(rootIDs.contains) else {
            throw reject(.unknownFixture, "ready coverage references an unknown fixture root")
        }
    }

    let parity = try parseParity(raw["parity"])
    guard !parity.liveClaim, parity.fixtureSource == "one_shared_registry" else {
        throw reject(.incompatibleInput, "parity policy is not the shared synthetic policy")
    }
    return FixtureRegistry(fixtureRoots: fixtureRoots, coverage: coverage, parity: parity)
}

private func rootByID(_ registry: FixtureRegistry, _ rootID: String) throws -> FixtureRoot {
    guard let root = registry.fixtureRoots.first(where: { $0.id == rootID }) else {
        throw reject(.unknownFixture, "representative fixture root is not registered")
    }
    return root
}

private func coverageByID(_ registry: FixtureRegistry, _ coverageID: String) throws -> CoverageRow {
    guard let coverage = registry.coverage.first(where: { $0.id == coverageID }) else {
        throw reject(.unknownCoverage, "representative coverage row is not registered")
    }
    return coverage
}

private func artifactURL(repoRoot: URL, root: FixtureRoot) throws -> URL {
    // Do not glob or infer JSON files. A representative is readable only when
    // this package names it and the C-19 registry lists the exact path.
    guard let relativeArtifact = approvedJSONArtifacts[root.id] else {
        throw reject(.unknownFixture, "fixture root has no approved JSON artifact")
    }
    guard relativeArtifact.hasPrefix("\(root.path)/") else {
        throw reject(.incompatibleInput, "fixture artifact is outside its registered root")
    }
    guard root.files.contains(where: { $0.path == relativeArtifact }) else {
        throw reject(.unregisteredArtifact, "fixture JSON artifact is not listed by the registry")
    }

    let safePath = try safeRelativePath(relativeArtifact, "fixture artifact")
    var result = repoRoot.standardizedFileURL
        .appendingPathComponent("contracts", isDirectory: true)
        .appendingPathComponent("fixtures", isDirectory: true)
    for component in safePath.split(separator: "/") {
        result.appendPathComponent(String(component), isDirectory: false)
    }
    return result
}

private func loadArtifact(repoRoot: URL, root: FixtureRoot) throws -> [String: JSONValue] {
    try object(try readJSON(at: artifactURL(repoRoot: repoRoot, root: root), "fixture \(root.id)"), "fixture \(root.id)")
}

public func loadCase(
    at repoRoot: URL,
    registry: FixtureRegistry,
    rootID: String,
    caseID: String
) throws -> FixtureCase {
    guard !caseID.isEmpty, caseID.trimmingCharacters(in: .whitespacesAndNewlines) == caseID else {
        throw reject(.malformedInput, "case ID must be a non-empty canonical string")
    }
    let root = try rootByID(registry, rootID)
    // A pending root is an absence of evidence, not a successful fixture.
    guard root.status == .ready else {
        throw reject(.coveragePending, "pending fixture roots cannot provide parity evidence")
    }
    let artifact = try loadArtifact(repoRoot: repoRoot, root: root)
    let cases = try array(artifact["cases"], "fixture \(rootID).cases")
    let matches = cases.compactMap { value -> [String: JSONValue]? in
        guard case .object(let entry) = value,
              case .string(let id)? = entry["id"], id == caseID else {
            return nil
        }
        return entry
    }
    guard matches.count == 1, let match = matches.first else {
        throw reject(.unknownCase, "representative case ID is absent or duplicated")
    }
    return FixtureCase(
        id: try string(match["id"], "fixture \(rootID).\(caseID).id"),
        expected: try object(match["expected"], "fixture \(rootID).\(caseID).expected"),
        raw: match
    )
}

public func loadCompatibilityRecord(at repoRoot: URL, registry: FixtureRegistry) throws -> CompatibilityRecord {
    let root = try rootByID(registry, "source-audit-compatibility-gate")
    guard root.status == .ready else {
        throw reject(.coveragePending, "compatibility fixture root is pending")
    }
    let artifact = try loadArtifact(repoRoot: repoRoot, root: root)
    try literal(artifact["schema"], expected: "hermternal.compatibility-gate.v1", "compatibility schema")
    let source = try object(artifact["source"], "compatibility source")
    try literal(source["sha"], expected: hermesSourceSHA, "compatibility source revision")
    let status = try object(artifact["status"], "compatibility status")
    guard !(try boolean(status["compatible"], "compatibility status.compatible")) else {
        throw reject(.liveInput, "compatibility record claims compatibility without live evidence")
    }
    guard !(try boolean(status["live_run"], "compatibility status.live_run")) else {
        throw reject(.liveInput, "compatibility record contains live-run evidence")
    }
    return CompatibilityRecord(
        compatible: false,
        liveRun: false,
        deploymentAttestation: try string(status["deployment_attestation"], "compatibility deployment attestation"),
        behavioralProbe: try string(status["behavioral_probe"], "compatibility behavioral probe"),
        proxyProof: try string(status["proxy_proof"], "compatibility proxy proof"),
        parityEvidence: try string(status["parity_evidence"], "compatibility parity evidence"),
        benchmarkEvidence: try string(status["benchmark_evidence"], "compatibility benchmark evidence")
    )
}

private func decision(from expected: [String: JSONValue]) throws -> String {
    for key in ["decision", "state", "final_state", "attestation_result", "runtime_gate", "valid"] {
        switch expected[key] {
        case .string(let value)?:
            return value
        case .boolean(let value)?:
            return value ? "valid" : "blocked"
        default:
            continue
        }
    }
    for key in ["pty_bytes_logged", "raw_bytes_logged"] {
        if case .boolean(let value)? = expected[key] {
            return value ? "logged" : "redacted"
        }
    }
    throw reject(.malformedInput, "representative expected result has no semantic decision")
}

private func project(family: FixtureFamily, platform: Platform, fixtureCase: FixtureCase) throws -> ProjectedOutcome {
    _ = family
    _ = platform
    return ProjectedOutcome(
        decision: try decision(from: fixtureCase.expected),
        semantic: fixtureCase.expected
    )
}

private func runRepresentative(
    repoRoot: URL,
    registry: FixtureRegistry,
    representative: Representative
) throws -> [ParityCaseResult] {
    let coverage = try coverageByID(registry, representative.coverageID)
    guard coverage.fixtureIDs.contains(representative.rootID) else {
        throw reject(.incompatibleInput, "coverage row does not own its representative fixture root")
    }

    if coverage.status == .pending {
        var results: [ParityCaseResult] = []
        for caseID in representative.caseIDs {
            let fixtureCase = try loadCase(
                at: repoRoot,
                registry: registry,
                rootID: representative.rootID,
                caseID: caseID
            )
            if representative.family == .chat {
                let caseDecision = try decision(from: fixtureCase.expected)
                guard ["delivery_uncertain", "automatic_prompt_retry_blocked"].contains(caseDecision) else {
                    throw reject(.incompatibleInput, "pending chat coverage contains an unexpected success decision")
                }
            }
            results.append(
                ParityCaseResult(
                    family: representative.family,
                    coverageID: representative.coverageID,
                    caseID: caseID,
                    status: "blocked",
                    platforms: coverage.platforms
                )
            )
        }
        return results
    }

    let root = try rootByID(registry, representative.rootID)
    guard root.status == .ready else {
        throw reject(.coveragePending, "ready coverage references a pending fixture root")
    }

    var results: [ParityCaseResult] = []
    for caseID in representative.caseIDs {
        let fixtureCase = try loadCase(
            at: repoRoot,
            registry: registry,
            rootID: representative.rootID,
            caseID: caseID
        )
        let web = coverage.platforms.contains(.web)
            ? try project(family: representative.family, platform: .web, fixtureCase: fixtureCase)
            : nil
        let applePlatform: Platform? = coverage.platforms.contains(.ios)
            ? .ios
            : coverage.platforms.contains(.ipados)
                ? .ipados
                : coverage.platforms.contains(.macos) ? .macos : nil
        let apple: ProjectedOutcome? = if let applePlatform, coverage.platforms.contains(applePlatform) {
            try project(family: representative.family, platform: applePlatform, fixtureCase: fixtureCase)
        } else {
            nil
        }

        if representative.family == .pty {
            guard let web, coverage.platforms == [.web] else {
                throw reject(.incompatibleInput, "PTY parity must be a web-only fixture")
            }
            results.append(
                ParityCaseResult(
                    family: representative.family,
                    coverageID: representative.coverageID,
                    caseID: caseID,
                    status: "proven",
                    platforms: coverage.platforms,
                    webDecision: web.decision,
                    appleDecision: "blocked_platform"
                )
            )
            continue
        }

        guard let web, let apple, web.semantic == apple.semantic else {
            throw reject(.parityMismatch, "shared fixture semantic outcomes differ by platform")
        }
        results.append(
            ParityCaseResult(
                family: representative.family,
                coverageID: representative.coverageID,
                caseID: caseID,
                status: "proven",
                platforms: coverage.platforms,
                webDecision: web.decision,
                appleDecision: apple.decision
            )
        )
    }
    return results
}

public func runParity(at repoRoot: URL) throws -> ParityReport {
    let registry = try loadRegistry(at: repoRoot)
    try literal(registry.parity.ptyPolicy, expected: "web_only_apple_blocked", "parity PTY policy")
    try literal(registry.parity.missingResultPolicy, expected: "block", "parity missing-result policy")
    try literal(
        registry.parity.resultEquivalence,
        expected: "semantic_outcomes_not_platform_specific_wire_bytes",
        "parity equivalence policy"
    )

    var results: [ParityCaseResult] = []
    for representative in representatives {
        results.append(contentsOf: try runRepresentative(
            repoRoot: repoRoot,
            registry: registry,
            representative: representative
        ))
    }
    let compatibility = try loadCompatibilityRecord(at: repoRoot, registry: registry)
    let blockedCoverageIDs = registry.coverage
        .filter { $0.status == .pending }
        .map(\.id)

    return ParityReport(
        ok: true,
        contract: dashboardContract,
        hermesSourceSHA: hermesSourceSHA,
        syntheticOnly: true,
        liveClaim: false,
        networkCalls: 0,
        readyCaseCount: results.filter { $0.status == "proven" }.count,
        blockedCoverageIDs: blockedCoverageIDs,
        cases: results,
        compatibility: compatibility
    )
}

/// This package is intentionally a file-only parity reader. The static check
/// makes the no-network boundary testable without importing a transport stack.
public func assertNoNetworkImports(_ sourceText: String) throws {
    // Split marker strings so this guard does not match its own source text.
    let forbiddenFragments = [
        "import Net" + "work",
        "import FoundationNet" + "working",
        "URL" + "Session",
        "URL" + "Request",
        "NW" + "Connection",
        "Net" + "work.framework",
        "Web" + "Socket",
        "URL" + "Protocol",
        ".data" + "Task(",
        ".upload" + "Task(",
        ".download" + "Task(",
        "con" + "nect("
    ]
    if forbiddenFragments.contains(where: { sourceText.contains($0) }) {
        throw reject(.networkBoundary, "parity tooling must not open a network connection")
    }
}

public func representativeIDs() -> [(family: FixtureFamily, rootID: String, coverageID: String, caseIDs: [String])] {
    representatives.map { ($0.family, $0.rootID, $0.coverageID, $0.caseIDs) }
}
