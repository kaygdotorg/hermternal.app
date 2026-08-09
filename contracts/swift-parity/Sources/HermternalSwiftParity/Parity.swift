import Foundation
import CryptoKit
import Dispatch
#if canImport(Darwin)
import Darwin
#endif

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
    case artifactIntegrity = "artifact_integrity"
    case parityMismatch = "parity_mismatch"
    case networkBoundary = "network_boundary"
    case regressionFailure = "regression_failure"
}

public struct ContractInputError: Error, Equatable, Sendable, CustomStringConvertible {
    public let code: ContractInputCode
    public let message: String

    public init(code: ContractInputCode, message: String) {
        self.code = code
        self.message = String(message.prefix(ParityBounds.maxErrorMessageLength))
    }

    public var description: String {
        "\(code.rawValue): \(message)"
    }
}

/// The parity reader's limits are deliberately small enough for checked-in
/// evidence and large enough to avoid making a fixture inventory a memory or
/// CPU budget. Descriptor reads enforce these limits before decoding bytes.
public enum ParityBounds {
    public static let maxJSONBytes = 512 * 1024
    public static let maxArtifactBytes = 512 * 1024
    public static let maxTotalArtifactBytes = 8 * 1024 * 1024
    public static let maxJSONDepth = 64
    public static let maxJSONNodes = 200_000
    public static let maxJSONStringLength = 4_096
    public static let maxJSONKeyLength = 256
    public static let maxIntegerDigits = 100
    public static let maxNumberLength = 256
    public static let maxInventoryFiles = 512
    public static let maxCaseCount = 512
    public static let maxCaseIDLength = 120
    public static let maxErrorMessageLength = 240
    public static let maxOutputBytes = 64 * 1024
    public static let maxReadDurationNanoseconds: UInt64 = 2_000_000_000
    public static let maxPreflightDurationNanoseconds: UInt64 = 5_000_000_000
    public static let maxPreflightOutputBytes = 16 * 1024
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

public enum CoverageStatus: String, CaseIterable, Sendable {
    case ready
    case pending
    case empty
    case failure
    case cancelled
    case unknown
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
    public let validator: String?
    public let files: [RegistryFile]
}

public struct CoverageRow: Equatable, Sendable {
    public let id: String
    public let status: CoverageStatus
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
    public let status: String
    public let errorCode: String?
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
        status: String,
        errorCode: String? = nil,
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
        self.status = status
        self.errorCode = errorCode
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

struct ProjectedOutcome {
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
    guard let value = value, case .object(let result) = value,
          result.count <= ParityBounds.maxJSONNodes else {
        throw reject(.malformedInput, "\(label) must be a bounded object")
    }
    return result
}

private func array(_ value: JSONValue?, _ label: String) throws -> [JSONValue] {
    guard let value = value, case .array(let result) = value,
          result.count <= ParityBounds.maxJSONNodes else {
        throw reject(.malformedInput, "\(label) must be a bounded array")
    }
    return result
}

private func string(_ value: JSONValue?, _ label: String) throws -> String {
    guard let value = value, case .string(let result) = value,
          !result.isEmpty,
          result.count <= ParityBounds.maxJSONStringLength,
          !result.contains("\\0") else {
        throw reject(.malformedInput, "\(label) must be a bounded non-empty string")
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
          value.count <= 240,
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

#if canImport(Darwin)
private struct FileIdentity: Equatable {
    let device: UInt64
    let inode: UInt64
    let size: Int64

    init(_ metadata: stat) throws {
        guard metadata.st_size >= 0 else {
            throw reject(.artifactIntegrity, "regular-file size is invalid")
        }
        device = UInt64(metadata.st_dev)
        inode = UInt64(metadata.st_ino)
        size = Int64(metadata.st_size)
    }
}

private func descriptorError(_ code: ContractInputCode, _ message: String) -> ContractInputError {
    reject(code, message)
}

private func openRootDescriptor(at url: URL) throws -> Int32 {
    let absolute = url.path.hasPrefix("/")
        ? url.standardizedFileURL
        : URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
            .appendingPathComponent(url.path, isDirectory: true)
            .standardizedFileURL
    guard absolute.path.hasPrefix("/") else {
        throw descriptorError(.unsafePath, "repository root must be absolute")
    }
    // macOS exposes /tmp and /var as stable host aliases to /private. Map only
    // those documented aliases; every repository and fixture component still
    // crosses a held descriptor with O_NOFOLLOW.
    let rootPath: String
    if absolute.path == "/tmp" || absolute.path.hasPrefix("/tmp/") {
        rootPath = "/private\(absolute.path)"
    } else if absolute.path == "/var" || absolute.path.hasPrefix("/var/") {
        rootPath = "/private\(absolute.path)"
    } else {
        rootPath = absolute.path
    }

    let root = Darwin.open(
        "/",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
    )
    guard root >= 0 else {
        throw descriptorError(.missingArtifact, "repository root is not readable")
    }
    var current = root
    do {
        for component in rootPath.split(separator: "/") {
            let next = component.withCString {
                Darwin.openat(
                    current,
                    $0,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
                )
            }
            guard next >= 0 else {
                throw descriptorError(.missingArtifact, "repository root is not readable")
            }
            Darwin.close(current)
            current = next
        }
        return current
    } catch {
        Darwin.close(current)
        throw error
    }
}

private func openRelativeRegularFile(
    repoRoot: URL,
    relativePath: String
) throws -> (file: Int32, parent: Int32, leaf: String) {
    let safePath = try safeRelativePath(relativePath, "artifact path")
    let components = safePath.split(separator: "/").map(String.init)
    guard let leaf = components.last else {
        throw descriptorError(.unsafePath, "artifact path is empty")
    }

    var parent = try openRootDescriptor(at: repoRoot)
    do {
        for component in components.dropLast() {
            let next = component.withCString {
                Darwin.openat(
                    parent,
                    $0,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
                )
            }
            guard next >= 0 else {
                throw descriptorError(.missingArtifact, "artifact directory is not readable")
            }
            Darwin.close(parent)
            parent = next
        }
        let file = leaf.withCString {
            Darwin.openat(parent, $0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        }
        guard file >= 0 else {
            throw descriptorError(.missingArtifact, "artifact is not checked in")
        }
        return (file, parent, leaf)
    } catch {
        Darwin.close(parent)
        throw error
    }
}

private func regularFileIdentity(_ descriptor: Int32) throws -> FileIdentity {
    var metadata = stat()
    guard Darwin.fstat(descriptor, &metadata) == 0 else {
        throw descriptorError(.missingArtifact, "artifact metadata is not readable")
    }
    guard (metadata.st_mode & S_IFMT) == S_IFREG else {
        throw descriptorError(.artifactIntegrity, "artifact is not a regular file")
    }
    return try FileIdentity(metadata)
}

private func readRegularFile(
    repoRoot: URL,
    relativePath: String,
    label: String,
    maxBytes: Int,
    expected: RegistryFile? = nil,
    beforeFinalReopen: (() throws -> Void)? = nil
) throws -> Data {
    let opened = try openRelativeRegularFile(repoRoot: repoRoot, relativePath: relativePath)
    defer {
        Darwin.close(opened.file)
        Darwin.close(opened.parent)
    }

    let before = try regularFileIdentity(opened.file)
    guard before.size <= Int64(maxBytes) else {
        throw reject(.malformedInput, "\(label) exceeds the byte limit")
    }
    if let expected {
        guard before.size == Int64(expected.sizeBytes) else {
            throw reject(.artifactIntegrity, "\(label) size does not match its registry binding")
        }
    }

    let deadline = DispatchTime.now().uptimeNanoseconds + ParityBounds.maxReadDurationNanoseconds
    var bytes = Data()
    bytes.reserveCapacity(Int(before.size))
    var buffer = [UInt8](repeating: 0, count: 64 * 1024)
    // Regular files should not report EAGAIN, but bounded retries keep the
    // non-blocking descriptor contract fail-closed under transient host errors.
    var transientReadFailures = 0
    while true {
        guard DispatchTime.now().uptimeNanoseconds <= deadline else {
            throw reject(.malformedInput, "\(label) read exceeded the time limit")
        }
        let count = buffer.withUnsafeMutableBytes { storage -> Int in
            guard let baseAddress = storage.baseAddress else { return 0 }
            return Darwin.read(opened.file, baseAddress, storage.count)
        }
        if count < 0 {
            let readError = errno
            guard readError == EINTR || readError == EAGAIN else {
                throw reject(.missingArtifact, "\(label) could not be read")
            }
            transientReadFailures += 1
            guard transientReadFailures <= 128,
                  DispatchTime.now().uptimeNanoseconds <= deadline else {
                throw reject(.malformedInput, "\(label) read exceeded the time limit")
            }
            if readError == EAGAIN {
                usleep(1_000)
            }
            continue
        }
        transientReadFailures = 0
        if count == 0 { break }
        bytes.append(contentsOf: buffer.prefix(count))
        guard bytes.count <= maxBytes else {
            throw reject(.malformedInput, "\(label) exceeds the byte limit")
        }
    }
    let directAfter = try regularFileIdentity(opened.file)
    guard directAfter == before, bytes.count == Int(before.size) else {
        throw reject(.artifactIntegrity, "\(label) changed while it was read")
    }

    try beforeFinalReopen?()
    let reopened = opened.leaf.withCString {
        Darwin.openat(opened.parent, $0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
    }
    guard reopened >= 0 else {
        throw reject(.artifactIntegrity, "\(label) was replaced while it was read")
    }
    defer { Darwin.close(reopened) }
    let pathAfter = try regularFileIdentity(reopened)
    guard pathAfter == before else {
        throw reject(.artifactIntegrity, "\(label) was replaced while it was read")
    }

    if let expected {
        guard expected.sizeBytes == bytes.count else {
            throw reject(.artifactIntegrity, "\(label) size does not match its registry binding")
        }
        guard sha256Hex(bytes) == expected.sha256 else {
            throw reject(.artifactIntegrity, "\(label) digest does not match its registry binding")
        }
    }
    return bytes
}
#else
private func readRegularFile(
    repoRoot: URL,
    relativePath: String,
    label: String,
    maxBytes: Int,
    expected: RegistryFile? = nil,
    beforeFinalReopen: (() throws -> Void)? = nil
) throws -> Data {
    _ = repoRoot
    _ = relativePath
    _ = maxBytes
    _ = expected
    _ = beforeFinalReopen
    throw reject(.missingArtifact, "\(label) requires a host descriptor reader")
}
#endif

private func sha256Hex(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

private struct StrictJSONParser {
    private let bytes: [UInt8]
    private let label: String
    private var index = 0
    private var nodeCount = 0
    private let deadline: UInt64

    init(data: Data, label: String) {
        self.bytes = Array(data)
        self.label = label
        self.deadline = DispatchTime.now().uptimeNanoseconds + ParityBounds.maxReadDurationNanoseconds
    }

    private func rejectJSON() -> ContractInputError {
        reject(.malformedJSON, "\(label) is not valid JSON")
    }

    private mutating func checkBudget(depth: Int) throws {
        guard DispatchTime.now().uptimeNanoseconds <= deadline else {
            throw reject(.malformedInput, "\(label) parse exceeded the time limit")
        }
        guard depth <= ParityBounds.maxJSONDepth else {
            throw reject(.malformedInput, "\(label) exceeds the JSON depth limit")
        }
        nodeCount += 1
        guard nodeCount <= ParityBounds.maxJSONNodes else {
            throw reject(.malformedInput, "\(label) exceeds the JSON node limit")
        }
    }

    private mutating func skipWhitespace() {
        while index < bytes.count && [0x20, 0x09, 0x0A, 0x0D].contains(bytes[index]) {
            index += 1
        }
    }

    private mutating func consume(_ byte: UInt8) -> Bool {
        guard index < bytes.count, bytes[index] == byte else { return false }
        index += 1
        return true
    }

    private mutating func parseString() throws -> String {
        guard consume(0x22) else { throw rejectJSON() }
        let tokenStart = index - 1
        var escaped = false
        while index < bytes.count {
            let byte = bytes[index]
            index += 1
            if byte < 0x20 && !escaped {
                throw rejectJSON()
            }
            if escaped {
                escaped = false
                continue
            }
            if byte == 0x5C {
                escaped = true
                continue
            }
            if byte == 0x22 {
                let token = Data(bytes[tokenStart..<index])
                guard let value = try? JSONSerialization.jsonObject(with: token, options: [.fragmentsAllowed]) as? String,
                      value.count <= ParityBounds.maxJSONStringLength,
                      !value.contains("\\0") else {
                    throw rejectJSON()
                }
                return value
            }
        }
        throw rejectJSON()
    }

    private mutating func parseNumber() throws -> JSONValue {
        let start = index
        if consume(0x2D) { }
        guard index < bytes.count else { throw rejectJSON() }
        if bytes[index] == 0x30 {
            index += 1
        } else {
            guard bytes[index] >= 0x31 && bytes[index] <= 0x39 else { throw rejectJSON() }
            while index < bytes.count, bytes[index] >= 0x30 && bytes[index] <= 0x39 {
                index += 1
            }
        }
        var isInteger = true
        if consume(0x2E) {
            isInteger = false
            guard index < bytes.count, bytes[index] >= 0x30 && bytes[index] <= 0x39 else {
                throw rejectJSON()
            }
            while index < bytes.count, bytes[index] >= 0x30 && bytes[index] <= 0x39 {
                index += 1
            }
        }
        if index < bytes.count, bytes[index] == 0x65 || bytes[index] == 0x45 {
            isInteger = false
            index += 1
            if index < bytes.count, bytes[index] == 0x2B || bytes[index] == 0x2D {
                index += 1
            }
            guard index < bytes.count, bytes[index] >= 0x30 && bytes[index] <= 0x39 else {
                throw rejectJSON()
            }
            while index < bytes.count, bytes[index] >= 0x30 && bytes[index] <= 0x39 {
                index += 1
            }
        }
        let token = String(decoding: bytes[start..<index], as: UTF8.self)
        guard token.count <= ParityBounds.maxNumberLength else { throw rejectJSON() }
        if isInteger {
            let digits = token.drop(while: { $0 == "-" })
            guard digits.count <= ParityBounds.maxIntegerDigits else { throw rejectJSON() }
        }
        guard let value = Double(token), value.isFinite else { throw rejectJSON() }
        return .number(value)
    }

    private mutating func parseLiteral(_ literal: String, value: JSONValue) throws -> JSONValue {
        let encoded = Array(literal.utf8)
        guard bytes[index...].starts(with: encoded) else { throw rejectJSON() }
        index += encoded.count
        return value
    }

    private mutating func parseArray(depth: Int) throws -> JSONValue {
        guard consume(0x5B) else { throw rejectJSON() }
        try checkBudget(depth: depth)
        skipWhitespace()
        var values: [JSONValue] = []
        if consume(0x5D) { return .array(values) }
        while true {
            guard values.count < ParityBounds.maxJSONNodes else {
                throw reject(.malformedInput, "\(label) exceeds the JSON array limit")
            }
            values.append(try parseValue(depth: depth + 1))
            skipWhitespace()
            if consume(0x5D) { return .array(values) }
            guard consume(0x2C) else { throw rejectJSON() }
            skipWhitespace()
        }
    }

    private mutating func parseObject(depth: Int) throws -> JSONValue {
        guard consume(0x7B) else { throw rejectJSON() }
        try checkBudget(depth: depth)
        skipWhitespace()
        var values: [String: JSONValue] = [:]
        if consume(0x7D) { return .object(values) }
        while true {
            let key = try parseString()
            guard key.count <= ParityBounds.maxJSONKeyLength else { throw rejectJSON() }
            guard values[key] == nil else {
                throw reject(.malformedJSON, "\(label) contains a duplicate object key")
            }
            skipWhitespace()
            guard consume(0x3A) else { throw rejectJSON() }
            skipWhitespace()
            values[key] = try parseValue(depth: depth + 1)
            skipWhitespace()
            if consume(0x7D) { return .object(values) }
            guard consume(0x2C) else { throw rejectJSON() }
            skipWhitespace()
        }
    }

    private mutating func parseValue(depth: Int) throws -> JSONValue {
        skipWhitespace()
        guard index < bytes.count else { throw rejectJSON() }
        try checkBudget(depth: depth)
        switch bytes[index] {
        case 0x7B:
            return try parseObject(depth: depth)
        case 0x5B:
            return try parseArray(depth: depth)
        case 0x22:
            return .string(try parseString())
        case 0x74:
            return try parseLiteral("true", value: .boolean(true))
        case 0x66:
            return try parseLiteral("false", value: .boolean(false))
        case 0x6E:
            return try parseLiteral("null", value: .null)
        case 0x2D, 0x30...0x39:
            return try parseNumber()
        default:
            throw rejectJSON()
        }
    }

    mutating func parse() throws -> JSONValue {
        skipWhitespace()
        let value = try parseValue(depth: 0)
        skipWhitespace()
        guard index == bytes.count else { throw rejectJSON() }
        return value
    }
}

private func decodeJSON(_ data: Data, _ label: String) throws -> JSONValue {
    guard data.count <= ParityBounds.maxJSONBytes else {
        throw reject(.malformedInput, "\(label) exceeds the JSON byte limit")
    }
    guard String(data: data, encoding: .utf8) != nil else {
        throw reject(.malformedUTF8, "\(label) is not valid UTF-8")
    }
    var parser = StrictJSONParser(data: data, label: label)
    return try parser.parse()
}

private func readJSON(
    repoRoot: URL,
    relativePath: String,
    _ label: String,
    expected: RegistryFile? = nil,
    beforeFinalReopen: (() throws -> Void)? = nil
) throws -> JSONValue {
    let bytes = try readRegularFile(
        repoRoot: repoRoot,
        relativePath: relativePath,
        label: label,
        maxBytes: ParityBounds.maxJSONBytes,
        expected: expected,
        beforeFinalReopen: beforeFinalReopen
    )
    return try decodeJSON(bytes, label)
}

private func parseRegistryFile(_ value: JSONValue?, _ label: String) throws -> RegistryFile {
    let entry = try object(value, label)
    let digest = try string(entry["sha256"], "\(label).sha256")
    let hexDigits = CharacterSet(charactersIn: "0123456789abcdef")
    guard digest.count == 64,
          digest.unicodeScalars.allSatisfy({ hexDigits.contains($0) }) else {
        throw reject(.malformedInput, "\(label).sha256 is not a canonical digest")
    }
    let size = try nonNegativeInteger(entry["size_bytes"], "\(label).size_bytes")
    guard size <= ParityBounds.maxArtifactBytes else {
        throw reject(.malformedInput, "\(label).size_bytes exceeds the artifact limit")
    }
    return RegistryFile(
        path: try safeRelativePath(try string(entry["path"], "\(label).path"), "\(label).path"),
        sha256: digest,
        sizeBytes: size
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
    let validator: String?
    switch entry["validator"] {
    case .null?:
        validator = nil
    case .string?:
        validator = try string(entry["validator"], "\(label).validator")
    default:
        throw reject(.malformedInput, "\(label).validator must be text or null")
    }
    guard files.count <= ParityBounds.maxInventoryFiles else {
        throw reject(.malformedInput, "\(label).files exceeds the inventory limit")
    }
    guard Set(files.map(\.path)).count == files.count else {
        throw reject(.malformedInput, "\(label).files contains a duplicate path")
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
        validator: validator,
        files: files
    )
}

private func parseCoverage(_ value: JSONValue?, index: Int) throws -> CoverageRow {
    let label = "coverage[\(index)]"
    let entry = try object(value, label)
    let rawStatus = try string(entry["status"], "\(label).status")
    guard let status = CoverageStatus(rawValue: rawStatus) else {
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

private func loadRegistryImpl(
    at repoRoot: URL,
    beforeFinalReopen: (() throws -> Void)? = nil
) throws -> FixtureRegistry {
    // The registry is the compatibility allowlist. Missing or additive parity
    // metadata is not permission to discover another fixture or platform.
    let root = repoRoot.standardizedFileURL
    let raw = try object(
        try readJSON(
            repoRoot: root,
            relativePath: "contracts/fixtures/index.json",
            "fixture index",
            beforeFinalReopen: beforeFinalReopen
        ),
        "fixture index"
    )

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
        guard entry.files.allSatisfy({ $0.path == entry.path || $0.path.hasPrefix("\(entry.path)/") }) else {
            throw reject(.unsafePath, "fixture root inventory escapes its root")
        }
    }

    let rootIDs = Set(fixtureRoots.map(\.id))
    for entry in coverage {
        guard entry.fixtureIDs.allSatisfy(rootIDs.contains) else {
            throw reject(.unknownFixture, "coverage references an unknown fixture root")
        }
        if entry.status == .ready {
            guard entry.fixtureIDs.allSatisfy({ rootID in
                fixtureRoots.first(where: { $0.id == rootID })?.status == .ready
            }) else {
                throw reject(.coveragePending, "ready coverage references a pending fixture root")
            }
        }
    }

    let parity = try parseParity(raw["parity"])
    guard !parity.liveClaim, parity.fixtureSource == "one_shared_registry" else {
        throw reject(.incompatibleInput, "parity policy is not the shared synthetic policy")
    }
    return FixtureRegistry(fixtureRoots: fixtureRoots, coverage: coverage, parity: parity)
}

public func loadRegistry(at repoRoot: URL) throws -> FixtureRegistry {
    try loadRegistryImpl(at: repoRoot)
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

private func artifactRecord(root: FixtureRoot) throws -> RegistryFile {
    // Do not glob or infer JSON files. A representative is readable only when
    // this package names it and the C-19 registry lists the exact path.
    guard let relativeArtifact = approvedJSONArtifacts[root.id] else {
        throw reject(.unknownFixture, "fixture root has no approved JSON artifact")
    }
    guard relativeArtifact.hasPrefix("\(root.path)/") else {
        throw reject(.incompatibleInput, "fixture artifact is outside its registered root")
    }
    let matches = root.files.filter { $0.path == relativeArtifact }
    guard matches.count == 1, let record = matches.first else {
        throw reject(.unregisteredArtifact, "fixture JSON artifact is not listed by the registry")
    }
    return record
}

private func loadArtifact(
    repoRoot: URL,
    root: FixtureRoot,
    beforeFinalReopen: (() throws -> Void)? = nil
) throws -> [String: JSONValue] {
    let record = try artifactRecord(root: root)
    let bytes = try readRegularFile(
        repoRoot: repoRoot,
        relativePath: "contracts/fixtures/\(record.path)",
        label: "fixture \(root.id)",
        maxBytes: ParityBounds.maxArtifactBytes,
        expected: record,
        beforeFinalReopen: beforeFinalReopen
    )
    return try object(try decodeJSON(bytes, "fixture \(root.id)"), "fixture \(root.id)")
}

private func loadCaseImpl(
    at repoRoot: URL,
    registry: FixtureRegistry,
    rootID: String,
    caseID: String,
    beforeFinalReopen: (() throws -> Void)? = nil
) throws -> FixtureCase {
    let caseIDCharacters = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")
    guard !caseID.isEmpty,
          caseID.count <= ParityBounds.maxCaseIDLength,
          caseID.trimmingCharacters(in: .whitespacesAndNewlines) == caseID,
          caseID.unicodeScalars.allSatisfy({ caseIDCharacters.contains($0) }) else {
        throw reject(.malformedInput, "case ID must be a bounded canonical string")
    }
    let root = try rootByID(registry, rootID)
    // A pending root is an absence of evidence, not a successful fixture.
    guard root.status == .ready else {
        throw reject(.coveragePending, "pending fixture roots cannot provide parity evidence")
    }
    let artifact = try loadArtifact(
        repoRoot: repoRoot,
        root: root,
        beforeFinalReopen: beforeFinalReopen
    )
    let cases = try array(artifact["cases"], "fixture \(rootID).cases")
    guard cases.count <= ParityBounds.maxCaseCount else {
        throw reject(.malformedInput, "fixture \(rootID).cases exceeds the case limit")
    }
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

public func loadCase(
    at repoRoot: URL,
    registry: FixtureRegistry,
    rootID: String,
    caseID: String
) throws -> FixtureCase {
    try loadCaseImpl(
        at: repoRoot,
        registry: registry,
        rootID: rootID,
        caseID: caseID
    )
}

func loadCaseForTests(
    at repoRoot: URL,
    registry: FixtureRegistry,
    rootID: String,
    caseID: String,
    beforeFinalReopen: @escaping () throws -> Void
) throws -> FixtureCase {
    try loadCaseImpl(
        at: repoRoot,
        registry: registry,
        rootID: rootID,
        caseID: caseID,
        beforeFinalReopen: beforeFinalReopen
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

private func projectedString(
    _ expected: [String: JSONValue],
    key: String,
    family: FixtureFamily,
    caseID: String
) throws -> String {
    guard case .string(let value)? = expected[key],
          !value.isEmpty,
          value.count <= ParityBounds.maxJSONStringLength else {
        throw reject(.malformedInput, "\(family.rawValue).\(caseID).expected.\(key) is not a bounded string")
    }
    return value
}

private func projectedBoolean(
    _ expected: [String: JSONValue],
    key: String,
    family: FixtureFamily,
    caseID: String
) throws -> Bool {
    guard case .boolean(let value)? = expected[key] else {
        throw reject(.malformedInput, "\(family.rawValue).\(caseID).expected.\(key) is not a boolean")
    }
    return value
}

private func projectedInteger(
    _ expected: [String: JSONValue],
    key: String,
    family: FixtureFamily,
    caseID: String
) throws -> Int {
    guard case .number(let value)? = expected[key],
          value.isFinite,
          value.rounded() == value,
          value >= Double(Int.min),
          value <= Double(Int.max) else {
        throw reject(.malformedInput, "\(family.rawValue).\(caseID).expected.\(key) is not an integer")
    }
    return Int(value)
}

private func projectedOptionalString(
    _ expected: [String: JSONValue],
    key: String,
    family: FixtureFamily,
    caseID: String
) throws -> String? {
    switch expected[key] {
    case .null?:
        return nil
    case .string(let value)?:
        guard !value.isEmpty, value.count <= ParityBounds.maxJSONStringLength else {
            throw reject(.malformedInput, "\(family.rawValue).\(caseID).expected.\(key) is not bounded")
        }
        return value
    default:
        throw reject(.malformedInput, "\(family.rawValue).\(caseID).expected.\(key) is not text or null")
    }
}

private func projectedEffects(
    _ expected: [String: JSONValue],
    family: FixtureFamily,
    caseID: String
) throws -> Set<String> {
    guard case .array(let values)? = expected["effects"] else {
        throw reject(.malformedInput, "\(family.rawValue).\(caseID).expected.effects is not an array")
    }
    let effects = try values.map { value -> String in
        guard case .string(let effect) = value,
              !effect.isEmpty,
              effect.count <= ParityBounds.maxJSONStringLength else {
            throw reject(.malformedInput, "\(family.rawValue).\(caseID).expected.effects contains an invalid value")
        }
        return effect
    }
    return Set(effects)
}

private func normalizedSemantic(_ decision: String) -> [String: JSONValue] {
    ["decision": .string(decision)]
}

/// The Web projection follows browser-visible response and transport fields.
/// It does not reuse the fixture's expected dictionary as proof output.
private func projectWeb(family: FixtureFamily, fixtureCase: FixtureCase) throws -> ProjectedOutcome {
    let expected = fixtureCase.expected
    let caseID = fixtureCase.id
    let decision: String

    switch family {
    case .auth:
        let status = try projectedInteger(expected, key: "status", family: family, caseID: caseID)
        let redirect = try projectedOptionalString(expected, key: "redirect", family: family, caseID: caseID)
        let sessionCookie = try projectedString(expected, key: "session_cookie", family: family, caseID: caseID)
        if status == 302, redirect != nil, sessionCookie == "present" {
            decision = "authenticated"
        } else if status >= 400, redirect == nil, sessionCookie == "absent" {
            decision = "blocked"
        } else {
            throw reject(.parityMismatch, "Web auth response does not satisfy the reviewed outcome")
        }
    case .connection:
        switch try projectedString(expected, key: "final_state", family: family, caseID: caseID) {
        case "ready": decision = "restored"
        case "delivery_uncertain": decision = "delivery_uncertain"
        default: throw reject(.parityMismatch, "Web connection state is outside the reviewed outcome")
        }
    case .session:
        switch try projectedString(expected, key: "final_state", family: family, caseID: caseID) {
        case "ready": decision = "session_persisted"
        case "delivery_uncertain": decision = "delivery_uncertain"
        case "incompatible": decision = "automatic_prompt_retry_blocked"
        default: throw reject(.parityMismatch, "Web session state is outside the reviewed outcome")
        }
    case .chat:
        switch try projectedString(expected, key: "final_state", family: family, caseID: caseID) {
        case "delivery_uncertain": decision = "delivery_uncertain"
        case "incompatible": decision = "automatic_prompt_retry_blocked"
        default: throw reject(.parityMismatch, "Web chat state is outside the reviewed outcome")
        }
    case .image:
        let attachmentState = try projectedString(expected, key: "attachment_state", family: family, caseID: caseID)
        let uploadStarted = try projectedBoolean(expected, key: "upload_started", family: family, caseID: caseID)
        switch attachmentState {
        case "empty" where !uploadStarted: decision = "no_attachment"
        case "failed" where !uploadStarted: decision = "rejected"
        case "uploaded" where uploadStarted: decision = "accepted"
        default: throw reject(.parityMismatch, "Web attachment state is outside the reviewed outcome")
        }
    case .pty:
        if case .boolean(let logged)? = expected["pty_bytes_logged"] {
            decision = logged ? "logged" : "redacted"
        } else if case .boolean(let logged)? = expected["raw_bytes_logged"] {
            decision = logged ? "logged" : "redacted"
        } else {
            throw reject(.parityMismatch, "Web PTY result has no logging decision")
        }
    case .deepLink:
        let valid = try projectedBoolean(expected, key: "valid", family: family, caseID: caseID)
        let kind = try projectedString(expected, key: "kind", family: family, caseID: caseID)
        guard case .array(let values)? = expected["reasons"] else {
            throw reject(.malformedInput, "deep-link.\(caseID).expected.reasons is not an array")
        }
        if valid, kind == "web", values.isEmpty {
            decision = "valid"
        } else if !valid, !values.isEmpty {
            decision = "blocked"
        } else {
            throw reject(.parityMismatch, "Web deep-link result is outside the reviewed outcome")
        }
    case .compatibility:
        switch try projectedString(expected, key: "attestation_result", family: family, caseID: caseID) {
        case "verified": decision = "verified"
        case "blocked": decision = "blocked"
        default: throw reject(.parityMismatch, "Web compatibility result is outside the reviewed outcome")
        }
    }

    return ProjectedOutcome(decision: decision, semantic: normalizedSemantic(decision))
}

/// The Apple projection follows native state, persistence, and platform-gate
/// fields. It is intentionally a separate derivation from the Web projection.
private func projectApple(family: FixtureFamily, fixtureCase: FixtureCase) throws -> ProjectedOutcome {
    let expected = fixtureCase.expected
    let caseID = fixtureCase.id
    let decision: String

    switch family {
    case .auth:
        let state = try projectedString(expected, key: "state", family: family, caseID: caseID)
        let cleanup = try projectedString(expected, key: "cookie_cleanup", family: family, caseID: caseID)
        let exchange = try projectedString(expected, key: "provider_exchange", family: family, caseID: caseID)
        switch state {
        case "authenticated":
            decision = cleanup == "clear_ephemeral" && exchange == "called" ? "authenticated" : "blocked"
        case "blocked":
            decision = "blocked"
        default:
            throw reject(.parityMismatch, "Apple auth state is outside the reviewed outcome")
        }
    case .connection, .session, .chat:
        let effects = try projectedEffects(expected, family: family, caseID: caseID)
        switch family {
        case .connection:
            if effects.contains("server_session_restored") {
                decision = "restored"
            } else if effects.contains("prompt_delivery_uncertain") {
                decision = "delivery_uncertain"
            } else {
                throw reject(.parityMismatch, "Apple connection effects are outside the reviewed outcome")
            }
        case .session:
            if effects.contains("session_row_persisted") {
                decision = "session_persisted"
            } else if effects.contains("delivery_uncertain") {
                decision = "delivery_uncertain"
            } else if effects.contains("automatic_prompt_retry_blocked") {
                decision = "automatic_prompt_retry_blocked"
            } else {
                throw reject(.parityMismatch, "Apple session effects are outside the reviewed outcome")
            }
        case .chat:
            if effects.contains("prompt_delivery_uncertain") || effects.contains("delivery_uncertain") {
                decision = "delivery_uncertain"
            } else if effects.contains("automatic_prompt_retry_blocked") {
                decision = "automatic_prompt_retry_blocked"
            } else {
                throw reject(.parityMismatch, "Apple chat effects are outside the reviewed outcome")
            }
        default:
            throw reject(.parityMismatch, "Apple state projection received an unsupported family")
        }
    case .image:
        let attachmentState = try projectedString(expected, key: "attachment_state", family: family, caseID: caseID)
        let attempts = try projectedInteger(expected, key: "upload_attempts", family: family, caseID: caseID)
        let transcriptReference = try projectedOptionalString(expected, key: "transcript_reference", family: family, caseID: caseID)
        switch attachmentState {
        case "empty" where attempts == 0 && transcriptReference == nil: decision = "no_attachment"
        case "failed" where attempts == 0: decision = "rejected"
        case "uploaded": decision = attempts == 1 && transcriptReference != nil ? "accepted" : "rejected"
        default: throw reject(.parityMismatch, "Apple attachment state is outside the reviewed outcome")
        }
    case .pty:
        throw reject(.incompatibleInput, "Apple PTY projection is blocked by contract")
    case .deepLink:
        let valid = try projectedBoolean(expected, key: "valid", family: family, caseID: caseID)
        let sessionID = try projectedString(expected, key: "session_id", family: family, caseID: caseID)
        let messageID = try projectedOptionalString(expected, key: "message_id", family: family, caseID: caseID)
        guard case .array(let values)? = expected["reasons"] else {
            throw reject(.malformedInput, "deep-link.\(caseID).expected.reasons is not an array")
        }
        if valid, !sessionID.isEmpty, messageID == nil, values.isEmpty {
            decision = "valid"
        } else if !valid, !sessionID.isEmpty, messageID == nil, !values.isEmpty {
            decision = "blocked"
        } else {
            throw reject(.parityMismatch, "Apple deep-link result is outside the reviewed outcome")
        }
    case .compatibility:
        switch try projectedString(expected, key: "runtime_gate", family: family, caseID: caseID) {
        case "separate_probe_gate": decision = "verified"
        case "blocked_incompatible": decision = "blocked"
        default: throw reject(.parityMismatch, "Apple compatibility result is outside the reviewed outcome")
        }
    }

    return ProjectedOutcome(decision: decision, semantic: normalizedSemantic(decision))
}

func project(family: FixtureFamily, platform: Platform, fixtureCase: FixtureCase) throws -> ProjectedOutcome {
    switch platform {
    case .web:
        return try projectWeb(family: family, fixtureCase: fixtureCase)
    case .ios, .ipados, .macos:
        return try projectApple(family: family, fixtureCase: fixtureCase)
    }
}

private func runRepresentative(
    repoRoot: URL,
    registry: FixtureRegistry,
    representative: Representative
) throws -> [ParityCaseResult] {
    let coverage = try coverageByID(registry, representative.coverageID)
    let orderedPlatforms = coverage.platforms.sorted { $0.rawValue < $1.rawValue }
    if coverage.status != .ready {
        return representative.caseIDs.map { caseID in
            ParityCaseResult(
                family: representative.family,
                coverageID: representative.coverageID,
                caseID: caseID,
                status: "blocked",
                platforms: orderedPlatforms
            )
        }
    }
    guard coverage.fixtureIDs.contains(representative.rootID) else {
        throw reject(.incompatibleInput, "ready coverage does not own its representative fixture root")
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
                    platforms: orderedPlatforms,
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
                platforms: orderedPlatforms,
                webDecision: web.decision,
                appleDecision: apple.decision
            )
        )
    }
    return results
}

private enum C19PreflightOutcome {
    case passed
    case blocked(String)
}

#if os(macOS)
private struct BoundedPipeResult: Sendable {
    let data: Data
    let truncated: Bool
}

private final class BoundedPipeBox: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: BoundedPipeResult?

    func store(_ result: BoundedPipeResult) {
        lock.lock()
        stored = result
        lock.unlock()
    }

    var result: BoundedPipeResult? {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }
}

private func collectBoundedOutput(
    from handle: FileHandle,
    limit: Int,
    group: DispatchGroup
) -> BoundedPipeResult {
    var data = Data()
    var truncated = false
    defer { group.leave() }
    while true {
        let chunk: Data
        do {
            chunk = try handle.read(upToCount: 4 * 1024) ?? Data()
        } catch {
            break
        }
        if chunk.isEmpty { break }
        let remaining = max(0, limit - data.count)
        if chunk.count > remaining {
            truncated = true
        }
        if remaining > 0 {
            data.append(chunk.prefix(remaining))
        }
    }
    return BoundedPipeResult(data: data, truncated: truncated)
}

private final class InputWriteBox: @unchecked Sendable {
    private let lock = NSLock()
    private var writeFailed = false

    func markFailed() {
        lock.lock()
        writeFailed = true
        lock.unlock()
    }

    var failed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return writeFailed
    }
}

private func feedValidator(
    _ data: Data,
    to handle: FileHandle,
    box: InputWriteBox,
    group: DispatchGroup
) {
    defer { group.leave() }
    do {
        try handle.write(contentsOf: data)
    } catch {
        box.markFailed()
    }
    try? handle.close()
}

private func closeValidatorPipes(_ stdin: Pipe, _ stdout: Pipe, _ stderr: Pipe) {
    try? stdin.fileHandleForWriting.close()
    try? stdout.fileHandleForReading.close()
    try? stderr.fileHandleForReading.close()
}

private func waitForDrain(_ group: DispatchGroup, until deadline: UInt64) -> Bool {
    let now = DispatchTime.now().uptimeNanoseconds
    guard now < deadline else { return false }
    let remaining = deadline - now
    return group.wait(
        timeout: DispatchTime.now() + .nanoseconds(Int(min(remaining, UInt64(Int.max))))
    ) == .success
}

private func stopValidator(
    _ process: Process,
    stdin: Pipe,
    stdout: Pipe,
    stderr: Pipe,
    group: DispatchGroup,
    deadline: UInt64
) {
    process.terminate()
    if process.isRunning {
        kill(process.processIdentifier, SIGKILL)
    }
    closeValidatorPipes(stdin, stdout, stderr)
    process.waitUntilExit()
    _ = waitForDrain(group, until: deadline)
}

private let c19SuccessOutputKeys: Set<String> = [
    "ok",
    "complete",
    "evidence_status",
    "compatible",
    "live_claim",
    "fixture_count",
    "coverage_count",
]

private func validateC19SuccessOutput(_ value: JSONValue) throws {
    let output = try object(value, "C-19 validator output")
    guard Set(output.keys) == c19SuccessOutputKeys else {
        throw reject(.malformedInput, "C-19 validator output keys are not the reviewed success schema")
    }
    guard try boolean(output["ok"], "C-19 validator output.ok") else {
        throw reject(.malformedInput, "C-19 validator output.ok is not true")
    }
    let complete = try boolean(output["complete"], "C-19 validator output.complete")
    let evidenceStatus = try string(output["evidence_status"], "C-19 validator output.evidence_status")
    guard evidenceStatus == "partial" || evidenceStatus == "complete",
          complete == (evidenceStatus == "complete") else {
        throw reject(.malformedInput, "C-19 validator output evidence status is invalid")
    }
    guard !(try boolean(output["compatible"], "C-19 validator output.compatible")),
          !(try boolean(output["live_claim"], "C-19 validator output.live_claim")) else {
        throw reject(.malformedInput, "C-19 validator output makes a live or compatibility claim")
    }
    let fixtureCount = try nonNegativeInteger(output["fixture_count"], "C-19 validator output.fixture_count")
    let coverageCount = try nonNegativeInteger(output["coverage_count"], "C-19 validator output.coverage_count")
    guard fixtureCount <= ParityBounds.maxInventoryFiles,
          coverageCount <= ParityBounds.maxInventoryFiles else {
        throw reject(.malformedInput, "C-19 validator output counts exceed the inventory bound")
    }
}

private func runC19Validator(
    at repoRoot: URL,
    beforeLaunch: ((URL) throws -> Void)? = nil
) -> C19PreflightOutcome {
    do {
        let root = repoRoot.standardizedFileURL
        let scriptRelativePath = "contracts/fixtures/validator/validate.py"
        // Read the script through the same descriptor boundary before asking the
        // host interpreter to execute it. The validator remains authoritative;
        // Swift never reimplements its aggregate inventory or trust anchor.
        let scriptData = try readRegularFile(
            repoRoot: root,
            relativePath: scriptRelativePath,
            label: "C-19 validator",
            maxBytes: ParityBounds.maxArtifactBytes
        )

        let scriptURL = root.appendingPathComponent(scriptRelativePath)
        try beforeLaunch?(scriptURL)
        let executionDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("hermternal-c19-validator-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: executionDirectory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: executionDirectory) }

        let bootstrap = """
        import sys
        reviewed_path = sys.argv[1]
        sys.argv[:] = [reviewed_path]
        __file__ = reviewed_path
        reviewed_source = sys.stdin.buffer.read()
        reviewed_code = compile(reviewed_source, reviewed_path, "exec")
        reviewed_globals = {
            "__name__": "__main__",
            "__file__": reviewed_path,
            "__builtins__": __builtins__,
        }
        exec(reviewed_code, reviewed_globals, reviewed_globals)
        """
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = ["-I", "-B", "-c", bootstrap, scriptURL.path]
        process.currentDirectoryURL = executionDirectory
        // Isolated mode removes Python path and user-site imports. Keep the
        // process environment minimal as a second boundary against host
        // configuration changing which code the reviewed bytes import.
        process.environment = [
            "PATH": "/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
        ]

        let stdin = Pipe()
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()

        let group = DispatchGroup()
        let stdoutBox = BoundedPipeBox()
        let stderrBox = BoundedPipeBox()
        let inputBox = InputWriteBox()
        group.enter()
        DispatchQueue.global(qos: .utility).async {
            feedValidator(
                scriptData,
                to: stdin.fileHandleForWriting,
                box: inputBox,
                group: group
            )
        }
        group.enter()
        DispatchQueue.global(qos: .utility).async {
            stdoutBox.store(collectBoundedOutput(
                from: stdout.fileHandleForReading,
                limit: ParityBounds.maxPreflightOutputBytes,
                group: group
            ))
        }
        group.enter()
        DispatchQueue.global(qos: .utility).async {
            stderrBox.store(collectBoundedOutput(
                from: stderr.fileHandleForReading,
                limit: ParityBounds.maxPreflightOutputBytes,
                group: group
            ))
        }

        let deadline = DispatchTime.now().uptimeNanoseconds + ParityBounds.maxPreflightDurationNanoseconds
        while process.isRunning {
            guard DispatchTime.now().uptimeNanoseconds <= deadline else {
                stopValidator(
                    process,
                    stdin: stdin,
                    stdout: stdout,
                    stderr: stderr,
                    group: group,
                    deadline: deadline
                )
                return .blocked("c19_validator_timeout")
            }
            usleep(10_000)
        }
        guard DispatchTime.now().uptimeNanoseconds <= deadline else {
            closeValidatorPipes(stdin, stdout, stderr)
            process.waitUntilExit()
            return .blocked("c19_validator_timeout")
        }
        guard waitForDrain(group, until: deadline) else {
            closeValidatorPipes(stdin, stdout, stderr)
            process.waitUntilExit()
            return .blocked("c19_validator_timeout")
        }
        guard let stdoutResult = stdoutBox.result,
              let stderrResult = stderrBox.result,
              !inputBox.failed,
              !stdoutResult.truncated, !stderrResult.truncated,
              stdoutResult.data.count <= ParityBounds.maxPreflightOutputBytes else {
            return .blocked("c19_validator_output_bound")
        }

        let value: JSONValue
        do {
            value = try decodeJSON(stdoutResult.data, "C-19 validator output")
        } catch {
            return .blocked("c19_validator_output_contract")
        }
        let output: [String: JSONValue]
        do {
            output = try object(value, "C-19 validator output")
        } catch {
            return .blocked("c19_validator_output_contract")
        }

        if process.terminationStatus != 0 {
            let evidenceStatus = try? string(
                output["evidence_status"],
                "C-19 validator output.evidence_status"
            )
            return evidenceStatus == "blocked"
                ? .blocked("c19_validator_blocked")
                : .blocked("c19_validator_failed")
        }

        do {
            try validateC19SuccessOutput(value)
        } catch {
            return .blocked("c19_validator_output_contract")
        }
        return .passed
    } catch {
        return .blocked("c19_validator_unavailable")
    }
}
#endif

private func runC19Preflight(at repoRoot: URL) -> C19PreflightOutcome {
    #if os(macOS)
    return runC19Validator(at: repoRoot)
    #else
    // Non-host builds cannot execute the authoritative host validator and must
    // remain blocked; no caller-supplied status can substitute for it.
    return .blocked("c19_validator_unavailable")
    #endif
}

#if os(macOS)
func runC19ValidatorForTests(
    at repoRoot: URL,
    beforeLaunch: @escaping (URL) throws -> Void
) -> (passed: Bool, errorCode: String?) {
    switch runC19Validator(at: repoRoot, beforeLaunch: beforeLaunch) {
    case .passed:
        return (true, nil)
    case .blocked(let code):
        return (false, code)
    }
}
#endif

private func unavailableCompatibilityRecord() -> CompatibilityRecord {
    CompatibilityRecord(
        compatible: false,
        liveRun: false,
        deploymentAttestation: "not_available",
        behavioralProbe: "not_available",
        proxyProof: "not_available",
        parityEvidence: "not_available",
        benchmarkEvidence: "not_available"
    )
}

private func blockedParityReport(code: String) -> ParityReport {
    ParityReport(
        ok: false,
        status: "blocked",
        errorCode: code,
        contract: dashboardContract,
        hermesSourceSHA: hermesSourceSHA,
        syntheticOnly: true,
        liveClaim: false,
        networkCalls: 0,
        readyCaseCount: 0,
        blockedCoverageIDs: [],
        cases: [],
        compatibility: unavailableCompatibilityRecord()
    )
}

private func runParityCore(at repoRoot: URL) throws -> ParityReport {
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
    // Canonical ordering keeps bounded reports stable across registry traversal changes.
    let orderedResults = results.sorted {
        ($0.family.rawValue, $0.coverageID, $0.caseID) <
            ($1.family.rawValue, $1.coverageID, $1.caseID)
    }
    let blockedCoverageIDs = registry.coverage
        .filter { $0.status != .ready }
        .map(\.id)
        .sorted()

    return ParityReport(
        ok: true,
        status: "ready",
        contract: dashboardContract,
        hermesSourceSHA: hermesSourceSHA,
        syntheticOnly: true,
        liveClaim: false,
        networkCalls: 0,
        readyCaseCount: orderedResults.filter { $0.status == "proven" }.count,
        blockedCoverageIDs: blockedCoverageIDs,
        cases: orderedResults,
        compatibility: compatibility
    )
}

/// The production entry point owns C-19 preflight. Callers cannot replace the
/// authoritative host result with a passed status or synthetic evidence.
public func runParity(at repoRoot: URL) throws -> ParityReport {
    switch runC19Preflight(at: repoRoot) {
    case .blocked(let code):
        return blockedParityReport(code: code)
    case .passed:
        return try runParityCore(at: repoRoot)
    }
}

/// Synthetic projection tests need to exercise the post-preflight core without
/// entering production report generation. This helper is internal so external
/// callers and the CLI cannot bypass the public host preflight.
func runParityForTests(at repoRoot: URL) throws -> ParityReport {
    try runParityCore(at: repoRoot)
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
