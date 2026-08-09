import Foundation
import HermternalSwiftParity

private struct Failure: Encodable {
    let ok = false
    let error: ErrorPayload

    struct ErrorPayload: Encodable {
        let code: String
        let message: String
    }
}

private func parseRepositoryRoot() throws -> URL {
    let arguments = Array(CommandLine.arguments.dropFirst())
    var repositoryRoot: URL?
    var index = 0

    while index < arguments.count {
        let argument = arguments[index]
        guard argument == "--repo-root" else {
            throw ContractInputError(
                code: argument.hasPrefix("--") ? .unknownInput : .malformedInput,
                message: "parity CLI accepts only --repo-root"
            )
        }
        let nextIndex = index + 1
        guard nextIndex < arguments.count,
              !arguments[nextIndex].hasPrefix("--"),
              repositoryRoot == nil else {
            throw ContractInputError(
                code: .malformedInput,
                message: "--repo-root requires one value"
            )
        }
        repositoryRoot = URL(fileURLWithPath: arguments[nextIndex], isDirectory: true)
        index += 2
    }

    return repositoryRoot ?? URL(
        fileURLWithPath: FileManager.default.currentDirectoryPath,
        isDirectory: true
    )
}

private func canonicalJSON<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    var data = try encoder.encode(value)
    data.append(0x0A)
    guard data.count <= ParityBounds.maxOutputBytes else {
        throw ContractInputError(
            code: .malformedInput,
            message: "parity output exceeds the byte limit"
        )
    }
    return data
}

private func writeCanonical<T: Encodable>(_ value: T, to handle: FileHandle) -> Bool {
    guard let data = try? canonicalJSON(value) else { return false }
    handle.write(data)
    return true
}

private func fail(_ failure: Failure) -> Never {
    let fallback = Data("{\"error\":{\"code\":\"unexpected_failure\",\"message\":\"parity check failed without a contract error\"},\"ok\":false}\n".utf8)
    if !writeCanonical(failure, to: FileHandle.standardError) {
        FileHandle.standardError.write(fallback)
    }
    exit(1)
}

do {
    let report = try runParity(at: try parseRepositoryRoot())
    guard writeCanonical(report, to: FileHandle.standardOutput) else {
        fail(Failure(error: .init(code: "output_bound", message: "parity output exceeds the byte limit")))
    }
    if !report.ok {
        exit(1)
    }
    exit(0)
} catch let error as ContractInputError {
    fail(Failure(error: .init(code: error.code.rawValue, message: error.message)))
} catch {
    fail(Failure(error: .init(code: "unexpected_failure", message: "parity check failed without a contract error")))
}
