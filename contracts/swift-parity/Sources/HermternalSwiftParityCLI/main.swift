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

private func writeJSON<T: Encodable>(_ value: T, to handle: FileHandle) {
    let encoder = JSONEncoder()
    encoder.outputFormatting = []
    do {
        let data = try encoder.encode(value)
        handle.write(data)
        handle.write(Data([0x0A]))
    } catch {
        handle.write(Data("{\"ok\":false,\"error\":{\"code\":\"unexpected_failure\",\"message\":\"parity check failed without a contract error\"}}\n".utf8))
    }
}

do {
    let report = try runParity(at: try parseRepositoryRoot())
    writeJSON(report, to: FileHandle.standardOutput)
} catch let error as ContractInputError {
    writeJSON(
        Failure(error: .init(code: error.code.rawValue, message: error.message)),
        to: FileHandle.standardError
    )
    exit(1)
} catch {
    writeJSON(
        Failure(error: .init(code: "unexpected_failure", message: "parity check failed without a contract error")),
        to: FileHandle.standardError
    )
    exit(1)
}
