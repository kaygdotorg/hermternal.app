import AppleBenchmarkHarness
import Darwin
import Foundation

@main
struct AppleBenchmarkCLI {
  static func main() {
    do {
      let options = try parse(Array(CommandLine.arguments.dropFirst()))
      if options.help {
        print(usage)
        return
      }
      guard let sourceCommitSHA = options.sourceCommitSHA else {
        throw AppleBenchmarkError.sourceCommitMissing
      }
      let destinations = try CLIOutputPolicy.canonicalize(
        evidencePath: options.outputPath,
        tracePath: options.traceOutputPath
      )

      let loaded = try WorkloadFixtureLoader.load()
      let build = ReleaseBuildMetadataFactory.current()
      let result = try AppleBenchmarkRunner().run(
        workload: loaded.fixture,
        workloadBytes: loaded.bytes,
        sourceCommitSHA: sourceCommitSHA,
        build: build
      )
      let evidenceBytes = try BenchmarkJSON.encode(result.evidence)
      try write(result.traceBytes, to: destinations.trace)
      try write(evidenceBytes, to: destinations.evidence)
    } catch let error as AppleBenchmarkError {
      emitFailure(error)
    } catch {
      emitFailure(.evidenceMalformed)
    }
  }

  private struct Options {
    var outputPath: URL?
    var traceOutputPath: URL?
    var sourceCommitSHA: String?
    var help = false
  }

  private static func parse(_ arguments: [String]) throws -> Options {
    var options = Options()
    var index = 0
    while index < arguments.count {
      switch arguments[index] {
      case "--help", "-h":
        options.help = true
        index += 1
      case "--output":
        guard index + 1 < arguments.count else { throw AppleBenchmarkError.unsupportedArgument }
        options.outputPath = URL(fileURLWithPath: arguments[index + 1])
        index += 2
      case "--trace-output":
        guard index + 1 < arguments.count else { throw AppleBenchmarkError.unsupportedArgument }
        options.traceOutputPath = URL(fileURLWithPath: arguments[index + 1])
        index += 2
      case "--source-commit-sha":
        guard index + 1 < arguments.count else { throw AppleBenchmarkError.unsupportedArgument }
        options.sourceCommitSHA = arguments[index + 1]
        index += 2
      default:
        throw AppleBenchmarkError.unsupportedArgument
      }
    }
    return options
  }

  private static func write(_ data: Data, to path: URL?) throws {
    guard let path else {
      if let text = String(data: data, encoding: .utf8) {
        print(text)
        return
      }
      throw AppleBenchmarkError.outputWriteFailed
    }
    do {
      try data.write(to: path, options: .atomic)
    } catch {
      throw AppleBenchmarkError.outputWriteFailed
    }
  }

  private static func emitFailure(_ error: AppleBenchmarkError) {
    let payload =
      "{\"schema\":\"hermternal.apple-benchmark-error.v1\",\"status\":\"failed\",\"code\":\"\(error.code)\",\"message\":\"benchmark failed closed\"}"
    FileHandle.standardError.write(Data((payload + "\n").utf8))
    exit(2)
  }

  private static let usage = """
    apple-benchmark --source-commit-sha <40-lowercase-hex> --trace-output <raw-trace.json> [--output <evidence.json>]

    Runs deterministic, offline model workloads. Build the package with -c release.
    """
}
