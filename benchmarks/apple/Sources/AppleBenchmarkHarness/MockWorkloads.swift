import Foundation

// The workload is deliberately model-only. Keeping these values outside
// SwiftUI makes the harness useful before the product's native views exist and
// prevents a local run from being mistaken for a UI or device measurement.
public struct SeededFixtureGenerator: Sendable {
  private var state: UInt64

  public init(seed: UInt64) {
    state = seed == 0 ? 0x9E37_79B9_7F4A_7C15 : seed
  }

  public mutating func nextUInt64() -> UInt64 {
    state &+= 0x9E37_79B9_7F4A_7C15
    var value = state
    value = (value ^ (value >> 30)) &* 0xBF58_476D_1CE4_E5B9
    value = (value ^ (value >> 27)) &* 0x94D0_49BB_1331_11EB
    return value ^ (value >> 31)
  }

  public mutating func nextInt(upperBound: Int) -> Int {
    precondition(upperBound > 0)
    return Int(nextUInt64() % UInt64(upperBound))
  }

  public mutating func nextText(length: Int) -> String {
    let alphabet = Array("abcdefghijkmnopqrstuvwxyz ")
    return String((0..<length).map { _ in alphabet[nextInt(upperBound: alphabet.count)] })
  }
}

struct MockSessionState: Equatable {
  let sessionIDs: [String]
  let selectedSessionIndex: Int
  let checksum: UInt64
}

struct MockStreamBatch: Equatable {
  let sequence: Int
  let text: String
}

struct MockTranscriptMessage: Equatable {
  let id: String
  let text: String
}

struct MockSceneRestorationState: Codable, Equatable {
  let selectedSessionID: String
  let scrollOffsets: [String: Double]
  let expandedSections: [String]
}

struct MockLayoutMetrics: Equatable {
  let lineCount: Int
  let height: Double
  let maxWidth: Double
}

@inline(never)
func consumeMockResult(_ result: UInt64) {
  // A volatile-looking branch keeps the optimizer from erasing a pure mock
  // operation without introducing I/O, global state, or a platform API.
  if result == UInt64.max {
    fatalError("unreachable mock result")
  }
}

enum MockWorkloadExecutor {
  static func execute(
    operation: WorkloadOperationSpec,
    fixture: AppleWorkloadFixture,
    iteration: Int
  ) throws -> UInt64 {
    let seed = fixture.seed &+ UInt64(iteration) &+ UInt64(operation.itemCount)
    switch operation.kind {
    case .launchSetupStateConstruction:
      return launchSetupState(operation: operation, seed: seed)
    case .streamingBatchReduction:
      return streamingBatchReduction(operation: operation, seed: seed)
    case .transcriptDiffScrollModel:
      return transcriptDiffAndScroll(operation: operation, seed: seed)
    case .sceneRestorationSerialization:
      return try sceneRestorationSerialization(operation: operation, seed: seed)
    case .dynamicTypeLayoutCalculation:
      return dynamicTypeLayout(operation: operation, seed: seed)
    }
  }

  private static func launchSetupState(operation: WorkloadOperationSpec, seed: UInt64) -> UInt64 {
    var generator = SeededFixtureGenerator(seed: seed)
    var ids: [String] = []
    ids.reserveCapacity(operation.itemCount)
    var checksum: UInt64 = 0xcbf2_9ce4_8422_2325
    for index in 0..<operation.itemCount {
      let suffix = generator.nextUInt64() & 0xffff
      let id = "session-\(index)-\(String(suffix, radix: 16))"
      ids.append(id)
      for byte in id.utf8 {
        checksum ^= UInt64(byte)
        checksum &*= 0x100_0000_01b3
      }
    }
    let state = MockSessionState(
      sessionIDs: ids,
      selectedSessionIndex: operation.itemCount / 2,
      checksum: checksum
    )
    return state.checksum ^ UInt64(state.sessionIDs.count) ^ UInt64(state.selectedSessionIndex)
  }

  private static func streamingBatchReduction(operation: WorkloadOperationSpec, seed: UInt64)
    -> UInt64
  {
    var generator = SeededFixtureGenerator(seed: seed)
    var batches: [MockStreamBatch] = []
    batches.reserveCapacity(operation.itemCount / operation.batchSize)
    for sequence in 0..<(operation.itemCount / operation.batchSize) {
      let text = generator.nextText(length: operation.textLength)
      batches.append(.init(sequence: sequence, text: text))
    }

    var totalCharacters = 0
    var checksum: UInt64 = 0
    for batch in batches.sorted(by: { $0.sequence < $1.sequence }) {
      totalCharacters += batch.text.count
      for byte in batch.text.utf8 {
        checksum = (checksum &* 33) &+ UInt64(byte)
      }
    }
    return checksum ^ UInt64(totalCharacters) ^ UInt64(batches.count)
  }

  private static func transcriptDiffAndScroll(operation: WorkloadOperationSpec, seed: UInt64)
    -> UInt64
  {
    var oldGenerator = SeededFixtureGenerator(seed: seed)
    var newGenerator = SeededFixtureGenerator(seed: seed &+ 0x517c_c1b7_2722_0a95)
    var oldMessages: [MockTranscriptMessage] = []
    var newMessages: [MockTranscriptMessage] = []
    oldMessages.reserveCapacity(operation.itemCount)
    newMessages.reserveCapacity(operation.itemCount)
    for index in 0..<operation.itemCount {
      let id = "message-\(index)"
      let oldText = oldGenerator.nextText(length: operation.textLength)
      let newText =
        index.isMultiple(of: 7)
        ? newGenerator.nextText(length: operation.textLength)
        : oldText
      oldMessages.append(.init(id: id, text: oldText))
      newMessages.append(.init(id: id, text: newText))
    }

    var changed = 0
    var checksum: UInt64 = 0
    for (old, new) in zip(oldMessages, newMessages) {
      if old != new {
        changed += 1
        checksum &+= UInt64(new.text.utf8.reduce(0) { $0 &+ UInt64($1) })
      }
    }
    let scrollTarget = min(operation.itemCount, changed + operation.itemCount / 4)
    return checksum ^ UInt64(changed) ^ UInt64(scrollTarget)
  }

  private static func sceneRestorationSerialization(
    operation: WorkloadOperationSpec,
    seed: UInt64
  ) throws -> UInt64 {
    var generator = SeededFixtureGenerator(seed: seed)
    var offsets: [String: Double] = [:]
    var expanded: [String] = []
    for index in 0..<operation.itemCount {
      let sessionID = "session-\(index)"
      offsets[sessionID] = Double(generator.nextInt(upperBound: 10_000)) / 10.0
      if index.isMultiple(of: 3) {
        expanded.append("section-\(index)")
      }
    }
    let state = MockSceneRestorationState(
      selectedSessionID: "session-\(operation.itemCount / 2)",
      scrollOffsets: offsets,
      expandedSections: expanded
    )
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = try encoder.encode(state)
    let restored = try JSONDecoder().decode(MockSceneRestorationState.self, from: data)
    guard restored == state else {
      throw AppleBenchmarkError.evidenceMalformed
    }
    return UInt64(data.count) ^ UInt64(restored.expandedSections.count)
  }

  private static func dynamicTypeLayout(operation: WorkloadOperationSpec, seed: UInt64) -> UInt64 {
    var generator = SeededFixtureGenerator(seed: seed)
    let scales = [1.0, 1.2, 1.35, 1.6]
    var aggregate: UInt64 = 0
    for index in 0..<operation.itemCount {
      let text = generator.nextText(length: operation.textLength + generator.nextInt(upperBound: 8))
      let scale = scales[index % scales.count]
      let metrics = layout(text: text, scale: scale)
      aggregate &+= UInt64(metrics.lineCount)
      aggregate &+= UInt64(metrics.height.rounded())
      aggregate &+= UInt64(metrics.maxWidth.rounded())
    }
    return aggregate
  }

  private static func layout(text: String, scale: Double) -> MockLayoutMetrics {
    let baseCharactersPerLine = 42.0
    let charactersPerLine = max(12, Int((baseCharactersPerLine / scale).rounded(.down)))
    let lineCount = max(1, Int(ceil(Double(text.count) / Double(charactersPerLine))))
    let lineHeight = 19.0 * scale
    let width = min(320.0, Double(min(text.count, charactersPerLine)) * 7.2 * scale)
    return MockLayoutMetrics(
      lineCount: lineCount,
      height: Double(lineCount) * lineHeight,
      maxWidth: width
    )
  }
}
