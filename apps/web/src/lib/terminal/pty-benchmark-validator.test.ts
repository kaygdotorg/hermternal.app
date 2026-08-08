import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  validatePtyBenchmarkArtifact,
  validatePtyBenchmarkFile,
} from "./validate-pty-benchmarks";

const CHECKED_IN_RECONNECT_ARTIFACT =
  "src/lib/terminal/pty-reconnect-supersession-benchmark.json";
const CHECKED_IN_CONNECTING_ARTIFACT =
  "src/lib/terminal/pty-connecting-ownership-benchmark.json";
const RECONNECT_BENCHMARK =
  "src/lib/terminal/pty-reconnect-supersession.bench.ts";
const CONNECTING_BENCHMARK =
  "src/lib/terminal/pty-connecting-ownership.bench.ts";
const CLI = "src/lib/terminal/pty-benchmark-validator.ts";

let reconnectArtifactPath = CHECKED_IN_RECONNECT_ARTIFACT;
let connectingArtifactPath = CHECKED_IN_CONNECTING_ARTIFACT;
let harnessArtifactDirectory: string | undefined;

type MutableArtifact = Record<string, any>;

function readArtifact(path: string): MutableArtifact {
  return JSON.parse(readFileSync(path, "utf8")) as MutableArtifact;
}

function cloneArtifact(path: string): MutableArtifact {
  return JSON.parse(JSON.stringify(readArtifact(path))) as MutableArtifact;
}

function generateHarnessArtifacts(): void {
  const repoRoot = execFileSync(
    "git",
    ["rev-parse", "--show-toplevel"],
    { cwd: process.cwd(), encoding: "utf8" },
  ).trim();
  const directory = mkdtempSync(join(tmpdir(), "hermternal-pty-harness-"));
  const checkout = join(directory, "checkout");
  try {
    execFileSync(
      "git",
      ["worktree", "add", "--detach", "--quiet", checkout, "HEAD"],
      { cwd: repoRoot, stdio: ["ignore", "ignore", "pipe"] },
    );
    const benchmarkCwd = join(checkout, "apps/web");
    const reconnectOutput = execFileSync("bun", [RECONNECT_BENCHMARK], {
      cwd: benchmarkCwd,
      encoding: "utf8",
    });
    const connectingOutput = execFileSync("bun", [CONNECTING_BENCHMARK], {
      cwd: benchmarkCwd,
      encoding: "utf8",
    });
    reconnectArtifactPath = join(directory, "reconnect.json");
    connectingArtifactPath = join(directory, "connecting.json");
    writeFileSync(reconnectArtifactPath, reconnectOutput);
    writeFileSync(connectingArtifactPath, connectingOutput);
    harnessArtifactDirectory = directory;
  } finally {
    try {
      execFileSync(
        "git",
        ["worktree", "remove", "--force", checkout],
        { cwd: repoRoot, stdio: "ignore" },
      );
    } catch {
      // Preserve the benchmark failure; cleanup is best effort.
    }
    if (harnessArtifactDirectory !== directory) {
      rmSync(directory, { recursive: true, force: true });
    }
  }
}

beforeAll(generateHarnessArtifacts);
afterAll(() => {
  if (harnessArtifactDirectory !== undefined) {
    rmSync(harnessArtifactDirectory, { recursive: true, force: true });
  }
});

function runCli(
  path: string,
  optimized = false,
): { readonly ok: boolean; readonly output: string } {
  try {
    const output = execFileSync(
      "bun",
      [CLI, ...(optimized ? ["--optimized"] : []), path],
      {
        cwd: process.cwd(),
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    return { ok: true, output };
  } catch (error) {
    const failure = error as {
      readonly stdout?: string | Uint8Array;
      readonly stderr?: string | Uint8Array;
    };
    const stringify = (value: string | Uint8Array | undefined): string =>
      typeof value === "string"
        ? value
        : value
          ? new TextDecoder().decode(value)
          : "";
    return {
      ok: false,
      output: `${stringify(failure.stdout)}${stringify(failure.stderr)}`,
    };
  }
}

function withTempArtifact<T>(
  artifact: MutableArtifact,
  callback: (path: string) => T,
): T {
  const directory = mkdtempSync(join(tmpdir(), "hermternal-pty-validator-"));
  const path = join(directory, "artifact.json");
  writeFileSync(path, JSON.stringify(artifact, null, 2));
  try {
    return callback(path);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function expectCliFailure(
  artifact: MutableArtifact,
  pattern: RegExp,
  optimized = false,
): void {
  withTempArtifact(artifact, (path) => {
    const result = runCli(path, optimized);
    expect(result.ok).toBe(false);
    expect(result.output).toMatch(pattern);
  });
}

describe("PTY benchmark evidence validator", () => {
  it("validates current harness artifacts through the file API", () => {
    expect(() => validatePtyBenchmarkFile(reconnectArtifactPath)).not.toThrow();
    expect(() => validatePtyBenchmarkFile(connectingArtifactPath)).not.toThrow();
  });

  it("keeps intentionally stale checked-in evidence out of the positive path", () => {
    expect(() => validatePtyBenchmarkFile(CHECKED_IN_RECONNECT_ARTIFACT)).toThrow(
      /followed only by evidence changes|schema-specific contract/iu,
    );
    expect(() => validatePtyBenchmarkFile(CHECKED_IN_CONNECTING_ARTIFACT)).toThrow(
      /followed only by evidence changes|schema-specific contract/iu,
    );
  });

  it("runs distinct standard and optimized CLI validation", () => {
    const artifact = cloneArtifact(reconnectArtifactPath);
    withTempArtifact(artifact, (path) => {
      const standard = runCli(path);
      const optimized = runCli(path, true);
      expect(standard.ok).toBe(true);
      expect(JSON.parse(standard.output)).toMatchObject({
        valid: true,
        optimized: false,
        validationMode: "standard-provenance-and-proof-ledger",
      });
      expect(optimized.ok).toBe(true);
      expect(JSON.parse(optimized.output)).toMatchObject({
        valid: true,
        optimized: true,
        validationMode: "strict-provenance-and-proof-ledger",
      });
    });

    const reordered = cloneArtifact(reconnectArtifactPath);
    reordered.provenance.sourceBlobs.reverse();
    withTempArtifact(reordered, (path) => {
      expect(runCli(path).ok).toBe(true);
      const optimized = runCli(path, true);
      expect(optimized.ok).toBe(false);
      expect(optimized.output).toMatch(/canonical source blob ordering/iu);
    });
  });

  it("rejects schema-specific operation and metric metadata drift through the CLI", () => {
    const cases = [
      {
        path: reconnectArtifactPath,
        operation: "same-identity reconnect after ordinary detach quarantine",
        metric: {
          name: "quarantine_settle_wall_time",
          unit: "ms",
          clock: "performance.now",
          start: "connect attempt starts",
          end: "ignored adapter settles after detach and blocked reconnect",
        },
      },
      {
        path: connectingArtifactPath,
        operation:
          "connecting observer ownership decision before socket factory",
        metric: {
          name: "ownership_decision_settle_wall_time",
          unit: "ms",
          clock: "performance.now",
          start:
            "performance.now immediately before connecting observer cancellation or replacement action",
          end: "cancelled operation rejects",
        },
      },
    ] as const;

    for (const { path, operation, metric } of cases) {
      const operationDrift = cloneArtifact(path);
      operationDrift.operation = `${operation} drift`;
      expectCliFailure(operationDrift, /operation/iu);

      for (const field of ["name", "unit", "clock", "start", "end"] as const) {
        const metricDrift = cloneArtifact(path);
        metricDrift.metric[field] = `${metric[field]} drift`;
        expectCliFailure(metricDrift, new RegExp(`metric\\.${field}`, "iu"));
      }
    }
  });

  it("rejects arbitrary tracked blobs and source or command drift", () => {
    const arbitraryBlob = cloneArtifact(reconnectArtifactPath);
    arbitraryBlob.provenance.sourceBlobs[0].path =
      "apps/web/src/lib/terminal/pty-transport.md";
    expectCliFailure(
      arbitraryBlob,
      /expected benchmark input|omitted an expected/iu,
    );

    const sourcePath = cloneArtifact(reconnectArtifactPath);
    sourcePath.sourcePath = "apps/web/src/lib/terminal/pty-transport.md";
    expectCliFailure(sourcePath, /sourcePath and command/iu);

    const command = cloneArtifact(reconnectArtifactPath);
    command.command = "bun src/lib/terminal/pty-connecting-ownership.bench.ts";
    expectCliFailure(command, /sourcePath and command/iu);
  });

  it("requires exact schema assertion keys and proven true values", () => {
    const missing = cloneArtifact(reconnectArtifactPath);
    delete missing.results[0].runs[0].assertions.socketClosureLedgerExact;
    expectCliFailure(missing, /keys did not match/iu);

    const renamed = cloneArtifact(reconnectArtifactPath);
    renamed.results[0].runs[0].assertions.socketClosureLedgerExactProof =
      renamed.results[0].runs[0].assertions.socketClosureLedgerExact;
    delete renamed.results[0].runs[0].assertions.socketClosureLedgerExact;
    expectCliFailure(renamed, /keys did not match/iu);

    const falseProof = cloneArtifact(reconnectArtifactPath);
    falseProof.results[0].runs[0].assertions.cleanupRecorded = false;
    expectCliFailure(falseProof, /not proven true/iu);

    const fabricated = cloneArtifact(reconnectArtifactPath);
    fabricated.results[0].runs[0].assertions = { foo: true };
    expectCliFailure(fabricated, /keys did not match/iu);

    const connecting = cloneArtifact(connectingArtifactPath);
    delete connecting.results[0].runs[0].assertions.connectingGuard;
    expectCliFailure(connecting, /keys did not match/iu);
  });

  it("binds proof assertions to validator counts, owners, cleanup, and late-event suppression", () => {
    const validatorCount = cloneArtifact(reconnectArtifactPath);
    validatorCount.results[0].runs[0].validatorCalls += 1;
    expectCliFailure(validatorCount, /expected ownership ledger/iu);

    const ownerIdentity = cloneArtifact(reconnectArtifactPath);
    ownerIdentity.results[0].runs[0].activeOwnerIdentities[0] = {
      ...ownerIdentity.results[0].runs[0].activeOwnerIdentities[0],
      processIdentity: "other-process",
    };
    expectCliFailure(ownerIdentity, /expected ownership identities/iu);

    const closeLedger = cloneArtifact(reconnectArtifactPath);
    closeLedger.results[0].runs[0].replacementSocketCloseCalls = 0;
    expectCliFailure(closeLedger, /expected ownership ledger/iu);

    const lateEventProof = cloneArtifact(connectingArtifactPath);
    lateEventProof.results[3].runs[0].postCloseBytesEvents = 1;
    expectCliFailure(lateEventProof, /expected ownership ledger/iu);
  });

  it("rejects owner tuple, socket ID, and callback-proof applicability drift", () => {
    const ownerTuple = cloneArtifact(reconnectArtifactPath);
    ownerTuple.results[0].runs[0].expectedOwnerIdentity = {
      ...ownerTuple.results[0].runs[0].expectedOwnerIdentity,
      attach: "other-attach",
    };
    expectCliFailure(ownerTuple, /expected owner identity/iu);

    const socketId = cloneArtifact(reconnectArtifactPath);
    socketId.results[2].runs[0].socketClosures[0].socketId = "socket-foreign";
    expectCliFailure(socketId, /exact per-socket cleanup ledger/iu);

    const callbackProofApplicable = cloneArtifact(connectingArtifactPath);
    callbackProofApplicable.results[3].runs[0].callbackProofApplicable = false;
    expectCliFailure(
      callbackProofApplicable,
      /callbackProofApplicable did not match the action/iu,
    );
  });

  it("rejects totals, distributions, repetition, and warmup drift", () => {
    const totals = cloneArtifact(reconnectArtifactPath);
    totals.results[0].totals.ticketRequests += 1;
    expectCliFailure(totals, /totals\.ticketRequests/iu);

    const distribution = cloneArtifact(reconnectArtifactPath);
    distribution.results[0].distribution.min += 1;
    expectCliFailure(distribution, /does not match its raw samples/iu);

    for (const [field, value] of [
      ["repetitions", 29],
      ["repetitions", 30.5],
      ["warmups", 4],
      ["warmups", 4.5],
    ] as const) {
      const metadata = cloneArtifact(reconnectArtifactPath);
      metadata[field] = value;
      expectCliFailure(metadata, /repetition metadata/iu);
    }
  });

  it("rejects attached checkout and runtime or engine provenance drift", () => {
    const attached = cloneArtifact(reconnectArtifactPath);
    attached.provenance.detachedHead = false;
    expectCliFailure(attached, /detached clean checkout/iu);

    const hostNode = cloneArtifact(reconnectArtifactPath);
    hostNode.provenance.runtime.hostNode = "24.3.0";
    expectCliFailure(hostNode, /hostNode|package runtime|engines/iu);

    const declaredNode = cloneArtifact(reconnectArtifactPath);
    declaredNode.provenance.runtime.declaredNode = "24.3.0";
    expectCliFailure(declaredNode, /package runtime|engines/iu);
  });

  it("fails generation on the attached checkout instead of fabricating evidence", () => {
    expect(() =>
      execFileSync(
        "bun",
        ["src/lib/terminal/pty-reconnect-supersession.bench.ts"],
        {
          cwd: process.cwd(),
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
        },
      ),
    ).toThrow(/clean checkout|detached clean checkout/iu);
  });

  it("rejects arbitrary source revisions or missing raw proof through the API", () => {
    const artifact = cloneArtifact(reconnectArtifactPath);
    expect(() =>
      validatePtyBenchmarkArtifact({
        ...artifact,
        provenance: {
          ...artifact.provenance,
          sourceRevision: "arbitrary",
        },
      }),
    ).toThrow(/full 40-hex/iu);
    expect(() =>
      validatePtyBenchmarkArtifact({
        ...artifact,
        results: [
          { ...artifact.results[0], samples: [] },
          ...artifact.results.slice(1),
        ],
      }),
    ).toThrow(/non-empty array/iu);
  });
});
