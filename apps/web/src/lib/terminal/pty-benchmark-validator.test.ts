import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  validatePtyBenchmarkArtifact,
  validatePtyBenchmarkFile,
} from "./validate-pty-benchmarks";

const RECONNECT_ARTIFACT =
  "src/lib/terminal/pty-reconnect-supersession-benchmark.json";
const CONNECTING_ARTIFACT =
  "src/lib/terminal/pty-connecting-ownership-benchmark.json";
const CLI = "src/lib/terminal/pty-benchmark-validator.ts";

type MutableArtifact = Record<string, any>;

function readArtifact(path: string): MutableArtifact {
  return JSON.parse(readFileSync(path, "utf8")) as MutableArtifact;
}

function cloneArtifact(path: string): MutableArtifact {
  return JSON.parse(JSON.stringify(readArtifact(path))) as MutableArtifact;
}

function runCliArgs(
  args: readonly string[],
): { readonly ok: boolean; readonly output: string } {
  try {
    const output = execFileSync("bun", [CLI, ...args], {
      cwd: process.cwd(),
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
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

function runCli(
  path: string,
  optimized = false,
): { readonly ok: boolean; readonly output: string } {
  return runCliArgs([...(optimized ? ["--optimized"] : []), path]);
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

function withTempJson<T>(source: string, callback: (path: string) => T): T {
  const directory = mkdtempSync(join(tmpdir(), "hermternal-pty-json-"));
  const path = join(directory, "artifact.json");
  writeFileSync(path, source);
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
  it("validates both checked-in v2 artifacts in both modes", () => {
    for (const path of [RECONNECT_ARTIFACT, CONNECTING_ARTIFACT]) {
      expect(() => validatePtyBenchmarkFile(path)).not.toThrow();
      expect(() =>
        validatePtyBenchmarkFile(path, { optimized: true }),
      ).not.toThrow();
    }
  });

  it("runs distinct standard and optimized CLI validation", () => {
    const artifact = cloneArtifact(RECONNECT_ARTIFACT);
    withTempArtifact(artifact, (path) => {
      const standard = runCli(path);
      const optimized = runCli(path, true);
      expect(standard.ok).toBe(true);
      expect(JSON.parse(standard.output)).toMatchObject({
        valid: true,
        optimized: false,
        validationMode: "standard-order-insensitive-provenance-and-proof-ledger",
      });
      expect(optimized.ok).toBe(true);
      expect(JSON.parse(optimized.output)).toMatchObject({
        valid: true,
        optimized: true,
        validationMode: "optimized-canonical-provenance-and-proof-ledger",
      });
    });

    withTempArtifact(cloneArtifact(CONNECTING_ARTIFACT), (path) => {
      expect(runCli(path).ok).toBe(true);
      expect(runCli(path, true).ok).toBe(true);
    });

    const reordered = cloneArtifact(RECONNECT_ARTIFACT);
    reordered.provenance.sourceBlobs.reverse();
    withTempArtifact(reordered, (path) => {
      expect(runCli(path).ok).toBe(true);
      const optimized = runCli(path, true);
      expect(optimized.ok).toBe(false);
      expect(optimized.output).toMatch(/canonical source blob ordering/iu);
    });
  });

  it("rejects schema-specific operation and metric metadata drift in both modes", () => {
    const cases = [
      {
        path: RECONNECT_ARTIFACT,
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
        path: CONNECTING_ARTIFACT,
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
      for (const optimized of [false, true]) {
        const operationDrift = cloneArtifact(path);
        operationDrift.operation = `${operation} drift`;
        expectCliFailure(operationDrift, /operation/iu, optimized);

        const missingOperation = cloneArtifact(path);
        delete missingOperation.operation;
        expectCliFailure(
          missingOperation,
          /operation|keys did not match/iu,
          optimized,
        );

        const methodDrift = cloneArtifact(path);
        methodDrift.method = `${methodDrift.method} drift`;
        expectCliFailure(methodDrift, /method/iu, optimized);

        for (const field of ["name", "unit", "clock", "start", "end"] as const) {
          const metricDrift = cloneArtifact(path);
          metricDrift.metric[field] = `${metric[field]} drift`;
          expectCliFailure(
            metricDrift,
            new RegExp(`metric\\.${field}`, "iu"),
            optimized,
          );
        }

        const missingStart = cloneArtifact(path);
        delete missingStart.metric.start;
        expectCliFailure(missingStart, /metric\.start|keys did not match/iu, optimized);

        const extraMetric = cloneArtifact(path);
        extraMetric.metric.extra = "not reviewed";
        expectCliFailure(extraMetric, /metric|keys did not match/iu, optimized);
      }
    }
  });

  it("enforces exact root metadata and nested runtime or OS keys in both modes", () => {
    for (const path of [RECONNECT_ARTIFACT, CONNECTING_ARTIFACT]) {
      for (const optimized of [false, true]) {
        const missingMethod = cloneArtifact(path);
        delete missingMethod.method;
        expectCliFailure(missingMethod, /method|keys did not match/iu, optimized);

        const extraRoot = cloneArtifact(path);
        extraRoot.unreviewed = true;
        expectCliFailure(extraRoot, /artifact|keys did not match/iu, optimized);

        const reorderedRoot = Object.fromEntries(
          Object.entries(cloneArtifact(path)).reverse(),
        ) as MutableArtifact;
        const reorderedResult = withTempArtifact(reorderedRoot, (tempPath) =>
          runCli(tempPath, optimized),
        );
        if (optimized) {
          expect(reorderedResult.ok).toBe(false);
          expect(reorderedResult.output).toMatch(/canonical order/iu);
        } else {
          expect(reorderedResult.ok).toBe(true);
        }

        for (const nested of ["runtime", "os"] as const) {
          const nestedArtifact = cloneArtifact(path);
          const nestedValue = nestedArtifact.provenance[nested];
          const key = nested === "runtime" ? "bun" : "platform";
          delete nestedValue[key];
          expectCliFailure(
            nestedArtifact,
            new RegExp(`provenance\\.${nested}.*keys|provenance\\.${nested}\\.${key}`, "iu"),
            optimized,
          );

          const extraNested = cloneArtifact(path);
          extraNested.provenance[nested].unreviewed = true;
          expectCliFailure(
            extraNested,
            new RegExp(`provenance\\.${nested}.*keys|reviewed`, "iu"),
            optimized,
          );
        }
      }
    }
  });

  it("rejects arbitrary tracked blobs and source or command drift", () => {
    for (const optimized of [false, true]) {
      const arbitraryBlob = cloneArtifact(RECONNECT_ARTIFACT);
      arbitraryBlob.provenance.sourceBlobs[0].path =
        "apps/web/src/lib/terminal/pty-transport.md";
      expectCliFailure(
        arbitraryBlob,
        /expected benchmark input|omitted an expected/iu,
        optimized,
      );

      const extraBlobKey = cloneArtifact(RECONNECT_ARTIFACT);
      extraBlobKey.provenance.sourceBlobs[0].unreviewed = true;
      expectCliFailure(extraBlobKey, /sourceBlobs.*keys/iu, optimized);
    }

    const sourcePath = cloneArtifact(RECONNECT_ARTIFACT);
    sourcePath.sourcePath = "apps/web/src/lib/terminal/pty-transport.md";
    expectCliFailure(sourcePath, /sourcePath and command/iu);

    const command = cloneArtifact(RECONNECT_ARTIFACT);
    command.command = "bun src/lib/terminal/pty-connecting-ownership.bench.ts";
    expectCliFailure(command, /sourcePath and command/iu);
  });

  it("rejects unsupported v1 before attempting v2 metric checks in both modes", () => {
    const v1 = readArtifact("src/lib/terminal/pty-error-retention-benchmark.json");
    delete v1.metric.start;
    for (const optimized of [false, true]) {
      expectCliFailure(v1, /unsupported PTY benchmark schema/iu, optimized);
    }
  });

  it("rejects unknown and duplicate CLI flags while accepting the delimiter", () => {
    const unknown = runCliArgs(["--unknown"]);
    expect(unknown.ok).toBe(false);
    expect(unknown.output).toMatch(/unknown option --unknown/iu);
    expect(unknown.output).not.toMatch(/ENOENT|no such file/iu);

    const duplicate = runCliArgs(["--optimized", "--optimized"]);
    expect(duplicate.ok).toBe(false);
    expect(duplicate.output).toMatch(/duplicate --optimized/iu);

    const delimited = runCliArgs(["--", RECONNECT_ARTIFACT]);
    expect(delimited.ok).toBe(true);

    const defaults = runCliArgs([]);
    expect(defaults.ok).toBe(true);
  });

  it("rejects duplicate JSON object keys before JSON.parse overwrites them", () => {
    withTempJson(
      '{"schema":"hermternal.pty-unsupported-benchmark.v1","schema":"hermternal.pty-reconnect-supersession-benchmark.v2"}',
      (path) => {
        expect(() => validatePtyBenchmarkFile(path)).toThrow(
          /duplicate JSON object key/iu,
        );
      },
    );
  });

  it("requires exact schema assertion keys and proven true values", () => {
    const missing = cloneArtifact(RECONNECT_ARTIFACT);
    delete missing.results[0].runs[0].assertions.cleanupRecorded;
    expectCliFailure(missing, /keys did not match/iu);

    const renamed = cloneArtifact(RECONNECT_ARTIFACT);
    renamed.results[0].runs[0].assertions.cleanupRecordedProof =
      renamed.results[0].runs[0].assertions.cleanupRecorded;
    delete renamed.results[0].runs[0].assertions.cleanupRecorded;
    expectCliFailure(renamed, /keys did not match/iu);

    const falseProof = cloneArtifact(RECONNECT_ARTIFACT);
    falseProof.results[0].runs[0].assertions.cleanupRecorded = false;
    expectCliFailure(falseProof, /not proven true/iu);

    const fabricated = cloneArtifact(RECONNECT_ARTIFACT);
    fabricated.results[0].runs[0].assertions = { foo: true };
    expectCliFailure(fabricated, /keys did not match/iu);

    const connecting = cloneArtifact(CONNECTING_ARTIFACT);
    delete connecting.results[0].runs[0].assertions.connectingGuard;
    expectCliFailure(connecting, /keys did not match/iu);
  });

  it("binds proof assertions to validator counts, owners, cleanup, and late-event suppression", () => {
    const validatorCount = cloneArtifact(RECONNECT_ARTIFACT);
    validatorCount.results[0].runs[0].validatorCalls += 1;
    expectCliFailure(validatorCount, /expected ownership ledger/iu);

    const ownerIdentity = cloneArtifact(RECONNECT_ARTIFACT);
    ownerIdentity.results[0].runs[0].activeOwnerIdentities[0] = "other-session";
    expectCliFailure(ownerIdentity, /ownership identities/iu);

    const closeLedger = cloneArtifact(RECONNECT_ARTIFACT);
    closeLedger.results[0].runs[0].replacementSocketCloseCalls = 0;
    expectCliFailure(closeLedger, /expected ownership ledger/iu);

    const lateEventProof = cloneArtifact(CONNECTING_ARTIFACT);
    lateEventProof.results[3].runs[0].postCloseBytesEvents = 1;
    expectCliFailure(lateEventProof, /expected ownership ledger/iu);
  });

  it("rejects totals, distributions, repetition, and warmup drift", () => {
    const totals = cloneArtifact(RECONNECT_ARTIFACT);
    totals.results[0].totals.ticketRequests += 1;
    expectCliFailure(totals, /totals\.ticketRequests/iu);

    const distribution = cloneArtifact(RECONNECT_ARTIFACT);
    distribution.results[0].distribution.min += 1;
    expectCliFailure(distribution, /does not match its raw samples/iu);

    for (const [field, value] of [
      ["repetitions", 29],
      ["repetitions", 30.5],
      ["warmups", 4],
      ["warmups", 4.5],
    ] as const) {
      const metadata = cloneArtifact(RECONNECT_ARTIFACT);
      metadata[field] = value;
      expectCliFailure(metadata, /repetition metadata/iu);
    }
  });

  it("rejects attached checkout and runtime or engine provenance drift", () => {
    for (const optimized of [false, true]) {
      const attached = cloneArtifact(RECONNECT_ARTIFACT);
      attached.provenance.detachedHead = false;
      expectCliFailure(attached, /detached clean checkout/iu, optimized);

      const hostNode = cloneArtifact(RECONNECT_ARTIFACT);
      hostNode.provenance.runtime.hostNode = "24.3.0";
      expectCliFailure(hostNode, /hostNode|reviewed|package runtime|engines/iu, optimized);

      const declaredNode = cloneArtifact(RECONNECT_ARTIFACT);
      declaredNode.provenance.runtime.declaredNode = "24.3.0";
      expectCliFailure(declaredNode, /package runtime|reviewed|engines/iu, optimized);

      const cpuModel = cloneArtifact(RECONNECT_ARTIFACT);
      cpuModel.provenance.os.cpuModel = "attacker-cpu";
      expectCliFailure(cpuModel, /cpuModel|reviewed/iu, optimized);
    }
  });

  it("fails generation on the attached checkout instead of fabricating evidence", () => {
    try {
      execFileSync(
        "bun",
        ["src/lib/terminal/pty-reconnect-supersession.bench.ts"],
        {
          cwd: process.cwd(),
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
        },
      );
      throw new Error("benchmark unexpectedly succeeded");
    } catch (error) {
      const failure = error as { readonly stderr?: string | Uint8Array };
      const stderr =
        typeof failure.stderr === "string"
          ? failure.stderr
          : failure.stderr
            ? new TextDecoder().decode(failure.stderr)
            : "";
      expect(stderr).toMatch(/clean checkout/iu);
    }
  });

  it("rejects arbitrary source revisions or missing raw proof through the API", () => {
    const artifact = cloneArtifact(RECONNECT_ARTIFACT);
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
