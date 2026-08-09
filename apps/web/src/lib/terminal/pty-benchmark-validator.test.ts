import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  parseGitChangedPaths,
  validatePtyBenchmarkArtifact,
  validatePtyBenchmarkFile,
} from "./validate-pty-benchmarks";
import { REVIEWED_PTY_BENCHMARK_TRUST_PIN } from "./pty-benchmark-trust-pin";

const CHECKED_IN_RECONNECT_ARTIFACT =
  "src/lib/terminal/pty-reconnect-supersession-benchmark.json";
const CHECKED_IN_CONNECTING_ARTIFACT =
  "src/lib/terminal/pty-connecting-ownership-benchmark.json";
const RECONNECT_BENCHMARK =
  "src/lib/terminal/pty-reconnect-supersession.bench.ts";
const CONNECTING_BENCHMARK =
  "src/lib/terminal/pty-connecting-ownership.bench.ts";
const CLI = join(process.cwd(), "src/lib/terminal/pty-benchmark-validator.ts");

let reconnectArtifactPath = CHECKED_IN_RECONNECT_ARTIFACT;
let connectingArtifactPath = CHECKED_IN_CONNECTING_ARTIFACT;
let harnessArtifactDirectory: string | undefined;
let harnessEvidenceAppDirectory: string | undefined;
let harnessSourceRevision: string | undefined;
let harnessEvidenceRevision: string | undefined;

type MutableArtifact = Record<string, any>;

function git(cwd: string, args: readonly string[]): string {
  return execFileSync("git", args, { cwd, encoding: "utf8" }).trim();
}

function readArtifact(path: string): MutableArtifact {
  return JSON.parse(readFileSync(path, "utf8")) as MutableArtifact;
}

function sourceBlobsForRevision(
  revision: string,
  paths: readonly string[],
): Array<{ readonly path: string; readonly gitBlobSha: string; readonly sha256: string }> {
  const repoRoot = git(process.cwd(), ["rev-parse", "--show-toplevel"]);
  return paths.map((path) => {
    const bytes = execFileSync("git", ["show", `${revision}:${path}`], {
      cwd: repoRoot,
    });
    return {
      path,
      gitBlobSha: git(repoRoot, ["rev-parse", `${revision}:${path}`]),
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
  });
}

function cloneArtifact(path: string): MutableArtifact {
  return JSON.parse(JSON.stringify(readArtifact(path))) as MutableArtifact;
}

function removeWorktree(repoRoot: string, checkout: string): void {
  try {
    execFileSync("git", ["worktree", "remove", "--force", checkout], {
      cwd: repoRoot,
      stdio: "ignore",
    });
  } catch {
    // Preserve the original test failure; cleanup is best effort.
  }
}

function generateHarnessArtifacts(): void {
  const repoRoot = git(process.cwd(), ["rev-parse", "--show-toplevel"]);
  const directory = mkdtempSync(join(tmpdir(), "hermternal-pty-harness-"));
  const sourceCheckout = join(directory, "source");
  const evidenceCheckout = join(directory, "evidence");
  let sourceAdded = false;
  let evidenceAdded = false;
  try {
    const sourceRevision = REVIEWED_PTY_BENCHMARK_TRUST_PIN.sourceRevision;
    const trustedRevision = git(repoRoot, ["rev-parse", "HEAD"]);
    expect(trustedRevision).not.toBe(sourceRevision);
    execFileSync(
      "git",
      ["worktree", "add", "--detach", "--quiet", sourceCheckout, sourceRevision],
      { cwd: repoRoot, stdio: ["ignore", "ignore", "pipe"] },
    );
    sourceAdded = true;
    expect(git(sourceCheckout, ["rev-parse", "HEAD"])).toBe(sourceRevision);
    expect(git(sourceCheckout, ["rev-parse", "--abbrev-ref", "HEAD"])).toBe(
      "HEAD",
    );
    const benchmarkCwd = join(sourceCheckout, "apps/web");
    const reconnectOutput = execFileSync("bun", [RECONNECT_BENCHMARK], {
      cwd: benchmarkCwd,
      encoding: "utf8",
    });
    const connectingOutput = execFileSync("bun", [CONNECTING_BENCHMARK], {
      cwd: benchmarkCwd,
      encoding: "utf8",
    });

    execFileSync(
      "git",
      ["worktree", "add", "--detach", "--quiet", evidenceCheckout, trustedRevision],
      { cwd: repoRoot, stdio: ["ignore", "ignore", "pipe"] },
    );
    evidenceAdded = true;
    const evidenceAppDirectory = join(evidenceCheckout, "apps/web");
    reconnectArtifactPath = join(evidenceAppDirectory, CHECKED_IN_RECONNECT_ARTIFACT);
    connectingArtifactPath = join(evidenceAppDirectory, CHECKED_IN_CONNECTING_ARTIFACT);
    writeFileSync(reconnectArtifactPath, reconnectOutput);
    writeFileSync(connectingArtifactPath, connectingOutput);
    execFileSync(
      "git",
      [
        "add",
        "apps/web/src/lib/terminal/pty-reconnect-supersession-benchmark.json",
        "apps/web/src/lib/terminal/pty-connecting-ownership-benchmark.json",
      ],
      { cwd: evidenceCheckout, stdio: "ignore" },
    );
    execFileSync(
      "git",
      [
        "-c",
        "user.name=Hermternal PTY Test",
        "-c",
        "user.email=hermternal-pty-test@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "test: add temporary PTY benchmark evidence",
      ],
      { cwd: evidenceCheckout, stdio: "ignore" },
    );
    const evidenceRevision = git(evidenceCheckout, ["rev-parse", "HEAD"]);
    expect(evidenceRevision).not.toBe(sourceRevision);
    execFileSync(
      "git",
      ["merge-base", "--is-ancestor", sourceRevision, evidenceRevision],
      { cwd: evidenceCheckout, stdio: "ignore" },
    );
    execFileSync(
      "git",
      ["merge-base", "--is-ancestor", trustedRevision, evidenceRevision],
      { cwd: evidenceCheckout, stdio: "ignore" },
    );
    removeWorktree(repoRoot, sourceCheckout);
    sourceAdded = false;
    harnessArtifactDirectory = directory;
    harnessEvidenceAppDirectory = evidenceAppDirectory;
    harnessSourceRevision = sourceRevision;
    harnessEvidenceRevision = evidenceRevision;
  } catch (error) {
    if (sourceAdded) removeWorktree(repoRoot, sourceCheckout);
    if (evidenceAdded) removeWorktree(repoRoot, evidenceCheckout);
    rmSync(directory, { recursive: true, force: true });
    throw error;
  }
}

beforeAll(generateHarnessArtifacts);
afterAll(() => {
  if (harnessArtifactDirectory !== undefined) {
    const repoRoot = git(process.cwd(), ["rev-parse", "--show-toplevel"]);
    removeWorktree(repoRoot, join(harnessArtifactDirectory, "evidence"));
    rmSync(harnessArtifactDirectory, { recursive: true, force: true });
  }
});

function runCliArgs(
  args: readonly string[],
  cwd = harnessEvidenceAppDirectory ?? process.cwd(),
): { readonly ok: boolean; readonly output: string } {
  try {
    const output = execFileSync("bun", [CLI, ...args], {
      cwd,
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
  const path =
    artifact.schema === "hermternal.pty-connecting-ownership-benchmark.v2"
      ? connectingArtifactPath
      : reconnectArtifactPath;
  const original = readFileSync(path);
  writeFileSync(path, JSON.stringify(artifact, null, 2));
  try {
    return callback(path);
  } finally {
    writeFileSync(path, original);
  }
}

function withTempJson<T>(source: string, callback: (path: string) => T): T {
  const path = reconnectArtifactPath;
  const original = readFileSync(path);
  writeFileSync(path, source);
  try {
    return callback(path);
  } finally {
    writeFileSync(path, original);
  }
}

function withDetachedCheckout<T>(
  revision: string,
  callback: (checkout: string) => T,
): T {
  const repoRoot = git(process.cwd(), ["rev-parse", "--show-toplevel"]);
  const directory = mkdtempSync(join(tmpdir(), "hermternal-pty-checkout-"));
  const checkout = join(directory, "checkout");
  execFileSync(
    "git",
    ["worktree", "add", "--detach", "--quiet", checkout, revision],
    { cwd: repoRoot, stdio: ["ignore", "ignore", "pipe"] },
  );
  try {
    expect(git(checkout, ["rev-parse", "--abbrev-ref", "HEAD"])).toBe("HEAD");
    return callback(checkout);
  } finally {
    removeWorktree(repoRoot, checkout);
    rmSync(directory, { recursive: true, force: true });
  }
}

function withWorkingDirectory<T>(directory: string, callback: () => T): T {
  const original = process.cwd();
  process.chdir(directory);
  try {
    return callback();
  } finally {
    process.chdir(original);
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

describe("PTY benchmark evidence validator", { timeout: 30_000 }, () => {
  it("validates detached source generation in an evidence-only successor", () => {
    expect(harnessSourceRevision).toMatch(/^[0-9a-f]{40}$/u);
    expect(harnessEvidenceRevision).toMatch(/^[0-9a-f]{40}$/u);
    expect(harnessEvidenceRevision).not.toBe(harnessSourceRevision);
    for (const path of [reconnectArtifactPath, connectingArtifactPath]) {
      const artifact = readArtifact(path);
      expect(artifact.provenance.sourceRevision).toBe(harnessSourceRevision);
      expect(artifact.provenance.generationCommit).toBe(harnessSourceRevision);
      expect(artifact.provenance.cleanCheckout).toBe(true);
      expect(artifact.provenance.detachedHead).toBe(true);
      expect(artifact.provenance.sourceBlobs).toHaveLength(5);
      withWorkingDirectory(harnessEvidenceAppDirectory!, () => {
        expect(() => validatePtyBenchmarkFile(path)).not.toThrow();
        expect(() =>
          validatePtyBenchmarkFile(path, { optimized: true }),
        ).not.toThrow();
      });
    }
  });

  it("binds the reviewed source manifest to exact Git objects", () => {
    const repoRoot = git(process.cwd(), ["rev-parse", "--show-toplevel"]);
    const sourceRevision = REVIEWED_PTY_BENCHMARK_TRUST_PIN.sourceRevision;
    expect(git(repoRoot, ["rev-parse", `${sourceRevision}^{tree}`])).toBe(
      REVIEWED_PTY_BENCHMARK_TRUST_PIN.sourceTree,
    );
    expect(
      sourceBlobsForRevision(
        sourceRevision,
        REVIEWED_PTY_BENCHMARK_TRUST_PIN.sourceBlobs.map((entry) => entry.path),
      ),
    ).toEqual(REVIEWED_PTY_BENCHMARK_TRUST_PIN.sourceBlobs);

    const trustedHead = git(repoRoot, ["rev-parse", "HEAD"]);
    for (const entry of REVIEWED_PTY_BENCHMARK_TRUST_PIN.trustedCode) {
      expect(git(repoRoot, ["rev-parse", `${trustedHead}:${entry.path}`])).toBe(
        entry.gitBlobSha,
      );
    }
  });

  it("keeps intentionally stale checked-in evidence out of the positive path", () => {
    expect(() => validatePtyBenchmarkFile(CHECKED_IN_RECONNECT_ARTIFACT)).toThrow(
      /reviewed PTY source pin|followed only by evidence changes|schema-specific contract|reviewed metric contract/iu,
    );
    expect(() => validatePtyBenchmarkFile(CHECKED_IN_CONNECTING_ARTIFACT)).toThrow(
      /reviewed PTY source pin|followed only by evidence changes|schema-specific contract|reviewed metric contract/iu,
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
        validationMode: "standard-order-insensitive-provenance-and-proof-ledger",
      });
      expect(optimized.ok).toBe(true);
      expect(JSON.parse(optimized.output)).toMatchObject({
        valid: true,
        optimized: true,
        validationMode: "optimized-canonical-provenance-and-proof-ledger",
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

  it("rejects prototype schema names before any v2 metadata checks", () => {
    const artifact = cloneArtifact(reconnectArtifactPath);
    for (const schema of ["__proto__", "constructor", "toString"]) {
      const candidate: MutableArtifact = { ...artifact, schema };
      Reflect.deleteProperty(candidate, "metric");
      expect(() => validatePtyBenchmarkArtifact(candidate)).toThrow(
        new RegExp(`^unsupported PTY benchmark schema ${schema}$`, "iu"),
      );
    }
  });

  it("rejects exact changed-path parser hazards without trimming", () => {
    expect(parseGitChangedPaths(new TextEncoder().encode("safe/path\0"))).toEqual([
      "safe/path",
    ]);
    for (const bytes of [
      new TextEncoder().encode(" leading/path\0"),
      new TextEncoder().encode("trailing/path \0"),
      new TextEncoder().encode("line\nfeed/path\0"),
      new TextEncoder().encode("duplicate/path\0duplicate/path\0"),
      new Uint8Array([0xff, 0x00]),
      new TextEncoder().encode("unterminated/path"),
    ]) {
      expect(() => parseGitChangedPaths(bytes)).toThrow(
        /changed path|changed-path output|NUL terminated/iu,
      );
    }
  });

  it("rejects unsafe names from actual NUL-delimited Git output", () => {
    const directory = mkdtempSync(join(tmpdir(), "hermternal-pty-paths-"));
    const names = [" leading.json", "trailing.json ", "line\nfeed.json"];
    try {
      execFileSync("git", ["-c", "init.defaultBranch=main", "init", "--quiet"], {
        cwd: directory,
        stdio: "ignore",
      });
      execFileSync("git", ["config", "user.name", "Hermternal PTY Test"], {
        cwd: directory,
        stdio: "ignore",
      });
      execFileSync(
        "git",
        ["config", "user.email", "hermternal-pty-test@example.invalid"],
        { cwd: directory, stdio: "ignore" },
      );
      for (const name of names) writeFileSync(join(directory, name), "base\\n");
      execFileSync("git", ["add", "--", ...names], {
        cwd: directory,
        stdio: "ignore",
      });
      execFileSync("git", ["commit", "--quiet", "-m", "base"], {
        cwd: directory,
        stdio: "ignore",
      });
      for (const name of names) {
        writeFileSync(join(directory, name), "base\\nchanged\\n");
        const changedPaths = execFileSync(
          "git",
          ["diff", "--name-only", "-z", "HEAD", "--", name],
          { cwd: directory },
        );
        expect(() => parseGitChangedPaths(changedPaths)).toThrow(
          /whitespace|control/iu,
        );
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
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

    const delimited = runCliArgs(["--", reconnectArtifactPath]);
    expect(delimited.ok).toBe(true);
  });

  it("rejects duplicate JSON keys, including nested metadata keys", () => {
    withTempJson(
      '{"schema":"hermternal.pty-reconnect-supersession-benchmark.v2","metric":{"name":"x","name":"y"}}',
      (path) => {
        expect(() => validatePtyBenchmarkFile(path)).toThrow(
          /duplicate JSON object key/iu,
        );
      },
    );
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
          start:
            "performance.now immediately before ordinary detach begins quarantine settlement",
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
            "performance.now at the connecting state lifecycle event before observer cancellation or replacement action",
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

  it("requires canonical nested ordering only in optimized mode", () => {
    const cases: Array<{
      readonly label: string;
      readonly mutate: (artifact: MutableArtifact) => void;
    }> = [
      {
        label: "metric",
        mutate: (artifact) => {
          artifact.metric = Object.fromEntries(
            Object.entries(artifact.metric).reverse(),
          );
        },
      },
      {
        label: "runtime",
        mutate: (artifact) => {
          artifact.provenance.runtime = Object.fromEntries(
            Object.entries(artifact.provenance.runtime).reverse(),
          );
        },
      },
      {
        label: "source blobs",
        mutate: (artifact) => artifact.provenance.sourceBlobs.reverse(),
      },
    ];
    for (const { mutate } of cases) {
      const reordered = cloneArtifact(reconnectArtifactPath);
      mutate(reordered);
      expectCliFailure(reordered, /canonical|optimized/iu, true);
      withTempArtifact(reordered, (path) => {
        expect(runCli(path).ok).toBe(true);
      });
    }
  }, 30_000);

  it(
    "enforces exact root, method, result, distribution, and nested metadata keys",
    () => {
    for (const optimized of [false, true]) {
      const extraRoot = cloneArtifact(reconnectArtifactPath);
      extraRoot.unreviewed = true;
      expectCliFailure(extraRoot, /artifact.*keys/iu, optimized);

      const method = cloneArtifact(reconnectArtifactPath);
      method.method = `${method.method} drift`;
      expectCliFailure(method, /method/iu, optimized);

      const extraResult = cloneArtifact(reconnectArtifactPath);
      extraResult.results[0].unreviewed = true;
      expectCliFailure(extraResult, /results\[0\].*keys/iu, optimized);

      const extraDistribution = cloneArtifact(reconnectArtifactPath);
      extraDistribution.results[0].distribution.unreviewed = true;
      expectCliFailure(
        extraDistribution,
        /distribution.*keys/iu,
        optimized,
      );

      const extraSocketClosure = cloneArtifact(reconnectArtifactPath);
      extraSocketClosure.results[2].runs[0].socketClosures[0].unreviewed = true;
      expectCliFailure(extraSocketClosure, /socketClosures.*keys/iu, optimized);

      const extraRuntime = cloneArtifact(reconnectArtifactPath);
      extraRuntime.provenance.runtime.unreviewed = true;
      expectCliFailure(extraRuntime, /provenance\.runtime.*keys/iu, optimized);

      const extraOs = cloneArtifact(reconnectArtifactPath);
      extraOs.provenance.os.unreviewed = true;
      expectCliFailure(extraOs, /provenance\.os.*keys/iu, optimized);
    }
    },
    30_000,
  );

  it("rejects four-blob legacy provenance on every current v2 artifact", () => {
    const legacyV2 = cloneArtifact(reconnectArtifactPath);
    legacyV2.provenance.sourceBlobs = legacyV2.provenance.sourceBlobs.slice(0, 4);
    expectCliFailure(legacyV2, /v2.*exactly five|reviewed helper/iu);
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
    expectCliFailure(falseProof, /not bound to its proof ledger|not proven true/iu);

    const fabricated = cloneArtifact(reconnectArtifactPath);
    fabricated.results[0].runs[0].assertions = { foo: true };
    expectCliFailure(fabricated, /keys did not match/iu);

    const connecting = cloneArtifact(connectingArtifactPath);
    delete connecting.results[0].runs[0].assertions.connectingGuard;
    expectCliFailure(connecting, /keys did not match/iu);
  }, 30_000);

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
  }, 30_000);

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
      /callbackProofApplicable did not match the expected replacement\/recovery stage/iu,
    );

    const callbackBoundSocketCount = cloneArtifact(reconnectArtifactPath);
    callbackBoundSocketCount.results[0].runs[0].callbackBoundSocketCount -= 1;
    expectCliFailure(
      callbackBoundSocketCount,
      /callbackBoundSocketCount|callbackProofApplicable|callback.*(?:binding|applicability|proof)/iu,
    );
  });

  it("binds every connecting stale ledger to the producer owner tuple", () => {
    const producerOwner = {
      sessionId: "benchmark-session-a",
      attach: "benchmark-attach-a",
      processIdentity: "benchmark-process-a",
    };
    const exact = cloneArtifact(connectingArtifactPath);
    for (const result of exact.results) {
      const run = result.runs[0];
      expect(run.staleSocketIdentities[0]).toEqual(producerOwner);
      expect(run.staleSocketIdentity).toEqual(producerOwner);
      expect(run.socketClosures[0].ownerIdentity).toEqual(producerOwner);
    }
    withTempArtifact(exact, (path) => {
      expect(runCli(path).ok).toBe(true);
      expect(runCli(path, true).ok).toBe(true);
    });

    const unsuffixedTuple = {
      sessionId: "benchmark-session",
      attach: "benchmark-attach",
      processIdentity: "benchmark-process",
    };
    const forged = cloneArtifact(connectingArtifactPath);
    for (const result of forged.results) {
      const run = result.runs[0];
      run.staleSocketIdentities[0] = { ...unsuffixedTuple };
      run.staleSocketIdentity = { ...unsuffixedTuple };
      run.socketClosures[0].ownerIdentity = { ...unsuffixedTuple };
    }
    expectCliFailure(
      forged,
      /expected owner identity|deferred socket ledger|exact per-socket cleanup ledger|ownership identities/iu,
    );
  }, 30_000);

  it("rejects edits to retained callback, Blob, and replacement-state ledgers", () => {
    const sinkNames = cloneArtifact(connectingArtifactPath);
    sinkNames.results[3].runs[0].callbackBoundSinkNames.reverse();
    expectCliFailure(sinkNames, /callbackBoundSinkNames|sink bindings/iu);

    const sinkCount = cloneArtifact(connectingArtifactPath);
    sinkCount.results[3].runs[0].callbackBoundSinkCount -= 1;
    expectCliFailure(sinkCount, /callbackBoundSinkCount|sink bindings/iu);

    const boundFlag = cloneArtifact(reconnectArtifactPath);
    boundFlag.results[0].runs[0].callbackBindings[0].onmessageBound = false;
    expectCliFailure(boundFlag, /callback bindings|callbackBoundSocketCount/iu);

    const nullFlag = cloneArtifact(reconnectArtifactPath);
    nullFlag.results[0].runs[0].callbackBindings[0].onmessageNullAfterClose = false;
    expectCliFailure(nullFlag, /callback bindings|allCallbacksNullAfterClose/iu);

    const nullSummary = cloneArtifact(reconnectArtifactPath);
    nullSummary.results[0].runs[0].allCallbacksNullAfterClose = false;
    expectCliFailure(nullSummary, /allCallbacksNullAfterClose|callback bindings/iu);

    const blobEvents = cloneArtifact(reconnectArtifactPath);
    blobEvents.results[0].runs[0].delayedBlob.events = [
      "dispatch",
      "close",
      "conversion-start",
      "completion",
    ];
    expectCliFailure(blobEvents, /delayedBlob|Blob event ledger/iu);

    const replacementState = cloneArtifact(connectingArtifactPath);
    replacementState.results[3].runs[0].replacementStateStatus = "failed";
    expectCliFailure(replacementState, /replacementStateStatus/iu);
  }, 30_000);

  it("rejects non-zero stale publications at every named sink", () => {
    const sinks = ["onEvent", "subscribe", "onStateChange"] as const;
    const counters = ["eventCount", "stateCount", "bytesCount", "noticeCount"] as const;
    for (const path of [reconnectArtifactPath, connectingArtifactPath]) {
      for (const sink of sinks) {
        for (const counter of counters) {
          const artifact = cloneArtifact(path);
          artifact.results[0].runs[0].stalePublications[sink][counter] = 1;
          expectCliFailure(
            artifact,
            new RegExp(`stalePublications\\.${sink}|stale publication|event categories`, "iu"),
          );
        }
      }
    }
  }, 30_000);

  it("rejects delayed Blob count, ordering, and publication-proof drift", () => {
    const applicableCases = [
      { path: reconnectArtifactPath, resultIndex: 0 },
      { path: connectingArtifactPath, resultIndex: 3 },
    ] as const;
    for (const { path, resultIndex } of applicableCases) {
      for (const field of [
        "scheduledCount",
        "completionCount",
        "dispatchedBeforeClose",
        "conversionStartedBeforeClose",
        "resolvedAfterClose",
        "postCloseBytesRejected",
      ] as const) {
        const artifact = cloneArtifact(path);
        const delayedBlob = artifact.results[resultIndex].runs[0].delayedBlob;
        delayedBlob[field] =
          typeof delayedBlob[field] === "number" ? delayedBlob[field] + 1 : false;
        expectCliFailure(artifact, /delayedBlob/iu);
      }
    }

    const inapplicable = cloneArtifact(connectingArtifactPath);
    inapplicable.results[0].runs[0].delayedBlob.scheduledCount = 1;
    expectCliFailure(inapplicable, /delayedBlob/iu);
  }, 30_000);

  it("derives delayed Blob rejection from raw events and publication ledgers", () => {
    const falseClaim = cloneArtifact(reconnectArtifactPath);
    const falseClaimRun = falseClaim.results[0].runs[0];
    expect(falseClaimRun.assertions.delayedBlobPostClosePublicationRejected).toBe(true);
    falseClaimRun.delayedBlob.postCloseBytesRejected = false;
    expectCliFailure(
      falseClaim,
      /postCloseBytesRejected was not derived from the raw Blob event and publication ledgers/iu,
    );

    const inverseClaim = cloneArtifact(reconnectArtifactPath);
    const inverseClaimRun = inverseClaim.results[0].runs[0];
    expect(inverseClaimRun.assertions.delayedBlobPostClosePublicationRejected).toBe(true);
    inverseClaimRun.stalePublications.onEvent.bytesCount = 1;
    expectCliFailure(
      inverseClaim,
      /postCloseBytesRejected was not derived from the raw Blob event and publication ledgers/iu,
    );
  }, 30_000);

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
      ["warmups", 0],
      ["warmups", 4],
      ["warmups", 4.5],
    ] as const) {
      const metadata = cloneArtifact(reconnectArtifactPath);
      metadata[field] = value;
      expectCliFailure(metadata, /repetition metadata/iu);
    }

    const zeroRequiredCounter = cloneArtifact(reconnectArtifactPath);
    zeroRequiredCounter.results[0].runs[0].validatorCalls = 0;
    expectCliFailure(zeroRequiredCounter, /expected ownership ledger/iu);
  }, 30_000);

  it("rejects source/evidence HEAD equality and accepts a strict successor in both modes", () => {
    const artifact = readArtifact(reconnectArtifactPath);
    expect(harnessSourceRevision).toBeDefined();
    withDetachedCheckout(harnessSourceRevision!, (checkout) => {
      const artifactPath = join(
        checkout,
        "apps/web/src/lib/terminal/pty-reconnect-supersession-benchmark.json",
      );
      writeFileSync(artifactPath, JSON.stringify(artifact, null, 2));
      const cwd = join(checkout, "apps/web");
      for (const optimized of [false, true]) {
        const result = runCliArgs(
          [...(optimized ? ["--optimized"] : []), "src/lib/terminal/pty-reconnect-supersession-benchmark.json"],
          cwd,
        );
        expect(result.ok).toBe(false);
        expect(result.output).toMatch(
          /strict predecessor|trusted PTY pin|evidence checkout/iu,
        );
      }
    });

    withWorkingDirectory(harnessEvidenceAppDirectory!, () => {
      expect(() => validatePtyBenchmarkFile(reconnectArtifactPath)).not.toThrow();
      expect(() =>
        validatePtyBenchmarkFile(reconnectArtifactPath, { optimized: true }),
      ).not.toThrow();
    });
  });

  it("binds source trees, blobs, helper identity, and descendant paths", () => {
    const sourceTree = cloneArtifact(reconnectArtifactPath);
    sourceTree.provenance.sourceTree = "0".repeat(40);
    expectCliFailure(sourceTree, /sourceTree/iu);

    const blob = cloneArtifact(reconnectArtifactPath);
    blob.provenance.sourceBlobs[0].gitBlobSha = "0".repeat(40);
    expectCliFailure(blob, /git blob drift|reviewed PTY pin/iu);

    const fileHash = cloneArtifact(reconnectArtifactPath);
    fileHash.provenance.sourceBlobs[0].sha256 = "0".repeat(64);
    expectCliFailure(fileHash, /file hash drift|reviewed PTY pin/iu);

    const helper = cloneArtifact(reconnectArtifactPath);
    helper.provenance.sourceBlobs[4].gitBlobSha = "0".repeat(40);
    expectCliFailure(helper, /git blob drift|reviewed PTY pin/iu);

    const outside = mkdtempSync(join(tmpdir(), "hermternal-pty-outside-"));
    const outsidePath = join(outside, "artifact.json");
    writeFileSync(outsidePath, JSON.stringify(readArtifact(reconnectArtifactPath)));
    try {
      const result = runCliArgs([outsidePath]);
      expect(result.ok).toBe(false);
      expect(result.output).toMatch(/retained PTY benchmark JSON identities/iu);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("rejects non-ancestor source revisions and non-evidence descendants", () => {
    const nonAncestor = cloneArtifact(reconnectArtifactPath);
    const revision = git(process.cwd(), ["rev-parse", "c22358f"]);
    nonAncestor.provenance.sourceRevision = revision;
    nonAncestor.provenance.generationCommit = revision;
    nonAncestor.provenance.sourceTree = git(process.cwd(), [
      "rev-parse",
      `${revision}^{tree}`,
    ]);
    nonAncestor.provenance.sourceBlobs = sourceBlobsForRevision(
      revision,
      nonAncestor.provenance.sourceBlobs.map((blob: MutableArtifact) => blob.path),
    );
    expectCliFailure(nonAncestor, /not an ancestor|immutable reviewed PTY source pin/iu);

    expect(harnessEvidenceRevision).toBeDefined();
    withDetachedCheckout(harnessEvidenceRevision!, (checkout) => {
      const marker = join(checkout, "evidence-descendant-marker.txt");
      writeFileSync(marker, "unreviewed descendant change\n");
      execFileSync("git", ["add", "evidence-descendant-marker.txt"], {
        cwd: checkout,
        stdio: "ignore",
      });
      execFileSync(
        "git",
        [
          "-c",
          "user.name=Hermternal PTY Test",
          "-c",
          "user.email=hermternal-pty-test@example.invalid",
          "commit",
          "--quiet",
          "-m",
          "test: add forbidden descendant path",
        ],
        { cwd: checkout, stdio: "ignore" },
      );
      const result = runCliArgs(
        ["src/lib/terminal/pty-reconnect-supersession-benchmark.json"],
        join(checkout, "apps/web"),
      );
      expect(result.ok).toBe(false);
      expect(result.output).toMatch(
        /followed only by (?:the two retained evidence JSON paths|evidence changes)/iu,
      );
    });
  });

  it("rejects unreviewed source M forgery and validator or CLI drift before evidence E", () => {
    const repoRoot = git(process.cwd(), ["rev-parse", "--show-toplevel"]);
    const directory = mkdtempSync(join(tmpdir(), "hermternal-pty-unreviewed-") );
    const maliciousCheckout = join(directory, "malicious");
    const evidenceCheckout = join(directory, "evidence");
    let maliciousAdded = false;
    let evidenceAdded = false;
    try {
      execFileSync(
        "git",
        ["worktree", "add", "--detach", "--quiet", maliciousCheckout, git(repoRoot, ["rev-parse", "HEAD"])],
        { cwd: repoRoot, stdio: ["ignore", "ignore", "pipe"] },
      );
      maliciousAdded = true;
      const changedPaths = [
        "apps/web/src/lib/terminal/pty-reconnect-supersession.bench.ts",
        "apps/web/src/lib/terminal/pty-transport.ts",
        "apps/web/package.json",
        "apps/web/bun.lock",
        "apps/web/src/lib/terminal/pty-benchmark-validator.ts",
        "apps/web/src/lib/terminal/validate-pty-benchmarks.ts",
      ];
      for (const path of changedPaths) {
        writeFileSync(join(maliciousCheckout, path), `${readFileSync(join(maliciousCheckout, path), "utf8")}\n// unreviewed M\n`);
      }
      execFileSync("git", ["add", "--", ...changedPaths], {
        cwd: maliciousCheckout,
        stdio: "ignore",
      });
      execFileSync(
        "git",
        [
          "-c",
          "user.name=Hermternal PTY Test",
          "-c",
          "user.email=hermternal-pty-test@example.invalid",
          "commit",
          "--quiet",
          "-m",
          "test: create unreviewed PTY source M",
        ],
        { cwd: maliciousCheckout, stdio: "ignore" },
      );
      const maliciousRevision = git(maliciousCheckout, ["rev-parse", "HEAD"]);
      execFileSync(
        "git",
        ["worktree", "add", "--detach", "--quiet", evidenceCheckout, maliciousRevision],
        { cwd: repoRoot, stdio: ["ignore", "ignore", "pipe"] },
      );
      evidenceAdded = true;
      const forged = cloneArtifact(reconnectArtifactPath);
      forged.provenance.sourceRevision = maliciousRevision;
      forged.provenance.generationCommit = maliciousRevision;
      forged.provenance.sourceTree = git(evidenceCheckout, [
        "rev-parse",
        `${maliciousRevision}^{tree}`,
      ]);
      forged.provenance.sourceBlobs = sourceBlobsForRevision(
        maliciousRevision,
        forged.provenance.sourceBlobs.map((blob: MutableArtifact) => blob.path),
      );
      const forgedPath = join(
        evidenceCheckout,
        "apps/web/src/lib/terminal/pty-reconnect-supersession-benchmark.json",
      );
      const cleanPath = join(
        evidenceCheckout,
        "apps/web/src/lib/terminal/pty-connecting-ownership-benchmark.json",
      );
      writeFileSync(forgedPath, JSON.stringify(forged, null, 2));
      writeFileSync(cleanPath, JSON.stringify(readArtifact(connectingArtifactPath), null, 2));
      execFileSync(
        "git",
        ["add", "apps/web/src/lib/terminal/pty-reconnect-supersession-benchmark.json", "apps/web/src/lib/terminal/pty-connecting-ownership-benchmark.json"],
        { cwd: evidenceCheckout, stdio: "ignore" },
      );
      execFileSync(
        "git",
        [
          "-c",
          "user.name=Hermternal PTY Test",
          "-c",
          "user.email=hermternal-pty-test@example.invalid",
          "commit",
          "--quiet",
          "-m",
          "test: add forged evidence E",
        ],
        { cwd: evidenceCheckout, stdio: "ignore" },
      );
      const forgedResult = runCliArgs(
        ["src/lib/terminal/pty-reconnect-supersession-benchmark.json"],
        join(evidenceCheckout, "apps/web"),
      );
      expect(forgedResult.ok).toBe(false);
      expect(forgedResult.output).toMatch(/immutable reviewed PTY source pin|reviewed PTY source/iu);
      const driftResult = runCliArgs(
        ["src/lib/terminal/pty-connecting-ownership-benchmark.json"],
        join(evidenceCheckout, "apps/web"),
      );
      expect(driftResult.ok).toBe(false);
      expect(driftResult.output).toMatch(/two retained evidence JSON paths|unreviewed source or validator/iu);
    } finally {
      if (evidenceAdded) removeWorktree(repoRoot, evidenceCheckout);
      if (maliciousAdded) removeWorktree(repoRoot, maliciousCheckout);
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("rejects attached checkout and runtime or engine provenance drift", () => {
    const attached = cloneArtifact(reconnectArtifactPath);
    attached.provenance.detachedHead = false;
    expectCliFailure(attached, /detached clean checkout/iu);

    const dirty = cloneArtifact(reconnectArtifactPath);
    dirty.provenance.cleanCheckout = false;
    expectCliFailure(dirty, /detached clean checkout/iu);

    for (const [field, value] of [
      ["bun", "1.3.13"],
      ["packageManager", "bun@1.3.13"],
      ["declaredBun", "1.3.13"],
      ["hostNode", "24.3.0"],
      ["declaredNode", "24.3.0"],
    ] as const) {
      const runtime = cloneArtifact(reconnectArtifactPath);
      runtime.provenance.runtime[field] = value;
      expectCliFailure(runtime, /provenance\.runtime|package runtime|engines/iu);
    }

    for (const [field, value] of [
      ["platform", "linux"],
      ["release", "24.0.0"],
      ["architecture", "x86_64"],
      ["cpuModel", "unreviewed CPU"],
      ["cpuCount", 1],
    ] as const) {
      const operatingSystem = cloneArtifact(reconnectArtifactPath);
      operatingSystem.provenance.os[field] = value;
      expectCliFailure(operatingSystem, /provenance\.os|reviewed synthetic harness/iu);
    }
  }, 30_000);

  it("constructs and verifies its own attached and dirty generation failures", () => {
    const repoRoot = git(process.cwd(), ["rev-parse", "--show-toplevel"]);
    const directory = mkdtempSync(join(tmpdir(), "hermternal-pty-attached-"));
    const checkout = join(directory, "checkout");
    const branch = `pty-test-attached-${process.pid}-${Date.now()}`;
    try {
      execFileSync(
        "git",
        ["worktree", "add", "--quiet", "-b", branch, checkout, harnessSourceRevision!],
        { cwd: repoRoot, stdio: ["ignore", "ignore", "pipe"] },
      );
      expect(git(checkout, ["rev-parse", "--abbrev-ref", "HEAD"])).toBe(branch);
      expect(git(checkout, ["status", "--porcelain=v1"])).toBe("");
      expect(() =>
        execFileSync("bun", [RECONNECT_BENCHMARK], {
          cwd: join(checkout, "apps/web"),
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
        }),
      ).toThrow(/clean checkout|detached clean checkout/iu);
    } finally {
      removeWorktree(repoRoot, checkout);
      rmSync(directory, { recursive: true, force: true });
    }

    withDetachedCheckout(harnessSourceRevision!, (detachedCheckout) => {
      writeFileSync(join(detachedCheckout, "dirty-generation-marker.txt"), "dirty\n");
      expect(() =>
        execFileSync("bun", [RECONNECT_BENCHMARK], {
          cwd: join(detachedCheckout, "apps/web"),
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
        }),
      ).toThrow(/clean checkout/iu);
    });
  });

  it("accepts a matching and rejects mismatching GIT_SOURCE_REVISION overrides", () => {
    withDetachedCheckout(harnessSourceRevision!, (checkout) => {
      const benchmarkCwd = join(checkout, "apps/web");
      const matchingOutput = execFileSync("bun", [RECONNECT_BENCHMARK], {
        cwd: benchmarkCwd,
        encoding: "utf8",
        env: {
          ...process.env,
          GIT_SOURCE_REVISION: harnessSourceRevision,
        },
      });
      expect(JSON.parse(matchingOutput).provenance.sourceRevision).toBe(
        harnessSourceRevision,
      );

      const mismatch = git(process.cwd(), ["rev-parse", "c22358f"]);
      expect(() =>
        execFileSync("bun", [RECONNECT_BENCHMARK], {
          cwd: benchmarkCwd,
          encoding: "utf8",
          env: { ...process.env, GIT_SOURCE_REVISION: mismatch },
          stdio: ["ignore", "pipe", "pipe"],
        }),
      ).toThrow(/GIT_SOURCE_REVISION/iu);

      expect(() =>
        execFileSync("bun", [RECONNECT_BENCHMARK], {
          cwd: benchmarkCwd,
          encoding: "utf8",
          env: { ...process.env, GIT_SOURCE_REVISION: "not-a-revision" },
          stdio: ["ignore", "pipe", "pipe"],
        }),
      ).toThrow(/GIT_SOURCE_REVISION/iu);
    });
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

    const unknownRevision = "0".repeat(40);
    expect(() =>
      validatePtyBenchmarkArtifact({
        ...artifact,
        provenance: {
          ...artifact.provenance,
          sourceRevision: unknownRevision,
          generationCommit: unknownRevision,
        },
      }),
    ).toThrow(/git cat-file|failed|immutable reviewed PTY source pin/iu);

    withWorkingDirectory(harnessEvidenceAppDirectory!, () => {
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
});
