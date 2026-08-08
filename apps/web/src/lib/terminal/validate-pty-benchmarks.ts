import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const DEFAULT_ARTIFACTS = [
  "src/lib/terminal/pty-reconnect-supersession-benchmark.json",
  "src/lib/terminal/pty-connecting-ownership-benchmark.json",
] as const;

const EXPECTED_STAGES: Record<string, readonly string[]> = {
  "hermternal.pty-reconnect-supersession-benchmark.v2": [
    "validator",
    "ticket",
    "factory",
  ],
  "hermternal.pty-connecting-ownership-benchmark.v2": [
    "abort",
    "close",
    "detach",
    "replace",
  ],
};

const REQUIRED_RUN_COUNTERS = [
  "ticketRequests",
  "socketFactoryCalls",
  "openedSockets",
  "cleanupCalls",
  "duplicateOwnerViolations",
] as const;

interface RecordLike {
  readonly [key: string]: unknown;
}

function asRecord(value: unknown, label: string): RecordLike {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as RecordLike;
}

function asString(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`${label} must be a string`);
  return value;
}

function asBoolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`);
  return value;
}

function asFiniteNumber(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new Error(`${label} must be a finite non-negative number`);
  }
  return value;
}

function asSamples(value: unknown, label: string): number[] {
  if (!Array.isArray(value) || value.length === 0) throw new Error(`${label} must be a non-empty array`);
  return value.map((sample, index) => asFiniteNumber(sample, `${label}[${index}]`));
}

function git(args: readonly string[]): string {
  try {
    return execFileSync("git", [...args], { encoding: "utf8" }).trim();
  } catch (error) {
    const detail = error instanceof Error ? `: ${error.message}` : "";
    throw new Error(`git ${args.join(" ")} failed${detail}`);
  }
}

function gitBytes(args: readonly string[]): Uint8Array {
  try {
    return execFileSync("git", [...args]);
  } catch (error) {
    const detail = error instanceof Error ? `: ${error.message}` : "";
    throw new Error(`git ${args.join(" ")} failed${detail}`);
  }
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function round(value: number): number {
  return Number(value.toFixed(6));
}

function percentile(sorted: readonly number[], quantile: number): number {
  const position = (sorted.length - 1) * quantile;
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  if (lower === upper) return sorted[lower]!;
  const fraction = position - lower;
  return sorted[lower]! + (sorted[upper]! - sorted[lower]!) * fraction;
}

function validateProvenance(root: RecordLike, schema: string): void {
  const provenance = asRecord(root.provenance, `${schema}.provenance`);
  const sourceRevision = asString(provenance.sourceRevision, "provenance.sourceRevision");
  const generationCommit = asString(provenance.generationCommit, "provenance.generationCommit");
  const sourceTree = asString(provenance.sourceTree, "provenance.sourceTree");
  if (!/^[0-9a-f]{40}$/u.test(sourceRevision)) {
    throw new Error("provenance.sourceRevision must be a full 40-hex commit SHA");
  }
  if (!/^[0-9a-f]{40}$/u.test(generationCommit) || generationCommit !== sourceRevision) {
    throw new Error("provenance.generationCommit must equal the measured source commit");
  }
  if (!/^[0-9a-f]{40}$/u.test(sourceTree)) {
    throw new Error("provenance.sourceTree must be a full 40-hex tree SHA");
  }
  git(["cat-file", "-e", `${sourceRevision}^{commit}`]);
  if (git(["rev-parse", `${sourceRevision}^{tree}`]) !== sourceTree) {
    throw new Error("provenance.sourceTree does not match sourceRevision");
  }
  if (provenance.cleanCheckout !== true) {
    throw new Error("benchmark evidence must be generated from a clean checkout");
  }
  const command = asString(provenance.command, "provenance.command");
  if (!command.includes("bun src/lib/terminal/") || command.includes("GIT_SOURCE_REVISION=")) {
    throw new Error("provenance.command must use the actual checked-out source commit without an arbitrary revision override");
  }
  asString(provenance.sourceCheckout, "provenance.sourceCheckout");

  const blobs = provenance.sourceBlobs;
  if (!Array.isArray(blobs) || blobs.length !== 4) {
    throw new Error("provenance.sourceBlobs must pin benchmark, transport, package, and lockfile blobs");
  }
  const blobPaths = new Set<string>();
  for (const [index, rawBlob] of blobs.entries()) {
    const blob = asRecord(rawBlob, `provenance.sourceBlobs[${index}]`);
    const path = asString(blob.path, `provenance.sourceBlobs[${index}].path`);
    const gitBlobSha = asString(blob.gitBlobSha, `provenance.sourceBlobs[${index}].gitBlobSha`);
    const fileSha256 = asString(blob.sha256, `provenance.sourceBlobs[${index}].sha256`);
    if (blobPaths.has(path)) throw new Error(`duplicate provenance blob path ${path}`);
    blobPaths.add(path);
    if (!/^[0-9a-f]{40}$/u.test(gitBlobSha) || !/^[0-9a-f]{64}$/u.test(fileSha256)) {
      throw new Error(`invalid provenance hash for ${path}`);
    }
    if (git(["rev-parse", `${sourceRevision}:${path}`]) !== gitBlobSha) {
      throw new Error(`git blob drift for ${path}`);
    }
    if (sha256(gitBytes(["show", `${sourceRevision}:${path}`])) !== fileSha256) {
      throw new Error(`file hash drift for ${path}`);
    }
    if (path.endsWith(".bench.ts")) {
      const source = new TextDecoder().decode(gitBytes(["show", `${sourceRevision}:${path}`]));
      if (/Promise\.all\s*\(/u.test(source)) {
        throw new Error(`${path} must not run benchmark stages with Promise.all`);
      }
    }
  }
  for (const required of [
    "apps/web/src/lib/terminal/pty-transport.ts",
    "apps/web/package.json",
    "apps/web/bun.lock",
  ]) {
    if (!blobPaths.has(required)) throw new Error(`missing provenance blob ${required}`);
  }
  const runtime = asRecord(provenance.runtime, "provenance.runtime");
  asString(runtime.bun, "provenance.runtime.bun");
  asString(runtime.node, "provenance.runtime.node");
  asString(runtime.packageManager, "provenance.runtime.packageManager");
  const os = asRecord(provenance.os, "provenance.os");
  asString(os.platform, "provenance.os.platform");
  asString(os.release, "provenance.os.release");
  asString(os.architecture, "provenance.os.architecture");
  asString(os.cpuModel, "provenance.os.cpuModel");
  asFiniteNumber(os.cpuCount, "provenance.os.cpuCount");
}

function validateDistribution(samples: readonly number[], value: unknown, label: string): void {
  const distribution = asRecord(value, label);
  const sorted = samples.toSorted((left, right) => left - right);
  const expected = {
    min: round(sorted[0]!),
    median: round(percentile(sorted, 0.5)),
    p95: round(percentile(sorted, 0.95)),
  };
  for (const key of ["min", "median", "p95"] as const) {
    if (distribution[key] !== expected[key]) {
      throw new Error(`${label}.${key} does not match its raw samples`);
    }
  }
}

function validateResults(root: RecordLike, schema: string): void {
  const repetitions = asFiniteNumber(root.repetitions, `${schema}.repetitions`);
  const warmups = asFiniteNumber(root.warmups, `${schema}.warmups`);
  if (!Number.isInteger(repetitions) || repetitions < 1 || !Number.isInteger(warmups)) {
    throw new Error(`${schema} repetition metadata is invalid`);
  }
  if (root.sequential !== true || root.concurrentStages !== false) {
    throw new Error(`${schema} must explicitly record sequential stage execution`);
  }
  if (root.threshold !== null) throw new Error(`${schema} must not claim an unsupported threshold`);
  if (root.networkPolicy !== "synthetic-only") throw new Error(`${schema} must be synthetic-only`);
  const stageOrder = root.stageOrder;
  const expectedStages = EXPECTED_STAGES[schema]!;
  if (
    !Array.isArray(stageOrder) ||
    stageOrder.length !== expectedStages.length ||
    stageOrder.some((stage, index) => stage !== expectedStages[index])
  ) {
    throw new Error(`${schema}.stageOrder is not the deterministic sequential order`);
  }
  const results = root.results;
  if (!Array.isArray(results) || results.length !== expectedStages.length) {
    throw new Error(`${schema}.results does not match stageOrder`);
  }
  for (const [resultIndex, rawResult] of results.entries()) {
    const result = asRecord(rawResult, `${schema}.results[${resultIndex}]`);
    const stage = asString(result.stage, `${schema}.results[${resultIndex}].stage`);
    if (stage !== expectedStages[resultIndex]) throw new Error(`${schema} stage order drift at ${stage}`);
    const samples = asSamples(result.samples, `${schema}.${stage}.samples`);
    if (samples.length !== repetitions) throw new Error(`${schema}.${stage} sample count drift`);
    validateDistribution(samples, result.distribution, `${schema}.${stage}.distribution`);
    const runs = result.runs;
    if (!Array.isArray(runs) || runs.length !== repetitions) {
      throw new Error(`${schema}.${stage}.runs must retain every raw run proof`);
    }
    const totals = asRecord(result.totals, `${schema}.${stage}.totals`);
    const sums = new Map<string, number>();
    for (const [runIndex, rawRun] of runs.entries()) {
      const run = asRecord(rawRun, `${schema}.${stage}.runs[${runIndex}]`);
      if (round(asFiniteNumber(run.sampleMs, "run.sampleMs")) !== samples[runIndex]) {
        throw new Error(`${schema}.${stage}.runs[${runIndex}] does not match its raw sample`);
      }
      for (const counter of REQUIRED_RUN_COUNTERS) {
        const value = asFiniteNumber(run[counter], `${schema}.${stage}.runs[${runIndex}].${counter}`);
        sums.set(counter, (sums.get(counter) ?? 0) + value);
      }
      const activeOwnerCount = asFiniteNumber(
        run.activeOwnerCount,
        `${schema}.${stage}.runs[${runIndex}].activeOwnerCount`,
      );
      if (activeOwnerCount > 1) throw new Error(`${schema}.${stage}.runs[${runIndex}] had duplicate active owners`);
      const assertions = asRecord(run.assertions, `${schema}.${stage}.runs[${runIndex}].assertions`);
      const assertionValues = Object.values(assertions);
      if (assertionValues.length === 0 || assertionValues.some((value) => value !== true)) {
        throw new Error(`${schema}.${stage}.runs[${runIndex}] contains a failed proof assertion`);
      }
    }
    for (const counter of REQUIRED_RUN_COUNTERS) {
      const total = asFiniteNumber(totals[counter], `${schema}.${stage}.totals.${counter}`);
      if (total !== sums.get(counter)) {
        throw new Error(`${schema}.${stage}.totals.${counter} does not match raw runs`);
      }
    }
  }
}

export function validatePtyBenchmarkArtifact(artifact: unknown): void {
  const root = asRecord(artifact, "benchmark artifact");
  const schema = asString(root.schema, "benchmark.schema");
  if (!(schema in EXPECTED_STAGES)) throw new Error(`unsupported PTY benchmark schema ${schema}`);
  validateProvenance(root, schema);
  validateResults(root, schema);
}

export function validatePtyBenchmarkFile(path: string): void {
  validatePtyBenchmarkArtifact(JSON.parse(readFileSync(path, "utf8")));
}

