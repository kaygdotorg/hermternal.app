import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { PTY_BENCHMARK_SOURCES } from "./pty-benchmark-provenance";

const TRANSPORT_SOURCE = "apps/web/src/lib/terminal/pty-transport.ts";
const PACKAGE_SOURCE = "apps/web/package.json";
const LOCKFILE_SOURCE = "apps/web/bun.lock";
const EXPECTED_REPETITIONS = 30;
const EXPECTED_WARMUPS = 5;

const BENCHMARK_SPECS = {
  "hermternal.pty-reconnect-supersession-benchmark.v2": {
    operation: "same-identity reconnect after ordinary detach quarantine",
    metric: {
      name: "quarantine_settle_wall_time",
      unit: "ms",
      clock: "performance.now",
      start: "connect attempt starts",
      end: "ignored adapter settles after detach and blocked reconnect",
    },
    source: PTY_BENCHMARK_SOURCES.reconnect,
    stages: ["validator", "ticket", "factory"],
    assertionKeys: [
      "quarantineValidatorFence",
      "quarantineTicketFence",
      "quarantineFactoryFence",
      "expectedValidatorCount",
      "expectedTicketCount",
      "expectedFactoryCount",
      "staleSocketIdentityMatchesStage",
      "staleSocketClosedExactly",
      "staleSocketNeverOpened",
      "replacementIdentityMatchesExpected",
      "replacementOpenedExactlyOnce",
      "replacementClosedExactlyOnce",
      "replacementReachedAttached",
      "expectedOwnerIsOnlyActiveOwner",
      "noDuplicateOwners",
      "allCallbacksNullAfterClose",
      "staleCallbacksExercised",
      "staleOnopenIgnored",
      "staleOnmessageIgnored",
      "staleOnerrorIgnored",
      "staleOncloseIgnored",
      "noPostCloseStateEvents",
      "noPostCloseBytesEvents",
      "noPostCloseNoticeEvents",
      "cleanupRecorded",
    ],
    runKeys: [
      "sampleMs",
      "validatorCalls",
      "validatorCallsBeforeRecovery",
      "ticketRequests",
      "ticketRequestsBeforeRecovery",
      "socketFactoryCalls",
      "socketFactoryCallsBeforeRecovery",
      "openedSockets",
      "cleanupCalls",
      "duplicateOwnerViolations",
      "activeOwnerCount",
      "expectedOwnerIdentity",
      "activeOwnerIdentities",
      "staleSocketIdentities",
      "staleSocketIdentity",
      "staleSocketCloseCalls",
      "replacementSocketIdentity",
      "replacementSocketCloseCalls",
      "socketClosures",
      "staleCleanupCalls",
      "staleOpenCalls",
      "allCallbacksNullAfterClose",
      "staleOnopenDispatches",
      "staleOnmessageDispatches",
      "staleOnerrorDispatches",
      "staleOncloseDispatches",
      "postCloseStateEvents",
      "postCloseBytesEvents",
      "postCloseNoticeEvents",
      "assertions",
    ],
    runCounters: [
      "validatorCalls",
      "validatorCallsBeforeRecovery",
      "ticketRequests",
      "ticketRequestsBeforeRecovery",
      "socketFactoryCalls",
      "socketFactoryCallsBeforeRecovery",
      "openedSockets",
      "cleanupCalls",
      "duplicateOwnerViolations",
      "activeOwnerCount",
      "staleSocketCloseCalls",
      "replacementSocketCloseCalls",
      "staleCleanupCalls",
      "staleOpenCalls",
      "staleOnopenDispatches",
      "staleOnmessageDispatches",
      "staleOnerrorDispatches",
      "staleOncloseDispatches",
      "postCloseStateEvents",
      "postCloseBytesEvents",
      "postCloseNoticeEvents",
    ],
    totalCounters: [
      "validatorCalls",
      "ticketRequests",
      "socketFactoryCalls",
      "openedSockets",
      "cleanupCalls",
      "duplicateOwnerViolations",
    ],
  },
  "hermternal.pty-connecting-ownership-benchmark.v2": {
    operation: "connecting observer ownership decision before socket factory",
    metric: {
      name: "ownership_decision_settle_wall_time",
      unit: "ms",
      clock: "performance.now",
      start:
        "performance.now immediately before connecting observer cancellation or replacement action",
      end: "cancelled operation rejects",
    },
    source: PTY_BENCHMARK_SOURCES.connecting,
    stages: ["abort", "close", "detach", "replace"],
    assertionKeys: [
      "connectingGuard",
      "staleSocketNeverOpened",
      "expectedFactoryCount",
      "expectedTicketCount",
      "replacementOpenedExactlyOnce",
      "replacementAttached",
      "expectedOwnerIsOnlyActiveOwner",
      "noDuplicateOwners",
      "staleSocketIdentityFence",
      "replacementClosedExactlyOnce",
      "exactSocketCleanup",
      "allCallbacksNullAfterClose",
      "staleCallbacksExercised",
      "staleOnopenIgnored",
      "staleOnmessageIgnored",
      "staleOnerrorIgnored",
      "staleOncloseIgnored",
      "noPostCloseStateEvents",
      "noPostCloseBytesEvents",
      "noPostCloseNoticeEvents",
      "cleanupRecorded",
    ],
    runKeys: [
      "sampleMs",
      "ticketRequests",
      "socketFactoryCalls",
      "openedSockets",
      "cleanupCalls",
      "duplicateOwnerViolations",
      "activeOwnerCount",
      "expectedOwnerIdentity",
      "activeOwnerIdentities",
      "staleSocketIdentities",
      "staleSocketCloseCalls",
      "replacementSocketIdentity",
      "replacementSocketCloseCalls",
      "socketClosures",
      "staleOpenCalls",
      "allCallbacksNullAfterClose",
      "staleOnopenDispatches",
      "staleOnmessageDispatches",
      "staleOnerrorDispatches",
      "staleOncloseDispatches",
      "postCloseStateEvents",
      "postCloseBytesEvents",
      "postCloseNoticeEvents",
      "assertions",
    ],
    runCounters: [
      "ticketRequests",
      "socketFactoryCalls",
      "openedSockets",
      "cleanupCalls",
      "duplicateOwnerViolations",
      "activeOwnerCount",
      "staleSocketCloseCalls",
      "replacementSocketCloseCalls",
      "staleOpenCalls",
      "staleOnopenDispatches",
      "staleOnmessageDispatches",
      "staleOnerrorDispatches",
      "staleOncloseDispatches",
      "postCloseStateEvents",
      "postCloseBytesEvents",
      "postCloseNoticeEvents",
    ],
    totalCounters: [
      "ticketRequests",
      "socketFactoryCalls",
      "openedSockets",
      "cleanupCalls",
      "duplicateOwnerViolations",
    ],
  },
} as const;

type BenchmarkSchema = keyof typeof BENCHMARK_SPECS;
type BenchmarkSpec = (typeof BENCHMARK_SPECS)[BenchmarkSchema];

interface RecordLike {
  readonly [key: string]: unknown;
}

export interface PtyBenchmarkValidationOptions {
  /** Strict mode checks canonical provenance ordering and the complete ledger. */
  readonly optimized?: boolean;
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

function asFiniteNumber(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new Error(`${label} must be a finite non-negative number`);
  }
  return value;
}

function asSamples(value: unknown, label: string): number[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${label} must be a non-empty array`);
  }
  return value.map((sample, index) =>
    asFiniteNumber(sample, `${label}[${index}]`),
  );
}

function asStringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value.map((entry, index) => asString(entry, `${label}[${index}]`));
}

interface SocketClosure {
  readonly identity: string;
  readonly closeCalls: number;
}

function asSocketClosures(value: unknown, label: string): SocketClosure[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value.map((entry, index) => {
    const closure = asRecord(entry, `${label}[${index}]`);
    return {
      identity: asString(closure.identity, `${label}[${index}].identity`),
      closeCalls: asFiniteNumber(
        closure.closeCalls,
        `${label}[${index}].closeCalls`,
      ),
    };
  });
}

function expectStringArray(
  actual: readonly string[],
  expected: readonly string[],
  label: string,
): void {
  if (
    actual.length !== expected.length ||
    actual.some((value, index) => value !== expected[index])
  ) {
    throw new Error(`${label} did not match the expected ownership identities`);
  }
}

function expectSocketClosures(
  actual: readonly SocketClosure[],
  expected: readonly SocketClosure[],
  label: string,
): void {
  if (
    actual.length !== expected.length ||
    actual.some(
      (closure, index) =>
        closure.identity !== expected[index]?.identity ||
        closure.closeCalls !== expected[index]?.closeCalls,
    )
  ) {
    throw new Error(
      `${label} did not match the exact per-socket cleanup ledger`,
    );
  }
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

function expectedSpec(schema: string): BenchmarkSpec {
  if (!(schema in BENCHMARK_SPECS)) {
    throw new Error(`unsupported PTY benchmark schema ${schema}`);
  }
  return BENCHMARK_SPECS[schema as BenchmarkSchema];
}

function assertExactKeys(
  value: RecordLike,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).toSorted();
  const wanted = [...expected].toSorted();
  if (actual.join("\n") !== wanted.join("\n")) {
    throw new Error(`${label} keys did not match the schema-specific contract`);
  }
}

// Keep the operation and timing boundaries schema-specific so evidence cannot
// be relabeled while retaining a valid ownership proof ledger.
function validateOperationAndMetric(
  root: RecordLike,
  schema: BenchmarkSchema,
): void {
  const spec = BENCHMARK_SPECS[schema];
  if (asString(root.operation, `${schema}.operation`) !== spec.operation) {
    throw new Error(`${schema}.operation did not match the reviewed operation`);
  }

  const metric = asRecord(root.metric, `${schema}.metric`);
  const metricKeys = ["name", "unit", "clock", "start", "end"] as const;
  assertExactKeys(metric, metricKeys, `${schema}.metric`);
  for (const key of metricKeys) {
    if (asString(metric[key], `${schema}.metric.${key}`) !== spec.metric[key]) {
      throw new Error(
        `${schema}.metric.${key} did not match the reviewed metric contract`,
      );
    }
  }
}

function expectedRunCounters(
  schema: BenchmarkSchema,
  stage: string,
): Record<string, number> {
  if (schema === "hermternal.pty-reconnect-supersession-benchmark.v2") {
    const factory = stage === "factory";
    const ticket = stage !== "validator";
    return {
      validatorCalls: 2,
      validatorCallsBeforeRecovery: 1,
      ticketRequests: ticket ? 2 : 1,
      ticketRequestsBeforeRecovery: ticket ? 1 : 0,
      socketFactoryCalls: factory ? 2 : 1,
      socketFactoryCallsBeforeRecovery: factory ? 1 : 0,
      openedSockets: 1,
      cleanupCalls: factory ? 2 : 1,
      duplicateOwnerViolations: 0,
      activeOwnerCount: 1,
      staleSocketCloseCalls: factory ? 1 : 0,
      replacementSocketCloseCalls: 1,
      staleCleanupCalls: factory ? 1 : 0,
      staleOpenCalls: 0,
      staleOnopenDispatches: 1,
      staleOnmessageDispatches: 1,
      staleOnerrorDispatches: 1,
      staleOncloseDispatches: 1,
      postCloseStateEvents: 0,
      postCloseBytesEvents: 0,
      postCloseNoticeEvents: 0,
    };
  }
  const replacement = stage === "replace";
  return {
    ticketRequests: replacement ? 2 : 1,
    socketFactoryCalls: replacement ? 1 : 0,
    openedSockets: replacement ? 1 : 0,
    cleanupCalls: replacement ? 1 : 0,
    duplicateOwnerViolations: 0,
    activeOwnerCount: replacement ? 1 : 0,
    staleSocketCloseCalls: 0,
    replacementSocketCloseCalls: replacement ? 1 : 0,
    staleOpenCalls: 0,
    staleOnopenDispatches: replacement ? 1 : 0,
    staleOnmessageDispatches: replacement ? 1 : 0,
    staleOnerrorDispatches: replacement ? 1 : 0,
    staleOncloseDispatches: replacement ? 1 : 0,
    postCloseStateEvents: 0,
    postCloseBytesEvents: 0,
    postCloseNoticeEvents: 0,
  };
}

function validateRuntimeAndHost(provenance: RecordLike): void {
  const runtime = asRecord(provenance.runtime, "provenance.runtime");
  const bun = asString(runtime.bun, "provenance.runtime.bun");
  const node = asString(runtime.node, "provenance.runtime.node");
  const hostNode = asString(runtime.hostNode, "provenance.runtime.hostNode");
  const packageManager = asString(
    runtime.packageManager,
    "provenance.runtime.packageManager",
  );
  const declaredBun = asString(
    runtime.declaredBun,
    "provenance.runtime.declaredBun",
  );
  const declaredNode = asString(
    runtime.declaredNode,
    "provenance.runtime.declaredNode",
  );
  const semver = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/u;
  if (!semver.test(bun) || !semver.test(node) || !semver.test(hostNode)) {
    throw new Error(
      "provenance runtime versions must be exact semantic versions",
    );
  }
  if (packageManager !== `bun@${bun}` || declaredBun !== bun) {
    throw new Error(
      "provenance.runtime Bun fields must match the captured package runtime",
    );
  }
  if (hostNode !== declaredNode || !semver.test(declaredNode)) {
    throw new Error(
      "provenance.runtime.hostNode must match package.json engines.node",
    );
  }

  const os = asRecord(provenance.os, "provenance.os");
  const platform = asString(os.platform, "provenance.os.platform");
  const release = asString(os.release, "provenance.os.release");
  const architecture = asString(os.architecture, "provenance.os.architecture");
  const cpuModel = asString(os.cpuModel, "provenance.os.cpuModel");
  const cpuCount = asFiniteNumber(os.cpuCount, "provenance.os.cpuCount");
  if (!/^[a-z0-9._-]+$/u.test(platform) || platform === "unknown") {
    throw new Error("provenance.os.platform must identify the host platform");
  }
  if (!/^[a-zA-Z0-9._:+() -]+$/u.test(release) || release === "unknown") {
    throw new Error("provenance.os.release must identify the host release");
  }
  if (!/^[a-z0-9._-]+$/u.test(architecture) || architecture === "unknown") {
    throw new Error(
      "provenance.os.architecture must identify the host architecture",
    );
  }
  if (cpuModel.trim() === "" || cpuModel === "unknown") {
    throw new Error("provenance.os.cpuModel must identify the captured CPU");
  }
  if (!Number.isInteger(cpuCount) || cpuCount < 1) {
    throw new Error("provenance.os.cpuCount must be a positive integer");
  }
}

function validateProvenance(
  root: RecordLike,
  schema: BenchmarkSchema,
  optimized: boolean,
): void {
  const spec = BENCHMARK_SPECS[schema];
  const sourcePath = asString(root.sourcePath, `${schema}.sourcePath`);
  const command = asString(root.command, `${schema}.command`);
  if (sourcePath !== spec.source.path || command !== spec.source.command) {
    throw new Error(
      `${schema} sourcePath and command were not the reviewed benchmark pair`,
    );
  }

  const provenance = asRecord(root.provenance, `${schema}.provenance`);
  const sourceRevision = asString(
    provenance.sourceRevision,
    "provenance.sourceRevision",
  );
  const generationCommit = asString(
    provenance.generationCommit,
    "provenance.generationCommit",
  );
  const sourceTree = asString(provenance.sourceTree, "provenance.sourceTree");
  if (!/^[0-9a-f]{40}$/u.test(sourceRevision)) {
    throw new Error(
      "provenance.sourceRevision must be a full 40-hex commit SHA",
    );
  }
  if (
    !/^[0-9a-f]{40}$/u.test(generationCommit) ||
    generationCommit !== sourceRevision
  ) {
    throw new Error(
      "provenance.generationCommit must equal the measured source commit",
    );
  }
  if (!/^[0-9a-f]{40}$/u.test(sourceTree)) {
    throw new Error("provenance.sourceTree must be a full 40-hex tree SHA");
  }
  git(["cat-file", "-e", `${sourceRevision}^{commit}`]);
  if (git(["rev-parse", `${sourceRevision}^{tree}`]) !== sourceTree) {
    throw new Error("provenance.sourceTree does not match sourceRevision");
  }
  const evidenceHead = git(["rev-parse", "HEAD"]);
  try {
    execFileSync(
      "git",
      ["merge-base", "--is-ancestor", sourceRevision, evidenceHead],
      {
        stdio: "ignore",
      },
    );
  } catch {
    throw new Error(
      "provenance.sourceRevision was not an ancestor of the evidence checkout",
    );
  }
  const evidenceChangedPaths = git([
    "diff",
    "--name-only",
    `${sourceRevision}..${evidenceHead}`,
  ])
    .split("\n")
    .map((path) => path.trim())
    .filter(Boolean);
  const allowedEvidencePaths = new Set([
    "apps/web/src/lib/terminal/pty-reconnect-supersession-benchmark.json",
    "apps/web/src/lib/terminal/pty-connecting-ownership-benchmark.json",
  ]);
  if (evidenceChangedPaths.some((path) => !allowedEvidencePaths.has(path))) {
    throw new Error(
      "provenance.sourceRevision was not followed only by evidence changes",
    );
  }
  if (provenance.cleanCheckout !== true || provenance.detachedHead !== true) {
    throw new Error(
      "benchmark evidence must be generated from a detached clean checkout",
    );
  }
  if (asString(provenance.command, "provenance.command") !== command) {
    throw new Error("provenance.command must match the artifact command");
  }
  if (
    asString(provenance.sourceCheckout, "provenance.sourceCheckout") !==
    "git switch --detach <sourceRevision>"
  ) {
    throw new Error(
      "provenance.sourceCheckout must document detached source generation",
    );
  }
  validateRuntimeAndHost(provenance);

  const blobs = provenance.sourceBlobs;
  const expectedPaths = [
    spec.source.path,
    TRANSPORT_SOURCE,
    PACKAGE_SOURCE,
    LOCKFILE_SOURCE,
  ];
  if (!Array.isArray(blobs) || blobs.length !== expectedPaths.length) {
    throw new Error(
      "provenance.sourceBlobs must pin the benchmark source and transport inputs",
    );
  }
  const seen = new Set<string>();
  for (const [index, rawBlob] of blobs.entries()) {
    const blob = asRecord(rawBlob, `provenance.sourceBlobs[${index}]`);
    const path = asString(blob.path, `provenance.sourceBlobs[${index}].path`);
    const gitBlobSha = asString(
      blob.gitBlobSha,
      `provenance.sourceBlobs[${index}].gitBlobSha`,
    );
    const fileSha256 = asString(
      blob.sha256,
      `provenance.sourceBlobs[${index}].sha256`,
    );
    if (seen.has(path))
      throw new Error(`duplicate provenance blob path ${path}`);
    seen.add(path);
    if (!expectedPaths.includes(path as (typeof expectedPaths)[number])) {
      throw new Error(
        `provenance blob ${path} was not an expected benchmark input`,
      );
    }
    if (
      !/^[0-9a-f]{40}$/u.test(gitBlobSha) ||
      !/^[0-9a-f]{64}$/u.test(fileSha256)
    ) {
      throw new Error(`invalid provenance hash for ${path}`);
    }
    if (git(["rev-parse", `${sourceRevision}:${path}`]) !== gitBlobSha) {
      throw new Error(`git blob drift for ${path}`);
    }
    if (
      sha256(gitBytes(["show", `${sourceRevision}:${path}`])) !== fileSha256
    ) {
      throw new Error(`file hash drift for ${path}`);
    }
    if (path.endsWith(".bench.ts")) {
      const source = new TextDecoder().decode(
        gitBytes(["show", `${sourceRevision}:${path}`]),
      );
      if (/Promise\.all\s*\(/u.test(source)) {
        throw new Error(
          `${path} must not run benchmark stages with Promise.all`,
        );
      }
    }
  }
  if (seen.size !== expectedPaths.length) {
    throw new Error(
      "provenance.sourceBlobs omitted an expected benchmark input",
    );
  }
  if (
    optimized &&
    blobs.some(
      (rawBlob, index) =>
        asRecord(rawBlob, "provenance blob").path !== expectedPaths[index],
    )
  ) {
    throw new Error(
      "optimized provenance validation requires canonical source blob ordering",
    );
  }

  const packageSource = JSON.parse(
    new TextDecoder().decode(
      gitBytes(["show", `${sourceRevision}:${PACKAGE_SOURCE}`]),
    ),
  ) as {
    readonly packageManager?: unknown;
    readonly engines?: { readonly bun?: unknown; readonly node?: unknown };
  };
  const runtime = asRecord(provenance.runtime, "provenance.runtime");
  if (
    runtime.packageManager !== packageSource.packageManager ||
    runtime.declaredBun !== packageSource.engines?.bun ||
    runtime.declaredNode !== packageSource.engines?.node
  ) {
    throw new Error(
      "provenance runtime metadata did not match the declared package engines",
    );
  }
}

function validateDistribution(
  samples: readonly number[],
  value: unknown,
  label: string,
): void {
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

function validateOwnershipProof(
  schema: BenchmarkSchema,
  stage: string,
  run: RecordLike,
  label: string,
): void {
  const reconnect =
    schema === "hermternal.pty-reconnect-supersession-benchmark.v2";
  const replacement = stage === "replace";
  const expectedOwnerIdentity = reconnect
    ? "benchmark-session"
    : replacement
      ? "benchmark-session-b"
      : null;
  const expectedActiveIdentities =
    expectedOwnerIdentity === null ? [] : [expectedOwnerIdentity];
  const expectedStaleIdentities =
    reconnect && stage === "factory" ? ["benchmark-session"] : [];
  const expectedSocketClosures = reconnect
    ? stage === "factory"
      ? [
          { identity: "benchmark-session", closeCalls: 1 },
          { identity: "benchmark-session", closeCalls: 1 },
        ]
      : [{ identity: "benchmark-session", closeCalls: 1 }]
    : replacement
      ? [{ identity: "benchmark-session-b", closeCalls: 1 }]
      : [];

  if (expectedOwnerIdentity === null) {
    if (run.expectedOwnerIdentity !== null) {
      throw new Error(
        `${label}.expectedOwnerIdentity must be null without a replacement owner`,
      );
    }
    if (run.replacementSocketIdentity !== null) {
      throw new Error(
        `${label}.replacementSocketIdentity must be null without a replacement socket`,
      );
    }
  } else {
    if (
      asString(run.expectedOwnerIdentity, `${label}.expectedOwnerIdentity`) !==
      expectedOwnerIdentity
    ) {
      throw new Error(
        `${label}.expectedOwnerIdentity did not match the authorized owner`,
      );
    }
    if (
      asString(
        run.replacementSocketIdentity,
        `${label}.replacementSocketIdentity`,
      ) !== expectedOwnerIdentity
    ) {
      throw new Error(
        `${label}.replacementSocketIdentity did not match the authorized owner`,
      );
    }
  }

  expectStringArray(
    asStringArray(run.activeOwnerIdentities, `${label}.activeOwnerIdentities`),
    expectedActiveIdentities,
    `${label}.activeOwnerIdentities`,
  );
  expectStringArray(
    asStringArray(run.staleSocketIdentities, `${label}.staleSocketIdentities`),
    expectedStaleIdentities,
    `${label}.staleSocketIdentities`,
  );
  if (reconnect) {
    const expectedStaleIdentity = expectedStaleIdentities[0] ?? null;
    if (run.staleSocketIdentity !== expectedStaleIdentity) {
      throw new Error(
        `${label}.staleSocketIdentity did not match the deferred socket ledger`,
      );
    }
  }
  expectSocketClosures(
    asSocketClosures(run.socketClosures, `${label}.socketClosures`),
    expectedSocketClosures,
    `${label}.socketClosures`,
  );
  if (run.allCallbacksNullAfterClose !== true) {
    throw new Error(
      `${label}.allCallbacksNullAfterClose did not prove callback disownership`,
    );
  }
}

function validateResults(root: RecordLike, schema: BenchmarkSchema): void {
  const spec = BENCHMARK_SPECS[schema];
  const repetitions = asFiniteNumber(root.repetitions, `${schema}.repetitions`);
  const warmups = asFiniteNumber(root.warmups, `${schema}.warmups`);
  if (
    !Number.isInteger(repetitions) ||
    !Number.isInteger(warmups) ||
    repetitions !== EXPECTED_REPETITIONS ||
    warmups !== EXPECTED_WARMUPS
  ) {
    throw new Error(
      `${schema} repetition metadata is not the reviewed deterministic run count`,
    );
  }
  if (root.sequential !== true || root.concurrentStages !== false) {
    throw new Error(
      `${schema} must explicitly record sequential stage execution`,
    );
  }
  if (root.threshold !== null)
    throw new Error(`${schema} must not claim an unsupported threshold`);
  if (root.networkPolicy !== "synthetic-only")
    throw new Error(`${schema} must be synthetic-only`);
  const stageOrder = root.stageOrder;
  if (
    !Array.isArray(stageOrder) ||
    stageOrder.length !== spec.stages.length ||
    stageOrder.some((stage, index) => stage !== spec.stages[index])
  ) {
    throw new Error(
      `${schema}.stageOrder is not the deterministic sequential order`,
    );
  }
  const results = root.results;
  if (!Array.isArray(results) || results.length !== spec.stages.length) {
    throw new Error(`${schema}.results does not match stageOrder`);
  }
  for (const [resultIndex, rawResult] of results.entries()) {
    const result = asRecord(rawResult, `${schema}.results[${resultIndex}]`);
    const stage = asString(
      result.stage,
      `${schema}.results[${resultIndex}].stage`,
    );
    if (stage !== spec.stages[resultIndex])
      throw new Error(`${schema} stage order drift at ${stage}`);
    const samples = asSamples(result.samples, `${schema}.${stage}.samples`);
    if (samples.length !== repetitions)
      throw new Error(`${schema}.${stage} sample count drift`);
    validateDistribution(
      samples,
      result.distribution,
      `${schema}.${stage}.distribution`,
    );
    const runs = result.runs;
    if (!Array.isArray(runs) || runs.length !== repetitions) {
      throw new Error(
        `${schema}.${stage}.runs must retain every raw run proof`,
      );
    }
    const totals = asRecord(result.totals, `${schema}.${stage}.totals`);
    const sums = new Map<string, number>();
    const expectedCounters = expectedRunCounters(schema, stage);
    assertExactKeys(totals, spec.totalCounters, `${schema}.${stage}.totals`);
    for (const [runIndex, rawRun] of runs.entries()) {
      const run = asRecord(rawRun, `${schema}.${stage}.runs[${runIndex}]`);
      const runLabel = `${schema}.${stage}.runs[${runIndex}]`;
      assertExactKeys(run, spec.runKeys, runLabel);
      if (
        round(asFiniteNumber(run.sampleMs, `${runLabel}.sampleMs`)) !==
        samples[runIndex]
      ) {
        throw new Error(`${runLabel} does not match its raw sample`);
      }
      for (const counter of spec.runCounters) {
        const value = asFiniteNumber(run[counter], `${runLabel}.${counter}`);
        if (value !== expectedCounters[counter]) {
          throw new Error(
            `${runLabel}.${counter} did not match the expected ownership ledger`,
          );
        }
        sums.set(counter, (sums.get(counter) ?? 0) + value);
      }
      validateOwnershipProof(schema, stage, run, runLabel);
      const assertions = asRecord(run.assertions, `${runLabel}.assertions`);
      assertExactKeys(assertions, spec.assertionKeys, `${runLabel}.assertions`);
      for (const key of spec.assertionKeys) {
        if (assertions[key] !== true) {
          throw new Error(`${runLabel}.assertions.${key} was not proven true`);
        }
      }
    }
    for (const counter of spec.totalCounters) {
      const total = asFiniteNumber(
        totals[counter],
        `${schema}.${stage}.totals.${counter}`,
      );
      if (total !== sums.get(counter)) {
        throw new Error(
          `${schema}.${stage}.totals.${counter} does not match raw runs`,
        );
      }
    }
  }
}

function validateOptimizedShape(
  root: RecordLike,
  schema: BenchmarkSchema,
): void {
  const expectedTopLevel = [
    "schema",
    "operation",
    "metric",
    "method",
    "sourcePath",
    "command",
    "stageOrder",
    "sequential",
    "concurrentStages",
    "repetitions",
    "warmups",
    "networkPolicy",
    "exclusions",
    "provenance",
    "results",
    "threshold",
  ];
  assertExactKeys(root, expectedTopLevel, `${schema} artifact`);
  const spec = BENCHMARK_SPECS[schema];
  const blobs = asRecord(root.provenance, `${schema}.provenance`).sourceBlobs;
  if (!Array.isArray(blobs))
    throw new Error(`${schema}.provenance.sourceBlobs must be an array`);
  const expectedPaths = [
    spec.source.path,
    TRANSPORT_SOURCE,
    PACKAGE_SOURCE,
    LOCKFILE_SOURCE,
  ];
  if (
    blobs.some(
      (rawBlob, index) =>
        asRecord(rawBlob, "provenance blob").path !== expectedPaths[index],
    )
  ) {
    throw new Error(
      `${schema} optimized validation rejected non-canonical provenance order`,
    );
  }
}

export function validatePtyBenchmarkArtifact(
  artifact: unknown,
  options: PtyBenchmarkValidationOptions = {},
): void {
  const root = asRecord(artifact, "benchmark artifact");
  const schema = asString(root.schema, "benchmark.schema");
  expectedSpec(schema);
  const benchmarkSchema = schema as BenchmarkSchema;
  validateOperationAndMetric(root, benchmarkSchema);
  validateProvenance(root, benchmarkSchema, options.optimized === true);
  validateResults(root, benchmarkSchema);
  if (options.optimized === true) validateOptimizedShape(root, benchmarkSchema);
}

export function validatePtyBenchmarkFile(
  path: string,
  options: PtyBenchmarkValidationOptions = {},
): void {
  validatePtyBenchmarkArtifact(JSON.parse(readFileSync(path, "utf8")), options);
}
