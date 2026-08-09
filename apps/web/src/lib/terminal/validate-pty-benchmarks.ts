import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  PTY_BENCHMARK_PROVENANCE_SOURCE,
  PTY_BENCHMARK_SOURCES,
  REVIEWED_PTY_BENCHMARK_ENVIRONMENT,
} from "./pty-benchmark-provenance";
import {
  PTY_BENCHMARK_TRUST_PIN_SOURCE,
  REVIEWED_PTY_BENCHMARK_TRUST_PIN,
} from "./pty-benchmark-trust-pin";

const TRANSPORT_SOURCE = "apps/web/src/lib/terminal/pty-transport.ts";
const PACKAGE_SOURCE = "apps/web/package.json";
const LOCKFILE_SOURCE = "apps/web/bun.lock";
const EXPECTED_REPETITIONS = 30;
const EXPECTED_WARMUPS = 5;
const REVIEWED_METHOD = "R-7 inclusive linear interpolation over rounded raw samples";
const ROOT_KEYS = [
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
] as const;
const RUNTIME_KEYS = [
  "bun",
  "node",
  "hostNode",
  "packageManager",
  "declaredBun",
  "declaredNode",
] as const;
const OS_KEYS = [
  "platform",
  "release",
  "architecture",
  "cpuModel",
  "cpuCount",
] as const;
const PROVENANCE_KEYS = [
  "sourceRevision",
  "generationCommit",
  "sourceTree",
  "sourceBlobs",
  "cleanCheckout",
  "detachedHead",
  "command",
  "sourceCheckout",
  "runtime",
  "os",
] as const;
const ALLOWED_EVIDENCE_CHANGE_PATHS = new Set([
  "apps/web/src/lib/terminal/pty-reconnect-supersession-benchmark.json",
  "apps/web/src/lib/terminal/pty-connecting-ownership-benchmark.json",
]);
const TRUSTED_REVIEW_CHANGE_PATHS = new Set([
  PTY_BENCHMARK_TRUST_PIN_SOURCE,
  ...REVIEWED_PTY_BENCHMARK_TRUST_PIN.trustedCode.map((entry) => entry.path),
  "apps/web/src/lib/terminal/pty-benchmark-validator.test.ts",
  "apps/web/src/lib/terminal/pty-transport.md",
]);
const TRUSTED_REPOSITORY_ROOT = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../..",
);
const LEGACY_V1_FOUR_BLOB_ARTIFACTS = new Set([
  "hermternal.pty-retry-authorization-benchmark.v1|apps/web/src/lib/terminal/pty-retry-authorization.bench.ts",
  "hermternal.pty-error-retention-benchmark.v1|apps/web/src/lib/terminal/pty-error-retention.bench.ts",
]);
const REVIEWED_HELPER_IDENTITIES = [
  {
    gitBlobSha: "bf9d564df819dbfffc1b76649aab124907b471e7",
    sha256: "1ee7ee726a0486442df55e4865bacf5407754e30e23f7478203f04cef84a7e9b",
    legacySourceBlobs: true,
  },
  {
    gitBlobSha: "65efc760da96b532be2103ff5a75c3555ec78fd5",
    sha256: "0599ad00bc91539811b44955ce66778f4ae1510056ced520cc0201a487541383",
    legacySourceBlobs: false,
  },
  {
    gitBlobSha: "45c2b2b1d993f7097b972af7c2c64c083383c106",
    sha256: "2539798548a46391c3ed821b9d56d1f9eef0f9e62251ae50e31405aa0dc6edeb",
    legacySourceBlobs: false,
  },
] as const;

const BENCHMARK_SPECS = {
  "hermternal.pty-reconnect-supersession-benchmark.v2": {
    operation: "same-identity reconnect after ordinary detach quarantine",
    metric: {
      name: "quarantine_settle_wall_time",
      unit: "ms",
      clock: "performance.now",
      start:
        "performance.now immediately before ordinary detach begins quarantine settlement",
      end: "ignored adapter settles after detach and blocked reconnect",
    },
    method: REVIEWED_METHOD,
    rootKeys: ROOT_KEYS,
    exclusions: [
      "network",
      "Hermes",
      "credentials",
      "PTY bytes",
      "rendering",
      "latency threshold",
    ],
    source: PTY_BENCHMARK_SOURCES.reconnect,
    stages: ["validator", "ticket", "factory"],
    assertionKeys: [
      "quarantineValidatorFence",
      "quarantineTicketFence",
      "quarantineFactoryFence",
      "negativeControlUsesPreConnectClock",
      "negativeControlIncludesStagedWork",
      "expectedValidatorCount",
      "expectedTicketCount",
      "expectedFactoryCount",
      "staleSocketIdentityMatchesStage",
      "staleSocketIdMatchesStage",
      "staleSocketClosedExactly",
      "staleSocketNeverOpened",
      "replacementIdentityMatchesExpected",
      "replacementSocketIdUnique",
      "replacementOpenedExactlyOnce",
      "replacementClosedExactlyOnce",
      "replacementReachedAttached",
      "expectedOwnerIsOnlyActiveOwner",
      "activeSocketIsReplacement",
      "socketClosureLedgerExact",
      "ownerSocketClosureLedgerExact",
      "noDuplicateOwners",
      "callbackApplicabilityMatchesLedger",
      "replacementCallbacksBound",
      "allCallbacksNullAfterClose",
      "callbackBindingCoversAllSinks",
      "perSinkStalePublicationRejected",
      "delayedBlobConversionObserved",
      "delayedBlobPostClosePublicationRejected",
      "staleCallbacksExercised",
      "staleOnopenIgnored",
      "staleOnmessageIgnored",
      "staleOnerrorIgnored",
      "staleOncloseIgnored",
      "stalePublicationRejected",
      "noPostCloseStateEvents",
      "noPostCloseBytesEvents",
      "noPostCloseNoticeEvents",
      "cleanupRecorded",
    ],
    runKeys: [
      "sampleMs",
      "negativeControlSampleMs",
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
      "activeSocketIds",
      "expectedOwnerIdentity",
      "activeOwnerIdentities",
      "staleSocketIds",
      "staleSocketIdentities",
      "staleSocketId",
      "staleSocketIdentity",
      "staleSocketCloseCalls",
      "replacementSocketId",
      "replacementSocketIdentity",
      "replacementSocketCloseCalls",
      "replacementStateStatus",
      "socketClosures",
      "callbackBoundSocketCount",
      "callbackBoundSinkCount",
      "callbackBoundSinkNames",
      "callbackBindings",
      "callbackProofApplicable",
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
      "stalePublications",
      "delayedBlob",
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
        "performance.now at the connecting state lifecycle event before observer cancellation or replacement action",
      end: "cancelled operation rejects",
    },
    method: REVIEWED_METHOD,
    rootKeys: ROOT_KEYS,
    exclusions: [
      "network",
      "Hermes",
      "credentials",
      "PTY bytes",
      "rendering",
      "latency threshold",
    ],
    source: PTY_BENCHMARK_SOURCES.connecting,
    stages: ["abort", "close", "detach", "replace"],
    assertionKeys: [
      "connectingGuard",
      "staleSocketNeverOpened",
      "expectedValidatorCount",
      "expectedFactoryCount",
      "expectedTicketCount",
      "negativeControlUsesPreConnectClock",
      "negativeControlIncludesSetupAndTicket",
      "replacementOpenedExactlyOnce",
      "replacementAttached",
      "expectedOwnerIsOnlyActiveOwner",
      "activeSocketIsReplacement",
      "noDuplicateOwners",
      "staleSocketIdentityFence",
      "staleSocketIdFence",
      "replacementIdentityMatchesExpected",
      "replacementSocketIdUnique",
      "replacementClosedExactlyOnce",
      "exactSocketCleanup",
      "ownerSocketClosureLedgerExact",
      "callbackApplicabilityMatchesAction",
      "allCallbacksNullAfterClose",
      "replacementCallbacksBound",
      "callbackBindingCoversAllSinks",
      "perSinkStalePublicationRejected",
      "delayedBlobConversionObserved",
      "delayedBlobPostClosePublicationRejected",
      "staleCallbacksExercised",
      "staleOnopenIgnored",
      "staleOnmessageIgnored",
      "staleOnerrorIgnored",
      "staleOncloseIgnored",
      "stalePublicationRejected",
      "noPostCloseStateEvents",
      "noPostCloseBytesEvents",
      "noPostCloseNoticeEvents",
      "cleanupRecorded",
    ],
    runKeys: [
      "sampleMs",
      "negativeControlSampleMs",
      "validatorCalls",
      "ticketRequests",
      "socketFactoryCalls",
      "openedSockets",
      "cleanupCalls",
      "duplicateOwnerViolations",
      "activeOwnerCount",
      "activeSocketIds",
      "expectedOwnerIdentity",
      "activeOwnerIdentities",
      "staleSocketIds",
      "staleSocketIdentities",
      "staleSocketId",
      "staleSocketIdentity",
      "staleSocketCloseCalls",
      "replacementSocketId",
      "replacementSocketIdentity",
      "replacementSocketCloseCalls",
      "replacementStateStatus",
      "socketClosures",
      "callbackBoundSocketCount",
      "callbackBoundSinkCount",
      "callbackBoundSinkNames",
      "callbackBindings",
      "callbackProofApplicable",
      "staleOpenCalls",
      "allCallbacksNullAfterClose",
      "staleOnopenDispatches",
      "staleOnmessageDispatches",
      "staleOnerrorDispatches",
      "staleOncloseDispatches",
      "postCloseStateEvents",
      "postCloseBytesEvents",
      "postCloseNoticeEvents",
      "stalePublications",
      "delayedBlob",
      "assertions",
    ],
    runCounters: [
      "validatorCalls",
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
      "validatorCalls",
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
const RESULT_KEYS = ["stage", "samples", "distribution", "runs", "totals"] as const;
const DISTRIBUTION_KEYS = ["min", "median", "p95"] as const;
const SINK_PUBLICATION_KEYS = ["onEvent", "subscribe", "onStateChange"] as const;
const SINK_COUNTER_KEYS = [
  "eventCount",
  "stateCount",
  "bytesCount",
  "noticeCount",
] as const;
const DELAYED_BLOB_KEYS = [
  "scheduledCount",
  "completionCount",
  "dispatchedBeforeClose",
  "conversionStartedBeforeClose",
  "resolvedAfterClose",
  "postCloseBytesRejected",
  "events",
] as const;
const CALLBACK_BINDING_KEYS = [
  "socketId",
  "onopenBound",
  "onmessageBound",
  "onerrorBound",
  "oncloseBound",
  "onopenNullAfterClose",
  "onmessageNullAfterClose",
  "onerrorNullAfterClose",
  "oncloseNullAfterClose",
] as const;
const DELAYED_BLOB_EVENT_SEQUENCE = [
  "dispatch",
  "conversion-start",
  "close",
  "completion",
] as const;

interface RecordLike {
  readonly [key: string]: unknown;
}

export interface PtyBenchmarkValidationOptions {
  /** Strict mode checks canonical provenance ordering and the complete ledger. */
  readonly optimized?: boolean;
  /** CLI mode binds each retained JSON path to its reviewed schema identity. */
  readonly expectedSchema?: string;
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

function asCounter(value: unknown, label: string): number {
  const counter = asFiniteNumber(value, label);
  if (!Number.isInteger(counter)) {
    throw new Error(`${label} must be a non-negative integer`);
  }
  return counter;
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

// Keep owner fields and physical socket IDs separate so same-owner
// supersession cannot hide stale cleanup or replacement ownership drift.
interface OwnerIdentity {
  readonly sessionId: string;
  readonly attach: string;
  readonly processIdentity: string;
}

function asOwnerIdentity(
  value: unknown,
  label: string,
  optimized = false,
): OwnerIdentity {
  const owner = asRecord(value, label);
  const ownerKeys = ["sessionId", "attach", "processIdentity"] as const;
  assertExactKeys(owner, ownerKeys, label);
  if (optimized) assertCanonicalKeys(owner, ownerKeys, label);
  return {
    sessionId: asString(owner.sessionId, `${label}.sessionId`),
    attach: asString(owner.attach, `${label}.attach`),
    processIdentity: asString(
      owner.processIdentity,
      `${label}.processIdentity`,
    ),
  };
}

function asOwnerIdentityArray(
  value: unknown,
  label: string,
  optimized = false,
): OwnerIdentity[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value.map((entry, index) =>
    asOwnerIdentity(entry, `${label}[${index}]`, optimized),
  );
}

function sameOwnerIdentity(
  actual: OwnerIdentity,
  expected: OwnerIdentity,
): boolean {
  return (
    actual.sessionId === expected.sessionId &&
    actual.attach === expected.attach &&
    actual.processIdentity === expected.processIdentity
  );
}

interface SocketClosure {
  readonly socketId: string;
  readonly ownerIdentity: OwnerIdentity;
  readonly closeCalls: number;
  readonly opened: boolean;
}

interface CallbackBindingLedger {
  readonly socketId: string;
  readonly onopenBound: boolean;
  readonly onmessageBound: boolean;
  readonly onerrorBound: boolean;
  readonly oncloseBound: boolean;
  readonly onopenNullAfterClose: boolean;
  readonly onmessageNullAfterClose: boolean;
  readonly onerrorNullAfterClose: boolean;
  readonly oncloseNullAfterClose: boolean;
}

function asCallbackBindings(
  value: unknown,
  label: string,
  optimized: boolean,
): CallbackBindingLedger[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value.map((entry, index) => {
    const binding = asRecord(entry, `${label}[${index}]`);
    const bindingLabel = `${label}[${index}]`;
    assertExactKeys(binding, CALLBACK_BINDING_KEYS, bindingLabel);
    if (optimized) assertCanonicalKeys(binding, CALLBACK_BINDING_KEYS, bindingLabel);
    return {
      socketId: asString(binding.socketId, `${bindingLabel}.socketId`),
      onopenBound: asBoolean(binding.onopenBound, `${bindingLabel}.onopenBound`),
      onmessageBound: asBoolean(
        binding.onmessageBound,
        `${bindingLabel}.onmessageBound`,
      ),
      onerrorBound: asBoolean(binding.onerrorBound, `${bindingLabel}.onerrorBound`),
      oncloseBound: asBoolean(binding.oncloseBound, `${bindingLabel}.oncloseBound`),
      onopenNullAfterClose: asBoolean(
        binding.onopenNullAfterClose,
        `${bindingLabel}.onopenNullAfterClose`,
      ),
      onmessageNullAfterClose: asBoolean(
        binding.onmessageNullAfterClose,
        `${bindingLabel}.onmessageNullAfterClose`,
      ),
      onerrorNullAfterClose: asBoolean(
        binding.onerrorNullAfterClose,
        `${bindingLabel}.onerrorNullAfterClose`,
      ),
      oncloseNullAfterClose: asBoolean(
        binding.oncloseNullAfterClose,
        `${bindingLabel}.oncloseNullAfterClose`,
      ),
    };
  });
}

function asSocketClosures(
  value: unknown,
  label: string,
  optimized: boolean,
): SocketClosure[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value.map((entry, index) => {
    const closure = asRecord(entry, `${label}[${index}]`);
    const closureLabel = `${label}[${index}]`;
    const closureKeys = ["socketId", "ownerIdentity", "closeCalls", "opened"] as const;
    assertExactKeys(closure, closureKeys, closureLabel);
    if (optimized) assertCanonicalKeys(closure, closureKeys, closureLabel);
    if (typeof closure.opened !== "boolean") {
      throw new Error(`${label}[${index}].opened must be a boolean`);
    }
    return {
      socketId: asString(closure.socketId, `${label}[${index}].socketId`),
      ownerIdentity: asOwnerIdentity(
        closure.ownerIdentity,
        `${label}[${index}].ownerIdentity`,
        optimized,
      ),
      closeCalls: asFiniteNumber(
        closure.closeCalls,
        `${label}[${index}].closeCalls`,
      ),
      opened: closure.opened,
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

function expectOwnerIdentity(
  actual: unknown,
  expected: OwnerIdentity,
  label: string,
  optimized = false,
): void {
  const parsed = asOwnerIdentity(actual, label, optimized);
  if (!sameOwnerIdentity(parsed, expected)) {
    throw new Error(`${label} did not match the expected owner identity`);
  }
}

function expectOwnerIdentityArray(
  actual: readonly OwnerIdentity[],
  expected: readonly OwnerIdentity[],
  label: string,
): void {
  if (
    actual.length !== expected.length ||
    actual.some(
      (owner, index) =>
        expected[index] === undefined ||
        !sameOwnerIdentity(owner, expected[index]!),
    )
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
    actual.some((closure, index) => {
      const wanted = expected[index];
      return (
        wanted === undefined ||
        closure.socketId !== wanted.socketId ||
        !sameOwnerIdentity(closure.ownerIdentity, wanted.ownerIdentity) ||
        closure.closeCalls !== wanted.closeCalls ||
        closure.opened !== wanted.opened
      );
    })
  ) {
    throw new Error(
      `${label} did not match the exact per-socket cleanup ledger`,
    );
  }
}

function git(args: readonly string[], cwd = process.cwd()): string {
  try {
    return execFileSync("git", [...args], { cwd, encoding: "utf8" }).trim();
  } catch (error) {
    const detail = error instanceof Error ? `: ${error.message}` : "";
    throw new Error(`git ${args.join(" ")} failed${detail}`);
  }
}

function gitBytes(args: readonly string[], cwd = process.cwd()): Uint8Array {
  try {
    return execFileSync("git", [...args], { cwd });
  } catch (error) {
    const detail = error instanceof Error ? `: ${error.message}` : "";
    throw new Error(`git ${args.join(" ")} failed${detail}`);
  }
}

export function parseGitChangedPaths(bytes: Uint8Array): readonly string[] {
  if (bytes.length === 0) return [];
  if (bytes[bytes.length - 1] !== 0) {
    throw new Error("git changed-path output was not NUL terminated");
  }
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const paths: string[] = [];
  const seen = new Set<string>();
  let start = 0;
  for (let index = 0; index < bytes.length; index += 1) {
    if (bytes[index] !== 0) continue;
    if (index === start) {
      throw new Error("git changed-path output contained an empty path");
    }
    let path: string;
    try {
      path = decoder.decode(bytes.slice(start, index));
    } catch {
      throw new Error("git changed path was not valid UTF-8");
    }
    if (/^\s|\s$/u.test(path)) {
      throw new Error(`git changed path had leading or trailing whitespace: ${path}`);
    }
    if (/[\p{Cc}]/u.test(path)) {
      throw new Error(`git changed path contained a control character: ${path}`);
    }
    if (seen.has(path)) {
      throw new Error(`git changed path was duplicated: ${path}`);
    }
    seen.add(path);
    paths.push(path);
    start = index + 1;
  }
  return paths;
}

function assertStrictAncestor(
  ancestor: string,
  descendant: string,
  cwd: string,
  label: string,
): void {
  if (ancestor === descendant) {
    throw new Error(`${label} must be a strict descendant of the reviewed source`);
  }
  try {
    execFileSync(
      "git",
      ["merge-base", "--is-ancestor", ancestor, descendant],
      { cwd, stdio: "ignore" },
    );
  } catch {
    throw new Error(`${label} was not descended from the reviewed source`);
  }
}

function validateReviewedTrustPin(
  evidenceCwd: string,
  sourceRevision: string,
): { readonly trustedCwd: string; readonly trustedHead: string } {
  const trustedCwd = TRUSTED_REPOSITORY_ROOT;
  const trustedHead = git(["rev-parse", "HEAD"], trustedCwd);
  assertStrictAncestor(
    REVIEWED_PTY_BENCHMARK_TRUST_PIN.sourceRevision,
    trustedHead,
    trustedCwd,
    "trusted PTY pin checkout",
  );
  if (sourceRevision !== REVIEWED_PTY_BENCHMARK_TRUST_PIN.sourceRevision) {
    throw new Error(
      "provenance.sourceRevision did not match the immutable reviewed PTY source pin",
    );
  }
  const trustedChangedPaths = parseGitChangedPaths(
    gitBytes(
      [
        "diff",
        "--name-only",
        "-z",
        `${REVIEWED_PTY_BENCHMARK_TRUST_PIN.sourceRevision}..${trustedHead}`,
      ],
      trustedCwd,
    ),
  );
  if (trustedChangedPaths.some((path) => !TRUSTED_REVIEW_CHANGE_PATHS.has(path))) {
    throw new Error(
      "trusted PTY pin checkout contained an unreviewed source or validator change",
    );
  }
  for (const entry of REVIEWED_PTY_BENCHMARK_TRUST_PIN.sourceBlobs) {
    if (
      git(["rev-parse", `${sourceRevision}:${entry.path}`], evidenceCwd) !==
      entry.gitBlobSha
    ) {
      throw new Error(`reviewed PTY source blob drift for ${entry.path}`);
    }
    if (
      sha256(gitBytes(["show", `${sourceRevision}:${entry.path}`], evidenceCwd)) !==
      entry.sha256
    ) {
      throw new Error(`reviewed PTY source hash drift for ${entry.path}`);
    }
  }
  for (const entry of REVIEWED_PTY_BENCHMARK_TRUST_PIN.trustedCode) {
    const trustedBlob = git(
      ["rev-parse", `${trustedHead}:${entry.path}`],
      trustedCwd,
    );
    if (trustedBlob !== entry.gitBlobSha) {
      throw new Error(`reviewed PTY validator blob drift for ${entry.path}`);
    }
    if (
      sha256(gitBytes(["show", `${trustedHead}:${entry.path}`], trustedCwd)) !==
      entry.sha256
    ) {
      throw new Error(`reviewed PTY validator hash drift for ${entry.path}`);
    }
  }
  const evidenceHead = git(["rev-parse", "HEAD"], evidenceCwd);
  assertStrictAncestor(trustedHead, evidenceHead, evidenceCwd, "evidence checkout");
  return { trustedCwd, trustedHead };
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
  if (!Object.prototype.hasOwnProperty.call(BENCHMARK_SPECS, schema)) {
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

function assertCanonicalKeys(
  value: RecordLike,
  expected: readonly string[],
  label: string,
): void {
  if (Object.keys(value).join("\n") !== expected.join("\n")) {
    throw new Error(`${label} keys did not match the optimized canonical order`);
  }
}

function validateReviewedProvenanceHelper(
  sourceRevision: string,
  cwd: string,
): (typeof REVIEWED_HELPER_IDENTITIES)[number] {
  const path = `${sourceRevision}:${PTY_BENCHMARK_PROVENANCE_SOURCE}`;
  const identity = {
    gitBlobSha: git(["rev-parse", path], cwd),
    sha256: sha256(gitBytes(["show", path], cwd)),
  };
  const reviewed = REVIEWED_HELPER_IDENTITIES.find(
    (candidate) =>
      candidate.gitBlobSha === identity.gitBlobSha &&
      candidate.sha256 === identity.sha256,
  );
  if (!reviewed) {
    throw new Error(
      "provenance helper identity was not one of the reviewed PTY harness versions",
    );
  }
  return reviewed;
}

// Keep the operation and timing boundaries schema-specific so evidence cannot
// be relabeled while retaining a valid ownership proof ledger.
function validateOperationAndMetric(
  root: RecordLike,
  schema: BenchmarkSchema,
  optimized: boolean,
): void {
  const spec = BENCHMARK_SPECS[schema];
  if (asString(root.operation, `${schema}.operation`) !== spec.operation) {
    throw new Error(`${schema}.operation did not match the reviewed operation`);
  }
  if (asString(root.method, `${schema}.method`) !== spec.method) {
    throw new Error(`${schema}.method did not match the reviewed method`);
  }

  const metric = asRecord(root.metric, `${schema}.metric`);
  const metricKeys = ["name", "unit", "clock", "start", "end"] as const;
  assertExactKeys(metric, metricKeys, `${schema}.metric`);
  if (optimized) assertCanonicalKeys(metric, metricKeys, `${schema}.metric`);
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
    validatorCalls: replacement ? 2 : 1,
    ticketRequests: replacement ? 2 : 1,
    // The approved transport may invoke the stale factory after a connecting
    // observer cancels. It closes that unopened socket; replacement then owns a
    // second socket and proves its callbacks separately.
    socketFactoryCalls: replacement ? 2 : 1,
    openedSockets: replacement ? 1 : 0,
    cleanupCalls: replacement ? 2 : 1,
    duplicateOwnerViolations: 0,
    activeOwnerCount: replacement ? 1 : 0,
    staleSocketCloseCalls: 1,
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

function validateRuntimeAndHost(
  provenance: RecordLike,
  optimized: boolean,
): void {
  const runtime = asRecord(provenance.runtime, "provenance.runtime");
  assertExactKeys(runtime, RUNTIME_KEYS, "provenance.runtime");
  if (optimized) assertCanonicalKeys(runtime, RUNTIME_KEYS, "provenance.runtime");
  const reviewedRuntime = REVIEWED_PTY_BENCHMARK_ENVIRONMENT.runtime;
  for (const key of RUNTIME_KEYS) {
    if (runtime[key] !== reviewedRuntime[key]) {
      throw new Error(
        `provenance.runtime.${key} did not match the reviewed synthetic harness`,
      );
    }
  }
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
  assertExactKeys(os, OS_KEYS, "provenance.os");
  if (optimized) assertCanonicalKeys(os, OS_KEYS, "provenance.os");
  const reviewedOs = REVIEWED_PTY_BENCHMARK_ENVIRONMENT.os;
  for (const key of OS_KEYS) {
    if (os[key] !== reviewedOs[key]) {
      throw new Error(
        `provenance.os.${key} did not match the reviewed synthetic harness`,
      );
    }
  }
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

function validateRootMetadata(
  root: RecordLike,
  schema: BenchmarkSchema,
  optimized: boolean,
): void {
  const spec = BENCHMARK_SPECS[schema];
  assertExactKeys(root, spec.rootKeys, `${schema} artifact`);
  if (optimized) assertCanonicalKeys(root, spec.rootKeys, `${schema} artifact`);
  const exclusions = asStringArray(root.exclusions, `${schema}.exclusions`);
  if (
    exclusions.length !== spec.exclusions.length ||
    exclusions.some((value, index) => value !== spec.exclusions[index])
  ) {
    throw new Error(`${schema}.exclusions did not match the reviewed scope`);
  }
}

function validateProvenance(
  root: RecordLike,
  schema: BenchmarkSchema,
  optimized: boolean,
  evidenceCwd: string,
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
  assertExactKeys(provenance, PROVENANCE_KEYS, `${schema}.provenance`);
  if (optimized) {
    assertCanonicalKeys(provenance, PROVENANCE_KEYS, `${schema}.provenance`);
  }
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
  const { trustedHead } = validateReviewedTrustPin(evidenceCwd, sourceRevision);
  git(["cat-file", "-e", `${sourceRevision}^{commit}`], evidenceCwd);
  if (
    git(["rev-parse", `${sourceRevision}^{tree}`], evidenceCwd) !==
    sourceTree
  ) {
    throw new Error("provenance.sourceTree does not match sourceRevision");
  }
  if (sourceTree !== REVIEWED_PTY_BENCHMARK_TRUST_PIN.sourceTree) {
    throw new Error("provenance.sourceTree did not match the immutable reviewed PTY source pin");
  }
  const helperIdentity = validateReviewedProvenanceHelper(
    sourceRevision,
    evidenceCwd,
  );
  const evidenceHead = git(["rev-parse", "HEAD"], evidenceCwd);
  const evidenceChangedPaths = parseGitChangedPaths(
    gitBytes(
      ["diff", "--name-only", "-z", `${trustedHead}..${evidenceHead}`],
      evidenceCwd,
    ),
  );
  if (
    evidenceChangedPaths.some((path) => !ALLOWED_EVIDENCE_CHANGE_PATHS.has(path))
  ) {
    throw new Error(
      "evidence checkout was not followed only by the two retained evidence JSON paths",
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
  validateRuntimeAndHost(provenance, optimized);

  const blobs = provenance.sourceBlobs;
  const legacyPaths = [
    spec.source.path,
    TRANSPORT_SOURCE,
    PACKAGE_SOURCE,
    LOCKFILE_SOURCE,
  ] as const;
  const currentPaths = [
    ...legacyPaths,
    PTY_BENCHMARK_PROVENANCE_SOURCE,
  ] as const;
  const legacyFourBlobArtifact = LEGACY_V1_FOUR_BLOB_ARTIFACTS.has(
    `${schema}|${sourcePath}`,
  );
  const expectedPaths = legacyFourBlobArtifact ? legacyPaths : currentPaths;
  if (!Array.isArray(blobs) || blobs.length !== expectedPaths.length) {
    throw new Error(
      legacyFourBlobArtifact
        ? "legacy v1 provenance.sourceBlobs must pin exactly four legacy inputs"
        : `${schema} v2 provenance.sourceBlobs must pin exactly five current inputs, including the reviewed helper`,
    );
  }
  if (!legacyFourBlobArtifact && !helperIdentity.legacySourceBlobs) {
    // Current v2 evidence must carry the helper even when a legacy helper blob
    // identity remains reviewed for explicitly scoped v1 artifacts.
    if (blobs.length !== currentPaths.length) {
      throw new Error(
        `${schema} v2 provenance.sourceBlobs must include the reviewed helper`,
      );
    }
  }
  const seen = new Set<string>();
  for (const [index, rawBlob] of blobs.entries()) {
    const blob = asRecord(rawBlob, `provenance.sourceBlobs[${index}]`);
    assertExactKeys(
      blob,
      ["path", "gitBlobSha", "sha256"],
      `provenance.sourceBlobs[${index}]`,
    );
    if (optimized) {
      assertCanonicalKeys(
        blob,
        ["path", "gitBlobSha", "sha256"],
        `provenance.sourceBlobs[${index}]`,
      );
    }
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
    if (!expectedPaths.some((expectedPath) => expectedPath === path)) {
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
    const pinned = REVIEWED_PTY_BENCHMARK_TRUST_PIN.sourceBlobs.find(
      (entry) => entry.path === path,
    );
    if (
      pinned === undefined ||
      pinned.gitBlobSha !== gitBlobSha ||
      pinned.sha256 !== fileSha256
    ) {
      throw new Error(`provenance hash was not bound to the reviewed PTY pin for ${path}`);
    }
    if (
      git(["rev-parse", `${sourceRevision}:${path}`], evidenceCwd) !==
      gitBlobSha
    ) {
      throw new Error(`git blob drift for ${path}`);
    }
    if (
      sha256(gitBytes(["show", `${sourceRevision}:${path}`], evidenceCwd)) !==
      fileSha256
    ) {
      throw new Error(`file hash drift for ${path}`);
    }
    if (path.endsWith(".bench.ts")) {
      const source = new TextDecoder().decode(
        gitBytes(["show", `${sourceRevision}:${path}`], evidenceCwd),
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
      gitBytes(["show", `${sourceRevision}:${PACKAGE_SOURCE}`], evidenceCwd),
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
  optimized: boolean,
): void {
  const distribution = asRecord(value, label);
  assertExactKeys(distribution, DISTRIBUTION_KEYS, label);
  if (optimized) assertCanonicalKeys(distribution, DISTRIBUTION_KEYS, label);
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

function validateStalePublications(
  value: unknown,
  label: string,
  optimized: boolean,
): void {
  const publications = asRecord(value, label);
  assertExactKeys(publications, SINK_PUBLICATION_KEYS, label);
  if (optimized) assertCanonicalKeys(publications, SINK_PUBLICATION_KEYS, label);
  for (const sink of SINK_PUBLICATION_KEYS) {
    const counters = asRecord(publications[sink], `${label}.${sink}`);
    assertExactKeys(counters, SINK_COUNTER_KEYS, `${label}.${sink}`);
    if (optimized) {
      assertCanonicalKeys(counters, SINK_COUNTER_KEYS, `${label}.${sink}`);
    }
    const counts = Object.fromEntries(
      SINK_COUNTER_KEYS.map((counter) => [
        counter,
        asCounter(counters[counter], `${label}.${sink}.${counter}`),
      ]),
    ) as Record<(typeof SINK_COUNTER_KEYS)[number], number>;
    if (
      counts.eventCount !==
      counts.stateCount + counts.bytesCount + counts.noticeCount
    ) {
      throw new Error(`${label}.${sink}.eventCount did not match its event categories`);
    }
    if (Object.values(counts).some((count) => count !== 0)) {
      throw new Error(`${label}.${sink} recorded a stale publication`);
    }
  }
}

function validateDelayedBlob(
  value: unknown,
  label: string,
  applicable: boolean,
  optimized: boolean,
  stalePublications: RecordLike,
  stalePublicationsLabel: string,
  postCloseBytesEvents: number,
): boolean {
  const delayedBlob = asRecord(value, label);
  assertExactKeys(delayedBlob, DELAYED_BLOB_KEYS, label);
  if (optimized) assertCanonicalKeys(delayedBlob, DELAYED_BLOB_KEYS, label);
  const expectedCount = applicable ? 1 : 0;
  const scheduledCount = asCounter(
    delayedBlob.scheduledCount,
    `${label}.scheduledCount`,
  );
  const completionCount = asCounter(
    delayedBlob.completionCount,
    `${label}.completionCount`,
  );
  for (const [counter, actual] of [
    ["scheduledCount", scheduledCount],
    ["completionCount", completionCount],
  ] as const) {
    if (actual !== expectedCount) {
      throw new Error(`${label}.${counter} did not match callback applicability`);
    }
  }
  const events = asStringArray(delayedBlob.events, `${label}.events`);
  const expectedEvents = applicable ? DELAYED_BLOB_EVENT_SEQUENCE : [];
  expectStringArray(events, expectedEvents, `${label}.events`);
  const temporalOrder =
    events.length === DELAYED_BLOB_EVENT_SEQUENCE.length &&
    events.every((event, index) => event === DELAYED_BLOB_EVENT_SEQUENCE[index]);
  for (const proof of [
    "dispatchedBeforeClose",
    "conversionStartedBeforeClose",
    "resolvedAfterClose",
  ] as const) {
    const actual = asBoolean(delayedBlob[proof], `${label}.${proof}`);
    const expected = applicable && temporalOrder;
    if (actual !== expected) {
      throw new Error(`${label}.${proof} was not derived from the raw Blob event ledger`);
    }
  }

  // Derive the post-close byte result here, from the event sequence, raw
  // post-close byte count, and every publication sink. The producer boolean is
  // only a checked summary; it cannot authorize an otherwise failed ledger.
  const publicationBytesRejected = SINK_PUBLICATION_KEYS.every((sink) => {
    const counters = asRecord(
      stalePublications[sink],
      `${stalePublicationsLabel}.${sink}`,
    );
    assertExactKeys(
      counters,
      SINK_COUNTER_KEYS,
      `${stalePublicationsLabel}.${sink}`,
    );
    if (optimized) {
      assertCanonicalKeys(
        counters,
        SINK_COUNTER_KEYS,
        `${stalePublicationsLabel}.${sink}`,
      );
    }
    return (
      asCounter(
        counters.bytesCount,
        `${stalePublicationsLabel}.${sink}.bytesCount`,
      ) === 0
    );
  });
  const expectedPostCloseBytesRejected =
    applicable &&
    scheduledCount === 1 &&
    completionCount === 1 &&
    temporalOrder &&
    postCloseBytesEvents === 0 &&
    publicationBytesRejected;
  const postCloseBytesRejected = asBoolean(
    delayedBlob.postCloseBytesRejected,
    `${label}.postCloseBytesRejected`,
  );
  if (postCloseBytesRejected !== expectedPostCloseBytesRejected) {
    throw new Error(
      `${label}.postCloseBytesRejected was not derived from the raw Blob event and publication ledgers`,
    );
  }
  return applicable && temporalOrder;
}

// Callback and delayed-Blob proofs are non-vacuous: a real replacement or
// recovery must bind one physical socket and all three publication sinks before
// Close, then complete one delayed conversion after ownership is lost without
// publishing to any sink. Stages that never allocate a socket must record the
// inapplicable zero/false ledger rather than claiming an empty proof succeeded.
function validateCallbackBindingProof(
  schema: BenchmarkSchema,
  stage: string,
  run: RecordLike,
  label: string,
  optimized: boolean,
): boolean {
  const reconnect =
    schema === "hermternal.pty-reconnect-supersession-benchmark.v2";
  const applicable = reconnect || stage === "replace";
  const expectedSocketCount = applicable ? 1 : 0;
  const callbackBindings = asCallbackBindings(
    run.callbackBindings,
    `${label}.callbackBindings`,
    optimized,
  );
  const callbackBoundSinkNames = asStringArray(
    run.callbackBoundSinkNames,
    `${label}.callbackBoundSinkNames`,
  );
  expectStringArray(
    callbackBoundSinkNames,
    SINK_PUBLICATION_KEYS,
    `${label}.callbackBoundSinkNames`,
  );
  const derivedSocketCount = callbackBindings.filter(
    (binding) =>
      binding.onopenBound &&
      binding.onmessageBound &&
      binding.onerrorBound &&
      binding.oncloseBound,
  ).length;
  const allCallbacksNullAfterClose = callbackBindings.every(
    (binding) =>
      binding.onopenNullAfterClose &&
      binding.onmessageNullAfterClose &&
      binding.onerrorNullAfterClose &&
      binding.oncloseNullAfterClose,
  );
  if (asCounter(run.callbackBoundSocketCount, `${label}.callbackBoundSocketCount`) !== derivedSocketCount) {
    throw new Error(`${label}.callbackBoundSocketCount was not derived from callback bindings`);
  }
  if (asCounter(run.callbackBoundSinkCount, `${label}.callbackBoundSinkCount`) !== callbackBoundSinkNames.length) {
    throw new Error(`${label}.callbackBoundSinkCount was not derived from sink bindings`);
  }
  if (derivedSocketCount !== expectedSocketCount) {
    throw new Error(`${label}.callback bindings did not match callback applicability`);
  }
  if (run.callbackProofApplicable !== applicable) {
    throw new Error(
      `${label}.callbackProofApplicable did not match the expected replacement/recovery stage`,
    );
  }
  if (!allCallbacksNullAfterClose) {
    throw new Error(`${label}.callback bindings retained a callback after close`);
  }
  if (run.allCallbacksNullAfterClose !== allCallbacksNullAfterClose) {
    throw new Error(`${label}.allCallbacksNullAfterClose was not derived from callback bindings`);
  }
  const stalePublications = asRecord(
    run.stalePublications,
    `${label}.stalePublications`,
  );
  validateDelayedBlob(
    run.delayedBlob,
    `${label}.delayedBlob`,
    applicable,
    optimized,
    stalePublications,
    `${label}.stalePublications`,
    asCounter(run.postCloseBytesEvents, `${label}.postCloseBytesEvents`),
  );
  validateStalePublications(
    stalePublications,
    `${label}.stalePublications`,
    optimized,
  );
  return applicable;
}

// Every assertion is recomputed from the run ledger. This prevents a producer
// or an evidence editor from changing a boolean independently of the counts,
// socket identities, callback snapshots, or delayed Blob proof it claims.
function expectedAssertionValues(
  schema: BenchmarkSchema,
  stage: string,
  run: RecordLike,
  label: string,
  optimized: boolean,
): Readonly<Record<string, boolean>> {
  const reconnect =
    schema === "hermternal.pty-reconnect-supersession-benchmark.v2";
  const replacement = stage === "replace";
  const applicable = reconnect || replacement;
  const expectedCounters = expectedRunCounters(schema, stage);
  const count = (key: string): number =>
    asCounter(run[key], `${label}.${key}`);
  const expectedCount = (key: string): number => expectedCounters[key]!;
  const sampleMs = asFiniteNumber(run.sampleMs, `${label}.sampleMs`);
  const negativeControlSampleMs = asFiniteNumber(
    run.negativeControlSampleMs,
    `${label}.negativeControlSampleMs`,
  );
  const publications = asRecord(run.stalePublications, `${label}.stalePublications`);
  const stalePublicationsRejected = SINK_PUBLICATION_KEYS.every((sink) => {
    const counters = asRecord(publications[sink], `${label}.stalePublications.${sink}`);
    return SINK_COUNTER_KEYS.every(
      (counter) =>
        asCounter(
          counters[counter],
          `${label}.stalePublications.${sink}.${counter}`,
        ) === 0,
    );
  });
  const callbackBindings = asCallbackBindings(
    run.callbackBindings,
    `${label}.callbackBindings`,
    optimized,
  );
  const callbackBoundSinkNames = asStringArray(
    run.callbackBoundSinkNames,
    `${label}.callbackBoundSinkNames`,
  );
  const callbackBoundSinkNamesMatch =
    callbackBoundSinkNames.length === SINK_PUBLICATION_KEYS.length &&
    callbackBoundSinkNames.every(
      (sink, index) => sink === SINK_PUBLICATION_KEYS[index],
    );
  const derivedCallbackBoundSocketCount = callbackBindings.filter(
    (binding) =>
      binding.onopenBound &&
      binding.onmessageBound &&
      binding.onerrorBound &&
      binding.oncloseBound,
  ).length;
  const derivedAllCallbacksNullAfterClose = callbackBindings.every(
    (binding) =>
      binding.onopenNullAfterClose &&
      binding.onmessageNullAfterClose &&
      binding.onerrorNullAfterClose &&
      binding.oncloseNullAfterClose,
  );
  const callbackProofApplicable =
    applicable &&
    derivedCallbackBoundSocketCount === 1 &&
    callbackBoundSinkNamesMatch;
  const delayedBlob = asRecord(run.delayedBlob, `${label}.delayedBlob`);
  const delayedBlobEvents = asStringArray(
    delayedBlob.events,
    `${label}.delayedBlob.events`,
  );
  const delayedEventOrder =
    delayedBlobEvents.length === DELAYED_BLOB_EVENT_SEQUENCE.length &&
    delayedBlobEvents.every(
      (event, index) => event === DELAYED_BLOB_EVENT_SEQUENCE[index],
    );
  const delayedObserved =
    !applicable ||
    (asCounter(delayedBlob.scheduledCount, `${label}.delayedBlob.scheduledCount`) === 1 &&
      asCounter(delayedBlob.completionCount, `${label}.delayedBlob.completionCount`) === 1 &&
      delayedEventOrder);
  const delayedRejected =
    !applicable ||
    (delayedObserved &&
      count("postCloseBytesEvents") === 0 &&
      stalePublicationsRejected &&
      SINK_PUBLICATION_KEYS.every((sink) => {
        const counters = asRecord(publications[sink], `${label}.stalePublications.${sink}`);
        return asCounter(
          counters.bytesCount,
          `${label}.stalePublications.${sink}.bytesCount`,
        ) === 0;
      }));

  const reconnectOwner: OwnerIdentity = {
    sessionId: "benchmark-session",
    attach: "benchmark-attach",
    processIdentity: "benchmark-process",
  };
  // Connecting raw ledgers use the producer's suffixed input tuple; reconnect
  // retains its separate unsuffixed schema identity above.
  const connectingOwner: OwnerIdentity = {
    sessionId: "benchmark-session-a",
    attach: "benchmark-attach-a",
    processIdentity: "benchmark-process-a",
  };
  const replacementOwner: OwnerIdentity = {
    sessionId: "benchmark-session-b",
    attach: "benchmark-attach-b",
    processIdentity: "benchmark-process-b",
  };
  const expectedOwner = reconnect
    ? reconnectOwner
    : replacement
      ? replacementOwner
      : null;
  const activeOwnerIdentities = asOwnerIdentityArray(
    run.activeOwnerIdentities,
    `${label}.activeOwnerIdentities`,
    optimized,
  );
  const activeSocketIds = asStringArray(
    run.activeSocketIds,
    `${label}.activeSocketIds`,
  );
  const staleSocketIds = asStringArray(
    run.staleSocketIds,
    `${label}.staleSocketIds`,
  );
  const staleSocketIdentities = asOwnerIdentityArray(
    run.staleSocketIdentities,
    `${label}.staleSocketIdentities`,
    optimized,
  );
  const staleSocketId =
    run.staleSocketId === null
      ? null
      : asString(run.staleSocketId, `${label}.staleSocketId`);
  const replacementSocketId =
    run.replacementSocketId === null
      ? null
      : asString(run.replacementSocketId, `${label}.replacementSocketId`);
  const replacementSocketIdentity =
    run.replacementSocketIdentity === null
      ? null
      : asOwnerIdentity(
          run.replacementSocketIdentity,
          `${label}.replacementSocketIdentity`,
          optimized,
        );
  const replacementStateStatus =
    run.replacementStateStatus === null
      ? null
      : asString(run.replacementStateStatus, `${label}.replacementStateStatus`);
  const expectedReplacementStateStatus = applicable ? "attached" : null;
  const replacementStateMatchesExpected =
    replacementStateStatus === expectedReplacementStateStatus;
  const socketClosures = asSocketClosures(
    run.socketClosures,
    `${label}.socketClosures`,
    optimized,
  );
  const replacementClosure = socketClosures.find(
    (closure) => closure.socketId === replacementSocketId,
  );
  const replacementIdentityMatchesExpected =
    expectedOwner === null
      ? !replacement
      : replacementSocketIdentity !== null &&
        sameOwnerIdentity(replacementSocketIdentity, expectedOwner);
  const replacementOpenedExactlyOnce =
    replacementClosure?.opened === true && count("openedSockets") === 1;
  const activeSocketIsReplacement =
    (reconnect || replacement) &&
    activeSocketIds.length === 1 &&
    activeSocketIds[0] === replacementSocketId;
  const expectedSocketCount = reconnect
    ? stage === "factory"
      ? 2
      : 1
    : replacement
      ? 2
      : 1;
  const socketClosureLedgerExact = reconnect
    ? socketClosures.length === expectedSocketCount &&
      socketClosures.every(
        (closure) =>
          sameOwnerIdentity(closure.ownerIdentity, reconnectOwner) &&
          closure.closeCalls === 1 &&
          closure.opened === (closure.socketId === replacementSocketId),
      )
    : false;
  const reconnectStaleClosureExact =
    reconnect &&
    staleSocketId !== null &&
    socketClosures.some(
      (closure) =>
        closure.socketId === staleSocketId &&
        sameOwnerIdentity(closure.ownerIdentity, reconnectOwner) &&
        closure.closeCalls === 1 &&
        !closure.opened,
    );
  const connectingStaleClosureExact =
    !reconnect &&
    staleSocketId !== null &&
    socketClosures.some(
      (closure) =>
        closure.socketId === staleSocketId &&
        sameOwnerIdentity(closure.ownerIdentity, connectingOwner) &&
        closure.closeCalls === 1 &&
        !closure.opened,
    );
  const replacementClosureExact =
    replacementSocketId !== null &&
    expectedOwner !== null &&
    socketClosures.some(
      (closure) =>
        closure.socketId === replacementSocketId &&
        sameOwnerIdentity(closure.ownerIdentity, expectedOwner) &&
        closure.closeCalls === 1 &&
        closure.opened,
    );
  const ownerSocketClosureLedgerExact =
    socketClosures.length === expectedSocketCount &&
    (reconnect
      ? replacementClosureExact &&
        (stage !== "factory" ? staleSocketId === null : reconnectStaleClosureExact)
      : connectingStaleClosureExact && (!replacement || replacementClosureExact));
  const callbackBoundSocketCount = derivedCallbackBoundSocketCount;
  const callbackBoundSinkCount = callbackBoundSinkNames.length;
  const callbackApplicability =
    callbackBoundSocketCount === (applicable ? 1 : 0) &&
    callbackBoundSinkNamesMatch &&
    (!reconnect || count("activeOwnerCount") === 1);
  const callbackBindingCoversAllSinks = callbackBoundSinkNamesMatch;
  const allCallbacksNullAfterClose =
    !applicable || derivedAllCallbacksNullAfterClose;
  const staleDispatchesExercised =
    count("staleOnopenDispatches") === (applicable ? 1 : 0) &&
    count("staleOnmessageDispatches") === (applicable ? 1 : 0) &&
    count("staleOnerrorDispatches") === (applicable ? 1 : 0) &&
    count("staleOncloseDispatches") === (applicable ? 1 : 0);
  const noPostCloseStateEvents = count("postCloseStateEvents") === 0;
  const noPostCloseBytesEvents = count("postCloseBytesEvents") === 0;
  const noPostCloseNoticeEvents = count("postCloseNoticeEvents") === 0;
  const staleOnopenIgnored =
    staleDispatchesExercised && noPostCloseStateEvents;
  const staleOnmessageIgnored =
    staleDispatchesExercised && noPostCloseBytesEvents;
  const staleOnerrorIgnored =
    staleDispatchesExercised && noPostCloseStateEvents;
  const staleOncloseIgnored =
    staleDispatchesExercised && noPostCloseStateEvents;
  const stalePublicationRejected =
    staleDispatchesExercised &&
    noPostCloseStateEvents &&
    noPostCloseBytesEvents &&
    noPostCloseNoticeEvents &&
    stalePublicationsRejected &&
    delayedObserved &&
    delayedRejected;
  const cleanupRecorded = count("cleanupCalls") === expectedSocketCount;

  if (reconnect) {
    const factory = stage === "factory";
    const ticket = stage !== "validator";
    const negativeControlUsesPreConnectClock =
      negativeControlSampleMs >= sampleMs &&
      count("validatorCallsBeforeRecovery") === 1 &&
      count("ticketRequestsBeforeRecovery") === (ticket ? 1 : 0);
    const negativeControlIncludesStagedWork =
      negativeControlUsesPreConnectClock &&
      count("socketFactoryCallsBeforeRecovery") === (factory ? 1 : 0);
    const expectedOwnerIsOnlyActiveOwner =
      count("activeOwnerCount") === 1 &&
      activeOwnerIdentities.length === 1 &&
      sameOwnerIdentity(activeOwnerIdentities[0]!, reconnectOwner);
    return {
      quarantineValidatorFence:
        count("validatorCallsBeforeRecovery") === 1,
      quarantineTicketFence:
        negativeControlUsesPreConnectClock,
      quarantineFactoryFence:
        count("socketFactoryCallsBeforeRecovery") === (factory ? 1 : 0),
      negativeControlUsesPreConnectClock,
      negativeControlIncludesStagedWork,
      expectedValidatorCount: count("validatorCalls") === 2,
      expectedTicketCount:
        count("ticketRequests") === (stage === "validator" ? 1 : 2),
      expectedFactoryCount:
        count("socketFactoryCalls") === (factory ? 2 : 1),
      staleSocketIdentityMatchesStage:
        factory
          ? staleSocketIdentities.length === 1 &&
            sameOwnerIdentity(staleSocketIdentities[0]!, reconnectOwner)
          : staleSocketIdentities.length === 0,
      staleSocketIdMatchesStage:
        !factory ||
        (staleSocketIds.length === 1 && staleSocketIds[0] !== replacementSocketId),
      staleSocketClosedExactly:
        !factory || count("staleSocketCloseCalls") === 1,
      staleSocketNeverOpened: count("staleOpenCalls") === 0,
      replacementIdentityMatchesExpected,
      replacementSocketIdUnique: replacementSocketId !== staleSocketId,
      replacementOpenedExactlyOnce,
      replacementClosedExactlyOnce:
        count("replacementSocketCloseCalls") === 1,
      replacementReachedAttached:
        replacementOpenedExactlyOnce &&
        activeSocketIsReplacement &&
        replacementStateMatchesExpected,
      expectedOwnerIsOnlyActiveOwner,
      activeSocketIsReplacement,
      socketClosureLedgerExact,
      ownerSocketClosureLedgerExact,
      noDuplicateOwners: count("duplicateOwnerViolations") === 0,
      callbackApplicabilityMatchesLedger:
        callbackProofApplicable === callbackApplicability,
      replacementStateMatchesExpected,
      replacementCallbacksBound:
        callbackProofApplicable && callbackApplicability,
      allCallbacksNullAfterClose,
      callbackBindingCoversAllSinks,
      perSinkStalePublicationRejected: stalePublicationsRejected,
      delayedBlobConversionObserved: delayedObserved,
      delayedBlobPostClosePublicationRejected: delayedRejected,
      staleCallbacksExercised: staleDispatchesExercised,
      staleOnopenIgnored,
      staleOnmessageIgnored,
      staleOnerrorIgnored,
      staleOncloseIgnored,
      stalePublicationRejected,
      noPostCloseStateEvents,
      noPostCloseBytesEvents,
      noPostCloseNoticeEvents,
      cleanupRecorded,
    };
  }

  const expectedOwnerIsOnlyActiveOwner =
    count("activeOwnerCount") === (replacement ? 1 : 0) &&
    activeOwnerIdentities.length === (replacement ? 1 : 0) &&
    (!replacement ||
      (expectedOwner !== null &&
        sameOwnerIdentity(activeOwnerIdentities[0]!, expectedOwner)));
  const exactSocketCleanup =
    socketClosures.length === expectedSocketCount &&
    socketClosures.every(
      (closure) =>
        closure.closeCalls === 1 &&
        (closure.socketId === replacementSocketId
          ? closure.opened &&
            expectedOwner !== null &&
            sameOwnerIdentity(closure.ownerIdentity, expectedOwner)
          : !closure.opened &&
            sameOwnerIdentity(closure.ownerIdentity, connectingOwner)),
    );
  const callbackApplicabilityMatchesAction =
    callbackProofApplicable === (replacement && callbackApplicability);
  return {
    connectingGuard:
      staleSocketIds.length === 1 &&
      staleSocketIdentities.length === 1 &&
      count("staleOpenCalls") === 0 &&
      count("staleSocketCloseCalls") === 1 &&
      count("activeOwnerCount") === (replacement ? 1 : 0),
    staleSocketNeverOpened: count("staleOpenCalls") === 0,
    expectedValidatorCount:
      count("validatorCalls") === expectedCount("validatorCalls"),
    expectedFactoryCount:
      count("socketFactoryCalls") === expectedCount("socketFactoryCalls"),
    expectedTicketCount:
      count("ticketRequests") === expectedCount("ticketRequests"),
    negativeControlUsesPreConnectClock:
      negativeControlSampleMs >= sampleMs,
    negativeControlIncludesSetupAndTicket:
      negativeControlSampleMs >= sampleMs && count("validatorCalls") >= 1 && count("ticketRequests") >= 1,
    replacementOpenedExactlyOnce: !replacement || replacementOpenedExactlyOnce,
    replacementAttached:
      !replacement ||
      (replacementOpenedExactlyOnce &&
        activeSocketIsReplacement &&
        replacementStateMatchesExpected),
    expectedOwnerIsOnlyActiveOwner,
    activeSocketIsReplacement: !replacement || activeSocketIsReplacement,
    noDuplicateOwners: count("duplicateOwnerViolations") === 0,
    staleSocketIdentityFence:
      staleSocketIdentities.length === 1 &&
      sameOwnerIdentity(staleSocketIdentities[0]!, connectingOwner) &&
      count("staleSocketCloseCalls") === 1,
    staleSocketIdFence:
      staleSocketIds.length === 1 &&
      staleSocketId !== null &&
      staleSocketId !== replacementSocketId,
    replacementIdentityMatchesExpected: !replacement || replacementIdentityMatchesExpected,
    replacementStateMatchesExpected,
    replacementSocketIdUnique: !replacement || (replacementSocketId !== null && replacementSocketId !== staleSocketId),
    replacementClosedExactlyOnce: !replacement || count("replacementSocketCloseCalls") === 1,
    exactSocketCleanup,
    ownerSocketClosureLedgerExact,
    callbackApplicabilityMatchesAction,
    allCallbacksNullAfterClose,
    replacementCallbacksBound: !replacement || (callbackProofApplicable && callbackApplicability),
    callbackBindingCoversAllSinks,
    perSinkStalePublicationRejected: stalePublicationsRejected,
    delayedBlobConversionObserved: delayedObserved,
    delayedBlobPostClosePublicationRejected: delayedRejected,
    staleCallbacksExercised: !replacement || staleDispatchesExercised,
    staleOnopenIgnored: !replacement || staleOnopenIgnored,
    staleOnmessageIgnored: !replacement || staleOnmessageIgnored,
    staleOnerrorIgnored: !replacement || staleOnerrorIgnored,
    staleOncloseIgnored: !replacement || staleOncloseIgnored,
    stalePublicationRejected: !replacement || stalePublicationRejected,
    noPostCloseStateEvents,
    noPostCloseBytesEvents,
    noPostCloseNoticeEvents,
    cleanupRecorded,
  };
}

function validateOwnershipProof(
  schema: BenchmarkSchema,
  stage: string,
  run: RecordLike,
  label: string,
  optimized: boolean,
): void {
  const reconnect =
    schema === "hermternal.pty-reconnect-supersession-benchmark.v2";
  const replacement = stage === "replace";
  const reconnectOwner: OwnerIdentity = {
    sessionId: "benchmark-session",
    attach: "benchmark-attach",
    processIdentity: "benchmark-process",
  };
  // Connecting raw ledgers use the producer's suffixed input tuple; reconnect
  // retains its separate unsuffixed schema identity above.
  const connectingOwner: OwnerIdentity = {
    sessionId: "benchmark-session-a",
    attach: "benchmark-attach-a",
    processIdentity: "benchmark-process-a",
  };
  const replacementOwner: OwnerIdentity = {
    sessionId: "benchmark-session-b",
    attach: "benchmark-attach-b",
    processIdentity: "benchmark-process-b",
  };
  const expectedOwnerIdentity = reconnect
    ? reconnectOwner
    : replacement
      ? replacementOwner
      : null;
  const expectedActiveIdentities =
    expectedOwnerIdentity === null ? [] : [expectedOwnerIdentity];
  const connectingStale = !reconnect;
  const expectedActiveSocketIds =
    expectedOwnerIdentity === null
      ? []
      : [
          reconnect && stage === "factory"
            ? "socket-2"
            : !reconnect
              ? "socket-2"
              : "socket-1",
        ];
  const expectedStaleIdentities =
    reconnect && stage === "factory"
      ? [reconnectOwner]
      : connectingStale
        ? [connectingOwner]
        : [];
  const expectedStaleSocketIds =
    reconnect && stage === "factory"
      ? ["socket-1"]
      : connectingStale
        ? ["socket-1"]
        : [];
  const expectedStaleSocketId = expectedStaleSocketIds[0] ?? null;
  const expectedReplacementSocketId =
    expectedOwnerIdentity === null
      ? null
      : reconnect && stage === "factory"
        ? "socket-2"
        : !reconnect
          ? "socket-2"
          : "socket-1";
  const expectedSocketClosures: SocketClosure[] = reconnect
    ? stage === "factory"
      ? [
          {
            socketId: "socket-1",
            ownerIdentity: reconnectOwner,
            closeCalls: 1,
            opened: false,
          },
          {
            socketId: "socket-2",
            ownerIdentity: reconnectOwner,
            closeCalls: 1,
            opened: true,
          },
        ]
      : [
          {
            socketId: "socket-1",
            ownerIdentity: reconnectOwner,
            closeCalls: 1,
            opened: true,
          },
        ]
    : [
        {
          socketId: "socket-1",
          ownerIdentity: connectingOwner,
          closeCalls: 1,
          opened: false,
        },
        ...(replacement
          ? [
              {
                socketId: "socket-2",
                ownerIdentity: replacementOwner,
                closeCalls: 1,
                opened: true,
              },
            ]
          : []),
      ];

  const callbackProofApplicable = validateCallbackBindingProof(
    schema,
    stage,
    run,
    label,
    optimized,
  );
  const replacementStateStatus =
    run.replacementStateStatus === null
      ? null
      : asString(run.replacementStateStatus, `${label}.replacementStateStatus`);
  const expectedReplacementStateStatus = reconnect || replacement ? "attached" : null;
  if (replacementStateStatus !== expectedReplacementStateStatus) {
    throw new Error(
      `${label}.replacementStateStatus did not match the ownership stage`,
    );
  }

  const activeSocketIds = asStringArray(
    run.activeSocketIds,
    `${label}.activeSocketIds`,
  );
  expectStringArray(
    activeSocketIds,
    expectedActiveSocketIds,
    `${label}.activeSocketIds`,
  );

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
    expectOwnerIdentity(
      run.expectedOwnerIdentity,
      expectedOwnerIdentity,
      `${label}.expectedOwnerIdentity`,
      optimized,
    );
    if (run.replacementSocketIdentity === null) {
      throw new Error(
        `${label}.replacementSocketIdentity must not be null with a replacement socket`,
      );
    }
    expectOwnerIdentity(
      run.replacementSocketIdentity,
      expectedOwnerIdentity,
      `${label}.replacementSocketIdentity`,
      optimized,
    );
  }

  expectOwnerIdentityArray(
    asOwnerIdentityArray(
      run.activeOwnerIdentities,
      `${label}.activeOwnerIdentities`,
      optimized,
    ),
    expectedActiveIdentities,
    `${label}.activeOwnerIdentities`,
  );
  expectStringArray(
    asStringArray(run.staleSocketIds, `${label}.staleSocketIds`),
    expectedStaleSocketIds,
    `${label}.staleSocketIds`,
  );
  expectOwnerIdentityArray(
    asOwnerIdentityArray(
      run.staleSocketIdentities,
      `${label}.staleSocketIdentities`,
      optimized,
    ),
    expectedStaleIdentities,
    `${label}.staleSocketIdentities`,
  );

  const staleSocketId =
    run.staleSocketId === null
      ? null
      : asString(run.staleSocketId, `${label}.staleSocketId`);
  if (staleSocketId !== expectedStaleSocketId) {
    throw new Error(
      `${label}.staleSocketId did not match the deferred socket ledger`,
    );
  }
  const staleSocketIdentity =
    run.staleSocketIdentity === null
      ? null
      : asOwnerIdentity(
          run.staleSocketIdentity,
          `${label}.staleSocketIdentity`,
          optimized,
        );
  if (expectedStaleIdentities.length === 0) {
    if (staleSocketIdentity !== null) {
      throw new Error(
        `${label}.staleSocketIdentity must be null without a stale socket`,
      );
    }
  } else if (
    staleSocketIdentity === null ||
    !sameOwnerIdentity(staleSocketIdentity, expectedStaleIdentities[0]!)
  ) {
    throw new Error(
      `${label}.staleSocketIdentity did not match the deferred socket ledger`,
    );
  }

  const replacementSocketId =
    run.replacementSocketId === null
      ? null
      : asString(run.replacementSocketId, `${label}.replacementSocketId`);
  if (replacementSocketId !== expectedReplacementSocketId) {
    throw new Error(
      `${label}.replacementSocketId did not match the replacement socket ledger`,
    );
  }

  expectSocketClosures(
    asSocketClosures(run.socketClosures, `${label}.socketClosures`, optimized),
    expectedSocketClosures,
    `${label}.socketClosures`,
  );

  if (!reconnect) {
    // A connecting observer can lose ownership before the factory promise
    // settles. The approved transport retains that late value as one unopened,
    // callback-free stale socket; replacement adds one opened socket whose
    // callbacks are exercised and then nulled during cleanup.
    if (run.allCallbacksNullAfterClose !== true) {
      throw new Error(
        `${label}.allCallbacksNullAfterClose did not prove callback disownership`,
      );
    }
    const expectedCallbackDispatches = replacement ? 1 : 0;
    for (const key of [
      "staleOnopenDispatches",
      "staleOnmessageDispatches",
      "staleOnerrorDispatches",
      "staleOncloseDispatches",
    ] as const) {
      if (
        asFiniteNumber(run[key], `${label}.${key}`) !==
        expectedCallbackDispatches
      ) {
        throw new Error(
          `${label}.${key} did not match the connecting callback dispatch ledger`,
        );
      }
    }
  } else if (run.allCallbacksNullAfterClose !== true) {
    throw new Error(
      `${label}.allCallbacksNullAfterClose did not prove callback disownership`,
    );
  }
}

function validateResults(
  root: RecordLike,
  schema: BenchmarkSchema,
  optimized: boolean,
): void {
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
    assertExactKeys(result, RESULT_KEYS, `${schema}.results[${resultIndex}]`);
    if (optimized) {
      assertCanonicalKeys(
        result,
        RESULT_KEYS,
        `${schema}.results[${resultIndex}]`,
      );
    }
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
      optimized,
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
    if (optimized) {
      assertCanonicalKeys(totals, spec.totalCounters, `${schema}.${stage}.totals`);
    }
    for (const [runIndex, rawRun] of runs.entries()) {
      const run = asRecord(rawRun, `${schema}.${stage}.runs[${runIndex}]`);
      const runLabel = `${schema}.${stage}.runs[${runIndex}]`;
      assertExactKeys(run, spec.runKeys, runLabel);
      if (optimized) assertCanonicalKeys(run, spec.runKeys, runLabel);
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
      validateOwnershipProof(schema, stage, run, runLabel, optimized);
      const assertions = asRecord(run.assertions, `${runLabel}.assertions`);
      assertExactKeys(assertions, spec.assertionKeys, `${runLabel}.assertions`);
      if (optimized) {
        assertCanonicalKeys(assertions, spec.assertionKeys, `${runLabel}.assertions`);
      }
      const expectedAssertions = expectedAssertionValues(
        schema,
        stage,
        run,
        runLabel,
        optimized,
      );
      for (const key of spec.assertionKeys) {
        if (!(key in expectedAssertions) || assertions[key] !== expectedAssertions[key]) {
          throw new Error(
            `${runLabel}.assertions.${key} was not bound to its proof ledger`,
          );
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
  const spec = BENCHMARK_SPECS[schema];
  const blobs = asRecord(root.provenance, `${schema}.provenance`).sourceBlobs;
  if (!Array.isArray(blobs))
    throw new Error(`${schema}.provenance.sourceBlobs must be an array`);
  const expectedPaths = [
    spec.source.path,
    TRANSPORT_SOURCE,
    PACKAGE_SOURCE,
    LOCKFILE_SOURCE,
    PTY_BENCHMARK_PROVENANCE_SOURCE,
  ];
  const legacyExpectedPaths = expectedPaths.slice(0, -1);
  const legacyFourBlobArtifact = LEGACY_V1_FOUR_BLOB_ARTIFACTS.has(
    `${schema}|${spec.source.path}`,
  );
  const canonicalPaths = legacyFourBlobArtifact
    ? legacyExpectedPaths
    : expectedPaths;
  if (
    blobs.length !== canonicalPaths.length ||
    blobs.some(
      (rawBlob, index) =>
        asRecord(rawBlob, "provenance blob").path !== canonicalPaths[index],
    )
  ) {
    throw new Error(
      `${schema} optimized validation rejected non-canonical provenance order`,
    );
  }
}

function validatePtyBenchmarkArtifactInCheckout(
  artifact: unknown,
  options: PtyBenchmarkValidationOptions,
  evidenceCwd: string,
): void {
  const root = asRecord(artifact, "benchmark artifact");
  const schema = asString(root.schema, "benchmark.schema");
  expectedSpec(schema);
  if (
    options.expectedSchema !== undefined &&
    schema !== options.expectedSchema
  ) {
    throw new Error(
      `benchmark schema ${schema} did not match the retained artifact identity ${options.expectedSchema}`,
    );
  }
  const benchmarkSchema = schema as BenchmarkSchema;
  const optimized = options.optimized === true;
  // Dispatch before v2 metadata checks so unsupported schemas have precedence
  // over misleading metric or root-shape errors.
  validateRootMetadata(root, benchmarkSchema, optimized);
  validateOperationAndMetric(root, benchmarkSchema, optimized);
  validateProvenance(root, benchmarkSchema, optimized, evidenceCwd);
  validateResults(root, benchmarkSchema, optimized);
  if (optimized) validateOptimizedShape(root, benchmarkSchema);
}

export function validatePtyBenchmarkArtifact(
  artifact: unknown,
  options: PtyBenchmarkValidationOptions = {},
): void {
  validatePtyBenchmarkArtifactInCheckout(artifact, options, process.cwd());
}

function parseJsonWithoutDuplicateKeys(source: string): unknown {
  let index = 0;

  const skipWhitespace = (): void => {
    while (index < source.length && /\s/u.test(source[index]!)) index += 1;
  };

  const parseString = (): string => {
    const start = index;
    if (source[index] !== '"') throw new Error("invalid JSON artifact");
    index += 1;
    while (index < source.length) {
      const character = source[index]!;
      if (character === "\\") {
        index += 2;
        continue;
      }
      index += 1;
      if (character === '"') {
        try {
          const value = JSON.parse(source.slice(start, index)) as unknown;
          if (typeof value !== "string") throw new Error("invalid JSON artifact");
          return value;
        } catch {
          throw new Error("invalid JSON artifact");
        }
      }
    }
    throw new Error("invalid JSON artifact");
  };

  const parseValue = (): void => {
    skipWhitespace();
    const character = source[index];
    if (character === '"') {
      parseString();
      return;
    }
    if (character === "{") {
      index += 1;
      skipWhitespace();
      const keys = new Set<string>();
      if (source[index] === "}") {
        index += 1;
        return;
      }
      while (index < source.length) {
        skipWhitespace();
        const key = parseString();
        if (keys.has(key)) throw new Error("duplicate JSON object key");
        keys.add(key);
        skipWhitespace();
        if (source[index] !== ":") throw new Error("invalid JSON artifact");
        index += 1;
        parseValue();
        skipWhitespace();
        if (source[index] === "}") {
          index += 1;
          return;
        }
        if (source[index] !== ",") throw new Error("invalid JSON artifact");
        index += 1;
      }
      throw new Error("invalid JSON artifact");
    }
    if (character === "[") {
      index += 1;
      skipWhitespace();
      if (source[index] === "]") {
        index += 1;
        return;
      }
      while (index < source.length) {
        parseValue();
        skipWhitespace();
        if (source[index] === "]") {
          index += 1;
          return;
        }
        if (source[index] !== ",") throw new Error("invalid JSON artifact");
        index += 1;
      }
      throw new Error("invalid JSON artifact");
    }
    for (const literal of ["true", "false", "null"] as const) {
      if (source.startsWith(literal, index)) {
        index += literal.length;
        return;
      }
    }
    const numberStart = index;
    while (
      index < source.length &&
      !/[\s,\]}]/u.test(source[index]!)
    ) {
      index += 1;
    }
    if (numberStart === index) throw new Error("invalid JSON artifact");
  };

  parseValue();
  skipWhitespace();
  if (index !== source.length) throw new Error("invalid JSON artifact");
  try {
    return JSON.parse(source) as unknown;
  } catch {
    throw new Error("invalid JSON artifact");
  }
}

function gitRootForPath(path: string): string {
  return git(["rev-parse", "--show-toplevel"], dirname(resolve(path)));
}

export function validatePtyBenchmarkFile(
  path: string,
  options: PtyBenchmarkValidationOptions = {},
): void {
  validatePtyBenchmarkArtifactInCheckout(
    parseJsonWithoutDuplicateKeys(readFileSync(path, "utf8")),
    options,
    gitRootForPath(path),
  );
}
