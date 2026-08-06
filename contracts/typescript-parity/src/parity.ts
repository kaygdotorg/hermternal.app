import { resolve, relative, normalize, isAbsolute, join } from "node:path";

export const HERMES_SOURCE_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e";
export const CONTRACT = "dashboard-v0.0.1";
export const REGISTRY_SCHEMA = "hermternal.fixture-index.v1";

export const PLATFORMS = ["web", "ios", "ipados", "macos"] as const;
export type Platform = (typeof PLATFORMS)[number];
export type Family =
  | "auth"
  | "connection"
  | "session"
  | "chat"
  | "image"
  | "pty"
  | "deep-link"
  | "compatibility";

export type JsonPrimitive = null | boolean | number | string;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonRecord = { [key: string]: JsonValue };

export class ContractInputError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "ContractInputError";
    this.code = code;
  }
}

interface RegistryFile {
  readonly path: string;
  readonly sha256: string;
  readonly sizeBytes: number;
}

interface FixtureRoot {
  readonly id: string;
  readonly path: string;
  readonly status: "ready" | "pending";
  readonly contract: string;
  readonly hermesSourceSha: string;
  readonly syntheticOnly: true;
  readonly liveClaim: false;
  readonly platforms: readonly Platform[];
  readonly states: readonly string[];
  readonly coverageIds: readonly string[];
  readonly validator: string;
  readonly files: readonly RegistryFile[];
}

interface CoverageRow {
  readonly id: string;
  readonly status: "ready" | "pending";
  readonly fixtureIds: readonly string[];
  readonly platforms: readonly Platform[];
  readonly requiredStates: readonly string[];
  readonly notes: string;
}

interface RegistryParity {
  readonly status: string;
  readonly fixtureSource: string;
  readonly platforms: readonly Platform[];
  readonly ptyPolicy: string;
  readonly missingResultPolicy: string;
  readonly resultEquivalence: string;
  readonly liveClaim: false;
}

export interface FixtureRegistry {
  readonly fixtureRoots: readonly FixtureRoot[];
  readonly coverage: readonly CoverageRow[];
  readonly parity: RegistryParity;
}

export interface FixtureCase {
  readonly id: string;
  readonly expected: JsonRecord;
  readonly raw: JsonRecord;
}

export interface CompatibilityRecord {
  readonly compatible: false;
  readonly liveRun: false;
  readonly deploymentAttestation: string;
  readonly behavioralProbe: string;
  readonly proxyProof: string;
  readonly parityEvidence: string;
  readonly benchmarkEvidence: string;
}

export interface ProjectedOutcome {
  readonly family: Family;
  readonly caseId: string;
  readonly platform: Platform;
  readonly decision: string;
  readonly semantic: JsonRecord;
}

export interface ParityCaseResult {
  readonly family: Family;
  readonly coverageId: string;
  readonly caseId: string;
  readonly status: "proven" | "blocked";
  readonly platforms: readonly Platform[];
  readonly webDecision?: string;
  readonly appleDecision?: string;
}

export interface ParityReport {
  readonly ok: true;
  readonly contract: string;
  readonly hermesSourceSha: string;
  readonly syntheticOnly: true;
  readonly liveClaim: false;
  readonly networkCalls: 0;
  readonly readyCaseCount: number;
  readonly blockedCoverageIds: readonly string[];
  readonly cases: readonly ParityCaseResult[];
  readonly compatibility: CompatibilityRecord;
}

const JSON_ARTIFACTS: Readonly<Record<string, string>> = {
  "deployment-security-browser-auth": "deployment-security/browser-auth/cases.json",
  "connection-restoration": "connection-restoration/cases.json",
  "session-persistence": "session-persistence/cases.json",
  "image-attachment-lifecycle": "image-attachment-lifecycle/cases.json",
  "pty-contract": "pty-contract/pty-contract-fixtures.json",
  "deep-link-grammar": "deep-link-grammar/cases.json",
  "compatibility-attestation": "compatibility-attestation/cases.json",
  "source-audit-compatibility-gate":
    "source-audit/compatibility-gate/compatibility_record.json",
};

interface Representative {
  readonly family: Family;
  readonly rootId: string;
  readonly coverageId: string;
  readonly caseIds: readonly string[];
}

const REPRESENTATIVES: readonly Representative[] = [
  {
    family: "auth",
    rootId: "deployment-security-browser-auth",
    coverageId: "browser-cookie-auth",
    caseIds: ["login-success", "callback-csrf-mismatch"],
  },
  {
    family: "connection",
    rootId: "connection-restoration",
    coverageId: "connection-restoration",
    caseIds: ["initial-connect-ready", "prompt-transport-loss-uncertain"],
  },
  {
    family: "session",
    rootId: "session-persistence",
    coverageId: "chat-stream-and-completion",
    caseIds: ["first-prompt-persists-session", "transport-loss-enters-delivery-uncertain"],
  },
  {
    family: "chat",
    rootId: "session-persistence",
    coverageId: "chat-stream-and-completion",
    caseIds: ["transport-loss-enters-delivery-uncertain", "automatic-prompt-retry-fails-closed"],
  },
  {
    family: "image",
    rootId: "image-attachment-lifecycle",
    coverageId: "image-attachment-lifecycle",
    caseIds: ["empty-selection", "malformed-base64", "success-transcript-reference"],
  },
  {
    family: "pty",
    rootId: "pty-contract",
    coverageId: "web-pty",
    caseIds: ["raw-bytes-preserve", "no-byte-logging"],
  },
  {
    family: "deep-link",
    rootId: "deep-link-grammar",
    coverageId: "private-deep-link",
    caseIds: ["valid-web-session", "wrong-origin"],
  },
  {
    family: "compatibility",
    rootId: "compatibility-attestation",
    coverageId: "deployment-attestation",
    caseIds: ["valid_attestation_with_probe", "missing_attestation"],
  },
];

function fail(code: string, message: string): never {
  throw new ContractInputError(code, message);
}

function isRecord(value: JsonValue | undefined): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isJsonValue(value: unknown): value is JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return true;
  }
  if (typeof value === "number") {
    return Number.isFinite(value);
  }
  if (Array.isArray(value)) {
    return value.every(isJsonValue);
  }
  if (typeof value === "object") {
    return Object.values(value).every(isJsonValue);
  }
  return false;
}

function record(value: JsonValue | undefined, label: string): JsonRecord {
  if (!isRecord(value)) {
    fail("malformed_input", `${label} must be an object`);
  }
  return value;
}

function array(value: JsonValue | undefined, label: string): JsonValue[] {
  if (!Array.isArray(value)) {
    fail("malformed_input", `${label} must be an array`);
  }
  return value;
}

function string(value: JsonValue | undefined, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    fail("malformed_input", `${label} must be a non-empty string`);
  }
  return value;
}

function boolean(value: JsonValue | undefined, label: string): boolean {
  if (typeof value !== "boolean") {
    fail("malformed_input", `${label} must be a boolean`);
  }
  return value;
}

function number(value: JsonValue | undefined, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    fail("malformed_input", `${label} must be a non-negative safe integer`);
  }
  return value;
}

function literal(value: JsonValue | undefined, expected: string, label: string): void {
  if (value !== expected) {
    fail("incompatible_input", `${label} does not match the reviewed contract`);
  }
}

function safeRelativePath(value: string, label: string): string {
  if (
    isAbsolute(value) ||
    value.includes("://") ||
    value.includes("\\") ||
    value === "" ||
    normalize(value) !== value ||
    value === "." ||
    value.startsWith("../") ||
    value.includes("/../")
  ) {
    fail("unsafe_path", `${label} is not a safe repository-relative path`);
  }
  return value;
}

function platform(value: JsonValue | undefined, label: string): Platform {
  const candidate = string(value, label);
  if (!PLATFORMS.includes(candidate as Platform)) {
    fail("unknown_platform", `${label} is not a supported parity platform`);
  }
  return candidate as Platform;
}

function platforms(value: JsonValue | undefined, label: string): readonly Platform[] {
  const result = array(value, label).map((entry, index) => platform(entry, `${label}[${index}]`));
  if (new Set(result).size !== result.length) {
    fail("malformed_input", `${label} contains a duplicate platform`);
  }
  return result;
}

function strings(value: JsonValue | undefined, label: string): readonly string[] {
  const result = array(value, label).map((entry, index) => string(entry, `${label}[${index}]`));
  if (new Set(result).size !== result.length) {
    fail("malformed_input", `${label} contains a duplicate value`);
  }
  return result;
}

function parseJson(text: string, label: string): JsonValue {
  try {
    const value: unknown = JSON.parse(text);
    if (!isJsonValue(value)) {
      fail("malformed_json", `${label} contains a non-finite JSON value`);
    }
    return value;
  } catch (error) {
    if (error instanceof ContractInputError) {
      throw error;
    }
    fail("malformed_json", `${label} is not valid JSON`);
  }
}

async function readJson(path: string, label: string): Promise<JsonValue> {
  try {
    const file = Bun.file(path);
    if (!(await file.exists())) {
      fail("missing_artifact", `${label} is not checked in`);
    }
    const bytes = await file.arrayBuffer();
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return parseJson(text, label);
  } catch (error) {
    if (error instanceof ContractInputError) {
      throw error;
    }
    fail("malformed_utf8", `${label} is not valid UTF-8`);
  }
}

function parseRegistryFile(value: JsonValue | undefined, label: string): RegistryFile {
  const entry = record(value, label);
  return {
    path: safeRelativePath(string(entry.path, `${label}.path`), `${label}.path`),
    sha256: string(entry.sha256, `${label}.sha256`),
    sizeBytes: number(entry.size_bytes, `${label}.size_bytes`),
  };
}

function parseFixtureRoot(value: JsonValue | undefined, index: number): FixtureRoot {
  const entry = record(value, `fixture_roots[${index}]`);
  const status = string(entry.status, `fixture_roots[${index}].status`);
  if (status !== "ready" && status !== "pending") {
    fail("unknown_status", `fixture_roots[${index}].status is unknown`);
  }
  return {
    id: string(entry.id, `fixture_roots[${index}].id`),
    path: safeRelativePath(string(entry.path, `fixture_roots[${index}].path`), `fixture_roots[${index}].path`),
    status,
    contract: string(entry.contract, `fixture_roots[${index}].contract`),
    hermesSourceSha: string(entry.hermes_source_sha, `fixture_roots[${index}].hermes_source_sha`),
    syntheticOnly: boolean(entry.synthetic_only, `fixture_roots[${index}].synthetic_only`) as true,
    liveClaim: boolean(entry.live_claim, `fixture_roots[${index}].live_claim`) as false,
    platforms: platforms(entry.platforms, `fixture_roots[${index}].platforms`),
    states: strings(entry.states, `fixture_roots[${index}].states`),
    coverageIds: strings(entry.coverage_ids, `fixture_roots[${index}].coverage_ids`),
    validator: string(entry.validator, `fixture_roots[${index}].validator`),
    files: array(entry.files, `fixture_roots[${index}].files`).map((file, fileIndex) =>
      parseRegistryFile(file, `fixture_roots[${index}].files[${fileIndex}]`),
    ),
  };
}

function parseCoverage(value: JsonValue | undefined, index: number): CoverageRow {
  const entry = record(value, `coverage[${index}]`);
  const status = string(entry.status, `coverage[${index}].status`);
  if (status !== "ready" && status !== "pending") {
    fail("unknown_status", `coverage[${index}].status is unknown`);
  }
  return {
    id: string(entry.id, `coverage[${index}].id`),
    status,
    fixtureIds: strings(entry.fixture_ids, `coverage[${index}].fixture_ids`),
    platforms: platforms(entry.platforms, `coverage[${index}].platforms`),
    requiredStates: strings(entry.required_states, `coverage[${index}].required_states`),
    notes: string(entry.notes, `coverage[${index}].notes`),
  };
}

function parseParity(value: JsonValue | undefined): RegistryParity {
  const entry = record(value, "parity");
  return {
    status: string(entry.status, "parity.status"),
    fixtureSource: string(entry.fixture_source, "parity.fixture_source"),
    platforms: platforms(entry.platforms, "parity.platforms"),
    ptyPolicy: string(entry.pty_policy, "parity.pty_policy"),
    missingResultPolicy: string(entry.missing_result_policy, "parity.missing_result_policy"),
    resultEquivalence: string(entry.result_equivalence, "parity.result_equivalence"),
    liveClaim: boolean(entry.live_claim, "parity.live_claim") as false,
  };
}

export async function loadRegistry(repoRoot: string): Promise<FixtureRegistry> {
  const root = resolve(repoRoot);
  const raw = record(await readJson(join(root, "contracts/fixtures/index.json"), "fixture index"), "fixture index");
  literal(raw.schema, REGISTRY_SCHEMA, "fixture index schema");
  literal(raw.contract, CONTRACT, "fixture index contract");
  literal(raw.hermes_source_sha, HERMES_SOURCE_SHA, "fixture index source revision");
  if (boolean(raw.synthetic_only, "fixture index synthetic_only") !== true) {
    fail("live_input", "fixture index is not synthetic-only");
  }
  if (boolean(raw.live_claim, "fixture index live_claim") !== false) {
    fail("live_input", "fixture index makes a live claim");
  }

  const fixtureRoots = array(raw.fixture_roots, "fixture_roots").map(parseFixtureRoot);
  const coverage = array(raw.coverage, "coverage").map(parseCoverage);
  if (new Set(fixtureRoots.map((entry) => entry.id)).size !== fixtureRoots.length) {
    fail("malformed_input", "fixture root IDs are not unique");
  }
  if (new Set(coverage.map((entry) => entry.id)).size !== coverage.length) {
    fail("malformed_input", "coverage IDs are not unique");
  }
  for (const entry of fixtureRoots) {
    if (entry.contract !== CONTRACT || entry.hermesSourceSha !== HERMES_SOURCE_SHA) {
      fail("incompatible_input", "fixture root is not pinned to the reviewed contract");
    }
    if (entry.syntheticOnly !== true || entry.liveClaim !== false) {
      fail("live_input", "fixture root is not synthetic-only");
    }
  }
  const rootIds = new Set(fixtureRoots.map((entry) => entry.id));
  for (const entry of coverage) {
    if (entry.status === "ready" && entry.fixtureIds.some((id) => !rootIds.has(id))) {
      fail("unknown_fixture", "ready coverage references an unknown fixture root");
    }
  }
  const parity = parseParity(raw.parity);
  if (parity.liveClaim !== false || parity.fixtureSource !== "one_shared_registry") {
    fail("incompatible_input", "parity policy is not the shared synthetic policy");
  }
  return { fixtureRoots, coverage, parity };
}

function rootById(registry: FixtureRegistry, rootId: string): FixtureRoot {
  const root = registry.fixtureRoots.find((entry) => entry.id === rootId);
  if (!root) {
    fail("unknown_fixture", "representative fixture root is not registered");
  }
  return root;
}

function coverageById(registry: FixtureRegistry, coverageId: string): CoverageRow {
  const coverage = registry.coverage.find((entry) => entry.id === coverageId);
  if (!coverage) {
    fail("unknown_coverage", "representative coverage row is not registered");
  }
  return coverage;
}

function artifactPath(repoRoot: string, root: FixtureRoot): string {
  const relativeArtifact = JSON_ARTIFACTS[root.id];
  if (!relativeArtifact) {
    fail("unknown_fixture", "fixture root has no approved JSON artifact");
  }
  const expectedPrefix = `${root.path}/`;
  if (!relativeArtifact.startsWith(expectedPrefix)) {
    fail("incompatible_input", "fixture artifact is outside its registered root");
  }
  const registered = root.files.some((entry) => entry.path === relativeArtifact);
  if (!registered) {
    fail("unregistered_artifact", "fixture JSON artifact is not listed by the registry");
  }
  return join(resolve(repoRoot), "contracts/fixtures", safeRelativePath(relativeArtifact, "fixture artifact"));
}

async function loadArtifact(repoRoot: string, root: FixtureRoot): Promise<JsonRecord> {
  return record(await readJson(artifactPath(repoRoot, root), `fixture ${root.id}`), `fixture ${root.id}`);
}

export async function loadCase(repoRoot: string, registry: FixtureRegistry, rootId: string, caseId: string): Promise<FixtureCase> {
  if (!caseId || caseId.trim() !== caseId) {
    fail("malformed_input", "case ID must be a non-empty canonical string");
  }
  const root = rootById(registry, rootId);
  if (root.status !== "ready") {
    fail("coverage_pending", "pending fixture roots cannot provide parity evidence");
  }
  const artifact = await loadArtifact(repoRoot, root);
  const cases = array(artifact.cases, `fixture ${rootId}.cases`);
  const matches = cases.filter((entry) => isRecord(entry) && entry.id === caseId);
  if (matches.length !== 1) {
    fail("unknown_case", "representative case ID is absent or duplicated");
  }
  const raw = record(matches[0], `fixture ${rootId}.${caseId}`);
  return {
    id: string(raw.id, `fixture ${rootId}.${caseId}.id`),
    expected: record(raw.expected, `fixture ${rootId}.${caseId}.expected`),
    raw,
  };
}

export async function loadCompatibilityRecord(repoRoot: string, registry: FixtureRegistry): Promise<CompatibilityRecord> {
  const root = rootById(registry, "source-audit-compatibility-gate");
  const artifact = await loadArtifact(repoRoot, root);
  literal(artifact.schema, "hermternal.compatibility-gate.v1", "compatibility schema");
  const source = record(artifact.source, "compatibility source");
  literal(source.sha, HERMES_SOURCE_SHA, "compatibility source revision");
  const status = record(artifact.status, "compatibility status");
  if (boolean(status.compatible, "compatibility status.compatible") !== false) {
    fail("live_claim", "compatibility record claims compatibility without live evidence");
  }
  if (boolean(status.live_run, "compatibility status.live_run") !== false) {
    fail("live_input", "compatibility record contains live-run evidence");
  }
  return {
    compatible: false,
    liveRun: false,
    deploymentAttestation: string(status.deployment_attestation, "compatibility deployment attestation"),
    behavioralProbe: string(status.behavioral_probe, "compatibility behavioral probe"),
    proxyProof: string(status.proxy_proof, "compatibility proxy proof"),
    parityEvidence: string(status.parity_evidence, "compatibility parity evidence"),
    benchmarkEvidence: string(status.benchmark_evidence, "compatibility benchmark evidence"),
  };
}

function sorted(value: JsonValue): JsonValue {
  if (Array.isArray(value)) {
    return value.map(sorted);
  }
  if (isRecord(value)) {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key] ?? null)]));
  }
  return value;
}

function decision(expected: JsonRecord): string {
  for (const key of ["decision", "state", "final_state", "attestation_result", "runtime_gate", "valid"]) {
    const value = expected[key];
    if (typeof value === "string") {
      return value;
    }
    if (typeof value === "boolean") {
      return value ? "valid" : "blocked";
    }
  }
  for (const key of ["pty_bytes_logged", "raw_bytes_logged"]) {
    const value = expected[key];
    if (typeof value === "boolean") {
      return value ? "logged" : "redacted";
    }
  }
  fail("malformed_input", "representative expected result has no semantic decision");
}

function project(family: Family, platformName: Platform, fixtureCase: FixtureCase): ProjectedOutcome {
  return {
    family,
    caseId: fixtureCase.id,
    platform: platformName,
    decision: decision(fixtureCase.expected),
    semantic: record(sorted(fixtureCase.expected), "semantic expected result"),
  };
}

function equalJson(left: JsonValue, right: JsonValue): boolean {
  return JSON.stringify(sorted(left)) === JSON.stringify(sorted(right));
}

async function runRepresentative(
  repoRoot: string,
  registry: FixtureRegistry,
  representative: Representative,
): Promise<ParityCaseResult[]> {
  const coverage = coverageById(registry, representative.coverageId);
  if (!coverage.fixtureIds.includes(representative.rootId)) {
    fail("incompatible_input", "coverage row does not own its representative fixture root");
  }
  if (coverage.status === "pending") {
    const results: ParityCaseResult[] = [];
    for (const caseId of representative.caseIds) {
      const fixtureCase = await loadCase(repoRoot, registry, representative.rootId, caseId);
      if (representative.family === "chat" && !["delivery_uncertain", "automatic_prompt_retry_blocked"].includes(decision(fixtureCase.expected))) {
        fail("incompatible_input", "pending chat coverage contains an unexpected success decision");
      }
      results.push({
        family: representative.family,
        coverageId: representative.coverageId,
        caseId,
        status: "blocked",
        platforms: coverage.platforms,
      });
    }
    return results;
  }

  const root = rootById(registry, representative.rootId);
  if (root.status !== "ready") {
    fail("coverage_pending", "ready coverage references a pending fixture root");
  }
  const results: ParityCaseResult[] = [];
  for (const caseId of representative.caseIds) {
    const fixtureCase = await loadCase(repoRoot, registry, representative.rootId, caseId);
    const web = coverage.platforms.includes("web") ? project(representative.family, "web", fixtureCase) : undefined;
    const applePlatform = coverage.platforms.includes("ios") ? "ios" : coverage.platforms.includes("ipados") ? "ipados" : "macos";
    const apple = coverage.platforms.includes(applePlatform) ? project(representative.family, applePlatform, fixtureCase) : undefined;

    if (representative.family === "pty") {
      if (!web || coverage.platforms.length !== 1 || coverage.platforms[0] !== "web") {
        fail("incompatible_input", "PTY parity must be a web-only fixture");
      }
      results.push({
        family: representative.family,
        coverageId: representative.coverageId,
        caseId,
        status: "proven",
        platforms: coverage.platforms,
        webDecision: web.decision,
        appleDecision: "blocked_platform",
      });
      continue;
    }

    if (!web || !apple || !equalJson(web.semantic, apple.semantic)) {
      fail("parity_mismatch", "shared fixture semantic outcomes differ by platform");
    }
    results.push({
      family: representative.family,
      coverageId: representative.coverageId,
      caseId,
      status: "proven",
      platforms: coverage.platforms,
      webDecision: web.decision,
      appleDecision: apple.decision,
    });
  }
  return results;
}

export async function runParity(repoRoot: string): Promise<ParityReport> {
  const registry = await loadRegistry(repoRoot);
  literal(registry.parity.ptyPolicy, "web_only_apple_blocked", "parity PTY policy");
  literal(registry.parity.missingResultPolicy, "block", "parity missing-result policy");
  literal(registry.parity.resultEquivalence, "semantic_outcomes_not_platform_specific_wire_bytes", "parity equivalence policy");

  const cases: ParityCaseResult[] = [];
  for (const representative of REPRESENTATIVES) {
    cases.push(...(await runRepresentative(repoRoot, registry, representative)));
  }
  const compatibility = await loadCompatibilityRecord(repoRoot, registry);
  const blockedCoverageIds = registry.coverage.filter((entry) => entry.status === "pending").map((entry) => entry.id);
  return {
    ok: true,
    contract: CONTRACT,
    hermesSourceSha: HERMES_SOURCE_SHA,
    syntheticOnly: true,
    liveClaim: false,
    networkCalls: 0,
    readyCaseCount: cases.filter((entry) => entry.status === "proven").length,
    blockedCoverageIds,
    cases,
    compatibility,
  };
}

export function repoRootFromModule(moduleDirectory: string): string {
  return resolve(moduleDirectory, "../../..");
}

export function assertRejects(error: unknown, code: string): void {
  if (!(error instanceof ContractInputError) || error.code !== code) {
    fail("regression_failure", `expected ${code} rejection`);
  }
}

export function representativeIds(): readonly Representative[] {
  return REPRESENTATIVES;
}

export function assertNoNetworkImports(sourceText: string): void {
  if (/\b(fetch|WebSocket|XMLHttpRequest|net|https?\.request|connect)\s*\(/.test(sourceText)) {
    fail("network_boundary", "parity tooling must not open a network connection");
  }
}
