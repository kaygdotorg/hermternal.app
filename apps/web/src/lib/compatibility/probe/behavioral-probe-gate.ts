import behavioralProbeFixture from '../../../../../../contracts/fixtures/behavioral-probe/probe-fixtures.json';

const EVIDENCE_SCHEMA = 'hermternal.web-behavioral-probe-evidence.v1';
const FIXTURE_SCHEMA = 'hermternal.behavioral-probe.v1';
const DASHBOARD_CONTRACT = 'dashboard-v0.0.1';
const PINNED_HERMES_SOURCE_SHA = 'f5be9236e00ddf2f2a412697f267078fc4ee068e';
const PINNED_ROUTE_MANIFEST_SHA256 =
  '3c6b44dc8dd90836f4fc5c5158d459959c569fb811db4b198e87d78ea5010197';
const REQUIRED_CASE_COUNT = 64;
const REQUIRED_REQUIREMENT_COUNT = 11;
const MAX_IDENTIFIER_LENGTH = 128;
const MAX_STRING_LENGTH = 8_192;
const MAX_JSON_DEPTH = 16;
const MAX_JSON_NODES = 4_096;

export type BehavioralProbeStateId =
  | 'pending'
  | 'empty'
  | 'success'
  | 'failure'
  | 'cancelled'
  | 'unknown';

export type BehavioralProbeGateDecision = 'blocked' | 'blocked_live_compatibility';

export type BehavioralProbeJsonValue =
  | null
  | boolean
  | number
  | string
  | BehavioralProbeJsonValue[]
  | { [key: string]: BehavioralProbeJsonValue };

export interface BehavioralProbeCaseResult {
  readonly id: string;
  readonly observed: BehavioralProbeJsonValue;
}

export interface BehavioralProbeRequirementResult {
  readonly id: string;
  readonly passed: boolean;
}

export interface BehavioralProbeEvidence {
  readonly schema: typeof EVIDENCE_SCHEMA;
  readonly fixtureSchema: string;
  readonly contract: string;
  readonly hermesSourceSha: string;
  readonly routeManifestSha256: string;
  readonly syntheticOnly: true;
  readonly liveRun: false;
  readonly state: BehavioralProbeStateId;
  readonly caseResults: readonly BehavioralProbeCaseResult[];
  readonly requirementResults: readonly BehavioralProbeRequirementResult[];
}

export interface BehavioralProbeGateResult {
  readonly status: 'blocked';
  readonly state: BehavioralProbeStateId | 'incompatible';
  readonly evidenceState: string;
  readonly gateDecision: BehavioralProbeGateDecision;
  readonly safeState: string;
  readonly retryPolicy: string;
  readonly compatible: false;
  readonly liveRun: false;
  readonly fixtureValidated: boolean;
  readonly requiresSourceStateReread: boolean;
  readonly reason: 'fixture-state' | 'incompatible-evidence' | 'fixture-contract-invalid';
}

interface FixtureCase {
  readonly id: string;
  readonly expected: BehavioralProbeJsonValue;
}

interface FixtureState {
  readonly id: BehavioralProbeStateId;
  readonly evidenceState: string;
  readonly gateDecision: BehavioralProbeGateDecision;
  readonly safeState: string;
  readonly retryPolicy: string;
}

interface FixtureContract {
  readonly schema: string;
  readonly contract: string;
  readonly hermesSourceSha: string;
  readonly routeManifestSha256: string;
  readonly cases: readonly FixtureCase[];
  readonly requirements: readonly string[];
  readonly states: ReadonlyMap<BehavioralProbeStateId, FixtureState>;
}

const EVIDENCE_KEYS = [
  'schema',
  'fixtureSchema',
  'contract',
  'hermesSourceSha',
  'routeManifestSha256',
  'syntheticOnly',
  'liveRun',
  'state',
  'caseResults',
  'requirementResults'
] as const;

const STATE_IDS = new Set<BehavioralProbeStateId>([
  'pending',
  'empty',
  'success',
  'failure',
  'cancelled',
  'unknown'
]);

/**
 * Evaluates only checked-in synthetic evidence. This boundary intentionally has
 * no fetch, storage, WebSocket, credential, or retry side effect. Even a fully
 * matching synthetic fixture remains blocked from claiming live compatibility.
 */
export function evaluateBehavioralProbeGate(evidence: unknown): BehavioralProbeGateResult {
  const contract = readFixtureContract();
  if (!contract) {
    return incompatibleResult('fixture-contract-invalid');
  }

  try {
    const parsed = readEvidence(evidence, contract);
    if (!parsed) {
      return incompatibleResult('incompatible-evidence');
    }

    const state = contract.states.get(parsed.state);
    if (!state || !isStateEvidenceConsistent(parsed, contract)) {
      return incompatibleResult('incompatible-evidence');
    }

    return {
      status: 'blocked',
      state: state.id,
      evidenceState: state.evidenceState,
      gateDecision: state.gateDecision,
      safeState: state.safeState,
      retryPolicy: state.retryPolicy,
      compatible: false,
      liveRun: false,
      fixtureValidated: state.id === 'success',
      requiresSourceStateReread: state.retryPolicy.includes('source_state'),
      reason: 'fixture-state'
    };
  } catch {
    // Hostile proxies and throwing accessors are incompatible evidence too.
    return incompatibleResult('incompatible-evidence');
  }
}

/**
 * Builds named deterministic evidence for focused tests and offline prototypes.
 * It reproduces the canonical case inventory but never turns on a live claim.
 */
export function createBehavioralProbeFixtureEvidence(
  state: BehavioralProbeStateId
): BehavioralProbeEvidence {
  const contract = readFixtureContract();
  if (!contract) {
    throw new Error('The behavioral-probe fixture contract is invalid.');
  }

  const success = state === 'success';
  const failure = state === 'failure';

  return {
    schema: EVIDENCE_SCHEMA,
    fixtureSchema: contract.schema,
    contract: contract.contract,
    hermesSourceSha: contract.hermesSourceSha,
    routeManifestSha256: contract.routeManifestSha256,
    syntheticOnly: true,
    liveRun: false,
    state,
    caseResults: success
      ? contract.cases.map(({ id, expected }) => ({ id, observed: cloneJson(expected) }))
      : [],
    requirementResults: contract.requirements.map((id, index) => ({
      id,
      passed: success || (failure ? index !== 0 : false)
    }))
  };
}

function readFixtureContract(): FixtureContract | null {
  const fixture: unknown = behavioralProbeFixture;
  if (!isPlainObject(fixture) || !hasExactKeys(fixture, [
    'schema',
    'contract',
    'hermes_source_sha',
    'synthetic_only',
    'probe',
    'evidence_requirements',
    'route_manifest',
    'route_manifest_sha256',
    'attestation_observations',
    'proxy_matrix',
    'proxy_observations',
    'platform_observations',
    'pty_lifecycle',
    'cases',
    'probe_states',
    'redaction',
    'parity',
    'accessibility',
    'proof_run'
  ])) {
    return null;
  }

  if (
    fixture.schema !== FIXTURE_SCHEMA ||
    fixture.contract !== DASHBOARD_CONTRACT ||
    fixture.hermes_source_sha !== PINNED_HERMES_SOURCE_SHA ||
    fixture.synthetic_only !== true ||
    fixture.route_manifest_sha256 !== PINNED_ROUTE_MANIFEST_SHA256 ||
    !isSha256(fixture.route_manifest_sha256) ||
    !isPlainObject(fixture.probe) ||
    fixture.probe.live_run !== false ||
    fixture.probe.compatible !== false ||
    !Array.isArray(fixture.evidence_requirements) ||
    !Array.isArray(fixture.cases) ||
    !Array.isArray(fixture.probe_states)
  ) {
    return null;
  }

  const requirements = readUniqueIdentifiers(fixture.evidence_requirements);
  if (!requirements || requirements.length !== REQUIRED_REQUIREMENT_COUNT) {
    return null;
  }

  const cases: FixtureCase[] = [];
  const caseIds = new Set<string>();
  for (const candidate of fixture.cases) {
    if (
      !isPlainObject(candidate) ||
      !isIdentifier(candidate.id) ||
      candidate.synthetic !== true ||
      !('expected' in candidate) ||
      !isBoundedJson(candidate.expected) ||
      caseIds.has(candidate.id)
    ) {
      return null;
    }
    caseIds.add(candidate.id);
    cases.push({ id: candidate.id, expected: candidate.expected });
  }

  if (
    cases.length !== REQUIRED_CASE_COUNT ||
    fixture.probe.required_case_count !== cases.length ||
    fixture.probe.required_state_count !== fixture.probe_states.length
  ) {
    return null;
  }

  const states = new Map<BehavioralProbeStateId, FixtureState>();
  for (const candidate of fixture.probe_states) {
    if (
      !isPlainObject(candidate) ||
      !isStateId(candidate.id) ||
      typeof candidate.evidence_state !== 'string' ||
      !isGateDecision(candidate.gate_decision) ||
      typeof candidate.safe_state !== 'string' ||
      typeof candidate.retry_policy !== 'string' ||
      states.has(candidate.id)
    ) {
      return null;
    }
    states.set(candidate.id, {
      id: candidate.id,
      evidenceState: candidate.evidence_state,
      gateDecision: candidate.gate_decision,
      safeState: candidate.safe_state,
      retryPolicy: candidate.retry_policy
    });
  }

  if (states.size !== STATE_IDS.size || [...STATE_IDS].some((id) => !states.has(id))) {
    return null;
  }

  return {
    schema: fixture.schema,
    contract: fixture.contract,
    hermesSourceSha: fixture.hermes_source_sha,
    routeManifestSha256: fixture.route_manifest_sha256,
    cases,
    requirements,
    states
  };
}

function readEvidence(evidence: unknown, contract: FixtureContract): BehavioralProbeEvidence | null {
  if (!isPlainObject(evidence) || !hasExactKeys(evidence, EVIDENCE_KEYS)) {
    return null;
  }

  if (
    evidence.schema !== EVIDENCE_SCHEMA ||
    evidence.fixtureSchema !== contract.schema ||
    evidence.contract !== contract.contract ||
    evidence.hermesSourceSha !== contract.hermesSourceSha ||
    evidence.routeManifestSha256 !== contract.routeManifestSha256 ||
    evidence.syntheticOnly !== true ||
    evidence.liveRun !== false ||
    !isStateId(evidence.state) ||
    !Array.isArray(evidence.caseResults) ||
    !Array.isArray(evidence.requirementResults) ||
    evidence.caseResults.length > contract.cases.length ||
    evidence.requirementResults.length !== contract.requirements.length
  ) {
    return null;
  }

  const expectedCases = new Set(contract.cases.map(({ id }) => id));
  const seenCases = new Set<string>();
  for (const result of evidence.caseResults) {
    if (
      !isPlainObject(result) ||
      !hasExactKeys(result, ['id', 'observed']) ||
      !isIdentifier(result.id) ||
      !expectedCases.has(result.id) ||
      seenCases.has(result.id) ||
      !isBoundedJson(result.observed)
    ) {
      return null;
    }
    seenCases.add(result.id);
  }

  const seenRequirements = new Set<string>();
  for (const result of evidence.requirementResults) {
    if (
      !isPlainObject(result) ||
      !hasExactKeys(result, ['id', 'passed']) ||
      !isIdentifier(result.id) ||
      typeof result.passed !== 'boolean' ||
      !contract.requirements.includes(result.id) ||
      seenRequirements.has(result.id)
    ) {
      return null;
    }
    seenRequirements.add(result.id);
  }

  if (contract.requirements.some((id) => !seenRequirements.has(id))) {
    return null;
  }

  return evidence as unknown as BehavioralProbeEvidence;
}

function isStateEvidenceConsistent(
  evidence: BehavioralProbeEvidence,
  contract: FixtureContract
): boolean {
  const allRequirementsPass = evidence.requirementResults.every(({ passed }) => passed);
  const expectedById = new Map(contract.cases.map(({ id, expected }) => [id, expected]));
  const allCasesMatch =
    evidence.caseResults.length === contract.cases.length &&
    evidence.caseResults.every(({ id, observed }) => jsonEquals(observed, expectedById.get(id)));

  if (evidence.state === 'success') {
    return allRequirementsPass && allCasesMatch;
  }

  if (evidence.state === 'empty') {
    return evidence.caseResults.length === 0 && !allRequirementsPass;
  }

  if (evidence.state === 'failure') {
    return !allRequirementsPass || !allCasesMatch;
  }

  return !allRequirementsPass || !allCasesMatch;
}

function incompatibleResult(
  reason: 'incompatible-evidence' | 'fixture-contract-invalid'
): BehavioralProbeGateResult {
  // The result is deliberately bounded and never reflects untrusted evidence.
  return {
    status: 'blocked',
    state: 'incompatible',
    evidenceState: 'untrusted_or_malformed',
    gateDecision: 'blocked',
    safeState: 'no_success_claim',
    retryPolicy: 'reread_source_state_before_retry',
    compatible: false,
    liveRun: false,
    fixtureValidated: false,
    requiresSourceStateReread: true,
    reason
  };
}

function isStateId(value: unknown): value is BehavioralProbeStateId {
  return typeof value === 'string' && STATE_IDS.has(value as BehavioralProbeStateId);
}

function isGateDecision(value: unknown): value is BehavioralProbeGateDecision {
  return value === 'blocked' || value === 'blocked_live_compatibility';
}

function isIdentifier(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= MAX_IDENTIFIER_LENGTH &&
    /^[a-z0-9][a-z0-9._-]*$/u.test(value)
  );
}

function isSha256(value: string): boolean {
  return /^[a-f0-9]{64}$/u.test(value);
}

function readUniqueIdentifiers(value: readonly unknown[]): readonly string[] | null {
  const result: string[] = [];
  const seen = new Set<string>();
  for (const item of value) {
    if (!isIdentifier(item) || seen.has(item)) {
      return null;
    }
    seen.add(item);
    result.push(item);
  }
  return result;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === expected.length && expected.every((key) => actual.includes(key));
}

function isBoundedJson(value: unknown): value is BehavioralProbeJsonValue {
  let nodes = 0;
  const active = new Set<object>();

  function visit(candidate: unknown, depth: number): boolean {
    nodes += 1;
    if (nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH) {
      return false;
    }
    if (candidate === null || typeof candidate === 'boolean') {
      return true;
    }
    if (typeof candidate === 'number') {
      return Number.isFinite(candidate) && (!Number.isInteger(candidate) || Number.isSafeInteger(candidate));
    }
    if (typeof candidate === 'string') {
      return candidate.length <= MAX_STRING_LENGTH;
    }
    if (typeof candidate !== 'object' || active.has(candidate)) {
      return false;
    }

    active.add(candidate);
    let valid: boolean;
    if (Array.isArray(candidate)) {
      valid = candidate.length <= 500 && candidate.every((item) => visit(item, depth + 1));
    } else if (isPlainObject(candidate)) {
      const keys = Object.keys(candidate);
      valid =
        keys.length <= 64 &&
        keys.every((key) => key.length <= MAX_IDENTIFIER_LENGTH && visit(candidate[key], depth + 1));
    } else {
      valid = false;
    }
    active.delete(candidate);
    return valid;
  }

  return visit(value, 0);
}

function jsonEquals(left: BehavioralProbeJsonValue, right: BehavioralProbeJsonValue | undefined): boolean {
  if (right === undefined || typeof left !== typeof right || left === null || right === null) {
    return left === right;
  }
  if (typeof left !== 'object' || typeof right !== 'object') {
    return Object.is(left, right);
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    return (
      Array.isArray(left) &&
      Array.isArray(right) &&
      left.length === right.length &&
      left.every((item, index) => jsonEquals(item, right[index]))
    );
  }
  const leftKeys = Object.keys(left);
  const rightKeys = Object.keys(right);
  return (
    leftKeys.length === rightKeys.length &&
    leftKeys.every((key) => key in right && jsonEquals(left[key], right[key]))
  );
}

function cloneJson(value: BehavioralProbeJsonValue): BehavioralProbeJsonValue {
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(cloneJson);
  }
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, cloneJson(item)]));
}
