import behavioralProbeFixture from '../../../../../../contracts/fixtures/behavioral-probe/probe-fixtures.json';
import { CANONICAL_CASE_IDS, CANONICAL_REQUIREMENT_IDS } from './canonical-identities';
import { CANONICAL_ROUTE_MANIFEST_BYTES } from './canonical-route-manifest';

const EVIDENCE_SCHEMA = 'hermternal.web-behavioral-probe-evidence.v1';
const FIXTURE_SCHEMA = 'hermternal.behavioral-probe.v1';
const DASHBOARD_CONTRACT = 'dashboard-v0.0.1';
const PINNED_HERMES_SOURCE_SHA = 'f5be9236e00ddf2f2a412697f267078fc4ee068e';
const ROUTE_MANIFEST_PATH = 'contracts/hermes-dashboard/manifest.md';
const PINNED_ROUTE_MANIFEST_SHA256 =
  '0f2f1ea3af722cf2d14f6a43754a8430d20bae98d335b961c64b3f1229bd07c1';
const PINNED_FIXTURE_CANONICAL_SHA256 =
  '92d3fecf993cfba8071d9e3a58070d0a944cc840f6eea56516324e30d1776baa';
const MAX_IDENTIFIER_LENGTH = 128;
const MAX_STRING_UTF8_BYTES = 8_192;
const MAX_TOTAL_STRING_UTF8_BYTES = 131_072;
const MAX_EVIDENCE_UTF8_BYTES = 262_144;
const MAX_CANONICAL_OUTPUT_UTF8_BYTES = 262_144;
const MAX_JSON_DEPTH = 24;
const MAX_EVIDENCE_JSON_NODES = 4_096;
const MAX_FIXTURE_JSON_NODES = 32_768;
const MAX_ARRAY_ITEMS = 500;
const MAX_OBJECT_KEYS = 128;
const MAX_NUMBER_TOKEN_LENGTH = 64;

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
  'caseResults', 'contract', 'fixtureSchema', 'hermesSourceSha', 'liveRun',
  'requirementResults', 'routeManifestSha256', 'schema', 'state', 'syntheticOnly'
] as const;
const FIXTURE_KEYS = [
  'schema', 'contract', 'hermes_source_sha', 'route_manifest', 'route_manifest_sha256',
  'synthetic_only', 'probe', 'proof_run', 'evidence_requirements',
  'attestation_observations', 'proxy_observations', 'platform_observations',
  'proxy_matrix', 'parity', 'probe_states', 'pty_lifecycle', 'cases',
  'redaction', 'accessibility'
] as const;
const STATE_IDS = new Set<BehavioralProbeStateId>([
  'pending', 'empty', 'success', 'failure', 'cancelled', 'unknown'
]);

/**
 * Evaluates canonical JSON text only. Rejecting every object before parsing is
 * the trust boundary: an attacker-controlled Proxy never reaches reflection,
 * getters, iteration, or any other executable object hook on this thread.
 */
export function evaluateBehavioralProbeGate(evidenceJson: unknown): BehavioralProbeGateResult {
  if (typeof evidenceJson !== 'string' || evidenceJson.length > MAX_EVIDENCE_UTF8_BYTES) {
    return incompatibleResult('incompatible-evidence');
  }
  const contract = readFixtureContract(behavioralProbeFixture, CANONICAL_ROUTE_MANIFEST_BYTES);
  if (!contract) return incompatibleResult('fixture-contract-invalid');

  try {
    const parsed = readEvidence(parseCanonicalEvidenceJson(evidenceJson), contract);
    if (!parsed) return incompatibleResult('incompatible-evidence');
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
    return incompatibleResult('incompatible-evidence');
  }
}

/** Builds canonical serialized test evidence; it never represents a live probe. */
export function createBehavioralProbeFixtureEvidence(state: BehavioralProbeStateId): string {
  const contract = readFixtureContract(behavioralProbeFixture, CANONICAL_ROUTE_MANIFEST_BYTES);
  if (!contract) throw new Error('The behavioral-probe fixture contract is invalid.');
  const success = state === 'success';
  const failure = state === 'failure';
  const evidence: BehavioralProbeEvidence = {
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
  return canonicalJson(evidence as unknown as BehavioralProbeJsonValue);
}

/** @internal Digest seam for canonical contract regression tests only. */
export function behavioralProbeFixtureDigestForTest(fixture: unknown): string {
  return sha256(JSON.stringify(snapshotJson(fixture, MAX_FIXTURE_JSON_NODES)));
}

/** @internal Mutation seam for contract-drift regression tests only. */
export function validateBehavioralProbeFixtureForTest(
  fixture: unknown,
  manifestBytes: string
): boolean {
  return readFixtureContract(fixture, manifestBytes) !== null;
}

function readFixtureContract(fixtureInput: unknown, manifestBytes: string): FixtureContract | null {
  try {
    const snapshot = snapshotJson(fixtureInput, MAX_FIXTURE_JSON_NODES);
    if (!isRecord(snapshot) || !hasExactDataKeys(snapshot, FIXTURE_KEYS)) return null;
    // The full canonical digest independently pins ordered request, kind,
    // surface, expected, state, proxy, parity, and redaction semantics.
    if (sha256(JSON.stringify(snapshot)) !== PINNED_FIXTURE_CANONICAL_SHA256) return null;
    if (sha256(manifestBytes) !== PINNED_ROUTE_MANIFEST_SHA256) return null;
    if (
      snapshot.schema !== FIXTURE_SCHEMA || snapshot.contract !== DASHBOARD_CONTRACT ||
      snapshot.hermes_source_sha !== PINNED_HERMES_SOURCE_SHA || snapshot.synthetic_only !== true ||
      snapshot.route_manifest !== ROUTE_MANIFEST_PATH ||
      snapshot.route_manifest_sha256 !== PINNED_ROUTE_MANIFEST_SHA256
    ) return null;

    const requirementsValue = snapshot.evidence_requirements;
    const casesValue = snapshot.cases;
    const statesValue = snapshot.probe_states;
    const probe = snapshot.probe;
    if (!Array.isArray(requirementsValue) || !Array.isArray(casesValue) ||
        !Array.isArray(statesValue) || !isRecord(probe) ||
        probe.live_run !== false || probe.compatible !== false) return null;

    const requirements = readOrderedIdentifiers(requirementsValue, CANONICAL_REQUIREMENT_IDS);
    if (!requirements || casesValue.length !== CANONICAL_CASE_IDS.length) return null;
    const cases: FixtureCase[] = [];
    for (let index = 0; index < CANONICAL_CASE_IDS.length; index += 1) {
      const candidate = casesValue[index];
      if (!isRecord(candidate) || candidate.id !== CANONICAL_CASE_IDS[index] ||
          candidate.synthetic !== true || !isJsonValue(candidate.expected)) return null;
      cases.push({ id: CANONICAL_CASE_IDS[index], expected: candidate.expected });
    }
    if (probe.required_case_count !== CANONICAL_CASE_IDS.length ||
        probe.required_state_count !== STATE_IDS.size) return null;

    const states = new Map<BehavioralProbeStateId, FixtureState>();
    for (const candidate of statesValue) {
      if (!isRecord(candidate) || !isStateId(candidate.id) ||
          typeof candidate.evidence_state !== 'string' || !isGateDecision(candidate.gate_decision) ||
          typeof candidate.safe_state !== 'string' || typeof candidate.retry_policy !== 'string' ||
          states.has(candidate.id)) return null;
      states.set(candidate.id, {
        id: candidate.id, evidenceState: candidate.evidence_state,
        gateDecision: candidate.gate_decision, safeState: candidate.safe_state,
        retryPolicy: candidate.retry_policy
      });
    }
    if (states.size !== STATE_IDS.size || [...STATE_IDS].some((id) => !states.has(id))) return null;
    return {
      schema: FIXTURE_SCHEMA, contract: DASHBOARD_CONTRACT,
      hermesSourceSha: PINNED_HERMES_SOURCE_SHA,
      routeManifestSha256: PINNED_ROUTE_MANIFEST_SHA256,
      cases: Object.freeze(cases), requirements, states
    };
  } catch {
    return null;
  }
}

function readEvidence(snapshot: BehavioralProbeJsonValue, contract: FixtureContract): BehavioralProbeEvidence | null {
  if (!isRecord(snapshot) || !hasExactDataKeys(snapshot, EVIDENCE_KEYS)) return null;
  const caseResults = snapshot.caseResults;
  const requirementResults = snapshot.requirementResults;
  if (
    snapshot.schema !== EVIDENCE_SCHEMA || snapshot.fixtureSchema !== contract.schema ||
    snapshot.contract !== contract.contract || snapshot.hermesSourceSha !== contract.hermesSourceSha ||
    snapshot.routeManifestSha256 !== contract.routeManifestSha256 || snapshot.syntheticOnly !== true ||
    snapshot.liveRun !== false || !isStateId(snapshot.state) || !Array.isArray(caseResults) ||
    !Array.isArray(requirementResults) || caseResults.length > contract.cases.length ||
    requirementResults.length !== contract.requirements.length
  ) return null;

  const parsedCases: BehavioralProbeCaseResult[] = [];
  for (let index = 0; index < caseResults.length; index += 1) {
    const result = caseResults[index];
    const expected = contract.cases[index];
    if (!result || !expected || !isRecord(result) ||
        !hasExactDataKeys(result, ['id', 'observed']) ||
        result.id !== expected.id || !isIdentifier(result.id) ||
        !isJsonValue(result.observed)) return null;
    parsedCases.push({ id: result.id, observed: result.observed });
  }

  const parsedRequirements: BehavioralProbeRequirementResult[] = [];
  for (let index = 0; index < requirementResults.length; index += 1) {
    const result = requirementResults[index];
    const expectedId = contract.requirements[index];
    if (!result || expectedId === undefined || !isRecord(result) ||
        !hasExactDataKeys(result, ['id', 'passed']) || result.id !== expectedId ||
        !isIdentifier(result.id) || typeof result.passed !== 'boolean') return null;
    parsedRequirements.push({ id: result.id, passed: result.passed });
  }
  return Object.freeze({
    schema: EVIDENCE_SCHEMA,
    fixtureSchema: contract.schema,
    contract: contract.contract,
    hermesSourceSha: contract.hermesSourceSha,
    routeManifestSha256: contract.routeManifestSha256,
    syntheticOnly: true,
    liveRun: false,
    state: snapshot.state,
    caseResults: Object.freeze(parsedCases),
    requirementResults: Object.freeze(parsedRequirements)
  });
}

function isStateEvidenceConsistent(evidence: BehavioralProbeEvidence, contract: FixtureContract): boolean {
  const allRequirementsPass = evidence.requirementResults.every(({ passed }) => passed);
  const expectedById = new Map(contract.cases.map(({ id, expected }) => [id, expected]));
  const allCasesMatch = evidence.caseResults.length === contract.cases.length &&
    evidence.caseResults.every(({ id, observed }) => jsonEquals(observed, expectedById.get(id)));
  if (evidence.state === 'success') return allRequirementsPass && allCasesMatch;
  if (evidence.state === 'empty') return evidence.caseResults.length === 0 && !allRequirementsPass;
  if (evidence.state === 'failure') return !allRequirementsPass || !allCasesMatch;
  return !allRequirementsPass || !allCasesMatch;
}

function incompatibleResult(reason: 'incompatible-evidence' | 'fixture-contract-invalid'): BehavioralProbeGateResult {
  return {
    status: 'blocked', state: 'incompatible', evidenceState: 'untrusted_or_malformed',
    gateDecision: 'blocked', safeState: 'no_success_claim',
    retryPolicy: 'reread_source_state_before_retry', compatible: false, liveRun: false,
    fixtureValidated: false, requiresSourceStateReread: true, reason
  };
}

function parseCanonicalEvidenceJson(input: string): BehavioralProbeJsonValue {
  if (utf8Length(input, MAX_EVIDENCE_UTF8_BYTES) > MAX_EVIDENCE_UTF8_BYTES) {
    throw new TypeError('invalid evidence');
  }
  let offset = 0;
  let nodes = 0;
  let totalStringBytes = 0;

  function fail(): never {
    throw new TypeError('invalid evidence');
  }
  function addNode(depth: number): void {
    nodes += 1;
    if (nodes > MAX_EVIDENCE_JSON_NODES || depth > MAX_JSON_DEPTH) fail();
  }
  function parseValue(depth: number): BehavioralProbeJsonValue {
    addNode(depth);
    const token = input[offset];
    if (token === 'n' && input.slice(offset, offset + 4) === 'null') {
      offset += 4;
      return null;
    }
    if (token === 't' && input.slice(offset, offset + 4) === 'true') {
      offset += 4;
      return true;
    }
    if (token === 'f' && input.slice(offset, offset + 5) === 'false') {
      offset += 5;
      return false;
    }
    if (token === '"') return parseString();
    if (token === '[') return parseArray(depth);
    if (token === '{') return parseObject(depth);
    return parseNumber();
  }
  function parseString(): string {
    if (input[offset] !== '"') fail();
    const start = offset;
    offset += 1;
    while (offset < input.length) {
      const code = input.charCodeAt(offset);
      if (code === 0x22) {
        offset += 1;
        let value: unknown;
        try {
          value = JSON.parse(input.slice(start, offset));
        } catch {
          fail();
        }
        if (typeof value !== 'string' || hasLoneSurrogate(value)) fail();
        const bytes = utf8Length(value, MAX_STRING_UTF8_BYTES);
        if (bytes > MAX_STRING_UTF8_BYTES) fail();
        totalStringBytes += bytes;
        if (totalStringBytes > MAX_TOTAL_STRING_UTF8_BYTES) fail();
        return value;
      }
      if (code < 0x20) fail();
      if (code === 0x5c) {
        offset += 1;
        const escape = input[offset];
        if (escape === 'u') {
          for (let index = 1; index <= 4; index += 1) {
            if (!/[0-9a-fA-F]/u.test(input[offset + index] ?? '')) fail();
          }
          offset += 5;
          continue;
        }
        if (!escape || !'"\\/bfnrt'.includes(escape)) fail();
      }
      offset += 1;
    }
    return fail();
  }
  function parseArray(depth: number): BehavioralProbeJsonValue[] {
    offset += 1;
    const result: BehavioralProbeJsonValue[] = [];
    if (input[offset] === ']') {
      offset += 1;
      return Object.freeze(result) as unknown as BehavioralProbeJsonValue[];
    }
    while (true) {
      if (result.length >= MAX_ARRAY_ITEMS) fail();
      result.push(parseValue(depth + 1));
      const separator = input[offset];
      if (separator === ']') {
        offset += 1;
        return Object.freeze(result) as unknown as BehavioralProbeJsonValue[];
      }
      if (separator !== ',') fail();
      offset += 1;
    }
  }
  function parseObject(depth: number): { [key: string]: BehavioralProbeJsonValue } {
    offset += 1;
    const result: Record<string, BehavioralProbeJsonValue> = Object.create(null);
    let previousKey: string | undefined;
    let keyCount = 0;
    if (input[offset] === '}') {
      offset += 1;
      return Object.freeze(result);
    }
    while (true) {
      if (keyCount >= MAX_OBJECT_KEYS) fail();
      const key = parseString();
      if (previousKey !== undefined && key <= previousKey) fail();
      previousKey = key;
      if (input[offset] !== ':') fail();
      offset += 1;
      result[key] = parseValue(depth + 1);
      keyCount += 1;
      const separator = input[offset];
      if (separator === '}') {
        offset += 1;
        return Object.freeze(result);
      }
      if (separator !== ',') fail();
      offset += 1;
    }
  }
  function parseNumber(): number {
    const remainder = input.slice(offset);
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u.exec(remainder);
    const token = match?.[0];
    if (!token || token.length > MAX_NUMBER_TOKEN_LENGTH) fail();
    offset += token.length;
    const value = Number(token);
    if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) fail();
    if (JSON.stringify(value) !== token) fail();
    return value;
  }

  const parsed = parseValue(0);
  if (offset !== input.length) fail();
  if (canonicalJson(parsed) !== input) fail();
  return parsed;
}

function canonicalJson(value: BehavioralProbeJsonValue): string {
  function serialize(candidate: BehavioralProbeJsonValue): string {
    if (candidate === null || typeof candidate !== 'object') return JSON.stringify(candidate);
    if (Array.isArray(candidate)) return `[${candidate.map(serialize).join(',')}]`;
    return `{${Object.keys(candidate).sort().map((key) =>
      `${JSON.stringify(key)}:${serialize(candidate[key]!)}`
    ).join(',')}}`;
  }
  const result = serialize(value);
  if (utf8Length(result, MAX_CANONICAL_OUTPUT_UTF8_BYTES) > MAX_CANONICAL_OUTPUT_UTF8_BYTES) {
    throw new TypeError('invalid evidence');
  }
  return result;
}

function utf8Length(value: string, stopAfter: number): number {
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x80) bytes += 1;
    else if (code < 0x800) bytes += 2;
    else if (code >= 0xd800 && code <= 0xdbff && index + 1 < value.length &&
      value.charCodeAt(index + 1) >= 0xdc00 && value.charCodeAt(index + 1) <= 0xdfff) {
      bytes += 4;
      index += 1;
    } else bytes += 3;
    if (bytes > stopAfter) return bytes;
  }
  return bytes;
}

function hasLoneSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) return true;
  }
  return false;
}

function snapshotJson(value: unknown, maxNodes: number): BehavioralProbeJsonValue {
  let nodes = 0;
  const active = new Set<object>();
  function visit(candidate: unknown, depth: number): BehavioralProbeJsonValue {
    nodes += 1;
    if (nodes > maxNodes || depth > MAX_JSON_DEPTH) throw new TypeError('invalid evidence');
    if (candidate === null || typeof candidate === 'boolean') return candidate;
    if (typeof candidate === 'number') {
      if (!Number.isFinite(candidate) || (Number.isInteger(candidate) && !Number.isSafeInteger(candidate))) {
        throw new TypeError('invalid evidence');
      }
      return candidate;
    }
    if (typeof candidate === 'string') {
      if (utf8Length(candidate, MAX_STRING_UTF8_BYTES) > MAX_STRING_UTF8_BYTES) throw new TypeError('invalid evidence');
      return candidate;
    }
    if (typeof candidate !== 'object' || active.has(candidate)) throw new TypeError('invalid evidence');
    active.add(candidate);
    try {
      if (Array.isArray(candidate)) {
        // Never read through the array object. A proxy can make `length`,
        // `keys`, or iteration stateful; one own data descriptor provides the
        // bounded inventory without invoking getters or array methods.
        const lengthDescriptor = Object.getOwnPropertyDescriptor(candidate, 'length');
        if (!lengthDescriptor || !('value' in lengthDescriptor) ||
            lengthDescriptor.enumerable !== false ||
            !Number.isSafeInteger(lengthDescriptor.value) ||
            lengthDescriptor.value < 0 || lengthDescriptor.value > MAX_ARRAY_ITEMS) {
          throw new TypeError('invalid evidence');
        }
        const length = lengthDescriptor.value;
        const keys = Reflect.ownKeys(candidate);
        if (keys.length !== length + 1 || keys[length] !== 'length') {
          throw new TypeError('invalid evidence');
        }
        const result: BehavioralProbeJsonValue[] = [];
        for (let index = 0; index < length; index += 1) {
          const key = String(index);
          if (keys[index] !== key) throw new TypeError('invalid evidence');
          const descriptor = Object.getOwnPropertyDescriptor(candidate, key);
          if (!descriptor || !('value' in descriptor) || descriptor.enumerable !== true) {
            throw new TypeError('invalid evidence');
          }
          result.push(visit(descriptor.value, depth + 1));
        }
        return Object.freeze(result) as unknown as BehavioralProbeJsonValue[];
      }
      if (!isPlainPrototype(candidate)) throw new TypeError('invalid evidence');
      const keys = Reflect.ownKeys(candidate);
      if (keys.length > 128 || keys.some((key) => typeof key !== 'string')) throw new TypeError('invalid evidence');
      const result: Record<string, BehavioralProbeJsonValue> = Object.create(null);
      for (const key of keys as string[]) {
        if (key.length > MAX_IDENTIFIER_LENGTH) throw new TypeError('invalid evidence');
        const descriptor = Object.getOwnPropertyDescriptor(candidate, key);
        if (!descriptor || !('value' in descriptor) || descriptor.enumerable !== true) {
          throw new TypeError('invalid evidence');
        }
        result[key] = visit(descriptor.value, depth + 1);
      }
      return Object.freeze(result);
    } finally {
      active.delete(candidate);
    }
  }
  return visit(value, 0);
}

function hasExactDataKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Reflect.ownKeys(value);
  if (keys.length !== expected.length) return false;
  for (let index = 0; index < expected.length; index += 1) {
    if (keys[index] !== expected[index]) return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, expected[index]);
    if (!descriptor || !('value' in descriptor) || descriptor.enumerable !== true) return false;
  }
  return true;
}

function readOrderedIdentifiers(value: readonly unknown[], expected: readonly string[]): readonly string[] | null {
  if (value.length !== expected.length) return null;
  const result: string[] = [];
  for (let index = 0; index < expected.length; index += 1) {
    const item = value[index];
    if (item !== expected[index] || !isIdentifier(item)) return null;
    result.push(item);
  }
  return Object.freeze(result);
}

function isRecord(value: BehavioralProbeJsonValue): value is { [key: string]: BehavioralProbeJsonValue } {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function isPlainPrototype(value: object): boolean {
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
function isJsonValue(value: unknown): value is BehavioralProbeJsonValue {
  return value === null || typeof value === 'boolean' || typeof value === 'string' ||
    (typeof value === 'number' && Number.isFinite(value)) || Array.isArray(value) || isPlainPrototype(value as object);
}
function isStateId(value: unknown): value is BehavioralProbeStateId {
  return typeof value === 'string' && STATE_IDS.has(value as BehavioralProbeStateId);
}
function isGateDecision(value: unknown): value is BehavioralProbeGateDecision {
  return value === 'blocked' || value === 'blocked_live_compatibility';
}
function isIdentifier(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_IDENTIFIER_LENGTH &&
    /^[a-z0-9][a-z0-9._-]*$/u.test(value);
}

function jsonEquals(left: BehavioralProbeJsonValue, right: BehavioralProbeJsonValue | undefined): boolean {
  if (right === undefined || typeof left !== typeof right || left === null || right === null) return left === right;
  if (typeof left !== 'object' || typeof right !== 'object') return Object.is(left, right);
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left) && Array.isArray(right) && left.length === right.length &&
      left.every((item, index) => jsonEquals(item, right[index]));
  }
  const leftKeys = Object.keys(left);
  const rightKeys = Object.keys(right);
  return leftKeys.length === rightKeys.length &&
    leftKeys.every((key) => Object.hasOwn(right, key) && jsonEquals(left[key], right[key]));
}
function cloneJson(value: BehavioralProbeJsonValue): BehavioralProbeJsonValue {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(cloneJson);
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, cloneJson(item)]));
}

// Synchronous SHA-256 keeps this pure gate usable before any asynchronous
// connection work and avoids a Node-only crypto dependency in the web bundle.
export function sha256ForTest(input: string): string {
  return sha256(input);
}

function sha256(input: string): string {
  const bytes = new TextEncoder().encode(input);
  const bitLength = bytes.length * 8;
  const paddedLength = Math.ceil((bytes.length + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLength);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(paddedLength - 4, bitLength >>> 0, false);
  view.setUint32(paddedLength - 8, Math.floor(bitLength / 0x1_0000_0000), false);
  const h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ]);
  const k = SHA256_K;
  const w = new Uint32Array(64);
  for (let offset = 0; offset < paddedLength; offset += 64) {
    for (let i = 0; i < 16; i += 1) w[i] = view.getUint32(offset + i * 4, false);
    for (let i = 16; i < 64; i += 1) {
      const s0 = rotateRight(w[i - 15], 7) ^ rotateRight(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotateRight(w[i - 2], 17) ^ rotateRight(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i += 1) {
      const s1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + s1 + ch + k[i] + w[i]) >>> 0;
      const s0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (s0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }
  return [...h].map((value) => value.toString(16).padStart(8, '0')).join('');
}
function rotateRight(value: number, count: number): number {
  return (value >>> count) | (value << (32 - count));
}
const SHA256_K = new Uint32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]);
