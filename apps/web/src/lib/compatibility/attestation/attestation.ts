import {
  createJsonRpcChatTransport,
  type JsonRpcChatOptions,
  type JsonRpcChatTransport,
  type JsonRpcCompatibilityGate
} from '../../chat/json-rpc-chat';
import { parseStrictJson } from '../../transport/strict-json';

export const REVISION_ATTESTATION_SCHEMA = 'hermternal.revision-attestation.v1' as const;
export const PINNED_DASHBOARD_CONTRACT = 'dashboard-v0.0.1' as const;
export const PINNED_HERMES_SOURCE_SHA = 'f5be9236e00ddf2f2a412697f267078fc4ee068e' as const;
export const PINNED_DEPLOYMENT_IDENTITY = 'synthetic-deployment-001' as const;
export const PINNED_TRUST_CHANNEL = 'release-channel' as const;
export const PINNED_DEPLOYMENT_SCOPE = 'fixture_only' as const;

const EXPECTED_ROUTE_MANIFEST = {
  path: 'contracts/hermes-dashboard/manifest.md',
  contractRevision: PINNED_DASHBOARD_CONTRACT,
  sha256: '680e1ef387c403538a8fa0959243f7414ad12c4d33cecae4fb1081a509c3f1b5',
  sizeBytes: 18_163
} as const;
const EXPECTED_SOURCE_REVIEW = {
  path: 'contracts/fixtures/source-audit/planning-reconciliation/planning_review.json',
  sha256: '0a84cba82e6e966ab35de187f560fd38d6e10c43dd2204062d6ebf2bc5c32077',
  sizeBytes: 20_045
} as const;
const EXPECTED_PROXY_PROOF = {
  path: 'docs/deployment/proof-matrix.md',
  sha256: '99945f3193f5ea9aa72c00c786d4c447c117774803ac036b1617575f0da8944d',
  sizeBytes: 18_047
} as const;

const ROOT_KEYS = [
  'schema',
  'operation',
  'contract',
  'hermes',
  'deployment',
  'route_manifest',
  'source_review',
  'proxy_proof',
  'dashboard_metadata',
  'requirements',
  'redaction'
] as const;
const HERMES_KEYS = ['repository', 'source_sha'] as const;
const DEPLOYMENT_KEYS = ['identity', 'trust_channel', 'scope'] as const;
const ROUTE_MANIFEST_KEYS = ['path', 'contract_revision', 'sha256', 'size_bytes'] as const;
const ARTIFACT_KEYS = ['path', 'sha256', 'size_bytes'] as const;
const DASHBOARD_METADATA_KEYS = [
  'source_revision_observable',
  'stable_wire_version_observable',
  'blocked_ssh_ownership_version_is_evidence'
] as const;
const REQUIREMENT_KEYS = [
  'full_source_sha_required',
  'unknown_revision_policy',
  'behavioral_probe_required_before_live_operation',
  'attestation_alone_enables_live_operation'
] as const;
const REDACTION_KEYS = [
  'synthetic_only',
  'contains_credentials',
  'contains_hosts',
  'contains_auth_material',
  'contains_raw_tickets',
  'contains_prompts',
  'contains_transcripts',
  'contains_user_data'
] as const;
const TRUST_KEYS = ['status', 'channel', 'deploymentIdentity', 'scope'] as const;
const RUNTIME_ROOT_KEYS = [
  'contract',
  'hermesSourceSha',
  'websocketPath',
  'deployment',
  'routeManifest',
  'sourceReview',
  'proxyProof',
  'gatewayReadyPayload'
] as const;
const RUNTIME_DEPLOYMENT_KEYS = ['identity', 'trustChannel', 'scope'] as const;
const RUNTIME_ROUTE_KEYS = ['path', 'revision', 'sha256', 'sizeBytes'] as const;
const RUNTIME_ARTIFACT_KEYS = ['path', 'sha256', 'sizeBytes'] as const;
const PROHIBITED_SERVER_METADATA_KEYS = new Set([
  'dashboard_protocol_version',
  'protocol_version',
  'server_source_sha',
  'source_sha_from_response',
  'revision_from_response'
]);

const MAX_ATTESTATION_CODE_UNITS = 16 * 1024;
const MAX_ATTESTATION_UTF8_BYTES = 32 * 1024;
const MAX_EVIDENCE_NODES = 1_024;
const MAX_EVIDENCE_DEPTH = 16;
const MAX_EVIDENCE_ARRAY_LENGTH = 1_024;
const MAX_EVIDENCE_OBJECT_KEYS = 64;
const MAX_EVIDENCE_STRING_CODE_UNITS = 8 * 1024;
const MAX_EVIDENCE_TOTAL_CODE_UNITS = 64 * 1024;
const MAX_EVIDENCE_TOTAL_UTF8_BYTES = 128 * 1024;

const behavioralProbeMarker: unique symbol = Symbol('behavioral-probe');
const trustedContexts = new WeakSet<object>();
const attestationCallbacks = new WeakSet<JsonRpcCompatibilityGate>();
const behavioralProbeCallbacks = new WeakMap<object, JsonRpcCompatibilityGate>();
const pairedAttestationGates = new WeakSet<object>();
const pairedBehavioralProbeGates = new WeakSet<object>();

type RecordValue = Record<string, unknown>;
type SnapshotValue = null | boolean | number | string | SnapshotValue[] | RecordValue;

export interface AttestationTrustContext {
  readonly status: 'trusted';
  readonly channel: typeof PINNED_TRUST_CHANNEL;
  readonly deploymentIdentity: typeof PINNED_DEPLOYMENT_IDENTITY;
  readonly scope: typeof PINNED_DEPLOYMENT_SCOPE;
}

export interface BehavioralProbeGate {
  readonly kind: 'behavioral-probe';
  readonly [behavioralProbeMarker]: true;
}

export type CompatibilityTransportOptions = Omit<
  JsonRpcChatOptions,
  'verifyAttestation' | 'runBehavioralProbe'
> & {
  readonly verifyAttestation?: never;
  readonly runBehavioralProbe?: never;
};

export interface CompatibilityTransportFactory {
  readonly kind: 'compatibility-transport-factory';
  createTransport(options: CompatibilityTransportOptions): JsonRpcChatTransport;
}

export interface CompatibilityAttestationGate {
  readonly kind: 'compatibility-attestation';
  pairWithBehavioralProbe(probe: BehavioralProbeGate): CompatibilityTransportFactory;
}

export type AttestationDecisionCode =
  | 'verified'
  | 'aborted'
  | 'missing'
  | 'empty'
  | 'malformed'
  | 'untrusted-source'
  | 'unsupported-schema'
  | 'unsupported-contract'
  | 'revision-mismatch'
  | 'evidence-mismatch'
  | 'server-metadata-rejected';

export type AttestationDecision =
  | { readonly passed: true; readonly code: 'verified' }
  | {
      readonly passed: false;
      readonly code: Exclude<AttestationDecisionCode, 'verified'>;
    };

interface SnapshotBudget {
  nodes: number;
  codeUnits: number;
  utf8Bytes: number;
}

interface SnapshotTask {
  readonly source: object;
  readonly target: SnapshotValue[] | RecordValue;
  readonly depth: number;
  readonly arrayLength?: number;
}

function blocked(code: Exclude<AttestationDecisionCode, 'verified'>): AttestationDecision {
  return Object.freeze({ passed: false, code });
}

function utf8ByteLengthBounded(value: string, maximum: number): number | undefined {
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x7f) bytes += 1;
    else if (code <= 0x7ff) bytes += 2;
    else if (code >= 0xd800 && code <= 0xdbff && index + 1 < value.length) {
      const following = value.charCodeAt(index + 1);
      if (following >= 0xdc00 && following <= 0xdfff) {
        bytes += 4;
        index += 1;
      } else bytes += 3;
    } else bytes += 3;
    if (bytes > maximum) return undefined;
  }
  return bytes;
}

function consumeString(value: string, budget: SnapshotBudget): boolean {
  if (value.length > MAX_EVIDENCE_STRING_CODE_UNITS) return false;
  budget.codeUnits += value.length;
  if (budget.codeUnits > MAX_EVIDENCE_TOTAL_CODE_UNITS) return false;
  const remaining = MAX_EVIDENCE_TOTAL_UTF8_BYTES - budget.utf8Bytes;
  const bytes = utf8ByteLengthBounded(value, remaining);
  if (bytes === undefined) return false;
  budget.utf8Bytes += bytes;
  return true;
}

function primitiveSnapshot(value: unknown, budget: SnapshotBudget): SnapshotValue | undefined {
  budget.nodes += 1;
  if (budget.nodes > MAX_EVIDENCE_NODES) return undefined;
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number') return Number.isFinite(value) ? value : undefined;
  if (typeof value === 'string') return consumeString(value, budget) ? value : undefined;
  return undefined;
}

/**
 * Copies untrusted evidence using descriptors only. Accessors, symbols,
 * non-enumerable object fields, exotic prototypes, cycles, and oversized data
 * are rejected before validation so later checks read an inert snapshot.
 */
function snapshotBoundedValue(input: unknown): SnapshotValue | undefined {
  const budget: SnapshotBudget = { nodes: 0, codeUnits: 0, utf8Bytes: 0 };
  const seen = new WeakSet<object>();

  const createContainer = (
    value: unknown
  ): Pick<SnapshotTask, 'target' | 'arrayLength'> | undefined => {
    if (typeof value !== 'object' || value === null) return undefined;
    budget.nodes += 1;
    if (budget.nodes > MAX_EVIDENCE_NODES || seen.has(value)) return undefined;
    seen.add(value);
    if (Array.isArray(value)) {
      const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
      if (
        !lengthDescriptor ||
        !('value' in lengthDescriptor) ||
        !Number.isSafeInteger(lengthDescriptor.value) ||
        lengthDescriptor.value < 0 ||
        lengthDescriptor.value > MAX_EVIDENCE_ARRAY_LENGTH
      )
        return undefined;
      // Retain the validated descriptor value so traversal never reads
      // `source.length` and cannot invoke a Proxy get trap.
      const arrayLength = lengthDescriptor.value as number;
      return {
        target: new Array(arrayLength) as SnapshotValue[],
        arrayLength
      };
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return undefined;
    return { target: Object.create(null) as RecordValue };
  };

  try {
    const primitive = primitiveSnapshot(input, budget);
    if (primitive !== undefined || input === null) return primitive;
    const root = createContainer(input);
    if (!root) return undefined;
    const tasks: SnapshotTask[] = [{ source: input as object, ...root, depth: 0 }];

    while (tasks.length > 0) {
      const task = tasks.pop();
      if (!task || task.depth > MAX_EVIDENCE_DEPTH) return undefined;
      const keys = Reflect.ownKeys(task.source);
      if (task.arrayLength !== undefined) {
        if (keys.length !== task.arrayLength + 1 || keys.at(-1) !== 'length') return undefined;
      } else if (keys.length > MAX_EVIDENCE_OBJECT_KEYS) return undefined;

      let arrayIndex = 0;
      for (const key of keys) {
        if (task.arrayLength !== undefined && key === 'length') continue;
        if (typeof key !== 'string') return undefined;
        if (task.arrayLength !== undefined && key !== String(arrayIndex)) return undefined;
        const descriptor = Object.getOwnPropertyDescriptor(task.source, key);
        if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) return undefined;
        if (!consumeString(key, budget)) return undefined;

        const childPrimitive = primitiveSnapshot(descriptor.value, budget);
        if (childPrimitive !== undefined || descriptor.value === null) {
          (task.target as RecordValue)[key] = childPrimitive;
        } else {
          const child = createContainer(descriptor.value);
          if (!child) return undefined;
          (task.target as RecordValue)[key] = child.target;
          tasks.push({
            source: descriptor.value as object,
            ...child,
            depth: task.depth + 1
          });
        }
        arrayIndex += 1;
      }
    }
    return root.target;
  } catch {
    // Proxies and hostile descriptor traps are untrusted evidence, not errors
    // that may escape the compatibility boundary.
    return undefined;
  }
}

function asRecord(value: unknown): RecordValue | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as RecordValue)
    : undefined;
}

function exactRecord(
  value: unknown,
  expected: readonly string[],
  ordered = false
): RecordValue | undefined {
  const record = asRecord(value);
  if (!record) return undefined;
  const keys = Object.keys(record);
  if (keys.length !== expected.length) return undefined;
  if (ordered) return expected.every((key, index) => keys[index] === key) ? record : undefined;
  return expected.every((key) => Object.hasOwn(record, key)) ? record : undefined;
}

function matchesArtifact(
  value: unknown,
  expected: {
    readonly path: string;
    readonly sha256: string;
    readonly sizeBytes: number;
  },
  route = false
): boolean {
  const record = exactRecord(value, route ? ROUTE_MANIFEST_KEYS : ARTIFACT_KEYS, true);
  return (
    record !== undefined &&
    record.path === expected.path &&
    (!route || record.contract_revision === EXPECTED_ROUTE_MANIFEST.contractRevision) &&
    record.sha256 === expected.sha256 &&
    record.size_bytes === expected.sizeBytes
  );
}

function normalizeAttestation(
  input: unknown
): { readonly value: unknown } | { readonly error: 'missing' | 'empty' | 'malformed' } {
  if (input === undefined || input === null) return { error: 'missing' };
  if (typeof input !== 'string') {
    const snapshot = snapshotBoundedValue(input);
    const record = asRecord(snapshot);
    if (record && Object.keys(record).length === 0) return { error: 'empty' };
    return snapshot === undefined ? { error: 'malformed' } : { value: snapshot };
  }
  // Bound both representations before trim or parse so whitespace and astral
  // input cannot force an unbounded copy or UTF-8 encoding allocation.
  if (input.length > MAX_ATTESTATION_CODE_UNITS) return { error: 'malformed' };
  if (utf8ByteLengthBounded(input, MAX_ATTESTATION_UTF8_BYTES) === undefined) {
    return { error: 'malformed' };
  }
  if (input.trim().length === 0) return { error: 'empty' };
  try {
    return {
      value: parseStrictJson(input, {
        maxDepth: 8,
        maxNodes: 128,
        maxStringLength: 512,
        maxArrayLength: 1,
        maxObjectKeys: ROOT_KEYS.length
      })
    };
  } catch {
    return { error: 'malformed' };
  }
}

function verifyTrustContext(value: unknown): boolean {
  if (typeof value !== 'object' || value === null || !trustedContexts.has(value)) return false;
  const snapshot = snapshotBoundedValue(value);
  const trust = exactRecord(snapshot, TRUST_KEYS, true);
  return (
    trust !== undefined &&
    trust.status === 'trusted' &&
    trust.channel === PINNED_TRUST_CHANNEL &&
    trust.deploymentIdentity === PINNED_DEPLOYMENT_IDENTITY &&
    trust.scope === PINNED_DEPLOYMENT_SCOPE
  );
}

function verifyAttestationShape(value: unknown): AttestationDecisionCode | undefined {
  const root = exactRecord(value, ROOT_KEYS, true);
  if (!root) return 'malformed';
  if (root.schema !== REVISION_ATTESTATION_SCHEMA || root.operation !== 'C-04') {
    return 'unsupported-schema';
  }
  if (root.contract !== PINNED_DASHBOARD_CONTRACT) return 'unsupported-contract';

  const hermes = exactRecord(root.hermes, HERMES_KEYS, true);
  if (!hermes || hermes.repository !== 'NousResearch/hermes-agent') return 'malformed';
  if (hermes.source_sha !== PINNED_HERMES_SOURCE_SHA) return 'revision-mismatch';

  const deployment = exactRecord(root.deployment, DEPLOYMENT_KEYS, true);
  if (
    !deployment ||
    deployment.identity !== PINNED_DEPLOYMENT_IDENTITY ||
    deployment.trust_channel !== PINNED_TRUST_CHANNEL ||
    deployment.scope !== PINNED_DEPLOYMENT_SCOPE
  )
    return 'evidence-mismatch';

  if (
    !matchesArtifact(root.route_manifest, EXPECTED_ROUTE_MANIFEST, true) ||
    !matchesArtifact(root.source_review, EXPECTED_SOURCE_REVIEW) ||
    !matchesArtifact(root.proxy_proof, EXPECTED_PROXY_PROOF)
  )
    return 'evidence-mismatch';

  const dashboardMetadata = exactRecord(root.dashboard_metadata, DASHBOARD_METADATA_KEYS, true);
  if (
    !dashboardMetadata ||
    dashboardMetadata.source_revision_observable !== false ||
    dashboardMetadata.stable_wire_version_observable !== false ||
    dashboardMetadata.blocked_ssh_ownership_version_is_evidence !== false
  )
    return 'server-metadata-rejected';

  const requirements = exactRecord(root.requirements, REQUIREMENT_KEYS, true);
  if (
    !requirements ||
    requirements.full_source_sha_required !== true ||
    requirements.unknown_revision_policy !== 'block' ||
    requirements.behavioral_probe_required_before_live_operation !== true ||
    requirements.attestation_alone_enables_live_operation !== false
  )
    return 'malformed';

  const redaction = exactRecord(root.redaction, REDACTION_KEYS, true);
  if (
    !redaction ||
    redaction.synthetic_only !== true ||
    REDACTION_KEYS.slice(1).some((key) => redaction[key] !== false)
  )
    return 'malformed';
  return undefined;
}

function normalizeMetadataKey(key: string): string {
  return key
    .replace(/([a-z0-9])([A-Z])/gu, '$1_$2')
    .replace(/[^a-z0-9]+/giu, '_')
    .replace(/^_+|_+$/gu, '')
    .toLowerCase();
}

function isProhibitedMetadataKey(key: string): boolean {
  const compact = normalizeMetadataKey(key).replaceAll('_', '');
  for (const prohibited of PROHIBITED_SERVER_METADATA_KEYS) {
    // Fail closed even when an untrusted server wraps the key in punctuation,
    // whitespace, camel case, or attacker-chosen prefixes and suffixes.
    if (compact.includes(prohibited.replaceAll('_', ''))) return true;
  }
  return false;
}

function hasProhibitedServerMetadata(value: unknown): boolean {
  const pending: unknown[] = [value];
  let visited = 0;
  while (pending.length > 0) {
    const current = pending.pop();
    visited += 1;
    if (visited > MAX_EVIDENCE_NODES) return true;
    if (Array.isArray(current)) {
      if (current.length > MAX_EVIDENCE_ARRAY_LENGTH) return true;
      for (let index = 0; index < current.length; index += 1) pending.push(current[index]);
      continue;
    }
    const record = asRecord(current);
    if (!record) continue;
    for (const [key, nested] of Object.entries(record)) {
      if (isProhibitedMetadataKey(key)) return true;
      pending.push(nested);
    }
  }
  return false;
}

function runtimeEvidenceMatches(value: unknown): AttestationDecisionCode | undefined {
  const snapshot = snapshotBoundedValue(value);
  const evidence = exactRecord(snapshot, RUNTIME_ROOT_KEYS);
  if (!evidence) return 'evidence-mismatch';
  if (evidence.contract !== PINNED_DASHBOARD_CONTRACT) return 'unsupported-contract';
  if (evidence.hermesSourceSha !== PINNED_HERMES_SOURCE_SHA) return 'revision-mismatch';
  if (evidence.websocketPath !== '/api/ws') return 'evidence-mismatch';

  const deployment = exactRecord(evidence.deployment, RUNTIME_DEPLOYMENT_KEYS);
  const routeManifest = exactRecord(evidence.routeManifest, RUNTIME_ROUTE_KEYS);
  const sourceReview = exactRecord(evidence.sourceReview, RUNTIME_ARTIFACT_KEYS);
  const proxyProof = exactRecord(evidence.proxyProof, RUNTIME_ARTIFACT_KEYS);
  if (
    !deployment ||
    deployment.identity !== PINNED_DEPLOYMENT_IDENTITY ||
    deployment.trustChannel !== PINNED_TRUST_CHANNEL ||
    deployment.scope !== PINNED_DEPLOYMENT_SCOPE ||
    !routeManifest ||
    routeManifest.path !== EXPECTED_ROUTE_MANIFEST.path ||
    routeManifest.revision !== EXPECTED_ROUTE_MANIFEST.contractRevision ||
    routeManifest.sha256 !== EXPECTED_ROUTE_MANIFEST.sha256 ||
    routeManifest.sizeBytes !== EXPECTED_ROUTE_MANIFEST.sizeBytes ||
    !sourceReview ||
    sourceReview.path !== EXPECTED_SOURCE_REVIEW.path ||
    sourceReview.sha256 !== EXPECTED_SOURCE_REVIEW.sha256 ||
    sourceReview.sizeBytes !== EXPECTED_SOURCE_REVIEW.sizeBytes ||
    !proxyProof ||
    proxyProof.path !== EXPECTED_PROXY_PROOF.path ||
    proxyProof.sha256 !== EXPECTED_PROXY_PROOF.sha256 ||
    proxyProof.sizeBytes !== EXPECTED_PROXY_PROOF.sizeBytes
  )
    return 'evidence-mismatch';
  return hasProhibitedServerMetadata(evidence.gatewayReadyPayload)
    ? 'server-metadata-rejected'
    : undefined;
}

/**
 * Creates the only accepted synthetic trust context. Plain objects that merely
 * repeat these public fixture strings are intentionally not trusted evidence.
 */
export function createCanonicalFixtureTrustContext(): AttestationTrustContext {
  const context = Object.freeze({
    status: 'trusted',
    channel: PINNED_TRUST_CHANNEL,
    deploymentIdentity: PINNED_DEPLOYMENT_IDENTITY,
    scope: PINNED_DEPLOYMENT_SCOPE
  }) satisfies AttestationTrustContext;
  trustedContexts.add(context);
  return context;
}

/**
 * Evaluates detached evidence without network access. A verified result proves
 * only the pinned fixture bindings; a distinct behavioral probe must still pass.
 */
export function evaluateCompatibilityAttestation(
  input: unknown,
  trustContext: unknown,
  evidence: unknown,
  signal?: AbortSignal
): AttestationDecision {
  if (signal?.aborted) return blocked('aborted');
  const normalized = normalizeAttestation(input);
  if ('error' in normalized) return blocked(normalized.error);
  const shapeError = verifyAttestationShape(normalized.value);
  if (shapeError) return blocked(shapeError as Exclude<AttestationDecisionCode, 'verified'>);
  if (!verifyTrustContext(trustContext)) return blocked('untrusted-source');
  const runtimeError = runtimeEvidenceMatches(evidence);
  return runtimeError
    ? blocked(runtimeError as Exclude<AttestationDecisionCode, 'verified'>)
    : Object.freeze({ passed: true, code: 'verified' });
}

/**
 * Wraps an independently implemented probe without exposing its callback on the
 * nominal object. This helper does not perform or simulate the probe itself.
 */
export function createBehavioralProbeGate(
  runBehavioralProbe: JsonRpcCompatibilityGate
): BehavioralProbeGate {
  if (typeof runBehavioralProbe !== 'function' || attestationCallbacks.has(runBehavioralProbe)) {
    throw new TypeError('An independent behavioral-probe callback is required.');
  }
  const gate = Object.freeze({
    kind: 'behavioral-probe' as const,
    [behavioralProbeMarker]: true as const
  });
  behavioralProbeCallbacks.set(gate, runBehavioralProbe);
  return gate;
}

/**
 * Returns a nominal attestation object, not either callback. The only callback
 * boundary pairs this attestation with a separately created behavioral-probe
 * object, preventing the attestation factory or its result from being assigned
 * directly to `runBehavioralProbe`.
 */
export function createCompatibilityAttestationGate(
  input: unknown,
  trustContext: unknown
): CompatibilityAttestationGate {
  const verifyAttestation: JsonRpcCompatibilityGate = (evidence, signal) => {
    const decision = evaluateCompatibilityAttestation(input, trustContext, evidence, signal);
    return { passed: decision.passed };
  };
  attestationCallbacks.add(verifyAttestation);

  const gate: CompatibilityAttestationGate = {
    kind: 'compatibility-attestation',
    pairWithBehavioralProbe(probe) {
      const runBehavioralProbe = behavioralProbeCallbacks.get(probe);
      if (!runBehavioralProbe) {
        // Forged structural lookalikes are not accepted as independent probes.
        throw new TypeError('A canonical behavioral-probe wrapper is required.');
      }
      if (pairedAttestationGates.has(gate) || pairedBehavioralProbeGates.has(probe)) {
        throw new TypeError('Compatibility gate wrappers can be paired only once.');
      }
      pairedAttestationGates.add(gate);
      pairedBehavioralProbeGates.add(probe);
      let consumed = false;

      return Object.freeze({
        kind: 'compatibility-transport-factory' as const,
        createTransport(options: CompatibilityTransportOptions) {
          if (consumed) {
            throw new TypeError('Compatibility transport factory has already been consumed.');
          }
          // Consume before reading options. A concurrent or reentrant call must
          // fail before it can create a transport or expose either role callback.
          consumed = true;
          // The role callbacks never cross the module boundary. Supplying gates
          // last also prevents cast JavaScript options from replacing either role.
          return createJsonRpcChatTransport({
            ...options,
            verifyAttestation,
            runBehavioralProbe
          });
        }
      });
    }
  };
  return Object.freeze(gate);
}
