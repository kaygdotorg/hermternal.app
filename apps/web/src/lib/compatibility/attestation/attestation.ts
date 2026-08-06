import type { JsonRpcCompatibilityGate } from '../../chat/json-rpc-chat';
import { parseStrictJson } from '../../transport/strict-json';

export const REVISION_ATTESTATION_SCHEMA = 'hermternal.revision-attestation.v1' as const;
export const PINNED_DASHBOARD_CONTRACT = 'dashboard-v0.0.1' as const;
export const PINNED_HERMES_SOURCE_SHA =
  'f5be9236e00ddf2f2a412697f267078fc4ee068e' as const;

const EXPECTED_ROUTE_MANIFEST = {
  path: 'contracts/hermes-dashboard/manifest.md',
  contract_revision: PINNED_DASHBOARD_CONTRACT,
  sha256: '3c6b44dc8dd90836f4fc5c5158d459959c569fb811db4b198e87d78ea5010197',
  size_bytes: 17_859
} as const;
const EXPECTED_SOURCE_REVIEW = {
  path: 'contracts/fixtures/source-audit/planning-reconciliation/planning_review.json',
  sha256: '0a84cba82e6e966ab35de187f560fd38d6e10c43dd2204062d6ebf2bc5c32077',
  size_bytes: 20_045
} as const;
const EXPECTED_PROXY_PROOF = {
  path: 'docs/deployment/proof-matrix.md',
  sha256: '52fb8d0fb9f21ee7a80c5796343c3893a7f715c93fd47e832f5be098bc865212',
  size_bytes: 16_167
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
const TRUST_KEYS = ['status', 'channel'] as const;
const PROHIBITED_SERVER_METADATA_KEYS = new Set([
  'dashboard_protocol_version',
  'protocol_version',
  'server_source_sha',
  'source_sha_from_response',
  'revision_from_response'
]);
const MAX_METADATA_NODES = 1_024;

export interface AttestationTrustContext {
  /**
   * This status must come from an authenticated out-of-band boundary. The
   * attestation record cannot mark its own release channel as trusted.
   */
  readonly status: 'trusted' | 'untrusted' | 'unknown';
  readonly channel: string;
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
  | { readonly passed: false; readonly code: Exclude<AttestationDecisionCode, 'verified'> };

type RecordValue = Record<string, unknown>;

interface VerifiedAttestation {
  readonly deploymentIdentity: string;
  readonly trustChannel: string;
}

function blocked(code: Exclude<AttestationDecisionCode, 'verified'>): AttestationDecision {
  return { passed: false, code };
}

function asRecord(value: unknown): RecordValue | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as RecordValue)
    : undefined;
}

function hasExactKeys(record: RecordValue, expected: readonly string[]): boolean {
  const actual = Object.keys(record);
  return actual.length === expected.length && expected.every((key, index) => actual[index] === key);
}

function matchesArtifact(
  value: unknown,
  expected: { readonly path: string; readonly sha256: string; readonly size_bytes: number },
  keys: readonly string[] = ARTIFACT_KEYS
): boolean {
  const record = asRecord(value);
  return (
    record !== undefined &&
    hasExactKeys(record, keys) &&
    record.path === expected.path &&
    record.sha256 === expected.sha256 &&
    record.size_bytes === expected.size_bytes
  );
}

function normalizeAttestation(input: unknown):
  | { readonly value: unknown }
  | { readonly error: 'missing' | 'empty' | 'malformed' } {
  if (input === undefined || input === null) {
    return { error: 'missing' };
  }
  if (typeof input !== 'string') {
    const record = asRecord(input);
    if (record && Object.keys(record).length === 0) {
      return { error: 'empty' };
    }
    return { value: input };
  }
  if (input.trim().length === 0) {
    return { error: 'empty' };
  }
  try {
    // The shared bounded parser preserves duplicate-key rejection before any
    // evidence can be overwritten by normal JSON parsing.
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

function verifyTrustContext(value: unknown, channel: string): boolean {
  const trust = asRecord(value);
  return (
    trust !== undefined &&
    hasExactKeys(trust, TRUST_KEYS) &&
    trust.status === 'trusted' &&
    trust.channel === channel
  );
}

function verifyAttestationShape(value: unknown):
  | { readonly verified: VerifiedAttestation }
  | { readonly error: Exclude<AttestationDecisionCode, 'verified' | 'aborted' | 'missing' | 'empty'> } {
  const root = asRecord(value);
  if (!root || !hasExactKeys(root, ROOT_KEYS)) {
    return { error: 'malformed' };
  }
  if (root.schema !== REVISION_ATTESTATION_SCHEMA || root.operation !== 'C-04') {
    return { error: 'unsupported-schema' };
  }
  if (root.contract !== PINNED_DASHBOARD_CONTRACT) {
    return { error: 'unsupported-contract' };
  }

  const hermes = asRecord(root.hermes);
  if (!hermes || !hasExactKeys(hermes, HERMES_KEYS) || hermes.repository !== 'NousResearch/hermes-agent') {
    return { error: 'malformed' };
  }
  if (hermes.source_sha !== PINNED_HERMES_SOURCE_SHA) {
    return { error: 'revision-mismatch' };
  }

  const deployment = asRecord(root.deployment);
  if (
    !deployment ||
    !hasExactKeys(deployment, DEPLOYMENT_KEYS) ||
    typeof deployment.identity !== 'string' ||
    deployment.identity.length === 0 ||
    typeof deployment.trust_channel !== 'string' ||
    deployment.trust_channel.length === 0 ||
    deployment.scope !== 'fixture_only'
  ) {
    return { error: 'malformed' };
  }

  if (
    !matchesArtifact(root.route_manifest, EXPECTED_ROUTE_MANIFEST, ROUTE_MANIFEST_KEYS) ||
    !matchesArtifact(root.source_review, EXPECTED_SOURCE_REVIEW) ||
    !matchesArtifact(root.proxy_proof, EXPECTED_PROXY_PROOF)
  ) {
    return { error: 'evidence-mismatch' };
  }

  const dashboardMetadata = asRecord(root.dashboard_metadata);
  if (
    !dashboardMetadata ||
    !hasExactKeys(dashboardMetadata, DASHBOARD_METADATA_KEYS) ||
    dashboardMetadata.source_revision_observable !== false ||
    dashboardMetadata.stable_wire_version_observable !== false ||
    dashboardMetadata.blocked_ssh_ownership_version_is_evidence !== false
  ) {
    return { error: 'server-metadata-rejected' };
  }

  const requirements = asRecord(root.requirements);
  if (
    !requirements ||
    !hasExactKeys(requirements, REQUIREMENT_KEYS) ||
    requirements.full_source_sha_required !== true ||
    requirements.unknown_revision_policy !== 'block' ||
    requirements.behavioral_probe_required_before_live_operation !== true ||
    requirements.attestation_alone_enables_live_operation !== false
  ) {
    return { error: 'malformed' };
  }

  const redaction = asRecord(root.redaction);
  if (
    !redaction ||
    !hasExactKeys(redaction, REDACTION_KEYS) ||
    redaction.synthetic_only !== true ||
    REDACTION_KEYS.slice(1).some((key) => redaction[key] !== false)
  ) {
    return { error: 'malformed' };
  }

  return {
    verified: {
      deploymentIdentity: deployment.identity,
      trustChannel: deployment.trust_channel
    }
  };
}

function normalizeMetadataKey(key: string): string {
  return key
    .replace(/([a-z0-9])([A-Z])/gu, '$1_$2')
    .replace(/[^a-z0-9]+/giu, '_')
    .toLowerCase();
}

function hasProhibitedServerMetadata(value: unknown): boolean {
  const pending: unknown[] = [value];
  let visited = 0;
  while (pending.length > 0) {
    const current = pending.pop();
    visited += 1;
    if (visited > MAX_METADATA_NODES) {
      return true;
    }
    if (Array.isArray(current)) {
      pending.push(...current);
      continue;
    }
    const record = asRecord(current);
    if (!record) {
      continue;
    }
    for (const [key, nested] of Object.entries(record)) {
      if (PROHIBITED_SERVER_METADATA_KEYS.has(normalizeMetadataKey(key))) {
        return true;
      }
      pending.push(nested);
    }
  }
  return false;
}

function runtimeEvidenceMatches(
  value: unknown,
  attestation: VerifiedAttestation
): AttestationDecisionCode | undefined {
  const evidence = asRecord(value);
  if (!evidence) {
    return 'evidence-mismatch';
  }
  if (evidence.contract !== PINNED_DASHBOARD_CONTRACT) {
    return 'unsupported-contract';
  }
  if (evidence.hermesSourceSha !== PINNED_HERMES_SOURCE_SHA) {
    return 'revision-mismatch';
  }
  if (evidence.websocketPath !== '/api/ws') {
    return 'evidence-mismatch';
  }

  const deployment = asRecord(evidence.deployment);
  const routeManifest = asRecord(evidence.routeManifest);
  const sourceReview = asRecord(evidence.sourceReview);
  const proxyProof = asRecord(evidence.proxyProof);
  if (
    !deployment ||
    deployment.identity !== attestation.deploymentIdentity ||
    deployment.trustChannel !== attestation.trustChannel ||
    deployment.scope !== 'fixture_only' ||
    !routeManifest ||
    routeManifest.path !== EXPECTED_ROUTE_MANIFEST.path ||
    routeManifest.revision !== EXPECTED_ROUTE_MANIFEST.contract_revision ||
    routeManifest.sha256 !== EXPECTED_ROUTE_MANIFEST.sha256 ||
    routeManifest.sizeBytes !== EXPECTED_ROUTE_MANIFEST.size_bytes ||
    !sourceReview ||
    sourceReview.path !== EXPECTED_SOURCE_REVIEW.path ||
    sourceReview.sha256 !== EXPECTED_SOURCE_REVIEW.sha256 ||
    sourceReview.sizeBytes !== EXPECTED_SOURCE_REVIEW.size_bytes ||
    !proxyProof ||
    proxyProof.path !== EXPECTED_PROXY_PROOF.path ||
    proxyProof.sha256 !== EXPECTED_PROXY_PROOF.sha256 ||
    proxyProof.sizeBytes !== EXPECTED_PROXY_PROOF.size_bytes
  ) {
    return 'evidence-mismatch';
  }
  if (hasProhibitedServerMetadata(evidence.gatewayReadyPayload)) {
    return 'server-metadata-rejected';
  }
  return undefined;
}

/**
 * Evaluates detached evidence without network access. A verified result means
 * only that the pinned fixture fields and trusted release-channel context match;
 * the independent behavioral probe must still pass before chat becomes ready.
 */
export function evaluateCompatibilityAttestation(
  input: unknown,
  trustContext: unknown,
  evidence: unknown,
  signal?: AbortSignal
): AttestationDecision {
  if (signal?.aborted) {
    return blocked('aborted');
  }
  const normalized = normalizeAttestation(input);
  if ('error' in normalized) {
    return blocked(normalized.error);
  }
  const shape = verifyAttestationShape(normalized.value);
  if ('error' in shape) {
    return blocked(shape.error);
  }
  if (!verifyTrustContext(trustContext, shape.verified.trustChannel)) {
    return blocked('untrusted-source');
  }
  const runtimeError = runtimeEvidenceMatches(evidence, shape.verified);
  return runtimeError ? blocked(runtimeError as Exclude<AttestationDecisionCode, 'verified'>) : { passed: true, code: 'verified' };
}

/** Creates a structurally compatible callback for the existing JSON-RPC gate. */
export function createCompatibilityAttestationGate(
  input: unknown,
  trustContext: unknown
): JsonRpcCompatibilityGate {
  return (evidence, signal) => {
    const decision = evaluateCompatibilityAttestation(input, trustContext, evidence, signal);
    return { passed: decision.passed };
  };
}
