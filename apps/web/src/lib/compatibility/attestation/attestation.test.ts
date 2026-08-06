import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { JsonRpcCompatibilityEvidence } from '../../chat/json-rpc-chat';
import {
  createCompatibilityAttestationGate,
  evaluateCompatibilityAttestation
} from './attestation';

const FIXTURE_ROOT = resolve(
  process.cwd(),
  '../../contracts/fixtures/compatibility-attestation'
);
const CANONICAL_ATTESTATION = JSON.parse(
  readFileSync(resolve(FIXTURE_ROOT, 'revision_attestation.json'), 'utf8')
) as Record<string, unknown>;
const CASES = JSON.parse(readFileSync(resolve(FIXTURE_ROOT, 'cases.json'), 'utf8')) as {
  cases: Array<{
    id: string;
    input: {
      attestation: string;
      revision: string;
      route_manifest: string;
      source_review: string;
      proxy_proof: string;
      behavioral_probe: string;
      dashboard_metadata: string;
    };
    expected: { attestation_result: 'verified' | 'blocked' };
  }>;
};

const TRUSTED_FIXTURE_CHANNEL = {
  status: 'trusted',
  channel: 'release-channel'
} as const;

const RUNTIME_EVIDENCE: JsonRpcCompatibilityEvidence = {
  contract: 'dashboard-v0.0.1',
  hermesSourceSha: 'f5be9236e00ddf2f2a412697f267078fc4ee068e',
  websocketPath: '/api/ws',
  deployment: {
    identity: 'synthetic-deployment-001',
    trustChannel: 'release-channel',
    scope: 'fixture_only'
  },
  routeManifest: {
    path: 'contracts/hermes-dashboard/manifest.md',
    revision: 'dashboard-v0.0.1',
    sha256: '3c6b44dc8dd90836f4fc5c5158d459959c569fb811db4b198e87d78ea5010197',
    sizeBytes: 17_859
  },
  sourceReview: {
    path: 'contracts/fixtures/source-audit/planning-reconciliation/planning_review.json',
    sha256: '0a84cba82e6e966ab35de187f560fd38d6e10c43dd2204062d6ebf2bc5c32077',
    sizeBytes: 20_045
  },
  proxyProof: {
    path: 'docs/deployment/proof-matrix.md',
    sha256: '52fb8d0fb9f21ee7a80c5796343c3893a7f715c93fd47e832f5be098bc865212',
    sizeBytes: 16_167
  },
  gatewayReadyPayload: Object.create(null) as Record<string, never>
};

function cloneAttestation(): Record<string, unknown> {
  return structuredClone(CANONICAL_ATTESTATION);
}

function nested(record: Record<string, unknown>, key: string): Record<string, unknown> {
  return record[key] as Record<string, unknown>;
}

function fixtureInput(caseInput: (typeof CASES.cases)[number]['input']): unknown {
  if (caseInput.attestation === 'missing') return undefined;
  if (caseInput.attestation === 'empty') return '';
  if (caseInput.attestation === 'malformed') return '{"schema":';

  const record = cloneAttestation();
  if (caseInput.revision === 'unknown') nested(record, 'hermes').source_sha = 'unknown';
  if (caseInput.revision === 'abbreviated') nested(record, 'hermes').source_sha = 'f5be9236';
  if (caseInput.revision === 'mismatched') {
    nested(record, 'hermes').source_sha = '0000000000000000000000000000000000000000';
  }
  if (caseInput.route_manifest === 'mismatch') nested(record, 'route_manifest').sha256 = '0'.repeat(64);
  if (caseInput.source_review === 'mismatch') nested(record, 'source_review').sha256 = '0'.repeat(64);
  if (caseInput.proxy_proof === 'mismatch') nested(record, 'proxy_proof').sha256 = '0'.repeat(64);
  if (caseInput.dashboard_metadata === 'unexpected') {
    nested(record, 'dashboard_metadata').source_revision_observable = true;
  }
  return record;
}

describe('fixture-driven compatibility attestation', () => {
  it('implements every source-backed C-04 attestation result without promoting probe state', () => {
    for (const fixtureCase of CASES.cases) {
      const result = evaluateCompatibilityAttestation(
        fixtureInput(fixtureCase.input),
        TRUSTED_FIXTURE_CHANNEL,
        RUNTIME_EVIDENCE
      );
      expect(result.passed, fixtureCase.id).toBe(
        fixtureCase.expected.attestation_result === 'verified'
      );
    }
  });

  it('fails closed for unknown or self-declared trust contexts', () => {
    for (const trust of [
      undefined,
      {},
      { status: 'unknown', channel: 'release-channel' },
      { status: 'untrusted', channel: 'release-channel' },
      { status: 'trusted', channel: 'other-channel' },
      { status: 'trusted', channel: 'release-channel', assertedBy: 'record' }
    ]) {
      expect(
        evaluateCompatibilityAttestation(
          CANONICAL_ATTESTATION,
          trust,
          RUNTIME_EVIDENCE
        )
      ).toEqual({ passed: false, code: 'untrusted-source' });
    }
  });

  it('rejects duplicate, reordered, additive, and non-finite JSON evidence', () => {
    const canonicalJson = JSON.stringify(CANONICAL_ATTESTATION);
    const duplicateSchema = canonicalJson.replace(
      '"schema":"hermternal.revision-attestation.v1",',
      '"schema":"hermternal.revision-attestation.v1","schema":"hermternal.revision-attestation.v1",'
    );
    const reordered = cloneAttestation();
    const schema = reordered.schema;
    delete reordered.schema;
    reordered.schema = schema;
    const additive = cloneAttestation();
    additive.compatible = true;

    for (const input of [duplicateSchema, reordered, additive, canonicalJson.replace('17859', '1e9999')]) {
      expect(
        evaluateCompatibilityAttestation(input, TRUSTED_FIXTURE_CHANNEL, RUNTIME_EVIDENCE).passed
      ).toBe(false);
    }
  });

  it('binds runtime evidence to the detached record and rejects server-shaped version claims', () => {
    expect(
      evaluateCompatibilityAttestation(
        CANONICAL_ATTESTATION,
        TRUSTED_FIXTURE_CHANNEL,
        undefined
      )
    ).toEqual({ passed: false, code: 'evidence-mismatch' });

    const mismatchedEvidence: JsonRpcCompatibilityEvidence = {
      ...RUNTIME_EVIDENCE,
      proxyProof: { ...RUNTIME_EVIDENCE.proxyProof, sha256: '0'.repeat(64) }
    };
    expect(
      evaluateCompatibilityAttestation(
        CANONICAL_ATTESTATION,
        TRUSTED_FIXTURE_CHANNEL,
        mismatchedEvidence
      )
    ).toEqual({ passed: false, code: 'evidence-mismatch' });

    for (const key of ['protocol_version', 'protocolVersion', 'protocol-version']) {
      const serverClaim: JsonRpcCompatibilityEvidence = {
        ...RUNTIME_EVIDENCE,
        gatewayReadyPayload: {
          nested: { [key]: 'dashboard-v0.0.1' }
        }
      };
      expect(
        evaluateCompatibilityAttestation(
          CANONICAL_ATTESTATION,
          TRUSTED_FIXTURE_CHANNEL,
          serverClaim
        ),
        key
      ).toEqual({ passed: false, code: 'server-metadata-rejected' });
    }
  });

  it('preserves cancellation and exposes a fail-closed JSON-RPC gate callback', async () => {
    const controller = new AbortController();
    controller.abort();
    expect(
      evaluateCompatibilityAttestation(
        CANONICAL_ATTESTATION,
        TRUSTED_FIXTURE_CHANNEL,
        RUNTIME_EVIDENCE,
        controller.signal
      )
    ).toEqual({ passed: false, code: 'aborted' });

    const gate = createCompatibilityAttestationGate(
      CANONICAL_ATTESTATION,
      TRUSTED_FIXTURE_CHANNEL
    );
    await expect(
      Promise.resolve(gate(RUNTIME_EVIDENCE, new AbortController().signal))
    ).resolves.toEqual({ passed: true });
  });

  it('bounds untrusted gateway metadata traversal', () => {
    let value: Record<string, unknown> = {};
    const root = value;
    for (let index = 0; index < 1_025; index += 1) {
      value.next = {};
      value = value.next as Record<string, unknown>;
    }
    const evidence: JsonRpcCompatibilityEvidence = {
      ...RUNTIME_EVIDENCE,
      gatewayReadyPayload: root as JsonRpcCompatibilityEvidence['gatewayReadyPayload']
    };
    expect(
      evaluateCompatibilityAttestation(
        CANONICAL_ATTESTATION,
        TRUSTED_FIXTURE_CHANNEL,
        evidence
      )
    ).toEqual({ passed: false, code: 'server-metadata-rejected' });
  });
});
