import { readFileSync, statSync } from 'node:fs';
import { arch, platform, release } from 'node:os';
import type { JsonRpcCompatibilityEvidence } from '../../chat/json-rpc-chat';
import {
  createCanonicalFixtureTrustContext,
  evaluateCompatibilityAttestation
} from './attestation';

const fixtureUrl = new URL(
  '../../../../../../contracts/fixtures/compatibility-attestation/revision_attestation.json',
  import.meta.url
);
const moduleUrl = new URL('./attestation.ts', import.meta.url);
const attestation = JSON.parse(readFileSync(fixtureUrl, 'utf8')) as unknown;
const trust = createCanonicalFixtureTrustContext();
const evidence: JsonRpcCompatibilityEvidence = {
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
    sha256: '0f2f1ea3af722cf2d14f6a43754a8430d20bae98d335b961c64b3f1229bd07c1',
    sizeBytes: 18_396
  },
  sourceReview: {
    path: 'contracts/fixtures/source-audit/planning-reconciliation/planning_review.json',
    sha256: '0a84cba82e6e966ab35de187f560fd38d6e10c43dd2204062d6ebf2bc5c32077',
    sizeBytes: 20_045
  },
  proxyProof: {
    path: 'docs/deployment/proof-matrix.md',
    sha256: '01a12174bf770e5380505a5c89930d36b8ba4e43b22b27df1b89dbf9623055a9',
    sizeBytes: 18_532
  },
  gatewayReadyPayload: Object.create(null) as Record<string, never>
};

const repetitions = 30;
const operationsPerRepetition = 1_000;
const samples: number[] = [];
let verified = 0;

for (let warmup = 0; warmup < 5_000; warmup += 1) {
  evaluateCompatibilityAttestation(attestation, trust, evidence);
}
for (let repetition = 0; repetition < repetitions; repetition += 1) {
  const started = performance.now();
  for (let operation = 0; operation < operationsPerRepetition; operation += 1) {
    if (evaluateCompatibilityAttestation(attestation, trust, evidence).passed) verified += 1;
  }
  samples.push(performance.now() - started);
}

const sorted = [...samples].sort((left, right) => left - right);
const percentile = (fraction: number): number =>
  sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * fraction))];
const round = (value: number): number => Number(value.toFixed(4));

process.stdout.write(
  `${JSON.stringify(
    {
      schema: 'hermternal.web-compatibility-attestation-benchmark.v1',
      workload: 'valid_attestation_pending_probe',
      source_fixture: 'contracts/fixtures/compatibility-attestation/revision_attestation.json',
      metric: 'milliseconds_per_1000_evaluations',
      environment: `${platform()}-${release()}-${arch()} / Bun ${process.versions.bun ?? 'unknown'}`,
      build_mode: 'n/a',
      build_mode_reason: 'Pure offline TypeScript gate measured directly; the production web build is checked separately.',
      repetitions,
      operations_per_repetition: operationsPerRepetition,
      duration_ms: {
        min: round(sorted[0]),
        p50: round(percentile(0.5)),
        p95: round(percentile(0.95)),
        max: round(sorted.at(-1) ?? 0),
        mean: round(samples.reduce((sum, sample) => sum + sample, 0) / samples.length)
      },
      verified_operations: verified,
      artifact_bytes: statSync(fixtureUrl).size + statSync(moduleUrl).size,
      threshold: null,
      threshold_reason: 'No B-01/B-08A approved budget is recorded for this gate.',
      measurement_authenticated: false,
      network_calls: 0
    },
    null,
    2
  )}\n`
);
