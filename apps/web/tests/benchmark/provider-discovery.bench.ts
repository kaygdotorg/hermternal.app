import { discoverProviders, type ProviderDiscoveryFetch } from '../../src/lib/auth-ui/provider-discovery';

const samplesCount = 30;
const fixtureId = 'w03-provider-discovery-synthetic-v1';
const payload = JSON.stringify({
  providers: [
    { name: 'nous', display_name: 'Nous', supports_password: false },
    { name: 'hermes-password', display_name: 'Hermes password', supports_password: true }
  ]
});

const fetcher: ProviderDiscoveryFetch = async () =>
  new Response(payload, {
    status: 200,
    headers: { 'content-type': 'application/json' }
  });

const samplesMs: number[] = [];
for (let index = 0; index < samplesCount; index += 1) {
  const started = performance.now();
  const result = await discoverProviders({ fetch: fetcher });
  if (result.providers.length !== 2) throw new Error('Synthetic provider benchmark fixture changed.');
  samplesMs.push(round(performance.now() - started));
}

const ordered = [...samplesMs].sort((left, right) => left - right);
const evidence = {
  schema: 'hermternal.w03-provider-discovery-benchmark.v1',
  fixtureId,
  command: 'bun tests/benchmark/provider-discovery.bench.ts',
  environment: {
    runtime: `Bun ${process.versions.bun ?? 'unknown'}`,
    nodeCompatibility: process.version,
    platform: process.platform,
    arch: process.arch,
    mode: process.env.NODE_ENV ?? 'development'
  },
  repetitions: samplesCount,
  samplesMs,
  distributionMs: {
    min: ordered[0] ?? 0,
    p50: percentile(ordered, 0.5),
    p95: percentile(ordered, 0.95),
    p99: percentile(ordered, 0.99),
    max: ordered.at(-1) ?? 0,
    mean: round(samplesMs.reduce((sum, sample) => sum + sample, 0) / samplesMs.length)
  },
  threshold: null,
  provenance: {
    transport: 'injectable synthetic fetcher',
    network: 'none',
    credentials: 'none',
    response: 'bounded two-provider JSON fixture'
  }
};

process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);

function percentile(values: number[], fraction: number): number {
  const index = Math.min(values.length - 1, Math.max(0, Math.ceil(values.length * fraction) - 1));
  return values[index] ?? 0;
}

function round(value: number): number {
  return Math.round(value * 1_000) / 1_000;
}
