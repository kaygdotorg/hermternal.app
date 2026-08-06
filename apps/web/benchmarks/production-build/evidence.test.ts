import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { distribution } from './run';

const benchmarkRoot = import.meta.dir;

interface EvidenceRun {
  id: string;
  state: 'cold' | 'warm';
  repetitions: number;
  command: string;
  raw_samples: number[];
  sample_provenance_sha256: string;
  distribution: ReturnType<typeof distribution>;
  environment: Record<string, string>;
}

interface Evidence {
  schema: string;
  revision: { commit_sha: string; fixture_sha256: string };
  runs: EvidenceRun[];
  artifacts: Array<{ path: string; bytes: number; sha256: string }>;
  artifact_manifest_sha256: string;
  threshold: null;
  budget: null;
}

interface TraceSample {
  duration_ms: number;
  artifact_sha256: string;
}

interface Trace {
  schema: string;
  source_commit_sha: string;
  fixture_sha256: string;
  warmup_excluded_from_distribution: TraceSample;
  runs: Array<{ id: string; state: 'cold' | 'warm'; samples: TraceSample[] }>;
}

function digest(value: Uint8Array | string): string {
  return createHash('sha256').update(value).digest('hex');
}

function canonical(value: unknown): Uint8Array {
  return new TextEncoder().encode(`${JSON.stringify(value)}\n`);
}

async function loadJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, 'utf8')) as T;
}

describe('checked-in production-build evidence', () => {
  test('binds 30 raw cold and warm samples to the B-01 method', async () => {
    const evidence = await loadJson<Evidence>(join(benchmarkRoot, 'evidence/benchmark-evidence.json'));
    const trace = await loadJson<Trace>(join(benchmarkRoot, 'evidence/raw-trace.json'));

    expect(evidence.schema).toBe('hermternal.benchmark-evidence.v1');
    expect(trace.schema).toBe('hermternal.web-production-build-trace.v1');
    expect(evidence.threshold).toBeNull();
    expect(evidence.budget).toBeNull();
    expect(evidence.revision.commit_sha).toBe('8b114f9c340c7dfc4044f006a2812ff1cff880a7');
    expect(evidence.revision.commit_sha).toBe(trace.source_commit_sha);
    expect(evidence.revision.fixture_sha256).toBe('5f1d48a9666203dd0e29053c433e5de1a89a1f04815b26f82f329d2dc2810778');
    expect(evidence.revision.fixture_sha256).toBe(trace.fixture_sha256);
    expect(evidence.runs.map((run) => run.state)).toEqual(['cold', 'warm']);

    for (const run of evidence.runs) {
      expect(run.repetitions).toBe(30);
      expect(run.raw_samples).toHaveLength(30);
      expect(run.distribution).toEqual(distribution(run.raw_samples));
      expect(run.environment.browser).toBe('not_applicable');
      expect(run.sample_provenance_sha256).toBe(
        digest(
          canonical({
            id: run.id,
            state: run.state,
            command: run.command,
            repetitions: run.repetitions,
            raw_samples: run.raw_samples
          })
        )
      );
      const traceRun = trace.runs.find((candidate) => candidate.id === run.id);
      expect(traceRun?.samples.map((sample) => sample.duration_ms)).toEqual(run.raw_samples);
    }
  });

  test('binds local artifacts and one deterministic build identity', async () => {
    const evidence = await loadJson<Evidence>(join(benchmarkRoot, 'evidence/benchmark-evidence.json'));
    const trace = await loadJson<Trace>(join(benchmarkRoot, 'evidence/raw-trace.json'));

    expect(evidence.artifacts.map((artifact) => artifact.path)).toEqual(['workload.json', 'evidence/raw-trace.json']);
    for (const artifact of evidence.artifacts) {
      const bytes = await readFile(join(benchmarkRoot, artifact.path));
      expect(bytes.byteLength).toBe(artifact.bytes);
      expect(digest(bytes)).toBe(artifact.sha256);
    }
    expect(evidence.artifact_manifest_sha256).toBe(digest(canonical(evidence.artifacts)));

    const identities = [
      trace.warmup_excluded_from_distribution.artifact_sha256,
      ...trace.runs.flatMap((run) => run.samples.map((sample) => sample.artifact_sha256))
    ];
    expect(new Set(identities)).toEqual(new Set(['191dd9cd25a6546bb53270be04cbd8fe8a7f2ad3aa9130804abd20ddf6de92be']));
  });
});
