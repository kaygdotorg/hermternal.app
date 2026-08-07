const FULL_COMMIT_SHA = /^[0-9a-f]{40}$/iu;

export const BENCHMARK_REPETITIONS = {
  cold_initialization: 5,
  first_byte_to_first_glyph: 5,
  sustained_output: 10,
  resize_settling: 10,
  replay_1_mib: 5,
  repeated_mount_dispose: 10
} as const;

type Distribution = Readonly<{
  min: number;
  p50: number;
  p95: number;
  p99: number;
  max: number;
  mean: number;
}>;

type SampleSet = Readonly<{
  raw_samples: readonly number[];
  distribution?: Distribution;
}>;

/** Validate counts and finite published values before a trace is emitted. */
export function assertBenchmarkSampleCounts(
  samples: Readonly<Record<string, SampleSet>>,
  repetitions: Readonly<Record<string, number>>
): void {
  for (const [name, expected] of Object.entries(repetitions)) {
    const sampleSet = samples[name];
    const actual = sampleSet?.raw_samples.length;
    if (actual !== expected) {
      throw new Error(`benchmark sample count for ${name} was ${actual ?? 0}; expected ${expected}`);
    }
    if (!sampleSet || !Array.isArray(sampleSet.raw_samples)) {
      throw new Error(`benchmark samples for ${name} were not an array`);
    }
    for (const value of sampleSet.raw_samples) {
      if (!Number.isFinite(value) || value < 0) {
        throw new Error(`benchmark sample for ${name} was not a finite non-negative number`);
      }
    }
    if (sampleSet.distribution) {
      for (const value of Object.values(sampleSet.distribution)) {
        if (!Number.isFinite(value) || value < 0) {
          throw new Error(`benchmark distribution for ${name} was not finite and non-negative`);
        }
      }
    }
  }
}

/** Validate the explicit source revision required for a reproducible trace. */
export function validateFullCommit(value: string | undefined): string {
  const commit = value?.trim() ?? '';
  if (!FULL_COMMIT_SHA.test(commit)) {
    throw new Error('GIT_COMMIT must be an explicit 40-character commit SHA');
  }
  return commit.toLowerCase();
}

/** Keep the trace tied to the checkout that supplied its execution inputs. */
export function assertCommitMatchesHead(commit: string, head: string): void {
  if (commit.toLowerCase() !== head.trim().toLowerCase()) {
    throw new Error(`GIT_COMMIT ${commit} does not match checkout HEAD ${head.trim()}`);
  }
}

/** Refuse evidence from a dirty renderer or benchmark harness checkout. */
export function assertCleanExecutionInputs(status: string): void {
  const dirty = status.trim();
  if (dirty) {
    throw new Error(`execution-critical benchmark inputs are dirty:\n${dirty}`);
  }
}
