const FULL_COMMIT_SHA = /^[0-9a-f]{40}$/iu;
const INPUT_SHA256 = /^[0-9a-f]{64}$/iu;

export const BENCHMARK_REPETITIONS = {
  cold_initialization: 5,
  first_byte_to_first_glyph: 5,
  sustained_output: 10,
  resize_settling: 10,
  replay_1_mib: 5,
  repeated_mount_dispose: 10
} as const;

export const BENCHMARK_EXECUTION_INPUT_PATHS = [
  'apps/web/src/lib/terminal/renderer.ts',
  'apps/web/src/lib/terminal/terminal.css',
  'apps/web/package.json',
  'apps/web/bun.lock',
  'apps/web/tests/bench/terminal-renderer.browser.ts',
  'apps/web/tests/bench/terminal-renderer.bench.ts',
  'apps/web/tests/bench/terminal-renderer.provenance.ts'
] as const;

export type BenchmarkDistribution = Readonly<{
  min: number;
  p50: number;
  p95: number;
  p99: number;
  max: number;
  mean: number;
}>;

export type BenchmarkSampleSet = Readonly<{
  raw_samples?: readonly number[];
  distribution?: Partial<BenchmarkDistribution>;
}>;

const DISTRIBUTION_KEYS = ['min', 'p50', 'p95', 'p99', 'max', 'mean'] as const;

type BenchmarkSamples = Readonly<Record<string, BenchmarkSampleSet>>;

/** Use decimal half-even rounding for both workload output and validation. */
export function roundBenchmarkValue(value: number): number {
  const scale = 1000;
  const scaled = value * scale;
  const sign = scaled < 0 ? -1 : 1;
  const magnitude = Math.abs(scaled);
  const lower = Math.floor(magnitude);
  const fraction = magnitude - lower;
  const epsilon = Number.EPSILON * Math.max(1, magnitude) * 8;
  const roundedInteger = fraction > 0.5 + epsilon
    ? lower + 1
    : fraction < 0.5 - epsilon
      ? lower
      : lower % 2 === 0 ? lower : lower + 1;
  return sign * roundedInteger / scale;
}

function percentile(sorted: readonly number[], quantile: number): number {
  const position = (sorted.length - 1) * quantile;
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  if (lower === upper) return sorted[lower] ?? 0;
  const low = sorted[lower] ?? 0;
  const high = sorted[upper] ?? low;
  return low + (high - low) * (position - lower);
}

/** Recompute published statistics from the already-rounded raw samples. */
export function summarizeBenchmarkSamples(rawSamples: readonly number[]): Readonly<{
  raw_samples: number[];
  distribution: BenchmarkDistribution;
}> {
  const publishedSamples = rawSamples.map(roundBenchmarkValue);
  const sorted = [...publishedSamples].sort((left, right) => left - right);
  const mean = publishedSamples.reduce((total, value) => total + value, 0) / Math.max(1, publishedSamples.length);
  return {
    raw_samples: publishedSamples,
    distribution: {
      min: sorted[0] ?? 0,
      p50: roundBenchmarkValue(percentile(sorted, 0.5)),
      p95: roundBenchmarkValue(percentile(sorted, 0.95)),
      p99: roundBenchmarkValue(percentile(sorted, 0.99)),
      max: sorted.at(-1) ?? 0,
      mean: roundBenchmarkValue(mean)
    }
  };
}

/** Validate counts, recomputed distributions, and finite published values. */
export function assertBenchmarkSampleCounts(
  samples: BenchmarkSamples,
  repetitions: Readonly<Record<string, number>>
): void {
  for (const [name, expected] of Object.entries(repetitions)) {
    const sampleSet = samples[name];
    const actual = sampleSet?.raw_samples?.length;
    if (actual !== expected) {
      throw new Error(`benchmark sample count for ${name} was ${actual ?? 0}; expected ${expected}`);
    }
    if (!sampleSet || !Array.isArray(sampleSet.raw_samples)) {
      throw new Error(`benchmark samples for ${name} were not an array`);
    }
    const rawSamples = sampleSet.raw_samples;
    for (const value of rawSamples) {
      if (!Number.isFinite(value) || value < 0) {
        throw new Error(`benchmark sample for ${name} was not a finite non-negative number`);
      }
    }
    const distribution = sampleSet.distribution;
    if (!distribution) {
      throw new Error(`benchmark distribution for ${name} was missing`);
    }
    for (const key of DISTRIBUTION_KEYS) {
      if (!Object.prototype.hasOwnProperty.call(distribution, key)) {
        throw new Error(`benchmark distribution for ${name} was incomplete; missing ${key}`);
      }
      const value = distribution[key];
      if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
        throw new Error(`benchmark distribution for ${name} was not finite and non-negative`);
      }
    }
    const expectedDistribution = summarizeBenchmarkSamples(rawSamples).distribution;
    for (const key of DISTRIBUTION_KEYS) {
      if (distribution[key] !== expectedDistribution[key]) {
        throw new Error(`benchmark distribution for ${name} did not match recomputed ${key}`);
      }
    }
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

/** Validate the checked-in trace independently from the benchmark producer. */
export function assertBenchmarkTrace(value: unknown): void {
  if (!isRecord(value) || value.schema !== 'hermternal.web-terminal-renderer-benchmark.v1') {
    throw new Error('checked-in benchmark evidence schema was invalid');
  }
  const revision = value.revision;
  if (!isRecord(revision) || !FULL_COMMIT_SHA.test(String(revision.source_commit ?? ''))) {
    throw new Error('checked-in benchmark evidence source commit was invalid');
  }
  const inputs = revision.execution_inputs;
  if (!Array.isArray(inputs) || inputs.length !== BENCHMARK_EXECUTION_INPUT_PATHS.length) {
    throw new Error('checked-in benchmark evidence execution inputs were incomplete');
  }
  for (let index = 0; index < BENCHMARK_EXECUTION_INPUT_PATHS.length; index += 1) {
    const input = inputs[index];
    if (
      !isRecord(input) ||
      input.path !== BENCHMARK_EXECUTION_INPUT_PATHS[index] ||
      typeof input.bytes !== 'number' ||
      !Number.isInteger(input.bytes) ||
      input.bytes < 0 ||
      typeof input.sha256 !== 'string' ||
      !INPUT_SHA256.test(input.sha256)
    ) {
      throw new Error('checked-in benchmark evidence execution input was invalid');
    }
  }
  const browser = value.browser;
  if (!isRecord(browser) || !isRecord(browser.samples)) {
    throw new Error('checked-in benchmark evidence browser samples were missing');
  }
  const sampleNames = Object.keys(browser.samples).sort();
  const expectedNames = Object.keys(BENCHMARK_REPETITIONS).sort();
  if (sampleNames.join('\n') !== expectedNames.join('\n')) {
    throw new Error('checked-in benchmark evidence workloads were incomplete');
  }
  assertBenchmarkSampleCounts(
    browser.samples as BenchmarkSamples,
    BENCHMARK_REPETITIONS
  );
  const method = value.method;
  if (!isRecord(method) || !isRecord(method.repetitions)) {
    throw new Error('checked-in benchmark evidence repetitions were missing');
  }
  for (const [name, expected] of Object.entries(BENCHMARK_REPETITIONS)) {
    if (method.repetitions[name] !== expected) {
      throw new Error(`checked-in benchmark evidence repetition for ${name} was invalid`);
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
