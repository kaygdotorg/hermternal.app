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

export type BenchmarkExecutionInput = Readonly<{
  path: string;
  bytes: number;
  sha256: string;
}>;

export const BENCHMARK_BUILD_COMMAND = 'vite build --configFile false --minify';

export type BenchmarkBuildFile = Readonly<{
  path: string;
  bytes: number;
  sha256: string;
}>;

export type BenchmarkBuild = Readonly<{
  command: string;
  files: readonly BenchmarkBuildFile[];
  entry_bytes: number;
  lazy_chunk_bytes: number;
  wasm_bytes: number;
  css_bytes: number;
}>;

export type BenchmarkCheckout = Readonly<{
  /** The clean source checkout used to produce or review the trace. */
  head: string;
  clean: boolean;
  execution_inputs: readonly BenchmarkExecutionInput[];
  /** Artifact bytes and hashes collected from the exact produced build output. */
  build: BenchmarkBuild;
  /**
   * Checked-in evidence must be a distinct successor of the measured source.
   * This makes provenance non-circular: a commit cannot self-attest its trace.
   */
  evidence_head?: string;
  /** The source-to-evidence range must contain this artifact and nothing else. */
  evidence_changed_paths?: readonly string[];
  /** Git resolution independently proved source is a strict anchor ancestor. */
  evidence_source_is_strict_ancestor?: boolean;
  /** The immutable anchor tree contains the exact checked-in evidence blob. */
  evidence_blob_matches?: boolean;
  /** Exactly one historical evidence commit may contain this exact blob. */
  evidence_anchor_count?: number;
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

function isSafeBuildPath(path: string): boolean {
  return (
    path.length > 0 &&
    !path.startsWith('/') &&
    !path.includes('\\') &&
    !path.split('/').some((segment) => segment === '' || segment === '.' || segment === '..')
  );
}

function recomputeBuildTotals(files: readonly BenchmarkBuildFile[]): Readonly<{
  entry_bytes: number;
  lazy_chunk_bytes: number;
  wasm_bytes: number;
  css_bytes: number;
}> {
  const entryFiles = files.filter((file) => file.path === 'entry.js');
  if (entryFiles.length !== 1) {
    throw new Error('benchmark build must contain exactly one entry.js artifact');
  }
  return {
    entry_bytes: entryFiles[0]?.bytes ?? 0,
    lazy_chunk_bytes: files
      .filter((file) => file.path.startsWith('chunks/'))
      .reduce((total, file) => total + file.bytes, 0),
    wasm_bytes: files
      .filter((file) => file.path.endsWith('.wasm'))
      .reduce((total, file) => total + file.bytes, 0),
    css_bytes: files
      .filter((file) => file.path.endsWith('.css'))
      .reduce((total, file) => total + file.bytes, 0)
  };
}

function parseBenchmarkBuild(value: unknown, label: string): BenchmarkBuild {
  if (!isRecord(value) || value.command !== BENCHMARK_BUILD_COMMAND || !Array.isArray(value.files) || value.files.length === 0) {
    throw new Error(`${label} build metadata was invalid`);
  }
  const files: BenchmarkBuildFile[] = [];
  const paths = new Set<string>();
  for (const file of value.files) {
    if (
      !isRecord(file) ||
      typeof file.path !== 'string' ||
      !isSafeBuildPath(file.path) ||
      paths.has(file.path) ||
      typeof file.bytes !== 'number' ||
      !Number.isInteger(file.bytes) ||
      file.bytes < 0 ||
      typeof file.sha256 !== 'string' ||
      !INPUT_SHA256.test(file.sha256)
    ) {
      throw new Error(`${label} build artifact metadata was invalid`);
    }
    paths.add(file.path);
    files.push({
      path: file.path,
      bytes: file.bytes,
      sha256: file.sha256
    });
  }
  for (let index = 1; index < files.length; index += 1) {
    if (files[index - 1]!.path.localeCompare(files[index]!.path) > 0) {
      throw new Error(`${label} build artifacts were not sorted by path`);
    }
  }
  const totals = recomputeBuildTotals(files);
  for (const key of ['entry_bytes', 'lazy_chunk_bytes', 'wasm_bytes', 'css_bytes'] as const) {
    const number = value[key];
    if (typeof number !== 'number' || !Number.isInteger(number) || number < 0 || number !== totals[key]) {
      throw new Error(`${label} build ${key} did not match recomputed artifacts`);
    }
  }
  return {
    command: BENCHMARK_BUILD_COMMAND,
    files,
    ...totals
  };
}

function assertBuildMatchesExpected(actual: unknown, expected: unknown): void {
  const actualBuild = parseBenchmarkBuild(actual, 'checked-in benchmark evidence');
  const expectedBuild = parseBenchmarkBuild(expected, 'recomputed checkout');
  if (
    actualBuild.files.length !== expectedBuild.files.length ||
    actualBuild.files.some((file, index) => {
      const expectedFile = expectedBuild.files[index];
      return (
        !expectedFile ||
        file.path !== expectedFile.path ||
        file.bytes !== expectedFile.bytes ||
        file.sha256.toLowerCase() !== expectedFile.sha256.toLowerCase()
      );
    }) ||
    actualBuild.entry_bytes !== expectedBuild.entry_bytes ||
    actualBuild.lazy_chunk_bytes !== expectedBuild.lazy_chunk_bytes ||
    actualBuild.wasm_bytes !== expectedBuild.wasm_bytes ||
    actualBuild.css_bytes !== expectedBuild.css_bytes
  ) {
    throw new Error('checked-in benchmark evidence build did not match the recomputed checkout artifacts');
  }
}

const RENDER_FENCE = 'visible-text-sentinel';
const REPLAY_BYTES = 1024 * 1024;
const REPLAY_CHUNK_BYTES = 64 * 1024;
const INITIAL_COLS = 80;
const INITIAL_ROWS = 24;
const SCROLLBACK_BYTES = 64 * 1024;

function assertBrowserEnvironment(environment: Record<string, unknown>): void {
  const stringKeys = ['user_agent', 'platform', 'viewport', 'device_pixel_ratio', 'cross_origin_isolated'] as const;
  if (stringKeys.some((key) => typeof environment[key] !== 'string' || environment[key] === '')) {
    throw new Error('checked-in benchmark evidence browser environment metadata was invalid');
  }
  const viewport = String(environment.viewport).match(/^(\d+)x(\d+)$/u);
  if (!viewport || Number(viewport[1]) < 1 || Number(viewport[2]) < 1) {
    throw new Error('checked-in benchmark evidence browser viewport metadata was invalid');
  }
  const devicePixelRatio = Number(environment.device_pixel_ratio);
  if (!Number.isFinite(devicePixelRatio) || devicePixelRatio <= 0) {
    throw new Error('checked-in benchmark evidence browser device-pixel-ratio metadata was invalid');
  }
  if (environment.cross_origin_isolated !== 'true' && environment.cross_origin_isolated !== 'false') {
    throw new Error('checked-in benchmark evidence browser isolation metadata was invalid');
  }
  // The route records every request outside the exact local origin. A missing
  // value cannot prove the policy ran, and any nonzero count proves it failed.
  if (environment.disallowed_network_requests !== '0') {
    throw new Error('checked-in benchmark evidence browser network policy was invalid');
  }
}

function assertLongTaskMetadata(value: unknown): void {
  if (!Array.isArray(value)) {
    throw new Error('checked-in benchmark evidence long-task samples were invalid');
  }
  for (const duration of value) {
    if (typeof duration !== 'number' || !Number.isFinite(duration) || duration < 0) {
      throw new Error('checked-in benchmark evidence long-task samples were invalid');
    }
  }
}

function assertMemoryMetadata(value: unknown): void {
  if (!isRecord(value) || typeof value.supported !== 'boolean' || !(value.reason === null || typeof value.reason === 'string')) {
    throw new Error('checked-in benchmark evidence memory metadata was invalid');
  }
  const fields = ['before_replay_bytes', 'after_replay_bytes', 'after_dispose_bytes'] as const;
  for (const field of fields) {
    const bytes = value[field];
    if (bytes !== null && (typeof bytes !== 'number' || !Number.isInteger(bytes) || bytes < 0)) {
      throw new Error('checked-in benchmark evidence memory metadata was invalid');
    }
  }
  const hasSample = fields.some((field) => value[field] !== null);
  if (value.supported !== hasSample || (value.supported && value.reason !== null) || (!value.supported && !value.reason)) {
    throw new Error('checked-in benchmark evidence memory support metadata was inconsistent');
  }
}

function assertWorkloadMetadata(value: unknown): void {
  if (!isRecord(value) || !isRecord(value.initial_size)) {
    throw new Error('checked-in benchmark evidence workload metadata was invalid');
  }
  const integerFields = ['replay_bytes', 'replay_chunks', 'mount_dispose_repetitions', 'scrollback_limit_bytes'] as const;
  for (const field of integerFields) {
    const number = value[field];
    if (typeof number !== 'number' || !Number.isInteger(number) || number < 0) {
      throw new Error('checked-in benchmark evidence workload metadata was invalid');
    }
  }
  if (
    value.replay_bytes !== REPLAY_BYTES ||
    value.replay_chunks !== REPLAY_BYTES / REPLAY_CHUNK_BYTES ||
    value.mount_dispose_repetitions !== BENCHMARK_REPETITIONS.repeated_mount_dispose ||
    value.scrollback_limit_bytes !== SCROLLBACK_BYTES
  ) {
    throw new Error('checked-in benchmark evidence workload metadata did not match the reviewed workload');
  }
  const cols = value.initial_size.cols;
  const rows = value.initial_size.rows;
  if (
    typeof cols !== 'number' || !Number.isInteger(cols) || cols !== INITIAL_COLS ||
    typeof rows !== 'number' || !Number.isInteger(rows) || rows !== INITIAL_ROWS
  ) {
    throw new Error('checked-in benchmark evidence initial terminal size was invalid');
  }
}

/** Validate the checked-in trace against a clean, recomputed source checkout. */
export function assertBenchmarkTrace(value: unknown, checkout: BenchmarkCheckout): void {
  if (!isRecord(value) || value.schema !== 'hermternal.web-terminal-renderer-benchmark.v1') {
    throw new Error('checked-in benchmark evidence schema was invalid');
  }
  const revision = value.revision;
  if (!isRecord(revision) || !FULL_COMMIT_SHA.test(String(revision.source_commit ?? ''))) {
    throw new Error('checked-in benchmark evidence source commit was invalid');
  }
  if (
    revision.browser_entry !== 'apps/web/tests/bench/terminal-renderer.browser.ts' ||
    revision.renderer_module !== 'apps/web/src/lib/terminal/renderer.ts'
  ) {
    throw new Error('checked-in benchmark evidence revision paths were invalid');
  }
  if (
    !checkout ||
    !FULL_COMMIT_SHA.test(checkout.head) ||
    !checkout.clean ||
    !Array.isArray(checkout.execution_inputs) ||
    !isRecord(checkout.build)
  ) {
    throw new Error('checked-in benchmark evidence checkout was not a clean full-commit source');
  }
  if (String(revision.source_commit).toLowerCase() !== checkout.head.toLowerCase()) {
    throw new Error('checked-in benchmark evidence source commit did not match the reviewed checkout HEAD');
  }
  if (checkout.evidence_head !== undefined || checkout.evidence_changed_paths !== undefined) {
    const evidencePath = 'apps/web/tests/bench/terminal-renderer.evidence.json';
    if (
      typeof checkout.evidence_head !== 'string' ||
      !FULL_COMMIT_SHA.test(checkout.evidence_head) ||
      checkout.evidence_head.toLowerCase() === checkout.head.toLowerCase() ||
      checkout.evidence_source_is_strict_ancestor !== true ||
      checkout.evidence_blob_matches !== true ||
      checkout.evidence_anchor_count !== 1 ||
      !Array.isArray(checkout.evidence_changed_paths) ||
      checkout.evidence_changed_paths.length !== 1 ||
      checkout.evidence_changed_paths[0] !== evidencePath
    ) {
      // An empty range would let one commit attest itself; any other path would
      // make an old source appear authorized by unrelated later changes.
      throw new Error('checked-in benchmark evidence source relationship was not evidence-only');
    }
  }
  if (
    checkout.execution_inputs.length !== BENCHMARK_EXECUTION_INPUT_PATHS.length ||
    checkout.execution_inputs.some((input, index) =>
      !isRecord(input) ||
      input.path !== BENCHMARK_EXECUTION_INPUT_PATHS[index] ||
      typeof input.bytes !== 'number' ||
      !Number.isInteger(input.bytes) ||
      input.bytes < 0 ||
      typeof input.sha256 !== 'string' ||
      !INPUT_SHA256.test(input.sha256)
    )
  ) {
    throw new Error('recomputed checkout execution inputs were invalid');
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
  if (
    checkout.execution_inputs.length !== BENCHMARK_EXECUTION_INPUT_PATHS.length ||
    checkout.execution_inputs.some((expected, index) => {
      const actual = inputs[index];
      return (
        expected.path !== BENCHMARK_EXECUTION_INPUT_PATHS[index] ||
        !isRecord(actual) ||
        actual.path !== expected.path ||
        actual.bytes !== expected.bytes ||
        String(actual.sha256).toLowerCase() !== expected.sha256.toLowerCase()
      );
    })
  ) {
    throw new Error('checked-in benchmark evidence execution inputs did not match the recomputed checkout');
  }
  const browser = value.browser;
  if (
    !isRecord(browser) ||
    browser.schema !== 'hermternal.web-terminal-renderer-browser-benchmark.v1' ||
    !isRecord(browser.environment) ||
    browser.render_fence !== RENDER_FENCE ||
    !isRecord(browser.samples)
  ) {
    throw new Error('checked-in benchmark evidence browser metadata or samples were invalid');
  }
  assertBrowserEnvironment(browser.environment);
  assertLongTaskMetadata(browser.long_tasks_ms);
  assertMemoryMetadata(browser.memory);
  assertWorkloadMetadata(browser.workload);
  assertBuildMatchesExpected(value.build, checkout.build);
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
  if (
    !isRecord(method) ||
    method.browser !== 'Playwright Chromium headless' ||
    method.warmups !== 0 ||
    method.percentile !== 'inclusive-linear-r7' ||
    method.rounding !== 'decimal-half-even-to-three-places' ||
    !Array.isArray(method.quantiles) ||
    method.quantiles.length !== 3 ||
    method.quantiles.some((quantile) => typeof quantile !== 'number' || !Number.isFinite(quantile)) ||
    method.quantiles.join(',') !== '0.5,0.95,0.99' ||
    !isRecord(method.repetitions)
  ) {
    throw new Error('checked-in benchmark evidence method metadata was invalid');
  }
  const repetitionNames = Object.keys(method.repetitions).sort();
  const expectedRepetitionNames = Object.keys(BENCHMARK_REPETITIONS).sort();
  if (repetitionNames.join('\\n') !== expectedRepetitionNames.join('\\n')) {
    throw new Error('checked-in benchmark evidence repetition metadata was incomplete');
  }
  for (const [name, expected] of Object.entries(BENCHMARK_REPETITIONS)) {
    if (method.repetitions[name] !== expected) {
      throw new Error(`checked-in benchmark evidence repetition for ${name} was invalid`);
    }
  }
  const redaction = value.redaction;
  const redactionKeys = [
    'synthetic_only',
    'loopback_http_access',
    'external_network_access',
    'provider_access',
    'credentials',
    'cookies',
    'terminal_bytes_logged',
    'hostnames',
    'user_data'
  ];
  if (
    !isRecord(redaction) ||
    // `network_access: false` was contradictory: this harness loads its local
    // HTTP server. Keep loopback use and external/provider isolation explicit.
    Object.prototype.hasOwnProperty.call(redaction, 'network_access') ||
    redactionKeys.some((key) => typeof redaction[key] !== 'boolean') ||
    redaction.synthetic_only !== true ||
    redaction.loopback_http_access !== true ||
    redaction.external_network_access !== false ||
    redaction.provider_access !== false ||
    redaction.credentials !== false ||
    redaction.cookies !== false ||
    redaction.terminal_bytes_logged !== false ||
    redaction.hostnames !== false ||
    redaction.user_data !== false ||
    value.threshold !== null ||
    value.budget !== null
  ) {
    throw new Error('checked-in benchmark evidence redaction metadata was invalid');
  }
}

/**
 * Allow only the loopback benchmark server and browser-internal resource schemes.
 * Playwright's declarative network flag is not a runtime enforcement boundary, so
 * the benchmark installs this predicate in an explicit request route instead.
 */
export function isAllowedBenchmarkRequest(requestUrl: string, localOrigin: string): boolean {
  try {
    const parsed = new URL(requestUrl);
    if (parsed.protocol === 'about:' || parsed.protocol === 'blob:' || parsed.protocol === 'data:') {
      return true;
    }
    // Origin omits userinfo, so compare it only after rejecting credentials.
    // Otherwise a credential-bearing URL could masquerade as the local server.
    return (
      (parsed.protocol === 'http:' || parsed.protocol === 'https:') &&
      parsed.username === '' &&
      parsed.password === '' &&
      parsed.origin === localOrigin
    );
  } catch {
    return false;
  }
}

/** Fail closed if the browser attempted any request outside the local policy. */
export function assertNoDisallowedNetworkRequests(count: number): void {
  if (!Number.isInteger(count) || count < 0 || count !== 0) {
    throw new Error(`benchmark attempted ${count} disallowed network request(s)`);
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
