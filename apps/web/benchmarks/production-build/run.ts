import { createHash } from 'node:crypto';
import { copyFile, lstat, mkdir, mkdtemp, readdir, readFile, rename, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { arch, cpus, platform, release, tmpdir, type } from 'node:os';
import { delimiter, dirname, join, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import process from 'node:process';

const BENCHMARK_ROOT = import.meta.dir;
const APP_ROOT = resolve(BENCHMARK_ROOT, '..', '..');
const WORKLOAD_PATH = join(BENCHMARK_ROOT, 'workload.json');
const EVIDENCE_DIRECTORY = join(BENCHMARK_ROOT, 'evidence');
const TRACE_PATH = join(EVIDENCE_DIRECTORY, 'raw-trace.json');
const EVIDENCE_PATH = join(EVIDENCE_DIRECTORY, 'benchmark-evidence.json');
const NETWORK_GUARD_PATH = join(BENCHMARK_ROOT, 'network-guard.mjs');
const MAX_ERROR_BYTES = 512;
const activeWorkspaces = new Set<string>();
let activeChild: ReturnType<typeof Bun.spawn> | undefined;
let handlingSignal = false;

export interface Workload {
  schema: string;
  fixture_id: string;
  fixture_version: string;
  build: {
    entrypoint: string;
    arguments: string[];
    input_files: string[];
    input_roots: string[];
    output_root: string;
    version_name: string;
  };
  repetitions: { cold: number; warm: number; maximum: number };
  limits: {
    build_timeout_ms: number;
    stdout_bytes: number;
    stderr_bytes: number;
    workspace_input_bytes: number;
    artifact_files: number;
    artifact_bytes: number;
    node_heap_megabytes: number;
  };
  network: { mode: string; guard: string };
  hermes_source_sha: string;
}

export interface Distribution {
  min: number;
  p50: number;
  p95: number;
  p99: number;
  max: number;
  mean: number;
}

interface BuildObservation {
  sequence: number;
  duration_ms: number;
  exit_code: number;
  stdout_bytes: number;
  stderr_bytes: number;
  artifact_files: number;
  artifact_bytes: number;
  artifact_sha256: string;
}

interface RunOptions {
  coldRepetitions: number;
  warmRepetitions: number;
  writeEvidence: boolean;
}

export class BenchmarkError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

function sha256(bytes: Uint8Array | string): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(`${JSON.stringify(value)}\n`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireExactKeys(candidate: Record<string, unknown>, expected: string[], code: string): void {
  const actual = Object.keys(candidate).sort();
  const required = [...expected].sort();
  if (actual.length !== required.length || actual.some((key, index) => key !== required[index])) {
    throw new BenchmarkError(code);
  }
}

function requirePositiveInteger(value: unknown, code: string): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) {
    throw new BenchmarkError(code);
  }
  return value as number;
}

export function validateWorkload(candidate: unknown): Workload {
  if (!isRecord(candidate) || candidate.schema !== 'hermternal.web-production-build-workload.v1') {
    throw new BenchmarkError('workload_schema_invalid');
  }
  const build = candidate.build;
  const repetitions = candidate.repetitions;
  const limits = candidate.limits;
  const network = candidate.network;
  if (!isRecord(build) || !isRecord(repetitions) || !isRecord(limits) || !isRecord(network)) {
    throw new BenchmarkError('workload_shape_invalid');
  }
  requireExactKeys(candidate, ['schema', 'fixture_id', 'fixture_version', 'build', 'repetitions', 'limits', 'network', 'hermes_source_sha'], 'workload_keys_invalid');
  requireExactKeys(build, ['entrypoint', 'arguments', 'input_files', 'input_roots', 'output_root', 'version_name'], 'build_keys_invalid');
  requireExactKeys(repetitions, ['cold', 'warm', 'maximum'], 'repetition_keys_invalid');
  requireExactKeys(
    limits,
    ['build_timeout_ms', 'stdout_bytes', 'stderr_bytes', 'workspace_input_bytes', 'artifact_files', 'artifact_bytes', 'node_heap_megabytes'],
    'limit_keys_invalid'
  );
  requireExactKeys(network, ['mode', 'guard'], 'network_keys_invalid');
  const pathLists = [build.input_files, build.input_roots, build.arguments];
  if (
    candidate.fixture_id !== 'web-production-build' ||
    candidate.fixture_version !== '1.0.0' ||
    build.entrypoint !== 'node_modules/vite/bin/vite.js' ||
    build.output_root !== 'build' ||
    build.version_name !== 'hermternal-web-production-build-v1' ||
    pathLists.some((list) => !Array.isArray(list) || list.some((item) => typeof item !== 'string')) ||
    network.mode !== 'deny' ||
    network.guard !== 'network-guard.mjs' ||
    candidate.hermes_source_sha !== 'f5be9236e00ddf2f2a412697f267078fc4ee068e'
  ) {
    throw new BenchmarkError('workload_identity_invalid');
  }
  for (const item of [...(build.input_files as string[]), ...(build.input_roots as string[])]) {
    if (!item || item.startsWith('/') || item.includes('..') || item.includes('\\')) {
      throw new BenchmarkError('workload_path_invalid');
    }
  }
  const maximum = requirePositiveInteger(repetitions.maximum, 'repetition_limit_invalid');
  const cold = requirePositiveInteger(repetitions.cold, 'cold_repetitions_invalid');
  const warm = requirePositiveInteger(repetitions.warm, 'warm_repetitions_invalid');
  if (cold > maximum || warm > maximum || maximum > 100) {
    throw new BenchmarkError('repetition_limit_invalid');
  }
  const validatedLimits = {
    build_timeout_ms: requirePositiveInteger(limits.build_timeout_ms, 'timeout_limit_invalid'),
    stdout_bytes: requirePositiveInteger(limits.stdout_bytes, 'stdout_limit_invalid'),
    stderr_bytes: requirePositiveInteger(limits.stderr_bytes, 'stderr_limit_invalid'),
    workspace_input_bytes: requirePositiveInteger(limits.workspace_input_bytes, 'input_limit_invalid'),
    artifact_files: requirePositiveInteger(limits.artifact_files, 'artifact_file_limit_invalid'),
    artifact_bytes: requirePositiveInteger(limits.artifact_bytes, 'artifact_byte_limit_invalid'),
    node_heap_megabytes: requirePositiveInteger(limits.node_heap_megabytes, 'heap_limit_invalid')
  };
  if (
    validatedLimits.build_timeout_ms > 300_000 ||
    validatedLimits.stdout_bytes > 1_048_576 ||
    validatedLimits.stderr_bytes > 1_048_576 ||
    validatedLimits.workspace_input_bytes > 67_108_864 ||
    validatedLimits.artifact_files > 10_000 ||
    validatedLimits.artifact_bytes > 268_435_456 ||
    validatedLimits.node_heap_megabytes > 4096
  ) {
    throw new BenchmarkError('resource_limit_invalid');
  }
  return candidate as unknown as Workload;
}

export function roundRationalHalfEven(numerator: number, denominator: number): number {
  if (!Number.isSafeInteger(numerator) || !Number.isSafeInteger(denominator) || denominator <= 0) {
    throw new BenchmarkError('rounding_input_invalid');
  }
  const quotient = Math.floor(numerator / denominator);
  const remainder = numerator % denominator;
  const doubled = remainder * 2;
  if (doubled < denominator) return quotient;
  if (doubled > denominator) return quotient + 1;
  return quotient % 2 === 0 ? quotient : quotient + 1;
}

function quantileMicros(sortedMicros: number[], numerator: number, denominator: number): number {
  const scaledPosition = (sortedMicros.length - 1) * numerator;
  const lowerIndex = Math.floor(scaledPosition / denominator);
  const remainder = scaledPosition % denominator;
  if (remainder === 0) return sortedMicros[lowerIndex];
  const lowerWeight = denominator - remainder;
  const valueNumerator = sortedMicros[lowerIndex] * lowerWeight + sortedMicros[lowerIndex + 1] * remainder;
  return roundRationalHalfEven(valueNumerator, denominator);
}

export function distribution(rawSamples: number[]): Distribution {
  if (rawSamples.length === 0 || rawSamples.some((sample) => !Number.isFinite(sample) || sample <= 0)) {
    throw new BenchmarkError('raw_samples_invalid');
  }
  const micros = rawSamples.map((sample) => Math.round(sample * 1000)).sort((a, b) => a - b);
  const sum = micros.reduce((total, sample) => total + sample, 0);
  if (!Number.isSafeInteger(sum)) throw new BenchmarkError('raw_samples_too_large');
  return {
    min: micros[0] / 1000,
    p50: quantileMicros(micros, 1, 2) / 1000,
    p95: quantileMicros(micros, 19, 20) / 1000,
    p99: quantileMicros(micros, 99, 100) / 1000,
    max: micros[micros.length - 1] / 1000,
    mean: roundRationalHalfEven(sum, micros.length) / 1000
  };
}

export function parseArguments(args: string[], workload: Workload): RunOptions {
  let coldRepetitions = workload.repetitions.cold;
  let warmRepetitions = workload.repetitions.warm;
  let writeEvidence = false;
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--write-evidence') {
      writeEvidence = true;
      continue;
    }
    if (argument !== '--cold' && argument !== '--warm') throw new BenchmarkError('argument_invalid');
    const rawValue = args[index + 1];
    if (!rawValue || !/^\d+$/.test(rawValue)) throw new BenchmarkError('argument_value_invalid');
    const value = Number(rawValue);
    if (value < 1 || value > workload.repetitions.maximum) throw new BenchmarkError('argument_value_invalid');
    if (argument === '--cold') coldRepetitions = value;
    else warmRepetitions = value;
    index += 1;
  }
  if (writeEvidence && (coldRepetitions < 30 || warmRepetitions < 30)) {
    throw new BenchmarkError('evidence_requires_30_repetitions');
  }
  return { coldRepetitions, warmRepetitions, writeEvidence };
}

async function copyBoundedFile(source: string, destination: string, state: { bytes: number }, limit: number): Promise<void> {
  const sourceStat = await lstat(source);
  if (!sourceStat.isFile()) throw new BenchmarkError('input_type_invalid');
  state.bytes += sourceStat.size;
  if (state.bytes > limit) throw new BenchmarkError('workspace_input_limit_exceeded');
  await mkdir(dirname(destination), { recursive: true });
  await copyFile(source, destination);
}

async function copyBoundedTree(source: string, destination: string, state: { bytes: number }, limit: number): Promise<void> {
  const sourceStat = await lstat(source);
  if (!sourceStat.isDirectory()) throw new BenchmarkError('input_type_invalid');
  await mkdir(destination, { recursive: true });
  const entries = await readdir(source, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name));
  for (const entry of entries) {
    const sourcePath = join(source, entry.name);
    const destinationPath = join(destination, entry.name);
    if (entry.isSymbolicLink()) throw new BenchmarkError('input_symlink_denied');
    if (entry.isDirectory()) await copyBoundedTree(sourcePath, destinationPath, state, limit);
    else if (entry.isFile()) await copyBoundedFile(sourcePath, destinationPath, state, limit);
    else throw new BenchmarkError('input_type_invalid');
  }
}

async function createWorkspace(workload: Workload): Promise<string> {
  const workspace = await mkdtemp(join(tmpdir(), 'hermternal-web-build-'));
  activeWorkspaces.add(workspace);
  try {
    const copied = { bytes: 0 };
    for (const inputFile of workload.build.input_files) {
      await copyBoundedFile(join(APP_ROOT, inputFile), join(workspace, inputFile), copied, workload.limits.workspace_input_bytes);
    }
    for (const inputRoot of workload.build.input_roots) {
      await copyBoundedTree(join(APP_ROOT, inputRoot), join(workspace, inputRoot), copied, workload.limits.workspace_input_bytes);
    }
    const copiedConfig = join(workspace, 'svelte.config.js');
    await rename(copiedConfig, join(workspace, 'svelte.config.source.js'));
    const deterministicConfig = `import config from './svelte.config.source.js';\n\n// The benchmark pins SvelteKit's otherwise timestamp-based version so identical\n// source inputs produce identical production artifacts across repetitions.\nexport default {\n  ...config,\n  kit: {\n    ...config.kit,\n    version: { name: ${JSON.stringify(workload.build.version_name)}, pollInterval: 0 }\n  }\n};\n`;
    copied.bytes += new TextEncoder().encode(deterministicConfig).byteLength;
    if (copied.bytes > workload.limits.workspace_input_bytes) throw new BenchmarkError('workspace_input_limit_exceeded');
    await writeFile(copiedConfig, deterministicConfig);
    const dependencies = join(APP_ROOT, 'node_modules');
    if (!(await stat(dependencies)).isDirectory()) throw new BenchmarkError('dependencies_missing');
    await symlink(dependencies, join(workspace, 'node_modules'), 'dir');
    await mkdir(join(workspace, '.home'), { recursive: true });
    await mkdir(join(workspace, '.tmp'), { recursive: true });
    return workspace;
  } catch (error) {
    await removeWorkspace(workspace);
    throw error;
  }
}

async function removeWorkspace(workspace: string): Promise<void> {
  await rm(workspace, { recursive: true, force: true });
  activeWorkspaces.delete(workspace);
}

async function measureArtifacts(
  root: string,
  limits: Workload['limits'],
  includeDigest = false
): Promise<{ files: number; bytes: number; sha256?: string }> {
  let files = 0;
  let bytes = 0;
  const records: Array<{ path: string; bytes: number; sha256: string }> = [];
  async function visit(directory: string): Promise<void> {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new BenchmarkError('artifact_symlink_denied');
      if (entry.isDirectory()) await visit(path);
      else if (entry.isFile()) {
        const fileStat = await stat(path);
        files += 1;
        bytes += fileStat.size;
        if (files > limits.artifact_files) throw new BenchmarkError('artifact_file_limit_exceeded');
        if (bytes > limits.artifact_bytes) throw new BenchmarkError('artifact_byte_limit_exceeded');
        if (includeDigest) {
          records.push({
            path: relative(root, path).split(sep).join('/'),
            bytes: fileStat.size,
            sha256: sha256(await readFile(path))
          });
        }
      } else throw new BenchmarkError('artifact_type_invalid');
    }
  }
  await visit(root);
  records.sort((left, right) => left.path.localeCompare(right.path));
  return { files, bytes, ...(includeDigest ? { sha256: sha256(canonicalBytes(records)) } : {}) };
}

async function consumeBounded(stream: ReadableStream<Uint8Array>, limit: number, onOverflow: () => void): Promise<number> {
  const reader = stream.getReader();
  let bytes = 0;
  let exceeded = false;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) return Math.min(bytes, limit + 1);
      bytes += result.value.byteLength;
      if (!exceeded && bytes > limit) {
        exceeded = true;
        onOverflow();
      }
    }
  } finally {
    reader.releaseLock();
  }
}

function isMissingPath(error: unknown): boolean {
  return isRecord(error) && error.code === 'ENOENT';
}

async function monitorArtifactLimits(
  outputPath: string,
  limits: Workload['limits'],
  shouldStop: () => boolean,
  onExceeded: (code: string) => void
): Promise<void> {
  while (!shouldStop()) {
    try {
      await measureArtifacts(outputPath, limits);
    } catch (error) {
      if (!isMissingPath(error)) {
        onExceeded(error instanceof BenchmarkError ? error.code : 'artifact_monitor_failed');
        return;
      }
    }
    await Bun.sleep(50);
  }
}

function benchmarkEnvironment(workspace: string, workload: Workload, nodePath: string): Record<string, string> {
  const executableDirectory = dirname(nodePath);
  return {
    PATH: [executableDirectory, '/usr/bin', '/bin'].join(delimiter),
    HOME: join(workspace, '.home'),
    TMPDIR: join(workspace, '.tmp'),
    CI: '1',
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    TZ: 'UTC',
    NO_COLOR: '1',
    NODE_ENV: 'production',
    npm_config_offline: 'true',
    npm_config_update_notifier: 'false',
    BUN_INSTALL_OFFLINE: '1',
    NODE_OPTIONS: `--max-old-space-size=${workload.limits.node_heap_megabytes} --import=${pathToFileURL(NETWORK_GUARD_PATH).href}`
  };
}

async function runBuild(workspace: string, workload: Workload, sequence: number): Promise<BuildObservation> {
  const nodePath = Bun.which('node');
  if (!nodePath) throw new BenchmarkError('node_runtime_missing');
  const entrypoint = join(workspace, workload.build.entrypoint);
  const command = [nodePath, entrypoint, ...workload.build.arguments];
  const start = performance.now();
  const child = Bun.spawn(command, {
    cwd: workspace,
    env: benchmarkEnvironment(workspace, workload, nodePath),
    stdin: 'ignore',
    stdout: 'pipe',
    stderr: 'pipe'
  });
  activeChild = child;
  let timedOut = false;
  let outputExceeded = false;
  let artifactFailure: string | undefined;
  let processFinished = false;
  const outputPath = join(workspace, workload.build.output_root);
  const timer = setTimeout(() => {
    timedOut = true;
    child.kill();
  }, workload.limits.build_timeout_ms);
  const onOverflow = () => {
    outputExceeded = true;
    child.kill();
  };
  const artifactMonitor = monitorArtifactLimits(
    outputPath,
    workload.limits,
    () => processFinished,
    (code) => {
      artifactFailure = code;
      child.kill();
    }
  );
  try {
    const [exitCode, stdoutBytes, stderrBytes] = await Promise.all([
      child.exited,
      consumeBounded(child.stdout, workload.limits.stdout_bytes, onOverflow),
      consumeBounded(child.stderr, workload.limits.stderr_bytes, onOverflow)
    ]);
    processFinished = true;
    await artifactMonitor;
    if (timedOut) throw new BenchmarkError('build_timeout');
    if (outputExceeded) throw new BenchmarkError('process_output_limit_exceeded');
    if (artifactFailure) throw new BenchmarkError(artifactFailure);
    if (exitCode !== 0) throw new BenchmarkError('production_build_failed');
    const artifacts = await measureArtifacts(outputPath, workload.limits, true);
    if (!artifacts.sha256) throw new BenchmarkError('artifact_digest_missing');
    return {
      sequence,
      duration_ms: Math.round((performance.now() - start) * 1000) / 1000,
      exit_code: exitCode,
      stdout_bytes: stdoutBytes,
      stderr_bytes: stderrBytes,
      artifact_files: artifacts.files,
      artifact_bytes: artifacts.bytes,
      artifact_sha256: artifacts.sha256
    };
  } finally {
    processFinished = true;
    if (child.exitCode === null) child.kill();
    await artifactMonitor;
    clearTimeout(timer);
    if (activeChild === child) activeChild = undefined;
  }
}

async function runCold(workload: Workload, repetitions: number): Promise<BuildObservation[]> {
  const observations: BuildObservation[] = [];
  for (let sequence = 1; sequence <= repetitions; sequence += 1) {
    const workspace = await createWorkspace(workload);
    try {
      observations.push(await runBuild(workspace, workload, sequence));
    } finally {
      await removeWorkspace(workspace);
    }
  }
  return observations;
}

async function runWarm(workload: Workload, repetitions: number): Promise<{ warmup: BuildObservation; observations: BuildObservation[] }> {
  const workspace = await createWorkspace(workload);
  try {
    const warmup = await runBuild(workspace, workload, 0);
    const observations: BuildObservation[] = [];
    for (let sequence = 1; sequence <= repetitions; sequence += 1) {
      observations.push(await runBuild(workspace, workload, sequence));
    }
    return { warmup, observations };
  } finally {
    await removeWorkspace(workspace);
  }
}

function safeCpuModel(): string {
  return (cpus()[0]?.model ?? 'unknown-cpu').replace(/[^A-Za-z0-9._ -]/g, '').slice(0, 80) || 'unknown-cpu';
}

function commandVersion(command: string, args: string[]): string {
  const result = Bun.spawnSync([command, ...args], { stdout: 'pipe', stderr: 'ignore' });
  if (result.exitCode !== 0 || result.stdout.byteLength > 128) throw new BenchmarkError('runtime_version_unavailable');
  return new TextDecoder().decode(result.stdout).trim();
}

function sourceCommit(): string {
  const result = Bun.spawnSync(['git', '-C', resolve(APP_ROOT, '..', '..'), 'rev-parse', 'HEAD'], {
    stdout: 'pipe',
    stderr: 'ignore'
  });
  const commit = new TextDecoder().decode(result.stdout).trim();
  if (result.exitCode !== 0 || !/^[0-9a-f]{40}$/.test(commit)) throw new BenchmarkError('source_commit_unavailable');
  return commit;
}

async function inputIdentity(workload: Workload): Promise<{ bytes: number; sha256: string }> {
  const records: Array<{ path: string; bytes: number; sha256: string }> = [];
  async function addFile(path: string): Promise<void> {
    const bytes = await readFile(path);
    records.push({ path: relative(APP_ROOT, path).split(sep).join('/'), bytes: bytes.byteLength, sha256: sha256(bytes) });
  }
  async function addTree(root: string): Promise<void> {
    const entries = await readdir(root, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const path = join(root, entry.name);
      if (entry.isDirectory()) await addTree(path);
      else if (entry.isFile()) await addFile(path);
      else throw new BenchmarkError('input_type_invalid');
    }
  }
  for (const inputFile of workload.build.input_files) await addFile(join(APP_ROOT, inputFile));
  for (const inputRoot of workload.build.input_roots) await addTree(join(APP_ROOT, inputRoot));
  records.sort((left, right) => left.path.localeCompare(right.path));
  return { bytes: records.reduce((total, record) => total + record.bytes, 0), sha256: sha256(canonicalBytes(records)) };
}

function sampleProvenance(run: { id: string; state: string; command: string; repetitions: number; raw_samples: number[] }): string {
  return sha256(canonicalBytes(run));
}

async function writeEvidenceFiles(
  workload: Workload,
  cold: BuildObservation[],
  warmup: BuildObservation,
  warm: BuildObservation[]
): Promise<void> {
  const workloadBytes = await readFile(WORKLOAD_PATH);
  const nodePath = Bun.which('node');
  if (!nodePath) throw new BenchmarkError('node_runtime_missing');
  const commitSha = sourceCommit();
  const input = await inputIdentity(workload);
  const artifactIdentities = [warmup, ...cold, ...warm].map((sample) => sample.artifact_sha256);
  if (new Set(artifactIdentities).size !== 1) throw new BenchmarkError('artifact_identity_drift');
  const environment = {
    platform: `${platform()}-${release()}`,
    os: `${type()}-${release()}`,
    architecture: arch(),
    device: `local-${safeCpuModel()}`,
    runtime: `Bun-${Bun.version}; Node-${commandVersion(nodePath, ['--version'])}; Vite-${commandVersion(nodePath, [join(APP_ROOT, 'node_modules/vite/bin/vite.js'), '--version'])}`,
    browser: 'not_applicable'
  };
  const trace = {
    schema: 'hermternal.web-production-build-trace.v1',
    recorded_at_utc: new Date().toISOString(),
    source_commit_sha: commitSha,
    fixture_sha256: sha256(workloadBytes),
    build_input: input,
    network_mode: 'deny',
    limits: workload.limits,
    warmup_excluded_from_distribution: warmup,
    runs: [
      { id: 'web-production-build-cold', state: 'cold', samples: cold },
      { id: 'web-production-build-warm', state: 'warm', samples: warm }
    ]
  };
  await mkdir(EVIDENCE_DIRECTORY, { recursive: true });
  const traceBytes = canonicalBytes(trace);
  await writeFile(TRACE_PATH, traceBytes);
  const command = 'node node_modules/vite/bin/vite.js build';
  const coldSamples = cold.map((sample) => sample.duration_ms);
  const warmSamples = warm.map((sample) => sample.duration_ms);
  const coldIdentity = {
    id: 'web-production-build-cold',
    state: 'cold',
    command,
    repetitions: coldSamples.length,
    raw_samples: coldSamples
  };
  const warmIdentity = {
    id: 'web-production-build-warm',
    state: 'warm',
    command,
    repetitions: warmSamples.length,
    raw_samples: warmSamples
  };
  const artifacts = [
    { path: 'workload.json', bytes: workloadBytes.byteLength, sha256: sha256(workloadBytes) },
    { path: 'evidence/raw-trace.json', bytes: traceBytes.byteLength, sha256: sha256(traceBytes) }
  ];
  const evidence = {
    schema: 'hermternal.benchmark-evidence.v1',
    evidence_id: 'web-production-build-baseline',
    revision: {
      commit_sha: commitSha,
      fixture_id: workload.fixture_id,
      fixture_version: workload.fixture_version,
      fixture_sha256: sha256(workloadBytes),
      hermes_source_sha: workload.hermes_source_sha
    },
    metric: { name: 'production_build_duration', unit: 'ms', clock: 'monotonic' },
    method: {
      percentile_method: 'inclusive_linear_interpolation_r7',
      position_formula: '(n - 1) * q',
      rounding: 'half_even_to_3_decimal_places',
      quantiles: { p50: 0.5, p95: 0.95, p99: 0.99 },
      minimum_repetitions: 30
    },
    runs: [
      {
        id: coldIdentity.id,
        platform: 'web',
        environment,
        state: coldIdentity.state,
        build_mode: 'production',
        optimization: 'not_applicable',
        command,
        repetitions: coldIdentity.repetitions,
        raw_samples: coldIdentity.raw_samples,
        sample_provenance_sha256: sampleProvenance(coldIdentity),
        distribution: distribution(coldIdentity.raw_samples)
      },
      {
        id: warmIdentity.id,
        platform: 'web',
        environment,
        state: warmIdentity.state,
        build_mode: 'production',
        optimization: 'not_applicable',
        command,
        repetitions: warmIdentity.repetitions,
        raw_samples: warmIdentity.raw_samples,
        sample_provenance_sha256: sampleProvenance(warmIdentity),
        distribution: distribution(warmIdentity.raw_samples)
      }
    ],
    artifacts,
    artifact_manifest_sha256: sha256(canonicalBytes(artifacts)),
    redaction: {
      policy: 'semantic_only',
      synthetic_only: true,
      contains_credentials: false,
      contains_tokens: false,
      contains_user_data: false,
      contains_live_hosts: false,
      contains_transcripts: false
    },
    threshold: null,
    budget: null
  };
  await writeFile(EVIDENCE_PATH, canonicalBytes(evidence));
}

async function loadWorkload(): Promise<Workload> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(WORKLOAD_PATH, 'utf8'));
  } catch {
    throw new BenchmarkError('workload_json_invalid');
  }
  return validateWorkload(parsed);
}

async function handleSignal(exitCode: number): Promise<void> {
  if (handlingSignal) return;
  handlingSignal = true;
  activeChild?.kill();
  await Promise.all([...activeWorkspaces].map((workspace) => removeWorkspace(workspace)));
  process.exit(exitCode);
}

async function main(): Promise<void> {
  process.once('SIGINT', () => void handleSignal(130));
  process.once('SIGTERM', () => void handleSignal(143));
  const workload = await loadWorkload();
  const options = parseArguments(process.argv.slice(2), workload);
  const cold = await runCold(workload, options.coldRepetitions);
  const warmResult = await runWarm(workload, options.warmRepetitions);
  const artifactIdentities = [warmResult.warmup, ...cold, ...warmResult.observations].map((sample) => sample.artifact_sha256);
  if (new Set(artifactIdentities).size !== 1) throw new BenchmarkError('artifact_identity_drift');
  if (options.writeEvidence) await writeEvidenceFiles(workload, cold, warmResult.warmup, warmResult.observations);
  const summary = {
    ok: true,
    cold: { repetitions: cold.length, distribution: distribution(cold.map((sample) => sample.duration_ms)) },
    warm: {
      repetitions: warmResult.observations.length,
      distribution: distribution(warmResult.observations.map((sample) => sample.duration_ms))
    },
    artifact_sha256: artifactIdentities[0],
    threshold: null,
    evidence_written: options.writeEvidence
  };
  process.stdout.write(`${JSON.stringify(summary)}\n`);
}

if (import.meta.main) {
  main().catch((error: unknown) => {
    const code = error instanceof BenchmarkError ? error.code : 'benchmark_failed';
    const output = JSON.stringify({ ok: false, error: code }).slice(0, MAX_ERROR_BYTES);
    process.stderr.write(`${output}\n`);
    process.exitCode = 2;
  });
}
