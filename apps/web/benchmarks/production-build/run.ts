import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants as fsConstants, mkdtempSync, realpathSync, writeFileSync } from 'node:fs';
import { copyFile, lstat, mkdir, mkdtemp, open, readdir, readFile, realpath, rename, stat, symlink, writeFile } from 'node:fs/promises';
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
const SANDBOX_RUNNER_PATH = join(BENCHMARK_ROOT, 'sandbox-runner.py');
const ARTIFACT_SCANNER_PATH = join(BENCHMARK_ROOT, 'artifact-scanner.py');
const SYSTEM_PYTHON_PATH = '/usr/bin/python3';
const MACOS_SANDBOX_PATH = '/usr/bin/sandbox-exec';
const LINUX_SANDBOX_PATH = '/usr/bin/bwrap';
const SIGNAL_CLEANUP_DEADLINE_MS = 10_000;
const MAX_WORKLOAD_BYTES = 16 * 1024;
const MAX_ERROR_BYTES = 512;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const activeWorkspaces = new Set<string>();
const activeRunRoots = new Set<string>();
const quotaDevices = new Map<string, string>();
let activeChild: ChildProcess | undefined;
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
  network: { mode: string; boundary: string };
  launcher: { supervisor_sha256: string; scanner_sha256: string };
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

function canonicalDigestBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(value));
}

function canonicalBytes(value: unknown): Uint8Array {
  const payload = canonicalDigestBytes(value);
  const output = new Uint8Array(payload.byteLength + 1);
  output.set(payload);
  output[payload.byteLength] = 10;
  return output;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function plainJsonSnapshot(value: unknown, code: string, depth = 0): unknown {
  if (depth > 16) throw new BenchmarkError(code);
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new BenchmarkError(code);
    return value;
  }
  if (typeof value !== 'object') throw new BenchmarkError(code);
  const array = Array.isArray(value);
  const expectedPrototype = array ? Array.prototype : Object.prototype;
  if (Object.getPrototypeOf(value) !== expectedPrototype) throw new BenchmarkError(code);
  const keys = Reflect.ownKeys(value);
  const copy: unknown[] | Record<string, unknown> = array ? [] : {};
  for (const key of keys) {
    if (typeof key !== 'string') throw new BenchmarkError(code);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (array && key === 'length') {
      if (!descriptor || descriptor.enumerable || !descriptor.writable || descriptor.configurable || descriptor.value !== keys.length - 1) {
        throw new BenchmarkError(code);
      }
      continue;
    }
    if (!descriptor || !descriptor.enumerable || !descriptor.writable || !descriptor.configurable || !('value' in descriptor)) {
      throw new BenchmarkError(code);
    }
    Object.defineProperty(copy, key, {
      value: plainJsonSnapshot(descriptor.value, code, depth + 1),
      enumerable: true,
      writable: false,
      configurable: false
    });
  }
  return Object.freeze(copy);
}

function requireExactKeys(candidate: Record<string, unknown>, expected: string[], code: string): void {
  const actual = Reflect.ownKeys(candidate);
  if (actual.some((key) => typeof key !== 'string')) throw new BenchmarkError(code);
  const actualStrings = (actual as string[]).sort();
  const required = [...expected].sort();
  if (actualStrings.length !== required.length || actualStrings.some((key, index) => key !== required[index])) {
    throw new BenchmarkError(code);
  }
}

function requirePositiveInteger(value: unknown, code: string): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) {
    throw new BenchmarkError(code);
  }
  return value as number;
}

export function validateWorkload(untrusted: unknown): Workload {
  const candidate = plainJsonSnapshot(untrusted, 'workload_json_semantics_invalid');
  if (!isRecord(candidate) || candidate.schema !== 'hermternal.web-production-build-workload.v1') {
    throw new BenchmarkError('workload_schema_invalid');
  }
  const build = candidate.build;
  const repetitions = candidate.repetitions;
  const limits = candidate.limits;
  const network = candidate.network;
  const launcher = candidate.launcher;
  if (!isRecord(build) || !isRecord(repetitions) || !isRecord(limits) || !isRecord(network) || !isRecord(launcher)) {
    throw new BenchmarkError('workload_shape_invalid');
  }
  requireExactKeys(candidate, ['schema', 'fixture_id', 'fixture_version', 'build', 'repetitions', 'limits', 'network', 'launcher', 'hermes_source_sha'], 'workload_keys_invalid');
  requireExactKeys(build, ['entrypoint', 'arguments', 'input_files', 'input_roots', 'output_root', 'version_name'], 'build_keys_invalid');
  requireExactKeys(repetitions, ['cold', 'warm', 'maximum'], 'repetition_keys_invalid');
  requireExactKeys(
    limits,
    ['build_timeout_ms', 'stdout_bytes', 'stderr_bytes', 'workspace_input_bytes', 'artifact_files', 'artifact_bytes', 'node_heap_megabytes'],
    'limit_keys_invalid'
  );
  requireExactKeys(network, ['mode', 'boundary'], 'network_keys_invalid');
  requireExactKeys(launcher, ['supervisor_sha256', 'scanner_sha256'], 'launcher_keys_invalid');
  const pathLists = [build.input_files, build.input_roots, build.arguments];
  if (
    candidate.fixture_id !== 'web-production-build' ||
    candidate.fixture_version !== '1.0.0' ||
    build.entrypoint !== 'node_modules/vite/bin/vite.js' ||
    build.output_root !== '.artifact-output/build' ||
    build.version_name !== 'hermternal-web-production-build-v1' ||
    pathLists.some((list) => !Array.isArray(list) || list.some((item) => typeof item !== 'string')) ||
    JSON.stringify(build.arguments) !== JSON.stringify(['build', '--configLoader', 'runner']) ||
    JSON.stringify(build.input_files) !==
      JSON.stringify(['package.json', 'bun.lock', 'svelte.config.js', 'tsconfig.json', 'vite.config.ts', '.svelte-kit/tsconfig.json']) ||
    JSON.stringify(build.input_roots) !== JSON.stringify(['src', 'static']) ||
    network.mode !== 'deny' ||
    network.boundary !== 'os_sandbox' ||
    typeof launcher.supervisor_sha256 !== 'string' || !SHA256_PATTERN.test(launcher.supervisor_sha256) ||
    typeof launcher.scanner_sha256 !== 'string' || !SHA256_PATTERN.test(launcher.scanner_sha256) ||
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

async function cloneDependencySnapshot(runRoot: string): Promise<string> {
  const source = join(APP_ROOT, 'node_modules');
  if (!(await stat(source)).isDirectory()) throw new BenchmarkError('dependencies_missing');
  const destination = join(runRoot, 'node_modules');
  const copyCommand = platform() === 'darwin'
    ? ['/bin/cp', '-cR', source, destination]
    : ['/bin/cp', '-a', '--reflink=auto', source, destination];
  const copied = spawnSync(copyCommand[0], copyCommand.slice(1), { stdio: 'ignore' });
  if (copied.status !== 0) throw new BenchmarkError('dependency_snapshot_failed');
  const protectedSnapshot = spawnSync('/bin/chmod', ['-R', 'a-w', destination], { stdio: 'ignore' });
  if (protectedSnapshot.status !== 0) throw new BenchmarkError('dependency_snapshot_failed');
  return destination;
}

function runChecked(command: string, args: string[], code: string): void {
  const result = spawnSync(command, args, { stdio: 'ignore' });
  if (result.status !== 0) throw new BenchmarkError(code);
}

export async function mountArtifactQuota(workspace: string, artifactBytes: number): Promise<void> {
  const output = join(workspace, '.artifact-output');
  await mkdir(output, { recursive: true });
  if (platform() !== 'darwin') return;
  const image = join(workspace, '.artifact-quota.sparseimage');
  // hdiutil's `b` suffix is a count of 512-byte sectors, not bytes.
  // Convert explicitly so filesystem capacity enforces the reviewed byte cap.
  const quotaSectors = Math.ceil(artifactBytes / 512);
  runChecked('/usr/bin/hdiutil', ['create', '-quiet', '-size', `${quotaSectors}b`, '-fs', 'HFS+', '-volname', 'hermternal-benchmark', '-type', 'SPARSE', '-nospotlight', image], 'artifact_quota_create_failed');
  runChecked('/usr/bin/hdiutil', ['attach', '-quiet', '-nobrowse', '-mountpoint', output, image], 'artifact_quota_mount_failed');
  const diskInfo = spawnSync('/usr/sbin/diskutil', ['info', '-plist', output], { encoding: 'utf8', maxBuffer: 16384 });
  const deviceMatch = typeof diskInfo.stdout === 'string'
    ? diskInfo.stdout.match(/<key>DeviceIdentifier<\/key>\s*<string>(disk[0-9]+s[0-9]+)<\/string>/)
    : null;
  if (diskInfo.status !== 0 || !deviceMatch) throw new BenchmarkError('artifact_quota_mount_failed');
  quotaDevices.set(workspace, `/dev/${deviceMatch[1]}`);
}

async function bindDependencySnapshot(workspace: string, dependencySnapshot: string): Promise<void> {
  const bindingRoot = join(workspace, 'node_modules');
  await mkdir(bindingRoot, { recursive: true });
  const entries = await readdir(dependencySnapshot, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name));
  for (const entry of entries) {
    // Vite owns this cache directory during config loading. Keep it local and
    // writable instead of binding the immutable snapshot's prior cache bytes.
    if (entry.name === '.vite-temp') continue;
    const source = join(dependencySnapshot, entry.name);
    const destination = join(bindingRoot, entry.name);
    if (entry.name.startsWith('@') && entry.isDirectory()) {
      await mkdir(destination, { recursive: true });
      const scoped = await readdir(source, { withFileTypes: true });
      for (const packageEntry of scoped) {
        if (!packageEntry.isDirectory() && !packageEntry.isSymbolicLink()) throw new BenchmarkError('dependency_type_invalid');
        await symlink(join(source, packageEntry.name), join(destination, packageEntry.name), 'dir');
      }
    } else {
      if (!entry.isDirectory() && !entry.isSymbolicLink()) throw new BenchmarkError('dependency_type_invalid');
      await symlink(source, destination, 'dir');
    }
  }
  // Every build-writable byte must remain below the one quota boundary. Vite's
  // config-runner cache keeps its expected path while resolving into that volume.
  await mkdir(join(workspace, '.artifact-output', '.vite-temp'), { recursive: true });
  await symlink('../.artifact-output/.vite-temp', join(bindingRoot, '.vite-temp'), 'dir');
}

async function createWorkspace(workload: Workload, dependencySnapshot: string): Promise<string> {
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
    const deterministicConfig = `import adapter from '@sveltejs/adapter-static';\nimport config from './svelte.config.source.js';\n\n// The benchmark pins SvelteKit's otherwise timestamp-based version so identical\n// source inputs produce identical production artifacts across repetitions. The\n// adapter and SvelteKit intermediates stay below the same quota mount. Keeping\n// their configured paths real preserves generated relative imports while bounding\n// peak bytes, not only the final scanned artifact extent.\nexport default {\n  ...config,\n  kit: {\n    ...config.kit,\n    outDir: '.artifact-output/.svelte-kit',\n    adapter: adapter({ pages: '.artifact-output/build', assets: '.artifact-output/build', fallback: '200.html' }),\n    version: { name: ${JSON.stringify(workload.build.version_name)}, pollInterval: 0 }\n  }\n};\n`;
    copied.bytes += new TextEncoder().encode(deterministicConfig).byteLength;
    if (copied.bytes > workload.limits.workspace_input_bytes) throw new BenchmarkError('workspace_input_limit_exceeded');
    await writeFile(copiedConfig, deterministicConfig);
    await mountArtifactQuota(workspace, workload.limits.artifact_bytes);
    await bindDependencySnapshot(workspace, dependencySnapshot);
    await mkdir(join(workspace, '.artifact-output', '.home'), { recursive: true });
    await mkdir(join(workspace, '.artifact-output', '.tmp'), { recursive: true });
    await mkdir(join(workspace, '.artifact-output', '.svelte-kit'), { recursive: true });
    return workspace;
  } catch (error) {
    await removeWorkspace(workspace);
    throw error;
  }
}

export async function removeWorkspace(workspace: string): Promise<void> {
  const quotaDevice = quotaDevices.get(workspace);
  if (quotaDevice) {
    // Detach by device: a full HFS+ volume may lose its mount point before
    // cleanup, but the attached disk must still be released before deletion.
    spawnSync('/usr/bin/hdiutil', ['detach', '-quiet', '-force', quotaDevice], { stdio: 'ignore', timeout: 60_000 });
    quotaDevices.delete(workspace);
  }
  spawnSync('/bin/chmod', ['-R', 'u+w', workspace], { stdio: 'ignore', timeout: 1000 });
  const removed = spawnSync('/bin/rm', ['-rf', workspace], { stdio: 'ignore', timeout: 3000 });
  if (removed.status !== 0) throw new BenchmarkError('workspace_cleanup_failed');
  activeWorkspaces.delete(workspace);
}

export async function measureArtifacts(
  root: string,
  workspace: string,
  limits: Workload['limits'],
  includeDigest = false
): Promise<{ files: number; bytes: number; sha256?: string }> {
  const relativeRoot = relative(workspace, root).split(sep).join('/');
  if (!relativeRoot || relativeRoot.startsWith('../') || relativeRoot === '..') {
    throw new BenchmarkError('artifact_root_escape');
  }
  const scanned = spawnSync(SYSTEM_PYTHON_PATH, [
    ARTIFACT_SCANNER_PATH,
    '--workspace', workspace,
    '--root', relativeRoot,
    '--max-files', String(limits.artifact_files),
    '--max-bytes', String(limits.artifact_bytes)
  ], { encoding: 'utf8', maxBuffer: 4096 });
  if (scanned.status !== 0 || typeof scanned.stdout !== 'string' || scanned.stdout.length > 1024) {
    throw new BenchmarkError('artifact_scan_failed');
  }
  let result: unknown;
  try {
    result = JSON.parse(scanned.stdout);
  } catch {
    throw new BenchmarkError('artifact_scan_failed');
  }
  result = plainJsonSnapshot(result, 'artifact_scan_invalid');
  const record = result as Record<string, unknown>;
  requireExactKeys(record, ['files', 'bytes', 'sha256'], 'artifact_scan_invalid');
  if (typeof record.files !== 'number' || !Number.isInteger(record.files) || record.files < 0 || record.files > limits.artifact_files ||
      typeof record.bytes !== 'number' || !Number.isInteger(record.bytes) || record.bytes < 0 || record.bytes > limits.artifact_bytes ||
      typeof record.sha256 !== 'string' || !SHA256_PATTERN.test(record.sha256)) {
    throw new BenchmarkError('artifact_scan_invalid');
  }
  return {
    files: record.files,
    bytes: record.bytes,
    ...(includeDigest ? { sha256: record.sha256 } : {})
  };
}

async function consumeBounded(
  stream: NodeJS.ReadableStream,
  limit: number,
  onOverflow: () => void,
  tailLimit = 0
): Promise<{ bytes: number; tail: string }> {
  let bytes = 0;
  let exceeded = false;
  let tail = Buffer.alloc(0);
  for await (const chunk of stream) {
    const value = Buffer.from(chunk);
    bytes += value.byteLength;
    if (tailLimit > 0) tail = Buffer.concat([tail, value]).subarray(-tailLimit);
    if (!exceeded && bytes > limit) {
      exceeded = true;
      onOverflow();
    }
  }
  return { bytes: Math.min(bytes, limit + 1), tail: tail.toString('utf8') };
}

function boundedWait<T>(promise: Promise<T>, timeoutMs: number, code: string): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) => setTimeout(() => reject(new BenchmarkError(code)), timeoutMs))
  ]);
}

function processGroupExists(pid: number): boolean {
  try {
    process.kill(-pid, 0);
    return true;
  } catch {
    return false;
  }
}

export async function terminateProcessGroup(child: ChildProcess, graceMs = 500): Promise<void> {
  if (child.pid === undefined) return;
  try {
    process.kill(-child.pid, 'SIGTERM');
  } catch {}
  const deadline = performance.now() + graceMs;
  while (processGroupExists(child.pid) && performance.now() < deadline) await Bun.sleep(20);
  if (processGroupExists(child.pid)) {
    try {
      process.kill(-child.pid, 'SIGKILL');
    } catch {}
    const forceDeadline = performance.now() + graceMs;
    while (processGroupExists(child.pid) && performance.now() < forceDeadline) await Bun.sleep(20);
  }
}

export interface ProtectedRuntime {
  nodePath: string;
  pythonPath: string;
  sandboxPath: string;
}

async function fixedExecutable(candidates: string[], code: string): Promise<string> {
  for (const candidate of candidates) {
    try {
      const resolved = await realpath(candidate);
      const metadata = await stat(resolved);
      if (metadata.isFile() && (metadata.mode & 0o111) !== 0) return resolved;
    } catch {}
  }
  throw new BenchmarkError(code);
}

export async function protectedRuntime(workload: Workload): Promise<ProtectedRuntime> {
  const pythonPath = await fixedExecutable([SYSTEM_PYTHON_PATH], 'python_runtime_missing');
  const sandboxPath = await fixedExecutable(
    [platform() === 'darwin' ? MACOS_SANDBOX_PATH : LINUX_SANDBOX_PATH],
    'sandbox_runtime_missing'
  );
  const nodePath = await fixedExecutable(
    platform() === 'darwin'
      ? ['/opt/homebrew/bin/node', '/usr/local/bin/node', '/usr/bin/node']
      : ['/usr/bin/node', '/usr/local/bin/node'],
    'node_runtime_missing'
  );
  const supervisor = await fileIdentity(SANDBOX_RUNNER_PATH);
  const scanner = await fileIdentity(ARTIFACT_SCANNER_PATH);
  if (supervisor.sha256 !== workload.launcher.supervisor_sha256 || scanner.sha256 !== workload.launcher.scanner_sha256) {
    throw new BenchmarkError('protected_helper_identity_mismatch');
  }
  return { nodePath, pythonPath, sandboxPath };
}

export function sandboxLauncher(
  runtime: ProtectedRuntime,
  workspace: string,
  dependencySnapshot: string,
  artifactBytes: number,
  command: string[],
  resultFd = -1,
  artifactFiles = 10_000
): { command: string; args: string[] } {
  const canonicalWorkspace = realpathSync(workspace);
  const canonicalDependencySnapshot = realpathSync(dependencySnapshot);
  const supervised = [
    runtime.pythonPath,
    '-I',
    '-S',
    SANDBOX_RUNNER_PATH,
    '--workspace',
    canonicalWorkspace,
    '--result-fd',
    String(resultFd),
    '--scanner',
    ARTIFACT_SCANNER_PATH,
    '--artifact-root',
    '.artifact-output/build',
    '--max-files',
    String(artifactFiles),
    '--max-bytes',
    String(artifactBytes),
    '--',
    ...command
  ];
  if (platform() === 'darwin') {
    const writableRoot = join(canonicalWorkspace, '.artifact-output').replaceAll('"', '');
    const dependencyRoot = canonicalDependencySnapshot.replaceAll('"', '');
    const profile = [
      '(version 1)',
      '(allow default)',
      '(deny network*)',
      '(deny file-write*)',
      // The supervisor may spawn the measured Node process and scanner. The
      // measured executable itself cannot fork, so fast daemons cannot escape
      // ancestry acquisition between polls.
      `(deny process-fork (process-path "${runtime.nodePath.replaceAll('"', '')}"))`,
      `(allow file-write* (subpath "${writableRoot}"))`,
      '(allow file-write* (literal "/dev/null"))',
      `(deny file-write* (subpath "${dependencyRoot}"))`
    ].join('');
    return { command: runtime.sandboxPath, args: ['-p', profile, ...supervised] };
  }
  return {
    command: runtime.sandboxPath,
    args: [
      '--die-with-parent',
      '--unshare-net',
      '--unshare-pid',
      '--as-pid-1',
      '--new-session',
      '--ro-bind', '/', '/',
      // The measured process can write only to this aggregate quota. The
      // supervisor scans it before the private mount namespace is destroyed.
      '--size', String(artifactBytes),
      '--tmpfs', join(canonicalWorkspace, '.artifact-output'),
      '--ro-bind', canonicalDependencySnapshot, canonicalDependencySnapshot,
      '--',
      ...supervised
    ]
  };
}

function benchmarkEnvironment(workspace: string, workload: Workload, nodePath: string): Record<string, string> {
  const executableDirectory = dirname(nodePath);
  return {
    PATH: [executableDirectory, '/usr/bin', '/bin'].join(delimiter),
    HOME: join(workspace, '.artifact-output', '.home'),
    TMPDIR: join(workspace, '.artifact-output', '.tmp'),
    CI: '1',
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    TZ: 'UTC',
    NO_COLOR: '1',
    NODE_ENV: 'production',
    npm_config_offline: 'true',
    npm_config_update_notifier: 'false',
    BUN_INSTALL_OFFLINE: '1',
    NODE_OPTIONS: `--max-old-space-size=${workload.limits.node_heap_megabytes}`
  };
}

async function runBuild(
  workspace: string,
  dependencySnapshot: string,
  workload: Workload,
  runtime: ProtectedRuntime,
  sequence: number
): Promise<BuildObservation> {
  const entrypoint = join(workspace, workload.build.entrypoint);
  const executedCommand = [runtime.nodePath, entrypoint, ...workload.build.arguments];
  // The first child is the fixed OS sandbox executable. Python startup and the
  // reviewed supervisor helper therefore occur only after network denial exists.
  const launcher = sandboxLauncher(
    runtime,
    workspace,
    dependencySnapshot,
    workload.limits.artifact_bytes,
    executedCommand,
    1,
    workload.limits.artifact_files
  );
  const child = spawn(launcher.command, launcher.args, {
    cwd: workspace,
    env: benchmarkEnvironment(workspace, workload, runtime.nodePath),
    detached: true,
    stdio: ['ignore', 'pipe', 'pipe']
  });
  activeChild = child;
  let timedOut = false;
  let outputExceeded = false;
  const stopTree = () => void terminateProcessGroup(child);
  const timer = setTimeout(() => {
    timedOut = true;
    stopTree();
  }, workload.limits.build_timeout_ms);
  const onOverflow = () => {
    outputExceeded = true;
    stopTree();
  };
  if (!child.stdout || !child.stderr) throw new BenchmarkError('production_build_spawn_failed');
  // The supervisor writes one canonical result line after the measured command
  // and after descendant cleanup. Retaining only a bounded stdout tail prevents
  // a build from forging the final authenticated observation.
  const stdoutDrain = consumeBounded(child.stdout, workload.limits.stdout_bytes, onOverflow, 1024);
  const stderrDrain = consumeBounded(child.stderr, workload.limits.stderr_bytes, onOverflow);
  try {
    const exitCode = await new Promise<number>((resolve, reject) => {
      child.once('error', () => reject(new BenchmarkError('production_build_spawn_failed')));
      child.once('exit', (code) => resolve(code ?? 128));
    });
    await terminateProcessGroup(child);
    const [stdoutResult, stderrResult] = await boundedWait(
      Promise.all([stdoutDrain, stderrDrain]),
      1000,
      'process_pipe_drain_timeout'
    );
    const stdoutBytes = stdoutResult.bytes;
    const stderrBytes = stderrResult.bytes;
    if (timedOut) throw new BenchmarkError('build_timeout');
    if (outputExceeded) throw new BenchmarkError('process_output_limit_exceeded');
    if (exitCode !== 0) throw new BenchmarkError('production_build_failed');
    let supervisorResult: unknown;
    try {
      const resultLine = stdoutResult.tail.trimEnd().split('\n').at(-1);
      if (!resultLine?.startsWith('HERMTERNAL_RESULT ')) throw new Error('missing');
      supervisorResult = JSON.parse(resultLine.slice('HERMTERNAL_RESULT '.length));
    } catch {
      throw new BenchmarkError('supervisor_result_invalid');
    }
    supervisorResult = plainJsonSnapshot(supervisorResult, 'supervisor_result_invalid');
    const resultRecord = supervisorResult as Record<string, unknown>;
    requireExactKeys(resultRecord, ['exit_code', 'duration_us', 'artifact_files', 'artifact_bytes', 'artifact_sha256'], 'supervisor_result_invalid');
    if (
      resultRecord.exit_code !== 0 ||
      !Number.isSafeInteger(resultRecord.duration_us) || (resultRecord.duration_us as number) <= 0 ||
      !Number.isSafeInteger(resultRecord.artifact_files) || (resultRecord.artifact_files as number) < 0 ||
      (resultRecord.artifact_files as number) > workload.limits.artifact_files ||
      !Number.isSafeInteger(resultRecord.artifact_bytes) || (resultRecord.artifact_bytes as number) < 0 ||
      (resultRecord.artifact_bytes as number) > workload.limits.artifact_bytes ||
      typeof resultRecord.artifact_sha256 !== 'string' || !SHA256_PATTERN.test(resultRecord.artifact_sha256)
    ) {
      throw new BenchmarkError('supervisor_result_invalid');
    }
    const durationMs = (resultRecord.duration_us as number) / 1000;
    const artifacts = {
      files: resultRecord.artifact_files as number,
      bytes: resultRecord.artifact_bytes as number,
      sha256: resultRecord.artifact_sha256 as string
    };
    return {
      sequence,
      duration_ms: durationMs,
      exit_code: exitCode,
      stdout_bytes: stdoutBytes,
      stderr_bytes: stderrBytes,
      artifact_files: artifacts.files,
      artifact_bytes: artifacts.bytes,
      artifact_sha256: artifacts.sha256
    };
  } finally {
    clearTimeout(timer);
    await terminateProcessGroup(child);
    child.stdout?.destroy();
    child.stderr?.destroy();
    if (activeChild === child) activeChild = undefined;
  }
}

async function runCold(workload: Workload, dependencySnapshot: string, runtime: ProtectedRuntime, repetitions: number): Promise<BuildObservation[]> {
  const observations: BuildObservation[] = [];
  for (let sequence = 1; sequence <= repetitions; sequence += 1) {
    const workspace = await createWorkspace(workload, dependencySnapshot);
    try {
      observations.push(await runBuild(workspace, dependencySnapshot, workload, runtime, sequence));
    } finally {
      await removeWorkspace(workspace);
    }
  }
  return observations;
}

async function runWarm(
  workload: Workload,
  dependencySnapshot: string,
  runtime: ProtectedRuntime,
  repetitions: number
): Promise<{ warmup: BuildObservation; observations: BuildObservation[] }> {
  const workspace = await createWorkspace(workload, dependencySnapshot);
  try {
    const warmup = await runBuild(workspace, dependencySnapshot, workload, runtime, 0);
    const observations: BuildObservation[] = [];
    for (let sequence = 1; sequence <= repetitions; sequence += 1) {
      observations.push(await runBuild(workspace, dependencySnapshot, workload, runtime, sequence));
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
  const result = Bun.spawnSync(['/usr/bin/git', '-C', resolve(APP_ROOT, '..', '..'), 'rev-parse', 'HEAD'], {
    stdout: 'pipe',
    stderr: 'ignore'
  });
  const commit = new TextDecoder().decode(result.stdout).trim();
  if (result.exitCode !== 0 || !/^[0-9a-f]{40}$/.test(commit)) throw new BenchmarkError('source_commit_unavailable');
  return commit;
}

interface TreeIdentity { files: number; symlinks: number; bytes: number; sha256: string }

async function treeIdentity(root: string): Promise<TreeIdentity> {
  const resolvedRoot = await realpath(root);
  const records: Array<{ path: string; type: 'file' | 'symlink'; bytes: number; sha256: string }> = [];
  async function visit(directory: string): Promise<void> {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const path = join(directory, entry.name);
      const metadata = await lstat(path);
      if (metadata.isDirectory()) await visit(path);
      else if (metadata.isFile()) {
        const handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
        try {
          const opened = await handle.stat();
          records.push({
            path: relative(root, path).split(sep).join('/'),
            type: 'file',
            bytes: opened.size,
            sha256: sha256(await handle.readFile())
          });
        } finally {
          await handle.close();
        }
      } else if (metadata.isSymbolicLink()) {
        const target = await realpath(path);
        if (target !== resolvedRoot && !target.startsWith(`${resolvedRoot}${sep}`)) {
          throw new BenchmarkError('dependency_symlink_escape');
        }
        const targetText = relative(dirname(path), target).split(sep).join('/');
        records.push({ path: relative(root, path).split(sep).join('/'), type: 'symlink', bytes: 0, sha256: sha256(targetText) });
      } else throw new BenchmarkError('dependency_type_invalid');
    }
  }
  await visit(root);
  records.sort((left, right) => left.path.localeCompare(right.path));
  return {
    files: records.filter((record) => record.type === 'file').length,
    symlinks: records.filter((record) => record.type === 'symlink').length,
    bytes: records.reduce((total, record) => total + record.bytes, 0),
    sha256: sha256(new TextEncoder().encode(JSON.stringify(records)))
  };
}

async function fileIdentity(path: string): Promise<{ bytes: number; sha256: string }> {
  const resolved = await realpath(path);
  const handle = await open(resolved, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile()) throw new BenchmarkError('toolchain_file_invalid');
    return { bytes: metadata.size, sha256: sha256(await handle.readFile()) };
  } finally {
    await handle.close();
  }
}

async function toolchainIdentity(dependencySnapshot: string, runtime: ProtectedRuntime): Promise<Record<string, unknown>> {
  return {
    package_json: await fileIdentity(join(APP_ROOT, 'package.json')),
    bun_lock: await fileIdentity(join(APP_ROOT, 'bun.lock')),
    benchmark_runner: await fileIdentity(import.meta.path),
    sandbox_runner: await fileIdentity(SANDBOX_RUNNER_PATH),
    artifact_scanner: await fileIdentity(ARTIFACT_SCANNER_PATH),
    node_executable: await fileIdentity(runtime.nodePath),
    bun_executable: await fileIdentity(process.execPath),
    python_executable: await fileIdentity(runtime.pythonPath),
    sandbox_executable: await fileIdentity(runtime.sandboxPath),
    dependencies: await treeIdentity(dependencySnapshot),
    vite: await treeIdentity(join(dependencySnapshot, 'vite')),
    sveltekit: await treeIdentity(join(dependencySnapshot, '@sveltejs', 'kit')),
    vite_svelte_plugin: await treeIdentity(join(dependencySnapshot, '@sveltejs', 'vite-plugin-svelte')),
    svelte: await treeIdentity(join(dependencySnapshot, 'svelte')),
    typescript_native: await treeIdentity(join(dependencySnapshot, '@typescript', 'native'))
  };
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

function sampleProvenance(run: Record<string, unknown>): string {
  return sha256(canonicalDigestBytes(run));
}

async function writeEvidenceFiles(
  workload: Workload,
  runtime: ProtectedRuntime,
  toolchain: Record<string, unknown>,
  cold: BuildObservation[],
  warmup: BuildObservation,
  warm: BuildObservation[]
): Promise<void> {
  const workloadBytes = await readFile(WORKLOAD_PATH);
  const nodePath = runtime.nodePath;
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
  const command = ['node', workload.build.entrypoint, ...workload.build.arguments].join(' ');
  const coldSamples = cold.map((sample) => sample.duration_ms);
  const warmSamples = warm.map((sample) => sample.duration_ms);
  const coldIdentity = {
    id: 'web-production-build-cold',
    platform: 'web',
    environment,
    state: 'cold',
    build_mode: 'production',
    optimization: 'not_applicable',
    command,
    repetitions: coldSamples.length,
    raw_samples: coldSamples
  };
  const warmIdentity = {
    id: 'web-production-build-warm',
    platform: 'web',
    environment,
    state: 'warm',
    build_mode: 'production',
    optimization: 'not_applicable',
    command,
    repetitions: warmSamples.length,
    raw_samples: warmSamples
  };
  const trace = {
    schema: 'hermternal.web-production-build-trace.v1',
    recorded_at_utc: new Date().toISOString(),
    source_commit_sha: commitSha,
    fixture_sha256: sha256(workloadBytes),
    environment,
    build_input: input,
    toolchain,
    network_mode: 'os_sandbox_deny',
    limits: workload.limits,
    warmup_excluded_from_distribution: warmup,
    runs: [
      { provenance: coldIdentity, samples: cold },
      { provenance: warmIdentity, samples: warm }
    ]
  };
  await mkdir(EVIDENCE_DIRECTORY, { recursive: true });
  const traceBytes = canonicalBytes(trace);
  await writeFile(TRACE_PATH, traceBytes);
  const artifacts = [];
  for (const [path, absolutePath] of [
    ['workload.json', WORKLOAD_PATH],
    ['run.ts', import.meta.path],
    ['sandbox-runner.py', SANDBOX_RUNNER_PATH],
    ['artifact-scanner.py', ARTIFACT_SCANNER_PATH]
  ] as const) {
    const bytes = await readFile(absolutePath);
    artifacts.push({ path, bytes: bytes.byteLength, sha256: sha256(bytes) });
  }
  artifacts.push({ path: 'evidence/raw-trace.json', bytes: traceBytes.byteLength, sha256: sha256(traceBytes) });
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
    artifact_manifest_sha256: sha256(canonicalDigestBytes(artifacts)),
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
  let raw: Uint8Array;
  let parsed: unknown;
  try {
    const handle = await open(WORKLOAD_PATH, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    try {
      const buffer = new Uint8Array(MAX_WORKLOAD_BYTES + 1);
      const { bytesRead } = await handle.read(buffer, 0, buffer.byteLength, 0);
      if (bytesRead > MAX_WORKLOAD_BYTES) throw new Error('oversized');
      raw = buffer.slice(0, bytesRead);
    } finally {
      await handle.close();
    }
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
  } catch {
    throw new BenchmarkError('workload_json_invalid');
  }
  const workload = validateWorkload(parsed);
  const canonical = canonicalBytes(workload);
  if (raw.byteLength !== canonical.byteLength || raw.some((byte, index) => byte !== canonical[index])) {
    // Canonical equality also rejects duplicate keys because JSON.parse would
    // collapse them before the exact byte comparison.
    throw new BenchmarkError('workload_json_not_canonical');
  }
  return workload;
}

async function removeRunRoot(runRoot: string): Promise<void> {
  spawnSync('/bin/chmod', ['-R', 'u+w', runRoot], { stdio: 'ignore', timeout: 1000 });
  const removed = spawnSync('/bin/rm', ['-rf', runRoot], { stdio: 'ignore', timeout: 3000 });
  if (removed.status !== 0) throw new BenchmarkError('run_root_cleanup_failed');
  activeRunRoots.delete(runRoot);
}

function remainingCleanupMs(deadline: number): number {
  return Math.max(1, Math.floor(deadline - performance.now()));
}

async function handleSignal(exitCode: number): Promise<void> {
  if (handlingSignal) return;
  handlingSignal = true;
  const deadline = performance.now() + SIGNAL_CLEANUP_DEADLINE_MS;
  try {
    if (activeChild) await terminateProcessGroup(activeChild, Math.min(1500, remainingCleanupMs(deadline)));
    for (const workspace of [...activeWorkspaces]) {
      const quotaDevice = quotaDevices.get(workspace);
      if (quotaDevice) {
        const detached = spawnSync('/usr/bin/hdiutil', ['detach', '-quiet', '-force', quotaDevice], {
          stdio: 'ignore', timeout: remainingCleanupMs(deadline)
        });
        if (detached.status !== 0) throw new BenchmarkError('signal_cleanup_failed');
        quotaDevices.delete(workspace);
      }
      spawnSync('/bin/chmod', ['-R', 'u+w', workspace], { stdio: 'ignore', timeout: remainingCleanupMs(deadline) });
      const removed = spawnSync('/bin/rm', ['-rf', workspace], { stdio: 'ignore', timeout: remainingCleanupMs(deadline) });
      if (removed.status !== 0) throw new BenchmarkError('signal_cleanup_failed');
      activeWorkspaces.delete(workspace);
    }
    for (const runRoot of [...activeRunRoots]) {
      spawnSync('/bin/chmod', ['-R', 'u+w', runRoot], { stdio: 'ignore', timeout: remainingCleanupMs(deadline) });
      const removed = spawnSync('/bin/rm', ['-rf', runRoot], { stdio: 'ignore', timeout: remainingCleanupMs(deadline) });
      if (removed.status !== 0) throw new BenchmarkError('signal_cleanup_failed');
      activeRunRoots.delete(runRoot);
    }
    if (performance.now() > deadline || activeWorkspaces.size || activeRunRoots.size) {
      throw new BenchmarkError('signal_cleanup_timeout');
    }
    process.exit(exitCode);
  } catch {
    // A cleanup failure is not reported as successful signal completion.
    process.exit(2);
  }
}

async function main(): Promise<void> {
  process.once('SIGINT', () => void handleSignal(130));
  process.once('SIGTERM', () => void handleSignal(143));
  const workload = await loadWorkload();
  const options = parseArguments(process.argv.slice(2), workload);
  // Synchronous creation and registration form one signal-free JavaScript turn;
  // SIGINT/SIGTERM can no longer observe an unregistered on-disk run root.
  const runRoot = mkdtempSync(join(tmpdir(), 'hermternal-web-benchmark-'));
  activeRunRoots.add(runRoot);
  try {
    const dependencySnapshot = await cloneDependencySnapshot(runRoot);
    const runtime = await protectedRuntime(workload);
    const toolchain = await toolchainIdentity(dependencySnapshot, runtime);
    const readinessFile = process.env.HERMTERNAL_BENCHMARK_READY_FILE;
    if (readinessFile) {
      const readinessPath = resolve(readinessFile);
      const readinessParent = realpathSync(dirname(readinessPath));
      if (readinessParent === realpathSync(tmpdir()) && readinessPath.split(sep).at(-1)?.startsWith('hermternal-benchmark-ready-')) {
        // Readiness means dependency cloning, helper verification, and toolchain
        // identity are complete. Signal tests cannot race an ordinary startup error.
        try { writeFileSync(readinessPath, 'ready\n', { flag: 'wx', mode: 0o600 }); } catch {}
      }
    }
    const cold = await runCold(workload, dependencySnapshot, runtime, options.coldRepetitions);
    const warmResult = await runWarm(workload, dependencySnapshot, runtime, options.warmRepetitions);
    const artifactIdentities = [warmResult.warmup, ...cold, ...warmResult.observations].map((sample) => sample.artifact_sha256);
    if (new Set(artifactIdentities).size !== 1) throw new BenchmarkError('artifact_identity_drift');
    const finalToolchain = await toolchainIdentity(dependencySnapshot, runtime);
    if (JSON.stringify(toolchain) !== JSON.stringify(finalToolchain)) throw new BenchmarkError('dependency_snapshot_mutated');
    if (options.writeEvidence) await writeEvidenceFiles(workload, runtime, toolchain, cold, warmResult.warmup, warmResult.observations);
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
  } finally {
    await removeRunRoot(runRoot);
  }
}

if (import.meta.main) {
  main().catch((error: unknown) => {
    const code = error instanceof BenchmarkError ? error.code : 'benchmark_failed';
    const output = JSON.stringify({ ok: false, error: code }).slice(0, MAX_ERROR_BYTES);
    process.stderr.write(`${output}\n`);
    process.exitCode = 2;
  });
}
