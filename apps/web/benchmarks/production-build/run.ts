import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants as fsConstants, mkdtempSync, realpathSync, writeFileSync } from 'node:fs';
import { copyFile, lstat, mkdir, mkdtemp, open, readFile, readdir, readlink, realpath, rename, stat, symlink, writeFile, type FileHandle } from 'node:fs/promises';
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
const TRANSIENT_DEPENDENCY_ENTRIES = ['.vite', '.vite-temp'] as const;
const SIGNAL_CLEANUP_DEADLINE_MS = 10_000;
const SERIES_CLEANUP_GRACE_MS = 2_000;
export const MAX_JSON_BYTES = 16 * 1024;
const MAX_ERROR_BYTES = 512;
const GENERATED_SVELTE_TSCONFIG = `{
  "compilerOptions": {
    "paths": {
      "$lib": ["../src/lib"],
      "$lib/*": ["../src/lib/*"],
      "$app/types": ["./types/index.d.ts"]
    },
    "rootDirs": ["..", "./types"],
    "verbatimModuleSyntax": true,
    "isolatedModules": true,
    "lib": ["esnext", "DOM", "DOM.Iterable"],
    "moduleResolution": "bundler",
    "module": "esnext",
    "noEmit": true,
    "target": "esnext"
  },
  "include": [
    "ambient.d.ts",
    "env.d.ts",
    "non-ambient.d.ts",
    "./types/**/$types.d.ts",
    "../vite.config.js",
    "../vite.config.ts",
    "../src/**/*.js",
    "../src/**/*.ts",
    "../src/**/*.svelte",
    "../test/**/*.js",
    "../test/**/*.ts",
    "../test/**/*.svelte",
    "../tests/**/*.js",
    "../tests/**/*.ts",
    "../tests/**/*.svelte"
  ],
  "exclude": [
    "../node_modules/**",
    "../src/service-worker.js",
    "../src/service-worker/**/*.js",
    "../src/service-worker.ts",
    "../src/service-worker/**/*.ts",
    "../src/service-worker.d.ts",
    "../src/service-worker/**/*.d.ts"
  ]
}\n`;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const PACKAGE_VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/;
const activeWorkspaces = new Set<string>();
const activeRunRoots = new Set<string>();
const quotaDevices = new Map<string, string>();
let activeChild: ChildProcess | undefined;
let handlingSignal = false;

export interface FileIdentity {
  bytes: number;
  sha256: string;
}

export interface TreeIdentity extends FileIdentity {
  files: number;
  symlinks: number;
}

export interface RuntimeIdentity {
  node: FileIdentity;
  bun: FileIdentity;
  python: FileIdentity;
  sandbox: FileIdentity;
}

interface IntegrityAnchors {
  package_json: FileIdentity;
  bun_lock: FileIdentity;
  dependencies: TreeIdentity;
  vite: TreeIdentity;
  sveltekit: TreeIdentity;
  vite_svelte_plugin: TreeIdentity;
  svelte: TreeIdentity;
  typescript_native: TreeIdentity;
  runtime: Partial<Record<'darwin' | 'linux', RuntimeIdentity>>;
}

interface PackageManagerPin {
  name: string;
  version: string;
  install_args: string[];
}

interface ToolchainPin {
  bun_version: string;
  node_version: string;
}

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
  package_manager: PackageManagerPin;
  toolchain: ToolchainPin;
  integrity: IntegrityAnchors;
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
  const packageManager = candidate.package_manager;
  const toolchain = candidate.toolchain;
  const integrity = candidate.integrity;
  if (
    !isRecord(build) || !isRecord(repetitions) || !isRecord(limits) || !isRecord(network) ||
    !isRecord(launcher) || !isRecord(packageManager) || !isRecord(toolchain) || !isRecord(integrity) || !isRecord(integrity.runtime)
  ) {
    throw new BenchmarkError('workload_shape_invalid');
  }
  requireExactKeys(
    candidate,
    ['schema', 'fixture_id', 'fixture_version', 'build', 'repetitions', 'limits', 'network', 'launcher', 'package_manager', 'toolchain', 'integrity', 'hermes_source_sha'],
    'workload_keys_invalid'
  );
  requireExactKeys(build, ['entrypoint', 'arguments', 'input_files', 'input_roots', 'output_root', 'version_name'], 'build_keys_invalid');
  requireExactKeys(repetitions, ['cold', 'warm', 'maximum'], 'repetition_keys_invalid');
  requireExactKeys(
    limits,
    ['build_timeout_ms', 'stdout_bytes', 'stderr_bytes', 'workspace_input_bytes', 'artifact_files', 'artifact_bytes', 'node_heap_megabytes'],
    'limit_keys_invalid'
  );
  requireExactKeys(network, ['mode', 'boundary'], 'network_keys_invalid');
  requireExactKeys(launcher, ['supervisor_sha256', 'scanner_sha256'], 'launcher_keys_invalid');
  requireExactKeys(packageManager, ['name', 'version', 'install_args'], 'package_manager_keys_invalid');
  requireExactKeys(toolchain, ['bun_version', 'node_version'], 'toolchain_keys_invalid');
  requireExactKeys(
    integrity,
    ['package_json', 'bun_lock', 'dependencies', 'vite', 'sveltekit', 'vite_svelte_plugin', 'svelte', 'typescript_native', 'runtime'],
    'integrity_keys_invalid'
  );
  const runtimeKeys = Reflect.ownKeys(integrity.runtime);
  if (
    runtimeKeys.some((key) => typeof key !== 'string' || (key !== 'darwin' && key !== 'linux')) ||
    !runtimeKeys.includes('darwin') || runtimeKeys.length > 2
  ) {
    throw new BenchmarkError('runtime_anchor_keys_invalid');
  }
  const fileAnchors = [integrity.package_json, integrity.bun_lock];
  const treeAnchors = [
    integrity.dependencies,
    integrity.vite,
    integrity.sveltekit,
    integrity.vite_svelte_plugin,
    integrity.svelte,
    integrity.typescript_native
  ];
  if (
    fileAnchors.some((value) => !isRecord(value)) ||
    treeAnchors.some((value) => !isRecord(value)) ||
    Object.values(integrity.runtime).some((value) => !isRecord(value))
  ) {
    throw new BenchmarkError('integrity_shape_invalid');
  }
  for (const anchor of fileAnchors) {
    requireExactKeys(anchor, ['bytes', 'sha256'], 'file_integrity_keys_invalid');
    if (!Number.isSafeInteger(anchor.bytes) || anchor.bytes <= 0 || typeof anchor.sha256 !== 'string' || !SHA256_PATTERN.test(anchor.sha256)) {
      throw new BenchmarkError('file_integrity_invalid');
    }
  }
  for (const anchor of treeAnchors) {
    requireExactKeys(anchor, ['files', 'symlinks', 'bytes', 'sha256'], 'tree_integrity_keys_invalid');
    if (
      !Number.isSafeInteger(anchor.files) || anchor.files <= 0 ||
      !Number.isSafeInteger(anchor.symlinks) || anchor.symlinks < 0 ||
      !Number.isSafeInteger(anchor.bytes) || anchor.bytes <= 0 ||
      typeof anchor.sha256 !== 'string' || !SHA256_PATTERN.test(anchor.sha256)
    ) {
      throw new BenchmarkError('tree_integrity_invalid');
    }
  }
  for (const runtimeAnchor of Object.values(integrity.runtime)) {
    requireExactKeys(runtimeAnchor, ['node', 'bun', 'python', 'sandbox'], 'runtime_integrity_keys_invalid');
    for (const anchor of Object.values(runtimeAnchor)) {
      if (!isRecord(anchor)) throw new BenchmarkError('runtime_integrity_invalid');
      requireExactKeys(anchor, ['bytes', 'sha256'], 'runtime_integrity_keys_invalid');
      if (!Number.isSafeInteger(anchor.bytes) || anchor.bytes <= 0 || typeof anchor.sha256 !== 'string' || !SHA256_PATTERN.test(anchor.sha256)) {
        throw new BenchmarkError('runtime_integrity_invalid');
      }
    }
  }
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
      JSON.stringify(['package.json', '.bun-version', 'bun.lock', 'svelte.config.js', 'tsconfig.json', 'vite.config.ts']) ||
    JSON.stringify(build.input_roots) !== JSON.stringify(['src', 'static']) ||
    packageManager.name !== 'bun' ||
    packageManager.version !== '1.3.14' ||
    JSON.stringify(packageManager.install_args) !== JSON.stringify(['install', '--frozen-lockfile']) ||
    toolchain.bun_version !== '1.3.14' ||
    toolchain.node_version !== 'v26.7.0' ||
    packageManager.version !== toolchain.bun_version ||
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
  if (cold > maximum || warm + 1 > maximum || maximum > 100) {
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
    if (
      value < 1 ||
      value > workload.repetitions.maximum ||
      (argument === '--warm' && value + 1 > workload.repetitions.maximum)
    ) {
      throw new BenchmarkError('argument_value_invalid');
    }
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

export async function captureInputSnapshot(
  workload: Workload,
  sourceRoot: string,
  destination: string,
  limit: number
): Promise<{ root: string; identity: { bytes: number; sha256: string } }> {
  const copied = { bytes: 0 };
  await mkdir(destination, { recursive: true });
  for (const inputFile of workload.build.input_files) {
    await copyBoundedFile(join(sourceRoot, inputFile), join(destination, inputFile), copied, limit);
  }
  for (const inputRoot of workload.build.input_roots) {
    await copyBoundedTree(join(sourceRoot, inputRoot), join(destination, inputRoot), copied, limit);
  }
  // Workspaces are writable copies, but the captured source must remain fixed
  // while cold and warm samples execute. A read-only snapshot also prevents a
  // build from turning its own later evidence into a source mutation.
  runChecked('/bin/chmod', ['-R', 'a-w', destination], 'input_snapshot_protection_failed');
  return { root: destination, identity: await inputIdentity(workload, destination) };
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
  // Root caches are generated by Vitest/Vite, not resolved packages. Remove
  // them from the private clone so a fresh frozen install and a checkout that
  // has run tests produce the same dependency snapshot.
  for (const entry of TRANSIENT_DEPENDENCY_ENTRIES) {
    const generatedCache = spawnSync('/bin/rm', ['-rf', join(destination, entry)], { stdio: 'ignore' });
    if (generatedCache.status !== 0) throw new BenchmarkError('dependency_snapshot_failed');
  }
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

export async function bindDependencySnapshot(workspace: string, dependencySnapshot: string): Promise<void> {
  const bindingRoot = join(workspace, 'node_modules');
  await mkdir(bindingRoot, { recursive: true });
  const entries = await readdir(dependencySnapshot, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name));
  for (const entry of entries) {
    // Vite owns this cache directory during config loading. Keep it local and
    // writable instead of binding the immutable snapshot's prior cache bytes.
    if ((TRANSIENT_DEPENDENCY_ENTRIES as readonly string[]).includes(entry.name)) continue;
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

async function createWorkspace(workload: Workload, dependencySnapshot: string, inputSnapshot: string): Promise<string> {
  const workspace = await mkdtemp(join(tmpdir(), 'hermternal-web-build-'));
  activeWorkspaces.add(workspace);
  try {
    const copied = { bytes: 0 };
    for (const inputFile of workload.build.input_files) {
      await copyBoundedFile(join(inputSnapshot, inputFile), join(workspace, inputFile), copied, workload.limits.workspace_input_bytes);
    }
    for (const inputRoot of workload.build.input_roots) {
      await copyBoundedTree(join(inputSnapshot, inputRoot), join(workspace, inputRoot), copied, workload.limits.workspace_input_bytes);
    }
    const generatedTsconfig = join(workspace, '.svelte-kit', 'tsconfig.json');
    await mkdir(dirname(generatedTsconfig), { recursive: true });
    const generatedTsconfigBytes = new TextEncoder().encode(GENERATED_SVELTE_TSCONFIG);
    copied.bytes += generatedTsconfigBytes.byteLength;
    if (copied.bytes > workload.limits.workspace_input_bytes) throw new BenchmarkError('workspace_input_limit_exceeded');
    await writeFile(generatedTsconfig, generatedTsconfigBytes);
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
  artifactFiles = 10_000,
  repetitions = 1,
  stdoutBytes = 1_048_576,
  stderrBytes = 1_048_576,
  timeoutMs = 120_000
): { command: string; args: string[] } {
  if (
    !Number.isSafeInteger(repetitions) || repetitions < 1 || repetitions > 100 ||
    !Number.isSafeInteger(stdoutBytes) || stdoutBytes < 1 ||
    !Number.isSafeInteger(stderrBytes) || stderrBytes < 1 ||
    !Number.isSafeInteger(timeoutMs) || timeoutMs < 1
  ) {
    throw new BenchmarkError('repetition_limit_invalid');
  }
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
    '--max-stdout',
    String(stdoutBytes),
    '--max-stderr',
    String(stderrBytes),
    '--timeout-ms',
    String(timeoutMs),
    '--repetitions',
    String(repetitions),
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

interface ParsedSupervisorResult {
  duration_ms: number;
  stdout_bytes: number;
  stderr_bytes: number;
  artifact_files: number;
  artifact_bytes: number;
  artifact_sha256: string;
}

function parseSupervisorResult(resultLine: string, workload: Workload): ParsedSupervisorResult {
  let supervisorResult: unknown;
  try {
    if (!resultLine.startsWith('HERMTERNAL_RESULT ')) throw new Error('missing');
    supervisorResult = JSON.parse(resultLine.slice('HERMTERNAL_RESULT '.length));
  } catch {
    throw new BenchmarkError('supervisor_result_invalid');
  }
  supervisorResult = plainJsonSnapshot(supervisorResult, 'supervisor_result_invalid');
  const resultRecord = supervisorResult as Record<string, unknown>;
  requireExactKeys(
    resultRecord,
    ['exit_code', 'duration_us', 'stdout_bytes', 'stderr_bytes', 'artifact_files', 'artifact_bytes', 'artifact_sha256'],
    'supervisor_result_invalid'
  );
  if (
    resultRecord.exit_code !== 0 ||
    !Number.isSafeInteger(resultRecord.duration_us) || (resultRecord.duration_us as number) <= 0 ||
    !Number.isSafeInteger(resultRecord.stdout_bytes) || (resultRecord.stdout_bytes as number) < 0 ||
    (resultRecord.stdout_bytes as number) > workload.limits.stdout_bytes ||
    !Number.isSafeInteger(resultRecord.stderr_bytes) || (resultRecord.stderr_bytes as number) < 0 ||
    (resultRecord.stderr_bytes as number) > workload.limits.stderr_bytes ||
    !Number.isSafeInteger(resultRecord.artifact_files) || (resultRecord.artifact_files as number) < 0 ||
    (resultRecord.artifact_files as number) > workload.limits.artifact_files ||
    !Number.isSafeInteger(resultRecord.artifact_bytes) || (resultRecord.artifact_bytes as number) < 0 ||
    (resultRecord.artifact_bytes as number) > workload.limits.artifact_bytes ||
    typeof resultRecord.artifact_sha256 !== 'string' || !SHA256_PATTERN.test(resultRecord.artifact_sha256)
  ) {
    throw new BenchmarkError('supervisor_result_invalid');
  }
  return {
    duration_ms: (resultRecord.duration_us as number) / 1000,
    stdout_bytes: resultRecord.stdout_bytes as number,
    stderr_bytes: resultRecord.stderr_bytes as number,
    artifact_files: resultRecord.artifact_files as number,
    artifact_bytes: resultRecord.artifact_bytes as number,
    artifact_sha256: resultRecord.artifact_sha256 as string
  };
}

export async function runBuildSeries(
  workspace: string,
  dependencySnapshot: string,
  workload: Workload,
  runtime: ProtectedRuntime,
  repetitions: number
): Promise<BuildObservation[]> {
  if (!Number.isSafeInteger(repetitions) || repetitions < 1 || repetitions > workload.repetitions.maximum) {
    throw new BenchmarkError('repetition_limit_invalid');
  }
  const entrypoint = join(workspace, workload.build.entrypoint);
  const executedCommand = [runtime.nodePath, entrypoint, ...workload.build.arguments];
  // One sandbox invocation is required for warm samples: Linux mounts a fresh
  // tmpfs per invocation, so only one supervised series preserves generated
  // SvelteKit/Vite state and the reviewed aggregate quota across repetitions.
  const launcher = sandboxLauncher(
    runtime,
    workspace,
    dependencySnapshot,
    workload.limits.artifact_bytes,
    executedCommand,
    1,
    workload.limits.artifact_files,
    repetitions,
    workload.limits.stdout_bytes,
    workload.limits.stderr_bytes,
    workload.limits.build_timeout_ms
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
  const seriesTimeoutMs = workload.limits.build_timeout_ms * repetitions + SERIES_CLEANUP_GRACE_MS;
  const timer = setTimeout(() => {
    timedOut = true;
    stopTree();
  }, seriesTimeoutMs);
  const onOverflow = () => {
    outputExceeded = true;
    stopTree();
  };
  if (!child.stdout || !child.stderr) throw new BenchmarkError('production_build_spawn_failed');
  // Keep enough bounded tail space for every canonical result line. The
  // supervisor emits each line after its child and scanner, making the final
  // series authenticated even if the measured command prints forged prefixes.
  const stdoutTailLimit = Math.min(workload.limits.stdout_bytes, 1024 + repetitions * 768);
  // The supervisor enforces each child stream separately. The outer pipe sees
  // the concatenated series, so its cap includes every per-sample allowance
  // plus the bounded authenticated result tail.
  const outerStdoutLimit = workload.limits.stdout_bytes * repetitions + stdoutTailLimit;
  const outerStderrLimit = workload.limits.stderr_bytes * repetitions;
  const stdoutDrain = consumeBounded(child.stdout, outerStdoutLimit, onOverflow, stdoutTailLimit);
  const stderrDrain = consumeBounded(child.stderr, outerStderrLimit, onOverflow);
  try {
    const exitCode = await new Promise<number>((resolve, reject) => {
      child.once('error', () => reject(new BenchmarkError('production_build_spawn_failed')));
      child.once('exit', (code) => resolve(code ?? 128));
    });
    await terminateProcessGroup(child);
    const [stdoutResult] = await boundedWait(
      Promise.all([stdoutDrain, stderrDrain]),
      1000,
      'process_pipe_drain_timeout'
    );
    if (timedOut || exitCode === 124) throw new BenchmarkError('build_timeout');
    if (outputExceeded) throw new BenchmarkError('process_output_limit_exceeded');
    if (exitCode !== 0) throw new BenchmarkError('production_build_failed');
    const resultLines = stdoutResult.tail
      .trimEnd()
      .split('\n')
      .filter((line) => line.startsWith('HERMTERNAL_RESULT '));
    if (resultLines.length < repetitions) throw new BenchmarkError('supervisor_result_invalid');
    const canonicalResults = resultLines.slice(-repetitions).map((line) => parseSupervisorResult(line, workload));
    return canonicalResults.map((result, sequence) => ({
      sequence,
      duration_ms: result.duration_ms,
      exit_code: exitCode,
      stdout_bytes: result.stdout_bytes,
      stderr_bytes: result.stderr_bytes,
      artifact_files: result.artifact_files,
      artifact_bytes: result.artifact_bytes,
      artifact_sha256: result.artifact_sha256
    }));
  } finally {
    clearTimeout(timer);
    await terminateProcessGroup(child);
    child.stdout?.destroy();
    child.stderr?.destroy();
    if (activeChild === child) activeChild = undefined;
  }
}

async function runBuild(
  workspace: string,
  dependencySnapshot: string,
  workload: Workload,
  runtime: ProtectedRuntime,
  sequence: number
): Promise<BuildObservation> {
  const [observation] = await runBuildSeries(workspace, dependencySnapshot, workload, runtime, 1);
  if (!observation) throw new BenchmarkError('supervisor_result_invalid');
  return { ...observation, sequence };
}

async function runCold(workload: Workload, dependencySnapshot: string, inputSnapshot: string, runtime: ProtectedRuntime, repetitions: number): Promise<BuildObservation[]> {
  const observations: BuildObservation[] = [];
  for (let sequence = 1; sequence <= repetitions; sequence += 1) {
    const workspace = await createWorkspace(workload, dependencySnapshot, inputSnapshot);
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
  inputSnapshot: string,
  runtime: ProtectedRuntime,
  repetitions: number
): Promise<{ warmup: BuildObservation; observations: BuildObservation[] }> {
  // The first helper repetition is an excluded warm-up, so the public warm
  // count must leave one slot below both the workload and supervisor bounds.
  if (!Number.isSafeInteger(repetitions) || repetitions < 1 || repetitions + 1 > workload.repetitions.maximum) {
    throw new BenchmarkError('repetition_limit_invalid');
  }
  const workspace = await createWorkspace(workload, dependencySnapshot, inputSnapshot);
  try {
    const series = await runBuildSeries(workspace, dependencySnapshot, workload, runtime, repetitions + 1);
    const warmup = series[0];
    if (!warmup || series.length !== repetitions + 1) throw new BenchmarkError('supervisor_result_invalid');
    return {
      warmup: { ...warmup, sequence: 0 },
      observations: series.slice(1).map((observation, index) => ({ ...observation, sequence: index + 1 }))
    };
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

export function assertToolchainVersions(workload: Workload, nodeVersion: string): void {
  if (Bun.version !== workload.toolchain.bun_version || nodeVersion !== workload.toolchain.node_version) {
    throw new BenchmarkError('toolchain_version_mismatch');
  }
}

export function assertEvidenceEnvironment(
  workload: Workload,
  nodeVersion: string,
  targetPlatform = platform(),
  targetArchitecture = arch()
): void {
  assertToolchainVersions(workload, nodeVersion);
  if (targetPlatform !== 'darwin' || targetArchitecture !== 'arm64') {
    throw new BenchmarkError('evidence_environment_unsupported');
  }
}

export type BoundedFileHandle = Pick<FileHandle, 'read' | 'stat' | 'close'>;
export type BoundedFileStats = Awaited<ReturnType<FileHandle['stat']>>;
export type BoundedFileOpener = (path: string, flags: number) => Promise<BoundedFileHandle>;

const BOUNDED_FILE_METADATA_KEYS = [
  'dev',
  'ino',
  'mode',
  'size',
  'mtimeNs',
  'ctimeNs',
  'mtimeMs',
  'ctimeMs'
] as const;

function boundedFileMetadataValue(metadata: BoundedFileStats, key: string): unknown {
  return (metadata as unknown as Record<string, unknown>)[key];
}

function boundedFileSize(metadata: BoundedFileStats): number {
  const value = boundedFileMetadataValue(metadata, 'size');
  if (typeof value === 'bigint') {
    if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('bounded_file_metadata_invalid');
    return Number(value);
  }
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new Error('bounded_file_metadata_invalid');
  }
  return value;
}

function assertRegularBoundedFile(metadata: BoundedFileStats): number {
  if (typeof metadata.isFile !== 'function' || !metadata.isFile()) {
    throw new Error('bounded_file_not_regular');
  }
  for (const key of ['dev', 'ino', 'mode'] as const) {
    if (boundedFileMetadataValue(metadata, key) === undefined) {
      throw new Error('bounded_file_metadata_invalid');
    }
  }
  return boundedFileSize(metadata);
}

function sameBoundedFileMetadata(initial: BoundedFileStats, final: BoundedFileStats): boolean {
  return BOUNDED_FILE_METADATA_KEYS.every((key) => {
    const initialValue = boundedFileMetadataValue(initial, key);
    const finalValue = boundedFileMetadataValue(final, key);
    if (initialValue === undefined && finalValue === undefined) return true;
    return initialValue !== undefined && finalValue !== undefined && initialValue === finalValue;
  });
}

export async function readBoundedFile(
  path: string,
  limit: number,
  openFile: BoundedFileOpener = (filePath, flags) => open(filePath, flags)
): Promise<Uint8Array> {
  const handle = await openFile(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    // Stat the opened descriptor, not the pathname. The initial regular-file
    // check and size cap prevent a replacement or oversized file from causing
    // an unbounded allocation before the descriptor-bounded read begins.
    const initial = await handle.stat();
    const initialSize = assertRegularBoundedFile(initial);
    if (initialSize > limit) throw new Error('bounded_file_oversized');

    // Read one byte beyond the accepted bound through the opened descriptor.
    // EOF is checked against final descriptor metadata so an append or growth
    // after the first EOF observation cannot be accepted as stable content.
    const buffer = new Uint8Array(limit + 1);
    let bytesRead = 0;
    while (bytesRead < buffer.byteLength) {
      const result = await handle.read(buffer, bytesRead, buffer.byteLength - bytesRead, bytesRead);
      if (result.bytesRead === 0) break;
      bytesRead += result.bytesRead;
    }

    const final = await handle.stat();
    const finalSize = assertRegularBoundedFile(final);
    if (!sameBoundedFileMetadata(initial, final) || bytesRead !== finalSize) {
      throw new Error('bounded_file_changed');
    }
    if (bytesRead > limit) throw new Error('bounded_file_oversized');
    return buffer.slice(0, bytesRead);
  } finally {
    await handle.close();
  }
}

export async function readPackageVersion(
  dependencySnapshot: string,
  openFile?: BoundedFileOpener
): Promise<string> {
  const packagePath = join(dependencySnapshot, 'vite', 'package.json');
  let raw: Uint8Array;
  try {
    raw = await readBoundedFile(packagePath, MAX_JSON_BYTES, openFile);
  } catch {
    throw new BenchmarkError('vite_metadata_unavailable');
  }
  let parsed: unknown;
  try {
    parsed = plainJsonSnapshot(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw)), 'vite_metadata_invalid');
  } catch (error) {
    if (error instanceof BenchmarkError) throw error;
    throw new BenchmarkError('vite_metadata_invalid');
  }
  if (!isRecord(parsed) || typeof parsed.version !== 'string' || !PACKAGE_VERSION_PATTERN.test(parsed.version)) {
    throw new BenchmarkError('vite_metadata_invalid');
  }
  // Package metadata is read from the immutable dependency snapshot. Do not
  // execute Vite's bin script: that would leave the measured OS boundary and
  // could observe a mutable checkout or caller-controlled preload environment.
  return parsed.version;
}

export function assertMeasuredInputsTracked(
  workload: Workload,
  repositoryRoot = resolve(APP_ROOT, '..', '..')
): void {
  const measuredPaths = [...workload.build.input_files, ...workload.build.input_roots].map((path) =>
    join('apps', 'web', path).split(sep).join('/')
  );
  const status = Bun.spawnSync(
    [
      '/usr/bin/git',
      '-C',
      repositoryRoot,
      'status',
      '--porcelain=v1',
      '-z',
      '--untracked-files=all',
      '--ignored=matching',
      '--',
      ...measuredPaths
    ],
    { stdout: 'pipe', stderr: 'ignore' }
  );
  if (status.exitCode !== 0) throw new BenchmarkError('source_input_status_unavailable');
  // Porcelain -z records are NUL-delimited. Never split on newlines: Git
  // permits newlines in filenames, and every matching record is untrusted.
  const records = new TextDecoder().decode(status.stdout).split('\0').filter(Boolean);
  if (records.length > 0) throw new BenchmarkError('source_input_tree_dirty');
}

export function sourceCommit(): string {
  const repositoryRoot = resolve(APP_ROOT, '..', '..');
  const result = Bun.spawnSync(['/usr/bin/git', '-C', repositoryRoot, 'rev-parse', 'HEAD'], {
    stdout: 'pipe',
    stderr: 'ignore'
  });
  const commit = new TextDecoder().decode(result.stdout).trim();
  if (result.exitCode !== 0 || !/^[0-9a-f]{40}$/.test(commit)) throw new BenchmarkError('source_commit_unavailable');
  // HEAD alone is not provenance: a modified tracked runner, helper, workload,
  // or web input can execute while rev-parse still reports the same commit.
  // Bind the entire measured web tree to that commit before and after samples.
  const clean = Bun.spawnSync(['/usr/bin/git', '-C', repositoryRoot, 'diff', '--quiet', 'HEAD', '--', 'apps/web'], {
    stdout: 'ignore',
    stderr: 'ignore'
  });
  if (clean.exitCode !== 0) throw new BenchmarkError('source_tree_dirty');
  return commit;
}

export function assertSourceIdentityUnchanged(
  expectedCommitSha: string,
  expectedInput: { bytes: number; sha256: string },
  currentCommitSha: string,
  currentInput: { bytes: number; sha256: string }
): void {
  if (currentCommitSha !== expectedCommitSha || JSON.stringify(currentInput) !== JSON.stringify(expectedInput)) {
    throw new BenchmarkError('source_input_mutated');
  }
}

export async function treeIdentity(root: string, excludedRootEntries: readonly string[] = []): Promise<TreeIdentity> {
  const resolvedRoot = await realpath(root);
  const excluded = new Set(excludedRootEntries);
  const records: Array<{ path: string; type: 'file' | 'symlink'; bytes: number; sha256: string }> = [];
  async function visit(directory: string): Promise<void> {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      if ((directory === root || directory === resolvedRoot) && excluded.has(entry.name)) continue;
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
        // Hash the stored link text, not the resolved absolute path. Clone
        // destinations vary per run; the raw relative link is the stable
        // dependency identity while realpath above still rejects escapes.
        const targetText = (await readlink(path)).split(sep).join('/');
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

export async function fileIdentity(path: string): Promise<FileIdentity> {
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

function sameIdentity(actual: FileIdentity | TreeIdentity, expected: FileIdentity | TreeIdentity): boolean {
  return JSON.stringify(actual) === JSON.stringify(expected);
}

export function requireRuntimeAnchor(workload: Workload, targetPlatform = platform()): RuntimeIdentity {
  if (targetPlatform !== 'darwin' && targetPlatform !== 'linux') {
    throw new BenchmarkError('runtime_platform_unsupported');
  }
  const anchor = workload.integrity.runtime[targetPlatform];
  if (!anchor) throw new BenchmarkError('runtime_identity_anchor_missing');
  return anchor;
}

export function assertRuntimeIdentity(actual: RuntimeIdentity, expected: RuntimeIdentity): void {
  for (const key of Object.keys(expected) as Array<keyof RuntimeIdentity>) {
    if (!sameIdentity(actual[key], expected[key])) throw new BenchmarkError('runtime_identity_mismatch');
  }
}

export function assertToolchainRuntimeAnchor(
  toolchain: Record<string, unknown>,
  workload: Workload,
  targetPlatform = platform()
): void {
  const anchor = requireRuntimeAnchor(workload, targetPlatform);
  const mappings = [
    ['node_executable', 'node'],
    ['bun_executable', 'bun'],
    ['python_executable', 'python'],
    ['sandbox_executable', 'sandbox']
  ] as const;
  for (const [toolchainKey, anchorKey] of mappings) {
    const actual = toolchain[toolchainKey];
    if (!isRecord(actual) || !sameIdentity(actual as unknown as FileIdentity, anchor[anchorKey])) {
      throw new BenchmarkError('runtime_identity_mismatch');
    }
  }
}

async function verifyDependencySnapshot(
  workload: Workload,
  dependencySnapshot: string,
  inputSnapshot: string,
  runtime: ProtectedRuntime
): Promise<void> {
  const expected = workload.integrity;
  const actualFiles = {
    package_json: await fileIdentity(join(inputSnapshot, 'package.json')),
    bun_lock: await fileIdentity(join(inputSnapshot, 'bun.lock'))
  };
  if (!sameIdentity(actualFiles.package_json, expected.package_json) || !sameIdentity(actualFiles.bun_lock, expected.bun_lock)) {
    throw new BenchmarkError('dependency_identity_mismatch');
  }
  const actualTrees = {
    dependencies: await treeIdentity(dependencySnapshot, TRANSIENT_DEPENDENCY_ENTRIES),
    vite: await treeIdentity(join(dependencySnapshot, 'vite')),
    sveltekit: await treeIdentity(join(dependencySnapshot, '@sveltejs', 'kit')),
    vite_svelte_plugin: await treeIdentity(join(dependencySnapshot, '@sveltejs', 'vite-plugin-svelte')),
    svelte: await treeIdentity(join(dependencySnapshot, 'svelte')),
    typescript_native: await treeIdentity(join(dependencySnapshot, '@typescript', 'native'))
  };
  for (const key of Object.keys(actualTrees) as Array<keyof typeof actualTrees>) {
    if (!sameIdentity(actualTrees[key], expected[key])) throw new BenchmarkError('dependency_identity_mismatch');
  }
  const runtimeAnchor = requireRuntimeAnchor(workload);
  const actualRuntime = {
    node: await fileIdentity(runtime.nodePath),
    bun: await fileIdentity(process.execPath),
    python: await fileIdentity(runtime.pythonPath),
    sandbox: await fileIdentity(runtime.sandboxPath)
  };
  assertRuntimeIdentity(actualRuntime, runtimeAnchor);
}

async function toolchainIdentity(
  dependencySnapshot: string,
  inputSnapshot: string,
  runtime: ProtectedRuntime,
  workload: Workload
): Promise<Record<string, unknown>> {
  return {
    package_manager: {
      name: workload.package_manager.name,
      version: Bun.version,
      install_args: [...workload.package_manager.install_args]
    },
    node_version: commandVersion(runtime.nodePath, ['--version']),
    package_json: await fileIdentity(join(inputSnapshot, 'package.json')),
    bun_lock: await fileIdentity(join(inputSnapshot, 'bun.lock')),
    benchmark_runner: await fileIdentity(import.meta.path),
    sandbox_runner: await fileIdentity(SANDBOX_RUNNER_PATH),
    artifact_scanner: await fileIdentity(ARTIFACT_SCANNER_PATH),
    node_executable: await fileIdentity(runtime.nodePath),
    bun_executable: await fileIdentity(process.execPath),
    python_executable: await fileIdentity(runtime.pythonPath),
    sandbox_executable: await fileIdentity(runtime.sandboxPath),
    dependencies: await treeIdentity(dependencySnapshot, TRANSIENT_DEPENDENCY_ENTRIES),
    vite: await treeIdentity(join(dependencySnapshot, 'vite')),
    sveltekit: await treeIdentity(join(dependencySnapshot, '@sveltejs', 'kit')),
    vite_svelte_plugin: await treeIdentity(join(dependencySnapshot, '@sveltejs', 'vite-plugin-svelte')),
    svelte: await treeIdentity(join(dependencySnapshot, 'svelte')),
    typescript_native: await treeIdentity(join(dependencySnapshot, '@typescript', 'native'))
  };
}

export async function inputIdentity(workload: Workload, inputRoot = APP_ROOT): Promise<{ bytes: number; sha256: string }> {
  const records: Array<{ path: string; bytes: number; sha256: string }> = [];
  async function addFile(path: string): Promise<void> {
    const bytes = await readFile(path);
    records.push({ path: relative(inputRoot, path).split(sep).join('/'), bytes: bytes.byteLength, sha256: sha256(bytes) });
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
  for (const inputFile of workload.build.input_files) await addFile(join(inputRoot, inputFile));
  for (const inputRootPath of workload.build.input_roots) await addTree(join(inputRoot, inputRootPath));
  records.sort((left, right) => left.path.localeCompare(right.path));
  return { bytes: records.reduce((total, record) => total + record.bytes, 0), sha256: sha256(canonicalBytes(records)) };
}

function sampleProvenance(run: Record<string, unknown>): string {
  return sha256(canonicalDigestBytes(run));
}

async function writeEvidenceFiles(
  workload: Workload,
  workloadBytes: Uint8Array,
  runtime: ProtectedRuntime,
  dependencySnapshot: string,
  toolchain: Record<string, unknown>,
  commitSha: string,
  input: { bytes: number; sha256: string },
  cold: BuildObservation[],
  warmup: BuildObservation,
  warm: BuildObservation[]
): Promise<void> {
  const nodePath = runtime.nodePath;
  const nodeVersion = commandVersion(nodePath, ['--version']);
  assertToolchainRuntimeAnchor(toolchain, workload);
  const viteVersion = await readPackageVersion(dependencySnapshot);
  const artifactIdentities = [warmup, ...cold, ...warm].map((sample) => sample.artifact_sha256);
  if (new Set(artifactIdentities).size !== 1) throw new BenchmarkError('artifact_identity_drift');
  const environment = {
    platform: `${platform()}-${release()}`,
    os: `${type()}-${release()}`,
    architecture: arch(),
    device: `local-${safeCpuModel()}`,
    runtime: `Bun-${Bun.version}; Node-${nodeVersion}; Vite-vite/${viteVersion} ${platform()}-${arch()} node-${nodeVersion}`,
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

async function loadWorkload(): Promise<{ workload: Workload; bytes: Uint8Array }> {
  let raw: Uint8Array;
  let parsed: unknown;
  try {
    raw = await readBoundedFile(WORKLOAD_PATH, MAX_JSON_BYTES);
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
  return { workload, bytes: raw };
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
  const loadedWorkload = await loadWorkload();
  const workload = loadedWorkload.workload;
  const workloadBytes = loadedWorkload.bytes;
  const options = parseArguments(process.argv.slice(2), workload);
  // Do not begin copying or measuring on a platform whose executable bytes are
  // not independently anchored by the reviewed workload fixture.
  requireRuntimeAnchor(workload);
  const runtime = await protectedRuntime(workload);
  const nodeVersion = commandVersion(runtime.nodePath, ['--version']);
  assertToolchainVersions(workload, nodeVersion);
  if (options.writeEvidence) assertEvidenceEnvironment(workload, nodeVersion);
  // Synchronous creation and registration form one signal-free JavaScript turn;
  // SIGINT/SIGTERM can no longer observe an unregistered on-disk run root.
  const runRoot = mkdtempSync(join(tmpdir(), 'hermternal-web-benchmark-'));
  activeRunRoots.add(runRoot);
  try {
    // Capture the measured source before the first sample. Workspaces are
    // copied from this immutable snapshot, while the live checkout is checked
    // again after the run so a concurrent edit cannot receive evidence.
    const sourceCommitSha = sourceCommit();
    // Git membership is checked only against the live source repository. The
    // snapshot and temporary workspaces are intentionally outside Git, so this
    // preflight must remain separate from inputIdentity().
    assertMeasuredInputsTracked(workload);
    const sourceInput = await inputIdentity(workload);
    const inputSnapshot = await captureInputSnapshot(
      workload,
      APP_ROOT,
      join(runRoot, 'input-snapshot'),
      workload.limits.workspace_input_bytes
    );
    const capturedInputAfterSnapshot = await inputIdentity(workload);
    assertSourceIdentityUnchanged(sourceCommitSha, sourceInput, sourceCommit(), capturedInputAfterSnapshot);
    if (JSON.stringify(sourceInput) !== JSON.stringify(inputSnapshot.identity)) {
      throw new BenchmarkError('source_input_mutated');
    }
    const dependencySnapshot = await cloneDependencySnapshot(runRoot);
    await verifyDependencySnapshot(workload, dependencySnapshot, inputSnapshot.root, runtime);
    const toolchain = await toolchainIdentity(dependencySnapshot, inputSnapshot.root, runtime, workload);
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
    const cold = await runCold(workload, dependencySnapshot, inputSnapshot.root, runtime, options.coldRepetitions);
    const warmResult = await runWarm(workload, dependencySnapshot, inputSnapshot.root, runtime, options.warmRepetitions);
    const artifactIdentities = [warmResult.warmup, ...cold, ...warmResult.observations].map((sample) => sample.artifact_sha256);
    if (new Set(artifactIdentities).size !== 1) throw new BenchmarkError('artifact_identity_drift');
    const finalToolchain = await toolchainIdentity(dependencySnapshot, inputSnapshot.root, runtime, workload);
    if (JSON.stringify(toolchain) !== JSON.stringify(finalToolchain)) throw new BenchmarkError('dependency_snapshot_mutated');
    assertMeasuredInputsTracked(workload);
    const finalSourceCommit = sourceCommit();
    const finalSourceInput = await inputIdentity(workload);
    assertSourceIdentityUnchanged(sourceCommitSha, sourceInput, finalSourceCommit, finalSourceInput);
    if (options.writeEvidence) {
      await writeEvidenceFiles(
        workload,
        workloadBytes,
        runtime,
        dependencySnapshot,
        toolchain,
        sourceCommitSha,
        inputSnapshot.identity,
        cold,
        warmResult.warmup,
        warmResult.observations
      );
    }
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
