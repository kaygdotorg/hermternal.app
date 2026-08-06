import { describe, expect, test } from 'bun:test';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  BenchmarkError,
  distribution,
  measureArtifacts,
  mountArtifactQuota,
  parseArguments,
  removeWorkspace,
  roundRationalHalfEven,
  terminateProcessGroup,
  validateWorkload,
  type Workload
} from './run';

const benchmarkRoot = import.meta.dir;

async function workload(): Promise<Workload> {
  return validateWorkload(JSON.parse(await readFile(join(benchmarkRoot, 'workload.json'), 'utf8')));
}

async function sandboxNetworkAttempt(clearNodeOptions: boolean): Promise<number> {
  const root = await mkdtemp(join(tmpdir(), 'hermternal-sandbox-test-'));
  const workspace = join(root, 'workspace');
  const dependencyRoot = join(root, 'dependencies');
  for (const path of [
    workspace,
    dependencyRoot,
    join(workspace, '.svelte-kit'),
    join(workspace, '.artifact-output'),
    join(workspace, '.home'),
    join(workspace, '.tmp'),
    join(workspace, 'node_modules', '.vite-temp')
  ]) await mkdir(path, { recursive: true });

  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('listener unavailable');
  const socketAttempt = `const net=require('node:net');const socket=new net.Socket();socket.setTimeout(1000);socket.once('connect',()=>process.exit(9));socket.once('error',()=>process.exit(0));socket.once('timeout',()=>process.exit(0));socket.connect(${address.port},'127.0.0.1');`;
  const executed = clearNodeOptions
    ? [process.execPath, '-e', `const {spawnSync}=require('node:child_process');const result=spawnSync(process.execPath,['-e',${JSON.stringify(socketAttempt)}],{env:{...process.env,NODE_OPTIONS:''}});process.exit(result.status??8);`]
    : [process.execPath, '-e', socketAttempt];
  try {
    const child = Bun.spawn([
      'python3', join(benchmarkRoot, 'sandbox-runner.py'),
      '--workspace', workspace,
      '--dependency-root', dependencyRoot,
      '--artifact-bytes', '1048576',
      '--', ...executed
    ], { cwd: workspace, stdout: 'pipe', stderr: 'pipe' });
    return await child.exited;
  } finally {
    server.close();
    await rm(root, { recursive: true, force: true });
  }
}

describe('production-build benchmark contract', () => {
  test('accepts the reviewed deterministic workload', async () => {
    const candidate = await workload();
    expect(candidate.network).toEqual({ mode: 'deny', boundary: 'os_sandbox' });
    expect(candidate.repetitions).toEqual({ cold: 30, warm: 30, maximum: 100 });
    expect(candidate.build.version_name).toBe('hermternal-web-production-build-v1');
    expect(candidate.build.output_root).toBe('.artifact-output/build');
    expect(candidate.limits.artifact_bytes).toBe(67_108_864);
  });

  test('rejects unbounded resource mutations', async () => {
    const candidate = structuredClone(await workload());
    candidate.limits.build_timeout_ms = 300_001;
    expect(() => validateWorkload(candidate)).toThrow(new BenchmarkError('resource_limit_invalid'));
  });

  test('snapshots exact plain data and rejects executable object shapes', async () => {
    const original = structuredClone(await workload());
    const snapshot = validateWorkload(original);
    original.build.arguments[0] = 'serve';
    expect(snapshot.build.arguments[0]).toBe('build');
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(Object.isFrozen(snapshot.build.arguments)).toBe(true);

    for (const mutate of [
      (value: object) => Object.defineProperty(value, 'hidden', { value: true }),
      (value: object) => Object.defineProperty(value, 'schema', { get: () => 'hermternal.web-production-build-workload.v1', enumerable: true }),
      (value: object) => Object.defineProperty(value, Symbol('hidden'), { value: true, enumerable: true }),
      (value: object) => Object.setPrototypeOf(value, { inherited: true })
    ]) {
      const candidate = structuredClone(await workload());
      mutate(candidate);
      expect(() => validateWorkload(candidate)).toThrow(BenchmarkError);
    }
  });

  test('requires reviewed repetition counts before writing evidence', async () => {
    const candidate = await workload();
    expect(() => parseArguments(['--cold', '2', '--warm', '2', '--write-evidence'], candidate)).toThrow(
      new BenchmarkError('evidence_requires_30_repetitions')
    );
    expect(parseArguments(['--cold', '2', '--warm', '3'], candidate)).toEqual({
      coldRepetitions: 2,
      warmRepetitions: 3,
      writeEvidence: false
    });
  });

  test('uses exact R-7 interpolation and half-even rounding', () => {
    expect(roundRationalHalfEven(5, 2)).toBe(2);
    expect(roundRationalHalfEven(7, 2)).toBe(4);
    expect(distribution([12, 12.14, 12.21, 12.35, 12.48, 12.61, 12.76, 12.88, 13.01, 13.12])).toEqual({
      min: 12,
      p50: 12.545,
      p95: 13.07,
      p99: 13.11,
      max: 13.12,
      mean: 12.556
    });
  });

  test('OS sandbox denies direct TCP and descendants clearing NODE_OPTIONS', async () => {
    expect(await sandboxNetworkAttempt(false)).toBe(0);
    expect(await sandboxNetworkAttempt(true)).toBe(0);
  });

  test('OS sandbox keeps the dependency snapshot read-only', async () => {
    const root = await mkdtemp(join(tmpdir(), 'hermternal-dependency-test-'));
    const workspace = join(root, 'workspace');
    const dependencyRoot = join(root, 'dependencies');
    for (const path of [
      dependencyRoot,
      join(workspace, '.svelte-kit'),
      join(workspace, '.artifact-output'),
      join(workspace, '.home'),
      join(workspace, '.tmp'),
      join(workspace, 'node_modules', '.vite-temp')
    ]) await mkdir(path, { recursive: true });
    const target = join(dependencyRoot, 'mutation');
    try {
      const command = `const fs=require('node:fs');try{fs.writeFileSync(${JSON.stringify(target)},'changed');process.exit(9)}catch{process.exit(0)}`;
      const child = Bun.spawn([
        'python3', join(benchmarkRoot, 'sandbox-runner.py'),
        '--workspace', workspace,
        '--dependency-root', dependencyRoot,
        '--artifact-bytes', '1048576',
        '--', process.execPath, '-e', command
      ], { cwd: workspace, stdout: 'pipe', stderr: 'pipe' });
      expect(await child.exited).toBe(0);
      expect(await Bun.file(target).exists()).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test('quota mount rejects a transient artifact that exceeds peak bytes', async () => {
    if (process.platform !== 'darwin') return;
    const workspace = await mkdtemp(join(tmpdir(), 'hermternal-quota-test-'));
    const dependencyRoot = join(workspace, 'dependencies');
    for (const path of [
      dependencyRoot,
      join(workspace, '.svelte-kit'),
      join(workspace, '.home'),
      join(workspace, '.tmp'),
      join(workspace, 'node_modules', '.vite-temp')
    ]) await mkdir(path, { recursive: true });
    const quotaBytes = 64 * 1024 * 1024;
    try {
      await mountArtifactQuota(workspace, quotaBytes);
      const target = join(workspace, '.artifact-output', 'peak.bin');
      const command = `const fs=require('node:fs');const fd=fs.openSync(${JSON.stringify(target)},'w');try{const chunk=Buffer.alloc(1048576);for(let index=0;index<256;index+=1)fs.writeSync(fd,chunk);process.exit(9)}catch{process.exit(0)}finally{fs.closeSync(fd)}`;
      const child = Bun.spawn([
        'python3', join(benchmarkRoot, 'sandbox-runner.py'),
        '--workspace', workspace,
        '--dependency-root', dependencyRoot,
        '--artifact-bytes', String(quotaBytes),
        '--', process.execPath, '-e', command
      ], { cwd: workspace, stdout: 'pipe', stderr: 'pipe' });
      expect(await child.exited).toBe(0);
    } finally {
      await removeWorkspace(workspace);
    }
  }, 20_000);

  test('artifact scanner rejects root and descendant symlink escapes without reading targets', async () => {
    const root = await mkdtemp(join(tmpdir(), 'hermternal-artifact-test-'));
    const workspace = join(root, 'workspace');
    const output = join(workspace, '.artifact-output', 'build');
    const external = join(root, 'external-secret');
    await mkdir(output, { recursive: true });
    await writeFile(external, 'must-not-be-hashed');
    const limits = (await workload()).limits;
    try {
      await symlink(external, join(output, 'escape'));
      await expect(measureArtifacts(output, workspace, limits, true)).rejects.toThrow(new BenchmarkError('artifact_scan_failed'));
      await rm(join(workspace, '.artifact-output'), { recursive: true, force: true });
      await symlink(root, join(workspace, '.artifact-output'));
      await expect(measureArtifacts(output, workspace, limits, true)).rejects.toThrow(new BenchmarkError('artifact_scan_failed'));
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test('process-group cleanup kills a descendant that ignores SIGTERM and holds pipes', async () => {
    const script = `const {spawn}=require('node:child_process');const child=spawn(process.execPath,['-e',"process.on('SIGTERM',()=>{});setInterval(()=>{},1000)"],{stdio:['ignore','inherit','inherit']});console.log(child.pid);setInterval(()=>{},1000);`;
    const child = spawn(process.execPath, ['-e', script], { detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    const descendantPid = await new Promise<number>((resolve, reject) => {
      child.stdout.once('data', (chunk) => resolve(Number(String(chunk).trim())));
      child.once('error', reject);
    });
    const exited = new Promise<void>((resolve) => child.once('exit', () => resolve()));
    await terminateProcessGroup(child, 100);
    await Promise.race([
      exited,
      Bun.sleep(1000).then(() => { throw new Error('child survived cleanup'); })
    ]);
    expect(() => process.kill(descendantPid, 0)).toThrow();
  });

  test('CLI failures are bounded JSON without attacker-controlled values', () => {
    const result = Bun.spawnSync([process.execPath, join(benchmarkRoot, 'run.ts'), '--unknown', 'sensitive-value'], {
      stdout: 'pipe',
      stderr: 'pipe'
    });
    const stderr = new TextDecoder().decode(result.stderr);
    expect(result.exitCode).toBe(2);
    expect(new TextDecoder().decode(result.stdout)).toBe('');
    expect(stderr.length).toBeLessThanOrEqual(513);
    expect(stderr).not.toContain('sensitive-value');
    expect(JSON.parse(stderr)).toEqual({ ok: false, error: 'argument_invalid' });
  });
});
