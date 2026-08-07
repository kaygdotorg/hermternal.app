import { describe, expect, test } from 'bun:test';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { chmod, mkdir, mkdtemp, readFile, readdir, rename, rm, symlink, truncate, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  BenchmarkError,
  assertMeasuredInputsTracked,
  assertRuntimeIdentity,
  assertSourceIdentityUnchanged,
  captureInputSnapshot,
  distribution,
  inputIdentity,
  measureArtifacts,
  MAX_JSON_BYTES,
  mountArtifactQuota,
  parseArguments,
  protectedRuntime,
  readPackageVersion,
  removeWorkspace,
  requireRuntimeAnchor,
  roundRationalHalfEven,
  sourceCommit,
  runBuildSeries,
  sandboxLauncher,
  terminateProcessGroup,
  validateWorkload,
  type BoundedFileOpener,
  type Workload
} from './run';

const benchmarkRoot = import.meta.dir;

async function workload(): Promise<Workload> {
  return validateWorkload(JSON.parse(await readFile(join(benchmarkRoot, 'workload.json'), 'utf8')));
}

async function sandboxNetworkAttempt(clearNodeOptions: boolean, pathOverride?: string): Promise<number> {
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
    join(workspace, '.supervisor'),
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
    const candidate = await workload();
    const runtime = await protectedRuntime(candidate);
    const launcher = sandboxLauncher(runtime, workspace, dependencyRoot, 1048576, executed);
    const child = Bun.spawn([launcher.command, ...launcher.args], {
      cwd: workspace,
      env: { ...process.env, ...(pathOverride ? { PATH: pathOverride } : {}) },
      stdout: 'pipe',
      stderr: 'pipe'
    });
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

  test('freezes input identity before samples can observe a later source edit', async () => {
    const candidate = structuredClone(await workload());
    candidate.build.input_files = ['package.json'];
    candidate.build.input_roots = ['src'];
    const root = await mkdtemp(join(tmpdir(), 'hermternal-input-snapshot-'));
    const source = join(root, 'source');
    const snapshot = join(root, 'snapshot');
    try {
      await mkdir(join(source, 'src'), { recursive: true });
      await writeFile(join(source, 'package.json'), 'before');
      await writeFile(join(source, 'src', 'entry.ts'), 'before');
      const captured = await captureInputSnapshot(candidate, source, snapshot, 1024);
      expect(captured.identity).toEqual(await inputIdentity(candidate, snapshot));
      await writeFile(join(source, 'package.json'), 'after');
      await writeFile(join(source, 'src', 'entry.ts'), 'after');
      expect(await inputIdentity(candidate, snapshot)).toEqual(captured.identity);
      expect(await inputIdentity(candidate, source)).not.toEqual(captured.identity);
    } finally {
      Bun.spawnSync(['/bin/chmod', '-R', 'u+w', root], { stdout: 'ignore', stderr: 'ignore' });
      await rm(root, { recursive: true, force: true });
    }
  });

  test('rechecks source commit and input identity after the run', () => {
    const expected = { bytes: 12, sha256: 'a'.repeat(64) };
    expect(() => assertSourceIdentityUnchanged('a'.repeat(40), expected, 'a'.repeat(40), expected)).not.toThrow();
    expect(() => assertSourceIdentityUnchanged('a'.repeat(40), expected, 'b'.repeat(40), expected)).toThrow(
      new BenchmarkError('source_input_mutated')
    );
    expect(() => assertSourceIdentityUnchanged('a'.repeat(40), expected, 'a'.repeat(40), { bytes: 13, sha256: expected.sha256 })).toThrow(
      new BenchmarkError('source_input_mutated')
    );
  });

  test('rejects a tracked runner edit even when HEAD is unchanged', async () => {
    const runnerPath = join(benchmarkRoot, 'run.ts');
    const original = await readFile(runnerPath);
    const expectedCommit = sourceCommit();
    try {
      await writeFile(runnerPath, Buffer.concat([original, Buffer.from('\\n')]));
      expect(() => sourceCommit()).toThrow(new BenchmarkError('source_tree_dirty'));
    } finally {
      await writeFile(runnerPath, original);
    }
    expect(sourceCommit()).toBe(expectedCommit);
  });

  test('rejects untracked files under an explicit measured input file', async () => {
    const candidate = structuredClone(await workload());
    const relativePath = `preflight-explicit-${process.pid}-${Date.now()}\\ninput.json`;
    const appRoot = resolve(benchmarkRoot, '../..');
    const absolutePath = join(appRoot, relativePath);
    candidate.build.input_files = [relativePath];
    candidate.build.input_roots = [];
    try {
      await writeFile(absolutePath, 'untracked');
      expect(() => assertMeasuredInputsTracked(candidate)).toThrow(new BenchmarkError('source_input_tree_dirty'));
    } finally {
      await rm(absolutePath, { force: true });
    }
  });

  test('rejects untracked files under a recursive measured input root', async () => {
    const candidate = structuredClone(await workload());
    const relativePath = `preflight-root-${process.pid}-${Date.now()}\\ninput.ts`;
    const absolutePath = join(resolve(benchmarkRoot, '../..'), 'src', relativePath);
    candidate.build.input_files = [];
    candidate.build.input_roots = ['src'];
    try {
      await writeFile(absolutePath, 'untracked');
      expect(() => assertMeasuredInputsTracked(candidate)).toThrow(new BenchmarkError('source_input_tree_dirty'));
    } finally {
      await rm(absolutePath, { force: true });
    }
  });

  test('rejects ignored files under an explicit measured input file', async () => {
    const candidate = structuredClone(await workload());
    const relativePath = `.svelte-kit/preflight-ignored-${process.pid}-${Date.now()}\\ninput.json`;
    const absolutePath = join(resolve(benchmarkRoot, '../..'), relativePath);
    candidate.build.input_files = [relativePath];
    candidate.build.input_roots = [];
    try {
      await writeFile(absolutePath, 'ignored');
      expect(() => assertMeasuredInputsTracked(candidate)).toThrow(new BenchmarkError('source_input_tree_dirty'));
    } finally {
      await rm(absolutePath, { force: true });
    }
  });

  test('rejects an ignored recursive measured input root', async () => {
    const candidate = structuredClone(await workload());
    const marker = `preflight-ignored-root-${process.pid}-${Date.now()}\\ninput.json`;
    const absolutePath = join(resolve(benchmarkRoot, '../..'), '.svelte-kit', marker);
    candidate.build.input_files = [];
    candidate.build.input_roots = ['.svelte-kit'];
    try {
      await writeFile(absolutePath, 'ignored');
      expect(() => assertMeasuredInputsTracked(candidate)).toThrow(new BenchmarkError('source_input_tree_dirty'));
    } finally {
      await rm(absolutePath, { force: true });
    }
  });

  test('requires platform runtime anchors and rejects an anchored identity mismatch', async () => {
    const candidate = await workload();
    expect(requireRuntimeAnchor(candidate, 'darwin')).toEqual(candidate.integrity.runtime.darwin);
    expect(() => requireRuntimeAnchor(candidate, 'linux')).toThrow(new BenchmarkError('runtime_identity_anchor_missing'));
    const linuxCandidate = structuredClone(candidate);
    linuxCandidate.integrity.runtime.linux = structuredClone(candidate.integrity.runtime.darwin);
    const linuxAnchor = requireRuntimeAnchor(linuxCandidate, 'linux');
    const changed = structuredClone(linuxAnchor);
    changed.node.bytes += 1;
    expect(() => assertRuntimeIdentity(changed, linuxAnchor)).toThrow(new BenchmarkError('runtime_identity_mismatch'));
  });

  test('reads Vite version metadata without executing the package bin', async () => {
    const root = await mkdtemp(join(tmpdir(), 'hermternal-vite-metadata-'));
    const packageRoot = join(root, 'vite');
    try {
      await mkdir(join(packageRoot, 'bin'), { recursive: true });
      const marker = join(root, 'executed');
      await writeFile(join(packageRoot, 'package.json'), JSON.stringify({ name: 'vite', version: '9.9.9' }));
      await writeFile(join(packageRoot, 'bin', 'vite.js'), `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'executed')`);
      expect(await readPackageVersion(root)).toBe('9.9.9');
      expect(await Bun.file(marker).exists()).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test('rejects oversized Vite metadata before JSON parsing', async () => {
    const root = await mkdtemp(join(tmpdir(), 'hermternal-vite-oversized-'));
    try {
      await mkdir(join(root, 'vite'), { recursive: true });
      await writeFile(join(root, 'vite', 'package.json'), Buffer.alloc(MAX_JSON_BYTES + 1, 0x20));
      await expect(readPackageVersion(root)).rejects.toThrow(new BenchmarkError('vite_metadata_unavailable'));
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test('bounds Vite metadata growth through the opened descriptor', async () => {
    let requestedLength = 0;
    let reads = 0;
    const opener = (async () => ({
      read: async (_buffer: Uint8Array, _offset: number, length: number) => {
        requestedLength = length;
        reads += 1;
        return { bytesRead: reads === 1 ? 1 : MAX_JSON_BYTES };
      },
      stat: async () => ({ size: 1 }),
      close: async () => {}
    })) as unknown as BoundedFileOpener;
    await expect(readPackageVersion('/replacement-race', opener)).rejects.toThrow(
      new BenchmarkError('vite_metadata_unavailable')
    );
    expect(requestedLength).toBe(MAX_JSON_BYTES);
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

  test('reserves one supervisor repetition for the excluded warm-up', async () => {
    const candidate = await workload();
    expect(() => parseArguments(['--warm', '100'], candidate)).toThrow(new BenchmarkError('argument_value_invalid'));
    expect(parseArguments(['--warm', '99'], candidate).warmRepetitions).toBe(99);
    const invalid = structuredClone(candidate);
    invalid.repetitions.warm = invalid.repetitions.maximum;
    expect(() => validateWorkload(invalid)).toThrow(new BenchmarkError('repetition_limit_invalid'));
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

  test('enforces a per-build timeout before the series deadline', async () => {
    const sandboxAvailable = process.platform === 'darwin'
      ? await Bun.file('/usr/bin/sandbox-exec').exists()
      : process.platform === 'linux' && await Bun.file('/usr/bin/bwrap').exists();
    if (!sandboxAvailable) return;
    const candidate = await workload();
    const root = await mkdtemp(join(tmpdir(), 'hermternal-timeout-test-'));
    const workspace = join(root, 'workspace');
    const dependencyRoot = join(root, 'dependencies');
    try {
      await mkdir(join(workspace, '.artifact-output'), { recursive: true });
      await mkdir(dependencyRoot, { recursive: true });
      const runtime = await protectedRuntime(candidate);
      const launcher = sandboxLauncher(
        runtime,
        workspace,
        dependencyRoot,
        candidate.limits.artifact_bytes,
        [runtime.nodePath, '-e', 'setTimeout(() => {}, 5000)'],
        -1,
        candidate.limits.artifact_files,
        1,
        candidate.limits.stdout_bytes,
        candidate.limits.stderr_bytes,
        100
      );
      const started = performance.now();
      const child = Bun.spawn([launcher.command, ...launcher.args], { cwd: workspace, stdout: 'pipe', stderr: 'pipe' });
      expect(await child.exited).toBe(124);
      expect(performance.now() - started).toBeLessThan(3000);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test('Linux warm series preserves generated state inside one tmpfs sandbox', async () => {
    if (process.platform !== 'linux' || !(await Bun.file('/usr/bin/bwrap').exists())) return;
    const candidate = structuredClone(await workload());
    candidate.build.entrypoint = 'warm-state-test.js';
    candidate.build.arguments = [];
    const root = await mkdtemp(join(tmpdir(), 'hermternal-linux-warm-state-'));
    const workspace = join(root, 'workspace');
    const dependencyRoot = join(root, 'dependencies');
    try {
      await mkdir(workspace, { recursive: true });
      await mkdir(dependencyRoot, { recursive: true });
      await writeFile(
        join(workspace, 'warm-state-test.js'),
        "const fs=require('node:fs');fs.mkdirSync('.artifact-output/build',{recursive:true});const state='.artifact-output/.svelte-kit/warm-state';if(!fs.existsSync(state)){fs.writeFileSync(state,'warm');process.exit(0)}fs.writeFileSync('.artifact-output/build/survived.txt','warm');"
      );
      const runtime = await protectedRuntime(candidate);
      const observations = await runBuildSeries(workspace, dependencyRoot, candidate, runtime, 2);
      expect(observations).toHaveLength(2);
      expect(observations[0]?.artifact_files).toBe(0);
      expect(observations[1]?.artifact_files).toBe(1);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test('immutable dependency snapshot binaries execute only inside the OS boundary', async () => {
    const sandboxAvailable = process.platform === 'darwin'
      ? await Bun.file('/usr/bin/sandbox-exec').exists()
      : process.platform === 'linux' && await Bun.file('/usr/bin/bwrap').exists();
    if (!sandboxAvailable) return;
    const candidate = await workload();
    const root = await mkdtemp(join(tmpdir(), 'hermternal-snapshot-binary-'));
    const workspace = join(root, 'workspace');
    const dependencyRoot = join(root, 'dependencies');
    const marker = join(root, 'outside-marker');
    try {
      await mkdir(join(workspace, '.artifact-output', 'build'), { recursive: true });
      await mkdir(dependencyRoot, { recursive: true });
      await writeFile(
        join(dependencyRoot, 'probe.js'),
        `const fs=require('node:fs');try{fs.writeFileSync(${JSON.stringify(marker)},'escaped');process.exit(9)}catch{fs.writeFileSync('.artifact-output/build/probe-ran','yes')}`
      );
      const runtime = await protectedRuntime(candidate);
      const launcher = sandboxLauncher(
        runtime,
        workspace,
        dependencyRoot,
        candidate.limits.artifact_bytes,
        [runtime.nodePath, join(dependencyRoot, 'probe.js')],
        1,
        candidate.limits.artifact_files,
        1,
        candidate.limits.stdout_bytes,
        candidate.limits.stderr_bytes
      );
      const child = Bun.spawn([launcher.command, ...launcher.args], {
        cwd: workspace,
        env: process.env,
        stdout: 'pipe',
        stderr: 'pipe'
      });
      const [exitCode, stdout] = await Promise.all([child.exited, new Response(child.stdout).text()]);
      expect(exitCode).toBe(0);
      expect(await Bun.file(marker).exists()).toBe(false);
      expect(stdout).toContain('HERMTERNAL_RESULT ');
    } finally {
      Bun.spawnSync(['/bin/chmod', '-R', 'u+w', root], { stdout: 'ignore', stderr: 'ignore' });
      await rm(root, { recursive: true, force: true });
    }
  });

  test('rejects installed Vite bytes changed under an unchanged lockfile', async () => {
    const appRoot = resolve(benchmarkRoot, '../..');
    const vitePackage = join(appRoot, 'node_modules', 'vite', 'package.json');
    const original = await readFile(vitePackage);
    try {
      await writeFile(vitePackage, Buffer.concat([original, Buffer.from('\\n')]));
      const result = Bun.spawnSync([process.execPath, join(benchmarkRoot, 'run.ts'), '--cold', '1', '--warm', '1'], {
        cwd: appRoot,
        stdout: 'pipe',
        stderr: 'pipe'
      });
      expect(result.exitCode).toBe(2);
      expect(new TextDecoder().decode(result.stderr)).toContain('dependency_identity_mismatch');
    } finally {
      await writeFile(vitePackage, original);
    }
  }, 15_000);

  test('enters the OS boundary before any PATH-selected Python shim can execute', async () => {
    const shimRoot = await mkdtemp(join(tmpdir(), 'hermternal-python-shim-'));
    const marker = join(shimRoot, 'executed');
    const shim = join(shimRoot, 'python3');
    try {
      await writeFile(shim, `#!/bin/sh\n: > ${JSON.stringify(marker)}\nexit 91\n`);
      await chmod(shim, 0o755);
      expect(await sandboxNetworkAttempt(false, `${shimRoot}:/usr/bin:/bin`)).toBe(0);
      expect(await Bun.file(marker).exists()).toBe(false);
    } finally {
      await rm(shimRoot, { recursive: true, force: true });
    }
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
      join(workspace, '.supervisor'),
      join(workspace, 'node_modules', '.vite-temp')
    ]) await mkdir(path, { recursive: true });
    const target = join(dependencyRoot, 'mutation');
    try {
      const command = `const fs=require('node:fs');try{fs.writeFileSync(${JSON.stringify(target)},'changed');process.exit(9)}catch{process.exit(0)}`;
      const candidate = await workload();
      const runtime = await protectedRuntime(candidate);
      const launcher = sandboxLauncher(runtime, workspace, dependencyRoot, 1048576, [process.execPath, '-e', command]);
      const child = Bun.spawn([launcher.command, ...launcher.args], { cwd: workspace, stdout: 'pipe', stderr: 'pipe' });
      expect(await child.exited).toBe(0);
      expect(await Bun.file(target).exists()).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test('64 MiB aggregate quota rejects a transient 128 MiB output symlink escape', async () => {
    if (process.platform !== 'darwin') return;
    const workspace = await mkdtemp(join(tmpdir(), 'hermternal-quota-test-'));
    const dependencyRoot = join(workspace, 'dependencies');
    await mkdir(dependencyRoot, { recursive: true });
    const quotaBytes = 64 * 1024 * 1024;
    try {
      await mountArtifactQuota(workspace, quotaBytes);
      const output = join(workspace, '.artifact-output', 'build');
      const alternate = join(workspace, '.artifact-output', '.tmp');
      await mkdir(alternate, { recursive: true });
      const command = `const fs=require('node:fs');const output=${JSON.stringify(output)};const alternate=${JSON.stringify(alternate)};fs.symlinkSync(alternate,output,'dir');let blocked=false;try{const fd=fs.openSync(output+'/peak.bin','w');try{const chunk=Buffer.alloc(1048576);for(let index=0;index<128;index+=1)fs.writeSync(fd,chunk)}finally{fs.closeSync(fd)}}catch{blocked=true}fs.rmSync(output,{recursive:true,force:true});fs.mkdirSync(output,{recursive:true});fs.writeFileSync(output+'/final.txt','ok');process.exit(blocked?0:9)`;
      const candidate = await workload();
      const runtime = await protectedRuntime(candidate);
      const launcher = sandboxLauncher(runtime, workspace, dependencyRoot, quotaBytes, [process.execPath, '-e', command]);
      const child = Bun.spawn([launcher.command, ...launcher.args], { cwd: workspace, stdout: 'pipe', stderr: 'pipe' });
      expect(await child.exited).toBe(0);
      expect((await readFile(join(output, 'final.txt'))).byteLength).toBe(2);
    } finally {
      await removeWorkspace(workspace);
    }
  }, 90_000);

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

  test('artifact scanner rejects growth, shrink, mutation, and path replacement', async () => {
    const root = await mkdtemp(join(tmpdir(), 'hermternal-artifact-stability-'));
    const workspace = join(root, 'workspace');
    const output = join(workspace, '.artifact-output', 'build');
    const artifact = join(output, 'artifact.bin');
    await mkdir(output, { recursive: true });
    const mutations: Array<[string, () => Promise<void>]> = [
      ['growth', () => writeFile(artifact, Buffer.from([9]), { flag: 'a' })],
      ['shrink', () => truncate(artifact, 512 * 1024)],
      ['same-size mutation', () => writeFile(artifact, Buffer.alloc(1024 * 1024, 8))],
      ['path replacement', async () => {
        await rename(artifact, join(output, 'replaced.bin'));
        await writeFile(artifact, Buffer.alloc(1024 * 1024, 7));
      }]
    ];
    try {
      for (const [name, mutate] of mutations) {
        await rm(output, { recursive: true, force: true });
        await mkdir(output, { recursive: true });
        await writeFile(artifact, Buffer.alloc(1024 * 1024, 7));
        const ready = join(root, `scanner-ready-${name.replaceAll(' ', '-')}`);
        const scanner = spawn('/usr/bin/python3', [
          join(benchmarkRoot, 'artifact-scanner.py'),
          '--workspace', workspace,
          '--root', '.artifact-output/build',
          '--max-files', '1',
          '--max-bytes', String(2 * 1024 * 1024),
          '--test-pause-ms', '500',
          '--test-ready-file', ready
        ], {
          env: { ...process.env, HERMTERNAL_SCANNER_TEST_MODE: '1' },
          stdio: ['ignore', 'pipe', 'pipe']
        });
        for (let attempt = 0; attempt < 100 && !(await Bun.file(ready).exists()); attempt += 1) await Bun.sleep(10);
        expect(await Bun.file(ready).exists()).toBe(true);
        await mutate();
        const exitCode = await new Promise<number | null>((resolveExit) => scanner.once('exit', resolveExit));
        expect(exitCode).toBe(2);
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 10_000);

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

  test('fast detached descendants cannot survive completion, SIGINT, or SIGTERM', async () => {
    if (process.platform !== 'darwin') return;
    const root = await mkdtemp(join(tmpdir(), 'hermternal-setsid-test-'));
    const workspace = join(root, 'workspace');
    const dependencyRoot = join(root, 'dependencies');
    await mkdir(join(workspace, '.artifact-output'), { recursive: true });
    await mkdir(dependencyRoot, { recursive: true });
    try {
      const candidate = await workload();
      const runtime = await protectedRuntime(candidate);
      for (const mode of ['completion', 'SIGINT', 'SIGTERM'] as const) {
        const detachedScript = `const {spawn}=require('node:child_process');try{const escaped=spawn(process.execPath,['-e',"process.on('SIGTERM',()=>{});process.on('SIGINT',()=>{});setInterval(()=>{},1000)"],{detached:true,stdio:'ignore'});console.log(escaped.pid);${mode === 'completion' ? 'process.exit(0)' : 'setInterval(()=>{},1000)' }}catch{console.log('denied');${mode === 'completion' ? 'process.exit(0)' : 'setInterval(()=>{},1000)' }}`;
        const launcher = sandboxLauncher(runtime, workspace, dependencyRoot, 1048576, [runtime.nodePath, '-e', detachedScript]);
        const child = spawn(launcher.command, launcher.args, {
          cwd: workspace,
          detached: true,
          env: process.env,
          stdio: ['ignore', 'pipe', 'pipe']
        });
        const line = await Promise.race([
          new Promise<string>((resolveLine, reject) => {
            child.stdout.once('data', (chunk) => resolveLine(String(chunk).trim()));
            child.once('error', reject);
          }),
          Bun.sleep(10_000).then(() => { throw new Error(`${mode} descendant readiness timeout`); })
        ]);
        const supervisorExited = new Promise<number | null>((resolveExit) => child.once('exit', resolveExit));
        if (mode !== 'completion' && child.pid) process.kill(-child.pid, mode);
        await Promise.race([
          supervisorExited,
          Bun.sleep(10_000).then(() => { throw new Error(`${mode} supervisor survived cleanup`); })
        ]);
        if (/^\d+$/.test(line)) expect(() => process.kill(Number(line), 0)).toThrow();
        else expect(line).toBe('denied');
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 60_000);

  test('SIGTERM finishes registered cleanup before exit across repeated runs', async () => {
    const prefix = 'hermternal-web-benchmark-';
    for (let iteration = 0; iteration < 20; iteration += 1) {
      const before = new Set((await readdir(tmpdir())).filter((name) => name.startsWith(prefix)));
      const readinessFile = join(tmpdir(), `hermternal-benchmark-ready-${process.pid}-${iteration}`);
      await rm(readinessFile, { force: true });
      const child = spawn(process.execPath, [join(benchmarkRoot, 'run.ts'), '--cold', '1', '--warm', '1'], {
        cwd: resolve(benchmarkRoot, '../..'),
        env: { ...process.env, HERMTERNAL_BENCHMARK_READY_FILE: readinessFile },
        stdio: ['ignore', 'pipe', 'pipe']
      });
      const exited = new Promise<number | null>((resolveExit) => child.once('exit', resolveExit));
      await Promise.race([
        (async () => {
          for (let attempt = 0; attempt < 3000; attempt += 1) {
            if (await Bun.file(readinessFile).exists()) return;
            if (child.exitCode !== null) throw new Error(`runner exited before readiness: ${child.exitCode}`);
            await Bun.sleep(10);
          }
          throw new Error('runner readiness timeout');
        })(),
        new Promise<never>((_, reject) => child.once('error', reject))
      ]);
      child.kill('SIGTERM');
      const exitCode = await Promise.race([
        exited,
        Bun.sleep(10_000).then(() => { throw new Error('runner signal cleanup deadline exceeded'); })
      ]);
      expect(exitCode).toBe(143);
      const after = (await readdir(tmpdir())).filter((name) => name.startsWith(prefix) && !before.has(name));
      expect(after).toEqual([]);
      await rm(readinessFile, { force: true });
    }
  }, 300_000);

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
