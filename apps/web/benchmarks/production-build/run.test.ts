import { describe, expect, test } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { BenchmarkError, distribution, parseArguments, roundRationalHalfEven, validateWorkload, type Workload } from './run';

const benchmarkRoot = import.meta.dir;

async function workload(): Promise<Workload> {
  return validateWorkload(JSON.parse(await readFile(join(benchmarkRoot, 'workload.json'), 'utf8')));
}

describe('production-build benchmark contract', () => {
  test('accepts the reviewed deterministic workload', async () => {
    const candidate = await workload();
    expect(candidate.network.mode).toBe('deny');
    expect(candidate.repetitions).toEqual({ cold: 30, warm: 30, maximum: 100 });
    expect(candidate.build.version_name).toBe('hermternal-web-production-build-v1');
    expect(candidate.limits.artifact_bytes).toBe(67_108_864);
  });

  test('rejects unbounded resource mutations', async () => {
    const candidate = structuredClone(await workload());
    candidate.limits.build_timeout_ms = 300_001;
    expect(() => validateWorkload(candidate)).toThrow(new BenchmarkError('resource_limit_invalid'));
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

  test('preload guard denies fetch before a network request can start', () => {
    const guard = pathToFileURL(join(benchmarkRoot, 'network-guard.mjs')).href;
    const result = Bun.spawnSync(
      [
        process.execPath,
        '--smol',
        '-e',
        `import ${JSON.stringify(guard)}; try { await fetch('https://example.invalid'); } catch (error) { console.log(error.message); }`
      ],
      { stdout: 'pipe', stderr: 'pipe' }
    );
    expect(result.exitCode).toBe(0);
    expect(new TextDecoder().decode(result.stderr)).toBe('');
    expect(new TextDecoder().decode(result.stdout).trim()).toBe('network access denied by production-build benchmark');
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
