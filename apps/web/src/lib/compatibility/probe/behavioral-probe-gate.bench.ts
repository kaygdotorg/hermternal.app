import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createBehavioralProbeFixtureEvidence,
  evaluateBehavioralProbeGate
} from './behavioral-probe-gate';

const REPETITIONS = 30;
const WARMUPS = 5;
const BASE_COMMIT = '7eb082509125ef3ffed8e141b200c4c5156cf631';
const COMMANDS = {
  normal: 'bun build behavioral-probe-gate.bench.ts --target=bun --outfile=<temp>/normal.mjs && bun <temp>/normal.mjs --worker normal',
  optimized: 'bun build behavioral-probe-gate.bench.ts --target=bun --minify --outfile=<temp>/optimized.mjs && bun <temp>/optimized.mjs --worker optimized'
} as const;

type Optimization = keyof typeof COMMANDS;
type Distribution = Readonly<{
  min: number;
  p50: number;
  p95: number;
  p99: number;
  max: number;
  mean: number;
}>;

type WorkerResult = Readonly<{
  optimization: Optimization;
  environment: Readonly<Record<string, string>>;
  runs: ReadonlyArray<{
    run_id: string;
    raw_samples: number[];
    distribution: Distribution;
  }>;
}>;

function sha256Bytes(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function roundRationalMicromilliseconds(numerator: bigint, denominator: bigint): number {
  const divisor = denominator * 1_000n;
  const quotient = numerator / divisor;
  const remainder = numerator % divisor;
  const doubled = remainder * 2n;
  const rounded = doubled > divisor || (doubled === divisor && quotient % 2n === 1n)
    ? quotient + 1n
    : quotient;
  return Number(rounded) / 1_000;
}

function percentile(values: readonly number[], quantileNumerator: bigint, quantileDenominator: bigint): number {
  const sorted = values.map((value) => BigInt(Math.round(value * 1_000_000))).sort((left, right) =>
    left < right ? -1 : left > right ? 1 : 0
  );
  const positionNumerator = BigInt(sorted.length - 1) * quantileNumerator;
  const lower = positionNumerator / quantileDenominator;
  const remainder = positionNumerator % quantileDenominator;
  const low = sorted[Number(lower)]!;
  const high = sorted[Math.min(Number(lower + 1n), sorted.length - 1)]!;
  return roundRationalMicromilliseconds(
    low * quantileDenominator + (high - low) * remainder,
    quantileDenominator
  );
}

function summarize(values: readonly number[]): Distribution {
  const units = values.map((value) => BigInt(Math.round(value * 1_000_000)));
  const sorted = [...units].sort((left, right) => left < right ? -1 : left > right ? 1 : 0);
  return {
    min: roundRationalMicromilliseconds(sorted[0]!, 1n),
    p50: percentile(values, 1n, 2n),
    p95: percentile(values, 19n, 20n),
    p99: percentile(values, 99n, 100n),
    max: roundRationalMicromilliseconds(sorted.at(-1)!, 1n),
    mean: roundRationalMicromilliseconds(units.reduce((sum, value) => sum + value, 0n), BigInt(units.length))
  };
}

function measure(run: () => unknown): { raw_samples: number[]; distribution: Distribution } {
  for (let index = 0; index < WARMUPS; index += 1) run();
  const raw: number[] = [];
  for (let index = 0; index < REPETITIONS; index += 1) {
    const started = performance.now();
    run();
    raw.push(Number((performance.now() - started).toFixed(6)));
  }
  return { raw_samples: raw, distribution: summarize(raw) };
}

function worker(optimization: Optimization): WorkerResult {
  const canonical = createBehavioralProbeFixtureEvidence('success');
  // This maximum-sized primitive is inert but adversarial: it forces the total
  // UTF-8 scan and then fails before parser allocation or object inspection.
  const boundedHostileText = 'a'.repeat(262_144);
  return {
    optimization,
    environment: {
      runtime: `bun-${process.versions.bun ?? 'unknown'}`,
      platform: process.platform,
      arch: process.arch,
      cpu: execFileSync('sysctl', ['-n', 'machdep.cpu.brand_string'], { encoding: 'utf8' }).trim(),
      device: execFileSync('sysctl', ['-n', 'hw.model'], { encoding: 'utf8' }).trim(),
      os: `macOS-${execFileSync('sw_vers', ['-productVersion'], { encoding: 'utf8' }).trim()}`,
      kernel: `Darwin-${execFileSync('uname', ['-r'], { encoding: 'utf8' }).trim()}`,
      build: optimization === 'optimized' ? 'bun-target-bun-minified' : 'bun-target-bun'
    },
    runs: [
      { run_id: 'canonical_success', ...measure(() => evaluateBehavioralProbeGate(canonical)) },
      { run_id: 'bounded_hostile_text', ...measure(() => evaluateBehavioralProbeGate(boundedHostileText)) }
    ]
  };
}

const workerIndex = process.argv.indexOf('--worker');
if (workerIndex >= 0) {
  const optimization = process.argv[workerIndex + 1];
  if (optimization !== 'normal' && optimization !== 'optimized') throw new Error('invalid worker mode');
  console.log(JSON.stringify(worker(optimization)));
} else {
  const sourcePath = fileURLToPath(import.meta.url);
  const sourceDirectory = resolve(sourcePath, '..');
  const repositoryRoot = resolve(sourceDirectory, '../../../../../..');
  const temporary = mkdtempSync(resolve(tmpdir(), 'hermternal-probe-benchmark-'));
  try {
    const results: WorkerResult[] = [];
    for (const optimization of ['normal', 'optimized'] as const) {
      const output = resolve(temporary, `${optimization}.mjs`);
      const buildArguments = ['build', sourcePath, '--target=bun', `--outfile=${output}`];
      if (optimization === 'optimized') buildArguments.splice(3, 0, '--minify');
      execFileSync('bun', buildArguments, { stdio: ['ignore', 'ignore', 'inherit'] });
      results.push(JSON.parse(execFileSync('bun', [output, '--worker', optimization], {
        encoding: 'utf8',
        env: process.env
      })) as WorkerResult);
    }
    const evaluatorPath = resolve(sourceDirectory, 'behavioral-probe-gate.ts');
    const evidence = {
      schema: 'hermternal.web-behavioral-probe-benchmark.v1',
      revision: {
        source_base_commit: BASE_COMMIT,
        evaluator_path: 'apps/web/src/lib/compatibility/probe/behavioral-probe-gate.ts',
        evaluator_sha256: sha256Bytes(evaluatorPath),
        benchmark_harness_path: 'apps/web/src/lib/compatibility/probe/behavioral-probe-gate.bench.ts',
        benchmark_harness_sha256: sha256Bytes(sourcePath),
        fixture_id: 'behavioral-probe-canonical-success-and-bounded-hostile-text-v1',
        pinned_hermes_source_sha: 'f5be9236e00ddf2f2a412697f267078fc4ee068e'
      },
      metric: { name: 'synchronous_evaluator_wall_time', unit: 'ms', clock: 'performance.now' },
      method: {
        percentile: 'inclusive-linear-r7',
        quantiles: [0.5, 0.95, 0.99],
        rounding: 'decimal-half-even-to-three-places',
        warmups: WARMUPS,
        repetitions: REPETITIONS
      },
      runs: results.flatMap((result) => result.runs.map((run) => ({
        run_id: `${run.run_id}_${result.optimization}`,
        platform: 'web',
        state: 'warm',
        build_mode: 'production',
        optimization: result.optimization,
        command: COMMANDS[result.optimization],
        environment: result.environment,
        repetitions: REPETITIONS,
        raw_samples: run.raw_samples,
        distribution: run.distribution
      }))),
      redaction: {
        synthetic_only: true,
        network_access: false,
        provider_access: false,
        credentials: false,
        cookies: false,
        tickets: false,
        hostnames: false,
        user_data: false
      },
      threshold: null,
      budget: null
    };
    console.log(JSON.stringify(evidence, null, 2));
    console.error(`benchmark.source=${basename(sourcePath)} repository=${basename(repositoryRoot)}`);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}
