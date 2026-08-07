import { arch, platform, release } from 'node:os';
import { statSync } from 'node:fs';
import {
  PINNED_DASHBOARD_CONTRACT,
  PINNED_HERMES_SOURCE_SHA,
  createSessionCoordinator,
  type ChatSessionPort,
  type TerminalSessionPort
} from './coordinator';

const REPETITIONS = 30;
const WARMUPS = 5;
const OPERATIONS_PER_REPETITION = 1_000;
const SESSION_ID = 'benchmark-session-001';
const BASE_COMMIT = '7fd050624ec6757fe98d1716cbd2091f5d334251';

interface Distribution {
  min: number;
  p50: number;
  p95: number;
  p99: number;
  max: number;
  mean: number;
}

function percentile(sorted: readonly number[], fraction: number): number {
  const position = (sorted.length - 1) * fraction;
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  const weight = position - lower;
  return sorted[lower]! + (sorted[upper]! - sorted[lower]!) * weight;
}

function summarize(samples: readonly number[]): Distribution {
  const sorted = [...samples].sort((left, right) => left - right);
  const mean = samples.reduce((sum, value) => sum + value, 0) / samples.length;
  const round = (value: number): number => Number(value.toFixed(6));
  return {
    min: round(sorted[0] ?? 0),
    p50: round(percentile(sorted, 0.5)),
    p95: round(percentile(sorted, 0.95)),
    p99: round(percentile(sorted, 0.99)),
    max: round(sorted.at(-1) ?? 0),
    mean: round(mean)
  };
}

function createBenchmarkChat(): ChatSessionPort {
  let status: 'ready' = 'ready';
  let selectedSessionId = SESSION_ID;
  return {
    get state() {
      return { status, generation: 1 };
    },
    get selectedSessionId() {
      return selectedSessionId;
    },
    async connect() {
      status = 'ready';
    },
    async reconnect() {
      status = 'ready';
    },
    async restore(sessionId: string) {
      selectedSessionId = sessionId;
      status = 'ready';
    },
    close() {
      status = 'ready';
    }
  };
}

function createBenchmarkTerminal(): TerminalSessionPort {
  return {
    attach(sessionId: string) {
      return {
        sessionId,
        invalidate() {}
      };
    },
    release() {}
  };
}

async function measureTransitions(): Promise<number> {
  const coordinator = createSessionCoordinator({
    chat: createBenchmarkChat(),
    terminal: createBenchmarkTerminal(),
    deployment: {
      status: 'compatible',
      contract: PINNED_DASHBOARD_CONTRACT,
      hermesSourceSha: PINNED_HERMES_SOURCE_SHA
    },
    initialSessionId: SESSION_ID
  });
  await coordinator.activate('terminal');
  await coordinator.activate('chat');

  const started = performance.now();
  for (let index = 0; index < OPERATIONS_PER_REPETITION; index += 1) {
    await coordinator.activate(index % 2 === 0 ? 'terminal' : 'chat');
  }
  return performance.now() - started;
}

const samples: number[] = [];
for (let index = 0; index < WARMUPS; index += 1) await measureTransitions();
for (let index = 0; index < REPETITIONS; index += 1) {
  samples.push(await measureTransitions());
}

const sourcePath = new URL('./coordinator.ts', import.meta.url);
const benchmarkPath = new URL('./coordinator.bench.ts', import.meta.url);
const result = {
  schema: 'hermternal.web-session-coordinator-benchmark.v1',
  workload: 'in_memory_mode_transitions',
  source: 'apps/web/src/lib/session/coordinator.ts',
  benchmark: 'apps/web/src/lib/session/coordinator.bench.ts',
  base_commit: BASE_COMMIT,
  pinned_dashboard_contract: PINNED_DASHBOARD_CONTRACT,
  pinned_hermes_source_sha: PINNED_HERMES_SOURCE_SHA,
  metric: 'milliseconds_per_1000_mode_transitions',
  environment: `${platform()}-${release()}-${arch()} / Bun ${process.versions.bun ?? 'unknown'}`,
  build_mode: 'direct TypeScript benchmark',
  build_mode_reason:
    'Only in-memory coordinator state, fake adapters, and mode transitions are measured; network, renderer, and transcript work are outside the loop.',
  warmups: WARMUPS,
  repetitions: REPETITIONS,
  operations_per_repetition: OPERATIONS_PER_REPETITION,
  raw_samples_ms: samples.map((sample) => Number(sample.toFixed(6))),
  distribution_ms: summarize(samples),
  network_calls: 0,
  renderer_operations: 0,
  transcript_mirror_entries: 0,
  artifact_bytes: statSync(sourcePath).size + statSync(benchmarkPath).size,
  threshold: null,
  threshold_reason: 'No reviewed runtime budget exists for this planning-only coordinator.',
  measurement_authenticated: false
};

process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
