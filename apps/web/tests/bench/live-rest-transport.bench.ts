import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createLiveRestTransport } from '../../src/lib/transport/live-rest-transport';

function reviewedSourceCommit(): string {
  const commit = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  if (!/^[0-9a-f]{40}$/u.test(commit)) {
    throw new Error('benchmark source commit is not a full Git SHA');
  }
  return commit;
}

const SOURCE_COMMIT = reviewedSourceCommit();
const PINNED_HERMES_SHA = 'f5be9236e00ddf2f2a412697f267078fc4ee068e';
const COMMAND = 'bun tests/bench/live-rest-transport.bench.ts';
const WARMUPS = 5;
const REPETITIONS = 30;

type Distribution = {
  min: number;
  p50: number;
  p95: number;
  p99: number;
  max: number;
  mean: number;
};

type Measurement = {
  bodyBytes: number;
  rawSamples: number[];
  distribution: Distribution;
};

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function roundThree(value: number): number {
  const scaled = value * 1_000;
  const lower = Math.floor(scaled);
  const fraction = scaled - lower;
  const rounded = fraction > 0.5 || (fraction === 0.5 && lower % 2 !== 0) ? lower + 1 : lower;
  return rounded / 1_000;
}

function percentile(values: number[], quantile: number): number {
  const sorted = [...values].sort((left, right) => left - right);
  const position = (sorted.length - 1) * quantile;
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  const lowerValue = sorted[lower] ?? 0;
  const upperValue = sorted[upper] ?? lowerValue;
  return lower === upper ? lowerValue : lowerValue + (upperValue - lowerValue) * (position - lower);
}

function summarize(values: number[]): Distribution {
  const sorted = [...values].sort((left, right) => left - right);
  const mean = values.reduce((total, value) => total + value, 0) / values.length;
  return {
    min: roundThree(sorted[0] ?? 0),
    p50: roundThree(percentile(values, 0.5)),
    p95: roundThree(percentile(values, 0.95)),
    p99: roundThree(percentile(values, 0.99)),
    max: roundThree(sorted.at(-1) ?? 0),
    mean: roundThree(mean)
  };
}

async function measure(
  body: string,
  run: (transport: ReturnType<typeof createLiveRestTransport>) => Promise<unknown>
): Promise<Measurement> {
  const fetcher = async () =>
    new Response(body, {
      status: 200,
      headers: { 'content-type': 'application/json' }
    });
  const transport = createLiveRestTransport({ fetch: fetcher });

  for (let index = 0; index < WARMUPS; index += 1) {
    await run(transport);
  }

  const rawSamples: number[] = [];
  for (let index = 0; index < REPETITIONS; index += 1) {
    const started = performance.now();
    await run(transport);
    rawSamples.push(performance.now() - started);
  }

  const recordedSamples = rawSamples.map((value) => Number(value.toFixed(6)));
  return {
    bodyBytes: Buffer.byteLength(body, 'utf8'),
    rawSamples: recordedSamples,
    distribution: summarize(recordedSamples)
  };
}

const sessionId = 'synthetic-session-0001';
const messagesBody = JSON.stringify({
  session_id: sessionId,
  messages: Array.from({ length: 500 }, () => ({
    role: 'assistant',
    content: 'Synthetic benchmark message'
  })),
  pagination: { limit: 500, offset: 0, returned: 500 }
});
const sessionsBody = JSON.stringify({
  sessions: Array.from({ length: 100 }, (_, index) => ({
    id: `synthetic-session-${String(index + 1).padStart(4, '0')}`,
    source: 'synthetic',
    model: 'synthetic-model',
    title: 'Synthetic benchmark session',
    started_at: 1_767_225_600 + index,
    ended_at: null,
    last_active: 1_767_225_601 + index,
    is_active: false,
    message_count: 1,
    tool_call_count: 0,
    input_tokens: 0,
    output_tokens: 0,
    preview: 'Synthetic benchmark preview',
    profile: 'synthetic-profile',
    is_default_profile: true,
    archived: false,
    pinned: false
  })),
  total: 100,
  limit: 100,
  offset: 0
});

const sessions = await measure(sessionsBody, (transport) => transport.listSessions({ limit: 100 }));
const messages = await measure(messagesBody, (transport) =>
  transport.getSessionMessages(sessionId, { limit: 500 })
);

const environment = {
  runtime: `bun-${process.versions.bun ?? 'unknown'}`,
  node: process.version,
  platform: process.platform,
  arch: process.arch
};
const revision = {
  source_commit: SOURCE_COMMIT,
  fixture_id: 'w06-live-rest-route-cap-v1',
  fixture_version: '1',
  pinned_hermes_source_sha: PINNED_HERMES_SHA
};
const metric = {
  name: 'typed_rest_parse_and_projection',
  unit: 'ms',
  clock: 'performance.now'
};
const method = {
  percentile: 'inclusive-linear-r7',
  quantiles: [0.5, 0.95, 0.99],
  rounding: 'decimal-half-even-to-three-places',
  warmups: WARMUPS,
  repetitions: REPETITIONS
};
const runs = [
  {
    run_id: 'sessions_100',
    platform: 'web',
    state: 'warm',
    build_mode: 'not_applicable',
    optimization: 'normal',
    command: COMMAND,
    environment,
    raw_samples: sessions.rawSamples,
    repetitions: REPETITIONS,
    sample_provenance: {
      body_bytes: sessions.bodyBytes,
      body_sha256: sha256(sessionsBody),
      route: '/api/sessions?limit=100'
    },
    distribution: sessions.distribution
  },
  {
    run_id: 'messages_500',
    platform: 'web',
    state: 'warm',
    build_mode: 'not_applicable',
    optimization: 'normal',
    command: COMMAND,
    environment,
    raw_samples: messages.rawSamples,
    repetitions: REPETITIONS,
    sample_provenance: {
      body_bytes: messages.bodyBytes,
      body_sha256: sha256(messagesBody),
      route: '/api/sessions/{session_id}/messages?limit=500'
    },
    distribution: messages.distribution
  }
];
const traceArtifact = {
  schema: 'hermternal.benchmark-trace.v1',
  revision,
  metric,
  method,
  environment,
  runs,
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

console.log(`transport.benchmark.sessions_100_bytes=${sessions.bodyBytes}`);
console.log(`transport.benchmark.messages_500_bytes=${messages.bodyBytes}`);
console.log(`transport.benchmark.iterations=${REPETITIONS}_warmups=${WARMUPS}`);
console.log(`transport.benchmark.environment=${JSON.stringify(environment)}`);
console.log(`transport.benchmark.provenance=${JSON.stringify(revision)}`);
for (const run of runs) {
  const prefix = `transport.benchmark.${run.run_id}`;
  console.log(`${prefix}_raw_samples=${JSON.stringify(run.raw_samples)}`);
  for (const [key, value] of Object.entries(run.distribution)) {
    console.log(`${prefix}_${key}_ms=${value.toFixed(3)}`);
  }
}
const traceText = JSON.stringify(traceArtifact);
console.log(`transport.benchmark.trace_bytes=${Buffer.byteLength(traceText, 'utf8')}`);
console.log(`transport.benchmark.trace_sha256=${sha256(traceText)}`);
console.log(`transport.benchmark.trace=${traceText}`);
