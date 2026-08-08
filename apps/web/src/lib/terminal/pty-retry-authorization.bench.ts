import {
  createPtyTransport,
  type PtyConnectionInput,
  type PtyWebSocket,
} from "./pty-transport";

const REPETITIONS = 1_000;
const WARMUPS = 100;
const NOW_MS = 50_000;
const INPUT: PtyConnectionInput = {
  sessionId: "benchmark-session",
  attach: "benchmark-attach",
  processIdentity: "benchmark-process",
};

class BenchmarkSocket implements PtyWebSocket {
  onopen: ((event?: unknown) => void) | null = null;
  onmessage: ((event: { readonly data: unknown }) => void) | null = null;
  onerror: ((event?: unknown) => void) | null = null;
  onclose: ((event?: { readonly code?: number }) => void) | null = null;
  readyState = 0;

  send(): void {}

  close(): void {
    this.readyState = 3;
  }
}

function percentile(sorted: readonly number[], quantile: number): number {
  const position = (sorted.length - 1) * quantile;
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  if (lower === upper) return sorted[lower]!;
  const fraction = position - lower;
  return sorted[lower]! + (sorted[upper]! - sorted[lower]!) * fraction;
}

const sockets: BenchmarkSocket[] = [];
let ticketCalls = 0;
const transport = createPtyTransport({
  now: () => NOW_MS,
  validateAttachment: () => true,
  ticketProvider: async () => {
    ticketCalls += 1;
    return `benchmark-ticket-${ticketCalls}`;
  },
  createWebSocket: () => {
    const socket = new BenchmarkSocket();
    sockets.push(socket);
    return socket;
  },
});

const initial = transport.connect(INPUT);
for (let index = 0; index < 16; index += 1) await Promise.resolve();
const socket = sockets[0];
if (!socket?.onopen || !socket.onclose) throw new Error("benchmark setup failed");
socket.readyState = 1;
socket.onopen();
await initial;
socket.onclose({ code: 4409 });

async function assertBlockedRetry(decision: Promise<void>): Promise<void> {
  try {
    await decision;
    throw new Error("blocked retry unexpectedly succeeded");
  } catch (error) {
    if (
      typeof error !== "object" ||
      error === null ||
      !("code" in error) ||
      error.code !== "attachment-superseded"
    ) {
      throw error;
    }
  }
}

for (let index = 0; index < WARMUPS; index += 1) {
  await assertBlockedRetry(transport.connect({ ...INPUT, detachedAtMs: NOW_MS }));
}

const samples: number[] = [];
for (let index = 0; index < REPETITIONS; index += 1) {
  const started = performance.now();
  const decision = transport.connect({ ...INPUT, detachedAtMs: NOW_MS });
  samples.push(performance.now() - started);
  await assertBlockedRetry(decision);
}

if (ticketCalls !== 1 || sockets.length !== 1) {
  throw new Error("benchmark included unauthorized ticket or socket work");
}

const sorted = samples.toSorted((left, right) => left - right);
const round = (value: number): number => Number(value.toFixed(6));
console.log(JSON.stringify({
  schema: "hermternal.pty-retry-authorization-benchmark.v1",
  operation: "same-identity retry decision blocked after 4409",
  metric: { name: "blocked_retry_decision_wall_time", unit: "ms", clock: "performance.now" },
  method: "R-7 inclusive linear interpolation",
  repetitions: REPETITIONS,
  warmups: WARMUPS,
  exclusions: ["ticket minting", "socket creation", "rendering", "network"],
  authorizationProof: { ticketCalls, socketCreations: sockets.length },
  distribution: {
    p50: round(percentile(sorted, 0.5)),
    p95: round(percentile(sorted, 0.95)),
    p99: round(percentile(sorted, 0.99)),
  },
  threshold: null,
}, null, 2));
