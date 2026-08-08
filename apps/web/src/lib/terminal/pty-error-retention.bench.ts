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

async function prepareOpenedAttach(): Promise<{
  readonly error: () => void;
  readonly state: () => string;
}> {
  const sockets: BenchmarkSocket[] = [];
  const transport = createPtyTransport({
    now: () => NOW_MS,
    validateAttachment: () => true,
    ticketProvider: async () => "benchmark-ticket",
    createWebSocket: () => {
      const socket = new BenchmarkSocket();
      sockets.push(socket);
      return socket;
    },
  });
  const pending = transport.connect(INPUT);
  for (let index = 0; index < 16; index += 1) await Promise.resolve();
  const socket = sockets[0];
  if (!socket?.onopen || !socket.onerror) throw new Error("benchmark setup failed");
  socket.readyState = 1;
  socket.onopen();
  await pending;
  const error = socket.onerror;
  return {
    error: () => error?.(),
    state: () => transport.state.status,
  };
}

for (let index = 0; index < WARMUPS; index += 1) {
  const prepared = await prepareOpenedAttach();
  prepared.error();
  if (prepared.state() !== "detached") throw new Error("warmup did not detach");
}

const samples: number[] = [];
for (let index = 0; index < REPETITIONS; index += 1) {
  const prepared = await prepareOpenedAttach();
  const started = performance.now();
  prepared.error();
  samples.push(performance.now() - started);
  if (prepared.state() !== "detached") throw new Error("error cleanup did not detach");
}

const sorted = samples.toSorted((left, right) => left - right);
const round = (value: number): number => Number(value.toFixed(6));
console.log(JSON.stringify({
  schema: "hermternal.pty-error-retention-benchmark.v1",
  operation: "opened attach adapter error cleanup and retention-anchor capture",
  metric: { name: "error_cleanup_and_anchor_wall_time", unit: "ms", clock: "performance.now" },
  method: "R-7 inclusive linear interpolation",
  repetitions: REPETITIONS,
  warmups: WARMUPS,
  exclusions: ["ticket minting", "socket creation", "rendering", "network"],
  setupProof: { openedAttachPerOperation: 1, errorOnly: true },
  distribution: {
    p50: round(percentile(sorted, 0.5)),
    p95: round(percentile(sorted, 0.95)),
    p99: round(percentile(sorted, 0.99)),
  },
  threshold: null,
}, null, 2));
