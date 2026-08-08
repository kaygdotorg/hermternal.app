import {
  capturePtyBenchmarkProvenance,
  distribution,
  roundSample,
} from "./pty-benchmark-provenance";
import {
  createPtyTransport,
  type PtyConnectionInput,
  type PtyTransport,
  type PtyTransportEvent,
  type PtyWebSocket,
  type PtyWebSocketUpgradeRequest,
} from "./pty-transport";

const REPETITIONS = 30;
const WARMUPS = 5;
const TIMEOUT_MS = 1_000;
const INPUT: PtyConnectionInput = {
  sessionId: "benchmark-session-a",
  attach: "benchmark-attach-a",
  processIdentity: "benchmark-process-a",
};
const REPLACEMENT_INPUT: PtyConnectionInput = {
  sessionId: "benchmark-session-b",
  attach: "benchmark-attach-b",
  processIdentity: "benchmark-process-b",
};
const ACTIONS = ["abort", "close", "detach", "replace"] as const;
type Action = (typeof ACTIONS)[number];

class BenchmarkSocket implements PtyWebSocket {
  readonly identity: string;
  onopen: ((event?: unknown) => void) | null = null;
  onmessage: ((event: { readonly data: unknown }) => void) | null = null;
  onerror: ((event?: unknown) => void) | null = null;
  onclose: ((event?: { readonly code?: number }) => void) | null = null;
  readyState = 0;
  opened = false;
  closed = false;
  closeCalls = 0;

  constructor(identity: string) {
    this.identity = identity;
  }

  send(): void {}

  close(): void {
    this.closeCalls += 1;
    this.closed = true;
    this.readyState = 3;
  }

  open(): void {
    if (this.closed) throw new Error("benchmark attempted to open a cleaned-up socket");
    this.readyState = 1;
    this.opened = true;
    this.onopen?.();
  }
}

interface RunProof {
  readonly sampleMs: number;
  readonly ticketRequests: number;
  readonly socketFactoryCalls: number;
  readonly openedSockets: number;
  readonly cleanupCalls: number;
  readonly duplicateOwnerViolations: number;
  readonly activeOwnerCount: number;
  readonly staleOpenCalls: number;
  readonly assertions: Readonly<Record<string, boolean>>;
}

async function within<T>(promise: Promise<T>, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`PTY benchmark timed out while waiting for ${label}`)), TIMEOUT_MS);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

async function flush(): Promise<void> {
  for (let index = 0; index < 96; index += 1) await Promise.resolve();
}

async function expectAborted(operation: Promise<void>, label: string): Promise<void> {
  try {
    await within(operation, label);
    throw new Error(`${label} unexpectedly resolved`);
  } catch (error) {
    if (
      typeof error !== "object" ||
      error === null ||
      !("code" in error) ||
      error.code !== "aborted"
    ) {
      throw error;
    }
  }
}

async function runAction(action: Action): Promise<RunProof> {
  const controller = new AbortController();
  const sockets: BenchmarkSocket[] = [];
  let transport!: PtyTransport;
  let replacementPromise: Promise<void> | undefined;
  let actionTaken = false;
  let ticketRequests = 0;
  let socketFactoryCalls = 0;
  let openedSockets = 0;

  const onEvent = (event: PtyTransportEvent): void => {
    if (actionTaken || event.type !== "state" || event.state.status !== "connecting") return;
    actionTaken = true;
    if (action === "abort") controller.abort();
    if (action === "close") transport.close();
    if (action === "detach") transport.detach();
    if (action === "replace") replacementPromise = transport.connect(REPLACEMENT_INPUT);
  };
  const createWebSocket = (upgrade: PtyWebSocketUpgradeRequest): BenchmarkSocket => {
    socketFactoryCalls += 1;
    const socket = new BenchmarkSocket(upgrade.query.resume);
    sockets.push(socket);
    return socket;
  };

  transport = createPtyTransport({
    validateAttachment: () => true,
    ticketProvider: async () => {
      ticketRequests += 1;
      return `benchmark-ticket-${ticketRequests}`;
    },
    createWebSocket,
    onEvent,
  });

  const started = performance.now();
  const cancelled = transport.connect(INPUT, controller.signal);
  await expectAborted(cancelled, `${action} cancelled operation`);
  const sampleMs = roundSample(performance.now() - started);
  if (!actionTaken) throw new Error(`${action} did not run a connecting observer action`);
  await flush();

  const replacementSocket = sockets.find((socket) => socket.identity === REPLACEMENT_INPUT.sessionId);
  if (action === "replace") {
    if (!replacementPromise || !replacementSocket) {
      throw new Error("replacement action did not allocate an identity-owned socket");
    }
    replacementSocket.open();
    openedSockets += 1;
    await within(replacementPromise, "replacement onopen");
  }
  const replacementAttached = action !== "replace" || transport.state.status === "attached";
  const staleSockets = sockets.filter((socket) => socket.identity === INPUT.sessionId);
  const staleOpenCalls = staleSockets.filter((socket) => socket.opened).length;
  const activeOwnerCount = sockets.filter((socket) => socket.opened && !socket.closed).length;
  const duplicateOwnerViolations = activeOwnerCount > 1 ? 1 : 0;
  transport.close();
  await flush();
  const cleanupCalls = sockets.reduce((total, socket) => total + socket.closeCalls, 0);
  const assertions = {
    connectingGuard: staleSockets.length === 0,
    staleSocketNeverOpened: staleOpenCalls === 0,
    expectedFactoryCount: socketFactoryCalls === (action === "replace" ? 1 : 0),
    expectedTicketCount: ticketRequests === (action === "replace" ? 2 : 1),
    replacementOpenedExactlyOnce: action !== "replace" || (replacementSocket?.opened === true && openedSockets === 1),
    replacementAttached,
    noDuplicateOwners: duplicateOwnerViolations === 0,
    cleanupRecorded: action !== "replace" || cleanupCalls === 1,
  };
  if (Object.values(assertions).some((value) => !value)) {
    throw new Error(`${action} proof assertion failed: ${JSON.stringify(assertions)}`);
  }

  return {
    sampleMs,
    ticketRequests,
    socketFactoryCalls,
    openedSockets,
    cleanupCalls,
    duplicateOwnerViolations,
    activeOwnerCount,
    staleOpenCalls,
    assertions,
  };
}

async function measure(action: Action): Promise<{
  readonly samples: readonly number[];
  readonly runs: readonly RunProof[];
}> {
  for (let index = 0; index < WARMUPS; index += 1) await runAction(action);
  const samples: number[] = [];
  const runs: RunProof[] = [];
  for (let index = 0; index < REPETITIONS; index += 1) {
    const proof = await runAction(action);
    samples.push(proof.sampleMs);
    runs.push(proof);
  }
  return { samples, runs };
}

const results: Array<Record<string, unknown>> = [];
for (const action of ACTIONS) {
  const measured = await measure(action);
  const total = (key: keyof RunProof): number =>
    measured.runs.reduce((sum, run) => sum + (typeof run[key] === "number" ? run[key] as number : 0), 0);
  results.push({
    stage: action,
    samples: measured.samples,
    distribution: distribution(measured.samples),
    runs: measured.runs,
    totals: {
      ticketRequests: total("ticketRequests"),
      socketFactoryCalls: total("socketFactoryCalls"),
      openedSockets: total("openedSockets"),
      cleanupCalls: total("cleanupCalls"),
      duplicateOwnerViolations: total("duplicateOwnerViolations"),
    },
  });
}

const artifact = {
  schema: "hermternal.pty-connecting-ownership-benchmark.v2",
  operation: "connecting observer ownership decision before socket factory",
  metric: {
    name: "ownership_decision_settle_wall_time",
    unit: "ms",
    clock: "performance.now",
    start: "connecting state observer action",
    end: "cancelled operation rejects",
  },
  method: "R-7 inclusive linear interpolation over rounded raw samples",
  sourcePath: "apps/web/src/lib/terminal/pty-connecting-ownership.bench.ts",
  command: "bun src/lib/terminal/pty-connecting-ownership.bench.ts",
  stageOrder: [...ACTIONS],
  sequential: true,
  concurrentStages: false,
  repetitions: REPETITIONS,
  warmups: WARMUPS,
  networkPolicy: "synthetic-only",
  exclusions: ["network", "Hermes", "credentials", "PTY bytes", "rendering", "latency threshold"],
  provenance: capturePtyBenchmarkProvenance(
    "apps/web/src/lib/terminal/pty-connecting-ownership.bench.ts",
    "bun src/lib/terminal/pty-connecting-ownership.bench.ts",
  ),
  results,
  threshold: null,
};

console.log(JSON.stringify(artifact, null, 2));
