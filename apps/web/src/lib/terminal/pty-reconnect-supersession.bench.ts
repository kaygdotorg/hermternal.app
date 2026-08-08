import {
  createPtyTransport,
  type PtyConnectionInput,
  type PtyWebSocket,
} from "./pty-transport";

const REPETITIONS = 30;
const WARMUPS = 5;
const INPUT: PtyConnectionInput = {
  sessionId: "benchmark-session",
  attach: "benchmark-attach",
  processIdentity: "benchmark-process",
  detachedAtMs: 1,
};

class BenchmarkSocket implements PtyWebSocket {
  onopen: ((event?: unknown) => void) | null = null;
  onmessage: ((event: { readonly data: unknown }) => void) | null = null;
  onerror: ((event?: unknown) => void) | null = null;
  onclose: ((event?: { readonly code?: number }) => void) | null = null;
  readyState = 0;
  closes = 0;

  send(): void {}

  close(): void {
    this.closes += 1;
    this.readyState = 3;
  }
}

type Stage = "validator" | "ticket" | "factory";

interface Proof {
  readonly ticketRequests: number;
  readonly validatorCalls: number;
  readonly socketFactoryCalls: number;
  readonly openedSockets: number;
  readonly cleanupCalls: number;
  readonly duplicateOwnerViolations: number;
}

async function flush(): Promise<void> {
  for (let index = 0; index < 64; index += 1) await Promise.resolve();
}

function percentile(sorted: readonly number[], quantile: number): number {
  const position = (sorted.length - 1) * quantile;
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  if (lower === upper) return sorted[lower]!;
  const fraction = position - lower;
  return sorted[lower]! + (sorted[upper]! - sorted[lower]!) * fraction;
}

async function expectAborted(operation: Promise<void>): Promise<void> {
  try {
    await operation;
    throw new Error("cancelled operation unexpectedly succeeded");
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

async function runBurst(stage: Stage): Promise<Proof> {
  let resolveValidator!: (value: boolean) => void;
  let resolveTicket!: (value: string) => void;
  let resolveSocket!: (value: BenchmarkSocket) => void;
  let ticketRequests = 0;
  let validatorCalls = 0;
  let socketFactoryCalls = 0;
  let openedSockets = 0;
  let cleanupCalls = 0;
  const transport = createPtyTransport({
    now: () => 1,
    validateAttachment: () => {
      validatorCalls += 1;
      return stage === "validator"
        ? new Promise<boolean>((resolve) => {
            resolveValidator = resolve;
          })
        : true;
    },
    ticketProvider: async () => {
      ticketRequests += 1;
      return stage === "ticket"
        ? new Promise<string>((resolve) => {
            resolveTicket = resolve;
          })
        : "benchmark-ticket";
    },
    createWebSocket: () => {
      socketFactoryCalls += 1;
      return stage === "factory"
        ? new Promise<BenchmarkSocket>((resolve) => {
            resolveSocket = resolve;
          })
        : new BenchmarkSocket();
    },
  });

  const cancelled = transport.connect(INPUT);
  await flush();
  transport.detach();
  await expectAborted(cancelled);
  await expectAborted(transport.reconnect());

  if (stage === "validator") resolveValidator(true);
  if (stage === "ticket") resolveTicket("benchmark-ticket");
  if (stage === "factory") {
    const staleSocket = new BenchmarkSocket();
    resolveSocket(staleSocket);
    await flush();
    cleanupCalls = staleSocket.closes;
  }
  await flush();

  return {
    ticketRequests,
    validatorCalls,
    socketFactoryCalls,
    openedSockets,
    cleanupCalls,
    duplicateOwnerViolations: Math.max(0, ticketRequests - 1, validatorCalls - 1, socketFactoryCalls - 1),
  };
}

async function measure(stage: Stage): Promise<{ readonly samples: number[]; readonly proofs: Proof[] }> {
  for (let index = 0; index < WARMUPS; index += 1) await runBurst(stage);
  const samples: number[] = [];
  const proofs: Proof[] = [];
  for (let index = 0; index < REPETITIONS; index += 1) {
    const started = performance.now();
    proofs.push(await runBurst(stage));
    samples.push(performance.now() - started);
  }
  return { samples, proofs };
}

const results = await Promise.all((["validator", "ticket", "factory"] as const).map(async (stage) => {
  const { samples, proofs } = await measure(stage);
  const sorted = samples.toSorted((left, right) => left - right);
  const total = (key: keyof Proof): number => proofs.reduce((sum, proof) => sum + proof[key], 0);
  return {
    stage,
    distribution: {
      min: Number(sorted[0]!.toFixed(6)),
      median: Number(percentile(sorted, 0.5).toFixed(6)),
      p95: Number(percentile(sorted, 0.95).toFixed(6)),
    },
    totals: {
      ticketRequests: total("ticketRequests"),
      validatorCalls: total("validatorCalls"),
      socketFactoryCalls: total("socketFactoryCalls"),
      openedSockets: total("openedSockets"),
      cleanupCalls: total("cleanupCalls"),
      duplicateOwnerViolations: total("duplicateOwnerViolations"),
    },
  };
}));

console.log(JSON.stringify({
  schema: "hermternal.pty-reconnect-supersession-benchmark.v1",
  operation: "same-identity reconnect after ignored cancellation",
  metric: { name: "reconnect_burst_settle_wall_time", unit: "ms", clock: "performance.now" },
  method: "R-7 inclusive linear interpolation",
  environment: { runtime: `Bun ${process.versions.bun ?? "unknown"}`, platform: process.platform, mode: "test" },
  repetitions: REPETITIONS,
  warmups: WARMUPS,
  exclusions: ["network", "Hermes", "credentials", "PTY bytes", "rendering"],
  results,
  threshold: null,
}, null, 2));
