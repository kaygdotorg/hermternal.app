import {
  createPtyTransport,
  type PtyConnectionInput,
  type PtyTransportEvent,
  type PtyWebSocket,
  type PtyWebSocketUpgradeRequest,
} from "./pty-transport";

const REPETITIONS = 30;
const WARMUPS = 5;
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

type Cancellation = "abort" | "close" | "detach" | "replace";

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

  open(): void {
    this.readyState = 1;
    this.onopen?.();
  }
}

interface Proof {
  readonly factoryCalls: number;
  readonly staleFactoryCalls: number;
  readonly allocatedSockets: number;
  readonly openedSockets: number;
  readonly staleStateEvents: number;
  readonly cleanupCalls: number;
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

async function runOwnershipDecision(cancellation: Cancellation): Promise<{
  readonly elapsedMs: number;
  readonly proof: Proof;
}> {
  const controller = new AbortController();
  const sockets: BenchmarkSocket[] = [];
  let transport!: ReturnType<typeof createPtyTransport>;
  let replacement: Promise<void> | undefined;
  let cancellationStartedAt = Number.NaN;
  let factoryCalls = 0;
  let staleFactoryCalls = 0;
  let openedSockets = 0;
  let staleStateEvents = 0;
  let cancelled = false;

  const onEvent = (event: PtyTransportEvent): void => {
    if (event.type !== "state") return;
    // Only replacement makes generation one stale. Close, Detach, and caller
    // abort legitimately settle their still-current generation as detached.
    if (
      cancellation === "replace" &&
      Number.isFinite(cancellationStartedAt) &&
      event.state.generation === 1
    ) {
      staleStateEvents += 1;
    }
    if (cancelled || event.state.status !== "connecting") return;
    cancelled = true;
    cancellationStartedAt = performance.now();
    if (cancellation === "abort") controller.abort();
    if (cancellation === "close") transport.close();
    if (cancellation === "detach") transport.detach();
    if (cancellation === "replace") {
      replacement = transport.connect(REPLACEMENT_INPUT);
    }
  };

  const createWebSocket = (upgrade: PtyWebSocketUpgradeRequest): BenchmarkSocket => {
    factoryCalls += 1;
    if (upgrade.query.attach === INPUT.attach) staleFactoryCalls += 1;
    const socket = new BenchmarkSocket();
    sockets.push(socket);
    return socket;
  };

  transport = createPtyTransport({
    validateAttachment: () => true,
    ticketProvider: async () => "benchmark-ticket",
    createWebSocket,
    onEvent,
  });

  const cancelledAttempt = transport.connect(INPUT, controller.signal);
  await expectAborted(cancelledAttempt);
  const elapsedMs = performance.now() - cancellationStartedAt;

  if (replacement) {
    await flush();
    const replacementSocket = sockets[0];
    if (!replacementSocket) throw new Error("replacement did not allocate a socket");
    replacementSocket.open();
    openedSockets += 1;
    await replacement;
  }

  return {
    elapsedMs,
    proof: {
      factoryCalls,
      staleFactoryCalls,
      allocatedSockets: sockets.length,
      openedSockets,
      staleStateEvents,
      cleanupCalls: sockets.reduce((total, socket) => total + socket.closes, 0),
    },
  };
}

async function measure(cancellation: Cancellation): Promise<{
  readonly samples: number[];
  readonly proofs: Proof[];
}> {
  for (let index = 0; index < WARMUPS; index += 1) {
    await runOwnershipDecision(cancellation);
  }
  const samples: number[] = [];
  const proofs: Proof[] = [];
  for (let index = 0; index < REPETITIONS; index += 1) {
    const result = await runOwnershipDecision(cancellation);
    samples.push(result.elapsedMs);
    proofs.push(result.proof);
  }
  return { samples, proofs };
}

const results = await Promise.all(
  (["abort", "close", "detach", "replace"] as const).map(async (cancellation) => {
    const { samples, proofs } = await measure(cancellation);
    const sorted = samples.toSorted((left, right) => left - right);
    const total = (key: keyof Proof): number =>
      proofs.reduce((sum, proof) => sum + proof[key], 0);
    return {
      cancellation,
      distribution: {
        min: Number(sorted[0]!.toFixed(6)),
        median: Number(percentile(sorted, 0.5).toFixed(6)),
        p95: Number(percentile(sorted, 0.95).toFixed(6)),
      },
      totals: {
        factoryCalls: total("factoryCalls"),
        staleFactoryCalls: total("staleFactoryCalls"),
        allocatedSockets: total("allocatedSockets"),
        openedSockets: total("openedSockets"),
        staleStateEvents: total("staleStateEvents"),
        cleanupCalls: total("cleanupCalls"),
      },
    };
  }),
);

console.log(
  JSON.stringify(
    {
      schema: "hermternal.pty-connecting-ownership-benchmark.v1",
      operation: "post-connecting ownership decision before socket factory",
      metric: {
        name: "ownership_decision_settle_wall_time",
        unit: "ms",
        clock: "performance.now",
        start: "reentrant connecting observer cancellation",
        end: "cancelled operation rejects",
      },
      method: "R-7 inclusive linear interpolation",
      provenance: {
        // The artifact is committed after this source revision. This avoids a
        // circular self-hash while retaining an immutable reproducer.
        sourceRevision: process.env.GIT_SOURCE_REVISION ?? "unrecorded",
        command:
          "GIT_SOURCE_REVISION=<source-sha> bun src/lib/terminal/pty-connecting-ownership.bench.ts",
        exitStatus: 0,
        runtime: `Bun ${process.versions.bun ?? "unknown"}`,
        platform: process.platform,
        architecture: process.arch,
        mode: "test",
      },
      repetitions: REPETITIONS,
      warmups: WARMUPS,
      exclusions: [
        "ticket minting before connecting",
        "network",
        "Hermes",
        "credentials",
        "PTY bytes",
        "rendering",
      ],
      results,
      threshold: null,
    },
    null,
    2,
  ),
);
