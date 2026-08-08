import {
  capturePtyBenchmarkProvenance,
  distribution,
  roundSample,
} from "./pty-benchmark-provenance";
import {
  createPtyTransport,
  type PtyConnectionInput,
  type PtyTransport,
  type PtyWebSocket,
} from "./pty-transport";

const REPETITIONS = 30;
const WARMUPS = 5;
const TIMEOUT_MS = 1_000;
const INPUT: PtyConnectionInput = {
  sessionId: "benchmark-session",
  attach: "benchmark-attach",
  processIdentity: "benchmark-process",
};
const STAGES = ["validator", "ticket", "factory"] as const;
type Stage = (typeof STAGES)[number];

class BenchmarkSocket implements PtyWebSocket {
  onopen: ((event?: unknown) => void) | null = null;
  onmessage: ((event: { readonly data: unknown }) => void) | null = null;
  onerror: ((event?: unknown) => void) | null = null;
  onclose: ((event?: { readonly code?: number }) => void) | null = null;
  readyState = 0;
  opened = false;
  closed = false;
  closeCalls = 0;

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
  readonly staleCleanupCalls: number;
  readonly staleOpenCalls: number;
  readonly assertions: Readonly<Record<string, boolean>>;
}

function timeoutError(label: string): Error {
  return new Error(`PTY benchmark timed out while waiting for ${label}`);
}

async function within<T>(promise: Promise<T>, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(timeoutError(label)), TIMEOUT_MS);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

async function flush(): Promise<void> {
  for (let index = 0; index < 96; index += 1) await Promise.resolve();
}

async function expectCode(operation: Promise<void>, code: string, label: string): Promise<void> {
  try {
    await within(operation, label);
    throw new Error(`${label} unexpectedly resolved`);
  } catch (error) {
    if (
      typeof error !== "object" ||
      error === null ||
      !("code" in error) ||
      error.code !== code
    ) {
      throw error;
    }
  }
}

async function runStage(stage: Stage): Promise<RunProof> {
  let resolveValidation!: (value: boolean) => void;
  let resolveTicket!: (value: string) => void;
  let resolveFactory!: (value: BenchmarkSocket) => void;
  let ticketRequests = 0;
  let socketFactoryCalls = 0;
  let openedSockets = 0;
  const sockets: BenchmarkSocket[] = [];
  let staleSocket: BenchmarkSocket | undefined;
  let transport!: PtyTransport;

  const validateAttachment = (): Promise<boolean> | true => {
    if (stage !== "validator") return true;
    return new Promise<boolean>((resolve) => {
      resolveValidation = resolve;
    });
  };
  const ticketProvider = (): Promise<string> => {
    ticketRequests += 1;
    if (stage === "ticket" && ticketRequests === 1) {
      return new Promise<string>((resolve) => {
        resolveTicket = resolve;
      });
    }
    return Promise.resolve(`benchmark-ticket-${ticketRequests}`);
  };
  const createWebSocket = (): Promise<BenchmarkSocket> | BenchmarkSocket => {
    socketFactoryCalls += 1;
    const socket = new BenchmarkSocket();
    sockets.push(socket);
    if (stage === "factory" && socketFactoryCalls === 1) {
      staleSocket = socket;
      return new Promise<BenchmarkSocket>((resolve) => {
        resolveFactory = resolve;
      });
    }
    return socket;
  };

  transport = createPtyTransport({
    now: () => 1,
    validateAttachment,
    ticketProvider,
    createWebSocket,
  });

  const started = performance.now();
  const cancelledAttempt = transport.connect(INPUT);
  await flush();
  if (stage === "validator" && !resolveValidation) throw new Error("validator stage did not start");
  if (stage === "ticket" && ticketRequests !== 1) throw new Error("ticket stage did not start");
  if (stage === "factory" && socketFactoryCalls !== 1) throw new Error("factory stage did not start");

  transport.detach();
  await expectCode(cancelledAttempt, "aborted", `${stage} cancelled attempt`);
  await expectCode(transport.reconnect(), "aborted", `${stage} quarantined reconnect`);

  if (stage === "validator") resolveValidation(true);
  if (stage === "ticket") resolveTicket(`benchmark-ticket-${ticketRequests}`);
  if (stage === "factory") {
    if (!staleSocket || !resolveFactory) throw new Error("factory stage lost stale socket ownership");
    resolveFactory(staleSocket);
  }
  await flush();
  const sampleMs = roundSample(performance.now() - started);

  // Recovery is outside the measured quarantine-settlement interval. It proves
  // that late cleanup released exactly one owner and that the replacement's
  // real onopen callback, not a synthetic counter, reached attached state.
  // Pre-open detach cannot seed a retention anchor, so recover with an explicit
  // same-identity connect rather than claiming a reattach authorization.
  const recovery = transport.connect(INPUT);
  await flush();
  const replacement = sockets.find((socket) => socket !== staleSocket && !socket.closed && !socket.opened);
  if (!replacement) throw new Error(`${stage} recovery did not allocate an owned replacement socket`);
  replacement.open();
  openedSockets += 1;
  await within(recovery, `${stage} recovery open`);
  const recoveryAttached = transport.state.status === "attached";
  const activeOwnerCountBeforeCleanup = sockets.filter((socket) => socket.opened && !socket.closed).length;
  transport.close();
  await flush();

  const cleanupCalls = sockets.reduce((total, socket) => total + socket.closeCalls, 0);
  const staleCleanupCalls = staleSocket?.closeCalls ?? 0;
  const staleOpenCalls = staleSocket?.opened ? 1 : 0;
  const duplicateOwnerViolations = activeOwnerCountBeforeCleanup > 1 ? 1 : 0;
  const assertions = {
    quarantineTicketFence: ticketRequests === (stage === "validator" ? 0 : 1),
    quarantineFactoryFence: socketFactoryCalls === (stage === "factory" ? 1 : 0),
    staleSocketClosedOnce: stage !== "factory" || staleCleanupCalls === 1,
    staleSocketNeverOpened: staleOpenCalls === 0,
    replacementOpenedExactlyOnce: replacement.opened && openedSockets === 1,
    replacementReachedAttached: recoveryAttached,
    noDuplicateOwners: duplicateOwnerViolations === 0,
    cleanupRecorded: cleanupCalls >= 1,
  };
  if (Object.values(assertions).some((value) => !value)) {
    throw new Error(`${stage} proof assertion failed: ${JSON.stringify(assertions)}`);
  }

  return {
    sampleMs,
    ticketRequests,
    socketFactoryCalls,
    openedSockets,
    cleanupCalls,
    duplicateOwnerViolations,
    activeOwnerCount: activeOwnerCountBeforeCleanup,
    staleCleanupCalls,
    staleOpenCalls,
    assertions,
  };
}

async function measure(stage: Stage): Promise<{
  readonly samples: readonly number[];
  readonly runs: readonly RunProof[];
}> {
  for (let index = 0; index < WARMUPS; index += 1) await runStage(stage);
  const samples: number[] = [];
  const runs: RunProof[] = [];
  for (let index = 0; index < REPETITIONS; index += 1) {
    const proof = await runStage(stage);
    samples.push(proof.sampleMs);
    runs.push(proof);
  }
  return { samples, runs };
}

const results: Array<Record<string, unknown>> = [];
for (const stage of STAGES) {
  const measured = await measure(stage);
  const total = (key: keyof RunProof): number =>
    measured.runs.reduce((sum, run) => sum + (typeof run[key] === "number" ? run[key] as number : 0), 0);
  results.push({
    stage,
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
  schema: "hermternal.pty-reconnect-supersession-benchmark.v2",
  operation: "same-identity reconnect after ordinary detach quarantine",
  metric: {
    name: "quarantine_settle_wall_time",
    unit: "ms",
    clock: "performance.now",
    start: "connect attempt starts",
    end: "ignored adapter settles after detach and blocked reconnect",
  },
  method: "R-7 inclusive linear interpolation over rounded raw samples",
  sourcePath: "apps/web/src/lib/terminal/pty-reconnect-supersession.bench.ts",
  command: "bun src/lib/terminal/pty-reconnect-supersession.bench.ts",
  stageOrder: [...STAGES],
  sequential: true,
  concurrentStages: false,
  repetitions: REPETITIONS,
  warmups: WARMUPS,
  networkPolicy: "synthetic-only",
  exclusions: ["network", "Hermes", "credentials", "PTY bytes", "rendering", "latency threshold"],
  provenance: capturePtyBenchmarkProvenance(
    "apps/web/src/lib/terminal/pty-reconnect-supersession.bench.ts",
    "bun src/lib/terminal/pty-reconnect-supersession.bench.ts",
  ),
  results,
  threshold: null,
};

console.log(JSON.stringify(artifact, null, 2));
