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

interface CallbackSnapshot {
  readonly onopen: ((event?: unknown) => void) | null;
  readonly onmessage: ((event: { readonly data: unknown }) => void) | null;
  readonly onerror: ((event?: unknown) => void) | null;
  readonly onclose: ((event?: { readonly code?: number }) => void) | null;
}

interface StaleCallbackDispatches {
  readonly onopen: number;
  readonly onmessage: number;
  readonly onerror: number;
  readonly onclose: number;
}

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

  captureCallbacks(): CallbackSnapshot {
    return {
      onopen: this.onopen,
      onmessage: this.onmessage,
      onerror: this.onerror,
      onclose: this.onclose,
    };
  }

  dispatchStaleCallbacks(callbacks: CallbackSnapshot): StaleCallbackDispatches {
    let onopen = 0;
    let onmessage = 0;
    let onerror = 0;
    let onclose = 0;
    if (callbacks.onopen) {
      onopen = 1;
      callbacks.onopen();
    }
    if (callbacks.onmessage) {
      onmessage = 1;
      callbacks.onmessage({ data: new Uint8Array([0x42]).buffer });
    }
    if (callbacks.onerror) {
      onerror = 1;
      callbacks.onerror();
    }
    if (callbacks.onclose) {
      onclose = 1;
      callbacks.onclose({ code: 1006 });
    }
    return { onopen, onmessage, onerror, onclose };
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
  readonly expectedOwnerIdentity: string | null;
  readonly activeOwnerIdentities: readonly string[];
  readonly staleSocketIdentities: readonly string[];
  readonly staleSocketCloseCalls: number;
  readonly replacementSocketIdentity: string | null;
  readonly replacementSocketCloseCalls: number;
  readonly socketClosures: readonly Readonly<{ readonly identity: string; readonly closeCalls: number }>[];
  readonly staleOpenCalls: number;
  readonly allCallbacksNullAfterClose: boolean;
  readonly staleOnopenDispatches: number;
  readonly staleOnmessageDispatches: number;
  readonly staleOnerrorDispatches: number;
  readonly staleOncloseDispatches: number;
  readonly postCloseStateEvents: number;
  readonly postCloseBytesEvents: number;
  readonly postCloseNoticeEvents: number;
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
  const events: PtyTransportEvent[] = [];
  let transport!: PtyTransport;
  let replacementPromise: Promise<void> | undefined;
  let actionTaken = false;
  let actionStartedAt: number | undefined;
  let ticketRequests = 0;
  let socketFactoryCalls = 0;
  let openedSockets = 0;

  const onEvent = (event: PtyTransportEvent): void => {
    events.push(event);
    if (actionTaken || event.type !== "state" || event.state.status !== "connecting") return;
    actionTaken = true;
    // Start at the ownership decision itself, not at setup or ticket work. The
    // measured interval ends when the cancelled owner rejects below.
    actionStartedAt = performance.now();
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

  const cancelled = transport.connect(INPUT, controller.signal);
  await expectAborted(cancelled, `${action} cancelled operation`);
  if (!actionTaken || actionStartedAt === undefined) {
    throw new Error(`${action} did not run a connecting observer action`);
  }
  const sampleMs = roundSample(performance.now() - actionStartedAt);
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
  const expectedOwnerIdentity = action === "replace" ? REPLACEMENT_INPUT.sessionId : null;
  const activeOwnerIdentities = sockets
    .filter((socket) => socket.opened && !socket.closed)
    .map((socket) => socket.identity);
  const activeOwnerCount = activeOwnerIdentities.length;
  const duplicateOwnerViolations = activeOwnerCount > 1 ? 1 : 0;
  const callbackSnapshots = sockets.map((socket) => ({
    socket,
    callbacks: socket.captureCallbacks(),
  }));

  // Close must detach every adapter callback before its safeClose call. Replay
  // each callback captured from the live socket after Close to prove stale
  // open, message, error, and close events cannot publish anything.
  transport.close();
  const allCallbacksNullAfterClose = sockets.every(
    (socket) =>
      socket.onopen === null &&
      socket.onmessage === null &&
      socket.onerror === null &&
      socket.onclose === null,
  );
  let staleOnopenDispatches = 0;
  let staleOnmessageDispatches = 0;
  let staleOnerrorDispatches = 0;
  let staleOncloseDispatches = 0;
  const postCloseEventStart = events.length;
  for (const { socket, callbacks } of callbackSnapshots) {
    const dispatches = socket.dispatchStaleCallbacks(callbacks);
    staleOnopenDispatches += dispatches.onopen;
    staleOnmessageDispatches += dispatches.onmessage;
    staleOnerrorDispatches += dispatches.onerror;
    staleOncloseDispatches += dispatches.onclose;
  }
  await flush();
  const postCloseEvents = events.slice(postCloseEventStart);
  const postCloseStateEvents = postCloseEvents.filter((event) => event.type === "state").length;
  const postCloseBytesEvents = postCloseEvents.filter((event) => event.type === "bytes").length;
  const postCloseNoticeEvents = postCloseEvents.filter((event) => event.type === "notice").length;
  const cleanupCalls = sockets.reduce((total, socket) => total + socket.closeCalls, 0);
  const staleSocketIdentities = staleSockets.map((socket) => socket.identity);
  const staleSocketCloseCalls = staleSockets.reduce((total, socket) => total + socket.closeCalls, 0);
  const replacementSocketIdentity = replacementSocket?.identity ?? null;
  const replacementSocketCloseCalls = replacementSocket?.closeCalls ?? 0;
  const socketClosures = sockets.map((socket) => ({
    identity: socket.identity,
    closeCalls: socket.closeCalls,
  }));
  const assertions = {
    connectingGuard: staleSockets.length === 0,
    staleSocketNeverOpened: staleOpenCalls === 0,
    expectedFactoryCount: socketFactoryCalls === (action === "replace" ? 1 : 0),
    expectedTicketCount: ticketRequests === (action === "replace" ? 2 : 1),
    replacementOpenedExactlyOnce: action !== "replace" || (replacementSocket?.opened === true && openedSockets === 1),
    replacementAttached,
    expectedOwnerIsOnlyActiveOwner:
      activeOwnerIdentities.length === (expectedOwnerIdentity === null ? 0 : 1) &&
      (expectedOwnerIdentity === null || activeOwnerIdentities[0] === expectedOwnerIdentity),
    noDuplicateOwners: duplicateOwnerViolations === 0,
    staleSocketIdentityFence: staleSocketIdentities.length === 0 && staleSocketCloseCalls === 0,
    replacementClosedExactlyOnce: action !== "replace" || replacementSocketCloseCalls === 1,
    exactSocketCleanup: action !== "replace" || socketClosures.length === 1 && socketClosures.every((socket) => socket.closeCalls === 1),
    allCallbacksNullAfterClose,
    staleCallbacksExercised:
      staleOnopenDispatches === activeOwnerCount &&
      staleOnmessageDispatches === activeOwnerCount &&
      staleOnerrorDispatches === activeOwnerCount &&
      staleOncloseDispatches === activeOwnerCount,
    staleOnopenIgnored: staleOnopenDispatches === activeOwnerCount && postCloseStateEvents === 0,
    staleOnmessageIgnored: staleOnmessageDispatches === activeOwnerCount && postCloseBytesEvents === 0,
    staleOnerrorIgnored: staleOnerrorDispatches === activeOwnerCount && postCloseStateEvents === 0,
    staleOncloseIgnored: staleOncloseDispatches === activeOwnerCount && postCloseStateEvents === 0,
    noPostCloseStateEvents: postCloseStateEvents === 0,
    noPostCloseBytesEvents: postCloseBytesEvents === 0,
    noPostCloseNoticeEvents: postCloseNoticeEvents === 0,
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
    expectedOwnerIdentity,
    activeOwnerIdentities,
    staleSocketIdentities,
    staleSocketCloseCalls,
    replacementSocketIdentity,
    replacementSocketCloseCalls,
    socketClosures,
    staleOpenCalls,
    allCallbacksNullAfterClose,
    staleOnopenDispatches,
    staleOnmessageDispatches,
    staleOnerrorDispatches,
    staleOncloseDispatches,
    postCloseStateEvents,
    postCloseBytesEvents,
    postCloseNoticeEvents,
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
    start: "performance.now immediately before connecting observer cancellation or replacement action",
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
