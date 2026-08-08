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

interface BenchmarkOwnerIdentity {
  readonly sessionId: string;
  readonly attach?: string;
  readonly processIdentity?: string;
}

interface SocketClosure {
  readonly socketId: string;
  readonly ownerIdentity: BenchmarkOwnerIdentity;
  readonly closeCalls: number;
  readonly opened: boolean;
}

function ownerIdentityFor(input: PtyConnectionInput): BenchmarkOwnerIdentity {
  // Keep the ledger tied to the PTY identity; detachedAtMs is local evidence.
  return Object.freeze({
    sessionId: input.sessionId,
    ...(input.attach ? { attach: input.attach } : {}),
    ...(input.processIdentity ? { processIdentity: input.processIdentity } : {}),
  });
}

function sameOwnerIdentity(
  left: BenchmarkOwnerIdentity,
  right: BenchmarkOwnerIdentity,
): boolean {
  return (
    left.sessionId === right.sessionId &&
    left.attach === right.attach &&
    left.processIdentity === right.processIdentity
  );
}

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
  readonly socketId: string;
  readonly ownerIdentity: BenchmarkOwnerIdentity;
  onopen: ((event?: unknown) => void) | null = null;
  onmessage: ((event: { readonly data: unknown }) => void) | null = null;
  onerror: ((event?: unknown) => void) | null = null;
  onclose: ((event?: { readonly code?: number }) => void) | null = null;
  readyState = 0;
  opened = false;
  closed = false;
  closeCalls = 0;

  constructor(socketId: string, ownerIdentity: BenchmarkOwnerIdentity) {
    this.socketId = socketId;
    this.ownerIdentity = ownerIdentity;
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

function snapshotSocket(socket: BenchmarkSocket): SocketClosure {
  return {
    socketId: socket.socketId,
    ownerIdentity: socket.ownerIdentity,
    closeCalls: socket.closeCalls,
    opened: socket.opened,
  };
}

interface RunProof {
  readonly sampleMs: number;
  readonly validatorCalls: number;
  readonly ticketRequests: number;
  readonly socketFactoryCalls: number;
  readonly openedSockets: number;
  readonly cleanupCalls: number;
  readonly duplicateOwnerViolations: number;
  readonly activeOwnerCount: number;
  readonly activeSocketIds: readonly string[];
  readonly expectedOwnerIdentity: BenchmarkOwnerIdentity | null;
  readonly activeOwnerIdentities: readonly BenchmarkOwnerIdentity[];
  readonly staleSocketIds: readonly string[];
  readonly staleSocketIdentities: readonly BenchmarkOwnerIdentity[];
  readonly staleSocketId: string | null;
  readonly staleSocketIdentity: BenchmarkOwnerIdentity | null;
  readonly staleSocketCloseCalls: number;
  readonly replacementSocketId: string | null;
  readonly replacementSocketIdentity: BenchmarkOwnerIdentity | null;
  readonly replacementSocketCloseCalls: number;
  readonly socketClosures: readonly SocketClosure[];
  readonly callbackProofApplicable: boolean;
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
  let validatorCalls = 0;
  let ticketRequests = 0;
  let socketFactoryCalls = 0;
  let openedSockets = 0;
  let nextSocketId = 0;
  const inputOwnerIdentity = ownerIdentityFor(INPUT);
  const replacementOwnerIdentity = ownerIdentityFor(REPLACEMENT_INPUT);

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
    const ownerIdentity =
      upgrade.query.resume === inputOwnerIdentity.sessionId
        ? inputOwnerIdentity
        : upgrade.query.resume === replacementOwnerIdentity.sessionId
          ? replacementOwnerIdentity
          : undefined;
    if (!ownerIdentity || upgrade.query.attach !== ownerIdentity.attach) {
      throw new Error("benchmark factory received an unexpected PTY owner");
    }
    // The local sequence distinguishes physical sockets without weakening the
    // structured PTY owner identity used by the ownership assertions.
    const socket = new BenchmarkSocket(`socket-${++nextSocketId}`, ownerIdentity);
    sockets.push(socket);
    return socket;
  };

  transport = createPtyTransport({
    validateAttachment: () => {
      validatorCalls += 1;
      return true;
    },
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

  const replacementSocket = sockets.find((socket) =>
    sameOwnerIdentity(socket.ownerIdentity, replacementOwnerIdentity),
  );
  if (action === "replace") {
    if (!replacementPromise || !replacementSocket) {
      throw new Error("replacement action did not allocate an identity-owned socket");
    }
    replacementSocket.open();
    openedSockets += 1;
    await within(replacementPromise, "replacement onopen");
  }
  const replacementAttached = action !== "replace" || transport.state.status === "attached";
  const staleSockets = sockets.filter((socket) =>
    sameOwnerIdentity(socket.ownerIdentity, inputOwnerIdentity),
  );
  const staleOpenCalls = staleSockets.filter((socket) => socket.opened).length;
  const expectedOwnerIdentity = action === "replace" ? replacementOwnerIdentity : null;
  const activeSockets = sockets.filter((socket) => socket.opened && !socket.closed);
  const activeSocketIds = activeSockets.map((socket) => socket.socketId);
  const activeOwnerIdentities = activeSockets.map((socket) => socket.ownerIdentity);
  const activeOwnerCount = activeOwnerIdentities.length;
  const duplicateOwnerViolations = activeOwnerCount > 1 ? 1 : 0;
  // The connecting guard intentionally allocates no socket for abort, Close, or
  // detach. Their callback proof is therefore inapplicable, while replacement
  // must bind and replay every callback on its allocated socket.
  const callbackProofApplicable = action === "replace";
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
  const staleSocketIds = staleSockets.map((socket) => socket.socketId);
  const staleSocketIdentities = staleSockets.map((socket) => socket.ownerIdentity);
  const staleSocketId = staleSockets[0]?.socketId ?? null;
  const staleSocketIdentity = staleSockets[0]?.ownerIdentity ?? null;
  const staleSocketCloseCalls = staleSockets.reduce((total, socket) => total + socket.closeCalls, 0);
  const replacementSocketId = replacementSocket?.socketId ?? null;
  const replacementSocketIdentity = replacementSocket?.ownerIdentity ?? null;
  const replacementSocketCloseCalls = replacementSocket?.closeCalls ?? 0;
  // Record the exact post-close state for every allocated physical socket.
  const socketClosures = sockets.map(snapshotSocket);
  const assertions = {
    connectingGuard: staleSockets.length === 0,
    staleSocketNeverOpened: staleOpenCalls === 0,
    expectedValidatorCount: validatorCalls === (action === "replace" ? 2 : 1),
    expectedFactoryCount: socketFactoryCalls === (action === "replace" ? 1 : 0),
    expectedTicketCount: ticketRequests === (action === "replace" ? 2 : 1),
    replacementOpenedExactlyOnce:
      action !== "replace" || (replacementSocket?.opened === true && openedSockets === 1),
    replacementAttached,
    expectedOwnerIsOnlyActiveOwner:
      activeOwnerIdentities.length === (expectedOwnerIdentity === null ? 0 : 1) &&
      (expectedOwnerIdentity === null ||
        sameOwnerIdentity(activeOwnerIdentities[0]!, expectedOwnerIdentity)),
    activeSocketIsReplacement:
      action !== "replace" ||
      (activeSocketIds.length === 1 && activeSocketIds[0] === replacementSocketId),
    noDuplicateOwners: duplicateOwnerViolations === 0,
    staleSocketIdentityFence: staleSocketIdentities.length === 0 && staleSocketCloseCalls === 0,
    staleSocketIdFence: staleSocketIds.length === 0 && staleSocketId === null,
    replacementIdentityMatchesExpected:
      action !== "replace" ||
      (replacementSocketIdentity !== null &&
        sameOwnerIdentity(replacementSocketIdentity, expectedOwnerIdentity!)),
    replacementSocketIdUnique:
      action !== "replace" || replacementSocketId !== null && replacementSocketId !== staleSocketId,
    replacementClosedExactlyOnce: action !== "replace" || replacementSocketCloseCalls === 1,
    exactSocketCleanup:
      action !== "replace" ||
      (socketClosures.length === 1 &&
        socketClosures.every((socket) => socket.closeCalls === 1 && socket.opened)),
    allCallbacksNullAfterClose,
    replacementCallbacksBound:
      !callbackProofApplicable ||
      (callbackSnapshots.length === 1 &&
        callbackSnapshots.every(
          ({ callbacks }) =>
            callbacks.onopen !== null &&
            callbacks.onmessage !== null &&
            callbacks.onerror !== null &&
            callbacks.onclose !== null,
        )),
    staleCallbacksExercised:
      !callbackProofApplicable ||
      (staleOnopenDispatches === 1 &&
        staleOnmessageDispatches === 1 &&
        staleOnerrorDispatches === 1 &&
        staleOncloseDispatches === 1),
    staleOnopenIgnored:
      !callbackProofApplicable || staleOnopenDispatches === 1 && postCloseStateEvents === 0,
    staleOnmessageIgnored:
      !callbackProofApplicable || staleOnmessageDispatches === 1 && postCloseBytesEvents === 0,
    staleOnerrorIgnored:
      !callbackProofApplicable || staleOnerrorDispatches === 1 && postCloseStateEvents === 0,
    staleOncloseIgnored:
      !callbackProofApplicable || staleOncloseDispatches === 1 && postCloseStateEvents === 0,
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
    validatorCalls,
    ticketRequests,
    socketFactoryCalls,
    openedSockets,
    cleanupCalls,
    duplicateOwnerViolations,
    activeOwnerCount,
    activeSocketIds,
    expectedOwnerIdentity,
    activeOwnerIdentities,
    staleSocketIds,
    staleSocketIdentities,
    staleSocketId,
    staleSocketIdentity,
    staleSocketCloseCalls,
    replacementSocketId,
    replacementSocketIdentity,
    replacementSocketCloseCalls,
    socketClosures,
    callbackProofApplicable: callbackProofApplicable,
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
      validatorCalls: total("validatorCalls"),
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
