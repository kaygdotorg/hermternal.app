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
  sessionId: "benchmark-session",
  attach: "benchmark-attach",
  processIdentity: "benchmark-process",
};
const STAGES = ["validator", "ticket", "factory"] as const;
type Stage = (typeof STAGES)[number];

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
  readonly validatorCalls: number;
  readonly validatorCallsBeforeRecovery: number;
  readonly ticketRequests: number;
  readonly ticketRequestsBeforeRecovery: number;
  readonly socketFactoryCalls: number;
  readonly socketFactoryCallsBeforeRecovery: number;
  readonly openedSockets: number;
  readonly cleanupCalls: number;
  readonly duplicateOwnerViolations: number;
  readonly activeOwnerCount: number;
  readonly expectedOwnerIdentity: string;
  readonly activeOwnerIdentities: readonly string[];
  readonly staleSocketIdentities: readonly string[];
  readonly staleSocketIdentity: string | null;
  readonly staleSocketCloseCalls: number;
  readonly replacementSocketIdentity: string;
  readonly replacementSocketCloseCalls: number;
  readonly socketClosures: readonly Readonly<{ readonly identity: string; readonly closeCalls: number }>[];
  readonly staleCleanupCalls: number;
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
  let validatorCalls = 0;
  let ticketRequests = 0;
  let socketFactoryCalls = 0;
  let openedSockets = 0;
  const sockets: BenchmarkSocket[] = [];
  const events: PtyTransportEvent[] = [];
  let staleSocket: BenchmarkSocket | undefined;
  let transport!: PtyTransport;

  const validateAttachment = (): Promise<boolean> | true => {
    validatorCalls += 1;
    if (stage !== "validator" || validatorCalls > 1) return true;
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
  const createWebSocket = (
    upgrade: PtyWebSocketUpgradeRequest,
  ): Promise<BenchmarkSocket> | BenchmarkSocket => {
    socketFactoryCalls += 1;
    const socket = new BenchmarkSocket(upgrade.query.resume);
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
    onEvent: (event) => events.push(event),
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
  const validatorCallsBeforeRecovery = validatorCalls;
  const ticketRequestsBeforeRecovery = ticketRequests;
  const socketFactoryCallsBeforeRecovery = socketFactoryCalls;

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
  const expectedOwnerIdentity = INPUT.sessionId;
  const activeOwnerIdentities = sockets
    .filter((socket) => socket.opened && !socket.closed)
    .map((socket) => socket.identity);
  const activeOwnerCountBeforeCleanup = activeOwnerIdentities.length;
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
  const staleSocketIdentities = staleSocket ? [staleSocket.identity] : [];
  const staleSocketIdentity = staleSocket?.identity ?? null;
  const staleSocketCloseCalls = staleSocket?.closeCalls ?? 0;
  const replacementSocketIdentity = replacement.identity;
  const replacementSocketCloseCalls = replacement.closeCalls;
  const socketClosures = sockets.map((socket) => ({
    identity: socket.identity,
    closeCalls: socket.closeCalls,
  }));
  const staleCleanupCalls = staleSocketCloseCalls;
  const staleOpenCalls = staleSocket?.opened ? 1 : 0;
  const duplicateOwnerViolations = activeOwnerCountBeforeCleanup > 1 ? 1 : 0;
  const assertions = {
    quarantineValidatorFence: validatorCallsBeforeRecovery === 1,
    quarantineTicketFence:
      validatorCallsBeforeRecovery === 1 &&
      ticketRequestsBeforeRecovery === (stage === "validator" ? 0 : 1),
    quarantineFactoryFence: socketFactoryCallsBeforeRecovery === (stage === "factory" ? 1 : 0),
    expectedValidatorCount: validatorCalls === 2,
    expectedTicketCount: ticketRequests === (stage === "validator" ? 1 : 2),
    expectedFactoryCount: socketFactoryCalls === (stage === "factory" ? 2 : 1),
    staleSocketIdentityMatchesStage:
      stage === "factory"
        ? staleSocketIdentities.length === 1 && staleSocketIdentities[0] === expectedOwnerIdentity
        : staleSocketIdentities.length === 0,
    staleSocketClosedExactly: stage !== "factory" || staleSocketCloseCalls === 1,
    staleSocketNeverOpened: staleOpenCalls === 0,
    replacementIdentityMatchesExpected: replacementSocketIdentity === expectedOwnerIdentity,
    replacementOpenedExactlyOnce: replacement.opened && openedSockets === 1,
    replacementClosedExactlyOnce: replacementSocketCloseCalls === 1,
    replacementReachedAttached: recoveryAttached,
    expectedOwnerIsOnlyActiveOwner:
      activeOwnerIdentities.length === 1 && activeOwnerIdentities[0] === expectedOwnerIdentity,
    noDuplicateOwners: duplicateOwnerViolations === 0,
    allCallbacksNullAfterClose,
    staleCallbacksExercised:
      staleOnopenDispatches === activeOwnerCountBeforeCleanup &&
      staleOnmessageDispatches === activeOwnerCountBeforeCleanup &&
      staleOnerrorDispatches === activeOwnerCountBeforeCleanup &&
      staleOncloseDispatches === activeOwnerCountBeforeCleanup,
    staleOnopenIgnored: staleOnopenDispatches === activeOwnerCountBeforeCleanup && postCloseStateEvents === 0,
    staleOnmessageIgnored: staleOnmessageDispatches === activeOwnerCountBeforeCleanup && postCloseBytesEvents === 0,
    staleOnerrorIgnored: staleOnerrorDispatches === activeOwnerCountBeforeCleanup && postCloseStateEvents === 0,
    staleOncloseIgnored: staleOncloseDispatches === activeOwnerCountBeforeCleanup && postCloseStateEvents === 0,
    noPostCloseStateEvents: postCloseStateEvents === 0,
    noPostCloseBytesEvents: postCloseBytesEvents === 0,
    noPostCloseNoticeEvents: postCloseNoticeEvents === 0,
    cleanupRecorded: cleanupCalls === (stage === "factory" ? 2 : 1),
  };
  if (Object.values(assertions).some((value) => !value)) {
    throw new Error(`${stage} proof assertion failed: ${JSON.stringify(assertions)}`);
  }

  return {
    sampleMs,
    validatorCalls,
    validatorCallsBeforeRecovery,
    ticketRequests,
    ticketRequestsBeforeRecovery,
    socketFactoryCalls,
    socketFactoryCallsBeforeRecovery,
    openedSockets,
    cleanupCalls,
    duplicateOwnerViolations,
    activeOwnerCount: activeOwnerCountBeforeCleanup,
    expectedOwnerIdentity,
    activeOwnerIdentities,
    staleSocketIdentities,
    staleSocketIdentity,
    staleSocketCloseCalls,
    replacementSocketIdentity,
    replacementSocketCloseCalls,
    socketClosures,
    staleCleanupCalls,
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
