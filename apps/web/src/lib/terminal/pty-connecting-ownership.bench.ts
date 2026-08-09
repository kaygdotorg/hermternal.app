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

interface CallbackBindingLedger {
  readonly socketId: string;
  readonly onopenBound: boolean;
  readonly onmessageBound: boolean;
  readonly onerrorBound: boolean;
  readonly oncloseBound: boolean;
  readonly onopenNullAfterClose: boolean;
  readonly onmessageNullAfterClose: boolean;
  readonly onerrorNullAfterClose: boolean;
  readonly oncloseNullAfterClose: boolean;
}

interface StaleCallbackDispatches {
  readonly onopen: number;
  readonly onmessage: number;
  readonly onerror: number;
  readonly onclose: number;
}

interface PublicationLedger {
  readonly eventCount: number;
  readonly stateCount: number;
  readonly bytesCount: number;
  readonly noticeCount: number;
}

type MutablePublicationLedger = {
  -readonly [Key in keyof PublicationLedger]: number;
};

interface StalePublications {
  readonly onEvent: PublicationLedger;
  readonly subscribe: PublicationLedger;
  readonly onStateChange: PublicationLedger;
}

interface DelayedBlobProof {
  readonly scheduledCount: number;
  readonly completionCount: number;
  readonly dispatchedBeforeClose: boolean;
  readonly conversionStartedBeforeClose: boolean;
  readonly resolvedAfterClose: boolean;
  readonly postCloseBytesRejected: boolean;
  /** Raw lifecycle sequence; validator derives the temporal booleans from it. */
  readonly events: readonly string[];
}

function createPublicationLedger(): MutablePublicationLedger {
  return {
    eventCount: 0,
    stateCount: 0,
    bytesCount: 0,
    noticeCount: 0,
  };
}

function recordEventPublication(
  ledger: MutablePublicationLedger,
  event: PtyTransportEvent,
): void {
  ledger.eventCount += 1;
  if (event.type === "state") ledger.stateCount += 1;
  if (event.type === "bytes") ledger.bytesCount += 1;
  if (event.type === "notice") ledger.noticeCount += 1;
}

function recordStatePublication(ledger: MutablePublicationLedger): void {
  ledger.eventCount += 1;
  ledger.stateCount += 1;
}

/**
 * The deferred frame is synthetic and stays unresolved until the benchmark
 * explicitly releases it after cleanup. This keeps conversion in flight while
 * ownership is revoked, so a late Blob completion cannot publish stale bytes.
 */
class DeferredBlob extends Blob {
  scheduledCount = 0;
  completionCount = 0;
  private resolveBytes: ((value: ArrayBuffer) => void) | null = null;

  constructor(
    private readonly onConversionStart: () => void,
    private readonly onCompletion: () => void,
  ) {
    super([new Uint8Array([0xaa])]);
  }

  override arrayBuffer(): Promise<ArrayBuffer> {
    this.scheduledCount += 1;
    this.onConversionStart();
    return new Promise<ArrayBuffer>((resolve) => {
      this.resolveBytes = (value) => {
        this.completionCount += 1;
        this.onCompletion();
        resolve(value);
      };
    });
  }

  release(): void {
    if (!this.resolveBytes) throw new Error("benchmark released an unscheduled Blob");
    const resolve = this.resolveBytes;
    this.resolveBytes = null;
    resolve(new Uint8Array([0xaa]).buffer);
  }
}

function dispatchCallbacks(callbacks: CallbackSnapshot): StaleCallbackDispatches {
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
  private lateCallbacks: CallbackSnapshot | null = null;

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

  /**
   * Keep the adapter's already-issued callback references so a late event can
   * still invoke them after transport cleanup nulls the socket properties.
   */
  retainCallbacksForLateDispatch(): CallbackSnapshot {
    this.lateCallbacks = this.captureCallbacks();
    return this.lateCallbacks;
  }

  dispatchLateCallbacks(): StaleCallbackDispatches {
    return dispatchCallbacks(this.lateCallbacks ?? {
      onopen: null,
      onmessage: null,
      onerror: null,
      onclose: null,
    });
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
  /** Pre-connect timing control; never used as the ownership sample. */
  readonly negativeControlSampleMs: number;
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
  readonly replacementStateStatus: string | null;
  readonly socketClosures: readonly SocketClosure[];
  readonly callbackBoundSocketCount: number;
  readonly callbackBoundSinkCount: number;
  readonly callbackBoundSinkNames: readonly string[];
  readonly callbackBindings: readonly CallbackBindingLedger[];
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
  readonly stalePublications: StalePublications;
  readonly delayedBlob: DelayedBlobProof;
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
  let connectStartedAt: number | undefined;
  let validatorCalls = 0;
  let ticketRequests = 0;
  let socketFactoryCalls = 0;
  let openedSockets = 0;
  let nextSocketId = 0;
  let ownershipLost = false;
  const inputOwnerIdentity = ownerIdentityFor(INPUT);
  const replacementOwnerIdentity = ownerIdentityFor(REPLACEMENT_INPUT);
  // Keep one exact ledger per publication sink. It starts after close returns so
  // cleanup's own closing/detached states are not misclassified as stale output.
  const stalePublications: {
    readonly onEvent: MutablePublicationLedger;
    readonly subscribe: MutablePublicationLedger;
    readonly onStateChange: MutablePublicationLedger;
  } = {
    onEvent: createPublicationLedger(),
    subscribe: createPublicationLedger(),
    onStateChange: createPublicationLedger(),
  };
  const boundSinks = new Set<"onEvent" | "subscribe" | "onStateChange">();
  const delayedBlobEvents: string[] = [];

  const onEvent = (event: PtyTransportEvent): void => {
    boundSinks.add("onEvent");
    events.push(event);
    if (ownershipLost) recordEventPublication(stalePublications.onEvent, event);
    if (actionTaken || event.type !== "state" || event.state.status !== "connecting") return;
    actionTaken = true;
    // The declared lifecycle boundary is the observable `connecting` state.
    // Setup and ticket work may precede it; the pre-connect clock below is kept
    // only as a negative control to prove that work is not part of sampleMs.
    actionStartedAt = performance.now();
    if (action === "abort") controller.abort();
    if (action === "close") transport.close();
    if (action === "detach") transport.detach();
    if (action === "replace") replacementPromise = transport.connect(REPLACEMENT_INPUT);
  };
  const onStateChange = (): void => {
    boundSinks.add("onStateChange");
    if (ownershipLost) recordStatePublication(stalePublications.onStateChange);
  };
  const onSubscribe = (event: PtyTransportEvent): void => {
    boundSinks.add("subscribe");
    if (ownershipLost) recordEventPublication(stalePublications.subscribe, event);
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
    onStateChange,
  });
  const unsubscribe = transport.subscribe(onSubscribe);

  // This clock intentionally starts before connect. It is a negative control:
  // validator and ticket setup are expected to appear here, but not in sampleMs.
  connectStartedAt = performance.now();
  const cancelled = transport.connect(INPUT, controller.signal);
  await expectAborted(cancelled, `${action} cancelled operation`);
  if (
    !actionTaken ||
    actionStartedAt === undefined ||
    connectStartedAt === undefined
  ) {
    throw new Error(`${action} did not run a connecting observer action`);
  }
  const sampleEndAt = performance.now();
  const sampleMs = roundSample(sampleEndAt - actionStartedAt);
  const negativeControlSampleMs = roundSample(sampleEndAt - connectStartedAt);
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
  // Capture the replacement state before cleanup transitions the transport to
  // detached; non-replacement stages intentionally retain a null state.
  const replacementStateStatus = action === "replace" ? transport.state.status : null;
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
  // The connecting guard prevents the stale pre-replacement adapter from
  // becoming an active owner. The approved transport may still return that
  // late factory value, so its unopened callback-free socket is retained for
  // exact cleanup while replacement must bind every socket callback and sink.
  const callbackSnapshots = sockets.map((socket) => ({
    socket,
    callbacks: socket.retainCallbacksForLateDispatch(),
  }));
  const callbackBindingsBeforeClose = callbackSnapshots.map(
    ({ socket, callbacks }): CallbackBindingLedger => ({
      socketId: socket.socketId,
      onopenBound: callbacks.onopen !== null,
      onmessageBound: callbacks.onmessage !== null,
      onerrorBound: callbacks.onerror !== null,
      oncloseBound: callbacks.onclose !== null,
      onopenNullAfterClose: false,
      onmessageNullAfterClose: false,
      onerrorNullAfterClose: false,
      oncloseNullAfterClose: false,
    }),
  );
  const callbackBoundSocketCount = callbackBindingsBeforeClose.filter(
    (binding) =>
      binding.onopenBound &&
      binding.onmessageBound &&
      binding.onerrorBound &&
      binding.oncloseBound,
  ).length;
  const callbackBoundSinkNames = (["onEvent", "subscribe", "onStateChange"] as const).filter(
    (sink) => boundSinks.has(sink),
  );
  const callbackBoundSinkCount = callbackBoundSinkNames.length;
  const callbackProofApplicable =
    action === "replace" &&
    callbackBoundSocketCount === 1 &&
    callbackBoundSinkNames.join("|") === "onEvent|subscribe|onStateChange";

  // Start a real Blob conversion before ownership is revoked. Its resolver is
  // held until after Close, so completion and stale-byte rejection are distinct
  // observations rather than a synchronous ArrayBuffer shortcut.
  const delayedBlob = new DeferredBlob(
    () => delayedBlobEvents.push("conversion-start"),
    () => delayedBlobEvents.push("completion"),
  );
  let delayedBlobDispatched = false;
  const replacementCallbacks = callbackSnapshots.find(
    ({ socket }) => socket === replacementSocket,
  )?.callbacks;
  if (callbackProofApplicable && replacementCallbacks?.onmessage) {
    delayedBlobEvents.push("dispatch");
    replacementCallbacks.onmessage({ data: delayedBlob });
    delayedBlobDispatched = true;
    await flush();
  }

  // Close must detach every adapter callback before its safeClose call. Replay
  // each callback captured from the live socket after Close to prove stale
  // open, message, error, and close events cannot publish anything.
  transport.close();
  if (callbackProofApplicable) delayedBlobEvents.push("close");
  ownershipLost = true;
  const postCloseEventStart = events.length;
  if (delayedBlobDispatched && delayedBlob.scheduledCount === 1) {
    delayedBlob.release();
    await flush();
  }
  const callbackBindings = callbackSnapshots.map(
    ({ socket, callbacks }): CallbackBindingLedger => ({
      socketId: socket.socketId,
      onopenBound: callbacks.onopen !== null,
      onmessageBound: callbacks.onmessage !== null,
      onerrorBound: callbacks.onerror !== null,
      oncloseBound: callbacks.onclose !== null,
      onopenNullAfterClose: socket.onopen === null,
      onmessageNullAfterClose: socket.onmessage === null,
      onerrorNullAfterClose: socket.onerror === null,
      oncloseNullAfterClose: socket.onclose === null,
    }),
  );
  const allCallbacksNullAfterClose = callbackBindings.every(
    (binding) =>
      binding.onopenNullAfterClose &&
      binding.onmessageNullAfterClose &&
      binding.onerrorNullAfterClose &&
      binding.oncloseNullAfterClose,
  );
  let staleOnopenDispatches = 0;
  let staleOnmessageDispatches = 0;
  let staleOnerrorDispatches = 0;
  let staleOncloseDispatches = 0;
  for (const { socket } of callbackSnapshots) {
    const dispatches = socket.dispatchLateCallbacks();
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
  const delayedBlobEventOrder =
    delayedBlobEvents.length === 4 &&
    delayedBlobEvents[0] === "dispatch" &&
    delayedBlobEvents[1] === "conversion-start" &&
    delayedBlobEvents[2] === "close" &&
    delayedBlobEvents[3] === "completion";
  const delayedBlobProof: DelayedBlobProof = {
    scheduledCount: delayedBlob.scheduledCount,
    completionCount: delayedBlob.completionCount,
    dispatchedBeforeClose: delayedBlobEventOrder,
    conversionStartedBeforeClose: delayedBlobEventOrder,
    resolvedAfterClose: delayedBlobEventOrder,
    postCloseBytesRejected:
      delayedBlobEventOrder &&
      postCloseBytesEvents === 0 &&
      stalePublications.onEvent.bytesCount === 0 &&
      stalePublications.subscribe.bytesCount === 0 &&
      stalePublications.onStateChange.bytesCount === 0,
    events: [...delayedBlobEvents],
  };
  const staleSinkPublicationsRejected = Object.values(stalePublications).every(
    (ledger) =>
      ledger.eventCount === 0 &&
      ledger.stateCount === 0 &&
      ledger.bytesCount === 0 &&
      ledger.noticeCount === 0,
  );
  // Record the exact post-close state for every allocated physical socket.
  const socketClosures = sockets.map(snapshotSocket);
  // The approved transport may invoke the factory after a connecting observer
  // cancels. That adapter value is retained as one unopened stale socket and
  // closed exactly once; only replacement owns a second, opened socket.
  const expectedSocketCount = action === "replace" ? 2 : 1;
  const assertions = {
    connectingGuard:
      staleSockets.length === 1 &&
      staleOpenCalls === 0 &&
      staleSocketCloseCalls === 1 &&
      activeOwnerCount === (action === "replace" ? 1 : 0),
    staleSocketNeverOpened: staleOpenCalls === 0,
    expectedValidatorCount: validatorCalls === (action === "replace" ? 2 : 1),
    expectedFactoryCount: socketFactoryCalls === (action === "replace" ? 2 : 1),
    expectedTicketCount: ticketRequests === (action === "replace" ? 2 : 1),
    negativeControlUsesPreConnectClock:
      connectStartedAt !== undefined &&
      actionStartedAt !== undefined &&
      connectStartedAt <= actionStartedAt &&
      negativeControlSampleMs >= sampleMs,
    negativeControlIncludesSetupAndTicket:
      negativeControlSampleMs >= sampleMs && validatorCalls >= 1 && ticketRequests >= 1,
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
    staleSocketIdentityFence:
      staleSocketIdentities.length === 1 &&
      sameOwnerIdentity(staleSocketIdentities[0]!, inputOwnerIdentity) &&
      staleSocketCloseCalls === 1,
    staleSocketIdFence:
      staleSocketIds.length === 1 &&
      staleSocketId !== null &&
      staleSocketId !== replacementSocketId,
    replacementIdentityMatchesExpected:
      action !== "replace" ||
      (replacementSocketIdentity !== null &&
        sameOwnerIdentity(replacementSocketIdentity, expectedOwnerIdentity!)),
    replacementSocketIdUnique:
      action !== "replace" || replacementSocketId !== null && replacementSocketId !== staleSocketId,
    replacementClosedExactlyOnce: action !== "replace" || replacementSocketCloseCalls === 1,
    exactSocketCleanup:
      socketClosures.length === expectedSocketCount &&
      socketClosures.every(
        (socket) =>
          socket.closeCalls === 1 &&
          (socket.socketId === replacementSocketId
            ? socket.opened &&
              expectedOwnerIdentity !== null &&
              sameOwnerIdentity(socket.ownerIdentity, expectedOwnerIdentity)
            : !socket.opened &&
              sameOwnerIdentity(socket.ownerIdentity, inputOwnerIdentity)),
      ),
    ownerSocketClosureLedgerExact:
      socketClosures.length === expectedSocketCount &&
      socketClosures.some(
        (socket) =>
          socket.socketId === staleSocketId &&
          socket.closeCalls === 1 &&
          !socket.opened &&
          sameOwnerIdentity(socket.ownerIdentity, inputOwnerIdentity),
      ) &&
      (action !== "replace" ||
        (replacementSocketId !== null &&
          socketClosures.some(
            (socket) =>
              socket.socketId === replacementSocketId &&
              socket.closeCalls === 1 &&
              socket.opened &&
              expectedOwnerIdentity !== null &&
              sameOwnerIdentity(socket.ownerIdentity, expectedOwnerIdentity),
          ))),
    callbackApplicabilityMatchesAction:
      callbackProofApplicable ===
      (action === "replace" &&
        callbackBoundSocketCount === 1 &&
        callbackBoundSinkNames.join("|") === "onEvent|subscribe|onStateChange"),
    allCallbacksNullAfterClose:
      action !== "replace" || (callbackProofApplicable && allCallbacksNullAfterClose),
    replacementCallbacksBound:
      action !== "replace" ||
      (callbackProofApplicable &&
        callbackSnapshots.length === 2 &&
        callbackBoundSocketCount === 1 &&
        callbackBoundSinkNames.join("|") === "onEvent|subscribe|onStateChange"),
    callbackBindingCoversAllSinks:
      callbackBoundSinkNames.join("|") === "onEvent|subscribe|onStateChange",
    perSinkStalePublicationRejected: staleSinkPublicationsRejected,
    delayedBlobConversionObserved:
      !callbackProofApplicable ||
      (delayedBlobProof.scheduledCount === 1 &&
        delayedBlobProof.completionCount === 1 &&
        delayedBlobProof.dispatchedBeforeClose &&
        delayedBlobProof.conversionStartedBeforeClose &&
        delayedBlobProof.resolvedAfterClose),
    delayedBlobPostClosePublicationRejected:
      !callbackProofApplicable || delayedBlobProof.postCloseBytesRejected,
    staleCallbacksExercised:
      action !== "replace" ||
      (callbackProofApplicable &&
        staleOnopenDispatches === 1 &&
        staleOnmessageDispatches === 1 &&
        staleOnerrorDispatches === 1 &&
        staleOncloseDispatches === 1),
    staleOnopenIgnored:
      action !== "replace" ||
      (callbackProofApplicable && staleOnopenDispatches === 1 && postCloseStateEvents === 0),
    staleOnmessageIgnored:
      action !== "replace" ||
      (callbackProofApplicable && staleOnmessageDispatches === 1 && postCloseBytesEvents === 0),
    staleOnerrorIgnored:
      action !== "replace" ||
      (callbackProofApplicable && staleOnerrorDispatches === 1 && postCloseStateEvents === 0),
    staleOncloseIgnored:
      action !== "replace" ||
      (callbackProofApplicable && staleOncloseDispatches === 1 && postCloseStateEvents === 0),
    stalePublicationRejected:
      action !== "replace" ||
      (callbackProofApplicable &&
        staleOnopenDispatches === 1 &&
        staleOnmessageDispatches === 1 &&
        staleOnerrorDispatches === 1 &&
        staleOncloseDispatches === 1 &&
        postCloseStateEvents === 0 &&
        postCloseBytesEvents === 0 &&
        postCloseNoticeEvents === 0 &&
        staleSinkPublicationsRejected &&
        delayedBlobProof.dispatchedBeforeClose &&
        delayedBlobProof.conversionStartedBeforeClose &&
        delayedBlobProof.resolvedAfterClose &&
        delayedBlobProof.postCloseBytesRejected),
    noPostCloseStateEvents: postCloseStateEvents === 0,
    noPostCloseBytesEvents: postCloseBytesEvents === 0,
    noPostCloseNoticeEvents: postCloseNoticeEvents === 0,
    cleanupRecorded: cleanupCalls === expectedSocketCount,
  };
  if (Object.values(assertions).some((value) => !value)) {
    throw new Error(`${action} proof assertion failed: ${JSON.stringify(assertions)}`);
  }

  return {
    sampleMs,
    negativeControlSampleMs,
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
    replacementStateStatus,
    socketClosures,
    callbackBoundSocketCount,
    callbackBoundSinkCount,
    callbackBoundSinkNames,
    callbackBindings,
    callbackProofApplicable,
    staleOpenCalls,
    allCallbacksNullAfterClose,
    staleOnopenDispatches,
    staleOnmessageDispatches,
    staleOnerrorDispatches,
    staleOncloseDispatches,
    postCloseStateEvents,
    postCloseBytesEvents,
    postCloseNoticeEvents,
    stalePublications,
    delayedBlob: delayedBlobProof,
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
    start: "performance.now at the connecting state lifecycle event before observer cancellation or replacement action",
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
