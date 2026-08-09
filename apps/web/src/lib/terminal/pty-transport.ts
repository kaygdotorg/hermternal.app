import {
  MAX_WS_TICKET_LENGTH,
  WsTicketError,
} from "../chat/ws-ticket";

export const PTY_WS_TICKET_PATH = "/api/auth/ws-ticket" as const;
export const PTY_WEBSOCKET_PATH = "/api/pty" as const;
export const PTY_WEBSOCKET_ORIGIN = "same-origin" as const;
export const PTY_REPLAY_CAPACITY_BYTES = 1024 * 1024;
export const PTY_DETACH_RETENTION_MS = 30 * 60 * 1000;
export const PTY_MIN_COLS = 1;
export const PTY_MAX_COLS = 2000;
export const PTY_MIN_ROWS = 1;
export const PTY_MAX_ROWS = 1000;

const MAX_SESSION_ID_LENGTH = 128;
const MAX_ATTACH_HANDLE_LENGTH = 512;
const MAX_PROCESS_IDENTITY_LENGTH = 128;
const SAFE_OPAQUE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~-]*$/u;
const RESIZE_PREFIX = new Uint8Array([
  0x1b, 0x5b, 0x52, 0x45, 0x53, 0x49, 0x5a, 0x45, 0x3a,
]);
const RESIZE_SUFFIX = 0x5d;

export type PtyMode = "legacy" | "attach";
export type PtyStatus =
  | "closed"
  | "ticket_pending"
  | "connecting"
  | "starting"
  | "attached"
  | "reattaching"
  | "detached"
  | "closing"
  | "exited"
  | "failed";

export type PtyCloseClassification =
  | "authentication-rejected"
  | "host-or-origin-rejected"
  | "embedded-chat-disabled"
  | "peer-rejected"
  | "attachment-superseded"
  | "pty-process-exited"
  | "backend-failure"
  | "connection-closed"
  | "unsupported";

export type PtyErrorCode =
  | "aborted"
  | "authentication-required"
  | "closed"
  | "attachment-superseded"
  | "connection-failed"
  | "expired-attachment"
  | "invalid-attachment"
  | "invalid-frame"
  | "invalid-input"
  | "invalid-options"
  | "invalid-ticket"
  | "legacy-reattach-prohibited"
  | "not-attached"
  | "send-failed";

const ERROR_MESSAGES: Record<PtyErrorCode, string> = {
  aborted: "The Terminal connection attempt was cancelled.",
  "authentication-required": "Terminal authentication is required.",
  "attachment-superseded": "The Terminal attachment was superseded.",
  closed: "The Terminal transport is closed.",
  "connection-failed": "The Terminal WebSocket connection failed.",
  "expired-attachment": "The detached Terminal attachment expired.",
  "invalid-attachment": "The Terminal attachment failed closed validation.",
  "invalid-frame": "The Terminal WebSocket sent an invalid binary frame.",
  "invalid-input": "The Terminal input was outside the bounded contract.",
  "invalid-options": "The Terminal transport options were outside the bounded contract.",
  "invalid-ticket": "The Terminal WebSocket ticket was invalid.",
  "legacy-reattach-prohibited": "A legacy Terminal process cannot be reattached.",
  "not-attached": "The Terminal WebSocket is not attached.",
  "send-failed": "The Terminal WebSocket send failed.",
};

export class PtyTransportError extends Error {
  readonly code: PtyErrorCode;
  readonly generation?: number;

  constructor(code: PtyErrorCode, generation?: number) {
    super(ERROR_MESSAGES[code]);
    this.name = code === "aborted" ? "AbortError" : "PtyTransportError";
    this.code = code;
    this.generation = generation;
  }
}

/**
 * The caller owns issuance of an opaque attach handle. The transport requires
 * a validation seam because the pinned source exposes no client-visible handle
 * grammar and would otherwise turn an unknown value into a new PTY registry key.
 */
export interface PtyConnectionInput {
  readonly sessionId: string;
  readonly attach?: string;
  readonly processIdentity?: string;
  readonly detachedAtMs?: number;
}

export interface PtyConnectionState {
  readonly status: PtyStatus;
  readonly generation: number;
  readonly mode: PtyMode;
  readonly sessionId?: string;
  readonly processIdentity?: string;
  readonly closeCode?: number;
  readonly closeClassification?: PtyCloseClassification;
  readonly outputMayBeTruncated: boolean;
  /** False when transport policy has permanently blocked exact-identity reattach. */
  readonly reconnectSupported?: boolean;
}

export interface PtyBytesEvent {
  readonly type: "bytes";
  readonly generation: number;
  readonly bytes: Uint8Array;
  readonly outputMayBeTruncated: boolean;
}

export interface PtyStateEvent {
  readonly type: "state";
  readonly state: PtyConnectionState;
}

export interface PtyNoticeEvent {
  readonly type: "notice";
  readonly generation: number;
  readonly notice: "output-may-be-truncated";
  readonly replayCapacityBytes: typeof PTY_REPLAY_CAPACITY_BYTES;
}

export type PtyTransportEvent = PtyBytesEvent | PtyStateEvent | PtyNoticeEvent;

export interface PtyMessageEvent {
  readonly data: unknown;
}

export interface PtyCloseEvent {
  readonly code?: number;
}

export interface PtyWebSocket {
  onopen: ((event?: unknown) => void) | null;
  onmessage: ((event: PtyMessageEvent) => void) | null;
  onerror: ((event?: unknown) => void) | null;
  onclose: ((event?: PtyCloseEvent) => void) | null;
  binaryType?: string;
  send(data: Uint8Array): void;
  close(code?: number, reason?: string): void;
  readonly readyState?: number;
}

export interface PtyWebSocketUpgradeRequest {
  readonly path: typeof PTY_WEBSOCKET_PATH;
  readonly origin: typeof PTY_WEBSOCKET_ORIGIN;
  readonly query: {
    readonly ticket: string;
    readonly resume: string;
    readonly attach?: string;
  };
}

export interface PtyTicketRequestInput {
  readonly method: "POST";
  readonly path: typeof PTY_WS_TICKET_PATH;
  readonly credentials: "same-origin";
  readonly signal: AbortSignal;
}

export type PtyTicketRequestBoundary = (
  input: PtyTicketRequestInput,
) => Promise<unknown>;
export type FreshPtyTicketProvider = (signal: AbortSignal) => Promise<string>;
export type PtyWebSocketFactory = (
  upgrade: PtyWebSocketUpgradeRequest,
  signal: AbortSignal,
) => PtyWebSocket | Promise<PtyWebSocket>;
export type PtyAttachmentValidator = (
  input: Readonly<PtyConnectionInput>,
  signal: AbortSignal,
) => boolean | Promise<boolean>;

export interface PtyTransportOptions {
  readonly ticketProvider: FreshPtyTicketProvider;
  readonly createWebSocket: PtyWebSocketFactory;
  readonly validateAttachment?: PtyAttachmentValidator;
  readonly now?: () => number;
  readonly onEvent?: (event: PtyTransportEvent) => void;
  readonly onStateChange?: (state: PtyConnectionState) => void;
}

export interface PtyTransport {
  readonly state: PtyConnectionState;
  connect(input: PtyConnectionInput, signal?: AbortSignal): Promise<void>;
  reconnect(signal?: AbortSignal): Promise<void>;
  sendInput(input: string | Uint8Array): void;
  resize(cols: number, rows: number): void;
  /**
   * Stop the current owner, or no-op when an expected generation is stale.
   * The generation-scoped form lets a bridge quarantine a late adapter
   * completion without detaching a replacement owner.
   */
  detach(expectedGeneration?: number): void;
  close(expectedGeneration?: number): void;
  subscribe(listener: (event: PtyTransportEvent) => void): () => void;
}

interface SocketContext {
  readonly generation: number;
  readonly socket: PtyWebSocket;
  readonly mode: PtyMode;
  readonly input: PtyConnectionInput;
  readonly reattaching: boolean;
  closed: boolean;
  opened: boolean;
  messageChain: Promise<void>;
  resolveReady: () => void;
  rejectReady: (error: PtyTransportError) => void;
  readonly ready: Promise<void>;
}

interface ConnectionAttempt {
  readonly generation: number;
  readonly controller: AbortController;
  readonly promise: Promise<void>;
  waiters: number;
  unabortableWaiters: number;
  settled: boolean;
}

interface DetachedAttachment {
  readonly input: PtyConnectionInput;
  readonly atMs: number;
}

/**
 * Adapt the reviewed same-origin ticket request seam to the PTY transport.
 * The returned provider performs one request per call and retains no ticket
 * after its caller consumes the result for one WebSocket upgrade.
 */
export function createFreshPtyTicketProvider(
  request: PtyTicketRequestBoundary,
): FreshPtyTicketProvider {
  if (typeof request !== "function") {
    throw new PtyTransportError("invalid-options");
  }
  return async (signal): Promise<string> => {
    throwIfAborted(signal, 0);
    let response: unknown;
    try {
      response = await awaitWithAbort(
        Promise.resolve(
          request({
            method: "POST",
            path: PTY_WS_TICKET_PATH,
            credentials: "same-origin",
            signal,
          }),
        ),
        signal,
        0,
      );
    } catch (error) {
      if (signal.aborted || isAbortLike(error)) {
        throw new PtyTransportError("aborted");
      }
      if (error instanceof PtyTransportError) throw error;
      if (error instanceof WsTicketError) {
        if (error.code === "cancelled") {
          throw new PtyTransportError("aborted");
        }
        if (error.code === "authentication-failed" && error.status === 401) {
          throw new PtyTransportError("authentication-required");
        }
        if (error.code === "response-invalid") {
          throw new PtyTransportError("invalid-ticket");
        }
        throw new PtyTransportError("connection-failed");
      }
      throw new PtyTransportError("connection-failed");
    }
    return parseTicketResponse(response);
  };
}

export function createPtyTransport(options: PtyTransportOptions): PtyTransport {
  if (
    typeof options !== "object" ||
    options === null ||
    typeof options.ticketProvider !== "function" ||
    typeof options.createWebSocket !== "function" ||
    (options.validateAttachment !== undefined &&
      typeof options.validateAttachment !== "function") ||
    (options.now !== undefined && typeof options.now !== "function")
  ) {
    throw new PtyTransportError("invalid-options");
  }

  const now = options.now ?? Date.now;
  const listeners = new Set<(event: PtyTransportEvent) => void>();
  const pendingEvents: PtyTransportEvent[] = [];
  let dispatchingEvents = false;
  let currentGeneration = 0;
  let currentState: PtyConnectionState = {
    status: "closed",
    generation: 0,
    mode: "legacy",
    outputMayBeTruncated: false,
    reconnectSupported: false,
  };
  let currentInput: PtyConnectionInput | undefined;
  let activeContext: SocketContext | undefined;
  let activeAttempt: ConnectionAttempt | undefined;
  let detachedAttachment: DetachedAttachment | undefined;
  let reattachBlocked: PtyErrorCode | undefined;
  let userClosed = false;
  let explicitlyClosed = false;

  const detachedAtFor = (input: PtyConnectionInput): number | undefined =>
    detachedAttachment && sameConnectionInput(detachedAttachment.input, input)
      ? detachedAttachment.atMs
      : undefined;

  const clearDetachedFor = (input: PtyConnectionInput): void => {
    if (
      detachedAttachment &&
      sameConnectionInput(detachedAttachment.input, input)
    ) {
      detachedAttachment = undefined;
    }
  };

  const markDetached = (input: PtyConnectionInput, atMs: number): void => {
    if (modeFor(input) !== "attach") return;
    detachedAttachment = { input, atMs };
  };

  const observe = (callback: (() => void) | undefined): void => {
    try {
      callback?.();
    } catch {
      // Observers are not transport authorities. Their errors are discarded so
      // caller-controlled text cannot escape the closed diagnostic boundary or
      // interrupt socket cleanup and readiness settlement.
    }
  };

  const emit = (event: PtyTransportEvent): void => {
    pendingEvents.push(event);
    if (dispatchingEvents) return;

    dispatchingEvents = true;
    try {
      for (let index = 0; index < pendingEvents.length; index += 1) {
        const nextEvent = pendingEvents[index]!;
        // Capture one listener snapshot before any observer can synchronously
        // subscribe, unsubscribe, or publish a newer state. Reentrant events
        // stay queued until every subscriber has seen this older event, so a
        // listener cannot receive `closing`/`detached` before the `attached`
        // event that caused a sibling listener to close the transport.
        const snapshot = [...listeners];
        observe(options.onEvent ? () => options.onEvent?.(nextEvent) : undefined);
        for (const listener of snapshot) observe(() => listener(nextEvent));
      }
    } finally {
      pendingEvents.length = 0;
      dispatchingEvents = false;
    }
  };

  const setState = (
    status: PtyStatus,
    generation: number,
    input = currentInput,
    observation?: { readonly code?: number; readonly classification?: PtyCloseClassification },
    truncated = false,
  ): void => {
    const mode = modeFor(input);
    const retainedAttachment =
      mode === "attach" &&
      input !== undefined &&
      detachedAttachment !== undefined &&
      sameConnectionInput(detachedAttachment.input, input);
    // A failed handshake is not evidence that a detached PTY exists. Only an
    // established attachment or exact retained identity may advertise explicit
    // reconnect; this keeps 4401/4403 pre-open failures out of the retry UI.
    const reconnectSupported =
      mode === "attach" &&
      reattachBlocked === undefined &&
      !userClosed &&
      (status !== "failed" && status !== "exited" && status !== "closed" || retainedAttachment);
    const nextState = Object.freeze({
      status,
      generation,
      mode,
      ...(input ? { sessionId: input.sessionId } : {}),
      ...(mode === "attach" && input?.processIdentity
        ? { processIdentity: input.processIdentity }
        : {}),
      ...(observation?.code !== undefined ? { closeCode: observation.code } : {}),
      ...(observation ? { closeClassification: observation.classification } : {}),
      outputMayBeTruncated: truncated,
      reconnectSupported,
    });
    currentState = nextState;
    // Publish the immutable transition before observers can synchronously
    // replace it. The observer still receives the same intended value, while
    // currentState remains owned by the newest reentrant transition.
    emit({ type: "state", state: nextState });
    // onEvent runs before onStateChange and may synchronously Close or replace
    // this generation. Never deliver an obsolete callback after that handoff.
    if (currentState !== nextState || currentGeneration !== generation) return;
    observe(
      options.onStateChange
        ? () => options.onStateChange?.(nextState)
        : undefined,
    );
  };

  const isCurrent = (context: SocketContext): boolean =>
    activeContext === context &&
    context.generation === currentGeneration &&
    !context.closed;

  const detachHandlers = (context: SocketContext): void => {
    context.socket.onopen = null;
    context.socket.onmessage = null;
    context.socket.onerror = null;
    context.socket.onclose = null;
  };

  const invalidateContext = (context: SocketContext): void => {
    if (context.closed) return;
    context.closed = true;
    detachHandlers(context);
    if (activeContext === context) activeContext = undefined;
  };

  const failContext = (
    context: SocketContext,
    error: PtyTransportError,
    status: PtyStatus = "failed",
  ): void => {
    if (!isCurrent(context)) return;
    const generation = context.generation;
    invalidateContext(context);
    clearAttempt(generation);
    if (status === "detached") markDetached(context.input, now());
    safeClose(context.socket);
    context.rejectReady(error);
    // Adapter close hooks are user-controlled and may synchronously start a
    // replacement or explicit Close. Never publish this old failure after a
    // newer generation has claimed ownership.
    if (currentGeneration !== generation || userClosed) return;
    setState(status, generation, context.input);
  };

  const attachContext = (
    socket: PtyWebSocket,
    generation: number,
    input: PtyConnectionInput,
    reattaching: boolean,
    signal: AbortSignal,
  ): SocketContext => {
    let resolveReady!: () => void;
    let rejectReady!: (error: PtyTransportError) => void;
    const ready = new Promise<void>((resolve, reject) => {
      resolveReady = resolve;
      rejectReady = reject;
    });
    const context: SocketContext = {
      generation,
      socket,
      mode: modeFor(input),
      input,
      reattaching,
      closed: false,
      opened: false,
      messageChain: Promise.resolve(),
      resolveReady,
      rejectReady,
      ready,
    };
    socket.binaryType = "arraybuffer";
    socket.onopen = () => {
      if (!isCurrent(context) || signal.aborted) return;
      context.opened = true;
      clearDetachedFor(input);
      setState("attached", generation, input, undefined, reattaching);
      if (!isCurrent(context) || signal.aborted) return;
      if (reattaching) {
        emit({
          type: "notice",
          generation,
          notice: "output-may-be-truncated",
          replayCapacityBytes: PTY_REPLAY_CAPACITY_BYTES,
        });
        if (!isCurrent(context) || signal.aborted) return;
      }
      if (!isCurrent(context) || signal.aborted) return;
      context.resolveReady();
    };
    socket.onmessage = (event) => {
      if (!isCurrent(context)) return;
      // Blob conversion is asynchronous. One chain per socket preserves exact
      // frame order and the identity checks prevent stale callbacks from a
      // superseded or closed socket from reaching the renderer.
      context.messageChain = context.messageChain
        .then(async () => {
          if (!isCurrent(context)) return;
          const bytes = await toBytes(event.data);
          if (!isCurrent(context)) return;
          emit({
            type: "bytes",
            generation,
            bytes,
            outputMayBeTruncated: reattaching,
          });
        })
        .catch(() => failContext(context, new PtyTransportError("invalid-frame", generation)));
    };
    socket.onerror = () => {
      if (!isCurrent(context)) return;
      // Some adapters report a network failure without a follow-up close. An
      // already-open attach session is still eligible for explicit reattach;
      // an unopened handshake remains a failed connection and has no retention.
      const status =
        context.mode === "attach" && context.opened ? "detached" : "failed";
      failContext(
        context,
        new PtyTransportError("connection-failed", generation),
        status,
      );
    };
    socket.onclose = (event) => {
      if (!isCurrent(context)) return;
      const observation = classifyClose(event?.code);
      const opened = context.opened;
      invalidateContext(context);
      clearAttempt(context.generation);
      context.rejectReady(new PtyTransportError("connection-failed", generation));
      const status = statusForClose(context.mode, observation, opened);
      const retainAfterEstablishedFailure =
        opened &&
        context.mode === "attach" &&
        (observation.classification === "authentication-rejected" ||
          observation.classification === "backend-failure");
      if (status === "detached" || retainAfterEstablishedFailure) {
        markDetached(input, now());
      }
      reattachBlocked = retryBlockForClose(observation.classification);
      setState(status, generation, input, observation);
    };
    return context;
  };

  const clearAttempt = (generation: number): void => {
    if (activeAttempt?.generation === generation) activeAttempt = undefined;
  };

  const maybeAbortAttempt = (attempt: ConnectionAttempt): void => {
    if (
      !attempt.settled &&
      attempt.waiters === 0 &&
      attempt.unabortableWaiters === 0
    ) {
      attempt.controller.abort();
    }
  };

  const waitForAttempt = (
    attempt: ConnectionAttempt,
    signal?: AbortSignal,
  ): Promise<void> => {
    if (!signal) {
      // A caller without a signal keeps the shared attempt alive. Preserve the
      // shared promise identity for ordinary coalescing callers.
      if (!attempt.settled) {
        attempt.unabortableWaiters += 1;
        attempt.promise.then(
          () => {
            attempt.unabortableWaiters = Math.max(0, attempt.unabortableWaiters - 1);
          },
          () => {
            attempt.unabortableWaiters = Math.max(0, attempt.unabortableWaiters - 1);
          },
        );
      }
      return attempt.promise;
    }
    if (signal.aborted) {
      return Promise.reject(new PtyTransportError("aborted", attempt.generation));
    }

    attempt.waiters += 1;
    return new Promise<void>((resolve, reject) => {
      let settled = false;
      let registered = true;
      const release = (): void => {
        if (!registered) return;
        registered = false;
        attempt.waiters = Math.max(0, attempt.waiters - 1);
        maybeAbortAttempt(attempt);
      };
      const cleanup = (): void => signal.removeEventListener("abort", onAbort);
      const onAbort = (): void => {
        if (settled) return;
        settled = true;
        cleanup();
        release();
        reject(new PtyTransportError("aborted", attempt.generation));
      };

      signal.addEventListener("abort", onAbort, { once: true });
      if (signal.aborted) onAbort();
      attempt.promise.then(
        () => {
          if (settled) return;
          settled = true;
          cleanup();
          release();
          resolve();
        },
        (error: unknown) => {
          if (settled) return;
          settled = true;
          cleanup();
          release();
          reject(error);
        },
      );
    });
  };

  const start = (
    input: PtyConnectionInput,
    reattaching: boolean,
    signal?: AbortSignal,
  ): Promise<void> => {
    const normalized = validateInput(input);
    const staleAttempt = activeAttempt;
    const sameIdentity =
      currentInput !== undefined && sameConnectionInput(currentInput, normalized);
    const authRecovery =
      reattaching &&
      sameIdentity &&
      reattachBlocked === "authentication-required" &&
      detachedAtFor(normalized) !== undefined;
    if (staleAttempt && sameIdentity) {
      return waitForAttempt(staleAttempt, signal);
    }
    if (signal?.aborted) {
      return Promise.reject(new PtyTransportError("aborted", currentGeneration));
    }
    if (detachedAttachment && !sameIdentity) {
      // Retention belongs to one exact PTY identity. Do not let an old
      // session's expiry evidence reject a replacement current-session attach.
      detachedAttachment = undefined;
    }

    // A deterministic retry fence is transport evidence, not generic cleanup
    // state. A new identity or the documented explicit 4401 recovery action
    // may clear it; ordinary same-identity reconnect and cleanup must not.
    if (!sameIdentity || authRecovery) reattachBlocked = undefined;

    // Claim the replacement generation and its active-attempt slot before any
    // adapter-controlled close or abort callback. A nested connector can then
    // supersede this owner without the outer path overwriting its slot.
    const generation = ++currentGeneration;
    const controller = new AbortController();
    currentInput = normalized;
    userClosed = false;
    explicitlyClosed = false;

    let resolveAttempt!: () => void;
    let rejectAttempt!: (error: PtyTransportError) => void;
    const promise = new Promise<void>((resolve, reject) => {
      resolveAttempt = resolve;
      rejectAttempt = reject;
    });
    const attempt: ConnectionAttempt = {
      generation,
      controller,
      promise,
      waiters: 0,
      unabortableWaiters: 0,
      settled: false,
    };
    activeAttempt = attempt;

    const ownsAttempt = (): boolean =>
      currentGeneration === generation &&
      !userClosed &&
      activeAttempt === attempt;
    const throwIfNotCurrent = (): void => {
      throwIfAborted(controller.signal, generation);
      if (!ownsAttempt()) throw new PtyTransportError("aborted", generation);
    };
    const rejectStaleAttempt = (): void => {
      attempt.settled = true;
      controller.abort();
      rejectAttempt(new PtyTransportError("aborted", generation));
      clearAttempt(generation);
    };

    if (activeContext) {
      const stale = activeContext;
      invalidateContext(stale);
      stale.rejectReady(new PtyTransportError("aborted", stale.generation));
      safeClose(stale.socket);
      if (!ownsAttempt()) rejectStaleAttempt();
    }
    if (ownsAttempt() && staleAttempt) {
      staleAttempt.controller.abort();
      if (!ownsAttempt()) rejectStaleAttempt();
    }

    let attemptContext: SocketContext | undefined;
    let ownedSocket: PtyWebSocket | undefined;
    const closeOwnedSocket = (socket?: PtyWebSocket): void => {
      if (socket !== undefined) {
        // A catch path may have closed and cleared the slot before the late
        // promise reaction runs. Only the current owner may close this value.
        if (ownedSocket !== socket) return;
        ownedSocket = undefined;
        safeClose(socket);
        return;
      }
      const owned = ownedSocket;
      ownedSocket = undefined;
      if (owned) safeClose(owned);
    };

    if (!ownsAttempt()) return waitForAttempt(attempt, signal);

    void (async (): Promise<void> => {
      try {
        throwIfNotCurrent();
        await validateAttachPreflight(
          normalized,
          reattaching,
          detachedAtFor(normalized),
          now(),
          options,
          controller.signal,
          generation,
        );
        throwIfNotCurrent();
        setState("ticket_pending", generation, normalized);
        // The ticket-pending event is observable and can abort, Close, or
        // replace this attempt before the provider is allowed to mint a ticket.
        throwIfNotCurrent();
        const ticket = await awaitWithAbort(
          Promise.resolve(options.ticketProvider(controller.signal)),
          controller.signal,
          generation,
        );
        // The ticket promise can settle and remove its abort listener before a
        // queued abort or replacement runs this continuation. Do not validate,
        // publish, or invoke the socket factory for a stale owner.
        throwIfNotCurrent();
        validateTicket(ticket, generation);
        setState("connecting", generation, normalized);
        // The factory is intentionally invoked after the connecting observer,
        // even if that observer cancelled the attempt. Its returned socket is
        // captured by the ownership slot and closed by awaitWithAbort's late
        // value path instead of being left as an untracked adapter resource.
        const upgrade = createUpgrade(ticket, normalized);
        const socketPromise = Promise.resolve(
          options.createWebSocket(upgrade, controller.signal),
        ).then((socket) => {
          // Capture ownership before awaitWithAbort can settle. This closes a
          // factory value even when cancellation lands between promise
          // settlement and the async continuation's next statement.
          ownedSocket = socket;
          return socket;
        });
        const socket = await awaitWithAbort(
          socketPromise,
          controller.signal,
          generation,
          (lateSocket) => closeOwnedSocket(lateSocket),
        );
        throwIfNotCurrent();
        const context = attachContext(
          socket,
          generation,
          normalized,
          reattaching,
          controller.signal,
        );
        attemptContext = context;
        activeContext = context;
        // The active context now owns cleanup for this socket. Before this
        // transfer, every post-await cancellation path closes ownedSocket.
        ownedSocket = undefined;
        setState(reattaching ? "reattaching" : "starting", generation, normalized);
        await awaitWithAbort(context.ready, controller.signal, generation);
        throwIfNotCurrent();
        attempt.settled = true;
        resolveAttempt();
      } catch (error) {
        const sanitized = sanitizeError(error, controller.signal, generation);
        const contextAlreadyHandled = attemptContext?.closed === true;
        closeOwnedSocket();
        if (attemptContext && isCurrent(attemptContext)) {
          if (attemptContext.mode === "attach" && attemptContext.opened) {
            markDetached(attemptContext.input, now());
          }
          invalidateContext(attemptContext);
          attemptContext.rejectReady(sanitized);
          safeClose(attemptContext.socket);
        }
        // Clear before notifying state observers. A synchronous retry from a
        // failure observer must create a fresh attempt, while the finally block
        // remains generation-guarded so it cannot clear that replacement.
        clearAttempt(generation);
        if (
          generation === currentGeneration &&
          !userClosed &&
          !contextAlreadyHandled &&
          currentState.status !== "failed"
        ) {
          if (isPermanentReattachError(sanitized.code)) {
            reattachBlocked = sanitized.code;
          }
          setState(
            sanitized.code === "aborted" ? detachedStatus(normalized) : "failed",
            generation,
            normalized,
          );
        }
        attempt.settled = true;
        rejectAttempt(sanitized);
      } finally {
        clearAttempt(generation);
      }
    })();
    return waitForAttempt(attempt, signal);
  };

  const stop = (closing: boolean, expectedGeneration?: number): void => {
    // A late invalidated adapter completion may carry the generation that it
    // tried to claim. Ignore scoped cleanup once a newer generation owns the
    // transport; an old detach must never tear down that replacement.
    if (expectedGeneration !== undefined && expectedGeneration !== currentGeneration) return;

    // A coordinator lease invalidation calls detach() to start the exact-identity
    // retention window; only an explicit close() is a user-closed terminal that
    // must hide reconnect. Keep these intents distinct in public retry state.
    const hadActiveContext = activeContext !== undefined;
    const hadActiveAttempt = activeAttempt !== undefined;
    userClosed = closing;
    explicitlyClosed = closing;
    // Keep a server/authentication retry fence after cleanup has no active
    // owner. Only a new identity or explicit recovery in start() may clear it;
    // detach/Close must not turn failed authentication into an implicit retry.
    if (hadActiveContext || hadActiveAttempt) reattachBlocked = undefined;
    const generation = ++currentGeneration;
    const input = currentInput;
    const attempt = activeAttempt;
    activeAttempt = undefined;
    attempt?.controller.abort();
    let detachedOpenedSocket = false;
    if (activeContext) {
      const context = activeContext;
      detachedOpenedSocket = context.mode === "attach" && context.opened;
      invalidateContext(context);
      context.rejectReady(new PtyTransportError("closed", context.generation));
      safeClose(context.socket);
      // Adapter close is reentrant. If it started a replacement, the old
      // generation no longer owns detach evidence and must not write A after B
      // has claimed the transport.
      if (detachedOpenedSocket && currentGeneration === generation) {
        markDetached(context.input, now());
      }
    }

    // Close invalidates the old socket before exposing its transient state. A
    // reentrant observer can therefore start a replacement without the old
    // cleanup path later overwriting that replacement's state.
    if (closing && currentGeneration === generation) {
      setState("closing", generation, input);
    }
    if (currentGeneration !== generation) return;
    setState(detachedStatus(input), generation, input);
  };

  return {
    get state(): PtyConnectionState {
      return currentState;
    },
    connect(input, signal) {
      const normalized = validateInput(input);
      const authRecovery =
        reattachBlocked === "authentication-required" &&
        currentInput !== undefined &&
        sameConnectionInput(currentInput, normalized) &&
        detachedAtFor(normalized) !== undefined;
      if (
        reattachBlocked &&
        currentInput &&
        sameConnectionInput(currentInput, normalized) &&
        !authRecovery
      ) {
        return Promise.reject(
          new PtyTransportError(reattachBlocked, currentGeneration),
        );
      }
      // A same-identity connect after 4401 is the sole explicit recovery path;
      // reconnect() remains fenced until this deliberate attempt succeeds.
      return start(normalized, authRecovery, signal);
    },
    reconnect(signal) {
      if (explicitlyClosed && currentInput && modeFor(currentInput) === "attach") {
        return Promise.reject(new PtyTransportError("closed", currentGeneration));
      }
      if (!currentInput || modeFor(currentInput) !== "attach") {
        return Promise.reject(
          new PtyTransportError("legacy-reattach-prohibited", currentGeneration),
        );
      }
      if (reattachBlocked) {
        return Promise.reject(
          new PtyTransportError(reattachBlocked, currentGeneration),
        );
      }
      return start(currentInput, true, signal);
    },
    sendInput(input) {
      const context = requireAttached(activeContext, currentGeneration);
      let bytes: Uint8Array;
      if (typeof input === "string") {
        bytes = new TextEncoder().encode(input);
      } else if (input instanceof Uint8Array) {
        bytes = input.slice();
      } else {
        throw new PtyTransportError("invalid-input", currentGeneration);
      }
      sendBytes(context, bytes);
    },
    resize(cols, rows) {
      const context = requireAttached(activeContext, currentGeneration);
      sendBytes(context, encodeResize(cols, rows));
    },
    detach(expectedGeneration) {
      stop(false, expectedGeneration);
    },
    close(expectedGeneration) {
      stop(true, expectedGeneration);
    },
    subscribe(listener) {
      if (typeof listener !== "function") throw new PtyTransportError("invalid-options");
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
}

function createUpgrade(ticket: string, input: PtyConnectionInput): PtyWebSocketUpgradeRequest {
  const attach = input.attach;
  return {
    path: PTY_WEBSOCKET_PATH,
    origin: PTY_WEBSOCKET_ORIGIN,
    query: {
      ticket,
      resume: input.sessionId,
      ...(attach ? { attach } : {}),
    },
  };
}

function validateInput(input: PtyConnectionInput): PtyConnectionInput {
  if (typeof input !== "object" || input === null) throw new PtyTransportError("invalid-input");
  const keys = Object.keys(input);
  if (keys.some((key) => !["sessionId", "attach", "processIdentity", "detachedAtMs"].includes(key))) {
    throw new PtyTransportError("invalid-input");
  }
  if (!isSafeOpaque(input.sessionId, MAX_SESSION_ID_LENGTH)) throw new PtyTransportError("invalid-input");
  if (input.attach !== undefined && typeof input.attach !== "string") throw new PtyTransportError("invalid-input");
  if (input.attach && input.attach.length > MAX_ATTACH_HANDLE_LENGTH) throw new PtyTransportError("invalid-attachment");
  if (input.attach && !isSafeOpaque(input.processIdentity, MAX_PROCESS_IDENTITY_LENGTH)) {
    throw new PtyTransportError("invalid-attachment");
  }
  if (!input.attach && (input.processIdentity !== undefined || input.detachedAtMs !== undefined)) {
    throw new PtyTransportError("invalid-input");
  }
  if (
    input.detachedAtMs !== undefined &&
    (!Number.isFinite(input.detachedAtMs) || !Number.isInteger(input.detachedAtMs) || input.detachedAtMs < 0)
  ) {
    throw new PtyTransportError("invalid-attachment");
  }
  return Object.freeze({
    sessionId: input.sessionId,
    ...(input.attach ? { attach: input.attach } : {}),
    ...(input.attach && input.processIdentity ? { processIdentity: input.processIdentity } : {}),
    ...(input.attach && input.detachedAtMs !== undefined ? { detachedAtMs: input.detachedAtMs } : {}),
  });
}

async function validateAttachPreflight(
  input: PtyConnectionInput,
  reattaching: boolean,
  localDetachedAtMs: number | undefined,
  nowMs: number,
  options: PtyTransportOptions,
  signal: AbortSignal,
  generation: number,
): Promise<void> {
  if (!input.attach) return;
  const detachedAt = localDetachedAtMs ?? input.detachedAtMs;
  if (reattaching && detachedAt === undefined) throw new PtyTransportError("invalid-attachment", generation);
  if (detachedAt !== undefined && (nowMs < detachedAt || nowMs - detachedAt > PTY_DETACH_RETENTION_MS)) {
    throw new PtyTransportError("expired-attachment", generation);
  }
  if (!options.validateAttachment) throw new PtyTransportError("invalid-attachment", generation);
  const valid = await awaitWithAbort(
    Promise.resolve(options.validateAttachment(input, signal)),
    signal,
    generation,
  );
  if (valid !== true) throw new PtyTransportError("invalid-attachment", generation);
}

export function encodeResize(cols: number, rows: number): Uint8Array {
  if (!Number.isInteger(cols) || !Number.isInteger(rows)) throw new PtyTransportError("invalid-input");
  const effectiveCols = Math.min(PTY_MAX_COLS, Math.max(PTY_MIN_COLS, cols));
  const effectiveRows = Math.min(PTY_MAX_ROWS, Math.max(PTY_MIN_ROWS, rows));
  const dimensions = new TextEncoder().encode(`${effectiveCols};${effectiveRows}`);
  const frame = new Uint8Array(RESIZE_PREFIX.byteLength + dimensions.byteLength + 1);
  frame.set(RESIZE_PREFIX, 0);
  frame.set(dimensions, RESIZE_PREFIX.byteLength);
  frame[frame.byteLength - 1] = RESIZE_SUFFIX;
  return frame;
}

async function toBytes(data: unknown): Promise<Uint8Array> {
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data.slice(0));
  }
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(
      data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength),
    );
  }
  if (typeof Blob !== "undefined" && data instanceof Blob) {
    return new Uint8Array(await data.arrayBuffer());
  }
  throw new PtyTransportError("invalid-frame");
}

function sendBytes(context: SocketContext, bytes: Uint8Array): void {
  if (!isSocketOpen(context.socket) || context.closed) throw new PtyTransportError("not-attached", context.generation);
  try {
    context.socket.send(bytes);
  } catch {
    throw new PtyTransportError("send-failed", context.generation);
  }
}

function requireAttached(context: SocketContext | undefined, generation: number): SocketContext {
  if (!context || context.closed) throw new PtyTransportError("not-attached", generation);
  return context;
}

function isSocketOpen(socket: PtyWebSocket): boolean {
  return socket.readyState === undefined || socket.readyState === 1;
}

/**
 * Detached timestamps are local expiry evidence, not current-session identity.
 * They must not let callers bypass a supersession block by changing metadata.
 */
function sameConnectionInput(left: PtyConnectionInput, right: PtyConnectionInput): boolean {
  return (
    left.sessionId === right.sessionId &&
    left.attach === right.attach &&
    left.processIdentity === right.processIdentity
  );
}

function modeFor(input: PtyConnectionInput | undefined): PtyMode {
  return input?.attach ? "attach" : "legacy";
}

function detachedStatus(input: PtyConnectionInput | undefined): PtyStatus {
  return modeFor(input) === "attach" ? "detached" : "exited";
}

/**
 * The shared HTTP boundary validates `{ ticket, ttl_seconds: 30 }` and returns
 * only `{ ticket }`. Keep this adapter parser limited to that already-reviewed
 * normalized value; it must not become a second raw-response parser.
 */
function parseTicketResponse(response: unknown): string {
  try {
    if (
      typeof response !== "object" ||
      response === null ||
      Array.isArray(response)
    ) {
      throw new PtyTransportError("invalid-ticket");
    }
    const record = response as Record<string, unknown>;
    const keys = Object.keys(record);
    if (keys.length !== 1 || keys[0] !== "ticket") {
      throw new PtyTransportError("invalid-ticket");
    }
    const ticket = record.ticket;
    validateTicket(ticket, 0);
    return ticket;
  } catch (error) {
    if (error instanceof PtyTransportError) throw error;
    throw new PtyTransportError("invalid-ticket");
  }
}

function validateTicket(ticket: unknown, generation: number): asserts ticket is string {
  if (
    typeof ticket !== "string" ||
    ticket.length === 0 ||
    ticket.length > MAX_WS_TICKET_LENGTH ||
    !/^[A-Za-z0-9_-]+$/u.test(ticket)
  ) {
    throw new PtyTransportError("invalid-ticket", generation);
  }
}

function isSafeOpaque(value: unknown, maxLength: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength && SAFE_OPAQUE_PATTERN.test(value);
}

function classifyClose(code: number | undefined): {
  readonly code?: number;
  readonly classification: PtyCloseClassification;
} {
  const classification: PtyCloseClassification =
    code === 4401
      ? "authentication-rejected"
      : code === 4403
        ? "host-or-origin-rejected"
        : code === 4404
          ? "embedded-chat-disabled"
          : code === 4408
            ? "peer-rejected"
            : code === 4409
              ? "attachment-superseded"
              : code === 4410
                ? "pty-process-exited"
                : code === 1011
                  ? "backend-failure"
                  : code === 1000 || code === 1006 || code === undefined
                    ? "connection-closed"
                    : "unsupported";
  return { ...(code !== undefined ? { code } : {}), classification };
}

function statusForClose(
  mode: PtyMode,
  observation: { readonly classification: PtyCloseClassification },
  opened: boolean,
): PtyStatus {
  // A close before the handshake completes is a failed connection, not a
  // retained detach. Retention only starts after the current PTY was proven
  // attached, so a pre-open adapter error cannot extend its expiry window.
  if (!opened) return "failed";
  if (observation.classification === "pty-process-exited") return "exited";
  if (observation.classification === "attachment-superseded") return "detached";
  if (observation.classification === "connection-closed") {
    return mode === "attach" ? "detached" : "exited";
  }
  return "failed";
}

function isPermanentReattachError(code: PtyErrorCode): boolean {
  return (
    code === "authentication-required" ||
    code === "attachment-superseded" ||
    code === "expired-attachment" ||
    code === "invalid-attachment" ||
    code === "closed"
  );
}

function retryBlockForClose(
  classification: PtyCloseClassification,
): PtyErrorCode | undefined {
  if (classification === "authentication-rejected") {
    // A server 4401 is recoverable only through an explicit same-identity
    // connect after authentication. Do not let reconnect() mint a ticket while
    // the transport is still behind the auth boundary.
    return "authentication-required";
  }
  if (classification === "attachment-superseded") {
    return "attachment-superseded";
  }
  if (classification === "pty-process-exited") return "closed";
  if (
    classification === "host-or-origin-rejected" ||
    classification === "embedded-chat-disabled" ||
    classification === "peer-rejected" ||
    classification === "unsupported"
  ) {
    return "connection-failed";
  }
  return undefined;
}

function sanitizeError(error: unknown, signal: AbortSignal, generation: number): PtyTransportError {
  if (signal.aborted || isAbortLike(error)) return new PtyTransportError("aborted", generation);
  if (error instanceof PtyTransportError) return error;
  return new PtyTransportError("connection-failed", generation);
}

function safeClose(socket: PtyWebSocket): void {
  try {
    socket.close(1000, "client-detach");
  } catch {
    // Adapter errors are intentionally discarded; terminal bytes, tickets, and
    // attach handles must never cross into retained diagnostics.
  }
}

function throwIfAborted(signal: AbortSignal, generation: number): void {
  if (signal.aborted) throw new PtyTransportError("aborted", generation);
}

function awaitWithAbort<T>(
  promise: Promise<T>,
  signal: AbortSignal,
  generation: number,
  onLateValue?: (value: T) => void,
): Promise<T> {
  if (signal.aborted) {
    // The value promise may already own a socket even though this attempt was
    // cancelled before the abort listener could be installed. Keep late-value
    // cleanup attached so synchronous and delayed factories cannot leak it.
    promise.then(
      (value) => onLateValue?.(value),
      () => undefined,
    );
    return Promise.reject(new PtyTransportError("aborted", generation));
  }
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const cleanup = (): void => signal.removeEventListener("abort", onAbort);
    const onAbort = (): void => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new PtyTransportError("aborted", generation));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        if (settled) {
          onLateValue?.(value);
          return;
        }
        settled = true;
        cleanup();
        resolve(value);
      },
      (error: unknown) => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(error);
      },
    );
  });
}

function isAbortLike(error: unknown): boolean {
  if (typeof error !== "object" || error === null || !("name" in error)) return false;
  const name = (error as { readonly name?: unknown }).name;
  return name === "AbortError" || name === "CanceledError";
}
