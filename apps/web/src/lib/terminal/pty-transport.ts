export const PTY_WS_TICKET_PATH = "/api/auth/ws-ticket" as const;
export const PTY_WEBSOCKET_PATH = "/api/pty" as const;
export const PTY_WEBSOCKET_ORIGIN = "same-origin" as const;
export const PTY_REPLAY_CAPACITY_BYTES = 1024 * 1024;
export const PTY_DETACH_RETENTION_MS = 30 * 60 * 1000;
export const PTY_MIN_COLS = 1;
export const PTY_MAX_COLS = 2000;
export const PTY_MIN_ROWS = 1;
export const PTY_MAX_ROWS = 1000;

const MAX_TICKET_LENGTH = 512;
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
  detach(): void;
  close(): void;
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
  let currentGeneration = 0;
  let currentState: PtyConnectionState = {
    status: "closed",
    generation: 0,
    mode: "legacy",
    outputMayBeTruncated: false,
  };
  let currentInput: PtyConnectionInput | undefined;
  let activeContext: SocketContext | undefined;
  let activeAttempt: ConnectionAttempt | undefined;
  let detachedAtMs: number | undefined;
  let reattachBlocked: PtyErrorCode | undefined;
  let userClosed = false;

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
    observe(options.onEvent ? () => options.onEvent?.(event) : undefined);
    for (const listener of listeners) observe(() => listener(event));
  };

  const setState = (
    status: PtyStatus,
    generation: number,
    input = currentInput,
    observation?: { readonly code?: number; readonly classification?: PtyCloseClassification },
    truncated = currentState.outputMayBeTruncated,
  ): void => {
    const mode = modeFor(input);
    currentState = Object.freeze({
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
    });
    observe(
      options.onStateChange
        ? () => options.onStateChange?.(currentState)
        : undefined,
    );
    emit({ type: "state", state: currentState });
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

  const failContext = (context: SocketContext, error: PtyTransportError): void => {
    if (!isCurrent(context)) return;
    invalidateContext(context);
    safeClose(context.socket);
    context.rejectReady(error);
    setState("failed", context.generation, context.input, undefined, context.reattaching);
  };

  const attachContext = (
    socket: PtyWebSocket,
    generation: number,
    input: PtyConnectionInput,
    reattaching: boolean,
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
      if (!isCurrent(context)) return;
      context.opened = true;
      detachedAtMs = undefined;
      setState("attached", generation, input, undefined, reattaching);
      if (reattaching) {
        emit({
          type: "notice",
          generation,
          notice: "output-may-be-truncated",
          replayCapacityBytes: PTY_REPLAY_CAPACITY_BYTES,
        });
      }
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
      failContext(context, new PtyTransportError("connection-failed", generation));
    };
    socket.onclose = (event) => {
      if (!isCurrent(context)) return;
      const observation = classifyClose(event?.code);
      invalidateContext(context);
      context.rejectReady(new PtyTransportError("connection-failed", generation));
      if (context.mode === "attach" && context.opened) detachedAtMs = now();
      reattachBlocked = retryBlockForClose(observation.classification);
      const status = statusForClose(context.mode, observation);
      setState(status, generation, input, observation, reattaching);
    };
    return context;
  };

  const clearAttempt = (generation: number): void => {
    if (activeAttempt?.generation === generation) activeAttempt = undefined;
  };

  const start = (
    input: PtyConnectionInput,
    reattaching: boolean,
    signal?: AbortSignal,
  ): Promise<void> => {
    const normalized = validateInput(input);
    if (activeAttempt) {
      if (currentInput && sameConnectionInput(currentInput, normalized)) {
        return activeAttempt.promise;
      }
      // A current-session replacement cancels the old attempt before a new
      // ticket is minted. A connector that settles late is closed by the abort
      // guard and cannot install callbacks for the replacement generation.
      activeAttempt.controller.abort();
      activeAttempt = undefined;
    }
    const generation = ++currentGeneration;
    const controller = new AbortController();
    const unlinkAbort = linkAbort(signal, controller);
    currentInput = normalized;
    reattachBlocked = undefined;
    userClosed = false;

    if (activeContext) {
      const stale = activeContext;
      invalidateContext(stale);
      stale.rejectReady(new PtyTransportError("aborted", stale.generation));
      safeClose(stale.socket);
    }

    let attemptContext: SocketContext | undefined;
    const promise = (async (): Promise<void> => {
      try {
        throwIfAborted(controller.signal, generation);
        await validateAttachPreflight(normalized, reattaching, detachedAtMs, now(), options, controller.signal, generation);
        throwIfAborted(controller.signal, generation);
        setState("ticket_pending", generation, normalized, undefined, reattaching);
        let ticket = await awaitWithAbort(
          Promise.resolve(options.ticketProvider(controller.signal)),
          controller.signal,
          generation,
        );
        validateTicket(ticket, generation);
        setState("connecting", generation, normalized, undefined, reattaching);
        const upgrade = createUpgrade(ticket, normalized);
        const socket = await awaitWithAbort(
          Promise.resolve(options.createWebSocket(upgrade, controller.signal)),
          controller.signal,
          generation,
          safeClose,
        );
        ticket = "";
        throwIfAborted(controller.signal, generation);
        if (generation !== currentGeneration || userClosed) {
          safeClose(socket);
          throw new PtyTransportError("aborted", generation);
        }
        const context = attachContext(socket, generation, normalized, reattaching);
        attemptContext = context;
        activeContext = context;
        setState(reattaching ? "reattaching" : "starting", generation, normalized, undefined, reattaching);
        await awaitWithAbort(context.ready, controller.signal, generation);
      } catch (error) {
        const sanitized = sanitizeError(error, controller.signal, generation);
        if (attemptContext && isCurrent(attemptContext)) {
          invalidateContext(attemptContext);
          attemptContext.rejectReady(sanitized);
          safeClose(attemptContext.socket);
        }
        if (generation === currentGeneration && !userClosed && currentState.status !== "failed") {
          setState(sanitized.code === "aborted" ? detachedStatus(normalized) : "failed", generation, normalized, undefined, reattaching);
        }
        throw sanitized;
      } finally {
        unlinkAbort();
        clearAttempt(generation);
      }
    })();
    activeAttempt = { generation, controller, promise };
    return promise;
  };

  const stop = (closing: boolean): void => {
    userClosed = true;
    reattachBlocked = undefined;
    const generation = ++currentGeneration;
    activeAttempt?.controller.abort();
    activeAttempt = undefined;
    const input = currentInput;
    if (closing) setState("closing", generation, input);
    let detachedOpenedSocket = false;
    if (activeContext) {
      const context = activeContext;
      detachedOpenedSocket = context.mode === "attach" && context.opened;
      invalidateContext(context);
      context.rejectReady(new PtyTransportError("closed", context.generation));
      safeClose(context.socket);
    }
    if (detachedOpenedSocket) detachedAtMs = now();
    setState(detachedStatus(input), generation, input);
  };

  return {
    get state(): PtyConnectionState {
      return currentState;
    },
    connect(input, signal) {
      const normalized = validateInput(input);
      if (
        reattachBlocked &&
        currentInput &&
        sameConnectionInput(currentInput, normalized)
      ) {
        return Promise.reject(
          new PtyTransportError(reattachBlocked, currentGeneration),
        );
      }
      return start(normalized, false, signal);
    },
    reconnect(signal) {
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
    detach() {
      stop(false);
    },
    close() {
      stop(true);
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

function sameConnectionInput(left: PtyConnectionInput, right: PtyConnectionInput): boolean {
  return (
    left.sessionId === right.sessionId &&
    left.attach === right.attach &&
    left.processIdentity === right.processIdentity &&
    left.detachedAtMs === right.detachedAtMs
  );
}

function modeFor(input: PtyConnectionInput | undefined): PtyMode {
  return input?.attach ? "attach" : "legacy";
}

function detachedStatus(input: PtyConnectionInput | undefined): PtyStatus {
  return modeFor(input) === "attach" ? "detached" : "exited";
}

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
    ticket.length > MAX_TICKET_LENGTH ||
    !SAFE_OPAQUE_PATTERN.test(ticket)
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
): PtyStatus {
  if (observation.classification === "pty-process-exited") return "exited";
  if (observation.classification === "attachment-superseded") return "detached";
  if (observation.classification === "connection-closed") {
    return mode === "attach" ? "detached" : "exited";
  }
  return "failed";
}

function retryBlockForClose(
  classification: PtyCloseClassification,
): PtyErrorCode | undefined {
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

function linkAbort(signal: AbortSignal | undefined, controller: AbortController): () => void {
  if (!signal) return () => undefined;
  const onAbort = (): void => controller.abort();
  if (signal.aborted) {
    controller.abort();
    return () => undefined;
  }
  signal.addEventListener("abort", onAbort, { once: true });
  return () => signal.removeEventListener("abort", onAbort);
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
  if (signal.aborted) return Promise.reject(new PtyTransportError("aborted", generation));
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
