export const JSON_RPC_VERSION = '2.0' as const;
export const JSON_RPC_PROTOCOL = 'hermternal.chat.v1' as const;
export const JSON_RPC_HANDSHAKE_METHOD = 'chat.handshake' as const;
export const JSON_RPC_PROMPT_METHOD = 'chat.prompt' as const;
export const JSON_RPC_CANCEL_METHOD = 'chat.cancel' as const;
export const JSON_RPC_APPROVAL_METHOD = 'chat.approval.respond' as const;
export const JSON_RPC_CLARIFICATION_METHOD = 'chat.clarification.respond' as const;

export const MAX_JSON_RPC_FRAME_BYTES = 64 * 1024;
export const MAX_JSON_RPC_PROMPT_LENGTH = 16 * 1024;
export const MAX_JSON_RPC_TEXT_LENGTH = 8 * 1024;
export const MAX_JSON_RPC_ID_LENGTH = 128;
export const MAX_JSON_RPC_SEQUENCE = 1_000_000;
export const MAX_JSON_RPC_ACTIVE_REQUESTS = 32;
export const MAX_JSON_RPC_PENDING_CONTROLS = 32;

const MIN_FRAME_BYTES = 256;
const MAX_JSON_DEPTH = 16;
const MAX_JSON_NODES = 512;
const MAX_JSON_ARRAY_LENGTH = 64;
const MAX_JSON_OBJECT_KEYS = 32;
const MAX_TICKET_LENGTH = 512;
const MAX_TOOL_NAME_LENGTH = 128;
const MAX_TOOL_CALL_ID_LENGTH = 128;
const MAX_APPROVAL_ID_LENGTH = 128;
const MAX_CLARIFICATION_ID_LENGTH = 128;
const MAX_HANDSHAKE_EVENTS = 5;
const REQUEST_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/u;
const TICKET_PATTERN = /^[A-Za-z0-9_-]+$/u;

const HANDSHAKE_EVENTS = [
  'stream',
  'tool',
  'approval',
  'clarification',
  'completion'
] as const;

type HandshakeEventName = (typeof HANDSHAKE_EVENTS)[number];

type JsonPrimitive = null | boolean | number | string;
export type BoundedJsonValue = JsonPrimitive | BoundedJsonValue[] | { [key: string]: BoundedJsonValue };

export type JsonRpcFrameData = string | ArrayBuffer | Uint8Array;

export interface JsonRpcMessageEvent {
  readonly data: unknown;
}

export interface JsonRpcCloseEvent {
  readonly code?: number;
  readonly reason?: string;
}

/**
 * Small adapter seam for browser WebSocket implementations and deterministic
 * fakes. The transport never creates a URL, stores a ticket, or logs frames;
 * the injected factory owns the ephemeral upgrade operation.
 */
export interface JsonRpcWebSocket {
  onopen: ((event?: unknown) => void) | null;
  onmessage: ((event: JsonRpcMessageEvent) => void) | null;
  onerror: ((event?: unknown) => void) | null;
  onclose: ((event?: JsonRpcCloseEvent) => void) | null;
  send(data: string): void;
  close(code?: number, reason?: string): void;
  readonly readyState?: number;
}

export type FreshChatTicketProvider = (signal: AbortSignal) => Promise<string>;

export type JsonRpcWebSocketFactory = (
  ticket: string,
  signal: AbortSignal
) => JsonRpcWebSocket | Promise<JsonRpcWebSocket>;

export type JsonRpcChatErrorCode =
  | 'aborted'
  | 'cancelled'
  | 'closed'
  | 'connection-failed'
  | 'frame-too-large'
  | 'handshake-failed'
  | 'invalid-input'
  | 'invalid-options'
  | 'invalid-ticket'
  | 'malformed-frame'
  | 'not-connected'
  | 'protocol-violation'
  | 'server-rejected'
  | 'uncertain-delivery';

const ERROR_MESSAGES: Record<JsonRpcChatErrorCode, string> = {
  aborted: 'The chat connection attempt was cancelled.',
  cancelled: 'The chat request was cancelled.',
  closed: 'The chat connection was closed.',
  'connection-failed': 'The chat WebSocket connection failed.',
  'frame-too-large': 'The chat WebSocket frame exceeded the bounded limit.',
  'handshake-failed': 'The chat WebSocket handshake was rejected.',
  'invalid-input': 'The chat request input was outside the bounded contract.',
  'invalid-options': 'The chat transport options were outside the bounded contract.',
  'invalid-ticket': 'The chat WebSocket ticket was invalid.',
  'malformed-frame': 'The chat WebSocket frame was not valid bounded JSON.',
  'not-connected': 'The chat WebSocket is not connected.',
  'protocol-violation': 'The chat WebSocket violated the JSON-RPC contract.',
  'server-rejected': 'The chat server rejected the request.',
  'uncertain-delivery': 'The chat request delivery is uncertain and was not replayed.'
};

export class JsonRpcChatError extends Error {
  readonly code: JsonRpcChatErrorCode;
  readonly generation?: number;

  constructor(code: JsonRpcChatErrorCode, generation?: number) {
    super(ERROR_MESSAGES[code]);
    this.name = code === 'aborted' || code === 'cancelled' ? 'AbortError' : 'JsonRpcChatError';
    this.code = code;
    this.generation = generation;
  }
}

export type JsonRpcConnectionStatus =
  | 'idle'
  | 'connecting'
  | 'connected'
  | 'disconnected'
  | 'failed'
  | 'closed';

export interface JsonRpcConnectionState {
  readonly status: JsonRpcConnectionStatus;
  readonly generation: number;
}

export type JsonRpcDeliveryStatus =
  | 'pending'
  | 'accepted'
  | 'streaming'
  | 'completed'
  | 'cancelled'
  | 'failed'
  | 'uncertain-delivery';

export interface JsonRpcChatRequestState {
  readonly id: string;
  readonly status: JsonRpcDeliveryStatus;
}

export interface JsonRpcStreamEvent {
  readonly type: 'stream';
  readonly requestId: string;
  readonly sequence: number;
  readonly delta: string;
}

export type JsonRpcToolPhase = 'started' | 'completed' | 'failed';

export interface JsonRpcToolEvent {
  readonly type: 'tool';
  readonly requestId: string;
  readonly sequence: number;
  readonly toolCallId: string;
  readonly name: string;
  readonly phase: JsonRpcToolPhase;
}

export type JsonRpcApprovalState = 'requested' | 'resolved';

export interface JsonRpcApprovalEvent {
  readonly type: 'approval';
  readonly requestId: string;
  readonly sequence: number;
  readonly approvalId: string;
  readonly title: string;
  readonly state: JsonRpcApprovalState;
  readonly approved: boolean | null;
}

export interface JsonRpcClarificationEvent {
  readonly type: 'clarification';
  readonly requestId: string;
  readonly sequence: number;
  readonly clarificationId: string;
  readonly question: string;
}

export type JsonRpcCompletionOutcome = 'success' | 'cancelled' | 'failed';

export interface JsonRpcCompletionEvent {
  readonly type: 'completion';
  readonly requestId: string;
  readonly sequence: number;
  readonly outcome: JsonRpcCompletionOutcome;
}

export type JsonRpcChatEvent =
  | JsonRpcStreamEvent
  | JsonRpcToolEvent
  | JsonRpcApprovalEvent
  | JsonRpcClarificationEvent
  | JsonRpcCompletionEvent;

export type JsonRpcCloseReason =
  | 'client-close'
  | 'reconnect'
  | 'socket-close'
  | 'socket-error'
  | 'protocol-error'
  | 'handshake-error';

export interface JsonRpcChatRequest {
  readonly id: string;
  readonly completion: Promise<JsonRpcCompletionEvent>;
  readonly state: JsonRpcChatRequestState;
  abort(): void;
}

export interface JsonRpcChatOptions {
  readonly ticketProvider: FreshChatTicketProvider;
  readonly createWebSocket: JsonRpcWebSocketFactory;
  readonly requestIdFactory?: () => string;
  readonly maxFrameBytes?: number;
  readonly onEvent?: (event: JsonRpcChatEvent) => void;
  readonly onStateChange?: (state: JsonRpcConnectionState) => void;
  readonly onOpen?: () => void;
  readonly onClose?: (reason: JsonRpcCloseReason) => void;
  readonly onReconnect?: () => void;
  readonly onAbort?: (requestId: string) => void;
  readonly onUncertainDelivery?: (requestId: string) => void;
}

export interface JsonRpcChatTransport {
  readonly state: JsonRpcConnectionState;
  connect(signal?: AbortSignal): Promise<void>;
  reconnect(signal?: AbortSignal): Promise<void>;
  close(): void;
  sendPrompt(prompt: string, options?: { readonly signal?: AbortSignal }): JsonRpcChatRequest;
  respondToApproval(
    requestId: string,
    approvalId: string,
    approved: boolean,
    signal?: AbortSignal
  ): Promise<void>;
  answerClarification(
    requestId: string,
    clarificationId: string,
    answer: string,
    signal?: AbortSignal
  ): Promise<void>;
  abort(requestId: string): void;
  subscribe(listener: (event: JsonRpcChatEvent) => void): () => void;
}

interface JsonRpcRequestMessage {
  readonly kind: 'request';
  readonly id: string;
  readonly method: string;
  readonly params: BoundedJsonValue;
}

interface JsonRpcResponseMessage {
  readonly kind: 'response';
  readonly id: string;
  readonly result?: BoundedJsonValue;
  readonly error?: JsonRpcErrorShape;
}

interface JsonRpcNotificationMessage {
  readonly kind: 'notification';
  readonly method: string;
  readonly params: BoundedJsonValue;
}

type ParsedWireMessage =
  | JsonRpcResponseMessage
  | JsonRpcNotificationMessage
  | JsonRpcRequestMessage;

interface JsonRpcErrorShape {
  readonly code: number;
}

interface OperationRecord {
  readonly id: string;
  status: JsonRpcDeliveryStatus;
  nextSequence: number;
  readonly resolveCompletion: (event: JsonRpcCompletionEvent) => void;
  readonly rejectCompletion: (error: JsonRpcChatError) => void;
  readonly signal?: AbortSignal;
  removeAbortListener?: () => void;
}

interface ControlRecord {
  readonly id: string;
  readonly resolve: () => void;
  readonly reject: (error: JsonRpcChatError) => void;
  removeAbortListener?: () => void;
}

interface SocketContext {
  readonly generation: number;
  readonly socket: JsonRpcWebSocket;
  readonly handshakeId: string;
  readonly handshakePromise: Promise<void>;
  handshakeComplete: boolean;
  opened: boolean;
  closed: boolean;
  handshakeSettled: boolean;
  handshakeResolve: () => void;
  handshakeReject: (error: JsonRpcChatError) => void;
  failure?: JsonRpcChatError;
  failureReason?: JsonRpcCloseReason;
}

interface ConnectionAttempt {
  readonly generation: number;
  readonly controller: AbortController;
  readonly promise: Promise<void>;
}

/**
 * Create the browser-side JSON-RPC chat boundary. It owns no ticket, prompt,
 * credential, or transcript cache. Reconnect is always explicit and gets a
 * fresh ticket; in-flight operations become uncertain instead of replaying.
 */
export function createJsonRpcChatTransport(options: JsonRpcChatOptions): JsonRpcChatTransport {
  const maxFrameBytes = normalizeFrameLimit(options.maxFrameBytes);
  const listeners = new Set<(event: JsonRpcChatEvent) => void>();
  const activeRequests = new Map<string, OperationRecord>();
  const pendingControls = new Map<string, ControlRecord>();
  const ignoredResponseIds = new Set<string>();
  let nextGeneratedId = 0;
  let currentGeneration = 0;
  let currentState: JsonRpcConnectionState = { status: 'idle', generation: 0 };
  let activeContext: SocketContext | undefined;
  let activeAttempt: ConnectionAttempt | undefined;

  const safeCall = <T extends unknown[]>(callback: ((...args: T) => void) | undefined, ...args: T): void => {
    if (!callback) {
      return;
    }
    try {
      callback(...args);
    } catch {
      // Consumer hooks are observational. A hook cannot change delivery state
      // or cause the transport to retain an untrusted frame or error value.
    }
  };

  const setState = (status: JsonRpcConnectionStatus, generation = currentGeneration): void => {
    if (currentState.status === status && currentState.generation === generation) {
      return;
    }
    currentState = { status, generation };
    safeCall(options.onStateChange, currentState);
  };

  const emitEvent = (event: JsonRpcChatEvent): void => {
    safeCall(options.onEvent, event);
    for (const listener of [...listeners]) {
      safeCall(listener, event);
    }
  };

  const allocateId = (): string => {
    let id: string;
    try {
      id = options.requestIdFactory?.() ?? `rpc-${++nextGeneratedId}`;
    } catch {
      throw new JsonRpcChatError('invalid-options', currentGeneration);
    }

    if (
      !isSafeId(id) ||
      isIdReserved(id, activeContext, activeRequests, pendingControls) ||
      ignoredResponseIds.has(id)
    ) {
      throw new JsonRpcChatError('invalid-options', currentGeneration);
    }
    return id;
  };

  const sendFrame = (context: SocketContext, payload: Record<string, unknown>): void => {
    const frame = JSON.stringify(payload);
    if (byteLength(frame) > maxFrameBytes) {
      throw new JsonRpcChatError('frame-too-large', context.generation);
    }
    try {
      context.socket.send(frame);
    } catch {
      throw new JsonRpcChatError('connection-failed', context.generation);
    }
  };

  const assertOutboundFrame = (payload: Record<string, unknown>, generation: number): void => {
    if (byteLength(JSON.stringify(payload)) > maxFrameBytes) {
      throw new JsonRpcChatError('frame-too-large', generation);
    }
  };

  const markUncertain = (record: OperationRecord): void => {
    if (isTerminalStatus(record.status)) {
      return;
    }
    record.status = 'uncertain-delivery';
    activeRequests.delete(record.id);
    record.removeAbortListener?.();
    record.rejectCompletion(new JsonRpcChatError('uncertain-delivery', currentGeneration));
    safeCall(options.onUncertainDelivery, record.id);
  };

  const settleControl = (record: ControlRecord, error?: JsonRpcChatError): void => {
    pendingControls.delete(record.id);
    record.removeAbortListener?.();
    if (error) {
      record.reject(error);
    } else {
      record.resolve();
    }
  };

  const disconnectContext = (
    context: SocketContext,
    reason: JsonRpcCloseReason,
    error: JsonRpcChatError,
    updateState: boolean
  ): void => {
    if (context.closed) {
      return;
    }
    context.closed = true;
    if (!context.handshakeSettled) {
      context.handshakeSettled = true;
      context.handshakeReject(error);
    }

    for (const record of [...activeRequests.values()]) {
      markUncertain(record);
    }
    for (const record of [...pendingControls.values()]) {
      settleControl(record, new JsonRpcChatError('uncertain-delivery', currentGeneration));
    }

    context.socket.onopen = null;
    context.socket.onmessage = null;
    context.socket.onerror = null;
    context.socket.onclose = null;

    if (activeContext === context) {
      activeContext = undefined;
    }
    if (updateState && context.generation === currentGeneration) {
      const failed = reason === 'protocol-error' || reason === 'socket-error' || reason === 'handshake-error';
      setState(reason === 'client-close' ? 'closed' : failed ? 'failed' : 'disconnected', context.generation);
    }
    safeCall(options.onClose, reason);
  };

  const failContext = (context: SocketContext, code: JsonRpcChatErrorCode, reason: JsonRpcCloseReason): void => {
    if (context.closed) {
      return;
    }
    context.failure = new JsonRpcChatError(code, context.generation);
    context.failureReason = reason;
    try {
      context.socket.close(1002, 'protocol-error');
    } catch {
      // The close path below still releases local state when a fake or browser
      // socket refuses a close call.
    }
    disconnectContext(context, reason, context.failure, context.generation === currentGeneration);
  };

  const closeContext = (context: SocketContext, reason: JsonRpcCloseReason, updateState: boolean): void => {
    if (context.closed) {
      return;
    }
    try {
      context.socket.close(1000, reason === 'reconnect' ? 'replaced' : 'closed');
    } catch {
      // Treat a throwing close as closed locally; no socket error is retained.
    }
    disconnectContext(
      context,
      reason,
      new JsonRpcChatError(reason === 'client-close' ? 'closed' : 'connection-failed', context.generation),
      updateState
    );
  };

  const rememberIgnoredResponse = (requestId: string): void => {
    if (ignoredResponseIds.size >= MAX_JSON_RPC_ACTIVE_REQUESTS * 2) {
      const oldest = ignoredResponseIds.values().next().value;
      if (typeof oldest === 'string') {
        ignoredResponseIds.delete(oldest);
      }
    }
    ignoredResponseIds.add(requestId);
  };

  const handleAbort = (record: OperationRecord): void => {
    if (isTerminalStatus(record.status)) {
      return;
    }
    record.status = 'cancelled';
    activeRequests.delete(record.id);
    rememberIgnoredResponse(record.id);
    record.removeAbortListener?.();
    record.rejectCompletion(new JsonRpcChatError('cancelled', currentGeneration));
    safeCall(options.onAbort, record.id);

    const context = activeContext;
    if (context?.handshakeComplete && !context.closed) {
      try {
        // Cancellation is a notification by design. The local state is already
        // safe, so a lost cancel frame never causes a prompt replay or retry.
        sendFrame(context, {
          jsonrpc: JSON_RPC_VERSION,
          method: JSON_RPC_CANCEL_METHOD,
          params: { request_id: record.id }
        });
      } catch {
        // Cancellation remains local even if the socket has just disappeared.
      }
    }
  };

  const parseAndHandleFrame = (context: SocketContext, data: unknown): void => {
    if (!isCurrentContext(context)) {
      return;
    }

    let message: ParsedWireMessage;
    try {
      const value = parseBoundedJsonFrame(data, maxFrameBytes);
      message = parseWireMessage(value);
    } catch (error) {
      const code = error instanceof JsonRpcChatError ? error.code : 'malformed-frame';
      failContext(context, code, code === 'handshake-failed' ? 'handshake-error' : 'protocol-error');
      return;
    }

    if (message.kind === 'request') {
      failContext(context, 'protocol-violation', 'protocol-error');
      return;
    }

    if (message.kind === 'response') {
      handleResponse(context, message);
      return;
    }

    handleNotification(context, message);
  };

  const handleResponse = (context: SocketContext, message: JsonRpcResponseMessage): void => {
    if (!context.handshakeComplete) {
      if (message.id !== context.handshakeId) {
        failContext(context, 'handshake-failed', 'handshake-error');
        return;
      }
      if (message.error || !message.result || !isAcceptedResult(message.result)) {
        failContext(context, 'handshake-failed', 'handshake-error');
        return;
      }
      context.handshakeComplete = true;
      if (!context.handshakeSettled) {
        context.handshakeSettled = true;
        context.handshakeResolve();
      }
      return;
    }

    if (message.id === context.handshakeId) {
      failContext(context, 'protocol-violation', 'protocol-error');
      return;
    }
    if (ignoredResponseIds.delete(message.id)) {
      return;
    }

    const operation = activeRequests.get(message.id);
    if (operation) {
      if (operation.status !== 'pending') {
        failContext(context, 'protocol-violation', 'protocol-error');
        return;
      }
      if (message.error || !message.result || !isAcceptedResult(message.result)) {
        operation.status = 'failed';
        activeRequests.delete(operation.id);
        operation.removeAbortListener?.();
        operation.rejectCompletion(new JsonRpcChatError('server-rejected', context.generation));
        return;
      }
      operation.status = 'accepted';
      return;
    }

    const control = pendingControls.get(message.id);
    if (control) {
      if (message.error || !message.result || !isAcceptedResult(message.result)) {
        settleControl(control, new JsonRpcChatError('server-rejected', context.generation));
      } else {
        settleControl(control);
      }
      return;
    }

    failContext(context, 'protocol-violation', 'protocol-error');
  };

  const handleNotification = (context: SocketContext, message: JsonRpcNotificationMessage): void => {
    if (!context.handshakeComplete) {
      failContext(context, 'handshake-failed', 'handshake-error');
      return;
    }

    let event: JsonRpcChatEvent;
    try {
      event = parseChatEvent(message.method, message.params);
    } catch {
      failContext(context, 'protocol-violation', 'protocol-error');
      return;
    }

    const operation = activeRequests.get(event.requestId);
    if (!operation || operation.status === 'pending') {
      failContext(context, 'protocol-violation', 'protocol-error');
      return;
    }
    if (event.sequence !== operation.nextSequence) {
      failContext(context, 'protocol-violation', 'protocol-error');
      return;
    }
    operation.nextSequence += 1;

    if (event.type === 'completion') {
      finishOperation(operation, event);
      return;
    }

    operation.status = 'streaming';
    emitEvent(event);
  };

  const finishOperation = (operation: OperationRecord, event: JsonRpcCompletionEvent): void => {
    activeRequests.delete(operation.id);
    operation.removeAbortListener?.();
    if (event.outcome === 'success') {
      operation.status = 'completed';
      emitEvent(event);
      operation.resolveCompletion(event);
      return;
    }

    operation.status = event.outcome === 'cancelled' ? 'cancelled' : 'failed';
    emitEvent(event);
    operation.rejectCompletion(
      new JsonRpcChatError(event.outcome === 'cancelled' ? 'cancelled' : 'server-rejected', currentGeneration)
    );
  };

  const attachContext = (socket: JsonRpcWebSocket, generation: number): SocketContext => {
    const handshakeId = allocateId();
    let resolveHandshake!: () => void;
    let rejectHandshake!: (error: JsonRpcChatError) => void;
    const handshakePromise = new Promise<void>((resolve, reject) => {
      resolveHandshake = resolve;
      rejectHandshake = reject;
    });
    const context: SocketContext = {
      generation,
      socket,
      handshakeId,
      handshakePromise,
      handshakeComplete: false,
      opened: false,
      closed: false,
      handshakeSettled: false,
      handshakeResolve: resolveHandshake,
      handshakeReject: rejectHandshake
    };

    socket.onopen = () => {
      if (!isCurrentContext(context) || context.opened) {
        return;
      }
      context.opened = true;
      try {
        sendFrame(context, {
          jsonrpc: JSON_RPC_VERSION,
          id: handshakeId,
          method: JSON_RPC_HANDSHAKE_METHOD,
          params: {
            protocol: JSON_RPC_PROTOCOL,
            events: [...HANDSHAKE_EVENTS]
          }
        });
      } catch (error) {
        const code = error instanceof JsonRpcChatError ? error.code : 'connection-failed';
        failContext(context, code, 'handshake-error');
      }
    };

    socket.onmessage = (event) => parseAndHandleFrame(context, event.data);
    socket.onerror = () => {
      if (isCurrentContext(context)) {
        failContext(context, 'connection-failed', 'socket-error');
      }
    };
    socket.onclose = () => {
      if (!context.closed && isCurrentContext(context)) {
        disconnectContext(
          context,
          context.failureReason ?? (context.handshakeComplete ? 'socket-close' : 'handshake-error'),
          context.failure ?? new JsonRpcChatError('connection-failed', context.generation),
          true
        );
      }
    };

    activeContext = context;
    if (socket.readyState === 1) {
      queueMicrotask(() => socket.onopen?.());
    }

    return context;
  };

  const startConnection = (signal: AbortSignal | undefined, reconnecting: boolean): Promise<void> => {
    if (activeAttempt) {
      return activeAttempt.promise;
    }

    currentGeneration += 1;
    const generation = currentGeneration;
    const controller = new AbortController();
    const unlinkAbort = linkAbort(signal, controller);
    setState('connecting', generation);
    if (reconnecting) {
      safeCall(options.onReconnect);
    }

    let context: (SocketContext & { handshakePromise: Promise<void> }) | undefined;
    const promise = (async (): Promise<void> => {
      try {
        throwIfAborted(controller.signal);
        let ticket = await awaitWithAbort(
          Promise.resolve(options.ticketProvider(controller.signal)),
          controller.signal
        );
        validateTicket(ticket);
        const socket = await awaitWithAbort(
          Promise.resolve(options.createWebSocket(ticket, controller.signal)),
          controller.signal,
          safeClose
        );
        ticket = '';
        throwIfAborted(controller.signal);
        if (generation !== currentGeneration) {
          throw new JsonRpcChatError('connection-failed', generation);
        }
        context = attachContext(socket, generation);
        await context.handshakePromise;
        throwIfAborted(controller.signal);
        if (generation !== currentGeneration) {
          throw new JsonRpcChatError('connection-failed', generation);
        }
        if (context.closed || !context.handshakeComplete) {
          throw new JsonRpcChatError('handshake-failed', generation);
        }
        setState('connected', generation);
        safeCall(options.onOpen);
      } catch (error) {
        const sanitized = sanitizeConnectionError(error, controller.signal, generation);
        if (context && !context.closed) {
          disconnectContext(context, 'handshake-error', sanitized, generation === currentGeneration);
        }
        if (generation === currentGeneration && sanitized.code !== 'aborted') {
          setState(sanitized.code === 'handshake-failed' ? 'failed' : 'disconnected', generation);
        }
        throw sanitized;
      } finally {
        unlinkAbort();
        const attempt = activeAttempt as ConnectionAttempt | undefined;
        if (attempt && attempt.generation === generation) {
          activeAttempt = undefined;
        }
      }
    })();

    activeAttempt = { generation, controller, promise };
    return promise;
  };

  const connect = (signal?: AbortSignal): Promise<void> => {
    if (currentState.status === 'connected' && activeContext?.handshakeComplete) {
      return Promise.resolve();
    }
    return startConnection(signal, false);
  };

  const reconnect = (signal?: AbortSignal): Promise<void> => {
    const previousAttempt = activeAttempt;
    const previousContext = activeContext;
    if (previousAttempt) {
      previousAttempt.controller.abort();
      void previousAttempt.promise.catch(() => undefined);
      activeAttempt = undefined;
    }
    if (previousContext) {
      closeContext(previousContext, 'reconnect', false);
    }
    return startConnection(signal, true);
  };

  const close = (): void => {
    const previousAttempt = activeAttempt;
    if (previousAttempt) {
      previousAttempt.controller.abort();
      void previousAttempt.promise.catch(() => undefined);
      activeAttempt = undefined;
    }
    currentGeneration += 1;
    const previousContext = activeContext;
    if (previousContext) {
      closeContext(previousContext, 'client-close', false);
    } else {
      for (const record of [...activeRequests.values()]) {
        markUncertain(record);
      }
      for (const record of [...pendingControls.values()]) {
        settleControl(record, new JsonRpcChatError('uncertain-delivery', currentGeneration));
      }
    }
    setState('closed', currentGeneration);
  };

  const sendPrompt = (prompt: string, requestOptions: { readonly signal?: AbortSignal } = {}): JsonRpcChatRequest => {
    const context = activeContext;
    if (!context?.handshakeComplete || currentState.status !== 'connected') {
      throw new JsonRpcChatError('not-connected', currentGeneration);
    }
    validatePrompt(prompt);
    if (requestOptions.signal?.aborted) {
      throw new JsonRpcChatError('cancelled', currentGeneration);
    }
    if (activeRequests.size >= MAX_JSON_RPC_ACTIVE_REQUESTS) {
      throw new JsonRpcChatError('invalid-options', currentGeneration);
    }

    const id = allocateId();
    const promptPayload = {
      jsonrpc: JSON_RPC_VERSION,
      id,
      method: JSON_RPC_PROMPT_METHOD,
      params: { prompt }
    };
    assertOutboundFrame(promptPayload, context.generation);
    let resolveCompletion!: (event: JsonRpcCompletionEvent) => void;
    let rejectCompletion!: (error: JsonRpcChatError) => void;
    const completion = new Promise<JsonRpcCompletionEvent>((resolve, reject) => {
      resolveCompletion = resolve;
      rejectCompletion = reject;
    });
    const record: OperationRecord = {
      id,
      status: 'pending',
      nextSequence: 1,
      resolveCompletion,
      rejectCompletion,
      signal: requestOptions.signal
    };
    activeRequests.set(id, record);

    if (requestOptions.signal) {
      const onAbort = (): void => handleAbort(record);
      requestOptions.signal.addEventListener('abort', onAbort, { once: true });
      record.removeAbortListener = () => requestOptions.signal?.removeEventListener('abort', onAbort);
    }

    try {
      sendFrame(context, promptPayload);
    } catch (error) {
      markUncertain(record);
      throw error instanceof JsonRpcChatError ? error : new JsonRpcChatError('uncertain-delivery', context.generation);
    }

    return {
      id,
      completion,
      get state(): JsonRpcChatRequestState {
        return { id: record.id, status: record.status };
      },
      abort: () => handleAbort(record)
    };
  };

  const sendControl = (
    method: typeof JSON_RPC_APPROVAL_METHOD | typeof JSON_RPC_CLARIFICATION_METHOD,
    params: Record<string, BoundedJsonValue>,
    signal?: AbortSignal
  ): Promise<void> => {
    const context = activeContext;
    if (!context?.handshakeComplete || currentState.status !== 'connected') {
      return Promise.reject(new JsonRpcChatError('not-connected', currentGeneration));
    }
    if (pendingControls.size >= MAX_JSON_RPC_PENDING_CONTROLS) {
      return Promise.reject(new JsonRpcChatError('invalid-options', currentGeneration));
    }
    if (signal?.aborted) {
      return Promise.reject(new JsonRpcChatError('aborted', currentGeneration));
    }

    let id: string;
    try {
      id = allocateId();
    } catch (error) {
      return Promise.reject(error instanceof JsonRpcChatError ? error : new JsonRpcChatError('invalid-options'));
    }

    const controlPayload = { jsonrpc: JSON_RPC_VERSION, id, method, params };
    try {
      assertOutboundFrame(controlPayload, context.generation);
    } catch (error) {
      return Promise.reject(error instanceof JsonRpcChatError ? error : new JsonRpcChatError('frame-too-large'));
    }

    let resolve!: () => void;
    let reject!: (error: JsonRpcChatError) => void;
    const promise = new Promise<void>((resolvePromise, rejectPromise) => {
      resolve = resolvePromise;
      reject = rejectPromise;
    });
    const record: ControlRecord = { id, resolve, reject };
    pendingControls.set(id, record);

    if (signal) {
      const onAbort = (): void => settleControl(record, new JsonRpcChatError('aborted', context.generation));
      signal.addEventListener('abort', onAbort, { once: true });
      record.removeAbortListener = () => signal.removeEventListener('abort', onAbort);
    }

    try {
      sendFrame(context, controlPayload);
    } catch {
      settleControl(record, new JsonRpcChatError('uncertain-delivery', context.generation));
    }
    return promise;
  };

  const respondToApproval = (
    requestId: string,
    approvalId: string,
    approved: boolean,
    signal?: AbortSignal
  ): Promise<void> => {
    validateOpaqueInput(requestId, MAX_JSON_RPC_ID_LENGTH);
    validateOpaqueInput(approvalId, MAX_APPROVAL_ID_LENGTH);
    if (typeof approved !== 'boolean') {
      throw new JsonRpcChatError('invalid-input', currentGeneration);
    }
    requireActiveRequest(requestId, activeRequests);
    return sendControl(
      JSON_RPC_APPROVAL_METHOD,
      { request_id: requestId, approval_id: approvalId, approved },
      signal
    );
  };

  const answerClarification = (
    requestId: string,
    clarificationId: string,
    answer: string,
    signal?: AbortSignal
  ): Promise<void> => {
    validateOpaqueInput(requestId, MAX_JSON_RPC_ID_LENGTH);
    validateOpaqueInput(clarificationId, MAX_CLARIFICATION_ID_LENGTH);
    validatePrompt(answer);
    requireActiveRequest(requestId, activeRequests);
    return sendControl(
      JSON_RPC_CLARIFICATION_METHOD,
      { request_id: requestId, clarification_id: clarificationId, answer },
      signal
    );
  };

  const abort = (requestId: string): void => {
    validateOpaqueInput(requestId, MAX_JSON_RPC_ID_LENGTH);
    const record = activeRequests.get(requestId);
    if (record) {
      handleAbort(record);
    }
  };

  const subscribe = (listener: (event: JsonRpcChatEvent) => void): (() => void) => {
    listeners.add(listener);
    return () => listeners.delete(listener);
  };

  return {
    get state(): JsonRpcConnectionState {
      return currentState;
    },
    connect,
    reconnect,
    close,
    sendPrompt,
    respondToApproval,
    answerClarification,
    abort,
    subscribe
  };

  function isCurrentContext(context: SocketContext): boolean {
    return context.generation === currentGeneration && activeContext === context && !context.closed;
  }
};

export function parseBoundedJsonFrame(data: unknown, maxFrameBytes = MAX_JSON_RPC_FRAME_BYTES): BoundedJsonValue {
  const limit = normalizeFrameLimit(maxFrameBytes);
  const text = decodeFrame(data, limit);
  try {
    return new BoundedJsonParser({
      maxDepth: MAX_JSON_DEPTH,
      maxNodes: MAX_JSON_NODES,
      maxArrayLength: MAX_JSON_ARRAY_LENGTH,
      maxObjectKeys: MAX_JSON_OBJECT_KEYS,
      maxStringLength: MAX_JSON_RPC_TEXT_LENGTH * 2
    }).parse(text);
  } catch {
    throw new JsonRpcChatError('malformed-frame');
  }
}

function parseWireMessage(value: BoundedJsonValue): ParsedWireMessage {
  const object = requireObject(value, ['jsonrpc', 'id', 'method', 'params', 'result', 'error']);
  if (object.jsonrpc !== JSON_RPC_VERSION) {
    throw new JsonRpcChatError('protocol-violation');
  }

  if (object.method !== undefined) {
    const notification = requireObject(value, ['jsonrpc', 'id', 'method', 'params'], ['jsonrpc', 'method', 'params']);
    const method = requireString(notification.method, MAX_JSON_RPC_TEXT_LENGTH);
    if (notification.id !== undefined) {
      return {
        kind: 'request',
        id: requireSafeId(notification.id),
        method,
        params: notification.params ?? null
      };
    }
    return {
      kind: 'notification',
      method,
      params: notification.params ?? null
    };
  }

  const response = requireObject(value, ['jsonrpc', 'id', 'result', 'error'], ['jsonrpc', 'id']);
  const hasResult = response.result !== undefined;
  const hasError = response.error !== undefined;
  if (hasResult === hasError) {
    throw new JsonRpcChatError('protocol-violation');
  }

  return {
    kind: 'response',
    id: requireSafeId(response.id),
    ...(hasResult ? { result: response.result } : { error: parseErrorShape(response.error) })
  };
}

function parseChatEvent(method: string, params: BoundedJsonValue): JsonRpcChatEvent {
  switch (method) {
    case 'chat.stream': {
      const object = requireObject(params, ['request_id', 'sequence', 'delta'], [
        'request_id',
        'sequence',
        'delta'
      ]);
      return {
        type: 'stream',
        requestId: requireSafeId(object.request_id),
        sequence: requireSequence(object.sequence),
        delta: requireText(object.delta, MAX_JSON_RPC_TEXT_LENGTH, true)
      };
    }
    case 'chat.tool': {
      const object = requireObject(params, ['request_id', 'sequence', 'tool_call_id', 'name', 'phase'], [
        'request_id',
        'sequence',
        'tool_call_id',
        'name',
        'phase'
      ]);
      const phase = requireString(object.phase, 16);
      if (phase !== 'started' && phase !== 'completed' && phase !== 'failed') {
        throw new JsonRpcChatError('protocol-violation');
      }
      return {
        type: 'tool',
        requestId: requireSafeId(object.request_id),
        sequence: requireSequence(object.sequence),
        toolCallId: requireOpaqueString(object.tool_call_id, MAX_TOOL_CALL_ID_LENGTH),
        name: requireText(object.name, MAX_TOOL_NAME_LENGTH),
        phase
      };
    }
    case 'chat.approval': {
      const object = requireObject(
        params,
        ['request_id', 'sequence', 'approval_id', 'title', 'state', 'approved'],
        ['request_id', 'sequence', 'approval_id', 'title', 'state', 'approved']
      );
      const state = requireString(object.state, 16);
      if (state !== 'requested' && state !== 'resolved') {
        throw new JsonRpcChatError('protocol-violation');
      }
      const approved = object.approved;
      if (approved !== null && typeof approved !== 'boolean') {
        throw new JsonRpcChatError('protocol-violation');
      }
      if (state === 'resolved' && approved === null) {
        throw new JsonRpcChatError('protocol-violation');
      }
      return {
        type: 'approval',
        requestId: requireSafeId(object.request_id),
        sequence: requireSequence(object.sequence),
        approvalId: requireOpaqueString(object.approval_id, MAX_APPROVAL_ID_LENGTH),
        title: requireText(object.title, MAX_JSON_RPC_TEXT_LENGTH),
        state,
        approved
      };
    }
    case 'chat.clarification': {
      const object = requireObject(
        params,
        ['request_id', 'sequence', 'clarification_id', 'question'],
        ['request_id', 'sequence', 'clarification_id', 'question']
      );
      return {
        type: 'clarification',
        requestId: requireSafeId(object.request_id),
        sequence: requireSequence(object.sequence),
        clarificationId: requireOpaqueString(object.clarification_id, MAX_CLARIFICATION_ID_LENGTH),
        question: requireText(object.question, MAX_JSON_RPC_TEXT_LENGTH)
      };
    }
    case 'chat.complete': {
      const object = requireObject(params, ['request_id', 'sequence', 'outcome'], [
        'request_id',
        'sequence',
        'outcome'
      ]);
      const outcome = requireString(object.outcome, 16);
      if (outcome !== 'success' && outcome !== 'cancelled' && outcome !== 'failed') {
        throw new JsonRpcChatError('protocol-violation');
      }
      return {
        type: 'completion',
        requestId: requireSafeId(object.request_id),
        sequence: requireSequence(object.sequence),
        outcome
      };
    }
    default:
      throw new JsonRpcChatError('protocol-violation');
  }
}

function parseErrorShape(value: BoundedJsonValue | undefined): JsonRpcErrorShape {
  const object = requireObject(value ?? null, ['code', 'message'], ['code', 'message']);
  const code = object.code;
  const message = object.message;
  if (
    typeof code !== 'number' ||
    !Number.isInteger(code) ||
    code < -32_768 ||
    code > -32_000 ||
    typeof message !== 'string' ||
    message.length > MAX_JSON_RPC_TEXT_LENGTH
  ) {
    throw new JsonRpcChatError('protocol-violation');
  }
  return { code };
}

function isAcceptedResult(value: BoundedJsonValue): boolean {
  try {
    const object = requireObject(value, ['accepted'], ['accepted']);
    return object.accepted === true;
  } catch {
    return false;
  }
}

function requireActiveRequest(requestId: string, requests: Map<string, OperationRecord>): void {
  const request = requests.get(requestId);
  if (!request || isTerminalStatus(request.status)) {
    throw new JsonRpcChatError('invalid-input');
  }
}

function requireObject(
  value: BoundedJsonValue,
  allowedKeys: readonly string[],
  requiredKeys: readonly string[] = []
): { [key: string]: BoundedJsonValue } {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new JsonRpcChatError('protocol-violation');
  }
  const object = value as { [key: string]: BoundedJsonValue };
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(object)) {
    if (!allowed.has(key)) {
      throw new JsonRpcChatError('protocol-violation');
    }
  }
  for (const key of requiredKeys) {
    if (!(key in object)) {
      throw new JsonRpcChatError('protocol-violation');
    }
  }
  return object;
}

function requireString(value: BoundedJsonValue | undefined, maxLength: number): string {
  if (typeof value !== 'string' || value.length > maxLength || containsDisallowedControl(value)) {
    throw new JsonRpcChatError('protocol-violation');
  }
  return value;
}

function requireText(value: BoundedJsonValue | undefined, maxLength: number, allowEmpty = false): string {
  const text = requireString(value, maxLength);
  if (!allowEmpty && text.length === 0) {
    throw new JsonRpcChatError('protocol-violation');
  }
  return text;
}

function requireOpaqueString(value: BoundedJsonValue | undefined, maxLength: number): string {
  const text = requireText(value, maxLength);
  if (!isSafeId(text)) {
    throw new JsonRpcChatError('protocol-violation');
  }
  return text;
}

function requireSafeId(value: BoundedJsonValue | undefined): string {
  if (typeof value !== 'string' || !isSafeId(value)) {
    throw new JsonRpcChatError('protocol-violation');
  }
  return value;
}

function requireSequence(value: BoundedJsonValue | undefined): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1 || value > MAX_JSON_RPC_SEQUENCE) {
    throw new JsonRpcChatError('protocol-violation');
  }
  return value;
}

function validateTicket(ticket: unknown): asserts ticket is string {
  if (typeof ticket !== 'string' || ticket.length === 0 || ticket.length > MAX_TICKET_LENGTH || !TICKET_PATTERN.test(ticket)) {
    throw new JsonRpcChatError('invalid-ticket');
  }
}

function validatePrompt(prompt: unknown): asserts prompt is string {
  if (
    typeof prompt !== 'string' ||
    prompt.length === 0 ||
    prompt.length > MAX_JSON_RPC_PROMPT_LENGTH ||
    containsDisallowedControl(prompt)
  ) {
    throw new JsonRpcChatError('invalid-input');
  }
}

function validateOpaqueInput(value: unknown, maxLength: number): asserts value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength || !isSafeId(value)) {
    throw new JsonRpcChatError('invalid-input');
  }
}

function normalizeFrameLimit(value: number | undefined): number {
  const limit = value ?? MAX_JSON_RPC_FRAME_BYTES;
  if (!Number.isInteger(limit) || limit < MIN_FRAME_BYTES || limit > MAX_JSON_RPC_FRAME_BYTES) {
    throw new JsonRpcChatError('invalid-options');
  }
  return limit;
}

function isSafeId(value: string): boolean {
  return value.length > 0 && value.length <= MAX_JSON_RPC_ID_LENGTH && REQUEST_ID_PATTERN.test(value);
}

function isIdReserved(
  id: string,
  context: SocketContext | undefined,
  requests: Map<string, OperationRecord>,
  controls: Map<string, ControlRecord>
): boolean {
  return id === context?.handshakeId || requests.has(id) || controls.has(id);
}

function isTerminalStatus(status: JsonRpcDeliveryStatus): boolean {
  return status === 'completed' || status === 'cancelled' || status === 'failed' || status === 'uncertain-delivery';
}

function containsDisallowedControl(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (codePoint !== undefined && codePoint < 0x20 && codePoint !== 0x09 && codePoint !== 0x0a && codePoint !== 0x0d) {
      return true;
    }
  }
  return false;
}

function byteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function decodeFrame(data: unknown, maxFrameBytes: number): string {
  if (typeof data === 'string') {
    if (byteLength(data) > maxFrameBytes) {
      throw new JsonRpcChatError('frame-too-large');
    }
    return data;
  }

  let bytes: Uint8Array;
  if (data instanceof ArrayBuffer) {
    bytes = new Uint8Array(data);
  } else if (data instanceof Uint8Array) {
    bytes = data;
  } else {
    throw new JsonRpcChatError('malformed-frame');
  }

  if (bytes.byteLength > maxFrameBytes) {
    throw new JsonRpcChatError('frame-too-large');
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new JsonRpcChatError('malformed-frame');
  }
}

function linkAbort(signal: AbortSignal | undefined, controller: AbortController): () => void {
  if (!signal) {
    return () => undefined;
  }
  const onAbort = (): void => controller.abort();
  if (signal.aborted) {
    controller.abort();
    return () => undefined;
  }
  signal.addEventListener('abort', onAbort, { once: true });
  return () => signal.removeEventListener('abort', onAbort);
}

function throwIfAborted(signal: AbortSignal): void {
  if (signal.aborted) {
    throw new JsonRpcChatError('aborted');
  }
}

function sanitizeConnectionError(error: unknown, signal: AbortSignal, generation: number): JsonRpcChatError {
  if (signal.aborted || (error instanceof JsonRpcChatError && error.code === 'aborted')) {
    return new JsonRpcChatError('aborted', generation);
  }
  if (error instanceof JsonRpcChatError) {
    return new JsonRpcChatError(error.code, generation);
  }
  return new JsonRpcChatError('connection-failed', generation);
}

function safeClose(socket: JsonRpcWebSocket): void {
  try {
    socket.close(1000, 'cancelled');
  } catch {
    // No raw socket error is retained or surfaced.
  }
}

function awaitWithAbort<T>(
  promise: Promise<T>,
  signal: AbortSignal,
  onLateResolve?: (value: T) => void
): Promise<T> {
  if (signal.aborted) {
    return Promise.reject(new JsonRpcChatError('aborted'));
  }

  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const cleanup = (): void => signal.removeEventListener('abort', onAbort);
    const settle = (callback: () => void): void => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      callback();
    };
    const onAbort = (): void => settle(() => reject(new JsonRpcChatError('aborted')));

    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      (value) => {
        if (settled) {
          onLateResolve?.(value);
          return;
        }
        settle(() => resolve(value));
      },
      (error: unknown) => settle(() => reject(error))
    );
  });
}

class BoundedJsonParser {
  private readonly limits: {
    readonly maxDepth: number;
    readonly maxNodes: number;
    readonly maxArrayLength: number;
    readonly maxObjectKeys: number;
    readonly maxStringLength: number;
  };
  private index = 0;
  private nodes = 0;

  constructor(limits: {
    readonly maxDepth: number;
    readonly maxNodes: number;
    readonly maxArrayLength: number;
    readonly maxObjectKeys: number;
    readonly maxStringLength: number;
  }) {
    this.limits = limits;
  }

  parse(text: string): BoundedJsonValue {
    if (text.length === 0) {
      throw new Error('empty');
    }
    const value = this.parseValue(text, 0);
    this.skipWhitespace(text);
    if (this.index !== text.length) {
      throw new Error('trailing');
    }
    return value;
  }

  private parseValue(text: string, depth: number): BoundedJsonValue {
    if (depth > this.limits.maxDepth) {
      throw new Error('depth');
    }
    this.skipWhitespace(text);
    const character = text[this.index];
    if (character === '{') {
      return this.parseObject(text, depth + 1);
    }
    if (character === '[') {
      return this.parseArray(text, depth + 1);
    }
    if (character === '"') {
      return this.parseString(text);
    }
    if (character === 't' && text.startsWith('true', this.index)) {
      this.index += 4;
      this.countNode();
      return true;
    }
    if (character === 'f' && text.startsWith('false', this.index)) {
      this.index += 5;
      this.countNode();
      return false;
    }
    if (character === 'n' && text.startsWith('null', this.index)) {
      this.index += 4;
      this.countNode();
      return null;
    }
    return this.parseNumber(text);
  }

  private parseObject(text: string, depth: number): { [key: string]: BoundedJsonValue } {
    this.index += 1;
    this.countNode();
    const result: { [key: string]: BoundedJsonValue } = Object.create(null) as {
      [key: string]: BoundedJsonValue;
    };
    const keys = new Set<string>();
    this.skipWhitespace(text);
    if (text[this.index] === '}') {
      this.index += 1;
      return result;
    }

    while (this.index < text.length) {
      if (keys.size >= this.limits.maxObjectKeys || text[this.index] !== '"') {
        throw new Error('object');
      }
      const key = this.parseString(text);
      if (keys.has(key)) {
        throw new Error('duplicate');
      }
      keys.add(key);
      this.skipWhitespace(text);
      if (text[this.index] !== ':') {
        throw new Error('colon');
      }
      this.index += 1;
      result[key] = this.parseValue(text, depth);
      this.skipWhitespace(text);
      if (text[this.index] === '}') {
        this.index += 1;
        return result;
      }
      if (text[this.index] !== ',') {
        throw new Error('comma');
      }
      this.index += 1;
      this.skipWhitespace(text);
    }
    throw new Error('object-end');
  }

  private parseArray(text: string, depth: number): BoundedJsonValue[] {
    this.index += 1;
    this.countNode();
    const result: BoundedJsonValue[] = [];
    this.skipWhitespace(text);
    if (text[this.index] === ']') {
      this.index += 1;
      return result;
    }
    while (this.index < text.length) {
      if (result.length >= this.limits.maxArrayLength) {
        throw new Error('array');
      }
      result.push(this.parseValue(text, depth));
      this.skipWhitespace(text);
      if (text[this.index] === ']') {
        this.index += 1;
        return result;
      }
      if (text[this.index] !== ',') {
        throw new Error('comma');
      }
      this.index += 1;
      this.skipWhitespace(text);
    }
    throw new Error('array-end');
  }

  private parseString(text: string): string {
    if (text[this.index] !== '"') {
      throw new Error('string');
    }
    const start = this.index;
    this.index += 1;
    while (this.index < text.length) {
      const character = text[this.index];
      if (character === '"') {
        this.index += 1;
        const raw = text.slice(start, this.index);
        let value: unknown;
        try {
          value = JSON.parse(raw) as unknown;
        } catch {
          throw new Error('string');
        }
        if (
          typeof value !== 'string' ||
          value.length > this.limits.maxStringLength ||
          containsDisallowedControl(value)
        ) {
          throw new Error('string');
        }
        this.countNode();
        return value;
      }
      if (character === '\\') {
        this.index += 1;
        const escape = text[this.index];
        if (!escape || !'"\\/bfnrtu'.includes(escape)) {
          throw new Error('escape');
        }
        if (escape === 'u') {
          const codePoint = text.slice(this.index + 1, this.index + 5);
          if (!/^[0-9a-fA-F]{4}$/u.test(codePoint)) {
            throw new Error('unicode');
          }
          this.index += 4;
        }
      } else if (character < ' ') {
        throw new Error('control');
      }
      this.index += 1;
      if (this.index - start > this.limits.maxStringLength * 6 + 2) {
        throw new Error('string-size');
      }
    }
    throw new Error('string-end');
  }

  private parseNumber(text: string): number {
    const match = text
      .slice(this.index)
      .match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u);
    if (!match) {
      throw new Error('number');
    }
    const literal = match[0];
    const value = Number(literal);
    if (!Number.isFinite(value) || (Number.isInteger(value) && Math.abs(value) > Number.MAX_SAFE_INTEGER)) {
      throw new Error('number');
    }
    this.index += literal.length;
    this.countNode();
    return value;
  }

  private skipWhitespace(text: string): void {
    while (this.index < text.length) {
      const code = text.charCodeAt(this.index);
      if (code !== 9 && code !== 10 && code !== 13 && code !== 32) {
        return;
      }
      this.index += 1;
    }
  }

  private countNode(): void {
    this.nodes += 1;
    if (this.nodes > this.limits.maxNodes) {
      throw new Error('nodes');
    }
  }
}
