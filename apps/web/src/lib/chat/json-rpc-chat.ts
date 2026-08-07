export const JSON_RPC_VERSION = "2.0" as const;
export const DASHBOARD_CONTRACT = "dashboard-v0.0.1" as const;
export const HERMES_SOURCE_SHA =
  "f5be9236e00ddf2f2a412697f267078fc4ee068e" as const;
export const JSON_RPC_WS_PATH = "/api/ws" as const;
export const JSON_RPC_WS_ORIGIN = "same-origin" as const;
export const JSON_RPC_EVENT_METHOD = "event" as const;
export const JSON_RPC_GATEWAY_READY_EVENT = "gateway.ready" as const;
export const JSON_RPC_SESSION_CREATE_METHOD = "session.create" as const;
export const JSON_RPC_SESSION_RESUME_METHOD = "session.resume" as const;
export const JSON_RPC_PROMPT_METHOD = "prompt.submit" as const;
export const JSON_RPC_INTERRUPT_METHOD = "session.interrupt" as const;
export const JSON_RPC_APPROVAL_METHOD = "approval.respond" as const;
export const JSON_RPC_CLARIFICATION_METHOD = "clarify.respond" as const;

export const MAX_JSON_RPC_FRAME_BYTES = 64 * 1024;
export const MAX_JSON_RPC_PROMPT_LENGTH = 16 * 1024;
export const MAX_JSON_RPC_TEXT_LENGTH = 8 * 1024;
export const MAX_JSON_RPC_ID_LENGTH = 128;
export const MAX_JSON_RPC_SEQUENCE = 1_000_000;
export const MAX_JSON_RPC_ACTIVE_REQUESTS = 32;
export const MAX_JSON_RPC_PENDING_CONTROLS = 32;
export const MAX_JSON_RPC_DEPTH = 16;
export const DEFAULT_GATEWAY_READY_TIMEOUT_MS = 5_000;
export const DEFAULT_ACKNOWLEDGEMENT_TIMEOUT_MS = 5_000;
export const DEFAULT_COMPATIBILITY_GATE_TIMEOUT_MS = 5_000;

const MIN_FRAME_BYTES = 256;
const MAX_JSON_NODES = 512;
const MAX_JSON_ARRAY_LENGTH = 64;
const MAX_JSON_OBJECT_KEYS = 64;
const MAX_TICKET_LENGTH = 512;
const MAX_SESSION_ID_LENGTH = 128;
const MAX_APPROVAL_ID_LENGTH = 128;
const MAX_CLARIFICATION_ID_LENGTH = 128;
const MAX_EVENT_TYPE_LENGTH = 128;
const REQUEST_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/u;
const SESSION_ID_PATTERN =
  /^(?:[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9._~-]{0,126}[A-Za-z0-9])$/u;
const TICKET_PATTERN = /^[A-Za-z0-9._~-]+$/u;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;

const KNOWN_EVENT_NAMES = [
  JSON_RPC_GATEWAY_READY_EVENT,
  "session.info",
  "message.delta",
  "reasoning.delta",
  "thinking.delta",
  "message.complete",
  "tool.start",
  "tool.complete",
  "approval.request",
  "clarify.request",
  "error",
] as const;

type JsonRpcKnownEventName = (typeof KNOWN_EVENT_NAMES)[number];

const SENSITIVE_INTERACTIVE_EVENT_NAMES = new Set([
  "sudo.request",
  "secret.request",
  "terminal.read.request",
  "file.attach",
  "browser.request",
]);

type JsonPrimitive = null | boolean | number | string;
export type BoundedJsonValue =
  JsonPrimitive | BoundedJsonValue[] | { [key: string]: BoundedJsonValue };

export type JsonRpcFrameData = string | ArrayBuffer | Uint8Array;

export interface JsonRpcMessageEvent {
  readonly data: unknown;
}

export interface JsonRpcCloseEvent {
  readonly code?: number;
  readonly reason?: string;
}

/**
 * The upgrade boundary is deliberately explicit. A later browser adapter may
 * turn this into a same-origin `/api/ws?ticket=...` URL, but this prototype
 * never constructs a URL, reads cookies, or owns the ticket after the factory
 * call returns.
 */
export interface JsonRpcWebSocketUpgradeRequest {
  readonly path: typeof JSON_RPC_WS_PATH;
  readonly origin: typeof JSON_RPC_WS_ORIGIN;
  readonly query: {
    readonly ticket: string;
  };
}

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
  upgrade: JsonRpcWebSocketUpgradeRequest,
  signal: AbortSignal,
) => JsonRpcWebSocket | Promise<JsonRpcWebSocket>;

export interface JsonRpcDeploymentEvidence {
  readonly identity: string;
  readonly trustChannel: string;
  readonly scope: "fixture_only" | "official_image";
}

export interface JsonRpcArtifactEvidence {
  readonly path: string;
  readonly sha256: string;
  readonly sizeBytes: number;
}

export interface JsonRpcRouteManifestEvidence extends JsonRpcArtifactEvidence {
  readonly revision: typeof DASHBOARD_CONTRACT;
}

export interface JsonRpcCompatibilityEvidence {
  readonly contract: typeof DASHBOARD_CONTRACT;
  readonly hermesSourceSha: typeof HERMES_SOURCE_SHA;
  readonly websocketPath: typeof JSON_RPC_WS_PATH;
  readonly deployment: JsonRpcDeploymentEvidence;
  readonly routeManifest: JsonRpcRouteManifestEvidence;
  readonly sourceReview: JsonRpcArtifactEvidence;
  readonly proxyProof: JsonRpcArtifactEvidence;
  readonly gatewayReadyPayload: BoundedJsonValue;
}

export type JsonRpcCompatibilityEvidenceInput = Omit<
  JsonRpcCompatibilityEvidence,
  "contract" | "hermesSourceSha" | "websocketPath" | "gatewayReadyPayload"
>;

export type JsonRpcCompatibilityGateResult =
  boolean | { readonly passed: boolean };

export type JsonRpcCompatibilityGate = (
  evidence: JsonRpcCompatibilityEvidence,
  signal: AbortSignal,
) => JsonRpcCompatibilityGateResult | Promise<JsonRpcCompatibilityGateResult>;

export type JsonRpcChatErrorCode =
  | "aborted"
  | "ack-timeout"
  | "authentication-required"
  | "cancelled"
  | "closed"
  | "connection-failed"
  | "frame-too-large"
  | "gateway-ready-timeout"
  | "handshake-failed"
  | "incompatible"
  | "invalid-input"
  | "invalid-options"
  | "invalid-ticket"
  | "malformed-frame"
  | "not-connected"
  | "protocol-violation"
  | "server-rejected"
  | "uncertain-delivery";

const ERROR_MESSAGES: Record<JsonRpcChatErrorCode, string> = {
  aborted: "The chat connection attempt was cancelled.",
  "ack-timeout": "The chat operation acknowledgement timed out.",
  "authentication-required": "Chat authentication is required.",
  cancelled: "The chat request was cancelled.",
  closed: "The chat connection is closing.",
  "connection-failed": "The chat WebSocket connection failed.",
  "frame-too-large": "The chat WebSocket frame exceeded the bounded limit.",
  "gateway-ready-timeout":
    "The chat gateway did not become ready before the deadline.",
  "handshake-failed": "The chat gateway readiness handshake failed.",
  incompatible: "The Dashboard deployment is outside the pinned chat contract.",
  "invalid-input": "The chat request input was outside the bounded contract.",
  "invalid-options":
    "The chat transport options were outside the bounded contract.",
  "invalid-ticket": "The chat WebSocket ticket was invalid.",
  "malformed-frame": "The chat WebSocket frame was not valid bounded JSON.",
  "not-connected": "The chat WebSocket is not ready.",
  "protocol-violation": "The chat WebSocket violated the JSON-RPC contract.",
  "server-rejected": "The chat server rejected the request.",
  "uncertain-delivery":
    "The chat request delivery is uncertain and was not replayed.",
};

export class JsonRpcChatError extends Error {
  readonly code: JsonRpcChatErrorCode;
  readonly generation?: number;

  constructor(code: JsonRpcChatErrorCode, generation?: number) {
    super(ERROR_MESSAGES[code]);
    this.name =
      code === "aborted" || code === "cancelled"
        ? "AbortError"
        : "JsonRpcChatError";
    this.code = code;
    this.generation = generation;
  }
}

export type JsonRpcConnectionStatus =
  | "offline"
  | "auth_required"
  | "connecting"
  | "handshaking"
  | "ready"
  | "restoring"
  | "reconnecting"
  | "delivery_uncertain"
  | "incompatible"
  | "failed"
  | "closing";

export type JsonRpcCloseClassification =
  | "authentication-rejected"
  | "host-or-origin-rejected"
  | "embedded-chat-disabled"
  | "peer-rejected"
  | "attachment-superseded"
  | "pty-process-exited"
  | "backend-failure"
  | "unsupported";

export interface JsonRpcCloseObservation {
  readonly code: number | undefined;
  readonly classification: JsonRpcCloseClassification;
}

export interface JsonRpcConnectionState {
  readonly status: JsonRpcConnectionStatus;
  readonly generation: number;
  readonly closeCode?: number;
  readonly closeClassification?: JsonRpcCloseClassification;
}

export type JsonRpcDeliveryStatus =
  | "submitting"
  | "accepted"
  | "streaming"
  | "awaiting_approval"
  | "awaiting_clarification"
  | "interrupting"
  | "completed"
  | "cancelled"
  | "failed"
  | "uncertain-delivery";

export interface JsonRpcChatRequestState {
  readonly id: string;
  readonly status: JsonRpcDeliveryStatus;
}

export interface JsonRpcChatEventBase<T extends JsonRpcKnownEventName> {
  readonly type: T;
  readonly sessionId?: string;
  readonly requestId?: string;
  readonly sequence?: number;
  readonly payload: BoundedJsonValue;
}

export interface JsonRpcGatewayReadyEvent extends JsonRpcChatEventBase<
  typeof JSON_RPC_GATEWAY_READY_EVENT
> {}
export interface JsonRpcSessionInfoEvent extends JsonRpcChatEventBase<"session.info"> {}
export interface JsonRpcMessageDeltaEvent extends JsonRpcChatEventBase<"message.delta"> {}
export interface JsonRpcReasoningDeltaEvent extends JsonRpcChatEventBase<"reasoning.delta"> {}
export interface JsonRpcThinkingDeltaEvent extends JsonRpcChatEventBase<"thinking.delta"> {}
export interface JsonRpcMessageCompleteEvent extends JsonRpcChatEventBase<"message.complete"> {}
export interface JsonRpcToolStartEvent extends JsonRpcChatEventBase<"tool.start"> {}
export interface JsonRpcToolCompleteEvent extends JsonRpcChatEventBase<"tool.complete"> {}

export interface JsonRpcApprovalRequestEvent extends JsonRpcChatEventBase<"approval.request"> {
  readonly approvalId: string;
}

export interface JsonRpcClarificationRequestEvent extends JsonRpcChatEventBase<"clarify.request"> {
  readonly clarificationId: string;
}

export interface JsonRpcErrorEvent extends JsonRpcChatEventBase<"error"> {}

export type JsonRpcChatEvent =
  | JsonRpcGatewayReadyEvent
  | JsonRpcSessionInfoEvent
  | JsonRpcMessageDeltaEvent
  | JsonRpcReasoningDeltaEvent
  | JsonRpcThinkingDeltaEvent
  | JsonRpcMessageCompleteEvent
  | JsonRpcToolStartEvent
  | JsonRpcToolCompleteEvent
  | JsonRpcApprovalRequestEvent
  | JsonRpcClarificationRequestEvent
  | JsonRpcErrorEvent;

export type JsonRpcCompletionEvent = JsonRpcMessageCompleteEvent;

export type JsonRpcCloseReason =
  | "client-close"
  | "reconnect"
  | "socket-close"
  | "socket-error"
  | "protocol-error"
  | "handshake-error"
  | "gateway-ready-timeout"
  | "incompatible"
  | "ack-timeout";

export interface JsonRpcChatRequest {
  readonly id: string;
  readonly completion: Promise<JsonRpcCompletionEvent>;
  readonly state: JsonRpcChatRequestState;
  abort(): void;
}

export interface JsonRpcCreatedSession {
  /** Ephemeral gateway ID used for the first prompt on this connection. */
  readonly sessionId: string;
  /** Durable REST identity allocated before the first prompt persists the row. */
  readonly storedSessionId: string;
  readonly model?: string;
}

export interface JsonRpcChatOptions {
  readonly ticketProvider: FreshChatTicketProvider;
  readonly createWebSocket: JsonRpcWebSocketFactory;
  readonly selectedSessionId?: string;
  readonly compatibilityEvidence: JsonRpcCompatibilityEvidenceInput;
  readonly verifyAttestation?: JsonRpcCompatibilityGate;
  readonly runBehavioralProbe?: JsonRpcCompatibilityGate;
  readonly requestIdFactory?: () => string;
  readonly maxFrameBytes?: number;
  readonly gatewayReadyTimeoutMs?: number;
  readonly acknowledgementTimeoutMs?: number;
  readonly compatibilityGateTimeoutMs?: number;
  readonly onEvent?: (event: JsonRpcChatEvent) => void;
  readonly onStateChange?: (state: JsonRpcConnectionState) => void;
  readonly onOpen?: () => void;
  readonly onClose?: (
    reason: JsonRpcCloseReason,
    observation?: JsonRpcCloseObservation,
  ) => void;
  readonly onCloseCode?: (observation: JsonRpcCloseObservation) => void;
  readonly onReconnect?: () => void;
  readonly onAbort?: (requestId: string) => void;
  readonly onUncertainDelivery?: (requestId: string) => void;
}

export interface JsonRpcChatTransport {
  readonly state: JsonRpcConnectionState;
  readonly selectedSessionId: string | undefined;
  connect(signal?: AbortSignal): Promise<void>;
  reconnect(signal?: AbortSignal): Promise<void>;
  createSession(signal?: AbortSignal): Promise<JsonRpcCreatedSession>;
  restore(sessionId?: string, signal?: AbortSignal): Promise<void>;
  close(): void;
  sendPrompt(
    prompt: string,
    options?: { readonly signal?: AbortSignal },
  ): JsonRpcChatRequest;
  interrupt(requestId: string, signal?: AbortSignal): Promise<void>;
  respondToApproval(
    requestId: string,
    approvalId: string,
    approved: boolean,
    signal?: AbortSignal,
  ): Promise<void>;
  answerClarification(
    requestId: string,
    clarificationId: string,
    answer: string,
    signal?: AbortSignal,
  ): Promise<void>;
  abort(requestId: string): void;
  subscribe(listener: (event: JsonRpcChatEvent) => void): () => void;
}

interface JsonRpcRequestMessage {
  readonly kind: "request";
  readonly id: string;
  readonly method: string;
  readonly params: BoundedJsonValue;
}

interface JsonRpcResponseMessage {
  readonly kind: "response";
  readonly id: string | null;
  readonly result?: BoundedJsonValue;
  readonly error?: JsonRpcErrorShape;
}

interface JsonRpcNotificationMessage {
  readonly kind: "notification";
  readonly method: string;
  readonly params: BoundedJsonValue;
}

type ParsedWireMessage =
  JsonRpcResponseMessage | JsonRpcNotificationMessage | JsonRpcRequestMessage;

interface JsonRpcErrorShape {
  readonly code: number;
  readonly message: string;
}

interface ParsedEventEnvelope {
  readonly type: string;
  readonly sessionId?: string;
  readonly requestId?: string;
  readonly sequence?: number;
  readonly payload: BoundedJsonValue;
}

interface OperationRecord {
  readonly id: string;
  status: JsonRpcDeliveryStatus;
  acknowledgementReceived: boolean;
  sequenceMode: "unknown" | "present" | "absent";
  nextSequence: number;
  readonly resolveCompletion: (event: JsonRpcCompletionEvent) => void;
  readonly rejectCompletion: (error: JsonRpcChatError) => void;
  readonly signal?: AbortSignal;
  removeAbortListener?: () => void;
  acknowledgementTimer?: ReturnType<typeof setTimeout>;
}

type ControlKind = "create" | "restore" | "interrupt" | "approval" | "clarification";

interface ControlRecord {
  readonly id: string;
  readonly kind: ControlKind;
  readonly resolve: () => void;
  readonly reject: (error: JsonRpcChatError) => void;
  /** Validate and project a source-owned result before acknowledging control success. */
  readonly acceptResult?: (result: BoundedJsonValue) => void;
  removeAbortListener?: () => void;
  acknowledgementTimer?: ReturnType<typeof setTimeout>;
}

interface PendingInteraction {
  readonly kind: "approval" | "clarification";
  readonly ownerId: string;
  responded: boolean;
}

interface SocketContext {
  readonly generation: number;
  readonly socket: JsonRpcWebSocket;
  readonly readyPromise: Promise<void>;
  readonly readyResolve: () => void;
  readonly readyReject: (error: JsonRpcChatError) => void;
  opened: boolean;
  gatewayReady: boolean;
  readySettled: boolean;
  closed: boolean;
  readyTimer?: ReturnType<typeof setTimeout>;
  compatibilityRunning: boolean;
  failure?: JsonRpcChatError;
  failureReason?: JsonRpcCloseReason;
}

interface ConnectionAttempt {
  readonly generation: number;
  readonly controller: AbortController;
  readonly promise: Promise<void>;
}

/**
 * Create the browser-side JSON-RPC boundary for the pinned Dashboard surface.
 * It owns no ticket, prompt, credential, transcript, or server event history.
 * Gates are intentionally injected because this planning-only prototype cannot
 * attest a deployment or perform a live behavioral probe itself.
 */
export function createJsonRpcChatTransport(
  options: JsonRpcChatOptions,
): JsonRpcChatTransport {
  const maxFrameBytes = normalizeFrameLimit(options.maxFrameBytes);
  const gatewayReadyTimeoutMs = normalizeTimeout(options.gatewayReadyTimeoutMs);
  const acknowledgementTimeoutMs = normalizeTimeout(
    options.acknowledgementTimeoutMs,
  );
  const compatibilityGateTimeoutMs = normalizeTimeout(
    options.compatibilityGateTimeoutMs,
  );
  const listeners = new Set<(event: JsonRpcChatEvent) => void>();
  const activeRequests = new Map<string, OperationRecord>();
  const pendingControls = new Map<string, ControlRecord>();
  const pendingInteractions = new Map<string, PendingInteraction>();
  const ignoredResponseIds = new Set<string>();
  let nextGeneratedId = 0;
  let currentGeneration = 0;
  let selectedSessionId = options.selectedSessionId;
  let currentState: JsonRpcConnectionState = {
    status: "offline",
    generation: 0,
  };
  let activeContext: SocketContext | undefined;
  let activeAttempt: ConnectionAttempt | undefined;
  let userClosed = false;

  if (selectedSessionId !== undefined) {
    validateSessionId(selectedSessionId);
  }

  const safeCall = <T extends unknown[]>(
    callback: ((...args: T) => void) | undefined,
    ...args: T
  ): void => {
    if (!callback) {
      return;
    }
    try {
      callback(...args);
    } catch {
      // Hooks are observational. Their failures cannot change transport state.
    }
  };

  const setState = (
    status: JsonRpcConnectionStatus,
    generation = currentGeneration,
    observation?: JsonRpcCloseObservation,
  ): void => {
    const next: JsonRpcConnectionState = {
      status,
      generation,
      ...(observation?.code !== undefined
        ? { closeCode: observation.code }
        : {}),
      ...(observation
        ? { closeClassification: observation.classification }
        : {}),
    };
    if (
      currentState.status === next.status &&
      currentState.generation === next.generation &&
      currentState.closeCode === next.closeCode &&
      currentState.closeClassification === next.closeClassification
    ) {
      return;
    }
    currentState = next;
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
      throw new JsonRpcChatError("invalid-options", currentGeneration);
    }
    if (
      !isSafeId(id) ||
      isIdReserved(id, activeRequests, pendingControls) ||
      ignoredResponseIds.has(id)
    ) {
      throw new JsonRpcChatError("invalid-options", currentGeneration);
    }
    return id;
  };

  const sendFrame = (
    context: SocketContext,
    payload: Record<string, unknown>,
  ): void => {
    const frame = JSON.stringify(payload);
    if (byteLength(frame) > maxFrameBytes) {
      throw new JsonRpcChatError("frame-too-large", context.generation);
    }
    try {
      context.socket.send(frame);
    } catch {
      throw new JsonRpcChatError("connection-failed", context.generation);
    }
  };

  const assertOutboundFrame = (
    payload: Record<string, unknown>,
    generation: number,
  ): void => {
    if (byteLength(JSON.stringify(payload)) > maxFrameBytes) {
      throw new JsonRpcChatError("frame-too-large", generation);
    }
  };

  const rememberIgnoredResponse = (id: string): void => {
    if (ignoredResponseIds.size >= MAX_JSON_RPC_ACTIVE_REQUESTS * 4) {
      const oldest = ignoredResponseIds.values().next().value;
      if (typeof oldest === "string") {
        ignoredResponseIds.delete(oldest);
      }
    }
    ignoredResponseIds.add(id);
  };

  const clearInteraction = (requestId: string): void => {
    pendingInteractions.delete(requestId);
  };

  const markUncertain = (record: OperationRecord): void => {
    if (isTerminalStatus(record.status)) {
      return;
    }
    clearTimeoutIfPresent(record.acknowledgementTimer);
    record.acknowledgementTimer = undefined;
    record.status = "uncertain-delivery";
    activeRequests.delete(record.id);
    rememberIgnoredResponse(record.id);
    clearInteraction(record.id);
    record.removeAbortListener?.();
    record.rejectCompletion(
      new JsonRpcChatError("uncertain-delivery", currentGeneration),
    );
    safeCall(options.onUncertainDelivery, record.id);
  };

  const settleControl = (
    record: ControlRecord,
    error?: JsonRpcChatError,
  ): void => {
    clearTimeoutIfPresent(record.acknowledgementTimer);
    record.acknowledgementTimer = undefined;
    pendingControls.delete(record.id);
    record.removeAbortListener?.();
    if (error) {
      rememberIgnoredResponse(record.id);
      record.reject(error);
    } else {
      record.resolve();
    }
  };

  const closeSocketWithoutCallbacks = (
    socket: JsonRpcWebSocket,
    code: number,
    reason: string,
  ): void => {
    try {
      socket.close(code, reason);
    } catch {
      // Local cleanup already happened; no raw adapter error is retained.
    }
  };

  const invalidateContext = (
    context: SocketContext,
    reason: JsonRpcCloseReason,
    error: JsonRpcChatError,
    status: JsonRpcConnectionStatus,
    observation?: JsonRpcCloseObservation,
    closeCode = reason === "protocol-error" ||
    reason === "handshake-error" ||
    reason === "gateway-ready-timeout"
      ? 1002
      : 1000,
  ): void => {
    if (context.closed) {
      return;
    }

    // Invalidate identity and detach handlers before calling user-supplied close.
    // Reentrant adapters can emit during close; those callbacks must be stale.
    context.closed = true;
    clearTimeoutIfPresent(context.readyTimer);
    context.readyTimer = undefined;
    if (activeContext === context) {
      activeContext = undefined;
      currentGeneration = Math.max(currentGeneration, context.generation + 1);
    }
    context.socket.onopen = null;
    context.socket.onmessage = null;
    context.socket.onerror = null;
    context.socket.onclose = null;

    if (!context.readySettled) {
      context.readySettled = true;
      context.readyReject(error);
    }
    for (const record of [...activeRequests.values()]) {
      markUncertain(record);
    }
    for (const record of [...pendingControls.values()]) {
      settleControl(
        record,
        new JsonRpcChatError("uncertain-delivery", currentGeneration),
      );
    }
    pendingInteractions.clear();
    closeSocketWithoutCallbacks(
      context.socket,
      closeCode,
      reason === "reconnect" ? "replaced" : "closed",
    );

    if (status === "delivery_uncertain") {
      setState(status, currentGeneration, observation);
    } else if (
      activeContext === undefined ||
      context.generation === currentGeneration - 1
    ) {
      setState(status, currentGeneration, observation);
    }
    if (observation) {
      safeCall(options.onCloseCode, observation);
    }
    safeCall(options.onClose, reason, observation);
  };

  const failContext = (
    context: SocketContext,
    code: JsonRpcChatErrorCode,
    reason: JsonRpcCloseReason,
    status: JsonRpcConnectionStatus =
      code === "incompatible"
        ? "incompatible"
        : code === "authentication-required"
          ? "auth_required"
          : "failed",
  ): void => {
    if (context.closed) {
      return;
    }
    const error = new JsonRpcChatError(code, context.generation);
    context.failure = error;
    context.failureReason = reason;
    invalidateContext(context, reason, error, status);
  };

  const handleSendFailure = (
    context: SocketContext,
    error: unknown,
  ): JsonRpcChatError => {
    const sanitized =
      error instanceof JsonRpcChatError
        ? error
        : new JsonRpcChatError("connection-failed", context.generation);
    if (!context.closed) {
      invalidateContext(
        context,
        "socket-error",
        sanitized,
        "delivery_uncertain",
      );
    }
    return sanitized;
  };

  const eventSessionId = (event: ParsedEventEnvelope): string | undefined =>
    event.sessionId ?? selectedSessionId;

  const findOperationForEvent = (
    event: ParsedEventEnvelope,
  ): OperationRecord | undefined => {
    if (event.requestId) {
      const operation = activeRequests.get(event.requestId);
      if (operation) {
        return operation;
      }
      return undefined;
    }
    const sessionId = eventSessionId(event);
    const matches = [...activeRequests.values()].filter(
      (record) =>
        sessionId === undefined ||
        selectedSessionId === undefined ||
        sessionId === selectedSessionId,
    );
    return matches.length === 1 ? matches[0] : undefined;
  };

  const updateSequence = (
    operation: OperationRecord,
    sequence: number | undefined,
  ): void => {
    if (sequence === undefined) {
      if (operation.sequenceMode === "present") {
        throw new JsonRpcChatError("protocol-violation", currentGeneration);
      }
      operation.sequenceMode = "absent";
      return;
    }
    if (
      operation.sequenceMode === "absent" ||
      sequence !== operation.nextSequence
    ) {
      throw new JsonRpcChatError("protocol-violation", currentGeneration);
    }
    operation.sequenceMode = "present";
    operation.nextSequence += 1;
  };

  const isSuccessfulCompletion = (
    event: JsonRpcMessageCompleteEvent,
  ): boolean => {
    if (
      event.payload === null ||
      typeof event.payload !== "object" ||
      Array.isArray(event.payload)
    ) {
      return true;
    }
    const payload = event.payload as Record<string, BoundedJsonValue>;
    const status = payload.status ?? payload.outcome;
    return status !== "error" && status !== "failed" && status !== "cancelled";
  };

  const finishOperation = (
    operation: OperationRecord,
    event: JsonRpcMessageCompleteEvent,
  ): void => {
    clearTimeoutIfPresent(operation.acknowledgementTimer);
    operation.acknowledgementTimer = undefined;
    if (!operation.acknowledgementReceived) {
      // Events and JSON-RPC replies share one channel. Keep a bounded tombstone
      // so a valid response that follows completion cannot become a protocol
      // failure or be mistaken for a new request.
      rememberIgnoredResponse(operation.id);
    }
    activeRequests.delete(operation.id);
    clearInteraction(operation.id);
    operation.removeAbortListener?.();
    emitEvent(event);
    if (isSuccessfulCompletion(event)) {
      operation.status = "completed";
      operation.resolveCompletion(event);
      return;
    }
    operation.status = "failed";
    operation.rejectCompletion(
      new JsonRpcChatError("server-rejected", currentGeneration),
    );
  };

  const parseAndHandleFrame = (context: SocketContext, data: unknown): void => {
    if (!isCurrentContext(context)) {
      return;
    }
    let message: ParsedWireMessage;
    try {
      message = parseWireMessage(parseBoundedJsonFrame(data, maxFrameBytes));
    } catch (error) {
      const code =
        error instanceof JsonRpcChatError ? error.code : "malformed-frame";
      failContext(
        context,
        code,
        context.gatewayReady ? "protocol-error" : "handshake-error",
      );
      return;
    }
    if (message.kind === "request") {
      failContext(context, "protocol-violation", "protocol-error");
      return;
    }
    if (message.kind === "response") {
      handleResponse(context, message);
      return;
    }
    handleNotification(context, message);
  };

  const handleResponse = (
    context: SocketContext,
    message: JsonRpcResponseMessage,
  ): void => {
    if (message.id === null) {
      if (message.error?.code === -32700 || message.error?.code === -32603) {
        failContext(context, "server-rejected", "protocol-error");
      } else {
        failContext(context, "protocol-violation", "protocol-error");
      }
      return;
    }
    if (ignoredResponseIds.delete(message.id)) {
      return;
    }

    const operation = activeRequests.get(message.id);
    if (operation) {
      operation.acknowledgementReceived = true;
      clearTimeoutIfPresent(operation.acknowledgementTimer);
      operation.acknowledgementTimer = undefined;
      if (message.error) {
        operation.status = "failed";
        activeRequests.delete(operation.id);
        clearInteraction(operation.id);
        operation.removeAbortListener?.();
        operation.rejectCompletion(
          new JsonRpcChatError("server-rejected", context.generation),
        );
        setState("failed", currentGeneration);
        return;
      }
      if (
        isTerminalStatus(operation.status) ||
        operation.status !== "submitting"
      ) {
        // A streaming, approval, clarification, or completed event may have
        // crossed the acknowledgement on this shared channel. The response
        // records delivery but never regresses the event-derived lifecycle.
        return;
      }
      operation.status = "accepted";
      return;
    }

    const control = pendingControls.get(message.id);
    if (control) {
      if (message.error) {
        settleControl(
          control,
          new JsonRpcChatError("server-rejected", context.generation),
        );
      } else {
        try {
          control.acceptResult?.(message.result ?? null);
          settleControl(control);
        } catch {
          settleControl(
            control,
            new JsonRpcChatError("protocol-violation", context.generation),
          );
          failContext(context, "protocol-violation", "protocol-error");
        }
      }
      return;
    }

    failContext(context, "protocol-violation", "protocol-error");
  };

  const createPublicEvent = (event: ParsedEventEnvelope): JsonRpcChatEvent => {
    const base = {
      type: event.type as JsonRpcKnownEventName,
      ...(event.sessionId ? { sessionId: event.sessionId } : {}),
      ...(event.requestId ? { requestId: event.requestId } : {}),
      ...(event.sequence !== undefined ? { sequence: event.sequence } : {}),
      payload: event.payload,
    };
    if (event.type === "approval.request") {
      return {
        ...base,
        type: event.type,
        approvalId: findInteractionOwner(event, "approval"),
      };
    }
    if (event.type === "clarify.request") {
      return {
        ...base,
        type: event.type,
        clarificationId: findInteractionOwner(event, "clarification"),
      };
    }
    return base as JsonRpcChatEvent;
  };

  const handleGatewayReady = (
    context: SocketContext,
    envelope: ParsedEventEnvelope,
  ): void => {
    if (context.gatewayReady || context.compatibilityRunning) {
      failContext(context, "protocol-violation", "handshake-error");
      return;
    }
    context.gatewayReady = true;
    clearTimeoutIfPresent(context.readyTimer);
    context.readyTimer = undefined;
    const event = createPublicEvent(envelope) as JsonRpcGatewayReadyEvent;
    emitEvent(event);
    context.compatibilityRunning = true;
    void runCompatibilityGates(context, envelope.payload);
  };

  const handleNotification = (
    context: SocketContext,
    message: JsonRpcNotificationMessage,
  ): void => {
    if (message.method !== JSON_RPC_EVENT_METHOD) {
      if (isInteractiveEventName(message.method)) {
        failContext(context, "incompatible", "incompatible", "incompatible");
      }
      // Unknown additive non-interactive notifications are ignored by design.
      return;
    }

    let envelope: ParsedEventEnvelope;
    try {
      envelope = parseEventEnvelope(message.params);
    } catch {
      failContext(
        context,
        "protocol-violation",
        context.gatewayReady ? "protocol-error" : "handshake-error",
      );
      return;
    }

    if (!KNOWN_EVENT_NAMES.includes(envelope.type as JsonRpcKnownEventName)) {
      if (!context.gatewayReady) {
        failContext(context, "handshake-failed", "handshake-error");
      } else if (isInteractiveEventName(envelope.type)) {
        failContext(context, "incompatible", "incompatible", "incompatible");
      }
      return;
    }
    if (
      !context.gatewayReady &&
      envelope.type !== JSON_RPC_GATEWAY_READY_EVENT
    ) {
      failContext(context, "handshake-failed", "handshake-error");
      return;
    }
    if (envelope.type === JSON_RPC_GATEWAY_READY_EVENT) {
      handleGatewayReady(context, envelope);
      return;
    }
    if (envelope.type === "session.info") {
      emitEvent(createPublicEvent(envelope));
      return;
    }

    const operation = findOperationForEvent(envelope);
    if (!operation) {
      failContext(context, "protocol-violation", "protocol-error");
      return;
    }
    if (
      envelope.sessionId &&
      selectedSessionId &&
      envelope.sessionId !== selectedSessionId
    ) {
      failContext(context, "protocol-violation", "protocol-error");
      return;
    }
    try {
      updateSequence(operation, envelope.sequence);
    } catch {
      failContext(context, "protocol-violation", "protocol-error");
      return;
    }

    let event: JsonRpcChatEvent;
    try {
      // Interaction owner fields are untrusted protocol data. Validate them
      // inside the fail-closed boundary before mutating operation state.
      event = createPublicEvent(envelope);
    } catch {
      failContext(context, "protocol-violation", "protocol-error");
      return;
    }
    if (envelope.type === "approval.request") {
      try {
        validateApprovalState(envelope.payload);
      } catch {
        failContext(context, "protocol-violation", "protocol-error");
        return;
      }
      if (pendingInteractions.has(operation.id)) {
        failContext(context, "protocol-violation", "protocol-error");
        return;
      }
      pendingInteractions.set(operation.id, {
        kind: "approval",
        ownerId: (event as JsonRpcApprovalRequestEvent).approvalId,
        responded: false,
      });
      operation.status = "awaiting_approval";
      emitEvent(event);
      return;
    }
    if (envelope.type === "clarify.request") {
      if (pendingInteractions.has(operation.id)) {
        failContext(context, "protocol-violation", "protocol-error");
        return;
      }
      pendingInteractions.set(operation.id, {
        kind: "clarification",
        ownerId: (event as JsonRpcClarificationRequestEvent).clarificationId,
        responded: false,
      });
      operation.status = "awaiting_clarification";
      emitEvent(event);
      return;
    }
    if (envelope.type === "error") {
      emitEvent(event);
      operation.status = "failed";
      if (!operation.acknowledgementReceived) {
        rememberIgnoredResponse(operation.id);
      }
      activeRequests.delete(operation.id);
      clearInteraction(operation.id);
      operation.removeAbortListener?.();
      operation.rejectCompletion(
        new JsonRpcChatError("server-rejected", currentGeneration),
      );
      setState("failed", currentGeneration);
      return;
    }
    if (envelope.type === "message.complete") {
      finishOperation(operation, event as JsonRpcMessageCompleteEvent);
      return;
    }
    operation.status = "streaming";
    emitEvent(event);
  };

  const runCompatibilityGates = async (
    context: SocketContext,
    gatewayReadyPayload: BoundedJsonValue,
  ): Promise<void> => {
    const suppliedEvidence = options.compatibilityEvidence;
    if (!isCompleteCompatibilityEvidence(suppliedEvidence)) {
      failContext(context, "incompatible", "incompatible", "incompatible");
      return;
    }
    const evidence: JsonRpcCompatibilityEvidence = {
      contract: DASHBOARD_CONTRACT,
      hermesSourceSha: HERMES_SOURCE_SHA,
      websocketPath: JSON_RPC_WS_PATH,
      ...suppliedEvidence,
      gatewayReadyPayload,
    };
    const compatibilitySignal = activeAttempt?.controller.signal;
    try {
      const attestation = await evaluateGate(
        options.verifyAttestation,
        evidence,
        compatibilitySignal,
        compatibilityGateTimeoutMs,
      );
      if (!attestation) {
        throw new JsonRpcChatError("incompatible", context.generation);
      }
      const probe = await evaluateGate(
        options.runBehavioralProbe,
        evidence,
        compatibilitySignal,
        compatibilityGateTimeoutMs,
      );
      if (!probe) {
        throw new JsonRpcChatError("incompatible", context.generation);
      }
      if (!isCurrentContext(context)) {
        return;
      }
      context.compatibilityRunning = false;
      if (!context.readySettled) {
        context.readySettled = true;
        context.readyResolve();
      }
      setState("ready", currentGeneration);
      safeCall(options.onOpen);
    } catch (error) {
      if (!isCurrentContext(context)) {
        return;
      }
      const code =
        error instanceof JsonRpcChatError && error.code === "aborted"
          ? "aborted"
          : "incompatible";
      failContext(
        context,
        code,
        code === "aborted" ? "socket-error" : "incompatible",
        code === "aborted" ? "offline" : "incompatible",
      );
    }
  };

  const attachContext = (
    socket: JsonRpcWebSocket,
    generation: number,
  ): SocketContext => {
    let readyResolve!: () => void;
    let readyReject!: (error: JsonRpcChatError) => void;
    const readyPromise = new Promise<void>((resolve, reject) => {
      readyResolve = resolve;
      readyReject = reject;
    });
    const context: SocketContext = {
      generation,
      socket,
      readyPromise,
      readyResolve,
      readyReject,
      opened: false,
      gatewayReady: false,
      readySettled: false,
      closed: false,
      compatibilityRunning: false,
    };

    socket.onopen = () => {
      if (!isCurrentContext(context) || context.opened) {
        return;
      }
      context.opened = true;
      setState("handshaking", generation);
      context.readyTimer = setTimeout(() => {
        if (isCurrentContext(context) && !context.gatewayReady) {
          failContext(
            context,
            "gateway-ready-timeout",
            "gateway-ready-timeout",
          );
        }
      }, gatewayReadyTimeoutMs);
    };
    socket.onmessage = (event) => parseAndHandleFrame(context, event.data);
    socket.onerror = () => {
      if (isCurrentContext(context)) {
        failContext(context, "connection-failed", "socket-error");
      }
    };
    socket.onclose = (event) => {
      if (!isCurrentContext(context)) {
        return;
      }
      const observation = classifyCloseCode(event?.code);
      const status = statusForClose(observation);
      const errorCode =
        status === "auth_required"
          ? "connection-failed"
          : status === "incompatible"
            ? "incompatible"
            : "connection-failed";
      invalidateContext(
        context,
        "socket-close",
        new JsonRpcChatError(errorCode, generation),
        status,
        observation,
        1000,
      );
    };

    activeContext = context;
    if (socket.readyState === 1) {
      queueMicrotask(() => socket.onopen?.());
    }
    return context;
  };

  const sendRequest = (
    context: SocketContext,
    method: string,
    params: Record<string, BoundedJsonValue>,
    kind: ControlKind,
    signal?: AbortSignal,
    acceptResult?: (result: BoundedJsonValue) => void,
  ): Promise<void> => {
    if (pendingControls.size >= MAX_JSON_RPC_PENDING_CONTROLS) {
      return Promise.reject(
        new JsonRpcChatError("invalid-options", currentGeneration),
      );
    }
    if (signal?.aborted) {
      return Promise.reject(new JsonRpcChatError("aborted", currentGeneration));
    }
    let id: string;
    try {
      id = allocateId();
    } catch (error) {
      return Promise.reject(
        error instanceof JsonRpcChatError
          ? error
          : new JsonRpcChatError("invalid-options"),
      );
    }
    const payload = { jsonrpc: JSON_RPC_VERSION, id, method, params };
    try {
      assertOutboundFrame(payload, context.generation);
    } catch (error) {
      return Promise.reject(
        error instanceof JsonRpcChatError
          ? error
          : new JsonRpcChatError("frame-too-large"),
      );
    }

    let resolve!: () => void;
    let reject!: (error: JsonRpcChatError) => void;
    const promise = new Promise<void>((resolvePromise, rejectPromise) => {
      resolve = resolvePromise;
      reject = rejectPromise;
    });
    const record: ControlRecord = { id, kind, resolve, reject, acceptResult };
    pendingControls.set(id, record);
    record.acknowledgementTimer = setTimeout(() => {
      if (pendingControls.get(id) !== record) {
        return;
      }
      settleControl(
        record,
        new JsonRpcChatError("ack-timeout", currentGeneration),
      );
      if (isCurrentContext(context)) {
        invalidateContext(
          context,
          "ack-timeout",
          new JsonRpcChatError("ack-timeout", currentGeneration),
          "delivery_uncertain",
        );
      }
    }, acknowledgementTimeoutMs);

    if (signal) {
      const onAbort = (): void =>
        settleControl(
          record,
          new JsonRpcChatError("aborted", currentGeneration),
        );
      signal.addEventListener("abort", onAbort, { once: true });
      record.removeAbortListener = () =>
        signal.removeEventListener("abort", onAbort);
    }

    try {
      sendFrame(context, payload);
    } catch (error) {
      handleSendFailure(context, error);
    }
    return promise;
  };

  const restoreInternal = (
    context: SocketContext,
    sessionId: string,
    signal?: AbortSignal,
  ): Promise<void> => {
    setState("restoring", currentGeneration);
    return sendRequest(
      context,
      JSON_RPC_SESSION_RESUME_METHOD,
      { session_id: sessionId },
      "restore",
      signal,
    ).then(
      () => {
        if (isCurrentContext(context)) {
          setState("ready", currentGeneration);
        }
      },
      (error: JsonRpcChatError) => {
        if (isCurrentContext(context) && error.code !== "aborted") {
          setState("failed", currentGeneration);
        }
        throw error;
      },
    );
  };

  const startConnection = (
    signal: AbortSignal | undefined,
    reconnecting: boolean,
  ): Promise<void> => {
    if (activeAttempt) {
      return activeAttempt.promise;
    }
    const generation = ++currentGeneration;
    const controller = new AbortController();
    const unlinkAbort = linkAbort(signal, controller);
    setState(reconnecting ? "reconnecting" : "connecting", generation);
    let context: SocketContext | undefined;
    let unlinkContextAbort = (): void => undefined;
    let acquiredSocket: JsonRpcWebSocket | undefined;
    let adoptedSocket = false;
    const closeUnadoptedSocket = createIdempotentSocketCloser();

    const promise = (async (): Promise<void> => {
      try {
        throwIfAborted(controller.signal);
        let ticket = await awaitWithAbort(
          Promise.resolve(options.ticketProvider(controller.signal)),
          controller.signal,
        );
        validateTicket(ticket);
        const upgrade: JsonRpcWebSocketUpgradeRequest = {
          path: JSON_RPC_WS_PATH,
          origin: JSON_RPC_WS_ORIGIN,
          query: { ticket },
        };
        acquiredSocket = await awaitWithAbort(
          Promise.resolve(options.createWebSocket(upgrade, controller.signal)),
          controller.signal,
          closeUnadoptedSocket,
        );
        ticket = "";
        throwIfAborted(controller.signal);
        if (generation !== currentGeneration) {
          throw new JsonRpcChatError("aborted", generation);
        }
        context = attachContext(acquiredSocket, generation);
        adoptedSocket = true;
        const onAbort = (): void => {
          if (context && isCurrentContext(context)) {
            invalidateContext(
              context,
              "socket-error",
              new JsonRpcChatError("aborted", generation),
              "offline",
            );
          }
        };
        controller.signal.addEventListener("abort", onAbort, { once: true });
        unlinkContextAbort = () =>
          controller.signal.removeEventListener("abort", onAbort);
        await awaitWithAbort(context.readyPromise, controller.signal);
        throwIfAborted(controller.signal);
        if (!isCurrentContext(context)) {
          throw new JsonRpcChatError("connection-failed", generation);
        }
        if (selectedSessionId !== undefined) {
          await restoreInternal(context, selectedSessionId, controller.signal);
        }
      } catch (error) {
        if (acquiredSocket && !adoptedSocket) {
          closeUnadoptedSocket(acquiredSocket);
        }
        const sanitized = sanitizeConnectionError(
          error,
          controller.signal,
          generation,
        );
        if (context && !context.closed) {
          const status =
            sanitized.code === "incompatible"
              ? "incompatible"
              : sanitized.code === "authentication-required"
                ? "auth_required"
                : sanitized.code === "aborted"
                  ? "offline"
                  : "failed";
          invalidateContext(
            context,
            sanitized.code === "incompatible"
              ? "incompatible"
              : "handshake-error",
            sanitized,
            status,
          );
        }
        if (generation === currentGeneration && sanitized.code !== "aborted") {
          setState(
            sanitized.code === "incompatible"
              ? "incompatible"
              : sanitized.code === "authentication-required"
                ? "auth_required"
                : "failed",
            generation,
          );
        } else if (
          generation === currentGeneration &&
          sanitized.code === "aborted"
        ) {
          setState("offline", generation);
        }
        throw sanitized;
      } finally {
        unlinkContextAbort();
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
    if (currentState.status === "closing") {
      return Promise.reject(new JsonRpcChatError("closed", currentGeneration));
    }
    if (userClosed) {
      // A fresh explicit connect is the only user action that reopens a
      // transport after close; callbacks running during `closing` are blocked.
      userClosed = false;
    }
    if (currentState.status === "ready" && activeContext?.gatewayReady) {
      return Promise.resolve();
    }
    if (currentState.status === "restoring" && activeAttempt) {
      return activeAttempt.promise;
    }
    return startConnection(signal, false);
  };

  const reconnect = (signal?: AbortSignal): Promise<void> => {
    if (userClosed || currentState.status === "closing") {
      return Promise.reject(new JsonRpcChatError("closed", currentGeneration));
    }
    const previousAttempt = activeAttempt;
    const previousContext = activeContext;
    if (previousAttempt) {
      currentGeneration = Math.max(
        currentGeneration,
        previousAttempt.generation + 1,
      );
      previousAttempt.controller.abort();
      void previousAttempt.promise.catch(() => undefined);
      activeAttempt = undefined;
    }
    if (previousContext) {
      invalidateContext(
        previousContext,
        "reconnect",
        new JsonRpcChatError("uncertain-delivery", previousContext.generation),
        "reconnecting",
      );
    } else {
      setState("reconnecting", currentGeneration);
    }
    // This callback runs only after the old generation and handlers are stale.
    safeCall(options.onReconnect);
    return startConnection(signal, true);
  };

  const createSession = async (
    signal?: AbortSignal,
  ): Promise<JsonRpcCreatedSession> => {
    const context = activeContext;
    if (!context?.gatewayReady || currentState.status !== "ready") {
      throw new JsonRpcChatError("not-connected", currentGeneration);
    }

    let created: JsonRpcCreatedSession | undefined;
    await sendRequest(
      context,
      JSON_RPC_SESSION_CREATE_METHOD,
      {},
      "create",
      signal,
      (result) => {
        created = parseCreatedSession(result);
      },
    );
    if (!created) {
      throw new JsonRpcChatError("protocol-violation", currentGeneration);
    }
    // The first prompt addresses the ephemeral live ID. REST reconciliation uses
    // the separately returned stored ID after Hermes persists the first turn.
    selectedSessionId = created.sessionId;
    return created;
  };

  const restore = (
    sessionId = selectedSessionId,
    signal?: AbortSignal,
  ): Promise<void> => {
    if (sessionId === undefined) {
      return Promise.reject(
        new JsonRpcChatError("invalid-input", currentGeneration),
      );
    }
    validateSessionId(sessionId);
    const context = activeContext;
    if (!context?.gatewayReady || currentState.status !== "ready") {
      return Promise.reject(
        new JsonRpcChatError("not-connected", currentGeneration),
      );
    }
    selectedSessionId = sessionId;
    return restoreInternal(context, sessionId, signal);
  };

  const close = (): void => {
    userClosed = true;
    setState("closing", currentGeneration);
    const previousAttempt = activeAttempt;
    if (previousAttempt) {
      currentGeneration = Math.max(
        currentGeneration,
        previousAttempt.generation + 1,
      );
      previousAttempt.controller.abort();
      void previousAttempt.promise.catch(() => undefined);
      activeAttempt = undefined;
    }
    const previousContext = activeContext;
    if (previousContext) {
      invalidateContext(
        previousContext,
        "client-close",
        new JsonRpcChatError("closed", previousContext.generation),
        "closing",
      );
    } else {
      for (const record of [...activeRequests.values()]) {
        markUncertain(record);
      }
      for (const record of [...pendingControls.values()]) {
        settleControl(
          record,
          new JsonRpcChatError("uncertain-delivery", currentGeneration),
        );
      }
      setState("closing", currentGeneration);
    }
    // `closing` is observable during cleanup, but an explicit user close must
    // settle deterministically so callers never remain in a half-closed state.
    setState("offline", currentGeneration);
  };

  const sendPrompt = (
    prompt: string,
    requestOptions: { readonly signal?: AbortSignal } = {},
  ): JsonRpcChatRequest => {
    const context = activeContext;
    if (!context?.gatewayReady || currentState.status !== "ready") {
      throw new JsonRpcChatError("not-connected", currentGeneration);
    }
    validatePrompt(prompt);
    if (selectedSessionId === undefined) {
      throw new JsonRpcChatError("invalid-input", currentGeneration);
    }
    if (requestOptions.signal?.aborted) {
      throw new JsonRpcChatError("cancelled", currentGeneration);
    }
    if (activeRequests.size >= MAX_JSON_RPC_ACTIVE_REQUESTS) {
      throw new JsonRpcChatError("invalid-options", currentGeneration);
    }

    const id = allocateId();
    const promptPayload = {
      jsonrpc: JSON_RPC_VERSION,
      id,
      method: JSON_RPC_PROMPT_METHOD,
      params: { session_id: selectedSessionId, text: prompt },
    };
    assertOutboundFrame(promptPayload, context.generation);
    let resolveCompletion!: (event: JsonRpcCompletionEvent) => void;
    let rejectCompletion!: (error: JsonRpcChatError) => void;
    const completion = new Promise<JsonRpcCompletionEvent>(
      (resolve, reject) => {
        resolveCompletion = resolve;
        rejectCompletion = reject;
      },
    );
    const record: OperationRecord = {
      id,
      status: "submitting",
      acknowledgementReceived: false,
      sequenceMode: "unknown",
      nextSequence: 1,
      resolveCompletion,
      rejectCompletion,
      signal: requestOptions.signal,
    };
    activeRequests.set(id, record);
    record.acknowledgementTimer = setTimeout(() => {
      if (
        activeRequests.get(id) !== record ||
        isTerminalStatus(record.status)
      ) {
        return;
      }
      markUncertain(record);
      if (isCurrentContext(context)) {
        invalidateContext(
          context,
          "ack-timeout",
          new JsonRpcChatError("ack-timeout", currentGeneration),
          "delivery_uncertain",
        );
      }
    }, acknowledgementTimeoutMs);

    if (requestOptions.signal) {
      const onAbort = (): void => handlePromptAbort(record, context);
      requestOptions.signal.addEventListener("abort", onAbort, { once: true });
      record.removeAbortListener = () =>
        requestOptions.signal?.removeEventListener("abort", onAbort);
    }

    try {
      sendFrame(context, promptPayload);
    } catch (error) {
      // The synchronous send error is thrown to the caller, but the request
      // completion still has a rejected observer so cleanup cannot become an
      // unhandled rejection when the caller only needs the synchronous error.
      void completion.catch(() => undefined);
      handleSendFailure(context, error);
      throw error instanceof JsonRpcChatError
        ? error
        : new JsonRpcChatError("uncertain-delivery", context.generation);
    }

    return {
      id,
      completion,
      get state(): JsonRpcChatRequestState {
        return { id: record.id, status: record.status };
      },
      abort: () => handlePromptAbort(record, context),
    };
  };

  const interrupt = (
    requestId: string,
    signal?: AbortSignal,
  ): Promise<void> => {
    validateOpaqueInput(requestId, MAX_JSON_RPC_ID_LENGTH);
    const record = activeRequests.get(requestId);
    if (!record || isTerminalStatus(record.status)) {
      return Promise.reject(
        new JsonRpcChatError("invalid-input", currentGeneration),
      );
    }
    const context = activeContext;
    if (!context?.gatewayReady || selectedSessionId === undefined) {
      return Promise.reject(
        new JsonRpcChatError("not-connected", currentGeneration),
      );
    }
    record.status = "interrupting";
    return sendRequest(
      context,
      JSON_RPC_INTERRUPT_METHOD,
      { session_id: selectedSessionId },
      "interrupt",
      signal,
    );
  };

  const respondToApproval = (
    requestId: string,
    approvalId: string,
    approved: boolean,
    signal?: AbortSignal,
  ): Promise<void> => {
    validateOpaqueInput(requestId, MAX_JSON_RPC_ID_LENGTH);
    validateOpaqueInput(approvalId, MAX_APPROVAL_ID_LENGTH);
    if (typeof approved !== "boolean") {
      throw new JsonRpcChatError("invalid-input", currentGeneration);
    }
    const pending = pendingInteractions.get(requestId);
    if (
      !pending ||
      pending.kind !== "approval" ||
      pending.ownerId !== approvalId ||
      pending.responded
    ) {
      throw new JsonRpcChatError("invalid-input", currentGeneration);
    }
    const context = activeContext;
    if (!context?.gatewayReady || selectedSessionId === undefined) {
      return Promise.reject(
        new JsonRpcChatError("not-connected", currentGeneration),
      );
    }
    pending.responded = true;
    const promise = sendRequest(
      context,
      JSON_RPC_APPROVAL_METHOD,
      {
        session_id: selectedSessionId,
        choice: approved ? "once" : "deny",
        all: false,
      },
      "approval",
      signal,
    );
    return promise.finally(() => pendingInteractions.delete(requestId));
  };

  const answerClarification = (
    requestId: string,
    clarificationId: string,
    answer: string,
    signal?: AbortSignal,
  ): Promise<void> => {
    validateOpaqueInput(requestId, MAX_JSON_RPC_ID_LENGTH);
    validateOpaqueInput(clarificationId, MAX_CLARIFICATION_ID_LENGTH);
    validatePrompt(answer);
    const pending = pendingInteractions.get(requestId);
    if (
      !pending ||
      pending.kind !== "clarification" ||
      pending.ownerId !== clarificationId ||
      pending.responded
    ) {
      throw new JsonRpcChatError("invalid-input", currentGeneration);
    }
    const context = activeContext;
    if (!context?.gatewayReady || selectedSessionId === undefined) {
      return Promise.reject(
        new JsonRpcChatError("not-connected", currentGeneration),
      );
    }
    pending.responded = true;
    const promise = sendRequest(
      context,
      JSON_RPC_CLARIFICATION_METHOD,
      { request_id: requestId, answer },
      "clarification",
      signal,
    );
    return promise.finally(() => pendingInteractions.delete(requestId));
  };

  const abort = (requestId: string): void => {
    validateOpaqueInput(requestId, MAX_JSON_RPC_ID_LENGTH);
    const record = activeRequests.get(requestId);
    if (record) {
      handlePromptAbort(record, activeContext);
    }
  };

  const subscribe = (
    listener: (event: JsonRpcChatEvent) => void,
  ): (() => void) => {
    listeners.add(listener);
    return () => listeners.delete(listener);
  };

  return {
    get state(): JsonRpcConnectionState {
      return currentState;
    },
    get selectedSessionId(): string | undefined {
      return selectedSessionId;
    },
    connect,
    reconnect,
    createSession,
    restore,
    close,
    sendPrompt,
    interrupt,
    respondToApproval,
    answerClarification,
    abort,
    subscribe,
  };

  function isCurrentContext(context: SocketContext): boolean {
    return (
      context.generation === currentGeneration &&
      activeContext === context &&
      !context.closed
    );
  }

  function handlePromptAbort(
    record: OperationRecord,
    context: SocketContext | undefined,
  ): void {
    if (isTerminalStatus(record.status)) {
      return;
    }
    clearTimeoutIfPresent(record.acknowledgementTimer);
    record.acknowledgementTimer = undefined;
    record.status = "cancelled";
    activeRequests.delete(record.id);
    clearInteraction(record.id);
    rememberIgnoredResponse(record.id);
    record.removeAbortListener?.();
    record.rejectCompletion(
      new JsonRpcChatError("cancelled", currentGeneration),
    );
    safeCall(options.onAbort, record.id);

    // Aborting a prompt closes the socket rather than sending a best-effort
    // replayable cancel frame. The next connection must restore server state.
    if (context && isCurrentContext(context)) {
      invalidateContext(
        context,
        "client-close",
        new JsonRpcChatError("cancelled", currentGeneration),
        "offline",
      );
    }
  }
}

export function parseBoundedJsonFrame(
  data: unknown,
  maxFrameBytes = MAX_JSON_RPC_FRAME_BYTES,
): BoundedJsonValue {
  const limit = normalizeFrameLimit(maxFrameBytes);
  const text = decodeFrame(data, limit);
  try {
    return new BoundedJsonParser({
      maxDepth: MAX_JSON_RPC_DEPTH,
      maxNodes: MAX_JSON_NODES,
      maxArrayLength: MAX_JSON_ARRAY_LENGTH,
      maxObjectKeys: MAX_JSON_OBJECT_KEYS,
      maxStringLength: MAX_JSON_RPC_TEXT_LENGTH * 2,
    }).parse(text);
  } catch {
    throw new JsonRpcChatError("malformed-frame");
  }
}

function parseWireMessage(value: BoundedJsonValue): ParsedWireMessage {
  const object = requireObject(value, ["jsonrpc"]);
  if (object.jsonrpc !== JSON_RPC_VERSION) {
    throw new JsonRpcChatError("protocol-violation");
  }
  const hasMethod = Object.prototype.hasOwnProperty.call(object, "method");
  const hasId = Object.prototype.hasOwnProperty.call(object, "id");
  if (hasMethod) {
    const method = requireString(object.method, MAX_JSON_RPC_TEXT_LENGTH);
    if (hasId) {
      return {
        kind: "request",
        id: requireSafeId(object.id),
        method,
        params: object.params ?? null,
      };
    }
    return { kind: "notification", method, params: object.params ?? null };
  }
  if (!hasId) {
    throw new JsonRpcChatError("protocol-violation");
  }
  const hasResult = Object.prototype.hasOwnProperty.call(object, "result");
  const hasError = Object.prototype.hasOwnProperty.call(object, "error");
  if (hasResult === hasError) {
    throw new JsonRpcChatError("protocol-violation");
  }
  const id = object.id === null ? null : requireSafeId(object.id);
  return {
    kind: "response",
    id,
    ...(hasResult
      ? { result: object.result }
      : { error: parseErrorShape(object.error) }),
  };
}

function parseEventEnvelope(value: BoundedJsonValue): ParsedEventEnvelope {
  const object = requireObject(value, ["type"]);
  const type = requireString(object.type, MAX_EVENT_TYPE_LENGTH);
  const payload = object.payload ?? null;
  const payloadObject =
    payload !== null && typeof payload === "object" && !Array.isArray(payload)
      ? (payload as Record<string, BoundedJsonValue>)
      : undefined;
  const sessionId = optionalSessionId(
    object.session_id ??
      object.sessionId ??
      payloadObject?.session_id ??
      payloadObject?.sessionId,
  );
  const requestId = optionalSafeId(
    object.request_id ??
      object.requestId ??
      payloadObject?.request_id ??
      payloadObject?.requestId,
    MAX_JSON_RPC_ID_LENGTH,
  );
  const sequenceValue = object.sequence ?? payloadObject?.sequence;
  const sequence =
    sequenceValue === undefined ? undefined : requireSequence(sequenceValue);
  return {
    type,
    ...(sessionId ? { sessionId } : {}),
    ...(requestId ? { requestId } : {}),
    ...(sequence !== undefined ? { sequence } : {}),
    payload,
  };
}

function parseCreatedSession(value: BoundedJsonValue): JsonRpcCreatedSession {
  const object = requireObject(value, ["session_id", "stored_session_id"]);
  const sessionId = requireString(object.session_id, MAX_SESSION_ID_LENGTH);
  const storedSessionId = requireString(
    object.stored_session_id,
    MAX_SESSION_ID_LENGTH,
  );
  if (!isSafeSessionId(sessionId) || !isSafeSessionId(storedSessionId)) {
    throw new JsonRpcChatError("protocol-violation");
  }

  let model: string | undefined;
  if (object.info !== undefined) {
    const info = requireObject(object.info, []);
    if (info.model !== undefined) {
      const candidate = requireString(info.model, MAX_JSON_RPC_TEXT_LENGTH);
      if (candidate.length > 0) model = candidate;
    }
  }
  return { sessionId, storedSessionId, ...(model ? { model } : {}) };
}

function parseErrorShape(
  value: BoundedJsonValue | undefined,
): JsonRpcErrorShape {
  const object = requireObject(value ?? null, ["code", "message"]);
  if (
    typeof object.code !== "number" ||
    !Number.isInteger(object.code) ||
    object.code < -32_768 ||
    object.code > -32_000 ||
    typeof object.message !== "string" ||
    object.message.length > MAX_JSON_RPC_TEXT_LENGTH
  ) {
    throw new JsonRpcChatError("protocol-violation");
  }
  return { code: object.code, message: object.message };
}

function requireObject(
  value: BoundedJsonValue,
  requiredKeys: readonly string[],
): Record<string, BoundedJsonValue> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new JsonRpcChatError("protocol-violation");
  }
  const object = value as Record<string, BoundedJsonValue>;
  for (const key of requiredKeys) {
    if (!(key in object)) {
      throw new JsonRpcChatError("protocol-violation");
    }
  }
  return object;
}

function requireString(
  value: BoundedJsonValue | undefined,
  maxLength: number,
): string {
  if (
    typeof value !== "string" ||
    value.length > maxLength ||
    containsDisallowedControl(value)
  ) {
    throw new JsonRpcChatError("protocol-violation");
  }
  return value;
}

function requireSafeId(value: BoundedJsonValue | undefined): string {
  if (typeof value !== "string" || !isSafeId(value)) {
    throw new JsonRpcChatError("protocol-violation");
  }
  return value;
}

function optionalSafeId(
  value: BoundedJsonValue | undefined,
  maxLength: number,
): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (
    typeof value !== "string" ||
    value.length > maxLength ||
    !isSafeId(value)
  ) {
    throw new JsonRpcChatError("protocol-violation");
  }
  return value;
}

function optionalSessionId(
  value: BoundedJsonValue | undefined,
): string | undefined {
  if (value === undefined || value === null || value === "") {
    // Official session-less global broadcasts use an empty string sentinel.
    // Normalize it to absence; operation events still require an owner later.
    return undefined;
  }
  if (typeof value !== "string" || !isSafeSessionId(value)) {
    throw new JsonRpcChatError("protocol-violation");
  }
  return value;
}

function requireSequence(value: BoundedJsonValue | undefined): number {
  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value < 1 ||
    value > MAX_JSON_RPC_SEQUENCE
  ) {
    throw new JsonRpcChatError("protocol-violation");
  }
  return value;
}

function validateApprovalState(payload: BoundedJsonValue): void {
  if (
    payload === null ||
    typeof payload !== "object" ||
    Array.isArray(payload)
  ) {
    throw new JsonRpcChatError("protocol-violation");
  }
  const approval = payload as Record<string, BoundedJsonValue>;
  const state = approval.state;
  const approved = approval.approved;
  if (state === "requested" && approved !== null) {
    throw new JsonRpcChatError("protocol-violation");
  }
  if (state === "resolved" && typeof approved !== "boolean") {
    throw new JsonRpcChatError("protocol-violation");
  }
}

function findInteractionOwner(
  event: ParsedEventEnvelope,
  kind: "approval" | "clarification",
): string {
  const payload =
    event.payload !== null &&
    typeof event.payload === "object" &&
    !Array.isArray(event.payload)
      ? (event.payload as Record<string, BoundedJsonValue>)
      : undefined;
  const key = kind === "approval" ? "approval_id" : "clarification_id";
  const aliases =
    kind === "approval"
      ? ["approval_id", "approvalId", "id", "request_id"]
      : ["clarification_id", "clarificationId", "request_id", "id"];
  for (const alias of aliases) {
    const value =
      (alias === "request_id" ? event.requestId : undefined) ??
      payload?.[alias] ??
      payload?.[key];
    if (value !== undefined) {
      return requireOpaqueString(
        value,
        kind === "approval"
          ? MAX_APPROVAL_ID_LENGTH
          : MAX_CLARIFICATION_ID_LENGTH,
      );
    }
  }
  // The source owns the detailed approval/clarification payload shape. When it
  // omits an owner ID, derive a local opaque owner from the active request and
  // optional sequence; it is never echoed on the wire.
  const requestPart = (event.requestId ?? "session").slice(0, 96);
  const fallback = `${kind}-${requestPart}-${event.sequence ?? 1}`;
  return requireOpaqueString(
    fallback,
    kind === "approval" ? MAX_APPROVAL_ID_LENGTH : MAX_CLARIFICATION_ID_LENGTH,
  );
}

function requireOpaqueString(
  value: BoundedJsonValue | undefined,
  maxLength: number,
): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maxLength ||
    !isSafeId(value)
  ) {
    throw new JsonRpcChatError("protocol-violation");
  }
  return value;
}

function isCompleteCompatibilityEvidence(
  value: JsonRpcCompatibilityEvidenceInput | undefined,
): value is JsonRpcCompatibilityEvidenceInput {
  if (value === undefined || value === null || typeof value !== "object") {
    return false;
  }
  const deployment = value.deployment;
  const routeManifest = value.routeManifest;
  const sourceReview = value.sourceReview;
  const proxyProof = value.proxyProof;
  return (
    deployment !== null &&
    typeof deployment === "object" &&
    isBoundedEvidenceText(deployment.identity) &&
    isBoundedEvidenceText(deployment.trustChannel) &&
    (deployment.scope === "fixture_only" ||
      deployment.scope === "official_image") &&
    routeManifest !== null &&
    typeof routeManifest === "object" &&
    routeManifest.revision === DASHBOARD_CONTRACT &&
    isArtifactEvidence(routeManifest) &&
    isArtifactEvidence(sourceReview) &&
    isArtifactEvidence(proxyProof)
  );
}

function isArtifactEvidence(value: unknown): value is JsonRpcArtifactEvidence {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const artifact = value as JsonRpcArtifactEvidence;
  return (
    isBoundedEvidenceText(artifact.path) &&
    typeof artifact.sha256 === "string" &&
    SHA256_PATTERN.test(artifact.sha256) &&
    Number.isInteger(artifact.sizeBytes) &&
    artifact.sizeBytes >= 0 &&
    artifact.sizeBytes <= 10_000_000
  );
}

function isBoundedEvidenceText(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 256 &&
    !containsDisallowedControl(value)
  );
}

function validateTicket(ticket: unknown): asserts ticket is string {
  if (
    typeof ticket !== "string" ||
    ticket.length === 0 ||
    ticket.length > MAX_TICKET_LENGTH ||
    !TICKET_PATTERN.test(ticket)
  ) {
    throw new JsonRpcChatError("invalid-ticket");
  }
}

function validatePrompt(prompt: unknown): asserts prompt is string {
  if (
    typeof prompt !== "string" ||
    prompt.length === 0 ||
    prompt.length > MAX_JSON_RPC_PROMPT_LENGTH ||
    containsDisallowedControl(prompt)
  ) {
    throw new JsonRpcChatError("invalid-input");
  }
}

function validateSessionId(sessionId: unknown): asserts sessionId is string {
  if (typeof sessionId !== "string" || !isSafeSessionId(sessionId)) {
    throw new JsonRpcChatError("invalid-input");
  }
}

function validateOpaqueInput(
  value: unknown,
  maxLength: number,
): asserts value is string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maxLength ||
    !isSafeId(value)
  ) {
    throw new JsonRpcChatError("invalid-input");
  }
}

function normalizeFrameLimit(value: number | undefined): number {
  const limit = value ?? MAX_JSON_RPC_FRAME_BYTES;
  if (
    !Number.isInteger(limit) ||
    limit < MIN_FRAME_BYTES ||
    limit > MAX_JSON_RPC_FRAME_BYTES
  ) {
    throw new JsonRpcChatError("invalid-options");
  }
  return limit;
}

function normalizeTimeout(value: number | undefined): number {
  const timeout = value ?? DEFAULT_GATEWAY_READY_TIMEOUT_MS;
  if (!Number.isInteger(timeout) || timeout < 1 || timeout > 120_000) {
    throw new JsonRpcChatError("invalid-options");
  }
  return timeout;
}

function isSafeId(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= MAX_JSON_RPC_ID_LENGTH &&
    REQUEST_ID_PATTERN.test(value)
  );
}

function isSafeSessionId(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= MAX_SESSION_ID_LENGTH &&
    SESSION_ID_PATTERN.test(value)
  );
}

function isIdReserved(
  id: string,
  requests: Map<string, OperationRecord>,
  controls: Map<string, ControlRecord>,
): boolean {
  return requests.has(id) || controls.has(id);
}

function isTerminalStatus(status: JsonRpcDeliveryStatus): boolean {
  return (
    status === "completed" ||
    status === "cancelled" ||
    status === "failed" ||
    status === "uncertain-delivery"
  );
}

function isInteractiveEventName(name: string): boolean {
  return (
    SENSITIVE_INTERACTIVE_EVENT_NAMES.has(name) || name.endsWith(".request")
  );
}

function classifyCloseCode(code: number | undefined): JsonRpcCloseObservation {
  const classification: JsonRpcCloseClassification =
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
                  : "unsupported";
  return { code, classification };
}

function statusForClose(
  observation: JsonRpcCloseObservation,
): JsonRpcConnectionStatus {
  switch (observation.classification) {
    case "authentication-rejected":
      return "auth_required";
    case "host-or-origin-rejected":
    case "embedded-chat-disabled":
    case "unsupported":
      return "incompatible";
    default:
      return "failed";
  }
}

function containsDisallowedControl(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (
      codePoint !== undefined &&
      codePoint < 0x20 &&
      codePoint !== 0x09 &&
      codePoint !== 0x0a &&
      codePoint !== 0x0d
    ) {
      return true;
    }
  }
  return false;
}

function byteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function decodeFrame(data: unknown, maxFrameBytes: number): string {
  if (typeof data === "string") {
    if (byteLength(data) > maxFrameBytes) {
      throw new JsonRpcChatError("frame-too-large");
    }
    return data;
  }
  let bytes: Uint8Array;
  if (data instanceof ArrayBuffer) {
    bytes = new Uint8Array(data);
  } else if (data instanceof Uint8Array) {
    bytes = data;
  } else {
    throw new JsonRpcChatError("malformed-frame");
  }
  if (bytes.byteLength > maxFrameBytes) {
    throw new JsonRpcChatError("frame-too-large");
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new JsonRpcChatError("malformed-frame");
  }
}

function clearTimeoutIfPresent(
  timer: ReturnType<typeof setTimeout> | undefined,
): void {
  if (timer !== undefined) {
    clearTimeout(timer);
  }
}

function linkAbort(
  signal: AbortSignal | undefined,
  controller: AbortController,
): () => void {
  if (!signal) {
    return () => undefined;
  }
  const onAbort = (): void => controller.abort();
  if (signal.aborted) {
    controller.abort();
    return () => undefined;
  }
  signal.addEventListener("abort", onAbort, { once: true });
  return () => signal.removeEventListener("abort", onAbort);
}

function throwIfAborted(signal: AbortSignal): void {
  if (signal.aborted) {
    throw new JsonRpcChatError("aborted");
  }
}

function sanitizeConnectionError(
  error: unknown,
  signal: AbortSignal,
  generation: number,
): JsonRpcChatError {
  if (
    signal.aborted ||
    (error instanceof JsonRpcChatError && error.code === "aborted")
  ) {
    return new JsonRpcChatError("aborted", generation);
  }
  if (error instanceof JsonRpcChatError) {
    return new JsonRpcChatError(error.code, generation);
  }
  return new JsonRpcChatError("connection-failed", generation);
}

function createIdempotentSocketCloser(): (socket: JsonRpcWebSocket) => void {
  const closedSockets = new WeakSet<object>();
  return (socket: JsonRpcWebSocket): void => {
    if (closedSockets.has(socket)) return;
    closedSockets.add(socket);
    closeSocketForAwait(socket);
  };
}

function closeSocketForAwait(socket: JsonRpcWebSocket): void {
  try {
    socket.close(1000, "cancelled");
  } catch {
    // The late adapter result is discarded without retaining its error.
  }
}

function evaluateGate(
  gate: JsonRpcCompatibilityGate | undefined,
  evidence: JsonRpcCompatibilityEvidence,
  signal: AbortSignal | undefined,
  timeoutMs: number,
): Promise<boolean> {
  if (!gate || !signal) {
    return Promise.resolve(false);
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  const gateResult = Promise.resolve()
    .then(() => gate(evidence, signal))
    .then(
      (result) =>
        result === true ||
        (result !== null &&
          typeof result === "object" &&
          result.passed === true),
      () => false,
    );
  const deadline = new Promise<boolean>((resolve) => {
    timer = setTimeout(() => resolve(false), timeoutMs);
  });
  return awaitWithAbort(Promise.race([gateResult, deadline]), signal).finally(
    () => {
      clearTimeoutIfPresent(timer);
    },
  );
}

function awaitWithAbort<T>(
  promise: Promise<T>,
  signal: AbortSignal,
  onLateResolve?: (value: T) => void,
): Promise<T> {
  const handleLateResolve = (value: T): void => {
    try {
      onLateResolve?.(value);
    } catch {
      // Late cleanup cannot replace the bounded cancellation result.
    }
  };

  if (signal.aborted) {
    // The factory may have produced a socket before the already-aborted signal
    // was observed. Attach the late hook so that result is closed and discarded.
    promise.then(handleLateResolve, () => undefined);
    return Promise.reject(new JsonRpcChatError("aborted"));
  }
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const cleanup = (): void => signal.removeEventListener("abort", onAbort);
    const settle = (callback: () => void): void => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      callback();
    };
    const onAbort = (): void =>
      settle(() => reject(new JsonRpcChatError("aborted")));
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        if (settled) {
          handleLateResolve(value);
          return;
        }
        settle(() => resolve(value));
      },
      (error: unknown) => settle(() => reject(error)),
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
      throw new Error("empty");
    }
    const value = this.parseValue(text, 0);
    this.skipWhitespace(text);
    if (this.index !== text.length) {
      throw new Error("trailing");
    }
    return value;
  }

  private parseValue(text: string, depth: number): BoundedJsonValue {
    this.skipWhitespace(text);
    const character = text[this.index];
    if (character === "{") {
      const containerDepth = depth + 1;
      if (containerDepth > this.limits.maxDepth) {
        throw new Error("depth");
      }
      return this.parseObject(text, containerDepth);
    }
    if (character === "[") {
      const containerDepth = depth + 1;
      if (containerDepth > this.limits.maxDepth) {
        throw new Error("depth");
      }
      return this.parseArray(text, containerDepth);
    }
    if (character === '"') {
      return this.parseString(text);
    }
    if (character === "t" && text.startsWith("true", this.index)) {
      this.index += 4;
      this.countNode();
      return true;
    }
    if (character === "f" && text.startsWith("false", this.index)) {
      this.index += 5;
      this.countNode();
      return false;
    }
    if (character === "n" && text.startsWith("null", this.index)) {
      this.index += 4;
      this.countNode();
      return null;
    }
    return this.parseNumber(text);
  }

  private parseObject(
    text: string,
    depth: number,
  ): { [key: string]: BoundedJsonValue } {
    this.index += 1;
    this.countNode();
    const result: { [key: string]: BoundedJsonValue } = Object.create(null) as {
      [key: string]: BoundedJsonValue;
    };
    const keys = new Set<string>();
    this.skipWhitespace(text);
    if (text[this.index] === "}") {
      this.index += 1;
      return result;
    }
    while (this.index < text.length) {
      if (keys.size >= this.limits.maxObjectKeys || text[this.index] !== '"') {
        throw new Error("object");
      }
      const key = this.parseString(text);
      if (keys.has(key)) {
        throw new Error("duplicate");
      }
      keys.add(key);
      this.skipWhitespace(text);
      if (text[this.index] !== ":") {
        throw new Error("colon");
      }
      this.index += 1;
      result[key] = this.parseValue(text, depth);
      this.skipWhitespace(text);
      if (text[this.index] === "}") {
        this.index += 1;
        return result;
      }
      if (text[this.index] !== ",") {
        throw new Error("comma");
      }
      this.index += 1;
      this.skipWhitespace(text);
    }
    throw new Error("object-end");
  }

  private parseArray(text: string, depth: number): BoundedJsonValue[] {
    this.index += 1;
    this.countNode();
    const result: BoundedJsonValue[] = [];
    this.skipWhitespace(text);
    if (text[this.index] === "]") {
      this.index += 1;
      return result;
    }
    while (this.index < text.length) {
      if (result.length >= this.limits.maxArrayLength) {
        throw new Error("array");
      }
      result.push(this.parseValue(text, depth));
      this.skipWhitespace(text);
      if (text[this.index] === "]") {
        this.index += 1;
        return result;
      }
      if (text[this.index] !== ",") {
        throw new Error("comma");
      }
      this.index += 1;
      this.skipWhitespace(text);
    }
    throw new Error("array-end");
  }

  private parseString(text: string): string {
    if (text[this.index] !== '"') {
      throw new Error("string");
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
          throw new Error("string");
        }
        if (
          typeof value !== "string" ||
          value.length > this.limits.maxStringLength ||
          containsDisallowedControl(value)
        ) {
          throw new Error("string");
        }
        this.countNode();
        return value;
      }
      if (character === "\\") {
        this.index += 1;
        const escape = text[this.index];
        if (!escape || !'"\\/bfnrtu'.includes(escape)) {
          throw new Error("escape");
        }
        if (escape === "u") {
          const codePoint = text.slice(this.index + 1, this.index + 5);
          if (!/^[0-9a-fA-F]{4}$/u.test(codePoint)) {
            throw new Error("unicode");
          }
          this.index += 4;
        }
      } else if (character < " ") {
        throw new Error("control");
      }
      this.index += 1;
      if (this.index - start > this.limits.maxStringLength * 6 + 2) {
        throw new Error("string-size");
      }
    }
    throw new Error("string-end");
  }

  private parseNumber(text: string): number {
    const match = text
      .slice(this.index)
      .match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u);
    if (!match) {
      throw new Error("number");
    }
    const literal = match[0];
    const value = Number(literal);
    if (
      !Number.isFinite(value) ||
      (Number.isInteger(value) && Math.abs(value) > Number.MAX_SAFE_INTEGER)
    ) {
      throw new Error("number");
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
      throw new Error("nodes");
    }
  }
}
