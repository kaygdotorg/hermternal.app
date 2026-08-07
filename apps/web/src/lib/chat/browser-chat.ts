import {
  DASHBOARD_CONTRACT,
  HERMES_SOURCE_SHA,
  JSON_RPC_WS_PATH,
  JsonRpcChatError,
  createJsonRpcChatTransport,
  type BoundedJsonValue,
  type JsonRpcChatOptions,
  type JsonRpcChatTransport,
  type JsonRpcCompatibilityEvidence,
  type JsonRpcWebSocket,
} from "./json-rpc-chat";
import {
  WsTicketError,
  createWsTicketClient,
  createWsTicketRequestBoundary,
  type WsTicketFetch,
} from "./ws-ticket";

export const OFFICIAL_HERMES_IMAGE =
  "docker.io/nousresearch/hermes-agent:v2026.8.3@sha256:16788311e2fa3035456bdc1bafb8ec2b1777db64ebf020af9bb7eb73c3712c9e" as const;

const CONSUMED_TICKET_MARKER = "ticket-consumed-by-browser-adapter";

const OFFICIAL_COMPATIBILITY_EVIDENCE: JsonRpcChatOptions["compatibilityEvidence"] =
  {
    deployment: {
      identity: OFFICIAL_HERMES_IMAGE,
      trustChannel: "official-upstream-image-digest",
      scope: "official_image",
    },
    routeManifest: {
      path: "contracts/hermes-dashboard/manifest.md",
      revision: DASHBOARD_CONTRACT,
      sha256:
        "680e1ef387c403538a8fa0959243f7414ad12c4d33cecae4fb1081a509c3f1b5",
      sizeBytes: 18_163,
    },
    sourceReview: {
      path: "contracts/fixtures/source-audit/planning-reconciliation/planning_review.json",
      sha256:
        "0a84cba82e6e966ab35de187f560fd38d6e10c43dd2204062d6ebf2bc5c32077",
      sizeBytes: 20_045,
    },
    proxyProof: {
      path: "docs/deployment/proof-matrix.md",
      sha256:
        "99945f3193f5ea9aa72c00c786d4c447c117774803ac036b1617575f0da8944d",
      sizeBytes: 18_047,
    },
  };

export type BrowserWebSocketFactory = (url: string) => JsonRpcWebSocket;

export interface BrowserChatOptions extends Omit<
  JsonRpcChatOptions,
  | "ticketProvider"
  | "createWebSocket"
  | "compatibilityEvidence"
  | "verifyAttestation"
  | "runBehavioralProbe"
> {
  readonly fetch?: WsTicketFetch;
  readonly createSocket?: BrowserWebSocketFactory;
}

interface PreparedSocketAttempt {
  readonly token: number;
  readonly signal: AbortSignal;
  socket?: JsonRpcWebSocket;
  unlinkAbort?: () => void;
}

/**
 * Compose the reviewed ticket and JSON-RPC boundaries for the official Hermes
 * browser lane. The ticket client constructs the real upgrade URL and hands it
 * directly to WebSocket. JSON-RPC receives only a fixed consumed marker, so the
 * raw ticket is never copied into controller state, callbacks, or diagnostics.
 */
export function createBrowserChatTransport(
  options: BrowserChatOptions,
): JsonRpcChatTransport {
  const fetcher = options.fetch ?? globalThis.fetch?.bind(globalThis);
  if (!fetcher) {
    throw new JsonRpcChatError("invalid-options");
  }
  const createSocket = options.createSocket ?? defaultSocketFactory;
  let preparedAttempt: PreparedSocketAttempt | undefined;
  let latestAttempt: PreparedSocketAttempt | undefined;
  let nextAttemptToken = 0;
  const attemptsBySignal = new WeakMap<AbortSignal, PreparedSocketAttempt>();
  const unlinkSocketAbort = new WeakMap<JsonRpcWebSocket, () => void>();

  const releaseSocketAbort = (socket: JsonRpcWebSocket): void => {
    unlinkSocketAbort.get(socket)?.();
    unlinkSocketAbort.delete(socket);
  };

  const forgetAttempt = (attempt: PreparedSocketAttempt): void => {
    attempt.unlinkAbort?.();
    attempt.unlinkAbort = undefined;
    if (attemptsBySignal.get(attempt.signal) === attempt) {
      attemptsBySignal.delete(attempt.signal);
    }
    if (latestAttempt === attempt) latestAttempt = undefined;
  };

  const closeAttemptSocket = (attempt: PreparedSocketAttempt): void => {
    const socket = attempt.socket;
    attempt.socket = undefined;
    forgetAttempt(attempt);
    if (socket) {
      releaseSocketAbort(socket);
      closeSocket(socket);
    }
  };

  const closePreparedSocket = (owner?: PreparedSocketAttempt): void => {
    const current = preparedAttempt;
    if (!current || (owner && current !== owner)) return;
    preparedAttempt = undefined;
    closeAttemptSocket(current);
  };

  const ticketClient = createWsTicketClient<JsonRpcWebSocket>({
    request: createWsTicketRequestBoundary(fetcher),
    connect: (upgradeUrl, signal) => {
      // Both the ticket boundary's late-result hook and this adapter's abort
      // ownership can observe one cancellation. The wrapper makes that shared
      // boundary idempotent before either path reaches the real socket.
      const socket = createIdempotentSocket(createSocket(upgradeUrl.toString()));
      const closeOnAbort = (): void => {
        releaseSocketAbort(socket);
        socket.close(1000, "cancelled");
      };
      signal.addEventListener("abort", closeOnAbort, { once: true });
      unlinkSocketAbort.set(socket, () =>
        signal.removeEventListener("abort", closeOnAbort),
      );
      // A synchronous factory can abort between returning the socket and this
      // listener setup. Close immediately and remove the no-longer-needed
      // ownership entry; the wrapper still absorbs any late cleanup call.
      if (signal.aborted) {
        releaseSocketAbort(socket);
        socket.close(1000, "cancelled");
      }
      return socket;
    },
  });

  return createJsonRpcChatTransport({
    ...options,
    ticketProvider: async (signal) => {
      const attempt: PreparedSocketAttempt = {
        token: ++nextAttemptToken,
        signal
      };
      attemptsBySignal.set(signal, attempt);
      latestAttempt = attempt;
      // A newer attempt owns the single prepared slot. Stale ticket/open
      // continuations retain only their attempt identity and cannot close it.
      closePreparedSocket();

      let socket: JsonRpcWebSocket;
      try {
        socket = await ticketClient.open(signal);
      } catch (error) {
        closePreparedSocket(attempt);
        // Only a genuine 401 means the browser is unauthenticated. Keep 403
        // and other ticket failures out of the permanent auth-required state.
        if (
          error instanceof WsTicketError &&
          error.code === "authentication-failed" &&
          error.status === 401
        ) {
          throw new JsonRpcChatError("authentication-required");
        }
        throw error;
      }

      attempt.socket = socket;
      // The ticket client can resolve immediately before the outer JSON-RPC
      // await observes cancellation or a newer attempt. Never install a stale
      // socket in the shared prepared slot.
      if (signal.aborted || latestAttempt !== attempt) {
        closeAttemptSocket(attempt);
        throw new JsonRpcChatError("aborted");
      }

      preparedAttempt = attempt;
      const onAbort = (): void => {
        if (preparedAttempt === attempt) {
          closePreparedSocket(attempt);
        } else {
          closeAttemptSocket(attempt);
        }
      };
      signal.addEventListener("abort", onAbort, { once: true });
      attempt.unlinkAbort = () => signal.removeEventListener("abort", onAbort);
      if (signal.aborted || latestAttempt !== attempt) {
        closePreparedSocket(attempt);
        throw new JsonRpcChatError("aborted");
      }
      return CONSUMED_TICKET_MARKER;
    },
    createWebSocket: (upgrade, signal) => {
      const attempt = attemptsBySignal.get(signal);
      const prepared = preparedAttempt;
      if (
        signal.aborted ||
        upgrade.path !== JSON_RPC_WS_PATH ||
        upgrade.query.ticket !== CONSUMED_TICKET_MARKER ||
        !attempt ||
        latestAttempt !== attempt ||
        prepared !== attempt ||
        !prepared.socket
      ) {
        // Cleanup is identity-scoped. An old invalid createWebSocket call must
        // not close a newer prepared socket.
        if (attempt) closePreparedSocket(attempt);
        throw new JsonRpcChatError(
          signal.aborted ? "aborted" : "connection-failed",
        );
      }
      const socket = prepared.socket;
      preparedAttempt = undefined;
      forgetAttempt(attempt);
      releaseSocketAbort(socket);
      return socket;
    },
    compatibilityEvidence: OFFICIAL_COMPATIBILITY_EVIDENCE,
    verifyAttestation: verifyOfficialEvidence,
    // The source-backed live probe requires both documented gateway.ready keys.
    // Their values remain opaque because the manifest does not pin full shapes.
    runBehavioralProbe: (evidence) =>
      verifyGatewayReadyBehavior(evidence.gatewayReadyPayload),
  });
}

function createIdempotentSocket(socket: JsonRpcWebSocket): JsonRpcWebSocket {
  let closed = false;
  return {
    get onopen() {
      return socket.onopen;
    },
    set onopen(handler: ((event?: unknown) => void) | null) {
      socket.onopen = handler;
    },
    get onmessage() {
      return socket.onmessage;
    },
    set onmessage(handler: ((event: { readonly data: unknown }) => void) | null) {
      socket.onmessage = handler;
    },
    get onerror() {
      return socket.onerror;
    },
    set onerror(handler: ((event?: unknown) => void) | null) {
      socket.onerror = handler;
    },
    get onclose() {
      return socket.onclose;
    },
    set onclose(handler: ((event?: { readonly code?: number; readonly reason?: string }) => void) | null) {
      socket.onclose = handler;
    },
    send: (data) => socket.send(data),
    close: (code, reason) => {
      if (closed) return;
      closed = true;
      try {
        socket.close(code, reason);
      } catch {
        // The first close owns the bounded cancellation outcome.
      }
    },
    get readyState() {
      return socket.readyState;
    },
  };
}

function closeSocket(socket: JsonRpcWebSocket): void {
  try {
    socket.close(1000, "cancelled");
  } catch {
    // Cleanup cannot replace the bounded connection diagnostic.
  }
}

function defaultSocketFactory(url: string): JsonRpcWebSocket {
  if (typeof WebSocket === "undefined") {
    throw new JsonRpcChatError("invalid-options");
  }
  const nativeSocket = new WebSocket(url);
  const adapter: JsonRpcWebSocket = {
    onopen: null,
    onmessage: null,
    onerror: null,
    onclose: null,
    send: (data) => nativeSocket.send(data),
    close: (code, reason) => nativeSocket.close(code, reason),
    get readyState() {
      return nativeSocket.readyState;
    },
  };
  nativeSocket.onopen = (event) => adapter.onopen?.(event);
  nativeSocket.onmessage = (event) => adapter.onmessage?.({ data: event.data });
  nativeSocket.onerror = (event) => adapter.onerror?.(event);
  nativeSocket.onclose = (event) =>
    adapter.onclose?.({ code: event.code, reason: event.reason });
  return adapter;
}

function verifyGatewayReadyBehavior(payload: BoundedJsonValue): boolean {
  return (
    payload !== null &&
    typeof payload === "object" &&
    !Array.isArray(payload) &&
    Object.prototype.hasOwnProperty.call(payload, "skin") &&
    Object.prototype.hasOwnProperty.call(payload, "change_events")
  );
}

function verifyOfficialEvidence(
  evidence: JsonRpcCompatibilityEvidence,
): boolean {
  return (
    evidence.contract === DASHBOARD_CONTRACT &&
    evidence.hermesSourceSha === HERMES_SOURCE_SHA &&
    evidence.websocketPath === JSON_RPC_WS_PATH &&
    evidence.deployment.identity === OFFICIAL_HERMES_IMAGE &&
    evidence.deployment.trustChannel === "official-upstream-image-digest" &&
    evidence.deployment.scope === "official_image" &&
    evidence.routeManifest.sha256 ===
      OFFICIAL_COMPATIBILITY_EVIDENCE.routeManifest.sha256 &&
    evidence.sourceReview.sha256 ===
      OFFICIAL_COMPATIBILITY_EVIDENCE.sourceReview.sha256 &&
    evidence.proxyProof.sha256 ===
      OFFICIAL_COMPATIBILITY_EVIDENCE.proxyProof.sha256
  );
}
