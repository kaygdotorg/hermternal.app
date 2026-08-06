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
        "3c6b44dc8dd90836f4fc5c5158d459959c569fb811db4b198e87d78ea5010197",
      sizeBytes: 17_859,
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
        "52fb8d0fb9f21ee7a80c5796343c3893a7f715c93fd47e832f5be098bc865212",
      sizeBytes: 16_167,
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
  let preparedSocket: JsonRpcWebSocket | undefined;

  const ticketClient = createWsTicketClient<JsonRpcWebSocket>({
    request: createWsTicketRequestBoundary(fetcher),
    connect: (upgradeUrl, signal) => {
      const socket = createSocket(upgradeUrl.toString());
      const closeOnAbort = (): void => {
        try {
          socket.close(1000, "cancelled");
        } catch {
          // The transport reports only its fixed cancellation diagnostic.
        }
      };
      signal.addEventListener("abort", closeOnAbort, { once: true });
      return socket;
    },
  });

  return createJsonRpcChatTransport({
    ...options,
    ticketProvider: async (signal) => {
      if (preparedSocket) {
        throw new JsonRpcChatError("invalid-options");
      }
      preparedSocket = await ticketClient.open(signal);
      return CONSUMED_TICKET_MARKER;
    },
    createWebSocket: (upgrade, signal) => {
      if (
        signal.aborted ||
        upgrade.path !== JSON_RPC_WS_PATH ||
        upgrade.query.ticket !== CONSUMED_TICKET_MARKER ||
        !preparedSocket
      ) {
        throw new JsonRpcChatError("connection-failed");
      }
      const socket = preparedSocket;
      preparedSocket = undefined;
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
