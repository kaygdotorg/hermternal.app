import { parseStrictJson } from "../transport/strict-json";

export const WS_TICKET_PATH = "/api/auth/ws-ticket" as const;
export const CHAT_WEBSOCKET_PATH = "/api/ws" as const;
export const WS_TICKET_TTL_SECONDS = 30 as const;
export const MAX_WS_TICKET_LENGTH = 512 as const;
export const MAX_WS_TICKET_RESPONSE_BYTES = 2 * 1024;
export const MAX_WS_TICKET_ERROR_LENGTH = 240 as const;
export const DEFAULT_WS_TICKET_ATTEMPT_TIMEOUT_MS = 5_000 as const;

// A hostile response stream must not hold the ticket boundary open while its
// cancellation promise settles. The reader lock is released after this bound.
const WS_TICKET_RESPONSE_CANCEL_TIMEOUT_MS = 100;

export type WsTicketErrorCode =
  | "cancelled"
  | "authentication-failed"
  | "response-invalid"
  | "request-failed"
  | "upgrade-failed"
  | "origin-unavailable";

const ERROR_MESSAGES: Record<WsTicketErrorCode, string> = {
  cancelled: "WebSocket ticket acquisition was cancelled.",
  "authentication-failed": "WebSocket ticket authentication failed.",
  "response-invalid": "WebSocket ticket response was invalid.",
  "request-failed": "WebSocket ticket request failed.",
  "upgrade-failed": "WebSocket upgrade failed.",
  "origin-unavailable": "WebSocket upgrade origin was unavailable.",
};

/**
 * Public failure shape for this boundary. Messages are selected from a closed
 * set so response bodies, cookie values, bearer values, and ticket fragments
 * can never cross into retained error text.
 */
export class WsTicketError extends Error {
  readonly code: WsTicketErrorCode;
  readonly status?: number;
  readonly retryable: boolean;

  constructor(code: WsTicketErrorCode, status?: number) {
    super(ERROR_MESSAGES[code].slice(0, MAX_WS_TICKET_ERROR_LENGTH));
    this.name = code === "cancelled" ? "AbortError" : "WsTicketError";
    this.code = code;
    this.status = normalizeStatus(status);
    this.retryable = code === "request-failed" || code === "upgrade-failed";
  }
}

export class WsTicketCancelledError extends WsTicketError {
  constructor() {
    super("cancelled");
  }
}

/**
 * The request boundary intentionally has no headers or credential input. The
 * browser's protected same-origin cookie is selected by the adapter, while a
 * bearer value cannot be supplied or promoted into the WebSocket upgrade.
 */
export interface WsTicketRequestInput {
  readonly method: "POST";
  readonly path: typeof WS_TICKET_PATH;
  readonly credentials: "same-origin";
  readonly signal: AbortSignal;
}

export type WsTicketRequestBoundary = (
  input: WsTicketRequestInput,
) => Promise<unknown>;

export interface WsTicketFetch {
  (input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
}

export type WsTicketUpgradeBoundary<Connection> = (
  upgradeUrl: URL,
  signal: AbortSignal,
) => Connection | Promise<Connection>;

export interface WsTicketClientOptions<Connection> {
  readonly request: WsTicketRequestBoundary;
  readonly connect: WsTicketUpgradeBoundary<Connection>;
}

export interface WsTicketClient<Connection> {
  /** Start one attempt, or coalesce with the currently active attempt. */
  open(signal?: AbortSignal): Promise<Connection>;
  /** Explicit recovery entry point; it never performs an automatic retry. */
  retry(signal?: AbortSignal): Promise<Connection>;
}

/**
 * Adapt an injected fetch implementation to the narrow W-05 request shape.
 * Keeping fetch injected makes the client deterministic in Vitest and lets
 * W-06 provide its own typed transport without changing this security seam.
 */
export function createWsTicketRequestBoundary(
  fetcher: WsTicketFetch,
): WsTicketRequestBoundary {
  return async ({ method, path, credentials, signal }): Promise<unknown> => {
    if (
      method !== "POST" ||
      path !== WS_TICKET_PATH ||
      credentials !== "same-origin"
    ) {
      throw new WsTicketError("request-failed");
    }

    try {
      const response = await fetcher(path, {
        method,
        mode: "same-origin",
        credentials,
        cache: "no-store",
        redirect: "error",
        headers: { Accept: "application/json" },
        signal,
      });

      if (!response.ok) {
        // Error responses can contain an unbounded or hostile body even though
        // the status is already enough to classify the ticket failure. Cancel
        // it before publishing the fixed status error, with the same bounded
        // cleanup used by malformed successful responses.
        await cancelBody(response.body);
        throw new WsTicketError(
          response.status === 401 || response.status === 403
            ? "authentication-failed"
            : "request-failed",
          response.status,
        );
      }

      return await readTicketResponse(response, signal);
    } catch (error) {
      if (signal.aborted || isAbortLike(error)) {
        throw new WsTicketCancelledError();
      }

      if (error instanceof WsTicketError) {
        throw error;
      }

      throw new WsTicketError("request-failed");
    }
  };
}

async function readTicketResponse(
  response: Response,
  signal: AbortSignal,
): Promise<unknown> {
  const contentType = response.headers
    .get("content-type")
    ?.split(";", 1)[0]
    ?.trim()
    .toLowerCase();
  if (contentType !== "application/json" || response.body === null) {
    await cancelBody(response.body);
    throw new WsTicketError("response-invalid");
  }

  let declaredLength: number | undefined;
  try {
    declaredLength = parseContentLength(response.headers.get("content-length"));
  } catch {
    await cancelBody(response.body);
    throw new WsTicketError("response-invalid");
  }
  if (
    declaredLength !== undefined &&
    declaredLength > MAX_WS_TICKET_RESPONSE_BYTES
  ) {
    await cancelBody(response.body);
    throw new WsTicketError("response-invalid");
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let byteLength = 0;

  try {
    while (true) {
      const result = await awaitWithAbort(reader.read(), signal);
      if (result.done) {
        break;
      }
      byteLength += result.value.byteLength;
      if (byteLength > MAX_WS_TICKET_RESPONSE_BYTES) {
        throw new WsTicketError("response-invalid");
      }
      chunks.push(result.value);
    }

    if (declaredLength !== undefined && declaredLength !== byteLength) {
      throw new WsTicketError("response-invalid");
    }

    const body = new Uint8Array(byteLength);
    let offset = 0;
    for (const chunk of chunks) {
      body.set(chunk, offset);
      offset += chunk.byteLength;
    }

    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(body);
    } catch {
      throw new WsTicketError("response-invalid");
    }

    let parsed: unknown;
    try {
      parsed = parseStrictJson(text, {
        maxDepth: 2,
        maxNodes: 8,
        maxStringLength: MAX_WS_TICKET_LENGTH,
        maxArrayLength: 1,
        maxObjectKeys: 2,
      });
    } catch {
      throw new WsTicketError("response-invalid");
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new WsTicketError("response-invalid");
    }
    const record = parsed as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    const ticket = record.ticket;
    if (
      keys.length !== 2 ||
      keys[0] !== "ticket" ||
      keys[1] !== "ttl_seconds" ||
      typeof ticket !== "string" ||
      ticket.length === 0 ||
      ticket.length > MAX_WS_TICKET_LENGTH ||
      !/^[A-Za-z0-9_-]+$/.test(ticket) ||
      record.ttl_seconds !== WS_TICKET_TTL_SECONDS
    ) {
      throw new WsTicketError("response-invalid");
    }
    // TTL is validated at the HTTP boundary, then discarded with other response
    // metadata so the client seam retains only the one ephemeral ticket value.
    return { ticket };
  } catch (error) {
    await cancelReader(reader);
    if (signal.aborted || isAbortLike(error)) {
      throw new WsTicketCancelledError();
    }
    if (error instanceof WsTicketError) {
      throw error;
    }
    throw new WsTicketError("response-invalid");
  } finally {
    reader.releaseLock();
  }
}

function parseContentLength(value: string | null): number | undefined {
  if (value === null) {
    return undefined;
  }
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new WsTicketError("response-invalid");
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new WsTicketError("response-invalid");
  }
  return parsed;
}

async function cancelBody(
  body: ReadableStream<Uint8Array> | null,
): Promise<void> {
  if (body === null) {
    return;
  }

  let cancellation: Promise<unknown>;
  try {
    cancellation = Promise.resolve(body.cancel());
  } catch {
    return;
  }
  await awaitCleanupBounded(cancellation);
}

async function cancelReader(
  reader: ReadableStreamDefaultReader<Uint8Array>,
): Promise<void> {
  let cancellation: Promise<unknown>;
  try {
    cancellation = Promise.resolve(reader.cancel());
  } catch {
    return;
  }
  await awaitCleanupBounded(cancellation);
}

async function awaitCleanupBounded(cleanup: Promise<unknown>): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<void>((resolve) => {
    timer = setTimeout(resolve, WS_TICKET_RESPONSE_CANCEL_TIMEOUT_MS);
  });

  try {
    await Promise.race([cleanup, deadline]);
  } catch {
    // Cleanup cannot replace the bounded ticket diagnostic.
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}

/**
 * Create the ephemeral browser-side ticket flow. The client retains only the
 * active Promise. The raw ticket exists briefly while the upgrade URL is
 * assembled and is never copied to client state, storage, DOM, history, logs,
 * fixtures, reports, or error text.
 */
interface ActiveTicketAttempt<Connection> {
  readonly controller: AbortController;
  readonly promise: Promise<Connection>;
}

export function createWsTicketClient<Connection>(
  options: WsTicketClientOptions<Connection>,
): WsTicketClient<Connection> {
  let activeAttempt: ActiveTicketAttempt<Connection> | undefined;

  const startAttempt = (callerSignal?: AbortSignal): Promise<Connection> => {
    // A reconnect can abort the caller signal while the old request or
    // connector still has promise work pending. Do not coalesce a replacement
    // into that canceled attempt; its bounded abort path will finish separately.
    if (activeAttempt && !activeAttempt.controller.signal.aborted) {
      return activeAttempt.promise;
    }

    const controller = new AbortController();
    const promise = runAttempt(options, callerSignal, controller).finally(() => {
      if (activeAttempt?.promise === promise) {
        activeAttempt = undefined;
      }
    });

    activeAttempt = { controller, promise };
    return promise;
  };

  return {
    open: startAttempt,
    retry: startAttempt,
  };
}

async function runAttempt<Connection>(
  options: WsTicketClientOptions<Connection>,
  callerSignal: AbortSignal | undefined,
  controller: AbortController,
): Promise<Connection> {
  const origin = resolveOrigin();
  const unlinkAbort = linkAbort(callerSignal, controller);
  const closeLateConnection = createIdempotentConnectionCloser<Connection>();
  // The coalescing slot must not be held forever when a custom request or
  // connector ignores the caller signal. The internal deadline aborts the
  // attempt and lets the explicit retry path acquire a fresh ticket.
  const deadline = setTimeout(() => controller.abort(), DEFAULT_WS_TICKET_ATTEMPT_TIMEOUT_MS);

  try {
    throwIfAborted(callerSignal);

    const response = await requestTicket(options.request, controller.signal);
    throwIfAborted(callerSignal);
    const ticket = parseTicketResponse(response);
    const upgradeUrl = createUpgradeUrl(origin, ticket);

    // The URL is handed directly to the connector and is not stored on the
    // client. Connector implementations must honor the supplied signal.
    throwIfAborted(callerSignal);
    const connection = await upgradeTicket(
      options.connect,
      upgradeUrl,
      controller.signal,
      closeLateConnection,
    );
    throwIfAborted(callerSignal);
    return connection;
  } catch (error) {
    if (
      callerSignal?.aborted ||
      controller.signal.aborted ||
      isAbortLike(error)
    ) {
      throw new WsTicketCancelledError();
    }

    if (error instanceof WsTicketError) {
      throw error;
    }

    throw new WsTicketError("upgrade-failed");
  } finally {
    clearTimeout(deadline);
    unlinkAbort();
  }
}

async function requestTicket(
  request: WsTicketRequestBoundary,
  signal: AbortSignal,
): Promise<unknown> {
  try {
    return await awaitWithAbort(
      Promise.resolve(
        request({
          method: "POST",
          path: WS_TICKET_PATH,
          credentials: "same-origin",
          signal,
        }),
      ),
      signal,
    );
  } catch (error) {
    if (signal.aborted || isAbortLike(error)) {
      throw new WsTicketCancelledError();
    }

    if (error instanceof WsTicketError) {
      throw error;
    }

    throw new WsTicketError("request-failed");
  }
}

async function upgradeTicket<Connection>(
  connect: WsTicketUpgradeBoundary<Connection>,
  upgradeUrl: URL,
  signal: AbortSignal,
  onLateResolve: (connection: Connection) => void,
): Promise<Connection> {
  try {
    return await awaitWithAbort(
      Promise.resolve(connect(upgradeUrl, signal)),
      signal,
      onLateResolve,
    );
  } catch (error) {
    if (signal.aborted || isAbortLike(error)) {
      throw new WsTicketCancelledError();
    }

    if (error instanceof WsTicketError) {
      throw error;
    }

    throw new WsTicketError("upgrade-failed");
  }
}

function createIdempotentConnectionCloser<Connection>(): (
  connection: Connection,
) => void {
  const closedConnections = new WeakSet<object>();

  return (connection: Connection): void => {
    if (typeof connection !== "object" || connection === null) {
      return;
    }

    const candidate = connection as object & {
      close?: (code?: number, reason?: string) => unknown;
    };
    if (typeof candidate.close !== "function" || closedConnections.has(candidate)) {
      return;
    }

    closedConnections.add(candidate);
    try {
      candidate.close(1000, "cancelled");
    } catch {
      // A late connector result is already outside the active attempt.
    }
  };
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
    // Attach a rejection handler even for an already-aborted signal. A connector
    // may still resolve later, and its result must reach the late close hook.
    promise.then(handleLateResolve, () => undefined);
    return Promise.reject(new WsTicketCancelledError());
  }

  return new Promise<T>((resolve, reject) => {
    let settled = false;

    const cleanup = (): void => {
      signal.removeEventListener("abort", onAbort);
    };

    const settle = (callback: () => void): void => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      callback();
    };

    const onAbort = (): void => {
      settle(() => reject(new WsTicketCancelledError()));
    };

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

function parseTicketResponse(value: unknown): string {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new WsTicketError("response-invalid");
  }

  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  const ticket = record.ticket;

  if (
    keys.length !== 1 ||
    keys[0] !== "ticket" ||
    typeof ticket !== "string" ||
    ticket.length === 0 ||
    ticket.length > MAX_WS_TICKET_LENGTH ||
    !/^[A-Za-z0-9_-]+$/.test(ticket)
  ) {
    throw new WsTicketError("response-invalid");
  }

  return ticket;
}

function resolveOrigin(): URL {
  if (typeof location === "undefined") {
    throw new WsTicketError("origin-unavailable");
  }

  try {
    const parsed = new URL(location.origin);
    if (
      (parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
      parsed.origin !== location.origin
    ) {
      throw new Error("unsupported-origin");
    }
    return parsed;
  } catch {
    throw new WsTicketError("origin-unavailable");
  }
}

function createUpgradeUrl(origin: URL, ticket: string): URL {
  const url = new URL(CHAT_WEBSOCKET_PATH, origin);
  url.protocol = origin.protocol === "https:" ? "wss:" : "ws:";
  url.search = "";
  url.hash = "";
  url.searchParams.set("ticket", ticket);
  return url;
}

function linkAbort(
  signal: AbortSignal | undefined,
  controller: AbortController,
): () => void {
  if (!signal) {
    return () => undefined;
  }

  const onAbort = (): void => {
    // Do not forward signal.reason: callers could put credential-shaped data
    // there, and the reason is not needed to preserve cancellation semantics.
    controller.abort();
  };

  if (signal.aborted) {
    controller.abort();
    return () => undefined;
  }

  signal.addEventListener("abort", onAbort, { once: true });
  return () => signal.removeEventListener("abort", onAbort);
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) {
    throw new WsTicketCancelledError();
  }
}

function isAbortLike(error: unknown): boolean {
  if (typeof error !== "object" || error === null || !("name" in error)) {
    return false;
  }

  const name = (error as { name?: unknown }).name;
  return name === "AbortError" || name === "CanceledError";
}

function normalizeStatus(status: number | undefined): number | undefined {
  return typeof status === "number" &&
    Number.isInteger(status) &&
    status >= 100 &&
    status <= 599
    ? status
    : undefined;
}
