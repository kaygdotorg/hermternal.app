import { describe, expect, it, vi } from "vitest";
import {
  CHAT_WEBSOCKET_PATH,
  DEFAULT_WS_TICKET_ATTEMPT_TIMEOUT_MS,
  MAX_WS_TICKET_RESPONSE_BYTES,
  WS_TICKET_PATH,
  WsTicketError,
  createWsTicketClient,
  createWsTicketRequestBoundary,
} from "./ws-ticket";
import type { WsTicketClientOptions, WsTicketFetch } from "./ws-ticket";

function opaqueTicket(): string {
  return crypto.randomUUID().replaceAll("-", "");
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function deferred<T>(): {
  promise: Promise<T>;
  resolve(value: T): void;
  reject(reason?: unknown): void;
} {
  let resolvePromise!: (value: T) => void;
  let rejectPromise!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });

  return {
    promise,
    resolve: resolvePromise,
    reject: rejectPromise,
  };
}

function neverSettlingCancelResponse(
  contentType: string,
  bodyBytes: Uint8Array = new Uint8Array(),
): { response: Response; wasCancelled: () => boolean } {
  let cancelled = false;
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      if (bodyBytes.byteLength > 0) controller.enqueue(bodyBytes);
    },
    cancel() {
      cancelled = true;
      return new Promise<void>(() => undefined);
    },
  });
  return {
    response: new Response(body, { headers: { "Content-Type": contentType } }),
    wasCancelled: () => cancelled,
  };
}

describe("createWsTicketRequestBoundary", () => {
  it("sends only the fixed same-origin POST shape", async () => {
    const calls: Array<{ input: RequestInfo | URL; init?: RequestInit }> = [];
    const fetcher: WsTicketFetch = async (input, init) => {
      calls.push({ input, init });
      return jsonResponse({ ticket: opaqueTicket(), ttl_seconds: 30 });
    };
    const boundary = createWsTicketRequestBoundary(fetcher);
    const signal = new AbortController().signal;

    await boundary({
      method: "POST",
      path: WS_TICKET_PATH,
      credentials: "same-origin",
      signal,
    });

    expect(calls).toHaveLength(1);
    expect(calls[0]?.input).toBe(WS_TICKET_PATH);
    expect(calls[0]?.init).toMatchObject({
      method: "POST",
      mode: "same-origin",
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      headers: { Accept: "application/json" },
      signal,
    });
    const headers = calls[0]?.init?.headers as Record<string, string>;
    expect("authorization" in headers).toBe(false);
    expect("cookie" in headers).toBe(false);
  });

  it("maps invalid authentication to a bounded semantic failure without reading the body", async () => {
    const rawResponseMarker = opaqueTicket();
    let bodyRead = false;
    const fetcher: WsTicketFetch = async () =>
      ({
        ok: false,
        status: 401,
        json: async () => {
          bodyRead = true;
          return { detail: `Bearer ${rawResponseMarker}` };
        },
      }) as Response;
    const boundary = createWsTicketRequestBoundary(fetcher);

    await expect(
      boundary({
        method: "POST",
        path: WS_TICKET_PATH,
        credentials: "same-origin",
        signal: new AbortController().signal,
      }),
    ).rejects.toMatchObject({ code: "authentication-failed", status: 401 });
    expect(bodyRead).toBe(false);
  });

  it("rejects duplicate ticket keys instead of accepting a parser overwrite", async () => {
    const first = opaqueTicket();
    const second = opaqueTicket();
    const fetcher: WsTicketFetch = async () =>
      new Response(
        `{"ticket":"${first}","ticket":"${second}","ttl_seconds":30}`,
        { headers: { "Content-Type": "application/json" } },
      );
    const boundary = createWsTicketRequestBoundary(fetcher);

    await expect(
      boundary({
        method: "POST",
        path: WS_TICKET_PATH,
        credentials: "same-origin",
        signal: new AbortController().signal,
      }),
    ).rejects.toMatchObject({ code: "response-invalid" });
  });

  it("accepts the official fields in either JSON key order", async () => {
    const ticket = opaqueTicket();
    const boundary = createWsTicketRequestBoundary(
      async () =>
        new Response(`{"ttl_seconds":30,"ticket":"${ticket}"}`, {
          headers: { "Content-Type": "application/json" },
        }),
    );

    await expect(
      boundary({
        method: "POST",
        path: WS_TICKET_PATH,
        credentials: "same-origin",
        signal: new AbortController().signal,
      }),
    ).resolves.toEqual({ ticket });
  });

  it.each([
    { ticket: opaqueTicket() },
    { ticket: opaqueTicket(), ttl_seconds: 29 },
    { ticket: opaqueTicket(), ttl_seconds: "30" },
    { ticket: opaqueTicket(), ttl_seconds: 30, unexpected: true },
  ])("rejects a ticket response outside the official 30-second shape", async (body) => {
    const boundary = createWsTicketRequestBoundary(async () => jsonResponse(body));

    await expect(
      boundary({
        method: "POST",
        path: WS_TICKET_PATH,
        credentials: "same-origin",
        signal: new AbortController().signal,
      }),
    ).rejects.toMatchObject({ code: "response-invalid" });
  });

  it("cancels an oversized streaming body before consuming the full response", async () => {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(MAX_WS_TICKET_RESPONSE_BYTES + 1));
      },
      cancel() {
        cancelled = true;
      },
    });
    const fetcher: WsTicketFetch = async () =>
      new Response(body, { headers: { "Content-Type": "application/json" } });
    const boundary = createWsTicketRequestBoundary(fetcher);

    await expect(
      boundary({
        method: "POST",
        path: WS_TICKET_PATH,
        credentials: "same-origin",
        signal: new AbortController().signal,
      }),
    ).rejects.toMatchObject({ code: "response-invalid" });
    expect(cancelled).toBe(true);
  });

  it("bounds a body.cancel that never settles after headers fail closed", async () => {
    const tracked = neverSettlingCancelResponse("text/html");
    const boundary = createWsTicketRequestBoundary(async () => tracked.response);
    const startedAt = Date.now();

    await expect(
      boundary({
        method: "POST",
        path: WS_TICKET_PATH,
        credentials: "same-origin",
        signal: new AbortController().signal,
      }),
    ).rejects.toMatchObject({ code: "response-invalid" });

    expect(tracked.wasCancelled()).toBe(true);
    expect(Date.now() - startedAt).toBeLessThan(1_000);
  });

  it("bounds a reader.cancel that never settles after a streaming body fails closed", async () => {
    const tracked = neverSettlingCancelResponse(
      "application/json",
      new Uint8Array(MAX_WS_TICKET_RESPONSE_BYTES + 1),
    );
    const boundary = createWsTicketRequestBoundary(async () => tracked.response);
    const startedAt = Date.now();

    await expect(
      boundary({
        method: "POST",
        path: WS_TICKET_PATH,
        credentials: "same-origin",
        signal: new AbortController().signal,
      }),
    ).rejects.toMatchObject({ code: "response-invalid" });

    expect(tracked.wasCancelled()).toBe(true);
    expect(Date.now() - startedAt).toBeLessThan(1_000);
  });
});

describe("createWsTicketClient", () => {
  it("derives the upgrade origin from browser location and ignores an injected origin", async () => {
    let upgradeUrl: URL | undefined;
    const options = {
      origin: "https://attacker.invalid",
      request: async () => ({ ticket: opaqueTicket() }),
      connect: async (url: URL) => {
        upgradeUrl = url;
        return "connected";
      },
    } as unknown as WsTicketClientOptions<string>;
    const client = createWsTicketClient(options);

    await expect(client.open()).resolves.toBe("connected");
    expect(upgradeUrl?.hostname).toBe(location.hostname);
    expect(upgradeUrl?.port).toBe(location.port);
    expect(upgradeUrl?.protocol).toBe(
      location.protocol === "https:" ? "wss:" : "ws:",
    );
    expect(upgradeUrl?.hostname).not.toBe("attacker.invalid");
  });

  it("requires the exact response shape and never copies a rejected value into the error", async () => {
    const rawResponseMarker = opaqueTicket();
    const connect = vi.fn(async () => "never-connected");
    const client = createWsTicketClient({
      request: async () => ({ ticket: rawResponseMarker, unexpected: true }),
      connect,
    });

    const error = await client.open().catch((value: unknown) => value);

    expect(error).toBeInstanceOf(WsTicketError);
    expect((error as WsTicketError).code).toBe("response-invalid");
    expect((error as Error).message.includes(rawResponseMarker)).toBe(false);
    expect(connect).not.toHaveBeenCalled();
  });

  it("coalesces one active attempt and acquires a fresh value after it settles", async () => {
    const firstGate = deferred<void>();
    const tickets = [opaqueTicket(), opaqueTicket()];
    let requestCount = 0;
    const upgradeUrls: URL[] = [];
    const request = vi.fn(async () => {
      const ticket = tickets[requestCount++];
      if (!ticket) {
        throw new WsTicketError("request-failed");
      }
      if (requestCount === 1) {
        await firstGate.promise;
      }
      return { ticket };
    });
    const connect = vi.fn(async (url: URL) => {
      upgradeUrls.push(url);
      return upgradeUrls.length;
    });
    const client = createWsTicketClient({
      request,
      connect,
    });

    const first = client.open();
    const duplicate = client.open();
    expect(first === duplicate).toBe(true);
    expect(request).toHaveBeenCalledTimes(1);

    firstGate.resolve(undefined);
    await expect(first).resolves.toBe(1);
    await expect(client.retry()).resolves.toBe(2);

    expect(request).toHaveBeenCalledTimes(2);
    expect(connect).toHaveBeenCalledTimes(2);
    expect(
      upgradeUrls.every((url) => {
        const keys = [...url.searchParams.keys()];
        return (
          (url.protocol === "wss:" || url.protocol === "ws:") &&
          url.pathname === CHAT_WEBSOCKET_PATH &&
          keys.length === 1 &&
          keys[0] === "ticket" &&
          url.hash === ""
        );
      }),
    ).toBe(true);
    expect(
      upgradeUrls[0]?.searchParams.get("ticket") ===
        upgradeUrls[1]?.searchParams.get("ticket"),
    ).toBe(false);
  });

  it("cancels before a response is verified and does not connect or retry automatically", async () => {
    const responseGate = deferred<{ ticket: string }>();
    const controller = new AbortController();
    const connect = vi.fn(async () => "connected");
    const request = vi.fn(async () => responseGate.promise);
    const client = createWsTicketClient({
      request,
      connect,
    });

    const attempt = client.open(controller.signal);
    controller.abort();
    responseGate.resolve({ ticket: opaqueTicket() });

    await expect(attempt).rejects.toMatchObject({
      code: "cancelled",
      name: "AbortError",
    });
    expect(connect).not.toHaveBeenCalled();
    expect(request).toHaveBeenCalledTimes(1);
  });

  it("requires an explicit retry after authentication failure and redacts arbitrary boundary errors", async () => {
    const rawErrorMarker = opaqueTicket();
    const freshTicket = opaqueTicket();
    let requestCount = 0;
    const request = vi.fn(async () => {
      requestCount += 1;
      if (requestCount === 1) {
        throw new Error(`Cookie: ${rawErrorMarker}`);
      }
      return { ticket: freshTicket };
    });
    const connect = vi.fn(async () => "connected");
    const client = createWsTicketClient({
      request,
      connect,
    });

    const firstError = await client.open().catch((value: unknown) => value);
    expect(firstError).toBeInstanceOf(WsTicketError);
    expect((firstError as WsTicketError).code).toBe("request-failed");
    expect((firstError as Error).message.includes(rawErrorMarker)).toBe(false);
    expect(request).toHaveBeenCalledTimes(1);
    expect(connect).not.toHaveBeenCalled();

    await expect(client.retry()).resolves.toBe("connected");
    expect(request).toHaveBeenCalledTimes(2);
    expect(connect).toHaveBeenCalledTimes(1);
  });

  it("clears a never-resolving request without a caller signal and permits retry after the deadline", async () => {
    vi.useFakeTimers();
    try {
      let requestCount = 0;
      const request = vi.fn(async () => {
        requestCount += 1;
        if (requestCount === 1) return new Promise<{ ticket: string }>(() => undefined);
        return { ticket: opaqueTicket() };
      });
      const client = createWsTicketClient({
        request,
        connect: async () => "connected",
      });

      const first = client.open();
      void first.catch(() => undefined);
      expect(request).toHaveBeenCalledTimes(1);
      await vi.advanceTimersByTimeAsync(DEFAULT_WS_TICKET_ATTEMPT_TIMEOUT_MS);
      await expect(first).rejects.toMatchObject({ code: "cancelled" });

      await expect(client.retry()).resolves.toBe("connected");
      expect(request).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not forward an abort reason that could contain sensitive input", async () => {
    const controller = new AbortController();
    const requestSignal = deferred<AbortSignal>();
    const request = vi.fn(async (input) => {
      requestSignal.resolve(input.signal);
      return new Promise<{ ticket: string }>(() => undefined);
    });
    const client = createWsTicketClient({
      request,
      connect: async () => "never-connected",
    });

    const attempt = client.open(controller.signal);
    const signal = await requestSignal.promise;
    controller.abort(opaqueTicket());

    expect(signal.aborted).toBe(true);
    await expect(attempt).rejects.toMatchObject({ code: "cancelled" });
  });
});
