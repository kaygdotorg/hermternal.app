import { describe, expect, it, vi } from "vitest";
import {
  JSON_RPC_EVENT_METHOD,
  JSON_RPC_GATEWAY_READY_EVENT,
  type JsonRpcWebSocket,
} from "./json-rpc-chat";
import {
  OFFICIAL_HERMES_IMAGE,
  createBrowserChatTransport,
} from "./browser-chat";

class FakeWebSocket implements JsonRpcWebSocket {
  onopen: ((event?: unknown) => void) | null = null;
  onmessage: ((event: { readonly data: unknown }) => void) | null = null;
  onerror: ((event?: unknown) => void) | null = null;
  onclose:
    | ((event?: { readonly code?: number; readonly reason?: string }) => void)
    | null = null;
  readonly sent: string[] = [];
  readonly close = vi.fn();

  send(data: string): void {
    this.sent.push(data);
  }

  emitOpen(): void {
    this.onopen?.();
  }

  emitGatewayReady(): void {
    this.onmessage?.({
      data: JSON.stringify({
        jsonrpc: "2.0",
        method: JSON_RPC_EVENT_METHOD,
        params: {
          type: JSON_RPC_GATEWAY_READY_EVENT,
          payload: { skin: "official", change_events: true },
        },
      }),
    });
  }
}

async function waitForAttachedSocket(
  sockets: readonly FakeWebSocket[],
  index: number,
): Promise<FakeWebSocket> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const socket = sockets[index];
    if (socket?.onopen) return socket;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error("socket handlers were not attached");
}

describe("createBrowserChatTransport", () => {
  it("uses a fresh same-origin ticket directly in the browser WebSocket URL", async () => {
    const urls: string[] = [];
    const socket = new FakeWebSocket();
    const fetcher = vi.fn(
      async () =>
        new Response('{"ticket":"fresh-ticket-1","ttl_seconds":30}', {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    const transport = createBrowserChatTransport({
      fetch: fetcher,
      createSocket: (url) => {
        urls.push(url);
        return socket;
      },
    });

    const connection = transport.connect();
    await waitForAttachedSocket([socket], 0);
    socket.emitOpen();
    socket.emitGatewayReady();
    await connection;

    expect(fetcher).toHaveBeenCalledWith(
      "/api/auth/ws-ticket",
      expect.objectContaining({
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
      }),
    );
    expect(urls).toHaveLength(1);
    expect(new URL(urls[0] ?? "http://invalid").pathname).toBe("/api/ws");
    expect(
      new URL(urls[0] ?? "http://invalid").searchParams.get("ticket"),
    ).toBe("fresh-ticket-1");
    expect(transport.state.status).toBe("ready");
    expect(JSON.stringify(transport.state)).not.toContain("fresh-ticket-1");
    expect(JSON.stringify(transport.state)).not.toContain(
      OFFICIAL_HERMES_IMAGE,
    );
  });

  it("closes a synchronous connector exactly once when abort wins before promise fulfillment", async () => {
    const socket = new FakeWebSocket();
    let transport: ReturnType<typeof createBrowserChatTransport>;
    const connection = (transport = createBrowserChatTransport({
      fetch: async () =>
        new Response('{"ticket":"fresh-ticket-1","ttl_seconds":30}', {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      createSocket: () => {
        queueMicrotask(() => transport.close());
        return socket;
      },
    })).connect();

    await expect(connection).rejects.toMatchObject({ code: "aborted" });
    expect(socket.close).toHaveBeenCalledTimes(1);
    expect(socket.close).toHaveBeenCalledWith(1000, "cancelled");
  });

  it("clears an unconsumed prepared socket on abort so the next connect is fresh", async () => {
    const sockets = [new FakeWebSocket(), new FakeWebSocket()];
    let transport: ReturnType<typeof createBrowserChatTransport>;
    let connectCalls = 0;
    const connection = (transport = createBrowserChatTransport({
      fetch: async () =>
        new Response('{"ticket":"fresh-ticket-1","ttl_seconds":30}', {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      createSocket: () => {
        const socket = sockets[connectCalls];
        connectCalls += 1;
        if (!socket) throw new Error("missing socket");
        if (connectCalls === 1) {
          queueMicrotask(() => queueMicrotask(() => transport.close()));
        }
        return socket;
      },
    })).connect();

    await expect(connection).rejects.toMatchObject({ code: "aborted" });
    expect(sockets[0]?.close).toHaveBeenCalledTimes(1);

    const retry = transport.connect();
    const second = sockets[1];
    await waitForAttachedSocket(sockets, 1);
    second.emitOpen();
    second.emitGatewayReady();
    await retry;

    expect(connectCalls).toBe(2);
    expect(sockets[0]?.close).toHaveBeenCalledTimes(1);
    expect(transport.state.status).toBe("ready");
  });

  it("maps a genuine ticket HTTP 401 to authentication-required state", async () => {
    const socket = new FakeWebSocket();
    const transport = createBrowserChatTransport({
      fetch: async () =>
        new Response("unauthenticated", {
          status: 401,
          headers: { "content-type": "text/plain" },
        }),
      createSocket: () => socket,
    });

    await expect(transport.connect()).rejects.toMatchObject({
      code: "authentication-required",
    });
    expect(transport.state.status).toBe("auth_required");
    expect(socket.close).not.toHaveBeenCalled();
  });

  it("does not classify a ticket HTTP 403 as authentication-required", async () => {
    const transport = createBrowserChatTransport({
      fetch: async () =>
        new Response("forbidden", {
          status: 403,
          headers: { "content-type": "text/plain" },
        }),
      createSocket: () => new FakeWebSocket(),
    });

    await expect(transport.connect()).rejects.toMatchObject({
      code: "connection-failed",
    });
    expect(transport.state.status).toBe("failed");
  });

  it("fails closed when gateway.ready omits source-backed behavior keys", async () => {
    const socket = new FakeWebSocket();
    const transport = createBrowserChatTransport({
      fetch: async () =>
        new Response('{"ticket":"fresh-ticket-1","ttl_seconds":30}', {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      createSocket: () => socket,
    });

    const connection = transport.connect();
    await waitForAttachedSocket([socket], 0);
    socket.emitOpen();
    socket.onmessage?.({
      data: JSON.stringify({
        jsonrpc: "2.0",
        method: JSON_RPC_EVENT_METHOD,
        params: {
          type: JSON_RPC_GATEWAY_READY_EVENT,
          payload: { status: "ready" },
        },
      }),
    });

    await expect(connection).rejects.toMatchObject({ code: "incompatible" });
    expect(transport.state.status).toBe("incompatible");
  });

  it("acquires another ticket only after an explicit reconnect", async () => {
    const availableSockets = [new FakeWebSocket(), new FakeWebSocket()];
    const createdSockets: FakeWebSocket[] = [];
    let ticket = 0;
    const fetcher = vi.fn(async () => {
      ticket += 1;
      return new Response(`{"ticket":"fresh-ticket-${ticket}","ttl_seconds":30}`, {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    const urls: string[] = [];
    const transport = createBrowserChatTransport({
      fetch: fetcher,
      createSocket: (url) => {
        urls.push(url);
        const next = availableSockets.shift();
        if (!next) throw new Error("missing socket");
        createdSockets.push(next);
        return next;
      },
    });

    const first = transport.connect();
    const firstSocket = await waitForAttachedSocket(createdSockets, 0);
    firstSocket.emitOpen();
    firstSocket.emitGatewayReady();
    await first;

    const second = transport.reconnect();
    const secondSocket = await waitForAttachedSocket(createdSockets, 1);
    secondSocket.emitOpen();
    secondSocket.emitGatewayReady();
    await second;

    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(urls[0]).toContain("fresh-ticket-1");
    expect(urls[1]).toContain("fresh-ticket-2");
  });
});
