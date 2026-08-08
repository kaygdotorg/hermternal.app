import { describe, expect, it, vi } from "vitest";
import {
  PTY_DETACH_RETENTION_MS,
  PTY_REPLAY_CAPACITY_BYTES,
  PTY_WEBSOCKET_PATH,
  PTY_WS_TICKET_PATH,
  PtyTransportError,
  createFreshPtyTicketProvider,
  createPtyTransport,
  encodeResize,
  type PtyConnectionInput,
  type PtyTransportEvent,
  type PtyTransportOptions,
  type PtyWebSocket,
  type PtyWebSocketUpgradeRequest,
} from "./pty-transport";

class FakeSocket implements PtyWebSocket {
  onopen: ((event?: unknown) => void) | null = null;
  onmessage: ((event: { readonly data: unknown }) => void) | null = null;
  onerror: ((event?: unknown) => void) | null = null;
  onclose: ((event?: { readonly code?: number }) => void) | null = null;
  binaryType?: string;
  readyState = 0;
  readonly sent: Uint8Array[] = [];
  readonly closes: Array<{ readonly code?: number; readonly reason?: string }> = [];

  send(data: Uint8Array): void {
    if (this.readyState !== 1) throw new Error("closed");
    this.sent.push(data.slice());
  }

  close(code?: number, reason?: string): void {
    this.closes.push({ code, reason });
    this.readyState = 3;
  }

  open(): void {
    this.readyState = 1;
    this.onopen?.();
  }

  message(data: unknown): void {
    this.onmessage?.({ data });
  }

  closeFromServer(code: number): void {
    this.readyState = 3;
    this.onclose?.({ code });
  }
}

interface Harness {
  readonly transport: ReturnType<typeof createPtyTransport>;
  readonly sockets: FakeSocket[];
  readonly upgrades: PtyWebSocketUpgradeRequest[];
  readonly tickets: string[];
  readonly events: PtyTransportEvent[];
  readonly ticketProvider: ReturnType<typeof vi.fn>;
}

const ATTACH_INPUT: PtyConnectionInput = {
  sessionId: "session-current-001",
  attach: "attach-current-001",
  processIdentity: "process-current-001",
};

function makeHarness(
  overrides: Partial<PtyTransportOptions> = {},
): Harness {
  const sockets: FakeSocket[] = [];
  const upgrades: PtyWebSocketUpgradeRequest[] = [];
  const tickets: string[] = [];
  const events: PtyTransportEvent[] = [];
  let ticketIndex = 0;
  const ticketProvider = vi.fn(async () => {
    ticketIndex += 1;
    return `ticket-${ticketIndex}`;
  });
  const transport = createPtyTransport({
    ticketProvider,
    createWebSocket: (upgrade) => {
      upgrades.push(upgrade);
      tickets.push(upgrade.query.ticket);
      const socket = new FakeSocket();
      sockets.push(socket);
      return socket;
    },
    validateAttachment: async (input) => input === ATTACH_INPUT || input.attach === ATTACH_INPUT.attach,
    onEvent: (event) => events.push(event),
    ...overrides,
  });
  return { transport, sockets, upgrades, tickets, events, ticketProvider };
}

async function flush(): Promise<void> {
  for (let index = 0; index < 64; index += 1) await Promise.resolve();
}

async function open(
  harness: Harness,
  input: PtyConnectionInput = ATTACH_INPUT,
): Promise<FakeSocket> {
  const pending = harness.transport.connect(input);
  await flush();
  const socket = harness.sockets.at(-1);
  if (!socket) throw new Error("missing fake socket");
  socket.open();
  await pending;
  return socket;
}

async function reattach(harness: Harness): Promise<FakeSocket> {
  const pending = harness.transport.reconnect();
  await flush();
  const socket = harness.sockets.at(-1);
  if (!socket) throw new Error("missing replacement socket");
  socket.open();
  await pending;
  return socket;
}

async function openTruncated(harness: Harness): Promise<FakeSocket> {
  await open(harness);
  harness.transport.detach();
  const socket = await reattach(harness);
  expect(harness.transport.state.outputMayBeTruncated).toBe(true);
  return socket;
}

describe("PTY transport", () => {
  it("adapts the same-origin authenticated ticket seam without retaining a credential", async () => {
    const calls: unknown[] = [];
    let index = 0;
    const provider = createFreshPtyTicketProvider(async (input) => {
      calls.push(input);
      index += 1;
      return { ticket: `ticket-${index}` };
    });
    const first = await provider(new AbortController().signal);
    const second = await provider(new AbortController().signal);
    expect([first, second]).toEqual(["ticket-1", "ticket-2"]);
    expect(calls).toHaveLength(2);
    expect(calls[0]).toMatchObject({
      method: "POST",
      path: PTY_WS_TICKET_PATH,
      credentials: "same-origin",
    });

    for (const response of [
      {},
      { ticket: "" },
      { ticket: "bad!ticket" },
      { ticket: "ticket", extra: true },
      ["ticket"],
      null,
    ]) {
      const invalid = createFreshPtyTicketProvider(async () => response);
      await expect(invalid(new AbortController().signal)).rejects.toMatchObject({
        code: "invalid-ticket",
      });
    }
  });

  it("does not cache an already-aborted external attempt", async () => {
    const harness = makeHarness();
    const controller = new AbortController();
    controller.abort();

    await expect(harness.transport.connect(ATTACH_INPUT, controller.signal)).rejects.toMatchObject({
      code: "aborted",
    });
    const retry = harness.transport.connect(ATTACH_INPUT);
    await flush();
    expect(harness.ticketProvider).toHaveBeenCalledTimes(1);
    const socket = harness.sockets[0]!;
    socket.open();
    await retry;
    expect(harness.transport.state.status).toBe("attached");
  });

  it("uses one fresh ticket per upgrade without exposing or reusing it", async () => {
    const harness = makeHarness();
    await open(harness);
    harness.transport.detach();
    await reattach(harness);

    expect(harness.ticketProvider).toHaveBeenCalledTimes(2);
    expect(harness.tickets).toEqual(["ticket-1", "ticket-2"]);
    expect(harness.upgrades).toEqual([
      {
        path: PTY_WEBSOCKET_PATH,
        origin: "same-origin",
        query: {
          ticket: "ticket-1",
          resume: ATTACH_INPUT.sessionId,
          attach: ATTACH_INPUT.attach,
        },
      },
      {
        path: PTY_WEBSOCKET_PATH,
        origin: "same-origin",
        query: {
          ticket: "ticket-2",
          resume: ATTACH_INPUT.sessionId,
          attach: ATTACH_INPUT.attach,
        },
      },
    ]);
    expect(JSON.stringify(harness.transport.state)).not.toContain("ticket-");
  });

  it("coalesces one active upgrade but consumes a fresh ticket after settlement", async () => {
    const harness = makeHarness();
    const first = harness.transport.connect(ATTACH_INPUT);
    const duplicate = harness.transport.connect(ATTACH_INPUT);
    expect(duplicate).toBe(first);
    await flush();
    harness.sockets[0]!.open();
    await first;
    expect(harness.ticketProvider).toHaveBeenCalledTimes(1);
    harness.transport.detach();
    await reattach(harness);
    expect(harness.ticketProvider).toHaveBeenCalledTimes(2);
  });

  it("keeps a shared upgrade alive when a duplicate caller is already aborted", async () => {
    const harness = makeHarness();
    const first = harness.transport.connect(ATTACH_INPUT);
    await flush();
    const controller = new AbortController();
    controller.abort();

    await expect(
      harness.transport.connect(ATTACH_INPUT, controller.signal),
    ).rejects.toMatchObject({ code: "aborted" });
    expect(harness.ticketProvider).toHaveBeenCalledTimes(1);

    harness.sockets[0]!.open();
    await first;
    expect(harness.transport.state.status).toBe("attached");
  });

  it("cancels only a duplicate caller wait while an unabortable caller continues", async () => {
    const harness = makeHarness();
    const first = harness.transport.connect(ATTACH_INPUT);
    await flush();
    const controller = new AbortController();
    const duplicate = harness.transport.connect(ATTACH_INPUT, controller.signal);
    controller.abort();

    await expect(duplicate).rejects.toMatchObject({ code: "aborted" });
    expect(harness.ticketProvider).toHaveBeenCalledTimes(1);
    harness.sockets[0]!.open();
    await first;
    expect(harness.transport.state.status).toBe("attached");
  });

  it("stops ticket-stage stale work before validation and socket creation", async () => {
    let resolveTicket!: (ticket: string) => void;
    let factoryCalls = 0;
    const controller = new AbortController();
    const harness = makeHarness({
      ticketProvider: () =>
        new Promise<string>((resolve) => {
          resolveTicket = resolve;
        }),
      createWebSocket: () => {
        factoryCalls += 1;
        return new FakeSocket();
      },
    });
    const pending = harness.transport.connect(ATTACH_INPUT, controller.signal);
    await flush();
    resolveTicket("ticket-microtask");
    queueMicrotask(() => controller.abort());

    await expect(pending).rejects.toMatchObject({ code: "aborted" });
    await flush();
    expect(factoryCalls).toBe(0);
    expect(harness.upgrades).toHaveLength(0);
    expect(harness.transport.state.status).toBe("detached");
  });

  it("quarantines an ignored ticket after cancellation so reconnect cannot mint a duplicate", async () => {
    let resolveTicket!: (ticket: string) => void;
    const retainedInput = { ...ATTACH_INPUT, detachedAtMs: 1 };
    let ticketCalls = 0;
    const harness = makeHarness({
      now: () => 1,
      ticketProvider: () => {
        ticketCalls += 1;
        return ticketCalls === 1
          ? new Promise<string>((resolve) => {
              resolveTicket = resolve;
            })
          : Promise.resolve(`ticket-${ticketCalls}`);
      },
    });
    const cancelled = harness.transport.connect(retainedInput);
    await flush();
    harness.transport.detach();
    await expect(cancelled).rejects.toMatchObject({ code: "aborted" });

    await expect(harness.transport.reconnect()).rejects.toMatchObject({
      code: "aborted",
    });
    expect(ticketCalls).toBe(1);
    expect(harness.sockets).toHaveLength(0);
    expect(harness.transport.state).toMatchObject({
      status: "detached",
      generation: 2,
    });

    resolveTicket("ticket-ignored-after-abort");
    await flush();
    expect(harness.sockets).toHaveLength(0);

    const retry = harness.transport.reconnect();
    await flush();
    expect(ticketCalls).toBe(2);
    harness.sockets[0]!.open();
    await retry;
    expect(harness.transport.state).toMatchObject({ status: "attached", generation: 3 });
  });

  it("quarantines an ignored attachment validation before ticket minting", async () => {
    let resolveValidation!: (valid: boolean) => void;
    const retainedInput = { ...ATTACH_INPUT, detachedAtMs: 1 };
    const validator = vi.fn(
      () =>
        new Promise<boolean>((resolve) => {
          resolveValidation = resolve;
        }),
    );
    const harness = makeHarness({ now: () => 1, validateAttachment: validator });
    const cancelled = harness.transport.connect(retainedInput);
    await flush();
    harness.transport.detach();
    await expect(cancelled).rejects.toMatchObject({ code: "aborted" });

    await expect(harness.transport.reconnect()).rejects.toMatchObject({
      code: "aborted",
    });
    expect(validator).toHaveBeenCalledTimes(1);
    expect(harness.ticketProvider).not.toHaveBeenCalled();

    resolveValidation(true);
    await flush();
    const retry = harness.transport.reconnect();
    await flush();
    expect(validator).toHaveBeenCalledTimes(2);
    expect(harness.ticketProvider).not.toHaveBeenCalled();
    resolveValidation(true);
    await flush();
    expect(harness.ticketProvider).toHaveBeenCalledTimes(1);
    harness.sockets[0]!.open();
    await retry;
  });

  it("closes an ignored factory socket and fences reconnect until it settles", async () => {
    let resolveSocket!: (socket: FakeSocket) => void;
    const retainedInput = { ...ATTACH_INPUT, detachedAtMs: 1 };
    let factoryCalls = 0;
    const harness = makeHarness({
      now: () => 1,
      createWebSocket: () => {
        factoryCalls += 1;
        if (factoryCalls === 1) {
          return new Promise<FakeSocket>((resolve) => {
            resolveSocket = resolve;
          });
        }
        const socket = new FakeSocket();
        harness.sockets.push(socket);
        return socket;
      },
    });
    const controller = new AbortController();
    const cancelled = harness.transport.connect(retainedInput, controller.signal);
    await flush();
    expect(factoryCalls).toBe(1);
    controller.abort();
    await expect(cancelled).rejects.toMatchObject({ code: "aborted" });

    await expect(harness.transport.reconnect()).rejects.toMatchObject({
      code: "aborted",
    });
    expect(harness.ticketProvider).toHaveBeenCalledTimes(1);
    expect(factoryCalls).toBe(1);

    const staleSocket = new FakeSocket();
    resolveSocket(staleSocket);
    await flush();
    expect(staleSocket.closes).toEqual([{ code: 1000, reason: "client-detach" }]);
    expect(harness.transport.state.status).toBe("detached");
    expect(harness.events.filter((event) => event.type === "notice")).toHaveLength(0);

    const retry = harness.transport.reconnect();
    await flush();
    expect(harness.ticketProvider).toHaveBeenCalledTimes(2);
    expect(factoryCalls).toBe(2);
    harness.sockets[0]!.open();
    await retry;
    expect(harness.transport.state).toMatchObject({ status: "attached", generation: 2 });
  });

  it("does not mint a ticket after a ticket-pending observer aborts", async () => {
    const controller = new AbortController();
    const harness = makeHarness({
      onEvent: (event) => {
        if (event.type === "state" && event.state.status === "ticket_pending") {
          controller.abort();
        }
      },
    });

    const pending = harness.transport.connect(ATTACH_INPUT, controller.signal);
    await expect(pending).rejects.toMatchObject({ code: "aborted" });
    await flush();
    expect(harness.ticketProvider).not.toHaveBeenCalled();
    expect(harness.sockets).toHaveLength(0);
    expect(harness.transport.state.status).toBe("detached");
  });

  it("rejects malformed tickets with bounded semantic errors before upgrade", async () => {
    const fragment = "credential-shaped-ticket-fragment";
    const harness = makeHarness({ ticketProvider: async () => `${fragment}!` });
    const error = await harness.transport.connect(ATTACH_INPUT).catch((value: unknown) => value);
    expect(error).toMatchObject({ code: "invalid-ticket" });
    expect(String(error)).not.toContain(fragment);
    expect(harness.sockets).toHaveLength(0);
    expect(JSON.stringify(harness.transport.state)).not.toContain(fragment);
  });

  it("treats missing and empty attach as exact legacy mode", async () => {
    for (const input of [
      { sessionId: "session-legacy-missing" },
      { sessionId: "session-legacy-empty", attach: "" },
    ] satisfies PtyConnectionInput[]) {
      const harness = makeHarness();
      const socket = await open(harness, input);
      expect(harness.upgrades[0]?.query).toEqual({
        ticket: "ticket-1",
        resume: input.sessionId,
      });
      expect(harness.transport.state.mode).toBe("legacy");
      harness.transport.detach();
      expect(socket.closes).toEqual([{ code: 1000, reason: "client-detach" }]);
      expect(harness.transport.state.status).toBe("exited");
      await expect(harness.transport.reconnect()).rejects.toMatchObject({
        code: "legacy-reattach-prohibited",
      });
    }
  });

  it("fails attach preflight before ticket mint or socket creation", async () => {
    const harness = makeHarness({ validateAttachment: async () => false });
    await expect(harness.transport.connect(ATTACH_INPUT)).rejects.toMatchObject({
      code: "invalid-attachment",
    });
    expect(harness.ticketProvider).not.toHaveBeenCalled();
    expect(harness.sockets).toHaveLength(0);
  });

  it("preserves raw frame bytes and rejects non-binary frames", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const harness = makeHarness();
    const socket = await open(harness);
    socket.message(new Uint8Array([0, 255, 27, 91, 128]).buffer);
    await flush();
    const bytes = harness.events.filter((event) => event.type === "bytes");
    expect(bytes).toHaveLength(1);
    expect([...bytes[0]!.bytes]).toEqual([0, 255, 27, 91, 128]);
    expect(consoleSpy).not.toHaveBeenCalled();

    socket.message("not-binary");
    await flush();
    expect(harness.transport.state.status).toBe("failed");
    expect(socket.closes.at(-1)).toEqual({ code: 1000, reason: "client-detach" });
    consoleSpy.mockRestore();
  });

  it("drops a delayed binary conversion after Close", async () => {
    let resolveBytes!: (value: ArrayBuffer) => void;
    class DeferredBlob extends Blob {
      override arrayBuffer(): Promise<ArrayBuffer> {
        return new Promise((resolve) => {
          resolveBytes = resolve;
        });
      }
    }
    const harness = makeHarness();
    const socket = await open(harness);
    socket.message(new DeferredBlob([new Uint8Array([0xaa])]));
    await flush();
    harness.transport.close();
    resolveBytes(new Uint8Array([0xaa]).buffer);
    await flush();
    expect(harness.events.filter((event) => event.type === "bytes")).toHaveLength(0);
    expect(harness.transport.state.status).toBe("detached");
  });

  it("encodes exact clamped resize frames and rejects malformed dimensions", async () => {
    const cases = [
      [1, 1, "1b5b524553495a453a313b315d"],
      [2000, 1000, "1b5b524553495a453a323030303b313030305d"],
      [-1, 24, "1b5b524553495a453a313b32345d"],
      [2001, 1001, "1b5b524553495a453a323030303b313030305d"],
    ] as const;
    for (const [cols, rows, expected] of cases) {
      expect(Buffer.from(encodeResize(cols, rows)).toString("hex")).toBe(expected);
    }
    for (const [cols, rows] of [
      [1.5, 24],
      [80, 24.5],
      [Number.NaN, 24],
      [80, Number.POSITIVE_INFINITY],
      [true, 24],
      [80, "24"],
      [null, 24],
    ] as unknown as Array<[number, number]>) {
      expect(() => encodeResize(cols, rows)).toThrow(PtyTransportError);
    }

    const harness = makeHarness();
    const socket = await open(harness);
    harness.transport.resize(80, 24);
    expect(Buffer.from(socket.sent[0]!).toString("hex")).toBe(
      "1b5b524553495a453a38303b32345d",
    );
  });

  it("never queues or replays input, resize, prompt, or tool actions", async () => {
    const harness = makeHarness();
    const socket = await open(harness);
    harness.transport.sendInput("synthetic-input");
    harness.transport.resize(80, 24);
    expect(socket.sent).toHaveLength(2);
    harness.transport.detach();
    expect(() => harness.transport.sendInput("do-not-replay")).toThrowError(
      expect.objectContaining({ code: "not-attached" }),
    );
    expect(() => harness.transport.resize(100, 30)).toThrowError(
      expect.objectContaining({ code: "not-attached" }),
    );

    const replacement = await reattach(harness);
    expect(replacement.sent).toHaveLength(0);
    expect(Object.keys(harness.transport).sort()).toEqual([
      "close",
      "connect",
      "detach",
      "reconnect",
      "resize",
      "sendInput",
      "state",
      "subscribe",
    ]);
  });

  it("emits receive-order bytes and a bounded truncation notice on reattach", async () => {
    const harness = makeHarness();
    await open(harness);
    harness.transport.detach();
    const socket = await reattach(harness);
    socket.message(new Uint8Array([0x52]).buffer);
    socket.message(new Uint8Array([0x4c]).buffer);
    await flush();

    expect(
      harness.events
        .filter((event) => event.type === "notice")
        .map((event) => [event.notice, event.replayCapacityBytes]),
    ).toEqual([["output-may-be-truncated", PTY_REPLAY_CAPACITY_BYTES]]);
    expect(
      harness.events
        .filter((event) => event.type === "bytes")
        .map((event) => [event.bytes[0], event.outputMayBeTruncated]),
    ).toEqual([
      [0x52, true],
      [0x4c, true],
    ]);
  });

  it("allows the exact retention boundary and rejects expiry before ticket mint", async () => {
    let now = 100_000;
    const boundary = makeHarness({ now: () => now });
    await open(boundary);
    boundary.transport.detach();
    now += PTY_DETACH_RETENTION_MS;
    await reattach(boundary);
    expect(boundary.ticketProvider).toHaveBeenCalledTimes(2);

    boundary.transport.detach();
    now += PTY_DETACH_RETENTION_MS + 1;
    const socketCount = boundary.sockets.length;
    await expect(boundary.transport.reconnect()).rejects.toMatchObject({
      code: "expired-attachment",
    });
    expect(boundary.sockets).toHaveLength(socketCount);
    expect(boundary.ticketProvider).toHaveBeenCalledTimes(2);
  });

  it("cancels a pending session attempt before installing its late socket", async () => {
    let resolveFirst!: (socket: FakeSocket) => void;
    let factoryCalls = 0;
    const sockets: FakeSocket[] = [];
    const harness = makeHarness({
      validateAttachment: async () => true,
      createWebSocket: () => {
        factoryCalls += 1;
        const socket = new FakeSocket();
        sockets.push(socket);
        if (factoryCalls === 1) {
          return new Promise<PtyWebSocket>((resolve) => {
            resolveFirst = resolve as (socket: FakeSocket) => void;
          });
        }
        return socket;
      },
    });
    const firstPending = harness.transport.connect(ATTACH_INPUT);
    await flush();
    const replacementInput: PtyConnectionInput = {
      sessionId: "session-current-002",
      attach: "attach-current-002",
      processIdentity: "process-current-002",
    };
    const replacementPending = harness.transport.connect(replacementInput);
    await flush();
    sockets[1]!.open();
    await replacementPending;
    const late = sockets[0]!;
    resolveFirst(late);
    await expect(firstPending).rejects.toMatchObject({ code: "aborted" });
    await flush();
    expect(late.closes).toEqual([{ code: 1000, reason: "client-detach" }]);
    expect(harness.transport.state).toMatchObject({
      status: "attached",
      sessionId: replacementInput.sessionId,
    });
  });

  it("claims a replacement attempt before abort listeners can duplicate connect", async () => {
    let harness!: Harness;
    let ticketCalls = 0;
    let reentrant!: Promise<void>;
    const replacementInput: PtyConnectionInput = {
      sessionId: "session-abort-replacement",
      attach: "attach-abort-replacement",
      processIdentity: "process-abort-replacement",
    };
    harness = makeHarness({
      ticketProvider: async (signal) => {
        ticketCalls += 1;
        if (ticketCalls === 1) {
          signal.addEventListener(
            "abort",
            () => {
              reentrant = harness.transport.connect(replacementInput);
            },
            { once: true },
          );
          return new Promise<string>(() => undefined);
        }
        return `ticket-${ticketCalls}`;
      },
      validateAttachment: async () => true,
    });

    const first = harness.transport.connect(ATTACH_INPUT);
    await flush();
    const replacement = harness.transport.connect(replacementInput);
    await flush();
    expect(reentrant).toBe(replacement);
    expect(ticketCalls).toBe(2);
    const socket = harness.sockets[0]!;
    socket.open();
    await replacement;
    await expect(first).rejects.toMatchObject({ code: "aborted" });
  });

  it("does not reopen after an abort listener closes a replacement", async () => {
    let harness!: Harness;
    let ticketCalls = 0;
    const replacementInput: PtyConnectionInput = {
      sessionId: "session-abort-close",
      attach: "attach-abort-close",
      processIdentity: "process-abort-close",
    };
    harness = makeHarness({
      ticketProvider: async (signal) => {
        ticketCalls += 1;
        if (ticketCalls === 1) {
          signal.addEventListener("abort", () => harness.transport.close(), {
            once: true,
          });
          return new Promise<string>(() => undefined);
        }
        return `ticket-${ticketCalls}`;
      },
      validateAttachment: async () => true,
    });

    const first = harness.transport.connect(ATTACH_INPUT);
    await flush();
    const replacement = harness.transport.connect(replacementInput);
    await expect(first).rejects.toMatchObject({ code: "aborted" });
    await expect(replacement).rejects.toMatchObject({ code: "aborted" });
    expect(ticketCalls).toBe(1);
    expect(harness.transport.state.status).toBe("detached");

    const fresh = harness.transport.connect(replacementInput);
    await flush();
    expect(ticketCalls).toBe(2);
    const socket = harness.sockets[0]!;
    socket.open();
    await fresh;
  });

  it("closes a synchronous socket returned after connecting cancellation", async () => {
    let harness!: Harness;
    let created!: FakeSocket;
    harness = makeHarness({
      createWebSocket: () => {
        created = new FakeSocket();
        return created;
      },
      onStateChange: (state) => {
        if (state.status === "connecting") harness.transport.close();
      },
    });

    const pending = harness.transport.connect(ATTACH_INPUT);
    await expect(pending).rejects.toMatchObject({ code: "aborted" });
    await flush();
    expect(created.closes).toEqual([{ code: 1000, reason: "client-detach" }]);
    created.open();
    await flush();
    expect(harness.transport.state.status).toBe("detached");
  });

  it("closes a delayed socket resolved after connecting cancellation", async () => {
    let harness!: Harness;
    let resolveSocket!: (socket: FakeSocket) => void;
    const created = new FakeSocket();
    harness = makeHarness({
      createWebSocket: () =>
        new Promise<PtyWebSocket>((resolve) => {
          resolveSocket = resolve as (socket: FakeSocket) => void;
        }),
      onStateChange: (state) => {
        if (state.status === "connecting") harness.transport.close();
      },
    });

    const pending = harness.transport.connect(ATTACH_INPUT);
    await expect(pending).rejects.toMatchObject({ code: "aborted" });
    resolveSocket(created);
    await flush();
    expect(created.closes).toEqual([{ code: 1000, reason: "client-detach" }]);
    created.open();
    await flush();
    expect(harness.transport.state.status).toBe("detached");
  });

  it("replaces sessions without allowing stale callbacks to affect the active socket", async () => {
    const harness = makeHarness({
      validateAttachment: async () => true,
    });
    const first = await open(harness);
    const staleMessage = first.onmessage;
    const staleClose = first.onclose;
    const replacementInput: PtyConnectionInput = {
      sessionId: "session-current-002",
      attach: "attach-current-002",
      processIdentity: "process-current-002",
    };
    const replacementPending = harness.transport.connect(replacementInput);
    await flush();
    const replacement = harness.sockets[1]!;
    replacement.open();
    await replacementPending;

    staleMessage?.({ data: new Uint8Array([0xff]).buffer });
    staleClose?.({ code: 4409 });
    await flush();
    expect(harness.transport.state).toMatchObject({
      status: "attached",
      sessionId: replacementInput.sessionId,
      processIdentity: replacementInput.processIdentity,
    });
    expect(harness.events.filter((event) => event.type === "bytes")).toHaveLength(0);
    expect(first.closes.at(-1)).toEqual({ code: 1000, reason: "client-detach" });
  });

  it("observes 4409 before blocking stale reattach cleanup", async () => {
    const harness = makeHarness();
    const first = await open(harness);
    first.closeFromServer(4409);
    expect(harness.transport.state).toMatchObject({
      status: "detached",
      closeCode: 4409,
      closeClassification: "attachment-superseded",
    });
    await expect(harness.transport.reconnect()).rejects.toMatchObject({
      code: "attachment-superseded",
    });
    await expect(harness.transport.connect(ATTACH_INPUT)).rejects.toMatchObject({
      code: "attachment-superseded",
    });
    await expect(
      harness.transport.connect({ ...ATTACH_INPUT, detachedAtMs: 1 }),
    ).rejects.toMatchObject({ code: "attachment-superseded" });
    expect(harness.ticketProvider).toHaveBeenCalledTimes(1);
    expect(harness.sockets).toHaveLength(1);
  });

  it("does not extend expiry after a failed unopened reattach", async () => {
    let now = 0;
    const harness = makeHarness({ now: () => now });
    await open(harness);
    harness.transport.detach();
    now = PTY_DETACH_RETENTION_MS - 1_000;
    const failed = harness.transport.reconnect();
    await flush();
    harness.sockets[1]!.closeFromServer(1006);
    await expect(failed).rejects.toMatchObject({ code: "connection-failed" });
    now = PTY_DETACH_RETENTION_MS + 1;
    await expect(harness.transport.reconnect()).rejects.toMatchObject({
      code: "expired-attachment",
    });
    expect(harness.ticketProvider).toHaveBeenCalledTimes(2);
    expect(harness.sockets).toHaveLength(2);
  });

  it("anchors opened error-only attach retention once for the detached reattach state", async () => {
    let now = 100_000;
    const harness = makeHarness({ now: () => now });
    const socket = await open(harness);
    const staleError = socket.onerror;

    socket.onerror?.();
    expect(harness.transport.state.status).toBe("detached");
    expect(harness.ticketProvider).toHaveBeenCalledTimes(1);

    now += PTY_DETACH_RETENTION_MS - 1;
    await reattach(harness);
    expect(harness.ticketProvider).toHaveBeenCalledTimes(2);

    // The detached callback was removed. A buggy adapter may still invoke its
    // captured error function, but that stale event cannot create a new anchor.
    staleError?.();
    expect(harness.transport.state.status).toBe("attached");
  });

  it("does not extend an error-only retention anchor with repeated stale errors", async () => {
    let now = 200_000;
    const harness = makeHarness({ now: () => now });
    const socket = await open(harness);
    const staleError = socket.onerror;

    socket.onerror?.();
    now += PTY_DETACH_RETENTION_MS + 1;
    staleError?.();

    await expect(harness.transport.reconnect()).rejects.toMatchObject({
      code: "expired-attachment",
    });
    // Expiry is a failed reattach preflight, so the exposed action changes from
    // detached Reattach to the existing failed-state safe recovery contract.
    expect(harness.transport.state.status).toBe("failed");
    expect(harness.ticketProvider).toHaveBeenCalledTimes(1);
    expect(harness.sockets).toHaveLength(1);
  });

  it("emits immutable state transitions before reentrant Close transitions", async () => {
    let harness!: Harness;
    let closed = false;
    harness = makeHarness({
      onStateChange: (state) => {
        if (state.status === "attached" && !closed) {
          closed = true;
          harness.transport.close();
        }
      },
    });

    const pending = harness.transport.connect(ATTACH_INPUT);
    await flush();
    const socket = harness.sockets[0]!;
    socket.open();
    await expect(pending).rejects.toMatchObject({ code: "aborted" });
    expect(
      harness.events
        .filter((event) => event.type === "state")
        .map((event) => `${event.state.status}:${event.state.generation}`),
    ).toEqual([
      "ticket_pending:1",
      "connecting:1",
      "starting:1",
      "attached:1",
      "closing:2",
      "detached:2",
    ]);
    expect(socket.closes).toEqual([{ code: 1000, reason: "client-detach" }]);
    expect(harness.transport.state.status).toBe("detached");
  });

  it("does not invoke a stale onStateChange after onEvent closes", async () => {
    let harness!: Harness;
    const stateChanges: string[] = [];
    harness = makeHarness({
      onEvent: (event) => {
        if (event.type === "state" && event.state.status === "attached") {
          harness.transport.close();
        }
      },
      onStateChange: (state) => {
        stateChanges.push(`${state.status}:${state.generation}`);
      },
    });

    const pending = harness.transport.connect(ATTACH_INPUT);
    await flush();
    const socket = harness.sockets[0]!;
    socket.open();
    await expect(pending).rejects.toMatchObject({ code: "aborted" });
    expect(stateChanges).toEqual([
      "ticket_pending:1",
      "connecting:1",
      "starting:1",
      "closing:2",
      "detached:2",
    ]);
    expect(harness.transport.state.status).toBe("detached");
  });

  it("does not emit a stale reattach notice after an attached observer closes", async () => {
    let attachedCount = 0;
    let harness!: Harness;
    harness = makeHarness({
      onStateChange: (state) => {
        if (state.status === "attached") {
          attachedCount += 1;
          if (attachedCount === 2) harness.transport.close();
        }
      },
    });

    await open(harness);
    harness.transport.detach();
    const reattachPending = harness.transport.reconnect();
    await flush();
    const socket = harness.sockets[1]!;
    socket.open();
    await expect(reattachPending).rejects.toMatchObject({ code: "aborted" });
    expect(harness.events.filter((event) => event.type === "notice")).toHaveLength(0);
    expect(harness.transport.state.status).toBe("detached");
  });

  it("does not publish truncation after a reattach observer aborts", async () => {
    let attachedCount = 0;
    let harness!: Harness;
    const controller = new AbortController();
    harness = makeHarness({
      onStateChange: (state) => {
        if (state.status === "attached") {
          attachedCount += 1;
          if (attachedCount === 2) controller.abort();
        }
      },
    });

    await open(harness);
    harness.transport.detach();
    const pending = harness.transport.reconnect(controller.signal);
    await flush();
    const socket = harness.sockets[1]!;
    socket.open();
    await expect(pending).rejects.toMatchObject({ code: "aborted" });
    await flush();
    expect(harness.events.filter((event) => event.type === "notice")).toHaveLength(0);
    expect(harness.transport.state).toMatchObject({
      status: "detached",
      outputMayBeTruncated: false,
    });
    expect(socket.closes).toEqual([{ code: 1000, reason: "client-detach" }]);
  });

  it("resets truncation evidence on detach and explicit Close after a reattach", async () => {
    for (const operation of ["detach", "close"] as const) {
      const harness = makeHarness();
      await openTruncated(harness);
      harness.transport[operation]();
      expect(harness.transport.state.outputMayBeTruncated).toBe(false);
    }
  });

  it("resets truncation evidence after a prior reattach is cancelled", async () => {
    const harness = makeHarness();
    await openTruncated(harness);
    harness.transport.detach();
    const controller = new AbortController();
    const pending = harness.transport.reconnect(controller.signal);
    await flush();
    const socket = harness.sockets.at(-1)!;
    socket.open();
    controller.abort();
    await expect(pending).rejects.toMatchObject({ code: "aborted" });
    await flush();
    expect(harness.transport.state.outputMayBeTruncated).toBe(false);
  });

  it("resets truncation evidence on pre-open failure after a prior reattach", async () => {
    const replacementInput: PtyConnectionInput = {
      sessionId: "session-truncation-pre-open",
      attach: "attach-truncation-pre-open",
      processIdentity: "process-truncation-pre-open",
    };
    const harness = makeHarness({ validateAttachment: async () => true });
    await openTruncated(harness);
    const pending = harness.transport.connect(replacementInput);
    await flush();
    const socket = harness.sockets.at(-1)!;
    socket.closeFromServer(1006);
    await expect(pending).rejects.toMatchObject({ code: "connection-failed" });
    expect(harness.transport.state).toMatchObject({
      status: "failed",
      outputMayBeTruncated: false,
    });
  });

  it("resets truncation evidence on a fresh attach and ignores stale generations", async () => {
    const replacementInput: PtyConnectionInput = {
      sessionId: "session-truncation-fresh",
      attach: "attach-truncation-fresh",
      processIdentity: "process-truncation-fresh",
    };
    const harness = makeHarness({ validateAttachment: async () => true });
    const stale = await openTruncated(harness);
    const staleOpen = stale.onopen;
    const pending = harness.transport.connect(replacementInput);
    await flush();
    staleOpen?.();
    expect(harness.transport.state.outputMayBeTruncated).toBe(false);
    const replacement = harness.sockets.at(-1)!;
    replacement.open();
    await pending;
    expect(harness.transport.state).toMatchObject({
      status: "attached",
      outputMayBeTruncated: false,
    });
  });

  it("clears a failed pre-open attempt before synchronous retry observers run", async () => {
    let harness!: Harness;
    let retry: Promise<void> | undefined;
    let duplicateRetry: Promise<void> | undefined;
    harness = makeHarness({
      onStateChange: (state) => {
        if (state.status === "failed" && !retry) {
          retry = harness.transport.connect(ATTACH_INPUT);
          duplicateRetry = harness.transport.connect(ATTACH_INPUT);
        }
      },
    });

    const first = harness.transport.connect(ATTACH_INPUT);
    await flush();
    const failedSocket = harness.sockets[0]!;
    failedSocket.onerror?.();

    await expect(first).rejects.toMatchObject({ code: "connection-failed" });
    expect(retry).toBeDefined();
    expect(duplicateRetry).toBe(retry);
    await flush();
    const replacement = harness.sockets[1]!;
    replacement.open();
    await retry;
    expect(harness.transport.state.status).toBe("attached");
    expect(harness.ticketProvider).toHaveBeenCalledTimes(2);
  });

  it("keeps pre-open close and error failures out of detach retention", async () => {
    for (const signal of ["error", "close"] as const) {
      const harness = makeHarness();
      const pending = harness.transport.connect(ATTACH_INPUT);
      await flush();
      const socket = harness.sockets[0]!;
      if (signal === "error") socket.onerror?.();
      else socket.closeFromServer(1006);

      await expect(pending).rejects.toMatchObject({ code: "connection-failed" });
      expect(harness.transport.state.status).toBe("failed");
      await expect(harness.transport.reconnect()).rejects.toMatchObject({
        code: "invalid-attachment",
      });
      expect(harness.ticketProvider).toHaveBeenCalledTimes(1);
    }
  });

  it("does not let detached expiry evidence cross a replacement PTY identity", async () => {
    let now = 100_000;
    const harness = makeHarness({ now: () => now });
    await open(harness);
    harness.transport.detach();
    now += PTY_DETACH_RETENTION_MS + 1;
    const replacementInput: PtyConnectionInput = {
      sessionId: "session-current-replacement",
      attach: ATTACH_INPUT.attach,
      processIdentity: "process-current-replacement",
    };

    const pending = harness.transport.connect(replacementInput);
    await flush();
    const replacement = harness.sockets[1]!;
    replacement.open();
    await pending;
    expect(harness.transport.state).toMatchObject({
      status: "attached",
      sessionId: replacementInput.sessionId,
      processIdentity: replacementInput.processIdentity,
    });
  });

  it("does not retain A detach evidence after A Close reentrantly starts B", async () => {
    let now = 100_000;
    let harness!: Harness;
    let replacementPending: Promise<void> | undefined;
    const replacementInput: PtyConnectionInput = {
      sessionId: "session-current-reentrant-replacement",
      attach: "attach-current-reentrant-replacement",
      processIdentity: "process-current-reentrant-replacement",
    };
    harness = makeHarness({ now: () => now, validateAttachment: async () => true });
    const original = await open(harness);
    const originalClose = original.close.bind(original);
    original.close = (code, reason) => {
      if (!replacementPending) {
        replacementPending = harness.transport.connect(replacementInput);
      }
      originalClose(code, reason);
    };

    harness.transport.close();
    expect(replacementPending).toBeDefined();
    await flush();
    const replacement = harness.sockets[1]!;
    replacement.open();
    await replacementPending;

    now += PTY_DETACH_RETENTION_MS + 1;
    const reconnectOriginal = harness.transport.connect(ATTACH_INPUT);
    await flush();
    const reconnected = harness.sockets[2]!;
    reconnected.open();
    await reconnectOriginal;
    expect(harness.transport.state).toMatchObject({
      status: "attached",
      sessionId: ATTACH_INPUT.sessionId,
      processIdentity: ATTACH_INPUT.processIdentity,
    });
  });

  it("does not let a reentrant Close observer overwrite a replacement connection", async () => {
    let harness!: Harness;
    let replacementPending: Promise<void> | undefined;
    harness = makeHarness({
      onStateChange: (state) => {
        if (state.status === "closing" && !replacementPending) {
          replacementPending = harness.transport.connect(ATTACH_INPUT);
        }
      },
    });

    await open(harness);
    harness.transport.close();
    expect(harness.transport.state.status).toBe("closing");
    await flush();
    const replacement = harness.sockets[1]!;
    replacement.open();
    await replacementPending;
    expect(harness.transport.state.status).toBe("attached");
  });

  it("does not publish a stale failure after adapter close starts a replacement", async () => {
    let harness!: Harness;
    let replacementPending: Promise<void> | undefined;
    const replacementInput: PtyConnectionInput = {
      sessionId: "session-fail-context-replacement",
      attach: "attach-fail-context-replacement",
      processIdentity: "process-fail-context-replacement",
    };
    harness = makeHarness({ validateAttachment: async () => true });
    const socket = await open(harness);
    const originalClose = socket.close.bind(socket);
    socket.close = (code, reason) => {
      if (!replacementPending) {
        replacementPending = harness.transport.connect(replacementInput);
      }
      originalClose(code, reason);
    };

    socket.onerror?.();
    await flush();
    expect(replacementPending).toBeDefined();
    const replacement = harness.sockets[1]!;
    replacement.open();
    await replacementPending;
    expect(harness.transport.state).toMatchObject({
      status: "attached",
      sessionId: replacementInput.sessionId,
      processIdentity: replacementInput.processIdentity,
    });
    expect(
      harness.events.filter(
        (event) => event.type === "state" && event.state.status === "failed",
      ),
    ).toHaveLength(0);
  });

  it("reattaches attach mode after network loss but never legacy mode", async () => {
    const attached = makeHarness();
    const socket = await open(attached);
    socket.closeFromServer(1006);
    expect(attached.transport.state).toMatchObject({
      status: "detached",
      closeClassification: "connection-closed",
    });
    await reattach(attached);
    expect(attached.ticketProvider).toHaveBeenCalledTimes(2);

    const legacy = makeHarness();
    const legacySocket = await open(legacy, { sessionId: "session-legacy-loss" });
    legacySocket.closeFromServer(1006);
    expect(legacy.transport.state.status).toBe("exited");
    await expect(legacy.transport.reconnect()).rejects.toMatchObject({
      code: "legacy-reattach-prohibited",
    });
  });

  it("maps process exit and failures without unsafe automatic retry", async () => {
    for (const [code, status, classification] of [
      [4410, "exited", "pty-process-exited"],
      [4401, "failed", "authentication-rejected"],
      [4403, "failed", "host-or-origin-rejected"],
      [4404, "failed", "embedded-chat-disabled"],
      [4408, "failed", "peer-rejected"],
      [1011, "failed", "backend-failure"],
      [3999, "failed", "unsupported"],
    ] as const) {
      const harness = makeHarness();
      const socket = await open(harness);
      socket.closeFromServer(code);
      expect(harness.transport.state).toMatchObject({ status, closeClassification: classification });
      expect(harness.ticketProvider).toHaveBeenCalledTimes(1);
    }
  });

  it("detaches attach mode and exits legacy mode on Close with full cleanup", async () => {
    const attached = makeHarness();
    const attachedSocket = await open(attached);
    attached.transport.close();
    expect(attached.transport.state.status).toBe("detached");
    expect(attachedSocket.onmessage).toBeNull();
    expect(attachedSocket.onclose).toBeNull();
    expect(attachedSocket.closes).toEqual([{ code: 1000, reason: "client-detach" }]);

    const legacy = makeHarness();
    const legacySocket = await open(legacy, { sessionId: "session-legacy-close" });
    legacy.transport.close();
    expect(legacy.transport.state.status).toBe("exited");
    expect(legacySocket.onmessage).toBeNull();
    expect(legacySocket.onclose).toBeNull();
  });

  it("blocks reconnect after explicit Close until a new connect", async () => {
    const harness = makeHarness();
    const first = await open(harness);
    const staleOpen = first.onopen;
    const staleClose = first.onclose;
    harness.transport.close();
    harness.transport.detach();
    await expect(harness.transport.reconnect()).rejects.toMatchObject({
      code: "closed",
    });
    expect(harness.ticketProvider).toHaveBeenCalledTimes(1);
    expect(harness.sockets).toHaveLength(1);

    staleOpen?.();
    staleClose?.({ code: 1006 });
    expect(harness.transport.state.status).toBe("detached");

    const replacementPending = harness.transport.connect(ATTACH_INPUT);
    await flush();
    const replacement = harness.sockets.at(-1);
    if (!replacement) throw new Error("missing replacement fake socket");
    replacement.open();
    await replacementPending;
    expect(harness.transport.state.status).toBe("attached");
    expect(harness.ticketProvider).toHaveBeenCalledTimes(2);
    expect(harness.sockets).toHaveLength(2);
  });

  it("keeps observer failures outside lifecycle and retained diagnostics", async () => {
    const secret = "secret-callback-fragment";
    const harness = makeHarness({
      onEvent: () => {
        throw new Error(secret);
      },
      onStateChange: () => {
        throw new Error(secret);
      },
    });
    harness.transport.subscribe(() => {
      throw new Error(secret);
    });
    const socket = await open(harness);
    socket.message(new Uint8Array([0xaa]).buffer);
    await flush();
    expect(harness.transport.state.status).toBe("attached");
    expect(JSON.stringify(harness.transport.state)).not.toContain(secret);
  });

  it("aborts after socket installation and prevents a late open", async () => {
    const controller = new AbortController();
    const harness = makeHarness();
    const pending = harness.transport.connect(ATTACH_INPUT, controller.signal);
    await flush();
    const socket = harness.sockets[0]!;
    controller.abort();
    await expect(pending).rejects.toMatchObject({ code: "aborted" });
    socket.open();
    await flush();
    expect(socket.closes).toEqual([{ code: 1000, reason: "client-detach" }]);
    expect(harness.transport.state.status).toBe("detached");
  });

  it("aborts pending authentication and closes late sockets without retaining secrets", async () => {
    let resolveSocket!: (socket: FakeSocket) => void;
    const controller = new AbortController();
    const ticketFragment = "ticket-sensitive-fragment";
    const harness = makeHarness({
      ticketProvider: async () => ticketFragment,
      createWebSocket: () =>
        new Promise<PtyWebSocket>((resolve) => {
          resolveSocket = resolve as (socket: FakeSocket) => void;
        }),
    });
    const pending = harness.transport.connect(ATTACH_INPUT, controller.signal);
    await flush();
    controller.abort();
    const late = new FakeSocket();
    resolveSocket(late);
    await expect(pending).rejects.toMatchObject({ code: "aborted" });
    await flush();
    expect(late.closes).toEqual([{ code: 1000, reason: "client-detach" }]);
    expect(JSON.stringify(harness.transport.state)).not.toContain(ticketFragment);
  });
});
