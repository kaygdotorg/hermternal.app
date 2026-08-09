import { describe, expect, it, vi } from "vitest";
import {
  PtyTransportError,
  type PtyConnectionInput,
  type PtyConnectionState,
  type PtyTransport,
  type PtyTransportEvent,
  type PtyWebSocket,
} from "./pty-transport";
import type { TerminalBinding } from "$lib/session/coordinator";
import {
  CurrentSessionTerminalBridge,
  createBrowserPtyTransport,
  type CurrentSessionTerminalEvent,
  type BrowserPtyWebSocketFactory,
} from "./current-session-terminal";

function deferred<T>(): {
  readonly promise: Promise<T>;
  resolve(value: T): void;
} {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((nextResolve) => {
    resolve = nextResolve;
  });
  return { promise, resolve };
}

async function flush(): Promise<void> {
  for (let index = 0; index < 32; index += 1) await Promise.resolve();
}

function isValid(binding: TerminalBinding): boolean {
  return (
    (binding as TerminalBinding & { isValid?: () => boolean }).isValid?.() ??
    false
  );
}

function createFakePty() {
  const listeners = new Set<(event: PtyTransportEvent) => void>();
  const initial: PtyConnectionState = {
    status: "closed",
    generation: 0,
    mode: "legacy",
    outputMayBeTruncated: false,
  };
  let state = initial;
  const connect = vi.fn(
    async (input: PtyConnectionInput, _signal?: AbortSignal) => {
      state = {
        status: "attached",
        generation: state.generation + 1,
        mode: input.attach ? "attach" : "legacy",
        sessionId: input.sessionId,
        ...(input.attach && input.processIdentity
          ? { processIdentity: input.processIdentity }
          : {}),
        outputMayBeTruncated: false,
      };
      for (const listener of listeners) listener({ type: "state", state });
    },
  );
  const detach = vi.fn(() => {
    state = {
      ...state,
      status: "detached",
    };
    for (const listener of listeners) listener({ type: "state", state });
  });
  const close = vi.fn(() => {
    state = {
      ...state,
      status: "exited",
    };
    for (const listener of listeners) listener({ type: "state", state });
  });
  const reconnect = vi.fn(async () => {
    if (state.mode !== "attach") {
      throw new PtyTransportError(
        "legacy-reattach-prohibited",
        state.generation,
      );
    }
    state = {
      ...state,
      status: "attached",
      generation: state.generation + 1,
    };
    for (const listener of listeners) listener({ type: "state", state });
  });
  const pty: PtyTransport = {
    get state() {
      return state;
    },
    connect,
    reconnect,
    sendInput: vi.fn(),
    resize: vi.fn(),
    detach,
    close,
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
  return {
    pty,
    connect,
    reconnect,
    detach,
    close,
    emit(event: PtyTransportEvent) {
      if (event.type === "state") state = event.state;
      for (const listener of listeners) listener(event);
    },
  };
}

describe("CurrentSessionTerminalBridge", () => {
  it("owns one PTY, reuses a same-session binding, and invalidates on replacement", async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
    });

    const first = await bridge.attach(
      "session-one",
      new AbortController().signal,
    );
    const second = await bridge.attach(
      "session-one",
      new AbortController().signal,
    );
    expect(second).toBe(first);
    expect(fake.connect).toHaveBeenCalledTimes(1);

    first.invalidate();
    expect(fake.detach).toHaveBeenCalledTimes(1);
    expect(isValid(first)).toBe(false);

    await bridge.attach("session-two", new AbortController().signal);
    expect(fake.connect).toHaveBeenCalledTimes(2);
  });

  it("exposes only its real binding and native transport generation as lifecycle identity", async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
    });

    expect(bridge.lifecycleIdentity).toEqual({
      binding: undefined,
      nativeTransportGeneration: 0,
    });
    const binding = await bridge.attach(
      "session-one",
      new AbortController().signal,
    );
    expect(bridge.lifecycleIdentity).toEqual({
      binding,
      nativeTransportGeneration: 1,
    });

    binding.invalidate();
    // Invalidating a lease does not invent a root-facing lifecycle value. The
    // identity is absent while the bridge retains the transport's real number.
    expect(bridge.lifecycleIdentity).toEqual({
      binding: undefined,
      nativeTransportGeneration: 1,
    });
  });

  it("stamps state callbacks with the active bridge lease before a 4401 retires it", async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({ createTransport: () => fake.pty });
    const states: Extract<CurrentSessionTerminalEvent, { type: "state" }>[] = [];
    bridge.subscribe((event) => {
      if (event.type === "state") states.push(event);
    });
    const binding = await bridge.attach("session-one", new AbortController().signal);
    states.length = 0;

    fake.emit({
      type: "state",
      state: {
        status: "failed",
        generation: 2,
        mode: "legacy",
        sessionId: "session-one",
        closeCode: 4401,
        closeClassification: "authentication-rejected",
        outputMayBeTruncated: false,
      },
    });

    expect(states.at(-1)?.lifecycle).toEqual({ binding, nativeTransportGeneration: 1 });
    expect(bridge.lifecycleIdentity.binding).toBeUndefined();
  });

  it.each([
    [["detach", "detach"], 1, 0],
    [["close", "close"], 0, 1],
    [["detach", "close"], 1, 0],
    [["close", "detach"], 0, 1],
  ] as const)(
    "assigns one cleanup owner across %s",
    async (actions, detaches, closes) => {
      const fake = createFakePty();
      const bridge = new CurrentSessionTerminalBridge({
        createTransport: () => fake.pty,
      });
      await bridge.attach("session-one", new AbortController().signal);

      for (const action of actions) bridge[action]();
      bridge.dispose();

      expect(fake.detach).toHaveBeenCalledTimes(detaches);
      expect(fake.close).toHaveBeenCalledTimes(closes);
    },
  );

  it("forwards the exact raw Uint8Array without decoding or retaining it", async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
    });
    const events: CurrentSessionTerminalEvent[] = [];
    bridge.subscribe((event) => events.push(event));
    await bridge.attach("session-one", new AbortController().signal);

    const bytes = new Uint8Array([0xff, 0x00, 0x80]);
    fake.emit({
      type: "bytes",
      generation: 1,
      bytes,
      outputMayBeTruncated: false,
    });

    const byteEvent = events.find(
      (
        event,
      ): event is Extract<CurrentSessionTerminalEvent, { type: "bytes" }> =>
        event.type === "bytes",
    );
    expect(byteEvent?.bytes).toBe(bytes);
    expect(JSON.stringify(bridge.state)).not.toContain("ff");
    expect(JSON.stringify(bridge.state)).not.toContain("128");
  });

  it("projects 4401 authentication and 4403 origin boundaries without sharing raw errors", () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
    });
    const states: string[] = [];
    bridge.subscribe((event) => {
      if (event.type === "state") states.push(event.state.failure ?? "none");
    });

    fake.emit({
      type: "state",
      state: {
        status: "failed",
        generation: 1,
        mode: "legacy",
        sessionId: "session-one",
        closeCode: 4401,
        closeClassification: "authentication-rejected",
        outputMayBeTruncated: false,
      },
    });
    fake.emit({
      type: "state",
      state: {
        status: "failed",
        generation: 2,
        mode: "legacy",
        sessionId: "session-one",
        closeCode: 4403,
        closeClassification: "host-or-origin-rejected",
        outputMayBeTruncated: false,
      },
    });

    expect(states).toEqual([
      "none",
      "authentication-required",
      "incompatible-origin",
    ]);
    expect(bridge.state.closeCode).toBe(4403);
    expect(bridge.state.failure).toBe("incompatible-origin");
  });

  it("rejects stale-generation bytes and invalidates a binding after unsolicited PTY failure", async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
    });
    const events: CurrentSessionTerminalEvent[] = [];
    bridge.subscribe((event) => events.push(event));
    const binding = await bridge.attach(
      "session-one",
      new AbortController().signal,
    );

    const staleBytes = new Uint8Array([1]);
    fake.emit({
      type: "bytes",
      generation: 0,
      bytes: staleBytes,
      outputMayBeTruncated: false,
    });
    expect(events.some((event) => event.type === "bytes")).toBe(false);

    fake.emit({
      type: "state",
      state: {
        status: "detached",
        generation: 2,
        mode: "legacy",
        sessionId: "session-one",
        outputMayBeTruncated: false,
      },
    });
    expect(isValid(binding)).toBe(false);

    await bridge.attach("session-one", new AbortController().signal);
    expect(fake.connect).toHaveBeenCalledTimes(2);
  });

  it("invalidates only the matching stale binding and allows a later attach to recover", async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
    });
    const events: CurrentSessionTerminalEvent[] = [];
    bridge.subscribe((event) => events.push(event));

    const staleBinding = await bridge.attach(
      "session-one",
      new AbortController().signal,
    );
    const staleIdentity = bridge.lifecycleIdentity;
    events.length = 0;
    bridge.invalidateBindingForSession("session-one", staleIdentity);

    expect(isValid(staleBinding)).toBe(false);
    expect(fake.detach).toHaveBeenCalledTimes(1);
    expect(events).toEqual([]);
    expect(bridge.state.status).toBe("detached");
    expect(bridge.state.sessionId).toBeUndefined();

    const freshBinding = await bridge.attach(
      "session-one",
      new AbortController().signal,
    );
    const bytes = new Uint8Array([0xff, 0x00, 0x80]);
    fake.emit({
      type: "bytes",
      generation: 2,
      bytes,
      outputMayBeTruncated: false,
    });

    expect(isValid(freshBinding)).toBe(true);
    expect(events.find((event) => event.type === "bytes")).toMatchObject({
      bytes,
    });

    // Same session id is insufficient: a delayed A callback must not detach B.
    bridge.invalidateBindingForSession("session-one", staleIdentity);
    expect(isValid(freshBinding)).toBe(true);
    expect(bridge.lifecycleIdentity.binding).toBe(freshBinding);
    expect(fake.detach).toHaveBeenCalledTimes(1);

    const otherFake = createFakePty();
    const otherBridge = new CurrentSessionTerminalBridge({
      createTransport: () => otherFake.pty,
    });
    const otherBinding = await otherBridge.attach(
      "session-two",
      new AbortController().signal,
    );
    otherBridge.invalidateBindingForSession(
      "session-one",
      otherBridge.lifecycleIdentity,
    );
    expect(isValid(otherBinding)).toBe(true);
  });

  it("finishes cleanup after an adapter ignores binding invalidation until late connect completion", async () => {
    const fake = createFakePty();
    const connectGate = deferred<void>();
    const originalConnect = fake.connect.getMockImplementation();
    if (!originalConnect)
      throw new Error("PTY connect implementation is missing");
    fake.connect.mockImplementation(async (input, signal) => {
      await connectGate.promise;
      return originalConnect(input, signal);
    });
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
    });
    const events: CurrentSessionTerminalEvent[] = [];
    bridge.subscribe((event) => events.push(event));

    const pending = bridge.attach("session-one", new AbortController().signal);
    await Promise.resolve();
    await Promise.resolve();
    bridge.invalidateBindingForSession("session-one", bridge.lifecycleIdentity);
    connectGate.resolve(undefined);

    await expect(pending).rejects.toMatchObject({ code: "aborted" });
    // The native transport owns its late-connect generation fence. The bridge
    // makes one cleanup decision and only releases quarantine after settlement.
    expect(fake.detach).toHaveBeenCalledTimes(1);
    expect(bridge.state.status).toBe("detached");
    expect(bridge.state.sessionId).toBeUndefined();
    expect(
      events.filter(
        (event) => event.type === "state" && event.state.status === "attached",
      ),
    ).toEqual([]);

    bridge.invalidateBindingForSession("session-one", bridge.lifecycleIdentity);
    expect(fake.detach).toHaveBeenCalledTimes(1);
  });

  it("stops later listeners after the first stale-state listener invalidates the binding", async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
    });
    const firstListener = vi.fn((event: CurrentSessionTerminalEvent) => {
      if (event.type === "state" && event.state.status === "attached") {
        bridge.invalidateBindingForSession(
          "session-one",
          bridge.lifecycleIdentity,
        );
      }
    });
    const secondListener = vi.fn();
    bridge.subscribe(firstListener);
    bridge.subscribe(secondListener);
    firstListener.mockClear();
    secondListener.mockClear();

    await expect(
      bridge.attach("session-one", new AbortController().signal),
    ).rejects.toMatchObject({
      code: "aborted",
    });

    expect(firstListener).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "state",
        state: expect.objectContaining({ status: "attached" }),
      }),
    );
    expect(secondListener).not.toHaveBeenCalledWith(
      expect.objectContaining({
        type: "state",
        state: expect.objectContaining({ status: "attached" }),
      }),
    );
    expect(fake.detach).toHaveBeenCalledTimes(1);
    expect(bridge.state.status).toBe("detached");
  });

  it("suppresses stale bytes, notices, and immediate state replay after invalidation", async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
    });
    const events: CurrentSessionTerminalEvent[] = [];
    await bridge.attach("session-one", new AbortController().signal);
    bridge.subscribe((event) => events.push(event));
    events.length = 0;
    bridge.invalidateBindingForSession("session-one", bridge.lifecycleIdentity);

    fake.emit({
      type: "bytes",
      generation: 1,
      bytes: new Uint8Array([1]),
      outputMayBeTruncated: false,
    });
    fake.emit({
      type: "notice",
      generation: 1,
      notice: "output-may-be-truncated",
      replayCapacityBytes: 1,
    });
    const laterEvents: CurrentSessionTerminalEvent[] = [];
    bridge.subscribe((event) => laterEvents.push(event));

    expect(events).toEqual([]);
    expect(laterEvents).toEqual([]);
  });

  it("checks cancellation before same-session binding reuse and isolates initial observer errors", async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
    });
    const binding = await bridge.attach(
      "session-one",
      new AbortController().signal,
    );
    const controller = new AbortController();
    controller.abort();

    await expect(
      bridge.attach("session-one", controller.signal),
    ).rejects.toMatchObject({ code: "aborted" });
    expect(fake.connect).toHaveBeenCalledTimes(1);
    expect(isValid(binding)).toBe(true);

    expect(() =>
      bridge.subscribe(() => {
        throw new Error("observer failure");
      }),
    ).not.toThrow();
  });

  it("waits for the lazy renderer gate before the first PTY attach", async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
    });
    bridge.setRendererReady(false);
    const pending = bridge.attach("session-one", new AbortController().signal);

    await Promise.resolve();
    expect(fake.connect).not.toHaveBeenCalled();
    bridge.setRendererReady(true);
    await pending;
    expect(fake.connect).toHaveBeenCalledTimes(1);
  });

  it("does not release a pending attach when the renderer sink is torn down", async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
    });
    bridge.setRendererReady(false);
    const pending = bridge.attach("session-one", new AbortController().signal);

    await Promise.resolve();
    bridge.setRendererReady(false);
    await Promise.resolve();
    expect(fake.connect).not.toHaveBeenCalled();

    bridge.dispose();
    await expect(pending).rejects.toMatchObject({ code: "closed" });
    expect(fake.connect).not.toHaveBeenCalled();
  });

  it("defers the first PTY bytes across an independent renderer remount", async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
    });
    const events: CurrentSessionTerminalEvent[] = [];
    bridge.subscribe((event) => events.push(event));
    bridge.setRendererReady(false);
    const pending = bridge.attach("session-one", new AbortController().signal);

    await Promise.resolve();
    bridge.setRendererReady(false);
    await Promise.resolve();
    expect(fake.connect).not.toHaveBeenCalled();
    expect(events.some((event) => event.type === "bytes")).toBe(false);

    // A later renderer mount is the only operation allowed to reopen the gate.
    bridge.setRendererReady(true);
    await pending;
    expect(fake.connect).toHaveBeenCalledTimes(1);

    const bytes = new Uint8Array([0xff, 0x00, 0x80]);
    fake.emit({
      type: "bytes",
      generation: 1,
      bytes,
      outputMayBeTruncated: false,
    });
    const byteEvent = events.find(
      (
        event,
      ): event is Extract<CurrentSessionTerminalEvent, { type: "bytes" }> =>
        event.type === "bytes",
    );
    expect(byteEvent?.bytes).toBe(bytes);
  });

  it("rejects reconnect for the normal legacy binding instead of pretending it can reattach", async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
    });

    await bridge.attach("session-one", new AbortController().signal);

    expect(bridge.state.reconnectSupported).toBe(false);
    await expect(bridge.reconnect()).rejects.toMatchObject({
      code: "legacy-reattach-prohibited",
    });
    expect(fake.pty.reconnect).not.toHaveBeenCalled();
  });

  it("hides deterministic attach-mode reconnect blocks from the public retry state", async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
    });
    fake.emit({
      type: "state",
      state: {
        status: "failed",
        generation: 1,
        mode: "attach",
        sessionId: "session-one",
        closeCode: 4403,
        closeClassification: "host-or-origin-rejected",
        outputMayBeTruncated: false,
      },
    });

    expect(bridge.state.reconnectSupported).toBe(false);
    await expect(bridge.reconnect()).rejects.toMatchObject({
      code: "legacy-reattach-prohibited",
    });
    expect(fake.reconnect).not.toHaveBeenCalled();
  });

  it("keeps reviewed attach identity values inside the transport and exposes attach-mode reconnect", async () => {
    const fake = createFakePty();
    const createAttachment = vi.fn(async (sessionId: string) => ({
      attach: `attach-${sessionId}`,
      processIdentity: `process-${sessionId}`,
    }));
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
      createAttachment,
    });

    await bridge.attach("session-one", new AbortController().signal);

    expect(createAttachment).toHaveBeenCalledWith(
      "session-one",
      expect.any(AbortSignal),
    );
    expect(fake.connect).toHaveBeenCalledWith(
      {
        sessionId: "session-one",
        attach: "attach-session-one",
        processIdentity: "process-session-one",
      },
      expect.any(AbortSignal),
    );
    expect(bridge.state).toMatchObject({
      status: "attached",
      reconnectSupported: true,
    });

    await bridge.reconnect();
    expect(fake.pty.reconnect).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(bridge.state)).not.toContain("attach-session-one");
    expect(JSON.stringify(bridge.state)).not.toContain("process-session-one");
  });

  it("cancels renderer-gated attach and reconnect on explicit detach", async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
      createAttachment: () => ({
        attach: "attach-one",
        processIdentity: "process-one",
      }),
    });
    bridge.setRendererReady(false);
    const pendingAttach = bridge.attach(
      "session-one",
      new AbortController().signal,
    );
    await Promise.resolve();
    bridge.detach();
    await expect(pendingAttach).rejects.toMatchObject({ code: "aborted" });
    bridge.setRendererReady(true);
    expect(fake.connect).not.toHaveBeenCalled();

    await bridge.attach("session-one", new AbortController().signal);
    bridge.setRendererReady(false);
    const pendingReconnect = bridge.reconnect();
    await Promise.resolve();
    bridge.detach();
    await expect(pendingReconnect).rejects.toMatchObject({ code: "aborted" });
    bridge.setRendererReady(true);
    expect(fake.reconnect).not.toHaveBeenCalled();
  });

  it("allows a legitimate attach-mode reconnect to clear a stale marker", async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
      createAttachment: () => ({
        attach: "attach-one",
        processIdentity: "process-one",
      }),
    });
    const events: CurrentSessionTerminalEvent[] = [];
    bridge.subscribe((event) => events.push(event));
    await bridge.attach("session-one", new AbortController().signal);
    bridge.invalidateBindingForSession("session-one", bridge.lifecycleIdentity);
    events.length = 0;
    fake.reconnect.mockImplementation(async () => {
      fake.emit({
        type: "state",
        state: {
          status: "reattaching",
          generation: 2,
          mode: "attach",
          sessionId: "session-one",
          outputMayBeTruncated: false,
        },
      });
      fake.emit({
        type: "state",
        state: {
          status: "attached",
          generation: 2,
          mode: "attach",
          sessionId: "session-one",
          outputMayBeTruncated: false,
        },
      });
    });

    await bridge.reconnect();
    const bytes = new Uint8Array([7]);
    fake.emit({
      type: "bytes",
      generation: 2,
      bytes,
      outputMayBeTruncated: true,
    });

    expect(events.map((event) => event.type)).toEqual([
      "state",
      "state",
      "bytes",
    ]);
    expect(events.at(-1)).toMatchObject({ type: "bytes", bytes });
  });

  it("waits for renderer readiness before attach-mode reconnect", async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
      createAttachment: () => ({
        attach: "attach-one",
        processIdentity: "process-one",
      }),
    });

    await bridge.attach("session-one", new AbortController().signal);
    bridge.setRendererReady(false);
    const pending = bridge.reconnect();

    await Promise.resolve();
    expect(fake.pty.reconnect).not.toHaveBeenCalled();
    bridge.setRendererReady(true);
    await pending;
    expect(fake.pty.reconnect).toHaveBeenCalledTimes(1);
  });

  it("suppresses synchronous transport events after bridge disposal", async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
    });
    const events: CurrentSessionTerminalEvent[] = [];
    bridge.subscribe((event) => events.push(event));
    await bridge.attach("session-one", new AbortController().signal);
    events.length = 0;

    bridge.dispose();

    expect(events).toEqual([]);
    expect(() => bridge.sendInput("after dispose")).toThrowError(
      expect.objectContaining({ code: "closed" }),
    );
    expect(() => bridge.resize(80, 24)).toThrowError(
      expect.objectContaining({ code: "closed" }),
    );
    expect(fake.close).toHaveBeenCalledTimes(1);
  });

  it("fails closed before ticket minting when browser origin is absent", () => {
    vi.stubGlobal("location", undefined);
    const fetcher = vi.fn();
    const createSocket = vi.fn();

    expect(() =>
      createBrowserPtyTransport({ fetch: fetcher, createSocket }),
    ).toThrowError(expect.objectContaining({ code: "invalid-options" }));
    expect(fetcher).not.toHaveBeenCalled();
    expect(createSocket).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });

  it("keeps browser attach mode closed without an issuance validator", async () => {
    vi.stubGlobal("location", { origin: "https://reviewed.example" });
    const fetcher = vi.fn();
    const createSocket = vi.fn();
    const transport = createBrowserPtyTransport({
      fetch: fetcher,
      createSocket,
    });

    await expect(
      transport.connect({
        sessionId: "session-one",
        attach: "attach-one",
        processIdentity: "process-one",
      }),
    ).rejects.toMatchObject({ code: "invalid-attachment" });
    expect(fetcher).not.toHaveBeenCalled();
    expect(createSocket).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });

  it("passes attach mode only through the injected issuance validator", async () => {
    vi.stubGlobal("location", { origin: "https://reviewed.example" });
    let readyState = 0;
    const socket: PtyWebSocket = {
      onopen: null,
      onmessage: null,
      onerror: null,
      onclose: null,
      get readyState() {
        return readyState;
      },
      send: vi.fn(),
      close: vi.fn(),
    };
    const fetcher = vi.fn(
      async () =>
        new Response(
          JSON.stringify({ ticket: "pty-ticket", ttl_seconds: 30 }),
          {
            headers: { "content-type": "application/json" },
          },
        ),
    );
    const validateAttachment = vi.fn(() => true);
    const transport = createBrowserPtyTransport({
      fetch: fetcher,
      createSocket: () => socket,
      validateAttachment,
    });
    const pending = transport.connect({
      sessionId: "session-one",
      attach: "attach-one",
      processIdentity: "process-one",
    });
    await flush();
    expect(validateAttachment).toHaveBeenCalledWith(
      expect.objectContaining({
        attach: "attach-one",
        processIdentity: "process-one",
      }),
      expect.any(AbortSignal),
    );
    readyState = 1;
    socket.onopen?.();
    await pending;
    expect(transport.state.status).toBe("attached");
    vi.unstubAllGlobals();
  });

  it.each([
    ["http://localhost", "ws:"],
    ["https://reviewed.example", "wss:"],
  ] as const)(
    "maps the browser origin %s to a %s PTY upgrade",
    async (origin, protocol) => {
      vi.stubGlobal("location", { origin });
      let readyState = 0;
      const socket: PtyWebSocket = {
        onopen: null,
        onmessage: null,
        onerror: null,
        onclose: null,
        get readyState() {
          return readyState;
        },
        send: vi.fn(),
        close: vi.fn(),
      };
      const urls: string[] = [];
      const signals: AbortSignal[] = [];
      const createSocket: BrowserPtyWebSocketFactory = vi.fn((url, signal) => {
        urls.push(url);
        signals.push(signal);
        return socket;
      });
      const transport = createBrowserPtyTransport({
        fetch: vi.fn(
          async () =>
            new Response(
              JSON.stringify({ ticket: "pty-ticket", ttl_seconds: 30 }),
              {
                headers: { "content-type": "application/json" },
              },
            ),
        ),
        createSocket,
      });

      const pending = transport.connect({ sessionId: "session-one" });
      await flush();
      expect(createSocket).toHaveBeenCalledTimes(1);
      expect(signals[0]).toEqual(expect.any(AbortSignal));
      const upgrade = new URL(urls[0] ?? "http://invalid");
      expect(upgrade.protocol).toBe(protocol);
      expect(upgrade.pathname).toBe("/api/pty");

      readyState = 1;
      socket.onopen?.();
      await pending;
      expect(transport.state.status).toBe("attached");
      vi.unstubAllGlobals();
    },
  );

  it("closes a default browser socket once when abort and PTY cleanup overlap", async () => {
    vi.stubGlobal("location", { origin: "https://reviewed.example" });
    const close = vi.fn();
    class NativeSocket {
      static latest: NativeSocket | undefined;
      binaryType = "";
      readyState = 0;
      onopen: ((event?: unknown) => void) | null = null;
      onmessage: ((event: MessageEvent) => void) | null = null;
      onerror: ((event?: unknown) => void) | null = null;
      onclose: ((event: CloseEvent) => void) | null = null;
      constructor(_url: string) {
        NativeSocket.latest = this;
      }
      send(_data: unknown): void {}
      close = close;
    }
    vi.stubGlobal("WebSocket", NativeSocket);
    const transport = createBrowserPtyTransport({
      fetch: vi.fn(
        async () =>
          new Response(
            JSON.stringify({ ticket: "pty-ticket", ttl_seconds: 30 }),
            {
              headers: { "content-type": "application/json" },
            },
          ),
      ),
    });
    const controller = new AbortController();
    const pending = transport.connect(
      { sessionId: "session-one" },
      controller.signal,
    );
    await flush();
    expect(NativeSocket.latest).toBeDefined();
    controller.abort();
    transport.close();
    await expect(pending).rejects.toMatchObject({ code: "aborted" });
    expect(close).toHaveBeenCalledTimes(1);
    vi.unstubAllGlobals();
  });

  it("normalizes foreign attachment, connect, and reconnect errors without retaining secrets", async () => {
    const secret = "ticket=secret wss://reviewed.example/?attach=secret";
    const attachmentBridge = new CurrentSessionTerminalBridge({
      createTransport: () => createFakePty().pty,
      createAttachment: () => {
        throw new Error(secret);
      },
    });
    const attachmentError = await attachmentBridge
      .attach("session-one", new AbortController().signal)
      .catch((error) => error);
    expect(attachmentError).toMatchObject({ code: "invalid-attachment" });
    expect(attachmentError).toBeInstanceOf(PtyTransportError);
    expect(
      `${String(attachmentError)} ${JSON.stringify(attachmentError)}`,
    ).not.toContain(secret);

    const connectFake = createFakePty();
    connectFake.connect.mockImplementationOnce(() => {
      throw new Error(secret);
    });
    const connectBridge = new CurrentSessionTerminalBridge({
      createTransport: () => connectFake.pty,
    });
    const connectError = await connectBridge
      .attach("session-one", new AbortController().signal)
      .catch((error) => error);
    expect(connectError).toMatchObject({ code: "connection-failed" });
    expect(connectError).toBeInstanceOf(PtyTransportError);
    expect(
      `${String(connectError)} ${JSON.stringify(connectError)}`,
    ).not.toContain(secret);

    const reconnectFake = createFakePty();
    const reconnectBridge = new CurrentSessionTerminalBridge({
      createTransport: () => reconnectFake.pty,
      createAttachment: () => ({
        attach: "attach-one",
        processIdentity: "process-one",
      }),
    });
    await reconnectBridge.attach("session-one", new AbortController().signal);
    reconnectFake.reconnect.mockImplementationOnce(() => {
      throw new Error(secret);
    });
    const reconnectError = await reconnectBridge
      .reconnect()
      .catch((error) => error);
    expect(reconnectError).toMatchObject({ code: "connection-failed" });
    expect(reconnectError).toBeInstanceOf(PtyTransportError);
    expect(
      `${String(reconnectError)} ${JSON.stringify(reconnectError)}`,
    ).not.toContain(secret);

    const reviewed = new PtyTransportError("invalid-attachment");
    const reviewedBridge = new CurrentSessionTerminalBridge({
      createTransport: () => createFakePty().pty,
      createAttachment: () => {
        throw reviewed;
      },
    });
    const normalized = await reviewedBridge
      .attach("session-one", new AbortController().signal)
      .catch((error) => error);
    expect(normalized).toMatchObject({ code: "invalid-attachment" });
    expect(normalized).not.toBe(reviewed);
  });

  it.each([
    [4401, "authentication-rejected", "authentication-required"],
    [4403, "host-or-origin-rejected", "incompatible-origin"],
  ] as const)(
    "preserves an initial PTY close classification through bridge attach (%s)",
    async (closeCode, closeClassification, failure) => {
      const fake = createFakePty();
      fake.connect.mockImplementationOnce(async (input) => {
        const state: PtyConnectionState = {
          status: "failed",
          generation: 1,
          mode: "attach",
          sessionId: input.sessionId,
          closeCode,
          closeClassification,
          outputMayBeTruncated: false,
        };
        fake.emit({ type: "state", state });
        throw new PtyTransportError("connection-failed");
      });
      const bridge = new CurrentSessionTerminalBridge({
        createTransport: () => fake.pty,
      });
      const events: CurrentSessionTerminalEvent[] = [];
      bridge.subscribe((event) => events.push(event));
      events.length = 0;

      await expect(
        bridge.attach("session-one", new AbortController().signal),
      ).rejects.toMatchObject({
        code: "connection-failed",
      });

      const failureEvent = events.find(
        (
          event,
        ): event is Extract<CurrentSessionTerminalEvent, { type: "state" }> =>
          event.type === "state" && event.state.status === "failed",
      );
      expect(failureEvent?.state).toMatchObject({
        closeCode,
        closeClassification,
        failure,
        reconnectSupported: false,
      });
      expect(
        events
          .filter((event) => event.type === "state")
          .map((event) => event.state.status),
      ).toEqual(["failed"]);
      expect(fake.detach).not.toHaveBeenCalled();
      expect(fake.close).not.toHaveBeenCalled();
      // Settlement must retain the classified native result, not overwrite it
      // with bridge cleanup's generic detached/exited projection.
      expect(bridge.state).toMatchObject({
        status: "failed",
        closeCode,
        closeClassification,
        failure,
      });
    },
  );

  it("starts a replacement attach while a cancelled adapter ignores AbortSignal", async () => {
    const fake = createFakePty();
    const firstGate = deferred<void>();
    const originalConnect = fake.connect.getMockImplementation();
    if (!originalConnect)
      throw new Error("PTY connect implementation is missing");
    fake.connect
      .mockImplementationOnce(async (input, signal) => {
        await firstGate.promise;
        return originalConnect(input, signal);
      })
      .mockImplementationOnce(async (input, signal) => {
        // B enters the adapter only after deferred A cleanup released raw ownership.
        expect(fake.pty.state.status).toBe("detached");
        return originalConnect(input, signal);
      });
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
    });
    const first = bridge.attach("session-one", new AbortController().signal);
    await Promise.resolve();
    await Promise.resolve();

    bridge.invalidateBindingForSession("session-one", bridge.lifecycleIdentity);
    const replacement = bridge.attach(
      "session-two",
      new AbortController().signal,
    );
    await Promise.resolve();
    await Promise.resolve();

    // Replacement is serialized: B must not touch a generic shared adapter
    // before ignored A has settled and received its single ownership cleanup.
    expect(fake.connect).toHaveBeenCalledTimes(1);
    expect(fake.detach).not.toHaveBeenCalled();
    firstGate.resolve(undefined);
    await expect(first).rejects.toMatchObject({ code: "aborted" });
    await replacement;
    expect(fake.connect).toHaveBeenCalledTimes(2);
    expect(fake.detach).toHaveBeenCalledTimes(1);
    expect(bridge.state.sessionId).toBe("session-two");
  });

  it("quarantines delayed A terminal publication until B has its own generation", async () => {
    const fake = createFakePty();
    const firstGate = deferred<void>();
    const secondGate = deferred<void>();
    const originalConnect = fake.connect.getMockImplementation();
    if (!originalConnect)
      throw new Error("PTY connect implementation is missing");
    fake.connect
      .mockImplementationOnce(async (input, signal) => {
        // A claims generation 1, but its terminal state publication is delayed.
        fake.emit({
          type: "state",
          state: {
            status: "starting",
            generation: 1,
            mode: "legacy",
            sessionId: input.sessionId,
            outputMayBeTruncated: false,
          },
        });
        await firstGate.promise;
        return originalConnect(input, signal);
      })
      .mockImplementationOnce(async (input, signal) => {
        await secondGate.promise;
        return originalConnect(input, signal);
      });
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
    });
    const first = bridge.attach("session-one", new AbortController().signal);
    await flush();
    bridge.invalidateBindingForSession("session-one", bridge.lifecycleIdentity);
    const replacement = bridge.attach(
      "session-one",
      new AbortController().signal,
    );
    await flush();
    expect(fake.connect).toHaveBeenCalledTimes(1);

    firstGate.resolve(undefined);
    await expect(first).rejects.toMatchObject({ code: "aborted" });
    await flush();
    expect(fake.connect).toHaveBeenCalledTimes(2);

    // The stale generation must not be attributed to pending B simply because
    // both leases use the same session id.
    fake.emit({
      type: "state",
      state: {
        status: "failed",
        generation: 1,
        mode: "legacy",
        sessionId: "session-one",
        closeCode: 4401,
        closeClassification: "authentication-rejected",
        outputMayBeTruncated: false,
      },
    });
    secondGate.resolve(undefined);
    const binding = await replacement;
    expect(isValid(binding)).toBe(true);
    expect(bridge.lifecycleIdentity.binding).toBe(binding);
    expect(bridge.lifecycleIdentity.nativeTransportGeneration).toBe(2);
  });

  it("serializes reconnect behind an ignored cancelled reconnect", async () => {
    const fake = createFakePty();
    const firstGate = deferred<void>();
    const originalReconnect = fake.reconnect.getMockImplementation();
    if (!originalReconnect)
      throw new Error("PTY reconnect implementation is missing");
    fake.reconnect
      .mockImplementationOnce(async () => {
        await firstGate.promise;
        return originalReconnect();
      })
      .mockImplementationOnce(async () => {
        expect(fake.pty.state.status).toBe("detached");
        return originalReconnect();
      });
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
      createAttachment: () => ({
        attach: "attach-one",
        processIdentity: "process-one",
      }),
    });
    await bridge.attach("session-one", new AbortController().signal);

    const first = bridge.reconnect();
    await flush();
    bridge.detach();
    const replacement = bridge.reconnect();
    await flush();
    expect(fake.reconnect).toHaveBeenCalledTimes(1);

    firstGate.resolve(undefined);
    await expect(first).rejects.toMatchObject({ code: "aborted" });
    await replacement;
    expect(fake.reconnect).toHaveBeenCalledTimes(2);
    expect(fake.detach).toHaveBeenCalledTimes(1);
  });

  it("keeps the coordinator binding through reconnect and invalidates it on failure", async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
      createAttachment: () => ({
        attach: "attach-one",
        processIdentity: "process-one",
      }),
    });

    const binding = await bridge.attach(
      "session-one",
      new AbortController().signal,
    );
    await bridge.reconnect();
    expect(bridge.lifecycleIdentity.binding).toBe(binding);
    expect(isValid(binding)).toBe(true);

    fake.reconnect.mockImplementationOnce(() => {
      throw new PtyTransportError("connection-failed");
    });
    await expect(bridge.reconnect()).rejects.toMatchObject({
      code: "connection-failed",
    });
    expect(isValid(binding)).toBe(false);
    expect(bridge.lifecycleIdentity.binding).toBeUndefined();
  });

  it("coalesces concurrent same-session attaches until the shared transport settles", async () => {
    const fake = createFakePty();
    const gate = deferred<void>();
    const originalConnect = fake.connect.getMockImplementation();
    if (!originalConnect)
      throw new Error("PTY connect implementation is missing");
    fake.connect.mockImplementation(async (input, signal) => {
      await gate.promise;
      return originalConnect(input, signal);
    });
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
    });
    const first = bridge.attach("session-one", new AbortController().signal);
    const second = bridge.attach("session-one", new AbortController().signal);
    await flush();
    expect(fake.connect).toHaveBeenCalledTimes(1);
    gate.resolve(undefined);
    await expect(second).resolves.toBe(await first);
  });

  it.each(["close", "dispose"] as const)(
    "%s escalates quarantined detach cleanup to close and gates I/O on a valid lease",
    async (action) => {
      const fake = createFakePty();
      const gate = deferred<void>();
      const originalConnect = fake.connect.getMockImplementation();
      if (!originalConnect)
        throw new Error("PTY connect implementation is missing");
      fake.connect.mockImplementation(async (input, signal) => {
        await gate.promise;
        return originalConnect(input, signal);
      });
      const bridge = new CurrentSessionTerminalBridge({
        createTransport: () => fake.pty,
      });
      const pending = bridge.attach(
        "session-one",
        new AbortController().signal,
      );
      await flush();
      bridge.invalidateBindingForSession(
        "session-one",
        bridge.lifecycleIdentity,
      );
      bridge[action]();
      expect(fake.close).toHaveBeenCalledTimes(1);
      gate.resolve(undefined);
      await expect(pending).rejects.toMatchObject({ code: "aborted" });
      const rejectedCode = action === "dispose" ? "closed" : "not-attached";
      expect(() => bridge.sendInput("x")).toThrowError(
        expect.objectContaining({ code: rejectedCode }),
      );
      expect(() => bridge.resize(80, 24)).toThrowError(
        expect.objectContaining({ code: rejectedCode }),
      );
    },
  );

  it("invalidates a lease on unsolicited closed state and reconstructs injected errors", async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
    });
    const binding = await bridge.attach(
      "session-one",
      new AbortController().signal,
    );
    fake.emit({
      type: "state",
      state: { ...fake.pty.state, status: "closed", generation: 2 },
    });
    expect(isValid(binding)).toBe(false);

    const foreign = new PtyTransportError("invalid-attachment", 3);
    Object.assign(foreign, {
      message: "ticket=secret",
      cause: new Error("secret"),
      foreign: true,
    });
    const rejecting = new CurrentSessionTerminalBridge({
      createTransport: () => createFakePty().pty,
      createAttachment: () => {
        throw foreign;
      },
    });
    const error = await rejecting
      .attach("session-two", new AbortController().signal)
      .catch((value) => value);
    expect(error).toMatchObject({ code: "invalid-attachment", generation: 3 });
    expect(error).not.toBe(foreign);
    expect(JSON.stringify(error)).not.toContain("secret");
  });

  it.each(["detach", "close"] as const)(
    "publishes truthful user %s state when the adapter keeps an attached snapshot",
    async (action) => {
      const fake = createFakePty();
      fake.detach.mockImplementation(() => undefined);
      fake.close.mockImplementation(() => undefined);
      const bridge = new CurrentSessionTerminalBridge({
        createTransport: () => fake.pty,
      });
      const events: CurrentSessionTerminalEvent[] = [];
      bridge.subscribe((event) => events.push(event));
      await bridge.attach("session-one", new AbortController().signal);
      events.length = 0;

      bridge[action]();

      const stateEvent = events.find(
        (
          event,
        ): event is Extract<CurrentSessionTerminalEvent, { type: "state" }> =>
          event.type === "state",
      );
      expect(stateEvent?.state.status).toBe(
        action === "detach" ? "exited" : "closed",
      );
      expect(bridge.state.status).toBe(
        action === "detach" ? "exited" : "closed",
      );
    },
  );
});
