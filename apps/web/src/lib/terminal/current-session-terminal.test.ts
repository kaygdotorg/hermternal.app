import { describe, expect, it, vi } from 'vitest';
import {
  PtyTransportError,
  type PtyConnectionInput,
  type PtyConnectionState,
  type PtyTransport,
  type PtyTransportEvent,
  type PtyWebSocket
} from './pty-transport';
import {
  CurrentSessionTerminalBridge,
  createBrowserPtyTransport,
  type CurrentSessionTerminalEvent,
  type BrowserPtyWebSocketFactory
} from './current-session-terminal';

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

function createFakePty() {
  const listeners = new Set<(event: PtyTransportEvent) => void>();
  const initial: PtyConnectionState = {
    status: 'closed',
    generation: 0,
    mode: 'legacy',
    outputMayBeTruncated: false
  };
  let state = initial;
  const connect = vi.fn(async (input: PtyConnectionInput, _signal?: AbortSignal) => {
    state = {
      status: 'attached',
      generation: state.generation + 1,
      mode: input.attach ? 'attach' : 'legacy',
      sessionId: input.sessionId,
      ...(input.attach && input.processIdentity ? { processIdentity: input.processIdentity } : {}),
      outputMayBeTruncated: false,
      reconnectSupported: Boolean(input.attach)
    };
    for (const listener of listeners) listener({ type: 'state', state });
  });
  const detach = vi.fn(() => {
    state = {
      ...state,
      status: 'detached'
    };
    for (const listener of listeners) listener({ type: 'state', state });
  });
  const close = vi.fn(() => {
    state = {
      ...state,
      status: 'exited'
    };
    for (const listener of listeners) listener({ type: 'state', state });
  });
  const reconnect = vi.fn(async () => {
    if (state.mode !== 'attach') {
      throw new PtyTransportError('legacy-reattach-prohibited', state.generation);
    }
    state = {
      ...state,
      status: 'attached',
      generation: state.generation + 1,
      reconnectSupported: true
    };
    for (const listener of listeners) listener({ type: 'state', state });
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
    }
  };
  return {
    pty,
    connect,
    reconnect,
    detach,
    close,
    emit(event: PtyTransportEvent) {
      if (event.type === 'state') state = event.state;
      for (const listener of listeners) listener(event);
    }
  };
}

describe('CurrentSessionTerminalBridge', () => {
  it('owns one PTY, reuses a same-session binding, and invalidates on replacement', async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({ createTransport: () => fake.pty });

    const first = await bridge.attach('session-one', new AbortController().signal);
    const second = await bridge.attach('session-one', new AbortController().signal);
    expect(second).toBe(first);
    expect(fake.connect).toHaveBeenCalledTimes(1);

    first.invalidate();
    expect(fake.detach).toHaveBeenCalledTimes(1);
    expect(first.isValid?.()).toBe(false);

    await bridge.attach('session-two', new AbortController().signal);
    expect(fake.connect).toHaveBeenCalledTimes(2);
  });

  it('forwards the exact raw Uint8Array without decoding or retaining it', async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({ createTransport: () => fake.pty });
    const events: CurrentSessionTerminalEvent[] = [];
    bridge.subscribe((event) => events.push(event));
    await bridge.attach('session-one', new AbortController().signal);

    const bytes = new Uint8Array([0xff, 0x00, 0x80]);
    fake.emit({
      type: 'bytes',
      generation: 1,
      bytes,
      outputMayBeTruncated: false
    });

    const byteEvent = events.find((event): event is Extract<CurrentSessionTerminalEvent, { type: 'bytes' }> => event.type === 'bytes');
    expect(byteEvent?.bytes).toBe(bytes);
    expect(JSON.stringify(bridge.state)).not.toContain('ff');
    expect(JSON.stringify(bridge.state)).not.toContain('128');
  });

  it('projects 4401 authentication and 4403 origin boundaries without sharing raw errors', () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({ createTransport: () => fake.pty });
    const states: string[] = [];
    bridge.subscribe((event) => {
      if (event.type === 'state') states.push(event.state.failure ?? 'none');
    });

    fake.emit({
      type: 'state',
      state: {
        status: 'failed',
        generation: 1,
        mode: 'legacy',
        sessionId: 'session-one',
        closeCode: 4401,
        closeClassification: 'authentication-rejected',
        outputMayBeTruncated: false
      }
    });
    fake.emit({
      type: 'state',
      state: {
        status: 'failed',
        generation: 2,
        mode: 'legacy',
        sessionId: 'session-one',
        closeCode: 4403,
        closeClassification: 'host-or-origin-rejected',
        outputMayBeTruncated: false
      }
    });

    expect(states).toEqual(['none', 'authentication-required', 'incompatible-origin']);
    expect(bridge.state.closeCode).toBe(4403);
    expect(bridge.state.failure).toBe('incompatible-origin');
  });

  it('rejects stale-generation bytes and invalidates a binding after unsolicited PTY failure', async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({ createTransport: () => fake.pty });
    const events: CurrentSessionTerminalEvent[] = [];
    bridge.subscribe((event) => events.push(event));
    const binding = await bridge.attach('session-one', new AbortController().signal);

    const staleBytes = new Uint8Array([1]);
    fake.emit({ type: 'bytes', generation: 0, bytes: staleBytes, outputMayBeTruncated: false });
    expect(events.some((event) => event.type === 'bytes')).toBe(false);

    fake.emit({
      type: 'state',
      state: {
        status: 'detached',
        generation: 2,
        mode: 'legacy',
        sessionId: 'session-one',
        outputMayBeTruncated: false
      }
    });
    expect(binding.isValid?.()).toBe(false);

    await bridge.attach('session-one', new AbortController().signal);
    expect(fake.connect).toHaveBeenCalledTimes(2);
  });

  it('invalidates only the matching stale binding and allows a later attach to recover', async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({ createTransport: () => fake.pty });
    const events: CurrentSessionTerminalEvent[] = [];
    bridge.subscribe((event) => events.push(event));

    const staleBinding = await bridge.attach('session-one', new AbortController().signal);
    events.length = 0;
    bridge.invalidateBindingForSession('session-one');

    expect(staleBinding.isValid?.()).toBe(false);
    expect(fake.detach).toHaveBeenCalledTimes(1);
    expect(events).toEqual([]);
    expect(bridge.state.status).toBe('detached');
    expect(bridge.state.sessionId).toBeUndefined();

    const freshBinding = await bridge.attach('session-one', new AbortController().signal);
    const bytes = new Uint8Array([0xff, 0x00, 0x80]);
    fake.emit({ type: 'bytes', generation: 2, bytes, outputMayBeTruncated: false });

    expect(freshBinding.isValid?.()).toBe(true);
    expect(events.find((event) => event.type === 'bytes')).toMatchObject({ bytes });

    const otherFake = createFakePty();
    const otherBridge = new CurrentSessionTerminalBridge({ createTransport: () => otherFake.pty });
    const otherBinding = await otherBridge.attach('session-two', new AbortController().signal);
    otherBridge.invalidateBindingForSession('session-one');
    expect(otherBinding.isValid?.()).toBe(true);
  });

  it('finishes cleanup after an adapter ignores binding invalidation until late connect completion', async () => {
    const fake = createFakePty();
    const connectGate = deferred<void>();
    const originalConnect = fake.connect.getMockImplementation();
    if (!originalConnect) throw new Error('PTY connect implementation is missing');
    fake.connect.mockImplementation(async (input, signal) => {
      await connectGate.promise;
      return originalConnect(input, signal);
    });
    const bridge = new CurrentSessionTerminalBridge({ createTransport: () => fake.pty });
    const events: CurrentSessionTerminalEvent[] = [];
    bridge.subscribe((event) => events.push(event));

    const pending = bridge.attach('session-one', new AbortController().signal);
    await Promise.resolve();
    await Promise.resolve();
    bridge.invalidateBindingForSession('session-one');
    connectGate.resolve(undefined);

    await expect(pending).rejects.toMatchObject({ code: 'aborted' });
    expect(fake.detach).toHaveBeenCalledTimes(2);
    expect(fake.pty.state.status).toBe('detached');
    expect(bridge.state.sessionId).toBeUndefined();
    expect(events.filter((event) => event.type === 'state' && event.state.status === 'attached')).toEqual([]);

    bridge.invalidateBindingForSession('session-one');
    expect(fake.detach).toHaveBeenCalledTimes(2);
  });

  it('stops later listeners after the first stale-state listener invalidates the binding', async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({ createTransport: () => fake.pty });
    const firstListener = vi.fn((event: CurrentSessionTerminalEvent) => {
      if (event.type === 'state' && event.state.status === 'attached') {
        bridge.invalidateBindingForSession('session-one');
      }
    });
    const secondListener = vi.fn();
    bridge.subscribe(firstListener);
    bridge.subscribe(secondListener);
    firstListener.mockClear();
    secondListener.mockClear();

    await expect(bridge.attach('session-one', new AbortController().signal)).rejects.toMatchObject({
      code: 'aborted'
    });

    expect(firstListener).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'state', state: expect.objectContaining({ status: 'attached' }) })
    );
    expect(secondListener).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: 'state', state: expect.objectContaining({ status: 'attached' }) })
    );
    expect(fake.detach).toHaveBeenCalledTimes(2);
    expect(fake.pty.state.status).toBe('detached');
  });

  it('suppresses stale bytes, notices, and immediate state replay after invalidation', async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({ createTransport: () => fake.pty });
    const events: CurrentSessionTerminalEvent[] = [];
    await bridge.attach('session-one', new AbortController().signal);
    bridge.subscribe((event) => events.push(event));
    events.length = 0;
    bridge.invalidateBindingForSession('session-one');

    fake.emit({
      type: 'bytes',
      generation: 1,
      bytes: new Uint8Array([1]),
      outputMayBeTruncated: false
    });
    fake.emit({ type: 'notice', generation: 1, notice: 'output-may-be-truncated', replayCapacityBytes: 1 });
    const laterEvents: CurrentSessionTerminalEvent[] = [];
    bridge.subscribe((event) => laterEvents.push(event));

    expect(events).toEqual([]);
    expect(laterEvents).toEqual([]);
  });

  it('checks cancellation before same-session binding reuse and isolates initial observer errors', async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({ createTransport: () => fake.pty });
    const binding = await bridge.attach('session-one', new AbortController().signal);
    const controller = new AbortController();
    controller.abort();

    await expect(bridge.attach('session-one', controller.signal)).rejects.toMatchObject({ code: 'aborted' });
    expect(fake.connect).toHaveBeenCalledTimes(1);
    expect(binding.isValid?.()).toBe(true);

    expect(() => bridge.subscribe(() => { throw new Error('observer failure'); })).not.toThrow();
  });

  it('waits for the lazy renderer gate before the first PTY attach', async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({ createTransport: () => fake.pty });
    bridge.setRendererReady(false);
    const pending = bridge.attach('session-one', new AbortController().signal);

    await Promise.resolve();
    expect(fake.connect).not.toHaveBeenCalled();
    bridge.setRendererReady(true);
    await pending;
    expect(fake.connect).toHaveBeenCalledTimes(1);
  });

  it('does not release a pending attach when the renderer sink is torn down', async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({ createTransport: () => fake.pty });
    bridge.setRendererReady(false);
    const pending = bridge.attach('session-one', new AbortController().signal);

    await Promise.resolve();
    bridge.setRendererReady(false);
    await Promise.resolve();
    expect(fake.connect).not.toHaveBeenCalled();

    bridge.dispose();
    await expect(pending).rejects.toMatchObject({ code: 'closed' });
    expect(fake.connect).not.toHaveBeenCalled();
  });

  it('defers the first PTY bytes across an independent renderer remount', async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({ createTransport: () => fake.pty });
    const events: CurrentSessionTerminalEvent[] = [];
    bridge.subscribe((event) => events.push(event));
    bridge.setRendererReady(false);
    const pending = bridge.attach('session-one', new AbortController().signal);

    await Promise.resolve();
    bridge.setRendererReady(false);
    await Promise.resolve();
    expect(fake.connect).not.toHaveBeenCalled();
    expect(events.some((event) => event.type === 'bytes')).toBe(false);

    // A later renderer mount is the only operation allowed to reopen the gate.
    bridge.setRendererReady(true);
    await pending;
    expect(fake.connect).toHaveBeenCalledTimes(1);

    const bytes = new Uint8Array([0xff, 0x00, 0x80]);
    fake.emit({ type: 'bytes', generation: 1, bytes, outputMayBeTruncated: false });
    const byteEvent = events.find(
      (event): event is Extract<CurrentSessionTerminalEvent, { type: 'bytes' }> => event.type === 'bytes'
    );
    expect(byteEvent?.bytes).toBe(bytes);
  });

  it('rejects reconnect for the normal legacy binding instead of pretending it can reattach', async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({ createTransport: () => fake.pty });

    await bridge.attach('session-one', new AbortController().signal);

    expect(bridge.state.reconnectSupported).toBe(false);
    await expect(bridge.reconnect()).rejects.toMatchObject({ code: 'legacy-reattach-prohibited' });
    expect(fake.pty.reconnect).not.toHaveBeenCalled();
  });

  it('hides deterministic attach-mode reconnect blocks from the public retry state', async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({ createTransport: () => fake.pty });
    fake.emit({
      type: 'state',
      state: {
        status: 'failed',
        generation: 1,
        mode: 'attach',
        sessionId: 'session-one',
        closeCode: 4403,
        closeClassification: 'host-or-origin-rejected',
        outputMayBeTruncated: false,
        reconnectSupported: false
      }
    });

    expect(bridge.state.reconnectSupported).toBe(false);
    await expect(bridge.reconnect()).rejects.toMatchObject({ code: 'legacy-reattach-prohibited' });
    expect(fake.reconnect).not.toHaveBeenCalled();
  });

  it('keeps reviewed attach identity values inside the transport and exposes attach-mode reconnect', async () => {
    const fake = createFakePty();
    const createAttachment = vi.fn(async (sessionId: string) => ({
      attach: `attach-${sessionId}`,
      processIdentity: `process-${sessionId}`
    }));
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
      createAttachment
    });

    await bridge.attach('session-one', new AbortController().signal);

    expect(createAttachment).toHaveBeenCalledWith('session-one', expect.any(AbortSignal));
    expect(fake.connect).toHaveBeenCalledWith(
      { sessionId: 'session-one', attach: 'attach-session-one', processIdentity: 'process-session-one' },
      expect.any(AbortSignal)
    );
    expect(bridge.state).toMatchObject({ status: 'attached', reconnectSupported: true });

    await bridge.reconnect();
    expect(fake.pty.reconnect).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(bridge.state)).not.toContain('attach-session-one');
    expect(JSON.stringify(bridge.state)).not.toContain('process-session-one');
  });

  it('returns a fresh binding for coordinator-owned attach-mode reconnect', async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
      createAttachment: () => ({ attach: 'attach-one', processIdentity: 'process-one' })
    });

    const first = await bridge.attach('session-one', new AbortController().signal);
    first.invalidate();
    const second = await bridge.reconnectBinding('session-one', new AbortController().signal);

    expect(second).not.toBe(first);
    expect(second.isValid?.()).toBe(true);
    expect(fake.reconnect).toHaveBeenCalledTimes(1);
    second.invalidate();
    expect(fake.detach).toHaveBeenCalledTimes(2);
  });

  it('invokes lease adoption before a synchronous recovered attached event', async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
      createAttachment: () => ({ attach: 'attach-one', processIdentity: 'process-one' })
    });
    const first = await bridge.attach('session-one', new AbortController().signal);
    first.invalidate();
    const order: string[] = [];
    fake.reconnect.mockImplementationOnce(async () => {
      order.push('transport-reconnect');
      fake.emit({
        type: 'state',
        state: {
          status: 'attached',
          generation: 2,
          mode: 'attach',
          sessionId: 'session-one',
          outputMayBeTruncated: true,
          reconnectSupported: true
        }
      });
    });

    const second = await bridge.reconnectBinding(
      'session-one',
      new AbortController().signal,
      () => order.push('lease-adopted')
    );

    expect(order).toEqual(['lease-adopted', 'transport-reconnect']);
    expect(second.isValid?.()).toBe(true);
  });

  it('cancels renderer-gated attach and reconnect on explicit detach', async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
      createAttachment: () => ({ attach: 'attach-one', processIdentity: 'process-one' })
    });
    bridge.setRendererReady(false);
    const pendingAttach = bridge.attach('session-one', new AbortController().signal);
    await Promise.resolve();
    bridge.detach();
    await expect(pendingAttach).rejects.toMatchObject({ code: 'aborted' });
    bridge.setRendererReady(true);
    expect(fake.connect).not.toHaveBeenCalled();

    await bridge.attach('session-one', new AbortController().signal);
    bridge.setRendererReady(false);
    const pendingReconnect = bridge.reconnect();
    await Promise.resolve();
    bridge.detach();
    await expect(pendingReconnect).rejects.toMatchObject({ code: 'aborted' });
    bridge.setRendererReady(true);
    expect(fake.reconnect).not.toHaveBeenCalled();
  });

  it('allows a legitimate attach-mode reconnect to clear a stale marker', async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
      createAttachment: () => ({ attach: 'attach-one', processIdentity: 'process-one' })
    });
    const events: CurrentSessionTerminalEvent[] = [];
    bridge.subscribe((event) => events.push(event));
    await bridge.attach('session-one', new AbortController().signal);
    bridge.invalidateBindingForSession('session-one');
    events.length = 0;
    fake.reconnect.mockImplementation(async () => {
      fake.emit({
        type: 'state',
        state: {
          status: 'reattaching',
          generation: 2,
          mode: 'attach',
          sessionId: 'session-one',
          outputMayBeTruncated: false
        }
      });
      fake.emit({
        type: 'state',
        state: {
          status: 'attached',
          generation: 2,
          mode: 'attach',
          sessionId: 'session-one',
          outputMayBeTruncated: false
        }
      });
    });

    await bridge.reconnect();
    const bytes = new Uint8Array([7]);
    fake.emit({ type: 'bytes', generation: 2, bytes, outputMayBeTruncated: true });

    expect(events.map((event) => event.type)).toEqual(['state', 'state', 'bytes']);
    expect(events.at(-1)).toMatchObject({ type: 'bytes', bytes });
  });

  it('waits for renderer readiness before attach-mode reconnect', async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
      createAttachment: () => ({ attach: 'attach-one', processIdentity: 'process-one' })
    });

    await bridge.attach('session-one', new AbortController().signal);
    bridge.setRendererReady(false);
    const pending = bridge.reconnect();

    await Promise.resolve();
    expect(fake.pty.reconnect).not.toHaveBeenCalled();
    bridge.setRendererReady(true);
    await pending;
    expect(fake.pty.reconnect).toHaveBeenCalledTimes(1);
  });

  it('suppresses synchronous transport events after bridge disposal', async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({ createTransport: () => fake.pty });
    const events: CurrentSessionTerminalEvent[] = [];
    bridge.subscribe((event) => events.push(event));
    await bridge.attach('session-one', new AbortController().signal);
    events.length = 0;

    bridge.dispose();

    expect(events).toEqual([]);
    expect(() => bridge.sendInput('after dispose')).toThrowError(
      expect.objectContaining({ code: 'closed' })
    );
    expect(() => bridge.resize(80, 24)).toThrowError(expect.objectContaining({ code: 'closed' }));
    expect(fake.close).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['http://localhost', 'ws:'],
    ['https://reviewed.example', 'wss:']
  ] as const)('maps the browser origin %s to a %s PTY upgrade', async (origin, protocol) => {
    vi.stubGlobal('location', { origin });
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
      close: vi.fn()
    };
    const urls: string[] = [];
    const signals: AbortSignal[] = [];
    const createSocket: BrowserPtyWebSocketFactory = vi.fn((url, signal) => {
      urls.push(url);
      signals.push(signal);
      return socket;
    });
    const transport = createBrowserPtyTransport({
      fetch: vi.fn(async () =>
        new Response(JSON.stringify({ ticket: 'pty-ticket', ttl_seconds: 30 }), {
          headers: { 'content-type': 'application/json' }
        })
      ),
      createSocket
    });

    const pending = transport.connect({ sessionId: 'session-one' });
    await flush();
    expect(createSocket).toHaveBeenCalledTimes(1);
    expect(signals[0]).toEqual(expect.any(AbortSignal));
    const upgrade = new URL(urls[0] ?? 'http://invalid');
    expect(upgrade.protocol).toBe(protocol);
    expect(upgrade.pathname).toBe('/api/pty');

    readyState = 1;
    socket.onopen?.();
    await pending;
    expect(transport.state.status).toBe('attached');
    vi.unstubAllGlobals();
  });

  it.each([
    ['file:///tmp/hermternal', 'file:'],
    ['data:text/plain,opaque', 'data:'],
    ['custom://reviewed.example', 'custom:'],
    ['ws://reviewed.example', 'ws:'],
    ['null', 'opaque'],
    ['', 'missing']
  ] as const)('rejects %s before constructing a PTY socket (%s)', async (origin, protocol) => {
    expect(protocol).toBeTruthy();
    vi.stubGlobal('location', origin === '' ? undefined : { origin });
    const createSocket = vi.fn((): PtyWebSocket => ({
      onopen: null,
      onmessage: null,
      onerror: null,
      onclose: null,
      readyState: 0,
      send: vi.fn(),
      close: vi.fn()
    }));
    const transport = createBrowserPtyTransport({
      fetch: vi.fn(async () =>
        new Response(JSON.stringify({ ticket: 'pty-ticket', ttl_seconds: 30 }), {
          headers: { 'content-type': 'application/json' }
        })
      ),
      createSocket
    });

    try {
      await expect(transport.connect({ sessionId: 'session-one' })).rejects.toMatchObject({
        code: 'invalid-options'
      });
      expect(createSocket).not.toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('rejects an unavailable origin before invoking the native WebSocket constructor', async () => {
    class StubWebSocket {
      static readonly instances: StubWebSocket[] = [];
      binaryType = '';
      readyState = 0;
      onopen: ((event?: unknown) => void) | null = null;
      onmessage: ((event: MessageEvent) => void) | null = null;
      onerror: ((event?: unknown) => void) | null = null;
      onclose: ((event?: { readonly code?: number }) => void) | null = null;
      readonly send = vi.fn();
      readonly close = vi.fn((..._args: unknown[]) => {
        this.readyState = 3;
      });

      constructor(readonly url: string) {
        StubWebSocket.instances.push(this);
      }
    }
    vi.stubGlobal('location', undefined);
    vi.stubGlobal('WebSocket', StubWebSocket);
    const transport = createBrowserPtyTransport({
      fetch: vi.fn(async () =>
        new Response(JSON.stringify({ ticket: 'pty-ticket', ttl_seconds: 30 }), {
          headers: { 'content-type': 'application/json' }
        })
      )
    });

    try {
      await expect(transport.connect({ sessionId: 'session-one' })).rejects.toMatchObject({
        code: 'invalid-options'
      });
      expect(StubWebSocket.instances).toHaveLength(0);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it.each([
    ['abort, close, native onclose', ['abort', 'close', 'onclose']],
    ['close, abort, native onclose', ['close', 'abort', 'onclose']],
    ['abort, native onclose, close', ['abort', 'onclose', 'close']]
  ] as const)('closes the default native PTY socket exactly once (%s)', async (_label, actions) => {
    class StubWebSocket {
      static readonly instances: StubWebSocket[] = [];
      binaryType = '';
      readyState = 0;
      onopen: ((event?: unknown) => void) | null = null;
      onmessage: ((event: MessageEvent) => void) | null = null;
      onerror: ((event?: unknown) => void) | null = null;
      onclose: ((event?: { readonly code?: number }) => void) | null = null;
      readonly send = vi.fn();
      readonly close = vi.fn((..._args: unknown[]) => {
        this.readyState = 3;
      });

      constructor(readonly url: string) {
        StubWebSocket.instances.push(this);
      }
    }
    vi.stubGlobal('location', { origin: 'http://localhost' });
    vi.stubGlobal('WebSocket', StubWebSocket);
    const transport = createBrowserPtyTransport({
      fetch: vi.fn(async () =>
        new Response(JSON.stringify({ ticket: 'pty-ticket', ttl_seconds: 30 }), {
          headers: { 'content-type': 'application/json' }
        })
      )
    });
    const controller = new AbortController();
    const pending = transport.connect({ sessionId: 'session-one' }, controller.signal);
    await flush();
    const native = StubWebSocket.instances[0];
    if (!native) throw new Error('native WebSocket was not constructed');

    try {
      for (const action of actions) {
        if (action === 'abort') controller.abort();
        if (action === 'close') transport.close();
        if (action === 'onclose') native.onclose?.({ code: 1000 });
      }
      await expect(pending).rejects.toBeInstanceOf(PtyTransportError);
      expect(native.close).toHaveBeenCalledTimes(1);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it.each([
    [4401, 'authentication-rejected', 'authentication-required'],
    [4403, 'host-or-origin-rejected', 'incompatible-origin']
  ] as const)('preserves an initial PTY close classification through bridge attach (%s)', async (closeCode, closeClassification, failure) => {
    const fake = createFakePty();
    fake.connect.mockImplementationOnce(async (input) => {
      const state: PtyConnectionState = {
        status: 'failed',
        generation: 1,
        mode: 'attach',
        sessionId: input.sessionId,
        closeCode,
        closeClassification,
        outputMayBeTruncated: false,
        reconnectSupported: false
      };
      fake.emit({ type: 'state', state });
      throw new PtyTransportError('connection-failed');
    });
    const bridge = new CurrentSessionTerminalBridge({ createTransport: () => fake.pty });
    const events: CurrentSessionTerminalEvent[] = [];
    bridge.subscribe((event) => events.push(event));
    events.length = 0;

    await expect(bridge.attach('session-one', new AbortController().signal)).rejects.toMatchObject({
      code: 'connection-failed'
    });

    const failureEvent = events.find(
      (event): event is Extract<CurrentSessionTerminalEvent, { type: 'state' }> =>
        event.type === 'state' && event.state.status === 'failed'
    );
    expect(failureEvent?.state).toMatchObject({
      closeCode,
      closeClassification,
      failure,
      reconnectSupported: false
    });
    expect(events.filter((event) => event.type === 'state').map((event) => event.state.status)).toEqual([
      'failed'
    ]);
  });

  it('starts a replacement attach while a cancelled adapter ignores AbortSignal', async () => {
    const fake = createFakePty();
    const firstGate = deferred<void>();
    const originalConnect = fake.connect.getMockImplementation();
    if (!originalConnect) throw new Error('PTY connect implementation is missing');
    fake.connect.mockImplementationOnce(async (input, signal) => {
      await firstGate.promise;
      return originalConnect(input, signal);
    });
    const bridge = new CurrentSessionTerminalBridge({ createTransport: () => fake.pty });
    const first = bridge.attach('session-one', new AbortController().signal);
    await Promise.resolve();
    await Promise.resolve();

    bridge.invalidateBindingForSession('session-one');
    const replacement = bridge.attach('session-two', new AbortController().signal);
    await Promise.resolve();
    await Promise.resolve();

    expect(fake.connect).toHaveBeenCalledTimes(2);
    await replacement;
    firstGate.resolve(undefined);
    await expect(first).rejects.toMatchObject({ code: 'aborted' });
    expect(bridge.state.sessionId).toBe('session-two');
  });

  it('cleans a late invalidated adapter owner by generation without detaching its replacement', async () => {
    const listeners = new Set<(event: PtyTransportEvent) => void>();
    const firstGate = deferred<void>();
    const rawOwners = new Map<number, string>();
    let nextGeneration = 0;
    let visibleOwner: { readonly generation: number; readonly sessionId: string } | undefined;
    let state: PtyConnectionState = {
      status: 'closed',
      generation: 0,
      mode: 'legacy',
      outputMayBeTruncated: false
    };
    const emitState = (next: PtyConnectionState): void => {
      state = next;
      for (const listener of listeners) listener({ type: 'state', state: next });
    };
    const connect = vi.fn(async (input: PtyConnectionInput) => {
      const generation = ++nextGeneration;
      if (input.sessionId === 'session-one') await firstGate.promise;
      rawOwners.set(generation, input.sessionId);
      visibleOwner = { generation, sessionId: input.sessionId };
      emitState({
        status: 'attached',
        generation,
        mode: 'legacy',
        sessionId: input.sessionId,
        outputMayBeTruncated: false
      });
    });
    const detach = vi.fn((expectedGeneration?: number) => {
      const generation = expectedGeneration ?? visibleOwner?.generation;
      if (generation === undefined) return;
      rawOwners.delete(generation);
      if (visibleOwner?.generation !== generation) return;
      const replacement = [...rawOwners.entries()].sort(([left], [right]) => right - left)[0];
      if (!replacement) {
        visibleOwner = undefined;
        emitState({
          ...state,
          status: 'detached',
          sessionId: undefined,
          generation
        });
        return;
      }
      visibleOwner = { generation: replacement[0], sessionId: replacement[1] };
      emitState({
        ...state,
        status: 'attached',
        generation: replacement[0],
        sessionId: replacement[1]
      });
    });
    const close = vi.fn((expectedGeneration?: number) => detach(expectedGeneration));
    const pty: PtyTransport = {
      get state() {
        return state;
      },
      connect,
      reconnect: vi.fn(async () => undefined),
      sendInput: vi.fn(),
      resize: vi.fn(),
      detach,
      close,
      subscribe(listener) {
        listeners.add(listener);
        return () => listeners.delete(listener);
      }
    };
    const bridge = new CurrentSessionTerminalBridge({ createTransport: () => pty });

    const first = bridge.attach('session-one', new AbortController().signal);
    await flush();
    bridge.invalidateBindingForSession('session-one');
    const replacement = bridge.attach('session-two', new AbortController().signal);
    await replacement;

    firstGate.resolve(undefined);
    await expect(first).rejects.toMatchObject({ code: 'aborted' });

    expect(rawOwners).toEqual(new Map([[2, 'session-two']]));
    expect(detach).toHaveBeenCalledWith(1);
    expect(bridge.state).toMatchObject({ status: 'attached', sessionId: 'session-two', generation: 2 });
  });

  it('keeps direct reconnect binding ownership for later detach and close', async () => {
    const fake = createFakePty();
    const bridge = new CurrentSessionTerminalBridge({
      createTransport: () => fake.pty,
      createAttachment: () => ({ attach: 'attach-one', processIdentity: 'process-one' })
    });

    const first = await bridge.attach('session-one', new AbortController().signal);
    first.invalidate();
    await bridge.reconnect();
    bridge.detach();
    expect(fake.detach).toHaveBeenCalledTimes(2);

    await bridge.reconnect();
    bridge.close();
    expect(fake.close).toHaveBeenCalledTimes(1);
    expect(bridge.state.status).toBe('closed');
    expect(bridge.state.reconnectSupported).toBe(false);
  });

  it.each(['detach', 'close'] as const)('publishes truthful user %s state when the adapter keeps an attached snapshot', async (action) => {
    const fake = createFakePty();
    fake.detach.mockImplementation(() => undefined);
    fake.close.mockImplementation(() => undefined);
    const bridge = new CurrentSessionTerminalBridge({ createTransport: () => fake.pty });
    const events: CurrentSessionTerminalEvent[] = [];
    bridge.subscribe((event) => events.push(event));
    await bridge.attach('session-one', new AbortController().signal);
    events.length = 0;

    bridge[action]();

    const stateEvent = events.find(
      (event): event is Extract<CurrentSessionTerminalEvent, { type: 'state' }> => event.type === 'state'
    );
    expect(stateEvent?.state.status).toBe(action === 'detach' ? 'exited' : 'closed');
    expect(bridge.state.status).toBe(action === 'detach' ? 'exited' : 'closed');
  });
});
