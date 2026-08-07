import { describe, expect, it, vi } from 'vitest';
import {
  PtyTransportError,
  type PtyConnectionInput,
  type PtyConnectionState,
  type PtyTransport,
  type PtyTransportEvent
} from './pty-transport';
import {
  CurrentSessionTerminalBridge,
  type CurrentSessionTerminalEvent
} from './current-session-terminal';

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
      outputMayBeTruncated: false
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
});
