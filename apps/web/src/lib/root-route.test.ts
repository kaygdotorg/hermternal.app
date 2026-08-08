import { describe, expect, it, vi } from 'vitest';
import type { LiveRestFetch } from '$lib/transport';
import { createLiveRootContext, resolveRootRoute } from './root-route';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' }
  });
}

const IDENTITY = {
  user_id: 'user-1',
  email: '',
  display_name: 'Test person',
  org_id: '',
  provider: 'basic',
  expires_at: 4_000_000_000
};

function createSocketHarness() {
  const socket = {
    onopen: null as (() => void) | null,
    onmessage: null as ((event: { readonly data: unknown }) => void) | null,
    onerror: null as (() => void) | null,
    onclose: null as ((event?: { readonly code?: number }) => void) | null,
    readyState: 1,
    send: vi.fn((_data: unknown) => undefined),
    close: vi.fn((code?: number) => socket.onclose?.({ code }))
  };
  return {
    socket,
    open: () => socket.onopen?.(),
    closeFromServer: (code: number) => socket.onclose?.({ code })
  };
}

async function flush(): Promise<void> {
  for (let index = 0; index < 32; index += 1) {
    await Promise.resolve();
  }
}

describe('root route composition', () => {
  it('keeps only closed valid scenario values in the deterministic fixture lane', () => {
    expect(resolveRootRoute('?scenario=success')).toEqual({ mode: 'fixture', scenario: 'success', delayMs: 0 });
    expect(resolveRootRoute('?scenario=empty&delayMs=short')).toEqual({
      mode: 'fixture',
      scenario: 'empty',
      delayMs: 250
    });
    expect(resolveRootRoute('?scenario=failure&delayMs=other')).toEqual({
      mode: 'fixture',
      scenario: 'failure',
      delayMs: 0
    });
    expect(resolveRootRoute('')).toEqual({ mode: 'live' });
    expect(resolveRootRoute('?scenario=unknown')).toEqual({ mode: 'live' });
    expect(resolveRootRoute('?delayMs=short')).toEqual({ mode: 'live' });
  });

  it('uses identity verification before provider discovery on the normal live path', async () => {
    const requests: string[] = [];
    const fetch: LiveRestFetch = vi.fn(async (input, init) => {
      const path = String(input);
      requests.push(`${init?.method ?? 'GET'} ${path}`);
      if (path === '/api/auth/me') return jsonResponse({ detail: 'not authenticated' }, 401);
      if (path === '/api/auth/providers') {
        return jsonResponse({
          providers: [{ name: 'basic', display_name: 'Disposable Basic', supports_password: true }]
        });
      }
      throw new Error('unexpected request');
    });
    const context = createLiveRootContext({ fetch });

    await context.auth.initialize();

    expect(requests).toEqual(['GET /api/auth/me', 'GET /api/auth/providers']);
    expect(context.auth.current).toMatchObject({
      status: 'signed_out',
      providers: [{ id: 'basic', name: 'Disposable Basic', kind: 'password' }]
    });
  });

  it('invalidates local workspace state before the logout request progresses', async () => {
    const events: string[] = [];
    let identityActive = true;
    const fetch: LiveRestFetch = vi.fn(async (input, init) => {
      const path = String(input);
      if (path === '/api/auth/me') {
        events.push(identityActive ? 'identity-active' : 'identity-cleared');
        return identityActive ? jsonResponse(IDENTITY) : jsonResponse({ detail: 'not authenticated' }, 401);
      }
      if (path === '/auth/logout' && init?.method === 'POST') {
        events.push('logout-request');
        identityActive = false;
        return new Response(null, { status: 302, headers: { location: '/login' } });
      }
      throw new Error('unexpected request');
    });
    const context = createLiveRootContext({ fetch });
    const invalidateImplementation = context.workspace.invalidate.bind(context.workspace);
    const invalidate = vi.spyOn(context.workspace, 'invalidate').mockImplementation(() => {
      events.push('local-invalidated');
      invalidateImplementation();
    });
    await context.auth.initialize();

    await context.auth.logout();

    expect(invalidate).toHaveBeenCalledTimes(1);
    expect(events).toEqual(['identity-active', 'local-invalidated', 'logout-request', 'identity-cleared']);
    expect(context.auth.current.status).toBe('signed_out');
    expect(context.workspace.current).toMatchObject({ state: 'loading', sessions: [], timeline: [] });
    expect(events.filter((event) => event === 'logout-request')).toHaveLength(1);
  });

  it('keeps live auth expiry invalidation inside the composed root boundary', async () => {
    const fetch: LiveRestFetch = vi.fn(async (input) => {
      if (String(input) === '/api/auth/me') return jsonResponse(IDENTITY);
      throw new Error('unexpected request');
    });
    const context = createLiveRootContext({ fetch });
    const invalidate = vi.spyOn(context.workspace, 'invalidate');

    await context.auth.initialize();
    context.auth.expire();

    expect(invalidate).toHaveBeenCalledTimes(1);
    expect(context.auth.current.status).toBe('expired');
    expect(context.workspace.current).toMatchObject({ state: 'loading', sessions: [], timeline: [] });
  });

  it('routes the shared root socket seam into the normal PTY upgrade', async () => {
    const harness = createSocketHarness();
    const urls: string[] = [];
    const signals: Array<AbortSignal | undefined> = [];
    const fetch: LiveRestFetch = vi.fn(async (input) => {
      if (String(input) === '/api/auth/ws-ticket') return jsonResponse({ ticket: 'pty-ticket', ttl_seconds: 30 });
      throw new Error('unexpected request');
    });
    const createSocket = vi.fn((url: string, signal?: AbortSignal) => {
      urls.push(url);
      signals.push(signal);
      return harness.socket;
    });
    const context = createLiveRootContext({ fetch, createSocket });
    const terminal = context.workspace.terminal;
    if (!terminal) throw new Error('terminal bridge was not composed');

    const controller = new AbortController();
    const pending = terminal.attach('session-1', controller.signal);
    await flush();

    expect(createSocket).toHaveBeenCalledTimes(1);
    // The PTY owns an internal abort controller so transport cancellation can
    // close the socket even when the attach caller has no signal.
    expect(signals[0]).toEqual(expect.any(AbortSignal));
    expect(signals[0]).not.toBe(controller.signal);
    const upgrade = new URL(urls[0] ?? 'http://invalid');
    expect(upgrade.protocol).toBe('ws:');
    expect(upgrade.pathname).toBe('/api/pty');
    expect(upgrade.searchParams.get('resume')).toBe('session-1');
    expect(upgrade.searchParams.get('ticket')).toBe('pty-ticket');

    harness.open();
    await pending;
    expect(terminal.state).toMatchObject({ status: 'attached', sessionId: 'session-1', reconnectSupported: false });

    context.workspace.dispose();
  });

  it('expires authenticated root state for a hidden TerminalSurface PTY 4401', async () => {
    const harness = createSocketHarness();
    const fetch: LiveRestFetch = vi.fn(async (input) => {
      const path = String(input);
      if (path === '/api/auth/me') return jsonResponse(IDENTITY);
      if (path === '/api/auth/ws-ticket') return jsonResponse({ ticket: 'pty-ticket', ttl_seconds: 30 });
      throw new Error('unexpected request');
    });
    const context = createLiveRootContext({
      fetch,
      createPtySocket: () => harness.socket
    });
    await context.auth.initialize();
    expect(context.auth.current.status).toBe('authenticated');

    const terminal = context.workspace.terminal;
    if (!terminal) throw new Error('terminal bridge was not composed');
    const pending = terminal.attach('session-1', new AbortController().signal);
    await flush();
    harness.open();
    await pending;

    const expire = vi.spyOn(context.auth, 'expire');
    harness.closeFromServer(4401);

    expect(expire).toHaveBeenCalledTimes(1);
    expect(context.auth.current.status).toBe('expired');
    expect(context.workspace.current).toMatchObject({ state: 'loading', sessions: [], timeline: [] });
    expect(context.workspace.current.terminal).toBeUndefined();

    context.workspace.dispose();
    context.auth.dispose();
  });

  it('expires each recreated authenticated PTY bridge once across two 4401 cycles', async () => {
    const harnesses: ReturnType<typeof createSocketHarness>[] = [];
    const chatSocket = {
      onopen: null as (() => void) | null,
      onmessage: null as ((event: { readonly data: unknown }) => void) | null,
      onerror: null as (() => void) | null,
      onclose: null as ((event?: { readonly code?: number }) => void) | null,
      readyState: 1,
      sent: [] as string[],
      send: vi.fn((data: string) => {
        chatSocket.sent.push(data);
        const parsed = JSON.parse(data) as { readonly id?: string };
        if (parsed.id) {
          queueMicrotask(() => {
            chatSocket.onmessage?.({
              data: JSON.stringify({ jsonrpc: '2.0', id: parsed.id, result: { restored: true } })
            });
          });
        }
      }),
      close: vi.fn()
    };
    const session = {
      id: 'session-two',
      source: 'web',
      model: 'Hermes',
      title: 'Session two',
      started_at: 1,
      ended_at: null,
      last_active: 2,
      is_active: true,
      message_count: 0,
      tool_call_count: 0,
      input_tokens: 0,
      output_tokens: 0,
      preview: ''
    };
    const fetch: LiveRestFetch = vi.fn(async (input) => {
      const path = String(input);
      if (path === '/api/auth/me') return jsonResponse(IDENTITY);
      if (path === '/api/auth/ws-ticket') return jsonResponse({ ticket: 'pty-ticket', ttl_seconds: 30 });
      if (path.startsWith('/api/sessions/session-two/messages')) {
        return jsonResponse({
          session_id: 'session-two',
          messages: [],
          pagination: { limit: 500, offset: 0, returned: 0 }
        });
      }
      if (path.startsWith('/api/sessions?')) {
        return jsonResponse({ sessions: [session], total: 1, limit: 100, offset: 0 });
      }
      throw new Error(`unexpected request: ${path}`);
    });
    const context = createLiveRootContext({
      fetch,
      createSocket: () => chatSocket,
      createPtySocket: () => {
        const harness = harnesses.at(-1);
        if (!harness) throw new Error('missing PTY socket harness');
        return harness.socket;
      }
    });
    await context.auth.initialize();
    const expire = vi.spyOn(context.auth, 'expire');

    const attachAndExpire = async (sessionId: string): Promise<void> => {
      const harness = createSocketHarness();
      harnesses.push(harness);
      const terminal = context.workspace.terminal;
      if (!terminal) throw new Error('terminal bridge was not composed');
      const pending = terminal.attach(sessionId, new AbortController().signal);
      await flush();
      harness.open();
      await pending;
      const closeHandler = harness.socket.onclose;
      harness.closeFromServer(4401);
      // The transport removes its native close handler after the first event;
      // invoke the saved callback once more to prove duplicate 4401 delivery
      // stays inside the same epoch's expiry dedupe boundary.
      closeHandler?.({ code: 4401 });
      await flush();
    };

    await attachAndExpire('session-one');
    expect(expire).toHaveBeenCalledTimes(1);
    expect(context.auth.current.status).toBe('expired');

    await context.auth.initialize();
    expect(context.auth.current.status).toBe('authenticated');
    // Recreate the lazy bridge before restore so coordinator ownership can adopt
    // the session before its PTY state callbacks arrive.
    const recreatedTerminal = context.workspace.terminal;
    if (!recreatedTerminal) throw new Error('terminal bridge was not recreated');
    const initialization = context.workspace.initialize();
    for (let attempt = 0; attempt < 100 && !chatSocket.onopen; attempt += 1) await flush();
    chatSocket.onopen?.();
    for (let attempt = 0; attempt < 100 && !chatSocket.onmessage; attempt += 1) await flush();
    chatSocket.onmessage?.({
      data: JSON.stringify({
        jsonrpc: '2.0',
        method: 'event',
        params: {
          type: 'gateway.ready',
          payload: { skin: 'official', change_events: true }
        }
      })
    });
    await flush();
    await initialization;
    expect(context.workspace.current.activeSessionId).toBe('session-two');
    await attachAndExpire('session-two');

    expect(expire).toHaveBeenCalledTimes(2);
    expect(context.workspace.current.terminal).toBeUndefined();

    context.workspace.dispose();
    context.auth.dispose();
  });

  it('keeps PTY 4403 outside authenticated recovery', async () => {
    const harness = createSocketHarness();
    const fetch: LiveRestFetch = vi.fn(async (input) => {
      const path = String(input);
      if (path === '/api/auth/me') return jsonResponse(IDENTITY);
      if (path === '/api/auth/ws-ticket') return jsonResponse({ ticket: 'pty-ticket', ttl_seconds: 30 });
      throw new Error('unexpected request');
    });
    const context = createLiveRootContext({
      fetch,
      createPtySocket: () => harness.socket
    });
    await context.auth.initialize();

    const terminal = context.workspace.terminal;
    if (!terminal) throw new Error('terminal bridge was not composed');
    const pending = terminal.attach('session-1', new AbortController().signal);
    await flush();
    harness.open();
    await pending;

    const expire = vi.spyOn(context.auth, 'expire');
    harness.closeFromServer(4403);

    expect(expire).not.toHaveBeenCalled();
    expect(context.auth.current.status).toBe('authenticated');
    expect(context.workspace.current.terminal).toMatchObject({
      closeCode: 4403,
      failure: 'incompatible-origin'
    });

    context.workspace.dispose();
    context.auth.dispose();
  });
});
