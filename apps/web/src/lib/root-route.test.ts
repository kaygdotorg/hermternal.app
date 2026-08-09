import { describe, expect, it, vi } from 'vitest';
import type { LiveRestFetch } from '$lib/transport';
import { LiveWorkspaceSession } from '$lib/workspace/live-workspace-session';
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

function createPtySocketHarness() {
  const socket = {
    onopen: null as (() => void) | null,
    onmessage: null as ((event: { readonly data: unknown }) => void) | null,
    onerror: null as (() => void) | null,
    onclose: null as ((event?: { readonly code?: number; readonly reason?: string }) => void) | null,
    readyState: 1,
    send: vi.fn((_data: string | ArrayBuffer | ArrayBufferView) => undefined),
    close: vi.fn((code?: number, reason?: string) => socket.onclose?.({ code, reason }))
  };
  return { socket, open: () => socket.onopen?.() };
}

async function flush(): Promise<void> {
  for (let index = 0; index < 16; index += 1) await Promise.resolve();
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

  it('owns the PTY adapter at the root and releases its socket exactly once', async () => {
    const harness = createPtySocketHarness();
    const urls: string[] = [];
    const fetch: LiveRestFetch = vi.fn(async (input) => {
      if (String(input) === '/api/auth/ws-ticket') {
        return jsonResponse({ ticket: 'opaque-test-ticket', ttl_seconds: 30 });
      }
      throw new Error('unexpected request');
    });
    const createPtySocket = vi.fn((url: string) => {
      urls.push(url);
      return harness.socket;
    });
    const context = createLiveRootContext({ fetch, createPtySocket });
    const terminal = context.workspace.terminal;
    if (!terminal) throw new Error('terminal bridge was not composed');

    const pending = terminal.attach('session-1', new AbortController().signal);
    await flush();
    harness.open();
    await pending;

    expect(createPtySocket).toHaveBeenCalledTimes(1);
    const upgrade = new URL(urls[0] ?? 'http://invalid');
    expect(upgrade.pathname).toBe('/api/pty');
    expect(upgrade.searchParams.get('resume')).toBe('session-1');
    expect(JSON.stringify(context.workspace.current)).not.toContain('opaque-test-ticket');

    context.dispose();
    context.dispose();

    expect(harness.socket.close).toHaveBeenCalledTimes(1);
  });

  it('reuses the root workspace when the authenticated view remounts after expiry', async () => {
    const fetch: LiveRestFetch = vi.fn(async (input) => {
      if (String(input) === '/api/auth/me') return jsonResponse(IDENTITY);
      throw new Error('unexpected request');
    });
    const context = createLiveRootContext({ fetch });
    const initialize = vi.spyOn(context.workspace, 'initialize').mockResolvedValue(undefined);
    const workspace = context.workspace;
    const terminalBeforeExpiry = workspace.terminal;

    await context.auth.initialize();
    context.auth.expire();
    // The authenticated view may unmount here, but it now only releases its
    // subscription; root disposal remains the sole permanent lifecycle action.
    await context.auth.initialize();
    const unsubscribe = workspace.subscribe(() => {});
    await workspace.initialize();

    expect(context.auth.current.status).toBe('authenticated');
    expect(context.workspace).toBe(workspace);
    expect(workspace.terminal).not.toBe(terminalBeforeExpiry);
    expect(initialize).toHaveBeenCalledTimes(1);
    unsubscribe();
    context.dispose();
  });

  it('retires a bridge-stamped 4401 lease across reauthentication', async () => {
    const sockets = [createPtySocketHarness(), createPtySocketHarness()];
    let socketIndex = 0;
    const fetch: LiveRestFetch = vi.fn(async (input) => {
      if (String(input) === '/api/auth/me') return jsonResponse(IDENTITY);
      if (String(input) === '/api/auth/ws-ticket') return jsonResponse({ ticket: 'opaque-test-ticket', ttl_seconds: 30 });
      throw new Error('unexpected request');
    });
    const context = createLiveRootContext({
      fetch,
      createPtySocket: vi.fn(() => sockets[socketIndex++]!.socket)
    });
    const expire = vi.spyOn(context.auth, 'expire');
    await context.auth.initialize();
    const oldTerminal = context.workspace.terminal;
    if (!oldTerminal) throw new Error('terminal bridge was not composed');
    let observedStamp: object | undefined;
    oldTerminal.subscribe((event) => {
      if (event.type === 'state') observedStamp = event.lifecycle;
    });
    const oldAttach = oldTerminal.attach('session-1', new AbortController().signal);
    await flush();
    sockets[0]!.open();
    await oldAttach;
    const oldStamp = observedStamp;
    const oldLease = context.registerTerminalLifecycle(oldTerminal, oldStamp!);
    expect(oldLease).toBeDefined();

    let replacementStamp: object | undefined;
    oldTerminal.subscribe((event) => {
      if (event.type === 'state') replacementStamp = event.lifecycle;
    });
    // Replacing a binding on the same bridge proves a new producer-issued stamp
    // can authorize a successor lease without synthesizing an identity at root.
    const replacementAttach = oldTerminal.attach('session-2', new AbortController().signal);
    await flush();
    sockets[1]!.open();
    await replacementAttach;
    const replacementLease = context.registerTerminalLifecycle(oldTerminal, replacementStamp!);
    expect(replacementLease).toBeDefined();
    expect(replacementLease).not.toBe(oldLease);

    // The retired lease cannot expire the successor; the new lease is exact-once.
    context.expireTerminalAuthentication(oldLease);
    expect(expire).not.toHaveBeenCalled();
    context.expireTerminalAuthentication(replacementLease);
    context.expireTerminalAuthentication(replacementLease);
    expect(expire).toHaveBeenCalledTimes(1);
    await context.auth.initialize();

    const newTerminal = context.workspace.terminal;
    if (!newTerminal) throw new Error('replacement terminal bridge was not composed');
    expect(newTerminal).not.toBe(oldTerminal);
    // A caller-made structural lookalike and a replayed old producer stamp
    // cannot mint a lease for the reauthenticated bridge.
    const forgedStamp = Object.freeze({
      binding: { sessionId: 'session-1', invalidate: () => {} },
      nativeTransportGeneration: 1
    });
    expect(context.registerTerminalLifecycle(newTerminal, forgedStamp)).toBeUndefined();
    expect(context.registerTerminalLifecycle(newTerminal, oldStamp!)).toBeUndefined();
    expect(context.registerTerminalLifecycle(newTerminal, replacementStamp!)).toBeUndefined();
    context.dispose();
  });

  it('permanently disposes the root workspace exactly once', async () => {
    const fetch: LiveRestFetch = vi.fn(async (input) => {
      if (String(input) === '/api/auth/me') return jsonResponse(IDENTITY);
      throw new Error('unexpected request');
    });
    const disposeWorkspace = vi.spyOn(LiveWorkspaceSession.prototype, 'dispose');
    const context = createLiveRootContext({ fetch });
    const disposeAuth = vi.spyOn(context.auth, 'dispose');

    await context.auth.initialize();
    context.dispose();
    context.dispose();

    expect(disposeWorkspace).toHaveBeenCalledTimes(1);
    expect(disposeAuth).toHaveBeenCalledTimes(1);
  });
});
