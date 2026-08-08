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

  it('reuses the root workspace when the authenticated view remounts after expiry', async () => {
    const fetch: LiveRestFetch = vi.fn(async (input) => {
      if (String(input) === '/api/auth/me') return jsonResponse(IDENTITY);
      throw new Error('unexpected request');
    });
    const context = createLiveRootContext({ fetch });
    const initialize = vi.spyOn(context.workspace, 'initialize').mockResolvedValue(undefined);
    const workspace = context.workspace;

    await context.auth.initialize();
    context.auth.expire();
    // The authenticated view may unmount here, but it now only releases its
    // subscription; root disposal remains the sole permanent lifecycle action.
    await context.auth.initialize();
    const unsubscribe = workspace.subscribe(() => {});
    await workspace.initialize();

    expect(context.auth.current.status).toBe('authenticated');
    expect(context.workspace).toBe(workspace);
    expect(initialize).toHaveBeenCalledTimes(1);
    unsubscribe();
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
