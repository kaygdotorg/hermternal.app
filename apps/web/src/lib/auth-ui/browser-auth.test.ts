import { describe, expect, it, vi } from 'vitest';
import {
  AUTH_ME_PATH,
  BrowserAuthError,
  createBrowserAuthClient,
  LOGOUT_PATH,
  PASSWORD_LOGIN_PATH
} from './browser-auth';

const identity = {
  user_id: 'user-1',
  email: 'person@example.invalid',
  display_name: 'Synthetic Person',
  org_id: 'org-1',
  provider: 'basic',
  expires_at: 2_000_000_000
};

function jsonResponse(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { 'content-type': 'application/json', 'content-length': String(new TextEncoder().encode(body).length) }
  });
}

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

function pendingBodyResponse(): { response: Response; wasCancelled: () => boolean } {
  let cancelled = false;
  const response = new Response(
    new ReadableStream<Uint8Array>({
      cancel() {
        cancelled = true;
      }
    }),
    { status: 200, headers: { 'content-type': 'application/json' } }
  );
  return { response, wasCancelled: () => cancelled };
}

function neverSettlingCancelResponse(): { response: Response; wasCancelled: () => boolean } {
  let cancelled = false;
  const response = new Response(
    new ReadableStream<Uint8Array>({
      cancel() {
        cancelled = true;
        return new Promise<void>(() => {});
      }
    }),
    { status: 500, headers: { 'content-type': 'application/json' } }
  );
  return { response, wasCancelled: () => cancelled };
}

describe('browser authentication boundary', () => {
  it('submits one same-origin password request and verifies the cookie identity', async () => {
    const requests: Array<{ path: string; init?: RequestInit }> = [];
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      requests.push({ path, init });
      if (path === PASSWORD_LOGIN_PATH) return jsonResponse('{"ok":true,"next":"/"}');
      if (path === AUTH_ME_PATH) return jsonResponse(JSON.stringify(identity));
      throw new Error('unexpected path');
    });
    const client = createBrowserAuthClient({ fetch: fetcher });

    const result = await client.loginWithPassword({
      provider: 'basic',
      username: 'synthetic-user',
      password: 'synthetic-password'
    });

    expect(result).toEqual({
      next: '/',
      identity: {
        userId: 'user-1',
        email: 'person@example.invalid',
        displayName: 'Synthetic Person',
        organizationId: 'org-1',
        provider: 'basic',
        expiresAt: 2_000_000_000
      }
    });
    expect(requests.map(({ path }) => path)).toEqual([PASSWORD_LOGIN_PATH, AUTH_ME_PATH]);
    expect(requests[0]?.init).toMatchObject({
      method: 'POST',
      mode: 'same-origin',
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer'
    });
    expect(JSON.parse(String(requests[0]?.init?.body))).toEqual({
      provider: 'basic',
      username: 'synthetic-user',
      password: 'synthetic-password',
      next: '/'
    });
  });

  it('rejects duplicate password submissions while the first attempt is pending', async () => {
    const pending = deferred<Response>();
    const fetcher = vi.fn((input: RequestInfo | URL) => {
      if (String(input) === PASSWORD_LOGIN_PATH) return pending.promise;
      return Promise.resolve(jsonResponse(JSON.stringify(identity)));
    });
    const client = createBrowserAuthClient({ fetch: fetcher });
    const first = client.loginWithPassword({ provider: 'basic', username: 'first', password: 'fixture-one' });

    await expect(
      client.loginWithPassword({ provider: 'basic', username: 'second', password: 'fixture-two' })
    ).rejects.toMatchObject({ code: 'busy' });

    pending.resolve(jsonResponse('{"ok":true,"next":"/"}'));
    await expect(first).resolves.toMatchObject({ next: '/' });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it.each([
    [401, 'invalid-credentials'],
    [404, 'provider-unavailable'],
    [429, 'rate-limited'],
    [503, 'provider-unavailable']
  ] as const)('maps password HTTP %s to the fixed %s diagnostic', async (status, code) => {
    const secret = 'provider-secret-must-not-escape';
    const client = createBrowserAuthClient({
      fetch: async () => jsonResponse(JSON.stringify({ detail: secret }), status)
    });

    const error = await client
      .loginWithPassword({ provider: 'basic', username: 'synthetic-user', password: 'synthetic-password' })
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(BrowserAuthError);
    expect(error).toMatchObject({ code, status });
    expect(String(error)).not.toContain(secret);
    expect(String(error)).not.toContain('synthetic-password');
  });

  it('rejects duplicate response keys before probing identity', async () => {
    const fetcher = vi.fn(async () => jsonResponse('{"ok":true,"ok":true,"next":"/"}'));
    const client = createBrowserAuthClient({ fetch: fetcher });

    await expect(
      client.loginWithPassword({ provider: 'basic', username: 'synthetic-user', password: 'synthetic-password' })
    ).rejects.toMatchObject({ code: 'invalid-response' });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('fails closed when login succeeds but identity verification is rejected', async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL) =>
      String(input) === PASSWORD_LOGIN_PATH
        ? jsonResponse('{"ok":true,"next":"/"}')
        : jsonResponse('{"detail":"Unauthorized"}', 401)
    );
    const client = createBrowserAuthClient({ fetch: fetcher });

    await expect(
      client.loginWithPassword({ provider: 'basic', username: 'synthetic-user', password: 'synthetic-password' })
    ).rejects.toMatchObject({ code: 'identity-unverified' });
  });

  it.each([
    [500, '{"detail":"server failure"}', 'identity-failed', 500],
    [302, '', 'identity-failed', undefined],
    [200, '{"user_id":', 'identity-failed', undefined]
  ] as const)('classifies non-401 identity failures as %s without treating them as signed out', async (status, body, code, errorStatus) => {
    const client = createBrowserAuthClient({
      fetch: async () =>
        new Response(body, {
          status,
          headers: { 'content-type': 'application/json' }
        })
    });

    await expect(client.verify()).rejects.toMatchObject({ code, status: errorStatus });
  });

  it('classifies an identity timeout as a non-discovery failure', async () => {
    const pending = deferred<Response>();
    const client = createBrowserAuthClient({
      fetch: async () => pending.promise,
      timeoutMs: 5
    });

    await expect(client.verify()).rejects.toMatchObject({ code: 'identity-failed' });
  });

  it('bounds a response cancel that never settles after headers fail closed', async () => {
    const tracked = neverSettlingCancelResponse();
    const fetcher = vi.fn(async () => tracked.response);
    const client = createBrowserAuthClient({ fetch: fetcher });
    const startedAt = Date.now();

    await expect(
      client.loginWithPassword({ provider: 'basic', username: 'synthetic-user', password: 'synthetic-password' })
    ).rejects.toMatchObject({ code: 'invalid-response', status: 500 });

    expect(tracked.wasCancelled()).toBe(true);
    expect(Date.now() - startedAt).toBeLessThan(1_000);
  });

  it('treats logout as complete only after the identity probe returns 401', async () => {
    const requests: Array<{ path: string; init?: RequestInit }> = [];
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      requests.push({ path, init });
      if (path === LOGOUT_PATH) return new Response(null, { status: 302, headers: { location: '/login' } });
      return jsonResponse('{"detail":"Unauthorized"}', 401);
    });
    const client = createBrowserAuthClient({ fetch: fetcher });

    await expect(client.logout()).resolves.toBeUndefined();
    expect(requests.map(({ path }) => path)).toEqual([LOGOUT_PATH, AUTH_ME_PATH]);
    expect(requests[0]?.init).toMatchObject({
      method: 'POST',
      mode: 'same-origin',
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'manual',
      referrerPolicy: 'no-referrer'
    });
  });

  it('coalesces duplicate logout calls and rejects a still-authenticated session', async () => {
    const logoutPending = deferred<Response>();
    const fetcher = vi.fn((input: RequestInfo | URL) => {
      if (String(input) === LOGOUT_PATH) return logoutPending.promise;
      return Promise.resolve(jsonResponse(JSON.stringify(identity)));
    });
    const client = createBrowserAuthClient({ fetch: fetcher });
    const first = client.logout();
    const second = client.logout();

    logoutPending.resolve(new Response(null, { status: 302, headers: { location: '/login' } }));
    await expect(first).rejects.toMatchObject({ code: 'logout-failed' });
    await expect(second).rejects.toMatchObject({ code: 'logout-failed' });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it.each([
    [200, undefined],
    [302, undefined],
    [302, 'https://evil.example/login'],
    [302, '/auth/login']
  ] as const)('rejects a logout response outside the exact 302 /login contract (%s, %s)', async (status, location) => {
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      if (String(input) !== LOGOUT_PATH) throw new Error('identity probe must not run');
      return new Response(null, {
        status,
        ...(location ? { headers: { location } } : {})
      });
    });
    const client = createBrowserAuthClient({ fetch: fetcher });

    await expect(client.logout()).rejects.toMatchObject({ code: 'invalid-response', status });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('cancels a password response reader when the caller aborts after headers', async () => {
    const tracked = pendingBodyResponse();
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      if (String(input) === PASSWORD_LOGIN_PATH) return tracked.response;
      throw new Error('identity probe must not run');
    });
    const controller = new AbortController();
    const client = createBrowserAuthClient({ fetch: fetcher });
    const pending = client.loginWithPassword(
      { provider: 'basic', username: 'synthetic-user', password: 'synthetic-password' },
      controller.signal
    );
    await vi.waitFor(() => expect(fetcher).toHaveBeenCalledOnce());
    controller.abort();

    await expect(pending).rejects.toMatchObject({ code: 'aborted' });
    await vi.waitFor(() => expect(tracked.wasCancelled()).toBe(true));
  });

  it('cancels a password response reader when the operation deadline expires', async () => {
    const tracked = pendingBodyResponse();
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      if (String(input) === PASSWORD_LOGIN_PATH) return tracked.response;
      throw new Error('identity probe must not run');
    });
    const client = createBrowserAuthClient({ fetch: fetcher, timeoutMs: 5 });

    await expect(
      client.loginWithPassword({ provider: 'basic', username: 'synthetic-user', password: 'synthetic-password' })
    ).rejects.toMatchObject({ code: 'timeout' });
    await vi.waitFor(() => expect(tracked.wasCancelled()).toBe(true));
  });

  it('does not issue a request for malformed or already-aborted input', async () => {
    const fetcher = vi.fn();
    const client = createBrowserAuthClient({ fetch: fetcher });

    await expect(
      client.loginWithPassword({ provider: '../basic', username: 'synthetic-user', password: 'synthetic-password' })
    ).rejects.toMatchObject({ code: 'invalid-input' });

    const controller = new AbortController();
    controller.abort();
    await expect(
      client.loginWithPassword(
        { provider: 'basic', username: 'synthetic-user', password: 'synthetic-password' },
        controller.signal
      )
    ).rejects.toMatchObject({ code: 'aborted' });
    expect(fetcher).not.toHaveBeenCalled();
  });
});
