import { describe, expect, it, vi } from 'vitest';
import type { AuthIdentity } from '$lib/transport/live-rest-types';
import { BrowserAuthError, type BrowserAuthClient } from './browser-auth';
import { ProviderDiscoveryError } from './provider-discovery';
import { BrowserAuthSession } from './browser-auth-session';

const identity: AuthIdentity = {
  userId: 'user-1',
  email: 'person@example.invalid',
  displayName: 'Synthetic Person',
  organizationId: 'org-1',
  provider: 'basic',
  expiresAt: 2_000_000_000
};

const passwordProvider = {
  id: 'basic',
  name: 'Hermes password',
  monogram: 'H',
  kind: 'password' as const,
  description: 'Username and password supported'
};

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void; reject: (error: unknown) => void } {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((settle, fail) => {
    resolve = settle;
    reject = fail;
  });
  return { promise, resolve, reject };
}

function client(overrides: Partial<BrowserAuthClient> = {}): BrowserAuthClient {
  return {
    verify: vi.fn(async () => identity),
    loginWithPassword: vi.fn(async () => ({ identity, next: '/' as const })),
    logout: vi.fn(async () => undefined),
    ...overrides
  };
}

describe('BrowserAuthSession', () => {
  it('verifies identity before entering authenticated state', async () => {
    const authClient = client();
    const discoverProviders = vi.fn();
    const session = new BrowserAuthSession({ client: authClient, discoverProviders, invalidateLocalSession: vi.fn() });

    await session.initialize();

    expect(authClient.verify).toHaveBeenCalledTimes(1);
    expect(discoverProviders).not.toHaveBeenCalled();
    expect(session.current).toEqual({ status: 'authenticated', identity, providers: [] });
  });

  it('discovers providers only after the identity probe rejects authentication', async () => {
    const order: string[] = [];
    const authClient = client({
      verify: vi.fn(async () => {
        order.push('verify');
        throw new BrowserAuthError('identity-unverified', 401);
      })
    });
    const discoverProviders = vi.fn(async () => {
      order.push('discover');
      return { providers: [passwordProvider] };
    });
    const session = new BrowserAuthSession({
      client: authClient,
      discoverProviders,
      invalidateLocalSession: vi.fn()
    });

    await session.initialize();

    expect(order).toEqual(['verify', 'discover']);
    expect(session.current).toEqual({ status: 'signed_out', providers: [passwordProvider] });
  });

  it('keeps password values transient and suppresses a duplicate submission', async () => {
    const pending = deferred<{ identity: AuthIdentity; next: '/' }>();
    const loginWithPassword = vi.fn(() => pending.promise);
    const authClient = client({ loginWithPassword });
    const session = new BrowserAuthSession({
      client: authClient,
      discoverProviders: async () => ({ providers: [passwordProvider] }),
      invalidateLocalSession: vi.fn()
    });
    await session.retryDiscovery();
    session.chooseProvider('basic');

    const first = session.loginWithPassword({ username: 'synthetic-user', password: 'transient-secret' });
    const second = session.loginWithPassword({ username: 'duplicate', password: 'second-secret' });

    expect(loginWithPassword).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(session.current)).not.toContain('transient-secret');
    expect(JSON.stringify(session.current)).not.toContain('second-secret');
    await second;
    pending.resolve({ identity, next: '/' });
    await first;
    expect(session.current.status).toBe('authenticated');
  });

  it('invalidates local chat before logout and accepts only verified server logout', async () => {
    const events: string[] = [];
    const authClient = client({
      logout: vi.fn(async () => {
        events.push('server-logout');
      })
    });
    const session = new BrowserAuthSession({
      client: authClient,
      discoverProviders: async () => ({ providers: [] }),
      invalidateLocalSession: () => events.push('invalidate-local')
    });
    await session.initialize();

    await session.logout();

    expect(events).toEqual(['invalidate-local', 'server-logout']);
    expect(session.current).toEqual({ status: 'signed_out', providers: [] });
  });

  it('does not invoke logout before a verified authenticated identity exists', async () => {
    const logout = vi.fn(async () => undefined);
    const signedOut = new BrowserAuthSession({
      client: client({ logout }),
      discoverProviders: async () => ({ providers: [] }),
      invalidateLocalSession: vi.fn()
    });

    await signedOut.logout();
    expect(logout).not.toHaveBeenCalled();

    const failed = new BrowserAuthSession({
      client: client({
        logout,
        verify: vi.fn(async () => {
          throw new BrowserAuthError('identity-failed', 500);
        })
      }),
      discoverProviders: async () => ({ providers: [] }),
      invalidateLocalSession: vi.fn()
    });
    await failed.initialize();
    await failed.logout();
    expect(logout).not.toHaveBeenCalled();
  });

  it('does not reconcile an invalid logout contract into signed_out', async () => {
    const verify = vi
      .fn<BrowserAuthClient['verify']>()
      .mockResolvedValueOnce(identity)
      .mockRejectedValueOnce(new BrowserAuthError('identity-unverified', 401));
    const logout = vi.fn(async () => {
      throw new BrowserAuthError('invalid-response', 302);
    });
    const session = new BrowserAuthSession({
      client: client({ verify, logout }),
      discoverProviders: async () => ({ providers: [] }),
      invalidateLocalSession: vi.fn()
    });

    await session.initialize();
    await session.logout();

    expect(verify).toHaveBeenCalledTimes(1);
    expect(session.current).toEqual({
      status: 'logout_failed',
      identity,
      providers: [],
      errorCode: 'logout-unverified'
    });
  });

  it('permits retry logout only with the retained verified identity', async () => {
    const logout = vi
      .fn<BrowserAuthClient['logout']>()
      .mockRejectedValueOnce(new BrowserAuthError('logout-failed'))
      .mockResolvedValueOnce(undefined);
    const session = new BrowserAuthSession({
      client: client({ logout }),
      discoverProviders: async () => ({ providers: [] }),
      invalidateLocalSession: vi.fn()
    });

    await session.initialize();
    await session.logout();
    await session.logout();

    expect(logout).toHaveBeenCalledTimes(2);
    expect(session.current).toEqual({ status: 'signed_out', providers: [] });
  });

  it('closes local chat immediately on expiry and ignores stale authentication completion', async () => {
    const pending = deferred<AuthIdentity>();
    const invalidateLocalSession = vi.fn();
    const session = new BrowserAuthSession({
      client: client({ verify: vi.fn(() => pending.promise) }),
      discoverProviders: async () => ({ providers: [] }),
      invalidateLocalSession
    });

    const initialization = session.initialize();
    session.expire();
    pending.resolve(identity);
    await initialization;

    expect(invalidateLocalSession).toHaveBeenCalledTimes(1);
    expect(session.current).toEqual({ status: 'expired', providers: [] });
  });

  it('cancels superseded provider discovery without publishing its stale result', async () => {
    const first = deferred<{ providers: (typeof passwordProvider)[] }>();
    const discoverProviders = vi
      .fn()
      .mockImplementationOnce(() => first.promise)
      .mockResolvedValueOnce({ providers: [] });
    const session = new BrowserAuthSession({
      client: client(),
      discoverProviders,
      invalidateLocalSession: vi.fn()
    });

    const firstAttempt = session.retryDiscovery();
    const secondAttempt = session.retryDiscovery();
    await secondAttempt;
    first.resolve({ providers: [passwordProvider] });
    await firstAttempt;

    expect(session.current).toEqual({ status: 'provider_unavailable', providers: [] });
  });

  it('treats only provider-discovery aborts as cancellation and keeps real failures visible', async () => {
    const discoverProviders = vi
      .fn()
      .mockRejectedValueOnce(new ProviderDiscoveryError('aborted'))
      .mockRejectedValueOnce(new ProviderDiscoveryError('network'));
    const session = new BrowserAuthSession({
      client: client(),
      discoverProviders,
      invalidateLocalSession: vi.fn()
    });

    await session.retryDiscovery();
    expect(session.current).toEqual({ status: 'discovering', providers: [] });

    await session.retryDiscovery();
    expect(session.current).toEqual({ status: 'provider_unavailable', providers: [] });
  });

  it('fails closed on non-401 identity errors without entering provider discovery', async () => {
    const verify = vi.fn(async () => {
      throw new BrowserAuthError('identity-failed', 500);
    });
    const discoverProviders = vi.fn(async () => ({ providers: [passwordProvider] }));
    const session = new BrowserAuthSession({
      client: client({ verify }),
      discoverProviders,
      invalidateLocalSession: vi.fn()
    });

    await session.initialize();
    await session.retryDiscovery();

    expect(verify).toHaveBeenCalledTimes(2);
    expect(discoverProviders).not.toHaveBeenCalled();
    expect(session.current).toMatchObject({ status: 'failed', errorCode: 'identity-failed', providers: [] });
  });

  it('keeps logout non-interruptible and does not start retry discovery while it is pending', async () => {
    const logoutPending = deferred<void>();
    let logoutSignal: AbortSignal | undefined;
    const logout = vi.fn((signal?: AbortSignal) => {
      logoutSignal = signal;
      return logoutPending.promise;
    });
    const discoverProviders = vi.fn(async () => ({ providers: [passwordProvider] }));
    const session = new BrowserAuthSession({
      client: client({ logout }),
      discoverProviders,
      invalidateLocalSession: vi.fn()
    });
    await session.initialize();

    const pendingLogout = session.logout();
    expect(session.current.status).toBe('logging_out');

    await session.retryDiscovery();
    session.cancel();

    expect(discoverProviders).not.toHaveBeenCalled();
    expect(logoutSignal?.aborted).toBe(false);
    expect(session.current.status).toBe('logging_out');

    logoutPending.resolve();
    await pendingLogout;
    expect(session.current).toEqual({ status: 'signed_out', providers: [] });
  });

  it('reconciles an ambiguous logout before staying signed out', async () => {
    const verify = vi
      .fn<BrowserAuthClient['verify']>()
      .mockResolvedValueOnce(identity)
      .mockRejectedValueOnce(new BrowserAuthError('identity-unverified', 401));
    const logout = vi.fn(async () => {
      throw new BrowserAuthError('network');
    });
    const discoverProviders = vi.fn(async () => ({ providers: [passwordProvider] }));
    const session = new BrowserAuthSession({
      client: client({ verify, logout }),
      discoverProviders,
      invalidateLocalSession: vi.fn()
    });

    await session.initialize();
    await session.logout();

    expect(verify).toHaveBeenCalledTimes(2);
    expect(discoverProviders).not.toHaveBeenCalled();
    expect(session.current).toEqual({ status: 'signed_out', providers: [] });
  });

  it('publishes dedicated logout recovery when the server identity remains active', async () => {
    const verify = vi.fn<BrowserAuthClient['verify']>(async () => identity);
    const logout = vi.fn(async () => {
      throw new BrowserAuthError('logout-failed');
    });
    const discoverProviders = vi.fn(async () => ({ providers: [passwordProvider] }));
    const session = new BrowserAuthSession({
      client: client({ verify, logout }),
      discoverProviders,
      invalidateLocalSession: vi.fn()
    });

    await session.initialize();
    await session.logout();
    await session.retryDiscovery();
    session.cancel();

    expect(verify).toHaveBeenCalledTimes(1);
    expect(discoverProviders).not.toHaveBeenCalled();
    expect(session.current).toEqual({
      status: 'logout_failed',
      identity,
      providers: [],
      errorCode: 'logout-failed'
    });
  });
});
