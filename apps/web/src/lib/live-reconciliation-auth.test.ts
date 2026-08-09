import { describe, expect, it } from 'vitest';
import { runLiveReconciliationAttempt } from '../../tests/live/live-reconciliation-auth.mjs';

async function runLoginFailure(failure: () => Promise<void>) {
  const calls: string[] = [];
  const result = await runLiveReconciliationAttempt({
    operation: async (markLoginRequest) => {
      markLoginRequest();
      await failure();
    },
    logout: async () => {
      calls.push('logout');
    },
    clearCookies: async () => {
      calls.push('cookies');
    },
    clearBrowserState: async () => {
      calls.push('browser-state');
    }
  });
  return { result, calls };
}

describe('live reconciliation authentication cleanup', () => {
  it('revokes after malformed login JSON and still clears scoped browser state', async () => {
    const { result, calls } = await runLoginFailure(async () => {
      throw new Error('malformed login JSON');
    });
    expect(result).toEqual({
      operationFailed: true,
      cleanupFailed: false,
      loginRequestMayHaveIssuedSession: true,
      logoutAttempted: true,
      cookiesCleanupAttempted: true,
      browserStateCleanupAttempted: true
    });
    expect(calls).toEqual(['logout', 'cookies', 'browser-state']);
  });

  it('revokes after oversized login JSON and still clears scoped browser state', async () => {
    const { result, calls } = await runLoginFailure(async () => {
      throw new Error('login JSON exceeded its bound');
    });
    expect(result).toMatchObject({
      operationFailed: true,
      cleanupFailed: false,
      loginRequestMayHaveIssuedSession: true,
      logoutAttempted: true
    });
    expect(calls).toEqual(['logout', 'cookies', 'browser-state']);
  });

  it('revokes after a login body-read failure and still clears scoped browser state', async () => {
    const { result, calls } = await runLoginFailure(async () => {
      throw new Error('login body read failed');
    });
    expect(result).toMatchObject({
      operationFailed: true,
      cleanupFailed: false,
      loginRequestMayHaveIssuedSession: true,
      logoutAttempted: true
    });
    expect(calls).toEqual(['logout', 'cookies', 'browser-state']);
  });

  it('revokes after auth/me validation fails even when login parsing succeeded', async () => {
    const { result, calls } = await runLoginFailure(async () => {
      await Promise.resolve();
      throw new Error('auth/me validation failed');
    });
    expect(result).toMatchObject({
      operationFailed: true,
      cleanupFailed: false,
      loginRequestMayHaveIssuedSession: true,
      logoutAttempted: true
    });
    expect(calls).toEqual(['logout', 'cookies', 'browser-state']);
  });

  it('continues local cleanup after logout fails and reports cleanup failure', async () => {
    const calls: string[] = [];
    const result = await runLiveReconciliationAttempt({
      operation: async (markLoginRequest) => {
        markLoginRequest();
      },
      logout: async () => {
        calls.push('logout');
        throw new Error('logout failed');
      },
      clearCookies: async () => {
        calls.push('cookies');
      },
      clearBrowserState: async () => {
        calls.push('browser-state');
      }
    });
    expect(result).toMatchObject({
      operationFailed: false,
      cleanupFailed: true,
      logoutAttempted: true,
      cookiesCleanupAttempted: true,
      browserStateCleanupAttempted: true
    });
    expect(calls).toEqual(['logout', 'cookies', 'browser-state']);
  });
});
