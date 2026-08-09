import { describe, expect, it, vi } from 'vitest';
import { runLiveReconciliationAttempt } from '../../tests/live/live-reconciliation-auth.mjs';
import {
  LIVE_RECONCILIATION_MAX_RESPONSE_BYTES,
  readBoundedLiveReconciliationJson,
  requestLiveReconciliationProjection
} from '../../tests/live/live-reconciliation-transport.mjs';

type ReaderStats = {
  readCount: number;
  cancelCount: number;
  bytesRead: number;
};

function responseFromChunks(
  chunks: Uint8Array[],
  contentLength?: string
): { response: any; stats: ReaderStats } {
  let index = 0;
  const stats: ReaderStats = { readCount: 0, cancelCount: 0, bytesRead: 0 };
  const reader = {
    async read() {
      stats.readCount += 1;
      if (index >= chunks.length) return { done: true, value: undefined };
      const value = chunks[index];
      index += 1;
      stats.bytesRead += value.byteLength;
      return { done: false, value };
    },
    async cancel() {
      stats.cancelCount += 1;
    }
  };
  return {
    response: {
      status: 200,
      body: { getReader: () => reader },
      headers: {
        get(name: string) {
          if (name === 'content-length') return contentLength ?? null;
          if (name === 'content-type') return 'application/json';
          return null;
        }
      }
    },
    stats
  };
}

function pageWithFetch(fetchImplementation: typeof fetch) {
  return {
    evaluate: async (callback: (value: unknown) => Promise<unknown>, value: unknown) => {
      const previousFetch = globalThis.fetch;
      globalThis.fetch = fetchImplementation;
      try {
        return await callback(value);
      } finally {
        globalThis.fetch = previousFetch;
      }
    }
  };
}

type FailureOutcome =
  | { kind: 'settled'; value: unknown }
  | { kind: 'rejected'; error: unknown }
  | { kind: 'watchdog' };

function settleWithWatchdog(operation: Promise<unknown>, delayMs = 50): Promise<FailureOutcome> {
  let watchdogTimer: ReturnType<typeof setTimeout> | undefined;
  const watchdog = new Promise<{ kind: 'watchdog' }>((resolve) => {
    watchdogTimer = setTimeout(() => resolve({ kind: 'watchdog' }), delayMs);
  });
  return Promise.race([
    operation.then(
      (value) => ({ kind: 'settled', value } as const),
      (error) => ({ kind: 'rejected', error } as const)
    ),
    watchdog
  ]).finally(() => {
    if (watchdogTimer !== undefined) clearTimeout(watchdogTimer);
  });
}

function expectFixedFailure(outcome: FailureOutcome, expectedMessage: string): Error {
  expect(outcome.kind).toBe('rejected');
  if (outcome.kind !== 'rejected' || !(outcome.error instanceof Error)) {
    throw new Error('live reconciliation transport did not settle before its watchdog');
  }
  expect(outcome.error.message).toBe(expectedMessage);
  expect(outcome.error.message).not.toContain('raw-cancel-diagnostic');
  return outcome.error;
}

describe('live reconciliation bounded transport', () => {
  it('aborts and cancels before reading beyond the byte cap', async () => {
    const { response, stats } = responseFromChunks([
      new Uint8Array(LIVE_RECONCILIATION_MAX_RESPONSE_BYTES),
      new Uint8Array([123]),
      new Uint8Array([125])
    ]);
    const controller = new AbortController();

    await expect(readBoundedLiveReconciliationJson(response, controller)).rejects.toThrow(
      'exceeded its bound'
    );
    expect(controller.signal.aborted).toBe(true);
    expect(stats.readCount).toBe(2);
    expect(stats.bytesRead).toBe(LIVE_RECONCILIATION_MAX_RESPONSE_BYTES + 1);
    expect(stats.cancelCount).toBeGreaterThan(0);
  });

  it('stops an endless chunked response at the bounded transport budget', async () => {
    const stats: ReaderStats = { readCount: 0, cancelCount: 0, bytesRead: 0 };
    const reader = {
      async read() {
        stats.readCount += 1;
        const value = new Uint8Array(64 * 1024);
        stats.bytesRead += value.byteLength;
        return { done: false, value };
      },
      async cancel() {
        stats.cancelCount += 1;
      }
    };
    const controller = new AbortController();

    await expect(
      readBoundedLiveReconciliationJson(
        { body: { getReader: () => reader }, headers: { get: () => null } },
        controller
      )
    ).rejects.toThrow('exceeded its bound');
    expect(stats.readCount).toBe(5);
    expect(stats.bytesRead).toBe(5 * 64 * 1024);
    expect(stats.bytesRead).toBeLessThanOrEqual(LIVE_RECONCILIATION_MAX_RESPONSE_BYTES + 64 * 1024);
    expect(stats.cancelCount).toBeGreaterThan(0);
    expect(controller.signal.aborted).toBe(true);
  });

  it('rejects absent or non-streaming bodies before buffering', async () => {
    const controller = new AbortController();
    await expect(
      readBoundedLiveReconciliationJson(
        { body: null, headers: { get: () => null } },
        controller
      )
    ).rejects.toThrow('not streamable');
    expect(controller.signal.aborted).toBe(true);

    const secondController = new AbortController();
    await expect(
      readBoundedLiveReconciliationJson(
        { body: {}, headers: { get: () => null } },
        secondController
      )
    ).rejects.toThrow('not streamable');
    expect(secondController.signal.aborted).toBe(true);
  });

  it('rejects an oversized declared body before opening its reader', async () => {
    let getReaderCount = 0;
    const controller = new AbortController();
    await expect(
      readBoundedLiveReconciliationJson(
        {
          body: {
            getReader: () => {
              getReaderCount += 1;
              return { read: async () => ({ done: true }), cancel: async () => undefined };
            }
          },
          headers: { get: () => String(LIVE_RECONCILIATION_MAX_RESPONSE_BYTES + 1) }
        },
        controller
      )
    ).rejects.toThrow('exceeded its bound');
    expect(getReaderCount).toBe(0);
    expect(controller.signal.aborted).toBe(true);
  });

  it('counts actual decompressed chunks despite missing or lying lengths', async () => {
    for (const declaredLength of [null, '1']) {
      const { response, stats } = responseFromChunks(
        [
          new Uint8Array(LIVE_RECONCILIATION_MAX_RESPONSE_BYTES),
          new Uint8Array([1])
        ],
        declaredLength ?? undefined
      );
      const controller = new AbortController();
      await expect(readBoundedLiveReconciliationJson(response, controller)).rejects.toThrow(
        'exceeded its bound'
      );
      expect(stats.bytesRead).toBe(LIVE_RECONCILIATION_MAX_RESPONSE_BYTES + 1);
      expect(stats.cancelCount).toBeGreaterThan(0);
      expect(controller.signal.aborted).toBe(true);
    }

    const compressed = responseFromChunks(
      [new Uint8Array(LIVE_RECONCILIATION_MAX_RESPONSE_BYTES), new Uint8Array([1])]
    );
    compressed.response.headers.get = (name: string) => {
      if (name === 'content-encoding') return 'gzip';
      if (name === 'content-type') return 'application/json';
      return null;
    };
    const compressedController = new AbortController();
    await expect(
      readBoundedLiveReconciliationJson(compressed.response, compressedController)
    ).rejects.toThrow('exceeded its bound');
    expect(compressed.stats.bytesRead).toBe(LIVE_RECONCILIATION_MAX_RESPONSE_BYTES + 1);
    expect(compressed.stats.cancelCount).toBeGreaterThan(0);
  });

  it('uses only approved auth routes and still cleans up after a capped login response', async () => {
    const routes: string[] = [];
    const { response, stats } = responseFromChunks([
      new Uint8Array(LIVE_RECONCILIATION_MAX_RESPONSE_BYTES),
      new Uint8Array([1])
    ]);
    const page = pageWithFetch(async (input) => {
      routes.push(new URL(String(input)).pathname);
      return response as Response;
    });
    const calls: string[] = [];
    const result = await runLiveReconciliationAttempt({
      operation: async (markLoginRequest) => {
        markLoginRequest();
        await requestLiveReconciliationProjection(page, {
          baseURL: 'http://127.0.0.1:4187/',
          kind: 'login',
          provider: 'password',
          username: 'user',
          password: 'password'
        });
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

    expect(result).toMatchObject({
      operationFailed: true,
      cleanupFailed: false,
      loginRequestMayHaveIssuedSession: true,
      logoutAttempted: true
    });
    expect(calls).toEqual(['logout', 'cookies', 'browser-state']);
    expect(routes).toEqual(['/auth/password-login']);
    expect(routes.some((route) => route.includes('prompt') || route.includes('ticket') || route === '/api/ws')).toBe(false);
    expect(stats.readCount).toBe(2);
    expect(stats.cancelCount).toBeGreaterThan(0);
  });

  it('fails promptly when invalid chunks have a never-settling cancel thenable', async () => {
    let cancelCount = 0;
    const hostileThenable = { then() {} };
    const reader = {
      async read() {
        return { done: false, value: 'raw-invalid-chunk' };
      },
      cancel() {
        cancelCount += 1;
        return hostileThenable;
      }
    };
    const controller = new AbortController();
    const outcome = await settleWithWatchdog(
      readBoundedLiveReconciliationJson(
        { body: { getReader: () => reader }, headers: { get: () => null } },
        controller
      )
    );

    expectFixedFailure(outcome, 'live reconciliation response chunk is invalid');
    expect(cancelCount).toBe(1);
    expect(controller.signal.aborted).toBe(true);
  });

  it('fails promptly when the byte cap has a never-settling cancel promise', async () => {
    let readCount = 0;
    let cancelCount = 0;
    const reader = {
      async read() {
        readCount += 1;
        return readCount === 1
          ? { done: false, value: new Uint8Array(LIVE_RECONCILIATION_MAX_RESPONSE_BYTES) }
          : { done: false, value: new Uint8Array([1]) };
      },
      cancel() {
        cancelCount += 1;
        return new Promise(() => undefined);
      }
    };
    const controller = new AbortController();
    const outcome = await settleWithWatchdog(
      readBoundedLiveReconciliationJson(
        { body: { getReader: () => reader }, headers: { get: () => null } },
        controller
      )
    );

    expectFixedFailure(outcome, 'live reconciliation response exceeded its bound');
    expect(readCount).toBe(2);
    expect(cancelCount).toBe(1);
    expect(controller.signal.aborted).toBe(true);
  });

  it('keeps synchronous cancel throws out of the fixed invalid-chunk failure', async () => {
    let cancelCount = 0;
    const reader = {
      async read() {
        return { done: false, value: 'raw-invalid-chunk' };
      },
      cancel() {
        cancelCount += 1;
        throw new Error('raw-cancel-diagnostic');
      }
    };
    const controller = new AbortController();
    const outcome = await settleWithWatchdog(
      readBoundedLiveReconciliationJson(
        { body: { getReader: () => reader }, headers: { get: () => null } },
        controller
      )
    );

    expectFixedFailure(outcome, 'live reconciliation response chunk is invalid');
    expect(cancelCount).toBe(1);
    expect(controller.signal.aborted).toBe(true);
  });

  it('clears page transport timers and abort listeners before independent cleanup', async () => {
    const previousFetch = globalThis.fetch;
    const routes: string[] = [];
    const evidence = {
      readCount: 0,
      cancelCount: 0,
      abortCount: 0,
      activeAbortListeners: 0
    };
    const hostileThenable = { then() {} };
    const reader = {
      async read() {
        evidence.readCount += 1;
        return evidence.readCount === 1
          ? { done: false, value: new Uint8Array(LIVE_RECONCILIATION_MAX_RESPONSE_BYTES) }
          : { done: false, value: new Uint8Array([1]) };
      },
      cancel() {
        evidence.cancelCount += 1;
        return hostileThenable;
      }
    };
    const response = {
      status: 200,
      body: { getReader: () => reader },
      headers: {
        get(name: string) {
          if (name === 'content-type') return 'application/json';
          return null;
        }
      }
    };
    const page = pageWithFetch(
      (async (input, init) => {
        routes.push(new URL(String(input)).pathname);
        const signal = init?.signal;
        if (!signal) throw new Error('raw-cancel-diagnostic');
        signal.addEventListener(
          'abort',
          () => {
            evidence.abortCount += 1;
            evidence.activeAbortListeners -= 1;
          },
          { once: true }
        );
        evidence.activeAbortListeners += 1;
        return response as unknown as Response;
      }) as typeof fetch
    );
    const calls: string[] = [];
    let operationError: string | undefined;
    vi.useFakeTimers();
    const attempt = runLiveReconciliationAttempt({
      operation: async (markLoginRequest) => {
        markLoginRequest();
        try {
          await requestLiveReconciliationProjection(page, {
            baseURL: 'http://127.0.0.1:4187/',
            kind: 'login',
            provider: 'password',
            username: 'user',
            password: 'password'
          });
        } catch (error) {
          operationError = error instanceof Error ? error.message : 'live reconciliation transport failed';
          throw error;
        }
      },
      logout: async () => {
        calls.push('logout');
        throw new Error('raw-cleanup-diagnostic');
      },
      clearCookies: async () => {
        calls.push('cookies');
      },
      clearBrowserState: async () => {
        calls.push('browser-state');
      }
    });

    let watchdogTimer: ReturnType<typeof setTimeout> | undefined;
    try {
      const settledPromise = Promise.race([
        attempt.then(() => 'attempt' as const),
        new Promise<'watchdog'>((resolve) => {
          watchdogTimer = setTimeout(() => resolve('watchdog'), 50);
        })
      ]);
      for (let count = 0; count < 10; count += 1) await Promise.resolve();
      await vi.advanceTimersByTimeAsync(50);
      const settled = await settledPromise;
      if (watchdogTimer !== undefined) clearTimeout(watchdogTimer);
      expect(settled).toBe('attempt');
      const result = await attempt;

      expect(operationError).toBe('live reconciliation response exceeded its bound');
      expect(operationError).not.toContain('raw-cancel-diagnostic');
      expect(result).toMatchObject({
        operationFailed: true,
        cleanupFailed: true,
        loginRequestMayHaveIssuedSession: true,
        logoutAttempted: true,
        cookiesCleanupAttempted: true,
        browserStateCleanupAttempted: true
      });
      expect(calls).toEqual(['logout', 'cookies', 'browser-state']);
      expect(routes).toEqual(['/auth/password-login']);
      expect(evidence).toEqual({
        readCount: 2,
        cancelCount: 1,
        abortCount: 1,
        activeAbortListeners: 0
      });
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      if (watchdogTimer !== undefined) clearTimeout(watchdogTimer);
      globalThis.fetch = previousFetch;
      vi.clearAllTimers();
      vi.useRealTimers();
    }
  });
});
