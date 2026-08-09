import { describe, expect, it } from 'vitest';
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
});
