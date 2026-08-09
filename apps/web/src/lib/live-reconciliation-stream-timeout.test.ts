import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { describe, expect, it, vi } from 'vitest';
import { runLiveReconciliationAttempt } from '../../tests/live/live-reconciliation-auth.mjs';
import {
  LIVE_RECONCILIATION_RESPONSE_TIMEOUT_MS,
  requestLiveReconciliationProjection
} from '../../tests/live/live-reconciliation-transport.mjs';
import {
  createLivePlaywrightConfig,
  getLivePlaywrightPaths
} from '../../tests/live/live-playwright-config.mjs';

type StreamMode = 'fetch' | 'reader';

type TransportEvidence = {
  mode: StreamMode;
  routes: string[];
  readCount: number;
  cancelCount: number;
  abortCount: number;
  activeAbortListeners: number;
  restore: () => void;
};

type PageLike = {
  evaluate: (
    callback: (value: unknown) => Promise<unknown>,
    value: unknown
  ) => Promise<unknown>;
};

function pageWithNonCooperativeTransport(evidence: TransportEvidence): PageLike {
  let restored = false;
  const pendingRead = new Promise<never>(() => undefined);
  const restore = () => {
    if (restored) return;
    restored = true;
    globalThis.fetch = originalFetch;
  };
  evidence.restore = restore;
  const originalFetch = globalThis.fetch;

  return {
    evaluate: async (callback, value) => {
      const previousFetch = globalThis.fetch;
      globalThis.fetch = (async (input, init) => {
        evidence.routes.push(new URL(String(input)).pathname);
        const signal = (init as RequestInit | undefined)?.signal;
        if (!signal) throw new Error('raw-test-fetch-signal-missing');
        const onAbort = () => {
          evidence.abortCount += 1;
          evidence.activeAbortListeners = Math.max(0, evidence.activeAbortListeners - 1);
        };
        signal.addEventListener('abort', onAbort, { once: true });
        evidence.activeAbortListeners += 1;

        if (evidence.mode === 'fetch') {
          // This promise intentionally ignores AbortSignal; fetch must still settle
          // through the internal deadline race instead of trusting browser behavior.
          return new Promise<never>(() => undefined);
        }

        const reader = {
          read: () => {
            evidence.readCount += 1;
            // This reader intentionally ignores abort and cancel, so the deadline
            // race must settle without waiting for either hostile promise.
            return pendingRead;
          },
          cancel: async () => {
            evidence.cancelCount += 1;
          }
        };
        return {
          status: 200,
          body: { getReader: () => reader },
          headers: {
            get: (name: string) => (name === 'content-type' ? 'application/json' : null)
          }
        } as unknown as Response;
      }) as typeof fetch;
      try {
        return await callback(value);
      } finally {
        globalThis.fetch = previousFetch;
      }
    }
  };
}

function newEvidence(mode: StreamMode): TransportEvidence {
  return {
    mode,
    routes: [],
    readCount: 0,
    cancelCount: 0,
    abortCount: 0,
    activeAbortListeners: 0,
    restore: () => undefined
  };
}

async function runDeadlineCase(mode: StreamMode): Promise<{
  evidence: TransportEvidence;
  operationError: string | undefined;
  cleanupCalls: string[];
  result: Awaited<ReturnType<typeof runLiveReconciliationAttempt>>;
  timerCount: number;
}> {
  const evidence = newEvidence(mode);
  const cleanupCalls: string[] = [];
  let operationError: string | undefined;
  vi.useFakeTimers();
  const attempt = runLiveReconciliationAttempt({
    operation: async (markLoginRequest) => {
      markLoginRequest();
      try {
        await requestLiveReconciliationProjection(pageWithNonCooperativeTransport(evidence), {
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
      cleanupCalls.push('logout');
    },
    clearCookies: async () => {
      cleanupCalls.push('cookies');
    },
    clearBrowserState: async () => {
      cleanupCalls.push('browser-state');
    }
  });

  try {
    // Let page-context fetch/read start before advancing the single deadline.
    const watchdog = new Promise<'watchdog'>((resolveWatchdog) => {
      setTimeout(
        () => resolveWatchdog('watchdog'),
        LIVE_RECONCILIATION_RESPONSE_TIMEOUT_MS + 1
      );
    });
    const settledPromise = Promise.race([
      attempt.then(() => 'attempt' as const),
      watchdog
    ]);
    // Let page-context fetch/read start before advancing the single deadline.
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(LIVE_RECONCILIATION_RESPONSE_TIMEOUT_MS + 1);
    for (let index = 0; index < 10; index += 1) await Promise.resolve();
    const settled = await settledPromise;
    expect(settled).toBe('attempt');
    const result = await attempt;
    return {
      evidence,
      operationError,
      cleanupCalls,
      result,
      timerCount: vi.getTimerCount()
    };
  } finally {
    evidence.restore();
    vi.useRealTimers();
  }
}

describe('live reconciliation stream deadline', () => {
  it('guards the actual reconciliation integration and fixed safe timeout contract', async () => {
    const appRoot = resolve(process.cwd());
    const paths = getLivePlaywrightPaths(
      pathToFileURL(resolve(appRoot, 'playwright.live.config.ts')).href
    );
    const integrationSpecSource = await readFile(
      join(paths.liveTestsDirectory, 'reconcile-live-proof.spec.ts'),
      'utf8'
    );
    const integrationConfigSource = await readFile(paths.configFile, 'utf8');

    // These are the production integration entrypoints, not correction-only test
    // helpers. The guard fails if the live spec bypasses bounded transport or
    // independent cleanup.
    expect(integrationSpecSource).toContain('requestLiveReconciliationProjection');
    expect(integrationSpecSource).toContain('runLiveReconciliationAttempt');
    expect(integrationSpecSource).toContain("kind: 'login'");
    expect(integrationSpecSource).toContain('logout: () => logoutAndVerify(context, baseURL)');
    expect(integrationSpecSource).toContain('clearCookies: async () =>');
    expect(integrationSpecSource).toContain('clearBrowserState: () => clearBrowserState(context, baseURL)');
    expect(integrationConfigSource).toContain('createLivePlaywrightConfig');

    const config = createLivePlaywrightConfig({
      paths,
      port: 4187,
      outputDirectory: join(tmpdir(), 'hermternal-reconciliation-stream-timeout'),
      launchOptions: { headless: true },
      desktopChrome: {},
      reconciliationOnly: true
    });
    expect(config.testMatch).toBe('**/reconcile-live-proof.spec.ts');
    expect(config.testIgnore).toEqual([
      '**/official-hermes.spec.ts',
      '**/*capture*.spec.ts'
    ]);
  });

  it('settles a fetch promise that ignores abort and still performs cleanup', async () => {
    const result = await runDeadlineCase('fetch');
    expect(result).toMatchObject({
      operationError: 'live reconciliation transport timed out',
      cleanupCalls: ['logout', 'cookies', 'browser-state'],
      result: {
        operationFailed: true,
        cleanupFailed: false,
        loginRequestMayHaveIssuedSession: true,
        logoutAttempted: true,
        cookiesCleanupAttempted: true,
        browserStateCleanupAttempted: true
      },
      timerCount: 0
    });
    expect(result.operationError).not.toContain('raw-test-fetch-signal-missing');
    expect(result.evidence.routes).toEqual(['/auth/password-login']);
    expect(result.evidence.abortCount).toBe(1);
    expect(result.evidence.activeAbortListeners).toBe(0);
    expect(result.evidence.cancelCount).toBe(0);
    expect(result.evidence.readCount).toBe(0);
  });

  it('settles a reader that ignores abort and cancel with fixed cleanup', async () => {
    const result = await runDeadlineCase('reader');
    expect(result).toMatchObject({
      operationError: 'live reconciliation transport timed out',
      cleanupCalls: ['logout', 'cookies', 'browser-state'],
      result: {
        operationFailed: true,
        cleanupFailed: false,
        loginRequestMayHaveIssuedSession: true,
        logoutAttempted: true,
        cookiesCleanupAttempted: true,
        browserStateCleanupAttempted: true
      },
      timerCount: 0
    });
    expect(result.operationError).not.toContain('raw-test-fetch-signal-missing');
    expect(result.evidence.routes).toEqual(['/auth/password-login']);
    expect(result.evidence.abortCount).toBe(1);
    expect(result.evidence.activeAbortListeners).toBe(0);
    expect(result.evidence.cancelCount).toBe(1);
    expect(result.evidence.readCount).toBe(1);
  });
});
