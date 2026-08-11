import { test as base } from './live-test-fixtures';
import {
  LIVE_RECONCILIATION_ENV,
  formatLiveReconciliationResult
} from './live-reconciliation.mjs';
import { isLiveReconciliationEnabled } from './live-playwright-config.mjs';
import { runLiveReconciliationAttempt } from './live-reconciliation-auth.mjs';
import { requestLiveReconciliationProjection } from './live-reconciliation-transport.mjs';
import { setLiveProofStatus } from './live-proof-status.mjs';

const test = base;
const password = process.env.HERMES_TEST_PASSWORD;
const username = process.env.HERMES_TEST_USERNAME ?? 'hermternal-test';
const reconciliationOnly = isLiveReconciliationEnabled();

test.skip(
  !reconciliationOnly,
  `${LIVE_RECONCILIATION_ENV}=1 is required; this mode is opt-in and never submits`
);
test.skip(!password, 'HERMES_TEST_PASSWORD is required for the authorized disposable lane.');

test('read-only reconciliation checks the current account without submitting', async ({ context, page }, testInfo) => {
  setLiveProofStatus(testInfo, { phase: 'not-started', delivery: 'not-submitted' });
  const configuredBaseURL = testInfo.project.use.baseURL;
  const baseURL =
    typeof configuredBaseURL === 'string' && /^http:\/\/127\.0\.0\.1:\d+\/$/u.test(configuredBaseURL)
      ? configuredBaseURL
      : undefined;
  if (!baseURL) throw new Error('live reconciliation origin is not approved');
  const passwordValue = password;
  if (!passwordValue) throw new Error('live reconciliation password is unavailable');
  await page.goto(new URL('/login', baseURL).href, { waitUntil: 'domcontentloaded' });

  let result = {
    promptMatches: 'zero',
    completedPairs: 'zero',
    status: 'reconciliation-failed-uncertain'
  };
  const attempt = await runLiveReconciliationAttempt({
    operation: async (markLoginRequest) => {
      const providerProjection = await requestLiveReconciliationProjection(page, {
        baseURL,
        kind: 'providers'
      });
      const provider = providerProjection.provider;
      // Mark the request before transport starts: a malformed, oversized, or
      // unreadable login response may still have issued the session cookie.
      markLoginRequest();
      await requestLiveReconciliationProjection(page, {
        baseURL,
        kind: 'login',
        provider,
        username,
        password: passwordValue
      });
      await requestLiveReconciliationProjection(page, { baseURL, kind: 'auth-me' });
      setLiveProofStatus(testInfo, { phase: 'authenticated', delivery: 'not-submitted' });

      setLiveProofStatus(testInfo, { phase: 'ready-no-submit', delivery: 'not-submitted' });
      result = await requestLiveReconciliationProjection(page, {
        baseURL,
        kind: 'history'
      });
      setLiveProofStatus(testInfo, { phase: 'history-reconciled', delivery: 'uncertain' });
    },
    logout: () => logoutAndVerify(context, baseURL),
    clearCookies: async () => {
      await context.clearCookies();
      if ((await context.cookies(baseURL)).length !== 0) throw new Error('cookie cleanup failed');
    },
    clearBrowserState: () => clearBrowserState(context, baseURL)
  });
  const operationFailed = attempt.operationFailed;
  const cleanupFailed = attempt.cleanupFailed;

  if (operationFailed || cleanupFailed) {
    result = {
      promptMatches: 'zero',
      completedPairs: 'zero',
      status: 'reconciliation-failed-uncertain'
    };
    setLiveProofStatus(testInfo, { phase: 'uncertain', delivery: 'uncertain' });
  }
  console.log(formatLiveReconciliationResult(result));
  if (operationFailed || cleanupFailed) throw new Error('live reconciliation failed closed');
});

async function logoutAndVerify(
  context: import('@playwright/test').BrowserContext,
  baseURL: string
): Promise<void> {
  const response = await context.request.post(new URL('/auth/logout', baseURL).href, {
    headers: { accept: 'application/json' },
    maxRedirects: 0,
    failOnStatusCode: false
  });
  if (response.status() !== 302 || response.headers().location !== '/login') {
    throw new Error('live reconciliation logout was not verified');
  }
  const identity = await context.request.get(new URL('/api/auth/me', baseURL).href, {
    headers: { accept: 'application/json' },
    maxRedirects: 0,
    failOnStatusCode: false
  });
  if (identity.status() !== 401) throw new Error('live reconciliation logout identity remained active');
}

async function clearBrowserState(
  context: import('@playwright/test').BrowserContext,
  baseURL: string
): Promise<void> {
  const page = await context.newPage();
  try {
    await page.goto(new URL('/login', baseURL).href, { waitUntil: 'domcontentloaded' });
    const cleared = await page.evaluate(async () => {
      try {
        localStorage.clear();
        sessionStorage.clear();
        const databaseList = typeof indexedDB.databases === 'function' ? await indexedDB.databases() : undefined;
        if (!databaseList || databaseList.length > 64) return false;
        for (const database of databaseList) {
          if (!database || typeof database.name !== 'string' || database.name.length > 256) return false;
          await new Promise<void>((resolve, reject) => {
            const request = indexedDB.deleteDatabase(database.name!);
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
            request.onblocked = () => reject(new Error('database cleanup blocked'));
          });
        }
        if ((await indexedDB.databases()).length !== 0) return false;
        const cacheNames = await caches.keys();
        if (cacheNames.length > 64) return false;
        for (const name of cacheNames) {
          if (typeof name !== 'string' || name.length > 256 || !(await caches.delete(name))) return false;
        }
        if ((await caches.keys()).length !== 0) return false;
        const registrations = await navigator.serviceWorker.getRegistrations();
        if (registrations.length > 64) return false;
        for (const registration of registrations) {
          if (!(await registration.unregister())) return false;
        }
        const localStorageCleared = localStorage.length === 0;
        const sessionStorageCleared = sessionStorage.length === 0;
        const serviceWorkersCleared = (await navigator.serviceWorker.getRegistrations()).length === 0;
        return localStorageCleared && sessionStorageCleared && serviceWorkersCleared;
      } catch {
        return false;
      }
    });
    if (cleared !== true) throw new Error('live reconciliation browser cleanup was incomplete');
  } finally {
    await page.close();
  }
}
