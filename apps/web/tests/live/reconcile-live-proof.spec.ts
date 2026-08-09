import { test as base } from './live-test-fixtures';
import { LIVE_PROOF_ASSISTANT_MARKER, LIVE_PROOF_PROMPT } from './live-proof-ledger.mjs';
import {
  LIVE_RECONCILIATION_ENV,
  formatLiveReconciliationResult,
  parseReconciliationSessionList,
  parseReconciliationSessionMessages,
  reconcileLiveHistory
} from './live-reconciliation.mjs';
import { setLiveProofStatus } from './live-proof-status.mjs';

const test = base;
const password = process.env.HERMES_TEST_PASSWORD;
const username = process.env.HERMES_TEST_USERNAME ?? 'hermternal-test';
const MAX_RESPONSE_BYTES = 256 * 1024;
const MAX_PROVIDER_COUNT = 32;
const SAFE_PROVIDER_NAME = /^[a-z0-9][a-z0-9._-]{0,95}$/u;

test.skip(
  process.env[LIVE_RECONCILIATION_ENV] !== '1',
  'HERMTERNAL_LIVE_RECONCILIATION=1 is required; this mode is opt-in and never submits'
);
test.skip(!password, 'HERMES_TEST_PASSWORD is required for the authorized disposable lane.');

test('read-only reconciliation checks the current account without submitting', async ({ context }, testInfo) => {
  setLiveProofStatus(testInfo, { phase: 'not-started', delivery: 'not-submitted' });
  const configuredBaseURL = testInfo.project.use.baseURL;
  const baseURL =
    typeof configuredBaseURL === 'string' && /^http:\/\/127\.0\.0\.1:\d+\/$/u.test(configuredBaseURL)
      ? configuredBaseURL
      : undefined;
  if (!baseURL) throw new Error('live reconciliation origin is not approved');
  const passwordValue = password;
  if (!passwordValue) throw new Error('live reconciliation password is unavailable');

  let authenticated = false;
  let result = {
    promptMatches: 'zero',
    completedPairs: 'zero',
    status: 'ambiguous'
  };
  let operationFailed = false;
  let cleanupFailed = false;

  try {
    const provider = parsePasswordProvider(await requestJson(context, baseURL, '/api/auth/providers'));
    const login = await requestJson(context, baseURL, '/auth/password-login', {
      method: 'POST',
      data: { provider, username, password: passwordValue, next: '/' }
    });
    assertPasswordLogin(login);
    await assertAuthenticated(context, baseURL);
    authenticated = true;
    setLiveProofStatus(testInfo, { phase: 'authenticated', delivery: 'not-submitted' });

    const sessions = parseReconciliationSessionList(
      await requestJson(context, baseURL, '/api/sessions?limit=100&offset=0')
    );
    setLiveProofStatus(testInfo, { phase: 'ready-no-submit', delivery: 'not-submitted' });
    result = await reconcileLiveHistory({
      sessions,
      getMessages: async (sessionId, messageCount) =>
        parseReconciliationSessionMessages(
          await requestJson(
            context,
            baseURL,
            `/api/sessions/${encodeURIComponent(sessionId)}/messages?limit=500&offset=0`
          ),
          sessionId,
          messageCount
        )
    });
    setLiveProofStatus(testInfo, { phase: 'history-reconciled', delivery: 'uncertain' });
  } catch {
    operationFailed = true;
  } finally {
    try {
      if (authenticated) await logoutAndVerify(context, baseURL);
      await context.clearCookies();
      if ((await context.cookies(baseURL)).length !== 0) throw new Error('cookie cleanup failed');
      await clearBrowserState(context, baseURL);
    } catch {
      cleanupFailed = true;
    }
  }

  if (operationFailed || cleanupFailed) {
    result = { promptMatches: 'zero', completedPairs: 'zero', status: 'ambiguous' };
    setLiveProofStatus(testInfo, { phase: 'uncertain', delivery: 'uncertain' });
  }
  console.log(formatLiveReconciliationResult(result));
  if (operationFailed || cleanupFailed) throw new Error('live reconciliation failed closed');
});

async function requestJson(
  context: import('@playwright/test').BrowserContext,
  baseURL: string,
  path: string,
  options: {
    method?: 'GET' | 'POST';
    data?: Record<string, string>;
  } = {}
): Promise<unknown> {
  const url = new URL(path, baseURL).href;
  const response = options.method === 'POST'
    ? await context.request.post(url, {
        data: options.data,
        headers: { accept: 'application/json', 'content-type': 'application/json' },
        maxRedirects: 0,
        failOnStatusCode: false
      })
    : await context.request.get(url, {
        headers: { accept: 'application/json' },
        maxRedirects: 0,
        failOnStatusCode: false
      });
  if (response.status() !== 200 || response.headers()['content-type']?.toLowerCase().includes('application/json') !== true) {
    throw new Error('live reconciliation response was not approved');
  }
  const body = await response.body();
  if (body.byteLength > MAX_RESPONSE_BYTES) throw new Error('live reconciliation response exceeded its bound');
  try {
    return JSON.parse(body.toString('utf8')) as unknown;
  } catch {
    throw new Error('live reconciliation response was malformed');
  }
}

async function assertAuthenticated(
  context: import('@playwright/test').BrowserContext,
  baseURL: string
): Promise<void> {
  const identity = await requestJson(context, baseURL, '/api/auth/me');
  if (identity === null || typeof identity !== 'object' || Array.isArray(identity)) {
    throw new Error('live reconciliation authentication was not verified');
  }
  const record = identity as Record<string, unknown>;
  const expiresAt = record.expires_at;
  if (
    !isBoundedNonEmptyString(record.user_id, 512) ||
    typeof record.provider !== 'string' ||
    record.provider.length === 0 ||
    record.provider.length > 512 ||
    typeof expiresAt !== 'number' ||
    !Number.isInteger(expiresAt) ||
    expiresAt < 0 ||
    expiresAt > 4_294_967_295
  ) {
    throw new Error('live reconciliation authentication was not verified');
  }
}

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

function parsePasswordProvider(value: unknown): string {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('live reconciliation provider response was invalid');
  }
  const record = value as Record<string, unknown>;
  const providers = record.providers;
  if (!Array.isArray(providers) || providers.length === 0 || providers.length > MAX_PROVIDER_COUNT) {
    throw new Error('live reconciliation provider response was invalid');
  }
  const passwordProviders = providers.filter((provider) => {
    if (provider === null || typeof provider !== 'object' || Array.isArray(provider)) return false;
    const record = provider as Record<string, unknown>;
    return (
      typeof record.name === 'string' &&
      SAFE_PROVIDER_NAME.test(record.name) &&
      typeof record.display_name === 'string' &&
      record.display_name.length <= 512 &&
      record.supports_password === true
    );
  });
  if (passwordProviders.length !== 1) throw new Error('live reconciliation password provider is ambiguous');
  const provider = passwordProviders[0] as Record<string, unknown>;
  return provider.name as string;
}

function assertPasswordLogin(value: unknown): void {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('live reconciliation login was not verified');
  }
  const record = value as Record<string, unknown>;
  if (
    record.ok !== true ||
    record.next !== '/' ||
    Object.keys(record).some((key) => key !== 'ok' && key !== 'next')
  ) {
    throw new Error('live reconciliation login was not verified');
  }
}

function isBoundedNonEmptyString(value: unknown, maxLength: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= maxLength;
}
