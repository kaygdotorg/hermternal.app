import { expect, test } from './live-test-fixtures';
import { captureLiveChatScreenshotIfEnabled } from './live-screenshot-capture.mjs';
import {
  LIVE_PROOF_ASSISTANT_MARKER,
  LIVE_PROOF_PROMPT,
  createLiveProofLedger,
  matchLiveProofHistory,
  matchLiveProofLedger
} from './live-proof-ledger.mjs';

const password = process.env.HERMES_TEST_PASSWORD;
const username = process.env.HERMES_TEST_USERNAME ?? 'hermternal-test';

test.skip(!password, 'HERMES_TEST_PASSWORD is required for the authorized disposable lane.');

test('browser UI reaches official Hermes, reconciles exact history, and logs out', async ({ page, context }) => {
  const ledger = createLiveProofLedger();
  const controlRequests = new Map<string, 'session.create' | 'session.resume'>();
  let expectedStoredSessionId: string | undefined;
  let promptRequestId: string | undefined;
  let promptSessionId: string | undefined;
  let websocketUpgradeCount = 0;
  let websocketQueryIsTicketOnly = false;
  let websocketCloseCount = 0;
  let historyMatched = false;
  let latestHistoryProjection = Promise.resolve();

  // Playwright exposes frames but not a browser WebSocket close operation. Track
  // only the live proof sockets in the page realm so teardown can close the same
  // proof connection before the shared-context logout request.
  await page.addInitScript(() => {
    const sockets = new Set<WebSocket>();
    const nativeWebSocket = window.WebSocket;
    const trackedWebSocket = new Proxy(nativeWebSocket, {
      construct(target, argumentsList, newTarget) {
        const socket = Reflect.construct(target, argumentsList, newTarget) as WebSocket;
        sockets.add(socket);
        socket.addEventListener('close', () => sockets.delete(socket), { once: true });
        return socket;
      }
    });
    Object.defineProperty(window, 'WebSocket', {
      configurable: true,
      writable: true,
      value: trackedWebSocket
    });
    Object.defineProperty(window, '__hermternalCloseLiveProofSockets', {
      configurable: true,
      value: () => {
        for (const socket of sockets) socket.close(1000, 'live proof complete');
        sockets.clear();
      }
    });
  });

  page.on('request', (request) => {
    const route = trackedRoute(request.url());
    if (!route) return;
    ledger.recordHttpRequest({ method: request.method(), route });
  });

  page.on('response', (response) => {
    const request = response.request();
    const route = trackedRoute(request.url());
    if (!route) return;
    ledger.recordHttpResponse({ method: request.method(), route, status: response.status() });
    if (promptRequestId && request.method() === 'GET' && route.endsWith('/messages')) {
      const responseSessionId = expectedStoredSessionId;
      latestHistoryProjection = projectHistoryResponse(
        response,
        responseSessionId,
        ledger,
        (matched) => {
          historyMatched = matched;
        }
      );
    }
  });

  page.on('websocket', (socket) => {
    const url = new URL(socket.url());
    websocketUpgradeCount += 1;
    websocketQueryIsTicketOnly =
      url.pathname === '/api/ws' &&
      [...url.searchParams.keys()].length === 1 &&
      url.searchParams.has('ticket');
    ledger.recordWebSocketOpen({ route: url.pathname, ticketOnly: websocketQueryIsTicketOnly });
    socket.on('close', () => {
      websocketCloseCount += 1;
    });
    socket.on('framesent', ({ payload }) => {
      const envelope = parseFrame(payload);
      if (!envelope || typeof envelope.method !== 'string') return;
      const requestId = stringValue(envelope.id);
      const params = isRecord(envelope.params) ? envelope.params : undefined;
      const sessionId = stringValue(params?.session_id);
      ledger.recordWebSocketSent({
        method: envelope.method,
        requestId,
        sessionId
      });

      if (envelope.method === 'session.create' || envelope.method === 'session.resume') {
        if (requestId) controlRequests.set(requestId, envelope.method);
        if (envelope.method === 'session.resume' && sessionId) {
          expectedStoredSessionId = sessionId;
          ledger.recordSessionAction({
            method: envelope.method,
            requestId,
            sessionId
          });
        }
      }

      if (envelope.method === 'prompt.submit') {
        promptRequestId = requestId;
        promptSessionId = sessionId;
        ledger.recordPrompt({
          requestId,
          sessionId,
          promptMatches: stringValue(params?.text) === LIVE_PROOF_PROMPT
        });
      }
    });
    socket.on('framereceived', ({ payload }) => {
      const envelope = parseFrame(payload);
      if (!envelope) return;

      if (typeof envelope.method === 'string') {
        if (envelope.method !== 'event' || !isRecord(envelope.params)) return;
        const params = envelope.params;
        const type = stringValue(params.type);
        if (!type) return;
        const payloadValue = params.payload;
        const payloadRecord = isRecord(payloadValue) ? payloadValue : undefined;
        const sessionId =
          stringValue(params.session_id) ??
          stringValue(params.sessionId) ??
          stringValue(payloadRecord?.session_id) ??
          stringValue(payloadRecord?.sessionId);
        const requestId =
          stringValue(params.request_id) ??
          stringValue(params.requestId) ??
          ((type === 'message.delta' || type === 'message.complete' || type === 'error')
            ? promptRequestId
            : undefined);
        ledger.recordWebSocketReceived({ event: type, requestId, sessionId });

        if (type === 'gateway.ready') {
          ledger.recordGatewayReady({ sessionId });
        } else if (type === 'message.delta') {
          ledger.recordDelta({
            requestId,
            sessionId: sessionId ?? promptSessionId
          });
        } else if (type === 'message.complete') {
          const status =
            stringValue(payloadRecord?.status) ??
            stringValue(payloadRecord?.outcome) ??
            'unknown';
          ledger.recordCompletion({
            requestId,
            sessionId: sessionId ?? promptSessionId,
            status,
            markerMatches: containsText(payloadValue, LIVE_PROOF_ASSISTANT_MARKER)
          });
        }
        return;
      }

      const responseId = stringValue(envelope.id);
      if (!responseId) return;
      ledger.recordWebSocketReceived({ event: 'response', requestId: responseId });
      const controlMethod = controlRequests.get(responseId);
      if (controlMethod === 'session.create' && isRecord(envelope.result)) {
        const sessionId = stringValue(envelope.result.session_id);
        const storedSessionId = stringValue(envelope.result.stored_session_id);
        expectedStoredSessionId = storedSessionId;
        ledger.recordSessionAction({
          method: controlMethod,
          requestId: responseId,
          sessionId,
          storedSessionId
        });
      }
      controlRequests.delete(responseId);
    });
  });

  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Username & Password' })).toBeVisible();
  await page.getByRole('button', { name: 'Username & Password' }).click();
  await page.getByLabel('Username').fill(username);
  await page.locator('#auth-password').fill(password!);
  await page.getByRole('form', { name: 'Hermes password sign in' }).evaluate((form) =>
    (form as HTMLFormElement).requestSubmit()
  );

  const workspace = page.getByTestId('runtime-preview');
  await expect(workspace).toBeVisible();
  await expect(workspace).toHaveAttribute('data-state', /^(empty|ready)$/);

  const hasExistingSession = (await page.locator('.session-items button').count()) > 0;
  if (!hasExistingSession) {
    // A fresh disposable instance has no durable history. New chat creates the
    // source-owned ephemeral draft; its response supplies the durable ID.
    await page.getByRole('button', { name: 'Start a new chat' }).click();
    await expect.poll(() => hasEvent(ledger, 'session.action')).toBe(true);
    await expect(workspace).toHaveAttribute('data-state', 'empty');
  } else {
    await expect.poll(() => hasEvent(ledger, 'session.action')).toBe(true);
  }

  await expect.poll(() => hasEvent(ledger, 'gateway.ready')).toBe(true);
  expect(websocketUpgradeCount).toBe(1);
  expect(websocketQueryIsTicketOnly).toBe(true);

  const initialMessageReadCount = countHttpRequests(ledger, 'GET', '/messages');
  await page.getByLabel('Message Hermes').fill(LIVE_PROOF_PROMPT);
  await page.getByRole('button', { name: 'Send message' }).click();
  await expect.poll(() => countEvents(ledger, 'prompt.submit')).toBe(1);
  await expect.poll(
    () => countEvents(ledger, 'message.delta') + countEvents(ledger, 'message.complete') + countEvents(ledger, 'error'),
    { timeout: 90_000 }
  ).toBeGreaterThan(0);
  expect(countEvents(ledger, 'error')).toBe(0);
  await expect.poll(() => countEvents(ledger, 'message.complete'), { timeout: 90_000 }).toBe(1);
  await expect(workspace).toHaveAttribute('data-state', /^(empty|ready)$/);
  await expect.poll(
    () => countHttpRequests(ledger, 'GET', '/messages'),
    { timeout: 30_000 }
  ).toBeGreaterThan(initialMessageReadCount);
  await expect.poll(() => countEvents(ledger, 'history.response'), { timeout: 30_000 }).toBeGreaterThan(0);
  await latestHistoryProjection;
  expect(historyMatched).toBe(true);

  const captureState = await workspace.getAttribute('data-state');
  if (captureState !== 'empty' && captureState !== 'ready') {
    throw new Error('live screenshot capture state was not approved');
  }
  await captureLiveChatScreenshotIfEnabled({ page, uiState: captureState });

  const eventsBeforeLogout = ledger.snapshot();
  const expectedSession = expectedStoredSessionId;
  expect(typeof expectedSession).toBe('string');
  expect(typeof promptRequestId).toBe('string');
  expect(typeof promptSessionId).toBe('string');
  const proof = matchLiveProofLedger(eventsBeforeLogout, {
    sessionId: expectedSession!,
    promptRequestId,
    promptSessionId,
    completionStatus: 'ok'
  });
  expect(proof).toEqual({
    ordered: true,
    websocketOpen: true,
    gatewayReady: true,
    serverFirstReady: true,
    sessionAction: true,
    prompt: true,
    promptAcknowledgement: true,
    delta: true,
    completion: true,
    history: true,
    historyStatusOk: true,
    messageCount: expect.any(Number),
    promptCount: 1,
    completionCount: 1
  });

  const loginSequence = findEventSequence(
    eventsBeforeLogout,
    (event) => event.kind === 'http.request' && event.method === 'POST' && event.route === '/auth/password-login'
  );
  const authenticatedSequence = findEventSequence(
    eventsBeforeLogout,
    (event) =>
      event.kind === 'http.request' &&
      event.method === 'GET' &&
      event.route === '/api/auth/me' &&
      typeof loginSequence === 'number' &&
      typeof event.sequence === 'number' &&
      event.sequence > loginSequence
  );
  const ticketSequence = findEventSequence(
    eventsBeforeLogout,
    (event) =>
      event.kind === 'http.request' &&
      event.method === 'POST' &&
      event.route === '/api/auth/ws-ticket' &&
      typeof authenticatedSequence === 'number' &&
      typeof event.sequence === 'number' &&
      event.sequence > authenticatedSequence
  );
  const socketSequence = findEventSequence(
    eventsBeforeLogout,
    (event) =>
      event.kind === 'ws.open' &&
      typeof ticketSequence === 'number' &&
      typeof event.sequence === 'number' &&
      event.sequence > ticketSequence
  );
  const readySequence = findEventSequence(
    eventsBeforeLogout,
    (event) =>
      event.kind === 'gateway.ready' &&
      typeof socketSequence === 'number' &&
      typeof event.sequence === 'number' &&
      event.sequence > socketSequence
  );
  expect(loginSequence).toBeDefined();
  expect(authenticatedSequence).toBeDefined();
  expect(ticketSequence).toBeDefined();
  expect(socketSequence).toBeDefined();
  expect(readySequence).toBeDefined();

  const proofOrigin = new URL(page.url()).origin;
  await page.evaluate(() => {
    const closeSockets = (window as Window & {
      __hermternalCloseLiveProofSockets?: () => void;
    }).__hermternalCloseLiveProofSockets;
    closeSockets?.();
  });
  await expect.poll(() => websocketCloseCount).toBe(1);
  await page.close();

  const authenticatedIdentityResponse = await context.request.get(`${proofOrigin}/api/auth/me`, {
    maxRedirects: 0,
    failOnStatusCode: false
  });
  ledger.recordHttpRequest({ method: 'GET', route: '/api/auth/me' });
  ledger.recordHttpResponse({
    method: 'GET',
    route: '/api/auth/me',
    status: authenticatedIdentityResponse.status()
  });
  expect(authenticatedIdentityResponse.status()).toBe(200);
  expect(await authenticatedIdentityShape(authenticatedIdentityResponse)).toBe(true);

  const cookiesBeforeLogout = await context.cookies(proofOrigin);
  expect(cookiesBeforeLogout.length).toBeGreaterThan(0);
  ledger.recordHttpRequest({ method: 'POST', route: '/auth/logout' });
  const logoutResponse = await context.request.post(`${proofOrigin}/auth/logout`, {
    maxRedirects: 0,
    failOnStatusCode: false,
    headers: { accept: 'text/html' }
  });
  ledger.recordHttpResponse({ method: 'POST', route: '/auth/logout', status: logoutResponse.status() });
  expect(logoutResponse.status()).toBe(302);
  expect(logoutResponse.headers().location).toBe('/login');

  ledger.recordHttpRequest({ method: 'GET', route: '/api/auth/me' });
  const loggedOutIdentityResponse = await context.request.get(`${proofOrigin}/api/auth/me`, {
    maxRedirects: 0,
    failOnStatusCode: false
  });
  ledger.recordHttpResponse({
    method: 'GET',
    route: '/api/auth/me',
    status: loggedOutIdentityResponse.status()
  });
  expect(loggedOutIdentityResponse.status()).toBe(401);

  const cookiesAfterLogout = await context.cookies(proofOrigin);
  const storagePage = await context.newPage();
  await storagePage.goto(`${proofOrigin}/login`, { waitUntil: 'domcontentloaded' });
  const persistentStorage = await storagePage.evaluate(async () => inspectPersistentBrowserState());
  await storagePage.close();
  const cookieJarCleared = cookiesBeforeLogout.length > 0 && cookiesAfterLogout.length === 0;
  const storageCleared = persistentStorage.cleared;
  ledger.recordLogout({
    status: logoutResponse.status(),
    cookieJarCleared,
    storageCleared
  });
  expect(cookieJarCleared).toBe(true);
  expect(storageCleared).toBe(true);

  const logoutEvent = ledger.snapshot().find((event) => event.kind === 'logout');
  expect(logoutEvent).toMatchObject({
    kind: 'logout',
    status: 302,
    cookieJarCleared: true,
    storageCleared: true
  });
});

/** @param {string} url */
function trackedRoute(url: string): string | undefined {
  try {
    const parsed = new URL(url);
    if (!parsed.pathname.startsWith('/api/') && !parsed.pathname.startsWith('/auth/')) return undefined;
    return parsed.pathname;
  } catch {
    return undefined;
  }
}

function parseFrame(payload: string | Buffer): Record<string, unknown> | undefined {
  try {
    const parsed: unknown = JSON.parse(typeof payload === 'string' ? payload : payload.toString('utf8'));
    return isRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 && value.length <= 256 ? value : undefined;
}

function containsText(value: unknown, marker: string, depth = 0): boolean {
  if (depth > 8) return false;
  if (typeof value === 'string') return value.includes(marker);
  if (Array.isArray(value)) {
    for (const item of value.slice(0, 128)) {
      if (containsText(item, marker, depth + 1)) return true;
    }
    return false;
  }
  if (!isRecord(value)) return false;
  let inspected = 0;
  for (const item of Object.values(value)) {
    if (inspected >= 128) break;
    inspected += 1;
    if (containsText(item, marker, depth + 1)) return true;
  }
  return false;
}

function hasEvent(ledger: ReturnType<typeof createLiveProofLedger>, kind: string): boolean {
  return countEvents(ledger, kind) > 0;
}

function countEvents(ledger: ReturnType<typeof createLiveProofLedger>, kind: string): number {
  return ledger.snapshot().filter((event) => event.kind === kind).length;
}

function countHttpRequests(
  ledger: ReturnType<typeof createLiveProofLedger>,
  method: string,
  routeSuffix: string
): number {
  return ledger.snapshot().filter((event) =>
    event.kind === 'http.request' &&
    event.method === method &&
    typeof event.route === 'string' &&
    (routeSuffix === '/messages' ? event.route.endsWith(routeSuffix) : event.route === routeSuffix)
  ).length;
}

function findEventSequence(
  events: Array<Record<string, unknown>>,
  predicate: (event: Record<string, unknown>) => boolean
): number | undefined {
  return events.find((event) => predicate(event))?.sequence as number | undefined;
}

async function projectHistoryResponse(
  response: import('@playwright/test').Response,
  expectedSessionId: string | undefined,
  ledger: ReturnType<typeof createLiveProofLedger>,
  onMatched: (matched: boolean) => void
): Promise<void> {
  const status = response.status();
  try {
    const body: unknown = await response.json();
    const match = expectedSessionId
      ? matchLiveProofHistory(body, {
          sessionId: expectedSessionId,
          prompt: LIVE_PROOF_PROMPT,
          assistantMarker: LIVE_PROOF_ASSISTANT_MARKER
        })
      : {
          sessionMatches: false,
          promptMatches: false,
          assistantMarkerMatches: false,
          messageCount: 0,
          matched: false
        };
    ledger.recordHistoryResponse({
      status,
      sessionId: expectedSessionId,
      promptMatches: match.promptMatches,
      assistantMarkerMatches: match.assistantMarkerMatches,
      messageCount: match.messageCount
    });
    onMatched(match.matched);
  } catch {
    ledger.recordHistoryResponse({
      status,
      sessionId: undefined,
      promptMatches: false,
      assistantMarkerMatches: false,
      messageCount: 0
    });
    onMatched(false);
  }
}

async function authenticatedIdentityShape(response: import('@playwright/test').APIResponse): Promise<boolean> {
  try {
    const value: unknown = await response.json();
    if (!isRecord(value)) return false;
    const keys = ['display_name', 'email', 'expires_at', 'org_id', 'provider', 'user_id'];
    const boundedText = (candidate: unknown): candidate is string =>
      typeof candidate === 'string' && candidate.length <= 512;
    const stableText = (candidate: unknown): candidate is string =>
      boundedText(candidate) && candidate.length > 0;
    return (
      JSON.stringify(Object.keys(value).sort()) === JSON.stringify(keys) &&
      stableText(value.user_id) &&
      boundedText(value.email) &&
      boundedText(value.display_name) &&
      boundedText(value.org_id) &&
      stableText(value.provider) &&
      typeof value.expires_at === 'number' &&
      Number.isInteger(value.expires_at) &&
      value.expires_at >= 0 &&
      value.expires_at <= 4_294_967_295
    );
  } catch {
    return false;
  }
}

async function inspectPersistentBrowserState(): Promise<{
  localStorageCleared: boolean;
  sessionStorageCleared: boolean;
  indexedDbCleared: boolean;
  cacheStorageCleared: boolean;
  serviceWorkerCacheCleared: boolean;
  cleared: boolean;
}> {
  const countStorage = (storage: Storage): number => {
    let count = 0;
    for (let index = 0; index < storage.length; index += 1) {
      count += 1;
      if (count > 1024) return count;
    }
    return count;
  };
  const localStorageEntries = countStorage(localStorage);
  const sessionStorageEntries = countStorage(sessionStorage);
  const databases =
    typeof indexedDB.databases === 'function' ? await indexedDB.databases() : undefined;
  const cacheNames = typeof caches?.keys === 'function' ? await caches.keys() : undefined;
  const localStorageCleared = localStorageEntries === 0;
  const sessionStorageCleared = sessionStorageEntries === 0;
  const indexedDbCleared = databases !== undefined && databases.length === 0;
  const cacheStorageCleared = cacheNames !== undefined && cacheNames.length === 0;
  // Cache Storage is shared by window and service-worker clients, so an empty
  // cache namespace proves the service-worker cache boundary is empty too.
  const serviceWorkerCacheCleared = cacheStorageCleared;
  return {
    localStorageCleared,
    sessionStorageCleared,
    indexedDbCleared,
    cacheStorageCleared,
    serviceWorkerCacheCleared,
    cleared:
      localStorageCleared &&
      sessionStorageCleared &&
      indexedDbCleared &&
      cacheStorageCleared &&
      serviceWorkerCacheCleared
  };
}
