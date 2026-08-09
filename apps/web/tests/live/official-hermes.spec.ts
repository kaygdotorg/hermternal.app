import { expect, test } from './live-test-fixtures';
import { captureLiveChatScreenshotIfEnabled } from './live-screenshot-capture.mjs';
import {
  LIVE_PROOF_ASSISTANT_MARKER,
  LIVE_PROOF_PROMPT,
  createLiveProofLedger,
  normalizeLiveProofRoute,
  matchLiveProofHistory,
  matchLiveProofLedger
} from './live-proof-ledger.mjs';
import { setLiveProofStatus } from './live-proof-status.mjs';
import { isLiveReconciliationEnabled } from './live-playwright-config.mjs';

const password = process.env.HERMES_TEST_PASSWORD;
const username = process.env.HERMES_TEST_USERNAME ?? 'hermternal-test';
const reconciliationOnly = isLiveReconciliationEnabled();

test.skip(
  reconciliationOnly,
  'official Hermes prompt lane is disabled during read-only reconciliation'
);
test.skip(!password, 'HERMES_TEST_PASSWORD is required for the authorized disposable lane.');

test('browser UI reaches official Hermes, reconciles exact history, and logs out', async ({ page, context }, testInfo) => {
  setLiveProofStatus(testInfo, { phase: 'not-started', delivery: 'not-submitted' });
  const ledger = createLiveProofLedger();
  const controlRequests = new Map<string, 'session.create' | 'session.resume'>();
  let expectedStoredSessionId: string | undefined;
  let promptRequestId: string | undefined;
  let promptSessionId: string | undefined;
  let websocketUpgradeCount = 0;
  let websocketQueryIsTicketOnly = false;
  let websocketCloseCount = 0;

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
        // Hermes message events carry only the source-provided session_id in
        // their event envelope. Never infer a session or fabricate a request
        // identity from the prompt RPC; the completion contract is session-
        // correlated and one-submission only.
        const sessionId = stringValue(params.session_id);
        const requestId =
          type === 'message.delta' || type === 'message.complete' || type === 'error'
            ? undefined
            : stringValue(params.request_id) ?? stringValue(params.requestId);
        ledger.recordWebSocketReceived({ event: type, requestId, sessionId });

        if (type === 'gateway.ready') {
          ledger.recordGatewayReady();
        } else if (type === 'message.delta') {
          ledger.recordDelta({ sessionId });
        } else if (type === 'message.complete') {
          const status =
            stringValue(payloadRecord?.status) ??
            stringValue(payloadRecord?.outcome) ??
            'unknown';
          ledger.recordCompletion({
            sessionId,
            status,
            markerMatches: hasExactText(payloadValue, LIVE_PROOF_ASSISTANT_MARKER)
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
  setLiveProofStatus(testInfo, { phase: 'authenticated', delivery: 'not-submitted' });

  const hasExistingSession = (await page.locator('.session-items button').count()) > 0;
  if (!hasExistingSession) {
    // session.create persists lazily on the first prompt in the pinned Hermes
    // source, so a fresh draft cannot establish a pre-send REST fence safely.
    // Refuse before any prompt rather than weakening the causal boundary.
    setLiveProofStatus(testInfo, { phase: 'uncertain', delivery: 'uncertain' });
    throw new Error('live proof requires an existing canonical session');
  }
  await expect.poll(() => hasEvent(ledger, 'session.action')).toBe(true);

  await expect.poll(() => hasEvent(ledger, 'gateway.ready')).toBe(true);
  expect(websocketUpgradeCount).toBe(1);
  expect(websocketQueryIsTicketOnly).toBe(true);
  setLiveProofStatus(testInfo, { phase: 'ready-no-submit', delivery: 'not-submitted' });

  const canonicalSessionId = expectedStoredSessionId;
  if (!canonicalSessionId) {
    setLiveProofStatus(testInfo, { phase: 'uncertain', delivery: 'uncertain' });
    throw new Error('live proof canonical session identity was unavailable');
  }
  let preSendHistory: Awaited<ReturnType<typeof readCanonicalProofHistory>>;
  try {
    preSendHistory = await readCanonicalProofHistory(page, canonicalSessionId, ledger, {
      phase: 'pre-send'
    });
  } catch {
    setLiveProofStatus(testInfo, { phase: 'uncertain', delivery: 'uncertain' });
    throw new Error('live proof pre-send history read failed');
  }
  ledger.recordHistoryResponse({
    phase: 'pre-send',
    status: preSendHistory.status,
    sessionId: canonicalSessionId,
    historyComplete: preSendHistory.historyComplete,
    watermarkEstablished: preSendHistory.watermarkEstablished,
    prefixStable: preSendHistory.prefixStable,
    postFenceMatched: preSendHistory.postFenceMatched,
    promptMatches: preSendHistory.promptMatches,
    assistantMarkerMatches: preSendHistory.assistantMarkerMatches,
    candidateUserCount: preSendHistory.candidateUserCount,
    candidateAssistantCount: preSendHistory.candidateAssistantCount,
    messageCount: preSendHistory.messageCount,
    historyProjectionTag: preSendHistory.historyProjectionTag,
    prefixProjectionTag: preSendHistory.prefixProjectionTag
  });
  if (!preSendHistory.matched || preSendHistory.watermark === undefined) {
    setLiveProofStatus(testInfo, { phase: 'uncertain', delivery: 'uncertain' });
    throw new Error('live proof pre-send history fence was not established');
  }
  const fence = preSendHistory.watermark;
  const preHistoryProjectionTag = preSendHistory.historyProjectionTag;
  if (!preHistoryProjectionTag) {
    setLiveProofStatus(testInfo, { phase: 'uncertain', delivery: 'uncertain' });
    throw new Error('live proof pre-send history identity was unavailable');
  }

  await page.getByLabel('Message Hermes').fill(LIVE_PROOF_PROMPT);
  await page.getByRole('button', { name: 'Send message' }).click();
  setLiveProofStatus(testInfo, { phase: 'submitted', delivery: 'submitted' });
  await expect.poll(() => countEvents(ledger, 'prompt.submit')).toBe(1);
  await expect.poll(
    () => countEvents(ledger, 'message.delta') + countEvents(ledger, 'message.complete') + countEvents(ledger, 'error'),
    { timeout: 90_000 }
  ).toBeGreaterThan(0);
  expect(countEvents(ledger, 'error')).toBe(0);
  await expect.poll(() => countEvents(ledger, 'message.complete'), { timeout: 90_000 }).toBe(1);
  setLiveProofStatus(testInfo, { phase: 'completed', delivery: 'completed' });
  await expect(workspace).toHaveAttribute('data-state', /^(empty|ready)$/);

  let postCompletionHistory: Awaited<ReturnType<typeof readCanonicalProofHistory>>;
  try {
    postCompletionHistory = await readCanonicalProofHistory(page, canonicalSessionId, ledger, {
      phase: 'post-completion',
      fence,
      preHistoryProjectionTag
    });
  } catch {
    setLiveProofStatus(testInfo, { phase: 'uncertain', delivery: 'uncertain' });
    throw new Error('live proof post-completion history read failed');
  }
  ledger.recordHistoryResponse({
    phase: 'post-completion',
    status: postCompletionHistory.status,
    sessionId: canonicalSessionId,
    historyComplete: postCompletionHistory.historyComplete,
    watermarkEstablished: postCompletionHistory.watermarkEstablished,
    prefixStable: postCompletionHistory.prefixStable,
    postFenceMatched: postCompletionHistory.postFenceMatched,
    promptMatches: postCompletionHistory.promptMatches,
    assistantMarkerMatches: postCompletionHistory.assistantMarkerMatches,
    candidateUserCount: postCompletionHistory.candidateUserCount,
    candidateAssistantCount: postCompletionHistory.candidateAssistantCount,
    messageCount: postCompletionHistory.messageCount,
    historyProjectionTag: postCompletionHistory.historyProjectionTag,
    prefixProjectionTag: postCompletionHistory.prefixProjectionTag
  });
  if (!postCompletionHistory.matched) {
    setLiveProofStatus(testInfo, { phase: 'uncertain', delivery: 'uncertain' });
    throw new Error('live proof post-completion history did not match the fence');
  }
  setLiveProofStatus(testInfo, { phase: 'history-reconciled', delivery: 'completed' });

  const captureState = await workspace.getAttribute('data-state');
  if (captureState !== 'empty' && captureState !== 'ready') {
    throw new Error('live screenshot capture state was not approved');
  }

  const eventsBeforeLogout = ledger.snapshot();
  const expectedSession = expectedStoredSessionId;
  expect(typeof expectedSession).toBe('string');
  expect(typeof promptRequestId).toBe('string');
  expect(typeof promptSessionId).toBe('string');
  const proof = matchLiveProofLedger(eventsBeforeLogout, {
    sessionTag: ledger.identityTag(expectedSession),
    promptRequestTag: ledger.identityTag(promptRequestId),
    promptSessionTag: ledger.identityTag(promptSessionId),
    completionStatus: 'complete'
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
  setLiveProofStatus(testInfo, { phase: 'reconciled', delivery: 'reconciled' });
  await captureLiveChatScreenshotIfEnabled({ page, uiState: captureState, proof });

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
    return normalizeLiveProofRoute(parsed.pathname);
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

function hasExactText(value: unknown, marker: string, depth = 0): boolean {
  if (depth > 8) return false;
  if (typeof value === 'string') return value === marker;
  if (Array.isArray(value)) {
    for (const item of value.slice(0, 128)) {
      if (hasExactText(item, marker, depth + 1)) return true;
    }
    return false;
  }
  if (!isRecord(value)) return false;
  let inspected = 0;
  for (const item of Object.values(value)) {
    if (inspected >= 128) break;
    inspected += 1;
    if (hasExactText(item, marker, depth + 1)) return true;
  }
  return false;
}

function hasEvent(ledger: ReturnType<typeof createLiveProofLedger>, kind: string): boolean {
  return countEvents(ledger, kind) > 0;
}

function countEvents(ledger: ReturnType<typeof createLiveProofLedger>, kind: string): number {
  return ledger.snapshot().filter((event) => event.kind === kind).length;
}

function findEventSequence(
  events: Array<Record<string, unknown>>,
  predicate: (event: Record<string, unknown>) => boolean
): number | undefined {
  return events.find((event) => predicate(event))?.sequence as number | undefined;
}

async function readCanonicalProofHistory(
  page: import('@playwright/test').Page,
  sessionId: string,
  ledger: ReturnType<typeof createLiveProofLedger>,
  options: {
    phase: 'pre-send' | 'post-completion';
    fence?: number;
    preHistoryProjectionTag?: string;
  }
): Promise<ReturnType<typeof matchLiveProofHistory> & { status: number }> {
  const body = await page.evaluate(async (value) => {
    const maxBytes = 256 * 1024;
    const maxChunks = 4096;
    const deadline = Date.now() + 30_000;
    const controller = new AbortController();
    const abortTimer = setTimeout(() => controller.abort(), 30_000);
    try {
      const encodedSessionId = encodeURIComponent(value.sessionId);
      const response = await fetch(
        `/api/sessions/${encodedSessionId}/messages?limit=500&offset=0`,
        {
          method: 'GET',
          headers: { accept: 'application/json' },
          credentials: 'include',
          cache: 'no-store',
          redirect: 'error',
          signal: controller.signal
        }
      );
      if (
        response.status !== 200 ||
        response.headers.get('content-type')?.toLowerCase().includes('application/json') !== true
      ) {
        throw new Error('live proof history response was not approved');
      }
      const contentLength = response.headers.get('content-length');
      if (contentLength !== null) {
        if (!/^(?:0|[1-9][0-9]*)$/u.test(contentLength) || Number(contentLength) > maxBytes) {
          throw new Error('live proof history response exceeded its bound');
        }
      }
      if (!response.body) throw new Error('live proof history response was not streamable');
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let bytes = 0;
      let chunkCount = 0;
      const readChunk = async () => {
        const remaining = deadline - Date.now();
        if (remaining <= 0) throw new Error('live proof history read timed out');
        let readTimer: ReturnType<typeof setTimeout> | undefined;
        const timeout = new Promise<never>((_, reject) => {
          readTimer = setTimeout(() => reject(new Error('live proof history read timed out')), remaining);
        });
        try {
          return await Promise.race([reader.read(), timeout]);
        } finally {
          if (readTimer) clearTimeout(readTimer);
        }
      };
      try {
        while (true) {
          const next = await readChunk();
          if (next.done) break;
          if (!(next.value instanceof Uint8Array)) {
            throw new Error('live proof history response chunk was invalid');
          }
          chunkCount += 1;
          if (chunkCount > maxChunks || next.value.byteLength > maxBytes - bytes) {
            throw new Error('live proof history response exceeded its bound');
          }
          chunks.push(next.value);
          bytes += next.value.byteLength;
        }
      } catch {
        void Promise.resolve(reader.cancel()).catch(() => undefined);
        controller.abort();
        throw new Error('live proof canonical history read failed');
      }
      const raw = new Uint8Array(bytes);
      let offset = 0;
      for (const chunk of chunks) {
        raw.set(chunk, offset);
        offset += chunk.byteLength;
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(new TextDecoder().decode(raw));
      } catch {
        throw new Error('live proof history response was malformed');
      }
      return { status: response.status, body: parsed };
    } catch {
      controller.abort();
      throw new Error('live proof canonical history read failed');
    } finally {
      clearTimeout(abortTimer);
    }
  }, { sessionId });
  return {
    status: body.status,
    ...matchLiveProofHistory(body.body, {
      phase: options.phase,
      sessionId,
      prompt: LIVE_PROOF_PROMPT,
      assistantMarker: LIVE_PROOF_ASSISTANT_MARKER,
      messageProjectionTagger: ledger.messageProjectionTag,
      fence: options.fence,
      preHistoryProjectionTag: options.preHistoryProjectionTag
    })
  };
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
