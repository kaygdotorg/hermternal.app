import { expect, test } from './live-test-fixtures';
import {
  SHARED_SESSION_FIRST_ASSISTANT_MARKER,
  SHARED_SESSION_FIRST_PROMPT,
  SHARED_SESSION_SECOND_ASSISTANT_MARKER,
  SHARED_SESSION_SECOND_PROMPT,
  createSharedSessionProofLedger,
  matchSharedSessionHistory,
  matchSharedSessionProofLedger
} from './shared-session-proof-ledger.mjs';

const password = process.env.HERMES_TEST_PASSWORD;
const username = process.env.HERMES_TEST_USERNAME ?? 'hermternal-test';

test.skip(!password, 'HERMES_TEST_PASSWORD is required for the authorized disposable lane.');

test('preserves one Chat owner across Terminal and back to Chat', async ({ page, context }) => {
  const ledger = createSharedSessionProofLedger();
  let firstApplicationEvent: string | undefined;
  let sessionActionMethod: 'session.create' | 'session.resume' | undefined;
  let pendingSessionActionRequestId: string | undefined;
  let pendingSessionActionSessionId: string | undefined;
  let pendingPromptRequestId: string | undefined;
  let pendingPromptSessionId: string | undefined;
  let activePromptPhase: 'first' | 'second' | undefined;
  let historyPhaseToRecord: 'first' | 'second' | undefined;
  const historyMatched = { first: false, second: false };
  let authoritativeSelectedSessionId: string | undefined;
  let ephemeralSessionId: string | undefined;
  let committedSessionId: string | undefined;
  let latestSessionIdentityProjection = Promise.resolve();
  let latestAuthIdentityProjection = Promise.resolve();
  let chatWebSocketCount = 0;
  let ptyUpgradeCount = 0;
  let websocketCloseCount = 0;
  let errorEventCount = 0;
  let latestHistoryProjection = Promise.resolve();

  // Keep socket handles only in the page realm so the proof can close every
  // live transport before page teardown. The ledger receives only close-count
  // projections; it never retains a WebSocket object or frame.
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
    Object.defineProperty(window, '__hermternalCloseSharedProofSockets', {
      configurable: true,
      value: () => {
        for (const socket of sockets) socket.close(1000, 'shared proof complete');
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

    if (route === '/api/auth/me' && request.method() === 'GET' && response.status() === 200) {
      latestAuthIdentityProjection = latestAuthIdentityProjection.then(async () => {
        ledger.recordAuthenticatedIdentity({ matches: await authenticatedIdentityShape(response) });
      });
    }

    if (route === '/api/sessions' && request.method() === 'GET') {
      latestSessionIdentityProjection = latestSessionIdentityProjection.then(async () => {
        const projection = await projectSessionListIdentity(response);
        if (projection.matches) authoritativeSelectedSessionId = projection.sessionId;
      });
    } else if (route === '/api/sessions/:session' && request.method() === 'GET') {
      // The detail response binds the UI-selected durable identity. The raw ID
      // is compared transiently and never enters the ledger or failure output.
      latestSessionIdentityProjection = latestSessionIdentityProjection.then(async () => {
        const projection = await projectSessionIdentity(response);
        if (projection.matches) authoritativeSelectedSessionId = projection.sessionId;
      });
    }

    if (route !== '/api/sessions/:session/messages' || !historyPhaseToRecord) return;
    const phase = historyPhaseToRecord;
    const expectedSessionId = committedSessionId;
    const routeSessionId = sessionIdFromMessagesUrl(response.url());
    // Do not suppress a second qualifying response. The matcher requires one
    // history capture per phase so duplicate/ambiguous refreshes fail closed.
    latestHistoryProjection = latestHistoryProjection.then(() => projectHistoryResponse(
      response,
      phase,
      routeSessionId,
      expectedSessionId,
      ledger,
      (matched) => {
        historyMatched[phase] = matched;
      }
    ));
  });

  page.on('websocket', (socket) => {
    const parsed = parseSocketProjection(socket.url(), committedSessionId);
    if (!parsed) return;
    socket.on('close', () => {
      if (parsed.route === '/api/ws') {
        websocketCloseCount += 1;
        ledger.recordChatWebSocketClose();
      }
    });

    if (parsed.route === '/api/ws') {
      chatWebSocketCount += 1;
      ledger.recordChatWebSocket({ route: parsed.route, ticketOnly: parsed.ticketOnly });
      return;
    }

    if (parsed.route !== '/api/pty') return;
    ptyUpgradeCount += 1;
    ledger.recordPtyUpgrade({
      route: parsed.route,
      queryKeyCount: parsed.queryKeyCount,
      ticketPresent: parsed.ticketPresent,
      resumePresent: parsed.resumePresent,
      attachPresent: parsed.attachPresent,
      ticketLength: parsed.ticketLength,
      resumeLength: parsed.resumeLength,
      attachLength: parsed.attachLength,
      resumeMatches: parsed.resumeMatches && committedSessionId !== undefined,
      legacyMode: !parsed.attachPresent
    });
  });

  page.on('websocket', (socket) => {
    if (parseSocketProjection(socket.url(), committedSessionId)?.route !== '/api/ws') return;
    socket.on('framesent', ({ payload }) => {
      const envelope = parseFrame(payload);
      if (!envelope) return;
      const method = stringValue(envelope.method);
      const requestId = stringValue(envelope.id);
      const params = isRecord(envelope.params) ? envelope.params : undefined;
      const sessionId = stringValue(params?.session_id) ?? stringValue(params?.sessionId);

      if (method === 'session.create' || method === 'session.resume') {
        sessionActionMethod = method;
        pendingSessionActionRequestId = requestId;
        pendingSessionActionSessionId = sessionId;
        if (method === 'session.resume') {
          // The outbound durable ID remains the continuity candidate until the
          // authoritative REST detail projection confirms the UI selection.
          committedSessionId = sessionId;
          ledger.recordSessionAction({ method });
        }
        return;
      }

      if (method !== 'prompt.submit') return;
      const phase = activePromptPhase;
      if (!phase) return;
      pendingPromptRequestId = requestId;
      pendingPromptSessionId = sessionId;
      // Hermes exposes an ephemeral create response ID, but the workspace
      // commits only stored_session_id as the owner used by every prompt.
      const expectedPromptSessionId = committedSessionId;
      const expectedPrompt = phase === 'first' ? SHARED_SESSION_FIRST_PROMPT : SHARED_SESSION_SECOND_PROMPT;
      ledger.recordPrompt({
        phase,
        markerMatches: stringValue(params?.text) === expectedPrompt,
        sessionMatches: sessionId !== undefined && sessionId === expectedPromptSessionId
      });
    });

    socket.on('framereceived', ({ payload }) => {
      const envelope = parseFrame(payload);
      if (!envelope) return;

      if (envelope.method === 'event' && isRecord(envelope.params)) {
        const params = envelope.params;
        const eventName = stringValue(params.type);
        if (!eventName) return;
        if (firstApplicationEvent === undefined) firstApplicationEvent = eventName;
        const payloadValue = params.payload;
        const payloadRecord = isRecord(payloadValue) ? payloadValue : undefined;
        const eventSessionId =
          stringValue(params.session_id) ??
          stringValue(params.sessionId) ??
          stringValue(payloadRecord?.session_id) ??
          stringValue(payloadRecord?.sessionId);
        const requestId =
          stringValue(params.request_id) ??
          stringValue(params.requestId) ??
          ((eventName === 'message.delta' || eventName === 'message.complete')
            ? pendingPromptRequestId
            : undefined);

        if (eventName === 'gateway.ready') {
          ledger.recordGatewayReady({ serverFirst: firstApplicationEvent === eventName });
        } else if (eventName === 'message.delta' && activePromptPhase) {
          const correlatedEventSessionId = eventSessionId ?? pendingPromptSessionId;
          ledger.recordDelta({
            phase: activePromptPhase,
            requestMatches: requestId !== undefined && requestId === pendingPromptRequestId,
            sessionMatches: correlatedEventSessionId !== undefined && correlatedEventSessionId === pendingPromptSessionId,
            requestIdPresent: stringValue(params.request_id) !== undefined || stringValue(params.requestId) !== undefined,
            sessionIdPresent: eventSessionId !== undefined
          });
        } else if (eventName === 'message.complete' && activePromptPhase) {
          const phase = activePromptPhase;
          const expectedSessionId = phase === 'first' ? pendingPromptSessionId : committedSessionId;
          const correlatedEventSessionId = eventSessionId ?? pendingPromptSessionId;
          const completionSessionMatches =
            correlatedEventSessionId !== undefined && correlatedEventSessionId === expectedSessionId;
          const requestMatches = requestId !== undefined && requestId === pendingPromptRequestId;
          const marker = phase === 'first'
            ? SHARED_SESSION_FIRST_ASSISTANT_MARKER
            : SHARED_SESSION_SECOND_ASSISTANT_MARKER;
          const status = stringValue(payloadRecord?.status) ?? stringValue(payloadRecord?.outcome) ?? 'unknown';
          ledger.recordCompletion({
            phase,
            status,
            requestMatches,
            sessionMatches: completionSessionMatches,
            markerMatches: containsText(payloadValue, marker),
            requestIdPresent: stringValue(params.request_id) !== undefined || stringValue(params.requestId) !== undefined,
            sessionIdPresent: eventSessionId !== undefined
          });
          if (status === 'ok' && requestMatches && completionSessionMatches) {
            historyPhaseToRecord = phase;
            // Fence the active prompt before the REST refresh can complete.
            // Late delta/complete frames must not be attributed to the next turn.
            activePromptPhase = undefined;
            pendingPromptRequestId = undefined;
            pendingPromptSessionId = undefined;
          }
        } else if (eventName === 'error') {
          errorEventCount += 1;
          activePromptPhase = undefined;
          pendingPromptRequestId = undefined;
          pendingPromptSessionId = undefined;
        }
        return;
      }

      const responseId = stringValue(envelope.id);
      if (!responseId) return;
      if (pendingSessionActionRequestId && responseId === pendingSessionActionRequestId) {
        if (sessionActionMethod === 'session.create' && isRecord(envelope.result)) {
          const createdSessionId = stringValue(envelope.result.session_id);
          const storedSessionId = stringValue(envelope.result.stored_session_id);
          ephemeralSessionId = createdSessionId;
          const promotionMatches =
            ephemeralSessionId !== undefined &&
            storedSessionId !== undefined &&
            ephemeralSessionId !== storedSessionId;
          committedSessionId = storedSessionId;
          ledger.recordSessionAction({ method: 'session.create' });
          ledger.recordSessionIdentity({
            method: 'session.create',
            matches: promotionMatches,
            promoted: promotionMatches
          });
        } else if (sessionActionMethod === 'session.resume') {
          const resumeSessionId = pendingSessionActionSessionId;
          void latestSessionIdentityProjection.then(() => {
            const identityMatches =
              resumeSessionId !== undefined &&
              authoritativeSelectedSessionId !== undefined &&
              resumeSessionId === authoritativeSelectedSessionId;
            ledger.recordSessionIdentity({
              method: 'session.resume',
              matches: identityMatches,
              promoted: false
            });
          });
        }
        pendingSessionActionRequestId = undefined;
        pendingSessionActionSessionId = undefined;
        return;
      }
      if (pendingPromptRequestId && responseId === pendingPromptRequestId && activePromptPhase) {
        ledger.recordPromptAcknowledgement({
          phase: activePromptPhase,
          requestMatches: true
        });
      }
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
    await page.getByRole('button', { name: 'Start a new chat' }).click();
  }
  await expect.poll(() => ledger.snapshot().some((event) => event.kind === 'gateway.ready')).toBe(true);
  await expect.poll(() => ledger.snapshot().some((event) => event.kind === 'session.action')).toBe(true);
  await latestSessionIdentityProjection;
  await expect.poll(
    () => ledger.snapshot().some((event) => event.kind === 'session.identity' && event.matches === true),
    { timeout: 30_000 }
  ).toBe(true);
  expect(chatWebSocketCount).toBe(1);

  activePromptPhase = 'first';
  await page.getByLabel('Message Hermes').fill(SHARED_SESSION_FIRST_PROMPT);
  await page.getByRole('button', { name: 'Send message' }).click();
  await expect.poll(() => countEvents(ledger.snapshot(), 'prompt.submit')).toBe(1);
  await expect.poll(() => countEvents(ledger.snapshot(), 'message.delta'), { timeout: 90_000 }).toBe(1);
  await expect.poll(() => countEvents(ledger.snapshot(), 'message.complete'), { timeout: 90_000 }).toBe(1);
  expect(errorEventCount).toBe(0);
  await expect(workspace).toHaveAttribute('data-state', /^(empty|ready)$/);
  await expect.poll(() => historyMatched.first, { timeout: 30_000 }).toBe(true);
  await latestHistoryProjection;
  await expect(workspace).toHaveAttribute('data-state', /^(empty|ready)$/);
  expect(committedSessionId).toBeDefined();

  // Keep the phase armed until all observed history responses are projected so
  // a duplicate qualifying refresh cannot be hidden by an early match.
  historyPhaseToRecord = undefined;
  ledger.recordModeTransition({ event: 'chat-to-terminal' });
  await page.getByRole('button', { name: 'Open terminal mode' }).click();
  const terminalSurface = page.getByTestId('terminal-surface');
  await expect(terminalSurface).toBeVisible();
  await expect(terminalSurface).toHaveAttribute('data-terminal-state', 'open');
  await expect(page.getByRole('button', { name: 'Terminal mode selected' })).toBeVisible();
  await expect.poll(() => ptyUpgradeCount, { timeout: 30_000 }).toBe(1);

  ledger.recordModeTransition({ event: 'terminal-to-chat' });
  await page.getByRole('button', { name: 'Switch to Chat mode' }).click();
  await expect(page.getByRole('button', { name: 'Chat mode selected' })).toBeVisible();
  await expect.poll(() => chatWebSocketCount).toBe(1);
  await expect.poll(() => ptyUpgradeCount).toBe(1);

  activePromptPhase = 'second';
  await page.getByLabel('Message Hermes').fill(SHARED_SESSION_SECOND_PROMPT);
  await page.getByRole('button', { name: 'Send message' }).click();
  await expect.poll(() => countEvents(ledger.snapshot(), 'prompt.submit')).toBe(2);
  await expect.poll(() => countEvents(ledger.snapshot(), 'message.delta'), { timeout: 90_000 }).toBe(2);
  await expect.poll(() => countEvents(ledger.snapshot(), 'message.complete'), { timeout: 90_000 }).toBe(2);
  expect(errorEventCount).toBe(0);
  await expect(workspace).toHaveAttribute('data-state', /^(empty|ready)$/);
  await expect.poll(() => historyMatched.second, { timeout: 30_000 }).toBe(true);
  await latestHistoryProjection;
  await expect(workspace).toHaveAttribute('data-state', /^(empty|ready)$/);
  await latestAuthIdentityProjection;
  await expect.poll(
    () => ledger.snapshot().some((event) => event.kind === 'auth.identity' && event.matches === true),
    { timeout: 30_000 }
  ).toBe(true);

  const proof = matchSharedSessionProofLedger(ledger.snapshot());
  expect(proof).toEqual({
    ordered: true,
    login: true,
    authenticated: true,
    ticket: true,
    chatWebSocketOpen: true,
    chatWebSocketCount: 1,
    chatWebSocketCloseCount: 0,
    chatWebSocketClosed: false,
    gatewayReady: true,
    sessionAction: true,
    freshSessionPromotion: true,
    resumeAuthoritativeIdentity: true,
    sessionCreateCount: hasExistingSession ? 0 : 1,
    sessionResumeCount: hasExistingSession ? 1 : 0,
    noSecondSessionCreate: true,
    firstPrompt: true,
    secondPrompt: true,
    secondPromptSameOwner: true,
    promptCount: 2,
    firstPromptAcknowledgement: true,
    secondPromptAcknowledgement: true,
    firstDelta: true,
    secondDelta: true,
    firstCompletion: true,
    secondCompletion: true,
    completionCount: 2,
    firstHistory: true,
    finalHistory: true,
    historyPairCount: 2,
    modeChatToTerminal: true,
    modeTerminalToChat: true,
    ptyUpgrade: true,
    ptyUpgradeCount: 1,
    ptyQueryExact: true,
    ptyTicketPresent: true,
    ptyResumePresent: true,
    ptyResumeMatches: true,
    ptyAttachAbsent: true,
    legacyMode: true,
    noSecondChatTransport: true,
    noSecondPtyUpgrade: true,
    finalHistoryMessageCount: expect.any(Number),
    logout: false
  });

  const proofOrigin = new URL(page.url()).origin;
  await page.evaluate(() => {
    const closeSockets = (window as Window & {
      __hermternalCloseSharedProofSockets?: () => void;
    }).__hermternalCloseSharedProofSockets;
    closeSockets?.();
  });
  await expect.poll(() => websocketCloseCount, { timeout: 30_000 }).toBe(1);
  await page.close();

  const authenticatedResponse = await context.request.get(`${proofOrigin}/api/auth/me`, {
    maxRedirects: 0,
    failOnStatusCode: false
  });
  ledger.recordHttpRequest({ method: 'GET', route: '/api/auth/me' });
  ledger.recordHttpResponse({
    method: 'GET',
    route: '/api/auth/me',
    status: authenticatedResponse.status()
  });
  expect(authenticatedResponse.status()).toBe(200);
  const authenticatedIdentityMatches = await authenticatedIdentityShape(authenticatedResponse);
  ledger.recordAuthenticatedIdentity({ matches: authenticatedIdentityMatches });
  expect(authenticatedIdentityMatches).toBe(true);
  const cookiesBeforeLogoutCount = (await context.cookies(proofOrigin)).length;
  expect(cookiesBeforeLogoutCount).toBeGreaterThan(0);

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
  const loggedOutResponse = await context.request.get(`${proofOrigin}/api/auth/me`, {
    maxRedirects: 0,
    failOnStatusCode: false
  });
  ledger.recordHttpResponse({
    method: 'GET',
    route: '/api/auth/me',
    status: loggedOutResponse.status()
  });
  expect(loggedOutResponse.status()).toBe(401);
  const cookiesAfterLogoutCount = (await context.cookies(proofOrigin)).length;
  const storagePage = await context.newPage();
  await storagePage.goto(`${proofOrigin}/login`, { waitUntil: 'domcontentloaded' });
  const persistentStorage = await storagePage.evaluate(() => inspectPersistentBrowserState());
  await storagePage.close();
  const cookieJarCleared = cookiesBeforeLogoutCount > 0 && cookiesAfterLogoutCount === 0;
  const storageCleared = persistentStorage.cleared;
  ledger.recordLogout({
    status: logoutResponse.status(),
    cookieJarCleared,
    storageCleared
  });
  expect(cookieJarCleared).toBe(true);
  expect(storageCleared).toBe(true);

  const finalProof = matchSharedSessionProofLedger(ledger.snapshot());
  expect(finalProof.chatWebSocketClosed).toBe(true);
  expect(finalProof.logout).toBe(true);
});

/** @param {string} url */
function trackedRoute(url: string): string | undefined {
  try {
    const parsed = new URL(url);
    const pathname = parsed.pathname;
    if (!pathname.startsWith('/api/') && !pathname.startsWith('/auth/')) return undefined;
    if (pathname === '/api/pty') return '/api/pty';
    if (/^\/api\/sessions\/[^/]+\/messages$/u.test(pathname)) return '/api/sessions/:session/messages';
    if (/^\/api\/sessions\/[^/]+$/u.test(pathname)) return '/api/sessions/:session';
    return pathname;
  } catch {
    return undefined;
  }
}

function parseSocketProjection(url: string, expectedSessionId: string | undefined): {
  route: '/api/ws' | '/api/pty';
  ticketOnly: boolean;
  queryKeyCount: number;
  ticketPresent: boolean;
  resumePresent: boolean;
  attachPresent: boolean;
  ticketLength: number;
  resumeLength: number;
  attachLength: number;
  resumeMatches: boolean;
} | undefined {
  try {
    const parsed = new URL(url);
    if (parsed.pathname === '/api/ws') {
      const keys = [...parsed.searchParams.keys()];
      return {
        route: '/api/ws',
        ticketOnly: keys.length === 1 && keys[0] === 'ticket',
        queryKeyCount: 0,
        ticketPresent: false,
        resumePresent: false,
        attachPresent: false,
        ticketLength: 0,
        resumeLength: 0,
        attachLength: 0,
        resumeMatches: false
      };
    }
    if (parsed.pathname !== '/api/pty') return undefined;
    const ticket = parsed.searchParams.get('ticket');
    const resume = parsed.searchParams.get('resume');
    const attach = parsed.searchParams.get('attach');
    const keys = [...parsed.searchParams.keys()];
    return {
      route: '/api/pty',
      ticketOnly: false,
      queryKeyCount: keys.length,
      ticketPresent: keys.includes('ticket'),
      resumePresent: keys.includes('resume'),
      attachPresent: keys.includes('attach'),
      ticketLength: ticket?.length ?? 0,
      resumeLength: resume?.length ?? 0,
      attachLength: attach?.length ?? 0,
      resumeMatches: resume !== null && resume === expectedSessionId
    };
  } catch {
    return undefined;
  }
}

function sessionIdFromDetailUrl(url: string): string | undefined {
  try {
    const parsed = new URL(url);
    const match = parsed.pathname.match(/^\/api\/sessions\/([^/]+)$/u);
    return match ? stringValue(decodeURIComponent(match[1])) : undefined;
  } catch {
    return undefined;
  }
}

function sessionIdFromMessagesUrl(url: string): string | undefined {
  try {
    const parsed = new URL(url);
    const match = parsed.pathname.match(/^\/api\/sessions\/([^/]+)\/messages$/u);
    return match ? stringValue(decodeURIComponent(match[1])) : undefined;
  } catch {
    return undefined;
  }
}

async function projectSessionListIdentity(
  response: import('@playwright/test').Response
): Promise<{ matches: boolean; sessionId?: string }> {
  if (response.status() !== 200) return { matches: false };
  try {
    const body: unknown = await response.json();
    if (!isRecord(body) || !Array.isArray(body.sessions) || body.sessions.length === 0 || body.sessions.length > 100) {
      return { matches: false };
    }
    const sessions = body.sessions.filter(isRecord);
    if (sessions.length !== body.sessions.length) return { matches: false };
    const active = sessions.find((session) =>
      session.is_active === true || session.isActive === true
    ) ?? sessions[0];
    const sessionId = stringValue(active.id) ?? stringValue(active.session_id) ?? stringValue(active.sessionId);
    return sessionId === undefined ? { matches: false } : { matches: true, sessionId };
  } catch {
    return { matches: false };
  }
}

async function projectSessionIdentity(
  response: import('@playwright/test').Response
): Promise<{ matches: boolean; sessionId?: string }> {
  const routeSessionId = sessionIdFromDetailUrl(response.url());
  if (response.status() !== 200 || routeSessionId === undefined) {
    return { matches: false };
  }
  try {
    const body: unknown = await response.json();
    if (!isRecord(body)) return { matches: false };
    const bodySessionId = stringValue(body.id) ?? stringValue(body.session_id) ?? stringValue(body.sessionId);
    return {
      matches: bodySessionId !== undefined && bodySessionId === routeSessionId,
      sessionId: routeSessionId
    };
  } catch {
    return { matches: false };
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

function countEvents(events: readonly Record<string, unknown>[], kind: string): number {
  return events.filter((event) => event.kind === kind).length;
}

async function authenticatedIdentityShape(
  response: { status(): number; json(): Promise<unknown> }
): Promise<boolean> {
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
  serviceWorkerRegistrationsCleared: boolean;
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
  try {
    const localStorageCleared = countStorage(localStorage) === 0;
    const sessionStorageCleared = countStorage(sessionStorage) === 0;
    const databases =
      typeof indexedDB.databases === 'function' ? await indexedDB.databases() : undefined;
    const cacheNames = typeof caches?.keys === 'function' ? await caches.keys() : undefined;
    const registrations =
      typeof navigator.serviceWorker?.getRegistrations === 'function'
        ? await navigator.serviceWorker.getRegistrations()
        : undefined;
    const indexedDbCleared = databases !== undefined && databases.length === 0;
    const cacheStorageCleared = cacheNames !== undefined && cacheNames.length === 0;
    // Cache Storage is shared by window and service-worker clients. Requiring
    // registrations to be gone separately closes the worker lifecycle boundary.
    const serviceWorkerCacheCleared = cacheStorageCleared;
    const serviceWorkerRegistrationsCleared = registrations !== undefined && registrations.length === 0;
    return {
      localStorageCleared,
      sessionStorageCleared,
      indexedDbCleared,
      cacheStorageCleared,
      serviceWorkerCacheCleared,
      serviceWorkerRegistrationsCleared,
      cleared:
        localStorageCleared &&
        sessionStorageCleared &&
        indexedDbCleared &&
        cacheStorageCleared &&
        serviceWorkerCacheCleared &&
        serviceWorkerRegistrationsCleared
    };
  } catch {
    return {
      localStorageCleared: false,
      sessionStorageCleared: false,
      indexedDbCleared: false,
      cacheStorageCleared: false,
      serviceWorkerCacheCleared: false,
      serviceWorkerRegistrationsCleared: false,
      cleared: false
    };
  }
}

async function projectHistoryResponse(
  response: import('@playwright/test').Response,
  phase: 'first' | 'second',
  routeSessionId: string | undefined,
  expectedSessionId: string | undefined,
  ledger: ReturnType<typeof createSharedSessionProofLedger>,
  onMatched: (matched: boolean) => void
): Promise<void> {
  const status = response.status();
  try {
    const body: unknown = await response.json();
    const match = expectedSessionId
      ? matchSharedSessionHistory(body, {
          sessionId: expectedSessionId,
          firstPrompt: SHARED_SESSION_FIRST_PROMPT,
          firstAssistantMarker: SHARED_SESSION_FIRST_ASSISTANT_MARKER,
          secondPrompt: SHARED_SESSION_SECOND_PROMPT,
          secondAssistantMarker: SHARED_SESSION_SECOND_ASSISTANT_MARKER
        })
      : {
          sessionMatches: false,
          firstPromptMatches: false,
          firstAssistantMarkerMatches: false,
          secondPromptMatches: false,
          secondAssistantMarkerMatches: false,
          messageCount: 0,
          matched: false
        };
    const sessionMatches =
      match.sessionMatches &&
      routeSessionId !== undefined &&
      expectedSessionId !== undefined &&
      routeSessionId === expectedSessionId;
    ledger.recordHistory({
      phase,
      status,
      sessionMatches,
      firstPromptMatches: match.firstPromptMatches,
      firstAssistantMarkerMatches: match.firstAssistantMarkerMatches,
      secondPromptMatches: match.secondPromptMatches,
      secondAssistantMarkerMatches: match.secondAssistantMarkerMatches,
      messageCount: match.messageCount
    });
    onMatched(
      phase === 'first'
        ? sessionMatches && match.firstPromptMatches && match.firstAssistantMarkerMatches
        : sessionMatches && match.matched
    );
  } catch {
    ledger.recordHistory({
      phase,
      status,
      sessionMatches: false,
      firstPromptMatches: false,
      firstAssistantMarkerMatches: false,
      secondPromptMatches: false,
      secondAssistantMarkerMatches: false,
      messageCount: 0
    });
    onMatched(false);
  }
}
