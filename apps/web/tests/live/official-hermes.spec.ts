import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { expect, test } from './live-test-fixtures';
import {
  captureReviewedLiveScreenshots,
  retainedScreenshotDirectory
} from './live-screenshot-contract.mjs';
import {
  LIVE_PROOF_ASSISTANT_MARKER,
  LIVE_PROOF_PROMPT,
  createLiveProofLedger,
  matchLiveProofLedger
} from './live-proof-ledger.mjs';
import {
  assertLiveProofPageBridgeReady,
  closeLiveProofPageSockets,
  drainLiveProofPageEvents,
  installLiveProofPageBridge,
  readLiveProofPageHistory,
  readLiveProofPageState
} from './live-proof-page-bridge.mjs';

type LiveProofHistoryProjection = {
  status: number;
  sessionTag: string;
  sessionMatches: boolean;
  historyComplete: boolean;
  watermarkEstablished: boolean;
  prefixStable: boolean;
  postFenceMatched: boolean;
  promptMatches: boolean;
  assistantMarkerMatches: boolean;
  candidateUserCount: number;
  candidateAssistantCount: number;
  messageCount: number;
  historyProjectionTag: string;
  prefixProjectionTag: string;
  matched: boolean;
};

type LiveProofPageEvent =
  | { kind: 'http.request'; method: string; route: string }
  | { kind: 'http.response'; method: string; route: string; status: number }
  | { kind: 'http.failure'; method: string; route: string }
  | { kind: 'ws.open'; route: string; ticketOnly: boolean; originBound: boolean }
  | {
      kind: 'ws.sent';
      method: string;
      requestTag?: string;
      sessionTag?: string;
    }
  | {
      kind: 'ws.received';
      event: string;
      requestTag?: string;
      sessionTag?: string;
      acknowledgement?: boolean;
    }
  | { kind: 'gateway.ready'; sessionTag?: string }
  | {
      kind: 'session.action';
      method: 'session.create' | 'session.resume';
      requestTag?: string;
      sessionTag?: string;
      storedSessionTag?: string;
    }
  | {
      kind: 'prompt.submit';
      requestTag?: string;
      sessionTag?: string;
      promptMatches: boolean;
    }
  | { kind: 'message.delta'; sessionTag?: string }
  | {
      kind: 'message.complete';
      sessionTag?: string;
      status: string;
      markerMatches: boolean;
    };

type AuthenticatedIdentityProjection = {
  status: number;
  shape: boolean;
};

const password = process.env.HERMES_TEST_PASSWORD;
const username = process.env.HERMES_TEST_USERNAME ?? 'hermternal-test';
const reconciliationOnly = isLiveReconciliationEnabled();

type LiveProofStatus = {
  phase:
    | 'not-started'
    | 'authenticated'
    | 'ready-no-submit'
    | 'submitted'
    | 'completed'
    | 'history-reconciled'
    | 'reconciled'
    | 'uncertain';
  delivery: 'not-submitted' | 'submitted' | 'completed' | 'reconciled' | 'uncertain';
};

function isLiveReconciliationEnabled(environment: NodeJS.ProcessEnv = process.env): boolean {
  const value = environment.HERMTERNAL_LIVE_RECONCILIATION;
  if (value === undefined) return false;
  if (value !== '1') throw new Error('HERMTERNAL_LIVE_RECONCILIATION must equal exactly 1');
  return true;
}

/** Keep the reporter channel fixed to reviewed semantic phase values only. */
function setLiveProofStatus(
  testInfo: { annotations: Array<{ type: string; description?: string }> },
  status: LiveProofStatus
): void {
  testInfo.annotations.push({
    type: 'live-proof',
    description: `${status.phase}/${status.delivery}`
  });
}

test.skip(reconciliationOnly, 'official Hermes prompt lane is disabled during read-only reconciliation');
test.skip(!password, 'HERMES_TEST_PASSWORD is required for the authorized disposable lane.');

test('browser UI reaches official Hermes, reconciles exact history, and logs out', async ({
  page,
  context
}, testInfo) => {
  setLiveProofStatus(testInfo, {
    phase: 'not-started',
    delivery: 'not-submitted'
  });
  const ledger = createLiveProofLedger(256, { signer: { kind: 'page' } });
  // The bridge owns the nonextractable HMAC key and all dynamic source values.
  // Playwright receives only the bounded projections drained below.
  await page.addInitScript(installLiveProofPageBridge, {
    prompt: LIVE_PROOF_PROMPT,
    marker: LIVE_PROOF_ASSISTANT_MARKER
  });

  await page.goto('/');
  await expect(page.evaluate(assertLiveProofPageBridgeReady)).resolves.toBe(true);
  await expect(page.getByRole('button', { name: 'Username & Password' })).toBeVisible();
  await page.getByRole('button', { name: 'Username & Password' }).click();
  await page.getByLabel('Username').fill(username);
  await page.locator('#auth-password').fill(password!);
  await page
    .getByRole('form', { name: 'Hermes password sign in' })
    .evaluate((form) => (form as HTMLFormElement).requestSubmit());

  const workspace = page.getByTestId('runtime-preview');
  await expect(workspace).toBeVisible();
  await expect(workspace).toHaveAttribute('data-state', /^(empty|ready)$/);
  setLiveProofStatus(testInfo, {
    phase: 'authenticated',
    delivery: 'not-submitted'
  });

  const hasExistingSession = (await page.locator('.session-items button').count()) > 0;
  if (!hasExistingSession) {
    // session.create persists lazily on the first prompt in the pinned Hermes
    // source, so a fresh draft cannot establish a pre-send REST fence safely.
    // Refuse before any prompt rather than weakening the causal boundary.
    setLiveProofStatus(testInfo, { phase: 'uncertain', delivery: 'uncertain' });
    throw new Error('live proof requires an existing canonical session');
  }
  await expect
    .poll(async () => {
      await drainPageProofEvents(page, ledger);
      return hasEvent(ledger, 'session.action');
    })
    .toBe(true);

  await expect
    .poll(async () => {
      await drainPageProofEvents(page, ledger);
      return hasEvent(ledger, 'gateway.ready');
    })
    .toBe(true);
  const socketState = await page.evaluate(readLiveProofPageState);
  expect(socketState.websocketOpenCount).toBe(1);
  expect(ledger.snapshot()).toContainEqual(
    expect.objectContaining({
      kind: 'ws.open',
      route: '/api/ws',
      ticketOnly: true,
      originBound: true
    })
  );
  setLiveProofStatus(testInfo, {
    phase: 'ready-no-submit',
    delivery: 'not-submitted'
  });

  let preSendHistory: Awaited<ReturnType<typeof readCanonicalProofHistory>>;
  try {
    preSendHistory = await readCanonicalProofHistory(page, ledger, {
      phase: 'pre-send'
    });
  } catch {
    setLiveProofStatus(testInfo, { phase: 'uncertain', delivery: 'uncertain' });
    throw new Error('live proof pre-send history read failed');
  }
  ledger.recordHistoryResponse({
    phase: 'pre-send',
    status: preSendHistory.status,
    sessionTag: preSendHistory.sessionTag,
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
  if (!preSendHistory.matched || !preSendHistory.historyProjectionTag) {
    setLiveProofStatus(testInfo, { phase: 'uncertain', delivery: 'uncertain' });
    throw new Error('live proof pre-send history fence was not established');
  }

  await page.getByLabel('Message Hermes').fill(LIVE_PROOF_PROMPT);
  await page.getByRole('button', { name: 'Send message' }).click();
  setLiveProofStatus(testInfo, { phase: 'submitted', delivery: 'submitted' });
  await expect
    .poll(async () => {
      await drainPageProofEvents(page, ledger);
      return countEvents(ledger, 'prompt.submit');
    })
    .toBe(1);
  await expect
    .poll(
      async () => {
        await drainPageProofEvents(page, ledger);
        return (
          countEvents(ledger, 'message.delta') +
          countEvents(ledger, 'message.complete') +
          countEvents(ledger, 'ws.received')
        );
      },
      { timeout: 90_000 }
    )
    .toBeGreaterThan(0);
  await expect
    .poll(
      async () => {
        await drainPageProofEvents(page, ledger);
        return countEvents(ledger, 'message.complete');
      },
      { timeout: 90_000 }
    )
    .toBe(1);
  setLiveProofStatus(testInfo, { phase: 'completed', delivery: 'completed' });
  await expect(workspace).toHaveAttribute('data-state', /^(empty|ready)$/);

  let postCompletionHistory: Awaited<ReturnType<typeof readCanonicalProofHistory>>;
  try {
    postCompletionHistory = await readCanonicalProofHistory(page, ledger, {
      phase: 'post-completion'
    });
  } catch {
    setLiveProofStatus(testInfo, { phase: 'uncertain', delivery: 'uncertain' });
    throw new Error('live proof post-completion history read failed');
  }
  ledger.recordHistoryResponse({
    phase: 'post-completion',
    status: postCompletionHistory.status,
    sessionTag: postCompletionHistory.sessionTag,
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
  setLiveProofStatus(testInfo, {
    phase: 'history-reconciled',
    delivery: 'completed'
  });

  const captureState = await workspace.getAttribute('data-state');
  if (captureState !== 'empty' && captureState !== 'ready') {
    throw new Error('live screenshot capture state was not approved');
  }

  await drainPageProofEvents(page, ledger);
  // Keep the identity response body in the page realm; Node retains only its
  // fixed status and shape projection before the capture-only transform.
  const authenticatedIdentityProjection = await page.evaluate(readAuthenticatedIdentityProjection);
  await drainPageProofEvents(page, ledger);
  expect(authenticatedIdentityProjection.status).toBe(200);
  expect(authenticatedIdentityProjection.shape).toBe(true);
  const eventsBeforeLogout = ledger.snapshot();
  const identityTags = await page.evaluate(readLiveProofPageState);
  const proof = matchLiveProofLedger(eventsBeforeLogout, {
    sessionTag: identityTags.canonicalSessionTag,
    promptRequestTag: identityTags.promptRequestTag,
    promptSessionTag: identityTags.promptSessionTag,
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
  const repositoryRoot = resolve(process.cwd(), '../..');
  const clientCommit = execFileSync('git', ['-C', repositoryRoot, 'rev-parse', 'HEAD'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore']
  }).trim();
  await captureReviewedLiveScreenshots({
    page,
    outputRoot: requiredEnvironment('PLAYWRIGHT_LIVE_OUTPUT_DIR'),
    retainedDirectory: retainedScreenshotDirectory(repositoryRoot),
    repositoryRoot,
    clientCommit,
    scrubHook: requiredEnvironment('HERMES_SCREENSHOT_SCRUB_HOOK'),
    reviewHook: requiredEnvironment('HERMES_SCREENSHOT_REVIEW_HOOK')
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
  await page.evaluate(closeLiveProofPageSockets);
  await expect.poll(async () => (await page.evaluate(readLiveProofPageState)).websocketCloseCount).toBe(1);
  await page.close();

  const cookiesBeforeLogout = await context.cookies(proofOrigin);
  expect(cookiesBeforeLogout.length).toBeGreaterThan(0);
  ledger.recordHttpRequest({ method: 'POST', route: '/auth/logout' });
  const logoutResponse = await context.request.post(`${proofOrigin}/auth/logout`, {
    maxRedirects: 0,
    failOnStatusCode: false,
    headers: { accept: 'text/html' }
  });
  ledger.recordHttpResponse({
    method: 'POST',
    route: '/auth/logout',
    status: logoutResponse.status()
  });
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
  await storagePage.goto(`${proofOrigin}/login`, {
    waitUntil: 'domcontentloaded'
  });
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

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required for reviewed screenshot retention`);
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function drainPageProofEvents(
  page: import('@playwright/test').Page,
  ledger: ReturnType<typeof createLiveProofLedger>
): Promise<void> {
  const events = parseLiveProofPageEvents(await page.evaluate(drainLiveProofPageEvents));
  for (const event of events) {
    switch (event.kind) {
      case 'http.request':
        ledger.recordHttpRequest({ method: event.method, route: event.route });
        break;
      case 'http.response':
        ledger.recordHttpResponse({
          method: event.method,
          route: event.route,
          status: event.status
        });
        break;
      case 'ws.open':
        ledger.recordWebSocketOpen({
          route: event.route,
          ticketOnly: event.ticketOnly,
          originBound: event.originBound
        });
        break;
      case 'ws.sent':
        ledger.recordWebSocketSent({
          method: event.method,
          requestTag: event.requestTag,
          sessionTag: event.sessionTag
        });
        break;
      case 'ws.received':
        ledger.recordWebSocketReceived({
          event: event.event,
          requestTag: event.requestTag,
          sessionTag: event.sessionTag,
          acknowledgement: event.acknowledgement
        });
        break;
      case 'gateway.ready':
        ledger.recordGatewayReady({ sessionTag: event.sessionTag });
        break;
      case 'session.action':
        ledger.recordSessionAction({
          method: event.method,
          requestTag: event.requestTag,
          sessionTag: event.sessionTag,
          storedSessionTag: event.storedSessionTag
        });
        break;
      case 'prompt.submit':
        ledger.recordPrompt({
          requestTag: event.requestTag,
          sessionTag: event.sessionTag,
          promptMatches: event.promptMatches
        });
        break;
      case 'message.delta':
        ledger.recordDelta({ sessionTag: event.sessionTag });
        break;
      case 'message.complete':
        ledger.recordCompletion({
          sessionTag: event.sessionTag,
          status: event.status,
          markerMatches: event.markerMatches
        });
        break;
      case 'http.failure':
        // A failed request has no safe ledger event. Its route and method are
        // bounded above, while no source error or response body crosses here.
        break;
    }
  }
}

function parseLiveProofPageEvents(value: unknown): LiveProofPageEvent[] {
  if (!Array.isArray(value)) throw new Error('live proof page bridge returned an invalid event list');
  return value.map((candidate, index) => {
    if (!isRecord(candidate) || typeof candidate.kind !== 'string') {
      throw new Error(`live proof page bridge event ${index} is invalid`);
    }
    switch (candidate.kind) {
      case 'http.request':
        requireProjectionKeys(candidate, ['kind', 'method', 'route'], index);
        return {
          kind: 'http.request',
          method: projectionText(candidate.method, 64, index),
          route: projectionText(candidate.route, 256, index)
        };
      case 'http.response':
        requireProjectionKeys(candidate, ['kind', 'method', 'route', 'status'], index);
        return {
          kind: 'http.response',
          method: projectionText(candidate.method, 64, index),
          route: projectionText(candidate.route, 256, index),
          status: projectionStatus(candidate.status, index)
        };
      case 'http.failure':
        requireProjectionKeys(candidate, ['kind', 'method', 'route'], index);
        return {
          kind: 'http.failure',
          method: projectionText(candidate.method, 64, index),
          route: projectionText(candidate.route, 256, index)
        };
      case 'ws.open':
        requireProjectionKeys(candidate, ['kind', 'route', 'ticketOnly', 'originBound'], index);
        return {
          kind: 'ws.open',
          route: projectionText(candidate.route, 256, index),
          ticketOnly: projectionBoolean(candidate.ticketOnly, index),
          originBound: projectionBoolean(candidate.originBound, index)
        };
      case 'ws.sent':
        requireProjectionKeys(candidate, ['kind', 'method', 'requestTag', 'sessionTag'], index);
        return {
          kind: 'ws.sent',
          method: projectionText(candidate.method, 64, index),
          requestTag: projectionTag(candidate.requestTag, index),
          sessionTag: projectionTag(candidate.sessionTag, index)
        };
      case 'ws.received': {
        requireProjectionKeys(candidate, ['kind', 'event', 'requestTag', 'sessionTag', 'acknowledgement'], index);
        const event = projectionText(candidate.event, 96, index);
        const acknowledgement =
          event === 'response' ? projectionBoolean(candidate.acknowledgement, index) : projectionOptionalBoolean(candidate.acknowledgement, index);
        return {
          kind: 'ws.received',
          event,
          requestTag: projectionTag(candidate.requestTag, index),
          sessionTag: projectionTag(candidate.sessionTag, index),
          acknowledgement
        };
      }
      case 'gateway.ready':
        requireProjectionKeys(candidate, ['kind', 'sessionTag'], index);
        return {
          kind: 'gateway.ready',
          sessionTag: projectionTag(candidate.sessionTag, index)
        };
      case 'session.action': {
        requireProjectionKeys(candidate, ['kind', 'method', 'requestTag', 'sessionTag', 'storedSessionTag'], index);
        const method = projectionText(candidate.method, 64, index);
        if (method !== 'session.create' && method !== 'session.resume') {
          throw new Error(`live proof page bridge event ${index} has an invalid session method`);
        }
        return {
          kind: 'session.action',
          method,
          requestTag: projectionTag(candidate.requestTag, index),
          sessionTag: projectionTag(candidate.sessionTag, index),
          storedSessionTag: projectionTag(candidate.storedSessionTag, index)
        };
      }
      case 'prompt.submit':
        requireProjectionKeys(candidate, ['kind', 'requestTag', 'sessionTag', 'promptMatches'], index);
        return {
          kind: 'prompt.submit',
          requestTag: projectionTag(candidate.requestTag, index),
          sessionTag: projectionTag(candidate.sessionTag, index),
          promptMatches: projectionBoolean(candidate.promptMatches, index)
        };
      case 'message.delta':
        requireProjectionKeys(candidate, ['kind', 'sessionTag'], index);
        return {
          kind: 'message.delta',
          sessionTag: projectionTag(candidate.sessionTag, index)
        };
      case 'message.complete':
        requireProjectionKeys(candidate, ['kind', 'sessionTag', 'status', 'markerMatches'], index);
        return {
          kind: 'message.complete',
          sessionTag: projectionTag(candidate.sessionTag, index),
          status: projectionText(candidate.status, 32, index),
          markerMatches: projectionBoolean(candidate.markerMatches, index)
        };
      default:
        throw new Error(`live proof page bridge returned an unknown projection at ${index}`);
    }
  });
}

function requireProjectionKeys(value: Record<string, unknown>, keys: readonly string[], index: number): void {
  const actualKeys = Object.keys(value);
  if (actualKeys.some((key) => !keys.includes(key))) {
    throw new Error(`live proof page bridge event ${index} contains an unsafe field`);
  }
}

function projectionText(value: unknown, maxLength: number, index: number): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength) {
    throw new Error(`live proof page bridge event ${index} contains unsafe text`);
  }
  return value;
}

function projectionTag(value: unknown, index: number): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || !/^h1:[0-9a-f]{64}$/u.test(value)) {
    throw new Error(`live proof page bridge event ${index} contains an unsafe identity tag`);
  }
  return value;
}

function projectionBoolean(value: unknown, index: number): boolean {
  if (typeof value !== 'boolean') throw new Error(`live proof page bridge event ${index} contains an unsafe boolean`);
  return value;
}

function projectionOptionalBoolean(value: unknown, index: number): boolean | undefined {
  if (value === undefined) return undefined;
  return projectionBoolean(value, index);
}

function projectionStatus(value: unknown, index: number): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 100 || value > 599) {
    throw new Error(`live proof page bridge event ${index} contains an unsafe status`);
  }
  return value;
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
  ledger: ReturnType<typeof createLiveProofLedger>,
  options: { phase: 'pre-send' | 'post-completion' }
): Promise<LiveProofHistoryProjection> {
  let projection: unknown;
  try {
    projection = await page.evaluate(readLiveProofPageHistory, {
      phase: options.phase
    });
  } finally {
    // History transport and WebSocket observation share the page bridge queue.
    // Drain only its fixed projections, even when the one-shot read fails.
    await drainPageProofEvents(page, ledger);
  }
  if (!isSafeLiveProofHistoryProjection(projection)) {
    throw new Error('live proof page history projection was not approved');
  }
  return {
    status: projection.status,
    sessionTag: projection.sessionTag,
    sessionMatches: projection.sessionMatches,
    historyComplete: projection.historyComplete,
    watermarkEstablished: projection.watermarkEstablished,
    prefixStable: projection.prefixStable,
    postFenceMatched: projection.postFenceMatched,
    promptMatches: projection.promptMatches,
    assistantMarkerMatches: projection.assistantMarkerMatches,
    candidateUserCount: projection.candidateUserCount,
    candidateAssistantCount: projection.candidateAssistantCount,
    messageCount: projection.messageCount,
    historyProjectionTag: projection.historyProjectionTag,
    prefixProjectionTag: projection.prefixProjectionTag,
    matched: projection.matched
  };
}

function isSafeLiveProofHistoryProjection(value: unknown): value is LiveProofHistoryProjection {
  if (!isRecord(value)) return false;
  const keys = [
    'status',
    'sessionTag',
    'sessionMatches',
    'historyComplete',
    'watermarkEstablished',
    'prefixStable',
    'postFenceMatched',
    'promptMatches',
    'assistantMarkerMatches',
    'candidateUserCount',
    'candidateAssistantCount',
    'messageCount',
    'historyProjectionTag',
    'prefixProjectionTag',
    'matched'
  ];
  const actualKeys = Object.keys(value);
  if (actualKeys.length !== keys.length || keys.some((key) => !actualKeys.includes(key))) return false;
  const tag = (candidate: unknown): candidate is string =>
    typeof candidate === 'string' && /^h1:[0-9a-f]{64}$/u.test(candidate);
  const count = (candidate: unknown): candidate is number =>
    typeof candidate === 'number' && Number.isInteger(candidate) && candidate >= 0 && candidate <= 500;
  return (
    typeof value.status === 'number' &&
    Number.isInteger(value.status) &&
    value.status >= 100 &&
    value.status <= 599 &&
    tag(value.sessionTag) &&
    typeof value.sessionMatches === 'boolean' &&
    typeof value.historyComplete === 'boolean' &&
    typeof value.watermarkEstablished === 'boolean' &&
    typeof value.prefixStable === 'boolean' &&
    typeof value.postFenceMatched === 'boolean' &&
    typeof value.promptMatches === 'boolean' &&
    typeof value.assistantMarkerMatches === 'boolean' &&
    count(value.candidateUserCount) &&
    count(value.candidateAssistantCount) &&
    count(value.messageCount) &&
    tag(value.historyProjectionTag) &&
    tag(value.prefixProjectionTag) &&
    typeof value.matched === 'boolean'
  );
}

async function readAuthenticatedIdentityProjection(): Promise<AuthenticatedIdentityProjection> {
  try {
    const response = await fetch('/api/auth/me', {
      method: 'GET',
      headers: { accept: 'application/json' },
      credentials: 'include',
      cache: 'no-store'
    });
    const status = response.status;
    if (status !== 200 || response.headers.get('content-type')?.toLowerCase().includes('application/json') !== true) {
      return { status, shape: false };
    }
    const value: unknown = await response.json();
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      return { status, shape: false };
    }
    const keys = ['display_name', 'email', 'expires_at', 'org_id', 'provider', 'user_id'];
    const boundedText = (candidate: unknown): candidate is string =>
      typeof candidate === 'string' && candidate.length <= 512;
    const stableText = (candidate: unknown): candidate is string => boundedText(candidate) && candidate.length > 0;
    const record = value as Record<string, unknown>;
    return {
      status,
      shape:
        JSON.stringify(Object.keys(record).sort()) === JSON.stringify(keys) &&
        stableText(record.user_id) &&
        boundedText(record.email) &&
        boundedText(record.display_name) &&
        boundedText(record.org_id) &&
        stableText(record.provider) &&
        typeof record.expires_at === 'number' &&
        Number.isInteger(record.expires_at) &&
        record.expires_at >= 0 &&
        record.expires_at <= 4_294_967_295
    };
  } catch {
    return { status: 0, shape: false };
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
  const databases = typeof indexedDB.databases === 'function' ? await indexedDB.databases() : undefined;
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
