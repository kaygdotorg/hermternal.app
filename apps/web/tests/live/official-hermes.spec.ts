import { expect, test } from '@playwright/test';

const password = process.env.HERMES_TEST_PASSWORD;
const username = process.env.HERMES_TEST_USERNAME ?? 'hermternal-test';
const prompt = 'Reply with exactly: Hermternal live proof complete.';

test.skip(!password, 'HERMES_TEST_PASSWORD is required for the authorized disposable lane.');

test('browser UI reaches the official Hermes gateway through completion', async ({ page }) => {
  const requests: string[] = [];
  const sentMethods: string[] = [];
  const receivedEvents: string[] = [];
  let websocketUpgradeCount = 0;
  let websocketQueryIsTicketOnly = false;

  page.on('request', (request) => {
    const url = new URL(request.url());
    if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/auth/')) {
      requests.push(`${request.method()} ${url.pathname}`);
    }
  });
  page.on('websocket', (socket) => {
    const url = new URL(socket.url());
    websocketUpgradeCount += 1;
    websocketQueryIsTicketOnly =
      url.pathname === '/api/ws' &&
      [...url.searchParams.keys()].length === 1 &&
      url.searchParams.has('ticket');

    socket.on('framesent', (frame) => {
      const envelope = parseFrame(frame.payload);
      if (envelope && typeof envelope.method === 'string') sentMethods.push(envelope.method);
    });
    socket.on('framereceived', (frame) => {
      const envelope = parseFrame(frame.payload);
      if (
        envelope?.method === 'event' &&
        isRecord(envelope.params) &&
        typeof envelope.params.type === 'string'
      ) {
        receivedEvents.push(envelope.params.type);
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

  // A fresh disposable instance has no durable history. The user-led New chat
  // action must create the source-owned ephemeral draft before the first prompt.
  if ((await page.locator('.session-items button').count()) === 0) {
    await page.getByRole('button', { name: 'Start a new chat' }).click();
    await expect.poll(() => sentMethods.includes('session.create')).toBe(true);
    await expect(workspace).toHaveAttribute('data-state', 'empty');
  } else {
    await expect.poll(() => sentMethods.includes('session.resume')).toBe(true);
  }

  await expect.poll(() => receivedEvents.includes('gateway.ready')).toBe(true);
  expect(requests).toContain('GET /api/auth/me');
  expect(requests).toContain('GET /api/auth/providers');
  expect(requests).toContain('POST /auth/password-login');
  expect(requests).toContain('GET /api/sessions');
  // A brand-new source draft has no durable REST history until its first prompt.
  expect(requests).toContain('POST /api/auth/ws-ticket');
  expect(websocketUpgradeCount).toBe(1);
  expect(websocketQueryIsTicketOnly).toBe(true);

  const credentialRetention = await page.evaluate((marker) => ({
    dom: document.documentElement.outerHTML.includes(marker),
    url: location.href.includes(marker),
    localStorage: Object.values(localStorage).some((value) => value.includes(marker)),
    sessionStorage: Object.values(sessionStorage).some((value) => value.includes(marker))
  }), password!);
  expect(credentialRetention).toEqual({
    dom: false,
    url: false,
    localStorage: false,
    sessionStorage: false
  });

  const initialMessageReadCount = requests.filter((entry) => entry.endsWith('/messages')).length;
  await page.getByLabel('Message Hermes').fill(prompt);
  await page.getByRole('button', { name: 'Send message' }).click();
  await expect.poll(() => sentMethods.includes('prompt.submit')).toBe(true);
  await expect
    .poll(
      () =>
        receivedEvents.includes('message.delta') ||
        receivedEvents.includes('message.complete') ||
        receivedEvents.includes('error'),
      { timeout: 90_000 }
    )
    .toBe(true);
  // Do not retain the source error payload. An `error` event proves transport but
  // blocks completion, usually because the disposable VM lacks inference auth.
  expect(receivedEvents.includes('error')).toBe(false);
  await expect.poll(() => receivedEvents.includes('message.complete'), { timeout: 90_000 }).toBe(true);
  await expect(workspace).toHaveAttribute('data-state', /^(empty|ready)$/);
  // Completion is transient. The controller must replace it from Hermes REST
  // history instead of retaining a second local transcript copy.
  await expect.poll(
    () => requests.filter((entry) => entry.endsWith('/messages')).length,
    { timeout: 30_000 }
  ).toBeGreaterThan(initialMessageReadCount);

  expect(requests.filter((entry) => entry === 'POST /api/auth/ws-ticket')).toHaveLength(1);
  expect(sentMethods.filter((method) => method === 'prompt.submit')).toHaveLength(1);
});

test('browser auth logs out of the official Hermes session', async ({ page }) => {
  const password = process.env.HERMES_TEST_PASSWORD;
  const username = process.env.HERMES_TEST_USERNAME ?? 'hermternal-test';
  test.skip(!password, 'HERMES_TEST_PASSWORD is required for the authorized disposable lane.');

  const requests: string[] = [];
  page.on('request', (request) => {
    const url = new URL(request.url());
    if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/auth/')) {
      requests.push(`${request.method()} ${url.pathname}`);
    }
  });

  await page.goto('/');
  await page.getByRole('button', { name: 'Username & Password' }).click();
  await page.getByLabel('Username').fill(username);
  await page.locator('#auth-password').fill(password!);
  await page.getByRole('form', { name: 'Hermes password sign in' }).evaluate((form) =>
    (form as HTMLFormElement).requestSubmit()
  );
  await expect(page.getByTestId('runtime-preview')).toBeVisible();

  // The approved Paper workspace has no logout control yet. Exercise the same
  // reviewed same-origin boundary here without inventing a UI state.
  const logout = await page.evaluate(async () => {
    const authenticatedIdentity = await fetch('/api/auth/me', {
      method: 'GET',
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error'
    });
    const authenticatedValue: unknown = await authenticatedIdentity.json();
    const authenticatedRecord =
      authenticatedValue !== null && typeof authenticatedValue === 'object' && !Array.isArray(authenticatedValue)
        ? (authenticatedValue as Record<string, unknown>)
        : undefined;
    const identityKeys = ['display_name', 'email', 'expires_at', 'org_id', 'provider', 'user_id'];
    const boundedText = (value: unknown): value is string =>
      typeof value === 'string' && value.length <= 512;
    const stableText = (value: unknown): value is string =>
      boundedText(value) && value.length > 0;
    // Basic provider profile metadata may be empty; user/provider/expiry are
    // the stable fields that prove the authenticated session shape.
    const authenticatedIdentityShape =
      authenticatedRecord !== undefined &&
      JSON.stringify(Object.keys(authenticatedRecord).sort()) === JSON.stringify(identityKeys) &&
      stableText(authenticatedRecord.user_id) &&
      boundedText(authenticatedRecord.email) &&
      boundedText(authenticatedRecord.display_name) &&
      boundedText(authenticatedRecord.org_id) &&
      stableText(authenticatedRecord.provider) &&
      typeof authenticatedRecord.expires_at === 'number' &&
      Number.isInteger(authenticatedRecord.expires_at) &&
      authenticatedRecord.expires_at >= 0 &&
      authenticatedRecord.expires_at <= 4_294_967_295;
    const response = await fetch('/auth/logout', {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'manual'
    });
    const identity = await fetch('/api/auth/me', {
      method: 'GET',
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error'
    });
    return {
      authenticatedIdentityStatus: authenticatedIdentity.status,
      authenticatedIdentityShape,
      logoutStatus: response.status,
      logoutLocation: response.headers.get('location'),
      logoutRedirected: response.redirected,
      identityStatus: identity.status
    };
  });

  expect(logout.authenticatedIdentityStatus).toBe(200);
  expect(logout.authenticatedIdentityShape).toBe(true);
  expect(logout.logoutStatus).toBe(302);
  expect(logout.logoutLocation).toBe('/login');
  expect(logout.logoutRedirected).toBe(false);
  expect(logout.identityStatus).toBe(401);
  expect(requests).toContain('POST /auth/logout');
  expect(requests).toContain('GET /api/auth/me');
});

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
