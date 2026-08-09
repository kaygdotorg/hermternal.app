import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

const identity = {
  user_id: 'accessibility-user',
  email: 'accessibility@example.invalid',
  display_name: 'Accessibility Fixture',
  org_id: 'accessibility-org',
  provider: 'accessibility-provider',
  expires_at: 4_294_967_295
};

const session = {
  id: 'accessibility-session-0001',
  source: 'accessibility-fixture',
  model: 'Hermes 4',
  title: 'Accessible current session',
  started_at: 1,
  ended_at: null,
  last_active: 2,
  is_active: true,
  message_count: 2,
  tool_call_count: 0,
  input_tokens: 0,
  output_tokens: 0,
  preview: null
};

const sessionMessages = {
  session_id: session.id,
  messages: [
    { role: 'user', content: 'Review the deterministic accessibility fixture.' },
    { role: 'assistant', content: 'The live Chat accessibility fixture is ready for review.' }
  ],
  pagination: { limit: 500, offset: 0, returned: 2 }
};

function jsonHeaders(): Record<string, string> {
  return { 'content-type': 'application/json' };
}

async function installSyntheticLiveBoundary(page: Page): Promise<void> {
  // This boundary proves the authenticated route without credentials, Hermes, or
  // retained browser artifacts. Every REST and WebSocket response is synthetic.
  await page.route('**/api/auth/me', (route) =>
    route.fulfill({ status: 200, headers: jsonHeaders(), body: JSON.stringify(identity) })
  );
  await page.route('**/api/auth/ws-ticket', (route) =>
    route.fulfill({
      status: 200,
      headers: jsonHeaders(),
      body: JSON.stringify({ ticket: 'accessibility-ticket-placeholder', ttl_seconds: 30 })
    })
  );
  await page.route('**/api/sessions**', (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (request.method() === 'GET' && url.pathname === '/api/sessions') {
      void route.fulfill({
        status: 200,
        headers: jsonHeaders(),
        body: JSON.stringify({ sessions: [session], total: 1, limit: 100, offset: 0 })
      });
      return;
    }
    if (request.method() === 'GET' && url.pathname === `/api/sessions/${session.id}/messages`) {
      void route.fulfill({ status: 200, headers: jsonHeaders(), body: JSON.stringify(sessionMessages) });
      return;
    }
    if (request.method() === 'GET' && url.pathname === `/api/sessions/${session.id}`) {
      void route.fulfill({ status: 200, headers: jsonHeaders(), body: JSON.stringify(session) });
      return;
    }
    void route.fulfill({ status: 405, headers: jsonHeaders(), body: '{}' });
  });
  await page.routeWebSocket('**/api/ws**', (socket) => {
    socket.onMessage((message) => {
      const frame = JSON.parse(String(message)) as { id?: string; method?: string };
      if (frame.method === 'session.resume') {
        socket.send(
          JSON.stringify({ jsonrpc: '2.0', id: frame.id, result: { session_id: session.id, restored: true } })
        );
      }
    });
    setTimeout(() => {
      socket.send(
        JSON.stringify({
          jsonrpc: '2.0',
          method: 'event',
          params: { type: 'gateway.ready', payload: { skin: 'accessibility-synthetic', change_events: true } }
        })
      );
    }, 0);
  });
}

for (const colorScheme of ['light', 'dark'] as const) {
  for (const scenario of ['success', 'empty', 'failure'] as const) {
    test(`prototype shell has no axe violations in ${colorScheme} ${scenario} state`, async ({ page }) => {
      await page.emulateMedia({ colorScheme, reducedMotion: 'reduce' });
      await page.goto(`/?scenario=${scenario}`);
      await expect(page.getByRole('main')).toBeVisible();
      await expect(page.getByTestId(`status-${scenario}`)).toBeVisible();

      const results = await new AxeBuilder({ page }).analyze();
      expect(results.violations).toEqual([]);
    });
  }

  test(`authenticated live Chat has no axe violations in ${colorScheme} mode`, async ({ page }) => {
    await page.emulateMedia({ colorScheme, reducedMotion: 'reduce' });
    await page.setViewportSize({ width: 1440, height: 960 });
    await installSyntheticLiveBoundary(page);
    await page.goto('/');

    const workspace = page.getByRole('region', { name: 'Hermternal runtime workspace preview' });
    await expect(workspace).toHaveAttribute('data-appearance', colorScheme);
    await expect(workspace).toHaveAttribute('data-mode-source', 'live');
    await expect(page.getByRole('button', { name: 'Edit conversation title' })).toContainText(session.title);
    await expect(page.getByText(sessionMessages.messages[1].content)).toBeVisible();
    await expect(page.getByRole('complementary', { name: 'Workspace inspector' })).toBeVisible();

    const results = await new AxeBuilder({ page }).analyze();
    expect(results.violations).toEqual([]);
  });
}

test('authenticated live Chat keeps focus and forced-color semantics when supported', async ({ page }) => {
  await page.emulateMedia({ forcedColors: 'active', reducedMotion: 'reduce' });
  const forcedColorsSupported = await page.evaluate(() => matchMedia('(forced-colors: active)').matches);
  test.skip(!forcedColorsSupported, 'Chromium does not expose forced-colors emulation in this environment.');

  await page.setViewportSize({ width: 1440, height: 960 });
  await installSyntheticLiveBoundary(page);
  await page.goto('/');

  const workspace = page.getByRole('region', { name: 'Hermternal runtime workspace preview' });
  const title = page.getByRole('button', { name: 'Edit conversation title' });
  await expect(workspace).toHaveAttribute('data-mode-source', 'live');
  await expect(title).toBeVisible();
  await title.focus();
  await expect(title).toBeFocused();
  await expect
    .poll(() => title.evaluate((element) => getComputedStyle(element).outlineStyle))
    .not.toBe('none');

  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
});
