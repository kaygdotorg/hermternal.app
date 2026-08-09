import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

const identity = {
  user_id: 'visual-user',
  email: 'visual@example.invalid',
  display_name: 'Visual Fixture',
  org_id: 'visual-org',
  provider: 'visual-provider',
  expires_at: 4_294_967_295
};

const session = {
  id: 'visual-session-0001',
  source: 'visual-fixture',
  model: 'Hermes 4',
  title: 'Quarterly analysis',
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
    { role: 'user', content: 'Compare the approved logistics plan with the latest inventory movement.' },
    {
      role: 'assistant',
      content: 'The plan remains on track. Rotterdam needs the closest review because its transfer window is narrower.'
    }
  ],
  pagination: { limit: 500, offset: 0, returned: 2 }
};

function jsonHeaders(): Record<string, string> {
  return { 'content-type': 'application/json' };
}

async function installSyntheticLiveBoundary(page: Page): Promise<void> {
  await page.route('**/api/auth/me', (route) =>
    route.fulfill({ status: 200, headers: jsonHeaders(), body: JSON.stringify(identity) })
  );
  await page.route('**/api/auth/ws-ticket', (route) =>
    route.fulfill({
      status: 200,
      headers: jsonHeaders(),
      body: JSON.stringify({ ticket: 'visual-ticket-placeholder', ttl_seconds: 30 })
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
          params: { type: 'gateway.ready', payload: { skin: 'visual-synthetic', change_events: true } }
        })
      );
    }, 0);
  });
}

for (const fixture of [
  { name: 'desktop-light', appearance: 'light' as const, viewport: { width: 1440, height: 960 } },
  { name: 'desktop-dark', appearance: 'dark' as const, viewport: { width: 1440, height: 960 } },
  { name: 'mobile-light', appearance: 'light' as const, viewport: { width: 390, height: 844 } },
  { name: 'mobile-dark', appearance: 'dark' as const, viewport: { width: 390, height: 844 } }
]) {
  test(`authenticated Chat matches the ${fixture.name} resting reference`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: fixture.appearance, reducedMotion: 'reduce' });
    await page.setViewportSize(fixture.viewport);
    await installSyntheticLiveBoundary(page);
    await page.goto('/');

    const workspace = page.getByRole('region', { name: 'Hermternal runtime workspace preview' });
    await expect(workspace).toHaveAttribute('data-appearance', fixture.appearance);
    await expect(page.getByRole('button', { name: 'Edit conversation title' })).toContainText(session.title);
    await expect(page.getByText(sessionMessages.messages[1].content)).toBeVisible();
    await expect(page.getByText('Generated · mock · just now')).toHaveCount(1);
    expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
    await expect(workspace).toHaveScreenshot(`live-chat-${fixture.name}.png`, {
      animations: 'disabled',
      caret: 'hide'
    });
  });
}

test('authenticated Chat reflows increased text without shrinking controls or clipping horizontally', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await installSyntheticLiveBoundary(page);
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Edit conversation title' })).toContainText(session.title);
  await page.addStyleTag({
    content: `
      .workspace-preview :is(.pill-label, .assistant-name, .assistant-model, .assistant-copy, .user-message p) {
        font-size: 20px !important;
        line-height: 28px !important;
      }
    `
  });

  const controls = page.locator('.mobile-title-island button, .mobile-mode-selector button');
  for (let index = 0; index < (await controls.count()); index += 1) {
    const box = await controls.nth(index).boundingBox();
    expect(box?.height).toBeGreaterThanOrEqual(40);
  }
  const overflow = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth
  }));
  expect(overflow.scrollWidth).toBeLessThanOrEqual(overflow.clientWidth + 1);
  await expect(page.getByText(sessionMessages.messages[1].content)).toBeVisible();
});

test('authenticated Chat uses the bounded intermediate family without horizontal overflow', async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 900 });
  await installSyntheticLiveBoundary(page);
  await page.goto('/');

  const workspace = page.getByRole('region', { name: 'Hermternal runtime workspace preview' });
  const conversation = workspace.locator('.conversation-panel');
  await expect(workspace.locator('.mobile-toolbar')).toBeVisible();
  await expect(workspace.locator('.workspace-mobile-status-bar')).toBeHidden();
  await expect(workspace.locator('.sidebar')).toBeHidden();
  await expect(workspace.locator('.desktop-inspector')).toBeHidden();
  expect((await conversation.boundingBox())?.width).toBe(720);
  expect(
    await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth
    }))
  ).toEqual({ clientWidth: 1024, scrollWidth: 1024 });
});

for (const compactFixture of [
  { name: 'narrow', viewport: { width: 390, height: 844 } },
  { name: 'intermediate', viewport: { width: 1024, height: 900 } }
]) {
  test(`authenticated ${compactFixture.name} Chat exposes the labeled mock inspector drawer by pointer and keyboard`, async ({
    page
  }) => {
    await page.setViewportSize(compactFixture.viewport);
    await installSyntheticLiveBoundary(page);
    await page.goto('/');
    await expect(page.getByRole('button', { name: 'Edit conversation title' })).toContainText(session.title);

    const openWorkspace = page.getByRole('button', { name: 'Open workspace' });
    const drawer = page.getByRole('dialog', { name: 'Workspace' });
    await expect(openWorkspace).toBeVisible();

    // A real click guards the separate hit region; keyboard-only activation
    // would not detect an overlapping mode-selector layer.
    await openWorkspace.click();
    await expect(drawer).toBeVisible();
    await expect(drawer.getByText('Generated · mock · just now')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(drawer).toBeHidden();
    await expect(openWorkspace).toBeFocused();

    await page.keyboard.press('Enter');
    await expect(drawer).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(drawer).toBeHidden();
    await expect(openWorkspace).toBeFocused();
  });
}
