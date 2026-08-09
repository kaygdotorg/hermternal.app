import { expect, test, type Locator, type Page } from '@playwright/test';

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
  // This route boundary is deliberately local and deterministic: it proves the
  // authenticated projection without live Hermes, credentials, or screenshot output.
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

async function openAuthenticatedChat(
  page: Page,
  viewport: { width: number; height: number },
  appearance: 'light' | 'dark' = 'light'
): Promise<Locator> {
  await page.emulateMedia({ colorScheme: appearance, reducedMotion: 'reduce' });
  await page.setViewportSize(viewport);
  await installSyntheticLiveBoundary(page);
  await page.goto('/');

  const workspace = page.getByRole('region', { name: 'Hermternal runtime workspace preview' });
  await expect(workspace).toBeVisible();
  await expect(workspace).toHaveAttribute('data-appearance', appearance);
  await expect(workspace).toHaveAttribute('data-mode-source', 'live');
  await expect(page.getByRole('button', { name: 'Edit conversation title' })).toContainText(session.title);
  await expect(page.getByText(sessionMessages.messages[1].content)).toBeVisible();
  return workspace;
}

async function expectEffectiveTarget(locator: Locator): Promise<void> {
  const target = await locator.evaluate((element) => {
    const box = element.getBoundingClientRect();
    const pointerExtension = getComputedStyle(element, '::before');
    return {
      width: Math.max(box.width, Number.parseFloat(pointerExtension.width) || 0),
      height: Math.max(box.height, Number.parseFloat(pointerExtension.height) || 0)
    };
  });
  // The Paper compact shell paints 40px mode segments but reserves a 44px
  // effective pointer target through the pseudo-element extension.
  expect(target.width).toBeGreaterThanOrEqual(44);
  expect(target.height).toBeGreaterThanOrEqual(44);
}

async function reachByTab(page: Page, target: Locator, maximumTabs = 64): Promise<void> {
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
  for (let index = 0; index < maximumTabs; index += 1) {
    await page.keyboard.press('Tab');
    if (await target.evaluate((element) => element === document.activeElement)) return;
  }
  throw new Error(`Keyboard focus did not reach ${await target.getAttribute('aria-label')}`);
}

async function expectNoHorizontalOverflow(page: Page): Promise<void> {
  const overflow = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth
  }));
  expect(overflow.scrollWidth).toBeLessThanOrEqual(overflow.clientWidth + 1);
}

test('authenticated Chat honors the Paper desktop geometry and dynamic viewport height', async ({ page }) => {
  const workspace = await openAuthenticatedChat(page, { width: 1440, height: 960 });
  const workspaceBox = await workspace.boundingBox();
  const grid = workspace.locator('.workspace-grid');
  const gridBox = await grid.boundingBox();
  const sidebarBox = await workspace.locator('.sidebar').boundingBox();
  const conversationBox = await workspace.locator('.conversation-panel').boundingBox();
  const inspectorBox = await workspace.locator('.desktop-inspector').boundingBox();

  expect(workspaceBox).not.toBeNull();
  expect(gridBox).not.toBeNull();
  expect(sidebarBox).not.toBeNull();
  expect(conversationBox).not.toBeNull();
  expect(inspectorBox).not.toBeNull();
  expect(workspaceBox?.width).toBe(1440);
  expect(workspaceBox?.height).toBe(960);

  const viewportContract = await workspace.evaluate((element) => {
    const style = getComputedStyle(element);
    return {
      height: style.height,
      minHeight: style.minHeight,
      overflow: style.overflow,
      viewportHeight: window.innerHeight
    };
  });
  expect(viewportContract).toEqual({
    height: '960px',
    minHeight: '0px',
    overflow: 'hidden',
    viewportHeight: 960
  });

  expect(gridBox?.x).toBe(workspaceBox?.x);
  expect(gridBox?.y).toBe(workspaceBox?.y);
  expect(gridBox?.width).toBe(1440);
  expect(gridBox?.height).toBe(928);
  expect(sidebarBox?.x).toBe((workspaceBox?.x ?? 0) + 16);
  expect(conversationBox?.x).toBe((workspaceBox?.x ?? 0) + 16 + 276 + 16);
  expect(inspectorBox?.x).toBe((workspaceBox?.x ?? 0) + 16 + 276 + 16 + 720 + 16);
  expect(sidebarBox?.y).toBe((workspaceBox?.y ?? 0) + 16);
  expect(conversationBox?.y).toBe((workspaceBox?.y ?? 0) + 16);
  expect(inspectorBox?.y).toBe((workspaceBox?.y ?? 0) + 16);
  expect(sidebarBox?.width).toBe(276);
  expect(conversationBox?.width).toBe(720);
  expect(inspectorBox?.width).toBe(380);
  expect(sidebarBox?.height).toBe(928);
  expect(conversationBox?.height).toBe(928);
  expect(inspectorBox?.height).toBe(928);

  const computedGrid = await grid.evaluate((element) => {
    const style = getComputedStyle(element);
    return { columns: style.gridTemplateColumns, rows: style.gridTemplateRows };
  });
  expect(computedGrid).toEqual({ columns: '276px 720px 380px', rows: '928px' });
  await expectNoHorizontalOverflow(page);
});

test('authenticated Chat keeps the exact desktop and narrow family boundaries', async ({ page }) => {
  for (const fixture of [
    { name: 'narrow', viewport: { width: 390, height: 844 } },
    { name: 'mobile-boundary', viewport: { width: 760, height: 844 } },
    { name: 'intermediate-boundary', viewport: { width: 761, height: 900 } },
    { name: 'desktop', viewport: { width: 1408, height: 900 } }
  ]) {
    const workspace = await openAuthenticatedChat(page, fixture.viewport);
    const conversation = workspace.locator('.conversation-panel');

    if (fixture.name === 'narrow' || fixture.name === 'mobile-boundary') {
      await expect(workspace.locator('.workspace-mobile-status-bar')).toBeVisible();
      await expect(workspace.locator('.mobile-toolbar')).toBeVisible();
      await expect(workspace.locator('.conversation-header')).toBeHidden();
      await expect(workspace.locator('.sidebar')).toBeHidden();
      await expect(workspace.locator('.desktop-inspector')).toBeHidden();
      expect((await conversation.boundingBox())?.width).toBe(fixture.viewport.width);
    } else if (fixture.name === 'intermediate-boundary') {
      await expect(workspace.locator('.workspace-mobile-status-bar')).toBeHidden();
      await expect(workspace.locator('.mobile-toolbar')).toBeVisible();
      await expect(workspace.locator('.conversation-header')).toBeHidden();
      await expect(workspace.locator('.sidebar')).toBeHidden();
      await expect(workspace.locator('.desktop-inspector')).toBeHidden();
      expect((await conversation.boundingBox())?.width).toBe(720);
    } else {
      await expect(workspace.locator('.workspace-mobile-status-bar')).toBeHidden();
      await expect(workspace.locator('.mobile-toolbar')).toBeHidden();
      await expect(workspace.locator('.conversation-header')).toBeVisible();
      await expect(workspace.locator('.sidebar')).toBeVisible();
      await expect(workspace.locator('.desktop-inspector')).toBeVisible();
      expect((await conversation.boundingBox())?.width).toBe(720);
    }

    await expectNoHorizontalOverflow(page);
  }
});

test('authenticated live Chat labels the inspector mock without replacing server timeline data', async ({ page }) => {
  const workspace = await openAuthenticatedChat(page, { width: 1440, height: 960 }, 'dark');
  const inspector = page.getByRole('complementary', { name: 'Workspace inspector' });

  await expect(inspector).toBeVisible();
  await expect(inspector).toContainText('Generated · mock · just now');
  await expect(inspector).toContainText('Delay signal · 12% · synthetic fixture');
  await expect(page.getByText(sessionMessages.messages[1].content)).toBeVisible();
  await expect(page.getByText('Quarterly inventory movement')).toHaveCount(0);
  await expect(workspace).toHaveAttribute('data-mode-source', 'live');
});

test('authenticated Chat keeps keyboard focus, modal restoration, and effective 44px targets', async ({ page }) => {
  const workspace = await openAuthenticatedChat(page, { width: 390, height: 844 });
  const conversations = page.getByRole('button', { name: 'Open conversations' });
  const title = page.getByRole('button', { name: 'Edit conversation title' });
  const modeControls = workspace.locator('.mobile-mode-selector button');

  await expect(conversations).toBeVisible();
  await expect(title).toBeVisible();
  await expect(modeControls).toHaveCount(2);
  await expectEffectiveTarget(conversations);
  await expectEffectiveTarget(title);
  await expectEffectiveTarget(page.getByRole('button', { name: 'Chat mode selected' }));
  await expectEffectiveTarget(page.getByRole('button', { name: 'Open terminal mode' }));

  await reachByTab(page, conversations);
  await expect(conversations).toBeFocused();
  await page.keyboard.press('Enter');
  const drawer = page.getByTestId('mobile-session-drawer');
  await expect(drawer).toBeVisible();
  await expect(drawer.locator('button:not([disabled])').first()).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(drawer).toBeHidden();
  await expect(conversations).toBeFocused();
  await expect(workspace.locator('.workspace-underlay')).not.toHaveAttribute('inert', '');
});

test('authenticated Chat honors reduced motion and text growth at the intermediate zoom-equivalent width', async ({ page }) => {
  const workspace = await openAuthenticatedChat(page, { width: 720, height: 900 });
  await page.addStyleTag({
    content: `
      .workspace-preview :is(.pill-label, .assistant-name, .assistant-model, .assistant-copy, .user-message p) {
        font-size: 20px !important;
        line-height: 28px !important;
      }
    `
  });

  const motion = await page.getByRole('button', { name: 'Chat mode selected' }).evaluate((element) => ({
    reducedMotion: matchMedia('(prefers-reduced-motion: reduce)').matches,
    transitionDuration: getComputedStyle(element).transitionDuration,
    transform: getComputedStyle(element).transform
  }));
  expect(motion.reducedMotion).toBe(true);
  expect(motion.transitionDuration.split(',').every((duration) => duration.trim() === '0s')).toBe(true);
  expect(motion.transform).toBe('none');

  const controls = workspace.locator('.mobile-title-island button, .mobile-mode-selector button');
  for (let index = 0; index < (await controls.count()); index += 1) {
    await expectEffectiveTarget(controls.nth(index));
  }
  await expect(page.getByText(sessionMessages.messages[1].content)).toBeVisible();
  await expectNoHorizontalOverflow(page);
});
