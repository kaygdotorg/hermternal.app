import { expect, test, type Locator, type Page } from '@playwright/test';

const identity = {
  user_id: 'e2e-user',
  email: 'e2e@example.invalid',
  display_name: 'E2E User',
  org_id: 'e2e-org',
  provider: 'e2e-provider',
  expires_at: 4_294_967_295
};

const session = {
  id: 'e2e-session-0001',
  source: 'e2e',
  model: 'Hermes 4',
  title: 'E2E current session',
  started_at: 1,
  ended_at: null,
  last_active: 2,
  is_active: true,
  message_count: 0,
  tool_call_count: 0,
  input_tokens: 0,
  output_tokens: 0,
  preview: null
};

const sessionMessages = {
  session_id: session.id,
  messages: [],
  pagination: { limit: 500, offset: 0, returned: 0 }
};

function jsonHeaders(): Record<string, string> {
  return { 'content-type': 'application/json' };
}

async function reachByTab(page: Page, target: Locator, maximumTabs = 24): Promise<void> {
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
  for (let index = 0; index < maximumTabs; index += 1) {
    await page.keyboard.press('Tab');
    if (await target.evaluate((element) => element === document.activeElement)) return;
  }
  throw new Error(`Keyboard focus did not reach ${await target.getAttribute('aria-label')}`);
}

async function expectMinimumTarget(locator: Locator): Promise<void> {
  const target = await locator.evaluate((element) => {
    const box = element.getBoundingClientRect();
    const pointerExtension = getComputedStyle(element, '::before');
    return {
      width: Math.max(box.width, Number.parseFloat(pointerExtension.width) || 0),
      height: Math.max(box.height, Number.parseFloat(pointerExtension.height) || 0)
    };
  });
  // Paper uses a 40px visible segment with a 44px pseudo-element pointer box.
  // Measure the effective target instead of requiring the painted shell to grow.
  expect(target.width).toBeGreaterThanOrEqual(44);
  expect(target.height).toBeGreaterThanOrEqual(44);
}

type TerminalTicketMode = 'ready' | 'delayed' | 'failed';

async function installSyntheticLiveComposition(page: Page, terminalTicketMode: TerminalTicketMode = 'ready') {
  let ticketRequests = 0;
  let releaseTerminalTicket!: () => void;
  const terminalTicketRelease = new Promise<void>((resolve) => { releaseTerminalTicket = resolve; });

  await page.route('**/api/auth/me', (route) =>
    route.fulfill({ status: 200, headers: jsonHeaders(), body: JSON.stringify(identity) })
  );
  await page.route('**/api/auth/ws-ticket', async (route) => {
    ticketRequests += 1;
    if (ticketRequests === 2 && terminalTicketMode === 'delayed') await terminalTicketRelease;
    if (ticketRequests === 2 && terminalTicketMode === 'failed') {
      await route.fulfill({ status: 503, headers: jsonHeaders(), body: JSON.stringify({ code: 'synthetic-unavailable' }) });
      return;
    }
    await route.fulfill({
      status: 200,
      headers: jsonHeaders(),
      body: JSON.stringify({ ticket: `synthetic-ticket-${ticketRequests}`, ttl_seconds: 30 })
    });
  });
  await page.route('**/api/sessions**', (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (request.method() === 'GET' && url.pathname === '/api/sessions') {
      void route.fulfill({ status: 200, headers: jsonHeaders(), body: JSON.stringify({ sessions: [session], total: 1, limit: 100, offset: 0 }) });
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
    void route.fulfill({ status: 405, headers: jsonHeaders(), body: JSON.stringify({}) });
  });
  await page.routeWebSocket('**', (socket) => {
    const pathname = new URL(socket.url()).pathname;
    if (pathname === '/api/ws') {
      socket.onMessage((message) => {
        const frame = JSON.parse(String(message)) as { id?: string; method?: string };
        if (frame.method === 'session.resume') {
          socket.send(JSON.stringify({ jsonrpc: '2.0', id: frame.id, result: { session_id: session.id, restored: true } }));
        }
      });
      setTimeout(() => socket.send(JSON.stringify({
        jsonrpc: '2.0', method: 'event', params: { type: 'gateway.ready', payload: { skin: 'terminal-proof-synthetic', change_events: true } }
      })), 0);
      return;
    }
    if (pathname === '/api/pty') {
      // This proof uses only the socket lifecycle. It never sends, reads, stores,
      // snapshots, or reports terminal output bytes.
      socket.onMessage(() => undefined);
      return;
    }
    void socket.close({ code: 1008, reason: 'unsupported synthetic socket' });
  });

  return { releaseTerminalTicket };
}

async function waitForSyntheticSession(page: Page): Promise<void> {
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Edit conversation title' })).toContainText(session.title);
}

async function expectNoHorizontalClipping(page: Page, controls: readonly Locator[]): Promise<void> {
  const viewport = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth
  }));
  expect(viewport.scrollWidth).toBeLessThanOrEqual(viewport.clientWidth + 1);
  for (const control of controls) {
    await expect(control).toBeVisible();
    const box = await control.boundingBox();
    expect(box).not.toBeNull();
    expect(box!.x).toBeGreaterThanOrEqual(0);
    expect(box!.x + box!.width).toBeLessThanOrEqual(viewport.clientWidth + 1);
  }
}

async function expectVisibleHitTestFocus(locator: Locator): Promise<void> {
  await locator.focus();
  await expect(locator).toBeFocused();
  expect(await locator.evaluate((element) => {
    const rect = element.getBoundingClientRect();
    const hit = document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2);
    const style = getComputedStyle(element);
    return {
      focusVisible: element.matches(':focus-visible'),
      hitTestVisible: Boolean(hit && (hit === element || element.contains(hit))),
      outlineVisible: style.outlineStyle !== 'none' && Number.parseFloat(style.outlineWidth) > 0
    };
  })).toEqual({ focusVisible: true, hitTestVisible: true, outlineVisible: true });
}

test('narrow production route keeps one current session across accessible Chat and Terminal mode round trips', async ({ page }) => {
  let ticketRequests = 0;
  let chatConnections = 0;
  let terminalConnections = 0;
  let resumeRequests = 0;
  let createRequests = 0;

  await page.route('**/api/auth/me', (route) =>
    route.fulfill({ status: 200, headers: jsonHeaders(), body: JSON.stringify(identity) })
  );
  await page.route('**/api/auth/ws-ticket', (route) => {
    ticketRequests += 1;
    const ticket = `e2e-ticket-${ticketRequests}`;
    void route.fulfill({
      status: 200,
      headers: jsonHeaders(),
      body: JSON.stringify({ ticket, ttl_seconds: 30 })
    });
  });
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
    if (request.method() === 'POST') {
      createRequests += 1;
      void route.fulfill({ status: 405, headers: jsonHeaders(), body: JSON.stringify({}) });
      return;
    }
    void route.continue();
  });

  await page.routeWebSocket('**', (socket) => {
    const pathname = new URL(socket.url()).pathname;
    if (pathname === '/api/ws') {
      chatConnections += 1;
      socket.onMessage((message) => {
        const frame = JSON.parse(String(message)) as { id?: string; method?: string };
        if (frame.method === 'session.resume') {
          resumeRequests += 1;
          socket.send(
            JSON.stringify({
              jsonrpc: '2.0',
              id: frame.id,
              result: { session_id: session.id, restored: true }
            })
          );
        }
        if (frame.method === 'session.create') createRequests += 1;
      });
      // Deliver the required server-first readiness frame after the browser has
      // completed its socket-open turn; an immediate synthetic send can race the
      // client's message listener on a fresh production preview.
      setTimeout(() => {
        socket.send(
          JSON.stringify({
            jsonrpc: '2.0',
            method: 'event',
            params: {
              type: 'gateway.ready',
              payload: { skin: 'e2e-synthetic', change_events: true }
            }
          })
        );
      }, 0);
      return;
    }
    if (pathname === '/api/pty') {
      terminalConnections += 1;
      // The PTY bridge only needs the socket-open lifecycle for this synthetic
      // browser proof. No terminal bytes are retained or asserted here.
      socket.onMessage(() => undefined);
      return;
    }
    void socket.close({ code: 1008, reason: 'unsupported synthetic socket' });
  });

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');

  const workspace = page.getByRole('region', { name: 'Hermternal runtime workspace preview' });
  const underlay = page.getByTestId('workspace-underlay');
  const chatSelected = page.getByRole('button', { name: 'Chat mode selected' });
  const openTerminal = page.getByRole('button', { name: 'Open terminal mode' });

  await expect(workspace).toBeVisible();
  // The route paints a bounded empty preview before authenticated history wins.
  // Wait for the mocked durable session so mode assertions cannot hit that shell.
  await expect(page.getByRole('button', { name: 'Edit conversation title' })).toContainText(session.title);
  await expect(chatSelected).toBeVisible();
  await expect(openTerminal).toBeVisible();
  await expect(chatSelected).toHaveAttribute('aria-pressed', 'true');
  await expect(openTerminal).toHaveAttribute('aria-pressed', 'false');
  await expectMinimumTarget(chatSelected);
  await expectMinimumTarget(openTerminal);

  // The narrow toolbar is part of the keyboard contract, not a touch-only
  // escape hatch. Enter and Space exercise both native button activation paths.
  await reachByTab(page, openTerminal);
  await expect(openTerminal).toBeFocused();
  await page.keyboard.press('Enter');

  const terminalSurface = page.getByTestId('terminal-surface');
  const terminalSelected = page.getByRole('button', { name: 'Terminal mode selected' });
  const openChat = page.getByRole('button', { name: 'Open chat mode' });
  await expect(terminalSurface).toHaveAttribute('data-terminal-state', 'open');
  await expect(terminalSelected).toBeVisible();
  await expect(openChat).toBeVisible();
  await expect(terminalSelected).toHaveAttribute('aria-pressed', 'true');
  await expect(openChat).toHaveAttribute('aria-pressed', 'false');
  await expectMinimumTarget(terminalSelected);
  await expectMinimumTarget(openChat);
  await expect(underlay).toHaveAttribute('inert', '');
  await expect(underlay).toHaveAttribute('aria-hidden', 'true');
  await expect(terminalSurface).not.toHaveCSS('background-color', 'rgba(0, 0, 0, 0)');

  await reachByTab(page, openChat);
  await expect(openChat).toBeFocused();
  await page.evaluate(() => {
    const layer = document.querySelector<HTMLElement>('.terminal-layer');
    const result = { chatFocusWasVisible: false, terminalWasVisibleAtChatFocus: false };
    const originalFocus = HTMLElement.prototype.focus;
    Object.assign(window, {
      __e2eChatFocusHandoff: result,
      __e2eRestoreFocus: () => { HTMLElement.prototype.focus = originalFocus; }
    });
    // The escape pill is already focused for Space activation, so calling focus()
    // again need not emit focusin. Observe the handoff invocation itself to prove
    // that its target is visible while Terminal remains painted.
    HTMLElement.prototype.focus = function (options?: FocusOptions): void {
      if (this.matches('button[aria-label="Open chat mode"], button[aria-label="Chat mode selected"]')) {
        const rect = this.getBoundingClientRect();
        const hit = document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2);
        result.chatFocusWasVisible = Boolean(hit && (hit === this || this.contains(hit)));
        result.terminalWasVisibleAtChatFocus = layer !== null && getComputedStyle(layer).visibility !== 'hidden';
      }
      originalFocus.call(this, options);
    };
  });
  await page.keyboard.press('Space');

  await expect(terminalSurface).toBeHidden();
  await expect(chatSelected).toBeVisible();
  await expect(chatSelected).toHaveAttribute('aria-pressed', 'true');
  await expect(chatSelected).toBeFocused();
  await expect(underlay).not.toHaveAttribute('inert', '');
  await expect(underlay).not.toHaveAttribute('aria-hidden', 'true');
  expect(
    await page.evaluate(
      () =>
        (window as typeof window & {
          __e2eChatFocusHandoff?: { chatFocusWasVisible: boolean; terminalWasVisibleAtChatFocus: boolean };
        }).__e2eChatFocusHandoff
    )
  ).toEqual({ chatFocusWasVisible: true, terminalWasVisibleAtChatFocus: false });
  await page.evaluate(() => {
    (window as typeof window & { __e2eRestoreFocus?: () => void }).__e2eRestoreFocus?.();
  });

  await reachByTab(page, openTerminal);
  await page.keyboard.press('Enter');
  await expect(terminalSurface).toHaveAttribute('data-terminal-state', 'open');
  await expect(terminalSelected).toBeVisible();

  // Narrow uses the selector above Terminal. Desktop instead returns focus to a
  // Chat control in the covered underlay, so assert hit-test visibility at the
  // instant the real handoff calls focus rather than trusting a layout rect.
  // The exact Paper desktop family begins when all 276 / 720 / 380 columns fit;
  // narrower widths use the compact selector and modal secondary surfaces.
  await page.setViewportSize({ width: 1440, height: 800 });
  // The inactive Desktop control is intentionally behind the Terminal-owned
  // accessibility boundary. Use its stable DOM selector until the handoff flips
  // it to the selected, released Chat control.
  const desktopChat = underlay.locator('button[aria-label="Chat mode selected"]');
  const returnToChat = page.getByRole('button', { name: 'Return to Chat mode' });
  await expect(returnToChat).toBeVisible();
  await returnToChat.focus();
  await page.evaluate(() => {
    const layer = document.querySelector<HTMLElement>('.terminal-layer');
    const result = { focused: false, hitTestVisible: false, terminalHiddenAtFocus: false };
    const originalFocus = HTMLElement.prototype.focus;
    Object.assign(window, {
      __e2eDesktopChatFocusHandoff: result,
      __e2eRestoreDesktopFocus: () => { HTMLElement.prototype.focus = originalFocus; }
    });
    HTMLElement.prototype.focus = function (options?: FocusOptions): void {
      if (this.matches('[data-testid="workspace-underlay"] button[aria-label="Chat mode selected"]')) {
        const rect = this.getBoundingClientRect();
        const hit = document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2);
        result.focused = true;
        result.hitTestVisible = Boolean(hit && (hit === this || this.contains(hit)));
        result.terminalHiddenAtFocus = layer !== null && getComputedStyle(layer).visibility === 'hidden';
      }
      originalFocus.call(this, options);
    };
  });
  await page.keyboard.press('Space');
  await expect(terminalSurface).toBeHidden();
  await expect(desktopChat).toBeFocused();
  await expect(underlay).not.toHaveAttribute('inert', '');
  expect(
    await page.evaluate(
      () => (window as typeof window & {
        __e2eDesktopChatFocusHandoff?: { focused: boolean; hitTestVisible: boolean; terminalHiddenAtFocus: boolean };
      }).__e2eDesktopChatFocusHandoff
    )
  ).toEqual({ focused: true, hitTestVisible: true, terminalHiddenAtFocus: true });
  await page.evaluate(() => {
    (window as typeof window & { __e2eRestoreDesktopFocus?: () => void }).__e2eRestoreDesktopFocus?.();
  });

  expect(createRequests).toBe(0);
  expect(chatConnections).toBe(1);
  expect(resumeRequests).toBe(1);
  expect(terminalConnections).toBe(1);
  expect(ticketRequests).toBe(2);
});

const terminalActiveLayouts = [
  { name: 'desktop', viewport: { width: 1440, height: 900 }, forcedColors: false },
  { name: 'narrow 390 by 844', viewport: { width: 390, height: 844 }, forcedColors: false },
  { name: 'forced colors', viewport: { width: 1280, height: 800 }, forcedColors: true },
  { name: '640 CSS-pixel zoom equivalent', viewport: { width: 640, height: 900 }, forcedColors: false }
] as const;

for (const layout of terminalActiveLayouts) {
  test(`Terminal-active ${layout.name} keeps actions, status, focus, and escape paths discoverable`, async ({ page }) => {
    await page.setViewportSize(layout.viewport);
    await page.emulateMedia({ forcedColors: layout.forcedColors ? 'active' : 'none', reducedMotion: 'reduce' });
    await installSyntheticLiveComposition(page);
    await waitForSyntheticSession(page);

    const openTerminal = page.getByRole('button', { name: 'Open terminal mode' });
    await reachByTab(page, openTerminal);
    await page.keyboard.press('Enter');

    const terminal = page.getByRole('region', { name: 'Terminal workspace' });
    const terminalSurface = page.getByTestId('terminal-surface');
    const status = terminal.locator('.terminal-state-bar');
    const returnToChat = page.getByRole('button', { name: 'Return to Chat mode' });
    const detach = page.getByRole('button', { name: 'Detach terminal' });
    const close = page.getByRole('button', { name: 'Close terminal' });
    const underlay = page.getByTestId('workspace-underlay');

    await expect(terminalSurface).toHaveAttribute('data-terminal-state', 'open');
    await expect(status).toContainText('Open');
    await expect(status).toContainText('Attached · input enabled');
    await expect(status).toHaveAttribute('aria-live', 'polite');
    await expect(terminal).toHaveAccessibleName('Terminal workspace');
    await expect(underlay).toHaveAttribute('inert', '');
    await expect(underlay).toHaveAttribute('aria-hidden', 'true');
    await expectNoHorizontalClipping(page, [returnToChat, detach, close]);
    await expectMinimumTarget(returnToChat);
    await expectMinimumTarget(detach);
    await expectMinimumTarget(close);
    await expectVisibleHitTestFocus(returnToChat);

    // Forced-colors emulation proves that semantic borders and focus remain
    // discoverable. It does not claim a particular OS high-contrast palette.
    if (layout.forcedColors) {
      await expect(terminal.locator('.terminal-state-bar')).toHaveCSS('border-top-style', 'solid');
      await expect(terminal.locator('.terminal-viewport')).toHaveCSS('border-top-style', 'solid');
    }

    // Chromium has no stable cross-platform browser-zoom API. A 640 CSS-pixel
    // layout viewport is the reviewed 200% zoom reflow equivalent; this does not
    // claim browser chrome, device-scale, or zoom-engine behavior.
    if (layout.viewport.width === 640) {
      expect(await page.evaluate(() => document.documentElement.clientWidth)).toBe(640);
      expect(await page.evaluate(() => getComputedStyle(document.documentElement).zoom)).toBe('1');
    }

    await page.keyboard.press('Escape');
    await expect(returnToChat).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(detach).toBeFocused();
    await page.keyboard.press('Shift+Tab');
    await expect(returnToChat).toBeFocused();

    // Pointer activation proves the escape does not depend on keyboard focus.
    await returnToChat.click();
    await expect(terminalSurface).toBeHidden();
    await expect(underlay).not.toHaveAttribute('inert', '');
    await expect(underlay).not.toHaveAttribute('aria-hidden', 'true');
    const chatSelected = page.getByRole('button', { name: 'Chat mode selected' });
    await expect(chatSelected).toBeFocused();
    await expectVisibleHitTestFocus(chatSelected);
  });
}

test('Terminal status exposes connecting and fixed failure recovery without output retention or a focus trap', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const pending = await installSyntheticLiveComposition(page, 'delayed');
  await waitForSyntheticSession(page);
  await page.getByRole('button', { name: 'Open terminal mode' }).click();

  const terminal = page.getByRole('region', { name: 'Terminal workspace' });
  const terminalSurface = page.getByTestId('terminal-surface');
  const status = terminal.locator('.terminal-state-bar');
  await expect(terminalSurface).toHaveAttribute('data-terminal-state', 'connecting');
  await expect(status).toContainText('Connecting');
  await expect(status).toContainText('Current session · input paused');
  await expect(status).toHaveAttribute('aria-live', 'polite');
  await expect(terminal).not.toContainText('terminal-proof-synthetic');

  pending.releaseTerminalTicket();
  await expect(terminalSurface).toHaveAttribute('data-terminal-state', 'open');
  await expect(status).toContainText('Attached · input enabled');
  // The production browser composition is intentionally legacy PTY mode and
  // exposes no attach identity, so reconnecting is not an applicable live-route
  // state. Its status semantics remain covered at the TerminalSurface boundary.
  await expect(page.getByRole('button', { name: 'Reconnect terminal' })).toHaveCount(0);

  await page.getByRole('button', { name: 'Return to Chat mode' }).click();
  await expect(terminalSurface).toBeHidden();
});

test('Terminal ticket failure keeps a visible keyboard recovery action and stable failure status', async ({ page }) => {
  await page.setViewportSize({ width: 640, height: 900 });
  await installSyntheticLiveComposition(page, 'failed');
  await waitForSyntheticSession(page);
  await page.getByRole('button', { name: 'Open terminal mode' }).click();

  const terminal = page.getByRole('region', { name: 'Terminal workspace' });
  const terminalSurface = page.getByTestId('terminal-surface');
  const status = terminal.locator('.terminal-state-bar');
  const returnToChat = page.getByRole('button', { name: 'Return to Chat mode' });
  await expect(terminalSurface).toHaveAttribute('data-terminal-state', 'failed');
  await expect(status).toContainText('Failed');
  await expect(status).toContainText('Terminal attach failed · Chat remains available');
  await expectNoHorizontalClipping(page, [returnToChat]);
  await expectMinimumTarget(returnToChat);
  await reachByTab(page, returnToChat);
  await expectVisibleHitTestFocus(returnToChat);
  await page.keyboard.press('Space');
  await expect(terminalSurface).toBeHidden();
  await expect(page.getByRole('button', { name: 'Chat mode selected' })).toBeFocused();
});
