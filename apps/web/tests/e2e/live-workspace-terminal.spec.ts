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

  // At 1280px the approved intermediate layout keeps its compact mode
  // selector above Terminal. The handoff must target its visible Chat control,
  // not the hidden ConversationHeader copy in the underlay.
  await page.setViewportSize({ width: 1280, height: 800 });
  const intermediateModeSelector = page.getByTestId('mobile-mode-selector');
  const intermediateChat = intermediateModeSelector.locator('button:first-child');
  await expect(intermediateModeSelector).toBeVisible();
  await expect(intermediateChat).toBeVisible();
  await expect(intermediateChat).toHaveAttribute('aria-label', 'Open chat mode');
  await expect(intermediateChat).toHaveAttribute('aria-pressed', 'false');
  const returnToChat = page.getByRole('button', { name: 'Return to Chat mode' });
  await expect(returnToChat).toBeVisible();
  await returnToChat.focus();
  await page.evaluate(() => {
    const layer = document.querySelector<HTMLElement>('.terminal-layer');
    const result = { focused: false, hitTestVisible: false, terminalHiddenAtFocus: false };
    const originalFocus = HTMLElement.prototype.focus;
    Object.assign(window, {
      __e2eIntermediateChatFocusHandoff: result,
      __e2eRestoreIntermediateFocus: () => { HTMLElement.prototype.focus = originalFocus; }
    });
    HTMLElement.prototype.focus = function (options?: FocusOptions): void {
      if (this.matches('[data-testid="mobile-mode-selector"] button[aria-label="Chat mode selected"]')) {
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
  await expect(intermediateChat).toHaveAttribute('aria-label', 'Chat mode selected');
  await expect(intermediateChat).toHaveAttribute('aria-pressed', 'true');
  await expect(intermediateChat).toBeFocused();
  await expect(underlay).not.toHaveAttribute('inert', '');
  expect(
    await page.evaluate(
      () => (window as typeof window & {
        __e2eIntermediateChatFocusHandoff?: { focused: boolean; hitTestVisible: boolean; terminalHiddenAtFocus: boolean };
      }).__e2eIntermediateChatFocusHandoff
    )
  ).toEqual({ focused: true, hitTestVisible: true, terminalHiddenAtFocus: true });
  await page.evaluate(() => {
    (window as typeof window & { __e2eRestoreIntermediateFocus?: () => void }).__e2eRestoreIntermediateFocus?.();
  });

  expect(createRequests).toBe(0);
  expect(chatConnections).toBe(1);
  expect(resumeRequests).toBe(1);
  expect(terminalConnections).toBe(1);
  expect(ticketRequests).toBe(2);
});
