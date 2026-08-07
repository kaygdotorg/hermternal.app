import { expect, test } from '@playwright/test';

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

test('normal route keeps one current session across Chat and Terminal mode round trips', async ({ page }) => {
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
    const body = ticketRequests === 1 ? { ticket, ttl_seconds: 30 } : { ticket };
    void route.fulfill({
      status: 200,
      headers: jsonHeaders(),
      body: JSON.stringify(body)
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

  await page.goto('/');
  await expect(page.getByRole('region', { name: 'Hermternal runtime workspace preview' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Chat mode selected' })).toBeVisible();

  await page.getByRole('button', { name: 'Open terminal mode' }).click();
  await expect(page.getByRole('button', { name: 'Terminal mode selected' })).toBeVisible();
  await expect(page.getByTestId('terminal-surface')).toHaveAttribute('data-terminal-state', 'open');

  await page.getByRole('button', { name: 'Switch to Chat mode' }).click();
  await expect(page.getByRole('button', { name: 'Chat mode selected' })).toBeVisible();

  await page.getByRole('button', { name: 'Open terminal mode' }).click();
  await expect(page.getByRole('button', { name: 'Terminal mode selected' })).toBeVisible();
  await expect(page.getByTestId('terminal-surface')).toHaveAttribute('data-terminal-state', 'open');

  expect(createRequests).toBe(0);
  expect(chatConnections).toBe(1);
  expect(resumeRequests).toBe(1);
  expect(terminalConnections).toBe(1);
  expect(ticketRequests).toBe(2);
});
