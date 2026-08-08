import { expect, test } from '@playwright/test';

test('normal root verifies identity and discovers password providers', async ({ page }) => {
  const requests: string[] = [];

  await page.route('**/api/auth/me', async (route) => {
    requests.push(`${route.request().method()} /api/auth/me`);
    await route.fulfill({
      status: 401,
      contentType: 'application/json',
      body: JSON.stringify({ detail: 'not authenticated' })
    });
  });
  await page.route('**/api/auth/providers', async (route) => {
    requests.push(`${route.request().method()} /api/auth/providers`);
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        providers: [{ name: 'basic', display_name: 'Disposable Basic', supports_password: true }]
      })
    });
  });

  await page.goto('/');

  await expect(page.getByRole('button', { name: 'Disposable Basic' })).toBeVisible();
  expect(requests).toEqual(['GET /api/auth/me', 'GET /api/auth/providers']);
  await expect(page.getByTestId('status-success')).toHaveCount(0);
});

test('authenticated root forwards one visible Sign out activation through the session lifecycle', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 960 });
  const requests: string[] = [];
  let meRequests = 0;
  let logoutRequests = 0;
  let releaseLogout!: () => void;
  const logoutGate = new Promise<void>((resolve) => {
    releaseLogout = resolve;
  });

  await page.route('**/api/auth/me', async (route) => {
    meRequests += 1;
    requests.push(`${route.request().method()} /api/auth/me`);
    if (meRequests === 1) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          user_id: 'e2e-user',
          email: 'logout@example.test',
          display_name: 'Logout test',
          org_id: 'e2e-org',
          provider: 'basic',
          expires_at: 2_000_000_000
        })
      });
      return;
    }
    await route.fulfill({
      status: 401,
      contentType: 'application/json',
      body: JSON.stringify({ detail: 'signed out' })
    });
  });
  await page.route('**/api/sessions**', async (route) => {
    requests.push(`${route.request().method()} /api/sessions`);
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ sessions: [] })
    });
  });
  await page.route('**/api/auth/providers', async (route) => {
    requests.push(`${route.request().method()} /api/auth/providers`);
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ providers: [] })
    });
  });
  await page.route('**/auth/logout', async (route) => {
    logoutRequests += 1;
    requests.push(`${route.request().method()} /auth/logout`);
    await logoutGate;
    await route.fulfill({ status: 302, headers: { location: '/login' }, body: '' });
  });

  await page.goto('/');
  const trigger = page.getByRole('button', { name: 'Open account menu' });
  await expect(trigger).toBeVisible();
  await trigger.click();
  await expect(page.getByRole('menu', { name: 'Account menu' })).toBeVisible();
  const signOut = page.getByRole('menuitem', { name: 'Sign out' });
  await expect(signOut).toBeVisible();

  await signOut.click();
  await expect.poll(() => logoutRequests).toBe(1);
  await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'logout-pending');
  await expect(page.getByRole('heading', { name: 'Signing out' })).toBeVisible();
  expect(requests.filter((request) => request === 'POST /auth/logout')).toHaveLength(1);
  expect(requests.filter((request) => request === 'GET /api/sessions')).toHaveLength(1);

  // Playwright's intercepted manual redirects are exposed as an opaque
  // redirect in Chromium. The browser-auth unit tests cover the exact
  // `302 Location: /login` contract; this root test keeps the request gated
  // long enough to prove the visible callback enters the shared pending state,
  // then confirms the existing dedicated recovery branch.
  releaseLogout();
  await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'logout-failed');
  expect(meRequests).toBe(1);
  expect(requests).toEqual(['GET /api/auth/me', 'GET /api/sessions', 'POST /auth/logout']);
});
