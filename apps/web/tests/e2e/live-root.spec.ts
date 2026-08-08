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

test('native field Enter preserves live values while failing closed without navigation, requests, storage, or serialization', async ({ page }) => {
  const cdp = await page.context().newCDPSession(page);
  const requestUrls: string[] = [];
  const navigationUrls: string[] = [];
  const onRequest = (request: { isNavigationRequest(): boolean; url(): string }) => {
    requestUrls.push(request.url());
    if (request.isNavigationRequest()) navigationUrls.push(request.url());
  };
  page.on('request', onRequest);

  try {
    await page.route('**/api/auth/me', async (route) => {
      await route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ detail: 'not authenticated' })
      });
    });
    await page.route('**/api/auth/providers', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          providers: [{ name: 'basic', display_name: 'Disposable Basic', supports_password: true }]
        })
      });
    });

    await page.goto('/');
    await page.getByRole('button', { name: 'Disposable Basic' }).click();
    const form = page.getByRole('form', { name: 'Hermes password sign in' });
    await expect(form).toHaveAttribute('data-field-ownership', 'ready');

    const originalUrl = page.url();
    const storageBefore = await page.context().storageState();
    const username = page.getByLabel('Username');
    const password = page.getByRole('textbox', { name: 'Password' });
    const usernameValue = 'native-field-enter-user';
    const passwordValue = 'native-field-enter-password';
    await cdp.send('Emulation.setScriptExecutionDisabled', { value: true });
    await username.fill(usernameValue);
    await password.fill(passwordValue);

    // The browser protocol captures request and navigation evidence outside the
    // disabled page runtime. Input Enter has no running handler or native reset
    // target, so retaining the live control values is an allowed outcome.
    requestUrls.length = 0;
    navigationUrls.length = 0;
    await password.press('Enter');

    await expect(username).toHaveValue(usernameValue);
    await expect(password).toHaveValue(passwordValue);
    expect(page.url()).toBe(originalUrl);
    expect(navigationUrls).toEqual([]);
    expect(requestUrls).toEqual([]);
    expect(await page.context().storageState()).toEqual(storageBefore);

    // `page.content()` is a browser-observable serialized-DOM snapshot, not a
    // callback in the disabled page. The live properties may retain values, but
    // neither credential may be serialized into the document markup.
    const serializedDom = await page.content();
    expect(serializedDom).not.toContain(usernameValue);
    expect(serializedDom).not.toContain(passwordValue);
  } finally {
    page.off('request', onRequest);
  }
});
