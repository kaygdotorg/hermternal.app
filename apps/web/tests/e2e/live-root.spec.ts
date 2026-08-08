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

test('native field Enter preserves live values while failing closed without navigation, requests, storage, or credential serialization', async ({ page }) => {
  const cdp = await page.context().newCDPSession(page);
  let requestCount = 0;
  let navigationCount = 0;
  const onRequest = (request: { isNavigationRequest(): boolean }) => {
    requestCount += 1;
    if (request.isNavigationRequest()) navigationCount += 1;
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
    const storageSummary = async (): Promise<{ cookieCount: number; originCount: number; localStorageEntryCount: number }> => {
      const storage = await page.context().storageState();
      return {
        cookieCount: storage.cookies.length,
        originCount: storage.origins.length,
        localStorageEntryCount: storage.origins.reduce((count, origin) => count + origin.localStorage.length, 0)
      };
    };
    const storageBefore = await storageSummary();
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
    requestCount = 0;
    navigationCount = 0;
    await password.press('Enter');

    const nativeValuesRemain =
      (await username.inputValue()) === usernameValue && (await password.inputValue()) === passwordValue;
    expect(nativeValuesRemain).toBe(true);
    expect(page.url()).toBe(originalUrl);
    expect(navigationCount).toBe(0);
    expect(requestCount).toBe(0);
    const storageUnchanged = JSON.stringify(await storageSummary()) === JSON.stringify(storageBefore);
    expect(storageUnchanged).toBe(true);

    // Derive only a credential-presence count inside the browser. This is not
    // a screenshot or complete-DOM redaction claim, and raw markup never leaves
    // the page evaluation or remains in the test trace.
    const serializedCredentialCount = await page.evaluate(
      ([usernameText, passwordText]) =>
        [usernameText, passwordText].reduce(
          (count, value) => count + Number(document.documentElement.outerHTML.includes(value)),
          0
        ),
      [usernameValue, passwordValue]
    );
    expect(serializedCredentialCount).toBe(0);
  } finally {
    page.off('request', onRequest);
    await page.unroute('**/api/auth/me').catch(() => undefined);
    await page.unroute('**/api/auth/providers').catch(() => undefined);
    await cdp.send('Emulation.setScriptExecutionDisabled', { value: false }).catch(() => undefined);
    await cdp.detach().catch(() => undefined);
  }
});
