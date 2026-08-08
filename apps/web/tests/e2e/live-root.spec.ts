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

test('native field Enter dispatches no formdata event after script execution stops', async ({ page }) => {
  const cdp = await page.context().newCDPSession(page);
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

  await form.evaluate((element) => {
    const evidence: { eventCount: number; entries: Array<[string, string]> | null } = {
      eventCount: 0,
      entries: null
    };
    (element as HTMLFormElement).addEventListener('formdata', (event) => {
      evidence.eventCount += 1;
      evidence.entries = [...event.formData.entries()].map(([name, value]) => [
        name,
        typeof value === 'string' ? value : value.name
      ]);
    });
    (window as Window & {
      __authFormDataEvidence?: { eventCount: number; entries: Array<[string, string]> | null };
    }).__authFormDataEvidence = evidence;
  });

  const username = page.getByLabel('Username');
  const password = page.getByRole('textbox', { name: 'Password' });
  const usernameValue = 'native-formdata-user';
  const passwordValue = 'native-formdata-password';
  await username.fill(usernameValue);
  await password.fill(passwordValue);
  await cdp.send('Emulation.setScriptExecutionDisabled', { value: true });
  await password.press('Enter');

  const evidence = await page.evaluate(
    () =>
      (window as Window & {
        __authFormDataEvidence?: { eventCount: number; entries: Array<[string, string]> | null };
      }).__authFormDataEvidence ?? { eventCount: 0, entries: null }
  );
  // `entries: []` would prove an empty constructed FormData. `entries: null`
  // paired with zero events records the actual Chromium result: no FormData
  // construction occurred for field Enter with script execution disabled.
  expect(evidence).toEqual({ eventCount: 0, entries: null });
  await expect(username).toHaveValue(usernameValue);
  await expect(password).toHaveValue(passwordValue);
});
