import { expect, test } from '@playwright/test';

test('the static shell makes no cross-origin requests', async ({ page, baseURL }) => {
  const unexpectedRequests: string[] = [];
  const expectedOrigin = new URL(baseURL ?? 'http://127.0.0.1:4173').origin;

  await page.route('**/*', async (route) => {
    const requestUrl = new URL(route.request().url());
    if (requestUrl.origin !== expectedOrigin) {
      unexpectedRequests.push(requestUrl.href);
      await route.abort();
      return;
    }
    await route.continue();
  });

  await page.goto('/');
  await expect(page.getByTestId('status-success')).toBeVisible();
  expect(unexpectedRequests).toEqual([]);
});
