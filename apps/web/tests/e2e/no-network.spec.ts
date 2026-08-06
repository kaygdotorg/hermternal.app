import { expect, test } from '@playwright/test';

const blockedProbePaths = [
  '/api',
  '/api/pty',
  '/hermes/status',
  '/auth/login',
  '/ws/socket',
  '/pty/session',
  '/unknown-route'
];

function isAllowedShellRequest(url: URL, expectedOrigin: string): boolean {
  return (
    url.origin === expectedOrigin &&
    (url.pathname === '/' ||
      url.pathname === '/index.html' ||
      url.pathname === '/200.html' ||
      url.pathname === '/manifest.webmanifest' ||
      url.pathname === '/icon.svg' ||
      url.pathname.startsWith('/_app/'))
  );
}

test('the shell makes no unexpected cross-origin or same-origin requests', async ({ page, baseURL }) => {
  const expectedOrigin = new URL(baseURL ?? 'http://127.0.0.1:4173').origin;
  const unexpectedRequests: string[] = [];
  const blockedProbeRequests: string[] = [];
  const probes = new Set(blockedProbePaths);
  let probing = false;

  await page.route('**/*', async (route) => {
    const requestUrl = new URL(route.request().url());
    if (isAllowedShellRequest(requestUrl, expectedOrigin)) {
      await route.continue();
      return;
    }

    if (probing && requestUrl.origin === expectedOrigin && probes.has(requestUrl.pathname)) {
      blockedProbeRequests.push(requestUrl.pathname);
    } else {
      unexpectedRequests.push(`${route.request().method()} ${requestUrl.href}`);
    }
    await route.abort();
  });

  await page.goto('/');
  await expect(page.getByTestId('status-success')).toBeVisible();
  expect(unexpectedRequests).toEqual([]);

  probing = true;
  const probeResults = await page.evaluate(async (paths) => {
    return Promise.all(
      paths.map(async (path) => {
        try {
          const response = await fetch(path);
          return { path, status: response.status };
        } catch {
          return { path, status: 'blocked' };
        }
      })
    );
  }, blockedProbePaths);
  probing = false;

  expect(probeResults).toHaveLength(blockedProbePaths.length);
  expect([...new Set(blockedProbeRequests)].sort()).toEqual([...blockedProbePaths].sort());
  expect(unexpectedRequests).toEqual([]);
});
