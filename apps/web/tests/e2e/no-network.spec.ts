import { expect, test, type Page } from '@playwright/test';

const blockedProbePaths = [
  '/api',
  '/api/pty',
  '/hermes/status',
  '/auth/login',
  '/ws/socket',
  '/pty/session',
  '/unknown-route'
];
const canonicalClientRoute = '/v1/c/abcdefghijklmnop';

function isAllowedShellRequest(method: string, url: URL, expectedOrigin: string): boolean {
  return (
    (method === 'GET' || method === 'HEAD') &&
    url.origin === expectedOrigin &&
    (url.pathname === '/' ||
      url.pathname === '/index.html' ||
      url.pathname === '/200.html' ||
      url.pathname === '/manifest.webmanifest' ||
      url.pathname === '/icon.svg' ||
      url.pathname === '/service-worker.js' ||
      url.pathname.startsWith('/_app/'))
  );
}

async function installAndControlWorker(page: Page): Promise<void> {
  await page.waitForFunction(() => Boolean(navigator.serviceWorker?.controller), undefined, {
    timeout: 10_000
  });

  const installation = await page.evaluate(async () => {
    const ready = await navigator.serviceWorker.ready;
    await ready.update();
    const cacheName = (await caches.keys()).find((name) =>
      name.startsWith('hermternal-prototype-assets-')
    );
    const cachedFallback = cacheName
      ? Boolean(await caches.open(cacheName).then((cache) => cache.match('/200.html')))
      : false;
    return {
      activeState: ready.active?.state ?? null,
      scriptURL: ready.active?.scriptURL ?? null,
      scope: ready.scope,
      controlledBeforeReload: Boolean(navigator.serviceWorker.controller),
      cacheName,
      cachedFallback
    };
  });

  expect(installation.activeState).toBe('activated');
  expect(installation.scriptURL).toContain('/service-worker.js');
  expect(installation.scope).toMatch(/\/$/);
  expect(installation.controlledBeforeReload).toBe(true);
  expect(installation.cacheName).toMatch(/^hermternal-prototype-assets-/);
  expect(installation.cachedFallback).toBe(true);

  // Reload verifies update checks and control survive the normal document
  // lifecycle; the startup layout owns registration rather than this test.
  await page.reload();
  await expect(page.getByTestId('status-success')).toBeVisible();

  const control = await page.evaluate(() => ({
    controlled: Boolean(navigator.serviceWorker.controller),
    controllerScriptURL: navigator.serviceWorker.controller?.scriptURL ?? null
  }));
  expect(control.controlled).toBe(true);
  expect(control.controllerScriptURL).toContain('/service-worker.js');
}

test('the shell uses an active worker and makes no unexpected cross-origin or same-origin requests', async ({
  page,
  baseURL
}) => {
  const expectedOrigin = new URL(baseURL ?? 'http://127.0.0.1:4173').origin;
  const unexpectedRequests: string[] = [];
  const blockedProbeRequests: string[] = [];
  const probes = new Set(blockedProbePaths);
  let probing = false;

  await page.route('**/*', async (route) => {
    const requestUrl = new URL(route.request().url());
    const method = route.request().method();
    if (isAllowedShellRequest(method, requestUrl, expectedOrigin)) {
      await route.continue();
      return;
    }

    if (probing && method === 'GET' && requestUrl.origin === expectedOrigin && probes.has(requestUrl.pathname)) {
      blockedProbeRequests.push(`${method} ${requestUrl.pathname}`);
    } else {
      unexpectedRequests.push(`${method} ${requestUrl.href}`);
    }
    await route.abort();
  });

  // The query is an allowed root fixture selector, not a live route.
  await page.goto('/?scenario=success');
  await expect(page.getByTestId('status-success')).toBeVisible();
  expect(unexpectedRequests).toEqual([]);

  await installAndControlWorker(page);

  // True offline navigation must be answered by the worker's cached 200.html
  // route. If startup registration or control failed, this navigation fails
  // instead of creating a false-positive host fallback.
  await page.context().setOffline(true);
  try {
    const deepLinkResponse = await page.goto(canonicalClientRoute);
    expect(deepLinkResponse?.status()).toBe(200);
    expect(await deepLinkResponse?.headerValue('x-hermternal-static-source')).toBe('fallback-file');
    const deepLinkControl = await page.evaluate(() => ({
      controlled: Boolean(navigator.serviceWorker.controller)
    }));
    expect(deepLinkControl.controlled).toBe(true);
  } finally {
    await page.context().setOffline(false);
  }
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

  expect(probeResults).toEqual(
    blockedProbePaths.map((path) => ({ path, status: 'blocked' }))
  );
  expect(blockedProbeRequests.sort()).toEqual(
    blockedProbePaths.map((path) => `GET ${path}`).sort()
  );
  expect(unexpectedRequests).toEqual([]);
});
