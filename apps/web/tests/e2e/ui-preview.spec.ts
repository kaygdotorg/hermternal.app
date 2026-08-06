import { spawn, type ChildProcessByStdio } from 'node:child_process';
import { createServer } from 'node:net';
import type { Readable } from 'node:stream';
import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';

let uiPreviewOrigin = '';
let previewProcess: ChildProcessByStdio<null, Readable, Readable> | undefined;
let previewDiagnostics = '';

async function reservePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });

  const address = server.address();
  if (!address || typeof address === 'string') {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    throw new Error('The UI preview test could not reserve a local port.');
  }

  const port = address.port;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
  return port;
}

async function waitForPreview(url: string): Promise<void> {
  const deadline = Date.now() + 15_000;
  let lastFailure = 'no response';

  while (Date.now() < deadline) {
    if (previewProcess?.exitCode !== null && previewProcess?.exitCode !== undefined) {
      throw new Error(`The isolated UI preview exited before readiness: ${previewDiagnostics}`);
    }

    try {
      const response = await fetch(url, { redirect: 'manual' });
      if (response.status >= 200 && response.status < 400) return;
      lastFailure = `HTTP ${response.status}`;
    } catch (error) {
      lastFailure = error instanceof Error ? error.message : String(error);
    }

    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  throw new Error(`The isolated UI preview did not become ready: ${lastFailure}. ${previewDiagnostics}`);
}

function previewUrl(path: string): string {
  if (!uiPreviewOrigin) throw new Error('The isolated UI preview server is not ready.');
  return `${uiPreviewOrigin}${path}`;
}

test.beforeAll(async () => {
  const port = await reservePort();
  uiPreviewOrigin = `http://127.0.0.1:${port}`;
  previewDiagnostics = '';
  const serverProcess = spawn('bun', ['run', 'preview', '--', '--host', '127.0.0.1', '--port', String(port)], {
    cwd: process.cwd(),
    stdio: ['ignore', 'pipe', 'pipe']
  });
  previewProcess = serverProcess;

  const collectDiagnostics = (chunk: Buffer): void => {
    previewDiagnostics = `${previewDiagnostics}${chunk.toString()}`.slice(-4_000);
  };
  serverProcess.stdout.on('data', collectDiagnostics);
  serverProcess.stderr.on('data', collectDiagnostics);
  await waitForPreview(previewUrl('/ui-preview'));
});

test.afterAll(async () => {
  const processToStop = previewProcess;
  previewProcess = undefined;
  if (!processToStop || processToStop.exitCode !== null) return;

  processToStop.kill('SIGTERM');
  await new Promise<void>((resolve) => {
    const timeout = setTimeout(() => {
      processToStop.kill('SIGKILL');
      resolve();
    }, 2_000);
    processToStop.once('exit', () => {
      clearTimeout(timeout);
      resolve();
    });
  });
});

for (const viewport of [
  { name: 'desktop', width: 1440, height: 900 },
  { name: 'tablet', width: 768, height: 1024 },
  { name: 'narrow', width: 390, height: 844 }
]) {
  test(`${viewport.name} UI preview keeps both surfaces usable`, async ({ page }) => {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.goto(previewUrl('/ui-preview'));

    await expect(page.getByRole('heading', { name: 'Runtime and authentication states' })).toBeVisible();
    await expect(page.getByTestId('runtime-preview')).toBeVisible();
    await expect(page.getByTestId('auth-preview')).toBeVisible();

    const overflow = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth
    }));
    expect(overflow.scrollWidth).toBeLessThanOrEqual(overflow.clientWidth + 1);
  });
}

test('UI preview exposes local state controls and dark appearance', async ({ page }) => {
  await page.goto(previewUrl('/ui-preview'));

  await page.getByRole('combobox', { name: 'Runtime state' }).selectOption('streaming');
  await page.getByRole('combobox', { name: 'Authentication state' }).selectOption('failure');
  await page.getByRole('combobox', { name: 'Appearance' }).selectOption('dark');

  await expect(page.getByTestId('runtime-preview')).toHaveAttribute('data-state', 'streaming');
  await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'failure');
  await expect(page.getByTestId('runtime-preview')).toHaveAttribute('data-appearance', 'dark');
  await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-appearance', 'dark');
  await expect(page.getByText('Hermes is responding')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Sign-in did not complete' })).toBeVisible();
});

test('narrow absolute surfaces stay contained and Send activates the local action', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(previewUrl('/ui-preview'));

  const auth = page.locator('.auth-preview');
  const statusBar = page.locator('.mobile-status-bar');
  const authBox = await auth.boundingBox();
  const statusBox = await statusBar.boundingBox();
  expect(authBox).not.toBeNull();
  expect(statusBox).not.toBeNull();
  expect(Math.abs((statusBox?.y ?? 0) - (authBox?.y ?? 0))).toBeLessThanOrEqual(1);

  await page.getByRole('combobox', { name: 'Runtime state' }).selectOption('ready');
  await page.getByRole('button', { name: 'Open conversations' }).click();
  const workspace = page.locator('.workspace-preview');
  const sidebar = page.locator('.workspace-preview .sidebar');
  const workspaceBox = await workspace.boundingBox();
  const sidebarBox = await sidebar.boundingBox();
  expect(workspaceBox).not.toBeNull();
  expect(sidebarBox).not.toBeNull();
  expect(Math.abs((sidebarBox?.y ?? 0) - ((workspaceBox?.y ?? 0) + 64))).toBeLessThanOrEqual(1);
  expect((sidebarBox?.x ?? 0) + (sidebarBox?.width ?? 0)).toBeLessThanOrEqual(
    (workspaceBox?.x ?? 0) + (workspaceBox?.width ?? 0) + 1
  );

  const composer = page.getByRole('textbox', { name: 'Message Hermes' });
  await composer.fill('Pointer fixture');
  await page.getByRole('button', { name: 'Send message' }).click();
  await expect(page.locator('.section-note').first()).toHaveText('send');
});

test('password preview submits only a credential-free local fixture action', async ({ page }) => {
  await page.goto(previewUrl('/ui-preview'));
  await page.getByRole('combobox', { name: 'Authentication state' }).selectOption('password');

  await page.getByLabel('Username').fill('sam');
  await page.getByRole('textbox', { name: 'Password' }).fill('browser-only-fixture');
  await page.getByRole('button', { name: 'Sign in' }).click();

  await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'password-submitting');
  await expect(page.getByRole('textbox', { name: 'Password' })).toHaveValue('');
  await expect(page.locator('.section-note').nth(1)).toHaveText('submit-password-fixture');
  await expect(page.getByText(/sent only to the configured/i)).not.toBeVisible();
});

test('opt-in live provider discovery uses the same-origin GET boundary and transitions from pending to success', async ({
  page
}) => {
  test.skip(
    process.env.VITE_HERMES_LIVE_AUTH_DISCOVERY !== 'true',
    'Set VITE_HERMES_LIVE_AUTH_DISCOVERY=true to build the opt-in live discovery lane.'
  );

  const requests: Array<{ method: string; url: string; headers: Record<string, string> }> = [];
  let releaseResponse!: () => void;
  const responseGate = new Promise<void>((resolve) => {
    releaseResponse = resolve;
  });

  await page.route('**/api/auth/providers', async (route) => {
    const request = route.request();
    requests.push({ method: request.method(), url: request.url(), headers: request.headers() });
    await responseGate;
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        providers: [
          { name: 'nous', display_name: 'Nous', supports_password: false },
          { name: 'hermes-password', display_name: 'Hermes password', supports_password: true }
        ]
      })
    });
  });

  await page.goto(previewUrl('/ui-preview?authDiscovery=live'));
  await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-discovery-mode', 'live');
  await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'discovery-pending');

  releaseResponse();
  await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'provider-selection');
  await expect(page.getByRole('button', { name: 'Nous' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Hermes password' })).toBeVisible();

  expect(requests).toHaveLength(1);
  expect(requests[0]?.method).toBe('GET');
  expect(requests[0]?.url).toBe(`${uiPreviewOrigin}/api/auth/providers`);
  expect(requests[0]?.headers.authorization).toBeUndefined();
  expect(requests[0]?.url).not.toContain('?');
});

test('opt-in live provider discovery fails closed on reviewed 503 and retries idempotently', async ({ page }) => {
  test.skip(
    process.env.VITE_HERMES_LIVE_AUTH_DISCOVERY !== 'true',
    'Set VITE_HERMES_LIVE_AUTH_DISCOVERY=true to build the opt-in live discovery lane.'
  );

  let requestCount = 0;
  await page.route('**/api/auth/providers', async (route) => {
    requestCount += 1;
    if (requestCount === 1) {
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ detail: 'no auth providers registered' })
      });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        providers: [{ name: 'nous', display_name: 'Nous', supports_password: false }]
      })
    });
  });

  await page.goto(previewUrl('/ui-preview?authDiscovery=live'));
  await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'provider-unavailable');
  await expect(page.getByRole('heading', { name: 'Provider discovery stopped' })).toBeVisible();

  await page.getByRole('button', { name: 'Retry discovery' }).click();
  await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'provider-selection');
  await expect(page.getByRole('button', { name: 'Nous' })).toBeVisible();
  expect(requestCount).toBe(2);
});

test('opt-in live provider discovery exposes cancellation and retries after abort', async ({ page }) => {
  test.skip(
    process.env.VITE_HERMES_LIVE_AUTH_DISCOVERY !== 'true',
    'Set VITE_HERMES_LIVE_AUTH_DISCOVERY=true to build the opt-in live discovery lane.'
  );

  let requestCount = 0;
  let releaseFirstResponse!: () => void;
  const firstResponseGate = new Promise<void>((resolve) => {
    releaseFirstResponse = resolve;
  });

  await page.route('**/api/auth/providers', async (route) => {
    requestCount += 1;
    if (requestCount === 1) {
      await firstResponseGate;
      try {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ providers: [{ name: 'nous', display_name: 'Nous', supports_password: false }] })
        });
      } catch {
        // The browser cancellation is the behavior under test.
      }
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ providers: [{ name: 'nous', display_name: 'Nous', supports_password: false }] })
    });
  });

  await page.goto(previewUrl('/ui-preview?authDiscovery=live'));
  await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'discovery-pending');
  await page.getByRole('button', { name: 'Cancel discovery' }).click();
  await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'discovery-aborted');

  releaseFirstResponse();
  await page.getByRole('button', { name: 'Retry discovery' }).click();
  await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'provider-selection');
  expect(requestCount).toBe(2);
});

test('discovery fixture states remain accessible across empty, malformed, unavailable, aborted, and retry variants', async ({
  page
}) => {
  await page.goto(previewUrl('/ui-preview'));

  for (const state of [
    'discovery-empty',
    'discovery-malformed',
    'provider-unavailable',
    'discovery-aborted',
    'discovery-retry'
  ]) {
    await page.getByRole('combobox', { name: 'Authentication state' }).selectOption(state);
    const results = await new AxeBuilder({ page }).analyze();
    expect(results.violations, state).toEqual([]);
  }
});

test('UI preview has no axe violations', async ({ page }) => {
  await page.goto(previewUrl('/ui-preview'));

  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
});

test('records production preview timing without a threshold', async ({ page }) => {
  await page.goto(previewUrl('/ui-preview'), { waitUntil: 'networkidle' });

  const measurement = await page.evaluate(() => {
    const navigation = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming | undefined;
    return {
      domContentLoaded: navigation?.domContentLoadedEventEnd ?? null,
      loadEventEnd: navigation?.loadEventEnd ?? null,
      transferSize: navigation?.transferSize ?? null,
      resourceCount: performance.getEntriesByType('resource').length
    };
  });

  console.info('production ui-preview measurement', measurement);
  expect(measurement).toBeTruthy();
});

test('visible UI controls keep the shared 44px effective target', async ({ page }) => {
  for (const viewport of [
    { width: 1440, height: 900 },
    { width: 390, height: 844 }
  ]) {
    await page.setViewportSize(viewport);
    await page.goto(previewUrl('/ui-preview'));

    const undersizedControls = await page.evaluate(() =>
      Array.from(document.querySelectorAll('button, select, input, textarea'))
        .filter((element) => {
          const target = element.closest('label') ?? element;
          const style = getComputedStyle(target);
          const rect = target.getBoundingClientRect();
          return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 10 && rect.height > 10;
        })
        .filter((element) => {
          const target = element.closest('label') ?? element;
          const rect = target.getBoundingClientRect();
          return rect.width < 44 || rect.height < 44;
        })
        .map((element) => {
          const target = element.closest('label') ?? element;
          const rect = target.getBoundingClientRect();
          return {
            label: element.getAttribute('aria-label') ?? element.textContent?.trim() ?? element.tagName,
            width: rect.width,
            height: rect.height
          };
        })
    );

    expect(undersizedControls).toEqual([]);
  }
});

test('UI preview stays local and accessible at 200% zoom with reduced motion', async ({ page }) => {
  const unexpectedRequests: string[] = [];
  const expectedOrigin = uiPreviewOrigin;

  await page.route('**/*', async (route) => {
    const requestUrl = new URL(route.request().url());
    if (requestUrl.origin !== expectedOrigin) {
      unexpectedRequests.push(requestUrl.href);
      await route.abort();
      return;
    }
    await route.continue();
  });
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto(previewUrl('/ui-preview'));
  await page.evaluate(() => {
    document.documentElement.style.zoom = '2';
  });

  await expect(page.getByRole('heading', { name: 'Runtime and authentication states' })).toBeVisible();
  expect(await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches)).toBe(true);
  const hasReducedTransparencyFallback = await page.evaluate(() =>
    Array.from(document.styleSheets).some((styleSheet) => {
      try {
        return Array.from(styleSheet.cssRules).some((rule) => rule.cssText.includes('prefers-reduced-transparency'));
      } catch {
        return false;
      }
    })
  );
  expect(hasReducedTransparencyFallback).toBe(true);
  expect(unexpectedRequests).toEqual([]);

  const overflow = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth
  }));
  expect(overflow.scrollWidth).toBeLessThanOrEqual(overflow.clientWidth + 1);
});
