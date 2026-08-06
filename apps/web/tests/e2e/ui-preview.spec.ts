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
  await expect(page.getByText('Synthetic preview response')).toBeVisible();
  await expect(page.getByText('Local fixture playback · no live Hermes connection')).toBeVisible();
  await expect(page.getByRole('article', { name: 'Synthetic preview response from a local fixture' })).toBeVisible();
  await expect(page.getByText('Hermes is responding')).toHaveCount(0);
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

test('provider choices route to deterministic local password and callback states', async ({ page }) => {
  await page.goto(previewUrl('/ui-preview'));

  await page.getByRole('button', { name: 'Nous' }).click();
  await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'callback');
  await expect(page.getByRole('heading', { name: 'Completing sign-in' })).toBeFocused();

  await page.getByRole('button', { name: 'Cancel and return to providers' }).click();
  await page.getByRole('button', { name: 'Hermes password' }).click();
  await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'password');
  await expect(page.getByLabel('Username')).toBeFocused();
});

test('approved compatibility gates inert every underlying action for pointer, keyboard, and accessibility users', async ({
  page
}) => {
  for (const fixture of [
    {
      state: 'compatibility-check-failed',
      heading: 'Compatibility check failed',
      appearance: 'light',
      viewport: { width: 1440, height: 900 }
    },
    {
      state: 'unsupported-version',
      heading: 'Unsupported Hermes revision',
      appearance: 'dark',
      viewport: { width: 390, height: 844 }
    }
  ]) {
    await page.setViewportSize(fixture.viewport);
    await page.goto(previewUrl('/ui-preview'));
    await page.getByRole('combobox', { name: 'Appearance' }).selectOption(fixture.appearance);
    await page.getByRole('combobox', { name: 'Runtime state' }).selectOption(fixture.state);

    const preview = page.getByTestId('runtime-preview');
    const underlay = page.getByTestId('workspace-underlay');
    const retry = preview.getByRole('button', { name: 'Retry compatibility check' });
    const returnToSignIn = preview.getByRole('button', { name: 'Return to sign-in' });
    await expect(page.getByRole('heading', { name: fixture.heading })).toBeVisible();
    await expect(underlay).toHaveAttribute('inert', '');
    await expect(retry).toBeFocused();

    // The workspace remains visibly recognizable behind the gate, but inert
    // removes every descendant from keyboard, pointer, and accessibility APIs.
    await expect(underlay.locator('.workspace-grid')).toBeVisible();
    await expect(underlay.locator('[aria-label="Start a new chat"]')).toHaveCount(1);
    await expect(underlay.getByRole('button')).toHaveCount(0);
    await expect(underlay.getByRole('textbox')).toHaveCount(0);
    await expect(preview.getByRole('button')).toHaveCount(2);

    const sidebar = underlay.locator('.sidebar');
    await expect(sidebar).not.toHaveClass(/open/);
    const blockedNewChat = underlay.locator('[aria-label="Start a new chat"]');
    await blockedNewChat.dispatchEvent('pointerdown', { button: 0, pointerType: 'mouse' });
    await blockedNewChat.evaluate((element: HTMLElement) => element.click());
    await underlay
      .locator('[aria-label="Edit conversation title"]')
      .first()
      .evaluate((element: HTMLElement) => element.click());
    await underlay
      .locator('[aria-label="Open conversations"]')
      .evaluate((element: HTMLElement) => element.click());
    await expect(page.locator('.section-note').first()).toHaveText('No runtime action yet');
    await expect(page.getByTestId('mobile-title-editor')).toHaveCount(0);
    await expect(sidebar).not.toHaveClass(/open/);

    await underlay.locator('[aria-label="Start a new chat"]').evaluate((element: HTMLElement) => element.focus());
    await expect(retry).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(returnToSignIn).toBeFocused();
    await page.keyboard.press('Shift+Tab');
    await expect(retry).toBeFocused();

    await retry.click();
    await expect(page.locator('.section-note').first()).toHaveText('retry-compatibility-check');
    await returnToSignIn.focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('.section-note').first()).toHaveText('return-to-sign-in');

    const overflow = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth
    }));
    expect(overflow.scrollWidth).toBeLessThanOrEqual(overflow.clientWidth + 1);
  }
});

test('narrow title editing uses the compound island, separate workspace action, dimmer, and represented keyboard', async ({
  page
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(previewUrl('/ui-preview'));
  await page.getByRole('combobox', { name: 'Runtime state' }).selectOption('ready');

  const island = page.locator('.mobile-title-island');
  await expect(island.getByRole('button', { name: 'Open conversations' })).toBeVisible();
  await expect(island.getByRole('button', { name: 'Edit conversation title' })).toBeVisible();
  await expect(island.getByRole('button', { name: 'Open workspace' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Open workspace' })).toBeVisible();

  await island.getByRole('button', { name: 'Edit conversation title' }).click();
  await expect(page.getByTestId('mobile-title-editor')).toBeVisible();
  await expect(page.getByTestId('represented-mobile-keyboard')).toBeVisible();
  await expect(page.getByRole('textbox', { name: 'Conversation title' })).toBeFocused();
  expect(await page.locator('.title-edit-dimmer').evaluate((node) => getComputedStyle(node).backdropFilter)).toContain(
    'blur'
  );
});

test('password preview submits only a credential-free local fixture action', async ({ page }) => {
  await page.goto(previewUrl('/ui-preview'));
  await page.getByRole('combobox', { name: 'Authentication state' }).selectOption('password');

  const fixtureForm = page.getByRole('form', { name: 'Hermes password sign in' });
  const username = page.getByLabel('Username');
  const password = page.getByRole('textbox', { name: 'Password' });
  await expect(fixtureForm).toHaveAttribute('autocomplete', 'off');
  await expect(fixtureForm).toHaveAttribute('data-form-type', 'other');
  await expect(fixtureForm).toHaveAttribute('method', 'dialog');
  await expect(username).not.toHaveAttribute('name', /.+/);
  await expect(username).toHaveAttribute('data-fixture-field', 'username');
  await expect(username).toHaveAttribute('autocomplete', 'off');
  await expect(password).not.toHaveAttribute('name', /.+/);
  await expect(password).toHaveAttribute('data-fixture-field', 'password');
  await expect(password).toHaveAttribute('autocomplete', 'off');

  await username.fill('sam');
  await password.fill('browser-only-fixture');
  await page.getByRole('button', { name: 'Sign in' }).click();

  await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'password-submitting');
  await expect(page.getByRole('textbox', { name: 'Password' })).toHaveValue('');
  await expect(page.locator('.section-note').nth(1)).toHaveText('submit-password-fixture');
  await expect(page.getByText(/sent only to the configured/i)).not.toBeVisible();
});

test('password form cannot navigate with credential values after script execution stops', async ({ page }) => {
  await page.goto(previewUrl('/ui-preview'));
  await page.getByRole('combobox', { name: 'Authentication state' }).selectOption('password');
  const originalUrl = page.url();
  const navigationRequests: string[] = [];
  page.on('request', (request) => {
    if (request.isNavigationRequest()) navigationRequests.push(request.url());
  });

  const cdp = await page.context().newCDPSession(page);
  await cdp.send('Emulation.setScriptExecutionDisabled', { value: true });
  await page.getByLabel('Username').fill('url-history-username');
  await page.getByRole('textbox', { name: 'Password' }).fill('url-history-password');
  await page.getByRole('button', { name: 'Sign in' }).click();

  await expect(page).toHaveURL(originalUrl);
  expect(page.url()).not.toContain('url-history-username');
  expect(page.url()).not.toContain('url-history-password');
  expect(navigationRequests).toEqual([]);
});

test('Pill consumes one pointer gesture across leave, re-entry, and compatibility click', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(previewUrl('/ui-preview'));
  await page.getByRole('combobox', { name: 'Runtime state' }).selectOption('ready');
  const workspace = page.getByRole('button', { name: 'Open workspace' });

  await workspace.dispatchEvent('pointerdown', { button: 0, pointerType: 'mouse' });
  await expect(workspace).toHaveAttribute('aria-expanded', 'true');
  await workspace.dispatchEvent('pointerleave', { pointerType: 'mouse' });
  await workspace.dispatchEvent('pointerenter', { pointerType: 'mouse' });
  await workspace.dispatchEvent('pointerup', { button: 0, pointerType: 'mouse' });
  await workspace.dispatchEvent('click', { detail: 1 });
  await expect(workspace).toHaveAttribute('aria-expanded', 'true');

  await workspace.focus();
  await page.keyboard.press('Enter');
  await expect(workspace).toHaveAttribute('aria-expanded', 'false');
});

test('UI preview state branches have no axe violations in light, dark, desktop, and narrow layouts', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  for (const fixture of [
    {
      runtime: 'compatibility-check-failed',
      auth: 'password-submitting',
      appearance: 'light',
      viewport: { width: 1440, height: 900 }
    },
    {
      runtime: 'unsupported-version',
      auth: 'failure',
      appearance: 'dark',
      viewport: { width: 390, height: 844 }
    },
    {
      runtime: 'ready',
      auth: 'session-expired',
      appearance: 'light',
      viewport: { width: 768, height: 1024 }
    },
    {
      runtime: 'offline',
      auth: 'discovery-retry',
      appearance: 'dark',
      viewport: { width: 640, height: 900 }
    }
  ]) {
    await page.setViewportSize(fixture.viewport);
    await page.goto(previewUrl('/ui-preview'));
    await page.getByRole('combobox', { name: 'Runtime state' }).selectOption(fixture.runtime);
    await page.getByRole('combobox', { name: 'Authentication state' }).selectOption(fixture.auth);
    await page.getByRole('combobox', { name: 'Appearance' }).selectOption(fixture.appearance);

    const results = await new AxeBuilder({ page }).analyze();
    expect(results.violations, JSON.stringify(fixture)).toEqual([]);
  }
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

test('narrow reduced-transparency mode computes fully opaque materials without blur or saturation', async ({ page }) => {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('Emulation.setEmulatedMedia', {
    features: [{ name: 'prefers-reduced-transparency', value: 'reduce' }]
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(previewUrl('/ui-preview'));
  await page.getByRole('combobox', { name: 'Runtime state' }).selectOption('ready');

  expect(await page.evaluate(() => matchMedia('(prefers-reduced-transparency: reduce)').matches)).toBe(true);
  const materials = await page.locator('.workspace-preview').evaluate((preview) => {
    const styleFor = (selector: string) => {
      const element = preview.querySelector(selector);
      if (!element) throw new Error(`Missing reduced-transparency fixture: ${selector}`);
      const style = getComputedStyle(element);
      return { backdropFilter: style.backdropFilter, backgroundColor: style.backgroundColor };
    };
    return {
      mobilePill: styleFor('.mobile-toolbar > .pill'),
      titleIsland: styleFor('.mobile-title-island'),
      conversationPanel: styleFor('.conversation-panel'),
      composer: styleFor('.composer')
    };
  });

  for (const material of Object.values(materials)) {
    expect(material.backdropFilter).toBe('none');
    expect(material.backgroundColor).toMatch(/^rgb\(/);
    expect(material.backgroundColor).not.toMatch(/^rgba\(/);
  }
});

test('UI preview stays local at the 200% browser-zoom reflow equivalent with reduced motion', async ({ page }) => {
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
  // Chromium exposes no stable cross-platform Ctrl-plus API. A real 640 CSS-pixel
  // layout viewport reproduces a 1280px desktop viewport at 200% browser zoom
  // without relying on the non-standard CSS zoom property.
  await page.setViewportSize({ width: 640, height: 900 });
  await page.goto(previewUrl('/ui-preview'));
  await page.getByRole('combobox', { name: 'Runtime state' }).selectOption('compatibility-check-failed');
  await page.getByRole('button', { name: 'Nous' }).click();
  await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'callback');
  await page.getByRole('button', { name: 'Cancel and return to providers' }).click();
  await page.getByRole('button', { name: 'Hermes password' }).click();
  await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'password');

  await expect(page.getByRole('heading', { name: 'Runtime and authentication states' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.clientWidth)).toBe(640);
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
