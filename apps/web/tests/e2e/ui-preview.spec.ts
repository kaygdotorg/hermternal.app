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

test('Paper desktop geometry keeps the fixed three-column workspace and composer baseline', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 960 });
  await page.goto(previewUrl('/ui-preview'));
  await page.getByRole('combobox', { name: 'Runtime state' }).selectOption('ready');

  const workspace = page.locator('.workspace-preview');
  const workspaceBox = await workspace.boundingBox();
  const gridBox = await workspace.locator('.workspace-grid').boundingBox();
  const sidebarBox = await workspace.locator('.sidebar').boundingBox();
  const conversationBox = await workspace.locator('.conversation-panel').boundingBox();
  const inspectorBox = await workspace.locator('.desktop-inspector').boundingBox();
  const composerBox = await workspace.getByRole('form', { name: 'Message composer' }).boundingBox();
  expect(workspaceBox).not.toBeNull();
  expect(gridBox).not.toBeNull();
  expect(sidebarBox).not.toBeNull();
  expect(conversationBox).not.toBeNull();
  expect(inspectorBox).not.toBeNull();
  expect(composerBox).not.toBeNull();

  expect(workspaceBox?.width).toBe(1440);
  expect(workspaceBox?.height).toBe(960);
  expect(gridBox?.x).toBe(workspaceBox?.x);
  expect(gridBox?.y).toBe(workspaceBox?.y);
  expect(gridBox?.width).toBe(1440);
  expect(gridBox?.height).toBe(928);
  expect(sidebarBox?.x).toBe((workspaceBox?.x ?? 0) + 16);
  expect(conversationBox?.x).toBe((workspaceBox?.x ?? 0) + 16 + 276 + 16);
  expect(inspectorBox?.x).toBe((workspaceBox?.x ?? 0) + 16 + 276 + 16 + 720 + 16);
  expect(sidebarBox?.y).toBe((workspaceBox?.y ?? 0) + 16);
  expect(conversationBox?.y).toBe((workspaceBox?.y ?? 0) + 16);
  expect(inspectorBox?.y).toBe((workspaceBox?.y ?? 0) + 16);
  expect(sidebarBox?.width).toBe(276);
  expect(conversationBox?.width).toBe(720);
  expect(inspectorBox?.width).toBe(380);
  expect(sidebarBox?.height).toBe(928);
  expect(conversationBox?.height).toBe(928);
  expect(inspectorBox?.height).toBe(928);
  expect(composerBox?.height).toBe(112);
  expect(Math.abs((composerBox?.y ?? 0) - ((workspaceBox?.y ?? 0) + 800))).toBeLessThanOrEqual(1);

  const computedGrid = await workspace.locator('.workspace-grid').evaluate((element) => {
    const style = getComputedStyle(element);
    return { columns: style.gridTemplateColumns, rows: style.gridTemplateRows };
  });
  expect(computedGrid.columns).toBe('276px 720px 380px');
  expect(computedGrid.rows).toBe('928px');
  await expect(workspace.locator('.conversation-body .timeline')).toHaveCSS('overflow-y', 'auto');
});

test('Paper mobile geometry uses the fixed shell, modal drawers, and local Send action', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(previewUrl('/ui-preview'));

  const auth = page.locator('.auth-preview');
  const authStatusBar = page.locator('.mobile-status-bar');
  const authBox = await auth.boundingBox();
  const authStatusBox = await authStatusBar.boundingBox();
  expect(authBox).not.toBeNull();
  expect(authStatusBox).not.toBeNull();
  expect(Math.abs((authStatusBox?.y ?? 0) - (authBox?.y ?? 0))).toBeLessThanOrEqual(1);

  await page.getByRole('combobox', { name: 'Runtime state' }).selectOption('ready');
  const workspace = page.locator('.workspace-preview');
  const workspaceBox = await workspace.boundingBox();
  const statusBar = workspace.locator('.workspace-mobile-status-bar');
  const toolbar = workspace.locator('.mobile-toolbar');
  const conversation = workspace.locator('.conversation-panel');
  const composer = page.getByRole('form', { name: 'Message composer' });
  const workspaceStatusBox = await statusBar.boundingBox();
  const toolbarBox = await toolbar.boundingBox();
  const conversationBox = await conversation.boundingBox();
  const composerBox = await composer.boundingBox();
  expect(workspaceBox).not.toBeNull();
  expect(workspaceStatusBox).not.toBeNull();
  expect(toolbarBox).not.toBeNull();
  expect(conversationBox).not.toBeNull();
  expect(composerBox).not.toBeNull();
  expect(workspaceBox?.width).toBe(390);
  expect(workspaceBox?.height).toBe(844);
  expect(workspaceStatusBox?.x).toBe(workspaceBox?.x);
  expect(workspaceStatusBox?.y).toBe(workspaceBox?.y);
  expect(workspaceStatusBox?.width).toBe(390);
  expect(workspaceStatusBox?.height).toBe(62);
  expect(toolbarBox?.x).toBe(workspaceBox?.x);
  expect(toolbarBox?.y).toBe((workspaceBox?.y ?? 0) + 62);
  expect(toolbarBox?.width).toBe(390);
  expect(toolbarBox?.height).toBe(64);
  expect(conversationBox?.x).toBe(workspaceBox?.x);
  expect(conversationBox?.y).toBe((workspaceBox?.y ?? 0) + 126);
  expect(conversationBox?.width).toBe(390);
  expect(conversationBox?.height).toBe(718);
  expect(composerBox?.y).toBe((workspaceBox?.y ?? 0) + 728);
  expect(composerBox?.height).toBe(100);
  await expect(workspace.locator('.workspace-grid .desktop-inspector')).toBeHidden();

  const conversations = page.getByRole('button', { name: 'Open conversations' });
  await conversations.click();
  const scrim = page.getByTestId('mobile-drawer-scrim');
  const sessionDrawer = page.getByTestId('mobile-session-drawer');
  const scrimBox = await scrim.boundingBox();
  const sessionDrawerBox = await sessionDrawer.boundingBox();
  expect(scrimBox).not.toBeNull();
  expect(sessionDrawerBox).not.toBeNull();
  expect(scrimBox?.x).toBe(workspaceBox?.x);
  expect(scrimBox?.y).toBe((workspaceBox?.y ?? 0) + 62);
  expect(scrimBox?.width).toBe(390);
  expect(scrimBox?.height).toBe(782);
  expect(sessionDrawerBox?.x).toBe((workspaceBox?.x ?? 0) + 12);
  expect(sessionDrawerBox?.y).toBe((workspaceBox?.y ?? 0) + 74);
  expect(sessionDrawerBox?.width).toBe(342);
  expect(sessionDrawerBox?.height).toBe(756);
  await expect(sessionDrawer).toHaveAttribute('role', 'dialog');
  await expect(sessionDrawer).toHaveAttribute('aria-modal', 'true');
  await expect(workspace.locator('.workspace-underlay')).toHaveAttribute('inert', '');
  await expect(workspace.locator('.workspace-underlay')).toHaveAttribute('aria-hidden', 'true');
  await expect(sessionDrawer.locator('button:not([disabled])').first()).toBeFocused();

  const sessionFocusables = sessionDrawer.locator(
    'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
  );
  await sessionFocusables.last().focus();
  await page.keyboard.press('Tab');
  await expect(sessionFocusables.first()).toBeFocused();
  await page.keyboard.press('Shift+Tab');
  await expect(sessionFocusables.last()).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(sessionDrawer).toBeHidden();
  await expect(conversations).toBeFocused();

  const workspaceTrigger = page.getByRole('button', { name: 'Open workspace' });
  await workspaceTrigger.click();
  const workspaceDrawer = page.getByTestId('mobile-workspace-drawer');
  const workspaceAfterSessionBox = await workspace.boundingBox();
  const workspaceDrawerBox = await workspaceDrawer.boundingBox();
  expect(workspaceAfterSessionBox).not.toBeNull();
  expect(workspaceDrawerBox).not.toBeNull();
  expect(workspaceDrawerBox?.x).toBe((workspaceAfterSessionBox?.x ?? 0) + 12);
  expect(workspaceDrawerBox?.y).toBe((workspaceAfterSessionBox?.y ?? 0) + 74);
  expect(workspaceDrawerBox?.width).toBe(366);
  expect(workspaceDrawerBox?.height).toBe(756);
  await expect(workspace.locator('.workspace-grid .desktop-inspector')).toBeHidden();
  await expect(workspaceDrawer.locator('.inspector')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(workspaceDrawer).toBeHidden();
  await expect(workspaceTrigger).toBeFocused();

  await composer.getByRole('textbox', { name: 'Message Hermes' }).fill('Pointer fixture');
  await page.getByRole('button', { name: 'Send message' }).click();
  await expect(page.locator('.section-note').first()).toHaveText('send');
});

test('Paper effective width switches exactly at 760px without a tabbed desktop replacement', async ({ page }) => {
  for (const width of [760, 761]) {
    await page.setViewportSize({ width, height: 844 });
    await page.goto(previewUrl('/ui-preview'));
    await page.getByRole('combobox', { name: 'Runtime state' }).selectOption('ready');
    const workspace = page.locator('.workspace-preview');
    expect((await workspace.boundingBox())?.width).toBe(width);

    if (width === 760) {
      await expect(workspace.locator('.mobile-toolbar')).toBeVisible();
      await expect(workspace.locator('.conversation-header')).toBeHidden();
    } else {
      await expect(workspace.locator('.mobile-toolbar')).toBeHidden();
      await expect(workspace.locator('.conversation-header')).toBeVisible();
      await expect(workspace.locator('.sidebar')).toBeVisible();
    }
  }
});

test('Paper action labels stay under a stationary pointer through repeated hover transitions', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 960 });
  await page.goto(previewUrl('/ui-preview'));
  await page.getByRole('combobox', { name: 'Runtime state' }).selectOption('ready');

  const workspace = page.locator('.workspace-preview');
  const actionLabels = [
    'Chat mode selected',
    'Open terminal mode',
    'Allow once',
    'Allow for session',
    'Always allow',
    'Deny',
    'Open artifact preview',
    'Download artifact preview'
  ];

  for (const ariaLabel of actionLabels) {
    const pill = workspace.getByRole('button', { name: ariaLabel });
    const copy = pill.locator('.pill-copy');
    await expect(pill).toBeVisible();

    for (let run = 0; run < 3; run += 1) {
      // Reset the previous reveal before putting the pointer over the next
      // control. The pointer then stays at one fixed screen coordinate for the
      // entire transition, exposing layout-induced hover loops.
      await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
      await page.mouse.move(0, 0);
      await expect
        .poll(
          () =>
            pill.evaluate((element) => {
              const copy = element.querySelector<HTMLElement>('.pill-copy');
              return {
                opacity: copy ? getComputedStyle(copy).opacity : '',
                maxWidth: copy ? getComputedStyle(copy).maxWidth : ''
              };
            }),
          { message: `${ariaLabel} resting state` }
        )
        .toEqual({ opacity: '0', maxWidth: '0px' });

      const resting = await pill.evaluate((element) => {
        const copy = element.querySelector<HTMLElement>('.pill-copy');
        const rect = element.getBoundingClientRect();
        const iconRect = element.querySelector<HTMLElement>('.icon-slot')?.getBoundingClientRect();
        return {
          width: rect.width,
          opacity: copy ? getComputedStyle(copy).opacity : '',
          maxWidth: copy ? getComputedStyle(copy).maxWidth : '',
          iconOffset: iconRect ? iconRect.x - rect.x : null
        };
      });
      expect(resting.opacity, ariaLabel).toBe('0');
      expect(resting.maxWidth, ariaLabel).toBe('0px');
      expect(resting.width, ariaLabel).toBe(44);

      const box = await pill.boundingBox();
      expect(box, ariaLabel).not.toBeNull();
      await page.mouse.move((box?.x ?? 0) + (box?.width ?? 0) / 2, (box?.y ?? 0) + (box?.height ?? 0) / 2);

      const samples: Array<{ hovered: boolean; opacity: string; maxWidth: number; copyWidth: number }> = [];
      for (let sample = 0; sample < 10; sample += 1) {
        await page.waitForTimeout(30);
        samples.push(
          await pill.evaluate((element) => {
            const copy = element.querySelector<HTMLElement>('.pill-copy');
            const style = copy ? getComputedStyle(copy) : undefined;
            return {
              hovered: element.matches(':hover'),
              opacity: style?.opacity ?? '',
              maxWidth: Number.parseFloat(style?.maxWidth ?? '0'),
              copyWidth: copy?.getBoundingClientRect().width ?? 0
            };
          })
        );
      }

      expect(samples.every((sample) => sample.hovered), ariaLabel).toBe(true);
      const revealed = samples.at(-1);
      expect(revealed?.opacity, ariaLabel).toBe('1');
      expect(revealed?.maxWidth, ariaLabel).toBeGreaterThan(0);
      expect(revealed?.copyWidth, ariaLabel).toBeGreaterThan(0);

      const hovered = await pill.evaluate((element) => {
        const rect = element.getBoundingClientRect();
        const iconRect = element.querySelector<HTMLElement>('.icon-slot')?.getBoundingClientRect();
        return { width: rect.width, iconOffset: iconRect ? iconRect.x - rect.x : null };
      });
      // The label is a visual overlay. The real 44px hit target and fixed icon
      // slot stay put while the surrounding layout remains unchanged.
      expect(hovered.width, ariaLabel).toBe(resting.width);
      expect(hovered.iconOffset, ariaLabel).toBeCloseTo(resting.iconOffset ?? 0, 4);
    }

    if (!(await pill.isDisabled())) {
      await page.mouse.move(0, 0);
      await page.waitForTimeout(220);
      await pill.focus();
      await expect.poll(() => copy.evaluate((element) => getComputedStyle(element).opacity), { message: ariaLabel }).toBe('1');
    }
  }
});

test('Paper mode overlays clear adjacent controls and preserve long localized focus labels', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 960 });
  await page.goto(previewUrl('/ui-preview'));
  await page.getByRole('combobox', { name: 'Runtime state' }).selectOption('ready');

  const workspace = page.locator('.workspace-preview');
  const terminal = workspace.getByRole('button', { name: 'Open terminal mode' });
  const terminalCopy = terminal.locator('.pill-copy');
  const approval = workspace.getByRole('button', { name: 'Allow once' });
  const approvalCopy = approval.locator('.pill-copy');
  await terminal.hover();
  await expect(terminalCopy).toHaveCSS('opacity', '1');

  const stacking = await page.evaluate(() => {
    const modeControls = document.querySelector<HTMLElement>('.mode-controls');
    const terminal = document.querySelector<HTMLElement>('button[aria-label="Open terminal mode"]');
    const terminalCopy = terminal?.querySelector<HTMLElement>('.pill-copy');
    const workspaceOptions = document.querySelector<HTMLElement>('button[aria-label="Workspace options"]');
    if (!modeControls || !terminal || !terminalCopy || !workspaceOptions) return null;

    const modeRect = modeControls.getBoundingClientRect();
    const terminalRect = terminal.getBoundingClientRect();
    const copyRect = terminalCopy.getBoundingClientRect();
    const optionsRect = workspaceOptions.getBoundingClientRect();
    const optionsCenterX = optionsRect.left + optionsRect.width / 2;
    const optionsCenterY = optionsRect.top + optionsRect.height / 2;
    const hit = document.elementFromPoint(optionsCenterX, optionsCenterY);
    const modeZIndex = Number.parseInt(getComputedStyle(modeControls).zIndex, 10);
    const optionsZIndex = Number.parseInt(getComputedStyle(workspaceOptions).zIndex, 10);

    return {
      modeWidth: modeRect.width,
      terminalWidth: terminalRect.width,
      copyWidth: copyRect.width,
      copyRight: copyRect.right,
      optionsLeft: optionsRect.left,
      overlapX: Math.min(copyRect.right, optionsRect.right) - Math.max(copyRect.left, optionsRect.left),
      overlapY: Math.min(copyRect.bottom, optionsRect.bottom) - Math.max(copyRect.top, optionsRect.top),
      modeZIndex: Number.isNaN(modeZIndex) ? 0 : modeZIndex,
      optionsZIndex: Number.isNaN(optionsZIndex) ? 0 : optionsZIndex,
      hitLabel: hit?.closest('button')?.getAttribute('aria-label') ?? null,
      copyOpacity: getComputedStyle(terminalCopy).opacity
    };
  });

  expect(stacking).not.toBeNull();
  expect(stacking?.modeWidth).toBe(92);
  expect(stacking?.terminalWidth).toBe(44);
  expect(stacking?.copyWidth).toBeGreaterThan(44);
  expect(stacking?.copyRight).toBeGreaterThan(stacking?.optionsLeft ?? 0);
  expect(stacking?.overlapX).toBeGreaterThan(0);
  expect(stacking?.overlapY).toBeGreaterThan(0);
  expect(stacking?.modeZIndex).toBeGreaterThan(stacking?.optionsZIndex ?? 0);
  expect(stacking?.copyOpacity).toBe('1');
  // The label is pointer-transparent, so the adjacent control remains the
  // hit target even while the label paints above it.
  expect(stacking?.hitLabel).toBe('Workspace options');

  await page.mouse.move(0, 0);
  await expect(terminalCopy).toHaveCSS('opacity', '0');
  await approval.evaluate((element) => {
    const label = element.querySelector<HTMLElement>('.pill-label');
    if (label) label.textContent = 'Einmal zulassen · lokalisierte Arbeitsbereichssteuerung';
  });
  // Use an enabled approval action for the keyboard branch. Mode switching is
  // intentionally disabled in this preview, while approval focus is real.
  await approval.focus();
  await expect(approval).toBeFocused();
  await expect(approvalCopy).toHaveCSS('opacity', '1');

  const localized = await approval.evaluate((element) => {
    const copy = element.querySelector<HTMLElement>('.pill-copy');
    const label = element.querySelector<HTMLElement>('.pill-label');
    const buttonRect = element.getBoundingClientRect();
    const copyRect = copy?.getBoundingClientRect();
    return {
      buttonWidth: buttonRect.width,
      copyWidth: copyRect?.width ?? 0,
      copyMaxWidth: Number.parseFloat(copy ? getComputedStyle(copy).maxWidth : '0'),
      labelText: label?.textContent ?? '',
      copyClientWidth: copy?.clientWidth ?? 0,
      copyScrollWidth: copy?.scrollWidth ?? 0
    };
  });

  expect(localized.buttonWidth).toBe(44);
  expect(localized.copyWidth).toBeGreaterThan(44);
  expect(localized.copyMaxWidth).toBeGreaterThan(120);
  expect(localized.copyMaxWidth).toBeLessThanOrEqual(180);
  expect(localized.labelText).toContain('lokalisierte');
  expect(localized.copyScrollWidth).toBeGreaterThan(localized.copyClientWidth);
  await expect(approval).toBeFocused();
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

  const workspace = page.locator('.workspace-preview');
  const workspaceBox = await workspace.boundingBox();
  await island.getByRole('button', { name: 'Edit conversation title' }).click();
  const titleLayer = page.getByTestId('mobile-title-editor');
  const dimmer = page.locator('.title-edit-dimmer');
  const dimmerBox = await dimmer.boundingBox();
  await expect(titleLayer).toBeVisible();
  await expect(titleLayer).toHaveAttribute('role', 'dialog');
  await expect(titleLayer).toHaveAttribute('aria-modal', 'true');
  await expect(page.getByTestId('represented-mobile-keyboard')).toBeVisible();
  await expect(page.getByRole('textbox', { name: 'Conversation title' })).toBeFocused();
  expect(dimmerBox).not.toBeNull();
  expect(dimmerBox?.x).toBe(workspaceBox?.x);
  expect(dimmerBox?.y).toBe((workspaceBox?.y ?? 0) + 62);
  expect(dimmerBox?.width).toBe(390);
  expect(dimmerBox?.height).toBe(782);
  expect(await dimmer.evaluate((node) => getComputedStyle(node).backdropFilter)).toContain('blur');

  await page.keyboard.press('Escape');
  await expect(titleLayer).toBeHidden();
  await expect(island.getByRole('button', { name: 'Edit conversation title' })).toBeFocused();
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

test('hydrated password submission remains keyboard accessible and credential-free', async ({ page }) => {
  await page.goto(previewUrl('/ui-preview'));
  await page.getByRole('combobox', { name: 'Authentication state' }).selectOption('password');
  const username = page.getByLabel('Username');
  const password = page.getByRole('textbox', { name: 'Password' });
  await username.fill('keyboard-fixture');
  await password.fill('keyboard-only-value');
  await password.press('Enter');

  await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'password-submitting');
  await expect(username).toHaveValue('');
  await expect(password).toHaveValue('');
  await expect(page.locator('.section-note').nth(1)).toHaveText('submit-password-fixture');
  expect(await page.locator('html').textContent()).not.toContain('keyboard-only-value');
});

test('native password activation clears live values without navigation when script execution stops', async ({ page }) => {
  const cdp = await page.context().newCDPSession(page);

  for (const activation of ['click', 'enter'] as const) {
    await cdp.send('Emulation.setScriptExecutionDisabled', { value: false });
    await page.goto(previewUrl('/ui-preview'));
    await page.getByRole('combobox', { name: 'Authentication state' }).selectOption('password');
    const originalUrl = page.url();
    const originalHistoryLength = await page.evaluate(() => history.length);
    const usernameValue = `visible-username-${activation}`;
    const passwordValue = `raw-password-${activation}`;
    const navigationRequests: string[] = [];
    const requestUrls: string[] = [];
    const consoleMessages: string[] = [];
    const onRequest = (request: { isNavigationRequest(): boolean; url(): string }) => {
      requestUrls.push(request.url());
      if (request.isNavigationRequest()) navigationRequests.push(request.url());
    };
    const onConsole = (message: { text(): string }) => consoleMessages.push(message.text());
    page.on('request', onRequest);
    page.on('console', onConsole);

    await cdp.send('Emulation.setScriptExecutionDisabled', { value: true });
    const username = page.getByLabel('Username');
    const password = page.getByRole('textbox', { name: 'Password' });
    await username.fill(usernameValue);
    await password.fill(passwordValue);

    const signIn = page.getByRole('button', { name: 'Sign in' });
    if (activation === 'click') await signIn.click();
    else {
      await signIn.focus();
      await signIn.press('Enter');
    }

    await expect(username).toHaveValue('');
    await expect(password).toHaveValue('');
    await expect(page).toHaveURL(originalUrl);
    expect(await page.evaluate(() => history.length)).toBe(originalHistoryLength);
    const liveDom = await page.locator('html').evaluate((root) => ({
      html: root.outerHTML,
      values: Array.from(root.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>('input, textarea')).map(
        (field) => field.value
      )
    }));
    expect(JSON.stringify(liveDom)).not.toContain(usernameValue);
    expect(JSON.stringify(liveDom)).not.toContain(passwordValue);
    expect(JSON.stringify(consoleMessages)).not.toContain(passwordValue);
    expect(JSON.stringify(requestUrls)).not.toContain(passwordValue);
    expect(JSON.stringify(requestUrls)).not.toContain(usernameValue);
    expect(navigationRequests).toEqual([]);
    // An empty live username control is the screenshot boundary: the captured
    // pixels cannot render the previously entered fixture value.
    expect((await page.screenshot()).byteLength).toBeGreaterThan(0);

    page.off('request', onRequest);
    page.off('console', onConsole);
  }
});

test('Pill consumes one pointer gesture across leave, re-entry, and compatibility click', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(previewUrl('/ui-preview'));
  await page.getByRole('combobox', { name: 'Runtime state' }).selectOption('ready');
  // The trigger remains in the inert, aria-hidden underlay while its modal
  // drawer is open, so inspect the stable DOM control rather than the exposed
  // accessibility tree for the state assertion.
  const workspace = page.locator('button[aria-label="Open workspace"]');

  await workspace.dispatchEvent('pointerdown', { button: 0, pointerType: 'mouse' });
  await expect(workspace).toHaveAttribute('aria-expanded', 'true');
  await workspace.dispatchEvent('pointerleave', { pointerType: 'mouse' });
  await workspace.dispatchEvent('pointerenter', { pointerType: 'mouse' });
  await workspace.dispatchEvent('pointerup', { button: 0, pointerType: 'mouse' });
  await workspace.dispatchEvent('click', { detail: 1 });
  await expect(workspace).toHaveAttribute('aria-expanded', 'true');

  // The open drawer makes the underlay inert, so Escape is the modal close
  // path. Keyboard activation is then verified from the restored trigger.
  await page.keyboard.press('Escape');
  await expect(workspace).toHaveAttribute('aria-expanded', 'false');
  await expect(workspace).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(workspace).toHaveAttribute('aria-expanded', 'true');
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
  await expect(page.getByTestId('auth-preview').getByRole('status')).toContainText('Discovering sign-in methods');
  await expect(page.getByRole('heading', { name: 'Discovering sign-in methods' })).toBeFocused();
  const liveStateOutput = page.getByRole('combobox', { name: 'Authentication state' });
  await expect(liveStateOutput).toBeDisabled();

  releaseResponse();
  await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'provider-selection');
  await expect(page.getByRole('button', { name: 'Nous, unavailable' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Hermes password' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Connect to Hermes' })).toBeFocused();

  await liveStateOutput.evaluate((select: HTMLSelectElement) => {
    select.value = 'discovery-empty';
    select.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'provider-selection');

  // `supports_password: false` does not prove OAuth capability. Only the
  // password-capable provider advances through this reviewed response shape.
  await page.getByRole('button', { name: 'Hermes password' }).click();
  await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'password');
  await expect(page.getByLabel('Username')).toBeFocused();

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
  await expect(page.getByTestId('auth-preview').getByRole('alert')).toContainText('No sign-in method is available');
  await expect(page.getByRole('heading', { name: 'Provider discovery stopped' })).toBeFocused();
  await expect(page.getByRole('combobox', { name: 'Authentication state' })).toBeDisabled();

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
  await expect(page.getByTestId('auth-preview').getByRole('alert')).toContainText('Provider discovery was cancelled');
  await expect(page.getByRole('heading', { name: 'Provider discovery was cancelled' })).toBeFocused();

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

test('forced-colors mode keeps the workspace chrome and focus ring discoverable', async ({ page }) => {
  await page.emulateMedia({ forcedColors: 'active' });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(previewUrl('/ui-preview'));
  await page.getByRole('combobox', { name: 'Runtime state' }).selectOption('ready');

  expect(await page.evaluate(() => matchMedia('(forced-colors: active)').matches)).toBe(true);
  const chrome = await page.locator('.workspace-preview').evaluate((preview) => {
    const element = preview.querySelector('.composer');
    if (!element) throw new Error('Missing workspace composer.');
    const style = getComputedStyle(element);
    return { backgroundColor: style.backgroundColor, borderColor: style.borderColor, boxShadow: style.boxShadow };
  });

  expect(chrome.backgroundColor).toMatch(/^rgb/);
  expect(chrome.borderColor).toMatch(/^rgb/);
  expect(chrome.boxShadow).toBe('none');

  const conversations = page.getByRole('button', { name: 'Open conversations' });
  await conversations.focus();
  await expect(conversations).toBeFocused();
  const outline = await conversations.evaluate((element) => getComputedStyle(element).outlineColor);
  expect(outline).toMatch(/^rgb/);
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
