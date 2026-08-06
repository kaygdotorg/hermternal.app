import { expect, test } from '@playwright/test';

for (const viewport of [
  { name: 'desktop', width: 1280, height: 720 },
  { name: 'narrow', width: 375, height: 812 }
]) {
  test(`${viewport.name} layout keeps the prototype shell usable`, async ({ page }) => {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.goto('/?scenario=success');

    await expect(page.getByRole('main')).toBeVisible();
    await expect(page.getByTestId('status-success')).toBeVisible();

    const overflow = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth
    }));
    expect(overflow.scrollWidth).toBeLessThanOrEqual(overflow.clientWidth + 1);
  });
}

test('Tab and Space activate the focused action with an effective target and visible focus', async ({ page }) => {
  await page.goto('/?scenario=success');
  const action = page.getByRole('button', { name: 'Re-run mock check' });

  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
  await page.keyboard.press('Tab');
  await expect(action).toBeFocused();
  const metrics = await action.evaluate((element) => {
    const style = getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    return {
      height: rect.height,
      width: rect.width,
      outlineStyle: style.outlineStyle,
      outlineWidth: style.outlineWidth
    };
  });
  expect(metrics.height).toBeGreaterThanOrEqual(44);
  expect(metrics.width).toBeGreaterThanOrEqual(44);
  expect(metrics.outlineStyle).not.toBe('none');
  expect(metrics.outlineWidth).not.toBe('0px');

  await page.keyboard.press('Space');
  await expect(page.getByTestId('status-success')).toBeVisible();
});

test('200% browser zoom equivalent uses a real 640 CSS-pixel viewport', async ({ page }) => {
  await page.setViewportSize({ width: 640, height: 720 });
  await page.goto('/?scenario=success');

  await expect(page.getByRole('heading', { name: 'Prototype shell' })).toBeVisible();
  const viewportAndOverflow = await page.evaluate(() => ({
    innerWidth: window.innerWidth,
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth
  }));
  expect(viewportAndOverflow.innerWidth).toBe(640);
  expect(viewportAndOverflow.scrollWidth).toBeLessThanOrEqual(viewportAndOverflow.clientWidth + 1);
});

test('computed reduced-motion behavior disables action transition duration', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('/?scenario=success');

  const motion = await page.getByRole('button', { name: 'Re-run mock check' }).evaluate((element) => ({
    mediaMatches: matchMedia('(prefers-reduced-motion: reduce)').matches,
    transitionDuration: getComputedStyle(element).transitionDuration
  }));
  expect(motion.mediaMatches).toBe(true);
  expect(motion.transitionDuration).toBe('0s');
});

test('pending cancellation is visible and safe in the browser shell', async ({ page }) => {
  await page.addInitScript(() => {
    // Hold only the synthetic 250 ms fixture timer. The abort action clears
    // this real browser timer, so the test has no arbitrary click race window.
    const nativeSetTimeout = window.setTimeout.bind(window);
    let holdNextMockDelay = true;
    window.setTimeout = ((handler: TimerHandler, timeout?: number, ...args: any[]) => {
      if (holdNextMockDelay && timeout === 250) {
        holdNextMockDelay = false;
        return nativeSetTimeout(() => undefined, 2_147_483_647);
      }
      return nativeSetTimeout(handler, timeout, ...args);
    }) as typeof window.setTimeout;
  });

  await page.goto('/?scenario=success&delayMs=short');
  await expect(page.getByTestId('status-pending')).toBeVisible();
  const cancel = page.getByRole('button', { name: 'Cancel mock check' });
  await expect(cancel).toBeVisible();
  await expect(cancel).toBeEnabled();
  await cancel.click();

  await expect(page.getByTestId('status-cancelled')).toBeVisible();
  await expect(page.getByTestId('fixture-id')).toHaveText('w01-cancelled-v1');
});
