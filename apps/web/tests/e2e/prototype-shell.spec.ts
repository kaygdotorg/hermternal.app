import { expect, test } from '@playwright/test';

for (const viewport of [
  { name: 'desktop', width: 1280, height: 720 },
  { name: 'narrow', width: 375, height: 812 }
]) {
  test(`${viewport.name} layout keeps the prototype shell usable`, async ({ page }) => {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.goto('/');

    await expect(page.getByRole('main')).toBeVisible();
    await expect(page.getByTestId('status-success')).toBeVisible();

    const overflow = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth
    }));
    expect(overflow.scrollWidth).toBeLessThanOrEqual(overflow.clientWidth + 1);
  });
}

test('keyboard focus and activation remain available', async ({ page }) => {
  await page.goto('/');
  const action = page.getByRole('button', { name: 'Re-run mock check' });

  await action.focus();
  await expect(action).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.getByTestId('status-success')).toBeVisible();
});

test('200% zoom simulation and reduced motion keep content accessible', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('/');
  await page.evaluate(() => {
    document.documentElement.style.zoom = '2';
  });

  await expect(page.getByRole('heading', { name: 'Prototype shell' })).toBeVisible();
  expect(await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches)).toBe(true);

  const overflow = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth
  }));
  expect(overflow.scrollWidth).toBeLessThanOrEqual(overflow.clientWidth + 1);
});
