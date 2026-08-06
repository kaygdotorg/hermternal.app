import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';

for (const viewport of [
  { name: 'desktop', width: 1440, height: 900 },
  { name: 'tablet', width: 768, height: 1024 },
  { name: 'narrow', width: 390, height: 844 }
]) {
  test(`${viewport.name} UI preview keeps both surfaces usable`, async ({ page }) => {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.goto('/ui-preview');

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
  await page.goto('/ui-preview');

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

test('UI preview has no axe violations', async ({ page }) => {
  await page.goto('/ui-preview');

  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
});

test('records production preview timing without a threshold', async ({ page }) => {
  await page.goto('/ui-preview', { waitUntil: 'networkidle' });

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
    await page.goto('/ui-preview');

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
  const expectedOrigin = new URL('http://127.0.0.1:4173').origin;

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
  await page.goto('/ui-preview');
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
