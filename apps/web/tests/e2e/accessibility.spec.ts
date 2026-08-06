import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';

test('prototype shell has no axe violations', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('main')).toBeVisible();

  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
});
