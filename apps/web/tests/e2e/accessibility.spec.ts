import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';

for (const colorScheme of ['light', 'dark'] as const) {
  for (const scenario of ['success', 'empty', 'failure'] as const) {
    test(`prototype shell has no axe violations in ${colorScheme} ${scenario} state`, async ({ page }) => {
      await page.emulateMedia({ colorScheme, reducedMotion: 'reduce' });
      await page.goto(`/?scenario=${scenario}`);
      await expect(page.getByRole('main')).toBeVisible();
      await expect(page.getByTestId(`status-${scenario}`)).toBeVisible();

      const results = await new AxeBuilder({ page }).analyze();
      expect(results.violations).toEqual([]);
    });
  }
}
