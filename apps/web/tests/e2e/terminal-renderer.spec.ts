import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';

const wTermCss = readFileSync(resolve(process.cwd(), 'node_modules/@wterm/dom/src/terminal.css'), 'utf8');
const rendererCss = readFileSync(resolve(process.cwd(), 'src/lib/terminal/terminal.css'), 'utf8');

test('production-shaped terminal cursor disables animation under reduced motion', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.setContent(`
    <style>${wTermCss}\n${rendererCss}</style>
    <div class="terminal-renderer wterm focused cursor-blink" role="region" aria-label="Terminal">
      <div class="term-grid"><div class="term-row"><span class="term-cursor">x</span></div></div>
    </div>
  `);

  await expect(page.locator('.term-cursor')).toHaveCSS('animation-name', 'none');
});

test('normalized W-Term input has no axe violations for aria-hidden-focus', async ({ page }) => {
  await page.setContent(`
    <main>
      <div class="terminal-renderer wterm" role="region" aria-label="Terminal">
        <textarea tabindex="0" aria-label="Terminal input"></textarea>
        <div class="term-grid"><div class="term-row"><span>output</span></div></div>
      </div>
    </main>
  `);

  const results = await new AxeBuilder({ page })
    .include('.terminal-renderer')
    .withRules(['aria-hidden-focus'])
    .analyze();
  expect(results.violations).toEqual([]);
});
