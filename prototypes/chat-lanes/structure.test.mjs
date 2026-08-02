import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, statSync } from 'node:fs';

import {
  renderPicker,
  renderThemeOptions,
  renderVariant,
} from './view.mjs';

const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
const styles = readFileSync(new URL('./styles.css', import.meta.url), 'utf8');
const app = readFileSync(new URL('./app.mjs', import.meta.url), 'utf8');

test('selected Canvas refinement exposes reusable material and control primitives', () => {
  const primitives = readFileSync(new URL('./primitives.css', import.meta.url), 'utf8');

  assert.match(html, /href="primitives\.css"/);
  assert.match(primitives, /\.glass-surface/);
  assert.match(primitives, /\.ui-button/);
  assert.match(primitives, /\.ui-pill/);
  assert.match(primitives, /\.ui-selector/);
  assert.match(primitives, /\.ui-action-cluster/);
  assert.match(primitives, /backdrop-filter:\s*blur\(var\(--glass-blur\)\)\s+saturate\(var\(--glass-saturation\)\)/);
});

test('material, layering, typography, and magnetic motion use accepted shared tokens', () => {
  assert.match(styles, /--material-opacity:\s*50%/);
  assert.match(styles, /--surface-raised-opacity:\s*50%/);
  assert.doesNotMatch(styles, /--(?:material|surface-raised):\s*rgba/);
  assert.match(styles, /\.proto-picker\s*\{[^}]*background:\s*rgba\(10, 10, 10, 0\.5\)/s);
  assert.match(styles, /\.proto-picker\s*\{[^}]*-webkit-backdrop-filter:\s*blur\(var\(--glass-blur\)\)\s+saturate\(var\(--glass-saturation\)\)[^}]*backdrop-filter:\s*blur\(var\(--glass-blur\)\)\s+saturate\(var\(--glass-saturation\)\)/s);
  assert.match(styles, /@media \(prefers-reduced-transparency: reduce\)\s*\{[^]*\.glass-surface, \.material-floating, \.proto-picker\s*\{[^}]*background:\s*var\(--material-solid\)[^}]*backdrop-filter:\s*none[^}]*-webkit-backdrop-filter:\s*none/s);
  assert.doesNotMatch(styles, /\.composer-dock::before/);
  assert.match(styles, /--layer-sidebar:\s*20/);
  assert.match(styles, /--layer-menu:\s*100/);
  assert.match(styles, /\.sidebar\s*\{[^}]*z-index:\s*var\(--layer-sidebar\)/s);
  assert.match(styles, /\.floating-menu\s*\{[^}]*z-index:\s*var\(--layer-menu\)/s);
  assert.match(app, /MAGNETIC_STRENGTH\s*=\s*0\.18/);
  assert.match(app, /MAGNETIC_MAX\s*=\s*7/);
  assert.match(app, /target\.style\.translate/);
});

test('system theme follows the host color scheme without changing explicit themes', () => {
  assert.match(
    styles,
    /@media \(prefers-color-scheme: dark\)\s*\{\s*html\[data-theme="system"\]\s*\{[^}]*color-scheme:\s*dark/s,
  );
  assert.match(styles, /html\[data-theme="system"\][\s\S]*--canvas:\s*#171a20/);
  assert.match(styles, /html\[data-theme="nord"\]\s*\{\s*color-scheme:\s*dark/s);
});

test('menus expose keyboard navigation and preserve touch-sized brand hit areas', () => {
  assert.match(app, /function moveMenuFocus\(event\)/);
  assert.match(app, /event\.key === 'ArrowDown'/);
  assert.match(app, /event\.key === 'ArrowUp'/);
  assert.match(app, /previouslyOpenTrigger\.focus/);
  assert.match(styles, /\.brand, \.mobile-brand\s*\{[^}]*min-height:\s*44px/s);
});

test('official Geist variable fonts are self-hosted with license and fallbacks', () => {
  const sans = new URL('./assets/fonts/Geist[wght].woff2', import.meta.url);
  const mono = new URL('./assets/fonts/GeistMono[wght].woff2', import.meta.url);
  assert.equal(existsSync(sans), true);
  assert.equal(existsSync(mono), true);
  assert.ok(statSync(sans).size > 60_000);
  assert.ok(statSync(mono).size > 60_000);
  assert.equal(existsSync(new URL('./assets/fonts/OFL.txt', import.meta.url)), true);
  assert.match(styles, /@font-face\s*\{[^}]*font-family:\s*"Geist"[^}]*Geist%5Bwght%5D\.woff2[^}]*font-display:\s*swap/s);
  assert.match(styles, /@font-face\s*\{[^}]*font-family:\s*"Geist Mono"[^}]*GeistMono%5Bwght%5D\.woff2[^}]*font-display:\s*swap/s);
  assert.match(styles, /font-family:\s*"Geist", system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif/);
  assert.match(styles, /\.proto-picker\s*\{[^}]*font-family:\s*"Geist", system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif/s);
});

test('compact composer keeps its selector quiet and its actions unframed', () => {
  assert.match(html, /class="model-trigger ui-button ui-selector magnetic"/);
  assert.match(styles, /\.composer\s*\{[^}]*min-height:\s*6\.25rem/s);
  assert.match(styles, /\.model-trigger\s*\{[^}]*background:\s*transparent/s);
  assert.doesNotMatch(html, /composer-toolbar[^]*ui-action-cluster/);
});

test('desktop shell heights align and the top chrome is composed from islands', () => {
  assert.match(html, /class="conversation-title glass-surface header-island"/);
  assert.match(html, /class="header-actions glass-surface header-island"/);
  assert.match(styles, /\.app-shell\s*\{[^}]*align-items:\s*stretch/s);
  assert.match(styles, /\.sidebar\s*\{[^}]*position:\s*relative[^}]*height:\s*auto/s);
  assert.match(html, /class="sidebar-inner"/);
  assert.match(styles, /\.sidebar-inner\s*\{[^}]*position:\s*sticky[^}]*height:\s*calc\(100vh - 2rem\)/s);
  assert.match(styles, /\.conversation-header\s*\{[^}]*border-bottom:\s*0[^}]*background:\s*transparent[^}]*backdrop-filter:\s*none/s);
  assert.match(styles, /\.header-island\s*\{[^}]*border-radius:\s*999px/s);
  assert.match(styles, /\.header-actions \.ui-action-cluster\s*\{[^}]*border:\s*0[^}]*background:\s*transparent/s);
  assert.match(styles, /@media \(max-width: 820px\)\s*\{[^]*\.app-shell\s*\{[^}]*z-index:\s*auto/s);
  const primitives = readFileSync(new URL('./primitives.css', import.meta.url), 'utf8');
  assert.match(primitives, /\.ui-pill\s*\{[^}]*background:\s*var\(--material\)/s);
  assert.match(primitives, /\.ui-action-cluster\s*\{[^}]*background:\s*var\(--material\)/s);
});

test('compact chrome uses one primary label without stacked subtitles', () => {
  const sidebar = html.match(/<aside class="sidebar[\s\S]*?<\/aside>/)?.[0] ?? '';
  const title = html.match(/<div class="conversation-title[\s\S]*?<\/div>/)?.[0] ?? '';
  const models = html.match(/<div class="floating-menu model-menu[\s\S]*?<\/div>\s*<\/div>/)?.[0] ?? '';
  assert.doesNotMatch(sidebar, /<small/);
  assert.doesNotMatch(title, /<p>/);
  assert.equal((title.match(/<h1/g) ?? []).length, 1);
  assert.doesNotMatch(models, /<small/);
  assert.doesNotMatch(html, /data-theme-label/);
  assert.doesNotMatch(html, /Color only—geometry stays fixed/);
  assert.match(styles, /\.conversation-title\.header-island\s*\{[^}]*display:\s*flex[^}]*align-items:\s*center[^}]*justify-content:\s*center/s);
});

test('motion opportunities use restrained shared recipes and reduced-motion fallbacks', () => {
  assert.match(app, /MENU_ENTER_MS\s*=\s*180/);
  assert.match(app, /MENU_EXIT_MS\s*=\s*130/);
  assert.match(app, /menu\.animate/);
  assert.match(app, /lastInputModality\s*===\s*'keyboard'/);
  assert.match(app, /TOAST_EXIT_MS\s*=\s*140/);
  assert.match(app, /lastInputModality\s*!==\s*'keyboard'\s*\?\s*''\s*:\s*' motion-immediate'/);
  assert.match(styles, /\.toast\.motion-immediate[^}]*transition:\s*none/s);
  assert.match(styles, /\.toast\.is-visible\s*\{[^}]*opacity:\s*1[^}]*transform:\s*translateY\(0\) scale\(1\)/s);
  assert.match(styles, /@starting-style\s*\{[^]*\.local-turn\s*\{[^}]*opacity:\s*0[^}]*transform:\s*translateY\(8px\)/s);
  assert.match(styles, /@starting-style\s*\{[^]*\.approval-result\s*\{[^}]*opacity:\s*0[^}]*transform:\s*translateY\(4px\)/s);
  assert.match(styles, /@media \(prefers-reduced-motion: reduce\)\s*\{[^]*transition-duration:\s*120ms\s*!important/s);
  assert.match(styles, /@media \(prefers-reduced-motion: reduce\)\s*\{[^]*\.toast\.motion-immediate[^}]*transition:\s*none\s*!important/s);
});

test('each lane renders the same conversation content through a distinct container model', () => {
  const continuous = renderVariant('continuous');
  const stacks = renderVariant('stacks');
  const focus = renderVariant('focus');

  for (const [lane, markup] of Object.entries({ continuous, stacks, focus })) {
    assert.match(markup, new RegExp(`data-lane="${lane}"`));
    assert.match(markup, /Plan a calm product launch/);
    assert.match(markup, /Reviewing launch-notes\.md/);
    assert.match(markup, /Allow once/);
  }

  assert.match(continuous, /lane-continuous/);
  assert.match(stacks, /lane-stacks/);
  assert.match(focus, /lane-focus/);
});

test('picker exposes exactly three named lane controls', () => {
  const picker = renderPicker();
  assert.equal((picker.match(/data-variant-index=/g) ?? []).length, 3);
  assert.match(picker, /aria-label="Continuous Canvas">Canvas</);
  assert.match(picker, /aria-label="Turn Stacks">Stacks</);
  assert.match(picker, /aria-label="Focus Lane">Focus</);
});

test('theme menu exposes all ten theme fixtures as named controls', () => {
  const options = renderThemeOptions();
  assert.equal((options.match(/data-theme-value=/g) ?? []).length, 10);
  assert.match(options, />System</);
  assert.match(options, />Monokai</);
});

test('mobile overlays clear the fixed prototype picker without losing menu scroll budget', () => {
  assert.match(
    styles,
    /@media \(max-width: 820px\)\s*\{[^]*\.theme-menu\s*\{[^}]*bottom:\s*4\.75rem[^}]*max-height:\s*75vh[^}]*overflow-y:\s*auto/s,
  );
  assert.match(
    styles,
    /@media \(max-width: 820px\)\s*\{[^]*\.toast\s*\{[^}]*bottom:\s*calc\(4\.75rem \+ 7\.25rem \+ \.75rem\)/s,
  );
});

test('appearance menu escapes the sidebar backdrop root while keeping the shared glass recipe', () => {
  const sidebarEnd = html.indexOf('</aside>');
  const themeMenu = html.indexOf('id="theme-menu"');

  assert.ok(sidebarEnd > -1);
  assert.ok(themeMenu > sidebarEnd);
  assert.match(html, /data-menu-trigger="theme"[^>]*aria-controls="theme-menu"/);
  assert.match(styles, /\.theme-menu\s*\{[^}]*position:\s*fixed[^}]*z-index:\s*var\(--layer-menu\)/s);
});

test('model menu also escapes its blurred composer and anchors through shared menu geometry', () => {
  const composerMarkup = html.match(/<form class="composer[\s\S]*?<\/form>/)?.[0] ?? '';
  const mainEnd = html.indexOf('</main>');
  const modelMenu = html.indexOf('id="model-menu"');

  assert.doesNotMatch(composerMarkup, /data-menu="model"/);
  assert.ok(modelMenu > mainEnd);
  assert.match(html, /data-menu-trigger="model"[^>]*aria-controls="model-menu"/);
  assert.match(styles, /\.model-menu\s*\{[^}]*position:\s*fixed/s);
  assert.match(app, /function positionFloatingMenu\(menu, trigger\)/);
});

test('tool and approval rows reserve a readable two-line content block', () => {
  const continuous = renderVariant('continuous');

  assert.equal((continuous.match(/class="event-copy"/g) ?? []).length, 2);
  assert.match(styles, /\.event-row\s*\{[^}]*min-height:\s*72px[^}]*padding:\s*\.7rem\s+\.75rem/s);
  assert.match(styles, /\.event-copy\s*\{[^}]*min-height:\s*2\.5rem[^}]*align-content:\s*center[^}]*gap:\s*\.18rem/s);
  assert.match(styles, /\.event-copy span\s*\{[^}]*line-height:\s*1\.35/s);
});

test('composer actions use mobile-reference visual weight without shrinking touch targets', () => {
  assert.match(html, /href="primitives\.css"[^>]*>[\s\S]*href="styles\.css"/);
  assert.match(styles, /--composer-action-size:\s*48px/);
  assert.match(styles, /\.composer-toolbar \.ui-icon-button\s*\{[^}]*width:\s*var\(--composer-action-size\)[^}]*height:\s*var\(--composer-action-size\)/s);
  assert.match(styles, /\.composer-toolbar \.ui-icon-button svg\s*\{[^}]*width:\s*1\.3rem[^}]*height:\s*1\.3rem/s);
  assert.match(styles, /\.text-control, \.model-trigger\s*\{[^}]*min-height:\s*var\(--composer-action-size\)/s);
});
