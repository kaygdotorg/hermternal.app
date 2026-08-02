# Geist Typography and 50/50 Material Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refine the selected Canvas mockup with self-hosted Geist typography, single-line compact chrome, and one visually consistent 50/50 translucent material system.

**Architecture:** Keep the dependency-free static prototype and its shared token/primitives boundary. Add two pinned official Geist variable webfonts as local assets, express typography and material behavior through existing semantic tokens, simplify static HTML rather than hiding unwanted subtitles with CSS, and protect the decisions with source contracts plus Playwright computed-style and responsive checks.

**Tech Stack:** Static HTML, CSS custom properties, vanilla ES modules, Node test runner, Playwright Chromium, official Geist WOFF2 assets under SIL OFL 1.1.

## Global Constraints

- Prototype-only: no Hermes gateway, authentication, production API, telemetry, persistence, or live user data.
- Web is the only implementation target in this task; verify desktop, iPad-width, and iPhone-width responsive states.
- Self-host Geist Sans for UI/prose and Geist Mono only for code/tool output; keep `system-ui`, `-apple-system`, `BlinkMacSystemFont`, and `"Segoe UI"` fallbacks.
- Permit only weights 400, 500, and 600 in app typography.
- Every translucent material and raised surface uses 50% opacity; every glass surface keeps `20px` blur and `1.38` saturation.
- Compact pills, islands, sidebar rows, and menu options show one primary label only; timestamps and section headings remain separate metadata.
- Controls retain 44 CSS-pixel minimum targets, magnetic pointer behavior, keyboard immediacy, and Reduced Motion/Transparency handling.
- Load no remote runtime assets and preserve the prototype's dependency-free startup.

---

### Task 1: Pin and load the official Geist family

**Files:**
- Create: `prototypes/chat-lanes/assets/fonts/Geist[wght].woff2`
- Create: `prototypes/chat-lanes/assets/fonts/GeistMono[wght].woff2`
- Create: `prototypes/chat-lanes/assets/fonts/OFL.txt`
- Create: `prototypes/chat-lanes/assets/fonts/LICENSE.txt`
- Modify: `prototypes/chat-lanes/styles.css:1-45`
- Modify: `prototypes/chat-lanes/structure.test.mjs:1-48`

**Interfaces:**
- Consumes: official `vercel/geist-font` commit `10dc7658f13c38a474cde201bb09a4617267545b`.
- Produces: CSS families `"Geist"` and `"Geist Mono"`, available before all theme and component rules.

- [ ] **Step 1: Write the failing font asset and CSS contract**

Add `existsSync` and `statSync` imports in `structure.test.mjs`, then add:

```js
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
});
```

- [ ] **Step 2: Run the test and verify the missing-asset failure**

Run: `rtk run 'node --test prototypes/chat-lanes/structure.test.mjs'`

Expected: FAIL in `official Geist variable fonts are self-hosted with license and fallbacks` because the font assets and `@font-face` rules do not exist.

- [ ] **Step 3: Copy pinned official assets and verify their hashes**

Use the already-audited checkout `/tmp/geist-font-ref` at commit `10dc7658f13c38a474cde201bb09a4617267545b`:

```sh
mkdir -p prototypes/chat-lanes/assets/fonts
cp '/tmp/geist-font-ref/fonts/Geist/webfonts/Geist[wght].woff2' prototypes/chat-lanes/assets/fonts/
cp '/tmp/geist-font-ref/fonts/GeistMono/webfonts/GeistMono[wght].woff2' prototypes/chat-lanes/assets/fonts/
cp /tmp/geist-font-ref/OFL.txt /tmp/geist-font-ref/LICENSE.txt prototypes/chat-lanes/assets/fonts/
sha256sum prototypes/chat-lanes/assets/fonts/*
```

Expected hashes:

```text
2ffebe993e969069a9789d15164b7715d42491b5835516c5e3b935d5f81b05f1  Geist[wght].woff2
afaacc4c5fbba89d2ebf7a02dc4070208540874592a5504d57175782fe893101  GeistMono[wght].woff2
c683bfbcc7e087f5d37a54ef628f10387c451a83ddc459b151403a164ac46c90  OFL.txt
930853ee1daa68554d9e35c8a9175affb74f699fad9a5da6ee5ebe76379d9137  LICENSE.txt
```

- [ ] **Step 4: Add the font-face and semantic family rules**

At the top of `styles.css`, add:

```css
@font-face {
  font-family: "Geist";
  src: url("assets/fonts/Geist%5Bwght%5D.woff2") format("woff2");
  font-style: normal;
  font-weight: 100 900;
  font-display: swap;
}

@font-face {
  font-family: "Geist Mono";
  src: url("assets/fonts/GeistMono%5Bwght%5D.woff2") format("woff2");
  font-style: normal;
  font-weight: 100 900;
  font-display: swap;
}
```

Change the root family to:

```css
font-family: "Geist", system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
```

Change tool/code rules to:

```css
font-family: "Geist Mono", ui-monospace, "SFMono-Regular", Consolas, monospace;
```

- [ ] **Step 5: Run the font contract and syntax checks**

Run: `rtk run 'node --check prototypes/chat-lanes/app.mjs' && rtk run 'node --test prototypes/chat-lanes/*.test.mjs'`

Expected: all tests PASS.

- [ ] **Step 6: Commit the font foundation**

```sh
git add prototypes/chat-lanes/assets/fonts prototypes/chat-lanes/styles.css prototypes/chat-lanes/structure.test.mjs
git commit -m "feat(mockup): self-host geist typography"
```

### Task 2: Collapse compact chrome to one label

**Files:**
- Modify: `prototypes/chat-lanes/index.html:27-108`
- Modify: `prototypes/chat-lanes/app.mjs:121-129`
- Modify: `prototypes/chat-lanes/styles.css:280-430`
- Modify: `prototypes/chat-lanes/structure.test.mjs:49-82`

**Interfaces:**
- Consumes: the `"Geist"` family from Task 1 and existing `data-theme-value`/`data-model` selection hooks.
- Produces: a single-label sidebar, conversation title island, Appearance heading, and model menu without changing selection behavior.

- [ ] **Step 1: Write the failing single-label structure contract**

Add:

```js
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
```

- [ ] **Step 2: Run the test and verify the subtitle failure**

Run: `rtk run 'node --test prototypes/chat-lanes/structure.test.mjs'`

Expected: FAIL because sidebar `<small>` elements, the title `<p>`, model subtitles, and the Appearance explanation remain.

- [ ] **Step 3: Simplify semantic HTML without hiding information in CSS**

In `index.html`:

- Replace brand content with `<span><strong>Hermternal</strong></span>`.
- Remove each history-row `<small>` while retaining its `<strong>` title and `<time>`.
- Replace Appearance content with `<span><strong>Appearance</strong></span>` and remove `data-theme-label`.
- Replace profile content with `<span><strong>Alex Morgan</strong></span>`.
- Replace the conversation title island contents with `<h1>Shape the opening</h1>`.
- Replace the theme menu header with `<header><strong>Theme</strong></header>`.
- Remove every model option `<small>` while preserving model names and `data-model` attributes.

In `app.mjs`, remove the line that writes to `[data-theme-label]`; theme radio state remains the source of truth.

- [ ] **Step 4: Normalize Geist metrics and vertical alignment**

In `styles.css`:

```css
.brand strong, .profile-row strong, .footer-row strong, .history-row strong {
  font-size: .8125rem;
  font-weight: 500;
  line-height: 1.2;
  letter-spacing: -.006em;
}
.history-row { min-height: 48px; }
.section-label, .history-row time { font-size: .6875rem; }
.conversation-title.header-island {
  display: flex;
  min-width: 0;
  min-height: 50px;
  align-items: center;
  justify-content: center;
  padding: 0 1rem;
}
.conversation-title h1 {
  overflow: hidden;
  font-size: .9375rem;
  font-weight: 600;
  line-height: 1;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.theme-menu header { display: flex; align-items: center; min-height: 44px; padding: 0 .65rem; }
```

Delete obsolete `small` and `.conversation-title p` selectors. Keep all interactive rows at least 44px tall.

- [ ] **Step 5: Run source and interaction regressions**

Run: `rtk run 'node --check prototypes/chat-lanes/app.mjs' && rtk run 'node --test prototypes/chat-lanes/*.test.mjs' && rtk run 'node /tmp/hermternal-motion-qa.mjs > /tmp/hermternal-motion-qa-geist.json'`

Expected: all tests pass; theme/model selection and motion checks remain green with no console errors.

- [ ] **Step 6: Commit the single-label hierarchy**

```sh
git add prototypes/chat-lanes/index.html prototypes/chat-lanes/app.mjs prototypes/chat-lanes/styles.css prototypes/chat-lanes/structure.test.mjs
git commit -m "refactor(mockup): simplify compact chat chrome"
```

### Task 3: Normalize every translucent surface to 50/50

**Files:**
- Modify: `prototypes/chat-lanes/styles.css:1-40,360-465`
- Modify: `prototypes/chat-lanes/structure.test.mjs:25-48`
- Modify: `prototypes/chat-lanes/README.md:20-34`

**Interfaces:**
- Consumes: shared `--material`, `--surface-raised`, `.glass-surface`, and `.material-floating` boundaries.
- Produces: one 0.5-alpha material/raised-surface invariant and an unpainted composer dock backdrop.

- [ ] **Step 1: Write the failing 50/50 and no-veil contract**

Update the material contract to assert:

```js
assert.match(styles, /--material-opacity:\s*50%/);
assert.match(styles, /--surface-raised-opacity:\s*50%/);
assert.match(styles, /\.proto-picker\s*\{[^}]*background:\s*rgba\(10, 10, 10, 0\.5\)/s);
assert.doesNotMatch(styles, /\.composer-dock::before/);
```

- [ ] **Step 2: Run the test and verify the 60/40 failure**

Run: `rtk run 'node --test prototypes/chat-lanes/structure.test.mjs'`

Expected: FAIL because both opacity tokens and picker alpha remain 60%, and the dock pseudo-element still paints a 58% veil.

- [ ] **Step 3: Apply the one-token material rule**

In `styles.css`:

```css
--material-opacity: 50%;
--surface-raised-opacity: 50%;
```

Change `.proto-picker` background to `rgba(10, 10, 10, 0.5)` and delete `.composer-dock::before` entirely. Do not alter semantic danger/recording overlays or the drawer scrim because they are state indicators, not material surfaces.

- [ ] **Step 4: Document the new invariant and font assets**

Update `prototypes/chat-lanes/README.md` to state:

- Geist Sans/Mono are pinned, self-hosted prototype assets under SIL OFL 1.1.
- Compact chrome contains one primary label.
- Material and raised-surface opacity is 50%, blur is 20px, saturation is 1.38.
- The composer dock does not paint an additional veil.

- [ ] **Step 5: Run the full source suite**

Run: `rtk run 'node --test prototypes/chat-lanes/*.test.mjs' && rtk git diff --check`

Expected: all tests pass and diff check emits no output.

- [ ] **Step 6: Commit the 50/50 material refinement**

```sh
git add prototypes/chat-lanes/styles.css prototypes/chat-lanes/structure.test.mjs prototypes/chat-lanes/README.md
git commit -m "feat(mockup): normalize glass surfaces to fifty fifty"
```

### Task 4: Browser, accessibility, visual, and repository verification

**Files:**
- Modify only if a verification failure requires an in-scope correction: `prototypes/chat-lanes/index.html`, `prototypes/chat-lanes/styles.css`, `prototypes/chat-lanes/app.mjs`, `prototypes/chat-lanes/structure.test.mjs`, `prototypes/chat-lanes/README.md`

**Interfaces:**
- Consumes: completed Geist, single-label, and 50/50 tasks.
- Produces: desktop/iPad/iPhone screenshots and measured proof for final handoff.

- [ ] **Step 1: Verify computed fonts and materials in Chromium**

Using Playwright against `http://127.0.0.1:33918/?v=1`, assert:

```js
await page.evaluate(() => document.fonts.check('16px Geist')) === true;
```

For `.composer`, `.theme-menu`, `.model-menu`, `.sidebar`, `.header-island`, and `.mobile-toolbar`, parse `getComputedStyle(element).backgroundColor` and require alpha `0.5`; require `backdropFilter === 'blur(20px) saturate(1.38)'`. Open each menu before measuring it. Require `getComputedStyle(document.querySelector('.composer-dock'), '::before').content === 'none'`.

- [ ] **Step 2: Verify responsive hierarchy and accessibility**

At 1440×1000, 1024×1366, and 390×844:

- Require no horizontal overflow.
- Require every visible button to have an accessible name.
- Require sidebar and canvas desktop heights to differ by at most 1px.
- Require the mobile drawer close hit target to win `elementFromPoint` and return focus to the hamburger.
- Require the title island, history rows, Appearance row, profile row, model rows, and theme header to remain single-line.
- Exercise theme selection, model selection, local send, approval, Escape dismissal, keyboard send, and Reduced Motion.
- Record zero `console.error`, `console.warn`, and `pageerror` events.

- [ ] **Step 3: Verify every theme's material alpha and contrast**

For System, Nord, Dracula, Gruvbox, Solarized, Catppuccin, Tokyo Night, Rosé Pine, One Dark, and Monokai:

- Open Appearance and measure composer/menu background alpha at `0.5`.
- Confirm primary and secondary text contrast remains at least 4.5:1 against the solid reading canvas.
- Confirm focus outlines remain visible.

- [ ] **Step 4: Capture and inspect final screenshots**

Capture:

```text
/tmp/hermternal-geist-desktop.png
/tmp/hermternal-geist-ipad.png
/tmp/hermternal-geist-iphone.png
/tmp/hermternal-geist-appearance.png
```

Use `view_image` on all four. Reject the result if typography looks cramped, any compact chrome contains two text tiers, the composer looks more opaque than the Appearance menu over the solid canvas, or the composer obscures controls/content illegibly.

- [ ] **Step 5: Update graph and inspect change impact**

Run:

```sh
code-review-graph update --brief
code-review-graph detect-changes
code-review-graph impact --files prototypes/chat-lanes/index.html prototypes/chat-lanes/styles.css prototypes/chat-lanes/app.mjs prototypes/chat-lanes/structure.test.mjs
rtk git diff --check
rtk git diff --stat
```

Expected: graph update succeeds, changed scope remains within the prototype and its documentation, and diff check emits no output.

- [ ] **Step 6: Push atomic commits and verify the NetBird endpoint**

Run:

```sh
git push
systemctl --user is-active hermternal-chat-lanes.service
curl -fsSI --max-time 5 'http://10.69.69.155:33918/?v=1'
git status --short
git log -4 --oneline
```

Expected: push succeeds, service is `active`, endpoint returns HTTP 200, worktree is clean, and the log shows the spec plus three implementation commits.

