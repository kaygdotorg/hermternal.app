# Hermternal Chat Lanes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build three coherent, interactive Hermternal chat-screen variants behind the installed prototype picker's exact switching harness and serve them as a web-only mockup.

**Architecture:** Add an isolated static surface at `prototypes/chat-lanes/` so the rejected root prototype remains untouched. A small pure ES module owns variant/theme selection and draft normalization; one DOM controller renders the shared shell and lane-specific transcript composition. Shared semantic tokens enforce geometry, typography, material, themes, responsive behavior, and motion across all lanes.

**Tech Stack:** Semantic HTML, modern CSS, dependency-free ES modules, Node.js built-in test runner, Python static server, Playwright CLI for rendered QA when available.

## Global Constraints

- Web only; no Hermes gateway, authentication, credentials, persistence, telemetry, production API calls, or live user data.
- Primary radii are exactly `12px`, `18px`, and `26px`; circles are limited to avatars, status dots, and icon-only controls.
- Font weights are limited to `400`, `500`, and `600`; no serif typography.
- Sidebar and composer share one material recipe.
- Theme changes affect semantic color/material tokens only.
- All primary controls meet a 44 by 44 CSS-pixel target.
- The current root prototype remains unchanged.
- The prototype picker markup, class names, URL behavior, and keyboard wiring match `/home/hermy/.codex/skills/prototype/PICKER.md`; its visible material alpha follows the later user-approved 60/40 invariant.

---

### Task 1: Pure prototype state contracts

**Files:**
- Create: `prototypes/chat-lanes/state.mjs`
- Create: `prototypes/chat-lanes/state.test.mjs`

**Interfaces:**
- Produces: `VARIANTS`, `THEMES`, `resolveVariant(value)`, `stepVariant(current, delta)`, `normalizeDraft(value)`, and `canSend(value)`.
- `VARIANTS` is the frozen ordered array `continuous`, `stacks`, `focus`.
- `THEMES` is the frozen ordered array `system`, `nord`, `dracula`, `gruvbox`, `solarized`, `catppuccin`, `tokyo-night`, `rose-pine`, `one-dark`, `monokai`.

- [ ] **Step 1: Write failing state behavior tests**

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import { canSend, normalizeDraft, resolveVariant, stepVariant } from './state.mjs';

test('invalid picker input resolves to the first lane', () => {
  assert.equal(resolveVariant('0'), 0);
  assert.equal(resolveVariant('4'), 0);
  assert.equal(resolveVariant('word'), 0);
});

test('variant stepping wraps in both directions', () => {
  assert.equal(stepVariant(2, 1), 0);
  assert.equal(stepVariant(0, -1), 2);
});

test('draft normalization rejects whitespace-only sends', () => {
  assert.equal(normalizeDraft('  hello  '), 'hello');
  assert.equal(canSend('   '), false);
  assert.equal(canSend('hello'), true);
});
```

- [ ] **Step 2: Run the state test and verify RED**

Run: `node --test prototypes/chat-lanes/state.test.mjs`

Expected: FAIL because `state.mjs` does not exist.

- [ ] **Step 3: Implement the minimal pure state module**

```js
export const VARIANTS = Object.freeze(['continuous', 'stacks', 'focus']);
export const THEMES = Object.freeze(['system', 'nord', 'dracula', 'gruvbox', 'solarized', 'catppuccin', 'tokyo-night', 'rose-pine', 'one-dark', 'monokai']);

export function resolveVariant(value) {
  const index = Number.parseInt(value, 10) - 1;
  return Number.isInteger(index) && index >= 0 && index < VARIANTS.length ? index : 0;
}

export function stepVariant(current, delta) {
  return (current + delta + VARIANTS.length) % VARIANTS.length;
}

export function normalizeDraft(value) {
  return value.trim();
}

export function canSend(value) {
  return normalizeDraft(value).length > 0;
}
```

- [ ] **Step 4: Run the state test and verify GREEN**

Run: `node --test prototypes/chat-lanes/state.test.mjs`

Expected: 3 tests pass, 0 fail.

- [ ] **Step 5: Commit the state contract**

```bash
git add prototypes/chat-lanes/state.mjs prototypes/chat-lanes/state.test.mjs
git commit -m "test(mockup): define chat lane state contracts"
```

### Task 2: Shared shell, exact picker, and three lane compositions

**Files:**
- Create: `prototypes/chat-lanes/index.html`
- Create: `prototypes/chat-lanes/styles.css`
- Create: `prototypes/chat-lanes/app.mjs`
- Create: `prototypes/chat-lanes/structure.test.mjs`

**Interfaces:**
- Consumes: state exports from Task 1.
- Produces: `mountVariant(index)`, `setTheme(theme)`, `setSidebar(open)`, `setMenu(name, open)`, `submitDraft()`, and a full semantic DOM surface.
- The stage root carries `data-lane="continuous|stacks|focus"`; CSS changes composition through that attribute without changing semantic content.

- [ ] **Step 1: Write a failing rendered-structure test**

The test starts a temporary `python3 -m http.server` rooted at `prototypes/chat-lanes`, opens it with Playwright when the local CLI is available, and asserts these user-observable outcomes: the page title is `Hermternal chat lanes`; one `main`, one primary `aside`, and one composer form are visible; the picker has exactly three lane buttons; clicking `Turn Stacks` changes the stage to `data-lane="stacks"`; all visible buttons have accessible names.

- [ ] **Step 2: Run the structure test and verify RED**

Run: `node --test prototypes/chat-lanes/structure.test.mjs`

Expected: FAIL because the prototype document and controller do not exist.

- [ ] **Step 3: Implement semantic shared markup and fixtures**

Create realistic local fixtures for long prompts, assistant prose, a compact tool call, an approval request, attachment state, an error row, and a streaming response. Use one app shell with floating sidebar, conversation shell, mobile toolbar/drawer, and matched-material composer. Include attachment/context controls at composer bottom-left; model, voice, and send controls at bottom-right; expand at top-right.

- [ ] **Step 4: Implement exact picker behavior**

Copy the picker markup and CSS from `PICKER.md` verbatim, using names `Continuous Canvas`, `Turn Stacks`, and `Focus Lane`. Implement URL persistence through `?v=1..3`, instant keyed lane remounting, number and arrow keys, replay, active attributes, and the two-frame `data-ready` activation.

- [ ] **Step 5: Implement the shared visual system and lane differences**

Define semantic tokens for the exact radius scale, typography weights, 44px targets, common glass material, shell material, spacing scale, easing, and ten themes. Continuous Canvas uses open assistant prose and one restrained user inset; Turn Stacks groups each exchange with shared boundaries; Focus Lane narrows measure and reveals secondary metadata on focus/hover. Remove traffic lights, trace rails, serif pull quotes, neon, arbitrary gradients, and unrelated cards.

- [ ] **Step 6: Implement responsive and accessible states**

At widths below 820px, replace the sidebar with a left drawer and scrim, preserve focus return, support Escape dismissal, and prevent page scroll while open. Add visible focus, reduced motion, reduced transparency, increased contrast, 200% zoom-safe wrapping, and fine-pointer-only magnetic movement capped at 3px.

- [ ] **Step 7: Run the structure test and verify GREEN**

Run: `node --test prototypes/chat-lanes/structure.test.mjs`

Expected: all structure and picker assertions pass with no browser console error.

- [ ] **Step 8: Commit the shared surface**

```bash
git add prototypes/chat-lanes
git commit -m "feat(mockup): add coherent chat lane picker"
```

### Task 3: Interactive mock states

**Files:**
- Modify: `prototypes/chat-lanes/app.mjs`
- Modify: `prototypes/chat-lanes/styles.css`
- Modify: `prototypes/chat-lanes/structure.test.mjs`

**Interfaces:**
- Consumes: the shared DOM and pure state helpers.
- Produces: local theme switching, model switching, attachment feedback, composer expansion, voice timer, approval outcomes, tool inspection, and local send/streaming behavior.

- [ ] **Step 1: Add failing interaction assertions**

Extend the rendered test to assert: selecting `Nord` changes the document theme while preserving the active lane; choosing `Sonnet` updates the model button; expand toggles `aria-expanded`; whitespace does not send; a real draft appends a local user turn and simulated assistant state; Escape closes the open model menu; opening and closing the mobile drawer restores hamburger focus.

- [ ] **Step 2: Run the interaction test and verify RED**

Run: `node --test prototypes/chat-lanes/structure.test.mjs`

Expected: FAIL on the first missing interaction outcome.

- [ ] **Step 3: Implement minimal local interaction behavior**

Bind controls through stable data attributes. Menus originate at their triggers and close symmetrically. Voice timing runs only while recording. Sending normalizes the draft, appends local markup in the active lane's composition, exposes an `aria-live="polite"` status, and performs no network request.

- [ ] **Step 4: Run all automated tests and verify GREEN**

Run: `node --test prototypes/chat-lanes/*.test.mjs`

Expected: all tests pass, 0 fail, with no warnings.

- [ ] **Step 5: Commit interactions**

```bash
git add prototypes/chat-lanes
git commit -m "feat(mockup): add local chat lane interactions"
```

### Task 4: Documentation, visual QA, serving, and handoff

**Files:**
- Modify: `README.md`
- Create: `prototypes/chat-lanes/README.md`
- Create temporarily outside repo: `/tmp/hermternal-chat-lanes-qa.mjs`
- Create temporarily outside repo: `/tmp/hermternal-chat-lanes-*.png`

**Interfaces:**
- Produces: documented mocked boundaries, a verified browser surface, screenshots outside source control, and a NetBird URL on port `33918`.

- [ ] **Step 1: Document the isolated prototype**

Explain the three lane axes, picker keys, ten theme fixtures, interactive mock states, accessibility behavior, performance boundaries, and the exact command `python3 -m http.server 33918 --bind 0.0.0.0 --directory prototypes/chat-lanes`.

- [ ] **Step 2: Run syntax, test, and source checks**

Run: `node --check prototypes/chat-lanes/app.mjs && node --check prototypes/chat-lanes/state.mjs && node --test prototypes/chat-lanes/*.test.mjs && git diff --check`

Expected: all commands exit 0.

- [ ] **Step 3: Run desktop and mobile browser QA**

The Browser plugin is absent, so use Playwright. Verify page identity, meaningful DOM, no framework overlay, no console warnings/errors, all three picker lanes, theme and model changes, composer expand/send, mobile drawer, keyboard controls, 1440 by 1000 desktop, 1024 by 1366 tablet, and 390 by 844 mobile.

- [ ] **Step 4: Capture and inspect evidence**

Capture each lane at 1440 by 1000 and the Continuous Canvas mobile state at 390 by 844. Use `view_image` on the captures in one QA pass. Record at least five comparison points: radius consistency, typography weights, shared sidebar/composer material, transcript cohesion, control placement, responsive drawer, and theme invariance.

- [ ] **Step 5: Update graph and review impact**

Run: `code-review-graph update --brief && code-review-graph detect-changes`.

Expected: changes remain isolated to documentation and `prototypes/chat-lanes/`; the rejected root prototype is unchanged.

- [ ] **Step 6: Commit and push documentation**

```bash
git add README.md prototypes/chat-lanes/README.md
git commit -m "docs(mockup): document chat lane exploration"
git push -u origin mockup/chat-lanes-v3-build
```

- [ ] **Step 7: Serve the verified picker on NetBird**

Stop only the existing Python server bound to `0.0.0.0:33918`, start the exact server command from Step 1 in the build worktree, and verify `curl -I http://10.69.69.155:33918/` returns HTTP 200.

### Task 5: Refine the selected Canvas system

**Files:**
- Modify: `prototypes/chat-lanes/index.html`
- Modify: `prototypes/chat-lanes/styles.css`
- Modify: `prototypes/chat-lanes/app.mjs`
- Modify: `prototypes/chat-lanes/structure.test.mjs`
- Modify: `prototypes/chat-lanes/README.md`

**Interfaces:**
- Produces named layer, opacity, blur, radius, type, and magnetic-motion tokens.
- Produces reusable `icon-button`, `pill`, `action-cluster`, and `segmented-selector` class contracts.
- Preserves all existing local-only interactions and the three-lane comparison harness.

- [ ] **Step 1: Add failing source and structure contracts**

Assert a named menu layer above the conversation shell, a 60%-opaque shared material token, an 18%/7px magnetic configuration using CSS `translate`, reusable control-family classes, and a plain model trigger without the persistent accent fill.

- [ ] **Step 2: Run tests and verify RED**

Run: `node --test prototypes/chat-lanes/*.test.mjs`

Expected: the new refinement contracts fail against the original Canvas system.

- [ ] **Step 3: Implement the shared material, controls, and compact composer**

Apply the accepted system without adding dependencies or production integrations. Preserve 44px targets, keyboard behavior, reduced motion, reduced transparency, and all ten themes.

- [ ] **Step 4: Run automated and rendered checks**

Run syntax, unit, structure, Playwright desktop/mobile interaction, contrast, zoom, and screenshot checks. Inspect the screenshots directly and correct visual drift.

- [ ] **Step 5: Document, inspect, commit, push, and serve**

Update the prototype README with the material and primitive contracts, update the code-review graph, inspect change impact and diff, commit the atomic refinement, push the branch, and verify HTTP 200 at `http://10.69.69.155:33918/`.
