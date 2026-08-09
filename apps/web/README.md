# Web client

## Status

This directory contains the W-01 static scaffold and a separate high-fidelity presentation preview. Both are planning, mock, and proof artifacts:

- Svelte 5 + SvelteKit 2 + Vite + Bun
- `@sveltejs/adapter-static` with a distinct `200.html` client-route fallback
- a web app manifest and same-origin static-asset service worker with a closed allowlist
- normal app-startup service-worker registration that fails closed without blocking input or logging URLs/errors
- a prototype-labelled root shell backed by deterministic in-memory transport fixtures
- `/ui-preview`, a selector-driven Runtime and Authentication presentation surface backed only by local fixtures

The `/ui-preview` route renders the approved D-15W Runtime and Authentication states for responsive, interaction, accessibility, dark-mode, and no-network review. It is not a production sign-in or Hermes client. Provider choices, password submission, callback progress, compatibility evidence, retries, and workspace actions are synthetic state transitions. They do not call a provider or gateway, inspect callback parameters, retain credentials, or send transcript data.

The Paper-approved Chat workspace uses exactly two responsive families. The desktop family preserves the sidebar and Workspace inspector at the 1440 × 960 reference geometry: 276px sidebar, 720px conversation cap, 380px inspector, and 16px outer insets and gaps. The mobile family uses the 390 × 844 shell with a 62px status bar, 64px header, 100px composer, conversation drawer, Workspace drawer, and title-edit state. The breakpoint follows effective preview width; desktop never substitutes top tabs for the sidebar. All workspace content on `/ui-preview` is local fixture data. It does not contact Hermes, load remote artifacts, retain credentials, or mirror a transcript.

The canonical artboard-to-implementation manifest is `../../contracts/design-tokens/web/artboards.json`. The preview consumes the matching semantic presentation tokens and implements the approved desktop and narrow state inventory, including fail-closed compatibility gates. Runtime behavior that Paper cannot prove remains covered by local component and browser tests.

The planned chat surface has one profile, provider-neutral discovery, session restore, streaming, approvals, clarification, interruption, images only for attachments, and no transcript mirror.

## Presentation packages

- `src/lib/auth-ui/` owns typed authentication view states, fail-closed validation of synthetic provider arrays, provider cards, fixture-only password-manager suppression, credential-free form actions, deliberate focus transfer, and live-region semantics. Empty, duplicate, malformed, missing-kind, and future-kind provider data resolves to the unavailable state. The Paper-approved password states begin empty and show `Cleared` while submitting. Synthetic fixture controls retain the ignore markers and `autocomplete=off`/`data-form-type=other` boundary; live username and password controls omit those suppressors, expose stable `autocomplete`/`name` semantics, and remain read-only until hydration completes the explicit username focus transfer. Element refs keep keyboard input and submission channels owned by the correct field. The primary control is a native reset action with a non-navigating default method: click or focused Enter clears both live values synchronously even if script execution stops, while hydrated submission emits only a fixture action. Live discovery accepts only exact bounded JSON syntax and schemas; malformed declared lengths, rejected responses, caller cancellation, and timeout all cancel active body work before the adapter returns a fixed credential-free diagnostic.
- `src/lib/workspace/` owns the shared pill primitive, runtime-state fixtures, compatibility gates, timeline, composer, session navigation, artifact inspector, and responsive narrow workspace chrome. Compatibility gates guard both emitted actions and local drawer/editor mutation against forced events. A pointer gesture activates a pill once on pointer down while its compatibility click remains consumed across leave, re-entry, and cancellation; keyboard and assistive activation remain independent. The reduced-transparency fallback uses fully opaque computed materials and removes blur and saturation rather than only changing token declarations.
- `src/routes/ui-preview/` composes both packages and exposes local selectors for state and appearance. It records only action type names as visible test evidence.
- `src/lib/transport/` remains the independent W-01 mock transport for the root scaffold. The presentation packages do not import it and do not create a hidden production transport path.

These packages are presentation-only and transport-independent. Do not add provider SDKs, gateway calls, browser-readable reusable credentials, callback parsing, production authentication, or live data to them.

Internal stable session and message IDs remain allowed. Required authentication callback routing also remains allowed.

User-facing deep-link UI and full-text session-search UI are deferred to `v0.0.2`. Both UIs need redesign. The deep-link and search contracts remain future compatibility references. User-facing sharing is deferred to `v0.0.2`.

## Static-host contract

The generated static output contains `index.html` for `/` and a distinct `200.html` fallback for
private Hermternal client routes. The supported direct-load route grammar is:

- `/` and `/index.html` serve the root shell;
- `/v1/c/<full-session-id>` and `/v1/c/<full-session-id>/m/<full-message-id>` rewrite to `200.html`,
  where each opaque ID is at least 16 ASCII unreserved characters;
- `/api`, `/hermes`, `/auth`, `/ws`, and `/pty` paths are reserved and never rewrite to `200.html`;
- canonical private routes and static assets reject query or fragment mutations; root query parameters
  are online-only synthetic fixture selectors and are not worker-intercepted;
- raw percent escapes, backslashes, duplicate separators, dot segments, traversal attempts, absolute-form
  targets, and network-path targets fail closed before URL normalization;
- GET and HEAD are the only successful static methods; recognized other methods return 405 and malformed
  method tokens are rejected by the HTTP parser;
- `/service-worker.js` is served as a JavaScript asset;
- all other paths, including unknown nested routes and reserved-prefix lookalikes, remain 404s.

A static host must apply that order before serving a file. The production-build server proof in
`tests/static/assert-static-routes.mjs` uses raw HTTP request targets, not `fetch`, and tests this exact
W-01 host contract. The dedicated host is also used by Playwright so the worker can precache `/200.html`
and control a canonical private navigation. The scaffold does not claim that Vite preview or an arbitrary
static host provides a general SPA rewrite.

This correction does not close C-20 / #70 (TypeScript contract parity), B-03 / #107
(web production-build benchmarking), or D-14W / #205 (web semantic design tokens); those
hard dependencies remain tracked separately.

## Service-worker lifecycle

Production app startup in `src/routes/+layout.svelte` registers the fixed
`/service-worker.js` script at `/`. Development, SSR, build evaluation, and module import do not
register it. Unsupported browsers and rejected registration or update checks pass through silently;
no raw URL, query, fragment, private identifier, or error object is logged or rendered.

Initial control does not reload the shell. A later controller transition on an already controlled
page may request one reload to apply an update. Unmount teardown removes the listener idempotently
and never unregisters the persistent worker. The shared route grammar in
`src/lib/static-route-grammar.mjs` is consumed by both the worker policy and the static evidence
host; `contracts/fixtures/deep-link-grammar/cases.json` and `docs/architecture/deep-links.md`
remain the normative deep-link references.

## Run and verify

Run these commands from this directory. The repository pins Bun `1.3.14`
through `.bun-version`, `packageManager`, and `engines`, and pins Node `v26.7.0`.
Use a fresh frozen install rather than a reused dependency tree:

```sh
test "$(bun --version)" = "1.3.14"
test "$(node --version)" = "v26.7.0"
rm -rf node_modules
bun install --frozen-lockfile
bun run typecheck:version
bun run typecheck
bun run check
bun run test
bun run test:static
bun run test:e2e
bun run test:a11y
bun run test:no-network
```

The primary compiler is TypeScript 7 through the `@typescript/native` package alias. The separate
`typescript` package is pinned to the TypeScript 5.9 compatibility API for Svelte tooling only; it
is not the primary typecheck command.

## Mock boundary

`src/lib/transport/` contains the complete W-01 transport surface. It returns named synthetic
fixtures for success, empty, failure, and cancellation states. It does not call `fetch`, open a
socket, read browser storage, use credentials, or mirror a transcript. Keep live Hermes, provider,
and browser-auth integrations out of this package until their contracts and proof gates are
explicitly approved.

The page creates the success fixture in memory. The component exposes pending, cancelled, empty,
failure, retry, unmount, and stale-result-safe states. Cancellation retains the safe deterministic
`w01-cancelled-v1` identity and is never presented as a transport failure.

## Regression foundations

- Vitest + Testing Library cover mock transport cancellation, shell loading, pending-to-cancelled-to-
  retry, failure/empty states, unmount aborts, stale-result suppression, and service-worker
  registration failure, unsupported-browser, controller-change, and teardown paths.
- Playwright covers Tab/Space activation, visible keyboard focus, effective target size, narrow and
  desktop widths, a real 640 CSS-pixel viewport as the 200% browser-zoom equivalent, computed
  reduced-motion behavior, deterministic cancellation, ordinary-startup service-worker
  registration, update/reload control, real offline cached navigation, and no-network requests.
- Axe runs against success, empty, and failure states in both light and dark color schemes.
- The password preview regression delays the hydration focus frame, sends rapid keyboard input, repeats
  field transitions, and submits from the password control. Ordinary Vitest does not resolve the browser
  cache or Python publication child; only genuinely browser-dependent tests skip, while filesystem
  publication tests use controlled pinned provenance. The live browser lane requires the explicit
  `HERMTERNAL_LIVE_SCREENSHOT_BROWSER_PREREQUISITE=1` gate and is never part of ordinary test commands.
  The opt-in live lane uses one run-owned 0700 temporary root with an owner marker, disabled media
  artifacts, and a status-only reporter. The Playwright project output directory is a disposable child
  of that root because Playwright clears its project output before a run; workers adopt the inherited root
  only after validating its marker and token, so retries and sequential workers share one run owner. Every Playwright worker preloads
  `tests/live/live-ipc-guard.cjs` through `NODE_OPTIONS --require` before the
  test body. `PW_RUNNER_DEBUG` is incompatible with this lane: the config rejects any truthy value before
  worker spawn because Playwright otherwise inherits worker stderr directly. The guard captures the
  credential variants once at preload, then pins `process.send`, never mutates `Object.prototype`,
  `Array.prototype`, or `testInfo.errors`, and detaches/redacts every worker-to-parent payload, including
  step, test-end, fatal, attachment, stdio, environment, and response messages. Playwright stdio buffers
  and attachment bodies are bounded-decoded from base64 and replaced when their bytes contain a captured
  credential encoding or end in any non-empty prefix of one; this closes split-write reconstruction across parent IPC messages while preserving buffers proven safe. Malformed or oversized binary fields fail closed. Unknown, trapped, or over-budget
  values are replaced or not forwarded, so Playwright cannot fall back to serializing the unsafe source
  graph. Per-test finalization validates every path ancestor and only quarantines strict child output directories;
  symlink ancestors fail closed. It preserves the shared marker, root, and root-level artifacts. The config routes Playwright's post-teardown
  `LastRunReporter` to the platform null sink, so it cannot recreate a markerless `.last-run.json` directory after
  global teardown. Global teardown alone removes the complete root by atomic quarantine plus bounded
  known-entry non-recursive `unlink`/`rmdir`, retaining any unknown, replaced, or raced remnant. Detached descriptor-aware snapshots cover native Error causes, Playwright
  `errorContext`, matcher results, logs, ARIA snapshots, and structured form values without retaining the
  source graph. Snapshot arrays remain real Playwright-compatible arrays with normal push/map/iterator
  behavior and safe own serialization/species behavior. Own `toJSON` hooks, stateful or inconsistent
  properties, incomplete descriptors, malformed values, and over-budget graphs fail closed. Balanced
  serialized contenteditable markup, raw-text textarea bodies, select/option nesting, and actual `value`
  attributes are scanned structurally, including unquoted values. Comments, nested or mismatched form
  markup, unclosed containers, malformed or unknown markup, duplicate or ambiguous attributes, and encoded
  credentials fail closed rather than allowing a later editable element to be skipped. Scrub failures fail
  the proof unless `page.isClosed()` returns `true`; generic error text such as `page crashed` is never
  accepted as termination proof. Attachments and safe output cleanup run in `finally` even when redaction
  fails, so a failed proof cannot retain synthetic credentials in traces, screenshots, reports, error
  contexts, or `test-results`. The official proof stores only a bounded typed ledger of method, route,
  event, request/session identity, status, boolean-match, and count projections. It requires the
  ordered auth/ticket/upgrade, server-first readiness, session, one-prompt acknowledgement, correlated
  delta/completion, and canonical REST history chain, then performs same-context logout and browser
  storage absence checks. The screenshot helper receives the exact complete ledger match only after
  that assertion; an incomplete proof cannot enter capture or retention. Failed live tests expose only
  the fixed semantic proof phase and delivery state through a dynamic Playwright annotation channel;
  the allowlist rejects arbitrary, duplicate, or extra values, and the reporter never forwards IDs,
  bodies, URLs, errors, DOM, credentials, or other diagnostics. Screenshot retention uses a
  trusted private staging parent anchored by
  device/inode, an absolute trusted Python child with `-I -S` and a credential-free environment, and
  exclusive no-overwrite publication. Source swaps, parent swaps, quarantine remnants, attachment
  failures, and cleanup errors are surfaced without recursive pathname deletion. No live Hermes run or
  retainable live screenshot was performed for this correction. The separate opt-in
  `HERMTERNAL_LIVE_RECONCILIATION=1` mode performs a fresh password login and bounded read-only
  session/history enumeration without creating or resuming a session, acquiring a ticket, opening a
  WebSocket, or submitting a prompt. It reports only zero/one/multiple fixed prompt matches, zero/one/
  multiple ordered completion pairs, and `no-match-uncertain`, `delivery-observed`,
  `completion-observed`, or `ambiguous`; zero history matches remain uncertain, not absent. It fails
  closed on malformed or incomplete pagination and cleanup failure, then verifies logout and clears
  cookies, Web Storage, IndexedDB, Cache Storage, and service workers. The mode never retains IDs,
  timestamps, bodies, prompt/response text, endpoints, headers, raw errors, or artifacts, and it is
  mutually exclusive with screenshot capture. No live reconciliation was run for this correction.
- `tests/static/assert-static-build.mjs`, `tests/static/assert-css-tokens.mjs`, and
  `tests/static/assert-static-routes.mjs` verify static output, canonical Paper token parity, the
  distinct `200.html` fallback, the generated `/service-worker.js` route, raw request target
  rejection, the supported deep-link grammar, method denial, generic missing-asset 404s, and
  reserved-path denial without a server directory.
- Semantic CSS tokens, reflow rules, focus styles, minimum action height, and reduced-motion rules
  provide the narrow/desktop, zoom, keyboard, and motion regression baseline.
- `src/lib/service-worker-runtime.test.ts` directly proves foreign same-origin caches are not
  deleted or read and reserved/API/auth/WS/PTy/unknown requests are not intercepted.

These checks are scaffold evidence, not proof that a future Runtime or Authentication screen is
ready to ship. No real provider, Hermes gateway, authentication provider, deployment, credential,
or user-data integration is present.

## Existing product boundary

The future web client is intended to own web chat and the full web-only `/api/pty` Terminal. Apple
clients do not use that Terminal surface. The planned chat surface has one profile,
provider-neutral discovery, session restore, streaming, approvals, clarification, interruption,
and images only for attachments. Sharing is deferred to `v0.0.2`.

Browser authentication will use server-issued HttpOnly cookies. Reusable Hermes credentials must
never enter local storage, session storage, or other browser-readable state. The pinned Hermes
revision, contract, deployment, compatibility, security, accessibility, performance, and Paper
proofs remain prerequisites for any later live implementation.
