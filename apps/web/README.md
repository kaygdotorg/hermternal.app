# Web client

## Status

This directory now contains the W-01 scaffold only. It is a planning, mock, and proof artifact:

- Svelte 5 + SvelteKit 2 + Vite + Bun
- `@sveltejs/adapter-static` with a distinct `200.html` client-route fallback
- a web app manifest and same-origin static-asset service worker with a closed allowlist
- normal app-startup service-worker registration that fails closed without blocking input or logging URLs/errors
- a prototype-labelled shell, not a Runtime or Authentication screen
- deterministic in-memory fixtures with no live transport

The final user-facing Runtime and Authentication surfaces are intentionally absent. The D-15W
artboard-to-implementation manifest is merged at `../../contracts/design-tokens/web/artboards.json`
with token hash `cb15f2b1`; this scaffold consumes its shipped runtime token set but does not claim
Runtime or Authentication screen parity. Those surfaces remain separate in #267.

The planned chat surface has one profile, provider-neutral discovery, session restore, streaming, approvals, clarification, interruption, images only for attachments, and no transcript mirror.

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
