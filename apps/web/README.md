# Web client

## Status

This directory now contains the W-01 scaffold only. It is a planning, mock, and proof artifact:

- Svelte 5 + SvelteKit 2 + Vite + Bun
- `@sveltejs/adapter-static` with a client-only SPA fallback
- a web app manifest and same-origin static-asset service worker
- a prototype-labelled shell, not a Runtime or Authentication screen
- deterministic in-memory fixtures with no live transport

The final user-facing Runtime and Authentication surfaces are intentionally absent. The D-15W
artboard-to-implementation manifest and explicit visual approval are still open, so this scaffold
does not invent product visual design or claim Paper parity.

The planned chat surface has one profile, provider-neutral discovery, session restore, streaming, approvals, clarification, interruption, images only for attachments, and no transcript mirror.

Internal stable session and message IDs remain allowed. Required authentication callback routing also remains allowed.

User-facing deep-link UI and full-text session-search UI are deferred to `v0.0.2`. Both UIs need redesign. The deep-link and search contracts remain future compatibility references. User-facing sharing is deferred to `v0.0.2`.

## Run and verify

Run these commands from this directory:

```sh
bun install
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

The page creates the success fixture in memory. The component still exposes pending, empty,
failure, retry, and stale-result-safe states so test infrastructure can exercise the boundary
without adding product features.

## Regression foundations

- Vitest + Testing Library cover the mock transport and prototype shell.
- Playwright covers keyboard focus and activation, no-network requests, narrow and desktop widths,
  200% zoom simulation, reduced motion, and static preview behavior.
- Axe runs against the prototype shell and reports violations as test failures.
- `tests/static/assert-static-build.mjs` verifies that the production output is static and contains
  the manifest without a server directory.
- Semantic CSS tokens, reflow rules, focus styles, minimum action height, and reduced-motion rules
  provide the narrow/desktop, zoom, keyboard, and motion regression baseline.

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
