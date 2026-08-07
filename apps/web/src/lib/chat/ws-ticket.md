# Chat WebSocket ticket boundary

W-05 owns the browser-side seam that acquires one short-lived chat ticket for
one gated WebSocket upgrade. This is a typed, mockable client boundary. It does
not add a route, UI, deep link, search surface, storage layer, or live Hermes
integration.

## Contract

- Mint with same-origin `POST /api/auth/ws-ticket`.
- Let the browser send its protected same-origin cookie through
  `credentials: 'same-origin'`; JavaScript never reads or supplies a cookie,
  bearer value, password, refresh value, or authorization header.
- Read at most 2 KiB of UTF-8 JSON, cancel an oversized or malformed stream, and
  require the official exact object shape `{ "ticket": "<URL-safe value>",
  "ttl_seconds": 30 }`. The bounded duplicate-key-rejecting parser accepts either
  key order. Missing, duplicate, extra, mistyped, or changed-TTL fields fail closed
  before upgrade. Non-2xx response bodies are cancelled before status errors are
  published. Body and reader cancellation are bounded, and reader locks are
  released after cleanup. The validated TTL is discarded before the ephemeral
  ticket is handed to the client seam.
- Derive the upgrade authority only from the browser's current `location.origin`.
  Caller input cannot replace the origin. Put the value only in the ephemeral
  `ws(s)://<current-origin>/api/ws?ticket=...` URL passed to the injected connector.
- Coalesce duplicate calls while one attempt is active. Every attempt also has
  an internal five-second deadline, including calls without a caller signal, so a
  stuck request or connector clears the coalescing slot and an explicit retry can
  acquire a fresh ticket. A connector result that arrives after cancellation is
  closed through an idempotent late-resolution cleanup. The browser adapter shares
  that idempotent close boundary with its own abort listener, owns a prepared
  socket until JSON-RPC consumes it, and clears/closes it before retry when abort
  happens in that handoff window. After an attempt settles, the next explicit call
  acquires a fresh ticket instead of reusing the old one.
- Propagate an `AbortSignal`; cancellation discards an unverified response and
  never starts an upgrade or an automatic retry.
- Expose only bounded semantic errors. Response bodies, cookie or bearer values,
  ticket values, ticket fragments, URLs, and provider text are not copied into
  errors or retained client state. The browser consumer preserves a genuine
  `HTTP 401` as unauthenticated/permanent state; `HTTP 403` remains a distinct
  non-401 failure.

The server contract remains authoritative for the exact 30-second, single-use
lifetime. This client enforces the client-side half of that rule by never
retaining or reusing a ticket. W-06 may adapt its typed REST transport to the
injected `WsTicketRequestBoundary`; W-05 does not edit or depend on W-06 files.

## Verification scope

`ws-ticket.test.ts` covers request shape, strict response parsing, fresh-ticket
retry, duplicate-attempt coalescing, cancellation, invalid authentication, and
redacted errors. `apps/web/tests/e2e/ws-ticket.browser.spec.ts` loads the same
source into a real browser and checks same-origin acquisition, cancellation,
explicit retry, and the absence of ticket material from storage, DOM, history,
console observations, and error text. Browser tests generate opaque values at
runtime; no ticket value is committed as a fixture or report.

This is prototype-only evidence. It does not prove a live deployment, Hermes
compatibility, cookie attributes, gateway behavior, or a production WebSocket.
