# W-06 typed REST transport

Status: prototype-only, same-origin transport boundary for issue #120.

The transport covers only the reviewed read routes from the pinned
`dashboard-v0.0.1` contract at Hermes source revision
`f5be9236e00ddf2f2a412697f267078fc4ee068e`:

- `GET /api/auth/providers`
- `GET /api/auth/me`
- `GET /api/sessions`
- `GET /api/sessions/{session_id}`
- `GET /api/sessions/{session_id}/messages`

Search and deep-link routes remain dormant v0.0.2 contracts. They are not
exported by this transport and are not readiness requirements for the web
client. No session mutation is exposed because this issue has no reviewed
mutation body fixture; a later focused operation must add one before a PATCH
or other non-idempotent route is enabled.

## Boundary rules

- Requests use only relative `/api` paths or an explicitly validated absolute
  URL whose origin equals the browser's current origin.
- Requests use `GET`, `credentials: same-origin`, `cache: no-store`, and
  `redirect: error`.
- The browser supplies protected cookies. The transport never reads cookies,
  local storage, session storage, IndexedDB, passwords, bearer credentials, or
  WebSocket tickets, and it never places credentials in a URL or response
  model.
- The transport does not add a server, proxy, WebSocket client, or fallback
  origin. A proxy proof must run on the same browser origin that serves the
  static client.
- Session IDs are opaque single ASCII path segments. Traversal, encoded slash,
  controls, non-ASCII, query-bearing, and overlong values fail before fetch.
- Response bodies are byte-capped, UTF-8 decoded with fatal errors, parsed by a
  duplicate-key rejecting bounded JSON parser, and projected onto the reviewed
  route fields. Unknown additive fields are ignored after bounded parsing; missing
  required fields, wrong types, unsafe numbers, excessive nesting, and mismatched
  pagination fail closed. A null-body fallback requires a valid declared byte
  length before allocation and rejects missing or lying length metadata.
- Provider discovery preserves source registration order, requires unique stable
  lowercase provider IDs, rejects separators, controls, and case-expansion folds,
  and treats display labels as bounded data without control characters.

## Resource budgets

- Request timeout: `10_000ms` default, `30_000ms` maximum.
- Response body: `128KiB` default, `1MiB` maximum, checked before decode.
- Route arrays: `32` providers, `100` sessions, and `500` messages.
- Strict JSON parser: depth `16`, strings `8,192` characters, object keys `64`,
  arrays `500`, and nodes `4,096`. A minimal 500-message response costs
  `2,007` nodes: the root object, message array, session ID, pagination object,
  three pagination scalars, and four nodes per message row. The larger node cap
  leaves bounded room for reviewed additive fields without making route limits
  unreachable.
- Redirects, non-success HTTP statuses, network failures, timeout, and abort
  produce bounded fixed diagnostics. Server error bodies are not echoed.

The fixtures in `live-rest-fixtures.ts` are synthetic redacted evidence only.
They contain no live provider data, hostnames, cookies, credentials, tickets,
transcripts, or user data. Real compatibility testing must use the official
upstream Hermes image only; this change never builds Hermes from source.

## Browser and benchmark evidence

`tests/e2e/live-rest-boundary.spec.ts` loads the non-product
`/__w06/transport` harness. That bundled page imports the exported transport,
executes it in the Chromium realm, and supplies only a deterministic fetcher;
it does not call `fetch` directly or inspect cookies. The harness checks the
request init contract and proves attacker origins, search, and ticket roots are
rejected before their fetchers can run.

Run the local synthetic route-cap benchmark with
`bun run benchmark:transport`. It performs five warmups and twenty timed runs
for 100 sessions and 500 messages, reports UTF-8 body bytes plus median and p95
latency, and never contacts a server or provider. The output is evidence for
parser/transport cost only, not a production performance claim.
