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
  duplicate-key rejecting bounded JSON parser, and checked against closed route
  schemas. Unknown keys, malformed values, unsafe numbers, excessive nesting,
  and mismatched pagination fail closed.
- Redirects, non-success HTTP statuses, network failures, timeout, and abort
  produce bounded fixed diagnostics. Server error bodies are not echoed.

The fixtures in `live-rest-fixtures.ts` are synthetic redacted evidence only.
They contain no live provider data, hostnames, cookies, credentials, tickets,
transcripts, or user data. Real compatibility testing must use the official
upstream Hermes image only; this change never builds Hermes from source.
