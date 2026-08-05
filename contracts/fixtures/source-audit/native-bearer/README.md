# Native bearer REST source audit

**Status:** deterministic planning/proof fixture
**Contract:** `dashboard-v0.0.1`
**Pinned Hermes revision:** `f5be9236e00ddf2f2a412697f267078fc4ee068e6`
**Surface:** web-only mock/proof

This fixture set records the native bearer-authenticated REST routes that were
proven from the pinned Hermes source. It is not a client implementation, does
not call Hermes, and does not contain credentials, cookies, tickets, provider
data, hostnames, transcripts, or user data. Every credential state in
`cases.json` is a synthetic classification such as `valid` or `invalid`; no
value is an access token.

## Decision

The frozen native bearer route set is:

- `GET /api/auth/me`
- `POST /api/auth/ws-ticket`
- `GET /api/sessions`
- `GET /api/sessions/search`
- `GET /api/sessions/{session_id}`
- `GET /api/sessions/{session_id}/messages`
- `PATCH /api/sessions/{session_id}`
- `POST /api/chat/image-upload`

The route templates are matched by exact HTTP method and exact path shape.
Parameterized `session_id` segments must be non-empty single path segments.
The source gate itself is path-based, but the contract keeps the registered
method/path pairs narrow so a method or route expansion cannot be inferred
without a new source review.

These routes are source-proven as *eligible for native bearer session
verification*. A valid bearer lets the request continue to the handler; the
fixture does not claim a handler response body or status. An invalid or
expired bearer is rejected with the structured `401` path, and a provider
outage is represented by the source's `503` path. A bearer is never silently
converted to cookie authentication after bearer verification fails.

The following routes are intentionally not in the native bearer set:

- `/api/auth/providers` and the native authorize/token/refresh endpoints are
  public bootstrap or credential-issuance/rotation routes.
- `POST /api/gateway/drain` belongs to the separate exact-path service-token
  seam registered through `register_token_route`.
- Any other method/path pair is `blocked_unverified` by this contract. That
  label means Hermternal must not claim native bearer support; it does not
  assert that every upstream route is unauthenticated.

## Source evidence

The audit uses these source facts from the pinned checkout. Line references
are source-file line numbers at the audited revision.

- `middleware.py:49-86` defines the public auth/bootstrap prefixes and exact
  public API checks.
- `middleware.py:281-320` extracts and verifies an `Authorization: Bearer`
  value through the session-provider stack.
- `middleware.py:323-373` bypasses public paths, accepts a verified native
  bearer session, returns `503` for a provider outage, and returns structured
  `401` for an invalid bearer without falling through to cookies.
- `routes.py:778-817` registers `/api/auth/me` and `/api/auth/ws-ticket`.
- `sessions.py:50-51`, `166-167`, `552-553`, `598-599`, and `661-662` register
  the selected session list, search, detail, messages, and rename routes.
- `web_server.py:2306` registers `/api/chat/image-upload`.
- `routes.py:152`, `289`, `841`, and `894` identify provider discovery and
  native authorization/token/refresh endpoints that are public bootstrap or
  issuance paths.
- `token_auth.py:60-75` defines exact-path service-token registration, while
  `token_auth.py:144-183` defines its independent bearer-token decisions.
- `web_server.py:4000-4011` documents `POST /api/gateway/drain` as using that
  separate token-auth seam when configured.

The machine-readable route inventory is in `source_audit.json`. Synthetic
positive and negative requests are in `cases.json`. Run the standard-library
validator from this directory:

```text
python3 test_native_bearer.py
```

The validator checks the pinned revision, exact frozen route inventory,
parameterized path shape, public/service-token distinctions, fail-closed
unverified cases, and the expected `401`/`503` bearer outcomes. It reports
validation duration and fixture artifact size for repeatable review evidence.
