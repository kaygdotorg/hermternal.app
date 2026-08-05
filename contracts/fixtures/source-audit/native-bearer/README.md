# Native bearer REST source audit

**Status:** deterministic planning/proof fixture
**Contract:** `dashboard-v0.0.1`
**Pinned Hermes revision:** `f5be9236e00ddf2f2a412697f267078fc4ee068e6`
**Surface:** web-only mock/proof

This fixture set records a conservative Hermternal client allowlist from the
pinned Hermes source. It is not a client implementation, does not call Hermes,
and does not contain credentials, cookies, tickets, provider data, hostnames,
transcripts, or user data. Every credential state in `cases.json` is a
synthetic classification such as `valid` or `invalid`; no value is an access
token.

## Source behavior versus supported coverage

The pinned `gated_auth_middleware` is broader than this contract. On an auth-
required bind it attempts native bearer verification for **every non-public
path**, not only the eight routes listed below (`middleware.py:323-373`). The
eight pairs are therefore a conservative, source-cited Hermternal reviewed
allowlist, not a claim that the upstream bearer-acceptance inventory is
complete. Any route outside the allowlist remains `blocked_unverified` in the
Hermternal contract until separately reviewed.

The source-defined public bypass inventory is complete in `source_audit.json`:

- `PUBLIC_API_PATHS` exact paths: `/api/health`, `/api/status`,
  `/api/config/defaults`, `/api/config/schema`, `/api/model/info`,
  `/api/dashboard/themes`, `/api/dashboard/plugins`, and `/api/cron/fire`.
- `_GATE_PUBLIC_PREFIXES`: `/auth/login`, `/auth/callback`,
  `/auth/native/authorize`, `/auth/native/token`, `/auth/native/refresh`,
  `/auth/password-login`, `/auth/logout`, `/login`, `/api/auth/providers`,
  `/api/mcp/oauth/callback/`, `/assets/`, `/favicon.ico`, `/ds-assets/`,
  `/fonts/`, and `/fonts-terminal/`.

Exact public API paths use membership. Prefix entries use the pinned source
expression `path == prefix or path.startswith(prefix)`. The fixtures include
`/assets/app.js` as public and `/assetsleak` as blocked, plus exact-API and
other slash-prefix boundary cases. The source's non-slash prefixes, such as
`/favicon.ico`, intentionally retain their source semantics; the fixture does
not silently improve or narrow them.

## Conservative native bearer allowlist

The reviewed native bearer method/path pairs are:

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
A valid bearer lets a supported request continue to the handler; the fixture
does not claim a handler response body or status.

An invalid or expired bearer is rejected with the structured `401` path even
when a valid cookie is present. A bearer is never silently converted to cookie
authentication after bearer verification fails. With no bearer, a valid cookie
may authenticate the request. Provider stacking follows the pinned source:

- a reachable accepting provider succeeds even when another provider is
  unreachable;
- all reachable providers rejecting the bearer produce `401`;
- no acceptance plus at least one unreachable provider produces `503`.

## Conditional drain route

`POST /api/gateway/drain` is **not** an unconditional separate service-token
route in this contract. The drain plugin is conditional:

- when a strong drain secret enables the plugin, the plugin registers the exact
  path with `register_token_route`; the token seam owns the request and does
  not fall back to cookies;
- when the plugin is absent or declines registration, `token_auth.py` passes the
  path through, and the gated or loopback session gate remains authoritative.
  On a gated bind, the broad source middleware may attempt native bearer
  verification for this non-public path, but Hermternal does not freeze that
  path as supported native bearer coverage.

The conditional behavior is sourced from `web_server.py:4000-4011`,
`token_auth.py:54-183`, and the plugin registration at
`plugins/dashboard_auth/drain/__init__.py:229-291`.

## Source provenance and validator

`source_audit.json` pins the Hermes revision, the exact source evidence IDs and
line ranges, and SHA-256 digests for every audited source file. Every native
route citation is required to reference a source-evidence record and a line
range inside that record. When the pinned checkout is available, verify the
file digests with:

```text
python3 test_native_bearer.py --source-root <pinned-Hermes-checkout>
```

The standard-library-only validator checks the pinned revision, source digest
metadata, citation bindings, complete public inventories, exact route policy,
parameterized path shape, provider stacking, conditional drain modes,
fail-closed unverified cases, and mutation regressions. It reports validation
duration and fixture artifact size for repeatable review evidence.

```text
python3 test_native_bearer.py
```

This is a web-only mock/proof artifact. It adds no live Hermes integration,
production authentication, deployment configuration, or Apple implementation.
