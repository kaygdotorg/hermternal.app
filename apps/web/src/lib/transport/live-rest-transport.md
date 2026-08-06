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
  pagination fail closed. When `Content-Length` is present, the actual streamed or
  null-body byte count must match it exactly; short and long metadata is rejected.
  The reader is cancelled on abort, oversize, and metadata mismatch. A null-body
  fallback requires a valid declared byte length before allocation and rejects
  missing or lying length metadata. HTTP 3xx responses are classified as bounded
  redirects even when a synthetic fetcher does not set `redirected`.
- Provider discovery preserves source registration order, requires unique stable
  lowercase provider IDs, rejects separators, controls, and case-expansion folds,
  and treats display labels as bounded data without control characters.

## Pinned source projection

The Dashboard manifest freezes the route and authentication surface, but it
explicitly keeps REST bodies source-defined. This section documents the local
bounded projection; it does not create a new normative Hermes schema.

Pinned source citations at `f5be9236e00ddf2f2a412697f267078fc4ee068e`:

- [`web/src/lib/api.ts#L1332-L1339`](https://github.com/NousResearch/hermes-agent/blob/f5be9236e00ddf2f2a412697f267078fc4ee068e/web/src/lib/api.ts#L1332-L1339)
  declares `AuthMeResponse.expires_at` as a number.
- [`web/src/lib/api.ts#L1992-L2007`](https://github.com/NousResearch/hermes-agent/blob/f5be9236e00ddf2f2a412697f267078fc4ee068e/web/src/lib/api.ts#L1992-L2007)
  identifies the message roles, nullable content, and `session_id`/`messages`
  envelope. The pinned handler returns source-owned message values directly, so
  the client does not coerce or flatten structured multimodal/tool content.
- [`dashboard_auth/routes.py#L778-L791`](https://github.com/NousResearch/hermes-agent/blob/f5be9236e00ddf2f2a412697f267078fc4ee068e/hermes_cli/dashboard_auth/routes.py#L778-L791)
  returns the verified identity, including `expires_at`, from the authenticated
  session.
- [`web_routers/sessions.py#L598-L630`](https://github.com/NousResearch/hermes-agent/blob/f5be9236e00ddf2f2a412697f267078fc4ee068e/hermes_cli/web_routers/sessions.py#L598-L630)
  returns the resolved session ID, raw `messages`, and pagination values.
- The local manifest's schema policy at
  `contracts/hermes-dashboard/manifest.md:39-45` requires additive-field
  tolerance and says not to infer fields from an unknown JSON object.

Conversion rules are deliberately narrow and lossless within the transport
budgets:

- `expires_at` is `null` or an integer Unix-second value in `0..4,294,967,295`.
  The number is returned unchanged; strings, fractions, negatives, and excessive
  integers fail closed.
- A message `id` is a non-negative integer in `0..1,000,000,000` and is returned
  unchanged. String IDs are not coerced.
- Message `content` is `null`, a bounded string (including an empty string), or a
  bounded JSON list/dictionary. Nested values remain the strict parser's JSON
  values so multimodal parts and tool payloads are preserved without logging,
  storage, or stringification. Booleans and numbers are not accepted as the root
  content value because they are not part of the reviewed projection.
- Duplicate keys, non-finite or unsafe numbers, excessive depth, nodes, strings,
  arrays, and object keys are rejected before these conversions. Unknown additive
  fields are ignored only after those parser budgets pass.

The route/auth compatibility gate remains out-of-band: the deployed Hermes SHA
must match the attested pinned revision and a non-destructive behavioral probe
must pass before enabling the client. An invalid bearer remains a `401`; the
browser transport sends only `credentials: same-origin` and has no cookie or
bearer fallback path.

## Resource budgets

- Request timeout: `10_000ms` default, `30_000ms` maximum.
- Response body: `128KiB` default, `1MiB` maximum, checked before decode.
- Route arrays: `32` providers, `100` sessions, and `500` messages.
- Strict JSON parser: depth `16`, strings `8,192` characters, object keys `64`,
  arrays `500`, and nodes `4,096`. A minimal 500-message response costs
  `2,007` nodes: the root object, message array, session ID, pagination object,
  three pagination scalars, and four nodes per message row. The larger node cap
  leaves bounded room for reviewed additive fields and structured message content
  without making route limits unreachable.
- Numeric projections: message IDs are capped at `1,000,000,000`; Unix expiry
  seconds are capped at `4,294,967,295`. These are local representation budgets,
  not claims that the manifest freezes handler schemas.
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
`bun run benchmark:transport`. It performs five warmups and thirty timed runs
for 100 sessions and 500 messages, reports the raw samples plus min, p50, p95,
p99, max, and mean latency, and emits a sanitized
`hermternal.benchmark-trace.v1` JSON trace artifact containing the pinned
revision, fixture provenance, runtime/platform environment, workload bytes, and
redaction boundary. The command also emits the trace byte count and SHA-256 so
the captured stdout artifact can be bound to its raw samples. It never contacts
a server or provider. The output is B-01 format evidence for parser/transport
cost only, not a production performance claim.
