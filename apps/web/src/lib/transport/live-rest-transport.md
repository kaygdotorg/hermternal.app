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
  pagination fail closed. When `Content-Length` is present, the actual streamed
  byte count must match it exactly; short and long metadata is rejected before the
  response is accepted. Every cancellable reader is cancelled on abort, oversize,
  metadata mismatch, redirects, wrong media, and non-success responses with a
  bounded cancellation deadline. A null-body response is rejected before any
  uncancellable `arrayBuffer()` fallback. HTTP 3xx responses are classified as
  bounded redirects even when a synthetic fetcher does not set `redirected`.
- Provider discovery preserves source registration order, requires unique stable
  lowercase provider IDs, rejects separators, controls, and case-expansion folds,
  and treats display labels as bounded data without control characters.

## Pinned source projection

The Dashboard manifest freezes the route and authentication surface, but it
explicitly keeps REST bodies source-defined. This section documents the local
bounded projection; it does not create a new normative Hermes schema.

Pinned source citations at `f5be9236e00ddf2f2a412697f267078fc4ee068e`:

- [`web/src/lib/api.ts`](https://github.com/NousResearch/hermes-agent/blob/f5be9236e00ddf2f2a412697f267078fc4ee068e/web/src/lib/api.ts)
  defines `AuthMeResponse` with non-null string fields and numeric
  `expires_at`; non-null does not mean non-empty for provider profile data.
  `user_id`, `provider`, and `expires_at` are the stable authentication
  identity used by the client. `email`, `display_name`, and `org_id` are
  profile metadata and may be empty for the pinned Basic provider. The source
  also defines `SessionInfo` with required source fields, numeric
  `started_at`/`last_active`, nullable numeric `ended_at`, required
  activity/token counters, and optional `parent_session_id`. That type is the
  richer list projection, not a guarantee that every field appears on the
  raw session-detail route.
- The same pinned web type defines `SessionMessage.content` as `string | null`
  and permits optional `tool_calls`, `tool_name`, `tool_call_id`, and numeric
  `timestamp`. Official history can serialize any of those optional tool fields
  as explicit `null` when they have no value. This client accepts omitted,
  `null`, or bounded array/string values as appropriate and preserves the
  distinction between omitted and explicit null. The non-null `tool_calls` array
  shape remains source-authoritative: arbitrary arrays or dictionaries at the
  content root are rejected rather than preserved as an invented multimodal
  schema.
- [`dashboard_auth/routes.py#L778-L791`](https://github.com/NousResearch/hermes-agent/blob/f5be9236e00ddf2f2a412697f267078fc4ee068e/hermes_cli/dashboard_auth/routes.py#L778-L791)
  returns the verified identity, including non-null source fields and numeric
  `expires_at`, from the authenticated session.
- [`web_routers/sessions.py#L598-L630`](https://github.com/NousResearch/hermes-agent/blob/f5be9236e00ddf2f2a412697f267078fc4ee068e/hermes_cli/web_routers/sessions.py#L598-L630)
  returns the resolved session ID, raw `messages`, and a source-observed
  `pagination` object. The frontend interface omits that additive envelope, but
  this transport requires the pinned backend route's bounded pagination fields.
- [`web_routers/sessions.py`](https://github.com/NousResearch/hermes-agent/blob/f5be9236e00ddf2f2a412697f267078fc4ee068e/hermes_cli/web_routers/sessions.py)
  uses a rich list query for `GET /api/sessions`, computes `is_active`, and
  normalizes `archived`/`pinned` to JSON booleans. The detail handler calls
  `SessionDB.get_session`, which returns the raw database row; it does not add
  list-derived `last_active`, `is_active`, or `preview`, and it leaves the
  SQLite archive/pin integers unchanged.
- [`hermes_state.py`](https://github.com/NousResearch/hermes-agent/blob/f5be9236e00ddf2f2a412697f267078fc4ee068e/hermes_cli/hermes_state.py)
  selects `sessions.*` for `get_session`, while
  [`hermes_state_common.py`](https://github.com/NousResearch/hermes-agent/blob/f5be9236e00ddf2f2a412697f267078fc4ee068e/hermes_cli/hermes_state_common.py)
  defines `archived` and `pinned` as `INTEGER NOT NULL DEFAULT 0`; the source
  setters write only `0` or `1`.
- The local manifest's schema policy at
  `contracts/hermes-dashboard/manifest.md:39-45` requires additive-field
  tolerance and says not to infer fields from an unknown JSON object.

Conversion rules are deliberately narrow and lossless within the transport
budgets:

- `expires_at` is a required integer Unix-second value in
  `0..4,294,967,295`. Strings, `null`, fractions, negatives, and excessive
  integers fail closed.
- Session `started_at` is required, while `ended_at` is required and nullable.
  List-derived `last_active` is optional on the shared projection because raw
  detail rows omit it; when present it must be a finite bounded Unix-second
  value. Fractional seconds are preserved because the official Hermes session
  store emits sub-second timestamps. Source strings are not coerced. Message
  timestamps use the same bounded rule. The pinned session counters,
  pagination fields, and token totals remain integers.
- List-derived `is_active` and `preview` are also optional on raw detail rows.
  When present, `is_active` must be a JSON boolean and `preview` must be a
  bounded string or explicit `null`. Omission remains omission; the client does
  not synthesize list values for a detail response.
- `archived` and `pinned` are optional additive flags. The list route supplies
  booleans, while the raw detail route supplies the SQLite integer encoding;
  only booleans or exact numeric `0`/`1` are accepted and they are normalized
  to booleans. `null`, numeric strings, fractions, and other integers fail
  closed.
- A returned session ID is validated independently. It may differ from the
  requested path because Hermes resolves aliases and continuation sessions to a
  canonical ID before returning session details or messages. Only a detail
  response produced by this constructed transport receives its private,
  request-bound canonical-alias marker; the workspace may use that marker to
  adopt the validated canonical detail ID. History remains a strict commit key,
  so a custom adapter or foreign message response cannot replace the selected
  timeline or identity.
- Source-defined strings stay bounded but may be empty when the pinned
  TypeScript type says only `string`. This includes the identity's optional
  profile metadata (`email`, `display_name`, and `org_id`), nullable session
  text when it is non-null, provider display labels, profiles, message content,
  and optional tool metadata. Empty strings are rejected for the stable auth
  identity keys (`user_id` and `provider`) and reviewed local identifiers such
  as provider names and session IDs.
- Message content is `null` or a bounded string. Optional `tool_calls` is
  projected as omitted, explicit `null`, or a bounded array whose members have
  the pinned scalar/object shapes. Optional `tool_name` and `tool_call_id` are
  projected as omitted, explicit `null`, or bounded strings; their source values
  are not coerced. Other types fail closed, and arbitrary arrays or dictionaries
  at the content root are rejected.
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
  `1,508` nodes: the root object, message array, session ID, pagination object,
  three pagination scalars, and three nodes per message row (message object,
  role, and content). The remaining bounded node budget covers optional pinned
  tool metadata and additive fields without making route limits unreachable.
- Numeric projections: Unix timestamps and expiry seconds are capped at
  `4,294,967,295`; message metadata timestamps use the same bound. These are
  local representation budgets, not claims that the manifest freezes unknown
  handler schemas.
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
`hermternal.benchmark-trace.v1` JSON trace artifact containing the exact Git
`HEAD` resolved by `git rev-parse HEAD`, the pinned Hermes source SHA, fixture
provenance, runtime/platform environment, workload bytes, and redaction boundary.
The `source_commit` must equal the corrected exact PR head when evidence is
posted. The command also emits the trace byte count and SHA-256 so the captured
stdout artifact can be bound to its raw samples. It never contacts a server or
provider. The output is B-01 format evidence for parser/transport cost only,
not a production performance claim.
