# Dashboard route and method allowlist

**Contract:** `dashboard-v0.0.1`
**Pinned Hermes revision:** `f5be9236e00ddf2f2a412697f267078fc4ee068e`
**Status:** deterministic source-audit and planning fixture
**Live integration:** none

This C-01 artifact freezes the reviewed Hermternal client surface. It is
source-audit work, not a Hermes client, reverse proxy, deployment attestation,
or live compatibility claim. The fixture uses synthetic classifications only.
It contains no cookies, bearer values, WebSocket tickets, PTY handles,
transcripts, hostnames, provider data, or user data.

## Three different inventories

The machine-readable [`route_allowlist.json`](route_allowlist.json) keeps three
inventories separate:

1. **`source_present`** records selected observations from the pinned source.
   It includes the source's exact public bypass inventory and representative
   routes and operations that are deliberately not client-approved. It is not a
   complete upstream route or JSON-RPC inventory.
2. **`client_allowlist`** is the conservative Hermternal v0.0.1 set. A route
   needs the exact method and path shape, an approved upgrade surface, or an
   exact approved JSON-RPC operation to pass. Source presence alone never
   widens this set.
3. **`future_external_proxy_allowlist`** is explicitly empty and not frozen.
   A future reverse proxy or external gateway needs a separate source review;
   this client contract does not authorize a broader proxy surface.

Unknown REST method/path pairs and unknown JSON-RPC operations are default
Deny. Unknown additive noninteractive events may be ignored, but an unknown
interactive event must never be promoted to an approval or clarification.

## Reviewed REST pairs

The exact client-approved pairs are:

Every REST authorization decision requires explicit `applicability`: exactly
`browser` or `native`. Missing, empty, unknown, or non-string applicability
fails closed. A shared route such as `/api/auth/me` must be checked separately
for each platform; native-only and browser-only routes cannot pass under the
other platform or without platform context.

| Method | Path | Browser/native applicability | Authentication mode |
| --- | --- | --- | --- |
| `GET` | `/login` | browser | public |
| `GET` | `/api/auth/providers` | browser, native | public provider discovery |
| `GET` | `/auth/login` | browser | public |
| `GET` | `/auth/callback` | browser | public callback |
| `POST` | `/auth/password-login` | browser, native | public password-provider entry |
| `POST` | `/auth/logout` | browser, native | protected cookie session |
| `GET` | `/api/auth/me` | browser, native | cookie or reviewed native bearer |
| `POST` | `/api/auth/ws-ticket` | browser, native | cookie or reviewed native bearer |
| `GET` | `/auth/native/authorize` | native | public native authorization |
| `POST` | `/auth/native/token` | native | public loopback code plus PKCE |
| `POST` | `/auth/native/refresh` | native | public native refresh material |
| `GET` | `/api/sessions` | browser, native | cookie or reviewed native bearer |
| `GET` | `/api/sessions/search` | browser, native | cookie or reviewed native bearer |
| `GET` | `/api/sessions/{session_id}` | browser, native | cookie or reviewed native bearer |
| `GET` | `/api/sessions/{session_id}/messages` | browser, native | cookie or reviewed native bearer |
| `PATCH` | `/api/sessions/{session_id}` | browser, native | cookie or reviewed native bearer |
| `POST` | `/api/chat/image-upload` | browser, native | cookie or reviewed native bearer |

The `session_id` template accepts one opaque ASCII path segment with this
conservative grammar: one character, or 2–128 characters whose first and last
characters are ASCII letters or digits and whose internal characters are ASCII
letters, digits, `.`, `_`, `-`, or `~`. The matcher does not URL-decode, strip,
resolve dot segments, or treat a prefix as a match. It rejects empty or double
segments, trailing slashes, `.`, `..`, controls, non-ASCII, backslashes, percent
escapes (including encoded slashes), query strings, fragments, and any
ticket-bearing path value. A method mutation, suffix, extra segment, prefix
lookalike, or broad wildcard is denied. The image route is the only approved
upload route; arbitrary files, filesystem access, media, SSH, gateway
administration, configuration, plugin management, and cron or MCP management
remain outside the client allowlist even when the pinned source exposes a route
or public bypass.

`GET /api/model/options` is recorded as source-present but not client-
allowlisted. The focused model fixture freezes `model.options` over JSON-RPC;
this artifact does not silently add the REST equivalent.

## Upgrade surfaces and authentication

- **Chat:** `WS /api/ws` is approved for browser and native clients. In gated
  mode, mint a fresh single-use `/api/auth/ws-ticket` ticket and consume it on
  the upgrade. Browser cookie sessions and reviewed native bearer sessions may
  create that ticket. The cookie or bearer is not sent directly on the gated
  WebSocket. Non-gated local mode may use the source-defined `?token=` path;
  that path is not a fallback after the OAuth gate is active.
- **PTY:** `WS /api/pty` is approved only for the web client on an attested POSIX
  or WSL Hermes host. It uses the same fresh gated ticket when required. Apple
  and other native clients do not invoke this route in v0.0.1. The source's
  attach, resize, replay, and close behavior remains bounded by the merged PTY
  evidence; the fixture does not create or log a PTY handle.
- **Source sidecars:** `/api/pub`, `/api/events`, and the source-documented
  `/api/console` path are source observations, not direct Hermternal client
  routes. They are not proxy permission.

Tickets are 30-second and single-use at the pinned revision. Reuse, expiry,
missing credentials, and a gated legacy query token fail closed. Invalid-ticket
logging may retain only a bounded diagnostic fragment and credential class; it
must not retain a raw ticket, bearer, PTY input, PTY output, or transcript.

## Reviewed JSON-RPC surface

The client may send these operation names on `/api/ws`:

- Session: `session.create`, `session.resume`, `session.list`,
  `session.active_list`, `session.most_recent`, `session.history`,
  `session.status`, `session.close`.
- Prompt and control: `prompt.submit`, `session.interrupt`.
- Human input: `approval.respond`, `clarify.respond`.
- Model: `model.options`, and `config.set` with the source-defined `model` key
  only. Other configuration keys are denied.

The selected source events are `gateway.ready`, `session.info`,
`message.delta`, `reasoning.delta`, `thinking.delta`, `message.complete`,
`tool.start`, `tool.complete`, `approval.request`, `clarify.request`, and
`error`. Parse failures are `-32700`; dispatch failures are `-32603`.

The client does not call or expose sensitive source-present operations such as
`session.delete`, `model.save_key`, `llm.oneshot`, `sudo.respond`,
`secret.respond`, `terminal.read.respond`, or `file.attach`. It does not infer
an operation from a route, an event, or a screen.

## Fixtures and validator

[`cases.json`](cases.json) contains strict synthetic coverage for approved and
disallowed REST pairs, method mutation, path-prefix confusion, bearer/cookie
fallback, ticket reuse and expiry, gated token misuse, web-only PTY behavior,
management/admin exposure, JSON-RPC key and operation denial, event policy,
PTY logging redaction, and malformed input.

[`test_route_allowlist.py`](test_route_allowlist.py) uses only Python's standard
library. It rejects duplicate JSON object keys, `NaN`/`Infinity`/`-Infinity`,
unknown schema keys, wrong leaf types, JSON booleans where integers are
required, excessive JSON nesting, incoherent or stale baseline evidence, route
widening, method mutation, source/provenance drift, credential-like redaction
markers, and malformed inputs that would otherwise produce a traceback.
Redaction scanning covers all three JSON documents and credential-shaped values
in this README and the manifest. It can optionally verify the pinned Git
commit/tree, recorded full-file SHA-256 digests, Git blob IDs resolved from the
pinned `f5be9236e00ddf2f2a412697f267078fc4ee068e:path` objects, and canonical
citation markers against an independently fetched source root. In pinned Git
checkout mode, inherited Git repository, worktree, namespace, and object
redirect variables are removed; each blob is fetched through one
`git cat-file --batch` response with `GIT_NO_REPLACE_OBJECTS=1` and
`GIT_NO_LAZY_FETCH=1`, and the parsed exact bytes are used for both digest and
marker checks. Mutable worktree files are not used for those claims. Missing,
mismatched, non-blob, truncated, or unavailable objects are controlled
validation failures:

```text
python3 contracts/fixtures/route-allowlist/test_route_allowlist.py
python3 -O contracts/fixtures/route-allowlist/test_route_allowlist.py
python3 -m unittest discover -s contracts/fixtures/route-allowlist -p 'test_*.py'
python3 -m py_compile contracts/fixtures/route-allowlist/test_route_allowlist.py
python3 contracts/fixtures/route-allowlist/test_route_allowlist.py --source-root /path/to/hermes-agent
```

The validator currently runs 27 regression tests. Discovery is intentionally
scoped to this fixture directory with `-s contracts/fixtures/route-allowlist`
and `-p 'test_*.py'`; a bare repository-root discovery is not evidence for this
contract.

The checked-in `source_audit.json` baseline records the raw command, standard-
library validator environment, seven repetitions, min/median/p95/max/mean
duration, and fixture artifact size. `artifact_size_bytes` is the sum of this README, the
allowlist JSON, the synthetic cases JSON, and the validator, excluding
`source_audit.json` because it stores the measurement. The baseline records
`build_mode: N/A` and no invented latency or size threshold; `threshold` is
`null`. Re-run the raw command when changing the fixture and update the evidence
from the observed environment rather than claiming live compatibility.

## Accessibility and Paper evidence

Paper evidence is **N/A** because C-01 changes no user-facing board, runtime
view, focus order, semantic label, motion, contrast, Dynamic Type, VoiceOver,
Switch Control, browser zoom, or touch target. The artifact preserves the
existing accessibility obligations: a later client must still implement the
web and Apple accessibility contracts for every approved user-facing route and
must not treat an unsupported route or event as a hidden UI fallback.
