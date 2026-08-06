# DEP-02 external exposure allowlist

**Issue:** `#89` (`DEP-02`)
**Contract:** `dashboard-v0.0.1`
**Status:** deterministic synthetic deployment-security fixture
**Live integration:** none
**Proxy syntax:** none

This directory freezes the public method and path boundary for a future
external gateway. It is a Caddy/Traefik-neutral contract, not proxy
configuration and not a deployment attestation. The validator is offline: it
does not import Hermes, start a proxy, open a socket, resolve a host, contact an
identity provider, or perform a live compatibility check.

## Source and separation

The reviewed source evidence is the merged C-01 route contract at:

`contracts/fixtures/route-allowlist/route_allowlist.json`

The planning pin is
`f5be9236e00ddf2f2a412697f267078fc4ee068e`, with source audit id
`route-allowlist-c01-f5be9236`. C-01 explicitly separates its conservative
client allowlist from a future external proxy allowlist. DEP-02 is that separate
reviewed boundary; source presence, public bypasses, and broad upstream access
do not widen it.

The manifest duplicates the frozen route tuples in the validator. This is
intentional: changing `cases.json` alone cannot authorize a new route. A route
needs the exact method, exact raw path shape, approved client, approved
transport, and symbolic authentication mode.

## Public static shell

The static surface is finite and exact. It has no broad SPA wildcard.

| Method | Path | Surface |
| --- | --- | --- |
| `GET` | `/` | shell root |
| `HEAD` | `/` | shell root metadata |
| `GET` | `/app` | SPA deep link |
| `GET` | `/app/chat` | SPA deep link |
| `GET` | `/settings` | SPA deep link |
| `GET` | `/signed-out` | SPA deep link |

A trailing slash, query-bearing raw target, fragment-bearing raw target, path
mutation, non-browser client, or other deep link is denied. The list is not an
instruction to serve arbitrary files.

## External Dashboard surface

Every Dashboard route below has exactly one `/hermes` prefix. The external
contract does not authorize the unprefixed C-01 path.

| Method | External path | Client | Auth marker |
| --- | --- | --- | --- |
| `GET` | `/hermes/login` | browser | public |
| `GET` | `/hermes/api/auth/providers` | browser, native | public |
| `GET` | `/hermes/auth/login` | browser | public |
| `GET` | `/hermes/auth/callback` | browser | public |
| `POST` | `/hermes/auth/password-login` | browser, native | public |
| `POST` | `/hermes/auth/logout` | browser, native | session |
| `GET` | `/hermes/api/auth/me` | browser, native | session |
| `POST` | `/hermes/api/auth/ws-ticket` | browser, native | session |
| `GET` | `/hermes/auth/native/authorize` | native | public |
| `POST` | `/hermes/auth/native/token` | native | native code plus PKCE |
| `POST` | `/hermes/auth/native/refresh` | native | native refresh material |
| `GET` | `/hermes/api/sessions` | browser, native | session |
| `GET` | `/hermes/api/sessions/search` | browser, native | session |
| `GET` | `/hermes/api/sessions/{session_id}` | browser, native | session |
| `GET` | `/hermes/api/sessions/{session_id}/messages` | browser, native | session |
| `PATCH` | `/hermes/api/sessions/{session_id}` | browser, native | session |
| `POST` | `/hermes/api/chat/image-upload` | browser, native | session |

The `session_id` marker is one opaque ASCII segment. It is one character, or
2–128 characters with an ASCII letter or digit at each end and only ASCII
letters, digits, dot, underscore, hyphen, or tilde internally. Empty segments,
double separators, suffixes, extra segments, controls, non-ASCII, backslashes,
percent escapes, encoded separators, encoded dots, dot traversal, and prefix
lookalikes are denied. The matcher does not URL-decode, strip, resolve, or
normalize a path.

The image route is the only reviewed upload route. Filesystem, SSH, media,
plugin, configuration, model-management, cron, gateway-management, event,
console, pub, MCP, health, status, and other source-present paths remain
outside the external allowlist. There is no broad `/hermes/*` or `/api/*`
permission.

## Upgrade surfaces

The WebSocket handshake is represented as an exact `GET` request with
`transport` set to `websocket`:

- `/hermes/api/ws` is the structured chat surface for browser and native
  clients. The auth marker is either `fresh_ticket` for gated mode or
  `local_query_token` for the source-defined local mode.
- `/hermes/api/pty` is the full Hermes TUI surface for browser clients only. It
  has the same symbolic auth choices and requires an attested POSIX or WSL
  Hermes host. Native clients are denied.

The fixture never carries a ticket, bearer, cookie, PTY handle, transcript,
provider value, host name, or user data. It records only symbolic auth modes.
It does not prove that a ticket is fresh or that a host is attested; those are
later runtime responsibilities at the boundary represented here.

## Default-deny and mutation cases

Unknown paths and methods deny. The ordered cases include:

- unprefixed `/api/ws` and `/api/*` lookalikes;
- repeated `/hermes` prefixes and broad wildcard paths;
- trailing slashes, extra segments, invalid session markers, and oversized
  session markers;
- plain traversal, encoded slash, encoded dot, encoded prefix, and other
  encoded-path attempts;
- method mutation and the standard header/query method-override aliases;
- HTTP requests sent to the chat WebSocket path;
- native use of the web-only PTY path and browser use of native-only auth;
- missing protected auth markers; and
- Dashboard administration and unrelated management paths, including source
  public bypasses and WebSocket sidecars.

The evaluator returns only a fixed decision, reason, route id, and surface. It
never copies the request path, query, headers, or auth marker into a diagnostic.

## Strict local validation

`validate.py` uses only Python's standard library. It rejects duplicate JSON
object keys, literal non-finite numbers, exponent overflow, oversized integer
literals, malformed UTF-8, excessive JSON depth, excessive node count, wide
objects, long arrays, oversized strings, control characters, wrong scalar
identity, unknown keys, route widening, method widening, path encoding, and
credential-shaped or live-host material. Explicit exceptions are used instead
of executable assertions, so normal and optimized runs enforce the same rules.

Failures are one bounded JSON line with exit status `2`. The CLI does not emit
tracebacks, usage text, untrusted argument values, or request material.

Run from the repository root:

```sh
python3 contracts/fixtures/deployment-security/external-allowlist/validate.py
python3 -O contracts/fixtures/deployment-security/external-allowlist/validate.py
python3 contracts/fixtures/deployment-security/external-allowlist/test_validate.py
python3 -O contracts/fixtures/deployment-security/external-allowlist/test_validate.py
python3 -m unittest discover \
  -s contracts/fixtures/deployment-security/external-allowlist \
  -p 'test_*.py'
python3 -O -m unittest discover \
  -s contracts/fixtures/deployment-security/external-allowlist \
  -p 'test_*.py'
python3 -m py_compile \
  contracts/fixtures/deployment-security/external-allowlist/validate.py \
  contracts/fixtures/deployment-security/external-allowlist/test_validate.py
```

Malformed temporary manifests can be checked without baseline evidence:

```sh
python3 contracts/fixtures/deployment-security/external-allowlist/validate.py \
  --cases /tmp/synthetic-external-cases.json \
  --skip-baseline
```

## Reproducibility baseline

`validation-baseline.json` records 30 observed wall-clock samples for the
normal command and 30 for the optimized command. It records the measured local
platform and Python version, exact commands, fixed linear-interpolated
`min`, `p50`, `p95`, `p99`, `max`, and `mean` values, and a SHA-256 digest over
`README.md`, `cases.json`, and `validate.py` in sorted path order. The two
pinned evidence literals inside `validate.py` are replaced with fixed markers
before hashing so the validator hash is not circular. The baseline excludes
itself from that digest. `threshold` is `null` because DEP-02 defines
no reviewed latency budget; the measurements are observations, not a promise.

Any fixture or documentation change requires rerunning both commands and
replacing the trace and artifact evidence from the observed local environment.

## Scope limits

This is a mocked, offline contract. It does not configure Caddy, Traefik, a
TLS listener, DNS, an identity provider, Hermes, a browser, or an operating
system host. It does not establish authentication, authorization, WebSocket
handshake behavior, upload limits, session ownership, PTY safety, or production
compatibility. Those later implementations must preserve this default-deny
matrix and add their platform-specific evidence without silently widening it.
