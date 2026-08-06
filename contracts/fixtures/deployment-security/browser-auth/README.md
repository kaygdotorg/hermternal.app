# Mock browser-auth boundary proof

Status: deterministic synthetic fixture for issue `#207` (`DEP-06M`).

This directory proves the browser-auth boundary with a small local state model.
It does not implement authentication and it does not contact Hermes, a reverse
proxy, an identity provider, a browser, DNS, or any network service.

The only source revision named for traceability is the planning pin
`f5be9236e00ddf2f2a412697f267078fc4ee068e`. The validator does not fetch or
import that revision. A passing result is fixture evidence, not a deployment
attestation or a claim that a provider is compatible.

## Boundary covered

`cases.json` is a closed, ordered matrix for these synthetic operations:

- provider discovery, including an empty registry and filtering a provider
  that cannot create a browser session;
- login start with a same-origin return path;
- successful callback with symbolic state, CSRF, and PKCE-cookie evidence;
- missing state, CSRF mismatch, provider error, malformed callback code, and
  expired PKCE-cookie failures;
- logout with a symbolic session cookie and a missing-CSRF failure;
- restoration of an expired or invalid symbolic session cookie;
- wrong-origin callback rejection;
- external and traversal return-target rejection;
- browser-storage denial before provider exchange;
- cancellation during a pending callback, preserving the last verified session
  state without a provider exchange or outward change; and
- an idempotent restore retry that re-reads stale source state, plus rejection of
  a retry that would repeat a non-idempotent callback.

The model emits only fixed status, reason, state, cleanup, and provider-exchange
markers. It never copies callback text, cookie contents, a return URL, or an
input diagnostic into its output. A successful callback redirects only to the
reviewed synthetic paths `/`, `/app`, `/app/chat`, `/settings`, or
`/signed-out`. Provider exchange is a symbolic `called`/`not_called` marker; no
HTTP request is made. Cancellation and retry diagnostics are fixed markers: a
cancellation preserves the last verified state, while a retry must re-read a
stale source marker and cannot repeat non-idempotent work or duplicate provider,
session, or outward side effects.

## Symbolic cookie and CSRF contract

Cookie values are never represented. The fixture permits only these symbolic
states:

- `present`
- `absent`
- `expired`
- `invalid`

The callback and logout records use symbolic CSRF outcomes (`match`, `missing`,
`mismatch`, or `malformed`) and never carry a nonce, token, or cookie value.
The validator fails closed when the origin, provider marker, storage state,
PKCE state, CSRF state, session state, or return target is missing, malformed,
unknown, or inconsistent.

The security invariants are:

1. The exact synthetic HTTPS origin is required; a different synthetic origin
   cannot create or restore a session.
2. A callback cannot issue a session unless the symbolic PKCE cookie is present,
   the callback state matches, the CSRF cookie is present, the CSRF result
   matches, and the code is present and well-shaped.
3. Provider errors and malformed callbacks do not call the provider exchange
   and do not issue a session cookie.
4. Logout requires a present CSRF cookie and matching CSRF result, then clears
   the symbolic session state. Expired and invalid sessions are never revived.
5. Return targets are same-origin path markers only. Absolute targets, scheme
   relative targets, encoded targets, controls, and traversal are rejected.
6. Storage denial is a controlled failure and never silently continues.
7. Cancellation preserves the last verified session or signed-out boundary and
   creates no new provider exchange, session, redirect, or other outward change.
8. Retry re-reads stale source state and is allowed only for idempotent discovery
   or restore work; a callback retry is rejected before any duplicate side effect.
9. Diagnostics are fixed or redacted and capped at 240 characters.

## Strict validation and regressions

`validate.py` uses only Python's standard library. Its JSON loader rejects
duplicate object keys, non-finite numbers, overflowing floats, integers beyond
the bounded digit limit, malformed UTF-8, excessive nesting, excessive nodes,
oversized strings, and control characters. Closed schemas use exact key order,
exact scalar types, bounded arrays, and independent outcome comparison. The
validator uses explicit exceptions rather than executable assertions, so normal
and optimized (`-O`) runs retain the same checks. Baseline validation recomputes
`min`, `p50`, `p95`, `p99`, `max`, and `mean` from all 30 raw samples with fixed
linear interpolation and binds each run to its exact approved command.

Run from the repository root:

```sh
python3 contracts/fixtures/deployment-security/browser-auth/validate.py
python3 -O contracts/fixtures/deployment-security/browser-auth/validate.py
python3 contracts/fixtures/deployment-security/browser-auth/test_validate.py
python3 -O contracts/fixtures/deployment-security/browser-auth/test_validate.py
python3 -m unittest discover \
  -s contracts/fixtures/deployment-security/browser-auth \
  -p 'test_*.py'
python3 -O -m unittest discover \
  -s contracts/fixtures/deployment-security/browser-auth \
  -p 'test_*.py'
python3 -m py_compile \
  contracts/fixtures/deployment-security/browser-auth/validate.py \
  contracts/fixtures/deployment-security/browser-auth/test_validate.py
```

Malformed temporary documents can be checked without baseline evidence:

```sh
python3 contracts/fixtures/deployment-security/browser-auth/validate.py \
  --cases /tmp/synthetic-cases.json \
  --skip-baseline
```

A failure is one JSON line, status `2`, with a bounded
`browser_auth_fixture_validation_error` message and no traceback or argparse
usage text. Invalid or unknown CLI arguments use the same controlled object and
do not echo argument values. The diagnostic redactor removes credential-shaped
assignments, including cookie, ticket, CSRF, session, state, PKCE, and token
names, including `session_id` and `ticket_id` with case, hyphen, underscore,
separator, and quoted JSON-key forms, plus bearer-shaped text, private-key
markers, and common live-token prefixes before applying the output cap. The
checked-in JSON and baseline
contain no credentials, raw cookies, tokens, provider data, transcripts, user
data, or public hosts.

## Baseline evidence

`validation-baseline.json` records a reproducibility baseline for the checked-in
fixture. It names:

- fixture: `cases.json`;
- metric: validator wall-clock duration in milliseconds;
- environment: the measured local platform and Python version;
- exact commands: `python3 contracts/fixtures/deployment-security/browser-auth/validate.py`
  and `python3 -O contracts/fixtures/deployment-security/browser-auth/validate.py`;
- build modes: normal and optimized;
- repetitions: exactly 30 samples per mode;
- distribution: `min`, `p50`, `p95`, `p99`, `max`, and `mean`, recomputed from the
  raw trace with fixed inclusive linear interpolation; and
- threshold: `null`, because issue `#207` defines no reviewed performance
  budget.

The artifact records `README.md`, `cases.json`, and `validate.py`, their total
byte count, and a SHA-256 digest over sorted path names and file bytes. The
validator checks that digest so a stale benchmark cannot silently describe a
different fixture. The measurements are observations, not a latency promise.
Re-run both recorded commands for a new commit and replace the trace only when
the fixture changes.

## Scope limits

This is not a browser test, a live OAuth/OIDC test, a cookie implementation, or
a deployment proof. It does not start Caddy, Traefik, Hermes, or an identity
provider; it does not use public HTTPS, real credentials, a proxy, a socket,
or live data. Accessibility, focus order, browser zoom, Dynamic Type, VoiceOver,
reduced motion, and touch targets are not applicable to this non-UI fixture and
remain requirements for later clients.
