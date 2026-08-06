# Protocol fixtures

This directory contains synthetic, redacted request, response, WebSocket, Terminal, and recovery fixtures for both clients.

## Required coverage

Fixtures must represent:

- browser HttpOnly-cookie auth;
- native username/password provider auth, isolated `URLSession` cookies, and WebSocket tickets;
- one profile and provider-neutral discovery;
- session restore, long sessions, streaming, interruption, reconnect, loading, empty, success, and failure;
- approvals and clarification as separate pending actions;
- idle model switching, normal deferred switching, and deferred expensive-choice confirmation loss;
- images-only attachments;
- private deep links under `/v1/c/...`;
- the full web-only `/api/pty` Terminal on a POSIX or WSL host, plus an unsupported-host negative case;
- missing and mismatched deployment attestation;
- failed behavioral probes;
- missing, malformed, expired, and reused WebSocket tickets; and
- malformed JSON with a non-sensitive marker and verified upstream log controls.

Fixtures must identify the pinned Hermes revision `f5be9236e00ddf2f2a412697f267078fc4ee068e`, contract version, expected state transitions, and whether the fixture is web-only or shared. A native OAuth/OIDC provider that requires an unsupported callback transport is a negative fixture, not a fallback path.

Use synthetic data only. Do not commit credentials, cookies, WebSocket tickets, ticket fragments, live transcripts, hostnames, tokens, secrets, provider data, or user data. Invalid-ticket fixtures use non-secret markers and verify that the pinned source's bounded audit fragment is removed from retained logs. Fixtures describe behavior; they do not create a transcript mirror.

## C-19 aggregate registry

[`index.json`](index.json) is the language-neutral registry consumed by later
TypeScript and Swift parity checks. [`schema.json`](schema.json) documents the
wire-neutral shape. Each ready fixture root lists every checked-in artifact,
its byte count, and its SHA-256 digest. The aggregate validator also rejects
unsafe paths, duplicate JSON keys, non-finite numbers, oversized input,
malformed UTF-8, credential-shaped values, live claims, `http`/`https`/`ws`/`wss`
live hosts, symlinks, and unindexed artifacts. Registered Python artifacts are
parsed and their retained string literals and comments are scanned, including
assignment-shaped `ticket=`, `cookie=`, `password=`, `secret=`, and `token=`
values; detector regex definitions and explicit domain negative-test markers are
not treated as retained credentials. Domain validators remain authoritative for
case semantics; the aggregate layer does not run them and makes no network
request.

The `--baseline` input is bound to the exact canonical path named by the
registry (`validator/validation-baseline.json`). Its full canonical content is
also checked against a reviewed SHA-256 trust anchor in the validator; only the
validator's own manifest digest and derived byte total are normalized to avoid a
self-referential cycle. A schema-valid copy or coordinated sample/distribution/
manifest replacement cannot replace the checked-in benchmark evidence. Ready
coverage may reference only
ready fixture roots with real manifests. A registry can be structurally valid
while coverage remains `partial`. A `pending`, `empty`, `failure`, `cancelled`,
or `unknown` coverage row is never promoted to successful evidence. The
checked-in index now inventories the C-05 connection-restoration and C-14 image
attachment lifecycle artifacts, while C-05 coverage and C-08 stream-dependent
coverage remain pending until their dependency gates complete. `live_claim` is
always `false`; a passing validator proves only synthetic artifact integrity and
registry consistency.

The validator emits one bounded semantic JSON line. Failures do not echo
arguments, paths, keys, values, secrets, or tracebacks. Normal and optimized
Python runs share the same checks:

```sh
python3 contracts/fixtures/validator/validate.py
python3 -O contracts/fixtures/validator/validate.py
python3 contracts/fixtures/validator/test_validate.py
python3 -O contracts/fixtures/validator/test_validate.py
python3 -m unittest discover -s contracts/fixtures/validator -p 'test_*.py'
python3 -O -m unittest discover -s contracts/fixtures/validator -p 'test_*.py'
python3 -m py_compile \
  contracts/fixtures/validator/validate.py \
  contracts/fixtures/validator/test_validate.py
```

The validator is offline. It does not start Hermes, contact a proxy or
identity provider, open a socket, follow a referenced URL, or claim deployment
compatibility. `validator/validation-baseline.json` records 30 raw process
samples and their min/p50/p95/max/mean distributions for normal and optimized
runs. It is reproducibility evidence only: `threshold` is intentionally `null`
until the benchmark-method work defines an approved budget.

## P0-01 source review

The source-derived planning claims are reconciled by the local [P0-01 review record](source-audit/planning-reconciliation/planning_review.json). Reproduce it with the [validator](source-audit/planning-reconciliation/validate.py) against a local checkout of the pinned Hermes SHA. This evidence is source-only: it does not contact a live Dashboard or replace deployment attestation, behavioral probes, parity tests, or the focused source-audit units owned by issue `#200` and PRs `#216`, `#218`, `#219`, and `#220`.
