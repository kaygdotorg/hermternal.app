# Hermes behavioral-probe contract fixture

**Operation:** C-04A — define the Hermes behavioral compatibility probe
**Contract:** `dashboard-v0.0.1`
**Pinned Hermes source:** `f5be9236e00ddf2f2a412697f267078fc4ee068e`
**Status:** deterministic synthetic fixture and offline validator only

This directory defines the probe that a later implementation may run. It does
not start Hermes, contact a proxy, contact an identity provider, open a socket,
read deployment state, or claim live compatibility. `probe-fixtures.json` is a
language-neutral 64-case matrix. `validate.py` proves that the checked-in
matrix and baseline retain the reviewed contract. A passing validator means
only that the fixture proof is internally valid; it does not mean a deployment
passed.

## Contract boundary

The probe is required before an authenticated connection becomes usable. A live
run must bind all evidence to the pinned source SHA, the exact route manifest
bytes, a trusted out-of-band attestation, and the approved proxy proof. Missing,
malformed, unknown, interrupted, expired, denied, or mismatched evidence blocks
operation. There is no guessed route, downgrade, best-effort compatibility
mode, legacy query-token fallback, or automatic resend of an uncertain prompt.

The fixture covers these semantic observations:

- browser cookie REST and native password-provider REST with isolated cookie
  state;
- provider discovery, password login, WebSocket-ticket minting, native
  authorize, native token, and native refresh route review;
- supported native OAuth or OIDC REST using a source-issued bearer class;
- missing or invalid authentication without a silent cookie fallback;
- approved `/api/ws` upgrades with a fresh, single-use ticket and the exact
  source-backed 30-second ticket time-to-live;
- missing, malformed, reused, expired, and legacy-query ticket denial;
- required `Upgrade: websocket` and `Connection: upgrade` semantics, including
  separate missing-header denials;
- web-only `/api/pty` upgrade with separate POSIX and WSL web cases, and
  distinct iOS, iPadOS, and macOS denials before a PTY request;
- edge public-origin, public-host, and unknown-path 403/421/404 results kept
  separate from upstream Hermes `400` and `4403` results;
- approved and denied JSON-RPC operations, duplicate keys, wrong top-level
  values, invalid UTF-8, syntax errors, oversized integers, deep nesting,
  secret-shaped huge keys, and unknown events;
- reconnect with a fresh ticket, close-as-detach, `session.resume`, and
  connection-loss uncertainty that never resends a prompt automatically;
- PTY input forwarding without replay, attach-mode detach, and eventual TTL
  reap, without promising immediate kill or replay-before-live ordering; and
- semantic-only log evidence with no raw credentials, tickets, attach handles,
  PTY bytes, prompts, transcripts, provider data, or user data.

The matrix records executable synthetic attestation match/mismatch observations,
Caddy and Traefik approved/denied mapped-header observations, and explicit web,
iOS, iPadOS, and macOS shared-fixture observations. These observations document
contract decisions only. They never enable compatibility and every observation
keeps `live_claim: false`. The separate `/api/ssh/ownership` protocol version
is not part of this contract and is not used as compatibility evidence.

## Run states and recovery

`probe-fixtures.json` freezes six states: `pending`, `empty`, `success`,
`failure`, `cancelled`, and `unknown`.

- `pending` and `empty` remain blocked until required evidence exists.
- `success` means only that the synthetic fixture was validated; it keeps
  `live_run: false` and `compatible: false`.
- `failure` preserves the failed evidence and permits only idempotent collection
  retry.
- `cancelled` preserves safe state and makes no outward change.
- `unknown` blocks and requires a source-state reread before retry; it must not
  duplicate a prompt submission, session creation, credential exchange, ticket
  mint, PTY input, or other outward action.

## Strict validation, malformed input, and redaction

The validator uses only the Python standard library. It rejects duplicate JSON
keys, non-finite numbers, unsupported types, changed key order, changed case
order, changed state/proxy/lifecycle inventories, unsafe route-manifest paths,
manifest digest drift, malformed baseline samples, and any live-compatibility
claim. Four required counts are exact JSON integers: booleans, floats, strings,
and other numeric lookalikes are rejected even when fixture digest verification
is bypassed. Semantic case decisions are also closed independently of the
canonical digest.

Malformed JSON evidence is represented by explicit inventory rows for duplicate
keys, wrong top-level type, invalid UTF-8, syntax error, oversized integer, deep
nesting, and secret-shaped or huge keys. Warning sources are executable,
non-sensitive markers capped at 240 characters before retention. CLI syntax
errors, malformed fixtures, duplicate keys, oversized input, deep paths, and
other failures emit one bounded JSON object with `compatible: false` and
`live_run: false`; they do not echo raw flags, keys, values, secrets, or
tracebacks. Normal and optimized CLI behavior use the same safe failure marker.

The recursive redaction scan normalizes camelCase, dotted, colon-delimited,
hyphenated, slash-delimited, and whitespace aliases for ticket fragments,
prompt text, transcript bytes, PTY input/output, attach handles, cookies,
bearers, authorization headers, refresh tokens, and related credentials. It
also rejects generic JWT-shaped three-segment values in nested text. Checked-in
values are semantic markers only. A later live probe must remove full ticket
values and bounded invalid-ticket fragments from retained logs and must cap a
malformed-input warning to the non-sensitive marker before retention.

The route manifest is bound by this SHA-256 digest:

```text
0f2f1ea3af722cf2d14f6a43754a8430d20bae98d335b961c64b3f1229bd07c1
```

`proof_run.status` is `synthetic_observed` because the fixture contains
executable synthetic observations. `proof_run.live_result` remains
`not_recorded`, `probe.live_run` remains `false`, and `probe.compatible` remains
`false`. Synthetic observations cannot be promoted to live compatibility.

## Accessibility and Paper applicability

Paper and direct UI accessibility evidence are **N/A** because this change is a
non-UI protocol fixture and standard-library validator. It creates no control,
focus order, semantic name, screen-reader or VoiceOver surface, Switch Control
behavior, Dynamic Type or browser-zoom layout, contrast, motion, transparency,
or touch-target behavior. The fixture preserves those downstream obligations:
later web and Apple clients must preserve the blocked compatibility state safely
and must still verify their platform accessibility contracts.

## Measured baseline evidence

The baseline is reproducibility evidence, not a product budget. It records
artifact bytes and the observed duration distribution for 30 fresh normal and
optimized validator processes. `build_mode` is N/A because this directory has
no production or release executable. `threshold` is `null`; no latency,
render, memory, startup, bundle, or artifact-size threshold is invented.

The baseline is explicitly
`evidence_mode: "worktree_recomputed_against_approved_commit"` with
`immutable_evidence: false`. The approved reviewed remote head is
`6ff29b05d12fa1efd3e7f49d0cb45f660da1d958`. The baseline records a separate
approved-artifact manifest whose SHA-256 and byte counts are read from that
exact local Git commit, plus the current worktree artifact manifest used for
the regenerated measurement. This avoids claiming that mutable worktree
measurements are immutable while preventing a stale reviewed-commit/artifact
pair. The baseline also binds the exact canonical baseline digest and size and
the artifact SHA-256 and byte count for every current worktree file.

The canonical baseline digest is held in the checked-in
`baseline-canonical-sha256.txt` trust anchor. That anchor is intentionally
outside the measured artifact manifest so the digest check does not become
self-referential. The baseline excludes itself from the current artifact
manifest and is not immutable timing evidence: re-run it on the target machine
when the fixture, validator, tests, README, or interpreter changes.

## Reproduce the proof

Run from the repository root:

```sh
python3 contracts/fixtures/behavioral-probe/validate.py
python3 -O contracts/fixtures/behavioral-probe/validate.py
python3 contracts/fixtures/behavioral-probe/validate.py --unknown-flag
python3 contracts/fixtures/behavioral-probe/test_validate.py
python3 -O contracts/fixtures/behavioral-probe/test_validate.py
python3 -m unittest discover \
  -s contracts/fixtures/behavioral-probe \
  -p 'test_*.py'
python3 -O -m unittest discover \
  -s contracts/fixtures/behavioral-probe \
  -p 'test_*.py'
python3 -m py_compile \
  contracts/fixtures/behavioral-probe/validate.py \
  contracts/fixtures/behavioral-probe/test_validate.py
```

The commands are offline. They do not prove a proxy, a deployment, Hermes
runtime behavior, a live auth flow, a PTY lifecycle, or cross-platform parity.
Those results remain blocked until a later implementation records approved live
evidence against this fixture contract.
