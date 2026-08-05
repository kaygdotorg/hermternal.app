# Hermes behavioral-probe contract fixture

**Operation:** C-04A — define the Hermes behavioral compatibility probe
**Contract:** `dashboard-v0.0.1`
**Pinned Hermes source:** `f5be9236e00ddf2f2a412697f267078fc4ee068e`
**Status:** deterministic synthetic fixture and offline validator only

This directory defines the probe that a later implementation may run. It does
not start Hermes, contact a proxy, contact an identity provider, open a socket,
read deployment state, or claim live compatibility. `probe-fixtures.json` is a
language-neutral case matrix. `validate.py` proves that the checked-in matrix
and baseline retain the reviewed contract. A passing validator means only that
the fixture proof is internally valid; it does not mean a deployment passed.

## Contract boundary

The probe is required before an authenticated connection becomes usable. A live
run must bind all evidence to the pinned source SHA, the exact route manifest
bytes, a trusted out-of-band attestation, and the approved proxy proof. Missing,
malformed, unknown, interrupted, expired, denied, or mismatched evidence blocks
operation. There is no guessed route, downgrade, or best-effort compatibility
mode.

The fixture covers these semantic observations:

- browser cookie REST;
- native password-provider REST with isolated cookie state;
- supported native OAuth or OIDC REST with a source-issued bearer class;
- missing or invalid authentication without a silent fallback;
- approved `/api/ws` upgrades with a fresh, short-lived, single-use ticket;
- missing, reused, expired, and legacy-query ticket denial;
- web-only `/api/pty` upgrade and native denial;
- POSIX or WSL host requirement for the web Terminal;
- edge public-origin and public-host denial separated from upstream Hermes
  `400` and `4403` results;
- approved and denied JSON-RPC operations, malformed JSON, and unknown events;
- PTY input forwarding without replay, attach-mode detach, and eventual TTL
  reap, without promising immediate kill or replay-before-live ordering; and
- semantic-only log evidence with no raw credentials, tickets, attach handles,
  PTY bytes, prompts, transcripts, provider data, or user data.

The matrix also names the required Caddy/Traefik equivalence pairs and one
shared web/iOS/iPadOS/macOS fixture source. Apple clients are explicitly barred
from `/api/pty`. The separate `/api/ssh/ownership` protocol version is not part
of this contract and is not used as compatibility evidence.

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

## Strict validation and redaction

The validator uses only the Python standard library. It rejects duplicate JSON
keys, non-finite numbers, unsupported types, changed key order, changed case
order, changed state/proxy/lifecycle inventories, unsafe route-manifest paths,
manifest digest drift, malformed baseline samples, and any live-compatibility
claim. It compares the canonical fixture digest as well as the semantic schema,
so changing both a case and its expected result cannot make a regression pass.

The recursive redaction scan rejects credential-shaped values, NUL bytes, and
sensitive object keys. The checked-in values are semantic markers only. A later
live probe must remove full ticket values and bounded invalid-ticket fragments
from retained logs and must cap a malformed-input warning to a non-sensitive
240-character marker before retention.

The route manifest is bound by this SHA-256 digest:

```text
3c6b44dc8dd90836f4fc5c5158d459959c569fb811db4b198e87d78ea5010197
```

`proof_run.attestation_state` and `proof_run.status` are intentionally absent
or not-run states. They cannot be changed to a pass in this fixture-only scope.

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

`probe-baseline.json` excludes itself from `artifact_size_bytes` and records the
raw command, environment, all samples, and min/p50/p95/max/mean values. Re-run
on the target machine when the fixture or interpreter changes.

## Reproduce the proof

Run from the repository root:

```sh
python3 contracts/fixtures/behavioral-probe/validate.py
python3 -O contracts/fixtures/behavioral-probe/validate.py
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
Those results remain blocked until a later implementation records the approved
live evidence against this fixture contract.
