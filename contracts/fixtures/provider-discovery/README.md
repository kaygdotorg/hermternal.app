# Provider discovery fixtures

**Contract:** `dashboard-v0.0.1`
**Operation:** `GET /api/auth/providers`
**Pinned Hermes revision:** `f5be9236e00ddf2f2a412697f267078fc4ee068e`
**Scope:** shared web and Apple authentication bootstrap
**Status:** deterministic offline synthetic contract

This fixture freezes the provider-neutral discovery boundary. It does not
implement authentication, contact Hermes, contact an identity provider, open a
socket, or claim live compatibility. All provider names, labels, and responses
are synthetic markers.

## Pinned source behavior

The pinned Dashboard route returns HTTP 200 with exactly one top-level field:

```json
{
  "providers": [
    {
      "name": "synthetic-provider",
      "display_name": "Synthetic Provider",
      "supports_password": false
    }
  ]
}
```

The route calls `list_session_providers()`. The registry filters out providers
whose `supports_session` value is false and preserves registration order. A
missing `supports_session` value defaults to true. The route serializes
`supports_password` with `bool(getattr(provider, "supports_password", false))`,
so a missing capability defaults to false. The response does not expose a
Python class name, callback URL, issuer, origin, credentials, or provider
administration data.

An empty interactive registry is not a successful empty list. The pinned route
returns HTTP 503 with exactly:

```json
{"detail": "no auth providers registered"}
```

The route does not normalize malformed entries. A missing provider attribute
fails before a JSON response is produced. The client contract therefore fails
closed into `provider_unavailable`; it does not invent a status, coerce a
provider into `basic`, or fall back to another provider or origin.

Provider identifiers and labels are deployment data, not Hermternal policy.
The fixture accepts synthetic provider-neutral names and preserves their
source order. A password capability only means that the reviewed Dashboard
password path may be offered; it never authorizes HTTP Basic headers or a
Hermternal-owned password endpoint.

The immutable source hashes, commit-pinned URLs, exact markers, and contract
surface are recorded in [`source_audit.json`](source_audit.json). The validator
checks that metadata exactly and never fetches those URLs during normal runs.
An optional `--source-root` check can verify the cited bytes from an already
available pinned checkout or content-only snapshot.

## Fixture coverage

[`cases.json`](cases.json) covers:

- pending discovery, which remains `discovering` without claiming success;
- a native password-capable provider;
- multiple provider-neutral entries with registration-order preservation;
- a lowercase Unicode provider identifier and localized display label;
- a provider with the source defaults `supports_session: true` and `supports_password: false`;
- an empty registry and a registry containing only non-session providers, both
  with the exact 503 response;
- a malformed source provider entry, which has no invented response status;
- a malformed 200 response entry, rejected before it becomes usable; and
- user cancellation, which returns to a safe signed-out state and permits an
  explicit retry.

The recovery contract makes discovery retryable and idempotent, but only after
user action. An unknown result is re-read before retry. No prompt or session
mutation is possible before authentication, and no credentials or live data
appear in the retry record.

## Strict validation

`test_provider_discovery.py` uses Python's standard library only. It rejects
duplicate JSON object keys, parser and post-parse non-finite numbers, oversized
integers, unknown schema keys, boolean or non-integer evidence, scalar rows,
over-deep direct inputs, malformed provider rows, duplicate provider names,
wrong status or error details, route mutations, case-kind relabeling,
source-order or capability drift, source-audit drift, credential-shaped
redaction markers, and response shapes that could silently widen provider
policy. Provider names preserve the pinned lowercase Unicode boundary without
an unsupported ASCII restriction. It uses explicit exceptions rather than
executable `assert` statements, and `main()` reports controlled validation
failures without tracebacks, so normal and optimized (`-O`) runs exercise the
same fail-closed checks.

Run the focused proof from the repository root:

```sh
python3 contracts/fixtures/provider-discovery/test_provider_discovery.py
python3 -O contracts/fixtures/provider-discovery/test_provider_discovery.py
python3 -m unittest discover \
  -s contracts/fixtures/provider-discovery \
  -p 'test_*.py'
python3 -O -m unittest discover \
  -s contracts/fixtures/provider-discovery \
  -p 'test_*.py'
python3 -m py_compile contracts/fixtures/provider-discovery/test_provider_discovery.py
```

Optional source verification uses only a local source tree that the caller has
already obtained and pinned:

```sh
python3 contracts/fixtures/provider-discovery/test_provider_discovery.py \
  --source-root /path/to/hermes-agent-f5be9236e00ddf2f2a412697f267078fc4ee068e
```

The validator never clones, fetches, imports, or executes Hermes. Source-root
mode verifies the pinned commit when Git metadata is present, reads each cited
blob once, checks its SHA-256 and Git blob ID, and requires every recorded
marker in the cited file. Content-only snapshots are labeled as such and do
not claim checkout verification.

## Baseline and accessibility

`source_audit.json` records the raw normal, optimized, discovery, and compile
commands, 30 raw normal and optimized validator samples, recomputed
`min`/`p50`/`p95`/`p99`/`max`/`mean` summaries, the measured fixture artifact
size and SHA-256, the measured source commit, the local Python environment,
`build_mode: N/A`, and `threshold: null`. The samples are fresh subprocess
observations of the exact recorded command and mode. They are reproducibility
observations, not a product latency budget or performance gate. Re-run the raw
commands after changing the fixture, bind the new trace to the code commit
that was measured, and replace the recorded observations and artifact digest.

Accessibility and Paper evidence are **N/A** because this change is a
non-UI protocol fixture and validator. It changes no focus order, semantic
label, contrast, motion, transparency, Dynamic Type, VoiceOver, Switch
Control, browser zoom, or touch target. Later clients must still render
provider labels with their existing web and Apple accessibility contracts.
