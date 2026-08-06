# Fixture-driven behavioral-probe gate

This directory is the exclusive W-02A web proof boundary. It consumes the
checked-in `contracts/fixtures/behavioral-probe/probe-fixtures.json` contract and
evaluates deterministic synthetic evidence in memory.

The gate does not call Hermes, a proxy, an identity provider, `fetch`,
`WebSocket`, browser storage, or any production integration. It does not own a
screen or change a route. Paper and direct accessibility verification are N/A
because this is a non-UI protocol gate; downstream blocked-state UI obligations
remain unchanged.

## Fail-closed behavior

`evaluateBehavioralProbeGate` accepts only primitive canonical JSON text. It
rejects every object, array, boxed string, typed array, and Proxy before any
reflection. This is intentional: JavaScript Proxy traps are synchronous and
cannot be terminated by a timer on the application thread. A caller must
serialize evidence at its own isolated collection boundary before invoking the
gate.

The bounded parser rejects malformed UTF-8 representations, lone surrogates,
duplicate or non-canonically ordered object keys, non-canonical numbers,
non-finite values, unsafe integers, excess whitespace, aliases that JSON cannot
represent, and inputs over the total UTF-8, depth, node, array, object, per-string,
total-string, number-token, or canonical-output limits. It constructs null-
prototype objects and frozen arrays recursively, then requires byte-for-byte
canonical serialization before contract evaluation. No mutable caller alias can
reach the decision logic or returned result.

After parsing, the gate accepts only the pinned contract, Hermes source SHA,
canonical fixture digest, exact route-manifest path and bytes, exact evidence
fields, ordered 64 case IDs with their complete request/kind/surface/expected
semantics, and ordered 11 requirement IDs. A `success` state must reproduce all
canonical case outcomes and pass every required evidence row. The production
gate verifies those bindings itself; it does not rely on the Python validator at
runtime.

All results remain blocked. Canonical synthetic success reports
`blocked_live_compatibility`, `compatible: false`, and `liveRun: false`; it is
fixture evidence, not deployment proof. Missing, malformed, additive,
duplicated, reordered, unknown, incompatible, or mismatched evidence returns the
same fixed redacted `incompatible` result. `cancelled` and `unknown` preserve the
source-state-reread recovery rule. The gate performs no retry or outward action,
so it cannot duplicate a prompt, session, credential exchange, ticket mint, PTY
input, or other side effect.

`createBehavioralProbeFixtureEvidence` returns canonical serialized text only.
It exists for deterministic tests and no-network prototypes and must not be
treated as live evidence.

## Focused verification

Run from `apps/web`:

```sh
bun run typecheck:version
bun run typecheck
bun run check
bun x vitest run src/lib/compatibility/probe/behavioral-probe-gate.test.ts
bun run build
```

The fixture validator remains the source contract proof:

```sh
python3 contracts/fixtures/behavioral-probe/validate.py
python3 -O contracts/fixtures/behavioral-probe/validate.py
python3 contracts/fixtures/behavioral-probe/test_validate.py
python3 -O contracts/fixtures/behavioral-probe/test_validate.py
python3 apps/web/src/lib/compatibility/probe/validate_evaluator_benchmark.py
python3 -O apps/web/src/lib/compatibility/probe/validate_evaluator_benchmark.py
python3 apps/web/src/lib/compatibility/probe/test_validate_evaluator_benchmark.py
python3 -O apps/web/src/lib/compatibility/probe/test_validate_evaluator_benchmark.py
```

## Evaluator benchmark evidence

`evaluator-benchmark-evidence.json` contains four production-bundle runs: the
canonical success path and the maximum-sized bounded hostile-text rejection path
for normal and minified optimized Bun bundles. Every run contains five warmups,
30 raw `performance.now()` samples, the exact build-and-run command, sanitized
environment metadata, and R-7 p50/p95/p99 distributions rounded with decimal
half-even to three places. The recorded p50/p95/p99 values in milliseconds are:

- canonical normal: `17.641 / 20.892 / 22.188`;
- bounded hostile text normal: `17.903 / 43.574 / 48.754`;
- canonical optimized: `21.782 / 42.674 / 49.618`; and
- bounded hostile text optimized: `17.966 / 39.183 / 42.456`.

These measurements are evidence, not a performance promise. `threshold` and
`budget` remain `null` until B-08A approves them. The independent standard-
library Python validator pins the evaluator and harness byte identities,
recomputes all distributions from raw samples, and rejects schema, order,
metadata, environment, sample, distribution, threshold, duplicate-key,
non-finite, and UTF-8 drift. Regenerate evidence from this directory with
`bun behavioral-probe-gate.bench.ts > evaluator-benchmark-evidence.json`, then
update the validator's reviewed evaluator, harness, and raw-sample provenance
hashes in the same change.
