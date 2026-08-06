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

`evaluateBehavioralProbeGate` accepts only the pinned contract, Hermes source
SHA, canonical fixture digest, exact route-manifest path and bytes, exact
evidence fields, the ordered 64 case IDs, their complete request/kind/surface/
expected semantics, and the ordered 11 requirement IDs. A `success` state must
reproduce all canonical case outcomes and pass every required evidence row.
The production gate verifies those bindings itself; it does not rely on the
Python validator at runtime.

All results remain blocked. Canonical synthetic success reports
`blocked_live_compatibility`, `compatible: false`, and `liveRun: false`; it is
fixture evidence, not deployment proof. Evidence is copied exactly once from
own enumerable data descriptors into inert structures before any decision.
Accessors, symbols, non-enumerable additions, missing, malformed, additive,
duplicated, reordered, unknown, incompatible, cyclic, or mismatched evidence
returns one bounded `incompatible` result without reflecting the supplied
content. Arrays are inspected only through one own `length` data descriptor,
bounded locally generated numeric keys, and own element descriptors. The gate
never reads an array property or calls an array method, including through a
Proxy.
`cancelled` and `unknown` preserve the source-state-reread recovery rule. The
gate performs no retry or outward action, so it cannot duplicate a prompt,
session, credential exchange, ticket mint, PTY input, or other side effect.

`createBehavioralProbeFixtureEvidence` exists only for deterministic tests and
no-network prototypes. It must not be treated as live evidence.

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
python3 contracts/fixtures/behavioral-probe/test_validate.py
```

Performance evidence is N/A for this constant-size, synchronous mock gate. There
is no approved product latency budget or live/release probe workload. The
canonical fixture's measured validator baseline remains the applicable
reproducibility evidence; this change makes no new runtime benchmark claim.
