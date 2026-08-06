# Fixture-driven web compatibility attestation

This directory implements W-02 as an offline web gate over the approved C-04
fixtures. It performs no fetch, Hermes, proxy, authentication, credential, or
production configuration work.

## Boundary

`evaluateCompatibilityAttestation` verifies all of these inputs before it
returns `passed: true`:

- the exact `hermternal.revision-attestation.v1` schema, dashboard contract, and
  full pinned Hermes SHA;
- the reviewed route-manifest, source-review, and proxy-proof paths, digests,
  and byte counts;
- the detached deployment identity and release channel against the runtime
  evidence already supplied to the JSON-RPC client;
- an independent trust context whose authenticated channel matches the detached
  record; and
- the C-04 requirements that attestation alone cannot enable live operation.

The record cannot declare itself trusted. Missing, empty, malformed, unknown,
untrusted, additive, reordered, mismatched, oversized, or server-derived version
evidence fails closed. Cancellation also returns a blocked decision. The helper
`createCompatibilityAttestationGate` is structurally compatible with the
existing JSON-RPC `verifyAttestation` callback, but this focused change does not
wire a live connection or bypass the separate behavioral-probe gate.

The checked-in record is synthetic. A `verified` result proves only that the
fixture bindings and caller-supplied trusted-channel context match. It does not
prove a deployment, authenticate a release channel, or claim live compatibility.
A later production boundary must supply authenticated trust context out of band.

## Source-backed tests

The tests read these contract fixtures directly from `contracts/`:

- `contracts/fixtures/compatibility-attestation/revision_attestation.json`
- `contracts/fixtures/compatibility-attestation/cases.json`

They execute every C-04 attestation result and add regressions for untrusted
context, duplicate/reordered/additive JSON, non-finite numbers, runtime evidence
drift, server-shaped version metadata, bounded metadata traversal, and aborts.
Run the focused checks from `apps/web`:

```sh
bun x vitest run src/lib/compatibility/attestation/attestation.test.ts
bun x --package @typescript/native tsc --noEmit --pretty false -p tsconfig.json
bun run check
bun run build
```

## Paper and accessibility

The approved Paper manifest entry `runtime.compatibility-check-failed` was
inspected. This module adds no user interface and does not change the root route,
focus order, names, keyboard behavior, browser zoom, contrast, motion,
transparency, or touch targets. Paper implementation and accessibility checks
are therefore N/A for W-02. A later UI must use that manifest state and must not
hide a blocked decision behind a fallback.

## Benchmark evidence

Run the deterministic fixture workload from `apps/web`:

```sh
bun src/lib/compatibility/attestation/benchmark.ts
```

The command emits one JSON object with the workload and source fixture, metric,
environment, build-mode reason, 30 repetitions, distribution, operation count,
artifact bytes, zero network calls, and a null threshold. No budget is invented.
The measurement is developer-observed and unauthenticated. The production web
build remains a separate required check.
