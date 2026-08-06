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
- the canonical synthetic deployment identity `synthetic-deployment-001`, trust
  channel `release-channel`, and scope `fixture_only` in both detached and runtime
  evidence;
- an opaque trust context created by `createCanonicalFixtureTrustContext`; plain
  attacker-controlled objects that repeat the fixture strings remain untrusted; and
- the C-04 requirements that attestation alone cannot enable live operation.

The record cannot declare itself trusted. Missing, empty, malformed, unknown,
untrusted, additive, reordered, mismatched, oversized, accessor-backed,
non-enumerable, symbolic, or server-derived version evidence fails closed.
String code units and UTF-8 bytes are bounded before trimming or parsing. Object
and array evidence is copied through data descriptors into an inert bounded
snapshot; a million-entry array is rejected without spreading it onto the stack.

Cancellation also returns a blocked decision. `createCompatibilityAttestationGate`
returns a nominal non-callable wrapper with no exposed callback. It accepts only
a privately branded wrapper from `createBehavioralProbeGate`, can be paired once,
and returns a transport factory rather than either raw role callback. The factory
installs both callbacks inside this module, so an extracted attestation callback
cannot be registered, bound, wrapped, proxied, or reused as a probe. A private
function-identity registry also rejects any exact cross-role registration if the
boundary changes later. Forged probe objects and repeated pairings are rejected.
The source-backed transport tests prove pending, passed, failed, and cancelled
probe states and prove that attestation alone never reaches `ready`. This focused
change does not wire a live connection or implement the independent behavioral
probe.

The checked-in record is synthetic. A `verified` result proves only that the
fixture bindings and caller-supplied trusted-channel context match. It does not
prove a deployment, authenticate a release channel, or claim live compatibility.
A later production boundary must supply authenticated trust context out of band.

## Source-backed tests

The tests read these contract fixtures directly from `contracts/`:

- `contracts/fixtures/compatibility-attestation/revision_attestation.json`
- `contracts/fixtures/compatibility-attestation/cases.json`

They execute every C-04 `attestation_result`, `behavioral_probe`, and
`runtime_gate` value through `createJsonRpcChatTransport`. Regressions cover
untrusted matching context, canonical deployment drift, duplicate/reordered/
additive JSON, non-finite numbers, accessor/symbol/non-enumerable runtime data,
normalized server-version metadata, million-entry arrays, Proxy array get traps,
oversized whitespace, bounded traversal, distinct probe success, and aborts.
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
