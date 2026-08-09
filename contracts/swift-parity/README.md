# Swift contract parity

This package owns the C-21 Swift parity gate for the supported `dashboard-v0.0.1`
surface. It reads the checked-in language-neutral registry and the selected,
synthetic JSON fixture artifacts directly from `contracts/fixtures/`.

The package is an offline proof tool. It never starts Hermes, sends a URL request,
opens a socket, imports a transport or authentication framework, reads Keychain
material, performs OAuth, signs an artifact, renders Apple UI, or loads Terminal
fixtures. It makes no live compatibility claim.

## Covered representative outcomes

The runner mirrors the C-20 representative semantic projection for:

- browser cookie authentication and a rejected CSRF callback;
- connection restoration and session persistence, while keeping pending coverage
  blocked;
- chat delivery uncertainty and automatic prompt retry rejection;
- empty, malformed, and accepted image attachment states;
- web-only PTY byte preservation and redaction, with Apple invocation blocked;
- valid and rejected private deep links; and
- matching and missing deployment attestation, plus the blocked aggregate
  compatibility record.

The result compares independently derived Web and Apple semantic projections,
not the fixture's `expected` dictionary or platform-specific wire bytes. Web
projection reads browser response and transport fields; Apple projection reads
native state, persistence, and platform-gate fields. A divergence is a parity
failure rather than evidence. The registry's `pending` rows become `blocked`
results and can never be promoted to proof. Unknown fixture roots, case selectors, platform values,
statuses, unsafe paths, and unregistered representative artifacts fail closed.
Every read is rooted at a held repository descriptor. Directory and regular-file
components use no-follow opens; regular-file metadata is checked before and
after bounded reads, and the path is reopened from the held parent descriptor to
detect replacement. Selected JSON artifacts must match the registry's exact
size and SHA-256 binding. There is no pathname or glob fallback. Strict JSON
parsing rejects duplicate keys and bounds bytes, depth, nodes, keys, strings,
integers, arrays, case counts, error text, and parser time. Coverage rows preserve
all neutral statuses (`ready`, `pending`, `empty`, `failure`, `cancelled`, and
`unknown`); only `ready` can provide evidence, while pending roots may explicitly
set `validator` to JSON `null`.

Before reading parity evidence, the runner performs an authoritative C-19
preflight. On macOS it may execute the checked-in validator with bounded
`/usr/bin/python3 -B`, `PYTHONDONTWRITEBYTECODE=1`, a fixed host `PATH`, bounded
stdout/stderr, and a five-second deadline. A blocked, unavailable, malformed,
truncated, timed-out, failed, or live-claiming validator result returns a blocked
report with a specific `errorCode`, zero proven cases, and `liveClaim: false`. On
iOS and other non-host builds, callers must inject a separately verified preflight
result; otherwise the runner fails closed with `c19_validator_unavailable`.
The injected preflight mode is for offline tests and verified host-produced
results only; it does not replace the C-19 validator or make a live claim.

## Commands

Run from this directory:

```sh
swift test
swift run hermternal-swift-parity --repo-root ../..
```

The CLI emits one bounded JSON line with sorted object keys and canonical case,
platform, and coverage ordering. A ready report exits zero. A blocked report is
still emitted as JSON on stdout but exits nonzero; the current host registry is
expected to return `status: "blocked"` with `errorCode: "c19_validator_blocked"`
until the authoritative aggregate validator passes. `networkCalls` is always
zero and `liveClaim` is always false.

## Exact limitations

- This is a parity reader, not a runtime client and not an Apple application.
- It implements the reviewed representative projection only. It does not infer
  schemas for arbitrary JSON-RPC bodies or events that the Dashboard manifest
  intentionally leaves source-defined.
- It selects only the approved JSON artifacts used by the parity contract. It
  does not scan every registered artifact or treat an unindexed artifact as
  eligible evidence. The selected inventory is bounded and every selected
  manifest record is checked against descriptor metadata, byte count, and
  SHA-256 before decode.
- The C-19 aggregate validator remains authoritative for duplicate-key checks,
  full registry schema validation, artifact digests, redaction scanning, and
  the complete unindexed-artifact inventory. This package independently checks
  its selected paths before decoding them but does not replace that validator.
- PTY is represented only by synthetic web evidence. Apple Terminal remains
  blocked by contract and no PTY bytes are read from a live process.
- A passing report proves synthetic fixture parity only. It does not attest a
  deployment, pass a behavioral probe, authorize authentication, or establish
  Hermes compatibility.

No files under `contracts/fixtures/validator/` are required or changed by this
package.
