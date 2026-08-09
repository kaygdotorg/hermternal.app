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
components use no-follow, close-on-exec, non-blocking opens (with directory
opens constrained by `O_DIRECTORY`); macOS `/tmp` and `/var` aliases are mapped
to `/private` without realpath or pathname reads. Regular-file metadata is checked
before and after bounded reads, and the leaf is reopened from the held parent
file descriptor to detect replacement. FIFO and other non-regular inputs fail
closed before any read. Selected JSON artifacts must match the registry's exact
size and SHA-256 binding. There is no pathname or glob fallback. Strict JSON
parsing rejects duplicate keys and bounds bytes, depth, nodes, keys, strings,
integers, arrays, case counts, error text, and parser time. Coverage rows preserve
all neutral statuses (`ready`, `pending`, `empty`, `failure`, `cancelled`, and
`unknown`); only `ready` can provide evidence, while pending roots may explicitly
set `validator` to JSON `null`.

Before reading parity evidence, the public runner performs an authoritative
C-19 preflight. On macOS it executes the checked-in validator's exact, bounded
bytes with `/usr/bin/python3 -I -B -c` and a stdin pipe (the reviewed path is
only the compile filename and `__file__` value, never a script reopen). The
interpreter runs from a fresh private empty directory with a minimal environment;
isolated mode excludes repository imports, `PYTHONPATH`, `PYTHONHOME`, and
user-site customizations. The success output must have exactly the reviewed
keys `ok`, `complete`, `evidence_status`, `compatible`, `live_claim`,
`fixture_count`, and `coverage_count`; it requires `ok: true`,
`compatible: false`, `live_claim: false`, a matching `partial`/`complete`
evidence status, and bounded non-negative counts. `PYTHONDONTWRITEBYTECODE=1`, bounded
stdin/stdout/stderr, and one five-second deadline remain enforced. A blocked,
unavailable, malformed, truncated, timed-out, failed, contract-invalid, or
live-claiming validator result returns a blocked report with a specific
`errorCode`, zero proven cases, and `liveClaim: false`.

On macOS, the safe host-speed classification set for a blocked real validator
is exactly `{c19_validator_timeout, c19_validator_blocked}`. The timeout code
means the process was still running at the five-second deadline. The blocked
code means the reviewed validator emitted its valid nonzero blocked marker and
finished before that deadline. The result therefore does not depend on whether
this host schedules the validator quickly or slowly. Both classifications are
safe because the report remains `ok: false`, contains no cases or compatibility
evidence, has `readyCaseCount: 0`, `networkCalls: 0`, and `liveClaim: false`.
`c19_validator_failed`, output-contract, output-bound, and unavailable results
are not interchangeable with this safe set. The checked-in
`../fixtures/validator/validation-baseline.json` records 30 Darwin arm64
samples ranging from 724.392ms to 791.332ms; those measurements describe
runtime, not a new semantic outcome.

On iOS and other non-host builds, the public runner always fails closed with
`c19_validator_unavailable`; no caller-supplied preflight status or evidence can
replace the host validator. The internal `@testable`
`runParityForTests(at:)` helper exists only for synthetic projection tests and is
not part of the public API or CLI report path.

The provisional parent used for this rehearsal narrows `browser-cookie-auth`
coverage to Web even though its representative fixture carries independent
Apple semantics. The tests preserve production parity logic by copying the
fixture repository into test-owned temporary data and broadening only that
temporary coverage row to `web`, `ios`, `ipados`, and `macos`. No checked-in
fixture or validator bytes are changed. The CLI test also uses a separate,
longer host process budget than the validator's five-second deadline so host
scheduling does not turn the safe `blocked` and `timeout` classifications into
a test failure.

## Commands

Run from this directory:

```sh
swift test
swift run hermternal-swift-parity --repo-root ../..
```

The CLI emits one bounded JSON line with sorted object keys and canonical case,
platform, and coverage ordering. A ready report exits zero. A blocked report is
still emitted as JSON on stdout but exits nonzero. On macOS, the current host
registry may return either `errorCode: "c19_validator_timeout"` or
`errorCode: "c19_validator_blocked"`; these are the only interchangeable
speed-dependent classifications. The report still has `ok: false`,
`status: "blocked"`, `readyCaseCount: 0`, no cases or compatibility evidence,
`networkCalls: 0`, and `liveClaim: false`. Other error codes remain distinct
failure or availability conditions. The authoritative aggregate validator must
pass before this package can produce parity evidence.

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
