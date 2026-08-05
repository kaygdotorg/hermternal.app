# PTY byte and lifecycle contract fixtures

**Status:** normative synthetic proof for the web-only `WS /api/pty` route.

This directory freezes the PTY byte, resize, attach, replay, close-code, and
retained-diagnostics boundaries without running a real PTY, proxy, Hermes
gateway, port `9119`, or Apple client. All identifiers and payloads are
synthetic and deterministic. The pinned Hermes revision is
`f5be9236e00ddf2f2a412697f267078fc4ee068e`.

The existing Terminal state model remains the lifecycle source of truth. This
fixture set adds the byte-adapter proof required by C-17 and does not edit the
shared state model or aggregate fixture index.

## Frozen behavior

| Area | Contract |
| --- | --- |
| PTY output | Treat every WebSocket PTY frame as raw binary bytes. Preserve frame order and boundaries. Do not UTF-8 decode, re-encode, or log the bytes. |
| Resize | Emit one binary control message: `ESC [RESIZE:<cols>;<rows>]`. Every integer column and row is clamped to `1..2000` and `1..1000` before encoding and send. Negative, zero, and high integer values therefore clamp; out-of-range integers are not rejection cases. |
| Resize rejection | Reject non-integer numbers, booleans, strings, nulls, non-finite values, and malformed syntax before binary send. The JSON fixture represents `NaN` and `Infinity` as explicit wire tokens because the fixture parser itself rejects non-finite JSON extensions; direct mutation tests still reject actual non-finite Python values. |
| Legacy attach | Missing or empty `attach` selects legacy mode. The disconnect and explicit Close cases have separate accept, bridge-close, terminate, and reap timelines. Each ends in `exited` and prohibits reattach. |
| Attach keep-alive | A non-empty opaque handle selects registry mode. The executable timeline proves socket A detach, registry retention, socket B accept, registry reuse, reattach with the same handle, session, and process identity, then an explicit Close on socket B followed by its final registry detach. Disconnect and attach-mode Close detach the socket while retaining the process for 1800 seconds. |
| Replacement | A superseded socket receives close code `4409` before the replacement is assigned. Stale cleanup is ignored and cannot detach the replacement; the handle, session, and process identity remain bound. |
| Process exit | A dead PTY closes with code `4410` and the client does not retry the dead process. |
| Registry | The registry remains bounded at 16 entries. |
| Replay | Retain only the newest 1 MiB of PTY output; an exactly 1 MiB newest segment is valid. The fixture binds the evicted prefix and retained tail to immutable segment roles and references, so labels cannot be relabeled to weaken the proof. Input, resize, prompt, and tool actions are never replayed. Prompt and tool output bytes may be retained as output. Retained and live output may race; no replay boundary or separator is inserted. |
| Logging | Diagnostics retain only semantic metadata. Raw PTY bytes and input, resize, prompt, and tool action payloads are absent from retained records and log payload fields. |

The detach predicate is `elapsed > 1800`. The TTL fixture proves that 1799
seconds is allowed, exactly 1800 seconds is still allowed, and 1801 seconds is
expired.

The raw-byte boundary fixture includes a four-byte UTF-8 code point split over
two adjacent binary frames, an incomplete fragment, and an invalid fragment.
Validation compares hex bytes and frame references only; it never decodes the
fragments as text.

## Source-audit binding

`source_audit` in `pty-contract-fixtures.json` fingerprints the existing
immutable `contracts/fixtures/source-audit/pty-attach/**` evidence. It binds the
source-audit README, attach fixture, and source-evidence artifact to exact
SHA-256 digests and byte sizes, and binds both JSON artifacts to the pinned
commit snapshot and schemas. The validator reads those files locally and
verifies the revision fields. It does not copy source extracts into this
focused contract. Any digest, size, schema, or pinned-revision drift fails
closed and requires a new source audit.

## Files

- `pty-contract-fixtures.json` — closed, redacted fixture schema with the raw-byte boundary, resize matrix, lifecycle timelines, replay, logging, and source-audit fingerprint cases.
- `validate.py` — standard-library validator. It rejects unknown keys, wrong types, duplicate fixture IDs, payload-shaped or otherwise non-synthetic references, secret-shaped text, duplicate JSON keys, JSON `NaN`/`Infinity`, deep JSON trees, source-audit drift, and baseline content drift. Controlled diagnostics are capped at 240 characters. Its mutation inventory is executable and must fail closed.
- `test_validate.py` — regression tests for the canonical fixture, all named contract mutations, controlled CLI failures, raw frame boundaries, resize type handling, lifecycle identity, TTL equality, logging redaction, source fingerprints, baseline schema, and baseline content digests.
- `validation-baseline.json` — measured normal and optimized validator timing plus exact owned-artifact sizes and SHA-256 content fingerprints. It records observations only and invents no approved performance threshold.

## Verification

Run from the repository root:

```text
python3 contracts/fixtures/pty-contract/validate.py
python3 -O contracts/fixtures/pty-contract/validate.py
python3 -m unittest discover -s contracts/fixtures/pty-contract -p 'test_*.py'
python3 -O -m unittest discover -s contracts/fixtures/pty-contract -p 'test_*.py'
```

The validator CLI loads the canonical `validation-baseline.json` by default,
checks its exact schema, derived distributions, artifact sizes, and content
hashes against the current owned files, and fails closed if the evidence is
stale. `--baseline` is available for isolated mutation tests; the default
path remains the checked-in baseline.

The validator and tests are offline. No live integration, credentials,
cookies, transcripts, hostnames, or user data belong in these artifacts.

## Accessibility and security evidence

Accessibility is **N/A for this artifact** because it is a protocol fixture and
contains no UI nodes or interaction code. The contract preserves the required
web Terminal accessibility behavior by referencing
`contracts/state-models/terminal.md`; later clients must still verify keyboard,
focus, semantic names, zoom, contrast, reduced motion/transparency, and touch
targets.

Security proof is synthetic-only. Raw bytes appear only in explicit fixture
input/output fields. The logging case covers two output frames plus input,
resize, prompt, and tool actions, while requiring null payload fields,
empty retained action references, and metadata-only records. The parser rejects
duplicate keys and non-finite numeric extensions so an ambiguous or
non-portable fixture cannot pass validation.
