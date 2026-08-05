# PTY byte and lifecycle contract fixtures

**Status:** normative synthetic proof for the web-only `WS /api/pty` route.

This directory freezes the PTY byte, resize, attach, replay, and close-code
boundary without running a real PTY, proxy, Hermes gateway, port `9119`, or
Apple client. All identifiers and payloads are deterministic synthetic values.
The pinned Hermes revision is
`f5be9236e00ddf2f2a412697f267078fc4ee068e`.

The existing Terminal state model remains the lifecycle source of truth. This
fixture set adds the byte-adapter proof required by C-17 and does not edit the
shared state model or aggregate fixture index.

## Frozen behavior

| Area | Contract |
| --- | --- |
| PTY output | Treat WebSocket PTY frames as raw binary bytes. Do not UTF-8 decode, re-encode, or log the bytes. |
| Resize | Emit one binary control message: `ESC [RESIZE:<cols>;<rows>]`. Valid columns are `1..2000`; valid rows are `1..1000`. The control message is not PTY input. Malformed or out-of-range adapter inputs fail before binary send. |
| Legacy attach | Missing or empty `attach` selects legacy mode. Disconnect and explicit Close terminate the child and end in `exited`; reattach is prohibited. |
| Attach keep-alive | A non-empty opaque synthetic handle selects registry mode. Disconnect and attach-mode Close detach the socket while retaining the process and registry identity for 1800 seconds. |
| Replacement | A superseded socket receives close code `4409` before the replacement is assigned. Stale cleanup cannot detach the replacement. |
| Process exit | A dead PTY closes with code `4410` and the client does not retry the dead process. |
| Registry | The registry remains bounded at 16 entries. |
| Replay | Retain only the newest 1 MiB of PTY output. Input, resize, prompt, and tool actions are never replayed. Prompt and tool output bytes may be retained as output. Retained and live output may race; no replay boundary or separator is inserted. |
| Logging | PTY byte payloads never enter log records. Metadata such as frame reference and byte length is allowed. |

The resize fixture also retains the source-model normalization examples for
minimum and maximum dimensions. The separate rejection case proves that
malformed and out-of-range values are not sent by the synthetic adapter.

## Files

- `pty-contract-fixtures.json` — closed, redacted fixture schema and all normal,
  failure, lifecycle, replay, logging, and race cases.
- `validate.py` — standard-library validator. It rejects unknown keys, wrong
  types, duplicate fixture IDs, non-synthetic references, secret-shaped text,
  duplicate JSON keys, and JSON `NaN`/`Infinity`. Its mutation inventory is
  executable and must fail closed.
- `test_validate.py` — regression tests for the canonical fixture, every named
  mutation, controlled CLI failures, duplicate keys, and non-finite numbers.
- `validation-baseline.json` — measured normal and optimized validator timing
  plus stable owned-artifact size. It records observations only; no approved
  performance threshold is invented.

## Verification

Run from the repository root:

```text
python3 contracts/fixtures/pty-contract/validate.py
python3 -O contracts/fixtures/pty-contract/validate.py
python3 -m unittest discover -s contracts/fixtures/pty-contract -p 'test_*.py'
python3 -O -m unittest discover -s contracts/fixtures/pty-contract -p 'test_*.py'
```

The validator and tests are offline. No live integration, credentials, cookies,
transcripts, hostnames, or user data belong in these artifacts.

## Accessibility and security evidence

Accessibility is **N/A for this artifact** because it is a protocol fixture and
contains no UI nodes or interaction code. The contract preserves the required
web Terminal accessibility behavior by referencing
`contracts/state-models/terminal.md`; later clients must still verify keyboard,
focus, semantic names, zoom, contrast, reduced motion/transparency, and touch
targets.

Security proof is synthetic-only. Raw bytes appear only in explicit fixture
input/output fields; the logging case requires null payloads and metadata-only
records. The parser rejects duplicate keys and non-finite numeric extensions so
an ambiguous or non-portable fixture cannot pass validation.
