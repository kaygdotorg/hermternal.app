# PTY detach, retained-output race, truncation, and expiry fixtures

**Status:** normative synthetic C-18 contract evidence for the web-only `WS /api/pty` route.

This focused fixture directory proves the detached-session and retained-output
boundaries without opening a real PTY, WebSocket, Hermes gateway, host socket,
port, or Apple client. Every handle, session, process, socket, host, action,
output segment, and log reference is synthetic. The fixture is not a transcript
and does not contain credentials, cookies, tickets, hostnames, or user data.

The existing PTY state model and the previously merged C-18A source audit remain
read-only semantic references. This directory is intentionally separate from
`contracts/fixtures/pty-contract/`, `contracts/fixtures/source-audit/`, and any
aggregate fixture index.

## Frozen C-18 behavior

| Area | Contract |
| --- | --- |
| Detach retention | A detached attach session may reattach while `elapsed <= 1800` seconds. Expiry occurs only when `elapsed > 1800`; 1799, 1800, and 1801 are explicit probes. |
| Registry bound | The registry holds at most 16 entries. A seventeenth synthetic entry is rejected without eviction or replacement. |
| Replay truncation | Replay contains only the newest 1 MiB of PTY output. A newest segment exactly 1 MiB is valid; older output may be absent. |
| Replay/live race | Retained output and a newly live frame may arrive in either order. The client renders receive order and no replay separator is inserted. |
| Active attachment | One handle has at most one active socket. Supersession sends `4409` to the old socket before replacement assignment; stale cleanup cannot detach the replacement. |
| Explicit Close | Attach-mode Close detaches the socket and retains the session; it does not terminate the process. |
| Host rejection | An unsupported host is rejected before socket acceptance or PTY spawn. |
| Resize | Exact built-in integers are clamped to columns `1..2000` and rows `1..1000`, then framed as one binary `ESC [RESIZE:<cols>;<rows>]` message. Floats, booleans, strings, null, non-finite tokens, and malformed frames are rejected. |
| Reconnect | Reattach reuses the same handle, session, and process identity. Truncation may remove older output before the snapshot is sent. |
| Action exclusion | Input, resize, prompt submission, and tool actions are never replayed. Prompt/tool output bytes may be retained as PTY output. |
| Logging | Raw PTY bytes and action payloads are absent from logs and retained diagnostics; metadata-only references are allowed. |

## Files

- `pty-detach-race-fixtures.json` — closed, redacted, language-neutral fixture data.
- `validate.py` — standard-library-only validator with duplicate-key rejection,
  non-finite rejection, exact built-in type checks, bounded traversal, controlled
  diagnostics, executable mutation checks, and baseline integrity checks.
- `test_validate.py` — normal and optimized-compatible regression tests for the
  canonical contract and meaningful malformed or drifted mutations.
- `validation-baseline.json` — observation-only benchmark distributions with 30
  normal and 30 optimized samples plus exact owned-artifact sizes and digests.

## Verification

Run from the repository root:

```text
python3 contracts/fixtures/pty-detach-race/validate.py
python3 -O contracts/fixtures/pty-detach-race/validate.py
python3 -m unittest discover -s contracts/fixtures/pty-detach-race -p 'test_*.py'
python3 -O -m unittest discover -s contracts/fixtures/pty-detach-race -p 'test_*.py'
python3 -m py_compile contracts/fixtures/pty-detach-race/validate.py contracts/fixtures/pty-detach-race/test_validate.py
```

The CLI loads the checked-in baseline by default. It checks the closed baseline
schema, 30-sample distributions, owned artifact sizes, SHA-256 digests, and the
manifest digest. The benchmark has `threshold: null`: timings are evidence, not
an invented performance budget. `--baseline` is available for isolated mutation
checks.

## Redaction and limitations

The JSON loader rejects duplicate keys at every object level, JSON `NaN`,
`Infinity`, `-Infinity`, exponent-overflow non-finite numbers, unsupported value
types, and nesting deeper than the bounded limit. Diagnostics are capped and
never include raw fixture values. Synthetic references may not encode a payload
as an even-length hexadecimal suffix. Raw bytes appear only in explicit input or
output fixture fields, never in log payload fields.

This is offline contract evidence only. It does not prove runtime scheduling,
network transport, process signals, browser rendering, accessibility, or live
Hermes behavior. Later clients must implement the state model and verify their
own focus, keyboard, zoom, contrast, reduced-motion, and failure behavior.
