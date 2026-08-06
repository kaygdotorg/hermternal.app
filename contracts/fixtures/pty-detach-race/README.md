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
| Resize | Exact built-in integers are clamped to columns `1..2000` and rows `1..1000`, then framed as one binary `ESC [RESIZE:<cols>;<rows>]` message. The fixture freezes lower, upper, and out-of-range samples and eight unique malformed/type rejection classes. Floats, booleans, strings, null, non-finite tokens, and malformed frames are rejected. |
| Reconnect | Reattach reuses the same handle, session, and process identity. Truncation may remove older output before the snapshot is sent. |
| Action exclusion | Input, resize, prompt submission, and tool actions are never replayed. The retained and replay reference lists must equal the canonical prompt-output and tool-output inventory; action references cannot be substituted. Prompt/tool output bytes may be retained as PTY output. |
| Logging | Evidence contains exactly one `pty.output`, `user.input`, `terminal.resize`, `prompt.submit`, and `tool.action` record in that order. The output record has a non-null frame reference, each action record has its canonical non-null action reference, and every byte or action payload field is `null`. |

## Closed evidence inventories

`no-input-replay` binds `retained_output_refs` and `replay_refs` to these exact
output records, including their byte provenance:

- `synthetic-output-prompt` — `prompt-output` — `70726f6d70742d6f7574707574`
- `synthetic-output-tool` — `tool-output` — `746f6f6c2d6f7574707574`

The sensitive action inventory is also exact and ordered: `input` maps to
`synthetic-action-input`, `resize` to `synthetic-action-resize`, `prompt` to
`synthetic-action-prompt`, and `tool` to `synthetic-action-tool`. The logging
frame inventory is fixed to `synthetic-output-log-a` (`00ff`) and
`synthetic-output-log-b` (`1b5b`). No action or output-frame alias is accepted
as retained, replayed, or logged evidence.

The resize boundary set is fixed to lower, upper, and out-of-range tuples:
`(1,1)->(1,1)`, `(2000,1000)->(2000,1000)`, `(-1,24)->(1,24)`,
`(0,0)->(1,1)`, `(80,-1)->(80,1)`, `(2001,24)->(2000,24)`,
`(80,1001)->(80,1000)`, and `(2001,1001)->(2000,1000)`. The rejection set
covers each malformed/type class exactly once, including fractional,
boolean, string, null, non-finite, malformed-frame, and row variants.

## Files

- `pty-detach-race-fixtures.json` — closed, redacted, language-neutral fixture data.
- `validate.py` — standard-library-only validator with duplicate-key rejection,
  redacted reusable-loader diagnostics, non-finite rejection, exact built-in type
  checks, bounded traversal, controlled CLI failures, executable mutation checks,
  and code-pinned source/benchmark identity checks outside the baseline.
- `test_validate.py` — normal and optimized-compatible regression tests for the
  canonical contract, meaningful malformed or drifted mutations, credential-shaped
  duplicate keys, coordinated artifact/baseline rebinding, alternate-fixture
  rebinding, forged benchmarks, and rebound validator source.
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

The CLI loads the checked-in baseline by default. Before running contract or
mutation checks, it authenticates the executing `validate.py` bytes against a
code-pinned normalized source digest whose identity marker is excluded to avoid a
circular hash. The bytes selected by `--fixture` must independently match the
code-pinned canonical fixture identity; a copied or mutated alternate file cannot
be authorized by changing baseline metadata. It also binds both benchmark modes'
sample traces and derived distributions to code-pinned reviewed SHA-256
identities. Owned artifact sizes, SHA-256 digests, and the manifest must match the
immutable artifact identity; rewriting baseline metadata cannot rebind the
evidence. The benchmark has
`threshold: null`: timings are evidence, not an invented performance budget.
`--baseline` is available for isolated mutation checks. Invalid arguments and
unavailable or malformed inputs return fixed, bounded diagnostics and never echo
caller-controlled flags, paths, fixture values, or duplicate JSON key names.

## Redaction and limitations

The JSON loader rejects duplicate keys at every object level, JSON `NaN`,
`Infinity`, `-Infinity`, exponent-overflow non-finite numbers, unsupported value
types, and nesting deeper than the bounded limit. Diagnostics are capped and
never include raw fixture values or duplicate JSON key names. Synthetic
references may not encode a payload
as an even-length hexadecimal suffix. Raw bytes appear only in explicit input or
output fixture fields, never in log payload fields.

This is offline contract evidence only. It does not prove runtime scheduling,
network transport, process signals, browser rendering, accessibility, or live
Hermes behavior. Later clients must implement the state model and verify their
own focus, keyboard, zoom, contrast, reduced-motion, and failure behavior.
