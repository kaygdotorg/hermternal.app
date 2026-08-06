# PTY local byte-adapter proof

**Status:** deterministic synthetic deployment-security evidence for issue `#209`
(`DEP-10M`).

This directory proves the web-only `WS /api/pty` boundary with a local byte
adapter. It does not open a real PTY, WebSocket, proxy, Hermes process, port
`9119`, Apple client, or network connection. Every handle, session, process,
socket, host class, frame, action, and log reference is synthetic. The pinned
Hermes revision is recorded for traceability only; the validator does not fetch
or import it.

## Frozen behavior

`cases.json` is a closed, ordered matrix for these operations:

- accept a supported synthetic upgrade into a binary local byte adapter without
  spawning a process;
- preserve the independently anchored binary frame bytes, frame order, and frame
  boundaries without UTF-8 decoding or re-encoding, including a split code point,
  an incomplete fragment, and an invalid fragment;
- clamp integer resize dimensions to columns `1..2000` and rows `1..1000`, then
  emit one exact binary `ESC [RESIZE:<cols>;<rows>]` control message using the
  independently anchored prefix and suffix bytes;
- reject fractional, boolean, string, null, non-finite-token, and malformed
  resize inputs before binary send, with each candidate bound to the exact
  `ESC [RESIZE:<cols>;<rows>]` grammar or its one-character malformed form;
- attach and reattach the same, non-aliased handle, session, and process to a
  distinct second socket without a second spawn, while retaining the detached
  session;
- retain only the newest `1 MiB` output segment and allow retained output and a
  live frame to race in either receive order without a separator;
- allow detach at `1799` and `1800` seconds and expire only after `1800` seconds;
- retain prompt and tool output references while never replaying input, resize,
  prompt, or tool action references;
- keep PTY byte and action payload fields null in diagnostics and retained
  records;
- send replacement close `4409`, dead-process close `4410`, and clean legacy
  disconnect close `1000`; prove the legacy bridge-close, process terminate,
  process reap, and reattach-prohibited timeline; and cover backend `1011`,
  auth `4401`/`4408`, and host `4403`/`4404` errors; and
- reject an unsupported host before upgrade, socket acceptance, adapter setup,
  or process spawn.

The fixture is contract evidence, not a PTY implementation. It does not prove
runtime scheduling, WebSocket framing performed by a browser, process signals,
terminal rendering, accessibility, or live Hermes behavior.

## Strict validation and redaction

`validate.py` uses only the Python standard library. It rejects duplicate JSON
object keys, non-finite numbers, oversized integers, malformed UTF-8, control
characters, excessive JSON depth, excessive nodes, oversized strings, and
unknown or reordered object keys. Immutable byte, resize, lifecycle, close-code,
and error-code anchors prevent the fixture from passing after semantic drift.
Exact scalar types are used, so booleans are not accepted as integer dimensions.
Validation uses explicit exceptions rather than `assert`, so the same checks run
under normal Python and `python3 -O`.

Diagnostics are bounded to 240 characters and redact secret-shaped assignments,
bearer-shaped values, private-key markers, and live URL markers before the cap
is applied. CLI failures emit one fixed JSON object and do not echo caller
paths, flags, duplicate field names, fixture values, credentials, cookies,
transcripts, or user data. Raw bytes appear only in explicit fixture input or
output fields. Log payload fields are required to be null.

## Verification

Run from the repository root:

```sh
python3 contracts/fixtures/deployment-security/pty-local-adapter/validate.py
python3 -O contracts/fixtures/deployment-security/pty-local-adapter/validate.py
python3 -m unittest discover \
  -s contracts/fixtures/deployment-security/pty-local-adapter \
  -p 'test_*.py'
python3 -O -m unittest discover \
  -s contracts/fixtures/deployment-security/pty-local-adapter \
  -p 'test_*.py'
python3 -m py_compile \
  contracts/fixtures/deployment-security/pty-local-adapter/validate.py \
  contracts/fixtures/deployment-security/pty-local-adapter/test_validate.py
```

For isolated malformed-case checks, skip the checked-in benchmark artifact:

```sh
python3 contracts/fixtures/deployment-security/pty-local-adapter/validate.py \
  --cases /tmp/synthetic-pty-cases.json \
  --skip-baseline
```

The real CLI regressions in `test_validate.py` invoke both approved commands,
with and without `-O`, and check success and controlled failure output.

## Baseline evidence

`validation-baseline.json` records 30 wall-clock validator samples for each
build mode. It names the fixture, validator, metric, canonical measured
environment (`macOS-26.5.2-arm64-arm-64bit-Mach-O`, Python `3.14.6`), exact
command, repetitions, raw trace, and a deterministic distribution using
inclusive linear interpolation for `p50`, `p95`, and `p99`. Runs are ordered
`normal` then `optimized`; the artifact digest covers `README.md`, `cases.json`,
and `validate.py` in path order.

`threshold` is `null`: issue `#209` has no reviewed performance budget. The
trace is observation-only evidence, not a latency promise. The validator
recomputes every distribution, checks the exact ordered mutation inventory, and
checks the artifact digest plus immutable source/artifact identity before
accepting the baseline. Re-run both recorded commands for a new reviewed
artifact; do not claim a performance threshold without a later decision.

## Accessibility and security scope

Accessibility is **N/A for this protocol-only fixture** because it contains no
UI nodes or interaction code. The later Terminal client must still verify
keyboard and focus behavior, semantic names, browser zoom, contrast,
reduced-motion/transparency behavior, localization growth, and effective touch
targets against `contracts/state-models/terminal.md`.

Security evidence is synthetic-only. No real PTY, Hermes, proxy, port, host,
credential, cookie, transcript, or user data is used. Do not treat a passing
fixture as a deployment attestation or a live transport test.
