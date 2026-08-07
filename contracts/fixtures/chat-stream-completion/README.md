# Chat stream and completion fixture

This directory is the focused C-08 proof for deterministic chat stream and completion ordering. It is a standard-library-only, synthetic protocol fixture. It does not open a WebSocket, call Hermes, submit a prompt, execute a tool, read a transcript, or implement a production client.

## Contract and source binding

- Dashboard contract: `dashboard-v0.0.1`
- Reviewed Hermes commit: `f5be9236e00ddf2f2a412697f267078fc4ee068e`
- Reviewed Hermes tree: `886db5eb1150f819344d67fedc81aef0caab09ff`
- Operation: `C-08`
- Canonical cases: `cases.json`
- Pinned source citations: `source-audit.json`
- Offline validator: `validate.py`
- Focused regressions: `test_validate.py`
- Measurement evidence: `validation-baseline.json`

`source-audit.json` binds each claim to an exact pinned source path, file SHA-256, Git blob SHA, line range, and source marker. The citations establish that display deltas may be buffered, non-streaming frames flush earlier deltas, tool lifecycle frames are ordered, `message.complete` is terminal for success or recoverable error, and `session.interrupt` requires a confirmed result. These identities are review evidence, not a runtime checkout or deployment check.

## Executable ordering contract

The closed 22-case inventory covers empty, pending, normal, success, failure, interruption, rejected interruption, and malformed sequences. Every stream frame is bound to one synthetic session, request, and turn. Numbered frames start at ordinal 1 and increase by exactly one.

The reducer enforces these rules:

- `message.delta`, `reasoning.delta`, and `thinking.delta` preserve arrival order;
- `tool.start` must precede one matching `tool.complete`;
- tools cannot overlap;
- normal completion is rejected while a tool remains open;
- `message.complete(status=complete)` is terminal success and has no `recoverable` field;
- `message.complete(status=error)` is terminal error, requires `recoverable`, and preserves only synthetic semantic markers;
- a gateway `error` is terminal without an invented completion;
- no frame is accepted after completion, error, or confirmed interruption;
- `interrupt.request` blocks every ordinal-bearing progress frame until its result;
- confirmed interruption may abandon an open tool without fabricating `tool.complete`;
- rejected interruption resumes the prior active state;
- unknown additive non-interactive events are ignored but still consume their ordinal;
- unknown interactive events fail closed;
- wrong-session, wrong-request, wrong-turn, missing interrupt result, ordinal gap, duplicate terminal, and lifecycle conflicts fail closed.

A fail-closed result clears retained segments and completed-tool markers. This prevents malformed ordering from becoming display state.

## Strict input and redaction boundary

The validator performs bounded incremental reads of regular files and requests at most the remaining capacity plus one rejection byte. It rejects symlinks, non-regular files, invalid UTF-8, duplicate keys, `NaN`, `Infinity`, exponent overflow, exponent underflow such as `1e-9999`, oversized integers, excessive nesting, excessive nodes, wide objects, long arrays, and long strings. Root, nested object, event, source citation, and benchmark key order is closed. Required scalars use exact built-in types, so booleans cannot substitute for ordinals.

Canonical case and source-audit bytes are pinned in the validator. Baseline artifact hashes bind the README, cases, source audit, validator, and tests. The benchmark environment, commands, raw samples, distributions, repetitions, and null threshold are separately pinned by a canonical identity in code.

All content is synthetic or source-derived. The fixture contains no prompt text, transcript, tool arguments, tool results, credentials, hosts, or user data. Correlation, content, tool, and error values are semantic markers only. CLI rejection is exactly one fixed redacted JSON line and does not expose paths or malformed input.

## Commands and benchmark evidence

Run validation in both interpreter modes:

```text
python3 contracts/fixtures/chat-stream-completion/validate.py
python3 -O contracts/fixtures/chat-stream-completion/validate.py
```

Run focused tests:

```text
python3 -m unittest discover -s contracts/fixtures/chat-stream-completion -p 'test_*.py'
python3 -O -m unittest discover -s contracts/fixtures/chat-stream-completion -p 'test_*.py'
```

Compile without importing a service:

```text
python3 -m py_compile contracts/fixtures/chat-stream-completion/validate.py contracts/fixtures/chat-stream-completion/test_validate.py
```

The baseline records 30 normal and 30 optimized samples, raw sample values, and deterministic distributions. The approved commands are the two validator commands above. `threshold` is deliberately `null`; this planning fixture does not invent a performance budget or claim deployment performance.

## Scope and registration hold

This protocol fixture has no direct UI or accessibility surface. Keyboard, screen-reader, zoom, Dynamic Type, color, loading, and visual-state checks are not applicable to this focused file set.

Aggregate registration is intentionally held. PR #265 and the separately owned aggregate registry task control `contracts/fixtures/index.json` and aggregate validator files. This change does not edit those shared files. Register this family only after that ownership lane merges and coordinates the canonical aggregate update.
