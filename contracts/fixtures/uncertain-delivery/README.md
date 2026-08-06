# Uncertain prompt-delivery fixture

This directory is the focused C-06 contract for uncertain prompt delivery. It
is a deterministic, standard-library-only fixture. It does not start Hermes,
open a Dashboard WebSocket, contact a proxy or identity provider, store prompt
text, read a transcript, or claim live compatibility.

## Contract binding

- Operation: `C-06`
- Dashboard contract: `dashboard-v0.0.1`
- Reviewed Hermes source: `f5be9236e00ddf2f2a412697f267078fc4ee068e`
- Canonical inputs: `cases.json`
- Validator: `validate.py`
- Regression tests: `test_validate.py`
- Measurement record: `validation-baseline.json`

The source observations are limited to the pinned `gateway.ready`,
`WebSocketDisconnect`, `prompt.submit`, and `session.resume` anchors. They bind
this planning result to the reviewed source without importing it or claiming
that a local checkout is a running deployment.

## Frozen transition rules

The fixture proves these rules as executable traces:

- A confirmed accepted prompt or correlated server event is not submitted a
  second time.
- A timeout, WebSocket close, app suspension, or process loss after send is
  `delivery_uncertain`, not rejection.
- Restore is a barrier. The client rereads server-owned history and status
  before making any resend decision.
- Present history or a running/completed turn wins over the local draft; the
  client renders that server result and does not resend.
- Absent history plus idle server status keeps the original draft and waits for
  an explicit user decision. Only that decision may create one new send.
- A confirmed request rejection preserves the draft and permits one later
  explicit retry. It does not authorize automatic resend.
- A second uncertain send never receives an automatic third send.
- `session.resume`, `session.history`, `session.status`, and `model.options`
  are the only automatic retry methods in this fixture. Prompt submission,
  session creation, and interruption are never automatically retried.
- Duplicate send while `submitting` or `streaming` is locally blocked and does
  not increase the outward submission count.
- An uncertain interrupt remains unconfirmed until restored server status
  proves its result. Sign-out clears the selected session and suppresses
  reconnect while preserving the local draft.
- Pending compatibility evidence remains pending. Mismatched evidence and
  unknown interactive events fail closed; they are not converted into an
  approval or clarification control.

The fixture uses only bounded semantic markers such as `session-marker-001`
and `request-marker-001`. It has no prompt body, transcript bytes, ticket,
credential, host, path, attachment, PTY data, or user data.

## Strict validation and bounded failure output

`validate.py` rejects duplicate object keys at every level, invalid UTF-8,
non-finite numbers, exponent overflow, oversized integers, deep or oversized
JSON, wrong exact scalar types, changed object-key order, changed case order,
source-observation drift, and semantic timeline contradictions. Assertions are
not used for contract guards, so normal and optimized Python modes enforce the
same checks.

The loader and retained-marker scan reject credential-shaped keys, raw prompt
or transcript fields, URLs, paths, hosts, cookie and authorization material,
JWT-like values, and base64-like payloads. CLI failures are one fixed JSON line
on standard error, capped at 240 characters. They do not echo paths, flags,
keys, values, parser details, or tracebacks.

The checked-in case bytes, normalized validator source, owned artifact manifest,
and both benchmark sample/distribution identities are pinned outside the
mutable baseline object. Rebinding a baseline or copying a mutated case file
therefore fails closed instead of replacing reviewed evidence.

## Reproduce the proof

Run from the repository root:

```text
python3 contracts/fixtures/uncertain-delivery/validate.py
python3 -O contracts/fixtures/uncertain-delivery/validate.py
python3 -m unittest discover -s contracts/fixtures/uncertain-delivery -p 'test_*.py'
python3 -O -m unittest discover -s contracts/fixtures/uncertain-delivery -p 'test_*.py'
PYTHONPYCACHEPREFIX=/tmp/hermternal-c06-pycache python3 -m py_compile contracts/fixtures/uncertain-delivery/validate.py contracts/fixtures/uncertain-delivery/test_validate.py
```

The focused tests execute the real validator CLI in both normal and optimized
modes. They cover accepted/present, absent-and-idle, confirmed rejection,
timeout, WebSocket close, app suspension, process loss, restore, explicit
resend, duplicate prevention, interruption, cancellation, sign-out, pending
proof, compatibility failure, unknown interactive events, strict JSON, bounded
redaction, canonical artifact rebinding, and forged benchmark evidence.

`validation-baseline.json` records 30 raw subprocess samples for each normal
and optimized command, with min/mean/median/p95/max distributions and the
measured environment. `threshold` is intentionally `null`: this offline
contract records reproducibility evidence and does not invent a product
performance budget. `build_mode` is `N/A` because there is no production or
release executable in this fixture.

## Accessibility and Paper scope

Paper and direct UI accessibility evidence are **N/A**. This change owns a
non-UI protocol contract and standard-library validator, so it creates no
control, focus order, semantic name, screen-reader or VoiceOver surface,
Switch Control behavior, Dynamic Type or browser-zoom layout, contrast, motion,
transparency, or touch target. The state model preserves those downstream
obligations for later web, iOS, iPadOS, and macOS client implementations.
