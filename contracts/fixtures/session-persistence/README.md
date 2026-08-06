# C-07 session persistence fixture

This directory is the focused synthetic contract fixture for GitHub issue #55
(C-07). It covers the session boundary without connecting to Hermes or creating a
runtime client.

## Scope

The fixture defines deterministic behavior for:

- empty `session.create` drafts and the lazy durable-row boundary;
- first-prompt persistence and idempotent row creation;
- reopen/resume of the same stored session and server-owned history;
- explicit empty, interrupted, detached, and delivery-uncertain states;
- duplicate create, prompt, persistence, and resume evidence;
- persistence, resume, malformed, foreign, and unknown-event failures;
- fail-closed behavior with no silent new-session or automatic prompt fallback.

The reducer in `validate.py` is a proof fixture, not a Hermes implementation. It
uses only standard-library Python and synthetic markers. It does not import
Hermes, open a WebSocket, read a state database, call a provider, create a
credential, or store a local transcript mirror. Server-owned history is modeled
only as an observable result of resume.

## Pinned source observations

The observations are pinned to Hermes revision
`f5be9236e00ddf2f2a412697f267078fc4ee068e` and record the reviewed source paths
and anchors in `cases.json`:

- `session.create` allocates a live id and stored key but defers the database
  row until the first prompt;
- `prompt.submit` persists the row before deferred agent work and returns a safe
  storage error when that write fails;
- `SessionDB.create_session` is idempotent for the stored session key;
- `session.resume` reopens an ended row and reads the durable history projection;
- `session.interrupt` clears queued input and does not resend it automatically;
- WebSocket loss detaches ordinary sessions for a bounded reconnect window;
- parse, dispatch, malformed, and incompatible results are errors, not success.

This fixture does not claim behavior outside those observations. A shared
contract change is not required for this subtree; any future mismatch belongs in
a coordinator/child follow-up rather than in `contracts/state-models/chat.md` or
the shared fixture index.

## Contract rules

The semantic inventory is intentionally strict. Object key order, case order,
state names, source observations, invariant values, and redaction metadata are
validated exactly. The loader rejects duplicate JSON keys, invalid UTF-8,
`NaN`/`Infinity`, oversized integers, excessive depth, and oversized object,
array, string, node, or file inputs. Validator failures emit one stable,
redacted error line and never include input, paths, credentials, cookies,
tickets, tokens, hostnames, prompts, transcripts, or user data.

The important boundary is:

1. `session.create` creates an empty ephemeral draft.
2. The first `prompt.submit` attempts one idempotent durable-row write.
3. A known persistence failure preserves the draft, clears transient running
   state, and requires an explicit retry.
4. Resume reads the existing server session and restores its durable projection.
5. A missing, foreign, interrupted, malformed, or unknown result fails closed.
6. When prompt delivery is uncertain, restore source state before any user-led
   decision. Automatic prompt resubmission is forbidden.

## Commands and evidence

Run from the repository root:

```text
python3 contracts/fixtures/session-persistence/validate.py
python3 -O contracts/fixtures/session-persistence/validate.py
python3 -m unittest contracts/fixtures/session-persistence/test_validate.py
```

`test_validate.py` invokes both approved validator commands as real subprocesses,
then exercises strict JSON, redaction, baseline, and semantic regression paths.
`validation-baseline.json` contains 30 measured normal samples and 30 measured
`-O` samples from the approved commands, with min/p50/p95/max/mean distributions.
The baseline is reproducibility evidence for the reviewed machine only;
`threshold` is deliberately `null` and is not a performance budget.

## Applicability boundaries

This is a non-UI protocol fixture. Paper, visual regression, Dynamic Type,
VoiceOver, keyboard, touch-target, and reduced-motion checks are not applicable
to these files. Any later UI implementation must separately follow the shared
session-state and accessibility contracts; this fixture must remain synthetic
and offline.
