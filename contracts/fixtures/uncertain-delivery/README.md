# Uncertain prompt-delivery fixture

This directory is the focused C-06 contract for uncertain prompt delivery. It
is a deterministic, standard-library-only fixture. It does not start Hermes,
open a Dashboard WebSocket, contact a proxy or identity provider, store prompt
text, read a transcript, or claim live compatibility.

## Contract binding

- Operation: `C-06`
- Dashboard contract: `dashboard-v0.0.1`
- Reviewed Hermes source: `f5be9236e00ddf2f2a412697f267078fc4ee068e`
- External expected revision: supplied by review/CI as `HERMTERNAL_C06_EXPECTED_COMMIT`
- Non-release audit tag: `hermternal-c06-uncertain-delivery-final-anchor`
- Canonical inputs: `cases.json`
- Validator: `validate.py`
- Regression tests: `test_validate.py`
- Measurement record: `validation-baseline.json`
- Normative state model: `../../state-models/chat.md`

The validator requires an exact 40-character commit object from the external
review or CI invocation. It does not derive that value from this tree, a branch,
or a tag. The expected commit supplies immutable Git-tree bytes for the six
canonical artifacts; the current checkout may be a normal merge commit or a
later unchanged commit, but its canonical bytes and clean worktree must match
that external revision exactly. Missing, malformed, unavailable, or mismatched
external expectation fails closed.

Every supported validator launch uses Python isolated mode: `python3 -I` for
normal execution and `python3 -I -O` for optimized execution. Isolated mode
removes the fixture directory from `sys.path` before `validate.py` imports
standard-library modules such as `selectors` and `subprocess`; the validator's
shebang applies the same mode to direct executable launches. A non-isolated
`python3 validate.py` invocation is unsupported because a sibling `.py` file
could execute before trust checks.

The annotated tag is a non-release audit/availability marker only. It is not a
signature, release tag, or trust root. A protected repository owner must publish
it without force-retagging and keep its target equal to the externally supplied
reviewed commit. A force-retagged, forged, missing, `--no-tags`, shallow, or
partial clone fails closed. The executing source and caller-supplied cases and
baseline paths must be repository-owned. The fixture directory must contain
only its five declared files; unexpected or special-file siblings, including
`selectors.py` or `subprocess.py`, fail closed. The validator-source digest masks
only its own digest literals; it does not mask code, schema, reducer, or
redaction changes.

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
- Restore is a barrier. The client must observe `gateway.ready` with matching
  contract/source compatibility, then reread fresh server-owned history and
  status before making any resend decision. History and status keep independent
  current-attempt failure latches; a failed history read invalidates its prior
  result and any paired status, and each transient read requires a successful
  retry of that same read before a fresh result can pass.
- Present history or a running/completed turn wins over the local draft; the
  client renders that correlated server result and does not resend.
- Absent history plus idle server status keeps the original draft and waits for
  an explicit user decision. Only that decision may create one new send, and a
  later uncertain send must start a new history read.
- A confirmed request rejection preserves the draft and permits one later
  explicit retry. It does not authorize automatic resend.
- A second uncertain send never receives an automatic third send.
- `delivery_uncertain` always retains a present original draft. Keeping that
  draft before restore leaves the state uncertain with a pending barrier; the
  user can then restore, collect fresh absent-and-idle evidence, and continue
  through one explicit resend.
- `session.resume`, `session.history`, `session.status`, and `model.options`
  are the only automatic retry methods in this fixture. Every automatic history,
  status, or model-options retry requires a selected session, ready transport,
  observed `gateway.ready`, and matching compatibility evidence; history and
  status retries also require `restoring`. Prompt submission, session creation,
  and interruption are never automatically retried.
- Duplicate send while `submitting` or `streaming` is locally blocked and does
  not increase the outward submission count.
- Every server event carries request, turn, and session markers and is accepted
  only in an active compatible state on a ready transport. Empty, failed,
  terminal, stale, or uncorrelated events fail closed.
- An uncertain interrupt remains unconfirmed until restored server status
  proves its result. Sign-out clears every armed retry, request, and restore
  reference, latches the client offline, preserves the local draft, and rejects
  all stale events until a new authenticated session starts.
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
or transcript fields, ordinary prompt prose, bare `sk-proj-*` keys, URLs,
relative and absolute paths, `C:/Users/...` and other Windows paths, IPv4 and
IPv6 hosts, cookie and authorization material, JWT/API-key-like values, and
base64-like payloads. CLI failures are one fixed JSON line on standard error,
capped at 240 characters. They do not echo paths, flags, keys, values, parser
details, or tracebacks. Regular-file stat bounds run before every JSON or
artifact read, so oversized files and special paths fail without an unbounded
read or FIFO/device block.

The checked-in case, baseline, executing-source, README, regression tests,
chat-contract, and artifact files are bound to repository-owned canonical paths
and hard-coded digests. The authoritative trust input is the externally
supplied `HERMTERNAL_C06_EXPECTED_COMMIT`; it is checked as an exact commit
object and its canonical tree bytes are compared with the checkout. This is
independent of branch parent shape, so a normal post-merge `dev`/`main` clone
and a later unchanged commit can validate when the same reviewed expectation is
supplied. An absent expectation, altered canonical bytes, force-retagged audit
tag, missing tags, shallow history, tarball, or partial clone fails closed.

Fresh-clone procedure (the expected commit is supplied by protected review/CI,
not discovered from a mutable branch):

```text
git clone <repository-url> <checkout>
cd <checkout>
git fetch --tags --unshallow 2>/dev/null || git fetch --tags
HERMTERNAL_C06_EXPECTED_COMMIT=<reviewed-commit> python3 -I contracts/fixtures/uncertain-delivery/validate.py
HERMTERNAL_C06_EXPECTED_COMMIT=<reviewed-commit> python3 -I -O contracts/fixtures/uncertain-delivery/validate.py
git cat-file -t refs/tags/hermternal-c06-uncertain-delivery-final-anchor
git rev-parse --verify refs/tags/hermternal-c06-uncertain-delivery-final-anchor^{commit}
```

The audit tag is an annotated, non-release consistency marker. It must be
protected from force updates by the repository owner and remain equal to the
reviewed external expectation. A superseding reviewed correction publishes a
new commit and a new non-release audit tag, updates the protected review/CI
expected-commit record and this documentation in the same reviewed change, and
retires the old marker only after consumers have migrated; existing markers are
never silently moved. Tags are not signatures and do not replace the external
expected-object control. The validator also freezes state meanings, terminal
flags, action order, case order, and baseline key/type/order rules. Copying or
coordinately rebinding a mutated case, baseline, source, README, tests, or chat
contract therefore fails closed instead of replacing reviewed evidence.

## Reproduce the proof

Run from the repository root:

```text
export HERMTERNAL_C06_EXPECTED_COMMIT=<reviewed-commit>
python3 -I contracts/fixtures/uncertain-delivery/validate.py
python3 -I -O contracts/fixtures/uncertain-delivery/validate.py
python3 -I -B -m unittest discover -s contracts/fixtures/uncertain-delivery -p 'test_*.py'
python3 -I -B -O -m unittest discover -s contracts/fixtures/uncertain-delivery -p 'test_*.py'
PYTHONPYCACHEPREFIX=/tmp/hermternal-c06-pycache python3 -I -B -m py_compile contracts/fixtures/uncertain-delivery/validate.py contracts/fixtures/uncertain-delivery/test_validate.py
```

The focused tests execute the real validator CLI in both normal and optimized
modes. They cover accepted/present, absent-and-idle, confirmed rejection,
timeout, WebSocket close, app suspension, process loss, restore, explicit
resend, duplicate prevention, interruption, cancellation, sign-out, pending
proof, compatibility failure, unknown interactive events, strict JSON, bounded
redaction, canonical artifact rebinding, forged benchmark evidence, gateway,
transport, draft, initial-state, state-identity, and event-correlation, isolated-import, and unexpected-sibling-module mutations.
Oversized files, long keys, directories, and FIFOs fail through the same
bounded error path without opening unbounded or special-file streams.

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
