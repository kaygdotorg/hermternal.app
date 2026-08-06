# C-07B session-lineage fixture

This directory contains the deterministic, offline proof for issue #57 C-07B.
It defines how a synthetic root session, a branch session, and a resumed
session retain identity and lineage without copying a conversation locally.

The fixture is contract evidence, not a Hermes integration test. It does not
open a network connection, run a gateway, read a database, send a prompt, or
claim that Hermes supports a parent/fork request field.

## Scope

The fixture covers:

- one complete opaque `session_id` for every created session;
- a stable `root_id` and an explicit `parent_id` for a branch;
- root creation without a parent;
- branch creation from an open or closed durable parent;
- duplicate creation suppression by an idempotency key;
- exact resume of an existing session;
- the difference between resume and an explicit new root;
- missing, malformed, foreign, self-referential, and cyclic parent rejection;
- deleted-parent rejection while retaining closed-parent addressability;
- interrupted and unknown creation or resume results;
- reconciliation before retry after delivery uncertainty;
- compatibility failure with no new-session fallback; and
- the invariant that no transcript mirror is stored in this fixture.

All identifiers and events are synthetic markers. No fixture value is a live
session reference, credential, host, prompt, transcript, ticket, or user data.

## Source boundary

The source observation set is pinned to Hermes revision
`f5be9236e00ddf2f2a412697f267078fc4ee068e` and the Hermternal contract
`dashboard-v0.0.1`. The observations in `cases.json` are deliberately narrow:

- `session.create` establishes the live session identity. An empty create is
  not durable until the first persistence boundary.
- `session.resume` reopens an addressable stored identity. A missing identity
  is an error, not permission to create a replacement.
- Reopening a stored session clears ended markers for that same identity.
- Session-row creation is idempotent for a repeated stored identity.
- Transport loss detaches a session for bounded recovery. It does not prove
  that the server session was deleted.
- Parse and dispatch failures are explicit errors, not successful method
  results.

The pinned Dashboard source does not define an approved general-purpose
parent/fork wire schema. Therefore this fixture models lineage metadata as a
reviewed synthetic contract boundary and fails closed when evidence is absent,
foreign, malformed, unsupported, cyclic, self-referential, or incompatible.

## Contract rules

### Identity

- IDs are opaque, exact, ASCII, single-segment values.
- A full ID is required. Prefixes, ellipses, Unicode lookalikes, URL escapes,
  path separators, and ticket-bearing values are not accepted.
- A root has `root_id == session_id` and `parent_id == null`.
- A branch has a new `session_id`, the inherited `root_id`, and the exact
  durable parent in `parent_id`.
- A new transport is not a new server session.

### Creation and duplication

Creation is explicit. Root creation has no parent. Branch creation requires a
complete durable parent that is open or closed, and the requested child must
not already occur in its ancestor list. A repeated create with the same
idempotency key and complete identity is suppressed. It does not create a
second child or rewrite the parent link.

Creation is lazy with respect to durable persistence: an accepted identity is
not treated as durable until the synthetic `session.lineage.persisted` event.
This mirrors the Dashboard contract's empty-session boundary without storing
any transcript content.

### Resume and new session

Resume addresses the exact existing `session_id` and returns the same root,
parent, and lineage kind. A missing or deleted identity fails without a new
session fallback. A new root is permitted only after an explicit user choice;
it never inherits a parent from the failed resume.

### Failure and compatibility

Interrupted operations enter a safe state. An interrupted create may use only
the same idempotency key for retry. An unknown create result enters delivery
uncertainty and must be reconciled before any retry. A present reconciliation
reuses the original identity; a missing reconciliation remains failed until an
explicit user decision.

Unknown events, malformed evidence, foreign identities, invalid parent
references, self-parenting, cycles, deleted parents, and compatibility failure
all stop the operation. No failure path silently converts resume into create.

### History ownership

Hermternal stores only lineage and lightweight UI state in this fixture. The
server remains the source of truth for session history. The fixture contains
no prompt text, message body, tool output, transcript mirror, or local history
reconstruction.

## Files

- `cases.json` contains the closed schema, source observations, state and
  invariant tables, redaction policy, and 32 exact semantic traces.
- `validate.py` is the standard-library-only validator and reducer.
- `test_validate.py` exercises the checked-in contract, both CLI modes, strict
  JSON handling, redaction, identity binding, and semantic failure paths.
- `baseline-evidence.json` contains 30 measured normal and 30 measured `-O`
  samples with derived distributions.
- `validation-baseline.json` binds the evidence and fixture artifact digests.

The baseline `threshold` is intentionally `null`. The repository has no
approved performance budget for this fixture, so the samples are reproducible
measurement evidence rather than a pass/fail claim.

## Validation

Run the real validator in both supported interpreter modes:

```text
python3 contracts/fixtures/session-lineage/validate.py
python3 -O contracts/fixtures/session-lineage/validate.py
```

Run the focused regression suite:

```text
python3 -m unittest discover -s contracts/fixtures/session-lineage -p 'test_*.py'
```

The validator emits one stable success line. Any failure emits one redacted
JSON error and never includes a raw path, payload, identifier, or sensitive
marker.
