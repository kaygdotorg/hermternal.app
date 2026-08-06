# C-16 deep-link resolution fixtures

This directory contains the deterministic proof for GitHub issue #66. The
proof is synthetic and offline. It does not contact Hermes, a Dashboard, DNS, a
browser, an Apple service, or another network service.

The proof consumes exact checked-in deep-link grammar and session-lineage
artifacts. It does not change them.

## Resolver order

The resolver uses this order:

1. Parse the private `https` or `hermternal` link.
2. Set an explicit 300-second in-memory deadline.
3. Confirm authentication.
4. Look up the exact full session ID.
5. Derive one latest descendant from explicit bounded sequence evidence when
   requested.
6. Open the exact resolved session.
7. Focus the exact message when it exists.
8. Open the session with `message_not_found` when the message is absent.
9. Erase the pending link, session ID, message ID, and deadline.

The resolver does not normalize, shorten, decode, or case-fold an ID. Unknown
and denied sessions return the same `session_not_found` result.

## Latest-descendant evidence

A latest-descendant trace contains an explicit bounded lineage list. Each node
has an exact session ID, root ID, parent ID, and integer sequence. The reducer
walks parent links iteratively. Every child sequence must be greater than its
parent sequence. It selects the one strict descendant with the highest sequence.
It never selects the requested root when descendants exist.

The proof includes canonical sibling, tie, non-integer, decreasing, cycle,
missing-parent, wrong-root, and duplicate-node cases. Each malformed case returns
`lineage_unavailable`. The reducer does not use a hard-coded descendant ID.

The pinned session-lineage fixture confirms every supplied node and parent edge.
The valid branching case uses the reviewed root, branch, and closed-branch IDs.
A parentless or self-rooted known branch and any fabricated descendant fail
closed. Resolver sequence evidence adds only deterministic synthetic ordering.
It does not claim a live Hermes ordering field.

## Pending target and reload

The receive time plus 300 seconds is the exact deadline. A receive time must
leave room for that addition within the bounded integer range. An overflowing
receive time fails with the fixed controlled error. Every pending action
requires a time before the deadline. At exact second 300, authentication,
lookup, message handling, completion, interruption, recovery, cancellation, and
logout expire the target before acting. One trace proves that the target remains
pending one second before the deadline.

Success, failure, cancellation, expiry, and logout erase the raw input link and
all pending target IDs. The focused result records the exact message ID. Reload
does not reuse erased target data. Reload first erases the prior opened session,
root, parent, focused message, and focus state. Its reload event then supplies a
fresh synthetic input and repeats grammar parsing, authentication confirmation,
and exact lookup. The cases cover success followed by success and success
followed by failure.

An interrupted lookup can recover only before its deadline. Recovery confirms
authentication again before an idempotent lookup retry.

## Hard boundaries

Every trace keeps these values:

- `session_creations: 0`
- `shares: 0`
- `transcript_mirror: false`
- `network: false`

The proof does not create a session, define sharing, or store a transcript
mirror. Hermes remains the future source of truth for session and message data.

## Strict immutable input handling

All fixture and evidence data is inert JSON. The loader rejects duplicate keys,
non-finite numbers, overflow, wrong exact types, oversized strings or
containers, excessive nodes, and excessive depth. The JSON walk is iterative.

Every artifact is opened once. The validator rejects symlinks and special files
before a blocking open. It reads regular files in bounded 64 KiB chunks. It
enforces the one MiB limit before full allocation. It hashes and parses the same
immutable bytes. It rejects inode replacement, size changes, and modification-
time changes during a read.

`review-root.json` binds the cases, tests, exact validator source, raw evidence,
baseline, documentation, and exact dependency bytes. Its durable digest anchor
is `contracts/fixtures/review-anchors/deep-link-resolution.sha256`, outside this
mutable local proof set. Coordinated replacement of the local artifacts, review
root, a local digest copy, and source constants still fails against that anchor.
Shared aggregate registration remains serialized behind PR #265.

Argument parsing is inside the controlled failure boundary. Unknown arguments,
including arguments that contain raw links or IDs, emit one fixed line on
standard output and no standard error:

```json
{"error":{"code":"contract","message":"deep-link resolution fixture rejected"}}
```

## Performance evidence

`baseline-evidence.json` contains 30 raw normal samples and 30 raw `-O`
samples. The validator uses the repository-approved inclusive linear
interpolation R-7 method. The threshold is `null`; no budget is invented.

```text
normal: min=147.280459 p50=242.687813 p95=559.644058 max=673.528459 mean=299.641703
-O:     min=92.498334 p50=151.238583 p95=222.135383 max=236.905208 mean=155.370844
```

The recorded environment is CPython 3.14.6 on macOS 26.5.2 arm64. Build mode
is N/A.

## Validation

```sh
python3 contracts/fixtures/deep-link-resolution/validate.py
python3 -O contracts/fixtures/deep-link-resolution/validate.py
python3 -m unittest discover -s contracts/fixtures/deep-link-resolution -p 'test_*.py'
python3 -O -m unittest discover -s contracts/fixtures/deep-link-resolution -p 'test_*.py'
python3 -m py_compile contracts/fixtures/deep-link-resolution/validate.py contracts/fixtures/deep-link-resolution/test_validate.py
```

Accessibility checks are N/A because this fixture has no UI. It does not change
focus, semantics, touch targets, VoiceOver, Dynamic Type, zoom, contrast,
motion, transparency, or Switch Control.
