# Phase A and external anchor successor

This checkpoint adds the missing genuine Phase A and create-only external
anchor runner for issues #397 and #404. It does not run Phase B or replay. It
does not execute the candidate shell. It does not use a network, credentials,
sockets, or Hermes.

## Frozen authority

The runner binds frozen commit
`28553997d43fd20291513c8524871e31b0ba8181` and tree
`0ce8703a6d278c8a8e630950a01d9b319b6288fa`. It checks the exact SHA-256
and Git blob ID for these sources:

- the durable Phase A validator;
- the genuine anchor provisioner;
- the durable Phase B module and its reviewer;
- the approved #399 lifecycle successor;
- the approved #400 Git hardening successor;
- the approved #403 final-set inspector;
- the approved #401 authority module.

The loader compiles only the stable-read, verified source bytes. It also routes
legacy imports to the verified byte buffers. It installs the approved #400
reviewer in the approved #399 Phase B module, but it does not call Phase B or
Git review.

The final authority root stays fixed at
`/home/kayg/Developer/hermternal/handover/issue-397/task464-candidate5-final`.
The runner stable-reads the exact five-file final set. It checks the approved
descriptor and provenance SHA-256 values and calls the genuine #403
`inspect_complete` function. The approved #401 module then checks the exact
JSON, Markdown, shell, normalized identity, argv, and stdin authority.

## Durable external layout

The external root is fixed at
`/home/kayg/Developer/hermternal-issue397-phase-a-anchor`. It must not exist
before the real Phase A command. Its parent must be canonical, owned by the
current user, and not group or world writable.

The Phase A command creates only this layout:

```text
/home/kayg/Developer/hermternal-issue397-phase-a-anchor/  0700
  phase-a/                                                0700
    .owner                                                0600
    input-manifest.json                                   0600
  external-review/                                        0700
  evidence/                                               0700
    phase-a.json                                          0600
```

The anchor command creates only these additional files:

```text
  external-review/phase-a-approval-anchor.json            0600
  evidence/anchor.json                                    0600
```

All files are create-only, single-link regular files. The runner fsyncs each
file and parent directory and then does three stable no-follow rereads. A
runner evidence write failure removes only the exact runner-owned inode. It
reports foreign or moved residue and does not claim a clean rollback.

## Stage contract

Run Phase A only from a clean checkout at the recorded repository root:

```sh
/usr/bin/python3 -B handover/issue-397/task409-phase-a-anchor-successor/phase_a_anchor_runner.py phase-a
```

The runner builds the manifest from genuine stable reads. It calls the genuine
durable `validate_artifacts` function exactly once before it creates the
external root. It then writes one closed Phase A evidence record. The record
contains actual file and directory identities, byte counts, LF counts,
terminal bytes, SHA-256 values, the Phase A approval digest, the approved
policy digest, and explicit not-run safety values.

The closed schema requires exact canonical paths and scalar types. Identity
records include device, inode, user, group, mode, size, link count, mtime, and
ctime. The Phase A prior digest is the exact all-zero SHA-256 sentinel.

An independent reviewer must check the Phase A result before the anchor stage.
The runner does not make or infer this independent decision.

After that review, run the create-only anchor stage:

```sh
/usr/bin/python3 -B handover/issue-397/task409-phase-a-anchor-successor/phase_a_anchor_runner.py anchor \
  --expected-phase-a-sha256 <INDEPENDENTLY_REVIEWED_PHASE_A_EVIDENCE_SHA256>
```

The anchor stage stable-rereads the Phase A record, manifest, and final
authority. The supplied Phase A evidence digest is a required handoff from the
independent review. The runner rejects a missing, malformed, or different
digest before it trusts the record. It compares every recorded authority,
root, parent, owner-marker, manifest, and digest observation with a fresh
stable read. It recomputes the manifest, approval, and policy digests. It calls
the genuine anchor provisioner exactly once and proves that the provisioner
calls its genuine Phase A validator exactly once. It then writes the closed
anchor evidence record. Both `prior_sha256` and
`inputs.expected_phase_a_sha256` bind the reviewed Phase A record SHA-256.

A collision, changed record, changed manifest, changed final file, changed
parent identity, extra validator call, or existing target causes a rejection.
The runner does not repair, replace, adopt, or delete durable evidence.

## Tests

The tests use disposable, test-owned sibling roots. They redirect only the
external output constant. They do not redirect the final authority and do not
use fixture results. Wrappers count genuine function calls and return the
genuine results.

Run:

```sh
python3 -B handover/issue-397/task409-phase-a-anchor-successor/test_phase_a_anchor_runner.py
python3 -O -B handover/issue-397/task409-phase-a-anchor-successor/test_phase_a_anchor_runner.py
```

This checkpoint is create-capable but has not run against the durable external
root. Its existence is not Phase A approval, anchor approval, replay evidence,
or live Hermes approval.
