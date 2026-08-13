# Candidate-five retained-driver successor

This directory contains an offline derivation tool. The tool does not run the
candidate shell, Git, replay, a network command, or Hermes.

The tool reads the exact durable five-file #403 authority at:

```text
/home/kayg/Developer/hermternal/handover/issue-397/task464-candidate5-final
```

It checks the exact descriptor, provenance, JSON, Markdown, and shell hashes.
It also verified-loads the approved #401 authority, #403 orchestrator, #403
final-freeze coordinator, framing successor, and frozen generator bytes. It
executes code only from bytes that it read and checked.

The transform uses exact anchors and exact occurrence counts. It keeps the
replay transaction and lane order unchanged. It changes only the successful
lifecycle and its pending-output boundary:

- The replay repository name changes from `replay` to `repository`.
- The driver keeps the repository and clean-primary after success. The retained
  repository needs the clean-primary object alternate for later review.
- The driver changes the old cleanup functions to fail-closed stubs.
- The driver completes all internal Git and closure observations before it
  creates the output directory.
- The last fallible driver action creates and syncs only
  `replay-result.pending.json`.
- The only later shell action is the built-in
  `printf 'TASK409_RETAINED_REPLAY_OK=1\n'`.

The pending layout is:

```text
/private/tmp/hermternal-task409-final-replay.<pid>/  0700
  repository/                                      0700
  replay-root/                                     0700
    replay-result.pending.json                     0600, create-only
```

The pending file has the closed
`hermternal.issue-397.replay-result.pending/v1` schema. It contains observed
repository paths and identities, detached head, parent, tree, and frozen
ancestry policy. It does not claim process success, replay completion, Phase A
approval, stdout delivery, or stderr state. The derived driver never creates
`replay-result.json` or `replay-completion.json`.

`derive_contract()` supplies the trusted outer wrapper with the exact
authenticated argv, exact derived stdin bytes, frozen source SHA-256, and
derived stdin SHA-256. The derived hash must differ from the frozen source
hash because the reviewed transform changes the shell bytes.

The trusted corrected #405 outer wrapper owns process evidence. It must capture
the actual argv, exact stdin bytes and hash, stdout bytes and hash, stderr bytes
and hash, and exit code. It may create final result and completion files only
after all of these checks pass:

- Exit code is zero.
- Stdout is exactly `TASK409_RETAINED_REPLAY_OK=1\n`.
- Stderr meets the corrected #405 contract.
- Fresh Git and filesystem observations match the pending file.
- The pending file and all bound inputs pass stable reread.

The wrapper must publish final files atomically and create-only, then sync and
stably reread them. A nonzero exit, missing marker, extra stdout, late output
failure, or validation mismatch must not produce final completion evidence.
The wrapper must report any pending residue.

The tests execute only the isolated Python pending writer in a temporary
directory. They supply observed object IDs and do not execute the shell or Git.
They verify create-only output, the closed pending schema, retained repository
state, a late sync failure with pending residue, anchor drift, argv, and the
derived-versus-source hash boundary.

Run the offline checks with:

```sh
python3 -B handover/issue-397/task409-retained-driver-successor/test_retained_driver_successor.py
python3 -O -B handover/issue-397/task409-retained-driver-successor/test_retained_driver_successor.py
python3 -B handover/issue-397/task409-retained-driver-successor/retained_driver_successor.py
```

The last command prints only a derivation summary. `--output PATH` creates a
private derived shell at a new path and rejects an existing path. Do not
execute that output before independent review and the complete #404/#405 gate.

This checkpoint is not replay evidence. It is not Phase A approval, Phase B
approval, a live Hermes result, or permission to update `dev` or `main`.
