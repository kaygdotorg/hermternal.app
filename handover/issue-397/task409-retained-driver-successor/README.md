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
- The driver keeps the repository and clean-primary after success.
- The driver changes the old cleanup functions to fail-closed stubs.
- The driver converts the retained repository to a self-contained object store
  before it creates the output directory.
- The driver repeats strict closure and ancestry checks without an alternate.
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

## Self-contained retained repository

The derived driver builds a closed, sorted commit-root inventory from the
authenticated candidate JSON. It requires the fixed base, protected main,
every source commit, both rejected-authentication endpoints, and every
forbidden ancestry commit. The driver also receives the exact final head,
proves that it is the repository head, and adds it to the sorted roots. It
enumerates the complete object closure for all of these roots.

It then runs exact `git pack-objects` without `--thin` and without `--local`.
The object IDs are supplied on stdin. Git output is captured, bounded, and not
written to driver stdout. The output must be one exact lowercase pack hash.
The previously empty pack directory must then contain only the matching `.pack`
and `.idx` files. Both files must be owned, single-link files with exact mode
`0400` or `0600`; group, other, and executable bits are forbidden. The driver
hashes and binds both files through stable descriptor reads.

Only after the pack is complete, the driver opens the exact private
`repository/.git/objects/info/alternates` file through a held parent directory.
It requires one link, mode `0600`, stable identity, and exact
`CLEAN_PRIMARY_OBJECTS` plus LF bytes. It unlinks only that bound name, syncs
the parent directory, and proves that the path is absent.

With no alternate present, it runs strict `git fsck`, all-ref missing-object
closure, and exact commit-type checks for every proof root. It stable-rereads
the pack and index. The shell then repeats forbidden-ancestry and full replay
closure checks. Its inherited object-binding check uses an explicit lifecycle
state: bootstrap requires the exact alternate, and the post-conversion state
requires no alternate and the exact private self-contained pack pair. It proves
again that the alternates path is absent before it creates pending evidence.
The retained clean-primary remains available for diagnosis, but it is not an
object dependency of the retained repository.

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

The tests execute only isolated file helpers and the pending writer in private
temporary directories. They supply observed object IDs and do not execute the
shell or Git. They verify create-only pending output, proof-root completeness,
non-thin and non-local packing, pack and index mutation, alternates content,
hardlink and swap rejection, exact unlink and parent sync, unlink-sync failure,
pre-existing pack collision, final-head root inclusion and omission, private
pack modes, post-conversion success reachability, post-unlink proof ordering,
output capture, the sole marker, anchor drift, argv, and the
derived-versus-source hash boundary.

Run the offline checks with:

```sh
python3 -B handover/issue-397/task409-retained-driver-successor/test_retained_driver_successor.py
python3 -O -B handover/issue-397/task409-retained-driver-successor/test_retained_driver_successor.py
python3 -B handover/issue-397/task409-retained-driver-successor/retained_driver_successor.py
/bin/bash -n /absolute/path/to/create-only-derived-driver.sh
```

The third command prints only a derivation summary. `--output PATH` creates a
private derived shell at a new path and rejects an existing path. The Bash
command is a syntax check only. Do not execute the output before independent
review and the complete #404/#405 gate.

This checkpoint is not replay evidence. It is not Phase A approval, Phase B
approval, a live Hermes result, or permission to update `dev` or `main`.
