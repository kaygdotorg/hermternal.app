# Candidate-five retained-driver successor

This directory contains an offline derivation tool. The tool does not run the
candidate shell. It does not run Git, replay, a network command, or Hermes.

The tool reads the exact durable five-file #403 authority at this fixed root:

```text
/home/kayg/Developer/hermternal/handover/issue-397/task464-candidate5-final
```

It checks the exact descriptor, provenance, JSON, Markdown, and shell hashes.
It also verified-loads the approved #401 authority, #403 orchestrator, #403
final-freeze coordinator, framing successor, and frozen generator bytes. It
executes code only from the bytes that it read and checked. It does not reopen
a module path after the byte check.

The transform uses exact text anchors and exact occurrence counts. It keeps the
replay transaction and lane order unchanged. It changes only the successful
lifecycle and output boundary:

- The replay repository name changes from `replay` to `repository`.
- The driver keeps the repository after success.
- The driver keeps clean-primary because the repository object alternate needs
  it for later read-only review.
- The driver creates `replay-root` as a sibling of `repository` only after all
  Phase A and approval-anchor data passes.
- The driver creates `replay-result.json` and `replay-completion.json` once.
- The driver changes both old success-cleanup functions to fail-closed stubs.
- The driver sends successful Git commit summaries to `/dev/null`. This makes
  the full successful stdout record deterministic for completion evidence.

The retained layout is:

```text
/private/tmp/hermternal-task409-final-replay.<pid>/  0700
  repository/                                      0700
  replay-root/                                     0700
    replay-result.json                             0600, one link
    replay-completion.json                         0600, one link
```

`replay-result.json` has the exact closed
`task409-execution-preflight/replay-result/v2` schema. It uses lane
`candidate-4` because that is the current genuine Phase B contract. It binds
the fixed base, base tree, protected main commit, required ancestry, forbidden
ancestry, retained paths, directory identities, detached final head, one
parent, and final tree.

`replay-completion.json` has the closed
`hermternal.issue-397.replay-completion.v1` schema. It binds the result bytes
and inode, frozen driver source, final triad, provenance, source commit,
authenticated argv and stdin, and the exact final success record. Phase A
digests stay in the exact v2 result. The stdout hash is the hash of that final
success record plus the preceding final-head record. Successful commit
summaries are not part of stdout. Stderr must be empty on success.

The driver does not accept extra environment values. The #401 `/usr/bin/env
-i` argv stays unchanged. These two Phase A paths are fixed:

```text
/private/tmp/hermternal-task409-phase-a/input-manifest.json
/private/tmp/hermternal-task409-phase-a-approval/phase-a-approval-anchor.json
```

The tests execute only the isolated Python evidence writer in a temporary
directory. They supply mock final-head, parent, and tree observations. They do
not execute the shell or a Git command. They verify create-only output, exact
schemas, stable file modes, retained repository state, anchored-transform
failure, and fail-closed Phase A rejection.

Run the offline checks with:

```sh
python3 -B handover/issue-397/task409-retained-driver-successor/test_retained_driver_successor.py
python3 -O -B handover/issue-397/task409-retained-driver-successor/test_retained_driver_successor.py
python3 -B handover/issue-397/task409-retained-driver-successor/retained_driver_successor.py
```

The last command prints only a derivation summary. `--output PATH` can create a
private derived shell at a new path. It rejects an existing output path. Do not
execute that output before independent review and the complete #404/#405 gate.

This checkpoint is not replay evidence. It is not Phase A approval, Phase B
approval, a live Hermes result, or permission to update `dev` or `main`.
