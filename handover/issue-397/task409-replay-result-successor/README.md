# Retained replay-result lifecycle successor

This successor is an offline-tested authority gate. It verified-loads the exact
integrated #403 final-freeze and orchestration bytes, #401 candidate authority,
and #400 Git reviewer. It accepts only the fixed durable final root. Its tests
also create an actual disposable #403 prepare output. They do not run replay,
mutate Git, use a network, use credentials, use Hermes, or clean up data.

The current Phase B result schema is closed. Therefore `replay-result.json`
contains only `task409-execution-preflight/replay-result/v2` fields. The bound
`replay-completion.json` contains the driver, final-triad, provenance, source
commit, argv, stdin, and output hashes that the closed Phase B schema cannot
yet contain.

The wrapper creates one fresh canonical mode-0700 run parent and these exact
private sibling roots. A prior parent or either prior root is rejected.

```text
run-parent/                 0700
  replay-root/              0700
    replay-result.json      0600, one link, create only
    replay-completion.json  0600, one link, create only
  repository/               0700
```

The repository cannot be inside replay-root because genuine Phase B rejects
that overlap. The driver must retain both roots after success. Cleanup is a
separate future command; this successor rejects it even when requested and
cannot delete a branch, stash, worktree, or any replay data.

The gate derives the exact argv and stdin from genuine #401 validation. It reads
base, base-tree, protected-main, source, and forbidden ancestry only from the
authenticated candidate JSON. The real #403 provenance schema binds only its
actual `output_root` and output records; no invented repository-boundary fields
are accepted.

The retained replay driver remains unavailable. This is intentional: the
approved candidate driver still deletes its replay output and cannot produce the
required retained Phase-B result. Therefore the gate always blocks execution;
it cannot delete a branch, stash, worktree, or replay data.

Run the focused test with normal and optimized Python. This is not final-freeze
approval, replay evidence, or Phase B approval.
