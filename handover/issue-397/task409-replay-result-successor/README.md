# Retained replay-result lifecycle successor

This speculative successor defines the required driver patch. It does not run a
driver, Git, replay, network operation, Hermes, or cleanup.

The current Phase B result schema is closed. Therefore `replay-result.json`
contains only `task409-execution-preflight/replay-result/v2` fields. The bound
`replay-completion.json` contains the driver, final-triad, provenance, source
commit, argv, stdin, and output hashes that the closed Phase B schema cannot
yet contain.

The final approved driver must create these retained, sibling private roots
below one fresh canonical mode-0700 run parent:

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

`publish_retained_result` creates only private files, fsyncs the file and
parent, then stable-rereads each file three times. It takes the process observer
instead of caller-supplied command evidence, so output hashes are derived from
the one observed call. `verify_publication` binds
the result and completion records to their exact names, bytes, identities, and
directory identities. The only test double is the process observer passed to
`invoke_driver`; no real subprocess is owned by this module.

Run the focused test with normal and optimized Python. This is not final-driver
generation, final-freeze approval, replay evidence, or Phase B approval.
