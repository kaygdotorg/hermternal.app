# Retained replay-result lifecycle successor

This successor is an offline-tested driver wrapper. Its tests mock only the
single process boundary and the read-only repository observation. They do not
run a replay, mutate Git, use a network, use credentials, use Hermes, or clean
up data.

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

`publish_retained_result` stable-reads the closed #403 authority descriptor,
provenance manifest, and triad three times. It derives the driver argv, stdin,
artifact hashes, provenance hash, source commit, base, tree, and protected-main
pins from these verified bytes. It then runs only that argv and stdin with an
empty inherited environment. A successful process must emit the closed marker.
The trusted repository reviewer derives the detached final head, its one parent,
tree, device, inode, mode, and owner. The wrapper creates only private 0600
files, fsyncs each file and parent, and stable-rereads all retained evidence.

`verify_publication` re-reads the complete authority and the repository. It
rejects authority substitutions, path swaps, artifact changes, and semantic
repository changes. Callers cannot provide replay facts or completion hashes.
Cleanup remains disabled and has no implementation, so it cannot delete a
branch, stash, worktree, or replay data.

Run the focused test with normal and optimized Python. This is not final-freeze
approval, replay evidence, or Phase B approval.
