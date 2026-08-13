# Retained replay outer-wrapper successor

This checkpoint adds the corrected outer wrapper for issues #397 and #405. It
does not run replay. It does not change Git, use a network, use credentials,
start Hermes, or clean retained evidence.

## Verified authority

The wrapper verifies and loads these exact sources before it can call a process:

- the retained pending-driver successor, SHA-256
  `3e3dc1444879b416fa7e8e884a3523566ba9f4a9a96f2857380d8c4869917e20`;
- the corrected #404 Phase A and anchor runner, SHA-256
  `fb11d84062c05a2054a2f4162908de54ed15a530538fbf671ee54ff999baaf84`;
- the approved #400 Git authority, SHA-256
  `b2b5a5f1e0ed813325a23cb32eb075b2637872f5c5176e81c79879af4ab1861a`.

The retained driver verifies the final #403 five-file authority and generator
chain. It derives the exact invocation array and changed stdin bytes from that
authority. The wrapper requires the approved self-contained derived stdin
SHA-256
`ea10248929964a5570623de3ecd653cd3ba7348d3df565491a94816872647e2d`.
It also checks that this hash is different from the frozen source-shell hash.
It does not accept caller-supplied argv, stdin, or environment values.

## Process contract

The wrapper has one injectable process boundary. The production boundary uses
the exact derived argv and stdin, an empty inherited environment, `/` as its
working directory, and byte pipes for stdin, stdout, and stderr. The derived
argv starts `/usr/bin/env -i`, so the child gets only the environment that the
approved shell creates. The wrapper drains stdout and stderr incrementally and
stops the child as soon as either stream exceeds its fixed byte limit. It never
uses an unbounded `communicate()` capture.

Success requires all of these exact observations:

- return code `0`;
- stdout exactly `TASK409_RETAINED_REPLAY_OK=1\n`;
- stderr empty;
- a stable, private `replay-result.pending.json` at the PID-derived retained
  replay root;
- pending paths, identities, Git object IDs, and ancestry policy equal to the
  authenticated authority;
- fresh read-only repository observations through the pinned #400 reviewer;
- stable rereads of pending, Phase A evidence, and authority before final
  publication.

A rejection reports `PENDING_RESIDUE` when the pending file exists. It never
uses process output as Git evidence.

## Phase A input

The command requires the exact durable #404 v2 anchor evidence path and its
independently reviewed SHA-256:

```sh
python3 -B handover/issue-397/task409-replay-result-successor/replay_result_successor.py \
  --phase-a-evidence /home/kayg/Developer/hermternal-issue397-phase-a-anchor-v2/evidence/anchor.json \
  --expected-phase-a-evidence-sha256 <INDEPENDENTLY_REVIEWED_SHA256>
```

The verified #404 runner requires schema
`hermternal.issue-397.phase-a-anchor-evidence.v2`, stable-reads the exact path,
and parses the closed anchor record. The wrapper extracts
`phase_a_manifest_sha256` and `phase_a_approval_digest` from the verified
record. It does not accept these two values directly from the caller.

Before the process and after both final files exist, the wrapper uses the
genuine v2 validators to stable-read `phase-a.json`, `anchor.json`,
`input-manifest.json`, `phase-a-approval-anchor.json`, and `.owner`. It also
binds the v2 root and its three runtime directories. Cross-module snapshots are
converted to closed primitive path, hash, byte-count, identity, and directory
records. The wrapper never compares dataclass instances from separate verified
module loads.

## Final publication

Only a successful complete validation can create:

```text
run-parent/                 0700
  replay-root/              0700
    replay-result.pending.json  0600, retained driver output
    replay-result.json          0600, create-only replay-result/v2
    replay-completion.json      0600, create-only replay-completion/v2
  repository/               0700
```

The completion record binds the actual return code, stderr policy, argv count,
argv byte count, stdin byte count, stdout byte count, stderr byte count, and
their SHA-256 values. It also binds the pending file, final result, driver
module, frozen driver source, final triad, provenance, source commit, and Phase
A evidence.

Both final files use `O_EXCL`, file `fsync`, directory `fsync`, and three stable
no-follow rereads. Publication is one transaction. It records each owned device
and inode immediately after creation. Any write, sync, stable-read, schema
verification, or final live-input verification failure reconciles both final
names. It removes only exact files owned by that transaction, preserves a
foreign replacement, and reports residue. It does not remove pending evidence
or the retained repository. A pre-existing final file is never changed.

## Self-contained repository review

The approved retained driver makes the repository self-contained before it
publishes pending evidence. It creates a complete non-thin local pack for the
approved roots and the observed final head. It then removes and syncs the exact
bound alternate:

```text
repository/.git/objects/info/alternates
```

The wrapper does not weaken #400. Its two fresh #400 inspections require the
alternate to be absent and require the self-contained repository metadata,
object closure, clean state, detached head, ancestry, and exact Git facts to
pass the approved checks before final publication.

## Offline checks

Run:

```sh
python3 -m py_compile \
  handover/issue-397/task409-replay-result-successor/replay_result_successor.py \
  handover/issue-397/task409-replay-result-successor/test_replay_result_successor.py
python3 -B handover/issue-397/task409-replay-result-successor/test_replay_result_successor.py
python3 -O -B handover/issue-397/task409-replay-result-successor/test_replay_result_successor.py
```

The tests inject the replay process boundary and do not run the derived shell.
They use the genuine #404 v2 Phase A and anchor functions in a disposable root,
and they test a successful approved #400 observation contract without running
Git. They cover exact argv, stdin, and environment; pinned derived stdin;
nonzero exit; missing, late, and extra markers; stderr; pending mutation;
repository drift; policy drift; pre-existing final files; late final sync
failure; pending residue; and the exact #404 v2 input interface.
They also cover cross-module primitive equality, missing pending evidence,
stream overflow, post-create read failure, final verification failure, late
pending replacement, live Phase A file mutation, and complete rollback of both
owned final names.

This checkpoint is not replay evidence, Phase B approval, live Hermes proof, or
permission to update `dev` or `main`.
