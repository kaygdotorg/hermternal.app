# Retained replay outer-wrapper successor

This checkpoint adds the corrected outer wrapper for issues #397 and #405. It
does not run replay. It does not change Git, use a network, use credentials,
start Hermes, or clean retained evidence.

## Verified authority

The wrapper verifies and loads these exact sources before it can call a process:

- the retained pending-driver successor, SHA-256
  `a11bbba3feaab58e31011b2d76d15835c048b22447302d73e3f14dbab159e438`;
- the corrected #404 Phase A and anchor runner, SHA-256
  `6f5024996daca712f5b2814d39d48540d0ea5369941d3e2b3f1c5a00dcb614f4`;
- the approved #400 Git authority, SHA-256
  `b2b5a5f1e0ed813325a23cb32eb075b2637872f5c5176e81c79879af4ab1861a`.

The retained driver verifies the final #403 five-file authority and generator
chain. It derives the exact invocation array and changed stdin bytes from that
authority. The wrapper checks that the derived stdin hash is different from the
frozen source-shell hash. It does not accept caller-supplied argv, stdin, or
environment values.

## Process contract

The wrapper has one injectable process boundary. The production boundary uses
the exact derived argv and stdin, an empty inherited environment, `/` as its
working directory, and byte pipes for stdin, stdout, and stderr. The derived
argv starts `/usr/bin/env -i`, so the child gets only the environment that the
approved shell creates.

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

The command requires an independently reviewed #404 anchor evidence path and
its exact SHA-256:

```sh
python3 -B handover/issue-397/task409-replay-result-successor/replay_result_successor.py \
  --phase-a-evidence /absolute/path/to/evidence/anchor.json \
  --expected-phase-a-evidence-sha256 <INDEPENDENTLY_REVIEWED_SHA256>
```

The verified #404 runner stable-reads and parses this closed evidence. The
wrapper extracts `phase_a_manifest_sha256` and `phase_a_approval_digest` from
the verified record. It does not accept these two values directly from the
caller.

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
no-follow rereads. If publication fails, the wrapper removes only the exact
device and inode that this call created. It does not remove pending evidence or
the retained repository. A pre-existing final file is never changed.

## Current execution blocker

This wrapper is complete as a fail-closed checkpoint, but the retained driver
is not ready for execution. The retained driver keeps this file so the replay
repository can read the retained clean-primary object store:

```text
repository/.git/objects/info/alternates
```

The approved #400 reviewer rejects that entry. Its closed object-info grammar
allows only `packs`, `commit-graph`, and `commit-graphs`. The wrapper must not
weaken #400. Therefore a real wrapper run would stop at repository review and
would publish no final result.

The next retained-driver correction must make the repository self-contained
before pending publication. It must copy all reachable objects into its own
object store, remove the alternates file through a reviewed exact path and
inode boundary, prove strict object closure, and retain the clean-primary and
repository. The correction must preserve the sole terminal marker and pending
publication contract. This work needs separate review before replay.

## Offline checks

Run:

```sh
python3 -m py_compile \
  handover/issue-397/task409-replay-result-successor/replay_result_successor.py \
  handover/issue-397/task409-replay-result-successor/test_replay_result_successor.py
python3 -B handover/issue-397/task409-replay-result-successor/test_replay_result_successor.py
python3 -O -B handover/issue-397/task409-replay-result-successor/test_replay_result_successor.py
```

The tests inject the process and #400 observation boundaries. They do not run
the shell or a Git command. They cover exact argv, stdin, and environment;
derived versus source stdin; nonzero exit; missing, late, and extra markers;
stderr; pending mutation; repository drift; policy drift; pre-existing final
files; late final sync failure; pending residue; and required #404 input
arguments.

This checkpoint is not replay evidence, Phase B approval, live Hermes proof, or
permission to update `dev` or `main`.
