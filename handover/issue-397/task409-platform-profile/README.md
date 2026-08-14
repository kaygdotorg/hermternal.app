# Linux platform profile successor

This directory defines the only mutable host contract for the issue #397
guarded replay. `linux-host-v1.json` is a build-time profile. Runtime
environment variables cannot override it.

`platform_successor.py` verified-loads approved #401, #402, and #403 code. It
derives one Linux triad and publishes it create-only. The generated JSON,
Markdown, and shell repeat profile literals because their cross-format bytes
must agree. The closed adaptation manifest records predecessor hashes, the two
semantic host changes, the dependent temporary-parent derivation, and unchanged
replay semantics.

`linux_retained_driver.py` verified-loads the reviewed retained-driver
transform. `linux_replay_wrapper.py` pins the reviewed outer wrapper to the new
driver contract. It is a read-only preflight and cannot run replay. New Phase A
v3 evidence is required before replay authorization.

`linux_phase_a_v3.py` verified-loads the approved Phase A v2 runner and changes
only its schema, Linux authority pins, profile-bound owner record, and durable
v3 evidence root. Its `phase-a` and `anchor` commands are separate create-only
steps. Do not run these durable commands until an independent review approves
this adapter. `load_approved_wrapper` removes the deliberate disabled boundary
only after it authenticates an independently supplied anchor digest. Loading
or testing the adapter does not run replay.
Its old dependency pins now fail closed. Keep its source and durable evidence
as historical authority; use v4 for new approval work.

## Parent-binding v9 boundary successor

`linux_phase_a_v8.py` proved its disposable Phase A-to-anchor lifecycle but
did not call `load_approved_wrapper`. Its inherited v3 method still searched
for the old v3 disabled-boundary literal while the frozen v5 wrapper correctly
uses the v8 literal. `linux_phase_a_v9.py` authenticates and executes exact v8
bytes, then replaces only that one loaded v3 code constant. The existing
preserved-method replacement remains unchanged. It has a new v9 schema, owner
pin, and create-only evidence root. `linux_replay_failure_v7.py` retains the
same one-shot failure interface against the v9 adapter in a separate v7 root.
Neither successor regenerates authority or runs replay.

`linux_replay_failure_v8.py` corrects one outer-loader propagation gap without
changing v9 or replay bytes.  The inherited failure-v2 mechanism creates a
fresh failure-v1 module and reads that module's adapter pin.  Failure v8 wraps
that exact factory so it receives the authenticated v9 adapter.  Its test runs
the complete disposable Phase-to-anchor flow through the actual outer failure
loader.  It does not execute replay, network access, credentials, or Hermes.

`linux_phase_a_v4.py` verified-loads the unchanged v3 adapter. It binds only
the corrected Linux driver and wrapper bytes, the v4 evidence schema, and the
new `hermternal-issue397-phase-a-anchor-v4` root. The v1-v3 evidence stays
frozen. Its tests use a disposable root for a genuine Phase A-to-anchor cycle.

`linux_replay_failure_v1.py` is a successor over the exact approved Phase A
adapter bytes. It adds one create-only, private, fsynced
`replay-failure.json` to the replay result root for a nonzero child result or
an invalid success marker. The timestamp-free record keeps exact output hashes
and counts with bounded credential-redacted excerpts. It does not claim
completion, delete the record, or retry replay. Success rejects a preexisting
failure record.

`linux_replay_failure_v2.py` handles failure before the child can create its
ephemeral replay root. Before process launch it creates and fsyncs one fixed
profile-derived v2 directory with mode 0700 and a create-only owner marker. A
process or marker failure publishes the mode-0600 record there and adds exact
ephemeral residue observations. Success removes only the transaction-owned
marker and empty directory before final validation.

The retained Linux driver also corrects one stale validator assumption in its
derived stdin. The #403 generator replaces later Markdown closing fences with
one durable HTML boundary. The derived validator now parses exactly one JSON
appendix and requires that exact boundary. The frozen authority and preserved
`hermternal-issue397-replay-failure-v1` evidence stay unchanged.

`git_config_policy.py` is the one canonical Git-config policy source for the
Linux correction. It binds the exact #400 replay config bytes and records to
`protocol.allow=never`. Its generated-validator predicate treats `remote.*`
records as repository metadata. It applies the `never` value rule only to
`protocol.allow` and named `protocol.<name>.allow` records.

`linux_retained_driver_v2.py` embeds that shared predicate at the one faulty
generated-shell anchor. `linux_replay_wrapper_v2.py` binds #405 to the new
derived stdin and checks the shared policy against #400. The original driver,
wrapper, authority triad, and failure-v2 evidence stay frozen.

The derived stdin hash changed. Thus, `linux_phase_a_v5.py` uses a new
create-only `hermternal-issue397-phase-a-anchor-v5` evidence root.
`linux_replay_failure_v3.py` uses a separate
`hermternal-issue397-replay-failure-v3` root. Do not reuse or change v4 Phase A
or failure-v2 evidence. The new tests use only disposable evidence roots and
local temporary Git repositories. They do not run replay.

`forbidden_proof.py` is the shared successor policy for the 22 forbidden
ancestry IDs. A present ID must be a commit and must return exact non-ancestor
status. An absent ID is accepted only after strict repository, indirection,
`fsck`, all-ref closure, and base/main/source closure checks. The current
profile proves that 17 IDs are present non-ancestors and that five IDs are
absent. It handles all five as one canonical classification.

`linux_retained_driver_v3.py` and `linux_replay_wrapper_v3.py` use that one
classification in preflight and in the three generated predicates that depend
on forbidden-object availability. They do not change the frozen authority.
`linux_phase_a_v6.py` binds the complete proof record and its SHA-256 in a new
owner marker and evidence root. A classification change makes the later anchor
fail. `linux_replay_failure_v4.py` gives any later, separately approved replay
attempt a new failure root. The v5 and failure-v3 evidence stays frozen.

Run:

```sh
/usr/bin/python3 -B test_platform_profile.py
/usr/bin/python3 -O -B test_platform_profile.py
/usr/bin/python3 -B platform_successor.py --prepare
/usr/bin/python3 -B linux_replay_wrapper.py
/usr/bin/python3 -B test_linux_phase_a_v4.py
/usr/bin/python3 -O -B test_linux_phase_a_v4.py
/usr/bin/python3 -B test_linux_replay_failure_v1.py
/usr/bin/python3 -O -B test_linux_replay_failure_v1.py
/usr/bin/python3 -B test_linux_replay_failure_v2.py
/usr/bin/python3 -O -B test_linux_replay_failure_v2.py
/usr/bin/python3 -B test_git_config_policy.py
/usr/bin/python3 -O -B test_git_config_policy.py
/usr/bin/python3 -B linux_replay_wrapper_v2.py
/usr/bin/python3 -B test_linux_phase_a_v5.py
/usr/bin/python3 -O -B test_linux_phase_a_v5.py
/usr/bin/python3 -B test_linux_replay_failure_v3.py
/usr/bin/python3 -O -B test_linux_replay_failure_v3.py
/usr/bin/python3 -B test_forbidden_proof.py
/usr/bin/python3 -O -B test_forbidden_proof.py
/usr/bin/python3 -B linux_replay_wrapper_v3.py
/usr/bin/python3 -B test_linux_phase_a_v6.py
/usr/bin/python3 -O -B test_linux_phase_a_v6.py
/usr/bin/python3 -B test_linux_replay_failure_v4.py
/usr/bin/python3 -O -B test_linux_replay_failure_v4.py
/usr/bin/python3 -B linux_anchor_authority_v2.py --prepare
/usr/bin/python3 -B test_section_anchor_metadata.py
/usr/bin/python3 -O -B test_section_anchor_metadata.py
/usr/bin/python3 -B linux_replay_wrapper_v4.py
/usr/bin/python3 -B test_linux_phase_a_v7.py
/usr/bin/python3 -O -B test_linux_phase_a_v7.py
/usr/bin/python3 -B test_linux_replay_failure_v5.py
/usr/bin/python3 -O -B test_linux_replay_failure_v5.py
```

Do not run `--publish` again. The durable final set already exists and a second
publication must fail. No tool in this directory executes the generated shell,
Git replay, Hermes, network access, or credentials.

## Section-anchor LF successor

`section_anchor_metadata.py` is the strict reusable intake and generated-output
invariant for `live_overlap.scripts_readme.section_anchor`. The only accepted
decoded value is `## Disposable Caddy proof renderer` followed by one real LF.
The visible two-character `\\n` legacy value is rejected after the one
versioned repair. `linux_anchor_authority_v2.py` creates the separate
`task464-candidate5-linux-v1-anchor-lf-final` authority triad. Its output and
derived stdin have new hashes, so `linux_retained_driver_v4.py`,
`linux_replay_wrapper_v4.py`, `linux_phase_a_v7.py`, and
`linux_replay_failure_v5.py` bind only new authority and evidence roots.
Earlier authority and Phase/failure roots remain frozen. Tests use mocked
worktree identity and disposable local evidence; they do not execute replay,
Hermes, network access, or credentials.

## Local object-preservation successor

`object_preservation.py` fixes only object availability after the reviewed
heads-only clone. It exports one complete, non-thin local pack from the exact
11 independent authority tips. It does not create refs, fetch, use alternates,
or change the source repository. The disposable clean-primary imports the pack
with `index-pack` without `--fix-thin`.

The policy authenticates the 563 typed authority objects, 17 present forbidden
commits, and five missing-proved commits as one record. It then requires strict
`fsck`, all-ref closure, and each of the 11 root closures in the source and the
disposable clone. Pack bytes, file identity, mode, and SHA-256 stay stable
before and after import. The temporary pack is private and is removed after the
check. No durable replay result is made by this step.

The generated runtime reads the preservation policy and forbidden-proof policy
twice with `O_NOFOLLOW`. It checks full file identity and SHA-256, then compiles
and executes those exact buffers. A pathname reopen cannot select different
code, and an earlier unverified `forbidden_proof` import cannot win resolution.

`linux_retained_driver_v7.py` keeps the reviewed local-pack preservation step
and corrects the generated replay invariants found by the disposable core run.
It resolves relative Git object paths from the replay repository, carries the
exact authenticated post-state for each active range, semantic, matrix, and
README-merge operation into the commit gate, and ignores shared `/tmp` link
count churn while it still binds directory device, inode, owner, mode, and
canonical path. It disables Git's optional reverse-index sidecar for the final
retained pack, so the verified output stays an exact pack/index pair.
Two generated validator heredocs each receive the same strict LF record parser
source. Each heredoc starts a separate Python process, so neither process can
reuse a parser definition from another heredoc.
`linux_replay_wrapper_v7.py` stays disabled. `linux_phase_a_v11.py` binds the
canonical record, record SHA-256, and policy SHA-256 in a new create-only owner
and evidence root. `linux_replay_failure_v10.py` uses a separate failure root.
All older authority, Phase A, and failure evidence stays frozen.
The v11 adapter retargets the runner and every nested outer-loader factory to
`hermternal-issue397-phase-a-anchor-v11`; it cannot resolve the frozen v10 root.

`linux_replay_failure_v11.py` is the public-loader successor. It authenticates
the exact failure-v10, Phase-v11, and closed local import buffers before it
executes any of them. It installs the exact imports only while a bound loader
call runs, then restores every changed local and synthetic module name to its
exact prior object or absence. An unlisted local cache change is rejected. It
then gives each fresh
nested evidence validator the v11 schema and root.
This lets the public outer loader authenticate the approved v11 anchor. The
successor also binds that nested loader to the already authenticated v7
wrapper. Thus, the final public stdin has exactly one local-pack preservation
call before clean-primary validation. The regression compares the public stdin
with independently derived v7 bytes; it does not execute that stdin.
`test_linux_retained_driver_v7_object_path.py` also enumerates all 79 commit
operations and all 305 active path instances in the frozen matrix. It requires
one exact post-state for every path in each active operation and proves that
the generated commit gate does not call the old global path-state inference.
The source-pin correction changes the wrapper, Phase-v11, and failure module
hashes but leaves the derived stdin unchanged. The failure successor uses the
separate, create-only
`hermternal-issue397-replay-failure-v11` root only if a later approved replay
calls the boundary.

Run the disposable tests in normal and optimized Python modes:

```sh
/usr/bin/python3 -B test_object_preservation.py
/usr/bin/python3 -O -B test_object_preservation.py
/usr/bin/python3 -B test_linux_retained_driver_v7_object_path.py
/usr/bin/python3 -O -B test_linux_retained_driver_v7_object_path.py
/usr/bin/python3 -B test_linux_phase_a_v11.py
/usr/bin/python3 -O -B test_linux_phase_a_v11.py
/usr/bin/python3 -B test_linux_replay_failure_v11.py
/usr/bin/python3 -O -B test_linux_replay_failure_v11.py
/usr/bin/python3 -B test_linux_replay_failure_v11_ordering.py
/usr/bin/python3 -O -B test_linux_replay_failure_v11_ordering.py
```
