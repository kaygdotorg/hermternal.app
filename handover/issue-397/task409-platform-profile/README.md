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
```

Do not run `--publish` again. The durable final set already exists and a second
publication must fail. No tool in this directory executes the generated shell,
Git replay, Hermes, network access, or credentials.
