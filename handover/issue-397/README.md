# Issue #397 guarded-replay artifact handover

This directory preserves local-only guarded-replay inputs for issue #397 on branch `handover/397-guarded-replay-artifacts`. It is a handover bundle, not candidate-five approval and not replay evidence.

## Fixed repository boundary

The bundle was based on the exact `origin/dev` state below.

| Ref | Value |
| --- | --- |
| Base commit | `729f2613af2b78d58b07918478e9102d5716f367` |
| Base tree | `43f86b645fc9f89d5d4aa1e6978b1f61f0b5c69f` |
| Protected `origin/main` commit | `3ebf8b3fe4767442490ab3053c0c1ccf84e8019f` |
| Branch | `handover/397-guarded-replay-artifacts` |

The primary checkout was not written. No merge, replay, Hermes execution, network call, credential use, or live proof was performed. No unrelated cache, log, transcript, credential, or generated Python cache is included.

## Contents

- `task464-candidate5/` contains the candidate-five generator and its three tests.
- `task464-inputs/` contains the candidate-five working Markdown, JSON, and source-shell inputs.
- `task409-matrix/` contains the exact execution-matrix Markdown and JSON.
- `task409-execution-preflight/` contains Phase A/Phase B sources, tests, reviewers, the anchor provisioner, and wrapper.
- `task409-postreplay-gates/` contains offline post-replay gate source and self-tests.
- `historical/candidate-four/` contains immutable candidate-four evidence only.
- `historical/candidate-three-rejected/` contains rejected candidate-three evidence only.
- `manifest.json` is the machine-readable bundle manifest.
- `SHA256SUMS` contains the final byte hashes for every preserved artifact. `manifest.json` records each artifact's path, byte count, mode, and SHA-256; check both hashes and modes before use.

The preserved source modes include the candidate-five generator at `0600`, the Phase A wrapper and rejected candidate-three runner at `0700`, and historical candidate-four files at `0444`. Do not normalize or rewrite frozen bytes.

## Exact matrix identities

The matrix JSON is preserved byte-for-byte. Its normalized identity is:

`94774470b8cd9a6a7ec8e6b480883762d432b845355fa5520b398d9b60fdb6d8`

The declared algorithm is byte-preserving: replace every `expected_normalized_sha256` token and every `shell_sha256`, `driver_shell_sha256`, and `expected_body_sha256` 64-hex value with zeroes, without whitespace normalization or JSON reserialization, then hash the resulting bytes.

The shell embedded in the exact matrix JSON is independently extracted and hashes to `1599b4a0155c5963f5272ca18377cbfbee170ce6e92372ec643dfac3b256ab26`. It is 184,832 bytes, 3,880 LF-terminated lines, and ends in byte `0a`.

## Restore ephemeral paths on another machine

The preserved tests intentionally retain their original stable paths. On a fresh machine, create private copies only after checking out this branch and verifying `SHA256SUMS`. Use a private temporary directory, not the primary checkout, and map the paths as follows.

```sh
BUNDLE="$PWD/handover/issue-397"
mkdir -p /private/tmp/f932bc703a5e-task464-candidate5 /private/tmp/task409-execution-preflight /private/tmp/task409-postreplay-gates
install -m 0600 "$BUNDLE/task464-candidate5/f932bc703a5e-task464-candidate5-generator.py" /private/tmp/f932bc703a5e-task464-candidate5/f932bc703a5e-task464-candidate5-generator.py
install -m 0644 "$BUNDLE/task464-candidate5/test_f932bc703a5e-task464-candidate5-framing-range.py" /private/tmp/f932bc703a5e-task464-candidate5/test_f932bc703a5e-task464-candidate5-framing-range.py
install -m 0644 "$BUNDLE/task464-candidate5/test_f932bc703a5e-task464-candidate5-generator.py" /private/tmp/f932bc703a5e-task464-candidate5/test_f932bc703a5e-task464-candidate5-generator.py
install -m 0644 "$BUNDLE/task464-candidate5/test_stable_reader_f932bc703a5e-task464-candidate5.py" /private/tmp/f932bc703a5e-task464-candidate5/test_stable_reader_f932bc703a5e-task464-candidate5.py
install -m 0644 "$BUNDLE/task464-inputs/task464-working-input.md" /private/tmp/task464-working-input.md
install -m 0644 "$BUNDLE/task464-inputs/task464-working-input.json" /private/tmp/task464-working-input.json
install -m 0644 "$BUNDLE/task464-inputs/task464-source-shell-current.txt" /private/tmp/task464-source-shell-current.txt
install -m 0644 "$BUNDLE/task409-matrix/hermternal-task409-final-execution-matrix.md" /private/tmp/hermternal-task409-final-execution-matrix.md
install -m 0644 "$BUNDLE/task409-matrix/hermternal-task409-final-execution-matrix.json" /private/tmp/hermternal-task409-final-execution-matrix.json
install -m 0644 "$BUNDLE/task409-execution-preflight/task409_execution_preflight_v3.py" /private/tmp/task409-execution-preflight/task409_execution_preflight_v3.py
install -m 0644 "$BUNDLE/task409-execution-preflight/review_frozen_pair.py" /private/tmp/task409-execution-preflight/review_frozen_pair.py
install -m 0700 "$BUNDLE/task409-execution-preflight/run_task409_execution_preflight_v3.sh" /private/tmp/task409-execution-preflight/run_task409_execution_preflight_v3.sh
```

The unchanged Phase A regression test refers to the historical candidate-four paths `/private/tmp/task464-test32-json.json` and `/private/tmp/task464-test32-shell.sh`. If that test is run as a historical compatibility check, restore only the corresponding immutable candidate-four files from `historical/candidate-four/` under those names. Do not present that test as candidate-five approval.

The preserved source and tests also contain stale `/private/tmp` names as policy text or fail-closed rejection fixtures. Do not rewrite those strings. In particular, the candidate-five final triad and provenance manifest do not exist in this bundle and cannot be reconstructed by renaming candidate-four evidence.

## Checks

Verify bytes before running any preserved test.

```sh
cd /path/to/checkout/handover/issue-397
shasum -a 256 -c SHA256SUMS
python3 -B task464-candidate5/test_f932bc703a5e-task464-candidate5-framing-range.py
python3 -B task464-candidate5/test_f932bc703a5e-task464-candidate5-generator.py
python3 -O -B task464-candidate5/test_f932bc703a5e-task464-candidate5-framing-range.py
python3 -O -B task464-candidate5/test_f932bc703a5e-task464-candidate5-generator.py
python3 -B task409-postreplay-gates/test_post_replay_gates.py
```

The unchanged stable-reader test is intentionally retained. It stops immediately at its old frozen generator hash pin: expected `600f4e9f4b75a5a4ded039fb6ae0e8f5778854147f15ec8190fef87fab1a7102`, actual candidate-five generator `cc73c1743c4059cc995be4a9e097cd16007c8095bc87a7c572418134c4d434dc`. This is a frozen-test incompatibility, not a stable-reader behavioral approval or failure. Do not edit the frozen test in place.

## Security scan

A redacted Gitleaks scan found 38 matches. Every finding was classified as a lowercase hexadecimal Git commit, tree, or blob object ID embedded in offline fixtures, matrix data, or rejected historical evidence. No credential-shaped secret was identified. Secret values are not reproduced here. Generated `__pycache__` content was removed before the bundle was finalized.

## Resume order and omissions

1. Independently review the frozen candidate-five framing/range checkpoint and decide how to establish a new stable-reader pin without modifying frozen evidence.
2. Correct and independently review the rejected Phase B lifecycle harness. It must exercise genuine Phase A validation, constrain and independently verify triad paths and normalized identity, and assert validator call counts.
3. Freeze a real candidate-five Markdown/JSON/shell triad and create its provenance manifest. Neither is present here.
4. Replace candidate-four placeholders in Phase A inputs with the approved candidate-five values and run Phase A consistency checks.
5. Provision and independently verify the Phase A approval anchor, then run the Phase B Git review.
6. Only after every gate passes, allocate a clean primary clone and isolated replay root, extract the shell from the exact triad, and consider guarded offline replay into `dev` only.
7. Run post-replay gates and obtain independent review before any non-force `dev` update.

The following were not performed and must not be inferred from this handover: candidate-five approval, Phase A approval, Phase B approval, guarded replay, Hermes or live proof, `dev`/`main` merge, push, production checks, or cleanup.

See `manifest.json` for machine-readable paths, hashes, source policy, scan classification, and known limitations.
