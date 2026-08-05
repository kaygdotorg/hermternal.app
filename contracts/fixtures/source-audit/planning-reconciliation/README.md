# P0-01 planning source review

This directory contains the reproducible, source-only evidence for issue `#40`.
It reconciles the source-derived v0.0.1 planning claims with exactly
`NousResearch/hermes-agent` commit
`f5be9236e00ddf2f2a412697f267078fc4ee068e`.

The review is intentionally local. It reads a checked-out source tree and the
planning documents in this repository. It does not call Hermes, a Dashboard,
a provider, or a deployment, and it does not create credentials or live
fixtures.

## Files

- [`planning_review.json`](planning_review.json) records the reviewed source
  paths, SHA-256 digests, source anchors, planning-document coverage, and
  deferred ownership boundaries.
- [`validate.py`](validate.py) verifies the pinned source checkout, file
  digests, anchors, document coverage, and required links. It fails closed when
  the source root or any required evidence is missing.
- [`test_validate.py`](test_validate.py) tests successful validation and the
  missing, changed, and malformed evidence cases with temporary synthetic
  source trees.

The validator freezes the required-link set, ordered planning-document and
source-file coverage, required anchors and absent fields, claim IDs, statuses,
source references, document references, summaries, and deferred ownership.
It rejects absolute paths, `..` traversal, and resolved symlinks that escape the
approved repository or pinned source root. These checks run in both full and
document-only modes when a source root is supplied, so a matching digest or
anchor cannot make an out-of-root path valid.

Full validation also requires a clean source checkout at the exact pinned Git
HEAD. It reads every reviewed file with `git cat-file blob HEAD:path`, not from
the mutable worktree, and fails if tracked, untracked, or ignored worktree
changes are present. A changed worktree file cannot become accepted by changing
its recorded digest.

## Reproduce the review

Fetch the public source outside this repository, pin the immutable commit, and
run the validator. The validator itself never fetches source or contacts a
service.

```sh
SOURCE_ROOT=/tmp/hermes-agent-f5be9236e00ddf2f2a412697f267078fc4ee068e

git clone --filter=blob:none --no-checkout \
  https://github.com/NousResearch/hermes-agent.git "$SOURCE_ROOT"
git -C "$SOURCE_ROOT" checkout --detach \
  f5be9236e00ddf2f2a412697f267078fc4ee068e

python3 contracts/fixtures/source-audit/planning-reconciliation/validate.py \
  --source-root "$SOURCE_ROOT"
python3 contracts/fixtures/source-audit/planning-reconciliation/validate.py \
  --check-docs-only --source-root "$SOURCE_ROOT"
python3 -m unittest discover \
  -s contracts/fixtures/source-audit/planning-reconciliation \
  -p 'test_*.py'
```

A passing run proves only that the pinned source files and planning references
match this review record. It does not replace deployment attestation, Caddy or
Traefik proof, a behavioral probe, parity tests, accessibility checks, or later
source-audit units.

## Benchmark evidence

This operation reconciles static source and planning documents. It has no client
runtime, production or release build, device workload, render path, memory
profile, or live network boundary to benchmark.

- Deterministic workload: the P0-01 review record and the validator command above.
- Metric: N/A for runtime performance; `validate.py` emits `duration_ms` only as
  diagnostic evidence for the local source check.
- Environment and device: the local checkout, Python standard library, and the
  detached pinned source tree; no device or browser is involved.
- Build mode: N/A for this source-only planning artifact.
- Repetitions and distribution: N/A until the benchmark format is defined by
  B-01 (`#102`); no one-off timing is presented as a product baseline.
- Trace artifact: validator JSON output, including `ok`, `source_head`, and
  `duration_ms`.
- Baseline or approved budget: N/A; this operation does not invent a threshold
  before the benchmark prerequisite establishes one.

The focused source-audit units owned by issue `#200` and PRs `#216`, `#218`,
`#219`, and `#220` remain separate. This change does not edit their files or
claim their route, OAuth, PTY-attach, model-options, or native-bearer fixture
proofs.
