# P0-02 compatibility gate fixture

Status: synthetic fixture-only record. This directory does not attest a deployment,
run Hermes, contact a provider, contact a proxy, or claim compatibility.

## Purpose

`compatibility_record.json` binds the reviewed fixture set to:

- contract `dashboard-v0.0.1`;
- Hermes commit `f5be9236e00ddf2f2a412697f267078fc4ee068e` as the source pin;
- the exact merged `dev` commit and tree after the recorded PRs;
- the ordered, source-audit artifact inventory already present on that merged
  commit; and
- an explicitly blocked status with `compatible: false` and `live_run: false`.

The merged PR list preserves the issue's requested order (`#221`, `#216`,
`#218`, `#219`, `#220`). The validator also checks that every recorded merge
commit exists locally and is an ancestor of the pinned merged `dev` head.

This record is not a deployment attestation. It does not contain a deployment
identity, public host, proxy configuration, credentials, cookies, bearer values,
raw WebSocket tickets, prompt text, transcripts, PTY bytes, or live results.

## Strict record contract

The standard-library-only `validate.py` rejects:

- duplicate JSON object keys at any nesting level;
- unknown keys, wrong types, changed key ordering, reordered PRs, or reordered
  artifact paths;
- absolute paths, Windows paths, `..` traversal, and symlink resolution that
  escapes the repository root;
- a missing or different local `dev` ref, tree, merge commit, or Git blob;
- changed artifact SHA-256 values, sizes, or the canonical artifact-set digest;
- `compatible: true`, `live_run: true`, positive proof statuses, or added
  observed/live-proof fields; and
- sensitive keys or credential-shaped values.

Artifact bytes are read with `git cat-file blob` from the pinned merged commit,
with `GIT_NO_LAZY_FETCH=1`. The mutable worktree is used only for path
containment checks. The artifact-set digest is SHA-256 over UTF-8 lines in the
recorded order, where each line is:

```text
relative/path\0file_sha256\0size_bytes\n
```

The record intentionally excludes the compatibility-gate directory from that
inventory. Otherwise the record would need to digest itself and could not be a
stable check of the already-merged fixture evidence.

## Reproduce offline

Run from the repository root with the local `dev` ref available:

```sh
python3 contracts/fixtures/source-audit/compatibility-gate/validate.py
python3 contracts/fixtures/source-audit/compatibility-gate/test_validate.py
python3 -m unittest discover \
  -s contracts/fixtures/source-audit/compatibility-gate \
  -p 'test_validate.py'
python3 -m py_compile \
  contracts/fixtures/source-audit/compatibility-gate/validate.py \
  contracts/fixtures/source-audit/compatibility-gate/test_validate.py
```

The validator is offline and uses only the Python standard library plus the
local Git object database. A passing run proves only the checked-in record,
merged-dev identity, containment rules, and artifact bytes. It does not prove a
live service or a deployment.

## Related fixture validators

The compatibility gate aggregates the existing synthetic source-audit artifacts;
it does not replace their focused checks. Re-run the focused validators when
reviewing this record:

```sh
python3 contracts/fixtures/source-audit/planning-reconciliation/validate.py \
  --check-docs-only
python3 contracts/fixtures/source-audit/planning-reconciliation/test_validate.py
python3 contracts/fixtures/source-audit/oauth-browser/test_oauth_browser.py
python3 contracts/fixtures/source-audit/native-bearer/test_native_bearer.py
python3 contracts/fixtures/source-audit/model-options/test_model_options.py
python3 contracts/fixtures/source-audit/pty-attach/validate.py
```

The planning review's full mode additionally needs a separately checked-out
Hermes source tree at the pinned SHA. No such checkout is created by this
fixture-only gate.

## Explicit remaining blockers

The record remains incompatible because fixture-only work cannot supply:

1. a verifiable out-of-band deployment attestation;
2. a redacted behavioral probe against a deployment;
3. edge/proxy proof for the approved variants;
4. web and Apple parity plus the required accessibility evidence; or
5. benchmark environment, repetition, trace, and budget evidence.

Those are exact blockers for the issue's full definition of done. This change
records them without inventing a live result, best-effort compatibility, or a
replacement integration.

## Scope boundary

Only the four files in this directory are owned by this change. Existing audits,
central protocol documents, `.superdesign` output, live integrations, and Apple
paths remain unchanged. All values in the compatibility record are synthetic or
public source-control metadata, and the gate fails closed when a required value
is absent or mismatched.
