# P0-02 compatibility gate fixture

Status: synthetic fixture-only record. This directory does not attest a deployment,
run Hermes, contact a provider, contact a proxy, or claim compatibility.

## Purpose

`compatibility_record.json` binds the reviewed fixture set to:

- contract `dashboard-v0.0.1`;
- Hermes commit `f5be9236e00ddf2f2a412697f267078fc4ee068e` as the source pin;
- `merged_dev`, the immutable historical review at commit
  `8465bd4cacc87fe62ff952c38d7f3c2b5927bfbd` and tree
  `aede9b87932f5cc28462120ef28be52a9a4aba7f`;
- `integration_dev`, the explicit current `dev` snapshot at commit
  `3a279cf209a41d47e3bcef471ccf977c08c3cb7a` and tree
  `39fff048fcd35cf54799c9207ff2d7063daeb000`;
- the ordered, source-audit artifact inventory verified against both commits;
- observational artifact-size and validator-duration measurements with no
  performance threshold; and
- an explicitly blocked status with `compatible: false` and `live_run: false`.

`merged_dev` is historical evidence. `integration_dev` is a current-dev
integration check, not a replacement review and not a live compatibility claim.
The current branch name is used only to locate the expected local ref; the
recorded full commit and tree must match, so moving `dev` cannot silently
change the evidence target. A refresh must record a new explicit commit and
rerun the immutable checks.

The merged PR list uses the fixture's canonical recorded order (`#221`,
`#216`, `#218`, `#219`, `#220`); issue #41 does not prescribe an order. Artifact
paths use canonical lexicographic ordering. The validator checks both exact
ordering and that every recorded merge commit exists locally and is an ancestor
of the historical reviewed head.

This record is not a deployment attestation. It does not contain a deployment
identity, public host, proxy configuration, credentials, cookies, bearer values,
raw WebSocket tickets, prompt text, transcripts, PTY bytes, or live results.

## Strict record contract

The standard-library-only `validate.py` rejects:

- duplicate JSON object keys at any nesting level;
- `NaN`, `Infinity`, exponent overflow, unsupported values, and nesting deeper
  than the bounded JSON depth;
- unknown keys, wrong exact types (including booleans where integers are
  required), changed key ordering, reordered PRs, or reordered artifact paths;
- absolute paths, Windows paths, NULs, `..` traversal, and symlink resolution
  that escapes the repository root;
- a missing, malformed, replaced, or different historical/current commit or
  tree, and a moving `dev` ref that does not match the recorded full OID;
- changed artifact SHA-256 values, sizes, or the canonical artifact-set digest;
- wrong or missing Git objects, wrong object types, and truncated `cat-file`
  batch output;
- `compatible: true`, `live_run: true`, positive proof statuses, or added
  observed/live-proof fields; and
- sensitive keys or credential-shaped values.

Git verification clears inherited Git redirects and sets both
`GIT_NO_REPLACE_OBJECTS=1` and `GIT_NO_LAZY_FETCH=1`. It captures an explicit
full commit OID, then reads each artifact's type, size, and bytes from one
`git cat-file --batch` response. The digest and size checks use that same
buffer and commit. The mutable worktree is used only for path containment
checks. The artifact-set digest is SHA-256 over UTF-8 lines in the recorded
order, where each line is:

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
python3 -O contracts/fixtures/source-audit/compatibility-gate/validate.py
python3 contracts/fixtures/source-audit/compatibility-gate/test_validate.py
python3 -O contracts/fixtures/source-audit/compatibility-gate/test_validate.py
python3 -m unittest discover \
  -s contracts/fixtures/source-audit/compatibility-gate \
  -p 'test_validate.py'
python3 -m py_compile \
  contracts/fixtures/source-audit/compatibility-gate/validate.py \
  contracts/fixtures/source-audit/compatibility-gate/test_validate.py
rm -rf contracts/fixtures/source-audit/compatibility-gate/__pycache__
```

The validator is offline and uses only the Python standard library plus the
local Git object database. A passing run proves only the checked-in record,
the historical reviewed commit, the current-dev integration snapshot,
containment rules, and artifact bytes. Its JSON output names both the
`historical_reviewed_commit` and the `verified_commit` with
`verified_commit_kind: current_dev_integration`. It does not prove a live
service or a deployment.

## Accessibility

Accessibility verification is N/A for this operation because it produces no UI
and changes no interaction, focus, semantic-name, VoiceOver, Switch Control,
Dynamic Type, browser-zoom, contrast, motion, transparency, or touch-target
behavior. The fixture preserves rather than removes those future accessibility
requirements; any later UI contract must still provide its platform-specific
checks.

## Reproducible tooling benchmark

This is an offline command-line validator, so production or release build mode
is N/A: this change does not build or ship an executable, service, or client.
The benchmark records fixture artifact bytes and validator-duration distribution
only. The checked-in `observations` object records the committed artifact byte
total, repetition count, and one local duration distribution as observational
evidence. It has no invented performance threshold; the measurements are review
evidence, not normative compatibility requirements.

Run this from the repository root to repeat the recorded benchmark. It uses
30 validations against immutable local Git blobs and prints the artifact byte
count plus min, p50, p95, max, and mean duration in milliseconds:

```sh
python3 - <<'PY'
import json
import math
import platform
import statistics
import sys
import time
from pathlib import Path

root = Path.cwd()
fixture = root / "contracts/fixtures/source-audit/compatibility-gate"
sys.path.insert(0, str(fixture))
import validate

record = validate.load_record(fixture / "compatibility_record.json")
durations = []
for _ in range(30):
    started = time.perf_counter()
    validate.validate_record(record, root)
    durations.append((time.perf_counter() - started) * 1000)
ordered = sorted(durations)
def percentile(fraction):
    return ordered[min(len(ordered) - 1, max(0, math.ceil(fraction * len(ordered)) - 1))]
print(json.dumps({
    "artifact_bytes": sum(item["size_bytes"] for item in record["artifacts"]["files"]),
    "artifact_count": len(record["artifacts"]["files"]),
    "environment": platform.platform(),
    "python": sys.version.split()[0],
    "repetitions": len(durations),
    "duration_ms": {
        "min": round(min(durations), 3),
        "p50": round(percentile(0.50), 3),
        "p95": round(percentile(0.95), 3),
        "max": round(max(durations), 3),
        "mean": round(statistics.mean(durations), 3),
    },
}, sort_keys=True))
PY
```

The raw command and output for the checked-in run are included in the review
PR and final issue evidence. Repeat the command on the target environment
before using the measurements for a performance decision.

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

## Fail-closed status boundary

The record intentionally remains incompatible because this fixture-only gate
cannot claim deployment, runtime, proxy, parity, accessibility, or benchmark
proof. Those statuses are record-level fail-closed metadata, not a dependency
claim that downstream runtime-proof contracts must complete before this issue
can be reviewed. Issue #41 blocks downstream issues #51 and #52; they do not
block this synthetic fixture operation.

This change records the missing live evidence without inventing a live result,
best-effort compatibility, or a replacement integration. Review may decide the
scoped issue outcome from this artifact; downstream proof remains outside this
four-file change.

## Scope boundary

Only the four files in this directory are owned by this change. Existing audits,
central protocol documents, `.superdesign` output, live integrations, and Apple
paths remain unchanged. All values in the compatibility record are synthetic or
public source-control metadata, and the gate fails closed when a required value
is absent or mismatched.
