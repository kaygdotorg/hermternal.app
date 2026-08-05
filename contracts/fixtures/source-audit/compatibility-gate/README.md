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
- `integration_dev`, the explicit captured `origin/dev` snapshot at commit
  `0671593b42235d4fbad2f7f3e04255c9f51b257d` and tree
  `16fac2e9d6aa64dd2631b9f4b445146c115acfb0`;
- the ordered, source-audit artifact inventory verified against the historical,
  integration, and executing-validator snapshots;
- raw normal and optimized validator-duration samples with distributions and
  `threshold: null`; and
- an explicitly blocked status with `compatible: false` and `live_run: false`.

`merged_dev` is historical evidence. `integration_dev` is one explicit
captured `origin/dev` snapshot, not a replacement review and not a live
compatibility claim. The validator captures `HEAD` once for the executing
snapshot, reads the canonical record and validator bytes from that commit, and
compares both working-tree files byte-for-byte. It captures `origin/dev` once,
reads all evidence blobs from that commit, and rechecks the ref before success;
a moved ref fails closed. A refresh must record a new explicit commit and rerun
the immutable checks.

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

- a non-canonical `--record` path, a working-tree record replacement, or a
  validator whose bytes do not match the captured committed snapshot;
- duplicate JSON object keys at any nesting level;
- `NaN`, `Infinity`, exponent overflow, oversized integers, oversized input,
  strings, containers, nodes, unsupported values, and nesting deeper than the
  bounded JSON limits;
- unknown keys, wrong exact types (including booleans where integers are
  required), changed key ordering, reordered PRs, or reordered artifact paths;
- absolute paths, Windows paths, NULs, `..` traversal, and symlink resolution
  that escapes the repository root;
- a missing, malformed, replaced, or different historical/integration/captured
  commit or tree, and a moving `dev` ref that does not match the recorded full
  OID;
- changed artifact SHA-256 values, sizes, or the canonical artifact-set digest;
- wrong or missing Git objects, wrong object types, wrong blob OIDs, truncated
  or extra `cat-file` batch output;
- `compatible: true`, `live_run: true`, positive proof statuses, or added
  observed/live-proof fields; and
- sensitive keys or credential-shaped values. CLI failures are one bounded,
  redacted JSON object and do not echo absolute paths or record content.

Git verification clears inherited Git redirects and sets both
`GIT_NO_REPLACE_OBJECTS=1` and `GIT_NO_LAZY_FETCH=1`. It captures an explicit
full `HEAD` snapshot for the canonical record and executing validator, then
captures one full `origin/dev` OID for integration evidence. Each artifact's
exact blob OID, type, size, and bytes come from one complete
`git cat-file --batch` response. The digest and size checks use that same
buffer and commit. The mutable worktree is used only for path containment and
byte-for-byte snapshot checks. The artifact-set digest is SHA-256 over UTF-8
lines in the recorded order, where each line is:

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
PYTHONPYCACHEPREFIX=/tmp/hermternal-pycache python3 -m py_compile \
  contracts/fixtures/source-audit/compatibility-gate/validate.py \
  contracts/fixtures/source-audit/compatibility-gate/test_validate.py
```

The validator is offline and uses only the Python standard library plus the
local Git object database. A passing run proves only the canonical committed
record and validator bytes, the historical reviewed commit, the captured
integration snapshot, containment rules, and artifact bytes. Its JSON output
names the `historical_reviewed_commit`, `captured_snapshot_tree`, exact record
and validator blobs, and `verified_commit_kind: captured_snapshot`. It does not
prove a live service or a deployment. An alternate `--record` path is rejected
before parsing and can never claim current-dev or captured-snapshot evidence.

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
The checked-in `observations.validator_duration_ms` object contains 30 raw
subprocess samples for both normal and optimized Python execution. Each mode
records its exact command, integration snapshot commit, environment, artifact
set digest, artifact size, and min/p50/p95/p99/max/mean distribution. Both
modes use `threshold: null`; these are review measurements, not normative
compatibility requirements.

Run this from the repository root to repeat the recorded benchmark. It invokes
30 normal and 30 optimized subprocess validations against immutable local Git
objects and prints the raw samples plus distributions:

```sh
python3 - <<'PY'
import json
import math
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path

root = Path.cwd()
fixture = root / "contracts/fixtures/source-audit/compatibility-gate"
record_path = fixture / "compatibility_record.json"
record = json.loads(record_path.read_text(encoding="utf-8"))
commands = {
    "normal": ["python3", str(fixture / "validate.py"), "--repo-root", ".", "--record", str(record_path)],
    "optimized": ["python3", "-O", str(fixture / "validate.py"), "--repo-root", ".", "--record", str(record_path)],
}
def percentile(ordered, fraction):
    return ordered[min(len(ordered) - 1, max(0, math.ceil(fraction * len(ordered)) - 1))]
def distribution(samples):
    ordered = sorted(samples)
    return {
        "min": round(min(samples), 3),
        "p50": round(percentile(ordered, 0.50), 3),
        "p95": round(percentile(ordered, 0.95), 3),
        "p99": round(percentile(ordered, 0.99), 3),
        "max": round(max(samples), 3),
        "mean": round(statistics.mean(samples), 3),
    }
output = {}
for mode, command in commands.items():
    samples = []
    for _ in range(30):
        started = time.perf_counter()
        completed = subprocess.run(command, cwd=root, capture_output=True, text=True, check=False)
        elapsed = (time.perf_counter() - started) * 1000
        if completed.returncode != 0:
            raise SystemExit(completed.stdout or completed.stderr)
        samples.append(round(elapsed, 3))
    output[mode] = {
        "command": " ".join(command),
        "commit": record["observations"]["validator_duration_ms"][mode]["commit"],
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "artifact_set_sha256": record["artifacts"]["set_sha256"],
        "artifact_size_bytes": sum(item["size_bytes"] for item in record["artifacts"]["files"]),
        "samples_ms": samples,
        "distribution": distribution(samples),
        "threshold": None,
    }
print(json.dumps(output, indent=2, sort_keys=True))
PY
```

The raw command and output for the checked-in run are included in
`compatibility_record.json`, the review PR, and final issue evidence. Repeat
the command on the target environment before using the measurements for a
performance decision.

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
