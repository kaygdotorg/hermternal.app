#!/usr/bin/env python3
"""Validate the synthetic, source-only compatibility gate record.

This validator is deliberately offline. It reads the checked-in JSON record and
immutable Git blobs from one historical reviewed commit plus one explicit
current-``dev`` integration snapshot. It never contacts Hermes, a proxy, an
identity provider, or a deployment. A record can therefore prove only that the
reviewed fixture artifacts are the exact bytes recorded for those revisions; it
cannot turn missing deployment or behavioral evidence into compatibility.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import time
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parent
RECORD_NAME = "compatibility_record.json"
RECORD_PATH = ROOT / RECORD_NAME
SCHEMA = "hermternal.compatibility-gate.v1"
OPERATION = "P0-02"
CONTRACT = "dashboard-v0.0.1"
HERMES_REPOSITORY = "NousResearch/hermes-agent"
HERMES_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
DEV_REF = "dev"
HISTORICAL_DEV_HEAD = "8465bd4cacc87fe62ff952c38d7f3c2b5927bfbd"
HISTORICAL_DEV_TREE = "aede9b87932f5cc28462120ef28be52a9a4aba7f"
MAX_JSON_DEPTH = 128
GIT_REDIRECT_ENV_VARS = (
    "GIT_DIR",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
)

# The merged PR entries use the fixture's canonical recorded order, not a claim
# about issue-defined ordering or when the commits landed. The validator
# separately checks that every commit is an ancestor of the pinned merged dev
# head. Artifact paths below use canonical lexicographic ordering.
MERGED_PRS = (
    (221, "203dfca63eb073e5d4ddc27921447b5d0ab64a51"),
    (216, "8465bd4cacc87fe62ff952c38d7f3c2b5927bfbd"),
    (218, "c3c29992a85737dc0487772947780ed3239705fd"),
    (219, "41211da8e27c4dceeeac5782208d8140034a19de"),
    (220, "f32d4782b041a12347acba2d7d36172594dec6f7"),
)

# This is the complete, ordered artifact set that existed on the merged dev
# commit. It intentionally excludes this compatibility-gate directory: the
# gate records and verifies the already-merged audit artifacts without creating
# a self-referential digest.
ARTIFACT_PATHS = (
    "contracts/fixtures/source-audit/model-options/absent.json",
    "contracts/fixtures/source-audit/model-options/empty.json",
    "contracts/fixtures/source-audit/model-options/malformed.json",
    "contracts/fixtures/source-audit/model-options/present.json",
    "contracts/fixtures/source-audit/model-options/test_model_options.py",
    "contracts/fixtures/source-audit/model-options/unknown-operation.json",
    "contracts/fixtures/source-audit/native-bearer/README.md",
    "contracts/fixtures/source-audit/native-bearer/cases.json",
    "contracts/fixtures/source-audit/native-bearer/source_audit.json",
    "contracts/fixtures/source-audit/native-bearer/test_native_bearer.py",
    "contracts/fixtures/source-audit/oauth-browser/README.md",
    "contracts/fixtures/source-audit/oauth-browser/cases.json",
    "contracts/fixtures/source-audit/oauth-browser/source_audit.json",
    "contracts/fixtures/source-audit/oauth-browser/source_excerpts/cookies.py.txt",
    "contracts/fixtures/source-audit/oauth-browser/source_excerpts/nous_provider.py.txt",
    "contracts/fixtures/source-audit/oauth-browser/source_excerpts/routes_auth.py.txt",
    "contracts/fixtures/source-audit/oauth-browser/test_oauth_browser.py",
    "contracts/fixtures/source-audit/planning-reconciliation/README.md",
    "contracts/fixtures/source-audit/planning-reconciliation/planning_review.json",
    "contracts/fixtures/source-audit/planning-reconciliation/test_validate.py",
    "contracts/fixtures/source-audit/planning-reconciliation/validate.py",
    "contracts/fixtures/source-audit/pty-attach/README.md",
    "contracts/fixtures/source-audit/pty-attach/pty-attach-fixtures.json",
    "contracts/fixtures/source-audit/pty-attach/source-evidence.json",
    "contracts/fixtures/source-audit/pty-attach/validate.py",
    "contracts/fixtures/source-audit/pty-attach/validation-baseline.json",
    "contracts/hermes-dashboard/model-options/README.md",
    "contracts/hermes-dashboard/model-options/source-audit.json",
)

ROOT_KEYS = (
    "schema",
    "operation",
    "contract",
    "source",
    "merged_dev",
    "integration_dev",
    "artifacts",
    "observations",
    "status",
    "redaction",
    "blockers",
)
SOURCE_KEYS = ("repository", "sha")
MERGED_DEV_KEYS = ("ref", "head", "tree", "merged_prs")
INTEGRATION_DEV_KEYS = ("ref", "head", "tree")
MERGED_PR_KEYS = ("number", "merge_commit")
ARTIFACTS_KEYS = ("algorithm", "files", "set_sha256")
ARTIFACT_KEYS = ("path", "sha256", "size_bytes")
OBSERVATIONS_KEYS = ("artifact_size_bytes", "validator_duration_ms", "repetitions")
DURATION_KEYS = ("min", "p50", "p95", "max", "mean")
STATUS_KEYS = (
    "compatible",
    "live_run",
    "deployment_attestation",
    "behavioral_probe",
    "proxy_proof",
    "parity_evidence",
    "benchmark_evidence",
)
REDACTION_KEYS = (
    "synthetic_only",
    "contains_credentials",
    "contains_hosts",
    "contains_raw_tickets",
    "contains_prompts",
    "contains_transcripts",
    "contains_pty_bytes",
)
EXPECTED_STATUS = {
    "compatible": False,
    "live_run": False,
    "deployment_attestation": "absent",
    "behavioral_probe": "not_run",
    "proxy_proof": "not_run",
    "parity_evidence": "not_recorded",
    "benchmark_evidence": "not_recorded",
}
EXPECTED_REDACTION = {
    "synthetic_only": True,
    "contains_credentials": False,
    "contains_hosts": False,
    "contains_raw_tickets": False,
    "contains_prompts": False,
    "contains_transcripts": False,
    "contains_pty_bytes": False,
}
EXPECTED_BLOCKERS = (
    "deployment_attestation_absent",
    "behavioral_probe_not_run",
    "proxy_proof_not_run",
    "parity_and_accessibility_evidence_not_recorded",
    "benchmark_evidence_not_recorded",
    "fixture_only_scope_cannot_close_live_compatibility_gate",
)

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b", re.IGNORECASE),
    re.compile(r"\b(?:ghp|github_pat|glpat|sk|xox[baprs])[-_][A-Za-z0-9_-]{8,}\b", re.IGNORECASE),
    re.compile(r"\bBearer\s+\S+", re.IGNORECASE),
    re.compile(r"\bBasic\s+[A-Za-z0-9+/=_-]{12,}", re.IGNORECASE),
)
FORBIDDEN_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "authorization",
        "bearer",
        "cookie",
        "cookie_value",
        "credential",
        "credentials",
        "host",
        "hostname",
        "password",
        "prompt",
        "pty_bytes",
        "raw_handle",
        "raw_ticket",
        "secret",
        "session_token",
        "ticket",
        "ticket_value",
        "token",
        "transcript",
        "user_data",
    }
)


class ValidationError(AssertionError):
    """Raised when a compatibility record violates its closed contract."""


class DuplicateKeyError(ValueError):
    """Raised before JSON data can hide a duplicate object key."""


class NonFiniteJSONError(ValueError):
    """Raised when JSON numeric syntax would produce NaN or infinity."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def strict_keys(value: Any, expected: tuple[str, ...], label: str) -> dict[str, Any]:
    require(type(value) is dict, f"{label} must be an object")
    require(tuple(value.keys()) == expected, f"{label} keys or ordering changed")
    return value


def strict_equal(actual: Any, expected: Any, label: str) -> None:
    require(type(actual) is type(expected), f"{label} has the wrong type")
    if isinstance(expected, dict):
        require(tuple(actual.keys()) == tuple(expected.keys()), f"{label} keys or ordering changed")
        for key, expected_value in expected.items():
            strict_equal(actual[key], expected_value, f"{label}.{key}")
        return
    if isinstance(expected, list):
        require(len(actual) == len(expected), f"{label} length changed")
        for index, (actual_value, expected_value) in enumerate(zip(actual, expected)):
            strict_equal(actual_value, expected_value, f"{label}[{index}]")
        return
    require(actual == expected, f"{label} value changed")


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_nonfinite_json_constant(value: str) -> Any:
    raise NonFiniteJSONError(f"non-finite JSON number is not allowed: {value}")


def _finite_json_float(value: str) -> float:
    try:
        result = float(value)
    except (OverflowError, ValueError):
        raise NonFiniteJSONError(f"malformed JSON number: {value}") from None
    if not math.isfinite(result):
        raise NonFiniteJSONError(f"non-finite JSON number is not allowed: {value}")
    return result


def _validate_json_tree(value: Any, context: str = "record", depth: int = 0) -> None:
    """Reject unsupported values and hostile nesting before schema validation."""
    require(depth <= MAX_JSON_DEPTH, f"{context}: maximum JSON nesting depth exceeded")
    if type(value) is dict:
        for key, child in value.items():
            require(type(key) is str, f"{context}: object keys must be text")
            _validate_json_tree(child, f"{context}.{key}", depth + 1)
        return
    if type(value) is list:
        for index, child in enumerate(value):
            _validate_json_tree(child, f"{context}[{index}]", depth + 1)
        return
    if type(value) is float:
        require(math.isfinite(value), f"{context}: non-finite number is not allowed")
        return
    require(value is None or type(value) in (str, bool, int), f"{context}: unsupported JSON value type")


def load_record(path: Path = RECORD_PATH) -> dict[str, Any]:
    """Load one bounded JSON document without silently coercing hostile values."""
    try:
        text = path.read_text(encoding="utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_nonfinite_json_constant,
            parse_float=_finite_json_float,
        )
        _validate_json_tree(value)
    except DuplicateKeyError:
        raise
    except ValidationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, NonFiniteJSONError, RecursionError, ValueError) as exc:
        raise ValidationError(f"cannot read compatibility record {path}: {exc}") from None
    require(type(value) is dict, "compatibility record must be an object")
    return value


def _is_unsafe_relative_path(value: str) -> bool:
    """Reject POSIX, Windows, NUL, and lexical traversal forms before resolution."""
    if type(value) is not str or not value or "\\" in value or "\x00" in value:
        return True
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    return (
        Path(value).is_absolute()
        or posix.is_absolute()
        or windows.is_absolute()
        or any(part == ".." for part in posix.parts)
        or any(part == ".." for part in windows.parts)
    )


def resolve_under_root(root: Path, relative: str) -> Path:
    """Resolve a path and reject symlinks that escape the approved root."""
    require(type(relative) is str, "artifact path must be text")
    require(
        not _is_unsafe_relative_path(relative),
        f"artifact path must be relative POSIX text without '..': {relative!r}",
    )
    try:
        root_resolved = root.resolve(strict=False)
        resolved = (root_resolved / relative).resolve(strict=False)
        resolved.relative_to(root_resolved)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValidationError(f"artifact path escapes repository root: {relative!r}") from exc
    return resolved


def _strict_git_environment() -> dict[str, str]:
    """Keep every Git read on this checkout's local object database."""
    environment = os.environ.copy()
    # Clear all Git-controlled redirects, including config-driven object and
    # repository overrides. The two safety flags are set only after the purge.
    for variable in tuple(environment):
        if variable.startswith("GIT_"):
            environment.pop(variable, None)
    for variable in GIT_REDIRECT_ENV_VARS:
        environment.pop(variable, None)
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment["GIT_NO_LAZY_FETCH"] = "1"
    return environment


def _git_run(repo_root: Path, args: list[str], *, text: bool) -> subprocess.CompletedProcess[Any]:
    return subprocess.run(
        ["git", "-C", str(repo_root), *args],
        check=False,
        capture_output=True,
        text=text,
        env=_strict_git_environment(),
    )


def _git_revision(repo_root: Path, expression: str) -> str | None:
    try:
        result = _git_run(
            repo_root,
            ["rev-parse", "--verify", "--end-of-options", expression],
            text=True,
        )
    except (OSError, UnicodeError):
        return None
    if result.returncode != 0 or not isinstance(result.stdout, str):
        return None
    revision = result.stdout.strip()
    if "\n" in revision or HEX40.fullmatch(revision) is None:
        return None
    return revision


def _git_commit_oid(repo_root: Path, expression: str) -> str | None:
    """Resolve and type-check one full commit OID without replacement refs."""
    if type(expression) is not str or not expression:
        return None
    return _git_revision(repo_root, f"{expression}^{{commit}}")


def _git_tree_oid(repo_root: Path, commit_oid: str) -> str | None:
    if type(commit_oid) is not str or HEX40.fullmatch(commit_oid) is None:
        return None
    return _git_revision(repo_root, f"{commit_oid}^{{tree}}")


def _git_blob(repo_root: Path, commit_oid: str, relative: str) -> bytes | None:
    """Read type, size, and bytes from one immutable cat-file batch response."""
    if type(commit_oid) is not str or HEX40.fullmatch(commit_oid) is None or _is_unsafe_relative_path(relative):
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "cat-file", "--batch"],
            input=f"{commit_oid}:{relative}\n".encode("utf-8"),
            check=False,
            capture_output=True,
            env=_strict_git_environment(),
        )
    except OSError:
        return None
    if result.returncode != 0 or not isinstance(result.stdout, bytes):
        return None

    header, separator, payload = result.stdout.partition(b"\n")
    if separator != b"\n":
        return None
    fields = header.split(b" ")
    if len(fields) == 2 and fields[1] == b"missing":
        return None
    if len(fields) != 3 or re.fullmatch(rb"[0-9a-f]{40}", fields[0]) is None:
        return None
    if fields[1] != b"blob" or not fields[2].isdigit() or len(fields[2]) > 20:
        return None
    try:
        object_size = int(fields[2], 10)
    except (TypeError, ValueError, OverflowError):
        return None
    if len(payload) != object_size + 1 or payload[-1:] != b"\n":
        return None
    return payload[:object_size]


def _git_object_exists(repo_root: Path, revision: str) -> bool:
    return _git_commit_oid(repo_root, revision) is not None


def _is_ancestor(repo_root: Path, ancestor: str, descendant: str) -> bool:
    if (
        type(ancestor) is not str
        or type(descendant) is not str
        or HEX40.fullmatch(ancestor) is None
        or HEX40.fullmatch(descendant) is None
    ):
        return False
    try:
        result = _git_run(repo_root, ["merge-base", "--is-ancestor", ancestor, descendant], text=False)
    except OSError:
        return False
    return result.returncode == 0


def _validate_shape(record: dict[str, Any]) -> None:
    strict_keys(record, ROOT_KEYS, "record")
    require(record["schema"] == SCHEMA, "record schema changed")
    require(record["operation"] == OPERATION, "record operation changed")
    require(record["contract"] == CONTRACT, "record contract changed")

    source = strict_keys(record["source"], SOURCE_KEYS, "record.source")
    require(source["repository"] == HERMES_REPOSITORY, "record source repository changed")
    require(source["sha"] == HERMES_SHA, "record source SHA changed")

    merged = strict_keys(record["merged_dev"], MERGED_DEV_KEYS, "record.merged_dev")
    require(merged["ref"] == DEV_REF, "record merged dev ref changed")
    require(type(merged["head"]) is str and HEX40.fullmatch(merged["head"]) is not None, "record historical dev head is not a full SHA")
    require(merged["head"] == HISTORICAL_DEV_HEAD, "record historical dev head changed")
    require(type(merged["tree"]) is str and HEX40.fullmatch(merged["tree"]) is not None, "record historical dev tree is not a full SHA")
    require(merged["tree"] == HISTORICAL_DEV_TREE, "record historical dev tree changed")
    prs = merged["merged_prs"]
    require(type(prs) is list, "record merged_prs must be a list")
    require(len(prs) == len(MERGED_PRS), "record merged_prs length changed")
    for index, (entry, (expected_number, expected_commit)) in enumerate(zip(prs, MERGED_PRS)):
        item = strict_keys(entry, MERGED_PR_KEYS, f"record.merged_dev.merged_prs[{index}]")
        require(type(item["number"]) is int, f"merged PR {index} number must be an integer")
        require(item["number"] == expected_number, f"merged PR order or number changed at index {index}")
        require(type(item["merge_commit"]) is str and HEX40.fullmatch(item["merge_commit"]) is not None, f"merged PR {expected_number} commit is not a full SHA")
        require(item["merge_commit"] == expected_commit, f"merged PR #{expected_number} commit changed")

    integration = strict_keys(record["integration_dev"], INTEGRATION_DEV_KEYS, "record.integration_dev")
    require(integration["ref"] == DEV_REF, "record integration dev ref changed")
    require(type(integration["head"]) is str and HEX40.fullmatch(integration["head"]) is not None, "record integration dev head is not a full SHA")
    require(type(integration["tree"]) is str and HEX40.fullmatch(integration["tree"]) is not None, "record integration dev tree is not a full SHA")

    artifacts = strict_keys(record["artifacts"], ARTIFACTS_KEYS, "record.artifacts")
    require(artifacts["algorithm"] == "sha256", "artifact digest algorithm changed")
    files = artifacts["files"]
    require(type(files) is list, "record.artifacts.files must be a list")
    require(len(files) == len(ARTIFACT_PATHS), "artifact file count changed")
    seen: set[str] = set()
    for index, entry in enumerate(files):
        item = strict_keys(entry, ARTIFACT_KEYS, f"record.artifacts.files[{index}]")
        path = item["path"]
        require(type(path) is str and path, f"artifact path {index} is missing")
        require(path not in seen, f"duplicate artifact path: {path}")
        seen.add(path)
        require(path == ARTIFACT_PATHS[index], f"artifact path/order changed at index {index}")
        require(type(item["sha256"]) is str and HEX64.fullmatch(item["sha256"]) is not None, f"invalid artifact SHA at index {index}")
        require(type(item["size_bytes"]) is int and item["size_bytes"] >= 0, f"invalid artifact size at index {index}")
    require(type(artifacts["set_sha256"]) is str and HEX64.fullmatch(artifacts["set_sha256"]) is not None, "artifact set SHA is not a full digest")

    observations = strict_keys(record["observations"], OBSERVATIONS_KEYS, "record.observations")
    require(type(observations["artifact_size_bytes"]) is int and observations["artifact_size_bytes"] >= 0, "observed artifact size must be a non-negative integer")
    require(observations["artifact_size_bytes"] == sum(item["size_bytes"] for item in files), "observed artifact size is stale")
    duration = strict_keys(observations["validator_duration_ms"], DURATION_KEYS, "record.observations.validator_duration_ms")
    require(type(observations["repetitions"]) is int and observations["repetitions"] > 0, "observation repetitions must be a positive integer")
    for name, value in duration.items():
        if type(value) is int:
            require(value >= 0, f"observed duration {name} must be non-negative")
        elif type(value) is float:
            require(math.isfinite(value) and value >= 0, f"observed duration {name} must be finite and non-negative")
        else:
            raise ValidationError(f"observed duration {name} must be numeric")

    status = strict_keys(record["status"], STATUS_KEYS, "record.status")
    strict_equal(status, EXPECTED_STATUS, "record.status")
    redaction = strict_keys(record["redaction"], REDACTION_KEYS, "record.redaction")
    strict_equal(redaction, EXPECTED_REDACTION, "record.redaction")

    blockers = record["blockers"]
    require(type(blockers) is list, "record.blockers must be a list")
    require(tuple(blockers) == EXPECTED_BLOCKERS, "record blockers or ordering changed")


def _validate_redaction(value: Any, path: str = "$") -> None:
    """Reject credential-shaped data and raw operational material recursively."""
    if isinstance(value, dict):
        for key, child in value.items():
            require(type(key) is str, f"{path}: object keys must be text")
            normalized = key.casefold().replace("-", "_")
            # The explicit contains_* redaction flags are policy metadata, not
            # captured material; all other sensitive key names are blocked.
            if not normalized.startswith("contains_"):
                require(normalized not in FORBIDDEN_KEYS, f"{path}.{key}: prohibited sensitive key")
            _validate_redaction(child, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _validate_redaction(child, f"{path}[{index}]")
        return
    if isinstance(value, str):
        for pattern in SECRET_PATTERNS:
            require(pattern.search(value) is None, f"{path}: credential-shaped value")
        require("\x00" not in value, f"{path}: embedded NUL is not allowed")


def _git_ref_exists(repo_root: Path, ref: str) -> bool:
    try:
        result = _git_run(repo_root, ["show-ref", "--verify", "--quiet", ref], text=False)
    except OSError:
        return False
    return result.returncode == 0


def _local_dev_commit_oid(repo_root: Path) -> str | None:
    """Choose one local dev ref, never a branch name without its full OID."""
    for ref in ("refs/heads/dev", "refs/remotes/origin/dev"):
        if _git_ref_exists(repo_root, ref):
            return _git_commit_oid(repo_root, ref)
    return None


def _validate_merged_dev(repo_root: Path, record: dict[str, Any]) -> str:
    """Validate the immutable historical review independent of moving dev."""
    merged = record["merged_dev"]
    historical_oid = merged["head"]
    require(_git_commit_oid(repo_root, historical_oid) == historical_oid, "historical reviewed commit is unavailable locally")
    require(_git_tree_oid(repo_root, historical_oid) == merged["tree"], "historical reviewed tree digest changed")

    for number, merge_commit in MERGED_PRS:
        require(_git_commit_oid(repo_root, merge_commit) == merge_commit, f"merged PR #{number} commit is unavailable locally")
        require(_is_ancestor(repo_root, merge_commit, historical_oid), f"merged PR #{number} is not an ancestor of historical reviewed dev")
    return historical_oid


def _validate_integration_dev(repo_root: Path, record: dict[str, Any]) -> str:
    """Validate the explicit current-dev snapshot and its ancestry."""
    integration = record["integration_dev"]
    current_oid = integration["head"]
    local_oid = _local_dev_commit_oid(repo_root)
    require(local_oid is not None, "current dev ref is unavailable locally")
    require(local_oid == current_oid, f"current dev ref is not the recorded integration commit: {local_oid}")
    require(_git_commit_oid(repo_root, current_oid) == current_oid, "current integration commit is unavailable locally")
    require(_git_tree_oid(repo_root, current_oid) == integration["tree"], "current integration tree digest changed")
    require(
        _is_ancestor(repo_root, record["merged_dev"]["head"], current_oid),
        "current integration commit does not descend from the historical review",
    )
    return current_oid


def _artifact_set_digest(files: Iterable[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for item in files:
        canonical = f"{item['path']}\0{item['sha256']}\0{item['size_bytes']}\n"
        digest.update(canonical.encode("utf-8"))
    return digest.hexdigest()


def _validate_artifacts(repo_root: Path, record: dict[str, Any], commit_oid: str, evidence_label: str) -> int:
    files = record["artifacts"]["files"]
    for item in files:
        # Resolve the mutable worktree path as a containment check. Content is
        # still read from immutable Git storage below, so a changed worktree
        # cannot forge a digest by replacing a file or symlink.
        resolve_under_root(repo_root, item["path"])

        blob = _git_blob(repo_root, commit_oid, item["path"])
        require(blob is not None, f"missing {evidence_label} artifact blob: {item['path']}")
        actual_sha = hashlib.sha256(blob).hexdigest()
        require(actual_sha == item["sha256"], f"{evidence_label} artifact digest mismatch: {item['path']}")
        require(len(blob) == item["size_bytes"], f"{evidence_label} artifact size mismatch: {item['path']}")

    require(
        _artifact_set_digest(files) == record["artifacts"]["set_sha256"],
        "artifact set digest mismatch",
    )
    return len(files)


def validate_record(record: dict[str, Any], repo_root: Path, *, verify_git: bool = True) -> int:
    """Validate historical evidence and the explicitly pinned dev integration."""
    _validate_json_tree(record)
    _validate_shape(record)
    _validate_redaction(record)
    if verify_git:
        historical_oid = _validate_merged_dev(repo_root, record)
        current_oid = _validate_integration_dev(repo_root, record)
        historical_count = _validate_artifacts(repo_root, record, historical_oid, "historical")
        current_count = _validate_artifacts(repo_root, record, current_oid, "current")
        require(current_count == historical_count, "historical and current artifact counts differ")
        return current_count
    return len(record["artifacts"]["files"])


def default_repo_root() -> Path:
    # validate.py lives four directories below the repository root.
    return ROOT.parents[3]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=default_repo_root(),
        help="local checkout containing the recorded current dev integration ref",
    )
    parser.add_argument(
        "--record",
        type=Path,
        default=ROOT / RECORD_NAME,
        help="compatibility record JSON path",
    )
    args = parser.parse_args(argv)

    started = time.perf_counter()
    errors: list[str] = []
    artifact_count = 0
    record: dict[str, Any] | None = None
    try:
        record = load_record(args.record.resolve())
        artifact_count = validate_record(record, args.repo_root.resolve())
    except (ValidationError, DuplicateKeyError, OSError, UnicodeError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        errors.append(str(exc))
    duration_ms = (time.perf_counter() - started) * 1000
    result = {
        "ok": not errors,
        "compatible": False,
        "live_run": False,
        "artifact_count": artifact_count,
        "artifact_size_bytes": sum(item["size_bytes"] for item in record["artifacts"]["files"]) if record is not None and not errors else 0,
        "duration_ms": round(duration_ms, 3),
        "evidence_scope": "historical_review_and_current_dev_integration" if not errors else "unverified",
        "historical_reviewed_commit": record["merged_dev"]["head"] if record is not None and not errors else None,
        "verified_commit": record["integration_dev"]["head"] if record is not None and not errors else None,
        "verified_commit_kind": "current_dev_integration" if not errors else None,
        "errors": errors,
    }
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
