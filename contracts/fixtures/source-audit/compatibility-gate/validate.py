#!/usr/bin/env python3
"""Validate the synthetic, source-only compatibility gate record.

This validator is deliberately offline. It reads the checked-in JSON record and
immutable Git blobs from the locally available merged ``dev`` commit. It never
contacts Hermes, a proxy, an identity provider, or a deployment. A record can
therefore prove only that the reviewed fixture artifacts are the exact bytes
recorded for the selected ``dev`` revision; it cannot turn missing deployment
or behavioral evidence into compatibility.
"""

from __future__ import annotations

import argparse
import hashlib
import json
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
DEV_HEAD = "8465bd4cacc87fe62ff952c38d7f3c2b5927bfbd"
DEV_TREE = "aede9b87932f5cc28462120ef28be52a9a4aba7f"

# The order is the issue's requested audit order, not a claim about when the
# merge commits landed. The validator separately checks that every commit is
# an ancestor of the pinned merged dev head.
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
    "artifacts",
    "status",
    "redaction",
    "blockers",
)
SOURCE_KEYS = ("repository", "sha")
MERGED_DEV_KEYS = ("ref", "head", "tree", "merged_prs")
MERGED_PR_KEYS = ("number", "merge_commit")
ARTIFACTS_KEYS = ("algorithm", "files", "set_sha256")
ARTIFACT_KEYS = ("path", "sha256", "size_bytes")
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


def load_record(path: Path = RECORD_PATH) -> dict[str, Any]:
    """Load JSON while rejecting duplicate keys at every nesting level."""
    try:
        text = path.read_text(encoding="utf-8")
        value = json.loads(text, object_pairs_hook=_object_without_duplicate_keys)
    except DuplicateKeyError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"cannot read compatibility record {path}: {exc}") from exc
    require(type(value) is dict, "compatibility record must be an object")
    return value


def _is_unsafe_relative_path(value: str) -> bool:
    """Reject POSIX, Windows, and lexical traversal forms before resolution."""
    if not value or "\\" in value:
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


def _git_run(repo_root: Path, args: list[str], *, text: bool) -> subprocess.CompletedProcess[Any]:
    env = os.environ.copy()
    # The record must never turn a missing local blob into an implicit network fetch.
    env["GIT_NO_LAZY_FETCH"] = "1"
    return subprocess.run(
        ["git", "-C", str(repo_root), *args],
        check=False,
        capture_output=True,
        text=text,
        env=env,
    )


def _git_revision(repo_root: Path, expression: str) -> str | None:
    try:
        result = _git_run(repo_root, ["rev-parse", "--verify", expression], text=True)
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _git_blob(repo_root: Path, revision: str, relative: str) -> bytes | None:
    try:
        result = _git_run(repo_root, ["cat-file", "blob", f"{revision}:{relative}"], text=False)
    except OSError:
        return None
    if result.returncode != 0 or not isinstance(result.stdout, bytes):
        return None
    return result.stdout


def _git_object_exists(repo_root: Path, revision: str) -> bool:
    try:
        result = _git_run(repo_root, ["cat-file", "-e", f"{revision}^{{commit}}"], text=False)
    except OSError:
        return False
    return result.returncode == 0


def _is_ancestor(repo_root: Path, ancestor: str, descendant: str) -> bool:
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
    require(type(merged["head"]) is str and HEX40.fullmatch(merged["head"]) is not None, "record dev head is not a full SHA")
    require(merged["head"] == DEV_HEAD, "record merged dev head changed")
    require(type(merged["tree"]) is str and HEX40.fullmatch(merged["tree"]) is not None, "record dev tree is not a full SHA")
    require(merged["tree"] == DEV_TREE, "record merged dev tree changed")
    prs = merged["merged_prs"]
    require(type(prs) is list, "record merged_prs must be a list")
    require(len(prs) == len(MERGED_PRS), "record merged_prs length changed")
    for index, (entry, (expected_number, expected_commit)) in enumerate(zip(prs, MERGED_PRS)):
        item = strict_keys(entry, MERGED_PR_KEYS, f"record.merged_dev.merged_prs[{index}]")
        require(type(item["number"]) is int, f"merged PR {index} number must be an integer")
        require(item["number"] == expected_number, f"merged PR order or number changed at index {index}")
        require(type(item["merge_commit"]) is str and HEX40.fullmatch(item["merge_commit"]) is not None, f"merged PR {expected_number} commit is not a full SHA")
        require(item["merge_commit"] == expected_commit, f"merged PR #{expected_number} commit changed")

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


def _validate_merged_dev(repo_root: Path, record: dict[str, Any]) -> None:
    merged = record["merged_dev"]
    local_dev = _git_revision(repo_root, "refs/heads/dev")
    if local_dev is None:
        local_dev = _git_revision(repo_root, "refs/remotes/origin/dev")
    require(local_dev == DEV_HEAD, f"local dev ref is not the pinned merged commit: {local_dev or 'unavailable'}")
    require(_git_revision(repo_root, f"{DEV_HEAD}^{{tree}}") == DEV_TREE, "merged dev tree digest changed")
    require(_git_object_exists(repo_root, DEV_HEAD), "merged dev commit is unavailable locally")

    for number, merge_commit in MERGED_PRS:
        require(_git_object_exists(repo_root, merge_commit), f"merged PR #{number} commit is unavailable locally")
        require(_is_ancestor(repo_root, merge_commit, DEV_HEAD), f"merged PR #{number} is not an ancestor of merged dev")


def _artifact_set_digest(files: Iterable[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for item in files:
        canonical = f"{item['path']}\0{item['sha256']}\0{item['size_bytes']}\n"
        digest.update(canonical.encode("utf-8"))
    return digest.hexdigest()


def _validate_artifacts(repo_root: Path, record: dict[str, Any]) -> int:
    files = record["artifacts"]["files"]
    for item in files:
        # Resolve the mutable worktree path as a containment check. Content is
        # still read from immutable Git storage below, so a changed worktree
        # cannot forge a digest by replacing a file or symlink.
        resolve_under_root(repo_root, item["path"])

        blob = _git_blob(repo_root, DEV_HEAD, item["path"])
        require(blob is not None, f"missing merged-dev artifact blob: {item['path']}")
        actual_sha = hashlib.sha256(blob).hexdigest()
        require(actual_sha == item["sha256"], f"artifact digest mismatch: {item['path']}")
        require(len(blob) == item["size_bytes"], f"artifact size mismatch: {item['path']}")

    require(
        _artifact_set_digest(files) == record["artifacts"]["set_sha256"],
        "artifact set digest mismatch",
    )
    return len(files)


def validate_record(record: dict[str, Any], repo_root: Path, *, verify_git: bool = True) -> int:
    """Validate a record and return its immutable artifact count."""
    _validate_shape(record)
    _validate_redaction(record)
    if verify_git:
        _validate_merged_dev(repo_root, record)
        return _validate_artifacts(repo_root, record)
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
        help="local checkout containing the pinned merged dev ref",
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
    try:
        record = load_record(args.record.resolve())
        artifact_count = validate_record(record, args.repo_root.resolve())
    except (ValidationError, DuplicateKeyError, OSError, UnicodeError, TypeError, ValueError) as exc:
        errors.append(str(exc))
    duration_ms = (time.perf_counter() - started) * 1000
    result = {
        "ok": not errors,
        "compatible": False,
        "live_run": False,
        "artifact_count": artifact_count,
        "duration_ms": round(duration_ms, 3),
        "errors": errors,
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
