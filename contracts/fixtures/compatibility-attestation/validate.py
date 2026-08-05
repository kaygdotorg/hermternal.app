#!/usr/bin/env python3
"""Validate the synthetic out-of-band revision-attestation contract.

This validator is intentionally offline. It reads only the checked-in JSON
fixtures and immutable Git blobs for the reviewed policy evidence. It never
contacts Hermes, a Dashboard, a proxy, an identity provider, or a deployment.
A passing result verifies the attestation shape and evidence bindings; it does
not claim a live deployment or replace the independent behavioral probe.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any


ROOT = Path(__file__).resolve().parent
ATTESTATION_PATH = ROOT / "revision_attestation.json"
CASES_PATH = ROOT / "cases.json"
BASELINE_PATH = ROOT / "validation-baseline.json"
SCHEMA = "hermternal.revision-attestation.v1"
FIXTURE_SCHEMA = "hermternal.revision-attestation-fixtures.v1"
BASELINE_SCHEMA = "hermternal.revision-attestation-baseline.v1"
OPERATION = "C-04"
CONTRACT = "dashboard-v0.0.1"
HERMES_REPOSITORY = "NousResearch/hermes-agent"
HERMES_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
VALIDATOR_PATH = "contracts/fixtures/compatibility-attestation/validate.py"
VALIDATOR_COMMAND = "python3 contracts/fixtures/compatibility-attestation/validate.py"
ATTESTATION_RELATIVE = "contracts/fixtures/compatibility-attestation/revision_attestation.json"
CASES_RELATIVE = "contracts/fixtures/compatibility-attestation/cases.json"
BASELINE_RELATIVE = "contracts/fixtures/compatibility-attestation/validation-baseline.json"
BASELINE_ENVIRONMENT = {
    "platform": "macOS-26.5.2-arm64-arm-64bit-Mach-O",
    "python": "3.14.6",
}

ATTESTATION_ROOT_KEYS = (
    "schema",
    "operation",
    "contract",
    "hermes",
    "deployment",
    "route_manifest",
    "source_review",
    "proxy_proof",
    "dashboard_metadata",
    "requirements",
    "redaction",
)
CASES_ROOT_KEYS = (
    "schema",
    "operation",
    "contract",
    "pinned_source_sha",
    "cases",
    "redaction",
)
BASELINE_ROOT_KEYS = (
    "schema",
    "validator",
    "command",
    "build_mode",
    "artifact_files",
    "artifact_bytes",
    "environment",
    "repetitions",
    "duration_ms",
    "threshold",
)

EXPECTED_REDACTION = {
    "synthetic_only": True,
    "contains_credentials": False,
    "contains_hosts": False,
    "contains_auth_material": False,
    "contains_raw_tickets": False,
    "contains_prompts": False,
    "contains_transcripts": False,
    "contains_user_data": False,
}

EVIDENCE = {
    "route_manifest": {
        "path": "contracts/hermes-dashboard/manifest.md",
        "contract_revision": CONTRACT,
        "sha256": "3c6b44dc8dd90836f4fc5c5158d459959c569fb811db4b198e87d78ea5010197",
        "size_bytes": 17859,
    },
    "source_review": {
        "path": "contracts/fixtures/source-audit/planning-reconciliation/planning_review.json",
        "sha256": "0a84cba82e6e966ab35de187f560fd38d6e10c43dd2204062d6ebf2bc5c32077",
        "size_bytes": 20045,
    },
    "proxy_proof": {
        "path": "docs/deployment/proof-matrix.md",
        "sha256": "52fb8d0fb9f21ee7a80c5796343c3893a7f715c93fd47e832f5be098bc865212",
        "size_bytes": 16167,
    },
}

BASELINE_ARTIFACT_PATHS = (
    "contracts/fixtures/compatibility-attestation/README.md",
    "contracts/fixtures/compatibility-attestation/revision_attestation.json",
    "contracts/fixtures/compatibility-attestation/cases.json",
    "contracts/fixtures/compatibility-attestation/validate.py",
    "contracts/fixtures/compatibility-attestation/test_validate.py",
)

CASE_SPECS = (
    (
        "valid_attestation_pending_probe",
        {
            "attestation": "present",
            "revision": "pinned",
            "route_manifest": "match",
            "source_review": "match",
            "proxy_proof": "match",
            "behavioral_probe": "not_run",
            "dashboard_metadata": "absent",
        },
        {"attestation_result": "verified", "runtime_gate": "blocked_pending_probe"},
    ),
    (
        "valid_attestation_with_probe",
        {
            "attestation": "present",
            "revision": "pinned",
            "route_manifest": "match",
            "source_review": "match",
            "proxy_proof": "match",
            "behavioral_probe": "passed",
            "dashboard_metadata": "absent",
        },
        {"attestation_result": "verified", "runtime_gate": "separate_probe_gate"},
    ),
    (
        "missing_attestation",
        {
            "attestation": "missing",
            "revision": "unknown",
            "route_manifest": "not_checked",
            "source_review": "not_checked",
            "proxy_proof": "not_checked",
            "behavioral_probe": "not_run",
            "dashboard_metadata": "absent",
        },
        {"attestation_result": "blocked", "runtime_gate": "blocked_incompatible"},
    ),
    (
        "empty_attestation",
        {
            "attestation": "empty",
            "revision": "unknown",
            "route_manifest": "not_checked",
            "source_review": "not_checked",
            "proxy_proof": "not_checked",
            "behavioral_probe": "not_run",
            "dashboard_metadata": "absent",
        },
        {"attestation_result": "blocked", "runtime_gate": "blocked_incompatible"},
    ),
    (
        "malformed_attestation",
        {
            "attestation": "malformed",
            "revision": "unknown",
            "route_manifest": "not_checked",
            "source_review": "not_checked",
            "proxy_proof": "not_checked",
            "behavioral_probe": "not_run",
            "dashboard_metadata": "absent",
        },
        {"attestation_result": "blocked", "runtime_gate": "blocked_incompatible"},
    ),
    (
        "unknown_revision",
        {
            "attestation": "present",
            "revision": "unknown",
            "route_manifest": "match",
            "source_review": "match",
            "proxy_proof": "match",
            "behavioral_probe": "not_run",
            "dashboard_metadata": "absent",
        },
        {"attestation_result": "blocked", "runtime_gate": "blocked_incompatible"},
    ),
    (
        "abbreviated_revision",
        {
            "attestation": "present",
            "revision": "abbreviated",
            "route_manifest": "match",
            "source_review": "match",
            "proxy_proof": "match",
            "behavioral_probe": "not_run",
            "dashboard_metadata": "absent",
        },
        {"attestation_result": "blocked", "runtime_gate": "blocked_incompatible"},
    ),
    (
        "mismatched_revision",
        {
            "attestation": "present",
            "revision": "mismatched",
            "route_manifest": "match",
            "source_review": "match",
            "proxy_proof": "match",
            "behavioral_probe": "not_run",
            "dashboard_metadata": "absent",
        },
        {"attestation_result": "blocked", "runtime_gate": "blocked_incompatible"},
    ),
    (
        "mismatched_route_manifest",
        {
            "attestation": "present",
            "revision": "pinned",
            "route_manifest": "mismatch",
            "source_review": "match",
            "proxy_proof": "match",
            "behavioral_probe": "not_run",
            "dashboard_metadata": "absent",
        },
        {"attestation_result": "blocked", "runtime_gate": "blocked_incompatible"},
    ),
    (
        "mismatched_source_review",
        {
            "attestation": "present",
            "revision": "pinned",
            "route_manifest": "match",
            "source_review": "mismatch",
            "proxy_proof": "match",
            "behavioral_probe": "not_run",
            "dashboard_metadata": "absent",
        },
        {"attestation_result": "blocked", "runtime_gate": "blocked_incompatible"},
    ),
    (
        "mismatched_proxy_proof",
        {
            "attestation": "present",
            "revision": "pinned",
            "route_manifest": "match",
            "source_review": "match",
            "proxy_proof": "mismatch",
            "behavioral_probe": "not_run",
            "dashboard_metadata": "absent",
        },
        {"attestation_result": "blocked", "runtime_gate": "blocked_incompatible"},
    ),
    (
        "unexpected_dashboard_metadata",
        {
            "attestation": "present",
            "revision": "pinned",
            "route_manifest": "match",
            "source_review": "match",
            "proxy_proof": "match",
            "behavioral_probe": "passed",
            "dashboard_metadata": "unexpected",
        },
        {"attestation_result": "blocked", "runtime_gate": "blocked_incompatible"},
    ),
    (
        "failed_behavioral_probe",
        {
            "attestation": "present",
            "revision": "pinned",
            "route_manifest": "match",
            "source_review": "match",
            "proxy_proof": "match",
            "behavioral_probe": "failed",
            "dashboard_metadata": "absent",
        },
        {"attestation_result": "verified", "runtime_gate": "blocked_incompatible"},
    ),
)
CASE_IDS = tuple(item[0] for item in CASE_SPECS)
MAX_REDACTION_DEPTH = 64
MAX_INTEGER_BITS = 4096
CONTROL_PATTERN = re.compile(r"[\x00-\x1f\x7f]")
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b", re.IGNORECASE),
    re.compile(r"\b(?:ghp|github_pat|glpat|sk|xox[baprs])[-_][A-Za-z0-9_-]{8,}\b", re.IGNORECASE),
    re.compile(r"\bhttps?://[^\s<>\"']+", re.IGNORECASE),
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    re.compile(r"\b(?:AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|SECRET_KEY|API_KEY)\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"\bBearer\s+\S+", re.IGNORECASE),
    re.compile(r"\bBasic\s+[A-Za-z0-9+/=_-]{12,}", re.IGNORECASE),
    re.compile(r"\b(?:cookie|set-cookie|ticket|raw-ticket)\s*[:=]\s*\S+", re.IGNORECASE),
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
        "dashboard_protocol_version",
        "protocol_version",
        "server_source_sha",
        "source_sha_from_response",
        "revision_from_response",
    }
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")


class ValidationError(AssertionError):
    """Raised when a fixture violates its closed contract."""


class DuplicateKeyError(ValueError):
    """Raised before duplicate JSON keys can overwrite evidence."""


@dataclass(frozen=True)
class GitSnapshot:
    """One immutable commit/tree pair used for every blob in a validation."""

    commit: str
    tree: str


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


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _validate_json_numbers(value: Any, path: str = "$", *, depth: int = 0) -> None:
    """Reject parser-produced infinities, including exponent overflow."""
    require(depth <= MAX_REDACTION_DEPTH, f"{path}: JSON depth exceeds the bounded limit")
    if isinstance(value, dict):
        for key, child in value.items():
            _validate_json_numbers(child, f"{path}.{key}", depth=depth + 1)
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _validate_json_numbers(child, f"{path}[{index}]", depth=depth + 1)
        return
    if type(value) is float:
        require(math.isfinite(value), f"{path}: non-finite JSON number is not allowed")


def _parse_json_text(text: str, label: str) -> Any:
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_constant,
        )
        _validate_json_numbers(value)
        return value
    except DuplicateKeyError:
        raise
    except RecursionError as exc:
        raise ValidationError(f"cannot read strict JSON {label}: nesting is too deep") from exc
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValidationError(f"cannot read strict JSON {label}: {exc}") from exc


def load_json(path: Path) -> Any:
    """Load JSON while rejecting duplicates, non-finite numbers, and bad UTF-8."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValidationError(f"cannot read strict JSON {path}: {exc}") from exc
    return _parse_json_text(text, str(path))


def _validate_redaction(value: Any, path: str = "$", *, depth: int = 0) -> None:
    require(depth <= MAX_REDACTION_DEPTH, f"{path}: redaction depth exceeds the bounded limit")
    if isinstance(value, dict):
        for key, child in value.items():
            require(type(key) is str, f"{path}: object keys must be text")
            normalized = key.casefold().replace("-", "_")
            if not normalized.startswith("contains_"):
                require(normalized not in FORBIDDEN_KEYS, f"{path}.{key}: prohibited sensitive key")
            _validate_redaction(child, f"{path}.{key}", depth=depth + 1)
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _validate_redaction(child, f"{path}[{index}]", depth=depth + 1)
        return
    if isinstance(value, str):
        require(CONTROL_PATTERN.search(value) is None, f"{path}: control character is not allowed")
        for pattern in SECRET_PATTERNS:
            require(pattern.search(value) is None, f"{path}: credential-shaped value")


def _is_unsafe_relative_path(value: str) -> bool:
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
    require(type(relative) is str, "evidence path must be text")
    require(
        not _is_unsafe_relative_path(relative),
        f"evidence path must be relative POSIX text without '..': {relative!r}",
    )
    try:
        root_resolved = root.resolve(strict=False)
        resolved = (root_resolved / relative).resolve(strict=False)
        resolved.relative_to(root_resolved)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValidationError(f"evidence path escapes repository root: {relative!r}") from exc
    return resolved


def _git_env() -> dict[str, str]:
    env = os.environ.copy()
    for name in (
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_NAMESPACE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_WORK_TREE",
    ):
        env.pop(name, None)
    env["GIT_NO_LAZY_FETCH"] = "1"
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    return env


def _git_revision(repo_root: Path, expression: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "--verify", expression],
            check=False,
            capture_output=True,
            text=True,
            env=_git_env(),
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def capture_git_snapshot(repo_root: Path) -> GitSnapshot:
    """Capture one commit/tree pair before reading any immutable blob."""
    commit = _git_revision(repo_root, "HEAD")
    require(commit is not None and HEX40.fullmatch(commit) is not None, "immutable HEAD commit is unavailable")
    tree = _git_revision(repo_root, f"{commit}^{{tree}}")
    require(tree is not None and HEX40.fullmatch(tree) is not None, "immutable HEAD tree is unavailable")
    return GitSnapshot(commit=commit, tree=tree)


def _git_blob(repo_root: Path, commit: str, relative: str) -> bytes | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "cat-file", "blob", f"{commit}:{relative}"],
            check=False,
            capture_output=True,
            text=False,
            env=_git_env(),
        )
    except OSError:
        return None
    if result.returncode != 0 or not isinstance(result.stdout, bytes):
        return None
    return result.stdout


def _load_json_blob(repo_root: Path, snapshot: GitSnapshot, relative: str) -> Any:
    blob = _git_blob(repo_root, snapshot.commit, relative)
    require(blob is not None, f"missing immutable JSON fixture: {relative}")
    try:
        text = blob.decode("utf-8")
    except UnicodeError as exc:
        raise ValidationError(f"cannot read immutable JSON {relative}: invalid UTF-8") from exc
    return _parse_json_text(text, f"{snapshot.commit}:{relative}")


def _evidence_bytes(
    repo_root: Path,
    relative: str,
    *,
    verify_git: bool,
    snapshot: GitSnapshot | None = None,
) -> bytes:
    resolved = resolve_under_root(repo_root, relative)
    if verify_git:
        require(snapshot is not None, "immutable validation requires a captured Git snapshot")
        blob = _git_blob(repo_root, snapshot.commit, relative)
        require(blob is not None, f"missing immutable Git evidence: {relative}")
        return blob
    try:
        return resolved.read_bytes()
    except (OSError, IOError) as exc:
        raise ValidationError(f"cannot read evidence file {relative}: {exc}") from exc


def _validate_digest(value: Any, label: str) -> None:
    require(type(value) is str and HEX64.fullmatch(value) is not None, f"{label} must be a SHA-256 digest")


def _validate_size(value: Any, label: str) -> None:
    require(type(value) is int and value >= 0, f"{label} must be a non-negative integer")


def _validate_evidence_reference(
    item: dict[str, Any],
    expected: dict[str, Any],
    label: str,
    repo_root: Path,
    *,
    verify_git: bool,
    has_revision: bool,
    snapshot: GitSnapshot | None,
) -> None:
    keys = ("path", "contract_revision", "sha256", "size_bytes") if has_revision else ("path", "sha256", "size_bytes")
    strict_keys(item, keys, label)
    strict_keys(expected, keys, f"{label}.expected")
    require(item["path"] == expected["path"], f"{label}.path changed")
    if has_revision:
        require(item["contract_revision"] == expected["contract_revision"], f"{label}.contract_revision changed")
    _validate_digest(item["sha256"], f"{label}.sha256")
    _validate_size(item["size_bytes"], f"{label}.size_bytes")
    _validate_digest(expected["sha256"], f"{label}.expected.sha256")
    _validate_size(expected["size_bytes"], f"{label}.expected.size_bytes")
    require(item["sha256"] == expected["sha256"], f"{label}.sha256 does not match reviewed evidence")
    require(item["size_bytes"] == expected["size_bytes"], f"{label}.size_bytes does not match reviewed evidence")
    evidence = _evidence_bytes(repo_root, expected["path"], verify_git=verify_git, snapshot=snapshot)
    require(hashlib.sha256(evidence).hexdigest() == expected["sha256"], f"{label}.sha256 does not match immutable evidence")
    require(len(evidence) == expected["size_bytes"], f"{label}.size_bytes does not match immutable evidence")


def validate_attestation(
    record: dict[str, Any],
    repo_root: Path,
    *,
    verify_git: bool = True,
    snapshot: GitSnapshot | None = None,
) -> None:
    """Validate the canonical detached attestation and its evidence bindings."""
    if verify_git and snapshot is None:
        snapshot = capture_git_snapshot(repo_root)
    strict_keys(record, ATTESTATION_ROOT_KEYS, "attestation")
    require(record["schema"] == SCHEMA, "attestation schema changed")
    require(record["operation"] == OPERATION, "attestation operation changed")
    require(record["contract"] == CONTRACT, "attestation contract changed")

    hermes = strict_keys(record["hermes"], ("repository", "source_sha"), "attestation.hermes")
    require(hermes["repository"] == HERMES_REPOSITORY, "attestation Hermes repository changed")
    require(type(hermes["source_sha"]) is str and HEX40.fullmatch(hermes["source_sha"]) is not None, "attestation source SHA is not a full commit SHA")
    require(hermes["source_sha"] == HERMES_SHA, "attestation source SHA is not the pinned revision")

    deployment = strict_keys(
        record["deployment"],
        ("identity", "trust_channel", "scope"),
        "attestation.deployment",
    )
    require(deployment["identity"] == "synthetic-deployment-001", "deployment identity changed")
    require(deployment["trust_channel"] == "release-channel", "deployment trust channel changed")
    require(deployment["scope"] == "fixture_only", "fixture must not claim live deployment scope")

    _validate_evidence_reference(
        strict_keys(record["route_manifest"], ("path", "contract_revision", "sha256", "size_bytes"), "attestation.route_manifest"),
        EVIDENCE["route_manifest"],
        "attestation.route_manifest",
        repo_root,
        verify_git=verify_git,
        has_revision=True,
        snapshot=snapshot,
    )
    _validate_evidence_reference(
        record["source_review"],
        EVIDENCE["source_review"],
        "attestation.source_review",
        repo_root,
        verify_git=verify_git,
        has_revision=False,
        snapshot=snapshot,
    )
    _validate_evidence_reference(
        record["proxy_proof"],
        EVIDENCE["proxy_proof"],
        "attestation.proxy_proof",
        repo_root,
        verify_git=verify_git,
        has_revision=False,
        snapshot=snapshot,
    )

    dashboard_metadata = strict_keys(
        record["dashboard_metadata"],
        (
            "source_revision_observable",
            "stable_wire_version_observable",
            "blocked_ssh_ownership_version_is_evidence",
        ),
        "attestation.dashboard_metadata",
    )
    strict_equal(
        dashboard_metadata,
        {
            "source_revision_observable": False,
            "stable_wire_version_observable": False,
            "blocked_ssh_ownership_version_is_evidence": False,
        },
        "attestation.dashboard_metadata",
    )

    requirements = strict_keys(
        record["requirements"],
        (
            "full_source_sha_required",
            "unknown_revision_policy",
            "behavioral_probe_required_before_live_operation",
            "attestation_alone_enables_live_operation",
        ),
        "attestation.requirements",
    )
    strict_equal(
        requirements,
        {
            "full_source_sha_required": True,
            "unknown_revision_policy": "block",
            "behavioral_probe_required_before_live_operation": True,
            "attestation_alone_enables_live_operation": False,
        },
        "attestation.requirements",
    )

    redaction = strict_keys(record["redaction"], tuple(EXPECTED_REDACTION.keys()), "attestation.redaction")
    strict_equal(redaction, EXPECTED_REDACTION, "attestation.redaction")
    _validate_redaction(record)


def evaluate_case(case: dict[str, Any], repo_root: Path) -> dict[str, str]:
    """Execute one symbolic fixture row against the attestation validator."""
    item = strict_keys(case, ("id", "description", "input", "expected"), f"case {case.get('id', '<unknown>')}")
    input_value = strict_keys(
        item["input"],
        (
            "attestation",
            "revision",
            "route_manifest",
            "source_review",
            "proxy_proof",
            "behavioral_probe",
            "dashboard_metadata",
        ),
        f"case {item['id']}.input",
    )
    attestation_state = input_value["attestation"]
    if attestation_state != "present":
        require(attestation_state in {"missing", "empty", "malformed"}, f"case {item['id']}: unsupported attestation state")
        return {"attestation_result": "blocked", "runtime_gate": "blocked_incompatible"}

    record = load_json(ATTESTATION_PATH)
    require(type(record) is dict, "canonical attestation must be an object")
    record = copy.deepcopy(record)
    revision_state = input_value["revision"]
    revision_values = {
        "pinned": HERMES_SHA,
        "unknown": "unknown",
        "abbreviated": HERMES_SHA[:12],
        "mismatched": "0" * 40,
    }
    require(revision_state in revision_values, f"case {item['id']}: unsupported revision state")
    record["hermes"]["source_sha"] = revision_values[revision_state]

    for evidence_key in ("route_manifest", "source_review", "proxy_proof"):
        evidence_state = input_value[evidence_key]
        require(evidence_state in {"match", "mismatch"}, f"case {item['id']}: unsupported {evidence_key} state")
        if evidence_state == "mismatch":
            record[evidence_key]["sha256"] = "0" * 64

    dashboard_state = input_value["dashboard_metadata"]
    require(dashboard_state in {"absent", "unexpected"}, f"case {item['id']}: unsupported dashboard metadata state")
    if dashboard_state == "unexpected":
        record["dashboard_metadata"]["stable_wire_version_observable"] = True

    try:
        validate_attestation(record, repo_root, verify_git=True)
    except (ValidationError, DuplicateKeyError, OSError, UnicodeError, TypeError, ValueError):
        attestation_result = "blocked"
    else:
        attestation_result = "verified"

    probe_state = input_value["behavioral_probe"]
    require(probe_state in {"not_run", "passed", "failed"}, f"case {item['id']}: unsupported behavioral probe state")
    if attestation_result == "blocked" or probe_state == "failed":
        runtime_gate = "blocked_incompatible"
    elif probe_state == "not_run":
        runtime_gate = "blocked_pending_probe"
    else:
        runtime_gate = "separate_probe_gate"
    return {"attestation_result": attestation_result, "runtime_gate": runtime_gate}


def validate_cases(cases: dict[str, Any]) -> None:
    """Validate deterministic normal, empty, and failure-state fixture cases."""
    strict_keys(cases, CASES_ROOT_KEYS, "cases")
    require(cases["schema"] == FIXTURE_SCHEMA, "cases schema changed")
    require(cases["operation"] == OPERATION, "cases operation changed")
    require(cases["contract"] == CONTRACT, "cases contract changed")
    require(cases["pinned_source_sha"] == HERMES_SHA, "cases source SHA changed")
    require(type(cases["cases"]) is list, "cases.cases must be a list")
    require(len(cases["cases"]) == len(CASE_SPECS), "case count changed")

    for index, (case, (expected_id, expected_input, expected_result)) in enumerate(zip(cases["cases"], CASE_SPECS)):
        item = strict_keys(case, ("id", "description", "input", "expected"), f"cases.cases[{index}]")
        require(item["id"] == expected_id, f"case order or ID changed at index {index}")
        require(type(item["description"]) is str and item["description"], f"case {expected_id} description is missing")
        input_value = strict_keys(
            item["input"],
            (
                "attestation",
                "revision",
                "route_manifest",
                "source_review",
                "proxy_proof",
                "behavioral_probe",
                "dashboard_metadata",
            ),
            f"case {expected_id}.input",
        )
        strict_equal(input_value, expected_input, f"case {expected_id}.input")
        result_value = strict_keys(
            item["expected"],
            ("attestation_result", "runtime_gate"),
            f"case {expected_id}.expected",
        )
        strict_equal(result_value, expected_result, f"case {expected_id}.expected")

    redaction = strict_keys(cases["redaction"], tuple(EXPECTED_REDACTION.keys()), "cases.redaction")
    strict_equal(redaction, EXPECTED_REDACTION, "cases.redaction")
    _validate_redaction(cases)


def _number(value: Any, label: str) -> None:
    if type(value) is int:
        require(value >= 0, f"{label} must be a finite non-negative number")
        require(value.bit_length() <= MAX_INTEGER_BITS, f"{label} integer is oversized")
        return
    require(type(value) is float, f"{label} must be a finite number")
    require(math.isfinite(value) and value >= 0, f"{label} must be a finite non-negative number")


def validate_baseline(
    baseline: dict[str, Any],
    repo_root: Path,
    *,
    verify_git: bool,
    snapshot: GitSnapshot | None = None,
) -> int:
    """Validate measured evidence without creating a normative performance threshold."""
    if verify_git and snapshot is None:
        snapshot = capture_git_snapshot(repo_root)
    strict_keys(baseline, BASELINE_ROOT_KEYS, "baseline")
    _validate_redaction(baseline)
    require(baseline["schema"] == BASELINE_SCHEMA, "baseline schema changed")
    require(baseline["validator"] == VALIDATOR_PATH, "baseline validator path changed")
    require(baseline["command"] == VALIDATOR_COMMAND, "baseline command changed")
    require(baseline["build_mode"] == "N/A", "baseline build mode changed")
    require(baseline["threshold"] is None, "baseline must not invent a threshold")

    artifact_files = baseline["artifact_files"]
    require(type(artifact_files) is list, "baseline artifact_files must be a list")
    require(len(artifact_files) == len(BASELINE_ARTIFACT_PATHS), "baseline artifact count changed")
    measured_bytes = 0
    for index, (item, expected_path) in enumerate(zip(artifact_files, BASELINE_ARTIFACT_PATHS)):
        entry = strict_keys(item, ("path", "sha256", "size_bytes"), f"baseline.artifact_files[{index}]")
        require(entry["path"] == expected_path, f"baseline artifact path/order changed at index {index}")
        _validate_digest(entry["sha256"], f"baseline.artifact_files[{index}].sha256")
        _validate_size(entry["size_bytes"], f"baseline.artifact_files[{index}].size_bytes")
        evidence = _evidence_bytes(repo_root, expected_path, verify_git=verify_git, snapshot=snapshot)
        require(hashlib.sha256(evidence).hexdigest() == entry["sha256"], f"baseline digest mismatch: {expected_path}")
        require(len(evidence) == entry["size_bytes"], f"baseline size mismatch: {expected_path}")
        measured_bytes += len(evidence)
    require(type(baseline["artifact_bytes"]) is int, "baseline artifact_bytes must be an integer")
    require(baseline["artifact_bytes"] == measured_bytes, "baseline artifact byte count changed")

    environment = strict_keys(baseline["environment"], ("platform", "python"), "baseline.environment")
    strict_equal(environment, BASELINE_ENVIRONMENT, "baseline.environment")
    require(type(baseline["repetitions"]) is int and baseline["repetitions"] == 30, "baseline repetitions must be 30")

    durations = strict_keys(
        baseline["duration_ms"],
        ("min", "p50", "p95", "max", "mean"),
        "baseline.duration_ms",
    )
    for key, value in durations.items():
        _number(value, f"baseline.duration_ms.{key}")
    require(durations["min"] > 0, "baseline duration minimum must be positive")
    require(durations["min"] <= durations["p50"] <= durations["p95"] <= durations["max"], "baseline duration distribution is not ordered")
    require(durations["min"] <= durations["mean"] <= durations["max"], "baseline duration mean is outside the recorded range")
    return measured_bytes


def validate_all(
    repo_root: Path,
    *,
    verify_git: bool = True,
    snapshot: GitSnapshot | None = None,
) -> tuple[int, int]:
    if verify_git and snapshot is None:
        snapshot = capture_git_snapshot(repo_root)
    if verify_git:
        require(snapshot is not None, "immutable validation requires a captured Git snapshot")
        record = _load_json_blob(repo_root, snapshot, ATTESTATION_RELATIVE)
        cases = _load_json_blob(repo_root, snapshot, CASES_RELATIVE)
        baseline = _load_json_blob(repo_root, snapshot, BASELINE_RELATIVE)
    else:
        record = load_json(ATTESTATION_PATH)
        cases = load_json(CASES_PATH)
        baseline = load_json(BASELINE_PATH)
    require(type(record) is dict, "attestation root must be an object")
    require(type(cases) is dict, "cases root must be an object")
    require(type(baseline) is dict, "baseline root must be an object")
    validate_attestation(record, repo_root, verify_git=verify_git, snapshot=snapshot)
    validate_cases(cases)
    artifact_bytes = validate_baseline(baseline, repo_root, verify_git=verify_git, snapshot=snapshot)
    return len(cases["cases"]), artifact_bytes


def default_repo_root() -> Path:
    # This validator lives at root/contracts/fixtures/compatibility-attestation.
    return ROOT.parents[2]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=default_repo_root(),
        help="repository root containing the immutable evidence files",
    )
    parser.add_argument(
        "--worktree",
        action="store_true",
        help="read evidence from the mutable worktree instead of HEAD Git blobs",
    )
    args = parser.parse_args(argv)

    started = time.perf_counter()
    errors: list[str] = []
    case_count = 0
    artifact_bytes = 0
    snapshot: GitSnapshot | None = None
    source_mode = "worktree" if args.worktree else "immutable_commit"
    try:
        repo_root = args.repo_root.resolve()
        if not args.worktree:
            snapshot = capture_git_snapshot(repo_root)
        case_count, artifact_bytes = validate_all(
            repo_root,
            verify_git=not args.worktree,
            snapshot=snapshot,
        )
    except (ValidationError, DuplicateKeyError, OSError, UnicodeError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        errors.append(str(exc))
    duration_ms = (time.perf_counter() - started) * 1000
    result = {
        "ok": not errors,
        "fixture_valid": not errors,
        "attestation_verified": bool(not errors and not args.worktree),
        "source_mode": source_mode,
        "verified_commit": snapshot.commit if snapshot is not None else None,
        "verified_tree": snapshot.tree if snapshot is not None else None,
        "live_operation": False,
        "case_count": case_count,
        "artifact_bytes": artifact_bytes,
        "duration_ms": round(duration_ms, 3),
        "errors": errors,
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
