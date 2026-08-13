#!/usr/bin/env python3
"""Validate the Phase A to external anchor to Phase B artifact lifecycle.

This checkpoint validates artifact authority only. It does not run Git, replay,
the candidate shell, a network operation, or Hermes. A caller supplies the Git
observation function for the final, read-only Phase B observation.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

SCHEMA = "hermternal.issue-397.phase-b-lifecycle.v1"
ANCHOR_SCHEMA = "hermternal.issue-397.phase-a-anchor.v1"
ROLES = ("markdown", "json", "shell")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
MAX_BYTES = {"descriptor": 64 * 1024, "markdown": 2 * 1024 * 1024, "json": 4 * 1024 * 1024, "shell": 2 * 1024 * 1024}
ZERO_SHA = b"0" * 64


class Reject(Exception):
    """A deliberate fail-closed lifecycle rejection."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Reject(message)


@dataclass(frozen=True)
class Snapshot:
    path: Path
    raw: bytes
    sha256: str
    identity: tuple[int, int, int, int, int, int, int]


@dataclass(frozen=True)
class PhaseAReceipt:
    descriptor: Snapshot
    artifacts: Mapping[str, Snapshot]
    normalized_json_sha256: str
    approval_digest: str


def _identity(st: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (int(st.st_dev), int(st.st_ino), int(st.st_uid), int(st.st_gid), stat.S_IMODE(st.st_mode), int(st.st_size), int(st.st_nlink))


def _read_once(path: Path, label: str, limit: int) -> Snapshot:
    require(path.is_absolute() and str(path) == os.path.realpath(path), f"{label} path must be canonical absolute")
    parent_before = os.lstat(path.parent)
    require(stat.S_ISDIR(parent_before.st_mode) and not stat.S_ISLNK(parent_before.st_mode), f"{label} parent must be a directory")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, f"{label} must be a single-link regular file")
        require(before.st_uid == os.getuid() and not stat.S_IMODE(before.st_mode) & 0o022, f"{label} must be private")
        require(0 < before.st_size <= limit, f"{label} size is outside its bound")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            require(total <= limit, f"{label} exceeds its read bound")
        after = os.fstat(fd)
    finally:
        os.close(fd)
    final = os.lstat(path)
    parent_after = os.lstat(path.parent)
    require(_identity(before) == _identity(after) == _identity(final), f"{label} identity changed during read")
    require(_identity(parent_before) == _identity(parent_after), f"{label} parent changed during read")
    raw = b"".join(chunks)
    require(len(raw) == before.st_size, f"{label} byte count differs from its descriptor")
    return Snapshot(path, raw, hashlib.sha256(raw).hexdigest(), _identity(before))


def read_stable(path: Path, label: str, limit: int) -> Snapshot:
    first = _read_once(path, label, limit)
    second = _read_once(path, label, limit)
    third = _read_once(path, label, limit)
    require(first.identity == second.identity == third.identity, f"{label} identity changed across stable reads")
    require(first.raw == second.raw == third.raw, f"{label} bytes changed across stable reads")
    return first


def _parse_object(raw: bytes, label: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            require(key not in result, f"{label} contains duplicate key {key!r}")
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except Reject:
        raise
    except Exception as exc:
        raise Reject(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    require(isinstance(value, dict), f"{label} root must be an object")
    return value


def normalized_json_sha256(raw: bytes, expected: str) -> str:
    """Compute the declared byte normalization without JSON reserialization."""
    require(SHA_RE.fullmatch(expected) is not None, "normalized JSON SHA-256 is invalid")
    normalized = raw.replace(expected.encode("ascii"), ZERO_SHA)
    for key in (b'"shell_sha256": "', b'"driver_shell_sha256": "', b'"expected_body_sha256": "'):
        normalized = re.sub(re.escape(key) + rb"[0-9a-f]{64}(?=\")", lambda match: match.group(0)[: len(key)] + ZERO_SHA, normalized)
    return hashlib.sha256(normalized).hexdigest()


def validate_phase_a(descriptor_path: Path, descriptor_sha256: str) -> PhaseAReceipt:
    """Run genuine Phase A artifact validation and return authenticated facts."""
    require(SHA_RE.fullmatch(descriptor_sha256) is not None, "descriptor SHA-256 is invalid")
    descriptor = read_stable(descriptor_path, "triad descriptor", MAX_BYTES["descriptor"])
    require(descriptor.sha256 == descriptor_sha256, "triad descriptor SHA-256 differs")
    value = _parse_object(descriptor.raw, "triad descriptor")
    require(set(value) == {"schema", "artifacts", "normalized_json_sha256"}, "triad descriptor fields differ")
    require(value["schema"] == SCHEMA, "triad descriptor schema differs")
    records = value["artifacts"]
    require(isinstance(records, list) and len(records) == 3, "triad descriptor must contain exactly three artifacts")
    require([record.get("role") if isinstance(record, dict) else None for record in records] == list(ROLES), "triad roles or order differ")
    artifacts: dict[str, Snapshot] = {}
    paths: list[Path] = []
    for role, record in zip(ROLES, records):
        require(isinstance(record, dict) and set(record) == {"role", "path", "sha256"}, f"{role} descriptor fields differ")
        require(isinstance(record["path"], str), f"{role} path is invalid")
        require(isinstance(record["sha256"], str) and SHA_RE.fullmatch(record["sha256"]) is not None, f"{role} SHA-256 is invalid")
        path = Path(record["path"])
        snapshot = read_stable(path, role, MAX_BYTES[role])
        require(snapshot.sha256 == record["sha256"], f"{role} SHA-256 differs")
        paths.append(path)
        artifacts[role] = snapshot
    require(len(set(paths)) == 3, "triad paths must be distinct")
    expected_normalized = value["normalized_json_sha256"]
    require(isinstance(expected_normalized, str), "normalized JSON SHA-256 is missing")
    actual_normalized = normalized_json_sha256(artifacts["json"].raw, expected_normalized)
    require(actual_normalized == expected_normalized, "independent normalized JSON SHA-256 differs")
    shell_sha = artifacts["shell"].sha256
    document = _parse_object(artifacts["json"].raw, "triad JSON")
    require(document.get("shell_sha256") == shell_sha, "triad JSON shell authority differs")
    require(document.get("normalized_json_sha256") == expected_normalized, "triad JSON normalized authority differs")
    require(artifacts["markdown"].raw.count(artifacts["shell"].raw) == 1, "Markdown must contain the exact shell once")
    approval_payload = {"descriptor_sha256": descriptor.sha256, "artifacts": {role: artifacts[role].sha256 for role in ROLES}, "normalized_json_sha256": expected_normalized}
    approval_digest = hashlib.sha256(json.dumps(approval_payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return PhaseAReceipt(descriptor, artifacts, expected_normalized, approval_digest)


def provision_anchor(descriptor_path: Path, descriptor_sha256: str) -> tuple[bytes, PhaseAReceipt]:
    receipt = validate_phase_a(descriptor_path, descriptor_sha256)
    anchor = {"schema": ANCHOR_SCHEMA, "descriptor_sha256": descriptor_sha256, "phase_a_approval_digest": receipt.approval_digest, "decision": "approve-consistency-only"}
    return (json.dumps(anchor, sort_keys=True, separators=(",", ":")) + "\n").encode(), receipt


def validate_phase_b(
    descriptor_path: Path,
    descriptor_sha256: str,
    anchor_raw: bytes,
    observe_git: Callable[[], Mapping[str, str]],
) -> tuple[dict[str, str], PhaseAReceipt]:
    """Revalidate Phase A, authenticate its anchor, then observe Git read-only."""
    receipt = validate_phase_a(descriptor_path, descriptor_sha256)
    anchor = _parse_object(anchor_raw, "Phase A anchor")
    require(set(anchor) == {"schema", "descriptor_sha256", "phase_a_approval_digest", "decision"}, "Phase A anchor fields differ")
    require(anchor == {"schema": ANCHOR_SCHEMA, "descriptor_sha256": descriptor_sha256, "phase_a_approval_digest": receipt.approval_digest, "decision": "approve-consistency-only"}, "Phase A anchor authority differs")
    observed = dict(observe_git())
    require(set(observed) == {"final_head", "parent", "tree"}, "Git observation fields differ")
    require(all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) for value in observed.values()), "Git observation identity is invalid")
    # The Phase B validator runs once. Final stable reads protect the same
    # authenticated objects without a hidden second validator invocation.
    final_descriptor = read_stable(descriptor_path, "triad descriptor final", MAX_BYTES["descriptor"])
    require(final_descriptor == receipt.descriptor, "Phase A descriptor changed during Phase B")
    for role in ROLES:
        final_artifact = read_stable(receipt.artifacts[role].path, f"{role} final", MAX_BYTES[role])
        require(final_artifact == receipt.artifacts[role], f"Phase A {role} authority changed during Phase B")
    return observed, receipt
