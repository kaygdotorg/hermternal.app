#!/usr/bin/env python3
"""Validate one JSON, Markdown, and freshly extracted shell authority."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA = "hermternal.issue-397.candidate-five-authority.v1"
ROLES = ("markdown", "json", "shell")
ROLE_NAMES = {"markdown": "candidate-five.md", "json": "candidate-five.json", "shell": "candidate-five.sh"}
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
HEADING = b"## Canonical machine-readable ordered execution driver\n"
OPENING = b"```bash\n"
CLOSING_RE = re.compile(rb"(?m)^```[ \t]*(?:\r?\n|\Z)")
MAX_BYTES = {"descriptor": 64 * 1024, "markdown": 2 * 1024 * 1024, "json": 4 * 1024 * 1024, "shell": 2 * 1024 * 1024}
ARGV = ("/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "HOME=/dev/null", "LANG=C", "LC_ALL=C", "/bin/bash", "-euo", "pipefail", "-s")


class Reject(Exception):
    """A deliberate fail-closed authority rejection."""


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
class Authority:
    descriptor: Snapshot
    artifacts: dict[str, Snapshot]
    normalized_json_sha256: str
    argv: tuple[str, ...]
    stdin: bytes


def _identity(st: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_size, st.st_nlink)


def stable_read(path: Path, label: str, limit: int) -> Snapshot:
    """Read three times with no-follow descriptors and bind the final name."""
    snapshots = []
    for _ in range(3):
        require(path.is_absolute() and str(path) == os.path.realpath(path), f"{label} path must be canonical absolute")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, f"{label} must be a single-link regular file")
            require(before.st_uid == os.getuid() and not stat.S_IMODE(before.st_mode) & 0o022, f"{label} must be private")
            require(0 < before.st_size <= limit, f"{label} size is outside its bound")
            raw = b""
            while True:
                chunk = os.read(fd, min(65536, limit + 1 - len(raw)))
                if not chunk:
                    break
                raw += chunk
                require(len(raw) <= limit, f"{label} exceeds its bound")
            after = os.fstat(fd)
        finally:
            os.close(fd)
        final = os.lstat(path)
        require(_identity(before) == _identity(after) == _identity(final), f"{label} changed during read")
        snapshots.append(Snapshot(path, raw, hashlib.sha256(raw).hexdigest(), _identity(before)))
    require(snapshots[0] == snapshots[1] == snapshots[2], f"{label} changed across stable reads")
    return snapshots[0]


def parse_object(raw: bytes, label: str) -> dict[str, Any]:
    def pairs(items):
        result = {}
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
    """Zero declared identity and shell hashes in the exact raw JSON bytes."""
    require(SHA_RE.fullmatch(expected) is not None, "normalized JSON SHA-256 is invalid")
    normalized = raw.replace(expected.encode("ascii"), b"0" * 64)
    for key in (b'"shell_sha256": "', b'"driver_shell_sha256": "', b'"expected_body_sha256": "'):
        normalized = re.sub(re.escape(key) + rb"[0-9a-f]{64}(?=\")", lambda match: match.group(0)[: len(key)] + b"0" * 64, normalized)
    return hashlib.sha256(normalized).hexdigest()


def extract_shell(markdown: bytes) -> bytes:
    heading = markdown.find(HEADING)
    require(heading >= 0, "Markdown authority heading is missing")
    opening = markdown.find(OPENING, heading + len(HEADING))
    require(opening >= 0, "Markdown shell opening fence is missing")
    start = opening + len(OPENING)
    closing = CLOSING_RE.search(markdown, start)
    require(closing is not None, "Markdown shell closing fence is missing")
    require(CLOSING_RE.search(markdown, closing.end()) is None, "Markdown has a duplicate closing fence")
    return markdown[start:closing.start()]


def validate(descriptor_path: Path, authority_root: Path, descriptor_sha256: str) -> Authority:
    """Return CLI input only after all three representations agree."""
    require(SHA_RE.fullmatch(descriptor_sha256) is not None, "descriptor SHA-256 is invalid")
    root = Path(authority_root)
    require(root.is_absolute() and str(root) == os.path.realpath(root), "authority root must be canonical absolute")
    descriptor = stable_read(Path(descriptor_path), "authority descriptor", MAX_BYTES["descriptor"])
    require(descriptor.sha256 == descriptor_sha256, "authority descriptor SHA-256 differs")
    value = parse_object(descriptor.raw, "authority descriptor")
    require(set(value) == {"schema", "roles", "normalized_json_sha256"}, "authority descriptor fields differ")
    require(value["schema"] == SCHEMA, "authority descriptor schema differs")
    records = value["roles"]
    require(isinstance(records, list) and len(records) == 3, "authority descriptor must have exactly three roles")
    require([item.get("role") if isinstance(item, dict) else None for item in records] == list(ROLES), "authority role order differs")
    artifacts = {}
    for role, record in zip(ROLES, records):
        require(set(record) == {"role", "path", "sha256"}, f"{role} record fields differ")
        expected_path = root / ROLE_NAMES[role]
        require(record["path"] == str(expected_path), f"{role} path differs from fixed authority")
        snapshot = stable_read(expected_path, role, MAX_BYTES[role])
        require(record["sha256"] == snapshot.sha256, f"{role} SHA-256 differs")
        artifacts[role] = snapshot
    normalized = value["normalized_json_sha256"]
    require(isinstance(normalized, str) and normalized_json_sha256(artifacts["json"].raw, normalized) == normalized, "normalized JSON identity differs")
    document = parse_object(artifacts["json"].raw, "authority JSON")
    require(document.get("artifact_paths") == {"markdown": str(artifacts["markdown"].path), "json": str(artifacts["json"].path)}, "JSON artifact paths differ")
    execution = document.get("execution_driver")
    require(isinstance(execution, dict) and execution.get("source_of_truth") == "/execution_driver/shell", "JSON shell authority differs")
    require(execution.get("shell_sha256") == artifacts["shell"].sha256, "JSON shell hash differs")
    require(execution.get("shell", "").encode("utf-8") == artifacts["shell"].raw, "JSON shell bytes differ")
    require(execution.get("matrix_identity", {}).get("expected_normalized_sha256") == normalized, "JSON normalized identity declaration differs")
    require(extract_shell(artifacts["markdown"].raw) == artifacts["shell"].raw, "Markdown shell bytes differ")
    require(artifacts["shell"].raw.endswith(b"\n"), "shell must end with LF")
    for stale in document.get("execution_driver", {}).get("non_authoritative_standalone_scripts", []):
        require(stale.get("path") != str(artifacts["shell"].path), "fresh shell is declared stale")
    return Authority(descriptor, artifacts, normalized, ARGV, artifacts["shell"].raw)


def verified_module(path: Path, expected_sha256: str) -> types.ModuleType:
    """Compile and execute only bytes returned by the verified stable read."""
    snapshot = stable_read(path, "verified module", 2 * 1024 * 1024)
    require(snapshot.sha256 == expected_sha256, "verified module SHA-256 differs")
    module = types.ModuleType("candidate5_verified_authority_module")
    module.__file__ = str(path)
    module.__loader__ = None
    exec(compile(snapshot.raw, str(path), "exec", dont_inherit=True), module.__dict__)
    return module
