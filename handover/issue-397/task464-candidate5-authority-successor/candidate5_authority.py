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
ARGV = ("/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "HOME=/dev/null", "LANG=C", "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "GIT_NO_REPLACE_OBJECTS=1", "/bin/bash", "-euo", "pipefail", "-s")
ROOT_KEYS = frozenset({"artifact_paths", "artifact_task", "authority", "base", "execution_driver", "forbidden_ancestry", "generated_cache_cleanup", "generated_on", "guard_procedures", "historical_compatibility_objects", "known_limitations", "live_after_replay_only", "live_overlap", "mode", "notation", "operation_boundary", "ordered_lanes", "schema", "task", "validation_contract", "verification_fanout"})
EXECUTION_KEYS = frozenset({"argv", "clean_primary_clone_transport", "clean_primary_identity_fields", "clean_primary_repository_template", "clean_primary_root_template", "clean_primary_root_template_normalized", "clean_primary_storage_identity", "clean_primary_whole_worktree_status", "forbidden_commands", "fresh_shell_requirement", "immutable", "markdown_fence_extraction", "markdown_parity_appendix", "matrix_identity", "matrix_path", "mode", "mutation_contract", "no_push_boundary", "non_authoritative_standalone_scripts", "object_closure_contract", "ordered_steps", "primary_repository", "replay_root_constraint", "replay_root_identity", "replay_root_template", "replay_root_template_normalized", "reproducible_hash_commands", "root_creation_contract", "schema", "shell", "shell_sha256", "shell_size_metadata", "source_identity_fields", "source_of_truth", "strict_git_environment", "trusted_executables", "worktree_separation_contract"})
STRICT_ENV = {
    "set": {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1"},
    "per_command": ["core.hooksPath=/dev/null", "protocol.allow=never"],
    "allowlist": ["PATH", "HOME", "LANG", "LC_ALL", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_TERMINAL_PROMPT", "GIT_OPTIONAL_LOCKS", "GIT_NO_REPLACE_OBJECTS", "PWD", "GIT_NO_LAZY_FETCH", "SHLVL", "_"],
    "reject_inherited_patterns": ["GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_*", "GIT_CONFIG_VALUE_*", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE", "PYTHONINSPECT", "PYTHONWARNINGS", "BASH_ENV", "ENV", "CDPATH", "NODE_OPTIONS", "RUBYOPT", "PERL5OPT", "DYLD_*", "LD_*"],
}


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
    require(set(document) == ROOT_KEYS, "authority JSON root fields differ")
    require(document.get("artifact_paths") == {"markdown": str(artifacts["markdown"].path), "json": str(artifacts["json"].path)}, "JSON artifact paths differ")
    execution = document.get("execution_driver")
    require(isinstance(execution, dict) and execution.get("source_of_truth") == "/execution_driver/shell", "JSON shell authority differs")
    require(set(execution) == EXECUTION_KEYS, "JSON execution_driver fields differ")
    argv = execution.get("argv")
    require(isinstance(argv, list) and all(isinstance(item, str) for item in argv), "JSON argv must be a string array")
    require(tuple(argv) == ARGV, "JSON argv differs from the reviewed CLI")
    require(execution.get("strict_git_environment") == STRICT_ENV, "JSON strict Git environment differs")
    require(execution.get("shell_sha256") == artifacts["shell"].sha256, "JSON shell hash differs")
    require(execution.get("shell", "").encode("utf-8") == artifacts["shell"].raw, "JSON shell bytes differ")
    require(execution.get("matrix_identity", {}).get("expected_normalized_sha256") == normalized, "JSON normalized identity declaration differs")
    require(extract_shell(artifacts["markdown"].raw) == artifacts["shell"].raw, "Markdown shell bytes differ")
    require(artifacts["shell"].raw.endswith(b"\n"), "shell must end with LF")
    for stale in document.get("execution_driver", {}).get("non_authoritative_standalone_scripts", []):
        require(stale.get("path") != str(artifacts["shell"].path), "fresh shell is declared stale")
    require(argv[-1] == "-s", "JSON CLI does not select authenticated stdin")
    return Authority(descriptor, artifacts, normalized, tuple(argv), execution["shell"].encode("utf-8"))


def verified_module(path: Path, expected_sha256: str) -> types.ModuleType:
    """Compile and execute only bytes returned by the verified stable read."""
    snapshot = stable_read(path, "verified module", 2 * 1024 * 1024)
    require(snapshot.sha256 == expected_sha256, "verified module SHA-256 differs")
    module = types.ModuleType("candidate5_verified_authority_module")
    module.__file__ = str(path)
    module.__loader__ = None
    exec(compile(snapshot.raw, str(path), "exec", dont_inherit=True), module.__dict__)
    return module
