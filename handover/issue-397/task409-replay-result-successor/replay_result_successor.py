#!/usr/bin/env python3
"""Publish retained replay evidence from approved bytes and observations only.

This successor owns one exact driver invocation.  It never accepts caller
claims for replay identity or final-triad evidence.  The final #403 authority
is stable-read before and after the invocation, and the retained repository is
observed through the trusted Git reviewer before and after publication.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

BASE = Path(__file__).resolve().parents[1]
REVIEW_PATH = BASE / "task409-execution-preflight" / "review_task464_git_v3.py"
RESULT_SCHEMA = "task409-execution-preflight/replay-result/v2"
RESULT_PHASE = "B-post-replay-detached-final-head"
COMPLETION_SCHEMA = "hermternal.issue-397.replay-completion.v1"
RESULT_NAME = "replay-result.json"
COMPLETION_NAME = "replay-completion.json"
COMPLETION_MARKER = b"replay-complete-retained\n"
MAX_BYTES = 2 * 1024 * 1024
OID_RE = re.compile(r"[0-9a-f]{40}\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
ROLE_NAMES = {"markdown": "candidate-five.md", "json": "candidate-five.json", "shell": "candidate-five.sh"}
RESULT_KEYS = frozenset({"schema", "phase", "lane", "phase_a_manifest_sha256", "phase_a_approval_digest", "replay_root", "replay_root_identity", "repository", "repository_identity", "head_state", "final_head", "parent", "tree", "base_commit", "base_tree", "protected_main_commit", "required_ancestors", "forbidden_ancestors"})
COMPLETION_KEYS = frozenset({"schema", "completion_marker", "result_path", "result_sha256", "result_identity", "driver_sha256", "markdown_sha256", "json_sha256", "shell_sha256", "provenance_sha256", "source_commit", "argv_sha256", "stdin_sha256", "stdout_sha256", "stderr_sha256", "stdout_bytes", "stderr_bytes"})
PROVENANCE_KEYS = frozenset({"schema", "issue", "candidate", "generation", "repository_boundary", "dependencies", "source_inputs", "outputs", "cross_format_authority", "publication", "safety_claims"})
BOUNDARY_KEYS = frozenset({"integrated_commit", "integrated_tree", "base_commit", "base_tree", "protected_main_commit", "source_commit"})

class Reject(Exception):
    """A deliberate fail-closed retained-replay rejection."""

def require(value: bool, message: str) -> None:
    if not value:
        raise Reject(message)

def _sha(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA_RE.fullmatch(value) is not None, f"{label} must be 64 lowercase hex")
    return value

def _oid(value: Any, label: str) -> str:
    require(isinstance(value, str) and OID_RE.fullmatch(value) is not None, f"{label} must be 40 lowercase hex")
    return value

def _identity(st: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (int(st.st_dev), int(st.st_ino), int(st.st_uid), int(stat.S_IMODE(st.st_mode)), int(st.st_size), int(st.st_nlink))

def _canonical(path: Path, label: str) -> Path:
    path = Path(path)
    require(path.is_absolute() and os.path.realpath(path) == os.fspath(path), f"{label} is not canonical absolute")
    return path

def _dir_identity(path: Path, label: str) -> dict[str, int]:
    st = os.lstat(path)
    require(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode), f"{label} is not a directory")
    require(st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o700, f"{label} is not owned mode 0700")
    return {"st_dev": int(st.st_dev), "st_ino": int(st.st_ino), "st_uid": int(st.st_uid), "st_mode": 0o700, "st_nlink": int(st.st_nlink)}

def _json(raw: bytes, label: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            require(key not in result, f"{label} has duplicate key {key!r}")
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except Reject:
        raise
    except Exception as error:
        raise Reject(f"{label} is not strict UTF-8 JSON: {error}") from error
    require(isinstance(value, dict), f"{label} root is not an object")
    return value

@dataclass(frozen=True)
class Snapshot:
    path: Path
    identity: tuple[int, int, int, int, int, int]
    raw: bytes
    sha256: str

def stable_read(path: Path, label: str, *, limit: int = MAX_BYTES, mode: int = 0o600) -> Snapshot:
    """Read one private, single-link file three times and reject any change."""
    path = _canonical(path, label)
    values: list[Snapshot] = []
    for _ in range(3):
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid(), f"{label} is not an owned regular file")
            require(stat.S_IMODE(before.st_mode) == mode and before.st_nlink == 1, f"{label} mode or link count differs")
            require(0 < before.st_size <= limit, f"{label} size differs")
            raw = bytearray()
            while True:
                block = os.read(fd, min(131072, limit + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
                require(len(raw) <= limit, f"{label} exceeds size bound")
            after = os.fstat(fd)
        finally:
            os.close(fd)
        final = os.lstat(path)
        require(_identity(before) == _identity(after) == _identity(final), f"{label} changed during read")
        values.append(Snapshot(path, _identity(before), bytes(raw), hashlib.sha256(raw).hexdigest()))
    require(values[0] == values[1] == values[2], f"{label} changed across stable reads")
    return values[0]

@dataclass(frozen=True)
class Authority:
    root: Path
    descriptor: Snapshot
    provenance: Snapshot
    artifacts: Mapping[str, Snapshot]
    argv: tuple[str, ...]
    stdin: bytes
    base_commit: str
    base_tree: str
    protected_main_commit: str
    source_commit: str

def load_authority(root: Path, approved_provenance_sha256: str) -> Authority:
    """Authenticate the closed #403 five-file set and derive all static facts."""
    root = _canonical(root, "final authority root")
    _dir_identity(root, "final authority root")
    expected = _sha(approved_provenance_sha256, "approved provenance")
    descriptor = stable_read(root / "authority-descriptor.json", "authority descriptor")
    provenance = stable_read(root / "provenance-manifest.json", "final provenance")
    require(provenance.sha256 == expected, "approved provenance hash differs")
    d = _json(descriptor.raw, "authority descriptor")
    require(set(d) == {"schema", "roles", "normalized_json_sha256"}, "authority descriptor schema differs")
    require(isinstance(d["roles"], list) and [item.get("role") if isinstance(item, dict) else None for item in d["roles"]] == list(ROLE_NAMES), "authority role order differs")
    artifacts: dict[str, Snapshot] = {}
    for record in d["roles"]:
        require(isinstance(record, dict) and set(record) == {"role", "path", "sha256"}, "authority role schema differs")
        role = record["role"]; path = root / ROLE_NAMES[role]
        require(record["path"] == str(path), "authority artifact path differs")
        snap = stable_read(path, role)
        require(record["sha256"] == snap.sha256, "authority artifact hash differs")
        artifacts[role] = snap
    document = _json(artifacts["json"].raw, "authority JSON")
    execution = document.get("execution_driver")
    require(isinstance(execution, dict) and execution.get("shell", "").encode("utf-8") == artifacts["shell"].raw, "authority shell differs")
    argv = execution.get("argv")
    require(isinstance(argv, list) and argv and all(isinstance(item, str) and item for item in argv), "authority argv differs")
    require(artifacts["shell"].raw.endswith(b"\n"), "authority shell lacks LF")
    p = _json(provenance.raw, "final provenance")
    require(set(p) == PROVENANCE_KEYS and p.get("issue") == 397 and p.get("candidate") == "five", "final provenance schema differs")
    outputs = p.get("outputs")
    require(isinstance(outputs, dict) and set(outputs) == set(ROLE_NAMES), "final provenance outputs differ")
    for role, snap in artifacts.items():
        require(isinstance(outputs[role], dict) and outputs[role].get("path") == str(snap.path) and outputs[role].get("sha256") == snap.sha256, "final provenance artifact differs")
    boundary = p.get("repository_boundary")
    require(isinstance(boundary, dict) and set(boundary) == BOUNDARY_KEYS, "final provenance boundary differs")
    return Authority(root, descriptor, provenance, artifacts, tuple(argv), artifacts["shell"].raw, _oid(boundary["base_commit"], "base commit"), _oid(boundary["base_tree"], "base tree"), _oid(boundary["protected_main_commit"], "protected main"), _oid(boundary["source_commit"], "source commit"))

def _review_module() -> Any:
    spec = importlib.util.spec_from_file_location("retained_replay_trusted_review", REVIEW_PATH)
    require(spec is not None and spec.loader is not None, "trusted Git reviewer is unavailable")
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module; spec.loader.exec_module(module)
    return module

@dataclass(frozen=True)
class RepositoryObservation:
    identity: Mapping[str, int]
    final_head: str
    parent: str
    tree: str

def observe_repository(repository: Path) -> RepositoryObservation:
    """Use the reviewed Git boundary to derive the detached final identity."""
    review = _review_module(); identity = review.inspect_metadata(repository, "retained replay")
    guard = review.RepoGuard(identity)
    head = review.read_bound_file(repository / ".git" / "HEAD", "retained replay HEAD").raw
    require(re.fullmatch(rb"[0-9a-f]{40}\n", head) is not None, "retained repository HEAD is not detached")
    final_head = head[:-1].decode("ascii")
    parents = review._decode(review.git_output(repository, ["rev-list", "--parents", "-n", "1", final_head], guard=guard), "retained final parent").split()
    require(len(parents) == 2 and parents[0] == final_head, "retained final head must have one parent")
    parent = _oid(parents[1], "retained parent")
    tree = _oid(review._rev_parse(repository, f"{final_head}^{{tree}}", "retained final tree", guard), "retained tree")
    guard.assert_stable()
    return RepositoryObservation(review.directory_identity(identity), _oid(final_head, "retained head"), parent, tree)

def create_layout(run_parent: Path) -> tuple[Path, Path, Path]:
    """Create one fresh private parent and its exact private sibling roots."""
    run_parent = _canonical(run_parent, "run parent")
    require(not os.path.lexists(run_parent), "run parent already exists")
    try:
        os.mkdir(run_parent, 0o700); os.mkdir(run_parent / "replay-root", 0o700); os.mkdir(run_parent / "repository", 0o700)
    except OSError as error:
        raise Reject(f"fresh replay layout creation failed: {error}") from error
    replay_root, repository = run_parent / "replay-root", run_parent / "repository"
    _dir_identity(run_parent, "run parent"); _dir_identity(replay_root, "replay root"); _dir_identity(repository, "repository")
    return run_parent, replay_root, repository

def _create_once(path: Path, raw: bytes, label: str) -> Snapshot:
    require(not os.path.lexists(path), f"{label} already exists")
    fd = -1
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
        view = memoryview(raw)
        while view:
            count = os.write(fd, view); require(count > 0, f"{label} write made no progress"); view = view[count:]
        os.fsync(fd)
    finally:
        if fd >= 0: os.close(fd)
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try: os.fsync(parent_fd)
    finally: os.close(parent_fd)
    result = stable_read(path, label); require(result.raw == raw, f"{label} changed after creation"); return result

def _run_driver(authority: Authority, repository: Path, runner: Callable[..., Any]) -> Any:
    """Run exactly the approved argv/stdin with an empty inherited environment."""
    result = runner(authority.argv, input=authority.stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={}, cwd=str(repository), check=False)
    require(isinstance(result.returncode, int) and result.returncode == 0, "replay driver did not succeed")
    require(isinstance(result.stdout, bytes) and isinstance(result.stderr, bytes), "driver output is not bytes")
    require(len(result.stdout) <= MAX_BYTES and len(result.stderr) <= MAX_BYTES, "driver output exceeds bound")
    require(COMPLETION_MARKER in result.stdout, "driver did not emit retained completion marker")
    return result

@dataclass(frozen=True)
class Publication:
    authority: Authority
    result: Snapshot
    completion: Snapshot
    repository: RepositoryObservation
    process: Any
    run_parent: Path

def _result_bytes(authority: Authority, replay_root: Path, repository: Path, observed: RepositoryObservation) -> bytes:
    value = {"schema": RESULT_SCHEMA, "phase": RESULT_PHASE, "lane": "candidate-5", "phase_a_manifest_sha256": authority.provenance.sha256, "phase_a_approval_digest": authority.descriptor.sha256, "replay_root": str(replay_root), "replay_root_identity": _dir_identity(replay_root, "replay root"), "repository": str(repository), "repository_identity": dict(observed.identity), "head_state": "detached", "final_head": observed.final_head, "parent": observed.parent, "tree": observed.tree, "base_commit": authority.base_commit, "base_tree": authority.base_tree, "protected_main_commit": authority.protected_main_commit, "required_ancestors": [], "forbidden_ancestors": []}
    require(set(value) == RESULT_KEYS, "result construction schema differs")
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()

def _completion_bytes(authority: Authority, result: Snapshot, process: Any) -> bytes:
    value = {"schema": COMPLETION_SCHEMA, "completion_marker": COMPLETION_MARKER.decode().strip(), "result_path": str(result.path), "result_sha256": result.sha256, "result_identity": {"st_dev": result.identity[0], "st_ino": result.identity[1], "st_uid": result.identity[2], "st_mode": result.identity[3], "st_size": result.identity[4], "st_nlink": result.identity[5]}, "driver_sha256": authority.artifacts["shell"].sha256, "markdown_sha256": authority.artifacts["markdown"].sha256, "json_sha256": authority.artifacts["json"].sha256, "shell_sha256": hashlib.sha256(authority.stdin).hexdigest(), "provenance_sha256": authority.provenance.sha256, "source_commit": authority.source_commit, "argv_sha256": hashlib.sha256(("\0".join(authority.argv) + "\0").encode()).hexdigest(), "stdin_sha256": hashlib.sha256(authority.stdin).hexdigest(), "stdout_sha256": hashlib.sha256(process.stdout).hexdigest(), "stderr_sha256": hashlib.sha256(process.stderr).hexdigest(), "stdout_bytes": len(process.stdout), "stderr_bytes": len(process.stderr)}
    require(set(value) == COMPLETION_KEYS, "completion construction schema differs")
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()

def publish_retained_result(run_parent: Path, authority_root: Path, approved_provenance_sha256: str, *, runner: Callable[..., Any] = subprocess.run) -> Publication:
    """Create retained evidence only after one authority-bound driver result."""
    authority = load_authority(authority_root, approved_provenance_sha256)
    run_parent, replay_root, repository = create_layout(run_parent)
    process = _run_driver(authority, repository, runner)
    observed = observe_repository(repository)
    result = _create_once(replay_root / RESULT_NAME, _result_bytes(authority, replay_root, repository, observed), "replay result")
    completion = _create_once(replay_root / COMPLETION_NAME, _completion_bytes(authority, result, process), "replay completion")
    publication = Publication(authority, result, completion, observed, process, run_parent)
    verify_publication(publication)
    return publication

def verify_publication(publication: Publication) -> None:
    """Re-read authority and repository; reject any semantic or path mutation."""
    authority = load_authority(publication.authority.root, publication.authority.provenance.sha256)
    replay_root, repository = publication.run_parent / "replay-root", publication.run_parent / "repository"
    _dir_identity(publication.run_parent, "run parent"); _dir_identity(replay_root, "replay root"); _dir_identity(repository, "repository")
    observed = observe_repository(repository)
    result = stable_read(publication.result.path, "replay result"); completion = stable_read(publication.completion.path, "replay completion")
    require(result == publication.result and completion == publication.completion, "retained replay record changed")
    require(_result_bytes(authority, replay_root, repository, observed) == result.raw, "replay result semantic evidence differs")
    require(_completion_bytes(authority, result, publication.process) == completion.raw, "completion process evidence differs")
    value = _json(completion.raw, "replay completion")
    require(set(value) == COMPLETION_KEYS and value["result_sha256"] == result.sha256 and value["source_commit"] == authority.source_commit, "completion semantic evidence differs")

def request_cleanup(*, enable_cleanup: bool = False) -> None:
    """Cleanup is deliberately absent and cannot delete replay or Git data."""
    require(not enable_cleanup, "cleanup remains disabled")
    raise Reject("cleanup has no implementation")
