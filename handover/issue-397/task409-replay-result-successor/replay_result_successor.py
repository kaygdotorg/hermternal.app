#!/usr/bin/env python3
"""Create retained replay evidence without executing a replay driver.

This speculative successor is a contract for the later reviewed driver patch.
It accepts a process-bound completion only from an injected observer.  It has no
subprocess, Git, network, credential, socket, or cleanup implementation.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


RESULT_SCHEMA = "task409-execution-preflight/replay-result/v2"
RESULT_PHASE = "B-post-replay-detached-final-head"
COMPLETION_SCHEMA = "hermternal.issue-397.replay-completion.v1"
LANE = "candidate-4"
RESULT_NAME = "replay-result.json"
COMPLETION_NAME = "replay-completion.json"
COMPLETION_MARKER = "replay-complete-retained"
MAX_BYTES = 2 * 1024 * 1024
OID_RE = re.compile(r"[0-9a-f]{40}\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
DIR_FIELDS = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink")
RESULT_KEYS = frozenset({
    "schema", "phase", "lane", "phase_a_manifest_sha256",
    "phase_a_approval_digest", "replay_root", "replay_root_identity",
    "repository", "repository_identity", "head_state", "final_head",
    "parent", "tree", "base_commit", "base_tree", "protected_main_commit",
    "required_ancestors", "forbidden_ancestors",
})
COMPLETION_KEYS = frozenset({
    "schema", "completion_marker", "result_path", "result_sha256",
    "result_identity", "driver_sha256", "markdown_sha256", "json_sha256",
    "shell_sha256", "provenance_sha256", "source_commit", "argv_sha256", "stdin_sha256",
    "stdout_sha256", "stderr_sha256", "stdout_bytes", "stderr_bytes",
})


class Reject(Exception):
    """A deliberate fail-closed retained-replay rejection."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Reject(message)


def _sha(value: str, label: str) -> str:
    require(isinstance(value, str) and SHA_RE.fullmatch(value) is not None, f"{label} must be 64 lowercase hex")
    return value


def _oid(value: str, label: str) -> str:
    require(isinstance(value, str) and OID_RE.fullmatch(value) is not None, f"{label} must be 40 lowercase hex")
    return value


def _identity(st: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (int(st.st_dev), int(st.st_ino), int(st.st_uid), int(stat.S_IMODE(st.st_mode)), int(st.st_size), int(st.st_nlink))


def _dir_identity(path: Path, label: str) -> dict[str, int]:
    st = os.lstat(path)
    require(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode), f"{label} is not a directory")
    require(st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o700, f"{label} is not private mode 0700")
    return {"st_dev": int(st.st_dev), "st_ino": int(st.st_ino), "st_uid": int(st.st_uid), "st_mode": int(stat.S_IMODE(st.st_mode)), "st_nlink": int(st.st_nlink)}


def _canonical(path: Path, label: str) -> Path:
    path = Path(path)
    require(path.is_absolute() and os.path.realpath(path) == os.fspath(path), f"{label} is not canonical absolute")
    return path


def _strict_json(raw: bytes, label: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            require(key not in value, f"{label} has duplicate key {key!r}")
            value[key] = item
        return value
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except Reject:
        raise
    except Exception as exc:
        raise Reject(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    require(isinstance(value, dict), f"{label} root is not an object")
    return value


@dataclass(frozen=True)
class Snapshot:
    path: Path
    identity: tuple[int, int, int, int, int, int]
    raw: bytes
    sha256: str


def stable_read(path: Path, label: str, *, limit: int = MAX_BYTES, mode: int = 0o600) -> Snapshot:
    """Read exact private bytes three times through no-follow descriptors."""
    path = _canonical(path, label)
    snapshots: list[Snapshot] = []
    for _ in range(3):
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode), f"{label} is not regular")
            require(before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == mode, f"{label} mode or owner differs")
            require(before.st_nlink == 1 and 0 < before.st_size <= limit, f"{label} link count or size differs")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, min(131072, limit + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                require(total <= limit, f"{label} exceeds size bound")
                chunks.append(chunk)
            after = os.fstat(fd)
        finally:
            os.close(fd)
        final = os.lstat(path)
        identity = _identity(before)
        require(identity == _identity(after) == _identity(final), f"{label} identity changed during read")
        raw = b"".join(chunks)
        require(len(raw) == before.st_size, f"{label} byte count differs")
        snapshots.append(Snapshot(path, identity, raw, hashlib.sha256(raw).hexdigest()))
    require(snapshots[0] == snapshots[1] == snapshots[2], f"{label} changed across stable reads")
    return snapshots[0]


@dataclass(frozen=True)
class DriverContract:
    """Exact hashes and argv that a final #403 authority must supply."""
    argv: tuple[str, ...]
    stdin: bytes
    driver_sha256: str
    markdown_sha256: str
    json_sha256: str
    shell_sha256: str
    provenance_sha256: str

    def __post_init__(self) -> None:
        require(isinstance(self.argv, tuple) and self.argv and all(isinstance(item, str) and item for item in self.argv), "driver argv is invalid")
        require(isinstance(self.stdin, bytes) and self.stdin.endswith(b"\n"), "driver stdin must be LF-terminated bytes")
        for label, value in (("driver", self.driver_sha256), ("markdown", self.markdown_sha256), ("json", self.json_sha256), ("shell", self.shell_sha256), ("provenance", self.provenance_sha256)):
            _sha(value, label)
        require(hashlib.sha256(self.stdin).hexdigest() == self.shell_sha256, "authenticated stdin does not match shell hash")


@dataclass(frozen=True)
class ProcessResult:
    """The only test-double boundary: an observed driver process result."""
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class CommandEvidence:
    argv_sha256: str
    stdin_sha256: str
    stdout_sha256: str
    stderr_sha256: str
    stdout_bytes: int
    stderr_bytes: int


def invoke_driver(contract: DriverContract, observer: Callable[[tuple[str, ...], bytes], ProcessResult]) -> CommandEvidence:
    """Observe one exact driver call; the successor never owns a real spawn."""
    result = observer(contract.argv, contract.stdin)
    require(isinstance(result, ProcessResult), "process observer returned an invalid result")
    require(result.returncode == 0, "replay driver did not succeed")
    require(len(result.stdout) <= MAX_BYTES and len(result.stderr) <= MAX_BYTES, "driver output exceeds bound")
    marker = (COMPLETION_MARKER + "\n").encode("ascii")
    require(marker in result.stdout, "driver did not emit retained completion marker")
    argv_raw = ("\0".join(contract.argv) + "\0").encode("utf-8")
    return CommandEvidence(hashlib.sha256(argv_raw).hexdigest(), hashlib.sha256(contract.stdin).hexdigest(), hashlib.sha256(result.stdout).hexdigest(), hashlib.sha256(result.stderr).hexdigest(), len(result.stdout), len(result.stderr))


@dataclass(frozen=True)
class ReplayFacts:
    phase_a_manifest_sha256: str
    phase_a_approval_digest: str
    final_head: str
    parent: str
    tree: str
    base_commit: str
    base_tree: str
    protected_main_commit: str
    source_commit: str
    required_ancestors: tuple[str, ...]
    forbidden_ancestors: tuple[str, ...]

    def __post_init__(self) -> None:
        for label, value in (("Phase A manifest", self.phase_a_manifest_sha256), ("Phase A approval", self.phase_a_approval_digest)):
            _sha(value, label)
        for label, value in (("final head", self.final_head), ("parent", self.parent), ("tree", self.tree), ("base commit", self.base_commit), ("base tree", self.base_tree), ("protected main", self.protected_main_commit), ("source commit", self.source_commit)):
            _oid(value, label)
        for label, values in (("required ancestry", self.required_ancestors), ("forbidden ancestry", self.forbidden_ancestors)):
            require(len(values) == len(set(values)), f"{label} contains duplicates")
            for value in values:
                _oid(value, label)


def validate_layout(run_parent: Path, replay_root: Path, repository: Path) -> tuple[Path, Path, Path]:
    """Require retained replay control and repository roots to be exact siblings."""
    run_parent, replay_root, repository = (_canonical(value, label) for value, label in ((run_parent, "run parent"), (replay_root, "replay root"), (repository, "repository")))
    _dir_identity(run_parent, "run parent")
    require(replay_root.parent == run_parent and repository.parent == run_parent, "replay roots must be direct run-parent children")
    require(replay_root.name == "replay-root" and repository.name == "repository", "replay root names differ")
    require(replay_root != repository, "replay roots overlap")
    _dir_identity(replay_root, "replay root")
    _dir_identity(repository, "repository")
    return run_parent, replay_root, repository


def _result_bytes(replay_root: Path, repository: Path, facts: ReplayFacts) -> bytes:
    result = {
        "schema": RESULT_SCHEMA, "phase": RESULT_PHASE, "lane": LANE,
        "phase_a_manifest_sha256": facts.phase_a_manifest_sha256,
        "phase_a_approval_digest": facts.phase_a_approval_digest,
        "replay_root": str(replay_root), "replay_root_identity": _dir_identity(replay_root, "replay root"),
        "repository": str(repository), "repository_identity": _dir_identity(repository, "repository"),
        "head_state": "detached", "final_head": facts.final_head, "parent": facts.parent,
        "tree": facts.tree, "base_commit": facts.base_commit, "base_tree": facts.base_tree,
        "protected_main_commit": facts.protected_main_commit,
        "required_ancestors": list(facts.required_ancestors), "forbidden_ancestors": list(facts.forbidden_ancestors),
    }
    require(set(result) == RESULT_KEYS, "result schema construction differs")
    return (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _completion_bytes(result: Snapshot, contract: DriverContract, command: CommandEvidence, facts: ReplayFacts) -> bytes:
    value = {
        "schema": COMPLETION_SCHEMA, "completion_marker": COMPLETION_MARKER,
        "result_path": str(result.path), "result_sha256": result.sha256,
        "result_identity": {"st_dev": result.identity[0], "st_ino": result.identity[1], "st_uid": result.identity[2], "st_mode": result.identity[3], "st_size": result.identity[4], "st_nlink": result.identity[5]},
        "driver_sha256": contract.driver_sha256, "markdown_sha256": contract.markdown_sha256,
        "json_sha256": contract.json_sha256, "shell_sha256": contract.shell_sha256,
        "provenance_sha256": contract.provenance_sha256, "source_commit": facts.source_commit,
        "argv_sha256": command.argv_sha256,
        "stdin_sha256": command.stdin_sha256, "stdout_sha256": command.stdout_sha256,
        "stderr_sha256": command.stderr_sha256, "stdout_bytes": command.stdout_bytes,
        "stderr_bytes": command.stderr_bytes,
    }
    require(set(value) == COMPLETION_KEYS, "completion schema construction differs")
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _create_once(path: Path, raw: bytes, label: str) -> Snapshot:
    require(not os.path.lexists(path), f"{label} already exists")
    fd = -1
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            require(written > 0, f"{label} write made no progress")
            offset += written
        os.fsync(fd)
    except FileExistsError as exc:
        raise Reject(f"{label} already exists") from exc
    except OSError as exc:
        raise Reject(f"{label} write failed: {exc}") from exc
    finally:
        if fd >= 0:
            os.close(fd)
    try:
        parent_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except OSError as exc:
        raise Reject(f"{label} parent fsync failed: {exc}") from exc
    snapshot = stable_read(path, label)
    require(snapshot.raw == raw, f"{label} bytes differ after publication")
    return snapshot


@dataclass(frozen=True)
class Publication:
    result: Snapshot
    completion: Snapshot


def publish_retained_result(
    run_parent: Path,
    replay_root: Path,
    repository: Path,
    facts: ReplayFacts,
    contract: DriverContract,
    observer: Callable[[tuple[str, ...], bytes], ProcessResult],
) -> Publication:
    """Observe one exact driver call, then create strict retained evidence once."""
    _, replay_root, repository = validate_layout(run_parent, replay_root, repository)
    result_path = replay_root / RESULT_NAME
    completion_path = replay_root / COMPLETION_NAME
    require(not os.path.lexists(result_path) and not os.path.lexists(completion_path), "a retained replay record already exists")
    command = invoke_driver(contract, observer)
    result = _create_once(result_path, _result_bytes(replay_root, repository, facts), "replay result")
    completion = _create_once(completion_path, _completion_bytes(result, contract, command, facts), "replay completion")
    verify_publication(Publication(result, completion), run_parent, replay_root, repository)
    return Publication(result, completion)


def verify_publication(publication: Publication, run_parent: Path, replay_root: Path, repository: Path) -> None:
    """Reject path swaps, mutations, or a completion/result binding difference."""
    _, replay_root, repository = validate_layout(run_parent, replay_root, repository)
    require(publication.result.path == replay_root / RESULT_NAME and publication.completion.path == replay_root / COMPLETION_NAME, "publication paths differ")
    result = stable_read(publication.result.path, "replay result")
    completion = stable_read(publication.completion.path, "replay completion")
    require(result == publication.result and completion == publication.completion, "retained replay record changed")
    result_value = _strict_json(result.raw, "replay result")
    completion_value = _strict_json(completion.raw, "replay completion")
    require(set(result_value) == RESULT_KEYS and result_value["schema"] == RESULT_SCHEMA and result_value["phase"] == RESULT_PHASE, "replay result schema differs")
    require(set(completion_value) == COMPLETION_KEYS and completion_value["schema"] == COMPLETION_SCHEMA, "replay completion schema differs")
    require(completion_value["completion_marker"] == COMPLETION_MARKER, "completion marker differs")
    require(completion_value["result_path"] == str(result.path) and completion_value["result_sha256"] == result.sha256, "completion result binding differs")
    expected_identity = {"st_dev": result.identity[0], "st_ino": result.identity[1], "st_uid": result.identity[2], "st_mode": result.identity[3], "st_size": result.identity[4], "st_nlink": result.identity[5]}
    require(completion_value["result_identity"] == expected_identity, "completion result identity differs")
    require(result_value["replay_root"] == str(replay_root) and result_value["repository"] == str(repository), "result layout differs")
    require(result_value["replay_root_identity"] == _dir_identity(replay_root, "replay root"), "result replay-root identity differs")
    require(result_value["repository_identity"] == _dir_identity(repository, "repository"), "result repository identity differs")


def request_cleanup(*, enable_cleanup: bool = False) -> None:
    """Keep cleanup a separate explicit command and disabled in this successor."""
    require(enable_cleanup, "cleanup is disabled unless explicitly requested")
    raise Reject("cleanup has no implementation in this speculative successor")
