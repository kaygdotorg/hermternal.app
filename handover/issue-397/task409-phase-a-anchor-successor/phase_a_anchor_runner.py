#!/usr/bin/env python3
"""Run only genuine Phase A and its create-only external approval anchor.

This checkpoint does not execute the candidate shell, replay, Git review,
network access, credentials, sockets, or Hermes.  It compiles only source bytes
that match the frozen commit and records each completed stage as create-only,
fsynced canonical JSON.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.abc
import importlib.util
import json
import os
import stat
import subprocess
import sys
import types
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence


SCHEMA = "hermternal.issue-397.phase-a-anchor-runner.v1"
EVIDENCE_SCHEMA = "hermternal.issue-397.phase-a-anchor-evidence.v1"
FROZEN_COMMIT = "28553997d43fd20291513c8524871e31b0ba8181"
FROZEN_TREE = "0ce8703a6d278c8a8e630950a01d9b319b6288fa"
REPOSITORY_ROOT = Path("/home/kayg/Developer/hermternal")
EXTERNAL_ROOT = Path("/home/kayg/Developer/hermternal-issue397-phase-a-anchor")
AUTHORITY_REL = Path("handover/issue-397/task464-candidate5-final")
PHASE_A_REL = Path("handover/issue-397/task409-execution-preflight/task409_execution_preflight_v3.py")
ANCHOR_REL = Path("handover/issue-397/task409-execution-preflight/provision_task409_phase_a_anchor_v3.py")
PHASE_B_REL = Path("handover/issue-397/task409-execution-preflight/task409_post_replay_identity_v3.py")
REVIEW_REL = Path("handover/issue-397/task409-execution-preflight/review_task464_git_v3.py")
PARITY_REL = Path("handover/issue-397/task409-execution-preflight/review_frozen_pair.py")
LIFECYCLE_REL = Path("handover/issue-397/task409-phase-b-lifecycle-successor/phase_b_lifecycle_successor.py")
GIT_HARDENING_REL = Path("handover/issue-397/task464-candidate5-git-config-successor/candidate5_git_config_successor.py")
FINAL_TOOL_REL = Path("handover/issue-397/task464-candidate5-final-triad/generator_orchestrator.py")
AUTHORITY_MODULE_REL = Path("handover/issue-397/task464-candidate5-authority-successor/candidate5_authority.py")

SOURCE_PINS = {
    PHASE_A_REL: ("54cb41fb3b3602404ff056befb0bd584f6d1b28ee7e0a079da0793619457aa31", "db8a4bf139da1199b52db594804dcbb432fedd01"),
    ANCHOR_REL: ("738530abecd61f38a3c9c6fe23d227b28bfd9f9093aa427796063692bb424ea8", "ec61ef26c0bc98ebc054388cfd70f8743b9f2b74"),
    PHASE_B_REL: ("4163d2b05ad40bb07dad2ccd2b59c16751541e32acb4fa6c1c7a526053faaaf9", "cf364f6bac02b290db52e0e375cfd5fbbde96e1d"),
    REVIEW_REL: ("dc4e95cc055947673702048222fe963cbce1ac9673e35d072ecd2214e252ab7c", "0ad33db10d541781621cf375969ca024a6a6ff65"),
    PARITY_REL: ("9190c18378ad80c2d2845d72be4bfeddea117775056364598d4e303256382a41", "617bdec7aa89742970e0a906ccf93a637fe04137"),
    LIFECYCLE_REL: ("e5b6846ad813a2e4b607983f8a95e49e41075195582b12c0ec8225d066a7cd4d", "681c8e600a8d4502edaa2964a6668987504d1d10"),
    GIT_HARDENING_REL: ("b2b5a5f1e0ed813325a23cb32eb075b2637872f5c5176e81c79879af4ab1861a", "95f6dc3d767c944aa2bb15581e77c0e30cfe282c"),
    FINAL_TOOL_REL: ("d9c36a3c3e99d0379186fc9ea0a26a5d93ac26eb4bd1c826c209b9bee0547361", "6a4199c07a3e6eff482a2056c43b2b8d9fe19738"),
    AUTHORITY_MODULE_REL: ("1eec1b59f608a3c64d4abb532fe6dbe031c4ba8008b46775db3ee6a75c9bb9a8", "7ec57e0bd876aabe5c3fcd0df992ff53a15145f8"),
}
FINAL_PINS = {
    "candidate-five.md": "706237ec508d96f564e5395e86dba943a11eb5057fb676bf95b924815158dad9",
    "candidate-five.json": "dd0e9873941c30aee7515a382e3ca7c282df840d2d4364a7dfa5f21fce0ecd60",
    "candidate-five.sh": "f7d5adfc9178431942d62948ffaf1953a2273bdec002661def9d0e80ffc34676",
    "authority-descriptor.json": "cf10f8286eca92d42130c17b9e086b8776dc385fa3a297c90725787415776f34",
    "provenance-manifest.json": "363d6f62335a5ff9f92eefabe87dd568032e71871390fa9fc5ae6fd72e3ac320",
}
FINAL_NAMES = tuple(FINAL_PINS)
PHASE_A_RECORD = "phase-a.json"
ANCHOR_RECORD = "anchor.json"
ANCHOR_NAME = "phase-a-approval-anchor.json"
MAX_SOURCE = 2 * 1024 * 1024
MAX_EVIDENCE = 4 * 1024 * 1024


class Reject(Exception):
    """A deliberate fail-closed runner rejection."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Reject(message)


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _identity(st: os.stat_result) -> dict[str, int]:
    return {
        "st_dev": int(st.st_dev), "st_ino": int(st.st_ino), "st_uid": int(st.st_uid),
        "st_gid": int(st.st_gid), "st_mode": stat.S_IMODE(st.st_mode),
        "st_size": int(st.st_size), "st_nlink": int(st.st_nlink),
        "st_mtime_ns": int(st.st_mtime_ns), "st_ctime_ns": int(st.st_ctime_ns),
    }


def _directory_binding(identity: Mapping[str, int]) -> tuple[int, int, int, int, int]:
    """Return directory fields that do not change when a child is created."""
    return tuple(identity[key] for key in ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode"))


def _directory_identity(path: Path, label: str, *, exact_mode: int | None = None) -> dict[str, int]:
    require(path.is_absolute() and os.path.realpath(path) == os.fspath(path), f"{label} is not canonical absolute")
    current = os.lstat(path)
    require(stat.S_ISDIR(current.st_mode) and not stat.S_ISLNK(current.st_mode), f"{label} is not a directory")
    require(current.st_uid == os.getuid(), f"{label} owner differs")
    mode = stat.S_IMODE(current.st_mode)
    require(not mode & 0o022, f"{label} is group/world writable")
    require(exact_mode is None or mode == exact_mode, f"{label} mode differs")
    return _identity(current)


@dataclass(frozen=True)
class Snapshot:
    path: Path
    raw: bytes
    sha256: str
    identity: Mapping[str, int]


def stable_read(path: Path, label: str, limit: int = MAX_EVIDENCE) -> Snapshot:
    """Read a canonical single-link file three times through no-follow handles."""
    path = Path(path)
    require(path.is_absolute() and os.path.realpath(path) == os.fspath(path), f"{label} path is not canonical absolute")
    reads: list[Snapshot] = []
    for _ in range(3):
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, f"{label} is not a single-link regular file")
            require(before.st_uid == os.getuid() and not stat.S_IMODE(before.st_mode) & 0o022, f"{label} is not private")
            require(0 < before.st_size <= limit, f"{label} size is outside its bound")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, min(131072, limit + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                require(total <= limit, f"{label} exceeds its byte bound")
            after = os.fstat(fd)
        finally:
            os.close(fd)
        final = os.lstat(path)
        raw = b"".join(chunks)
        identity = _identity(before)
        require(identity == _identity(after) == _identity(final), f"{label} identity changed during read")
        require(len(raw) == before.st_size, f"{label} byte count differs")
        reads.append(Snapshot(path, raw, hashlib.sha256(raw).hexdigest(), identity))
    require(reads[0] == reads[1] == reads[2], f"{label} changed across stable reads")
    return reads[0]


class _VerifiedLoader(importlib.abc.Loader):
    """Execute one already verified byte buffer without reopening its path."""

    def __init__(self, path: Path, raw: bytes) -> None:
        self.path = path
        self.raw = raw

    def create_module(self, spec: Any) -> types.ModuleType | None:
        return None

    def exec_module(self, module: types.ModuleType) -> None:
        module.__file__ = os.fspath(self.path)
        module.__package__ = ""
        exec(compile(self.raw, os.fspath(self.path), "exec", dont_inherit=True), module.__dict__)


@contextmanager
def _verified_imports(sources: Mapping[Path, bytes]) -> Iterator[None]:
    """Route legacy file loaders to the exact bytes already verified here."""
    original = importlib.util.spec_from_file_location

    def from_verified(name: str, location: Any, *args: Any, **kwargs: Any) -> Any:
        path = Path(location).resolve()
        raw = sources.get(path)
        if raw is not None:
            return importlib.util.spec_from_loader(name, _VerifiedLoader(path, raw), origin=os.fspath(path))
        return original(name, location, *args, **kwargs)

    importlib.util.spec_from_file_location = from_verified
    try:
        yield
    finally:
        importlib.util.spec_from_file_location = original


def _load_from_bytes(name: str, path: Path, raw: bytes, sources: Mapping[Path, bytes]) -> types.ModuleType:
    module = types.ModuleType(name)
    module.__file__ = os.fspath(path)
    module.__loader__ = None
    module.__package__ = ""
    module.__spec__ = None
    sys.modules[name] = module
    try:
        with _verified_imports(sources):
            exec(compile(raw, os.fspath(path), "exec", dont_inherit=True), module.__dict__)
    except Exception:
        sys.modules.pop(name, None)
        raise
    return module


def _trusted_git_state() -> tuple[tuple[int, ...], str]:
    path = Path("/usr/bin/git")
    results: list[tuple[tuple[int, ...], str]] = []
    for _ in range(3):
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= 16 * 1024 * 1024, "trusted Git file identity differs")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, min(131072, 16 * 1024 * 1024 + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                require(total <= 16 * 1024 * 1024, "trusted Git exceeds its byte bound")
            after = os.fstat(fd)
        finally:
            os.close(fd)
        final = os.lstat(path)
        identity = (int(before.st_dev), int(before.st_ino), int(before.st_uid), stat.S_IMODE(before.st_mode), int(before.st_size), int(before.st_nlink), int(before.st_mtime_ns), int(before.st_ctime_ns))
        final_identity = (int(final.st_dev), int(final.st_ino), int(final.st_uid), stat.S_IMODE(final.st_mode), int(final.st_size), int(final.st_nlink), int(final.st_mtime_ns), int(final.st_ctime_ns))
        after_identity = (int(after.st_dev), int(after.st_ino), int(after.st_uid), stat.S_IMODE(after.st_mode), int(after.st_size), int(after.st_nlink), int(after.st_mtime_ns), int(after.st_ctime_ns))
        require(identity == after_identity == final_identity and total == before.st_size, "trusted Git changed during read")
        require(before.st_uid == 0 and not stat.S_IMODE(before.st_mode) & 0o022 and stat.S_IMODE(before.st_mode) & 0o111, "trusted Git ownership or mode differs")
        results.append((identity, hashlib.sha256(b"".join(chunks)).hexdigest()))
    require(results[0] == results[1] == results[2], "trusted Git changed across stable reads")
    return results[0]


def _git(root: Path, binding: Any, *args: str) -> bytes:
    require(_trusted_git_state() == (binding.identity, binding.sha256), "trusted Git differs before command")
    env = {"PATH": "/usr/bin:/bin", "HOME": "/dev/null", "LANG": "C", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1", "GIT_ATTR_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1"}
    result = subprocess.run(["/usr/bin/git", "-C", os.fspath(root), *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False)
    require(_trusted_git_state() == (binding.identity, binding.sha256), "trusted Git differs after command")
    require(result.returncode == 0, f"read-only Git check failed: {' '.join(args)}")
    return result.stdout.rstrip(b"\n")


def verify_frozen_repository(binding: Any, root: Path = REPOSITORY_ROOT) -> None:
    """Bind the frozen tree, source blobs, and a clean local checkout."""
    root = Path(root)
    _directory_identity(root, "repository root")
    require(_git(root, binding, "rev-parse", "--show-toplevel") == os.fspath(root).encode(), "repository top level differs")
    require(_git(root, binding, "rev-parse", f"{FROZEN_COMMIT}^{{tree}}").decode() == FROZEN_TREE, "frozen tree differs")
    require(_git(root, binding, "status", "--porcelain=v1", "--untracked-files=all") == b"", "repository checkout is not clean")
    for relative, (_, blob) in SOURCE_PINS.items():
        observed = _git(root, binding, "rev-parse", f"{FROZEN_COMMIT}:{relative}").decode()
        require(observed == blob, f"frozen Git blob differs: {relative}")


@dataclass(frozen=True)
class Modules:
    phase_a: types.ModuleType
    anchor: types.ModuleType
    lifecycle: types.ModuleType
    final_tool: types.ModuleType
    git_reviewer: types.ModuleType


def load_modules(root: Path = REPOSITORY_ROOT) -> Modules:
    """Stable-read and execute the complete approved Phase-A dependency chain."""
    paths = {relative: (Path(root) / relative).resolve() for relative in SOURCE_PINS}
    snapshots: dict[Path, Snapshot] = {}
    for relative, path in paths.items():
        snapshot = stable_read(path, f"source {relative}", MAX_SOURCE)
        require(snapshot.sha256 == SOURCE_PINS[relative][0], f"source SHA-256 differs: {relative}")
        snapshots[path] = snapshot
    source_bytes = {path: snapshot.raw for path, snapshot in snapshots.items()}
    phase_a = _load_from_bytes("issue397_phase_a_anchor_genuine_phase_a", paths[PHASE_A_REL], source_bytes[paths[PHASE_A_REL]], source_bytes)
    anchor = _load_from_bytes("issue397_phase_a_anchor_genuine_anchor", paths[ANCHOR_REL], source_bytes[paths[ANCHOR_REL]], source_bytes)
    lifecycle = _load_from_bytes("issue397_phase_a_anchor_approved_lifecycle", paths[LIFECYCLE_REL], source_bytes[paths[LIFECYCLE_REL]], source_bytes)
    final_tool = _load_from_bytes("issue397_phase_a_anchor_final_tool", paths[FINAL_TOOL_REL], source_bytes[paths[FINAL_TOOL_REL]], source_bytes)
    git_hardening = _load_from_bytes("issue397_phase_a_anchor_git_hardening", paths[GIT_HARDENING_REL], source_bytes[paths[GIT_HARDENING_REL]], source_bytes)
    git_reviewer = git_hardening.install_successor()
    lifecycle.PHASE_B.REVIEW = git_reviewer
    require(lifecycle.PHASE_A.validate_artifacts.__code__.co_filename == os.fspath(paths[PHASE_A_REL]), "#399 Phase A source differs")
    require(anchor.PHASE_A.validate_artifacts.__code__.co_filename == os.fspath(paths[PHASE_A_REL]), "anchor Phase A source differs")
    require(lifecycle.PHASE_B.REVIEW is git_reviewer, "#400 was not installed in #399")
    return Modules(phase_a, anchor, lifecycle, final_tool, git_reviewer)


def _authority_state(modules: Modules) -> tuple[dict[str, Snapshot], Any, dict[str, int], dict[str, int]]:
    # The descriptor contains the frozen canonical absolute role paths. Tests
    # may load source from an isolated checkout, but they never redirect this
    # authority to fixture bytes or a temporary path.
    authority_root = REPOSITORY_ROOT / AUTHORITY_REL
    root_identity = _directory_identity(authority_root, "final authority root")
    parent_identity = _directory_identity(authority_root.parent, "final authority parent")
    snapshots = {name: stable_read(authority_root / name, f"final {name}") for name in FINAL_NAMES}
    for name, snapshot in snapshots.items():
        require(snapshot.sha256 == FINAL_PINS[name], f"final {name} SHA-256 differs")
    result = modules.final_tool.inspect_complete(authority_root, FINAL_PINS["authority-descriptor.json"], FINAL_PINS["provenance-manifest.json"])
    require(_directory_identity(authority_root, "final authority root") == root_identity, "final authority root changed")
    require(_directory_identity(authority_root.parent, "final authority parent") == parent_identity, "final authority parent changed")
    return snapshots, result, root_identity, parent_identity


def _manifest(modules: Modules, authority: Any) -> dict[str, Any]:
    artifacts = authority.artifacts
    values: list[str] = []
    for role in ("markdown", "json", "shell"):
        values.append(os.fspath(artifacts[role].path))
    for role in ("markdown", "json", "shell"):
        values.append(artifacts[role].sha256)
    values.append(authority.normalized_json_sha256)
    for role in ("markdown", "json", "shell"):
        values.append(",".join(str(item) for item in artifacts[role].identity))
    shell = artifacts["shell"].raw
    values.extend([str(len(shell)), str(shell.count(b"\n")), shell[-1:].hex()])
    values.extend([modules.phase_a.LANE, "sha1", modules.phase_a.BASE_REF, modules.phase_a.BASE_COMMIT, modules.phase_a.BASE_TREE, modules.phase_a.MAIN_REF, modules.phase_a.MAIN_COMMIT])
    return modules.phase_a._manifest_from_wrapper(values)


def _create_directory(path: Path, label: str) -> dict[str, int]:
    parent_identity = _directory_identity(path.parent, f"{label} parent")
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        require(_identity(os.fstat(parent_fd)) == parent_identity, f"{label} parent changed before create")
        os.mkdir(path.name, 0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except FileExistsError as exc:
        raise Reject(f"{label} already exists") from exc
    finally:
        os.close(parent_fd)
    require(_directory_binding(_directory_identity(path.parent, f"{label} parent")) == _directory_binding(parent_identity), f"{label} parent changed")
    return _directory_identity(path, label, exact_mode=0o700)


def _publish_bytes(path: Path, raw: bytes, label: str) -> Snapshot:
    """Create, fsync, and reread bytes or remove the exact owned inode."""
    require(raw and isinstance(raw, bytes), f"{label} bytes are invalid")
    parent_identity = _directory_identity(path.parent, f"{path.name} parent", exact_mode=0o700)
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    fd = -1
    owned_inode: tuple[int, int] | None = None
    try:
        require(_identity(os.fstat(parent_fd)) == parent_identity, f"{path.name} parent changed before create")
        fd = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=parent_fd)
        opened = os.fstat(fd)
        owned_inode = (int(opened.st_dev), int(opened.st_ino))
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            require(written > 0, f"{path.name} write made no progress")
            offset += written
        os.fsync(fd)
        written_identity = _identity(os.fstat(fd))
        require(written_identity["st_mode"] == 0o600 and written_identity["st_nlink"] == 1 and written_identity["st_size"] == len(raw), f"{path.name} identity differs")
        os.fsync(parent_fd)
        require(_directory_binding(_directory_identity(path.parent, f"{path.name} parent", exact_mode=0o700)) == _directory_binding(parent_identity), f"{path.name} parent changed")
        snapshot = stable_read(path, label)
        require(snapshot.raw == raw and snapshot.identity["st_mode"] == 0o600, f"{label} publication differs")
        return snapshot
    except BaseException as primary:
        residue = "none"
        if owned_inode is not None:
            try:
                target = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
                if (int(target.st_dev), int(target.st_ino)) == owned_inode:
                    os.unlink(path.name, dir_fd=parent_fd)
                    os.fsync(parent_fd)
                    if fd >= 0 and os.fstat(fd).st_nlink != 0:
                        residue = "owned-inode-linked"
                else:
                    residue = "foreign-target-preserved"
            except FileNotFoundError:
                if fd >= 0 and os.fstat(fd).st_nlink != 0:
                    residue = "owned-inode-moved"
            except OSError as cleanup_error:
                residue = f"cleanup-failed:{cleanup_error}"
        if residue != "none":
            raise Reject(f"{label} publication failed: {primary}; residue={residue}") from primary
        raise
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent_fd)


def _publish_record(path: Path, value: Mapping[str, Any]) -> Snapshot:
    return _publish_bytes(path, _canonical_json(value), path.name)


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(item in "0123456789abcdef" for item in value)


def _validate_identity(value: Any, label: str) -> None:
    keys = {"st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_size", "st_nlink", "st_mtime_ns", "st_ctime_ns"}
    require(isinstance(value, dict) and set(value) == keys, f"{label} identity fields differ")
    require(all(isinstance(item, int) and not isinstance(item, bool) and item >= 0 for item in value.values()), f"{label} identity values differ")


def _validate_evidence(value: Mapping[str, Any], stage: str) -> None:
    """Validate the exact nested schema before publication or resume."""
    require(set(value) == {"schema", "stage", "prior_sha256", "inputs", "observations", "safety"}, f"{stage} evidence fields differ")
    require(value["schema"] == EVIDENCE_SCHEMA and value["stage"] == stage, f"{stage} evidence identity differs")
    require(_is_sha256(value["prior_sha256"]), f"{stage} prior SHA-256 differs")
    require(value["safety"] == _safety(), f"{stage} safety fields differ")
    inputs = value["inputs"]
    observations = value["observations"]
    require(isinstance(inputs, dict) and isinstance(observations, dict), f"{stage} evidence objects differ")
    if stage == "phase-a":
        require(value["prior_sha256"] == "0" * 64, "Phase A prior SHA-256 is not zero")
        require(set(inputs) == {"frozen_commit", "frozen_tree", "repository_root", "external_root"}, "Phase A input fields differ")
        require(inputs == {"frozen_commit": FROZEN_COMMIT, "frozen_tree": FROZEN_TREE, "repository_root": os.fspath(REPOSITORY_ROOT), "external_root": os.fspath(EXTERNAL_ROOT)} or os.environ.get("HERMTERNAL_PHASE_A_TEST_ROOT") == inputs.get("external_root"), "Phase A canonical inputs differ")
        require(set(observations) == {"anchor_provisioner_calls", "authority_files", "authority_parent_identity", "authority_root_identity", "external_parent_identity", "external_root_identity", "manifest", "owner_marker", "phase_a_approval_digest", "phase_a_validator_calls", "policy_sha256"}, "Phase A observation fields differ")
        require(observations["phase_a_validator_calls"] == 1 and observations["anchor_provisioner_calls"] == 0, "Phase A call counts differ")
        require(set(observations["authority_files"]) == set(FINAL_NAMES), "Phase A authority file set differs")
        for name, record in observations["authority_files"].items():
            require(set(record) == {"path", "sha256", "identity", "bytes", "lf_count", "terminal_byte_hex"}, f"Phase A {name} fields differ")
            require(_is_sha256(record["sha256"]) and record["sha256"] == FINAL_PINS[name], f"Phase A {name} digest differs")
            require(record["path"] == os.fspath(REPOSITORY_ROOT / AUTHORITY_REL / name), f"Phase A {name} path differs")
            require(all(isinstance(record[field], int) and not isinstance(record[field], bool) and record[field] >= 0 for field in ("bytes", "lf_count")), f"Phase A {name} scalar type differs")
            require(record["terminal_byte_hex"] == "0a", f"Phase A {name} terminal byte differs")
            _validate_identity(record["identity"], f"Phase A {name}")
            require(record["identity"]["st_uid"] == os.getuid() and record["identity"]["st_nlink"] == 1 and not record["identity"]["st_mode"] & 0o022, f"Phase A {name} file contract differs")
        for name in ("authority_parent_identity", "authority_root_identity", "external_parent_identity", "external_root_identity"):
            _validate_identity(observations[name], name)
        require(set(observations["manifest"]) == {"path", "sha256", "identity", "bytes"}, "Phase A manifest fields differ")
        require(_is_sha256(observations["manifest"]["sha256"]), "Phase A manifest digest differs")
        require(observations["manifest"]["path"] == os.fspath(Path(inputs["external_root"]) / "phase-a" / "input-manifest.json"), "Phase A manifest path differs")
        require(isinstance(observations["manifest"]["bytes"], int) and not isinstance(observations["manifest"]["bytes"], bool) and observations["manifest"]["bytes"] > 0, "Phase A manifest byte count differs")
        _validate_identity(observations["manifest"]["identity"], "Phase A manifest")
        require(observations["manifest"]["identity"]["st_uid"] == os.getuid() and observations["manifest"]["identity"]["st_mode"] == 0o600 and observations["manifest"]["identity"]["st_nlink"] == 1, "Phase A manifest file contract differs")
        require(set(observations["owner_marker"]) == {"path", "identity"}, "owner marker fields differ")
        require(observations["owner_marker"]["path"] == os.fspath(Path(inputs["external_root"]) / "phase-a" / ".owner"), "owner marker path differs")
        _validate_identity(observations["owner_marker"]["identity"], "owner marker")
        require(observations["owner_marker"]["identity"]["st_uid"] == os.getuid() and observations["owner_marker"]["identity"]["st_mode"] == 0o600 and observations["owner_marker"]["identity"]["st_nlink"] == 1, "owner marker file contract differs")
        require(_is_sha256(observations["phase_a_approval_digest"]) and _is_sha256(observations["policy_sha256"]), "Phase A derived digest differs")
    elif stage == "anchor":
        require(value["prior_sha256"] != "0" * 64, "anchor prior SHA-256 is zero")
        require(set(inputs) == {"expected_phase_a_sha256", "phase_a_manifest_sha256", "phase_a_approval_digest", "policy_sha256"}, "anchor input fields differ")
        require(all(_is_sha256(item) for item in inputs.values()), "anchor input digest differs")
        require(inputs["expected_phase_a_sha256"] == value["prior_sha256"], "anchor reviewed Phase A digest differs")
        require(set(observations) == {"anchor", "anchor_genuine_phase_a_validator_calls", "anchor_provisioner_calls", "authority_files", "external_root_identity", "phase_a_manifest_identity"}, "anchor observation fields differ")
        require(observations["anchor_provisioner_calls"] == 1 and observations["anchor_genuine_phase_a_validator_calls"] == 1, "anchor call counts differ")
        anchor_record = observations["anchor"]
        require(set(anchor_record) == {"path", "sha256", "identity", "bytes", "lf_count", "terminal_byte_hex", "fields"}, "anchor file fields differ")
        require(_is_sha256(anchor_record["sha256"]), "anchor file digest differs")
        require(isinstance(anchor_record["bytes"], int) and not isinstance(anchor_record["bytes"], bool) and anchor_record["bytes"] > 0, "anchor byte count differs")
        require(isinstance(anchor_record["lf_count"], int) and not isinstance(anchor_record["lf_count"], bool) and anchor_record["lf_count"] == 1, "anchor LF count differs")
        require(anchor_record["terminal_byte_hex"] == "0a", "anchor terminal byte differs")
        _validate_identity(anchor_record["identity"], "anchor file")
        require(set(anchor_record["fields"]) == {"schema", "phase", "manifest_sha256", "phase_a_approval_digest", "policy_sha256", "decision", "provisioning_boundary"}, "anchor content fields differ")
        require(anchor_record["fields"] == {"schema": "task409-execution-preflight/phase-a-approval-anchor/v1", "phase": "external-review-of-phase-a-consistency", "manifest_sha256": inputs["phase_a_manifest_sha256"], "phase_a_approval_digest": inputs["phase_a_approval_digest"], "policy_sha256": inputs["policy_sha256"], "decision": "approve-consistency-only", "provisioning_boundary": "external-review-input"}, "anchor content values differ")
        expected_root = Path(os.environ.get("HERMTERNAL_PHASE_A_TEST_ROOT", os.fspath(EXTERNAL_ROOT)))
        require(anchor_record["path"] == os.fspath(expected_root / "external-review" / ANCHOR_NAME), "anchor canonical path differs")
        expected_anchor_raw = _canonical_json(anchor_record["fields"])
        require(anchor_record["sha256"] == hashlib.sha256(expected_anchor_raw).hexdigest() and anchor_record["bytes"] == len(expected_anchor_raw), "anchor byte binding differs")
        require(anchor_record["identity"]["st_uid"] == os.getuid() and anchor_record["identity"]["st_mode"] == 0o600 and anchor_record["identity"]["st_nlink"] == 1, "anchor file contract differs")
        require(set(observations["authority_files"]) == set(FINAL_NAMES), "anchor authority file set differs")
        for name, record in observations["authority_files"].items():
            require(set(record) == {"sha256", "identity"} and record["sha256"] == FINAL_PINS[name], f"anchor {name} binding differs")
            _validate_identity(record["identity"], f"anchor {name}")
        _validate_identity(observations["external_root_identity"], "anchor external root")
        _validate_identity(observations["phase_a_manifest_identity"], "anchor Phase A manifest")
    else:
        raise Reject(f"unknown evidence stage: {stage}")


def _publish_evidence(path: Path, value: Mapping[str, Any], stage: str) -> Snapshot:
    _validate_evidence(value, stage)
    return _publish_record(path, value)


def _parse_closed_record(snapshot: Snapshot, stage: str) -> dict[str, Any]:
    try:
        value = json.loads(snapshot.raw.decode("utf-8"), object_pairs_hook=lambda pairs: _unique_object(pairs, snapshot.path.name))
    except Reject:
        raise
    except Exception as exc:
        raise Reject(f"{snapshot.path.name} is not strict JSON: {exc}") from exc
    require(isinstance(value, dict), f"{snapshot.path.name} root differs")
    _validate_evidence(value, stage)
    return value


def _unique_object(pairs: Sequence[tuple[str, Any]], label: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"{label} has duplicate key {key!r}")
        result[key] = value
    return result


def _safety() -> dict[str, str]:
    return {"approval": "consistency-only", "candidate_identity": "not-claimed", "execution": "not-run", "mutation": "not-run", "network": "not-used"}


def phase_a(
    modules: Modules,
    *,
    repository_root: Path = REPOSITORY_ROOT,
    external_root: Path = EXTERNAL_ROOT,
    validator_wrapper: Callable[[Callable[[dict[str, Any]], dict[str, Any]]], Callable[[dict[str, Any]], dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Validate genuine Phase A once, then create its root, manifest, and evidence."""
    repository_root = Path(repository_root)
    external_root = Path(external_root)
    require(external_root == EXTERNAL_ROOT or os.environ.get("HERMTERNAL_PHASE_A_TEST_ROOT") == os.fspath(external_root), "external root differs from fixed authority")
    require(external_root.is_absolute() and not os.path.lexists(external_root), "external root must be absent and absolute")
    require(repository_root not in external_root.parents and external_root not in repository_root.parents, "external root overlaps repository")
    parent_identity = _directory_identity(external_root.parent, "external root parent")
    before, authority, authority_root_identity, authority_parent_identity = _authority_state(modules)
    manifest = _manifest(modules, authority)
    calls = 0
    genuine = modules.phase_a.validate_artifacts

    def counted(value: dict[str, Any]) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return genuine(value)

    validator = validator_wrapper(counted) if validator_wrapper else counted
    try:
        validated = validator(manifest)
    except Exception as exc:
        raise Reject(f"genuine Phase A rejected: {exc}") from exc
    require(calls == 1, "genuine Phase A validator call count differs")
    _create_directory(external_root, "external root")
    _create_directory(external_root / "external-review", "external review root")
    _create_directory(external_root / "evidence", "evidence root")
    phase_root = external_root / "phase-a"
    _create_directory(phase_root, "Phase A root")
    owner_marker = phase_root / ".owner"
    _publish_record(owner_marker, {"executor": "not-implemented", "kind": "task409-phase-a-anchor-successor-owner", "read_only": True, "schema": SCHEMA, "uid": os.getuid()})
    manifest_path = phase_root / "input-manifest.json"
    manifest_raw = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode("utf-8")
    manifest_snapshot = _publish_bytes(manifest_path, manifest_raw, "Phase A manifest")
    manifest_sha256 = manifest_snapshot.sha256
    approval_digest = modules.phase_a.phase_a_approval_digest(manifest)
    policy_sha256 = modules.phase_a.policy_digest(validated["policy"])
    manifest_snapshot = stable_read(manifest_path, "Phase A manifest")
    require(manifest_snapshot.sha256 == manifest_sha256, "Phase A manifest SHA-256 differs")
    after, _, final_root_identity, final_parent_identity = _authority_state(modules)
    require(before == after and authority_root_identity == final_root_identity and authority_parent_identity == final_parent_identity, "final authority changed during Phase A")
    require(_directory_binding(_directory_identity(external_root.parent, "external root parent")) == _directory_binding(parent_identity), "external root parent changed")
    observations = {
        "anchor_provisioner_calls": 0,
        "authority_files": {name: {"path": os.fspath(item.path), "sha256": item.sha256, "identity": dict(item.identity), "bytes": len(item.raw), "lf_count": item.raw.count(b"\n"), "terminal_byte_hex": item.raw[-1:].hex()} for name, item in after.items()},
        "authority_parent_identity": authority_parent_identity,
        "authority_root_identity": authority_root_identity,
        "external_parent_identity": _directory_identity(external_root.parent, "external root parent"),
        "external_root_identity": _directory_identity(external_root, "external root", exact_mode=0o700),
        "manifest": {"path": os.fspath(manifest_path), "sha256": manifest_sha256, "identity": dict(manifest_snapshot.identity), "bytes": len(manifest_snapshot.raw)},
        "owner_marker": {"path": os.fspath(owner_marker), "identity": dict(stable_read(owner_marker, "owner marker").identity)},
        "phase_a_approval_digest": approval_digest,
        "phase_a_validator_calls": calls,
        "policy_sha256": policy_sha256,
    }
    record = {"schema": EVIDENCE_SCHEMA, "stage": "phase-a", "prior_sha256": "0" * 64, "inputs": {"frozen_commit": FROZEN_COMMIT, "frozen_tree": FROZEN_TREE, "repository_root": os.fspath(repository_root), "external_root": os.fspath(external_root)}, "observations": observations, "safety": _safety()}
    evidence_path = external_root / "evidence" / PHASE_A_RECORD
    evidence_snapshot = _publish_evidence(evidence_path, record, "phase-a")
    final_authority, _, final_root_identity, final_parent_identity = _authority_state(modules)
    require(after == final_authority and authority_root_identity == final_root_identity and authority_parent_identity == final_parent_identity, "final authority changed after Phase A evidence")
    require(stable_read(manifest_path, "final Phase A manifest") == manifest_snapshot, "Phase A manifest changed before PASS")
    require(stable_read(evidence_path, "final Phase A evidence") == evidence_snapshot, "Phase A evidence changed before PASS")
    require(_directory_binding(_directory_identity(external_root, "final external root", exact_mode=0o700)) == _directory_binding(observations["external_root_identity"]), "external root changed before Phase A PASS")
    return record


def anchor(
    modules: Modules,
    *,
    repository_root: Path = REPOSITORY_ROOT,
    external_root: Path = EXTERNAL_ROOT,
    expected_phase_a_sha256: str,
    provisioner_wrapper: Callable[[Callable[..., dict[str, Any]]], Callable[..., dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Resume exact Phase-A evidence and call the genuine anchor once."""
    repository_root = Path(repository_root)
    external_root = Path(external_root)
    require(external_root == EXTERNAL_ROOT or os.environ.get("HERMTERNAL_PHASE_A_TEST_ROOT") == os.fspath(external_root), "external root differs from fixed authority")
    root_identity = _directory_identity(external_root, "external root", exact_mode=0o700)
    phase_snapshot = stable_read(external_root / "evidence" / PHASE_A_RECORD, "Phase A evidence")
    require(_is_sha256(expected_phase_a_sha256), "expected Phase A SHA-256 is invalid")
    require(phase_snapshot.sha256 == expected_phase_a_sha256, "Phase A evidence SHA-256 differs from reviewed handoff")
    phase_record = _parse_closed_record(phase_snapshot, "phase-a")
    require(phase_record["inputs"] == {"frozen_commit": FROZEN_COMMIT, "frozen_tree": FROZEN_TREE, "repository_root": os.fspath(repository_root), "external_root": os.fspath(external_root)}, "Phase A evidence inputs differ")
    observations = phase_record["observations"]
    require(isinstance(observations, dict) and observations.get("phase_a_validator_calls") == 1 and observations.get("anchor_provisioner_calls") == 0, "Phase A evidence call counts differ")
    before, _, authority_root_identity, authority_parent_identity = _authority_state(modules)
    require(observations.get("authority_root_identity") == authority_root_identity and observations.get("authority_parent_identity") == authority_parent_identity, "Phase A authority binding differs")
    observed_authority = observations.get("authority_files")
    require(isinstance(observed_authority, dict), "Phase A authority observations differ")
    for name, snapshot in before.items():
        expected_record = {"path": os.fspath(snapshot.path), "sha256": snapshot.sha256, "identity": dict(snapshot.identity), "bytes": len(snapshot.raw), "lf_count": snapshot.raw.count(b"\n"), "terminal_byte_hex": snapshot.raw[-1:].hex()}
        require(observed_authority.get(name) == expected_record, f"Phase A {name} observation changed")
    require(observations.get("external_root_identity") == root_identity, "Phase A external root observation changed")
    require(observations.get("external_parent_identity") == _directory_identity(external_root.parent, "external root parent"), "Phase A external parent observation changed")
    manifest_path = external_root / "phase-a" / "input-manifest.json"
    manifest_snapshot = stable_read(manifest_path, "Phase A manifest")
    manifest_record = observations.get("manifest")
    require(isinstance(manifest_record, dict) and manifest_record.get("path") == os.fspath(manifest_path) and manifest_record.get("sha256") == manifest_snapshot.sha256 and manifest_record.get("identity") == manifest_snapshot.identity, "Phase A manifest evidence differs")
    require(manifest_record.get("bytes") == len(manifest_snapshot.raw), "Phase A manifest byte observation differs")
    owner_path = external_root / "phase-a" / ".owner"
    owner_snapshot = stable_read(owner_path, "Phase A owner marker")
    require(observations.get("owner_marker") == {"path": os.fspath(owner_path), "identity": dict(owner_snapshot.identity)}, "Phase A owner marker observation changed")
    manifest, observed_manifest_sha = modules.phase_a.load_manifest(manifest_path)
    require(observed_manifest_sha == manifest_snapshot.sha256, "Phase A manifest stable digest differs")
    approval_digest = modules.phase_a.phase_a_approval_digest(manifest)
    policy_sha256 = modules.phase_a.policy_digest(manifest["policy"])
    require(approval_digest == observations.get("phase_a_approval_digest") and policy_sha256 == observations.get("policy_sha256"), "Phase A derived digests differ")
    calls = 0
    validation_calls = 0
    genuine = modules.anchor.provision_anchor
    genuine_validate = modules.anchor.PHASE_A.validate_artifacts

    def counted_validate(value: dict[str, Any]) -> dict[str, Any]:
        nonlocal validation_calls
        validation_calls += 1
        return genuine_validate(value)

    def counted(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return genuine(*args, **kwargs)

    provisioner = provisioner_wrapper(counted) if provisioner_wrapper else counted
    anchor_path = external_root / "external-review" / ANCHOR_NAME
    modules.anchor.PHASE_A.validate_artifacts = counted_validate
    try:
        try:
            result = provisioner(manifest_path, anchor_path, manifest_sha256=manifest_snapshot.sha256, phase_a_approval_digest=approval_digest, policy_sha256=policy_sha256, decision=modules.anchor.DECISION)
        except Exception as exc:
            raise Reject(f"genuine anchor rejected: {exc}") from exc
    finally:
        modules.anchor.PHASE_A.validate_artifacts = genuine_validate
    require(calls == 1, "genuine anchor provisioner call count differs")
    require(validation_calls == 1, "anchor genuine Phase A validator call count differs")
    anchor_snapshot = stable_read(anchor_path, "external approval anchor")
    anchor_value = json.loads(anchor_snapshot.raw.decode("utf-8"), object_pairs_hook=lambda pairs: _unique_object(pairs, ANCHOR_NAME))
    require(isinstance(anchor_value, dict) and set(anchor_value) == set(modules.anchor.ANCHOR_KEYS), "anchor fields differ")
    require(result == {"path": os.fspath(anchor_path), "sha256": anchor_snapshot.sha256, "manifest_sha256": manifest_snapshot.sha256, "phase_a_approval_digest": approval_digest, "policy_sha256": policy_sha256, "decision": modules.anchor.DECISION, "provisioning_boundary": modules.anchor.PROVISIONING_BOUNDARY}, "anchor return differs from durable bytes")
    after, _, final_root_identity, final_parent_identity = _authority_state(modules)
    require(before == after and authority_root_identity == final_root_identity and authority_parent_identity == final_parent_identity, "final authority changed during anchor creation")
    require(_directory_identity(external_root, "external root", exact_mode=0o700) == root_identity, "external root changed")
    record = {"schema": EVIDENCE_SCHEMA, "stage": "anchor", "prior_sha256": expected_phase_a_sha256, "inputs": {"expected_phase_a_sha256": expected_phase_a_sha256, "phase_a_manifest_sha256": manifest_snapshot.sha256, "phase_a_approval_digest": approval_digest, "policy_sha256": policy_sha256}, "observations": {"anchor": {"path": os.fspath(anchor_path), "sha256": anchor_snapshot.sha256, "identity": dict(anchor_snapshot.identity), "bytes": len(anchor_snapshot.raw), "lf_count": anchor_snapshot.raw.count(b"\n"), "terminal_byte_hex": anchor_snapshot.raw[-1:].hex(), "fields": anchor_value}, "anchor_genuine_phase_a_validator_calls": validation_calls, "anchor_provisioner_calls": calls, "authority_files": {name: {"sha256": item.sha256, "identity": dict(item.identity)} for name, item in after.items()}, "external_root_identity": root_identity, "phase_a_manifest_identity": dict(manifest_snapshot.identity)}, "safety": _safety()}
    evidence_path = external_root / "evidence" / ANCHOR_RECORD
    evidence_snapshot = _publish_evidence(evidence_path, record, "anchor")
    final_authority, _, final_root_identity, final_parent_identity = _authority_state(modules)
    require(after == final_authority and authority_root_identity == final_root_identity and authority_parent_identity == final_parent_identity, "final authority changed after anchor evidence")
    require(stable_read(phase_snapshot.path, "final Phase A evidence") == phase_snapshot, "Phase A evidence changed before anchor PASS")
    require(stable_read(manifest_path, "final Phase A manifest") == manifest_snapshot, "Phase A manifest changed before anchor PASS")
    require(stable_read(anchor_path, "final external approval anchor") == anchor_snapshot, "external anchor changed before PASS")
    require(stable_read(evidence_path, "final anchor evidence") == evidence_snapshot, "anchor evidence changed before PASS")
    require(_directory_binding(_directory_identity(external_root, "final external root", exact_mode=0o700)) == _directory_binding(root_identity), "external root changed before anchor PASS")
    return record


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run genuine Phase A or create its external approval anchor")
    subparsers = parser.add_subparsers(dest="stage", required=True)
    subparsers.add_parser("phase-a")
    anchor_parser = subparsers.add_parser("anchor")
    anchor_parser.add_argument("--expected-phase-a-sha256", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(list(sys.argv[1:] if argv is None else argv))
        modules = load_modules()
        verify_frozen_repository(modules.git_reviewer.CANDIDATE5_GIT_BINDING)
        record = phase_a(modules) if args.stage == "phase-a" else anchor(modules, expected_phase_a_sha256=args.expected_phase_a_sha256)
        print(f"PASS: genuine {args.stage} checkpoint completed")
        print(json.dumps(record, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as exc:
        print(f"REJECT: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
