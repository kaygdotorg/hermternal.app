#!/usr/bin/env python3
"""Preserve early replay failures outside child-owned ephemeral roots.

This successor verified-loads failure v1 and changes only failure publication.
It creates one profile-derived private transaction directory before the child
starts. Phase A, anchor, wrapper, driver, and replay semantics stay unchanged.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import platform_profile

HERE = Path(__file__).resolve().parent
V1_PATH = HERE / "linux_replay_failure_v1.py"
V1_SHA256 = "a98d32b3dc5c2d8beeba0f8fb59963872e1d471f3af3a59e8eebd377bdd70efe"
SCHEMA = "hermternal.issue-397.replay-failure.v2"
DIRECTORY_NAME = "hermternal-issue397-replay-failure-v1"
OWNER_NAME = ".owner"
FAILURE_NAME = "replay-failure.json"


def _load_v1() -> types.ModuleType:
    """Compile only one stable buffer with the approved v1 digest."""
    descriptor = os.open(V1_PATH, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError("failure v1 is not a single-link regular file")
        raw = b""
        while len(raw) < before.st_size:
            block = os.read(descriptor, before.st_size - len(raw))
            if not block:
                raise RuntimeError("failure v1 read ended early")
            raw += block
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    final = os.lstat(V1_PATH)
    identity = lambda value: (value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode, value.st_size, value.st_nlink, value.st_mtime_ns, value.st_ctime_ns)
    if identity(before) != identity(after) or identity(before) != identity(final) or hashlib.sha256(raw).hexdigest() != V1_SHA256:
        raise RuntimeError("failure v1 identity or SHA-256 differs")
    module = types.ModuleType("issue397_linux_replay_failure_v2_base")
    module.__file__ = os.fspath(V1_PATH)
    sys.modules[module.__name__] = module
    exec(compile(raw, module.__file__, "exec", dont_inherit=True), module.__dict__)
    return module


@dataclass(frozen=True)
class Transaction:
    """Inode identities owned by this one boundary call."""

    root: Path
    root_inode: tuple[int, int]
    owner_inode: tuple[int, int]
    parent_fd: int
    root_fd: int


def _failure_root(profile: platform_profile.PlatformProfile) -> Path:
    return Path(profile.source_repository).parent / DIRECTORY_NAME


def _owner_bytes(profile, anchor_sha: str) -> bytes:
    value = {"schema": "hermternal.issue-397.replay-failure-owner.v1", "profile_id": profile.profile_id, "profile_sha256": profile.sha256, "anchor_evidence_sha256": anchor_sha, "failure_successor_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _write_at(root_fd: int, name: str, raw: bytes, label: str) -> tuple[int, int]:
    """Create, fsync, and reread one file through a held root descriptor."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, 0o600, dir_fd=root_fd)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_nlink != 1:
            raise RuntimeError(f"{label} identity differs")
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise RuntimeError(f"{label} write made no progress")
            offset += written
        os.fsync(descriptor)
        identity = (opened.st_dev, opened.st_ino)
    finally:
        os.close(descriptor)
    os.fsync(root_fd)
    for _ in range(3):
        read_fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=root_fd)
        try:
            before = os.fstat(read_fd)
            observed = b""
            while len(observed) < before.st_size:
                block = os.read(read_fd, before.st_size - len(observed))
                if not block:
                    raise RuntimeError(f"{label} reread ended early")
                observed += block
            after = os.fstat(read_fd)
        finally:
            os.close(read_fd)
        if (before.st_dev, before.st_ino) != identity or before != after or observed != raw:
            raise RuntimeError(f"{label} changed during stable reread")
    return identity


def _prepare(wrapper, profile, anchor_sha: str) -> Transaction:
    """Create and durably bind the fixed private directory before process start."""
    root = _failure_root(profile)
    if not root.is_absolute() or os.path.realpath(root) != os.fspath(root):
        raise wrapper.Reject("failure root is not canonical absolute")
    parent_fd = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    root_fd = -1
    try:
        parent_inode = (os.fstat(parent_fd).st_dev, os.fstat(parent_fd).st_ino)
        if os.path.lexists(root):
            raise wrapper.Reject("failure root already exists")
        os.mkdir(root.name, 0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
        root_stat = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(root_stat.st_mode) or stat.S_IMODE(root_stat.st_mode) != 0o700 or root_stat.st_uid != os.getuid():
            raise wrapper.Reject("new failure root identity differs")
        root_inode = (root_stat.st_dev, root_stat.st_ino)
        current_parent = os.stat(root.parent, follow_symlinks=False)
        if (current_parent.st_dev, current_parent.st_ino) != parent_inode:
            raise wrapper.Reject("failure root parent was replaced")
        root_fd = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        opened_root = os.fstat(root_fd)
        if (opened_root.st_dev, opened_root.st_ino) != root_inode:
            raise wrapper.Reject("failure root was replaced before binding")
        owner_inode = _write_at(root_fd, OWNER_NAME, _owner_bytes(profile, anchor_sha), "failure owner")
        current = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != root_inode:
            raise wrapper.Reject("failure root was replaced before child start")
        return Transaction(root, root_inode, owner_inode, parent_fd, root_fd)
    except BaseException:
        if root_fd >= 0:
            os.close(root_fd)
        os.close(parent_fd)
        raise


def _residue(wrapper, pid: int) -> dict[str, Any]:
    run_root = wrapper._run_root(pid)
    replay_root = run_root / "replay-root"
    paths = {"run_root": run_root, "replay_root": replay_root, "pending": replay_root / wrapper.PENDING_NAME, "result": replay_root / wrapper.RESULT_NAME, "completion": replay_root / wrapper.COMPLETION_NAME}
    return {name: {"path": os.fspath(path), "exists": os.path.lexists(path)} for name, path in paths.items()}


def _publish_failure(wrapper, v1, adapter, authority, profile, transaction: Transaction, phase_path: Path, phase_sha: str, anchor_sha: str, result) -> None:
    record = v1._record(adapter, authority, profile, phase_path, phase_sha, anchor_sha, result)
    record["schema"] = SCHEMA
    record["expected_ephemeral_residue"] = _residue(wrapper, result.pid)
    raw = wrapper._canonical_json(record)
    current = os.stat(transaction.root.name, dir_fd=transaction.parent_fd, follow_symlinks=False)
    wrapper.require((current.st_dev, current.st_ino) == transaction.root_inode, "failure root was replaced after child")
    _write_at(transaction.root_fd, FAILURE_NAME, raw, "early replay failure")
    current = os.stat(transaction.root.name, dir_fd=transaction.parent_fd, follow_symlinks=False)
    wrapper.require((current.st_dev, current.st_ino) == transaction.root_inode, "failure root was replaced after publication")


def _remove_empty_owned(wrapper, transaction: Transaction) -> None:
    """Remove only this call's marker and empty directory after child success."""
    try:
        root_stat = os.stat(transaction.root.name, dir_fd=transaction.parent_fd, follow_symlinks=False)
        wrapper.require((root_stat.st_dev, root_stat.st_ino) == transaction.root_inode and stat.S_ISDIR(root_stat.st_mode), "failure root was replaced")
        wrapper.require(set(os.listdir(transaction.root_fd)) == {OWNER_NAME}, "failure root is not transaction-owned empty")
        owner = os.stat(OWNER_NAME, dir_fd=transaction.root_fd, follow_symlinks=False)
        wrapper.require((owner.st_dev, owner.st_ino) == transaction.owner_inode and stat.S_ISREG(owner.st_mode), "failure owner was replaced")
        os.unlink(OWNER_NAME, dir_fd=transaction.root_fd)
        os.fsync(transaction.root_fd)
        current = os.stat(transaction.root.name, dir_fd=transaction.parent_fd, follow_symlinks=False)
        wrapper.require((current.st_dev, current.st_ino) == transaction.root_inode, "failure root changed before cleanup")
        os.rmdir(transaction.root.name, dir_fd=transaction.parent_fd)
        os.fsync(transaction.parent_fd)
    finally:
        os.close(transaction.root_fd)
        os.close(transaction.parent_fd)


def load_approved_wrapper(expected_anchor_sha256: str):
    """Install fixed-root failure publication without starting replay."""
    v1 = _load_v1()
    anchor_sha = v1._sha(expected_anchor_sha256, "anchor evidence SHA-256")
    adapter = v1.load_phase_a_adapter()
    wrapper, authority = adapter.load_approved_wrapper(anchor_sha, v1.PHASE_A_ADAPTER_SHA256)
    profile = platform_profile.load()
    predecessor = wrapper.execute_and_publish

    def execute_and_publish(phase_a_evidence, expected_phase_a_evidence_sha256, *, process_boundary=wrapper._run_process):
        def observed(argv, stdin, environment):
            transaction = _prepare(wrapper, profile, anchor_sha)
            result = process_boundary(argv, stdin, environment)
            failed = result.returncode != 0 or result.stdout != wrapper.SUCCESS_OUTPUT or bool(result.stderr)
            if failed:
                try:
                    _publish_failure(wrapper, v1, adapter, authority, profile, transaction, Path(phase_a_evidence), v1._sha(expected_phase_a_evidence_sha256, "Phase A evidence SHA-256"), anchor_sha, result)
                finally:
                    os.close(transaction.root_fd)
                    os.close(transaction.parent_fd)
            else:
                _remove_empty_owned(wrapper, transaction)
            return result
        return predecessor(phase_a_evidence, expected_phase_a_evidence_sha256, process_boundary=observed)

    wrapper.execute_and_publish = execute_and_publish
    return wrapper, authority
