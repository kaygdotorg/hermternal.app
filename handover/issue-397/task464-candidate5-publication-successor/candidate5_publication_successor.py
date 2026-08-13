#!/usr/bin/env python3
"""Publish exactly three candidate-five artifacts with create-only semantics."""
from __future__ import annotations

import fcntl
import hashlib
import os
import secrets
import stat
from pathlib import Path
from typing import Callable, Sequence

ROLES = ("markdown", "json", "shell")
NAMES = ("candidate-five.md", "candidate-five.json", "candidate-five.sh")


class Reject(Exception):
    """A fail-closed publication rejection, possibly with owned residue."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Reject(message)


def _inode(st: os.stat_result) -> tuple[int, int]:
    return (int(st.st_dev), int(st.st_ino))


def _dir_identity(st: os.stat_result) -> tuple[int, int, int, int]:
    # A child directory changes the parent's link count. Bind only static fields.
    return (int(st.st_dev), int(st.st_ino), int(st.st_uid), stat.S_IMODE(st.st_mode))


def _file_identity(st: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (int(st.st_dev), int(st.st_ino), int(st.st_uid), stat.S_IMODE(st.st_mode), int(st.st_size), int(st.st_nlink))


def _read_fd(fd: int, size: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks = []
    total = 0
    while total < size:
        chunk = os.read(fd, size - total)
        if not chunk:
            break
        chunks.append(chunk); total += len(chunk)
    raw = b"".join(chunks)
    require(len(raw) == size, "published file read was short")
    return raw


def _current_parent(root: Path, expected: tuple[int, ...]) -> None:
    require(str(root) == os.path.realpath(root), "publication parent became noncanonical")
    require(_dir_identity(os.lstat(root)) == expected, "publication parent was replaced")


def _owned_unlink(dir_fd: int, name: str, inode: tuple[int, int]) -> bool:
    """Remove only an owned inode and confirm that the name stays absent."""
    try:
        current = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    if _inode(current) != inode:
        return False
    os.unlink(name, dir_fd=dir_fd)
    try:
        os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    return False


def _validate_public(entry: dict, public_fd: int) -> None:
    """Bind a single-link public name to its full retained payload."""
    fd = os.open(entry["path"].name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=public_fd)
    try:
        before = os.fstat(fd)
        require(_inode(before) == entry["inode"], f"{entry['role']} public inode differs")
        require(
            stat.S_ISREG(before.st_mode)
            and stat.S_IMODE(before.st_mode) == 0o600
            and before.st_size == len(entry["payload"])
            and before.st_nlink == 1,
            f"{entry['role']} public identity differs",
        )
        raw = _read_fd(fd, len(entry["payload"]))
        require(os.read(fd, 1) == b"", f"{entry['role']} public bytes have a suffix")
        after = os.fstat(fd)
    finally:
        os.close(fd)
    final = os.stat(entry["path"].name, dir_fd=public_fd, follow_symlinks=False)
    require(
        _file_identity(before) == _file_identity(after) == _file_identity(final)
        and _inode(final) == entry["inode"],
        f"{entry['role']} public identity changed",
    )
    require(raw == entry["payload"] and hashlib.sha256(raw).digest() == hashlib.sha256(entry["payload"]).digest(), f"{entry['role']} public bytes differ")


def publish(
    targets: Sequence[Path],
    payloads: Sequence[bytes],
    *,
    validate: Callable[[tuple[Path, ...], tuple[bytes, ...]], object] | None = None,
    link_impl: Callable[..., None] = os.link,
    fsync_impl: Callable[[int], None] = os.fsync,
) -> object:
    """Create three names once, or roll back only transaction-owned inodes.

    POSIX has no crash-atomic transaction for three directory entries. Process
    death can leave a partial set. A detected runtime failure attempts complete
    owned rollback and raises an explicit residue error if cleanup is incomplete.
    """
    require(len(targets) == len(payloads) == 3, "publication requires exactly three roles")
    paths = tuple(Path(path) for path in targets)
    parent = paths[0].parent
    require(tuple(path.name for path in paths) == NAMES, "publication role names or order differ")
    require(len(set(paths)) == 3 and all(path.parent == parent for path in paths), "publication targets must be distinct siblings")
    require(parent.is_absolute() and str(parent) == os.path.realpath(parent), "publication parent must be canonical absolute")
    require(all(str(path) == str(parent / name) for path, name in zip(paths, NAMES)), "publication targets are noncanonical")
    pst = os.lstat(parent)
    require(stat.S_ISDIR(pst.st_mode) and not stat.S_ISLNK(pst.st_mode), "publication parent is not a directory")
    require(pst.st_uid == os.getuid() and stat.S_IMODE(pst.st_mode) == 0o700, "publication parent must be owned mode 0700")
    parent_identity = _dir_identity(pst)
    public_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    stage_fd = -1
    stage_name = ".candidate-five-stage-" + secrets.token_hex(12)
    entries: list[dict] = []
    primary: BaseException | None = None
    try:
        require(_dir_identity(os.fstat(public_fd)) == parent_identity, "held publication parent identity differs")
        fcntl.flock(public_fd, fcntl.LOCK_EX)
        _current_parent(parent, parent_identity)
        for path in paths:
            try: os.stat(path.name, dir_fd=public_fd, follow_symlinks=False)
            except FileNotFoundError: pass
            else: raise Reject(f"publication target already exists: {path}")
        os.mkdir(stage_name, 0o700, dir_fd=public_fd)
        stage_fd = os.open(stage_name, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=public_fd)
        require(stat.S_IMODE(os.fstat(stage_fd).st_mode) == 0o700, "staging directory mode differs")
        for role, path, payload in zip(ROLES, paths, payloads):
            require(isinstance(payload, bytes) and payload, f"{role} payload must be nonempty bytes")
            leaf = role + ".stage"
            fd = os.open(leaf, os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=stage_fd)
            entry = {"role": role, "path": path, "leaf": leaf, "fd": fd, "payload": payload, "published": False}
            entries.append(entry)
            before = os.fstat(fd); entry["inode"] = _inode(before)
            view = memoryview(payload)
            while view:
                written = os.write(fd, view); require(written > 0, f"{role} staged write made no progress"); view = view[written:]
            fsync_impl(fd)
            final = os.fstat(fd)
            require(stat.S_ISREG(final.st_mode) and stat.S_IMODE(final.st_mode) == 0o600 and final.st_nlink == 1 and final.st_size == len(payload), f"{role} staged identity differs")
            require(_read_fd(fd, len(payload)) == payload, f"{role} staged bytes differ")
            entry["identity"] = _file_identity(final)
        fsync_impl(stage_fd)
        for entry in entries:
            _current_parent(parent, parent_identity)
            link_error = None
            try:
                link_impl(entry["leaf"], entry["path"].name, src_dir_fd=stage_fd, dst_dir_fd=public_fd, follow_symlinks=False)
            except BaseException as exc:
                link_error = exc
            try: target_stat = os.stat(entry["path"].name, dir_fd=public_fd, follow_symlinks=False)
            except FileNotFoundError: target_stat = None
            entry["published"] = target_stat is not None and _inode(target_stat) == entry["inode"]
            if link_error is not None: raise link_error
            require(entry["published"], f"{entry['role']} link reconciliation failed")
        fsync_impl(public_fd)
        # Remove only the staging names before authority validation. The open
        # file descriptors and inode records retain transaction ownership while
        # each public artifact reaches the required single-link state.
        for entry in entries:
            require(_owned_unlink(stage_fd, entry["leaf"], entry["inode"]), f"{entry['role']} stage ownership changed")
        fsync_impl(stage_fd)
        fsync_impl(public_fd)
        for entry in entries:
            _current_parent(parent, parent_identity)
            _validate_public(entry, public_fd)
        result = validate(paths, tuple(payloads)) if validate is not None else paths
        # The callback receives exact retained payload bytes, but it can observe
        # pathnames. Rebind every public name after it returns before success.
        _current_parent(parent, parent_identity)
        for entry in entries:
            _validate_public(entry, public_fd)
        _current_parent(parent, parent_identity)
        for entry in entries:
            os.close(entry["fd"]); entry["fd"] = -1
        fsync_impl(stage_fd); os.close(stage_fd); stage_fd = -1
        os.rmdir(stage_name, dir_fd=public_fd); fsync_impl(public_fd)
        _current_parent(parent, parent_identity)
        return result
    except BaseException as exc:
        primary = exc
        residue = []
        for entry in reversed(entries):
            # Reconcile every name from its recorded inode. A cached published
            # flag is not authority because the link can succeed before an
            # observation failure.
            try:
                if not _owned_unlink(public_fd, entry["path"].name, entry["inode"]): residue.append(str(entry["path"]))
            except OSError as cleanup_error:
                residue.append(f"{entry['path']} (unobserved: {cleanup_error})")
            if stage_fd >= 0:
                try:
                    if not _owned_unlink(stage_fd, entry["leaf"], entry["inode"]): residue.append(stage_name + "/" + entry["leaf"])
                except OSError as cleanup_error:
                    residue.append(f"{stage_name}/{entry['leaf']} (unobserved: {cleanup_error})")
            if entry.get("fd", -1) >= 0:
                try: os.close(entry["fd"])
                except OSError: pass
        if stage_fd >= 0:
            try: fsync_impl(stage_fd)
            except OSError: pass
            try: os.close(stage_fd)
            except OSError: pass
            try: os.rmdir(stage_name, dir_fd=public_fd)
            except OSError: residue.append(stage_name)
        try: fsync_impl(public_fd)
        except OSError: residue.append("publication-parent-fsync")
        if residue: raise Reject(f"publication failed with owned or foreign residue: {residue}; cause: {exc}") from exc
        raise Reject(f"publication failed and rolled back: {exc}") from exc
    finally:
        try: fcntl.flock(public_fd, fcntl.LOCK_UN)
        except OSError: pass
        os.close(public_fd)
