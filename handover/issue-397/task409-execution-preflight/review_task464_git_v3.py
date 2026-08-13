#!/usr/bin/env python3
"""Hermetic, read-only Git observations for Task #409 Phase B.

This reviewer treats the repository metadata as an authority boundary.  It reads
and rejects command-bearing local configuration before starting Git, binds the
configuration and detached ``.git/HEAD`` bytes to stable file identities, and
rechecks those bindings around every Git subprocess.  The caller still owns the
post-replay result schema and approval-digest binding.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

BASE_COMMIT = "729f2613af2b78d58b07918478e9102d5716f367"
BASE_TREE = "43f86b645fc9f89d5d4aa1e6978b1f61f0b5c69f"
MAIN_COMMIT = "3ebf8b3fe4767442490ab3053c0c1ccf84e8019f"
OID_RE = re.compile(r"[0-9a-f]{40}\Z")
MAX_OUTPUT = 16 * 1024 * 1024
MAX_METADATA_ENTRIES = 500_000
GIT_TIMEOUT = 30
PATCH_TIMEOUT = 15
SAFE_ENV = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/dev/null",
    "LANG": "C",
    "LC_ALL": "C",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_ATTR_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_NO_LAZY_FETCH": "1",
}


class Reject(Exception):
    """A deliberate fail-closed review rejection."""


def reject(message: str) -> None:
    raise Reject(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        reject(message)


def _git_executable() -> str:
    for candidate in ("/usr/bin/git", "/opt/homebrew/bin/git"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    reject("trusted Git executable is unavailable")


GIT = _git_executable()


def _bounded(data: bytes, label: str, limit: int = MAX_OUTPUT) -> bytes:
    if len(data) > limit:
        reject(f"{label} exceeds bounded size")
    return data


def _decode(data: bytes, label: str) -> str:
    _bounded(data, label)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        reject(f"{label} is not valid UTF-8: {exc}")
    raise AssertionError("unreachable")


def _identity(st: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        int(st.st_dev),
        int(st.st_ino),
        int(st.st_uid),
        int(stat.S_IMODE(st.st_mode)),
        int(st.st_size),
        int(st.st_nlink),
        int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1_000_000_000))),
        int(getattr(st, "st_ctime_ns", int(st.st_ctime * 1_000_000_000))),
    )


def identity_dict(value: tuple[int, ...]) -> dict[str, int]:
    fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_size", "st_nlink", "st_mtime_ns", "st_ctime_ns")
    require(len(value) == len(fields), "file identity width differs")
    return dict(zip(fields, value))


@dataclass(frozen=True)
class FileSnapshot:
    path: Path
    identity: tuple[int, int, int, int, int, int, int, int]
    sha256: str
    raw: bytes


def _canonical_file_parent(path: Path, label: str) -> Path:
    require(path.is_absolute(), f"{label} must be absolute")
    require(str(path) == os.path.realpath(str(path)), f"{label} must already be canonical")
    parent = path.parent
    require(str(parent) == os.path.realpath(str(parent)), f"{label} parent must already be canonical")
    return parent


def _open_directory_chain(directory: Path, label: str) -> tuple[list[int], tuple[tuple[int, ...], ...]]:
    """Open every absolute component with descriptor-relative no-follow.

    Ancestors are traversal boundaries, not trust boundaries: root-owned 0755
    system directories and the root-owned sticky ``/private/tmp`` are allowed.
    The repository/result/artifact boundary itself is checked by its caller.
    Every component identity is retained and re-walked before the file snapshot
    is returned, so a symlink or inode swap cannot redirect the read.
    """
    directory = Path(directory)
    require(directory.is_absolute(), f"{label} must be absolute")
    require(str(directory) == os.path.realpath(str(directory)), f"{label} must already be canonical")
    parts = directory.parts
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    fds: list[int] = []
    identities: list[tuple[int, ...]] = []
    try:
        current = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | nofollow)
        fds.append(current)
        root_st = os.fstat(current)
        require(stat.S_ISDIR(root_st.st_mode), f"{label} root is not a directory")
        identities.append(_identity(root_st))
        for part in parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | nofollow, dir_fd=current)
            fds.append(child)
            child_st = os.fstat(child)
            require(stat.S_ISDIR(child_st.st_mode), f"{label} component is not a directory: {part}")
            mode = stat.S_IMODE(child_st.st_mode)
            # No ordinary group/world-writable traversal component is trusted.
            # The only exception is a root-owned sticky directory such as
            # /private/tmp, whose entries are protected by the sticky bit.
            if mode & 0o022:
                require(child_st.st_uid == 0 and (mode & 0o1000) and (mode & 0o002),
                        f"{label} component is writable without a sticky root-owned boundary: {part}")
            identities.append(_identity(child_st))
            current = child
        return fds, tuple(identities)
    except Reject:
        for fd in reversed(fds):
            os.close(fd)
        raise
    except OSError as exc:
        for fd in reversed(fds):
            os.close(fd)
        reject(f"{label} directory chain cannot be opened safely: {exc}")
    raise AssertionError("unreachable")


def _directory_chain_matches(directory: Path, expected: tuple[tuple[int, ...], ...], label: str) -> None:
    fds, observed = _open_directory_chain(directory, label)
    try:
        require(observed == expected, f"{label} intermediate directory identity changed")
    finally:
        for fd in reversed(fds):
            os.close(fd)


def read_bound_file(path: Path, label: str, *, limit: int = 2 * 1024 * 1024) -> FileSnapshot:
    """Read one regular file through held no-follow descriptors.

    The final descriptor-relative ``stat`` binds the pathname entry to the
    inode that was read.  A second descriptor walk binds every intermediate
    component, including ``.git``, before the snapshot is returned.
    """
    path = Path(path)
    parent = _canonical_file_parent(path, label)
    fds, chain_before = _open_directory_chain(parent, f"{label} parent")
    parent_fd = fds[-1]
    fd = -1
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        parent_before = os.fstat(parent_fd)
        fd = os.open(path.name, os.O_RDONLY | nofollow, dir_fd=parent_fd)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode), f"{label} is not a regular file")
        require(before.st_uid == os.getuid(), f"{label} owner differs from current uid")
        require(not stat.S_IMODE(before.st_mode) & 0o022, f"{label} is group/world writable")
        require(before.st_nlink == 1, f"{label} must have exactly one hard link")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(131072, limit - total + 1))
            if not chunk:
                break
            total += len(chunk)
            require(total <= limit, f"{label} exceeds bounded read limit")
            chunks.append(chunk)
        after = os.fstat(fd)
        final = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        parent_after = os.fstat(parent_fd)
        require(_identity(before) == _identity(after), f"{label} changed while being read")
        require(_identity(before) == _identity(final), f"{label} final directory entry was substituted")
        require(_identity(parent_before) == _identity(parent_after), f"{label} parent changed while being read")
        _directory_chain_matches(parent, chain_before, f"{label} parent")
        require(str(path) == os.path.realpath(str(path)), f"{label} became non-canonical while being read")
        raw = b"".join(chunks)
        require(len(raw) == before.st_size, f"{label} byte count disagrees with metadata")
        return FileSnapshot(path, _identity(before), hashlib.sha256(raw).hexdigest(), raw)
    except Reject:
        raise
    except OSError as exc:
        reject(f"{label} cannot be read safely: {exc}")
    finally:
        if fd >= 0:
            os.close(fd)
        for held in reversed(fds):
            os.close(held)


def read_stable_file(path: Path, label: str, *, limit: int = 2 * 1024 * 1024) -> bytes:
    return read_bound_file(path, label, limit=limit).raw


def _run_process(
    argv: Sequence[str], *, input_bytes: Optional[bytes] = None, timeout: int, cwd: str = "/"
) -> subprocess.CompletedProcess[bytes]:
    kwargs = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "env": dict(SAFE_ENV),
        "cwd": cwd,
        "timeout": timeout,
        "check": False,
    }
    if input_bytes is not None:
        kwargs["input"] = input_bytes
    try:
        result = subprocess.run(list(argv), **kwargs)
    except subprocess.TimeoutExpired:
        reject("bounded subprocess timed out")
    except OSError as exc:
        reject(f"trusted subprocess could not start: {exc}")
    _bounded(result.stdout or b"", "subprocess stdout")
    _bounded(result.stderr or b"", "subprocess stderr")
    return result


def _git_argv(root: Path, args: Sequence[str]) -> list[str]:
    return [
        GIT,
        "--no-lazy-fetch",
        "-C",
        str(root),
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "protocol.allow=never",
        *args,
    ]


def run_git(
    root: Path,
    args: Sequence[str],
    *,
    guard: Optional["RepoGuard"] = None,
    input_bytes: Optional[bytes] = None,
    timeout: int = GIT_TIMEOUT,
) -> subprocess.CompletedProcess[bytes]:
    if guard is not None:
        guard.assert_stable()
    result = _run_process(_git_argv(root, args), input_bytes=input_bytes, timeout=timeout)
    if guard is not None:
        guard.assert_stable()
    return result


def require_git_success(result: subprocess.CompletedProcess[bytes], label: str) -> bytes:
    if result.returncode != 0:
        reject(f"{label} failed with rc={result.returncode}: {_decode(result.stderr or b'', label + ' stderr').strip() or 'no stderr'}")
    if result.stderr:
        reject(f"{label} wrote unexpected stderr: {_decode(result.stderr, label + ' stderr').strip()}")
    return result.stdout or b""


def git_output(root: Path, args: Sequence[str], *, guard: Optional["RepoGuard"] = None) -> bytes:
    return require_git_success(run_git(root, args, guard=guard), "git " + " ".join(args))


def validate_oid(value: str, label: str) -> None:
    require(isinstance(value, str) and OID_RE.fullmatch(value) is not None, f"{label} must be exactly 40 lowercase hexadecimal characters")


def _lstat(path: Path, label: str) -> os.stat_result:
    try:
        st = os.lstat(path)
    except OSError as exc:
        reject(f"{label} metadata cannot be inspected: {exc}")
    require(not stat.S_ISLNK(st.st_mode), f"{label} must not be a symlink")
    return st


def _directory(path: Path, label: str) -> os.stat_result:
    st = _lstat(path, label)
    require(stat.S_ISDIR(st.st_mode), f"{label} is not a directory")
    require(st.st_uid == os.getuid(), f"{label} owner differs from current uid")
    require(not stat.S_IMODE(st.st_mode) & 0o022, f"{label} is group/world writable")
    return st


def _regular(path: Path, label: str) -> os.stat_result:
    st = _lstat(path, label)
    require(stat.S_ISREG(st.st_mode), f"{label} is not a regular file")
    require(st.st_uid == os.getuid(), f"{label} owner differs from current uid")
    require(not stat.S_IMODE(st.st_mode) & 0o022, f"{label} is group/world writable")
    require(st.st_nlink == 1, f"{label} must have one hard link")
    return st


def _reject_config_commands(raw: bytes, label: str) -> None:
    """Reject command, include, transport, and valueless config selectors.

    This parser is intentionally stricter than Git's config grammar.  A
    valueless command key such as ``[core] fsmonitor`` is rejected instead of
    being silently treated as a harmless boolean, and every non-comment line
    must be an assignment that this gate can classify.
    """
    text = _decode(raw, label)
    section = ""
    dangerous_sections = {"filter", "diff", "submodule", "credential", "remote", "url"}
    dangerous_keys = {
        "clean", "smudge", "process", "textconv", "external", "command", "update",
        "fsmonitor", "fsmonitorhookpath", "sshcommand", "gitproxy", "helper",
        "uploadpack", "receivepack", "proxy", "include", "path", "insteadof",
        "pushinsteadof", "worktreeconfig", "partialclonefilter", "promisor",
    }
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        if stripped.startswith("["):
            require(stripped.endswith("]"), f"{label} has an unterminated section at line {line_number}")
            section = stripped[1:-1].strip().split(None, 1)[0].lower().strip('"')
            require(section and re.fullmatch(r"[a-z0-9.-]+", section) is not None,
                    f"{label} has an unsafe section at line {line_number}")
            section_root = section.split(".", 1)[0]
            require(section_root not in dangerous_sections,
                    f"{label} contains command-bearing section {section}")
            continue
        require("=" in stripped, f"{label} has a valueless or malformed key at line {line_number}")
        key, _value = stripped.split("=", 1)
        compact = key.strip().lower().replace(" ", "")
        require(compact and re.fullmatch(r"[a-z0-9.-]+", compact) is not None,
                f"{label} has an unsafe key at line {line_number}")
        full = f"{section}.{compact}" if section else compact
        if compact in dangerous_keys and (section in dangerous_sections or compact in {
            "fsmonitor", "fsmonitorhookpath", "sshcommand", "gitproxy", "uploadpack",
            "receivepack", "proxy", "include", "path", "worktreeconfig",
            "partialclonefilter", "promisor", "insteadof", "pushinsteadof",
        }):
            reject(f"{label} contains command-bearing or redirected key {full}")
        if section.startswith("remote") and compact in {"uploadpack", "receivepack", "proxy"}:
            reject(f"{label} contains custom transport key {full}")
        if section.startswith("submodule") and compact in {"update", "url", "path", "command"}:
            reject(f"{label} contains custom submodule key {full}")


def _reject_attribute_commands(repo: Path, git_dir: Path, label: str) -> None:
    """Assess non-config command selectors before any Git worktree command."""
    candidates = [repo / ".gitattributes", git_dir / "info" / "attributes"]
    for path in candidates:
        if not os.path.lexists(path):
            continue
        snap = read_bound_file(path, f"{label} {path.name}", limit=256 * 1024)
        text = _decode(snap.raw, f"{label} {path.name}")
        if re.search(r"(?:^|\s)(?:filter|diff|merge)\s*=", text, re.IGNORECASE):
            reject(f"{label} attributes select a command-bearing filter/diff/merge")
    modules = repo / ".gitmodules"
    if os.path.lexists(modules):
        reject(f"{label} contains .gitmodules; submodule update behavior is not permitted")


def _metadata_entries(git_dir: Path):
    stack = [git_dir]
    count = 0
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError as exc:
            reject(f"Git metadata directory cannot be scanned: {exc}")
        for entry in entries:
            count += 1
            require(count <= MAX_METADATA_ENTRIES, "Git metadata entry count exceeds bounded limit")
            path = Path(entry.path)
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                reject(f"Git metadata entry cannot be inspected: {path}: {exc}")
            require(not stat.S_ISLNK(st.st_mode), f"Git metadata symlink is not allowed: {path}")
            if stat.S_ISDIR(st.st_mode):
                require(not stat.S_IMODE(st.st_mode) & 0o022, f"Git metadata directory is writable: {path}")
                stack.append(path)
            elif stat.S_ISREG(st.st_mode):
                require(st.st_uid == os.getuid(), f"Git metadata owner differs from current uid: {path}")
                require(not stat.S_IMODE(st.st_mode) & 0o022, f"Git metadata file is writable: {path}")
                require(st.st_nlink == 1, f"Git metadata hardlink is not allowed: {path}")
                yield path, st
            else:
                reject(f"unsupported Git metadata file type: {path}")


def _validate_object_entry(git_dir: Path, path: Path) -> None:
    objects = git_dir / "objects"
    try:
        rel = path.relative_to(objects).parts
    except ValueError:
        return
    if not rel:
        return
    if rel[0] == "info":
        require(len(rel) == 2 and rel[1] in {"packs", "commit-graph", "commit-graphs"}, f"unsupported object info entry: {path}")
        return
    if rel[0] == "pack":
        require(len(rel) == 2 and re.fullmatch(r"pack-[0-9a-f]{40}\.(?:pack|idx|bitmap|rev|keep)", rel[1]) is not None, f"unsupported object pack entry: {path}")
        return
    require(len(rel) == 2 and re.fullmatch(r"[0-9a-f]{2}", rel[0]) and re.fullmatch(r"[0-9a-f]{38}", rel[1]), f"unsupported object entry: {path}")


@dataclass(frozen=True)
class RepoIdentity:
    label: str
    root: Path
    # Store the complete lstat tuples observed during inspection.  A later
    # RepoGuard must compare against these exact values; retaining only
    # device/inode would let mode, size, link-count, or timestamp changes cross
    # the inspect-to-guard trust boundary.
    root_identity: tuple[int, ...]
    git_dir: Path
    git_identity: tuple[int, ...]
    common_dir: Path
    common_identity: tuple[int, ...]
    objects: Path
    objects_identity: tuple[int, ...]
    index_identity: Optional[tuple[int, ...]]
    object_file_identities: frozenset[tuple[int, ...]]
    # Every Git metadata pathname, including nested refs, reflogs, worktree
    # administration, and directory entries, is bound before the first Git
    # subprocess.  The complete tuple prevents mode, size, link-count, or
    # timestamp changes from crossing the inspect-to-guard boundary.
    metadata_identities: tuple[tuple[str, tuple[int, ...]], ...]
    config_snapshot: FileSnapshot
    head_snapshot: FileSnapshot


def _metadata_identity_snapshot(git_dir: Path, label: str) -> tuple[tuple[str, tuple[int, ...]], ...]:
    """Capture every non-symlink entry beneath ``.git`` without Git."""
    records: list[tuple[str, tuple[int, ...]]] = []
    stack = [git_dir]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(os.scandir(current), key=lambda item: item.name)
        except OSError as exc:
            reject(f"{label} metadata cannot be scanned: {exc}")
        for entry in entries:
            path = Path(entry.path)
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                reject(f"{label} metadata entry cannot be inspected: {path}: {exc}")
            require(not stat.S_ISLNK(st.st_mode), f"{label} metadata symlink is not allowed: {path}")
            require(stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode), f"unsupported Git metadata entry type: {path}")
            require(st.st_uid == os.getuid(), f"{label} metadata owner differs from current uid: {path}")
            require(not stat.S_IMODE(st.st_mode) & 0o022, f"{label} metadata is group/world writable: {path}")
            if stat.S_ISREG(st.st_mode):
                require(st.st_nlink == 1, f"{label} metadata hardlink is not allowed: {path}")
            relative = path.relative_to(git_dir).as_posix()
            records.append((relative, _identity(st)))
            if stat.S_ISDIR(st.st_mode):
                stack.append(path)
    return tuple(sorted(records))


def inspect_metadata(root: Path, label: str) -> RepoIdentity:
    root_st = _directory(root, f"{label} root")
    git_dir = root / ".git"
    git_st = _directory(git_dir, f"{label} .git")
    config = git_dir / "config"
    head = git_dir / "HEAD"
    _regular(config, f"{label} .git/config")
    _regular(head, f"{label} .git/HEAD")
    objects = git_dir / "objects"
    object_st = _directory(objects, f"{label} .git/objects")
    for forbidden in ("gitdir", "commondir", "shallow", "config.worktree"):
        require(not os.path.lexists(git_dir / forbidden), f"{label} has forbidden Git metadata path: {git_dir / forbidden}")
    require(not os.path.lexists(git_dir / "info" / "grafts"), f"{label} has graft metadata")
    require(not os.path.lexists(git_dir / "refs" / "replace"), f"{label} has replacement refs")

    # These reads and rejections are deliberately before the first Git call.
    config_snapshot = read_bound_file(config, f"{label} config")
    _reject_config_commands(config_snapshot.raw, f"{label} config")
    head_snapshot = read_bound_file(head, f"{label} HEAD")
    _reject_attribute_commands(root, git_dir, label)

    object_files: set[tuple[int, ...]] = set()
    for path, st in _metadata_entries(git_dir):
        _validate_object_entry(git_dir, path)
        try:
            path.relative_to(objects)
        except ValueError:
            pass
        else:
            object_files.add(_identity(st))
    index_identity: Optional[tuple[int, ...]] = None
    index = git_dir / "index"
    if os.path.lexists(index):
        st = _regular(index, f"{label} index")
        index_identity = _identity(st)
    metadata_identities = _metadata_identity_snapshot(git_dir, label)
    return RepoIdentity(
        label=label,
        root=root,
        root_identity=_identity(root_st),
        git_dir=git_dir,
        git_identity=_identity(git_st),
        common_dir=git_dir,
        common_identity=_identity(git_st),
        objects=objects,
        objects_identity=_identity(object_st),
        index_identity=index_identity,
        object_file_identities=frozenset(object_files),
        metadata_identities=metadata_identities,
        config_snapshot=config_snapshot,
        head_snapshot=head_snapshot,
    )


def directory_identity(identity: RepoIdentity) -> dict[str, int]:
    st = _lstat(identity.root, f"{identity.label} root")
    return {
        "st_dev": int(st.st_dev),
        "st_ino": int(st.st_ino),
        "st_uid": int(st.st_uid),
        "st_mode": int(stat.S_IMODE(st.st_mode)),
        "st_nlink": int(st.st_nlink),
    }


class RepoGuard:
    """Bind the complete pre-Git metadata snapshot around every Git call."""

    def __init__(self, identity: RepoIdentity) -> None:
        self.identity = identity
        # Capture immediately and compare to inspect_metadata's independent
        # snapshot.  This constructor is called before the first run_git call;
        # a replacement .git directory or nested HEAD therefore fails closed.
        current = self._capture()
        require(current["root"] == identity.root_identity, f"{identity.label} root changed before RepoGuard")
        require(current["git"] == identity.git_identity, f"{identity.label} .git changed before RepoGuard")
        require(current["common"] == identity.common_identity, f"{identity.label} common directory changed before RepoGuard")
        require(current["objects"] == identity.objects_identity, f"{identity.label} objects directory changed before RepoGuard")
        require(current["metadata"] == identity.metadata_identities, f"{identity.label} metadata changed before RepoGuard")
        require(current["config"] == (*identity.config_snapshot.identity, identity.config_snapshot.sha256), f"{identity.label} config changed before RepoGuard")
        require(current["head"] == (*identity.head_snapshot.identity, identity.head_snapshot.sha256), f"{identity.label} HEAD changed before RepoGuard")
        if identity.index_identity is None:
            require(current["index"] is None, f"{identity.label} index appeared before RepoGuard")
        else:
            require(current["index"] == identity.index_identity, f"{identity.label} index changed before RepoGuard")
        self._expected = current

    def _capture(self) -> dict[str, Any]:
        root_st = _directory(self.identity.root, f"{self.identity.label} guarded root")
        git_st = _directory(self.identity.git_dir, f"{self.identity.label} guarded .git")
        objects_st = _directory(self.identity.objects, f"{self.identity.label} guarded objects")
        index_path = self.identity.git_dir / "index"
        index_identity = _identity(_regular(index_path, f"{self.identity.label} guarded index")) if os.path.lexists(index_path) else None
        config = read_bound_file(self.identity.config_snapshot.path, f"{self.identity.label} guarded config")
        head = read_bound_file(self.identity.head_snapshot.path, f"{self.identity.label} guarded HEAD")
        return {
            "root": _identity(root_st),
            "git": _identity(git_st),
            "common": _identity(git_st),
            "objects": _identity(objects_st),
            "index": index_identity,
            "metadata": _metadata_identity_snapshot(self.identity.git_dir, self.identity.label),
            "config": (*config.identity, config.sha256),
            "head": (*head.identity, head.sha256),
        }

    def assert_stable(self) -> None:
        current = self._capture()
        require(current == self._expected, f"{self.identity.label} repository/config/HEAD identity changed during review")


def _require_empty(result: subprocess.CompletedProcess[bytes], label: str) -> None:
    require_git_success(result, label)
    require(not result.stdout, f"{label} returned unexpected output")


def check_worktree_registry(repo: Path, identity: RepoIdentity, guard: RepoGuard) -> None:
    raw = git_output(repo, ["worktree", "list", "--porcelain"], guard=guard)
    blocks = [block for block in _decode(raw, "worktree registry").split("\n\n") if block]
    require(len(blocks) == 1, f"{identity.label} has linked or ambiguous worktrees")
    lines = blocks[0].splitlines()
    require(lines and lines[0].startswith("worktree "), f"{identity.label} worktree registry is malformed")
    listed = lines[0][len("worktree ") :]
    require(os.path.realpath(listed) == str(identity.root), f"{identity.label} worktree registry root mismatch")
    for line in lines[1:]:
        require(not line.startswith(("locked ", "prunable ")), f"{identity.label} worktree registry contains stale state")
        require(not line or line.startswith(("HEAD ", "branch ", "detached")), f"{identity.label} worktree registry has unknown state")


def check_clean(repo: Path, guard: RepoGuard) -> None:
    status = run_git(repo, ["status", "--porcelain=v1", "--untracked-files=all", "--ignored=traditional", "--ignore-submodules=none"], guard=guard)
    require_git_success(status, "clean status")
    require(not status.stdout, "repository is not clean")
    ignored = run_git(repo, ["ls-files", "--others", "--ignored", "--exclude-standard", "-z"], guard=guard)
    require_git_success(ignored, "ignored-descendant enumeration")
    require(not ignored.stdout, "repository has ignored or untracked descendants")
    for args, label in ((["diff", "--no-ext-diff", "--no-textconv", "--quiet"], "unstaged diff"), (["diff", "--cached", "--no-ext-diff", "--no-textconv", "--quiet"], "staged diff")):
        result = run_git(repo, args, guard=guard)
        require(result.returncode in (0, 1), f"{label} returned unexpected rc={result.returncode}")
        require(not result.stderr, f"{label} wrote stderr")
        require(result.returncode == 0, f"repository has {label}")


def check_index_flags(repo: Path, guard: RepoGuard) -> None:
    staged = git_output(repo, ["ls-files", "--stage", "-z"], guard=guard)
    for record in staged.split(b"\0"):
        if not record:
            continue
        try:
            meta, path = record.split(b"\t", 1)
            mode, oid, stage = meta.split()
        except ValueError:
            reject("index stage record is malformed")
        require(stage == b"0", f"index path is not stage zero: {path!r}")
        require(mode in {b"100644", b"100755", b"120000", b"160000"}, f"index path has unsupported mode: {mode!r}")
        validate_oid(oid.decode("ascii", "ignore"), "index object")
    verbose = git_output(repo, ["ls-files", "-v", "-z"], guard=guard)
    for record in verbose.split(b"\0"):
        if record:
            require(len(record) >= 2 and record[1:2] == b" ", "verbose index record is malformed")
            require(not chr(record[0]).islower() and chr(record[0]) not in {"S", "U"}, f"index path has unsafe state: {record!r}")


def _assert_oid_type(repo: Path, oid: str, wanted: str, label: str, guard: RepoGuard) -> None:
    validate_oid(oid, label)
    actual = _decode(git_output(repo, ["cat-file", "-t", oid], guard=guard), label).strip()
    require(actual == wanted, f"{label} has type {actual!r}, expected {wanted!r}")


def _rev_parse(repo: Path, expression: str, label: str, guard: RepoGuard) -> str:
    value = _decode(git_output(repo, ["rev-parse", "--verify", "--end-of-options", expression], guard=guard), label).strip()
    validate_oid(value, label)
    return value


def _check_repo_shape(repo: Path, identity: RepoIdentity, guard: RepoGuard) -> None:
    require(_decode(git_output(repo, ["rev-parse", "--is-bare-repository"], guard=guard), "bare state").strip() == "false", f"{identity.label} must be non-bare")
    require(_decode(git_output(repo, ["rev-parse", "--is-shallow-repository"], guard=guard), "shallow state").strip() == "false", f"{identity.label} must not be shallow")
    require(_decode(git_output(repo, ["rev-parse", "--show-object-format"], guard=guard), "object format").strip() == "sha1", f"{identity.label} must use SHA-1")
    top = _decode(git_output(repo, ["rev-parse", "--show-toplevel"], guard=guard), "repository root").strip()
    require(os.path.realpath(top) == str(repo), f"{identity.label} top-level path mismatch")
    git_path = _decode(git_output(repo, ["rev-parse", "--git-dir"], guard=guard), "Git directory").strip()
    require(os.path.realpath(os.path.join(str(repo), git_path)) == str(identity.git_dir), f"{identity.label} Git directory mismatch")
    common = _decode(git_output(repo, ["rev-parse", "--git-common-dir"], guard=guard), "Git common directory").strip()
    require(os.path.realpath(os.path.join(str(repo), common)) == str(identity.common_dir), f"{identity.label} common directory mismatch")
    objects = _decode(git_output(repo, ["rev-parse", "--git-path", "objects"], guard=guard), "object directory").strip()
    require(os.path.realpath(os.path.join(str(repo), objects)) == str(identity.objects), f"{identity.label} object directory mismatch")


def _check_origin_and_base(repo: Path, label: str, guard: RepoGuard, *, policy: Mapping[str, Any]) -> None:
    """Check refs and base only against the authenticated Phase-A policy."""
    require(isinstance(policy, Mapping), f"{label} authenticated policy is missing")
    base_ref = policy.get("base_ref")
    main_ref = policy.get("main_ref")
    base_commit = policy.get("base_commit")
    base_tree_expected = policy.get("base_tree")
    main_commit = policy.get("main_commit")
    require(isinstance(base_ref, str) and isinstance(main_ref, str), f"{label} policy refs are invalid")
    require(base_ref == "refs/remotes/origin/dev" and main_ref == "refs/remotes/origin/main", f"{label} policy refs are not exact origin refs")
    validate_oid(base_commit, f"{label} policy base commit")
    validate_oid(base_tree_expected, f"{label} policy base tree")
    validate_oid(main_commit, f"{label} policy main commit")
    dev = _rev_parse(repo, f"{base_ref}^{{commit}}", f"{label} origin/dev", guard)
    main = _rev_parse(repo, f"{main_ref}^{{commit}}", f"{label} origin/main", guard)
    base_tree = _rev_parse(repo, f"{base_commit}^{{tree}}", f"{label} base tree", guard)
    require(dev == base_commit, f"{label} origin/dev pin mismatch")
    require(main == main_commit, f"{label} origin/main pin mismatch")
    require(base_tree == base_tree_expected, f"{label} base tree pin mismatch")


def _check_ancestry(repo: Path, descendant: str, ancestor: str, *, forbidden: bool, guard: RepoGuard) -> None:
    validate_oid(descendant, "ancestry descendant")
    validate_oid(ancestor, "ancestry ancestor")
    result = run_git(repo, ["merge-base", "--is-ancestor", ancestor, descendant], guard=guard)
    require(result.returncode in (0, 1) and not result.stdout and not result.stderr, "merge-base returned an unexpected result")
    if forbidden:
        require(result.returncode != 0, f"forbidden ancestor is present: {ancestor}")
    else:
        require(result.returncode == 0, f"required ancestor is absent: {ancestor}")


def _check_fsck(repo: Path, identity: RepoIdentity, guard: RepoGuard) -> None:
    fsck = run_git(repo, ["fsck", "--strict", "--full", "--no-reflogs", "--no-progress"], guard=guard)
    require(fsck.returncode == 0, f"{identity.label} strict fsck failed")
    text = (_decode(fsck.stdout or b"", "fsck stdout") + "\n" + _decode(fsck.stderr or b"", "fsck stderr")).lower()
    require(not re.search(r"(?:missing|broken|corrupt|fatal|error):?", text), f"{identity.label} fsck reported invalid object state")
    all_objects = run_git(repo, ["rev-list", "--objects", "--all", "--missing=error"], guard=guard)
    require(all_objects.returncode == 0, f"{identity.label} all-object closure is incomplete")


def _check_explicit_closure(repo: Path, root_oid: str, guard: RepoGuard) -> None:
    """Traverse closure and require exact ordered batch-check correspondence."""
    raw = run_git(repo, ["rev-list", "--objects", "--missing=error", root_oid], guard=guard)
    require(raw.returncode == 0, "detached FINAL_HEAD object closure is incomplete")
    oids: list[str] = []
    for line in _decode(raw.stdout or b"", "detached object closure").splitlines():
        if line:
            fields = line.split(" ", 1)
            oid = fields[0]
            validate_oid(oid, "detached closure object")
            oids.append(oid)
    require(oids and oids[0] == root_oid, "detached object closure omitted or reordered FINAL_HEAD")
    require(len(oids) == len(set(oids)), "detached object closure contains duplicate OIDs")
    batch_input = ("\n".join(oids) + "\n").encode("ascii")
    checked = run_git(repo, ["cat-file", "--batch-check"], guard=guard, input_bytes=batch_input)
    require_git_success(checked, "detached closure object types")
    records = _decode(checked, "detached closure object types").splitlines()
    require(len(records) == len(oids), "detached closure batch response cardinality differs")
    for requested, line in zip(oids, records):
        fields = line.split()
        require(len(fields) >= 2 and OID_RE.fullmatch(fields[0]) is not None, "detached closure type record is malformed")
        require(fields[0] == requested, "detached closure batch response OID order differs")
        require(fields[1] in {"commit", "tree", "blob"}, f"detached closure has unsafe object type {fields[1]!r}")


def check_cross_repository_separation(identities: Sequence[RepoIdentity]) -> None:
    for i, left in enumerate(identities):
        for right in identities[i + 1 :]:
            try:
                common = os.path.commonpath([str(left.root), str(right.root)])
            except ValueError:
                common = ""
            require(common not in {str(left.root), str(right.root)}, f"repository roots overlap: {left.label}, {right.label}")
            require(left.git_identity != right.git_identity and left.objects_identity != right.objects_identity, "Git metadata is shared")
            require(not {item[:2] for item in left.object_file_identities}.intersection({item[:2] for item in right.object_file_identities}), "object-store files are hardlinked")
