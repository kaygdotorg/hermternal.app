#!/usr/bin/env python3
"""Verify the final v2 aggregate fixture authority from immutable Git objects.

This verifier is intentionally separate from the aggregate scanner. The legacy
v1 authority and the historical bootstrap v2 authority remain readable in Git
history, while this lane consumes a distinct final v2 path. The final authority
is introduced only after its direct predecessor commit has finalized the
scanner, index, tests, and baseline. The checkout is compared with authority
bytes read from the local Git object database, so replacing the visible
authority file or refreshing local hashes cannot silently authorize different
scanner inputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterator


LEGACY_AUTHORITY_PATH = "scripts/fixture_registry_authority.json"
LEGACY_AUTHORITY_SCHEMA = "hermternal.fixture-registry-authority.v1"
LEGACY_AUTHORITY_SIZE = 442
LEGACY_AUTHORITY_SHA256 = "3792ee51370ec6b5cf7257d8473f71c7e810e03c7216969d079d933033734a14"
LEGACY_AUTHORITY_BLOB_OID = "be0abad11385cddd7a93670f9641a77a285d9782"
LEGACY_AUTHORITY_KEYS = (
    "schema",
    "validator_path",
    "validator_size_bytes",
    "validator_sha256",
    "baseline_path",
    "baseline_size_bytes",
    "baseline_sha256",
)
LEGACY_VALIDATOR_PATH = "contracts/fixtures/validator/validate.py"
LEGACY_BASELINE_PATH = "contracts/fixtures/validator/validation-baseline.json"
AUTHORITY_PATH = "scripts/fixture_registry_authority.v2.final.json"
AUTHORITY_SCHEMA = "hermternal.fixture-registry-authority.v2"
AUTHORITY_ROLE = "aggregate_predecessor"
# These pins are outside the v2 manifest bytes. They prevent an otherwise
# internally consistent synthetic history from selecting a caller-controlled
# authority introduction and predecessor.
EXPECTED_AUTHORITY_COMMIT = "285acdcf9c11c049180a7844e689eee0f1490de4"
EXPECTED_SOURCE_COMMIT = "263cb75adcf153d6fe252636b064e5fbc3e3f877"
EXPECTED_ARTIFACT_PATHS = (
    "contracts/fixtures/index.json",
    "contracts/fixtures/validator/test_validate.py",
    "contracts/fixtures/validator/validate.py",
    "contracts/fixtures/validator/validation-baseline.json",
)
AUTHORITY_KEYS = (
    "schema",
    "role",
    "source_commit",
    "artifact_manifest",
    "canonicalization",
    "synthetic_only",
    "live_claim",
)
RECORD_KEYS = ("path", "blob_oid", "sha256", "size_bytes")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_GIT_OUTPUT = 512 * 1024
GIT_TIMEOUT_SECONDS = 10.0
# Ordinary metadata and loose objects stay at the conservative one-MiB cap.
# Packed clones need a separate bound. The refreshed trusted four-ref bundle
# produces a 33,787,115-byte pack in a fresh no-local single-head clone on
# macOS after the versioned authority bundle rotation. A 48 MiB per-pack cap
# retains 8,155,925 measured bytes of headroom. The seeded clone retains two
# packs plus metadata, so its separate 96 MiB aggregate cap preserves bounded
# copy accounting while leaving file-count, output, and timeout limits intact.
MAX_SNAPSHOT_FILE_BYTES = 1 * 1024 * 1024
MAX_SNAPSHOT_PACK_FILE_BYTES = 48 * 1024 * 1024
MAX_SNAPSHOT_TOTAL_BYTES = 96 * 1024 * 1024
# Snapshot metadata is bounded separately from copied bytes. A repository with
# unlimited empty entries could otherwise exhaust directory listings, retained
# names, or descriptor stacks before any byte budget is reached.
MAX_SNAPSHOT_ENTRIES = 4_096
MAX_SNAPSHOT_DIRECTORIES = 1_024
MAX_SNAPSHOT_FILES = 3_072
MAX_SNAPSHOT_DEPTH = 64
MAX_SNAPSHOT_PATH_STORAGE_BYTES = 1 * 1024 * 1024
SNAPSHOT_TIMEOUT_SECONDS = 30.0
MAX_ERROR_LENGTH = 220
SAFE_ERROR_MESSAGE = "fixture registry authority rejected"
TRUSTED_GIT_EXECUTABLE = Path("/usr/bin/git")
# Git may invoke helper processes while reading repository metadata. Keep that
# helper search path fixed; the host owning these system directories is part of
# this fixture-only trust boundary, not an untrusted checkout input.
TRUSTED_HELPER_PATH = "/usr/bin:/bin"
# macOS exposes the host temporary directory through /tmp, /var,
# /var/folders, and /var/tmp; permit only those system aliases while rejecting
# caller-created symlinked ancestors.
TRUSTED_PATH_ALIASES = frozenset(
    {Path("/tmp"), Path("/var"), Path("/var/folders"), Path("/var/tmp")}
)
GIT_REDIRECT_ENV_VARS = (
    "GIT_DIR",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_REPLACE_REF_BASE",
    "GIT_PROMISOR_REMOTE",
)
GIT_METADATA_FILES = (
    "HEAD",
    "config",
    "config.worktree",
    "index",
    "packed-refs",
    "objects",
    "objects/info",
    "refs",
    "refs/replace",
    "info",
    "gitdir",
    "commondir",
)
GIT_FORBIDDEN_METADATA = (
    "objects/info/alternates",
    "objects/info/http-alternates",
    "info/grafts",
    "shallow",
)
BLOCKED_CORE_CONFIG_KEYS = frozenset(
    {
        "alternaterefscommand",
        "alternaterefsprefixes",
        "askpass",
        "fsmonitor",
        "fsmonitorhookversion",
        "gitproxy",
        "hookspath",
        "sshcommand",
        "usereplacerefs",
        "worktree",
    }
)
BLOCKED_REMOTE_CONFIG_KEYS = frozenset(
    {"promisor", "partialclonefilter", "proxy", "uploadpack", "receivepack"}
)
BLOCKED_CONFIG_SECTIONS = frozenset(
    {"include", "includeif", "url", "credential", "filter", "http", "ssh", "submodule"}
)


class AuthorityError(ValueError):
    """Raised for any untrusted checkout or Git-object authority mismatch."""


class ArgumentParseError(ValueError):
    """Raised without allowing argparse to reflect untrusted command-line text."""


def _require(condition: bool) -> None:
    if not condition:
        raise AuthorityError()


def _resolve_path(path: Path, *, strict: bool) -> Path:
    """Convert every filesystem resolution failure into the bounded error type."""

    try:
        return path.resolve(strict=strict)
    except (OSError, RuntimeError, ValueError) as exc:
        raise AuthorityError() from exc


def _open_directory_chain(
    path: Path, *, deadline: float | None = None
) -> tuple[int, Path]:
    """Open every absolute path component through a stable parent descriptor."""

    _require(path.is_absolute())
    _require(all(component not in ("", ".", "..") for component in path.parts[1:]))
    no_follow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    _require(type(no_follow) is int and type(nonblock) is int and type(directory_flag) is int)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | no_follow | nonblock | directory_flag
    current_fd: int | None = None
    current_path = Path(path.anchor)
    transferred = False
    try:
        if deadline is not None:
            _require(time.monotonic() <= deadline)
        current_fd = os.open(path.anchor, flags)
        for component in path.parts[1:]:
            if deadline is not None:
                _require(time.monotonic() <= deadline)
            candidate = current_path / component
            try:
                next_fd = os.open(component, flags, dir_fd=current_fd)
            except OSError:
                # macOS exposes the host temporary tree through the four
                # explicitly trusted aliases above. Only those exact system
                # aliases may be followed; all other ancestors must be opened
                # with O_NOFOLLOW from their parent fd.
                _require(candidate in TRUSTED_PATH_ALIASES)
                next_fd = os.open(component, flags & ~no_follow, dir_fd=current_fd)
            old_fd = current_fd
            try:
                os.close(old_fd)
            except OSError:
                os.close(next_fd)
                raise
            current_fd = next_fd
            current_path = candidate
        _require(current_fd is not None and stat.S_ISDIR(os.fstat(current_fd).st_mode))
        # Resolve only after the descriptor chain is anchored. The resolved
        # name is used for private Git commands and diagnostics; source reads
        # continue through the already-open descriptor.
        canonical = _resolve_path(path, strict=True)
        transferred = True
        return current_fd, canonical
    except AuthorityError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise AuthorityError() from exc
    finally:
        if current_fd is not None and not transferred:
            try:
                os.close(current_fd)
            except OSError:
                pass


def _canonical_directory(path: Path) -> Path:
    """Require an absolute directory after descriptor-anchored traversal."""

    descriptor, canonical = _open_directory_chain(path)
    try:
        _require(stat.S_ISDIR(os.fstat(descriptor).st_mode))
        return canonical
    except (OSError, RuntimeError, ValueError) as exc:
        raise AuthorityError() from exc
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _lstat_optional(path: Path) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None
    except (OSError, RuntimeError, ValueError) as exc:
        raise AuthorityError() from exc


def _require_plain_directory(path: Path) -> None:
    metadata = _lstat_optional(path)
    _require(metadata is not None and stat.S_ISDIR(metadata.st_mode))


def _require_missing(path: Path) -> None:
    _require(_lstat_optional(path) is None)


def _read_bounded_regular_path(path: Path, limit: int) -> bytes:
    """Read a metadata file without blocking on a non-regular replacement."""

    no_follow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    _require(type(no_follow) is int and type(nonblock) is int)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | no_follow | nonblock
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        _require(stat.S_ISREG(os.fstat(descriptor).st_mode))
        data = bytearray()
        while len(data) < limit + 1:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        _require(len(data) <= limit)
        return bytes(data)
    except AuthorityError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise AuthorityError() from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _validate_local_config(data: bytes) -> None:
    """Reject local config features that can redirect reads or execute helpers."""

    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise AuthorityError() from exc
    section = ""
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line[0] in ";#":
            continue
        if line.startswith("["):
            _require(line.endswith("]"))
            body = line[1:-1].strip()
            section = body.split(None, 1)[0].casefold()
            _require(bool(section))
            _require(section not in BLOCKED_CONFIG_SECTIONS)
            _require(section != "extensions")
            continue
        key, separator, value = line.partition("=")
        key = key.strip().casefold()
        value = value.strip().casefold() if separator else ""
        _require(bool(key) and (separator or re.fullmatch(r"[a-z0-9_.-]+", key) is not None))
        if section == "core":
            _require(key not in BLOCKED_CORE_CONFIG_KEYS)
            _require(not key.startswith("alternateRefs".casefold()))
            if key == "repositoryformatversion":
                _require(value in {"", "0"})
            if key == "bare":
                _require(value not in {"true", "yes", "on", "1"})
        if section == "remote":
            _require(key not in BLOCKED_REMOTE_CONFIG_KEYS)
        _require(not key.endswith(".promisor") and not key.endswith(".partialclonefilter"))
        _require(key not in {"insteadof", "pushinsteadof"})


def _walk_plain_tree(path: Path, budget: "_SnapshotBudget | None" = None) -> None:
    """Descriptor-walk a Git tree without following nested symlinks."""

    no_follow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    _require(type(no_follow) is int and type(nonblock) is int and type(directory_flag) is int)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | no_follow | nonblock
    active_budget = budget or _SnapshotBudget.start()
    root_fd: int | None = None
    pending: list[tuple[int, PurePosixPath, int]] = []
    try:
        active_budget.check()
        root_fd = os.open(path, flags | directory_flag)
        pending.append((root_fd, PurePosixPath(), 0))
        root_fd = None
        while pending:
            active_budget.check()
            directory_fd, relative_directory, depth = pending.pop()
            try:
                _require(stat.S_ISDIR(os.fstat(directory_fd).st_mode))
                with os.scandir(directory_fd) as entries:
                    while True:
                        active_budget.check()
                        try:
                            entry = next(entries)
                        except StopIteration:
                            break
                        except OSError as exc:
                            raise AuthorityError() from exc
                        name = entry.name
                        _require(name not in ("", ".", ".."))
                        child_relative = relative_directory / name
                        child_fd: int | None = None
                        try:
                            child_fd = os.open(name, flags, dir_fd=directory_fd)
                            mode = os.fstat(child_fd).st_mode
                            is_directory = stat.S_ISDIR(mode)
                            active_budget.account_entry(
                                child_relative,
                                directory=is_directory,
                                depth=depth + 1,
                            )
                            if is_directory:
                                pending.append((child_fd, child_relative, depth + 1))
                                child_fd = None
                            else:
                                _require(stat.S_ISREG(mode))
                        finally:
                            if child_fd is not None:
                                os.close(child_fd)
            finally:
                os.close(directory_fd)
    except AuthorityError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise AuthorityError() from exc
    finally:
        if root_fd is not None:
            try:
                os.close(root_fd)
            except OSError:
                pass
        while pending:
            descriptor, _relative, _depth = pending.pop()
            try:
                os.close(descriptor)
            except OSError:
                pass


def _file_stat_fingerprint(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


@dataclass
class _SnapshotBudget:
    """Bound private metadata copying before any Git command can run."""

    deadline: float
    total_bytes: int = 0
    entries: int = 0
    directories: int = 0
    files: int = 0
    path_storage_bytes: int = 0

    @classmethod
    def start(cls) -> "_SnapshotBudget":
        return cls(deadline=time.monotonic() + SNAPSHOT_TIMEOUT_SECONDS)

    def check(self) -> None:
        _require(time.monotonic() <= self.deadline)

    def account_entry(
        self,
        relative_path: PurePosixPath,
        *,
        directory: bool,
        depth: int,
    ) -> None:
        self.check()
        self.entries += 1
        _require(self.entries <= MAX_SNAPSHOT_ENTRIES)
        _require(depth <= MAX_SNAPSHOT_DEPTH)
        try:
            path_bytes = len(str(relative_path).encode("utf-8", "surrogatepass")) + 1
        except (UnicodeError, ValueError) as exc:
            raise AuthorityError() from exc
        self.path_storage_bytes += path_bytes
        _require(self.path_storage_bytes <= MAX_SNAPSHOT_PATH_STORAGE_BYTES)
        if directory:
            self.directories += 1
            _require(self.directories <= MAX_SNAPSHOT_DIRECTORIES)
        else:
            self.files += 1
            _require(self.files <= MAX_SNAPSHOT_FILES)

    def check_file_size(self, size: int, file_limit: int) -> None:
        self.check()
        _require(0 <= size <= file_limit)
        # Reject an aggregate overrun before opening and reading the file. The
        # per-chunk reservation below still protects against a file growing
        # after this initial descriptor stat.
        _require(self.total_bytes + size <= MAX_SNAPSHOT_TOTAL_BYTES)

    def reserve(self, amount: int, copied_in_file: int, file_limit: int) -> int:
        self.check()
        _require(amount >= 0)
        _require(copied_in_file + amount <= file_limit)
        _require(self.total_bytes + amount <= MAX_SNAPSHOT_TOTAL_BYTES)
        self.total_bytes += amount
        self.check()
        return copied_in_file + amount


def _snapshot_file_limit(relative_path: PurePosixPath) -> int:
    """Use pack-directory headroom without widening loose-file limits."""

    if relative_path.parts[:2] == ("objects", "pack"):
        return MAX_SNAPSHOT_PACK_FILE_BYTES
    return MAX_SNAPSHOT_FILE_BYTES


def _copy_regular_from_fd(
    source_fd: int,
    destination: Path,
    budget: _SnapshotBudget,
    relative_path: PurePosixPath,
) -> None:
    """Copy one regular file under category, aggregate, and time caps."""

    budget.check()
    before = os.fstat(source_fd)
    _require(stat.S_ISREG(before.st_mode))
    file_limit = _snapshot_file_limit(relative_path)
    budget.check_file_size(before.st_size, file_limit)
    destination_fd: int | None = None
    copied = 0
    try:
        destination_fd = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        while True:
            budget.check()
            chunk = os.read(source_fd, 64 * 1024)
            if not chunk:
                break
            copied = budget.reserve(len(chunk), copied, file_limit)
            remaining = memoryview(chunk)
            while remaining:
                budget.check()
                written = os.write(destination_fd, remaining)
                _require(written > 0)
                remaining = remaining[written:]
        budget.check()
        after = os.fstat(source_fd)
        _require(_file_stat_fingerprint(before) == _file_stat_fingerprint(after))
        _require(copied == before.st_size)
    except AuthorityError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise AuthorityError() from exc
    finally:
        if destination_fd is not None:
            try:
                os.close(destination_fd)
            except OSError:
                pass


def _copy_git_tree(
    source_fd: int,
    destination: Path,
    budget: _SnapshotBudget,
    relative_path: PurePosixPath,
) -> None:
    """Create a bounded private regular-file snapshot from an open Git fd."""

    no_follow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    _require(type(no_follow) is int and type(nonblock) is int and type(directory_flag) is int)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | no_follow | nonblock
    budget.check()
    before = os.fstat(source_fd)
    _require(stat.S_ISDIR(before.st_mode))
    try:
        os.mkdir(destination, 0o700)
        budget.check()
        with os.scandir(source_fd) as entries:
            while True:
                budget.check()
                try:
                    entry = next(entries)
                except StopIteration:
                    break
                except OSError as exc:
                    raise AuthorityError() from exc
                name = entry.name
                _require(name not in ("", ".", ".."))
                child_fd: int | None = None
                child_destination = destination / name
                child_relative_path = relative_path / name
                try:
                    child_fd = os.open(name, flags, dir_fd=source_fd)
                    mode = os.fstat(child_fd).st_mode
                    is_directory = stat.S_ISDIR(mode)
                    budget.account_entry(
                        child_relative_path,
                        directory=is_directory,
                        depth=len(child_relative_path.parts),
                    )
                    if is_directory:
                        _copy_git_tree(child_fd, child_destination, budget, child_relative_path)
                    else:
                        _require(stat.S_ISREG(mode))
                        _copy_regular_from_fd(
                            child_fd,
                            child_destination,
                            budget,
                            child_relative_path,
                        )
                finally:
                    if child_fd is not None:
                        os.close(child_fd)
        budget.check()
        _require(_file_stat_fingerprint(before) == _file_stat_fingerprint(os.fstat(source_fd)))
    except AuthorityError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise AuthorityError() from exc


def _read_bounded_fd(descriptor: int, limit: int) -> bytes:
    """Read a stable regular descriptor without following a replacement."""

    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode))
        _require(0 <= before.st_size <= limit)
        data = bytearray()
        while len(data) < limit + 1:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        _require(len(data) <= limit)
        _require(_file_stat_fingerprint(before) == _file_stat_fingerprint(os.fstat(descriptor)))
        return bytes(data)
    except AuthorityError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise AuthorityError() from exc


def _snapshot_object_repository(
    object_repo: Path,
) -> tuple[tempfile.TemporaryDirectory[str], Path]:
    """Snapshot a canonical plain Git repository before path-based commands run.

    Linked worktrees are deliberately outside this trust boundary. Callers must
    provide a separate ordinary clone whose ``.git`` directory owns its object
    database, refs, and configuration directly.
    """

    no_follow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    _require(type(no_follow) is int and type(nonblock) is int and type(directory_flag) is int)
    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | no_follow | nonblock | directory_flag
    entry_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | no_follow | nonblock
    root_fd: int | None = None
    marker_fd: int | None = None
    source_fd: int | None = None
    temporary: tempfile.TemporaryDirectory[str] | None = None
    budget = _SnapshotBudget.start()
    try:
        # Keep the root fd returned by the descriptor chain. Reopening the
        # caller path here would reintroduce an ancestor replacement race.
        root_fd, _ = _open_directory_chain(object_repo, deadline=budget.deadline)
        budget.check()
        marker_fd = os.open(".git", entry_flags, dir_fd=root_fd)
        _require(stat.S_ISDIR(os.fstat(marker_fd).st_mode))
        source_fd = marker_fd
        marker_fd = None
        temporary = tempfile.TemporaryDirectory(prefix="fixture-authority-snapshot-")
        snapshot_root = Path(temporary.name) / "repo"
        os.mkdir(snapshot_root, 0o700)
        budget.check()
        _copy_git_tree(source_fd, snapshot_root / ".git", budget, PurePosixPath())
        return temporary, snapshot_root
    except AuthorityError:
        if temporary is not None:
            temporary.cleanup()
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        if temporary is not None:
            temporary.cleanup()
        raise AuthorityError() from exc
    finally:
        for descriptor in (source_fd, marker_fd, root_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _validate_snapshot_repository(snapshot_root: Path) -> Path:
    """Validate and use only the private snapshot, never the caller paths."""

    root = _canonical_directory(snapshot_root)
    git_dir = root / ".git"
    _require_plain_directory(git_dir)
    for relative in GIT_METADATA_FILES:
        path = git_dir / relative
        metadata = _lstat_optional(path)
        if metadata is not None and stat.S_ISLNK(metadata.st_mode):
            raise AuthorityError()
    for relative in ("HEAD", "config", "objects", "refs"):
        path = git_dir / relative
        metadata = _lstat_optional(path)
        _require(metadata is not None)
        if relative in {"objects", "refs"}:
            _require(stat.S_ISDIR(metadata.st_mode))
        else:
            _require(stat.S_ISREG(metadata.st_mode))
    for relative in GIT_FORBIDDEN_METADATA:
        _require_missing(git_dir / relative)
    for relative in ("gitdir", "commondir", "config.worktree"):
        _require_missing(git_dir / relative)
    _validate_local_config(_read_bounded_regular_path(git_dir / "config", MAX_GIT_OUTPUT))
    _walk_plain_tree(git_dir / "objects")
    _walk_plain_tree(git_dir / "refs")
    # Verify every copied object before trusting any authority or artifact blob.
    _git(root, "fsck", "--full", "--strict", "--no-reflogs", "--no-progress")

    _require(_git(root, "rev-parse", "--show-toplevel") == f"{root}\n".encode("utf-8"))
    _require(_git(root, "rev-parse", "--is-inside-work-tree") == b"true\n")
    _require(_git(root, "rev-parse", "--is-bare-repository") == b"false\n")
    _require(_git(root, "rev-parse", "--is-shallow-repository") == b"false\n")
    _require(_git(root, "for-each-ref", "--format=%(refname)", "refs/replace") == b"")
    return root


@contextmanager
def _validate_object_repository(object_repo: Path) -> Iterator[Path]:
    """Validate a private plain-repository snapshot before Git reads."""

    temporary, snapshot_root = _snapshot_object_repository(object_repo)
    try:
        yield _validate_snapshot_repository(snapshot_root)
    finally:
        temporary.cleanup()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuthorityError()
        result[key] = value
    return result


def _parse_json(data: bytes) -> dict[str, Any]:
    _require(len(data) <= MAX_GIT_OUTPUT)
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (AuthorityError, UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise AuthorityError() from exc
    _require(type(value) is dict)
    return value


def _trusted_git_path() -> Path:
    """Use one validated absolute Git executable, never caller-controlled PATH."""

    path = TRUSTED_GIT_EXECUTABLE
    _require(path.is_absolute())
    try:
        metadata = os.lstat(path)
    except (OSError, RuntimeError, ValueError) as exc:
        raise AuthorityError() from exc
    _require(stat.S_ISREG(metadata.st_mode) and metadata.st_mode & 0o111)
    _require(_resolve_path(path, strict=True) == path)
    return path


def _strict_git_environment() -> dict[str, str]:
    """Keep every Git read on this checkout's local object database."""

    environment = os.environ.copy()
    # Purge every inherited Git variable before restoring a deterministic
    # no-network configuration. Local includes are rejected from the raw
    # checkout config separately; system/global config is disabled here.
    for variable in tuple(environment):
        if variable.startswith("GIT_"):
            environment.pop(variable, None)
    for variable in GIT_REDIRECT_ENV_VARS:
        environment.pop(variable, None)
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_COUNT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "PATH": TRUSTED_HELPER_PATH,
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    return environment


def _close_git_stream(selector: selectors.BaseSelector | None, stream: Any) -> None:
    if selector is not None:
        try:
            selector.unregister(stream)
        except (KeyError, ValueError):
            pass
    try:
        stream.close()
    except (OSError, ValueError):
        pass


def _signal_git_group(
    process: subprocess.Popen[bytes], signal_number: int
) -> None:
    """Signal an isolated Git session, falling back to its leader if needed."""

    try:
        os.killpg(process.pid, signal_number)
        return
    except (AttributeError, OSError, RuntimeError, ValueError):
        pass
    try:
        if signal_number == signal.SIGKILL:
            process.kill()
        else:
            process.terminate()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
        pass


def _terminate_and_drain_git(
    process: subprocess.Popen[bytes] | None,
    selector: selectors.BaseSelector | None,
    streams: tuple[Any, ...] = (),
) -> None:
    """Kill the complete isolated child session and drain registered pipes."""

    if process is not None:
        _signal_git_group(process, signal.SIGTERM)
        try:
            process.wait(timeout=0.25)
        except (subprocess.TimeoutExpired, OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            pass
        # A descendant can retain stdout/stderr after the leader exits. Kill
        # the process group again before draining so those descriptors close.
        _signal_git_group(process, signal.SIGKILL)
        try:
            process.wait(timeout=0.25)
        except (subprocess.TimeoutExpired, OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            pass

    deadline = time.monotonic() + 1.0
    if selector is not None:
        while True:
            try:
                registered = selector.get_map()
            except (OSError, RuntimeError, ValueError):
                break
            if not registered:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                events = selector.select(remaining)
            except (OSError, RuntimeError, ValueError):
                break
            if not events:
                break
            for key, _ in events:
                stream = key.fileobj
                try:
                    while True:
                        chunk = os.read(stream.fileno(), 64 * 1024)
                        if not chunk:
                            _close_git_stream(selector, stream)
                            break
                except BlockingIOError:
                    continue
                except (OSError, RuntimeError, ValueError):
                    _close_git_stream(selector, stream)
        try:
            remaining_streams = [key.fileobj for key in selector.get_map().values()]
        except (OSError, RuntimeError, ValueError):
            remaining_streams = []
        for stream in remaining_streams:
            _close_git_stream(selector, stream)

    registered_ids: set[int] = set()
    if selector is not None:
        try:
            registered_ids = {id(key.fileobj) for key in selector.get_map().values()}
        except (OSError, RuntimeError, ValueError):
            pass
    for stream in streams:
        if stream is not None and id(stream) not in registered_ids:
            _close_git_stream(None, stream)


def _run_bounded_git(
    command: list[str], environment: dict[str, str]
) -> tuple[int, bytes, bytes]:
    """Collect both pipes incrementally and abort at the first output cap."""

    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    streams: tuple[Any, ...] = ()
    buffers: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
            env=environment,
        )
        streams = (process.stdout, process.stderr)
        selector = selectors.DefaultSelector()
        labeled_streams = ((process.stdout, "stdout"), (process.stderr, "stderr"))
        for stream, label in labeled_streams:
            if stream is None:
                raise AuthorityError()
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AuthorityError()
            events = selector.select(remaining)
            if not events:
                raise AuthorityError()
            for key, _ in events:
                stream = key.fileobj
                label = key.data
                try:
                    chunk = os.read(
                        stream.fileno(),
                        min(64 * 1024, MAX_GIT_OUTPUT + 1 - len(buffers[label])),
                    )
                except BlockingIOError:
                    continue
                if not chunk:
                    _close_git_stream(selector, stream)
                    continue
                buffers[label].extend(chunk)
                if len(buffers[label]) > MAX_GIT_OUTPUT:
                    raise AuthorityError()
        try:
            returncode = process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            raise AuthorityError() from exc
        return returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"])
    except AuthorityError:
        _terminate_and_drain_git(process, selector, streams)
        raise
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        _terminate_and_drain_git(process, selector, streams)
        raise AuthorityError() from exc
    finally:
        if selector is not None:
            try:
                remaining_streams = [key.fileobj for key in selector.get_map().values()]
            except (OSError, RuntimeError, ValueError):
                remaining_streams = []
            for stream in remaining_streams:
                _close_git_stream(selector, stream)
            try:
                selector.close()
            except (OSError, RuntimeError, ValueError):
                pass
        for stream in streams:
            if stream is not None:
                _close_git_stream(None, stream)


def _git(repo_root: Path, *arguments: str) -> bytes:
    """Read only bounded data from the local object database; never fetches."""

    try:
        returncode, stdout, stderr = _run_bounded_git(
            [
                str(_trusted_git_path()),
                "--no-replace-objects",
                "--no-lazy-fetch",
                "--no-optional-locks",
                "-C",
                str(repo_root),
                *arguments,
            ],
            _strict_git_environment(),
        )
    except AuthorityError:
        raise
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        raise AuthorityError() from exc
    _require(returncode == 0 and stderr == b"")
    _require(len(stdout) <= MAX_GIT_OUTPUT)
    return stdout


def _authority_introduction_commit(
    object_repo: Path,
    authority_path: str = AUTHORITY_PATH,
    expected_commit: str | None = None,
) -> str:
    """Resolve one exact authority introduction without trusting the checkout tip.

    The historical and active authorities are protected by independent exact pins.
    A rebased checkout can therefore have a different first-parent tip while the
    pinned introduction object remains present in the plain object repository.
    When a pin is supplied, verify that the pinned commit itself changes this
    path instead of inferring a replacement from ``HEAD``. The unpinned form
    remains useful for bounded-output regressions.
    """

    if expected_commit is not None:
        _require(HEX40.fullmatch(expected_commit) is not None)
        _require(_git(object_repo, "cat-file", "-t", expected_commit) == b"commit\n")
        # An exact pin may identify a reviewed rotation that updates an
        # already-existing path, so require the pinned commit to change this
        # path rather than inferring an older path-addition from HEAD.
        output = _git(
            object_repo,
            "diff-tree",
            "--no-commit-id",
            "--name-status",
            "-r",
            expected_commit,
            "--",
            authority_path,
        )
        try:
            changes = output.decode("ascii").splitlines()
        except UnicodeError as exc:
            raise AuthorityError() from exc
        _require(
            len(changes) == 1
            and changes[0].split("\t")[-1] == authority_path
            and changes[0].split("\t", 1)[0] in {"A", "M"}
        )
        return expected_commit
    output = _git(
        object_repo,
        "log",
        "--format=%H",
        "--diff-filter=A",
        "--first-parent",
        "HEAD",
        "--",
        authority_path,
    )
    try:
        commits = output.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise AuthorityError() from exc
    _require(len(commits) == 1 and HEX40.fullmatch(commits[0]) is not None)
    _require(_git(object_repo, "cat-file", "-t", commits[0]) == b"commit\n")
    return commits[0]


def _git_blob(object_repo: Path, revision: str, path: str) -> tuple[str, bytes]:
    try:
        blob_oid = _git(object_repo, "rev-parse", f"{revision}:{path}").decode("ascii").strip()
    except UnicodeError as exc:
        raise AuthorityError() from exc
    _require(HEX40.fullmatch(blob_oid) is not None)
    _require(_git(object_repo, "cat-file", "-t", blob_oid) == b"blob\n")
    data = _git(object_repo, "cat-file", "blob", blob_oid)
    return blob_oid, data


def _validate_manifest(authority: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    _require(tuple(authority.keys()) == AUTHORITY_KEYS)
    _require(authority["schema"] == AUTHORITY_SCHEMA)
    _require(authority["role"] == AUTHORITY_ROLE)
    source_commit = authority["source_commit"]
    _require(type(source_commit) is str and HEX40.fullmatch(source_commit) is not None)
    _require(authority["canonicalization"] == "exact_bytes")
    _require(authority["synthetic_only"] is True and authority["live_claim"] is False)
    manifest = authority["artifact_manifest"]
    _require(type(manifest) is list and len(manifest) == len(EXPECTED_ARTIFACT_PATHS))
    paths: list[str] = []
    records: list[dict[str, Any]] = []
    for raw in manifest:
        _require(type(raw) is dict and tuple(raw.keys()) == RECORD_KEYS)
        path = raw["path"]
        _require(type(path) is str and path in EXPECTED_ARTIFACT_PATHS)
        _require(path not in paths)
        paths.append(path)
        blob_oid = raw["blob_oid"]
        digest = raw["sha256"]
        size = raw["size_bytes"]
        _require(type(blob_oid) is str and HEX40.fullmatch(blob_oid) is not None)
        _require(type(digest) is str and HEX64.fullmatch(digest) is not None)
        _require(type(size) is int and type(size) is not bool and 0 < size <= MAX_GIT_OUTPUT)
        records.append(raw)
    _require(tuple(paths) == EXPECTED_ARTIFACT_PATHS)
    return source_commit, records


def _validate_legacy_manifest(authority: dict[str, Any]) -> dict[str, Any]:
    """Read the historical v1 schema plus six legacy fields (seven total keys) without treating it as v2 trust."""

    _require(tuple(authority.keys()) == LEGACY_AUTHORITY_KEYS)
    _require(authority["schema"] == LEGACY_AUTHORITY_SCHEMA)
    _require(authority["validator_path"] == LEGACY_VALIDATOR_PATH)
    _require(authority["baseline_path"] == LEGACY_BASELINE_PATH)
    for prefix in ("validator", "baseline"):
        size = authority[f"{prefix}_size_bytes"]
        digest = authority[f"{prefix}_sha256"]
        _require(type(size) is int and type(size) is not bool and 0 < size <= MAX_GIT_OUTPUT)
        _require(type(digest) is str and HEX64.fullmatch(digest) is not None)
    return authority


def _legacy_blob_oid(data: bytes) -> str:
    """Compute Git's SHA-1 blob identity without invoking a mutable Git binary."""

    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def load_legacy_authority(checkout_root: Path) -> dict[str, Any]:
    """Load the preserved legacy v1 authority with exact byte identity."""

    try:
        authority_bytes = _read_checkout_file(checkout_root, LEGACY_AUTHORITY_PATH)
        _require(len(authority_bytes) == LEGACY_AUTHORITY_SIZE)
        _require(hashlib.sha256(authority_bytes).hexdigest() == LEGACY_AUTHORITY_SHA256)
        _require(_legacy_blob_oid(authority_bytes) == LEGACY_AUTHORITY_BLOB_OID)
        return _validate_legacy_manifest(_parse_json(authority_bytes))
    except AuthorityError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise AuthorityError() from exc


def load_trusted_authority(
    object_repo: Path,
    *,
    authority_path: str = AUTHORITY_PATH,
    expected_authority_commit: str | None = EXPECTED_AUTHORITY_COMMIT,
    expected_source_commit: str | None = EXPECTED_SOURCE_COMMIT,
    required_ancestor_commit: str | None = None,
) -> dict[str, Any]:
    """Load and verify a v2 authority from an isolated immutable Git snapshot."""

    try:
        _require(type(authority_path) is str and authority_path and "\x00" not in authority_path)
        if expected_authority_commit is not None:
            _require(HEX40.fullmatch(expected_authority_commit) is not None)
        if expected_source_commit is not None:
            _require(HEX40.fullmatch(expected_source_commit) is not None)
        if required_ancestor_commit is not None:
            _require(HEX40.fullmatch(required_ancestor_commit) is not None)
        with _validate_object_repository(object_repo) as isolated_repo:
            introduction = _authority_introduction_commit(
                isolated_repo,
                authority_path,
                expected_commit=expected_authority_commit,
            )
            authority_bytes = _git(isolated_repo, "show", f"{introduction}:{authority_path}")
            authority = _parse_json(authority_bytes)
            source_commit, records = _validate_manifest(authority)
            if expected_source_commit is not None:
                _require(source_commit == expected_source_commit)
            _require(source_commit != introduction)
            _require(_git(isolated_repo, "cat-file", "-t", source_commit) == b"commit\n")
            try:
                first_parent = _git(isolated_repo, "rev-parse", f"{introduction}^1").decode("ascii").strip()
            except UnicodeError as exc:
                raise AuthorityError() from exc
            _require(first_parent == source_commit)
            _require(_git(isolated_repo, "merge-base", "--is-ancestor", source_commit, introduction) == b"")
            if required_ancestor_commit is not None:
                _require(_git(isolated_repo, "merge-base", "--is-ancestor", required_ancestor_commit, introduction) == b"")
            for record in records:
                blob_oid, data = _git_blob(isolated_repo, source_commit, record["path"])
                _require(blob_oid == record["blob_oid"])
                _require(len(data) == record["size_bytes"])
                _require(hashlib.sha256(data).hexdigest() == record["sha256"])
        return {
            "authority_path": authority_path,
            "schema": AUTHORITY_SCHEMA,
            "authority_commit": introduction,
            "source_commit": source_commit,
            "authority_bytes": authority_bytes,
            "artifact_manifest": records,
        }
    except AuthorityError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise AuthorityError() from exc


def _read_checkout_file(checkout_root: Path, path: str) -> bytes:
    """Read a bounded regular file without traversing checkout symlinks."""

    _require(type(path) is str and path and "\\" not in path and "\x00" not in path)
    relative = PurePosixPath(path)
    _require(
        relative.parts
        and not relative.is_absolute()
        and all(part not in ("", ".", "..") for part in relative.parts)
    )
    no_follow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    _require(type(no_follow) is int and type(nonblock) is int and type(directory_flag) is int)
    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | no_follow | nonblock | directory_flag
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | no_follow | nonblock
    directory_fds: list[int] = []
    file_fd: int | None = None
    try:
        current_fd, _ = _open_directory_chain(checkout_root)
        directory_fds.append(current_fd)
        _require(stat.S_ISDIR(os.fstat(current_fd).st_mode))
        for component in relative.parts[:-1]:
            current_fd = os.open(component, directory_flags, dir_fd=current_fd)
            directory_fds.append(current_fd)
            _require(stat.S_ISDIR(os.fstat(current_fd).st_mode))
        file_fd = os.open(relative.parts[-1], file_flags, dir_fd=current_fd)
        _require(stat.S_ISREG(os.fstat(file_fd).st_mode))
        data = bytearray()
        while len(data) < MAX_GIT_OUTPUT + 1:
            chunk = os.read(file_fd, min(64 * 1024, MAX_GIT_OUTPUT + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        _require(len(data) <= MAX_GIT_OUTPUT)
        return bytes(data)
    except AuthorityError:
        raise
    except (OSError, RuntimeError, ValueError, IndexError) as exc:
        raise AuthorityError() from exc
    finally:
        if file_fd is not None:
            try:
                os.close(file_fd)
            except OSError:
                pass
        for descriptor in reversed(directory_fds):
            try:
                os.close(descriptor)
            except OSError:
                pass


def verify_checkout(checkout_root: Path, object_repo: Path) -> dict[str, Any]:
    """Compare checkout trust inputs with the immutable predecessor manifest."""

    try:
        authority = load_trusted_authority(object_repo)
        _require(_read_checkout_file(checkout_root, AUTHORITY_PATH) == authority["authority_bytes"])
        for record in authority["artifact_manifest"]:
            data = _read_checkout_file(checkout_root, record["path"])
            _require(len(data) == record["size_bytes"])
            _require(hashlib.sha256(data).hexdigest() == record["sha256"])
        return {
            "ok": True,
            "stage": "aggregate_predecessor_v2",
            "authority_path": authority["authority_path"],
            "schema": authority["schema"],
            "authority_commit": authority["authority_commit"],
            "source_commit": authority["source_commit"],
            "artifact_count": len(authority["artifact_manifest"]),
            "live_claim": False,
        }
    except AuthorityError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise AuthorityError() from exc


def format_failure() -> str:
    payload = {
        "ok": False,
        "live_claim": False,
        "error": {"code": "fixture_registry_authority_invalid", "message": SAFE_ERROR_MESSAGE},
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    if len(encoded) > MAX_ERROR_LENGTH:
        raise AuthorityError()
    return encoded


def emit_failure() -> None:
    print(format_failure())


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise ArgumentParseError()


def main(argv: list[str] | None = None) -> int:
    try:
        # Resolve the script default inside the redacted failure boundary. A
        # hostile symlink loop or path-resolution error must never print a
        # traceback or escape as an uncaught RuntimeError.
        default_repo = _resolve_path(Path(__file__), strict=True).parents[1]
        parser = _Parser(description=__doc__)
        parser.add_argument("--repo-root", type=Path, default=default_repo)
        parser.add_argument("--checkout-root", type=Path, default=default_repo)
        args = parser.parse_args(argv)
        result = verify_checkout(args.checkout_root, args.repo_root)
    except ArgumentParseError:
        emit_failure()
        return 2
    except (AuthorityError, OSError, RuntimeError, ValueError, IndexError):
        emit_failure()
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
