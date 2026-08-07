#!/usr/bin/env python3
"""Verify the v2 aggregate fixture authority from immutable Git objects.

This verifier is intentionally separate from the aggregate scanner. The legacy v1 authority (its schema plus six legacy fields) remains readable
at its historical path, while the new multi-artifact bootstrap uses the distinct
v2 path and schema. Stage two pins
the checked-in predecessor bytes only; the later scanner correction must rebase
onto the merged predecessor and create its next authority independently. The
checkout is compared with authority bytes read from the local Git object
database, so replacing the visible authority file or refreshing local hashes
cannot silently authorize different scanner inputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import stat
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, Iterator


LEGACY_AUTHORITY_PATH = "scripts/fixture_registry_authority.json"
LEGACY_AUTHORITY_SCHEMA = "hermternal.fixture-registry-authority.v1"
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
AUTHORITY_PATH = "scripts/fixture_registry_authority.v2.json"
AUTHORITY_SCHEMA = "hermternal.fixture-registry-authority.v2"
AUTHORITY_ROLE = "bootstrap_predecessor"
# The bootstrap is approved only for this reviewed external predecessor. An
# ancestry check alone would let a self-consistent but unreviewed commit become
# the authority source.
APPROVED_SOURCE_COMMIT = "abb6754bddd1cf18927b0172ed9fa3456235b035"
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
MAX_ERROR_LENGTH = 220
SAFE_ERROR_MESSAGE = "fixture registry authority rejected"
TRUSTED_GIT_EXECUTABLE = Path("/usr/bin/git")
# Git may invoke helper processes while reading repository metadata. Keep that
# helper search path fixed; the host owning these system directories is part of
# this fixture-only trust boundary, not an untrusted checkout input.
TRUSTED_HELPER_PATH = "/usr/bin:/bin"
# macOS exposes the host temporary directory through /tmp; permit that
# system alias while rejecting caller-created symlinked ancestors.
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


def _canonical_directory(path: Path) -> Path:
    """Require an absolute directory without caller-controlled path aliases."""

    _require(path.is_absolute())
    _require(all(component not in ("", ".", "..") for component in path.parts[1:]))
    try:
        _require(not path.is_symlink())
        ancestor = Path(path.anchor)
        for component in path.parts[1:-1]:
            ancestor /= component
            if ancestor.is_symlink():
                _require(ancestor in TRUSTED_PATH_ALIASES)
    except (OSError, RuntimeError, ValueError) as exc:
        raise AuthorityError() from exc
    resolved = _resolve_path(path, strict=True)
    _require(resolved.is_dir())
    return resolved


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


def _walk_plain_tree(path: Path) -> None:
    """Descriptor-walk a Git tree without following nested symlinks."""

    no_follow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    _require(type(no_follow) is int and type(nonblock) is int and type(directory_flag) is int)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | no_follow | nonblock
    root_fd: int | None = None
    pending: list[int] = []
    try:
        root_fd = os.open(path, flags | directory_flag)
        pending.append(root_fd)
        root_fd = None
        while pending:
            directory_fd = pending.pop()
            try:
                _require(stat.S_ISDIR(os.fstat(directory_fd).st_mode))
                for name in os.listdir(directory_fd):
                    _require(name not in ("", ".", ".."))
                    child_fd: int | None = None
                    try:
                        child_fd = os.open(name, flags, dir_fd=directory_fd)
                        mode = os.fstat(child_fd).st_mode
                        if stat.S_ISDIR(mode):
                            pending.append(child_fd)
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
            descriptor = pending.pop()
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


def _copy_regular_from_fd(source_fd: int, destination: Path) -> None:
    """Copy one already-open regular file without reopening its source path."""

    before = os.fstat(source_fd)
    destination_fd: int | None = None
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
            chunk = os.read(source_fd, 64 * 1024)
            if not chunk:
                break
            remaining = memoryview(chunk)
            while remaining:
                written = os.write(destination_fd, remaining)
                _require(written > 0)
                remaining = remaining[written:]
        _require(_file_stat_fingerprint(before) == _file_stat_fingerprint(os.fstat(source_fd)))
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


def _copy_git_tree(source_fd: int, destination: Path) -> None:
    """Create a private regular-file snapshot from an open Git directory fd."""

    no_follow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    _require(type(no_follow) is int and type(nonblock) is int and type(directory_flag) is int)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | no_follow | nonblock
    before = os.fstat(source_fd)
    try:
        os.mkdir(destination, 0o700)
        for name in os.listdir(source_fd):
            _require(name not in ("", ".", ".."))
            child_fd: int | None = None
            child_destination = destination / name
            try:
                child_fd = os.open(name, flags, dir_fd=source_fd)
                mode = os.fstat(child_fd).st_mode
                if stat.S_ISDIR(mode):
                    _copy_git_tree(child_fd, child_destination)
                else:
                    _require(stat.S_ISREG(mode))
                    _copy_regular_from_fd(child_fd, child_destination)
            finally:
                if child_fd is not None:
                    os.close(child_fd)
        _require(_file_stat_fingerprint(before) == _file_stat_fingerprint(os.fstat(source_fd)))
    except AuthorityError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise AuthorityError() from exc


def _snapshot_object_repository(object_repo: Path) -> tuple[tempfile.TemporaryDirectory[str], Path]:
    """Snapshot the caller repository before any path-based Git command runs."""

    root = _canonical_directory(object_repo)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    _require(type(no_follow) is int and type(nonblock) is int and type(directory_flag) is int)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | no_follow | nonblock | directory_flag
    root_fd: int | None = None
    git_fd: int | None = None
    temporary: tempfile.TemporaryDirectory[str] | None = None
    try:
        root_fd = os.open(root, flags)
        git_fd = os.open(".git", flags, dir_fd=root_fd)
        temporary = tempfile.TemporaryDirectory(prefix="fixture-authority-snapshot-")
        snapshot_root = Path(temporary.name) / "repo"
        os.mkdir(snapshot_root, 0o700)
        _copy_git_tree(git_fd, snapshot_root / ".git")
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
        for descriptor in (git_fd, root_fd):
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
    """Validate a private snapshot so later Git opens cannot race the caller."""

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


def _close_git_stream(selector: selectors.BaseSelector, stream: Any) -> None:
    try:
        selector.unregister(stream)
    except (KeyError, ValueError):
        pass
    try:
        stream.close()
    except (OSError, ValueError):
        pass


def _terminate_and_drain_git(
    process: subprocess.Popen[bytes], selector: selectors.BaseSelector
) -> None:
    """Stop a bounded-output child and drain its pipes without retaining data."""

    try:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=0.25)
            except subprocess.TimeoutExpired:
                process.kill()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
        try:
            process.kill()
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            pass

    deadline = time.monotonic() + 1.0
    while selector.get_map():
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

    for key in list(selector.get_map().values()):
        _close_git_stream(selector, key.fileobj)
    try:
        process.wait(timeout=0.25)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            pass
        try:
            process.wait(timeout=0.25)
        except subprocess.SubprocessError:
            pass


def _run_bounded_git(
    command: list[str], environment: dict[str, str]
) -> tuple[int, bytes, bytes]:
    """Collect both pipes incrementally and abort at the first output cap."""

    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        env=environment,
    )
    selector = selectors.DefaultSelector()
    buffers: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    streams: tuple[tuple[Any, str], ...] = (
        (process.stdout, "stdout"),
        (process.stderr, "stderr"),
    )
    try:
        for stream, label in streams:
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
        _terminate_and_drain_git(process, selector)
        raise
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        _terminate_and_drain_git(process, selector)
        raise AuthorityError() from exc
    finally:
        for key in list(selector.get_map().values()):
            _close_git_stream(selector, key.fileobj)
        selector.close()


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


def _authority_introduction_commit(object_repo: Path) -> str:
    output = _git(
        object_repo,
        "log",
        "--format=%H",
        "--diff-filter=A",
        "--first-parent",
        "HEAD",
        "--",
        AUTHORITY_PATH,
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
    _require(source_commit == APPROVED_SOURCE_COMMIT)
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


def load_legacy_authority(checkout_root: Path) -> dict[str, Any]:
    """Load the preserved legacy v1 authority for migration compatibility."""

    try:
        return _validate_legacy_manifest(
            _parse_json(_read_checkout_file(checkout_root, LEGACY_AUTHORITY_PATH))
        )
    except AuthorityError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise AuthorityError() from exc


def load_trusted_authority(object_repo: Path) -> dict[str, Any]:
    """Load and verify the v2 authority from immutable Git history."""

    try:
        with _validate_object_repository(object_repo) as isolated_repo:
            introduction = _authority_introduction_commit(isolated_repo)
            authority_bytes = _git(isolated_repo, "show", f"{introduction}:{AUTHORITY_PATH}")
            authority = _parse_json(authority_bytes)
            source_commit, records = _validate_manifest(authority)
            _require(source_commit != introduction)
            _require(_git(isolated_repo, "cat-file", "-t", source_commit) == b"commit\n")
            _require(_git(isolated_repo, "merge-base", "--is-ancestor", source_commit, introduction) == b"")
            for record in records:
                blob_oid, data = _git_blob(isolated_repo, source_commit, record["path"])
                _require(blob_oid == record["blob_oid"])
                _require(len(data) == record["size_bytes"])
                _require(hashlib.sha256(data).hexdigest() == record["sha256"])
        return {
            "authority_path": AUTHORITY_PATH,
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
    root = _canonical_directory(checkout_root)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    _require(type(no_follow) is int and type(nonblock) is int)
    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | no_follow
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | no_follow | nonblock
    directory_fds: list[int] = []
    file_fd: int | None = None
    try:
        current_fd = os.open(root, directory_flags)
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
            "stage": "bootstrap_predecessor_v2",
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
