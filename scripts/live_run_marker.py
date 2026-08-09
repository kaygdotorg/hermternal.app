#!/usr/bin/env python3
"""Strict per-run ownership markers for disposable Hermes fixtures.

The launcher receives one caller-selected marker path. This module never scans a
runs directory, infers a "latest" run, or follows a path to discover ownership.
A marker is a small, private, atomically written capability record: it binds one
run ID to one container identity, loopback endpoint, state file, and fresh
credential file. The credential value is intentionally never read here.
"""

from __future__ import annotations

import contextvars
import ctypes
import errno
import json
import os
import re
import secrets
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit


SCHEMA = "hermternal.live-run-marker.v1"
STATUS_RUNNING = "running"
STATUS_CLEANUP_FAILED = "cleanup_failed"
MARKER_MODES = 0o600
RUNS_DIR_MODE = 0o700
CREDENTIAL_MODE = 0o600
MAX_MARKER_BYTES = 16 * 1024
MAX_PATH_BYTES = 4096
MAX_TEXT_BYTES = 4096
MAX_CREDENTIAL_BYTES = 256

RUN_ID_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
INSTANCE_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$")
CONTAINER_ID_PATTERN = re.compile(r"[0-9a-f]{12,64}\Z")
CONTAINER_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
IMAGE_PATTERN = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")

MARKER_KEYS = frozenset(
    {
        "schema",
        "status",
        "marker_path",
        "run_id",
        "instance",
        "container_id",
        "container_name",
        "image",
        "endpoint",
        "state_path",
        "credential_path",
        "credential_identity",
    }
)
CREDENTIAL_IDENTITY_KEYS = frozenset({"device", "inode", "mode", "size", "nlink"})


MarkerFileIdentity = tuple[int, int, int, int, int]
ParentIdentity = tuple[int, int, int]
_MARKER_RENAME_EXPECTED: contextvars.ContextVar[tuple[int, str, str, MarkerFileIdentity] | None] = contextvars.ContextVar(
    "marker_rename_expected",
    default=None,
)
_EXPECTED_PARENT_IDENTITY: contextvars.ContextVar[ParentIdentity | None] = contextvars.ContextVar(
    "marker_expected_parent_identity",
    default=None,
)

# Quarantines are deliberately fixed-name slots rather than randomly named
# entries. This bounds retained evidence without enumerating a runs directory;
# an occupied slot is never removed or overwritten, even when it is foreign.
QUARANTINE_SLOT_COUNT = 16
QUARANTINE_MAX_ENTRIES = QUARANTINE_SLOT_COUNT * 3
QUARANTINE_MAX_BYTES = 128 * 1024
_QUARANTINE_KINDS = ("cleanup", "replace", "replace-tmp")


class MarkerError(Exception):
    """Stable fail-closed marker error without path or run-ID echoing."""

    def __init__(self, code: str = "marker_invalid") -> None:
        self.code = code
        super().__init__(code)


class OwnedMarkerError(MarkerError):
    """A marker write failed after this process created one exact inode."""

    def __init__(self, code: str, *, path: Path, identity: MarkerFileIdentity) -> None:
        self.path = path
        self.identity = identity
        super().__init__(code)


@dataclass(frozen=True)
class CredentialIdentity:
    """The lstat identity pinned into a marker, never the credential value."""

    device: int
    inode: int
    mode: int
    size: int
    nlink: int

    @classmethod
    def from_stat(cls, info: os.stat_result) -> "CredentialIdentity":
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or stat.S_IMODE(info.st_mode) != CREDENTIAL_MODE
            or info.st_size < 1
            or info.st_size > MAX_CREDENTIAL_BYTES
            or info.st_nlink != 1
        ):
            raise MarkerError("credential_identity_invalid")
        return cls(
            device=info.st_dev,
            inode=info.st_ino,
            mode=stat.S_IMODE(info.st_mode),
            size=info.st_size,
            nlink=info.st_nlink,
        )

    @classmethod
    def from_document(cls, value: object) -> "CredentialIdentity":
        if not isinstance(value, dict) or set(value) != CREDENTIAL_IDENTITY_KEYS:
            raise MarkerError("marker_schema_invalid")
        values = [value[key] for key in ("device", "inode", "mode", "size", "nlink")]
        if any(type(item) is not int or item < 0 for item in values):
            raise MarkerError("marker_schema_invalid")
        identity = cls(*values)
        if (
            identity.mode != CREDENTIAL_MODE
            or identity.size < 1
            or identity.size > MAX_CREDENTIAL_BYTES
            or identity.nlink != 1
        ):
            raise MarkerError("marker_schema_invalid")
        return identity

    def document(self) -> dict[str, int]:
        return {
            "device": self.device,
            "inode": self.inode,
            "mode": self.mode,
            "size": self.size,
            "nlink": self.nlink,
        }


@dataclass(frozen=True)
class RunMarker:
    """One fully bound run marker or a bounded cleanup-failure tombstone."""

    marker_path: Path
    status: str
    run_id: str
    instance: str
    container_id: str
    container_name: str
    image: str
    endpoint: str
    state_path: Path
    credential_path: Path
    credential_identity: CredentialIdentity

    def document(self) -> dict[str, object]:
        return {
            "schema": SCHEMA,
            "status": self.status,
            "marker_path": str(self.marker_path),
            "run_id": self.run_id,
            "instance": self.instance,
            "container_id": self.container_id,
            "container_name": self.container_name,
            "image": self.image,
            "endpoint": self.endpoint,
            "state_path": str(self.state_path),
            "credential_path": str(self.credential_path),
            "credential_identity": self.credential_identity.document(),
        }

    def with_status(self, status: str) -> "RunMarker":
        return RunMarker(
            marker_path=self.marker_path,
            status=status,
            run_id=self.run_id,
            instance=self.instance,
            container_id=self.container_id,
            container_name=self.container_name,
            image=self.image,
            endpoint=self.endpoint,
            state_path=self.state_path,
            credential_path=self.credential_path,
            credential_identity=self.credential_identity,
        )

    def with_container_id(self, container_id: str) -> "RunMarker":
        return RunMarker(
            marker_path=self.marker_path,
            status=self.status,
            run_id=self.run_id,
            instance=self.instance,
            container_id=container_id,
            container_name=self.container_name,
            image=self.image,
            endpoint=self.endpoint,
            state_path=self.state_path,
            credential_path=self.credential_path,
            credential_identity=self.credential_identity,
        )


@dataclass(frozen=True)
class MarkerPaths:
    """Exact sibling paths owned by one caller-selected marker."""

    marker: Path
    state: Path
    credential: Path
    cidfile: Path


def _fail(code: str) -> None:
    raise MarkerError(code)


def _bounded_text(value: object, code: str = "marker_schema_invalid") -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > MAX_TEXT_BYTES:
        _fail(code)
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        _fail(code)
    return value


def canonical_path(value: str | Path, *, code: str = "marker_path_invalid") -> Path:
    """Return one absolute, normalized, non-symlink path or fail closed."""

    if isinstance(value, Path):
        raw = str(value)
    elif isinstance(value, str):
        raw = value
    else:
        _fail(code)
    if not raw or len(raw.encode("utf-8")) > MAX_PATH_BYTES or not os.path.isabs(raw):
        _fail(code)
    if os.path.normpath(raw) != raw:
        _fail(code)
    try:
        resolved = os.path.realpath(raw)
    except (OSError, ValueError):
        # ``realpath`` rejects embedded NULs with ``ValueError`` on some
        # platforms. Convert hostile path bytes into the same bounded marker
        # error as every other canonical-path failure.
        _fail(code)
    if resolved != raw:
        _fail(code)
    return Path(raw)


def ensure_private_runs_dir(path: str | Path) -> Path:
    """Validate one existing private runs directory without following links."""

    directory = canonical_path(path, code="runs_dir_invalid")
    try:
        info = directory.lstat()
    except OSError:
        _fail("runs_dir_invalid")
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        _fail("runs_dir_invalid")
    if stat.S_IMODE(info.st_mode) != RUNS_DIR_MODE:
        _fail("runs_dir_not_private")
    return directory


def marker_paths(marker_path: str | Path) -> MarkerPaths:
    """Validate the exact marker and derive fixed, run-scoped sibling files."""

    marker = canonical_path(marker_path)
    directory = ensure_private_runs_dir(marker.parent)
    del directory
    if marker.name in {"", ".", ".."} or marker.name.startswith("."):
        _fail("marker_path_invalid")
    state = canonical_path(marker.with_name(f"{marker.stem}.state.json"), code="state_path_invalid")
    credential = canonical_path(marker.with_name(f"{marker.stem}.credential"), code="credential_path_invalid")
    cidfile = canonical_path(marker.with_name(f"{marker.stem}.cidfile"), code="cidfile_path_invalid")
    siblings = (state, credential, cidfile)
    if any(path.parent != marker.parent for path in siblings):
        _fail("marker_path_invalid")
    if len(set((marker, *siblings))) != 4:
        _fail("marker_path_invalid")
    return MarkerPaths(marker, state, credential, cidfile)


def new_run_id() -> str:
    """Generate the opaque 256-bit lowercase run identity before startup."""

    run_id = secrets.token_hex(32)
    if RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise MarkerError("run_id_generation_failed")
    return run_id


def _validate_endpoint(value: object) -> str:
    endpoint = _bounded_text(value)
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except ValueError:
        _fail("marker_schema_invalid")
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or port is None
        or not 1 <= port <= 65535
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        _fail("marker_schema_invalid")
    return endpoint


def _validate_marker_document(document: object, requested_path: Path) -> RunMarker:
    if not isinstance(document, dict) or set(document) != MARKER_KEYS:
        _fail("marker_schema_invalid")
    if document.get("schema") != SCHEMA:
        _fail("marker_schema_invalid")
    status = document.get("status")
    if type(status) is not str or status not in {STATUS_RUNNING, STATUS_CLEANUP_FAILED}:
        _fail("marker_status_invalid")
    marker = canonical_path(document.get("marker_path"), code="marker_path_invalid")
    if marker != requested_path:
        _fail("marker_path_mismatch")
    run_id = _bounded_text(document.get("run_id"))
    if RUN_ID_PATTERN.fullmatch(run_id) is None:
        _fail("marker_schema_invalid")
    instance = _bounded_text(document.get("instance"))
    if INSTANCE_PATTERN.fullmatch(instance) is None:
        _fail("marker_schema_invalid")
    container_id = _bounded_text(document.get("container_id"))
    if CONTAINER_ID_PATTERN.fullmatch(container_id) is None:
        _fail("marker_schema_invalid")
    container_name = _bounded_text(document.get("container_name"))
    if CONTAINER_NAME_PATTERN.fullmatch(container_name) is None:
        _fail("marker_schema_invalid")
    image = _bounded_text(document.get("image"))
    if IMAGE_PATTERN.fullmatch(image) is None:
        _fail("marker_schema_invalid")
    endpoint = _validate_endpoint(document.get("endpoint"))
    state_path = canonical_path(document.get("state_path"), code="state_path_invalid")
    credential_path = canonical_path(document.get("credential_path"), code="credential_path_invalid")
    if state_path.parent != requested_path.parent or credential_path.parent != requested_path.parent:
        _fail("marker_path_invalid")
    if state_path in {requested_path, credential_path} or credential_path == requested_path:
        _fail("marker_path_invalid")
    expected_state_path = requested_path.with_name(f"{requested_path.stem}.state.json")
    expected_credential_path = requested_path.with_name(f"{requested_path.stem}.credential")
    if state_path != expected_state_path or credential_path != expected_credential_path:
        # Sibling paths are derived from the one caller-selected marker. A
        # same-directory alternate cannot become a second run-scoped resource.
        _fail("marker_path_mismatch")
    identity = CredentialIdentity.from_document(document.get("credential_identity"))
    return RunMarker(
        marker_path=marker,
        status=status,
        run_id=run_id,
        instance=instance,
        container_id=container_id,
        container_name=container_name,
        image=image,
        endpoint=endpoint,
        state_path=state_path,
        credential_path=credential_path,
        credential_identity=identity,
    )


def _json_load(raw: bytes) -> object:
    if len(raw) > MAX_MARKER_BYTES:
        _fail("marker_too_large")

    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                _fail("marker_duplicate_key")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        del value
        _fail("marker_json_invalid")

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate,
            parse_constant=reject_constant,
        )
    except MarkerError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
        _fail("marker_json_invalid")
    raise AssertionError("unreachable")


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        try:
            written = os.write(descriptor, view)
        except OSError:
            _fail("marker_write_failed")
        if written <= 0:
            _fail("marker_write_failed")
        view = view[written:]


def _parent_identity(info: os.stat_result, *, code: str = "marker_invalid") -> ParentIdentity:
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != RUNS_DIR_MODE:
        _fail(code)
    return (info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode))


def parent_identity(parent_fd: int, *, code: str = "marker_invalid") -> ParentIdentity:
    """Capture the exact private parent identity held by one operation."""

    try:
        return _parent_identity(os.fstat(parent_fd), code=code)
    except OSError:
        _fail(code)
    raise AssertionError("unreachable")


def _set_expected_parent_identity(identity: ParentIdentity):
    return _EXPECTED_PARENT_IDENTITY.set(identity)


def _reset_expected_parent_identity(token: contextvars.Token[ParentIdentity | None]) -> None:
    _EXPECTED_PARENT_IDENTITY.reset(token)


def revalidate_runs_parent_path(
    marker_path: str | Path,
    parent_fd: int,
    *,
    expected: ParentIdentity | None = None,
    code: str = "marker_invalid",
) -> None:
    """Require the marker pathname to still name the original held directory."""

    marker = canonical_path(marker_path, code="marker_path_invalid")
    try:
        current = _parent_identity(marker.parent.lstat(), code=code)
        held = parent_identity(parent_fd, code=code)
    except OSError:
        _fail("runs_dir_replaced")
    if held != current or (expected is not None and held != expected):
        _fail("runs_dir_replaced")


def _validate_runs_parent_fd(parent_fd: int, *, code: str = "marker_invalid") -> None:
    """Validate a caller-held private runs directory without reopening its path."""

    current = parent_identity(parent_fd, code=code)
    expected = _EXPECTED_PARENT_IDENTITY.get()
    if expected is not None and current != expected:
        _fail("runs_dir_replaced")


def _open_runs_parent(directory: Path, *, code: str = "marker_invalid") -> int:
    """Hold one validated private runs directory across marker operations."""

    try:
        descriptor = os.open(
            directory,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            _validate_runs_parent_fd(descriptor, code=code)
        except MarkerError:
            os.close(descriptor)
            raise
        return descriptor
    except MarkerError:
        raise
    except OSError:
        _fail(code)
    raise AssertionError("unreachable")


def open_runs_parent(marker_path: str | Path, *, code: str = "marker_invalid") -> int:
    """Open the caller-selected marker's private parent without following links."""

    marker = canonical_path(marker_path, code="marker_path_invalid")
    ensure_private_runs_dir(marker.parent)
    return _open_runs_parent(marker.parent, code=code)


def _marker_bytes(marker: RunMarker) -> bytes:
    # ``sort_keys`` and compact separators keep the bounded record deterministic.
    content = (json.dumps(marker.document(), sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(content) > MAX_MARKER_BYTES:
        _fail("marker_too_large")
    return content


def quarantine_slot_names(kind: str) -> tuple[str, ...]:
    if kind not in _QUARANTINE_KINDS:
        _fail("quarantine_kind_invalid")
    return tuple(f".{kind}-{index:02x}" for index in range(QUARANTINE_SLOT_COUNT))


def _quarantine_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )


def quarantine_usage(parent_fd: int) -> tuple[int, int]:
    """Measure only the fixed quarantine slots, without directory enumeration."""

    _validate_runs_parent_fd(parent_fd)
    count = 0
    total = 0
    for kind in _QUARANTINE_KINDS:
        for name in quarantine_slot_names(kind):
            descriptor = -1
            try:
                descriptor = os.open(name, _quarantine_open_flags(), dir_fd=parent_fd)
            except FileNotFoundError:
                continue
            except OSError:
                # An unopenable occupied slot is conservatively counted. It can
                # never be reclaimed by this process, so it consumes capacity.
                count += 1
                continue
            try:
                info = os.fstat(descriptor)
                count += 1
                total += max(0, info.st_size)
            except OSError:
                count += 1
            finally:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
    if count > QUARANTINE_MAX_ENTRIES or total > QUARANTINE_MAX_BYTES:
        _fail("quarantine_quota_exceeded")
    return count, total


def reserve_quarantine_slot(
    parent_fd: int,
    kind: str,
    size: int,
    *,
    exclude: set[str] | None = None,
) -> str:
    """Reserve a bounded fixed slot; races only make a slot unavailable."""

    if type(size) is not int or size < 0:
        _fail("quarantine_quota_exceeded")
    count, total = quarantine_usage(parent_fd)
    if count >= QUARANTINE_MAX_ENTRIES or total + size > QUARANTINE_MAX_BYTES:
        _fail("quarantine_quota_exceeded")
    excluded = exclude or set()
    for name in quarantine_slot_names(kind):
        if name in excluded:
            continue
        descriptor = -1
        try:
            descriptor = os.open(name, _quarantine_open_flags(), dir_fd=parent_fd)
        except FileNotFoundError:
            return name
        except OSError:
            continue
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
    _fail("quarantine_quota_exceeded")
    raise AssertionError("unreachable")


def validate_marker(marker: RunMarker) -> RunMarker:
    """Validate a marker object before it crosses an atomic filesystem write."""

    paths = marker_paths(marker.marker_path)
    if marker.marker_path != paths.marker or marker.state_path != paths.state or marker.credential_path != paths.credential:
        _fail("marker_path_mismatch")
    _validate_marker_document(marker.document(), paths.marker)
    return marker


def create_marker(marker: RunMarker, *, parent_fd: int | None = None) -> MarkerFileIdentity:
    """Create one marker with O_EXCL, fsync, and a held private parent fd."""

    validate_marker(marker)
    path = marker.marker_path
    content = _marker_bytes(marker)
    owns_parent = parent_fd is None
    if parent_fd is None:
        parent_fd = _open_runs_parent(path.parent)
    else:
        _validate_runs_parent_fd(parent_fd)
    descriptor = -1
    identity: MarkerFileIdentity | None = None
    try:
        try:
            descriptor = os.open(
                path.name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                MARKER_MODES,
                dir_fd=parent_fd,
            )
        except FileExistsError:
            _fail("marker_already_exists")
        except OSError:
            _fail("marker_create_failed")
        try:
            _write_all(descriptor, content)
            os.fchmod(descriptor, MARKER_MODES)
            os.fsync(descriptor)
            identity = _marker_file_identity(os.fstat(descriptor))
        except (MarkerError, OSError) as error:
            if identity is None:
                try:
                    identity = _marker_file_identity(os.fstat(descriptor))
                except MarkerError:
                    pass
                except OSError:
                    pass
            if identity is not None:
                code = error.code if isinstance(error, MarkerError) else "marker_create_failed"
                raise OwnedMarkerError(code, path=path, identity=identity) from None
            if isinstance(error, MarkerError):
                raise
            _fail("marker_create_failed")
        try:
            os.close(descriptor)
        except OSError:
            descriptor = -1
            assert identity is not None
            raise OwnedMarkerError("marker_close_failed", path=path, identity=identity) from None
        descriptor = -1
        try:
            os.fsync(parent_fd)
        except OSError:
            assert identity is not None
            raise OwnedMarkerError("marker_sync_failed", path=path, identity=identity) from None
        assert identity is not None
        return identity
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if owns_parent:
            try:
                os.close(parent_fd)
            except OSError:
                pass


def _marker_file_identity(info: os.stat_result) -> MarkerFileIdentity:
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != MARKER_MODES or info.st_nlink != 1:
        _fail("marker_invalid")
    return (info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode), info.st_size, info.st_nlink)


def _rename_noreplace(parent_fd: int, source_name: str, target_name: str) -> None:
    """Claim one same-directory entry without overwriting a replacement."""

    source = os.fsencode(source_name)
    target = os.fsencode(target_name)
    expected_claim = _MARKER_RENAME_EXPECTED.get()
    if expected_claim is not None:
        expected_parent, expected_source, expected_target, expected_identity = expected_claim
        if (expected_parent, expected_source, expected_target) == (parent_fd, source_name, target_name):
            descriptor = -1
            try:
                descriptor = os.open(
                    source_name,
                    os.O_RDONLY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_NONBLOCK", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=parent_fd,
                )
                current = _marker_file_identity(os.fstat(descriptor))
                if current != expected_identity:
                    _fail("marker_replaced")
            except FileNotFoundError:
                pass
            finally:
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin" and hasattr(libc, "renameatx_np"):
        operation = libc.renameatx_np
        operation.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        operation.restype = ctypes.c_int
        result = operation(parent_fd, source, parent_fd, target, 0x00000004)
    elif hasattr(libc, "renameat2"):
        operation = libc.renameat2
        operation.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        operation.restype = ctypes.c_int
        result = operation(parent_fd, source, parent_fd, target, 0x00000001)
    else:
        _fail("atomic_quarantine_unavailable")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        _fail("quarantine_exists")
    if error_number == errno.ENOENT:
        _fail("marker_missing")
    _fail("atomic_quarantine_failed")


def _rename_exact_noreplace(
    parent_fd: int,
    source_name: str,
    target_name: str,
    expected: MarkerFileIdentity,
) -> None:
    """Validate the source again inside the no-replace syscall boundary."""

    token = _MARKER_RENAME_EXPECTED.set((parent_fd, source_name, target_name, expected))
    try:
        _rename_noreplace(parent_fd, source_name, target_name)
    finally:
        _MARKER_RENAME_EXPECTED.reset(token)


def replace_marker(
    marker: RunMarker,
    *,
    expected: MarkerFileIdentity | None = None,
    parent_fd: int | None = None,
) -> MarkerFileIdentity:
    """Replace one exact marker without overwriting a concurrent replacement."""

    validate_marker(marker)
    path = marker.marker_path
    content = _marker_bytes(marker)
    owns_parent = parent_fd is None
    if parent_fd is None:
        parent_fd = _open_runs_parent(path.parent)
    else:
        _validate_runs_parent_fd(parent_fd)
    source_identity: MarkerFileIdentity | None = None
    source_fd = -1
    moved_fd = -1
    final_fd = -1
    temporary_fd = -1
    temporary_name: str | None = None
    quarantine_name: str | None = None
    temporary_identity: MarkerFileIdentity | None = None

    def remove_temporary() -> None:
        # Fixed private slots are bounded evidence. Do not unlink one by name
        # after validating an inode: a same-name replacement could be deleted
        # by that final pathname operation.
        return

    try:
        try:
            source_fd = os.open(
                path.name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            _fail("marker_missing")
        except OSError:
            _fail("marker_invalid")
        source_identity = _marker_file_identity(os.fstat(source_fd))
        if expected is not None and source_identity != expected:
            _fail("marker_replaced")
        for _ in range(QUARANTINE_SLOT_COUNT):
            candidate = reserve_quarantine_slot(parent_fd, "replace-tmp", len(content))
            try:
                temporary_fd = os.open(
                    candidate,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    MARKER_MODES,
                    dir_fd=parent_fd,
                )
            except FileExistsError:
                continue
            temporary_name = candidate
            break
        if temporary_fd < 0 or temporary_name is None:
            _fail("quarantine_quota_exceeded")
        _write_all(temporary_fd, content)
        os.fchmod(temporary_fd, MARKER_MODES)
        os.fsync(temporary_fd)
        temporary_identity = _marker_file_identity(os.fstat(temporary_fd))
        os.close(temporary_fd)
        temporary_fd = -1

        assert source_identity is not None
        for _ in range(QUARANTINE_SLOT_COUNT):
            candidate = reserve_quarantine_slot(
                parent_fd,
                "replace",
                source_identity[3],
                exclude={temporary_name},
            )
            try:
                _rename_exact_noreplace(parent_fd, path.name, candidate, source_identity)
            except MarkerError as error:
                if error.code == "quarantine_exists":
                    continue
                raise
            quarantine_name = candidate
            break
        if quarantine_name is None:
            _fail("quarantine_quota_exceeded")
        moved_fd = os.open(
            quarantine_name,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
        moved_identity = _marker_file_identity(os.fstat(moved_fd))
        if moved_identity != source_identity:
            # Never move a raced quarantine entry back by pathname: after the
            # descriptor check that name may already belong to a replacement.
            _fail("marker_replaced")

        assert temporary_name is not None
        _rename_noreplace(parent_fd, temporary_name, path.name)
        try:
            final_fd = os.open(
                path.name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_fd,
            )
        except OSError:
            _fail("marker_replaced")
        try:
            final_identity = _marker_file_identity(os.fstat(final_fd))
            moved_current = _marker_file_identity(os.fstat(moved_fd))
        except MarkerError:
            _fail("marker_replaced")
        if final_identity != temporary_identity or moved_current != moved_identity:
            _fail("marker_replaced")
        # The old marker remains in one of the finite private quarantine slots.
        try:
            os.fsync(parent_fd)
        except OSError:
            _fail("marker_sync_failed")
        assert temporary_identity is not None
        return temporary_identity
    except MarkerError:
        raise
    except OSError:
        _fail("marker_replace_failed")
    finally:
        if temporary_fd >= 0:
            try:
                os.close(temporary_fd)
            except OSError:
                pass
        if final_fd >= 0:
            try:
                os.close(final_fd)
            except OSError:
                pass
        # Never restore a quarantine by pathname after its descriptor has been
        # checked. A replacement at that name must remain untouched.
        remove_temporary()
        for descriptor in (moved_fd, source_fd):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if owns_parent and parent_fd >= 0:
            try:
                os.close(parent_fd)
            except OSError:
                pass


def rewrite_marker_exact(
    marker: RunMarker,
    expected: MarkerFileIdentity,
    *,
    parent_fd: int | None = None,
) -> MarkerFileIdentity:
    """Rewrite one exact marker inode when quarantine capacity is exhausted.

    This is the bounded fallback for cleanup evidence. It never follows or
    replaces the marker pathname: the held descriptor must still identify the
    expected private inode before bytes are changed. The operation is used only
    to turn an already-owned record into a cleanup tombstone when allocating a
    second quarantine inode would exceed the finite retention budget.
    """

    validate_marker(marker)
    content = _marker_bytes(marker)
    path = marker.marker_path
    owns_parent = parent_fd is None
    if parent_fd is None:
        parent_fd = _open_runs_parent(path.parent)
    else:
        _validate_runs_parent_fd(parent_fd)
    descriptor = -1
    try:
        try:
            descriptor = os.open(
                path.name,
                os.O_RDWR
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            _fail("marker_missing")
        except OSError:
            _fail("marker_rewrite_failed")
        before = _marker_file_identity(os.fstat(descriptor))
        if before != expected:
            _fail("marker_replaced")
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            os.ftruncate(descriptor, 0)
            _write_all(descriptor, content)
            os.fchmod(descriptor, MARKER_MODES)
            os.fsync(descriptor)
        except MarkerError:
            raise
        except OSError:
            _fail("marker_rewrite_failed")
        after = _marker_file_identity(os.fstat(descriptor))
        if after[:3] != before[:3] or after[4] != before[4] or after[3] != len(content):
            _fail("marker_replaced")
        try:
            os.fsync(parent_fd)
        except OSError:
            _fail("marker_sync_failed")
        return after
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if owns_parent:
            try:
                os.close(parent_fd)
            except OSError:
                pass


def _read_marker_record(path: Path, *, parent_fd: int | None = None) -> tuple[object, MarkerFileIdentity]:
    """Read, parse, and pin one marker through a held parent directory fd."""

    owns_parent = parent_fd is None
    if parent_fd is None:
        parent_fd = _open_runs_parent(path.parent)
    else:
        _validate_runs_parent_fd(parent_fd)
    descriptor = -1
    try:
        try:
            descriptor = os.open(
                path.name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            _fail("marker_missing")
        except OSError:
            _fail("marker_invalid")
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != MARKER_MODES
            or before.st_nlink != 1
            or before.st_size > MAX_MARKER_BYTES
        ):
            _fail("marker_invalid")
        raw = bytearray()
        while len(raw) <= MAX_MARKER_BYTES:
            chunk = os.read(descriptor, MAX_MARKER_BYTES + 1 - len(raw))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) > MAX_MARKER_BYTES:
            _fail("marker_too_large")
        # Parse before the final fstat while the same descriptor is still held;
        # pathname replacement cannot make an unowned document look adopted.
        document = _json_load(bytes(raw))
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            stat.S_IMODE(before.st_mode),
            before.st_size,
            before.st_nlink,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            stat.S_IMODE(after.st_mode),
            after.st_size,
            after.st_nlink,
        )
        if before_identity != after_identity:
            _fail("marker_replaced")
        return document, after_identity
    except OSError:
        _fail("marker_read_failed")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if owns_parent:
            try:
                os.close(parent_fd)
            except OSError:
                pass


def _read_marker_bytes(path: Path) -> bytes:
    document, _ = _read_marker_record(path)
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def load_marker_with_identity(
    marker_path: str | Path,
    *,
    selectable: bool = False,
    parent_fd: int | None = None,
) -> tuple[RunMarker, MarkerFileIdentity]:
    """Load one marker and its descriptor identity without a second pathname read."""

    paths = marker_paths(marker_path)
    document, identity = _read_marker_record(paths.marker, parent_fd=parent_fd)
    marker = _validate_marker_document(document, paths.marker)
    if selectable and marker.status != STATUS_RUNNING:
        _fail("marker_not_selectable")
    return marker, identity


def load_marker(
    marker_path: str | Path,
    *,
    selectable: bool = False,
    parent_fd: int | None = None,
) -> RunMarker:
    """Load exactly the caller's marker path; never enumerate or infer a run."""

    marker, _ = load_marker_with_identity(marker_path, selectable=selectable, parent_fd=parent_fd)
    return marker


def credential_lstat(path: str | Path, *, parent_fd: int | None = None) -> CredentialIdentity:
    """Inspect one exact credential path without opening or reading its value."""

    credential = canonical_path(path, code="credential_path_invalid")
    if parent_fd is None:
        try:
            info = credential.lstat()
        except OSError:
            _fail("credential_identity_invalid")
        return CredentialIdentity.from_stat(info)

    _validate_runs_parent_fd(code="credential_identity_invalid", parent_fd=parent_fd)
    descriptor = -1
    try:
        try:
            descriptor = os.open(credential.name, _quarantine_open_flags(), dir_fd=parent_fd)
        except OSError:
            _fail("credential_identity_invalid")
        try:
            info = os.fstat(descriptor)
        except OSError:
            _fail("credential_identity_invalid")
        return CredentialIdentity.from_stat(info)
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def verify_credential_identity(
    marker: RunMarker,
    *,
    parent_fd: int | None = None,
) -> CredentialIdentity:
    """Recheck the exact pinned credential identity without reading its value."""

    current = credential_lstat(marker.credential_path, parent_fd=parent_fd)
    if current != marker.credential_identity:
        _fail("credential_identity_mismatch")
    return current


def new_marker(
    marker_path: str | Path,
    *,
    run_id: str,
    instance: str,
    container_id: str,
    container_name: str,
    image: str,
    endpoint: str,
    credential_identity: CredentialIdentity,
) -> RunMarker:
    """Build a running marker from fully verified, already-created resources."""

    paths = marker_paths(marker_path)
    marker = RunMarker(
        marker_path=paths.marker,
        status=STATUS_RUNNING,
        run_id=run_id,
        instance=instance,
        container_id=container_id,
        container_name=container_name,
        image=image,
        endpoint=endpoint,
        state_path=paths.state,
        credential_path=paths.credential,
        credential_identity=credential_identity,
    )
    return validate_marker(marker)


def cleanup_failed(marker: RunMarker) -> RunMarker:
    """Return the bounded private tombstone form retained after cleanup failure."""

    return validate_marker(marker.with_status(STATUS_CLEANUP_FAILED))


__all__ = [
    "CREDENTIAL_MODE",
    "CREDENTIAL_IDENTITY_KEYS",
    "CredentialIdentity",
    "MARKER_KEYS",
    "MARKER_MODES",
    "MarkerError",
    "MarkerFileIdentity",
    "OwnedMarkerError",
    "MarkerPaths",
    "RunMarker",
    "RUNS_DIR_MODE",
    "SCHEMA",
    "STATUS_CLEANUP_FAILED",
    "STATUS_RUNNING",
    "canonical_path",
    "cleanup_failed",
    "create_marker",
    "credential_lstat",
    "ensure_private_runs_dir",
    "load_marker",
    "load_marker_with_identity",
    "marker_paths",
    "new_marker",
    "new_run_id",
    "replace_marker",
    "rewrite_marker_exact",
    "validate_marker",
    "verify_credential_identity",
]
