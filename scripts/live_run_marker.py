#!/usr/bin/env python3
"""Strict per-run ownership markers for disposable Hermes fixtures.

The launcher receives one caller-selected marker path. This module never scans a
runs directory, infers a "latest" run, or follows a path to discover ownership.
A marker is a small, private, atomically written capability record: it binds one
run ID to one container identity, loopback endpoint, state file, and fresh
credential file. The credential value is intentionally never read here.
"""

from __future__ import annotations

import contextlib
import contextvars
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Mapping


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
CREDENTIAL_GENERATION_BYTES = hashlib.sha256().digest_size
LIFECYCLE_LOCK_NAME = ".lifecycle.lock"
QUARANTINE_LOCK_NAME = ".quarantine.lock"

RUN_ID_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
INSTANCE_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$")
CONTAINER_ID_PATTERN = re.compile(r"[0-9a-f]{12,64}\Z")
CONTAINER_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
IMAGE_PATTERN = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
ENDPOINT_PATTERN = re.compile(r"http://127\.0\.0\.1:(?P<port>[0-9]{1,5})\Z")

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
CREDENTIAL_IDENTITY_KEYS_WITH_GENERATION = frozenset((*CREDENTIAL_IDENTITY_KEYS, "generation"))
GENERATION_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
CLEANUP_KEYS = frozenset({"cleanup_cidfile_path", "cleanup_cidfile_identity"})


MarkerFileIdentity = tuple[int, int, int, int, int]
CidfileIdentity = tuple[int, int, int, int, int]
ParentIdentity = tuple[int, int, int]
_MARKER_RENAME_EXPECTED: contextvars.ContextVar[
    tuple[int, str, str, MarkerFileIdentity, int | None] | None
] = contextvars.ContextVar(
    "marker_rename_expected",
    default=None,
)


def _before_rename_syscall() -> None:
    """Deterministic test boundary immediately before quarantine rename."""


def _before_marker_commit(parent_fd: int, source_name: str, source_fd: int) -> None:
    """Deterministic boundary before descriptor-backed marker creation."""

    del parent_fd, source_name, source_fd


_EXPECTED_PARENT_IDENTITY: contextvars.ContextVar[ParentIdentity | None] = contextvars.ContextVar(
    "marker_expected_parent_identity",
    default=None,
)
_ACTIVE_QUARANTINE_LOCK: contextvars.ContextVar[int | None] = contextvars.ContextVar(
    "marker_active_quarantine_lock",
    default=None,
)
_ACTIVE_LIFECYCLE_LOCK: contextvars.ContextVar[int | None] = contextvars.ContextVar(
    "marker_active_lifecycle_lock",
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
    """The private inode plus a one-way content generation.

    The generation detects same-inode, same-size credential replacement without
    retaining or serializing the credential bytes. Legacy records may omit it
    for schema compatibility, but every transient handoff rejects that form.
    """

    device: int
    inode: int
    mode: int
    size: int
    nlink: int
    generation: str = ""

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
    def from_stat_and_content(cls, info: os.stat_result, content: bytes) -> "CredentialIdentity":
        identity = cls.from_stat(info)
        if len(content) != identity.size or len(content) > MAX_CREDENTIAL_BYTES:
            raise MarkerError("credential_identity_invalid")
        return cls(
            identity.device,
            identity.inode,
            identity.mode,
            identity.size,
            identity.nlink,
            hashlib.sha256(content).hexdigest(),
        )

    @classmethod
    def from_document(cls, value: object) -> "CredentialIdentity":
        if not isinstance(value, dict) or set(value) not in {
            CREDENTIAL_IDENTITY_KEYS,
            CREDENTIAL_IDENTITY_KEYS_WITH_GENERATION,
        }:
            raise MarkerError("marker_schema_invalid")
        values = [value[key] for key in ("device", "inode", "mode", "size", "nlink")]
        if any(type(item) is not int or item < 0 for item in values):
            raise MarkerError("marker_schema_invalid")
        generation = value.get("generation", "")
        if type(generation) is not str or (generation and GENERATION_PATTERN.fullmatch(generation) is None):
            raise MarkerError("marker_schema_invalid")
        identity = cls(*values, generation=generation)
        if (
            identity.mode != CREDENTIAL_MODE
            or identity.size < 1
            or identity.size > MAX_CREDENTIAL_BYTES
            or identity.nlink != 1
        ):
            raise MarkerError("marker_schema_invalid")
        return identity

    def document(self) -> dict[str, int | str]:
        document: dict[str, int | str] = {
            "device": self.device,
            "inode": self.inode,
            "mode": self.mode,
            "size": self.size,
            "nlink": self.nlink,
        }
        if self.generation:
            document["generation"] = self.generation
        return document

    def file_identity(self) -> MarkerFileIdentity:
        return (self.device, self.inode, self.mode, self.size, self.nlink)


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
    cleanup_cidfile_path: Path | None = None
    cleanup_cidfile_identity: CidfileIdentity | None = None

    def document(self) -> dict[str, object]:
        document: dict[str, object] = {
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
        if self.cleanup_cidfile_path is not None or self.cleanup_cidfile_identity is not None:
            if self.cleanup_cidfile_path is None or self.cleanup_cidfile_identity is None:
                _fail("marker_schema_invalid")
            document.update(
                {
                    "cleanup_cidfile_path": str(self.cleanup_cidfile_path),
                    "cleanup_cidfile_identity": {
                        "device": self.cleanup_cidfile_identity[0],
                        "inode": self.cleanup_cidfile_identity[1],
                        "mode": self.cleanup_cidfile_identity[2],
                        "size": self.cleanup_cidfile_identity[3],
                        "nlink": self.cleanup_cidfile_identity[4],
                    },
                }
            )
        return document

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
            cleanup_cidfile_path=self.cleanup_cidfile_path,
            cleanup_cidfile_identity=self.cleanup_cidfile_identity,
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
            cleanup_cidfile_path=self.cleanup_cidfile_path,
            cleanup_cidfile_identity=self.cleanup_cidfile_identity,
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


def content_generation(
    content: bytes,
    *,
    maximum: int = MAX_CREDENTIAL_BYTES,
    code: str = "credential_identity_invalid",
) -> str:
    """Return a bounded one-way generation without retaining source bytes.

    Credentials use the small default bound. Marker and state snapshots pass
    their larger record limits explicitly; the hash is still the only retained
    content proof, so neither path stores a readable secret or record body.
    """

    if (
        not isinstance(content, bytes)
        or type(maximum) is not int
        or maximum < 0
        or len(content) > maximum
    ):
        _fail(code)
    return hashlib.sha256(content).hexdigest()


def _bounded_text(value: object, code: str = "marker_schema_invalid") -> str:
    if type(value) is not str or not value:
        _fail(code)
    try:
        if len(value.encode("utf-8")) > MAX_TEXT_BYTES:
            _fail(code)
    except UnicodeEncodeError:
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
    if not raw or not os.path.isabs(raw):
        _fail(code)
    try:
        if len(raw.encode("utf-8")) > MAX_PATH_BYTES:
            _fail(code)
    except UnicodeEncodeError:
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


def marker_paths(marker_path: str | Path, *, validate_parent: bool = True) -> MarkerPaths:
    """Validate the exact marker and derive fixed, run-scoped sibling files.

    ``validate_parent`` remains enabled for the public compatibility helper.
    Filesystem operations pass ``False`` after deriving the canonical path and
    then open and validate the parent directory descriptor exactly once; this
    avoids a validate-then-open window during a lifecycle transaction.
    """

    marker = canonical_path(marker_path)
    if validate_parent:
        ensure_private_runs_dir(marker.parent)
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
    # Keep marker storage on the exact producer grammar. URL parsers normalize
    # uppercase schemes, leading-zero ports, and empty delimiters.
    match = ENDPOINT_PATTERN.fullmatch(endpoint)
    if match is None:
        _fail("marker_schema_invalid")
    try:
        port = int(match.group("port"))
    except (TypeError, ValueError, OverflowError):
        _fail("marker_schema_invalid")
    if not 1 <= port <= 65535:
        _fail("marker_schema_invalid")
    return endpoint


def _validate_marker_document(document: object, requested_path: Path) -> RunMarker:
    if not isinstance(document, dict):
        _fail("marker_schema_invalid")
    keys = set(document)
    if keys != MARKER_KEYS and not (
        keys == MARKER_KEYS | CLEANUP_KEYS and document.get("status") == STATUS_CLEANUP_FAILED
    ):
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
    cleanup_path: Path | None = None
    cleanup_identity: CidfileIdentity | None = None
    if keys == MARKER_KEYS | CLEANUP_KEYS:
        cleanup_path = canonical_path(document.get("cleanup_cidfile_path"), code="cidfile_path_invalid")
        if cleanup_path != requested_path.with_name(f"{requested_path.stem}.cidfile"):
            _fail("marker_path_mismatch")
        raw_cleanup_identity = document.get("cleanup_cidfile_identity")
        if not isinstance(raw_cleanup_identity, dict) or set(raw_cleanup_identity) != {
            "device", "inode", "mode", "size", "nlink"
        }:
            _fail("marker_schema_invalid")
        values = tuple(raw_cleanup_identity.get(key) for key in ("device", "inode", "mode", "size", "nlink"))
        if any(type(value) is not int or value < 0 for value in values):
            _fail("marker_schema_invalid")
        cleanup_identity = values  # type: ignore[assignment]
        if cleanup_identity[2] != CREDENTIAL_MODE or cleanup_identity[3] > MAX_CREDENTIAL_BYTES:
            _fail("marker_schema_invalid")
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
        cleanup_cidfile_path=cleanup_path,
        cleanup_cidfile_identity=cleanup_identity,
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
    return _open_runs_parent(marker.parent, code=code)


def _lock_identity(info: os.stat_result, *, code: str) -> MarkerFileIdentity:
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != MARKER_MODES or info.st_nlink != 1:
        _fail(code)
    return (info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode), info.st_size, info.st_nlink)


@contextlib.contextmanager
def _exclusive_lock(parent_fd: int, name: str, *, code: str) -> Iterator[int]:
    _validate_runs_parent_fd(parent_fd, code=code)
    descriptor = -1
    try:
        try:
            descriptor = os.open(
                name,
                os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                MARKER_MODES,
                dir_fd=parent_fd,
            )
        except OSError:
            _fail(code)
        try:
            os.fchmod(descriptor, MARKER_MODES)
            before = _lock_identity(os.fstat(descriptor), code=code)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            after = _lock_identity(os.fstat(descriptor), code=code)
        except OSError:
            _fail(code)
        if before != after:
            _fail(f"{code}_replaced")
        yield descriptor
    finally:
        if descriptor >= 0:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(descriptor)
            except OSError:
                pass


@contextlib.contextmanager
def exclusive_lifecycle_lease(parent_fd: int, *, code: str = "lifecycle_lease_failed") -> Iterator[None]:
    """Serialize one launcher lifecycle across processes and runners."""

    active = _ACTIVE_LIFECYCLE_LOCK.get()
    if active is not None:
        if active != parent_fd:
            _fail(f"{code}_replaced")
        _validate_runs_parent_fd(parent_fd, code=code)
        yield
        return
    with _exclusive_lock(parent_fd, LIFECYCLE_LOCK_NAME, code=code) as descriptor:
        token = _ACTIVE_LIFECYCLE_LOCK.set(parent_fd)
        try:
            yield
        finally:
            _ACTIVE_LIFECYCLE_LOCK.reset(token)


@contextlib.contextmanager
def quarantine_exclusive(parent_fd: int, *, code: str = "quarantine_lock_failed") -> Iterator[None]:
    """Serialize quota measurement, reservation, and aggregate recheck."""

    active = _ACTIVE_QUARANTINE_LOCK.get()
    if active is not None:
        yield
        return
    with _exclusive_lock(parent_fd, QUARANTINE_LOCK_NAME, code=code) as descriptor:
        token = _ACTIVE_QUARANTINE_LOCK.set(descriptor)
        try:
            yield
        finally:
            _ACTIVE_QUARANTINE_LOCK.reset(token)


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


def _quarantine_usage_unlocked(parent_fd: int) -> tuple[int, int]:
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


def quarantine_usage(parent_fd: int) -> tuple[int, int]:
    """Measure fixed slots under the inter-process quota lock."""

    with quarantine_exclusive(parent_fd):
        return _quarantine_usage_unlocked(parent_fd)


def reserve_quarantine_slot(
    parent_fd: int,
    kind: str,
    size: int,
    *,
    exclude: set[str] | None = None,
) -> str:
    """Measure and choose one slot while holding the quota lock."""

    if type(size) is not int or size < 0:
        _fail("quarantine_quota_exceeded")
    active = _ACTIVE_QUARANTINE_LOCK.get()
    if active is None:
        with quarantine_exclusive(parent_fd):
            return reserve_quarantine_slot(parent_fd, kind, size, exclude=exclude)
    count, total = _quarantine_usage_unlocked(parent_fd)
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

    paths = marker_paths(marker.marker_path, validate_parent=False)
    if marker.marker_path != paths.marker or marker.state_path != paths.state or marker.credential_path != paths.credential:
        _fail("marker_path_mismatch")
    _validate_marker_document(marker.document(), paths.marker)
    return marker


def create_marker(marker: RunMarker, *, parent_fd: int | None = None) -> MarkerFileIdentity:
    """Create one marker through the shared mode-gated FD publication path."""

    validate_marker(marker)
    path = marker.marker_path
    content = _marker_bytes(marker)
    owns_parent = parent_fd is None
    if parent_fd is None:
        parent_fd = _open_runs_parent(path.parent)
    else:
        _validate_runs_parent_fd(parent_fd)
    temporary_fd = -1
    temporary_name: str | None = None
    temporary_identity: MarkerFileIdentity | None = None
    try:
        with quarantine_exclusive(parent_fd):
            try:
                existing = os.open(path.name, _quarantine_open_flags(), dir_fd=parent_fd)
            except FileNotFoundError:
                existing = -1
            except OSError:
                _fail("marker_create_failed")
            else:
                os.close(existing)
                _fail("marker_already_exists")

            for _ in range(QUARANTINE_SLOT_COUNT):
                candidate = reserve_quarantine_slot(parent_fd, "replace-tmp", len(content))
                try:
                    temporary_fd = os.open(
                        candidate,
                        os.O_RDWR
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_CLOEXEC", 0),
                        0,
                        dir_fd=parent_fd,
                    )
                except FileExistsError:
                    continue
                temporary_name = candidate
                break
            if temporary_fd < 0 or temporary_name is None:
                _fail("quarantine_quota_exceeded")
            _write_all(temporary_fd, content)
            os.fsync(temporary_fd)
            os.fchmod(temporary_fd, MARKER_MODES)
            os.fsync(temporary_fd)
            temporary_identity = _marker_file_identity(os.fstat(temporary_fd))
            _before_marker_commit(parent_fd, temporary_name, temporary_fd)
            identity = _publish_marker_from_descriptor(
                parent_fd,
                path.name,
                temporary_fd,
                temporary_identity,
                content,
            )
            _remove_owned_name(parent_fd, temporary_name, temporary_identity)
            return identity
    except MarkerError:
        raise
    except OSError:
        _fail("marker_create_failed")
    finally:
        if temporary_name is not None and temporary_identity is not None:
            _remove_owned_name(parent_fd, temporary_name, temporary_identity)
        if temporary_fd >= 0:
            try:
                os.close(temporary_fd)
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
    """Claim a source pathname for quarantine and let callers verify the inode.

    Darwin's rename APIs are pathname-only. This helper is intentionally limited
    to moving an old marker into bounded evidence; callers compare the moved
    descriptor with the held source and reconstruct the logical original from
    held bytes if a foreign source won the race. The final marker publication
    never uses this path-based operation.
    """

    source = os.fsencode(source_name)
    target = os.fsencode(target_name)
    expected_claim = _MARKER_RENAME_EXPECTED.get()
    expected_source_fd: int | None = None
    expected_identity: MarkerFileIdentity | None = None
    guarded_claim = False
    if expected_claim is not None:
        expected_parent, expected_source, expected_target, expected_identity, expected_source_fd = expected_claim
        guarded_claim = (expected_parent, expected_source, expected_target) == (
            parent_fd,
            source_name,
            target_name,
        )
    if guarded_claim:
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
            if expected_source_fd is not None:
                held = _held_marker_identity(expected_source_fd)
                if held[:4] != expected_identity[:4]:
                    _fail("marker_replaced")
        except FileNotFoundError:
            _fail("marker_replaced")
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

        _before_rename_syscall()
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
            if expected_source_fd is not None:
                held = _held_marker_identity(expected_source_fd)
                if held[:4] != expected_identity[:4]:
                    _fail("marker_replaced")
        except FileNotFoundError:
            _fail("marker_replaced")
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin" and hasattr(libc, "renameatx_np"):
        operation = libc.renameatx_np
        operation.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        operation.restype = ctypes.c_int
        result = operation(parent_fd, source, parent_fd, target, 0x00000004)
    elif hasattr(libc, "renameat2"):
        operation = libc.renameat2
        operation.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
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
    *,
    source_fd: int | None = None,
) -> None:
    """Validate the held source and pathname inside no-replace publication."""

    if source_fd is not None:
        try:
            held_identity = _held_marker_identity(source_fd)
        except (MarkerError, OSError):
            _fail("marker_replaced")
        if held_identity[:4] != expected[:4]:
            _fail("marker_replaced")
    token = _MARKER_RENAME_EXPECTED.set((parent_fd, source_name, target_name, expected, source_fd))
    try:
        _rename_noreplace(parent_fd, source_name, target_name)
    finally:
        _MARKER_RENAME_EXPECTED.reset(token)


def _remove_owned_name(parent_fd: int, name: str, expected: MarkerFileIdentity) -> None:
    """Retain a reserved slot; no portable unlink-by-inode exists on Darwin."""

    del parent_fd, name, expected
    # Occupied quarantine evidence is intentionally bounded and retained. A
    # check-then-unlink would allow a same-UID pathname replacement to turn
    # cleanup into deletion of a foreign inode.
    return


def _held_marker_identity(descriptor: int) -> MarkerFileIdentity:
    """Validate an exact marker fd even after its staging name is unlinked."""

    try:
        info = os.fstat(descriptor)
    except OSError:
        _fail("marker_replaced")
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_IMODE(info.st_mode) != MARKER_MODES
        or info.st_nlink not in {0, 1}
        or info.st_size < 1
        or info.st_size > MAX_MARKER_BYTES
    ):
        _fail("marker_replaced")
    return (info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode), info.st_size, info.st_nlink)


def _read_bounded_descriptor(descriptor: int) -> bytes:
    """Read one bounded staged marker through its already-held descriptor."""

    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        raw = bytearray()
        while len(raw) <= MAX_MARKER_BYTES:
            chunk = os.read(descriptor, MAX_MARKER_BYTES + 1 - len(raw))
            if not chunk:
                break
            raw.extend(chunk)
    except OSError:
        _fail("marker_read_failed")
    if len(raw) > MAX_MARKER_BYTES:
        _fail("marker_too_large")
    return bytes(raw)


def _fclonefileat(
    source_fd: int,
    parent_fd: int,
    target_name: str,
) -> None:
    """Clone one held source inode to an absent sibling on Darwin/APFS."""

    libc = ctypes.CDLL(None, use_errno=True)
    operation = getattr(libc, "fclonefileat", None)
    if operation is None:
        _fail("atomic_quarantine_unavailable")
    operation.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    operation.restype = ctypes.c_int
    result = operation(source_fd, parent_fd, os.fsencode(target_name), 0)
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        _fail("marker_replaced")
    if error_number in {errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS, errno.EINVAL}:
        _fail("atomic_quarantine_unavailable")
    _fail("marker_publish_failed")


def _publish_marker_from_descriptor(
    parent_fd: int,
    target_name: str,
    source_fd: int,
    source_expected: MarkerFileIdentity,
    expected_content: bytes,
) -> MarkerFileIdentity:
    """Publish exact staged bytes without exposing a complete final pathname.

    Darwin clones into a bounded temporary slot, gates that complete clone at
    mode ``000``, validates its descriptor and bytes, then moves it into the
    final pathname with no-replace semantics. The final name therefore cannot
    be opened as a complete readable marker before the mode gate and all
    descriptor/content/identity checks have passed. Other platforms use an
    exclusive destination FD and the same mode-gated validation sequence.
    """

    destination_fd = -1
    pathname_fd = -1
    staging_fd = -1
    staging_name: str | None = None
    try:
        held_identity = _held_marker_identity(source_fd)
        if held_identity[:4] != source_expected[:4] or held_identity[3] != len(expected_content):
            _fail("marker_replaced")
        actual_content = _read_bounded_descriptor(source_fd)
        if actual_content != expected_content:
            _fail("marker_replaced")

        cloned = False
        if sys.platform == "darwin":
            try:
                staging_name = reserve_quarantine_slot(
                    parent_fd,
                    "replace-tmp",
                    len(expected_content),
                )
                _fclonefileat(source_fd, parent_fd, staging_name)
                staging_fd = os.open(
                    staging_name,
                    os.O_RDWR
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=parent_fd,
                )
                staging_identity = _marker_file_identity(os.fstat(staging_fd))
                if staging_identity[3] != len(expected_content):
                    _fail("marker_replaced")
                if _read_bounded_descriptor(staging_fd) != expected_content:
                    _fail("marker_replaced")

                # The complete clone is private staging evidence. Gate it
                # before the final name can exist, then validate the gated fd
                # and bytes again while the held descriptor remains authoritative.
                os.fchmod(staging_fd, 0)
                os.fsync(staging_fd)
                gated = os.fstat(staging_fd)
                if (
                    not stat.S_ISREG(gated.st_mode)
                    or stat.S_IMODE(gated.st_mode) != 0
                    or gated.st_size != len(expected_content)
                    or gated.st_nlink != 1
                ):
                    _fail("marker_replaced")
                if _read_bounded_descriptor(staging_fd) != expected_content:
                    _fail("marker_replaced")
                os.fchmod(staging_fd, MARKER_MODES)
                os.fsync(staging_fd)
                staging_identity = _marker_file_identity(os.fstat(staging_fd))
                _rename_exact_noreplace(
                    parent_fd,
                    staging_name,
                    target_name,
                    staging_identity,
                    source_fd=staging_fd,
                )
                destination_fd = staging_fd
                staging_fd = -1
                staging_name = None
                cloned = True
            except MarkerError as error:
                if error.code != "atomic_quarantine_unavailable":
                    raise
                if staging_fd >= 0:
                    try:
                        os.close(staging_fd)
                    except OSError:
                        pass
                    staging_fd = -1
                staging_name = None

        if not cloned:
            try:
                destination_fd = os.open(
                    target_name,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    0,
                    dir_fd=parent_fd,
                )
            except FileExistsError:
                _fail("marker_replaced")
            _write_all(destination_fd, actual_content)
            os.fsync(destination_fd)

        os.fchmod(destination_fd, MARKER_MODES)
        os.fsync(destination_fd)
        destination_identity = _marker_file_identity(os.fstat(destination_fd))
        pathname_fd = os.open(target_name, _quarantine_open_flags(), dir_fd=parent_fd)
        pathname_identity = _marker_file_identity(os.fstat(pathname_fd))
        if pathname_identity != destination_identity:
            _fail("marker_replaced")
        if _read_bounded_descriptor(pathname_fd) != expected_content:
            _fail("marker_replaced")
        os.fsync(parent_fd)
        os.close(pathname_fd)
        pathname_fd = -1
        return destination_identity
    except MarkerError:
        raise
    except OSError:
        _fail("marker_publish_failed")
    finally:
        if pathname_fd >= 0:
            try:
                os.close(pathname_fd)
            except OSError:
                pass
        if destination_fd >= 0:
            try:
                os.close(destination_fd)
            except OSError:
                pass
        if staging_fd >= 0:
            try:
                os.close(staging_fd)
            except OSError:
                pass


def _restore_marker_from_descriptor(
    parent_fd: int,
    marker_name: str,
    source_fd: int,
    source_expected: MarkerFileIdentity,
    source_content: bytes,
) -> None:
    """Best-effort logical rollback that never overwrites a foreign pathname."""

    try:
        _publish_marker_from_descriptor(
            parent_fd,
            marker_name,
            source_fd,
            source_expected,
            source_content,
        )
    except (MarkerError, OSError):
        # O_EXCL preserves a replacement that appeared while rollback ran.
        return


def _rewrite_marker_descriptor(
    parent_fd: int,
    marker_name: str,
    descriptor: int,
    expected: MarkerFileIdentity,
    old_content: bytes,
    new_content: bytes,
    expected_generation: str | None = None,
) -> MarkerFileIdentity:
    """Commit a complete marker through its held inode under the lease.

    The descriptor remains authoritative if the marker pathname is unlinked or
    replaced. A bounded evidence copy is the rollback source, so a write,
    fsync, chmod, or final snapshot failure can restore the original bytes
    without touching a foreign pathname.
    """

    pathname_fd = -1
    try:
        held = _held_marker_identity(descriptor)
        if held[:4] != expected[:4] or held[4] != expected[4]:
            _fail("marker_replaced")
        if expected_generation is not None:
            current_content = _read_bounded_descriptor(descriptor)
            if content_generation(
                current_content,
                maximum=MAX_MARKER_BYTES,
                code="marker_replaced",
            ) != expected_generation:
                _fail("marker_replaced")
        os.fchmod(descriptor, 0)
        os.ftruncate(descriptor, 0)
        os.lseek(descriptor, 0, os.SEEK_SET)
        _write_all(descriptor, new_content)
        os.fsync(descriptor)
        os.fchmod(descriptor, MARKER_MODES)
        os.fsync(descriptor)
        after = _held_marker_identity(descriptor)
        if after[:3] != expected[:3] or after[4] != 1 or after[3] != len(new_content):
            _fail("marker_replaced")
        pathname_fd = os.open(marker_name, _quarantine_open_flags(), dir_fd=parent_fd)
        pathname_identity = _marker_file_identity(os.fstat(pathname_fd))
        if pathname_identity != after or _read_bounded_descriptor(pathname_fd) != new_content:
            _fail("marker_replaced")
        os.fsync(parent_fd)
        os.close(pathname_fd)
        pathname_fd = -1
        return after
    except MarkerError as error:
        try:
            os.fchmod(descriptor, 0)
            os.ftruncate(descriptor, 0)
            os.lseek(descriptor, 0, os.SEEK_SET)
            _write_all(descriptor, old_content)
            os.fsync(descriptor)
            os.fchmod(descriptor, MARKER_MODES)
            os.fsync(descriptor)
        except (MarkerError, OSError):
            _fail("marker_rewrite_failed")
        raise error
    except OSError:
        try:
            os.fchmod(descriptor, 0)
            os.ftruncate(descriptor, 0)
            os.lseek(descriptor, 0, os.SEEK_SET)
            _write_all(descriptor, old_content)
            os.fsync(descriptor)
            os.fchmod(descriptor, MARKER_MODES)
            os.fsync(descriptor)
        except (MarkerError, OSError):
            _fail("marker_rewrite_failed")
        _fail("marker_rewrite_failed")
    finally:
        if pathname_fd >= 0:
            try:
                os.close(pathname_fd)
            except OSError:
                pass


def replace_marker(
    marker: RunMarker,
    *,
    expected: MarkerFileIdentity | None = None,
    parent_fd: int | None = None,
) -> MarkerFileIdentity:
    """Publish a replacement marker as a new inode under the quarantine lease.

    Darwin has no descriptor-bound rename. The old marker is therefore moved
    through a held-descriptor no-replace claim into ``.replace-*`` evidence;
    new bytes are staged in a separate held descriptor and published at the
    final path with ``O_EXCL``. Same-inode rewriting is reserved for
    ``rewrite_marker_exact`` when the finite quarantine budget is exhausted.
    """

    validate_marker(marker)
    path = marker.marker_path
    content = _marker_bytes(marker)
    owns_parent = parent_fd is None
    if parent_fd is None:
        parent_fd = _open_runs_parent(path.parent)
    else:
        _validate_runs_parent_fd(parent_fd)
    source_fd = -1
    stage_fd = -1
    source_identity: MarkerFileIdentity | None = None
    source_content: bytes | None = None
    stage_identity: MarkerFileIdentity | None = None
    old_quarantine_name: str | None = None
    old_moved = False
    published = False
    try:
        with quarantine_exclusive(parent_fd):
            try:
                source_fd = os.open(
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
                _fail("marker_invalid")
            source_identity = _marker_file_identity(os.fstat(source_fd))
            source_content = _read_bounded_descriptor(source_fd)
            if expected is not None and source_identity != expected:
                _fail("marker_replaced")

            assert source_identity is not None
            assert source_content is not None
            for _ in range(QUARANTINE_SLOT_COUNT):
                stage_name = reserve_quarantine_slot(parent_fd, "replace-tmp", len(content))
                try:
                    stage_fd = os.open(
                        stage_name,
                        os.O_RDWR
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_CLOEXEC", 0),
                        0,
                        dir_fd=parent_fd,
                    )
                except FileExistsError:
                    continue
                try:
                    _write_all(stage_fd, content)
                    os.fsync(stage_fd)
                    os.fchmod(stage_fd, MARKER_MODES)
                    os.fsync(stage_fd)
                    stage_identity = _marker_file_identity(os.fstat(stage_fd))
                except MarkerError:
                    raise
                except OSError:
                    _fail("marker_replace_failed")
                break
            if stage_fd < 0 or stage_identity is None:
                _fail("quarantine_quota_exceeded")

            _before_marker_commit(parent_fd, path.name, source_fd)
            for _ in range(QUARANTINE_SLOT_COUNT):
                candidate = reserve_quarantine_slot(parent_fd, "replace", len(source_content))
                try:
                    _rename_exact_noreplace(
                        parent_fd,
                        path.name,
                        candidate,
                        source_identity,
                        source_fd=source_fd,
                    )
                except MarkerError as error:
                    if error.code == "quarantine_exists":
                        continue
                    raise
                old_quarantine_name = candidate
                old_moved = True
                break
            if not old_moved or old_quarantine_name is None:
                _fail("quarantine_quota_exceeded")
            moved_fd = -1
            try:
                moved_fd = os.open(old_quarantine_name, _quarantine_open_flags(), dir_fd=parent_fd)
                moved_identity = _marker_file_identity(os.fstat(moved_fd))
                if moved_identity != source_identity:
                    _fail("marker_replaced")
            finally:
                if moved_fd >= 0:
                    try:
                        os.close(moved_fd)
                    except OSError:
                        pass
            try:
                os.fsync(parent_fd)
            except OSError:
                _fail("marker_replace_sync_failed")

            final_identity = _publish_marker_from_descriptor(
                parent_fd,
                path.name,
                stage_fd,
                stage_identity,
                content,
            )
            published = True
            return final_identity
    except MarkerError:
        raise
    except OSError:
        _fail("marker_replace_failed")
    finally:
        if not published and old_moved and source_identity is not None and source_content is not None and source_fd >= 0:
            _restore_marker_from_descriptor(
                parent_fd,
                path.name,
                source_fd,
                source_identity,
                source_content,
            )
        # Both the old inode and the staged new bytes are retained as bounded
        # evidence. No check-then-unlink cleanup can delete a foreign pathname.
        if stage_fd >= 0:
            try:
                os.close(stage_fd)
            except OSError:
                pass
        if source_fd >= 0:
            try:
                os.close(source_fd)
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
    expected_generation: str | None = None,
    parent_fd: int | None = None,
) -> MarkerFileIdentity:
    """Rewrite one exact marker inode only as the bounded quota fallback.

    Normal replacement publishes a new inode. This path is used only after
    quarantine quota exhaustion, and its held descriptor plus rollback bytes
    keep partial tombstone writes from adopting or overwriting a replacement.
    """

    validate_marker(marker)
    path = marker.marker_path
    new_content = _marker_bytes(marker)
    owns_parent = parent_fd is None
    if parent_fd is None:
        parent_fd = _open_runs_parent(path.parent)
    else:
        _validate_runs_parent_fd(parent_fd)
    descriptor = -1
    try:
        with quarantine_exclusive(parent_fd):
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
                _fail("marker_invalid")
            current = _held_marker_identity(descriptor)
            if current != expected:
                _fail("marker_replaced")
            old_content = _read_bounded_descriptor(descriptor)
            if expected_generation is not None:
                actual_generation = content_generation(
                    old_content,
                    maximum=MAX_MARKER_BYTES,
                    code="marker_replaced",
                )
                if actual_generation != expected_generation:
                    _fail("marker_replaced")
            return _rewrite_marker_descriptor(
                parent_fd,
                path.name,
                descriptor,
                expected,
                old_content,
                new_content,
                expected_generation,
            )
    except MarkerError:
        raise
    except OSError:
        _fail("marker_rewrite_failed")
    finally:
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


def _read_marker_record_with_bytes(
    path: Path,
    *,
    parent_fd: int | None = None,
) -> tuple[object, MarkerFileIdentity, bytes]:
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
        return document, after_identity, bytes(raw)
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


def _read_marker_record(path: Path, *, parent_fd: int | None = None) -> tuple[object, MarkerFileIdentity]:
    """Read one exact marker while preserving the legacy two-value helper shape."""

    document, identity, _ = _read_marker_record_with_bytes(path, parent_fd=parent_fd)
    return document, identity


def _read_marker_bytes(path: Path) -> bytes:
    document, _ = _read_marker_record(path)
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def load_marker_with_identity_and_generation(
    marker_path: str | Path,
    *,
    selectable: bool = False,
    parent_fd: int | None = None,
) -> tuple[RunMarker, MarkerFileIdentity, str]:
    """Load one marker, its identity, and a hash of the exact bytes read."""

    paths = marker_paths(marker_path, validate_parent=False)
    document, identity, raw = _read_marker_record_with_bytes(paths.marker, parent_fd=parent_fd)
    marker = _validate_marker_document(document, paths.marker)
    if selectable and marker.status != STATUS_RUNNING:
        _fail("marker_not_selectable")
    generation = content_generation(
        raw,
        maximum=MAX_MARKER_BYTES,
        code="marker_generation_invalid",
    )
    return marker, identity, generation


def load_marker_with_identity(
    marker_path: str | Path,
    *,
    selectable: bool = False,
    parent_fd: int | None = None,
) -> tuple[RunMarker, MarkerFileIdentity]:
    """Load one marker and its descriptor identity without a second pathname read."""

    marker, identity, _ = load_marker_with_identity_and_generation(
        marker_path,
        selectable=selectable,
        parent_fd=parent_fd,
    )
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


def credential_snapshot(path: str | Path, *, parent_fd: int | None = None) -> CredentialIdentity:
    """Read one bounded credential through an exact descriptor and hash it."""

    credential = canonical_path(path, code="credential_path_invalid")
    owns_parent = parent_fd is None
    if parent_fd is None:
        parent_fd = _open_runs_parent(credential.parent, code="credential_identity_invalid")
    else:
        _validate_runs_parent_fd(parent_fd, code="credential_identity_invalid")
    descriptor = -1
    try:
        try:
            descriptor = os.open(credential.name, _quarantine_open_flags(), dir_fd=parent_fd)
            before = os.fstat(descriptor)
            identity = CredentialIdentity.from_stat(before)
            raw = bytearray()
            while len(raw) <= MAX_CREDENTIAL_BYTES:
                chunk = os.read(descriptor, MAX_CREDENTIAL_BYTES + 1 - len(raw))
                if not chunk:
                    break
                raw.extend(chunk)
            after = os.fstat(descriptor)
        except FileNotFoundError:
            _fail("credential_identity_invalid")
        except OSError:
            _fail("credential_identity_invalid")
        after_identity = CredentialIdentity.from_stat(after)
        if identity.file_identity() != after_identity.file_identity() or len(raw) != identity.size:
            _fail("credential_identity_mismatch")
        if len(raw) > MAX_CREDENTIAL_BYTES:
            _fail("credential_identity_invalid")
        return CredentialIdentity.from_stat_and_content(after, bytes(raw))
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if owns_parent and parent_fd is not None:
            try:
                os.close(parent_fd)
            except OSError:
                pass


def verify_credential_identity(
    marker: RunMarker,
    *,
    parent_fd: int | None = None,
) -> CredentialIdentity:
    """Recheck inode, size, and one-way content generation before exposure."""

    if not marker.credential_identity.generation:
        _fail("credential_generation_missing")
    current = credential_snapshot(marker.credential_path, parent_fd=parent_fd)
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

    paths = marker_paths(marker_path, validate_parent=False)
    if not credential_identity.generation and paths.credential.exists():
        credential_identity = credential_snapshot(paths.credential)
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
    "content_generation",
    "create_marker",
    "credential_lstat",
    "ensure_private_runs_dir",
    "load_marker",
    "load_marker_with_identity",
    "load_marker_with_identity_and_generation",
    "marker_paths",
    "new_marker",
    "new_run_id",
    "replace_marker",
    "rewrite_marker_exact",
    "validate_marker",
    "verify_credential_identity",
]
