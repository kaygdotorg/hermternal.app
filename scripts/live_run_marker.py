#!/usr/bin/env python3
"""Strict per-run ownership markers for disposable Hermes fixtures.

The launcher receives one caller-selected marker path. This module never scans a
runs directory, infers a "latest" run, or follows a path to discover ownership.
A marker is a small, private, atomically written capability record: it binds one
run ID to one container identity, loopback endpoint, state file, and fresh
credential file. The credential value is intentionally never read here.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
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


class MarkerError(Exception):
    """Stable fail-closed marker error without path or run-ID echoing."""

    def __init__(self, code: str = "marker_invalid") -> None:
        self.code = code
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


@dataclass(frozen=True)
class MarkerPaths:
    """Exact sibling paths owned by one caller-selected marker."""

    marker: Path
    state: Path
    credential: Path


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
    except OSError:
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
    if state.parent != marker.parent or credential.parent != marker.parent:
        _fail("marker_path_invalid")
    if state == marker or credential in {marker, state}:
        _fail("marker_path_invalid")
    return MarkerPaths(marker, state, credential)


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
    if status not in {STATUS_RUNNING, STATUS_CLEANUP_FAILED}:
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


def _sync_directory(directory: Path) -> None:
    try:
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        _fail("marker_sync_failed")


def _marker_bytes(marker: RunMarker) -> bytes:
    # ``sort_keys`` and compact separators keep the bounded record deterministic.
    return (json.dumps(marker.document(), sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def validate_marker(marker: RunMarker) -> RunMarker:
    """Validate a marker object before it crosses an atomic filesystem write."""

    paths = marker_paths(marker.marker_path)
    if marker.marker_path != paths.marker or marker.state_path != paths.state or marker.credential_path != paths.credential:
        _fail("marker_path_mismatch")
    _validate_marker_document(marker.document(), paths.marker)
    return marker


def create_marker(marker: RunMarker) -> None:
    """Create one marker with O_EXCL, fsync, and a private parent directory."""

    validate_marker(marker)
    path = marker.marker_path
    content = _marker_bytes(marker)
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            MARKER_MODES,
        )
    except FileExistsError:
        _fail("marker_already_exists")
    except OSError:
        _fail("marker_create_failed")
    try:
        _write_all(descriptor, content)
        os.fchmod(descriptor, MARKER_MODES)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _sync_directory(path.parent)


def replace_marker(marker: RunMarker) -> None:
    """Atomically replace an existing marker after validating its exact path."""

    validate_marker(marker)
    path = marker.marker_path
    try:
        info = path.lstat()
    except OSError:
        _fail("marker_missing")
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) != MARKER_MODES or info.st_nlink != 1:
        _fail("marker_invalid")
    temporary = path.with_name(f".{path.name}.tmp-{secrets.token_hex(8)}")
    content = _marker_bytes(marker)
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            MARKER_MODES,
        )
        try:
            _write_all(descriptor, content)
            os.fchmod(descriptor, MARKER_MODES)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        _sync_directory(path.parent)
    except MarkerError:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    except OSError:
        try:
            temporary.unlink()
        except OSError:
            pass
        _fail("marker_replace_failed")


def _read_marker_bytes(path: Path) -> bytes:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
    except FileNotFoundError:
        _fail("marker_missing")
    except OSError:
        _fail("marker_invalid")
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
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
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_nlink,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_nlink,
        ):
            _fail("marker_replaced")
        if len(raw) > MAX_MARKER_BYTES:
            _fail("marker_too_large")
        return bytes(raw)
    except OSError:
        _fail("marker_read_failed")
    finally:
        os.close(descriptor)


def load_marker(marker_path: str | Path, *, selectable: bool = False) -> RunMarker:
    """Load exactly the caller's marker path; never enumerate or infer a run."""

    paths = marker_paths(marker_path)
    raw = _read_marker_bytes(paths.marker)
    marker = _validate_marker_document(_json_load(raw), paths.marker)
    if selectable and marker.status != STATUS_RUNNING:
        _fail("marker_not_selectable")
    return marker


def credential_lstat(path: str | Path) -> CredentialIdentity:
    """Inspect one exact credential path without opening or reading its value."""

    credential = canonical_path(path, code="credential_path_invalid")
    try:
        info = credential.lstat()
    except OSError:
        _fail("credential_identity_invalid")
    return CredentialIdentity.from_stat(info)


def verify_credential_identity(marker: RunMarker) -> CredentialIdentity:
    """Recheck the exact pinned credential identity without reading its value."""

    current = credential_lstat(marker.credential_path)
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
    "marker_paths",
    "new_marker",
    "new_run_id",
    "replace_marker",
    "validate_marker",
    "verify_credential_identity",
]
