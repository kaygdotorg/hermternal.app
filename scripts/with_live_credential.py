#!/usr/bin/env python3
"""Run a local live-proof command with a transient marker-bound credential.

The disposable launcher writes one ASCII password line: 48 lowercase
hexadecimal characters followed by a line ending. This helper receives the
exact caller-selected marker path, loads it without selecting a candidate, and
revalidates the pinned credential identity immediately before reading through a
non-following file descriptor. The password is never printed or written by this
helper; it exists only in the child process environment as
``HERMES_TEST_PASSWORD``.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import NoReturn, Sequence


if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
import live_run_marker


PASSWORD_PATTERN = re.compile(rb"[0-9a-f]{48}\Z")
MAX_CREDENTIAL_BYTES = 256
LIVE_RUNNER_DEBUG_ENV = "PW_RUNNER_DEBUG"


class LiveProofCredentialError(Exception):
    """Stable local failure code that never includes credential contents."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _marker_with_identity(
    path: Path,
    *,
    parent_fd: int | None = None,
) -> tuple[live_run_marker.RunMarker, live_run_marker.MarkerFileIdentity]:
    try:
        return live_run_marker.load_marker_with_identity(path, selectable=True, parent_fd=parent_fd)
    except live_run_marker.MarkerError as error:
        raise LiveProofCredentialError(error.code) from None


def _marker(path: Path, *, parent_fd: int | None = None) -> live_run_marker.RunMarker:
    return _marker_with_identity(path, parent_fd=parent_fd)[0]


def _verify_marker_identity(
    marker: live_run_marker.RunMarker,
    expected: live_run_marker.MarkerFileIdentity,
    *,
    parent_fd: int,
) -> None:
    """Recheck the exact marker document and inode before and after use."""

    try:
        current, current_identity = live_run_marker.load_marker_with_identity(
            marker.marker_path,
            selectable=True,
            parent_fd=parent_fd,
        )
    except live_run_marker.MarkerError as error:
        raise LiveProofCredentialError(error.code) from None
    if current_identity != expected or current != marker:
        raise LiveProofCredentialError("marker_identity_mismatch")


def _credential_identity(info: os.stat_result) -> live_run_marker.CredentialIdentity:
    try:
        return live_run_marker.CredentialIdentity.from_stat(info)
    except live_run_marker.MarkerError as error:
        raise LiveProofCredentialError(error.code) from None


def _read_pinned_credential(
    marker: live_run_marker.RunMarker,
    *,
    marker_identity: live_run_marker.MarkerFileIdentity | None = None,
    parent_fd: int | None = None,
) -> bytes:
    """Read one exact credential inode after immediate marker and identity checks."""

    if marker_identity is not None:
        if parent_fd is None:
            raise LiveProofCredentialError("marker_identity_mismatch")
        _verify_marker_identity(marker, marker_identity, parent_fd=parent_fd)
    try:
        live_run_marker.verify_credential_identity(marker, parent_fd=parent_fd)
    except live_run_marker.MarkerError as error:
        raise LiveProofCredentialError(error.code) from None

    try:
        descriptor = os.open(
            marker.credential_path.name if parent_fd is not None else marker.credential_path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
    except OSError:
        raise LiveProofCredentialError("credential_file_invalid") from None

    try:
        try:
            before = os.fstat(descriptor)
            before_identity = _credential_identity(before)
        except OSError:
            raise LiveProofCredentialError("credential_file_invalid") from None
        if before_identity != marker.credential_identity:
            raise LiveProofCredentialError("credential_identity_mismatch")

        raw = bytearray()
        try:
            while len(raw) <= MAX_CREDENTIAL_BYTES:
                chunk = os.read(descriptor, MAX_CREDENTIAL_BYTES + 1 - len(raw))
                if not chunk:
                    break
                raw.extend(chunk)
            after = os.fstat(descriptor)
        except OSError:
            raise LiveProofCredentialError("credential_file_invalid") from None
        try:
            after_identity = _credential_identity(after)
        except LiveProofCredentialError:
            raise
        if after_identity != before_identity or after_identity != marker.credential_identity:
            raise LiveProofCredentialError("credential_identity_mismatch")
        if len(raw) > MAX_CREDENTIAL_BYTES:
            raise LiveProofCredentialError("credential_file_invalid")
        if marker_identity is not None:
            if parent_fd is None:
                raise LiveProofCredentialError("marker_identity_mismatch")
            _verify_marker_identity(marker, marker_identity, parent_fd=parent_fd)
        return bytes(raw)
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def read_credential_file(marker_path: Path) -> str:
    """Read the marker-pinned credential through one parent-directory lease."""

    parent_fd = -1
    expected: live_run_marker.ParentIdentity | None = None
    expected_token = None
    try:
        parent_fd = live_run_marker.open_runs_parent(marker_path, code="marker_path_invalid")
        expected = live_run_marker.parent_identity(parent_fd, code="marker_path_invalid")
        expected_token = live_run_marker._set_expected_parent_identity(expected)
        live_run_marker.revalidate_runs_parent_path(
            marker_path,
            parent_fd,
            expected=expected,
            code="runs_dir_invalid",
        )
        marker, marker_identity = _marker_with_identity(marker_path, parent_fd=parent_fd)
        raw = _read_pinned_credential(
            marker,
            marker_identity=marker_identity,
            parent_fd=parent_fd,
        )
        live_run_marker.revalidate_runs_parent_path(
            marker_path,
            parent_fd,
            expected=expected,
            code="runs_dir_invalid",
        )
        _verify_marker_identity(marker, marker_identity, parent_fd=parent_fd)
        normalized = raw.rstrip(b"\r\n")
        if PASSWORD_PATTERN.fullmatch(normalized) is None:
            raise LiveProofCredentialError("credential_file_invalid")
        return normalized.decode("ascii")
    except live_run_marker.MarkerError as error:
        raise LiveProofCredentialError(error.code) from None
    finally:
        if expected_token is not None:
            live_run_marker._reset_expected_parent_identity(expected_token)
        if parent_fd >= 0:
            try:
                os.close(parent_fd)
            except OSError:
                pass


def run_with_credential(marker_path: Path, command: Sequence[str]) -> NoReturn:
    """Replace this process with the proof command and a transient password env."""

    if not command:
        raise LiveProofCredentialError("command_missing")
    if os.environ.get(LIVE_RUNNER_DEBUG_ENV):
        raise LiveProofCredentialError("live_runner_debug_incompatible")
    password = read_credential_file(marker_path)
    environment = os.environ.copy()
    environment["HERMES_TEST_PASSWORD"] = password
    try:
        os.execvpe(command[0], list(command), environment)
    except OSError:
        raise LiveProofCredentialError("live_proof_command_failed") from None
    raise AssertionError("os.execvpe returned")


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) < 3 or arguments[1] != "--" or not arguments[2]:
        print("usage_invalid", file=sys.stderr)
        return 1

    try:
        run_with_credential(Path(arguments[0]), arguments[2:])
    except LiveProofCredentialError as error:
        print(error.code, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
