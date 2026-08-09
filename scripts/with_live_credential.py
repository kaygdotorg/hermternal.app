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


def _marker(path: Path) -> live_run_marker.RunMarker:
    try:
        return live_run_marker.load_marker(path, selectable=True)
    except live_run_marker.MarkerError as error:
        raise LiveProofCredentialError(error.code) from None


def _credential_identity(info: os.stat_result) -> live_run_marker.CredentialIdentity:
    try:
        return live_run_marker.CredentialIdentity.from_stat(info)
    except live_run_marker.MarkerError as error:
        raise LiveProofCredentialError(error.code) from None


def _read_pinned_credential(marker: live_run_marker.RunMarker) -> bytes:
    """Read one exact credential inode after an immediate identity recheck."""

    try:
        live_run_marker.verify_credential_identity(marker)
    except live_run_marker.MarkerError as error:
        raise LiveProofCredentialError(error.code) from None

    try:
        descriptor = os.open(
            marker.credential_path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
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
        return bytes(raw)
    finally:
        os.close(descriptor)


def read_credential_file(marker_path: Path) -> str:
    """Read the marker-pinned credential without following or reselecting paths."""

    marker = _marker(marker_path)
    raw = _read_pinned_credential(marker)
    normalized = raw.rstrip(b"\r\n")
    if PASSWORD_PATTERN.fullmatch(normalized) is None:
        raise LiveProofCredentialError("credential_file_invalid")
    return normalized.decode("ascii")


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
