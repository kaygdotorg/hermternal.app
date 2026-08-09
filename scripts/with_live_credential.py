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

import json
import os
import re
import sys
from pathlib import Path
from typing import Mapping, NoReturn, Sequence


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


def _proof_identity(value: object) -> live_run_marker.CredentialIdentity:
    try:
        identity = live_run_marker.CredentialIdentity.from_document(value)
    except live_run_marker.MarkerError:
        raise LiveProofCredentialError("proof_invalid") from None
    if not identity.generation:
        raise LiveProofCredentialError("proof_invalid")
    return identity


def _validate_launcher_proof(
    marker: live_run_marker.RunMarker,
    *,
    marker_path: Path,
    run_id: str | None,
    credential_file: str | Path | None,
    credential_identity: Mapping[str, object] | live_run_marker.CredentialIdentity | None,
) -> None:
    """Require the exact metadata freshly emitted by the launcher endpoint gate."""

    if run_id is None or credential_file is None or credential_identity is None:
        raise LiveProofCredentialError("proof_required")
    try:
        expected_marker = live_run_marker.canonical_path(marker_path)
        expected_credential = live_run_marker.canonical_path(credential_file, code="proof_invalid")
    except live_run_marker.MarkerError:
        raise LiveProofCredentialError("proof_invalid") from None
    if expected_marker != marker.marker_path or run_id != marker.run_id or expected_credential != marker.credential_path:
        raise LiveProofCredentialError("proof_mismatch")
    if isinstance(credential_identity, live_run_marker.CredentialIdentity):
        expected_identity = credential_identity
    else:
        expected_identity = _proof_identity(credential_identity)
    if expected_identity != marker.credential_identity:
        raise LiveProofCredentialError("proof_mismatch")


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
        if before_identity.file_identity() != marker.credential_identity.file_identity():
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
        if after_identity.file_identity() != before_identity.file_identity():
            raise LiveProofCredentialError("credential_identity_mismatch")
        if len(raw) > MAX_CREDENTIAL_BYTES:
            raise LiveProofCredentialError("credential_file_invalid")
        try:
            content_identity = live_run_marker.CredentialIdentity.from_stat_and_content(
                after, bytes(raw)
            )
        except live_run_marker.MarkerError:
            raise LiveProofCredentialError("credential_file_invalid") from None
        if content_identity != marker.credential_identity:
            raise LiveProofCredentialError("credential_identity_mismatch")
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


def read_credential_file(
    marker_path: Path,
    *,
    run_id: str | None = None,
    credential_file: str | Path | None = None,
    credential_identity: Mapping[str, object] | live_run_marker.CredentialIdentity | None = None,
) -> str:
    """Read one credential only after exact launcher proof is supplied."""

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
        _validate_launcher_proof(
            marker,
            marker_path=marker_path,
            run_id=run_id,
            credential_file=credential_file,
            credential_identity=credential_identity,
        )
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


def run_with_credential(
    marker_path: Path,
    *,
    run_id: str | None,
    credential_file: str | Path | None,
    credential_identity: Mapping[str, object] | live_run_marker.CredentialIdentity | None,
    command: Sequence[str],
) -> NoReturn:
    """Replace this process with a proof command and transient password env."""

    if not command:
        raise LiveProofCredentialError("command_missing")
    if os.environ.get(LIVE_RUNNER_DEBUG_ENV):
        raise LiveProofCredentialError("live_runner_debug_incompatible")
    password = read_credential_file(
        marker_path,
        run_id=run_id,
        credential_file=credential_file,
        credential_identity=credential_identity,
    )
    environment = os.environ.copy()
    environment["HERMES_TEST_PASSWORD"] = password
    try:
        os.execvpe(command[0], list(command), environment)
    except OSError:
        raise LiveProofCredentialError("live_proof_command_failed") from None
    raise AssertionError("os.execvpe returned")


def _parse_arguments(arguments: Sequence[str]) -> tuple[Path, str, str, Mapping[str, object], list[str]]:
    """Parse only the explicit proof-bearing handoff form."""

    try:
        delimiter = list(arguments).index("--")
    except ValueError:
        raise LiveProofCredentialError("proof_required") from None
    options = list(arguments[:delimiter])
    command = list(arguments[delimiter + 1 :])
    if not command or len(options) != 8:
        raise LiveProofCredentialError("proof_required")
    values: dict[str, str] = {}
    for index in range(0, len(options), 2):
        key, value = options[index : index + 2]
        if key not in {"--marker", "--run-id", "--credential-file", "--credential-identity"}:
            raise LiveProofCredentialError("proof_invalid")
        if key in values or not value:
            raise LiveProofCredentialError("proof_invalid")
        values[key] = value
    if set(values) != {"--marker", "--run-id", "--credential-file", "--credential-identity"}:
        raise LiveProofCredentialError("proof_required")
    try:
        identity = json.loads(values["--credential-identity"])
    except (TypeError, json.JSONDecodeError):
        raise LiveProofCredentialError("proof_invalid") from None
    if not isinstance(identity, dict):
        raise LiveProofCredentialError("proof_invalid")
    return (
        Path(values["--marker"]),
        values["--run-id"],
        values["--credential-file"],
        identity,
        command,
    )


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        marker_path, run_id, credential_file, credential_identity, command = _parse_arguments(arguments)
        run_with_credential(
            marker_path,
            run_id=run_id,
            credential_file=credential_file,
            credential_identity=credential_identity,
            command=command,
        )
    except LiveProofCredentialError as error:
        print(error.code, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
