#!/usr/bin/env python3
"""Run a local live-proof command with a transient credential-file value.

The disposable launcher writes one ASCII password line: 48 lowercase hexadecimal
characters followed by a line ending. This helper normalizes only terminal CR/LF
bytes, validates that exact shape, and replaces itself with the requested child
process. The password is never printed or written by this helper; it exists only
in the child process environment as ``HERMES_TEST_PASSWORD``.
"""

from __future__ import annotations

import os
import re
import stat
import sys
from pathlib import Path
from typing import NoReturn, Sequence


PASSWORD_PATTERN = re.compile(rb"[0-9a-f]{48}\Z")
MAX_CREDENTIAL_BYTES = 256


class LiveProofCredentialError(Exception):
    """Stable local failure code that never includes credential contents."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def read_credential_file(path: Path) -> str:
    """Read and validate one launcher-owned credential file without rewriting it."""

    try:
        info = path.lstat()
    except OSError:
        raise LiveProofCredentialError("credential_file_invalid") from None
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise LiveProofCredentialError("credential_file_invalid")

    try:
        raw = path.read_bytes()
    except OSError:
        raise LiveProofCredentialError("credential_file_invalid") from None
    if len(raw) > MAX_CREDENTIAL_BYTES:
        raise LiveProofCredentialError("credential_file_invalid")

    normalized = raw.rstrip(b"\r\n")
    if PASSWORD_PATTERN.fullmatch(normalized) is None:
        raise LiveProofCredentialError("credential_file_invalid")
    return normalized.decode("ascii")


def run_with_credential(path: Path, command: Sequence[str]) -> NoReturn:
    """Replace this process with the proof command and a transient password env."""

    if not command:
        raise LiveProofCredentialError("command_missing")
    password = read_credential_file(path)
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
