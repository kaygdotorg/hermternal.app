#!/usr/bin/env python3
"""Run a local live-proof command with a transient marker-bound credential.

The disposable launcher writes one ASCII password line: 48 lowercase
hexadecimal characters followed by a line ending. This helper receives the
exact caller-selected marker path, loads it without selecting a candidate, and
revalidates the pinned credential identity immediately before reading through a
non-following file descriptor. The password is never printed or written by this
helper; it exists only in the child process environment as
``HERMES_TEST_PASSWORD``. The child environment is rebuilt from an explicit
reviewed allowlist, so inherited passwords, preload hooks, proxy settings, and
unrelated secrets do not cross the credential boundary.
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Mapping, NoReturn, Sequence


if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
import live_run_marker


PASSWORD_PATTERN = re.compile(rb"[0-9a-f]{48}\Z")
MAX_CREDENTIAL_BYTES = 256
MAX_PROOF_BYTES = 4096
MAX_NUMERIC_DIGITS = 64
MAX_JSON_DEPTH = 32
_PROOF_OPTION_KEYS = (
    "--marker",
    "--run-id",
    "--credential-file",
    "--credential-identity",
)
MAX_PROOF_OPTIONS_BYTES = (
    2 * live_run_marker.MAX_PATH_BYTES
    + 64
    + MAX_PROOF_BYTES
    + sum(len(key.encode("utf-8")) for key in _PROOF_OPTION_KEYS)
)
LIVE_RUNNER_DEBUG_ENV = "PW_RUNNER_DEBUG"
LIVE_RUNNER_UI_DEBUG_ENV = "PWDEBUG"
LIVE_RUNNER_DEBUG_ENVS = (LIVE_RUNNER_DEBUG_ENV, LIVE_RUNNER_UI_DEBUG_ENV)
SAFE_CHILD_ENV_NAMES = (
    "PATH",
    "HERMES_LIVE_TARGET",
    "HERMES_TEST_USERNAME",
    "PLAYWRIGHT_LIVE_PORT",
    "HERMTERNAL_LIVE_RECONCILIATION",
    # Screenshot capture reads these proof-bound gates in the child process.
    "HERMTERNAL_LIVE_SCREENSHOT_CAPTURE",
    "HERMTERNAL_PAPER_PARITY_APPROVED",
    "HERMTERNAL_LIVE_SCREENSHOT_CLIENT_SHA",
    "HERMTERNAL_LIVE_SCREENSHOT_RETAIN",
    "HERMTERNAL_LIVE_SCREENSHOT_REVIEW",
    "HERMTERNAL_LIVE_SCREENSHOT_DESTINATION",
)

# The live proof accepts only the two reviewed command forms documented by the
# handoff contract. Bare names are resolved from this fixed list; ambient PATH
# lookup is never used. Homebrew's stable bin links are accepted only after
# their final canonical target and every parent directory pass the same trust
# checks as a direct system executable.
TRUSTED_EXECUTABLE_CANDIDATES = {
    "bun": (
        "/opt/homebrew/bin/bun",
        "/usr/local/bin/bun",
        "/usr/bin/bun",
        "/opt/local/bin/bun",
    ),
    "node": (
        "/opt/homebrew/bin/node",
        "/usr/local/bin/node",
        "/usr/bin/node",
        "/opt/local/bin/node",
    ),
}


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
        serialized = json.dumps(
            identity.document(),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        if len(serialized.encode("utf-8")) > MAX_PROOF_BYTES:
            raise LiveProofCredentialError("proof_invalid")
    except LiveProofCredentialError:
        raise
    except (
        live_run_marker.MarkerError,
        TypeError,
        ValueError,
        UnicodeEncodeError,
        RecursionError,
        MemoryError,
        OverflowError,
    ):
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
        if raw.endswith(b"\r\n"):
            normalized = raw[:-2]
        elif raw.endswith((b"\r", b"\n")):
            normalized = raw[:-1]
        else:
            normalized = raw
        # The framing contract is one password line: at most one terminal
        # ending, with no interior or repeated CR/LF bytes after removal.
        if b"\r" in normalized or b"\n" in normalized:
            raise LiveProofCredentialError("credential_file_invalid")
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


def _trusted_directory_chain(path: Path) -> None:
    """Require every fixed executable parent to be a private real directory."""

    if not path.is_absolute():
        raise LiveProofCredentialError("live_proof_command_invalid")
    current = Path(path.anchor)
    try:
        components = path.relative_to(current).parts
    except ValueError:
        raise LiveProofCredentialError("live_proof_command_invalid") from None
    current_uid = getattr(os, "getuid", lambda: None)()
    for component in components:
        current /= component
        try:
            info = current.lstat()
        except OSError:
            raise LiveProofCredentialError("live_proof_command_invalid") from None
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or (info.st_mode & 0o022) != 0
            or (current_uid is not None and info.st_uid not in {0, current_uid})
        ):
            raise LiveProofCredentialError("live_proof_command_invalid")


def _validate_trusted_executable(candidate: str) -> str:
    """Return a canonical fixed executable after ownership/mode checks."""

    path = Path(candidate)
    if not path.is_absolute() or str(path) != candidate:
        raise LiveProofCredentialError("live_proof_command_invalid")
    try:
        lexical = path.lstat()
        _trusted_directory_chain(path.parent)
        canonical = path.resolve(strict=True)
        _trusted_directory_chain(canonical.parent)
        target = canonical.lstat()
        current_uid = getattr(os, "getuid", lambda: None)()
        if (
            not stat.S_ISREG(target.st_mode)
            or (target.st_mode & 0o111) == 0
            or (target.st_mode & 0o022) != 0
            or (current_uid is not None and target.st_uid not in {0, current_uid})
            or canonical != canonical.resolve(strict=True)
        ):
            raise LiveProofCredentialError("live_proof_command_invalid")
        # A final stable bin link is acceptable, but its target is what execve
        # receives. The lexical entry itself must still be a file or symlink;
        # parent validation above prevents a writable link directory.
        if not (stat.S_ISREG(lexical.st_mode) or stat.S_ISLNK(lexical.st_mode)):
            raise LiveProofCredentialError("live_proof_command_invalid")
        if not os.access(canonical, os.X_OK):
            raise LiveProofCredentialError("live_proof_command_invalid")
    except LiveProofCredentialError:
        raise
    except (OSError, RuntimeError, ValueError):
        raise LiveProofCredentialError("live_proof_command_invalid") from None
    return str(canonical)


def _resolve_trusted_executable(command: str) -> str:
    """Resolve only a reviewed bare name or an exact fixed candidate path."""

    if type(command) is not str or not command:
        raise LiveProofCredentialError("live_proof_command_invalid")
    candidates = TRUSTED_EXECUTABLE_CANDIDATES.get(command)
    if candidates is None:
        candidates = tuple(
            candidate
            for entries in TRUSTED_EXECUTABLE_CANDIDATES.values()
            for candidate in entries
            if candidate == command
        )
    if not candidates:
        raise LiveProofCredentialError("live_proof_command_invalid")
    for candidate in candidates:
        try:
            return _validate_trusted_executable(candidate)
        except LiveProofCredentialError:
            continue
    raise LiveProofCredentialError("live_proof_command_invalid")


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
    # Both Playwright debug modes bypass the detached, redacted live-proof
    # boundary; reject them before marker access or child startup.
    if any(os.environ.get(name) for name in LIVE_RUNNER_DEBUG_ENVS):
        raise LiveProofCredentialError("live_runner_debug_incompatible")
    password = read_credential_file(
        marker_path,
        run_id=run_id,
        credential_file=credential_file,
        credential_identity=credential_identity,
    )
    executable = _resolve_trusted_executable(command[0])
    # Do not inherit ambient credentials, preload hooks, proxy settings, or
    # unrelated secrets. The validated password is the only newly injected key.
    environment = {
        name: os.environ[name]
        for name in SAFE_CHILD_ENV_NAMES
        if name in os.environ
    }
    environment["HERMES_TEST_PASSWORD"] = password
    try:
        os.execve(executable, [executable, *list(command[1:])], environment)
    except OSError:
        raise LiveProofCredentialError("live_proof_command_failed") from None
    raise AssertionError("os.execve returned")


def _proof_json(raw: str) -> object:
    """Decode one bounded, duplicate-free proof document."""

    if type(raw) is not str:
        raise LiveProofCredentialError("proof_invalid")
    try:
        if len(raw.encode("utf-8")) > MAX_PROOF_BYTES:
            raise LiveProofCredentialError("proof_invalid")
    except UnicodeEncodeError:
        raise LiveProofCredentialError("proof_invalid") from None

    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise LiveProofCredentialError("proof_invalid")
            document[key] = value
        return document

    def reject_constant(value: str) -> None:
        del value
        raise LiveProofCredentialError("proof_invalid")

    def bounded_int(value: str) -> int:
        if len(value.lstrip("-")) > MAX_NUMERIC_DIGITS:
            raise LiveProofCredentialError("proof_invalid")
        try:
            return int(value)
        except (ValueError, OverflowError):
            raise LiveProofCredentialError("proof_invalid") from None

    def reject_float(value: str) -> None:
        del value
        raise LiveProofCredentialError("proof_invalid")

    try:
        depth = 0
        in_string = False
        escaped = False
        for character in raw:
            if in_string:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    in_string = False
                continue
            if character == '"':
                in_string = True
            elif character in "[{":
                depth += 1
                if depth > MAX_JSON_DEPTH:
                    raise LiveProofCredentialError("proof_invalid")
            elif character in "]}":
                depth -= 1
                if depth < 0:
                    raise LiveProofCredentialError("proof_invalid")
        return json.loads(
            raw,
            object_pairs_hook=reject_duplicate,
            parse_constant=reject_constant,
            parse_int=bounded_int,
            parse_float=reject_float,
        )
    except LiveProofCredentialError:
        raise
    except (TypeError, json.JSONDecodeError, ValueError, RecursionError, MemoryError):
        raise LiveProofCredentialError("proof_invalid") from None


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
    total_bytes = 0
    for index in range(0, len(options), 2):
        key, value = options[index : index + 2]
        if type(key) is not str or type(value) is not str:
            raise LiveProofCredentialError("proof_invalid")
        if key not in set(_PROOF_OPTION_KEYS):
            raise LiveProofCredentialError("proof_invalid")
        if key in values or not value:
            raise LiveProofCredentialError("proof_invalid")
        try:
            key_bytes = len(key.encode("utf-8"))
            value_bytes = len(value.encode("utf-8"))
        except UnicodeEncodeError:
            raise LiveProofCredentialError("proof_invalid") from None
        if value_bytes > MAX_PROOF_BYTES:
            raise LiveProofCredentialError("proof_invalid")
        total_bytes += key_bytes + value_bytes
        if total_bytes > MAX_PROOF_OPTIONS_BYTES:
            raise LiveProofCredentialError("proof_invalid")
        values[key] = value
    if set(values) != {"--marker", "--run-id", "--credential-file", "--credential-identity"}:
        raise LiveProofCredentialError("proof_required")
    identity = _proof_json(values["--credential-identity"])
    if not isinstance(identity, dict):
        raise LiveProofCredentialError("proof_invalid")
    _proof_identity(identity)
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
