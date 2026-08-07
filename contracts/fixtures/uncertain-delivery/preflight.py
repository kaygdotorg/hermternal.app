"""Run the reviewed validator only after a trusted filesystem preflight.

This module is supplied to an isolated Python process from the externally
expected Git commit. It does not import the checkout's validator until its
canonical path, repository metadata, fixture entries, and exact Git-tree
bytes have all passed. The current ``preflight.py`` file is also checked by
that process, so a copied or symlinked launcher cannot become a trust root.
"""

from __future__ import annotations

import os
import pathlib
import re
import selectors
import signal
import stat
import subprocess
import sys
import time


ERROR_LINE = '{"error":{"code":"contract","message":"uncertain delivery fixture rejected"}}\n'
EXPECTED_COMMIT_ENV = "HERMTERNAL_C06_EXPECTED_COMMIT"
FIXTURE_RELATIVE = pathlib.Path("contracts/fixtures/uncertain-delivery")
VALIDATOR_RELATIVE = FIXTURE_RELATIVE / "validate.py"
TEST_RELATIVE = FIXTURE_RELATIVE / "test_validate.py"
TRUSTED_TARGETS = frozenset((VALIDATOR_RELATIVE, TEST_RELATIVE))
CHAT_RELATIVE = pathlib.Path("contracts/state-models/chat.md")
FIXTURE_NAMES = frozenset(
    (
        "README.md",
        "cases.json",
        "preflight.py",
        "test_validate.py",
        "validate.py",
        "validation-baseline.json",
    )
)
CANONICAL_RELATIVE = (
    FIXTURE_RELATIVE / "README.md",
    FIXTURE_RELATIVE / "cases.json",
    FIXTURE_RELATIVE / "preflight.py",
    FIXTURE_RELATIVE / "test_validate.py",
    FIXTURE_RELATIVE / "validate.py",
    FIXTURE_RELATIVE / "validation-baseline.json",
    CHAT_RELATIVE,
)
MAX_FILE_BYTES = 512 * 1024
MAX_GIT_OUTPUT_BYTES = MAX_FILE_BYTES + 1024
TRUSTED_GIT_EXECUTABLE = pathlib.Path("/usr/bin/git")
HEX40 = re.compile(r"^[0-9a-f]{40}$")


class PreflightError(Exception):
    """An intentionally bounded pre-execution failure."""


def _fail() -> None:
    raise PreflightError


def _plain_path(path: pathlib.Path) -> bool:
    try:
        return path.is_absolute() and not path.is_symlink() and path.resolve() == path
    except (OSError, RuntimeError, ValueError):
        return False


def _regular_file(path: pathlib.Path, limit: int) -> bytes:
    try:
        if path.is_symlink():
            _fail()
        descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except (OSError, ValueError):
        _fail()
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            _fail()
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            value = stream.read(limit + 1)
        if len(value) > limit:
            _fail()
        return value
    except PreflightError:
        raise
    except (OSError, ValueError):
        _fail()
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _git_env() -> dict[str, str]:
    """Remove inherited Git indirection before reading the reviewed blob."""
    environment = os.environ.copy()
    for name in list(environment):
        if name.startswith("GIT_"):
            environment.pop(name, None)
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_COUNT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
        }
    )
    return environment


def _kill(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        pass
    try:
        process.kill()
    except (OSError, ProcessLookupError):
        pass
    try:
        process.wait(timeout=1)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _git(root: pathlib.Path, arguments: list[str], limit: int) -> bytes:
    """Read fixed-Git stdout incrementally so the limit is a hard bound."""
    if limit <= 0:
        _fail()
    try:
        if not _plain_path(TRUSTED_GIT_EXECUTABLE):
            _fail()
        metadata = TRUSTED_GIT_EXECUTABLE.stat()
        if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111:
            _fail()
        process = subprocess.Popen(
            [
                str(TRUSTED_GIT_EXECUTABLE),
                "--no-replace-objects",
                "--no-lazy-fetch",
                "-C",
                str(root),
                *arguments,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_git_env(),
            start_new_session=True,
        )
    except (OSError, ValueError):
        _fail()

    selector = selectors.DefaultSelector()
    output = bytearray()
    try:
        if process.stdout is None:
            _kill(process)
            _fail()
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + 2
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill(process)
                _fail()
            events = selector.select(remaining)
            if not events:
                continue
            for key, _ in events:
                try:
                    # Ask the kernel for at most the unfilled capacity plus one
                    # rejection byte. The process never retains a full read chunk
                    # beyond the declared bound.
                    chunk = os.read(key.fileobj.fileno(), min(8192, limit - len(output) + 1))
                except OSError:
                    _kill(process)
                    _fail()
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output.extend(chunk)
                if len(output) > limit:
                    _kill(process)
                    _fail()
        try:
            returncode = process.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            _kill(process)
            _fail()
        if returncode != 0:
            _fail()
        return bytes(output)
    finally:
        selector.close()
        if process.stdout is not None:
            process.stdout.close()


def _reject_repository_metadata(root: pathlib.Path) -> None:
    marker = root / ".git"
    try:
        if marker.is_symlink():
            _fail()
        if marker.is_dir():
            git_dir = marker.resolve()
            common_dir = git_dir
            if (git_dir / "commondir").exists() or (git_dir / "commondir").is_symlink():
                _fail()
        elif marker.is_file():
            raw = _regular_file(marker, 4096).decode("ascii")
            lines = raw.splitlines()
            if len(lines) != 1 or not lines[0].startswith("gitdir:"):
                _fail()
            git_dir = pathlib.Path(lines[0][7:].strip())
            if not git_dir.is_absolute():
                git_dir = root / git_dir
            git_dir = git_dir.resolve()
            common_dir = (git_dir.parent.parent).resolve()
            if (
                not git_dir.is_dir()
                or git_dir.parent != common_dir / "worktrees"
                or common_dir.name != ".git"
                or not root.resolve().is_relative_to(common_dir.parent.resolve())
            ):
                _fail()
            commondir = git_dir / "commondir"
            if commondir.is_symlink() or not commondir.is_file():
                _fail()
            if (git_dir / _regular_file(commondir, 4096).decode("ascii").strip()).resolve() != common_dir:
                _fail()
            linked_marker = git_dir / "gitdir"
            if linked_marker.is_symlink() or not linked_marker.is_file():
                _fail()
            if pathlib.Path(_regular_file(linked_marker, 4096).decode("ascii").strip()).resolve() != marker.resolve():
                _fail()
        else:
            _fail()
        if not common_dir.is_dir() or common_dir.is_symlink():
            _fail()
        for metadata_dir in {git_dir, common_dir}:
            for relative in (
                pathlib.Path("HEAD"),
                pathlib.Path("config"),
                pathlib.Path("index"),
                pathlib.Path("packed-refs"),
                pathlib.Path("objects"),
                pathlib.Path("objects/info"),
                pathlib.Path("refs"),
                pathlib.Path("info"),
            ):
                if (metadata_dir / relative).is_symlink():
                    _fail()
            for relative in (
                pathlib.Path("objects/info/alternates"),
                pathlib.Path("objects/info/http-alternates"),
                pathlib.Path("info/grafts"),
                pathlib.Path("shallow"),
            ):
                path = metadata_dir / relative
                if path.exists() or path.is_symlink():
                    _fail()
    except (OSError, RuntimeError, ValueError, UnicodeError):
        _fail()


def _target_path(root: pathlib.Path) -> tuple[pathlib.Path, list[str]]:
    try:
        if len(sys.argv) < 2:
            _fail()
        target = pathlib.Path(sys.argv[1])
        if not target.is_absolute():
            target = root / target
        relative = target.relative_to(root)
        if relative not in TRUSTED_TARGETS or not _plain_path(target):
            _fail()
        fixture = root / FIXTURE_RELATIVE
        if not _plain_path(fixture):
            _fail()
        entries = tuple(fixture.iterdir())
        if {entry.name for entry in entries} != FIXTURE_NAMES:
            _fail()
        for entry in entries:
            if not _plain_path(entry) or not entry.is_file():
                _fail()
        for relative in CANONICAL_RELATIVE:
            if not _plain_path(root / relative):
                _fail()
        pwd = os.environ.get("PWD")
        if pwd:
            lexical = pathlib.Path(pwd)
            if not lexical.is_absolute() or not _plain_path(lexical) or lexical != root:
                _fail()
        return target, list(sys.argv[2:])
    except (OSError, RuntimeError, ValueError):
        _fail()


def _expected_commit() -> str:
    value = os.environ.get(EXPECTED_COMMIT_ENV)
    if value is None or HEX40.fullmatch(value) is None:
        _fail()
    return value


def _blob(root: pathlib.Path, expected: str, relative: pathlib.Path) -> bytes:
    return _git(root, ["cat-file", "blob", f"{expected}:{relative.as_posix()}"], MAX_GIT_OUTPUT_BYTES)


def _collect() -> tuple[pathlib.Path, list[str], bytes, bytes]:
    try:
        root = pathlib.Path.cwd()
        if not _plain_path(root):
            _fail()
        target, arguments = _target_path(root)
        _reject_repository_metadata(root)
        expected = _expected_commit()
        revision = _git(root, ["rev-parse", "--verify", f"{expected}^{{commit}}"], 128).decode("ascii").strip()
        if revision != expected:
            _fail()
        for relative in CANONICAL_RELATIVE:
            expected_bytes = _blob(root, expected, relative)
            if _regular_file(root / relative, MAX_FILE_BYTES) != expected_bytes:
                _fail()
        validator_source = _blob(root, expected, VALIDATOR_RELATIVE)
        target_source = validator_source if target.relative_to(root) == VALIDATOR_RELATIVE else _blob(root, expected, TEST_RELATIVE)
        return target, arguments, validator_source, target_source
    except PreflightError:
        raise
    except (OSError, UnicodeError, RuntimeError, ValueError):
        _fail()
    raise PreflightError


try:
    _target, _arguments, _validator_source, _target_source = _collect()
    sys.argv = [str(_target), *_arguments]
    if _target.relative_to(pathlib.Path.cwd()) == TEST_RELATIVE:
        import types

        # The test module imports only this verified in-memory validator. No
        # checkout-owned Python module is imported before every tree byte binds.
        _validator_module = types.ModuleType("validate")
        _validator_module.__file__ = str(pathlib.Path.cwd() / VALIDATOR_RELATIVE)
        _validator_module.__package__ = None
        _validator_module.__cached__ = None
        sys.modules["validate"] = _validator_module
        exec(
            compile(_validator_source, _validator_module.__file__, "exec", optimize=sys.flags.optimize),
            _validator_module.__dict__,
            _validator_module.__dict__,
        )
    import types

    _main_module = types.ModuleType("__main__")
    _main_module.__file__ = str(_target)
    _main_module.__package__ = None
    _main_module.__cached__ = None
    sys.modules["__main__"] = _main_module
    exec(
        compile(_target_source, str(_target), "exec", optimize=sys.flags.optimize),
        _main_module.__dict__,
        _main_module.__dict__,
    )
except SystemExit:
    # Validator and unittest exits already own their output. Preserve them
    # without adding a second diagnostic line.
    raise
except BaseException:
    sys.stderr.write(ERROR_LINE)
    raise SystemExit(1)
