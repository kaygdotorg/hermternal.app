#!/usr/bin/env python3
"""Load the frozen Git reviewer and install closed configuration authority."""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import sys
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence


BASE = Path(__file__).resolve().parents[1]
FROZEN_REVIEWER = (
    BASE / "task409-execution-preflight" / "review_task464_git_v3.py"
)
FROZEN_REVIEWER_SHA256 = (
    "dc4e95cc055947673702048222fe963cbce1ac9673e35d072ecd2214e252ab7c"
)
TRUSTED_GIT = Path("/usr/bin/git")
MAX_REVIEWER_BYTES = 2 * 1024 * 1024
MAX_GIT_BYTES = 16 * 1024 * 1024

# Git init and the guarded replay create only these records. Exact bytes close
# Git's flexible config grammar before the first Git subprocess can parse it.
CANONICAL_CONFIG = (
    b"[core]\n"
    b"\trepositoryformatversion = 0\n"
    b"\tfilemode = true\n"
    b"\tbare = false\n"
    b"\tlogallrefupdates = true\n"
    b"\thooksPath = /dev/null\n"
    b"[protocol]\n"
    b"\tallow = never\n"
)
CANONICAL_RECORDS = (
    ("core.repositoryformatversion", "0"),
    ("core.filemode", "true"),
    ("core.bare", "false"),
    ("core.logallrefupdates", "true"),
    ("core.hookspath", "/dev/null"),
    ("protocol.allow", "never"),
)
SAFE_ENV = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/dev/null",
    "LANG": "C",
    "LC_ALL": "C",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_ATTR_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_NO_LAZY_FETCH": "1",
}
GIT_PREFIX = (
    "/usr/bin/git",
    "--no-replace-objects",
    "--no-lazy-fetch",
    "--no-optional-locks",
)
GIT_CONFIG_OVERRIDES = (
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "protocol.allow=never",
)


@dataclass(frozen=True)
class ExecutableBinding:
    """Identity and content binding for the one permitted Git executable."""

    identity: tuple[int, int, int, int, int, int, int, int]
    sha256: str


def _identity(st: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        int(st.st_dev),
        int(st.st_ino),
        int(st.st_uid),
        int(stat.S_IMODE(st.st_mode)),
        int(st.st_size),
        int(st.st_nlink),
        int(st.st_mtime_ns),
        int(st.st_ctime_ns),
    )


def _read_bound(path: Path, label: str, limit: int) -> tuple[bytes, tuple[int, ...]]:
    """Read one canonical, single-link file through one no-follow descriptor."""
    if not path.is_absolute() or os.path.realpath(path) != os.fspath(path):
        raise RuntimeError(f"{label} path is not canonical and absolute")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(os.fspath(path), flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError(f"{label} is not a single-link regular file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(131072, limit - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise RuntimeError(f"{label} exceeds its byte limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    final = os.stat(path, follow_symlinks=False)
    if _identity(before) != _identity(after) or _identity(before) != _identity(final):
        raise RuntimeError(f"{label} identity changed during read")
    raw = b"".join(chunks)
    if len(raw) != before.st_size:
        raise RuntimeError(f"{label} byte count differs from metadata")
    return raw, _identity(before)


def _read_frozen_reviewer() -> bytes:
    raw, _ = _read_bound(FROZEN_REVIEWER, "frozen reviewer", MAX_REVIEWER_BYTES)
    if hashlib.sha256(raw).hexdigest() != FROZEN_REVIEWER_SHA256:
        raise RuntimeError("frozen reviewer SHA-256 differs")
    return raw


def _load_verified_reviewer(raw: bytes):
    """Execute only the reviewer bytes returned by the verified read."""
    if not isinstance(raw, bytes):
        raise RuntimeError("verified reviewer content is not bytes")
    module = types.ModuleType("candidate5_frozen_git_reviewer_for_successor")
    module.__file__ = os.fspath(FROZEN_REVIEWER)
    module.__package__ = ""
    module.__loader__ = None
    module.__spec__ = None
    sys.modules[module.__name__] = module
    code = compile(raw, module.__file__, "exec", dont_inherit=True)
    exec(code, module.__dict__)
    return module


def _bind_trusted_git() -> ExecutableBinding:
    if os.fspath(TRUSTED_GIT) != "/usr/bin/git":
        raise RuntimeError("trusted Git path differs")
    raw, identity = _read_bound(TRUSTED_GIT, "trusted Git", MAX_GIT_BYTES)
    if identity[2] != 0 or identity[3] & 0o022 or not identity[3] & 0o111:
        raise RuntimeError("trusted Git ownership or mode is unsafe")
    return ExecutableBinding(identity=identity, sha256=hashlib.sha256(raw).hexdigest())


def _assert_git_stable(binding: ExecutableBinding) -> None:
    raw, identity = _read_bound(TRUSTED_GIT, "trusted Git", MAX_GIT_BYTES)
    if identity != binding.identity or hashlib.sha256(raw).hexdigest() != binding.sha256:
        raise RuntimeError("trusted Git identity or bytes changed")


def validate_canonical_config(raw: bytes, label: str = "Git config") -> None:
    """Accept only the reviewed canonical Git-init serialization."""
    if not isinstance(raw, bytes) or raw != CANONICAL_CONFIG:
        raise ValueError(f"{label} is not the exact canonical six-record config")


def git_argv(root: Path, args: Sequence[str]) -> list[str]:
    """Build the one permitted Git command prefix without caller options."""
    root = Path(root)
    if not root.is_absolute() or os.path.realpath(root) != os.fspath(root):
        raise ValueError("Git repository root is not canonical and absolute")
    if not isinstance(args, (list, tuple)) or any(
        not isinstance(value, str) or not value or "\x00" in value for value in args
    ):
        raise ValueError("Git arguments are not a closed string sequence")
    return [*GIT_PREFIX, "-C", os.fspath(root), *GIT_CONFIG_OVERRIDES, *args]


def _expected_semantic_config() -> bytes:
    origin = b"file:.git/config\x00"
    return b"".join(
        origin + key.encode("ascii") + b"\n" + value.encode("ascii") + b"\x00"
        for key, value in CANONICAL_RECORDS
    )


def install_successor():
    """Install Git-config authority in a verified frozen reviewer module."""
    reviewer = _load_verified_reviewer(_read_frozen_reviewer())
    binding = _bind_trusted_git()
    original_run_process = reviewer._run_process
    original_guard_init = reviewer.RepoGuard.__init__

    def checked_git_argv(root: Path, args: Sequence[str]) -> list[str]:
        try:
            return git_argv(root, args)
        except ValueError as exc:
            reviewer.reject(str(exc))
        raise AssertionError("unreachable")

    def checked_run_process(
        argv: Sequence[str],
        *,
        input_bytes: Optional[bytes] = None,
        timeout: int,
        cwd: str = "/",
    ) -> subprocess.CompletedProcess[bytes]:
        # All subprocesses in the frozen reviewer are Git. Reject any future
        # executable, prefix, environment, or working-directory expansion.
        if not isinstance(argv, (list, tuple)) or tuple(argv[:4]) != GIT_PREFIX:
            reviewer.reject("Git subprocess argv prefix differs")
        if (
            len(argv) < 13
            or argv[4] != "-C"
            or not isinstance(argv[5], str)
            or tuple(argv[6:12]) != GIT_CONFIG_OVERRIDES
            or any(not isinstance(value, str) or not value or "\x00" in value for value in argv[12:])
        ):
            reviewer.reject("Git subprocess argv contract differs")
        root = Path(argv[5])
        if not root.is_absolute() or os.path.realpath(root) != os.fspath(root):
            reviewer.reject("Git subprocess root differs")
        if cwd != "/" or reviewer.SAFE_ENV != SAFE_ENV:
            reviewer.reject("Git subprocess environment or cwd differs")
        _assert_git_stable(binding)
        result = original_run_process(
            argv, input_bytes=input_bytes, timeout=timeout, cwd=cwd
        )
        _assert_git_stable(binding)
        return result

    def guarded_init(self, identity) -> None:
        original_guard_init(self, identity)
        self.assert_stable()
        result = checked_run_process(
            checked_git_argv(
                identity.root,
                ["config", "--local", "--show-origin", "--null", "--list"],
            ),
            timeout=reviewer.GIT_TIMEOUT,
        )
        self.assert_stable()
        reviewer.require_git_success(result, f"{identity.label} semantic config")
        if result.stdout != _expected_semantic_config():
            reviewer.reject(f"{identity.label} semantic config records differ")

    def closed_config(raw: bytes, label: str) -> None:
        try:
            validate_canonical_config(raw, label)
        except ValueError as exc:
            reviewer.reject(str(exc))

    reviewer.GIT = "/usr/bin/git"
    reviewer.SAFE_ENV = dict(SAFE_ENV)
    reviewer._git_argv = checked_git_argv
    reviewer._run_process = checked_run_process
    reviewer._reject_config_commands = closed_config
    reviewer.RepoGuard.__init__ = guarded_init
    reviewer.CANDIDATE5_GIT_BINDING = binding
    reviewer.CANDIDATE5_CANONICAL_CONFIG = CANONICAL_CONFIG
    return reviewer


if __name__ == "__main__":
    install_successor()
    print("candidate-five Git-config successor loaded")
