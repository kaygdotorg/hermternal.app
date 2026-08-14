#!/usr/bin/env python3
"""Propagate the authenticated v11 adapter through the v9 failure path."""
from __future__ import annotations

import hashlib
import os
import stat
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
V9_PATH = HERE / "linux_replay_failure_v9.py"
V9_SHA256 = "edc4108d1efa0aa1f154e0fd162ce4cd61fa01aeded7bd0333cc28443cc69e47"
PHASE_A_V11_PATH = HERE / "linux_phase_a_v11.py"
PHASE_A_V11_SHA256 = "fde754792e6c2c73df424ffabb5a73c92ca25156ceb76a87e40348b859facc6d"
SCHEMA = "hermternal.issue-397.replay-failure.v10"
DIRECTORY_NAME = "hermternal-issue397-replay-failure-v10"


def _stable_bytes(path: Path, digest: str, label: str) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError(f"{label} is not a single-link regular file")
        raw = os.read(descriptor, before.st_size)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = os.lstat(path)
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode,
        value.st_size, value.st_nlink, value.st_mtime_ns, value.st_ctime_ns
    )
    if identity(before) != identity(after) or identity(before) != identity(current):
        raise RuntimeError(f"{label} changed during read")
    if hashlib.sha256(raw).hexdigest() != digest:
        raise RuntimeError(f"{label} SHA-256 differs")
    return raw


def _load_v9() -> types.ModuleType:
    """Use authenticated v9 bytes with only the v11 Phase binding."""
    raw = _stable_bytes(V9_PATH, V9_SHA256, "failure v9")
    replacements = (
        (b"linux_phase_a_v10.py", b"linux_phase_a_v11.py"),
        (b"15e1492607fcb43f14cd290eef9e0e3df6d4b4a19e5b4bbf278b69647853461b", PHASE_A_V11_SHA256.encode()),
        (b"hermternal.issue-397.replay-failure.v9", SCHEMA.encode()),
        (b"hermternal-issue397-replay-failure-v9", DIRECTORY_NAME.encode()),
    )
    for old, new in replacements:
        expected_count = 2 if old == b"linux_phase_a_v10.py" else 1
        if raw.count(old) != expected_count:
            raise RuntimeError("failure v10 successor transform differs")
        raw = raw.replace(old, new)
    module = types.ModuleType("issue397_linux_replay_failure_v10_base")
    module.__file__ = os.fspath(Path(__file__).resolve())
    sys.modules[module.__name__] = module
    exec(compile(raw, os.fspath(V9_PATH), "exec", dont_inherit=True), module.__dict__)
    module.SCHEMA = SCHEMA
    module.DIRECTORY_NAME = DIRECTORY_NAME
    return module


def load_approved_wrapper(expected_anchor_sha256: str):
    return _load_v9().load_approved_wrapper(expected_anchor_sha256)


def __getattr__(name: str):
    return getattr(_load_v9(), name)
