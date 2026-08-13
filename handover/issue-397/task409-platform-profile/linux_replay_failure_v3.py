#!/usr/bin/env python3
"""Bind early failure evidence to corrected Phase A v5 authority.

Failure-v2 and its durable evidence stay frozen. This successor changes only
the Phase A adapter pin, failure schema, and profile-derived v3 directory.
"""
from __future__ import annotations

import hashlib
import os
import stat
import sys
import types
from pathlib import Path

import linux_phase_a_v5

HERE = Path(__file__).resolve().parent
V2_PATH = HERE / "linux_replay_failure_v2.py"
V2_SHA256 = "b364a44e487d8be347e7151aff662c737f0a823d00f74194013617cee60dbe17"
PHASE_A_V5_PATH = HERE / "linux_phase_a_v5.py"
PHASE_A_V5_SHA256 = "755fa35860f6991a35a0eed0d63b54cb59500e2e799da811f166d2ccfde76d54"
SCHEMA = "hermternal.issue-397.replay-failure.v3"
DIRECTORY_NAME = "hermternal-issue397-replay-failure-v3"


def _load_v2() -> types.ModuleType:
    """Compile one stable v2 buffer, then install v3 authority data."""
    descriptor = os.open(V2_PATH, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError("failure v2 is not a single-link regular file")
        raw = b""
        while len(raw) < before.st_size:
            block = os.read(descriptor, before.st_size - len(raw))
            if not block:
                raise RuntimeError("failure v2 read ended early")
            raw += block
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    final = os.lstat(V2_PATH)
    identity = lambda value: (value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode, value.st_size, value.st_nlink, value.st_mtime_ns, value.st_ctime_ns)
    if identity(before) != identity(after) or identity(before) != identity(final) or hashlib.sha256(raw).hexdigest() != V2_SHA256:
        raise RuntimeError("failure v2 identity or SHA-256 differs")
    module = types.ModuleType("issue397_linux_replay_failure_v3_base")
    module.__file__ = os.fspath(Path(__file__).resolve())
    sys.modules[module.__name__] = module
    exec(compile(raw, os.fspath(V2_PATH), "exec", dont_inherit=True), module.__dict__)
    module.PHASE_A_V4_PATH = PHASE_A_V5_PATH
    module.PHASE_A_V4_SHA256 = PHASE_A_V5_SHA256
    module.SCHEMA = SCHEMA
    module.DIRECTORY_NAME = DIRECTORY_NAME
    predecessor_load_v1 = module._load_v1

    def load_v2_mechanism():
        mechanism = predecessor_load_v1()
        mechanism.PHASE_A_ADAPTER_PATH = PHASE_A_V5_PATH
        mechanism.PHASE_A_ADAPTER_SHA256 = PHASE_A_V5_SHA256
        mechanism.load_phase_a_adapter = lambda: linux_phase_a_v5
        return mechanism

    module._load_v1 = load_v2_mechanism
    return module


def load_approved_wrapper(expected_anchor_sha256: str):
    """Install v2 publication mechanics for the exact v5 Phase A adapter."""
    return _load_v2().load_approved_wrapper(expected_anchor_sha256)


def __getattr__(name: str):
    """Expose the frozen v2 publication API without copying it."""
    return getattr(_load_v2(), name)
