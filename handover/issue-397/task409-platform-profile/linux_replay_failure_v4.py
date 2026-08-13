#!/usr/bin/env python3
"""Bind early failure evidence to proof-bound Phase A v6 authority."""
from __future__ import annotations

import hashlib
import os
import stat
import sys
import types
from pathlib import Path

import linux_phase_a_v6

HERE = Path(__file__).resolve().parent
V3_PATH = HERE / "linux_replay_failure_v3.py"
V3_SHA256 = "a5cdb83fe189a1d8902c97cbb5aad0cf2f6ba11af7aab7f819fe53451ae3d4a6"
PHASE_A_V6_PATH = HERE / "linux_phase_a_v6.py"
PHASE_A_V6_SHA256 = "b95c9f3e73e973180fe4f67a4f3a692abcf80ecf970fb856206eabe5a28f7e64"
SCHEMA = "hermternal.issue-397.replay-failure.v4"
DIRECTORY_NAME = "hermternal-issue397-replay-failure-v4"


def _load_v3() -> types.ModuleType:
    """Compile one stable v3 buffer, then install v4 authority data."""
    descriptor = os.open(V3_PATH, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError("failure v3 is not a single-link regular file")
        raw = b""
        while len(raw) < before.st_size:
            block = os.read(descriptor, before.st_size - len(raw))
            if not block:
                raise RuntimeError("failure v3 read ended early")
            raw += block
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = os.lstat(V3_PATH)
    identity = lambda value: (value.st_dev, value.st_ino, value.st_uid, value.st_gid,
                              value.st_mode, value.st_size, value.st_nlink,
                              value.st_mtime_ns, value.st_ctime_ns)
    if identity(before) != identity(after) or identity(before) != identity(current) or hashlib.sha256(raw).hexdigest() != V3_SHA256:
        raise RuntimeError("failure v3 identity or SHA-256 differs")
    if hashlib.sha256(PHASE_A_V6_PATH.read_bytes()).hexdigest() != PHASE_A_V6_SHA256:
        raise RuntimeError("Phase A v6 SHA-256 differs")
    module = types.ModuleType("issue397_linux_replay_failure_v4_base")
    module.__file__ = os.fspath(Path(__file__).resolve())
    sys.modules[module.__name__] = module
    exec(compile(raw, os.fspath(V3_PATH), "exec", dont_inherit=True), module.__dict__)
    module.PHASE_A_V5_PATH = PHASE_A_V6_PATH
    module.PHASE_A_V5_SHA256 = PHASE_A_V6_SHA256
    module.SCHEMA = SCHEMA
    module.DIRECTORY_NAME = DIRECTORY_NAME
    predecessor = module._load_v2

    def load_v3_mechanism():
        mechanism = predecessor()
        mechanism.PHASE_A_V4_PATH = PHASE_A_V6_PATH
        mechanism.PHASE_A_V4_SHA256 = PHASE_A_V6_SHA256
        inner = mechanism._load_v1

        def load_v2_mechanism():
            value = inner()
            value.PHASE_A_ADAPTER_PATH = PHASE_A_V6_PATH
            value.PHASE_A_ADAPTER_SHA256 = PHASE_A_V6_SHA256
            value.load_phase_a_adapter = lambda: linux_phase_a_v6
            return value

        mechanism._load_v1 = load_v2_mechanism
        return mechanism

    module._load_v2 = load_v3_mechanism
    return module


def load_approved_wrapper(expected_anchor_sha256: str):
    """Install v3 publication mechanics for exact Phase A v6 bytes."""
    return _load_v3().load_approved_wrapper(expected_anchor_sha256)


def __getattr__(name: str):
    return getattr(_load_v3(), name)
