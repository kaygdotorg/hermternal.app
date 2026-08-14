#!/usr/bin/env python3
"""Keep one-shot failure retention separate for a later Phase A v9 replay."""
from __future__ import annotations

import hashlib
import os
import stat
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
V6_PATH = HERE / "linux_replay_failure_v6.py"
V6_SHA256 = "c073906cb3f4c2e3bae0238180d8a66cddf75a65a07e964398d9b4b2ff93824a"
PHASE_A_V9_PATH = HERE / "linux_phase_a_v9.py"
PHASE_A_V9_SHA256 = "290d4ae114dad91b3bd15da0e31d698fe8a1b9d67dcc95f2e90d1f0b44c4b331"
SCHEMA = "hermternal.issue-397.replay-failure.v7"
DIRECTORY_NAME = "hermternal-issue397-replay-failure-v7"


def _stable_bytes(path: Path, digest: str, label: str, after_read=None) -> bytes:
    """Return one authenticated fd buffer before any source can execute."""
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError(f"{label} is not a single-link regular file")
        raw = b""
        while len(raw) < before.st_size:
            block = os.read(descriptor, before.st_size - len(raw))
            if not block:
                raise RuntimeError(f"{label} read ended early")
            raw += block
        if os.read(descriptor, 1):
            raise RuntimeError(f"{label} grew during read")
        if after_read is not None:
            after_read()
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = os.lstat(path)
    identity = lambda value: (value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode, value.st_size, value.st_nlink, value.st_mtime_ns, value.st_ctime_ns)
    if identity(before) != identity(after) or identity(before) != identity(current):
        raise RuntimeError(f"{label} changed during read")
    if hashlib.sha256(raw).hexdigest() != digest:
        raise RuntimeError(f"{label} SHA-256 differs")
    return raw


def _load_v9() -> types.ModuleType:
    """Compile only the exact v9 fd buffer and pass its immutable self digest."""
    raw = _stable_bytes(PHASE_A_V9_PATH, PHASE_A_V9_SHA256, "Phase A v9 adapter")
    module = types.ModuleType("issue397_linux_phase_a_v9_verified")
    module.__file__ = os.fspath(PHASE_A_V9_PATH)
    module._AUTHENTICATED_SELF_SHA256 = PHASE_A_V9_SHA256
    sys.modules[module.__name__] = module
    exec(compile(raw, os.fspath(PHASE_A_V9_PATH), "exec", dont_inherit=True), module.__dict__)
    return module


def _load_v6() -> types.ModuleType:
    """Reuse frozen v6 retention mechanics with authenticated Phase A v9 bytes."""
    raw = _stable_bytes(V6_PATH, V6_SHA256, "failure v6")
    phase_v9 = _load_v9()
    module = types.ModuleType("issue397_linux_replay_failure_v7_base")
    module.__file__ = os.fspath(Path(__file__).resolve()); sys.modules[module.__name__] = module
    exec(compile(raw, os.fspath(V6_PATH), "exec", dont_inherit=True), module.__dict__)
    module.PHASE_A_V8_PATH = PHASE_A_V9_PATH; module.PHASE_A_V8_SHA256 = PHASE_A_V9_SHA256
    module.SCHEMA = SCHEMA; module.DIRECTORY_NAME = DIRECTORY_NAME
    predecessor = module._load_v5

    def load_v6_mechanism():
        mechanism = predecessor(); mechanism.PHASE_A_V6_PATH = PHASE_A_V9_PATH; mechanism.PHASE_A_V6_SHA256 = PHASE_A_V9_SHA256
        inner = mechanism._load_v4

        def load_v7_mechanism():
            value = inner(); value.PHASE_A_V5_PATH = PHASE_A_V9_PATH; value.PHASE_A_V5_SHA256 = PHASE_A_V9_SHA256
            deeper = value._load_v3

            def load_v7_inner():
                result = deeper(); result.PHASE_A_V4_PATH = PHASE_A_V9_PATH; result.PHASE_A_V4_SHA256 = PHASE_A_V9_SHA256
                deepest = result._load_v2

                def load_v7_deepest():
                    leaf = deepest(); leaf.PHASE_A_ADAPTER_PATH = PHASE_A_V9_PATH; leaf.PHASE_A_ADAPTER_SHA256 = PHASE_A_V9_SHA256
                    leaf.load_phase_a_adapter = lambda: phase_v9
                    return leaf

                result._load_v2 = load_v7_deepest
                return result

            value._load_v3 = load_v7_inner
            return value

        mechanism._load_v4 = load_v7_mechanism
        return mechanism

    module._load_v5 = load_v6_mechanism
    return module


def load_approved_wrapper(expected_anchor_sha256: str):
    return _load_v6().load_approved_wrapper(expected_anchor_sha256)


def __getattr__(name: str):
    return getattr(_load_v6(), name)
