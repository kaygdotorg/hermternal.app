#!/usr/bin/env python3
"""Propagate the authenticated v9 adapter through the outer failure chain.

Failure v7 updated names on the v2 module, but the inherited v2 loader creates
one fresh failure-v1 module and reads its adapter pin.  This successor wraps
that exact factory so the fresh module receives the already-authenticated v9
adapter.  Replay and failure-publication behavior stay unchanged.
"""
from __future__ import annotations

import hashlib
import os
import stat
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
V7_PATH = HERE / "linux_replay_failure_v7.py"
V7_SHA256 = "a85a288052753f252ed9bd9caabebbc7619211cbb7b3410bb74b1b8e7ed34627"
PHASE_A_V9_PATH = HERE / "linux_phase_a_v9.py"
PHASE_A_V9_SHA256 = "290d4ae114dad91b3bd15da0e31d698fe8a1b9d67dcc95f2e90d1f0b44c4b331"
SCHEMA = "hermternal.issue-397.replay-failure.v8"
DIRECTORY_NAME = "hermternal-issue397-replay-failure-v8"


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
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode,
        value.st_size, value.st_nlink, value.st_mtime_ns, value.st_ctime_ns,
    )
    if identity(before) != identity(after) or identity(before) != identity(current):
        raise RuntimeError(f"{label} changed during read")
    if hashlib.sha256(raw).hexdigest() != digest:
        raise RuntimeError(f"{label} SHA-256 differs")
    return raw


def _verified_module(path: Path, digest: str, name: str, label: str) -> types.ModuleType:
    raw = _stable_bytes(path, digest, label)
    module = types.ModuleType(name)
    module.__file__ = os.fspath(path)
    if path == PHASE_A_V9_PATH:
        module._AUTHENTICATED_SELF_SHA256 = digest
    sys.modules[name] = module
    exec(compile(raw, os.fspath(path), "exec", dont_inherit=True), module.__dict__)
    return module


def _load_v9() -> types.ModuleType:
    return _verified_module(
        PHASE_A_V9_PATH, PHASE_A_V9_SHA256,
        "issue397_linux_phase_a_v9_failure_v8_verified", "Phase A v9 adapter",
    )


def _load_v7() -> types.ModuleType:
    """Load v7, then patch the fresh failure-v1 factory it actually uses."""
    module = _verified_module(
        V7_PATH, V7_SHA256,
        "issue397_linux_replay_failure_v8_base", "failure v7",
    )
    # V7 paths were resolved while its exact bytes loaded.  Use this successor
    # path only for the durable owner digest and the new schema/root identity.
    module.__file__ = os.fspath(Path(__file__).resolve())
    module.SCHEMA = SCHEMA
    module.DIRECTORY_NAME = DIRECTORY_NAME
    module._load_v9 = _load_v9
    predecessor_v6 = module._load_v6

    def load_v8_mechanism():
        top = predecessor_v6()
        predecessor_v5 = top._load_v5

        def load_v5():
            v5 = predecessor_v5()
            predecessor_v4 = v5._load_v4

            def load_v4():
                v4 = predecessor_v4()
                predecessor_v3 = v4._load_v3

                def load_v3():
                    v3 = predecessor_v3()
                    predecessor_v2 = v3._load_v2

                    def load_v2():
                        v2 = predecessor_v2()
                        predecessor_v1 = v2._load_v1

                        def load_v1():
                            v1 = predecessor_v1()
                            phase_v9 = _load_v9()
                            v1.PHASE_A_ADAPTER_PATH = PHASE_A_V9_PATH
                            v1.PHASE_A_ADAPTER_SHA256 = PHASE_A_V9_SHA256
                            v1.load_phase_a_adapter = lambda: phase_v9
                            return v1

                        v2._load_v1 = load_v1
                        return v2

                    v3._load_v2 = load_v2
                    return v3

                v4._load_v3 = load_v3
                return v4

            v5._load_v4 = load_v4
            return v5

        top._load_v5 = load_v5
        return top

    module._load_v6 = load_v8_mechanism
    return module


def load_approved_wrapper(expected_anchor_sha256: str):
    return _load_v7().load_approved_wrapper(expected_anchor_sha256)


def __getattr__(name: str):
    return getattr(_load_v7(), name)
