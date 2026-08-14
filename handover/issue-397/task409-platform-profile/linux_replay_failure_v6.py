#!/usr/bin/env python3
"""Keep failure evidence separate for the parent-binding Phase A v8 chain."""
from __future__ import annotations

import hashlib
import os
import stat
import sys
import types
from pathlib import Path

import linux_phase_a_v8

HERE = Path(__file__).resolve().parent
V5_PATH = HERE / "linux_replay_failure_v5.py"
V5_SHA256 = "8ded38a2e87ae7554c56fd2a8ed8e7c9bcae3971abfc2467404e511dcf4103fd"
PHASE_A_V8_PATH = HERE / "linux_phase_a_v8.py"
PHASE_A_V8_SHA256 = "140be86d9f597ca529991c6e8755960ab5f83ee627044ae093b6d392c3b88a3f"
SCHEMA = "hermternal.issue-397.replay-failure.v6"
DIRECTORY_NAME = "hermternal-issue397-replay-failure-v6"


def _load_v5() -> types.ModuleType:
    """Reuse exact v5 failure mechanics with only Phase A v8 data pins."""
    descriptor = os.open(V5_PATH, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1: raise RuntimeError("failure v5 is not a single-link regular file")
        raw = os.read(descriptor, before.st_size)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if before != after or hashlib.sha256(raw).hexdigest() != V5_SHA256: raise RuntimeError("failure v5 identity or SHA-256 differs")
    if hashlib.sha256(PHASE_A_V8_PATH.read_bytes()).hexdigest() != PHASE_A_V8_SHA256: raise RuntimeError("Phase A v8 SHA-256 differs")
    module = types.ModuleType("issue397_linux_replay_failure_v6_base")
    module.__file__ = os.fspath(Path(__file__).resolve()); sys.modules[module.__name__] = module
    exec(compile(raw, os.fspath(V5_PATH), "exec", dont_inherit=True), module.__dict__)
    module.PHASE_A_V7_PATH = PHASE_A_V8_PATH; module.PHASE_A_V7_SHA256 = PHASE_A_V8_SHA256
    module.SCHEMA = SCHEMA; module.DIRECTORY_NAME = DIRECTORY_NAME
    predecessor = module._load_v4

    def load_v5_mechanism():
        mechanism = predecessor(); mechanism.PHASE_A_V6_PATH = PHASE_A_V8_PATH; mechanism.PHASE_A_V6_SHA256 = PHASE_A_V8_SHA256
        inner = mechanism._load_v3
        def load_v6_mechanism():
            value = inner(); value.PHASE_A_V5_PATH = PHASE_A_V8_PATH; value.PHASE_A_V5_SHA256 = PHASE_A_V8_SHA256
            deeper = value._load_v2
            def load_v6_inner():
                result = deeper(); result.PHASE_A_V4_PATH = PHASE_A_V8_PATH; result.PHASE_A_V4_SHA256 = PHASE_A_V8_SHA256
                deepest = result._load_v1
                def load_v6_deepest():
                    leaf = deepest(); leaf.PHASE_A_ADAPTER_PATH = PHASE_A_V8_PATH; leaf.PHASE_A_ADAPTER_SHA256 = PHASE_A_V8_SHA256
                    leaf.load_phase_a_adapter = lambda: linux_phase_a_v8
                    return leaf
                result._load_v1 = load_v6_deepest
                return result
            value._load_v2 = load_v6_inner
            return value
        mechanism._load_v3 = load_v6_mechanism
        return mechanism

    module._load_v4 = load_v5_mechanism
    return module


def load_approved_wrapper(expected_anchor_sha256: str): return _load_v5().load_approved_wrapper(expected_anchor_sha256)
def __getattr__(name: str): return getattr(_load_v5(), name)
