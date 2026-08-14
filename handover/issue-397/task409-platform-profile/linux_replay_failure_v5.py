#!/usr/bin/env python3
"""Bind create-only failure evidence to the LF-corrected Phase A v7 chain."""
from __future__ import annotations

import hashlib
import os
import stat
import sys
import types
from pathlib import Path

import linux_phase_a_v7

HERE = Path(__file__).resolve().parent
V4_PATH = HERE / "linux_replay_failure_v4.py"
V4_SHA256 = "86b61404f5affda8232407086101ef8d06aac665d095dbde6f2299aa75aabc93"
PHASE_A_V7_PATH = HERE / "linux_phase_a_v7.py"
PHASE_A_V7_SHA256 = "3eebff57273b7787024fabf95a0a9e39fc0cff86a6af5577aee7e8b2279fc987"
SCHEMA = "hermternal.issue-397.replay-failure.v5"
DIRECTORY_NAME = "hermternal-issue397-replay-failure-v5"


def _load_v4() -> types.ModuleType:
    """Reuse exact v4 failure mechanics with only Phase A v7 data pins."""
    descriptor = os.open(V4_PATH, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1: raise RuntimeError("failure v4 is not a single-link regular file")
        raw = os.read(descriptor, before.st_size)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if before != after or hashlib.sha256(raw).hexdigest() != V4_SHA256: raise RuntimeError("failure v4 identity or SHA-256 differs")
    if hashlib.sha256(PHASE_A_V7_PATH.read_bytes()).hexdigest() != PHASE_A_V7_SHA256: raise RuntimeError("Phase A v7 SHA-256 differs")
    module = types.ModuleType("issue397_linux_replay_failure_v5_base")
    module.__file__ = os.fspath(Path(__file__).resolve()); sys.modules[module.__name__] = module
    exec(compile(raw, os.fspath(V4_PATH), "exec", dont_inherit=True), module.__dict__)
    module.PHASE_A_V6_PATH = PHASE_A_V7_PATH; module.PHASE_A_V6_SHA256 = PHASE_A_V7_SHA256
    module.SCHEMA = SCHEMA; module.DIRECTORY_NAME = DIRECTORY_NAME
    predecessor = module._load_v3
    def load_v4_mechanism():
        mechanism = predecessor(); mechanism.PHASE_A_V5_PATH = PHASE_A_V7_PATH; mechanism.PHASE_A_V5_SHA256 = PHASE_A_V7_SHA256
        inner = mechanism._load_v2
        def load_v3_mechanism():
            value = inner(); value.PHASE_A_V4_PATH = PHASE_A_V7_PATH; value.PHASE_A_V4_SHA256 = PHASE_A_V7_SHA256
            deeper = value._load_v1
            def load_v4_inner():
                result = deeper(); result.PHASE_A_ADAPTER_PATH = PHASE_A_V7_PATH; result.PHASE_A_ADAPTER_SHA256 = PHASE_A_V7_SHA256
                result.load_phase_a_adapter = lambda: linux_phase_a_v7
                return result
            value._load_v1 = load_v4_inner
            return value
        mechanism._load_v2 = load_v3_mechanism
        return mechanism
    module._load_v3 = load_v4_mechanism
    return module


def load_approved_wrapper(expected_anchor_sha256: str): return _load_v4().load_approved_wrapper(expected_anchor_sha256)
def __getattr__(name: str): return getattr(_load_v4(), name)
