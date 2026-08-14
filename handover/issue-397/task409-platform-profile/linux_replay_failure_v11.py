#!/usr/bin/env python3
"""Repair the public v11 loader without changing approved Phase A bytes.

The Phase v11 adapter retargeted the runner used to create evidence. Its public
loader can also create fresh predecessor runners, so this successor retargets
the validator globals on every such runner before it reads durable evidence.
"""
from __future__ import annotations

import hashlib
import os
import stat
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
V10_PATH = HERE / "linux_replay_failure_v10.py"
V10_SHA256 = "f9c41aaaeec8ee45c8b62327f22dd4d5de03a8a00ac709adfd03e4217010e499"
PHASE_A_V11_PATH = HERE / "linux_phase_a_v11.py"
PHASE_A_V11_SHA256 = "8fcee2a45123ea635c06e358fd2c82feda17617ef89eed0faba9dac5d0a401bd"
PHASE_SCHEMA = "hermternal.issue-397.phase-a-anchor-runner.v11"
PHASE_EVIDENCE_SCHEMA = "hermternal.issue-397.phase-a-anchor-evidence.v11"
PHASE_ROOT_NAME = "hermternal-issue397-phase-a-anchor-v11"
PHASE_EXTERNAL_ROOT = Path("/home/kayg/Developer") / PHASE_ROOT_NAME
SCHEMA = "hermternal.issue-397.replay-failure.v11"
DIRECTORY_NAME = "hermternal-issue397-replay-failure-v11"


def _stable_bytes(path: Path, digest: str, label: str) -> bytes:
    """Read one stable, single-link file through its authenticated descriptor."""
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


def _exec_verified(raw: bytes, path: Path, name: str) -> types.ModuleType:
    """Compile and execute only the buffer that the caller authenticated."""
    module = types.ModuleType(name)
    module.__file__ = os.fspath(path)
    sys.modules[name] = module
    exec(compile(raw, os.fspath(path), "exec", dont_inherit=True), module.__dict__)
    return module


def _retarget_runner(runner):
    """Give creation and validation functions the same closed v11 identity."""
    runner.EXTERNAL_ROOT = PHASE_EXTERNAL_ROOT
    runner.SCHEMA = PHASE_SCHEMA
    runner.EVIDENCE_SCHEMA = PHASE_EVIDENCE_SCHEMA
    for name in ("phase_a", "anchor", "_parse_closed_record", "_validate_evidence"):
        function = getattr(runner, name)
        function.__globals__["SCHEMA"] = PHASE_SCHEMA
        function.__globals__["EVIDENCE_SCHEMA"] = PHASE_EVIDENCE_SCHEMA
    if hasattr(runner, "_owner_value"):
        owner_globals = runner._owner_value.__globals__
        owner_globals["V3_SCHEMA"] = PHASE_SCHEMA
        owner_globals["V3_EVIDENCE_SCHEMA"] = PHASE_EVIDENCE_SCHEMA
        owner_globals["V3_ROOT_NAME"] = PHASE_ROOT_NAME
    return runner


def _retarget_phase_factory(module: types.ModuleType) -> types.ModuleType:
    """Retarget fresh nested modules made by the reviewed public loader."""
    for name in tuple(module.__dict__):
        if name.endswith("_ROOT_NAME"):
            module.__dict__[name] = PHASE_ROOT_NAME
    if "load_runner" in module.__dict__:
        prior_load_runner = module.load_runner

        def load_v11_runner():
            return _retarget_runner(prior_load_runner())

        module.load_runner = load_v11_runner
    for name in ("_load_v10", "_load_v8", "_load_v7", "_load_v3"):
        if name in module.__dict__:
            prior_factory = module.__dict__[name]

            def load_v11_factory(factory=prior_factory):
                return _retarget_phase_factory(factory())

            module.__dict__[name] = load_v11_factory
    return module


def _inject_phase(module: types.ModuleType, phase: types.ModuleType) -> types.ModuleType:
    """Install the authenticated Phase module at the outer chain's real seam."""
    if "load_phase_a_adapter" in module.__dict__:
        module.PHASE_A_ADAPTER_PATH = PHASE_A_V11_PATH
        module.PHASE_A_ADAPTER_SHA256 = PHASE_A_V11_SHA256
        module.load_phase_a_adapter = lambda: phase
    for name in tuple(module.__dict__):
        if name.startswith("_load_v") and name[7:].isdigit():
            prior_factory = module.__dict__[name]

            def load_injected(factory=prior_factory):
                return _inject_phase(factory(), phase)

            module.__dict__[name] = load_injected
    return module


def _load_authenticated() -> tuple[types.ModuleType, types.ModuleType]:
    """Authenticate both sources, then return the linked failure and Phase modules."""
    failure_raw = _stable_bytes(V10_PATH, V10_SHA256, "failure v10")
    phase_raw = _stable_bytes(PHASE_A_V11_PATH, PHASE_A_V11_SHA256, "Phase A v11 adapter")
    phase = _retarget_phase_factory(_exec_verified(
        phase_raw, PHASE_A_V11_PATH, "issue397_linux_phase_a_v11_failure_v11_verified"
    ))
    module = _exec_verified(
        failure_raw, V10_PATH, "issue397_linux_replay_failure_v11_base"
    )
    predecessor_factory = module._load_v9

    def load_v11_mechanism():
        return _inject_phase(predecessor_factory(), phase)

    module._load_v9 = load_v11_mechanism
    module.__file__ = os.fspath(Path(__file__).resolve())
    module.SCHEMA = SCHEMA
    module.DIRECTORY_NAME = DIRECTORY_NAME
    return module, phase


def _load_v10() -> types.ModuleType:
    """Return the failure successor linked to authenticated Phase v11 bytes."""
    module, _phase = _load_authenticated()
    return module


def load_approved_wrapper(expected_anchor_sha256: str):
    """Authenticate the durable v11 anchor and return a disabled boundary."""
    return _load_v10().load_approved_wrapper(expected_anchor_sha256)


def __getattr__(name: str):
    return getattr(_load_v10(), name)
