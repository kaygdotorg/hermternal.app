#!/usr/bin/env python3
"""Bind the reviewed Phase A v3 mechanism to corrected Linux stdin.

This successor verified-loads the exact v3 adapter and changes only its Linux
driver and wrapper pins, evidence schema, and durable evidence root. Loading or
testing it does not create durable evidence or start replay.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import types
from pathlib import Path
from typing import Sequence

import platform_profile

HERE = Path(__file__).resolve().parent
V3_PATH = HERE / "linux_phase_a_v3.py"
V3_SHA256 = "11204cffbff813e0860349f2128d184191261e509f0a72c92bda1e94d7594587"
LINUX_WRAPPER_ADAPTER_SHA256 = "faf4abdb90b1e446270f2b93d50c85f6c25decfeef03696526405e10b33c43aa"
LINUX_DRIVER_ADAPTER_SHA256 = "add9d9faad650f971a3f6c0dd00fda8188c849eb647dcdd8ff4df7cfca09b783"
V4_SCHEMA = "hermternal.issue-397.phase-a-anchor-runner.v4"
V4_EVIDENCE_SCHEMA = "hermternal.issue-397.phase-a-anchor-evidence.v4"
V4_ROOT_NAME = "hermternal-issue397-phase-a-anchor-v4"


def _load_v3() -> types.ModuleType:
    """Compile one exact v3 buffer before installing v4 data bindings."""
    raw = V3_PATH.read_bytes()
    if hashlib.sha256(raw).hexdigest() != V3_SHA256:
        raise RuntimeError("Phase A v3 adapter SHA-256 differs")
    eager = b"_EXPORT_RUNNER = load_runner()\n"
    deferred = b"_EXPORT_RUNNER = None  # v4 installs successor bindings before load\n"
    if raw.count(eager) != 1 or raw.count(deferred) != 0:
        raise RuntimeError("Phase A v3 eager-load anchor differs")
    raw = raw.replace(eager, deferred, 1)
    module = types.ModuleType("issue397_linux_phase_a_v4_base")
    module.__file__ = os.fspath(V3_PATH)
    sys.modules[module.__name__] = module
    exec(compile(raw, module.__file__, "exec", dont_inherit=True), module.__dict__)
    module.LINUX_WRAPPER_ADAPTER_SHA256 = LINUX_WRAPPER_ADAPTER_SHA256
    module.LINUX_DRIVER_ADAPTER_SHA256 = LINUX_DRIVER_ADAPTER_SHA256
    module.V3_SCHEMA = V4_SCHEMA
    module.V3_EVIDENCE_SCHEMA = V4_EVIDENCE_SCHEMA
    module.V3_ROOT_NAME = V4_ROOT_NAME
    module._adapter_sha256 = _adapter_sha256
    module._EXPORT_RUNNER = module.load_runner()
    return module


def _adapter_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def load_runner():
    """Return the exact v3 runner with only v4 authority data installed."""
    return _load_v3().load_runner()


def phase_a():
    """Run genuine Phase A against the fixed, absent durable v4 root."""
    base = _load_v3()
    runner = base.load_runner()
    return runner.phase_a(runner.load_modules(), repository_root=runner.REPOSITORY_ROOT, external_root=runner.EXTERNAL_ROOT)


def anchor(expected_phase_a_sha256: str):
    """Create a v4 anchor for one independently approved Phase A digest."""
    base = _load_v3()
    runner = base.load_runner()
    return runner.anchor(runner.load_modules(), repository_root=runner.REPOSITORY_ROOT, external_root=runner.EXTERNAL_ROOT, expected_phase_a_sha256=expected_phase_a_sha256)


def load_approved_wrapper(expected_anchor_sha256: str, expected_adapter_sha256: str):
    """Enable the reviewed boundary only after v4 anchor authentication."""
    if expected_adapter_sha256 != _adapter_sha256():
        raise RuntimeError("Phase A v4 adapter SHA-256 differs")
    wrapper, authority = _load_v3().load_approved_wrapper(expected_anchor_sha256, expected_adapter_sha256)
    original = wrapper._load_phase_a_evidence

    def translate(value):
        if isinstance(value, types.CodeType):
            return value.replace(co_consts=tuple(translate(item) for item in value.co_consts))
        if value == "hermternal.issue-397.phase-a-anchor-evidence.v3":
            return V4_EVIDENCE_SCHEMA
        if value == "Phase A evidence path differs from v2 authority":
            return "Phase A evidence path differs from v4 authority"
        if value == "Phase A evidence schema differs from approved v2":
            return "Phase A evidence schema differs from approved v4"
        return value

    wrapper._load_phase_a_evidence = types.FunctionType(
        translate(original.__code__),
        original.__globals__,
        original.__name__,
        original.__defaults__,
        original.__closure__,
    )
    wrapper.load_phase_a_evidence = wrapper._load_phase_a_evidence
    wrapper.PHASE_A_RUNNER_PATH = Path(__file__)
    return wrapper, authority


_EXPORT_BASE = _load_v3()
_EXPORT_RUNNER = _EXPORT_BASE.load_runner()


def __getattr__(name: str):
    """Expose the reviewed runner interface without copying its mechanism."""
    return getattr(_EXPORT_RUNNER, name)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["phase-a"]:
        print(json.dumps(phase_a(), sort_keys=True, separators=(",", ":")))
        return 0
    if len(arguments) == 3 and arguments[:2] == ["anchor", "--expected-phase-a-sha256"]:
        print(json.dumps(anchor(arguments[2]), sort_keys=True, separators=(",", ":")))
        return 0
    print("usage: linux_phase_a_v4.py phase-a | anchor --expected-phase-a-sha256 SHA256", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
