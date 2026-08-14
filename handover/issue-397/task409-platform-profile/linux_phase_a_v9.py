#!/usr/bin/env python3
"""Bind the v8 lifecycle to the v5 wrapper's v8 disabled boundary.

The frozen v8 adapter remains the lifecycle source.  v9 changes one loaded
v3 code constant so its existing preserved-method replacement targets the
unchanged v5 wrapper boundary.  It does not generate authority or run replay.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import types
from pathlib import Path
from typing import Sequence

import linux_replay_wrapper_v5
import linux_retained_driver_v5

HERE = Path(__file__).resolve().parent
FROZEN_V8_PATH = HERE / "linux_phase_a_v8.py"
V8_PATH = FROZEN_V8_PATH
V8_SHA256 = "140be86d9f597ca529991c6e8755960ab5f83ee627044ae093b6d392c3b88a3f"
LINUX_WRAPPER_ADAPTER_SHA256 = "83b9dd0fecb26889ddaa0de78a146ad1af22c3e991f4d4bcf56f7900b01c1968"
LINUX_DRIVER_ADAPTER_SHA256 = "0510d5f7ff5e011cb1875378ede3649222c8383ecb702978af8d791a408400e7"
V9_SCHEMA = "hermternal.issue-397.phase-a-anchor-runner.v9"
V9_EVIDENCE_SCHEMA = "hermternal.issue-397.phase-a-anchor-evidence.v9"
V9_ROOT_NAME = "hermternal-issue397-phase-a-anchor-v9"
DISABLED_V3 = b'    wrapper.execute_and_publish = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("Phase A v3 authority is not installed"))\n'
DISABLED_V8 = b'    wrapper.execute_and_publish = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("Phase A v8 authority is not installed"))\n'
PRESERVED_METHOD = b"    wrapper._phase_a_v3_predecessor_execute_and_publish = wrapper.execute_and_publish\n"


def _adapter_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _stable_v8_bytes(path: Path = V8_PATH) -> bytes:
    """Load only the fixed v8 pathname, so a matching swapped file cannot run."""
    if path != FROZEN_V8_PATH or V8_PATH != FROZEN_V8_PATH:
        raise RuntimeError("Phase A v8 adapter path differs")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != V8_SHA256:
        raise RuntimeError("Phase A v8 adapter SHA-256 differs")
    return raw


def _replace_v3_boundary(function):
    """Change one disabled literal and retain v3's approved restoration target."""
    constants = function.__code__.co_consts
    if constants.count(DISABLED_V3) != 1 or constants.count(DISABLED_V8) != 0:
        raise RuntimeError("Phase A v9 disabled-boundary count differs")
    if constants.count(PRESERVED_METHOD) != 1:
        raise RuntimeError("Phase A v9 preserved-method target differs")
    replaced = tuple(DISABLED_V8 if value == DISABLED_V3 else value for value in constants)
    return types.FunctionType(
        function.__code__.replace(co_consts=replaced), function.__globals__, function.__name__,
        function.__defaults__, function.__closure__,
    )


def _load_v8() -> types.ModuleType:
    """Install v9 data pins on authenticated v8 bytes and its loaded v3 method."""
    raw = _stable_v8_bytes()
    module = types.ModuleType("issue397_linux_phase_a_v9_base")
    module.__file__ = os.fspath(Path(__file__).resolve())
    sys.modules[module.__name__] = module
    exec(compile(raw, os.fspath(V8_PATH), "exec", dont_inherit=True), module.__dict__)
    module.LINUX_WRAPPER_ADAPTER_SHA256 = LINUX_WRAPPER_ADAPTER_SHA256
    module.LINUX_DRIVER_ADAPTER_SHA256 = LINUX_DRIVER_ADAPTER_SHA256
    module.V8_SCHEMA = V9_SCHEMA
    module.V8_EVIDENCE_SCHEMA = V9_EVIDENCE_SCHEMA
    module.V8_ROOT_NAME = V9_ROOT_NAME
    module._adapter_sha256 = _adapter_sha256
    module.FINAL_PINS = dict(linux_retained_driver_v5.HASHES)
    module.FINAL_NAMES = tuple(module.FINAL_PINS)
    predecessor_load_v7 = module._load_v7

    def load_v9_mechanism():
        value = predecessor_load_v7()
        predecessor_load_v3 = value._load_v3

        def load_v9_v3_mechanism():
            v3 = predecessor_load_v3()
            v3.load_approved_wrapper = _replace_v3_boundary(v3.load_approved_wrapper)
            return v3

        value._load_v3 = load_v9_v3_mechanism
        return value

    module._load_v7 = load_v9_mechanism
    module._EXPORT_RUNNER = module.load_runner()
    return module


def load_runner():
    return _load_v8().load_runner()


def phase_a():
    base = _load_v8(); runner = base.load_runner()
    return runner.phase_a(runner.load_modules(), repository_root=runner.REPOSITORY_ROOT, external_root=runner.EXTERNAL_ROOT)


def anchor(expected_phase_a_sha256: str):
    base = _load_v8(); runner = base.load_runner()
    return runner.anchor(runner.load_modules(), repository_root=runner.REPOSITORY_ROOT, external_root=runner.EXTERNAL_ROOT, expected_phase_a_sha256=expected_phase_a_sha256)


def load_approved_wrapper(expected_anchor_sha256: str, expected_adapter_sha256: str):
    if expected_adapter_sha256 != _adapter_sha256():
        raise RuntimeError("Phase A v9 adapter SHA-256 differs")
    wrapper, authority = _load_v8().load_approved_wrapper(expected_anchor_sha256, expected_adapter_sha256)
    wrapper.PHASE_A_RUNNER_PATH = Path(__file__)
    return wrapper, authority


_EXPORT_BASE = _load_v8(); _EXPORT_RUNNER = _EXPORT_BASE.load_runner()


def __getattr__(name: str):
    return getattr(_EXPORT_RUNNER, name)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["phase-a"]:
        print(json.dumps(phase_a(), sort_keys=True, separators=(",", ":"))); return 0
    if len(arguments) == 3 and arguments[:2] == ["anchor", "--expected-phase-a-sha256"]:
        print(json.dumps(anchor(arguments[2]), sort_keys=True, separators=(",", ":"))); return 0
    print("usage: linux_phase_a_v9.py phase-a | anchor --expected-phase-a-sha256 SHA256", file=sys.stderr); return 2


if __name__ == "__main__":
    raise SystemExit(main())
