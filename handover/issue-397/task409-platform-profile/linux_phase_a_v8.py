#!/usr/bin/env python3
"""Bind Phase A evidence to the parent-binding authority successor.

The reviewed v7 implementation is loaded as text and receives only the two
current adapter substitutions.  It retains one Phase A mechanism and one
create-only v8 evidence root; it does not run replay.
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
V7_PATH = HERE / "linux_phase_a_v7.py"
V7_SHA256 = "3eebff57273b7787024fabf95a0a9e39fc0cff86a6af5577aee7e8b2279fc987"
LINUX_WRAPPER_ADAPTER_SHA256 = "83b9dd0fecb26889ddaa0de78a146ad1af22c3e991f4d4bcf56f7900b01c1968"
LINUX_DRIVER_ADAPTER_SHA256 = "0510d5f7ff5e011cb1875378ede3649222c8383ecb702978af8d791a408400e7"
V8_SCHEMA = "hermternal.issue-397.phase-a-anchor-runner.v8"
V8_EVIDENCE_SCHEMA = "hermternal.issue-397.phase-a-anchor-evidence.v8"
V8_ROOT_NAME = "hermternal-issue397-phase-a-anchor-v8"


def _adapter_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _load_v7() -> types.ModuleType:
    """Install only v8 pins in the exact reviewed v7 lifecycle mechanism."""
    raw = V7_PATH.read_bytes()
    if hashlib.sha256(raw).hexdigest() != V7_SHA256:
        raise RuntimeError("Phase A v7 adapter SHA-256 differs")
    replacements = (
        (b"import linux_replay_wrapper_v4\n", b"import linux_replay_wrapper_v5 as linux_replay_wrapper_v4\n"),
        (b"import linux_retained_driver_v4\n", b"import linux_retained_driver_v5 as linux_retained_driver_v4\n"),
        (b"linux_replay_wrapper_v4 as linux_replay_wrapper", b"linux_replay_wrapper_v5 as linux_replay_wrapper"),
        (b"linux_retained_driver_v4.py", b"linux_retained_driver_v5.py"),
        (b"cdc91d0761ba78afa53d8de5a0857b5b8e0851d5880b9e249945aa29ae63eb85", LINUX_WRAPPER_ADAPTER_SHA256.encode()),
        (b"9a3f8dadbd1e013b5d663a72433c133cb12eede277ef677f04b620fab34d832d", LINUX_DRIVER_ADAPTER_SHA256.encode()),
        (b"hermternal.issue-397.phase-a-anchor-runner.v7", V8_SCHEMA.encode()),
        (b"hermternal.issue-397.phase-a-anchor-evidence.v7", V8_EVIDENCE_SCHEMA.encode()),
        (b"hermternal-issue397-phase-a-anchor-v7", V8_ROOT_NAME.encode()),
    )
    for old, new in replacements:
        # The reviewed source contains its own byte-replacement literals, so
        # a new token can be data before this outer adapter changes it.
        if raw.count(old) != 1:
            raise RuntimeError("Phase A v8 successor anchor differs")
        raw = raw.replace(old, new, 1)
    module = types.ModuleType("issue397_linux_phase_a_v8_base")
    module.__file__ = os.fspath(Path(__file__).resolve())
    sys.modules[module.__name__] = module
    exec(compile(raw, os.fspath(V7_PATH), "exec", dont_inherit=True), module.__dict__)
    module.LINUX_WRAPPER_ADAPTER_SHA256 = LINUX_WRAPPER_ADAPTER_SHA256
    module.LINUX_DRIVER_ADAPTER_SHA256 = LINUX_DRIVER_ADAPTER_SHA256
    module.V3_SCHEMA = V8_SCHEMA
    module.V3_EVIDENCE_SCHEMA = V8_EVIDENCE_SCHEMA
    module.V3_ROOT_NAME = V8_ROOT_NAME
    module._adapter_sha256 = _adapter_sha256
    module.FINAL_PINS = dict(linux_retained_driver_v5.HASHES)
    module.FINAL_NAMES = tuple(module.FINAL_PINS)
    predecessor_load_runner = module.load_runner

    def load_parent_binding_runner():
        runner = predecessor_load_runner()
        runner.AUTHORITY_REPOSITORY_ROOT = linux_retained_driver_v5.AUTHORITY_ROOT
        runner.FINAL_PINS = dict(linux_retained_driver_v5.HASHES)
        runner.FINAL_NAMES = tuple(runner.FINAL_PINS)
        predecessor_modules = runner.load_modules

        def load_parent_binding_modules(root=runner.REPOSITORY_ROOT):
            modules = predecessor_modules(root)
            corrected = modules.phase_a._trusted_contract_sha256(linux_retained_driver_v5.load_driver().load_frozen_authority().document["live_overlap"])
            old = modules.phase_a.EXPECTED_LIVE_OVERLAP_SHA256
            for validator in (modules.phase_a, modules.anchor.PHASE_A):
                function = validator._canonical_execution_contract
                constants = tuple(corrected if item == old else item for item in function.__code__.co_consts)
                validator._canonical_execution_contract = types.FunctionType(function.__code__.replace(co_consts=constants), function.__globals__, function.__name__, function.__defaults__, function.__closure__)
                validator.EXPECTED_LIVE_OVERLAP_SHA256 = corrected
            return modules

        runner.load_modules = load_parent_binding_modules
        return runner

    module.load_runner = load_parent_binding_runner
    module._EXPORT_RUNNER = module.load_runner()
    return module


def load_runner(): return _load_v7().load_runner()
def phase_a():
    base = _load_v7(); runner = base.load_runner()
    return runner.phase_a(runner.load_modules(), repository_root=runner.REPOSITORY_ROOT, external_root=runner.EXTERNAL_ROOT)
def anchor(expected_phase_a_sha256: str):
    base = _load_v7(); runner = base.load_runner()
    return runner.anchor(runner.load_modules(), repository_root=runner.REPOSITORY_ROOT, external_root=runner.EXTERNAL_ROOT, expected_phase_a_sha256=expected_phase_a_sha256)
def load_approved_wrapper(expected_anchor_sha256: str, expected_adapter_sha256: str):
    if expected_adapter_sha256 != _adapter_sha256(): raise RuntimeError("Phase A v8 adapter SHA-256 differs")
    wrapper, authority = _load_v7().load_approved_wrapper(expected_anchor_sha256, expected_adapter_sha256)
    wrapper.PHASE_A_RUNNER_PATH = Path(__file__)
    return wrapper, authority

_EXPORT_BASE = _load_v7(); _EXPORT_RUNNER = _EXPORT_BASE.load_runner()
def __getattr__(name: str): return getattr(_EXPORT_RUNNER, name)

def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["phase-a"]:
        print(json.dumps(phase_a(), sort_keys=True, separators=(",", ":"))); return 0
    if len(arguments) == 3 and arguments[:2] == ["anchor", "--expected-phase-a-sha256"]:
        print(json.dumps(anchor(arguments[2]), sort_keys=True, separators=(",", ":"))); return 0
    print("usage: linux_phase_a_v8.py phase-a | anchor --expected-phase-a-sha256 SHA256", file=sys.stderr); return 2

if __name__ == "__main__": raise SystemExit(main())
