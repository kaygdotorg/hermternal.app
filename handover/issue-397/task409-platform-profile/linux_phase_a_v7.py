#!/usr/bin/env python3
"""Bind Phase A evidence to the LF-corrected authority successor.

This adapter keeps v1-v6 roots frozen.  Its commands are create-only and are
not run by tests except against disposable roots with mocked worktree identity.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import types
from pathlib import Path
from typing import Sequence

import forbidden_proof
import linux_phase_a_v6
import linux_replay_wrapper_v4
import linux_retained_driver_v4

HERE = Path(__file__).resolve().parent
V6_PATH = HERE / "linux_phase_a_v6.py"
V6_SHA256 = "b95c9f3e73e973180fe4f67a4f3a692abcf80ecf970fb856206eabe5a28f7e64"
V3_PATH = HERE / "linux_phase_a_v3.py"
V3_SHA256 = "11204cffbff813e0860349f2128d184191261e509f0a72c92bda1e94d7594587"
LINUX_WRAPPER_ADAPTER_SHA256 = "cdc91d0761ba78afa53d8de5a0857b5b8e0851d5880b9e249945aa29ae63eb85"
LINUX_DRIVER_ADAPTER_SHA256 = "9a3f8dadbd1e013b5d663a72433c133cb12eede277ef677f04b620fab34d832d"
V7_SCHEMA = "hermternal.issue-397.phase-a-anchor-runner.v7"
V7_EVIDENCE_SCHEMA = "hermternal.issue-397.phase-a-anchor-evidence.v7"
V7_ROOT_NAME = "hermternal-issue397-phase-a-anchor-v7"


def _adapter_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _load_v3() -> types.ModuleType:
    """Install only v7 pins in the exact reviewed lifecycle mechanism."""
    if hashlib.sha256(V6_PATH.read_bytes()).hexdigest() != V6_SHA256:
        raise RuntimeError("Phase A v6 adapter SHA-256 differs")
    raw = V3_PATH.read_bytes()
    if hashlib.sha256(raw).hexdigest() != V3_SHA256:
        raise RuntimeError("Phase A v3 mechanism SHA-256 differs")
    replacements = (
        (b"import linux_replay_wrapper\n", b"import linux_replay_wrapper_v4 as linux_replay_wrapper\n"),
        (b'driver_path = HERE / "linux_retained_driver.py"\n', b'driver_path = HERE / "linux_retained_driver_v4.py"\n'),
        (b"_EXPORT_RUNNER = load_runner()\n", b"_EXPORT_RUNNER = None  # v7 installs LF authority bindings before load\n"),
    )
    for old, new in replacements:
        if raw.count(old) != 1 or new in raw:
            raise RuntimeError("Phase A v7 successor anchor differs")
        raw = raw.replace(old, new, 1)
    module = types.ModuleType("issue397_linux_phase_a_v7_base")
    module.__file__ = os.fspath(Path(__file__).resolve())
    sys.modules[module.__name__] = module
    exec(compile(raw, os.fspath(V3_PATH), "exec", dont_inherit=True), module.__dict__)
    module.LINUX_WRAPPER_ADAPTER_SHA256 = LINUX_WRAPPER_ADAPTER_SHA256
    module.LINUX_DRIVER_ADAPTER_SHA256 = LINUX_DRIVER_ADAPTER_SHA256
    module.V3_SCHEMA = V7_SCHEMA
    module.V3_EVIDENCE_SCHEMA = V7_EVIDENCE_SCHEMA
    module.V3_ROOT_NAME = V7_ROOT_NAME
    module._adapter_sha256 = _adapter_sha256
    # The reviewed runner still provides lifecycle mechanics, but v7 must read
    # the separately frozen corrected authority rather than the v1 profile root.
    module.FINAL_PINS = dict(linux_retained_driver_v4.HASHES)
    module.FINAL_NAMES = tuple(module.FINAL_PINS)
    predecessor_load_runner = module.load_runner
    def load_lf_runner():
        runner = predecessor_load_runner()
        runner.AUTHORITY_REPOSITORY_ROOT = linux_retained_driver_v4.AUTHORITY_ROOT
        runner.FINAL_PINS = dict(linux_retained_driver_v4.HASHES)
        runner.FINAL_NAMES = tuple(runner.FINAL_PINS)
        predecessor_modules = runner.load_modules
        def load_lf_modules(root=runner.REPOSITORY_ROOT):
            modules = predecessor_modules(root)
            corrected = modules.phase_a._trusted_contract_sha256(
                linux_retained_driver_v4.load_driver().load_frozen_authority().document["live_overlap"]
            )
            old = modules.phase_a.EXPECTED_LIVE_OVERLAP_SHA256
            for validator in (modules.phase_a, modules.anchor.PHASE_A):
                function = validator._canonical_execution_contract
                constants = tuple(corrected if item == old else item for item in function.__code__.co_consts)
                validator._canonical_execution_contract = types.FunctionType(
                    function.__code__.replace(co_consts=constants), function.__globals__, function.__name__, function.__defaults__, function.__closure__
                )
                validator.EXPECTED_LIVE_OVERLAP_SHA256 = corrected
            return modules
        runner.load_modules = load_lf_modules
        return runner
    module.load_runner = load_lf_runner
    predecessor_profile_record = module._profile_record
    def proof_profile_record(profile):
        value = predecessor_profile_record(profile)
        proof = linux_retained_driver_v4.forbidden_proof_record()
        value["forbidden_proof"] = proof
        value["forbidden_proof_sha256"] = forbidden_proof.record_sha256(proof)
        value["section_anchor"] = {"path": list(__import__("section_anchor_metadata").ANCHOR_PATH), "value": __import__("section_anchor_metadata").CANONICAL_ANCHOR}
        return value
    module._profile_record = proof_profile_record
    module._EXPORT_RUNNER = module.load_runner()
    return module


def load_runner(): return _load_v3().load_runner()
def phase_a():
    base = _load_v3(); runner = base.load_runner()
    return runner.phase_a(runner.load_modules(), repository_root=runner.REPOSITORY_ROOT, external_root=runner.EXTERNAL_ROOT)
def anchor(expected_phase_a_sha256: str):
    base = _load_v3(); runner = base.load_runner()
    return runner.anchor(runner.load_modules(), repository_root=runner.REPOSITORY_ROOT, external_root=runner.EXTERNAL_ROOT, expected_phase_a_sha256=expected_phase_a_sha256)
def load_approved_wrapper(expected_anchor_sha256: str, expected_adapter_sha256: str):
    if expected_adapter_sha256 != _adapter_sha256(): raise RuntimeError("Phase A v7 adapter SHA-256 differs")
    wrapper, authority = _load_v3().load_approved_wrapper(expected_anchor_sha256, expected_adapter_sha256)
    wrapper.PHASE_A_RUNNER_PATH = Path(__file__)
    return wrapper, authority

_EXPORT_BASE = _load_v3(); _EXPORT_RUNNER = _EXPORT_BASE.load_runner()
def __getattr__(name: str): return getattr(_EXPORT_RUNNER, name)

def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["phase-a"]:
        print(json.dumps(phase_a(), sort_keys=True, separators=(",", ":"))); return 0
    if len(arguments) == 3 and arguments[:2] == ["anchor", "--expected-phase-a-sha256"]:
        print(json.dumps(anchor(arguments[2]), sort_keys=True, separators=(",", ":"))); return 0
    print("usage: linux_phase_a_v7.py phase-a | anchor --expected-phase-a-sha256 SHA256", file=sys.stderr); return 2

if __name__ == "__main__": raise SystemExit(main())
