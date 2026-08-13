#!/usr/bin/env python3
"""Bind Phase A to the complete forbidden-object availability proof.

This successor authenticates v5 and reuses its exact lifecycle mechanism. It
adds the canonical proof record and SHA-256 to the owner marker, which Phase A
evidence and the later anchor already bind byte-for-byte.
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
import linux_replay_wrapper_v3
import linux_retained_driver_v3

HERE = Path(__file__).resolve().parent
V5_PATH = HERE / "linux_phase_a_v5.py"
V5_SHA256 = "755fa35860f6991a35a0eed0d63b54cb59500e2e799da811f166d2ccfde76d54"
V3_PATH = HERE / "linux_phase_a_v3.py"
V3_SHA256 = "11204cffbff813e0860349f2128d184191261e509f0a72c92bda1e94d7594587"
LINUX_WRAPPER_ADAPTER_SHA256 = "a357566dc7c451cf38e94be5fa4927b229807ef047d2f8d5fa8fc98bcb32ce8a"
LINUX_DRIVER_ADAPTER_SHA256 = "b19072f9d6cbc6cb9e6fc271bf468ffe182c3e4b7e1f04b0f6f4c7a54fcc2de5"
V6_SCHEMA = "hermternal.issue-397.phase-a-anchor-runner.v6"
V6_EVIDENCE_SCHEMA = "hermternal.issue-397.phase-a-anchor-evidence.v6"
V6_ROOT_NAME = "hermternal-issue397-phase-a-anchor-v6"


def _adapter_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _load_v3() -> types.ModuleType:
    """Install v6 bindings in exact v3 lifecycle bytes after v5 authentication."""
    if hashlib.sha256(V5_PATH.read_bytes()).hexdigest() != V5_SHA256:
        raise RuntimeError("Phase A v5 adapter SHA-256 differs")
    raw = V3_PATH.read_bytes()
    if hashlib.sha256(raw).hexdigest() != V3_SHA256:
        raise RuntimeError("Phase A v3 mechanism SHA-256 differs")
    replacements = (
        (b"import linux_replay_wrapper\n", b"import linux_replay_wrapper_v3 as linux_replay_wrapper\n"),
        (b'driver_path = HERE / "linux_retained_driver.py"\n', b'driver_path = HERE / "linux_retained_driver_v3.py"\n'),
        (b"_EXPORT_RUNNER = load_runner()\n", b"_EXPORT_RUNNER = None  # v6 installs proof bindings before load\n"),
    )
    for old, new in replacements:
        if raw.count(old) != 1 or new in raw:
            raise RuntimeError("Phase A v6 successor anchor differs")
        raw = raw.replace(old, new, 1)
    module = types.ModuleType("issue397_linux_phase_a_v6_base")
    module.__file__ = os.fspath(Path(__file__).resolve())
    sys.modules[module.__name__] = module
    exec(compile(raw, os.fspath(V3_PATH), "exec", dont_inherit=True), module.__dict__)
    module.LINUX_WRAPPER_ADAPTER_SHA256 = LINUX_WRAPPER_ADAPTER_SHA256
    module.LINUX_DRIVER_ADAPTER_SHA256 = LINUX_DRIVER_ADAPTER_SHA256
    module.V3_SCHEMA = V6_SCHEMA
    module.V3_EVIDENCE_SCHEMA = V6_EVIDENCE_SCHEMA
    module.V3_ROOT_NAME = V6_ROOT_NAME
    module._adapter_sha256 = _adapter_sha256
    predecessor_profile_record = module._profile_record

    def proof_profile_record(profile):
        value = predecessor_profile_record(profile)
        proof = linux_retained_driver_v3.forbidden_proof_record()
        value["forbidden_proof"] = proof
        value["forbidden_proof_sha256"] = forbidden_proof.record_sha256(proof)
        return value

    module._profile_record = proof_profile_record
    module._EXPORT_RUNNER = module.load_runner()
    return module


def load_runner():
    """Return the reviewed Phase A runner with v6 proof bindings."""
    return _load_v3().load_runner()


def phase_a():
    """Run genuine Phase A against the fixed absent v6 root."""
    base = _load_v3()
    runner = base.load_runner()
    return runner.phase_a(runner.load_modules(), repository_root=runner.REPOSITORY_ROOT, external_root=runner.EXTERNAL_ROOT)


def anchor(expected_phase_a_sha256: str):
    """Create a v6 anchor for one independently approved Phase A digest."""
    base = _load_v3()
    runner = base.load_runner()
    return runner.anchor(runner.load_modules(), repository_root=runner.REPOSITORY_ROOT,
                         external_root=runner.EXTERNAL_ROOT,
                         expected_phase_a_sha256=expected_phase_a_sha256)


def load_approved_wrapper(expected_anchor_sha256: str, expected_adapter_sha256: str):
    """Enable #405 only after exact v6 proof-bound anchor authentication."""
    if expected_adapter_sha256 != _adapter_sha256():
        raise RuntimeError("Phase A v6 adapter SHA-256 differs")
    wrapper, authority = _load_v3().load_approved_wrapper(expected_anchor_sha256, expected_adapter_sha256)
    wrapper.PHASE_A_RUNNER_PATH = Path(__file__)
    return wrapper, authority


_EXPORT_BASE = _load_v3()
_EXPORT_RUNNER = _EXPORT_BASE.load_runner()


def __getattr__(name: str):
    return getattr(_EXPORT_RUNNER, name)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["phase-a"]:
        print(json.dumps(phase_a(), sort_keys=True, separators=(",", ":")))
        return 0
    if len(arguments) == 3 and arguments[:2] == ["anchor", "--expected-phase-a-sha256"]:
        print(json.dumps(anchor(arguments[2]), sort_keys=True, separators=(",", ":")))
        return 0
    print("usage: linux_phase_a_v6.py phase-a | anchor --expected-phase-a-sha256 SHA256", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
