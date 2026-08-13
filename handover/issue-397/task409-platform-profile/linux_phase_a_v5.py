#!/usr/bin/env python3
"""Bind Phase A to the corrected Git-config policy authority.

This successor authenticates v4 and its exact v3 mechanism. It changes only
the wrapper and driver module names, their hashes, the evidence schema, and the
new durable root. Loading or testing this module does not run replay.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import types
from pathlib import Path
from typing import Sequence

import linux_replay_wrapper_v2
import platform_profile

HERE = Path(__file__).resolve().parent
V4_PATH = HERE / "linux_phase_a_v4.py"
V4_SHA256 = "f89ec8bdf2e77f45307b5d30a96aa6c4a2da7f576bcecf3ec102ed120283640f"
V3_PATH = HERE / "linux_phase_a_v3.py"
V3_SHA256 = "11204cffbff813e0860349f2128d184191261e509f0a72c92bda1e94d7594587"
LINUX_WRAPPER_ADAPTER_SHA256 = "9c2ce8a191efe8dcefd427da5c4bde7353683e5787ce8d32b988d9106aa32e54"
LINUX_DRIVER_ADAPTER_SHA256 = "77f7fc5262b5f4eb3b9eff336ebc50b1ed1a6b46d124f42d91ff444ec0db03be"
V5_SCHEMA = "hermternal.issue-397.phase-a-anchor-runner.v5"
V5_EVIDENCE_SCHEMA = "hermternal.issue-397.phase-a-anchor-evidence.v5"
V5_ROOT_NAME = "hermternal-issue397-phase-a-anchor-v5"


def _adapter_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _authenticate_v4() -> None:
    """Check the approved v4 link before deriving its pinned v3 mechanism."""
    raw = V4_PATH.read_bytes()
    if hashlib.sha256(raw).hexdigest() != V4_SHA256:
        raise RuntimeError("Phase A v4 adapter SHA-256 differs")
    if V3_SHA256.encode("ascii") not in raw:
        raise RuntimeError("Phase A v4 predecessor pin differs")
    compile(raw, os.fspath(V4_PATH), "exec", dont_inherit=True)


def _load_v3() -> types.ModuleType:
    """Install v5 data bindings in exact v3 mechanism bytes."""
    _authenticate_v4()
    raw = V3_PATH.read_bytes()
    if hashlib.sha256(raw).hexdigest() != V3_SHA256:
        raise RuntimeError("Phase A v3 adapter SHA-256 differs")
    replacements = (
        (b"import linux_replay_wrapper\n", b"import linux_replay_wrapper_v2 as linux_replay_wrapper\n"),
        (b'driver_path = HERE / "linux_retained_driver.py"\n', b'driver_path = HERE / "linux_retained_driver_v2.py"\n'),
        (b"_EXPORT_RUNNER = load_runner()\n", b"_EXPORT_RUNNER = None  # v5 installs successor bindings before load\n"),
    )
    for old, new in replacements:
        if raw.count(old) != 1 or new in raw:
            raise RuntimeError("Phase A v3 successor anchor differs")
        raw = raw.replace(old, new, 1)
    module = types.ModuleType("issue397_linux_phase_a_v5_base")
    module.__file__ = os.fspath(Path(__file__).resolve())
    sys.modules[module.__name__] = module
    exec(compile(raw, os.fspath(V3_PATH), "exec", dont_inherit=True), module.__dict__)
    module.LINUX_WRAPPER_ADAPTER_SHA256 = LINUX_WRAPPER_ADAPTER_SHA256
    module.LINUX_DRIVER_ADAPTER_SHA256 = LINUX_DRIVER_ADAPTER_SHA256
    module.V3_SCHEMA = V5_SCHEMA
    module.V3_EVIDENCE_SCHEMA = V5_EVIDENCE_SCHEMA
    module.V3_ROOT_NAME = V5_ROOT_NAME
    module._adapter_sha256 = _adapter_sha256
    module._EXPORT_RUNNER = module.load_runner()
    return module


def load_runner():
    """Return the reviewed Phase A runner with v5 authority data."""
    return _load_v3().load_runner()


def phase_a():
    """Run genuine Phase A against the fixed absent v5 root."""
    base = _load_v3()
    runner = base.load_runner()
    return runner.phase_a(runner.load_modules(), repository_root=runner.REPOSITORY_ROOT, external_root=runner.EXTERNAL_ROOT)


def anchor(expected_phase_a_sha256: str):
    """Create a v5 anchor for one independently approved Phase A digest."""
    base = _load_v3()
    runner = base.load_runner()
    return runner.anchor(runner.load_modules(), repository_root=runner.REPOSITORY_ROOT, external_root=runner.EXTERNAL_ROOT, expected_phase_a_sha256=expected_phase_a_sha256)


def load_approved_wrapper(expected_anchor_sha256: str, expected_adapter_sha256: str):
    """Enable #405 only after exact v5 anchor authentication."""
    if expected_adapter_sha256 != _adapter_sha256():
        raise RuntimeError("Phase A v5 adapter SHA-256 differs")
    wrapper, authority = _load_v3().load_approved_wrapper(expected_anchor_sha256, expected_adapter_sha256)
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
    print("usage: linux_phase_a_v5.py phase-a | anchor --expected-phase-a-sha256 SHA256", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
