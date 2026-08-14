#!/usr/bin/env python3
"""Bind Phase A evidence to the reviewed local object-preservation policy."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Sequence

import linux_phase_a_v10 as predecessor
import linux_replay_wrapper_v7
import linux_retained_driver_v7
import object_preservation

HERE = Path(__file__).resolve().parent
V10_PATH = HERE / "linux_phase_a_v10.py"
V10_SHA256 = "15e1492607fcb43f14cd290eef9e0e3df6d4b4a19e5b4bbf278b69647853461b"
WRAPPER_PATH = HERE / "linux_replay_wrapper_v7.py"
WRAPPER_SHA256 = "b192429bcb98b4a022d72ad7cf207a7da6c271b52b297168814f3d2007decce4"
DRIVER_PATH = HERE / "linux_retained_driver_v7.py"
DRIVER_SHA256 = "11adb45e1600717cb5b9cc91d99ea34d5d383320de6bc449cca1e10f0ad35476"
V11_SCHEMA = "hermternal.issue-397.phase-a-anchor-runner.v11"
V11_EVIDENCE_SCHEMA = "hermternal.issue-397.phase-a-anchor-evidence.v11"
V11_ROOT_NAME = "hermternal-issue397-phase-a-anchor-v11"
V11_EXTERNAL_ROOT = Path("/home/kayg/Developer") / V11_ROOT_NAME


def _adapter_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _load_v10():
    """Install only v11 hashes, schemas, and the canonical closure record."""
    if hashlib.sha256(V10_PATH.read_bytes()).hexdigest() != V10_SHA256:
        raise RuntimeError("Phase A v10 adapter SHA-256 differs")
    if hashlib.sha256(WRAPPER_PATH.read_bytes()).hexdigest() != WRAPPER_SHA256:
        raise RuntimeError("Linux replay wrapper v7 SHA-256 differs")
    if hashlib.sha256(DRIVER_PATH.read_bytes()).hexdigest() != DRIVER_SHA256:
        raise RuntimeError("Linux retained-driver v7 SHA-256 differs")
    def retarget(module):
        """Retarget every reviewed lifecycle factory to the one v11 root."""
        for name in tuple(module.__dict__):
            if name.endswith("_ROOT_NAME"):
                module.__dict__[name] = V11_ROOT_NAME
        if "load_runner" in module.__dict__:
            prior_load_runner = module.load_runner

            def load_v11_runner():
                value = prior_load_runner()
                value.EXTERNAL_ROOT = V11_EXTERNAL_ROOT
                return value

            module.load_runner = load_v11_runner
        for name in ("_load_v8", "_load_v7", "_load_v3"):
            if name in module.__dict__:
                prior_factory = module.__dict__[name]

                def load_v11_factory(factory=prior_factory):
                    return retarget(factory())

                module.__dict__[name] = load_v11_factory
        return module

    base = retarget(predecessor._load_v9())
    runner = base.load_runner()
    modules_globals = runner.load_modules.__globals__
    modules_globals["linux_replay_wrapper_v5"] = linux_replay_wrapper_v7
    modules_globals["linux_retained_driver_v5"] = linux_retained_driver_v7
    modules_globals["LINUX_WRAPPER_ADAPTER_SHA256"] = WRAPPER_SHA256
    modules_globals["LINUX_DRIVER_ADAPTER_SHA256"] = DRIVER_SHA256
    for function in (runner.phase_a, runner.anchor):
        function.__globals__["SCHEMA"] = V11_SCHEMA
        function.__globals__["EVIDENCE_SCHEMA"] = V11_EVIDENCE_SCHEMA
    owner_globals = runner._owner_value.__globals__
    owner_globals["V3_SCHEMA"] = V11_SCHEMA
    owner_globals["V3_EVIDENCE_SCHEMA"] = V11_EVIDENCE_SCHEMA
    owner_globals["V3_ROOT_NAME"] = V11_ROOT_NAME
    runner.EXTERNAL_ROOT = V11_EXTERNAL_ROOT
    prior_profile = owner_globals["_profile_record"]

    def preservation_profile(profile):
        value = prior_profile(profile)
        record = linux_retained_driver_v7.preservation_record()
        value["object_preservation"] = record
        value["object_preservation_sha256"] = object_preservation.record_sha256(record)
        value["object_preservation_policy_sha256"] = linux_retained_driver_v7.POLICY_SHA256
        return value

    owner_globals["_profile_record"] = preservation_profile
    base.load_runner = lambda: runner
    base._adapter_sha256 = _adapter_sha256
    return base


def load_runner():
    return _load_v10().load_runner()


def phase_a():
    base = _load_v10()
    runner = base.load_runner()
    return runner.phase_a(
        runner.load_modules(), repository_root=runner.REPOSITORY_ROOT,
        external_root=runner.EXTERNAL_ROOT
    )


def anchor(expected_phase_a_sha256: str):
    base = _load_v10()
    runner = base.load_runner()
    return runner.anchor(
        runner.load_modules(), repository_root=runner.REPOSITORY_ROOT,
        external_root=runner.EXTERNAL_ROOT,
        expected_phase_a_sha256=expected_phase_a_sha256
    )


def load_approved_wrapper(expected_anchor_sha256: str, expected_adapter_sha256: str):
    if expected_adapter_sha256 != _adapter_sha256():
        raise RuntimeError("Phase A v11 adapter SHA-256 differs")
    wrapper, authority = _load_v10().load_approved_wrapper(
        expected_anchor_sha256, expected_adapter_sha256
    )
    wrapper.PHASE_A_RUNNER_PATH = Path(__file__)
    return wrapper, authority


_EXPORT_BASE = _load_v10()
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
    print(
        "usage: linux_phase_a_v11.py phase-a | anchor --expected-phase-a-sha256 SHA256",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
