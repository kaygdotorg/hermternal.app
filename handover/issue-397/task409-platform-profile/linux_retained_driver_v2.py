#!/usr/bin/env python3
"""Correct the generated repository-config predicate in derived stdin.

This successor verified-loads the approved Linux retained-driver adapter. It
changes only the authenticated object-closure config block through the shared
Git policy. It does not execute the derived shell.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import types
from pathlib import Path

import git_config_policy

HERE = Path(__file__).resolve().parent
V1_PATH = HERE / "linux_retained_driver.py"
V1_SHA256 = "add9d9faad650f971a3f6c0dd00fda8188c849eb647dcdd8ff4df7cfca09b783"
POLICY_SHA256 = "ecc9c1e8e3b98a989c19b15b4c9c8bce535d97a02d5c31b79d227785d7f057fa"


def _load_v1() -> types.ModuleType:
    """Compile only the exact approved v1 adapter bytes."""
    raw = V1_PATH.read_bytes()
    if hashlib.sha256(raw).hexdigest() != V1_SHA256:
        raise RuntimeError("Linux retained-driver v1 SHA-256 differs")
    policy_raw = Path(git_config_policy.__file__).read_bytes()
    if hashlib.sha256(policy_raw).hexdigest() != POLICY_SHA256:
        raise RuntimeError("shared Git config policy SHA-256 differs")
    module = types.ModuleType("issue397_linux_retained_driver_v2_base")
    module.__file__ = os.fspath(V1_PATH)
    sys.modules[module.__name__] = module
    exec(compile(raw, module.__file__, "exec", dont_inherit=True), module.__dict__)
    return module


def load_driver() -> types.ModuleType:
    """Return the unchanged approved Linux driver loader."""
    return _load_v1().load_driver()


def derive_contract():
    """Return v1 authority with one shared config-policy correction."""
    base = _load_v1()
    contract = base.derive_contract()
    stdin = git_config_policy.repair_generated_validator(contract.stdin)
    driver = base.load_driver()
    driver.compile_derived(stdin)
    return driver.DerivedDriver(
        contract.argv,
        stdin,
        contract.source_sha256,
        hashlib.sha256(stdin).hexdigest(),
    )


def __getattr__(name: str):
    """Expose v1 data helpers without copying their mechanisms."""
    return getattr(_load_v1(), name)


if __name__ == "__main__":
    value = derive_contract()
    print(json.dumps({"argv": list(value.argv), "source_sha256": value.source_sha256, "derived_sha256": value.derived_sha256, "bytes": len(value.stdin), "replay_run": False}, sort_keys=True))
