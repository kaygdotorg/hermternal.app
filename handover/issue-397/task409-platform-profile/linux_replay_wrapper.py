#!/usr/bin/env python3
"""Pin the trusted wrapper to the Linux retained-driver contract.

This module is an offline authority preflight. It does not call the wrapper
process boundary. A later Phase A v3 record must pin these exact bytes before
the already-reviewed wrapper can be enabled for one replay.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import types
from pathlib import Path

import linux_retained_driver

BASE = Path(__file__).resolve().parents[1]
WRAPPER_PATH = BASE / "task409-replay-result-successor" / "replay_result_successor.py"
WRAPPER_SHA256 = "a8a00bab2d221c5231ddc1f03eba1e0113ed252eecce43df1f8493df0160be60"
DRIVER_ADAPTER_PATH = Path(linux_retained_driver.__file__).resolve()
DRIVER_ADAPTER_SHA256 = "e250cee3720cc3d8f7339b1e9d6a9f6545d983a64ea02afa5e714aea027cc40d"
DERIVED_STDIN_SHA256 = "6d50bb3f2432c9416d904f010727f969f4c367882f2355223af1ab7087e0ef77"


def _verified(path: Path, digest: str, name: str) -> types.ModuleType:
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise RuntimeError(f"{name} SHA-256 differs")
    module = types.ModuleType(name)
    module.__file__ = os.fspath(path)
    sys.modules[name] = module
    exec(compile(raw, os.fspath(path), "exec", dont_inherit=True), module.__dict__)
    return module


def preflight() -> dict[str, object]:
    """Verify wrapper, driver adapter, final authority, and exact stdin pins."""
    _verified(WRAPPER_PATH, WRAPPER_SHA256, "issue397_linux_wrapper_base")
    _verified(DRIVER_ADAPTER_PATH, DRIVER_ADAPTER_SHA256, "issue397_linux_driver_adapter_pin")
    driver = linux_retained_driver.load_driver()
    frozen = driver.load_frozen_authority()
    contract = linux_retained_driver.derive_contract()
    if contract.derived_sha256 != DERIVED_STDIN_SHA256:
        raise RuntimeError("Linux derived stdin SHA-256 differs")
    if hashlib.sha256(contract.stdin).hexdigest() != DERIVED_STDIN_SHA256:
        raise RuntimeError("Linux derived stdin bytes differ")
    if contract.source_sha256 != frozen.shell.sha256:
        raise RuntimeError("Linux source shell boundary differs")
    return {
        "wrapper_sha256": WRAPPER_SHA256,
        "driver_adapter_sha256": DRIVER_ADAPTER_SHA256,
        "source_shell_sha256": contract.source_sha256,
        "derived_stdin_sha256": contract.derived_sha256,
        "argv": list(contract.argv),
        "phase_a_v3_required": True,
        "replay_run": False,
    }


if __name__ == "__main__":
    print(json.dumps(preflight(), sort_keys=True))
