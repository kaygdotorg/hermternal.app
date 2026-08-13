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
DRIVER_ADAPTER_SHA256 = "00bf439d02e98753df0b49570145974f3307261e62763aab5937db13735fcd9b"
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


def load_wrapper() -> tuple[types.ModuleType, object]:
    """Return reviewed #405 with the Linux authority contract installed."""
    wrapper = _verified(WRAPPER_PATH, WRAPPER_SHA256, "issue397_linux_wrapper_base")
    _verified(DRIVER_ADAPTER_PATH, DRIVER_ADAPTER_SHA256, "issue397_linux_driver_adapter_pin")
    driver = linux_retained_driver.load_driver()
    frozen = driver.load_frozen_authority()
    contract = linux_retained_driver.derive_contract()
    profile = linux_retained_driver.platform_profile.load()
    # Install the authenticated Linux contract into the reviewed #405 wrapper.
    # Phase A v3 remains deliberately unavailable, so execution cannot start.
    wrapper.DRIVER_PATH = DRIVER_ADAPTER_PATH
    wrapper.DRIVER_SHA256 = DRIVER_ADAPTER_SHA256
    wrapper.DERIVED_STDIN_SHA256 = DERIVED_STDIN_SHA256
    wrapper.RUN_PARENT = Path(profile.temporary_parent)
    def linux_authority():
        base = linux_retained_driver.load_driver()
        frozen_linux = base.load_frozen_authority()
        contract_linux = linux_retained_driver.derive_contract()
        reviewer_module = wrapper._verified_module(wrapper.GIT_AUTHORITY_PATH, wrapper.GIT_AUTHORITY_SHA256, "issue397_linux_git_authority")
        reviewer = reviewer_module.install_successor()
        base_record = frozen_linux.document["base"]
        forbidden = frozen_linux.document["forbidden_ancestry"]
        source_commit = next(lane["source_commit"]["commit"] for lane in frozen_linux.document["ordered_lanes"] if isinstance(lane.get("source_commit"), dict))
        return wrapper.Authority(base, reviewer, contract_linux.argv, contract_linux.stdin, contract_linux.source_sha256, contract_linux.derived_sha256, frozen_linux.markdown.sha256, frozen_linux.json.sha256, frozen_linux.shell.sha256, frozen_linux.provenance.sha256, base_record["commit"], base_record["tree"], base_record["protected_main_commit"], source_commit, (base_record["commit"],), tuple(dict.fromkeys([*forbidden["commits"], *forbidden["raw_semantic_source_commits"]])))
    wrapper.load_authority = linux_authority
    loaded = wrapper.load_authority()
    if loaded.stdin != contract.stdin or loaded.derived_stdin_sha256 != contract.derived_sha256:
        raise RuntimeError("Linux wrapper authority injection differs")
    if contract.derived_sha256 != DERIVED_STDIN_SHA256:
        raise RuntimeError("Linux derived stdin SHA-256 differs")
    if hashlib.sha256(contract.stdin).hexdigest() != DERIVED_STDIN_SHA256:
        raise RuntimeError("Linux derived stdin bytes differ")
    if contract.source_sha256 != frozen.shell.sha256:
        raise RuntimeError("Linux source shell boundary differs")
    # Older Phase A records cannot start this wrapper. A later reviewed change
    # must install the exact Phase A v3 runner and evidence pins.
    wrapper.execute_and_publish = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("Phase A v3 authority is not installed"))
    return wrapper, loaded


def preflight() -> dict[str, object]:
    """Verify the installed Linux wrapper while replay stays disabled."""
    wrapper, loaded = load_wrapper()
    contract = linux_retained_driver.derive_contract()
    return {
        "wrapper_sha256": WRAPPER_SHA256,
        "driver_adapter_sha256": DRIVER_ADAPTER_SHA256,
        "source_shell_sha256": contract.source_sha256,
        "derived_stdin_sha256": contract.derived_sha256,
        "argv": list(contract.argv),
        "phase_a_v3_required": True,
        "runtime_parent": str(wrapper.RUN_PARENT),
        "execution_enabled": False,
        "replay_run": False,
    }


if __name__ == "__main__":
    print(json.dumps(preflight(), sort_keys=True))
