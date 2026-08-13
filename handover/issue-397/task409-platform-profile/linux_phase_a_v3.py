#!/usr/bin/env python3
"""Bind the reviewed Phase A v2 mechanism to the Linux authority.

This adapter changes data bindings only. The verified v2 module still owns
stable reads, create-only publication, cleanup, Phase A validation, and the
external approval-anchor lifecycle. The durable commands are intentionally
separate. Running this module without a subcommand cannot create evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import types
from pathlib import Path
from typing import Any, Sequence

import linux_replay_wrapper
import platform_profile

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
V2_RUNNER_PATH = BASE / "task409-phase-a-anchor-successor" / "phase_a_anchor_runner.py"
V2_RUNNER_SHA256 = "fb11d84062c05a2054a2f4162908de54ed15a530538fbf671ee54ff999baaf84"
PROFILE_SHA256 = "ac89acb0e3f5dcab6d5ac86cab22b67a62d2b393e5e912366345828809906776"
LINUX_WRAPPER_ADAPTER_SHA256 = "2bb2366fde413edfe5b55e0babd099e6e970801fcddd56ecc9b222dc88e39162"
LINUX_DRIVER_ADAPTER_SHA256 = "00bf439d02e98753df0b49570145974f3307261e62763aab5937db13735fcd9b"
V3_SCHEMA = "hermternal.issue-397.phase-a-anchor-runner.v3"
V3_EVIDENCE_SCHEMA = "hermternal.issue-397.phase-a-anchor-evidence.v3"
V3_ROOT_NAME = "hermternal-issue397-phase-a-anchor-v3"
FINAL_PINS = {
    "candidate-five.md": "d43061e62886e50465ca73fa69b7e21994ed1cad3f186162583b47aeef3e8a3a",
    "candidate-five.json": "d04a7567c03b3dd7d129a224592a77ca06e0790460406fa2172232e00bfce035",
    "candidate-five.sh": "9995382f83d26bb22a8c7641c1dc2f5a7157b7530f9eaadd0b73e329ecf2e75f",
    "authority-descriptor.json": "f7cf533c43fa76165872c72ca256a65c6a8aad55bc3aef52a308ea5d4a356458",
    "provenance-manifest.json": "3ae36dcd2e9328d50e95a53c4bcc7f093c4d7c2379ec2cfe04339cac6374f118",
    "platform-adaptation-manifest.json": "ee0444e00045d5e63f845888beaabf9981f15e61da1015afff601fd55033fd62",
}


def _verified_module(path: Path, digest: str, name: str) -> types.ModuleType:
    """Compile only bytes that match one reviewed SHA-256."""
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise RuntimeError(f"{name} SHA-256 differs")
    module = types.ModuleType(name)
    module.__file__ = os.fspath(path)
    sys.modules[name] = module
    exec(compile(raw, os.fspath(path), "exec", dont_inherit=True), module.__dict__)
    return module


def _adapter_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _profile_record(profile: platform_profile.PlatformProfile) -> dict[str, str]:
    return {
        "profile_id": profile.profile_id,
        "profile_path": os.fspath(platform_profile.PROFILE_PATH),
        "profile_sha256": profile.sha256,
        "phase_a_adapter_sha256": _adapter_sha256(),
        "linux_wrapper_adapter_sha256": LINUX_WRAPPER_ADAPTER_SHA256,
        "linux_driver_adapter_sha256": LINUX_DRIVER_ADAPTER_SHA256,
    }


def _translate_code(function, profile: platform_profile.PlatformProfile):
    """Translate only profile-owned literals in one reviewed code object."""
    translations = {
        profile.predecessor_bindings["python3"]: profile.tools["python3"].path,
        profile.predecessor_bindings["temporary_parent"]: profile.temporary_parent,
    }

    def translate(value):
        if isinstance(value, types.CodeType):
            return value.replace(co_consts=tuple(translate(item) for item in value.co_consts))
        if isinstance(value, str):
            for old, new in translations.items():
                value = value.replace(old, new)
        return value

    code = translate(function.__code__)
    return types.FunctionType(code, function.__globals__, function.__name__, function.__defaults__, function.__closure__)


def load_runner() -> types.ModuleType:
    """Install the Linux profile as data on exact reviewed v2 runner code."""
    profile = platform_profile.load()
    if profile.sha256 != PROFILE_SHA256:
        raise RuntimeError("Linux profile SHA-256 differs")
    if hashlib.sha256(Path(linux_replay_wrapper.__file__).read_bytes()).hexdigest() != LINUX_WRAPPER_ADAPTER_SHA256:
        raise RuntimeError("Linux wrapper adapter SHA-256 differs")
    driver_path = HERE / "linux_retained_driver.py"
    if hashlib.sha256(driver_path.read_bytes()).hexdigest() != LINUX_DRIVER_ADAPTER_SHA256:
        raise RuntimeError("Linux driver adapter SHA-256 differs")
    runner = _verified_module(V2_RUNNER_PATH, V2_RUNNER_SHA256, "issue397_linux_phase_a_v3_base")
    runner.SCHEMA = V3_SCHEMA
    runner.EVIDENCE_SCHEMA = V3_EVIDENCE_SCHEMA
    runner.REPOSITORY_ROOT = Path(profile.source_repository)
    runner.FROZEN_COMMIT = profile.source_detached_head
    runner.AUTHORITY_REPOSITORY_ROOT = Path(profile.authority_root)
    runner.AUTHORITY_REL = Path(".")
    runner.EXTERNAL_ROOT = Path(profile.source_repository).parent / V3_ROOT_NAME
    runner.FINAL_PINS = dict(FINAL_PINS)
    runner.FINAL_NAMES = tuple(FINAL_PINS)
    predecessor_load_modules = runner.load_modules

    def profile_modules(root: Path = runner.REPOSITORY_ROOT):
        modules = predecessor_load_modules(root)
        # The genuine validator owns all policy checks. These two functions are
        # the same reviewed code with only profile-owned path constants changed.
        modules.phase_a._canonical_execution_contract = _translate_code(
            modules.phase_a._canonical_execution_contract, profile
        )
        modules.anchor.PHASE_A._canonical_execution_contract = _translate_code(
            modules.anchor.PHASE_A._canonical_execution_contract, profile
        )
        return modules

    runner.load_modules = profile_modules
    predecessor_owner = runner._owner_value

    def profile_owner() -> dict[str, Any]:
        value = dict(predecessor_owner())
        value["platform_profile"] = _profile_record(profile)
        return value

    runner._owner_value = profile_owner
    return runner


def phase_a() -> dict[str, Any]:
    """Run genuine Phase A against the fixed, absent durable v3 root."""
    runner = load_runner()
    return runner.phase_a(runner.load_modules(), repository_root=runner.REPOSITORY_ROOT, external_root=runner.EXTERNAL_ROOT)


def anchor(expected_phase_a_sha256: str) -> dict[str, Any]:
    """Resume one independently reviewed Phase A digest and create its anchor."""
    runner = load_runner()
    return runner.anchor(runner.load_modules(), repository_root=runner.REPOSITORY_ROOT, external_root=runner.EXTERNAL_ROOT, expected_phase_a_sha256=expected_phase_a_sha256)


def load_approved_wrapper(expected_anchor_sha256: str, expected_adapter_sha256: str):
    """Enable the reviewed boundary only after live v3 anchor authentication.

    The code-object change translates the one schema guard from v2 to v3. All
    other #405 validation and publication instructions stay byte-derived from
    the reviewed wrapper. This function does not call the boundary.
    """
    if expected_adapter_sha256 != _adapter_sha256():
        raise RuntimeError("Phase A v3 adapter SHA-256 differs")
    runner = load_runner()
    anchor_path = runner.EXTERNAL_ROOT / "evidence" / runner.ANCHOR_RECORD
    anchor_snapshot = runner.stable_read(anchor_path, "Phase A v3 anchor evidence")
    if anchor_snapshot.sha256 != expected_anchor_sha256:
        raise RuntimeError("Phase A v3 anchor evidence SHA-256 differs")
    runner._parse_closed_record(anchor_snapshot, "anchor", runner.EXTERNAL_ROOT)

    source = Path(linux_replay_wrapper.__file__).read_bytes()
    disabled = b'    wrapper.execute_and_publish = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("Phase A v3 authority is not installed"))\n'
    preserved = b"    wrapper._phase_a_v3_predecessor_execute_and_publish = wrapper.execute_and_publish\n"
    if source.count(disabled) != 1:
        raise RuntimeError("Linux wrapper disabled boundary anchor differs")
    derived = source.replace(disabled, preserved)
    module = types.ModuleType("issue397_linux_phase_a_v3_wrapper_derivation")
    module.__file__ = os.fspath(linux_replay_wrapper.__file__)
    sys.modules[module.__name__] = module
    exec(compile(derived, module.__file__, "exec", dont_inherit=True), module.__dict__)
    wrapper, authority = module.load_wrapper()
    original = wrapper._load_phase_a_evidence
    constants = tuple(V3_EVIDENCE_SCHEMA if item == "hermternal.issue-397.phase-a-anchor-evidence.v2" else item for item in original.__code__.co_consts)
    wrapper._load_phase_a_evidence = types.FunctionType(original.__code__.replace(co_consts=constants), original.__globals__, original.__name__, original.__defaults__, original.__closure__)
    wrapper.load_phase_a_evidence = wrapper._load_phase_a_evidence
    wrapper.PHASE_A_RUNNER_PATH = Path(__file__)
    wrapper.PHASE_A_RUNNER_SHA256 = expected_adapter_sha256
    wrapper.execute_and_publish = wrapper._phase_a_v3_predecessor_execute_and_publish
    return wrapper, authority


_EXPORT_RUNNER = load_runner()


def __getattr__(name: str):
    """Expose the reviewed runner interface without copying its implementation."""
    return getattr(_EXPORT_RUNNER, name)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["phase-a"]:
        print(json.dumps(phase_a(), sort_keys=True, separators=(",", ":")))
        return 0
    if len(arguments) == 3 and arguments[:2] == ["anchor", "--expected-phase-a-sha256"]:
        print(json.dumps(anchor(arguments[2]), sort_keys=True, separators=(",", ":")))
        return 0
    print("usage: linux_phase_a_v3.py phase-a | anchor --expected-phase-a-sha256 SHA256", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
