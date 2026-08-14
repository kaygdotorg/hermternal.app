#!/usr/bin/env python3
"""Expose the authenticated v11 Linux publication to offline gates.

This adapter does not authorize or run replay. It converts the already-published
v11 records to the small read-only interface that the #406 gate parser uses.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any

BASE = Path(__file__).resolve().parents[1]
SCHEMA_PATH = BASE / "task409-replay-result-successor" / "replay_result_successor.py"
SCHEMA_SHA256 = "a8a00bab2d221c5231ddc1f03eba1e0113ed252eecce43df1f8493df0160be60"
SCHEMA_MODULE_NAME = f"{__name__}.issue397_publication_schema_base"
AUTHORITY_ROOT = Path("/tmp/hermternal-397-integrate/handover/issue-397/task464-candidate5-linux-v3-root-shape-final")
TRACKED_AUTHORITY_ROOT = BASE / "task464-candidate5-linux-v3-root-shape-final"
OWNER_PATH = Path("/home/kayg/Developer/hermternal-issue397-phase-a-anchor-v11/phase-a/.owner")
OWNER_SHA256 = "2d9fd17afce1bc419811b726de6e6c218c5f318a551903195a4ba7e9c59797b6"
ANCHOR_PATH = Path("/home/kayg/Developer/hermternal-issue397-phase-a-anchor-v11/evidence/anchor.json")
ANCHOR_SHA256 = "60692a0c9bb81ddb663fa20f74819e0db6e9a87f4d9d6e63faecd351ca811da2"
EVIDENCE_SCHEMA = "hermternal.issue-397.phase-a-anchor-evidence.v11"
DRIVER_SHA256 = "6592efac6ec27fde1508372d1ee2f9402cac0fdd9e6fd44276b2af8dffe54382"
STDERR_POLICY = "exact-known-clone-init-notices"
AUTHORITY_HASHES = {
    "authority-descriptor.json": "f127c148ac1b24254609b89e23becaec088d51b5d37817a5b70956546fbf2d50",
    "candidate-five.json": "c57d57a698ef76e91e29cf0241f9f0b98e5fb3ded75232fd54099178cfb6b0e3",
    "candidate-five.md": "e8c611e15a653d841f18a3e6b9304cb20d8f0f7948b94317e1ed85728c502e72",
    "candidate-five.sh": "a0c4f54e8d2e7d404327c12316dee67bb3e498f1e610851b6f58eb8e32226c32",
    "provenance-manifest.json": "fc43c26ee95a582669772441543a071f678081254c25daa27a589322d8ed7468",
    "root-shape-adaptation-manifest.json": "408667d7eeb84af1fc7aa356d86925a03990cfb90ff31801e895e5b8ec848f7b",
}


class Reject(Exception):
    """The publication is not the approved v11 byte set."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise Reject(message)


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_uid, stat.S_IMODE(value.st_mode), value.st_size, value.st_nlink, value.st_mtime_ns, value.st_ctime_ns)


def _read(path: Path, label: str, mode: int, limit: int = 8 * 1024 * 1024) -> SimpleNamespace:
    path = Path(path)
    _require(path.is_absolute() and os.path.realpath(path) == os.fspath(path), f"{label} path differs")
    values: list[SimpleNamespace] = []
    for _ in range(3):
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            before = os.fstat(descriptor)
            _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == mode and 0 < before.st_size <= limit, f"{label} metadata differs")
            raw = bytearray()
            while True:
                block = os.read(descriptor, min(131072, limit + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
                _require(len(raw) <= limit, f"{label} exceeds its limit")
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        final = os.lstat(path)
        _require(_identity(before) == _identity(after) == _identity(final), f"{label} changed")
        values.append(SimpleNamespace(path=path, raw=bytes(raw), sha256=_digest(bytes(raw)), identity=_identity(before)))
    _require(all(vars(value) == vars(values[0]) for value in values[1:]), f"{label} changed across reads")
    return values[0]


def _json(snapshot: SimpleNamespace, label: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            _require(key not in value, f"{label} has a duplicate key")
            value[key] = item
        return value
    try:
        value = json.loads(snapshot.raw.decode("utf-8"), object_pairs_hook=pairs)
    except Reject:
        raise
    except Exception as error:
        raise Reject(f"{label} is not strict JSON") from error
    _require(isinstance(value, dict), f"{label} root differs")
    return value


def _load_schema() -> types.ModuleType:
    """Hash source bytes before execution and reject a preloaded cache entry."""
    source = _read(SCHEMA_PATH.resolve(), "tracked result schema", 0o644, 2 * 1024 * 1024)
    _require(source.sha256 == SCHEMA_SHA256, "tracked result schema SHA-256 differs")
    _require(SCHEMA_MODULE_NAME not in sys.modules, "tracked result schema cache is preloaded")
    module = types.ModuleType(SCHEMA_MODULE_NAME)
    module.__file__ = os.fspath(source.path)
    sys.modules[SCHEMA_MODULE_NAME] = module
    try:
        exec(compile(source.raw, os.fspath(source.path), "exec", dont_inherit=True), module.__dict__)
    except Exception:
        if sys.modules.get(SCHEMA_MODULE_NAME) is module:
            del sys.modules[SCHEMA_MODULE_NAME]
        raise
    _require(sys.modules.get(SCHEMA_MODULE_NAME) is module, "tracked result schema cache changed during execution")
    del sys.modules[SCHEMA_MODULE_NAME]
    return module


_SCHEMA = _load_schema()
_require(_SCHEMA.RESULT_SCHEMA == "task409-execution-preflight/replay-result/v2", "result schema source differs")
_require(_SCHEMA.COMPLETION_SCHEMA == "hermternal.issue-397.replay-completion/v2", "completion schema source differs")
_require(_SCHEMA.STDERR_POLICY == "empty" and _SCHEMA.DRIVER_SHA256 == "3e3dc1444879b416fa7e8e884a3523566ba9f4a9a96f2857380d8c4869917e20", "retired source boundary differs")
RESULT_KEYS = _SCHEMA.RESULT_KEYS
RESULT_SCHEMA = _SCHEMA.RESULT_SCHEMA
RESULT_PHASE = _SCHEMA.RESULT_PHASE
RESULT_LANE = _SCHEMA.RESULT_LANE
COMPLETION_KEYS = _SCHEMA.COMPLETION_KEYS
COMPLETION_SCHEMA = _SCHEMA.COMPLETION_SCHEMA
SUCCESS_OUTPUT = _SCHEMA.SUCCESS_OUTPUT


def _v11_records() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    owner_snapshot = _read(OWNER_PATH, "v11 owner", 0o600)
    anchor_snapshot = _read(ANCHOR_PATH, "v11 anchor", 0o600)
    _require(owner_snapshot.sha256 == OWNER_SHA256 and anchor_snapshot.sha256 == ANCHOR_SHA256, "v11 record SHA-256 differs")
    owner, anchor = _json(owner_snapshot, "v11 owner"), _json(anchor_snapshot, "v11 anchor")
    _require(owner.get("schema") == "hermternal.issue-397.phase-a-anchor-runner.v11", "old Phase authority is not accepted")
    _require(anchor.get("schema") == EVIDENCE_SCHEMA, "old Phase evidence is not accepted")
    profile = owner.get("platform_profile")
    _require(isinstance(profile, dict), "v11 owner profile differs")
    _require(profile.get("linux_driver_adapter_sha256") == "4363f123a52863304f56eb6847c7e228fc43eae765eb1658d3c0cf521af88cde" and profile.get("linux_wrapper_adapter_sha256") == "c8887fd0449ad6af3cfdebb721cf14ef9c91840f4d9b35e53f47b150f9821331" and profile.get("phase_a_adapter_sha256") == "15e1492607fcb43f14cd290eef9e0e3df6d4b4a19e5b4bbf278b69647853461b", "v11 owner predecessor bindings differ")
    observed = anchor.get("observations", {}).get("authority_files")
    _require(isinstance(observed, dict) and set(observed) == set(AUTHORITY_HASHES), "v11 authority file set differs")
    authority_values: dict[str, SimpleNamespace] = {}
    for name, expected in AUTHORITY_HASHES.items():
        snapshot = _read((TRACKED_AUTHORITY_ROOT / name).resolve(), f"tracked authority {name}", 0o644)
        _require(snapshot.sha256 == expected and observed.get(name, {}).get("sha256") == expected, f"{name} publication SHA-256 differs")
        authority_values[name] = snapshot
    return owner, anchor, _json(authority_values["candidate-five.json"], "tracked candidate authority")


def load() -> SimpleNamespace:
    """Return the exact path-bound Linux authority root for the profile seam."""
    _v11_records()
    _require(AUTHORITY_ROOT.resolve() == AUTHORITY_ROOT, "Linux authority root path differs")
    return SimpleNamespace(authority_root=os.fspath(AUTHORITY_ROOT))


def load_authority() -> SimpleNamespace:
    """Return only authority fields that the offline chain compares."""
    _, _, candidate = _v11_records()
    base = candidate.get("base")
    forbidden = candidate.get("forbidden_ancestry")
    lanes = candidate.get("ordered_lanes")
    _require(isinstance(base, dict) and isinstance(forbidden, dict) and isinstance(lanes, list), "candidate authority structure differs")
    commits = forbidden.get("commits")
    raw = forbidden.get("raw_semantic_source_commits")
    _require(isinstance(commits, list) and isinstance(raw, list), "candidate forbidden authority differs")
    sources = [lane.get("source_commit", {}).get("commit") for lane in lanes if isinstance(lane, dict) and isinstance(lane.get("source_commit"), dict)]
    _require(sources and sources[0] == "d3c40687659ee645a5f03bc80cbf61ec8c49979a", "candidate source authority differs")
    return SimpleNamespace(base_commit=base.get("commit"), base_tree=base.get("tree"), protected_main_commit=base.get("protected_main_commit"), required_ancestors=[base.get("commit")], forbidden_ancestors=list(dict.fromkeys([*commits, *raw])), source_commit=sources[0])


def load_phase_a_evidence(path: Path, expected_sha256: str) -> SimpleNamespace:
    """Load the exact durable v11 anchor without importing its mutable closure."""
    supplied = Path(path).resolve()
    _require(supplied == ANCHOR_PATH and expected_sha256 == ANCHOR_SHA256, "v11 Phase evidence binding differs")
    _, anchor, _ = _v11_records()
    snapshot = _read(supplied, "v11 anchor", 0o600)
    inputs = anchor.get("inputs")
    _require(isinstance(inputs, dict), "v11 Phase inputs differ")
    manifest = inputs.get("phase_a_manifest_sha256")
    approval = inputs.get("phase_a_approval_digest")
    _require(manifest == "c83846f231f0b9b4c2d614a42da56984d75356bcf01a5e00fa221be3bc39c1a3" and approval == "c8a164287585de220eb22afe2cc35d06468b64e070b398b41892daa4c2b17720", "v11 Phase approval differs")
    return SimpleNamespace(snapshot=snapshot, manifest_sha256=manifest, approval_digest=approval, live_record=anchor)
