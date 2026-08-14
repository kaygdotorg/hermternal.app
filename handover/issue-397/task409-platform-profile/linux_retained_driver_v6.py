#!/usr/bin/env python3
"""Bind the retained driver to the immutable root-shape authority successor."""
from __future__ import annotations

import hashlib
import types
from pathlib import Path

import linux_retained_driver_v5 as predecessor
import linux_root_shape_authority_v4 as authority_v4

HERE = Path(__file__).resolve().parent
V5_PATH = HERE / "linux_retained_driver_v5.py"
V5_SHA256 = "0510d5f7ff5e011cb1875378ede3649222c8383ecb702978af8d791a408400e7"
AUTHORITY_GENERATOR_PATH = HERE / "linux_root_shape_authority_v4.py"
AUTHORITY_GENERATOR_SHA256 = "c6385587b52ba8477ced95fc9e2465dcd8716c76ec1ec3f77ec52e6d2c1ed4b3"
AUTHORITY_ROOT = authority_v4.AUTHORITY_ROOT
HASHES = {"authority-descriptor.json": "f127c148ac1b24254609b89e23becaec088d51b5d37817a5b70956546fbf2d50", "candidate-five.json": "c57d57a698ef76e91e29cf0241f9f0b98e5fb3ded75232fd54099178cfb6b0e3", "candidate-five.md": "e8c611e15a653d841f18a3e6b9304cb20d8f0f7948b94317e1ed85728c502e72", "candidate-five.sh": "a0c4f54e8d2e7d404327c12316dee67bb3e498f1e610851b6f58eb8e32226c32", "provenance-manifest.json": "fc43c26ee95a582669772441543a071f678081254c25daa27a589322d8ed7468", "root-shape-adaptation-manifest.json": "408667d7eeb84af1fc7aa356d86925a03990cfb90ff31801e895e5b8ec848f7b"}


def _authenticate() -> None:
    if hashlib.sha256(V5_PATH.read_bytes()).hexdigest() != V5_SHA256: raise RuntimeError("Linux retained-driver v5 SHA-256 differs")
    if hashlib.sha256(AUTHORITY_GENERATOR_PATH.read_bytes()).hexdigest() != AUTHORITY_GENERATOR_SHA256: raise RuntimeError("root-shape authority generator SHA-256 differs")


def load_driver():
    """Reuse v5 mechanics and authenticate the only changed parser authority."""
    _authenticate(); driver = predecessor.load_driver()
    def load_root_shape_authority():
        snapshots = {name: driver.stable_read(AUTHORITY_ROOT / name, f"root-shape authority {name}", mode=0o600) for name in HASHES}
        for name, snapshot in snapshots.items(): driver.require(snapshot.sha256 == HASHES[name], f"root-shape authority {name} SHA-256 differs")
        generated = authority_v4.generate(AUTHORITY_ROOT)
        for role, name in (("json", "candidate-five.json"), ("markdown", "candidate-five.md"), ("shell", "candidate-five.sh")): driver.require(generated[role] == snapshots[name].raw, f"root-shape authority generated {role} differs")
        document = driver._strict_json(snapshots["candidate-five.json"].raw, "root-shape authority JSON")
        adaptation = driver._strict_json(snapshots["root-shape-adaptation-manifest.json"].raw, "root-shape adaptation")
        expected = {"shared_source": "ASSERT_ROOT_SHAPE", "ledger_order": ["parent5", "root5", "root_real1", "child5"], "instantiations": ["clean-primary", "replay"], "root_realpath_required": True, "retained_ledgers": ["parent", "root", "child"]}
        driver.require(adaptation.get("schema") == authority_v4.ADAPTATION_SCHEMA and adaptation.get("semantic_change") == expected and adaptation.get("outputs") == {role: HASHES[name] for role, name in (("json", "candidate-five.json"), ("markdown", "candidate-five.md"), ("shell", "candidate-five.sh"))}, "root-shape adaptation manifest differs")
        authority = authority_v4.platform_successor.load_approved()[2]
        driver.require(authority.extract_shell(snapshots["candidate-five.md"].raw) == snapshots["candidate-five.sh"].raw, "root-shape Markdown shell differs")
        driver.require(document["execution_driver"]["shell"].encode() == snapshots["candidate-five.sh"].raw, "root-shape JSON shell differs")
        return driver.FrozenAuthority(snapshots["authority-descriptor.json"], snapshots["provenance-manifest.json"], snapshots["candidate-five.json"], snapshots["candidate-five.md"], snapshots["candidate-five.sh"], document)
    driver.load_frozen_authority = load_root_shape_authority
    return driver


def derive_contract():
    """Run the exact v5 derivation code with this authenticated authority loader."""
    _authenticate()
    return types.FunctionType(predecessor.derive_contract.__code__, {**predecessor.derive_contract.__globals__, "load_driver": load_driver}, predecessor.derive_contract.__name__, predecessor.derive_contract.__defaults__, predecessor.derive_contract.__closure__)()


def __getattr__(name: str): return getattr(predecessor, name)
