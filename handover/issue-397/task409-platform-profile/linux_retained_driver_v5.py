#!/usr/bin/env python3
"""Bind the retained replay driver to the immutable parent-binding authority."""
from __future__ import annotations

import hashlib
import types
from pathlib import Path

import linux_parent_binding_authority_v3 as authority_v3
import linux_retained_driver_v4 as predecessor

HERE = Path(__file__).resolve().parent
V4_PATH = HERE / "linux_retained_driver_v4.py"
V4_SHA256 = "9a3f8dadbd1e013b5d663a72433c133cb12eede277ef677f04b620fab34d832d"
AUTHORITY_GENERATOR_PATH = HERE / "linux_parent_binding_authority_v3.py"
AUTHORITY_GENERATOR_SHA256 = "9afa3fff6f897bbaac8d3a004080688bf7bf3c5746bb7e266dbb8ce5660f1928"
AUTHORITY_ROOT = authority_v3.AUTHORITY_ROOT
HASHES = {
    "authority-descriptor.json": "16a701069da72603f9bd91beca83f8bd98f980daf934da6c708d32a8d2368126",
    "candidate-five.json": "2d299aca62ee229d71c505eab978d04c9d66e7894fc1bfa8bc2b5a0f86323a73",
    "candidate-five.md": "27beef574daa3326b361778603279262ca1d0ecf2a8e67dd82c46c74b5f36e3e",
    "candidate-five.sh": "6b80b817dfabef66ef2ed2da4200e0e9e72aabd10b71de3edcfc5268869fbce1",
    "parent-binding-adaptation-manifest.json": "43e2b9fa72214d730fe83cdeebb2cab977c50d43ad9b52e1432028028ffb735f",
    "provenance-manifest.json": "37efac7140ec1807574af263e43e4e54425f9bc78f964198ece5542d1e1eca16",
}


def _authenticate() -> None:
    if hashlib.sha256(V4_PATH.read_bytes()).hexdigest() != V4_SHA256:
        raise RuntimeError("Linux retained-driver v4 SHA-256 differs")
    if hashlib.sha256(AUTHORITY_GENERATOR_PATH.read_bytes()).hexdigest() != AUTHORITY_GENERATOR_SHA256:
        raise RuntimeError("parent-binding authority generator SHA-256 differs")


def load_driver():
    """Reuse v4 mechanics while authenticating all v3 authority inputs."""
    _authenticate()
    driver = predecessor.load_driver()

    def load_parent_binding_authority():
        snapshots = {name: driver.stable_read(AUTHORITY_ROOT / name, f"parent-binding authority {name}", mode=0o600) for name in HASHES}
        for name, snapshot in snapshots.items():
            driver.require(snapshot.sha256 == HASHES[name], f"parent-binding authority {name} SHA-256 differs")
        generated = authority_v3.generate(AUTHORITY_ROOT)
        for role, name in (("json", "candidate-five.json"), ("markdown", "candidate-five.md"), ("shell", "candidate-five.sh")):
            driver.require(generated[role] == snapshots[name].raw, f"parent-binding authority generated {role} differs")
        document = driver._strict_json(snapshots["candidate-five.json"].raw, "parent-binding authority JSON")
        adaptation = driver._strict_json(snapshots["parent-binding-adaptation-manifest.json"].raw, "parent-binding adaptation")
        change = adaptation.get("semantic_change")
        driver.require(adaptation.get("schema") == authority_v3.ADAPTATION_SCHEMA and adaptation.get("outputs") == {role: HASHES[name] for role, name in (("json", "candidate-five.json"), ("markdown", "candidate-five.md"), ("shell", "candidate-five.sh"))}, "parent-binding adaptation manifest differs")
        driver.require(change == {"shared_source": "ROOT_PY", "instantiations": ["clean-primary", "replay"], "parent_binding": ["st_dev", "st_ino", "st_uid", "mode"], "excluded_intra_call_fields": ["st_nlink", "st_mtime", "st_ctime"], "retained_ledgers": ["parent", "root", "child"]}, "parent-binding adaptation semantics differ")
        authority = authority_v3.platform_successor.load_approved()[2]
        driver.require(authority.extract_shell(snapshots["candidate-five.md"].raw) == snapshots["candidate-five.sh"].raw, "parent-binding Markdown shell differs")
        driver.require(document["execution_driver"]["shell"].encode("utf-8") == snapshots["candidate-five.sh"].raw, "parent-binding JSON shell differs")
        return driver.FrozenAuthority(snapshots["authority-descriptor.json"], snapshots["provenance-manifest.json"], snapshots["candidate-five.json"], snapshots["candidate-five.md"], snapshots["candidate-five.sh"], document)

    driver.load_frozen_authority = load_parent_binding_authority
    return driver


def derive_contract():
    """Execute the exact v4 derivation code with only this authority loader."""
    _authenticate()
    inherited = types.FunctionType(predecessor.derive_contract.__code__, {**predecessor.derive_contract.__globals__, "load_driver": load_driver}, predecessor.derive_contract.__name__, predecessor.derive_contract.__defaults__, predecessor.derive_contract.__closure__)
    return inherited()


def __getattr__(name: str):
    return getattr(predecessor, name)
