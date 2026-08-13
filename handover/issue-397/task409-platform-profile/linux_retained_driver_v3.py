#!/usr/bin/env python3
"""Bind the retained driver to the reviewed missing-object proof policy.

The frozen authority stays unchanged. This successor changes only the three
generated predicates that consume forbidden historical object availability.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import forbidden_proof
import linux_retained_driver_v2

HERE = Path(__file__).resolve().parent
V2_PATH = HERE / "linux_retained_driver_v2.py"
V2_SHA256 = "77f7fc5262b5f4eb3b9eff336ebc50b1ed1a6b46d124f42d91ff444ec0db03be"
PROOF_PATH = HERE / "forbidden_proof.py"
PROOF_SHA256 = "95009c152eb9dbd04cdef58a5c1dddcce8f79365b22a8aca60ab272266a100b6"


def _authenticate() -> None:
    if hashlib.sha256(V2_PATH.read_bytes()).hexdigest() != V2_SHA256:
        raise RuntimeError("Linux retained-driver v2 SHA-256 differs")
    if hashlib.sha256(PROOF_PATH.read_bytes()).hexdigest() != PROOF_SHA256:
        raise RuntimeError("forbidden proof policy SHA-256 differs")


def load_driver():
    """Return the unchanged reviewed authority loader."""
    _authenticate()
    return linux_retained_driver_v2.load_driver()


def forbidden_proof_record():
    """Classify the complete frozen forbidden list against the profile source."""
    _authenticate()
    profile = linux_retained_driver_v2.platform_profile.load()
    authority = load_driver().load_frozen_authority().document
    forbidden = authority["forbidden_ancestry"]
    forbidden_oids = [*forbidden["commits"], *forbidden["raw_semantic_source_commits"]]
    closure_roots = [authority["base"]["commit"], authority["base"]["protected_main_commit"], profile.source_detached_head]
    return forbidden_proof.classify(
        Path(profile.source_repository), profile.source_detached_head,
        forbidden_oids, closure_roots,
    )


def derive_contract():
    """Return v2 authority with the bound forbidden-object proof predicate."""
    _authenticate()
    base = linux_retained_driver_v2.derive_contract()
    proof = forbidden_proof_record()
    proof_sha256 = forbidden_proof.record_sha256(proof)
    stdin = forbidden_proof.repair_generated_validator(base.stdin, proof, proof_sha256)
    driver = load_driver()
    driver.compile_derived(stdin)
    return driver.DerivedDriver(base.argv, stdin, base.source_sha256, hashlib.sha256(stdin).hexdigest())


def __getattr__(name: str):
    """Expose unchanged v2 profile and data helpers."""
    return getattr(linux_retained_driver_v2, name)


if __name__ == "__main__":
    contract = derive_contract()
    proof = forbidden_proof_record()
    print(json.dumps({"argv": list(contract.argv), "source_sha256": contract.source_sha256,
                      "derived_sha256": contract.derived_sha256, "bytes": len(contract.stdin),
                      "forbidden_proof_sha256": forbidden_proof.record_sha256(proof),
                      "replay_run": False}, sort_keys=True))
