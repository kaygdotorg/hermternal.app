#!/usr/bin/env python3
"""Add the reviewed local object-preservation step to retained driver v6."""
from __future__ import annotations

import hashlib
from pathlib import Path

import linux_retained_driver_v6 as predecessor
import object_preservation

HERE = Path(__file__).resolve().parent
V6_PATH = HERE / "linux_retained_driver_v6.py"
V6_SHA256 = "4363f123a52863304f56eb6847c7e228fc43eae765eb1658d3c0cf521af88cde"
POLICY_PATH = HERE / "object_preservation.py"
POLICY_SHA256 = "1894901105a07fc925b7271bdb32b0cae92ffb80bd2cbbcd77c828a09819b57e"
PROOF_PATH = HERE / "forbidden_proof.py"
PROOF_SHA256 = "95009c152eb9dbd04cdef58a5c1dddcce8f79365b22a8aca60ab272266a100b6"
PRESERVATION_RECORD_SHA256 = "8aea6f4fcc34388362fff8840518d61f39ca8565548dc1b63e78de31101631c3"


def _authenticate() -> None:
    if hashlib.sha256(V6_PATH.read_bytes()).hexdigest() != V6_SHA256:
        raise RuntimeError("Linux retained-driver v6 SHA-256 differs")
    if hashlib.sha256(POLICY_PATH.read_bytes()).hexdigest() != POLICY_SHA256:
        raise RuntimeError("object preservation policy SHA-256 differs")
    if hashlib.sha256(PROOF_PATH.read_bytes()).hexdigest() != PROOF_SHA256:
        raise RuntimeError("forbidden proof policy SHA-256 differs")


def load_driver():
    """Reuse the exact authenticated v6 driver mechanics."""
    _authenticate()
    return predecessor.load_driver()


def preservation_record() -> dict[str, object]:
    """Return the canonical authority closure and forbidden-object binding."""
    _authenticate()
    authority = load_driver().load_frozen_authority().document
    record = object_preservation.build_record(authority, predecessor.forbidden_proof_record())
    if object_preservation.record_sha256(record) != PRESERVATION_RECORD_SHA256:
        raise RuntimeError("object preservation record SHA-256 differs")
    return record


def derive_contract():
    """Change only the clone object-availability predicate in derived stdin."""
    _authenticate()
    base = predecessor.derive_contract()
    record = preservation_record()
    stdin = object_preservation.repair_generated_validator(
        base.stdin, record, PRESERVATION_RECORD_SHA256, POLICY_PATH, POLICY_SHA256,
        PROOF_PATH, PROOF_SHA256
    )
    load_driver().compile_derived(stdin)
    return load_driver().DerivedDriver(
        base.argv, stdin, base.source_sha256, hashlib.sha256(stdin).hexdigest()
    )


def __getattr__(name: str):
    return getattr(predecessor, name)
