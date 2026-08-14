#!/usr/bin/env python3
"""Bind the derived replay contract to the corrected LF authority triad."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import forbidden_proof
import git_config_policy
import linux_anchor_authority_v2 as authority_v2
import linux_retained_driver as retained_v1
import linux_retained_driver_v3 as predecessor
import platform_profile
import section_anchor_metadata as anchor

HERE = Path(__file__).resolve().parent
V3_PATH = HERE / "linux_retained_driver_v3.py"
V3_SHA256 = "b19072f9d6cbc6cb9e6fc271bf468ffe182c3e4b7e1f04b0f6f4c7a54fcc2de5"
AUTHORITY_GENERATOR_PATH = HERE / "linux_anchor_authority_v2.py"
AUTHORITY_GENERATOR_SHA256 = "32d8e751a2398a0530213559ea185547f1fd8bbab51ad4bc3f1115825a23331f"
AUTHORITY_ROOT = authority_v2.AUTHORITY_ROOT
HASHES = {
    "authority-descriptor.json": "1cceb57ced07178789e408c3bf4d163e18e3900826461c77a020bfa30e1efdd5",
    "candidate-five.json": "6549438c08905e4d278ccfaa028925d181a1ce032fa7793c9ec41899145826a1",
    "candidate-five.md": "3f3cc9d724fd08b0805a2a503e303b63ae239d7d974f1e92b8b93d54c2fe8947",
    "candidate-five.sh": "f811dbd09b73c5aa6a1a426773a0f27c636a9a66dd3e16b077f58204e1cf6cf6",
    "provenance-manifest.json": "0490512c1b2e2cd4e271849081201fda3582098c0b83bb3356540ab822377a30",
    "platform-adaptation-manifest.json": "e84f3a5fa56640b495831d3710c2f262c3ea0c5e61162dc6a8fc363826515903",
}


def _authenticate() -> None:
    if hashlib.sha256(V3_PATH.read_bytes()).hexdigest() != V3_SHA256:
        raise RuntimeError("Linux retained-driver v3 SHA-256 differs")
    if hashlib.sha256(AUTHORITY_GENERATOR_PATH.read_bytes()).hexdigest() != AUTHORITY_GENERATOR_SHA256:
        raise RuntimeError("LF authority generator SHA-256 differs")


def load_driver():
    """Load predecessor mechanics with a separately pinned corrected triad."""
    _authenticate()
    driver = predecessor.load_driver()

    def load_corrected_authority():
        snapshots = {name: driver.stable_read(AUTHORITY_ROOT / name, f"LF authority {name}", mode=0o600) for name in HASHES}
        for name, snapshot in snapshots.items():
            driver.require(snapshot.sha256 == HASHES[name], f"LF authority {name} SHA-256 differs")
        generated = authority_v2.generate(AUTHORITY_ROOT)
        for role, name in (("json", "candidate-five.json"), ("markdown", "candidate-five.md"), ("shell", "candidate-five.sh")):
            driver.require(generated[role] == snapshots[name].raw, f"LF authority generated {role} differs")
        document = anchor.strict_document(snapshots["candidate-five.json"].raw, "LF authority JSON")
        anchor.anchor_value(document, "LF authority JSON")
        authority = authority_v2.platform_successor.load_approved()[2]
        driver.require(authority.extract_shell(snapshots["candidate-five.md"].raw) == snapshots["candidate-five.sh"].raw, "LF authority Markdown shell differs")
        driver.require(document["execution_driver"]["shell"].encode("utf-8") == snapshots["candidate-five.sh"].raw, "LF authority JSON shell differs")
        adaptation = driver._strict_json(snapshots["platform-adaptation-manifest.json"].raw, "LF authority adaptation")
        driver.require(adaptation["semantic_change"] == {"path": list(anchor.ANCHOR_PATH), "from": anchor.LEGACY_DOUBLE_ESCAPED_ANCHOR, "to": anchor.CANONICAL_ANCHOR}, "LF authority metadata adaptation differs")
        return driver.FrozenAuthority(snapshots["authority-descriptor.json"], snapshots["provenance-manifest.json"], snapshots["candidate-five.json"], snapshots["candidate-five.md"], snapshots["candidate-five.sh"], document)

    driver.load_frozen_authority = load_corrected_authority
    return driver


def forbidden_proof_record():
    """Reuse the exact forbidden-object proof over the corrected authority."""
    _authenticate()
    profile = platform_profile.load()
    authority = load_driver().load_frozen_authority().document
    forbidden = authority["forbidden_ancestry"]
    return forbidden_proof.classify(Path(profile.source_repository), profile.source_detached_head,
                                   [*forbidden["commits"], *forbidden["raw_semantic_source_commits"]],
                                   [authority["base"]["commit"], authority["base"]["protected_main_commit"], profile.source_detached_head])


def derive_contract():
    """Apply the existing appendix, config, and forbidden-proof repairs once."""
    _authenticate()
    driver = load_driver()
    profile = platform_profile.load()
    authority = driver.load_frozen_authority()
    compatibility_raw = authority.shell.raw.replace(profile.temporary_parent.encode(), profile.predecessor_bindings["temporary_parent"].encode())
    compatibility_shell = driver.Snapshot(authority.shell.path, compatibility_raw, hashlib.sha256(compatibility_raw).hexdigest(), authority.shell.identity)
    def compatible(value):
        if isinstance(value, dict): return {key: compatible(item) for key, item in value.items()}
        if isinstance(value, list): return [compatible(item) for item in value]
        return value.replace(profile.temporary_parent, profile.predecessor_bindings["temporary_parent"]) if isinstance(value, str) else value
    compatibility = driver.FrozenAuthority(authority.descriptor, authority.provenance, authority.json, authority.markdown, compatibility_shell, compatible(authority.document))
    stdin = driver.transform_shell(compatibility).replace(profile.predecessor_bindings["temporary_parent"].encode(), profile.temporary_parent.encode())
    stdin = retained_v1._repair_markdown_appendix_parser(stdin)
    stdin = git_config_policy.repair_generated_validator(stdin)
    proof = forbidden_proof_record()
    stdin = forbidden_proof.repair_generated_validator(stdin, proof, forbidden_proof.record_sha256(proof))
    driver.compile_derived(stdin)
    return driver.DerivedDriver(tuple(authority.document["execution_driver"]["argv"]), stdin, authority.shell.sha256, hashlib.sha256(stdin).hexdigest())


def __getattr__(name: str):
    return getattr(predecessor, name)


if __name__ == "__main__":
    contract = derive_contract()
    print(json.dumps({"argv": list(contract.argv), "source_sha256": contract.source_sha256, "derived_sha256": contract.derived_sha256, "bytes": len(contract.stdin), "replay_run": False}, sort_keys=True))
