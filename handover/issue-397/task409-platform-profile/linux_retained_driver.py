#!/usr/bin/env python3
"""Derive the retained driver from the Linux platform successor.

This adapter verified-loads the reviewed retained-driver transform. It replaces
only its frozen-authority loader, so replay lifecycle semantics stay in the
reviewed module and platform bindings stay in the immutable profile.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import types
from pathlib import Path

import platform_profile

BASE = Path(__file__).resolve().parents[1]
DRIVER_PATH = BASE / "task409-retained-driver-successor" / "retained_driver_successor.py"
DRIVER_SHA256 = "3e3dc1444879b416fa7e8e884a3523566ba9f4a9a96f2857380d8c4869917e20"
AUTHORITY_PATH = BASE / "task464-candidate5-authority-successor" / "candidate5_authority.py"
AUTHORITY_SHA256 = "1eec1b59f608a3c64d4abb532fe6dbe031c4ba8008b46775db3ee6a75c9bb9a8"
HASHES = {
    "authority-descriptor.json": "f7cf533c43fa76165872c72ca256a65c6a8aad55bc3aef52a308ea5d4a356458",
    "candidate-five.json": "d04a7567c03b3dd7d129a224592a77ca06e0790460406fa2172232e00bfce035",
    "candidate-five.md": "d43061e62886e50465ca73fa69b7e21994ed1cad3f186162583b47aeef3e8a3a",
    "candidate-five.sh": "9995382f83d26bb22a8c7641c1dc2f5a7157b7530f9eaadd0b73e329ecf2e75f",
    "provenance-manifest.json": "3ae36dcd2e9328d50e95a53c4bcc7f093c4d7c2379ec2cfe04339cac6374f118",
    "platform-adaptation-manifest.json": "ee0444e00045d5e63f845888beaabf9981f15e61da1015afff601fd55033fd62",
}
OLD_APPENDIX_PARSER = b"""appendix_heading_start = markdown_bytes.index(appendix_heading)
appendix_opening_start = markdown_bytes.index(appendix_opening, appendix_heading_start + len(appendix_heading))
appendix_body_start = appendix_opening_start + len(appendix_opening)
appendix_closing_start = markdown_bytes.index(appendix_closing, appendix_body_start)
appendix = json.loads(markdown_bytes[appendix_body_start:appendix_closing_start].decode('utf-8'))
"""
NEW_APPENDIX_PARSER = b"""def parse_markdown_parity_appendix(markdown_bytes, heading, opening, closing):
    boundary = b'<!-- candidate-five non-authority fence boundary -->'
    if closing != b'```':
        raise SystemExit('Markdown parity appendix closing metadata differs')
    if markdown_bytes.count(heading) != 1 or markdown_bytes.count(opening) != 1 or markdown_bytes.count(boundary) != 1:
        raise SystemExit('Markdown parity appendix anchors are not unique')
    heading_start = markdown_bytes.find(heading)
    opening_start = markdown_bytes.find(opening, heading_start + len(heading))
    if heading_start < 0 or opening_start < heading_start + len(heading):
        raise SystemExit('Markdown parity appendix anchor order differs')
    body_start = opening_start + len(opening)
    try:
        body_text = markdown_bytes[body_start:].decode('utf-8')
        appendix, character_end = json.JSONDecoder().raw_decode(body_text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit('Markdown parity appendix JSON differs') from exc
    body_end = body_start + len(body_text[:character_end].encode('utf-8'))
    if markdown_bytes[body_end:] != b'\\n' + boundary + b'\\n':
        raise SystemExit('Markdown parity appendix durable boundary differs')
    return appendix
appendix = parse_markdown_parity_appendix(markdown_bytes, appendix_heading, appendix_opening, appendix_closing)
"""


def _module(path: Path, digest: str, name: str) -> types.ModuleType:
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise RuntimeError(f"{name} SHA-256 differs")
    module = types.ModuleType(name)
    module.__file__ = os.fspath(path)
    sys.modules[name] = module
    exec(compile(raw, os.fspath(path), "exec", dont_inherit=True), module.__dict__)
    return module


def _repair_markdown_appendix_parser(stdin: bytes) -> bytes:
    """Replace the obsolete fence search at one authenticated code anchor.

    The approved #403 generator changes all non-authority closing fences to a
    durable HTML boundary. The frozen validator still searches for the old
    fence. Parse one JSON value, then require the exact generated suffix.
    """
    if stdin.count(OLD_APPENDIX_PARSER) != 1 or stdin.count(NEW_APPENDIX_PARSER) != 0:
        raise RuntimeError("Markdown appendix parser anchor differs")
    repaired = stdin.replace(OLD_APPENDIX_PARSER, NEW_APPENDIX_PARSER, 1)
    if repaired.count(OLD_APPENDIX_PARSER) != 0 or repaired.count(NEW_APPENDIX_PARSER) != 1:
        raise RuntimeError("Markdown appendix parser replacement differs")
    return repaired


def load_driver() -> types.ModuleType:
    """Install the Linux authority callback into exact reviewed driver code."""
    profile = platform_profile.load()
    final_root = Path(profile.authority_root)
    driver = _module(DRIVER_PATH, DRIVER_SHA256, "issue397_linux_retained_driver_base")
    authority = _module(AUTHORITY_PATH, AUTHORITY_SHA256, "issue397_linux_retained_driver_authority")

    def load_linux_authority():
        descriptor = driver.stable_read(final_root / "authority-descriptor.json", "Linux authority descriptor", mode=0o600)
        provenance = driver.stable_read(final_root / "provenance-manifest.json", "Linux provenance manifest", mode=0o600)
        adaptation = driver.stable_read(final_root / "platform-adaptation-manifest.json", "Linux platform adaptation", mode=0o600)
        json_snapshot = driver.stable_read(final_root / "candidate-five.json", "Linux candidate JSON", mode=0o600)
        markdown = driver.stable_read(final_root / "candidate-five.md", "Linux candidate Markdown", mode=0o600)
        shell = driver.stable_read(final_root / "candidate-five.sh", "Linux candidate shell", mode=0o600)
        for name, snapshot in (("authority-descriptor.json", descriptor), ("provenance-manifest.json", provenance), ("candidate-five.json", json_snapshot), ("candidate-five.md", markdown), ("candidate-five.sh", shell)):
            driver.require(snapshot.sha256 == HASHES[name], f"Linux {name} SHA-256 differs")
        driver.require(adaptation.sha256 == HASHES["platform-adaptation-manifest.json"], "Linux adaptation SHA-256 differs")
        adaptation_value = driver._strict_json(adaptation.raw, "Linux platform adaptation")
        driver.require(adaptation_value["schema"] == "hermternal.issue-397.platform-adaptation/v1", "Linux adaptation schema differs")
        driver.require(adaptation_value["profile"] == {"path": os.fspath(platform_profile.PROFILE_PATH), "sha256": profile.sha256, "profile_id": profile.profile_id}, "Linux adaptation profile binding differs")
        driver.require([item["from"] for item in adaptation_value["semantic_changes"]] == [profile.predecessor_bindings["python3"], profile.predecessor_bindings["source_repository"]], "Linux adaptation predecessor changes differ")
        driver.require([item["to"] for item in adaptation_value["semantic_changes"]] == [profile.tools["python3"].path, profile.source_repository], "Linux adaptation successor changes differ")
        validated = authority.validate(descriptor.path, final_root, descriptor.sha256)
        driver.require(validated.artifacts["json"].raw == json_snapshot.raw and validated.artifacts["markdown"].raw == markdown.raw and validated.artifacts["shell"].raw == shell.raw, "Linux #401 bytes differ")
        document = driver._strict_json(json_snapshot.raw, "Linux candidate JSON")
        driver.require(document["execution_driver"]["shell"].encode() == shell.raw, "Linux JSON shell differs")
        driver.require(authority.extract_shell(markdown.raw) == shell.raw, "Linux Markdown shell differs")
        driver.require(document["execution_driver"]["trusted_executables"]["python3"] == profile.tools["python3"].path, "Linux Python profile binding differs")
        driver.require(document["execution_driver"]["primary_repository"] == profile.source_repository, "Linux source profile binding differs")
        provenance_value = driver._strict_json(provenance.raw, "Linux provenance")
        driver.require(provenance_value["repository_boundary"] == {"output_root": os.fspath(final_root)}, "Linux provenance root differs")
        return driver.FrozenAuthority(descriptor, provenance, json_snapshot, markdown, shell, document)

    driver.load_frozen_authority = load_linux_authority
    return driver


def derive_contract():
    """Return the exact argv and derived stdin for the trusted outer wrapper."""
    driver = load_driver()
    profile = platform_profile.load()
    authority = driver.load_frozen_authority()
    # The reviewed transform has exact anchors that contain its predecessor
    # temporary parent. Reconstruct that anchor form in memory, apply the exact
    # transform, then derive the runtime parent from the immutable profile.
    compatibility_raw = authority.shell.raw.replace(profile.temporary_parent.encode(), profile.predecessor_bindings["temporary_parent"].encode())
    compatibility_shell = driver.Snapshot(
        authority.shell.path,
        compatibility_raw,
        hashlib.sha256(compatibility_raw).hexdigest(),
        authority.shell.identity,
    )

    def compatibility_value(value):
        if isinstance(value, dict):
            return {key: compatibility_value(item) for key, item in value.items()}
        if isinstance(value, list):
            return [compatibility_value(item) for item in value]
        if isinstance(value, str):
            return value.replace(profile.temporary_parent, profile.predecessor_bindings["temporary_parent"])
        return value

    compatibility = driver.FrozenAuthority(
        authority.descriptor,
        authority.provenance,
        authority.json,
        authority.markdown,
        compatibility_shell,
        compatibility_value(authority.document),
    )
    stdin = driver.transform_shell(compatibility).replace(profile.predecessor_bindings["temporary_parent"].encode(), profile.temporary_parent.encode())
    stdin = _repair_markdown_appendix_parser(stdin)
    driver.compile_derived(stdin)
    return driver.DerivedDriver(
        tuple(authority.document["execution_driver"]["argv"]),
        stdin,
        authority.shell.sha256,
        hashlib.sha256(stdin).hexdigest(),
    )


if __name__ == "__main__":
    contract = derive_contract()
    print(json.dumps({"argv": list(contract.argv), "source_sha256": contract.source_sha256, "derived_sha256": contract.derived_sha256, "bytes": len(contract.stdin), "replay_run": False}, sort_keys=True))
