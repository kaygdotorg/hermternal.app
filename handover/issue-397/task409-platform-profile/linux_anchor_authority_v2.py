#!/usr/bin/env python3
"""Generate the LF-corrected Linux authority without changing the profile.

The predecessor triad is frozen.  This successor verified-loads its generator,
changes only the malformed section-anchor metadata and the necessarily new
authority-root binding, then creates a separate, create-only authority set.
It never executes a shell, replay, Hermes, network request, or credential flow.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
from types import SimpleNamespace

import platform_profile
import platform_successor
import section_anchor_metadata as anchor

HERE = Path(__file__).resolve().parent
V1_PATH = HERE / "platform_successor.py"
V1_SHA256 = "a16184b163330b2f2cfbf5482ec78753264a87fcf37f35997af0513cff6bc9c4"
AUTHORITY_ROOT = HERE.parent / "task464-candidate5-linux-v1-anchor-lf-final"
ADAPTATION_SCHEMA = "hermternal.issue-397.platform-adaptation/v2"
NAMES = platform_successor.NAMES
ROLES = platform_successor.ROLES


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _authenticate() -> None:
    if _sha(V1_PATH.read_bytes()) != V1_SHA256:
        raise RuntimeError("platform successor v1 SHA-256 differs")


def _replace_root(value, old: str, new: str):
    if isinstance(value, dict):
        return {key: _replace_root(item, old, new) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_root(item, old, new) for item in value]
    return value.replace(old, new) if isinstance(value, str) else value


def generate(root: Path = AUTHORITY_ROOT):
    """Return deterministic corrected JSON, Markdown, and shell bytes."""
    _authenticate()
    root = root.resolve()
    profile = platform_profile.load()
    # The predecessor requires a private mode-0700 staging directory although
    # it replaces that path with the profile authority before returning bytes.
    # Never let staging identity enter the successor payloads.
    with tempfile.TemporaryDirectory(prefix="issue397-anchor-lf-") as parent:
        staging = Path(parent) / "final"
        staging.mkdir(mode=0o700)
        base = platform_successor.generate(staging)
    before = anchor.strict_document(base.payloads["json"], "pre-fix generated JSON")
    document = anchor.repair_legacy(before)
    # A new immutable authority must name its own root.  This is the only
    # non-content binding difference; strict_one_field_diff protects content.
    document = _replace_root(document, profile.authority_root, os.fspath(root))
    normalized_before = _replace_root(before, profile.authority_root, os.fspath(root))
    anchor.strict_one_field_diff(normalized_before, document)
    _orchestrator, _publication, authority = platform_successor.load_approved()
    json_raw = platform_successor._update_fixed_point(document, authority)
    checked = anchor.strict_document(json_raw, "generated JSON")
    anchor.anchor_value(checked, "generated JSON")
    shell = checked["execution_driver"]["shell"].encode("utf-8")
    markdown = platform_successor._markdown(
        base.payloads["markdown"], shell, checked,
        ((profile.authority_root.encode(), os.fspath(root).encode()),),
    )
    if authority.extract_shell(markdown) != shell:
        raise RuntimeError("corrected Markdown shell parity differs")
    if checked["execution_driver"]["shell"].encode("utf-8") != shell:
        raise RuntimeError("corrected JSON shell parity differs")
    return {"json": json_raw, "markdown": markdown, "shell": shell}


def _adaptation(payloads: dict[str, bytes]) -> bytes:
    profile = platform_profile.load()
    value = {
        "schema": ADAPTATION_SCHEMA,
        "profile": {"path": os.fspath(platform_profile.PROFILE_PATH), "sha256": profile.sha256, "profile_id": profile.profile_id},
        "predecessor_authority": {"root": profile.authority_root, "generator_sha256": V1_SHA256},
        "successor_authority_root": os.fspath(AUTHORITY_ROOT),
        "semantic_change": {"path": list(anchor.ANCHOR_PATH), "from": anchor.LEGACY_DOUBLE_ESCAPED_ANCHOR, "to": anchor.CANONICAL_ANCHOR},
        "outputs": {role: _sha(payloads[role]) for role in ROLES},
        "safety_claims": {"shell_executed": False, "replay_run": False, "network_used": False, "credentials_used": False, "hermes_used": False},
    }
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def freeze(root: Path = AUTHORITY_ROOT) -> dict[str, str]:
    """Create the small successor authority once; reject any existing root."""
    _authenticate()
    root = root.resolve()
    profile = platform_profile.load()
    if root != AUTHORITY_ROOT.resolve():
        raise RuntimeError("successor authority root differs")
    if root.exists():
        raise RuntimeError("successor authority root already exists")
    root.mkdir(mode=0o700)
    if stat.S_IMODE(root.stat().st_mode) != 0o700:
        raise RuntimeError("successor authority root mode differs")
    payloads = generate(root)
    orchestrator, publication, authority = platform_successor.load_approved()
    adapted = SimpleNamespace(root=root, payloads=payloads)
    descriptor = orchestrator.descriptor_bytes(adapted, authority)
    platform_successor._create(root, "authority-descriptor.json", descriptor)
    descriptor_sha = _sha(descriptor)
    publication.publish(tuple(root / orchestrator.FINAL_NAMES[role] for role in ROLES),
                         tuple(payloads[role] for role in ROLES),
                         validate=lambda _paths, _payloads: authority.validate(root / "authority-descriptor.json", root, descriptor_sha))
    facts = {"generation": {"path": os.fspath(Path(__file__).resolve()), "sha256": _sha(Path(__file__).read_bytes()), "mode": "0644"},
             "repository_boundary": {"output_root": os.fspath(root)},
             "dependencies": [{"path": os.fspath(platform_successor.ORCHESTRATOR), "sha256": platform_successor.ORCHESTRATOR_SHA256},
                              {"path": os.fspath(platform_successor.PUBLICATION), "sha256": platform_successor.PUBLICATION_SHA256,
                               "commit": orchestrator.APPROVED_PUBLICATION_COMMIT}],
             "source_inputs": [{"path": os.fspath(platform_profile.PROFILE_PATH.relative_to(HERE.parent)), "sha256": profile.sha256},
                               {"path": os.fspath(V1_PATH.relative_to(HERE.parent)), "sha256": V1_SHA256}],
             "publication": {"commit": orchestrator.APPROVED_PUBLICATION_COMMIT, "sha256": platform_successor.PUBLICATION_SHA256, "roles": list(ROLES)},
             "safety_claims": {"shell_executed": False, "replay_run": False, "network_used": False, "credentials_used": False, "hermes_used": False}}
    provenance = orchestrator.provenance_bytes(adapted, facts, authority)
    platform_successor._create(root, "provenance-manifest.json", provenance)
    platform_successor._create(root, "platform-adaptation-manifest.json", _adaptation(payloads))
    return {name: _sha((root / name).read_bytes()) for name in NAMES}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--publish", action="store_true")
    args = parser.parse_args(argv)
    if args.prepare == args.publish:
        parser.error("choose exactly one of --prepare or --publish")
    if args.prepare:
        payloads = generate()
        result = {role: _sha(payloads[role]) for role in ROLES}
    else:
        result = freeze()
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
