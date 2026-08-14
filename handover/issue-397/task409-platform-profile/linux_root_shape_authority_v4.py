#!/usr/bin/env python3
"""Freeze one authority successor with the exact root-shape argv parser fix."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import linux_parent_binding_authority_v3 as predecessor
import platform_profile
import platform_successor
import section_anchor_metadata as anchor

HERE = Path(__file__).resolve().parent
PREDECESSOR_PATH = HERE / "linux_parent_binding_authority_v3.py"
PREDECESSOR_SHA256 = "9afa3fff6f897bbaac8d3a004080688bf7bf3c5746bb7e266dbb8ce5660f1928"
AUTHORITY_ROOT = HERE.parent / "task464-candidate5-linux-v3-root-shape-final"
ADAPTATION_SCHEMA = "hermternal.issue-397.root-shape-adaptation/v1"
NAMES = platform_successor.NAMES
ROLES = platform_successor.ROLES

OLD_PARSER = b"""clean_parent = take(5); clean_root_id = take(5); clean_child = take(5)
replay_parent = take(5); replay_root_id = take(5); replay_child = take(5)
"""
NEW_PARSER = b"""clean_parent = take(5); clean_root_id = take(5); clean_root_real = take(1); clean_child = take(5)
replay_parent = take(5); replay_root_id = take(5); replay_root_real = take(1); replay_child = take(5)
if idx != len(rest):
    raise SystemExit('root-shape ledger argv order differs')
def verify_root_real(path, wanted, label):
    if wanted != [path] or os.path.realpath(path) != path:
        raise SystemExit(label + ' root realpath changed')
"""
OLD_CLEAN_ROOT_VERIFY = b"""    verify_parent(os.path.dirname(clean_root), clean_parent, 'clean-primary parent')
    verify(clean_root, clean_root, clean_root_id, 'clean-primary root', 0o700)
"""
NEW_CLEAN_ROOT_VERIFY = b"""    verify_parent(os.path.dirname(clean_root), clean_parent, 'clean-primary parent')
    verify_root_real(clean_root, clean_root_real, 'clean-primary')
    verify(clean_root, clean_root, clean_root_id, 'clean-primary root', 0o700)
"""
OLD_REPLAY_ROOT_VERIFY = b"""    verify_parent(os.path.dirname(replay_root), replay_parent, 'replay parent')
    verify(replay_root, replay_root, replay_root_id, 'replay root', 0o700)
"""
NEW_REPLAY_ROOT_VERIFY = b"""    verify_parent(os.path.dirname(replay_root), replay_parent, 'replay parent')
    verify_root_real(replay_root, replay_root_real, 'replay')
    verify(replay_root, replay_root, replay_root_id, 'replay root', 0o700)
"""


def _sha(raw: bytes) -> str: return hashlib.sha256(raw).hexdigest()


def _authenticate() -> None:
    if _sha(PREDECESSOR_PATH.read_bytes()) != PREDECESSOR_SHA256:
        raise RuntimeError("root-shape predecessor authority SHA-256 differs")


def transform_root_shape_parser(shell: bytes) -> bytes:
    """Apply the complete shared ASSERT_ROOT_SHAPE parser correction once."""
    replacements = ((OLD_PARSER, NEW_PARSER), (OLD_CLEAN_ROOT_VERIFY, NEW_CLEAN_ROOT_VERIFY), (OLD_REPLAY_ROOT_VERIFY, NEW_REPLAY_ROOT_VERIFY))
    for old, new in replacements:
        if shell.count(old) != 1 or new in shell:
            raise RuntimeError("shared ASSERT_ROOT_SHAPE parser invariant differs")
        shell = shell.replace(old, new, 1)
    if shell.count(NEW_PARSER) != 1 or shell.count(b"verify_root_real(") != 3:
        raise RuntimeError("shared ASSERT_ROOT_SHAPE parser transform differs")
    return shell


def _replace_root(value, old: str, new: str):
    if isinstance(value, dict): return {key: _replace_root(item, old, new) for key, item in value.items()}
    if isinstance(value, list): return [_replace_root(item, old, new) for item in value]
    return value.replace(old, new) if isinstance(value, str) else value


def generate(root: Path = AUTHORITY_ROOT) -> dict[str, bytes]:
    """Return deterministic successor bytes without executing the shell."""
    _authenticate(); root = root.resolve()
    base = predecessor.generate(predecessor.AUTHORITY_ROOT)
    document = anchor.strict_document(base["json"], "root-shape predecessor JSON")
    document = _replace_root(document, os.fspath(predecessor.AUTHORITY_ROOT), os.fspath(root))
    document["execution_driver"]["shell"] = transform_root_shape_parser(document["execution_driver"]["shell"].encode()).decode()
    _orchestrator, _publication, authority = platform_successor.load_approved()
    json_raw = platform_successor._update_fixed_point(document, authority)
    checked = anchor.strict_document(json_raw, "root-shape generated JSON")
    anchor.anchor_value(checked, "root-shape generated JSON")
    shell = checked["execution_driver"]["shell"].encode()
    if shell.count(NEW_PARSER) != 1 or OLD_PARSER in shell:
        raise RuntimeError("root-shape fixed-point shell differs")
    markdown = platform_successor._markdown(base["markdown"], shell, checked, ((os.fspath(predecessor.AUTHORITY_ROOT).encode(), os.fspath(root).encode()),))
    if authority.extract_shell(markdown) != shell: raise RuntimeError("root-shape Markdown shell parity differs")
    return {"json": json_raw, "markdown": markdown, "shell": shell}


def _adaptation(payloads: dict[str, bytes]) -> bytes:
    profile = platform_profile.load()
    value = {"schema": ADAPTATION_SCHEMA, "profile": {"path": os.fspath(platform_profile.PROFILE_PATH), "sha256": profile.sha256, "profile_id": profile.profile_id}, "predecessor_authority": {"root": os.fspath(predecessor.AUTHORITY_ROOT), "generator_sha256": PREDECESSOR_SHA256}, "successor_authority_root": os.fspath(AUTHORITY_ROOT), "semantic_change": {"shared_source": "ASSERT_ROOT_SHAPE", "ledger_order": ("parent5", "root5", "root_real1", "child5"), "instantiations": ("clean-primary", "replay"), "root_realpath_required": True, "retained_ledgers": ("parent", "root", "child")}, "outputs": {role: _sha(payloads[role]) for role in ROLES}, "safety_claims": {"shell_executed": False, "replay_run": False, "network_used": False, "credentials_used": False, "hermes_used": False}}
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def freeze(root: Path = AUTHORITY_ROOT) -> dict[str, str]:
    """Create the new mode-0700, fsynced authority root exactly once."""
    _authenticate(); root = root.resolve()
    if root != AUTHORITY_ROOT.resolve() or root.exists(): raise RuntimeError("root-shape authority root differs or exists")
    root.mkdir(mode=0o700)
    if stat.S_IMODE(root.stat().st_mode) != 0o700: raise RuntimeError("root-shape authority root mode differs")
    payloads = generate(root); orchestrator, publication, authority = platform_successor.load_approved(); adapted = SimpleNamespace(root=root, payloads=payloads)
    descriptor = orchestrator.descriptor_bytes(adapted, authority); platform_successor._create(root, "authority-descriptor.json", descriptor); descriptor_sha = _sha(descriptor)
    publication.publish(tuple(root / orchestrator.FINAL_NAMES[role] for role in ROLES), tuple(payloads[role] for role in ROLES), validate=lambda _paths, _payloads: authority.validate(root / "authority-descriptor.json", root, descriptor_sha))
    facts = {"generation": {"path": os.fspath(Path(__file__).resolve()), "sha256": _sha(Path(__file__).read_bytes()), "mode": "0644"}, "repository_boundary": {"output_root": os.fspath(root)}, "dependencies": [{"path": os.fspath(platform_successor.ORCHESTRATOR), "sha256": platform_successor.ORCHESTRATOR_SHA256}, {"path": os.fspath(platform_successor.PUBLICATION), "sha256": platform_successor.PUBLICATION_SHA256, "commit": orchestrator.APPROVED_PUBLICATION_COMMIT}], "source_inputs": [{"path": os.fspath(platform_profile.PROFILE_PATH.relative_to(HERE.parent)), "sha256": platform_profile.load().sha256}, {"path": os.fspath(PREDECESSOR_PATH.relative_to(HERE.parent)), "sha256": PREDECESSOR_SHA256}], "publication": {"commit": orchestrator.APPROVED_PUBLICATION_COMMIT, "sha256": platform_successor.PUBLICATION_SHA256, "roles": list(ROLES)}, "safety_claims": {"shell_executed": False, "replay_run": False, "network_used": False, "credentials_used": False, "hermes_used": False}}
    platform_successor._create(root, "provenance-manifest.json", orchestrator.provenance_bytes(adapted, facts, authority))
    platform_successor._create(root, "root-shape-adaptation-manifest.json", _adaptation(payloads))
    expected = set(NAMES) - {"platform-adaptation-manifest.json"} | {"root-shape-adaptation-manifest.json"}
    if {path.name for path in root.iterdir()} != expected: raise RuntimeError("root-shape authority file set differs")
    return {name: _sha((root / name).read_bytes()) for name in sorted(expected)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(); group = parser.add_mutually_exclusive_group(required=True); group.add_argument("--prepare", action="store_true"); group.add_argument("--publish", action="store_true"); args = parser.parse_args(argv)
    result = {role: _sha(raw) for role, raw in generate().items()} if args.prepare else freeze()
    print(json.dumps(result, sort_keys=True)); return 0

if __name__ == "__main__": raise SystemExit(main())
