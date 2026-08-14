#!/usr/bin/env python3
"""Create the immutable v3 authority with stable parent directory binding.

This is a one-transform successor.  It loads the reviewed LF authority,
changes only the shared ROOT_PY parent comparison, and creates a new authority
root.  The five-field ledger remains unchanged: only the within-call parent
comparison excludes link count because mkdir necessarily changes it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import linux_anchor_authority_v2 as predecessor
import platform_profile
import platform_successor
import section_anchor_metadata as anchor

HERE = Path(__file__).resolve().parent
PREDECESSOR_PATH = HERE / "linux_anchor_authority_v2.py"
PREDECESSOR_SHA256 = "32d8e751a2398a0530213559ea185547f1fd8bbab51ad4bc3f1115825a23331f"
AUTHORITY_ROOT = HERE.parent / "task464-candidate5-linux-v2-parent-binding-final"
ADAPTATION_SCHEMA = "hermternal.issue-397.parent-binding-adaptation/v1"
NAMES = platform_successor.NAMES
ROLES = platform_successor.ROLES

OLD_PARENT_COMPARISON = b"""if ident(parent_before) != ident(parent_after):
    raise SystemExit(f'{label} parent changed during root/child creation')
"""
NEW_PARENT_COMPARISON = b"""def stable_parent_identity(st):
    # mkdir adds a child and changes parent link count.  Preserve only the
    # directory binding fields that must stay stable through this operation.
    return (str(st.st_dev), str(st.st_ino), str(st.st_uid), format(stat.S_IMODE(st.st_mode), '04o'))
if stable_parent_identity(parent_before) != stable_parent_identity(parent_after):
    raise SystemExit(f'{label} parent changed during root/child creation')
"""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _authenticate() -> None:
    if _sha(PREDECESSOR_PATH.read_bytes()) != PREDECESSOR_SHA256:
        raise RuntimeError("parent-binding predecessor authority SHA-256 differs")


def transform_parent_binding(shell: bytes) -> bytes:
    """Transform the two ROOT_PY instantiations through one exact invariant."""
    count = shell.count(OLD_PARENT_COMPARISON)
    if count != 2 or NEW_PARENT_COMPARISON in shell:
        raise RuntimeError("shared ROOT_PY parent comparison invariant differs")
    transformed = shell.replace(OLD_PARENT_COMPARISON, NEW_PARENT_COMPARISON)
    if transformed.count(NEW_PARENT_COMPARISON) != 2 or OLD_PARENT_COMPARISON in transformed:
        raise RuntimeError("shared ROOT_PY parent comparison transform differs")
    return transformed


def _replace_root(value, old: str, new: str):
    if isinstance(value, dict):
        return {key: _replace_root(item, old, new) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_root(item, old, new) for item in value]
    return value.replace(old, new) if isinstance(value, str) else value


def generate(root: Path = AUTHORITY_ROOT) -> dict[str, bytes]:
    """Return deterministic authority bytes without executing the shell."""
    _authenticate()
    root = root.resolve()
    base = predecessor.generate(predecessor.AUTHORITY_ROOT)
    document = anchor.strict_document(base["json"], "parent-binding predecessor JSON")
    document = _replace_root(document, os.fspath(predecessor.AUTHORITY_ROOT), os.fspath(root))
    original_shell = document["execution_driver"]["shell"].encode("utf-8")
    transformed_shell = transform_parent_binding(original_shell)
    document["execution_driver"]["shell"] = transformed_shell.decode("utf-8")
    _orchestrator, _publication, authority = platform_successor.load_approved()
    json_raw = platform_successor._update_fixed_point(document, authority)
    checked = anchor.strict_document(json_raw, "parent-binding generated JSON")
    anchor.anchor_value(checked, "parent-binding generated JSON")
    shell = checked["execution_driver"]["shell"].encode("utf-8")
    # Fixed-point generation changes its own matrix hash.  The parent block is
    # independent of that hash and must remain the exact shared transform.
    if shell.count(NEW_PARENT_COMPARISON) != 2 or OLD_PARENT_COMPARISON in shell:
        raise RuntimeError("parent-binding fixed-point shell differs")
    markdown = platform_successor._markdown(
        base["markdown"], shell, checked,
        ((os.fspath(predecessor.AUTHORITY_ROOT).encode(), os.fspath(root).encode()),),
    )
    if authority.extract_shell(markdown) != shell:
        raise RuntimeError("parent-binding Markdown shell parity differs")
    return {"json": json_raw, "markdown": markdown, "shell": shell}


def _adaptation(payloads: dict[str, bytes]) -> bytes:
    profile = platform_profile.load()
    value = {
        "schema": ADAPTATION_SCHEMA,
        "profile": {"path": os.fspath(platform_profile.PROFILE_PATH), "sha256": profile.sha256, "profile_id": profile.profile_id},
        "predecessor_authority": {"root": os.fspath(predecessor.AUTHORITY_ROOT), "generator_sha256": PREDECESSOR_SHA256},
        "successor_authority_root": os.fspath(AUTHORITY_ROOT),
        "semantic_change": {
            "shared_source": "ROOT_PY",
            "instantiations": ("clean-primary", "replay"),
            "parent_binding": ("st_dev", "st_ino", "st_uid", "mode"),
            "excluded_intra_call_fields": ("st_nlink", "st_mtime", "st_ctime"),
            "retained_ledgers": ("parent", "root", "child"),
        },
        "outputs": {role: _sha(payloads[role]) for role in ROLES},
        "safety_claims": {"shell_executed": False, "replay_run": False, "network_used": False, "credentials_used": False, "hermes_used": False},
    }
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def freeze(root: Path = AUTHORITY_ROOT) -> dict[str, str]:
    """Create the new immutable authority root once, with fsynced files."""
    _authenticate()
    root = root.resolve()
    if root != AUTHORITY_ROOT.resolve():
        raise RuntimeError("parent-binding authority root differs")
    if root.exists():
        raise RuntimeError("parent-binding authority root already exists")
    root.mkdir(mode=0o700)
    if stat.S_IMODE(root.stat().st_mode) != 0o700:
        raise RuntimeError("parent-binding authority root mode differs")
    payloads = generate(root)
    orchestrator, publication, authority = platform_successor.load_approved()
    adapted = SimpleNamespace(root=root, payloads=payloads)
    descriptor = orchestrator.descriptor_bytes(adapted, authority)
    platform_successor._create(root, "authority-descriptor.json", descriptor)
    descriptor_sha = _sha(descriptor)
    publication.publish(tuple(root / orchestrator.FINAL_NAMES[role] for role in ROLES), tuple(payloads[role] for role in ROLES), validate=lambda _paths, _payloads: authority.validate(root / "authority-descriptor.json", root, descriptor_sha))
    facts = {
        "generation": {"path": os.fspath(Path(__file__).resolve()), "sha256": _sha(Path(__file__).read_bytes()), "mode": "0644"},
        "repository_boundary": {"output_root": os.fspath(root)},
        "dependencies": [{"path": os.fspath(platform_successor.ORCHESTRATOR), "sha256": platform_successor.ORCHESTRATOR_SHA256}, {"path": os.fspath(platform_successor.PUBLICATION), "sha256": platform_successor.PUBLICATION_SHA256, "commit": orchestrator.APPROVED_PUBLICATION_COMMIT}],
        "source_inputs": [{"path": os.fspath(platform_profile.PROFILE_PATH.relative_to(HERE.parent)), "sha256": platform_profile.load().sha256}, {"path": os.fspath(PREDECESSOR_PATH.relative_to(HERE.parent)), "sha256": PREDECESSOR_SHA256}],
        "publication": {"commit": orchestrator.APPROVED_PUBLICATION_COMMIT, "sha256": platform_successor.PUBLICATION_SHA256, "roles": list(ROLES)},
        "safety_claims": {"shell_executed": False, "replay_run": False, "network_used": False, "credentials_used": False, "hermes_used": False},
    }
    platform_successor._create(root, "provenance-manifest.json", orchestrator.provenance_bytes(adapted, facts, authority))
    platform_successor._create(root, "parent-binding-adaptation-manifest.json", _adaptation(payloads))
    expected = set(NAMES) - {"platform-adaptation-manifest.json"} | {"parent-binding-adaptation-manifest.json"}
    if {path.name for path in root.iterdir()} != expected:
        raise RuntimeError("parent-binding authority file set differs")
    return {name: _sha((root / name).read_bytes()) for name in sorted(expected)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--prepare", action="store_true")
    group.add_argument("--publish", action="store_true")
    args = parser.parse_args(argv)
    if args.prepare:
        # The immutable target root is part of the authority bytes.  Prepare
        # therefore uses that same literal without creating the root.
        result = {role: _sha(raw) for role, raw in generate().items()}
    else:
        result = freeze()
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
