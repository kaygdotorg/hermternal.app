#!/usr/bin/env python3
"""Derive and freeze one Linux successor through approved replay artifact code.

The profile is a build-time input. It does not read runtime environment values.
This adapter verified-loads the approved #401/#402/#403 modules, transforms
structured authority, and never executes the generated shell or replay.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import platform_profile

BASE = Path(__file__).resolve().parents[1]
PREDECESSOR_ROOT = BASE / "task464-candidate5-final"
ORCHESTRATOR = BASE / "task464-candidate5-final-triad" / "generator_orchestrator.py"
PUBLICATION = BASE / "task464-candidate5-publication-successor" / "candidate5_publication_successor.py"
AUTHORITY = BASE / "task464-candidate5-authority-successor" / "candidate5_authority.py"
ORCHESTRATOR_SHA256 = "d9c36a3c3e99d0379186fc9ea0a26a5d93ac26eb4bd1c826c209b9bee0547361"
PUBLICATION_SHA256 = "09c7a0e514f64ed89b475ff1f7e0c24a4b28477837b7a575aa0952377ea22c28"
AUTHORITY_SHA256 = "1eec1b59f608a3c64d4abb532fe6dbe031c4ba8008b46775db3ee6a75c9bb9a8"
PREDECESSOR_SHA256 = {
    "authority-descriptor.json": "cf10f8286eca92d42130c17b9e086b8776dc385fa3a297c90725787415776f34",
    "candidate-five.json": "dd0e9873941c30aee7515a382e3ca7c282df840d2d4364a7dfa5f21fce0ecd60",
    "candidate-five.md": "706237ec508d96f564e5395e86dba943a11eb5057fb676bf95b924815158dad9",
    "candidate-five.sh": "f7d5adfc9178431942d62948ffaf1953a2273bdec002661def9d0e80ffc34676",
    "provenance-manifest.json": "363d6f62335a5ff9f92eefabe87dd568032e71871390fa9fc5ae6fd72e3ac320",
}
NAMES = ("candidate-five.md", "candidate-five.json", "candidate-five.sh", "authority-descriptor.json", "provenance-manifest.json", "platform-adaptation-manifest.json")
ROLES = ("markdown", "json", "shell")
ADAPTATION_SCHEMA = "hermternal.issue-397.platform-adaptation/v1"


class Reject(Exception):
    """Reject a derivation or publication that differs from the closed contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Reject(message)


@dataclass(frozen=True)
class Generated:
    root: Path
    payloads: Mapping[str, bytes]
    translation_counts: Mapping[str, int]


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _verified(path: Path, digest: str, name: str) -> types.ModuleType:
    raw = path.read_bytes()
    require(_sha(raw) == digest, f"{name} SHA-256 differs")
    module = types.ModuleType(name)
    module.__file__ = os.fspath(path)
    module.__package__ = ""
    sys.modules[name] = module
    exec(compile(raw, os.fspath(path), "exec", dont_inherit=True), module.__dict__)
    return module


def load_approved() -> tuple[types.ModuleType, types.ModuleType, types.ModuleType]:
    """Load exact approved generation, publication, and authority bytes."""
    orchestrator = _verified(ORCHESTRATOR, ORCHESTRATOR_SHA256, "linux_profile_orchestrator")
    publication = _verified(PUBLICATION, PUBLICATION_SHA256, "linux_profile_publication")
    authority = _verified(AUTHORITY, AUTHORITY_SHA256, "linux_profile_authority")
    require(orchestrator.APPROVED_PUBLICATION_SHA256 == PUBLICATION_SHA256, "#403 publication pin differs")
    require(callable(publication.publish) and callable(authority.validate), "approved API differs")
    return orchestrator, publication, authority


def _replace_values(value: Any, replacements: tuple[tuple[str, str], ...], counts: dict[str, int]) -> Any:
    if isinstance(value, dict):
        return {key: _replace_values(item, replacements, counts) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_values(item, replacements, counts) for item in value]
    if isinstance(value, str):
        for old, new in replacements:
            found = value.count(old)
            if found:
                counts[old] += found
                value = value.replace(old, new)
        return value
    return value


def _update_fixed_point(document: dict[str, Any], authority: types.ModuleType) -> bytes:
    execution = document["execution_driver"]
    validation = document["validation_contract"]
    candidate = execution["matrix_identity"]["expected_normalized_sha256"]
    for _ in range(80):
        shell = re.sub(r"(MATRIX_EXPECTED_BINDING_SHA256=')[0-9a-f]{64}(')", rf"\g<1>{candidate}\g<2>", execution["shell"], count=1)
        require(shell != execution["shell"] or candidate in shell, "matrix shell binding is absent")
        execution["shell"] = shell
        raw_shell = shell.encode("utf-8")
        shell_sha = _sha(raw_shell)
        execution["shell_sha256"] = shell_sha
        validation["driver_shell_sha256"] = shell_sha
        fence = execution["markdown_fence_extraction"]
        fence.update(expected_body_bytes=len(raw_shell), expected_body_lines=len(raw_shell.splitlines()), expected_terminal_byte_hex=raw_shell[-1:].hex(), expected_body_sha256=shell_sha)
        validation["markdown_fence_extraction"] = json.loads(json.dumps(fence))
        metadata = {"body_bytes": len(raw_shell), "body_lines": len(raw_shell.splitlines()), "terminal_byte_hex": raw_shell[-1:].hex()}
        execution["shell_size_metadata"] = metadata
        validation["shell_size_metadata"] = json.loads(json.dumps(metadata))
        validation["driver_shell_body_bytes"] = len(raw_shell)
        validation["driver_shell_body_lines"] = len(raw_shell.splitlines())
        execution["matrix_identity"]["expected_normalized_sha256"] = candidate
        validation["matrix_identity"]["expected_normalized_sha256"] = candidate
        raw = (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        following = authority.normalized_json_sha256(raw, candidate)
        if following == candidate:
            return raw
        candidate = following
    raise Reject("platform fixed-point hash did not converge")


def _markdown(raw: bytes, shell: bytes, document: dict[str, Any], replacements: tuple[tuple[bytes, bytes], ...]) -> bytes:
    for old, new in replacements:
        raw = raw.replace(old, new)
    heading = b"## Canonical machine-readable ordered execution driver\n"
    opening = b"```bash\n"
    section = raw.index(heading)
    body_start = raw.index(opening, section + len(heading)) + len(opening)
    body_end = raw.index(b"```", body_start)
    raw = raw[:body_start] + shell + raw[body_end:]
    execution = document["execution_driver"]
    digest = execution["shell_sha256"].encode("ascii")
    identity = execution["matrix_identity"]["expected_normalized_sha256"].encode("ascii")
    raw = re.sub(rb"(Driver shell SHA-256: `)[0-9a-f]{64}(`)", rb"\g<1>" + digest + rb"\g<2>", raw, count=1)
    raw = re.sub(rb"(Fresh extraction boundary:.*?shell SHA-256 `)[0-9a-f]{64}(`)", rb"\g<1>" + digest + rb"\g<2>", raw, count=1)
    raw = re.sub(rb"(Fresh extraction boundary:.*?normalized JSON identity `)[0-9a-f]{64}(`)", rb"\g<1>" + identity + rb"\g<2>", raw, count=1)
    raw = re.sub(rb"(?m)^(\| Driver shell SHA-256 \| `)[0-9a-f]{64}(` \|)$", rb"\g<1>" + digest + rb"\g<2>", raw, count=1)
    raw = re.sub(rb"(?im)(normalized JSON identity|Matrix identity:.*?normalized SHA-256) `([0-9a-f]{64})`", lambda match: match.group(1) + b" `" + identity + b"`", raw)
    for label, number in ((b"Shell body bytes", len(shell)), (b"Shell body lines", len(shell.splitlines()))):
        raw = re.sub(rb"(?m)^(\| " + label + rb" \| `)\d+(` \|)$", lambda match, number=number: match.group(1) + str(number).encode() + match.group(2), raw, count=1)
    raw = re.sub(rb"(body and JSON shell are `)\d+(` bytes)", lambda match: match.group(1) + str(len(shell)).encode() + match.group(2), raw, count=1)
    raw = re.sub(rb"(body and JSON shell are `)\d+(` LF lines)", lambda match: match.group(1) + str(len(shell.splitlines())).encode() + match.group(2), raw, count=1)
    raw = re.sub(rb"(Byte-exact Markdown extraction:.*?body and JSON shell are `)\d+(` bytes, SHA-256 `)[0-9a-f]{64}(`, terminal)", lambda match: match.group(1) + str(len(shell)).encode() + match.group(2) + digest + match.group(3), raw, count=1)
    return raw


def generate(root: Path) -> Generated:
    """Generate through #403, then apply only profile-declared bindings."""
    profile = platform_profile.load()
    old_python = profile.predecessor_bindings["python3"]
    old_source = profile.predecessor_bindings["source_repository"]
    old_temp = profile.predecessor_bindings["temporary_parent"]
    orchestrator, _, authority = load_approved()
    original = orchestrator.generate_in_memory(root)
    document = json.loads(original.payloads["json"].decode("utf-8"))
    counts = {old_python: 0, old_source: 0, old_temp: 0}
    root_counts = {os.fspath(root): 0}
    replacements = ((old_python, profile.tools["python3"].path), (old_source, profile.source_repository), (old_temp, profile.temporary_parent))
    document = _replace_values(document, replacements, counts)
    document = _replace_values(document, ((os.fspath(root), profile.authority_root),), root_counts)
    require(counts[old_python] == 2 and counts[old_source] == 3 and counts[old_temp] == 35, f"structured translation counts differ: {counts}")
    json_raw = _update_fixed_point(document, authority)
    shell = document["execution_driver"]["shell"].encode("utf-8")
    markdown_replacements = (*replacements, (os.fspath(root), profile.authority_root))
    markdown = _markdown(original.payloads["markdown"], shell, document, tuple((old.encode(), new.encode()) for old, new in markdown_replacements))
    require(authority.extract_shell(markdown) == shell, "Markdown shell parity differs")
    require(json.loads(json_raw)["execution_driver"]["shell"].encode() == shell, "JSON shell parity differs")
    for forbidden in (old_python, old_source, old_temp):
        require(forbidden.encode() not in json_raw + markdown + shell, f"old host token remained: {forbidden}")
    require(profile.tools["python3"].path.encode() in shell and profile.source_repository.encode() in shell, "profile bindings are absent")
    return Generated(root, {"markdown": markdown, "json": json_raw, "shell": shell}, counts)


def _adaptation_bytes(generated: Generated, profile: platform_profile.PlatformProfile) -> bytes:
    value = {
        "schema": ADAPTATION_SCHEMA,
        "profile": {"path": os.fspath(platform_profile.PROFILE_PATH), "sha256": profile.sha256, "profile_id": profile.profile_id},
        "predecessor": {"root": os.fspath(PREDECESSOR_ROOT), "outputs": PREDECESSOR_SHA256},
        "semantic_changes": [
            {"field": "trusted_python", "from": profile.predecessor_bindings["python3"], "to": profile.tools["python3"].path},
            {"field": "reviewed_source_repository", "from": profile.predecessor_bindings["source_repository"], "to": profile.source_repository, "detached_head": profile.source_detached_head},
        ],
        "dependent_path_derivations": [{"field": "temporary_parent", "from": profile.predecessor_bindings["temporary_parent"], "to": profile.temporary_parent}],
        "translation_counts": dict(generated.translation_counts),
        "outputs": {role: _sha(generated.payloads[role]) for role in ROLES},
        "unchanged_semantics": ["base_and_main_pins", "ordered_lanes", "ranges", "path_policy", "replay_transaction"],
        "safety_claims": {"shell_executed": False, "replay_run": False, "network_used": False, "credentials_used": False, "hermes_used": False},
    }
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _create(root: Path, name: str, raw: bytes) -> None:
    root_descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=root_descriptor)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(descriptor, view)
            require(count > 0, f"{name} write made no progress")
            view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
        os.fsync(root_descriptor)
        os.close(root_descriptor)


def freeze(root: Path) -> dict[str, str]:
    """Create the complete successor once through approved #402 publication."""
    root = root.resolve()
    profile = platform_profile.load()
    require(root == Path(profile.authority_root), "publication root differs from platform profile")
    require(root.is_absolute() and os.path.realpath(root) == os.fspath(root), "output root differs")
    if not root.exists():
        root.mkdir(mode=0o700)
    require(stat.S_IMODE(root.stat().st_mode) == 0o700 and not any(root.iterdir()), "output root is not empty mode 0700")
    orchestrator, publication, authority = load_approved()
    generated = generate(root)
    adapted = types.SimpleNamespace(root=root, payloads=generated.payloads)
    descriptor_raw = orchestrator.descriptor_bytes(adapted, authority)
    _create(root, "authority-descriptor.json", descriptor_raw)
    descriptor_sha = _sha(descriptor_raw)
    publication.publish(tuple(root / orchestrator.FINAL_NAMES[role] for role in ROLES), tuple(generated.payloads[role] for role in ROLES), validate=lambda _paths, _payloads: authority.validate(root / "authority-descriptor.json", root, descriptor_sha))
    facts = {
        "generation": {"path": os.fspath(Path(__file__).resolve()), "sha256": _sha(Path(__file__).read_bytes()), "mode": "0644"},
        "repository_boundary": {"output_root": os.fspath(root)},
        "dependencies": [{"path": os.fspath(ORCHESTRATOR), "sha256": ORCHESTRATOR_SHA256}, {"path": os.fspath(PUBLICATION), "sha256": PUBLICATION_SHA256, "commit": orchestrator.APPROVED_PUBLICATION_COMMIT}],
        "source_inputs": [{"path": os.fspath(platform_profile.PROFILE_PATH.relative_to(BASE)), "sha256": profile.sha256}],
        "publication": {"commit": orchestrator.APPROVED_PUBLICATION_COMMIT, "sha256": PUBLICATION_SHA256, "roles": list(ROLES)},
        "safety_claims": {"shell_executed": False, "replay_run": False, "network_used": False, "credentials_used": False, "hermes_used": False},
    }
    provenance = orchestrator.provenance_bytes(adapted, facts, authority)
    _create(root, "provenance-manifest.json", provenance)
    _create(root, "platform-adaptation-manifest.json", _adaptation_bytes(generated, profile))
    orchestrator.inspect_complete(root, descriptor_sha, _sha(provenance))
    require(set(path.name for path in root.iterdir()) == set(NAMES), "final set differs")
    return {name: _sha((root / name).read_bytes()) for name in NAMES}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--prepare", action="store_true")
    group.add_argument("--publish", action="store_true")
    args = parser.parse_args(argv)
    if args.prepare:
        with tempfile.TemporaryDirectory(prefix="issue397-linux-profile-") as parent:
            root = Path(parent) / "final"
            root.mkdir(mode=0o700)
            generated = generate(root)
            result = {role: _sha(generated.payloads[role]) for role in ROLES}
    else:
        result = freeze(Path(platform_profile.load().authority_root))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
