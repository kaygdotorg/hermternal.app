#!/usr/bin/env python3
"""Generate and publish candidate-five evidence without executing its shell.

This module is a speculative integration checkpoint. It does not publish the
durable final set by itself. A caller must supply one explicit private root and
all dependency bytes must match the reviewed SHA-256 values below.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


BASE = Path(__file__).resolve().parents[1]
FINAL_NAMES = {
    "markdown": "candidate-five.md",
    "json": "candidate-five.json",
    "shell": "candidate-five.sh",
}
ROLE_ORDER = ("markdown", "json", "shell")
DESCRIPTOR_NAME = "authority-descriptor.json"
PROVENANCE_NAME = "provenance-manifest.json"
FRAMING = BASE / "task464-candidate5-successor" / "candidate5_framing_range_successor.py"
AUTHORITY = BASE / "task464-candidate5-authority-successor" / "candidate5_authority.py"
GIT_AUTHORITY = BASE / "task464-candidate5-git-config-successor" / "candidate5_git_config_successor.py"
PUBLICATION = BASE / "task464-candidate5-publication-successor" / "candidate5_publication_successor.py"
INPUT_JSON = BASE / "task464-inputs" / "task464-working-input.json"
INPUT_MARKDOWN = BASE / "task464-inputs" / "task464-working-input.md"
EXPECTED = {
    FRAMING: "4287f89d87971f62c3f11504713134de9caba4290606b3c90eac63632125861e",
    AUTHORITY: "1eec1b59f608a3c64d4abb532fe6dbe031c4ba8008b46775db3ee6a75c9bb9a8",
    GIT_AUTHORITY: "b2b5a5f1e0ed813325a23cb32eb075b2637872f5c5176e81c79879af4ab1861a",
    PUBLICATION: "9f8aea33508e71a644d5c07ca94c7baacd5bd032f7e2d6caebbccc619f78116d",
    INPUT_JSON: "82f5f9b1f099304723d6e74220488011a46e785eab4a26e9aec1babeef95251c",
    INPUT_MARKDOWN: "4cc01babd55f9092aeb461dd0c9b5d918819564fec2d6ac4067e324e4c3e9adf",
}
PROVENANCE_SCHEMA = "hermternal.issue-397.candidate-five-provenance.v1"
PROVENANCE_KEYS = frozenset({
    "schema", "issue", "candidate", "generation", "repository_boundary",
    "dependencies", "source_inputs", "outputs", "cross_format_authority",
    "publication", "safety_claims",
})


class Reject(Exception):
    """A deliberate fail-closed orchestration rejection."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Reject(message)


@dataclass(frozen=True)
class Snapshot:
    """Exact bytes and stable local file identity."""

    path: Path
    raw: bytes
    sha256: str
    identity: tuple[int, int, int, int, int, int]


@dataclass(frozen=True)
class Generated:
    """Unpublished role bytes for one declared output root."""

    root: Path
    payloads: Mapping[str, bytes]


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_uid, stat.S_IMODE(value.st_mode), value.st_size, value.st_nlink)


def stable_read(path: Path, label: str, limit: int = 8 * 1024 * 1024, *, links: set[int] | None = None) -> Snapshot:
    """Read one canonical regular file three times through no-follow handles."""
    path = Path(path)
    require(path.is_absolute() and os.path.realpath(path) == os.fspath(path), f"{label} path is not canonical")
    results = []
    for _ in range(3):
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode), f"{label} is not regular")
            require(links is None or before.st_nlink in links, f"{label} link count differs")
            require(0 < before.st_size <= limit, f"{label} size is outside its bound")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, min(131072, limit + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk); total += len(chunk)
                require(total <= limit, f"{label} exceeds its bound")
            after = os.fstat(fd)
        finally:
            os.close(fd)
        final = os.stat(path, follow_symlinks=False)
        require(_identity(before) == _identity(after) == _identity(final), f"{label} changed during read")
        raw = b"".join(chunks)
        results.append(Snapshot(path, raw, hashlib.sha256(raw).hexdigest(), _identity(before)))
    require(results[0] == results[1] == results[2], f"{label} changed across reads")
    return results[0]


def verified_module(path: Path, expected_sha256: str, name: str) -> types.ModuleType:
    """Compile and execute only the bytes returned by the verified read."""
    snapshot = stable_read(path.resolve(), name, links={1})
    require(snapshot.sha256 == expected_sha256, f"{name} SHA-256 differs")
    module = types.ModuleType(name)
    module.__file__ = str(path.resolve())
    module.__loader__ = None
    module.__package__ = ""
    module.__spec__ = None
    sys.modules[name] = module
    exec(compile(snapshot.raw, module.__file__, "exec", dont_inherit=True), module.__dict__)
    return module


def verify_dependencies(*, include_publication: bool = False) -> dict[str, Snapshot]:
    """Bind every generation input before any generated bytes are accepted."""
    snapshots = {}
    for path, digest in EXPECTED.items():
        if path == PUBLICATION and not include_publication:
            continue
        require(path.exists(), f"required dependency is absent: {path}")
        snapshot = stable_read(path.resolve(), path.name, links={1})
        require(snapshot.sha256 == digest, f"dependency SHA-256 differs: {path}")
        snapshots[str(path.relative_to(BASE))] = snapshot
    return snapshots


def install_git_authority() -> types.ModuleType:
    """Install #400 before a caller starts any Git review operation."""
    module = verified_module(GIT_AUTHORITY, EXPECTED[GIT_AUTHORITY], "candidate5_final_git_authority")
    module.install_successor()
    return module


def generate_in_memory(root: Path) -> Generated:
    """Capture deterministic generator output without creating public names."""
    root = Path(root)
    require(root.is_absolute() and os.path.realpath(root) == os.fspath(root), "output root is not canonical")
    require(root.is_dir() and stat.S_IMODE(root.stat().st_mode) == 0o700, "output root must be a mode-0700 directory")
    targets = {role: root / name for role, name in FINAL_NAMES.items()}
    require(not any(path.exists() or path.is_symlink() for path in targets.values()), "an output name already exists")
    verify_dependencies()
    framing = verified_module(FRAMING, EXPECTED[FRAMING], "candidate5_final_framing")
    generator = framing.install_successor()
    captured: dict[str, bytes] = {}

    def canonical_target(value: str, label: str) -> Path:
        path = Path(value)
        require(path.is_absolute() and os.path.realpath(path) == os.fspath(path), f"{label} is not canonical")
        require(path.parent.is_dir(), f"{label} parent is absent")
        return path

    def reject_target_set(paths: Sequence[Path]) -> None:
        require(tuple(paths) == (targets["json"], targets["markdown"], targets["shell"]), "generator target order differs")
        require(not any(path.exists() or path.is_symlink() for path in paths), "generator target exists")

    def capture(paths: Sequence[Path], payloads: Sequence[bytes], final_validate: Callable[..., Any] | None = None) -> tuple[bytes, ...]:
        reject_target_set(paths)
        require(len(payloads) == 3 and all(isinstance(item, bytes) and item.endswith(b"\n") for item in payloads), "generator payload framing differs")
        if final_validate is not None:
            # The frozen callback expects path reads. It is publication-specific,
            # so cross-format validation is done by #401 after create-only publish.
            require(callable(final_validate), "generator final validator differs")
        captured.update(json=payloads[0], markdown=payloads[1], shell=payloads[2])
        return tuple(payloads)

    generator.canonical_target = canonical_target
    generator.reject_target_set = reject_target_set
    generator.publish_once = capture
    result = generator.main([
        "--input-json", str(INPUT_JSON), "--input-markdown", str(INPUT_MARKDOWN),
        "--output-json", str(targets["json"]), "--output-markdown", str(targets["markdown"]),
        "--output-shell", str(targets["shell"]),
    ])
    require(result == 0 and set(captured) == set(ROLE_ORDER), "generator did not return the exact triad")
    require(not any(path.exists() or path.is_symlink() for path in targets.values()), "generation created a public name")
    require(captured["shell"] in captured["markdown"], "Markdown does not contain the generated shell")
    document = json.loads(captured["json"].decode("utf-8"))
    require(document["execution_driver"]["shell"].encode("utf-8") == captured["shell"], "JSON shell differs")
    return Generated(root, dict(captured))


def descriptor_bytes(generated: Generated, authority_module: types.ModuleType) -> bytes:
    """Build the strict #401 descriptor, separate from provenance."""
    records = []
    for role in ROLE_ORDER:
        payload = generated.payloads[role]
        records.append({"role": role, "path": str(generated.root / FINAL_NAMES[role]), "sha256": hashlib.sha256(payload).hexdigest()})
    json_raw = generated.payloads["json"]
    declared = json.loads(json_raw)["execution_driver"]["matrix_identity"]["expected_normalized_sha256"]
    require(authority_module.normalized_json_sha256(json_raw, declared) == declared, "normalized JSON identity differs")
    value = {"schema": authority_module.SCHEMA, "roles": records, "normalized_json_sha256": declared}
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _record(path: str, raw: bytes, role: str) -> dict[str, Any]:
    return {
        "role": role, "path": path, "bytes": len(raw), "lf_count": raw.count(b"\n"),
        "terminal_byte_hex": raw[-1:].hex(), "sha256": hashlib.sha256(raw).hexdigest(),
        "git_blob_oid": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
        "publication_mode": "0600", "committed_git_mode": "100644",
    }


def provenance_bytes(generated: Generated, facts: Mapping[str, Any]) -> bytes:
    """Build deterministic provenance from a closed, caller-supplied fact set."""
    require(set(facts) == {"generation", "repository_boundary", "dependencies", "source_inputs", "publication", "safety_claims"}, "provenance facts differ")
    shell = generated.payloads["shell"]
    document = json.loads(generated.payloads["json"])
    normalized = document["execution_driver"]["matrix_identity"]["expected_normalized_sha256"]
    value = {
        "schema": PROVENANCE_SCHEMA, "issue": 397, "candidate": "five",
        "generation": facts["generation"], "repository_boundary": facts["repository_boundary"],
        "dependencies": facts["dependencies"], "source_inputs": facts["source_inputs"],
        "outputs": {role: _record(str(generated.root / FINAL_NAMES[role]), generated.payloads[role], role) for role in ROLE_ORDER},
        "cross_format_authority": {
            "schema": "hermternal.issue-397.candidate-five-authority.v1",
            "normalized_json_sha256": normalized,
            "json_shell_sha256": hashlib.sha256(document["execution_driver"]["shell"].encode()).hexdigest(),
            "markdown_shell_sha256": hashlib.sha256(shell).hexdigest(),
            "fresh_cli_argv_sha256": hashlib.sha256(json.dumps(document["execution_driver"]["argv"], separators=(",", ":")).encode()).hexdigest(),
            "all_shell_hashes_equal": True,
        },
        "publication": facts["publication"], "safety_claims": facts["safety_claims"],
    }
    require(set(value) == PROVENANCE_KEYS, "provenance fields differ")
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def create_once(path: Path, raw: bytes) -> Snapshot:
    """Create one private regular file, fsync it, and stable-reread it."""
    require(path.parent.is_dir() and not path.exists() and not path.is_symlink(), f"create-only target exists: {path}")
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=parent_fd)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view); require(count > 0, "create-only write made no progress"); view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
        os.fsync(parent_fd)
        os.close(parent_fd)
    return stable_read(path, path.name, links={1})


def inspect_complete(root: Path, descriptor_sha256: str, provenance_sha256: str) -> Any:
    """Accept only a complete triad, distinct descriptor, and provenance set."""
    root = Path(root)
    paths = [root / FINAL_NAMES[role] for role in ROLE_ORDER] + [root / DESCRIPTOR_NAME, root / PROVENANCE_NAME]
    present = [path.exists() and not path.is_symlink() for path in paths]
    require(all(present), f"publication set is incomplete: {[path.name for path, exists in zip(paths, present) if not exists]}")
    authority = verified_module(AUTHORITY, EXPECTED[AUTHORITY], "candidate5_final_authority")
    result = authority.validate(root / DESCRIPTOR_NAME, root, descriptor_sha256)
    provenance = stable_read(root / PROVENANCE_NAME, "provenance", links={1})
    require(provenance.sha256 == provenance_sha256, "provenance SHA-256 differs")
    value = authority.parse_object(provenance.raw, "provenance")
    require(set(value) == PROVENANCE_KEYS and value["schema"] == PROVENANCE_SCHEMA, "provenance schema differs")
    for role in ROLE_ORDER:
        require(value["outputs"][role]["sha256"] == result.artifacts[role].sha256, f"{role} provenance differs")
    return result


def require_publication_compatibility(publication_module: types.ModuleType, authority_module: types.ModuleType) -> None:
    """Reject the current #401/#402 link-count contract mismatch.

    #402 calls its validator while stage and public names still share an inode.
    #401 accepts only a final single-link artifact. Final publication stays
    # blocked until one reviewed dependency closes this mismatch.
    """
    require(PUBLICATION.exists(), "#402 is absent; the nlink=1 publication contract cannot be checked")
    source = stable_read(PUBLICATION.resolve(), "publication successor", links={1}).raw
    authority_source = stable_read(AUTHORITY.resolve(), "authority successor", links={1}).raw
    incompatible = b"result = validate(paths" in source and b"st_nlink == 1" in authority_source
    require(not incompatible, "#401 requires nlink=1 but #402 validates while stage links keep nlink=2")


def publish_final(*_args: Any, **_kwargs: Any) -> None:
    """Fail closed until the approved #402 integration is contract-compatible."""
    verify_dependencies(include_publication=True)
    authority = verified_module(AUTHORITY, EXPECTED[AUTHORITY], "candidate5_final_authority_publish")
    publication = verified_module(PUBLICATION, EXPECTED[PUBLICATION], "candidate5_final_publication")
    require_publication_compatibility(publication, authority)
    raise Reject("final publication is not enabled in the speculative checkpoint")
