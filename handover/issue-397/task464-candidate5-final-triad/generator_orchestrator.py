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
import re
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
#402 is not approved yet. Its path and exact SHA-256 are explicit inputs to the
#behavioral compatibility gate. No speculative branch tip is called approved.
PUBLICATION = BASE / "task464-candidate5-publication-successor" / "candidate5_publication_successor.py"
APPROVED_PUBLICATION_COMMIT = "bad52e81aac1e29639847339e789915eb0e9039c"
APPROVED_PUBLICATION_SHA256 = "09c7a0e514f64ed89b475ff1f7e0c24a4b28477837b7a575aa0952377ea22c28"
INPUT_JSON = BASE / "task464-inputs" / "task464-working-input.json"
INPUT_MARKDOWN = BASE / "task464-inputs" / "task464-working-input.md"
EXPECTED = {
    FRAMING: "4287f89d87971f62c3f11504713134de9caba4290606b3c90eac63632125861e",
    AUTHORITY: "1eec1b59f608a3c64d4abb532fe6dbe031c4ba8008b46775db3ee6a75c9bb9a8",
    GIT_AUTHORITY: "b2b5a5f1e0ed813325a23cb32eb075b2637872f5c5176e81c79879af4ab1861a",
    INPUT_JSON: "82f5f9b1f099304723d6e74220488011a46e785eab4a26e9aec1babeef95251c",
    INPUT_MARKDOWN: "4cc01babd55f9092aeb461dd0c9b5d918819564fec2d6ac4067e324e4c3e9adf",
}
PROVENANCE_SCHEMA = "hermternal.issue-397.candidate-five-provenance.v1"
PROVENANCE_KEYS = frozenset({
    "schema", "issue", "candidate", "generation", "repository_boundary",
    "dependencies", "source_inputs", "outputs", "cross_format_authority",
    "publication", "safety_claims",
})
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")


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


def verify_dependencies() -> dict[str, Snapshot]:
    """Bind every generation input before any generated bytes are accepted."""
    snapshots = {}
    for path, digest in EXPECTED.items():
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
    captured["markdown"] = close_markdown_authority(captured["markdown"])
    require(not any(path.exists() or path.is_symlink() for path in targets.values()), "generation created a public name")
    require(captured["shell"] in captured["markdown"], "Markdown does not contain the generated shell")
    document = json.loads(captured["json"].decode("utf-8"))
    require(document["execution_driver"]["shell"].encode("utf-8") == captured["shell"], "JSON shell differs")
    return Generated(root, dict(captured))


def close_markdown_authority(raw: bytes) -> bytes:
    """Make the one #401 shell fence the only exact closing-fence record.

    The durable source has later prose code fences. #401 defines every later
    exact closing delimiter as ambiguous. This explicit final-only adaptation
    replaces only later closing records with an HTML comment. It does not touch
    the authoritative fence, its shell body, or any opening-fence record.
    """
    heading = raw.find(b"## Canonical machine-readable ordered execution driver\n")
    require(heading >= 0, "Markdown authority heading is absent")
    opening = raw.find(b"```bash\n", heading)
    require(opening >= 0, "Markdown authority opening fence is absent")
    closing = re.search(rb"(?m)^```[ \t]*(?:\n|\Z)", raw[opening + 8:])
    require(closing is not None, "Markdown authority closing fence is absent")
    end = opening + 8 + closing.end()
    prefix, suffix = raw[:end], raw[end:]
    adapted, count = re.subn(rb"(?m)^```[ \t]*(?=\n|\Z)", b"<!-- candidate-five non-authority fence boundary -->", suffix)
    require(re.search(rb"(?m)^```[ \t]*(?:\n|\Z)", adapted) is None, "ambiguous later Markdown closing fence remains")
    require(count > 0, "expected durable later Markdown fences are absent")
    return prefix + adapted


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


def _cross_format(raw_json: bytes, raw_markdown: bytes, raw_shell: bytes, authority: types.ModuleType) -> dict[str, Any]:
    """Derive every cross-format field through the approved #401 algorithms."""
    document = authority.parse_object(raw_json, "authority JSON")
    execution = document.get("execution_driver")
    require(isinstance(execution, dict), "JSON execution_driver is absent")
    json_shell = execution.get("shell", "").encode("utf-8")
    markdown_shell = authority.extract_shell(raw_markdown)
    require(json_shell == markdown_shell == raw_shell, "JSON, Markdown, and standalone shell bytes differ")
    normalized = execution.get("matrix_identity", {}).get("expected_normalized_sha256", "")
    require(authority.normalized_json_sha256(raw_json, normalized) == normalized, "normalized JSON identity differs")
    argv = execution.get("argv")
    require(tuple(argv) == authority.ARGV, "authenticated argv differs")
    hashes = [hashlib.sha256(item).hexdigest() for item in (json_shell, markdown_shell, raw_shell)]
    return {
        "schema": authority.SCHEMA, "normalized_json_sha256": normalized,
        "json_shell_sha256": hashes[0], "markdown_shell_sha256": hashes[1],
        "shell_sha256": hashes[2],
        "fresh_cli_argv_sha256": hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode()).hexdigest(),
        "all_shell_hashes_equal": len(set(hashes)) == 1,
    }


def provenance_bytes(generated: Generated, facts: Mapping[str, Any], authority_module: types.ModuleType) -> bytes:
    """Build deterministic provenance from a closed, caller-supplied fact set."""
    require(set(facts) == {"generation", "repository_boundary", "dependencies", "source_inputs", "publication", "safety_claims"}, "provenance facts differ")
    cross_format = _cross_format(generated.payloads["json"], generated.payloads["markdown"], generated.payloads["shell"], authority_module)
    require(cross_format["all_shell_hashes_equal"] is True, "cross-format shell hashes differ")
    value = {
        "schema": PROVENANCE_SCHEMA, "issue": 397, "candidate": "five",
        "generation": facts["generation"], "repository_boundary": facts["repository_boundary"],
        "dependencies": facts["dependencies"], "source_inputs": facts["source_inputs"],
        "outputs": {role: _record(str(generated.root / FINAL_NAMES[role]), generated.payloads[role], role) for role in ROLE_ORDER},
        "cross_format_authority": cross_format,
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
    derived = _cross_format(result.artifacts["json"].raw, result.artifacts["markdown"].raw, result.artifacts["shell"].raw, authority)
    require(value["cross_format_authority"] == derived, "cross-format provenance differs from exact triad")
    return result


def publication_module(path: Path, approved_sha256: str) -> types.ModuleType:
    """Load #402 only from an explicit approved path and exact digest."""
    require(SHA_RE.fullmatch(approved_sha256) is not None, "approved #402 SHA-256 is invalid")
    return verified_module(Path(path), approved_sha256, "candidate5_final_publication")


def approved_publication_module() -> types.ModuleType:
    """Load the exact independently approved #402 implementation."""
    require(len(APPROVED_PUBLICATION_COMMIT) == 40, "approved #402 commit is invalid")
    return publication_module(PUBLICATION, APPROVED_PUBLICATION_SHA256)


def behavioral_publication_check(
    publication: types.ModuleType,
    generated: Generated,
    authority: types.ModuleType,
) -> Any:
    """Prove #402 calls genuine #401 against final single-link public files.

    Compatibility is a behavior, not a source-text shape. The caller provides a
    module that was already loaded from explicitly pinned bytes.
    """
    require(callable(getattr(publication, "publish", None)), "#402 publish API is absent")
    descriptor = descriptor_bytes(generated, authority)
    descriptor_path = generated.root / DESCRIPTOR_NAME
    descriptor_snapshot = create_once(descriptor_path, descriptor)
    calls = 0

    def validate(paths: tuple[Path, ...], payloads: tuple[bytes, ...]) -> Any:
        nonlocal calls
        calls += 1
        require(paths == tuple(generated.root / FINAL_NAMES[role] for role in ROLE_ORDER), "#402 callback role paths differ")
        require(payloads == tuple(generated.payloads[role] for role in ROLE_ORDER), "#402 callback payloads differ")
        # This is the genuine #401 validator. It requires each public artifact
        # to have nlink=1 and binds JSON, Markdown, shell, argv, and stdin.
        return authority.validate(descriptor_path, generated.root, descriptor_snapshot.sha256)

    result = publication.publish(
        tuple(generated.root / FINAL_NAMES[role] for role in ROLE_ORDER),
        tuple(generated.payloads[role] for role in ROLE_ORDER),
        validate=validate,
    )
    require(calls == 1, "#402 did not call genuine #401 exactly once")
    require(result.argv == authority.ARGV and result.stdin == generated.payloads["shell"], "#401 callback result differs")
    for role in ROLE_ORDER:
        snapshot = stable_read(generated.root / FINAL_NAMES[role], role, links={1})
        require(snapshot.raw == generated.payloads[role], f"{role} final bytes differ")
    return result


def publish_final(*_args: Any, **_kwargs: Any) -> None:
    """Keep final publication disabled until #402 has an approved exact pin."""
    raise Reject("final publication is disabled until #402 approval and final freeze review")
