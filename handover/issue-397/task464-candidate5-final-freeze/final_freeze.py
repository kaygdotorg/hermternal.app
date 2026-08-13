#!/usr/bin/env python3
"""Create the candidate-five final set once, without executing its shell.

This activation is intentionally narrow.  It only composes reviewed #403 and
#402 bytes, and it rejects a partial or replaced final set rather than trying
to repair or adopt it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping


BASE = Path(__file__).resolve().parents[1]
FINAL_ROOT = BASE / "task464-candidate5-final"
ORCHESTRATOR = BASE / "task464-candidate5-final-triad" / "generator_orchestrator.py"
PUBLICATION = BASE / "task464-candidate5-publication-successor" / "candidate5_publication_successor.py"
ORCHESTRATOR_SHA256 = "d9c36a3c3e99d0379186fc9ea0a26a5d93ac26eb4bd1c826c209b9bee0547361"
PUBLICATION_SHA256 = "09c7a0e514f64ed89b475ff1f7e0c24a4b28477837b7a575aa0952377ea22c28"
PUBLICATION_COMMIT = "bad52e81aac1e29639847339e789915eb0e9039c"
NAMES = ("candidate-five.md", "candidate-five.json", "candidate-five.sh", "authority-descriptor.json", "provenance-manifest.json")
ROLE_NAMES = ("markdown", "json", "shell")


class Reject(Exception):
    """Fail closed before a final set can be mistaken for valid evidence."""


@dataclass(frozen=True)
class Snapshot:
    path: Path
    raw: bytes
    sha256: str
    identity: tuple[int, int, int, int, int, int]


@dataclass(frozen=True)
class FreezeResult:
    root: Path
    snapshots: Mapping[str, Snapshot]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Reject(message)


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_uid, stat.S_IMODE(value.st_mode), value.st_size, value.st_nlink)


def stable_read(path: Path, label: str, *, limit: int = 8 * 1024 * 1024, mode: int = 0o600) -> Snapshot:
    """Read one single-link regular file through stable no-follow handles."""
    path = Path(path)
    require(path.is_absolute() and os.path.realpath(path) == os.fspath(path), f"{label} path is not canonical")
    samples: list[Snapshot] = []
    for _ in range(3):
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == mode, f"{label} mode differs")
            require(before.st_nlink == 1 and 0 < before.st_size <= limit, f"{label} identity differs")
            chunks: list[bytes] = []
            remaining = limit + 1
            while remaining:
                block = os.read(fd, min(131072, remaining))
                if not block:
                    break
                chunks.append(block)
                remaining -= len(block)
            require(remaining > 0, f"{label} exceeds its bound")
            after = os.fstat(fd)
        finally:
            os.close(fd)
        final = os.stat(path, follow_symlinks=False)
        require(_identity(before) == _identity(after) == _identity(final), f"{label} changed during read")
        raw = b"".join(chunks)
        samples.append(Snapshot(path, raw, hashlib.sha256(raw).hexdigest(), _identity(before)))
    require(samples[0] == samples[1] == samples[2], f"{label} changed across reads")
    return samples[0]


def verified_module(path: Path, digest: str, name: str) -> types.ModuleType:
    """Compile only the exact bytes read through the verified descriptor."""
    snapshot = stable_read(path.resolve(), name, mode=0o644)
    require(snapshot.sha256 == digest, f"{name} SHA-256 differs")
    module = types.ModuleType(name)
    module.__file__ = str(path.resolve())
    module.__loader__ = None
    module.__package__ = ""
    module.__spec__ = None
    sys.modules[name] = module
    exec(compile(snapshot.raw, module.__file__, "exec", dont_inherit=True), module.__dict__)
    return module


def load_approved() -> tuple[types.ModuleType, types.ModuleType]:
    """Bind the exact reviewed #403 coordinator and #402 publisher."""
    orchestrator = verified_module(ORCHESTRATOR, ORCHESTRATOR_SHA256, "candidate5_final_freeze_orchestrator")
    publication = verified_module(PUBLICATION, PUBLICATION_SHA256, "candidate5_final_freeze_publication")
    require(orchestrator.APPROVED_PUBLICATION_COMMIT == PUBLICATION_COMMIT, "#403 publication commit pin differs")
    require(orchestrator.APPROVED_PUBLICATION_SHA256 == PUBLICATION_SHA256, "#403 publication hash pin differs")
    require(tuple(orchestrator.FINAL_NAMES.values()) == NAMES[:3], "#403 final role names differ")
    require(callable(getattr(publication, "publish", None)), "#402 publication API is absent")
    return orchestrator, publication


def _root_identity(root: Path) -> tuple[int, int, int, int]:
    value = os.lstat(root)
    require(stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode), "output root is not a directory")
    require(value.st_uid == os.getuid() and stat.S_IMODE(value.st_mode) == 0o700, "output root must be owned mode 0700")
    return (value.st_dev, value.st_ino, value.st_uid, stat.S_IMODE(value.st_mode))


def _parent_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    """A newly-created child changes link count, so do not bind that field."""
    return (value.st_dev, value.st_ino, value.st_uid, stat.S_IMODE(value.st_mode))


def ensure_root(root: Path, *, fsync_impl: Callable[[int], None] = os.fsync) -> tuple[int, int, int, int]:
    """Create a canonical private root once, then bind its identity."""
    root = Path(root)
    require(root.is_absolute() and os.path.realpath(root) == os.fspath(root), "output root is not canonical")
    parent = root.parent
    parent_before = os.lstat(parent)
    require(stat.S_ISDIR(parent_before.st_mode) and not stat.S_ISLNK(parent_before.st_mode), "output parent is not a directory")
    try:
        os.mkdir(root, 0o700)
    except FileExistsError:
        pass
    parent_after = os.lstat(parent)
    require(_parent_identity(parent_before) == _parent_identity(parent_after), "output parent changed")
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        fsync_impl(parent_fd)
    finally:
        os.close(parent_fd)
    return _root_identity(root)


def require_absent(root: Path) -> None:
    """Reject every complete and partial prior output before any writer runs."""
    present = []
    for name in NAMES:
        try:
            os.lstat(root / name)
        except FileNotFoundError:
            continue
        present.append(name)
    require(not present, f"final output already has complete or partial residue: {present}")


def create_once(
    root: Path,
    name: str,
    raw: bytes,
    *,
    fsync_impl: Callable[[int], None] = os.fsync,
    write_impl: Callable[[int, memoryview], int] = os.write,
) -> Snapshot:
    """Create a distinct coordinator file with no replace or symlink follow."""
    require(name in NAMES and raw, "coordinator create request differs")
    path = root / name
    require_absent_path(path)
    parent_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=parent_fd)
        try:
            view = memoryview(raw)
            while view:
                count = write_impl(fd, view)
                require(count > 0, "coordinator write made no progress")
                view = view[count:]
            fsync_impl(fd)
        finally:
            os.close(fd)
        fsync_impl(parent_fd)
    finally:
        os.close(parent_fd)
    snapshot = stable_read(path, name)
    require(snapshot.raw == raw, f"{name} bytes differ after create")
    return snapshot


def require_absent_path(path: Path) -> None:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    raise Reject(f"create-only target exists: {path.name}")


def _facts(root: Path, orchestrator: types.ModuleType) -> dict[str, Any]:
    """Use deterministic, non-secret facts for the separate provenance record."""
    dependencies = [
        {"path": str(ORCHESTRATOR), "sha256": ORCHESTRATOR_SHA256},
        {"path": str(PUBLICATION), "sha256": PUBLICATION_SHA256, "commit": PUBLICATION_COMMIT},
    ]
    sources = [
        {"path": path, "sha256": snapshot.sha256}
        for path, snapshot in sorted(orchestrator.verify_dependencies().items())
    ]
    self_snapshot = stable_read(Path(__file__).resolve(), "final-freeze source", mode=0o644)
    return {
        "generation": {"path": str(Path(__file__).resolve()), "sha256": self_snapshot.sha256, "mode": "0644"},
        "repository_boundary": {"output_root": str(root)},
        "dependencies": dependencies,
        "source_inputs": sources,
        "publication": {"commit": PUBLICATION_COMMIT, "sha256": PUBLICATION_SHA256, "roles": list(ROLE_NAMES)},
        "safety_claims": {"shell_executed": False, "replay_run": False, "network_used": False, "credentials_used": False, "hermes_used": False},
    }


def freeze_to_root(
    root: Path,
    *,
    fsync_impl: Callable[[int], None] = os.fsync,
    orchestrator: types.ModuleType | None = None,
    publication: types.ModuleType | None = None,
) -> FreezeResult:
    """Publish exactly the reviewed five-file set or reject it as incomplete."""
    root = Path(root)
    require(root.is_absolute() and os.path.realpath(root) == os.fspath(root), "output root is not canonical")
    root_identity = ensure_root(root, fsync_impl=fsync_impl)
    require_absent(root)
    try:
        if orchestrator is None or publication is None:
            approved_orchestrator, approved_publication = load_approved()
            orchestrator = approved_orchestrator if orchestrator is None else orchestrator
            publication = approved_publication if publication is None else publication
        generated = orchestrator.generate_in_memory(root)
        authority = orchestrator.verified_module(orchestrator.AUTHORITY, orchestrator.EXPECTED[orchestrator.AUTHORITY], "candidate5_final_freeze_authority")
        descriptor = orchestrator.descriptor_bytes(generated, authority)
        descriptor_snapshot = create_once(root, NAMES[3], descriptor, fsync_impl=fsync_impl)
        calls = 0

        def validate(paths: tuple[Path, ...], payloads: tuple[bytes, ...]) -> Any:
            nonlocal calls
            calls += 1
            require(paths == tuple(root / orchestrator.FINAL_NAMES[role] for role in ROLE_NAMES), "#402 callback paths differ")
            require(payloads == tuple(generated.payloads[role] for role in ROLE_NAMES), "#402 callback payloads differ")
            return authority.validate(root / NAMES[3], root, descriptor_snapshot.sha256)

        publication.publish(
            tuple(root / orchestrator.FINAL_NAMES[role] for role in ROLE_NAMES),
            tuple(generated.payloads[role] for role in ROLE_NAMES),
            validate=validate,
        )
        require(calls == 1, "#402 did not call genuine #401 exactly once")
        require(_root_identity(root) == root_identity, "output root changed during publication")
        snapshots: dict[str, Snapshot] = {NAMES[3]: descriptor_snapshot}
        for role in ROLE_NAMES:
            name = orchestrator.FINAL_NAMES[role]
            snapshot = stable_read(root / name, role)
            require(snapshot.raw == generated.payloads[role], f"{role} bytes differ after publication")
            snapshots[name] = snapshot
        provenance = orchestrator.provenance_bytes(generated, _facts(root, orchestrator), authority)
        provenance_snapshot = create_once(root, NAMES[4], provenance, fsync_impl=fsync_impl)
        snapshots[NAMES[4]] = provenance_snapshot
        require(_root_identity(root) == root_identity, "output root changed before final inspection")
        orchestrator.inspect_complete(root, descriptor_snapshot.sha256, provenance_snapshot.sha256)
        for name in NAMES:
            snapshots[name] = stable_read(root / name, name)
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
        try:
            fsync_impl(root_fd)
        finally:
            os.close(root_fd)
        return FreezeResult(root, snapshots)
    except Reject:
        raise
    except Exception as error:
        raise Reject(f"final freeze failed: {type(error).__name__}: {error}") from error


def _summary(result: FreezeResult) -> dict[str, Any]:
    return {
        "root": str(result.root),
        "outputs": {
            name: {"path": str(snapshot.path), "sha256": snapshot.sha256, "bytes": len(snapshot.raw), "mode": "0600"}
            for name, snapshot in sorted(result.snapshots.items())
        },
        "shell_executed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create reviewed candidate-five evidence without executing its shell.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--prepare", action="store_true", help="build and validate only inside a disposable private root")
    mode.add_argument("--publish", action="store_true", help="one-shot publication to the fixed durable final root")
    args = parser.parse_args(argv)
    if args.prepare:
        with tempfile.TemporaryDirectory(prefix="hermternal-candidate-five-prepare-") as parent:
            root = (Path(parent) / "output").resolve()
            result = freeze_to_root(root)
            print(json.dumps(_summary(result), sort_keys=True))
        return 0
    result = freeze_to_root(FINAL_ROOT)
    print(json.dumps(_summary(result), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
