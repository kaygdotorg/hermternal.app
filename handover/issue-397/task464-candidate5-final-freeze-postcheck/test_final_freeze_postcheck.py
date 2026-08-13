#!/usr/bin/env python3
"""Verify the already-published candidate-five freeze without republishing it."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
import types
import unittest
from dataclasses import dataclass
from pathlib import Path


BASE = Path(__file__).resolve().parents[1]
ROOT = (BASE / "task464-candidate5-final").resolve()
FREEZE_SOURCE = BASE / "task464-candidate5-final-freeze" / "final_freeze.py"
FREEZE_SHA256 = "714f6ef3fd780acccd1520a090428c3d4c20c1be8178e84114015b1c07f87316"
NAMES = (
    "candidate-five.md",
    "candidate-five.json",
    "candidate-five.sh",
    "authority-descriptor.json",
    "provenance-manifest.json",
)
EXPECTED = {
    "candidate-five.md": ("706237ec508d96f564e5395e86dba943a11eb5057fb676bf95b924815158dad9", 489562, 10203),
    "candidate-five.json": ("dd0e9873941c30aee7515a382e3ca7c282df840d2d4364a7dfa5f21fce0ecd60", 606157, 6945),
    "candidate-five.sh": ("f7d5adfc9178431942d62948ffaf1953a2273bdec002661def9d0e80ffc34676", 289369, 5977),
    "authority-descriptor.json": ("cf10f8286eca92d42130c17b9e086b8776dc385fa3a297c90725787415776f34", 756, 1),
    "provenance-manifest.json": ("363d6f62335a5ff9f92eefabe87dd568032e71871390fa9fc5ae6fd72e3ac320", 3649, 1),
}


@dataclass(frozen=True)
class Snapshot:
    raw: bytes
    sha256: str
    identity: tuple[int, int, int, int, int, int]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_uid, stat.S_IMODE(value.st_mode), value.st_size, value.st_nlink)


def stable_read(path: Path, expected_size: int, *, mode: int = 0o600) -> Snapshot:
    """Read the canonical output three times and bind each descriptor to its name."""
    require(path.is_absolute() and str(path) == os.path.realpath(path), f"{path.name}: path is not canonical")
    samples: list[Snapshot] = []
    for _ in range(3):
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode), f"{path.name}: not regular")
            require(before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == mode, f"{path.name}: owner or mode differs")
            require(before.st_nlink == 1 and before.st_size == expected_size, f"{path.name}: link count or size differs")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(fd, 131072)
                if not chunk:
                    break
                chunks.append(chunk)
            after = os.fstat(fd)
        finally:
            os.close(fd)
        final = os.lstat(path)
        require(identity(before) == identity(after) == identity(final), f"{path.name}: identity changed during read")
        raw = b"".join(chunks)
        samples.append(Snapshot(raw, hashlib.sha256(raw).hexdigest(), identity(before)))
    require(samples[0] == samples[1] == samples[2], f"{path.name}: identity changed across reads")
    return samples[0]


def load_verified_freeze() -> types.ModuleType:
    source = stable_read(FREEZE_SOURCE.resolve(), FREEZE_SOURCE.stat().st_size, mode=0o644)
    require(stat.S_IMODE(FREEZE_SOURCE.stat().st_mode) == 0o644, "final-freeze source mode differs")
    require(source.sha256 == FREEZE_SHA256, "final-freeze source SHA-256 differs")
    module = types.ModuleType("candidate5_postfreeze_final_freeze")
    module.__file__ = str(FREEZE_SOURCE.resolve())
    module.__loader__ = None
    module.__package__ = ""
    module.__spec__ = None
    sys.modules[module.__name__] = module
    exec(compile(source.raw, module.__file__, "exec", dont_inherit=True), module.__dict__)
    return module


class PostFreezeTests(unittest.TestCase):
    def stable_set(self) -> dict[str, Snapshot]:
        self.assertEqual(set(path.name for path in ROOT.iterdir()), set(NAMES))
        snapshots = {}
        for name in NAMES:
            digest, size, lfs = EXPECTED[name]
            snapshot = stable_read(ROOT / name, size)
            self.assertEqual(snapshot.sha256, digest)
            self.assertEqual(snapshot.raw.count(b"\n"), lfs)
            self.assertTrue(snapshot.raw.endswith(b"\n"))
            self.assertNotIn(b"\r", snapshot.raw)
            snapshots[name] = snapshot
        self.assertEqual(len({snapshot.identity[:2] for snapshot in snapshots.values()}), len(NAMES))
        return snapshots

    def test_existing_frozen_set_passes_approved_inspection_and_authority(self) -> None:
        snapshots = self.stable_set()
        freeze = load_verified_freeze()
        orchestrator, _publication = freeze.load_approved()
        result = orchestrator.inspect_complete(ROOT, snapshots["authority-descriptor.json"].sha256, snapshots["provenance-manifest.json"].sha256)
        authority = orchestrator.verified_module(orchestrator.AUTHORITY, orchestrator.EXPECTED[orchestrator.AUTHORITY], "candidate5_postfreeze_authority")
        document = json.loads(snapshots["candidate-five.json"].raw)
        markdown_shell = authority.extract_shell(snapshots["candidate-five.md"].raw)
        self.assertEqual(markdown_shell, document["execution_driver"]["shell"].encode("utf-8"))
        self.assertEqual(markdown_shell, snapshots["candidate-five.sh"].raw)
        self.assertEqual(result.stdin, snapshots["candidate-five.sh"].raw)
        self.assertEqual(result.argv, authority.ARGV)

    def test_second_publication_rejects_without_mutating_the_frozen_set(self) -> None:
        before = self.stable_set()
        freeze = load_verified_freeze()
        with self.assertRaisesRegex(freeze.Reject, "complete or partial residue"):
            freeze.freeze_to_root(ROOT)
        after = self.stable_set()
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
