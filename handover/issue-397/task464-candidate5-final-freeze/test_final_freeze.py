#!/usr/bin/env python3
"""Focused fail-closed tests for the #403 final-freeze activation."""
from __future__ import annotations

import importlib.util
import os
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("candidate5_final_freeze", HERE / "final_freeze.py")
assert SPEC and SPEC.loader
FREEZE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = FREEZE
SPEC.loader.exec_module(FREEZE)


class FreezeTests(unittest.TestCase):
    def private_root(self, parent: str) -> Path:
        root = (Path(parent) / "output").resolve()
        root.mkdir(mode=0o700)
        return root

    def test_absent_success_uses_exact_reviewed_modules(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = self.private_root(parent)
            result = FREEZE.freeze_to_root(root)
            self.assertEqual(set(result.snapshots), set(FREEZE.NAMES))
            for name in FREEZE.NAMES:
                self.assertEqual(oct((root / name).stat().st_mode & 0o777), "0o600")

    def test_any_preexisting_or_partial_output_rejects_before_writer_load(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            for name in FREEZE.NAMES:
                with self.subTest(name=name):
                    root = (Path(parent) / ("output-" + name)).resolve()
                    root.mkdir(mode=0o700)
                    (root / name).write_bytes(b"residue\n")
                    os.chmod(root / name, 0o600)
                    with mock.patch.object(FREEZE, "load_approved", side_effect=AssertionError("must not load")):
                        with self.assertRaisesRegex(FREEZE.Reject, "partial residue"):
                            FREEZE.freeze_to_root(root)
                    os.unlink(root / name)

    def test_prepare_is_disposable_and_never_uses_durable_root(self) -> None:
        self.assertFalse(FREEZE.FINAL_ROOT.exists())
        self.assertEqual(FREEZE.main(["--prepare"]), 0)
        self.assertFalse(FREEZE.FINAL_ROOT.exists())

    def test_verified_approved_pin_mismatch_rejects(self) -> None:
        with mock.patch.object(FREEZE, "ORCHESTRATOR_SHA256", "0" * 64):
            with self.assertRaisesRegex(FREEZE.Reject, "SHA-256"):
                FREEZE.load_approved()
        with mock.patch.object(FREEZE, "PUBLICATION_SHA256", "0" * 64):
            with self.assertRaisesRegex(FREEZE.Reject, "SHA-256"):
                FREEZE.load_approved()

    def test_create_once_write_and_fsync_failures_reject(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = self.private_root(parent)
            with self.assertRaises(OSError):
                FREEZE.create_once(root, FREEZE.NAMES[3], b"descriptor\n", write_impl=lambda *_: (_ for _ in ()).throw(OSError("write")))
            self.assertTrue((root / FREEZE.NAMES[3]).exists())
            os.unlink(root / FREEZE.NAMES[3])
            with self.assertRaises(OSError):
                FREEZE.create_once(root, FREEZE.NAMES[3], b"descriptor\n", fsync_impl=lambda *_: (_ for _ in ()).throw(OSError("fsync")))

    def test_publication_link_failure_rejects(self) -> None:
        class BrokenPublication:
            def publish(self, *_args, **_kwargs):
                raise OSError("link failure")
        with tempfile.TemporaryDirectory() as parent:
            with self.assertRaisesRegex(FREEZE.Reject, "link failure"):
                FREEZE.freeze_to_root(self.private_root(parent), publication=BrokenPublication())

    def test_foreign_replacement_after_callback_rejects(self) -> None:
        class ForeignPublication:
            def publish(self, targets, payloads, *, validate):
                for target, payload in zip(targets, payloads):
                    target.write_bytes(payload); os.chmod(target, 0o600)
                validate(tuple(targets), tuple(payloads))
                foreign = targets[0].with_name("foreign")
                foreign.write_bytes(b"foreign\n"); os.chmod(foreign, 0o600)
                os.replace(foreign, targets[0])
        with tempfile.TemporaryDirectory() as parent:
            with self.assertRaisesRegex(FREEZE.Reject, "bytes differ"):
                FREEZE.freeze_to_root(self.private_root(parent), publication=ForeignPublication())

    def test_parent_swap_after_callback_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = self.private_root(parent)
            moved = root.with_name("moved")
            class SwapPublication:
                def publish(self, targets, payloads, *, validate):
                    for target, payload in zip(targets, payloads):
                        target.write_bytes(payload); os.chmod(target, 0o600)
                    validate(tuple(targets), tuple(payloads))
                    os.rename(root, moved); root.mkdir(mode=0o700)
            try:
                with self.assertRaisesRegex(FREEZE.Reject, "output root changed"):
                    FREEZE.freeze_to_root(root, publication=SwapPublication())
            finally:
                shutil.rmtree(root, ignore_errors=True)
                if moved.exists(): os.rename(moved, root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
