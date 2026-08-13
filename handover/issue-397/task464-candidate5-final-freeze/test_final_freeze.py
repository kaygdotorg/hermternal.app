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

    def assert_empty(self, root: Path) -> None:
        self.assertEqual(list(root.iterdir()), [])

    def injected_create_failure(self, name_to_fail: str, *, stage: str):
        original = FREEZE.create_once

        def fail(root, name, raw, **kwargs):
            if name != name_to_fail:
                return original(root, name, raw, **kwargs)
            if stage == "create":
                original_open = FREEZE.os.open
                def reject_open(path, *args, **open_kwargs):
                    if path == name and open_kwargs.get("dir_fd") is not None:
                        raise OSError("injected create")
                    return original_open(path, *args, **open_kwargs)
                with mock.patch.object(FREEZE.os, "open", side_effect=reject_open):
                    return original(root, name, raw, **kwargs)
            if stage == "write":
                return original(root, name, raw, write_impl=lambda *_: (_ for _ in ()).throw(OSError("injected write")), **kwargs)
            return original(root, name, raw, fsync_impl=lambda *_: (_ for _ in ()).throw(OSError("injected fsync")), **kwargs)

        return fail

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
            root = self.private_root(parent)
            with self.assertRaisesRegex(FREEZE.Reject, "rolled back") as raised:
                FREEZE.freeze_to_root(root, publication=BrokenPublication())
            self.assertEqual(raised.exception.residue, ())
            self.assert_empty(root)

    def test_descriptor_and_provenance_write_or_fsync_failures_roll_back(self) -> None:
        for name, stage in ((FREEZE.NAMES[3], "create"), (FREEZE.NAMES[3], "write"), (FREEZE.NAMES[3], "fsync"), (FREEZE.NAMES[4], "create"), (FREEZE.NAMES[4], "write"), (FREEZE.NAMES[4], "fsync")):
            with self.subTest(name=name, stage=stage), tempfile.TemporaryDirectory() as parent:
                root = self.private_root(parent)
                with mock.patch.object(FREEZE, "create_once", side_effect=self.injected_create_failure(name, stage=stage)):
                    with self.assertRaisesRegex(FREEZE.Reject, "rolled back") as raised:
                        FREEZE.freeze_to_root(root)
                self.assertEqual(raised.exception.residue, ())
                self.assert_empty(root)

    def test_provenance_generation_failure_rolls_back_descriptor_and_triad(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = self.private_root(parent)
            orchestrator, publication = FREEZE.load_approved()
            with mock.patch.object(orchestrator, "provenance_bytes", side_effect=OSError("injected provenance")):
                with self.assertRaisesRegex(FREEZE.Reject, "rolled back") as raised:
                    FREEZE.freeze_to_root(root, orchestrator=orchestrator, publication=publication)
            self.assertEqual(raised.exception.residue, ())
            self.assert_empty(root)

    def test_foreign_replacement_after_callback_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = self.private_root(parent)
            orchestrator, publication = FREEZE.load_approved()
            target = root / FREEZE.NAMES[0]
            def replace_then_fail(*_args, **_kwargs):
                foreign = root / "foreign"
                foreign.write_bytes(b"foreign\n"); os.chmod(foreign, 0o600)
                os.replace(foreign, target)
                raise OSError("injected foreign replacement")
            with mock.patch.object(orchestrator, "provenance_bytes", side_effect=replace_then_fail):
                with self.assertRaisesRegex(FREEZE.Reject, "foreign-replacement") as raised:
                    FREEZE.freeze_to_root(root, orchestrator=orchestrator, publication=publication)
            self.assertEqual(target.read_bytes(), b"foreign\n")
            self.assertTrue(any(item.state == "foreign-replacement" for item in raised.exception.residue))
            with self.assertRaisesRegex(FREEZE.Reject, "partial residue"):
                FREEZE.freeze_to_root(root, orchestrator=orchestrator, publication=publication)

    def test_unknown_moved_triad_is_reported_and_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = self.private_root(parent)
            orchestrator, publication = FREEZE.load_approved()
            target = root / FREEZE.NAMES[0]
            moved = root / "moved-owned-triad"
            def move_then_fail(*_args, **_kwargs):
                os.rename(target, moved)
                raise OSError("injected move")
            with mock.patch.object(orchestrator, "provenance_bytes", side_effect=move_then_fail):
                with self.assertRaisesRegex(FREEZE.Reject, "owned-moved-or-unknown") as raised:
                    FREEZE.freeze_to_root(root, orchestrator=orchestrator, publication=publication)
            self.assertTrue(moved.exists())
            self.assertTrue(any(item.state == "owned-moved-or-unknown" for item in raised.exception.residue))

    def test_foreign_descriptor_and_provenance_replacements_are_preserved(self) -> None:
        for target_name, after_creation in ((FREEZE.NAMES[3], False), (FREEZE.NAMES[4], True)):
            with self.subTest(target_name=target_name), tempfile.TemporaryDirectory() as parent:
                root = self.private_root(parent)
                orchestrator, publication = FREEZE.load_approved()
                target = root / target_name
                def replace_target():
                    foreign = root / "foreign"
                    foreign.write_bytes(b"foreign\n"); os.chmod(foreign, 0o600)
                    os.replace(foreign, target)
                    raise OSError("injected foreign replacement")
                if after_creation:
                    with mock.patch.object(orchestrator, "inspect_complete", side_effect=lambda *_: replace_target()):
                        with self.assertRaisesRegex(FREEZE.Reject, "foreign-replacement") as raised:
                            FREEZE.freeze_to_root(root, orchestrator=orchestrator, publication=publication)
                else:
                    with mock.patch.object(orchestrator, "provenance_bytes", side_effect=lambda *_: replace_target()):
                        with self.assertRaisesRegex(FREEZE.Reject, "foreign-replacement") as raised:
                            FREEZE.freeze_to_root(root, orchestrator=orchestrator, publication=publication)
                self.assertEqual(target.read_bytes(), b"foreign\n")
                self.assertTrue(any(item.state == "foreign-replacement" and item.name == target_name for item in raised.exception.residue))

    def test_parent_swap_after_callback_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = self.private_root(parent)
            moved = root.with_name("moved")
            orchestrator, publication = FREEZE.load_approved()
            authority = orchestrator.verified_module(orchestrator.AUTHORITY, orchestrator.EXPECTED[orchestrator.AUTHORITY], "swap_authority")
            original_validate = authority.validate
            def swap_validate(*args, **kwargs):
                result = original_validate(*args, **kwargs)
                os.rename(root, moved); root.mkdir(mode=0o700)
                return result
            authority.validate = swap_validate
            original_verified = orchestrator.verified_module
            def verified(path, *args, **kwargs):
                if path == orchestrator.AUTHORITY:
                    return authority
                return original_verified(path, *args, **kwargs)
            try:
                with mock.patch.object(orchestrator, "verified_module", side_effect=verified):
                    with self.assertRaisesRegex(FREEZE.Reject, "root-replaced-or-unknown") as raised:
                        FREEZE.freeze_to_root(root, orchestrator=orchestrator, publication=publication)
                self.assertTrue(any(item.state == "root-replaced-or-unknown" for item in raised.exception.residue))
                self.assert_empty(moved)
            finally:
                shutil.rmtree(root, ignore_errors=True)
                if moved.exists(): os.rename(moved, root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
