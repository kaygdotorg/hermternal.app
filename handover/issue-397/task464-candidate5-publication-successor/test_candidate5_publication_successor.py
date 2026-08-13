#!/usr/bin/env python3
"""Adversarial tests for candidate-five create-only publication."""
from __future__ import annotations
import importlib.util, os, shutil, stat, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("candidate5_publication", HERE / "candidate5_publication_successor.py")
MODULE = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = MODULE; SPEC.loader.exec_module(MODULE)

class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="issue397-publish-"); self.root = Path(self.temp.name).resolve(); os.chmod(self.root, 0o700)
        self.targets = tuple(self.root / name for name in MODULE.NAMES); self.payloads = (b"markdown\n", b'{"json":true}\n', b"#!/bin/bash\n")
    def tearDown(self): self.temp.cleanup()
    def assert_absent(self): self.assertTrue(all(not path.exists() for path in self.targets))
    def test_success_modes_bytes_and_idempotent_rejection(self):
        MODULE.publish(self.targets, self.payloads)
        for path, raw in zip(self.targets, self.payloads): self.assertEqual(path.read_bytes(), raw); self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        before = [path.stat().st_ino for path in self.targets]
        with self.assertRaises(MODULE.Reject): MODULE.publish(self.targets, self.payloads)
        self.assertEqual(before, [path.stat().st_ino for path in self.targets])
    def test_preexistence_symlink_and_role_mismatch_never_overwrite(self):
        foreign = self.root / "foreign"; foreign.write_bytes(b"foreign"); foreign.chmod(0o600); os.symlink(foreign, self.targets[0])
        with self.assertRaises(MODULE.Reject): MODULE.publish(self.targets, self.payloads)
        self.assertTrue(self.targets[0].is_symlink()); self.assertEqual(foreign.read_bytes(), b"foreign")
        with self.assertRaises(MODULE.Reject): MODULE.publish((self.targets[1], self.targets[0], self.targets[2]), self.payloads)
    def test_link_failure_and_after_effect_link_failure_roll_back(self):
        original = os.link; calls = 0
        def fail_second(*args, **kwargs):
            nonlocal calls; calls += 1
            if calls == 2: raise OSError("link failure")
            return original(*args, **kwargs)
        with self.assertRaises(MODULE.Reject): MODULE.publish(self.targets, self.payloads, link_impl=fail_second)
        self.assert_absent()
        calls = 0
        def link_then_fail(*args, **kwargs):
            nonlocal calls; calls += 1; original(*args, **kwargs)
            if calls == 2: raise OSError("after effect")
        with self.assertRaises(MODULE.Reject): MODULE.publish(self.targets, self.payloads, link_impl=link_then_fail)
        self.assert_absent()
    def test_fsync_and_validation_failures_roll_back_partial_publication(self):
        original = os.fsync; calls = 0
        def fail(*args):
            nonlocal calls; calls += 1
            if calls == 5: raise OSError("fsync failure")
            original(*args)
        with self.assertRaises(MODULE.Reject): MODULE.publish(self.targets, self.payloads, fsync_impl=fail)
        self.assert_absent()
        with self.assertRaises(MODULE.Reject): MODULE.publish(self.targets, self.payloads, validate=lambda *_: (_ for _ in ()).throw(RuntimeError("validation")))
        self.assert_absent()
    def test_foreign_replacement_is_preserved_and_reported_as_residue(self):
        foreign = self.root / "foreign"; foreign.write_bytes(b"foreign"); foreign.chmod(0o600)
        def replace_then_fail(paths, _payloads):
            moved = self.root / "owned-moved"; os.rename(paths[0], moved); os.rename(foreign, paths[0]); raise RuntimeError("replace")
        with self.assertRaisesRegex(MODULE.Reject, "residue"):
            MODULE.publish(self.targets, self.payloads, validate=replace_then_fail)
        self.assertEqual(self.targets[0].read_bytes(), b"foreign")
    def test_validator_successful_foreign_swap_never_returns_success(self):
        for index, role in enumerate(MODULE.ROLES):
            with self.subTest(role=role):
                foreign = self.root / f"foreign-{role}"; foreign.write_bytes(b"foreign"); foreign.chmod(0o600)
                moved = self.root / f"owned-moved-{role}"
                def replace_and_return(paths, _payloads):
                    os.rename(paths[index], moved); os.rename(foreign, paths[index]); return "must-not-return"
                with self.assertRaisesRegex(MODULE.Reject, "residue"):
                    MODULE.publish(self.targets, self.payloads, validate=replace_and_return)
                self.assertEqual(self.targets[index].read_bytes(), b"foreign")
                os.unlink(self.targets[index]); os.unlink(moved)
    def test_post_link_reconciliation_observation_failure_cleans_owned_target(self):
        original_stat = MODULE.os.stat; injected = False
        def fail_once_after_link(path, *args, **kwargs):
            nonlocal injected
            if path == self.targets[0].name and kwargs.get("dir_fd") is not None and not injected:
                try: original_stat(path, *args, **kwargs)
                except FileNotFoundError: return original_stat(path, *args, **kwargs)
                injected = True; raise OSError("reconciliation observation failure")
            return original_stat(path, *args, **kwargs)
        with patch.object(MODULE.os, "stat", side_effect=fail_once_after_link):
            with self.assertRaisesRegex(MODULE.Reject, "rolled back"):
                MODULE.publish(self.targets, self.payloads)
        self.assertTrue(injected); self.assert_absent()
    def test_parent_rename_or_symlink_substitution_rejects(self):
        parent = self.root.parent; moved = parent / (self.root.name + "-moved"); replacement = parent / (self.root.name + "-replacement"); replacement.mkdir(mode=0o700)
        original = os.link; calls = 0
        def swap(*args, **kwargs):
            nonlocal calls; calls += 1
            if calls == 1: os.rename(self.root, moved); os.rename(replacement, self.root)
            return original(*args, **kwargs)
        with self.assertRaises(MODULE.Reject): MODULE.publish(self.targets, self.payloads, link_impl=swap)
        self.assertTrue(self.root.is_dir())
        shutil.rmtree(self.root); os.rename(moved, self.root)

        outside = self.root / "symlink-target"; outside.mkdir(mode=0o700)
        moved = parent / (self.root.name + "-symlink-moved"); calls = 0
        def symlink_swap(*args, **kwargs):
            nonlocal calls; calls += 1
            if calls == 1:
                os.rename(self.root, moved); os.symlink(moved / "symlink-target", self.root)
            return original(*args, **kwargs)
        with self.assertRaises(MODULE.Reject): MODULE.publish(self.targets, self.payloads, link_impl=symlink_swap)
        self.assertTrue(self.root.is_symlink())
        os.unlink(self.root); os.rename(moved, self.root)

if __name__ == "__main__": unittest.main(verbosity=2)
