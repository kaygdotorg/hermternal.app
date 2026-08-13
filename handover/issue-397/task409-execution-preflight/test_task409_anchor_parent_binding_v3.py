#!/usr/bin/env python3
"""Deterministic output-parent binding and rollback tests for Task #409."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


BUNDLE = Path(__file__).resolve().parent


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ANCHOR = load_module("task409_anchor_parent_binding_v3_tests", BUNDLE / "provision_task409_phase_a_anchor_v3.py")


class AnchorParentBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.parent = self.base / "output"
        self.parent.mkdir(mode=0o700)
        self.manifest_path = self.base / "phase-a-manifest.json"
        self.anchor_path = self.parent / "phase-a-anchor.json"
        self.policy = ANCHOR.PHASE_A._expected_policy()
        self.manifest = {
            "schema": ANCHOR.PHASE_A.SCHEMA,
            "phase": ANCHOR.PHASE_A.PHASE,
            "artifacts": {},
            "shell_metadata": {},
            "normalized_json_sha256": "0" * 64,
            "inputs": {},
            "stale": {},
            "policy": self.policy,
            "approval": {
                "status": "consistency-only",
                "manifest_sha256": "not-bound-in-phase-a",
                "policy_sha256": ANCHOR.PHASE_A.policy_digest(self.policy),
            },
        }
        self._write_json(self.manifest_path, self.manifest)
        self.manifest_sha = hashlib.sha256(self.manifest_path.read_bytes()).hexdigest()
        self.approval_digest = ANCHOR.PHASE_A.phase_a_approval_digest(self.manifest)
        self.policy_sha = ANCHOR.PHASE_A.policy_digest(self.policy)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_json(self, path: Path, value: object) -> None:
        path.write_bytes((json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8"))
        path.chmod(0o600)

    def _provision(self, **overrides: object) -> dict:
        values = {
            "manifest_sha256": self.manifest_sha,
            "phase_a_approval_digest": self.approval_digest,
            "policy_sha256": self.policy_sha,
            "decision": ANCHOR.DECISION,
        }
        values.update(overrides)
        with patch.object(ANCHOR.PHASE_A, "validate_artifacts", return_value={"policy": self.policy}):
            return ANCHOR.provision_anchor(self.manifest_path, self.anchor_path, **values)

    def _reject(self, **overrides: object) -> str:
        values = {
            "manifest_sha256": self.manifest_sha,
            "phase_a_approval_digest": self.approval_digest,
            "policy_sha256": self.policy_sha,
            "decision": ANCHOR.DECISION,
        }
        values.update(overrides)
        with patch.object(ANCHOR.PHASE_A, "validate_artifacts", return_value={"policy": self.policy}):
            with self.assertRaises(ANCHOR.Reject) as caught:
                ANCHOR.provision_anchor(self.manifest_path, self.anchor_path, **values)
        return str(caught.exception)

    def test_baseline_is_canonical_lf_0600_and_no_overwrite(self) -> None:
        result = self._provision()
        raw = self.anchor_path.read_bytes()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\\n"))
        self.assertEqual(stat.S_IMODE(self.anchor_path.stat().st_mode), 0o600)
        self.assertEqual(result["sha256"], hashlib.sha256(raw).hexdigest())
        original = raw
        message = self._reject()
        self.assertIn("already exists", message)
        self.assertEqual(self.anchor_path.read_bytes(), original)

    def test_checked_parent_rename_replacement_redirect_is_rejected_and_rolled_back(self) -> None:
        replacement = self.base / "replacement"
        replacement.mkdir(mode=0o700)
        moved = self.base / "checked-parent"
        original_target = self.anchor_path
        original_target_stat = ANCHOR._target_stat
        calls = 0

        def replace_after_parent_check(binding):
            nonlocal calls
            calls += 1
            if calls == 1:
                os.rename(self.parent, moved)
                os.rename(replacement, self.parent)
            return original_target_stat(binding)

        with patch.object(ANCHOR, "_target_stat", side_effect=replace_after_parent_check):
            message = self._reject()
        self.assertIn("parent", message)
        self.assertFalse((moved / original_target.name).exists())
        self.assertFalse((self.parent / original_target.name).exists())

    def test_checked_parent_symlink_substitution_is_rejected_and_rolled_back(self) -> None:
        replacement = self.base / "replacement"
        replacement.mkdir(mode=0o700)
        moved = self.base / "checked-parent"
        original_target_stat = ANCHOR._target_stat
        calls = 0

        def substitute_with_symlink(binding):
            nonlocal calls
            calls += 1
            if calls == 1:
                os.rename(self.parent, moved)
                os.symlink(replacement, self.parent)
            return original_target_stat(binding)

        with patch.object(ANCHOR, "_target_stat", side_effect=substitute_with_symlink):
            message = self._reject()
        self.assertIn("parent", message)
        self.assertFalse((moved / self.anchor_path.name).exists())
        self.assertFalse((replacement / self.anchor_path.name).exists())
        self.assertTrue(self.parent.is_symlink())

    def test_preexisting_foreign_target_is_not_overwritten(self) -> None:
        foreign = b"foreign target\n"
        self.anchor_path.write_bytes(foreign)
        self.anchor_path.chmod(0o600)
        before = self.anchor_path.stat()
        message = self._reject()
        self.assertIn("already exists", message)
        self.assertEqual(self.anchor_path.read_bytes(), foreign)
        after = self.anchor_path.stat()
        self.assertEqual((after.st_dev, after.st_ino), (before.st_dev, before.st_ino))

    def test_after_effect_write_failure_reconciles_exact_owned_inode(self) -> None:
        original_write = ANCHOR.os.write
        calls = 0

        def write_then_fail(fd: int, data: bytes) -> int:
            nonlocal calls
            calls += 1
            written = original_write(fd, data)
            if calls == 1:
                raise OSError("injected after-effect write failure")
            return written

        with patch.object(ANCHOR.os, "write", side_effect=write_then_fail):
            message = self._reject()
        self.assertIn("after-effect", message)
        self.assertFalse(self.anchor_path.exists())

    def test_parent_fsync_failure_rolls_back_anchor(self) -> None:
        original_fsync = ANCHOR.os.fsync
        failed = False

        def fail_first_parent_fsync(fd: int) -> None:
            nonlocal failed
            if not failed and stat.S_ISDIR(os.fstat(fd).st_mode):
                failed = True
                raise OSError("injected parent fsync failure")
            original_fsync(fd)

        with patch.object(ANCHOR.os, "fsync", side_effect=fail_first_parent_fsync):
            message = self._reject()
        self.assertTrue(failed)
        self.assertIn("parent fsync", message)
        self.assertFalse(self.anchor_path.exists())

    def test_cleanup_failure_reports_owned_residual_and_never_approves(self) -> None:
        original_fsync = ANCHOR.os.fsync
        original_unlink = ANCHOR.os.unlink
        unlink_failed = False

        def fail_parent_durability(fd: int) -> None:
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("injected rollback fsync failure")
            original_fsync(fd)

        def fail_owned_unlink(path: str, *, dir_fd: int = -1) -> None:
            nonlocal unlink_failed
            if path == self.anchor_path.name and dir_fd >= 0:
                unlink_failed = True
                raise OSError("injected owned unlink failure")
            original_unlink(path, dir_fd=dir_fd)

        with patch.object(ANCHOR.os, "fsync", side_effect=fail_parent_durability), patch.object(
            ANCHOR.os, "unlink", side_effect=fail_owned_unlink
        ):
            message = self._reject()
        self.assertTrue(unlink_failed)
        self.assertIn("residual", message)
        self.assertTrue(self.anchor_path.exists())
        self.assertEqual(self.anchor_path.read_bytes()[:1], b"{")

    def test_final_parent_mutation_is_rejected_and_owned_inode_is_removed(self) -> None:
        replacement = self.base / "replacement"
        replacement.mkdir(mode=0o700)
        moved = self.base / "final-parent"
        original_read = ANCHOR._read_anchor_descriptor
        calls = 0

        def mutate_before_final_read(binding, path, expected_raw, expected_sha256, label):
            nonlocal calls
            calls += 1
            if calls == 1:
                os.rename(self.parent, moved)
                os.rename(replacement, self.parent)
            return original_read(binding, path, expected_raw, expected_sha256, label)

        with patch.object(ANCHOR, "_read_anchor_descriptor", side_effect=mutate_before_final_read):
            message = self._reject()
        self.assertIn("parent", message)
        self.assertFalse((moved / self.anchor_path.name).exists())
        self.assertFalse((self.parent / self.anchor_path.name).exists())

    def test_final_target_replacement_preserves_foreign_entry(self) -> None:
        foreign = self.base / "foreign-target.json"
        foreign.write_bytes(b"foreign\n")
        foreign.chmod(0o600)
        moved = self.base / "owned-before-replacement.json"
        original_read = ANCHOR._read_anchor_descriptor
        calls = 0

        def replace_target_before_final_read(binding, path, expected_raw, expected_sha256, label):
            nonlocal calls
            calls += 1
            if calls == 1:
                os.rename(self.anchor_path, moved)
                os.rename(foreign, self.anchor_path)
            return original_read(binding, path, expected_raw, expected_sha256, label)

        with patch.object(ANCHOR, "_read_anchor_descriptor", side_effect=replace_target_before_final_read):
            message = self._reject()
        self.assertIn("foreign", message)
        self.assertEqual(self.anchor_path.read_bytes(), b"foreign\n")
        self.assertTrue(moved.exists())
        self.assertEqual(moved.read_bytes()[:1], b"{")


if __name__ == "__main__":
    unittest.main(verbosity=2)
