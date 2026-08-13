#!/usr/bin/env python3
"""Offline checks for Phase A v5 and its corrected authority hashes."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.fspath(HERE))
import linux_phase_a_v5 as V5  # noqa: E402
import linux_replay_wrapper_v2 as WRAPPER  # noqa: E402


class LinuxPhaseAV5Tests(unittest.TestCase):
    @staticmethod
    def guarded(runner):
        identity = {"st_dev": 1, "st_ino": 2, "st_uid": os.getuid(), "st_gid": os.getgid(), "st_mode": 0o700, "st_size": 4096, "st_nlink": 2, "st_mtime_ns": 3, "st_ctime_ns": 4}
        binding = runner._binding_record(identity)
        return {"path": os.fspath(runner.REPOSITORY_ROOT), "binding": binding, "parent_binding": {**binding, "st_ino": 5}, "head": runner.FROZEN_COMMIT, "tree": runner.FROZEN_TREE, "detached": True, "source_repository": {"path": os.fspath(runner.SOURCE_REPOSITORY_ROOT), "binding": {**binding, "st_ino": 6}}, "git_common_dir": {"path": os.fspath(runner.GIT_COMMON_DIR), "binding": {**binding, "st_ino": 7}}, "git_object_dir": {"path": os.fspath(runner.GIT_OBJECT_DIR), "binding": {**binding, "st_ino": 8}}, "git_worktree_dir": {"path": os.fspath(runner.GIT_WORKTREE_DIR), "binding": {**binding, "st_ino": 9}}}

    def lifecycle(self):
        developer = Path(V5.platform_profile.load().source_repository).parent
        temporary = tempfile.TemporaryDirectory(prefix=".phase-a-v5-test-", dir=developer)
        self.addCleanup(temporary.cleanup)
        base = V5._load_v3()
        runner = base.load_runner()
        runner.EXTERNAL_ROOT = Path(temporary.name) / "external"
        modules = runner.load_modules()
        verifier = lambda: self.guarded(runner)
        phase = runner.phase_a(modules, repository_root=runner.REPOSITORY_ROOT, external_root=runner.EXTERNAL_ROOT, worktree_verifier=verifier)
        phase_snapshot = runner.stable_read(runner.EXTERNAL_ROOT / "evidence" / runner.PHASE_A_RECORD, "test phase")
        anchor = runner.anchor(modules, repository_root=runner.REPOSITORY_ROOT, external_root=runner.EXTERNAL_ROOT, expected_phase_a_sha256=phase_snapshot.sha256, worktree_verifier=verifier)
        anchor_snapshot = runner.stable_read(runner.EXTERNAL_ROOT / "evidence" / runner.ANCHOR_RECORD, "test anchor")
        return base, runner, phase, phase_snapshot, anchor, anchor_snapshot

    def test_v4_is_authenticated_and_v5_is_new_authority(self) -> None:
        self.assertEqual(hashlib.sha256(V5.V4_PATH.read_bytes()).hexdigest(), V5.V4_SHA256)
        runner = V5.load_runner()
        self.assertEqual(runner.SCHEMA, V5.V5_SCHEMA)
        self.assertEqual(runner.EVIDENCE_SCHEMA, V5.V5_EVIDENCE_SCHEMA)
        self.assertEqual(runner.EXTERNAL_ROOT.name, V5.V5_ROOT_NAME)
        self.assertFalse(runner.EXTERNAL_ROOT.exists())

    def test_wrapper_preflight_binds_new_driver_and_stays_disabled(self) -> None:
        result = WRAPPER.preflight()
        self.assertEqual(result["derived_stdin_sha256"], WRAPPER.DERIVED_STDIN_SHA256)
        self.assertEqual(result["driver_adapter_sha256"], V5.LINUX_DRIVER_ADAPTER_SHA256)
        self.assertTrue(result["phase_a_v5_required"])
        self.assertFalse(result["execution_enabled"])
        wrapper, _authority = WRAPPER.load_wrapper()
        with self.assertRaisesRegex(RuntimeError, "Phase A v3 authority"):
            wrapper.execute_and_publish(None, "0" * 64)

    def test_disposable_phase_anchor_enables_exact_corrected_boundary(self) -> None:
        base, runner, phase, phase_snapshot, anchor, anchor_snapshot = self.lifecycle()
        self.assertEqual(phase["schema"], V5.V5_EVIDENCE_SCHEMA)
        self.assertEqual(anchor["prior_sha256"], phase_snapshot.sha256)
        owner = json.loads((runner.EXTERNAL_ROOT / "phase-a" / ".owner").read_text())
        self.assertEqual(owner["platform_profile"]["phase_a_adapter_sha256"], V5._adapter_sha256())
        base.load_runner = lambda: runner
        with mock.patch.object(V5, "_load_v3", return_value=base):
            wrapper, authority = V5.load_approved_wrapper(anchor_snapshot.sha256, V5._adapter_sha256())
        self.assertIs(wrapper.execute_and_publish, wrapper._phase_a_v3_predecessor_execute_and_publish)
        self.assertEqual(authority.derived_stdin_sha256, WRAPPER.DERIVED_STDIN_SHA256)

    def test_wrong_anchor_does_not_create_v5_evidence(self) -> None:
        root = Path(V5.platform_profile.load().source_repository).parent / V5.V5_ROOT_NAME
        self.assertFalse(root.exists())
        with self.assertRaises((RuntimeError, FileNotFoundError)):
            V5.load_approved_wrapper("0" * 64, V5._adapter_sha256())
        self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
