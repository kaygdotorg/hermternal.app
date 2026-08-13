#!/usr/bin/env python3
"""Offline regression tests for the profile-aware Phase A v3 adapter."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.fspath(HERE))
import linux_phase_a_v3 as V3  # noqa: E402

DEVELOPER_ROOT = Path(V3.platform_profile.load().source_repository).parent


class LinuxPhaseAV3Tests(unittest.TestCase):
    """Exercise genuine v2 lifecycle code with disposable v3 bindings."""

    @staticmethod
    def guarded(runner):
        identity = {"st_dev": 1, "st_ino": 2, "st_uid": os.getuid(), "st_gid": os.getgid(), "st_mode": 0o700, "st_size": 4096, "st_nlink": 2, "st_mtime_ns": 3, "st_ctime_ns": 4}
        binding = runner._binding_record(identity)
        return {"path": os.fspath(runner.REPOSITORY_ROOT), "binding": binding, "parent_binding": {**binding, "st_ino": 5}, "head": runner.FROZEN_COMMIT, "tree": runner.FROZEN_TREE, "detached": True, "source_repository": {"path": os.fspath(runner.SOURCE_REPOSITORY_ROOT), "binding": {**binding, "st_ino": 6}}, "git_common_dir": {"path": os.fspath(runner.GIT_COMMON_DIR), "binding": {**binding, "st_ino": 7}}, "git_object_dir": {"path": os.fspath(runner.GIT_OBJECT_DIR), "binding": {**binding, "st_ino": 8}}, "git_worktree_dir": {"path": os.fspath(runner.GIT_WORKTREE_DIR), "binding": {**binding, "st_ino": 9}}}

    def lifecycle(self):
        temporary = tempfile.TemporaryDirectory(prefix=".phase-a-v3-test-", dir=DEVELOPER_ROOT)
        self.addCleanup(temporary.cleanup)
        runner = V3.load_runner()
        runner.EXTERNAL_ROOT = Path(temporary.name) / "external"
        modules = runner.load_modules()
        verifier = lambda: self.guarded(runner)
        phase = runner.phase_a(modules, repository_root=runner.REPOSITORY_ROOT, external_root=runner.EXTERNAL_ROOT, worktree_verifier=verifier)
        phase_snapshot = runner.stable_read(runner.EXTERNAL_ROOT / "evidence" / runner.PHASE_A_RECORD, "test phase")
        anchor = runner.anchor(modules, repository_root=runner.REPOSITORY_ROOT, external_root=runner.EXTERNAL_ROOT, expected_phase_a_sha256=phase_snapshot.sha256, worktree_verifier=verifier)
        anchor_snapshot = runner.stable_read(runner.EXTERNAL_ROOT / "evidence" / runner.ANCHOR_RECORD, "test anchor")
        return runner, phase, phase_snapshot, anchor, anchor_snapshot

    def test_exact_reviewed_loader_and_platform_pins(self):
        runner = V3.load_runner()
        self.assertEqual(hashlib.sha256(V3.V2_RUNNER_PATH.read_bytes()).hexdigest(), V3.V2_RUNNER_SHA256)
        self.assertEqual(runner.SCHEMA, V3.V3_SCHEMA)
        self.assertEqual(runner.EVIDENCE_SCHEMA, V3.V3_EVIDENCE_SCHEMA)
        self.assertEqual(runner.FINAL_PINS, V3.FINAL_PINS)
        self.assertEqual(runner.EXTERNAL_ROOT, DEVELOPER_ROOT / V3.V3_ROOT_NAME)
        self.assertEqual(runner.REPOSITORY_ROOT, Path(V3.platform_profile.load().source_repository))
        modules = runner.load_modules()
        self.assertTrue(modules.phase_a.validate_artifacts.__code__.co_filename.endswith("task409_execution_preflight_v3.py"))
        self.assertIs(modules.lifecycle.PHASE_B.REVIEW, modules.git_reviewer)

    def test_loader_rejects_replaced_source_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            replacement = Path(temporary) / "runner.py"
            replacement.write_bytes(V3.V2_RUNNER_PATH.read_bytes() + b"\n")
            with mock.patch.object(V3, "V2_RUNNER_PATH", replacement):
                with self.assertRaisesRegex(RuntimeError, "SHA-256 differs"):
                    V3.load_runner()

    def test_disposable_genuine_phase_to_anchor_lifecycle(self):
        runner, phase, phase_snapshot, anchor, _ = self.lifecycle()
        self.assertEqual(phase["schema"], V3.V3_EVIDENCE_SCHEMA)
        self.assertEqual(phase["prior_sha256"], "0" * 64)
        self.assertEqual(phase["observations"]["phase_a_validator_calls"], 1)
        self.assertEqual(anchor["prior_sha256"], phase_snapshot.sha256)
        self.assertEqual(anchor["inputs"]["expected_phase_a_sha256"], phase_snapshot.sha256)
        self.assertEqual(anchor["observations"]["anchor_provisioner_calls"], 1)
        self.assertEqual(anchor["observations"]["anchor_genuine_phase_a_validator_calls"], 1)
        self.assertEqual(set(phase["observations"]["authority_files"]), set(V3.FINAL_PINS))
        for name, record in phase["observations"]["authority_files"].items():
            self.assertEqual(record["sha256"], V3.FINAL_PINS[name])
            self.assertEqual(set(record["identity"]), {"st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_size", "st_nlink", "st_mtime_ns", "st_ctime_ns"})
        owner = json.loads((runner.EXTERNAL_ROOT / "phase-a" / ".owner").read_text())["platform_profile"]
        self.assertEqual(owner, V3._profile_record(V3.platform_profile.load()))

    def test_wrong_reviewed_digest_cannot_start_anchor(self):
        temporary = tempfile.TemporaryDirectory(prefix=".phase-a-v3-test-", dir=DEVELOPER_ROOT)
        self.addCleanup(temporary.cleanup)
        runner = V3.load_runner()
        runner.EXTERNAL_ROOT = Path(temporary.name) / "external"
        modules = runner.load_modules()
        verifier = lambda: self.guarded(runner)
        runner.phase_a(modules, repository_root=runner.REPOSITORY_ROOT, external_root=runner.EXTERNAL_ROOT, worktree_verifier=verifier)
        with self.assertRaisesRegex(runner.Reject, "reviewed handoff"):
            runner.anchor(modules, repository_root=runner.REPOSITORY_ROOT, external_root=runner.EXTERNAL_ROOT, expected_phase_a_sha256="0" * 64, worktree_verifier=verifier)
        self.assertFalse((runner.EXTERNAL_ROOT / "external-review" / runner.ANCHOR_NAME).exists())

    def test_profile_owner_and_file_modes_are_immutable(self):
        runner, _, _, _, _ = self.lifecycle()
        files = [runner.EXTERNAL_ROOT / "phase-a" / ".owner", runner.EXTERNAL_ROOT / "phase-a" / "input-manifest.json", runner.EXTERNAL_ROOT / "evidence" / runner.PHASE_A_RECORD, runner.EXTERNAL_ROOT / "external-review" / runner.ANCHOR_NAME, runner.EXTERNAL_ROOT / "evidence" / runner.ANCHOR_RECORD]
        for path in files:
            info = os.lstat(path)
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            self.assertEqual(info.st_nlink, 1)
            self.assertTrue(path.read_bytes().endswith(b"\n"))
        for path in [runner.EXTERNAL_ROOT, runner.EXTERNAL_ROOT / "phase-a", runner.EXTERNAL_ROOT / "external-review", runner.EXTERNAL_ROOT / "evidence"]:
            self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), 0o700)

    def test_old_and_unapproved_roots_are_rejected_without_change(self):
        runner = V3.load_runner()
        modules = runner.load_modules()
        for root in (runner.V1_EXTERNAL_ROOT, DEVELOPER_ROOT / "hermternal-issue397-phase-a-anchor-v2", Path("relative-v3")):
            before = os.path.lexists(root)
            with self.assertRaises(runner.Reject):
                runner.phase_a(modules, repository_root=runner.REPOSITORY_ROOT, external_root=root, worktree_verifier=lambda: self.guarded(runner))
            self.assertEqual(os.path.lexists(root), before)

    def test_approved_anchor_only_enables_boundary_without_running_it(self):
        runner, _, _, _, anchor_snapshot = self.lifecycle()
        with mock.patch.object(V3, "load_runner", return_value=runner):
            wrapper, authority = V3.load_approved_wrapper(anchor_snapshot.sha256, V3._adapter_sha256())
        self.assertIs(wrapper.execute_and_publish, wrapper._phase_a_v3_predecessor_execute_and_publish)
        self.assertEqual(wrapper.PHASE_A_RUNNER_SHA256, V3._adapter_sha256())
        self.assertEqual(authority.derived_stdin_sha256, V3.linux_replay_wrapper.DERIVED_STDIN_SHA256)

    def test_durable_commands_and_replay_are_not_run(self):
        self.assertFalse((DEVELOPER_ROOT / V3.V3_ROOT_NAME).exists())
        with self.assertRaises((RuntimeError, FileNotFoundError)):
            V3.load_approved_wrapper("0" * 64, V3._adapter_sha256())


if __name__ == "__main__":
    unittest.main(verbosity=2)
