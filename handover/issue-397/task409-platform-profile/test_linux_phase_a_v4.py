#!/usr/bin/env python3
"""Offline regression tests for the corrected Phase A v4 authority."""
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
import linux_phase_a_v4 as V4  # noqa: E402

DEVELOPER_ROOT = Path(V4.platform_profile.load().source_repository).parent


class LinuxPhaseAV4Tests(unittest.TestCase):
    """Exercise the genuine v3 lifecycle with disposable v4 bindings."""

    @staticmethod
    def guarded(runner):
        identity = {"st_dev": 1, "st_ino": 2, "st_uid": os.getuid(), "st_gid": os.getgid(), "st_mode": 0o700, "st_size": 4096, "st_nlink": 2, "st_mtime_ns": 3, "st_ctime_ns": 4}
        binding = runner._binding_record(identity)
        return {"path": os.fspath(runner.REPOSITORY_ROOT), "binding": binding, "parent_binding": {**binding, "st_ino": 5}, "head": runner.FROZEN_COMMIT, "tree": runner.FROZEN_TREE, "detached": True, "source_repository": {"path": os.fspath(runner.SOURCE_REPOSITORY_ROOT), "binding": {**binding, "st_ino": 6}}, "git_common_dir": {"path": os.fspath(runner.GIT_COMMON_DIR), "binding": {**binding, "st_ino": 7}}, "git_object_dir": {"path": os.fspath(runner.GIT_OBJECT_DIR), "binding": {**binding, "st_ino": 8}}, "git_worktree_dir": {"path": os.fspath(runner.GIT_WORKTREE_DIR), "binding": {**binding, "st_ino": 9}}}

    def lifecycle(self):
        temporary = tempfile.TemporaryDirectory(prefix=".phase-a-v4-test-", dir=DEVELOPER_ROOT)
        self.addCleanup(temporary.cleanup)
        base = V4._load_v3()
        runner = base.load_runner()
        runner.EXTERNAL_ROOT = Path(temporary.name) / "external"
        modules = runner.load_modules()
        verifier = lambda: self.guarded(runner)
        phase = runner.phase_a(modules, repository_root=runner.REPOSITORY_ROOT, external_root=runner.EXTERNAL_ROOT, worktree_verifier=verifier)
        phase_snapshot = runner.stable_read(runner.EXTERNAL_ROOT / "evidence" / runner.PHASE_A_RECORD, "test phase")
        anchor = runner.anchor(modules, repository_root=runner.REPOSITORY_ROOT, external_root=runner.EXTERNAL_ROOT, expected_phase_a_sha256=phase_snapshot.sha256, worktree_verifier=verifier)
        anchor_snapshot = runner.stable_read(runner.EXTERNAL_ROOT / "evidence" / runner.ANCHOR_RECORD, "test anchor")
        return base, runner, phase, phase_snapshot, anchor, anchor_snapshot

    def test_exact_v3_loader_and_v4_pins(self):
        self.assertEqual(hashlib.sha256(V4.V3_PATH.read_bytes()).hexdigest(), V4.V3_SHA256)
        base = V4._load_v3()
        runner = base.load_runner()
        self.assertEqual(runner.SCHEMA, V4.V4_SCHEMA)
        self.assertEqual(runner.EVIDENCE_SCHEMA, V4.V4_EVIDENCE_SCHEMA)
        self.assertEqual(runner.EXTERNAL_ROOT, DEVELOPER_ROOT / V4.V4_ROOT_NAME)
        self.assertEqual(base.LINUX_WRAPPER_ADAPTER_SHA256, V4.LINUX_WRAPPER_ADAPTER_SHA256)
        self.assertEqual(base.LINUX_DRIVER_ADAPTER_SHA256, V4.LINUX_DRIVER_ADAPTER_SHA256)

    def test_disposable_genuine_phase_to_anchor_lifecycle(self):
        _base, runner, phase, phase_snapshot, anchor, _anchor_snapshot = self.lifecycle()
        self.assertEqual(phase["schema"], V4.V4_EVIDENCE_SCHEMA)
        self.assertEqual(phase["observations"]["phase_a_validator_calls"], 1)
        self.assertEqual(anchor["prior_sha256"], phase_snapshot.sha256)
        self.assertEqual(anchor["observations"]["anchor_genuine_phase_a_validator_calls"], 1)
        owner = json.loads((runner.EXTERNAL_ROOT / "phase-a" / ".owner").read_text())["platform_profile"]
        self.assertEqual(owner["phase_a_adapter_sha256"], V4._adapter_sha256())
        self.assertEqual(owner["linux_wrapper_adapter_sha256"], V4.LINUX_WRAPPER_ADAPTER_SHA256)
        self.assertEqual(owner["linux_driver_adapter_sha256"], V4.LINUX_DRIVER_ADAPTER_SHA256)

    def test_disposable_anchor_enables_corrected_boundary_without_replay(self):
        base, runner, _phase, _phase_snapshot, _anchor, anchor_snapshot = self.lifecycle()
        base.load_runner = lambda: runner
        with mock.patch.object(V4, "_load_v3", return_value=base):
            wrapper, authority = V4.load_approved_wrapper(anchor_snapshot.sha256, V4._adapter_sha256())
        self.assertIs(wrapper.execute_and_publish, wrapper._phase_a_v3_predecessor_execute_and_publish)
        self.assertEqual(authority.derived_stdin_sha256, "ff28ec082218888503555d1a346e10f1a351e66181c932fc8a337bdea3c74496")

    def test_wrong_digest_does_not_change_durable_v4_root(self):
        durable = DEVELOPER_ROOT / V4.V4_ROOT_NAME
        before = {
            path.relative_to(durable): (stat.S_IMODE(path.lstat().st_mode), path.read_bytes() if path.is_file() else None)
            for path in ([durable] if durable.exists() else []) + (list(durable.rglob("*")) if durable.exists() else [])
        }
        with self.assertRaises((RuntimeError, FileNotFoundError)):
            V4.load_approved_wrapper("0" * 64, V4._adapter_sha256())
        after = {
            path.relative_to(durable): (stat.S_IMODE(path.lstat().st_mode), path.read_bytes() if path.is_file() else None)
            for path in ([durable] if durable.exists() else []) + (list(durable.rglob("*")) if durable.exists() else [])
        }
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
