#!/usr/bin/env python3
"""Offline lifecycle checks for the proof-bound Phase A v6 successor."""
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
import forbidden_proof  # noqa: E402
import linux_phase_a_v6 as V6  # noqa: E402
import linux_replay_wrapper_v3 as WRAPPER  # noqa: E402
import linux_retained_driver_v3 as DRIVER  # noqa: E402


class LinuxPhaseAV6Tests(unittest.TestCase):
    @staticmethod
    def guarded(runner):
        identity = {"st_dev": 1, "st_ino": 2, "st_uid": os.getuid(), "st_gid": os.getgid(), "st_mode": 0o700, "st_size": 4096, "st_nlink": 2, "st_mtime_ns": 3, "st_ctime_ns": 4}
        binding = runner._binding_record(identity)
        return {"path": os.fspath(runner.REPOSITORY_ROOT), "binding": binding, "parent_binding": {**binding, "st_ino": 5}, "head": runner.FROZEN_COMMIT, "tree": runner.FROZEN_TREE, "detached": True, "source_repository": {"path": os.fspath(runner.SOURCE_REPOSITORY_ROOT), "binding": {**binding, "st_ino": 6}}, "git_common_dir": {"path": os.fspath(runner.GIT_COMMON_DIR), "binding": {**binding, "st_ino": 7}}, "git_object_dir": {"path": os.fspath(runner.GIT_OBJECT_DIR), "binding": {**binding, "st_ino": 8}}, "git_worktree_dir": {"path": os.fspath(runner.GIT_WORKTREE_DIR), "binding": {**binding, "st_ino": 9}}}

    def start_phase(self):
        developer = Path(DRIVER.platform_profile.load().source_repository).parent
        temporary = tempfile.TemporaryDirectory(prefix=".phase-a-v6-test-", dir=developer)
        self.addCleanup(temporary.cleanup)
        base = V6._load_v3()
        runner = base.load_runner()
        runner.EXTERNAL_ROOT = Path(temporary.name) / "external"
        modules = runner.load_modules()
        verifier = lambda: self.guarded(runner)
        phase = runner.phase_a(modules, repository_root=runner.REPOSITORY_ROOT,
                               external_root=runner.EXTERNAL_ROOT,
                               worktree_verifier=verifier)
        phase_snapshot = runner.stable_read(
            runner.EXTERNAL_ROOT / "evidence" / runner.PHASE_A_RECORD,
            "test phase",
        )
        return base, runner, modules, verifier, phase, phase_snapshot

    def lifecycle(self):
        base, runner, modules, verifier, phase, phase_snapshot = self.start_phase()
        anchor = runner.anchor(modules, repository_root=runner.REPOSITORY_ROOT,
                               external_root=runner.EXTERNAL_ROOT,
                               expected_phase_a_sha256=phase_snapshot.sha256,
                               worktree_verifier=verifier)
        anchor_snapshot = runner.stable_read(
            runner.EXTERNAL_ROOT / "evidence" / runner.ANCHOR_RECORD,
            "test anchor",
        )
        return base, runner, phase, phase_snapshot, anchor, anchor_snapshot

    def test_predecessors_and_successor_adapters_are_authenticated(self) -> None:
        self.assertEqual(hashlib.sha256(V6.V5_PATH.read_bytes()).hexdigest(), V6.V5_SHA256)
        self.assertEqual(hashlib.sha256(V6.V3_PATH.read_bytes()).hexdigest(), V6.V3_SHA256)
        self.assertEqual(hashlib.sha256(V6.linux_replay_wrapper_v3.DRIVER_PATH.read_bytes()).hexdigest(), V6.LINUX_DRIVER_ADAPTER_SHA256)
        self.assertEqual(hashlib.sha256(Path(V6.linux_replay_wrapper_v3.__file__).read_bytes()).hexdigest(), V6.LINUX_WRAPPER_ADAPTER_SHA256)
        runner = V6.load_runner()
        self.assertEqual(runner.SCHEMA, V6.V6_SCHEMA)
        self.assertEqual(runner.EVIDENCE_SCHEMA, V6.V6_EVIDENCE_SCHEMA)
        self.assertEqual(runner.EXTERNAL_ROOT.name, V6.V6_ROOT_NAME)
        self.assertFalse(runner.EXTERNAL_ROOT.exists())

    def test_preflight_classifies_all_five_missing_and_stays_disabled(self) -> None:
        result = WRAPPER.preflight()
        proof = DRIVER.forbidden_proof_record()
        missing = [row["oid"] for row in proof["forbidden"] if row["status"] == "missing-proved"]
        self.assertEqual(len(proof["forbidden"]), 22)
        self.assertEqual(len(missing), 5)
        self.assertEqual(result["forbidden_proof_sha256"], forbidden_proof.record_sha256(proof))
        self.assertEqual(result["derived_stdin_sha256"], WRAPPER.DERIVED_STDIN_SHA256)
        self.assertTrue(result["phase_a_v6_required"])
        self.assertFalse(result["execution_enabled"])
        wrapper, _authority = WRAPPER.load_wrapper()
        with self.assertRaisesRegex(RuntimeError, "Phase A v3 authority"):
            wrapper.execute_and_publish(None, "0" * 64)

    def test_disposable_phase_anchor_binds_proof_and_enables_boundary(self) -> None:
        base, runner, phase, phase_snapshot, anchor, anchor_snapshot = self.lifecycle()
        self.assertEqual(phase["schema"], V6.V6_EVIDENCE_SCHEMA)
        self.assertEqual(anchor["prior_sha256"], phase_snapshot.sha256)
        owner = json.loads((runner.EXTERNAL_ROOT / "phase-a" / ".owner").read_text())
        profile = owner["platform_profile"]
        self.assertEqual(profile["phase_a_adapter_sha256"], V6._adapter_sha256())
        self.assertEqual(profile["forbidden_proof_sha256"], forbidden_proof.record_sha256(profile["forbidden_proof"]))
        self.assertEqual(len(profile["forbidden_proof"]["forbidden"]), 22)
        base.load_runner = lambda: runner
        with mock.patch.object(V6, "_load_v3", return_value=base):
            wrapper, authority = V6.load_approved_wrapper(anchor_snapshot.sha256, V6._adapter_sha256())
        self.assertIs(wrapper.execute_and_publish, wrapper._phase_a_v3_predecessor_execute_and_publish)
        self.assertEqual(authority.derived_stdin_sha256, WRAPPER.DERIVED_STDIN_SHA256)

    def test_classification_change_rejects_anchor(self) -> None:
        _base, runner, modules, verifier, _phase, phase_snapshot = self.start_phase()
        original = DRIVER.forbidden_proof_record()
        changed = json.loads(json.dumps(original))
        changed["forbidden"][0]["status"] = "missing-proved"
        with mock.patch.object(DRIVER, "forbidden_proof_record", return_value=changed):
            with self.assertRaises(runner.Reject):
                runner.anchor(modules, repository_root=runner.REPOSITORY_ROOT,
                              external_root=runner.EXTERNAL_ROOT,
                              expected_phase_a_sha256=phase_snapshot.sha256,
                              worktree_verifier=verifier)

    def test_wrong_anchor_does_not_create_v6_evidence(self) -> None:
        root = Path(DRIVER.platform_profile.load().source_repository).parent / V6.V6_ROOT_NAME
        self.assertFalse(root.exists())
        with self.assertRaises((RuntimeError, FileNotFoundError)):
            V6.load_approved_wrapper("0" * 64, V6._adapter_sha256())
        self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
