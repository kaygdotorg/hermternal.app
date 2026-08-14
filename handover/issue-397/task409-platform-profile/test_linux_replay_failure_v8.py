#!/usr/bin/env python3
"""Exercise the actual outer failure chain with the authenticated v9 adapter."""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.fspath(HERE))
import linux_phase_a_v9 as V9  # noqa: E402
import linux_replay_failure_v8 as V8  # noqa: E402
import linux_retained_driver_v5 as DRIVER  # noqa: E402


class FailureV8Tests(unittest.TestCase):
    @staticmethod
    def guarded(runner):
        identity = {"st_dev": 1, "st_ino": 2, "st_uid": os.getuid(), "st_gid": os.getgid(), "st_mode": 0o700, "st_size": 4096, "st_nlink": 2, "st_mtime_ns": 3, "st_ctime_ns": 4}
        binding = runner._binding_record(identity)
        return {"path": str(runner.REPOSITORY_ROOT), "binding": binding, "parent_binding": {**binding, "st_ino": 5}, "head": runner.FROZEN_COMMIT, "tree": runner.FROZEN_TREE, "detached": True, "source_repository": {"path": str(runner.SOURCE_REPOSITORY_ROOT), "binding": {**binding, "st_ino": 6}}, "git_common_dir": {"path": str(runner.GIT_COMMON_DIR), "binding": {**binding, "st_ino": 7}}, "git_object_dir": {"path": str(runner.GIT_OBJECT_DIR), "binding": {**binding, "st_ino": 8}}, "git_worktree_dir": {"path": str(runner.GIT_WORKTREE_DIR), "binding": {**binding, "st_ino": 9}}}

    def test_fresh_failure_v1_receives_v9_adapter(self):
        top = V8._load_v7()._load_v6()
        self.assertEqual(top.SCHEMA, V8.SCHEMA)
        self.assertEqual(top.DIRECTORY_NAME, V8.DIRECTORY_NAME)
        v1 = top._load_v5()._load_v4()._load_v3()._load_v2()._load_v1()
        self.assertEqual(v1.PHASE_A_ADAPTER_SHA256, V8.PHASE_A_V9_SHA256)
        adapter = v1.load_phase_a_adapter()
        self.assertEqual(adapter._adapter_sha256(), V8.PHASE_A_V9_SHA256)
        root = Path(DRIVER.AUTHORITY_ROOT).parent / V8.DIRECTORY_NAME
        self.assertFalse(root.exists())
        with self.assertRaises((RuntimeError, FileNotFoundError)):
            V8.load_approved_wrapper("0" * 64)
        self.assertFalse(root.exists())

    def test_disposable_phase_anchor_enables_actual_outer_chain(self):
        base = V9._load_v8()
        runner = base.load_runner()
        with tempfile.TemporaryDirectory(prefix=".failure-v8-test-", dir=Path(runner.REPOSITORY_ROOT).parent) as parent:
            runner.EXTERNAL_ROOT = Path(parent) / "external"
            modules = runner.load_modules()
            verifier = lambda: self.guarded(runner)
            runner.phase_a(modules, repository_root=runner.REPOSITORY_ROOT, external_root=runner.EXTERNAL_ROOT, worktree_verifier=verifier)
            phase = runner.stable_read(runner.EXTERNAL_ROOT / "evidence" / runner.PHASE_A_RECORD, "phase")
            runner.anchor(modules, repository_root=runner.REPOSITORY_ROOT, external_root=runner.EXTERNAL_ROOT, expected_phase_a_sha256=phase.sha256, worktree_verifier=verifier)
            anchor = runner.stable_read(runner.EXTERNAL_ROOT / "evidence" / runner.ANCHOR_RECORD, "anchor")
            v7 = base._load_v7()
            v3 = v7._load_v3()
            v3.load_runner = lambda: runner
            v7._load_v3 = lambda: v3
            base._load_v7 = lambda: v7
            with mock.patch.object(V9, "_load_v8", return_value=base), mock.patch.object(V8, "_load_v9", return_value=V9):
                wrapper, authority = V8.load_approved_wrapper(anchor.sha256)
        # The outer failure successor must wrap the restored replay method.
        # Successful loading proves that the disabled boundary was removed;
        # distinct identities prove that failure retention remains installed.
        self.assertIsNot(wrapper.execute_and_publish, wrapper._phase_a_v3_predecessor_execute_and_publish)
        self.assertTrue(callable(wrapper._phase_a_v3_predecessor_execute_and_publish))
        self.assertEqual(authority.derived_stdin_sha256, "df9a71fafdf1263e032644180b5211c4dd70771c624461e2e6a3a2b1e89d911c")

    def test_verified_sources_reject_symlink_and_after_read_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trusted = root / "trusted.py"; trusted.write_bytes(b"marker = 'trusted'\n")
            replacement = root / "replacement.py"; replacement.write_bytes(b"raise RuntimeError('replacement executed')\n")
            digest = hashlib.sha256(trusted.read_bytes()).hexdigest()
            link = root / "link.py"; link.symlink_to(trusted)
            with self.assertRaises(OSError):
                V8._stable_bytes(link, digest, "symlink")
            with self.assertRaisesRegex(RuntimeError, "changed during read"):
                V8._stable_bytes(trusted, digest, "replacement", after_read=lambda: os.replace(replacement, trusted))
            self.assertIn(b"replacement executed", trusted.read_bytes())


if __name__ == "__main__":
    unittest.main(verbosity=2)
