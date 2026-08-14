#!/usr/bin/env python3
"""Exercise the v9 disposable enable path and its single constant guard."""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.fspath(HERE))
import linux_phase_a_v9 as V9  # noqa: E402
import linux_replay_wrapper_v5 as WRAPPER  # noqa: E402
import linux_retained_driver_v5 as DRIVER  # noqa: E402


class PhaseAV9Tests(unittest.TestCase):
    @staticmethod
    def guarded(runner):
        identity = {"st_dev": 1, "st_ino": 2, "st_uid": os.getuid(), "st_gid": os.getgid(), "st_mode": 0o700, "st_size": 4096, "st_nlink": 2, "st_mtime_ns": 3, "st_ctime_ns": 4}
        binding = runner._binding_record(identity)
        return {"path": str(runner.REPOSITORY_ROOT), "binding": binding, "parent_binding": {**binding, "st_ino": 5}, "head": runner.FROZEN_COMMIT, "tree": runner.FROZEN_TREE, "detached": True, "source_repository": {"path": str(runner.SOURCE_REPOSITORY_ROOT), "binding": {**binding, "st_ino": 6}}, "git_common_dir": {"path": str(runner.GIT_COMMON_DIR), "binding": {**binding, "st_ino": 7}}, "git_object_dir": {"path": str(runner.GIT_OBJECT_DIR), "binding": {**binding, "st_ino": 8}}, "git_worktree_dir": {"path": str(runner.GIT_WORKTREE_DIR), "binding": {**binding, "st_ino": 9}}}

    def test_disposable_phase_anchor_enables_frozen_v5_boundary(self):
        self.assertEqual(hashlib.sha256(V9._stable_bytes(V9.V8_PATH, V9.V8_SHA256, "v8")).hexdigest(), V9.V8_SHA256)
        self.assertEqual(hashlib.sha256(V9._stable_bytes(V9.WRAPPER_V5_PATH, V9.LINUX_WRAPPER_ADAPTER_SHA256, "wrapper")).hexdigest(), V9.LINUX_WRAPPER_ADAPTER_SHA256)
        self.assertEqual(hashlib.sha256(V9._stable_bytes(V9.DRIVER_V5_PATH, V9.LINUX_DRIVER_ADAPTER_SHA256, "driver")).hexdigest(), V9.LINUX_DRIVER_ADAPTER_SHA256)
        self.assertEqual(WRAPPER.DERIVED_STDIN_SHA256, "df9a71fafdf1263e032644180b5211c4dd70771c624461e2e6a3a2b1e89d911c")
        self.assertEqual(DRIVER.HASHES["parent-binding-adaptation-manifest.json"], "43e2b9fa72214d730fe83cdeebb2cab977c50d43ad9b52e1432028028ffb735f")
        self.assertFalse(WRAPPER.preflight()["execution_enabled"])
        base = V9._load_v8()
        runner = base.load_runner()
        with tempfile.TemporaryDirectory(prefix=".phase-a-v9-test-", dir=Path(runner.REPOSITORY_ROOT).parent) as parent:
            runner.EXTERNAL_ROOT = Path(parent) / "external"
            modules = runner.load_modules()
            verifier = lambda: self.guarded(runner)
            phase = runner.phase_a(modules, repository_root=runner.REPOSITORY_ROOT, external_root=runner.EXTERNAL_ROOT, worktree_verifier=verifier)
            phase_snapshot = runner.stable_read(runner.EXTERNAL_ROOT / "evidence" / runner.PHASE_A_RECORD, "phase")
            anchor = runner.anchor(modules, repository_root=runner.REPOSITORY_ROOT, external_root=runner.EXTERNAL_ROOT, expected_phase_a_sha256=phase_snapshot.sha256, worktree_verifier=verifier)
            anchor_snapshot = runner.stable_read(runner.EXTERNAL_ROOT / "evidence" / runner.ANCHOR_RECORD, "anchor")
            v7 = base._load_v7()
            v3 = v7._load_v3()
            v3.load_runner = lambda: runner
            v7._load_v3 = lambda: v3
            base._load_v7 = lambda: v7
            with mock.patch.object(V9, "_load_v8", return_value=base):
                wrapper, authority = V9.load_approved_wrapper(anchor_snapshot.sha256, V9._adapter_sha256())
        self.assertEqual(phase["schema"], V9.V9_EVIDENCE_SCHEMA)
        self.assertEqual(anchor["prior_sha256"], phase_snapshot.sha256)
        self.assertIs(wrapper.execute_and_publish, wrapper._phase_a_v3_predecessor_execute_and_publish)
        self.assertEqual(wrapper.PHASE_A_RUNNER_PATH, Path(V9.__file__))
        self.assertEqual(authority.derived_stdin_sha256, WRAPPER.DERIVED_STDIN_SHA256)

    def test_count_target_and_path_swaps_fail_closed(self):
        function = V9._load_v8()._load_v7()._load_v3().load_approved_wrapper
        missing = tuple(value for value in function.__code__.co_consts if value != V9.DISABLED_V3)
        with self.assertRaisesRegex(RuntimeError, "count"):
            V9._replace_v3_boundary(types.FunctionType(function.__code__.replace(co_consts=missing), function.__globals__, function.__name__, function.__defaults__, function.__closure__))
        wrong_target = tuple(
            b"wrong preserved target" if value == V9.PRESERVED_METHOD else
            V9.DISABLED_V3 if value == V9.DISABLED_V8 else value
            for value in function.__code__.co_consts
        )
        with self.assertRaisesRegex(RuntimeError, "target"):
            V9._replace_v3_boundary(types.FunctionType(function.__code__.replace(co_consts=wrong_target), function.__globals__, function.__name__, function.__defaults__, function.__closure__))
        with mock.patch.object(V9, "V8_PATH", HERE / "swapped-v8.py"):
            with self.assertRaisesRegex(RuntimeError, "path"):
                V9._load_v8()

    def test_fd_reader_rejects_symlink_and_after_read_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trusted = root / "trusted.py"; trusted.write_bytes(b"marker = 'trusted'\n")
            replacement = root / "replacement.py"; replacement.write_bytes(b"raise RuntimeError('replacement executed')\n")
            digest = hashlib.sha256(trusted.read_bytes()).hexdigest()
            link = root / "linked.py"; link.symlink_to(trusted)
            with self.assertRaises(OSError):
                V9._stable_bytes(link, digest, "symlink")
            def swap():
                os.replace(replacement, trusted)
            with self.assertRaisesRegex(RuntimeError, "changed during read"):
                V9._stable_bytes(trusted, digest, "replacement", after_read=swap)
            self.assertIn(b"replacement executed", trusted.read_bytes())


if __name__ == "__main__":
    unittest.main(verbosity=2)
