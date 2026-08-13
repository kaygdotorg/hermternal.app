#!/usr/bin/env python3
"""Simulated-process tests for durable Linux replay failure evidence."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.fspath(HERE))
import linux_replay_failure_v1 as FAILURE  # noqa: E402
import linux_replay_wrapper  # noqa: E402


class ReplayFailureTests(unittest.TestCase):
    """Never start a subprocess; supply exact ProcessResult values directly."""

    def boundary(self):
        wrapper, authority = linux_replay_wrapper.load_wrapper()
        adapter = types.SimpleNamespace(FINAL_PINS={"authority-descriptor.json": "a" * 64})
        profile = FAILURE.platform_profile.load()
        temporary = tempfile.TemporaryDirectory(prefix=".failure-record-test-", dir=profile.temporary_parent)
        self.addCleanup(temporary.cleanup)
        wrapper.RUN_PARENT = Path(temporary.name)

        def predecessor(_phase, _sha, *, process_boundary):
            result = process_boundary(authority.argv, authority.stdin, {})
            return wrapper.validate_process(result, authority)

        wrapper.execute_and_publish = predecessor
        FAILURE._install(wrapper, authority, adapter, profile, "c" * 64)
        pid = 19171
        root = wrapper._run_root(pid) / "replay-root"
        root.mkdir(parents=True, mode=0o700)
        os.chmod(root.parent, 0o700)
        os.chmod(root, 0o700)
        return wrapper, authority, pid, root

    def test_rc1_retains_actual_stderr_without_completion(self):
        wrapper, _, pid, root = self.boundary()
        result = wrapper.ProcessResult(pid, 1, b"", b"fatal: exact diagnostic\n")
        with self.assertRaisesRegex(wrapper.Reject, "rc=1"):
            wrapper.execute_and_publish(Path("/approved/phase.json"), "b" * 64, process_boundary=lambda *_: result)
        value = json.loads((root / FAILURE.NAME).read_text())
        self.assertEqual(value["process"]["stderr"]["excerpt"], "fatal: exact diagnostic\n")
        self.assertEqual(value["process"]["stderr"]["sha256"], hashlib.sha256(result.stderr).hexdigest())
        self.assertFalse(value["outcome"]["completion_claimed"])
        self.assertFalse((root / wrapper.COMPLETION_NAME).exists())

    def test_overflow_is_hashed_bounded_and_secret_is_redacted(self):
        wrapper, _, pid, root = self.boundary()
        stderr = b"token=never-persist-this " + b"x" * (wrapper.MAX_BYTES + 1)
        result = wrapper.ProcessResult(pid, 1, b"overflow", stderr)
        with self.assertRaises(wrapper.Reject):
            wrapper.execute_and_publish(Path("/approved/phase.json"), "b" * 64, process_boundary=lambda *_: result)
        raw = (root / FAILURE.NAME).read_bytes()
        value = json.loads(raw)
        self.assertNotIn(b"never-persist-this", raw)
        self.assertTrue(value["process"]["stderr"]["truncated"])
        self.assertEqual(value["process"]["stderr"]["bytes"], len(stderr))
        self.assertEqual(value["process"]["stderr"]["sha256"], hashlib.sha256(stderr).hexdigest())

    def test_marker_mismatch_publishes_failure(self):
        wrapper, _, pid, root = self.boundary()
        result = wrapper.ProcessResult(pid, 0, b"unexpected marker\n", b"")
        with self.assertRaisesRegex(wrapper.Reject, "sole success marker"):
            wrapper.execute_and_publish(Path("/approved/phase.json"), "b" * 64, process_boundary=lambda *_: result)
        value = json.loads((root / FAILURE.NAME).read_text())
        self.assertEqual(value["process"]["returncode"], 0)
        self.assertEqual(value["process"]["stdout"]["excerpt"], "unexpected marker\n")

    def test_collision_write_failure_preserves_foreign_residue(self):
        wrapper, _, pid, root = self.boundary()
        path = root / FAILURE.NAME
        path.write_bytes(b"foreign\n")
        os.chmod(path, 0o600)
        with self.assertRaisesRegex(wrapper.Reject, "already exists"):
            wrapper.execute_and_publish(Path("/approved/phase.json"), "b" * 64, process_boundary=lambda *_: wrapper.ProcessResult(pid, 1, b"", b"failed\n"))
        self.assertEqual(path.read_bytes(), b"foreign\n")
        self.assertFalse((root / wrapper.COMPLETION_NAME).exists())

    def test_fsync_write_failure_preserves_diagnostic_residue(self):
        wrapper, _, pid, root = self.boundary()
        path = root / FAILURE.NAME

        def fail_after_write(target, raw, _label, _owner):
            target.write_bytes(raw)
            os.chmod(target, 0o600)
            raise OSError("simulated failure fsync")

        with mock.patch.object(wrapper, "_write_new", side_effect=fail_after_write):
            with self.assertRaisesRegex(OSError, "simulated failure fsync"):
                wrapper.execute_and_publish(Path("/approved/phase.json"), "b" * 64, process_boundary=lambda *_: wrapper.ProcessResult(pid, 1, b"", b"failed\n"))
        value = json.loads(path.read_text())
        self.assertTrue(value["outcome"]["replay_failure"])
        self.assertFalse((root / wrapper.COMPLETION_NAME).exists())

    def test_success_has_no_failure_and_rejects_preexisting_failure(self):
        wrapper, _, pid, root = self.boundary()
        success = wrapper.ProcessResult(pid, 0, wrapper.SUCCESS_OUTPUT, b"")
        wrapper.execute_and_publish(Path("/approved/phase.json"), "b" * 64, process_boundary=lambda *_: success)
        self.assertFalse((root / FAILURE.NAME).exists())
        (root / FAILURE.NAME).write_bytes(b"existing\n")
        os.chmod(root / FAILURE.NAME, 0o600)
        with self.assertRaisesRegex(wrapper.Reject, "preexisting replay failure"):
            wrapper.execute_and_publish(Path("/approved/phase.json"), "b" * 64, process_boundary=lambda *_: success)

    def test_approved_adapter_is_verified_from_one_buffer(self):
        raw = FAILURE.PHASE_A_ADAPTER_PATH.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), FAILURE.PHASE_A_ADAPTER_SHA256)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "adapter.py"
            path.write_bytes(raw + b"\n")
            with mock.patch.object(FAILURE, "PHASE_A_ADAPTER_PATH", path):
                with self.assertRaisesRegex(RuntimeError, "SHA-256 differs"):
                    FAILURE.load_phase_a_adapter()


if __name__ == "__main__":
    unittest.main(verbosity=2)
