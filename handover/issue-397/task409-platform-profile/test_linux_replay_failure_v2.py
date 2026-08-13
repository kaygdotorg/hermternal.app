#!/usr/bin/env python3
"""Simulated-process tests for fixed-root early failure evidence."""
from __future__ import annotations

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
import linux_replay_failure_v2 as V2  # noqa: E402

ANCHOR_SHA = "ebd414148fb55a60751ce14015094f0ce96a0b737e67103a2c3c955feb607a1c"
ANCHOR_PATH = Path("/home/kayg/Developer/hermternal-issue397-phase-a-anchor-v3/evidence/anchor.json")


class EarlyFailureTests(unittest.TestCase):
    """Use process-result fixtures only; no subprocess or replay is started."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix=".early-failure-test-", dir="/home/kayg/Developer")
        self.addCleanup(self.temporary.cleanup)
        self.failure_root = Path(self.temporary.name) / V2.DIRECTORY_NAME
        self.root_patch = mock.patch.object(V2, "_failure_root", return_value=self.failure_root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def wrapper(self):
        return V2.load_approved_wrapper(ANCHOR_SHA)[0]

    def test_child_creates_no_root_rc1_still_publishes_stderr(self):
        wrapper = self.wrapper()
        pid = 22101
        result = wrapper.ProcessResult(pid, 1, b"", b"fatal: early failure\n")
        with self.assertRaisesRegex(wrapper.Reject, "rc=1"):
            wrapper.execute_and_publish(ANCHOR_PATH, ANCHOR_SHA, process_boundary=lambda *_: result)
        path = self.failure_root / V2.FAILURE_NAME
        value = json.loads(path.read_text())
        self.assertEqual(stat.S_IMODE(os.lstat(self.failure_root).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), 0o600)
        self.assertEqual(value["process"]["stderr"]["excerpt"], "fatal: early failure\n")
        self.assertFalse(value["expected_ephemeral_residue"]["run_root"]["exists"])
        self.assertFalse(value["outcome"]["completion_claimed"])

    def test_preexisting_and_symlink_failure_roots_reject_before_process(self):
        for symlink in (False, True):
            if symlink:
                target = Path(self.temporary.name) / "target"
                target.mkdir(mode=0o700)
                self.failure_root.symlink_to(target, target_is_directory=True)
            else:
                self.failure_root.mkdir(mode=0o700)
            called = 0
            def boundary(*_args):
                nonlocal called
                called += 1
            with self.assertRaisesRegex(Exception, "already exists|not canonical"):
                self.wrapper().execute_and_publish(ANCHOR_PATH, ANCHOR_SHA, process_boundary=boundary)
            self.assertEqual(called, 0)
            if self.failure_root.is_symlink():
                self.failure_root.unlink()
            else:
                self.failure_root.rmdir()

    def test_parent_swap_is_rejected_without_child_start(self):
        wrapper = self.wrapper()
        original_stat = V2.os.stat
        def replaced_stat(path, *args, **kwargs):
            value = original_stat(path, *args, **kwargs)
            if Path(path) == self.failure_root.parent and kwargs.get("dir_fd") is None:
                values = list(value)
                values[1] += 1
                return os.stat_result(values)
            return value
        with mock.patch.object(V2.os, "stat", side_effect=replaced_stat):
            with self.assertRaises(Exception):
                wrapper.execute_and_publish(ANCHOR_PATH, ANCHOR_SHA, process_boundary=lambda *_: self.fail("child started"))

    def test_write_and_fsync_failures_leave_no_completion_claim(self):
        wrapper = self.wrapper()
        original_write = V2._write_at
        calls = 0
        def failed_write(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("simulated failure write")
            return original_write(*args, **kwargs)
        with mock.patch.object(V2, "_write_at", side_effect=failed_write):
            with self.assertRaisesRegex(wrapper.Reject, "filesystem failure"):
                wrapper.execute_and_publish(ANCHOR_PATH, ANCHOR_SHA, process_boundary=lambda *_: wrapper.ProcessResult(22102, 1, b"", b"failed\n"))
        self.assertTrue((self.failure_root / V2.OWNER_NAME).exists())
        self.assertFalse((self.failure_root / V2.FAILURE_NAME).exists())

    def test_root_swap_during_owner_write_rejects_before_child(self):
        wrapper = self.wrapper()
        original_write = V2._write_at
        displaced = self.failure_root.with_name(self.failure_root.name + ".displaced")
        def swap_then_write(*args, **kwargs):
            self.failure_root.rename(displaced)
            self.failure_root.mkdir(mode=0o700)
            return original_write(*args, **kwargs)
        with mock.patch.object(V2, "_write_at", side_effect=swap_then_write):
            with self.assertRaisesRegex(wrapper.Reject, "replaced before child"):
                wrapper.execute_and_publish(ANCHOR_PATH, ANCHOR_SHA, process_boundary=lambda *_: self.fail("child started"))
        self.assertFalse((self.failure_root / V2.OWNER_NAME).exists())
        self.assertTrue((displaced / V2.OWNER_NAME).exists())

    def test_prepare_fsync_failure_prevents_child_start(self):
        wrapper = self.wrapper()
        with mock.patch.object(V2.os, "fsync", side_effect=OSError("simulated parent fsync")):
            with self.assertRaisesRegex(wrapper.Reject, "filesystem failure"):
                wrapper.execute_and_publish(ANCHOR_PATH, ANCHOR_SHA, process_boundary=lambda *_: self.fail("child started"))
        self.assertTrue(self.failure_root.exists())

    def test_success_removes_only_owned_empty_transaction(self):
        wrapper = self.wrapper()
        success = wrapper.ProcessResult(22103, 0, wrapper.SUCCESS_OUTPUT, b"")
        with self.assertRaises(wrapper.Reject):
            wrapper.execute_and_publish(ANCHOR_PATH, ANCHOR_SHA, process_boundary=lambda *_: success)
        self.assertFalse(self.failure_root.exists())

    def test_bounded_redacted_v1_payload_is_retained(self):
        wrapper = self.wrapper()
        stderr = b"github_pat_123456789abcdef " + b"x" * (wrapper.MAX_BYTES + 1)
        with self.assertRaises(wrapper.Reject):
            wrapper.execute_and_publish(ANCHOR_PATH, ANCHOR_SHA, process_boundary=lambda *_: wrapper.ProcessResult(22104, 1, b"", stderr))
        raw = (self.failure_root / V2.FAILURE_NAME).read_bytes()
        value = json.loads(raw)
        self.assertNotIn(b"github_pat_123456789abcdef", raw)
        self.assertTrue(value["process"]["stderr"]["truncated"])
        self.assertEqual(value["process"]["stderr"]["bytes"], len(stderr))


if __name__ == "__main__":
    unittest.main(verbosity=2)
