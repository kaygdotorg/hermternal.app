#!/usr/bin/env python3
"""Offline tests for the thin fixed v4 replay operator."""
from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.fspath(HERE))
import replay_operator_v4 as OPERATOR  # noqa: E402


class ReplayOperatorTests(unittest.TestCase):
    """Mock only the two approved delegations; never start replay."""

    def test_preflight_delegates_once_and_never_calls_run(self):
        result = {"execution_enabled": False, "replay_run": False, "runtime_parent": "/tmp"}
        with mock.patch.object(OPERATOR, "_delegate_preflight", return_value=result) as preflight, mock.patch.object(OPERATOR, "_delegate_run", side_effect=AssertionError("run must not start")):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(OPERATOR.main(["--preflight"]), 0)
        preflight.assert_called_once_with()
        self.assertIn('"replay_run":false', stdout.getvalue())

    def test_run_delegates_once_with_only_fixed_anchor_values(self):
        publication = types.SimpleNamespace(result=types.SimpleNamespace(path=Path("/tmp/result.json")), completion=types.SimpleNamespace(path=Path("/tmp/completion.json")))
        wrapper = types.SimpleNamespace(execute_and_publish=mock.Mock(return_value=publication))
        adapter = types.SimpleNamespace(load_approved_wrapper=mock.Mock(return_value=(wrapper, object())))
        with mock.patch.object(OPERATOR, "_load_failure_v2", return_value=(adapter, object())) as loaded:
            self.assertIs(OPERATOR._delegate_run(), publication)
        loaded.assert_called_once_with()
        adapter.load_approved_wrapper.assert_called_once_with(OPERATOR.ANCHOR_SHA256)
        wrapper.execute_and_publish.assert_called_once_with(OPERATOR.ANCHOR_PATH, OPERATOR.ANCHOR_SHA256)

    def test_main_run_reports_only_closed_publication_fields(self):
        publication = types.SimpleNamespace(result=types.SimpleNamespace(path=Path("/tmp/result.json")), completion=types.SimpleNamespace(path=Path("/tmp/completion.json")))
        with mock.patch.object(OPERATOR, "_delegate_run", return_value=publication) as run:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(OPERATOR.main(["--run"]), 0)
        run.assert_called_once_with()
        self.assertEqual(stdout.getvalue(), "PASS: /tmp/result.json\nCOMPLETION: /tmp/completion.json\n")

    def test_parser_rejects_caller_selected_authority_arguments(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                OPERATOR.build_parser().parse_args(["--run", "--anchor", "/tmp/other.json"])
            with self.assertRaises(SystemExit):
                OPERATOR.build_parser().parse_args(["--preflight", "--profile", "/tmp/other.json"])

    def test_failure_v2_pin_mismatch_rejects_before_wrapper_load(self):
        with mock.patch.object(OPERATOR, "FAILURE_V2_SHA256", "0" * 64):
            with self.assertRaisesRegex(OPERATOR.Reject, "replay failure v2 adapter SHA-256 differs"):
                OPERATOR._load_failure_v2()

    def test_stable_read_rejects_path_swap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.py"
            replacement = root / "replacement.py"
            target.write_bytes(b"approved\n")
            replacement.write_bytes(b"replacement\n")
            digest = OPERATOR.hashlib.sha256(target.read_bytes()).hexdigest()
            original_lstat = OPERATOR.os.lstat
            target_lstat_calls = 0

            def swap_then_stat(path):
                nonlocal target_lstat_calls
                if Path(path) == target:
                    target_lstat_calls += 1
                # realpath() performs the first lstat. Replace only at the
                # post-read identity check, not before the approved open.
                if Path(path) == target and target_lstat_calls == 2 and replacement.exists():
                    os.replace(replacement, target)
                return original_lstat(path)

            with mock.patch.object(OPERATOR.os, "lstat", side_effect=swap_then_stat):
                with self.assertRaisesRegex(OPERATOR.Reject, "changed during read"):
                    OPERATOR._stable_bytes(target, digest, "test target")


if __name__ == "__main__":
    unittest.main(verbosity=2)
