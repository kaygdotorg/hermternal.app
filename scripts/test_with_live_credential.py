#!/usr/bin/env python3
"""Focused offline tests for the local live-proof credential handoff.

These tests use synthetic bytes only. They never contact Hermes, create a real
credential, start a browser, or retain authentication data.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "with_live_credential.py"
spec = importlib.util.spec_from_file_location("with_live_credential", SCRIPT)
if spec is None or spec.loader is None:
    raise RuntimeError(f"Could not load {SCRIPT}")
helper = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = helper
spec.loader.exec_module(helper)


class LiveProofCredentialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "password"
        self.value = b"a" * 48

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_read_strips_only_terminal_crlf_and_preserves_file(self) -> None:
        for label, suffix in (
            ("bare", b""),
            ("lf", b"\n"),
            ("cr", b"\r"),
            ("crlf", b"\r\n"),
            ("repeated-line-endings", b"\n\r"),
        ):
            with self.subTest(label=label):
                raw = self.value + suffix
                self.path.write_bytes(raw)
                self.assertEqual(helper.read_credential_file(self.path), self.value.decode("ascii"))
                self.assertEqual(self.path.read_bytes(), raw)

    def test_non_line_ending_whitespace_and_interior_line_endings_fail_closed(self) -> None:
        rejected = (
            ("space", self.value + b" "),
            ("tab-before-lf", self.value + b"\t\n"),
            ("interior-lf", self.value[:24] + b"\n" + self.value[24:]),
            ("trailing-bytes", self.value + b"\ntrailing"),
            ("uppercase", self.value.upper()),
            ("short", self.value[:-1]),
            ("long", self.value + b"0"),
            ("empty", b""),
        )
        for label, raw in rejected:
            with self.subTest(label=label):
                self.path.write_bytes(raw)
                with self.assertRaises(helper.LiveProofCredentialError) as raised:
                    helper.read_credential_file(self.path)
                self.assertEqual(raised.exception.code, "credential_file_invalid")

    def test_overlong_file_fails_before_command_and_does_not_log_value(self) -> None:
        self.path.write_bytes(self.value + (b"x" * (helper.MAX_CREDENTIAL_BYTES + 1)))
        stderr = io.StringIO()
        with mock.patch.object(helper.os, "execvpe") as execvpe, contextlib.redirect_stderr(stderr):
            status = helper.main([str(self.path), "--", "synthetic-proof"])

        self.assertEqual(status, 1)
        self.assertEqual(stderr.getvalue(), "credential_file_invalid\n")
        self.assertFalse(execvpe.called)
        self.assertNotIn(self.value.decode("ascii"), stderr.getvalue())

    def test_valid_value_is_only_passed_to_child_environment(self) -> None:
        raw = self.value + b"\r\n"
        self.path.write_bytes(raw)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(helper.os, "execvpe", side_effect=OSError) as execvpe,
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            status = helper.main([str(self.path), "--", "synthetic-proof", "--flag"])

        self.assertEqual(status, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "live_proof_command_failed\n")
        call = execvpe.call_args
        self.assertIsNotNone(call)
        command, arguments, environment = call.args
        self.assertEqual(command, "synthetic-proof")
        self.assertEqual(arguments, ["synthetic-proof", "--flag"])
        self.assertEqual(environment["HERMES_TEST_PASSWORD"], self.value.decode("ascii"))
        self.assertNotEqual(environment["HERMES_TEST_PASSWORD"], raw.decode("ascii"))
        self.assertNotIn(self.value.decode("ascii"), " ".join(arguments))
        self.assertEqual(self.path.read_bytes(), raw)

    def test_invalid_shape_never_starts_child(self) -> None:
        self.path.write_bytes(self.value + b"\n ")
        with mock.patch.object(helper.os, "execvpe") as execvpe:
            status = helper.main([str(self.path), "--", "synthetic-proof"])

        self.assertEqual(status, 1)
        self.assertFalse(execvpe.called)


if __name__ == "__main__":
    unittest.main(verbosity=2)
