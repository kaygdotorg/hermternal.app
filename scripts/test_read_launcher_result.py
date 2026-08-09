#!/usr/bin/env python3
"""Offline tests for launcher endpoint and credential-file result parsing."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import unittest


from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "read_launcher_result.py"
spec = importlib.util.spec_from_file_location("read_launcher_result", SCRIPT)
if spec is None or spec.loader is None:
    raise RuntimeError(f"Could not load {SCRIPT}")
parser = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = parser
spec.loader.exec_module(parser)


class LauncherResultTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = {
            "ok": True,
            "operation": "endpoint",
            "result": {
                "endpoint": "http://127.0.0.1:19124",
                "credential_file": "/private/tmp/hermes/issue118/password",
            },
        }

    def test_extracts_result_endpoint_and_credential_file(self) -> None:
        raw = json.dumps(self.document).encode("utf-8")
        self.assertEqual(
            parser.parse_launcher_result(raw),
            {
                "endpoint": "http://127.0.0.1:19124",
                "credential-file": "/private/tmp/hermes/issue118/password",
            },
        )

    def test_extracts_start_result_without_inventing_a_port(self) -> None:
        self.document["operation"] = "start"
        self.document["result"]["endpoint"] = "http://127.0.0.1:19287"
        parsed = parser.parse_launcher_result(json.dumps(self.document))
        self.assertEqual(parsed["endpoint"], "http://127.0.0.1:19287")

    def test_endpoint_requires_explicit_canonical_loopback_port(self) -> None:
        for endpoint in (
            "http://127.0.0.1",
            "http://localhost:19124",
            "http://[::1]:19124",
            "http://0.0.0.0:19124",
            "http://127.0.0.1:19124/path",
        ):
            with self.subTest(endpoint=endpoint):
                self.document["result"]["endpoint"] = endpoint
                with self.assertRaises(parser.LauncherResultError):
                    parser.parse_launcher_result(json.dumps(self.document))

    def test_cli_emits_only_requested_metadata(self) -> None:
        raw = json.dumps(self.document).encode("utf-8")
        with mock_stdin(raw), contextlib.redirect_stdout(io.StringIO()) as stdout:
            status = parser.main(["endpoint"])
        self.assertEqual(status, 0)
        self.assertEqual(stdout.getvalue(), "http://127.0.0.1:19124\n")

        with mock_stdin(raw), contextlib.redirect_stdout(io.StringIO()) as stdout:
            status = parser.main(["credential-file"])
        self.assertEqual(status, 0)
        self.assertEqual(stdout.getvalue(), "/private/tmp/hermes/issue118/password\n")

    def test_missing_or_malformed_result_fails_without_echoing_input(self) -> None:
        rejected = (
            b"not-json",
            json.dumps({"ok": False, "result": self.document["result"]}).encode("utf-8"),
            json.dumps({"ok": True, "result": {"endpoint": self.document["result"]["endpoint"]}}).encode("utf-8"),
            json.dumps({"ok": True, "result": {"endpoint": "", "credential_file": "path"}}).encode("utf-8"),
            json.dumps({"ok": True, "result": {"endpoint": "http://127.0.0.1\n:19124", "credential_file": "path"}}).encode("utf-8"),
        )
        for raw in rejected:
            with self.subTest(raw_label=len(raw)), mock_stdin(raw), contextlib.redirect_stderr(io.StringIO()) as stderr:
                status = parser.main(["endpoint"])
            self.assertEqual(status, 1)
            self.assertEqual(stderr.getvalue(), "launcher_result_invalid\n")
            self.assertNotIn(raw.decode("utf-8", errors="ignore"), stderr.getvalue())

    def test_invalid_field_usage_fails_before_reading_input(self) -> None:
        with mock_stdin(b"unexpected"), contextlib.redirect_stderr(io.StringIO()) as stderr:
            status = parser.main(["password"])
        self.assertEqual(status, 1)
        self.assertEqual(stderr.getvalue(), "usage_invalid\n")


@contextlib.contextmanager
def mock_stdin(value: bytes):
    original = sys.stdin
    sys.stdin = io.TextIOWrapper(io.BytesIO(value), encoding="utf-8")
    try:
        yield
    finally:
        sys.stdin = original


if __name__ == "__main__":
    unittest.main(verbosity=2)
