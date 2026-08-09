#!/usr/bin/env python3
"""Offline tests for verified launcher handoff metadata parsing."""

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
                "status": "running",
                "endpoint": "http://127.0.0.1:19124",
                "marker_path": "/private/tmp/hermes/runs/issue118.json",
                "credential_file": "/private/tmp/hermes/runs/issue118.credential",
            },
        }

    def test_extracts_only_verified_endpoint_and_exact_ownership_paths(self) -> None:
        raw = json.dumps(self.document).encode("utf-8")
        self.assertEqual(
            parser.parse_launcher_result(raw),
            {
                "endpoint": "http://127.0.0.1:19124",
                "marker-path": "/private/tmp/hermes/runs/issue118.json",
                "credential-file": "/private/tmp/hermes/runs/issue118.credential",
            },
        )

    def test_rejects_start_or_unverified_endpoint_results_before_handoff(self) -> None:
        bypasses = (
            {"operation": "start"},
            {"operation": "status"},
            {"operation": "credential-file"},
            {"result": {**self.document["result"], "status": "ready"}},
            {"result": {key: value for key, value in self.document["result"].items() if key != "status"}},
            {"result": {**self.document["result"], "unexpected": "metadata"}},
            {"result": {**self.document["result"], "marker_path": "relative-marker.json"}},
        )
        for replacement in bypasses:
            with self.subTest(replacement=replacement):
                document = {**self.document, **replacement}
                with self.assertRaises(parser.LauncherResultError):
                    parser.parse_launcher_result(json.dumps(document))

    def test_endpoint_requires_explicit_canonical_loopback_port(self) -> None:
        for endpoint in (
            "http://127.0.0.1",
            "http://localhost:19124",
            "http://[::1]:19124",
            "http://0.0.0.0:19124",
            "http://127.0.0.1:19124/path",
            "http://127.0.0.1:19124?query",
            "http://127.0.0.1:19124#fragment",
        ):
            with self.subTest(endpoint=endpoint):
                self.document["result"]["endpoint"] = endpoint
                with self.assertRaises(parser.LauncherResultError):
                    parser.parse_launcher_result(json.dumps(self.document))

    def test_cli_emits_only_requested_metadata(self) -> None:
        raw = json.dumps(self.document).encode("utf-8")
        for field, expected in (
            ("endpoint", "http://127.0.0.1:19124"),
            ("marker-path", "/private/tmp/hermes/runs/issue118.json"),
            ("credential-file", "/private/tmp/hermes/runs/issue118.credential"),
        ):
            with self.subTest(field=field), mock_stdin(raw), contextlib.redirect_stdout(io.StringIO()) as stdout:
                status = parser.main([field])
            self.assertEqual(status, 0)
            self.assertEqual(stdout.getvalue(), expected + "\n")

    def test_missing_or_malformed_result_fails_without_echoing_input(self) -> None:
        rejected = (
            b"not-json",
            json.dumps({"ok": False, "result": self.document["result"]}).encode("utf-8"),
            json.dumps({"ok": True, "operation": "endpoint", "result": {"endpoint": self.document["result"]["endpoint"]}}).encode("utf-8"),
            json.dumps({"ok": True, "operation": "endpoint", "result": {"status": "running", "endpoint": "", "marker_path": "path", "credential_file": "path"}}).encode("utf-8"),
            json.dumps({"ok": True, "operation": "endpoint", "result": {**self.document["result"], "endpoint": "http://127.0.0.1\n:19124"}}).encode("utf-8"),
            b'{"ok":true,"operation":"endpoint","operation":"endpoint","result":{}}',
            b'{"ok":true,"operation":"endpoint","result":{"status":"running","endpoint":NaN,"marker_path":"/tmp/m.json","credential_file":"/tmp/m.credential"}}',
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
