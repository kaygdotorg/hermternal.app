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
                "run_id": "a" * 64,
                "credential_file": "/private/tmp/hermes/runs/issue118.credential",
                "credential_identity": {
                    "device": 1,
                    "inode": 2,
                    "mode": 0o600,
                    "size": 49,
                    "nlink": 1,
                    "generation": "b" * 64,
                },
            },
        }

    def test_extracts_only_verified_endpoint_and_exact_ownership_paths(self) -> None:
        raw = parser._serialize_result(self.document)
        self.assertEqual(
            parser.parse_launcher_result(raw),
            {
                "endpoint": "http://127.0.0.1:19124",
                "marker-path": "/private/tmp/hermes/runs/issue118.json",
                "run-id": "a" * 64,
                "credential-file": "/private/tmp/hermes/runs/issue118.credential",
                "credential-identity": '{"device":1,"generation":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","inode":2,"mode":384,"nlink":1,"size":49}',
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
            "HTTP://127.0.0.1:19124",
            "http://127.0.0.1:01",
            "http://127.0.0.1:001",
            "http://127.0.0.1:00080",
            "http://127.0.0.1:019124",
            "http://localhost:19124",
            "http://[::1]:19124",
            "http://0.0.0.0:19124",
            "http://127.0.0.1:19124/",
            "http://127.0.0.1:19124/path",
            "http://127.0.0.1:19124?query",
            "http://127.0.0.1:19124?",
            "http://127.0.0.1:19124#fragment",
            "http://127.0.0.1:19124#",
        ):
            with self.subTest(endpoint=endpoint):
                self.document["result"]["endpoint"] = endpoint
                with self.assertRaises(parser.LauncherResultError):
                    parser.parse_launcher_result(json.dumps(self.document))

    def test_cli_emits_only_requested_metadata(self) -> None:
        raw = parser._serialize_result(self.document)
        for field, expected in (
            ("endpoint", "http://127.0.0.1:19124"),
            ("marker-path", "/private/tmp/hermes/runs/issue118.json"),
            ("run-id", "a" * 64),
            ("credential-file", "/private/tmp/hermes/runs/issue118.credential"),
            ("credential-identity", '{"device":1,"generation":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","inode":2,"mode":384,"nlink":1,"size":49}'),
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

    def test_exact_maximum_valid_compound_result_is_accepted(self) -> None:
        document = parser._maximum_valid_result_document()
        raw = parser._serialize_result(document)
        # Keep the parent-candidate failure at this assertion: its surrogate
        # packing is a valid smaller fixture, not the parser-wide maximum.
        self.assertEqual(parser.MAX_RESULT_BYTES, 25_068)
        self.assertEqual(
            len(json.dumps(document["result"]["marker_path"], ensure_ascii=True)),
            12_287,
        )
        self.assertEqual(len(raw), parser.MAX_RESULT_BYTES)
        parsed = parser.parse_launcher_result(raw)
        self.assertEqual(parsed["marker-path"], document["result"]["marker_path"])
        self.assertEqual(parsed["credential-file"], document["result"]["credential_file"])

    def test_accepts_4497_byte_producer_shaped_lower_bound(self) -> None:
        marker_path = "/" + ("a" * 1_993)
        document = parser._maximum_valid_result_document()
        document["result"]["marker_path"] = marker_path
        document["result"]["credential_file"] = marker_path + ".credential"
        raw = parser._serialize_result(document)
        self.assertEqual(len(marker_path.encode("utf-8")), 1_994)
        self.assertEqual(len((marker_path + ".state.json").encode("utf-8")), 2_005)
        self.assertEqual(len(document["result"]["credential_file"].encode("utf-8")), 2_005)
        self.assertEqual(len((marker_path + ".cidfile").encode("utf-8")), 2_002)
        self.assertEqual(len(raw), 4_497)
        parsed = parser.parse_launcher_result(raw)
        self.assertEqual(parsed["marker-path"], marker_path)
        self.assertEqual(parsed["credential-file"], marker_path + ".credential")

    def test_requires_canonical_producer_framing(self) -> None:
        raw = parser._serialize_result(self.document)
        for noncanonical in (raw[:-1], raw[:-1] + b"\r\n", b" " + raw, raw + b"\n"):
            with self.subTest(raw_length=len(noncanonical)):
                with self.assertRaises(parser.LauncherResultError):
                    parser.parse_launcher_result(noncanonical)

    def test_one_byte_over_exact_maximum_result_is_rejected(self) -> None:
        raw = parser._serialize_result(parser._maximum_valid_result_document())
        self.assertEqual(len(raw), parser.MAX_RESULT_BYTES)
        too_large = raw + b" "
        self.assertEqual(len(too_large), parser.MAX_RESULT_BYTES + 1)
        with mock_stdin(too_large), contextlib.redirect_stderr(io.StringIO()) as stderr:
            status = parser.main(["endpoint"])
        self.assertEqual(status, 1)
        self.assertEqual(stderr.getvalue(), "launcher_result_invalid\n")

    def test_cli_bounds_total_input_and_rejects_pathological_json_without_traceback(self) -> None:
        valid = json.dumps(self.document).encode("utf-8")
        huge_integer = (
            b'{"ok":true,"operation":"endpoint","result":{"status":"running",'
            b'"endpoint":"http://127.0.0.1:19124","marker_path":"/tmp/m.json",'
            b'"run_id":"' + b"a" * 64 + b'","credential_file":"/tmp/m.credential",'
            b'"credential_identity":{"device":' + b"9" * 5000 +
            b',"inode":2,"mode":384,"size":49,"nlink":1,"generation":"' +
            b"b" * 64 + b'"}}}'
        )
        deep = b"[" * (parser.MAX_JSON_DEPTH + 1) + b"0" + b"]" * (parser.MAX_JSON_DEPTH + 1)
        surrogate = json.dumps(
            {**self.document, "result": {**self.document["result"], "marker_path": "/tmp/\ud800"}},
            ensure_ascii=True,
        ).encode("ascii")
        rejected = (
            b" " * (parser.MAX_RESULT_BYTES - len(valid) + 1) + valid,
            valid + b"\n" + valid,
            huge_integer,
            deep,
            surrogate,
        )
        for raw in rejected:
            with self.subTest(raw_length=len(raw)), mock_stdin(raw):
                stdout = io.StringIO()
                stderr = io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    status = parser.main(["endpoint"])
                self.assertEqual(status, 1)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(stderr.getvalue(), "launcher_result_invalid\n")
                self.assertNotIn("Traceback", stderr.getvalue())
                self.assertNotIn("\\ud800", stderr.getvalue())
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
