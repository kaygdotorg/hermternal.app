#!/usr/bin/env python3
"""Regression tests for the synthetic DEP-02 external exposure boundary.

The tests use only the local manifest and Python's standard library.  They do
not import Hermes, start a proxy, open a socket, resolve a host, or contact a
provider.
"""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


FIXTURE_DIR = Path(__file__).resolve().parent
if str(FIXTURE_DIR) not in sys.path:
    sys.path.insert(0, str(FIXTURE_DIR))

import validate  # noqa: E402


class ExternalAllowlistTests(unittest.TestCase):
    """Keep the frozen matrix, model, parser, redaction, and baseline aligned."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.document = validate.load_json(validate.CASES_PATH)
        validate.validate_redaction(cls.document)
        validate.validate_cases_document(cls.document)
        cls.cases = {case["id"]: case for case in cls.document["cases"]}

    def _run_cli(self, content: bytes, *, optimized: bool = False) -> subprocess.CompletedProcess[str]:
        with tempfile.NamedTemporaryFile(suffix=".json") as handle:
            handle.write(content)
            handle.flush()
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.extend(
                [
                    str(FIXTURE_DIR / "validate.py"),
                    "--cases",
                    handle.name,
                    "--skip-baseline",
                ]
            )
            return subprocess.run(command, check=False, capture_output=True, text=True)

    def _run_compact_error(self, message: str, *, optimized: bool = False) -> subprocess.CompletedProcess[str]:
        script = (
            "import json, sys\n"
            f"sys.path.insert(0, {str(FIXTURE_DIR)!r})\n"
            "import validate\n"
            "print(json.dumps(validate.compact_error(sys.argv[1])))\n"
        )
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend(["-c", script, message])
        return subprocess.run(command, check=False, capture_output=True, text=True)

    def _assert_helper_redaction(self, message: str, markers: tuple[str, ...]) -> None:
        outputs: list[str] = []
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                completed = self._run_compact_error(message, optimized=optimized)
                self.assertEqual(completed.returncode, 0)
                self.assertEqual(completed.stderr, "")
                compacted = json.loads(completed.stdout)
                self.assertIsInstance(compacted, str)
                self.assertLessEqual(len(compacted), validate.MAX_ERROR_OUTPUT)
                for marker in markers:
                    self.assertNotIn(marker, compacted)
                outputs.append(compacted)
        self.assertEqual(outputs[0], outputs[1])

    def _assert_cli_failure(self, content: bytes) -> None:
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                completed = self._run_cli(content, optimized=optimized)
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stderr, "")
                lines = [line for line in completed.stdout.splitlines() if line.strip()]
                self.assertEqual(len(lines), 1)
                payload = json.loads(lines[0])
                self.assertFalse(payload["ok"])
                self.assertEqual(payload["error"]["code"], validate.ERROR_CODE)
                self.assertLessEqual(len(payload["error"]["message"]), validate.MAX_ERROR_OUTPUT)
                self.assertNotIn("Traceback", completed.stdout + completed.stderr)

    def _assert_cli_redaction_failure(self, document: dict[str, object], markers: tuple[str, ...]) -> None:
        content = json.dumps(document, separators=(",", ":")).encode()
        outputs: list[str] = []
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                completed = self._run_cli(content, optimized=optimized)
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stderr, "")
                lines = [line for line in completed.stdout.splitlines() if line.strip()]
                self.assertEqual(len(lines), 1)
                payload = json.loads(lines[0])
                self.assertFalse(payload["ok"])
                self.assertEqual(payload["error"]["code"], validate.ERROR_CODE)
                self.assertLessEqual(len(payload["error"]["message"]), validate.MAX_ERROR_OUTPUT)
                self.assertNotIn("Traceback", completed.stdout)
                for marker in markers:
                    self.assertNotIn(marker, completed.stdout)
                outputs.append(completed.stdout)
        self.assertEqual(outputs[0], outputs[1])

    def test_checked_in_manifest_has_expected_order_and_case_count(self) -> None:
        self.assertEqual(tuple(self.cases), validate.EXPECTED_CASE_IDS)
        self.assertEqual(len(self.cases), 71)
        self.assertEqual(len(self.document["static_routes"]), 6)
        self.assertEqual(len(self.document["external_routes"]), 19)

    def test_manifest_matches_frozen_routes_without_broad_patterns(self) -> None:
        self.assertEqual(tuple(self.document["static_routes"]), validate.EXPECTED_STATIC_ROUTES)
        self.assertEqual(tuple(self.document["external_routes"]), validate.EXPECTED_EXTERNAL_ROUTES)
        for route in self.document["external_routes"]:
            self.assertTrue(route["path"].startswith("/hermes/"))
            self.assertNotIn("*", route["path"])
            self.assertNotIn("%", route["path"])
        self.assertNotIn("/api/*", [route["path"] for route in self.document["external_routes"]])

    def test_each_allowlisted_route_has_a_positive_case(self) -> None:
        positive_ids = {
            case["expected"]["route_id"]
            for case in self.document["cases"]
            if case["expected"]["decision"] == "allow"
        }
        self.assertEqual(positive_ids, set(validate.ROUTE_BY_ID))

    def test_every_case_matches_independent_boundary_model(self) -> None:
        for case in self.document["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(validate.evaluate_case(case), case["expected"])

    def test_static_deep_links_are_finite_and_exact(self) -> None:
        allowed = {"/", "/app", "/app/chat", "/settings", "/signed-out"}
        for path in allowed:
            request = {
                "method": "GET",
                "path": path,
                "client": "browser",
                "transport": "http",
                "auth": "public",
                "headers": {},
                "query": {},
            }
            self.assertEqual(validate.evaluate_request(request)["decision"], "allow")
        for path in ("/app/", "/app/other", "/dashboard", "/app?route=chat"):
            request = {
                "method": "GET",
                "path": path,
                "client": "browser",
                "transport": "http",
                "auth": "public",
                "headers": {},
                "query": {},
            }
            self.assertEqual(validate.evaluate_request(request)["decision"], "deny")

    def test_session_id_accepts_only_the_reviewed_opaque_grammar(self) -> None:
        base = {
            "method": "GET",
            "path": "/hermes/api/sessions/a7",
            "client": "browser",
            "transport": "http",
            "auth": "browser_cookie",
            "headers": {},
            "query": {},
        }
        for session_id in ("a", "a7", "a7.session~2", "A_7-xyz"):
            request = dict(base, path=f"/hermes/api/sessions/{session_id}")
            self.assertEqual(validate.evaluate_request(request)["decision"], "allow")
        for session_id in ("", ".", "..", "a$b", "a/b", "a%2Fb", "_a", "a_", "a" * 129):
            request = dict(base, path=f"/hermes/api/sessions/{session_id}")
            self.assertEqual(validate.evaluate_request(request)["decision"], "deny")

    def test_prefix_encoding_and_traversal_are_not_normalized(self) -> None:
        expected = {
            "deny-unprefixed-chat-websocket": "path_prefix_required",
            "deny-duplicate-prefix": "duplicate_prefix_denied",
            "deny-encoded-slash": "encoded_path_denied",
            "deny-encoded-dot": "encoded_path_denied",
            "deny-encoded-prefix": "encoded_path_denied",
            "deny-traversal": "path_traversal_denied",
        }
        for case_id, reason in expected.items():
            with self.subTest(case=case_id):
                self.assertEqual(self.cases[case_id]["expected"]["reason"], reason)
                self.assertEqual(validate.evaluate_case(self.cases[case_id])["decision"], "deny")

    def test_method_override_aliases_are_denied_before_route_matching(self) -> None:
        base = {
            "method": "GET",
            "path": "/hermes/api/sessions",
            "client": "browser",
            "transport": "http",
            "auth": "browser_cookie",
            "headers": {},
            "query": {},
        }
        header_cases = (
            {"X-HTTP-Method-Override": "POST"},
            {"x-method-override": "PATCH"},
            {"x-http-method": "DELETE"},
        )
        for headers in header_cases:
            with self.subTest(headers=headers):
                self.assertEqual(validate.evaluate_request(dict(base, headers=headers))["reason"], "method_override_denied")
        query_aliases = (
            "_method",
            "METHOD",
            "method_override",
            "X-Method-Override",
            "X_HTTP_METHOD_OVERRIDE",
            "x-http-method",
            "X-HTTP-METHOD",
            "x_http_method",
            "x%2Dhttp%2Dmethod",
            "%78%252Dhttp%252Dmethod",
        )
        for key in query_aliases:
            with self.subTest(query_key=key):
                self.assertEqual(
                    validate.evaluate_request(dict(base, query={key: "POST"}))["reason"],
                    "method_override_denied",
                )

    def test_c01_client_auth_bindings_do_not_cross_containers(self) -> None:
        checks = (
            (
                "external-logout-native-cookie",
                "allow",
                "dashboard_route_allowed",
            ),
            (
                "deny-logout-native-bearer",
                "deny",
                "auth_not_allowlisted",
            ),
            (
                "deny-auth-me-native-cookie",
                "deny",
                "auth_not_allowlisted",
            ),
            (
                "deny-session-browser-native-bearer",
                "deny",
                "auth_not_allowlisted",
            ),
            (
                "deny-session-native-browser-cookie",
                "deny",
                "auth_not_allowlisted",
            ),
        )
        for case_id, decision, reason in checks:
            with self.subTest(case=case_id):
                result = validate.evaluate_case(self.cases[case_id])
                self.assertEqual(result["decision"], decision)
                self.assertEqual(result["reason"], reason)

    def test_management_and_source_sidecar_routes_are_denied(self) -> None:
        management_cases = {
            "deny-admin-config-defaults",
            "deny-admin-dashboard-plugins",
            "deny-admin-gateway-restart",
            "deny-admin-files",
            "deny-admin-ssh",
            "deny-admin-model-options",
            "deny-admin-pub",
            "deny-admin-events",
            "deny-admin-console",
            "deny-admin-cron",
            "deny-source-health",
        }
        for case_id in management_cases:
            with self.subTest(case=case_id):
                result = self.cases[case_id]["expected"]
                self.assertEqual(result["decision"], "deny")
                self.assertEqual(result["reason"], "management_route_denied")
                self.assertIsNone(result["route_id"])

    def test_cli_success_is_one_json_line_in_both_modes(self) -> None:
        for optimized in (False, True):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.append(str(FIXTURE_DIR / "validate.py"))
            completed = subprocess.run(command, check=False, capture_output=True, text=True)
            with self.subTest(optimized=optimized):
                self.assertEqual(completed.returncode, 0)
                self.assertEqual(completed.stderr, "")
                lines = [line for line in completed.stdout.splitlines() if line.strip()]
                self.assertEqual(len(lines), 1)
                payload = json.loads(lines[0])
                self.assertTrue(payload["ok"])
                self.assertEqual(payload["cases"], 71)
                self.assertIsNone(payload["threshold"])

    def test_cli_rejects_duplicate_nonfinite_overflow_deep_and_oversized_inputs(self) -> None:
        self._assert_cli_failure(b'{"value":1,"value":2}')
        self._assert_cli_failure(b'{"value":NaN}')
        self._assert_cli_failure(b'{"value":1e9999}')
        self._assert_cli_failure(b'{"value":' + b"1" * 4301 + b"}")
        self._assert_cli_failure(("[" * 65 + "0" + "]" * 65).encode())
        self._assert_cli_failure(b'{"value":"' + b"x" * (validate.MAX_STRING_LENGTH + 1) + b'"}')

    def test_cli_rejects_wrong_scalar_identity_and_unknown_keys(self) -> None:
        wrong_type = copy.deepcopy(self.document)
        wrong_type["cases"][0]["request"]["method"] = True
        self._assert_cli_failure(json.dumps(wrong_type).encode())
        unknown_key = copy.deepcopy(self.document)
        unknown_key["policy"]["unexpected"] = "deny"
        self._assert_cli_failure(json.dumps(unknown_key).encode())
        widened_route = copy.deepcopy(self.document)
        widened_route["external_routes"][0]["path"] = "/hermes/*"
        self._assert_cli_failure(json.dumps(widened_route).encode())

    def test_redaction_rejects_retained_output_classes_even_with_synthetic_values(self) -> None:
        messages = (
            "X-API-Key: synthetic",
            "password=synthetic",
            "token=synthetic",
            "Authorization: synthetic",
            "session-token=synthetic",
            "api-key=synthetic",
            "secret: synthetic",
            "data:image/png;base64,iVBORw0KGgo=",
            "short unpadded QUJDREVG value",
            "URL-safe padded AQIDBAUG-_== value",
            "short unpadded YWJjZGVm value",
            "URL-safe unpadded YWJjZGVm-_ value",
            "embedded padded AQIDBAUGBwgJ== value",
            "embedded unpadded AQIDBAUGBwgJ value",
            "artifact at /Users/alice/private/report.txt",
            r"artifact at C:\\Users\\Alice\\private\\report.txt",
            "artifact at ../local/report.txt",
            "uploaded filename report.txt",
            "artifact at /tmp",
            "artifact for localhost:3000",
            "artifact for evil.example.com",
            "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
            "Cookie: session=synthetic-cookie-value",
            "Bearer synthetic-bearer-value",
        )
        for message in messages:
            with self.subTest(message=message):
                with self.assertRaises(validate.ValidationError):
                    validate.validate_redaction({"message": message})

    def test_error_compaction_redacts_retained_edge_shapes_in_normal_and_optimized_modes(self) -> None:
        checks = (
            ("retained=QUJDREVG", ("QUJDREVG",)),
            ("retained=AQIDBAUG-_==", ("AQIDBAUG-_==",)),
            ("retained=YWJjZGVm", ("YWJjZGVm",)),
            ("retained=YWJjZGVm-_", ("YWJjZGVm-_",)),
            ("retained=/tmp", ("/tmp",)),
            ("retained=localhost:3000", ("localhost:3000",)),
        )
        for message, markers in checks:
            with self.subTest(message=message):
                self._assert_helper_redaction(message, markers)

    def test_real_cli_rejects_retained_edge_shapes_in_normal_and_optimized_modes(self) -> None:
        for value in ("QUJDREVG", "AQIDBAUG-_==", "YWJjZGVm", "YWJjZGVm-_", "/tmp", "localhost:3000"):
            with self.subTest(value=value):
                mutated = copy.deepcopy(self.document)
                mutated["cases"][0]["request"]["headers"]["X-Note"] = value
                self._assert_cli_redaction_failure(mutated, (value,))

    def test_real_cli_redacts_retained_output_in_normal_and_optimized_modes(self) -> None:
        markers = (
            "data:image/png;base64,iVBORw0KGgo=",
            "AQIDBAUGBwgJ==",
            "AQIDBAUGBwgJ",
            "YWJjZGVm",
            "YWJjZGVm-_",
            "/Users/alice/private/report.txt",
            "/tmp",
            "localhost:3000",
            r"C:\\Users\\Alice\\private\\report.txt",
            "../local/report.txt",
            "report.txt",
            "evil.example.com",
            "QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
            "synthetic-cookie-value",
            "synthetic-bearer-value",
        )
        values = (
            "data:image/png;base64,iVBORw0KGgo=",
            "embedded padded AQIDBAUGBwgJ== value",
            "embedded unpadded AQIDBAUGBwgJ value",
            "embedded short YWJjZGVm value",
            "embedded URL-safe YWJjZGVm-_ value",
            "artifact at /Users/alice/private/report.txt",
            "artifact at /tmp",
            "artifact for localhost:3000",
            r"artifact at C:\\Users\\Alice\\private\\report.txt",
            "artifact at ../local/report.txt",
            "uploaded filename report.txt",
            "artifact for evil.example.com",
            "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
            "Cookie: session=synthetic-cookie-value",
            "Bearer synthetic-bearer-value",
        )
        for value in values:
            with self.subTest(value=value):
                mutated = copy.deepcopy(self.document)
                mutated["cases"][0]["description"] = value
                self._assert_cli_redaction_failure(mutated, tuple(marker for marker in markers if marker in value))

        hostile_keys = (
            "data:image/png;base64,iVBORw0KGgo=",
            "AQIDBAUGBwgJ==",
            "YWJjZGVm",
            "YWJjZGVm-_",
            "/Users/alice/private/report.txt",
            "/tmp",
            "localhost:3000",
            r"C:\\Users\\Alice\\private\\report.txt",
            "report.txt",
            "evil.example.com",
        )
        for hostile_key in hostile_keys:
            with self.subTest(hostile_key=hostile_key):
                mutated = copy.deepcopy(self.document)
                mutated["cases"][0]["request"][hostile_key] = "synthetic"
                self._assert_cli_redaction_failure(mutated, (hostile_key,))

    def test_direct_requests_share_manifest_redaction_boundary(self) -> None:
        base = {
            "method": "GET",
            "path": "/hermes/api/sessions",
            "client": "browser",
            "transport": "http",
            "auth": "browser_cookie",
            "headers": {},
            "query": {},
        }
        with self.assertRaises(validate.ValidationError):
            validate.evaluate_request(dict(base, headers={"Authorization": "synthetic"}))
        with self.assertRaises(validate.ValidationError):
            validate.evaluate_request(dict(base, query={"token": "synthetic"}))
        with self.assertRaises(validate.ValidationError):
            validate.evaluate_request(dict(base, path="https://synthetic.invalid/hermes/api/sessions"))

    def test_error_compaction_redacts_retained_shapes_and_caps_output(self) -> None:
        markers = (
            "data:image/png;base64,iVBORw0KGgo=",
            "AQIDBAUGBwgJ==",
            "AQIDBAUGBwgJ",
            "YWJjZGVm",
            "YWJjZGVm-_",
            "/Users/alice/private/report.txt",
            "/tmp",
            "localhost:3000",
            r"C:\\Users\\Alice\\private\\report.txt",
            "../local/report.txt",
            "report.txt",
            "evil.example.com",
            "QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
            "synthetic-cookie-value",
            "synthetic-bearer-value",
            "ghp_example_secret",
        )
        message = (
            "data:image/png;base64,iVBORw0KGgo= embedded padded AQIDBAUGBwgJ== "
            "embedded unpadded AQIDBAUGBwgJ artifact /Users/alice/private/report.txt "
            r"C:\\Users\\Alice\\private\\report.txt ../local/report.txt report.txt "
            "evil.example.com Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ== "
            "Cookie: session=synthetic-cookie-value Bearer synthetic-bearer-value "
            "Authorization: Bearer ghp_example_secret "
            + "x" * 500
        )
        compacted = validate.compact_error(message)
        for marker in markers:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, compacted)
        self.assertLessEqual(len(compacted), validate.MAX_ERROR_OUTPUT)

    def test_invalid_cli_arguments_are_controlled_and_do_not_echo_values(self) -> None:
        for optimized in (False, True):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.extend([str(FIXTURE_DIR / "validate.py"), "--unknown=Authorization: raw-value"])
            completed = subprocess.run(command, check=False, capture_output=True, text=True)
            with self.subTest(optimized=optimized):
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stderr, "")
                self.assertNotIn("raw-value", completed.stdout)
                self.assertNotIn("usage:", completed.stdout.lower())
                self.assertNotIn("Traceback", completed.stdout)

    def test_baseline_has_two_30_sample_traces_and_null_threshold(self) -> None:
        baseline = validate.load_json(validate.BASELINE_PATH)
        validate.validate_redaction(baseline)
        validate.validate_baseline(baseline)
        self.assertEqual(baseline["threshold"], None)
        self.assertEqual([run["repetitions"] for run in baseline["runs"]], [30, 30])

    def test_baseline_recomputes_distribution_and_binds_artifact(self) -> None:
        baseline = validate.load_json(validate.BASELINE_PATH)
        forged_distribution = copy.deepcopy(baseline)
        forged_distribution["runs"][0]["distribution"]["p50_ms"] += 1.0
        with self.assertRaises(validate.ValidationError):
            validate.validate_baseline(forged_distribution)
        forged_command = copy.deepcopy(baseline)
        forged_command["runs"][1]["command"] = "echo fabricated"
        with self.assertRaises(validate.ValidationError):
            validate.validate_baseline(forged_command)
        forged_artifact = copy.deepcopy(baseline)
        forged_artifact["artifact"]["sha256"] = "0" * 64
        with self.assertRaises(validate.ValidationError):
            validate.validate_baseline(forged_artifact)

    def test_baseline_cannot_rebind_digest_to_a_mutated_fixture_copy(self) -> None:
        baseline = validate.load_json(validate.BASELINE_PATH)
        with tempfile.TemporaryDirectory() as directory:
            copied_root = Path(directory)
            for relative in validate.ARTIFACT_FILES:
                shutil.copy2(FIXTURE_DIR / relative, copied_root / relative)
            (copied_root / "README.md").write_text(
                (copied_root / "README.md").read_text(encoding="utf-8") + "\\nAdditional local note.\\n",
                encoding="utf-8",
            )
            rebound = copy.deepcopy(baseline)
            rebound["artifact"]["bytes"], rebound["artifact"]["sha256"] = validate.artifact_digest(copied_root)
            with self.assertRaises(validate.ValidationError):
                validate.validate_baseline(rebound, copied_root)

    def test_baseline_trace_types_are_exact(self) -> None:
        baseline = validate.load_json(validate.BASELINE_PATH)
        forged = copy.deepcopy(baseline)
        forged["runs"][0]["trace"][0] = 1
        with self.assertRaises(validate.ValidationError):
            validate.validate_baseline(forged)


if __name__ == "__main__":
    unittest.main()
