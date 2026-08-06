#!/usr/bin/env python3
"""Regression tests for the synthetic browser-authentication boundary.

The tests use only the checked-in synthetic fixture and Python's standard
library.  They do not import Hermes, start a browser, open a socket, or call a
provider.
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


FIXTURE_DIR = Path(__file__).resolve().parent
if str(FIXTURE_DIR) not in sys.path:
    sys.path.insert(0, str(FIXTURE_DIR))

import validate  # noqa: E402


class BrowserAuthBoundaryTests(unittest.TestCase):
    """Keep the closed schema, model, and fail-closed regressions aligned."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.document = validate.load_json(validate.CASES_PATH)
        validate.validate_redaction(cls.document)
        validate.validate_cases_document(cls.document)
        cls.cases = {case["id"]: case for case in cls.document["cases"]}

    def _run_cli(self, content: bytes, optimized: bool = False) -> subprocess.CompletedProcess[str]:
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

    def test_invalid_cli_arguments_are_one_bounded_redacted_json_error(self) -> None:
        for optimized in (False, True):
            for argument, secret in (
                ("--token=synthetic-secret", "synthetic-secret"),
                ("--unknown=untrusted-value", "untrusted-value"),
            ):
                with self.subTest(optimized=optimized, argument=argument):
                    command = [sys.executable]
                    if optimized:
                        command.append("-O")
                    command.extend([str(FIXTURE_DIR / "validate.py"), argument])
                    completed = subprocess.run(command, check=False, capture_output=True, text=True)
                    self.assertEqual(completed.returncode, 2)
                    self.assertEqual(completed.stderr, "")
                    lines = [line for line in completed.stdout.splitlines() if line.strip()]
                    self.assertEqual(len(lines), 1)
                    payload = json.loads(lines[0])
                    self.assertFalse(payload["ok"])
                    self.assertEqual(payload["error"]["code"], validate.ERROR_CODE)
                    self.assertNotIn(secret, completed.stdout)
                    self.assertNotIn("usage:", completed.stdout.lower())
                    self.assertLessEqual(len(completed.stdout), validate.MAX_ERROR_OUTPUT + 128)

    def test_checked_in_fixture_has_expected_case_order(self) -> None:
        self.assertEqual(tuple(self.cases), validate.EXPECTED_CASE_IDS)
        self.assertEqual(len(self.cases), 21)

    def test_every_case_matches_independent_boundary_model(self) -> None:
        for case in self.document["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(validate.evaluate_case(case), case["expected"])

    def test_baseline_has_two_30_run_traces_and_no_threshold(self) -> None:
        baseline = validate.load_json(validate.BASELINE_PATH)
        validate.validate_redaction(baseline)
        validate.validate_baseline(baseline)
        self.assertEqual(baseline["threshold"], None)
        self.assertEqual([run["repetitions"] for run in baseline["runs"]], [30, 30])

    def test_baseline_recomputes_distributions_and_binds_commands(self) -> None:
        baseline = validate.load_json(validate.BASELINE_PATH)
        forged_distribution = copy.deepcopy(baseline)
        forged_distribution["runs"][0]["distribution"]["p50_ms"] += 1
        with self.assertRaises(validate.ValidationError):
            validate.validate_baseline(forged_distribution)
        forged_command = copy.deepcopy(baseline)
        forged_command["runs"][1]["command"] = "echo fabricated"
        with self.assertRaises(validate.ValidationError):
            validate.validate_baseline(forged_command)

    def test_provider_discovery_is_synthetic_and_filters_non_session_entries(self) -> None:
        self.assertEqual(self.cases["provider-discovery"]["expected"]["providers"], ["synthetic-browser"])
        self.assertEqual(
            self.cases["provider-discovery-filters-non-session"]["expected"]["providers"],
            ["synthetic-browser"],
        )
        self.assertEqual(self.cases["provider-discovery-empty"]["expected"]["status"], 503)

    def test_cookie_values_are_symbolic_only(self) -> None:
        allowed = validate.COOKIE_STATES
        for case in self.document["cases"]:
            values = case["input"].get("cookies")
            if values is None:
                continue
            for key, value in values.items():
                with self.subTest(case=case["id"], cookie=key):
                    self.assertIn(value, allowed)
                    self.assertNotIn("=", value)
                    self.assertNotIn(".", value)

    def test_login_logout_and_expiry_transitions(self) -> None:
        success = self.cases["login-success"]["expected"]
        self.assertEqual(success["state"], "authenticated")
        self.assertEqual(success["session_cookie"], "present")
        self.assertEqual(success["cookie_cleanup"], "clear_ephemeral")
        logout = self.cases["logout-success"]["expected"]
        self.assertEqual(logout["state"], "signed_out")
        self.assertEqual(logout["session_cookie"], "absent")
        expiry = self.cases["restore-expired-session"]["expected"]
        self.assertEqual(expiry["reason"], "session_expired")
        self.assertEqual(expiry["cookie_cleanup"], "clear_session")

    def test_wrong_origin_fails_before_callback_exchange(self) -> None:
        result = self.cases["wrong-origin"]["expected"]
        self.assertEqual(result["reason"], "wrong_origin")
        self.assertEqual(result["provider_exchange"], "not_called")
        self.assertEqual(result["session_cookie"], "absent")

    def test_arbitrary_return_targets_fail_closed(self) -> None:
        external = self.cases["external-return-target"]["expected"]
        traversal = self.cases["traversal-return-target"]["expected"]
        self.assertEqual(external["reason"], "external_return_target")
        self.assertEqual(traversal["reason"], "return_target_traversal")
        self.assertIsNone(external["redirect"])
        self.assertIsNone(traversal["redirect"])

    def test_storage_denial_is_controlled(self) -> None:
        result = self.cases["storage-denied"]["expected"]
        self.assertEqual(result["status"], 503)
        self.assertEqual(result["reason"], "storage_denied")
        self.assertEqual(result["state"], "blocked")
        self.assertEqual(result["provider_exchange"], "not_called")

    def test_cancellation_preserves_last_verified_state_without_side_effects(self) -> None:
        case = self.cases["interruption-cancelled"]
        result = case["expected"]
        self.assertEqual(validate.evaluate_case(case), result)
        self.assertEqual(result["state"], "authenticated")
        self.assertEqual(result["session_cookie"], "present")
        self.assertIsNone(result["redirect"])
        self.assertEqual(result["provider_exchange"], "not_called")
        self.assertEqual(result["diagnostic"], "cancellation preserved last verified state; no new side effects")

    def test_retry_rereads_stale_source_and_does_not_duplicate_side_effects(self) -> None:
        case = self.cases["retry-source-reread"]
        result = case["expected"]
        self.assertEqual(validate.evaluate_case(case), result)
        self.assertEqual(case["input"]["source_before"], "stale")
        self.assertEqual(case["input"]["source_after_reread"], "verified")
        self.assertEqual(result["reason"], "retry_source_reread")
        self.assertEqual(result["provider_exchange"], "not_called")
        self.assertEqual(result["session_cookie"], "present")
        self.assertIsNone(result["redirect"])
        self.assertEqual(
            result["diagnostic"],
            "retry reread source; no duplicate provider, session, or outward side effects",
        )

    def test_retry_rejects_non_idempotent_callback_before_side_effects(self) -> None:
        result = self.cases["retry-non-idempotent"]["expected"]
        self.assertEqual(result["status"], 409)
        self.assertEqual(result["reason"], "retry_not_idempotent")
        self.assertEqual(result["provider_exchange"], "not_called")
        self.assertEqual(result["session_cookie"], "absent")
        self.assertIsNone(result["redirect"])

    def test_retry_rejects_unverified_reread(self) -> None:
        mutated = copy.deepcopy(self.cases["retry-source-reread"])
        mutated["input"]["source_after_reread"] = "changed"
        result = validate.evaluate_case(mutated)
        self.assertEqual(result["status"], 409)
        self.assertEqual(result["reason"], "source_reread_unverified")
        self.assertEqual(result["provider_exchange"], "not_called")
        self.assertEqual(result["session_cookie"], "absent")

    def test_redaction_covers_assignment_shaped_diagnostics(self) -> None:
        message = (
            "authorization=Bearer synthetic-bearer password=synthetic-password "
            "token='synthetic-token' cookie=rawcookie ticket=rawticket csrf=rawcsrf "
            "session=rawsession state=rawstate pkce_verifier=rawpkce"
        )
        redacted = validate.compact_error(message)
        self.assertIn("[REDACTED]", redacted)
        for secret in (
            "synthetic-bearer",
            "synthetic-password",
            "synthetic-token",
            "rawcookie",
            "rawticket",
            "rawcsrf",
            "rawsession",
            "rawstate",
            "rawpkce",
        ):
            self.assertNotIn(secret, redacted)
        self.assertLessEqual(len(redacted), validate.MAX_ERROR_OUTPUT)

    def test_redaction_rejects_sensitive_fixture_field(self) -> None:
        mutated = copy.deepcopy(self.document)
        mutated["cases"][0]["input"]["password"] = "synthetic-marker"
        with self.assertRaises(validate.ValidationError):
            validate.validate_redaction(mutated)

    def test_unknown_keys_and_boolean_statuses_fail_closed(self) -> None:
        unknown = copy.deepcopy(self.document)
        unknown["cases"][0]["expected"]["unexpected"] = "no"
        with self.assertRaises(validate.ValidationError):
            validate.validate_cases_document(unknown)
        boolean_status = copy.deepcopy(self.document)
        boolean_status["cases"][0]["expected"]["status"] = True
        with self.assertRaises(validate.ValidationError):
            validate.validate_cases_document(boolean_status)

    def test_outcome_mutation_is_detected_even_when_well_typed(self) -> None:
        mutated = copy.deepcopy(self.document)
        mutated["cases"][4]["expected"]["reason"] = "provider_discovered"
        with self.assertRaises(validate.ValidationError):
            validate.validate_cases_document(mutated)

    def test_duplicate_keys_are_rejected_without_echoing_attacker_key(self) -> None:
        huge_key = "attacker-" + ("x" * 1000)
        content = ("{\"" + huge_key + "\":1,\"" + huge_key + "\":2}").encode()
        self._assert_cli_failure(content)
        completed = self._run_cli(content)
        self.assertNotIn(huge_key, completed.stdout)

    def test_nonfinite_numbers_are_rejected(self) -> None:
        self._assert_cli_failure(b'{"value":NaN}')
        self._assert_cli_failure(b'{"value":1e9999}')

    def test_oversized_integer_is_rejected_without_float_conversion(self) -> None:
        oversized = b'{"value":' + (b"9" * (validate.MAX_JSON_INTEGER_DIGITS + 1)) + b"}"
        self._assert_cli_failure(oversized)

    def test_excessive_nesting_is_rejected_before_parser_recursion(self) -> None:
        nested = (b"[" * (validate.MAX_JSON_DEPTH + 1)) + (b"]" * (validate.MAX_JSON_DEPTH + 1))
        self._assert_cli_failure(nested)

    def test_malformed_json_is_one_controlled_error(self) -> None:
        self._assert_cli_failure(b'{"schema":')

    def test_normal_and_optimized_cli_keep_validation_active(self) -> None:
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                command = [sys.executable]
                if optimized:
                    command.append("-O")
                command.extend([str(FIXTURE_DIR / "validate.py"), "--skip-baseline"])
                completed = subprocess.run(command, check=False, capture_output=True, text=True)
                self.assertEqual(completed.returncode, 0)
                self.assertEqual(completed.stderr, "")
                payload = json.loads(completed.stdout)
                self.assertTrue(payload["ok"])
                self.assertEqual(payload["cases"], 21)
                self.assertIsNone(payload["threshold"])

    def test_only_standard_library_boundary_module_is_used(self) -> None:
        source = (FIXTURE_DIR / "validate.py").read_text(encoding="utf-8")
        self.assertNotIn("import requests", source)
        self.assertNotIn("import urllib", source)
        self.assertNotIn("import socket", source)
        self.assertNotIn("import hermes", source.lower())


if __name__ == "__main__":
    unittest.main()
