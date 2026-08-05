#!/usr/bin/env python3
"""Regression tests for the offline behavioral-probe fixture contract."""

from __future__ import annotations

import copy
import io
import json
import math
import py_compile
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import validate


FIXTURE_DIR = Path(__file__).resolve().parent
REPO_ROOT = FIXTURE_DIR.parents[2]
FIXTURE_PATH = FIXTURE_DIR / "probe-fixtures.json"
BASELINE_PATH = FIXTURE_DIR / "probe-baseline.json"
README_PATH = FIXTURE_DIR / "README.md"


class BehavioralProbeFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = validate.load_json(FIXTURE_PATH)
        cls.baseline = validate.load_json(BASELINE_PATH)
        validate.validate_all(cls.document, cls.baseline, REPO_ROOT)

    def assert_rejected(self, document: dict[str, object], *, verify_digest: bool = True) -> None:
        with self.assertRaises(validate.ContractError):
            validate.validate_document(document, REPO_ROOT, verify_digest=verify_digest)

    def run_cli(self, optimized: bool = False, *extra: str) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend([str(FIXTURE_DIR / "validate.py"), *extra])
        return subprocess.run(command, check=False, capture_output=True, text=True)

    def test_checked_in_fixture_and_baseline_validate(self) -> None:
        validate.validate_all(self.document, self.baseline, REPO_ROOT)
        self.assertEqual(len(self.document["cases"]), 27)
        self.assertEqual(len(self.document["probe_states"]), 6)
        self.assertEqual(len(self.document["proxy_matrix"]), 4)
        self.assertFalse(self.document["probe"]["live_run"])
        self.assertFalse(self.document["probe"]["compatible"])

    def test_case_inventory_and_order_are_frozen(self) -> None:
        self.assertEqual(
            tuple(case["id"] for case in self.document["cases"]),
            validate.EXPECTED_CASE_IDS,
        )
        self.assertEqual(
            tuple(state["id"] for state in self.document["probe_states"]),
            validate.EXPECTED_STATE_IDS,
        )
        self.assertEqual(
            tuple(pair["id"] for pair in self.document["proxy_matrix"]),
            validate.EXPECTED_PROXY_IDS,
        )
        self.assertEqual(
            tuple(item["id"] for item in self.document["pty_lifecycle"]),
            validate.EXPECTED_LIFECYCLE_IDS,
        )

    def test_required_auth_and_surface_cases_are_present(self) -> None:
        cases = {case["id"]: case for case in self.document["cases"]}
        self.assertEqual(cases["rest-browser-cookie-approved"]["request"]["auth_mode"], "browser_cookie")
        self.assertEqual(cases["rest-native-password-cookie-approved"]["request"]["auth_mode"], "native_password_cookie")
        self.assertEqual(cases["rest-native-oauth-bearer-approved"]["request"]["auth_mode"], "native_oauth_oidc_bearer")
        self.assertEqual(cases["ws-pty-native-denied"]["expected"]["decision"], "deny_default")
        self.assertEqual(cases["rpc-malformed-json-rejected"]["expected"]["warning_payload_policy"], "non_sensitive_marker_capped_at_240_before_retention")
        self.assertEqual(cases["upstream-hermes-400-preserved"]["expected"]["observed_layer"], "upstream")
        self.assertEqual(cases["edge-wrong-public-origin-denied"]["expected"]["observed_layer"], "edge")

    def test_all_run_states_remain_blocked_or_fixture_only(self) -> None:
        states = {state["id"]: state for state in self.document["probe_states"]}
        for state in states.values():
            self.assertIn(state["gate_decision"], {"blocked", "blocked_live_compatibility"})
        self.assertEqual(states["unknown"]["retry_policy"], "reread_source_state_before_retry")
        self.assertEqual(states["cancelled"]["safe_state"], "no_outward_change")
        self.assertEqual(states["success"]["safe_state"], "artifact_only_no_live_claim")

    def test_proxy_and_platform_parity_are_explicitly_not_run(self) -> None:
        self.assertEqual(self.document["proof_run"]["status"], "not_run")
        self.assertEqual(self.document["proof_run"]["attestation_state"], "absent")
        self.assertEqual(self.document["parity"]["status"], "not_run")
        self.assertEqual(self.document["parity"]["platforms"], ["web", "ios", "ipados", "macos"])
        self.assertEqual(self.document["parity"]["pty_policy"], "web_only_apple_blocked")

    def test_duplicate_keys_and_nonfinite_numbers_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            duplicate = Path(directory) / "duplicate.json"
            duplicate.write_text('{"schema":"one","schema":"two"}', encoding="utf-8")
            with self.assertRaises(validate.DuplicateKeyError):
                validate.load_json(duplicate)

            nonfinite = Path(directory) / "nonfinite.json"
            nonfinite.write_text('{"value": NaN}', encoding="utf-8")
            with self.assertRaises(validate.ContractError):
                validate.load_json(nonfinite)

    def test_schema_and_order_mutations_fail_closed(self) -> None:
        mutations = []

        extra_root = copy.deepcopy(self.document)
        extra_root["unexpected"] = True
        mutations.append(extra_root)

        reordered = copy.deepcopy(self.document)
        reordered["cases"].reverse()
        mutations.append(reordered)

        wrong_live_state = copy.deepcopy(self.document)
        wrong_live_state["probe"]["live_run"] = True
        mutations.append(wrong_live_state)

        wrong_digest = copy.deepcopy(self.document)
        wrong_digest["route_manifest_sha256"] = "0" * 64
        mutations.append(wrong_digest)

        wrong_type = copy.deepcopy(self.document)
        wrong_type["probe"]["required_case_count"] = True
        mutations.append(wrong_type)

        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_rejected(mutation)

    def test_case_behavior_digest_blocks_changed_expected_result(self) -> None:
        mutated = copy.deepcopy(self.document)
        mutated["cases"][0]["expected"]["decision"] = "deny_default"
        self.assert_rejected(mutated)

    def test_missing_case_and_duplicate_case_fail_closed(self) -> None:
        missing = copy.deepcopy(self.document)
        missing["cases"].pop()
        self.assert_rejected(missing)

        duplicate = copy.deepcopy(self.document)
        duplicate["cases"][1]["id"] = duplicate["cases"][0]["id"]
        self.assert_rejected(duplicate)

    def test_redaction_rejects_sensitive_keys_and_credential_shapes(self) -> None:
        for value in (
            {"raw_ticket": "not allowed"},
            {"authorization": "not allowed"},
            {"value": "Bearer synthetic-secret-value"},
            {"value": "ghp_synthetic_secret"},
        ):
            with self.subTest(value=value):
                with self.assertRaises(validate.ContractError):
                    validate._validate_redaction(value)

        self.assertFalse(self.document["redaction"]["contains_credentials"])
        self.assertFalse(self.document["redaction"]["contains_ticket_values"])

    def test_baseline_is_measured_and_has_no_threshold(self) -> None:
        self.assertEqual(self.baseline["threshold"], None)
        self.assertEqual(self.baseline["normal"]["repetitions"], 30)
        self.assertEqual(self.baseline["optimized"]["repetitions"], 30)
        for mode in ("normal", "optimized"):
            samples = self.baseline[mode]["samples_ms"]
            self.assertEqual(len(samples), 30)
            self.assertTrue(all(math.isfinite(value) and value >= 0 for value in samples))
            self.assertLessEqual(
                self.baseline[mode]["distribution_ms"]["min"],
                self.baseline[mode]["distribution_ms"]["p95"],
            )

    def test_accessibility_and_redaction_scope_are_recorded(self) -> None:
        readme = " ".join(README_PATH.read_text(encoding="utf-8").split())
        for marker in (
            "## Accessibility and Paper applicability",
            "non-UI protocol fixture",
            "later web and Apple clients must preserve",
            "## Measured baseline evidence",
            "threshold` is `null`",
            "does not start Hermes",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, readme)
        validate._validate_text_redaction(README_PATH)

    def test_cli_success_is_structured_and_still_blocked(self) -> None:
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                completed = self.run_cli(optimized)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stderr, "")
                result = json.loads(completed.stdout)
                self.assertTrue(result["ok"])
                self.assertFalse(result["compatible"])
                self.assertFalse(result["live_run"])
                self.assertEqual(result["case_count"], 27)

    def test_cli_malformed_fixture_emits_one_safe_error_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            malformed = Path(directory) / "malformed.json"
            malformed.write_text("{not-json", encoding="utf-8")
            for optimized in (False, True):
                with self.subTest(optimized=optimized):
                    completed = self.run_cli(
                        optimized,
                        "--fixtures",
                        str(malformed),
                        "--baseline",
                        str(BASELINE_PATH),
                    )
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertEqual(completed.stderr, "")
                    self.assertNotIn("Traceback", completed.stdout)
                    result = json.loads(completed.stdout)
                    self.assertFalse(result["ok"])
                    self.assertFalse(result["compatible"])
                    self.assertEqual(result["error"]["code"], "behavioral_probe_fixture_invalid")

    def test_compile_and_unittest_paths_are_explicit(self) -> None:
        py_compile.compile(str(FIXTURE_DIR / "validate.py"), doraise=True)
        py_compile.compile(str(FIXTURE_DIR / "test_validate.py"), doraise=True)

    def test_source_pin_and_route_manifest_binding_are_exact(self) -> None:
        self.assertEqual(self.document["hermes_source_sha"], validate.HERMES_SOURCE_SHA)
        self.assertEqual(self.document["route_manifest"], validate.ROUTE_MANIFEST)
        self.assertEqual(self.document["route_manifest_sha256"], validate.ROUTE_MANIFEST_SHA256)
        self.assertEqual(len(validate.ROUTE_MANIFEST_SHA256), 64)


if __name__ == "__main__":
    unittest.main(verbosity=2)
