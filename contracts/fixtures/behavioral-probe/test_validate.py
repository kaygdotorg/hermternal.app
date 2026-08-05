#!/usr/bin/env python3
"""Regression tests for the offline behavioral-probe fixture contract."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import py_compile
import subprocess
import sys
import tempfile
import unittest
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
        self.assertEqual(len(self.document["cases"]), 64)
        self.assertEqual(len(self.document["probe_states"]), 6)
        self.assertEqual(len(self.document["proxy_matrix"]), 5)
        self.assertEqual(len(self.document["pty_lifecycle"]), 3)
        self.assertFalse(self.document["probe"]["live_run"])
        self.assertFalse(self.document["probe"]["compatible"])
        self.assertEqual(self.document["proof_run"]["status"], "synthetic_observed")
        self.assertEqual(self.document["parity"]["status"], "synthetic_observed")

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

    def test_required_auth_provider_and_surface_cases_are_present(self) -> None:
        cases = {case["id"]: case for case in self.document["cases"]}
        self.assertEqual(cases["rest-browser-cookie-approved"]["request"]["auth_mode"], "browser_cookie")
        self.assertEqual(cases["rest-native-password-cookie-approved"]["request"]["auth_mode"], "native_password_cookie")
        self.assertEqual(cases["rest-native-oauth-bearer-approved"]["request"]["auth_mode"], "native_oauth_oidc_bearer")
        self.assertEqual(cases["rest-provider-discovery-approved"]["request"]["path"], "/api/auth/providers")
        self.assertEqual(cases["rest-password-login-approved"]["request"]["path"], "/auth/password-login")
        self.assertEqual(cases["rest-ws-ticket-password-cookie-approved"]["request"]["path"], "/api/auth/ws-ticket")
        self.assertEqual(cases["rest-native-authorize-reviewed"]["request"]["path"], "/auth/native/authorize")
        self.assertEqual(cases["rest-native-token-reviewed"]["request"]["path"], "/auth/native/token")
        self.assertEqual(cases["rest-native-refresh-reviewed"]["request"]["path"], "/auth/native/refresh")
        self.assertEqual(cases["ws-pty-native-denied"]["expected"]["decision"], "deny_default")
        self.assertEqual(cases["rpc-malformed-json-rejected"]["expected"]["warning_payload_policy"], "non_sensitive_marker_capped_at_240_before_retention")
        self.assertEqual(cases["upstream-hermes-400-preserved"]["expected"]["observed_layer"], "upstream")
        self.assertEqual(cases["edge-wrong-public-origin-denied"]["expected"]["observed_layer"], "edge")
        self.assertEqual(cases["edge-unknown-path-404"]["expected"]["http_status"], 404)

    def test_all_run_states_remain_blocked_or_fixture_only(self) -> None:
        states = {state["id"]: state for state in self.document["probe_states"]}
        for state in states.values():
            self.assertIn(state["gate_decision"], {"blocked", "blocked_live_compatibility"})
        self.assertEqual(states["unknown"]["retry_policy"], "reread_source_state_before_retry")
        self.assertEqual(states["cancelled"]["safe_state"], "no_outward_change")
        self.assertEqual(states["success"]["safe_state"], "artifact_only_no_live_claim")

    def test_synthetic_observations_are_explicit_and_never_live(self) -> None:
        self.assertEqual(
            tuple(item["id"] for item in self.document["attestation_observations"]),
            ("attestation-pinned-match", "attestation-source-mismatch"),
        )
        self.assertEqual(len(self.document["proxy_observations"]), 4)
        self.assertEqual(
            tuple(item["platform"] for item in self.document["platform_observations"]),
            ("web", "ios", "ipados", "macos"),
        )
        for inventory_name in ("attestation_observations", "proxy_observations", "platform_observations"):
            self.assertTrue(all(item["live_claim"] is False for item in self.document[inventory_name]))
        self.assertFalse(self.document["probe"]["live_run"])
        self.assertFalse(self.document["probe"]["compatible"])
        self.assertEqual(self.document["proof_run"]["live_result"], "not_recorded")

    def test_proxy_platform_and_lifecycle_parity_are_explicit(self) -> None:
        self.assertEqual(self.document["proof_run"]["proxy_variants"], ["caddy", "traefik"])
        self.assertEqual(self.document["parity"]["platforms"], ["web", "ios", "ipados", "macos"])
        self.assertEqual(self.document["parity"]["pty_policy"], "web_only_apple_blocked")
        self.assertEqual(
            self.document["pty_lifecycle"][2]["expected"],
            "eventual_ttl_reap_without_immediate_kill_or_replay_guarantee",
        )

    def test_websocket_headers_and_exact_ticket_lifetime_are_frozen(self) -> None:
        cases = {case["id"]: case for case in self.document["cases"]}
        for case_id in (
            "ws-chat-browser-fresh-ticket-approved",
            "ws-chat-native-fresh-ticket-approved",
            "ws-pty-browser-fresh-ticket-approved",
            "ws-pty-wsl-fresh-ticket-approved",
        ):
            case = cases[case_id]
            self.assertEqual(case["request"]["upgrade_header"], "websocket")
            self.assertEqual(case["request"]["connection_header"], "upgrade")
            self.assertEqual(case["expected"]["ticket_ttl_seconds"], 30)
        chat_missing = cases["ws-chat-missing-upgrade-denied"]
        self.assertIsNone(chat_missing["request"]["upgrade_header"])
        self.assertEqual(chat_missing["request"]["connection_header"], "upgrade")
        self.assertEqual(chat_missing["expected"]["upgrade_auth"], "missing_http_upgrade_headers")
        self.assertIsNone(chat_missing["expected"]["ticket_ttl_seconds"])

        pty_missing = cases["ws-pty-missing-upgrade-denied"]
        self.assertEqual(pty_missing["request"]["upgrade_header"], "websocket")
        self.assertIsNone(pty_missing["request"]["connection_header"])
        self.assertEqual(pty_missing["expected"]["upgrade_auth"], "missing_http_upgrade_headers")
        self.assertIsNone(pty_missing["expected"]["ticket_ttl_seconds"])
        for case_id in ("ws-chat-malformed-ticket-denied", "ws-pty-malformed-ticket-denied"):
            self.assertEqual(cases[case_id]["expected"]["upgrade_auth"], "ticket_malformed")

    def test_malformed_input_inventory_is_complete(self) -> None:
        cases = {case["id"]: case for case in self.document["cases"]}
        expected = {
            "rpc-duplicate-key-rejected": "duplicate_key",
            "rpc-wrong-top-level-rejected": "wrong_top_level",
            "rpc-invalid-utf8-rejected": "invalid_utf8",
            "rpc-syntax-error-rejected": "syntax_error",
            "rpc-oversized-integer-rejected": "oversized_integer",
            "rpc-deep-nesting-rejected": "deep_nesting",
            "rpc-secret-shaped-huge-key-rejected": "secret_shaped_huge_key",
        }
        for case_id, input_state in expected.items():
            with self.subTest(case_id=case_id):
                self.assertEqual(cases[case_id]["kind"], "malformed_input")
                self.assertEqual(cases[case_id]["request"]["input_state"], input_state)
                self.assertEqual(cases[case_id]["expected"]["decision"], "reject_without_traceback")

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

        for mutation in mutations:
            with self.subTest(mutation_type=type(mutation)):
                self.assert_rejected(mutation)

    def test_required_counts_are_exact_json_integers_even_without_digest(self) -> None:
        for field, value in (
            ("required_case_count", 64.0),
            ("required_state_count", True),
            ("required_lifecycle_count", "3"),
            ("required_proxy_pair_count", 5.0),
        ):
            mutated = copy.deepcopy(self.document)
            mutated["probe"][field] = value
            with self.subTest(field=field, value=value):
                self.assert_rejected(mutated, verify_digest=False)

    def test_non_object_inventory_entries_fail_without_attribute_errors(self) -> None:
        for inventory_name in ("proxy_matrix", "probe_states", "pty_lifecycle"):
            for bad_entry in (None, "not-an-object", 7, []):
                mutated = copy.deepcopy(self.document)
                mutated[inventory_name][0] = bad_entry
                with self.subTest(inventory=inventory_name, bad_entry=bad_entry):
                    with self.assertRaises(validate.ContractError) as caught:
                        validate.validate_document(mutated, REPO_ROOT, verify_digest=False)
                    self.assertEqual(str(caught.exception), validate.SAFE_ERROR_MESSAGE)

    def test_case_behavior_digest_and_semantic_inventory_block_changed_result(self) -> None:
        mutated = copy.deepcopy(self.document)
        mutated["cases"][0]["expected"]["decision"] = "deny_default"
        self.assert_rejected(mutated)
        self.assert_rejected(mutated, verify_digest=False)

    def test_missing_case_and_duplicate_case_fail_closed(self) -> None:
        missing = copy.deepcopy(self.document)
        missing["cases"].pop()
        self.assert_rejected(missing)

        duplicate = copy.deepcopy(self.document)
        duplicate["cases"][1]["id"] = duplicate["cases"][0]["id"]
        self.assert_rejected(duplicate)

    def test_redaction_rejects_sensitive_aliases_and_nested_credential_shapes(self) -> None:
        for value in (
            {"raw_ticket": "not allowed"},
            {"ticket-fragment": "not allowed"},
            {"prompt.text": "not allowed"},
            {"authorizationHeader": "not allowed"},
            {"ptyOutput": "not allowed"},
            {"refreshToken": "not allowed"},
            {"attach:handle": "not allowed"},
            {"authorization-headers": "not allowed"},
            {"prompt_texts": "not allowed"},
            {"value": "Bearer synthetic-secret-value"},
            {"value": "ghp_synthetic_secret"},
            {"nested": ["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature-value"]},
            {"nested": ["generic-header-segment.generic-payload-segment.generic-signature"]},
        ):
            with self.subTest(value=value):
                with self.assertRaises(validate.ContractError):
                    validate._validate_redaction(value)

        self.assertFalse(self.document["redaction"]["contains_credentials"])
        self.assertFalse(self.document["redaction"]["contains_ticket_values"])

    def test_warning_source_is_executable_bounded_and_redacted(self) -> None:
        self.assertEqual(validate.validate_warning_source("x" * 240), "x" * 240)
        for source in (
            "x" * 241,
            "Bearer synthetic-secret-value-1234567890",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature-value",
        ):
            with self.subTest(source_prefix=source[:12]):
                with self.assertRaises(validate.ContractError):
                    validate.validate_warning_source(source)

    def test_json_integer_depth_and_overflow_guards_are_controlled(self) -> None:
        with self.assertRaises(validate.ContractError):
            validate._validate_json_tree(10**309)
        self.assertFalse(validate._finite_nonnegative_number(10**309))
        with tempfile.TemporaryDirectory() as directory:
            oversized = Path(directory) / "oversized.json"
            oversized.write_text('{"value": ' + ("9" * 309) + "}", encoding="utf-8")
            with self.assertRaises(validate.ContractError):
                validate.load_json(oversized)

        nested: object = None
        for _ in range(validate.MAX_JSON_DEPTH + 2):
            nested = [nested]
        with self.assertRaises(validate.ContractError):
            validate._validate_json_tree(nested)

    def test_error_output_does_not_amplify_duplicate_keys_or_deep_paths(self) -> None:
        huge_key = "secret-shaped-" + ("x" * 1_000_000)
        with tempfile.TemporaryDirectory() as directory:
            duplicate = Path(directory) / "duplicate-huge-key.json"
            duplicate.write_text(
                "{" + json.dumps(huge_key) + ":1," + json.dumps(huge_key) + ":2}",
                encoding="utf-8",
            )
            for optimized in (False, True):
                with self.subTest(optimized=optimized):
                    completed = self.run_cli(optimized, "--fixtures", str(duplicate))
                    self.assertEqual(completed.returncode, 1)
                    self.assertEqual(completed.stderr, "")
                    self.assertEqual(len(completed.stdout.splitlines()), 1)
                    self.assertLessEqual(len(completed.stdout), validate.WARNING_MAX_LENGTH)
                    self.assertNotIn(huge_key, completed.stdout)
                    self.assertNotIn("Traceback", completed.stdout)

        mutated = copy.deepcopy(self.document)
        mutated["cases"][0]["request"][huge_key] = "value"
        with self.assertRaises(validate.ContractError) as caught:
            validate.validate_document(mutated, REPO_ROOT, verify_digest=False)
        self.assertEqual(str(caught.exception), validate.SAFE_ERROR_MESSAGE)
        self.assertNotIn(huge_key, str(caught.exception))

    def test_baseline_is_measured_bound_and_has_no_threshold(self) -> None:
        self.assertEqual(self.baseline["threshold"], None)
        self.assertEqual(self.baseline["normal"]["repetitions"], 30)
        self.assertEqual(self.baseline["optimized"]["repetitions"], 30)
        integrity = self.baseline["integrity"]
        self.assertEqual(integrity["reviewed_commit"], validate.EXPECTED_REVIEWED_COMMIT)
        self.assertEqual(integrity["evidence_mode"], "worktree_recomputed")
        self.assertFalse(integrity["immutable_evidence"])
        self.assertRegex(integrity["canonical_baseline_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(integrity["canonical_baseline_size_bytes"], len(validate._baseline_canonical_bytes(self.baseline)))
        self.assertEqual(integrity["baseline_file_size_bytes"], BASELINE_PATH.stat().st_size)
        self.assertEqual(len(integrity["artifact_manifest"]), 4)
        for mode in ("normal", "optimized"):
            samples = self.baseline[mode]["samples_ms"]
            self.assertEqual(len(samples), 30)
            self.assertTrue(all(math.isfinite(value) and value >= 0 for value in samples))
            distribution = self.baseline[mode]["distribution_ms"]
            self.assertLessEqual(distribution["min"], distribution["p50"])
            self.assertLessEqual(distribution["p50"], distribution["p95"])
            self.assertLessEqual(distribution["p95"], distribution["max"])

    def test_fabricated_internally_consistent_baseline_is_not_reviewed_evidence(self) -> None:
        mutated = copy.deepcopy(self.baseline)
        for mode in ("normal", "optimized"):
            mutated[mode]["samples_ms"] = [1.0] * validate.BASELINE_REPETITIONS
            mutated[mode]["distribution_ms"] = {
                "min": 1.0,
                "p50": 1.0,
                "p95": 1.0,
                "max": 1.0,
                "mean": 1.0,
            }
        canonical = validate._baseline_canonical_bytes(mutated)
        mutated["integrity"]["canonical_baseline_sha256"] = hashlib.sha256(canonical).hexdigest()
        mutated["integrity"]["canonical_baseline_size_bytes"] = len(canonical)
        with self.assertRaises(validate.ContractError):
            validate.validate_baseline(mutated, REPO_ROOT)

    def test_artifact_manifest_mutations_fail_closed(self) -> None:
        for field in ("sha256", "size_bytes"):
            mutated = copy.deepcopy(self.baseline)
            if field == "sha256":
                mutated["integrity"]["artifact_manifest"][0][field] = "0" * 64
            else:
                mutated["integrity"]["artifact_manifest"][0][field] += 1
            with self.subTest(field=field):
                with self.assertRaises(validate.ContractError):
                    validate.validate_baseline(mutated, REPO_ROOT)

    def test_accessibility_and_redaction_scope_are_recorded(self) -> None:
        readme = " ".join(README_PATH.read_text(encoding="utf-8").split())
        for marker in (
            "## Accessibility and Paper applicability",
            "non-UI protocol fixture",
            "later web and Apple clients must preserve",
            "## Measured baseline evidence",
            "evidence_mode: \"worktree_recomputed\"",
            "immutable_evidence: false",
            "threshold` is `null",
            "does not start Hermes",
            "30-second ticket time-to-live",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, readme)
        validate._validate_text_redaction(README_PATH)

    def test_cli_unknown_flag_emits_one_safe_syntax_error_in_both_modes(self) -> None:
        raw = "--unknown-flag=synthetic-secret-value"
        outputs = []
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                completed = self.run_cli(optimized, raw)
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stderr, "")
                self.assertEqual(len(completed.stdout.splitlines()), 1)
                result = json.loads(completed.stdout)
                self.assertFalse(result["ok"])
                self.assertFalse(result["compatible"])
                self.assertFalse(result["live_run"])
                self.assertEqual(result["error"]["code"], "behavioral_probe_cli_invalid")
                self.assertNotIn(raw, completed.stdout)
                self.assertNotIn("synthetic-secret-value", completed.stdout)
                self.assertLessEqual(len(completed.stdout), validate.WARNING_MAX_LENGTH)
                outputs.append(completed.stdout)
        self.assertEqual(outputs[0], outputs[1])

    def test_cli_success_is_structured_and_still_blocked(self) -> None:
        outputs = []
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                completed = self.run_cli(optimized)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stderr, "")
                self.assertEqual(len(completed.stdout.splitlines()), 1)
                result = json.loads(completed.stdout)
                self.assertTrue(result["ok"])
                self.assertFalse(result["compatible"])
                self.assertFalse(result["live_run"])
                self.assertEqual(result["case_count"], 64)
                self.assertEqual(result["state_count"], 6)
                self.assertEqual(result["proxy_pair_count"], 5)
                outputs.append(result)
        self.assertEqual(outputs[0], outputs[1])

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
                    self.assertEqual(completed.returncode, 1)
                    self.assertEqual(completed.stderr, "")
                    self.assertEqual(len(completed.stdout.splitlines()), 1)
                    self.assertNotIn("Traceback", completed.stdout)
                    result = json.loads(completed.stdout)
                    self.assertFalse(result["ok"])
                    self.assertFalse(result["compatible"])
                    self.assertFalse(result["live_run"])
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
