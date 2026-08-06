"""Regression tests for the synthetic WebSocket-ticket boundary validator."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import validate


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[3]


class WsTicketValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = validate.load_json(validate.FIXTURE_PATH)
        self.baseline = validate.load_json(validate.BASELINE_PATH)

    def test_fixture_and_baseline_validate(self) -> None:
        self.assertEqual(validate.validate_fixture(self.fixture), {"case_count": 21, "state_count": 5})
        self.assertEqual(validate.validate_baseline(self.baseline), {"normal_samples": 30, "optimized_samples": 30})

    def test_ticket_boundary_is_upgrade_only(self) -> None:
        policy = self.fixture["ticket_policy"]
        self.assertEqual(policy["acquisition"]["path"], "/api/auth/ws-ticket")
        self.assertEqual(policy["upgrade"]["path"], "/api/ws")
        self.assertEqual(policy["upgrade"]["query_key"], "ticket")
        self.assertEqual(policy["upgrade"]["rest_ticket_use"], "forbidden")
        self.assertTrue(policy["single_use"])
        self.assertEqual(policy["ttl_seconds"], 30)

    def test_required_denials_and_error_layers_are_present(self) -> None:
        by_id = {item["id"]: item for item in self.fixture["cases"]}
        for case_id in (
            "rest-ticket-query-rejected",
            "rest-ticket-header-rejected",
            "missing-ticket-rejected",
            "malformed-ticket-rejected",
            "expired-ticket-rejected",
            "reused-ticket-rejected",
        ):
            self.assertFalse(by_id[case_id]["expected"]["raw_value_retained"])
        self.assertEqual(by_id["edge-origin-error-distinct"]["expected"]["error_layer"], "edge")
        self.assertEqual(by_id["edge-not-found-error-distinct"]["expected"]["rest_status"], 404)
        self.assertEqual(by_id["upstream-auth-error-distinct"]["expected"]["error_layer"], "upstream")
        self.assertTrue(by_id["upstream-auth-error-distinct"]["expected"]["upstream_called"])
        self.assertEqual(by_id["upstream-handler-error-distinct"]["expected"]["rest_status"], 400)

    def test_expiry_boundary_is_29_fresh_and_30_expired(self) -> None:
        by_id = {item["id"]: item for item in self.fixture["cases"]}
        self.assertEqual(by_id["expiry-boundary-fresh"]["request"]["ticket_age_seconds"], 29)
        self.assertEqual(by_id["expiry-boundary-fresh"]["expected"]["decision"], "allow_upgrade")
        self.assertEqual(by_id["expiry-boundary-expired"]["request"]["ticket_age_seconds"], 30)
        self.assertEqual(by_id["expiry-boundary-expired"]["expected"]["decision"], "deny_upgrade")

    def test_redaction_surfaces_never_retain_raw_value(self) -> None:
        for case in self.fixture["cases"]:
            if case["surface"] in {"history", "logs", "dom"}:
                self.assertFalse(case["expected"]["raw_value_retained"])
        self.assertEqual(self.fixture["redaction"]["max_controlled_error_length"], 240)
        self.assertTrue(self.fixture["redaction"]["no_raw_input_echo"])
        self.assertTrue(self.fixture["redaction"]["no_traceback"])

    def test_source_audit_references_are_checked(self) -> None:
        ids = [item["id"] for item in self.fixture["source_evidence"]]
        self.assertEqual(ids, list(validate.SOURCE_EVIDENCE_IDS))
        self.assertEqual(self.fixture["route_manifest_sha256"], validate.MANIFEST_SHA256)

    def test_semantic_case_mutation_fails_without_digest_check(self) -> None:
        mutated = copy.deepcopy(self.fixture)
        for case in mutated["cases"]:
            if case["id"] == "rest-ticket-query-rejected":
                case["expected"]["decision"] = "allow_rest"
                break
        with self.assertRaises(validate.ContractError):
            validate._validate_fixture_shape(mutated)

    def test_exact_integer_count_rejects_float(self) -> None:
        mutated = copy.deepcopy(self.fixture)
        mutated["counts"]["cases"] = 21.0
        with self.assertRaises(validate.ContractError):
            validate._validate_fixture_shape(mutated)

    def test_duplicate_keys_and_nonfinite_numbers_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            duplicate = Path(directory) / "duplicate.json"
            duplicate.write_text('{"a": 1, "a": 2}', encoding="utf-8")
            with self.assertRaises(validate.ContractError):
                validate.load_json(duplicate)
            nonfinite = Path(directory) / "nonfinite.json"
            nonfinite.write_text('{"a": NaN}', encoding="utf-8")
            with self.assertRaises(validate.ContractError):
                validate.load_json(nonfinite)

    def test_oversized_integer_and_deep_json_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            oversized = Path(directory) / "oversized.json"
            oversized.write_text('{"a": 1' + ("0" * 110) + '}', encoding="utf-8")
            with self.assertRaises(validate.ContractError):
                validate.load_json(oversized)
            deep = Path(directory) / "deep.json"
            deep.write_text("[" * 60 + "0" + "]" * 60, encoding="utf-8")
            with self.assertRaises(validate.ContractError):
                validate.load_json(deep)

    def test_sensitive_key_and_jwt_like_value_fail_closed(self) -> None:
        with self.assertRaises(validate.ContractError):
            validate._scan_redaction({"raw_ticket_value": "not-retained"})
        with self.assertRaises(validate.ContractError):
            validate._scan_redaction({"marker": "abcdefghijk.lmnopqrstuv.wxyz0123456"})

    def test_uniform_fabricated_baseline_fails(self) -> None:
        fabricated = copy.deepcopy(self.baseline)
        samples = [1.0] * 30
        fabricated["observations"]["normal"]["samples_ms"] = samples
        fabricated["observations"]["normal"]["summary"] = {"min": 1.0, "p50": 1.0, "p95": 1.0, "max": 1.0, "mean": 1.0}
        with self.assertRaises(validate.ContractError):
            validate.validate_baseline(fabricated)

    def test_baseline_artifact_manifest_is_bound(self) -> None:
        mutated = copy.deepcopy(self.baseline)
        mutated["integrity"]["artifact_manifest"][0]["sha256"] = "0" * 64
        with self.assertRaises(validate.ContractError):
            validate.validate_baseline(mutated)

    def test_controlled_cli_unknown_flag_normal(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(ROOT / "validate.py"), "--raw-ticket=never-echo"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertNotIn("never-echo", completed.stdout)
        self.assertNotIn("Traceback", completed.stdout)
        payload = json.loads(completed.stdout)
        self.assertFalse(payload["compatible"])
        self.assertFalse(payload["live_run"])
        self.assertLessEqual(len(completed.stdout.strip()), 240)

    def test_controlled_cli_unknown_flag_optimized(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-O", str(ROOT / "validate.py"), "--raw-ticket=never-echo"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertNotIn("never-echo", completed.stdout)
        self.assertNotIn("Traceback", completed.stdout)
        self.assertEqual(json.loads(completed.stdout), json.loads(
            subprocess.run(
                [sys.executable, str(ROOT / "validate.py"), "--raw-ticket=never-echo"],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
            ).stdout
        ))

    def test_malformed_fixture_cli_is_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            malformed = Path(directory) / "bad.json"
            malformed.write_text('{"schema": NaN}', encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(ROOT / "validate.py"), "--fixture", str(malformed)],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 1)
        self.assertNotIn(str(malformed), completed.stdout)
        self.assertNotIn("Traceback", completed.stdout)
        self.assertLessEqual(len(completed.stdout.strip()), 240)


if __name__ == "__main__":
    unittest.main()
