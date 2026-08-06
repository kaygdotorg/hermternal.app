#!/usr/bin/env python3
"""Regression tests for the offline native password-provider fixture."""

from __future__ import annotations

import copy
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path

import validate


class NativePasswordProviderFixtureTests(unittest.TestCase):
    def test_fixture_and_mutation_matrix(self) -> None:
        audit = validate.load_json("source_audit.json")
        cases = validate.load_json("cases.json")
        validate.validate_source_provenance(audit)
        self.assertEqual(validate.validate_cases(cases), 26)
        self.assertEqual(validate.validate_mutation_regressions(audit, cases), 10)

    def test_cli_reports_offline_success(self) -> None:
        result = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("validate.py"))],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("native password-provider audit valid:", result.stdout)
        self.assertIn("cases=26", result.stdout)
        self.assertIn("provenance=metadata_only", result.stdout)

    def test_duplicate_json_keys_fail_without_echoing_key(self) -> None:
        with self.assertRaises(validate.DuplicateKeyError) as caught:
            json.loads(
                '{"safe": 1, "' + ("x" * 2000) + '": 2, "' + ("x" * 2000) + '": 3}',
                object_pairs_hook=validate._object_without_duplicate_keys,
            )
        self.assertEqual(str(caught.exception), "duplicate JSON object key is not allowed")

    def test_nonfinite_json_number_fails_at_parser_boundary(self) -> None:
        overflow = json.loads('{"value": 1e9999}')
        with self.assertRaises(validate.ValidationError):
            validate._scan_json(overflow)
        with self.assertRaises(validate.ValidationError):
            json.loads('{"value": NaN}', parse_constant=validate._reject_constant)

    def test_bounded_reader_rejects_oversized_input(self) -> None:
        stream = io.BytesIO(b"{" + b"a" * validate.MAX_JSON_BYTES + b"}")
        with self.assertRaises(validate.ValidationError):
            validate._read_bounded_stream(stream, "synthetic")

    def test_integer_limit_and_recursive_node_limit(self) -> None:
        with self.assertRaises(validate.ValidationError):
            json.loads(
                '{"value": ' + ("9" * (validate.MAX_INTEGER_BITS + 1)) + "}",
                parse_int=validate._bounded_int,
            )
        with self.assertRaises(validate.ValidationError):
            validate._scan_json([[]] * (validate.MAX_JSON_NODES + 1))

    def test_wrong_password_cannot_become_success(self) -> None:
        cases = validate.load_json("cases.json")
        mutated = copy.deepcopy(cases)
        case = next(item for item in mutated["cases"] if item["id"] == "login-wrong-password")
        case["expected"]["http_status"] = 200
        with self.assertRaises(validate.ValidationError):
            validate.validate_cases(mutated)

    def test_shared_browser_store_cannot_become_allowed(self) -> None:
        cases = validate.load_json("cases.json")
        mutated = copy.deepcopy(cases)
        case = next(item for item in mutated["cases"] if item["id"] == "cookie-app-isolated-store")
        case["expected"]["shared_browser_store_used"] = True
        with self.assertRaises(validate.ValidationError):
            validate.validate_cases(mutated)

    def test_ticket_failures_are_not_acceptance_paths(self) -> None:
        cases = validate.load_json("cases.json")
        for case_id in (
            "native-ws-malformed-ticket-denied",
            "native-ws-expired-ticket-denied",
            "native-ws-reused-ticket-denied",
        ):
            mutated = copy.deepcopy(cases)
            case = next(item for item in mutated["cases"] if item["id"] == case_id)
            case["expected"]["decision"] = "accept"
            with self.assertRaises(validate.ValidationError):
                validate.validate_cases(mutated)

    def test_sensitive_field_names_are_rejected(self) -> None:
        with self.assertRaises(validate.ValidationError):
            validate.validate_synthetic_keys({"raw_ticket": "synthetic"})
        with self.assertRaises(validate.ValidationError):
            validate.validate_synthetic_keys({"password": "synthetic"})
        validate.validate_synthetic_keys({"password": False})

    def test_source_digest_and_marker_mutations_fail_closed(self) -> None:
        audit = validate.load_json("source_audit.json")
        digest_mutation = copy.deepcopy(audit)
        digest_mutation["source_provenance"]["files"][0]["sha256"] = "0" * 64
        with self.assertRaises(validate.ValidationError):
            validate.validate_source_provenance(digest_mutation)

        marker_mutation = copy.deepcopy(audit)
        marker_mutation["source_evidence"][0]["marker"] = "supports_password = False"
        with self.assertRaises(validate.ValidationError):
            validate.validate_source_provenance(marker_mutation)

    def test_baseline_mean_must_match_samples(self) -> None:
        audit = validate.load_json("source_audit.json")
        mutated = copy.deepcopy(audit)
        mutated["validation_baseline"]["normal"] = {"samples_ms": [1.0, 3.0], "mean_ms": 5.0}
        with self.assertRaises(validate.ValidationError):
            validate.validate_source_provenance(mutated)


if __name__ == "__main__":
    unittest.main()
