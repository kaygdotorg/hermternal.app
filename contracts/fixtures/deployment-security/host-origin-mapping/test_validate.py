#!/usr/bin/env python3
"""Regression and mutation tests for the offline DEP-03 mapping proof."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
VALIDATOR = ROOT / "validate.py"
CASES = ROOT / "cases.json"
BASELINE = ROOT / "validation-baseline.json"

spec = importlib.util.spec_from_file_location("host_origin_mapping_validate", VALIDATOR)
if spec is None or spec.loader is None:
    raise RuntimeError("validator module could not be loaded")
validate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validate)


class HostOriginMappingProofTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.document = json.loads(CASES.read_text(encoding="utf-8"))

    def run_cli(self, arguments: list[str] | None = None, *, optimized: bool = False) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.append(str(VALIDATOR))
        command.extend(arguments or [])
        return subprocess.run(command, cwd=ROOT.parents[3], text=True, capture_output=True, check=False, timeout=20)

    def write_mutation(self, document: object) -> Path:
        handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False)
        with handle:
            json.dump(document, handle, separators=(",", ":"), ensure_ascii=True)
        self.addCleanup(lambda: Path(handle.name).unlink(missing_ok=True))
        return Path(handle.name)

    def assert_bounded_failure(self, result: subprocess.CompletedProcess[str], canary: str | None = None) -> None:
        self.assertEqual(result.returncode, 2, result)
        self.assertEqual(result.stderr, "")
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), 1)
        self.assertLessEqual(len(lines[0]), 240)
        parsed = json.loads(lines[0])
        self.assertEqual(parsed["status"], "failure")
        if canary is not None:
            self.assertNotIn(canary, result.stdout)

    def assert_mutation_fails_both_modes(self, document: object, canary: str | None = None) -> None:
        path = self.write_mutation(document)
        outputs = []
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                result = self.run_cli(["--cases", str(path), "--skip-baseline"], optimized=optimized)
                self.assert_bounded_failure(result, canary)
                outputs.append(result.stdout)
        self.assertEqual(outputs[0], outputs[1])

    def test_default_validator_passes_in_normal_and_optimized_modes(self) -> None:
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                result = self.run_cli(optimized=optimized)
                self.assertEqual(result.returncode, 0, result)
                self.assertEqual(result.stderr, "")
                parsed = json.loads(result.stdout)
                self.assertEqual(
                    parsed,
                    {
                        "status": "ok",
                        "fixture_id": "host-origin-mapping-dep-03-f5be9236",
                        "cases": 12,
                        "accepted": 1,
                        "rejected": 11,
                        "synthetic_only": True,
                        "live_claim": False,
                    },
                )

    def test_case_inventory_and_computed_results_are_frozen(self) -> None:
        retained = validate.validate_document(copy.deepcopy(self.document))
        self.assertEqual(tuple(case["id"] for case in self.document["cases"]), validate.EXPECTED_CASE_IDS)
        self.assertEqual(len(retained), 12)
        self.assertTrue(retained[0]["upstream_called"])
        self.assertEqual(retained[0]["mapped_host_marker"], "fixed_private_non_loopback_9119")
        self.assertEqual(retained[0]["mapped_origin_marker"], "mapped_private_http_origin")
        for evidence in retained[1:]:
            with self.subTest(case=evidence["case_id"]):
                self.assertFalse(evidence["upstream_called"])
                self.assertIsNone(evidence["mapped_host_marker"])
                self.assertIsNone(evidence["mapped_origin_marker"])

    def test_every_mapping_field_mutation_fails_both_modes(self) -> None:
        replacements = {
            "configured_public_scheme": "mutated_scheme",
            "configured_public_host": "mutated_public_host",
            "configured_public_origin": "mutated_public_origin",
            "hermes_bound_authority": "mutated_bound_authority",
            "hermes_required_origin": "mutated_required_origin",
            "mapping_source": "request_input",
            "request_values_never_select_upstream": False,
        }
        for field, replacement in replacements.items():
            with self.subTest(field=field):
                document = copy.deepcopy(self.document)
                document["mapping"][field] = replacement
                self.assert_mutation_fails_both_modes(document)

    def test_every_policy_field_mutation_fails_both_modes(self) -> None:
        replacements = {
            "route": "/mutated",
            "method": "POST",
            "transport": "http",
            "host_rejection_status": 200,
            "origin_rejection_status": 200,
            "host_precedes_origin": False,
            "rejection_upstream_called": True,
            "accepted_action": "allow_without_mapping",
        }
        for field, replacement in replacements.items():
            with self.subTest(field=field):
                document = copy.deepcopy(self.document)
                document["policy"][field] = replacement
                self.assert_mutation_fails_both_modes(document)

    def test_each_request_classification_mutation_fails_both_modes(self) -> None:
        for index, case in enumerate(self.document["cases"]):
            for field in validate.REQUEST_KEYS:
                with self.subTest(case=case["id"], field=field):
                    document = copy.deepcopy(self.document)
                    document["cases"][index]["request"][field] = "unsupported_mutation"
                    self.assert_mutation_fails_both_modes(document)

    def test_each_expected_result_mutation_fails_both_modes(self) -> None:
        replacements = {
            "decision": "mutated_decision",
            "status": 599,
            "responding_layer": "mutated_layer",
            "upstream_called": True,
            "public_host_result": "mutated_host_result",
            "public_origin_result": "mutated_origin_result",
            "mapped_host_marker": "mutated_host_marker",
            "mapped_origin_marker": "mutated_origin_marker",
        }
        for case_index, case in enumerate(self.document["cases"]):
            for field, replacement in replacements.items():
                with self.subTest(case=case["id"], field=field):
                    document = copy.deepcopy(self.document)
                    current = document["cases"][case_index]["expected"][field]
                    document["cases"][case_index]["expected"][field] = False if current is True else replacement
                    self.assert_mutation_fails_both_modes(document)

    def test_evidence_contract_mutations_fail_both_modes(self) -> None:
        mutations = {
            "retained_fields": ["case_id"],
            "forbidden_retained_classes": ["credentials"],
            "maximum_failure_line_characters": 10000,
            "maximum_retained_evidence_bytes": 32,
            "failure_output": "unbounded_text",
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                document = copy.deepcopy(self.document)
                document["evidence_contract"][field] = replacement
                self.assert_mutation_fails_both_modes(document)

    def test_host_is_rejected_before_origin_and_override(self) -> None:
        case = copy.deepcopy(self.document["cases"][-1])
        result = validate.evaluate_case(case)
        self.assertEqual(result["decision"], "reject_public_host")
        self.assertEqual(result["status"], 421)
        self.assertEqual(result["public_origin_result"], "not_evaluated")
        self.assertFalse(result["upstream_called"])

    def test_request_override_never_produces_mapped_values(self) -> None:
        for case in self.document["cases"]:
            if case["request"]["upstream_override"] == "absent":
                continue
            with self.subTest(case=case["id"]):
                result = validate.evaluate_case(copy.deepcopy(case))
                self.assertFalse(result["upstream_called"])
                self.assertIsNone(result["mapped_host_marker"])
                self.assertIsNone(result["mapped_origin_marker"])

    def test_sensitive_canaries_are_not_echoed_in_both_modes(self) -> None:
        canaries = (
            "password=synthetic-canary-value",
            "Authorization: Bearer synthetic-canary-value",
            "Cookie: synthetic-canary-value",
            "ticket=synthetic-canary-value",
            "https://unsafe.invalid/path",
            "192.0.2.44",
            "/private/synthetic/canary",
            "person@example.invalid",
            "-----BEGIN PRIVATE KEY-----",
        )
        for canary in canaries:
            with self.subTest(canary=canary):
                document = copy.deepcopy(self.document)
                document["fixture_id"] = canary
                self.assert_mutation_fails_both_modes(document, canary)

    def test_duplicate_keys_fail_without_echo(self) -> None:
        payload = '{"schema":"canary","schema":"secret=do-not-echo"}'
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as handle:
            handle.write(payload)
            path = Path(handle.name)
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        for optimized in (False, True):
            result = self.run_cli(["--cases", str(path), "--skip-baseline"], optimized=optimized)
            self.assert_bounded_failure(result, "do-not-echo")

    def test_malformed_utf8_fails_without_traceback(self) -> None:
        with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as handle:
            handle.write(b"\xff\xfe")
            path = Path(handle.name)
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        for optimized in (False, True):
            result = self.run_cli(["--cases", str(path), "--skip-baseline"], optimized=optimized)
            self.assert_bounded_failure(result)

    def test_cli_rejects_unknown_and_repeated_options(self) -> None:
        for arguments in (["--unknown", "secret=do-not-echo"], ["--skip-baseline", "--skip-baseline"], ["--cases"]):
            with self.subTest(arguments=arguments):
                result = self.run_cli(list(arguments))
                self.assert_bounded_failure(result, "do-not-echo")

    def test_baseline_is_exact_and_bound_to_current_artifacts(self) -> None:
        baseline, payload = validate.load_json(BASELINE)
        validate.validate_baseline(baseline, payload)
        self.assertEqual(baseline["artifact"], validate.artifact_manifest())
        mutated = copy.deepcopy(baseline)
        mutated["normal"]["samples"][0] += 0.001
        mutated_payload = json.dumps(mutated, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        with self.assertRaises(validate.ValidationError):
            validate.validate_baseline(mutated, mutated_payload)

    def test_failure_formatter_is_always_bounded(self) -> None:
        line = validate.bounded_failure("x" * 10000)
        self.assertLessEqual(len(line), 240)
        self.assertEqual(json.loads(line), {"status": "failure", "reason": "validation failed"})


if __name__ == "__main__":
    unittest.main()
