"""Regression tests for the deterministic PTY contract fixture."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import validate


ROOT = Path(__file__).resolve().parent
FIXTURE_PATH = ROOT / "pty-contract-fixtures.json"


class PtyContractValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = validate.load_fixture(FIXTURE_PATH)

    def test_canonical_fixture_passes(self) -> None:
        summary = validate.validate_contract(self.data)
        self.assertEqual(summary["case_count"], 14)
        self.assertEqual(summary["case_ids"], list(validate.EXPECTED_CASES))

    def test_every_named_mutation_fails_closed(self) -> None:
        mutations = validate.mutation_inventory(self.data)
        self.assertEqual(len(mutations), 30)
        self.assertEqual(len({mutation_id for mutation_id, _ in mutations}), 30)
        for mutation_id, candidate in mutations:
            with self.subTest(mutation_id=mutation_id):
                with self.assertRaises(validate.ValidationError):
                    validate.validate_contract(candidate)

    def test_mutation_runner_reports_all_checks(self) -> None:
        self.assertEqual(validate.validate_mutations(self.data), 30)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"schema_version":"pty-contract-v1","schema_version":"pty-contract-v0"}', encoding="utf-8")
            with self.assertRaisesRegex(validate.ValidationError, "duplicate JSON key"):
                validate.load_fixture(path)

    def test_non_finite_json_numbers_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "non-finite.json"
            path.write_text('{"value":NaN}', encoding="utf-8")
            with self.assertRaisesRegex(validate.ValidationError, "non-finite JSON number"):
                validate.load_fixture(path)
            path.write_text('{"value":Infinity}', encoding="utf-8")
            with self.assertRaisesRegex(validate.ValidationError, "non-finite JSON number"):
                validate.load_fixture(path)
            path.write_text('{"value":-Infinity}', encoding="utf-8")
            with self.assertRaisesRegex(validate.ValidationError, "non-finite JSON number"):
                validate.load_fixture(path)

    def test_cli_reports_malformed_fixture_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "malformed.json"
            path.write_text('{"schema_version":"pty-contract-v1","cases":null}', encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ROOT / "validate.py"), "--fixture", str(path)],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("validation failed:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_baseline_json_is_closed_and_observational(self) -> None:
        baseline_path = ROOT / "validation-baseline.json"
        with baseline_path.open("r", encoding="utf-8") as handle:
            baseline = json.load(handle)
        self.assertEqual(
            set(baseline),
            {
                "schema_version",
                "fixture",
                "metric",
                "environment",
                "runs",
                "artifact_size_bytes",
                "approved_budget",
                "notes",
            },
        )
        self.assertEqual(baseline["schema_version"], "pty-contract-baseline-v1")
        self.assertEqual(baseline["fixture"], "pty-contract-fixtures.json")
        self.assertEqual(baseline["metric"], "validator_wall_clock_ms")
        self.assertIsNone(baseline["approved_budget"])
        self.assertEqual(len(baseline["runs"]), 2)
        self.assertEqual({run["mode"] for run in baseline["runs"]}, {"normal", "optimized"})
        for run in baseline["runs"]:
            self.assertGreaterEqual(len(run["samples_ms"]), 5)
            self.assertGreater(run["distribution"]["median_ms"], 0)


if __name__ == "__main__":
    unittest.main()
