#!/usr/bin/env python3
"""Regression tests for evaluator benchmark drift rejection."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

DIRECTORY = Path(__file__).resolve().parent
VALIDATOR = DIRECTORY / "validate_evaluator_benchmark.py"
EVIDENCE = DIRECTORY / "evaluator-benchmark-evidence.json"
SPEC = importlib.util.spec_from_file_location("probe_benchmark_validator", VALIDATOR)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("validator import failed")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class EvaluatorBenchmarkValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = MODULE.load(EVIDENCE)

    def assert_rejected(self, mutate) -> None:
        document = copy.deepcopy(self.document)
        mutate(document)
        with self.assertRaises(MODULE.ValidationError):
            MODULE.validate_document(document)

    def test_checked_in_evidence_is_valid(self) -> None:
        MODULE.validate_document(self.document)

    def test_rejects_raw_sample_and_distribution_drift(self) -> None:
        self.assert_rejected(lambda value: value["runs"][0]["raw_samples"].__setitem__(0, MODULE.Decimal("999")))
        self.assert_rejected(lambda value: value["runs"][0]["distribution"].__setitem__("p95", MODULE.Decimal("999")))

        def coordinated_drift(value) -> None:
            value["runs"][0]["raw_samples"][0] = MODULE.Decimal("999")
            value["runs"][0]["distribution"] = MODULE.distribution(value["runs"][0]["raw_samples"])

        self.assert_rejected(coordinated_drift)

    def test_rejects_metadata_and_budget_drift(self) -> None:
        self.assert_rejected(lambda value: value["runs"][0].__setitem__("command", "changed"))
        self.assert_rejected(lambda value: value["runs"][0]["environment"].__setitem__("runtime", "changed"))
        self.assert_rejected(lambda value: value.__setitem__("threshold", MODULE.Decimal("1")))

    def test_rejects_missing_or_reordered_runs(self) -> None:
        self.assert_rejected(lambda value: value["runs"].pop())
        self.assert_rejected(lambda value: value["runs"].reverse())

    def test_cli_rejects_duplicate_keys_and_nonfinite_values_with_fixed_error(self) -> None:
        for payload in ('{"schema":"a","schema":"b"}', '{"sample":NaN}'):
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
                handle.write(payload)
                path = Path(handle.name)
            try:
                completed = subprocess.run(
                    ["python3", str(VALIDATOR), str(path)],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stdout, "")
                self.assertEqual(completed.stderr, '{"error":"invalid evaluator benchmark evidence"}\n')
            finally:
                path.unlink(missing_ok=True)

    def test_cli_accepts_checked_in_evidence(self) -> None:
        completed = subprocess.run(
            ["python3", str(VALIDATOR)],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, "")
        self.assertEqual(json.loads(completed.stdout)["samples_per_run"], 30)


if __name__ == "__main__":
    unittest.main()
