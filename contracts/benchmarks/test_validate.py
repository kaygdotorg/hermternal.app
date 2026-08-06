#!/usr/bin/env python3
"""Regression tests for the shared benchmark evidence contract.

The suite uses only synthetic JSON and the Python standard library.  It never
starts Hermes, opens a network connection, invokes a browser, or reads live
machine identifiers.
"""

from __future__ import annotations

import ast
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


class BenchmarkEvidenceTests(unittest.TestCase):
    """Keep the closed format, method, and redaction boundary aligned."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.document = validate.load_json(validate.EVIDENCE_PATH)
        validate.validate_evidence(cls.document)

    def _run_cli(
        self,
        raw: bytes,
        *,
        optimized: bool = False,
        extra: tuple[str, ...] = ("--skip-baseline",),
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.NamedTemporaryFile(suffix=".json") as handle:
            handle.write(raw)
            handle.flush()
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.extend([str(FIXTURE_DIR / "validate.py"), "--evidence", handle.name, *extra])
            return subprocess.run(command, check=False, capture_output=True, text=True)

    def _run_document(self, document: object, *, optimized: bool = False) -> subprocess.CompletedProcess[str]:
        return self._run_cli(json.dumps(document, separators=(",", ":")).encode(), optimized=optimized)

    def _assert_rejected(self, document: object) -> None:
        with self.assertRaises(validate.ValidationError):
            validate.validate_evidence(document)

    def _assert_cli_failure(self, raw: bytes, secret: str | None = None) -> None:
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                completed = self._run_cli(raw, optimized=optimized)
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stderr, "")
                lines = [line for line in completed.stdout.splitlines() if line.strip()]
                self.assertEqual(len(lines), 1)
                payload = json.loads(lines[0])
                self.assertFalse(payload["ok"])
                self.assertEqual(payload["error"]["code"], validate.ERROR_CODE)
                self.assertLessEqual(len(payload["error"]["message"]), validate.MAX_ERROR_OUTPUT)
                self.assertNotIn("Traceback", completed.stdout + completed.stderr)
                if secret is not None:
                    self.assertNotIn(secret, completed.stdout + completed.stderr)

    def test_checked_in_format_has_all_platform_and_state_examples(self) -> None:
        self.assertEqual(self.document["schema"], validate.SCHEMA)
        self.assertEqual(
            {run["platform"] for run in self.document["runs"]},
            {"web", "ios"},
        )
        self.assertEqual(
            {(run["platform"], run["state"]) for run in self.document["runs"]},
            {("web", "cold"), ("web", "warm"), ("ios", "cold"), ("ios", "warm")},
        )
        self.assertTrue(all(run["repetitions"] == len(run["raw_samples"]) == 30 for run in self.document["runs"]))
        self.assertIsNone(self.document["threshold"])
        self.assertIsNone(self.document["budget"])

    def test_canonical_distribution_is_recomputed_for_every_run(self) -> None:
        for run in self.document["runs"]:
            with self.subTest(run=run["id"]):
                expected = validate.expected_distribution(run["raw_samples"])
                for key, value in expected.items():
                    self.assertEqual(validate.Decimal(str(run["distribution"][key])), value)

    def test_percentile_method_is_inclusive_linear_interpolation(self) -> None:
        distribution = validate.expected_distribution(list(range(1, 31)))
        self.assertEqual(distribution["p50"], validate.Decimal("15.500"))
        self.assertEqual(distribution["p95"], validate.Decimal("28.550"))
        self.assertEqual(distribution["p99"], validate.Decimal("29.710"))
        method = self.document["method"]
        self.assertEqual(method["percentile_method"], "inclusive_linear_interpolation_r7")
        self.assertEqual(method["position_formula"], "(n - 1) * q")
        self.assertEqual(method["rounding"], "half_even_to_3_decimal_places")

    def test_missing_unknown_and_reordered_keys_fail_closed(self) -> None:
        missing = copy.deepcopy(self.document)
        del missing["budget"]
        self._assert_rejected(missing)

        unknown = copy.deepcopy(self.document)
        unknown["unexpected"] = "synthetic"
        self._assert_rejected(unknown)

        reordered = copy.deepcopy(self.document)
        reordered["threshold"], reordered["budget"] = reordered["budget"], reordered["threshold"]
        reordered = {key: reordered[key] for key in reversed(tuple(reordered))}
        self._assert_rejected(reordered)

    def test_repetitions_and_raw_samples_are_bound(self) -> None:
        mismatch = copy.deepcopy(self.document)
        mismatch["runs"][0]["repetitions"] = 29
        self._assert_rejected(mismatch)

        too_few = copy.deepcopy(self.document)
        too_few["runs"][0]["raw_samples"] = [1.0]
        too_few["runs"][0]["repetitions"] = 1
        self._assert_rejected(too_few)

        bool_sample = copy.deepcopy(self.document)
        bool_sample["runs"][0]["raw_samples"][0] = True
        self._assert_rejected(bool_sample)

    def test_cold_warm_and_build_mode_values_are_closed(self) -> None:
        invalid_state = copy.deepcopy(self.document)
        invalid_state["runs"][0]["state"] = "reused"
        self._assert_rejected(invalid_state)

        invalid_build = copy.deepcopy(self.document)
        invalid_build["runs"][0]["build_mode"] = "debug"
        self._assert_rejected(invalid_build)

        wrong_platform_build = copy.deepcopy(self.document)
        wrong_platform_build["runs"][0]["build_mode"] = "release"
        self._assert_rejected(wrong_platform_build)

        invalid_optimization = copy.deepcopy(self.document)
        invalid_optimization["runs"][0]["optimization"] = "debug"
        self._assert_rejected(invalid_optimization)

    def test_distribution_mutation_is_detected(self) -> None:
        mutated = copy.deepcopy(self.document)
        mutated["runs"][0]["distribution"]["p99"] += 1
        self._assert_rejected(mutated)

        nonfinite = copy.deepcopy(self.document)
        nonfinite["runs"][0]["raw_samples"][0] = float("inf")
        self._assert_rejected(nonfinite)

    def test_revision_and_artifact_identity_are_strict(self) -> None:
        bad_commit = copy.deepcopy(self.document)
        bad_commit["revision"]["commit_sha"] = "not-a-commit"
        self._assert_rejected(bad_commit)

        bad_version = copy.deepcopy(self.document)
        bad_version["revision"]["fixture_version"] = "latest"
        self._assert_rejected(bad_version)

        bad_hash = copy.deepcopy(self.document)
        bad_hash["artifacts"][0]["sha256"] = "0" * 64
        self._assert_rejected(bad_hash)

        bad_manifest = copy.deepcopy(self.document)
        bad_manifest["artifact_manifest_sha256"] = "0" * 64
        self._assert_rejected(bad_manifest)

        traversal = copy.deepcopy(self.document)
        traversal["artifacts"][0]["path"] = "../outside.json"
        self._assert_rejected(traversal)

    def test_threshold_and_budget_cannot_become_unreviewed_limits(self) -> None:
        for key in ("threshold", "budget"):
            mutated = copy.deepcopy(self.document)
            mutated[key] = 100
            with self.subTest(key=key):
                self._assert_rejected(mutated)

    def test_redaction_rejects_sensitive_fields_and_values(self) -> None:
        sensitive_value = copy.deepcopy(self.document)
        sensitive_value["runs"][0]["command"] = "token=raw-synthetic-secret"
        self._assert_rejected(sensitive_value)

        sensitive_key = copy.deepcopy(self.document)
        sensitive_key["runs"][0]["raw_token"] = "synthetic"
        self._assert_rejected(sensitive_key)

        redaction_flag = copy.deepcopy(self.document)
        redaction_flag["redaction"]["contains_tokens"] = True
        self._assert_rejected(redaction_flag)

        host_value = copy.deepcopy(self.document)
        host_value["runs"][0]["environment"]["device"] = "https://live.example.test"
        self._assert_rejected(host_value)

    def test_duplicate_keys_nonfinite_numbers_and_invalid_utf8_are_controlled(self) -> None:
        self._assert_cli_failure(b'{"schema":1,"schema":2}')
        self._assert_cli_failure(b'{"schema":NaN}')
        self._assert_cli_failure(b"\xff\xfe\xfd")

    def test_error_output_does_not_echo_sensitive_arguments_or_values(self) -> None:
        for optimized in (False, True):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.extend([str(FIXTURE_DIR / "validate.py"), "--token=raw-synthetic-secret"])
            completed = subprocess.run(command, check=False, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(completed.stderr, "")
            self.assertNotIn("raw-synthetic-secret", completed.stdout)
            self.assertNotIn("usage:", completed.stdout.lower())
            self.assertLessEqual(len(completed.stdout), validate.MAX_ERROR_OUTPUT + 128)

        raw = json.dumps(
            {"schema": "x", "command": "token=raw-synthetic-secret"},
            separators=(",", ":"),
        ).encode()
        self._assert_cli_failure(raw, "raw-synthetic-secret")

    def test_cli_succeeds_in_normal_and_optimized_modes(self) -> None:
        raw = validate.EVIDENCE_PATH.read_bytes()
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                completed = self._run_cli(raw, optimized=optimized)
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                self.assertEqual(completed.stderr, "")
                payload = json.loads(completed.stdout)
                self.assertTrue(payload["ok"])
                self.assertFalse(payload["baseline_checked"])

    def test_checked_in_validator_baseline_is_reproducible(self) -> None:
        baseline = validate.load_json(validate.BASELINE_PATH)
        validate.validate_baseline(baseline)
        self.assertEqual(baseline["evidence_id"], validate.BASELINE_EVIDENCE_ID)
        self.assertEqual({run["optimization"] for run in baseline["runs"]}, {"normal", "optimized"})
        self.assertTrue(all(run["repetitions"] == 30 for run in baseline["runs"]))
        self.assertIsNone(baseline["threshold"])
        self.assertIsNone(baseline["budget"])

    def test_baseline_mutations_fail_closed(self) -> None:
        baseline = validate.load_json(validate.BASELINE_PATH)
        for mutation in ("threshold", "budget"):
            candidate = copy.deepcopy(baseline)
            candidate[mutation] = 1
            with self.subTest(mutation=mutation):
                with self.assertRaises(validate.ValidationError):
                    validate.validate_baseline(candidate)

        candidate = copy.deepcopy(baseline)
        candidate["runs"][0]["distribution"]["p95"] += 0.001
        with self.assertRaises(validate.ValidationError):
            validate.validate_baseline(candidate)

    def test_only_standard_library_imports_are_used(self) -> None:
        tree = ast.parse(validate.EVIDENCE_PATH.with_name("validate.py").read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        stdlib = set(getattr(sys, "stdlib_module_names", ()))
        self.assertTrue(imported <= stdlib, sorted(imported - stdlib))
        self.assertNotIn("assert", validate.EVIDENCE_PATH.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
