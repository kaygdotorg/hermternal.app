"""Regression tests for the deterministic C-18 PTY lifecycle fixture."""

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
FIXTURE_PATH = ROOT / "pty-detach-race-fixtures.json"
BASELINE_PATH = ROOT / "validation-baseline.json"


class PtyDetachRaceValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = validate.load_fixture(FIXTURE_PATH)

    def test_canonical_fixture_and_mutation_inventory_pass(self) -> None:
        summary = validate.validate_contract(self.data)
        self.assertEqual(summary["case_count"], 12)
        self.assertEqual(summary["case_ids"], list(validate.EXPECTED_CASES))
        mutations = validate.mutation_inventory(self.data)
        self.assertEqual(len(mutations), 45)
        self.assertEqual(validate.validate_mutations(self.data), 45)

    def test_checked_in_baseline_matches_owned_artifacts(self) -> None:
        summary = validate.validate_baseline(validate.load_baseline(BASELINE_PATH))
        self.assertEqual(summary, {"artifact_count": 4, "sample_count": 60})

    def test_duplicate_keys_are_rejected_at_nested_levels(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"outer":{"value":1,"value":2}}', encoding="utf-8")
            with self.assertRaisesRegex(validate.ValidationError, "duplicate JSON key"):
                validate.load_fixture(path)

    def test_non_finite_json_extensions_and_overflow_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "non-finite.json"
            for token in ("NaN", "Infinity", "-Infinity", "1e999"):
                path.write_text('{"value":' + token + '}', encoding="utf-8")
                with self.subTest(token=token):
                    with self.assertRaises(validate.ValidationError):
                        validate.load_fixture(path)
            path.write_text('{"value":' + ("9" * 5000) + '}', encoding="utf-8")
            with self.assertRaisesRegex(validate.ValidationError, "invalid JSON value"):
                validate.load_fixture(path)

    def test_deep_input_and_large_diagnostics_fail_without_traceback(self) -> None:
        malformed = copy.deepcopy(self.data)
        nested: object = []
        for _ in range(validate.MAX_JSON_DEPTH + 8):
            nested = [nested]
        malformed["unexpected_nested"] = nested
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "deep.json"
            path.write_text(json.dumps(malformed), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ROOT / "validate.py"), "--fixture", str(path), "--baseline", str(BASELINE_PATH)],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("maximum JSON nesting depth exceeded", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

        oversized = copy.deepcopy(self.data)
        oversized.update({f"unexpected-{index:05d}": True for index in range(10_000)})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large-error.json"
            path.write_text(json.dumps(oversized), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ROOT / "validate.py"), "--fixture", str(path), "--baseline", str(BASELINE_PATH)],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertLessEqual(len(result.stderr.rstrip("\n")), validate.MAX_ERROR_LENGTH)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn(validate.ERROR_SUFFIX, result.stderr)

    def test_ttl_registry_and_explicit_close_contracts(self) -> None:
        ttl = validate._case(self.data, "detach-ttl")
        self.assertEqual(
            [(probe["elapsed_seconds"], probe["outcome"]) for probe in ttl["input"]["probes"]],
            [(1799, "reattach-allowed"), (1800, "reattach-allowed"), (1801, "reattach-expired")],
        )
        registry = validate._case(self.data, "registry-cap")
        self.assertEqual(len(registry["input"]["entry_refs"]), 16)
        close = validate._case(self.data, "explicit-close")
        self.assertFalse(close["expected"]["process_terminated"])
        self.assertEqual(close["expected"]["process_state"], "retained")
        validate.validate_contract(self.data)

    def test_exact_one_mib_replay_and_reconnect_truncation(self) -> None:
        replay = validate._case(self.data, "replay-newest-tail")
        newest = replay["input"]["segments"][1]
        self.assertEqual(newest["repeat"], 1_048_576)
        self.assertTrue(replay["expected"]["exact_capacity_valid"])
        reconnect = validate._case(self.data, "reconnect-truncation")
        self.assertEqual(reconnect["input"]["output_sizes"]["retained_bytes"], 1_048_576)
        self.assertEqual(reconnect["expected"]["state_sequence"], ["attached", "detached", "reattached"])
        validate.validate_contract(self.data)

    def test_race_orders_have_no_separator(self) -> None:
        race = validate._case(self.data, "replay-live-race")
        self.assertEqual(race["input"]["separator_hex"], "")
        self.assertEqual(
            [order["order"] for order in race["input"]["orders"]],
            ["retained-first", "live-first"],
        )
        validate.validate_contract(self.data)

    def test_supersession_closes_old_socket_before_assignment(self) -> None:
        case = validate._case(self.data, "superseded-attachment")
        events = case["input"]["events"]
        self.assertEqual(events[0]["close_code"], 4409)
        self.assertEqual(events[0]["name"], "old_socket_close")
        self.assertEqual(events[1]["name"], "replacement_assign")
        self.assertEqual(events[2]["result"], "ignored")
        self.assertEqual(case["expected"]["active_attachment_count"], 1)
        validate.validate_contract(self.data)

    def test_resize_bounds_rejection_and_exact_binary_frame(self) -> None:
        bounds = validate._case(self.data, "resize-bounds")
        self.assertEqual(bounds["input"]["samples"][2]["effective_cols"], 1)
        self.assertEqual(bounds["input"]["samples"][5]["effective_cols"], 2000)
        rejection = validate._case(self.data, "resize-rejection")
        self.assertEqual(len(rejection["input"]["candidates"]), 8)
        self.assertTrue(rejection["expected"]["all_rejected_before_binary_send"])
        validate.validate_contract(self.data)

    def test_action_exclusion_and_byte_logging_redaction(self) -> None:
        actions = validate._case(self.data, "no-input-replay")
        self.assertEqual(actions["input"]["replayed_action_refs"], [])
        self.assertEqual(
            actions["expected"]["non_replayable_kinds"],
            ["input", "resize", "prompt", "tool"],
        )
        logging_case = validate._case(self.data, "no-byte-logging")
        self.assertTrue(all(log["byte_payload_hex"] is None for log in logging_case["input"]["logs"]))
        self.assertTrue(all(log["action_payload_hex"] is None for log in logging_case["input"]["logs"]))
        validate.validate_contract(self.data)

    def test_cli_normal_success_and_optimized_success(self) -> None:
        for optimize in (False, True):
            command = [sys.executable]
            if optimize:
                command.append("-O")
            command.extend([str(ROOT / "validate.py"), "--fixture", str(FIXTURE_PATH), "--baseline", str(BASELINE_PATH)])
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            with self.subTest(optimize=optimize):
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("cases=12", result.stdout)
                self.assertIn("mutation_checks=45", result.stdout)
                self.assertIn("benchmark_samples=60", result.stdout)


if __name__ == "__main__":
    unittest.main()
