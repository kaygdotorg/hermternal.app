"""Regression tests for the synthetic PTY local byte-adapter proof."""

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
CASES_PATH = ROOT / "cases.json"
BASELINE_PATH = ROOT / "validation-baseline.json"


class PtyLocalAdapterValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = validate.load_json(CASES_PATH)

    def _case(self, case_id: str) -> dict[str, object]:
        return validate._case(self.document, case_id)

    def _run_cli(self, optimized: bool, *arguments: str) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend([str(ROOT / "validate.py"), *arguments])
        return subprocess.run(command, capture_output=True, text=True, check=False)

    def test_canonical_fixture_and_mutation_inventory(self) -> None:
        summary = validate.validate_cases_document(self.document)
        self.assertEqual(summary["case_count"], 11)
        self.assertEqual(summary["case_ids"], list(validate.EXPECTED_CASE_IDS))
        mutations = validate.mutation_inventory(self.document)
        self.assertGreaterEqual(len(mutations), 20)
        self.assertEqual(validate.validate_mutations(self.document), len(mutations))

    def test_upgrade_is_binary_local_adapter_without_process_spawn(self) -> None:
        case = self._case("upgrade-success")
        self.assertEqual(case["input"]["events"][1]["transport"], "binary")
        self.assertFalse(case["expected"]["process_spawned"])
        self.assertEqual(case["expected"]["adapter_mode"], "local-byte-adapter")
        validate.validate_cases_document(self.document)

    def test_byte_preservation_keeps_split_incomplete_and_invalid_frames(self) -> None:
        case = self._case("byte-preservation")
        frames = case["input"]["frames"]
        self.assertEqual([frame["frame_hex"] for frame in frames], ["f0", "9f9880", "e282", "c328"])
        self.assertEqual(case["expected"]["joined_hex"], "f09f9880e282c328")
        self.assertTrue(case["expected"]["frame_boundaries_preserved"])
        self.assertFalse(case["expected"]["utf8_decode"])
        self.assertFalse(case["expected"]["reencode"])
        validate.validate_cases_document(self.document)

    def test_resize_clamps_integer_boundaries_and_rejects_malformed_types(self) -> None:
        bounds = self._case("resize-bounds")
        self.assertEqual(
            [(sample["cols"], sample["rows"], sample["effective_cols"], sample["effective_rows"]) for sample in bounds["input"]["samples"]],
            [
                (1, 1, 1, 1),
                (2000, 1000, 2000, 1000),
                (-1, 24, 1, 24),
                (0, 0, 1, 1),
                (80, -1, 80, 1),
                (2001, 24, 2000, 24),
                (80, 1001, 80, 1000),
                (2001, 1001, 2000, 1000),
            ],
        )
        rejection = self._case("resize-rejection")
        self.assertEqual(
            [candidate["wire_shape"] for candidate in rejection["input"]["candidates"]],
            list(validate.RESIZE_REJECTION_SHAPES),
        )
        self.assertTrue(rejection["expected"]["all_rejected_before_binary_send"])
        validate.validate_cases_document(self.document)

    def test_attach_reattach_reuses_all_identity_and_one_spawn(self) -> None:
        case = self._case("attach-reattach")
        events = case["input"]["events"]
        self.assertEqual(events[1]["name"], "session.attach")
        self.assertEqual(events[5]["name"], "session.reattach")
        self.assertEqual(events[5]["session_ref"], case["input"]["session_ref"])
        self.assertEqual(events[5]["process_ref"], case["input"]["process_ref"])
        self.assertEqual(case["expected"]["spawn_count"], 1)
        self.assertTrue(case["expected"]["identity_preserved"])
        validate.validate_cases_document(self.document)

    def test_retained_output_race_keeps_exact_capacity_and_receive_order(self) -> None:
        case = self._case("retained-output-race")
        newest = case["input"]["segments"][1]
        self.assertEqual(newest["repeat"], validate.REPLAY_CAPACITY)
        self.assertEqual(case["expected"]["retained_bytes"], validate.REPLAY_CAPACITY)
        self.assertEqual(case["input"]["separator_hex"], "")
        self.assertEqual(
            [order["order"] for order in case["input"]["orders"]],
            ["retained-first", "live-first"],
        )
        validate.validate_cases_document(self.document)

    def test_expiry_allows_equality_and_expires_after_retention(self) -> None:
        case = self._case("expiry")
        self.assertEqual(
            [(probe["elapsed_seconds"], probe["outcome"]) for probe in case["input"]["probes"]],
            [(1799, "reattach-allowed"), (1800, "reattach-allowed"), (1801, "reattach-expired")],
        )
        validate.validate_cases_document(self.document)

    def test_input_actions_never_appear_in_replay_references(self) -> None:
        case = self._case("no-input-replay")
        self.assertEqual(case["input"]["replayed_action_refs"], [])
        self.assertEqual(case["expected"]["retained_action_refs"], [])
        self.assertEqual(
            case["expected"]["non_replayable_kinds"],
            ["input", "resize", "prompt", "tool"],
        )
        validate.validate_cases_document(self.document)

    def test_logs_have_canonical_refs_but_null_payloads(self) -> None:
        case = self._case("no-pty-byte-logging")
        self.assertEqual(
            [record["event"] for record in case["input"]["logs"]],
            list(validate.LOG_EVENT_ORDER),
        )
        self.assertTrue(all(record["byte_payload_hex"] is None for record in case["input"]["logs"]))
        self.assertTrue(all(record["action_payload_hex"] is None for record in case["input"]["logs"]))
        self.assertFalse(case["expected"]["pty_bytes_logged"])
        validate.validate_cases_document(self.document)

    def test_close_codes_cover_replacement_dead_process_and_legacy_disconnect(self) -> None:
        events = self._case("close-codes")["input"]["events"]
        self.assertEqual(events[0]["close_code"], validate.REPLACEMENT_CLOSE)
        self.assertEqual(events[3]["close_code"], validate.PROCESS_EXIT_CLOSE)
        self.assertEqual(events[4]["close_code"], validate.CLEAN_DISCONNECT_CLOSE)
        self.assertEqual(events[2]["result"], "ignored")
        validate.validate_cases_document(self.document)

    def test_unsupported_host_blocks_before_upgrade_and_spawn(self) -> None:
        case = self._case("unsupported-host")
        self.assertEqual(case["expected"]["reason"], "unsupported-host")
        self.assertFalse(case["expected"]["upgrade_attempted"])
        self.assertFalse(case["expected"]["socket_accepted"])
        self.assertFalse(case["expected"]["process_spawned"])
        validate.validate_cases_document(self.document)

    def test_duplicate_keys_and_nonfinite_numbers_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"outer":{"value":1,"value":2}}', encoding="utf-8")
            with self.assertRaisesRegex(validate.FixtureJSONError, "duplicate JSON object key"):
                validate.load_json(path)
            path.write_text('{"value":NaN}', encoding="utf-8")
            with self.assertRaisesRegex(validate.FixtureJSONError, "non-finite"):
                validate.load_json(path)
            path.write_text('{"value":Infinity}', encoding="utf-8")
            with self.assertRaisesRegex(validate.FixtureJSONError, "non-finite"):
                validate.load_json(path)

    def test_depth_and_sensitive_data_boundaries_fail_closed(self) -> None:
        nested: object = []
        for _ in range(validate.MAX_JSON_DEPTH + 2):
            nested = [nested]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "deep.json"
            path.write_text(json.dumps(nested), encoding="utf-8")
            with self.assertRaisesRegex(validate.FixtureJSONError, "nesting depth"):
                validate.load_json(path)

        with self.assertRaises(validate.ValidationError):
            validate.validate_redaction({"token": "synthetic-value"})
        with self.assertRaises(validate.ValidationError):
            validate.validate_redaction({"message": "Bearer live-value"})
        diagnostic = validate.compact_error("token=live-value " + ("x" * 500))
        self.assertLessEqual(len(diagnostic), validate.MAX_ERROR_OUTPUT)
        self.assertNotIn("live-value", diagnostic)

    def test_direct_nonfinite_resize_mutation_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.document)
        candidate["cases"][3]["input"]["candidates"][0]["cols"] = float("nan")
        with self.assertRaises(validate.FixtureJSONError):
            validate.validate_cases_document(candidate)

    def test_normal_and_optimized_cli_success_are_real_regressions(self) -> None:
        for optimized in (False, True):
            result = self._run_cli(optimized)
            with self.subTest(optimized=optimized):
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                payload = json.loads(result.stdout)
                self.assertTrue(payload["ok"])
                self.assertEqual(payload["cases"], 11)
                self.assertIsNone(payload["threshold"])
                self.assertEqual(result.stderr, "")

    def test_cli_skip_baseline_accepts_an_alternate_case_file(self) -> None:
        candidate = copy.deepcopy(self.document)
        candidate["cases"][0]["expected"]["status"] = "blocked"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            path.write_text(json.dumps(candidate), encoding="utf-8")
            result = self._run_cli(False, "--cases", str(path), "--skip-baseline")
        self.assertNotEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertFalse(payload["ok"])
        self.assertNotIn(str(path), result.stdout)
        self.assertNotIn("Traceback", result.stdout)

    def test_cli_failures_are_bounded_and_do_not_echo_flags_or_paths(self) -> None:
        missing = Path(tempfile.gettempdir()) / "token-shaped-pty-cases.json"
        for optimized in (False, True):
            result = self._run_cli(optimized, "--cases", str(missing), "--skip-baseline")
            with self.subTest(kind="missing", optimized=optimized):
                self.assertEqual(result.returncode, 2)
                self.assertLessEqual(len(result.stdout.rstrip("\n")), validate.MAX_ERROR_OUTPUT + 100)
                self.assertNotIn(str(missing), result.stdout)
                self.assertNotIn("Traceback", result.stdout)
                self.assertEqual(result.stderr, "")

            invalid = self._run_cli(optimized, "--unknown-sensitive-flag")
            with self.subTest(kind="flag", optimized=optimized):
                self.assertEqual(invalid.returncode, 2)
                self.assertNotIn("unknown-sensitive-flag", invalid.stdout)
                self.assertNotIn("usage:", invalid.stdout.lower())
                self.assertEqual(invalid.stderr, "")

    def test_checked_in_baseline_is_strict_and_threshold_is_null(self) -> None:
        baseline = validate.load_json(BASELINE_PATH)
        summary = validate.validate_baseline(baseline)
        self.assertEqual(summary["sample_count"], 60)
        self.assertIsNone(baseline["threshold"])
        self.assertEqual(tuple(baseline["artifact"]["files"]), validate.ARTIFACT_FILES)

    def test_baseline_mutations_fail_closed(self) -> None:
        baseline = validate.load_json(BASELINE_PATH)
        mutations = []
        candidate = copy.deepcopy(baseline)
        candidate["threshold"] = 1.0
        mutations.append(candidate)
        candidate = copy.deepcopy(baseline)
        candidate["runs"][0]["command"] = "python3 -O contracts/fixtures/deployment-security/pty-local-adapter/validate.py"
        mutations.append(candidate)
        candidate = copy.deepcopy(baseline)
        candidate["runs"][0]["distribution"]["mean_ms"] += 1.0
        mutations.append(candidate)
        candidate = copy.deepcopy(baseline)
        candidate["artifact"]["bytes"] += 1
        mutations.append(candidate)
        candidate = copy.deepcopy(baseline)
        candidate["artifact"]["files"].append("unexpected")
        mutations.append(candidate)
        for index, mutated in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaises(validate.ValidationError):
                    validate.validate_baseline(mutated)

    def test_cli_output_is_one_json_line_in_both_modes(self) -> None:
        for optimized in (False, True):
            result = self._run_cli(optimized)
            with self.subTest(optimized=optimized):
                self.assertEqual(len(result.stdout.splitlines()), 1)
                json.loads(result.stdout)


if __name__ == "__main__":
    unittest.main()
