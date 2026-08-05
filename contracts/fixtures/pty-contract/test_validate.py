"""Regression tests for the deterministic PTY contract fixture."""

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
FIXTURE_PATH = ROOT / "pty-contract-fixtures.json"


class PtyContractValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = validate.load_fixture(FIXTURE_PATH)

    def test_canonical_fixture_passes(self) -> None:
        summary = validate.validate_contract(self.data)
        self.assertEqual(summary["case_count"], 15)
        self.assertEqual(summary["case_ids"], list(validate.EXPECTED_CASES))

    def test_every_named_mutation_fails_closed(self) -> None:
        mutations = validate.mutation_inventory(self.data)
        self.assertEqual(len(mutations), 46)
        self.assertEqual(len({mutation_id for mutation_id, _ in mutations}), 46)
        for mutation_id, candidate in mutations:
            with self.subTest(mutation_id=mutation_id):
                with self.assertRaises(validate.ValidationError):
                    validate.validate_contract(candidate)

    def test_mutation_runner_reports_all_checks(self) -> None:
        self.assertEqual(validate.validate_mutations(self.data), 46)

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

    def test_cli_reports_canonical_root_cases_failure_without_traceback(self) -> None:
        malformed = copy.deepcopy(self.data)
        malformed["cases"] = None
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "malformed.json"
            path.write_text(json.dumps(malformed), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ROOT / "validate.py"), "--fixture", str(path)],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("validation failed:", result.stderr)
        self.assertIn("cases: must be an array", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_deeply_nested_data_fails_closed_during_direct_validation(self) -> None:
        malformed = copy.deepcopy(self.data)
        nested: object = []
        for _ in range(1100):
            nested = [nested]
        malformed["deep_extra"] = nested
        with self.assertRaisesRegex(validate.ValidationError, "maximum JSON nesting depth exceeded"):
            validate.validate_contract(malformed)

    def test_cli_reports_deeply_nested_json_without_traceback(self) -> None:
        malformed = copy.deepcopy(self.data)
        nested: object = []
        for _ in range(validate.MAX_JSON_DEPTH + 16):
            nested = [nested]
        malformed["deep_extra"] = nested
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "deep.json"
            path.write_text(json.dumps(malformed), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ROOT / "validate.py"), "--fixture", str(path)],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("maximum JSON nesting depth exceeded", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_resize_policy_clamps_integer_overflow_and_rejects_invalid_types(self) -> None:
        summary = validate.validate_contract(self.data)
        self.assertEqual(summary["case_count"], 15)
        resize_case = next(case for case in self.data["cases"] if case["id"] == "resize-bounds")
        samples = resize_case["input"]["samples"]
        self.assertEqual(
            [(sample["cols"], sample["rows"]) for sample in samples],
            [(1, 1), (2000, 1000), (-1, 24), (0, 0), (80, -1), (2001, 24), (80, 1001), (2001, 1001)],
        )
        self.assertEqual(
            [(sample["effective_cols"], sample["effective_rows"]) for sample in samples],
            [(1, 1), (2000, 1000), (1, 24), (1, 1), (80, 1), (2000, 24), (80, 1000), (2000, 1000)],
        )
        rejection_case = next(case for case in self.data["cases"] if case["id"] == "resize-rejection")
        self.assertEqual(
            [candidate["wire_shape"] for candidate in rejection_case["input"]["candidates"]],
            [
                "non-integer-number",
                "boolean-dimension",
                "string-dimension",
                "null-dimension",
                "non-finite-number-token",
                "malformed-frame",
                "non-integer-number",
                "boolean-dimension",
                "string-dimension",
                "null-dimension",
                "non-finite-number-token",
            ],
        )

    def test_non_finite_resize_dimensions_fail_closed_before_binary_send(self) -> None:
        candidate = copy.deepcopy(self.data)
        rejection = next(case for case in candidate["cases"] if case["id"] == "resize-rejection")
        rejection["input"]["candidates"][0]["cols"] = float("nan")
        with self.assertRaisesRegex(validate.ValidationError, "non-finite number"):
            validate.validate_contract(candidate)
        candidate = copy.deepcopy(self.data)
        rejection = next(case for case in candidate["cases"] if case["id"] == "resize-rejection")
        rejection["input"]["candidates"][10]["rows"] = float("inf")
        with self.assertRaisesRegex(validate.ValidationError, "non-finite number"):
            validate.validate_contract(candidate)

    def test_multiframe_raw_bytes_preserve_split_incomplete_and_invalid_fragments(self) -> None:
        case = next(case for case in self.data["cases"] if case["id"] == "raw-bytes-boundaries")
        frames = case["input"]["frames"]
        self.assertEqual([frame["frame_hex"] for frame in frames[:2]], ["f0", "9f9880"])
        self.assertEqual("".join(frame["frame_hex"] for frame in frames), case["expected"]["joined_hex"])
        self.assertEqual(case["expected"]["frame_boundaries_preserved"], True)
        self.assertFalse(case["expected"]["utf8_decode"])
        self.assertFalse(case["expected"]["reencode"])
        validate.validate_contract(self.data)

    def test_legacy_timelines_independently_terminate_and_reap(self) -> None:
        missing = next(case for case in self.data["cases"] if case["id"] == "legacy-missing-attach")
        empty = next(case for case in self.data["cases"] if case["id"] == "legacy-empty-attach")
        self.assertEqual(
            [event["name"] for event in missing["input"]["events"]],
            ["socket.accept", "socket.disconnect", "bridge.close", "process.terminate", "process.reap"],
        )
        self.assertEqual(
            [event["name"] for event in empty["input"]["events"]],
            ["socket.accept", "client.close", "bridge.close", "process.terminate", "process.reap"],
        )
        self.assertEqual(missing["expected"]["reattach"], "prohibited")
        self.assertEqual(empty["expected"]["reattach"], "prohibited")
        validate.validate_contract(self.data)

    def test_attach_reuses_same_identity_on_second_socket(self) -> None:
        case = next(case for case in self.data["cases"] if case["id"] == "attach-keepalive")
        events = case["input"]["events"]
        self.assertEqual(events[4]["name"], "registry.detach")
        self.assertEqual(events[5]["socket_ref"], "synthetic-socket-attach-b")
        self.assertEqual(events[6]["name"], "registry.reuse")
        self.assertEqual(events[7]["session_ref"], case["input"]["session_ref"])
        self.assertEqual(events[7]["process_ref"], case["input"]["process_ref"])
        self.assertEqual(case["expected"]["spawn_count"], 1)
        self.assertEqual(case["expected"]["registry_reuse_count"], 1)
        validate.validate_contract(self.data)

    def test_replacement_closes_old_socket_before_assignment(self) -> None:
        case = next(case for case in self.data["cases"] if case["id"] == "replacement-4409")
        events = case["input"]["events"]
        self.assertEqual(events[0]["name"], "old_socket_close")
        self.assertEqual(events[0]["code"], 4409)
        self.assertEqual(events[1]["name"], "replacement_assign")
        self.assertEqual(events[2]["result"], "ignored")
        self.assertTrue(case["expected"]["identity_preserved"])
        validate.validate_contract(self.data)

    def test_detach_ttl_allows_equality_and_expires_after(self) -> None:
        case = next(case for case in self.data["cases"] if case["id"] == "detach-window")
        self.assertEqual(
            [(probe["elapsed_seconds"], probe["outcome"]) for probe in case["input"]["probes"]],
            [(1799, "reattach-allowed"), (1800, "reattach-allowed"), (1801, "reattach-expired")],
        )
        validate.validate_contract(self.data)

    def test_logging_covers_two_frames_and_all_action_payloads(self) -> None:
        case = next(case for case in self.data["cases"] if case["id"] == "no-byte-logging")
        self.assertEqual(len(case["input"]["frames"]), 2)
        self.assertEqual(
            [action["kind"] for action in case["input"]["actions"]],
            ["input", "resize", "prompt", "tool"],
        )
        self.assertTrue(all(log["byte_payload_hex"] is None for log in case["input"]["logs"]))
        self.assertTrue(all(log["action_payload_hex"] is None for log in case["input"]["logs"]))
        self.assertEqual(case["input"]["retained"]["action_refs"], [])
        validate.validate_contract(self.data)

    def test_source_audit_binding_rejects_digest_size_and_revision_drift(self) -> None:
        for field, value in (
            ("sha256", "0" * 64),
            ("size_bytes", 1),
        ):
            candidate = copy.deepcopy(self.data)
            candidate["source_audit"]["artifacts"]["source-evidence.json"][field] = value
            with self.subTest(field=field):
                with self.assertRaises(validate.ValidationError):
                    validate.validate_contract(candidate)
        candidate = copy.deepcopy(self.data)
        candidate["source_audit"]["pinned_commit"]["sha"] = "0" * 40
        with self.assertRaises(validate.ValidationError):
            validate.validate_contract(candidate)

    def test_replay_tail_provenance_accepts_equal_old_and_new_bytes(self) -> None:
        candidate = copy.deepcopy(self.data)
        replay_case = next(case for case in candidate["cases"] if case["id"] == "replay-newest-tail")
        replay_case["input"]["output_segments"][0]["byte_hex"] = "42"
        validate.validate_contract(candidate)

    def test_baseline_json_schema_is_strict_and_derived(self) -> None:
        baseline_path = ROOT / "validation-baseline.json"
        baseline = validate.load_fixture(baseline_path)
        summary = validate.validate_baseline(baseline)
        self.assertEqual(summary["run_count"], 2)
        self.assertEqual(summary["artifact_size_bytes"], validate.artifact_bytes())

    def test_baseline_schema_mutations_fail_closed(self) -> None:
        baseline = validate.load_fixture(ROOT / "validation-baseline.json")
        mutations = []
        candidate = copy.deepcopy(baseline)
        candidate["environment"]["unexpected"] = True
        mutations.append(("environment-extra", candidate))
        candidate = copy.deepcopy(baseline)
        candidate["environment"]["python"] = 3.14
        mutations.append(("environment-type", candidate))
        candidate = copy.deepcopy(baseline)
        candidate["runs"][0]["distribution"]["unexpected"] = True
        mutations.append(("distribution-extra", candidate))
        candidate = copy.deepcopy(baseline)
        candidate["runs"][0]["distribution"]["median_ms"] = "55.171"
        mutations.append(("distribution-type", candidate))
        candidate = copy.deepcopy(baseline)
        candidate["runs"][0]["distribution"]["max_ms"] += 1.0
        mutations.append(("distribution-drift", candidate))
        candidate = copy.deepcopy(baseline)
        candidate["artifact_size_bytes"]["files"]["unexpected"] = 1
        mutations.append(("artifact-files-extra", candidate))
        candidate = copy.deepcopy(baseline)
        candidate["artifact_size_bytes"]["files"]["README.md"] = 1.0
        mutations.append(("artifact-files-type", candidate))
        candidate = copy.deepcopy(baseline)
        candidate["artifact_size_bytes"]["total"] += 1
        mutations.append(("artifact-total-drift", candidate))
        candidate = copy.deepcopy(baseline)
        candidate["artifact_content_sha256"]["files"]["README.md"] = "0" * 64
        mutations.append(("artifact-digest-drift", candidate))
        candidate = copy.deepcopy(baseline)
        candidate["artifact_content_sha256"]["manifest"] = "0" * 64
        mutations.append(("artifact-manifest-drift", candidate))
        candidate = copy.deepcopy(baseline)
        candidate["artifact_content_sha256"]["files"]["README.md"] = 3.14
        mutations.append(("artifact-digest-type", candidate))
        candidate = copy.deepcopy(baseline)
        candidate["artifact_content_sha256"]["files"]["unexpected"] = "0" * 64
        mutations.append(("artifact-digest-extra", candidate))
        for mutation_id, candidate in mutations:
            with self.subTest(mutation_id=mutation_id):
                with self.assertRaises(validate.ValidationError):
                    validate.validate_baseline(candidate)

    def test_baseline_duplicate_json_keys_are_rejected(self) -> None:
        baseline = validate.load_fixture(ROOT / "validation-baseline.json")
        serialized = json.dumps(baseline).replace(
            '"distribution": {', '"distribution": {}, "distribution": {', 1
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate-baseline.json"
            path.write_text(serialized, encoding="utf-8")
            with self.assertRaisesRegex(validate.ValidationError, "duplicate JSON key"):
                validate.load_fixture(path)


if __name__ == "__main__":
    unittest.main()
