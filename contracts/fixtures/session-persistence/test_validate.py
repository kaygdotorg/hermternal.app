#!/usr/bin/env python3
"""Regression tests for the synthetic C-07 session-persistence contract."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import validate  # noqa: E402


class SessionPersistenceValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = validate._load_json(validate.CASES_PATH, "cases")
        cls.baseline = validate._load_json(validate.BASELINE_PATH, "baseline")
        validate.validate_all(cls.document, cls.baseline)
        cls.cases = {case["id"]: case for case in cls.document["cases"]}

    def run_cli(self, optimized: bool = False, *extra: str) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend([str(ROOT / "validate.py"), *extra])
        return subprocess.run(command, check=False, capture_output=True, text=True)

    def evaluate_case_subprocess(self, case_id: str, optimized: bool = False) -> dict[str, object]:
        script = """
import importlib.util
import json
import sys
from pathlib import Path
root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("validate", root / "validate.py")
validate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validate)
case_id = sys.argv[2]
case_id, initial_state, context, events, notes = validate._case_definition_map()[case_id]
case = {"id": case_id, "initial_state": initial_state, "initial_context": context, "events": list(events), "expected": {}, "notes": notes}
print(json.dumps(validate.evaluate_case(case), sort_keys=True))
"""
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend(["-c", script, str(ROOT), case_id])
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        return json.loads(result.stdout)

    def redaction_probe_subprocess(self, values: list[str], optimized: bool = False) -> list[bool]:
        script = """
import importlib.util
import json
import sys
from pathlib import Path
root = Path(sys.argv[1])
values = json.loads(sys.argv[2])
spec = importlib.util.spec_from_file_location("validate", root / "validate.py")
validate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validate)
results = []
for value in values:
    try:
        validate._validate_redaction({"value": value})
    except validate.ContractError:
        results.append(False)
    else:
        results.append(True)
print(json.dumps(results))
"""
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend(["-c", script, str(ROOT), json.dumps(values)])
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        return json.loads(result.stdout)

    def test_checked_in_document_and_baseline_validate(self) -> None:
        case_count, artifact_bytes = validate.validate_all(self.document, self.baseline)
        self.assertEqual(case_count, 35)
        self.assertGreater(artifact_bytes, 0)
        self.assertEqual(len(self.document["states"]), 10)
        self.assertIsNone(self.baseline["threshold"])
        self.assertEqual(self.baseline["repetitions"], 30)

    def test_normal_and_optimized_cli_outputs_are_successful(self) -> None:
        normal = self.run_cli()
        optimized = self.run_cli(True)
        self.assertEqual(normal.returncode, 0, normal.stderr)
        self.assertEqual(optimized.returncode, 0, optimized.stderr)
        self.assertEqual(normal.stdout, optimized.stdout)
        self.assertEqual(normal.stderr, "")
        self.assertEqual(optimized.stderr, "")
        self.assertIn("states=10 cases=35", normal.stdout)

    def test_creation_and_lazy_persistence_boundaries(self) -> None:
        empty = self.cases["create-empty-draft"]["expected"]
        self.assertEqual(empty["final_state"], "empty")
        self.assertEqual(empty["selected_session"], "session-marker-001")
        self.assertEqual(empty["stored_session"], "stored-session-marker-001")
        self.assertFalse(empty["durable_row"])

        first_prompt = self.cases["first-prompt-persists-session"]["expected"]
        self.assertEqual(first_prompt["final_state"], "ready")
        self.assertTrue(first_prompt["durable_row"])
        self.assertEqual(first_prompt["persist_attempts"], 1)
        self.assertIn("session_row_persisted", first_prompt["effects"])

        duplicate = self.cases["duplicate-prompt-while-persisting"]["expected"]
        self.assertEqual(duplicate["final_state"], "pending_persist")
        self.assertEqual(duplicate["prompt_submissions"], 1)
        self.assertIn("duplicate_prompt_blocked", duplicate["effects"])

    def test_persistence_requires_matching_session_identity(self) -> None:
        no_identity = self.cases["prompt-without-session-identity-fails-closed"]["expected"]
        self.assertEqual(no_identity["final_state"], "incompatible")
        self.assertIn("prompt_without_session_identity", no_identity["effects"])

        missing_ack_identity = self.cases["persistence-ack-without-session-identity-fails-closed"]["expected"]
        self.assertEqual(missing_ack_identity["final_state"], "incompatible")
        self.assertFalse(missing_ack_identity["durable_row"])
        self.assertIn("persistence_identity_mismatch", missing_ack_identity["effects"])

        mismatched = self.cases["persistence-ack-with-mismatched-identity-fails-closed"]["expected"]
        self.assertEqual(mismatched["final_state"], "incompatible")
        self.assertFalse(mismatched["durable_row"])
        self.assertIn("persistence_identity_mismatch", mismatched["effects"])

    def test_persistence_failure_requires_explicit_retry(self) -> None:
        failed = self.cases["persistence-failure-preserves-draft"]["expected"]
        self.assertEqual(failed["final_state"], "failed")
        self.assertEqual(failed["error_kind"], "storage")
        self.assertFalse(failed["prompt_in_flight"])
        self.assertEqual(failed["draft"], "present")
        self.assertIn("automatic_prompt_retry_blocked", failed["effects"])

        retried = self.cases["persistence-retry-is-explicit"]["expected"]
        self.assertEqual(retried["final_state"], "ready")
        self.assertEqual(retried["persist_attempts"], 2)
        self.assertIn("explicit_retry_only", retried["effects"])

    def test_resume_reuses_durable_identity_and_server_history(self) -> None:
        restored = self.cases["resume-reopens-durable-session"]["expected"]
        self.assertEqual(restored["final_state"], "ready")
        self.assertEqual(restored["selected_session"], "session-marker-001")
        self.assertEqual(restored["stored_session"], "stored-session-marker-001")
        self.assertEqual(restored["history"], "present")
        self.assertEqual(restored["restore_barrier"], "passed")
        self.assertIn("server_history_reloaded", restored["effects"])

        missing = self.cases["resume-missing-fails-closed"]["expected"]
        self.assertEqual(missing["final_state"], "failed")
        self.assertEqual(missing["error_kind"], "resume_missing")
        self.assertIsNone(missing["selected_session"])
        self.assertIn("no_new_session_fallback", missing["effects"])

        concurrent = self.cases["duplicate-resume-request-is-deduplicated"]["expected"]
        self.assertEqual(concurrent["resume_attempts"], 1)
        self.assertIn("duplicate_resume_request_blocked", concurrent["effects"])

    def test_active_turn_and_empty_restore_invariants(self) -> None:
        active = self.cases["turn-completed-active-turn"]["expected"]
        self.assertEqual(active["final_state"], "ready")
        self.assertEqual(active["draft"], "empty")
        self.assertFalse(active["prompt_in_flight"])
        self.assertIn("turn_persisted_once", active["effects"])

        stale = self.cases["stale-turn-completed-fails-closed"]["expected"]
        self.assertEqual(stale["final_state"], "incompatible")
        self.assertIn("turn_completion_without_active_turn", stale["effects"])

        empty_restore = self.cases["empty-restore-requires-explicit-new-prompt"]["expected"]
        self.assertEqual(empty_restore["final_state"], "ready")
        self.assertEqual(empty_restore["history"], "empty")
        self.assertEqual(empty_restore["draft"], "present")
        self.assertTrue(empty_restore["prompt_in_flight"])
        self.assertEqual(empty_restore["persistence"], "available")

    def test_interruption_and_uncertain_delivery_never_auto_resend(self) -> None:
        interrupted = self.cases["confirmed-interruption-preserves-draft"]["expected"]
        self.assertEqual(interrupted["final_state"], "interrupted")
        self.assertFalse(interrupted["prompt_in_flight"])
        self.assertIn("queued_prompt_cleared", interrupted["effects"])
        self.assertIn("prompt_not_automatically_repeated", interrupted["effects"])

        uncertain = self.cases["transport-loss-enters-delivery-uncertain"]["expected"]
        self.assertEqual(uncertain["final_state"], "delivery_uncertain")
        self.assertEqual(uncertain["restore_barrier"], "pending")
        self.assertEqual(uncertain["prompt_retry"], "restore_before_user_decision")
        self.assertTrue(uncertain["transport_closed"])

        restored = self.cases["uncertain-resume-present-suppresses-duplicate"]["expected"]
        self.assertEqual(restored["final_state"], "ready")
        self.assertEqual(restored["prompt_retry"], "user_decision_after_source_reread")
        self.assertIn("duplicate_prompt_suppressed", restored["effects"])

        auto_retry = self.cases["automatic-prompt-retry-fails-closed"]["expected"]
        self.assertEqual(auto_retry["final_state"], "incompatible")
        self.assertTrue(auto_retry["automatic_prompt_retry_attempted"])
        self.assertIn("automatic_prompt_retry_blocked", auto_retry["effects"])

    def test_normal_and_optimized_case_regressions(self) -> None:
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                result = self.evaluate_case_subprocess("resume-reopens-durable-session", optimized)
                self.assertEqual(result["final_state"], "ready")
                self.assertEqual(result["stored_session"], "stored-session-marker-001")
                self.assertEqual(result["history"], "present")

                uncertain = self.evaluate_case_subprocess("uncertain-resume-present-suppresses-duplicate", optimized)
                self.assertEqual(uncertain["final_state"], "ready")
                self.assertEqual(uncertain["prompt_retry"], "user_decision_after_source_reread")

                malformed = self.evaluate_case_subprocess("malformed-persistence-result-fails-closed", optimized)
                self.assertEqual(malformed["final_state"], "incompatible")
                self.assertTrue(malformed["transport_closed"])

                stale = self.evaluate_case_subprocess("stale-turn-completed-fails-closed", optimized)
                self.assertEqual(stale["final_state"], "incompatible")
                self.assertIn("turn_completion_without_active_turn", stale["effects"])

                missing_identity = self.evaluate_case_subprocess("prompt-without-session-identity-fails-closed", optimized)
                self.assertEqual(missing_identity["final_state"], "incompatible")
                self.assertIn("prompt_without_session_identity", missing_identity["effects"])

    def test_foreign_unknown_and_close_boundaries_fail_closed(self) -> None:
        for case_id in (
            "foreign-resume-fails-closed",
            "unknown-event-fails-closed",
            "malformed-persistence-result-fails-closed",
        ):
            with self.subTest(case_id=case_id):
                result = self.cases[case_id]["expected"]
                self.assertEqual(result["final_state"], "incompatible")
                self.assertTrue(result["transport_closed"])
                self.assertEqual(result["error_kind"], "incompatible")
                self.assertIn("no_new_session_fallback", result["effects"])

        detached = self.cases["close-detach-preserves-durable-session"]["expected"]
        self.assertEqual(detached["final_state"], "closed")
        self.assertTrue(detached["durable_row"])
        self.assertEqual(detached["stored_session"], "stored-session-marker-001")
        self.assertTrue(detached["transport_closed"])

        for case_id in (
            "empty-close-without-durable-row-fails-closed",
            "pending-close-without-durable-row-fails-closed",
            "failed-close-without-durable-row-fails-closed",
        ):
            with self.subTest(case_id=case_id):
                result = self.cases[case_id]["expected"]
                self.assertEqual(result["final_state"], "incompatible")
                self.assertIn("close_without_durable_session", result["effects"])
                self.assertFalse(result["durable_row"])

    def test_baseline_identity_rejects_coordinated_samples_distributions_commands_and_environment(self) -> None:
        mutations: list[dict[str, object]] = []
        forged = copy.deepcopy(self.baseline)
        for mode in ("normal", "optimized"):
            forged[mode]["samples_ms"] = [1.0] * validate.BASELINE_REPETITIONS
            forged[mode]["distribution"] = validate._dist(forged[mode]["samples_ms"])
        mutations.append(forged)
        forged = copy.deepcopy(self.baseline)
        forged["normal"]["distribution"]["mean"] += 1.0
        mutations.append(forged)
        forged = copy.deepcopy(self.baseline)
        forged["normal"]["command"] = "python3 fabricated-validator.py"
        mutations.append(forged)
        forged = copy.deepcopy(self.baseline)
        forged["environment"] = {"platform": "synthetic-platform", "python": "3.13.0"}
        mutations.append(forged)

        with tempfile.TemporaryDirectory() as directory:
            for index, forged in enumerate(mutations):
                path = Path(directory) / f"forged-{index}.json"
                path.write_text(json.dumps(forged), encoding="utf-8")
                for optimized in (False, True):
                    with self.subTest(index=index, optimized=optimized):
                        result = self.run_cli(optimized, "--baseline", str(path))
                        self.assertEqual(result.returncode, 1)
                        self.assertEqual(result.stderr, "")
                        self.assertNotIn(str(path), result.stdout)
                        self.assertEqual(
                            json.loads(result.stdout),
                            {"error": {"code": "contract", "message": "session persistence fixture rejected"}},
                        )

    def test_redaction_rejects_sensitive_values_and_camel_keys_in_both_modes(self) -> None:
        rejected = [
            "Bearer synthetic-token",
            "Basic c2VjcmV0",
            "host=internal.example",
            "hostname: internal.example",
            "https://synthetic.invalid",
            "127.0.0.1:8080",
            "server.local",
            "/Users/alice/private.txt",
            "~/private.txt",
            "C:\\Users\\alice\\private.txt",
            "C:/Users/alice/private.txt",
            "\\\\server\\share\\private.txt",
            "password=synthetic",
            "accessToken: synthetic",
            "apiKey: synthetic",
            "clientSecret: synthetic",
            "prompt: synthetic",
            "transcript: synthetic",
        ]
        accepted = ["gateway.ready", "session-marker-001", validate.HERMES_SOURCE_SHA]
        rejected_keys = ["accessToken", "apiKey", "clientSecret", "prompt", "transcript"]
        for key in rejected_keys:
            with self.assertRaises(validate.ContractError):
                validate._validate_redaction({key: "synthetic-marker"})
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                self.assertEqual(self.redaction_probe_subprocess(rejected, optimized), [False] * len(rejected))
                self.assertEqual(self.redaction_probe_subprocess(accepted, optimized), [True] * len(accepted))

    def test_redaction_failures_run_through_real_validator_cli_in_both_modes(self) -> None:
        mutations = (
            "accessToken: synthetic-marker",
            "127.0.0.1:8080",
            "C:\\Users\\alice\\private.txt",
            "\\\\server\\share\\private.txt",
        )
        with tempfile.TemporaryDirectory() as directory:
            for index, value in enumerate(mutations):
                document = copy.deepcopy(self.document)
                document["source_observations"][0]["observation"] = value
                path = Path(directory) / f"redaction-{index}.json"
                path.write_text(json.dumps(document), encoding="utf-8")
                for optimized in (False, True):
                    with self.subTest(index=index, optimized=optimized):
                        result = self.run_cli(optimized, "--cases", str(path))
                        self.assertEqual(result.returncode, 1)
                        self.assertEqual(result.stderr, "")
                        self.assertNotIn(value, result.stdout)
                        self.assertNotIn(str(path), result.stdout)
                        self.assertEqual(
                            json.loads(result.stdout),
                            {"error": {"code": "contract", "message": "session persistence fixture rejected"}},
                        )

    def test_strict_json_rejects_duplicate_nonfinite_invalid_utf8_and_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mutations = {
                "duplicate.json": b'{"value":1,"value":2}',
                "nan.json": b'{"value":NaN}',
                "infinity.json": b'{"value":Infinity}',
                "overflow.json": b'{"value":1e9999}',
                "huge-int.json": (b'{"value":' + b"1" + (b"0" * validate.MAX_INTEGER_DIGITS) + b"}"),
                "deep.json": (b"[" * (validate.MAX_JSON_DEPTH + 2) + b"0" + b"]" * (validate.MAX_JSON_DEPTH + 2)),
                "invalid-utf8.json": b'{"value":"\xff"}',
            }
            for name, data in mutations.items():
                with self.subTest(name=name):
                    path = root / name
                    path.write_bytes(data)
                    with self.assertRaises(validate.ContractError):
                        validate._load_json(path, "synthetic input")

    def test_exact_schema_and_redacted_cli_failure(self) -> None:
        extra_key = copy.deepcopy(self.document)
        extra_key["unexpected"] = "marker"
        with self.assertRaises(validate.ContractError):
            validate.validate_document(extra_key)

        duplicate_id = copy.deepcopy(self.document)
        duplicate_id["cases"][1]["id"] = duplicate_id["cases"][0]["id"]
        with self.assertRaises(validate.ContractError):
            validate.validate_document(duplicate_id)

        marker = "synthetic-sensitive-marker"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad-cases.json"
            path.write_text('{"schema":"' + marker + '"}', encoding="utf-8")
            result = self.run_cli(False, "--cases", str(path))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        self.assertEqual(len(result.stdout.splitlines()), 1)
        self.assertNotIn(marker, result.stdout)
        self.assertNotIn(str(path), result.stdout)
        self.assertEqual(
            json.loads(result.stdout),
            {"error": {"code": "contract", "message": "session persistence fixture rejected"}},
        )

    def test_external_optimized_compile_succeeds(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "py_compile", str(ROOT / "validate.py")],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
