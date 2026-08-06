#!/usr/bin/env python3
"""Regression tests for the synthetic C-05 connection/restoration contract."""

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


class ConnectionRestorationValidationTests(unittest.TestCase):
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
case_id, initial_state, context, events, _ = validate._case_definition_map()[case_id]
case = {"initial_state": initial_state, "initial_context": context, "events": list(events)}
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

    def test_checked_in_document_and_baseline_validate(self) -> None:
        case_count, artifact_bytes = validate.validate_all(self.document, self.baseline)
        self.assertEqual(case_count, 45)
        self.assertGreater(artifact_bytes, 0)
        self.assertEqual(len(self.document["states"]), 11)
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
        self.assertIn("states=11 cases=45", normal.stdout)

    def test_gateway_and_compatibility_barriers(self) -> None:
        ready = self.cases["initial-connect-ready"]["expected"]
        self.assertEqual(ready["trace"], ["connecting", "handshaking", "ready", "restoring", "ready"])
        self.assertEqual(ready["final_state"], "ready")
        self.assertEqual(ready["compatibility_gate"], "passed")

        before_gateway = self.cases["send-before-gateway-ready"]["expected"]
        self.assertEqual(before_gateway["final_state"], "incompatible")
        self.assertIn("prompt_send_before_ready_blocked", before_gateway["effects"])

        missing_attestation = self.cases["attestation-mismatch-blocks"]["expected"]
        self.assertEqual(missing_attestation["final_state"], "incompatible")
        self.assertEqual(self.cases["probe-failure-blocks"]["expected"]["final_state"], "incompatible")
        self.assertEqual(self.cases["gates-before-gateway"]["expected"]["final_state"], "handshaking")

        timeout = self.cases["gateway-ready-timeout-fails"]["expected"]
        self.assertEqual(timeout["trace"], ["handshaking", "failed"])
        self.assertEqual(timeout["final_state"], "failed")
        self.assertEqual(timeout["decision"], "handshake_failed")
        self.assertTrue(timeout["transport_closed"])
        self.assertIn("gateway_ready_timeout", timeout["effects"])
        self.assertIn("transport_closed", timeout["effects"])
        self.assertIn("handshake_failed", timeout["effects"])

    def test_reconnect_uses_fresh_ticket_and_restores_before_retry(self) -> None:
        self.assertEqual(
            validate.RETRYABLE_METHODS,
            ("session.resume", "session.history", "session.status", "model.options"),
        )
        reconnect = self.cases["reconnect-fresh-ticket-and-restore"]["expected"]
        self.assertEqual(reconnect["ticket_generations"], [1, 2])
        self.assertLess(reconnect["trace"].index("restoring"), len(reconnect["trace"]) - 1)
        self.assertEqual(reconnect["final_state"], "ready")
        self.assertIn("server_session_restored", reconnect["effects"])
        self.assertEqual(reconnect["selected_session"], "session-marker-001")
        self.assertEqual(reconnect["selected_profile"], "profile-marker-001")
        self.assertEqual(reconnect["active_profile"], "profile-marker-001")
        self.assertEqual(reconnect["draft"], "present")

        no_fresh_ticket = self.cases["reconnect-without-fresh-ticket"]["expected"]
        self.assertEqual(no_fresh_ticket["final_state"], "auth_required")
        self.assertIn("fresh_ticket_required", no_fresh_ticket["effects"])
        self.assertEqual(self.cases["reconnect-ticket-reuse-blocked"]["expected"]["final_state"], "auth_required")

        blocked = self.cases["restore-before-idempotent-retry"]["expected"]
        self.assertEqual(blocked["final_state"], "incompatible")
        self.assertIn("retry_before_restore_blocked", blocked["effects"])
        allowed = self.cases["idempotent-retry-after-restore"]["expected"]
        self.assertEqual(allowed["final_state"], "ready")
        self.assertEqual(allowed["decision"], "idempotent_retry")

    def test_timeout_and_profile_drift_regressions_run_in_both_modes(self) -> None:
        for optimized in (False, True):
            with self.subTest(optimized=optimized, case_id="gateway-ready-timeout-fails"):
                timeout = self.evaluate_case_subprocess("gateway-ready-timeout-fails", optimized)
                self.assertEqual(timeout["final_state"], "failed")
                self.assertEqual(timeout["decision"], "handshake_failed")
                self.assertTrue(timeout["transport_closed"])
                self.assertIn("gateway_ready_timeout", timeout["effects"])
                self.assertIn("handshake_failed", timeout["effects"])

            for case_id in ("reconnect-profile-drift-rejected", "restore-profile-drift-rejected"):
                with self.subTest(optimized=optimized, case_id=case_id):
                    drift = self.evaluate_case_subprocess(case_id, optimized)
                    self.assertEqual(drift["final_state"], "incompatible")
                    self.assertEqual(drift["decision"], "profile_mismatch")
                    self.assertEqual(drift["selected_profile"], "profile-marker-001")
                    self.assertEqual(drift["active_profile"], "profile-marker-002")
                    self.assertTrue(drift["transport_closed"])
                    self.assertIn("profile_drift_observed", drift["effects"])
                    self.assertIn("profile_drift_rejected", drift["effects"])

    def test_uncertain_delivery_is_preserved_and_deferred_to_c06(self) -> None:
        uncertain = self.cases["prompt-transport-loss-uncertain"]["expected"]
        self.assertEqual(uncertain["final_state"], "delivery_uncertain")
        self.assertEqual(uncertain["restore_barrier"], "pending")
        self.assertEqual(uncertain["prompt_retry"], "deferred_to_C-06")
        self.assertEqual(uncertain["selected_session"], "session-marker-001")
        self.assertEqual(uncertain["draft"], "present")
        self.assertFalse(uncertain["prompt_auto_resubmitted"])

        restored = self.cases["uncertain-restore-barrier"]["expected"]
        self.assertEqual(restored["trace"], ["delivery_uncertain", "restoring", "ready"])
        self.assertEqual(restored["restore_barrier"], "passed")
        self.assertEqual(restored["prompt_retry"], "deferred_to_C-06")

        auto_retry = self.cases["prompt-auto-resubmit-blocked"]["expected"]
        self.assertEqual(auto_retry["final_state"], "incompatible")
        self.assertFalse(auto_retry["prompt_auto_resubmitted"])

    def test_cancellation_and_sign_out_are_safe(self) -> None:
        for case_id in ("cancel-connecting", "cancel-restoring", "cancel-reconnecting"):
            with self.subTest(case_id=case_id):
                result = self.cases[case_id]["expected"]
                self.assertEqual(result["trace"][-2:], ["closing", "offline"])
                self.assertIn("reconnect_suppressed", result["effects"])

        signed_out = self.cases["sign-out-clears-session-preserves-draft"]["expected"]
        self.assertIsNone(signed_out["selected_session"])
        self.assertEqual(signed_out["draft"], "present")
        self.assertIn("session_reference_cleared", signed_out["effects"])
        self.assertIn("draft_preserved", signed_out["effects"])

    def test_known_and_unknown_close_outcomes_are_distinct(self) -> None:
        expected = {
            "known-auth-close": "auth_required",
            "known-host-close-incompatible": "incompatible",
            "known-chat-disabled-close": "incompatible",
            "known-peer-rejected-close": "failed",
            "known-attachment-close": "failed",
            "known-pty-exited-close": "failed",
            "known-backend-failure": "failed",
            "unknown-close-fails-closed": "incompatible",
        }
        for case_id, state in expected.items():
            with self.subTest(case_id=case_id):
                self.assertEqual(self.cases[case_id]["expected"]["final_state"], state)
        self.assertIn("unknown_close_code_blocked", self.cases["unknown-close-fails-closed"]["expected"]["effects"])

    def test_strict_json_rejects_duplicate_nonfinite_overflow_and_bounded_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mutations = {
                "duplicate.json": '{"value":1,"value":2}',
                "nan.json": '{"value":NaN}',
                "infinity.json": '{"value":Infinity}',
                "overflow.json": '{"value":1e9999}',
                "huge-int.json": '{"value":' + "1" + ("0" * validate.MAX_INTEGER_DIGITS) + '}',
                "deep.json": "[" * (validate.MAX_JSON_DEPTH + 2) + "0" + "]" * (validate.MAX_JSON_DEPTH + 2),
            }
            for name, text in mutations.items():
                with self.subTest(name=name):
                    path = root / name
                    path.write_text(text, encoding="utf-8")
                    with self.assertRaises(validate.ContractError):
                        validate._load_json(path, "synthetic input")

    def test_exact_schema_types_and_order_fail_closed(self) -> None:
        wrong_bool = copy.deepcopy(self.document)
        wrong_bool["cases"][0]["initial_context"]["ticket_generation"] = True
        with self.assertRaises(validate.ContractError):
            validate.validate_document(wrong_bool)

        extra_key = copy.deepcopy(self.document)
        extra_key["unexpected"] = "marker"
        with self.assertRaises(validate.ContractError):
            validate.validate_document(extra_key)

        duplicate_id = copy.deepcopy(self.document)
        duplicate_id["cases"][1]["id"] = duplicate_id["cases"][0]["id"]
        with self.assertRaises(validate.ContractError):
            validate.validate_document(duplicate_id)

    def test_failure_output_is_one_line_and_redacted(self) -> None:
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
        payload = json.loads(result.stdout)
        self.assertEqual(payload, {"error": {"code": "contract", "message": "connection restoration fixture rejected"}})

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
