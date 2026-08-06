"""Regression tests for the synthetic C-06 uncertain-delivery contract."""

from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import validate


ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = ROOT.parents[2]
CHAT_PATH = REPOSITORY_ROOT / "contracts" / "state-models" / "chat.md"
CASES_PATH = ROOT / "cases.json"
BASELINE_PATH = ROOT / "validation-baseline.json"


class UncertainDeliveryValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = validate.load_json(CASES_PATH, "cases")
        cls.baseline = validate.load_json(BASELINE_PATH, "baseline")
        cls.cases = {case["id"]: case for case in cls.document["cases"]}

    def run_cli(self, optimized: bool = False, *arguments: str, cwd: Path | None = None, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend([str(ROOT / "validate.py"), *arguments])
        return subprocess.run(command, capture_output=True, text=True, check=False, cwd=cwd, timeout=timeout)

    def assert_cli_success_both_modes(self) -> None:
        for optimized in (False, True):
            result = self.run_cli(optimized)
            with self.subTest(optimized=optimized):
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, "")
                self.assertEqual(result.stdout, "uncertain_delivery_validation=ok cases=26 benchmark_samples=60\n")

    def assert_cli_failure_both_modes(self, *arguments: str, forbidden: str | None = None) -> None:
        for optimized in (False, True):
            result = self.run_cli(optimized, *arguments)
            with self.subTest(optimized=optimized, arguments=arguments):
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, '{"error":{"code":"contract","message":"uncertain delivery fixture rejected"}}\n')
                self.assertLessEqual(len(result.stderr), validate.MAX_ERROR_LENGTH)
                self.assertNotIn("Traceback", result.stderr)
                if forbidden is not None:
                    self.assertNotIn(forbidden, result.stderr)

    def write_json(self, directory: Path, name: str, value: object) -> Path:
        path = directory / name
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        return path

    def assert_cases_mutation_fails_both_modes(self, candidate: dict[str, object], name: str = "mutated-cases.json") -> None:
        with tempfile.TemporaryDirectory() as directory:
            cases_path = self.write_json(Path(directory), name, candidate)
            self.assert_cli_failure_both_modes("--cases", str(cases_path))

    def test_canonical_document_and_baseline_validate(self) -> None:
        self.assertEqual(validate.validate_all(self.document, self.baseline), 26)
        self.assertEqual(self.baseline["threshold"], None)
        self.assertEqual(self.baseline["normal"]["repetitions"], 30)
        self.assertEqual(self.baseline["optimized"]["repetitions"], 30)
        self.assertEqual(len(self.baseline["normal"]["samples_ms"]), 30)
        self.assertEqual(len(self.baseline["optimized"]["samples_ms"]), 30)

    def test_normal_and_optimized_cli_are_real_regressions(self) -> None:
        self.assert_cli_success_both_modes()

    def test_required_uncertain_delivery_states_are_executable(self) -> None:
        present = self.cases["timeout-present-after-restore"]["expected"]
        self.assertEqual(present["final_state"], "completed")
        self.assertEqual(present["restore_barrier"], "passed")
        self.assertEqual(present["submission_count"], 1)
        self.assertEqual(present["outward_changes"], 1)
        self.assertEqual(present["prompt_retry"], "none")

        absent = self.cases["websocket-close-absent-idle"]["expected"]
        self.assertEqual(absent["final_state"], "ready")
        self.assertEqual(absent["draft_state"], "present")
        self.assertEqual(absent["prompt_retry"], "explicit_user_only")
        self.assertTrue(absent["explicit_action_required"])

        rejection = self.cases["confirmed-rejection"]["expected"]
        self.assertEqual(rejection["final_state"], "failed")
        self.assertEqual(rejection["decision"], "confirmed_rejection")
        self.assertEqual(rejection["draft_state"], "present")

        for case_id in ("timeout-present-after-restore", "websocket-close-absent-idle", "app-suspension-absent-idle-explicit-resend", "process-loss-present-running"):
            with self.subTest(case_id=case_id):
                reasons = [event.get("reason") for event in self.cases[case_id]["events"] if event["kind"] == "transport_loss"]
                self.assertEqual(len(reasons), 1)
                self.assertIn(reasons[0], validate.UNCERTAIN_REASONS)

    def test_explicit_resend_and_duplicate_prevention(self) -> None:
        resend = self.cases["app-suspension-absent-idle-explicit-resend"]["expected"]
        self.assertEqual(resend["submission_count"], 2)
        self.assertEqual(resend["outward_changes"], 2)
        self.assertEqual(resend["duplicate_attempts"], 0)
        self.assertEqual(resend["decision"], "resent_after_absent_idle")

        duplicate = self.cases["duplicate-submit-blocked"]["expected"]
        self.assertEqual(duplicate["submission_count"], 1)
        self.assertEqual(duplicate["duplicate_attempts"], 1)
        self.assertEqual(duplicate["outward_changes"], 1)
        self.assertEqual(duplicate["decision"], "duplicate_blocked")

        no_third_send = self.cases["resend-unknown-no-third-send"]["expected"]
        self.assertEqual(no_third_send["submission_count"], 2)
        self.assertEqual(no_third_send["outward_changes"], 2)
        self.assertEqual(no_third_send["contract_error"], "prompt_retry_requires_restore")

    def test_interrupt_cancel_signout_and_pending_are_safe(self) -> None:
        self.assertEqual(self.cases["interrupt-confirmed"]["expected"]["decision"], "interrupt_confirmed")
        self.assertEqual(self.cases["interrupt-unknown-after-close"]["expected"]["final_state"], "streaming")
        self.assertEqual(self.cases["cancel-before-submit"]["expected"]["outward_changes"], 0)
        signed_out = self.cases["sign-out-during-uncertainty"]["expected"]
        self.assertIsNone(signed_out["selected_session"])
        self.assertEqual(signed_out["final_transport_state"], "offline")
        self.assertEqual(signed_out["draft_state"], "present")
        self.assertEqual(self.cases["pending-restore-evidence"]["expected"]["final_state"], "restoring")
        kept = self.cases["keep-draft-before-restore"]
        kept_result = validate.evaluate_case(kept)
        self.assertEqual(kept_result, kept["expected"])
        self.assertEqual(kept_result["trace"], ["delivery_uncertain", "restoring", "ready", "submitting", "completed"])
        self.assertEqual(kept_result["submission_count"], 2)
        self.assertEqual(kept_result["decision"], "resent_after_absent_idle")

    def test_strict_loader_rejects_duplicate_nonfinite_overflow_and_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mutations = {
                "duplicate.json": '{"value":1,"value":2}',
                "nested-duplicate.json": '{"outer":{"value":1,"value":2}}',
                "nan.json": '{"value":NaN}',
                "infinity.json": '{"value":Infinity}',
                "overflow.json": '{"value":1e9999}',
                "huge-int.json": '{"value":' + ("9" * (validate.MAX_INTEGER_DIGITS + 1)) + '}',
                "long-key.json": '{"' + ("k" * (validate.MAX_STRING_LENGTH + 1)) + '":1}',
                "deep.json": "[" * (validate.MAX_JSON_DEPTH + 2) + "0" + "]" * (validate.MAX_JSON_DEPTH + 2),
            }
            for name, text in mutations.items():
                path = root / name
                path.write_text(text, encoding="utf-8")
                with self.subTest(name=name):
                    with self.assertRaises(validate.ContractError):
                        validate.load_json(path, "synthetic input")

    def test_exact_types_and_semantic_mutations_fail_closed(self) -> None:
        wrong_bool = copy.deepcopy(self.document)
        wrong_bool["cases"][0]["initial"]["submission_count"] = True
        with self.assertRaises(validate.ContractError):
            validate.validate_document(wrong_bool)

        wrong_result = copy.deepcopy(self.document)
        wrong_result["cases"][1]["events"][0]["result"] = "rejected"
        with self.assertRaises(validate.ContractError):
            validate.validate_document(wrong_result)

        wrong_trace = copy.deepcopy(self.document)
        wrong_trace["cases"][2]["expected"]["trace"] = ["ready", "completed"]
        with self.assertRaises(validate.ContractError):
            validate.validate_document(wrong_trace)

        extra_key = copy.deepcopy(self.document)
        extra_key["cases"][0]["unexpected"] = "marker"
        with self.assertRaises(validate.ContractError):
            validate.validate_document(extra_key)

    def test_redaction_rejects_raw_material_and_sensitive_keys(self) -> None:
        mutations = (
            ("ordinary prompt prose", "Please summarize this private conversation.", "redaction_value"),
            ("dotted JWT", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature", "redaction_value"),
            ("ghp token", "ghp_1234567890abcdefghijk", "redaction_value"),
            ("host", "internal.example", "redaction_value"),
            ("credential", "Bearer synthetic-token", "redaction_value"),
            ("base64", "iVBORw0KGgo", "redaction_value"),
            ("relative path", "../private/prompt.txt", "redaction_value"),
            ("windows path", "C:\\private\\prompt.txt", "redaction_value"),
            ("ipv6 host", "2001:db8::1", "redaction_value"),
            ("api key", "api_key=sk_test_123456789", "redaction_value"),
            ("bare project key", "sk-proj-1234567890abcdef", "redaction_value"),
            ("windows users path", "C:/Users/alice/private/prompt.txt", "redaction_value"),
        )
        for name, value, code in mutations:
            candidate = copy.deepcopy(self.document)
            candidate["cases"][0]["notes"] = value
            with self.subTest(name=name):
                with self.assertRaises(validate.ContractError) as context:
                    validate.validate_document(candidate)
                self.assertEqual(context.exception.code, code)

        forbidden_key = copy.deepcopy(self.document)
        forbidden_key["cases"][0]["notes"] = {"prompt_text": "not retained"}
        with self.assertRaises(validate.ContractError) as context:
            validate.validate_document(forbidden_key)
        self.assertEqual(context.exception.code, "redaction_key")

    def test_real_cli_failures_are_bounded_and_do_not_echo_paths_or_markers(self) -> None:
        candidate = copy.deepcopy(self.document)
        marker = "synthetic-sensitive-marker"
        candidate["cases"][0]["notes"] = marker
        with tempfile.TemporaryDirectory() as directory:
            cases_path = self.write_json(Path(directory), "cases.json", candidate)
            self.assert_cli_failure_both_modes("--cases", str(cases_path), forbidden=marker)

    def test_real_cli_rejects_long_keys_and_special_paths_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            long_key = root / "long-key.json"
            long_key.write_text(json.dumps({"k" * (validate.MAX_STRING_LENGTH + 1): 1}), encoding="utf-8")
            self.assert_cli_failure_both_modes("--cases", str(long_key))
            oversized = root / "oversized.json"
            oversized.write_bytes(b"x" * (validate.MAX_JSON_BYTES + 1))
            self.assert_cli_failure_both_modes("--cases", str(oversized))
            special_directory = root / "cases-directory"
            special_directory.mkdir()
            self.assert_cli_failure_both_modes("--cases", str(special_directory))
            fifo = root / "cases.fifo"
            os.mkfifo(fifo)
            for optimized in (False, True):
                with self.subTest(kind="fifo", optimized=optimized):
                    try:
                        result = self.run_cli(optimized, "--cases", str(fifo), timeout=2)
                    except subprocess.TimeoutExpired as exc:
                        self.fail(f"special path blocked: {exc}")
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, '{"error":{"code":"contract","message":"uncertain delivery fixture rejected"}}\n')

    def test_real_cli_rejects_semantic_mutations_in_both_modes(self) -> None:
        candidate = copy.deepcopy(self.document)
        candidate["cases"][3]["events"][5]["prompt_presence"] = "present"
        self.assert_cases_mutation_fails_both_modes(candidate)

        self.assert_cli_failure_both_modes("--unknown-secret-flag")

    def test_real_cli_rejects_gateway_transport_draft_and_initial_mutations(self) -> None:
        mutations: list[dict[str, object]] = []

        missing_gateway = copy.deepcopy(self.document)
        missing_gateway["cases"][1]["events"].pop(0)
        mutations.append(missing_gateway)

        incompatible_ready = copy.deepcopy(self.document)
        incompatible_ready["cases"][1]["initial"]["transport_state"] = "reconnecting"
        mutations.append(incompatible_ready)

        absent_draft = copy.deepcopy(self.document)
        absent_draft["cases"][1]["initial"]["draft_state"] = "absent"
        mutations.append(absent_draft)

        uncertain_absent_draft = copy.deepcopy(self.document)
        uncertain_case = next(case for case in uncertain_absent_draft["cases"] if case["id"] == "idempotent-read-retry")
        uncertain_case["initial"]["draft_state"] = "absent"
        mutations.append(uncertain_absent_draft)

        missing_active_request = copy.deepcopy(self.document)
        missing_active_request["cases"][2]["initial"]["active_request_ref"] = None
        mutations.append(missing_active_request)

        empty_active_session = copy.deepcopy(self.document)
        empty_active_session["cases"][0]["initial"]["transport_state"] = "handshaking"
        mutations.append(empty_active_session)

        status_read_not_recovered = copy.deepcopy(self.document)
        status_read_not_recovered["cases"][8]["events"][2]["method"] = "session.status"
        status_read_not_recovered["cases"][8]["events"][3]["method"] = "session.history"
        mutations.append(status_read_not_recovered)

        for method in ("session.history", "session.status", "model.options"):
            retry_without_gateway = copy.deepcopy(self.document)
            retry_case = next(case for case in retry_without_gateway["cases"] if case["id"] == "idempotent-read-retry")
            retry_case["events"].insert(1, {"kind": "automatic_retry", "method": method})
            mutations.append(retry_without_gateway)

        stale_history_after_failure = copy.deepcopy(self.document)
        stale_history_case = next(case for case in stale_history_after_failure["cases"] if case["id"] == "idempotent-read-retry")
        stale_history_case["events"].insert(5, {"kind": "read_retry", "method": "session.history", "result": "transient_error"})
        mutations.append(stale_history_after_failure)

        for index, candidate in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assert_cases_mutation_fails_both_modes(candidate, f"gateway-state-{index}.json")

    def test_real_cli_rejects_state_identity_and_correlated_event_mutations(self) -> None:
        state_mutations: list[dict[str, object]] = []

        changed_meaning = copy.deepcopy(self.document)
        changed_meaning["states"][0]["meaning"] = "A different meaning."
        state_mutations.append(changed_meaning)

        changed_terminal = copy.deepcopy(self.document)
        changed_terminal["states"][0]["terminal"] = True
        state_mutations.append(changed_terminal)

        changed_action_order = copy.deepcopy(self.document)
        actions = changed_action_order["states"][0]["allowed_actions"]
        actions[:] = list(reversed(actions))
        state_mutations.append(changed_action_order)

        changed_action_inventory = copy.deepcopy(self.document)
        changed_action_inventory["states"][0]["allowed_actions"] = ["not-a-contract-action"]
        state_mutations.append(changed_action_inventory)

        for index, candidate in enumerate(state_mutations):
            with self.subTest(kind="state", mutation=index):
                self.assert_cases_mutation_fails_both_modes(candidate, f"state-identity-{index}.json")

        stale_empty_event = copy.deepcopy(self.document)
        stale_empty_event["cases"][0]["events"] = [
            {
                "kind": "server_event",
                "name": "message.complete",
                "request_ref": "request-marker-001",
                "turn_ref": "turn-marker-001",
                "session_ref": "session-marker-001",
            }
        ]
        self.assert_cases_mutation_fails_both_modes(stale_empty_event, "stale-empty-event.json")

        stale_completed_event = copy.deepcopy(self.document)
        stale_completed_event["cases"][1]["events"].append(
            {
                "kind": "server_event",
                "name": "message.delta",
                "request_ref": "request-marker-001",
                "turn_ref": "turn-marker-001",
                "session_ref": "session-marker-001",
            }
        )
        self.assert_cases_mutation_fails_both_modes(stale_completed_event, "stale-completed-event.json")

        stale_failed_event = copy.deepcopy(self.document)
        stale_failed_event["cases"][6]["events"].append(
            {
                "kind": "server_event",
                "name": "message.complete",
                "request_ref": "request-marker-001",
                "turn_ref": "turn-marker-001",
                "session_ref": "session-marker-001",
            }
        )
        self.assert_cases_mutation_fails_both_modes(stale_failed_event, "stale-failed-event.json")

        mismatched_request = copy.deepcopy(self.document)
        mismatched_request["cases"][1]["events"][2]["request_ref"] = "request-marker-002"
        self.assert_cases_mutation_fails_both_modes(mismatched_request, "mismatched-request.json")

        mismatched_turn = copy.deepcopy(self.document)
        mismatched_turn["cases"][1]["events"][2]["turn_ref"] = "turn-marker-002"
        self.assert_cases_mutation_fails_both_modes(mismatched_turn, "mismatched-turn.json")

        mismatched_session = copy.deepcopy(self.document)
        mismatched_session["cases"][1]["events"][2]["session_ref"] = "session-marker-002"
        self.assert_cases_mutation_fails_both_modes(mismatched_session, "mismatched-session.json")

    def test_sign_out_latch_and_transient_restore_recovery_are_regressions(self) -> None:
        signed_out_case = self.cases["sign-out-during-uncertainty"]
        signed_out_result = validate.evaluate_case(signed_out_case)
        self.assertEqual(signed_out_result, signed_out_case["expected"])
        self.assertEqual(signed_out_result["submission_count"], 1)
        self.assertEqual(signed_out_result["outward_changes"], 1)
        self.assertEqual(signed_out_result["selected_session"], None)
        self.assertEqual(signed_out_result["final_transport_state"], "offline")
        self.assertEqual(signed_out_result["contract_error"], "signed_out_latch")
        self.assertEqual(signed_out_result["decision"], "signed_out_latch")

        sign_out_only = copy.deepcopy(signed_out_case)
        sign_out_only["events"] = [{"kind": "sign_out"}]
        sign_out_only_result = validate.evaluate_case(sign_out_only)
        self.assertEqual(sign_out_only_result["final_state"], "empty")
        self.assertEqual(sign_out_only_result["final_transport_state"], "offline")
        self.assertFalse(sign_out_only_result["explicit_action_required"])
        self.assertEqual(sign_out_only_result["prompt_retry"], "blocked")

        recovered_case = self.cases["idempotent-read-retry"]
        recovered_result = validate.evaluate_case(recovered_case)
        self.assertEqual(recovered_result, recovered_case["expected"])
        self.assertEqual(recovered_result["idempotent_collection_retries"], 1)
        self.assertEqual(recovered_result["restore_barrier"], "passed")
        self.assertEqual(recovered_result["prompt_retry"], "explicit_user_only")

        unrecovered_case = self.cases["restore-transient-without-recovery"]
        unrecovered_result = validate.evaluate_case(unrecovered_case)
        self.assertEqual(unrecovered_result["restore_barrier"], "inconclusive")
        self.assertEqual(unrecovered_result["contract_error"], "restore_history_read_failed")
        self.assertEqual(unrecovered_result["prompt_retry"], "blocked")
        self.assert_cli_success_both_modes()

    def test_forged_baseline_samples_commands_and_environment_fail(self) -> None:
        mutations: list[dict[str, object]] = []
        forged_samples = copy.deepcopy(self.baseline)
        forged_samples["normal"]["samples_ms"] = [1.0] * 30
        forged_samples["normal"]["distribution"] = validate._distribution(forged_samples["normal"]["samples_ms"])
        mutations.append(forged_samples)

        forged_command = copy.deepcopy(self.baseline)
        forged_command["optimized"]["command"] = "python3 fabricated-validator.py"
        mutations.append(forged_command)

        forged_environment = copy.deepcopy(self.baseline)
        forged_environment["environment"]["python"] = "3.13.0"
        mutations.append(forged_environment)

        forged_repetitions = copy.deepcopy(self.baseline)
        forged_repetitions["normal"]["repetitions"] = 30.0
        mutations.append(forged_repetitions)

        forged_distribution_order = copy.deepcopy(self.baseline)
        distribution = forged_distribution_order["optimized"]["distribution"]
        forged_distribution_order["optimized"]["distribution"] = {key: distribution[key] for key in reversed(tuple(distribution.keys()))}
        mutations.append(forged_distribution_order)

        forged_overflow = copy.deepcopy(self.baseline)
        forged_overflow["normal"]["samples_ms"] = [1e308] * 30
        forged_overflow["normal"]["distribution"] = {
            "count": 30,
            "minimum_ms": 1e308,
            "maximum_ms": 1e308,
            "mean_ms": 1e308,
            "median_ms": 1e308,
            "p95_ms": 1e308,
        }
        mutations.append(forged_overflow)

        forged_distribution_value = copy.deepcopy(self.baseline)
        forged_distribution_value["optimized"]["distribution"]["mean_ms"] = 0.0
        mutations.append(forged_distribution_value)

        with tempfile.TemporaryDirectory() as directory:
            for index, baseline in enumerate(mutations):
                baseline_path = self.write_json(Path(directory), f"baseline-{index}.json", baseline)
                self.assert_cli_failure_both_modes("--baseline", str(baseline_path))

    def test_canonical_fixture_and_validator_rebinding_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copied = root / "uncertain-delivery"
            copied.mkdir()
            for name in ("README.md", "cases.json", "validate.py", "test_validate.py", "validation-baseline.json"):
                shutil.copy2(ROOT / name, copied / name)
            copied_chat = root / "chat.md"
            shutil.copy2(CHAT_PATH, copied_chat)

            copied_cases = root / "copied-cases.json"
            shutil.copy2(ROOT / "cases.json", copied_cases)
            copied_baseline = root / "copied-baseline.json"
            shutil.copy2(ROOT / "validation-baseline.json", copied_baseline)
            for arguments, kind in ((("--cases", str(copied_cases)), "cases-path"), (("--baseline", str(copied_baseline)), "baseline-path")):
                for optimized in (False, True):
                    result = self.run_cli(optimized, *arguments)
                    with self.subTest(kind=kind, optimized=optimized):
                        self.assertEqual(result.returncode, 1)
                        self.assertEqual(result.stdout, "")
                        self.assertEqual(result.stderr, '{"error":{"code":"contract","message":"uncertain delivery fixture rejected"}}\n')

            mutated_cases = json.loads((copied / "cases.json").read_text(encoding="utf-8"))
            mutated_cases["cases"][0]["notes"] = "changed-but-schema-valid"
            (copied / "cases.json").write_text(json.dumps(mutated_cases), encoding="utf-8")
            for optimized in (False, True):
                command = [sys.executable]
                if optimized:
                    command.append("-O")
                command.append(str(copied / "validate.py"))
                result = subprocess.run(command, capture_output=True, text=True, check=False)
                with self.subTest(kind="cases", optimized=optimized):
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, '{"error":{"code":"contract","message":"uncertain delivery fixture rejected"}}\n')

            shutil.copy2(ROOT / "cases.json", copied / "cases.json")
            validator_path = copied / "validate.py"
            validator_path.write_text(validator_path.read_text(encoding="utf-8") + "\n# synthetic source mutation\n", encoding="utf-8")
            for optimized in (False, True):
                command = [sys.executable]
                if optimized:
                    command.append("-O")
                command.append(str(validator_path))
                result = subprocess.run(command, capture_output=True, text=True, check=False)
                with self.subTest(kind="source", optimized=optimized):
                    self.assertEqual(result.returncode, 1)
                    self.assertNotIn("Traceback", result.stderr)

    def test_coordinated_copied_repository_rebinding_attack_fails_both_modes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            copied_repo = Path(directory) / "copied-repository"
            head = subprocess.check_output(["git", "-C", str(REPOSITORY_ROOT), "rev-parse", "HEAD"], text=True).strip()
            clone = subprocess.run(
                ["git", "clone", "--no-local", str(REPOSITORY_ROOT), str(copied_repo)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(clone.returncode, 0, clone.stderr)
            checkout = subprocess.run(
                ["git", "-C", str(copied_repo), "checkout", "--detach", head],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(checkout.returncode, 0, checkout.stderr)
            copied_fixture = copied_repo / "contracts" / "fixtures" / "uncertain-delivery"
            copied_chat = copied_repo / "contracts" / "state-models" / "chat.md"

            cases = json.loads((copied_fixture / "cases.json").read_text(encoding="utf-8"))
            cases["cases"][0]["notes"] = "coordinated prompt prose rebinding"
            (copied_fixture / "cases.json").write_text(json.dumps(cases, indent=2) + "\n", encoding="utf-8")
            (copied_fixture / "README.md").write_text((copied_fixture / "README.md").read_text(encoding="utf-8") + "\nrebound evidence\n", encoding="utf-8")
            (copied_fixture / "test_validate.py").write_text((copied_fixture / "test_validate.py").read_text(encoding="utf-8") + "\n# rebound tests\n", encoding="utf-8")
            copied_chat.write_text(copied_chat.read_text(encoding="utf-8") + "\nrebound contract\n", encoding="utf-8")

            validator_path = copied_fixture / "validate.py"
            validator_text = validator_path.read_text(encoding="utf-8") + "\n# rebound validator\n"
            for name in ("README.md", "cases.json", "test_validate.py", "chat.md"):
                old_digest = validate.EXPECTED_BOUND_SHA256[name]
                validator_text = validator_text.replace(f'"{name}": "{old_digest}"', f'"{name}": "' + ("0" * 64) + '"')
            validator_path.write_text(validator_text, encoding="utf-8")
            rebound_source_digest = validate._source_digest(validator_path)[1]
            old_source_digest = validate.EXPECTED_BOUND_SHA256["validate.py"]
            validator_text = validator_text.replace(f'"validate.py": "{old_source_digest}"', f'"validate.py": "{rebound_source_digest}"')
            validator_path.write_text(validator_text, encoding="utf-8")

            baseline = json.loads((copied_fixture / "validation-baseline.json").read_text(encoding="utf-8"))
            artifacts, manifest = validate._artifact_manifest(copied_fixture)
            baseline["artifacts"] = artifacts
            baseline["artifact_manifest_sha256"] = manifest
            baseline_path = copied_fixture / "validation-baseline.json"
            baseline_path.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
            rebound_baseline_digest = __import__("hashlib").sha256(baseline_path.read_bytes()).hexdigest()
            validator_text = validator_path.read_text(encoding="utf-8").replace(validate.EXPECTED_BASELINE_SHA256, rebound_baseline_digest)
            validator_path.write_text(validator_text, encoding="utf-8")

            for optimized in (False, True):
                command = [sys.executable]
                if optimized:
                    command.append("-O")
                command.append(str(copied_fixture / "validate.py"))
                result = subprocess.run(command, capture_output=True, text=True, check=False)
                with self.subTest(optimized=optimized):
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, '{"error":{"code":"contract","message":"uncertain delivery fixture rejected"}}\n')
                    self.assertLessEqual(len(result.stderr), validate.MAX_ERROR_LENGTH)

    def test_compile_in_both_modes_without_worktree_cache(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for optimized in (False, True):
                command = [sys.executable]
                if optimized:
                    command.append("-O")
                command.extend(["-m", "py_compile", str(ROOT / "validate.py"), str(ROOT / "test_validate.py")])
                result = subprocess.run(command, capture_output=True, text=True, check=False, env={**__import__("os").environ, "PYTHONPYCACHEPREFIX": directory})
                with self.subTest(optimized=optimized):
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
