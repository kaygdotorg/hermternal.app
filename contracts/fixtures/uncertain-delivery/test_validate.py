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
        cls.reviewed_commit = subprocess.check_output(
            ["git", "-C", str(REPOSITORY_ROOT), "rev-parse", "HEAD^{commit}"],
            text=True,
        ).strip()

    def canonical_environment(self) -> dict[str, str]:
        environment = os.environ.copy()
        environment[validate.EXPECTED_COMMIT_ENV] = self.reviewed_commit
        return environment

    def run_cli(
        self,
        optimized: bool = False,
        *arguments: str,
        cwd: Path | None = None,
        timeout: float | None = None,
        environment: dict[str, str] | None = None,
        validator: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend([str(validator or (ROOT / "validate.py")), *arguments])
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            cwd=cwd,
            timeout=timeout,
            env=environment if environment is not None else self.canonical_environment(),
        )

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

    def assert_validator_failure(self, validator_path: Path, environment: dict[str, str]) -> None:
        for optimized in (False, True):
            result = subprocess.run(
                [sys.executable, *(["-O"] if optimized else []), str(validator_path)],
                capture_output=True,
                text=True,
                check=False,
                env=environment,
            )
            with self.subTest(optimized=optimized, validator=str(validator_path)):
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, '{"error":{"code":"contract","message":"uncertain delivery fixture rejected"}}\n')
                self.assertLessEqual(len(result.stderr), validate.MAX_ERROR_LENGTH)
                self.assertNotIn("Traceback", result.stderr)

    def assert_cases_mutation_fails_both_modes(self, candidate: dict[str, object], name: str = "mutated-cases.json") -> None:
        with tempfile.TemporaryDirectory() as directory:
            cases_path = self.write_json(Path(directory), name, candidate)
            self.assert_cli_failure_both_modes("--cases", str(cases_path))

    def test_canonical_document_and_baseline_validate(self) -> None:
        previous = os.environ.get(validate.EXPECTED_COMMIT_ENV)
        os.environ[validate.EXPECTED_COMMIT_ENV] = self.reviewed_commit
        try:
            self.assertEqual(validate.validate_all(self.document, self.baseline), 26)
        finally:
            if previous is None:
                os.environ.pop(validate.EXPECTED_COMMIT_ENV, None)
            else:
                os.environ[validate.EXPECTED_COMMIT_ENV] = previous
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
                result = subprocess.run(command, capture_output=True, text=True, check=False, env=self.canonical_environment())
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
                result = subprocess.run(command, capture_output=True, text=True, check=False, env=self.canonical_environment())
                with self.subTest(kind="source", optimized=optimized):
                    self.assertEqual(result.returncode, 1)
                    self.assertNotIn("Traceback", result.stderr)

    def test_committed_coordinated_rebinding_attack_fails_both_modes(self) -> None:
        """A clean replacement commit cannot rewrite the external tag anchor."""
        with tempfile.TemporaryDirectory() as directory:
            copied_repo = Path(directory) / "copied-repository"
            clone = subprocess.run(
                ["git", "clone", "--no-local", str(REPOSITORY_ROOT), str(copied_repo)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(clone.returncode, 0, clone.stderr)
            checkout = subprocess.run(
                ["git", "-C", str(copied_repo), "checkout", "--detach", "3ec6a1f8eabc935575ba6f334195f9e86abeb1ff"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(checkout.returncode, 0, checkout.stderr)
            copied_fixture = copied_repo / "contracts" / "fixtures" / "uncertain-delivery"
            copied_chat = copied_repo / "contracts" / "state-models" / "chat.md"
            for name in ("README.md", "cases.json", "validate.py", "test_validate.py", "validation-baseline.json"):
                shutil.copy2(ROOT / name, copied_fixture / name)
            shutil.copy2(CHAT_PATH, copied_chat)

            cases = json.loads((copied_fixture / "cases.json").read_text(encoding="utf-8"))
            cases["cases"][0]["notes"] = "committed coordinated prompt prose rebinding"
            (copied_fixture / "cases.json").write_text(json.dumps(cases, indent=2) + "\n", encoding="utf-8")
            (copied_fixture / "README.md").write_text((copied_fixture / "README.md").read_text(encoding="utf-8") + "\ncommitted rebound evidence\n", encoding="utf-8")
            (copied_fixture / "test_validate.py").write_text((copied_fixture / "test_validate.py").read_text(encoding="utf-8") + "\n# committed rebound tests\n", encoding="utf-8")
            copied_chat.write_text(copied_chat.read_text(encoding="utf-8") + "\ncommitted rebound contract\n", encoding="utf-8")

            validator_path = copied_fixture / "validate.py"
            validator_text = validator_path.read_text(encoding="utf-8") + "\n# committed rebound validator\n"
            validator_path.write_text(validator_text, encoding="utf-8")
            for name in ("README.md", "cases.json", "test_validate.py", "chat.md"):
                path = validate._artifact_path(copied_fixture, name)
                digest = validate._sha256_bytes(path.read_bytes())
                old_digest = validate.EXPECTED_BOUND_SHA256[name]
                validator_text = validator_text.replace(f'"{name}": "{old_digest}"', f'"{name}": "{digest}"')
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
            rebound_baseline_digest = validate._sha256_bytes(baseline_path.read_bytes())
            validator_text = validator_path.read_text(encoding="utf-8").replace(validate.EXPECTED_BASELINE_SHA256, rebound_baseline_digest)
            validator_path.write_text(validator_text, encoding="utf-8")

            staged = subprocess.run(
                ["git", "-C", str(copied_repo), "add", "contracts/fixtures/uncertain-delivery", "contracts/state-models/chat.md"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(staged.returncode, 0, staged.stderr)
            committed = subprocess.run(
                [
                    "git",
                    "-C",
                    str(copied_repo),
                    "-c",
                    "user.name=synthetic",
                    "-c",
                    "user.email=synthetic@example.invalid",
                    "commit",
                    "-m",
                    "coordinated replacement",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(committed.returncode, 0, committed.stderr)
            status = subprocess.run(
                ["git", "-C", str(copied_repo), "status", "--porcelain"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(status.returncode, 0, status.stderr)
            self.assertEqual(status.stdout, "")
            attack_head = subprocess.check_output(["git", "-C", str(copied_repo), "rev-parse", "HEAD^{commit}"], text=True).strip()
            attack_parent = subprocess.check_output(["git", "-C", str(copied_repo), "rev-parse", "HEAD^{commit}^"], text=True).strip()
            tag_type = subprocess.check_output(["git", "-C", str(copied_repo), "cat-file", "-t", validate.TRUST_ANCHOR_REF], text=True).strip()
            anchor = subprocess.check_output(["git", "-C", str(copied_repo), "rev-parse", f"{validate.TRUST_ANCHOR_REF}^{{commit}}"], text=True).strip()
            self.assertNotEqual(attack_head, anchor)
            self.assertEqual(attack_parent, "3ec6a1f8eabc935575ba6f334195f9e86abeb1ff")
            self.assertEqual(tag_type, "tag")
            self.assertEqual(anchor, validate._trusted_anchor_commit(REPOSITORY_ROOT))

            for optimized in (False, True):
                command = [sys.executable]
                if optimized:
                    command.append("-O")
                command.append(str(copied_fixture / "validate.py"))
                result = subprocess.run(command, capture_output=True, text=True, check=False, env=self.canonical_environment())
                with self.subTest(optimized=optimized):
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, '{"error":{"code":"contract","message":"uncertain delivery fixture rejected"}}\n')
                    self.assertLessEqual(len(result.stderr), validate.MAX_ERROR_LENGTH)

    def test_committed_sibling_rebinding_attack_from_anchor_fails_both_modes(self) -> None:
        """A clean sibling commit from the anchor cannot be accepted."""
        with tempfile.TemporaryDirectory() as directory:
            copied_repo = Path(directory) / "sibling-repository"
            clone = subprocess.run(
                ["git", "clone", "--no-local", str(REPOSITORY_ROOT), str(copied_repo)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(clone.returncode, 0, clone.stderr)
            checkout = subprocess.run(
                ["git", "-C", str(copied_repo), "checkout", "--detach", "0ba168f16f6f8e646f5452a15627d7bb829828a5"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(checkout.returncode, 0, checkout.stderr)
            copied_fixture = copied_repo / "contracts" / "fixtures" / "uncertain-delivery"
            copied_chat = copied_repo / "contracts" / "state-models" / "chat.md"
            for name in ("README.md", "cases.json", "validate.py", "test_validate.py", "validation-baseline.json"):
                shutil.copy2(ROOT / name, copied_fixture / name)
            shutil.copy2(CHAT_PATH, copied_chat)

            cases = json.loads((copied_fixture / "cases.json").read_text(encoding="utf-8"))
            cases["cases"][0]["notes"] = "committed sibling prompt prose rebinding"
            (copied_fixture / "cases.json").write_text(json.dumps(cases, indent=2) + "\n", encoding="utf-8")
            (copied_fixture / "README.md").write_text((copied_fixture / "README.md").read_text(encoding="utf-8") + "\ncommitted sibling rebound evidence\n", encoding="utf-8")
            (copied_fixture / "test_validate.py").write_text((copied_fixture / "test_validate.py").read_text(encoding="utf-8") + "\n# committed sibling rebound tests\n", encoding="utf-8")
            copied_chat.write_text(copied_chat.read_text(encoding="utf-8") + "\ncommitted sibling rebound contract\n", encoding="utf-8")

            validator_path = copied_fixture / "validate.py"
            validator_text = validator_path.read_text(encoding="utf-8") + "\n# committed sibling rebound validator\n"
            validator_path.write_text(validator_text, encoding="utf-8")
            for name in ("README.md", "cases.json", "test_validate.py", "chat.md"):
                path = validate._artifact_path(copied_fixture, name)
                digest = validate._sha256_bytes(path.read_bytes())
                old_digest = validate.EXPECTED_BOUND_SHA256[name]
                validator_text = validator_text.replace(f'"{name}": "{old_digest}"', f'"{name}": "{digest}"')
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
            rebound_baseline_digest = validate._sha256_bytes(baseline_path.read_bytes())
            validator_text = validator_path.read_text(encoding="utf-8").replace(validate.EXPECTED_BASELINE_SHA256, rebound_baseline_digest)
            validator_path.write_text(validator_text, encoding="utf-8")

            staged = subprocess.run(
                ["git", "-C", str(copied_repo), "add", "contracts/fixtures/uncertain-delivery", "contracts/state-models/chat.md"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(staged.returncode, 0, staged.stderr)
            committed = subprocess.run(
                [
                    "git",
                    "-C",
                    str(copied_repo),
                    "-c",
                    "user.name=synthetic",
                    "-c",
                    "user.email=synthetic@example.invalid",
                    "commit",
                    "-m",
                    "sibling coordinated replacement",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(committed.returncode, 0, committed.stderr)
            status = subprocess.run(
                ["git", "-C", str(copied_repo), "status", "--porcelain"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(status.returncode, 0, status.stderr)
            self.assertEqual(status.stdout, "")
            attack_head = subprocess.check_output(["git", "-C", str(copied_repo), "rev-parse", "HEAD^{commit}"], text=True).strip()
            attack_parent = subprocess.check_output(["git", "-C", str(copied_repo), "rev-parse", "HEAD^{commit}^"], text=True).strip()
            tag_type = subprocess.check_output(["git", "-C", str(copied_repo), "cat-file", "-t", validate.TRUST_ANCHOR_REF], text=True).strip()
            anchor = subprocess.check_output(["git", "-C", str(copied_repo), "rev-parse", f"{validate.TRUST_ANCHOR_REF}^{{commit}}"], text=True).strip()
            self.assertNotEqual(attack_head, anchor)
            self.assertEqual(attack_parent, "0ba168f16f6f8e646f5452a15627d7bb829828a5")
            self.assertEqual(tag_type, "tag")
            self.assertEqual(anchor, validate._trusted_anchor_commit(REPOSITORY_ROOT))

            for optimized in (False, True):
                result = subprocess.run(
                    [sys.executable, *(["-O"] if optimized else []), str(copied_fixture / "validate.py")],
                    capture_output=True,
                    text=True,
                    check=False,
                    env=self.canonical_environment(),
                )
                with self.subTest(optimized=optimized):
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, '{"error":{"code":"contract","message":"uncertain delivery fixture rejected"}}\n')
                    self.assertLessEqual(len(result.stderr), validate.MAX_ERROR_LENGTH)

    def test_external_expected_revision_is_required_both_modes(self) -> None:
        environment = os.environ.copy()
        environment.pop(validate.EXPECTED_COMMIT_ENV, None)
        for optimized in (False, True):
            result = self.run_cli(optimized, environment=environment)
            with self.subTest(optimized=optimized):
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, '{"error":{"code":"contract","message":"uncertain delivery fixture rejected"}}\n')

    def test_hostile_git_environment_cannot_change_proof_both_modes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            hostile_root = Path(directory)
            fake_git = hostile_root / "fake-git"
            fake_git.mkdir()
            alternate = hostile_root / "alternate"
            alternate.mkdir()
            grafts = hostile_root / "grafts"
            grafts.write_text(f"{self.reviewed_commit} 3ec6a1f8eabc935575ba6f334195f9e86abeb1ff\n", encoding="ascii")
            shallow = hostile_root / "shallow"
            shallow.write_text(f"{self.reviewed_commit}\n", encoding="ascii")
            config = hostile_root / "config"
            config.write_text("[core]\n\\tbare = true\n", encoding="utf-8")
            environment = self.canonical_environment()
            environment.update(
                {
                    "GIT_DIR": str(fake_git),
                    "GIT_WORK_TREE": str(hostile_root / "worktree"),
                    "GIT_COMMON_DIR": str(hostile_root / "common"),
                    "GIT_INDEX_FILE": str(hostile_root / "index"),
                    "GIT_OBJECT_DIRECTORY": str(hostile_root / "objects"),
                    "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(alternate),
                    "GIT_NAMESPACE": "hostile-namespace",
                    "GIT_GRAFT_FILE": str(grafts),
                    "GIT_SHALLOW_FILE": str(shallow),
                    "GIT_CONFIG": str(config),
                    "GIT_CONFIG_GLOBAL": str(config),
                    "GIT_CONFIG_SYSTEM": str(config),
                    "GIT_CONFIG_NOSYSTEM": "0",
                    "GIT_CONFIG_COUNT": "2",
                    "GIT_CONFIG_KEY_0": "core.bare",
                    "GIT_CONFIG_VALUE_0": "true",
                    "GIT_CONFIG_KEY_1": "core.worktree",
                    "GIT_CONFIG_VALUE_1": str(hostile_root),
                    "GIT_CONFIG_PARAMETERS": "'core.bare=true'",
                    "GIT_REPLACE_REF_BASE": str(hostile_root / "replace"),
                    "GIT_EXTERNAL_DIFF": str(hostile_root / "external-diff"),
                    "GIT_DIFF_OPTS": "--no-index",
                    "GIT_PAGER": str(hostile_root / "pager"),
                    "GIT_SSH_COMMAND": str(hostile_root / "ssh"),
                    "GIT_UNKNOWN_REDIRECT": "hostile",
                }
            )
            for optimized in (False, True):
                result = self.run_cli(optimized, environment=environment)
                with self.subTest(optimized=optimized):
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, "uncertain_delivery_validation=ok cases=26 benchmark_samples=60\n")
                    self.assertEqual(result.stderr, "")

            original = dict(os.environ)
            try:
                os.environ.clear()
                os.environ.update(environment)
                sanitized = validate._git_env()
            finally:
                os.environ.clear()
                os.environ.update(original)
            for name in environment:
                if name.startswith("GIT_") and name not in {
                    "GIT_CONFIG_NOSYSTEM",
                    "GIT_CONFIG_GLOBAL",
                    "GIT_CONFIG_SYSTEM",
                    "GIT_CONFIG_COUNT",
                    "GIT_OPTIONAL_LOCKS",
                    "GIT_TERMINAL_PROMPT",
                    "GIT_NO_LAZY_FETCH",
                    "GIT_NO_REPLACE_OBJECTS",
                }:
                    self.assertNotIn(name, sanitized)
            self.assertEqual(sanitized["GIT_CONFIG_GLOBAL"], os.devnull)
            self.assertEqual(sanitized["GIT_CONFIG_SYSTEM"], os.devnull)
            self.assertEqual(sanitized["GIT_CONFIG_COUNT"], "0")

    def test_fake_path_git_cannot_change_proof_both_modes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_bin = Path(directory) / "bin"
            fake_bin.mkdir()
            fake_git = fake_bin / "git"
            fake_git.write_text("#!/bin/sh\nprintf 'deadbeef\n'\n", encoding="utf-8")
            fake_git.chmod(0o755)
            environment = self.canonical_environment()
            environment["PATH"] = str(fake_bin)
            for optimized in (False, True):
                result = self.run_cli(optimized, environment=environment)
                with self.subTest(optimized=optimized):
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, "uncertain_delivery_validation=ok cases=26 benchmark_samples=60\n")

    def test_git_helper_hang_and_output_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, body in (
                ("hang-git", "#!/bin/sh\nsleep 60\n"),
                ("output-git", "#!/bin/sh\nhead -c 1048576 /dev/zero\n"),
            ):
                executable = root / name
                executable.write_text(body, encoding="utf-8")
                executable.chmod(0o755)
                previous = validate.TRUSTED_GIT_EXECUTABLE
                validate.TRUSTED_GIT_EXECUTABLE = executable
                try:
                    result = validate._run_git(REPOSITORY_ROOT, ["rev-parse", "HEAD"], output_limit=1024)
                finally:
                    validate.TRUSTED_GIT_EXECUTABLE = previous
                self.assertIsNone(result)

    def test_fresh_clone_no_tags_and_shallow_lifecycle_both_modes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            cases = (
                ("fresh", ["--no-local"], True),
                ("no-tags", ["--no-local", "--no-tags"], False),
                ("shallow", ["--no-local", "--depth", "1"], False),
            )
            for label, options, succeeds in cases:
                clone_path = base / label
                clone = subprocess.run(
                    ["git", "clone", *options, str(REPOSITORY_ROOT), str(clone_path)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(clone.returncode, 0, clone.stderr)
                environment = self.canonical_environment()
                for optimized in (False, True):
                    result = subprocess.run(
                        [sys.executable, *(["-O"] if optimized else []), str(clone_path / "contracts/fixtures/uncertain-delivery/validate.py")],
                        capture_output=True,
                        text=True,
                        check=False,
                        env=environment,
                    )
                    with self.subTest(label=label, optimized=optimized):
                        if succeeds:
                            self.assertEqual(result.returncode, 0, result.stderr)
                            self.assertEqual(result.stdout, "uncertain_delivery_validation=ok cases=26 benchmark_samples=60\n")
                        else:
                            self.assertEqual(result.returncode, 1)
                            self.assertEqual(result.stdout, "")
                            self.assertEqual(result.stderr, '{"error":{"code":"contract","message":"uncertain delivery fixture rejected"}}\n')

    def test_merge_and_later_unchanged_commits_use_external_expectation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "merged-repository"
            clone = subprocess.run(
                ["git", "clone", "--no-local", str(REPOSITORY_ROOT), str(repository)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(clone.returncode, 0, clone.stderr)

            def git(*arguments: str) -> subprocess.CompletedProcess[str]:
                result = subprocess.run(
                    ["git", "-C", str(repository), *arguments],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                return result

            git("checkout", "--detach", self.reviewed_commit)
            git("checkout", "-b", "synthetic-side")
            (repository / "synthetic-merge-marker.txt").write_text("merge-only synthetic marker\n", encoding="utf-8")
            git("add", "synthetic-merge-marker.txt")
            git("-c", "user.name=synthetic", "-c", "user.email=synthetic@example.invalid", "commit", "-m", "synthetic side")
            git("checkout", "--detach", self.reviewed_commit)
            git("checkout", "-b", "synthetic-merge")
            git("merge", "--no-ff", "synthetic-side", "-m", "synthetic merge")

            environment = self.canonical_environment()
            validator_path = repository / "contracts/fixtures/uncertain-delivery/validate.py"
            for optimized in (False, True):
                result = subprocess.run(
                    [sys.executable, *(["-O"] if optimized else []), str(validator_path)],
                    capture_output=True,
                    text=True,
                    check=False,
                    env=environment,
                )
                with self.subTest(commit="merge", optimized=optimized):
                    self.assertEqual(result.returncode, 0, result.stderr)
            (repository / "later-unchanged-marker.txt").write_text("later synthetic marker\n", encoding="utf-8")
            git("add", "later-unchanged-marker.txt")
            git("-c", "user.name=synthetic", "-c", "user.email=synthetic@example.invalid", "commit", "-m", "later unchanged")
            for optimized in (False, True):
                result = subprocess.run(
                    [sys.executable, *(["-O"] if optimized else []), str(validator_path)],
                    capture_output=True,
                    text=True,
                    check=False,
                    env=environment,
                )
                with self.subTest(commit="later", optimized=optimized):
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_direct_child_semantic_weakening_attack_fails_both_modes(self) -> None:
        """Digest rebinding cannot hide a weakened reducer/result comparison."""
        with tempfile.TemporaryDirectory() as directory:
            copied_repo = Path(directory) / "semantic-repository"
            clone = subprocess.run(
                ["git", "clone", "--no-local", str(REPOSITORY_ROOT), str(copied_repo)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(clone.returncode, 0, clone.stderr)
            checkout = subprocess.run(
                ["git", "-C", str(copied_repo), "checkout", "--detach", "0ba168f16f6f8e646f5452a15627d7bb829828a5"],
                capture_output=True,
                text=True,
                check=False,
            )
            if checkout.returncode != 0:
                checkout = subprocess.run(
                    ["git", "-C", str(copied_repo), "checkout", "--detach", "0ba168f16f6f8e646f5452a15627d7bb829828a5"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            self.assertEqual(checkout.returncode, 0, checkout.stderr)
            copied_fixture = copied_repo / "contracts" / "fixtures" / "uncertain-delivery"
            copied_chat = copied_repo / "contracts" / "state-models" / "chat.md"
            for name in ("README.md", "cases.json", "validate.py", "test_validate.py", "validation-baseline.json"):
                shutil.copy2(ROOT / name, copied_fixture / name)
            shutil.copy2(CHAT_PATH, copied_chat)

            cases = json.loads((copied_fixture / "cases.json").read_text(encoding="utf-8"))
            for case in cases["cases"]:
                if case["id"] == "accepted-present":
                    case["expected"]["trace"] = ["ready", "completed"]
                    break
            (copied_fixture / "cases.json").write_text(json.dumps(cases, indent=2) + "\n", encoding="utf-8")
            validator_path = copied_fixture / "validate.py"
            validator_text = validator_path.read_text(encoding="utf-8").replace(
                'if result != case["expected"]:',
                'if False and result != case["expected"]:',
            )
            validator_path.write_text(validator_text, encoding="utf-8")
            for name in ("README.md", "cases.json", "test_validate.py", "chat.md"):
                path = validate._artifact_path(copied_fixture, name)
                digest = validate._sha256_bytes(path.read_bytes())
                old_digest = validate.EXPECTED_BOUND_SHA256[name]
                validator_text = validator_text.replace(f'"{name}": "{old_digest}"', f'"{name}": "{digest}"')
            validator_path.write_text(validator_text, encoding="utf-8")
            source_digest = validate._source_digest(validator_path)[1]
            validator_text = validator_text.replace(
                f'"validate.py": "{validate.EXPECTED_BOUND_SHA256["validate.py"]}"',
                f'"validate.py": "{source_digest}"',
            )
            validator_path.write_text(validator_text, encoding="utf-8")
            baseline_path = copied_fixture / "validation-baseline.json"
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            artifacts, manifest = validate._artifact_manifest(copied_fixture)
            baseline["artifacts"] = artifacts
            baseline["artifact_manifest_sha256"] = manifest
            baseline_path.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
            baseline_digest = validate._sha256_bytes(baseline_path.read_bytes())
            validator_path.write_text(
                validator_path.read_text(encoding="utf-8").replace(validate.EXPECTED_BASELINE_SHA256, baseline_digest),
                encoding="utf-8",
            )
            git_add = subprocess.run(
                ["git", "-C", str(copied_repo), "add", "contracts/fixtures/uncertain-delivery", "contracts/state-models/chat.md"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(git_add.returncode, 0, git_add.stderr)
            committed = subprocess.run(
                ["git", "-C", str(copied_repo), "-c", "user.name=synthetic", "-c", "user.email=synthetic@example.invalid", "commit", "-m", "semantic weakening"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(committed.returncode, 0, committed.stderr)
            attack_parent = subprocess.check_output(["git", "-C", str(copied_repo), "rev-parse", "HEAD^"], text=True).strip()
            self.assertEqual(attack_parent, "0ba168f16f6f8e646f5452a15627d7bb829828a5")
            self.assertNotEqual(subprocess.check_output(["git", "-C", str(copied_repo), "rev-parse", "HEAD"], text=True).strip(), self.reviewed_commit)
            self.assert_validator_failure(copied_fixture / "validate.py", self.canonical_environment())

    def test_checkout_metadata_anomalies_fail_both_modes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for label in ("index", "alternates", "grafts", "config", "config-helper", "untracked", "ignored"):
                repository = base / label
                clone = subprocess.run(
                    ["git", "clone", "--no-local", str(REPOSITORY_ROOT), str(repository)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(clone.returncode, 0, clone.stderr)
                if label == "index":
                    result = subprocess.run(["git", "-C", str(repository), "update-index", "--skip-worktree", "contracts/fixtures/uncertain-delivery/cases.json"], capture_output=True, text=True, check=False)
                elif label == "alternates":
                    path = repository / ".git/objects/info/alternates"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(str(base / "outside-objects") + "\n", encoding="utf-8")
                    result = subprocess.CompletedProcess([], 0, "", "")
                elif label == "grafts":
                    path = repository / ".git/info/grafts"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(f"{self.reviewed_commit} 3ec6a1f8eabc935575ba6f334195f9e86abeb1ff\n", encoding="ascii")
                    result = subprocess.CompletedProcess([], 0, "", "")
                elif label == "config":
                    result = subprocess.run(["git", "-C", str(repository), "config", "--local", "core.worktree", str(base / "wrong-worktree")], capture_output=True, text=True, check=False)
                elif label == "config-helper":
                    result = subprocess.run(["git", "-C", str(repository), "config", "--local", "core.fsmonitor", "true"], capture_output=True, text=True, check=False)
                else:
                    tracked = repository / "contracts/fixtures/uncertain-delivery/cases.json"
                    subprocess.run(["git", "-C", str(repository), "rm", "--cached", "-q", str(tracked.relative_to(repository))], capture_output=True, text=True, check=False)
                    if label == "ignored":
                        with (repository / ".git/info/exclude").open("a", encoding="utf-8") as exclude:
                            exclude.write("contracts/fixtures/uncertain-delivery/cases.json\n")
                    result = subprocess.CompletedProcess([], 0, "", "")
                self.assertEqual(result.returncode, 0, getattr(result, "stderr", ""))
                self.assert_validator_failure(repository / "contracts/fixtures/uncertain-delivery/validate.py", self.canonical_environment())

            with self.assertRaises(validate.ContractError):
                validate._require_clean_bound_worktree(REPOSITORY_ROOT / "contracts")

    def test_force_retagged_audit_tag_cannot_replace_external_expectation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "retagged"
            clone = subprocess.run(["git", "clone", "--no-local", str(REPOSITORY_ROOT), str(repository)], capture_output=True, text=True, check=False)
            self.assertEqual(clone.returncode, 0, clone.stderr)
            result = subprocess.run(
                [
                    "git",
                    "-C",
                    str(repository),
                    "tag",
                    "-a",
                    "-f",
                    "-m",
                    "forged synthetic audit marker",
                    "hermternal-c06-uncertain-delivery-final-anchor",
                    "0ba168f16f6f8e646f5452a15627d7bb829828a5",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            tag_type = subprocess.check_output(
                ["git", "-C", str(repository), "cat-file", "-t", validate.TRUST_ANCHOR_REF],
                text=True,
            ).strip()
            self.assertEqual(tag_type, "tag")
            self.assertEqual(
                subprocess.check_output(
                    ["git", "-C", str(repository), "rev-parse", f"{validate.TRUST_ANCHOR_REF}^{{commit}}"],
                    text=True,
                ).strip(),
                "0ba168f16f6f8e646f5452a15627d7bb829828a5",
            )
            self.assert_validator_failure(repository / "contracts/fixtures/uncertain-delivery/validate.py", self.canonical_environment())

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
