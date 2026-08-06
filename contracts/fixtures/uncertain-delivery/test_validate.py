"""Regression tests for the synthetic C-06 uncertain-delivery contract."""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import validate


ROOT = Path(__file__).resolve().parent
CASES_PATH = ROOT / "cases.json"
BASELINE_PATH = ROOT / "validation-baseline.json"


class UncertainDeliveryValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = validate.load_json(CASES_PATH, "cases")
        cls.baseline = validate.load_json(BASELINE_PATH, "baseline")
        cls.cases = {case["id"]: case for case in cls.document["cases"]}

    def run_cli(self, optimized: bool = False, *arguments: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend([str(ROOT / "validate.py"), *arguments])
        return subprocess.run(command, capture_output=True, text=True, check=False, cwd=cwd)

    def assert_cli_success_both_modes(self) -> None:
        for optimized in (False, True):
            result = self.run_cli(optimized)
            with self.subTest(optimized=optimized):
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, "")
                self.assertEqual(result.stdout, "uncertain_delivery_validation=ok cases=22 benchmark_samples=60\n")

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

    def test_canonical_document_and_baseline_validate(self) -> None:
        self.assertEqual(validate.validate_all(self.document, self.baseline), 22)
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
            ("prompt text", "synthetic prompt text", "redaction_value"),
            ("host", "internal.example", "redaction_value"),
            ("credential", "Bearer synthetic-token", "redaction_value"),
            ("base64", "iVBORw0KGgo", "redaction_value"),
            ("path", "/private/synthetic", "redaction_value"),
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

    def test_real_cli_rejects_semantic_mutations_in_both_modes(self) -> None:
        candidate = copy.deepcopy(self.document)
        candidate["cases"][3]["events"][4]["turn_state"] = "running"
        with tempfile.TemporaryDirectory() as directory:
            cases_path = self.write_json(Path(directory), "mutated.json", candidate)
            self.assert_cli_failure_both_modes("--cases", str(cases_path))

        self.assert_cli_failure_both_modes("--unknown-secret-flag")

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

        with tempfile.TemporaryDirectory() as directory:
            for index, baseline in enumerate(mutations):
                baseline_path = self.write_json(Path(directory), f"baseline-{index}.json", baseline)
                self.assert_cli_failure_both_modes("--baseline", str(baseline_path))

    def test_canonical_fixture_and_validator_rebinding_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "uncertain-delivery"
            copied.mkdir()
            for name in ("README.md", "cases.json", "validate.py", "test_validate.py", "validation-baseline.json"):
                shutil.copy2(ROOT / name, copied / name)
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
