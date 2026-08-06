#!/usr/bin/env python3
"""Regression tests for the synthetic C-07B session-lineage contract."""

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


class SessionLineageValidationTests(unittest.TestCase):
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
        self.assertEqual(case_count, 32)
        self.assertGreater(artifact_bytes, 0)
        self.assertEqual(len(self.document["states"]), 9)
        self.assertIsNone(self.baseline["threshold"])
        self.assertEqual(self.baseline["repetitions"], 30)
        self.assertTrue(self.document["synthetic_only"])
        self.assertFalse(self.document["redaction"]["contains_transcript_mirror"])

    def test_normal_and_optimized_cli_outputs_are_successful(self) -> None:
        normal = self.run_cli()
        optimized = self.run_cli(True)
        self.assertEqual(normal.returncode, 0, normal.stderr)
        self.assertEqual(optimized.returncode, 0, optimized.stderr)
        self.assertEqual(normal.stdout, optimized.stdout)
        self.assertEqual(normal.stderr, "")
        self.assertEqual(optimized.stderr, "")
        self.assertIn("states=9 cases=32", normal.stdout)

    def test_root_branch_and_resume_preserve_full_lineage(self) -> None:
        root = self.cases["persist-new-root-lineage"]["expected"]
        self.assertEqual(root["session_id"], validate.ROOT_SESSION_ID)
        self.assertEqual(root["root_id"], validate.ROOT_SESSION_ID)
        self.assertIsNone(root["parent_id"])
        self.assertEqual(root["lineage_kind"], "root")
        self.assertTrue(root["durable"])

        branch = self.cases["create-branch-from-open-root"]["expected"]
        self.assertEqual(branch["session_id"], validate.BRANCH_SESSION_ID)
        self.assertEqual(branch["root_id"], validate.ROOT_SESSION_ID)
        self.assertEqual(branch["parent_id"], validate.ROOT_SESSION_ID)
        self.assertEqual(branch["ancestor_ids"], [validate.ROOT_SESSION_ID])
        self.assertEqual(branch["lineage_kind"], "branch")

        resumed = self.cases["resume-existing-branch"]["expected"]
        self.assertEqual(resumed["final_state"], "ready")
        self.assertEqual(resumed["session_id"], validate.BRANCH_SESSION_ID)
        self.assertEqual(resumed["root_id"], validate.ROOT_SESSION_ID)
        self.assertEqual(resumed["parent_id"], validate.ROOT_SESSION_ID)
        self.assertIn("same_session_identity_reused", resumed["effects"])

    def test_closed_parent_is_forkable_but_deleted_parent_is_not(self) -> None:
        closed = self.cases["create-branch-from-closed-parent"]["expected"]
        self.assertEqual(closed["final_state"], "ready")
        self.assertEqual(closed["parent_state"], "closed")
        self.assertEqual(closed["parent_id"], validate.ROOT_SESSION_ID)

        deleted = self.cases["branch-deleted-parent-fails-closed"]["expected"]
        self.assertEqual(deleted["final_state"], "incompatible")
        self.assertIn("parent_deleted", deleted["effects"])
        self.assertIn("no_new_session_fallback", deleted["effects"])

    def test_resume_is_not_new_session_and_explicit_new_is_separate(self) -> None:
        missing = self.cases["resume-missing-fails-closed"]["expected"]
        self.assertEqual(missing["final_state"], "failed")
        self.assertEqual(missing["error_kind"], "resume_missing")
        self.assertIsNone(missing["session_id"])
        self.assertIn("no_new_session_fallback", missing["effects"])

        explicit = self.cases["explicit-new-root-after-missing-resume"]["expected"]
        self.assertEqual(explicit["lineage_kind"], "root")
        self.assertIsNone(explicit["parent_id"])
        self.assertEqual(explicit["creation_attempts"], 1)
        self.assertEqual(explicit["resume_attempts"], 1)

    def test_duplicate_create_and_resume_are_idempotent(self) -> None:
        root_duplicate = self.cases["create-new-root-duplicate-idempotent"]["expected"]
        self.assertEqual(root_duplicate["decision"], "duplicate_creation_reused")
        self.assertIn("duplicate_creation_suppressed", root_duplicate["effects"])
        self.assertEqual(root_duplicate["creation_attempts"], 1)

        branch_duplicate = self.cases["create-branch-duplicate-idempotent"]["expected"]
        self.assertEqual(branch_duplicate["decision"], "duplicate_creation_reused")
        self.assertEqual(branch_duplicate["creation_attempts"], 1)

        resume_duplicate = self.cases["duplicate-resume-is-idempotent"]["expected"]
        self.assertEqual(resume_duplicate["resume_attempts"], 1)
        self.assertTrue(resume_duplicate["duplicate_suppressed"])
        self.assertIn("duplicate_resume_suppressed", resume_duplicate["effects"])

    def test_missing_invalid_cycle_and_self_parent_fail_closed(self) -> None:
        for case_id, effect in (
            ("branch-missing-parent-fails-closed", "parent_missing"),
            ("branch-invalid-parent-fails-closed", "parent_invalid"),
            ("branch-self-parent-fails-closed", "self_parent"),
            ("branch-cyclic-parent-fails-closed", "cyclic_parent"),
            ("branch-parent-identity-mismatch-fails-closed", "parent_identity_mismatch"),
        ):
            with self.subTest(case_id=case_id):
                result = self.cases[case_id]["expected"]
                self.assertEqual(result["final_state"], "incompatible")
                self.assertEqual(result["error_kind"], "incompatible")
                self.assertIn(effect, result["effects"])
                self.assertTrue(result["transport_closed"])

    def test_interrupted_and_unknown_creation_require_safe_recovery(self) -> None:
        interrupted = self.cases["create-interrupted-preserves-parent"]["expected"]
        self.assertEqual(interrupted["final_state"], "interrupted")
        self.assertEqual(interrupted["retry_policy"], "reread_before_idempotent_retry")
        self.assertIn("no_duplicate_creation", interrupted["effects"])

        retry = self.cases["create-interrupted-idempotent-retry"]["expected"]
        self.assertEqual(retry["creation_attempts"], 2)
        self.assertEqual(retry["lineage_kind"], "branch")
        self.assertEqual(retry["parent_id"], validate.ROOT_SESSION_ID)

        uncertain = self.cases["create-unknown-enters-uncertain"]["expected"]
        self.assertEqual(uncertain["final_state"], "delivery_uncertain")
        self.assertEqual(uncertain["retry_policy"], "reconcile_before_retry")
        self.assertTrue(uncertain["transport_closed"])

        reconciled = self.cases["unknown-create-reconcile-present-no-duplicate"]["expected"]
        self.assertEqual(reconciled["final_state"], "ready")
        self.assertEqual(reconciled["creation_attempts"], 1)
        self.assertIn("no_duplicate_creation", reconciled["effects"])

        early_retry = self.cases["unknown-create-retry-before-reconcile-fails-closed"]["expected"]
        self.assertEqual(early_retry["final_state"], "incompatible")
        self.assertIn("retry_before_reconcile", early_retry["effects"])

    def test_compatibility_and_unknown_results_fail_closed(self) -> None:
        for case_id in (
            "compatibility-failure-blocks-new-root",
            "compatibility-failure-blocks-branch",
            "unknown-lineage-event-fails-closed",
            "malformed-lineage-event-fails-closed",
            "resume-foreign-full-id-fails-closed",
        ):
            with self.subTest(case_id=case_id):
                result = self.cases[case_id]["expected"]
                self.assertEqual(result["final_state"], "incompatible")
                self.assertEqual(result["compatibility"], "failed")
                self.assertTrue(result["transport_closed"])
                self.assertIn("no_new_session_fallback", result["effects"])

    def test_normal_and_optimized_case_regressions(self) -> None:
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                resumed = self.evaluate_case_subprocess("resume-existing-branch", optimized)
                self.assertEqual(resumed["final_state"], "ready")
                self.assertEqual(resumed["root_id"], validate.ROOT_SESSION_ID)
                self.assertEqual(resumed["parent_id"], validate.ROOT_SESSION_ID)

                uncertain = self.evaluate_case_subprocess("unknown-create-reconcile-present-no-duplicate", optimized)
                self.assertEqual(uncertain["final_state"], "ready")
                self.assertEqual(uncertain["creation_attempts"], 1)

                malformed = self.evaluate_case_subprocess("malformed-lineage-event-fails-closed", optimized)
                self.assertEqual(malformed["final_state"], "incompatible")
                self.assertTrue(malformed["transport_closed"])

                explicit = self.evaluate_case_subprocess("explicit-new-root-after-missing-resume", optimized)
                self.assertEqual(explicit["lineage_kind"], "root")
                self.assertIsNone(explicit["parent_id"])

    def test_baseline_identity_rejects_samples_distributions_commands_and_environment(self) -> None:
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
                            {"error": {"code": "contract", "message": "session lineage fixture rejected"}},
                        )

    def test_redaction_rejects_sensitive_values_and_keys_in_both_modes(self) -> None:
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
        accepted = ["gateway.ready", "session-root-0000000000000000000000000000000000000001", validate.HERMES_SOURCE_SHA]
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
                            {"error": {"code": "contract", "message": "session lineage fixture rejected"}},
                        )

    def test_strict_json_rejects_duplicate_nonfinite_invalid_utf8_and_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mutations = {
                "duplicate.json": b'{"value":1,"value":2}',
                "nan.json": b'{"value":NaN}',
                "infinity.json": b'{"value":Infinity}',
                "overflow.json": b'{"value":1e9999}',
                "huge-int.json": b'{"value":' + b"1" + (b"0" * validate.MAX_INTEGER_DIGITS) + b"}",
                "deep.json": (b"[" * (validate.MAX_JSON_DEPTH + 2) + b"0" + b"]" * (validate.MAX_JSON_DEPTH + 2)),
                "invalid-utf8.json": b'{"value":"\xff"}',
            }
            for name, data in mutations.items():
                with self.subTest(name=name):
                    path = root / name
                    path.write_bytes(data)
                    with self.assertRaises(validate.ContractError):
                        validate._load_json(path, "synthetic input")

    def test_exact_schema_duplicate_case_and_redacted_cli_failure(self) -> None:
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
            path.write_text(json.dumps({"schema": marker}), encoding="utf-8")
            result = self.run_cli(False, "--cases", str(path))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        self.assertEqual(len(result.stdout.splitlines()), 1)
        self.assertNotIn(marker, result.stdout)
        self.assertNotIn(str(path), result.stdout)
        self.assertEqual(
            json.loads(result.stdout),
            {"error": {"code": "contract", "message": "session lineage fixture rejected"}},
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
