"""Regression tests for the offline synthetic C-16 resolver proof."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import py_compile
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


FIXTURE_DIR = Path(__file__).resolve().parent
if str(FIXTURE_DIR) not in sys.path:
    sys.path.insert(0, str(FIXTURE_DIR))

import validate  # noqa: E402


class DeepLinkResolutionTests(unittest.TestCase):
    """Keep resolver traces, dependency identities, and safe failures aligned."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.document = validate.load_json(FIXTURE_DIR / "cases.json")
        cls.evidence = validate.load_json(FIXTURE_DIR / "baseline-evidence.json")
        cls.baseline = validate.load_json(FIXTURE_DIR / "validation-baseline.json")
        validate.validate_document(cls.document)

    def run_cli(self, optimized: bool = False, *extra: str) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend([str(FIXTURE_DIR / "validate.py"), *extra])
        return subprocess.run(command, check=False, capture_output=True, text=True)

    def assert_fixed_failure(self, path: Path, flag: str = "--cases") -> None:
        expected = json.dumps(validate.ERROR_PAYLOAD, separators=(",", ":"), sort_keys=True) + "\n"
        for optimized in (False, True):
            with self.subTest(optimized=optimized, path=path.name):
                completed = self.run_cli(optimized, flag, str(path))
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(completed.stdout, expected)
                self.assertEqual(completed.stderr, "")
                self.assertNotIn(validate.ROOT_ID, completed.stdout)

    def test_checked_in_validator_passes_in_normal_and_optimized_modes(self) -> None:
        for optimized in (False, True):
            completed = self.run_cli(optimized)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(completed.stderr, "")
            self.assertEqual(
                completed.stdout,
                "deep_link_resolution_validation=ok cases=15 mutations=18\n",
            )

    def test_all_cases_reduce_to_exact_expected_results(self) -> None:
        grammar = validate.load_grammar_module()
        lineage = validate.lineage_inventory()
        self.assertEqual(tuple(case["id"] for case in self.document["cases"]), validate.CASE_IDS)
        for case in self.document["cases"]:
            with self.subTest(case=case["id"]):
                self.assertTrue(validate.strict_equal(validate.reduce_case(case, grammar, lineage), case["expected"]))
                self.assertEqual(case["expected"]["session_creations"], 0)
                self.assertEqual(case["expected"]["shares"], 0)
                self.assertFalse(case["expected"]["transcript_mirror"])
                self.assertFalse(case["expected"]["network"])

    def test_missing_and_denied_are_authorization_safe_parity(self) -> None:
        cases = {case["id"]: case for case in self.document["cases"]}
        missing = cases["unknown-session-safe-not-found"]["expected"]
        denied = cases["unauthorized-session-safe-not-found"]["expected"]
        self.assertTrue(validate.strict_equal(missing, denied))
        self.assertEqual(missing["decision"], "session_not_found")

    def test_latest_descendant_preserves_reviewed_lineage(self) -> None:
        cases = {case["id"]: case for case in self.document["cases"]}
        for case_id in ("latest-descendant-preserves-lineage", "latest-descendant-message-focus"):
            result = cases[case_id]["expected"]
            self.assertEqual(result["requested_session_id"], validate.ROOT_ID)
            self.assertEqual(result["opened_session_id"], validate.BRANCH_ID)
            self.assertEqual(result["root_id"], validate.ROOT_ID)
            self.assertEqual(result["parent_id"], validate.ROOT_ID)

    def test_message_focus_and_fallback_are_distinct(self) -> None:
        cases = {case["id"]: case for case in self.document["cases"]}
        focused = cases["authenticated-message-anchor-focus"]["expected"]
        fallback = cases["message-not-found-opens-session"]["expected"]
        self.assertEqual(focused["decision"], "message_focused")
        self.assertEqual(focused["focus"], "message")
        self.assertEqual(fallback["decision"], "message_not_found")
        self.assertEqual(fallback["focus"], "session_start")
        self.assertEqual(fallback["opened_session_id"], validate.BRANCH_ID)

    def test_pending_target_clears_on_success_expiry_logout_and_failure(self) -> None:
        terminal = {
            "authenticated-exact-root-direct-load",
            "pending-auth-resolves-and-clears",
            "pending-target-expires",
            "logout-clears-pending-target",
            "unknown-session-safe-not-found",
            "unauthorized-session-safe-not-found",
            "interrupted-lookup-recovers",
        }
        for case in self.document["cases"]:
            if case["id"] in terminal:
                self.assertFalse(case["expected"]["pending_target"], case["id"])
                self.assertIn("pending_target_cleared", case["expected"]["effects"])

    def test_reload_reopens_idempotently_without_creation(self) -> None:
        case = next(case for case in self.document["cases"] if case["id"] == "direct-reload-idempotent-reopen")
        result = case["expected"]
        self.assertEqual(result["lookup_attempts"], 2)
        self.assertEqual(result["opened_session_id"], validate.BRANCH_ID)
        self.assertIn("idempotent_reopen", result["effects"])
        self.assertEqual(result["session_creations"], 0)

    def test_private_https_and_hermternal_boundaries_stop_before_lookup(self) -> None:
        cases = {case["id"]: case for case in self.document["cases"]}
        for case_id in ("invalid-private-https-origin", "invalid-hermternal-authority"):
            result = cases[case_id]["expected"]
            self.assertEqual(result["decision"], "invalid_link")
            self.assertEqual(result["lookup_attempts"], 0)
            self.assertIsNone(result["requested_session_id"])

    def test_duplicate_keys_and_nonfinite_numbers_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            duplicate = Path(directory) / "duplicate.json"
            duplicate.write_text('{"schema":"one","schema":"two"}', encoding="utf-8")
            nonfinite = Path(directory) / "nonfinite.json"
            nonfinite.write_text('{"schema":NaN}', encoding="utf-8")
            for path in (duplicate, nonfinite):
                with self.subTest(path=path.name):
                    with self.assertRaises(validate.ContractError):
                        validate.load_json(path)
                    self.assert_fixed_failure(path)

    def test_overflow_exact_types_and_container_bounds_fail_closed(self) -> None:
        mutations = []
        integer = copy.deepcopy(self.document)
        integer["pending_ttl_seconds"] = validate.MAX_INTEGER + 1
        mutations.append(integer)
        boolean = copy.deepcopy(self.document)
        boolean["pending_ttl_seconds"] = True
        mutations.append(boolean)
        container = copy.deepcopy(self.document)
        container["cases"][0]["events"] = ["receive"] * (validate.MAX_CONTAINER_ITEMS + 1)
        mutations.append(container)
        for index, mutated in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaises(validate.ContractError):
                    if index == 1:
                        validate.validate_document(mutated)
                    else:
                        validate.validate_tree(mutated)

    def test_byte_string_node_and_depth_bounds_are_iterative(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            too_large = Path(directory) / "large.json"
            too_large.write_bytes(b" " * (validate.MAX_FILE_BYTES + 1))
            with self.assertRaises(validate.ContractError):
                validate.load_json(too_large)
        with self.assertRaises(validate.ContractError):
            validate.validate_tree("x" * (validate.MAX_STRING_BYTES + 1))
        with mock.patch.object(validate, "MAX_NODES", 3):
            with self.assertRaises(validate.ContractError):
                validate.validate_tree([1, 2, 3])
        deep: object = None
        for _ in range(validate.MAX_DEPTH + 1):
            deep = [deep]
        with self.assertRaises(validate.ContractError):
            validate.validate_tree(deep)

    def test_coordinated_dependency_drift_and_rebinding_still_fail(self) -> None:
        changed = copy.deepcopy(self.document)
        fake = "0" * 64
        changed["dependencies"]["deep-link-grammar/cases.json"]["sha256"] = fake
        rebound = dict(validate.DEPENDENCIES)
        rebound["deep-link-grammar/cases.json"] = fake
        with mock.patch.object(validate, "DEPENDENCIES", rebound):
            with self.assertRaises(validate.ContractError):
                validate.verify_dependencies(changed)

        rebound_document = copy.deepcopy(self.document)
        rebound_document["dependencies"]["deep-link-grammar/cases.json"] = copy.deepcopy(
            rebound_document["dependencies"]["session-lineage/cases.json"]
        )
        with self.assertRaises(validate.ContractError):
            validate.verify_dependencies(rebound_document)

    def test_coordinated_fixture_and_baseline_drift_fail_exact_identities(self) -> None:
        changed = copy.deepcopy(self.document)
        changed["cases"][0]["notes"] = "coordinated drift"
        with tempfile.TemporaryDirectory() as directory:
            cases = Path(directory) / "cases.json"
            cases.write_text(json.dumps(changed), encoding="utf-8")
            self.assert_fixed_failure(cases)

        changed_baseline = copy.deepcopy(self.baseline)
        changed_evidence = copy.deepcopy(self.evidence)
        changed_evidence["normal"]["samples_ms"][0] += 1.0
        changed_evidence["normal"]["distribution"] = validate.distribution(changed_evidence["normal"]["samples_ms"])
        changed_baseline["normal"] = changed_evidence["normal"]
        changed_evidence_bytes = (json.dumps(changed_evidence, indent=2) + "\n").encode()
        changed_baseline["artifact_identities"]["baseline-evidence.json"] = validate.sha256_bytes(
            changed_evidence_bytes
        )
        with self.assertRaises(validate.ContractError):
            validate.validate_baseline(changed_baseline, changed_evidence)

    def test_raw_samples_have_null_threshold_and_exact_distribution(self) -> None:
        validate.validate_evidence(self.evidence)
        validate.validate_baseline(self.baseline, self.evidence)
        self.assertIsNone(self.baseline["threshold"])
        self.assertEqual(self.baseline["repetitions"], 30)

    def test_mutation_inventory_and_py_compile(self) -> None:
        self.assertEqual(validate.validate_mutations(self.document), 18)
        py_compile.compile(str(FIXTURE_DIR / "validate.py"), doraise=True)
        py_compile.compile(str(FIXTURE_DIR / "test_validate.py"), doraise=True)


if __name__ == "__main__":
    unittest.main()
