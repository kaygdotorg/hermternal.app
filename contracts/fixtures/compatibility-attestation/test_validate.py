#!/usr/bin/env python3
"""Regression tests for the synthetic C-04 revision-attestation contract."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[2]
sys.path.insert(0, str(ROOT))
import validate  # noqa: E402


class RevisionAttestationValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.record = validate.load_json(validate.ATTESTATION_PATH)
        cls.cases = validate.load_json(validate.CASES_PATH)
        cls.baseline = validate.load_json(validate.BASELINE_PATH)

    def test_attestation_binds_immutable_policy_blobs(self) -> None:
        validate.validate_attestation(self.record, REPO_ROOT, verify_git=True)

    def test_cases_are_deterministic_and_fail_closed(self) -> None:
        validate.validate_cases(self.cases)
        unknown = next(item for item in self.cases["cases"] if item["id"] == "unknown_revision")
        self.assertEqual(unknown["expected"]["attestation_result"], "blocked")
        self.assertEqual(unknown["expected"]["runtime_gate"], "blocked_incompatible")
        empty = next(item for item in self.cases["cases"] if item["id"] == "empty_attestation")
        self.assertEqual(empty["expected"]["runtime_gate"], "blocked_incompatible")

    def test_worktree_fixture_set_validates(self) -> None:
        case_count, artifact_bytes = validate.validate_all(REPO_ROOT, verify_git=False)
        self.assertEqual(case_count, len(validate.CASE_SPECS))
        self.assertGreater(artifact_bytes, 0)

    def test_unknown_revision_is_rejected_in_canonical_record(self) -> None:
        record = copy.deepcopy(self.record)
        record["hermes"]["source_sha"] = "0" * 40
        with self.assertRaises(validate.ValidationError):
            validate.validate_attestation(record, REPO_ROOT, verify_git=True)

    def test_unknown_root_key_is_rejected(self) -> None:
        record = copy.deepcopy(self.record)
        record["unexpected"] = "not part of the contract"
        with self.assertRaises(validate.ValidationError):
            validate.validate_attestation(record, REPO_ROOT, verify_git=True)

    def test_server_protocol_metadata_is_not_an_attestation_field(self) -> None:
        record = copy.deepcopy(self.record)
        record["dashboard_metadata"]["dashboard_protocol_version"] = "1"
        with self.assertRaises(validate.ValidationError):
            validate.validate_attestation(record, REPO_ROOT, verify_git=True)

    def test_immutable_digest_mismatch_is_rejected(self) -> None:
        record = copy.deepcopy(self.record)
        record["route_manifest"]["sha256"] = "0" * 64
        with self.assertRaises(validate.ValidationError):
            validate.validate_attestation(record, REPO_ROOT, verify_git=True)

    def test_credential_shaped_value_is_rejected(self) -> None:
        record = copy.deepcopy(self.record)
        record["deployment"]["identity"] = "Bearer synthetic-marker"
        with self.assertRaises(validate.ValidationError):
            validate.validate_attestation(record, REPO_ROOT, verify_git=True)

    def test_unsafe_evidence_path_is_rejected(self) -> None:
        with self.assertRaises(validate.ValidationError):
            validate.resolve_under_root(REPO_ROOT, "../outside.json")
        with self.assertRaises(validate.ValidationError):
            validate.resolve_under_root(REPO_ROOT, r"C:\outside.json")

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"schema": 1, "schema": 2}', encoding="utf-8")
            with self.assertRaises(validate.DuplicateKeyError):
                validate.load_json(path)

    def test_non_finite_json_numbers_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nonfinite.json"
            path.write_text('{"value": NaN}', encoding="utf-8")
            with self.assertRaises(validate.ValidationError):
                validate.load_json(path)

    def test_baseline_has_no_invented_threshold(self) -> None:
        validate.validate_baseline(self.baseline, REPO_ROOT, verify_git=False)
        self.assertIsNone(self.baseline["threshold"])
        self.assertEqual(self.baseline["repetitions"], 30)

    def test_fixture_never_claims_live_operation(self) -> None:
        result = validate.main(["--repo-root", str(REPO_ROOT), "--worktree"])
        self.assertEqual(result, 0)
        for item in self.cases["cases"]:
            self.assertNotEqual(item["expected"]["runtime_gate"], "enabled")


if __name__ == "__main__":
    unittest.main()
