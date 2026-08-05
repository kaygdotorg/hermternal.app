#!/usr/bin/env python3
"""Regression tests for the synthetic C-04 revision-attestation contract."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


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

    def test_alternate_matching_snapshot_is_rejected(self) -> None:
        alternate = validate.GitSnapshot(
            commit="609f9a74b7b06a4ab28a5eee1687e7a6e76523e7",
            tree="1f6d33d0b5ebee105b3f52ff235f8d3cf1366edc",
        )
        with self.assertRaises(validate.ValidationError):
            validate.validate_attestation(self.record, REPO_ROOT, verify_git=True, snapshot=alternate)

    def test_incorrect_reviewed_tree_is_rejected(self) -> None:
        snapshot = validate.GitSnapshot(validate.REVIEWED_COMMIT, "0" * 40)
        with self.assertRaises(validate.ValidationError):
            validate.validate_git_snapshot(REPO_ROOT, snapshot)

    def test_tree_valued_head_is_rejected_as_execution_commit(self) -> None:
        with mock.patch.object(validate, "_git_revision", return_value=validate.REVIEWED_TREE), mock.patch.object(
            validate, "_git_object_type", return_value="tree"
        ):
            with self.assertRaises(validate.ValidationError):
                validate.capture_git_snapshot(REPO_ROOT)

    def test_mutable_validator_copy_cannot_claim_immutable_attestation(self) -> None:
        path = Path(validate.__file__).resolve()
        original = path.read_bytes()
        try:
            path.write_bytes(original + b"\n# mutable substitution\n")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = validate.main(["--repo-root", str(REPO_ROOT)])
            payload = json.loads(stdout.getvalue())
            self.assertEqual(result, 1)
            self.assertFalse(payload["attestation_verified"])
            self.assertLess(len(json.dumps(payload)), 2048)
            self.assertNotIn("mutable substitution", stdout.getvalue())
        finally:
            path.write_bytes(original)

    def test_cases_are_deterministic_and_fail_closed(self) -> None:
        validate.validate_cases(self.cases)
        unknown = next(item for item in self.cases["cases"] if item["id"] == "unknown_revision")
        self.assertEqual(unknown["expected"]["attestation_result"], "blocked")
        self.assertEqual(unknown["expected"]["runtime_gate"], "blocked_incompatible")
        abbreviated = next(item for item in self.cases["cases"] if item["id"] == "abbreviated_revision")
        self.assertEqual(abbreviated["expected"]["attestation_result"], "blocked")
        empty = next(item for item in self.cases["cases"] if item["id"] == "empty_attestation")
        self.assertEqual(empty["expected"]["runtime_gate"], "blocked_incompatible")

    def test_every_case_executes_validator_semantics(self) -> None:
        validate.validate_cases(self.cases)
        for case in self.cases["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(validate.evaluate_case(case, REPO_ROOT), case["expected"])

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

    def test_evidence_digest_rebinding_is_rejected_for_each_reference(self) -> None:
        for evidence_key in ("route_manifest", "source_review", "proxy_proof"):
            with self.subTest(evidence_key=evidence_key), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for key, expected in validate.EVIDENCE.items():
                    target = root / expected["path"]
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(REPO_ROOT / expected["path"], target)
                changed = b"changed synthetic evidence"
                target = root / validate.EVIDENCE[evidence_key]["path"]
                target.write_bytes(changed)
                record = copy.deepcopy(self.record)
                record[evidence_key]["sha256"] = hashlib.sha256(changed).hexdigest()
                record[evidence_key]["size_bytes"] = len(changed)
                with self.assertRaises(validate.ValidationError):
                    validate.validate_attestation(record, root, verify_git=False)

    def test_credential_shaped_value_is_rejected(self) -> None:
        record = copy.deepcopy(self.record)
        record["deployment"]["identity"] = "Bearer synthetic-marker"
        with self.assertRaises(validate.ValidationError):
            validate.validate_attestation(record, REPO_ROOT, verify_git=True)

    def test_case_text_redaction_rejects_hosts_emails_and_material_markers(self) -> None:
        markers = (
            "https://prod.example.com",
            "ftp://prod.example.com",
            "prod.example.com",
            "prod/host",
            "host=synthetic",
            "www.example.com",
            "192.0.2.10:443",
            "foo@localhost",
            "http://",
            "customer@example.com",
            "AWS_SECRET_ACCESS_KEY=synthetic",
            "API-KEY: synthetic",
            "X-API-Key=synthetic",
            "AWS-SECRET-ACCESS-KEY=synthetic",
            "password: synthetic",
            "token=synthetic",
            "Authorization: synthetic",
            "Bearer synthetic-marker",
            "Cookie: session=synthetic",
            "set_cookie=synthetic",
            "raw_ticket: synthetic",
            "session-token=synthetic",
            "access-token: synthetic",
            "host-name=synthetic",
            "ticket=synthetic",
        )
        for marker in markers:
            with self.subTest(marker=marker):
                cases = copy.deepcopy(self.cases)
                cases["cases"][0]["description"] = marker
                with self.assertRaises(validate.ValidationError):
                    validate.validate_cases(cases)

    def test_baseline_text_redaction_rejects_hosts_material_and_controls(self) -> None:
        mutations = (
            ("platform", "https://prod.example.com"),
            ("python", "Bearer synthetic-marker"),
            ("platform", "AWS_SECRET_ACCESS_KEY=synthetic"),
            ("python", "Cookie: session=synthetic"),
            ("platform", "ticket=synthetic"),
            ("python", "control\x01marker"),
            ("platform", "nul\x00marker"),
        )
        for field, marker in mutations:
            with self.subTest(field=field, marker=marker):
                baseline = copy.deepcopy(self.baseline)
                baseline["environment"][field] = marker
                with self.assertRaises(validate.ValidationError):
                    validate.validate_baseline(baseline, REPO_ROOT, verify_git=False)

    def test_redaction_normalizes_sensitive_key_aliases(self) -> None:
        aliases = (
            "API-KEY",
            "AWS-SECRET-ACCESS-KEY",
            "set_cookie",
            "Set-Cookie",
            "raw_ticket",
            "session-token",
            "access-token",
            "host_name",
            "Host-Name",
        )
        for alias in aliases:
            with self.subTest(alias=alias):
                with self.assertRaises(validate.ValidationError):
                    validate._validate_redaction({alias: "synthetic"})

    def test_redaction_depth_is_bounded(self) -> None:
        nested: object = "leaf"
        for _ in range(validate.MAX_REDACTION_DEPTH + 1):
            nested = [nested]
        with self.assertRaises(validate.ValidationError):
            validate._validate_redaction(nested)

    def test_json_shape_limits_reject_direct_values(self) -> None:
        with self.assertRaises(validate.ValidationError):
            validate._validate_redaction("x" * (validate.MAX_STRING_LENGTH + 1))
        with self.assertRaises(validate.ValidationError):
            validate._validate_redaction([0] * (validate.MAX_ARRAY_LENGTH + 1))
        with self.assertRaises(validate.ValidationError):
            validate._validate_redaction({str(index): 0 for index in range(validate.MAX_OBJECT_KEYS + 1)})
        nested = [[0] * validate.MAX_ARRAY_LENGTH for _ in range((validate.MAX_JSON_NODES // validate.MAX_ARRAY_LENGTH) + 1)]
        with self.assertRaises(validate.ValidationError):
            validate._validate_redaction(nested)

    def test_json_input_byte_limit_is_rejected_without_retaining_payload(self) -> None:
        marker = "oversized-secret-marker"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversized.json"
            path.write_bytes(b'{"value":"' + (b"x" * validate.MAX_JSON_BYTES) + marker.encode("ascii") + b'"}')
            with self.assertRaises(validate.ValidationError) as context:
                validate.load_json(path)
            self.assertNotIn(marker, str(context.exception))

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
        for literal in ("NaN", "Infinity", "-Infinity", "1e9999"):
            with self.subTest(literal=literal), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "nonfinite.json"
                path.write_text('{"value": ' + literal + '}', encoding="utf-8")
                with self.assertRaises(validate.ValidationError):
                    validate.load_json(path)

    def test_oversized_integer_is_rejected_without_float_conversion(self) -> None:
        baseline = copy.deepcopy(self.baseline)
        baseline["duration_ms"]["min"] = 10**10000
        with self.assertRaises(validate.ValidationError):
            validate.validate_baseline(baseline, REPO_ROOT, verify_git=False)

    def test_baseline_mean_must_be_finite_and_within_recorded_range(self) -> None:
        for value in (0, 999, 1e300):
            with self.subTest(value=value):
                baseline = copy.deepcopy(self.baseline)
                baseline["duration_ms"]["mean"] = value
                with self.assertRaises(validate.ValidationError):
                    validate.validate_baseline(baseline, REPO_ROOT, verify_git=False)

    def test_baseline_rejects_all_zero_durations(self) -> None:
        baseline = copy.deepcopy(self.baseline)
        baseline["duration_ms"] = {key: 0 for key in baseline["duration_ms"]}
        with self.assertRaises(validate.ValidationError):
            validate.validate_baseline(baseline, REPO_ROOT, verify_git=False)

    def test_baseline_environment_is_bound_to_measured_machine(self) -> None:
        for field, value in (("platform", "attacker"), ("python", "not-python")):
            with self.subTest(field=field):
                baseline = copy.deepcopy(self.baseline)
                baseline["environment"][field] = value
                with self.assertRaises(validate.ValidationError):
                    validate.validate_baseline(baseline, REPO_ROOT, verify_git=False)

    def test_baseline_artifact_digest_and_size_are_immutable(self) -> None:
        for mutation in ("sha256", "size_bytes"):
            with self.subTest(mutation=mutation):
                baseline = copy.deepcopy(self.baseline)
                if mutation == "sha256":
                    baseline["artifact_files"][0][mutation] = "0" * 64
                else:
                    baseline["artifact_files"][0][mutation] += 1
                with self.assertRaises(validate.ValidationError):
                    validate.validate_baseline(baseline, REPO_ROOT, verify_git=False)

    def test_baseline_has_no_invented_threshold(self) -> None:
        validate.validate_baseline(self.baseline, REPO_ROOT, verify_git=False)
        self.assertIsNone(self.baseline["threshold"])
        self.assertEqual(self.baseline["repetitions"], 30)

    def test_cli_rejects_malformed_json_with_structured_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "malformed.json"
            path.write_text('{"schema":', encoding="utf-8")
            original = validate.ATTESTATION_PATH
            validate.ATTESTATION_PATH = path
            stdout = io.StringIO()
            stderr = io.StringIO()
            try:
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    result = validate.main(["--repo-root", str(REPO_ROOT), "--worktree"])
            finally:
                validate.ATTESTATION_PATH = original
            payload = json.loads(stdout.getvalue())
            self.assertEqual(result, 1)
            self.assertFalse(payload["ok"])
            self.assertTrue(payload["fixture_valid"] is False)
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_cli_rejects_non_finite_json_with_structured_output(self) -> None:
        for literal in ("NaN", "Infinity", "-Infinity", "1e9999"):
            with self.subTest(literal=literal), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "nonfinite.json"
                path.write_text('{"value": ' + literal + '}', encoding="utf-8")
                original = validate.ATTESTATION_PATH
                validate.ATTESTATION_PATH = path
                stdout = io.StringIO()
                stderr = io.StringIO()
                try:
                    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        result = validate.main(["--repo-root", str(REPO_ROOT), "--worktree"])
                finally:
                    validate.ATTESTATION_PATH = original
                payload = json.loads(stdout.getvalue())
                self.assertEqual(result, 1)
                self.assertFalse(payload["ok"])
                self.assertNotIn("Traceback", stderr.getvalue())

    def test_cli_rejects_bounded_json_overflows_with_capped_output(self) -> None:
        oversized_values = (
            "string",
            "array",
            "object",
            "nodes",
            "bytes",
        )
        for kind in oversized_values:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                if kind == "string":
                    value = "x" * (validate.MAX_STRING_LENGTH + 1)
                elif kind == "array":
                    value = [0] * (validate.MAX_ARRAY_LENGTH + 1)
                elif kind == "object":
                    value = {str(index): 0 for index in range(validate.MAX_OBJECT_KEYS + 1)}
                elif kind == "nodes":
                    value = [[0] * validate.MAX_ARRAY_LENGTH for _ in range((validate.MAX_JSON_NODES // validate.MAX_ARRAY_LENGTH) + 1)]
                else:
                    value = "x" * validate.MAX_JSON_BYTES
                path = Path(directory) / "oversized.json"
                path.write_text(json.dumps({"value": value}), encoding="utf-8")
                original = validate.ATTESTATION_PATH
                validate.ATTESTATION_PATH = path
                stdout = io.StringIO()
                stderr = io.StringIO()
                try:
                    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        result = validate.main(["--repo-root", str(REPO_ROOT), "--worktree"])
                finally:
                    validate.ATTESTATION_PATH = original
                payload = json.loads(stdout.getvalue())
                self.assertEqual(result, 1)
                self.assertFalse(payload["ok"])
                self.assertLess(len(json.dumps(payload)), 2048)
                self.assertNotIn("oversized-secret-marker", stdout.getvalue())
                self.assertNotIn("Traceback", stderr.getvalue())

    def test_cli_rejects_oversized_baseline_integer_with_structured_output(self) -> None:
        baseline = copy.deepcopy(self.baseline)
        baseline["duration_ms"]["min"] = int("9" * 1000)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            path.write_text(json.dumps(baseline), encoding="utf-8")
            original = validate.BASELINE_PATH
            validate.BASELINE_PATH = path
            stdout = io.StringIO()
            stderr = io.StringIO()
            try:
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    result = validate.main(["--repo-root", str(REPO_ROOT), "--worktree"])
            finally:
                validate.BASELINE_PATH = original
            payload = json.loads(stdout.getvalue())
            self.assertEqual(result, 1)
            self.assertFalse(payload["ok"])
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_worktree_output_never_claims_immutable_attestation(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            result = validate.main(["--repo-root", str(REPO_ROOT), "--worktree"])
        payload = json.loads(stdout.getvalue())
        self.assertEqual(result, 0)
        self.assertTrue(payload["fixture_valid"])
        self.assertFalse(payload["attestation_verified"])
        self.assertEqual(payload["source_mode"], "worktree")
        self.assertIsNone(payload["verified_commit"])
        self.assertIsNone(payload["verified_tree"])
        self.assertIsNone(payload["executing_commit"])
        self.assertFalse(payload["measurement_authenticated"])
        for item in self.cases["cases"]:
            self.assertNotEqual(item["expected"]["runtime_gate"], "enabled")

    def test_immutable_output_reports_commit_and_tree(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            result = validate.main(["--repo-root", str(REPO_ROOT)])
        payload = json.loads(stdout.getvalue())
        self.assertEqual(result, 0)
        self.assertTrue(payload["fixture_valid"])
        self.assertTrue(payload["attestation_verified"])
        self.assertEqual(payload["source_mode"], "immutable_commit")
        self.assertEqual(payload["verified_commit"], validate.REVIEWED_COMMIT)
        self.assertEqual(payload["verified_tree"], validate.REVIEWED_TREE)
        self.assertRegex(payload["executing_commit"], r"^[0-9a-f]{40}$")
        self.assertFalse(payload["measurement_authenticated"])


if __name__ == "__main__":
    unittest.main()
