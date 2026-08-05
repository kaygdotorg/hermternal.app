#!/usr/bin/env python3
"""Regression tests for the offline compatibility-gate validator."""

from __future__ import annotations

import copy
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import validate


FIXTURE_DIR = Path(__file__).resolve().parent
REPO_ROOT = FIXTURE_DIR.parents[3]
README_PATH = FIXTURE_DIR / "README.md"
RECORD_PATH = FIXTURE_DIR / "compatibility_record.json"


class CompatibilityGateValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.record = validate.load_record(RECORD_PATH)

    def assert_rejected(self, record: dict[str, object], *, verify_git: bool = False) -> None:
        with self.assertRaises(validate.ValidationError):
            validate.validate_record(record, REPO_ROOT, verify_git=verify_git)

    def test_checked_in_record_passes_against_merged_dev(self) -> None:
        artifact_count = validate.validate_record(self.record, REPO_ROOT)
        self.assertEqual(artifact_count, len(validate.ARTIFACT_PATHS))
        self.assertEqual(
            validate._artifact_set_digest(self.record["artifacts"]["files"]),
            self.record["artifacts"]["set_sha256"],
        )

    def test_duplicate_json_key_is_rejected_before_schema_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"schema":"one","schema":"two"}', encoding="utf-8")
            with self.assertRaises(validate.DuplicateKeyError):
                validate.load_record(path)

    def test_malformed_json_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "malformed.json"
            path.write_text("{not-json", encoding="utf-8")
            with self.assertRaises(validate.ValidationError):
                validate.load_record(path)

    def test_parent_traversal_and_absolute_paths_are_rejected(self) -> None:
        traversal = copy.deepcopy(self.record)
        traversal["artifacts"]["files"][0]["path"] = "../outside.json"
        self.assert_rejected(traversal)

        absolute = copy.deepcopy(self.record)
        absolute["artifacts"]["files"][0]["path"] = "/tmp/outside.json"
        self.assert_rejected(absolute)

        windows = copy.deepcopy(self.record)
        windows["artifacts"]["files"][0]["path"] = "C:/outside.json"
        self.assert_rejected(windows)

    def test_symlink_containment_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            outside = Path(directory) / "outside"
            root.mkdir()
            outside.mkdir()
            link = root / "link"
            os.symlink(outside, link)
            with self.assertRaises(validate.ValidationError):
                validate.resolve_under_root(root, "link/file.json")

    def test_sensitive_keys_and_credential_shapes_are_rejected(self) -> None:
        for value in (
            {"raw_ticket": "synthetic-ticket"},
            {"prompt": "synthetic prompt"},
            {"transcript": "synthetic transcript"},
            {"credential": "synthetic credential"},
            {"value": "Bearer synthetic-secret"},
            {"value": "ghp_live_synthetic_secret"},
        ):
            with self.subTest(value=value):
                with self.assertRaises(validate.ValidationError):
                    validate._validate_redaction(value)

        mutated = copy.deepcopy(self.record)
        mutated["blockers"][0] = "Bearer synthetic-secret"
        self.assert_rejected(mutated)

    def test_status_mutations_fail_closed(self) -> None:
        for field, value in (
            ("compatible", True),
            ("live_run", True),
            ("deployment_attestation", "passed"),
            ("behavioral_probe", "passed"),
            ("proxy_proof", "passed"),
            ("parity_evidence", "recorded"),
            ("benchmark_evidence", "recorded"),
        ):
            with self.subTest(field=field):
                mutated = copy.deepcopy(self.record)
                mutated["status"][field] = value
                self.assert_rejected(mutated)

    def test_non_boolean_live_run_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.record)
        mutated["status"]["live_run"] = 0
        self.assert_rejected(mutated)

    def test_observed_or_live_proof_fields_are_rejected(self) -> None:
        observed = copy.deepcopy(self.record)
        observed["status"]["observed"] = False
        self.assert_rejected(observed)

        live_proof = copy.deepcopy(self.record)
        live_proof["status"]["live_proof"] = "not_run"
        self.assert_rejected(live_proof)

    def test_artifact_digest_mutations_are_rejected(self) -> None:
        digest = copy.deepcopy(self.record)
        digest["artifacts"]["files"][0]["sha256"] = "0" * 64
        self.assert_rejected(digest, verify_git=True)

        set_digest = copy.deepcopy(self.record)
        set_digest["artifacts"]["set_sha256"] = "0" * 64
        self.assert_rejected(set_digest, verify_git=True)

        size = copy.deepcopy(self.record)
        size["artifacts"]["files"][0]["size_bytes"] += 1
        self.assert_rejected(size, verify_git=True)

    def test_merged_dev_identity_mutations_are_rejected(self) -> None:
        for field in ("head", "tree"):
            with self.subTest(field=field):
                mutated = copy.deepcopy(self.record)
                mutated["merged_dev"][field] = "0" * 40
                self.assert_rejected(mutated)

        commit = copy.deepcopy(self.record)
        commit["merged_dev"]["merged_prs"][0]["merge_commit"] = "0" * 40
        self.assert_rejected(commit)

    def test_artifact_paths_use_canonical_lexicographic_order(self) -> None:
        self.assertEqual(validate.ARTIFACT_PATHS, tuple(sorted(validate.ARTIFACT_PATHS)))
        self.assertEqual(
            tuple(item["path"] for item in self.record["artifacts"]["files"]),
            validate.ARTIFACT_PATHS,
        )

    def test_readme_preserves_accessibility_and_benchmark_requirements(self) -> None:
        readme = " ".join(README_PATH.read_text(encoding="utf-8").split())
        for marker in (
            "## Accessibility",
            "Accessibility verification is N/A for this operation because it produces no UI",
            "preserves rather than removes those future accessibility requirements",
            "## Reproducible tooling benchmark",
            "production or release build mode is N/A",
            "artifact bytes and validator-duration distribution",
            "no invented performance threshold",
            "30 validations against immutable local Git blobs",
            "raw command and output",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, readme)
        self.assertNotIn("issue's requested order", readme)
        self.assertNotIn("P0-01 blocker", readme)

    def test_artifact_and_merge_order_mutations_are_rejected(self) -> None:
        artifacts = copy.deepcopy(self.record)
        artifacts["artifacts"]["files"].reverse()
        self.assert_rejected(artifacts)

        merges = copy.deepcopy(self.record)
        merges["merged_dev"]["merged_prs"].reverse()
        self.assert_rejected(merges)

        duplicate_path = copy.deepcopy(self.record)
        duplicate_path["artifacts"]["files"][1]["path"] = duplicate_path["artifacts"]["files"][0]["path"]
        self.assert_rejected(duplicate_path)

    def test_unknown_nested_keys_are_rejected(self) -> None:
        mutated = copy.deepcopy(self.record)
        mutated["artifacts"]["files"][0]["unexpected"] = "synthetic"
        self.assert_rejected(mutated)

        mutated = copy.deepcopy(self.record)
        mutated["merged_dev"]["merged_prs"][0]["unexpected"] = "synthetic"
        self.assert_rejected(mutated)

    def test_cli_emits_structured_blocked_success(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            code = validate.main(["--repo-root", str(REPO_ROOT), "--record", str(RECORD_PATH)])
        self.assertEqual(code, 0)
        result = json.loads(output.getvalue())
        self.assertTrue(result["ok"])
        self.assertFalse(result["compatible"])
        self.assertFalse(result["live_run"])
        self.assertEqual(result["artifact_count"], len(validate.ARTIFACT_PATHS))


if __name__ == "__main__":
    unittest.main(verbosity=2)
