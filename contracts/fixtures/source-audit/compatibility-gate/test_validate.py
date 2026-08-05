#!/usr/bin/env python3
"""Regression tests for the offline compatibility-gate validator."""

from __future__ import annotations

import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock
from pathlib import Path

import validate


FIXTURE_DIR = Path(__file__).resolve().parent
REPO_ROOT = FIXTURE_DIR.parents[3]
README_PATH = FIXTURE_DIR / "README.md"
RECORD_PATH = FIXTURE_DIR / "compatibility_record.json"


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def _temporary_git_fixture(directory: str) -> tuple[Path, str]:
    root = Path(directory) / "source"
    root.mkdir()
    _git(root, "init", "-q")
    (root / "fixture.txt").write_text("pinned fixture\n", encoding="utf-8")
    (root / "tree").mkdir()
    (root / "tree" / "child.txt").write_text("tree object\n", encoding="utf-8")
    _git(root, "add", "fixture.txt", "tree/child.txt")
    _git(
        root,
        "-c",
        "user.name=Hermternal Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-qm",
        "fixture",
    )
    revision = _git(root, "rev-parse", "HEAD").stdout.strip()
    return root, revision


class CompatibilityGateValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.record = validate.load_record(RECORD_PATH)

    def assert_rejected(
        self,
        record: dict[str, object],
        *,
        verify_git: bool = False,
        snapshot: validate.CapturedSnapshot | None = None,
    ) -> None:
        with self.assertRaises(validate.ValidationError):
            validate.validate_record(record, REPO_ROOT, verify_git=verify_git, snapshot=snapshot)

    def test_checked_in_record_passes_against_merged_dev(self) -> None:
        artifact_count = validate.validate_record(self.record, REPO_ROOT)
        self.assertEqual(artifact_count, len(validate.ARTIFACT_PATHS))
        self.assertEqual(
            validate._artifact_set_digest(self.record["artifacts"]["files"]),
            self.record["artifacts"]["set_sha256"],
        )

    def test_current_dev_integration_is_separate_from_historical_review(self) -> None:
        self.assertEqual(
            self.record["merged_dev"]["head"],
            validate.HISTORICAL_DEV_HEAD,
        )
        self.assertNotEqual(
            self.record["integration_dev"]["head"],
            self.record["merged_dev"]["head"],
        )
        stale = copy.deepcopy(self.record)
        stale["integration_dev"]["head"] = stale["merged_dev"]["head"]
        self.assert_rejected(stale, verify_git=True)

    def test_canonical_record_and_validator_match_one_committed_snapshot(self) -> None:
        snapshot = validate._capture_snapshot(REPO_ROOT)
        self.assertEqual(snapshot.commit, _git(REPO_ROOT, "rev-parse", "HEAD").stdout.strip())
        self.assertEqual(snapshot.tree, _git(REPO_ROOT, "rev-parse", "HEAD^{tree}").stdout.strip())
        self.assertEqual(snapshot.record_bytes, RECORD_PATH.read_bytes())
        self.assertEqual(snapshot.validator_bytes, Path(validate.__file__).read_bytes())
        self.assertEqual(snapshot.record_blob, _git(REPO_ROOT, "rev-parse", f"{snapshot.commit}:contracts/fixtures/source-audit/compatibility-gate/compatibility_record.json").stdout.strip())
        self.assertEqual(snapshot.validator_blob, _git(REPO_ROOT, "rev-parse", f"{snapshot.commit}:contracts/fixtures/source-audit/compatibility-gate/validate.py").stdout.strip())

    def test_working_tree_record_replacement_cannot_authorize_success(self) -> None:
        original = RECORD_PATH.read_bytes()
        mutated = copy.deepcopy(self.record)
        mutated["integration_dev"]["head"] = "0" * 40
        try:
            RECORD_PATH.write_text(json.dumps(mutated), encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                code = validate.main(["--repo-root", str(REPO_ROOT)])
            self.assertEqual(code, 1)
            result = json.loads(output.getvalue())
            self.assertFalse(result["ok"])
            self.assertIsNone(result["verified_commit"])
            self.assertNotIn(str(RECORD_PATH), output.getvalue())
        finally:
            RECORD_PATH.write_bytes(original)

    def test_alternate_record_is_never_attested(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            alternate = Path(directory) / "attacker-record.json"
            attacker = copy.deepcopy(self.record)
            # This is self-consistent with another locally available commit, but
            # it must still be rejected before arbitrary bytes reach authority.
            attacker["integration_dev"]["head"] = validate.HISTORICAL_DEV_HEAD
            attacker["integration_dev"]["tree"] = validate.HISTORICAL_DEV_TREE
            alternate.write_text(json.dumps(attacker), encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                code = validate.main(["--repo-root", str(REPO_ROOT), "--record", str(alternate)])
            self.assertEqual(code, 1)
            result = json.loads(output.getvalue())
            self.assertFalse(result["ok"])
            self.assertIsNone(result["verified_commit"])
            self.assertNotIn("current_dev", output.getvalue())
            self.assertNotIn(str(alternate), output.getvalue())

    def test_snapshot_commit_argument_must_be_an_exact_commit_object(self) -> None:
        tree = _git(REPO_ROOT, "rev-parse", "HEAD^{tree}").stdout.strip()
        with self.assertRaises(validate.ValidationError):
            validate._capture_snapshot(REPO_ROOT, tree)

    def test_moved_dev_ref_fails_closed_after_snapshot_capture(self) -> None:
        snapshot = validate._capture_snapshot(REPO_ROOT)
        real_commit_oid = validate._git_commit_oid
        calls = {"dev": 0}

        def moved_ref(root: Path, expression: str) -> str | None:
            if expression == snapshot.dev_ref:
                calls["dev"] += 1
                if calls["dev"] >= 1:
                    return "0" * 40
            return real_commit_oid(root, expression)

        with mock.patch.object(validate, "_git_commit_oid", side_effect=moved_ref):
            self.assert_rejected(self.record, verify_git=True, snapshot=snapshot)

    def test_missing_or_malformed_current_commit_fails_closed(self) -> None:
        malformed = copy.deepcopy(self.record)
        malformed["integration_dev"]["head"] = "not-a-commit"
        self.assert_rejected(malformed)

        missing = copy.deepcopy(self.record)
        missing["integration_dev"]["head"] = "0" * 40
        self.assert_rejected(missing, verify_git=True)

    def test_boolean_integer_confusion_is_rejected_at_every_numeric_field(self) -> None:
        for path in (
            ("merged_dev", "merged_prs", 0, "number"),
            ("artifacts", "files", 0, "size_bytes"),
            ("observations", "repetitions"),
        ):
            mutated = copy.deepcopy(self.record)
            cursor: object = mutated
            for part in path[:-1]:
                cursor = cursor[part] if not isinstance(part, int) else cursor[part]
            cursor[path[-1]] = True
            with self.subTest(path=path):
                self.assert_rejected(mutated)

    def test_duplicate_json_key_is_rejected_before_schema_validation(self) -> None:
        for text in (
            '{"schema":"one","schema":"two"}',
            '{"outer":{"key":1,"key":2}}',
        ):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "duplicate.json"
                path.write_text(text, encoding="utf-8")
                with self.assertRaises(validate.DuplicateKeyError):
                    validate.load_record(path)

    def test_malformed_json_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "malformed.json"
            path.write_text("{not-json", encoding="utf-8")
            with self.assertRaises(validate.ValidationError):
                validate.load_record(path)

    def test_nonfinite_and_exponent_overflow_json_is_rejected(self) -> None:
        for text in (
            '{"value": NaN}',
            '{"value": Infinity}',
            '{"value": -Infinity}',
            '{"value": 1e9999}',
            '{"value": -1e9999}',
        ):
            with self.subTest(text=text), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "nonfinite.json"
                path.write_text(text, encoding="utf-8")
                with self.assertRaises(validate.ValidationError):
                    validate.load_record(path)

    def test_bounded_json_bytes_strings_containers_nodes_and_integers_are_rejected(self) -> None:
        oversized = '{"value":"' + ("x" * (validate.MAX_JSON_STRING_BYTES + 1)) + '"}'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversized.json"
            path.write_text(oversized, encoding="utf-8")
            with self.assertRaises(validate.ValidationError):
                validate.load_record(path)
            path.write_bytes(b"{" + b'"value":"' + b"x" * validate.MAX_JSON_BYTES + b'"}')
            with self.assertRaises(validate.ValidationError):
                validate.load_record(path)

        with self.assertRaises(validate.ValidationError):
            validate._load_record_bytes(b"{" + b'"value":' + b"9" * (validate.MAX_JSON_INTEGER_DIGITS + 1) + b"}")

        for value in (
            {"items": [None] * (validate.MAX_JSON_CONTAINER_ITEMS + 1)},
            {"items": {str(index): None for index in range(validate.MAX_JSON_CONTAINER_ITEMS + 1)}},
        ):
            with self.subTest(container=len(value["items"])):
                with self.assertRaises(validate.ValidationError):
                    validate._validate_json_tree(value)

        value: list[object] = [None] * (validate.MAX_JSON_NODES + 1)
        with self.assertRaises(validate.ValidationError):
            validate._validate_json_tree(value)

    def test_deep_json_is_rejected_without_tracebacks(self) -> None:
        value: dict[str, object] = {}
        cursor = value
        for _ in range(validate.MAX_JSON_DEPTH + 16):
            child: dict[str, object] = {}
            cursor["nested"] = child
            cursor = child
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "deep.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(validate.ValidationError):
                validate.load_record(path)
            for optimized in (False, True):
                command = [sys.executable]
                if optimized:
                    command.append("-O")
                command.extend(
                    [
                        str(validate.__file__),
                        "--repo-root",
                        str(REPO_ROOT),
                        "--record",
                        str(path),
                    ]
                )
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(result.returncode, 1, (optimized, result.stderr))
                self.assertNotIn("Traceback", result.stdout + result.stderr)
                parsed = json.loads(result.stdout)
                self.assertFalse(parsed["ok"])
                self.assertEqual(len(parsed["errors"]), 1)
                self.assertLessEqual(len(parsed["errors"][0].encode("utf-8")), validate.MAX_ERROR_MESSAGE_BYTES)
                self.assertNotIn(str(path), result.stdout)

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

    def test_git_batch_binding_rejects_redirects_replace_lazy_fetch_wrong_missing_and_truncated_objects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, revision = _temporary_git_fixture(directory)
            expected = b"pinned fixture\n"
            self.assertEqual(validate._git_blob(root, revision, "fixture.txt"), expected)
            self.assertIsNone(validate._git_blob(root, revision, "tree"))
            self.assertIsNone(validate._git_blob(root, revision, "missing.txt"))
            self.assertIsNone(validate._git_commit_oid(root, "0" * 40))

            (root / "fixture.txt").write_text("replacement fixture\n", encoding="utf-8")
            _git(root, "add", "fixture.txt")
            _git(
                root,
                "-c",
                "user.name=Hermternal Replacement",
                "-c",
                "user.email=replacement@example.invalid",
                "commit",
                "-qm",
                "replacement",
            )
            replacement = _git(root, "rev-parse", "HEAD").stdout.strip()
            _git(root, "replace", revision, replacement)
            self.assertEqual(validate._git_blob(root, revision, "fixture.txt"), expected)

            decoy = Path(directory) / "decoy"
            decoy.mkdir()
            _git(decoy, "init", "-q")
            redirect_environment = {
                "GIT_DIR": str(decoy / ".git"),
                "GIT_COMMON_DIR": str(decoy / ".git"),
                "GIT_OBJECT_DIRECTORY": str(decoy / ".git" / "objects"),
                "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(decoy / ".git" / "objects"),
                "GIT_NAMESPACE": "decoy",
                "GIT_WORK_TREE": str(decoy),
                "GIT_INDEX_FILE": str(decoy / ".git" / "index"),
                "GIT_CEILING_DIRECTORIES": str(directory),
                "GIT_DISCOVERY_ACROSS_FILESYSTEM": "1",
            }
            captured_environment: dict[str, str] = {}
            real_run = validate.subprocess.run

            def capture_batch_environment(*args: object, **kwargs: object) -> subprocess.CompletedProcess[object]:
                command = args[0] if args else kwargs.get("args")
                if isinstance(command, list) and "cat-file" in command:
                    captured_environment.update(kwargs["env"])
                return real_run(*args, **kwargs)

            with (
                mock.patch.dict(os.environ, redirect_environment, clear=False),
                mock.patch.object(validate.subprocess, "run", side_effect=capture_batch_environment),
            ):
                self.assertEqual(validate._git_blob(root, revision, "fixture.txt"), expected)
            self.assertEqual(captured_environment["GIT_NO_REPLACE_OBJECTS"], "1")
            self.assertEqual(captured_environment["GIT_NO_LAZY_FETCH"], "1")
            for variable in redirect_environment:
                self.assertNotIn(variable, captured_environment)

            truncated = subprocess.CompletedProcess(
                args=["git", "cat-file", "--batch"],
                returncode=0,
                stdout=b"a" * 40 + b" blob 9\nshort\n",
                stderr=b"",
            )
            with mock.patch.object(validate.subprocess, "run", return_value=truncated):
                self.assertIsNone(validate._git_blob(root, revision, "fixture.txt"))

            expected_oid = validate._git_path_oid(root, revision, "fixture.txt")
            self.assertIsNotNone(expected_oid)
            extra_output = subprocess.CompletedProcess(
                args=["git", "cat-file", "--batch"],
                returncode=0,
                stdout=expected_oid.encode("ascii") + b" blob 15\npinned fixture\nextra\n",
                stderr=b"",
            )
            with (
                mock.patch.object(validate, "_git_path_oid", return_value=expected_oid),
                mock.patch.object(validate.subprocess, "run", return_value=extra_output),
            ):
                self.assertIsNone(validate._git_blob(root, revision, "fixture.txt"))

            wrong_oid = subprocess.CompletedProcess(
                args=["git", "cat-file", "--batch"],
                returncode=0,
                stdout=b"0" * 40 + b" blob 15\npinned fixture\n",
                stderr=b"",
            )
            with (
                mock.patch.object(validate, "_git_path_oid", return_value=expected_oid),
                mock.patch.object(validate.subprocess, "run", return_value=wrong_oid),
            ):
                self.assertIsNone(validate._git_blob(root, revision, "fixture.txt"))

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

    def test_observation_values_are_finite_unthresholded_and_reproducible(self) -> None:
        for forged_value in (float("nan"), float("inf"), float("-inf"), True, -1.0):
            mutated = copy.deepcopy(self.record)
            mutated["observations"]["validator_duration_ms"]["normal"]["samples_ms"][0] = forged_value
            with self.subTest(forged_value=forged_value):
                self.assert_rejected(mutated)

        mutated = copy.deepcopy(self.record)
        mutated["observations"]["validator_duration_ms"]["normal"]["threshold"] = 1.0
        self.assert_rejected(mutated)

        mutated = copy.deepcopy(self.record)
        mutated["observations"]["artifact_size_bytes"] += 1
        self.assert_rejected(mutated)

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
            "`merged_dev`, the immutable historical review",
            "`integration_dev`, the explicit captured `origin/dev` snapshot",
            "one complete `git cat-file --batch` response",
            "## Accessibility",
            "Accessibility verification is N/A for this operation because it produces no UI",
            "preserves rather than removes those future accessibility requirements",
            "## Reproducible tooling benchmark",
            "30 raw subprocess samples for both normal and optimized Python execution",
            "min/p50/p95/p99/max/mean distribution",
            "`threshold: null`",
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
        self.assertEqual(result["historical_reviewed_commit"], self.record["merged_dev"]["head"])
        self.assertEqual(result["verified_commit_kind"], "captured_snapshot")
        self.assertEqual(result["verified_commit"], _git(REPO_ROOT, "rev-parse", "HEAD").stdout.strip())
        self.assertEqual(result["captured_dev_commit"], self.record["integration_dev"]["head"])
        self.assertEqual(result["captured_dev_ref"], "refs/remotes/origin/dev")
        self.assertEqual(result["evidence_scope"], "historical_review_and_captured_snapshot")
        self.assertEqual(result["errors"], [])

        for optimized in (False, True):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.extend(
                [
                    str(validate.__file__),
                    "--repo-root",
                    str(REPO_ROOT),
                    "--record",
                    str(RECORD_PATH),
                ]
            )
            completed = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, (optimized, completed.stderr))
            self.assertNotIn("Traceback", completed.stdout + completed.stderr)
            cli_result = json.loads(completed.stdout)
            self.assertEqual(cli_result["verified_commit"], _git(REPO_ROOT, "rev-parse", "HEAD").stdout.strip())
            self.assertEqual(cli_result["verified_commit_kind"], "captured_snapshot")


if __name__ == "__main__":
    unittest.main(verbosity=2)
