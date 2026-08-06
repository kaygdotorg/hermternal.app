#!/usr/bin/env python3
"""Regression tests for the aggregate fixture registry validator."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import validate


class StrictJsonTests(unittest.TestCase):
    def _write(self, payload: bytes) -> Path:
        handle = tempfile.NamedTemporaryFile(prefix="fixture-validator-", suffix=".json", delete=False)
        path = Path(handle.name)
        try:
            handle.write(payload)
            handle.close()
        except Exception:
            handle.close()
            path.unlink(missing_ok=True)
            raise
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        return path

    def test_duplicate_object_keys_fail_before_overwrite(self) -> None:
        with self.assertRaises(validate.DuplicateKeyError):
            validate.load_json(self._write(b'{"schema":"one","schema":"two"}'))

    def test_non_finite_number_fails(self) -> None:
        with self.assertRaises(validate.ValidationError):
            validate.load_json(self._write(b'{"value":NaN}'))
        with self.assertRaises(validate.ValidationError):
            validate.load_json(self._write(b'{"value":1e999}'))

    def test_invalid_utf8_fails(self) -> None:
        with self.assertRaises(validate.ValidationError):
            validate.load_json(self._write(b'{"value":"\xff"}'))

    def test_oversized_input_fails_before_json_parse(self) -> None:
        with self.assertRaises(validate.ValidationError):
            validate.load_json(self._write(b"{" + b"a" * validate.MAX_JSON_BYTES + b"}"))

    def test_excessive_integer_and_depth_fail(self) -> None:
        with self.assertRaises(validate.ValidationError):
            validate.load_json(self._write(("{\"value\":" + "9" * (validate.MAX_INTEGER_DIGITS + 1) + "}").encode()))
        nested = "0"
        for _ in range(validate.MAX_JSON_DEPTH + 2):
            nested = "[" + nested + "]"
        with self.assertRaises(validate.ValidationError):
            validate.load_json(self._write(("{\"value\":" + nested + "}").encode()))

    def test_nul_is_rejected_in_registry_documents(self) -> None:
        with self.assertRaises(validate.ValidationError):
            validate.load_json(self._write(b'{"value":"\\u0000"}'))


class RegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.index = validate.load_json(validate.INDEX_PATH)
        cls.schema = validate.load_json(validate.SCHEMA_PATH)
        cls.baseline = validate.load_json(validate.BASELINE_PATH)

    def test_checked_in_registry_is_valid_and_partial_is_not_success(self) -> None:
        fixture_count, coverage_count = validate.validate_all(
            self.index,
            self.schema,
            self.baseline,
            repo_root=validate.REPO_ROOT,
            baseline_path=validate.BASELINE_PATH,
        )
        self.assertEqual(fixture_count, len(self.index["fixture_roots"]))
        self.assertEqual(coverage_count, len(self.index["coverage"]))
        self.assertEqual(self.index["evidence_status"], "partial")
        self.assertFalse(self.index["live_claim"])

    def test_digest_mutation_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.index)
        mutated["fixture_roots"][0]["files"][0]["sha256"] = "0" * 64
        with self.assertRaises(validate.ValidationError):
            validate._validate_index_document(mutated, validate.REPO_ROOT)

    def test_reordered_root_keys_fail_closed(self) -> None:
        mutated = copy.deepcopy(self.index)
        mutated["contract"], mutated["schema"] = mutated["schema"], mutated["contract"]
        with self.assertRaises(validate.ValidationError):
            validate._validate_index_document(mutated, validate.REPO_ROOT)

    def test_live_claim_and_pending_success_claim_fail_closed(self) -> None:
        mutated = copy.deepcopy(self.index)
        mutated["live_claim"] = True
        with self.assertRaises(validate.ValidationError):
            validate._validate_index_document(mutated, validate.REPO_ROOT)

        mutated = copy.deepcopy(self.index)
        pending = next(item for item in mutated["coverage"] if item["status"] == "pending")
        pending["status"] = "ready"
        with self.assertRaises(validate.ValidationError):
            validate._validate_index_document(mutated, validate.REPO_ROOT)

    def test_redaction_mutation_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.index)
        mutated["redaction"]["contains_credentials"] = True
        with self.assertRaises(validate.ValidationError):
            validate._validate_index_document(mutated, validate.REPO_ROOT)

        with self.assertRaises(validate.ValidationError):
            validate._validate_text_value("Authorization: Bearer live-secret-value-1234")

    def test_baseline_threshold_and_distribution_mutations_fail(self) -> None:
        mutated = copy.deepcopy(self.baseline)
        mutated["threshold"] = 1.0
        with self.assertRaises(validate.ValidationError):
            validate._validate_baseline(mutated, validate.REPO_ROOT, validate.BASELINE_PATH)

        mutated = copy.deepcopy(self.baseline)
        mutated["normal"]["distribution_ms"]["p95"] += 1.0
        with self.assertRaises(validate.ValidationError):
            validate._validate_baseline(mutated, validate.REPO_ROOT, validate.BASELINE_PATH)


class CliTests(unittest.TestCase):
    def _run(
        self,
        *args: str,
        optimized: bool = False,
        repo_root: Path = validate.REPO_ROOT,
    ) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        script = repo_root / "contracts/fixtures/validator/validate.py"
        command.extend([str(script), *args])
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            command,
            cwd=repo_root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    def _copy_fixture_repo(self) -> Path:
        temporary = Path(tempfile.mkdtemp(prefix="fixture-validator-cli-"))
        self.addCleanup(shutil.rmtree, temporary, ignore_errors=True)
        shutil.copytree(
            validate.REPO_ROOT / "contracts/fixtures",
            temporary / "contracts/fixtures",
        )
        return temporary

    def _rebind_copy(self, repo_root: Path) -> tuple[dict[str, object], dict[str, object]]:
        """Refresh only integrity records in an isolated synthetic copy."""
        fixtures_root = repo_root / "contracts/fixtures"
        index_path = fixtures_root / "index.json"
        baseline_path = fixtures_root / "validator/validation-baseline.json"
        index = json.loads(index_path.read_text(encoding="utf-8"))
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))

        for fixture in index["fixture_roots"]:
            for record in fixture["files"]:
                artifact = fixtures_root / record["path"]
                if artifact.is_file():
                    data = artifact.read_bytes()
                    record["size_bytes"] = len(data)
                    record["sha256"] = hashlib.sha256(data).hexdigest()
        index_path.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")

        total = 0
        for record in baseline["artifact_manifest"]:
            artifact = repo_root / record["path"]
            data = artifact.read_bytes()
            record["size_bytes"] = len(data)
            record["sha256"] = hashlib.sha256(data).hexdigest()
            total += len(data)
        baseline["artifact_size_bytes"] = total
        baseline_path.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
        return index, baseline

    def _assert_blocked_in_both_modes(self, repo_root: Path, *args: str) -> None:
        for optimized in (False, True):
            completed = self._run(*args, optimized=optimized, repo_root=repo_root)
            self.assertEqual(completed.returncode, 1)
            self.assertEqual(completed.stderr, "")
            self.assertEqual(len(completed.stdout.splitlines()), 1)
            self.assertLessEqual(len(completed.stdout.strip()), validate.MAX_ERROR_LENGTH)
            payload = json.loads(completed.stdout)
            self.assertFalse(payload["ok"])
            self.assertFalse(payload["live_claim"])
            self.assertEqual(payload["evidence_status"], "blocked")

    def test_normal_and_optimized_success_have_same_boundary(self) -> None:
        normal = self._run()
        optimized = self._run(optimized=True)
        self.assertEqual(normal.returncode, 0)
        self.assertEqual(optimized.returncode, 0)
        self.assertEqual(json.loads(normal.stdout), json.loads(optimized.stdout))
        self.assertFalse(json.loads(normal.stdout)["compatible"])
        self.assertEqual(normal.stderr, "")
        self.assertEqual(optimized.stderr, "")

    def test_alternate_modified_baseline_is_rejected_in_both_modes(self) -> None:
        repo_root = self._copy_fixture_repo()
        alternate = repo_root / "contracts/fixtures/validator/alternate-baseline.json"
        baseline = json.loads((repo_root / "contracts/fixtures/validator/validation-baseline.json").read_text())
        baseline["notes"] = "forged alternate evidence"
        alternate.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
        self._assert_blocked_in_both_modes(repo_root, "--baseline", str(alternate))

    def test_registered_python_sensitive_value_is_rejected_in_both_modes(self) -> None:
        repo_root = self._copy_fixture_repo()
        python_artifact = repo_root / "contracts/fixtures/connection-restoration/validate.py"
        python_artifact.write_text(
            python_artifact.read_text(encoding="utf-8")
            + '\nFORGED_RETAINED_VALUE = "Bearer unredacted-secret-value-123456"\n',
            encoding="utf-8",
        )
        self._rebind_copy(repo_root)
        self._assert_blocked_in_both_modes(repo_root)

    def test_ready_coverage_cannot_reference_pending_root_in_both_modes(self) -> None:
        repo_root = self._copy_fixture_repo()
        index_path = repo_root / "contracts/fixtures/index.json"
        index = json.loads(index_path.read_text(encoding="utf-8"))
        provider = next(item for item in index["fixture_roots"] if item["id"] == "provider-discovery")
        shutil.rmtree(repo_root / "contracts/fixtures/provider-discovery")
        provider["path"] = "pending-provider-discovery"
        provider["status"] = "pending"
        provider["validator"] = None
        provider["files"] = []
        index_path.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
        self._rebind_copy(repo_root)
        self._assert_blocked_in_both_modes(repo_root)

    def test_unknown_flag_is_one_bounded_redacted_line(self) -> None:
        normal = self._run("--unknown-flag=synthetic-secret-value")
        optimized = self._run("--unknown-flag=synthetic-secret-value", optimized=True)
        for completed in (normal, optimized):
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(completed.stderr, "")
            self.assertEqual(len(completed.stdout.splitlines()), 1)
            self.assertLessEqual(len(completed.stdout.strip()), validate.MAX_ERROR_LENGTH)
            self.assertNotIn("synthetic-secret-value", completed.stdout)
            self.assertEqual(json.loads(completed.stdout)["live_claim"], False)


if __name__ == "__main__":
    unittest.main()
