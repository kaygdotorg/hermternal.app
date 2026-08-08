#!/usr/bin/env python3
"""Regression tests for the aggregate fixture registry validator."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import shutil
import statistics
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

    def test_canonical_baseline_anchor_matches_checked_in_content(self) -> None:
        self.assertEqual(validate._canonical_baseline_digest(self.baseline), validate.BASELINE_CANONICAL_SHA256)


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

    def _rebind_copy(
        self,
        repo_root: Path,
        *,
        refresh_anchor: bool = False,
    ) -> tuple[dict[str, object], dict[str, object]]:
        """Refresh integrity records in an isolated synthetic copy."""
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
        if refresh_anchor:
            validator_path = repo_root / "contracts/fixtures/validator/validate.py"
            source = validator_path.read_text(encoding="utf-8")
            old_anchor = f'BASELINE_CANONICAL_SHA256 = "{validate.BASELINE_CANONICAL_SHA256}"'
            digest = validate._canonical_baseline_digest(baseline)
            source = source.replace(old_anchor, f'BASELINE_CANONICAL_SHA256 = "{digest}"', 1)
            validator_path.write_text(source, encoding="utf-8")
            for record in baseline["artifact_manifest"]:
                if record["path"] == validate.BASELINE_SELF_MANIFEST_PATH:
                    data = validator_path.read_bytes()
                    record["size_bytes"] = len(data)
                    record["sha256"] = hashlib.sha256(data).hexdigest()
            baseline["artifact_size_bytes"] = sum(record["size_bytes"] for record in baseline["artifact_manifest"])
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

    def _run_scanner(self, artifact: Path, *, optimized: bool) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend([
            "-c",
            (
                "import sys; from pathlib import Path; "
                "sys.path.insert(0, sys.argv[1]); import validate; "
                "validate._validate_python_file(Path(sys.argv[2]))"
            ),
            str(artifact.parent.parent / "validator"),
            str(artifact),
        ])
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            command,
            cwd=artifact.parents[2],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    def _assert_scanner_rejects_in_both_modes(self, relative_path: str, source: bytes) -> None:
        repo_root = self._copy_fixture_repo()
        artifact = repo_root / "contracts/fixtures" / relative_path
        artifact.write_bytes(source)
        for optimized in (False, True):
            completed = self._run_scanner(artifact, optimized=optimized)
            self.assertNotEqual(completed.returncode, 0)

    def _assert_scanner_accepts_in_both_modes(self, relative_path: str, source: bytes) -> None:
        repo_root = self._copy_fixture_repo()
        artifact = repo_root / "contracts/fixtures" / relative_path
        artifact.write_bytes(source)
        for optimized in (False, True):
            completed = self._run_scanner(artifact, optimized=optimized)
            self.assertEqual(completed.returncode, 0, completed.stderr)

    @staticmethod
    def _distribution(samples: list[float]) -> dict[str, float]:
        ordered = sorted(samples)
        p50 = ordered[min(len(ordered) - 1, max(0, math.ceil(0.50 * len(ordered)) - 1))]
        p95 = ordered[min(len(ordered) - 1, max(0, math.ceil(0.95 * len(ordered)) - 1))]
        return {
            "min": min(samples),
            "p50": p50,
            "p95": p95,
            "max": max(samples),
            "mean": statistics.mean(samples),
        }

    def test_normal_and_optimized_success_have_same_boundary(self) -> None:
        normal = self._run()
        optimized = self._run(optimized=True)
        self.assertEqual(normal.returncode, 0)
        self.assertEqual(optimized.returncode, 0)
        self.assertEqual(json.loads(normal.stdout), json.loads(optimized.stdout))
        self.assertFalse(json.loads(normal.stdout)["compatible"])
        self.assertEqual(normal.stderr, "")
        self.assertEqual(optimized.stderr, "")

    def test_every_owned_file_is_indexed_without_weakening_unknown_file_detection(self) -> None:
        repo_root = self._copy_fixture_repo()
        for optimized in (False, True):
            completed = self._run(optimized=optimized, repo_root=repo_root)
            self.assertEqual(completed.returncode, 0)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["fixture_count"], 22)
            self.assertEqual(payload["coverage_count"], 22)
            self.assertEqual(payload["evidence_status"], "partial")
            self.assertEqual(completed.stderr, "")

        unknown = repo_root / "contracts/fixtures/pty-detach-race/unregistered-artifact.txt"
        unknown.write_text("synthetic unknown artifact\n", encoding="utf-8")
        self._assert_blocked_in_both_modes(repo_root)

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
        self._rebind_copy(repo_root, refresh_anchor=True)
        self._assert_blocked_in_both_modes(repo_root)

    def test_registered_python_assignment_literal_and_comment_are_rejected_in_both_modes(self) -> None:
        repo_root = self._copy_fixture_repo()
        python_artifact = repo_root / "contracts/fixtures/connection-restoration/validate.py"
        python_artifact.write_text(
            python_artifact.read_text(encoding="utf-8")
            + '\nFORGED_TICKET_LITERAL = "ticket=unredacted-secret-value-123456"\n'
            + '# token=unredacted-comment-secret-123456\n',
            encoding="utf-8",
        )
        self._rebind_copy(repo_root, refresh_anchor=True)
        self._assert_blocked_in_both_modes(repo_root)

    def test_registered_ws_and_wss_live_hosts_are_rejected_in_both_modes(self) -> None:
        repo_root = self._copy_fixture_repo()
        readme = repo_root / "contracts/fixtures/connection-restoration/README.md"
        readme.write_text(
            readme.read_text(encoding="utf-8")
            + "\nws://live.example.net and wss://live.example.net must never be retained.\n",
            encoding="utf-8",
        )
        self._rebind_copy(repo_root, refresh_anchor=True)
        self._assert_blocked_in_both_modes(repo_root)

    def test_canonical_baseline_sample_distribution_manifest_replacement_is_rejected_in_both_modes(self) -> None:
        repo_root = self._copy_fixture_repo()
        baseline_path = repo_root / "contracts/fixtures/validator/validation-baseline.json"
        artifact = repo_root / "contracts/fixtures/validator/test_validate.py"
        artifact.write_text(artifact.read_text(encoding="utf-8") + "\n# coordinated evidence replacement marker\n", encoding="utf-8")
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        samples = list(baseline["normal"]["samples_ms"])
        samples[0] += 1.0
        baseline["normal"]["samples_ms"] = samples
        baseline["normal"]["distribution_ms"] = self._distribution(samples)
        for record in baseline["artifact_manifest"]:
            if record["path"] == "contracts/fixtures/validator/test_validate.py":
                data = artifact.read_bytes()
                record["size_bytes"] = len(data)
                record["sha256"] = hashlib.sha256(data).hexdigest()
        baseline["artifact_size_bytes"] = sum(record["size_bytes"] for record in baseline["artifact_manifest"])
        baseline_path.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
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
        self._rebind_copy(repo_root, refresh_anchor=True)
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
