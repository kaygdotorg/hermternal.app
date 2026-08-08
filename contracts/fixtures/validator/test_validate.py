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

SCRIPTS_ROOT = Path(__file__).resolve().parents[3] / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import validate
from fixture_authority_test_source import PROTECTED_OBJECTS, seed_protected_objects


AUTHORITY_PIN_PATH = validate.REPO_ROOT / "scripts/fixture_registry_authority.v2.hardened.pin.json"


def _active_authority_environment() -> dict[str, str]:
    """Load the post-rotation runtime pin used by local synthetic tests."""

    pin = json.loads(AUTHORITY_PIN_PATH.read_text(encoding="utf-8"))
    if pin.get("schema") != "hermternal.fixture-registry-authority-pin.v1":
        raise AssertionError("active authority pin schema changed")
    if pin.get("authority_path") != validate.VALIDATOR_AUTHORITY_PATH:
        raise AssertionError("active authority pin path changed")
    authority_commit = pin.get("authority_commit")
    source_commit = pin.get("source_commit")
    if not isinstance(authority_commit, str) or not validate.HEX40.fullmatch(authority_commit):
        raise AssertionError("active authority introduction pin is invalid")
    if not isinstance(source_commit, str) or not validate.HEX40.fullmatch(source_commit):
        raise AssertionError("active authority source pin is invalid")
    return {
        validate.ACTIVE_AUTHORITY_COMMIT_ENV: authority_commit,
        validate.ACTIVE_SOURCE_COMMIT_ENV: source_commit,
    }


def _install_active_authority_environment(test_case: unittest.TestCase) -> None:
    previous = {name: os.environ.get(name) for name in _active_authority_environment()}
    os.environ.update(_active_authority_environment())

    def restore() -> None:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    test_case.addClassCleanup(restore)


def _protected_authority_objects() -> tuple[tuple[str, str], ...]:
    """Return every external authority/source object required by aggregate trust."""

    active = _active_authority_environment()
    pinned = (
        ("historical-authority", validate.EXPECTED_HISTORICAL_AUTHORITY_COMMIT),
        ("historical-source", validate.EXPECTED_HISTORICAL_SOURCE_COMMIT),
        ("active-authority", active[validate.ACTIVE_AUTHORITY_COMMIT_ENV]),
        ("active-source", active[validate.ACTIVE_SOURCE_COMMIT_ENV]),
    )
    if pinned != PROTECTED_OBJECTS:
        raise AssertionError("aggregate runtime pins differ from the trusted bundle")
    return pinned


def _seed_protected_objects(repository: Path) -> None:
    """Seed the exact four pins from the repository-versioned trusted bundle."""

    _protected_authority_objects()
    seed_protected_objects(repository)


def _assert_protected_objects_missing(repository: Path) -> None:
    """Prove an unseeded single-head clone omitted at least one trust root.

    The active rotation may be reachable from the reviewed head, while the
    preserved historical roots are intentionally not. One omitted required
    object is sufficient to prove that seeding is necessary before validation.
    """

    missing: list[str] = []
    for name, commit in _protected_authority_objects():
        verified = subprocess.run(
            ["git", "-C", str(repository), "cat-file", "-t", commit],
            check=False,
            capture_output=True,
            text=True,
        )
        if verified.returncode != 0:
            missing.append(name)
    if not missing:
        raise AssertionError("unseeded clone retained every protected authority object")


def _clone_plain_object_repository(*, seed: bool) -> tuple[tempfile.TemporaryDirectory[str], Path]:
    """Create a clean single-head object repository, optionally seeding trust roots."""

    temporary = tempfile.TemporaryDirectory(prefix="fixture-validator-regression-")
    object_repo = Path(temporary.name) / "repo"
    completed = subprocess.run(
        [
            "git",
            "clone",
            "--no-local",
            "--single-branch",
            "--no-hardlinks",
            "--quiet",
            str(validate.REPO_ROOT),
            str(object_repo),
        ],
        cwd=validate.REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        temporary.cleanup()
        raise AssertionError(completed.stderr or completed.stdout)
    if seed:
        _seed_protected_objects(object_repo)
    else:
        _assert_protected_objects_missing(object_repo)
    return temporary, object_repo


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
        _install_active_authority_environment(cls)
        cls.index = validate.load_json(validate.INDEX_PATH)
        cls.schema = validate.load_json(validate.SCHEMA_PATH)
        cls.baseline = validate.load_json(validate.BASELINE_PATH)
        cls.object_repo_temporary = tempfile.TemporaryDirectory(prefix="fixture-validator-object-repo-")
        cls.object_repo = Path(cls.object_repo_temporary.name) / "repo"
        completed = subprocess.run(
            [
                "git",
                "clone",
                "--no-local",
                "--single-branch",
                "--no-hardlinks",
                "--quiet",
                str(validate.REPO_ROOT),
                str(cls.object_repo),
            ],
            cwd=validate.REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            cls.object_repo_temporary.cleanup()
            raise AssertionError(completed.stderr or completed.stdout)
        try:
            _seed_protected_objects(cls.object_repo)
        except AssertionError:
            cls.object_repo_temporary.cleanup()
            raise
        cls.addClassCleanup(cls.object_repo_temporary.cleanup)

    def test_checked_in_registry_is_valid_and_partial_is_not_success(self) -> None:
        fixture_count, coverage_count = validate.validate_all(
            self.index,
            self.schema,
            self.baseline,
            repo_root=validate.REPO_ROOT,
            baseline_path=validate.BASELINE_PATH,
            object_repo=self.object_repo,
        )
        self.assertEqual(fixture_count, len(self.index["fixture_roots"]))
        self.assertEqual(coverage_count, len(self.index["coverage"]))
        self.assertEqual(self.index["evidence_status"], "partial")
        self.assertFalse(self.index["live_claim"])

    def test_validate_all_rejects_mutated_in_memory_index(self) -> None:
        for mutation in ("notes", "status"):
            with self.subTest(mutation=mutation):
                mutated = copy.deepcopy(self.index)
                if mutation == "notes":
                    mutated["coverage"][0]["notes"] += " caller mutation"
                else:
                    pending = next(item for item in mutated["coverage"] if item["status"] == "pending")
                    pending["status"] = "ready"
                with self.assertRaises(validate.ValidationError):
                    validate.validate_all(
                        mutated,
                        self.schema,
                        self.baseline,
                        repo_root=validate.REPO_ROOT,
                        baseline_path=validate.BASELINE_PATH,
                        object_repo=self.object_repo,
                    )

    def test_target_roots_are_complete_and_connected(self) -> None:
        expected = {
            "chat-stream-completion": {
                "id": "chat-stream-completion",
                "coverage_id": "chat-stream-and-completion",
                "coverage_status": "pending",
                "coverage_fixture_ids": ["chat-stream-completion", "session-persistence"],
                "states": ["cancelled", "empty", "failure", "pending", "success", "unknown"],
                "files": [
                    "chat-stream-completion/README.md",
                    "chat-stream-completion/cases.json",
                    "chat-stream-completion/source-audit.json",
                    "chat-stream-completion/test_validate.py",
                    "chat-stream-completion/validate.py",
                    "chat-stream-completion/validation-baseline.json",
                ],
            },
            "deployment-security/external-allowlist": {
                "id": "deployment-security-external-allowlist",
                "coverage_id": "external-allowlist",
                "coverage_status": "ready",
                "states": ["failure", "success"],
                "files": [
                    "deployment-security/external-allowlist/README.md",
                    "deployment-security/external-allowlist/cases.json",
                    "deployment-security/external-allowlist/test_validate.py",
                    "deployment-security/external-allowlist/validate.py",
                    "deployment-security/external-allowlist/validation-baseline.json",
                ],
            },
            "deployment-security/host-origin-mapping": {
                "id": "deployment-security-host-origin-mapping",
                "coverage_id": "host-origin-mapping",
                "coverage_status": "ready",
                "states": ["failure", "success"],
                "files": [
                    "deployment-security/host-origin-mapping/README.md",
                    "deployment-security/host-origin-mapping/cases.json",
                    "deployment-security/host-origin-mapping/test_validate.py",
                    "deployment-security/host-origin-mapping/validate.py",
                    "deployment-security/host-origin-mapping/validation-baseline.json",
                ],
            },
            "session-lineage": {
                "id": "session-lineage",
                "coverage_id": "session-lineage",
                "coverage_status": "ready",
                "states": ["cancelled", "empty", "failure", "pending", "success", "unknown"],
                "files": [
                    "session-lineage/README.md",
                    "session-lineage/baseline-evidence.json",
                    "session-lineage/cases.json",
                    "session-lineage/test_validate.py",
                    "session-lineage/validate.py",
                    "session-lineage/validation-baseline.json",
                ],
            },
        }
        roots = {item["path"]: item for item in self.index["fixture_roots"]}
        coverage = {item["id"]: item for item in self.index["coverage"]}
        for path, details in expected.items():
            self.assertIn(path, roots)
            fixture = roots[path]
            self.assertEqual(fixture["id"], details["id"])
            self.assertEqual(fixture["status"], "ready")
            self.assertEqual(fixture["states"], details["states"])
            self.assertEqual(fixture["coverage_ids"], [details["coverage_id"]])
            self.assertEqual([item["path"] for item in fixture["files"]], details["files"])
            self.assertIn(details["coverage_id"], coverage)
            self.assertEqual(coverage[details["coverage_id"]]["status"], details["coverage_status"])
            self.assertEqual(
                coverage[details["coverage_id"]]["fixture_ids"],
                details.get("coverage_fixture_ids", [details["id"]]),
            )

    def test_current_index_is_complete_after_authority_rotation(self) -> None:
        self.assertEqual(
            validate.validate_index_document(self.index, validate.REPO_ROOT),
            (30, 29),
        )

    def test_pr_260_compatibility_gate_manifest_is_current(self) -> None:
        fixture = next(item for item in self.index["fixture_roots"] if item["id"] == "source-audit-compatibility-gate")
        expected = {
            "source-audit/compatibility-gate/README.md": ("485412e75c266383232aaae47403fbdbbabe6b6aa2571b0a9c7ed9e7e8371a10", 11907),
            "source-audit/compatibility-gate/compatibility_record.json": ("baddfc67cb92cfe024dc64310a4f9b6f6ea28dab26652a1965fcf7579084559f", 11030),
            "source-audit/compatibility-gate/test_validate.py": ("1541c22f8025c0363c519cd8bea3adf713a8a42f6b886635247b83275435756f", 30144),
            "source-audit/compatibility-gate/validate.py": ("fd9a2aeb331063ff35c02852b0b1ea011ee11ff4827071e928ccb7cb14e13ee7", 41766),
        }
        manifest = {item["path"]: item for item in fixture["files"]}
        self.assertEqual(set(manifest), set(expected))
        for path, (digest, size) in expected.items():
            self.assertEqual(manifest[path]["sha256"], digest)
            self.assertEqual(manifest[path]["size_bytes"], size)

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

    def test_class_object_repository_contains_all_protected_objects(self) -> None:
        """Keep the shared aggregate object repository complete and explicit."""

        for name, commit in _protected_authority_objects():
            with self.subTest(name=name):
                verified = subprocess.check_output(
                    ["git", "-C", str(self.object_repo), "cat-file", "-t", commit],
                    text=True,
                ).strip()
                self.assertEqual(verified, "commit")

    def test_git_object_authority_matches_direct_v2_predecessor(self) -> None:
        authority = validate._trusted_authority(validate.REPO_ROOT, self.object_repo)
        self.assertEqual(authority["schema"], validate.VALIDATOR_AUTHORITY_SCHEMA)
        self.assertEqual(authority["role"], validate.VALIDATOR_AUTHORITY_ROLE)
        self.assertEqual(authority["authority_path"], validate.VALIDATOR_AUTHORITY_PATH)
        self.assertNotEqual(authority["authority_commit"], authority["source_commit"])
        records = {record["path"]: record for record in authority["artifact_manifest"]}
        self.assertEqual(tuple(records), validate.AUTHORITY_ARTIFACT_PATHS)
        for path in validate.AUTHORITY_ARTIFACT_PATHS:
            data = subprocess.check_output(
                ["git", "-C", str(self.object_repo), "show", f"{authority['source_commit']}:{path}"],
            )
            blob_oid = subprocess.check_output(
                ["git", "-C", str(self.object_repo), "rev-parse", f"{authority['source_commit']}:{path}"],
                text=True,
            ).strip()
            record = records[path]
            self.assertEqual(blob_oid, record["blob_oid"])
            self.assertEqual(len(data), record["size_bytes"])
            self.assertEqual(hashlib.sha256(data).hexdigest(), record["sha256"])


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        _install_active_authority_environment(cls)
        cls.object_repo_temporary = tempfile.TemporaryDirectory(prefix="fixture-validator-cli-object-repo-")
        cls.object_repo = Path(cls.object_repo_temporary.name) / "repo"
        completed = subprocess.run(
            [
                "git",
                "clone",
                "--no-local",
                "--single-branch",
                "--no-hardlinks",
                "--quiet",
                str(validate.REPO_ROOT),
                str(cls.object_repo),
            ],
            cwd=validate.REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            cls.object_repo_temporary.cleanup()
            raise AssertionError(completed.stderr or completed.stdout)
        try:
            _seed_protected_objects(cls.object_repo)
        except AssertionError:
            cls.object_repo_temporary.cleanup()
            raise
        cls.addClassCleanup(cls.object_repo_temporary.cleanup)

    def _run(
        self,
        *args: str,
        optimized: bool = False,
        repo_root: Path = validate.REPO_ROOT,
        object_repo: Path | None = None,
        environment_overrides: dict[str, str | None] | None = None,
        include_object_repo: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        script = repo_root / "contracts/fixtures/validator/validate.py"
        object_repo = self.object_repo if object_repo is None else object_repo
        command.append(str(script))
        if include_object_repo:
            command.extend(["--object-repo", str(object_repo)])
        command.extend(args)
        environment = dict(os.environ)
        environment.update(_active_authority_environment())
        if environment_overrides:
            for name, value in environment_overrides.items():
                if value is None:
                    environment.pop(name, None)
                else:
                    environment[name] = value
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
        (temporary / "scripts").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(
            validate.REPO_ROOT / "scripts/verify_fixture_registry_authority.py",
            temporary / "scripts/verify_fixture_registry_authority.py",
        )
        return temporary

    def _scan_artifact_bytes(self, relative_path: str, data: bytes) -> None:
        """Run one artifact scanner without manufacturing a replacement trust root."""
        with tempfile.TemporaryDirectory(prefix="fixture-scanner-") as directory:
            path = Path(directory) / Path(relative_path).name
            path.write_bytes(data)
            allowed_assignments = validate.EXACT_ASSIGNMENT_ALLOWANCES.get(relative_path, frozenset())
            allowed_full_values = validate.SYNTHETIC_FULL_VALUE_ALLOWANCES.get(relative_path, frozenset())
            allowed_structural_urls = validate.STRUCTURAL_URL_ALLOWANCES.get(relative_path, frozenset())
            suffix = path.suffix.casefold()
            if suffix == ".py":
                validate._validate_python_file(
                    path,
                    allow_synthetic_markers=relative_path in validate.SYNTHETIC_MARKER_PATHS,
                    allow_test_negative_basic_auth=relative_path in validate.TEST_NEGATIVE_BASIC_AUTH_PATHS,
                    allow_test_negative_rfc7617_token=relative_path in validate.TEST_NEGATIVE_RFC7617_TOKEN_PATHS,
                    allowed_assignment_values=allowed_assignments,
                    allowed_synthetic_full_values=allowed_full_values,
                    allowed_structural_urls=allowed_structural_urls,
                )
            elif suffix == ".json":
                document = validate.load_json(path, require_object=False, reject_nul=False)
                validate._validate_redaction_tree(
                    document,
                    allowed_assignment_values=allowed_assignments,
                    allowed_structural_urls=allowed_structural_urls,
                )
                validate._reject_live_claims(document)
            else:
                validate._validate_text_file(
                    path,
                    allowed_assignment_values=allowed_assignments,
                    allowed_structural_urls=allowed_structural_urls,
                )

    def _assert_scanner_rejects(self, relative_path: str, data: bytes) -> None:
        with self.assertRaises(validate.ValidationError):
            self._scan_artifact_bytes(relative_path, data)

    def _run_scanner_probe(
        self,
        relative_path: str,
        data: bytes,
        *,
        optimized: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        """Run one artifact scanner in a fresh normal or optimized interpreter."""

        suffix = Path(relative_path).suffix or ".txt"
        with tempfile.TemporaryDirectory(prefix="fixture-scanner-probe-") as directory:
            artifact = Path(directory) / ("artifact" + suffix)
            artifact.write_bytes(data)
            probe = (
                "import importlib.util, pathlib, sys\n"
                "spec = importlib.util.spec_from_file_location('probe_validate', sys.argv[1])\n"
                "module = importlib.util.module_from_spec(spec)\n"
                "sys.modules['probe_validate'] = module\n"
                "spec.loader.exec_module(module)\n"
                "path = pathlib.Path(sys.argv[2])\n"
                "relative = sys.argv[3]\n"
                "data = path.read_bytes()\n"
                "allowed_assignment = module.EXACT_ASSIGNMENT_ALLOWANCES.get(relative, frozenset())\n"
                "allowed_full = module.SYNTHETIC_FULL_VALUE_ALLOWANCES.get(relative, frozenset())\n"
                "allowed_urls = module.STRUCTURAL_URL_ALLOWANCES.get(relative, frozenset())\n"
                "try:\n"
                "    if path.suffix.casefold() == '.py':\n"
                "        module._validate_python_file(path, data=data, "
                "allow_synthetic_markers=relative in module.SYNTHETIC_MARKER_PATHS, "
                "allow_test_negative_basic_auth=relative in module.TEST_NEGATIVE_BASIC_AUTH_PATHS, "
                "allow_test_negative_rfc7617_token=relative in module.TEST_NEGATIVE_RFC7617_TOKEN_PATHS, "
                "allowed_assignment_values=allowed_assignment, "
                "allowed_synthetic_full_values=allowed_full, "
                "allowed_structural_urls=allowed_urls)\n"
                "    elif path.suffix.casefold() == '.json':\n"
                "        document = module.load_json(path, require_object=False, reject_nul=False)\n"
                "        module._validate_redaction_tree(document, allowed_assignment_values=allowed_assignment, "
                "allowed_structural_urls=allowed_urls)\n"
                "        module._reject_live_claims(document)\n"
                "    else:\n"
                "        module._validate_text_file(path, data=data, allowed_assignment_values=allowed_assignment, "
                "allowed_structural_urls=allowed_urls)\n"
                "except module.ValidationError:\n"
                "    raise SystemExit(2)\n"
                "raise SystemExit(0)\n"
            )
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.extend(["-c", probe, str(validate.__file__), str(artifact), relative_path])
            environment = dict(os.environ)
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            return subprocess.run(
                command,
                cwd=validate.REPO_ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )

    def _assert_scanner_rejects_in_both_modes(self, relative_path: str, data: bytes) -> None:
        results = []
        for optimized in (False, True):
            result = self._run_scanner_probe(relative_path, data, optimized=optimized)
            self.assertEqual(result.returncode, 2, result)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr, "")
            results.append((result.returncode, result.stdout, result.stderr))
        self.assertEqual(results[0], results[1])

    def _assert_scanner_accepts_in_both_modes(self, relative_path: str, data: bytes) -> None:
        results = []
        for optimized in (False, True):
            result = self._run_scanner_probe(relative_path, data, optimized=optimized)
            self.assertEqual(result.returncode, 0, result)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr, "")
            results.append((result.returncode, result.stdout, result.stderr))
        self.assertEqual(results[0], results[1])

    def _assert_json_document_rejects(self, relative_path: str, document: dict[str, object]) -> None:
        self._assert_scanner_rejects(
            relative_path,
            (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
        )

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

    def test_active_authority_runtime_pins_are_required_and_exact(self) -> None:
        valid = _active_authority_environment()
        pin_cases = (
            {
                validate.ACTIVE_AUTHORITY_COMMIT_ENV: None,
                validate.ACTIVE_SOURCE_COMMIT_ENV: None,
            },
            {
                validate.ACTIVE_AUTHORITY_COMMIT_ENV: "0" * 40,
                validate.ACTIVE_SOURCE_COMMIT_ENV: valid[validate.ACTIVE_SOURCE_COMMIT_ENV],
            },
            {
                validate.ACTIVE_AUTHORITY_COMMIT_ENV: valid[validate.ACTIVE_AUTHORITY_COMMIT_ENV],
                validate.ACTIVE_SOURCE_COMMIT_ENV: "0" * 40,
            },
        )
        for overrides in pin_cases:
            with self.subTest(overrides=overrides):
                normal = self._run(environment_overrides=overrides)
                optimized = self._run(optimized=True, environment_overrides=overrides)
                self.assertEqual(normal.stdout, optimized.stdout)
                self.assertEqual(normal.returncode, 1)
                self.assertEqual(optimized.returncode, 1)
                self.assertEqual(normal.stderr, "")
                self.assertEqual(optimized.stderr, "")
                self.assertEqual(json.loads(normal.stdout), json.loads(optimized.stdout))

    def test_plain_object_repository_is_required_and_separate(self) -> None:
        missing = self._run(include_object_repo=False)
        self.assertEqual(missing.returncode, 1)
        self.assertEqual(missing.stderr, "")
        self.assertEqual(json.loads(missing.stdout)["evidence_status"], "blocked")

        same = self._run(object_repo=validate.REPO_ROOT)
        self.assertEqual(same.returncode, 1)
        self.assertEqual(same.stderr, "")
        self.assertEqual(json.loads(same.stdout)["evidence_status"], "blocked")

    def test_unseeded_plain_clone_fails_and_seeded_clone_succeeds(self) -> None:
        """Require explicit trust-object provisioning instead of local clone luck."""

        unseeded_temporary, unseeded = _clone_plain_object_repository(seed=False)
        self.addCleanup(unseeded_temporary.cleanup)
        for optimized in (False, True):
            with self.subTest(state="unseeded", optimized=optimized):
                blocked = self._run(optimized=optimized, object_repo=unseeded)
                self.assertEqual(blocked.returncode, 1)
                self.assertEqual(blocked.stderr, "")
                self.assertEqual(json.loads(blocked.stdout)["evidence_status"], "blocked")

        seeded_temporary, seeded = _clone_plain_object_repository(seed=True)
        self.addCleanup(seeded_temporary.cleanup)
        for optimized in (False, True):
            with self.subTest(state="seeded", optimized=optimized):
                accepted = self._run(optimized=optimized, object_repo=seeded)
                self.assertEqual(accepted.returncode, 0)
                payload = json.loads(accepted.stdout)
                self.assertEqual(payload["fixture_count"], 30)
                self.assertEqual(payload["coverage_count"], 29)
                self.assertEqual(payload["evidence_status"], "partial")
                self.assertFalse(payload["live_claim"])
                self.assertEqual(accepted.stderr, "")

    def _append_artifact_and_block(self, relative_path: str, addition: str) -> None:
        artifact = validate.FIXTURES_ROOT / relative_path
        self._assert_scanner_rejects(
            relative_path,
            artifact.read_bytes() + addition.encode("utf-8"),
        )

    @staticmethod
    def _add_json_expected_value(document: dict[str, object], key: str, value: object) -> None:
        cases = document["cases"]
        if not isinstance(cases, list) or not cases or not isinstance(cases[0], dict):
            raise TypeError("fixture test case shape changed")
        expected = cases[0].setdefault("expected", {})
        if not isinstance(expected, dict):
            raise TypeError("fixture expected shape changed")
        expected[key] = value

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

    def test_canonical_normal_execution_with_bytecode_disabled_does_not_self_reject_cache(self) -> None:
        """Prove ``-B`` keeps the trusted canonical run outside its own cache boundary."""

        repo_root = self._copy_fixture_repo()
        source_commit = _active_authority_environment()[validate.ACTIVE_SOURCE_COMMIT_ENV]
        # The checked-in registry is intentionally stale on this restack. Use
        # the same trusted predecessor for every fixture artifact that drifted
        # after its manifest was generated, while keeping this proof local to a
        # disposable copy and never rewriting generated evidence in the branch.
        trusted_paths = set(validate.CENTRAL_VALIDATOR_SOURCE_PATHS)
        trusted_paths.update({
            "contracts/fixtures/README.md",
            "contracts/fixtures/deployment-security/host-origin-mapping/README.md",
            "contracts/fixtures/deployment-security/host-origin-mapping/cases.json",
            "contracts/fixtures/deployment-security/host-origin-mapping/test_validate.py",
            "contracts/fixtures/deployment-security/host-origin-mapping/validate.py",
            "contracts/fixtures/deployment-security/host-origin-mapping/validation-baseline.json",
        })
        for relative_path in trusted_paths:
            trusted_bytes = subprocess.check_output(
                [
                    "git",
                    "-C",
                    str(validate.REPO_ROOT),
                    "show",
                    f"{source_commit}:{relative_path}",
                ],
            )
            target = repo_root / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(trusted_bytes)

        cache_root = repo_root / "contracts/fixtures/validator/__pycache__"
        # The source worktree may contain an ignored interpreter cache from a
        # prior local test run. Remove that copied test artifact; the aggregate
        # inventory still rejects a cache if one is present during validation.
        if cache_root.exists():
            shutil.rmtree(cache_root)
        self.assertFalse(cache_root.exists())
        completed = self._run(
            repo_root=repo_root,
            environment_overrides={"PYTHONDONTWRITEBYTECODE": "1"},
        )
        self.assertEqual(completed.returncode, 0, completed)
        self.assertEqual(completed.stderr, "")
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["fixture_count"], 30)
        self.assertEqual(payload["coverage_count"], 29)
        self.assertFalse(cache_root.exists())
        self.assertEqual(tuple(repo_root.glob("**/__pycache__")), ())

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
            self.assertEqual(payload["fixture_count"], 30)
            self.assertEqual(payload["coverage_count"], 29)
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

    def test_alternate_index_and_schema_paths_are_rejected_in_both_modes(self) -> None:
        repo_root = self._copy_fixture_repo()
        fixtures_root = repo_root / "contracts/fixtures"
        # Keep alternates outside the fixture inventory so rejection proves CLI
        # path binding rather than the unrelated unindexed-artifact check.
        alternate_index = repo_root / "alternate-index.json"
        index = json.loads((fixtures_root / "index.json").read_text(encoding="utf-8"))
        index["coverage"][0]["notes"] += " alternate"
        alternate_index.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
        self._assert_blocked_in_both_modes(repo_root, "--index", str(alternate_index))

        alternate_schema = repo_root / "alternate-schema.json"
        schema = json.loads((fixtures_root / "schema.json").read_text(encoding="utf-8"))
        schema["$defs"]["file"]["additionalProperties"] = True
        alternate_schema.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
        self._assert_blocked_in_both_modes(repo_root, "--schema", str(alternate_schema))

    def test_registered_python_sensitive_value_is_rejected_in_both_modes(self) -> None:
        self._append_artifact_and_block(
            "connection-restoration/validate.py",
            '\nFORGED_RETAINED_VALUE = "Bearer unredacted-secret-value-123456"\n',
        )

    def test_registered_python_assignment_literal_and_comment_are_rejected_in_both_modes(self) -> None:
        self._append_artifact_and_block(
            "connection-restoration/validate.py",
            '\nFORGED_TICKET_LITERAL = "ticket=unredacted-secret-value-123456"\n'
            + '# token=unredacted-comment-secret-123456\n',
        )

    def test_synthetic_marker_allowances_are_not_global(self) -> None:
        snippets = (
            'FORGED_SYNTHETIC_BASIC = "Authorization: Basic synthetic-basic-value-123456"\n',
            'FORGED_SYNTHETIC_BEARER = "Authorization: Bearer synthetic-bearer-value-123456"\n',
            'FORGED_SYNTHETIC_ASSIGNMENT = "token=synthetic-token-value-123456"\n',
            'FORGED_SYNTHETIC_PROVIDER = "ghp_synthetic-provider-value-123456"\n',
            'FORGED_SYNTHETIC_JWT = "eyJsyntheticheader.eyJsyntheticpayload.eyJsyntheticsignature"\n',
            'FORGED_SYNTHETIC_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\\nsynthetic\\n-----END RSA PRIVATE KEY-----"\n',
        )
        for snippet in snippets:
            with self.subTest(snippet=snippet):
                self._append_artifact_and_block("connection-restoration/validate.py", "\n" + snippet)

    def test_registered_validate_python_rejects_rfc7617_sample_in_both_modes(self) -> None:
        self._append_artifact_and_block(
            "deployment-security/external-allowlist/validate.py",
            '\nFORGED_BASIC = "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="\n',
        )

    def test_raw_rfc7617_token_is_rejected_in_indexed_python_and_text(self) -> None:
        token = validate.TEST_NEGATIVE_BASIC_AUTH_CANDIDATE
        for relative_path, assignment in (
            ("connection-restoration/validate.py", f'FORGED_RAW_TOKEN = "{token}"\n'),
            ("connection-restoration/README.md", f"\n{token}\n"),
        ):
            with self.subTest(relative_path=relative_path):
                self._append_artifact_and_block(relative_path, assignment)

    def test_nested_json_raw_rfc7617_key_and_value_are_rejected_in_both_modes(self) -> None:
        token = validate.TEST_NEGATIVE_BASIC_AUTH_CANDIDATE
        for key, value in ((token, "redacted"), ("raw_token", token)):
            with self.subTest(key=key):
                document = json.loads(
                    (validate.FIXTURES_ROOT / "connection-restoration/cases.json").read_text(encoding="utf-8")
                )
                self._add_json_expected_value(document, key, value)
                self._assert_json_document_rejects("connection-restoration/cases.json", document)

    def test_regex_calls_and_static_string_construction_are_rejected_in_both_modes(self) -> None:
        snippets = (
            're.compile("Authorization: Basic AAAAAAAAAAAAAAAA")\n',
            'regex.compile("Authorization: Basic AAAAAAAAAAAAAAAA")\n',
            're.compile(r"https://live.example.net/v1/[A-Za-z]+")\n',
            're.compile(r"https://live\\.example\\.net/v1/.*")\n',
            're.compile(r"https://live[.]example[.]net/v1/.*")\n',
            're.compile(r"https://live\\x2eexample\\x2enet/v1/.*")\n',
            're.compile(r"https://live\\u002eexample\\u002enet/v1/.*")\n',
            're.compile(r"https://live\\U0000002eexample\\U0000002enet/v1/.*")\n',
            're.compile(r"https://live\\N{FULL STOP}example\\N{FULL STOP}net/v1/.*")\n',
            're.compile(r"https://live\\056example\\056net/v1/.*")\n',
            're.compile(r"https://l\\i\\v\\e\\.example\\.net/v1/.*")\n',
            're.compile(r"https://live\\ .example\\ .net/v1/.*", re.X)\n',
            'FORGED_PLUS = "Authorization: " + "Basic AAAAAAAAAAAAAAAA"\n',
            'FORGED_RUNTIME_PLUS = "Authorization: Basic " + runtime_secret\n',
            'FORGED_RUNTIME_SCHEME_PLUS = "Authorization: " + runtime_scheme + " AAAAAAAAAAAAAAAA"\n',
            'FORGED_SPLIT_SCHEME_PLUS = "Authorization" + ": " + runtime_scheme + " AAAAAAAAAAAAAAAA"\n',
            'FORGED_FSTRING = f"Authorization: Basic {\'AAAAAAAAAAAAAAAA\'}"\n',
            'FORGED_RUNTIME_FSTRING = f"Authorization: Basic {runtime_secret}"\n',
            'FORGED_RUNTIME_SCHEME_FSTRING = f"Authorization: {runtime_scheme} AAAAAAAAAAAAAAAA"\n',
            'FORGED_PARTS = {"scheme": "Basic", "token": "AAAAAAAAAAAAAAAA"}\nFORGED_SUBSCRIPT = f"Authorization: {FORGED_PARTS[\'scheme\']} {FORGED_PARTS[\'token\']}"\n',
            'FORGED_SEQUENCE = ("Basic", "AAAAAAAAAAAAAAAA")\nFORGED_SEQUENCE_SUBSCRIPT = f"Authorization: {FORGED_SEQUENCE[0]} {FORGED_SEQUENCE[1]}"\n',
            'FORGED_FORMAT = "Authorization: Basic {}".format("AAAAAAAAAAAAAAAA")\n',
            'FORGED_RUNTIME_FORMAT = "Authorization: Basic {}".format(runtime_secret)\n',
            'FORGED_RUNTIME_SCHEME_FORMAT = "Authorization: {} AAAAAAAAAAAAAAAA".format(runtime_scheme)\n',
            'FORGED_JOIN = "".join(["Authorization: ", "Basic ", "AAAAAAAAAAAAAAAA"])\n',
            'FORGED_PERCENT = "Authorization: Basic %s" % runtime_secret\n',
            'FORGED_PERCENT_SCHEME = "Authorization: %s AAAAAAAAAAAAAAAA" % runtime_scheme\n',
            'FORGED_PERCENT_MAPPING = "Authorization: %(scheme)s %(token)s" % {"scheme": runtime_scheme, "token": runtime_secret}\n',
            'FORGED_MAPPING_PARTS = {"scheme": runtime_scheme, "token": runtime_secret}\nFORGED_PERCENT_BOUND_MAPPING = "Authorization: %(scheme)s %(token)s" % FORGED_MAPPING_PARTS\n',
            'FORGED_PERCENT_UNRESOLVED_MAPPING = "Authorization: %(scheme)s %(token)s" % runtime_mapping_unresolved\n',
            'FORGED_PERCENT_MIXED_MAPPING = "Authorization: %(scheme)s %(secret)s" % {"scheme": "Basic", "secret": runtime_secret}\n',
            'FORGED_FORMAT_MAP = "Authorization: {scheme} {token}".format_map(runtime_mapping_unresolved)\n',
            'FORGED_PERCENT_LITERAL = "Authorization: Basic %s" % "AAAAAAAAAAAAAAAA"\n',
            'FORGED_STALE = "<redacted>"\nFORGED_STALE = runtime_secret\nFORGED_STALE_HEADER = f"Authorization: Bearer {FORGED_STALE}"\n',
        )
        for snippet in snippets:
            with self.subTest(snippet=snippet):
                self._append_artifact_and_block("connection-restoration/validate.py", "\n" + snippet)

    def test_exact_allowlisted_basic_match_cannot_hide_a_later_match(self) -> None:
        token = validate.TEST_NEGATIVE_BASIC_AUTH_CANDIDATE
        addition = (
            '\nFORGED_BASIC_CHAIN = '
            f'"Authorization: Basic {token}\nAuthorization: Basic AAAAAAAAAAAAAAAA"\n'
        )
        self._append_artifact_and_block(
            "deployment-security/external-allowlist/test_validate.py",
            addition,
        )

    def test_multiple_private_keys_aws_keys_and_provider_tokens_are_exhaustive(self) -> None:
        cases = (
            (
                "source-audit/model-options/test_model_options.py",
                'FORGED_PRIVATE_CHAIN = "-----BEGIN SYNTHETIC PRIVATE KEY-----\\n-----BEGIN RSA PRIVATE KEY-----"\n',
            ),
            (
                "source-audit/oauth-browser/test_oauth_browser.py",
                'FORGED_AWS_CHAIN = "AKIA0000000000000000 AKIA1234567890ABCDEF"\n',
            ),
            (
                "source-audit/oauth-browser/test_oauth_browser.py",
                'FORGED_PROVIDER_CHAIN = "ghp_synthetic-provider-value-123456 ghp_live-provider-value-123456"\n',
            ),
        )
        for relative_path, addition in cases:
            with self.subTest(relative_path=relative_path, addition=addition):
                self._append_artifact_and_block(relative_path, "\n" + addition)

    def test_nul_split_bearer_value_is_rejected_in_both_modes(self) -> None:
        self._append_artifact_and_block(
            "connection-restoration/validate.py",
            '\nFORGED_NUL = "Bearer unredacted-\\x00secret-value-123456"\n',
        )

    def test_c0_controls_cannot_split_credentials_in_python_markdown_and_json(self) -> None:
        for separator in ("\x01", "\t", "\n", "\r"):
            with self.subTest(separator=repr(separator)):
                split_bearer = f"Bearer abcdefghi{separator}secret-value-123456"
                self._append_artifact_and_block(
                    "connection-restoration/validate.py",
                    f'\nFORGED_CONTROL = {split_bearer!r}\n',
                )

        split_bearer = "Bearer abcdefghi\x01secret-value-123456"
        self._append_artifact_and_block(
            "connection-restoration/README.md",
            f"\n{split_bearer}\n",
        )
        document = json.loads(
            (validate.FIXTURES_ROOT / "connection-restoration/cases.json").read_text(encoding="utf-8")
        )
        self._add_json_expected_value(document, "control", split_bearer)
        self._assert_json_document_rejects("connection-restoration/cases.json", document)

    def test_markdown_assignment_value_is_rejected_in_both_modes(self) -> None:
        self._append_artifact_and_block(
            "connection-restoration/README.md",
            "\ntoken=unredacted-secret-value-123456\n",
        )

    def test_quoted_assignment_values_are_rejected_in_both_modes(self) -> None:
        for assignment in (
            'password="unredacted-secret-value-123456"\n',
            "password='unredacted-secret-value-123456'\n",
        ):
            with self.subTest(assignment=assignment):
                self._assert_scanner_rejects(
                    "connection-restoration/README.md",
                    assignment.encode("utf-8"),
                )

    def test_malformed_quoted_assignments_fail_closed_in_both_modes(self) -> None:
        malformed = (
            'password="unredacted-secret-value-123456\n',
            'password="unredacted-secret-value-123456"suffix\n',
            'password="unredacted-secret-value-123456\\"tail"\n',
            'password="' + ("é" * 65) + '"\n',
        )
        for assignment in malformed:
            with self.subTest(assignment=assignment):
                self._assert_scanner_rejects_in_both_modes(
                    "connection-restoration/README.md",
                    assignment.encode("utf-8"),
                )

        # The first literal is an exact reviewed marker, so rejection here
        # proves that a later suffix or concatenated literal cannot hide behind
        # the allowance rather than merely failing on the first value.
        for assignment in (
            'FORGED = "password=\\"redaction-canary\\" + \\"safe\\""\n',
            'FORGED = "password=\\"redaction-canary\\"junk"\n',
        ):
            with self.subTest(assignment=assignment):
                self._assert_scanner_rejects_in_both_modes(
                    "deployment-security/host-origin-mapping/test_validate.py",
                    assignment.encode("utf-8"),
                )

    def test_reviewed_quoted_assignment_marker_remains_bounded_and_accepted(self) -> None:
        self._assert_scanner_accepts_in_both_modes(
            "deployment-security/host-origin-mapping/test_validate.py",
            b'FORGED = "password=\\"redaction-canary\\""\n',
        )

    def test_bounded_static_string_rendering_rejects_large_fields_and_collections_in_both_modes(self) -> None:
        width = validate.MAX_STATIC_FORMAT_FIELD_WIDTH + 1
        precision = validate.MAX_STATIC_FORMAT_FIELD_WIDTH + 1
        large_collection = "[" + ", ".join('"x"' for _ in range(validate.MAX_STATIC_COLLECTION_ITEMS + 1)) + "]"
        mapping_fields = "".join("{field" + str(index) + "}" for index in range(validate.MAX_STATIC_MAPPING_FIELDS + 1))
        snippets = (
            "runtime_secret = get_secret()\n"
            + f'FORGED_FSTRING_WIDTH = f"Authorization: Basic {{runtime_secret:{width}}}"\n'
            + f'FORGED_FSTRING_PRECISION = f"Authorization: {{runtime_number:.{precision}f}}"\n'
            + f'FORGED_PERCENT_WIDTH = "Authorization: %{width}s" % runtime_secret\n'
            + f'FORGED_PERCENT_PRECISION = "Authorization: %.{precision}s" % runtime_secret\n',
            "runtime_secret = get_secret()\n"
            + f'FORGED_FORMAT_WIDTH = "Authorization: {{0:{width}}}".format(runtime_secret)\n'
            + f'FORGED_FORMAT_PRECISION = "Authorization: {{0:.{precision}f}}".format(runtime_number)\n',
            "runtime_mapping = get_mapping()\n"
            + f'FORGED_FORMAT_MAP = "Authorization: {{token:{width}}}".format_map(runtime_mapping)\n',
            "runtime_secret = get_secret()\n"
            + f"FORGED_JOIN_COLLECTION = \"Authorization: \".join({large_collection})\n"
            + f'FORGED_JOIN_SEPARATOR = ("x" * {validate.MAX_STATIC_RENDER_BYTES + 1}).join(["Authorization: ", runtime_secret])\n',
            "runtime_mapping = get_mapping()\n"
            + f"FORGED_MAPPING_PROBE = {('Authorization: ' + mapping_fields)!r}.format_map(runtime_mapping)\n",
        )
        for source in snippets:
            with self.subTest(source=source[:80]):
                self._assert_scanner_rejects_in_both_modes(
                    "connection-restoration/validate.py",
                    source.encode("utf-8"),
                )

    def test_dynamic_percent_fields_and_mapping_tuples_never_reach_formatting(self) -> None:
        """Keep ``*`` width/precision operands unknown before allocation in both modes."""

        probe = (
            "import importlib.util, sys\n"
            "spec = importlib.util.spec_from_file_location('percent_probe_validate', sys.argv[1])\n"
            "module = importlib.util.module_from_spec(spec)\n"
            "sys.modules[spec.name] = module\n"
            "spec.loader.exec_module(module)\n"
            "class Bomb:\n"
            "    def __str__(self):\n"
            "        raise RuntimeError('percent formatting executed')\n"
            "    def __float__(self):\n"
            "        raise RuntimeError('percent formatting executed')\n"
            "mapping = {'args': (10**1000000, Bomb())}\n"
            "cases = [\n"
            "    ('%*s', (10**1000000, Bomb())),\n"
            "    ('%.*f', (10**1000000, Bomb())),\n"
            "    ('%*.*f', (10**1000000, 10**1000000, Bomb())),\n"
            "    ('%*s', mapping['args']),\n"
            "]\n"
            "for template, operand in cases:\n"
            "    result = module._bounded_percent(template, operand)\n"
            "    if result is not module._STATIC_UNKNOWN:\n"
            "        raise SystemExit(2)\n"
            "raise SystemExit(0)\n"
        )
        for optimized in (False, True):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.extend(["-c", probe, str(validate.__file__)])
            completed = subprocess.run(
                command,
                cwd=validate.REPO_ROOT,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            with self.subTest(optimized=optimized):
                self.assertEqual(completed.returncode, 0, completed)
                self.assertEqual(completed.stdout, "")
                self.assertEqual(completed.stderr, "")

    def test_percent_aggregate_budget_precedes_formatting(self) -> None:
        """Reject repeated widths and nested tuple output before ``%`` allocates."""

        probe = (
            "import importlib.util, sys\n"
            "spec = importlib.util.spec_from_file_location('percent_budget_validate', sys.argv[1])\n"
            "module = importlib.util.module_from_spec(spec)\n"
            "sys.modules[spec.name] = module\n"
            "spec.loader.exec_module(module)\n"
            "limit = module.MAX_STATIC_RENDER_BYTES\n"
            "half = limit // 2 + 1\n"
            "cases = [\n"
            "    ('L' * (limit // 2) + '%'+str(half)+'s', 'x'),\n"
            "    ('%'+str(half)+'s%'+str(half)+'s', ('x', 'y')),\n"
            "    ('%s', (('x' * half, 'y' * half),)),\n"
            "    ('%(args)s', {'args': ('x' * half, 'y' * half)}),\n"
            "    ('%r', '\\x00' * (limit // 2)),\n"
            "]\n"
            "for template, operand in cases:\n"
            "    if module._bounded_percent(template, operand) is not module._STATIC_UNKNOWN:\n"
            "        raise SystemExit(2)\n"
            "raise SystemExit(0)\n"
        )
        for optimized in (False, True):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.extend(["-c", probe, str(validate.__file__)])
            completed = subprocess.run(
                command,
                cwd=validate.REPO_ROOT,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            with self.subTest(optimized=optimized):
                self.assertEqual(completed.returncode, 0, completed)
                self.assertEqual(completed.stdout, "")
                self.assertEqual(completed.stderr, "")

    def test_unresolved_mapping_probe_cardinality_is_bounded(self) -> None:
        template = "Authorization: " + "".join(
            "{field" + str(index) + "}" for index in range(validate.MAX_STATIC_MAPPING_FIELDS * 4)
        )
        probe = validate._mapping_probe_from_template(template, format_map=True)
        self.assertEqual(len(probe), validate.MAX_STATIC_MAPPING_FIELDS)
        self.assertEqual(probe["field0"], "AAAAAAAAAAAAAAAA")

    def test_sensitive_key_aliases_are_rejected_in_both_modes(self) -> None:
        aliases = (
            "apiKey",
            "access-key",
            "clientSecret",
            "aws-secret-access-key",
            "x-api-key",
            "apikey",
            "accesskey",
            "clientsecret",
            "awssecretaccesskey",
            "xapikey",
        )
        for alias in aliases:
            with self.subTest(alias=alias):
                document = json.loads(
                    (validate.FIXTURES_ROOT / "connection-restoration/cases.json").read_text(encoding="utf-8")
                )
                # A boolean is otherwise ignored by the generic tree walk, so
                # rejection proves the compact alias reached sensitive routing.
                self._add_json_expected_value(document, alias, True)
                self._assert_json_document_rejects("connection-restoration/cases.json", document)

    def test_assignment_and_query_aliases_are_scanned_across_text(self) -> None:
        for key in ("api_key", "x-api-key", "access_token", "refresh_token", "client_secret"):
            with self.subTest(key=key):
                self._assert_scanner_rejects(
                    "connection-restoration/README.md",
                    f"{key}=AAAAAAAAAAAAAAAA\n".encode("utf-8"),
                )
                self._assert_scanner_rejects(
                    "connection-restoration/README.md",
                    f"https://synthetic.invalid/?{key}=AAAAAAAAAAAAAAAA\n".encode("utf-8"),
                )

    def test_python_ast_credential_targets_and_flow_reassignment_fail_closed(self) -> None:
        source = (
            "api_key = runtime_secret\n"
            "headers['x-api-key'] = runtime_secret\n"
            "send(client_secret=runtime_secret)\n"
            "payload = {'access_token': runtime_secret}\n"
            "token = runtime_secret\n"
            "forged = f'Authorization: Bearer {token}'\n"
            "token = '<redacted>'\n"
        )
        self._assert_scanner_rejects("connection-restoration/validate.py", source.encode("utf-8"))

    def test_python_destructured_and_loop_credential_targets_fail_closed(self) -> None:
        snippets = (
            'api_key, other = ("unredacted-secret-value-123456", "x")\n',
            'api_key, other = ["unredacted-secret-value-123456", "x"]\n',
            'for api_key in ["unredacted-secret-value-123456"]:\n    pass\n',
            'for api_key in ("unredacted-secret-value-123456",):\n    pass\n',
        )
        for source in snippets:
            with self.subTest(source=source):
                self._assert_scanner_rejects(
                    "connection-restoration/validate.py",
                    source.encode("utf-8"),
                )

    def test_sensitive_json_keys_reject_format_and_control_aliases(self) -> None:
        for key in ("api​_key", "x-api⁠-key", "refresh_token"):
            with self.subTest(key=key):
                document = json.loads(
                    (validate.FIXTURES_ROOT / "connection-restoration/cases.json").read_text(encoding="utf-8")
                )
                self._add_json_expected_value(document, key, True)
                self._assert_json_document_rejects("connection-restoration/cases.json", document)

    def test_url_userinfo_is_rejected_even_on_synthetic_hosts(self) -> None:
        self._assert_scanner_rejects(
            "connection-restoration/README.md",
            b"https://fixture:password@synthetic.invalid/v1\n",
        )

    def test_encoded_url_query_and_userinfo_credentials_are_rejected(self) -> None:
        for value in (
            "https://synthetic.invalid/?t%6fken=unredacted-secret-value-123456\n",
            "https://user%3Aunredacted-secret-value-123456@synthetic.invalid\n",
            "https://evil.com\\@synthetic.invalid\n",
        ):
            with self.subTest(value=value):
                self._assert_scanner_rejects(
                    "connection-restoration/README.md",
                    value.encode("utf-8"),
                )

    def test_malformed_named_regex_escape_is_bounded_in_both_modes(self) -> None:
        """Bound malformed ``\\N{...}`` scanning before URL parsing begins."""

        probe = (
            "import importlib.util, sys\n"
            "spec = importlib.util.spec_from_file_location('named_escape_validate', sys.argv[1])\n"
            "module = importlib.util.module_from_spec(spec)\n"
            "sys.modules[spec.name] = module\n"
            "spec.loader.exec_module(module)\n"
            "limit = module.MAX_REGEX_ESCAPE_SOURCE_LENGTH\n"
            "class Probe(str):\n"
            "    def find(self, needle, start=0, end=None):\n"
            "        if needle == '}' and end is None:\n"
            "            raise SystemExit(2)\n"
            "        if needle == '}' and end - start > limit:\n"
            "            raise SystemExit(3)\n"
            "        if end is None:\n"
            "            return super().find(needle, start)\n"
            "        return super().find(needle, start, end)\n"
            "text = Probe('https:' + chr(92) + 'N{' + 'x' * (limit * 1024))\n"
            "decoded, consumed, uncertain = module._decode_regex_escape(text, 6)\n"
            "if decoded != '?' or not uncertain or consumed > 6 + 3 + limit:\n"
            "    raise SystemExit(4)\n"
            "if tuple(module._regex_scheme_matches(text)):\n"
            "    raise SystemExit(5)\n"
            "raise SystemExit(0)\n"
        )
        for optimized in (False, True):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.extend(["-c", probe, str(validate.__file__)])
            completed = subprocess.run(
                command,
                cwd=validate.REPO_ROOT,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            with self.subTest(optimized=optimized):
                self.assertEqual(completed.returncode, 0, completed)
                self.assertEqual(completed.stdout, "")
                self.assertEqual(completed.stderr, "")

    def test_dynamic_regex_scheme_prefixes_fail_closed_without_scanning_unknown_constructs(self) -> None:
        """Reject every bounded HTTP(S) regex construct before authority parsing."""

        live_patterns = (
            r'ht[tT]ps://api.live.invalid/x',
            r'htt[pP]s://api.live.invalid/x',
            r'http[sS]://api.live.invalid/x',
            r'[hH][tT]tps://api.live.invalid/x',
            r'h(?:t|T)tps://api.live.invalid/x',
            r'(?:https|http)://api.live.invalid/x',
            r'(https|http)://api.live.invalid/x',
            r'h(?:ttps?)://api.live.invalid/x',
            r'http(?:s)?://api.live.invalid/x',
            r'(?i:https)://api.live.invalid/x',
            r'(?:h)ttps://api.live.invalid/x',
            r'h{1}ttps://api.live.invalid/x',
            r'https{1}://api.live.invalid/x',
            r'(?:(?:h(?:t|T)tps)|ftp)://api.live.invalid/x',
            r'(?i:(?:h)(?:t|T)tps)://api.live.invalid/x',
            r'h{1}(?:t){1}tps://api.live.invalid/x',
            r'http(?:s{1})://api.live.invalid/x',
            r'[hH](?:t|T)(?:t)[pP]s://api.live.invalid/x',
            r'(?:(?:https)|(?:http))://api.live.invalid/x',
            r'(?i:(?:https|http))://api.live.invalid/x',
            r'(?P=scheme)https://api.live.invalid/x',
        )
        # Keep one unknown regex escape in the generated source. ``pattern!r``
        # would double the backslash and test a literal backslash instead.
        self._assert_scanner_rejects_in_both_modes(
            "connection-restoration/validate.py",
            f"re.compile(r'h{chr(92)}Qttps://api.live.invalid/x')\n".encode("utf-8"),
        )
        for pattern in live_patterns:
            with self.subTest(pattern=pattern):
                self._assert_scanner_rejects_in_both_modes(
                    "connection-restoration/validate.py",
                    f"re.compile(r{pattern!r})\n".encode("utf-8"),
                )

        non_matching_patterns = (
            r'h[xy]tps://api.live.invalid/x',
            r'h(?:x|y)tps://api.live.invalid/x',
            r'h{2}ttps://api.live.invalid/x',
            r'(?:(?:h{2}ttps)|ftp)://api.live.invalid/x',
            r'(?i:ftp)://api.live.invalid/x',
            r'(?:ghttps|httpsx)://api.live.invalid/x',
            r'(?=x)https://api.live.invalid/x',
            r'(?!h)https://api.live.invalid/x',
            r'h(?=x)ttps://api.live.invalid/x',
        )
        for pattern in non_matching_patterns:
            with self.subTest(pattern=pattern):
                self._assert_scanner_accepts_in_both_modes(
                    "connection-restoration/validate.py",
                    f"re.compile(r{pattern!r})\n".encode("utf-8"),
                )

    def test_regex_urls_share_raw_authority_query_and_port_policy(self) -> None:
        regex_rejections = (
            're.compile(r"https:\\/\\/api.live.invalid/token")\n',
            're.compile(r"https:\\x2f\\x2fapi.live.invalid/token")\n',
            're.compile(r"https:\\u002f\\u002fapi.live.invalid/token")\n',
            're.compile(r"https:\\U0000002f\\U0000002fapi.live.invalid/token")\n',
            're.compile(r"https:\\057\\057api.live.invalid/token")\n',
            're.compile(r"https:\\N{SOLIDUS}\\N{SOLIDUS}api.live.invalid/token")\n',
            're.compile(r"https:[/][/]api.live.invalid/token")\n',
            're.compile(r"https:[\\/][\\/]api.live.invalid/token")\n',
            're.compile(r"[hH]ttps://api.live.invalid/token")\n',
            're.compile(r"h[tT]tps://api.live.invalid/token")\n',
            're.compile(r"https?://api.live.invalid/token")\n',
            're.compile(r"(?:https?|http)://api.live.invalid/token")\n',
            're.compile(r"https://synthetic\\.invalid\\x3a0/path")\n',
            're.compile(r"https://fixture\\x3apassword@synthetic\\.invalid/path")\n',
            're.compile(r"https://evil.com\\x5c@synthetic\\.invalid/path")\n',
            're.compile(r"https://synthetic\\.invalid\\x25ZZ/path")\n',
            're.compile(r"https://synthetic\\.invalid/path\\x25ZZ")\n',
            're.compile(r"https://synthetic\\.invalid\\x3ftoken=unredacted-secret-value-123456")\n',
            're.compile(r"https://user%3Aunredacted-secret-value-123456@synthetic\\.invalid")\n',
            're.compile(r"https://evil\\.example\\.com\\\\@synthetic\\.invalid")\n',
            're.compile(r"https://synthetic\\.invalid/%ZZ")\n',
            're.compile(r"https://synthetic\\.invalid/?q=%")\n',
            're.compile(r"https://synthetic\\.invalid/#%G0")\n',
            're.compile(r"https://synthetic\\.invalid/?t%6fken=unredacted-secret-value-123456")\n',
            're.compile(r"https://synthetic\\.invalid:0/path")\n',
            're.compile(r"https://synthetic\\.invalid:65536/path")\n',
            're.compile(r"https://synthetic\\.invalid:abc/path")\n',
            're.compile(r"https://synthetic\\i\\.invalid/path")\n',
        )
        for source in regex_rejections:
            with self.subTest(source=source):
                self._assert_scanner_rejects_in_both_modes(
                    "connection-restoration/validate.py",
                    source.encode("utf-8"),
                )

        query = "&".join(f"field{index}=1" for index in range(validate.MAX_URL_QUERY_PAIRS + 1))
        query_source = f're.compile(r"https://synthetic\\.invalid/?{query}")\n'
        self._assert_scanner_rejects_in_both_modes(
            "connection-restoration/validate.py",
            query_source.encode("utf-8"),
        )

        long_path = "/" + ("x" * (validate.MAX_URL_COMPONENT_LENGTH + 1))
        long_source = f're.compile(r"https://synthetic\\.invalid{long_path}")\n'
        self._assert_scanner_rejects_in_both_modes(
            "connection-restoration/validate.py",
            long_source.encode("utf-8"),
        )
        long_url = "/" + ("x" * validate.MAX_URL_COMPONENT_LENGTH) + "?" + ("y" * validate.MAX_URL_COMPONENT_LENGTH)
        long_url_source = f're.compile(r"https://synthetic\\.invalid{long_url}")\n'
        self._assert_scanner_rejects_in_both_modes(
            "connection-restoration/validate.py",
            long_url_source.encode("utf-8"),
        )

        self._assert_scanner_accepts_in_both_modes(
            "connection-restoration/validate.py",
            b're.compile(r"https://synthetic\\.invalid:443/v1/%2F")\n',
        )

        raw_rejections = (
            b"https://user%3Aunredacted-secret-value-123456@synthetic.invalid\n",
            b"https://evil.com\\@synthetic.invalid\n",
            b"https://synthetic.invalid/%ZZ\n",
            b"https://synthetic.invalid/?q=%\n",
            b"https://synthetic.invalid:0/path\n",
            b"https://synthetic.invalid:65536/path\n",
            b"https://synthetic.invalid:abc/path\n",
            ("https://synthetic.invalid" + long_url + "\n").encode("utf-8"),
        )
        for value in raw_rejections:
            with self.subTest(value=value):
                self._assert_scanner_rejects_in_both_modes(
                    "connection-restoration/README.md",
                    value,
                )
        self._assert_scanner_accepts_in_both_modes(
            "connection-restoration/README.md",
            b"https://synthetic.invalid:443/v1/%2F\n",
        )

    def test_regex_query_pair_and_component_limits_are_bounded_before_rendering(self) -> None:
        fragment = "#" + ("x" * (validate.MAX_URL_COMPONENT_LENGTH + 1))
        source = f're.compile(r"https://synthetic\\.invalid{fragment}")\n'
        self._assert_scanner_rejects_in_both_modes(
            "connection-restoration/validate.py",
            source.encode("utf-8"),
        )

    def test_regex_url_groups_classes_and_scheme_prefixes_do_not_create_false_ports(self) -> None:
        snippets = (
            b're.compile(r"^https://[a-z0-9.-]+\\.hermternal\\.test(?::[0-9]{1,5})?$")\n',
            b're.compile(r"^https://[a-z0-9.-]+\\.hermternal\\.test(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~!$&\'()*+,;=:@/%-]*)?$")\n',
            b're.compile(r"^https:\\/\\/[a-z0-9.-]+\\.hermternal\\.test(?::[0-9]{1,5})?$")\n',
            b're.compile(r"^https:[/][/]api.hermternal.test(?::[0-9]{1,5})?$")\n',
            b're.compile(r"^[h]ttps://api.hermternal.test/token$")\n',
            b're.compile(r"^h[t]tps://api.hermternal.test/token$")\n',
            b're.compile(r"^https://synthetic\\.invalid\\x2fv1\\x3fmode=ok$")\n',
            b'if target.startswith("https://"):\n    pass\n',
        )
        for source in snippets:
            with self.subTest(source=source):
                self._assert_scanner_accepts_in_both_modes(
                    "connection-restoration/validate.py",
                    source,
                )

    def test_structural_url_allowances_are_exact_and_path_scoped(self) -> None:
        relative_path = "deployment-security/host-origin-mapping/test_validate.py"
        source = (validate.FIXTURES_ROOT / relative_path).read_bytes()
        # The reviewed negative source contains the exact comma-joined and IPv6
        # canaries. Both pass only through their exact artifact allowance.
        self._scan_artifact_bytes(relative_path, source)
        for mutation in (
            "https://chat.public.invalid,https://other.public.invalid,https://third.public.invalid",
            "https://[::1]evil",
            "https://192.0.2.1",
            "https://chat.public.invalid\\\\evilx",
            "https://chat.public.invalid]evilx",
            "https://chat.public.invalid^evilx",
        ):
            with self.subTest(mutation=mutation):
                self._assert_scanner_rejects(
                    relative_path,
                    source + ("\nFORGED_STRUCTURAL_URL = " + repr(mutation) + "\n").encode("utf-8"),
                )

        # A copied exact `.invalid` token is not accepted in an unrelated path;
        # structural allowances belong to the reviewed artifact that contains
        # the domain validator's negative vocabulary.
        self._assert_scanner_rejects(
            "connection-restoration/README.md",
            b"https://chat.public.invalid\n",
        )

    def test_unicode_compatibility_forms_cannot_bypass_credential_scanners(self) -> None:
        document = json.loads(
            (validate.FIXTURES_ROOT / "connection-restoration/cases.json").read_text(encoding="utf-8")
        )
        self._add_json_expected_value(document, "ａｐｉ＿ｋｅｙ", True)
        self._assert_json_document_rejects("connection-restoration/cases.json", document)
        self._assert_scanner_rejects(
            "connection-restoration/README.md",
            (
                (validate.FIXTURES_ROOT / "connection-restoration/README.md").read_text(encoding="utf-8")
                + "\nｔｏｋｅｎ＝AAAAAAAAAAAAAAAA\n"
            ).encode("utf-8"),
        )

    def test_sensitive_json_values_still_receive_generic_scanning(self) -> None:
        for value in (
            "ghp_liveprovider123456789",
            "Authorization: Basic AAAAAAAAAAAAAAAA",
            "https://live.example.net/v1/token",
            "token=unredacted-secret-value-123456",
            "synthetic-unreviewed-marker",
        ):
            with self.subTest(value=value):
                document = json.loads(
                    (validate.FIXTURES_ROOT / "connection-restoration/cases.json").read_text(encoding="utf-8")
                )
                self._add_json_expected_value(document, "token", value)
                self._assert_json_document_rejects("connection-restoration/cases.json", document)

    def test_retained_content_aliases_preserve_shape_but_reject_content(self) -> None:
        allowed = {
            "messages": "<redacted>",
            "conversation": "not_retained",
            "chat_history": None,
            "terminal": True,
            "terminal_output": "<placeholder>",
            "tool_output": False,
            "provider": "fixture-provider",
            "provider_state": "registered_password",
            "user_data": False,
            "transcript_text": "not_recorded",
            "pty_transcript": None,
        }
        for key, value in allowed.items():
            with self.subTest(key=key, value=value):
                document = json.loads(
                    (validate.FIXTURES_ROOT / "connection-restoration/cases.json").read_text(encoding="utf-8")
                )
                self._add_json_expected_value(document, key, value)
                self._scan_artifact_bytes(
                    "connection-restoration/cases.json",
                    (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
                )

        for key in (
            "messages",
            "conversation",
            "chat_history",
            "terminal_output",
            "tool_output",
            "user_data",
            "transcript_text",
            "pty_transcript",
        ):
            with self.subTest(key=key):
                document = json.loads(
                    (validate.FIXTURES_ROOT / "connection-restoration/cases.json").read_text(encoding="utf-8")
                )
                self._add_json_expected_value(document, key, "unreviewed retained content")
                self._assert_json_document_rejects("connection-restoration/cases.json", document)

        for key, value in (("terminal", "true"), ("provider", "opaque provider secret"), ("provider_state", "opaque provider secret")):
            with self.subTest(key=key):
                document = json.loads(
                    (validate.FIXTURES_ROOT / "connection-restoration/cases.json").read_text(encoding="utf-8")
                )
                self._add_json_expected_value(document, key, value)
                self._assert_json_document_rejects("connection-restoration/cases.json", document)

    def test_central_validator_sources_must_remain_in_baseline_binding(self) -> None:
        repo_root = self._copy_fixture_repo()
        baseline_path = repo_root / "contracts/fixtures/validator/validation-baseline.json"
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        baseline["artifact_manifest"] = [
            record
            for record in baseline["artifact_manifest"]
            if record["path"] != "contracts/fixtures/validator/validate.py"
        ]
        baseline["artifact_size_bytes"] = sum(record["size_bytes"] for record in baseline["artifact_manifest"])
        baseline_path.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
        self._assert_blocked_in_both_modes(repo_root)

    def test_unreviewed_central_validator_artifacts_are_rejected_in_both_modes(self) -> None:
        for relative_path, payload in (
            ("validator/unindexed.bin", b"synthetic\n"),
            ("validator/.DS_Store", b"synthetic\n"),
            ("validator/__pycache__/unindexed.pyc", b"synthetic\n"),
        ):
            with self.subTest(relative_path=relative_path):
                repo_root = self._copy_fixture_repo()
                artifact = repo_root / "contracts/fixtures" / relative_path
                artifact.parent.mkdir(parents=True, exist_ok=True)
                artifact.write_bytes(payload)
                self._assert_blocked_in_both_modes(repo_root)

        for kind in ("symlink", "fifo"):
            with self.subTest(kind=kind):
                repo_root = self._copy_fixture_repo()
                artifact = repo_root / "contracts/fixtures/validator" / f"unindexed-{kind}"
                if kind == "symlink":
                    artifact.symlink_to("validate.py")
                else:
                    os.mkfifo(artifact)
                self._assert_blocked_in_both_modes(repo_root)

    def test_registered_unknown_extension_is_rejected_in_both_modes(self) -> None:
        repo_root = self._copy_fixture_repo()
        fixtures_root = repo_root / "contracts/fixtures"
        artifact = fixtures_root / "connection-restoration/unscanned.bin"
        artifact.write_bytes(b"Authorization: Basic AAAAAAAAAAAAAAAA\n")
        index_path = fixtures_root / "index.json"
        index = json.loads(index_path.read_text(encoding="utf-8"))
        fixture = next(item for item in index["fixture_roots"] if item["id"] == "connection-restoration")
        fixture["files"].append({
            "path": "connection-restoration/unscanned.bin",
            "sha256": "0" * 64,
            "size_bytes": 0,
        })
        fixture["files"].sort(key=lambda record: record["path"])
        index_path.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
        self._assert_blocked_in_both_modes(repo_root)

    def test_registered_non_test_source_rejects_rfc7617_sample_in_both_modes(self) -> None:
        repo_root = self._copy_fixture_repo()
        readme = repo_root / "contracts/fixtures/deployment-security/external-allowlist/README.md"
        readme.write_text(
            readme.read_text(encoding="utf-8")
            + '\nAuthorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\n',
            encoding="utf-8",
        )
        self._assert_blocked_in_both_modes(repo_root)

    def test_nested_json_key_with_credential_shaped_text_is_rejected_in_both_modes(self) -> None:
        repo_root = self._copy_fixture_repo()
        json_artifact = repo_root / "contracts/fixtures/connection-restoration/cases.json"
        document = json.loads(json_artifact.read_text(encoding="utf-8"))
        document["cases"][0]["expected"]["nested"] = {
            "safe": {
                "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==": "redacted",
            },
        }
        json_artifact.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        self._assert_blocked_in_both_modes(repo_root)

    def test_registered_ws_and_wss_live_hosts_are_rejected_in_both_modes(self) -> None:
        repo_root = self._copy_fixture_repo()
        readme = repo_root / "contracts/fixtures/connection-restoration/README.md"
        readme.write_text(
            readme.read_text(encoding="utf-8")
            + "\nws://live.example.net and wss://live.example.net must never be retained.\n",
            encoding="utf-8",
        )
        self._assert_blocked_in_both_modes(repo_root)

    def test_canonical_baseline_sample_distribution_manifest_replacement_is_rejected_in_both_modes(self) -> None:
        repo_root = self._copy_fixture_repo()
        baseline_path = repo_root / "contracts/fixtures/validator/validation-baseline.json"
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        samples = list(baseline["normal"]["samples_ms"])
        samples[0] += 1.0
        baseline["normal"]["samples_ms"] = samples
        baseline["normal"]["distribution_ms"] = self._distribution(samples)
        baseline["artifact_size_bytes"] = sum(record["size_bytes"] for record in baseline["artifact_manifest"])
        baseline_path.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
        self._assert_blocked_in_both_modes(repo_root)

    def test_stale_manifest_or_baseline_is_a_hard_merge_blocker(self) -> None:
        """Protected evidence needs external authority-root/rotation approval before regeneration."""

        # These mutations stay in disposable copies. Never refresh a checked-in
        # manifest, baseline, authority JSON, or pin to make a scanner test pass.
        repo_root = self._copy_fixture_repo()
        readme = repo_root / "contracts/fixtures/connection-restoration/README.md"
        readme.write_text(
            readme.read_text(encoding="utf-8") + "\nreview-only local artifact drift\n",
            encoding="utf-8",
        )
        self._assert_blocked_in_both_modes(repo_root)

        repo_root = self._copy_fixture_repo()
        baseline_path = repo_root / "contracts/fixtures/validator/validation-baseline.json"
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        baseline["normal"]["samples_ms"][0] += 1.0
        baseline_path.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
        self._assert_blocked_in_both_modes(repo_root)

    def test_coordinated_scanner_manifest_baseline_anchor_and_test_rebinding_is_rejected(self) -> None:
        """Exercise the real CLI after refreshing every checkout-controlled root."""

        repo_root = self._copy_fixture_repo()
        readme = repo_root / "contracts/fixtures/connection-restoration/README.md"
        readme.write_text(
            readme.read_text(encoding="utf-8") + "\nQWxhZGRpbjpvcGVuIHNlc2FtZQ==\n",
            encoding="utf-8",
        )
        validator_path = repo_root / "contracts/fixtures/validator/validate.py"
        source = validator_path.read_text(encoding="utf-8")
        source = source.replace(
            "RAW_RFC7617_TOKEN_PATTERN.finditer(scanned_value)",
            "iter(())",
            1,
        )
        validator_path.write_text(source, encoding="utf-8")
        test_path = repo_root / "contracts/fixtures/validator/test_validate.py"
        test_path.write_text(
            test_path.read_text(encoding="utf-8")
            + '\nTRUSTED_VALIDATE_SOURCE_SHA256 = "' + ("0" * 64) + '"\n'
            + 'TRUSTED_BASELINE_SHA256 = "' + ("0" * 64) + '"\n',
            encoding="utf-8",
        )
        self._assert_blocked_in_both_modes(repo_root)

    def test_coverage_links_and_support_must_match_referenced_roots(self) -> None:
        mutations = ("reciprocity", "platform", "state")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                repo_root = self._copy_fixture_repo()
                index_path = repo_root / "contracts/fixtures/index.json"
                index = json.loads(index_path.read_text(encoding="utf-8"))
                coverage = next(item for item in index["coverage"] if item["id"] == "browser-cookie-auth")
                if mutation == "reciprocity":
                    coverage["fixture_ids"] = []
                elif mutation == "platform":
                    coverage["platforms"] = ["web", "ios"]
                else:
                    coverage["required_states"] = ["pending", "success", "failure"]
                index_path.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
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
        self._assert_blocked_in_both_modes(repo_root)

    def test_ready_fixture_must_name_a_validator_in_both_modes(self) -> None:
        repo_root = self._copy_fixture_repo()
        index_path = repo_root / "contracts/fixtures/index.json"
        index = json.loads(index_path.read_text(encoding="utf-8"))
        ready = next(item for item in index["fixture_roots"] if item["status"] == "ready")
        ready["validator"] = None
        index_path.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
        self._assert_blocked_in_both_modes(repo_root)

    def test_validator_role_requires_supported_executable_python(self) -> None:
        """Keep metadata from promoting a data file or helper as the validator."""
        with tempfile.TemporaryDirectory(prefix="fixture-validator-role-") as directory:
            fixtures_root = Path(directory)
            fixture_root = fixtures_root / "synthetic"
            fixture_root.mkdir()
            valid_source = (
                "import sys\n"
                "def main():\n"
                "    return 0\n"
                "if __name__==\"__main__\":sys.exit(main())\n"
            )
            for validator_name in ("validate.py", "test_role.py"):
                path = fixture_root / validator_name
                path.write_text(valid_source, encoding="utf-8")
                validate._validate_validator_role(
                    validator_name,
                    fixture_root="synthetic",
                    actual_files=[f"synthetic/{validator_name}"],
                    fixtures_root=fixtures_root,
                )
                path.unlink()

            invalid_roles = {
                "README.md": "fixture documentation\n",
                "cases.json": "{}\n",
                "validate.sh": "#!/bin/sh\n",
                "helper.py": "def main():\n    return 0\n",
                "test_helper.py": "def main():\n    return 0\n",
            }
            for validator_name, source in invalid_roles.items():
                with self.subTest(validator_name=validator_name):
                    path = fixture_root / validator_name
                    path.write_text(source, encoding="utf-8")
                    with self.assertRaises(validate.ValidationError):
                        validate._validate_validator_role(
                            validator_name,
                            fixture_root="synthetic",
                            actual_files=[f"synthetic/{validator_name}"],
                            fixtures_root=fixtures_root,
                        )
                    path.unlink()

    def test_fixture_inventory_covers_ordinary_artifacts_and_rejects_special_files(self) -> None:
        """Keep hidden, cache, bytecode, and binary entries inside the reviewed boundary."""
        with tempfile.TemporaryDirectory(prefix="fixture-inventory-") as directory:
            fixtures_root = Path(directory)
            fixture_root = fixtures_root / "synthetic"
            cache_root = fixture_root / "__pycache__"
            cache_root.mkdir(parents=True)
            expected = (
                "synthetic/.DS_Store",
                "synthetic/__pycache__/case.pyc",
                "synthetic/cases.json",
                "synthetic/payload.bin",
            )
            (fixture_root / ".DS_Store").write_bytes(b"synthetic cache marker\n")
            (cache_root / "case.pyc").write_bytes(b"synthetic bytecode\n")
            (fixture_root / "cases.json").write_text("{}\n", encoding="utf-8")
            (fixture_root / "payload.bin").write_bytes(b"\\x00synthetic\\xff")
            self.assertEqual(tuple(validate._actual_fixture_files("synthetic", fixtures_root)), expected)

            symlink = fixture_root / "linked"
            symlink.symlink_to("cases.json")
            with self.assertRaises(validate.ValidationError):
                validate._actual_fixture_files("synthetic", fixtures_root)
            symlink.unlink()

            fifo = fixture_root / "stream"
            os.mkfifo(fifo)
            try:
                with self.assertRaises(validate.ValidationError):
                    validate._actual_fixture_files("synthetic", fixtures_root)
            finally:
                fifo.unlink()

    def test_zero_byte_fixture_file_cardinality_is_bounded_in_both_modes(self) -> None:
        repo_root = self._copy_fixture_repo()
        fixture_root = repo_root / "contracts/fixtures/connection-restoration"
        for index in range(validate.MAX_FIXTURE_TRAVERSAL_FILES + 1):
            (fixture_root / f"empty-unindexed-{index}").touch()
        self._assert_blocked_in_both_modes(repo_root)

    def test_zero_byte_fixture_directory_cardinality_is_bounded_in_both_modes(self) -> None:
        repo_root = self._copy_fixture_repo()
        fixture_root = repo_root / "contracts/fixtures/connection-restoration"
        for index in range(validate.MAX_FIXTURE_TRAVERSAL_DIRECTORIES + 1):
            (fixture_root / f"empty-directory-{index}").mkdir()
        self._assert_blocked_in_both_modes(repo_root)

    def test_fixture_traversal_depth_is_bounded_in_both_modes(self) -> None:
        repo_root = self._copy_fixture_repo()
        current = repo_root / "contracts/fixtures/connection-restoration"
        for index in range(validate.MAX_FIXTURE_TRAVERSAL_DEPTH + 1):
            current = current / f"d{index}"
            current.mkdir()
        self._assert_blocked_in_both_modes(repo_root)

    def test_fixture_path_storage_is_bounded_before_artifact_bytes(self) -> None:
        repo_root = self._copy_fixture_repo()
        current = repo_root / "contracts/fixtures/connection-restoration"
        for index in range(8):
            current = current / ("long-unindexed-directory-" + ("x" * 44) + str(index))
            current.mkdir()
        for index in range(1_000):
            (current / (f"long-unindexed-file-{index:04d}" + ("y" * 70))).touch()
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
