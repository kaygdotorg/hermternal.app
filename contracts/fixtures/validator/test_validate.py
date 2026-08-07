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

    def test_target_roots_are_complete_and_connected(self) -> None:
        expected = {
            "deployment-security/external-allowlist": {
                "id": "deployment-security-external-allowlist",
                "coverage_id": "external-allowlist",
                "states": ["failure", "success"],
                "files": [
                    "deployment-security/external-allowlist/README.md",
                    "deployment-security/external-allowlist/cases.json",
                    "deployment-security/external-allowlist/test_validate.py",
                    "deployment-security/external-allowlist/validate.py",
                    "deployment-security/external-allowlist/validation-baseline.json",
                ],
            },
            "session-lineage": {
                "id": "session-lineage",
                "coverage_id": "session-lineage",
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
            self.assertEqual(coverage[details["coverage_id"]]["status"], "ready")
            self.assertEqual(coverage[details["coverage_id"]]["fixture_ids"], [details["id"]])

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

    def test_git_object_authority_matches_exact_checked_in_bytes(self) -> None:
        authority = validate._trusted_authority(validate.REPO_ROOT)
        validator = (validate.REPO_ROOT / validate.BASELINE_SELF_MANIFEST_PATH).read_bytes()
        baseline = validate.BASELINE_PATH.read_bytes()
        self.assertEqual(authority["validator_size_bytes"], len(validator))
        self.assertEqual(authority["validator_sha256"], hashlib.sha256(validator).hexdigest())
        self.assertEqual(authority["baseline_size_bytes"], len(baseline))
        self.assertEqual(authority["baseline_sha256"], hashlib.sha256(baseline).hexdigest())


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
        authority_commit = validate._authority_commit(validate.REPO_ROOT)
        for command in (
            ["git", "-C", str(temporary), "init", "--quiet"],
            [
                "git",
                "-C",
                str(temporary),
                "fetch",
                "--quiet",
                "--no-tags",
                str(validate.REPO_ROOT),
                authority_commit,
            ],
            ["git", "-C", str(temporary), "update-ref", "refs/heads/authority-test", "FETCH_HEAD"],
            ["git", "-C", str(temporary), "symbolic-ref", "HEAD", "refs/heads/authority-test"],
        ):
            subprocess.run(command, check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return temporary

    def _rebind_copy(
        self,
        repo_root: Path,
        *,
        refresh_anchor: bool = False,
    ) -> tuple[dict[str, object], dict[str, object]]:
        """Refresh copied local records while Git-object authority stays immutable."""
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

    def _append_artifact_and_block(self, relative_path: str, addition: str) -> None:
        repo_root = self._copy_fixture_repo()
        artifact = repo_root / "contracts/fixtures" / relative_path
        artifact.write_text(artifact.read_text(encoding="utf-8") + addition, encoding="utf-8")
        self._rebind_copy(repo_root, refresh_anchor=True)
        self._assert_blocked_in_both_modes(repo_root)

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
            self.assertEqual(payload["fixture_count"], 28)
            self.assertEqual(payload["coverage_count"], 28)
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
        repo_root = self._copy_fixture_repo()
        python_artifact = repo_root / "contracts/fixtures/deployment-security/external-allowlist/validate.py"
        python_artifact.write_text(
            python_artifact.read_text(encoding="utf-8")
            + '\nFORGED_BASIC = "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="\n',
            encoding="utf-8",
        )
        self._rebind_copy(repo_root, refresh_anchor=True)
        self._assert_blocked_in_both_modes(repo_root)

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
                repo_root = self._copy_fixture_repo()
                json_path = repo_root / "contracts/fixtures/connection-restoration/cases.json"
                document = json.loads(json_path.read_text(encoding="utf-8"))
                self._add_json_expected_value(document, key, value)
                json_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
                self._rebind_copy(repo_root, refresh_anchor=True)
                self._assert_blocked_in_both_modes(repo_root)

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
            're.compile(r"https://live\\056example\\056net/v1/.*")\n',
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
            'FORGED_PERCENT_MIXED_MAPPING = "Authorization: %(scheme)s %(secret)s" % {"scheme": "Basic", "secret": runtime_secret}\n',
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
        repo_root = self._copy_fixture_repo()
        json_path = repo_root / "contracts/fixtures/connection-restoration/cases.json"
        document = json.loads(json_path.read_text(encoding="utf-8"))
        self._add_json_expected_value(document, "control", split_bearer)
        json_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        self._rebind_copy(repo_root, refresh_anchor=True)
        self._assert_blocked_in_both_modes(repo_root)

    def test_markdown_assignment_value_is_rejected_in_both_modes(self) -> None:
        self._append_artifact_and_block(
            "connection-restoration/README.md",
            "\ntoken=unredacted-secret-value-123456\n",
        )

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
                repo_root = self._copy_fixture_repo()
                json_path = repo_root / "contracts/fixtures/connection-restoration/cases.json"
                document = json.loads(json_path.read_text(encoding="utf-8"))
                # A boolean is otherwise ignored by the generic tree walk, so
                # rejection proves the compact alias reached sensitive routing.
                self._add_json_expected_value(document, alias, True)
                json_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
                self._rebind_copy(repo_root, refresh_anchor=True)
                self._assert_blocked_in_both_modes(repo_root)

    def test_sensitive_json_values_still_receive_generic_scanning(self) -> None:
        for value in (
            "ghp_liveprovider123456789",
            "Authorization: Basic AAAAAAAAAAAAAAAA",
            "https://live.example.net/v1/token",
            "token=unredacted-secret-value-123456",
            "synthetic-unreviewed-marker",
        ):
            with self.subTest(value=value):
                repo_root = self._copy_fixture_repo()
                json_path = repo_root / "contracts/fixtures/connection-restoration/cases.json"
                document = json.loads(json_path.read_text(encoding="utf-8"))
                self._add_json_expected_value(document, "token", value)
                json_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
                self._rebind_copy(repo_root, refresh_anchor=True)
                self._assert_blocked_in_both_modes(repo_root)

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
        self._rebind_copy(repo_root, refresh_anchor=True)
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
        self._rebind_copy(repo_root, refresh_anchor=True)
        self._assert_blocked_in_both_modes(repo_root)

    def test_registered_non_test_source_rejects_rfc7617_sample_in_both_modes(self) -> None:
        repo_root = self._copy_fixture_repo()
        readme = repo_root / "contracts/fixtures/deployment-security/external-allowlist/README.md"
        readme.write_text(
            readme.read_text(encoding="utf-8")
            + '\nAuthorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\n',
            encoding="utf-8",
        )
        self._rebind_copy(repo_root, refresh_anchor=True)
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
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        samples = list(baseline["normal"]["samples_ms"])
        samples[0] += 1.0
        baseline["normal"]["samples_ms"] = samples
        baseline["normal"]["distribution_ms"] = self._distribution(samples)
        baseline["artifact_size_bytes"] = sum(record["size_bytes"] for record in baseline["artifact_manifest"])
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
        self._rebind_copy(repo_root, refresh_anchor=True)
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
                self._rebind_copy(repo_root, refresh_anchor=True)
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
