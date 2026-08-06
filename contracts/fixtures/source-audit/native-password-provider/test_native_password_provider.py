#!/usr/bin/env python3
"""Regression tests for the offline native password-provider fixture."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import validate


class NativePasswordProviderFixtureTests(unittest.TestCase):
    def test_fixture_and_mutation_matrix(self) -> None:
        audit = validate.load_json("source_audit.json")
        cases = validate.load_json("cases.json")
        validate.validate_source_provenance(audit)
        self.assertEqual(validate.validate_cases(cases), 33)
        self.assertEqual(validate.validate_mutation_regressions(audit, cases), 18)

    def test_cli_reports_offline_success(self) -> None:
        result = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("validate.py"))],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("native password-provider audit valid:", result.stdout)
        self.assertIn("cases=33", result.stdout)
        self.assertIn("provenance=metadata_only", result.stdout)

    def test_duplicate_json_keys_fail_without_echoing_key(self) -> None:
        with self.assertRaises(validate.DuplicateKeyError) as caught:
            json.loads(
                '{"safe": 1, "' + ("x" * 2000) + '": 2, "' + ("x" * 2000) + '": 3}',
                object_pairs_hook=validate._object_without_duplicate_keys,
            )
        self.assertEqual(str(caught.exception), "duplicate JSON object key is not allowed")

    def test_nonfinite_json_number_fails_at_parser_boundary(self) -> None:
        overflow = json.loads('{"value": 1e9999}')
        with self.assertRaises(validate.ValidationError):
            validate._scan_json(overflow)
        with self.assertRaises(validate.ValidationError):
            json.loads('{"value": NaN}', parse_constant=validate._reject_constant)

    def test_bounded_reader_rejects_oversized_input(self) -> None:
        stream = io.BytesIO(b"{" + b"a" * validate.MAX_JSON_BYTES + b"}")
        with self.assertRaises(validate.ValidationError):
            validate._read_bounded_stream(stream, "synthetic")

    def test_integer_limit_and_recursive_node_limit(self) -> None:
        with self.assertRaises(validate.ValidationError):
            json.loads(
                '{"value": ' + ("9" * (validate.MAX_INTEGER_BITS + 1)) + "}",
                parse_int=validate._bounded_int,
            )
        with self.assertRaises(validate.ValidationError):
            validate._scan_json([[]] * (validate.MAX_JSON_NODES + 1))

    def test_deep_valid_json_fails_closed_without_recursion(self) -> None:
        value: object = 0
        for _ in range(2000):
            value = [value]
        with self.assertRaises(validate.ValidationError):
            validate._scan_json(value)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("validate.py", "cases.json"):
                shutil.copy2(validate.ROOT / name, root / name)
            deep = "{\"nested\":" + ("[" * 2000) + "0" + ("]" * 2000) + "}"
            (root / "source_audit.json").write_text(deep, encoding="utf-8")
            for optimized in (False, True):
                command = [sys.executable]
                if optimized:
                    command.append("-O")
                command.append(str(root / "validate.py"))
                result = subprocess.run(command, check=False, capture_output=True, text=True)
                output = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output.strip(), validate.SAFE_ERROR_MESSAGE)
                self.assertNotIn("Traceback", output)
                self.assertNotIn("RecursionError", output)
                self.assertNotIn(str(root), output)

    def test_wrong_password_cannot_become_success(self) -> None:
        cases = validate.load_json("cases.json")
        mutated = copy.deepcopy(cases)
        case = next(item for item in mutated["cases"] if item["id"] == "login-wrong-password")
        case["expected"]["http_status"] = 200
        with self.assertRaises(validate.ValidationError):
            validate.validate_cases(mutated)

    def test_shared_browser_store_cannot_become_allowed(self) -> None:
        cases = validate.load_json("cases.json")
        mutated = copy.deepcopy(cases)
        case = next(item for item in mutated["cases"] if item["id"] == "cookie-app-isolated-store")
        case["expected"]["shared_browser_store_used"] = True
        with self.assertRaises(validate.ValidationError):
            validate.validate_cases(mutated)

    def test_ticket_failures_are_not_acceptance_paths(self) -> None:
        cases = validate.load_json("cases.json")
        for case_id in (
            "native-ws-malformed-ticket-denied",
            "native-ws-expired-ticket-denied",
            "native-ws-reused-ticket-denied",
        ):
            mutated = copy.deepcopy(cases)
            case = next(item for item in mutated["cases"] if item["id"] == case_id)
            case["expected"]["decision"] = "accept"
            with self.assertRaises(validate.ValidationError):
                validate.validate_cases(mutated)

    def test_sensitive_field_names_are_rejected(self) -> None:
        with self.assertRaises(validate.ValidationError):
            validate.validate_synthetic_keys({"raw_ticket": "synthetic"})
        with self.assertRaises(validate.ValidationError):
            validate.validate_synthetic_keys({"password": "synthetic"})
        validate.validate_synthetic_keys({"password": False})

    def test_source_claim_and_ticket_fragment_redaction_fail_closed(self) -> None:
        with self.assertRaises(validate.ValidationError):
            validate.validate_synthetic_keys({"reason": "unknown ticket: Abcdefgh…"})
        with self.assertRaises(validate.ValidationError):
            validate.validate_synthetic_keys({"reason": "ticket fragment: Abcdefgh"})
        with self.assertRaises(validate.ValidationError):
            validate.validate_synthetic_keys({"reason": "safe\x00claim"})
        with self.assertRaises(validate.ValidationError):
            validate.validate_synthetic_keys({"header": "Authorization: Basic dGVzdC1jcmVk"})
        with self.assertRaises(validate.ValidationError):
            validate.validate_synthetic_keys({"source": "/Users/synthetic/secret"})

        message = validate._bounded_error_message(
            RuntimeError("case=evil\nAuthorization: Basic dGVzdC1jcmVk /Users/synthetic/secret")
        )
        self.assertEqual(message, validate.SAFE_ERROR_MESSAGE)
        self.assertLessEqual(len(message), validate.MAX_ERROR_MESSAGE_LENGTH)
        self.assertNotIn("evil", message)
        self.assertNotIn("dGVzdC1jcmVk", message)

        cases = validate.load_json("cases.json")
        mutated = copy.deepcopy(cases)
        mutated["cases"][0]["id"] = "case\nAuthorization: Basic dGVzdC1jcmVk"
        with self.assertRaises(validate.ValidationError) as caught:
            validate.validate_cases(mutated)
        self.assertEqual(str(caught.exception), validate.SAFE_ERROR_MESSAGE)

    def test_auth_scheme_negatives_cannot_become_http_basic(self) -> None:
        cases = validate.load_json("cases.json")
        mutated = copy.deepcopy(cases)
        case = next(item for item in mutated["cases"] if item["id"] == "native-rest-no-http-basic")
        case["expected"]["http_authorization_basic"] = True
        with self.assertRaises(validate.ValidationError):
            validate.validate_cases(mutated)

    def test_nested_git_objects_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkout"
            git_dir = root / ".git"
            (git_dir / "objects" / "info").mkdir(parents=True)
            (git_dir / "refs" / "tags").mkdir(parents=True)
            for name in ("HEAD", "config", "index"):
                (git_dir / name).write_text("synthetic", encoding="ascii")
            outside = Path(temporary) / "outside-objects"
            outside.mkdir()
            (git_dir / "objects" / "pack").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(validate.ValidationError):
                validate._reject_repository_local_alternates(root)
            with self.assertRaises(validate.ValidationError):
                validate.verify_source_root(validate.load_json("source_audit.json"), root)

    def test_nested_git_refs_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkout"
            git_dir = root / ".git"
            (git_dir / "objects" / "info").mkdir(parents=True)
            (git_dir / "refs").mkdir(parents=True)
            for name in ("HEAD", "config", "index"):
                (git_dir / name).write_text("synthetic", encoding="ascii")
            outside = Path(temporary) / "outside-refs"
            outside.mkdir()
            (git_dir / "refs" / "tags").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(validate.ValidationError):
                validate._reject_repository_local_alternates(root)
            with self.assertRaises(validate.ValidationError):
                validate.verify_source_root(validate.load_json("source_audit.json"), root)

    def test_cli_rejects_nested_git_symlinks_in_both_modes(self) -> None:
        for nested_path, outside_name in (("objects/pack", "outside-objects"), ("refs/tags", "outside-refs")):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "checkout"
                git_dir = root / ".git"
                (git_dir / "objects" / "info").mkdir(parents=True)
                (git_dir / "refs").mkdir()
                for name in ("HEAD", "config", "index"):
                    (git_dir / name).write_text("synthetic", encoding="ascii")
                outside = Path(temporary) / outside_name
                outside.mkdir()
                (git_dir / nested_path).parent.mkdir(parents=True, exist_ok=True)
                (git_dir / nested_path).symlink_to(outside, target_is_directory=True)
                for optimized in (False, True):
                    command = [sys.executable]
                    if optimized:
                        command.append("-O")
                    command.extend([str(Path(validate.__file__)), "--source-root", str(root)])
                    result = subprocess.run(command, check=False, capture_output=True, text=True)
                    output = result.stdout + result.stderr
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(output.strip(), validate.SAFE_ERROR_MESSAGE)
                    self.assertNotIn("Traceback", output)
                    self.assertNotIn(str(outside), output)

    def test_source_root_rejects_redirects_bare_and_child_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkout"
            git_dir = root / ".git"
            (git_dir / "objects" / "info").mkdir(parents=True)
            (git_dir / "refs").mkdir()
            for name in ("HEAD", "config", "index"):
                (git_dir / name).write_text("synthetic", encoding="ascii")
            (git_dir / "objects" / "info" / "alternates").write_text("/tmp/other", encoding="ascii")
            with self.assertRaises(validate.ValidationError):
                validate._reject_repository_local_alternates(root)
            with self.assertRaises(validate.ValidationError):
                validate.verify_source_root(validate.load_json("source_audit.json"), git_dir)

            bare = Path(temporary) / "bare"
            (bare / "objects").mkdir(parents=True)
            (bare / "refs").mkdir()
            (bare / "HEAD").write_text("synthetic", encoding="ascii")
            (bare / "config").write_text("[core]\n\tbare = false\n\tworktree = /tmp/attacker-worktree\n", encoding="ascii")
            with self.assertRaises(validate.ValidationError):
                validate._reject_bare_shape(bare)

            parent = Path(temporary) / "parent"
            (parent / ".git").mkdir(parents=True)
            child = parent / "child"
            child.mkdir()
            with self.assertRaises(validate.ValidationError):
                validate._reject_bare_shape(child)

    def test_git_environment_scrubs_inherited_redirects(self) -> None:
        original = {key: os.environ.get(key) for key in validate._GIT_REDIRECT_KEYS}
        try:
            os.environ["GIT_DIR"] = "/tmp/attacker-git"
            os.environ["GIT_CONFIG_PARAMETERS"] = "--bad"
            env = validate._git_env(Path("/tmp/synthetic-checkout"))
            self.assertNotEqual(env.get("GIT_DIR"), "/tmp/attacker-git")
            self.assertNotIn("GIT_CONFIG_PARAMETERS", env)
            self.assertEqual(env["GIT_NO_REPLACE_OBJECTS"], "1")
            self.assertEqual(env["GIT_NO_LAZY_FETCH"], "1")
        finally:
            for key, value in original.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_retained_surfaces_reject_provider_ticket_and_authorization_values(self) -> None:
        probes = (
            "Provider unreachable: synthetic-provider-exception",
            "unknown ticket: Abcdefgh…",
            "ticket fragment: Abcdefgh",
            "ticket: Abcdefgh",
            "Authorization: Basic dGVzdC1jcmVk",
            "Authorization: Bearer synthetic-bearer-value",
        )
        for probe in probes:
            with self.assertRaises(validate.ValidationError):
                validate.validate_untrusted_text(probe)
        validate.validate_retained_artifacts()

    def test_recomputed_baseline_cannot_bless_retained_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("README.md", "cases.json", "source_audit.json", "validate.py", "test_native_password_provider.py"):
                shutil.copy2(validate.ROOT / name, root / name)
            readme = root / "README.md"
            readme.write_text(readme.read_text(encoding="utf-8") + "\nProvider unreachable: synthetic-provider-exception\n", encoding="utf-8")
            audit = json.loads((root / "source_audit.json").read_text(encoding="utf-8"))
            total = 0
            for item in audit["validation_baseline"]["artifacts"]:
                raw = (root / item["path"]).read_bytes()
                item["bytes"] = len(raw)
                item["sha256"] = hashlib.sha256(raw).hexdigest()
                total += len(raw)
            audit["validation_baseline"]["artifact_bytes"] = total
            original_root = validate.ROOT
            validate.ROOT = root
            try:
                with self.assertRaises(validate.ValidationError):
                    validate.validate_source_provenance(audit)
            finally:
                validate.ROOT = original_root

    def test_source_digest_and_marker_mutations_fail_closed(self) -> None:
        audit = validate.load_json("source_audit.json")
        digest_mutation = copy.deepcopy(audit)
        digest_mutation["source_provenance"]["files"][0]["sha256"] = "0" * 64
        with self.assertRaises(validate.ValidationError):
            validate.validate_source_provenance(digest_mutation)

        marker_mutation = copy.deepcopy(audit)
        marker_mutation["source_evidence"][0]["marker"] = "supports_password = False"
        with self.assertRaises(validate.ValidationError):
            validate.validate_source_provenance(marker_mutation)

    def test_baseline_mean_must_match_samples(self) -> None:
        audit = validate.load_json("source_audit.json")
        mutated = copy.deepcopy(audit)
        mutated["validation_baseline"]["normal"] = {"samples_ms": [1.0, 3.0], "mean_ms": 5.0}
        with self.assertRaises(validate.ValidationError):
            validate.validate_source_provenance(mutated)


if __name__ == "__main__":
    unittest.main()
