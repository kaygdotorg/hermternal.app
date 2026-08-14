#!/usr/bin/env python3
"""Regression tests for the aggregate fixture registry validator."""

from __future__ import annotations

import ast
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
        with self.assertRaises(validate.ValidationError):
            validate.load_json(self._write(b'{"bad\\u0000key":false}'))

    def test_nul_values_are_rejected_by_fixture_redaction_scans(self) -> None:
        document = validate._parse_json_bytes(b'{"value":"\\u0000"}', reject_nul=False)
        with self.assertRaises(validate.ValidationError):
            validate._validate_redaction_tree(
                document,
                allowed_assignment_values=frozenset(),
                allowed_structural_urls=frozenset(),
            )


class RegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.index = validate.load_json(validate.INDEX_PATH)
        cls.schema = validate.load_json(validate.SCHEMA_PATH)
        cls.baseline = validate.load_json(validate.BASELINE_PATH)

    def test_checked_in_registry_is_valid_and_partial_is_not_success(self) -> None:
        # Source-only validator corrections intentionally leave the checked-in
        # benchmark manifest frozen until evidence rotation is authorized. Keep
        # registry/artifact validation green independently, then require the
        # complete path to report the stale evidence boundary.
        fixture_count, coverage_count = validate._validate_index_document(self.index, validate.REPO_ROOT)
        self.assertEqual(fixture_count, len(self.index["fixture_roots"]))
        self.assertEqual(coverage_count, len(self.index["coverage"]))
        self.assertEqual(self.index["evidence_status"], "partial")
        self.assertFalse(self.index["live_claim"])
        with self.assertRaises(validate.ValidationError):
            validate.validate_all(
                self.index,
                self.schema,
                self.baseline,
                repo_root=validate.REPO_ROOT,
                baseline_path=validate.BASELINE_PATH,
            )

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

    def test_invalid_unicode_live_claim_key_fails_before_normalization(self) -> None:
        with self.assertRaises(validate.ValidationError):
            validate._reject_live_claims({"live​_claim": False})
        with self.assertRaises(validate.ValidationError):
            validate._reject_live_claims({"live_claim\x00": False})

    def test_validate_all_binds_caller_documents_to_canonical_files(self) -> None:
        mutated_index = copy.deepcopy(self.index)
        mutated_index["live_claim"] = False
        mutated_index["evidence_status"] = "complete"
        with self.assertRaises(validate.ValidationError):
            validate.validate_all(
                mutated_index,
                self.schema,
                self.baseline,
                repo_root=validate.REPO_ROOT,
                baseline_path=validate.BASELINE_PATH,
            )

        mutated_schema = copy.deepcopy(self.schema)
        mutated_schema["title"] = "forged schema"
        with self.assertRaises(validate.ValidationError):
            validate.validate_all(
                self.index,
                mutated_schema,
                self.baseline,
                repo_root=validate.REPO_ROOT,
                baseline_path=validate.BASELINE_PATH,
            )

        mutated_baseline = copy.deepcopy(self.baseline)
        mutated_baseline["notes"] = "forged evidence"
        with self.assertRaises(validate.ValidationError):
            validate.validate_all(
                self.index,
                self.schema,
                mutated_baseline,
                repo_root=validate.REPO_ROOT,
                baseline_path=validate.BASELINE_PATH,
            )

    def test_stable_reader_rejects_final_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fixture-stable-reader-") as temporary:
            root = Path(temporary)
            target = root / "target.txt"
            target.write_text("synthetic", encoding="utf-8")
            link = root / "link.txt"
            link.symlink_to(target)
            with self.assertRaises(validate.ValidationError):
                validate._stable_file_bytes(root, "link.txt", validate.MAX_ARTIFACT_BYTES)

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

    def test_canonical_baseline_anchor_reports_source_only_staleness(self) -> None:
        # The source-only correction must not rotate reviewed benchmark evidence.
        self.assertNotEqual(validate._canonical_baseline_digest(self.baseline), validate.BASELINE_CANONICAL_SHA256)


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
        fixtures_root = next(parent for parent in artifact.parents if parent.name == "fixtures")
        relative_path = artifact.relative_to(fixtures_root).as_posix()
        command.extend([
            "-c",
            (
                "import sys; from pathlib import Path; "
                "sys.path.insert(0, sys.argv[1]); import validate; "
                "relative_path = sys.argv[3]; "
                "validate._validate_python_file("
                "Path(sys.argv[2]), "
                "allow_synthetic_markers=("
                "relative_path in validate.SYNTHETIC_MARKER_PATHS), "
                "allow_test_negative_basic_auth=("
                "relative_path in validate.TEST_NEGATIVE_BASIC_AUTH_PATHS), "
                "allow_test_negative_rfc7617_token=("
                "relative_path in validate.TEST_NEGATIVE_RFC7617_TOKEN_PATHS), "
                "allowed_assignment_values=("
                "validate.EXACT_ASSIGNMENT_ALLOWANCES.get(relative_path, frozenset())), "
                "allowed_synthetic_full_values=("
                "validate.SYNTHETIC_FULL_VALUE_ALLOWANCES.get(relative_path, frozenset())), "
                "allowed_structural_urls=("
                "validate.STRUCTURAL_URL_ALLOWANCES.get(relative_path, frozenset())), "
                "allowed_empty_assignment_values=("
                "validate.EXACT_EMPTY_ASSIGNMENT_VALUES.get(relative_path, frozenset())), "
                "control_policy_path=relative_path, "
                "control_policy_root=Path(sys.argv[4])"
                ")"
            ),
            str(fixtures_root / "validator"),
            str(artifact),
            relative_path,
            str(fixtures_root),
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

    def test_scoped_negative_values_are_exact_and_path_bound(self) -> None:
        scoped = (
            (
                "deployment-security/external-allowlist/test_validate.py",
                'VALUE = "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="\n',
            ),
            (
                "chat-stream-completion/test_validate.py",
                'VALUE = "ghp_abcdefghijk"\n',
            ),
            (
                "uncertain-delivery/test_validate.py",
                'VALUE = "api_key=sk_test_123456789"\n',
            ),
            (
                "uncertain-delivery/test_validate.py",
                'VALUE = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature"\n',
            ),
            (
                "uncertain-delivery/test_validate.py",
                'VALUE = "ghp_1234567890abcdefghijk"\n',
            ),
            (
                "uncertain-delivery/test_validate.py",
                'VALUE = "sk-proj-1234567890abcdef"\n',
            ),
        )
        for relative_path, source in scoped:
            with self.subTest(relative_path=relative_path, source=source):
                self._assert_scanner_accepts_in_both_modes(relative_path, source.encode())

        for relative_path in (
            "deployment-security/external-allowlist/test_validate.py",
            "chat-stream-completion/test_validate.py",
            "uncertain-delivery/test_validate.py",
        ):
            with self.subTest(actual_source=relative_path):
                self._assert_scanner_accepts_in_both_modes(
                    relative_path,
                    (validate.FIXTURES_ROOT / relative_path).read_bytes(),
                )

        for source in (
            scoped[0][1],
            scoped[1][1],
            scoped[2][1],
            scoped[3][1],
            scoped[4][1],
            scoped[5][1],
        ):
            with self.subTest(unscoped_source=source):
                self._assert_scanner_rejects_in_both_modes(
                    "connection-restoration/validate.py",
                    source.encode(),
                )

        # An exact allowance cannot authorize a larger source literal that adds
        # another credential-shaped value after the reviewed negative sample.
        self._assert_scanner_rejects_in_both_modes(
            "uncertain-delivery/test_validate.py",
            b'VALUE = "api_key=sk_test_123456789; api_key=unredacted-secret-value"\n',
        )

    def test_empty_bare_assignments_fail_closed_but_annotations_remain_text(self) -> None:
        for source in (b'VALUE = "api_key="\n', b'VALUE = "token="\n'):
            with self.subTest(source=source):
                self._assert_scanner_rejects_in_both_modes(
                    "connection-restoration/validate.py",
                    source,
                )
        self._assert_scanner_accepts_in_both_modes(
            "connection-restoration/validate.py",
            b"token: str\n",
        )
        for key in ("api_key", "token"):
            with self.subTest(exact_full_allowance=key):
                with self.assertRaises(validate.ValidationError):
                    validate._validate_text_value(
                        f"{key}=",
                        allowed_synthetic_full_values=frozenset({f"{key}="}),
                    )

    def test_retained_markdown_and_text_scan_empty_assignments(self) -> None:
        for suffix in (".md", ".txt"):
            with self.subTest(suffix=suffix):
                handle = tempfile.NamedTemporaryFile(
                    prefix="fixture-retained-",
                    suffix=suffix,
                    delete=False,
                    mode="w",
                    encoding="utf-8",
                )
                path = Path(handle.name)
                try:
                    handle.write("api_key=\n")
                    handle.close()
                except Exception:
                    handle.close()
                    path.unlink(missing_ok=True)
                    raise
                self.addCleanup(lambda path=path: path.unlink(missing_ok=True))
                with self.assertRaises(validate.ValidationError):
                    validate._validate_text_file(path)

    def test_empty_assignment_exceptions_are_exactly_path_and_value_bound(self) -> None:
        route_line = next(iter(validate.EXACT_EMPTY_ASSIGNMENT_LINES["route-allowlist/README.md"]))
        route_path = validate.FIXTURES_ROOT / "route-allowlist/README.md"
        validate._validate_text_file(
            route_path,
            allowed_empty_assignment_lines=validate.EXACT_EMPTY_ASSIGNMENT_LINES["route-allowlist/README.md"],
        )
        with self.assertRaises(validate.ValidationError):
            validate._validate_text_file(route_path)

        repo_root = self._copy_fixture_repo()
        fixtures_root = (repo_root / "contracts/fixtures").resolve()
        index = json.loads((fixtures_root / "index.json").read_text(encoding="utf-8"))
        route_record = next(
            record
            for fixture in index["fixture_roots"]
            for record in fixture["files"]
            if record["path"] == "route-allowlist/README.md"
        )
        original_path = fixtures_root / route_record["path"]
        total_bytes = [0]
        self.assertEqual(
            validate._validate_manifest_file(
                route_record,
                fixtures_root=fixtures_root,
                fixture_relative_root="route-allowlist",
                total_bytes=total_bytes,
            ),
            "route-allowlist/README.md",
        )

        changed_path = fixtures_root / "route-allowlist/changed.md"
        changed_text = original_path.read_text(encoding="utf-8").replace(
            route_line,
            route_line + " changed",
            1,
        )
        changed_path.write_text(changed_text, encoding="utf-8")
        changed_record = copy.deepcopy(route_record)
        changed_record["path"] = "route-allowlist/changed.md"
        changed_data = changed_path.read_bytes()
        changed_record["size_bytes"] = len(changed_data)
        changed_record["sha256"] = hashlib.sha256(changed_data).hexdigest()
        with self.assertRaises(validate.ValidationError):
            validate._validate_manifest_file(
                changed_record,
                fixtures_root=fixtures_root,
                fixture_relative_root="route-allowlist",
                total_bytes=[0],
            )

        copied_path = fixtures_root / "route-allowlist/copied.md"
        copied_path.write_text(route_line + "\n", encoding="utf-8")
        copied_record = copy.deepcopy(route_record)
        copied_record["path"] = "route-allowlist/copied.md"
        copied_data = copied_path.read_bytes()
        copied_record["size_bytes"] = len(copied_data)
        copied_record["sha256"] = hashlib.sha256(copied_data).hexdigest()
        with self.assertRaises(validate.ValidationError):
            validate._validate_manifest_file(
                copied_record,
                fixtures_root=fixtures_root,
                fixture_relative_root="route-allowlist",
                total_bytes=[0],
            )

        exact_value = "?ticket=<single-use>"
        validate._validate_text_value(
            exact_value,
            allowed_empty_assignment_values=validate.EXACT_EMPTY_ASSIGNMENT_VALUES[
                "route-allowlist/test_route_allowlist.py"
            ],
        )
        with self.assertRaises(validate.ValidationError):
            validate._validate_text_value(
                exact_value + "-changed",
                allowed_empty_assignment_values=validate.EXACT_EMPTY_ASSIGNMENT_VALUES[
                    "route-allowlist/test_route_allowlist.py"
                ],
            )

    def test_python_control_policy_matches_an_independent_fixture_inventory(self) -> None:
        """Lock paths, typed values, roles, constructors, and ordinals independently."""
        def dotted(node: ast.AST) -> str:
            if isinstance(node, ast.Name):
                return node.id
            if isinstance(node, ast.Attribute):
                left = dotted(node.value)
                return f"{left}.{node.attr}" if left else node.attr
            return type(node).__name__

        def target_name(node: ast.AST) -> str:
            if isinstance(node, ast.Name):
                return node.id
            if isinstance(node, ast.Attribute):
                return dotted(node)
            if isinstance(node, ast.Subscript):
                return dotted(node)
            if isinstance(node, (ast.Tuple, ast.List)):
                return "[" + ",".join(target_name(child) for child in node.elts) + "]"
            return type(node).__name__

        def parent_map(tree: ast.AST) -> dict[int, tuple[ast.AST, str, int | None]]:
            result: dict[int, tuple[ast.AST, str, int | None]] = {}
            for parent in ast.walk(tree):
                for field, child in ast.iter_fields(parent):
                    if isinstance(child, ast.AST):
                        result[id(child)] = (parent, field, None)
                    elif isinstance(child, list):
                        for index, item in enumerate(child):
                            if isinstance(item, ast.AST):
                                result[id(item)] = (parent, field, index)
            return result

        def path_from(
            parents: dict[int, tuple[ast.AST, str, int | None]],
            node: ast.AST,
            ancestor: ast.AST,
        ) -> list[str] | None:
            steps: list[str] = []
            current = node
            while current is not ancestor:
                relation = parents.get(id(current))
                if relation is None:
                    return None
                _parent, field, index = relation
                steps.append(f"{field}[{index}]" if index is not None else field)
                current = _parent
            return list(reversed(steps))

        def scope(
            parents: dict[int, tuple[ast.AST, str, int | None]],
            node: ast.AST,
        ) -> str:
            scopes: list[str] = []
            current = node
            while id(current) in parents:
                parent, _field, _index = parents[id(current)]
                if isinstance(parent, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    scopes.append(parent.name)
                current = parent
            return ".".join(reversed(scopes)) if scopes else "module"

        def role(
            parents: dict[int, tuple[ast.AST, str, int | None]],
            node: ast.AST,
        ) -> str:
            function = scope(parents, node)
            current = node
            while id(current) in parents:
                parent, _field, _index = parents[id(current)]
                if isinstance(parent, ast.Call):
                    path = path_from(parents, node, parent) or []
                    if path and path[0].startswith("args["):
                        argument = path[0].split("[", 1)[1].rstrip("]")
                        return f"fn:{function}|call:{dotted(parent.func)}|arg:{argument}|path:{'/'.join(path[1:]) or 'direct'}"
                    if path and path[0].startswith("keywords["):
                        keyword_index = int(path[0].split("[", 1)[1].rstrip("]"))
                        keyword = parent.keywords[keyword_index]
                        return f"fn:{function}|call:{dotted(parent.func)}|kw:{keyword.arg or '**'}|path:{'/'.join(path[1:]) or 'direct'}"
                current = parent

            current = node
            while id(current) in parents:
                parent, _field, _index = parents[id(current)]
                if isinstance(parent, ast.Assign):
                    path = path_from(parents, node, parent) or []
                    return f"fn:{function}|assign:{','.join(target_name(item) for item in parent.targets)}|path:{'/'.join(path)}"
                if isinstance(parent, ast.AnnAssign):
                    path = path_from(parents, node, parent) or []
                    return f"fn:{function}|annassign:{target_name(parent.target)}|path:{'/'.join(path)}"
                if isinstance(parent, ast.NamedExpr):
                    path = path_from(parents, node, parent) or []
                    return f"fn:{function}|namedexpr:{target_name(parent.target)}|path:{'/'.join(path)}"
                current = parent

            current = node
            while id(current) in parents:
                parent, _field, _index = parents[id(current)]
                if isinstance(parent, (ast.Dict, ast.List, ast.Tuple, ast.Set)):
                    path = path_from(parents, node, parent) or []
                    return f"fn:{function}|container:{type(parent).__name__}|path:{'/'.join(path)}"
                if isinstance(parent, ast.Compare):
                    path = path_from(parents, node, parent) or []
                    operators = ",".join(type(operator).__name__ for operator in parent.ops)
                    return f"fn:{function}|compare:{operators}|path:{'/'.join(path)}"
                if isinstance(parent, ast.Assert):
                    path = path_from(parents, node, parent) or []
                    return f"fn:{function}|assert|path:{'/'.join(path)}"
                current = parent
            return f"fn:{function}|module-path"

        def static_int(node: ast.AST) -> int | None:
            return node.value if isinstance(node, ast.Constant) and type(node.value) is int else None

        def static_byte_hex(node: ast.AST) -> str | None:
            if isinstance(node, ast.Constant) and type(node.value) is bytes:
                return node.value.hex()
            if isinstance(node, (ast.List, ast.Tuple)):
                values = [static_int(child) for child in node.elts]
                if all(value is not None and 0 <= value <= 255 for value in values):
                    return "".join(f"{value:02x}" for value in values if value is not None)
            return None

        def utf8_hex(code: int) -> str:
            if code <= 0x7F:
                return f"{code:02x}"
            if code <= 0x7FF:
                return f"{0xC0 | (code >> 6):02x}{0x80 | (code & 0x3F):02x}"
            if code <= 0xFFFF:
                return f"{0xE0 | (code >> 12):02x}{0x80 | ((code >> 6) & 0x3F):02x}{0x80 | (code & 0x3F):02x}"
            return f"{0xF0 | (code >> 18):02x}{0x80 | ((code >> 12) & 0x3F):02x}{0x80 | ((code >> 6) & 0x3F):02x}{0x80 | (code & 0x3F):02x}"

        control_invalid = object()
        control_getattr_selector = object()
        control_module_prefix = "module:"
        control_direct_apis = frozenset({"chr", "bytes", "bytearray"})
        control_modules = frozenset({"builtins", "binascii", "codecs"})
        control_dynamic_selectors = frozenset({"getattr"})
        control_reserved_names = control_direct_apis | control_modules | control_dynamic_selectors
        control_canonical_apis = frozenset(
            {
                "chr",
                "bytes",
                "bytearray",
                "bytes.fromhex",
                "bytearray.fromhex",
                "binascii.unhexlify",
                "binascii.a2b_hex",
                "codecs.decode",
            }
        )
        control_source_apis = {
            "chr": "chr",
            "bytes": "bytes",
            "bytearray": "bytearray",
            "builtins.chr": "chr",
            "builtins.bytes": "bytes",
            "builtins.bytearray": "bytearray",
            "bytes.fromhex": "bytes.fromhex",
            "bytearray.fromhex": "bytearray.fromhex",
            "builtins.bytes.fromhex": "bytes.fromhex",
            "builtins.bytearray.fromhex": "bytearray.fromhex",
            "binascii.unhexlify": "binascii.unhexlify",
            "binascii.a2b_hex": "binascii.a2b_hex",
            "codecs.decode": "codecs.decode",
        }

        def scope_chain(scope_name: str) -> tuple[str, ...]:
            if scope_name == "module":
                return ("module",)
            parts = scope_name.split(".")
            return tuple(
                [".".join(parts[:index]) for index in range(len(parts), 0, -1)]
                + ["module"]
            )

        def lookup_binding(
            bindings: dict[tuple[str, str], object],
            scope_name: str,
            name: str,
        ) -> tuple[bool, object | None]:
            for candidate in scope_chain(scope_name):
                key = (candidate, name)
                if key in bindings:
                    return True, bindings[key]
            if name in control_direct_apis:
                return True, name
            if name in control_modules:
                return True, control_module_prefix + name
            if name in control_dynamic_selectors:
                return True, control_getattr_selector
            return False, None

        def resolve_expression(
            node: ast.AST,
            scope_name: str,
            bindings: dict[tuple[str, str], object],
        ) -> object | None:
            if isinstance(node, ast.Name):
                _found, value = lookup_binding(bindings, scope_name, node.id)
                return value
            if not isinstance(node, ast.Attribute):
                return None
            base = resolve_expression(node.value, scope_name, bindings)
            if base is control_invalid:
                return control_invalid
            if base == control_module_prefix + "builtins" and node.attr in control_direct_apis:
                return node.attr
            if base == control_module_prefix + "builtins" and node.attr in control_dynamic_selectors:
                return control_getattr_selector
            if base == control_module_prefix + "binascii" and node.attr in {"unhexlify", "a2b_hex"}:
                return "binascii." + node.attr
            if base == control_module_prefix + "codecs" and node.attr == "decode":
                return "codecs.decode"
            if base in {"bytes", "bytearray"} and node.attr == "fromhex":
                return base + ".fromhex"
            return None

        def bind_name(
            bindings: dict[tuple[str, str], object],
            scope_name: str,
            name: str,
            value: object,
            *,
            force: bool = False,
        ) -> None:
            key = (scope_name, name)
            if force:
                bindings[key] = value
            elif key in bindings:
                bindings[key] = control_invalid
            else:
                bindings[key] = value

        def target_names_for_binding(node: ast.AST) -> tuple[str, ...]:
            if isinstance(node, ast.Name):
                return (node.id,)
            if isinstance(node, (ast.Tuple, ast.List)):
                names: list[str] = []
                for child in node.elts:
                    names.extend(target_names_for_binding(child))
                return tuple(names)
            return ()

        def alias_bindings(
            tree: ast.AST,
            parents: dict[int, tuple[ast.AST, str, int | None]],
        ) -> dict[tuple[str, str], object]:
            bindings: dict[tuple[str, str], object] = {}
            nodes = sorted(
                ast.walk(tree),
                key=lambda item: (getattr(item, "lineno", -1), getattr(item, "col_offset", -1)),
            )
            for node in nodes:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    parent_scope = scope(parents, node)
                    if (
                        node.name in control_reserved_names
                        or (parent_scope, node.name) in bindings
                    ):
                        bind_name(bindings, parent_scope, node.name, control_invalid)
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        local_scope = node.name if parent_scope == "module" else f"{parent_scope}.{node.name}"
                        outer_scopes = scope_chain(parent_scope)
                        for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
                            if (
                                argument.arg in control_reserved_names
                                or any((candidate, argument.arg) in bindings for candidate in outer_scopes)
                            ):
                                bind_name(bindings, local_scope, argument.arg, control_invalid, force=True)
                        if node.args.vararg is not None and (
                            node.args.vararg.arg in control_reserved_names
                            or any((candidate, node.args.vararg.arg) in bindings for candidate in outer_scopes)
                        ):
                            bind_name(bindings, local_scope, node.args.vararg.arg, control_invalid, force=True)
                        if node.args.kwarg is not None and (
                            node.args.kwarg.arg in control_reserved_names
                            or any((candidate, node.args.kwarg.arg) in bindings for candidate in outer_scopes)
                        ):
                            bind_name(bindings, local_scope, node.args.kwarg.arg, control_invalid, force=True)
                elif isinstance(node, ast.Import):
                    scope_name = scope(parents, node)
                    for imported in node.names:
                        bound = imported.asname or imported.name.split(".", 1)[0]
                        if imported.name in control_modules:
                            bind_name(bindings, scope_name, bound, control_module_prefix + imported.name)
                        elif bound in control_reserved_names:
                            bind_name(bindings, scope_name, bound, control_invalid)
                elif isinstance(node, ast.ImportFrom):
                    scope_name = scope(parents, node)
                    module = node.module or ""
                    for imported in node.names:
                        bound = imported.asname or imported.name
                        canonical: object = control_invalid
                        if module == "builtins" and imported.name in control_direct_apis:
                            canonical = imported.name
                        elif module == "builtins" and imported.name in control_dynamic_selectors:
                            canonical = control_getattr_selector
                        elif module == "binascii" and imported.name in {"unhexlify", "a2b_hex"}:
                            canonical = "binascii." + imported.name
                        elif module == "codecs" and imported.name == "decode":
                            canonical = "codecs.decode"
                        elif imported.name in control_reserved_names:
                            canonical = control_invalid
                        if canonical is not control_invalid or bound in control_reserved_names:
                            bind_name(bindings, scope_name, bound, canonical)
                elif isinstance(node, ast.Assign):
                    scope_name = scope(parents, node)
                    resolved = resolve_expression(node.value, scope_name, bindings)
                    for target in node.targets:
                        for name in target_names_for_binding(target):
                            if name in control_reserved_names or (scope_name, name) in bindings:
                                bind_name(bindings, scope_name, name, control_invalid)
                            elif resolved is control_getattr_selector or resolved in control_canonical_apis or (
                                isinstance(resolved, str) and resolved.startswith(control_module_prefix)
                            ):
                                bind_name(bindings, scope_name, name, resolved)
                elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
                    scope_name = scope(parents, node)
                    resolved = resolve_expression(node.value, scope_name, bindings) if node.value is not None else None
                    for name in target_names_for_binding(node.target):
                        if name in control_reserved_names or (scope_name, name) in bindings:
                            bind_name(bindings, scope_name, name, control_invalid)
                        elif resolved is control_getattr_selector or resolved in control_canonical_apis or (
                            isinstance(resolved, str) and resolved.startswith(control_module_prefix)
                        ):
                            bind_name(bindings, scope_name, name, resolved)
                elif isinstance(node, (ast.AugAssign, ast.For, ast.AsyncFor)):
                    scope_name = scope(parents, node)
                    for name in target_names_for_binding(node.target):
                        if name in control_reserved_names or (scope_name, name) in bindings:
                            bind_name(bindings, scope_name, name, control_invalid)
            return bindings

        def static_scalar(node: ast.AST) -> str | bytes | None:
            if isinstance(node, ast.Constant) and type(node.value) in {str, bytes}:
                return node.value
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                left = static_scalar(node.left)
                right = static_scalar(node.right)
                if type(left) is type(right) and left is not None and len(left) + len(right) <= validate.MAX_ARTIFACT_BYTES:
                    return left + right
            return None

        def static_hex_payload(node: ast.AST) -> str | None:
            value = static_scalar(node)
            if value is None:
                return None
            if type(value) is bytes:
                try:
                    value = value.decode("ascii")
                except UnicodeDecodeError:
                    return None
            compact = "".join(value.split())
            if len(compact) % 2 or any(digit not in "0123456789abcdefABCDEF" for digit in compact):
                return None
            try:
                return "".join(
                    f"{int(compact[index:index + 2], 16):02x}"
                    for index in range(0, len(compact), 2)
                )
            except ValueError:
                return None

        def construction(
            node: ast.AST,
            parents: dict[int, tuple[ast.AST, str, int | None]],
            bindings: dict[tuple[str, str], object],
        ) -> tuple[str, str, str, str] | None:
            if not isinstance(node, ast.Call):
                return None
            name = dotted(node.func)
            scope_name = scope(parents, node)
            resolved = resolve_expression(node.func, scope_name, bindings)
            if isinstance(node.func, ast.Call):
                selector = resolve_expression(node.func.func, scope_name, bindings)
                # Keep the independent model fail-closed with production: an
                # aliased getattr can select a constructor only at runtime.
                if selector is control_getattr_selector or dotted(node.func.func) == "getattr":
                    raise validate.ValidationError()
            canonical = resolved if isinstance(resolved, str) else control_source_apis.get(name)
            if resolved is control_invalid:
                raise validate.ValidationError()
            if canonical not in control_canonical_apis:
                return None
            structural_role = role(parents, node)
            if canonical == "chr":
                if len(node.args) != 1 or node.keywords:
                    return None
                code = static_int(node.args[0])
                if code is None:
                    return "unknown", "", canonical, structural_role
                if not 0 <= code <= 0x10FFFF:
                    return None
                encoded = utf8_hex(code)
                controls = {code} if code < 32 or code == 127 else set()
                if controls and controls != {10}:
                    return "str", encoded, canonical, structural_role
                return None
            if canonical in {"bytes", "bytearray"}:
                if len(node.args) != 1 or node.keywords:
                    return None
                encoded = static_byte_hex(node.args[0])
                if encoded is None:
                    return "unknown", "", canonical, structural_role
                controls = {
                    int(encoded[index:index + 2], 16)
                    for index in range(0, len(encoded), 2)
                    if int(encoded[index:index + 2], 16) < 32
                    or int(encoded[index:index + 2], 16) == 127
                }
                if controls and controls != {10}:
                    return "bytes", encoded, canonical, structural_role
                return None
            if canonical in {
                "bytes.fromhex",
                "bytearray.fromhex",
                "binascii.unhexlify",
                "binascii.a2b_hex",
            }:
                if len(node.args) != 1 or node.keywords:
                    return None
                encoded = static_hex_payload(node.args[0])
                if encoded is None:
                    return "unknown", "", canonical, structural_role
                controls = {
                    int(encoded[index:index + 2], 16)
                    for index in range(0, len(encoded), 2)
                    if int(encoded[index:index + 2], 16) < 32
                    or int(encoded[index:index + 2], 16) == 127
                }
                if controls and controls != {10}:
                    return "bytes", encoded, canonical, structural_role
                return None
            if canonical == "codecs.decode":
                if len(node.args) != 2 or node.keywords:
                    return None
                encoding = node.args[1]
                if not isinstance(encoding, ast.Constant) or type(encoding.value) is not str:
                    return None
                if encoding.value.casefold() not in {"hex", "hex_codec"}:
                    return None
                encoded = static_hex_payload(node.args[0])
                if encoded is None:
                    return "unknown", "", canonical, structural_role
                controls = {
                    int(encoded[index:index + 2], 16)
                    for index in range(0, len(encoded), 2)
                    if int(encoded[index:index + 2], 16) < 32
                    or int(encoded[index:index + 2], 16) == 127
                }
                if controls and controls != {10}:
                    return "bytes", encoded, canonical, structural_role
                return None
            return None

        generated_literals: list[tuple[str, str, str, str, int]] = []
        generated_dynamic: list[tuple[str, str, str, str, str, int]] = []
        for path in sorted(validate.FIXTURES_ROOT.rglob("*.py")):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
            except (OSError, UnicodeError, SyntaxError):
                continue
            relative = path.relative_to(validate.FIXTURES_ROOT).as_posix()
            parents = parent_map(tree)
            control_bindings = alias_bindings(tree, parents)
            occurrences: dict[tuple[str, str, str], int] = {}
            for node in ast.walk(tree):
                if not isinstance(node, ast.Constant) or type(node.value) not in {str, bytes}:
                    continue
                value = node.value
                controls = (
                    {item for item in value if item < 32 or item == 127}
                    if isinstance(value, bytes)
                    else {ord(item) for item in value if ord(item) < 32 or ord(item) == 127}
                )
                if not controls or controls == {10}:
                    continue
                kind = "bytes" if isinstance(value, bytes) else "str"
                encoded = value.hex() if isinstance(value, bytes) else value.encode("utf-8").hex()
                structural_role = role(parents, node)
                key = (kind, encoded, structural_role)
                ordinal = occurrences.get(key, 0)
                occurrences[key] = ordinal + 1
                generated_literals.append((relative, kind, encoded, structural_role, ordinal))
            for node in ast.walk(tree):
                result = construction(node, parents, control_bindings)
                if result is None:
                    continue
                if result[0] == "unknown":
                    _kind, _encoded, constructor, structural_role = result
                    key = (_kind, constructor, structural_role)
                    ordinal = occurrences.get(key, 0)
                    occurrences[key] = ordinal + 1
                    generated_dynamic.append((relative, "unknown", "", constructor, key[2], ordinal))
                    continue
                kind, encoded, constructor, structural_role = result
                key = (kind, encoded, structural_role)
                ordinal = occurrences.get(key, 0)
                occurrences[key] = ordinal + 1
                generated_dynamic.append((relative, kind, encoded, constructor, structural_role, ordinal))

        self.assertEqual(
            tuple(sorted(generated_literals)),
            tuple(sorted(validate._PYTHON_CONTROL_LITERAL_ROWS)),
        )
        self.assertEqual(
            tuple(sorted(generated_dynamic)),
            tuple(sorted(validate._PYTHON_CONTROL_CONSTRUCTION_ROWS)),
        )
        self.assertEqual(len(generated_literals), 68)
        self.assertEqual(len(generated_dynamic), 30)
        self.assertEqual(len(generated_literals), len(set(generated_literals)))
        self.assertEqual(len(generated_dynamic), len(set(generated_dynamic)))

    def test_control_scope_disambiguates_same_local_names(self) -> None:
        source = (
            'def same():\n    value = "\\x00"\n'
            'class Alpha:\n    def same(self):\n        value = "\\x00"\n'
            'class Beta:\n    def same(self):\n        value = "\\x00"\n'
            'def outer():\n    def same():\n        value = "\\x00"\n'
        )
        tree = ast.parse(source)
        parents = validate._control_parent_map(tree)
        roles = [
            validate._control_role(parents, node)
            for node in ast.walk(tree)
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and len(node.value) == 1
                and ord(node.value) == 0
            )
        ]
        self.assertEqual(
            set(roles),
            {
                "fn:same|assign:value|path:value",
                "fn:Alpha.same|assign:value|path:value",
                "fn:Beta.same|assign:value|path:value",
                "fn:outer.same|assign:value|path:value",
            },
        )

    def test_control_aliases_and_static_decodes_have_canonical_rows(self) -> None:
        payload_hex = "006170695f6b65793d756e72656461637465642d736563726574"
        cases = (
            ('builtins.chr(0)\n', ("str", "00", "chr")),
            ('import builtins as b\nb.bytes([0, 65])\n', ("bytes", "0041", "bytes")),
            ('from builtins import chr as make\nmake(0)\n', ("str", "00", "chr")),
            ('from builtins import bytes as make_bytes\nmake_bytes([0])\n', ("bytes", "00", "bytes")),
            (
                f'from builtins import bytes as make_bytes\nmake_bytes.fromhex({payload_hex!r})\n',
                ("bytes", payload_hex, "bytes.fromhex"),
            ),
            (
                f'import binascii as bx\nbx.unhexlify({payload_hex!r})\n',
                ("bytes", payload_hex, "binascii.unhexlify"),
            ),
            (
                f'from binascii import a2b_hex as decode_hex\ndecode_hex({payload_hex!r})\n',
                ("bytes", payload_hex, "binascii.a2b_hex"),
            ),
            (
                f'import codecs as codec\ncodec.decode({payload_hex!r}, "hex")\n',
                ("bytes", payload_hex, "codecs.decode"),
            ),
            (
                f'from codecs import decode as decode_hex\ndecode_hex({payload_hex!r}, "hex_codec")\n',
                ("bytes", payload_hex, "codecs.decode"),
            ),
        )
        decoded_row: tuple[str, str, str, str] | None = None
        for source, expected in cases:
            with self.subTest(source=source):
                tree = ast.parse(source)
                parents = validate._control_parent_map(tree)
                bindings = validate._control_alias_bindings(tree, parents)
                call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call))
                row = validate._control_dynamic_constructor(call, parents, bindings)
                self.assertIsNotNone(row)
                assert row is not None
                self.assertEqual(row[:3], expected)
                self.assertEqual(row[3], "fn:module|module-path")
                if expected[2] == "codecs.decode":
                    decoded_row = row

        self.assertIsNotNone(decoded_row)
        assert decoded_row is not None
        projection = validate._control_projection_from_hex(decoded_row[0], decoded_row[1])
        self.assertEqual(projection, "api_key=unredacted-secret")
        with self.assertRaises(validate.ValidationError):
            validate._validate_text_value(projection or "")

    def test_unreviewed_control_aliases_and_api_forms_reject_in_both_modes(self) -> None:
        sources = (
            b'def same(chr):\n    return chr(0)\n',
            b'from builtins import chr as make\nmake = object()\nmake(0)\n',
            b'import builtins as b\nb = object()\nb.chr(0)\n',
            b'chr(value)\n',
            b'bytes(value)\n',
            b'bytes.fromhex("0")\n',
            b'import codecs\ncodecs.decode("00", "base64")\n',
            b'import codecs\ncodecs.decode("00", encoding)\n',
            b'chr(0, 1)\n',
            b'chr(code=0)\n',
            b'bytes.fromhex("00", "00")\n',
            b'import binascii as b\nb.unhexlify(value)\n',
            b'import builtins\ngetattr(builtins, "chr")(0)\n',
        )
        for source in sources:
            with self.subTest(source=source):
                self._assert_scanner_rejects_in_both_modes(
                    "connection-restoration/validate.py",
                    source,
                )

    def test_aliased_getattr_constructor_forms_reject_in_both_modes(self) -> None:
        """Aliased dynamic selection must fail closed before constructor use."""

        sources = (
            b'import builtins\ng = getattr\ng(builtins, "chr")(0)\n',
            b'import builtins as b\ng = b.getattr\ng(b, "chr")(0)\n',
            b'from builtins import getattr as select\nselect(builtins, "chr")(0)\n',
            b'import builtins\ng = getattr\nselect = g\nselect(builtins, "chr")(0)\n',
        )
        for source in sources:
            with self.subTest(source=source):
                self._assert_scanner_rejects_in_both_modes(
                    "connection-restoration/validate.py",
                    source,
                )

    def test_non_constructor_getattr_forms_remain_allowed_in_both_modes(self) -> None:
        source = b'import os\nvalue = getattr(os, "O_RDONLY")\n'
        self._assert_scanner_accepts_in_both_modes(
            "connection-restoration/validate.py",
            source,
        )

    def test_review_anchor_is_the_only_separate_inventory_exception(self) -> None:
        repo_root = self._copy_fixture_repo()
        fixtures_root = repo_root / "contracts/fixtures"
        index = json.loads((fixtures_root / "index.json").read_text(encoding="utf-8"))
        listed = {
            record["path"]
            for fixture in index["fixture_roots"]
            for record in fixture["files"]
        }
        for artifact in sorted(fixtures_root.rglob("*"), reverse=True):
            if not artifact.is_file():
                continue
            relative = artifact.relative_to(fixtures_root).as_posix()
            if (
                relative not in listed
                and relative not in {"README.md", "index.json", "schema.json", "review-anchors/deep-link-resolution.sha256"}
                and not relative.startswith("validator/")
            ):
                artifact.unlink()
        validate._validate_index_document(index, repo_root)

        anchor = fixtures_root / "review-anchors/deep-link-resolution.sha256"
        anchor.unlink()
        with self.assertRaises(validate.ValidationError):
            validate._validate_index_document(index, repo_root)

        anchor.write_text("synthetic anchor\n", encoding="utf-8")
        extra = fixtures_root / "review-anchors/other.sha256"
        extra.write_text("unindexed\n", encoding="utf-8")
        with self.assertRaises(validate.ValidationError):
            validate._validate_index_document(index, repo_root)

    def test_central_validator_inventory_is_exact(self) -> None:
        for missing in ("validate.py", "test_validate.py", "validation-baseline.json"):
            with self.subTest(missing=missing):
                repo_root = self._copy_fixture_repo()
                (repo_root / "contracts/fixtures/validator" / missing).unlink()
                index = json.loads((repo_root / "contracts/fixtures/index.json").read_text(encoding="utf-8"))
                with self.assertRaises(validate.ValidationError):
                    validate._validate_index_document(index, repo_root)

        repo_root = self._copy_fixture_repo()
        extra = repo_root / "contracts/fixtures/validator/extra-reviewed-artifact.py"
        extra.write_text("synthetic extra\n", encoding="utf-8")
        index = json.loads((repo_root / "contracts/fixtures/index.json").read_text(encoding="utf-8"))
        with self.assertRaises(validate.ValidationError):
            validate._validate_index_document(index, repo_root)

    def test_special_and_deep_fixture_entries_fail_closed(self) -> None:
        for kind in ("hidden", "symlink", "fifo"):
            with self.subTest(kind=kind):
                repo_root = self._copy_fixture_repo()
                validator_root = repo_root / "contracts/fixtures/validator"
                path = validator_root / {
                    "hidden": ".unreviewed-artifact",
                    "symlink": "unreviewed-link.py",
                    "fifo": "unreviewed-pipe",
                }[kind]
                if kind == "hidden":
                    path.write_text("hidden\n", encoding="utf-8")
                elif kind == "symlink":
                    path.symlink_to(validator_root / "validate.py")
                else:
                    os.mkfifo(path)
                index = json.loads((repo_root / "contracts/fixtures/index.json").read_text(encoding="utf-8"))
                with self.assertRaises(validate.ValidationError):
                    validate._validate_index_document(index, repo_root)

        repo_root = self._copy_fixture_repo()
        current = repo_root / "contracts/fixtures/validator"
        for index in range(validate.MAX_FIXTURE_TRAVERSAL_DEPTH + 1):
            current = current / f"nested-{index}"
            current.mkdir()
        index = json.loads((repo_root / "contracts/fixtures/index.json").read_text(encoding="utf-8"))
        with self.assertRaises(validate.ValidationError):
            validate._validate_index_document(index, repo_root)

    def test_canonical_index_and_schema_paths_are_required(self) -> None:
        repo_root = self._copy_fixture_repo()
        alternate_index = repo_root / "alternate-index.json"
        alternate_schema = repo_root / "alternate-schema.json"
        shutil.copy2(repo_root / "contracts/fixtures/index.json", alternate_index)
        shutil.copy2(repo_root / "contracts/fixtures/schema.json", alternate_schema)
        self._assert_blocked_in_both_modes(repo_root, "--index", str(alternate_index))
        self._assert_blocked_in_both_modes(repo_root, "--schema", str(alternate_schema))

    def test_historical_nul_parser_inputs_are_exactly_scoped(self) -> None:
        repo_root = self._copy_fixture_repo()
        index = json.loads((repo_root / "contracts/fixtures/index.json").read_text(encoding="utf-8"))
        # These are the two retained negative inputs named by the canonical
        # path/pointer/value/ancestry policy; the unchanged indexed corpus must pass.
        validate._validate_index_document(index, repo_root)

        # The pointer text is intentionally unchanged when the reviewed list is
        # replaced by numeric object keys. The container-shape binding must still
        # reject this array-to-object reuse for each historical allowance.
        repo_root = self._copy_fixture_repo()
        document_path = repo_root / "contracts/fixtures/attachment-policy/cases.json"
        document = json.loads(document_path.read_text(encoding="utf-8"))
        document["cases"] = {str(index): case for index, case in enumerate(document["cases"])}
        document_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        index, _ = self._rebind_copy(repo_root)
        with self.assertRaises(validate.ValidationError):
            validate._validate_index_document(index, repo_root)

        repo_root = self._copy_fixture_repo()
        document_path = repo_root / "contracts/fixtures/session-search/cases.json"
        document = json.loads(document_path.read_text(encoding="utf-8"))
        document["cases"] = {str(index): case for index, case in enumerate(document["cases"])}
        document_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        index, _ = self._rebind_copy(repo_root)
        with self.assertRaises(validate.ValidationError):
            validate._validate_index_document(index, repo_root)

        nul = chr(0)
        expected = "../unsafe name" + nul + ".png"
        repo_root = self._copy_fixture_repo()
        document_path = repo_root / "contracts/fixtures/attachment-policy/cases.json"
        document = json.loads(document_path.read_text(encoding="utf-8"))
        document["unreviewed_copy"] = expected
        document_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        index, _ = self._rebind_copy(repo_root)
        with self.assertRaises(validate.ValidationError):
            validate._validate_index_document(index, repo_root)

        repo_root = self._copy_fixture_repo()
        document_path = repo_root / "contracts/fixtures/connection-restoration/cases.json"
        document = json.loads(document_path.read_text(encoding="utf-8"))
        document["unreviewed_copy"] = "atlas" + nul
        document_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        index, _ = self._rebind_copy(repo_root)
        with self.assertRaises(validate.ValidationError):
            validate._validate_index_document(index, repo_root)

        for replacement in (
            "x/../unsafe name" + nul + ".png",
            "../unsafe name" + nul + ".png.extra",
            "../unsafe name" + nul + nul + ".png",
        ):
            with self.subTest(replacement=repr(replacement)):
                repo_root = self._copy_fixture_repo()
                document_path = repo_root / "contracts/fixtures/attachment-policy/cases.json"
                document = json.loads(document_path.read_text(encoding="utf-8"))
                document["cases"][10]["request"]["filename"] = replacement
                document_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
                index, _ = self._rebind_copy(repo_root)
                with self.assertRaises(validate.ValidationError):
                    validate._validate_index_document(index, repo_root)

        repo_root = self._copy_fixture_repo()
        document_path = repo_root / "contracts/fixtures/attachment-policy/cases.json"
        document = json.loads(document_path.read_text(encoding="utf-8"))
        document["bad" + nul + "key"] = False
        document_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        index, _ = self._rebind_copy(repo_root)
        with self.assertRaises(validate.ValidationError):
            validate._validate_index_document(index, repo_root)

    def test_credential_scanner_checks_every_match_in_both_modes(self) -> None:
        """A reviewed first negative sample cannot hide a later credential."""

        cases = (
            (
                "deployment-security/external-allowlist/test_validate.py",
                (
                    'VALUE = "Authorization: Basic '
                    + validate.TEST_NEGATIVE_BASIC_AUTH_CANDIDATE
                    + '; Authorization: Basic AAAAAAAAAAAAAAAA"\n'
                ),
            ),
            (
                "connection-restoration/validate.py",
                'VALUE = "synthetic -----BEGIN PRIVATE KEY----- -----BEGIN RSA PRIVATE KEY-----"\n',
            ),
            (
                "connection-restoration/validate.py",
                'VALUE = "ghp_example12345678 ghp_liveprovider12345678"\n',
            ),
            (
                "connection-restoration/validate.py",
                'VALUE = "AKIAxxxxxxxxxxxxxxxx AKIAABCDEFGHIJKLMNOP"\n',
            ),
            (
                "connection-restoration/validate.py",
                'VALUE = "Bearer request.payload.token Bearer AAAAAAAAAAAAAAAA"\n',
            ),
            (
                "connection-restoration/validate.py",
                'VALUE = "eyJexample123.eyJexample456.eyJexample789 eyJaaaaaaaa.eyJbbbbbbbb.eyJcccccccc"\n',
            ),
            (
                "connection-restoration/validate.py",
                'VALUE = "token=source.token token=unredacted-secret-value"\n',
            ),
        )
        for relative_path, source in cases:
            with self.subTest(relative_path=relative_path, source=source):
                self._assert_scanner_rejects_in_both_modes(relative_path, source.encode("utf-8"))

    def test_regex_compiler_aliases_are_scanned_in_both_modes(self) -> None:
        """Static aliases must receive the same bounded regex policy."""

        sources = (
            'import re as regex_module\nregex_module.compile(r"h(?:t|T)tps://live.example.net/x")\n',
            'from re import compile as regex_compile\nregex_compile(r"h(?:t|T)tps://live.example.net/x")\n',
            'import re\nregex_module = re\nregex_compile = regex_module.compile\nregex_compile(r"h(?:t|T)tps://live.example.net/x")\n',
            'import re\nregex_compile = getattr(re, "compile")\nregex_compile(r"h(?:t|T)tps://live.example.net/x")\n',
            'import re\ngetattr(re, "compile")(r"h(?:t|T)tps://live.example.net/x")\n',
            'import re\npattern = r"h(?:t|T)tps://"\nhost = "live.example.net/x"\nre.compile(pattern + host)\n',
            'import re\nre.compile(pattern=r"h(?:t|T)tps://live.example.net/x")\n',
            'import re\nre.compile(rb"h(?:t|T)tps://live.example.net/x")\n',
        )
        for source in sources:
            with self.subTest(source=source):
                self._assert_scanner_rejects_in_both_modes(
                    "connection-restoration/validate.py",
                    source.encode("utf-8"),
                )

    def test_uncompiled_regex_literals_are_scanned_in_both_modes(self) -> None:
        """Plain retained regex-shaped literals cannot hide live authorities."""

        sources = (
            'VALUE = r"h(?:x)://live.example.net/x"\n',
            'VALUE = r"h\\Qttps://live.example.net/x"\n',
        )
        for source in sources:
            with self.subTest(source=source):
                self._assert_scanner_rejects_in_both_modes(
                    "connection-restoration/validate.py",
                    source.encode("utf-8"),
                )

    def test_regex_protocol_prefix_branch_has_no_authority(self) -> None:
        """A detector branch ending at ``://`` must not absorb its sibling."""

        source = (
            'VALUE = r"(?:bearer\\s+|basic\\s+|https?://|'
            '(?:password|secret|token)\\s*[:=])"\n'
        )
        self._assert_scanner_accepts_in_both_modes(
            "connection-restoration/validate.py",
            source.encode("utf-8"),
        )
        self._assert_scanner_rejects_in_both_modes(
            "connection-restoration/validate.py",
            b'VALUE = r"https?://live.example.net/x"\n',
        )

    def test_malformed_named_group_headers_fail_closed_in_both_modes(self) -> None:
        """Do not let malformed group metadata hide schemes or authorities."""

        slash = chr(92)
        host = ".".join(("api", "live", "invalid"))
        schemes = ("http", "https", "ws", "wss")
        port_variants = ("abc", "0", "65536")
        for opener in ("(?P<", "(?<"):
            for width in (64, 65, 127, 128, 129):
                for scheme in schemes:
                    pattern = opener + ("x" * width) + scheme + "://" + host + "/x>safe)"
                    with self.subTest(opener=opener, width=width, scheme=scheme):
                        self._assert_scanner_rejects_in_both_modes(
                            "connection-restoration/validate.py",
                            ("re.compile(r'" + pattern + "')\n").encode("utf-8"),
                        )
                for port in port_variants:
                    pattern = opener + ("x" * width) + "https://" + host + ":" + port + "/x>safe)"
                    with self.subTest(opener=opener, width=width, port=port):
                        self._assert_scanner_rejects_in_both_modes(
                            "connection-restoration/validate.py",
                            ("re.compile(r'" + pattern + "')\n").encode("utf-8"),
                        )
                dynamic = opener + ("x" * width) + "h(?:t|T)tps://" + host + "/x>safe)"
                with self.subTest(opener=opener, width=width, dynamic=True):
                    self._assert_scanner_rejects_in_both_modes(
                        "connection-restoration/validate.py",
                        ("re.compile(r'" + dynamic + "')\n").encode("utf-8"),
                    )
                unknown = opener + ("x" * width) + slash + "Q>safe)"
                with self.subTest(opener=opener, width=width, unknown_escape=True):
                    self._assert_scanner_rejects_in_both_modes(
                        "connection-restoration/validate.py",
                        ("re.compile(r'" + unknown + "')\n").encode("utf-8"),
                    )

    def test_valid_named_groups_and_structural_boundaries_remain_bounded(self) -> None:
        """Keep valid names and exact 64/65/127/128/129 group boundaries."""

        host = ".".join(("synthetic", "invalid"))
        for opener in ("(?P<", "(?<"):
            pattern = opener + "url>" + host + ")"
            with self.subTest(named_opener=opener):
                self._assert_scanner_accepts_in_both_modes(
                    "connection-restoration/validate.py",
                    ("re.compile(r'" + pattern + "')\n").encode("utf-8"),
                )

        for opener in ("(?:", "(?P<n>", "(?<n>"):
            for total_length in (64, 65, 127, 128):
                body_length = total_length - len(opener) - 1
                pattern = opener + ("x" * body_length) + ")"
                with self.subTest(opener=opener, total_length=total_length):
                    self._assert_scanner_accepts_in_both_modes(
                        "connection-restoration/validate.py",
                        ("re.compile(r'" + pattern + "')\n").encode("utf-8"),
                    )
            total_length = 129
            body_length = total_length - len(opener) - 1
            pattern = opener + ("x" * body_length) + ")"
            with self.subTest(opener=opener, total_length=total_length):
                self._assert_scanner_rejects_in_both_modes(
                    "connection-restoration/validate.py",
                    ("re.compile(r'" + pattern + "')\n").encode("utf-8"),
                )

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

    def test_normal_and_optimized_blocked_modes_have_same_boundary(self) -> None:
        normal = self._run()
        optimized = self._run(optimized=True)
        self.assertEqual(normal.returncode, 1)
        self.assertEqual(optimized.returncode, 1)
        normal_payload = json.loads(normal.stdout)
        optimized_payload = json.loads(optimized.stdout)
        self.assertEqual(normal_payload, optimized_payload)
        self.assertFalse(normal_payload["ok"])
        self.assertFalse(normal_payload["live_claim"])
        self.assertEqual(normal_payload["evidence_status"], "blocked")
        self.assertEqual(normal_payload["error"]["code"], "fixture_index_invalid")
        self.assertEqual(normal.stderr, "")
        self.assertEqual(optimized.stderr, "")

    def test_every_owned_file_is_indexed_without_weakening_unknown_file_detection(self) -> None:
        repo_root = self._copy_fixture_repo()
        index = json.loads((repo_root / "contracts/fixtures/index.json").read_text(encoding="utf-8"))
        fixture_count, coverage_count = validate._validate_index_document(index, repo_root)
        self.assertEqual(fixture_count, 30)
        self.assertEqual(coverage_count, 29)
        # The copied source has the same intentionally frozen baseline, so the
        # complete CLI must remain blocked rather than claim refreshed evidence.
        for optimized in (False, True):
            completed = self._run(optimized=optimized, repo_root=repo_root)
            self.assertEqual(completed.returncode, 1)
            payload = json.loads(completed.stdout)
            self.assertFalse(payload["ok"])
            self.assertFalse(payload["live_claim"])
            self.assertEqual(payload["evidence_status"], "blocked")
            self.assertEqual(payload["error"]["code"], "fixture_index_invalid")
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
