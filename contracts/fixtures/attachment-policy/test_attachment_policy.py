"""Tests for the offline, synthetic images-only attachment policy contract.

The suite uses only synthetic JSON and temporary local Git repositories. It does
not use a machine-specific Hermes checkout, HTTP, Hermes, credentials,
transcripts, uploads, or user data. Source-attestation tests build immutable
objects locally so clean CI always exercises the adversarial Git boundary.
"""

from __future__ import annotations

import copy
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


FIXTURE_DIR = Path(__file__).resolve().parent
if str(FIXTURE_DIR) not in sys.path:
    sys.path.insert(0, str(FIXTURE_DIR))

import validate  # noqa: E402  (local contract module)


class AttachmentPolicyTests(unittest.TestCase):
    """Keep policy cases, strict schema, redaction, and provenance aligned."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.document = validate.load_document(FIXTURE_DIR / "cases.json")
        validate.validate_document(cls.document)
        cls.cases = {case["id"]: case for case in cls.document["cases"]}

    def _run_cli(
        self,
        path: Path | None = None,
        optimized: bool = False,
        source_root: Path | None = None,
        *extra: str,
    ) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.append(str(FIXTURE_DIR / "validate.py"))
        if path is not None:
            command.extend(["--cases", str(path)])
        if source_root is not None:
            command.extend(["--source-root", str(source_root)])
        command.extend(extra)
        return subprocess.run(command, check=False, capture_output=True, text=True)

    def _assert_structured_cli_failure(
        self,
        path: Path,
        *extra: str,
        forbidden: tuple[str, ...] = (),
    ) -> None:
        for optimized in (False, True):
            with self.subTest(optimized=optimized, path=path.name):
                completed = self._run_cli(path, optimized, None, *extra)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(completed.stderr, "")
                lines = [line for line in completed.stdout.splitlines() if line.strip()]
                self.assertEqual(len(lines), 1)
                self.assertLess(len(lines[0]), 512)
                payload = json.loads(lines[0])
                self.assertIn(payload["error"]["code"], {"contract", "runtime"})
                self.assertIsInstance(payload["error"]["message"], str)
                self.assertNotIn("Traceback", completed.stdout + completed.stderr)
                for raw in forbidden:
                    self.assertNotIn(raw, completed.stdout + completed.stderr)

    @staticmethod
    def _git(root: Path, *args: str, env: dict[str, str] | None = None) -> str:
        completed = subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )
        return completed.stdout.strip()

    def _make_source_repo(self) -> tuple[Path, dict[str, object], dict[str, str]]:
        """Build a deterministic local repository for source attestation tests."""

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "source"
        source_file = root / validate.SOURCE_PATH
        source_file.parent.mkdir(parents=True)
        source_lines = [
            "_CHAT_IMAGE_UPLOAD_MAX_BYTES = 25 * 1024 * 1024",
            '_CHAT_IMAGE_ALLOWED_EXTENSIONS = frozenset({".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"})',
            "_CHAT_IMAGE_MAGIC: tuple[tuple[bytes, str], ...] = (",
            "def _decode_chat_image_upload(payload: ChatImageUpload) -> tuple[bytes, str, str]:",
            '@app.post("/api/chat/image-upload")',
            '"bytes": len(data),',
        ]
        source_file.write_text("\n".join(source_lines) + "\n", encoding="utf-8")
        self._git(root, "init", "-q")
        self._git(root, "config", "user.email", "fixture@example.invalid")
        self._git(root, "config", "user.name", "Synthetic Fixture")
        self._git(root, "add", validate.SOURCE_PATH)
        self._git(root, "commit", "-q", "-m", "synthetic pinned source")

        commit = self._git(root, "rev-parse", "HEAD")
        tree = self._git(root, "rev-parse", "HEAD^{tree}")
        blob = self._git(root, "rev-parse", f"HEAD:{validate.SOURCE_PATH}")
        source_bytes = source_file.read_bytes()
        citations = [
            {
                "id": f"citation-{index}",
                "line": index + 1,
                "marker": marker,
                "claim": f"Synthetic source claim {index}.",
            }
            for index, marker in enumerate(source_lines)
        ]
        document = copy.deepcopy(self.document)
        document["source_evidence"] = {
            "path": validate.SOURCE_PATH,
            "git_blob_sha": blob,
            "file_sha256": hashlib.sha256(source_bytes).hexdigest(),
            "citations": citations,
        }
        metadata = {
            "commit": commit,
            "tree": tree,
            "blob": blob,
            "file_sha256": hashlib.sha256(source_bytes).hexdigest(),
        }
        return root, document, metadata

    @contextmanager
    def _source_constants(self, metadata: dict[str, str]):
        names = {
            "PINNED_SHA": metadata["commit"],
            "PINNED_TREE": metadata["tree"],
            "SOURCE_GIT_BLOB": metadata["blob"],
            "SOURCE_FILE_SHA256": metadata["file_sha256"],
        }
        with patch.multiple(validate, **names):
            yield

    def test_checked_in_document_validates_and_inventory_is_ordered(self) -> None:
        self.assertEqual(len(self.cases), len(validate.EXPECTED_CASE_IDS))
        self.assertEqual(tuple(self.cases), validate.EXPECTED_CASE_IDS)
        self.assertEqual(validate.validate_mutations(self.document), 14)

    def test_every_case_matches_the_policy_evaluator(self) -> None:
        for case in self.document["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(validate.evaluate_case(case), case["expected"])

    def test_all_pinned_signatures_are_executable(self) -> None:
        expected = {
            "valid-png": ("png", ".png"),
            "valid-jpeg": ("jpeg", ".jpg"),
            "valid-gif87a": ("gif87a", ".gif"),
            "valid-gif89a": ("gif89a", ".gif"),
            "valid-webp": ("webp", ".webp"),
            "valid-bmp": ("bmp", ".bmp"),
        }
        for case_id, (format_id, extension) in expected.items():
            case = self.cases[case_id]
            data, mime = validate._parse_data_url(case["request"]["data_url"])
            self.assertIsInstance(data, bytes)
            self.assertIn(mime, validate.SUPPORTED_IMAGE_MIME_FORMATS)
            self.assertEqual(validate._format_from_bytes(data), (format_id, extension))
            self.assertEqual(case["expected"]["detected_extension"], extension)
            self.assertIn(format_id, validate.SUPPORTED_IMAGE_MIME_FORMATS[mime])

    def test_exact_data_url_header_grammar_rejects_parameter_tricks(self) -> None:
        expected = {
            "invalid-base64-parameter-suffix": "invalid_data_url",
            "invalid-base64-parameter-extra": "invalid_data_url",
            "invalid-base64-parameter-repeat": "invalid_data_url",
            "invalid-base64-parameter-case": "invalid_data_url",
        }
        for case_id, reason in expected.items():
            with self.subTest(case=case_id):
                data, actual_reason = validate._parse_data_url(self.cases[case_id]["request"]["data_url"])
                self.assertIsNone(data)
                self.assertEqual(actual_reason, reason)
        malformed = (
            (" data:image/png;base64,iVBORw0KGgo=", "invalid_data_url"),
            ("data:image/png;base64,iVBORw0KGgo= ", "invalid_base64"),
            ("data:image/png;base64, iVBORw0KGgo=", "invalid_base64"),
            ("data:image/PNG;base64,iVBORw0KGgo=", "invalid_data_url"),
            ("data:IMAGE/png;base64,iVBORw0KGgo=", "invalid_data_url"),
        )
        for value, reason in malformed:
            with self.subTest(malformed=value):
                self.assertEqual(validate._parse_data_url(value)[1], reason)

    def test_base64_pad_bits_must_reencode_canonically(self) -> None:
        data, reason = validate._parse_data_url("data:image/png;base64,iVBORw0KGgp=")
        self.assertIsNone(data)
        self.assertEqual(reason, "noncanonical_base64")
        self.assertEqual(
            validate.evaluate_case(self.cases["invalid-noncanonical-base64"])["reason"],
            "noncanonical_base64",
        )

    def test_mime_and_bytes_must_agree(self) -> None:
        unsupported = self.cases["invalid-unsupported-image-mime"]
        self.assertEqual(validate.evaluate_case(unsupported)["reason"], "unsupported_image_mime")
        mismatch = self.cases["invalid-image-mime-mismatch"]
        self.assertEqual(validate.evaluate_case(mismatch)["reason"], "mime_mismatch")
        self.assertEqual(validate.evaluate_case(mismatch)["draft"], "preserved")

    def test_polyglots_fail_closed_but_foreign_text_inside_a_valid_chunk_does_not(self) -> None:
        polyglots = [case_id for case_id in self.cases if "polyglot" in case_id]
        self.assertEqual(len(polyglots), 5)
        for case_id in polyglots:
            with self.subTest(case=case_id):
                case = self.cases[case_id]
                self.assertEqual(validate.evaluate_case(case)["reason"], "polyglot_image")
                data, _ = validate._parse_data_url(case["request"]["data_url"])
                self.assertIsNone(validate._format_from_bytes(data))

        payload = b"%PDF-inside-a-valid-IDAT-chunk"
        chunk = len(payload).to_bytes(4, "big") + b"IDAT" + payload + b"\x00" * 4
        self.assertEqual(
            validate._format_from_bytes(b"\x89PNG\r\n\x1a\n" + chunk),
            ("png", ".png"),
        )
        iend = b"\x00\x00\x00\x00IEND" + b"\x00" * 4
        self.assertIsNone(validate._format_from_bytes(b"\x89PNG\r\n\x1a\n" + iend + b"%PDF-1.7"))

    def test_size_boundary_is_inclusive_and_oversize_is_rejected(self) -> None:
        boundary = copy.deepcopy(self.cases["valid-png"])
        boundary["fixture"]["decoded_size_override"] = validate.MAX_IMAGE_BYTES
        self.assertEqual(validate.evaluate_case(boundary)["decision"], "accepted")

        oversize = copy.deepcopy(self.cases["valid-png"])
        oversize["fixture"]["decoded_size_override"] = validate.MAX_IMAGE_BYTES + 1
        result = validate.evaluate_case(oversize)
        self.assertEqual(result["reason"], "too_large")
        self.assertEqual(result["draft"], "preserved")
        self.assertEqual(result["response_fields"], [])

    def test_filename_control_byte_is_escaped_and_omitted_or_null_defaults(self) -> None:
        raw = (FIXTURE_DIR / "cases.json").read_bytes()
        self.assertNotIn(b"\x00", raw)
        self.assertIn(b"\\u0000", raw)
        filename = self.cases["valid-sanitized-filename"]["request"]["filename"]
        self.assertIn("\x00", filename)
        self.assertEqual(validate.evaluate_case(self.cases["valid-sanitized-filename"])["filename_stem"], "unsafe_name")
        self.assertNotIn("unsafe", self.cases["valid-sanitized-filename"]["expected"]["diagnostic"])
        self.assertNotIn("filename", self.cases["valid-default-filename-omitted"]["request"])
        self.assertIsNone(self.cases["valid-null-filename"]["request"]["filename"])
        for case_id in ("valid-default-filename-omitted", "valid-null-filename"):
            self.assertEqual(validate.evaluate_case(self.cases[case_id])["filename_stem"], "pasted-image")

    def test_rejections_preserve_draft_and_never_return_storage_fields(self) -> None:
        rejection_ids = tuple(case_id for case_id in self.cases if case_id.startswith("invalid-"))
        self.assertEqual(len(rejection_ids), 22)
        for case_id in rejection_ids:
            with self.subTest(case=case_id):
                expected = self.cases[case_id]["expected"]
                self.assertEqual(expected["decision"], "rejected")
                self.assertEqual(expected["draft"], "preserved")
                self.assertEqual(expected["attachment_state"], "failed")
                self.assertEqual(expected["response_fields"], [])
                self.assertIsNone(expected["stored_under"])
                self.assertIsNone(expected["filename_stem"])

    def test_semantic_diagnostics_do_not_retain_raw_request_material(self) -> None:
        for case in self.document["cases"]:
            diagnostic = case["expected"]["diagnostic"]
            request = case["request"]
            self.assertNotIn("data:", diagnostic)
            self.assertNotIn("HERMES_HOME", diagnostic)
            if isinstance(request, dict):
                for key in ("data_url", "filename"):
                    value = request.get(key)
                    if isinstance(value, str) and value:
                        self.assertNotIn(value, diagnostic)

    def test_retained_notes_reject_raw_attachment_and_path_material_without_echo(self) -> None:
        forbidden_values = (
            "data:image/png;base64,iVBORw0KGgo=",
            "iVBORw0KGgo=",
            "/Users/example/clipboard.png",
            "file:///tmp/clipboard.png",
            r"C:\\Users\\example\\clipboard.png",
            "../unsafe name.png",
        )
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            for index, value in enumerate(forbidden_values):
                mutated = copy.deepcopy(self.document)
                mutated["cases"][0]["notes"] = value
                path = directory_path / f"notes-{index}.json"
                path.write_text(json.dumps(mutated), encoding="utf-8")
                with self.subTest(value=value):
                    with self.assertRaises(validate.ContractError):
                        validate.validate_document(mutated)
                    self._assert_structured_cli_failure(path, forbidden=(value,))

            claim_value = "data:image/png;base64,iVBORw0KGgo="
            mutated = copy.deepcopy(self.document)
            mutated["source_evidence"]["citations"][0]["claim"] = claim_value
            path = directory_path / "claim.json"
            path.write_text(json.dumps(mutated), encoding="utf-8")
            with self.assertRaises(validate.ContractError):
                validate.validate_document(mutated)
            self._assert_structured_cli_failure(path, forbidden=(claim_value,))

    def test_state_without_success_evidence_is_explicit(self) -> None:
        self.assertEqual(self.cases["empty-selection"]["expected"]["diagnostic"], "attachment[empty]")
        self.assertEqual(self.cases["pending-upload"]["expected"]["diagnostic"], "attachment[pending]")
        self.assertEqual(self.cases["interrupted-upload"]["expected"]["diagnostic"], "attachment[interrupted]")
        self.assertEqual(self.cases["incompatible-contract"]["expected"]["diagnostic"], "attachment[blocked;reason=incompatible_contract]")
        for case_id in ("pending-upload", "interrupted-upload", "incompatible-contract"):
            self.assertEqual(self.cases[case_id]["expected"]["draft"], "preserved")

    def test_duplicate_keys_nonfinite_and_parser_limits_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            fixtures = {
                "duplicate.json": b'{"schema": "one", "schema": "two"}',
                "nan.json": b'{"schema": NaN}',
                "exponent-overflow.json": b'{"schema": 1e309}',
                "huge-integer.json": b'{"schema": ' + (b"9" * 5000) + b"}",
                "deep.json": (b"[" * (validate.MAX_JSON_SCAN_DEPTH + 1)) + b"0" + (b"]" * (validate.MAX_JSON_SCAN_DEPTH + 1)),
                "syntax.json": b'{"schema":',
                "invalid-utf8.json": b"{\xff",
            }
            for name, raw in fixtures.items():
                path = directory_path / name
                path.write_bytes(raw)
                with self.subTest(path=name):
                    with self.assertRaises(validate.ContractError):
                        validate.load_document(path)
                    forbidden = () if name == "invalid-utf8.json" else (raw[:64].decode("utf-8", "ignore"),)
                    self._assert_structured_cli_failure(path, forbidden=forbidden)

    def test_strict_schema_rejects_extra_nested_values_and_bool_integers(self) -> None:
        mutations = []

        extra_expected = copy.deepcopy(self.document)
        extra_expected["cases"][0]["expected"]["unexpected"] = True
        mutations.append(extra_expected)

        bool_as_cap = copy.deepcopy(self.document)
        bool_as_cap["limits"]["max_bytes"] = True
        mutations.append(bool_as_cap)

        offset_only = copy.deepcopy(self.document)
        offset_only["limits"]["magic_formats"][1]["offset"] = 0
        mutations.append(offset_only)

        wrong_line = copy.deepcopy(self.document)
        wrong_line["source_evidence"]["citations"][0]["line"] = 0
        mutations.append(wrong_line)

        malformed_filename = copy.deepcopy(self.document)
        malformed_filename["cases"][2]["request"]["filename"] = 7
        mutations.append(malformed_filename)

        for mutated in mutations:
            with self.subTest(mutated=mutated):
                with self.assertRaises(validate.ContractError):
                    validate.validate_document(mutated)

    def test_source_attestation_exact_root_and_pinned_objects_are_offline(self) -> None:
        root, document, metadata = self._make_source_repo()
        with self._source_constants(metadata):
            validate.validate_source(root, document)
            with self.assertRaises(validate.ContractError):
                validate.validate_source(root / validate.SOURCE_PATH.rsplit("/", 1)[0], document)
            with self.assertRaises(validate.ContractError):
                validate.validate_source(root / ".git", document)

            bare = root.parent / "bare"
            self._git(root.parent, "clone", "--bare", "-q", str(root), str(bare))
            with self.assertRaises(validate.ContractError):
                validate.validate_source(bare, document)

    def test_source_attestation_rejects_redirects_wrong_objects_and_missing_objects(self) -> None:
        root, document, metadata = self._make_source_repo()
        unrelated = root.parent / "unrelated"
        unrelated.mkdir()
        redirect_names = (
            "GIT_COMMON_DIR",
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_CONFIG",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_PARAMETERS",
            "GIT_GRAFT_FILE",
            "GIT_SHALLOW_FILE",
            "GIT_IMPLICIT_WORK_TREE",
            "GIT_REPLACE_REF_BASE",
        )
        with self._source_constants(metadata):
            with patch.dict(os.environ, {"GIT_COMMON_DIR": str(root / ".git")}, clear=False):
                with self.assertRaises(validate.ContractError):
                    validate.validate_source(unrelated, document)
            for name in redirect_names:
                with self.subTest(variable=name):
                    self.assertNotIn(name, validate._git_environment())

            with patch.object(validate, "SOURCE_GIT_BLOB", metadata["tree"]):
                with self.assertRaises(validate.ContractError):
                    validate.validate_source(root, document)
            with patch.object(validate, "SOURCE_GIT_BLOB", "1" * 40):
                with self.assertRaises(validate.ContractError):
                    validate.validate_source(root, document)

    def test_source_attestation_rejects_truncated_blob_output(self) -> None:
        root, document, metadata = self._make_source_repo()
        real_git = shutil.which("git")
        self.assertIsNotNone(real_git)
        with tempfile.TemporaryDirectory() as directory:
            wrapper = Path(directory) / "git"
            wrapper.write_text(
                "#!/usr/bin/env python3\n"
                "import os, subprocess, sys\n"
                f"real = {real_git!r}\n"
                "args = sys.argv[1:]\n"
                "if len(args) >= 4 and args[-3:-1] == ['cat-file', 'blob']:\n"
                "    result = subprocess.run([real, *args], capture_output=True)\n"
                "    sys.stdout.buffer.write(result.stdout[:1])\n"
                "    sys.stderr.buffer.write(result.stderr)\n"
                "    raise SystemExit(result.returncode)\n"
                "os.execv(real, [real, *args])\n",
                encoding="utf-8",
            )
            wrapper.chmod(0o755)
            with self._source_constants(metadata):
                with patch.dict(os.environ, {"PATH": str(wrapper.parent) + os.pathsep + os.environ.get("PATH", "")}, clear=False):
                    with self.assertRaises(validate.ContractError):
                        validate.validate_source(root, document)

    def test_replace_refs_and_lazy_fetch_are_disabled_for_source_reads(self) -> None:
        root, document, metadata = self._make_source_repo()
        source_file = root / validate.SOURCE_PATH
        source_file.write_text("replacement commit\n", encoding="utf-8")
        self._git(root, "add", validate.SOURCE_PATH)
        self._git(root, "commit", "-q", "-m", "replacement")
        replacement = self._git(root, "rev-parse", "HEAD")
        self._git(root, "replace", "--force", metadata["commit"], replacement)
        with self._source_constants(metadata):
            validate.validate_source(root, document)
            with patch.dict(os.environ, {"GIT_NO_LAZY_FETCH": "0", "GIT_NO_REPLACE_OBJECTS": "0"}, clear=False):
                environment = validate._git_environment()
                self.assertEqual(environment["GIT_NO_LAZY_FETCH"], "1")
                self.assertEqual(environment["GIT_NO_REPLACE_OBJECTS"], "1")

    def test_source_errors_are_semantic_and_cli_redacts_non_directory_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "host-secret-source-file"
            path.write_bytes(b"not a directory")
            for optimized in (False, True):
                with self.subTest(optimized=optimized):
                    completed = self._run_cli(optimized=optimized, source_root=path)
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertEqual(completed.stderr, "")
                    self.assertNotIn(str(path), completed.stdout)
                    self.assertNotIn("host-secret", completed.stdout)
                    self.assertLess(len(completed.stdout), 512)
                    self.assertNotIn("Traceback", completed.stdout)

    def test_normal_and_optimized_cli_outputs_match(self) -> None:
        normal = self._run_cli()
        optimized = self._run_cli(optimized=True)
        for completed in (normal, optimized):
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stderr, "")
            self.assertEqual(
                completed.stdout.strip(),
                "attachment_policy_validation=ok cases=35 mutations=14",
            )
        self.assertEqual(normal.stdout, optimized.stdout)

    def test_cli_rejects_unknown_arguments_as_one_structured_error(self) -> None:
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                completed = self._run_cli(optimized=optimized, *["--unknown"])
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(completed.stderr, "")
                self.assertEqual(len(completed.stdout.splitlines()), 1)
                self.assertEqual(json.loads(completed.stdout)["error"]["code"], "contract")

    def test_validator_compiles_without_assert_based_validation(self) -> None:
        py_compile.compile(str(FIXTURE_DIR / "validate.py"), doraise=True)
        source = (FIXTURE_DIR / "validate.py").read_text(encoding="utf-8")
        self.assertNotIn("assert ", source)


if __name__ == "__main__":
    unittest.main()
