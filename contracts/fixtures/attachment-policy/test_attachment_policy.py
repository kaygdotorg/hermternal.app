"""Tests for the offline, synthetic images-only attachment policy contract.

These tests exercise deterministic policy evaluation and provenance checks only.
They do not perform HTTP, Hermes, filesystem-upload, credential, or user-data
operations. The optional pinned-source test reads immutable Git objects from the
local reference checkout when that checkout is available.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
import py_compile
import subprocess
import sys
import tempfile
import unittest


FIXTURE_DIR = Path(__file__).resolve().parent
SOURCE_ROOT = Path("/Users/agents/Developer/hermes-agent-reference")
if str(FIXTURE_DIR) not in sys.path:
    sys.path.insert(0, str(FIXTURE_DIR))

import validate  # noqa: E402  (local contract module)


class AttachmentPolicyTests(unittest.TestCase):
    """Keep policy cases, strict schema, diagnostics, and provenance aligned."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.document = validate.load_document(FIXTURE_DIR / "cases.json")
        validate.validate_document(cls.document)
        cls.cases = {case["id"]: case for case in cls.document["cases"]}

    def _run_cli(
        self,
        path: Path | None = None,
        optimized: bool = False,
        *extra: str,
    ) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend([str(FIXTURE_DIR / "validate.py")])
        if path is not None:
            command.extend(["--cases", str(path)])
        command.extend(extra)
        return subprocess.run(command, check=False, capture_output=True, text=True)

    def _assert_structured_cli_failure(self, path: Path, *extra: str) -> None:
        for optimized in (False, True):
            with self.subTest(optimized=optimized, path=path.name):
                completed = self._run_cli(path, optimized, *extra)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(completed.stderr, "")
                lines = [line for line in completed.stdout.splitlines() if line.strip()]
                self.assertEqual(len(lines), 1)
                payload = json.loads(lines[0])
                self.assertEqual(payload["error"]["code"], "contract")
                self.assertIsInstance(payload["error"]["message"], str)
                self.assertNotIn("Traceback", completed.stdout + completed.stderr)

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
            self.assertTrue(mime.startswith("image/"))
            self.assertEqual(validate._format_from_bytes(data), (format_id, extension))
            self.assertEqual(case["expected"]["detected_extension"], extension)

        self.assertEqual(validate._format_from_bytes(b"RIFF0000WEBP"), ("webp", ".webp"))
        self.assertIsNone(validate._format_from_bytes(b"RIFF0000NOPE"))
        self.assertIsNone(validate._format_from_bytes(b"not-an-image"))

    def test_mime_is_a_declaration_and_bytes_choose_the_extension(self) -> None:
        case = self.cases["valid-recognized-bytes-unknown-image-mime"]
        result = validate.evaluate_case(case)
        self.assertEqual(result["detected_extension"], ".png")
        self.assertEqual(result["filename_stem"], "relabelled")
        self.assertEqual(result["decision"], "accepted")
        self.assertEqual(case["request"]["data_url"].split(":", 1)[1].split(";", 1)[0], "image/tiff")

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

    def test_filename_control_byte_is_escaped_in_json_and_sanitized(self) -> None:
        raw = (FIXTURE_DIR / "cases.json").read_bytes()
        self.assertNotIn(b"\x00", raw)
        self.assertIn(b"\\u0000", raw)
        filename = self.cases["valid-sanitized-filename"]["request"]["filename"]
        self.assertIn("\x00", filename)
        result = validate.evaluate_case(self.cases["valid-sanitized-filename"])
        self.assertEqual(result["filename_stem"], "unsafe_name")
        self.assertNotIn("unsafe", result["diagnostic"])

    def test_rejections_preserve_draft_and_never_return_storage_fields(self) -> None:
        rejection_ids = tuple(case_id for case_id in self.cases if case_id.startswith("invalid-"))
        self.assertEqual(len(rejection_ids), 10)
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
            self.assertNotIn("iVBORw0KGgo=", diagnostic)
            self.assertNotIn("/9j/", diagnostic)
            self.assertNotIn("HERMES_HOME", diagnostic)
            if isinstance(request, dict):
                for key in ("data_url", "filename"):
                    value = request.get(key)
                    if isinstance(value, str) and value:
                        self.assertNotIn(value, diagnostic)

    def test_state_without_success_evidence_is_explicit(self) -> None:
        self.assertEqual(self.cases["empty-selection"]["expected"]["diagnostic"], "attachment[empty]")
        self.assertEqual(self.cases["pending-upload"]["expected"]["diagnostic"], "attachment[pending]")
        self.assertEqual(self.cases["interrupted-upload"]["expected"]["diagnostic"], "attachment[interrupted]")
        self.assertEqual(self.cases["incompatible-contract"]["expected"]["diagnostic"], "attachment[blocked;reason=incompatible_contract]")
        for case_id in ("pending-upload", "interrupted-upload", "incompatible-contract"):
            self.assertEqual(self.cases[case_id]["expected"]["draft"], "preserved")

    def test_duplicate_keys_and_non_finite_values_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            duplicate = directory_path / "duplicate.json"
            duplicate.write_text('{"schema": "one", "schema": "two"}', encoding="utf-8")
            non_finite = directory_path / "non-finite.json"
            non_finite.write_text('{"schema": NaN}', encoding="utf-8")
            for path in (duplicate, non_finite):
                with self.subTest(path=path.name):
                    with self.assertRaises(validate.ContractError):
                        validate.load_document(path)
                    self._assert_structured_cli_failure(path)

    def test_malformed_nested_documents_fail_closed_without_tracebacks(self) -> None:
        malformed_documents: list[object] = [
            None,
            [],
            {"schema": []},
            {"schema": validate.SCHEMA, "cases": None},
        ]
        malformed_cases = copy.deepcopy(self.document)
        malformed_cases["cases"] = [None]
        malformed_documents.append(malformed_cases)
        malformed_state = copy.deepcopy(self.document)
        malformed_state["cases"][0]["state"] = []
        malformed_documents.append(malformed_state)

        with tempfile.TemporaryDirectory() as directory:
            for index, document in enumerate(malformed_documents):
                path = Path(directory) / f"malformed-{index}.json"
                path.write_text(json.dumps(document), encoding="utf-8")
                self._assert_structured_cli_failure(path)

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

        for mutated in mutations:
            with self.subTest(mutated=mutated):
                with self.assertRaises(validate.ContractError):
                    validate.validate_document(mutated)

    def test_pinned_source_attestation_when_reference_checkout_is_available(self) -> None:
        if not SOURCE_ROOT.is_dir():
            self.skipTest(f"pinned source checkout is unavailable: {SOURCE_ROOT}")
        validate.validate_source(SOURCE_ROOT, self.document)

        mutated = copy.deepcopy(self.document)
        mutated["source_evidence"]["citations"][0]["line"] += 1
        with self.assertRaises(validate.ContractError):
            validate.validate_source(SOURCE_ROOT, mutated)

    def test_normal_and_optimized_cli_outputs_match(self) -> None:
        normal = self._run_cli()
        optimized = self._run_cli(optimized=True)
        for completed in (normal, optimized):
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stderr, "")
            self.assertEqual(
                completed.stdout.strip(),
                "attachment_policy_validation=ok cases=22 mutations=14",
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
