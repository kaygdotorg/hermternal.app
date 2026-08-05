"""Unit and mutation tests for the offline deep-link grammar contract.

The tests use only the checked-in synthetic JSON and the standard library.
They do not make live HTTP, Hermes, DNS, filesystem-session, or Apple calls.
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
if str(FIXTURE_DIR) not in sys.path:
    sys.path.insert(0, str(FIXTURE_DIR))

import validate  # noqa: E402  (local contract module)


class DeepLinkGrammarTests(unittest.TestCase):
    """Keep the parser, fixture schema, and fail-closed controls aligned."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.document = validate.load_document(FIXTURE_DIR / "cases.json")
        validate.validate_document(cls.document)
        cls.cases = {case["id"]: case for case in cls.document["cases"]}

    def _run_cli(self, path: Path, optimized: bool = False) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend([str(FIXTURE_DIR / "validate.py"), "--cases", str(path)])
        return subprocess.run(command, check=False, capture_output=True, text=True)

    def _assert_structured_cli_failure(self, path: Path) -> None:
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                completed = self._run_cli(path, optimized=optimized)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(completed.stderr, "")
                lines = [line for line in completed.stdout.splitlines() if line.strip()]
                self.assertEqual(len(lines), 1)
                payload = json.loads(lines[0])
                self.assertEqual(payload["error"]["code"], validate.ERROR_CODE)
                self.assertIsInstance(payload["error"]["message"], str)
                self.assertNotIn("Traceback", completed.stdout + completed.stderr)

    def test_checked_in_document_validates(self) -> None:
        self.assertEqual(len(self.cases), len(validate.EXPECTED_CASE_IDS))
        self.assertEqual(tuple(self.cases), validate.EXPECTED_CASE_IDS)

    def test_every_case_matches_the_parser(self) -> None:
        for case in self.document["cases"]:
            with self.subTest(case=case["id"]):
                result = validate.parse_link(case["link"])
                self.assertEqual(result.as_dict(), case["expected"])
                self.assertEqual(result.reason, case["expected"]["reasons"][0] if case["expected"]["reasons"] else "ok")

    def test_valid_web_and_native_forms_preserve_opaque_ids(self) -> None:
        session = "CaseSensitiveOpaque-0001"
        message = "MessageOpaque-0001"
        web = f"{validate.DEFAULT_ORIGIN}/v1/c/{session}/m/{message}"
        native = f"hermternal://open/v1/c/{session}/m/{message}"
        for link, kind in ((web, "web"), (native, "native")):
            with self.subTest(link=link):
                result = validate.parse_link(link)
                self.assertTrue(result.valid)
                self.assertEqual(result.kind, kind)
                self.assertEqual(result.session_id, session)
                self.assertEqual(result.message_id, message)

    def test_same_origin_is_exact_and_not_normalised(self) -> None:
        valid = self.cases["valid-web-session"]["link"]
        for link in (
            valid.replace("synthetic.hermternal.test", "other.hermternal.test"),
            valid.replace("https://", "HTTPS://"),
            valid.replace("synthetic.hermternal.test/", "synthetic.hermternal.test:443/"),
            valid.replace("/v1/", "/base/v1/"),
        ):
            with self.subTest(link=link):
                self.assertFalse(validate.parse_link(link).valid)
        self.assertTrue(validate.is_canonical_origin(validate.DEFAULT_ORIGIN))
        for origin in (
            "https://synthetic.hermternal.test/",
            "http://synthetic.hermternal.test",
            "https://user@synthetic.hermternal.test",
            "https://synthetic.hermternal.test/path",
            "https://synthetic.hermternal.test?x=1",
            "https://synthetic.hermternal.test#x",
        ):
            with self.subTest(origin=origin):
                self.assertFalse(validate.is_canonical_origin(origin))

    def test_empty_and_credential_userinfo_report_authority_before_origin(self) -> None:
        base = "/v1/c/" + validate.SESSION_1
        for prefix in ("https://@synthetic.hermternal.test", "https://:@synthetic.hermternal.test"):
            with self.subTest(prefix=prefix):
                result = validate.parse_link(prefix + base)
                self.assertEqual(result.reasons, ("authority", "origin"))
                self.assertFalse(result.valid)
        for prefix in (
            "https://synthetic-user@synthetic.hermternal.test",
            "https://synthetic-user:synthetic-pass@synthetic.hermternal.test",
        ):
            with self.subTest(prefix=prefix):
                result = validate.parse_link(prefix + base)
                self.assertEqual(result.reasons, ("authority", "origin"))
                self.assertFalse(result.valid)

    def test_all_lexical_rejections_fail_closed(self) -> None:
        base = self.cases["valid-web-session"]["link"]
        controls = {
            "%2F": "percent_escape",
            "\\child": "backslash",
            "\x01": "control",
            "é": "non_ascii",
            "?mode=synthetic": "query",
            "#synthetic": "fragment",
        }
        for suffix, reason in controls.items():
            with self.subTest(reason=reason):
                result = validate.parse_link(base + suffix)
                self.assertFalse(result.valid)
                self.assertEqual(result.reason, reason)
        trailing = validate.parse_link(base + "/")
        self.assertEqual(trailing.reasons, ("trailing_slash",))

    def test_reason_order_is_stable_for_multiple_failures(self) -> None:
        link = (
            "https://other.hermternal.test/v1/c/"
            + validate.SESSION_1
            + "%2F?mode=synthetic#anchor"
        )
        result = validate.parse_link(link)
        self.assertEqual(
            result.reasons,
            ("percent_escape", "query", "fragment", "origin"),
        )
        self.assertEqual(
            list(result.reasons),
            sorted(result.reasons, key=validate._REASON_INDEX.__getitem__),
        )

    def test_traversal_and_normalisation_are_not_equivalent_targets(self) -> None:
        traversal = validate.parse_link(
            f"{validate.DEFAULT_ORIGIN}/v1/c/../m/{validate.MESSAGE_1}"
        )
        self.assertEqual(traversal.reasons, ("traversal", "normalization"))
        doubled = validate.parse_link(
            f"{validate.DEFAULT_ORIGIN}/v1//c/{validate.SESSION_1}"
        )
        self.assertEqual(doubled.reasons, ("path", "normalization"))
        self.assertIsNone(traversal.session_id)
        self.assertIsNone(doubled.session_id)

    def test_optional_message_anchor_is_exact(self) -> None:
        session = validate.SESSION_1
        valid = validate.parse_link(f"{validate.DEFAULT_ORIGIN}/v1/c/{session}")
        anchored = validate.parse_link(
            f"{validate.DEFAULT_ORIGIN}/v1/c/{session}/m/{validate.MESSAGE_1}"
        )
        for result in (valid, anchored):
            self.assertTrue(result.valid)
        self.assertIsNone(valid.message_id)
        self.assertEqual(anchored.message_id, validate.MESSAGE_1)
        self.assertFalse(
            validate.parse_link(f"{validate.DEFAULT_ORIGIN}/v1/c/{session}/m").valid
        )

    def test_percent_escape_is_not_decoded(self) -> None:
        result = validate.parse_link(
            f"{validate.DEFAULT_ORIGIN}/v1/c/{validate.SESSION_1}%2F"
        )
        self.assertEqual(result.reason, "percent_escape")
        self.assertIsNone(result.session_id)

    def test_diagnostic_redaction_is_non_reversible(self) -> None:
        for case in self.document["cases"]:
            diagnostic = validate.redact_link(case["link"])
            self.assertEqual(diagnostic, case["expected"]["diagnostic"])
            self.assertNotIn(case["link"], diagnostic)
            for identifier in (validate.SESSION_1, validate.SESSION_2, validate.MESSAGE_1, validate.MESSAGE_2):
                self.assertNotIn(identifier, diagnostic)
        self.assertEqual(
            validate.redact_link("not a URI"),
            "deep-link[unknown;session=absent;message=absent]",
        )

    def test_ellipsis_id_is_rejected_as_an_abbreviation(self) -> None:
        result = validate.parse_link(self.cases["ellipsis-session-id"]["link"])
        self.assertEqual(result.reasons, ("full_id",))
        self.assertFalse(result.valid)
        self.assertIsNone(result.session_id)

    def test_malformed_kind_values_fail_with_contract_error(self) -> None:
        for malformed in ([], {}, 1, True):
            with self.subTest(malformed=malformed):
                mutated = copy.deepcopy(self.document)
                mutated["cases"][0]["expected"]["kind"] = malformed
                with self.assertRaises(validate.ContractError):
                    validate.validate_document(mutated)

    def test_strict_recursive_schema_rejects_extra_and_bool_values(self) -> None:
        mutations = []

        extra_root = copy.deepcopy(self.document)
        extra_root["unexpected"] = "synthetic"
        mutations.append(extra_root)

        extra_nested = copy.deepcopy(self.document)
        extra_nested["cases"][0]["expected"]["unexpected"] = True
        mutations.append(extra_nested)

        bool_as_length = copy.deepcopy(self.document)
        bool_as_length["id_policy"]["minimum_length"] = True
        mutations.append(bool_as_length)

        for mutated in mutations:
            with self.subTest(mutated=mutated):
                with self.assertRaises(validate.ContractError):
                    validate.validate_document(mutated)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"schema": "one", "schema": "two"}', encoding="utf-8")
            with self.assertRaises(validate.ContractError):
                validate.load_document(path)

    def test_non_finite_json_hook_rejects_nan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "non-finite.json"
            path.write_text('{"schema": NaN}', encoding="utf-8")
            with self.assertRaises(validate.ContractError):
                validate.load_document(path)

    def test_cli_returns_one_structured_error_for_duplicate_and_non_finite_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            duplicate = Path(directory) / "duplicate.json"
            duplicate.write_text('{"schema": "one", "schema": "two"}', encoding="utf-8")
            non_finite = Path(directory) / "non-finite.json"
            non_finite.write_text('{"schema": NaN}', encoding="utf-8")
            for path in (duplicate, non_finite):
                with self.subTest(path=path.name):
                    self._assert_structured_cli_failure(path)

    def test_cli_returns_one_structured_error_for_malformed_roots_and_substitutions(self) -> None:
        malformed_documents = (
            None,
            [],
            {"schema": []},
            {"schema": validate.SCHEMA, "cases": None},
        )
        with tempfile.TemporaryDirectory() as directory:
            for index, document in enumerate(malformed_documents):
                path = Path(directory) / f"malformed-{index}.json"
                path.write_text(json.dumps(document), encoding="utf-8")
                with self.subTest(path=path.name):
                    self._assert_structured_cli_failure(path)

    def test_mutation_inventory_is_executable(self) -> None:
        self.assertEqual(validate.validate_mutations(self.document), 15)

    def test_compile_and_optimised_cli_keep_validation_active(self) -> None:
        py_compile.compile(str(FIXTURE_DIR / "validate.py"), doraise=True)
        command = [sys.executable, "-O", str(FIXTURE_DIR / "validate.py")]
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("deep_link_validation=ok", completed.stdout)

    def test_invalid_input_type_fails_closed(self) -> None:
        result = validate.parse_link(None)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "type")
        self.assertEqual(result.diagnostic, "deep-link[unknown;session=absent;message=absent]")


if __name__ == "__main__":
    unittest.main()
