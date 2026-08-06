"""Tests for the synthetic image attachment lifecycle fixture."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


FIXTURE_DIR = Path(__file__).resolve().parent
VALIDATE_PATH = FIXTURE_DIR / "validate.py"
CASES_PATH = FIXTURE_DIR / "cases.json"
BASELINE_PATH = FIXTURE_DIR / "baseline.json"
SPEC = importlib.util.spec_from_file_location("image_attachment_lifecycle_validate", VALIDATE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load lifecycle validator")
VALIDATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VALIDATOR
SPEC.loader.exec_module(VALIDATOR)


class ImageAttachmentLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = VALIDATOR.load_json(CASES_PATH)
        cls.baseline = VALIDATOR.load_json(BASELINE_PATH)

    def assertContractFailure(self, callback, code: str | None = None) -> None:
        with self.assertRaises(VALIDATOR.ContractError) as context:
            callback()
        if code is not None:
            self.assertEqual(context.exception.code, code)
        self.assertNotIn("data:", str(context.exception))
        self.assertNotIn("/", str(context.exception))

    def test_canonical_document_and_baseline(self) -> None:
        VALIDATOR.validate_document(self.document)
        VALIDATOR.validate_baseline(self.baseline)
        self.assertEqual(len(self.document["cases"]), 16)
        self.assertEqual(self.baseline["threshold"], None)

    def test_case_matrix_covers_requested_lifecycle(self) -> None:
        ids = tuple(case["id"] for case in self.document["cases"])
        self.assertEqual(ids, VALIDATOR.EXPECTED_CASE_IDS)
        expected_decisions = {
            "empty-selection": "no_attachment",
            "local-preprocess-metadata-strip": "ready",
            "progress-uploading": "pending",
            "cancel-before-upload": "cancelled",
            "cancel-after-upload-start": "cancelled",
            "safe-retry-after-state-read": "accepted_after_retry",
            "success-transcript-reference": "accepted",
            "declaration-content-mismatch": "rejected",
            "malformed-base64": "rejected",
            "malformed-data-url": "rejected",
            "unsupported-format": "rejected",
            "oversized-image": "rejected",
            "network-interruption-before-upload": "interrupted",
            "network-interruption-after-upload": "interrupted",
            "uncertain-completion-no-duplicate": "unknown",
            "incompatible-contract": "blocked",
        }
        self.assertEqual({case["id"]: case["expected"]["decision"] for case in self.document["cases"]}, expected_decisions)

    def test_c13_policy_reference_and_redaction_contract(self) -> None:
        self.assertEqual(self.document["policy_reference"], VALIDATOR.C13_POLICY_REFERENCE)
        self.assertEqual(self.document["limits"]["max_bytes"], 25 * 1024 * 1024)
        self.assertTrue(VALIDATOR._format_agrees("gif", "gif87a"))
        self.assertTrue(VALIDATOR._format_agrees("gif", "gif89a"))
        self.assertFalse(VALIDATOR._format_agrees("gif", "png"))
        self.assertEqual(
            {case["input"]["declared_format"] for case in self.document["cases"] if case["input"]["declared_format"] is not None},
            {"png", "jpeg", "gif", "webp", "bmp", "svg"},
        )
        self.assertTrue(all(value is False for value in self.document["redaction"].values()))
        serialized = CASES_PATH.read_text(encoding="utf-8")
        for forbidden in ("data:", "file://", "http://", "https://", "Bearer ", "ghp_"):
            self.assertNotIn(forbidden, serialized)

    def test_strict_loader_rejects_duplicate_nested_nonfinite_and_overflow(self) -> None:
        cases = {
            "duplicate": '{"safe": 1, "safe": 2}',
            "nested_duplicate": '{"outer": {"safe": 1, "safe": 2}}',
            "nonfinite": '{"value": NaN}',
            "exponent_overflow": '{"value": 1e9999}',
            "oversized_integer": '{"value": ' + ("9" * (VALIDATOR.MAX_JSON_INTEGER_DIGITS + 1)) + "}",
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as stream:
                    stream.write(text)
                    stream.flush()
                    self.assertContractFailure(lambda: VALIDATOR.load_json(Path(stream.name)))

    def test_strict_loader_rejects_bounded_input_and_malformed_json(self) -> None:
        deep = '{"a":' * (VALIDATOR.MAX_JSON_DEPTH + 1) + "0" + ("}" * (VALIDATOR.MAX_JSON_DEPTH + 1))
        wide = "{" + ",".join(f'"k{index}":0' for index in range(VALIDATOR.MAX_JSON_OBJECT_KEYS + 1)) + "}"
        long_array = "[" + ",".join("0" for _ in range(VALIDATOR.MAX_JSON_ARRAY_ITEMS + 1)) + "]"
        malformed = '{"safe":'
        root_array = "[1]"
        oversized = "{" + '"value":"' + ("x" * VALIDATOR.MAX_JSON_BYTES) + '"}'
        cases = {
            "deep": deep,
            "wide": wide,
            "long_array": long_array,
            "malformed": malformed,
            "root_array": root_array,
            "oversized": oversized,
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as stream:
                    stream.write(text)
                    stream.flush()
                    self.assertContractFailure(lambda: VALIDATOR.load_json(Path(stream.name)))

    def test_exact_types_and_schema_fail_closed(self) -> None:
        wrong_integer = copy.deepcopy(self.document)
        wrong_integer["cases"][2]["expected"]["upload_attempts"] = 1.0
        self.assertContractFailure(lambda: VALIDATOR.validate_document(wrong_integer), "upload_attempts_type")

        wrong_boolean = copy.deepcopy(self.document)
        wrong_boolean["limits"]["max_bytes"] = True
        self.assertContractFailure(lambda: VALIDATOR.validate_document(wrong_boolean), "max_bytes_type")

        malformed_nested = copy.deepcopy(self.document)
        malformed_nested["cases"][0]["input"] = None
        self.assertContractFailure(lambda: VALIDATOR.validate_document(malformed_nested), "input_shape")

        semantic_drift = copy.deepcopy(self.document)
        semantic_drift["cases"][0]["expected"]["decision"] = "accepted"
        self.assertContractFailure(lambda: VALIDATOR.validate_document(semantic_drift), "semantic_drift")

    def test_duplicate_rejection_happens_before_redaction(self) -> None:
        text = '{"safe": "marker", "safe": "data:image/png;base64,secret"}'
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as stream:
            stream.write(text)
            stream.flush()
            self.assertContractFailure(lambda: VALIDATOR.load_json(Path(stream.name)), "duplicate_key")

    def test_redaction_rejects_raw_material_and_forbidden_keys(self) -> None:
        raw_data_url = copy.deepcopy(self.document)
        raw_data_url["cases"][0]["notes"] = "data:image/png;base64,secret"
        self.assertContractFailure(lambda: VALIDATOR.validate_document(raw_data_url), "raw_data_url")

        raw_path = copy.deepcopy(self.document)
        raw_path["cases"][0]["notes"] = "/private/attachment"
        self.assertContractFailure(lambda: VALIDATOR.validate_document(raw_path), "raw_path")

        raw_base64 = copy.deepcopy(self.document)
        raw_base64["cases"][0]["notes"] = "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        self.assertContractFailure(lambda: VALIDATOR.validate_document(raw_base64), "raw_base64")

        repeated_base64 = copy.deepcopy(self.document)
        repeated_base64["cases"][0]["notes"] = "A" * 24
        self.assertContractFailure(lambda: VALIDATOR.validate_document(repeated_base64), "raw_base64")

        filename = copy.deepcopy(self.document)
        filename["cases"][0]["notes"] = "photo.png"
        self.assertContractFailure(lambda: VALIDATOR.validate_document(filename), "filename_value")

        host = copy.deepcopy(self.document)
        host["cases"][0]["notes"] = "uploads.example.com"
        self.assertContractFailure(lambda: VALIDATOR.validate_document(host), "host_value")

        forbidden_key = copy.deepcopy(self.document)
        forbidden_key["cases"][0]["notes"] = {"filename_value": "synthetic"}
        self.assertContractFailure(lambda: VALIDATOR.validate_document(forbidden_key), "notes")

    def test_progress_and_retry_mutations_fail(self) -> None:
        regressed = copy.deepcopy(self.document)
        regressed["cases"][2]["progress"][2]["percent"] = 40
        regressed["cases"][2]["progress"][3]["percent"] = 20
        self.assertContractFailure(lambda: VALIDATOR.validate_document(regressed), "progress_regressed")

        duplicate_start = copy.deepcopy(self.document)
        duplicate_start["cases"][2]["timeline"].insert(4, "upload_started")
        self.assertContractFailure(lambda: VALIDATOR.validate_document(duplicate_start), "upload_start_count")

        unknown_retry = copy.deepcopy(self.document)
        unknown_retry["cases"][14]["expected"]["retry"] = "safe_after_state_read"
        self.assertContractFailure(lambda: VALIDATOR.validate_document(unknown_retry), "semantic_drift")

    def test_cli_is_controlled_and_capped_for_invalid_input(self) -> None:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as stream:
            stream.write('{"safe": "data:image/png;base64,secret"')
            stream.flush()
            result = subprocess.run(
                [sys.executable, str(VALIDATE_PATH), "--cases", stream.name, "--baseline", str(BASELINE_PATH)],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 2)
        self.assertLessEqual(len(result.stdout), VALIDATOR.MAX_ERROR_OUTPUT_LENGTH)
        self.assertNotIn("secret", result.stdout)
        self.assertNotIn("Traceback", result.stdout + result.stderr)
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed["error"]["synthetic_only"], True)

    def test_direct_cli_normal_and_optimized(self) -> None:
        for mode in ("normal", "optimized"):
            command = [sys.executable]
            if mode == "optimized":
                command.append("-O")
            command.append(str(VALIDATE_PATH))
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            with self.subTest(mode=mode):
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("image_attachment_lifecycle_validation=ok", result.stdout)
                self.assertNotIn("Traceback", result.stdout + result.stderr)

    def test_baseline_has_thirty_samples_per_mode_and_null_threshold(self) -> None:
        self.assertIsNone(self.baseline["threshold"])
        for mode in ("normal", "optimized"):
            record = self.baseline[mode]
            self.assertEqual(record["repetitions"], 30)
            self.assertEqual(len(record["samples_ms"]), 30)
            self.assertEqual(record["distribution"], VALIDATOR._distribution(record["samples_ms"]))


if __name__ == "__main__":
    unittest.main()
