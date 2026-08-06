#!/usr/bin/env python3
"""Security and semantic regressions for the offline C-07A fixture."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import validate  # noqa: E402


class SessionSearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = validate._load_json(validate.CASES_PATH)
        cls.baseline = validate._load_json(validate.BASELINE_PATH)
        cls.cases = {case["id"]: case for case in cls.document["cases"]}

    def run_cli(self, optimized: bool = False, *extra: str) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend([str(ROOT / "validate.py"), *extra])
        return subprocess.run(command, check=False, capture_output=True, text=True)

    def test_checked_in_contract_and_baseline_validate(self) -> None:
        case_count, artifact_bytes = validate.validate_all(self.document, self.baseline)
        self.assertEqual(case_count, 40)
        self.assertGreater(artifact_bytes, 0)
        self.assertEqual(self.baseline["repetitions"], 30)
        self.assertIsNone(self.baseline["threshold"])
        self.assertFalse(self.document["rules"]["privacy"]["local_transcript_mirror"])

    def test_normal_and_optimized_cli_have_exact_parity(self) -> None:
        normal = self.run_cli()
        optimized = self.run_cli(True)
        self.assertEqual(normal.returncode, 0, normal.stdout)
        self.assertEqual(optimized.returncode, 0, optimized.stdout)
        self.assertEqual(normal.stdout, optimized.stdout)
        self.assertEqual(normal.stderr, "")
        self.assertEqual(optimized.stderr, "")
        self.assertIn("cases=40", normal.stdout)

    def test_exact_ids_are_complete_opaque_and_not_normalized(self) -> None:
        exact = self.cases["exact-opaque-id"]["expected"]
        self.assertEqual(exact["results"], [{"session_id": validate.SESSION_A}])
        for case_id in (
            "exact-id-prefix-rejected",
            "exact-id-case-sensitive",
            "exact-id-leading-space-not-trimmed",
        ):
            with self.subTest(case_id=case_id):
                self.assertEqual(self.cases[case_id]["expected"]["decision"], "no_results")

    def test_only_source_backed_empty_normalization_is_applied(self) -> None:
        self.assertEqual(self.cases["empty-query"]["expected"]["decision"], "empty")
        self.assertEqual(self.cases["whitespace-only-query"]["expected"]["decision"], "empty")
        self.assertEqual(
            self.cases["literal-case-sensitive"]["expected"]["results"],
            [{"session_id": validate.SESSION_C}],
        )
        self.assertEqual(
            self.cases["unicode-literal-language-neutral"]["expected"]["results"],
            [{"session_id": validate.SESSION_D}],
        )

    def test_order_and_tie_breaker_are_deterministic(self) -> None:
        ordered = self.cases["newest-first-order"]["expected"]["results"]
        self.assertEqual(ordered, [{"session_id": validate.SESSION_A}, {"session_id": validate.SESSION_B}])
        tied = self.cases["session-id-tie-break"]["expected"]["results"]
        self.assertEqual(tied, [{"session_id": validate.SESSION_B}, {"session_id": validate.SESSION_C}])
        request = self.cases["stable-repeatability"]["request"]
        catalog = self.cases["stable-repeatability"]["catalog"]
        first = json.dumps(validate._execute(request, catalog), sort_keys=True, separators=(",", ":"))
        second = json.dumps(validate._execute(copy.deepcopy(request), list(reversed(list(reversed(catalog))))), sort_keys=True, separators=(",", ":"))
        self.assertEqual(first, second)

    def test_cursor_binds_query_mode_snapshot_and_marker(self) -> None:
        first = self.cases["first-page-with-cursor"]["expected"]
        self.assertEqual(first["results"], [{"session_id": validate.SESSION_A}])
        self.assertIsNotNone(first["next_cursor"])
        second = self.cases["second-page-from-cursor"]["expected"]
        self.assertEqual(second["results"], [{"session_id": validate.SESSION_B}])
        self.assertIsNone(second["next_cursor"])
        self.assertIsNone(self.cases["final-page-clears-cursor"]["expected"]["next_cursor"])
        for case_id in (
            "cursor-query-mismatch",
            "cursor-snapshot-mismatch",
            "cursor-mode-mismatch",
            "cursor-marker-missing",
            "malformed-cursor",
            "oversized-cursor",
        ):
            with self.subTest(case_id=case_id):
                error = self.cases[case_id]["expected"]["error"]
                self.assertEqual(error["code"], "invalid_cursor")

    def test_malformed_and_oversized_requests_fail_with_controlled_codes(self) -> None:
        expected_codes = {
            "zero-page-size": "invalid_page_size",
            "oversized-page-size": "invalid_page_size",
            "boolean-page-size": "invalid_page_size",
            "malformed-query-control": "invalid_query",
            "oversized-query": "invalid_query",
            "invalid-mode": "invalid_query",
        }
        for case_id, code in expected_codes.items():
            with self.subTest(case_id=case_id):
                result = self.cases[case_id]["expected"]
                self.assertEqual(result["error"]["code"], code)
                self.assertEqual(result["results"], [])
                self.assertIsNone(result["next_cursor"])

    def test_deleted_denied_unavailable_and_absent_do_not_disclose(self) -> None:
        shapes = []
        for case_id in (
            "no-result",
            "deleted-session-nondisclosure",
            "unauthorized-session-nondisclosure",
            "unavailable-session-nondisclosure",
        ):
            result = self.cases[case_id]["expected"]
            shapes.append(json.dumps(result, sort_keys=True, separators=(",", ":")))
        self.assertEqual(len(set(shapes)), 1)
        mixed = self.cases["mixed-hidden-visible"]["expected"]
        self.assertEqual(mixed["results"], [{"session_id": validate.SESSION_A}])
        self.assertIsNone(mixed["next_cursor"])

    def test_redacted_metadata_is_not_a_text_oracle(self) -> None:
        self.assertEqual(self.cases["redacted-metadata-not-searchable"]["expected"]["decision"], "no_results")
        exact = self.cases["redacted-exact-id-only"]["expected"]
        self.assertEqual(exact["results"], [{"session_id": validate.SESSION_HIDDEN}])
        self.assertEqual(tuple(exact["results"][0].keys()), ("session_id",))

    def test_interruption_and_retry_are_safe_and_repeatable(self) -> None:
        interrupted = self.cases["interrupted-before-response"]["expected"]
        self.assertEqual(interrupted["error"]["code"], "interrupted")
        self.assertIsNone(interrupted["next_cursor"])
        uncertain = self.cases["unknown-response"]["expected"]
        self.assertEqual(uncertain["error"]["code"], "delivery_uncertain")
        blocked = self.cases["unknown-response-direct-retry-blocked"]["expected"]
        self.assertEqual(blocked["error"]["code"], "retry_blocked")
        reconciled = self.cases["unknown-response-reconciled-retry"]["expected"]
        safe_retry = self.cases["interrupted-safe-retry"]["expected"]
        self.assertEqual(reconciled, safe_retry)

    def test_strict_json_rejects_duplicate_nonfinite_overflow_utf8_and_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payloads = {
                "duplicate": b'{"x":1,"x":2}',
                "nan": b'{"x":NaN}',
                "infinity": b'{"x":Infinity}',
                "overflow": b'{"x":1e9999}',
                "integer": b'{"x":' + b"9" * (validate.MAX_INTEGER_DIGITS + 1) + b"}",
                "utf8": b'{"x":"\xff"}',
                "depth": b"[" * (validate.MAX_DEPTH + 2) + b"0" + b"]" * (validate.MAX_DEPTH + 2),
                "string": b'{"x":"' + b"a" * (validate.MAX_STRING_CHARS + 1) + b'"}',
                "object": ("{" + ",".join(f'\"k{i}\":0' for i in range(validate.MAX_OBJECT_KEYS + 1)) + "}").encode(),
                "array": ("[" + ",".join("0" for _ in range(validate.MAX_ARRAY_ITEMS + 1)) + "]").encode(),
            }
            for name, payload in payloads.items():
                with self.subTest(name=name):
                    path = root / f"{name}.json"
                    path.write_bytes(payload)
                    with self.assertRaises(validate.ContractError):
                        validate._load_json(path)

    def test_iterative_node_bound_does_not_depend_on_assertions(self) -> None:
        root: list[object] = []
        current = root
        for _ in range(validate.MAX_DEPTH + 1):
            child: list[object] = []
            current.append(child)
            current = child
        with self.assertRaises(validate.ContractError):
            validate._check_bounds(root)

    def test_redaction_rejects_sensitive_keys_and_values(self) -> None:
        for value in (
            "Bearer synthetic",
            "https://synthetic.invalid",
            "127.0.0.1:8080",
            "/Users/alice/private",
            "C:\\Users\\alice\\private",
            "password=synthetic",
            "prompt: synthetic",
            "transcript: synthetic",
        ):
            with self.subTest(value=value), self.assertRaises(validate.ContractError):
                validate._validate_redaction({"value": value})
        for key in ("access_token", "ticket", "prompt", "message_content", "transcript"):
            with self.subTest(key=key), self.assertRaises(validate.ContractError):
                validate._validate_redaction({key: "synthetic"})

    def test_real_cli_failure_is_one_fixed_redacted_line_in_both_modes(self) -> None:
        marker = "Bearer synthetic-sensitive-value"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            document = copy.deepcopy(self.document)
            document["source_observations"][0]["observation"] = marker
            path.write_text(json.dumps(document), encoding="utf-8")
            for optimized in (False, True):
                with self.subTest(optimized=optimized):
                    result = self.run_cli(optimized, "--cases", str(path))
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(result.stderr, "")
                    self.assertEqual(len(result.stdout.splitlines()), 1)
                    self.assertNotIn(marker, result.stdout)
                    self.assertNotIn(str(path), result.stdout)
                    self.assertEqual(json.loads(result.stdout), {"error": {"code": "contract", "message": validate.ERROR_MESSAGE}})

    def test_baseline_samples_commands_and_distribution_are_immutable(self) -> None:
        for mutation in ("samples", "distribution", "command", "threshold"):
            forged = copy.deepcopy(self.baseline)
            if mutation == "samples":
                forged["normal"]["samples_ms"] = [1.0] * validate.BASELINE_REPETITIONS
                forged["normal"]["distribution"] = validate._distribution(forged["normal"]["samples_ms"])
            elif mutation == "distribution":
                forged["optimized"]["distribution"]["mean"] += 1.0
            elif mutation == "command":
                forged["normal"]["command"] = "python3 fabricated.py"
            else:
                forged["threshold"] = 1.0
            with self.subTest(mutation=mutation), self.assertRaises(validate.ContractError):
                validate.validate_baseline(forged)

    def test_coordinated_artifact_and_manifest_rebinding_hits_reviewed_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "session-search"
            shutil.copytree(ROOT, copied)
            cases_path = copied / "cases.json"
            document = json.loads(cases_path.read_text(encoding="utf-8"))
            document["cases"][0]["notes"] = "coordinated mutation"
            cases_path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            baseline_path = copied / "validation-baseline.json"
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            for artifact in baseline["artifact_files"]:
                if artifact["path"] == "cases.json":
                    raw = cases_path.read_bytes()
                    artifact["sha256"] = hashlib.sha256(raw).hexdigest()
                    artifact["size_bytes"] = len(raw)
            baseline["artifact_bytes"] = sum(item["size_bytes"] for item in baseline["artifact_files"])
            baseline_path.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
            for optimized in (False, True):
                command = [sys.executable]
                if optimized:
                    command.append("-O")
                command.append(str(copied / "validate.py"))
                result = subprocess.run(command, check=False, capture_output=True, text=True)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(json.loads(result.stdout), {"error": {"code": "contract", "message": validate.ERROR_MESSAGE}})

    def test_dependency_identities_and_source_pin_are_canonical(self) -> None:
        self.assertEqual(self.document["hermes_source_sha"], validate.SOURCE_SHA)
        self.assertEqual(self.document["dependencies"], validate.DEPENDENCIES)
        self.assertEqual(self.document["source_observations"], validate.SOURCE_OBSERVATIONS)
        validate._validate_dependencies()

    def test_dependency_files_reject_digest_rebinding_and_path_escape(self) -> None:
        forged = copy.deepcopy(validate.DEPENDENCIES)
        forged[0]["sha256"] = "0" * 64
        with mock.patch.object(validate, "DEPENDENCIES", forged), self.assertRaises(validate.ContractError):
            validate._validate_dependencies()
        escaped = copy.deepcopy(validate.DEPENDENCIES)
        escaped[0]["path"] = "../outside.json"
        with mock.patch.object(validate, "DEPENDENCIES", escaped), self.assertRaises(validate.ContractError):
            validate._validate_dependencies()


if __name__ == "__main__":
    unittest.main()
