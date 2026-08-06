#!/usr/bin/env python3
"""Regression and mutation tests for the offline DEP-03 raw mapping proof."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
VALIDATOR = ROOT / "validate.py"
CASES = ROOT / "cases.json"
BASELINE = ROOT / "validation-baseline.json"

spec = importlib.util.spec_from_file_location("host_origin_mapping_validate", VALIDATOR)
if spec is None or spec.loader is None:
    raise RuntimeError("validator module could not be loaded")
validate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validate)


class HostOriginMappingProofTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.document = json.loads(CASES.read_text(encoding="utf-8"))

    def run_cli(self, arguments: list[str] | None = None, *, optimized: bool = False) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.append(str(VALIDATOR)); command.extend(arguments or [])
        return subprocess.run(command, cwd=ROOT.parents[3], text=True, capture_output=True, check=False, timeout=30)

    def write_json(self, document: object) -> Path:
        handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False)
        with handle:
            json.dump(document, handle, separators=(",", ":"), ensure_ascii=True)
        path = Path(handle.name); self.addCleanup(lambda: path.unlink(missing_ok=True)); return path

    def assert_bounded_failure(self, result: subprocess.CompletedProcess[str], canary: str | None = None) -> None:
        self.assertEqual(result.returncode, 2, result); self.assertEqual(result.stderr, "")
        lines = result.stdout.splitlines(); self.assertEqual(len(lines), 1); self.assertLessEqual(len(lines[0]), 240)
        self.assertEqual(json.loads(lines[0])["status"], "failure")
        if canary is not None:
            self.assertNotIn(canary, result.stdout)

    def assert_mutation_fails_both_modes(self, document: object, canary: str | None = None) -> None:
        path = self.write_json(document); outputs = []
        for optimized in (False, True):
            result = self.run_cli(["--cases", str(path), "--skip-baseline"], optimized=optimized)
            self.assert_bounded_failure(result, canary); outputs.append(result.stdout)
        self.assertEqual(outputs[0], outputs[1])

    def test_default_validator_passes_in_normal_and_optimized_modes(self) -> None:
        for optimized in (False, True):
            result = self.run_cli(optimized=optimized)
            self.assertEqual(result.returncode, 0, result); self.assertEqual(result.stderr, "")
            self.assertEqual(json.loads(result.stdout), {"status": "ok", "fixture_id": "host-origin-mapping-dep-03-f5be9236", "cases": 32, "accepted": 1, "rejected": 31, "synthetic_only": True, "live_claim": False})

    def test_case_inventory_and_raw_results_are_frozen(self) -> None:
        retained = validate.validate_document(copy.deepcopy(self.document))
        self.assertEqual(tuple(case["id"] for case in self.document["cases"]), validate.EXPECTED_CASE_IDS)
        self.assertEqual(len(retained), 32); self.assertTrue(retained[0]["upstream_called"])
        raw_values = set()
        for case in self.document["cases"]:
            request = case["request"]
            raw_values.update(value for value in request["host_values"] if value)
            raw_values.update(value for value in request["origin_values"] if value)
            raw_values.update(value for value in (request["upstream_host_override"], request["upstream_origin_override"]) if value)
        retained_text = json.dumps(retained, sort_keys=True)
        for raw in raw_values:
            if raw not in {"null", "*"}:
                self.assertNotIn(raw, retained_text)
        for evidence in retained[1:]:
            self.assertFalse(evidence["upstream_called"]); self.assertIsNone(evidence["mapped_host_marker"]); self.assertIsNone(evidence["mapped_origin_marker"])

    def test_exact_scheme_serialization(self) -> None:
        accepted = ("https",)
        rejected = (None, "", "http", "HTTPS", " https", "https ", "https\t", "https\n", 1, True, [])
        for value in accepted:
            self.assertEqual(validate.classify_scheme(value), "accepted_exact")
        for value in rejected:
            self.assertNotEqual(validate.classify_scheme(value), "accepted_exact")

    def test_exact_host_serialization_and_cardinality(self) -> None:
        self.assertEqual(validate.classify_header_values(["chat.public.invalid"], validate.classify_host), "accepted_exact")
        mutations = [[], ["chat.public.invalid", "chat.public.invalid"], ["chat.public.invalid", "other.public.invalid"], "chat.public.invalid", [""], ["chat.public.invalid:443"], ["CHAT.PUBLIC.INVALID"], ["chat.public.invalid."], ["chat.public.invalid,other.public.invalid"], [" chat.public.invalid"], ["chat.public.invalid "], ["user@chat.public.invalid"], ["@chat.public.invalid"], ["https://chat.public.invalid"], ["chat.public.invalid/path"], ["chat.public.invalid?x"], ["chat.public.invalid#x"], ["chat..public.invalid"], ["-chat.public.invalid"], ["chat_.public.invalid"], ["chat.public.invalid:"], ["chat.public.invalid:abc"], ["chat.public.invalid:65536"], ["[::1]"], ["chat%2epublic.invalid"], ["chat\\public.invalid"], ["chat.é.invalid"], ["chat.public.invalid\t"], ["*"]]
        for value in mutations:
            with self.subTest(value=value):
                self.assertNotEqual(validate.classify_header_values(value, validate.classify_host), "accepted_exact")

    def test_exact_origin_serialization_and_cardinality(self) -> None:
        self.assertEqual(validate.classify_header_values(["https://chat.public.invalid"], validate.classify_origin), "accepted_exact")
        mutations = [[], ["https://chat.public.invalid", "https://chat.public.invalid"], ["https://chat.public.invalid", "https://other.public.invalid"], "https://chat.public.invalid", [""], ["null"], ["*"], ["http://chat.public.invalid"], ["HTTPS://chat.public.invalid"], ["https://CHAT.PUBLIC.INVALID"], ["https://chat.public.invalid."], ["https://chat.public.invalid:443"], ["https://chat.public.invalid:0443"], ["https://chat.public.invalid:abc"], ["https://chat.public.invalid:65536"], ["https://chat.public.invalid/"], ["https://chat.public.invalid/path"], ["https://chat.public.invalid?x"], ["https://chat.public.invalid#x"], ["https://user@chat.public.invalid"], ["https://@chat.public.invalid"], ["https://chat..public.invalid"], [" https://chat.public.invalid"], ["https://chat.public.invalid "], ["https://chat.public.invalid,https://other.public.invalid"], ["https://chat%2epublic.invalid"], ["https:\\chat.public.invalid"], ["https://chat.é.invalid"], ["//chat.public.invalid"], ["https://[::1]"]]
        for value in mutations:
            with self.subTest(value=value):
                self.assertNotEqual(validate.classify_header_values(value, validate.classify_origin), "accepted_exact")

    def test_non_null_overrides_always_reject(self) -> None:
        values = ("", "chat.public.invalid", "fixed_private_non_loopback_9119", [], {}, False, 0)
        for field, status in (("upstream_host_override", 421), ("upstream_origin_override", 403)):
            for value in values:
                case = copy.deepcopy(self.document["cases"][0]); case["request"][field] = value
                result = validate.evaluate_case(case)
                self.assertEqual(result["decision"], "reject_upstream_override"); self.assertEqual(result["status"], status); self.assertFalse(result["upstream_called"])

    def test_precedence_is_scheme_then_host_then_origin_then_overrides(self) -> None:
        case = copy.deepcopy(self.document["cases"][0]); case["request"].update({"scheme": "http", "host_values": ["bad host"], "origin_values": ["null"], "upstream_host_override": "x", "upstream_origin_override": "y"})
        self.assertEqual(validate.evaluate_case(case)["decision"], "reject_public_scheme")
        case["request"]["scheme"] = "https"; self.assertEqual(validate.evaluate_case(case)["decision"], "reject_public_host")
        case["request"]["host_values"] = ["chat.public.invalid"]; self.assertEqual(validate.evaluate_case(case)["decision"], "reject_public_origin")
        case["request"]["origin_values"] = ["https://chat.public.invalid"]; self.assertEqual(validate.evaluate_case(case)["status"], 421)
        case["request"]["upstream_host_override"] = None; self.assertEqual(validate.evaluate_case(case)["status"], 403)

    def test_every_request_and_expected_field_mutation_fails_both_modes(self) -> None:
        for case_index, case in enumerate(self.document["cases"]):
            for field in validate.REQUEST_KEYS:
                document = copy.deepcopy(self.document); document["cases"][case_index]["request"][field] = {"mutated": True}
                self.assert_mutation_fails_both_modes(document)
            for field in validate.EXPECTED_KEYS:
                document = copy.deepcopy(self.document); document["cases"][case_index]["expected"][field] = "mutated"
                self.assert_mutation_fails_both_modes(document)

    def test_mapping_policy_evidence_and_semantics_mutations_fail(self) -> None:
        for section in ("mapping", "policy", "evidence_contract"):
            for field in self.document[section]:
                document = copy.deepcopy(self.document); document[section][field] = "mutated"
                self.assert_mutation_fails_both_modes(document)
        document = copy.deepcopy(self.document); document["cases"].reverse(); self.assert_mutation_fails_both_modes(document)

    def test_each_retained_artifact_rejects_every_forbidden_class(self) -> None:
        canaries = {
            "credential": "password" + "=" + "redaction-canary",
            "bearer": "Authorization: " + "Bearer " + "redaction-canary",
            "cookie": "Cookie" + ": redaction-canary",
            "ticket": "ticket" + "=" + "redaction-canary",
            "url": "https" + "://unsafe.example/path",
            "host": "unsafe" + ".example.com",
            "ipv4": ".".join(("192", "0", "2", "44")),
            "ipv6": "2001" + ":db8::44",
            "path": "/" + "tmp/redaction-canary",
            "email": "person" + "@example.com",
            "key": "-----BEGIN " + "PRIVATE KEY-----",
        }
        for artifact in validate.ARTIFACT_FILES:
            original = (ROOT / artifact).read_bytes()
            validate.scan_artifact_bytes(artifact, original)
            for label, canary in canaries.items():
                with self.subTest(artifact=artifact, label=label):
                    with self.assertRaises(validate.ValidationError):
                        validate.scan_artifact_bytes(artifact, original + b"\n" + canary.encode() + b"\n")

    def test_structural_exemptions_are_exact_not_suffix_or_prefix_wildcards(self) -> None:
        for value in ("evilchat.public.invalid", "chat.public.invalid.evil.example", "https://chat.public.invalid.evil.example"):
            with self.subTest(value=value):
                with self.assertRaises(validate.ValidationError):
                    validate.scan_artifact_bytes("README.md", value.encode())

    def test_duplicate_keys_malformed_utf8_and_cli_fail_bounded(self) -> None:
        payloads = (b'{"schema":"x","schema":"secret=do-not-echo"}', b"\xff\xfe")
        for payload in payloads:
            with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as handle:
                handle.write(payload); path = Path(handle.name)
            self.addCleanup(lambda path=path: path.unlink(missing_ok=True))
            for optimized in (False, True):
                self.assert_bounded_failure(self.run_cli(["--cases", str(path), "--skip-baseline"], optimized=optimized), "do-not-echo")
        for arguments in (["--unknown", "secret=do-not-echo"], ["--skip-baseline", "--skip-baseline"], ["--cases"]):
            self.assert_bounded_failure(self.run_cli(list(arguments)), "do-not-echo")

    def test_baseline_and_coordinated_rebinding_are_rejected(self) -> None:
        baseline, payload = validate.load_json(BASELINE); validate.validate_baseline(baseline, payload)
        mutated = copy.deepcopy(baseline); mutated["semantics_sha256"] = "0" * 64
        with self.assertRaises(validate.ValidationError): validate.validate_baseline(mutated, json.dumps(mutated).encode())
        coordinated = copy.deepcopy(self.document); coordinated["mapping"]["configured_public_host"] = "other.public.invalid"; coordinated["mapping"]["configured_public_origin"] = "https://other.public.invalid"; coordinated["cases"][0]["request"]["host_values"] = ["other.public.invalid"]; coordinated["cases"][0]["request"]["origin_values"] = ["https://other.public.invalid"]
        with self.assertRaises(validate.ValidationError): validate.validate_document(coordinated)

    def test_failure_formatter_is_bounded_and_redacted(self) -> None:
        canary = "https" + "://unsafe.example/" + ("x" * 1000)
        line = validate.bounded_failure(canary); self.assertLessEqual(len(line), 240); self.assertNotIn(canary, line)


if __name__ == "__main__":
    unittest.main()
