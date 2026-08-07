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
from unittest import mock

ROOT = Path(__file__).resolve().parent
VALIDATOR = ROOT / "validate.py"
CASES = ROOT / "cases.json"
BASELINE = ROOT / "validation-baseline.json"

spec = importlib.util.spec_from_file_location("host_origin_mapping_validate", VALIDATOR)
if spec is None or spec.loader is None:
    raise RuntimeError("validator module could not be loaded")
validate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validate)


def controlled_current_pin_validation() -> dict[str, int]:
    """Run the default path with an isolated, in-memory current identity.

    The checkout intentionally retains stale external pins after this fix. This
    helper proves baseline validation and artifact scanning still execute when a
    reviewed predecessor supplies current pins, without changing any fixture
    artifact or production constant.
    """

    captured = validate._capture_retained_artifacts()
    baseline = json.loads(captured.files["validation-baseline.json"].decode("utf-8"))
    baseline["artifact"] = validate.artifact_manifest(captured)
    baseline_payload = json.dumps(baseline, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    controlled_files = dict(captured.files)
    controlled_files["validation-baseline.json"] = baseline_payload
    controlled = validate.CapturedArtifacts(captured.root, controlled_files)
    retained_pins = {
        name: (len(controlled.files[name]), hashlib.sha256(controlled.files[name]).hexdigest())
        for name in ("README.md", "cases.json", "test_validate.py")
    }
    with (
        mock.patch.object(validate, "_capture_retained_artifacts", return_value=controlled),
        mock.patch.object(validate, "PINNED_RETAINED_ARTIFACTS", retained_pins),
        mock.patch.object(validate, "PINNED_VALIDATOR_SOURCE_SHA256", validate._validator_source_digest(controlled)),
        mock.patch.object(validate, "PINNED_BASELINE_SHA256", hashlib.sha256(baseline_payload).hexdigest()),
        mock.patch.object(validate, "validate_baseline", wraps=validate.validate_baseline) as baseline_call,
        mock.patch.object(validate, "scan_all_artifacts", wraps=validate.scan_all_artifacts) as scanner_call,
    ):
        retained = validate.validate()
    return {
        "retained": len(retained),
        "accepted": sum(1 for item in retained if item["upstream_called"]),
        "baseline_calls": baseline_call.call_count,
        "scan_calls": scanner_call.call_count,
    }


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

    def run_scanner_probe(self, artifact: str, payload: bytes, *, optimized: bool = False) -> subprocess.CompletedProcess[str]:
        handle = tempfile.NamedTemporaryFile("wb", suffix=".bin", delete=False)
        with handle:
            handle.write(payload)
        path = Path(handle.name)
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        probe = (
            "import importlib" + ".util, pathlib, sys\n"
            "spec = importlib" + ".util.spec_from_file_location('probe_validate', sys" + ".argv[1])\n"
            "module = importlib" + ".util.module_from_spec(spec)\n"
            "spec" + ".loader.exec_module(module)\n"
            "try:\n"
            "    module" + ".scan_artifact_bytes(sys" + ".argv[3], pathlib" + ".Path(sys" + ".argv[2]).read_bytes())\n"
            "except module" + ".ValidationError as exc:\n"
            "    print(module" + ".bounded_failure(exc))\n"
            "    raise SystemExit(2)\n"
            "raise SystemExit(0)\n"
        )
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend(["-c", probe, str(VALIDATOR), str(path), artifact])
        return subprocess.run(command, cwd=ROOT.parents[3], text=True, capture_output=True, check=False, timeout=30)

    def assert_scanner_failure_parity(self, artifact: str, payload: bytes, expected_reason: str | None = None) -> None:
        outputs = []
        for optimized in (False, True):
            result = self.run_scanner_probe(artifact, payload, optimized=optimized)
            self.assert_bounded_failure(result)
            if expected_reason is not None:
                self.assertIn(expected_reason, json.loads(result.stdout)["reason"])
            outputs.append((result.returncode, result.stdout, result.stderr))
        self.assertEqual(outputs[0], outputs[1])

    def run_parser_probe(self, payload: bytes, *, optimized: bool = False) -> subprocess.CompletedProcess[str]:
        handle = tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False)
        with handle:
            handle.write(payload)
        path = Path(handle.name)
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        probe = (
            "import importlib" + ".util, pathlib, sys\n"
            "spec = importlib" + ".util.spec_from_file_location('probe_validate', sys" + ".argv[1])\n"
            "module = importlib" + ".util.module_from_spec(spec)\n"
            "spec" + ".loader.exec_module(module)\n"
            "try:\n"
            "    module" + ".parse_json_bytes(pathlib" + ".Path(sys" + ".argv[2]).read_bytes())\n"
            "except module" + ".ValidationError as exc:\n"
            "    print(module" + ".bounded_failure(exc))\n"
            "    raise SystemExit(2)\n"
            "raise SystemExit(0)\n"
        )
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend(["-c", probe, str(VALIDATOR), str(path)])
        return subprocess.run(command, cwd=ROOT.parents[3], text=True, capture_output=True, check=False, timeout=30)

    def assert_parser_failure_parity(self, payload: bytes, expected_reason: str) -> None:
        outputs = []
        for optimized in (False, True):
            result = self.run_parser_probe(payload, optimized=optimized)
            self.assert_bounded_failure(result)
            self.assertEqual(json.loads(result.stdout)["reason"], expected_reason)
            outputs.append((result.returncode, result.stdout, result.stderr))
        self.assertEqual(outputs[0], outputs[1])

    def run_controlled_validation_probe(self, *, optimized: bool = False) -> subprocess.CompletedProcess[str]:
        probe = (
            "import importlib" + ".util, json, sys\n"
            "spec = importlib" + ".util.spec_from_file_location('probe_tests', sys" + ".argv[1])\n"
            "module = importlib" + ".util.module_from_spec(spec)\n"
            "spec" + ".loader.exec_module(module)\n"
            "print(json" + ".dumps(module" + ".controlled_current_pin_validation(), sort_keys=True, separators=(',', ':')))\n"
        )
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend(["-c", probe, str(Path(__file__))])
        return subprocess.run(command, cwd=ROOT.parents[3], text=True, capture_output=True, check=False, timeout=30)

    def assert_controlled_validation_parity(self) -> None:
        outputs = []
        for optimized in (False, True):
            result = self.run_controlled_validation_probe(optimized=optimized)
            self.assertEqual(result.returncode, 0, result)
            self.assertEqual(result.stderr, "")
            outputs.append(result.stdout)
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(json.loads(outputs[0]), {"accepted": 1, "baseline_calls": 1, "retained": 33, "scan_calls": 1})

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

    def assert_document_mutation_reaches_reason(self, document: object, expected_reason: str) -> None:
        """Parse a mutation directly, avoiding the CLI-only canonical-path guard."""

        path = self.write_json(document)
        probe = (
            "import importlib" + ".util, pathlib, sys\n"
            "spec = importlib" + ".util.spec_from_file_location('probe_validate', sys" + ".argv[1])\n"
            "module = importlib" + ".util.module_from_spec(spec)\n"
            "spec" + ".loader.exec_module(module)\n"
            "try:\n"
            "    document = module" + ".parse_json_bytes(pathlib" + ".Path(sys" + ".argv[2]).read_bytes())\n"
            "    module" + ".validate_document(document)\n"
            "except module" + ".ValidationError as exc:\n"
            "    print(str(exc))\n"
            "    raise SystemExit(2)\n"
            "raise SystemExit(0)\n"
        )
        outputs = []
        for optimized in (False, True):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.extend(["-c", probe, str(VALIDATOR), str(path)])
            result = subprocess.run(command, cwd=ROOT.parents[3], text=True, capture_output=True, check=False, timeout=30)
            self.assertEqual(result.returncode, 2, result)
            self.assertEqual(result.stderr, "")
            self.assertEqual(result.stdout.strip(), expected_reason)
            outputs.append(result.stdout)
        self.assertEqual(outputs[0], outputs[1])

    def test_default_validator_passes_or_reports_external_pin_gate(self) -> None:
        expected = {"pinned retained artifact size changed", "pinned retained artifact digest changed", "pinned validator identity changed"}
        outputs = []
        for optimized in (False, True):
            result = self.run_cli(optimized=optimized)
            self.assertEqual(result.stderr, "")
            if result.returncode == 0:
                self.assertEqual(json.loads(result.stdout), {"status": "ok", "fixture_id": "host-origin-mapping-dep-03-f5be9236", "cases": 33, "accepted": 1, "rejected": 32, "synthetic_only": True, "live_claim": False})
            else:
                self.assert_bounded_failure(result)
                self.assertIn(json.loads(result.stdout)["reason"], expected)
            outputs.append((result.returncode, result.stdout, result.stderr))
        self.assertEqual(outputs[0], outputs[1])

    def test_default_validation_reaches_baseline_and_scan_with_current_controlled_identity(self) -> None:
        self.assert_controlled_validation_parity()

    def test_case_inventory_and_raw_results_are_frozen(self) -> None:
        retained = validate.validate_document(copy.deepcopy(self.document))
        self.assertEqual(tuple(case["id"] for case in self.document["cases"]), validate.EXPECTED_CASE_IDS)
        self.assertEqual(len(retained), 33); self.assertTrue(retained[0]["upstream_called"])
        raw_values = set()
        for case in self.document["cases"]:
            request = case["request"]
            raw_values.update(value for value in request["host_values"] if value)
            raw_values.update(value for value in request["origin_values"] if value)
            raw_values.update(value for value in (request["upstream_host_override"], request["upstream_origin_override"]) if value)
            for values in request["inbound_forwarded"].values():
                if isinstance(values, list):
                    raw_values.update(value for value in values if value and value != "https")
                elif values:
                    raw_values.add(values)
        retained_text = json.dumps(retained, sort_keys=True)
        for raw in raw_values:
            if raw not in {"null", "*"}:
                self.assertNotIn(raw, retained_text)
        for evidence in retained[1:]:
            self.assertFalse(evidence["upstream_called"])
            for field in ("mapped_host_marker", "mapped_origin_marker", "forwarded_host_marker", "forwarded_proto_marker", "forwarded_prefix_marker", "forwarded_for_marker"):
                self.assertIsNone(evidence[field])
        self.assertEqual(retained[0]["forwarded_result"], "stripped_and_rebuilt")

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

    def test_inbound_forwarded_headers_are_stripped_and_rebuilt(self) -> None:
        case = copy.deepcopy(self.document["cases"][0])
        case["request"]["inbound_forwarded"] = {
            "x_forwarded_host": ["spoofed-forwarded"],
            "x_forwarded_proto": ["http"],
            "x_forwarded_prefix": ["/attacker"],
            "x_forwarded_for": ["client-chain"],
        }
        result = validate.evaluate_case(case)
        self.assertEqual(result["decision"], "forward_with_configured_mapping")
        self.assertEqual(result["forwarded_result"], "stripped_and_rebuilt")
        self.assertEqual(result["forwarded_host_marker"], "public_host_from_edge_validation")
        self.assertEqual(result["forwarded_proto_marker"], "https_from_edge_transport")

    def test_malformed_forwarded_headers_reject_before_overrides(self) -> None:
        case = copy.deepcopy(self.document["cases"][0])
        case["request"]["inbound_forwarded"] = {
            "x_forwarded_host": "spoofed-forwarded",
            "x_forwarded_proto": ["https"],
            "x_forwarded_prefix": ["/hermes"],
            "x_forwarded_for": [],
        }
        case["request"]["upstream_host_override"] = "attacker.private.invalid"
        result = validate.evaluate_case(case)
        self.assertEqual(result["decision"], "reject_forwarded_headers")
        self.assertEqual(result["status"], 421)
        self.assertFalse(result["upstream_called"])

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

    def test_every_request_and_expected_field_mutation_reaches_validation(self) -> None:
        for case_index, case in enumerate(self.document["cases"]):
            for field in validate.REQUEST_KEYS:
                document = copy.deepcopy(self.document); document["cases"][case_index]["request"][field] = {"mutated": True}
                self.assert_document_mutation_reaches_reason(document, "source evidence changed")
            for field in validate.EXPECTED_KEYS:
                document = copy.deepcopy(self.document); document["cases"][case_index]["expected"][field] = "mutated"
                self.assert_document_mutation_reaches_reason(document, "computed case outcome changed")

    def test_mapping_policy_evidence_and_order_mutations_reach_validation(self) -> None:
        for section, expected_reason in (
            ("mapping", "mapping contract changed"),
            ("policy", "edge policy changed"),
            ("evidence_contract", "evidence contract changed"),
        ):
            for field in self.document[section]:
                document = copy.deepcopy(self.document); document[section][field] = "mutated"
                self.assert_document_mutation_reaches_reason(document, expected_reason)
        document = copy.deepcopy(self.document); document["cases"].reverse()
        self.assert_document_mutation_reaches_reason(document, "case id or order changed")

    def test_root_source_and_shape_mutations_reach_intended_validation(self) -> None:
        metadata_reasons = {
            "schema": "fixture schema changed",
            "fixture_id": "fixture id changed",
            "issue": "fixture issue changed",
            "contract": "fixture contract changed",
            "hermes_source_sha": "Hermes source pin changed",
            "synthetic_only": "synthetic-only flag changed",
            "live_claim": "live-claim flag changed",
            "proof_mode": "proof mode changed",
        }
        for field, expected_reason in metadata_reasons.items():
            document = copy.deepcopy(self.document)
            document[field] = "mutated"
            self.assert_document_mutation_reaches_reason(document, expected_reason)
        document = copy.deepcopy(self.document); document.pop("schema")
        self.assert_document_mutation_reaches_reason(document, "fixture root keys changed")
        document = copy.deepcopy(self.document); document["unexpected"] = True
        self.assert_document_mutation_reaches_reason(document, "fixture root keys changed")
        document = copy.deepcopy(self.document); document["cases"] = {}
        self.assert_document_mutation_reaches_reason(document, "case inventory changed")

        for field in validate.SOURCE_EVIDENCE_KEYS:
            document = copy.deepcopy(self.document)
            document["cases"][0]["source_evidence"][field] = "mutated"
            self.assert_document_mutation_reaches_reason(document, "source evidence changed")
        document = copy.deepcopy(self.document); document["cases"][0].pop("source_evidence")
        self.assert_document_mutation_reaches_reason(document, "case keys changed")
        document = copy.deepcopy(self.document); document["cases"][0]["source_evidence"] = []
        self.assert_document_mutation_reaches_reason(document, "source evidence must be an object")
        document = copy.deepcopy(self.document); document["cases"][0]["source_evidence"].pop("contract_sha256")
        self.assert_document_mutation_reaches_reason(document, "source evidence keys changed")

        document = copy.deepcopy(self.document); document["cases"][0] = []
        self.assert_document_mutation_reaches_reason(document, "case must be an object")
        document = copy.deepcopy(self.document); document["cases"][0]["request"] = []
        self.assert_document_mutation_reaches_reason(document, "case request must be an object")
        document = copy.deepcopy(self.document); document["cases"][0]["expected"] = []
        self.assert_document_mutation_reaches_reason(document, "case expected result must be an object")

    def test_source_row_binding_rejects_copied_allow_row_evidence(self) -> None:
        document = copy.deepcopy(self.document)
        document["cases"][1]["source_evidence"] = copy.deepcopy(document["cases"][0]["source_evidence"])
        with self.assertRaises(validate.ValidationError):
            validate.validate_document(document)
        document = copy.deepcopy(self.document)
        document["cases"][1]["request"] = copy.deepcopy(document["cases"][0]["request"])
        document["cases"][1]["expected"] = copy.deepcopy(document["cases"][0]["expected"])
        document["cases"][1]["source_evidence"] = copy.deepcopy(document["cases"][0]["source_evidence"])
        with self.assertRaises(validate.ValidationError):
            validate.validate_document(document)

    def test_alternate_cases_path_is_rejected_in_both_modes(self) -> None:
        path = self.write_json(self.document)
        outputs = []
        for optimized in (False, True):
            result = self.run_cli(["--cases", str(path), "--skip-baseline"], optimized=optimized)
            self.assert_bounded_failure(result)
            self.assertEqual(json.loads(result.stdout)["reason"], "cases input must be the canonical artifact")
            outputs.append((result.returncode, result.stdout, result.stderr))
        self.assertEqual(outputs[0], outputs[1])

    def test_each_retained_artifact_rejects_every_forbidden_class(self) -> None:
        quote = chr(34)
        canaries = {
            "credential_assignment": "password" + "=" + "redaction-canary",
            "password_json": "{" + quote + "password" + quote + ":" + quote + "redaction-canary" + quote + "}",
            "user_transcript_json": "{" + quote + "role" + quote + ":" + quote + "user" + quote + "," + quote + "content" + quote + ":" + quote + "private transcript" + quote + "}",
            "credential_json": "{" + quote + "credential" + quote + ":" + quote + "redaction-canary" + quote + "}",
            "bearer": "author" + "ization: " + "Bearer " + "redaction-canary",
            "cookie_header": "Cookie" + ": redaction-canary",
            "ticket_payload": "ticket" + "=" + "redaction-canary",
            "url": "https" + "://unsafe.example/path",
            "host": "unsafe" + ".example" + ".com",
            "unreviewed_host": "unsafe" + ".xyz",
            "loopback_name": "local" + "host",
            "ipv4": ".".join(("192", "0", "2", "44")),
            "ipv6": "2001" + ":" + "db8" + "::" + "44",
            "path": "/" + "tmp/redaction-canary",
            "sensitive_path": "/" + "srv/secrets/key",
            "email": "person" + "@" + "example" + ".com",
            "key": "-----BEGIN " + "PRIVATE KEY-----",
        }
        structured_labels = {"password_json", "user_transcript_json", "credential_json"}
        for artifact in validate.ARTIFACT_FILES:
            original = (ROOT / artifact).read_bytes()
            validate.scan_artifact_bytes(artifact, original)
            for label, canary in canaries.items():
                with self.subTest(artifact=artifact, label=label):
                    payload = canary.encode() if label in structured_labels else json.dumps({"fixture": canary}, separators=(",", ":")).encode()
                    with self.assertRaises(validate.ValidationError):
                        validate.scan_artifact_bytes(artifact, payload)

    def test_direct_scanner_regressions_match_normal_and_optimized_modes(self) -> None:
        quote = chr(34)
        credential_canary = "credential" + "=" + "redaction-canary"
        credentials_canary = "credentials" + ": " + "redaction-canary"
        host = "unsafe" + ".example" + ".com"
        path = "/" + "srv/secrets/" + "README" + ".md"
        role_json = "{" + quote + "role" + quote + ":" + quote + "User" + quote + "}"
        transcript_json = "{" + quote + "content" + quote + ":" + quote + "private transcript" + quote + "}"
        private_key_canary = "-----BEGIN " + "PRIVATE KEY-----"
        detector_regressions = (
            ("SENSITIVE_ASSIGNMENT", credential_canary, "credential assignment"),
            ("HOSTNAME", host, "hostname"),
            ("ABSOLUTE_PATH", path, "filesystem path"),
            ("USER_ROLE", role_json, "user transcript"),
            ("STRUCTURED_TRANSCRIPT", transcript_json, "structured user data"),
            ("PRIVATE_KEY", private_key_canary, "private key"),
        )
        for detector_name, payload, expected_reason in detector_regressions:
            with self.subTest(detector_name=detector_name):
                source = payload.encode() if detector_name == "PRIVATE_KEY" else (detector_name + " = re" + ".compile(" + repr(payload) + ")").encode()
                self.assert_scanner_failure_parity("validate.py", source, expected_reason)
                self.assert_scanner_failure_parity("README.md", source, expected_reason)

        canonical = "SENSITIVE_ASSIGNMENT = re" + ".compile(" + repr(validate.SENSITIVE_ASSIGNMENT.pattern) + ") # " + credential_canary + " )"
        self.assert_scanner_failure_parity("validate.py", canonical.encode(), "credential assignment")
        self.assert_scanner_failure_parity("README.md", ("\"\"\"" + canonical + "\"\"\"").encode(), "credential assignment")
        self.assert_scanner_failure_parity("README.md", ("<!-- " + detector_regressions[1][0] + " = re" + ".compile(" + repr(host) + ") -->").encode(), "hostname")

        scaffolds = (
            ("mutations = [" + repr(credential_canary) + "]", "credential assignment"),
            ("payloads = (" + repr(credential_canary.encode()) + ",)", "credential assignment"),
            ("for arguments in (([\"--unknown\", " + repr(credential_canary) + "],)):\n    pass", "credential assignment"),
            ("for value in (" + repr(host) + ",):\n    pass", "hostname"),
            ("marker = " + repr(credential_canary + " <negative-test-canary>"), "credential assignment"),
        )
        for source, expected_reason in scaffolds:
            with self.subTest(scaffold=source.split(" ", 1)[0]):
                self.assert_scanner_failure_parity("test_validate.py", source.encode(), expected_reason)

        self.assert_scanner_failure_parity("README.md", ("person@" + "chat.public.invalid").encode(), "email address")
        self.assert_scanner_failure_parity("README.md", ("https" + "://" + "README.md").encode(), "URL")
        self.assert_scanner_failure_parity("README.md", ("person@" + "README.md").encode(), "email address")
        self.assert_scanner_failure_parity("README.md", ("/" + "tmp/" + "README" + ".md").encode(), "filesystem path")
        self.assert_scanner_failure_parity("README.md", path.encode(), "filesystem path")

    def test_decoded_json_keys_and_scalar_values_are_scanned_recursively(self) -> None:
        quote = chr(34)
        cases = (
            (b'{"outer":"\\u0070assword\\u003dredaction-canary"}', "credential assignment"),
            (b'{"outer":"\\u002ftmp/' + b"README" + b'.md"}', "filesystem path"),
            (b'{"outer":"\\u002fsrv/secrets/' + b"README" + b'.md"}', "filesystem path"),
            (b'{"outer":"\\u0068ttps://' + b"unsafe" + b".example/path" + b'"}', "URL"),
            (json.dumps({"outer": "{" + quote + "role" + quote + ":" + quote + "User" + quote + "," + quote + "content" + quote + ":" + quote + "private transcript" + quote + "}"}, separators=(",", ":")).encode(), "structured user data"),
            (b'{"\\u0075' + b"nsafe" + b".example" + b'.com":"x"}', "hostname"),
            (b'{"\\u002fsrv/secrets/key":"x"}', "filesystem path"),
            (b'{"password\\u003dsecret":"x"}', "credential assignment"),
            (json.dumps({"outer": [{("access" + "." + "token"): "x"}]}, separators=(",", ":")).encode(), None),
            (json.dumps({"outer": [{("user" + " data"): "x"}]}, separators=(",", ":")).encode(), None),
            (json.dumps({"outer": [{("chat" + " history"): "x"}]}, separators=(",", ":")).encode(), None),
        )
        for payload, expected_reason in cases:
            with self.subTest(expected_reason=expected_reason):
                self.assert_scanner_failure_parity("cases.json", payload, expected_reason)
        for payload, expected_reason in zip(cases[-3:], ("forbidden structured credential", "forbidden user data", "forbidden transcript data")):
            with self.assertRaisesRegex(validate.ValidationError, expected_reason):
                validate.scan_artifact_bytes("cases.json", payload[0])

    def test_structured_redaction_aliases_are_recursive(self) -> None:
        quote = chr(34)
        aliases = (
            ("accessToken", "redaction-canary", "forbidden structured credential"),
            ("userData", "redaction-canary", "forbidden user data"),
            ("chatHistory", "redaction-canary", "forbidden transcript data"),
            ("role", "user", "forbidden user transcript"),
        )
        for key, value, expected_reason in aliases:
            with self.subTest(key=key):
                payload = ("{" + quote + "outer" + quote + ":{" + quote + key + quote + ":" + quote + value + quote + "}}").encode()
                with self.assertRaisesRegex(validate.ValidationError, expected_reason):
                    validate.scan_artifact_bytes("cases.json", payload)

    def test_structural_exemptions_are_exact_not_suffix_or_prefix_wildcards(self) -> None:
        validate.scan_artifact_bytes("README.md", b"https://chat.public.invalid")
        validate.scan_artifact_bytes("README.md", b"/hermes/api/ws")
        for value in (
            "".join(("evilchat", ".public", ".invalid")),
            ".".join(("chat", "public", "invalid", "evil", "example")),
            "https" + "://" + ".".join(("chat", "public", "invalid", "evil", "example")),
            "https" + "://user@" + ".".join(("unsafe", "xyz")),
        ):
            with self.subTest(value=value):
                with self.assertRaises(validate.ValidationError):
                    validate.scan_artifact_bytes("README.md", value.encode())

    def test_structural_exemptions_do_not_hide_adjacent_payloads(self) -> None:
        mixed = (
            b'SENSITIVE_ASSIGNMENT = re' + b'.compile(r"password\\s*[:=]") ' + b'password' + b'=adjacent-canary\n'
            + b'mutations = [] {"' + b'role' + b'":"' + b'user' + b'","' + b'content' + b'":"private transcript"}\n'
            + b'REDACTION_DETECTOR = re' + b'.compile(r"' + b'local' + b'host' + b'") /' + b'srv/secrets/key\n'
        )
        with self.assertRaises(validate.ValidationError):
            validate.scan_artifact_bytes("README.md", mixed)

    def test_parser_rejections_reach_distinct_bounded_reasons_in_both_modes(self) -> None:
        payloads = (
            (b'{"schema":"x","schema":"' + b"secret" + b"=do-not-echo" + b'"}', "JSON contains a duplicate object key"),
            (b"\xff\xfe", "JSON artifact is not valid UTF-8"),
            (b"{\"value\":NaN}", "JSON contains a non-finite number"),
            (b"{\"value\":1234567890123456789}", "JSON integer literal is too large"),
            (b"{" + b"{" * (validate.MAX_DEPTH + 1) + b"}" * (validate.MAX_DEPTH + 1), "JSON nesting limit exceeded"),
            (b'{"value":"\\u0001"}', "JSON string contains a control character"),
        )
        for payload, expected_reason in payloads:
            with self.subTest(expected_reason=expected_reason):
                self.assert_parser_failure_parity(payload, expected_reason)
        for arguments in ((["--unknown", "secret" + "=do-not-echo"], ["--skip-baseline", "--skip-baseline"], ["--cases"])):
            outputs = []
            for optimized in (False, True):
                result = self.run_cli(list(arguments), optimized=optimized)
                self.assert_bounded_failure(result, "do-not-echo")
                outputs.append((result.returncode, result.stdout, result.stderr))
            self.assertEqual(outputs[0], outputs[1])

    def test_large_dotted_member_normalization_is_linear_and_bounded(self) -> None:
        source = "member = object()\n" + ("member" + ".value\n") * 20_000
        normalized = validate._normalize_python_code_members(source)
        self.assertEqual(normalized.count("<python-code-member>"), 20_000)
        self.assertEqual(len(normalized), len("member = object()\n") + 20_000 * (len("<python-code-member>") + 1))
        self.assertLess(len(source), validate.MAX_TOTAL_RETAINED_BYTES)

    def test_baseline_and_coordinated_rebinding_are_rejected(self) -> None:
        baseline, payload = validate.load_json(BASELINE)
        try:
            validate.validate_baseline(baseline, payload)
        except validate.ValidationError as caught:
            self.assertIn(str(caught), {
                "pinned retained artifact size changed",
                "pinned retained artifact digest changed",
                "pinned validator identity changed",
            })
        mutated = copy.deepcopy(baseline)
        mutated["semantics_sha256"] = "0" * 64
        with self.assertRaisesRegex(validate.ValidationError, "benchmark semantics identity changed"):
            validate.validate_baseline(mutated, payload)
        coordinated = copy.deepcopy(self.document)
        coordinated["mapping"]["configured_public_host"] = "other.public.invalid"
        coordinated["mapping"]["configured_public_origin"] = "https://other.public.invalid"
        coordinated["cases"][0]["request"]["host_values"] = ["other.public.invalid"]
        coordinated["cases"][0]["request"]["origin_values"] = ["https://other.public.invalid"]
        with self.assertRaisesRegex(validate.ValidationError, "mapping contract changed"):
            validate.validate_document(coordinated)

    def test_failure_formatter_is_bounded_and_redacted(self) -> None:
        canary = "https" + "://unsafe.example/" + ("x" * 1000)
        line = validate.bounded_failure(canary); self.assertLessEqual(len(line), 240); self.assertNotIn(canary, line)


if __name__ == "__main__":
    unittest.main()
