#!/usr/bin/env python3
"""Regression tests for the offline synthetic DEP-11 denial proof.

Tests use temporary local files only. They never open sockets, invoke firewall
commands, start Hermes or a proxy, use containers, or contact infrastructure.
"""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parent
if str(FIXTURE_DIR) not in sys.path:
    sys.path.insert(0, str(FIXTURE_DIR))

import validate  # noqa: E402


HOST_CANARY = "retained" + ".invalid"
HOSTILE_URL = "https" + "://" + HOST_CANARY
ADDRESS_CANARY = "192" + ".0" + ".2" + ".1"
CREDENTIAL_CANARY = "token" + "=" + "synthetic-secret-canary"


class DirectPortDenialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.reviewed_cases = validate._load_reviewed_network_cases(validate._repo_root(FIXTURE_DIR))
        cls.document = validate.load_json(validate.CASES_PATH)
        validate.validate_redaction(cls.document)
        validate.validate_cases_document(cls.document, cls.reviewed_cases)
        cls.cases = {case["id"]: case for case in cls.document["cases"]}

    def _run_cli(
        self,
        content: bytes,
        *,
        optimized: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(dir=FIXTURE_DIR.parent) as directory:
            root = Path(directory) / "direct-port-denial"
            shutil.copytree(FIXTURE_DIR, root)
            (root / "cases.json").write_bytes(content)
            return self._run_fixture_copy(root, optimized=optimized)

    def _assert_cli_failure(self, content: bytes) -> None:
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                completed = self._run_cli(content, optimized=optimized)
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stderr, "")
                lines = [line for line in completed.stdout.splitlines() if line]
                self.assertEqual(len(lines), 1)
                payload = json.loads(lines[0])
                self.assertFalse(payload["ok"])
                self.assertFalse(payload["compatible"])
                self.assertFalse(payload["live_run"])
                self.assertEqual(payload["error"]["code"], validate.ERROR_CODE)
                self.assertLessEqual(len(payload["error"]["message"]), validate.MAX_ERROR_OUTPUT)
                self.assertNotIn("Traceback", completed.stdout + completed.stderr)
                self.assertNotIn("usage:", completed.stdout.lower())

    def _run_fixture_copy(self, root: Path, *, optimized: bool = False) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.append(str(root / "validate.py"))
        return subprocess.run(command, check=False, capture_output=True, text=True)

    def test_inventory_has_one_exact_allow_and_all_denials_skip_upstream(self) -> None:
        self.assertEqual(tuple(self.cases), validate.EXPECTED_CASE_IDS)
        self.assertEqual(len(self.cases), 16)
        allowed = [case for case in self.document["cases"] if case["expected"]["decision"] == "allow"]
        self.assertEqual([case["id"] for case in allowed], ["configured-proxy-path-allowed"])
        for case in self.document["cases"]:
            with self.subTest(case=case["id"]):
                index = validate.EXPECTED_CASE_IDS.index(case["id"])
                self.assertEqual(
                    validate.evaluate_case(case, index=index, reviewed_cases=self.reviewed_cases),
                    case["expected"],
                )
                self.assertFalse(case["expected"]["retained_hostile_values"])
                self.assertFalse(case["expected"]["live_claim"])
                if case["expected"]["decision"] == "deny":
                    self.assertEqual(case["expected"]["network_action"], "drop_without_upstream")
                    self.assertFalse(case["expected"]["upstream_call"])

    def test_required_direct_and_mismatch_paths_are_denied(self) -> None:
        expected_reasons = {
            "public-direct-path-denied": "public_source_direct_denied",
            "browser-direct-path-denied": "browser_source_direct_denied",
            "client-network-direct-path-denied": "client_network_direct_denied",
            "wrong-source-interface-denied": "source_interface_mismatch",
            "wrong-destination-interface-denied": "destination_interface_mismatch",
            "wrong-destination-port-denied": "destination_port_mismatch",
            "broad-firewall-source-denied": "firewall_source_not_exact",
            "missing-firewall-evidence-denied": "firewall_evidence_missing",
        }
        for case_id, reason in expected_reasons.items():
            with self.subTest(case=case_id):
                expected = self.cases[case_id]["expected"]
                self.assertEqual(expected["decision"], "deny")
                self.assertFalse(expected["upstream_call"])
                self.assertEqual(expected["reason"], reason)

    def test_raw_fields_not_case_labels_drive_evaluation(self) -> None:
        allowed = copy.deepcopy(self.cases["configured-proxy-path-allowed"])
        allowed["id"] = "public-direct-path-denied"
        allowed["kind"] = "malformed_evidence"
        allowed["expected"] = self.cases["public-direct-path-denied"]["expected"]
        derived = validate.evaluate_case(allowed, index=0, reviewed_cases=self.reviewed_cases)
        self.assertEqual(derived["decision"], "allow")
        self.assertEqual(derived["reason"], "configured_proxy_path_exact")

    def test_copying_every_allow_field_into_browser_case_fails_normal_and_optimized(self) -> None:
        document = copy.deepcopy(self.document)
        document["cases"][2]["raw_network"] = copy.deepcopy(document["cases"][0]["raw_network"])
        rebound = document["cases"][2]
        derived = validate.evaluate_case(rebound, index=2, reviewed_cases=self.reviewed_cases)
        self.assertEqual(derived["decision"], "deny")
        self.assertEqual(derived["reason"], "source_evidence_mismatch")
        self.assertFalse(derived["upstream_call"])
        self._assert_cli_failure(json.dumps(document).encode("utf-8"))

    def test_every_allow_field_mutation_fails_closed_in_normal_and_optimized_modes(self) -> None:
        mutations = (
            ("transport", "udp"),
            ("source_identity", "public_gateway"),
            ("source_identity", "browser_runtime"),
            ("source_identity", "client_network"),
            ("source_identity", "unconfigured_proxy"),
            ("source_interface", "public_ingress"),
            ("destination_identity", "public_service_bind"),
            ("destination_identity", "loopback_service_bind"),
            ("destination_interface", "public_service"),
            ("destination_port", 9120),
            ("proxy_hops", []),
            ("proxy_hops", ["configured_proxy", "unconfigured_proxy"]),
            ("source_evidence", None),
            ("source_evidence", copy.deepcopy(self.cases["browser-direct-path-denied"]["raw_network"]["source_evidence"])),
            ("firewall_rule", None),
        )
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                document = copy.deepcopy(self.document)
                document["cases"][0]["raw_network"][field] = value
                self._assert_cli_failure(json.dumps(document).encode("utf-8"))

        for field, value in (
            ("present", False),
            ("action", "deny"),
            ("protocol", "udp"),
            ("source_identity", "any_source"),
            ("source_interface", "any_interface"),
            ("destination_identity", "public_service_bind"),
            ("destination_interface", "public_service"),
            ("destination_port", 9120),
        ):
            with self.subTest(rule_field=field, value=value):
                document = copy.deepcopy(self.document)
                document["cases"][0]["raw_network"]["firewall_rule"][field] = value
                self._assert_cli_failure(json.dumps(document).encode("utf-8"))

    def test_missing_or_unknown_evidence_fails_closed(self) -> None:
        for mutation in ("raw-key", "root-key", "firewall-key"):
            document = copy.deepcopy(self.document)
            if mutation == "raw-key":
                del document["cases"][0]["raw_network"]["source_interface"]
            elif mutation == "root-key":
                del document["boundary"]
            else:
                del document["cases"][0]["raw_network"]["firewall_rule"]["source_identity"]
            with self.subTest(mutation=mutation):
                self._assert_cli_failure(json.dumps(document).encode("utf-8"))

        unknown = copy.deepcopy(self.document)
        unknown["cases"][0]["raw_network"]["source_identity"] = "attacker_selected_source"
        self._assert_cli_failure(json.dumps(unknown).encode("utf-8"))

    def test_exact_types_unknown_keys_and_order_fail_closed(self) -> None:
        for field, value in (
            ("destination_port", True),
            ("proxy_hops", "configured_proxy"),
            ("firewall_rule", False),
        ):
            document = copy.deepcopy(self.document)
            document["cases"][0]["raw_network"][field] = value
            with self.subTest(field=field):
                self._assert_cli_failure(json.dumps(document).encode("utf-8"))

        upstream_integer = copy.deepcopy(self.document)
        upstream_integer["cases"][0]["expected"]["upstream_call"] = 1
        self._assert_cli_failure(json.dumps(upstream_integer).encode("utf-8"))

        unknown_key = copy.deepcopy(self.document)
        unknown_key["cases"][0]["raw_network"]["trusted_classification"] = "allow"
        self._assert_cli_failure(json.dumps(unknown_key).encode("utf-8"))

        reordered = copy.deepcopy(self.document)
        raw = reordered["cases"][0]["raw_network"]
        reordered["cases"][0]["raw_network"] = {key: raw[key] for key in reversed(tuple(raw.keys()))}
        self._assert_cli_failure(json.dumps(reordered).encode("utf-8"))

    def test_duplicate_nonfinite_overflow_and_all_resource_bounds_fail_closed(self) -> None:
        self._assert_cli_failure(b'{"schema":"one","schema":"two"}')
        self._assert_cli_failure(b'{"value":NaN}')
        self._assert_cli_failure(b'{"value":Infinity}')
        self._assert_cli_failure(b'{"value":1e9999}')
        oversized_integer = b'{"value":' + b"9" * (validate.MAX_JSON_INTEGER_DIGITS + 1) + b"}"
        self._assert_cli_failure(oversized_integer)
        nested = b"[" * (validate.MAX_JSON_DEPTH + 1) + b"]" * (validate.MAX_JSON_DEPTH + 1)
        self._assert_cli_failure(nested)
        keys = b"{" + b",".join(f'"k{index}":0'.encode() for index in range(validate.MAX_OBJECT_KEYS + 1)) + b"}"
        self._assert_cli_failure(keys)
        items = b"[" + b",".join(b"0" for _ in range(validate.MAX_ARRAY_LENGTH + 1)) + b"]"
        self._assert_cli_failure(items)
        long_string = b'{"value":"' + b"x" * (validate.MAX_STRING_LENGTH + 1) + b'"}'
        self._assert_cli_failure(long_string)
        oversized_bytes = b" " * (validate.MAX_JSON_BYTES + 1)
        self._assert_cli_failure(oversized_bytes)
        node_heavy = [[0] * validate.MAX_ARRAY_LENGTH for _ in range(validate.MAX_JSON_NODES // validate.MAX_ARRAY_LENGTH + 1)]
        self._assert_cli_failure(json.dumps(node_heavy).encode("utf-8"))
        self._assert_cli_failure(b'"control\\u0000value"')
        self._assert_cli_failure(b"\xff")

    def test_retained_reader_rejects_oversize_symlink_and_special_file_before_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oversized = root / "oversized"
            oversized.write_bytes(b"x" * 17)
            with self.assertRaises(validate.ValidationError):
                validate._read_artifact(root, "oversized", limit=16)

            target = root / "target"
            target.write_bytes(b"safe")
            (root / "link").symlink_to(target)
            with self.assertRaises(validate.ValidationError):
                validate._read_artifact(root, "link", limit=16)

            fifo = root / "fifo"
            try:
                import os

                os.mkfifo(fifo)
            except (AttributeError, OSError):
                self.skipTest("FIFO creation is unavailable")
            with self.assertRaises(validate.ValidationError):
                validate._read_artifact(root, "fifo", limit=16)

            device = Path("/dev/null")
            if device.exists():
                with self.assertRaises(validate.ValidationError):
                    validate._read_artifact(device.parent, device.name, limit=16)

            raced = root / "raced"
            raced.write_bytes(b"safe")

            def replace_with_symlink(path: Path) -> None:
                path.unlink()
                path.symlink_to(target)

            with self.assertRaises(validate.ValidationError):
                validate._read_artifact(root, "raced", limit=16, _before_open=replace_with_symlink)

    def test_regular_file_replaced_with_fifo_before_open_never_blocks_in_either_mode(self) -> None:
        script = """
import os
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import validate
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    path = root / "artifact"
    path.write_bytes(b"safe")
    def replace_with_fifo(target):
        target.unlink()
        os.mkfifo(target)
    try:
        validate._read_artifact(root, "artifact", limit=16, _before_open=replace_with_fifo)
    except validate.ValidationError as exc:
        print(validate.compact_error(exc))
    else:
        raise SystemExit("raced FIFO was accepted")
"""
        for optimized in (False, True):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.extend(["-c", script, str(FIXTURE_DIR)])
            with self.subTest(optimized=optimized):
                completed = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                self.assertEqual(completed.stderr, "")
                self.assertIn("regular file", completed.stdout)

    def test_iterative_walks_handle_bounded_deep_values(self) -> None:
        value: object = "safe_marker"
        for _ in range(validate.MAX_JSON_DEPTH):
            value = [value]
        self.assertLessEqual(validate.validate_json_tree(value), validate.MAX_JSON_NODES)
        validate.validate_redaction(value)
        validate.strict_equal(value, copy.deepcopy(value), "deep value")

    def test_controlled_errors_do_not_retain_hostile_input(self) -> None:
        hostile = HOSTILE_URL + "/" + "x" * 1000
        duplicate = ("{\"" + hostile + "\":1,\"" + hostile + "\":2}").encode("utf-8")
        for optimized in (False, True):
            completed = self._run_cli(duplicate, optimized=optimized)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(completed.stderr, "")
            self.assertNotIn(HOST_CANARY, completed.stdout)
            self.assertNotIn("Traceback", completed.stdout)
            self.assertLessEqual(len(json.loads(completed.stdout)["error"]["message"]), validate.MAX_ERROR_OUTPUT)

    def test_invalid_arguments_are_controlled_and_discard_values(self) -> None:
        for optimized in (False, True):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.extend([str(FIXTURE_DIR / "validate.py"), "--unknown=" + HOSTILE_URL])
            completed = subprocess.run(command, check=False, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(completed.stderr, "")
            self.assertNotIn(HOST_CANARY, completed.stdout)
            self.assertNotIn("usage:", completed.stdout.lower())

    def test_every_retained_artifact_rejects_url_redaction_canary(self) -> None:
        for relative in validate.RETAINED_FILES:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "fixture"
                shutil.copytree(FIXTURE_DIR, root)
                path = root / relative
                path.write_bytes(path.read_bytes() + ("\n" + HOSTILE_URL + "\n").encode("utf-8"))
                with self.assertRaises(validate.ValidationError):
                    validate.validate_retained_artifact_redaction(root)

    def test_every_retained_artifact_rejects_credential_assignment_canary(self) -> None:
        for relative in validate.RETAINED_FILES:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "fixture"
                shutil.copytree(FIXTURE_DIR, root)
                path = root / relative
                path.write_bytes(path.read_bytes() + ("\n" + CREDENTIAL_CANARY + "\n").encode("utf-8"))
                with self.assertRaises(validate.ValidationError):
                    validate.validate_retained_artifact_redaction(root)

    def test_parsed_redaction_rejects_sensitive_keys_and_values(self) -> None:
        for value in (
            {"authorization": "synthetic"},
            {"safe": HOSTILE_URL},
            {"safe": ADDRESS_CANARY},
            {"safe": HOST_CANARY},
            {"safe": "token" + "=" + "synthetic"},
        ):
            with self.subTest(value=value):
                with self.assertRaises(validate.ValidationError):
                    validate.validate_redaction(value)

    def test_baseline_has_30_raw_samples_per_mode_and_null_threshold(self) -> None:
        baseline = validate.load_json(validate.BASELINE_PATH)
        validate.validate_baseline(baseline)
        self.assertIsNone(baseline["threshold"])
        self.assertEqual([run["repetitions"] for run in baseline["runs"]], [30, 30])
        self.assertEqual([len(run["trace"]) for run in baseline["runs"]], [30, 30])

    def test_forged_trace_and_local_identity_rebinding_fail(self) -> None:
        baseline = validate.load_json(validate.BASELINE_PATH)
        forged = copy.deepcopy(baseline)
        forged["runs"][0]["trace"] = [1.0] * validate.BASELINE_REPETITIONS
        forged["runs"][0]["distribution"] = validate._expected_distribution(forged["runs"][0]["trace"])
        with self.assertRaises(validate.ValidationError):
            validate.validate_baseline(forged)

        captured = validate._capture_retained_artifacts(FIXTURE_DIR)
        changed = dict(captured.files)
        changed["README.md"] += b"\nlocal_rebind_marker\n"
        rebound = validate.CapturedArtifacts(captured.root, changed)
        with self.assertRaises(validate.ValidationError):
            validate._validate_pinned_artifacts(rebound)

    def test_reviewed_git_objects_have_exact_independent_identities(self) -> None:
        repo_root = validate._repo_root(FIXTURE_DIR)
        validate._validate_reviewed_launcher(repo_root)
        reviewed = validate._load_reviewed_network_cases(repo_root)
        self.assertIn("reviewed-chat-via-proxy-approved", reviewed)
        with self.assertRaises(validate.ValidationError):
            validate._read_reviewed_git_artifact(
                repo_root,
                validate.REVIEWED_NETWORK_COMMIT,
                validate.REVIEWED_NETWORK_PATH,
                validate.REVIEWED_NETWORK_BYTES,
                "0" * 64,
            )

    def test_canonical_path_replacement_after_capture_cannot_change_parsed_or_hashed_bytes(self) -> None:
        with tempfile.TemporaryDirectory(dir=FIXTURE_DIR.parent) as directory:
            root = Path(directory) / "direct-port-denial"
            shutil.copytree(FIXTURE_DIR, root)
            captured = validate._capture_retained_artifacts(root)
            with self.assertRaises(TypeError):
                captured.files["cases.json"] = b"replacement"  # type: ignore[index]
            original_document = validate.parse_json_bytes(captured.files["cases.json"])
            original_digest = validate._artifact_digest(captured)
            (root / "cases.json").write_bytes(b'{"replacement":true}\n')
            self.assertEqual(validate.parse_json_bytes(captured.files["cases.json"]), original_document)
            self.assertEqual(validate._artifact_digest(captured), original_digest)
            self.assertNotEqual(captured.files["cases.json"], (root / "cases.json").read_bytes())

    def test_alternate_artifact_paths_are_rejected_in_normal_and_optimized_modes(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json") as alternate:
            alternate.write(json.dumps(self.document).encode("utf-8"))
            alternate.flush()
            for optimized in (False, True):
                command = [sys.executable]
                if optimized:
                    command.append("-O")
                command.extend([str(FIXTURE_DIR / "validate.py"), "--cases", alternate.name])
                completed = subprocess.run(command, check=False, capture_output=True, text=True)
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stderr, "")
                self.assertEqual(json.loads(completed.stdout)["error"]["message"], "invalid command-line arguments")

    def test_normal_and_optimized_cli_report_synthetic_scope(self) -> None:
        for optimized in (False, True):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.append(str(FIXTURE_DIR / "validate.py"))
            completed = subprocess.run(command, check=False, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(completed.stderr, "")
            payload = json.loads(completed.stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["case_count"], 16)
            self.assertFalse(payload["compatible"])
            self.assertFalse(payload["live_run"])
            self.assertIsNone(payload["threshold"])
            self.assertEqual(payload["cleanup"], "not_applicable_no_state_created")

    def test_validator_has_no_network_or_shell_primitives(self) -> None:
        source = (FIXTURE_DIR / "validate.py").read_text(encoding="utf-8")
        for forbidden in (
            "import socket",
            "import requests",
            "import urllib",
            "os.system",
            "shell=True",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn('["git", "-C", str(repo_root)', source)
        self.assertIn("network_access", source)
        self.assertIn("socket_operations", source)
        self.assertIn("firewall_changes", source)


if __name__ == "__main__":
    unittest.main()
