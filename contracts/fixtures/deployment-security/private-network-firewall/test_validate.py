#!/usr/bin/env python3
"""Regression tests for the synthetic DEP-01 deployment boundary.

The tests use only checked-in synthetic data and Python's standard library.  They
never start a proxy or Hermes, open a socket, invoke a firewall command, or call
a network service.
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


FIXTURE_DIR = Path(__file__).resolve().parent
if str(FIXTURE_DIR) not in sys.path:
    sys.path.insert(0, str(FIXTURE_DIR))

import validate  # noqa: E402


class PrivateNetworkFirewallTests(unittest.TestCase):
    """Keep the closed topology, model, and parser regressions aligned."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.document = validate.load_json(validate.CASES_PATH)
        validate.validate_redaction(cls.document)
        validate.validate_cases_document(cls.document)
        cls.cases = {case["id"]: case for case in cls.document["cases"]}

    def _run_cli(self, content: bytes, *, optimized: bool = False) -> subprocess.CompletedProcess[str]:
        with tempfile.NamedTemporaryFile(suffix=".json") as handle:
            handle.write(content)
            handle.flush()
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.extend([str(FIXTURE_DIR / "validate.py"), "--cases", handle.name, "--skip-baseline"])
            return subprocess.run(command, check=False, capture_output=True, text=True)

    def _assert_cli_failure(self, content: bytes) -> None:
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                completed = self._run_cli(content, optimized=optimized)
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stderr, "")
                lines = [line for line in completed.stdout.splitlines() if line.strip()]
                self.assertEqual(len(lines), 1)
                payload = json.loads(lines[0])
                self.assertFalse(payload["ok"])
                self.assertEqual(payload["error"]["code"], validate.ERROR_CODE)
                self.assertLessEqual(len(payload["error"]["message"]), validate.MAX_ERROR_OUTPUT)
                self.assertNotIn("Traceback", completed.stdout + completed.stderr)
                self.assertNotIn("usage:", completed.stdout.lower())

    def test_checked_in_inventory_and_safe_state_are_frozen(self) -> None:
        self.assertEqual(tuple(self.cases), validate.EXPECTED_CASE_IDS)
        self.assertEqual(len(self.cases), 18)
        self.assertFalse(self.document["network_access"])
        self.assertFalse(self.document["live_run"])
        self.assertFalse(self.document["compatible"])
        self.assertEqual(self.document["proof_status"], "not_run")

    def test_every_case_matches_independent_boundary_model(self) -> None:
        for case in self.document["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(validate.evaluate_case(case), case["expected"])

    def test_topology_freezes_single_origin_private_bind_and_proxy_identity(self) -> None:
        topology = self.document["topology"]
        self.assertEqual(topology["origin_count"], 1)
        self.assertEqual(topology["public_origin"], "configured_public_https_origin")
        self.assertEqual(topology["static_client_path"], "/")
        self.assertEqual(topology["proxy_network_identity"], "approved_proxy_network_identity")
        self.assertEqual(topology["hermes_bind"]["port"], 9119)
        self.assertEqual(topology["hermes_bind"]["address_class"], "private_non_loopback")
        self.assertFalse(topology["hermes_bind"]["publicly_reachable"])
        self.assertFalse(topology["hermes_bind"]["loopback_only"])

    def test_reviewed_routes_and_management_exclusions_are_explicit(self) -> None:
        routes = self.document["route_policy"]["reviewed_routes"]
        self.assertEqual([route["path"] for route in routes], [
            "/api/auth/me",
            "/api/auth/ws-ticket",
            "/api/sessions",
            "/api/ws",
            "/api/pty",
        ])
        self.assertEqual(
            self.document["route_policy"]["blocked_management_prefixes"],
            ["/api/config", "/api/env", "/api/system", "/api/gateway", "/api/ops", "/api/logs", "/api/ssh"],
        )
        self.assertEqual(self.cases["management-route-denied"]["expected"]["upstream_reached"], False)
        self.assertEqual(self.cases["unknown-route-denied"]["expected"]["route_action"], "deny_unknown_route")

    def test_direct_access_and_unsafe_topologies_fail_closed(self) -> None:
        for case_id, reason in (
            ("direct-public-private-denied", "direct_public_access_denied"),
            ("direct-client-private-denied", "direct_client_access_denied"),
            ("localhost-only-assumption-rejected", "localhost_only_assumption_rejected"),
            ("public-hermes-bind-rejected", "public_bind_rejected"),
            ("wrong-hermes-port-rejected", "private_port_mismatch"),
            ("broad-firewall-source-denied", "broad_firewall_source_denied"),
            ("unknown-network-identity-denied", "unknown_network_identity"),
            ("unknown-topology-blocked", "unknown_topology_blocked"),
            ("missing-firewall-rule-blocked", "firewall_rule_missing"),
            ("malformed-topology-blocked", "malformed_topology_blocked"),
        ):
            with self.subTest(case_id=case_id):
                expected = self.cases[case_id]["expected"]
                self.assertEqual(expected["decision"], "deny")
                self.assertFalse(expected["upstream_reached"])
                self.assertEqual(expected["reason"], reason)
                self.assertFalse(expected["live_claim"])

    def test_proxy_variants_are_equal_neutral_metadata_only(self) -> None:
        contract = self.document["proxy_contract"]
        self.assertEqual(contract["variants"], ["caddy", "traefik"])
        self.assertEqual(contract["status"], "not_run")
        self.assertEqual(contract["implementation"], "neutral_contract_only")

    def test_synthetic_redaction_has_no_live_values(self) -> None:
        validate.validate_redaction(self.document)
        serialized = json.dumps(self.document, sort_keys=True)
        self.assertNotIn("https://", serialized)
        self.assertNotRegex(serialized, r"(?:\d{1,3}\.){3}\d{1,3}")
        for forbidden in ("password", "authorization", "session_id", "ticket_value", "firewall_command"):
            self.assertNotIn(f'"{forbidden}"', serialized)

    def test_unknown_keys_and_exact_scalar_types_fail_closed(self) -> None:
        unknown = copy.deepcopy(self.document)
        unknown["unexpected"] = True
        with self.assertRaises(validate.ValidationError):
            validate.validate_cases_document(unknown)

        boolean_port = copy.deepcopy(self.document)
        boolean_port["topology"]["hermes_bind"]["port"] = True
        with self.assertRaises(validate.ValidationError):
            validate.validate_cases_document(boolean_port)

        boolean_outcome = copy.deepcopy(self.document)
        boolean_outcome["cases"][1]["expected"]["upstream_reached"] = 1
        with self.assertRaises(validate.ValidationError):
            validate.validate_cases_document(boolean_outcome)

    def test_duplicate_keys_nonfinite_overflow_depth_and_containers_are_bounded(self) -> None:
        self._assert_cli_failure(b'{"schema":"one","schema":"two"}')
        self._assert_cli_failure(b'{"value":NaN}')
        self._assert_cli_failure(b'{"value":1e9999}')
        oversized = b'{"value":' + (b"9" * (validate.MAX_JSON_INTEGER_DIGITS + 1)) + b"}"
        self._assert_cli_failure(oversized)
        nested = (b"[" * (validate.MAX_JSON_DEPTH + 1)) + (b"]" * (validate.MAX_JSON_DEPTH + 1))
        self._assert_cli_failure(nested)
        too_many_keys = b"{" + b",".join(f'"k{index}":0'.encode() for index in range(validate.MAX_OBJECT_KEYS + 1)) + b"}"
        self._assert_cli_failure(too_many_keys)
        too_many_items = b"[" + b",".join(b"0" for _ in range(validate.MAX_ARRAY_LENGTH + 1)) + b"]"
        self._assert_cli_failure(too_many_items)
        too_long = b'{"value":"' + (b"x" * (validate.MAX_STRING_LENGTH + 1)) + b'"}'
        self._assert_cli_failure(too_long)

    def test_malformed_inventory_and_overflow_baseline_are_controlled(self) -> None:
        malformed = copy.deepcopy(self.document)
        malformed["cases"][0] = None
        self._assert_cli_failure(json.dumps(malformed).encode())

        baseline = validate.load_json(validate.BASELINE_PATH)
        baseline["runs"][0]["trace"][0] = 10**2000
        with self.assertRaises(validate.ValidationError):
            validate.validate_baseline(baseline)

    def test_error_output_redacts_and_caps_untrusted_text(self) -> None:
        huge_key = "attacker-" + ("x" * 2000)
        content = ("{\"" + huge_key + "\":1,\"" + huge_key + "\":2}").encode()
        for optimized in (False, True):
            completed = self._run_cli(content, optimized=optimized)
            self.assertEqual(completed.returncode, 2)
            self.assertNotIn(huge_key, completed.stdout)
            payload = json.loads(completed.stdout)
            self.assertLessEqual(len(payload["error"]["message"]), validate.MAX_ERROR_OUTPUT)
        for message, secret in (
            ("token=synthetic-token", "synthetic-token"),
            ("firewall_command=iptables", "iptables"),
            ("https://synthetic.example", "synthetic.example"),
        ):
            redacted = validate.compact_error(message)
            self.assertNotIn(secret, redacted)
            self.assertLessEqual(len(redacted), validate.MAX_ERROR_OUTPUT)

    def test_baseline_is_anchored_and_has_two_30_run_traces(self) -> None:
        baseline = validate.load_json(validate.BASELINE_PATH)
        validate.validate_baseline(baseline)
        self.assertEqual(baseline["threshold"], None)
        self.assertEqual([run["repetitions"] for run in baseline["runs"]], [30, 30])

        forged = copy.deepcopy(baseline)
        forged["runs"][0]["trace"] = [1.0] * validate.BASELINE_REPETITIONS
        forged["runs"][0]["distribution"] = validate._expected_distribution(forged["runs"][0]["trace"])
        with self.assertRaises(validate.ValidationError):
            validate.validate_baseline(forged)

        stale_command = copy.deepcopy(baseline)
        stale_command["runs"][1]["command"] = "python3 -O fabricated.py"
        with self.assertRaises(validate.ValidationError):
            validate.validate_baseline(stale_command)

    def test_normal_and_optimized_cli_keep_claims_blocked(self) -> None:
        for optimized in (False, True):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.append(str(FIXTURE_DIR / "validate.py"))
            completed = subprocess.run(command, check=False, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stderr, "")
            payload = json.loads(completed.stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["case_count"], 18)
            self.assertFalse(payload["compatible"])
            self.assertFalse(payload["live_run"])
            self.assertIsNone(payload["threshold"])

    def test_invalid_cli_arguments_are_controlled(self) -> None:
        for optimized in (False, True):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.extend([str(FIXTURE_DIR / "validate.py"), "--unknown=synthetic-value"])
            completed = subprocess.run(command, check=False, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(completed.stderr, "")
            payload = json.loads(completed.stdout)
            self.assertFalse(payload["ok"])
            self.assertEqual(payload["error"]["code"], validate.ERROR_CODE)
            self.assertNotIn("synthetic-value", completed.stdout)
            self.assertNotIn("usage:", completed.stdout.lower())

    def test_validator_uses_only_local_standard_library_operations(self) -> None:
        source = (FIXTURE_DIR / "validate.py").read_text(encoding="utf-8")
        for forbidden in ("import requests", "import urllib", "import socket", "import subprocess", "os.system", "subprocess.run"):
            self.assertNotIn(forbidden, source)
        self.assertIn("network_access", source)
        self.assertIn("proxy_to_private_9119", source)


if __name__ == "__main__":
    unittest.main()
