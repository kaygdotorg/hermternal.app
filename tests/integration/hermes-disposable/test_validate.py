#!/usr/bin/env python3
"""Regression tests for the synthetic disposable Hermes Compose boundary.

The tests exercise only the renderer, bounded JSON loader, and fixed policy
model. They do not start Hermes, Podman, Docker, a provider, a browser, a PTY,
or a network service. The VM smoke evidence is a separate one-stack lane.
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path


FIXTURE_DIR = Path(__file__).resolve().parent
if str(FIXTURE_DIR) not in sys.path:
    sys.path.insert(0, str(FIXTURE_DIR))

import validate  # noqa: E402


class HermesDisposableHarnessTests(unittest.TestCase):
    """Keep render, parser, executor, and teardown boundaries closed."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.document = validate.load_json(validate.CASES_PATH)
        validate.validate_redaction(cls.document)
        validate.validate_cases_document(cls.document)
        cls.evidence = validate.load_json(validate.VM_EVIDENCE_PATH)
        validate.validate_vm_evidence(cls.evidence)
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

    def test_checked_in_inventory_is_synthetic_and_blocked(self) -> None:
        self.assertEqual(tuple(self.cases), validate.EXPECTED_CASE_IDS)
        self.assertEqual(len(self.cases), 11)
        self.assertEqual(self.document["pinned_source_sha"], validate.PINNED_HERMES_SHA)
        self.assertEqual(self.document["pinned_source_tree"], validate.PINNED_HERMES_TREE)
        self.assertFalse(self.document["network_access"])
        self.assertFalse(self.document["live_run"])
        self.assertFalse(self.document["compatible"])
        self.assertEqual(self.document["proof_status"], "not_run")
        self.assertEqual(self.document["executor_policy"]["default"], "podman")
        self.assertEqual(self.document["executor_policy"]["docker"]["smoke"], "not_run")

    def test_vm_evidence_is_blocked_and_records_both_executor_results(self) -> None:
        self.assertEqual(self.evidence["status"], "blocked_readiness")
        self.assertEqual(self.evidence["runtime"]["exit_code"], 2)
        self.assertEqual(self.evidence["docker_runtime"]["exit_code"], 126)
        self.assertEqual(self.evidence["docker_runtime"]["teardown_status"], 0)
        self.assertEqual(self.evidence["docker_runtime"]["leftover_containers"], 0)
        self.assertEqual(self.evidence["docker_runtime"]["leftover_networks"], 0)
        self.assertEqual(self.evidence["docker_runtime"]["leftover_volumes"], 0)
        self.assertEqual(self.evidence["provenance"]["compose"]["podman"]["config_status"], "pass")
        self.assertEqual(self.evidence["provenance"]["compose"]["docker"]["config_status"], "pass")
        self.assertIsNone(self.evidence["threshold"])
        self.assertTrue(self.evidence["redacted"])

    def test_every_case_matches_independent_boundary_model(self) -> None:
        for case in self.document["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(validate.evaluate_case(case), case["expected"])

    def test_rendered_stack_contains_all_no_exposure_invariants(self) -> None:
        for executor in ("podman", "docker"):
            with self.subTest(executor=executor):
                rendered = validate.render_stack("smoke", instance="one", executor=executor)
                validate.validate_rendered_stack(rendered)
                self.assertNotIn("container_name", rendered.compose)
                self.assertNotIn("network_mode", rendered.compose)
                self.assertNotIn("ports:", rendered.compose)
                self.assertNotIn("~/.hermes", rendered.compose)
                self.assertNotIn("entrypoint:", rendered.compose)
                self.assertNotIn("    user:", rendered.compose)
                self.assertNotIn("    init:", rendered.compose)
                self.assertIn('restart: "no"', rendered.compose)
                self.assertIn("internal: true", rendered.compose)
                self.assertIn('HERMES_UID: "10000"', rendered.compose)
                self.assertIn('HERMES_GID: "10000"', rendered.compose)
                self.assertIn('mem_limit: "512m"', rendered.compose)
                self.assertIn("pids_limit: 256", rendered.compose)
                self.assertIn('max-size: "1m"', rendered.compose)
                if executor == "podman":
                    self.assertIn('driver: "k8s-file"', rendered.compose)
                    self.assertNotIn("max-file:", rendered.compose)
                else:
                    self.assertIn('driver: "json-file"', rendered.compose)
                    self.assertIn('max-file: "2"', rendered.compose)

    def test_compose_named_volume_uses_service_key_and_explicit_name(self) -> None:
        rendered = validate.render_stack("volume", instance="one")
        self.assertIn('      - "data:/opt/data"', rendered.compose)
        self.assertNotIn(f'      - "{rendered.volume}:/opt/data"', rendered.compose)
        self.assertIn(f'    name: "{rendered.volume}"', rendered.compose)

    def test_lane_policies_do_not_enable_live_surfaces(self) -> None:
        no_provider = validate.render_stack("lanes", instance="none", lane="no-provider")
        browser = validate.render_stack("lanes", instance="browser", lane="browser")
        model = validate.render_stack("lanes", instance="model", lane="model")
        self.assertNotIn("HERMES_PROVIDER", no_provider.compose)
        self.assertNotIn("BASIC_AUTH_PASSWORD", no_provider.compose)
        self.assertIn("HERMES_DASHBOARD_BASIC_AUTH_USERNAME", browser.compose)
        self.assertIn("HERMES_DASHBOARD_BASIC_AUTH_PASSWORD", browser.compose)
        self.assertIn("synthetic-browser-", browser.compose)
        self.assertNotIn("API_SERVER_KEY", browser.compose)
        self.assertIn('HERMES_PROVIDER: "synthetic-local"', model.compose)
        self.assertIn('HERMES_PROVIDER_AUTO_DISCOVERY: "0"', model.compose)
        self.assertNotIn("API_SERVER_KEY", model.compose)

    def test_project_network_volume_names_are_unique_for_concurrent_instances(self) -> None:
        first = validate.render_stack("parallel", instance="first")
        second = validate.render_stack("parallel", instance="second")
        self.assertEqual(len({first.project, second.project}), 2)
        self.assertEqual(len({first.network, second.network}), 2)
        self.assertEqual(len({first.volume, second.volume}), 2)
        self.assertIn(first.network, first.compose)
        self.assertIn(first.volume, first.compose)
        self.assertIn(second.network, second.compose)
        self.assertIn(second.volume, second.compose)

    def test_unsafe_identifiers_and_executor_fail_closed(self) -> None:
        for kwargs in (
            {"stack_id": "..-escape"},
            {"stack_id": "Unsafe"},
            {"stack_id": "safe", "instance": "..-escape"},
            {"stack_id": "safe", "lane": "provider-auto"},
            {"stack_id": "safe", "executor": "unknown"},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(validate.ValidationError):
                    validate.render_stack(**kwargs)

    def test_teardown_requires_exact_generated_project_and_exact_flags(self) -> None:
        rendered = validate.render_stack("smoke", instance="one")
        validate.validate_teardown_target(rendered.project, rendered.project)
        with self.assertRaises(validate.ValidationError):
            validate.validate_teardown_target(rendered.project, "hermes-disposable-untrusted")
        command = validate.compose_command("podman", rendered.project, Path("compose.yml"), "down", "--volumes", "--remove-orphans")
        self.assertEqual(command[:4], ("podman", "compose", "--project-name", rendered.project))
        with self.assertRaises(validate.ValidationError):
            validate.compose_command("podman", rendered.project, Path("compose.yml"), "down", "--volumes")

    def test_render_mutations_are_rejected(self) -> None:
        rendered = validate.render_stack("mutation", instance="one")
        mutations = (
            ("ports:", "    ports:\n      - \"127.0.0.1:9119:9119\"\n"),
            ("container_name:", "    container_name: hermes\n"),
            ("network_mode:", "    network_mode: host\n"),
            ("entrypoint:", "    entrypoint: /bin/sh\n"),
            ("user:", "    user: 1234:1234\n"),
            ("init:", "    init: true\n"),
        )
        for label, insertion in mutations:
            with self.subTest(label=label):
                mutated = replace(rendered, compose=rendered.compose.replace("    restart: \"no\"\n", insertion + "    restart: \"no\"\n"))
                with self.assertRaises(validate.ValidationError):
                    validate.validate_rendered_stack(mutated)

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

    def test_error_output_redacts_controlled_failures_and_retained_data_shapes(self) -> None:
        huge_key = "attacker-" + ("x" * 2000)
        self._assert_cli_failure(("{\"" + huge_key + "\":1,\"" + huge_key + "\":2}").encode())
        for message, secret in (
            ("token=synthetic-token", "synthetic-token"),
            ("Authorization: Bearer synthetic-bearer", "synthetic-bearer"),
            ("Authorization: Basic synthetic-basic", "synthetic-basic"),
            ("Cookie: synthetic-cookie", "synthetic-cookie"),
            ("data:text/plain,synthetic-payload", "synthetic-payload"),
            ("https://synthetic.example", "synthetic.example"),
            ("/opt/hermes/profile.json", "profile.json"),
            ("synthetic-host.example", "synthetic-host.example"),
            ("embedded-base64-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
        ):
            redacted = validate.compact_error(message)
            with self.subTest(message=message):
                self.assertNotIn(secret, redacted)
                self.assertLessEqual(len(redacted), validate.MAX_ERROR_OUTPUT)

    def test_vm_evidence_mutation_fails_in_normal_and_optimized_cli(self) -> None:
        mutated = copy.deepcopy(self.evidence)
        mutated["status"] = "successful_release_proof"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as handle:
            json.dump(mutated, handle, ensure_ascii=False, indent=2)
            handle.flush()
            for optimized in (False, True):
                with self.subTest(optimized=optimized):
                    command = [sys.executable]
                    if optimized:
                        command.append("-O")
                    command.extend([str(FIXTURE_DIR / "validate.py"), "--vm-evidence", handle.name])
                    completed = subprocess.run(command, check=False, capture_output=True, text=True)
                    self.assertEqual(completed.returncode, 2)
                    self.assertEqual(completed.stderr, "")
                    lines = [line for line in completed.stdout.splitlines() if line.strip()]
                    self.assertEqual(len(lines), 1)
                    payload = json.loads(lines[0])
                    self.assertFalse(payload["ok"])
                    self.assertEqual(payload["error"]["code"], validate.ERROR_CODE)
                    self.assertNotIn("successful_release_proof", completed.stdout)
                    self.assertNotIn("Traceback", completed.stdout)

    def test_unapproved_hex_and_key_assignments_fail_closed(self) -> None:
        with self.assertRaises(validate.ValidationError):
            validate.validate_redaction({"retained": "a" * 40})
        with self.assertRaises(validate.ValidationError):
            validate.validate_redaction({"retained": "b" * 64})
        with self.assertRaises(validate.ValidationError):
            validate.validate_redaction({"value": validate.PINNED_HERMES_SHA})
        validate.validate_redaction({"pinned_source_sha": validate.PINNED_HERMES_SHA})
        for message, secret in (
            ("api_key=synthetic-api-key", "synthetic-api-key"),
            ("access_key: synthetic-access-key", "synthetic-access-key"),
            ("API-KEY=synthetic-api-key", "synthetic-api-key"),
            ("access.key=synthetic-access-key", "synthetic-access-key"),
        ):
            with self.subTest(message=message):
                redacted = validate.compact_error(message)
                self.assertNotIn(secret, redacted)
                self.assertLessEqual(len(redacted), validate.MAX_ERROR_OUTPUT)

    def test_docker_mount_projection_rejects_bind_and_wrong_volume(self) -> None:
        for field, value in (
            ("type", "bind"),
            ("name", "hermes-disposable-docker-untrusted_data"),
            ("destination", "/opt/untrusted"),
        ):
            with self.subTest(field=field):
                mutated = copy.deepcopy(self.evidence)
                mutated["inspection"]["docker_mounts"][0][field] = value
                with self.assertRaises(validate.ValidationError):
                    validate.validate_vm_evidence(mutated)

    def test_vm_evidence_mount_mutation_fails_in_normal_and_optimized_cli(self) -> None:
        mutated = copy.deepcopy(self.evidence)
        mutated["inspection"]["docker_mounts"][0]["type"] = "bind"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as handle:
            json.dump(mutated, handle, ensure_ascii=False, indent=2)
            handle.flush()
            for optimized in (False, True):
                with self.subTest(optimized=optimized):
                    command = [sys.executable]
                    if optimized:
                        command.append("-O")
                    command.extend([str(FIXTURE_DIR / "validate.py"), "--vm-evidence", handle.name])
                    completed = subprocess.run(command, check=False, capture_output=True, text=True)
                    self.assertEqual(completed.returncode, 2)
                    self.assertEqual(completed.stderr, "")
                    payload = json.loads(completed.stdout)
                    self.assertFalse(payload["ok"])
                    self.assertEqual(payload["error"]["code"], validate.ERROR_CODE)
                    self.assertNotIn('"type": "bind"', completed.stdout)
                    self.assertNotIn("Traceback", completed.stdout)

    def test_unknown_keys_and_exact_scalar_types_fail_closed(self) -> None:
        unknown = copy.deepcopy(self.document)
        unknown["unexpected"] = True
        with self.assertRaises(validate.ValidationError):
            validate.validate_cases_document(unknown)
        boolean_pid = copy.deepcopy(self.document)
        boolean_pid["stack_policy"]["pid_limit"] = True
        with self.assertRaises(validate.ValidationError):
            validate.validate_cases_document(boolean_pid)
        boolean_outcome = copy.deepcopy(self.document)
        boolean_outcome["cases"][0]["expected"]["resource_caps"] = 1
        with self.assertRaises(validate.ValidationError):
            validate.validate_cases_document(boolean_outcome)

    def test_normal_and_optimized_cli_keep_live_claims_blocked(self) -> None:
        for optimized in (False, True):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.extend([str(FIXTURE_DIR / "validate.py"), "--skip-baseline"])
            completed = subprocess.run(command, check=False, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stderr, "")
            payload = json.loads(completed.stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["case_count"], 11)
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

    def test_validator_is_standard_library_and_offline(self) -> None:
        source = (FIXTURE_DIR / "validate.py").read_text(encoding="utf-8")
        for forbidden in (
            "import requests",
            "import urllib",
            "import socket",
            "import subprocess",
            "os.system",
            "subprocess.run",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("rootless_preferred", source)
        self.assertIn("HERMES_PROVIDER_AUTO_DISCOVERY", source)
        self.assertIn("network_mode", source)


if __name__ == "__main__":
    unittest.main()
