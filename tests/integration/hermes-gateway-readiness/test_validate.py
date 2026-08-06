#!/usr/bin/env python3
"""Regression tests for the synthetic rootless Hermes gateway readiness contract.

These tests use only checked-in synthetic JSON and a fake argv executor.  They
never start Podman, connect to the VM, open a socket, invoke Hermes, publish a
port, call a provider, or use browser authentication.
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Sequence


FIXTURE_DIR = Path(__file__).resolve().parent
if str(FIXTURE_DIR) not in sys.path:
    sys.path.insert(0, str(FIXTURE_DIR))

import validate  # noqa: E402


IDENTITY = {
    "repository": "NousResearch/hermes-agent",
    "source_commit": validate.PINNED_HERMES_SHA,
    "source_tree": validate.PINNED_HERMES_TREE,
    "dockerfile_sha256": validate.PINNED_DOCKERFILE_SHA256,
    "image_reference": validate.IMAGE_REFERENCE,
}
APPROVED_POLICY = {
    "status": "approved",
    "cap_drop": ["ALL"],
    "cap_add": [],
    "no_new_privileges": True,
    "dependency": "issue_250_review",
}


class GatewayReadinessTests(unittest.TestCase):
    """Keep parser, isolation, cleanup, and CLI behavior fail-closed."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.document = validate.load_json(validate.CASES_PATH)
        cls.evidence = validate.load_json(validate.EVIDENCE_PATH)
        validate.validate_redaction(cls.document)
        validate.validate_redaction(cls.evidence)
        validate.validate_cases_document(cls.document)
        validate.validate_evidence_document(cls.evidence, cls.document)
        cls.cases = {case["id"]: case for case in cls.document["cases"]}

    def _run_cli(self, *arguments: str, optimized: bool = False) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend([str(FIXTURE_DIR / "validate.py"), *arguments])
        return subprocess.run(command, check=False, capture_output=True, text=True)

    def test_checked_in_contract_is_synthetic_and_blocked(self) -> None:
        self.assertEqual(tuple(self.cases), validate.EXPECTED_CASE_IDS)
        self.assertEqual(len(self.cases), 18)
        self.assertTrue(self.document["synthetic_only"])
        self.assertEqual(self.document["network_access"], "executor_only")
        self.assertFalse(self.document["live_run"])
        self.assertEqual(self.document["proof_status"], "not_run")
        self.assertEqual(self.document["capability_policy"]["status"], "awaiting_issue_250")
        self.assertEqual(self.document["executor_policy"]["ssh_target"], validate.SSH_TARGET)
        self.assertEqual(self.evidence["status"], "not_run")
        self.assertEqual(self.evidence["command_support"], "parser_option_present_readiness_candidate_requires_review")
        self.assertEqual(self.evidence["readiness_source_status"], "headless_backend_path_only")

    def test_every_checked_in_case_matches_the_independent_model(self) -> None:
        for case in self.document["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(validate._case_outcome(case), case["expected"])

    def test_exact_readiness_marker_and_duplicate_rejection(self) -> None:
        self.assertEqual(validate.parse_readiness_marker("HERMES_BACKEND_READY port=9119"), 9119)
        self.assertIsNone(validate.parse_readiness_marker("INFO HERMES_BACKEND_READY port=9119"))
        self.assertIsNone(validate.parse_readiness_marker("HERMES_BACKEND_READY port=65536"))
        self.assertIsNone(validate.parse_readiness_marker("HERMES_BACKEND_READY port=9119 trailing"))
        with self.assertRaises(validate.ProbeError):
            validate.parse_readiness_output(
                "HERMES_BACKEND_READY port=9119 HERMES_BACKEND_READY port=9119"
            )

    def test_exit_and_timeout_classification_is_explicit(self) -> None:
        expected = {
            (None, None, True): ("blocked", "timeout_waiting_for_readiness"),
            (None, 126, False): ("blocked", "exit_126_before_ready"),
            (None, 2, False): ("blocked", "exit_2_before_ready"),
            (None, -9, False): ("blocked", "signal_9_before_ready"),
            (9119, 0, False): ("ready", "readiness_marker"),
        }
        for inputs, result in expected.items():
            with self.subTest(inputs=inputs):
                self.assertEqual(
                    validate.classify_probe(
                        readiness_port=inputs[0], returncode=inputs[1], timed_out=inputs[2]
                    ),
                    result,
                )

    def test_renderer_is_rootless_private_and_deterministic(self) -> None:
        first = validate.render_probe("smoke", instance="one")
        second = validate.render_probe("smoke", instance="one")
        self.assertEqual(first, second)
        self.assertLessEqual(len(first.project), 63)
        self.assertIn('image: "hermes-agent:hermternal-f5be9236"', first.compose)
        self.assertIn('command: ["gateway", "run", "--no-supervise"]', first.compose)
        self.assertIn("internal: true", first.compose)
        self.assertNotIn("ports:", first.compose)
        self.assertNotIn("network_mode", first.compose)
        self.assertNotIn("docker.sock", first.compose)
        self.assertNotIn("~/.hermes", first.compose)
        self.assertNotIn("HERMES_PROVIDER:", first.compose)

    def test_renderer_rejects_unsafe_identifiers_and_host_exposure(self) -> None:
        with self.assertRaises(validate.ValidationError):
            validate.render_probe("../host", instance="one")
        rendered = validate.render_probe("smoke", instance="one")
        mutated = validate.RenderedProbe(
            rendered.project,
            rendered.network,
            rendered.volume,
            rendered.stack_id,
            rendered.instance,
            rendered.compose.replace(
                "    tty: false",
                '    ports:\n      - "9119:9119"\n    tty: false',
            ),
        )
        with self.assertRaises(validate.ValidationError):
            validate.validate_rendered_probe(mutated)

    def test_identity_and_image_binding_are_exact(self) -> None:
        validate.validate_pinned_identity(IDENTITY)
        drifted = copy.deepcopy(IDENTITY)
        drifted["source_tree"] = "0" * 40
        with self.assertRaises(validate.ValidationError):
            validate.validate_pinned_identity(drifted)
        inspect = {
            "RepoTags": [validate.IMAGE_REFERENCE],
            "Id": "sha256:" + "1" * 64,
            "RepoDigests": [],
            "Config": {"Labels": {"org.opencontainers.image.revision": validate.PINNED_HERMES_SHA}},
        }
        public = validate.validate_image_binding(inspect)
        self.assertEqual(public["reference"], validate.IMAGE_REFERENCE)
        self.assertNotIn("Labels", public)
        inspect["RepoTags"] = ["hermes-agent:other"]
        with self.assertRaises(validate.ValidationError):
            validate.validate_image_binding(inspect)

    def test_redaction_rejects_secrets_hosts_urls_and_host_paths(self) -> None:
        validate.validate_redaction({"internal": "/opt/data", "tmpfs": "/tmp:size=64m,mode=1777"})
        for value in (
            "https://synthetic.example/private",
            "198.51.100.10",
            "/Users/synthetic/profile.json",
            "authorization=Bearer SYNTHETIC_TOKEN",
            "-----BEGIN PRIVATE KEY-----",
            "dGVzdHN5bnRoZXRpY19zZWNyZXRfZGF0YQ==",
        ):
            with self.subTest(value=value), self.assertRaises(validate.ValidationError):
                validate.validate_redaction({"value": value})
        redacted = validate.compact_error(
            "token=synthetic-token https://synthetic.example/profile.json"
        )
        self.assertNotIn("synthetic-token", redacted)
        self.assertNotIn("synthetic.example", redacted)
        self.assertLessEqual(len(redacted), validate.MAX_ERROR_OUTPUT)

    def test_strict_json_rejects_duplicate_nonfinite_oversized_and_controlled_inputs(self) -> None:
        with self.assertRaises(validate.FixtureJSONError):
            validate.load_json_text(b'{"schema":1,"schema":2}')
        with self.assertRaises(validate.FixtureJSONError):
            validate.load_json_text(b'{"value":NaN}')
        with self.assertRaises(validate.FixtureJSONError):
            validate.load_json_text(b'{"value":1e9999}')
        with self.assertRaises(validate.FixtureJSONError):
            validate.load_json_text(
                b'{"value":' + b"9" * (validate.MAX_JSON_INTEGER_DIGITS + 1) + b"}"
            )
        nested = b"[" * (validate.MAX_JSON_DEPTH + 1) + b"]" * (validate.MAX_JSON_DEPTH + 1)
        with self.assertRaises(validate.FixtureJSONError):
            validate.load_json_text(nested)
        with self.assertRaises(validate.FixtureJSONError):
            validate.load_json_text(b'{"value":"' + b"x" * (validate.MAX_STRING_LENGTH + 1) + b'"}')
        with self.assertRaises(validate.FixtureJSONError):
            validate.load_json_text(b'{"value":"\xff"}')

    def test_exact_project_teardown_and_zero_leftovers(self) -> None:
        rendered = validate.render_probe("smoke", instance="one")
        with tempfile.TemporaryDirectory() as directory:
            compose_path = Path(directory) / "compose.yml"
            command = validate.teardown_command(rendered.project, compose_path)
        self.assertEqual(
            command[-3:],
            ("down", "--volumes", "--remove-orphans"),
        )
        self.assertIn(rendered.project, command)
        validate.validate_teardown_target(rendered.project, rendered.project)
        with self.assertRaises(validate.ValidationError):
            validate.validate_teardown_target(rendered.project, rendered.project + "-other")
        self.assertTrue(validate.zero_leftovers({"containers": 0, "networks": 0, "volumes": 0}))
        self.assertFalse(validate.zero_leftovers({"containers": 0, "networks": 0, "volumes": 1}))

    def test_pending_capability_policy_blocks_before_any_executor_call(self) -> None:
        calls: list[Sequence[str]] = []

        def unexpected_runner(command: Sequence[str], timeout: float) -> validate.CommandResult:
            del timeout
            calls.append(command)
            raise AssertionError("pending policy must block before executor calls")

        with tempfile.TemporaryDirectory() as directory:
            compose_path = Path(directory) / "compose.yml"
            result = validate.run_probe(
                validate.render_probe("smoke", instance="one"),
                compose_path,
                identity=IDENTITY,
                runner=unexpected_runner,
            )
        self.assertEqual(result.status, "blocked")
        self.assertEqual(result.classification, "capability_policy_pending")
        self.assertEqual(calls, [])

    def test_fake_rootless_probe_cleans_exact_project_and_accepts_one_marker(self) -> None:
        rendered = validate.render_probe("smoke", instance="one")
        calls: list[tuple[str, ...]] = []

        def fake_runner(command: Sequence[str], timeout: float) -> validate.CommandResult:
            del timeout
            command_tuple = tuple(command)
            calls.append(command_tuple)
            if "config" in command_tuple:
                return validate.CommandResult(0, "services: {}\n")
            if command_tuple[:4] == ("podman", "image", "inspect", "--format"):
                payload = {
                    "RepoTags": [validate.IMAGE_REFERENCE],
                    "Id": "sha256:" + "1" * 64,
                    "RepoDigests": [],
                    "Config": {"Labels": {"org.opencontainers.image.revision": validate.PINNED_HERMES_SHA}},
                }
                return validate.CommandResult(0, json.dumps([payload]))
            if " up " in f" {' '.join(command_tuple)} " or command_tuple[-4:] == ("--no-build", "gateway"):
                return validate.CommandResult(0, "gateway started\n")
            if "logs" in command_tuple:
                return validate.CommandResult(0, "HERMES_BACKEND_READY port=9119")
            if "ps" in command_tuple and "-a" in command_tuple:
                return validate.CommandResult(0, "[]")
            if "ps" in command_tuple and "--format" in command_tuple:
                return validate.CommandResult(0, '[{"State":"running","ExitCode":0}]')
            if command_tuple[1:3] == ("ps", "-a") or command_tuple[1:3] == ("network", "ls") or command_tuple[1:3] == ("volume", "ls"):
                return validate.CommandResult(0, "[]")
            if "down" in command_tuple:
                return validate.CommandResult(0, "removed\n")
            raise AssertionError(f"unexpected fake command: {command_tuple}")

        with tempfile.TemporaryDirectory() as directory:
            compose_path = Path(directory) / "compose.yml"
            result = validate.run_probe(
                rendered,
                compose_path,
                identity=IDENTITY,
                capability_policy=APPROVED_POLICY,
                runner=fake_runner,
                clock=lambda: 0.0,
                sleeper=lambda seconds: None,
            )
        self.assertEqual(result.status, "ready")
        self.assertEqual(result.classification, "readiness_marker")
        self.assertEqual(result.readiness_port, 9119)
        self.assertEqual(result.leftovers, {"containers": 0, "networks": 0, "volumes": 0})
        teardown_calls = [call for call in calls if "down" in call]
        self.assertEqual(len(teardown_calls), 1)
        self.assertEqual(teardown_calls[0][-3:], ("down", "--volumes", "--remove-orphans"))

    def test_fake_exit_before_readiness_still_tears_down_exact_project(self) -> None:
        rendered = validate.render_probe("smoke", instance="failure")
        calls: list[tuple[str, ...]] = []

        def fake_failure_runner(command: Sequence[str], timeout: float) -> validate.CommandResult:
            del timeout
            command_tuple = tuple(command)
            calls.append(command_tuple)
            if "config" in command_tuple:
                return validate.CommandResult(0, "services: {}\n")
            if command_tuple[:4] == ("podman", "image", "inspect", "--format"):
                return validate.CommandResult(
                    0,
                    json.dumps(
                        [{
                            "RepoTags": [validate.IMAGE_REFERENCE],
                            "Id": "sha256:" + "2" * 64,
                            "RepoDigests": [],
                            "Config": {"Labels": {"org.opencontainers.image.revision": validate.PINNED_HERMES_SHA}},
                        }]
                    ),
                )
            if " up " in f" {' '.join(command_tuple)} ":
                return validate.CommandResult(0, "gateway started\n")
            if "logs" in command_tuple:
                return validate.CommandResult(0, "synthetic bounded startup warning")
            if "ps" in command_tuple and "-a" in command_tuple:
                return validate.CommandResult(0, "[]")
            if "ps" in command_tuple and "--format" in command_tuple:
                return validate.CommandResult(0, '[{"State":"exited","ExitCode":126}]')
            if "down" in command_tuple:
                return validate.CommandResult(0, "removed\n")
            if command_tuple[1:3] in (("network", "ls"), ("volume", "ls")):
                return validate.CommandResult(0, "[]")
            raise AssertionError(f"unexpected fake command: {command_tuple}")

        with tempfile.TemporaryDirectory() as directory:
            result = validate.run_probe(
                rendered,
                Path(directory) / "compose.yml",
                identity=IDENTITY,
                capability_policy=APPROVED_POLICY,
                runner=fake_failure_runner,
                clock=lambda: 0.0,
                sleeper=lambda seconds: None,
            )
        self.assertEqual(result.status, "blocked")
        self.assertEqual(result.classification, "exit_126_before_ready")
        self.assertEqual(result.exit_code, 126)
        self.assertEqual(result.teardown_exit_code, 0)
        self.assertEqual(result.leftovers, {"containers": 0, "networks": 0, "volumes": 0})
        teardown_calls = [call for call in calls if "down" in call]
        self.assertEqual(len(teardown_calls), 1)
        self.assertEqual(teardown_calls[0][-3:], ("down", "--volumes", "--remove-orphans"))

    def test_normal_and_optimized_cli_regressions_are_controlled(self) -> None:
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                completed = self._run_cli(optimized=optimized)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stderr, "")
                payload = json.loads(completed.stdout)
                self.assertEqual(payload["case_count"], 18)
                self.assertFalse(payload["compatible"])
                self.assertFalse(payload["live_run"])
                self.assertEqual(payload["evidence_status"], "not_run")

                invalid = self._run_cli("--unknown=synthetic", optimized=optimized)
                self.assertEqual(invalid.returncode, 2)
                self.assertEqual(invalid.stderr, "")
                error = json.loads(invalid.stdout)
                self.assertFalse(error["ok"])
                self.assertEqual(error["error"]["code"], validate.ERROR_CODE)
                self.assertNotIn("synthetic", invalid.stdout)
                self.assertNotIn("usage:", invalid.stdout.lower())

    def test_live_flag_requires_explicit_source_and_remains_non_production(self) -> None:
        completed = self._run_cli("--run")
        self.assertEqual(completed.returncode, 2)
        payload = json.loads(completed.stdout)
        self.assertFalse(payload["ok"])
        self.assertIn("--allow-live", payload["error"]["message"])


if __name__ == "__main__":
    unittest.main()
