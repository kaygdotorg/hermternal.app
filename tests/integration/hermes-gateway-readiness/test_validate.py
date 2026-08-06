#!/usr/bin/env python3
"""Regression tests for the synthetic rootless Hermes gateway readiness contract.

These tests use only checked-in synthetic JSON and fake executor boundaries.
The live entrypoint regression uses a temporary synthetic source with mocked
local identity reads; it never starts Podman, connects to the VM, opens a
socket, invokes Hermes, publishes a port, calls a provider, or uses browser
authentication.
"""

from __future__ import annotations

from contextlib import redirect_stdout
import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Sequence
from unittest.mock import patch


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
    "image_digest": validate.PINNED_IMAGE_DIGEST,
}
APPROVED_POLICY = {
    "status": "approved",
    "cap_drop": ["ALL"],
    "cap_add": list(validate.APPROVED_CAPABILITIES),
    "no_new_privileges": True,
    "dependency": "issue_250_review",
}
PENDING_POLICY = {
    "status": "awaiting_issue_250",
    "cap_drop": ["ALL"],
    "cap_add": [],
    "no_new_privileges": True,
    "dependency": "issue_250_review",
}


def image_inspect_payload(*, digest: str = validate.PINNED_IMAGE_DIGEST) -> dict[str, object]:
    return {
        "RepoTags": [validate.IMAGE_REFERENCE],
        "Id": "sha256:" + "1" * 64,
        "RepoDigests": [validate.IMAGE_REPOSITORY + "@" + digest],
        "Config": {
            "Labels": {
                validate.IMAGE_SOURCE_LABEL: validate.IMAGE_SOURCE_URL,
                validate.IMAGE_REVISION_LABEL: validate.PINNED_HERMES_SHA,
                validate.IMAGE_DOCKERFILE_LABEL: validate.PINNED_DOCKERFILE_SHA256,
            }
        },
    }


class GatewayReadinessTests(unittest.TestCase):
    """Keep parser, isolation, cleanup, and CLI behavior fail-closed."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.document = validate.load_json(validate.CASES_PATH)
        cls.evidence = validate.load_json(validate.EVIDENCE_PATH)
        cls.rerun_evidence = validate.load_json(validate.RERUN_EVIDENCE_PATH)
        validate.validate_redaction(cls.document)
        validate.validate_redaction(cls.evidence)
        validate.validate_redaction(cls.rerun_evidence)
        validate.validate_cases_document(cls.document)
        validate.validate_evidence_document(cls.evidence, cls.document)
        validate.validate_rerun_evidence_document(cls.rerun_evidence, cls.document)
        cls.cases = {case["id"]: case for case in cls.document["cases"]}

    def _run_cli(self, *arguments: str, optimized: bool = False) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend([str(FIXTURE_DIR / "validate.py"), *arguments])
        return subprocess.run(command, check=False, capture_output=True, text=True)

    def _run_cli_with_temp_json(
        self,
        document: object,
        *,
        image_inspect: object | None = None,
        optimized: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        """Run the real validator CLI against one synthetic mutation."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases_path = root / "cases.json"
            cases_path.write_text(json.dumps(document), encoding="utf-8")
            arguments = ["--cases", str(cases_path)]
            if image_inspect is not None:
                image_path = root / "image-inspect.json"
                image_path.write_text(json.dumps(image_inspect), encoding="utf-8")
                arguments.extend(["--image-inspect", str(image_path)])
            return self._run_cli(*arguments, optimized=optimized)

    def test_checked_in_contract_and_first_attempt_evidence_are_bounded(self) -> None:
        self.assertEqual(tuple(self.cases), validate.EXPECTED_CASE_IDS)
        self.assertEqual(len(self.cases), 18)
        self.assertTrue(self.document["synthetic_only"])
        self.assertEqual(self.document["network_access"], "executor_only")
        self.assertFalse(self.document["live_run"])
        self.assertEqual(self.document["proof_status"], "not_run")
        self.assertEqual(self.document["capability_policy"]["status"], "approved")
        self.assertEqual(
            self.document["capability_policy"]["cap_add"],
            list(validate.APPROVED_CAPABILITIES),
        )
        self.assertEqual(self.document["executor_policy"]["ssh_target"], validate.SSH_TARGET)
        self.assertFalse(self.evidence["synthetic_only"])
        self.assertTrue(self.evidence["live_run"])
        self.assertEqual(self.evidence["status"], "blocked")
        self.assertEqual(self.evidence["classification"], "cleanup_failed")
        self.assertEqual(self.evidence["teardown_exit_code"], 1)
        self.assertEqual(self.evidence["command_support"], "parser_option_present_readiness_candidate_requires_review")
        self.assertEqual(self.evidence["readiness_source_status"], "headless_backend_path_only")
        self.assertEqual(self.evidence["observations"]["container_start"], "not_run")
        self.assertEqual(self.evidence["observations"]["readiness"], "not_run")
        self.assertEqual(self.evidence["observations"]["exit"], "not_run")
        self.assertEqual(self.evidence["observations"]["teardown"], "failed")
        self.assertEqual(self.evidence["observations"]["leftover_resources"], {
            "containers": 0,
            "networks": 0,
            "volumes": 0,
        })
        self.assertEqual(self.rerun_evidence["status"], "blocked")
        self.assertEqual(self.rerun_evidence["classification"], "image_identity_mismatch")
        self.assertEqual(self.rerun_evidence["teardown_exit_code"], 0)
        self.assertEqual(self.rerun_evidence["observations"]["teardown"], "passed")
        self.assertEqual(self.rerun_evidence["observations"]["leftover_resources"], {
            "containers": 0,
            "networks": 0,
            "volumes": 0,
        })

    def test_every_checked_in_case_matches_the_independent_model(self) -> None:
        for case in self.document["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(validate._case_outcome(case), case["expected"])

    def test_case_payloads_cannot_be_weakened_with_matching_expectations(self) -> None:
        accepted = self.cases["readiness-marker-accepted"]
        self.assertEqual(accepted["input"], {"text": "HERMES_BACKEND_READY port=9119"})
        self.assertEqual(accepted["expected"], {"accepted": True, "port": 9119})
        weakened = copy.deepcopy(self.document)
        case = next(row for row in weakened["cases"] if row["id"] == "readiness-marker-accepted")
        case["input"] = {"text": "not-a-marker"}
        case["expected"] = {"accepted": False, "port": None}
        with self.assertRaises(validate.ValidationError):
            validate.validate_cases_document(weakened)

    def test_cli_rejects_case_kind_mutation_in_normal_and_optimized_modes(self) -> None:
        mutated = copy.deepcopy(self.document)
        case = next(row for row in mutated["cases"] if row["id"] == "readiness-marker-accepted")
        case["kind"] = "readiness_output"
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                completed = self._run_cli_with_temp_json(mutated, optimized=optimized)
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stderr, "")
                payload = json.loads(completed.stdout)
                self.assertFalse(payload["ok"])
                self.assertEqual(payload["error"]["code"], validate.ERROR_CODE)
                self.assertNotIn("readiness_output", completed.stdout)

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

    def test_renderer_is_rootless_private_and_unique_per_run(self) -> None:
        first = validate.render_probe("smoke", instance="one")
        second = validate.render_probe("smoke", instance="one")
        self.assertNotEqual(first.project, second.project)
        self.assertNotEqual(first.network, second.network)
        self.assertNotEqual(first.volume, second.volume)
        self.assertLessEqual(len(first.project), 63)
        validate.validate_rendered_probe(first)
        validate.validate_rendered_probe(second)
        self.assertIn('image: "hermes-agent:hermternal-f5be9236"', first.compose)
        self.assertIn('    cap_add:\n      - "CAP_CHOWN"\n      - "CAP_SETGID"\n      - "CAP_SETUID"', first.compose)
        self.assertEqual(first.cap_add, validate.APPROVED_CAPABILITIES)
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

    def test_compose_rejects_extra_volumes_capabilities_duplicates_and_pty_overrides(self) -> None:
        rendered = validate.render_probe("smoke", instance="mutation")
        mutations = {
            "host_profile_volume": rendered.compose.replace(
                '      - "data:/opt/data"',
                '      - "/host/profile:/profile"\n      - "data:/opt/data"',
            ),
            "capability_addition": rendered.compose.replace(
                "    cap_drop:\n",
                '    cap_add:\n      - "NET_ADMIN"\n    cap_drop:\n',
            ),
            "duplicate_cpu_override": rendered.compose + '    cpus: "4.00"\n',
            "duplicate_pty_override": rendered.compose.replace(
                "    stdin_open: false\n",
                "    stdin_open: false\n    stdin_open: true\n",
            ),
        }
        for name, compose in mutations.items():
            with self.subTest(name=name), self.assertRaises(validate.ValidationError):
                validate.validate_rendered_probe(
                    validate.RenderedProbe(
                        rendered.project,
                        rendered.network,
                        rendered.volume,
                        rendered.stack_id,
                        rendered.instance,
                        compose,
                    )
                )

    def test_identity_and_image_binding_are_exact(self) -> None:
        validate.validate_pinned_identity(IDENTITY)
        drifted = copy.deepcopy(IDENTITY)
        drifted["source_tree"] = "0" * 40
        with self.assertRaises(validate.ValidationError):
            validate.validate_pinned_identity(drifted)
        inspect = {
            "RepoTags": [validate.IMAGE_REFERENCE],
            "Id": "sha256:" + "1" * 64,
            "RepoDigests": [validate.IMAGE_REPOSITORY + "@" + validate.PINNED_IMAGE_DIGEST],
            "Config": {
                "Labels": {
                    validate.IMAGE_SOURCE_LABEL: validate.IMAGE_SOURCE_URL,
                    validate.IMAGE_REVISION_LABEL: validate.PINNED_HERMES_SHA,
                    validate.IMAGE_DOCKERFILE_LABEL: validate.PINNED_DOCKERFILE_SHA256,
                }
            },
        }
        public = validate.validate_image_binding(inspect)
        self.assertEqual(public["reference"], validate.IMAGE_REFERENCE)
        self.assertTrue(public["source_label_verified"])
        self.assertTrue(public["dockerfile_label_verified"])
        self.assertTrue(public["digest_verified"])
        self.assertNotIn("Labels", public)
        mutations = []
        missing_digest = copy.deepcopy(inspect)
        missing_digest["RepoDigests"] = []
        mutations.append(missing_digest)
        missing_revision = copy.deepcopy(inspect)
        del missing_revision["Config"]["Labels"][validate.IMAGE_REVISION_LABEL]
        mutations.append(missing_revision)
        wrong_dockerfile = copy.deepcopy(inspect)
        wrong_dockerfile["Config"]["Labels"][validate.IMAGE_DOCKERFILE_LABEL] = "0" * 64
        mutations.append(wrong_dockerfile)
        wrong_digest_repository = copy.deepcopy(inspect)
        wrong_digest_repository["RepoDigests"] = ["other-image@" + validate.PINNED_IMAGE_DIGEST]
        mutations.append(wrong_digest_repository)
        same_repository_digest_drift = copy.deepcopy(inspect)
        same_repository_digest_drift["RepoDigests"] = [
            validate.IMAGE_REPOSITORY + "@sha256:" + "f" * 64
        ]
        mutations.append(same_repository_digest_drift)
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(validate.ValidationError):
                validate.validate_image_binding(mutation)
        inspect["RepoTags"] = ["hermes-agent:other"]
        with self.assertRaises(validate.ValidationError):
            validate.validate_image_binding(inspect)

    def test_cli_rejects_same_repository_image_digest_drift_in_both_modes(self) -> None:
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                accepted = self._run_cli_with_temp_json(
                    self.document,
                    image_inspect=image_inspect_payload(),
                    optimized=optimized,
                )
                self.assertEqual(accepted.returncode, 0, accepted.stderr)
                accepted_payload = json.loads(accepted.stdout)
                self.assertTrue(accepted_payload["image_binding"]["digest_verified"])

                drifted = self._run_cli_with_temp_json(
                    self.document,
                    image_inspect=image_inspect_payload(digest="sha256:" + "f" * 64),
                    optimized=optimized,
                )
                self.assertEqual(drifted.returncode, 2)
                self.assertEqual(drifted.stderr, "")
                payload = json.loads(drifted.stdout)
                self.assertFalse(payload["ok"])
                self.assertEqual(payload["error"]["code"], validate.ERROR_CODE)
                self.assertNotIn("f" * 64, drifted.stdout)

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

    def test_redaction_rejects_api_key_assignments_and_headers(self) -> None:
        for value in (
            "api_key=LEAK",
            "access_key: LEAK",
            "X-API-Key: LEAK",
            "x-access-key=LEAK",
        ):
            with self.subTest(value=value):
                redacted = validate.compact_error(value)
                self.assertNotIn("LEAK", redacted)
                self.assertIn("[REDACTED]", redacted)
                with self.assertRaises(validate.ValidationError):
                    validate.validate_redaction({"diagnostic": value})
        for key in ("API-Key", "Access-Key", "X-API-Key", "X-Access-Key"):
            with self.subTest(key=key), self.assertRaises(validate.ValidationError):
                validate.validate_redaction({key: "value123"})

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

    def test_executor_environment_pins_rootless_compose_provider(self) -> None:
        with patch.dict(os.environ, {"PODMAN_COMPOSE_PROVIDER": "docker-compose"}):
            environment = validate._executor_environment()
        self.assertEqual(environment["PODMAN_COMPOSE_PROVIDER"], "podman-compose")
        self.assertNotIn("DOCKER_HOST", environment)
        self.assertNotIn("HERMES_PROVIDER", environment)

    def test_run_bounded_caps_stdout_and_stderr_during_capture(self) -> None:
        command = (
            sys.executable,
            "-c",
            "import sys; sys.stdout.write('x' * 262144); sys.stderr.write('y' * 262144)",
        )
        result = validate.run_bounded(command, timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertFalse(result.timed_out)
        self.assertLessEqual(len(result.output.encode()), validate.MAX_COMMAND_OUTPUT)
        self.assertLessEqual(len(result.stderr.encode()), validate.MAX_COMMAND_OUTPUT)
        self.assertTrue(result.output.endswith("x" * 32))
        self.assertTrue(result.stderr.endswith("y" * 32))

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
                capability_policy=PENDING_POLICY,
                runner=unexpected_runner,
            )
        self.assertEqual(result.status, "blocked")
        self.assertEqual(result.classification, "capability_policy_pending")
        self.assertEqual(calls, [])

    def test_preflight_failures_teardown_exact_project_and_leave_zero_resources(self) -> None:
        """Config and image gates must clean up without starting a container."""

        rendered = validate.render_probe("smoke", instance="preflight")
        for failure in ("compose", "image"):
            with self.subTest(failure=failure):
                calls: list[tuple[str, ...]] = []

                def preflight_runner(command: Sequence[str], timeout: float) -> validate.CommandResult:
                    del timeout
                    command_tuple = tuple(command)
                    calls.append(command_tuple)
                    if "config" in command_tuple:
                        if failure == "compose":
                            return validate.CommandResult(23, "compose config failed")
                        return validate.CommandResult(0, "services: {}\\n")
                    if command_tuple[:4] == ("podman", "image", "inspect", "--format"):
                        self.assertEqual(failure, "image")
                        return validate.CommandResult(0, json.dumps(image_inspect_payload(digest="sha256:" + "f" * 64)))
                    if "up" in command_tuple:
                        raise AssertionError("preflight failure must not start a container")
                    if "down" in command_tuple:
                        return validate.CommandResult(0, "removed\\n")
                    if command_tuple[1:3] in (("ps", "-a"), ("network", "ls"), ("volume", "ls")):
                        return validate.CommandResult(0, "[]")
                    raise AssertionError(f"unexpected fake command: {command_tuple}")

                with tempfile.TemporaryDirectory() as directory:
                    result = validate.run_probe(
                        rendered,
                        Path(directory) / "compose.yml",
                        identity=IDENTITY,
                        capability_policy=APPROVED_POLICY,
                        runner=preflight_runner,
                    )
                expected_classification = (
                    "compose_config_failed" if failure == "compose" else "image_identity_mismatch"
                )
                self.assertEqual(result.status, "blocked")
                self.assertEqual(result.classification, expected_classification)
                self.assertIsNone(result.readiness_port)
                self.assertEqual(result.teardown_exit_code, 0)
                self.assertEqual(result.leftovers, {"containers": 0, "networks": 0, "volumes": 0})
                self.assertEqual(len([call for call in calls if "down" in call]), 1)
                self.assertFalse(any("up" in call for call in calls))

    def test_synthetic_temp_source_reaches_approved_live_boundary(self) -> None:
        """Exercise --run identity collection without starting a real executor."""

        with tempfile.TemporaryDirectory() as directory:
            source_root = Path(directory) / "synthetic-hermes"
            source_root.mkdir()
            dockerfile = source_root / "Dockerfile"
            dockerfile.write_bytes(b"synthetic Dockerfile bytes\n")
            dockerfile_bytes = dockerfile.read_bytes()
            git_calls: list[tuple[str, ...]] = []
            git_outputs = {
                ("rev-parse", "HEAD"): validate.PINNED_HERMES_SHA,
                ("rev-parse", "HEAD^{tree}"): validate.PINNED_HERMES_TREE,
            }

            def synthetic_git(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                del kwargs
                command_tuple = tuple(command)
                git_calls.append(command_tuple)
                self.assertEqual(command_tuple[:3], ("git", "-C", str(source_root)))
                key = command_tuple[3:]
                self.assertIn(key, git_outputs)
                return subprocess.CompletedProcess(
                    command_tuple,
                    0,
                    stdout=git_outputs[key] + "\n",
                    stderr="",
                )

            real_sha256 = validate.hashlib.sha256

            class SyntheticDigest:
                def hexdigest(self) -> str:
                    return validate.PINNED_DOCKERFILE_SHA256

            def synthetic_sha256(data: bytes = b"") -> object:
                if data == dockerfile_bytes:
                    return SyntheticDigest()
                return real_sha256(data)

            def blocked_boundary(*args: object, **kwargs: object) -> validate.ProbeResult:
                rendered = args[0]
                identity = kwargs["identity"]
                self.assertEqual(identity["image_digest"], validate.PINNED_IMAGE_DIGEST)
                self.assertEqual(rendered.cap_add, validate.APPROVED_CAPABILITIES)
                return validate.ProbeResult(
                    "blocked",
                    "image_identity_mismatch",
                    None,
                    0,
                    False,
                    0,
                    {"containers": 0, "networks": 0, "volumes": 0},
                    "image digest is not the reviewed immutable content",
                )

            output = io.StringIO()
            with (
                patch.object(validate.subprocess, "run", side_effect=synthetic_git),
                patch.object(validate.hashlib, "sha256", side_effect=synthetic_sha256),
                patch.object(validate, "run_probe", side_effect=blocked_boundary),
                redirect_stdout(output),
            ):
                returncode = validate.main(
                    [
                        "--run",
                        "--allow-live",
                        "--source-root",
                        str(source_root),
                    ]
                )

        self.assertEqual(returncode, 3)
        payload = json.loads(output.getvalue())
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["live_run"])
        self.assertEqual(payload["probe"]["classification"], "image_identity_mismatch")
        self.assertEqual(git_calls, [
            ("git", "-C", str(source_root), "rev-parse", "HEAD"),
            ("git", "-C", str(source_root), "rev-parse", "HEAD^{tree}"),
        ])

    def test_exceptional_up_still_attempts_exact_teardown(self) -> None:
        rendered = validate.render_probe("smoke", instance="partial")
        calls: list[tuple[str, ...]] = []

        def partial_runner(command: Sequence[str], timeout: float) -> validate.CommandResult:
            del timeout
            command_tuple = tuple(command)
            calls.append(command_tuple)
            if "config" in command_tuple:
                return validate.CommandResult(0, "services: {}\n")
            if command_tuple[:4] == ("podman", "image", "inspect", "--format"):
                payload = {
                    "RepoTags": [validate.IMAGE_REFERENCE],
                    "Id": "sha256:" + "3" * 64,
                    "RepoDigests": [validate.IMAGE_REPOSITORY + "@" + validate.PINNED_IMAGE_DIGEST],
                    "Config": {
                        "Labels": {
                            validate.IMAGE_SOURCE_LABEL: validate.IMAGE_SOURCE_URL,
                            validate.IMAGE_REVISION_LABEL: validate.PINNED_HERMES_SHA,
                            validate.IMAGE_DOCKERFILE_LABEL: validate.PINNED_DOCKERFILE_SHA256,
                        }
                    },
                }
                return validate.CommandResult(0, json.dumps([payload]))
            if " up " in f" {' '.join(command_tuple)} ":
                raise RuntimeError("synthetic partial start")
            if "down" in command_tuple:
                return validate.CommandResult(0, "removed\n")
            if command_tuple[1:3] in (("ps", "-a"), ("network", "ls"), ("volume", "ls")):
                return validate.CommandResult(0, "[]")
            raise AssertionError(f"unexpected fake command: {command_tuple}")

        with tempfile.TemporaryDirectory() as directory:
            result = validate.run_probe(
                rendered,
                Path(directory) / "compose.yml",
                identity=IDENTITY,
                capability_policy=APPROVED_POLICY,
                runner=partial_runner,
            )
        self.assertEqual(result.status, "blocked")
        self.assertEqual(result.classification, "executor_result_unknown")
        self.assertEqual(result.teardown_exit_code, 0)
        self.assertEqual(len([call for call in calls if "down" in call]), 1)

    def test_failed_logs_cannot_promote_a_marker_to_readiness(self) -> None:
        rendered = validate.render_probe("smoke", instance="log-failure")
        calls: list[tuple[str, ...]] = []

        def failed_logs_runner(command: Sequence[str], timeout: float) -> validate.CommandResult:
            del timeout
            command_tuple = tuple(command)
            calls.append(command_tuple)
            if "config" in command_tuple:
                return validate.CommandResult(0, "services: {}\n")
            if command_tuple[:4] == ("podman", "image", "inspect", "--format"):
                payload = {
                    "RepoTags": [validate.IMAGE_REFERENCE],
                    "Id": "sha256:" + "4" * 64,
                    "RepoDigests": [validate.IMAGE_REPOSITORY + "@" + validate.PINNED_IMAGE_DIGEST],
                    "Config": {
                        "Labels": {
                            validate.IMAGE_SOURCE_LABEL: validate.IMAGE_SOURCE_URL,
                            validate.IMAGE_REVISION_LABEL: validate.PINNED_HERMES_SHA,
                            validate.IMAGE_DOCKERFILE_LABEL: validate.PINNED_DOCKERFILE_SHA256,
                        }
                    },
                }
                return validate.CommandResult(0, json.dumps([payload]))
            if " up " in f" {' '.join(command_tuple)} ":
                return validate.CommandResult(0, "gateway started\n")
            if "logs" in command_tuple:
                return validate.CommandResult(17, "HERMES_BACKEND_READY port=9119")
            if "down" in command_tuple:
                return validate.CommandResult(0, "removed\n")
            if command_tuple[1:3] in (("ps", "-a"), ("network", "ls"), ("volume", "ls")):
                return validate.CommandResult(0, "[]")
            raise AssertionError(f"unexpected fake command: {command_tuple}")

        with tempfile.TemporaryDirectory() as directory:
            result = validate.run_probe(
                rendered,
                Path(directory) / "compose.yml",
                identity=IDENTITY,
                capability_policy=APPROVED_POLICY,
                runner=failed_logs_runner,
            )
        self.assertEqual(result.status, "blocked")
        self.assertEqual(result.classification, "logs_failed")
        self.assertIsNone(result.readiness_port)
        self.assertEqual(result.teardown_exit_code, 0)

    def test_stderr_marker_is_not_readiness_evidence(self) -> None:
        rendered = validate.render_probe("smoke", instance="stderr-marker")

        def stderr_marker_runner(command: Sequence[str], timeout: float) -> validate.CommandResult:
            del timeout
            command_tuple = tuple(command)
            if "config" in command_tuple:
                return validate.CommandResult(0, "services: {}\n")
            if command_tuple[:4] == ("podman", "image", "inspect", "--format"):
                payload = {
                    "RepoTags": [validate.IMAGE_REFERENCE],
                    "Id": "sha256:" + "5" * 64,
                    "RepoDigests": [validate.IMAGE_REPOSITORY + "@" + validate.PINNED_IMAGE_DIGEST],
                    "Config": {
                        "Labels": {
                            validate.IMAGE_SOURCE_LABEL: validate.IMAGE_SOURCE_URL,
                            validate.IMAGE_REVISION_LABEL: validate.PINNED_HERMES_SHA,
                            validate.IMAGE_DOCKERFILE_LABEL: validate.PINNED_DOCKERFILE_SHA256,
                        }
                    },
                }
                return validate.CommandResult(0, json.dumps([payload]))
            if " up " in f" {' '.join(command_tuple)} ":
                return validate.CommandResult(0, "gateway started\n")
            if "logs" in command_tuple:
                return validate.CommandResult(0, "", stderr="HERMES_BACKEND_READY port=9119")
            if "ps" in command_tuple and "--all" in command_tuple:
                return validate.CommandResult(0, '[{"State":"exited","ExitCode":0}]')
            if "down" in command_tuple:
                return validate.CommandResult(0, "removed\n")
            if command_tuple[1:3] in (("ps", "-a"), ("network", "ls"), ("volume", "ls")):
                return validate.CommandResult(0, "[]")
            raise AssertionError(f"unexpected fake command: {command_tuple}")

        with tempfile.TemporaryDirectory() as directory:
            result = validate.run_probe(
                rendered,
                Path(directory) / "compose.yml",
                identity=IDENTITY,
                capability_policy=APPROVED_POLICY,
                runner=stderr_marker_runner,
            )
        self.assertEqual(result.status, "blocked")
        self.assertEqual(result.classification, "exit_0_before_ready")
        self.assertIsNone(result.readiness_port)
        self.assertEqual(result.teardown_exit_code, 0)

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
                    "RepoDigests": [validate.IMAGE_REPOSITORY + "@" + validate.PINNED_IMAGE_DIGEST],
                    "Config": {
                        "Labels": {
                            validate.IMAGE_SOURCE_LABEL: validate.IMAGE_SOURCE_URL,
                            validate.IMAGE_REVISION_LABEL: validate.PINNED_HERMES_SHA,
                            validate.IMAGE_DOCKERFILE_LABEL: validate.PINNED_DOCKERFILE_SHA256,
                        }
                    },
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
                            "RepoDigests": [validate.IMAGE_REPOSITORY + "@" + validate.PINNED_IMAGE_DIGEST],
                            "Config": {
                                "Labels": {
                                    validate.IMAGE_SOURCE_LABEL: validate.IMAGE_SOURCE_URL,
                                    validate.IMAGE_REVISION_LABEL: validate.PINNED_HERMES_SHA,
                                    validate.IMAGE_DOCKERFILE_LABEL: validate.PINNED_DOCKERFILE_SHA256,
                                }
                            },
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
                self.assertEqual(payload["evidence_status"], "blocked")
                self.assertEqual(payload["rerun_evidence_status"], "blocked")

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
