#!/usr/bin/env python3
"""Regression tests for the official immutable-image readiness boundary.

The tests use bounded synthetic executor results. They never connect to the
VM, start a real container, open a socket, use a provider, or use browser
authentication. The checked-in official evidence is loaded through the same
validator entry point used by the CLI.
"""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Sequence
from unittest.mock import patch


FIXTURE_DIR = Path(__file__).resolve().parent
if str(FIXTURE_DIR) not in sys.path:
    sys.path.insert(0, str(FIXTURE_DIR))

import validate  # noqa: E402


IDENTITY = {
    "repository": validate.OFFICIAL_IMAGE_REPOSITORY,
    "tag": validate.OFFICIAL_IMAGE_TAG,
    "digest": validate.OFFICIAL_IMAGE_DIGEST,
    "reference": validate.OFFICIAL_IMAGE_REFERENCE,
}
APPROVED_EXECUTOR = {
    "account": validate.ROOTLESS_ACCOUNT,
    "ssh_target": validate.SSH_TARGET,
    "rootless": True,
    "podman_version": validate.EXPECTED_PODMAN_VERSION,
    "cgroup_version": "v2",
    "network_backend": "netavark",
    "storage_driver": "overlay",
    "compose_provider": validate.EXPECTED_COMPOSE_PROVIDER,
    "compose_version": validate.EXPECTED_COMPOSE_VERSION,
    "docker_host_cleared": True,
    "hermes_provider_cleared": True,
}


def image_inspect_payload(
    *,
    digest: str = validate.OFFICIAL_IMAGE_DIGEST,
    tags: list[str] | None = None,
    revision: str = validate.OFFICIAL_IMAGE_REVISION,
) -> dict[str, Any]:
    """Return a Podman image inspect record with actual official metadata shape."""

    return {
        "RepoTags": [] if tags is None else tags,
        "Id": "sha256:" + "1" * 64,
        "Digest": digest,
        "RepoDigests": [
            validate.OFFICIAL_IMAGE_REPO_DIGEST,
            validate.OFFICIAL_IMAGE_REPOSITORY + "@sha256:" + "2" * 64,
        ],
        "Config": {
            "Entrypoint": list(validate.OFFICIAL_RUNTIME_ENTRYPOINT),
            "Cmd": None,
            "User": "root",
            "WorkingDir": validate.OFFICIAL_CONTAINER_WORKING_DIR,
            "Labels": {validate.IMAGE_REVISION_LABEL: revision},
        },
    }


def runtime_inspect_payload(
    *,
    policy_matches: bool = True,
    running: bool = True,
    exit_code: int = 0,
    pid: int = 1234,
) -> dict[str, Any]:
    """Return the bounded Podman inspect fields retained in official evidence."""

    if policy_matches:
        cap_drop = ["ALL"]
        cap_add = list(validate.APPROVED_CAPABILITIES)
        security_opt = ["no-new-privileges:true"]
        no_new_privileges = True
        nano_cpus = 500000000
        memory_limit = 536870912
        pids_limit = 256
    else:
        cap_drop = []
        cap_add = []
        security_opt = []
        no_new_privileges = False
        nano_cpus = 500000000
        memory_limit = 536870912
        pids_limit = 2048
    return {
        "State": {
            "Running": running,
            "Status": "running" if running else "exited",
            "ExitCode": exit_code,
            "Pid": pid,
        },
        "Path": validate.OFFICIAL_RUNTIME_PATH,
        "Args": list(validate.PROBE_COMMAND),
        "Config": {"Entrypoint": list(validate.OFFICIAL_RUNTIME_ENTRYPOINT)},
        "HostConfig": {
            "CapDrop": cap_drop,
            "CapAdd": cap_add,
            "SecurityOpt": security_opt,
            "NoNewPrivileges": no_new_privileges,
            "PortBindings": {},
            "PublishAllPorts": False,
            "NetworkMode": "readiness_internal",
            "NanoCpus": nano_cpus,
            "Memory": memory_limit,
            "PidsLimit": pids_limit,
            "ShmSize": 67108864,
            "Tmpfs": {
                "/tmp": "size=64m,mode=1777",
                "/run": "size=16m,mode=755",
            },
            "RestartPolicy": {"Name": "no"},
            "LogConfig": {"Type": "k8s-file"},
            "IpcMode": "private",
            "PidMode": "private",
        },
        "Mounts": [{"Type": "volume", "Destination": "/opt/data"}],
    }


def fake_runner_factory(
    rendered: validate.RenderedProbe,
    *,
    policy_matches: bool = True,
    marker: str | None = "HERMES_BACKEND_READY port=9119",
    running: bool = True,
    exit_code: int = 0,
) -> tuple[validate.Runner, list[tuple[str, ...]]]:
    """Build a bounded fake Podman runner for the reusable live path."""

    container_id = "a" * 64
    runtime_payload = runtime_inspect_payload(
        policy_matches=policy_matches,
        running=running,
        exit_code=exit_code,
    )
    calls: list[tuple[str, ...]] = []

    def runner(command: Sequence[str], timeout: float) -> validate.CommandResult:
        del timeout
        argv = tuple(command)
        calls.append(argv)
        if argv[:4] == ("podman", "image", "pull", validate.OFFICIAL_IMAGE_REFERENCE):
            return validate.CommandResult(0, "pulled\n")
        if argv[:4] == ("podman", "image", "inspect", "--format"):
            return validate.CommandResult(0, json.dumps([image_inspect_payload()]))
        if argv[-1:] == ("config",):
            return validate.CommandResult(0, "services:\n  gateway:\n")
        if argv[-4:] == ("up", "--detach", "--no-build", "gateway"):
            return validate.CommandResult(0, "gateway started\n")
        if (
            argv[:2] == ("podman", "ps")
            and "--no-trunc" in argv
            and "io.podman.compose.project=" in " ".join(argv)
        ):
            return validate.CommandResult(0, json.dumps([{"Id": container_id}]))
        if argv[:4] == ("podman", "inspect", "--format", "json"):
            return validate.CommandResult(0, json.dumps([runtime_payload]))
        if argv[:2] == ("podman", "logs"):
            return validate.CommandResult(0, marker or "")
        if argv[-3:] == ("down", "--volumes", "--remove-orphans"):
            return validate.CommandResult(0, "removed\n")
        if argv[:3] in {
            ("podman", "ps", "-a"),
            ("podman", "network", "ls"),
            ("podman", "volume", "ls"),
        }:
            return validate.CommandResult(0, "[]")
        raise AssertionError(f"unexpected fake command: {argv}")

    return runner, calls


def synthetic_probe_result(
    rendered: validate.RenderedProbe,
    *,
    policy_matches: bool = False,
    status: str = "blocked",
    classification: str = "policy_not_applied",
    marker_in_logs: bool = False,
) -> validate.ProbeResult:
    """Create a result only for evidence-validator mutation tests."""

    runtime = validate._runtime_identity_from_row(
        runtime_inspect_payload(policy_matches=policy_matches),
        "b" * 64,
    )
    marker = "HERMES_BACKEND_READY port=9119" if marker_in_logs else "bounded startup output"
    observations = {
        "executor_preflight": "passed",
        "image_pull": "passed",
        "image_identity": "passed",
        "compose_config": "passed",
        "container_start": "started",
        "runtime_inspection": "passed",
        "readiness": "ready" if status == "ready" else "timeout",
        "exit": "observed",
        "exit_code": 0,
        "teardown": "passed",
        "leftover_resources": {"containers": 0, "networks": 0, "volumes": 0},
        "policy_inspection": "passed",
        "applied_policy": "passed" if policy_matches else "failed",
    }
    return validate.ProbeResult(
        status,
        classification,
        9119 if status == "ready" else None,
        0,
        False,
        0,
        {"containers": 0, "networks": 0, "volumes": 0},
        marker if marker_in_logs else "bounded startup output",
        executor=dict(APPROVED_EXECUTOR),
        image=validate.validate_image_binding(image_inspect_payload()),
        observations=observations,
        runtime_identity=runtime,
        log_tail=marker,
    )


class GatewayReadinessTests(unittest.TestCase):
    """Keep the official image, runtime, cleanup, and CLI boundaries fail-closed."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.document = validate.load_json(validate.CASES_PATH)
        cls.official_evidence = validate.load_json(validate.OFFICIAL_EVIDENCE_PATH)
        validate.validate_redaction(cls.document)
        validate.validate_redaction(cls.official_evidence)
        validate.validate_cases_document(cls.document)
        validate.validate_official_evidence_document(cls.official_evidence, cls.document)
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
        official_evidence: object | None = None,
        extra: Sequence[str] = (),
        optimized: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases_path = root / "cases.json"
            cases_path.write_text(json.dumps(document), encoding="utf-8")
            arguments = ["--cases", str(cases_path), *extra]
            if image_inspect is not None:
                image_path = root / "image-inspect.json"
                image_path.write_text(json.dumps(image_inspect), encoding="utf-8")
                arguments.extend(["--image-inspect", str(image_path)])
            if official_evidence is not None:
                evidence_path = root / "official-evidence.json"
                evidence_path.write_text(json.dumps(official_evidence), encoding="utf-8")
                arguments.extend(["--official-evidence", str(evidence_path)])
            return self._run_cli(*arguments, optimized=optimized)

    def test_cases_use_only_the_official_digest_pinned_identity(self) -> None:
        self.assertEqual(tuple(self.cases), validate.EXPECTED_CASE_IDS)
        self.assertEqual(self.document["pinned_identity"], IDENTITY)
        self.assertEqual(self.cases["identity-exact"]["input"], IDENTITY)
        drifted = copy.deepcopy(IDENTITY)
        drifted["digest"] = "sha256:" + "0" * 64
        self.assertEqual(
            validate._case_outcome({"kind": "identity", "input": drifted}),
            {"accepted": False, "reason": "pinned_identity_mismatch"},
        )

    def test_renderer_contains_only_the_official_reference_and_private_policy(self) -> None:
        first = validate.render_probe("smoke", instance="one")
        second = validate.render_probe("smoke", instance="one")
        self.assertNotEqual(first.project, second.project)
        self.assertIn(f'image: "{validate.OFFICIAL_IMAGE_REFERENCE}"', first.compose)
        self.assertNotIn("hermes-agent:hermternal-f5be9236", first.compose)
        self.assertIn('command: ["gateway", "run", "--no-supervise"]', first.compose)
        self.assertIn('      - "ALL"', first.compose)
        self.assertIn('      - "no-new-privileges:true"', first.compose)
        self.assertIn('    internal: true', first.compose)
        self.assertNotIn("ports:", first.compose)
        self.assertNotIn("network_mode", first.compose)
        self.assertNotIn("docker.sock", first.compose)
        self.assertNotIn("HERMES_PROVIDER:", first.compose)

    def test_renderer_rejects_unsafe_mutations(self) -> None:
        with self.assertRaises(validate.ValidationError):
            validate.render_probe("../host", instance="one")
        rendered = validate.render_probe("smoke", instance="mutation")
        mutations = (
            rendered.compose.replace("    tty: false", '    ports:\n      - "9119:9119"\n    tty: false'),
            rendered.compose.replace('      - "data:/opt/data"', '      - "/host/profile:/profile"\n      - "data:/opt/data"'),
            rendered.compose.replace("    cap_drop:\n", '    cap_add:\n      - "NET_ADMIN"\n    cap_drop:\n'),
        )
        for compose in mutations:
            with self.subTest(compose=compose):
                candidate = validate.RenderedProbe(
                    rendered.project,
                    rendered.network,
                    rendered.volume,
                    rendered.stack_id,
                    rendered.instance,
                    compose,
                )
                with self.assertRaises(validate.ValidationError):
                    validate.validate_rendered_probe(candidate)

    def test_image_binding_accepts_actual_empty_tags_and_verifies_all_attestations(self) -> None:
        record = image_inspect_payload()
        public = validate.validate_image_binding(record)
        self.assertEqual(public["repo_tags"], [])
        self.assertIn(validate.OFFICIAL_IMAGE_REPO_DIGEST, public["repo_digests"])
        self.assertEqual(public["manifest_digest"], validate.OFFICIAL_IMAGE_DIGEST)
        self.assertEqual(public["revision_label"], validate.OFFICIAL_IMAGE_REVISION)
        mutations = (
            {**record, "Digest": "sha256:" + "f" * 64},
            {**record, "RepoTags": ["hermes-agent:hermternal-f5be9236"]},
            {**record, "RepoDigests": [validate.OFFICIAL_IMAGE_REPOSITORY + "@sha256:" + "f" * 64]},
            {**record, "Config": {**record["Config"], "Labels": {validate.IMAGE_REVISION_LABEL: "0" * 40}}},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(validate.ValidationError):
                validate.validate_image_binding(mutation)

    def test_executor_boundary_rejects_fake_rootless_and_provider_facts(self) -> None:
        validate.validate_executor_info(APPROVED_EXECUTOR)
        for key, value in (
            ("account", "fake-user"),
            ("rootless", False),
            ("podman_version", "5.5.0"),
            ("cgroup_version", "v1"),
            ("network_backend", "cni"),
            ("storage_driver", "vfs"),
            ("compose_provider", "docker-compose"),
            ("compose_version", "2.0.0"),
        ):
            mutated = dict(APPROVED_EXECUTOR)
            mutated[key] = value
            with self.subTest(key=key), self.assertRaises(validate.ValidationError):
                validate.validate_executor_info(mutated)
        self.assertEqual(validate._podman_version({"Client": {"Version": "5.4.2"}}), "5.4.2")
        self.assertEqual(validate._compose_version("podman-compose version 1.3.0"), "1.3.0")

    def test_runtime_policy_is_derived_from_inspect_fields(self) -> None:
        matching = validate._runtime_identity_from_row(runtime_inspect_payload(), "a" * 64)
        mismatching = validate._runtime_identity_from_row(
            runtime_inspect_payload(policy_matches=False), "a" * 64
        )
        self.assertTrue(validate._runtime_policy_matches(matching))
        self.assertFalse(validate._runtime_policy_matches(mismatching))
        self.assertEqual(matching["path"], validate.OFFICIAL_RUNTIME_PATH)
        self.assertEqual(matching["args"], list(validate.PROBE_COMMAND))
        self.assertEqual(matching["pid"], 1234)
        self.assertEqual(matching["resources"]["pids_limit"], 256)
        self.assertEqual(matching["resources"]["shm_size"], 67108864)
        self.assertTrue(validate._runtime_tmpfs_matches(matching["resources"]["tmpfs"]))
        self.assertNotEqual(matching["namespaces"]["network"], "host")
        mutated = copy.deepcopy(matching)
        mutated["resources"]["tmpfs"]["/tmp"] = "size=1m,mode=1777"
        self.assertFalse(validate._runtime_policy_matches(mutated))
        for path, value in (
            (("policy", "cap_drop"), []),
            (("policy", "cap_add"), []),
            (("policy", "no_new_privileges"), False),
            (("resources", "pids_limit"), 2048),
        ):
            candidate = copy.deepcopy(matching)
            target = candidate
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path):
                self.assertFalse(validate._runtime_policy_matches(candidate))

    def test_fake_runner_reaches_ready_only_when_applied_policy_matches(self) -> None:
        for policy_matches, expected_status, expected_classification in (
            (True, "ready", "readiness_marker"),
            (False, "blocked", "policy_not_applied"),
        ):
            with self.subTest(policy_matches=policy_matches):
                rendered = validate.render_probe("smoke", instance="fake")
                runner, calls = fake_runner_factory(
                    rendered,
                    policy_matches=policy_matches,
                )
                with tempfile.TemporaryDirectory() as directory:
                    result = validate.run_probe(
                        rendered,
                        Path(directory) / "compose.yml",
                        executor_info=APPROVED_EXECUTOR,
                        runner=runner,
                        clock=lambda: 0.0,
                        sleeper=lambda seconds: None,
                    )
                self.assertEqual(result.status, expected_status)
                self.assertEqual(result.classification, expected_classification)
                self.assertEqual(result.readiness_port, 9119 if policy_matches else None)
                self.assertEqual(result.leftovers, {"containers": 0, "networks": 0, "volumes": 0})
                self.assertEqual(
                    [call[-3:] for call in calls if call[-3:] == ("down", "--volumes", "--remove-orphans")],
                    [("down", "--volumes", "--remove-orphans")],
                )

    def test_blocked_log_marker_is_redacted_and_cannot_be_promoted(self) -> None:
        rendered = validate.render_probe("smoke", instance="marker")
        runner, _ = fake_runner_factory(
            rendered,
            policy_matches=False,
            marker="HERMES_BACKEND_READY port=9119",
        )
        with tempfile.TemporaryDirectory() as directory:
            result = validate.run_probe(
                rendered,
                Path(directory) / "compose.yml",
                executor_info=APPROVED_EXECUTOR,
                runner=runner,
                clock=lambda: 0.0,
                sleeper=lambda seconds: None,
            )
        self.assertEqual(result.status, "blocked")
        self.assertEqual(result.classification, "policy_not_applied")
        self.assertNotIn(validate.READINESS_PREFIX, result.diagnostic)
        self.assertNotIn(validate.READINESS_PREFIX, result.log_tail)

    def test_generated_evidence_binds_runtime_and_cleanup_to_exact_scope(self) -> None:
        rendered = validate.render_probe("smoke", instance="evidence")
        result = synthetic_probe_result(rendered)
        evidence = validate.generate_official_evidence(result, rendered, self.document)
        validate.validate_official_evidence_document(evidence, self.document)
        self.assertEqual(
            evidence["cleanup_scope"],
            {"project": rendered.project, "network": rendered.network, "volume": rendered.volume},
        )
        self.assertEqual(evidence["observations"]["applied_policy"], "failed")
        self.assertEqual(evidence["runtime_identity"]["resources"]["pids_limit"], 2048)

    def test_official_evidence_mutations_fail_in_normal_and_optimized_real_loaders(self) -> None:
        mutations = (
            ("digest mismatch", ("image", "manifest_digest"), "sha256:" + "f" * 64),
            ("repo tag mismatch", ("image", "repo_tags"), ["localhost/hermes-agent:old"]),
            ("fake rootless", ("executor", "rootless"), False),
            ("fake provider", ("executor", "compose_provider"), "docker-compose"),
            ("unexecuted policy", ("observations", "applied_policy"), "passed"),
            ("leftover claim", ("observations", "leftover_resources", "volumes"), 1),
            ("cleanup project drift", ("cleanup_scope", "project"), "hermes-gateway-readiness-other-00000000"),
            ("cleanup network drift", ("cleanup_scope", "network"), "hermes-gateway-readiness-other-00000000_internal"),
            ("cleanup volume drift", ("cleanup_scope", "volume"), "hermes-gateway-readiness-other-00000000_data"),
            ("injected diagnostic marker", ("diagnostic",), "HERMES_BACKEND_READY port=9119"),
            ("injected log marker", ("log_tail",), "HERMES_BACKEND_READY port=9119"),
        )
        for label, path, value in mutations:
            mutated = copy.deepcopy(self.official_evidence)
            target = mutated
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            script = """
import copy
import json
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import validate
record = json.loads(Path(sys.argv[2]).read_text())
cases = validate.load_json(validate.CASES_PATH)
try:
    validate.validate_official_evidence_document(record, cases)
except validate.ValidationError:
    raise SystemExit(0)
raise SystemExit(1)
"""
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                evidence_path = root / "mutated.json"
                evidence_path.write_text(json.dumps(mutated), encoding="utf-8")
                script_path = root / "loader.py"
                script_path.write_text(script, encoding="utf-8")
                for optimized in (False, True):
                    with self.subTest(label=label, optimized=optimized):
                        command = [sys.executable]
                        if optimized:
                            command.append("-O")
                        command.extend([str(script_path), str(FIXTURE_DIR), str(evidence_path)])
                        completed = subprocess.run(command, check=False, capture_output=True, text=True)
                        self.assertEqual(completed.returncode, 0, completed.stderr)
                        self.assertEqual(completed.stdout, "")
                        self.assertEqual(completed.stderr, "")

    def test_cli_rejects_old_image_source_root_and_synthetic_live_inputs_in_both_modes(self) -> None:
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                old_image = self._run_cli(
                    "--image-inspect",
                    str(FIXTURE_DIR / "cases.json"),
                    optimized=optimized,
                )
                self.assertEqual(old_image.returncode, 2)
                self.assertFalse(json.loads(old_image.stdout)["ok"])
                rejected_source = self._run_cli(
                    "--run",
                    "--allow-live",
                    "--source-root",
                    "/tmp/synthetic-source",
                    optimized=optimized,
                )
                self.assertEqual(rejected_source.returncode, 2)
                self.assertFalse(json.loads(rejected_source.stdout)["ok"])
                rejected_image = self._run_cli_with_temp_json(
                    self.document,
                    image_inspect=image_inspect_payload(
                        tags=["hermes-agent:hermternal-f5be9236"]
                    ),
                    optimized=optimized,
                )
                self.assertEqual(rejected_image.returncode, 2)
                self.assertFalse(json.loads(rejected_image.stdout)["ok"])

    def test_pending_policy_blocks_before_any_executor_call(self) -> None:
        calls: list[Sequence[str]] = []

        def unexpected_runner(command: Sequence[str], timeout: float) -> validate.CommandResult:
            del timeout
            calls.append(command)
            raise AssertionError("pending policy must block before executor calls")

        rendered = validate.render_probe("smoke", instance="pending")
        with tempfile.TemporaryDirectory() as directory:
            result = validate.run_probe(
                rendered,
                Path(directory) / "compose.yml",
                capability_policy=validate.PENDING_CAPABILITY_POLICY,
                runner=unexpected_runner,
            )
        self.assertEqual(result.classification, "capability_policy_pending")
        self.assertEqual(calls, [])

    def test_bounded_runner_and_environment_remain_safe(self) -> None:
        with patch.dict(os.environ, {"PODMAN_COMPOSE_PROVIDER": "docker-compose", "DOCKER_HOST": "synthetic"}):
            environment = validate._executor_environment()
        self.assertEqual(environment["PODMAN_COMPOSE_PROVIDER"], "podman-compose")
        self.assertNotIn("DOCKER_HOST", environment)
        self.assertNotIn("HERMES_PROVIDER", environment)
        command = (
            sys.executable,
            "-c",
            "import sys; sys.stdout.write('x' * 262144); sys.stderr.write('y' * 262144)",
        )
        result = validate.run_bounded(command, timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertLessEqual(len(result.output.encode()), validate.MAX_COMMAND_OUTPUT)
        self.assertLessEqual(len(result.stderr.encode()), validate.MAX_COMMAND_OUTPUT)
        self.assertTrue(result.output.endswith("x" * 32))
        self.assertTrue(result.stderr.endswith("y" * 32))

    def test_exact_teardown_and_leftover_scope(self) -> None:
        rendered = validate.render_probe("smoke", instance="cleanup")
        with tempfile.TemporaryDirectory() as directory:
            command = validate.teardown_command(rendered.project, Path(directory) / "compose.yml")
        self.assertEqual(command[-3:], ("down", "--volumes", "--remove-orphans"))
        validate.validate_teardown_target(rendered.project, rendered.project)
        with self.assertRaises(validate.ValidationError):
            validate.validate_teardown_target(rendered.project, rendered.project + "-other")
        self.assertTrue(validate.zero_leftovers({"containers": 0, "networks": 0, "volumes": 0}))
        self.assertFalse(validate.zero_leftovers({"containers": 0, "networks": 0, "volumes": 1}))

    def test_readiness_and_classification_contract(self) -> None:
        self.assertEqual(validate.parse_readiness_marker("HERMES_BACKEND_READY port=9119"), 9119)
        self.assertIsNone(validate.parse_readiness_marker("INFO HERMES_BACKEND_READY port=9119"))
        self.assertIsNone(validate.parse_readiness_marker("HERMES_BACKEND_READY port=65536"))
        with self.assertRaises(validate.ProbeError):
            validate.parse_readiness_output(
                "HERMES_BACKEND_READY port=9119\nHERMES_BACKEND_READY port=9119"
            )
        self.assertEqual(
            validate.classify_probe(readiness_port=None, returncode=126, timed_out=False),
            ("blocked", "exit_126_before_ready"),
        )
        self.assertEqual(
            validate.classify_probe(readiness_port=None, returncode=None, timed_out=True),
            ("blocked", "timeout_waiting_for_readiness"),
        )

    def test_default_cli_validates_checked_in_official_evidence_in_both_modes(self) -> None:
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                completed = self._run_cli(optimized=optimized)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                payload = json.loads(completed.stdout)
                self.assertTrue(payload["ok"])
                self.assertFalse(payload["live_run"])
                self.assertEqual(payload["evidence_status"], self.official_evidence["status"])
                self.assertEqual(payload["case_count"], len(validate.EXPECTED_CASE_IDS))

    def test_live_flag_requires_explicit_opt_in(self) -> None:
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                completed = self._run_cli("--run", optimized=optimized)
                self.assertEqual(completed.returncode, 2)
                payload = json.loads(completed.stdout)
                self.assertFalse(payload["ok"])
                self.assertIn("--allow-live", payload["error"]["message"])


if __name__ == "__main__":
    unittest.main()
