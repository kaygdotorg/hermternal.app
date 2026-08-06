"""Normal and optimized regressions for the official Hermes upstream fleet.

The default suite uses a fake runner. It never starts Podman, Docker, Hermes,
a provider, a browser, or a network service. The guarded VM demo is exercised
only through its authorization failure path here.
"""

from __future__ import annotations

from contextlib import redirect_stdout
import inspect
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest


FIXTURE_DIR = Path(__file__).resolve().parent
if str(FIXTURE_DIR) not in sys.path:
    sys.path.insert(0, str(FIXTURE_DIR))

import validate  # noqa: E402


class FakeRunner:
    """Bounded fake engine with controllable partial-failure behavior."""

    def __init__(self, *, fail_projects: set[str] | None = None, interrupt_projects: set[str] | None = None) -> None:
        self.fail_projects = set(fail_projects or ())
        self.interrupt_projects = set(interrupt_projects or ())
        self.calls: list[tuple[tuple[str, ...], dict[str, str], float]] = []
        self.lock = threading.Lock()
        self.active = 0
        self.max_active = 0
        self.running_projects: set[str] = set()

    def __call__(self, command: tuple[str, ...], env: dict[str, str], timeout: float) -> validate.CommandResult:
        with self.lock:
            self.calls.append((command, dict(env), timeout))
        if command[:2] == ("podman-compose", "version"):
            return validate.CommandResult(0, stdout="podman-compose 1.0")
        if command[0] == "podman-compose":
            project = command[command.index("-p") + 1]
            if "up" in command:
                if project in self.interrupt_projects:
                    raise KeyboardInterrupt
                if project in self.fail_projects:
                    return validate.CommandResult(1, stderr="provider=secret path=/tmp/host")
                with self.lock:
                    self.active += 1
                    self.max_active = max(self.max_active, self.active)
                    self.running_projects.add(project)
                time.sleep(0.01)
                with self.lock:
                    self.active -= 1
                return validate.CommandResult(0, stdout="started")
            if "down" in command:
                self.running_projects.discard(project)
                return validate.CommandResult(0, stdout="removed")
        if command[:3] == ("podman", "ps", "-a"):
            project = next(
                (
                    token.removeprefix("label=io.podman.compose.project=")
                    for token in command
                    if token.startswith("label=io.podman.compose.project=")
                ),
                None,
            )
            if project in self.running_projects:
                return validate.CommandResult(
                    0,
                    stdout=json.dumps(
                        [{
                            "State": "running",
                            "Labels": {"io.podman.compose.project": project},
                        }]
                    ),
                )
            return validate.CommandResult(0, stdout="[]")
        if command[:3] in {
            ("podman", "network", "ls"),
            ("podman", "volume", "ls"),
        }:
            return validate.CommandResult(0, stdout="[]")
        if len(command) >= 3 and command[0] == "podman" and command[2] == "exists":
            return validate.CommandResult(1)
        if command[:3] == ("podman", "info", "--format"):
            return validate.CommandResult(0, stdout=json.dumps({"host": {"security": {"rootless": True}}}))
        if command[:2] == ("podman-compose", "version"):
            return validate.CommandResult(0, stdout="podman-compose 1.0")
        if command[:4] == ("podman", "image", "inspect", "--format"):
            return validate.CommandResult(
                0,
                stdout=json.dumps(
                    [{"RepoDigests": [f"{validate.IMAGE_REPOSITORY}@{validate.PINNED_IMAGE_DIGEST}"]}]
                ),
            )
        raise AssertionError(f"unexpected command: {command}")


class HermesUpstreamFleetTests(unittest.TestCase):
    """Keep planning, isolation, identity, execution, and cleanup fail closed."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = validate.load_cases()
        cls.vm_evidence = validate.load_vm_evidence()
        validate.validate_vm_evidence_anchor()

    def _plan(self, *items: tuple[str, str], fleet: str = "test") -> validate.FleetPlan:
        return validate.build_plan(fleet, items)

    def test_checked_in_cases_match_policy(self) -> None:
        self.assertEqual(self.cases["schema"], validate.CASES_SCHEMA)
        self.assertEqual(self.cases["image"], validate.PINNED_IMAGE)
        self.assertEqual(len(self.cases["cases"]), 20)
        validate.validate_cases_document(self.cases)
        self.assertTrue(self.vm_evidence["image"]["digest_verified"])
        self.assertTrue(self.vm_evidence["teardown"]["zero_leftovers"])

    def test_digest_is_official_immutable_and_rendered_once(self) -> None:
        plan = self._plan(("one", "auth"), fleet="digest")
        rendered = validate.render_compose(plan.instances[0])
        self.assertEqual(rendered.count(validate.PINNED_IMAGE), 1)
        self.assertIn("docker.io/nousresearch/hermes-agent@sha256:", rendered)
        self.assertNotIn("docker.io/nousresearch/hermes-agent:", rendered)
        self.assertNotIn("build:", rendered)
        self.assertNotIn("retag", rendered.lower())
        self.assertNotIn("labels:", rendered)
        with self.assertRaisesRegex(validate.ContractError, "image_digest_required"):
            validate.validate_image_reference("docker.io/nousresearch/hermes-agent:latest")
        with self.assertRaisesRegex(validate.ContractError, "image_digest_not_reviewed"):
            validate.validate_image_reference(
                "docker.io/nousresearch/hermes-agent@sha256:" + "0" * 64
            )

    def test_names_are_deterministic_unique_and_bounded(self) -> None:
        first = self._plan(("one", "auth"), ("two", "sessions-search"), fleet="parallel")
        second = self._plan(("one", "auth"), ("two", "sessions-search"), fleet="parallel")
        self.assertEqual(first.public(), second.public())
        self.assertEqual(len({item.project for item in first.instances}), 2)
        self.assertEqual(len({item.network for item in first.instances}), 2)
        self.assertEqual(len({item.volume for item in first.instances}), 2)
        self.assertTrue(all(len(item.volume) <= 63 for item in first.instances))
        with self.assertRaisesRegex(validate.ContractError, "unsafe_fleet"):
            validate.build_plan("../escape", [("one", "auth")])
        with self.assertRaisesRegex(validate.ContractError, "duplicate_instance"):
            validate.build_plan("parallel", [("one", "auth"), ("one", "auth")])
        with self.assertRaisesRegex(validate.ContractError, "name_budget_exceeded"):
            validate.build_plan("a" * 14, [("b" * 14, "auth")])

    def test_all_reviewed_profiles_fit_and_over_budget_requests_fail(self) -> None:
        plan = self._plan(
            ("auth", "auth"),
            ("search", "sessions-search"),
            ("stream", "stream-reconnect"),
            ("pty", "image-pty"),
            fleet="reviewed",
        )
        self.assertEqual(plan.totals.cpu, validate.Decimal("4.50"))
        self.assertEqual(plan.totals.memory_mib, 15360)
        self.assertEqual(plan.totals.pids, 3072)
        with self.assertRaisesRegex(validate.ContractError, "cpu_budget_exceeded"):
            validate.build_plan("too-many", [(str(i), "image-pty") for i in range(1, 6)])
        with self.assertRaisesRegex(validate.ContractError, "memory_budget_exceeded"):
            validate.build_plan("memory", [(str(i), "image-pty") for i in range(1, 5)])

    def test_compose_is_private_provider_free_and_profile_parameterized(self) -> None:
        plan = self._plan(("search", "sessions-search"), fleet="private")
        rendered = validate.render_compose(plan.instances[0])
        for fragment in (
            "internal: true",
            "data:/opt/data",
            "HERMES_PROVIDER_AUTO_DISCOVERY: \"0\"",
            'cpus: "1.25"',
            'mem_limit: "4096m"',
            "pids_limit: 768",
            "k8s-file",
            "no-new-privileges:true",
        ):
            self.assertIn(fragment, rendered)
        for forbidden in (
            "ports:",
            "network_mode:",
            "container_name:",
            "build:",
            "docker.sock",
            ".hermes",
            "HERMES_PROVIDER:",
            "entrypoint:",
            "user:",
        ):
            self.assertNotIn(forbidden, rendered)

    def test_environment_clears_docker_provider_and_secret_inheritance(self) -> None:
        cleaned = validate.clean_environment(
            {
                "PATH": "/bin",
                "DOCKER_HOST": "tcp://host.invalid:2375",
                "DOCKER_CONTEXT": "desktop",
                "CONTAINER_HOST": "tcp://remote.invalid:2375",
                "CONTAINER_CONNECTION": "remote-profile",
                "COMPOSE_PROJECT_NAME": "host-project",
                "HERMES_PROVIDER": "host-provider",
                "HERMES_PROVIDER_URL": "https://provider.invalid",
                "OPENAI_API_KEY": "synthetic-secret",
                "CUSTOM_API_TOKEN": "synthetic-token",
            }
        )
        self.assertNotIn("DOCKER_HOST", cleaned)
        self.assertNotIn("DOCKER_CONTEXT", cleaned)
        self.assertNotIn("CONTAINER_HOST", cleaned)
        self.assertNotIn("CONTAINER_CONNECTION", cleaned)
        self.assertNotIn("COMPOSE_PROJECT_NAME", cleaned)
        self.assertNotIn("HERMES_PROVIDER", cleaned)
        self.assertNotIn("HERMES_PROVIDER_URL", cleaned)
        self.assertNotIn("OPENAI_API_KEY", cleaned)
        self.assertNotIn("CUSTOM_API_TOKEN", cleaned)
        self.assertEqual(cleaned["PODMAN_COMPOSE_PROVIDER"], "podman-compose")
        self.assertEqual(cleaned["HERMES_PROVIDER_AUTO_DISCOVERY"], "0")
        self.assertEqual(cleaned["PATH"], validate.TRUSTED_PATH)

    def test_preflight_bypass_is_not_public_and_executables_ignore_shadowed_path(self) -> None:
        self.assertNotIn("enforce_preflight", inspect.signature(validate.start_fleet).parameters)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trusted = root / "trusted"
            shadow = root / "shadow"
            trusted.mkdir()
            shadow.mkdir()
            trusted_marker = root / "trusted.marker"
            shadow_marker = root / "shadow.marker"
            for name in ("podman", "podman-compose"):
                trusted_script = trusted / name
                trusted_script.write_text(
                    "#!/bin/sh" + chr(10) + f"printf trusted > {trusted_marker}" + chr(10),
                    encoding="utf-8",
                )
                trusted_script.chmod(0o700)
                shadow_script = shadow / name
                shadow_script.write_text(
                    "#!/bin/sh" + chr(10) + f"printf shadow > {shadow_marker}" + chr(10),
                    encoding="utf-8",
                )
                shadow_script.chmod(0o700)
            old_dirs = validate.TRUSTED_EXECUTABLE_DIRS
            old_candidates = validate.TRUSTED_EXECUTABLE_CANDIDATES
            validate.TRUSTED_EXECUTABLE_DIRS = (trusted,)
            validate.TRUSTED_EXECUTABLE_CANDIDATES = {
                validate.ENGINE_EXECUTABLE: (trusted / validate.ENGINE_EXECUTABLE,),
                validate.COMPOSE_EXECUTABLE: (trusted / validate.COMPOSE_EXECUTABLE,),
            }
            try:
                for command in (("podman", "version"), ("podman-compose", "version")):
                    result = validate.invoke(command, source_environment={"PATH": str(shadow)})
                    self.assertEqual(result.returncode, 0)
                self.assertTrue(trusted_marker.exists())
                self.assertFalse(shadow_marker.exists())
            finally:
                validate.TRUSTED_EXECUTABLE_DIRS = old_dirs
                validate.TRUSTED_EXECUTABLE_CANDIDATES = old_candidates

    def test_docker_executor_is_rejected_before_runner(self) -> None:
        runner = FakeRunner()
        with self.assertRaisesRegex(validate.ContractError, "docker_executor_rejected"):
            validate.invoke(("docker", "compose", "up"), runner=runner)
        self.assertEqual(runner.calls, [])
        with self.assertRaisesRegex(validate.ContractError, "docker_executor_rejected"):
            validate.compose_command(
                self._plan(("one", "auth")).instances[0],
                Path("/tmp/hermes.compose.yaml"),
                ("docker", "compose"),
            )

    def test_preflight_requires_rootless_podman_and_exact_digest(self) -> None:
        runner = FakeRunner()
        validate.preflight(runner=runner)
        self.assertTrue(any(call[0][:3] == ("podman", "info", "--format") for call in runner.calls))
        self.assertTrue(any(call[0][:2] == ("podman-compose", "version") for call in runner.calls))
        image_calls = [call for call in runner.calls if call[0][:3] == ("podman", "image", "inspect")]
        self.assertEqual(len(image_calls), 1)
        self.assertEqual(image_calls[0][0][-1], validate.PINNED_IMAGE)
        for _, env, _ in runner.calls:
            self.assertNotIn("DOCKER_HOST", env)
            self.assertNotIn("HERMES_PROVIDER", env)

    def test_generated_compose_and_state_paths_reject_links_and_nonregular_files(self) -> None:
        plan = self._plan(("one", "auth"), fleet="files")
        instance = plan.instances[0]
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory)
            compose = validate.compose_path(state_dir, instance)
            compose.symlink_to("missing-compose")
            with self.assertRaisesRegex(validate.ContractError, "compose_symlink_rejected"):
                validate.render_to_directory(plan, state_dir)
            compose.unlink()
            compose.mkdir()
            with self.assertRaisesRegex(validate.ContractError, "compose_non_regular_rejected"):
                validate.render_to_directory(plan, state_dir)
            compose.rmdir()

            manifest = validate.state_path(state_dir, plan.fleet_id)
            manifest.symlink_to("missing-state")
            with self.assertRaisesRegex(validate.ContractError, "state_symlink_rejected"):
                validate.write_manifest(plan, state_dir)
            manifest.unlink()
            manifest.mkdir()
            with self.assertRaisesRegex(validate.ContractError, "state_non_regular_rejected"):
                validate.write_manifest(plan, state_dir)
            manifest.rmdir()

            manifest.symlink_to("still-missing")
            with self.assertRaisesRegex(validate.ContractError, "state_symlink_rejected"):
                validate.load_manifest(state_dir, plan.fleet_id)

    def test_teardown_unlinks_only_dangling_compose_links_and_rejects_live_links(self) -> None:
        plan = self._plan(("one", "auth"), fleet="dangling")
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory)
            compose = validate.compose_path(state_dir, plan.instances[0])
            compose.symlink_to("missing-compose")
            removed = validate.teardown_one(plan.instances[0], compose, runner=FakeRunner())
            self.assertEqual(removed.status, "removed")
            self.assertFalse(compose.exists() or compose.is_symlink())

            target = state_dir / "target"
            target.write_text("not compose", encoding="utf-8")
            compose.symlink_to(target)
            runner = FakeRunner()
            rejected = validate.teardown_one(plan.instances[0], compose, runner=runner)
            self.assertEqual(rejected.status, "teardown_failed")
            self.assertTrue(compose.is_symlink())
            self.assertFalse(any(call[0][0] == "podman-compose" and "down" in call[0] for call in runner.calls))

    def test_parallel_start_uses_concurrency_and_keeps_each_project_separate(self) -> None:
        runner = FakeRunner()
        plan = self._plan(
            ("one", "auth"),
            ("two", "auth"),
            ("three", "auth"),
            fleet="parallel",
        )
        with tempfile.TemporaryDirectory() as directory:
            result = validate.start_fleet(
                plan,
                Path(directory),
                runner=runner,
            )
            self.assertEqual(result["status"], "started")
            self.assertGreaterEqual(runner.max_active, 2)
            up_projects = {
                call[0][call[0].index("-p") + 1]
                for call in runner.calls
                if call[0][0] == "podman-compose" and "up" in call[0]
            }
            self.assertEqual(up_projects, {item.project for item in plan.instances})

    def test_partial_start_cleans_started_and_unstarted_projects(self) -> None:
        plan = self._plan(("one", "auth"), ("two", "auth"), ("three", "auth"), fleet="partial")
        failed_project = plan.instances[1].project
        runner = FakeRunner(fail_projects={failed_project})
        with tempfile.TemporaryDirectory() as directory:
            result = validate.start_fleet(
                plan,
                Path(directory),
                runner=runner,
            )
            self.assertEqual(result["status"], "failed")
            self.assertTrue(result["zero_leftovers"])
            down_projects = {
                call[0][call[0].index("-p") + 1]
                for call in runner.calls
                if call[0][0] == "podman-compose" and "down" in call[0]
            }
            self.assertEqual(down_projects, {item.project for item in plan.instances})
            self.assertFalse(any(Path(directory).iterdir()))

    def test_interrupted_start_also_cleans_every_project(self) -> None:
        plan = self._plan(("one", "auth"), ("two", "auth"), fleet="interrupt")
        runner = FakeRunner(interrupt_projects={plan.instances[0].project})
        with tempfile.TemporaryDirectory() as directory:
            result = validate.start_fleet(
                plan,
                Path(directory),
                runner=runner,
            )
            self.assertEqual(result["status"], "failed")
            self.assertTrue(result["zero_leftovers"])
            down_projects = {
                call[0][call[0].index("-p") + 1]
                for call in runner.calls
                if call[0][0] == "podman-compose" and "down" in call[0]
            }
            self.assertEqual(down_projects, {item.project for item in plan.instances})

    def test_teardown_is_idempotent_and_scoped_to_manifest(self) -> None:
        plan = self._plan(("one", "auth"), ("two", "auth"), fleet="cleanup")
        runner = FakeRunner()
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory)
            validate.render_to_directory(plan, state_dir)
            validate.write_manifest(plan, state_dir)
            loaded = validate.load_manifest(state_dir, "cleanup")
            first = validate.teardown_fleet(loaded, state_dir, runner=runner)
            self.assertEqual(first["status"], "removed")
            second_output = io.StringIO()
            with redirect_stdout(second_output):
                exit_code = validate.main(
                    ["teardown", "--fleet-id", "cleanup", "--all", "--state-dir", directory],
                    _runner=runner,
                )
            self.assertEqual(exit_code, 0)
            second = json.loads(second_output.getvalue())
            self.assertTrue(second["idempotent"])
            down_projects = {
                call[0][call[0].index("-p") + 1]
                for call in runner.calls
                if call[0][0] == "podman-compose" and "down" in call[0]
            }
            self.assertEqual(down_projects, {item.project for item in plan.instances})

    def test_all_teardown_inventory_fails_closed_when_manifest_is_missing_or_corrupt(self) -> None:
        plan = self._plan(("one", "auth"), fleet="stale")
        project = plan.instances[0].project

        class InventoryRunner(FakeRunner):
            def __call__(self, command: tuple[str, ...], env: dict[str, str], timeout: float) -> validate.CommandResult:
                if command and command[0] == "podman" and "--filter" in command:
                    with self.lock:
                        self.calls.append((command, dict(env), timeout))
                    filter_value = command[command.index("--filter") + 1]
                    if filter_value == "label=io.podman.compose.project":
                        if command[1:3] == ("network", "ls"):
                            item = {"Name": plan.instances[0].network}
                        elif command[1:3] == ("volume", "ls"):
                            item = {"Name": plan.instances[0].volume}
                        else:
                            item = {"Names": [f"{project}-hermes-1"]}
                        item["Labels"] = {"io.podman.compose.project": project}
                        return validate.CommandResult(0, stdout=json.dumps([item]))
                    if filter_value == f"label=io.podman.compose.project={project}":
                        return validate.CommandResult(
                            0,
                            stdout=json.dumps(
                                [{"Name": project, "Labels": {"io.podman.compose.project": project}}]
                            ),
                        )
                return super().__call__(command, env, timeout)

        runner = InventoryRunner()
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with redirect_stdout(output):
                exit_code = validate.main(
                    ["teardown", "--fleet-id", "stale", "--all", "--state-dir", directory],
                    _runner=runner,
                )
            result = json.loads(output.getvalue())
            self.assertEqual(exit_code, 1)
            self.assertEqual(result["status"], "cleanup_failed")
            self.assertFalse(result["zero_leftovers"])
            self.assertTrue(result["resource_inventory_complete"])
            self.assertEqual(result["instances"][0]["project"], project)
            self.assertFalse(any(call[0][0] == "podman-compose" and "down" in call[0] for call in runner.calls))
            self.assertGreaterEqual(
                sum(
                    1
                    for call, _, _ in runner.calls
                    if call and call[0] == "podman" and "--filter" in call
                ),
                6,
            )

            state = validate.state_path(Path(directory), "stale")
            state.write_text("{corrupt", encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                exit_code = validate.main(
                    ["teardown", "--fleet-id", "stale", "--all", "--state-dir", directory],
                    _runner=runner,
                )
            corrupt = json.loads(output.getvalue())
            self.assertEqual(exit_code, 1)
            self.assertEqual(corrupt["manifest"], "unusable")
            self.assertFalse(corrupt["zero_leftovers"])

    def test_missing_manifest_inventory_exception_fails_closed(self) -> None:
        class FailingInventory(FakeRunner):
            def __call__(self, command: tuple[str, ...], env: dict[str, str], timeout: float) -> validate.CommandResult:
                if command and command[0] == "podman" and "--filter" in command:
                    raise RuntimeError("synthetic inventory failure")
                return super().__call__(command, env, timeout)

        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with redirect_stdout(output):
                exit_code = validate.main(
                    ["teardown", "--fleet-id", "missing", "--all", "--state-dir", directory],
                    _runner=FailingInventory(),
                )
            result = json.loads(output.getvalue())
            self.assertEqual(exit_code, 1)
            self.assertEqual(result["status"], "cleanup_failed")
            self.assertFalse(result["zero_leftovers"])
            self.assertFalse(result["resource_inventory_complete"])

    def test_leftover_network_blocks_cleanup_success(self) -> None:
        class NetworkLeftover(FakeRunner):
            def __call__(self, command: tuple[str, ...], env: dict[str, str], timeout: float) -> validate.CommandResult:
                if command[:3] == ("podman", "network", "ls"):
                    return validate.CommandResult(0, stdout='[{"Name":"hermes-upstream-fleet-leftover-one-private"}]')
                return super().__call__(command, env, timeout)

        plan = self._plan(("one", "auth"), fleet="leftover")
        runner = NetworkLeftover()
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory)
            validate.render_to_directory(plan, state_dir)
            validate.write_manifest(plan, state_dir)
            result = validate.teardown_fleet(plan, state_dir, runner=runner)
            self.assertEqual(result["status"], "cleanup_failed")
            self.assertFalse(result["zero_leftovers"])
            self.assertEqual(result["instances"][0]["leftovers"]["networks"], 1)

    def test_readiness_accepts_only_structured_exact_container_state(self) -> None:
        plan = self._plan(("one", "auth"), fleet="state")

        class StateRunner(FakeRunner):
            def __init__(self, payload: str) -> None:
                super().__init__()
                self.payload = payload

            def __call__(self, command: tuple[str, ...], env: dict[str, str], timeout: float) -> validate.CommandResult:
                if command[:3] == ("podman", "ps", "-a"):
                    return validate.CommandResult(0, stdout=self.payload)
                return super().__call__(command, env, timeout)

        with tempfile.TemporaryDirectory() as directory:
            path = validate.compose_path(Path(directory), plan.instances[0])
            cases = (
                ("running", "readiness_unknown"),
                ('[{"State":"not running"}]', "readiness_unknown"),
                ('[{"Status":"running"}]', "readiness_unknown"),
                ('[{"State":"running"}]', "process_running"),
            )
            for payload, expected in cases:
                operation = validate.readiness_one(
                    plan.instances[0],
                    path,
                    runner=StateRunner(payload),
                )
                self.assertEqual(operation.status, expected, payload)

    def test_start_and_demo_cleanup_cover_worker_and_listing_exceptions(self) -> None:
        plan = self._plan(("one", "auth"), ("two", "auth"), fleet="exceptions")

        class ExplodingRunner(FakeRunner):
            def __call__(self, command: tuple[str, ...], env: dict[str, str], timeout: float) -> validate.CommandResult:
                if command and command[0] == "podman-compose":
                    project = command[command.index("-p") + 1]
                    if "up" in command and project == plan.instances[0].project:
                        raise RuntimeError("synthetic worker failure")
                    if "down" in command:
                        raise RuntimeError("synthetic cleanup failure")
                if command and command[0] == "podman" and command[1:3] in {
                    ("ps", "-a"),
                    ("network", "ls"),
                    ("volume", "ls"),
                }:
                    raise RuntimeError("synthetic listing failure")
                return super().__call__(command, env, timeout)

        runner = ExplodingRunner()
        with tempfile.TemporaryDirectory() as directory:
            result = validate.start_fleet(plan, Path(directory), runner=runner)
            self.assertEqual(result["status"], "failed")
            self.assertFalse(result["zero_leftovers"])
            self.assertTrue(all("leftovers" in item for item in result["instances"]))

        old = os.environ.get("HERMTERNAL_UPSTREAM_FLEET_VM_DEMO")
        os.environ["HERMTERNAL_UPSTREAM_FLEET_VM_DEMO"] = "1"
        try:
            with tempfile.TemporaryDirectory() as directory:
                result = validate.demo(Path(directory), runner=ExplodingRunner())
            self.assertEqual(result["status"], "cleanup_failed")
            self.assertFalse(result["zero_leftovers"])
        finally:
            if old is None:
                os.environ.pop("HERMTERNAL_UPSTREAM_FLEET_VM_DEMO", None)
            else:
                os.environ["HERMTERNAL_UPSTREAM_FLEET_VM_DEMO"] = old

    def test_endpoint_is_private_and_readiness_does_not_claim_compatibility(self) -> None:
        plan = self._plan(("one", "auth"), fleet="endpoint")
        endpoint = validate.endpoint_one(plan.instances[0])
        self.assertEqual(endpoint["endpoint"], "http://hermes:8000")
        self.assertFalse(endpoint["published"])
        with tempfile.TemporaryDirectory() as directory:
            path = validate.render_to_directory(plan, Path(directory))["one"]
            result = validate.readiness_fleet(plan, Path(directory), runner=FakeRunner())
            self.assertEqual(result["status"], "not_ready")
            self.assertFalse(any("compatibility" in item for item in result["instances"][0]))
            self.assertTrue(path.exists())
            self.assertIn("no_browser_or_chat_compatibility_claim", result["limitations"])

    def test_redaction_is_bounded_and_does_not_echo_sensitive_diagnostics(self) -> None:
        diagnostic = (
            "Authorization: Bearer secret-token https://provider.invalid/api "
            "/Users/tester/.hermes/config password=super-secret " + "x" * 900
        )
        redacted = validate.redacted_diagnostic(diagnostic)
        self.assertLessEqual(len(redacted), validate.MAX_DIAGNOSTIC_BYTES + 1)
        self.assertNotIn("secret-token", redacted)
        self.assertNotIn("provider.invalid", redacted)
        self.assertNotIn("/Users/tester", redacted)
        self.assertNotIn("super-secret", redacted)

    def test_subprocess_capture_is_utf8_byte_bounded_before_retention(self) -> None:
        script = (
            "import sys; "
            "sys.stdout.write('€' * 70000); "
            "sys.stderr.write('password=secret-token ' + '€' * 70000)"
        )
        result = validate.invoke((sys.executable, "-c", script))
        self.assertEqual(result.returncode, 0)
        self.assertLessEqual(len(result.stdout.encode("utf-8")), validate.MAX_CAPTURE_BYTES)
        self.assertLessEqual(len(result.stderr.encode("utf-8")), validate.MAX_CAPTURE_BYTES)
        self.assertNotIn("secret-token", validate.redacted_diagnostic(result.stderr))
        self.assertLessEqual(
            len(validate.redacted_diagnostic("é" * 5000).encode("utf-8")),
            validate.MAX_DIAGNOSTIC_BYTES + len("…".encode("utf-8")),
        )

    def test_cli_runs_in_normal_and_optimized_modes(self) -> None:
        for optimized in (False, True):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.extend(
                [
                    str(FIXTURE_DIR / "validate.py"),
                    "plan",
                    "--fleet-id",
                    "cli",
                    "--instance",
                    "one:auth",
                    "--instance",
                    "two:image-pty",
                ]
            )
            completed = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            output = json.loads(completed.stdout)
            self.assertEqual(output["reserved"]["cpu"], "2.25")
            self.assertEqual(output["image"]["reference"], validate.PINNED_IMAGE)

    def test_cli_invalid_budget_is_bounded_in_normal_and_optimized_modes(self) -> None:
        for optimized in (False, True):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.extend(
                [
                    str(FIXTURE_DIR / "validate.py"),
                    "plan",
                    "--fleet-id",
                    "too-many",
                    "--instance",
                    "one:image-pty",
                    "--instance",
                    "two:image-pty",
                    "--instance",
                    "three:image-pty",
                    "--instance",
                    "four:image-pty",
                    "--instance",
                    "five:image-pty",
                ]
            )
            completed = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(json.loads(completed.stdout)["reason"], "cpu_budget_exceeded")
            self.assertLess(len(completed.stdout), 512)

    def test_authorized_demo_reports_digest_plan_readiness_and_cleanup(self) -> None:
        old = os.environ.get("HERMTERNAL_UPSTREAM_FLEET_VM_DEMO")
        os.environ["HERMTERNAL_UPSTREAM_FLEET_VM_DEMO"] = "1"
        try:
            with tempfile.TemporaryDirectory() as directory:
                result = validate.demo(Path(directory), runner=FakeRunner())
            self.assertEqual(result["status"], "process_ready")
            self.assertEqual(result["teardown"], "removed")
            self.assertTrue(result["zero_leftovers"])
            self.assertEqual(result["official_image_evidence"]["repo_digest"], f"{validate.IMAGE_REPOSITORY}@{validate.PINNED_IMAGE_DIGEST}")
            self.assertEqual(result["instance"]["project"], "hermes-upstream-fleet-vm-demo-official")
            self.assertFalse(result["instance"]["published"])
            self.assertEqual(result["instance"]["leftovers"]["containers"], 0)
        finally:
            if old is None:
                os.environ.pop("HERMTERNAL_UPSTREAM_FLEET_VM_DEMO", None)
            else:
                os.environ["HERMTERNAL_UPSTREAM_FLEET_VM_DEMO"] = old

    def test_demo_authorization_fails_before_engine_call(self) -> None:
        old = os.environ.pop("HERMTERNAL_UPSTREAM_FLEET_VM_DEMO", None)
        try:
            runner = FakeRunner()
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(validate.ContractError, "vm_authorization_required"):
                    validate.demo(Path(directory), runner=runner)
            self.assertEqual(runner.calls, [])
        finally:
            if old is not None:
                os.environ["HERMTERNAL_UPSTREAM_FLEET_VM_DEMO"] = old


if __name__ == "__main__":
    unittest.main()
