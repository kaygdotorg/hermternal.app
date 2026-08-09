#!/usr/bin/env python3
"""Offline tests for the marker-owned disposable Hermes launcher.

All Podman and readiness boundaries are synthetic. The suite never starts a
container, contacts Hermes, opens an endpoint, or reads a real credential value.
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Mapping, Sequence
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "hermes_agent.py"
spec = importlib.util.spec_from_file_location("hermes_agent", SCRIPT)
if spec is None or spec.loader is None:
    raise RuntimeError(f"Could not load {SCRIPT}")
launcher = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = launcher
spec.loader.exec_module(launcher)


class FakePodman:
    """Small exact-ID Podman boundary with no real process or socket."""

    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], dict[str, str]]] = []
        self.containers: dict[str, dict[str, object]] = {}
        self.fail_run_for: set[str] = set()
        self.fail_start_for: set[str] = set()
        self.fail_stop_for: set[str] = set()
        self.fail_rm_for: set[str] = set()
        self._next_id = 1

    def _resolve(self, target: str) -> tuple[str, dict[str, object]] | None:
        document = self.containers.get(target)
        if document is not None:
            return target, document
        for name, candidate in self.containers.items():
            if candidate.get("Id") == target:
                return name, candidate
        return None

    def __call__(
        self,
        command: Sequence[str],
        environment: Mapping[str, str],
        timeout: float,
    ) -> launcher.CommandResult:
        del timeout
        command_tuple = tuple(command)
        self.calls.append((command_tuple, dict(environment)))
        args = command_tuple[1:]
        if args == ("info", "--format", "{{.Host.Security.Rootless}}"):
            return launcher.CommandResult(0, "true\n")
        if args[:1] == ("pull",):
            return launcher.CommandResult(0, "pulled\n")
        if args[:2] == ("image", "inspect"):
            image = args[2]
            return launcher.CommandResult(
                0,
                json.dumps([{"RepoDigests": [launcher.expected_repo_digest(image)]}]),
            )
        if args[:2] == ("container", "exists"):
            return launcher.CommandResult(0 if self._resolve(args[2]) is not None else 1, "")
        if args[:2] == ("container", "inspect"):
            resolved = self._resolve(args[2])
            if resolved is None:
                return launcher.CommandResult(1, "")
            return launcher.CommandResult(0, json.dumps([resolved[1]]))
        if args[:1] == ("run",):
            name = args[args.index("--name") + 1]
            if name in self.fail_run_for:
                return launcher.CommandResult(125, "synthetic-run-output-secret")
            labels: dict[str, str] = {}
            for index, value in enumerate(args):
                if value == "--label":
                    key, label_value = args[index + 1].split("=", 1)
                    labels[key] = label_value
            volume = args[args.index("--volume") + 1]
            image = args[-3]
            host_ip, host_port, container_port = args[args.index("--publish") + 1].split(":")
            container_id = f"{self._next_id:012x}" + ("a" * 52)
            self._next_id += 1
            if "--cidfile" in args:
                cidfile = Path(args[args.index("--cidfile") + 1])
                cidfile.write_text(container_id + "\n", encoding="ascii")
                cidfile.chmod(0o600)
            self.containers[name] = {
                "Id": container_id,
                "Name": f"/{name}",
                "ImageName": image,
                "Config": {"Labels": labels},
                "Mounts": [
                    {
                        "Type": "bind",
                        "Source": volume.removesuffix(":/opt/data"),
                        "Destination": "/opt/data",
                    }
                ],
                "NetworkSettings": {
                    "Ports": {
                        f"{container_port}/tcp": [{"HostIp": host_ip, "HostPort": host_port}]
                    }
                },
                "State": {"Status": "running"},
            }
            return launcher.CommandResult(0, container_id + "\n")
        if args[:1] == ("start",):
            target = args[1]
            resolved = self._resolve(target)
            if resolved is None or target in self.fail_start_for or resolved[0] in self.fail_start_for:
                return launcher.CommandResult(125, "synthetic-start-output-secret")
            state = resolved[1]["State"]
            assert isinstance(state, dict)
            state["Status"] = "running"
            return launcher.CommandResult(0, "synthetic-start-id\n")
        if args[:1] == ("stop",):
            target = args[1]
            resolved = self._resolve(target)
            if resolved is None or target in self.fail_stop_for or resolved[0] in self.fail_stop_for:
                return launcher.CommandResult(125, "synthetic-stop-output-secret")
            state = resolved[1]["State"]
            assert isinstance(state, dict)
            state["Status"] = "exited"
            return launcher.CommandResult(0, "")
        if args[:2] == ("rm", "--force"):
            target = args[2]
            resolved = self._resolve(target)
            if resolved is None or target in self.fail_rm_for or resolved[0] in self.fail_rm_for:
                return launcher.CommandResult(125, "synthetic-rm-output-secret")
            self.containers.pop(resolved[0], None)
            return launcher.CommandResult(0, "")
        raise AssertionError(f"Unexpected fake Podman command: {command_tuple!r}")


class HermesAgentLauncherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.runs = self.root / "runs"
        self.runs.mkdir(mode=0o700)
        self.runs.chmod(0o700)
        self.roots = launcher.Roots(
            state=self.root / "legacy-state",
            data=self.root / "data",
            credentials=self.root / "legacy-credentials",
        )
        self.fake = FakePodman()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def marker_path(self, name: str = "fixture.json") -> Path:
        return self.runs / name

    def make_spec(self, instance: str = "test-one", port: int = 19119):
        return launcher.make_spec(instance, port, roots=self.roots)

    @staticmethod
    def ready(endpoint: str, attempts: int, interval: float) -> None:
        del endpoint, attempts, interval

    def start(self, spec=None, *, marker_path: Path | None = None, readiness=None, **overrides):
        current_spec = spec or self.make_spec()
        runner = overrides.pop("runner", self.fake)
        return launcher.start_instance(
            current_spec,
            marker_path=marker_path or self.marker_path(),
            runner=runner,
            readiness=readiness or self.ready,
            port_checker=lambda port: True,
            executable="/usr/bin/podman",
            source_environment={"PATH": "/usr/bin"},
            attempts=1,
            interval=0,
            **overrides,
        )

    def load(self, path: Path | None = None):
        return launcher.load_launcher_state(path or self.marker_path(), self.roots)

    def test_default_image_is_exact_official_tag_and_digest(self) -> None:
        tag, digest = launcher.validate_image(launcher.DEFAULT_IMAGE)
        self.assertEqual(tag, "v2026.8.3")
        self.assertEqual(
            digest,
            "sha256:16788311e2fa3035456bdc1bafb8ec2b1777db64ebf020af9bb7eb73c3712c9e",
        )
        self.assertEqual(launcher.expected_repo_digest(launcher.DEFAULT_IMAGE), "docker.io/nousresearch/hermes-agent@" + digest)

    def test_mutable_or_nonofficial_images_fail_closed(self) -> None:
        digest = "a" * 64
        rejected = (
            f"docker.io/nousresearch/hermes-agent:latest@sha256:{digest}",
            f"docker.io/other/hermes-agent:v1@sha256:{digest}",
            "docker.io/nousresearch/hermes-agent:v1",
            f"docker.io/nousresearch/hermes-agent:v1@sha256:{digest.upper()}",
        )
        for image in rejected:
            with self.subTest(image=image), self.assertRaises(launcher.LauncherError) as raised:
                launcher.validate_image(image)
            self.assertEqual(raised.exception.code, "image_not_immutable_official")

    def test_marker_is_required_and_run_arguments_bind_the_run_id_label(self) -> None:
        spec = self.make_spec()
        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.start_instance(spec, runner=self.fake, executable="/usr/bin/podman", source_environment={"PATH": "/usr/bin"})
        self.assertEqual(raised.exception.code, "marker_required")

        run_id = "a" * 64
        command = launcher.run_arguments(spec, "/usr/bin/podman", run_id)
        self.assertIn(f"io.hermternal.run-id={run_id}", command)
        self.assertEqual(command[-3:], (spec.image, "gateway", "run"))
        self.assertIn("127.0.0.1:19119:9119", command)
        forbidden = {"build", "compose", "tag", "--network", "host", "--cpus", "--memory", "--pids-limit", "--cap-add", "--cap-drop", "--security-opt", "podman.sock", "docker.sock"}
        self.assertTrue(forbidden.isdisjoint(command), command)

    def test_batch_paths_are_caller_supplied_and_unique_specs_remain_deterministic(self) -> None:
        specs = launcher.specs_for_batch(
            "playwright", 3, 19120, image=launcher.DEFAULT_IMAGE, username=launcher.DEFAULT_USERNAME, roots=self.roots
        )
        paths = [self.marker_path(f"run-{index}.json") for index in range(1, 4)]
        self.assertEqual([item.instance for item in specs], ["playwright-1", "playwright-2", "playwright-3"])
        self.assertEqual([item.port for item in specs], [19120, 19121, 19122])
        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.start_many(specs, paths[:-1], runner=self.fake, executable="/usr/bin/podman", source_environment={"PATH": "/usr/bin"})
        self.assertEqual(raised.exception.code, "marker_count_invalid")

        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.start_many(specs, [paths[0], paths[0], paths[2]], runner=self.fake, executable="/usr/bin/podman", source_environment={"PATH": "/usr/bin"})
        self.assertEqual(raised.exception.code, "marker_not_unique")
        self.assertEqual(self.fake.calls, [])

    def test_environment_is_provider_free_and_remote_podman_is_rejected(self) -> None:
        cleaned = launcher.clean_environment(
            {
                "PATH": "/usr/bin",
                "DOCKER_HOST": "synthetic",
                "COMPOSE_FILE": "synthetic",
                "HERMES_PROVIDER": "synthetic",
                "OPENAI_API_KEY": "synthetic-secret",
                "SAFE": "kept",
            }
        )
        self.assertEqual(cleaned, {"PATH": "/usr/bin", "SAFE": "kept"})
        for name in ("CONTAINER_HOST", "CONTAINER_CONNECTION"):
            with self.subTest(name=name), self.assertRaises(launcher.LauncherError) as raised:
                launcher.clean_environment({name: "ssh://synthetic"})
            self.assertEqual(raised.exception.code, "remote_podman_rejected")

    def test_malformed_runner_results_normalize_to_stable_launcher_errors(self) -> None:
        malformed = (
            object(),
            launcher.CommandResult(True, ""),
            launcher.CommandResult(256, ""),
            launcher.CommandResult(0, "x" * (launcher.MAX_COMMAND_BYTES + 1)),
            launcher.CommandResult(0, "", "x" * (launcher.MAX_COMMAND_BYTES + 1)),
        )
        for result in malformed:
            with self.subTest(result=type(result).__name__):
                with self.assertRaises(launcher.LauncherError) as raised:
                    launcher.invoke_runner(
                        lambda command, environment, timeout, result=result: result,
                        ("synthetic-runner",),
                        {"PATH": "/usr/bin"},
                        1,
                        failure_code="runner_result_invalid",
                    )
                self.assertEqual(raised.exception.code, "runner_result_invalid")

    def test_new_run_creates_fresh_scoped_credential_state_and_marker_without_secret_or_run_id_output(self) -> None:
        spec = self.make_spec()
        result, created = self.start(spec)
        self.assertTrue(created)
        state = self.load()
        bound = state.marker
        self.assertEqual(bound.status, "running")
        self.assertEqual(bound.instance, spec.instance)
        self.assertRegex(bound.run_id, r"^[0-9a-f]{64}$")
        self.assertEqual(bound.credential_path, self.runs / "fixture.credential")
        self.assertEqual(bound.state_path, self.runs / "fixture.state.json")
        self.assertEqual(stat.S_IMODE(bound.credential_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(bound.state_path.stat().st_mode), 0o600)
        password = bound.credential_path.read_text(encoding="ascii").strip()
        self.assertRegex(password, r"^[0-9a-f]{48}$")
        public = json.dumps(result)
        self.assertNotIn(password, public)
        self.assertNotIn(bound.run_id, public)
        self.assertNotIn(password, bound.state_path.read_text(encoding="utf-8"))
        self.assertNotIn(bound.run_id, result.get("marker_path", ""))

        run_count = sum(command[1] == "run" for command, _ in self.fake.calls)
        self.assertEqual(run_count, 1)
        run_command, environment = next((command, env) for command, env in self.fake.calls if command[1] == "run")
        self.assertEqual(environment["HERMES_DASHBOARD_BASIC_AUTH_PASSWORD"], password)
        self.assertNotIn(password, run_command)
        self.assertIn(f"io.hermternal.run-id={bound.run_id}", run_command)

    def test_credential_replacement_before_marker_publication_is_not_adopted(self) -> None:
        spec = self.make_spec()
        original_revalidate = launcher._revalidate_credential_identity
        replaced = False

        def race_credential(binding, *, parent_fd):
            nonlocal replaced
            if binding.credential_path.name == "fixture.credential" and not replaced:
                replaced = True
                replacement = self.runs / "credential-prepublish-replacement"
                replacement.write_bytes(b"replacement-credential")
                replacement.chmod(0o600)
                binding.credential_path.unlink()
                replacement.rename(binding.credential_path)
            return original_revalidate(binding, parent_fd=parent_fd)

        with mock.patch.object(launcher, "_revalidate_credential_identity", side_effect=race_credential):
            with self.assertRaises(launcher.LauncherError) as raised:
                self.start(spec)
        self.assertEqual(raised.exception.code, "credential_identity_mismatch")
        self.assertTrue(replaced)
        self.assertEqual((self.runs / "fixture.credential").read_bytes(), b"replacement-credential")
        self.assertEqual(len(self.fake.containers), 1)
        self.assertEqual(self.load().marker.status, "cleanup_failed")

    def test_marker_constructor_failure_still_cleans_exact_started_container(self) -> None:
        spec = self.make_spec()
        with mock.patch.object(
            launcher.live_run_marker,
            "new_marker",
            side_effect=launcher.live_run_marker.MarkerError("marker_schema_invalid"),
        ):
            with self.assertRaises(launcher.LauncherError) as raised:
                self.start(spec)
        self.assertEqual(raised.exception.code, "marker_schema_invalid")
        self.assertEqual(self.fake.containers, {})
        self.assertFalse(self.marker_path().exists())
        self.assertFalse((self.runs / "fixture.state.json").exists())
        self.assertFalse((self.runs / "fixture.credential").exists())

    def test_state_sync_failure_cleans_created_state_inode_without_orphan(self) -> None:
        original_sync = launcher._sync_parent

        def fail_state_sync(path: Path, code: str, *, parent_fd: int | None = None) -> None:
            if path.name == "fixture.state.json":
                self.assertIsNotNone(parent_fd)
                raise launcher.LauncherError("state_sync_failed")
            original_sync(path, code, parent_fd=parent_fd)

        with mock.patch.object(launcher, "_sync_parent", side_effect=fail_state_sync):
            with self.assertRaises(launcher.LauncherError) as raised:
                self.start(self.make_spec())
        self.assertEqual(raised.exception.code, "state_sync_failed")
        self.assertEqual(self.fake.containers, {})
        for path in (
            self.marker_path(),
            self.runs / "fixture.state.json",
            self.runs / "fixture.credential",
            self.runs / "fixture.cidfile",
        ):
            self.assertFalse(path.exists(), path)

    def test_runs_directory_replacement_fails_closed_without_publishing_into_new_directory(self) -> None:
        spec = self.make_spec()
        moved = self.root / "runs-original"

        def replace_runs_directory(command, environment, timeout):
            result = self.fake(command, environment, timeout)
            if len(command) > 1 and command[1] == "run":
                self.runs.rename(moved)
                self.runs.mkdir(mode=launcher.live_run_marker.RUNS_DIR_MODE)
                self.runs.chmod(launcher.live_run_marker.RUNS_DIR_MODE)
            return result

        with self.assertRaises(launcher.LauncherError) as raised:
            self.start(spec, runner=replace_runs_directory)
        self.assertEqual(raised.exception.code, "runs_dir_replaced")
        self.assertFalse(any(self.runs.iterdir()))
        self.assertTrue((moved / "fixture.json").exists())
        self.assertEqual(len(self.fake.containers), 1)

    def test_status_rejects_runs_directory_swap_after_runner(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        moved = self.root / "runs-status-original"

        def swap_after_preflight(command, environment, timeout):
            result = self.fake(command, environment, timeout)
            if len(command) > 1 and command[1] == "info":
                self.runs.rename(moved)
                self.runs.mkdir(mode=launcher.live_run_marker.RUNS_DIR_MODE)
                self.runs.chmod(launcher.live_run_marker.RUNS_DIR_MODE)
            return result

        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.status_instance(
                self.marker_path(),
                roots=self.roots,
                runner=swap_after_preflight,
                executable="/usr/bin/podman",
                source_environment={"PATH": "/usr/bin"},
            )
        self.assertEqual(raised.exception.code, "runs_dir_replaced")
        self.assertFalse((self.runs / "fixture.json").exists())
        self.assertTrue((moved / "fixture.json").exists())
        self.assertEqual(len(self.fake.containers), 1)

    def test_stop_rejects_runs_directory_swap_after_runner_and_tombstones_held_dir(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        moved = self.root / "runs-stop-original"

        def swap_after_preflight(command, environment, timeout):
            result = self.fake(command, environment, timeout)
            if len(command) > 1 and command[1] == "info":
                self.runs.rename(moved)
                self.runs.mkdir(mode=launcher.live_run_marker.RUNS_DIR_MODE)
                self.runs.chmod(launcher.live_run_marker.RUNS_DIR_MODE)
            return result

        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.stop_instance(
                self.marker_path(),
                roots=self.roots,
                runner=swap_after_preflight,
                executable="/usr/bin/podman",
                source_environment={"PATH": "/usr/bin"},
            )
        self.assertEqual(raised.exception.code, "runs_dir_replaced")
        self.assertFalse((self.runs / "fixture.json").exists())
        moved_document = json.loads((moved / "fixture.json").read_text(encoding="utf-8"))
        self.assertEqual(moved_document["status"], "cleanup_failed")
        self.assertEqual(len(self.fake.containers), 1)

    def test_execute_endpoint_rejects_runs_directory_swap_after_runner(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        moved = self.root / "runs-execute-original"
        args = type(
            "Args",
            (),
            {
                "operation": "endpoint",
                "marker": str(self.marker_path()),
                "state_root": str(self.roots.state),
                "data_root": str(self.roots.data),
                "credential_root": str(self.roots.credentials),
            },
        )()

        def fake_endpoint(state):
            launcher.invoke_runner(
                self.fake,
                ("/usr/bin/podman", "info", "--format", "{{.Host.Security.Rootless}}"),
                {"PATH": "/usr/bin"},
                15,
                failure_code="podman_preflight_failed",
            )
            self.runs.rename(moved)
            self.runs.mkdir(mode=launcher.live_run_marker.RUNS_DIR_MODE)
            self.runs.chmod(launcher.live_run_marker.RUNS_DIR_MODE)
            return {"status": "running", "endpoint": state.marker.endpoint}

        with mock.patch.object(launcher, "verify_handoff_endpoint", side_effect=fake_endpoint):
            with self.assertRaises(launcher.LauncherError) as raised:
                launcher.execute(args)
        self.assertEqual(raised.exception.code, "runs_dir_replaced")
        self.assertFalse((self.runs / "fixture.json").exists())
        self.assertTrue((moved / "fixture.json").exists())

    def test_quarantine_count_and_bytes_quota_never_delete_foreign_slots(self) -> None:
        for index in range(launcher.live_run_marker.QUARANTINE_SLOT_COUNT):
            occupied = self.runs / f".cleanup-{index:02x}"
            occupied.write_bytes(b"foreign")
            occupied.chmod(0o600)
        target = self.runs / "quota-target"
        target.write_bytes(b"owned")
        target.chmod(0o600)
        with self.assertRaises(launcher.LauncherError) as raised:
            launcher._remove_exact_file(target, code="quota_remove_failed")
        self.assertEqual(raised.exception.code, "quarantine_quota_exceeded")
        self.assertTrue(target.exists())
        self.assertEqual((self.runs / ".cleanup-00").read_bytes(), b"foreign")

        for name in launcher.live_run_marker.quarantine_slot_names("cleanup"):
            path = self.runs / name
            if path.exists():
                path.unlink()
        oversized = self.runs / ".cleanup-00"
        oversized.write_bytes(b"x" * launcher.live_run_marker.QUARANTINE_MAX_BYTES)
        oversized.chmod(0o600)
        target.write_bytes(b"owned")
        target.chmod(0o600)
        with self.assertRaises(launcher.LauncherError) as raised:
            launcher._remove_exact_file(target, code="quota_remove_failed")
        self.assertEqual(raised.exception.code, "quarantine_quota_exceeded")
        self.assertTrue(target.exists())
        self.assertEqual(oversized.stat().st_size, launcher.live_run_marker.QUARANTINE_MAX_BYTES)

    def test_quota_exhaustion_retains_cleanup_failed_tombstone_without_growth(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        for name in launcher.live_run_marker.quarantine_slot_names("cleanup"):
            occupied = self.runs / name
            occupied.write_bytes(b"foreign")
            occupied.chmod(0o600)
        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.stop_instance(
                self.marker_path(),
                roots=self.roots,
                runner=self.fake,
                executable="/usr/bin/podman",
                source_environment={"PATH": "/usr/bin"},
            )
        self.assertEqual(raised.exception.code, "quarantine_quota_exceeded")
        tombstone = self.load()
        self.assertEqual(tombstone.marker.status, "cleanup_failed")
        self.assertEqual(json.loads(tombstone.marker.state_path.read_text(encoding="utf-8"))["status"], "cleanup_failed")
        self.assertEqual(len(self.fake.containers), 0)
        parent_fd = os.open(self.runs, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            count, _ = launcher.live_run_marker.quarantine_usage(parent_fd)
        finally:
            os.close(parent_fd)
        # The initial marker publication retains one replace-tmp staging slot;
        # quota fallback rewrites in place and allocates no additional evidence.
        self.assertEqual(count, launcher.live_run_marker.QUARANTINE_SLOT_COUNT + 1)
        self.assertLessEqual(count, launcher.live_run_marker.QUARANTINE_MAX_ENTRIES)

    def test_marker_and_state_serialization_limits_apply_before_write(self) -> None:
        value = launcher.live_run_marker.new_marker(
            self.marker_path(),
            run_id="a" * 64,
            instance="fixture-one",
            container_id="b" * 64,
            container_name="hermternal-hermes-fixture-one",
            image=launcher.DEFAULT_IMAGE,
            endpoint="http://127.0.0.1:19119",
            credential_identity=launcher.live_run_marker.CredentialIdentity(1, 2, 0o600, 49, 1),
        )
        with mock.patch.object(launcher.live_run_marker, "MAX_MARKER_BYTES", 1):
            with self.assertRaises(launcher.live_run_marker.MarkerError) as raised:
                launcher.live_run_marker.create_marker(value)
        self.assertEqual(raised.exception.code, "marker_too_large")

        self.start(self.make_spec())
        state = self.load()
        with mock.patch.object(launcher, "MAX_STATE_BYTES", 1):
            with self.assertRaises(launcher.LauncherError) as raised:
                launcher.write_state(self.make_spec(), state.marker, replace=True, expected=state.state_identity)
        self.assertEqual(raised.exception.code, "instance_state_too_large")

    def test_runner_raise_after_creation_uses_cidfile_and_never_name_adopts(self) -> None:
        def raise_after_run(command, environment, timeout):
            result = self.fake(command, environment, timeout)
            if len(command) > 1 and command[1] == "run":
                raise RuntimeError("synthetic runner boundary secret")
            return result

        with self.assertRaises(launcher.LauncherError) as raised:
            self.start(self.make_spec(), runner=raise_after_run)
        self.assertEqual(raised.exception.code, "container_start_failed")
        self.assertEqual(self.fake.containers, {})
        run_id = next(command for command, _ in self.fake.calls if command[1] == "run")
        removed = [command for command, _ in self.fake.calls if command[1:3] == ("rm", "--force")]
        self.assertEqual(len(removed), 1)
        self.assertRegex(removed[0][3], r"^[0-9a-f]{64}$")
        self.assertNotEqual(removed[0][3], launcher.CONTAINER_PREFIX + self.make_spec().instance)
        self.assertIn("--cidfile", run_id)
        self.assertFalse(self.marker_path().exists())
        self.assertFalse((self.runs / "fixture.state.json").exists())
        self.assertFalse((self.runs / "fixture.credential").exists())
        self.assertFalse((self.runs / "fixture.cidfile").exists())

    def test_runner_raise_without_cidfile_keeps_unknown_container_and_private_tombstone(self) -> None:
        def raise_without_cidfile(command, environment, timeout):
            result = self.fake(command, environment, timeout)
            if len(command) > 1 and command[1] == "run":
                cidfile = Path(command[command.index("--cidfile") + 1])
                cidfile.unlink()
                raise RuntimeError("synthetic unknown-run secret")
            return result

        with self.assertRaises(launcher.LauncherError) as raised:
            self.start(self.make_spec(), runner=raise_without_cidfile)
        self.assertEqual(raised.exception.code, "container_start_failed")
        self.assertEqual(len(self.fake.containers), 1)
        tombstone = launcher.load_launcher_state(self.marker_path(), self.roots)
        self.assertEqual(tombstone.marker.status, "cleanup_failed")
        self.assertEqual(tombstone.marker.container_id, launcher.UNPROVEN_CONTAINER_ID)
        self.assertFalse(tombstone.marker.credential_path.exists())

        result = launcher.stop_instance(
            self.marker_path(),
            roots=self.roots,
            runner=self.fake,
            executable="/usr/bin/podman",
            source_environment={"PATH": "/usr/bin"},
        )
        self.assertEqual(result["status"], "removed")
        self.assertEqual(len(self.fake.containers), 1)

    def test_success_without_cidfile_never_falls_back_to_stdout(self) -> None:
        def return_without_cidfile(command, environment, timeout):
            result = self.fake(command, environment, timeout)
            if len(command) > 1 and command[1] == "run":
                Path(command[command.index("--cidfile") + 1]).unlink()
            return result

        with mock.patch.object(launcher, "container_id_from_run_result", side_effect=AssertionError("stdout fallback")):
            with self.assertRaises(launcher.LauncherError) as raised:
                self.start(self.make_spec(), runner=return_without_cidfile)
        self.assertEqual(raised.exception.code, "cidfile_missing")
        tombstone = self.load()
        self.assertEqual(tombstone.marker.status, "cleanup_failed")
        self.assertEqual(tombstone.marker.container_id, launcher.UNPROVEN_CONTAINER_ID)
        self.assertEqual(len(self.fake.containers), 1)
        self.assertFalse(tombstone.marker.credential_path.exists())

    def test_foreign_cidfile_is_not_adopted_and_retains_cleanup_tombstone(self) -> None:
        spec = self.make_spec()
        foreign_id = "e" * 64
        self.fake.containers["foreign-container"] = {
            "Id": foreign_id,
            "Name": "/foreign-container",
            "ImageName": spec.image,
            "Config": {"Labels": {}},
            "Mounts": [],
            "NetworkSettings": {"Ports": {}},
            "State": {"Status": "running"},
        }

        def raise_with_foreign_cidfile(command, environment, timeout):
            result = self.fake(command, environment, timeout)
            if len(command) > 1 and command[1] == "run":
                cidfile = Path(command[command.index("--cidfile") + 1])
                cidfile.write_text(f"{foreign_id}\n", encoding="ascii")
                cidfile.chmod(0o600)
                raise RuntimeError("synthetic foreign cidfile")
            return result

        with self.assertRaises(launcher.LauncherError) as raised:
            self.start(spec, runner=raise_with_foreign_cidfile)
        self.assertEqual(raised.exception.code, "container_start_failed")
        tombstone = self.load()
        self.assertEqual(tombstone.marker.status, "cleanup_failed")
        self.assertEqual(tombstone.marker.container_id, launcher.UNPROVEN_CONTAINER_ID)
        self.assertIn(spec.container, self.fake.containers)
        self.assertIn("foreign-container", self.fake.containers)

    def test_runner_inspect_and_remove_exceptions_are_normalized_and_tombstoned(self) -> None:
        def raise_on_inspect(command, environment, timeout):
            result = self.fake(command, environment, timeout)
            if command[1:3] == ("container", "inspect"):
                raise RuntimeError("synthetic inspect secret")
            return result

        with self.assertRaises(launcher.LauncherError) as raised:
            self.start(self.make_spec(), runner=raise_on_inspect)
        self.assertEqual(raised.exception.code, "container_inspect_failed")
        self.assertEqual(launcher.live_run_marker.load_marker(self.marker_path()).status, "cleanup_failed")
        self.assertTrue((self.runs / "fixture.state.json").exists())
        self.assertTrue((self.runs / "fixture.credential").exists())
        self.assertEqual(len(self.fake.containers), 1)

        def raise_on_remove(command, environment, timeout):
            if command[1:3] == ("rm", "--force"):
                raise RuntimeError("synthetic remove secret")
            return self.fake(command, environment, timeout)

        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.stop_instance(
                self.marker_path(),
                roots=self.roots,
                runner=raise_on_remove,
                executable="/usr/bin/podman",
                source_environment={"PATH": "/usr/bin"},
            )
        self.assertEqual(raised.exception.code, "container_remove_failed")
        self.assertEqual(launcher.live_run_marker.load_marker(self.marker_path()).status, "cleanup_failed")
        self.assertEqual(len(self.fake.containers), 1)

    def test_new_run_never_adopts_same_name_replacement_after_run(self) -> None:
        spec = self.make_spec()
        original_id: str | None = None

        def replace_after_run(command, environment, timeout):
            nonlocal original_id
            result = self.fake(command, environment, timeout)
            if len(command) > 1 and command[1] == "run":
                original = self.fake.containers[spec.container]
                original_id = str(original["Id"])
                original["Id"] = "d" * 64
            return result

        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.start_instance(
                spec,
                marker_path=self.marker_path(),
                runner=replace_after_run,
                readiness=self.ready,
                port_checker=lambda port: True,
                executable="/usr/bin/podman",
                source_environment={"PATH": "/usr/bin"},
                attempts=1,
                interval=0,
            )
        self.assertEqual(raised.exception.code, "container_inspect_failed")
        self.assertIsNotNone(original_id)
        self.assertIn(spec.container, self.fake.containers)
        self.assertEqual(self.fake.containers[spec.container]["Id"], "d" * 64)
        inspect_calls = [command for command, _ in self.fake.calls if command[1:3] == ("container", "inspect")]
        self.assertTrue(inspect_calls)
        self.assertEqual(inspect_calls[0][3], original_id)
        self.assertFalse(self.marker_path().exists())
        self.assertFalse((self.runs / "fixture.state.json").exists())
        self.assertFalse((self.runs / "fixture.credential").exists())
        self.assertFalse(any(command[1] == "rm" for command, _ in self.fake.calls))
        self.assertFalse(any(command[1] == "start" for command, _ in self.fake.calls))
        self.assertTrue(any(command[1:4] == ("container", "exists", original_id) for command, _ in self.fake.calls))

    def test_same_marker_reuses_one_running_instance_without_second_run_or_fresh_credential(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        original = self.load().marker
        original_credential = original.credential_path.read_bytes()
        self.fake.calls.clear()
        result, created = self.start(spec)
        self.assertFalse(created)
        self.assertFalse(result["created"])
        self.assertEqual(self.load().marker.run_id, original.run_id)
        self.assertEqual(original.credential_path.read_bytes(), original_credential)
        self.assertFalse(any(command[1] == "run" for command, _ in self.fake.calls))

    def test_different_marker_cannot_adopt_or_start_a_second_shared_instance(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        self.fake.calls.clear()
        other = self.marker_path("other.json")
        with self.assertRaises(launcher.LauncherError) as raised:
            self.start(spec, marker_path=other)
        self.assertEqual(raised.exception.code, "marker_missing")
        self.assertFalse(other.exists())
        self.assertEqual(len(self.fake.containers), 1)
        self.assertFalse(any(command[1] == "run" for command, _ in self.fake.calls if command[1] == "run"))

    def test_existing_unmarked_stopped_container_is_never_started(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        self.fake.containers[spec.container]["State"] = {"Status": "exited"}
        marker = self.marker_path()
        marker.unlink()
        self.load_marker_cleanup_files()
        self.fake.calls.clear()
        with self.assertRaises(launcher.LauncherError) as raised:
            self.start(spec)
        self.assertEqual(raised.exception.code, "marker_missing")
        lifecycle = [command[1:] for command, _ in self.fake.calls if command[1] in {"start", "stop", "rm"}]
        self.assertEqual(lifecycle, [])

    def load_marker_cleanup_files(self) -> None:
        for path in (self.runs / "fixture.state.json", self.runs / "fixture.credential"):
            if path.exists():
                path.unlink()

    def test_endpoint_selects_only_fully_bound_running_marker_and_releases_bounded_paths(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        state = self.load()
        result = launcher.verify_handoff_endpoint(
            state,
            runner=self.fake,
            executable="/usr/bin/podman",
            source_environment={"PATH": "/usr/bin"},
        )
        self.assertEqual(
            result,
            {
                "status": "running",
                "endpoint": spec.endpoint,
                "marker_path": str(self.marker_path()),
                "run_id": state.run_id,
                "credential_file": str(self.runs / "fixture.credential"),
                "credential_identity": state.marker.credential_identity.document(),
            },
        )
        credential = state.marker.credential_path.read_text(encoding="ascii")
        self.assertNotIn(credential.strip(), json.dumps(result))
        self.assertIn(state.run_id, json.dumps(result))
        self.assertEqual(self.fake.calls[-1][0][1:3], ("container", "inspect"))
        self.assertEqual(self.fake.calls[-1][0][3], state.container_id)

    def test_endpoint_rejects_stale_copied_symlink_and_replaced_resources_before_contact(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        original = self.load().marker
        copied = self.marker_path("copied.json")
        copied.write_bytes(original.marker_path.read_bytes())
        copied.chmod(0o600)
        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.execute(type("Args", (), {"operation": "endpoint", "marker": str(copied), "state_root": str(self.roots.state), "data_root": str(self.roots.data), "credential_root": str(self.roots.credentials)})())
        self.assertEqual(raised.exception.code, "marker_path_mismatch")

        self.fake.containers[spec.container]["Config"] = {"Labels": {}}
        self.fake.calls.clear()
        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.verify_handoff_endpoint(self.load(), runner=self.fake, executable="/usr/bin/podman", source_environment={"PATH": "/usr/bin"})
        self.assertEqual(raised.exception.code, "container_not_launcher_owned")
        self.assertEqual(self.fake.calls[-1][0][3], original.container_id)

        self.fake.containers[spec.container]["Config"] = {"Labels": {launcher.MANAGED_LABEL: launcher.MANAGED_VERSION}}
        with self.assertRaises(launcher.LauncherError):
            launcher.verify_handoff_endpoint(self.load(), runner=self.fake, executable="/usr/bin/podman", source_environment={"PATH": "/usr/bin"})

    def test_endpoint_rejects_mapping_and_credential_identity_replacements(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        state = self.load()
        ports = self.fake.containers[spec.container]["NetworkSettings"]["Ports"]
        assert isinstance(ports, dict)
        ports["9119/tcp"] = [{"HostIp": "0.0.0.0", "HostPort": str(spec.port)}]
        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.verify_handoff_endpoint(state, runner=self.fake, executable="/usr/bin/podman", source_environment={"PATH": "/usr/bin"})
        self.assertEqual(raised.exception.code, "container_endpoint_unproven")

        ports["9119/tcp"] = [{"HostIp": "127.0.0.1", "HostPort": str(spec.port)}]
        replacement = self.runs / "replacement"
        replacement.write_bytes(state.marker.credential_path.read_bytes())
        replacement.chmod(0o600)
        state.marker.credential_path.unlink()
        replacement.rename(state.marker.credential_path)
        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.verify_handoff_endpoint(state, runner=self.fake, executable="/usr/bin/podman", source_environment={"PATH": "/usr/bin"})
        self.assertEqual(raised.exception.code, "credential_identity_mismatch")

    def test_endpoint_rejects_same_inode_same_size_marker_mutation(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        state = self.load()
        document = json.loads(state.marker_path.read_text(encoding="utf-8"))
        document["endpoint"] = document["endpoint"][:-1] + "0"
        replacement = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        original = state.marker_path.read_bytes()
        self.assertEqual(len(replacement), len(original))
        descriptor = os.open(state.marker_path, os.O_RDWR | getattr(os, "O_CLOEXEC", 0))
        try:
            self.assertEqual(os.pwrite(descriptor, replacement, 0), len(replacement))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self.fake.calls.clear()
        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.verify_handoff_endpoint(
                state,
                runner=self.fake,
                executable="/usr/bin/podman",
                source_environment={"PATH": "/usr/bin"},
            )
        self.assertEqual(raised.exception.code, "marker_replaced")
        self.assertEqual(self.fake.calls, [])

    def test_endpoint_rejects_same_inode_same_size_state_mutation(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        state = self.load()
        document = json.loads(state.marker.state_path.read_text(encoding="utf-8"))
        document["username"] = document["username"][:-1] + "x"
        replacement = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        original = state.marker.state_path.read_bytes()
        self.assertEqual(len(replacement), len(original))
        descriptor = os.open(state.marker.state_path, os.O_RDWR | getattr(os, "O_CLOEXEC", 0))
        try:
            self.assertEqual(os.pwrite(descriptor, replacement, 0), len(replacement))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self.fake.calls.clear()
        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.verify_handoff_endpoint(
                state,
                runner=self.fake,
                executable="/usr/bin/podman",
                source_environment={"PATH": "/usr/bin"},
            )
        self.assertEqual(raised.exception.code, "state_replaced")
        self.assertEqual(self.fake.calls, [])

    def test_new_run_wildcard_mapping_is_cleaned_by_exact_marker(self) -> None:
        spec = self.make_spec()

        def wildcard_after_run(command, environment, timeout):
            result = self.fake(command, environment, timeout)
            if len(command) > 1 and command[1] == "run":
                ports = self.fake.containers[spec.container]["NetworkSettings"]["Ports"]
                assert isinstance(ports, dict)
                ports["9119/tcp"][0]["HostIp"] = "0.0.0.0"
            return result

        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.start_instance(
                spec,
                marker_path=self.marker_path(),
                runner=wildcard_after_run,
                readiness=self.ready,
                port_checker=lambda port: True,
                executable="/usr/bin/podman",
                source_environment={"PATH": "/usr/bin"},
                attempts=1,
                interval=0,
            )
        self.assertEqual(raised.exception.code, "container_endpoint_unproven")
        self.assertEqual(self.fake.containers, {})
        self.assertFalse(self.marker_path().exists())
        self.assertFalse((self.runs / "fixture.state.json").exists())
        self.assertFalse((self.runs / "fixture.credential").exists())

    def test_new_run_mapping_failure_retains_tombstone_when_exact_cleanup_fails(self) -> None:
        spec = self.make_spec()
        self.fake.fail_rm_for.add(spec.container)

        def wildcard_after_run(command, environment, timeout):
            result = self.fake(command, environment, timeout)
            if len(command) > 1 and command[1] == "run":
                ports = self.fake.containers[spec.container]["NetworkSettings"]["Ports"]
                assert isinstance(ports, dict)
                ports["9119/tcp"][0]["HostIp"] = "0.0.0.0"
            return result

        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.start_instance(
                spec,
                marker_path=self.marker_path(),
                runner=wildcard_after_run,
                readiness=self.ready,
                port_checker=lambda port: True,
                executable="/usr/bin/podman",
                source_environment={"PATH": "/usr/bin"},
                attempts=1,
                interval=0,
            )
        self.assertEqual(raised.exception.code, "container_endpoint_unproven")
        self.assertIn(spec.container, self.fake.containers)
        self.assertEqual(launcher.live_run_marker.load_marker(self.marker_path()).status, "cleanup_failed")
        self.assertTrue((self.runs / "fixture.state.json").exists())
        self.assertTrue((self.runs / "fixture.credential").exists())

    def test_container_label_run_id_mismatch_never_starts_or_contacts_endpoint(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        state = self.load()
        labels = self.fake.containers[spec.container]["Config"]["Labels"]
        assert isinstance(labels, dict)
        labels["io.hermternal.run-id"] = "f" * 64
        self.fake.calls.clear()
        with self.assertRaises(launcher.LauncherError) as raised:
            self.start(spec)
        self.assertEqual(raised.exception.code, "container_not_launcher_owned")
        self.assertFalse(any(command[1] in {"start", "stop", "rm"} for command, _ in self.fake.calls))

    def test_stopped_bound_container_starts_only_by_pinned_id_and_rolls_back_exactly(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        state = self.load()
        self.fake.containers[spec.container]["State"] = {"Status": "exited"}
        self.fake.calls.clear()
        result, created = self.start(spec)
        self.assertFalse(created)
        self.assertEqual(result["status"], "ready")
        lifecycle = [command[1:] for command, _ in self.fake.calls if command[1] in {"start", "stop"}]
        self.assertEqual(lifecycle, [("start", state.container_id)])

        self.fake.containers[spec.container]["State"] = {"Status": "exited"}

        def not_ready(endpoint: str, attempts: int, interval: float) -> None:
            del endpoint, attempts, interval
            raise launcher.LauncherError("provider_readiness_timeout")

        with self.assertRaises(launcher.LauncherError) as raised:
            self.start(spec, readiness=not_ready)
        self.assertEqual(raised.exception.code, "provider_readiness_timeout")
        self.assertEqual(self.fake.containers[spec.container]["State"]["Status"], "exited")
        lifecycle = [command[1:] for command, _ in self.fake.calls if command[1] in {"start", "stop"}]
        self.assertEqual(lifecycle[-2:], [("start", state.container_id), ("stop", state.container_id)])

    def test_readiness_failure_uses_marker_cleanup_and_removes_only_pinned_files(self) -> None:
        spec = self.make_spec()

        def not_ready(endpoint: str, attempts: int, interval: float) -> None:
            del endpoint, attempts, interval
            raise launcher.LauncherError("provider_readiness_timeout")

        with self.assertRaises(launcher.LauncherError) as raised:
            self.start(spec, readiness=not_ready)
        self.assertEqual(raised.exception.code, "provider_readiness_timeout")
        self.assertEqual(self.fake.containers, {})
        self.assertFalse(self.marker_path().exists())
        self.assertFalse((self.runs / "fixture.state.json").exists())
        self.assertFalse((self.runs / "fixture.credential").exists())
        self.assertTrue(self.runs.is_dir())

    def test_cleanup_failure_retains_bounded_cleanup_failed_tombstone_and_retry_is_exact(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        state = self.load()
        self.fake.fail_rm_for.add(spec.container)
        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.stop_instance(self.marker_path(), roots=self.roots, runner=self.fake, executable="/usr/bin/podman", source_environment={"PATH": "/usr/bin"})
        self.assertEqual(raised.exception.code, "container_remove_failed")
        tombstone = launcher.load_launcher_state(self.marker_path(), self.roots)
        self.assertEqual(tombstone.marker.status, "cleanup_failed")
        self.assertTrue(self.marker_path().exists())
        self.assertTrue(tombstone.marker.credential_path.exists())
        self.assertTrue(tombstone.marker.state_path.exists())
        self.assertEqual(len(self.fake.containers), 1)

        self.fake.fail_rm_for.clear()
        result = launcher.stop_instance(self.marker_path(), roots=self.roots, runner=self.fake, executable="/usr/bin/podman", source_environment={"PATH": "/usr/bin"})
        self.assertEqual(result["status"], "removed")
        self.assertFalse(self.marker_path().exists())
        self.assertFalse(tombstone.marker.credential_path.exists())
        self.assertFalse(tombstone.marker.state_path.exists())
        self.assertEqual(self.fake.containers, {})

    def test_cleanup_marker_unlink_failure_recreates_tombstone_for_exact_retry(self) -> None:
        spec = self.make_spec()
        self.start(spec)

        def fail_marker_unlink(
            current: launcher.LauncherState,
            expected: launcher.FileIdentity,
            *,
            parent_fd: int | None = None,
        ) -> None:
            del current, expected, parent_fd
            raise launcher.LauncherError("marker_remove_failed")

        with mock.patch.object(launcher, "_remove_marker_last", side_effect=fail_marker_unlink):
            with self.assertRaises(launcher.LauncherError) as raised:
                launcher.stop_instance(
                    self.marker_path(),
                    roots=self.roots,
                    runner=self.fake,
                    executable="/usr/bin/podman",
                    source_environment={"PATH": "/usr/bin"},
                )
        self.assertEqual(raised.exception.code, "marker_remove_failed")
        tombstone = self.load()
        self.assertEqual(tombstone.marker.status, "cleanup_failed")
        self.assertTrue(tombstone.marker.state_path.exists())
        self.assertFalse(tombstone.marker.credential_path.exists())
        self.assertEqual(self.fake.containers, {})

        result = launcher.stop_instance(
            self.marker_path(),
            roots=self.roots,
            runner=self.fake,
            executable="/usr/bin/podman",
            source_environment={"PATH": "/usr/bin"},
        )
        self.assertEqual(result["status"], "removed")
        self.assertFalse(self.marker_path().exists())
        self.assertFalse(tombstone.marker.state_path.exists())

    def test_cleanup_does_not_overwrite_a_raced_marker_replacement(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        state = self.load()
        raced = launcher.live_run_marker.RunMarker(
            marker_path=state.marker.marker_path,
            status=launcher.live_run_marker.STATUS_RUNNING,
            run_id="f" * 64,
            instance=state.marker.instance,
            container_id=state.marker.container_id,
            container_name=state.marker.container_name,
            image=state.marker.image,
            endpoint=state.marker.endpoint,
            state_path=state.marker.state_path,
            credential_path=state.marker.credential_path,
            credential_identity=state.marker.credential_identity,
        )

        def replace_marker_then_fail(
            current: launcher.LauncherState,
            expected: tuple[int, int, int, int, int],
            *,
            parent_fd: int | None = None,
        ) -> None:
            del current, expected
            assert parent_fd is not None
            os.unlink(raced.marker_path.name, dir_fd=parent_fd)
            launcher.live_run_marker.create_marker(raced, parent_fd=parent_fd)
            raise launcher.LauncherError("marker_replaced")

        with mock.patch.object(launcher, "_remove_marker_last", side_effect=replace_marker_then_fail):
            with self.assertRaises(launcher.LauncherError) as raised:
                launcher.stop_instance(
                    self.marker_path(),
                    roots=self.roots,
                    runner=self.fake,
                    executable="/usr/bin/podman",
                    source_environment={"PATH": "/usr/bin"},
                )
        self.assertEqual(raised.exception.code, "marker_replaced")
        self.assertEqual(launcher.live_run_marker.load_marker(self.marker_path()).run_id, "f" * 64)
        self.assertTrue(self.runs.joinpath("fixture.state.json").exists())
        self.assertEqual(json.loads(self.runs.joinpath("fixture.state.json").read_text())["status"], "cleanup_failed")

    def test_same_name_replacement_container_survives_pinned_id_cleanup(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        state = self.load()
        original_id = state.container_id
        swapped = False
        original_key = f"original-{original_id}"

        def swap_name_on_inspect(command, environment, timeout):
            nonlocal swapped
            if command[1:3] == ("container", "inspect") and command[3] == original_id and not swapped:
                swapped = True
                original = self.fake.containers.pop(spec.container)
                replacement = json.loads(json.dumps(original))
                replacement["Id"] = "d" * 64
                self.fake.containers[spec.container] = replacement
                self.fake.containers[original_key] = original
            return self.fake(command, environment, timeout)

        result = launcher.stop_instance(
            self.marker_path(),
            roots=self.roots,
            runner=swap_name_on_inspect,
            executable="/usr/bin/podman",
            source_environment={"PATH": "/usr/bin"},
        )
        self.assertEqual(result["status"], "removed")
        self.assertTrue(swapped)
        self.assertEqual(self.fake.containers[spec.container]["Id"], "d" * 64)
        self.assertFalse(self.marker_path().exists())
        self.assertFalse((self.runs / "fixture.state.json").exists())
        self.assertFalse((self.runs / "fixture.credential").exists())
        lifecycle = [command for command, _ in self.fake.calls if command[1:3] == ("rm", "--force")]
        self.assertEqual(lifecycle, [("/usr/bin/podman", "rm", "--force", original_id)])

    def test_concurrent_credential_replacement_is_preserved_and_original_erased(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        state = self.load()
        original_fd = os.open(state.marker.credential_path, os.O_RDONLY)
        replaced = False
        replacement_bytes = b"replacement-credential"

        def race_credential(parent_fd, source_name, target_name):
            nonlocal replaced
            if source_name == state.marker.credential_path.name and not replaced:
                replaced = True
                replacement = self.runs / "credential-replacement"
                replacement.write_bytes(replacement_bytes)
                replacement.chmod(0o600)
                state.marker.credential_path.unlink()
                replacement.rename(state.marker.credential_path)

        try:
            with mock.patch.object(launcher, "_before_rename_syscall", side_effect=race_credential):
                with self.assertRaises(launcher.LauncherError) as raised:
                    launcher.stop_instance(
                        self.marker_path(),
                        roots=self.roots,
                        runner=self.fake,
                        executable="/usr/bin/podman",
                        source_environment={"PATH": "/usr/bin"},
                    )
            os.lseek(original_fd, 0, os.SEEK_SET)
            self.assertEqual(os.read(original_fd, 256), b"")
        finally:
            os.close(original_fd)
        self.assertTrue(replaced)
        self.assertIn("credential_remove_failed_replaced", raised.exception.code)
        self.assertEqual(state.marker.credential_path.read_bytes(), replacement_bytes)
        self.assertEqual(self.fake.containers, {})

    def test_same_inode_same_size_credential_mutation_is_rejected_before_erase(self) -> None:
        path = self.runs / "claim.credential"
        original = b"a" * 16
        replacement = b"b" * len(original)
        path.write_bytes(original)
        path.chmod(0o600)
        expected = launcher.live_run_marker.credential_snapshot(path)
        mutated = False

        def mutate_before_claim(parent_fd, source_name, target_name):
            del target_name
            nonlocal mutated
            if source_name != path.name or mutated:
                return
            mutated = True
            descriptor = os.open(source_name, os.O_RDWR, dir_fd=parent_fd)
            try:
                self.assertEqual(os.pwrite(descriptor, replacement, 0), len(replacement))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

        with mock.patch.object(launcher, "_before_rename_syscall", side_effect=mutate_before_claim):
            with self.assertRaises(launcher.LauncherError) as raised:
                launcher._remove_exact_file(
                    path,
                    code="credential_remove_failed",
                    expected=expected,
                    erase=True,
                )
        self.assertTrue(mutated)
        self.assertIn("credential_remove_failed_replaced", raised.exception.code)
        evidence = [
            self.runs / name
            for name in launcher.live_run_marker.quarantine_slot_names("cleanup")
            if (self.runs / name).exists()
        ]
        self.assertTrue(any(candidate.read_bytes() == replacement for candidate in evidence))
        self.assertFalse(any(candidate.read_bytes() == b"" for candidate in evidence))

    def test_credential_erasure_overwrites_held_descriptor_before_truncate(self) -> None:
        path = self.runs / "erase.credential"
        path.write_bytes(b"synthetic-secret")
        path.chmod(0o600)
        descriptor = os.open(path, os.O_RDWR | getattr(os, "O_CLOEXEC", 0))
        observed: list[bytes] = []
        real_ftruncate = os.ftruncate

        def observe_before_truncate(current: int, size: int) -> None:
            observed.append(os.pread(current, launcher.live_run_marker.MAX_CREDENTIAL_BYTES, 0))
            real_ftruncate(current, size)

        try:
            with mock.patch.object(launcher.os, "ftruncate", side_effect=observe_before_truncate):
                launcher._erase_credential_descriptor(descriptor)
        finally:
            os.close(descriptor)
        self.assertEqual(observed, [b"\x00" * len(b"synthetic-secret")])
        self.assertEqual(path.read_bytes(), b"")

    def test_state_rewrite_rolls_back_after_write_sync_mode_and_parent_failures(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        state = self.load()
        tombstone = launcher.live_run_marker.cleanup_failed(state.marker)
        self.assertIsNotNone(state.state_identity)
        assert state.state_identity is not None
        old_content = state.marker.state_path.read_bytes()
        parent_fd = os.open(self.runs, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            for failure in ("write", "fsync", "chmod", "parent-sync"):
                with self.subTest(failure=failure):
                    if failure == "write":
                        real_write = os.write
                        calls = 0

                        def flaky_write(descriptor, content):
                            nonlocal calls
                            if calls == 0:
                                calls += 1
                                return real_write(descriptor, content[:1])
                            if calls == 1:
                                calls += 1
                                raise OSError("synthetic partial write")
                            return real_write(descriptor, content)

                        patcher = mock.patch.object(launcher.os, "write", side_effect=flaky_write)
                    elif failure == "fsync":
                        real_fsync = os.fsync
                        calls = 0

                        def flaky_fsync(descriptor):
                            nonlocal calls
                            if calls == 0:
                                calls += 1
                                raise OSError("synthetic fsync failure")
                            return real_fsync(descriptor)

                        patcher = mock.patch.object(launcher.os, "fsync", side_effect=flaky_fsync)
                    elif failure == "chmod":
                        real_fchmod = os.fchmod
                        calls = 0

                        def flaky_fchmod(descriptor, mode):
                            nonlocal calls
                            if calls == 0:
                                calls += 1
                                raise OSError("synthetic chmod failure")
                            return real_fchmod(descriptor, mode)

                        patcher = mock.patch.object(launcher.os, "fchmod", side_effect=flaky_fchmod)
                    else:
                        real_fsync = os.fsync

                        def flaky_parent_fsync(descriptor):
                            if descriptor == parent_fd:
                                raise OSError("synthetic parent sync failure")
                            return real_fsync(descriptor)

                        patcher = mock.patch.object(launcher.os, "fsync", side_effect=flaky_parent_fsync)
                    with patcher:
                        with self.assertRaises(launcher.LauncherError) as raised:
                            launcher._rewrite_state_exact(
                                spec,
                                tombstone,
                                state.state_identity,
                                parent_fd=parent_fd,
                            )
                    self.assertEqual(
                        raised.exception.code,
                        "state_sync_failed" if failure == "parent-sync" else "state_rewrite_failed",
                    )
                    self.assertEqual(state.marker.state_path.read_bytes(), old_content)
                    self.assertEqual(stat.S_IMODE(state.marker.state_path.stat().st_mode), 0o600)
        finally:
            os.close(parent_fd)

    def test_concurrent_state_replacement_is_preserved_without_marker_adoption(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        state = self.load()
        replacement_bytes = b"replacement-state"
        replaced = False

        def race_state(parent_fd, source_name, target_name):
            nonlocal replaced
            if source_name == state.marker.state_path.name and not replaced:
                replaced = True
                replacement = self.runs / "state-replacement"
                replacement.write_bytes(replacement_bytes)
                replacement.chmod(0o600)
                state.marker.state_path.unlink()
                replacement.rename(state.marker.state_path)

        with mock.patch.object(launcher, "_before_rename_syscall", side_effect=race_state):
            with self.assertRaises(launcher.LauncherError) as raised:
                launcher.stop_instance(
                    self.marker_path(),
                    roots=self.roots,
                    runner=self.fake,
                    executable="/usr/bin/podman",
                    source_environment={"PATH": "/usr/bin"},
                )
        self.assertIn("state_remove_failed_replaced", raised.exception.code)
        self.assertTrue(replaced)
        self.assertEqual(state.marker.state_path.read_bytes(), replacement_bytes)
        self.assertEqual(self.fake.containers, {})
        self.assertTrue(self.marker_path().exists())

    def test_concurrent_marker_replacement_is_preserved_without_marker_adoption(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        state = self.load()
        replacement = launcher.live_run_marker.RunMarker(
            marker_path=state.marker.marker_path,
            status=launcher.live_run_marker.STATUS_RUNNING,
            run_id="f" * 64,
            instance=state.marker.instance,
            container_id=state.marker.container_id,
            container_name=state.marker.container_name,
            image=state.marker.image,
            endpoint=state.marker.endpoint,
            state_path=state.marker.state_path,
            credential_path=state.marker.credential_path,
            credential_identity=state.marker.credential_identity,
        )
        replaced = False

        def race_marker(parent_fd, source_name, target_name):
            nonlocal replaced
            if source_name == state.marker.marker_path.name and not replaced:
                replaced = True
                state.marker.marker_path.unlink()
                launcher.live_run_marker.create_marker(replacement, parent_fd=parent_fd)

        with mock.patch.object(launcher, "_before_rename_syscall", side_effect=race_marker):
            with self.assertRaises(launcher.LauncherError) as raised:
                launcher.stop_instance(
                    self.marker_path(),
                    roots=self.roots,
                    runner=self.fake,
                    executable="/usr/bin/podman",
                    source_environment={"PATH": "/usr/bin"},
                )
        self.assertEqual(raised.exception.code, "marker_replaced")
        self.assertTrue(replaced)
        self.assertEqual(launcher.live_run_marker.load_marker(self.marker_path()).run_id, "f" * 64)
        self.assertEqual(self.fake.containers, {})

    def test_cleanup_rejects_replaced_credential_before_container_removal(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        state = self.load()
        replacement = self.runs / "replacement"
        replacement.write_bytes(state.marker.credential_path.read_bytes())
        replacement.chmod(0o600)
        state.marker.credential_path.unlink()
        replacement.rename(state.marker.credential_path)
        self.fake.calls.clear()
        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.stop_instance(self.marker_path(), roots=self.roots, runner=self.fake, executable="/usr/bin/podman", source_environment={"PATH": "/usr/bin"})
        self.assertEqual(raised.exception.code, "credential_identity_mismatch")
        self.assertEqual(self.fake.containers[spec.container]["State"]["Status"], "running")
        self.assertFalse(any(command[1] == "rm" for command, _ in self.fake.calls))
        self.assertEqual(launcher.load_launcher_state(self.marker_path(), self.roots).marker.status, "cleanup_failed")

    def test_cleanup_rejects_marker_copy_hardlink_symlink_and_fifo_without_mutation(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        copied = self.marker_path("copied.json")
        copied.write_bytes(self.marker_path().read_bytes())
        copied.chmod(0o600)
        with self.assertRaises(launcher.LauncherError):
            launcher.stop_instance(copied, roots=self.roots, runner=self.fake, executable="/usr/bin/podman", source_environment={"PATH": "/usr/bin"})
        self.assertTrue(self.marker_path().exists())

        hardlink = self.marker_path("hardlink.json")
        os.link(self.marker_path(), hardlink)
        with self.assertRaises(launcher.LauncherError):
            launcher.stop_instance(self.marker_path(), roots=self.roots, runner=self.fake, executable="/usr/bin/podman", source_environment={"PATH": "/usr/bin"})
        hardlink.unlink()

        symlink = self.marker_path("symlink.json")
        symlink.symlink_to(self.marker_path())
        with self.assertRaises(launcher.LauncherError):
            launcher.stop_instance(symlink, roots=self.roots, runner=self.fake, executable="/usr/bin/podman", source_environment={"PATH": "/usr/bin"})
        symlink.unlink()
        fifo = self.marker_path("fifo.json")
        os.mkfifo(fifo)
        with self.assertRaises(launcher.LauncherError):
            launcher.stop_instance(fifo, roots=self.roots, runner=self.fake, executable="/usr/bin/podman", source_environment={"PATH": "/usr/bin"})
        fifo.unlink()
        self.assertIn(spec.container, self.fake.containers)

    def test_rootless_false_fails_before_image_or_run(self) -> None:
        def rootful(command, environment, timeout):
            del environment, timeout
            if tuple(command[1:]) == ("info", "--format", "{{.Host.Security.Rootless}}"):
                return launcher.CommandResult(0, "false\n")
            raise AssertionError(command)

        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.start_instance(
                self.make_spec(),
                marker_path=self.marker_path(),
                runner=rootful,
                readiness=self.ready,
                port_checker=lambda port: True,
                executable="/usr/bin/podman",
                source_environment={"PATH": "/usr/bin"},
            )
        self.assertEqual(raised.exception.code, "rootless_podman_required")

    def test_cli_rejects_unhashable_status_and_nul_state_path_without_traceback(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        original = json.loads(self.marker_path().read_text(encoding="utf-8"))
        command = [
            sys.executable,
            str(SCRIPT),
            "status",
            "--marker",
            str(self.marker_path()),
            "--state-root",
            str(self.roots.state),
            "--data-root",
            str(self.roots.data),
            "--credential-root",
            str(self.roots.credentials),
        ]
        for status in ([], {}):
            with self.subTest(status=status):
                document = {**original, "status": status}
                self.marker_path().write_text(json.dumps(document), encoding="utf-8")
                self.marker_path().chmod(0o600)
                completed = subprocess.run(command, cwd=ROOT, check=False, capture_output=True, text=True)
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stderr, "")
                self.assertEqual(
                    json.loads(completed.stdout),
                    {"error": {"code": "marker_status_invalid"}, "ok": False},
                )
                self.assertNotIn("Traceback", completed.stdout)

        document = {**original, "state_path": str(self.runs / "bad\x00state.json")}
        self.marker_path().write_text(json.dumps(document), encoding="utf-8")
        self.marker_path().chmod(0o600)
        completed = subprocess.run(command, cwd=ROOT, check=False, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stderr, "")
        self.assertEqual(
            json.loads(completed.stdout),
            {"error": {"code": "state_path_invalid"}, "ok": False},
        )
        self.assertNotIn("Traceback", completed.stdout)

    def test_cli_invalid_image_is_bounded_and_requires_exact_marker_without_traceback(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "start",
                "--instance",
                "safe",
                "--port",
                "19119",
                "--marker",
                str(self.marker_path()),
                "--image",
                "docker.io/nousresearch/hermes-agent:latest",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stderr, "")
        payload = json.loads(completed.stdout)
        self.assertEqual(payload, {"error": {"code": "image_not_immutable_official"}, "ok": False})
        self.assertNotIn("Traceback", completed.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
