#!/usr/bin/env python3
"""Regression tests for the disposable official Hermes Agent launcher.

The unit suite uses a fake Podman boundary and local synthetic HTTP responses.
It never starts a container, contacts Hermes, or reads a real credential.
"""

from __future__ import annotations

import contextlib
import http.server
import importlib.util
import json
import os
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock
from typing import Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "hermes_agent.py"
spec = importlib.util.spec_from_file_location("hermes_agent", SCRIPT)
if spec is None or spec.loader is None:
    raise RuntimeError(f"Could not load {SCRIPT}")
launcher = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = launcher
spec.loader.exec_module(launcher)


class FakePodman:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], dict[str, str]]] = []
        self.containers: dict[str, dict[str, object]] = {}
        self.fail_run_for: set[str] = set()
        self.fail_start_for: set[str] = set()
        self.fail_stop_for: set[str] = set()
        self.raise_start_for: set[str] = set()
        self.raise_stop_for: set[str] = set()

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
    ):
        del timeout
        command_tuple = tuple(command)
        environment_copy = dict(environment)
        self.calls.append((command_tuple, environment_copy))
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
                return launcher.CommandResult(125, "")
            labels: dict[str, str] = {}
            for index, value in enumerate(args):
                if value == "--label":
                    key, label_value = args[index + 1].split("=", 1)
                    labels[key] = label_value
            volume = args[args.index("--volume") + 1]
            image = args[-3]
            published = args[args.index("--publish") + 1].split(":")
            host_ip, host_port, container_port = published
            self.containers[name] = {
                # The launcher persists Podman's immutable hexadecimal ID, never
                # a mutable container name, for endpoint-handoff verification.
                "Id": (f"{len(self.containers) + 1:012x}" + ("a" * 52)),
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
            return launcher.CommandResult(0, "synthetic-container-id\n")
        if args[:1] == ("start",):
            target = args[1]
            resolved = self._resolve(target)
            name = resolved[0] if resolved is not None else target
            if name in self.raise_start_for or target in self.raise_start_for:
                raise RuntimeError("synthetic-start-output-secret")
            if name in self.fail_start_for or target in self.fail_start_for:
                return launcher.CommandResult(125, "synthetic-start-output-secret")
            if resolved is None:
                return launcher.CommandResult(125, "synthetic-start-output-secret")
            state = resolved[1].get("State")
            if not isinstance(state, dict):
                raise AssertionError(f"missing fake state for {name}")
            state["Status"] = "running"
            return launcher.CommandResult(0, "synthetic-start-id\n")
        if args[:1] == ("stop",):
            target = args[1]
            resolved = self._resolve(target)
            name = resolved[0] if resolved is not None else target
            if name in self.raise_stop_for or target in self.raise_stop_for:
                raise RuntimeError("synthetic-stop-output-secret")
            if name in self.fail_stop_for or target in self.fail_stop_for:
                return launcher.CommandResult(125, "synthetic-stop-output-secret")
            if resolved is None:
                return launcher.CommandResult(125, "synthetic-stop-output-secret")
            state = resolved[1].get("State")
            if not isinstance(state, dict):
                raise AssertionError(f"missing fake state for {name}")
            state["Status"] = "exited"
            return launcher.CommandResult(0, "")
        if args[:2] == ("rm", "--force"):
            self.containers.pop(args[2], None)
            return launcher.CommandResult(0, "")
        if args[:3] == ("unshare", "rm", "-rf"):
            path = Path(args[-1])
            if path.exists():
                import shutil

                shutil.rmtree(path)
            return launcher.CommandResult(0, "")
        raise AssertionError(f"Unexpected fake Podman command: {command_tuple!r}")


class ProviderHandler(http.server.BaseHTTPRequestHandler):
    payload = b'{"providers":[{"name":"basic","supports_password":true}]}'
    status = 200

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/api/auth/providers":
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(self.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(self.payload)))
        self.end_headers()
        self.wfile.write(self.payload)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


@contextlib.contextmanager
def provider_server(payload: bytes, status: int = 200):
    handler = type("ConfiguredProviderHandler", (ProviderHandler,), {"payload": payload, "status": status})
    with socketserver.TCPServer(("127.0.0.1", 0), handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address
            yield f"http://{host}:{port}"
        finally:
            server.shutdown()
            thread.join(timeout=2)


class HermesAgentLauncherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.roots = launcher.Roots(
            state=root / "state",
            data=root / "data",
            credentials=root / "credentials",
        )
        self.fake = FakePodman()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_spec(self, instance: str = "test-one", port: int = 19119):
        return launcher.make_spec(instance, port, roots=self.roots)

    @staticmethod
    def ready(endpoint: str, attempts: int, interval: float) -> None:
        del endpoint, attempts, interval

    def foreign_container(self, spec, *, status: str) -> dict[str, object]:
        return {
            "Id": f"foreign-{spec.container}",
            "Name": f"/{spec.container}",
            "ImageName": "docker.io/other/hermes-agent:v1@sha256:" + ("b" * 64),
            "Config": {"Labels": {}},
            "Mounts": [],
            "State": {"Status": status},
        }

    def start(self, spec=None, *, readiness=None):
        return launcher.start_instance(
            spec or self.make_spec(),
            runner=self.fake,
            readiness=readiness or self.ready,
            port_checker=lambda port: True,
            executable="/usr/bin/podman",
            source_environment={"PATH": "/usr/bin"},
            attempts=1,
            interval=0,
        )

    def test_default_image_is_exact_official_tag_and_digest(self) -> None:
        tag, digest = launcher.validate_image(launcher.DEFAULT_IMAGE)
        self.assertEqual(tag, "v2026.8.3")
        self.assertEqual(
            digest,
            "sha256:16788311e2fa3035456bdc1bafb8ec2b1777db64ebf020af9bb7eb73c3712c9e",
        )
        self.assertEqual(
            launcher.expected_repo_digest(launcher.DEFAULT_IMAGE),
            "docker.io/nousresearch/hermes-agent@" + digest,
        )

    def test_mutable_or_nonofficial_images_fail_closed(self) -> None:
        digest = "a" * 64
        rejected = (
            f"docker.io/nousresearch/hermes-agent:latest@sha256:{digest}",
            f"docker.io/other/hermes-agent:v1@sha256:{digest}",
            "docker.io/nousresearch/hermes-agent:v1",
            f"docker.io/nousresearch/hermes-agent:v1@sha256:{digest.upper()}",
            f"docker.io/nousresearch/hermes-agent@sha256:{digest}",
        )
        for image in rejected:
            with self.subTest(image=image), self.assertRaises(launcher.LauncherError) as raised:
                launcher.validate_image(image)
            self.assertEqual(raised.exception.code, "image_not_immutable_official")

    def test_batch_names_and_ports_are_deterministic_and_unique(self) -> None:
        specs = launcher.specs_for_batch(
            "playwright",
            4,
            19120,
            image=launcher.DEFAULT_IMAGE,
            username=launcher.DEFAULT_USERNAME,
            roots=self.roots,
        )
        self.assertEqual([item.instance for item in specs], [f"playwright-{index}" for index in range(1, 5)])
        self.assertEqual([item.port for item in specs], [19120, 19121, 19122, 19123])
        self.assertEqual(len({item.container for item in specs}), 4)
        self.assertEqual(len({item.data_dir for item in specs}), 4)
        self.assertEqual(len({item.credential_file for item in specs}), 4)

    def test_run_command_preserves_upstream_behavior_without_policy_flags(self) -> None:
        spec = self.make_spec()
        command = launcher.run_arguments(spec, "/usr/bin/podman")
        self.assertEqual(command[-3:], (spec.image, "gateway", "run"))
        self.assertIn("127.0.0.1:19119:9119", command)
        self.assertIn(f"{spec.data_dir}:/opt/data", command)
        self.assertNotIn("--entrypoint", command)
        forbidden = {
            "build",
            "compose",
            "tag",
            "--network",
            "host",
            "--cpus",
            "--memory",
            "--pids-limit",
            "--cap-add",
            "--cap-drop",
            "--security-opt",
            "--log-driver",
            "8642",
        }
        self.assertTrue(forbidden.isdisjoint(command), command)
        self.assertFalse(any("/.hermes" in value or "~/.hermes" in value for value in command))
        self.assertFalse(any("podman.sock" in value or "docker.sock" in value for value in command))

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

    def test_password_is_private_reused_and_never_enters_public_artifacts(self) -> None:
        spec = self.make_spec()
        first = launcher.read_or_create_password(spec)
        second = launcher.read_or_create_password(spec)
        self.assertEqual(first, second)
        self.assertRegex(first, r"^[0-9a-f]{48}$")
        self.assertEqual(spec.credential_file.read_bytes(), (first + "\n").encode("ascii"))
        self.assertEqual(stat.S_IMODE(spec.credential_file.stat().st_mode), 0o600)

        result, created = self.start(spec)
        self.assertTrue(created)
        self.assertNotIn(first, json.dumps(result))
        self.assertNotIn(first, spec.state_file.read_text(encoding="utf-8"))
        run_calls = [(command, environment) for command, environment in self.fake.calls if command[1] == "run"]
        self.assertEqual(len(run_calls), 1)
        command, environment = run_calls[0]
        self.assertNotIn(first, command)
        self.assertEqual(environment["HERMES_DASHBOARD_BASIC_AUTH_PASSWORD"], first)
        self.assertIn("HERMES_DASHBOARD_BASIC_AUTH_PASSWORD", command)

    def test_existing_credential_file_normalizes_only_trailing_crlf(self) -> None:
        spec = self.make_spec()
        value = b"a" * 48
        spec.credential_file.parent.mkdir(parents=True)

        for suffix in (b"", b"\n", b"\r", b"\r\n", b"\n\r"):
            with self.subTest(suffix=suffix):
                spec.credential_file.write_bytes(value + suffix)
                self.assertEqual(launcher.read_or_create_password(spec), value.decode("ascii"))

        rejected = (
            value + b" ",
            value + b"\t\n",
            value + b"\ntrailing",
            value[:24] + b"\n" + value[24:],
            value.upper(),
            value[:-1],
            value + b"0",
            b"",
        )
        for raw in rejected:
            with self.subTest(raw=raw):
                spec.credential_file.write_bytes(raw)
                with self.assertRaises(launcher.LauncherError) as raised:
                    launcher.read_or_create_password(spec)
                self.assertEqual(raised.exception.code, "credential_file_invalid")

    def test_start_verifies_image_and_writes_nonsecret_state(self) -> None:
        spec = self.make_spec()
        result, created = self.start(spec)
        self.assertTrue(created)
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["endpoint"], "http://127.0.0.1:19119")
        self.assertEqual(result["credential_file"], str(spec.credential_file))
        loaded = launcher.load_state(spec.instance, self.roots)
        self.assertEqual(loaded, spec)
        commands = [command[1:] for command, _ in self.fake.calls]
        self.assertIn(("pull", spec.image), commands)
        self.assertIn(("image", "inspect", spec.image, "--format", "json"), commands)

    def test_verified_endpoint_requires_the_running_owned_loopback_mapping(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        state = launcher.load_launcher_state(spec.instance, self.roots)
        self.fake.calls.clear()

        result = launcher.verify_handoff_endpoint(
            state,
            runner=self.fake,
            executable="/usr/bin/podman",
            source_environment={"PATH": "/usr/bin"},
        )

        self.assertEqual(result, {**spec.public(), "status": "running"})
        self.assertEqual(self.fake.calls[-1][0][1:3], ("container", "inspect"))
        self.assertEqual(self.fake.calls[-1][0][3], state.container_id)

    def test_verified_endpoint_rejects_stopped_tombstone_before_handoff(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        original_id = launcher.load_launcher_state(spec.instance, self.roots).container_id
        launcher.stop_instance(
            spec,
            runner=self.fake,
            executable="/usr/bin/podman",
            source_environment={"PATH": "/usr/bin"},
        )
        state = launcher.load_launcher_state(spec.instance, self.roots)
        self.assertEqual(state.container_id, original_id)

        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.verify_handoff_endpoint(
                state,
                runner=self.fake,
                executable="/usr/bin/podman",
                source_environment={"PATH": "/usr/bin"},
            )

        self.assertEqual(raised.exception.code, "container_inspect_failed")

    def test_verified_endpoint_rejects_missing_or_rebound_port_mapping(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        state = launcher.load_launcher_state(spec.instance, self.roots)
        ports = self.fake.containers[spec.container]["NetworkSettings"]["Ports"]
        self.assertIsInstance(ports, dict)
        ports.clear()

        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.verify_handoff_endpoint(
                state,
                runner=self.fake,
                executable="/usr/bin/podman",
                source_environment={"PATH": "/usr/bin"},
            )
        self.assertEqual(raised.exception.code, "container_endpoint_unproven")

        ports["9119/tcp"] = [{"HostIp": "127.0.0.1", "HostPort": "19120"}]
        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.verify_handoff_endpoint(
                state,
                runner=self.fake,
                executable="/usr/bin/podman",
                source_environment={"PATH": "/usr/bin"},
            )
        self.assertEqual(raised.exception.code, "container_endpoint_unproven")

    def test_verified_endpoint_rejects_container_replacement_and_ownership_mismatch(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        state = launcher.load_launcher_state(spec.instance, self.roots)
        self.fake.containers[spec.container]["Id"] = "b" * 64

        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.verify_handoff_endpoint(
                state,
                runner=self.fake,
                executable="/usr/bin/podman",
                source_environment={"PATH": "/usr/bin"},
            )
        self.assertEqual(raised.exception.code, "container_inspect_failed")

        self.fake.containers[spec.container]["Id"] = state.container_id
        self.fake.containers[spec.container]["Config"] = {"Labels": {}}
        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.verify_handoff_endpoint(
                state,
                runner=self.fake,
                executable="/usr/bin/podman",
                source_environment={"PATH": "/usr/bin"},
            )
        self.assertEqual(raised.exception.code, "container_not_launcher_owned")

    def test_verified_endpoint_rejects_non_loopback_mapping(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        state = launcher.load_launcher_state(spec.instance, self.roots)
        ports = self.fake.containers[spec.container]["NetworkSettings"]["Ports"]
        self.assertIsInstance(ports, dict)
        ports["9119/tcp"] = [{"HostIp": "0.0.0.0", "HostPort": str(spec.port)}]

        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.verify_handoff_endpoint(
                state,
                runner=self.fake,
                executable="/usr/bin/podman",
                source_environment={"PATH": "/usr/bin"},
            )
        self.assertEqual(raised.exception.code, "container_endpoint_unproven")

    def test_existing_exact_container_is_reused_but_mismatch_is_rejected(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        self.fake.calls.clear()
        result, created = self.start(spec)
        self.assertFalse(created)
        self.assertFalse(result["created"])
        run_count = sum(command[1] == "run" for command, _ in self.fake.calls)
        self.assertEqual(run_count, 0)
        lifecycle = [command[1:] for command, _ in self.fake.calls if command[1] in {"start", "stop"}]
        self.assertEqual(lifecycle, [])

        self.fake.containers[spec.container]["Config"] = {"Labels": {}}
        with self.assertRaises(launcher.LauncherError) as raised:
            self.start(spec)
        self.assertEqual(raised.exception.code, "container_not_launcher_owned")

    def test_existing_stopped_container_is_started_before_readiness(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        self.fake.containers[spec.container]["State"] = {"Status": "exited"}
        self.fake.calls.clear()

        result, created = self.start(spec)

        self.assertFalse(created)
        self.assertEqual(result["status"], "ready")
        self.assertEqual(self.fake.containers[spec.container]["State"]["Status"], "running")
        lifecycle = [command[1:] for command, _ in self.fake.calls if command[1] in {"start", "stop"}]
        self.assertEqual(lifecycle, [("start", self.fake.containers[spec.container]["Id"])])

    def test_existing_stopped_container_failure_before_start_preserves_stopped_state(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        self.fake.containers[spec.container]["State"] = {"Status": "exited"}
        self.fake.calls.clear()

        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.start_instance(
                spec,
                runner=self.fake,
                readiness=self.ready,
                port_checker=lambda port: False,
                executable="/usr/bin/podman",
                source_environment={"PATH": "/usr/bin"},
                attempts=1,
                interval=0,
            )

        self.assertEqual(raised.exception.code, "port_unavailable")
        self.assertEqual(self.fake.containers[spec.container]["State"]["Status"], "exited")
        lifecycle = [command[1:] for command, _ in self.fake.calls if command[1] in {"start", "stop"}]
        self.assertEqual(lifecycle, [])

    def test_existing_stopped_container_failure_after_start_rolls_back_once(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        self.fake.containers[spec.container]["State"] = {"Status": "exited"}
        self.fake.calls.clear()

        def not_ready(endpoint: str, attempts: int, interval: float) -> None:
            del endpoint, attempts, interval
            raise launcher.LauncherError("provider_readiness_timeout")

        with self.assertRaises(launcher.LauncherError) as raised:
            self.start(spec, readiness=not_ready)

        self.assertEqual(raised.exception.code, "provider_readiness_timeout")
        self.assertEqual(self.fake.containers[spec.container]["State"]["Status"], "exited")
        lifecycle = [command[1:] for command, _ in self.fake.calls if command[1] in {"start", "stop"}]
        self.assertEqual(
            lifecycle,
            [("start", self.fake.containers[spec.container]["Id"]), ("stop", self.fake.containers[spec.container]["Id"])],
        )

    def test_existing_stopped_container_start_failure_is_bounded_and_redacted(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        self.fake.containers[spec.container]["State"] = {"Status": "exited"}
        self.fake.fail_start_for.add(spec.container)
        self.fake.calls.clear()

        with self.assertRaises(launcher.LauncherError) as raised:
            self.start(spec)

        self.assertEqual(raised.exception.code, "container_start_failed")
        self.assertNotIn("synthetic-start-output-secret", str(raised.exception))
        self.assertEqual(self.fake.containers[spec.container]["State"]["Status"], "exited")
        lifecycle = [command[1:] for command, _ in self.fake.calls if command[1] in {"start", "stop"}]
        self.assertEqual(lifecycle, [("start", self.fake.containers[spec.container]["Id"])])

    def test_existing_stopped_container_rollback_failure_fails_closed(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        self.fake.containers[spec.container]["State"] = {"Status": "exited"}
        self.fake.fail_stop_for.add(spec.container)
        self.fake.calls.clear()

        def not_ready(endpoint: str, attempts: int, interval: float) -> None:
            del endpoint, attempts, interval
            raise launcher.LauncherError("provider_readiness_timeout")

        with self.assertRaises(launcher.LauncherError) as raised:
            self.start(spec, readiness=not_ready)

        self.assertEqual(raised.exception.code, "container_recovery_rollback_failed")
        self.assertEqual(self.fake.containers[spec.container]["State"]["Status"], "running")
        lifecycle = [command[1:] for command, _ in self.fake.calls if command[1] in {"start", "stop"}]
        self.assertEqual(
            lifecycle,
            [("start", self.fake.containers[spec.container]["Id"]), ("stop", self.fake.containers[spec.container]["Id"])],
        )

    def test_existing_stopped_container_cancellation_rolls_back_once(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        self.fake.containers[spec.container]["State"] = {"Status": "exited"}
        self.fake.calls.clear()

        def cancelled(endpoint: str, attempts: int, interval: float) -> None:
            del endpoint, attempts, interval
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            self.start(spec, readiness=cancelled)

        self.assertEqual(self.fake.containers[spec.container]["State"]["Status"], "exited")
        lifecycle = [command[1:] for command, _ in self.fake.calls if command[1] in {"start", "stop"}]
        self.assertEqual(
            lifecycle,
            [("start", self.fake.containers[spec.container]["Id"]), ("stop", self.fake.containers[spec.container]["Id"])],
        )

    def test_existing_foreign_container_is_rejected_before_recovery_mutation(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        self.fake.containers[spec.container]["State"] = {"Status": "exited"}
        self.fake.containers[spec.container]["Config"] = {"Labels": {launcher.MANAGED_LABEL: launcher.MANAGED_VERSION}}
        self.fake.calls.clear()

        with self.assertRaises(launcher.LauncherError) as raised:
            self.start(spec)

        self.assertEqual(raised.exception.code, "container_not_launcher_owned")
        lifecycle = [command[1:] for command, _ in self.fake.calls if command[1] in {"start", "stop"}]
        self.assertEqual(lifecycle, [])

    def test_existing_container_mount_mismatch_fails_closed_before_recovery(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        self.fake.containers[spec.container]["State"] = {"Status": "exited"}
        self.fake.containers[spec.container]["Mounts"] = [
            {
                "Type": "bind",
                "Source": str(self.roots.data / "foreign"),
                "Destination": "/opt/data",
            }
        ]
        self.fake.calls.clear()

        with self.assertRaises(launcher.LauncherError) as raised:
            self.start(spec)

        self.assertEqual(raised.exception.code, "container_identity_unproven")
        lifecycle = [command[1:] for command, _ in self.fake.calls if command[1] in {"start", "stop"}]
        self.assertEqual(lifecycle, [])

    def test_existing_container_image_or_name_mismatch_fails_closed_before_recovery(self) -> None:
        for field, value in (("ImageName", "docker.io/other/hermes-agent:v1@sha256:" + ("a" * 64)), ("Name", "/foreign-container")):
            with self.subTest(field=field):
                spec = self.make_spec(instance=f"test-{field.lower()}")
                self.start(spec)
                self.fake.containers[spec.container]["State"] = {"Status": "exited"}
                self.fake.containers[spec.container][field] = value
                self.fake.calls.clear()

                with self.assertRaises(launcher.LauncherError) as raised:
                    self.start(spec)

                self.assertEqual(raised.exception.code, "container_identity_unproven")
                lifecycle = [command[1:] for command, _ in self.fake.calls if command[1] in {"start", "stop"}]
                self.assertEqual(lifecycle, [])

    def test_existing_container_replacement_race_is_rejected_before_start(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        self.fake.containers[spec.container]["State"] = {"Status": "exited"}
        self.fake.calls.clear()
        inspect_count = 0

        def racing_runner(command, environment, timeout):
            nonlocal inspect_count
            if tuple(command[1:3]) == ("container", "inspect"):
                inspect_count += 1
                if inspect_count == 2:
                    self.fake.containers[spec.container]["Id"] = "b" * 64
            return self.fake(command, environment, timeout)

        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.start_instance(
                spec,
                runner=racing_runner,
                readiness=self.ready,
                port_checker=lambda port: True,
                executable="/usr/bin/podman",
                source_environment={"PATH": "/usr/bin"},
                attempts=1,
                interval=0,
            )

        self.assertEqual(raised.exception.code, "container_recovery_race")
        lifecycle = [command[1:] for command, _ in self.fake.calls if command[1] in {"start", "stop"}]
        self.assertEqual(lifecycle, [])

    def test_existing_container_replacement_after_final_inspect_is_not_started(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        self.fake.containers[spec.container]["State"] = {"Status": "exited"}
        original_id = self.fake.containers[spec.container]["Id"]
        foreign = self.foreign_container(spec, status="exited")
        self.fake.calls.clear()

        def racing_runner(command, environment, timeout):
            if command[1:] == ("start", original_id):
                self.fake.containers[spec.container] = foreign
            return self.fake(command, environment, timeout)

        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.start_instance(
                spec,
                runner=racing_runner,
                readiness=self.ready,
                port_checker=lambda port: True,
                executable="/usr/bin/podman",
                source_environment={"PATH": "/usr/bin"},
                attempts=1,
                interval=0,
            )

        self.assertEqual(raised.exception.code, "container_start_failed")
        self.assertNotIn("synthetic-start-output-secret", str(raised.exception))
        self.assertEqual(foreign["State"]["Status"], "exited")
        lifecycle = [command[1:] for command, _ in self.fake.calls if command[1] in {"start", "stop"}]
        self.assertEqual(lifecycle, [("start", original_id)])

    def test_existing_container_replacement_after_rollback_inspect_is_not_stopped(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        self.fake.containers[spec.container]["State"] = {"Status": "exited"}
        original_id = self.fake.containers[spec.container]["Id"]
        foreign = self.foreign_container(spec, status="running")
        self.fake.calls.clear()

        def not_ready(endpoint: str, attempts: int, interval: float) -> None:
            del endpoint, attempts, interval
            raise launcher.LauncherError("provider_readiness_timeout")

        def racing_runner(command, environment, timeout):
            if command[1:] == ("stop", original_id):
                self.fake.containers[spec.container] = foreign
            return self.fake(command, environment, timeout)

        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.start_instance(
                spec,
                runner=racing_runner,
                readiness=not_ready,
                port_checker=lambda port: True,
                executable="/usr/bin/podman",
                source_environment={"PATH": "/usr/bin"},
                attempts=1,
                interval=0,
            )

        self.assertEqual(raised.exception.code, "container_recovery_rollback_failed")
        self.assertNotIn("synthetic-stop-output-secret", str(raised.exception))
        self.assertEqual(foreign["State"]["Status"], "running")
        lifecycle = [command[1:] for command, _ in self.fake.calls if command[1] in {"start", "stop"}]
        self.assertEqual(
            lifecycle,
            [("start", original_id), ("stop", original_id)],
        )

    def test_occupied_port_fails_before_run(self) -> None:
        spec = self.make_spec()
        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.start_instance(
                spec,
                runner=self.fake,
                readiness=self.ready,
                port_checker=lambda port: False,
                executable="/usr/bin/podman",
                source_environment={"PATH": "/usr/bin"},
            )
        self.assertEqual(raised.exception.code, "port_unavailable")
        self.assertFalse(any(command[1] == "run" for command, _ in self.fake.calls))

    def test_readiness_requires_expected_basic_provider(self) -> None:
        valid = b'{"providers":[{"name":"basic","supports_password":true}]}'
        with provider_server(valid) as endpoint:
            launcher.check_provider_readiness(endpoint, 1, 0)

        malformed = b'{"providers":"wrong"}'
        with provider_server(malformed) as endpoint:
            with self.assertRaises(launcher.LauncherError) as raised:
                launcher.check_provider_readiness(endpoint, 1, 0)
            self.assertEqual(raised.exception.code, "provider_readiness_invalid")

        missing = b'{"providers":[{"name":"oauth","supports_password":false}]}'
        with provider_server(missing) as endpoint:
            with self.assertRaises(launcher.LauncherError) as raised:
                launcher.check_provider_readiness(endpoint, 1, 0)
            self.assertEqual(raised.exception.code, "basic_provider_missing")

    def test_readiness_timeout_removes_only_created_container(self) -> None:
        spec = self.make_spec()

        def not_ready(endpoint: str, attempts: int, interval: float) -> None:
            del endpoint, attempts, interval
            raise launcher.LauncherError("provider_readiness_timeout")

        with self.assertRaises(launcher.LauncherError) as raised:
            self.start(spec, readiness=not_ready)
        self.assertEqual(raised.exception.code, "provider_readiness_timeout")
        self.assertNotIn(spec.container, self.fake.containers)
        self.assertTrue(spec.data_dir.is_dir())
        self.assertTrue(spec.credential_file.is_file())

    def test_partial_batch_failure_rolls_back_created_instances(self) -> None:
        specs = launcher.specs_for_batch(
            "batch",
            3,
            19200,
            image=launcher.DEFAULT_IMAGE,
            username=launcher.DEFAULT_USERNAME,
            roots=self.roots,
        )
        self.fake.fail_run_for.add(specs[1].container)
        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.start_many(
                specs,
                runner=self.fake,
                readiness=self.ready,
                port_checker=lambda port: True,
                executable="/usr/bin/podman",
                source_environment={"PATH": "/usr/bin"},
                attempts=1,
                interval=0,
            )
        self.assertEqual(raised.exception.code, "container_start_failed")
        self.assertEqual(self.fake.containers, {})
        self.assertFalse(specs[2].credential_file.exists())

    def test_container_owned_data_uses_exact_rootless_unshare_fallback(self) -> None:
        spec = self.make_spec()
        launcher._ensure_private_directory(spec.data_dir)
        real_remove = launcher._remove_owned_path

        def permission_once(path: Path) -> None:
            if path == spec.data_dir:
                raise launcher.LauncherError("owned_path_permission_denied")
            real_remove(path)

        with mock.patch.object(launcher, "_remove_owned_path", side_effect=permission_once):
            launcher._remove_container_owned_data(
                spec,
                self.fake,
                {"PATH": "/usr/bin"},
                "/usr/bin/podman",
            )
        self.assertFalse(spec.data_dir.exists())
        unshare = [command for command, _ in self.fake.calls if command[1:4] == ("unshare", "rm", "-rf")]
        self.assertEqual(
            unshare,
            [
                (
                    "/usr/bin/podman",
                    "unshare",
                    "rm",
                    "-rf",
                    "--",
                    str(spec.data_dir),
                )
            ],
        )

    def test_stop_is_idempotent_and_purge_is_explicit(self) -> None:
        spec = self.make_spec()
        self.start(spec)
        first = launcher.stop_instance(
            spec,
            runner=self.fake,
            executable="/usr/bin/podman",
            source_environment={"PATH": "/usr/bin"},
        )
        self.assertEqual(first["status"], "removed")
        self.assertTrue(spec.data_dir.exists())
        self.assertTrue(spec.credential_file.exists())
        self.assertTrue(spec.state_file.exists())

        second = launcher.stop_instance(
            spec,
            purge_data=True,
            runner=self.fake,
            executable="/usr/bin/podman",
            source_environment={"PATH": "/usr/bin"},
        )
        self.assertEqual(second["status"], "absent")
        self.assertFalse(spec.data_dir.exists())
        self.assertFalse(spec.credential_dir.exists())

    def test_rootless_false_fails_before_image_or_run(self) -> None:
        def rootful(command, environment, timeout):
            del environment, timeout
            if tuple(command[1:]) == ("info", "--format", "{{.Host.Security.Rootless}}"):
                return launcher.CommandResult(0, "false\n")
            raise AssertionError(command)

        with self.assertRaises(launcher.LauncherError) as raised:
            launcher.start_instance(
                self.make_spec(),
                runner=rootful,
                readiness=self.ready,
                port_checker=lambda port: True,
                executable="/usr/bin/podman",
                source_environment={"PATH": "/usr/bin"},
            )
        self.assertEqual(raised.exception.code, "rootless_podman_required")

    def test_cli_invalid_image_emits_one_bounded_json_error_without_traceback(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "start",
                "--instance",
                "safe",
                "--port",
                "19119",
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
    unittest.main()
