#!/usr/bin/env python3
"""Launch disposable official Hermes Agent instances with rootless Podman.

This command is a test-lane helper. It preserves the official image entrypoint,
uses the upstream ``gateway run`` command, and publishes the Dashboard only on
VM loopback. It deliberately does not apply custom capability or resource
policies: frontend tests need normal upstream behavior and the dedicated VM may
use its available resources.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence


DEFAULT_IMAGE = (
    "docker.io/nousresearch/hermes-agent:v2026.8.3@"
    "sha256:16788311e2fa3035456bdc1bafb8ec2b1777db64ebf020af9bb7eb73c3712c9e"
)
IMAGE_PATTERN = re.compile(
    r"^docker\.io/nousresearch/hermes-agent:"
    r"(?P<tag>[a-z0-9][a-z0-9._-]{0,127})@sha256:(?P<digest>[0-9a-f]{64})$"
)
INSTANCE_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$")
CONTAINER_PREFIX = "hermternal-hermes-"
MANAGED_LABEL = "io.hermternal.hermes-launcher"
MANAGED_VERSION = "v1"
DASHBOARD_PORT = 9119
DEFAULT_USERNAME = "hermternal-test"
MAX_PROVIDER_BYTES = 64 * 1024
MAX_STATE_BYTES = 16 * 1024
MAX_COMMAND_BYTES = 64 * 1024
CONTAINER_ACTION_TIMEOUT = 60

Runner = Callable[[Sequence[str], Mapping[str, str], float], "CommandResult"]
ReadinessChecker = Callable[[str, int, float], None]
PortChecker = Callable[[int], bool]


class LauncherError(Exception):
    """One stable failure code that contains no secret or raw engine output."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""


@dataclass(frozen=True)
class Roots:
    state: Path
    data: Path
    credentials: Path


@dataclass(frozen=True)
class InstanceSpec:
    instance: str
    port: int
    image: str
    username: str
    roots: Roots

    @property
    def container(self) -> str:
        return f"{CONTAINER_PREFIX}{self.instance}"

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def data_dir(self) -> Path:
        return self.roots.data / self.instance

    @property
    def credential_dir(self) -> Path:
        return self.roots.credentials / self.instance

    @property
    def credential_file(self) -> Path:
        return self.credential_dir / "password"

    @property
    def state_file(self) -> Path:
        return self.roots.state / f"{self.instance}.json"

    def public(self) -> dict[str, object]:
        return {
            "instance": self.instance,
            "container": self.container,
            "endpoint": self.endpoint,
            "image": self.image,
            "data_path": str(self.data_dir),
            "credential_file": str(self.credential_file),
        }


@dataclass(frozen=True)
class RecoverySnapshot:
    """Safe identity projection used immediately around lifecycle mutations."""

    container_id: str
    name: str
    image: str
    data_source: str
    status: str


def default_roots() -> Roots:
    home = Path.home()
    return Roots(
        state=home / ".local" / "state" / "hermternal" / "hermes-agent",
        data=home / ".local" / "share" / "hermternal-tests" / "hermes-agent",
        credentials=home / ".config" / "hermternal-tests" / "hermes-agent",
    )


def validate_image(image: str) -> tuple[str, str]:
    match = IMAGE_PATTERN.fullmatch(image)
    if match is None or match.group("tag") == "latest":
        raise LauncherError("image_not_immutable_official")
    return match.group("tag"), f"sha256:{match.group('digest')}"


def validate_instance(instance: str) -> str:
    if INSTANCE_PATTERN.fullmatch(instance) is None:
        raise LauncherError("instance_invalid")
    return instance


def validate_port(port: int) -> int:
    if type(port) is not int or not 1024 <= port <= 65535:
        raise LauncherError("port_invalid")
    return port


def make_spec(
    instance: str,
    port: int,
    *,
    image: str = DEFAULT_IMAGE,
    username: str = DEFAULT_USERNAME,
    roots: Roots | None = None,
) -> InstanceSpec:
    validate_instance(instance)
    validate_port(port)
    validate_image(image)
    if not username or len(username.encode("utf-8")) > 128 or any(ord(char) < 0x20 for char in username):
        raise LauncherError("username_invalid")
    return InstanceSpec(instance, port, image, username, roots or default_roots())


def clean_environment(source: Mapping[str, str] | None = None) -> dict[str, str]:
    values = dict(os.environ if source is None else source)
    if values.get("CONTAINER_HOST") or values.get("CONTAINER_CONNECTION"):
        raise LauncherError("remote_podman_rejected")
    blocked_exact = {
        "CONTAINER_HOST",
        "CONTAINER_CONNECTION",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
        "COMPOSE_FILE",
        "COMPOSE_PROJECT_NAME",
        "COMPOSE_PROFILES",
        "HERMES_PROVIDER",
        "HERMES_PROVIDER_NAME",
        "HERMES_PROVIDER_URL",
        "HERMES_PROVIDER_CONFIG",
    }
    for name in tuple(values):
        upper = name.upper()
        if (
            upper in blocked_exact
            or upper.startswith("DOCKER_")
            or upper.startswith("COMPOSE_")
            or upper.startswith("HERMES_PROVIDER_")
            or upper.endswith("_API_KEY")
            or upper.endswith("_API_TOKEN")
            or upper.endswith("_ACCESS_TOKEN")
        ):
            values.pop(name, None)
    return values


def _bounded_text(raw: bytes) -> str:
    return raw[:MAX_COMMAND_BYTES].decode("utf-8", errors="replace")


def run_command(command: Sequence[str], environment: Mapping[str, str], timeout: float) -> CommandResult:
    try:
        completed = subprocess.run(
            list(command),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=dict(environment),
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return CommandResult(124, "")
    return CommandResult(completed.returncode, _bounded_text(completed.stdout))


def podman_path() -> str:
    executable = shutil.which("podman")
    if executable is None or not os.path.isabs(executable):
        raise LauncherError("podman_unavailable")
    return executable


def podman_preflight(runner: Runner, environment: Mapping[str, str], executable: str) -> None:
    result = runner(
        (executable, "info", "--format", "{{.Host.Security.Rootless}}"),
        environment,
        15,
    )
    if result.returncode != 0 or result.stdout.strip() != "true":
        raise LauncherError("rootless_podman_required")


def expected_repo_digest(image: str) -> str:
    _, digest = validate_image(image)
    return f"docker.io/nousresearch/hermes-agent@{digest}"


def verify_image(
    image: str,
    runner: Runner,
    environment: Mapping[str, str],
    executable: str,
) -> None:
    pulled = runner((executable, "pull", image), environment, 300)
    if pulled.returncode != 0:
        raise LauncherError("image_pull_failed")
    inspected = runner(
        (executable, "image", "inspect", image, "--format", "json"),
        environment,
        30,
    )
    if inspected.returncode != 0:
        raise LauncherError("image_inspect_failed")
    try:
        document = json.loads(inspected.stdout)
        if not isinstance(document, list) or len(document) != 1 or not isinstance(document[0], dict):
            raise ValueError
        repo_digests = document[0].get("RepoDigests")
        if not isinstance(repo_digests, list) or any(type(value) is not str for value in repo_digests):
            raise ValueError
    except (json.JSONDecodeError, ValueError):
        raise LauncherError("image_inspect_invalid") from None
    if expected_repo_digest(image) not in repo_digests:
        raise LauncherError("image_digest_mismatch")


def is_port_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise LauncherError("owned_path_invalid")
    path.chmod(0o700)


def read_or_create_password(spec: InstanceSpec) -> str:
    _ensure_private_directory(spec.roots.credentials)
    _ensure_private_directory(spec.credential_dir)
    path = spec.credential_file
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise LauncherError("credential_file_invalid") from None
        raw = path.read_bytes()
        if len(raw) > 256:
            raise LauncherError("credential_file_invalid")
        try:
            password = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            raise LauncherError("credential_file_invalid") from None
        if not re.fullmatch(r"[0-9a-f]{48}", password):
            raise LauncherError("credential_file_invalid")
        path.chmod(0o600)
        return password
    password = secrets.token_hex(24)
    try:
        os.write(descriptor, (password + "\n").encode("ascii"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return password


def state_document(spec: InstanceSpec) -> dict[str, object]:
    return {
        "schema": "hermternal.hermes-agent-launcher.v1",
        **spec.public(),
        "username": spec.username,
    }


def write_state(spec: InstanceSpec) -> None:
    _ensure_private_directory(spec.roots.state)
    content = (json.dumps(state_document(spec), sort_keys=True) + "\n").encode("utf-8")
    temporary = spec.state_file.with_suffix(".json.tmp")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        temporary.unlink()
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, content)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, spec.state_file)
    spec.state_file.chmod(0o600)


def load_state(instance: str, roots: Roots) -> InstanceSpec:
    validate_instance(instance)
    path = roots.state / f"{instance}.json"
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise LauncherError("instance_state_missing") from None
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size > MAX_STATE_BYTES:
        raise LauncherError("instance_state_invalid")
    try:
        document = json.loads(path.read_bytes().decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise LauncherError("instance_state_invalid") from None
    expected_keys = {
        "schema",
        "instance",
        "container",
        "endpoint",
        "image",
        "data_path",
        "credential_file",
        "username",
    }
    if not isinstance(document, dict) or set(document) != expected_keys:
        raise LauncherError("instance_state_invalid")
    try:
        endpoint = urllib.parse.urlsplit(document["endpoint"])
        port = endpoint.port
    except (TypeError, ValueError):
        raise LauncherError("instance_state_invalid") from None
    if (
        document["schema"] != "hermternal.hermes-agent-launcher.v1"
        or document["instance"] != instance
        or document["container"] != f"{CONTAINER_PREFIX}{instance}"
        or endpoint.scheme != "http"
        or endpoint.hostname != "127.0.0.1"
        or endpoint.path not in ("", "/")
        or port is None
    ):
        raise LauncherError("instance_state_invalid")
    spec = make_spec(
        instance,
        port,
        image=document["image"],
        username=document["username"],
        roots=roots,
    )
    if document["data_path"] != str(spec.data_dir) or document["credential_file"] != str(spec.credential_file):
        raise LauncherError("instance_state_invalid")
    return spec


def container_exists(
    spec: InstanceSpec,
    runner: Runner,
    environment: Mapping[str, str],
    executable: str,
) -> bool:
    result = runner((executable, "container", "exists", spec.container), environment, 10)
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise LauncherError("container_lookup_failed")


def inspect_container(
    spec: InstanceSpec,
    runner: Runner,
    environment: Mapping[str, str],
    executable: str,
) -> dict[str, object]:
    result = runner(
        (executable, "container", "inspect", spec.container, "--format", "json"),
        environment,
        20,
    )
    if result.returncode != 0:
        raise LauncherError("container_inspect_failed")
    try:
        document = json.loads(result.stdout)
        if not isinstance(document, list) or len(document) != 1 or not isinstance(document[0], dict):
            raise ValueError
        return document[0]
    except (json.JSONDecodeError, ValueError):
        raise LauncherError("container_inspect_invalid") from None


def _labels_from_inspect(document: dict[str, object]) -> dict[str, str]:
    config = document.get("Config")
    if not isinstance(config, dict):
        raise LauncherError("container_inspect_invalid")
    labels = config.get("Labels")
    if not isinstance(labels, dict) or any(type(key) is not str or type(value) is not str for key, value in labels.items()):
        raise LauncherError("container_inspect_invalid")
    return labels


def require_owned_container(spec: InstanceSpec, document: dict[str, object]) -> None:
    labels = _labels_from_inspect(document)
    expected = {
        MANAGED_LABEL: MANAGED_VERSION,
        "io.hermternal.instance": spec.instance,
        "io.hermternal.port": str(spec.port),
        "io.hermternal.image": spec.image,
    }
    if any(labels.get(key) != value for key, value in expected.items()):
        raise LauncherError("container_not_launcher_owned")


def container_status(document: dict[str, object]) -> str:
    state = document.get("State")
    status = state.get("Status") if isinstance(state, dict) else None
    if type(status) is not str or not status:
        raise LauncherError("container_inspect_invalid")
    return status


def recovery_snapshot(spec: InstanceSpec, document: dict[str, object]) -> RecoverySnapshot:
    """Validate only the exact identity needed before a destructive action.

    Ordinary reuse keeps the historical label-only compatibility boundary. A
    stop or start is different: it needs a fresh inspect projection so a
    replaced container cannot inherit the launcher-owned name and labels.
    """

    require_owned_container(spec, document)
    container_id = document.get("Id")
    name = document.get("Name")
    image = document.get("ImageName")
    if (
        type(container_id) is not str
        or not container_id
        or type(name) is not str
        or name not in {spec.container, f"/{spec.container}"}
        or type(image) is not str
        or image not in {spec.image, expected_repo_digest(spec.image)}
    ):
        raise LauncherError("container_identity_unproven")

    mounts = document.get("Mounts")
    if not isinstance(mounts, list):
        raise LauncherError("container_identity_unproven")
    managed_mounts = [
        mount
        for mount in mounts
        if isinstance(mount, dict) and mount.get("Destination") == "/opt/data"
    ]
    if len(managed_mounts) != 1:
        raise LauncherError("container_identity_unproven")
    managed_mount = managed_mounts[0]
    if (
        managed_mount.get("Type") != "bind"
        or managed_mount.get("Source") != str(spec.data_dir)
    ):
        raise LauncherError("container_identity_unproven")
    # The published port/socket mapping is deliberately not an identity
    # rejection criterion: this lifecycle action is the narrowly scoped rebind.
    # Port availability is preflighted, while the exact container state is what
    # rollback restores; no mapping or listener is edited by this launcher.

    return RecoverySnapshot(
        container_id=container_id,
        name=name,
        image=image,
        data_source=str(spec.data_dir),
        status=container_status(document),
    )


def require_same_recovery_snapshot(
    spec: InstanceSpec,
    expected: RecoverySnapshot,
    document: dict[str, object],
) -> RecoverySnapshot:
    current = recovery_snapshot(spec, document)
    if (
        current.container_id != expected.container_id
        or current.name != expected.name
        or current.image != expected.image
        or current.data_source != expected.data_source
    ):
        raise LauncherError("container_recovery_race")
    return current


def _run_container_action(
    spec: InstanceSpec,
    action: str,
    runner: Runner,
    environment: Mapping[str, str],
    executable: str,
    failure_code: str,
) -> None:
    try:
        result = runner(
            (executable, action, spec.container),
            environment,
            CONTAINER_ACTION_TIMEOUT,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException:
        # Test runners and signal-aware adapters can fail synchronously. Do not
        # let their exception text become a launcher diagnostic.
        raise LauncherError(failure_code) from None
    if result.returncode != 0:
        raise LauncherError(failure_code)


def run_arguments(spec: InstanceSpec, executable: str) -> tuple[str, ...]:
    return (
        executable,
        "run",
        "--detach",
        "--name",
        spec.container,
        "--restart",
        "unless-stopped",
        "--label",
        f"{MANAGED_LABEL}={MANAGED_VERSION}",
        "--label",
        f"io.hermternal.instance={spec.instance}",
        "--label",
        f"io.hermternal.port={spec.port}",
        "--label",
        f"io.hermternal.image={spec.image}",
        "--volume",
        f"{spec.data_dir}:/opt/data",
        "--publish",
        f"127.0.0.1:{spec.port}:{DASHBOARD_PORT}",
        "--env",
        "HERMES_DASHBOARD",
        "--env",
        "HERMES_DASHBOARD_BASIC_AUTH_USERNAME",
        "--env",
        "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD",
        "--pull",
        "never",
        spec.image,
        "gateway",
        "run",
    )


def check_provider_readiness(endpoint: str, attempts: int, interval: float) -> None:
    if type(attempts) is not int or attempts < 1 or attempts > 600:
        raise LauncherError("readiness_attempts_invalid")
    if not isinstance(interval, (int, float)) or isinstance(interval, bool) or interval < 0 or interval > 30:
        raise LauncherError("readiness_interval_invalid")
    url = f"{endpoint}/api/auth/providers"
    for attempt in range(attempts):
        try:
            request = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(request, timeout=2) as response:
                if response.status != 200:
                    raise LauncherError("provider_readiness_unavailable")
                raw = response.read(MAX_PROVIDER_BYTES + 1)
            if len(raw) > MAX_PROVIDER_BYTES:
                raise LauncherError("provider_readiness_invalid")
            document = json.loads(raw.decode("utf-8"))
            providers = document.get("providers") if isinstance(document, dict) else None
            if not isinstance(providers, list):
                raise LauncherError("provider_readiness_invalid")
            for provider in providers:
                if (
                    isinstance(provider, dict)
                    and provider.get("name") == "basic"
                    and provider.get("supports_password") is True
                ):
                    return
            raise LauncherError("basic_provider_missing")
        except LauncherError as exc:
            if exc.code in {"provider_readiness_invalid", "basic_provider_missing"}:
                raise
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, UnicodeDecodeError):
            pass
        if attempt + 1 < attempts:
            time.sleep(interval)
    raise LauncherError("provider_readiness_timeout")


def remove_container(
    spec: InstanceSpec,
    runner: Runner,
    environment: Mapping[str, str],
    executable: str,
) -> bool:
    if not container_exists(spec, runner, environment, executable):
        return False
    document = inspect_container(spec, runner, environment, executable)
    require_owned_container(spec, document)
    result = runner((executable, "rm", "--force", spec.container), environment, 60)
    if result.returncode != 0:
        raise LauncherError("container_remove_failed")
    return True


def start_instance(
    spec: InstanceSpec,
    *,
    runner: Runner = run_command,
    readiness: ReadinessChecker = check_provider_readiness,
    port_checker: PortChecker = is_port_available,
    attempts: int = 60,
    interval: float = 1,
    executable: str | None = None,
    source_environment: Mapping[str, str] | None = None,
) -> tuple[dict[str, object], bool]:
    environment = clean_environment(source_environment)
    podman = executable or podman_path()
    podman_preflight(runner, environment, podman)
    verify_image(spec.image, runner, environment, podman)
    password = read_or_create_password(spec)
    _ensure_private_directory(spec.roots.data)
    _ensure_private_directory(spec.data_dir)

    if container_exists(spec, runner, environment, podman):
        document = inspect_container(spec, runner, environment, podman)
        require_owned_container(spec, document)
        original_status = container_status(document)
        if original_status == "running":
            readiness(spec.endpoint, attempts, interval)
            write_state(spec)
            return {**spec.public(), "status": "ready", "created": False}, False
        if original_status not in {"configured", "created", "stopped", "exited", "dead"}:
            raise LauncherError("container_state_unrecoverable")
        recovery_identity = recovery_snapshot(spec, document)
        if not port_checker(spec.port):
            raise LauncherError("port_unavailable")

        # Starting an existing stopped container is a transaction. Re-inspect
        # immediately before the action so a replacement cannot inherit the
        # launcher-owned name and labels. The rollback re-inspects again and
        # stops only the same container if it is still running.
        fresh_identity = require_same_recovery_snapshot(
            spec,
            recovery_identity,
            inspect_container(spec, runner, environment, podman),
        )
        if fresh_identity.status != original_status:
            raise LauncherError("container_recovery_race")
        recovery_attempted = False
        cleanup_done = False
        rollback_failure: LauncherError | None = None

        def rollback_once() -> LauncherError | None:
            nonlocal cleanup_done, rollback_failure
            if cleanup_done:
                return rollback_failure
            cleanup_done = True
            if not recovery_attempted:
                return None
            try:
                current_identity = require_same_recovery_snapshot(
                    spec,
                    recovery_identity,
                    inspect_container(spec, runner, environment, podman),
                )
                if current_identity.status == original_status:
                    return None
                if current_identity.status != "running":
                    raise LauncherError("container_recovery_rollback_failed")
                _run_container_action(
                    spec,
                    "stop",
                    runner,
                    environment,
                    podman,
                    "container_recovery_rollback_failed",
                )
            except BaseException as exc:
                rollback_failure = (
                    exc
                    if isinstance(exc, LauncherError)
                    else LauncherError("container_recovery_rollback_failed")
                )
            return rollback_failure

        try:
            recovery_attempted = True
            _run_container_action(
                spec,
                "start",
                runner,
                environment,
                podman,
                "container_start_failed",
            )
            readiness(spec.endpoint, attempts, interval)
            write_state(spec)
        except BaseException as exc:
            failed_rollback = rollback_once()
            if failed_rollback is not None and isinstance(exc, Exception):
                raise failed_rollback from None
            if isinstance(exc, LauncherError):
                raise
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise LauncherError("container_recovery_failed") from None
        return {**spec.public(), "status": "ready", "created": False}, False

    if not port_checker(spec.port):
        raise LauncherError("port_unavailable")

    child_environment = dict(environment)
    child_environment.update(
        {
            "HERMES_DASHBOARD": "1",
            "HERMES_DASHBOARD_BASIC_AUTH_USERNAME": spec.username,
            "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD": password,
        }
    )
    started = runner(run_arguments(spec, podman), child_environment, 300)
    if started.returncode != 0:
        raise LauncherError("container_start_failed")
    try:
        readiness(spec.endpoint, attempts, interval)
        write_state(spec)
    except BaseException:
        try:
            remove_container(spec, runner, environment, podman)
        except LauncherError:
            pass
        raise
    return {**spec.public(), "status": "ready", "created": True}, True


def start_many(
    specs: Sequence[InstanceSpec],
    **kwargs: object,
) -> list[dict[str, object]]:
    if not specs:
        raise LauncherError("instance_count_invalid")
    if len({spec.instance for spec in specs}) != len(specs) or len({spec.port for spec in specs}) != len(specs):
        raise LauncherError("batch_not_unique")
    results: list[dict[str, object]] = []
    created: list[InstanceSpec] = []
    try:
        for spec in specs:
            result, was_created = start_instance(spec, **kwargs)
            results.append(result)
            if was_created:
                created.append(spec)
    except BaseException:
        runner = kwargs.get("runner", run_command)
        executable = kwargs.get("executable")
        source_environment = kwargs.get("source_environment")
        environment = clean_environment(source_environment if isinstance(source_environment, Mapping) else None)
        podman = executable if isinstance(executable, str) else podman_path()
        for spec in reversed(created):
            try:
                remove_container(spec, runner, environment, podman)  # type: ignore[arg-type]
            except LauncherError:
                pass
        raise
    return results


def status_instance(
    spec: InstanceSpec,
    *,
    runner: Runner = run_command,
    executable: str | None = None,
    source_environment: Mapping[str, str] | None = None,
) -> dict[str, object]:
    environment = clean_environment(source_environment)
    podman = executable or podman_path()
    podman_preflight(runner, environment, podman)
    if not container_exists(spec, runner, environment, podman):
        return {**spec.public(), "status": "absent"}
    document = inspect_container(spec, runner, environment, podman)
    require_owned_container(spec, document)
    return {**spec.public(), "status": container_status(document)}


def _remove_owned_path(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    except OSError:
        raise LauncherError("owned_path_remove_failed") from None
    if stat.S_ISLNK(info.st_mode):
        raise LauncherError("owned_path_invalid")
    try:
        if stat.S_ISDIR(info.st_mode):
            shutil.rmtree(path)
        elif stat.S_ISREG(info.st_mode):
            path.unlink()
        else:
            raise LauncherError("owned_path_invalid")
    except PermissionError:
        raise LauncherError("owned_path_permission_denied") from None
    except OSError:
        raise LauncherError("owned_path_remove_failed") from None


def _remove_container_owned_data(
    spec: InstanceSpec,
    runner: Runner,
    environment: Mapping[str, str],
    executable: str,
) -> None:
    """Remove one bind-mounted data directory through Podman's user namespace.

    The official entrypoint can create mapped container-owned files under the
    host directory. Rootless ``podman unshare`` removes only the validated exact
    instance path without changing the image user, entrypoint, or runtime flags.
    """

    try:
        _remove_owned_path(spec.data_dir)
        return
    except LauncherError as exc:
        if exc.code != "owned_path_permission_denied":
            raise
    result = runner(
        (executable, "unshare", "rm", "-rf", "--", str(spec.data_dir)),
        environment,
        60,
    )
    if result.returncode != 0 or spec.data_dir.exists() or spec.data_dir.is_symlink():
        raise LauncherError("owned_path_remove_failed")


def stop_instance(
    spec: InstanceSpec,
    *,
    purge_data: bool = False,
    runner: Runner = run_command,
    executable: str | None = None,
    source_environment: Mapping[str, str] | None = None,
) -> dict[str, object]:
    environment = clean_environment(source_environment)
    podman = executable or podman_path()
    podman_preflight(runner, environment, podman)
    removed = remove_container(spec, runner, environment, podman)
    # Keep the non-secret state as an idempotency tombstone. A repeated stop can
    # still prove the exact instance identity without scanning or pruning Podman.
    write_state(spec)
    if purge_data:
        _remove_container_owned_data(spec, runner, environment, podman)
        _remove_owned_path(spec.credential_dir)
    return {
        **spec.public(),
        "status": "removed" if removed else "absent",
        "purged": purge_data,
    }


def specs_for_batch(
    prefix: str,
    count: int,
    base_port: int,
    *,
    image: str,
    username: str,
    roots: Roots,
) -> tuple[InstanceSpec, ...]:
    validate_instance(prefix)
    if type(count) is not int or count < 1 or count > 64512:
        raise LauncherError("instance_count_invalid")
    if base_port + count - 1 > 65535:
        raise LauncherError("port_range_invalid")
    return tuple(
        make_spec(
            f"{prefix}-{index}",
            base_port + index - 1,
            image=image,
            username=username,
            roots=roots,
        )
        for index in range(1, count + 1)
    )


def roots_from_args(args: argparse.Namespace) -> Roots:
    defaults = default_roots()
    return Roots(
        state=Path(args.state_root).expanduser() if args.state_root else defaults.state,
        data=Path(args.data_root).expanduser() if args.data_root else defaults.data,
        credentials=(
            Path(args.credential_root).expanduser()
            if args.credential_root
            else defaults.credentials
        ),
    )


def add_roots(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--state-root")
    parser.add_argument("--data-root")
    parser.add_argument("--credential-root")


def add_start_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--username", default=DEFAULT_USERNAME)
    parser.add_argument("--readiness-attempts", type=int, default=60)
    parser.add_argument("--readiness-interval", type=float, default=1)
    add_roots(parser)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)

    start = subparsers.add_parser("start")
    start.add_argument("--instance", required=True)
    start.add_argument("--port", required=True, type=int)
    add_start_options(start)

    start_many_parser = subparsers.add_parser("start-many")
    start_many_parser.add_argument("--prefix", required=True)
    start_many_parser.add_argument("--count", required=True, type=int)
    start_many_parser.add_argument("--base-port", required=True, type=int)
    add_start_options(start_many_parser)

    for operation in ("status", "endpoint", "credential-file", "stop"):
        command = subparsers.add_parser(operation)
        command.add_argument("--instance", required=True)
        if operation == "stop":
            command.add_argument("--purge-data", action="store_true")
        add_roots(command)

    stop_many_parser = subparsers.add_parser("stop-many")
    stop_many_parser.add_argument("--prefix", required=True)
    stop_many_parser.add_argument("--count", required=True, type=int)
    stop_many_parser.add_argument("--base-port", required=True, type=int)
    stop_many_parser.add_argument("--purge-data", action="store_true")
    stop_many_parser.add_argument("--image", default=DEFAULT_IMAGE)
    stop_many_parser.add_argument("--username", default=DEFAULT_USERNAME)
    add_roots(stop_many_parser)
    return parser


def execute(args: argparse.Namespace) -> dict[str, object]:
    roots = roots_from_args(args)
    if args.operation == "start":
        spec = make_spec(args.instance, args.port, image=args.image, username=args.username, roots=roots)
        result, _ = start_instance(
            spec,
            attempts=args.readiness_attempts,
            interval=args.readiness_interval,
        )
        return {"ok": True, "operation": "start", "result": result}
    if args.operation == "start-many":
        specs = specs_for_batch(
            args.prefix,
            args.count,
            args.base_port,
            image=args.image,
            username=args.username,
            roots=roots,
        )
        results = start_many(
            specs,
            attempts=args.readiness_attempts,
            interval=args.readiness_interval,
        )
        return {"ok": True, "operation": "start-many", "results": results}
    if args.operation in {"endpoint", "credential-file", "status", "stop"}:
        spec = load_state(args.instance, roots)
        if args.operation == "endpoint":
            return {"ok": True, "operation": "endpoint", "result": spec.public()}
        if args.operation == "credential-file":
            return {
                "ok": True,
                "operation": "credential-file",
                "result": {
                    "instance": spec.instance,
                    "credential_file": str(spec.credential_file),
                    "exists": spec.credential_file.is_file(),
                },
            }
        if args.operation == "status":
            return {"ok": True, "operation": "status", "result": status_instance(spec)}
        return {
            "ok": True,
            "operation": "stop",
            "result": stop_instance(spec, purge_data=args.purge_data),
        }
    if args.operation == "stop-many":
        specs = specs_for_batch(
            args.prefix,
            args.count,
            args.base_port,
            image=args.image,
            username=args.username,
            roots=roots,
        )
        results = [stop_instance(spec, purge_data=args.purge_data) for spec in specs]
        return {"ok": True, "operation": "stop-many", "results": results}
    raise LauncherError("operation_unknown")


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        payload = execute(args)
        status = 0
    except LauncherError as exc:
        payload = {"ok": False, "error": {"code": exc.code}}
        status = 2
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
