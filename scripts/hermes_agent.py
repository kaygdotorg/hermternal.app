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


if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
import live_run_marker


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


@dataclass(frozen=True)
class LauncherState:
    """One exact marker plus state record used by lifecycle operations."""

    spec: InstanceSpec
    marker: live_run_marker.RunMarker

    @property
    def container_id(self) -> str:
        return self.marker.container_id

    @property
    def run_id(self) -> str:
        return self.marker.run_id

    @property
    def marker_path(self) -> Path:
        return self.marker.marker_path


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


STATE_SCHEMA = "hermternal.live-run-state.v1"
STATE_KEYS = frozenset(
    {
        "schema",
        "status",
        "marker_path",
        "run_id",
        "instance",
        "container_id",
        "container_name",
        "image",
        "endpoint",
        "state_path",
        "credential_path",
        "credential_identity",
        "username",
        "data_path",
    }
)


def _marker_paths(marker_path: str | Path) -> live_run_marker.MarkerPaths:
    try:
        return live_run_marker.marker_paths(marker_path)
    except live_run_marker.MarkerError as error:
        raise LauncherError(error.code) from None


def _write_all(descriptor: int, content: bytes, code: str) -> None:
    view = memoryview(content)
    while view:
        try:
            written = os.write(descriptor, view)
        except OSError:
            raise LauncherError(code) from None
        if written <= 0:
            raise LauncherError(code)
        view = view[written:]


def _sync_parent(path: Path, code: str) -> None:
    try:
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        raise LauncherError(code) from None


def _create_private_file(path: Path, content: bytes, *, code: str) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except FileExistsError:
        raise LauncherError(f"{code}_exists") from None
    except OSError:
        raise LauncherError(code) from None
    try:
        _write_all(descriptor, content, code)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _sync_parent(path, code.replace("write", "sync"))


def _replace_private_file(path: Path, content: bytes, *, code: str) -> None:
    try:
        info = path.lstat()
    except OSError:
        raise LauncherError(f"{code}_missing") from None
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise LauncherError(f"{code}_invalid")
    temporary = path.with_name(f".{path.name}.tmp-{secrets.token_hex(8)}")
    try:
        _create_private_file(temporary, content, code=code)
        os.replace(temporary, path)
        _sync_parent(path, code.replace("write", "sync"))
    except LauncherError:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    except OSError:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise LauncherError(code) from None


def _read_private_file(path: Path, *, maximum: int, code: str) -> bytes:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
    except OSError:
        raise LauncherError(code) from None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size > maximum
        ):
            raise LauncherError(code)
        raw = bytearray()
        while len(raw) <= maximum:
            chunk = os.read(descriptor, maximum + 1 - len(raw))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_nlink) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_nlink,
        ):
            raise LauncherError(f"{code}_replaced")
        if len(raw) > maximum:
            raise LauncherError(f"{code}_oversized")
        return bytes(raw)
    except OSError:
        raise LauncherError(code) from None
    finally:
        os.close(descriptor)


def create_run_credential(marker_path: str | Path) -> tuple[str, live_run_marker.CredentialIdentity]:
    """Create one fresh run-scoped credential with exclusive creation."""

    paths = _marker_paths(marker_path)
    password = secrets.token_hex(24)
    try:
        _create_private_file(
            paths.credential,
            (password + "\n").encode("ascii"),
            code="credential_file_write_failed",
        )
        identity = live_run_marker.credential_lstat(paths.credential)
    except live_run_marker.MarkerError as error:
        raise LauncherError(error.code) from None
    return password, identity


def read_or_create_password(spec: InstanceSpec, *, marker_path: str | Path | None = None) -> str:
    """Compatibility name retained for callers; every new run is exclusive."""

    del spec
    if marker_path is None:
        raise LauncherError("marker_required")
    password, _ = create_run_credential(marker_path)
    return password


def validate_container_id(value: object) -> str:
    """Accept only Podman's immutable hexadecimal container identity."""

    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{12,64}", value) is None:
        raise LauncherError("instance_state_invalid")
    return value


def state_document(spec: InstanceSpec, binding: live_run_marker.RunMarker) -> dict[str, object]:
    return {
        "schema": STATE_SCHEMA,
        "status": binding.status,
        "marker_path": str(binding.marker_path),
        "run_id": binding.run_id,
        "instance": spec.instance,
        "container_id": validate_container_id(binding.container_id),
        "container_name": binding.container_name,
        "image": binding.image,
        "endpoint": binding.endpoint,
        "state_path": str(binding.state_path),
        "credential_path": str(binding.credential_path),
        "credential_identity": binding.credential_identity.document(),
        "username": spec.username,
        "data_path": str(spec.data_dir),
    }


def write_state(spec: InstanceSpec, binding: live_run_marker.RunMarker, *, replace: bool = False) -> None:
    paths = _marker_paths(binding.marker_path)
    if binding.state_path != paths.state:
        raise LauncherError("state_path_invalid")
    content = (json.dumps(state_document(spec, binding), sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if replace:
        _replace_private_file(paths.state, content, code="state_write_failed")
    else:
        _create_private_file(paths.state, content, code="state_write_failed")


def _state_document(raw: bytes) -> dict[str, object]:
    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise LauncherError("instance_state_duplicate_key")
            document[key] = value
        return document

    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate)
    except LauncherError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
        raise LauncherError("instance_state_invalid") from None
    if not isinstance(document, dict) or set(document) != STATE_KEYS:
        raise LauncherError("instance_state_invalid")
    return document


def load_launcher_state(marker_path: str | Path, roots: Roots) -> LauncherState:
    """Load one exact marker and its exact state file; never infer a run."""

    try:
        marker = live_run_marker.load_marker(marker_path)
    except live_run_marker.MarkerError as error:
        raise LauncherError(error.code) from None
    document = _state_document(_read_private_file(marker.state_path, maximum=MAX_STATE_BYTES, code="instance_state_invalid"))
    expected = {
        "schema": STATE_SCHEMA,
        "status": marker.status,
        "marker_path": str(marker.marker_path),
        "run_id": marker.run_id,
        "instance": marker.instance,
        "container_id": marker.container_id,
        "container_name": marker.container_name,
        "image": marker.image,
        "endpoint": marker.endpoint,
        "state_path": str(marker.state_path),
        "credential_path": str(marker.credential_path),
        "credential_identity": marker.credential_identity.document(),
    }
    for key, value in expected.items():
        if document.get(key) != value:
            raise LauncherError("instance_state_binding_mismatch")
    username = document.get("username")
    data_path = document.get("data_path")
    if not isinstance(username, str) or not username or not isinstance(data_path, str):
        raise LauncherError("instance_state_invalid")
    try:
        parsed = urllib.parse.urlsplit(marker.endpoint)
        port = parsed.port
    except (TypeError, ValueError):
        raise LauncherError("instance_state_invalid") from None
    if port is None:
        raise LauncherError("instance_state_invalid")
    spec = make_spec(marker.instance, port, image=marker.image, username=username, roots=roots)
    if data_path != str(spec.data_dir) or marker.container_name != spec.container:
        raise LauncherError("instance_state_binding_mismatch")
    return LauncherState(spec, marker)


def load_state(instance: str, roots: Roots) -> InstanceSpec:
    """Reject the legacy instance-only lookup; callers must pass one marker."""

    del instance, roots
    raise LauncherError("marker_required")


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
    *,
    target: str | None = None,
) -> dict[str, object]:
    result = runner(
        (executable, "container", "inspect", target or spec.container, "--format", "json"),
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


def require_owned_container(
    spec: InstanceSpec,
    document: dict[str, object],
    *,
    run_id: str | None = None,
) -> None:
    labels = _labels_from_inspect(document)
    expected = {
        MANAGED_LABEL: MANAGED_VERSION,
        "io.hermternal.instance": spec.instance,
        "io.hermternal.port": str(spec.port),
        "io.hermternal.image": spec.image,
    }
    if run_id is not None:
        expected["io.hermternal.run-id"] = run_id
    if any(labels.get(key) != value for key, value in expected.items()):
        raise LauncherError("container_not_launcher_owned")


def container_status(document: dict[str, object]) -> str:
    state = document.get("State")
    status = state.get("Status") if isinstance(state, dict) else None
    if type(status) is not str or not status:
        raise LauncherError("container_inspect_invalid")
    return status


def recovery_snapshot(
    spec: InstanceSpec,
    document: dict[str, object],
    *,
    run_id: str | None = None,
) -> RecoverySnapshot:
    """Validate only the exact identity needed before a destructive action.

    Ordinary reuse keeps the historical label-only compatibility boundary. A
    stop or start is different: it needs a fresh inspect projection so a
    replaced container cannot inherit the launcher-owned name and labels.
    """

    require_owned_container(spec, document, run_id=run_id)
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


def require_loopback_endpoint_mapping(spec: InstanceSpec, document: dict[str, object]) -> None:
    """Require the selected port to be this container's sole Dashboard mapping."""

    network = document.get("NetworkSettings")
    ports = network.get("Ports") if isinstance(network, dict) else None
    expected_key = f"{DASHBOARD_PORT}/tcp"
    if not isinstance(ports, dict) or set(ports) != {expected_key}:
        raise LauncherError("container_endpoint_unproven")
    binding = ports.get(expected_key)
    if not isinstance(binding, list) or len(binding) != 1 or not isinstance(binding[0], dict):
        raise LauncherError("container_endpoint_unproven")
    host_ip = binding[0].get("HostIp")
    host_port = binding[0].get("HostPort")
    # Accept only the launcher-created IPv4 loopback binding. A wildcard, IPv6,
    # extra mapping, missing mapping, or substituted port fails before the
    # credential file is read by the live-proof handoff.
    if host_ip != "127.0.0.1" or host_port != str(spec.port):
        raise LauncherError("container_endpoint_unproven")


def verify_handoff_endpoint(
    state: LauncherState,
    *,
    runner: Runner = run_command,
    executable: str | None = None,
    source_environment: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Freshly prove the running launcher container owns its exact endpoint.

    This is intentionally invoked by ``endpoint`` immediately before the
    credential handoff. It inspects the persisted immutable ID, never a mutable
    name, and exposes only public metadata on success.
    """

    if state.marker.status != live_run_marker.STATUS_RUNNING:
        raise LauncherError("marker_not_selectable")
    environment = clean_environment(source_environment)
    podman = executable or podman_path()
    podman_preflight(runner, environment, podman)
    document = inspect_container(state.spec, runner, environment, podman, target=state.container_id)
    snapshot = recovery_snapshot(state.spec, document, run_id=state.run_id)
    if snapshot.container_id != state.container_id:
        raise LauncherError("container_replaced")
    if snapshot.status != "running":
        raise LauncherError("container_not_running")
    require_loopback_endpoint_mapping(state.spec, document)
    try:
        live_run_marker.verify_credential_identity(state.marker)
    except live_run_marker.MarkerError as error:
        raise LauncherError(error.code) from None
    # Keep the handoff result bounded. It is the only operation that releases
    # the exact marker and credential paths to a transient local helper.
    return {
        "status": "running",
        "endpoint": state.marker.endpoint,
        "marker_path": str(state.marker.marker_path),
        "credential_file": str(state.marker.credential_path),
    }


def _run_container_action(
    target: str,
    action: str,
    runner: Runner,
    environment: Mapping[str, str],
    executable: str,
    failure_code: str,
) -> None:
    try:
        result = runner(
            (executable, action, target),
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


def run_arguments(spec: InstanceSpec, executable: str, run_id: str) -> tuple[str, ...]:
    if live_run_marker.RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise LauncherError("run_id_invalid")
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
        "--label",
        f"io.hermternal.run-id={run_id}",
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


def _public_run_result(spec: InstanceSpec, binding: live_run_marker.RunMarker, *, status: str, created: bool) -> dict[str, object]:
    return {
        "instance": spec.instance,
        "status": status,
        "marker_path": str(binding.marker_path),
        "created": created,
    }


def _load_bound_state(marker_path: str | Path, roots: Roots) -> LauncherState:
    return load_launcher_state(marker_path, roots)


def _inspect_bound_container(
    state: LauncherState,
    runner: Runner,
    environment: Mapping[str, str],
    executable: str,
) -> tuple[dict[str, object], RecoverySnapshot]:
    document = inspect_container(state.spec, runner, environment, executable, target=state.container_id)
    snapshot = recovery_snapshot(state.spec, document, run_id=state.run_id)
    if snapshot.container_id != state.container_id:
        raise LauncherError("container_replaced")
    return document, snapshot


def _file_identity(path: Path, *, code: str) -> tuple[int, int, int, int, int]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise LauncherError(f"{code}_missing") from None
    except OSError:
        raise LauncherError(code) from None
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise LauncherError(f"{code}_invalid")
    return (info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode), info.st_size, info.st_nlink)


def _remove_exact_file(
    path: Path,
    *,
    code: str,
    expected: tuple[int, int, int, int, int] | live_run_marker.CredentialIdentity | None = None,
    missing_ok: bool = False,
) -> None:
    try:
        identity = _file_identity(path, code=code)
    except LauncherError as error:
        if missing_ok and error.code == f"{code}_missing":
            return
        raise
    if isinstance(expected, live_run_marker.CredentialIdentity):
        expected_tuple = (expected.device, expected.inode, expected.mode, expected.size, expected.nlink)
        if identity != expected_tuple:
            raise LauncherError(f"{code}_replaced")
    elif expected is not None and identity != expected:
        raise LauncherError(f"{code}_replaced")
    try:
        path.unlink()
    except OSError:
        raise LauncherError(code) from None
    _sync_parent(path, code.replace("remove", "sync"))


def _remove_bound_container(
    state: LauncherState,
    runner: Runner,
    environment: Mapping[str, str],
    executable: str,
) -> None:
    try:
        _inspect_bound_container(state, runner, environment, executable)
    except LauncherError as error:
        if error.code != "container_inspect_failed":
            raise
        # A retry after a successful exact rm may find no container. Query only
        # the pinned immutable ID so cleanup can finish without adopting a name
        # or scanning the engine for a substitute.
        exists = runner(
            (executable, "container", "exists", state.container_id),
            environment,
            CONTAINER_ACTION_TIMEOUT,
        )
        if exists.returncode == 1:
            return
        if exists.returncode != 0:
            raise LauncherError("container_lookup_failed")
        raise
    result = runner((executable, "rm", "--force", state.container_id), environment, CONTAINER_ACTION_TIMEOUT)
    if result.returncode != 0:
        raise LauncherError("container_remove_failed")


def _marker_exists(marker_path: str | Path) -> bool:
    try:
        live_run_marker.load_marker(marker_path)
    except live_run_marker.MarkerError as error:
        if error.code == "marker_missing":
            return False
        raise LauncherError(error.code) from None
    return True


def start_instance(
    spec: InstanceSpec,
    *,
    marker_path: str | Path | None = None,
    runner: Runner = run_command,
    readiness: ReadinessChecker = check_provider_readiness,
    port_checker: PortChecker = is_port_available,
    attempts: int = 60,
    interval: float = 1,
    executable: str | None = None,
    source_environment: Mapping[str, str] | None = None,
) -> tuple[dict[str, object], bool]:
    if marker_path is None:
        raise LauncherError("marker_required")
    paths = _marker_paths(marker_path)
    environment = clean_environment(source_environment)
    podman = executable or podman_path()
    podman_preflight(runner, environment, podman)
    verify_image(spec.image, runner, environment, podman)
    _ensure_private_directory(spec.roots.data)
    _ensure_private_directory(spec.data_dir)

    if _marker_exists(paths.marker):
        state = _load_bound_state(paths.marker, spec.roots)
        if (
            state.spec.instance != spec.instance
            or state.spec.port != spec.port
            or state.spec.image != spec.image
            or state.spec.username != spec.username
        ):
            raise LauncherError("marker_spec_mismatch")
        if state.marker.status != live_run_marker.STATUS_RUNNING:
            raise LauncherError("cleanup_incomplete")
        try:
            live_run_marker.verify_credential_identity(state.marker)
        except live_run_marker.MarkerError as error:
            raise LauncherError(error.code) from None
        document, current = _inspect_bound_container(state, runner, environment, podman)
        original_status = current.status
        if original_status == "running":
            readiness(state.marker.endpoint, attempts, interval)
            write_state(state.spec, state.marker, replace=True)
            return _public_run_result(spec, state.marker, status="ready", created=False), False
        if original_status not in {"configured", "created", "stopped", "exited", "dead"}:
            raise LauncherError("container_state_unrecoverable")
        if not port_checker(spec.port):
            raise LauncherError("port_unavailable")
        fresh = _inspect_bound_container(state, runner, environment, podman)[1]
        if fresh.status != original_status:
            raise LauncherError("container_recovery_race")
        recovery_attempted = False
        try:
            recovery_attempted = True
            _run_container_action(
                state.container_id,
                "start",
                runner,
                environment,
                podman,
                "container_start_failed",
            )
            readiness(state.marker.endpoint, attempts, interval)
            write_state(state.spec, state.marker, replace=True)
        except BaseException as exc:
            rollback_error: LauncherError | None = None
            if recovery_attempted:
                try:
                    rollback_state = _inspect_bound_container(state, runner, environment, podman)[1]
                    if rollback_state.status == "running":
                        _run_container_action(
                            state.container_id,
                            "stop",
                            runner,
                            environment,
                            podman,
                            "container_recovery_rollback_failed",
                        )
                    elif rollback_state.status != original_status:
                        rollback_error = LauncherError("container_recovery_rollback_failed")
                except LauncherError as rollback:
                    rollback_error = rollback
            if rollback_error is not None and isinstance(exc, Exception):
                raise rollback_error from None
            if isinstance(exc, LauncherError):
                raise
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise LauncherError("container_recovery_failed") from None
        return _public_run_result(spec, state.marker, status="ready", created=False), False

    # A container under the deterministic name without its exact marker is not
    # adoptable. In particular, a stopped or foreign object is never started or
    # removed merely because its name resembles this instance.
    if container_exists(spec, runner, environment, podman):
        raise LauncherError("marker_missing")
    if not port_checker(spec.port):
        raise LauncherError("port_unavailable")

    # Generate the opaque run identity before the first container-start command.
    run_id = live_run_marker.new_run_id()
    password, credential_identity = create_run_credential(paths.marker)
    child_environment = dict(environment)
    child_environment.update(
        {
            "HERMES_DASHBOARD": "1",
            "HERMES_DASHBOARD_BASIC_AUTH_USERNAME": spec.username,
            "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD": password,
        }
    )
    started = runner(run_arguments(spec, podman, run_id), child_environment, 300)
    if started.returncode != 0:
        try:
            _remove_exact_file(paths.credential, code="credential_remove_failed")
        except LauncherError:
            pass
        raise LauncherError("container_start_failed")
    document = inspect_container(spec, runner, environment, podman)
    snapshot = recovery_snapshot(spec, document, run_id=run_id)
    if snapshot.status != "running":
        raise LauncherError("container_not_running")
    require_loopback_endpoint_mapping(spec, document)
    binding = live_run_marker.new_marker(
        paths.marker,
        run_id=run_id,
        instance=spec.instance,
        container_id=snapshot.container_id,
        container_name=spec.container,
        image=spec.image,
        endpoint=spec.endpoint,
        credential_identity=credential_identity,
    )
    write_state(spec, binding)
    try:
        live_run_marker.create_marker(binding)
    except live_run_marker.MarkerError as error:
        raise LauncherError(error.code) from None
    try:
        readiness(binding.endpoint, attempts, interval)
    except BaseException:
        # The marker now pins this exact container, so a failed startup can use
        # the same bounded cleanup path instead of a name/glob/prune fallback.
        try:
            stop_instance(
                binding.marker_path,
                roots=spec.roots,
                runner=runner,
                executable=podman,
                source_environment=source_environment,
            )
        except LauncherError:
            pass
        raise
    return _public_run_result(spec, binding, status="ready", created=True), True


def start_many(
    specs: Sequence[InstanceSpec],
    marker_paths: Sequence[str | Path] | None = None,
    **kwargs: object,
) -> list[dict[str, object]]:
    if not specs:
        raise LauncherError("instance_count_invalid")
    if marker_paths is None or len(marker_paths) != len(specs):
        raise LauncherError("marker_count_invalid")
    if len({spec.instance for spec in specs}) != len(specs) or len({spec.port for spec in specs}) != len(specs):
        raise LauncherError("batch_not_unique")
    try:
        exact_marker_paths = tuple(_marker_paths(path).marker for path in marker_paths)
    except LauncherError:
        raise
    if len(set(exact_marker_paths)) != len(exact_marker_paths):
        raise LauncherError("marker_not_unique")
    results: list[dict[str, object]] = []
    created: list[tuple[InstanceSpec, str | Path]] = []
    try:
        for spec, marker_path in zip(specs, exact_marker_paths):
            result, was_created = start_instance(spec, marker_path=marker_path, **kwargs)
            results.append(result)
            if was_created:
                created.append((spec, marker_path))
    except BaseException:
        runner = kwargs.get("runner", run_command)
        executable = kwargs.get("executable")
        source_environment = kwargs.get("source_environment")
        for spec, marker_path in reversed(created):
            try:
                stop_instance(
                    marker_path,
                    roots=spec.roots,
                    runner=runner,  # type: ignore[arg-type]
                    executable=executable if isinstance(executable, str) else None,
                    source_environment=source_environment if isinstance(source_environment, Mapping) else None,
                )
            except LauncherError:
                pass
        raise
    return results


def status_instance(
    marker_path: str | Path,
    *,
    roots: Roots | None = None,
    runner: Runner = run_command,
    executable: str | None = None,
    source_environment: Mapping[str, str] | None = None,
) -> dict[str, object]:
    state = _load_bound_state(marker_path, roots or default_roots())
    if state.marker.status != live_run_marker.STATUS_RUNNING:
        return {"status": state.marker.status, "marker_path": str(state.marker.marker_path)}
    environment = clean_environment(source_environment)
    podman = executable or podman_path()
    podman_preflight(runner, environment, podman)
    _, snapshot = _inspect_bound_container(state, runner, environment, podman)
    return {
        "instance": state.spec.instance,
        "status": snapshot.status,
        "marker_path": str(state.marker.marker_path),
    }


def _retain_cleanup_failed(
    state: LauncherState,
    *,
    expected_marker: tuple[int, int, int, int, int] | None = None,
    expected_state: tuple[int, int, int, int, int] | None = None,
) -> None:
    """Retain a tombstone without overwriting a raced marker or state file."""

    if expected_marker is not None:
        try:
            if _file_identity(state.marker_path, code="marker") != expected_marker:
                return
        except LauncherError:
            return

    tombstone = live_run_marker.cleanup_failed(state.marker)
    try:
        try:
            current_state = _file_identity(state.marker.state_path, code="state")
        except LauncherError as error:
            if error.code != "state_missing":
                return
            # The required cleanup order removes state before the marker. If
            # marker unlink then fails, recreate only this exact sibling state so
            # a later explicit retry can finish the same pinned cleanup.
            write_state(state.spec, tombstone, replace=False)
        else:
            if expected_state is not None and current_state != expected_state:
                return
            write_state(state.spec, tombstone, replace=True)

        if expected_marker is not None:
            if _file_identity(state.marker_path, code="marker") != expected_marker:
                return
        live_run_marker.replace_marker(tombstone)
    except (LauncherError, live_run_marker.MarkerError):
        pass


def _remove_marker_last(state: LauncherState, expected: tuple[int, int, int, int, int]) -> None:
    current = _file_identity(state.marker_path, code="marker")
    if current != expected:
        raise LauncherError("marker_replaced")
    try:
        state.marker_path.unlink()
    except OSError:
        raise LauncherError("marker_remove_failed") from None
    _sync_parent(state.marker_path, "marker_sync_failed")


def stop_instance(
    marker_path: str | Path,
    *,
    roots: Roots | None = None,
    purge_data: bool = False,
    runner: Runner = run_command,
    executable: str | None = None,
    source_environment: Mapping[str, str] | None = None,
) -> dict[str, object]:
    if purge_data:
        raise LauncherError("purge_not_supported")
    state = _load_bound_state(marker_path, roots or default_roots())
    marker_identity = _file_identity(state.marker_path, code="marker")
    environment = clean_environment(source_environment)
    podman = executable or podman_path()
    podman_preflight(runner, environment, podman)
    state_identity = _file_identity(state.marker.state_path, code="state")
    credential_missing_after_failed_cleanup = False
    if state.marker.status == live_run_marker.STATUS_CLEANUP_FAILED:
        try:
            state.marker.credential_path.lstat()
        except FileNotFoundError:
            # A prior exact cleanup may already have removed the credential
            # before marker unlink failed. Treat only that exact absence as
            # idempotent; replacements and nonregular paths still verify below.
            credential_missing_after_failed_cleanup = True
        except OSError:
            pass
    try:
        if not credential_missing_after_failed_cleanup:
            live_run_marker.verify_credential_identity(state.marker)
        credential_identity = state.marker.credential_identity
        _remove_bound_container(state, runner, environment, podman)
        _remove_exact_file(
            state.marker.credential_path,
            code="credential_remove_failed",
            expected=credential_identity,
            missing_ok=state.marker.status == live_run_marker.STATUS_CLEANUP_FAILED,
        )
        _remove_exact_file(
            state.marker.state_path,
            code="state_remove_failed",
            expected=state_identity,
            missing_ok=state.marker.status == live_run_marker.STATUS_CLEANUP_FAILED,
        )
        _remove_marker_last(state, marker_identity)
    except live_run_marker.MarkerError as error:
        _retain_cleanup_failed(
            state,
            expected_marker=marker_identity,
            expected_state=state_identity,
        )
        raise LauncherError(error.code) from None
    except LauncherError:
        _retain_cleanup_failed(
            state,
            expected_marker=marker_identity,
            expected_state=state_identity,
        )
        raise
    return {
        "instance": state.spec.instance,
        "status": "removed",
        "marker_path": str(state.marker.marker_path),
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


def add_marker(parser: argparse.ArgumentParser, *, many: bool = False) -> None:
    parser.add_argument("--marker", action="append" if many else None, required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)

    start = subparsers.add_parser("start")
    start.add_argument("--instance", required=True)
    start.add_argument("--port", required=True, type=int)
    add_marker(start)
    add_start_options(start)

    start_many_parser = subparsers.add_parser("start-many")
    start_many_parser.add_argument("--prefix", required=True)
    start_many_parser.add_argument("--count", required=True, type=int)
    start_many_parser.add_argument("--base-port", required=True, type=int)
    add_marker(start_many_parser, many=True)
    add_start_options(start_many_parser)

    for operation in ("status", "endpoint", "credential-file", "stop"):
        command = subparsers.add_parser(operation)
        add_marker(command)
        if operation == "stop":
            command.add_argument("--purge-data", action="store_true")
        add_roots(command)

    stop_many_parser = subparsers.add_parser("stop-many")
    add_marker(stop_many_parser, many=True)
    stop_many_parser.add_argument("--purge-data", action="store_true")
    add_roots(stop_many_parser)
    return parser


def execute(args: argparse.Namespace) -> dict[str, object]:
    roots = roots_from_args(args)
    if args.operation == "start":
        spec = make_spec(args.instance, args.port, image=args.image, username=args.username, roots=roots)
        result, _ = start_instance(
            spec,
            marker_path=args.marker,
            attempts=args.readiness_attempts,
            interval=args.readiness_interval,
        )
        return {"ok": True, "operation": "start", "result": result}
    if args.operation == "start-many":
        if len(args.marker) != args.count:
            raise LauncherError("marker_count_invalid")
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
            args.marker,
            attempts=args.readiness_attempts,
            interval=args.readiness_interval,
        )
        return {"ok": True, "operation": "start-many", "results": results}
    if args.operation in {"endpoint", "credential-file"}:
        state = _load_bound_state(args.marker, roots)
        result = verify_handoff_endpoint(state)
        return {"ok": True, "operation": args.operation, "result": result}
    if args.operation == "status":
        return {
            "ok": True,
            "operation": "status",
            "result": status_instance(args.marker, roots=roots),
        }
    if args.operation == "stop":
        return {
            "ok": True,
            "operation": "stop",
            "result": stop_instance(args.marker, roots=roots, purge_data=args.purge_data),
        }
    if args.operation == "stop-many":
        results = [stop_instance(path, roots=roots, purge_data=args.purge_data) for path in args.marker]
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
