#!/usr/bin/env python3
"""Run the reviewed rootless Podman Compose Hermes upstream fleet contract.

The launcher has one deployment boundary: every requested instance is a
separate Compose project with one private network and one named data volume.
The image is the official upstream image addressed by an immutable manifest
 digest.  The launcher never builds, tags, relabels, publishes, or mounts a
host path into the image.  It also never passes provider configuration through
from the caller's environment.

The normal command path is deliberately suitable for offline contract tests.
Live commands are explicit and use only the native ``podman`` CLI plus the
``podman-compose`` executable.  The ``demo`` command has a separate
authorization gate for the one no-provider VM smoke described in README.md.
All engine output is treated as untrusted diagnostic input and is omitted from
public evidence; callers receive bounded status objects instead.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import errno
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parent
CASES_PATH = ROOT / "cases.json"
VM_EVIDENCE_PATH = ROOT / "vm-demo-evidence.json"
VM_EVIDENCE_ANCHOR_PATH = ROOT / "vm-demo-evidence-sha256.txt"
SCHEMA = "hermternal.integration.hermes-upstream-fleet.v1"
CASES_SCHEMA = "hermternal.integration.hermes-upstream-fleet-cases.v1"
IMAGE_REPOSITORY = "docker.io/nousresearch/hermes-agent"
# Docker Hub's 2026-08-06 multi-platform ``latest`` manifest is frozen here.
# The tag is intentionally absent from every rendered service definition.
PINNED_IMAGE_DIGEST = "sha256:9a515dbef568dc625b217a7e699128e1a9d5abc8f4f93fd743fc894b0e7b0ccb"
PINNED_IMAGE = f"{IMAGE_REPOSITORY}@{PINNED_IMAGE_DIGEST}"
IMAGE_SOURCE_URL = "https://hub.docker.com/r/nousresearch/hermes-agent"
PROJECT_PREFIX = "hermes-upstream-fleet"
SERVICE_NAME = "hermes"
PRIVATE_PORT = 8000
COMPOSE_EXECUTABLE = "podman-compose"
ENGINE_EXECUTABLE = "podman"
MAX_CPU = Decimal("6.00")
MAX_MEMORY_MIB = 18 * 1024
MAX_PIDS = 3712
MAX_INSTANCES = 16
MAX_ID_LENGTH = 14
MAX_COMBINED_ID_LENGTH = 27
MAX_EVIDENCE_BYTES = 16 * 1024
MAX_DIAGNOSTIC_BYTES = 512
# Capture is bounded while pipes are drained, not after an unbounded
# subprocess.run() allocation.  Structured JSON that exceeds this budget is
# rejected by its parser instead of being treated as complete evidence.
MAX_CAPTURE_BYTES = 64 * 1024
MAX_STATE_BYTES = 512 * 1024
STATE_DIR_MODE = 0o700
STATE_FILE_MODE = 0o600
TRUSTED_EXECUTABLE_DIRS = (
    Path("/opt/homebrew/bin"),
    Path("/usr/local/bin"),
    Path("/usr/bin"),
    Path("/bin"),
)
TRUSTED_EXECUTABLE_CANDIDATES = {
    ENGINE_EXECUTABLE: tuple(directory / ENGINE_EXECUTABLE for directory in TRUSTED_EXECUTABLE_DIRS),
    COMPOSE_EXECUTABLE: tuple(directory / COMPOSE_EXECUTABLE for directory in TRUSTED_EXECUTABLE_DIRS),
}
TRUSTED_PATH = os.pathsep.join(str(directory) for directory in TRUSTED_EXECUTABLE_DIRS)
ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,12}[a-z0-9])?$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE_RE = re.compile(r"^docker\.io/nousresearch/hermes-agent@sha256:[0-9a-f]{64}$")

# These are the reviewed startup capabilities from the rootless-init contract.
# The launcher does not broaden this list for a workload profile.
APPROVED_CAPABILITIES = ("CAP_CHOWN", "CAP_SETGID", "CAP_SETUID")


class ContractError(Exception):
    """A stable, non-sensitive contract failure code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ResourceProfile:
    """A reviewed per-instance resource reservation."""

    name: str
    cpu: Decimal
    memory_mib: int
    pids: int
    purpose: str

    def public(self) -> dict[str, object]:
        return {
            "name": self.name,
            "cpu": format(self.cpu, "f"),
            "memory_mib": self.memory_mib,
            "pids": self.pids,
        }


PROFILES: dict[str, ResourceProfile] = {
    "auth": ResourceProfile(
        "auth", Decimal("0.75"), 2048, 512, "native and browser-auth boundary checks"
    ),
    "sessions-search": ResourceProfile(
        "sessions-search", Decimal("1.25"), 4096, 768, "session listing and search checks"
    ),
    "stream-reconnect": ResourceProfile(
        "stream-reconnect", Decimal("1.00"), 3072, 768, "stream interruption and reconnect checks"
    ),
    "image-pty": ResourceProfile(
        "image-pty", Decimal("1.50"), 6144, 1024, "image attachment and PTY boundary checks"
    ),
}


@dataclass(frozen=True)
class ResourceTotals:
    cpu: Decimal = Decimal("0")
    memory_mib: int = 0
    pids: int = 0

    def add(self, profile: ResourceProfile) -> "ResourceTotals":
        return ResourceTotals(
            self.cpu + profile.cpu,
            self.memory_mib + profile.memory_mib,
            self.pids + profile.pids,
        )

    def public(self) -> dict[str, object]:
        return {
            "cpu": format(self.cpu, "f"),
            "memory_mib": self.memory_mib,
            "pids": self.pids,
        }


@dataclass(frozen=True)
class InstancePlan:
    fleet_id: str
    instance_id: str
    profile: ResourceProfile
    project: str
    network: str
    volume: str
    endpoint: str

    def public(self) -> dict[str, object]:
        return {
            "id": self.instance_id,
            "profile": self.profile.name,
            "project": self.project,
            "network": self.network,
            "volume": self.volume,
            "endpoint": self.endpoint,
            "endpoint_scope": "private_compose_network",
            "published": False,
            "resources": self.profile.public(),
        }


@dataclass(frozen=True)
class FleetPlan:
    fleet_id: str
    instances: tuple[InstancePlan, ...]
    totals: ResourceTotals

    def public(self) -> dict[str, object]:
        return {
            "schema": SCHEMA,
            "fleet_id": self.fleet_id,
            "image": {
                "repository": IMAGE_REPOSITORY,
                "digest": PINNED_IMAGE_DIGEST,
                "reference": PINNED_IMAGE,
            },
            "executor": {
                "engine": ENGINE_EXECUTABLE,
                "compose": COMPOSE_EXECUTABLE,
                "rootless_required": True,
                "provider": "none",
            },
            "budget": {
                "cpu": format(MAX_CPU, "f"),
                "memory_mib": MAX_MEMORY_MIB,
                "pids": MAX_PIDS,
            },
            "reserved": self.totals.public(),
            "instances": [instance.public() for instance in self.instances],
        }


@dataclass(frozen=True)
class CommandResult:
    """A bounded internal command result; raw text never enters evidence."""

    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False


Runner = Callable[[Sequence[str], Mapping[str, str], float], CommandResult]


@dataclass(frozen=True)
class InstanceOperation:
    instance: InstancePlan
    status: str
    exit_code: int | None = None
    leftovers: dict[str, int | None] | None = None

    def public(self) -> dict[str, object]:
        result: dict[str, object] = {
            "id": self.instance.instance_id,
            "project": self.instance.project,
            "profile": self.instance.profile.name,
            "status": self.status,
        }
        if self.exit_code is not None:
            result["exit_code"] = self.exit_code
        if self.leftovers is not None:
            result["leftovers"] = self.leftovers
        return result


BLOCKED_ENV_EXACT = {
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH",
    "CONTAINER_HOST",
    "CONTAINER_CONNECTION",
    "COMPOSE_FILE",
    "COMPOSE_PROJECT_NAME",
    "COMPOSE_PROFILES",
    "HERMES_PROVIDER",
    "HERMES_PROVIDER_NAME",
    "HERMES_PROVIDER_URL",
    "HERMES_PROVIDER_CONFIG",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "OPENROUTER_API_KEY",
    "XAI_API_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
}
BLOCKED_ENV_PREFIXES = ("DOCKER_", "COMPOSE_", "HERMES_PROVIDER_")


def _is_provider_secret(name: str) -> bool:
    upper = name.upper()
    return upper.endswith("_API_KEY") or upper.endswith("_API_TOKEN") or upper.endswith(
        "_ACCESS_TOKEN"
    )


def clean_environment(source: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return a provider-free environment for Podman and Compose.

    Clearing instead of overriding these values matters because Compose can
    otherwise select a Docker provider or interpolate a host provider secret
    before the generated service is even parsed.
    """

    values = dict(os.environ if source is None else source)
    for name in tuple(values):
        upper = name.upper()
        if (
            upper in BLOCKED_ENV_EXACT
            or upper.startswith(BLOCKED_ENV_PREFIXES)
            or _is_provider_secret(upper)
        ):
            values.pop(name, None)
    # Absolute executable paths make the caller's PATH irrelevant.  Keep a
    # fixed search path too because podman-compose may launch podman itself.
    values["PATH"] = TRUSTED_PATH
    # These are launcher-owned policy values, not caller-provided provider data.
    values["PODMAN_COMPOSE_PROVIDER"] = "podman-compose"
    values["HERMES_PROVIDER_AUTO_DISCOVERY"] = "0"
    return values


def validate_image_reference(reference: str = PINNED_IMAGE) -> None:
    if not IMAGE_RE.fullmatch(reference or ""):
        raise ContractError("image_digest_required")
    if reference != PINNED_IMAGE:
        raise ContractError("image_digest_not_reviewed")
    if not DIGEST_RE.fullmatch(PINNED_IMAGE_DIGEST):
        raise ContractError("reviewed_digest_invalid")


def validate_identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or len(value) == 0 or len(value) > MAX_ID_LENGTH:
        raise ContractError(f"unsafe_{label}")
    if not ID_RE.fullmatch(value):
        raise ContractError(f"unsafe_{label}")
    return value


def parse_instance_spec(value: str, default_profile: str = "auth") -> tuple[str, str]:
    if not isinstance(value, str):
        raise ContractError("unsafe_instance")
    instance_id, separator, profile = value.partition(":")
    if not separator:
        profile = default_profile
    validate_identifier(instance_id, "instance")
    if profile not in PROFILES:
        raise ContractError("unknown_profile")
    return instance_id, profile


def make_names(fleet_id: str, instance_id: str) -> tuple[str, str, str]:
    validate_identifier(fleet_id, "fleet")
    validate_identifier(instance_id, "instance")
    if len(fleet_id) + 1 + len(instance_id) > MAX_COMBINED_ID_LENGTH:
        raise ContractError("name_budget_exceeded")
    project = f"{PROJECT_PREFIX}-{fleet_id}-{instance_id}"
    network = f"{project}-private"
    volume = f"{project}-data"
    if max(map(len, (project, network, volume))) > 63:
        raise ContractError("name_budget_exceeded")
    return project, network, volume


def build_plan(
    fleet_id: str,
    instances: Iterable[tuple[str, str]] | None = None,
    *,
    count: int | None = None,
    default_profile: str = "auth",
) -> FleetPlan:
    """Build and budget-check deterministic isolated instance plans."""

    validate_identifier(fleet_id, "fleet")
    if default_profile not in PROFILES:
        raise ContractError("unknown_profile")
    if instances is not None and count is not None:
        raise ContractError("count_and_instances_conflict")
    if instances is None:
        if count is None:
            count = 1
        if type(count) is not int or count < 1 or count > MAX_INSTANCES:
            raise ContractError("invalid_instance_count")
        items = [(f"instance-{index:02d}", default_profile) for index in range(1, count + 1)]
    else:
        items = list(instances)
        if not items or len(items) > MAX_INSTANCES:
            raise ContractError("invalid_instance_count")

    seen: set[str] = set()
    plans: list[InstancePlan] = []
    totals = ResourceTotals()
    for item in items:
        if type(item) is not tuple or len(item) != 2:
            raise ContractError("unsafe_instance")
        instance_id, profile_name = item
        validate_identifier(instance_id, "instance")
        if instance_id in seen:
            raise ContractError("duplicate_instance")
        seen.add(instance_id)
        if profile_name not in PROFILES:
            raise ContractError("unknown_profile")
        project, network, volume = make_names(fleet_id, instance_id)
        profile = PROFILES[profile_name]
        totals = totals.add(profile)
        plans.append(
            InstancePlan(
                fleet_id,
                instance_id,
                profile,
                project,
                network,
                volume,
                f"http://{SERVICE_NAME}:{PRIVATE_PORT}",
            )
        )

    if totals.cpu > MAX_CPU:
        raise ContractError("cpu_budget_exceeded")
    if totals.memory_mib > MAX_MEMORY_MIB:
        raise ContractError("memory_budget_exceeded")
    if totals.pids > MAX_PIDS:
        raise ContractError("pid_budget_exceeded")
    return FleetPlan(fleet_id, tuple(plans), totals)


def yaml_scalar(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def render_compose(instance: InstancePlan) -> str:
    """Render the reviewed upstream service without host exposure or adaptation."""

    validate_image_reference()
    profile = instance.profile
    lines = [
        "services:",
        f"  {SERVICE_NAME}:",
        f"    image: {yaml_scalar(PINNED_IMAGE)}",
        '    restart: "no"',
        '    command: ["gateway", "run", "--no-supervise"]',
        "    environment:",
        '      HERMES_PROVIDER_AUTO_DISCOVERY: "0"',
        '      HERMES_UID: "10000"',
        '      HERMES_GID: "10000"',
        "    volumes:",
        "      - data:/opt/data",
        "    networks:",
        "      - private",
        f'    cpus: "{profile.cpu:.2f}"',
        f'    mem_limit: "{profile.memory_mib}m"',
        f"    pids_limit: {profile.pids}",
        "    tmpfs:",
        '      - "/tmp:size=64m,mode=1777"',
        '      - "/run:size=16m,mode=755"',
        '    shm_size: "64m"',
        "    cap_drop:",
        "      - ALL",
        "    cap_add:",
    ]
    lines.extend(f"      - {cap}" for cap in APPROVED_CAPABILITIES)
    lines.extend(
        [
            "    security_opt:",
            '      - "no-new-privileges:true"',
            "    logging:",
            '      driver: "k8s-file"',
            "      options:",
            '        max-size: "1m"',
            "volumes:",
            "  data:",
            f"    name: {yaml_scalar(instance.volume)}",
            "networks:",
            "  private:",
            f"    name: {yaml_scalar(instance.network)}",
            "    internal: true",
            "",
        ]
    )
    rendered = "\n".join(lines)
    validate_rendered_compose(rendered, instance)
    return rendered


def validate_rendered_compose(rendered: str, instance: InstancePlan) -> None:
    """Fail closed if a rendered service drifts into a host-facing shape."""

    required = (
        f"image: {yaml_scalar(PINNED_IMAGE)}",
        'command: ["gateway", "run", "--no-supervise"]',
        "      - data:/opt/data",
        f"    name: {yaml_scalar(instance.volume)}",
        f"    name: {yaml_scalar(instance.network)}",
        "    internal: true",
        f'    cpus: "{instance.profile.cpu:.2f}"',
        f'    mem_limit: "{instance.profile.memory_mib}m"',
        f"    pids_limit: {instance.profile.pids}",
    )
    if any(fragment not in rendered for fragment in required):
        raise ContractError("compose_policy_missing")
    if "image: " + IMAGE_REPOSITORY + ":" in rendered:
        raise ContractError("image_tag_forbidden")
    forbidden = (
        "build:",
        "container_name:",
        "network_mode:",
        "ports:",
        "pid:",
        "privileged:",
        "docker.sock",
        "/var/run/docker",
        "/run/podman",
        ".hermes",
        "${DOCKER",
        "${HERMES_PROVIDER",
        "HERMES_PROVIDER:",
        "labels:",
        "entrypoint:",
        "user:",
    )
    if any(fragment in rendered for fragment in forbidden):
        raise ContractError("unsafe_compose_policy")
    if "@sha256:" not in rendered or rendered.count("@sha256:") != 1:
        raise ContractError("image_digest_missing")
    if rendered.count("internal: true") != 1:
        raise ContractError("private_network_missing")
    if rendered.count("data:/opt/data") != 1:
        raise ContractError("named_volume_missing")


def _prepare_state_dir(state_dir: Path) -> Path:
    """Create and validate the launcher directory without following a link."""

    path = Path(state_dir)
    try:
        path.mkdir(parents=True, exist_ok=True, mode=STATE_DIR_MODE)
        info = os.lstat(path)
    except OSError:
        raise ContractError("state_dir_unusable") from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ContractError("state_dir_unusable")
    return path


def _open_state_dir(state_dir: Path) -> int:
    path = _prepare_state_dir(state_dir)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):
            os.close(descriptor)
            raise ContractError("state_dir_unusable")
        return descriptor
    except ContractError:
        raise
    except OSError:
        raise ContractError("state_dir_unusable") from None


def _path_kind(path: Path) -> str:
    """Classify a generated path using lstat so dangling links are visible."""

    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "unreadable"
    if stat.S_ISLNK(info.st_mode):
        try:
            os.stat(path)
        except FileNotFoundError:
            return "dangling_symlink"
        except OSError:
            return "symlink"
        return "symlink"
    if not stat.S_ISREG(info.st_mode):
        return "non_regular"
    return "regular"


def _path_contract_error(kind: str, path_kind: str) -> ContractError:
    if path_kind == "symlink" or path_kind == "dangling_symlink":
        return ContractError(f"{kind}_symlink_rejected")
    if path_kind == "non_regular":
        return ContractError(f"{kind}_non_regular_rejected")
    return ContractError(f"{kind}_unreadable")


def _open_regular_file(path: Path, kind: str) -> int:
    """Open one generated file with no-follow and a regular-file check."""

    existing = _path_kind(path)
    if existing == "missing":
        raise ContractError(f"{kind}_missing")
    if existing != "regular":
        raise _path_contract_error(kind, existing)
    parent_descriptor = _open_state_dir(path.parent)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        try:
            descriptor = os.open(path.name, flags, dir_fd=parent_descriptor)
        except FileNotFoundError:
            raise ContractError(f"{kind}_missing") from None
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise ContractError(f"{kind}_symlink_rejected") from None
            raise ContractError(f"{kind}_unreadable") from None
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            os.close(descriptor)
            raise ContractError(f"{kind}_non_regular_rejected")
        return descriptor
    finally:
        os.close(parent_descriptor)


def _write_regular_file(path: Path, content: str, kind: str) -> None:
    """Write a generated file through a no-follow descriptor."""

    existing = _path_kind(path)
    if existing != "missing" and existing != "regular":
        raise _path_contract_error(kind, existing)
    parent_descriptor = _open_state_dir(path.parent)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_TRUNC
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor: int | None = None
    try:
        try:
            descriptor = os.open(path.name, flags, STATE_FILE_MODE, dir_fd=parent_descriptor)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise ContractError(f"{kind}_symlink_rejected") from None
            raise ContractError(f"{kind}_unreadable") from None
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ContractError(f"{kind}_non_regular_rejected")
        raw = content.encode("utf-8")
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_descriptor)


def _read_regular_file(path: Path, kind: str) -> bytes:
    descriptor = _open_regular_file(path, kind)
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            chunk = os.read(descriptor, min(64 * 1024, MAX_STATE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_STATE_BYTES:
                raise ContractError("json_too_large")
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def _unlink_owned_file(path: Path, kind: str, *, allow_dangling_symlink: bool = False) -> bool:
    """Unlink only the generated name inside an opened state directory."""

    parent_descriptor = _open_state_dir(path.parent)
    try:
        try:
            info = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return False
        except OSError:
            raise ContractError(f"{kind}_unreadable") from None
        if stat.S_ISLNK(info.st_mode):
            if not allow_dangling_symlink:
                raise ContractError(f"{kind}_symlink_rejected")
            try:
                os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=True)
            except FileNotFoundError:
                pass
            except OSError:
                raise ContractError(f"{kind}_symlink_rejected") from None
            else:
                raise ContractError(f"{kind}_symlink_rejected")
        elif not stat.S_ISREG(info.st_mode):
            raise ContractError(f"{kind}_non_regular_rejected")
        try:
            os.unlink(path.name, dir_fd=parent_descriptor)
        except FileNotFoundError:
            return False
        except OSError:
            raise ContractError(f"{kind}_unreadable") from None
        return True
    finally:
        os.close(parent_descriptor)


def compose_path(state_dir: Path, instance: InstancePlan) -> Path:
    return Path(state_dir) / f"{instance.project}.compose.yaml"


def render_to_directory(plan: FleetPlan, state_dir: Path) -> dict[str, Path]:
    state_dir = _prepare_state_dir(state_dir)
    paths: dict[str, Path] = {}
    for instance in plan.instances:
        path = compose_path(state_dir, instance)
        _write_regular_file(path, render_compose(instance), "compose")
        paths[instance.instance_id] = path
    return paths


def state_path(state_dir: Path, fleet_id: str) -> Path:
    validate_identifier(fleet_id, "fleet")
    return state_dir / f"{PROJECT_PREFIX}-{fleet_id}.json"


def manifest_for(plan: FleetPlan) -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "fleet_id": plan.fleet_id,
        "image": PINNED_IMAGE,
        "instances": [
            {
                "id": instance.instance_id,
                "profile": instance.profile.name,
                "project": instance.project,
                "network": instance.network,
                "volume": instance.volume,
                "compose_file": f"{instance.project}.compose.yaml",
            }
            for instance in plan.instances
        ],
        "reserved": plan.totals.public(),
    }


def write_manifest(plan: FleetPlan, state_dir: Path) -> Path:
    state_dir = _prepare_state_dir(state_dir)
    path = state_path(state_dir, plan.fleet_id)
    _write_regular_file(
        path,
        json.dumps(manifest_for(plan), sort_keys=True, indent=2) + "\n",
        "state",
    )
    return path


def load_json(path: Path) -> Any:
    """Load a small UTF-8 JSON document with duplicate-key rejection."""

    raw = _read_regular_file(path, "state")

    def pairs(pairs_list: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs_list:
            if key in result:
                raise ContractError("duplicate_json_key")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ContractError("json_invalid") from None


def load_manifest(state_dir: Path, fleet_id: str) -> FleetPlan:
    path = state_path(state_dir, fleet_id)
    kind = _path_kind(path)
    if kind == "missing":
        raise ContractError("state_missing")
    if kind != "regular":
        raise _path_contract_error("state", kind)
    document = load_json(path)
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        raise ContractError("state_schema_invalid")
    if document.get("fleet_id") != fleet_id or document.get("image") != PINNED_IMAGE:
        raise ContractError("state_identity_invalid")
    raw_instances = document.get("instances")
    if not isinstance(raw_instances, list) or not raw_instances:
        raise ContractError("state_instances_invalid")
    items: list[tuple[str, str]] = []
    for item in raw_instances:
        if not isinstance(item, dict) or set(item) != {
            "id",
            "profile",
            "project",
            "network",
            "volume",
            "compose_file",
        }:
            raise ContractError("state_instance_schema_invalid")
        instance_id = item.get("id")
        profile = item.get("profile")
        if not isinstance(instance_id, str) or not isinstance(profile, str):
            raise ContractError("state_instance_schema_invalid")
        items.append((instance_id, profile))
    plan = build_plan(fleet_id, items)
    for item, instance in zip(raw_instances, plan.instances):
        if (
            item["project"] != instance.project
            or item["network"] != instance.network
            or item["volume"] != instance.volume
            or item["compose_file"] != f"{instance.project}.compose.yaml"
        ):
            raise ContractError("state_name_mismatch")
    if document.get("reserved") != plan.totals.public():
        raise ContractError("state_budget_mismatch")
    return plan


def _capture_text(value: object, limit: int = MAX_CAPTURE_BYTES) -> str:
    """Keep captured streams bounded by UTF-8 bytes, including multibyte text."""

    if value is None:
        raw = b""
    elif isinstance(value, bytes):
        raw = value
    else:
        raw = str(value).encode("utf-8", errors="replace")
    bounded = raw[:limit]
    value = bounded.decode("utf-8", errors="replace")
    encoded = value.encode("utf-8")
    if len(encoded) > limit:
        # A replacement character can expand one truncated byte into three
        # encoded bytes.  Drop only the incomplete tail so the retained text
        # remains within the byte contract even for a multibyte boundary.
        value = encoded[:limit].decode("utf-8", errors="ignore")
    return value


def redacted_diagnostic(text: str) -> str:
    """Bound diagnostics without retaining paths, URLs, credentials, or tokens."""

    value = _capture_text(text)
    substitutions = (
        (r"(?i)(authorization\s*[:=]\s*(?:bearer|token|basic)\s+)[^\s,;]+", r"\1[REDACTED]"),
        (r"(?i)((?:api[_-]?key|access[_-]?key|token|password|secret)\s*[:=]\s*)[^\s,;]+", r"\1[REDACTED]"),
        (r"(?i)https?://[^\s\"']+", "[REDACTED_URL]"),
        (r"(?i)\b(?:path|file|directory|source|destination)\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^,\n;]+)", "[REDACTED_PATH]"),
        (r"(?<!\S)(?:/{1,2}|[A-Za-z]:[\\/]|\\\\)[^,\n;]+", "[REDACTED_PATH]"),
        (r"(?i)((?:cookie\s*[:=]\s*)[^\s,;]+)", r"[REDACTED]"),
    )
    for pattern, replacement in substitutions:
        value = re.sub(pattern, replacement, value)
    raw = value.encode("utf-8")
    if len(raw) > MAX_DIAGNOSTIC_BYTES:
        marker = "…".encode("utf-8")
        value = raw[: MAX_DIAGNOSTIC_BYTES - len(marker)].decode("utf-8", errors="ignore") + "…"
    return value


def emit(document: Mapping[str, object]) -> None:
    """Emit exactly one bounded JSON line."""

    try:
        encoded = json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        encoded = json.dumps({"schema": SCHEMA, "status": "error", "reason": "evidence_invalid"})
    if len(encoded.encode("utf-8")) > MAX_EVIDENCE_BYTES:
        encoded = json.dumps({"schema": SCHEMA, "status": "error", "reason": "evidence_too_large"})
    print(encoded)


def _coerce_result(value: object) -> CommandResult:
    """Normalize runner output before any parser or retained evidence sees it."""

    if isinstance(value, CommandResult):
        return CommandResult(
            value.returncode,
            _capture_text(value.stdout),
            _capture_text(value.stderr),
            value.timed_out,
        )
    if isinstance(value, subprocess.CompletedProcess):
        return CommandResult(
            value.returncode,
            _capture_text(value.stdout),
            _capture_text(value.stderr),
        )
    raise ContractError("runner_result_invalid")


def _resolve_trusted_executable(name: str) -> str:
    """Resolve only fixed absolute roots, never the caller's PATH."""

    candidates = TRUSTED_EXECUTABLE_CANDIDATES.get(name)
    if candidates is None:
        raise ContractError("trusted_executable_invalid")
    trusted_roots = tuple(path.resolve() for path in TRUSTED_EXECUTABLE_DIRS)
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
            info = resolved.stat()
        except OSError:
            continue
        if not stat.S_ISREG(info.st_mode) or not (info.st_mode & 0o111):
            continue
        if not any(resolved == root or root in resolved.parents for root in trusted_roots):
            continue
        return str(resolved)
    raise ContractError("trusted_executable_missing")


def _resolve_command(command: Sequence[str]) -> tuple[str, ...]:
    if not command:
        raise ContractError("empty_command")
    first = command[0]
    if first in {ENGINE_EXECUTABLE, COMPOSE_EXECUTABLE}:
        return (_resolve_trusted_executable(first), *command[1:])
    if first.startswith("/"):
        try:
            info = Path(first).stat()
        except OSError:
            raise ContractError("executable_invalid") from None
        if not stat.S_ISREG(info.st_mode) or not (info.st_mode & 0o111):
            raise ContractError("executable_invalid")
    return tuple(command)


def _drain_pipe(pipe: Any) -> bytes:
    captured = bytearray()
    try:
        while True:
            chunk = pipe.read(8192)
            if not chunk:
                return bytes(captured)
            if len(captured) < MAX_CAPTURE_BYTES:
                captured.extend(chunk[: MAX_CAPTURE_BYTES - len(captured)])
    finally:
        pipe.close()


def _run_subprocess(command: Sequence[str], env: Mapping[str, str], timeout: float) -> CommandResult:
    """Drain both streams concurrently while retaining only bounded bytes."""

    try:
        process = subprocess.Popen(
            tuple(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            env=dict(env),
        )
    except FileNotFoundError:
        return CommandResult(127, stderr="not_found")
    except OSError:
        return CommandResult(126, stderr="not_executable")

    assert process.stdout is not None
    assert process.stderr is not None
    stdout_result: list[bytes] = []
    stderr_result: list[bytes] = []

    def collect(pipe: Any, destination: list[bytes]) -> None:
        destination.append(_drain_pipe(pipe))

    stdout_thread = threading.Thread(target=collect, args=(process.stdout, stdout_result), daemon=True)
    stderr_thread = threading.Thread(target=collect, args=(process.stderr, stderr_result), daemon=True)
    stdout_thread.start()
    stderr_thread.start()
    timed_out = False
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        returncode = process.wait()
    stdout_thread.join()
    stderr_thread.join()
    return CommandResult(
        124 if timed_out else returncode,
        _capture_text(stdout_result[0] if stdout_result else b""),
        _capture_text(stderr_result[0] if stderr_result else b""),
        timed_out=timed_out,
    )


def invoke(
    argv: Sequence[str],
    *,
    runner: Runner | None = None,
    timeout: float = 30.0,
    source_environment: Mapping[str, str] | None = None,
) -> CommandResult:
    command = tuple(str(part) for part in argv)
    if not command:
        raise ContractError("empty_command")
    lowered = {part.lower() for part in command}
    if "docker" in lowered or any(part.lower().startswith("docker-") for part in command):
        raise ContractError("docker_executor_rejected")
    env = clean_environment(source_environment)
    if runner is not None:
        return _coerce_result(runner(command, env, timeout))
    return _run_subprocess(_resolve_command(command), env, timeout)


def compose_command(instance: InstancePlan, path: Path, action: Sequence[str]) -> tuple[str, ...]:
    if not path.name.endswith(".compose.yaml"):
        raise ContractError("compose_path_invalid")
    command = (COMPOSE_EXECUTABLE, "-p", instance.project, "-f", str(path), *action)
    if any("docker" in token.lower() for token in command):
        raise ContractError("docker_executor_rejected")
    return tuple(command)


def assert_rootless_podman(*, runner: Runner | None = None) -> None:
    info = invoke(
        (ENGINE_EXECUTABLE, "info", "--format", "json"),
        runner=runner,
        timeout=15.0,
    )
    if info.returncode != 0 or info.timed_out:
        raise ContractError("podman_unavailable")
    try:
        document = json.loads(info.stdout)
    except (TypeError, json.JSONDecodeError):
        raise ContractError("podman_info_invalid") from None
    rootless = None
    if isinstance(document, dict):
        host = document.get("host")
        if isinstance(host, dict):
            security = host.get("security")
            if isinstance(security, dict):
                rootless = security.get("rootless")
            if rootless is None:
                rootless = host.get("rootless")
        if rootless is None:
            rootless = document.get("rootless")
    if rootless is not True:
        raise ContractError("rootless_required")
    compose = invoke((COMPOSE_EXECUTABLE, "version"), runner=runner, timeout=15.0)
    if compose.returncode != 0 or compose.timed_out:
        raise ContractError("podman_compose_required")


def _repo_digests(document: object) -> list[str]:
    found: list[str] = []
    if isinstance(document, dict):
        for key, value in document.items():
            if key.lower() in {"repodigests", "repo_digests"} and isinstance(value, list):
                found.extend(item for item in value if isinstance(item, str))
            else:
                found.extend(_repo_digests(value))
    elif isinstance(document, list):
        for item in document:
            found.extend(_repo_digests(item))
    return found


def verify_official_image(*, runner: Runner | None = None) -> None:
    """Verify or pull the exact immutable official image, never a tag."""

    expected = f"{IMAGE_REPOSITORY}@{PINNED_IMAGE_DIGEST}"
    inspected = invoke(
        (ENGINE_EXECUTABLE, "image", "inspect", "--format", "json", PINNED_IMAGE),
        runner=runner,
        timeout=30.0,
    )
    if inspected.returncode != 0:
        pulled = invoke((ENGINE_EXECUTABLE, "pull", PINNED_IMAGE), runner=runner, timeout=300.0)
        if pulled.returncode != 0 or pulled.timed_out:
            raise ContractError("official_image_pull_failed")
        inspected = invoke(
            (ENGINE_EXECUTABLE, "image", "inspect", "--format", "json", PINNED_IMAGE),
            runner=runner,
            timeout=30.0,
        )
    if inspected.returncode != 0 or inspected.timed_out:
        raise ContractError("official_image_inspect_failed")
    try:
        document = json.loads(inspected.stdout)
    except (TypeError, json.JSONDecodeError):
        raise ContractError("official_image_inspect_invalid") from None
    if expected not in _repo_digests(document):
        raise ContractError("official_image_digest_mismatch")


def preflight(*, runner: Runner | None = None) -> None:
    assert_rootless_podman(runner=runner)
    verify_official_image(runner=runner)


def _resource_labels(item: object) -> dict[str, str] | None:
    if not isinstance(item, dict):
        return None
    for key in ("Labels", "labels", "Label"):
        labels = item.get(key)
        if isinstance(labels, dict) and all(isinstance(name, str) and isinstance(value, str) for name, value in labels.items()):
            return labels
    return None


def _parse_container_states(output: str, project: str) -> list[str] | None:
    """Parse Podman's JSON state enum; prose such as ``not running`` is invalid."""

    try:
        document = json.loads(output or "[]")
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(document, list):
        return None
    allowed = {"created", "configured", "dead", "exited", "paused", "running", "stopped"}
    states: list[str] = []
    for item in document:
        if not isinstance(item, dict):
            return None
        labels = _resource_labels(item)
        if labels is not None and labels.get("io.podman.compose.project") not in {None, project}:
            return None
        state = item.get("State", item.get("state"))
        if not isinstance(state, str):
            return None
        normalized = state.strip().lower()
        if normalized not in allowed:
            return None
        states.append(normalized)
    return states


def status_one(instance: InstancePlan, path: Path, *, runner: Runner | None = None) -> InstanceOperation:
    del path  # Native Podman state is authoritative; Compose prose is not.
    result = invoke(
        (
            ENGINE_EXECUTABLE,
            "ps",
            "-a",
            "--filter",
            f"label=io.podman.compose.project={instance.project}",
            "--format",
            "json",
        ),
        runner=runner,
        timeout=30.0,
    )
    if result.timed_out:
        return InstanceOperation(instance, "status_timeout", 124)
    if result.returncode != 0:
        return InstanceOperation(instance, "status_failed", result.returncode)
    states = _parse_container_states(result.stdout, instance.project)
    if states is None:
        return InstanceOperation(instance, "status_unknown", result.returncode)
    return InstanceOperation(instance, "running" if states and all(state == "running" for state in states) else "not_running", 0)


def readiness_one(instance: InstancePlan, path: Path, *, runner: Runner | None = None) -> InstanceOperation:
    """Report process-level readiness only; do not claim chat/browser compatibility."""

    result = status_one(instance, path, runner=runner)
    if result.status == "running":
        return InstanceOperation(instance, "process_running", result.exit_code)
    if result.status == "not_running":
        return InstanceOperation(instance, "process_not_running", result.exit_code)
    return InstanceOperation(instance, "readiness_unknown", result.exit_code)


def endpoint_one(instance: InstancePlan) -> dict[str, object]:
    return {
        "id": instance.instance_id,
        "endpoint": instance.endpoint,
        "scope": "private_compose_network",
        "published": False,
        "provider": "none",
        "compatibility_claim": False,
    }


def _resource_command(kind: str, *, project: str | None = None) -> tuple[str, ...]:
    if kind == "containers":
        command = [ENGINE_EXECUTABLE, "ps", "-a"]
    elif kind == "networks":
        command = [ENGINE_EXECUTABLE, "network", "ls"]
    elif kind == "volumes":
        command = [ENGINE_EXECUTABLE, "volume", "ls"]
    else:
        raise ContractError("resource_kind_invalid")
    command.extend(["--filter", "label=io.podman.compose.project"])
    if project is not None:
        command[-1] = f"label=io.podman.compose.project={project}"
    command.extend(["--format", "json"])
    return tuple(command)


def _parse_resource_items(stdout: str) -> list[object] | None:
    try:
        document = json.loads(stdout or "[]")
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(document, list):
        return None
    return document


def _parse_resource_count(stdout: str) -> int | None:
    items = _parse_resource_items(stdout)
    return None if items is None else len(items)


def _zero_leftovers_for_project(project: str, *, runner: Runner | None = None) -> dict[str, int | None]:
    counts: dict[str, int | None] = {}
    for kind in ("containers", "networks", "volumes"):
        result = invoke(_resource_command(kind, project=project), runner=runner, timeout=30.0)
        if result.returncode != 0 or result.timed_out:
            counts[kind] = None
            continue
        counts[kind] = _parse_resource_count(result.stdout)
    return counts


def zero_leftovers(instance: InstancePlan, *, runner: Runner | None = None) -> dict[str, int | None]:
    """Inspect only exact native Podman listings for one generated project."""

    return _zero_leftovers_for_project(instance.project, runner=runner)


def _resource_name(item: object) -> str | None:
    if not isinstance(item, dict):
        return None
    for key in ("Name", "name"):
        value = item.get(key)
        if isinstance(value, str):
            return value
    for key in ("Names", "names"):
        value = item.get(key)
        if isinstance(value, list) and value and isinstance(value[0], str):
            return value[0]
    return None


def _discover_fleet_projects(fleet_id: str, *, runner: Runner | None = None) -> tuple[list[str], bool]:
    """Discover only valid project labels belonging to one requested fleet."""

    validate_identifier(fleet_id, "fleet")
    prefix = f"{PROJECT_PREFIX}-{fleet_id}-"
    projects: set[str] = set()
    for kind in ("containers", "networks", "volumes"):
        try:
            result = invoke(_resource_command(kind), runner=runner, timeout=30.0)
        except BaseException:
            return sorted(projects), False
        if result.returncode != 0 or result.timed_out:
            return sorted(projects), False
        items = _parse_resource_items(result.stdout)
        if items is None:
            return sorted(projects), False
        for item in items:
            if not isinstance(item, dict):
                return sorted(projects), False
            labels = _resource_labels(item)
            project = labels.get("io.podman.compose.project") if labels is not None else None
            if project is None:
                continue
            if not isinstance(project, str) or not project.startswith(prefix):
                continue
            instance_id = project[len(prefix) :]
            try:
                validate_identifier(instance_id, "instance")
                expected_project, _, _ = make_names(fleet_id, instance_id)
            except ContractError:
                return sorted(projects), False
            if project != expected_project:
                return sorted(projects), False
            # Keep every valid project label, even when a resource name is
            # malformed.  The exact recheck must then report that leftover
            # instead of skipping it and falsely proving zero resources.
            projects.add(project)
    return sorted(projects), True


def _is_zero(leftovers: Mapping[str, int | None]) -> bool:
    return all(leftovers.get(key) == 0 for key in ("containers", "networks", "volumes"))


def _safe_zero_leftovers(instance: InstancePlan, *, runner: Runner | None = None) -> dict[str, int | None]:
    try:
        return zero_leftovers(instance, runner=runner)
    except BaseException:
        return {"containers": None, "networks": None, "volumes": None}


def teardown_one(
    instance: InstancePlan,
    path: Path,
    *,
    runner: Runner | None = None,
) -> InstanceOperation:
    kind = _path_kind(path)
    if kind == "regular":
        try:
            down = invoke(
                compose_command(instance, path, ("down", "--volumes", "--remove-orphans")),
                runner=runner,
                timeout=120.0,
            )
        except BaseException:
            down = CommandResult(126, timed_out=False)
    elif kind == "missing":
        down = CommandResult(0)
    else:
        leftovers = _safe_zero_leftovers(instance, runner=runner)
        if kind == "dangling_symlink" and _is_zero(leftovers):
            try:
                _unlink_owned_file(path, "compose", allow_dangling_symlink=True)
            except BaseException:
                return InstanceOperation(instance, "teardown_failed", None, leftovers)
            return InstanceOperation(instance, "removed", 0, leftovers)
        return InstanceOperation(instance, "teardown_failed", None, leftovers)

    leftovers = _safe_zero_leftovers(instance, runner=runner)
    if down.returncode != 0 or down.timed_out:
        return InstanceOperation(instance, "teardown_failed", down.returncode, leftovers)
    if not _is_zero(leftovers):
        return InstanceOperation(instance, "leftovers_detected", 0, leftovers)
    return InstanceOperation(instance, "removed", 0, leftovers)


def _run_parallel(
    instances: Sequence[InstancePlan],
    operation: Callable[[InstancePlan], InstanceOperation],
    *,
    on_error: Callable[[InstancePlan, BaseException], InstanceOperation] | None = None,
) -> list[InstanceOperation]:
    if not instances:
        return []
    results: list[InstanceOperation] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(instances))) as pool:
        futures = [(instance, pool.submit(operation, instance)) for instance in instances]
        for instance, future in futures:
            try:
                results.append(future.result())
            except BaseException as exc:
                if on_error is None:
                    raise
                results.append(on_error(instance, exc))
    return results


def _evidence(
    plan: FleetPlan,
    action: str,
    status: str,
    operations: Sequence[InstanceOperation],
    *,
    zero: bool | None = None,
    authorization: bool = False,
) -> dict[str, object]:
    if zero is None:
        observed = [operation.leftovers for operation in operations if operation.leftovers is not None]
        zero = all(_is_zero(leftovers) for leftovers in observed) if observed else None
    return {
        "schema": SCHEMA,
        "action": action,
        "status": status,
        "fleet_id": plan.fleet_id,
        "executor": {
            "engine": ENGINE_EXECUTABLE,
            "compose": COMPOSE_EXECUTABLE,
            "rootless": True,
        },
        "provider": "none",
        "image": {
            "repository": IMAGE_REPOSITORY,
            "digest": PINNED_IMAGE_DIGEST,
            "repo_digest": f"{IMAGE_REPOSITORY}@{PINNED_IMAGE_DIGEST}",
            "reference": PINNED_IMAGE,
            "official": True,
        },
        "cleanup_policy": {
            "teardown_command": ["down", "--volumes", "--remove-orphans"],
            "leftover_label": "io.podman.compose.project",
        },
        "budget": {
            "limit": {"cpu": format(MAX_CPU, "f"), "memory_mib": MAX_MEMORY_MIB, "pids": MAX_PIDS},
            "reserved": plan.totals.public(),
        },
        "instances": [operation.public() for operation in operations],
        "zero_leftovers": zero,
        "authorization": authorization,
        "redaction": {"bounded": True, "raw_engine_output": False},
        "limitations": [
            "process_readiness_only",
            "no_provider",
            "no_browser_or_chat_compatibility_claim",
        ],
    }


def start_fleet(
    plan: FleetPlan,
    state_dir: Path,
    *,
    runner: Runner | None = None,
) -> dict[str, object]:
    """Render, preflight, start, and clean every project on every failure."""

    state_dir = Path(state_dir)
    paths = {instance.instance_id: compose_path(state_dir, instance) for instance in plan.instances}
    operations: list[InstanceOperation] = []
    failure: str | None = None
    try:
        paths = render_to_directory(plan, state_dir)
        write_manifest(plan, state_dir)
        preflight(runner=runner)

        def start_one(instance: InstancePlan) -> InstanceOperation:
            result = invoke(
                compose_command(instance, paths[instance.instance_id], ("up", "-d")),
                runner=runner,
                timeout=300.0,
            )
            if result.timed_out:
                return InstanceOperation(instance, "start_timeout", 124)
            if result.returncode != 0:
                return InstanceOperation(instance, "start_failed", result.returncode)
            return InstanceOperation(instance, "started", 0)

        operations = _run_parallel(plan.instances, start_one)
        if any(operation.status != "started" for operation in operations):
            failure = "partial_start"
    except KeyboardInterrupt:
        failure = "interrupted"
    except ContractError as exc:
        failure = exc.code
    except BaseException:
        # Do not expose exception text from a worker or a provider environment.
        failure = "start_failed"

    if failure is None:
        # Starting is not cleanup proof.  Only a live teardown listing may set
        # zero_leftovers=true.
        return _evidence(plan, "start", "started", operations, zero=None)

    def cleanup_error(instance: InstancePlan, _error: BaseException) -> InstanceOperation:
        return InstanceOperation(
            instance,
            "cleanup_exception",
            None,
            _safe_zero_leftovers(instance, runner=runner),
        )

    try:
        cleanup = _run_parallel(
            plan.instances,
            lambda instance: teardown_one(instance, paths[instance.instance_id], runner=runner),
            on_error=cleanup_error,
        )
    except BaseException:
        cleanup = [
            InstanceOperation(
                instance,
                "cleanup_exception",
                None,
                _safe_zero_leftovers(instance, runner=runner),
            )
            for instance in plan.instances
        ]
    zero = bool(cleanup) and all(
        operation.status == "removed"
        and operation.leftovers is not None
        and _is_zero(operation.leftovers)
        for operation in cleanup
    )
    if zero:
        try:
            _remove_state_artifacts(plan, state_dir)
        except BaseException:
            zero = False
    cleanup_by_id = {operation.instance.instance_id: operation for operation in cleanup}
    started_by_id = {operation.instance.instance_id: operation for operation in operations}
    combined: list[InstanceOperation] = []
    for instance in plan.instances:
        started = started_by_id.get(instance.instance_id)
        cleanup_operation = cleanup_by_id.get(instance.instance_id)
        statuses = [failure]
        if started is not None and started.status != "started":
            statuses.append(started.status)
        if cleanup_operation is not None:
            statuses.append(cleanup_operation.status)
        combined.append(
            InstanceOperation(
                instance,
                ":".join(statuses),
                (cleanup_operation or started).exit_code if (cleanup_operation or started) else None,
                (cleanup_operation or started).leftovers if (cleanup_operation or started) else None,
            )
        )
    return _evidence(plan, "start", "failed", combined, zero=zero)


def _remove_state_artifacts(plan: FleetPlan, state_dir: Path) -> None:
    for instance in plan.instances:
        _unlink_owned_file(
            compose_path(state_dir, instance),
            "compose",
            allow_dangling_symlink=True,
        )
    _unlink_owned_file(
        state_path(state_dir, plan.fleet_id),
        "state",
        allow_dangling_symlink=True,
    )


def teardown_fleet(
    plan: FleetPlan,
    state_dir: Path,
    *,
    instance_id: str | None = None,
    runner: Runner | None = None,
) -> dict[str, object]:
    selected = list(plan.instances)
    if instance_id is not None:
        validate_identifier(instance_id, "instance")
        selected = [instance for instance in plan.instances if instance.instance_id == instance_id]
        if not selected:
            raise ContractError("unrecognized_instance")

    def cleanup_error(instance: InstancePlan, _error: BaseException) -> InstanceOperation:
        return InstanceOperation(
            instance,
            "cleanup_exception",
            None,
            _safe_zero_leftovers(instance, runner=runner),
        )

    operations = _run_parallel(
        selected,
        lambda instance: teardown_one(instance, compose_path(state_dir, instance), runner=runner),
        on_error=cleanup_error,
    )
    zero = bool(operations) and all(
        operation.status == "removed"
        and operation.leftovers is not None
        and _is_zero(operation.leftovers)
        for operation in operations
    )
    if zero:
        try:
            for instance in selected:
                _unlink_owned_file(compose_path(state_dir, instance), "compose", allow_dangling_symlink=True)
            remaining = [instance for instance in plan.instances if instance not in selected]
            if not remaining:
                _unlink_owned_file(
                    state_path(state_dir, plan.fleet_id),
                    "state",
                    allow_dangling_symlink=True,
                )
            else:
                remaining_plan = build_plan(
                    plan.fleet_id,
                    [(instance.instance_id, instance.profile.name) for instance in remaining],
                )
                write_manifest(remaining_plan, state_dir)
        except BaseException:
            zero = False
    status = "removed" if zero else "cleanup_failed"
    return _evidence(plan, "teardown", status, operations, zero=zero)


def _teardown_without_manifest(
    fleet_id: str,
    state_dir: Path,
    *,
    reason: str,
    runner: Runner | None = None,
) -> dict[str, object]:
    """Inventory exact project labels when trusted state is unavailable.

    A missing state file is idempotent only after all three native listings
    prove that no valid project label remains.  A corrupt state file is never
    treated as removable state; any uncertainty returns cleanup_failed.
    """

    del state_dir  # The inventory is deliberately independent of untrusted state.
    projects, complete = _discover_fleet_projects(fleet_id, runner=runner)
    inventory: list[dict[str, object]] = []
    all_zero = complete
    for project in projects:
        leftovers = _safe_zero_leftovers_for_project(project, runner=runner)
        all_zero = all_zero and _is_zero(leftovers)
        inventory.append({"project": project, "leftovers": leftovers})
    idempotent = reason == "state_missing" and complete and all_zero
    return {
        "schema": SCHEMA,
        "action": "teardown",
        "status": "removed" if idempotent else "cleanup_failed",
        "fleet_id": fleet_id,
        "instances": inventory,
        "zero_leftovers": True if idempotent else False,
        "idempotent": idempotent,
        "manifest": "missing" if reason == "state_missing" else "unusable",
        "resource_inventory_complete": complete,
        "redaction": {"bounded": True, "raw_engine_output": False},
    }


def _safe_zero_leftovers_for_project(
    project: str,
    *,
    runner: Runner | None = None,
) -> dict[str, int | None]:
    try:
        return _zero_leftovers_for_project(project, runner=runner)
    except BaseException:
        return {"containers": None, "networks": None, "volumes": None}


def status_fleet(plan: FleetPlan, state_dir: Path, *, runner: Runner | None = None) -> dict[str, object]:
    paths = {instance.instance_id: compose_path(state_dir, instance) for instance in plan.instances}
    operations = _run_parallel(
        plan.instances,
        lambda instance: status_one(instance, paths[instance.instance_id], runner=runner),
    )
    return _evidence(plan, "status", "reported", operations, zero=None)


def readiness_fleet(plan: FleetPlan, state_dir: Path, *, runner: Runner | None = None) -> dict[str, object]:
    paths = {instance.instance_id: compose_path(state_dir, instance) for instance in plan.instances}
    operations = _run_parallel(
        plan.instances,
        lambda instance: readiness_one(instance, paths[instance.instance_id], runner=runner),
    )
    all_running = all(operation.status == "process_running" for operation in operations)
    return _evidence(plan, "readiness", "process_ready" if all_running else "not_ready", operations, zero=None)


def demo(
    state_dir: Path,
    *,
    runner: Runner | None = None,
) -> dict[str, object]:
    """Run one explicitly authorized no-provider VM demonstration."""

    if os.environ.get("HERMTERNAL_UPSTREAM_FLEET_VM_DEMO") != "1":
        raise ContractError("vm_authorization_required")
    plan = build_plan("vm-demo", [("official", "auth")])
    try:
        started = start_fleet(plan, state_dir, runner=runner)
    except BaseException:
        started = _evidence(
            plan,
            "start",
            "failed",
            [InstanceOperation(instance, "start_exception") for instance in plan.instances],
            zero=False,
        )
    if started.get("status") != "started":
        try:
            retry_cleanup = teardown_fleet(plan, state_dir, runner=runner)
        except BaseException:
            retry_cleanup = _evidence(
                plan,
                "teardown",
                "cleanup_failed",
                [
                    InstanceOperation(
                        instance,
                        "cleanup_exception",
                        None,
                        _safe_zero_leftovers(instance, runner=runner),
                    )
                    for instance in plan.instances
                ],
                zero=False,
            )
        retry_status = str(retry_cleanup.get("status", "cleanup_failed"))
        return {
            **started,
            "action": "demo",
            "status": "failed" if retry_status == "removed" else "cleanup_failed",
            "authorization": True,
            "live_run": True,
            "teardown": retry_status,
            "zero_leftovers": retry_cleanup.get("zero_leftovers") is True,
            "official_image_evidence": {
                "reference": PINNED_IMAGE,
                "digest_verified": False,
            },
        }

    readiness_status = "unknown"
    try:
        readiness = readiness_fleet(plan, state_dir, runner=runner)
        readiness_status = str(readiness.get("status", "unknown"))
    except KeyboardInterrupt:
        readiness_status = "interrupted"
    except BaseException:
        readiness_status = "unknown"

    cleanup_status = "cleanup_failed"
    cleanup_zero = False
    cleanup: dict[str, object] | None = None
    try:
        cleanup = teardown_fleet(plan, state_dir, runner=runner)
        cleanup_status = str(cleanup.get("status", "cleanup_failed"))
        cleanup_zero = cleanup.get("zero_leftovers") is True
    except BaseException:
        # Keep the demo result bounded while making cleanup uncertainty visible.
        cleanup = None
        cleanup_status = "cleanup_failed"
        cleanup_zero = False

    observed_leftovers: Mapping[str, object] = {}
    if cleanup is not None:
        entries = cleanup.get("instances")
        if isinstance(entries, list) and entries and isinstance(entries[0], dict):
            value = entries[0].get("leftovers")
            if isinstance(value, dict):
                observed_leftovers = value
    final_status = readiness_status if cleanup_status == "removed" else "cleanup_failed"
    return {
        "schema": SCHEMA,
        "action": "demo",
        "status": final_status,
        "fleet_id": plan.fleet_id,
        "authorization": True,
        "live_run": True,
        "provider": "none",
        "readiness": readiness_status,
        "teardown": cleanup_status,
        "zero_leftovers": cleanup_zero,
        "executor": {
            "engine": ENGINE_EXECUTABLE,
            "compose": COMPOSE_EXECUTABLE,
            "rootless": True,
        },
        "official_image_evidence": {
            "reference": PINNED_IMAGE,
            "repo_digest": f"{IMAGE_REPOSITORY}@{PINNED_IMAGE_DIGEST}",
            "digest_verified": True,
        },
        "instance": {
            **plan.instances[0].public(),
            "readiness_classification": readiness_status,
            "teardown_status": cleanup_status,
            "leftovers": {
                "label": f"io.podman.compose.project={plan.instances[0].project}",
                "containers": observed_leftovers.get("containers"),
                "networks": observed_leftovers.get("networks"),
                "volumes": observed_leftovers.get("volumes"),
            },
        },
        "teardown_command": ["down", "--volumes", "--remove-orphans"],
        "redaction": {"bounded": True, "raw_engine_output": False},
        "limitations": [
            "process_readiness_only",
            "no_provider",
            "no_browser_or_chat_compatibility_claim",
        ],
    }


def load_cases(path: Path = CASES_PATH) -> dict[str, Any]:
    document = load_json(path)
    validate_cases_document(document)
    return document


def validate_cases_document(document: object) -> None:
    if not isinstance(document, dict) or document.get("schema") != CASES_SCHEMA:
        raise ContractError("cases_schema_invalid")
    if document.get("image") != PINNED_IMAGE:
        raise ContractError("cases_image_invalid")
    budget = document.get("budget")
    if budget != {"cpu": "6.00", "memory_mib": MAX_MEMORY_MIB, "pids": MAX_PIDS}:
        raise ContractError("cases_budget_invalid")
    profiles = document.get("profiles")
    if not isinstance(profiles, dict) or set(profiles) != set(PROFILES):
        raise ContractError("cases_profiles_invalid")
    for name, profile in PROFILES.items():
        expected = profile.public()
        if profiles.get(name) != expected:
            raise ContractError("cases_profile_invalid")
    cases = document.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ContractError("cases_missing")
    ids: set[str] = set()
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("id"), str):
            raise ContractError("case_invalid")
        if case["id"] in ids:
            raise ContractError("duplicate_case")
        ids.add(case["id"])


def load_vm_evidence(path: Path = VM_EVIDENCE_PATH) -> dict[str, Any]:
    document = load_json(path)
    validate_vm_evidence(document)
    return document


def validate_vm_evidence(document: object) -> None:
    """Validate the one authorized VM observation without accepting raw logs."""

    if not isinstance(document, dict):
        raise ContractError("vm_evidence_schema_invalid")
    if document.get("schema") != "hermternal.integration.hermes-upstream-fleet-vm-evidence.v1":
        raise ContractError("vm_evidence_schema_invalid")
    if document.get("operation") != "R-02C" or document.get("issue") != 272:
        raise ContractError("vm_evidence_identity_invalid")
    if document.get("authorized") is not True or document.get("live_run") is not True:
        raise ContractError("vm_evidence_not_authorized")
    if document.get("provider") != "none" or document.get("proof_status") != "blocked_readiness":
        raise ContractError("vm_evidence_scope_invalid")

    executor = document.get("executor")
    if not isinstance(executor, dict) or executor.get("engine") != ENGINE_EXECUTABLE:
        raise ContractError("vm_evidence_executor_invalid")
    if executor.get("compose") != COMPOSE_EXECUTABLE or executor.get("rootless") is not True:
        raise ContractError("vm_evidence_executor_invalid")
    if not isinstance(executor.get("podman_version"), str) or not isinstance(
        executor.get("compose_version"), str
    ):
        raise ContractError("vm_evidence_executor_invalid")

    image = document.get("image")
    expected_repo_digest = f"{IMAGE_REPOSITORY}@{PINNED_IMAGE_DIGEST}"
    if not isinstance(image, dict):
        raise ContractError("vm_evidence_image_invalid")
    if (
        image.get("repository") != IMAGE_REPOSITORY
        or image.get("reference") != PINNED_IMAGE
        or image.get("repo_digest") != expected_repo_digest
        or image.get("digest_verified") is not True
        or image.get("official") is not True
    ):
        raise ContractError("vm_evidence_image_invalid")

    expected_plan = build_plan("vm-demo", [("official", "auth")])
    instance = document.get("instance")
    if not isinstance(instance, dict):
        raise ContractError("vm_evidence_instance_invalid")
    expected = expected_plan.instances[0]
    if (
        instance.get("id") != expected.instance_id
        or instance.get("profile") != expected.profile.name
        or instance.get("project") != expected.project
        or instance.get("network") != expected.network
        or instance.get("volume") != expected.volume
        or instance.get("endpoint") != expected.endpoint
        or instance.get("endpoint_scope") != "private_compose_network"
        or instance.get("published") is not False
        or instance.get("resources") != expected.profile.public()
    ):
        raise ContractError("vm_evidence_instance_invalid")

    readiness = document.get("readiness")
    if not isinstance(readiness, dict) or readiness.get("status") != "not_ready":
        raise ContractError("vm_evidence_readiness_invalid")
    if readiness.get("compatibility_claim") is not False:
        raise ContractError("vm_evidence_compatibility_claim")

    teardown = document.get("teardown")
    if not isinstance(teardown, dict) or teardown.get("command") != [
        "down",
        "--volumes",
        "--remove-orphans",
    ]:
        raise ContractError("vm_evidence_teardown_invalid")
    if teardown.get("status") != 0 or teardown.get("zero_leftovers") is not True:
        raise ContractError("vm_evidence_teardown_invalid")

    leftovers = document.get("leftover_listing")
    expected_label = f"io.podman.compose.project={expected.project}"
    expected_commands = [
        ["podman", "ps", "-a", "--filter", f"label={expected_label}", "--format", "json"],
        ["podman", "network", "ls", "--filter", f"label={expected_label}", "--format", "json"],
        ["podman", "volume", "ls", "--filter", f"label={expected_label}", "--format", "json"],
    ]
    if not isinstance(leftovers, dict):
        raise ContractError("vm_evidence_leftovers_invalid")
    if leftovers.get("label") != expected_label or leftovers.get("commands") != expected_commands:
        raise ContractError("vm_evidence_leftovers_invalid")
    if leftovers.get("counts") != {"containers": 0, "networks": 0, "volumes": 0}:
        raise ContractError("vm_evidence_leftovers_invalid")
    if document.get("redacted") is not True or document.get("raw_engine_output") is not False:
        raise ContractError("vm_evidence_redaction_invalid")


def validate_vm_evidence_anchor(
    evidence_path: Path = VM_EVIDENCE_PATH,
    anchor_path: Path = VM_EVIDENCE_ANCHOR_PATH,
) -> None:
    try:
        actual = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        anchor = anchor_path.read_text(encoding="utf-8").strip()
    except OSError:
        raise ContractError("vm_evidence_anchor_missing") from None
    expected = f"{actual}  {evidence_path.name}"
    if anchor != expected:
        raise ContractError("vm_evidence_anchor_mismatch")


def _argument_plan(args: argparse.Namespace) -> FleetPlan:
    entries: list[tuple[str, str]] | None = None
    if args.instance:
        entries = [parse_instance_spec(value, args.profile) for value in args.instance]
    return build_plan(args.fleet_id, entries, count=args.count if entries is None else None, default_profile=args.profile)


def _default_state_dir() -> Path:
    configured = os.environ.get("HERMTERNAL_UPSTREAM_FLEET_STATE")
    if configured:
        return Path(configured)
    return Path(tempfile.gettempdir()) / "hermternal-upstream-fleet"


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="rootless Podman Compose Hermes upstream fleet launcher")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def common(subparser: argparse.ArgumentParser, *, fleet_default: str = "smoke") -> None:
        subparser.add_argument("--fleet-id", default=fleet_default)
        subparser.add_argument("--instance", action="append", help="ID[:profile], repeatable")
        subparser.add_argument("--count", type=int)
        subparser.add_argument("--profile", choices=sorted(PROFILES), default="auth")
        subparser.add_argument("--state-dir", type=Path, default=_default_state_dir())

    plan_parser = subparsers.add_parser("plan", help="print a budgeted deterministic plan")
    common(plan_parser)

    render_parser = subparsers.add_parser("render", help="render private Compose files and state")
    common(render_parser)

    for name, help_text in (
        ("start", "start all instances concurrently"),
        ("status", "report bounded Compose status"),
        ("readiness", "report process-level readiness only"),
    ):
        subparser = subparsers.add_parser(name, help=help_text)
        common(subparser)

    endpoint_parser = subparsers.add_parser("endpoint", help="print one private service endpoint")
    endpoint_parser.add_argument("--fleet-id", default="smoke")
    endpoint_parser.add_argument("--instance", required=True)
    endpoint_parser.add_argument("--profile", choices=sorted(PROFILES), default="auth")

    teardown_parser = subparsers.add_parser("teardown", help="remove one instance or the whole fleet")
    teardown_parser.add_argument("--fleet-id", required=True)
    teardown_parser.add_argument("--instance")
    teardown_parser.add_argument("--all", action="store_true")
    teardown_parser.add_argument("--state-dir", type=Path, default=_default_state_dir())

    demo_parser = subparsers.add_parser("demo", help="run the authorized one-instance no-provider VM demo")
    demo_parser.add_argument("--state-dir", type=Path, default=_default_state_dir())
    return parser


def _manifest_unusable(code: str) -> bool:
    return code.startswith("state_") or code in {"json_invalid", "json_too_large", "duplicate_json_key"}


def main(argv: Sequence[str] | None = None, *, _runner: Runner | None = None) -> int:
    """CLI entry point; ``_runner`` is a private offline-test seam only."""

    parser = make_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            emit(_argument_plan(args).public())
            return 0
        if args.command == "render":
            plan = _argument_plan(args)
            paths = render_to_directory(plan, args.state_dir)
            write_manifest(plan, args.state_dir)
            emit(
                _evidence(
                    plan,
                    "render",
                    "rendered",
                    [InstanceOperation(instance, "rendered") for instance in plan.instances],
                    zero=None,
                )
            )
            return 0
        if args.command == "start":
            plan = _argument_plan(args)
            result = start_fleet(plan, args.state_dir, runner=_runner)
            emit(result)
            return 0 if result.get("status") == "started" else 1
        if args.command == "status":
            plan = load_manifest(args.state_dir, args.fleet_id)
            emit(status_fleet(plan, args.state_dir, runner=_runner))
            return 0
        if args.command == "readiness":
            plan = load_manifest(args.state_dir, args.fleet_id)
            result = readiness_fleet(plan, args.state_dir, runner=_runner)
            emit(result)
            return 0 if result.get("status") == "process_ready" else 1
        if args.command == "endpoint":
            instance_id, profile = parse_instance_spec(args.instance, args.profile)
            plan = build_plan(args.fleet_id, [(instance_id, profile)])
            emit(endpoint_one(plan.instances[0]))
            return 0
        if args.command == "teardown":
            if args.instance is None and not args.all:
                raise ContractError("teardown_target_required")
            try:
                plan = load_manifest(args.state_dir, args.fleet_id)
            except ContractError as exc:
                if args.all and _manifest_unusable(exc.code):
                    result = _teardown_without_manifest(
                        args.fleet_id,
                        args.state_dir,
                        reason=exc.code,
                        runner=_runner,
                    )
                    emit(result)
                    return 0 if result.get("status") == "removed" else 1
                raise
            result = teardown_fleet(
                plan,
                args.state_dir,
                instance_id=args.instance,
                runner=_runner,
            )
            emit(result)
            return 0 if result.get("status") == "removed" else 1
        if args.command == "demo":
            result = demo(args.state_dir, runner=_runner)
            emit(result)
            return 0 if result.get("status") in {"process_ready", "not_ready"} else 1
        raise ContractError("unknown_command")
    except ContractError as exc:
        emit({"schema": SCHEMA, "status": "error", "reason": exc.code})
        return 2
    except KeyboardInterrupt:
        emit({"schema": SCHEMA, "status": "error", "reason": "interrupted"})
        return 130
    except BaseException:
        # Keep unexpected failures bounded and independent of environment text.
        emit({"schema": SCHEMA, "status": "error", "reason": "internal_error"})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
