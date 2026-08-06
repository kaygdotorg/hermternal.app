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
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
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
        if (
            name in BLOCKED_ENV_EXACT
            or name.startswith(BLOCKED_ENV_PREFIXES)
            or _is_provider_secret(name)
        ):
            values.pop(name, None)
    # This is a launcher-owned policy value, not caller-provided provider data.
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


def compose_path(state_dir: Path, instance: InstancePlan) -> Path:
    return state_dir / f"{instance.project}.compose.yaml"


def render_to_directory(plan: FleetPlan, state_dir: Path) -> dict[str, Path]:
    state_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    for instance in plan.instances:
        path = compose_path(state_dir, instance)
        path.write_text(render_compose(instance), encoding="utf-8")
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
    state_dir.mkdir(parents=True, exist_ok=True)
    path = state_path(state_dir, plan.fleet_id)
    if path.is_symlink():
        raise ContractError("state_symlink_rejected")
    path.write_text(json.dumps(manifest_for(plan), sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return path


def load_json(path: Path) -> Any:
    """Load a small UTF-8 JSON document with duplicate-key rejection."""

    try:
        raw = path.read_bytes()
    except OSError:
        raise ContractError("state_unreadable") from None
    if len(raw) > 512 * 1024:
        raise ContractError("json_too_large")

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
    if not path.is_file() or path.is_symlink():
        raise ContractError("state_missing")
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


def redacted_diagnostic(text: str) -> str:
    """Bound diagnostics without retaining paths, URLs, credentials, or tokens."""

    value = str(text)
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
    if len(value) > MAX_DIAGNOSTIC_BYTES:
        value = value[:MAX_DIAGNOSTIC_BYTES] + "…"
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
    if isinstance(value, CommandResult):
        return value
    if isinstance(value, subprocess.CompletedProcess):
        return CommandResult(value.returncode, str(value.stdout or ""), str(value.stderr or ""))
    raise ContractError("runner_result_invalid")


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
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout,
        )
    except FileNotFoundError:
        return CommandResult(127, stderr="not_found")
    except subprocess.TimeoutExpired as exc:
        return CommandResult(124, str(exc.stdout or ""), str(exc.stderr or ""), timed_out=True)
    return CommandResult(completed.returncode, completed.stdout or "", completed.stderr or "")


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


def _running_marker(output: str) -> bool:
    value = output.lower()
    return bool(
        re.search(r"\b(?:running|up)\b", value)
        or '"state":"running"' in value
        or '"status":"up"' in value
    )


def status_one(instance: InstancePlan, path: Path, *, runner: Runner | None = None) -> InstanceOperation:
    result = invoke(compose_command(instance, path, ("ps",)), runner=runner, timeout=30.0)
    if result.timed_out:
        return InstanceOperation(instance, "status_timeout", 124)
    if result.returncode != 0:
        return InstanceOperation(instance, "status_failed", result.returncode)
    return InstanceOperation(instance, "running" if _running_marker(result.stdout) else "not_running", 0)


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


def _parse_resource_count(stdout: str) -> int | None:
    try:
        document = json.loads(stdout or "[]")
    except (TypeError, json.JSONDecodeError):
        return None
    if isinstance(document, list):
        return len(document)
    if isinstance(document, dict):
        return 1
    return None


def zero_leftovers(instance: InstancePlan, *, runner: Runner | None = None) -> dict[str, int | None]:
    """Inspect only Podman's generated Compose project label.

    The label is generated by the selected ``podman-compose`` provider and
    scopes all three listings to this instance's project.  Using the native
    Podman listing commands avoids Docker-provider fallback and avoids broad
    host-wide cleanup or resource enumeration.
    """

    label = f"io.podman.compose.project={instance.project}"
    counts: dict[str, int | None] = {}
    for key, command in (
        (
            "containers",
            (
                ENGINE_EXECUTABLE,
                "ps",
                "-a",
                "--filter",
                f"label={label}",
                "--format",
                "json",
            ),
        ),
        (
            "networks",
            (
                ENGINE_EXECUTABLE,
                "network",
                "ls",
                "--filter",
                f"label={label}",
                "--format",
                "json",
            ),
        ),
        (
            "volumes",
            (
                ENGINE_EXECUTABLE,
                "volume",
                "ls",
                "--filter",
                f"label={label}",
                "--format",
                "json",
            ),
        ),
    ):
        result = invoke(command, runner=runner, timeout=30.0)
        if result.returncode != 0 or result.timed_out:
            counts[key] = None
            continue
        counts[key] = _parse_resource_count(result.stdout)
    return counts


def _is_zero(leftovers: Mapping[str, int | None]) -> bool:
    return all(leftovers.get(key) == 0 for key in ("containers", "networks", "volumes"))


def teardown_one(
    instance: InstancePlan,
    path: Path,
    *,
    runner: Runner | None = None,
) -> InstanceOperation:
    if path.exists() and path.is_symlink():
        raise ContractError("compose_symlink_rejected")
    if path.exists():
        down = invoke(
            compose_command(instance, path, ("down", "--volumes", "--remove-orphans")),
            runner=runner,
            timeout=120.0,
        )
    else:
        down = CommandResult(0)
    leftovers = zero_leftovers(instance, runner=runner)
    if down.returncode != 0 or down.timed_out:
        return InstanceOperation(instance, "teardown_failed", down.returncode, leftovers)
    if not _is_zero(leftovers):
        return InstanceOperation(instance, "leftovers_detected", 0, leftovers)
    return InstanceOperation(instance, "removed", 0, leftovers)


def _run_parallel(
    instances: Sequence[InstancePlan],
    operation: Callable[[InstancePlan], InstanceOperation],
) -> list[InstanceOperation]:
    if not instances:
        return []
    results: list[InstanceOperation] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(instances))) as pool:
        futures = [pool.submit(operation, instance) for instance in instances]
        for future in futures:
            results.append(future.result())
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
    enforce_preflight: bool = True,
) -> dict[str, object]:
    """Render, start concurrently, and clean every project on partial failure."""

    paths = render_to_directory(plan, state_dir)
    write_manifest(plan, state_dir)
    operations: list[InstanceOperation] = []
    failure: str | None = None
    try:
        if enforce_preflight:
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
        return _evidence(plan, "start", "started", operations, zero=True)

    cleanup: list[InstanceOperation] = []
    try:
        cleanup = _run_parallel(
            plan.instances,
            lambda instance: teardown_one(instance, paths[instance.instance_id], runner=runner),
        )
    except KeyboardInterrupt:
        cleanup = [InstanceOperation(instance, "cleanup_interrupted") for instance in plan.instances]
    zero = bool(cleanup) and all(operation.status == "removed" for operation in cleanup)
    combined: list[InstanceOperation] = []
    cleanup_by_id = {operation.instance.instance_id: operation for operation in cleanup}
    for instance in plan.instances:
        started = next((item for item in operations if item.instance.instance_id == instance.instance_id), None)
        cleanup_operation = cleanup_by_id.get(instance.instance_id)
        if started is not None and started.status != "started":
            combined.append(started)
        elif cleanup_operation is not None:
            combined.append(
                InstanceOperation(
                    instance,
                    f"{failure}:{cleanup_operation.status}",
                    cleanup_operation.exit_code,
                    cleanup_operation.leftovers,
                )
            )
    if zero:
        _remove_state_artifacts(plan, state_dir)
    return _evidence(plan, "start", "failed", combined, zero=zero)


def _remove_state_artifacts(plan: FleetPlan, state_dir: Path) -> None:
    for instance in plan.instances:
        path = compose_path(state_dir, instance)
        if path.is_file() and not path.is_symlink():
            path.unlink()
    manifest = state_path(state_dir, plan.fleet_id)
    if manifest.is_file() and not manifest.is_symlink():
        manifest.unlink()


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

    operations = _run_parallel(
        selected,
        lambda instance: teardown_one(instance, compose_path(state_dir, instance), runner=runner),
    )
    zero = all(operation.status == "removed" for operation in operations)
    if zero:
        for instance in selected:
            path = compose_path(state_dir, instance)
            if path.is_file() and not path.is_symlink():
                path.unlink()
        remaining = [instance for instance in plan.instances if instance not in selected]
        if not remaining:
            manifest = state_path(state_dir, plan.fleet_id)
            if manifest.is_file() and not manifest.is_symlink():
                manifest.unlink()
        else:
            remaining_plan = build_plan(
                plan.fleet_id,
                [(instance.instance_id, instance.profile.name) for instance in remaining],
            )
            write_manifest(remaining_plan, state_dir)
    status = "removed" if zero else "cleanup_failed"
    return _evidence(plan, "teardown", status, operations, zero=zero)


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
    started = start_fleet(plan, state_dir, runner=runner, enforce_preflight=True)
    if started.get("status") != "started":
        return {
            **started,
            "action": "demo",
            "authorization": True,
            "live_run": True,
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
    try:
        cleanup = teardown_fleet(plan, state_dir, runner=runner)
        cleanup_status = str(cleanup.get("status", "cleanup_failed"))
        cleanup_zero = cleanup.get("zero_leftovers") is True
    except BaseException:
        # Keep the demo result bounded while making cleanup uncertainty visible.
        cleanup_status = "cleanup_failed"
        cleanup_zero = False

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
                "containers": 0 if cleanup_zero else None,
                "networks": 0 if cleanup_zero else None,
                "volumes": 0 if cleanup_zero else None,
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


def main(argv: Sequence[str] | None = None) -> int:
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
                    zero=True,
                )
            )
            return 0
        if args.command == "start":
            plan = _argument_plan(args)
            result = start_fleet(plan, args.state_dir)
            emit(result)
            return 0 if result.get("status") == "started" else 1
        if args.command == "status":
            plan = load_manifest(args.state_dir, args.fleet_id)
            emit(status_fleet(plan, args.state_dir))
            return 0
        if args.command == "readiness":
            plan = load_manifest(args.state_dir, args.fleet_id)
            result = readiness_fleet(plan, args.state_dir)
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
                if exc.code == "state_missing" and args.all:
                    emit(
                        {
                            "schema": SCHEMA,
                            "action": "teardown",
                            "status": "removed",
                            "fleet_id": args.fleet_id,
                            "instances": [],
                            "zero_leftovers": True,
                            "idempotent": True,
                            "redaction": {"bounded": True, "raw_engine_output": False},
                        }
                    )
                    return 0
                raise
            result = teardown_fleet(
                plan,
                args.state_dir,
                instance_id=args.instance,
            )
            emit(result)
            return 0 if result.get("status") == "removed" else 1
        if args.command == "demo":
            result = demo(args.state_dir)
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
