#!/usr/bin/env python3
"""Validate and render the synthetic disposable Hermes Compose harness.

This module is intentionally standard-library-only. It validates a checked-in
policy and renders a small standalone Compose document; it never starts Hermes,
Podman, Docker, a provider, a browser, a PTY, or a network service. The VM
smoke runner invokes the rendered document with an executor outside this
module so the offline contract cannot silently become a live integration.

The image's entrypoint is deliberately omitted from the rendered service. The
pinned Hermes image owns `/opt/hermes/docker/entrypoint-dispatch.sh`, which
preserves its `/init` PID-1 path. An arbitrary Compose `entrypoint`, `init`, or
`user` override would bypass that source-reviewed behavior, so the validator
rejects those fields before a stack can be rendered.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
CASES_PATH = ROOT / "cases.json"
BASELINE_PATH = ROOT / "validation-baseline.json"
BASELINE_ANCHOR_PATH = ROOT / "validation-baseline-sha256.txt"
SCHEMA = "hermternal.integration.hermes-disposable.v1"
BASELINE_SCHEMA = "hermternal.integration.hermes-disposable-baseline.v1"
OPERATION = "R-02A"
CONTRACT = "hermes-disposable-v1"
PINNED_HERMES_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
PINNED_HERMES_TREE = "886db5eb1150f819344d67fedc81aef0caab09ff"
IMAGE_REPOSITORY = "hermes-agent"
IMAGE_TAG = "hermternal-f5be9236"
IMAGE_REFERENCE = f"{IMAGE_REPOSITORY}:{IMAGE_TAG}"
MAX_JSON_BYTES = 512 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_INTEGER_DIGITS = 1024
MAX_JSON_NODES = 4096
MAX_OBJECT_KEYS = 96
MAX_ARRAY_LENGTH = 512
MAX_STRING_LENGTH = 8192
MAX_ERROR_OUTPUT = 240
BASELINE_REPETITIONS = 30
ERROR_CODE = "hermes_disposable_harness_validation_error"
ARTIFACT_FILES = ("README.md", "cases.json", "test_validate.py")

# These values are filled after the focused fixture is written and benchmarked.
# The validator source uses a normalized self-identity to avoid a circular hash.
PINNED_RETAINED_ARTIFACTS: dict[str, tuple[int, str]] = {
    "README.md": (8563, "a747092dc27284ebef42c0a1f218cdc7d4a55c5026cb53cd831afd857b070385"),
    "cases.json": (11331, "d44ea076192e5e391082820b85c4ed3937cef377b57e4a7e8719dcbb01af5475"),
    "test_validate.py": (14398, "7a2095b93fb7f8ba698b69176ce34c3fcd3792e66c1f35f183c65d51befd8a0c"),
}
PINNED_VALIDATOR_SOURCE_SHA256 = "401dc6a66b74ca589501a6eee2cbe2ba9d11066cf1b5a76f499cdf269e0a0ea3"
PINNED_BASELINE_EVIDENCE_SHA256 = "3ecda8c4f9ca1a290166ec06c07415df8f2f3b12420113f9d792139d2fd176f0"
VALIDATOR_IDENTITY_RE = re.compile(r'(?m)^PINNED_VALIDATOR_SOURCE_SHA256 = "[^"]+"$')
HEX40_RE = re.compile(r"[0-9a-f]{40}")
HEX64_RE = re.compile(r"[0-9a-f]{64}")
STACK_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,31}")
INSTANCE_RE = re.compile(r"[a-z][a-z0-9-]{0,23}")
PROJECT_RE = re.compile(r"hermes-disposable-[a-z][a-z0-9-]{0,31}-[0-9a-f]{8}")

ROOT_KEYS = (
    "schema",
    "operation",
    "contract",
    "pinned_source_sha",
    "pinned_source_tree",
    "synthetic_only",
    "network_access",
    "live_run",
    "compatible",
    "proof_status",
    "executor_policy",
    "stack_policy",
    "lanes",
    "cases",
)
EXECUTOR_POLICY_KEYS = ("default", "podman", "docker")
EXECUTOR_DETAIL_KEYS = ("mode", "compose_command", "storage", "network", "cgroup", "smoke")
STACK_POLICY_KEYS = (
    "compose_format",
    "service_name",
    "internal_network",
    "named_volume",
    "container_name",
    "network_mode_host",
    "published_ports",
    "host_profile_bind",
    "preserve_image_entrypoint",
    "explicit_uid_gid",
    "restart",
    "cpu_limit",
    "memory_limit",
    "pid_limit",
    "tmpfs",
    "shm_size",
    "log_max_size",
    "log_max_files",
    "cap_drop",
    "no_new_privileges",
    "host_environment",
    "provider_auto_discovery",
    "api_default",
    "pty_public",
    "dashboard_public",
    "teardown",
)
LANE_KEYS = ("id", "provider", "dashboard", "api", "pty", "command", "scope")
CASE_KEYS = ("id", "kind", "input", "expected", "notes")
CASE_INPUT_KEYS = ("action", "stack_id", "instance", "other_instance", "lane", "executor", "teardown_target")
CASE_EXPECTED_KEYS = (
    "decision",
    "reason",
    "project_unique",
    "network_internal",
    "volume_named",
    "ports_published",
    "host_profile_bind",
    "entrypoint_override",
    "resource_caps",
    "logs_bounded",
    "live_claim",
)
BASELINE_ROOT_KEYS = ("schema", "validator", "fixture", "metric", "environment", "runs", "artifact", "threshold")
BASELINE_RUN_KEYS = ("mode", "command", "repetitions", "distribution", "trace")
BASELINE_DISTRIBUTION_KEYS = ("min_ms", "p50_ms", "p95_ms", "p99_ms", "max_ms", "mean_ms")
BASELINE_ENVIRONMENT_KEYS = ("platform", "python")
BASELINE_ARTIFACT_KEYS = ("files", "bytes", "sha256")
BASELINE_EVIDENCE_KEYS = ("schema", "validator", "fixture", "metric", "runs", "threshold")
BASELINE_COMMANDS = {
    "normal": "python3 tests/integration/hermes-disposable/validate.py",
    "optimized": "python3 -O tests/integration/hermes-disposable/validate.py",
}

EXPECTED_EXECUTOR_POLICY = {
    "default": "podman",
    "podman": {
        "mode": "rootless_preferred",
        "compose_command": "podman compose",
        "storage": "overlay",
        "network": "netavark",
        "cgroup": "v2",
        "smoke": "one_live_no_provider_stack",
    },
    "docker": {
        "mode": "compatibility_config_only",
        "compose_command": "docker compose",
        "storage": "engine_selected",
        "network": "engine_selected",
        "cgroup": "engine_selected",
        "smoke": "not_run",
    },
}
EXPECTED_STACK_POLICY = {
    "compose_format": "yaml",
    "service_name": "gateway",
    "internal_network": True,
    "named_volume": True,
    "container_name": False,
    "network_mode_host": False,
    "published_ports": False,
    "host_profile_bind": False,
    "preserve_image_entrypoint": True,
    "explicit_uid_gid": True,
    "restart": "no",
    "cpu_limit": "0.50",
    "memory_limit": "512m",
    "pid_limit": 256,
    "tmpfs": ["tmpfs_tmp_64m", "tmpfs_run_16m"],
    "shm_size": "64m",
    "log_max_size": "1m",
    "log_max_files": 2,
    "cap_drop": ["ALL"],
    "no_new_privileges": True,
    "host_environment": False,
    "provider_auto_discovery": False,
    "api_default": "disabled",
    "pty_public": False,
    "dashboard_public": False,
    "teardown": "project_volumes_orphans_only",
}
TMPFS_MOUNTS = ("/tmp:size=64m,mode=1777", "/run:size=16m,mode=755")
EXPECTED_LANES = [
    {
        "id": "no-provider",
        "provider": "none",
        "dashboard": "disabled",
        "api": "disabled",
        "pty": "disabled",
        "command": ["sleep", "infinity"],
        "scope": "smoke",
    },
    {
        "id": "browser",
        "provider": "none",
        "dashboard": "internal_disposable_basic_auth",
        "api": "disabled",
        "pty": "disabled",
        "command": ["sleep", "infinity"],
        "scope": "render_only",
    },
    {
        "id": "model",
        "provider": "synthetic-local",
        "dashboard": "disabled",
        "api": "disabled",
        "pty": "disabled",
        "command": ["sleep", "infinity"],
        "scope": "render_only",
    },
]
EXPECTED_CASE_IDS = (
    "render-podman-no-provider",
    "render-docker-no-provider",
    "render-browser-disposable",
    "render-model-synthetic",
    "unique-project-and-volume",
    "reject-stack-path-traversal",
    "reject-stack-uppercase",
    "reject-instance-path-traversal",
    "reject-unknown-lane",
    "reject-unknown-executor",
    "reject-unrecognized-teardown",
)

SENSITIVE_NORMALIZED_KEYS = frozenset(
    {
        "password",
        "passphrase",
        "token",
        "secret",
        "authorization",
        "bearer",
        "accesskey",
        "apikey",
        "cookie",
        "cookievalue",
        "clientsecret",
        "credential",
        "credentials",
        "host",
        "hostname",
        "ipaddress",
        "privateaddress",
        "sessionid",
        "sessiontoken",
        "ticket",
        "ticketid",
        "ticketvalue",
        "profilepath",
        "profilebind",
        "userdata",
        "userdatafile",
        "filename",
        "filepath",
    }
)
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?<![A-Za-z0-9])(?P<key>(?:password|passphrase|token|secret|authorization|bearer|"
    r"cookie(?:[_ .-]*(?:value|id))?|credential|credentials|host(?:name)?|"
    r"(?:private[_ .-]*)?address|session(?:[_ .-]*(?:id|token|value))?|"
    r"ticket(?:[_ .-]*(?:id|value|fragment))?|profile[_ .-]*(?:path|bind)|"
    r"user[_ .-]*data|file(?:name|path))\s*[:=]\s*)"
    r"(?P<value>[^\s,}\]]+)",
    re.IGNORECASE,
)
URL_RE = re.compile(r"\b(?:https?|ssh|file)://[^\s,}\]]+", re.IGNORECASE)
DATA_URL_RE = re.compile(r"\bdata:[^\s,}\]]+,[^\s,}\]]+", re.IGNORECASE)
HOSTNAME_RE = re.compile(
    r"(?<![A-Za-z0-9._/-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}(?![A-Za-z0-9.-])",
    re.IGNORECASE,
)
IPV4_RE = re.compile(r"(?<![A-Za-z0-9])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9])")
IPV6_RE = re.compile(r"(?<![A-Za-z0-9])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?![A-Za-z0-9])", re.IGNORECASE)
ABSOLUTE_PATH_RE = re.compile(r"(?<![A-Za-z0-9])(?:/[^\s,}\]]+|[A-Za-z]:[\\/][^\s,}\]]+)")
FILENAME_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_.-]+\.(?:json|ya?ml|txt|py|log|env|pem|key)(?![A-Za-z0-9])", re.IGNORECASE)
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=_])(?:[A-Za-z0-9+/]{20,}={0,2})(?![A-Za-z0-9+/=_-])")
SECRET_VALUE_PATTERNS = (
    DATA_URL_RE,
    URL_RE,
    re.compile(r"\b(?:Bearer|Basic)\s+[^\s,}\]]+", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z0-9 ]+ PRIVATE KEY-----", re.IGNORECASE),
    IPV4_RE,
    IPV6_RE,
    HOSTNAME_RE,
    ABSOLUTE_PATH_RE,
    FILENAME_RE,
    BASE64_RE,
)
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class FixtureJSONError(ValueError):
    """Raised for malformed, oversized, or unsafe fixture JSON."""


class ValidationError(ValueError):
    """Raised when the frozen disposable-stack contract is violated."""


@dataclass(frozen=True)
class RenderedStack:
    """A deterministic render result with metadata needed by the VM runner."""

    project: str
    network: str
    volume: str
    executor: str
    lane: str
    compose: str

    def public_metadata(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "network": self.network,
            "volume": self.volume,
            "executor": self.executor,
            "lane": self.lane,
        }


def compact_error(message: object) -> str:
    """Redact untrusted diagnostics before applying the fixed output cap."""

    redacted = str(message)
    for pattern in SECRET_VALUE_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)

    def redact_assignment(match: re.Match[str]) -> str:
        return f"{match.group('key')}[REDACTED]"

    redacted = SENSITIVE_ASSIGNMENT_RE.sub(redact_assignment, redacted)
    # Error labels are fixed; anything still shaped like a hostile object key or
    # shell fragment is safer as a marker than as retained diagnostic material.
    redacted = re.sub(r"(?:attacker|secret|credential)[^\s,}\]]*", "[REDACTED]", redacted, flags=re.IGNORECASE)
    if len(redacted) > MAX_ERROR_OUTPUT:
        return f"{redacted[: MAX_ERROR_OUTPUT - 3]}..."
    return redacted


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(compact_error(message))


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FixtureJSONError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_nonfinite_json_constant(value: str) -> Any:
    del value
    raise FixtureJSONError("non-finite JSON number is not allowed")


def _reject_overflowing_json_float(value: str) -> float:
    try:
        parsed = float(value)
    except (OverflowError, ValueError) as exc:
        raise FixtureJSONError("JSON float is outside the bounded range") from exc
    if not math.isfinite(parsed):
        raise FixtureJSONError("non-finite JSON number is not allowed")
    return parsed


def _reject_oversized_json_integer(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise FixtureJSONError("JSON integer digit limit exceeded")
    try:
        return int(value)
    except (OverflowError, ValueError) as exc:
        raise FixtureJSONError("invalid JSON integer") from exc


def scan_json_nesting(text: str) -> None:
    """Reject hostile structural depth before the JSON decoder recurses."""

    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise FixtureJSONError("JSON nesting exceeds the bounded limit")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise FixtureJSONError("malformed JSON structure")
    if in_string or escaped or depth != 0:
        raise FixtureJSONError("malformed JSON structure")


def validate_json_tree(value: Any, depth: int = 0) -> int:
    """Apply recursive node, container, text, and finite-number limits."""

    require(depth <= MAX_JSON_DEPTH, "JSON depth exceeds the bounded limit")
    if type(value) is dict:
        require(len(value) <= MAX_OBJECT_KEYS, "JSON object has too many keys")
        nodes = 1
        for key, child in value.items():
            require(type(key) is str, "JSON object key must be text")
            require(len(key) <= MAX_STRING_LENGTH, "JSON object key is too long")
            nodes += validate_json_tree(child, depth + 1)
            require(nodes <= MAX_JSON_NODES, "JSON node count exceeds the bounded limit")
        return nodes
    if type(value) is list:
        require(len(value) <= MAX_ARRAY_LENGTH, "JSON array is too long")
        nodes = 1
        for child in value:
            nodes += validate_json_tree(child, depth + 1)
            require(nodes <= MAX_JSON_NODES, "JSON node count exceeds the bounded limit")
        return nodes
    if type(value) is str:
        require(len(value) <= MAX_STRING_LENGTH, "JSON string is too long")
        require(CONTROL_RE.search(value) is None, "JSON control character is not allowed")
        return 1
    if type(value) is float:
        require(math.isfinite(value), "JSON number is not finite")
        return 1
    require(value is None or type(value) in {bool, int}, "unsupported JSON value type")
    return 1


def load_json(path: Path) -> Any:
    """Load one bounded UTF-8 JSON document with strict parser hooks."""

    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_JSON_BYTES + 1)
    except OSError as exc:
        raise FixtureJSONError("fixture file is unavailable") from exc
    if len(data) > MAX_JSON_BYTES:
        raise FixtureJSONError("fixture JSON exceeds the input byte limit")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FixtureJSONError("fixture JSON is not UTF-8") from exc
    scan_json_nesting(text)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonfinite_json_constant,
            parse_float=_reject_overflowing_json_float,
            parse_int=_reject_oversized_json_integer,
        )
    except FixtureJSONError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        raise FixtureJSONError("fixture JSON is malformed") from exc
    validate_json_tree(value)
    return value


def _normalize_sensitive_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", key.casefold())


def _walk_redaction(value: Any, *, allow_benchmark_paths: bool = False) -> None:
    if type(value) is dict:
        for key, child in value.items():
            require(type(key) is str, "redaction object key must be text")
            require(_normalize_sensitive_key(key) not in SENSITIVE_NORMALIZED_KEYS, "sensitive fixture field is not allowed")
            _walk_redaction(child, allow_benchmark_paths=allow_benchmark_paths)
        return
    if type(value) is list:
        for child in value:
            _walk_redaction(child, allow_benchmark_paths=allow_benchmark_paths)
        return
    if type(value) is str:
        if HEX40_RE.fullmatch(value) or HEX64_RE.fullmatch(value):
            return
        for pattern in SECRET_VALUE_PATTERNS:
            if allow_benchmark_paths and pattern in {ABSOLUTE_PATH_RE, FILENAME_RE, HOSTNAME_RE}:
                continue
            require(pattern.search(value) is None, "secret-shaped fixture value is not allowed")
        require(SENSITIVE_ASSIGNMENT_RE.search(value) is None, "credential-shaped fixture value is not allowed")


def validate_redaction(value: Any, *, allow_benchmark_paths: bool = False) -> None:
    """Reject retained credentials, hosts, URLs, and user-data shapes.

    Benchmark metadata may name the checked-in validator and fixture files; that
    narrow exception does not permit hostnames, URLs, credentials, or runtime
    paths in the observed trace.
    """

    _walk_redaction(value, allow_benchmark_paths=allow_benchmark_paths)


def strict_keys(value: Any, expected: tuple[str, ...], label: str) -> dict[str, Any]:
    require(type(value) is dict, f"{label} must be an object")
    require(tuple(value.keys()) == expected, f"{label} keys or ordering changed")
    return value


def _text(value: Any, label: str, *, max_length: int = MAX_STRING_LENGTH) -> str:
    require(type(value) is str, f"{label} must be text")
    require(0 < len(value) <= max_length, f"{label} has an invalid length")
    require(CONTROL_RE.search(value) is None, f"{label} contains control characters")
    return value


def _bool(value: Any, label: str) -> bool:
    require(type(value) is bool, f"{label} must be boolean")
    return value


def _int(value: Any, label: str) -> int:
    require(type(value) is int and type(value) is not bool, f"{label} must be an integer")
    return value


def _enum(value: Any, allowed: frozenset[str], label: str) -> str:
    result = _text(value, label)
    require(result in allowed, f"{label} has an unsupported value")
    return result


def strict_equal(actual: Any, expected: Any, label: str) -> None:
    """Compare values while preserving exact JSON type identity and order."""

    require(type(actual) is type(expected), f"{label} type changed")
    if isinstance(expected, dict):
        require(tuple(actual.keys()) == tuple(expected.keys()), f"{label} keys or ordering changed")
        for key, expected_value in expected.items():
            strict_equal(actual[key], expected_value, f"{label} field")
        return
    if isinstance(expected, list):
        require(len(actual) == len(expected), f"{label} length changed")
        for actual_value, expected_value in zip(actual, expected):
            strict_equal(actual_value, expected_value, f"{label} item")
        return
    require(actual == expected, f"{label} value changed")


def _slug(value: Any, pattern: re.Pattern[str], label: str) -> str:
    text = _text(value, label, max_length=32)
    require(pattern.fullmatch(text) is not None, f"{label} is not a safe identifier")
    require("--" not in text and ".." not in text, f"{label} contains an unsafe separator")
    return text


def _project_name(stack_id: str, instance: str) -> str:
    suffix = hashlib.sha256(f"{stack_id}\0{instance}".encode("ascii")).hexdigest()[:8]
    return f"hermes-disposable-{stack_id}-{suffix}"


def _browser_values(project: str) -> tuple[str, str]:
    """Create deterministic disposable values for a render-only browser lane."""

    digest = hashlib.sha256(f"browser\0{project}".encode("ascii")).hexdigest()
    return "synthetic-browser", f"synthetic-browser-{digest[:24]}"


def _yaml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def _lane_environment(lane: str, project: str) -> list[tuple[str, str]]:
    environment = [
        ("HERMES_HOME", "/opt/data"),
        ("HERMES_UID", "10000"),
        ("HERMES_GID", "10000"),
        ("HERMES_DISABLE_LAZY_INSTALLS", "1"),
    ]
    if lane == "no-provider":
        environment.append(("HERMES_DASHBOARD", "0"))
    elif lane == "browser":
        username, password = _browser_values(project)
        environment.extend(
            [
                ("HERMES_DASHBOARD", "1"),
                ("HERMES_DASHBOARD_HOST", "127.0.0.1"),
                ("HERMES_DASHBOARD_BASIC_AUTH_USERNAME", username),
                ("HERMES_DASHBOARD_BASIC_AUTH_PASSWORD", password),
            ]
        )
    elif lane == "model":
        environment.extend(
            [
                ("HERMES_DASHBOARD", "0"),
                ("HERMES_PROVIDER", "synthetic-local"),
                ("HERMES_PROVIDER_AUTO_DISCOVERY", "0"),
            ]
        )
    else:
        raise ValidationError("lane is not supported")
    return environment


def render_stack(
    stack_id: str,
    *,
    instance: str = "fixture",
    lane: str = "no-provider",
    executor: str = "podman",
) -> RenderedStack:
    """Render one safe stack without reading host environment or provider state."""

    stack_id = _slug(stack_id, STACK_ID_RE, "stack id")
    instance = _slug(instance, INSTANCE_RE, "stack instance")
    lane = _enum(lane, frozenset({"no-provider", "browser", "model"}), "lane")
    executor = _enum(executor, frozenset({"podman", "docker"}), "executor")
    project = _project_name(stack_id, instance)
    network = f"{project}_internal"
    volume = f"{project}_data"
    log_driver = "k8s-file" if executor == "podman" else "json-file"
    environment = _lane_environment(lane, project)
    lines = [
        "services:",
        "  gateway:",
        f"    image: {_yaml_string(IMAGE_REFERENCE)}",
        '    restart: "no"',
        "    cap_drop:",
        '      - "ALL"',
        "    security_opt:",
        '      - "no-new-privileges:true"',
        "    environment:",
    ]
    lines.extend(f"      {key}: {_yaml_string(value)}" for key, value in environment)
    lines.extend(
        [
            "    volumes:",
            '      - "data:/opt/data"',
            "    networks:",
            "      - internal",
            "    tmpfs:",
            f'      - "{TMPFS_MOUNTS[0]}"',
            f'      - "{TMPFS_MOUNTS[1]}"',
            f'    shm_size: "{EXPECTED_STACK_POLICY["shm_size"]}"',
            f'    cpus: "{EXPECTED_STACK_POLICY["cpu_limit"]}"',
            f'    mem_limit: "{EXPECTED_STACK_POLICY["memory_limit"]}"',
            f"    pids_limit: {EXPECTED_STACK_POLICY['pid_limit']}",
            "    logging:",
            f'      driver: "{log_driver}"',
            "      options:",
            f'        max-size: "{EXPECTED_STACK_POLICY["log_max_size"]}"',
        ]
    )
    if executor == "docker":
        lines.append(f'        max-file: "{EXPECTED_STACK_POLICY["log_max_files"]}"')
    lines.extend(
        [
            '    command: ["sleep", "infinity"]',
            "networks:",
            "  internal:",
            f'    name: "{network}"',
            "    internal: true",
            "volumes:",
            "  data:",
            f'    name: "{volume}"',
        ]
    )
    compose = "\n".join(lines) + "\n"
    result = RenderedStack(project, network, volume, executor, lane, compose)
    validate_rendered_stack(result)
    return result


def validate_rendered_stack(result: RenderedStack) -> None:
    """Check the canonical render for all no-host and entrypoint invariants."""

    require(type(result.project) is str and PROJECT_RE.fullmatch(result.project) is not None, "project name is not canonical")
    require(result.network == f"{result.project}_internal", "network name is not canonical")
    require(result.volume == f"{result.project}_data", "volume name is not canonical")
    require(result.executor in {"podman", "docker"}, "executor is not supported")
    require(result.lane in {"no-provider", "browser", "model"}, "lane is not supported")
    text = result.compose
    require(len(text.encode("utf-8")) <= MAX_JSON_BYTES, "rendered Compose exceeds the bounded size")
    require("${" not in text, "host environment interpolation is not allowed")
    require("container_name" not in text, "fixed container names are not allowed")
    require("network_mode" not in text, "host network mode is not allowed")
    require("ports:" not in text, "published ports are not allowed")
    require("entrypoint:" not in text, "entrypoint overrides are not allowed")
    require("    init:" not in text, "init overrides are not allowed")
    require("    user:" not in text, "user overrides are not allowed")
    require('      - "data:/opt/data"' in text, "data must use the named volume key")
    require(f'    name: "{result.network}"' in text, "network name is not unique")
    require(f'    name: "{result.volume}"' in text, "volume name is not unique")
    require("    internal: true" in text, "network must be internal")
    require('    restart: "no"' in text, "restart policy must be no")
    require('      HERMES_UID: "10000"' in text and '      HERMES_GID: "10000"' in text, "explicit Hermes UID/GID are required")
    require('    cpus: "0.50"' in text and '    mem_limit: "512m"' in text, "CPU and memory limits are required")
    require("    pids_limit: 256" in text and '    shm_size: "64m"' in text, "PID and shared-memory limits are required")
    require('        max-size: "1m"' in text, "bounded log size is required")
    require('      - "ALL"' in text and 'no-new-privileges:true' in text, "capability limits are required")
    require('    image: "hermes-agent:hermternal-f5be9236"' in text, "pinned image reference changed")
    require('    command: ["sleep", "infinity"]' in text, "startup command changed")
    if result.executor == "docker":
        require('      driver: "json-file"' in text and '        max-file: "2"' in text, "Docker log compatibility lane is not bounded")
    else:
        require('      driver: "k8s-file"' in text, "Podman log driver changed")
        require('        max-file:' not in text, "Podman lane must not assume Docker max-file semantics")
    if result.lane == "no-provider":
        require("HERMES_PROVIDER" not in text and "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD" not in text, "no-provider lane contains runtime credentials")
    elif result.lane == "browser":
        require('HERMES_DASHBOARD: "1"' in text, "browser lane dashboard is not enabled")
        require("HERMES_DASHBOARD_BASIC_AUTH_USERNAME" in text and "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD" in text, "browser lane auth is not generated")
        require("synthetic-browser-" in text, "browser lane value is not disposable")
        require("API_SERVER_KEY" not in text, "browser lane must not enable the API server")
    else:
        require('HERMES_PROVIDER: "synthetic-local"' in text, "model lane provider is not synthetic")
        require('HERMES_PROVIDER_AUTO_DISCOVERY: "0"' in text, "model lane auto-discovery is not disabled")
        require("API_SERVER_KEY" not in text, "model lane must not enable the API server")


def compose_command(executor: str, project: str, compose_path: Path, verb: str, *arguments: str) -> tuple[str, ...]:
    """Build an argv tuple for one explicitly selected Compose implementation."""

    executor = _enum(executor, frozenset({"podman", "docker"}), "executor")
    project = _slug(project, PROJECT_RE, "project")
    verb = _enum(verb, frozenset({"config", "up", "down"}), "Compose operation")
    require(isinstance(compose_path, Path) and compose_path.name.endswith((".yml", ".yaml")), "Compose path is not a YAML file")
    require(all(type(argument) is str and "\x00" not in argument for argument in arguments), "Compose argument is invalid")
    command = (executor, "compose", "--project-name", project, "--file", str(compose_path), verb, *arguments)
    if verb == "down":
        require(arguments == ("--volumes", "--remove-orphans"), "teardown must remove only project volumes and orphans")
    return command


def validate_teardown_target(expected_project: str, target_project: str) -> None:
    """Refuse teardown unless the caller names the exact generated project."""

    _slug(expected_project, PROJECT_RE, "expected project")
    require(type(target_project) is str and target_project == expected_project, "teardown project is not recognized")


def _validate_root(document: Any) -> dict[str, Any]:
    root = strict_keys(document, ROOT_KEYS, "cases")
    require(root["schema"] == SCHEMA, "cases schema changed")
    require(root["operation"] == OPERATION, "cases operation changed")
    require(root["contract"] == CONTRACT, "cases contract changed")
    require(root["pinned_source_sha"] == PINNED_HERMES_SHA and HEX40_RE.fullmatch(root["pinned_source_sha"]), "pinned Hermes SHA changed")
    require(root["pinned_source_tree"] == PINNED_HERMES_TREE and HEX40_RE.fullmatch(root["pinned_source_tree"]), "pinned Hermes tree changed")
    require(_bool(root["synthetic_only"], "cases.synthetic_only") is True, "cases must be synthetic")
    require(_bool(root["network_access"], "cases.network_access") is False, "network access must be disabled")
    require(_bool(root["live_run"], "cases.live_run") is False, "fixture cannot claim a live run")
    require(_bool(root["compatible"], "cases.compatible") is False, "fixture cannot claim compatibility")
    require(root["proof_status"] == "not_run", "proof status must remain not_run")
    strict_equal(root["executor_policy"], EXPECTED_EXECUTOR_POLICY, "executor policy")
    strict_equal(root["stack_policy"], EXPECTED_STACK_POLICY, "stack policy")
    strict_equal(root["lanes"], EXPECTED_LANES, "lanes")
    return root


def _validate_case_shape(case: Any, index: int) -> dict[str, Any]:
    row = strict_keys(case, CASE_KEYS, f"cases[{index}]")
    require(type(row["id"]) is str and row["id"] == EXPECTED_CASE_IDS[index], "case inventory or order changed")
    _enum(row["kind"], frozenset({"positive", "negative", "security", "compatibility"}), "case kind")
    request = strict_keys(row["input"], CASE_INPUT_KEYS, "case input")
    expected = strict_keys(row["expected"], CASE_EXPECTED_KEYS, "case expected")
    _enum(request["action"], frozenset({"render", "unique", "teardown"}), "case action")
    if request["stack_id"] is not None:
        _text(request["stack_id"], "case stack id")
    if request["instance"] is not None:
        _text(request["instance"], "case instance")
    if request["other_instance"] is not None:
        _text(request["other_instance"], "case other instance")
    if request["lane"] is not None:
        _text(request["lane"], "case lane")
    if request["executor"] is not None:
        _text(request["executor"], "case executor")
    if request["teardown_target"] is not None:
        _text(request["teardown_target"], "case teardown target")
    _enum(expected["decision"], frozenset({"allow", "deny"}), "case decision")
    _enum(expected["reason"], frozenset({"rendered_safe_stack", "unique_generated_names", "teardown_target_recognized", "unsafe_stack_id", "unsafe_instance", "unknown_lane", "unknown_executor", "unrecognized_teardown"}), "case reason")
    for key in CASE_EXPECTED_KEYS[2:]:
        _bool(expected[key], f"case expected {key}")
    _text(row["notes"], "case notes", max_length=240)
    require(expected["live_claim"] is False, "case cannot claim live evidence")
    return row


def _invariant_outcome(*, decision: str, reason: str, passed: bool) -> dict[str, Any]:
    return {
        "decision": decision,
        "reason": reason,
        "project_unique": passed,
        "network_internal": passed,
        "volume_named": passed,
        "ports_published": False,
        "host_profile_bind": False,
        "entrypoint_override": False,
        "resource_caps": passed,
        "logs_bounded": passed,
        "live_claim": False,
    }


def evaluate_case(case: Any) -> dict[str, Any]:
    """Evaluate one already-shaped synthetic case without trusting its ID."""

    request = case["input"]
    try:
        if request["action"] == "render":
            rendered = render_stack(
                request["stack_id"],
                instance=request["instance"],
                lane=request["lane"],
                executor=request["executor"],
            )
            del rendered
            return _invariant_outcome(decision="allow", reason="rendered_safe_stack", passed=True)
        if request["action"] == "unique":
            first = render_stack(request["stack_id"], instance=request["instance"], lane="no-provider", executor="podman")
            second = render_stack(request["stack_id"], instance=request["other_instance"], lane="no-provider", executor="podman")
            unique = len({first.project, second.project, first.network, second.network, first.volume, second.volume}) == 6
            require(unique, "generated stack names are not unique")
            return _invariant_outcome(decision="allow", reason="unique_generated_names", passed=True)
        if request["action"] == "teardown":
            expected = _project_name("smoke", "one")
            validate_teardown_target(expected, request["teardown_target"])
            return _invariant_outcome(decision="allow", reason="teardown_target_recognized", passed=True)
    except ValidationError:
        if case["id"] == "reject-stack-path-traversal":
            return _invariant_outcome(decision="deny", reason="unsafe_stack_id", passed=False)
        if case["id"] == "reject-stack-uppercase":
            return _invariant_outcome(decision="deny", reason="unsafe_stack_id", passed=False)
        if case["id"] == "reject-instance-path-traversal":
            return _invariant_outcome(decision="deny", reason="unsafe_instance", passed=False)
        if case["id"] == "reject-unknown-lane":
            return _invariant_outcome(decision="deny", reason="unknown_lane", passed=False)
        if case["id"] == "reject-unknown-executor":
            return _invariant_outcome(decision="deny", reason="unknown_executor", passed=False)
        if case["id"] == "reject-unrecognized-teardown":
            return _invariant_outcome(decision="deny", reason="unrecognized_teardown", passed=False)
        raise
    raise ValidationError("case action is not supported")


def validate_cases_document(document: Any) -> None:
    root = _validate_root(document)
    cases = root["cases"]
    require(type(cases) is list and len(cases) == len(EXPECTED_CASE_IDS), "case inventory changed")
    for index, case in enumerate(cases):
        row = _validate_case_shape(case, index)
        strict_equal(evaluate_case(row), row["expected"], "case outcome")


def _read_artifact(root: Path, relative: str) -> bytes:
    try:
        return (root / relative).read_bytes()
    except OSError as exc:
        raise ValidationError("benchmark artifact is unavailable") from exc


def _validator_source_digest(root: Path = ROOT) -> str:
    try:
        source = (root / "validate.py").read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValidationError("validator identity is unavailable") from exc
    canonical, replacements = VALIDATOR_IDENTITY_RE.subn('PINNED_VALIDATOR_SOURCE_SHA256 = "<code-pinned>"', source)
    require(replacements == 1, "validator identity marker changed")
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _validate_pinned_artifacts(root: Path = ROOT) -> None:
    for relative, (expected_bytes, expected_digest) in PINNED_RETAINED_ARTIFACTS.items():
        data = _read_artifact(root, relative)
        require(len(data) == expected_bytes, f"pinned artifact size changed: {relative}")
        require(hashlib.sha256(data).hexdigest() == expected_digest, f"pinned artifact digest changed: {relative}")
    require(_validator_source_digest(root) == PINNED_VALIDATOR_SOURCE_SHA256, "pinned validator identity changed")


def _canonical_baseline_evidence_bytes(baseline: dict[str, Any]) -> bytes:
    evidence = {key: baseline[key] for key in BASELINE_EVIDENCE_KEYS}
    return json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _artifact_digest(root: Path = ROOT) -> tuple[int, str]:
    digest = hashlib.sha256()
    total = 0
    for relative in ARTIFACT_FILES:
        data = _read_artifact(root, relative)
        total += len(data)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return total, digest.hexdigest()


def _finite_number(value: Any, label: str) -> float:
    require(type(value) in {int, float} and type(value) is not bool, f"{label} must be numeric")
    try:
        result = float(value)
    except (OverflowError, ValueError) as exc:
        raise ValidationError(compact_error(f"{label} is outside the bounded numeric range")) from exc
    require(math.isfinite(result) and result >= 0, f"{label} must be finite and non-negative")
    return result


def _round_milliseconds(value: float) -> float:
    return float(f"{value:.3f}")


def _percentile(values: list[float], percentage: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentage / 100
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return _round_milliseconds(ordered[lower])
    return _round_milliseconds(ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower))


def _expected_distribution(values: list[float]) -> dict[str, float]:
    return {
        "min_ms": _round_milliseconds(min(values)),
        "p50_ms": _percentile(values, 50),
        "p95_ms": _percentile(values, 95),
        "p99_ms": _percentile(values, 99),
        "max_ms": _round_milliseconds(max(values)),
        "mean_ms": _round_milliseconds(sum(values) / len(values)),
    }


def _canonical_baseline_bytes(baseline: dict[str, Any]) -> bytes:
    return json.dumps(baseline, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _validate_baseline_anchor(baseline: dict[str, Any], anchor_path: Path) -> None:
    try:
        anchor = anchor_path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise ValidationError("baseline anchor is unavailable") from exc
    require(HEX64_RE.fullmatch(anchor) is not None, "baseline anchor is malformed")
    require(anchor == hashlib.sha256(_canonical_baseline_bytes(baseline)).hexdigest(), "baseline canonical digest changed")


def validate_baseline(baseline: Any, root: Path = ROOT, anchor_path: Path = BASELINE_ANCHOR_PATH) -> None:
    record = strict_keys(baseline, BASELINE_ROOT_KEYS, "baseline")
    require(record["schema"] == BASELINE_SCHEMA, "baseline schema changed")
    require(record["validator"] == BASELINE_COMMANDS["normal"].replace("python3 ", ""), "baseline validator path changed")
    require(record["fixture"] == "tests/integration/hermes-disposable/cases.json", "baseline fixture path changed")
    require(record["metric"] == "validator_duration_ms", "baseline metric changed")
    environment = strict_keys(record["environment"], BASELINE_ENVIRONMENT_KEYS, "baseline.environment")
    _text(environment["platform"], "baseline environment platform", max_length=160)
    _text(environment["python"], "baseline environment python", max_length=64)
    runs = record["runs"]
    require(type(runs) is list and len(runs) == 2, "baseline must contain normal and optimized runs")
    seen_modes: set[str] = set()
    for index, item in enumerate(runs):
        run = strict_keys(item, BASELINE_RUN_KEYS, f"baseline run {index}")
        mode = _enum(run["mode"], frozenset({"normal", "optimized"}), "baseline mode")
        require(mode not in seen_modes, "baseline run mode is duplicated")
        seen_modes.add(mode)
        require(run["command"] == BASELINE_COMMANDS[mode], "baseline command is not approved")
        require(_int(run["repetitions"], "baseline repetitions") == BASELINE_REPETITIONS, "baseline repetitions must be 30")
        distribution = strict_keys(run["distribution"], BASELINE_DISTRIBUTION_KEYS, "baseline distribution")
        trace = run["trace"]
        require(type(trace) is list and len(trace) == BASELINE_REPETITIONS, "baseline trace must contain 30 samples")
        values = [_finite_number(value, "baseline trace sample") for value in trace]
        require(all(value > 0 for value in values), "baseline trace must be positive")
        expected = _expected_distribution(values)
        for key in BASELINE_DISTRIBUTION_KEYS:
            require(_finite_number(distribution[key], "baseline distribution value") == expected[key], "baseline distribution does not match trace")
        require(distribution["min_ms"] <= distribution["p50_ms"] <= distribution["p95_ms"] <= distribution["p99_ms"] <= distribution["max_ms"], "baseline distribution order changed")
    require(seen_modes == {"normal", "optimized"}, "baseline modes are incomplete")
    require(hashlib.sha256(_canonical_baseline_evidence_bytes(record)).hexdigest() == PINNED_BASELINE_EVIDENCE_SHA256, "baseline evidence digest changed")
    _validate_pinned_artifacts(root)
    artifact = strict_keys(record["artifact"], BASELINE_ARTIFACT_KEYS, "baseline artifact")
    require(type(artifact["files"]) is list and tuple(artifact["files"]) == ARTIFACT_FILES, "baseline artifact files changed")
    require(type(artifact["bytes"]) is int and type(artifact["bytes"]) is not bool and artifact["bytes"] > 0, "baseline artifact bytes invalid")
    require(type(artifact["sha256"]) is str and HEX64_RE.fullmatch(artifact["sha256"]) is not None, "baseline artifact digest invalid")
    actual_bytes, actual_digest = _artifact_digest(root)
    require(artifact["bytes"] == actual_bytes and artifact["sha256"] == actual_digest, "baseline artifact digest changed")
    require(record["threshold"] is None, "baseline must not invent a threshold")
    _validate_baseline_anchor(baseline, anchor_path)


def validate_all(*, cases_path: Path = CASES_PATH, baseline_path: Path = BASELINE_PATH, anchor_path: Path = BASELINE_ANCHOR_PATH, root: Path = ROOT) -> tuple[int, int]:
    document = load_json(cases_path)
    validate_redaction(document)
    validate_cases_document(document)
    baseline = load_json(baseline_path)
    validate_redaction(baseline, allow_benchmark_paths=True)
    validate_baseline(baseline, root, anchor_path)
    return len(document["cases"]), baseline["artifact"]["bytes"]


def _success_payload(case_count: int, artifact_bytes: int, *, rendered: RenderedStack | None = None) -> str:
    payload: dict[str, Any] = {
        "ok": True,
        "schema": SCHEMA,
        "operation": OPERATION,
        "case_count": case_count,
        "artifact_bytes": artifact_bytes,
        "compatible": False,
        "live_run": False,
        "threshold": None,
    }
    if rendered is not None:
        payload["rendered"] = rendered.public_metadata()
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def _failure_payload(error: object) -> str:
    return json.dumps(
        {
            "ok": False,
            "compatible": False,
            "live_run": False,
            "error": {"code": ERROR_CODE, "message": compact_error(error)},
        },
        separators=(",", ":"),
        sort_keys=True,
    )


class ControlledArgumentParser(argparse.ArgumentParser):
    """Keep argparse failures inside the bounded JSON error contract."""

    def error(self, message: str) -> None:
        del message
        raise ValidationError("invalid command-line arguments")

    def exit(self, status: int = 0, message: str | None = None) -> None:
        del message
        if status:
            raise ValidationError("invalid command-line arguments")
        raise ValidationError("command-line help is not part of the validator output contract")


def main(argv: list[str] | None = None) -> int:
    """Validate policy, optionally render one stack, and emit one JSON line."""

    try:
        parser = ControlledArgumentParser(add_help=False)
        parser.add_argument("--cases", type=Path, default=CASES_PATH)
        parser.add_argument("--baseline", type=Path, default=BASELINE_PATH)
        parser.add_argument("--baseline-anchor", type=Path, default=BASELINE_ANCHOR_PATH)
        parser.add_argument("--skip-baseline", action="store_true")
        parser.add_argument("--render", type=Path)
        parser.add_argument("--stack-id", default="fixture")
        parser.add_argument("--instance", default="one")
        parser.add_argument("--lane", default="no-provider")
        parser.add_argument("--executor", default="podman")
        args = parser.parse_args(argv)
        document = load_json(args.cases)
        validate_redaction(document)
        validate_cases_document(document)
        if args.skip_baseline:
            case_count = len(document["cases"])
            artifact_bytes = 0
        else:
            baseline = load_json(args.baseline)
            validate_redaction(baseline, allow_benchmark_paths=True)
            validate_baseline(baseline, ROOT, args.baseline_anchor)
            case_count = len(document["cases"])
            artifact_bytes = baseline["artifact"]["bytes"]
        rendered = None
        if args.render is not None:
            rendered = render_stack(args.stack_id, instance=args.instance, lane=args.lane, executor=args.executor)
            try:
                args.render.parent.mkdir(parents=True, exist_ok=True)
                args.render.write_text(rendered.compose, encoding="utf-8")
            except OSError as exc:
                raise ValidationError("render output is unavailable") from exc
        sys.stdout.write(_success_payload(case_count, artifact_bytes, rendered=rendered) + "\n")
        return 0
    except (Exception, SystemExit) as exc:
        sys.stdout.write(_failure_payload(exc) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
