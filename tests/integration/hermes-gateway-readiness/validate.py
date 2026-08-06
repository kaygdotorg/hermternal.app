#!/usr/bin/env python3
"""Validate and run the isolated rootless-Podman Hermes gateway probe.

The default command is an offline contract check.  The live runner is an
explicit opt-in and is intentionally blocked while issue #250's reviewed
minimal capability policy is pending.  It uses only ``podman compose`` with a
project-derived network and volume, never a shell, host ports, a provider, a
browser, a PTY, or a retained raw log.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


ROOT = Path(__file__).resolve().parent
CASES_PATH = ROOT / "cases.json"
EVIDENCE_PATH = ROOT / "evidence.json"
SCHEMA = "hermternal.integration.hermes-gateway-readiness.v1"
EVIDENCE_SCHEMA = "hermternal.integration.hermes-gateway-readiness.evidence.v1"
OPERATION = "R-02C"
CONTRACT = "hermes-gateway-readiness-v1"
PINNED_HERMES_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
PINNED_HERMES_TREE = "886db5eb1150f819344d67fedc81aef0caab09ff"
PINNED_DOCKERFILE_SHA256 = "a11fc9fc39eadcaffd99377d831b5ec2458f1e09a5f5d5312fd8adcec362b7fc"
IMAGE_REPOSITORY = "hermes-agent"
IMAGE_TAG = "hermternal-f5be9236"
IMAGE_REFERENCE = f"{IMAGE_REPOSITORY}:{IMAGE_TAG}"
IMAGE_SOURCE_LABEL = "org.opencontainers.image.source"
IMAGE_REVISION_LABEL = "org.opencontainers.image.revision"
IMAGE_DOCKERFILE_LABEL = "com.hermternal.dockerfile.sha256"
IMAGE_SOURCE_URL = "https://github.com/NousResearch/hermes-agent"
EXECUTOR = "podman"
COMPOSE = "compose"
ROOTLESS_ACCOUNT = "hermternal-test"
SSH_TARGET = f"{ROOTLESS_ACCOUNT}@hermternal-dev"
PROJECT_PREFIX = "hermes-gateway-readiness"
PROBE_COMMAND = ("gateway", "run", "--no-supervise")
READINESS_PREFIX = "HERMES_BACKEND_READY port="
READINESS_RE = re.compile(r"^HERMES_BACKEND_READY port=(?P<port>[1-9][0-9]{0,4})$")
HEX40_RE = re.compile(r"[0-9a-f]{40}")
HEX64_RE = re.compile(r"[0-9a-f]{64}")
IMAGE_ID_RE = re.compile(r"(?:sha256:)?[0-9a-f]{64}")
STACK_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,23}")
INSTANCE_RE = re.compile(r"[a-z][a-z0-9-]{0,23}")
PROJECT_RE = re.compile(rf"{PROJECT_PREFIX}-[a-z][a-z0-9-]{{0,23}}-[0-9a-f]{{8}}")
MAX_JSON_BYTES = 512 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_INTEGER_DIGITS = 1024
MAX_JSON_NODES = 4096
MAX_OBJECT_KEYS = 96
MAX_ARRAY_LENGTH = 512
MAX_STRING_LENGTH = 8192
MAX_ERROR_OUTPUT = 240
MAX_COMMAND_OUTPUT = 64 * 1024
MAX_LOG_BYTES = 32 * 1024
MAX_LOG_LINES = 128
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_POLL_INTERVAL_SECONDS = 0.25
ERROR_CODE = "hermes_gateway_readiness_validation_error"
PROBE_ERROR_CODE = "hermes_gateway_readiness_probe_blocked"

# This remains pending until #250 records the smallest source-reviewed policy.
# Keeping the policy explicit prevents an operator from silently adding a broad
# capability merely to make a readiness probe pass.
CAPABILITY_POLICY = {
    "status": "awaiting_issue_250",
    "cap_drop": ["ALL"],
    "cap_add": [],
    "no_new_privileges": True,
    "dependency": "issue_250_review",
}

EXPECTED_EXECUTOR_POLICY = {
    "name": "rootless_podman",
    "account": ROOTLESS_ACCOUNT,
    "ssh_target": SSH_TARGET,
    "rootless": True,
    "compose_command": "podman compose",
    "cgroup": "v2",
    "network_backend": "netavark",
    "storage_driver": "overlay",
    "correctness_executor": True,
    "docker_comparison": "not_a_substitute",
}

EXPECTED_PROBE_POLICY = {
    "service_name": "gateway",
    "command": list(PROBE_COMMAND),
    "readiness_prefix": READINESS_PREFIX,
    "readiness_stream": "stdout",
    "port_min": 1,
    "port_max": 65535,
    "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
    "poll_interval_seconds": DEFAULT_POLL_INTERVAL_SECONDS,
    "restart": "no",
    "log_driver": "k8s-file",
    "log_max_size": "1m",
    "log_max_files": None,
}

EXPECTED_RESOURCES = {
    "cpu_limit": "0.50",
    "memory_limit": "512m",
    "pid_limit": 256,
    "tmpfs": ["/tmp:size=64m,mode=1777", "/run:size=16m,mode=755"],
    "shm_size": "64m",
}

EXPECTED_ISOLATION_POLICY = {
    "project_prefix": PROJECT_PREFIX,
    "internal_network": True,
    "named_volume": True,
    "published_ports": False,
    "host_network": False,
    "host_profile_bind": False,
    "socket_mount": False,
    "pty": False,
    "provider": "none",
    "browser_auth": False,
    "model_turn": False,
    "resources": EXPECTED_RESOURCES,
    "teardown": ["down", "--volumes", "--remove-orphans"],
}

ROOT_KEYS = (
    "schema",
    "operation",
    "contract",
    "synthetic_only",
    "network_access",
    "live_run",
    "proof_status",
    "pinned_identity",
    "executor_policy",
    "capability_policy",
    "probe_policy",
    "isolation_policy",
    "cases",
)
IDENTITY_KEYS = (
    "repository",
    "source_commit",
    "source_tree",
    "dockerfile_sha256",
    "image_reference",
)
CASE_KEYS = ("id", "kind", "input", "expected", "notes")
EVIDENCE_KEYS = (
    "schema",
    "operation",
    "synthetic_only",
    "live_run",
    "status",
    "correctness_executor",
    "ssh_target",
    "pinned_identity",
    "command_candidate",
    "command_support",
    "readiness_marker",
    "readiness_source_status",
    "capability_policy",
    "observations",
    "limitations",
)
EVIDENCE_OBSERVATION_KEYS = (
    "compose_config",
    "container_start",
    "readiness",
    "exit",
    "teardown",
    "leftover_resources",
)

EXPECTED_CASE_IDS = (
    "readiness-marker-accepted",
    "readiness-marker-rejects-prefix",
    "readiness-marker-rejects-invalid-port",
    "readiness-conflicting-markers",
    "classify-timeout",
    "classify-exit-126",
    "classify-exit-2",
    "classify-signal",
    "redaction-symbolic-diagnostic",
    "identity-exact",
    "identity-drift-rejected",
    "isolation-rendered",
    "isolation-published-port-rejected",
    "capability-policy-pending",
    "cleanup-canonical-project",
    "cleanup-unrecognized-project",
    "cleanup-zero-leftovers",
    "cleanup-leftover-detected",
)

# Keep the adversarial payloads independent from cases.json.  Otherwise a
# weakened input and matching expected value could make the inventory pass.
PINNED_CASE_CONTRACTS: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {
    "readiness-marker-accepted": (
        {"text": "HERMES_BACKEND_READY port=9119"},
        {"accepted": True, "port": 9119},
    ),
    "readiness-marker-rejects-prefix": (
        {"text": "INFO HERMES_BACKEND_READY port=9119"},
        {"accepted": False, "port": None},
    ),
    "readiness-marker-rejects-invalid-port": (
        {"text": "HERMES_BACKEND_READY port=65536"},
        {"accepted": False, "port": None},
    ),
    "readiness-conflicting-markers": (
        {"text": "HERMES_BACKEND_READY port=9119 HERMES_BACKEND_READY port=9119"},
        {"accepted": False, "port": None},
    ),
    "classify-timeout": (
        {"readiness_port": None, "returncode": None, "timed_out": True},
        {"status": "blocked", "classification": "timeout_waiting_for_readiness"},
    ),
    "classify-exit-126": (
        {"readiness_port": None, "returncode": 126, "timed_out": False},
        {"status": "blocked", "classification": "exit_126_before_ready"},
    ),
    "classify-exit-2": (
        {"readiness_port": None, "returncode": 2, "timed_out": False},
        {"status": "blocked", "classification": "exit_2_before_ready"},
    ),
    "classify-signal": (
        {"readiness_port": None, "returncode": -9, "timed_out": False},
        {"status": "blocked", "classification": "signal_9_before_ready"},
    ),
    "redaction-symbolic-diagnostic": (
        {"fixture_id": "synthetic_diagnostic"},
        {"marker": "[REDACTED]", "bounded": True},
    ),
    "identity-exact": (
        {
            "repository": "NousResearch/hermes-agent",
            "source_commit": "f5be9236e00ddf2f2a412697f267078fc4ee068e",
            "source_tree": "886db5eb1150f819344d67fedc81aef0caab09ff",
            "dockerfile_sha256": "a11fc9fc39eadcaffd99377d831b5ec2458f1e09a5f5d5312fd8adcec362b7fc",
            "image_reference": "hermes-agent:hermternal-f5be9236",
        },
        {"accepted": True, "reason": "pinned_identity"},
    ),
    "identity-drift-rejected": (
        {
            "repository": "NousResearch/hermes-agent",
            "source_commit": "0000000000000000000000000000000000000000",
            "source_tree": "886db5eb1150f819344d67fedc81aef0caab09ff",
            "dockerfile_sha256": "a11fc9fc39eadcaffd99377d831b5ec2458f1e09a5f5d5312fd8adcec362b7fc",
            "image_reference": "hermes-agent:hermternal-f5be9236",
        },
        {"accepted": False, "reason": "pinned_identity_mismatch"},
    ),
    "isolation-rendered": (
        {"mutation": "none"},
        {"accepted": True, "reason": "rootless_private_project"},
    ),
    "isolation-published-port-rejected": (
        {"mutation": "published_port"},
        {"accepted": False, "reason": "published_port_rejected"},
    ),
    "capability-policy-pending": (
        {"policy": "checked_in"},
        {"status": "awaiting_issue_250", "live_allowed": False},
    ),
    "cleanup-canonical-project": (
        {"target": "canonical"},
        {"accepted": True, "reason": "exact_project_only"},
    ),
    "cleanup-unrecognized-project": (
        {"target": "other_project"},
        {"accepted": False, "reason": "unrecognized_project"},
    ),
    "cleanup-zero-leftovers": (
        {"leftovers": {"containers": 0, "networks": 0, "volumes": 0}},
        {"zero": True},
    ),
    "cleanup-leftover-detected": (
        {"leftovers": {"containers": 0, "networks": 0, "volumes": 1}},
        {"zero": False},
    ),
}

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
        "xaccesskey",
        "xapikey",
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
    r"user[_ .-]*data|file(?:name|path)|"
    r"(?:x[_ .-]*)?(?:api|access)[_ .-]*key)\s*[:=]\s*)"
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
IPV6_RE = re.compile(
    r"(?<![A-Za-z0-9])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?![A-Za-z0-9])",
    re.IGNORECASE,
)
ABSOLUTE_PATH_RE = re.compile(r"(?<![A-Za-z0-9])(?:/[^\s,}\]]+|[A-Za-z]:[\\/][^\s,}\]]+)")
FILENAME_RE = re.compile(
    r"(?<![A-Za-z0-9])[A-Za-z0-9_.-]+\.(?:json|ya?ml|txt|py|log|env|pem|key)(?![A-Za-z0-9])",
    re.IGNORECASE,
)
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=_])(?:[A-Za-z0-9+/]{20,}={0,2})(?![A-Za-z0-9+/=_-])")
SECRET_VALUE_PATTERNS = (
    DATA_URL_RE,
    URL_RE,
    re.compile(r"\b(?:Bearer|Basic)\s+[^\s,}\]]+", re.IGNORECASE),
    re.compile(r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----", re.IGNORECASE),
    IPV4_RE,
    IPV6_RE,
    HOSTNAME_RE,
    ABSOLUTE_PATH_RE,
    FILENAME_RE,
    BASE64_RE,
)
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

# The raw value exists only in this test-side symbolic model.  It is never
# placed in cases.json or returned by the live runner.
_SYNTHETIC_DIAGNOSTIC = (
    "authorization=Bearer SYNTHETIC_TOKEN_1234567890 "
    "password=SYNTHETIC_PASSWORD https://synthetic.invalid/private.log"
)


class FixtureJSONError(ValueError):
    """Raised for malformed, oversized, or unsafe fixture JSON."""


class ValidationError(ValueError):
    """Raised when the frozen readiness contract is violated."""


class ProbeError(RuntimeError):
    """Raised when the explicitly requested runner cannot execute safely."""


@dataclass(frozen=True)
class CommandResult:
    """A bounded executor result; raw output is never retained in evidence."""

    returncode: int | None
    output: str
    timed_out: bool = False
    stderr: str = ""


@dataclass(frozen=True)
class RenderedProbe:
    """Canonical Compose text and names for one isolated rootless project."""

    project: str
    network: str
    volume: str
    stack_id: str
    instance: str
    compose: str

    def public_metadata(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "network": self.network,
            "volume": self.volume,
            "executor": EXECUTOR,
            "ssh_target": SSH_TARGET,
            "service": "gateway",
            "command": list(PROBE_COMMAND),
        }


@dataclass(frozen=True)
class ProbeResult:
    """Bounded public outcome from one live or synthetic command sequence."""

    status: str
    classification: str
    readiness_port: int | None
    exit_code: int | None
    timed_out: bool
    teardown_exit_code: int | None
    leftovers: dict[str, int]
    diagnostic: str

    def public(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "classification": self.classification,
            "readiness_port": self.readiness_port,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "teardown_exit_code": self.teardown_exit_code,
            "leftovers": dict(self.leftovers),
            "diagnostic": self.diagnostic,
            "redacted": True,
        }


def compact_error(message: object) -> str:
    """Redact untrusted diagnostics before applying the fixed output cap."""

    redacted = str(message)
    for pattern in SECRET_VALUE_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)

    def redact_assignment(match: re.Match[str]) -> str:
        return f"{match.group('key')}[REDACTED]"

    redacted = SENSITIVE_ASSIGNMENT_RE.sub(redact_assignment, redacted)
    redacted = re.sub(
        r"(?:attacker|secret|credential)[^\s,}\]]*",
        "[REDACTED]",
        redacted,
        flags=re.IGNORECASE,
    )
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

    if depth > MAX_JSON_DEPTH:
        raise FixtureJSONError("JSON depth exceeds the bounded limit")
    if type(value) is dict:
        if len(value) > MAX_OBJECT_KEYS:
            raise FixtureJSONError("JSON object has too many keys")
        nodes = 1
        for key, child in value.items():
            if type(key) is not str:
                raise FixtureJSONError("JSON object key must be text")
            if len(key) > MAX_STRING_LENGTH:
                raise FixtureJSONError("JSON object key is too long")
            nodes += validate_json_tree(child, depth + 1)
            if nodes > MAX_JSON_NODES:
                raise FixtureJSONError("JSON node count exceeds the bounded limit")
        return nodes
    if type(value) is list:
        if len(value) > MAX_ARRAY_LENGTH:
            raise FixtureJSONError("JSON array is too long")
        nodes = 1
        for child in value:
            nodes += validate_json_tree(child, depth + 1)
            if nodes > MAX_JSON_NODES:
                raise FixtureJSONError("JSON node count exceeds the bounded limit")
        return nodes
    if type(value) is str:
        if len(value) > MAX_STRING_LENGTH:
            raise FixtureJSONError("JSON string is too long")
        if CONTROL_RE.search(value) is not None:
            raise FixtureJSONError("JSON control character is not allowed")
        return 1
    if type(value) is float:
        if not math.isfinite(value):
            raise FixtureJSONError("JSON number is not finite")
        return 1
    if value is None or type(value) in {bool, int}:
        return 1
    raise FixtureJSONError("unsupported JSON value type")


def load_json_text(data: bytes | str, *, label: str = "fixture") -> Any:
    """Decode one bounded UTF-8 JSON document with strict parser hooks."""

    raw = data.encode("utf-8") if isinstance(data, str) else data
    if len(raw) > MAX_JSON_BYTES:
        raise FixtureJSONError(f"{label} JSON exceeds the input byte limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FixtureJSONError(f"{label} JSON is not UTF-8") from exc
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
        raise FixtureJSONError(f"{label} JSON is malformed") from exc
    validate_json_tree(value)
    return value


def load_json(path: Path) -> Any:
    """Read one bounded JSON fixture without echoing its path on failure."""

    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_JSON_BYTES + 1)
    except OSError as exc:
        raise FixtureJSONError("fixture file is unavailable") from exc
    return load_json_text(data, label="fixture")


def _normalize_sensitive_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", key.casefold())


ALLOWED_CONTAINER_PATHS = frozenset({"/opt/data"})
ALLOWED_CONTAINER_PATH_PREFIXES = ("/tmp:size=", "/run:size=")


def _walk_redaction(value: Any) -> None:
    if type(value) is dict:
        for key, child in value.items():
            require(type(key) is str, "redaction object key must be text")
            require(
                _normalize_sensitive_key(key) not in SENSITIVE_NORMALIZED_KEYS,
                "sensitive fixture field is not allowed",
            )
            _walk_redaction(child)
        return
    if type(value) is list:
        for child in value:
            _walk_redaction(child)
        return
    if type(value) is str:
        if HEX40_RE.fullmatch(value) or HEX64_RE.fullmatch(value):
            return
        if value in ALLOWED_CONTAINER_PATHS or value.startswith(ALLOWED_CONTAINER_PATH_PREFIXES):
            return
        for pattern in SECRET_VALUE_PATTERNS:
            require(pattern.search(value) is None, "secret-shaped fixture value is not allowed")
        require(
            SENSITIVE_ASSIGNMENT_RE.search(value) is None,
            "credential-shaped fixture value is not allowed",
        )


def validate_redaction(value: Any) -> None:
    """Reject retained credentials, hosts, URLs, paths, and user-data shapes."""

    _walk_redaction(value)


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


def _number(value: Any, label: str) -> float:
    require(type(value) in {int, float} and type(value) is not bool, f"{label} must be numeric")
    result = float(value)
    require(math.isfinite(result), f"{label} must be finite")
    return result


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


def project_name(stack_id: str, instance: str) -> str:
    """Derive a unique, inspectable project name without host or user data."""

    stack_id = _slug(stack_id, STACK_ID_RE, "stack id")
    _slug(instance, INSTANCE_RE, "stack instance")
    # The random suffix prevents concurrent runs from sharing a network or
    # volume.  The readable stack prefix still makes exact-project teardown
    # reviewable without retaining host or user data.
    suffix = secrets.token_hex(4)
    require(re.fullmatch(r"[0-9a-f]{8}", suffix) is not None, "project nonce is invalid")
    return f"{PROJECT_PREFIX}-{stack_id}-{suffix}"


def _yaml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def validate_capability_policy(policy: Mapping[str, Any]) -> None:
    """Allow only the pending or later reviewed minimal policy, never a broad set."""

    keys = ("status", "cap_drop", "cap_add", "no_new_privileges", "dependency")
    value = strict_keys(dict(policy), keys, "capability policy")
    _enum(value["status"], frozenset({"awaiting_issue_250", "approved"}), "capability status")
    require(value["cap_drop"] == ["ALL"], "capability drop policy must remain ALL")
    require(type(value["cap_add"]) is list, "capability add policy must be a list")
    require(value["cap_add"] == [], "capability additions require the reviewed issue 250 policy")
    _bool(value["no_new_privileges"], "no-new-privileges policy")
    require(value["no_new_privileges"], "no-new-privileges must remain enabled")
    require(value["dependency"] == "issue_250_review", "capability policy dependency changed")


def _canonical_compose(project: str, network: str, volume: str) -> str:
    """Render the sole accepted Compose document for the probe policy."""

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
        '      HERMES_HOME: "/opt/data"',
        '      HERMES_UID: "10000"',
        '      HERMES_GID: "10000"',
        '      HERMES_DISABLE_LAZY_INSTALLS: "1"',
        '      HERMES_DASHBOARD: "0"',
        '      HERMES_PROVIDER_AUTO_DISCOVERY: "0"',
        "    volumes:",
        '      - "data:/opt/data"',
        "    networks:",
        "      - internal",
        '    tty: false',
        '    stdin_open: false',
        f'    tmpfs:\n      - "{EXPECTED_RESOURCES["tmpfs"][0]}"\n      - "{EXPECTED_RESOURCES["tmpfs"][1]}"',
        f'    shm_size: "{EXPECTED_RESOURCES["shm_size"]}"',
        f'    cpus: "{EXPECTED_RESOURCES["cpu_limit"]}"',
        f'    mem_limit: "{EXPECTED_RESOURCES["memory_limit"]}"',
        f"    pids_limit: {EXPECTED_RESOURCES['pid_limit']}",
        "    logging:",
        '      driver: "k8s-file"',
        "      options:",
        f'        max-size: "{EXPECTED_PROBE_POLICY["log_max_size"]}"',
        f'    command: ["{PROBE_COMMAND[0]}", "{PROBE_COMMAND[1]}", "{PROBE_COMMAND[2]}"]',
        "networks:",
        "  internal:",
        f'    name: "{network}"',
        "    internal: true",
        "volumes:",
        "  data:",
        f'    name: "{volume}"',
    ]
    return "\n".join(lines) + "\n"


def render_probe(
    stack_id: str,
    *,
    instance: str = "fixture",
    capability_policy: Mapping[str, Any] | None = None,
) -> RenderedProbe:
    """Render the canonical rootless Podman no-provider gateway Compose policy."""

    policy = dict(CAPABILITY_POLICY if capability_policy is None else capability_policy)
    validate_capability_policy(policy)
    stack_id = _slug(stack_id, STACK_ID_RE, "stack id")
    instance = _slug(instance, INSTANCE_RE, "stack instance")
    project = project_name(stack_id, instance)
    network = f"{project}_internal"
    volume = f"{project}_data"
    compose = _canonical_compose(project, network, volume)
    result = RenderedProbe(project, network, volume, stack_id, instance, compose)
    validate_rendered_probe(result)
    return result


def validate_rendered_probe(result: RenderedProbe) -> None:
    """Check every no-exposure and rootless resource invariant in the render."""

    require(PROJECT_RE.fullmatch(result.project) is not None, "project name is not canonical")
    stack_id = _slug(result.stack_id, STACK_ID_RE, "stack id")
    _slug(result.instance, INSTANCE_RE, "stack instance")
    require(
        result.project.startswith(f"{PROJECT_PREFIX}-{stack_id}-"),
        "project name is not bound to the stack id",
    )
    require(result.network == f"{result.project}_internal", "network name is not canonical")
    require(result.volume == f"{result.project}_data", "volume name is not canonical")
    text = result.compose
    # Validate the complete document, not merely required substrings.  This
    # rejects appended duplicate keys and any new volume, capability, PTY, or
    # resource field that could otherwise override an earlier safe value.
    require(
        text == _canonical_compose(result.project, result.network, result.volume),
        "Compose document is not the canonical policy",
    )
    require(len(text.encode("utf-8")) <= MAX_JSON_BYTES, "rendered Compose exceeds the bounded size")
    require("${" not in text, "host environment interpolation is not allowed")
    for forbidden in (
        "container_name",
        "network_mode",
        "privileged:",
        "entrypoint:",
        "    init:",
        "    user:",
        "docker.sock",
        "~/.hermes",
        "ports:",
    ):
        require(forbidden not in text, f"unsafe Compose field is present: {forbidden}")
    require('    image: "hermes-agent:hermternal-f5be9236"' in text, "image reference changed")
    require('    restart: "no"' in text, "restart policy must be no")
    require('      - "ALL"' in text, "all capabilities must be dropped")
    require('      - "no-new-privileges:true"' in text, "no-new-privileges is required")
    require('      HERMES_PROVIDER_AUTO_DISCOVERY: "0"' in text, "provider discovery must be disabled")
    require("HERMES_PROVIDER:" not in text, "provider configuration is not allowed")
    require("API_SERVER_KEY" not in text, "API server credentials are not allowed")
    require("BASIC_AUTH" not in text and "OAUTH" not in text, "browser auth is not allowed")
    require('      - "data:/opt/data"' in text, "data must use the named volume key")
    require(f'    name: "{result.network}"' in text, "network name is not unique")
    require(f'    name: "{result.volume}"' in text, "volume name is not unique")
    require("    internal: true" in text, "network must be internal")
    require('    tty: false' in text and '    stdin_open: false' in text, "PTY access is not allowed")
    require('    cpus: "0.50"' in text, "CPU limit changed")
    require('    mem_limit: "512m"' in text, "memory limit changed")
    require("    pids_limit: 256" in text, "PID limit changed")
    require('    shm_size: "64m"' in text, "shared-memory limit changed")
    require('        max-size: "1m"' in text, "log bound changed")
    require('      driver: "k8s-file"' in text, "rootless Podman log driver changed")
    require(
        '    command: ["gateway", "run", "--no-supervise"]' in text,
        "gateway run command changed",
    )


def validate_pinned_identity(identity: Mapping[str, Any]) -> None:
    """Require the full source/tree/Dockerfile/image binding, not abbreviations."""

    record = strict_keys(dict(identity), IDENTITY_KEYS, "pinned identity")
    require(record["repository"] == "NousResearch/hermes-agent", "Hermes repository changed")
    require(record["source_commit"] == PINNED_HERMES_SHA, "Hermes source commit changed")
    require(record["source_tree"] == PINNED_HERMES_TREE, "Hermes source tree changed")
    require(record["dockerfile_sha256"] == PINNED_DOCKERFILE_SHA256, "Dockerfile identity changed")
    require(record["image_reference"] == IMAGE_REFERENCE, "image reference changed")
    require(HEX40_RE.fullmatch(record["source_commit"]) is not None, "source commit is not a full SHA")
    require(HEX40_RE.fullmatch(record["source_tree"]) is not None, "source tree is not a full SHA")
    require(HEX64_RE.fullmatch(record["dockerfile_sha256"]) is not None, "Dockerfile digest is invalid")


def validate_image_binding(record: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a bounded Podman inspect record without retaining host details."""

    tags = record.get("RepoTags", record.get("repo_tags", record.get("Names", [])))
    require(type(tags) is list, "image tags are not a list")
    require(IMAGE_REFERENCE in tags, "image tag is not pinned")
    image_id = record.get("Id", record.get("id"))
    require(type(image_id) is str and IMAGE_ID_RE.fullmatch(image_id) is not None, "image id is invalid")
    digests = record.get("RepoDigests", record.get("repo_digests", []))
    require(type(digests) is list and digests, "image digest binding is missing")
    for digest in digests:
        require(type(digest) is str and re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", digest) is not None, "image digest is invalid")
    canonical_digest_prefix = f"{IMAGE_REPOSITORY}@sha256:"
    canonical_digests = [digest for digest in digests if digest.startswith(canonical_digest_prefix)]
    require(len(canonical_digests) == 1, "image digest repository is not pinned")

    config = record.get("Config", {})
    require(type(config) is dict, "image config is not an object")
    labels = config.get("Labels", record.get("labels"))
    require(type(labels) is dict, "image labels are not an object")
    require(labels.get(IMAGE_SOURCE_LABEL) == IMAGE_SOURCE_URL, "image source label is not pinned")
    require(labels.get(IMAGE_REVISION_LABEL) == PINNED_HERMES_SHA, "image source revision label is not pinned")
    require(labels.get(IMAGE_DOCKERFILE_LABEL) == PINNED_DOCKERFILE_SHA256, "image Dockerfile label is not pinned")
    return {
        "reference": IMAGE_REFERENCE,
        "id": image_id,
        "repo_digest_count": len(digests),
        "source_label_verified": True,
        "dockerfile_label_verified": True,
        "digest_verified": True,
    }


def collect_source_identity(source_root: Path) -> dict[str, Any]:
    """Read only pinned source identity; never include the checkout path in evidence."""

    require(isinstance(source_root, Path), "source root must be a Path")
    dockerfile = source_root / "Dockerfile"
    try:
        dockerfile_digest = hashlib.sha256(dockerfile.read_bytes()).hexdigest()
    except OSError as exc:
        raise ProbeError("pinned Dockerfile is unavailable") from exc

    def git_value(*arguments: str) -> str:
        try:
            completed = subprocess.run(
                ("git", "-C", str(source_root), *arguments),
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
                env=_executor_environment(),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ProbeError("pinned source identity command failed") from exc
        if completed.returncode != 0:
            raise ProbeError("pinned source identity command was rejected")
        value = completed.stdout.strip()
        if not value or len(value) > 128:
            raise ProbeError("pinned source identity output is invalid")
        return value

    identity = {
        "repository": "NousResearch/hermes-agent",
        "source_commit": git_value("rev-parse", "HEAD"),
        "source_tree": git_value("rev-parse", "HEAD^{tree}"),
        "dockerfile_sha256": dockerfile_digest,
        "image_reference": IMAGE_REFERENCE,
    }
    validate_pinned_identity(identity)
    return identity


def parse_readiness_marker(line: str) -> int | None:
    """Return the internal port only for the exact Hermes readiness line."""

    require(type(line) is str, "readiness line must be text")
    candidate = line.rstrip("\r\n")
    match = READINESS_RE.fullmatch(candidate)
    if match is None:
        return None
    port = int(match.group("port"))
    if not 1 <= port <= 65535:
        return None
    return port


def parse_readiness_output(output: str) -> int | None:
    """Find one consistent marker and reject conflicting readiness claims."""

    require(type(output) is str, "readiness output must be text")
    found: int | None = None
    for line in output.splitlines():
        port = parse_readiness_marker(line)
        if port is None:
            continue
        if found is not None:
            raise ProbeError("duplicate readiness markers")
        found = port
    return found


def classify_probe(
    *,
    readiness_port: int | None,
    returncode: int | None,
    timed_out: bool,
) -> tuple[str, str]:
    """Classify ready, timeout, signal, and exit-before-ready outcomes."""

    if readiness_port is not None:
        return "ready", "readiness_marker"
    if timed_out:
        return "blocked", "timeout_waiting_for_readiness"
    if returncode is None:
        return "blocked", "executor_result_unknown"
    if returncode < 0:
        return "blocked", f"signal_{-returncode}_before_ready"
    if returncode == 0:
        return "blocked", "exit_0_before_ready"
    if returncode == 2:
        return "blocked", "exit_2_before_ready"
    if returncode == 126:
        return "blocked", "exit_126_before_ready"
    return "blocked", "exit_nonzero_before_ready"


def redact_bounded_output(output: str) -> str:
    """Return one redacted diagnostic, capped before it reaches evidence."""

    return compact_error(output[-MAX_LOG_BYTES:])


def summarize_output(output: str) -> str:
    """Keep only a bounded redacted tail, never raw unbounded container logs."""

    lines = output.splitlines()
    if len(lines) > MAX_LOG_LINES:
        lines = lines[-MAX_LOG_LINES:]
    return redact_bounded_output("\n".join(lines))


def summarize_result(result: CommandResult) -> str:
    """Summarize diagnostics from separate streams without merging readiness."""

    streams = [result.output]
    if result.stderr:
        streams.append(result.stderr)
    return summarize_output("\n".join(streams))


def _executor_environment() -> dict[str, str]:
    """Pass only runtime basics; provider and host profile variables are excluded."""

    allowed = {"PATH", "HOME", "XDG_RUNTIME_DIR", "TMPDIR", "LANG", "LC_ALL"}
    return {key: value for key, value in os.environ.items() if key in allowed}


def _bounded_bytes(value: bytes) -> str:
    if len(value) > MAX_COMMAND_OUTPUT:
        value = value[-MAX_COMMAND_OUTPUT:]
    return value.decode("utf-8", errors="replace")


def _append_bounded(buffer: bytearray, chunk: bytes) -> None:
    buffer.extend(chunk)
    if len(buffer) > MAX_COMMAND_OUTPUT:
        del buffer[:-MAX_COMMAND_OUTPUT]


def _capture_pipe(pipe: Any, buffer: bytearray) -> None:
    """Read one pipe concurrently while retaining only its bounded tail."""

    try:
        while True:
            chunk = pipe.read(8192)
            if not chunk:
                return
            _append_bounded(buffer, chunk)
    except (OSError, ValueError):
        return


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            process.kill()
        except (OSError, ProcessLookupError):
            return


def run_bounded(command: Sequence[str], *, timeout: float) -> CommandResult:
    """Run one argv-only command with bounded stdout/stderr and no shell."""

    require(
        all(type(argument) is str and argument and "\x00" not in argument for argument in command),
        "executor command contains an unsafe argument",
    )
    try:
        process = subprocess.Popen(
            tuple(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_executor_environment(),
            start_new_session=True,
        )
    except OSError as exc:
        raise ProbeError("rootless executor is unavailable") from exc
    require(process.stdout is not None and process.stderr is not None, "executor pipes are unavailable")
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    readers = (
        threading.Thread(target=_capture_pipe, args=(process.stdout, stdout_buffer), daemon=True),
        threading.Thread(target=_capture_pipe, args=(process.stderr, stderr_buffer), daemon=True),
    )
    for reader in readers:
        reader.start()
    timed_out = False
    try:
        process.wait(timeout=max(0.1, float(timeout)))
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_process_group(process)
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass
    for reader in readers:
        reader.join(timeout=1.0)
    for pipe in (process.stdout, process.stderr):
        try:
            pipe.close()
        except OSError:
            pass
    return CommandResult(
        process.returncode,
        _bounded_bytes(bytes(stdout_buffer)),
        timed_out,
        _bounded_bytes(bytes(stderr_buffer)),
    )


def compose_command(
    project: str,
    compose_path: Path,
    verb: str,
    *arguments: str,
) -> tuple[str, ...]:
    """Build a rootless Podman Compose argv tuple with exact teardown rules."""

    require(PROJECT_RE.fullmatch(project) is not None, "Compose project is not recognized")
    require(isinstance(compose_path, Path), "Compose path is not a Path")
    require(compose_path.suffix in {".yml", ".yaml"}, "Compose path is not YAML")
    _enum(verb, frozenset({"config", "up", "ps", "logs", "down"}), "Compose operation")
    require(all(type(argument) is str and "\x00" not in argument for argument in arguments), "Compose argument is invalid")
    if verb == "down":
        require(arguments == ("--volumes", "--remove-orphans"), "teardown must be project volumes and orphans only")
    return (
        EXECUTOR,
        COMPOSE,
        "--project-name",
        project,
        "--file",
        str(compose_path),
        verb,
        *arguments,
    )


def teardown_command(project: str, compose_path: Path) -> tuple[str, ...]:
    """Return the only permitted cleanup command for the generated project."""

    return compose_command(project, compose_path, "down", "--volumes", "--remove-orphans")


def validate_teardown_target(expected_project: str, target_project: str) -> None:
    """Refuse cleanup unless the caller names the exact generated project."""

    require(PROJECT_RE.fullmatch(expected_project) is not None, "expected project is not canonical")
    require(type(target_project) is str and target_project == expected_project, "teardown project is not recognized")


def parse_resource_listing(output: str) -> int:
    """Count bounded JSON resource listings without retaining resource names."""

    if not output.strip():
        return 0
    value = load_json_text(output.encode("utf-8"), label="resource listing")
    if type(value) is list:
        return len(value)
    if type(value) is dict:
        return 1
    raise FixtureJSONError("resource listing is not an array or object")


def zero_leftovers(leftovers: Mapping[str, int]) -> bool:
    """Require all recognized project-scoped resource classes to be empty."""

    require(tuple(leftovers.keys()) == ("containers", "networks", "volumes"), "leftover resource keys changed")
    return all(type(value) is int and type(value) is not bool and value == 0 for value in leftovers.values())


def _container_state(output: str) -> tuple[bool, int | None]:
    """Read only running/exited state and exit code from bounded Compose JSON."""

    if not output.strip():
        return False, None
    value = load_json_text(output.encode("utf-8"), label="container state")
    rows = value if type(value) is list else [value]
    running = False
    exit_code: int | None = None
    for row in rows:
        require(type(row) is dict, "container state row is not an object")
        state = str(row.get("State", row.get("state", ""))).casefold()
        if "running" in state or "up" in state:
            running = True
        candidate = row.get("ExitCode", row.get("exit_code"))
        if candidate is not None:
            if type(candidate) is str and candidate.isdigit():
                candidate = int(candidate)
            require(type(candidate) is int and type(candidate) is not bool, "container exit code is invalid")
            exit_code = candidate
    return running, exit_code


def _image_inspect_from_output(output: str) -> dict[str, Any]:
    value = load_json_text(output.encode("utf-8"), label="image inspect")
    if type(value) is list:
        require(len(value) == 1, "image inspect returned an unexpected image count")
        value = value[0]
    require(type(value) is dict, "image inspect is not an object")
    return value


def _leftover_commands(project: str) -> tuple[tuple[str, ...], ...]:
    label = f"io.podman.compose.project={project}"
    return (
        (EXECUTOR, "ps", "-a", "--filter", f"label={label}", "--format", "json"),
        (EXECUTOR, "network", "ls", "--filter", f"label={label}", "--format", "json"),
        (EXECUTOR, "volume", "ls", "--filter", f"label={label}", "--format", "json"),
    )


Runner = Callable[[Sequence[str], float], CommandResult]


def _call_runner(runner: Runner, command: Sequence[str], timeout: float) -> CommandResult:
    """Convert partial executor failures into bounded probe evidence."""

    try:
        result = runner(command, timeout)
    except Exception as exc:
        return CommandResult(None, "", False, compact_error(exc))
    if not isinstance(result, CommandResult):
        return CommandResult(None, "", False, "executor returned an invalid result")
    return result


def run_probe(
    rendered: RenderedProbe,
    compose_path: Path,
    *,
    identity: Mapping[str, Any],
    capability_policy: Mapping[str, Any] | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
    runner: Runner = lambda command, timeout: run_bounded(command, timeout=timeout),
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> ProbeResult:
    """Run one bounded project, poll its marker, and tear down only that project."""

    policy = dict(CAPABILITY_POLICY if capability_policy is None else capability_policy)
    validate_capability_policy(policy)
    validate_pinned_identity(identity)
    validate_rendered_probe(rendered)
    require(timeout_seconds > 0 and timeout_seconds <= 300, "probe timeout is outside the bounded range")
    require(poll_interval_seconds > 0 and poll_interval_seconds <= 5, "probe poll interval is outside the bounded range")

    if policy["status"] != "approved":
        return ProbeResult(
            "blocked",
            "capability_policy_pending",
            None,
            None,
            False,
            None,
            {"containers": 0, "networks": 0, "volumes": 0},
            "issue 250 capability policy is not reviewed",
        )

    config_result = _call_runner(runner, compose_command(rendered.project, compose_path, "config"), 10)
    if config_result.timed_out or config_result.returncode != 0:
        return ProbeResult(
            "blocked",
            "compose_config_failed",
            None,
            config_result.returncode,
            config_result.timed_out,
            None,
            {"containers": 0, "networks": 0, "volumes": 0},
            summarize_result(config_result),
        )

    image_result = _call_runner(
        runner,
        (EXECUTOR, "image", "inspect", "--format", "json", IMAGE_REFERENCE),
        10,
    )
    if image_result.timed_out or image_result.returncode != 0:
        return ProbeResult(
            "blocked",
            "image_identity_unavailable",
            None,
            image_result.returncode,
            image_result.timed_out,
            None,
            {"containers": 0, "networks": 0, "volumes": 0},
            summarize_result(image_result),
        )
    try:
        validate_image_binding(_image_inspect_from_output(image_result.output))
    except (FixtureJSONError, ValidationError) as exc:
        return ProbeResult(
            "blocked",
            "image_identity_mismatch",
            None,
            image_result.returncode,
            False,
            None,
            {"containers": 0, "networks": 0, "volumes": 0},
            compact_error(exc),
        )

    readiness_port: int | None = None
    exit_code: int | None = None
    timed_out = False
    status, classification = "blocked", "executor_result_unknown"
    diagnostic = ""
    # The cleanup result is initialized so even an exceptional start path can
    # return a bounded outcome instead of losing the exact teardown proof.
    teardown_result = CommandResult(None, "", False, "teardown not attempted")
    try:
        # Keep the up call inside the cleanup scope.  A runner timeout or
        # partial exception after this point must still attempt exact teardown.
        up_result = _call_runner(
            runner,
            compose_command(rendered.project, compose_path, "up", "--detach", "--no-build", "gateway"),
            30,
        )
        started = up_result.returncode == 0 and not up_result.timed_out
        diagnostic = summarize_result(up_result)
        if not started:
            timed_out = up_result.timed_out
            status, classification = classify_probe(
                readiness_port=None,
                returncode=up_result.returncode,
                timed_out=up_result.timed_out,
            )
        else:
            deadline = clock() + timeout_seconds
            classification = "timeout_waiting_for_readiness"
            while True:
                log_result = _call_runner(
                    runner,
                    compose_command(
                        rendered.project,
                        compose_path,
                        "logs",
                        "--no-color",
                        "--no-log-prefix",
                        "--tail",
                        str(MAX_LOG_LINES),
                        "gateway",
                    ),
                    5,
                )
                diagnostic = summarize_result(log_result)
                # Only a successful log query can contribute stdout to the
                # readiness parser.  In particular, stderr is diagnostic-only.
                if log_result.timed_out:
                    timed_out = True
                    readiness_port = None
                    status, classification = "blocked", "logs_timeout"
                    break
                if log_result.returncode != 0:
                    readiness_port = None
                    status, classification = "blocked", "logs_failed"
                    break
                try:
                    readiness_port = parse_readiness_output(log_result.output)
                except ProbeError as exc:
                    readiness_port = None
                    status, classification = "blocked", "invalid_readiness_output"
                    diagnostic = compact_error(exc)
                    break
                state_result = _call_runner(
                    runner,
                    compose_command(
                        rendered.project,
                        compose_path,
                        "ps",
                        "--all",
                        "--format",
                        "json",
                        "gateway",
                    ),
                    5,
                )
                if state_result.timed_out or state_result.returncode != 0:
                    readiness_port = None
                    timed_out = state_result.timed_out
                    status = "blocked"
                    classification = "container_state_timeout" if state_result.timed_out else "container_state_failed"
                    diagnostic = summarize_result(state_result)
                    break
                running, observed_exit_code = _container_state(state_result.output)
                if observed_exit_code is not None:
                    exit_code = observed_exit_code
                if readiness_port is not None:
                    status, classification = classify_probe(
                        readiness_port=readiness_port,
                        returncode=exit_code,
                        timed_out=False,
                    )
                    break
                if not running and exit_code is not None:
                    status, classification = classify_probe(
                        readiness_port=None,
                        returncode=exit_code,
                        timed_out=False,
                    )
                    break
                remaining = deadline - clock()
                if remaining <= 0:
                    timed_out = True
                    status, classification = classify_probe(
                        readiness_port=None,
                        returncode=exit_code,
                        timed_out=True,
                    )
                    break
                sleeper(min(poll_interval_seconds, remaining))
    except Exception as exc:
        readiness_port = None
        status, classification = "blocked", "executor_failure"
        diagnostic = compact_error(exc)
    finally:
        teardown_result = _call_runner(runner, teardown_command(rendered.project, compose_path), 20)

    leftovers: dict[str, int] = {}
    for resource_name, command in zip(("containers", "networks", "volumes"), _leftover_commands(rendered.project)):
        listing = _call_runner(runner, command, 10)
        if listing.returncode != 0 or listing.timed_out:
            leftovers[resource_name] = -1
            continue
        try:
            leftovers[resource_name] = parse_resource_listing(listing.output)
        except (FixtureJSONError, ValidationError, ValueError, TypeError) as exc:
            leftovers[resource_name] = -1
            diagnostic = compact_error(exc)
    if not zero_leftovers(leftovers):
        status = "blocked"
        classification = "cleanup_leftovers"
    if teardown_result.returncode != 0 or teardown_result.timed_out:
        status = "blocked"
        classification = "cleanup_failed"
    return ProbeResult(
        status,
        classification,
        readiness_port,
        exit_code,
        timed_out,
        teardown_result.returncode,
        leftovers,
        diagnostic,
    )


def _case_outcome(case: Mapping[str, Any]) -> dict[str, Any]:
    kind = case["kind"]
    value = case["input"]
    if kind == "readiness_marker":
        port = parse_readiness_marker(value["text"])
        return {"accepted": port is not None, "port": port}
    if kind == "readiness_output":
        try:
            port = parse_readiness_output(value["text"])
            return {"accepted": port is not None, "port": port}
        except ProbeError:
            return {"accepted": False, "port": None}
    if kind == "classification":
        status, classification = classify_probe(
            readiness_port=value["readiness_port"],
            returncode=value["returncode"],
            timed_out=value["timed_out"],
        )
        return {"status": status, "classification": classification}
    if kind == "redaction":
        redacted = compact_error(_SYNTHETIC_DIAGNOSTIC)
        return {"marker": "[REDACTED]" if "[REDACTED]" in redacted else "", "bounded": len(redacted) <= MAX_ERROR_OUTPUT}
    if kind == "identity":
        try:
            validate_pinned_identity(value)
        except ValidationError:
            return {"accepted": False, "reason": "pinned_identity_mismatch"}
        return {"accepted": True, "reason": "pinned_identity"}
    if kind == "isolation":
        rendered = render_probe("fixture", instance="one")
        if value["mutation"] == "published_port":
            mutated = RenderedProbe(
                rendered.project,
                rendered.network,
                rendered.volume,
                rendered.stack_id,
                rendered.instance,
                rendered.compose.replace("    tty: false", "    ports:\n      - \\\"9119:9119\\\"\n    tty: false"),
            )
            try:
                validate_rendered_probe(mutated)
            except ValidationError:
                return {"accepted": False, "reason": "published_port_rejected"}
            return {"accepted": True, "reason": "unexpected"}
        validate_rendered_probe(rendered)
        return {"accepted": True, "reason": "rootless_private_project"}
    if kind == "capability":
        validate_capability_policy(CAPABILITY_POLICY)
        return {"status": CAPABILITY_POLICY["status"], "live_allowed": CAPABILITY_POLICY["status"] == "approved"}
    if kind == "cleanup":
        rendered = render_probe("fixture", instance="one")
        target = rendered.project if value["target"] == "canonical" else f"{rendered.project}-other"
        try:
            validate_teardown_target(rendered.project, target)
        except ValidationError:
            return {"accepted": False, "reason": "unrecognized_project"}
        return {"accepted": True, "reason": "exact_project_only"}
    if kind == "leftovers":
        return {"zero": zero_leftovers(value["leftovers"])}
    raise ValidationError("unknown fixture case kind")


def _validate_case_shape(case: Any, index: int) -> dict[str, Any]:
    row = strict_keys(case, CASE_KEYS, f"cases[{index}]")
    _text(row["id"], f"cases[{index}].id", max_length=80)
    kind = _enum(
        row["kind"],
        frozenset({"readiness_marker", "readiness_output", "classification", "redaction", "identity", "isolation", "capability", "cleanup", "leftovers"}),
        f"cases[{index}].kind",
    )
    require(type(row["input"]) is dict, f"cases[{index}].input must be an object")
    require(type(row["expected"]) is dict, f"cases[{index}].expected must be an object")
    _text(row["notes"], f"cases[{index}].notes", max_length=240)
    if kind in {"readiness_marker", "readiness_output"}:
        strict_keys(row["input"], ("text",), f"cases[{index}].input")
        strict_keys(row["expected"], ("accepted", "port"), f"cases[{index}].expected")
        _text(row["input"]["text"], f"cases[{index}].input.text")
        _bool(row["expected"]["accepted"], f"cases[{index}].expected.accepted")
        require(row["expected"]["port"] is None or type(row["expected"]["port"]) is int, f"cases[{index}].expected.port is invalid")
    elif kind == "classification":
        strict_keys(row["input"], ("readiness_port", "returncode", "timed_out"), f"cases[{index}].input")
        strict_keys(row["expected"], ("status", "classification"), f"cases[{index}].expected")
        require(row["input"]["readiness_port"] is None or type(row["input"]["readiness_port"]) is int, f"cases[{index}].input.readiness_port is invalid")
        require(row["input"]["returncode"] is None or (type(row["input"]["returncode"]) is int and type(row["input"]["returncode"]) is not bool), f"cases[{index}].input.returncode is invalid")
        _bool(row["input"]["timed_out"], f"cases[{index}].input.timed_out")
        _text(row["expected"]["status"], f"cases[{index}].expected.status")
        _text(row["expected"]["classification"], f"cases[{index}].expected.classification")
    elif kind == "redaction":
        strict_keys(row["input"], ("fixture_id",), f"cases[{index}].input")
        strict_keys(row["expected"], ("marker", "bounded"), f"cases[{index}].expected")
        require(row["input"]["fixture_id"] == "synthetic_diagnostic", f"cases[{index}] redaction fixture changed")
        require(row["expected"]["marker"] == "[REDACTED]", f"cases[{index}] redaction marker changed")
        _bool(row["expected"]["bounded"], f"cases[{index}].expected.bounded")
    elif kind == "identity":
        strict_keys(row["input"], IDENTITY_KEYS, f"cases[{index}].input")
        strict_keys(row["expected"], ("accepted", "reason"), f"cases[{index}].expected")
        _bool(row["expected"]["accepted"], f"cases[{index}].expected.accepted")
        _text(row["expected"]["reason"], f"cases[{index}].expected.reason")
    elif kind == "isolation":
        strict_keys(row["input"], ("mutation",), f"cases[{index}].input")
        strict_keys(row["expected"], ("accepted", "reason"), f"cases[{index}].expected")
        _enum(row["input"]["mutation"], frozenset({"none", "published_port"}), f"cases[{index}].input.mutation")
        _bool(row["expected"]["accepted"], f"cases[{index}].expected.accepted")
        _text(row["expected"]["reason"], f"cases[{index}].expected.reason")
    elif kind == "capability":
        strict_keys(row["input"], ("policy",), f"cases[{index}].input")
        strict_keys(row["expected"], ("status", "live_allowed"), f"cases[{index}].expected")
        require(row["input"]["policy"] == "checked_in", f"cases[{index}] capability policy changed")
        _text(row["expected"]["status"], f"cases[{index}].expected.status")
        _bool(row["expected"]["live_allowed"], f"cases[{index}].expected.live_allowed")
    elif kind == "cleanup":
        strict_keys(row["input"], ("target",), f"cases[{index}].input")
        strict_keys(row["expected"], ("accepted", "reason"), f"cases[{index}].expected")
        _enum(row["input"]["target"], frozenset({"canonical", "other_project"}), f"cases[{index}].input.target")
        _bool(row["expected"]["accepted"], f"cases[{index}].expected.accepted")
        _text(row["expected"]["reason"], f"cases[{index}].expected.reason")
    else:
        strict_keys(row["input"], ("leftovers",), f"cases[{index}].input")
        strict_keys(row["expected"], ("zero",), f"cases[{index}].expected")
        require(type(row["input"]["leftovers"]) is dict, f"cases[{index}].input.leftovers must be an object")
        strict_keys(row["input"]["leftovers"], ("containers", "networks", "volumes"), f"cases[{index}].input.leftovers")
        for key in row["input"]["leftovers"]:
            _int(row["input"]["leftovers"][key], f"cases[{index}].input.leftovers.{key}")
        _bool(row["expected"]["zero"], f"cases[{index}].expected.zero")
    return row


def validate_cases_document(document: Any) -> None:
    """Validate the checked-in policy and evaluate every deterministic case."""

    root = strict_keys(document, ROOT_KEYS, "cases")
    require(root["schema"] == SCHEMA, "cases schema changed")
    require(root["operation"] == OPERATION, "cases operation changed")
    require(root["contract"] == CONTRACT, "cases contract changed")
    require(root["synthetic_only"] is True, "fixture is not synthetic-only")
    require(root["network_access"] == "executor_only", "network access boundary changed")
    require(root["live_run"] is False, "checked-in fixture cannot claim a live run")
    require(root["proof_status"] == "not_run", "checked-in fixture cannot claim readiness proof")
    validate_pinned_identity(root["pinned_identity"])
    strict_equal(root["executor_policy"], EXPECTED_EXECUTOR_POLICY, "executor policy")
    strict_equal(root["probe_policy"], EXPECTED_PROBE_POLICY, "probe policy")
    strict_equal(root["isolation_policy"], EXPECTED_ISOLATION_POLICY, "isolation policy")
    strict_equal(root["capability_policy"], CAPABILITY_POLICY, "capability policy")
    validate_capability_policy(root["capability_policy"])
    require(type(root["cases"]) is list, "cases must be an array")
    require(all(type(case) is dict for case in root["cases"]), "case entry must be an object")
    require(tuple(case["id"] for case in root["cases"]) == EXPECTED_CASE_IDS, "case inventory changed")
    require(tuple(PINNED_CASE_CONTRACTS) == EXPECTED_CASE_IDS, "pinned case inventory changed")
    for index, case in enumerate(root["cases"]):
        row = _validate_case_shape(case, index)
        pinned_input, pinned_expected = PINNED_CASE_CONTRACTS[row["id"]]
        strict_equal(row["input"], pinned_input, f"case {row['id']} input")
        strict_equal(row["expected"], pinned_expected, f"case {row['id']} expected")
        expected = _case_outcome(row)
        strict_equal(expected, row["expected"], f"case {row['id']} outcome")


def validate_evidence_document(evidence: Any, cases_document: Mapping[str, Any]) -> None:
    """Validate the checked-in no-run evidence record without live claims."""

    record = strict_keys(evidence, EVIDENCE_KEYS, "evidence")
    require(record["schema"] == EVIDENCE_SCHEMA, "evidence schema changed")
    require(record["operation"] == OPERATION, "evidence operation changed")
    require(record["synthetic_only"] is True, "evidence is not synthetic-only")
    require(record["live_run"] is False, "evidence cannot claim a live run")
    require(record["status"] == "not_run", "evidence status changed")
    require(record["correctness_executor"] == "rootless_podman", "evidence executor changed")
    require(record["ssh_target"] == SSH_TARGET, "evidence SSH boundary changed")
    validate_pinned_identity(record["pinned_identity"])
    require(record["command_candidate"] == list(PROBE_COMMAND), "candidate command changed")
    require(
        record["command_support"] == "parser_option_present_readiness_candidate_requires_review",
        "candidate command support claim changed",
    )
    require(record["readiness_marker"] == READINESS_PREFIX, "readiness marker changed")
    require(record["readiness_source_status"] == "headless_backend_path_only", "readiness source claim changed")
    strict_equal(record["capability_policy"], cases_document["capability_policy"], "evidence capability policy")
    observations = strict_keys(record["observations"], EVIDENCE_OBSERVATION_KEYS, "evidence observations")
    for key in EVIDENCE_OBSERVATION_KEYS[:-1]:
        require(observations[key] == "not_run", f"evidence observation {key} changed")
    leftovers = strict_keys(observations["leftover_resources"], ("containers", "networks", "volumes"), "evidence leftovers")
    require(all(value is None for value in leftovers.values()), "evidence cannot claim cleanup")
    require(type(record["limitations"]) is list, "evidence limitations must be an array")
    require(
        record["limitations"] == [
            "no_live_run",
            "capability_policy_pending",
            "gateway_command_readiness_candidate",
            "no_provider_or_browser_auth",
        ],
        "evidence limitations changed",
    )


def _success_payload(
    document: Mapping[str, Any],
    *,
    evidence: Mapping[str, Any],
    rendered: RenderedProbe | None = None,
) -> dict[str, Any]:

    payload: dict[str, Any] = {
        "ok": True,
        "compatible": False,
        "live_run": False,
        "proof_status": document["proof_status"],
        "evidence_status": evidence["status"],
        "case_count": len(document["cases"]),
    }
    if rendered is not None:
        payload["rendered"] = rendered.public_metadata()
    return payload


def _failure_payload(code: str, message: object) -> dict[str, Any]:
    return {
        "ok": False,
        "compatible": False,
        "live_run": False,
        "error": {"code": code, "message": compact_error(message)},
    }


class ControlledArgumentParser(argparse.ArgumentParser):
    """Keep argparse failures inside the one-line JSON error contract."""

    def error(self, message: str) -> None:
        del message
        raise ValidationError("invalid command-line arguments")

    def exit(self, status: int = 0, message: str | None = None) -> None:
        del message
        if status:
            raise ValidationError("invalid command-line arguments")
        raise ValidationError("command-line help is not part of the validator output contract")


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = ControlledArgumentParser(add_help=False, description="Validate the rootless Hermes gateway readiness fixture")
    parser.add_argument("--cases", type=Path, default=CASES_PATH)
    parser.add_argument("--render", type=Path)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--allow-live", action="store_true")
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--stack-id", default="smoke")
    parser.add_argument("--instance", default="one")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parse_args(sys.argv[1:] if argv is None else argv)
        document = load_json(args.cases)
        evidence = load_json(EVIDENCE_PATH)
        validate_redaction(document)
        validate_redaction(evidence)
        validate_cases_document(document)
        validate_evidence_document(evidence, document)
        rendered: RenderedProbe | None = None
        if args.render is not None or args.run:
            rendered = render_probe(args.stack_id, instance=args.instance)
        if args.render is not None and rendered is not None:
            try:
                args.render.write_text(rendered.compose, encoding="utf-8")
            except OSError as exc:
                raise ValidationError("render output could not be written") from exc
        if not args.run:
            print(json.dumps(_success_payload(document, evidence=evidence, rendered=rendered), separators=(",", ":")))
            return 0
        if not args.allow_live:
            print(json.dumps(_failure_payload(ERROR_CODE, "live runner requires explicit --allow-live"), separators=(",", ":")))
            return 2
        if args.source_root is None:
            print(json.dumps(_failure_payload(ERROR_CODE, "live runner requires a pinned source root"), separators=(",", ":")))
            return 2
        identity = collect_source_identity(args.source_root)
        with tempfile.TemporaryDirectory(prefix="hermes-gateway-readiness-") as temporary:
            compose_path = Path(temporary) / "compose.yml"
            compose_path.write_text(rendered.compose if rendered is not None else render_probe(args.stack_id, instance=args.instance).compose, encoding="utf-8")
            result = run_probe(rendered or render_probe(args.stack_id, instance=args.instance), compose_path, identity=identity)
        payload = {
            "ok": result.status == "ready",
            "compatible": False,
            "live_run": result.status != "blocked" or result.classification != "capability_policy_pending",
            "probe": result.public(),
        }
        print(json.dumps(payload, separators=(",", ":")))
        return 0 if result.status == "ready" else 3
    except (FixtureJSONError, ValidationError, ProbeError, OSError, ValueError, TypeError) as exc:
        print(json.dumps(_failure_payload(ERROR_CODE, exc), separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
