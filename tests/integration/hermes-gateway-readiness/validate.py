#!/usr/bin/env python3
"""Validate and run the isolated rootless-Podman Hermes gateway probe.

The default command is an offline contract check.  The live runner is an
explicit opt-in and activates only issue #250's reviewed CAP_CHOWN,
CAP_SETGID, and CAP_SETUID capability set.  It uses only ``podman compose``
with a project-derived network and volume, never a shell, host ports, a
provider, a browser, a PTY, or a retained raw log.
"""

from __future__ import annotations

import argparse
import getpass
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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


ROOT = Path(__file__).resolve().parent
CASES_PATH = ROOT / "cases.json"
OFFICIAL_EVIDENCE_PATH = ROOT / "official-evidence.json"
SCHEMA = "hermternal.integration.hermes-gateway-readiness.v1"
OFFICIAL_EVIDENCE_SCHEMA = "hermternal.integration.hermes-gateway-readiness.official-evidence.v1"
OPERATION = "R-02C"
CONTRACT = "hermes-gateway-readiness-v1"
OFFICIAL_IMAGE_REPOSITORY = "docker.io/nousresearch/hermes-agent"
OFFICIAL_IMAGE_TAG = "v2026.8.3"
OFFICIAL_IMAGE_DIGEST = "sha256:16788311e2fa3035456bdc1bafb8ec2b1777db64ebf020af9bb7eb73c3712c9e"
OFFICIAL_IMAGE_REFERENCE = f"{OFFICIAL_IMAGE_REPOSITORY}:{OFFICIAL_IMAGE_TAG}@{OFFICIAL_IMAGE_DIGEST}"
OFFICIAL_IMAGE_REPO_DIGEST = f"{OFFICIAL_IMAGE_REPOSITORY}@{OFFICIAL_IMAGE_DIGEST}"
OFFICIAL_IMAGE_REVISION = "3c27eb6234bf91b8ceee9e9071591b31e9b148cb"
# The upstream image config carries the dispatch path and working directory.
# Runtime inspect remains the authoritative proof of the applied PID 1 path.
OFFICIAL_CONTAINER_WORKING_DIR = "/opt/hermes"
OFFICIAL_RUNTIME_PATH = "/opt/hermes/docker/entrypoint-dispatch.sh"
OFFICIAL_RUNTIME_ENTRYPOINT = [OFFICIAL_RUNTIME_PATH]
OFFICIAL_IMAGE_CONFIG_ENTRYPOINT = OFFICIAL_RUNTIME_ENTRYPOINT
OFFICIAL_IMAGE_CONFIG_CMD = None
OFFICIAL_IMAGE_CONFIG_USER = "root"
OFFICIAL_IMAGE_CONFIG_WORKING_DIR = OFFICIAL_CONTAINER_WORKING_DIR
IMAGE_REVISION_LABEL = "org.opencontainers.image.revision"
EXPECTED_PODMAN_VERSION = "5.4.2"
EXPECTED_COMPOSE_PROVIDER = "podman-compose"
EXPECTED_COMPOSE_VERSION = "1.3.0"
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

# Issue #250's exact source-reviewed set is now approved for this one live
# readiness attempt. Keeping the set duplicated here and in the validator makes
# a broad or reordered capability addition fail closed before the executor.
APPROVED_CAPABILITIES = ("CAP_CHOWN", "CAP_SETGID", "CAP_SETUID")
CAPABILITY_POLICY = {
    "status": "approved",
    "cap_drop": ["ALL"],
    "cap_add": list(APPROVED_CAPABILITIES),
    "no_new_privileges": True,
    "dependency": "issue_250_review",
}
PENDING_CAPABILITY_POLICY = {
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
    "tag",
    "digest",
    "reference",
)
CASE_KEYS = ("id", "kind", "input", "expected", "notes")
OFFICIAL_EVIDENCE_KEYS = (
    "schema",
    "operation",
    "synthetic_only",
    "live_run",
    "status",
    "classification",
    "teardown_exit_code",
    "correctness_executor",
    "ssh_target",
    "executor",
    "image",
    "command_candidate",
    "command_support",
    "readiness_marker",
    "readiness_source_status",
    "capability_policy",
    "isolation_policy",
    "cleanup_scope",
    "observations",
    "runtime_identity",
    "diagnostic",
    "log_tail",
    "limitations",
)
OFFICIAL_CLEANUP_KEYS = ("project", "network", "volume")
OFFICIAL_EXECUTOR_KEYS = (
    "account",
    "ssh_target",
    "rootless",
    "podman_version",
    "cgroup_version",
    "network_backend",
    "storage_driver",
    "compose_provider",
    "compose_version",
    "docker_host_cleared",
    "hermes_provider_cleared",
)
OFFICIAL_IMAGE_KEYS = (
    "reference",
    "repository",
    "tag",
    "requested_digest",
    "pull_status",
    "inspect_status",
    "image_id",
    "repo_tags",
    "repo_digests",
    "repo_digest_verified",
    "manifest_digest",
    "revision_label",
    "entrypoint",
    "cmd",
    "user",
    "working_dir",
)
OFFICIAL_OBSERVATION_KEYS = (
    "executor_preflight",
    "image_pull",
    "image_identity",
    "compose_config",
    "container_start",
    "runtime_inspection",
    "readiness",
    "exit",
    "exit_code",
    "teardown",
    "leftover_resources",
    "policy_inspection",
    "applied_policy",
)
OFFICIAL_RUNTIME_KEYS = (
    "container_id",
    "status",
    "pid",
    "state",
    "path",
    "args",
    "entrypoint",
    "policy",
    "resources",
    "namespaces",
)
OFFICIAL_RUNTIME_POLICY_KEYS = (
    "cap_drop",
    "cap_add",
    "security_opt",
    "no_new_privileges",
    "published_ports",
    "host_network",
    "named_volume_opt_data",
)
OFFICIAL_RUNTIME_NAMESPACE_KEYS = ("network", "ipc", "pid")
OFFICIAL_RUNTIME_RESOURCE_KEYS = (
    "nano_cpus",
    "memory_limit",
    "pids_limit",
    "shm_size",
    "tmpfs",
    "restart_policy",
    "log_driver",
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
    "capability-policy-approved",
    "cleanup-canonical-project",
    "cleanup-unrecognized-project",
    "cleanup-zero-leftovers",
    "cleanup-leftover-detected",
)

# Keep each semantic kind independent from cases.json. Otherwise a case can
# switch parser paths while preserving its input and expected result.
PINNED_CASE_KINDS = {
    "readiness-marker-accepted": "readiness_marker",
    "readiness-marker-rejects-prefix": "readiness_marker",
    "readiness-marker-rejects-invalid-port": "readiness_marker",
    "readiness-conflicting-markers": "readiness_output",
    "classify-timeout": "classification",
    "classify-exit-126": "classification",
    "classify-exit-2": "classification",
    "classify-signal": "classification",
    "redaction-symbolic-diagnostic": "redaction",
    "identity-exact": "identity",
    "identity-drift-rejected": "identity",
    "isolation-rendered": "isolation",
    "isolation-published-port-rejected": "isolation",
    "capability-policy-approved": "capability",
    "cleanup-canonical-project": "cleanup",
    "cleanup-unrecognized-project": "cleanup",
    "cleanup-zero-leftovers": "leftovers",
    "cleanup-leftover-detected": "leftovers",
}

# Keep the adversarial payloads independent from cases.json. Otherwise a
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
            "repository": OFFICIAL_IMAGE_REPOSITORY,
            "tag": OFFICIAL_IMAGE_TAG,
            "digest": OFFICIAL_IMAGE_DIGEST,
            "reference": OFFICIAL_IMAGE_REFERENCE,
        },
        {"accepted": True, "reason": "pinned_identity"},
    ),
    "identity-drift-rejected": (
        {
            "repository": OFFICIAL_IMAGE_REPOSITORY,
            "tag": OFFICIAL_IMAGE_TAG,
            "digest": "sha256:" + "0" * 64,
            "reference": OFFICIAL_IMAGE_REFERENCE,
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
    "capability-policy-approved": (
        {"policy": "checked_in"},
        {"status": "approved", "live_allowed": True},
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
    cap_add: tuple[str, ...] = APPROVED_CAPABILITIES

    def public_metadata(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "network": self.network,
            "volume": self.volume,
            "executor": EXECUTOR,
            "ssh_target": SSH_TARGET,
            "service": "gateway",
            "command": list(PROBE_COMMAND),
            "cap_add": list(self.cap_add),
        }


@dataclass(frozen=True)
class ProbeResult:
    """Bounded public outcome and observed runtime facts from one operation."""

    status: str
    classification: str
    readiness_port: int | None
    exit_code: int | None
    timed_out: bool
    teardown_exit_code: int | None
    leftovers: dict[str, int]
    diagnostic: str
    executor: dict[str, Any] = field(default_factory=dict)
    image: dict[str, Any] = field(default_factory=dict)
    observations: dict[str, Any] = field(default_factory=dict)
    runtime_identity: dict[str, Any] = field(default_factory=dict)
    log_tail: str = ""

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


def redact_readiness_markers(text: str) -> str:
    """Keep readiness claims out of blocked diagnostics and log tails."""

    return re.sub(
        r"(?m)^HERMES_BACKEND_READY port=[1-9][0-9]{0,4}$",
        "[REDACTED_READINESS_MARKER]",
        text,
    )


def compact_error(message: object) -> str:
    """Redact untrusted diagnostics before applying the fixed output cap."""

    redacted = redact_readiness_markers(str(message))
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
    # Evidence fields are single-line public summaries. Normalize newlines,
    # tabs, ANSI controls, and other terminal bytes before the output cap.
    redacted = CONTROL_RE.sub(" ", redacted)
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


def validate_json_tree(value: Any, depth: int = 0, *, allow_controls: bool = False) -> int:
    """Apply recursive node, container, text, and finite-number limits.

    Checked-in fixtures reject decoded control characters. Podman metadata can
    legitimately contain multiline runtime-version strings, so bounded command
    output may opt into those strings without weakening fixture validation.
    """

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
            nodes += validate_json_tree(child, depth + 1, allow_controls=allow_controls)
            if nodes > MAX_JSON_NODES:
                raise FixtureJSONError("JSON node count exceeds the bounded limit")
        return nodes
    if type(value) is list:
        if len(value) > MAX_ARRAY_LENGTH:
            raise FixtureJSONError("JSON array is too long")
        nodes = 1
        for child in value:
            nodes += validate_json_tree(child, depth + 1, allow_controls=allow_controls)
            if nodes > MAX_JSON_NODES:
                raise FixtureJSONError("JSON node count exceeds the bounded limit")
        return nodes
    if type(value) is str:
        if len(value) > MAX_STRING_LENGTH:
            raise FixtureJSONError("JSON string is too long")
        if not allow_controls and CONTROL_RE.search(value) is not None:
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


def load_command_json_text(data: bytes | str, *, label: str = "command JSON") -> Any:
    """Decode bounded executor JSON while allowing multiline metadata strings."""

    raw = data.encode("utf-8") if isinstance(data, str) else data
    if len(raw) > MAX_COMMAND_OUTPUT:
        raise FixtureJSONError(f"{label} exceeds the command output limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FixtureJSONError(f"{label} is not UTF-8") from exc
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
        raise FixtureJSONError(f"{label} is malformed") from exc
    validate_json_tree(value, allow_controls=True)
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


ALLOWED_CONTAINER_PATHS = frozenset({
    "/opt/data",
    OFFICIAL_CONTAINER_WORKING_DIR,
    OFFICIAL_RUNTIME_PATH,
})
ALLOWED_CONTAINER_PATH_PREFIXES = ("/tmp:size=", "/run:size=")
ALLOWED_PUBLIC_IMAGE_VALUES = frozenset({
    OFFICIAL_IMAGE_REPOSITORY,
    OFFICIAL_IMAGE_TAG,
    OFFICIAL_IMAGE_REFERENCE,
    OFFICIAL_IMAGE_DIGEST,
    OFFICIAL_IMAGE_REPO_DIGEST,
})


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
        if value in ALLOWED_PUBLIC_IMAGE_VALUES:
            return
        if re.fullmatch(r"docker\.io/nousresearch/hermes-agent(?::v2026\.8\.3)?@sha256:[0-9a-f]{64}", value):
            return
        if re.fullmatch(r"docker\.io/nousresearch/hermes-agent@sha256:[0-9a-f]{64}", value):
            return
        if (
            HEX40_RE.fullmatch(value)
            or HEX64_RE.fullmatch(value)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", value)
        ):
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
    """Allow only the pending policy or issue #250's exact reviewed set."""

    keys = ("status", "cap_drop", "cap_add", "no_new_privileges", "dependency")
    value = strict_keys(dict(policy), keys, "capability policy")
    status = _enum(
        value["status"],
        frozenset({"awaiting_issue_250", "approved"}),
        "capability status",
    )
    require(value["cap_drop"] == ["ALL"], "capability drop policy must remain ALL")
    require(type(value["cap_add"]) is list, "capability add policy must be a list")
    expected_caps = [] if status == "awaiting_issue_250" else list(APPROVED_CAPABILITIES)
    require(value["cap_add"] == expected_caps, "capability additions are not the reviewed set")
    _bool(value["no_new_privileges"], "no-new-privileges policy")
    require(value["no_new_privileges"], "no-new-privileges must remain enabled")
    require(value["dependency"] == "issue_250_review", "capability policy dependency changed")


def _canonical_compose(
    project: str,
    network: str,
    volume: str,
    cap_add: Sequence[str],
) -> str:
    """Render the sole accepted Compose document for the probe policy."""

    additions = tuple(cap_add)
    require(
        additions in {(), APPROVED_CAPABILITIES},
        "Compose capability additions are not the reviewed set",
    )
    lines = [
        "services:",
        "  gateway:",
        f"    image: {_yaml_string(OFFICIAL_IMAGE_REFERENCE)}",
        '    restart: "no"',
    ]
    if additions:
        lines.extend(["    cap_add:", *[f'      - "{capability}"' for capability in additions]])
    lines.extend([
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
    ])
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
    cap_add = tuple(policy["cap_add"])
    compose = _canonical_compose(project, network, volume, cap_add)
    result = RenderedProbe(project, network, volume, stack_id, instance, compose, cap_add)
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
    require(
        result.cap_add in {(), APPROVED_CAPABILITIES},
        "capability additions are not the reviewed set",
    )
    text = result.compose
    # Validate the complete document, not merely required substrings.  This
    # rejects appended duplicate keys and any new volume, capability, PTY, or
    # resource field that could otherwise override an earlier safe value.
    require(
        text == _canonical_compose(result.project, result.network, result.volume, result.cap_add),
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
    require(
        f'    image: "{OFFICIAL_IMAGE_REFERENCE}"' in text,
        "official immutable image reference changed",
    )
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
    """Require the official registry, tag, digest, and canonical reference."""

    record = strict_keys(dict(identity), IDENTITY_KEYS, "official image identity")
    require(record["repository"] == OFFICIAL_IMAGE_REPOSITORY, "official repository changed")
    require(record["tag"] == OFFICIAL_IMAGE_TAG, "official tag changed")
    require(record["digest"] == OFFICIAL_IMAGE_DIGEST, "official digest changed")
    require(record["reference"] == OFFICIAL_IMAGE_REFERENCE, "official image reference changed")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", record["digest"]) is not None, "official digest is invalid")


def validate_image_binding(record: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the actual official Podman image pull/inspect binding."""

    require(type(record) is dict, "image inspect record is not an object")
    tags = record.get("RepoTags", record.get("repo_tags", []))
    require(type(tags) is list, "image RepoTags are not a list")
    for tag in tags:
        require(type(tag) is str, "image RepoTags contain a non-text value")
        require(
            tag == f"{OFFICIAL_IMAGE_REPOSITORY}:{OFFICIAL_IMAGE_TAG}",
            "image RepoTags contain a non-official reference",
        )
    digests = record.get("RepoDigests", record.get("repo_digests", []))
    require(type(digests) is list and digests, "image RepoDigests are missing")
    for digest in digests:
        require(
            type(digest) is str
            and re.fullmatch(r"docker\.io/nousresearch/hermes-agent@sha256:[0-9a-f]{64}", digest)
            is not None,
            "image RepoDigests contain an invalid repository binding",
        )
    require(OFFICIAL_IMAGE_REPO_DIGEST in digests, "official RepoDigest binding is absent")
    manifest_digest = record.get("Digest", record.get("digest"))
    require(manifest_digest == OFFICIAL_IMAGE_DIGEST, "image manifest digest changed")
    image_id = record.get("Id", record.get("id"))
    require(type(image_id) is str and IMAGE_ID_RE.fullmatch(image_id) is not None, "image id is invalid")

    config = record.get("Config", {})
    require(type(config) is dict, "image config is not an object")
    labels = config.get("Labels", record.get("labels"))
    require(type(labels) is dict, "image labels are not an object")
    require(labels.get(IMAGE_REVISION_LABEL) == OFFICIAL_IMAGE_REVISION, "official revision label is not pinned")
    entrypoint = config.get("Entrypoint")
    cmd = config.get("Cmd")
    user = config.get("User")
    working_dir = config.get("WorkingDir")
    require(entrypoint == OFFICIAL_IMAGE_CONFIG_ENTRYPOINT, "official image entrypoint metadata changed")
    require(cmd == OFFICIAL_IMAGE_CONFIG_CMD, "official image command metadata changed")
    require(user == OFFICIAL_IMAGE_CONFIG_USER, "official image user changed")
    require(working_dir == OFFICIAL_IMAGE_CONFIG_WORKING_DIR, "official image working directory changed")
    return {
        "reference": OFFICIAL_IMAGE_REFERENCE,
        "repository": OFFICIAL_IMAGE_REPOSITORY,
        "tag": OFFICIAL_IMAGE_TAG,
        "requested_digest": OFFICIAL_IMAGE_DIGEST,
        "pull_status": "passed",
        "inspect_status": "passed",
        "image_id": image_id.removeprefix("sha256:"),
        "repo_tags": list(tags),
        "repo_digests": list(digests),
        "repo_digest_verified": True,
        "manifest_digest": manifest_digest,
        "revision_label": labels[IMAGE_REVISION_LABEL],
        "entrypoint": entrypoint,
        "cmd": cmd,
        "user": user,
        "working_dir": working_dir,
    }


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
    """Pin Podman's compose provider and exclude host/provider credentials."""

    allowed = {"PATH", "HOME", "XDG_RUNTIME_DIR", "TMPDIR", "LANG", "LC_ALL"}
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    # ``podman compose`` delegates to an external provider.  Podman prefers a
    # Docker Compose plugin when both providers exist, which would violate the
    # rootless-Podman correctness boundary even if the argv still says podman.
    environment["PODMAN_COMPOSE_PROVIDER"] = EXPECTED_COMPOSE_PROVIDER
    return environment


def _parse_json_rows(output: str, label: str) -> list[dict[str, Any]]:
    """Parse bounded Podman JSON or JSON-lines output without retaining names."""

    if not output.strip():
        return []
    try:
        value = load_json_text(output.encode("utf-8"), label=label)
        values = value if type(value) is list else [value]
    except FixtureJSONError:
        values = []
        for line in output.splitlines():
            if not line.strip():
                continue
            value = load_json_text(line.encode("utf-8"), label=label)
            values.append(value)
    require(all(type(value) is dict for value in values), f"{label} rows are not objects")
    return values


def _command_json(result: CommandResult, label: str) -> Any:
    require(not result.timed_out and result.returncode == 0, f"{label} command failed")
    return load_command_json_text(result.output.encode("utf-8"), label=label)


def _podman_version(value: Any) -> str:
    if type(value) is not dict:
        raise ValidationError("Podman version output is not an object")
    candidates = (
        value.get("Version"),
        (value.get("Client") or {}).get("Version") if type(value.get("Client")) is dict else None,
        (value.get("Server") or {}).get("Version") if type(value.get("Server")) is dict else None,
        (value.get("version") or {}).get("Version") if type(value.get("version")) is dict else None,
    )
    for candidate in candidates:
        if type(candidate) is str and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", candidate):
            return candidate
    raise ValidationError("Podman version is missing")


def _compose_version(output: str) -> str:
    match = re.search(r"podman-compose version ([0-9]+\.[0-9]+\.[0-9]+)", output)
    if match is None:
        raise ValidationError("podman-compose version is missing")
    return match.group(1)


def validate_executor_info(info: Mapping[str, Any]) -> None:
    """Require the actual rootless Podman boundary before image execution."""

    record = strict_keys(dict(info), OFFICIAL_EXECUTOR_KEYS, "executor identity")
    require(record["account"] == ROOTLESS_ACCOUNT, "rootless account changed")
    require(record["rootless"] is True, "Podman is not rootless")
    require(record["podman_version"] == EXPECTED_PODMAN_VERSION, "Podman version changed")
    require(record["cgroup_version"] == "v2", "cgroup version changed")
    require(record["network_backend"] == "netavark", "network backend changed")
    require(record["storage_driver"] == "overlay", "storage driver changed")
    require(record["compose_provider"] == EXPECTED_COMPOSE_PROVIDER, "compose provider changed")
    require(record["compose_version"] == EXPECTED_COMPOSE_VERSION, "compose provider version changed")
    require(record["docker_host_cleared"] is True, "DOCKER_HOST was not cleared")
    require(record["hermes_provider_cleared"] is True, "HERMES_PROVIDER was not cleared")


def _collect_executor_info(runner: Runner) -> dict[str, Any]:
    """Collect and validate only bounded public executor facts."""

    version_result = _call_runner(runner, (EXECUTOR, "version", "--format", "json"), 10)
    info_result = _call_runner(runner, (EXECUTOR, "info", "--format", "json"), 10)
    compose_result = _call_runner(runner, (EXECUTOR, COMPOSE, "version"), 10)
    version = _podman_version(_command_json(version_result, "Podman version"))
    info = _command_json(info_result, "Podman info")
    require(type(info) is dict, "Podman info is not an object")
    host = info.get("host") or {}
    store = info.get("store") or {}
    security = host.get("security") or {}
    record = {
        "account": getpass.getuser(),
        "ssh_target": SSH_TARGET,
        "rootless": security.get("rootless"),
        "podman_version": version,
        "cgroup_version": host.get("cgroupVersion"),
        "network_backend": host.get("networkBackend"),
        "storage_driver": store.get("graphDriverName"),
        "compose_provider": EXPECTED_COMPOSE_PROVIDER,
        "compose_version": _compose_version(compose_result.output + "\n" + compose_result.stderr),
        "docker_host_cleared": "DOCKER_HOST" not in _executor_environment(),
        "hermes_provider_cleared": "HERMES_PROVIDER" not in _executor_environment(),
    }
    validate_executor_info(record)
    return record


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
    return _image_inspect_from_value(value)


def _image_inspect_from_value(value: Any) -> dict[str, Any]:
    if type(value) is list:
        require(len(value) == 1, "image inspect returned an unexpected image count")
        value = value[0]
    require(type(value) is dict, "image inspect is not an object")
    return value


def _container_id_from_listing(output: str) -> str:
    rows = _parse_json_rows(output, "container listing")
    require(len(rows) == 1, "project must have exactly one gateway container")
    container_id = rows[0].get("Id", rows[0].get("ID"))
    require(type(container_id) is str and re.fullmatch(r"[0-9a-f]{12,64}", container_id) is not None, "container id is invalid")
    return container_id


def _runtime_identity_from_row(row: Mapping[str, Any], container_id: str) -> dict[str, Any]:
    state = row.get("State") or {}
    config = row.get("Config") or {}
    host = row.get("HostConfig") or {}
    mounts = row.get("Mounts") or []
    require(type(state) is dict, "container state is not an object")
    require(type(config) is dict, "container config is not an object")
    require(type(host) is dict, "container HostConfig is not an object")
    require(type(mounts) is list, "container mounts are not an array")
    cap_drop = list(host.get("CapDrop") or [])
    cap_add = list(host.get("CapAdd") or [])
    security_opt = list(host.get("SecurityOpt") or [])
    port_bindings = host.get("PortBindings") or {}
    restart = host.get("RestartPolicy") or {}
    log_config = host.get("LogConfig") or {}
    no_new_privileges = host.get("NoNewPrivileges")
    if type(no_new_privileges) is not bool:
        no_new_privileges = "no-new-privileges:true" in security_opt
    named_volume = any(
        type(mount) is dict
        and mount.get("Type") == "volume"
        and mount.get("Destination") == "/opt/data"
        for mount in mounts
    )
    pid = state.get("Pid")
    if type(pid) is not int or type(pid) is bool:
        pid = None
    exit_code = state.get("ExitCode")
    if type(exit_code) is not int or type(exit_code) is bool:
        exit_code = None
    return {
        "container_id": container_id,
        "status": "verified",
        "pid": pid,
        "state": {
            "running": state.get("Running"),
            "status": state.get("Status"),
            "exit_code": exit_code,
        },
        "path": row.get("Path"),
        "args": list(row.get("Args") or []),
        "entrypoint": config.get("Entrypoint"),
        "policy": {
            "cap_drop": cap_drop,
            "cap_add": cap_add,
            "security_opt": security_opt,
            "no_new_privileges": no_new_privileges,
            "published_ports": bool(port_bindings) or bool(host.get("PublishAllPorts")),
            "host_network": host.get("NetworkMode") == "host",
            "named_volume_opt_data": named_volume,
        },
        "resources": {
            "nano_cpus": host.get("NanoCpus", host.get("NanoCPUs", host.get("CpuQuota"))),
            "memory_limit": host.get("Memory"),
            "pids_limit": host.get("PidsLimit"),
            "shm_size": host.get("ShmSize"),
            "tmpfs": host.get("Tmpfs"),
            "restart_policy": restart.get("Name") if type(restart) is dict else restart,
            "log_driver": log_config.get("Type") if type(log_config) is dict else log_config,
        },
        "namespaces": {
            "network": host.get("NetworkMode"),
            "ipc": host.get("IpcMode"),
            "pid": host.get("PidMode"),
        },
    }


def _inspect_container_by_id(container_id: str, runner: Runner) -> dict[str, Any]:
    inspected = _call_runner(runner, (EXECUTOR, "inspect", "--format", "json", container_id), 5)
    require(not inspected.timed_out and inspected.returncode == 0, "container inspect failed")
    row = _image_inspect_from_output(inspected.output)
    return _runtime_identity_from_row(row, container_id)


def _inspect_runtime_container(
    project: str,
    runner: Runner,
) -> dict[str, Any]:
    listing = _call_runner(
        runner,
        (
            EXECUTOR,
            "ps",
            "--no-trunc",
            "-a",
            "--filter",
            f"label=io.podman.compose.project={project}",
            "--format",
            "json",
        ),
        5,
    )
    require(not listing.timed_out and listing.returncode == 0, "container listing failed")
    container_id = _container_id_from_listing(listing.output)
    return _inspect_container_by_id(container_id, runner)


def _runtime_tmpfs_matches(value: Any) -> bool:
    """Accept Podman's normalized tmpfs values while requiring reviewed sizes."""

    required = {
        "/tmp": "size=64m,mode=1777",
        "/run": "size=16m,mode=755",
    }
    if type(value) is dict:
        return all(
            type(value.get(path)) is str and value[path].startswith(prefix)
            for path, prefix in required.items()
        )
    if type(value) is list:
        return all(f"{path}:{prefix}" in value for path, prefix in required.items())
    return False


def _runtime_policy_matches(runtime: Mapping[str, Any]) -> bool:
    policy = runtime.get("policy")
    resources = runtime.get("resources")
    namespaces = runtime.get("namespaces")
    if type(policy) is not dict or type(resources) is not dict or type(namespaces) is not dict:
        return False
    return (
        policy.get("cap_drop") == ["ALL"]
        and policy.get("cap_add") == list(APPROVED_CAPABILITIES)
        and policy.get("no_new_privileges") is True
        and policy.get("published_ports") is False
        and policy.get("host_network") is False
        and policy.get("named_volume_opt_data") is True
        and resources.get("nano_cpus") == 500000000
        and resources.get("memory_limit") == 536870912
        and resources.get("pids_limit") == 256
        and resources.get("shm_size") == 67108864
        and _runtime_tmpfs_matches(resources.get("tmpfs"))
        and resources.get("restart_policy") == "no"
        and resources.get("log_driver") == "k8s-file"
        and namespaces.get("network") != "host"
        and namespaces.get("ipc") != "host"
        and namespaces.get("pid") != "host"
    )


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


def _empty_official_observations() -> dict[str, Any]:
    return {
        "executor_preflight": "not_run",
        "image_pull": "not_run",
        "image_identity": "not_run",
        "compose_config": "not_run",
        "container_start": "not_run",
        "runtime_inspection": "not_run",
        "readiness": "not_run",
        "exit": "not_run",
        "exit_code": None,
        "teardown": "not_run",
        "leftover_resources": {"containers": -1, "networks": -1, "volumes": -1},
        "policy_inspection": "not_run",
        "applied_policy": "not_verified",
    }


def _runtime_identity_matches(runtime: Mapping[str, Any]) -> bool:
    return (
        runtime.get("path") == OFFICIAL_RUNTIME_PATH
        and runtime.get("args") == list(PROBE_COMMAND)
        and (
            runtime.get("entrypoint") is None
            or runtime.get("entrypoint") == OFFICIAL_RUNTIME_ENTRYPOINT
        )
    )


def _cleanup_probe(
    rendered: RenderedProbe,
    compose_path: Path,
    runner: Runner,
    diagnostic: str,
) -> tuple[CommandResult, dict[str, int], str]:
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
    return teardown_result, leftovers, diagnostic


def run_probe(
    rendered: RenderedProbe,
    compose_path: Path,
    *,
    capability_policy: Mapping[str, Any] | None = None,
    executor_info: Mapping[str, Any] | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
    runner: Runner = lambda command, timeout: run_bounded(command, timeout=timeout),
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> ProbeResult:
    """Run only the official image and derive evidence from bounded commands."""

    policy = dict(CAPABILITY_POLICY if capability_policy is None else capability_policy)
    validate_capability_policy(policy)
    validate_rendered_probe(rendered)
    require(timeout_seconds > 0 and timeout_seconds <= 300, "probe timeout is outside the bounded range")
    require(poll_interval_seconds > 0 and poll_interval_seconds <= 5, "probe poll interval is outside the bounded range")
    observations = _empty_official_observations()
    executor: dict[str, Any] = {}
    image: dict[str, Any] = {}
    runtime: dict[str, Any] = {}
    log_tail = ""
    diagnostic = ""
    status = "blocked"
    classification = "executor_result_unknown"
    readiness_port: int | None = None
    exit_code: int | None = None
    timed_out = False
    teardown_result = CommandResult(None, "", False, "teardown not attempted")
    leftovers = {"containers": -1, "networks": -1, "volumes": -1}

    if policy["status"] != "approved":
        observations["executor_preflight"] = "not_run"
        return ProbeResult(
            status,
            "capability_policy_pending",
            None,
            None,
            False,
            None,
            {"containers": 0, "networks": 0, "volumes": 0},
            "issue 250 capability policy is not reviewed",
            observations=observations,
        )

    try:
        if executor_info is None:
            executor = _collect_executor_info(runner)
        else:
            executor = dict(executor_info)
            validate_executor_info(executor)
        observations["executor_preflight"] = "passed"

        pull_result = _call_runner(
            runner,
            (EXECUTOR, "image", "pull", OFFICIAL_IMAGE_REFERENCE),
            60,
        )
        if pull_result.timed_out or pull_result.returncode != 0:
            classification = "image_pull_failed"
            diagnostic = summarize_result(pull_result)
        else:
            observations["image_pull"] = "passed"
            inspect_result = _call_runner(
                runner,
                (EXECUTOR, "image", "inspect", "--format", "json", OFFICIAL_IMAGE_REFERENCE),
                10,
            )
            if inspect_result.timed_out or inspect_result.returncode != 0:
                classification = "image_identity_unavailable"
                diagnostic = summarize_result(inspect_result)
            else:
                try:
                    image = validate_image_binding(_image_inspect_from_output(inspect_result.output))
                except (FixtureJSONError, ValidationError) as exc:
                    classification = "image_identity_mismatch"
                    diagnostic = compact_error(exc)
                else:
                    observations["image_identity"] = "passed"
                    config_result = _call_runner(
                        runner,
                        compose_command(rendered.project, compose_path, "config"),
                        10,
                    )
                    if config_result.timed_out or config_result.returncode != 0:
                        classification = "compose_config_failed"
                        diagnostic = summarize_result(config_result)
                    else:
                        observations["compose_config"] = "passed"
                        up_result = _call_runner(
                            runner,
                            compose_command(rendered.project, compose_path, "up", "--detach", "--no-build", "gateway"),
                            30,
                        )
                        if up_result.timed_out or up_result.returncode != 0:
                            classification = "start_failed"
                            timed_out = up_result.timed_out
                            diagnostic = summarize_result(up_result)
                        else:
                            observations["container_start"] = "started"
                            try:
                                runtime = _inspect_runtime_container(rendered.project, runner)
                            except (FixtureJSONError, ValidationError, ProbeError) as exc:
                                classification = "runtime_inspection_failed"
                                diagnostic = compact_error(exc)
                            else:
                                observations["runtime_inspection"] = "passed"
                                observations["policy_inspection"] = "passed"
                                policy_matches = _runtime_policy_matches(runtime)
                                observations["applied_policy"] = "passed" if policy_matches else "failed"
                                if not _runtime_identity_matches(runtime):
                                    classification = "runtime_identity_mismatch"
                                else:
                                    container_id = runtime["container_id"]
                                    deadline = clock() + timeout_seconds
                                    classification = "timeout_waiting_for_readiness"
                                    while True:
                                        log_result = _call_runner(
                                            runner,
                                            (EXECUTOR, "logs", "--tail", str(MAX_LOG_LINES), container_id),
                                            5,
                                        )
                                        log_tail = summarize_output(log_result.output)
                                        diagnostic = summarize_result(log_result)
                                        if log_result.timed_out:
                                            timed_out = True
                                            classification = "logs_timeout"
                                            break
                                        if log_result.returncode != 0:
                                            classification = "logs_failed"
                                            break
                                        try:
                                            candidate_port = parse_readiness_output(log_result.output)
                                        except ProbeError as exc:
                                            classification = "invalid_readiness_output"
                                            diagnostic = compact_error(exc)
                                            break
                                        try:
                                            previous_pid = runtime.get("pid")
                                            latest_runtime = _inspect_container_by_id(container_id, runner)
                                            if type(previous_pid) is int and previous_pid > 0 and (latest_runtime.get("pid") or 0) <= 0:
                                                latest_runtime["pid"] = previous_pid
                                            runtime = latest_runtime
                                        except (FixtureJSONError, ValidationError, ProbeError) as exc:
                                            classification = "runtime_inspection_failed"
                                            diagnostic = compact_error(exc)
                                            break
                                        observations["runtime_inspection"] = "passed"
                                        observations["policy_inspection"] = "passed"
                                        policy_matches = _runtime_policy_matches(runtime)
                                        observations["applied_policy"] = "passed" if policy_matches else "failed"
                                        state = runtime["state"]
                                        running = state.get("running") is True or state.get("status") in {"running", "up"}
                                        observed_exit = state.get("exit_code") if not running else None
                                        exit_code = observed_exit
                                        observations["exit_code"] = exit_code
                                        if exit_code is not None:
                                            observations["exit"] = "observed"
                                        if candidate_port is not None:
                                            if policy_matches and _runtime_identity_matches(runtime):
                                                readiness_port = candidate_port
                                                status, classification = "ready", "readiness_marker"
                                                observations["readiness"] = "ready"
                                            else:
                                                classification = "policy_not_applied" if not policy_matches else "runtime_identity_mismatch"
                                                observations["readiness"] = "blocked"
                                            break
                                        if not running and exit_code is not None:
                                            classification = "policy_not_applied" if not policy_matches else classify_probe(
                                                readiness_port=None,
                                                returncode=exit_code,
                                                timed_out=False,
                                            )[1]
                                            observations["readiness"] = "not_ready"
                                            break
                                        remaining = deadline - clock()
                                        if remaining <= 0:
                                            timed_out = True
                                            classification = "policy_not_applied" if not policy_matches else "timeout_waiting_for_readiness"
                                            observations["readiness"] = "timeout"
                                            break
                                        sleeper(min(poll_interval_seconds, remaining))
    except Exception as exc:
        classification = classification if classification != "executor_result_unknown" else "executor_failure"
        diagnostic = compact_error(exc)
    finally:
        teardown_result, leftovers, diagnostic = _cleanup_probe(
            rendered,
            compose_path,
            runner,
            diagnostic,
        )
        observations["teardown"] = "passed" if teardown_result.returncode == 0 and not teardown_result.timed_out else "failed"
        observations["leftover_resources"] = dict(leftovers)

    if not zero_leftovers(leftovers):
        status = "blocked"
        classification = "cleanup_leftovers"
    if teardown_result.returncode != 0 or teardown_result.timed_out:
        status = "blocked"
        classification = "cleanup_failed"
    if status != "ready":
        status = "blocked"
        readiness_port = None
    observations["exit_code"] = exit_code
    if observations["container_start"] == "started" and observations["exit"] == "not_run":
        # A running container at the deadline has no observed process exit;
        # retain that distinction instead of treating Podman's default
        # ExitCode=0 field as a termination event.
        observations["exit"] = "not_observed"
    return ProbeResult(
        status,
        classification,
        readiness_port,
        exit_code,
        timed_out,
        teardown_result.returncode,
        leftovers,
        compact_error(diagnostic),
        executor=executor,
        image=image,
        observations=observations,
        runtime_identity=runtime,
        log_tail=log_tail,
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
    require(tuple(PINNED_CASE_KINDS) == EXPECTED_CASE_IDS, "pinned case kind inventory changed")
    require(tuple(PINNED_CASE_CONTRACTS) == EXPECTED_CASE_IDS, "pinned case inventory changed")
    for index, case in enumerate(root["cases"]):
        row = _validate_case_shape(case, index)
        require(row["kind"] == PINNED_CASE_KINDS[row["id"]], f"case {row['id']} kind changed")
        pinned_input, pinned_expected = PINNED_CASE_CONTRACTS[row["id"]]
        strict_equal(row["input"], pinned_input, f"case {row['id']} input")
        strict_equal(row["expected"], pinned_expected, f"case {row['id']} expected")
        expected = _case_outcome(row)
        strict_equal(expected, row["expected"], f"case {row['id']} outcome")


def _validate_cleanup_scope(scope: Any) -> dict[str, str]:
    record = strict_keys(scope, OFFICIAL_CLEANUP_KEYS, "official cleanup scope")
    project = _text(record["project"], "cleanup project", max_length=64)
    require(PROJECT_RE.fullmatch(project) is not None, "cleanup project is not canonical")
    require(record["network"] == f"{project}_internal", "cleanup network is not project-bound")
    require(record["volume"] == f"{project}_data", "cleanup volume is not project-bound")
    return record


def validate_official_evidence_document(
    evidence: Any,
    cases_document: Mapping[str, Any],
) -> None:
    """Validate generated official evidence without accepting unexecuted claims."""

    record = strict_keys(evidence, OFFICIAL_EVIDENCE_KEYS, "official image evidence")
    require(record["schema"] == OFFICIAL_EVIDENCE_SCHEMA, "official evidence schema changed")
    require(record["operation"] == OPERATION, "official evidence operation changed")
    require(record["synthetic_only"] is False, "official evidence must not be synthetic-only")
    require(record["live_run"] is True, "official evidence must identify the live run")
    require(record["status"] in {"blocked", "ready"}, "official evidence status changed")
    require(_int(record["teardown_exit_code"], "official teardown exit code") == 0, "official teardown failed")
    require(record["correctness_executor"] == "rootless_podman", "official executor changed")
    require(record["ssh_target"] == SSH_TARGET, "official SSH boundary changed")

    executor = strict_keys(record["executor"], OFFICIAL_EXECUTOR_KEYS, "official executor identity")
    validate_executor_info(executor)
    _validate_cleanup_scope(record["cleanup_scope"])

    image = strict_keys(record["image"], OFFICIAL_IMAGE_KEYS, "official image identity")
    require(image["reference"] == OFFICIAL_IMAGE_REFERENCE, "official image reference changed")
    require(image["repository"] == OFFICIAL_IMAGE_REPOSITORY, "official image repository changed")
    require(image["tag"] == OFFICIAL_IMAGE_TAG, "official image tag changed")
    require(image["requested_digest"] == OFFICIAL_IMAGE_DIGEST, "official requested digest changed")
    require(image["pull_status"] == "passed", "official image pull was not executed")
    require(image["inspect_status"] == "passed", "official image inspect was not executed")
    require(type(image["image_id"]) is str and HEX64_RE.fullmatch(image["image_id"]) is not None, "official image id is invalid")
    require(type(image["repo_tags"]) is list, "official RepoTags are not retained")
    for tag in image["repo_tags"]:
        require(tag == f"{OFFICIAL_IMAGE_REPOSITORY}:{OFFICIAL_IMAGE_TAG}", "official RepoTags drifted")
    require(type(image["repo_digests"]) is list and image["repo_digests"], "official RepoDigests are not retained")
    require(OFFICIAL_IMAGE_REPO_DIGEST in image["repo_digests"], "official RepoDigest binding is absent")
    require(image["repo_digest_verified"] is True, "official RepoDigest was not verified")
    require(image["manifest_digest"] == OFFICIAL_IMAGE_DIGEST, "official manifest digest changed")
    require(image["revision_label"] == OFFICIAL_IMAGE_REVISION, "official revision label changed")
    require(image["entrypoint"] == OFFICIAL_IMAGE_CONFIG_ENTRYPOINT, "official image entrypoint metadata changed")
    require(image["cmd"] == OFFICIAL_IMAGE_CONFIG_CMD, "official image command metadata changed")
    require(image["user"] == OFFICIAL_IMAGE_CONFIG_USER, "official image user changed")
    require(image["working_dir"] == OFFICIAL_IMAGE_CONFIG_WORKING_DIR, "official image working directory changed")

    require(record["command_candidate"] == list(PROBE_COMMAND), "official command candidate changed")
    require(record["command_support"] == "official_image_runtime_command", "official command support claim changed")
    require(record["readiness_marker"] == READINESS_PREFIX, "official readiness marker changed")
    require(record["readiness_source_status"] == "container_provenance_podman_logs", "readiness source is not container-provenance logs")
    strict_equal(record["capability_policy"], cases_document["capability_policy"], "official capability policy")
    strict_equal(record["isolation_policy"], cases_document["isolation_policy"], "official isolation policy")

    observations = strict_keys(record["observations"], OFFICIAL_OBSERVATION_KEYS, "official observations")
    require(observations["executor_preflight"] == "passed", "executor preflight was not executed")
    require(observations["image_pull"] == "passed", "image pull was not executed")
    require(observations["image_identity"] == "passed", "image identity was not verified")
    require(observations["compose_config"] == "passed", "Compose config was not executed")
    require(observations["container_start"] == "started", "container startup was not observed")
    require(observations["runtime_inspection"] == "passed", "runtime inspect was not executed")
    require(observations["policy_inspection"] == "passed", "applied policy was not inspected")
    require(observations["readiness"] in {"timeout", "not_ready", "blocked", "ready"}, "official readiness result changed")
    require(observations["exit"] in {"observed", "not_observed"}, "official exit observation changed")
    if observations["exit"] == "observed":
        require(observations["exit_code"] is not None, "observed exit lacks an exit code")
    else:
        require(observations["exit_code"] is None, "unobserved exit has an exit code")
    require(observations["teardown"] == "passed", "official teardown observation changed")
    require(observations["applied_policy"] in {"passed", "failed"}, "official applied-policy result is not derived")
    leftovers = strict_keys(observations["leftover_resources"], ("containers", "networks", "volumes"), "official leftovers")
    for resource_name, count in leftovers.items():
        _int(count, f"official leftovers.{resource_name}")
    require(leftovers == {"containers": 0, "networks": 0, "volumes": 0}, "official cleanup must prove zero leftovers")

    runtime = strict_keys(record["runtime_identity"], OFFICIAL_RUNTIME_KEYS, "official runtime identity")
    require(runtime["status"] == "verified", "official runtime identity was not verified")
    require(type(runtime["container_id"]) is str and re.fullmatch(r"[0-9a-f]{12,64}", runtime["container_id"]) is not None, "official container id is invalid")
    require(_int(runtime["pid"], "official PID 1") > 0, "official PID 1 is invalid")
    require(runtime["path"] == OFFICIAL_RUNTIME_PATH, "official PID 1 path changed")
    strict_equal(runtime["args"], list(PROBE_COMMAND), "official PID 1 arguments")
    require(runtime["entrypoint"] is None or runtime["entrypoint"] == OFFICIAL_RUNTIME_ENTRYPOINT, "official runtime entrypoint changed")
    policy = strict_keys(runtime["policy"], OFFICIAL_RUNTIME_POLICY_KEYS, "official applied policy")
    resources = strict_keys(runtime["resources"], OFFICIAL_RUNTIME_RESOURCE_KEYS, "official runtime resources")
    namespaces = strict_keys(runtime["namespaces"], OFFICIAL_RUNTIME_NAMESPACE_KEYS, "official runtime namespaces")
    require(type(policy["cap_drop"]) is list, "runtime CapDrop was not retained")
    require(type(policy["cap_add"]) is list, "runtime CapAdd was not retained")
    require(type(policy["security_opt"]) is list, "runtime SecurityOpt was not retained")
    _bool(policy["no_new_privileges"], "runtime NoNewPrivileges")
    _bool(policy["published_ports"], "runtime published ports")
    _bool(policy["host_network"], "runtime host network")
    _bool(policy["named_volume_opt_data"], "runtime data volume")
    _int(resources["nano_cpus"], "runtime CPU limit")
    _int(resources["memory_limit"], "runtime memory limit")
    _int(resources["pids_limit"], "runtime PID limit")
    _int(resources["shm_size"], "runtime shared-memory limit")
    require(_runtime_tmpfs_matches(resources["tmpfs"]), "runtime tmpfs policy changed")
    require(resources["restart_policy"] == "no", "runtime restart policy changed")
    require(resources["log_driver"] == "k8s-file", "runtime log driver changed")
    require(namespaces["network"] != "host", "runtime network namespace escaped to host")
    require(namespaces["ipc"] != "host", "runtime IPC namespace escaped to host")
    require(namespaces["pid"] != "host", "runtime PID namespace escaped to host")
    derived_policy = "passed" if _runtime_policy_matches(runtime) else "failed"
    require(observations["applied_policy"] == derived_policy, "applied policy claim was not derived from inspect")
    if record["status"] == "ready":
        require(derived_policy == "passed", "readiness cannot claim unverified policy")
        require(observations["readiness"] == "ready", "ready status lacks readiness observation")
    else:
        require(READINESS_PREFIX not in record["diagnostic"], "blocked diagnostic contains a readiness marker")
        require(READINESS_PREFIX not in record["log_tail"], "blocked log tail contains a readiness marker")
        require(record["status"] == "blocked", "blocked evidence status changed")

    _text(record["diagnostic"], "official diagnostic", max_length=MAX_ERROR_OUTPUT)
    _text(record["log_tail"], "official log tail", max_length=MAX_LOG_BYTES)
    require(type(record["limitations"]) is list, "official limitations must be an array")
    if record["status"] == "blocked":
        require("readiness_not_proven" in record["limitations"], "blocked evidence must state readiness is unproved")
    if derived_policy == "failed":
        require("runtime_policy_mismatch" in record["limitations"], "policy mismatch must be recorded")
    require("official_upstream_image_only" in record["limitations"], "official image boundary is missing")
    require("no_provider_or_browser_auth" in record["limitations"], "provider boundary is missing")


def generate_official_evidence(
    result: ProbeResult,
    rendered: RenderedProbe,
    cases_document: Mapping[str, Any],
) -> dict[str, Any]:
    """Build the checked-in record from the bounded runner result only."""

    observations = dict(result.observations)
    record = {
        "schema": OFFICIAL_EVIDENCE_SCHEMA,
        "operation": OPERATION,
        "synthetic_only": False,
        "live_run": True,
        "status": result.status,
        "classification": result.classification,
        "teardown_exit_code": result.teardown_exit_code,
        "correctness_executor": "rootless_podman",
        "ssh_target": SSH_TARGET,
        "executor": dict(result.executor),
        "image": dict(result.image),
        "command_candidate": list(PROBE_COMMAND),
        "command_support": "official_image_runtime_command",
        "readiness_marker": READINESS_PREFIX,
        "readiness_source_status": "container_provenance_podman_logs",
        "capability_policy": dict(cases_document["capability_policy"]),
        "isolation_policy": dict(cases_document["isolation_policy"]),
        "cleanup_scope": {
            "project": rendered.project,
            "network": rendered.network,
            "volume": rendered.volume,
        },
        "observations": observations,
        "runtime_identity": dict(result.runtime_identity),
        "diagnostic": result.diagnostic,
        "log_tail": result.log_tail,
        "limitations": [
            "official_upstream_image_only",
            *( ["readiness_not_proven"] if result.status != "ready" else [] ),
            *( ["runtime_policy_mismatch"] if observations.get("applied_policy") != "passed" else [] ),
            "no_concrete_upstream_error_observed",
            "no_provider_or_browser_auth",
            "no_source_equivalence_or_production_claim",
        ],
    }
    validate_redaction(record)
    return record


def _success_payload(
    document: Mapping[str, Any],
    *,
    official_evidence: Mapping[str, Any],
    rendered: RenderedProbe | None = None,
    image_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "ok": True,
        "compatible": False,
        "live_run": False,
        "proof_status": document["proof_status"],
        "evidence_status": official_evidence["status"],
        "case_count": len(document["cases"]),
    }
    if rendered is not None:
        payload["rendered"] = rendered.public_metadata()
    if image_binding is not None:
        payload["image_binding"] = dict(image_binding)
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
    parser = ControlledArgumentParser(add_help=False, description="Validate the official rootless Hermes gateway readiness boundary")
    parser.add_argument("--cases", type=Path, default=CASES_PATH)
    parser.add_argument("--official-evidence", type=Path, default=OFFICIAL_EVIDENCE_PATH)
    parser.add_argument("--image-inspect", type=Path)
    parser.add_argument("--render", type=Path)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--allow-live", action="store_true")
    parser.add_argument("--stack-id", default="smoke")
    parser.add_argument("--instance", default="one")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parse_args(sys.argv[1:] if argv is None else argv)
        document = load_json(args.cases)
        validate_redaction(document)
        validate_cases_document(document)
        image_binding: dict[str, Any] | None = None
        if args.image_inspect is not None:
            if args.run:
                raise ValidationError("live execution cannot use synthetic image inspect input")
            image_binding = validate_image_binding(
                _image_inspect_from_value(load_json(args.image_inspect))
            )
        rendered: RenderedProbe | None = None
        if args.render is not None or args.run:
            rendered = render_probe(args.stack_id, instance=args.instance)
        if args.render is not None and rendered is not None:
            try:
                args.render.write_text(rendered.compose, encoding="utf-8")
            except OSError as exc:
                raise ValidationError("render output could not be written") from exc
        if not args.run:
            official_evidence = load_json(args.official_evidence)
            validate_redaction(official_evidence)
            validate_official_evidence_document(official_evidence, document)
            print(
                json.dumps(
                    _success_payload(
                        document,
                        official_evidence=official_evidence,
                        rendered=rendered,
                        image_binding=image_binding,
                    ),
                    separators=(",", ":"),
                )
            )
            return 0
        if not args.allow_live:
            print(json.dumps(_failure_payload(ERROR_CODE, "live runner requires explicit --allow-live"), separators=(",", ":")))
            return 2
        if rendered is None:
            rendered = render_probe(args.stack_id, instance=args.instance)
        with tempfile.TemporaryDirectory(prefix="hermes-gateway-readiness-") as temporary:
            compose_path = Path(temporary) / "compose.yml"
            compose_path.write_text(rendered.compose, encoding="utf-8")
            result = run_probe(rendered, compose_path)
        official_evidence = generate_official_evidence(result, rendered, document)
        validate_official_evidence_document(official_evidence, document)
        try:
            args.official_evidence.write_text(
                json.dumps(official_evidence, indent=2) + "\n",
                encoding="utf-8",
            )
        except OSError as exc:
            raise ValidationError("official evidence could not be written") from exc
        payload = {
            "ok": result.status == "ready",
            "compatible": False,
            "live_run": True,
            "evidence_status": official_evidence["status"],
            "probe": result.public(),
        }
        print(json.dumps(payload, separators=(",", ":")))
        return 0 if result.status == "ready" else 3
    except (FixtureJSONError, ValidationError, ProbeError, OSError, ValueError, TypeError) as exc:
        print(json.dumps(_failure_payload(ERROR_CODE, exc), separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
