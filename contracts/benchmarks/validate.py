#!/usr/bin/env python3
"""Validate the shared, offline benchmark evidence contract.

The format is the hand-off boundary for later web and Apple harnesses.  This
module intentionally uses only the Python standard library: it reads local JSON,
recomputes the recorded distribution, verifies the reviewed artifact set and
sample provenance, and emits bounded diagnostics.  It never starts Hermes, opens
a socket, runs a browser, or contacts a service.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import sys
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN, localcontext
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = ROOT.parents[1]
EVIDENCE_PATH = ROOT / "benchmark-evidence.json"
BASELINE_PATH = ROOT / "validation-baseline.json"
WEB_BENCHMARK_ROOT = REPOSITORY_ROOT / "apps" / "web" / "benchmarks" / "production-build"
WEB_EVIDENCE_PATH = WEB_BENCHMARK_ROOT / "evidence" / "benchmark-evidence.json"

SCHEMA = "hermternal.benchmark-evidence.v1"
EVIDENCE_ID = "shared-format-example"
BASELINE_EVIDENCE_ID = "validator-baseline"
WEB_PRODUCTION_BUILD_EVIDENCE_ID = "web-production-build-baseline"
PINNED_HERMES_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
ERROR_CODE = "benchmark_evidence_validation_error"

MAX_JSON_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_INTEGER_DIGITS = 1000
MAX_JSON_NODES = 4096
MAX_OBJECT_KEYS = 64
MAX_ARRAY_LENGTH = 2048
MAX_STRING_LENGTH = 4096
MAX_ERROR_OUTPUT = 240
MAX_RUNS = 32
MAX_REPETITIONS = 10_000
MIN_REPETITIONS = 30

ROOT_KEYS = (
    "schema",
    "evidence_id",
    "revision",
    "metric",
    "method",
    "runs",
    "artifacts",
    "artifact_manifest_sha256",
    "redaction",
    "threshold",
    "budget",
)
REVISION_KEYS = (
    "commit_sha",
    "fixture_id",
    "fixture_version",
    "fixture_sha256",
    "hermes_source_sha",
)
METRIC_KEYS = ("name", "unit", "clock")
METHOD_KEYS = (
    "percentile_method",
    "position_formula",
    "rounding",
    "quantiles",
    "minimum_repetitions",
)
QUANTILE_KEYS = ("p50", "p95", "p99")
RUN_KEYS = (
    "id",
    "platform",
    "environment",
    "state",
    "build_mode",
    "optimization",
    "command",
    "repetitions",
    "raw_samples",
    "sample_provenance_sha256",
    "distribution",
)
PROVENANCE_INPUT_KEYS = (
    "id",
    "platform",
    "environment",
    "state",
    "build_mode",
    "optimization",
    "command",
    "repetitions",
    "raw_samples",
)
ENVIRONMENT_KEYS = (
    "platform",
    "os",
    "architecture",
    "device",
    "runtime",
    "browser",
)
DISTRIBUTION_KEYS = ("min", "p50", "p95", "p99", "max", "mean")
ARTIFACT_KEYS = ("path", "bytes", "sha256")
REDACTION_KEYS = (
    "policy",
    "synthetic_only",
    "contains_credentials",
    "contains_tokens",
    "contains_user_data",
    "contains_live_hosts",
    "contains_transcripts",
)
WEB_WORKLOAD_KEYS = (
    "schema", "fixture_id", "fixture_version", "build", "repetitions", "limits", "network", "launcher", "hermes_source_sha"
)
WEB_TRACE_KEYS = (
    "schema", "recorded_at_utc", "source_commit_sha", "fixture_sha256", "environment", "build_input", "toolchain",
    "network_mode", "limits", "warmup_excluded_from_distribution", "runs"
)
WEB_TOOLCHAIN_KEYS = (
    "package_json", "bun_lock", "benchmark_runner", "sandbox_runner", "artifact_scanner", "node_executable",
    "bun_executable", "python_executable", "sandbox_executable", "dependencies", "vite", "sveltekit",
    "vite_svelte_plugin", "svelte", "typescript_native"
)
WEB_FILE_IDENTITY_KEYS = ("bytes", "sha256")
WEB_TREE_IDENTITY_KEYS = ("files", "symlinks", "bytes", "sha256")
WEB_OBSERVATION_KEYS = (
    "sequence", "duration_ms", "exit_code", "stdout_bytes", "stderr_bytes", "artifact_files", "artifact_bytes", "artifact_sha256"
)
WEB_TRACE_RUN_KEYS = ("provenance", "samples")

PLATFORMS = frozenset({"shared", "web", "ios", "ipados", "macos"})
STATES = frozenset({"cold", "warm"})
BUILD_MODES = frozenset({"production", "release", "not_applicable"})
OPTIMIZATION_MODES = frozenset({"normal", "optimized", "not_applicable"})
METRIC_UNITS = frozenset({"ms", "bytes", "count"})

CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
IDENTIFIER_RE = re.compile(r"[a-z][a-z0-9._-]{1,63}\Z")
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
UTC_TIMESTAMP_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z\Z")
ARTIFACT_PATH_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}\Z")

SENSITIVE_KEY_PARTS = frozenset(
    {
        "accesskey",
        "apikey",
        "authorization",
        "bearer",
        "clientsecret",
        "cookie",
        "credential",
        "csrf",
        "email",
        "host",
        "hostname",
        "ipaddress",
        "nonce",
        "password",
        "pkce",
        "privateaddress",
        "privatekey",
        "secret",
        "session",
        "ticket",
        "token",
        "transcript",
        "userdata",
        "useremail",
        "xapikey",
    }
)
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:authorization|bearer|cookie|credential|csrf|nonce|password|pkce|secret|session|ticket|token|"
    r"api[_ .-]*key|x-api-key|client[_ .-]*secret)"
    r"\s*(?:[:=]|is)\s*[^\s,;}\]]+"
)
BEARER_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:authorization\s*:\s*)?Bearer\s+[^\s,;}\]]+"
)
PRIVATE_KEY_RE = re.compile(r"(?i)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
EMAIL_RE = re.compile(r"(?i)\b[^\s@]+@[^\s@]+\.[A-Za-z]{2,}\b")
ABSOLUTE_PATH_RE = re.compile(r"(?:^|[\s=(])(?:/|[A-Za-z]:[\\/])")
URL_RE = re.compile(r"(?i)\b(?:https?|wss?)://[^\s,;}\]]+")
HOSTNAME_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9._/-])(?:localhost|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})"
    r"(?::[0-9]{1,5})?(?![A-Za-z0-9._-])"
)
IPV4_RE = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
IPV6_RE = re.compile(r"(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])")
# Provider credentials are forbidden even when they appear in a field that
# otherwise permits a harmless identifier, such as metric.name.  Keep the
# suffix bounded so diagnostics stay cheap while covering common GitHub,
# GitLab, OpenAI/Stripe, Slack, and JWT-shaped token markers.
PROVIDER_TOKEN_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:github_pat_|gh[pousr]_|glpat-|sk[-_]|xox[baprs]-|eyJ)"
    r"[A-Za-z0-9._-]{8,}(?![A-Za-z0-9._-])"
)

BASELINE_COMMANDS = {
    "normal": "python3 contracts/benchmarks/validate.py --skip-baseline",
    "optimized": "python3 -O contracts/benchmarks/validate.py --skip-baseline",
}

# These review anchors deliberately live in validator code rather than in the
# mutable evidence records.  A record may restate an identity, but it cannot
# redefine the source, environment, fixture bytes, run inventory, or artifact
# path set that this validator is willing to review.
EXPECTED_REVISIONS = {
    EVIDENCE_ID: {
        "commit_sha": "ca7fa38aa115bb0c0905d6b6f0630300aea5dfb4",
        "fixture_id": "shared-synthetic-workload",
        "fixture_version": "1.0.0",
        "fixture_sha256": "7f21daeb684773ae9c9bb81cc7fd0e78ffe6553afdf8508397d4b96f6a447404",
        "hermes_source_sha": PINNED_HERMES_SHA,
    },
    BASELINE_EVIDENCE_ID: {
        "commit_sha": "af4e3e975238102e295552841e202d7214c863ca",
        "fixture_id": "shared-benchmark-validator",
        "fixture_version": "1.0.0",
        "fixture_sha256": "7b0e11706465195dafb6a6821049b1dceb384ca77230bc3d21adbbc26450dbc5",
        "hermes_source_sha": PINNED_HERMES_SHA,
    },
    WEB_PRODUCTION_BUILD_EVIDENCE_ID: {
        "commit_sha": "e3db0441a32f9f5ba80ec148cfec91886d2c9cd9",
        "fixture_id": "web-production-build",
        "fixture_version": "1.0.0",
        "fixture_sha256": "36b391786b8b8a8d8524c8be8514f31364091ce13126f35599b6703213e41e6d",
        "hermes_source_sha": PINNED_HERMES_SHA,
    },
}
EXPECTED_FIXTURE_PATHS = {
    EVIDENCE_ID: "synthetic/workload.json",
    BASELINE_EVIDENCE_ID: "sample-provenance.json",
    WEB_PRODUCTION_BUILD_EVIDENCE_ID: "workload.json",
}
EXPECTED_FIXTURE_SCHEMAS = {
    EVIDENCE_ID: "hermternal.benchmark-fixture.v1",
    BASELINE_EVIDENCE_ID: "hermternal.benchmark-sample-provenance.v1",
    WEB_PRODUCTION_BUILD_EVIDENCE_ID: "hermternal.web-production-build-workload.v1",
}
EXPECTED_ARTIFACT_PATHS = {
    EVIDENCE_ID: ("synthetic/workload.json", "synthetic/trace.json"),
    BASELINE_EVIDENCE_ID: (
        "README.md",
        "benchmark-evidence.json",
        "validate.py",
        "test_validate.py",
        "sample-provenance.json",
        "synthetic/workload.json",
        "synthetic/trace.json",
    ),
    WEB_PRODUCTION_BUILD_EVIDENCE_ID: (
        "workload.json", "run.ts", "sandbox-runner.py", "artifact-scanner.py", "evidence/raw-trace.json"
    ),
}
# These byte identities are a second, code-pinned review anchor.  Artifact
# records may restate them, but cannot change the bytes that this validator
# considers reviewed.  The validator source is the one deliberate exception:
# pinning its own hash would create a self-hash cycle when this constant changes.
# Its submitted metadata is still checked against the local file when artifact
# verification is enabled; every other artifact, including the synthetic trace,
# must match this immutable anchor exactly.
EXPECTED_ARTIFACT_METADATA = {
    EVIDENCE_ID: (
        ("synthetic/workload.json", 4042, "7f21daeb684773ae9c9bb81cc7fd0e78ffe6553afdf8508397d4b96f6a447404"),
        ("synthetic/trace.json", 409, "0d94d8af0992133ddff7b48cfe9a3d3dd48846649da5fc8cc378e89193e0e5a7"),
    ),
    BASELINE_EVIDENCE_ID: (
        ("README.md", 7581, "cea7d5eae37398d0b6f4cad593be5d72b0bebb77c5a3bd73e5e08d4c835e944a"),
        ("benchmark-evidence.json", 6446, "aa652867dc336467ab07873964f54a9d5000cfb01b1d55756091be2e8797a6eb"),
        ("test_validate.py", 23177, "ce9e318da479b061cf8c6bdae10b2416d5cd577d93b2dfaec281f64745ee40bb"),
        ("sample-provenance.json", 2308, "7b0e11706465195dafb6a6821049b1dceb384ca77230bc3d21adbbc26450dbc5"),
        ("synthetic/workload.json", 4042, "7f21daeb684773ae9c9bb81cc7fd0e78ffe6553afdf8508397d4b96f6a447404"),
        ("synthetic/trace.json", 409, "0d94d8af0992133ddff7b48cfe9a3d3dd48846649da5fc8cc378e89193e0e5a7"),
    ),
    WEB_PRODUCTION_BUILD_EVIDENCE_ID: (
        ("workload.json", 1002, "36b391786b8b8a8d8524c8be8514f31364091ce13126f35599b6703213e41e6d"),
        ("run.ts", 49795, "d9d973f2826593e4ca34b2a52718dad76fc76393080480a78bb6686418dcc30b"),
        ("sandbox-runner.py", 6676, "f60e98a4a66baa2b4fce41b930e4768863522747d1d50f7ff09b80bef0e0a14c"),
        ("artifact-scanner.py", 5994, "79e68fabb9e8c83a171783eeb9eec5e5593a4871b05eebd46d18bff8feef87cb"),
        ("evidence/raw-trace.json", 17600, "aa77567fd1b0dbaa8b8b45dce2f6319c6fca8a55074e773af3d4b46f96727c4c"),
    ),
}
SELF_AUTHENTICATED_ARTIFACT_PATHS = {
    BASELINE_EVIDENCE_ID: frozenset({"validate.py"}),
}
EXPECTED_RUN_METADATA = {
    EVIDENCE_ID: {
        "web-cold-production": {
            "platform": "web",
            "environment": {
                "platform": "synthetic-web",
                "os": "synthetic-os-1",
                "architecture": "synthetic-arm64",
                "device": "synthetic-desktop",
                "runtime": "synthetic-browser-runtime",
                "browser": "synthetic-browser",
            },
            "state": "cold",
            "build_mode": "production",
            "optimization": "not_applicable",
            "command": "synthetic web cold workload",
            "repetitions": 30,
        },
        "web-warm-production": {
            "platform": "web",
            "environment": {
                "platform": "synthetic-web",
                "os": "synthetic-os-1",
                "architecture": "synthetic-arm64",
                "device": "synthetic-desktop",
                "runtime": "synthetic-browser-runtime",
                "browser": "synthetic-browser",
            },
            "state": "warm",
            "build_mode": "production",
            "optimization": "not_applicable",
            "command": "synthetic web warm workload",
            "repetitions": 30,
        },
        "ios-cold-release": {
            "platform": "ios",
            "environment": {
                "platform": "synthetic-ios",
                "os": "synthetic-os-1",
                "architecture": "synthetic-arm64",
                "device": "synthetic-phone",
                "runtime": "synthetic-swift-runtime",
                "browser": "not_applicable",
            },
            "state": "cold",
            "build_mode": "release",
            "optimization": "not_applicable",
            "command": "synthetic iOS cold workload",
            "repetitions": 30,
        },
        "ios-warm-release": {
            "platform": "ios",
            "environment": {
                "platform": "synthetic-ios",
                "os": "synthetic-os-1",
                "architecture": "synthetic-arm64",
                "device": "synthetic-phone",
                "runtime": "synthetic-swift-runtime",
                "browser": "not_applicable",
            },
            "state": "warm",
            "build_mode": "release",
            "optimization": "not_applicable",
            "command": "synthetic iOS warm workload",
            "repetitions": 30,
        },
    },
    BASELINE_EVIDENCE_ID: {
        "validator-normal-cold": {
            "platform": "shared",
            "environment": {
                "platform": "macOS-26.5.2-arm64-arm-64bit-Mach-O",
                "os": "Darwin-25.5.0",
                "architecture": "arm64",
                "device": "local-synthetic-runner",
                "runtime": "Python-3.14.6",
                "browser": "not_applicable",
            },
            "state": "cold",
            "build_mode": "not_applicable",
            "optimization": "normal",
            "command": BASELINE_COMMANDS["normal"],
            "repetitions": 30,
        },
        "validator-optimized-cold": {
            "platform": "shared",
            "environment": {
                "platform": "macOS-26.5.2-arm64-arm-64bit-Mach-O",
                "os": "Darwin-25.5.0",
                "architecture": "arm64",
                "device": "local-synthetic-runner",
                "runtime": "Python-3.14.6",
                "browser": "not_applicable",
            },
            "state": "cold",
            "build_mode": "not_applicable",
            "optimization": "optimized",
            "command": BASELINE_COMMANDS["optimized"],
            "repetitions": 30,
        },
    },
    WEB_PRODUCTION_BUILD_EVIDENCE_ID: {
        "web-production-build-cold": {
            "platform": "web",
            "environment": {
                "platform": "darwin-25.5.0",
                "os": "Darwin-25.5.0",
                "architecture": "arm64",
                "device": "local-Apple M2 Max",
                "runtime": "Bun-1.3.14; Node-v26.7.0; Vite-vite/8.2.0 darwin-arm64 node-v26.7.0",
                "browser": "not_applicable",
            },
            "state": "cold",
            "build_mode": "production",
            "optimization": "not_applicable",
            "command": "node node_modules/vite/bin/vite.js build --configLoader runner",
            "repetitions": 30,
        },
        "web-production-build-warm": {
            "platform": "web",
            "environment": {
                "platform": "darwin-25.5.0",
                "os": "Darwin-25.5.0",
                "architecture": "arm64",
                "device": "local-Apple M2 Max",
                "runtime": "Bun-1.3.14; Node-v26.7.0; Vite-vite/8.2.0 darwin-arm64 node-v26.7.0",
                "browser": "not_applicable",
            },
            "state": "warm",
            "build_mode": "production",
            "optimization": "not_applicable",
            "command": "node node_modules/vite/bin/vite.js build --configLoader runner",
            "repetitions": 30,
        },
    },
}
EXPECTED_METRICS = {
    EVIDENCE_ID: {"name": "operation_duration", "unit": "ms", "clock": "monotonic"},
    BASELINE_EVIDENCE_ID: {"name": "validator_duration", "unit": "ms", "clock": "monotonic"},
    WEB_PRODUCTION_BUILD_EVIDENCE_ID: {"name": "production_build_duration", "unit": "ms", "clock": "monotonic"},
}


class ValidationError(ValueError):
    """A controlled, non-sensitive contract validation failure."""


def require(condition: bool, message: str) -> None:
    """Raise an explicit exception so checks survive optimized Python runs."""

    if not condition:
        raise ValidationError(message)


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValidationError("duplicate JSON object key is not allowed")
    return dict(pairs)


def _reject_nonfinite_json_constant(value: str) -> Any:
    del value
    raise ValidationError("non-finite JSON number is not allowed")


def _parse_json_integer(value: str) -> int:
    digits = value.lstrip("-")
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise ValidationError("JSON integer digit limit exceeded")
    return int(value)


def _parse_json_bytes(raw: bytes) -> Any:
    require(len(raw) <= MAX_JSON_BYTES, "input exceeds the bounded byte limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValidationError("input is not valid UTF-8") from None
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonfinite_json_constant,
            parse_int=_parse_json_integer,
        )
    except (ValidationError, json.JSONDecodeError, RecursionError, ValueError):
        raise ValidationError("input is malformed JSON") from None
    validate_json_tree(value)
    return value


def load_json(path: Path) -> Any:
    """Read bounded UTF-8 JSON with duplicate-key and numeric checks."""

    try:
        return _parse_json_bytes(path.read_bytes())
    except OSError:
        raise ValidationError("input could not be read") from None


def validate_json_tree(value: Any, label: str = "input", depth: int = 0) -> int:
    """Apply portable bounds before the closed benchmark schema is inspected."""

    require(depth <= MAX_JSON_DEPTH, f"{label}: JSON depth exceeds the bounded limit")
    if isinstance(value, dict):
        require(len(value) <= MAX_OBJECT_KEYS, f"{label}: object has too many keys")
        nodes = 1
        for key, child in value.items():
            require(type(key) is str, f"{label}: object keys must be text")
            require(len(key) <= MAX_STRING_LENGTH, f"{label}: object key is too long")
            require(CONTROL_RE.search(key) is None, f"{label}: object key contains control characters")
            nodes += validate_json_tree(child, f"{label}.<field>", depth + 1)
            require(nodes <= MAX_JSON_NODES, f"{label}: JSON node count exceeds the bounded limit")
        return nodes
    if isinstance(value, list):
        require(len(value) <= MAX_ARRAY_LENGTH, f"{label}: array is too long")
        nodes = 1
        for child in value:
            nodes += validate_json_tree(child, f"{label}[]", depth + 1)
            require(nodes <= MAX_JSON_NODES, f"{label}: JSON node count exceeds the bounded limit")
        return nodes
    if type(value) is str:
        require(len(value) <= MAX_STRING_LENGTH, f"{label}: string is too long")
        require(CONTROL_RE.search(value) is None, f"{label}: control character is not allowed")
        return 1
    if type(value) is float:
        require(math.isfinite(value), f"{label}: non-finite JSON number is not allowed")
        return 1
    require(value is None or type(value) in {bool, int}, f"{label}: unsupported JSON value type")
    return 1


def _strict_keys(value: Any, expected: tuple[str, ...], label: str) -> dict[str, Any]:
    require(type(value) is dict, f"{label} must be an object")
    require(tuple(value.keys()) == expected, f"{label} keys or ordering changed")
    return value


def _text(value: Any, label: str, *, pattern: re.Pattern[str] | None = None) -> str:
    require(type(value) is str, f"{label} must be text")
    require(0 < len(value) <= MAX_STRING_LENGTH, f"{label} has an invalid length")
    require(CONTROL_RE.search(value) is None, f"{label} contains control characters")
    if pattern is not None:
        require(pattern.fullmatch(value) is not None, f"{label} has an invalid format")
    return value


def _bool(value: Any, label: str) -> bool:
    require(type(value) is bool, f"{label} must be boolean")
    return value


def _integer(value: Any, label: str, *, minimum: int | None = None, maximum: int | None = None) -> int:
    require(type(value) is int and type(value) is not bool, f"{label} must be an integer")
    if minimum is not None:
        require(value >= minimum, f"{label} is below the minimum")
    if maximum is not None:
        require(value <= maximum, f"{label} exceeds the maximum")
    return value


def _finite_decimal(value: Any, label: str, *, positive: bool = False) -> Decimal:
    require(type(value) in {int, float} and type(value) is not bool, f"{label} must be numeric")
    try:
        number = Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise ValidationError(f"{label} is not numeric") from None
    require(number.is_finite(), f"{label} must be finite")
    require(number > 0 if positive else number >= 0, f"{label} must be non-negative")
    return number


def _reject_sensitive_text(text: str, label: str, *, allow_relative_artifact_path: bool = False) -> None:
    require(PROVIDER_TOKEN_RE.search(text) is None, f"{label} contains a provider token")
    require(SENSITIVE_ASSIGNMENT_RE.search(text) is None, f"{label} contains sensitive material")
    require(BEARER_RE.search(text) is None, f"{label} contains a bearer value")
    require(PRIVATE_KEY_RE.search(text) is None, f"{label} contains key material")
    require(EMAIL_RE.search(text) is None, f"{label} contains an email address")
    require(ABSOLUTE_PATH_RE.search(text) is None, f"{label} contains an absolute path")
    if not allow_relative_artifact_path:
        require(URL_RE.search(text) is None, f"{label} contains a URL")
        require(HOSTNAME_RE.search(text) is None, f"{label} contains a host")
        require(IPV4_RE.search(text) is None, f"{label} contains an IPv4 address")
        require(IPV6_RE.search(text) is None, f"{label} contains an IPv6 address")


def _safe_marker(value: Any, label: str) -> str:
    text = _text(value, label)
    _reject_sensitive_text(text, label)
    return text


def _normalize_sensitive_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def _walk_redaction(value: Any, path: str = "$") -> None:
    """Reject secret-shaped fields and values outside the redaction record."""

    if isinstance(value, dict):
        for key, child in value.items():
            if path == "$.redaction":
                continue
            normalized = _normalize_sensitive_key(key)
            require(
                normalized not in SENSITIVE_KEY_PARTS,
                f"{path}: sensitive field is not allowed",
            )
            _walk_redaction(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk_redaction(child, f"{path}[{index}]")
    elif type(value) is str:
        _reject_sensitive_text(
            value,
            path,
            allow_relative_artifact_path=(path.startswith("$.artifacts[") and path.endswith(".path")) or path == "$.recorded_at_utc",
        )


def validate_redaction(value: Any) -> None:
    redaction = _strict_keys(value, REDACTION_KEYS, "redaction")
    require(redaction["policy"] == "semantic_only", "redaction policy changed")
    require(_bool(redaction["synthetic_only"], "redaction.synthetic_only"), "redaction.synthetic_only must remain true")
    for key in REDACTION_KEYS[2:]:
        require(not _bool(redaction[key], f"redaction.{key}"), f"redaction.{key} must remain false")


def _validate_revision(value: Any, evidence_id: str) -> None:
    revision = _strict_keys(value, REVISION_KEYS, "revision")
    expected = EXPECTED_REVISIONS[evidence_id]
    for key, pattern in (
        ("commit_sha", COMMIT_RE),
        ("fixture_id", IDENTIFIER_RE),
        ("fixture_version", VERSION_RE),
        ("fixture_sha256", SHA256_RE),
        ("hermes_source_sha", COMMIT_RE),
    ):
        _text(revision[key], f"revision.{key}", pattern=pattern)
        require(revision[key] == expected[key], f"revision.{key} is not the reviewed identity")


def _validate_metric(value: Any, evidence_id: str) -> None:
    metric = _strict_keys(value, METRIC_KEYS, "metric")
    require(metric == EXPECTED_METRICS[evidence_id], "metric is not the reviewed identity")
    _text(metric["name"], "metric.name", pattern=IDENTIFIER_RE)
    _text(metric["unit"], "metric.unit")
    require(metric["unit"] in METRIC_UNITS, "metric.unit is unsupported")
    _text(metric["clock"], "metric.clock")
    if metric["unit"] == "ms":
        require(metric["clock"] == "monotonic", "duration metrics require a monotonic clock")
    else:
        require(metric["clock"] == "not_applicable", "non-duration metrics require no clock")


def _validate_method(value: Any) -> None:
    method = _strict_keys(value, METHOD_KEYS, "method")
    require(method["percentile_method"] == "inclusive_linear_interpolation_r7", "percentile method changed")
    require(method["position_formula"] == "(n - 1) * q", "percentile position formula changed")
    require(method["rounding"] == "half_even_to_3_decimal_places", "rounding method changed")
    quantiles = _strict_keys(method["quantiles"], QUANTILE_KEYS, "method.quantiles")
    expected = {"p50": Decimal("0.50"), "p95": Decimal("0.95"), "p99": Decimal("0.99")}
    for key, expected_value in expected.items():
        actual = _finite_decimal(quantiles[key], f"method.quantiles.{key}")
        require(actual == expected_value, f"method.quantiles.{key} changed")
    require(
        _integer(method["minimum_repetitions"], "method.minimum_repetitions", minimum=MIN_REPETITIONS)
        == MIN_REPETITIONS,
        "minimum repetition count changed",
    )


def _validate_environment(value: Any, label: str) -> None:
    environment = _strict_keys(value, ENVIRONMENT_KEYS, label)
    for key in ENVIRONMENT_KEYS:
        _safe_marker(environment[key], f"{label}.{key}")
    require(environment["browser"] == "not_applicable" or len(environment["browser"]) <= 128, f"{label}.browser is too long")


def _round_decimal(value: Decimal) -> Decimal:
    with localcontext() as context:
        context.prec = 50
        return value.quantize(Decimal("0.001"), rounding=ROUND_HALF_EVEN)


def _percentile(values: list[Decimal], quantile: Decimal) -> Decimal:
    ordered = sorted(values)
    position = Decimal(len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - Decimal(lower)
    interpolated = ordered[lower] + (ordered[upper] - ordered[lower]) * fraction
    return _round_decimal(interpolated)


def expected_distribution(samples: list[Any]) -> dict[str, Decimal]:
    values = [_finite_decimal(value, "raw sample", positive=True) for value in samples]
    require(values, "raw_samples must not be empty")
    with localcontext() as context:
        context.prec = 50
        mean = sum(values, Decimal("0")) / Decimal(len(values))
    return {
        "min": _round_decimal(min(values)),
        "p50": _percentile(values, Decimal("0.50")),
        "p95": _percentile(values, Decimal("0.95")),
        "p99": _percentile(values, Decimal("0.99")),
        "max": _round_decimal(max(values)),
        "mean": _round_decimal(mean),
    }


def _validate_distribution(value: Any, samples: list[Any], label: str) -> None:
    distribution = _strict_keys(value, DISTRIBUTION_KEYS, label)
    expected = expected_distribution(samples)
    for key in DISTRIBUTION_KEYS:
        actual = _finite_decimal(distribution[key], f"{label}.{key}")
        require(actual == expected[key], f"{label}.{key} does not match raw samples")
    require(
        expected["min"] <= expected["p50"] <= expected["p95"] <= expected["p99"] <= expected["max"],
        f"{label} quantile order is invalid",
    )


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _provenance_input(run: dict[str, Any]) -> dict[str, Any]:
    return {key: run[key] for key in PROVENANCE_INPUT_KEYS}


def sample_provenance_digest(run: dict[str, Any]) -> str:
    """Hash the exact command, identity, and raw samples used for one run."""

    return hashlib.sha256(_canonical_json_bytes(_provenance_input(run))).hexdigest()


def _validate_run(value: Any, index: int, evidence_id: str) -> dict[str, Any]:
    label = f"runs[{index}]"
    run = _strict_keys(value, RUN_KEYS, label)
    run_id = _text(run["id"], f"{label}.id", pattern=IDENTIFIER_RE)
    expected = EXPECTED_RUN_METADATA[evidence_id].get(run_id)
    require(expected is not None, f"{label}.id is not a reviewed run")
    for key in ("platform", "environment", "state", "build_mode", "optimization", "command", "repetitions"):
        require(run[key] == expected[key], f"{label}.{key} is not the reviewed identity")
    _text(run["platform"], f"{label}.platform")
    require(run["platform"] in PLATFORMS, f"{label}.platform is unsupported")
    _validate_environment(run["environment"], f"{label}.environment")
    _text(run["state"], f"{label}.state")
    require(run["state"] in STATES, f"{label}.state is unsupported")
    _text(run["build_mode"], f"{label}.build_mode")
    require(run["build_mode"] in BUILD_MODES, f"{label}.build_mode is unsupported")
    _text(run["optimization"], f"{label}.optimization")
    require(run["optimization"] in OPTIMIZATION_MODES, f"{label}.optimization is unsupported")
    if run["platform"] == "shared":
        require(run["build_mode"] == "not_applicable", f"{label}.build_mode must be N/A for shared tooling")
    elif run["platform"] == "web":
        require(run["build_mode"] == "production", f"{label}.build_mode must be production for web")
    else:
        require(run["build_mode"] == "release", f"{label}.build_mode must be release for Apple")
    require(run["optimization"] == "not_applicable" or run["platform"] == "shared", f"{label}.optimization is not portable")
    _safe_marker(run["command"], f"{label}.command")
    repetitions = _integer(run["repetitions"], f"{label}.repetitions", minimum=MIN_REPETITIONS, maximum=MAX_REPETITIONS)
    require(type(run["raw_samples"]) is list, f"{label}.raw_samples must be an array")
    require(len(run["raw_samples"]) == repetitions, f"{label}.raw_samples count must equal repetitions")
    require(len(run["raw_samples"]) <= MAX_REPETITIONS, f"{label}.raw_samples is too long")
    for sample_index, sample in enumerate(run["raw_samples"]):
        _finite_decimal(sample, f"{label}.raw_samples[{sample_index}]", positive=True)
    _text(run["sample_provenance_sha256"], f"{label}.sample_provenance_sha256", pattern=SHA256_RE)
    _validate_distribution(run["distribution"], run["raw_samples"], f"{label}.distribution")
    return run


def artifact_manifest_digest(artifacts: list[dict[str, Any]]) -> str:
    """Hash only stable artifact metadata, not JSON whitespace or file paths."""

    payload = json.dumps(artifacts, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _validate_artifacts(value: Any, label: str) -> list[dict[str, Any]]:
    require(type(value) is list, f"{label} must be an array")
    require(0 < len(value) <= MAX_ARRAY_LENGTH, f"{label} has an invalid length")
    seen: set[str] = set()
    artifacts: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        artifact = _strict_keys(item, ARTIFACT_KEYS, f"{label}[{index}]")
        path = _text(artifact["path"], f"{label}[{index}].path", pattern=ARTIFACT_PATH_RE)
        parts = path.split("/")
        require(path not in seen, f"{label}[{index}].path is duplicated")
        require(not path.startswith("/") and "\\" not in path, f"{label}[{index}].path is not portable")
        require(".." not in parts and "" not in parts, f"{label}[{index}].path escapes its root")
        seen.add(path)
        _integer(artifact["bytes"], f"{label}[{index}].bytes", minimum=1, maximum=MAX_JSON_BYTES)
        _text(artifact["sha256"], f"{label}[{index}].sha256", pattern=SHA256_RE)
        artifacts.append(artifact)
    return artifacts


def _reviewed_artifact_metadata(
    artifacts: list[dict[str, Any]],
    evidence_id: str,
) -> tuple[tuple[str, int, str], ...]:
    """Return candidate metadata covered by the independent review anchor."""

    self_paths = SELF_AUTHENTICATED_ARTIFACT_PATHS.get(evidence_id, frozenset())
    return tuple(
        (artifact["path"], artifact["bytes"], artifact["sha256"])
        for artifact in artifacts
        if artifact["path"] not in self_paths
    )


def _read_local_file(root: Path, portable_path: str, label: str) -> bytes:
    """Read one reviewed file through an O_NOFOLLOW descriptor chain."""

    parts = portable_path.split("/")
    require(parts and all(part not in {"", ".", ".."} for part in parts), f"{label} path is invalid")
    descriptors: list[int] = []
    try:
        current = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(current)
        for part in parts[:-1]:
            current = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            descriptors.append(current)
        file_descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=current)
        descriptors.append(file_descriptor)
        metadata = os.fstat(file_descriptor)
        require(stat.S_ISREG(metadata.st_mode), f"{label} is not a regular file")
        require(metadata.st_size <= MAX_JSON_BYTES, f"{label} exceeds the bounded byte limit")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(file_descriptor, min(65536, remaining))
            require(bool(chunk), f"{label} changed while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    except (OSError, ValidationError):
        raise ValidationError(f"{label} could not be read safely") from None
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _validate_local_artifacts(artifacts: list[dict[str, Any]], root: Path) -> None:
    for artifact in artifacts:
        raw = _read_local_file(root, artifact["path"], "recorded artifact")
        require(len(raw) == artifact["bytes"], "recorded artifact byte count changed")
        require(hashlib.sha256(raw).hexdigest() == artifact["sha256"], "recorded artifact hash changed")


def _load_reviewed_json(root: Path, evidence_id: str, portable_path: str, label: str) -> Any:
    raw = _read_local_file(root, portable_path, label)
    metadata = {path: (byte_count, digest) for path, byte_count, digest in EXPECTED_ARTIFACT_METADATA[evidence_id]}
    expected = metadata.get(portable_path)
    require(expected is not None, f"{label} is not a reviewed artifact")
    require(len(raw) == expected[0], f"{label} byte count changed")
    require(hashlib.sha256(raw).hexdigest() == expected[1], f"{label} digest changed")
    return _parse_json_bytes(raw)


def _validate_web_observation(value: Any, label: str, *, expected_sequence: int | None = None) -> dict[str, Any]:
    observation = _strict_keys(value, WEB_OBSERVATION_KEYS, label)
    sequence = _integer(observation["sequence"], f"{label}.sequence", minimum=0, maximum=MAX_REPETITIONS)
    if expected_sequence is not None:
        require(sequence == expected_sequence, f"{label}.sequence changed")
    _finite_decimal(observation["duration_ms"], f"{label}.duration_ms", positive=True)
    require(_integer(observation["exit_code"], f"{label}.exit_code", minimum=0, maximum=255) == 0, f"{label}.exit_code changed")
    _integer(observation["stdout_bytes"], f"{label}.stdout_bytes", minimum=0, maximum=131073)
    _integer(observation["stderr_bytes"], f"{label}.stderr_bytes", minimum=0, maximum=131073)
    _integer(observation["artifact_files"], f"{label}.artifact_files", minimum=1, maximum=2048)
    _integer(observation["artifact_bytes"], f"{label}.artifact_bytes", minimum=1, maximum=67108864)
    _text(observation["artifact_sha256"], f"{label}.artifact_sha256", pattern=SHA256_RE)
    return observation


def _validate_web_provenance(record: dict[str, Any], root: Path) -> None:
    workload = _load_reviewed_json(root, WEB_PRODUCTION_BUILD_EVIDENCE_ID, "workload.json", "web workload")
    workload = _strict_keys(workload, WEB_WORKLOAD_KEYS, "web workload")
    require(workload["schema"] == EXPECTED_FIXTURE_SCHEMAS[WEB_PRODUCTION_BUILD_EVIDENCE_ID], "web workload schema changed")
    require(workload["fixture_id"] == record["revision"]["fixture_id"], "web workload fixture identity changed")
    require(workload["fixture_version"] == record["revision"]["fixture_version"], "web workload fixture version changed")
    require(workload["hermes_source_sha"] == record["revision"]["hermes_source_sha"], "web workload Hermes identity changed")
    build = _strict_keys(workload["build"], ("entrypoint", "arguments", "input_files", "input_roots", "output_root", "version_name"), "web workload.build")
    require(build == {
        "entrypoint": "node_modules/vite/bin/vite.js",
        "arguments": ["build", "--configLoader", "runner"],
        "input_files": ["package.json", "bun.lock", "svelte.config.js", "tsconfig.json", "vite.config.ts", ".svelte-kit/tsconfig.json"],
        "input_roots": ["src", "static"],
        "output_root": ".artifact-output/build",
        "version_name": "hermternal-web-production-build-v1",
    }, "web workload build changed")
    repetitions = _strict_keys(workload["repetitions"], ("cold", "warm", "maximum"), "web workload.repetitions")
    require(repetitions == {"cold": 30, "warm": 30, "maximum": 100}, "web workload repetitions changed")
    limits = _strict_keys(workload["limits"], ("build_timeout_ms", "stdout_bytes", "stderr_bytes", "workspace_input_bytes", "artifact_files", "artifact_bytes", "node_heap_megabytes"), "web workload.limits")
    require(limits == {"build_timeout_ms": 120000, "stdout_bytes": 131072, "stderr_bytes": 131072, "workspace_input_bytes": 16777216, "artifact_files": 2048, "artifact_bytes": 67108864, "node_heap_megabytes": 1024}, "web workload limits changed")
    network = _strict_keys(workload["network"], ("mode", "boundary"), "web workload.network")
    require(network == {"mode": "deny", "boundary": "os_sandbox"}, "web workload network boundary changed")
    launcher = _strict_keys(workload["launcher"], ("supervisor_sha256", "scanner_sha256"), "web workload.launcher")
    require(launcher == {
        "supervisor_sha256": "f60e98a4a66baa2b4fce41b930e4768863522747d1d50f7ff09b80bef0e0a14c",
        "scanner_sha256": "79e68fabb9e8c83a171783eeb9eec5e5593a4871b05eebd46d18bff8feef87cb",
    }, "web workload protected helper identities changed")

    trace = _load_reviewed_json(root, WEB_PRODUCTION_BUILD_EVIDENCE_ID, "evidence/raw-trace.json", "web trace")
    _walk_redaction(trace)
    trace = _strict_keys(trace, WEB_TRACE_KEYS, "web trace")
    require(trace["schema"] == "hermternal.web-production-build-trace.v1", "web trace schema changed")
    _text(trace["recorded_at_utc"], "web trace.recorded_at_utc", pattern=UTC_TIMESTAMP_RE)
    require(trace["source_commit_sha"] == record["revision"]["commit_sha"], "web trace source commit changed")
    require(trace["fixture_sha256"] == record["revision"]["fixture_sha256"], "web trace fixture digest changed")
    require(trace["environment"] == record["runs"][0]["environment"], "web trace environment changed")
    _validate_environment(trace["environment"], "web trace.environment")
    build_input = _strict_keys(trace["build_input"], WEB_FILE_IDENTITY_KEYS, "web trace.build_input")
    _integer(build_input["bytes"], "web trace.build_input.bytes", minimum=1, maximum=16777216)
    _text(build_input["sha256"], "web trace.build_input.sha256", pattern=SHA256_RE)
    toolchain = _strict_keys(trace["toolchain"], WEB_TOOLCHAIN_KEYS, "web trace.toolchain")
    for key in WEB_TOOLCHAIN_KEYS[:9]:
        identity = _strict_keys(toolchain[key], WEB_FILE_IDENTITY_KEYS, f"web trace.toolchain.{key}")
        _integer(identity["bytes"], f"web trace.toolchain.{key}.bytes", minimum=1)
        _text(identity["sha256"], f"web trace.toolchain.{key}.sha256", pattern=SHA256_RE)
    for key in WEB_TOOLCHAIN_KEYS[9:]:
        identity = _strict_keys(toolchain[key], WEB_TREE_IDENTITY_KEYS, f"web trace.toolchain.{key}")
        _integer(identity["files"], f"web trace.toolchain.{key}.files", minimum=1)
        _integer(identity["symlinks"], f"web trace.toolchain.{key}.symlinks", minimum=0)
        _integer(identity["bytes"], f"web trace.toolchain.{key}.bytes", minimum=1)
        _text(identity["sha256"], f"web trace.toolchain.{key}.sha256", pattern=SHA256_RE)
    require(trace["network_mode"] == "os_sandbox_deny", "web trace network mode changed")
    require(trace["limits"] == limits, "web trace limits changed")
    artifact_identities: set[str] = set()
    warmup = _validate_web_observation(trace["warmup_excluded_from_distribution"], "web trace.warmup", expected_sequence=0)
    artifact_identities.add(warmup["artifact_sha256"])
    require(type(trace["runs"]) is list and len(trace["runs"]) == len(record["runs"]), "web trace run inventory changed")
    for index, (trace_item, evidence_run) in enumerate(zip(trace["runs"], record["runs"])):
        trace_run = _strict_keys(trace_item, WEB_TRACE_RUN_KEYS, f"web trace.runs[{index}]")
        provenance = _strict_keys(trace_run["provenance"], PROVENANCE_INPUT_KEYS, f"web trace.runs[{index}].provenance")
        require(provenance == _provenance_input(evidence_run), f"web trace.runs[{index}] provenance changed")
        require(evidence_run["sample_provenance_sha256"] == sample_provenance_digest(provenance), f"web trace.runs[{index}] provenance digest changed")
        require(type(trace_run["samples"]) is list and len(trace_run["samples"]) == evidence_run["repetitions"], f"web trace.runs[{index}] samples changed")
        for sample_index, observation_value in enumerate(trace_run["samples"], 1):
            observation = _validate_web_observation(observation_value, f"web trace.runs[{index}].samples[{sample_index - 1}]", expected_sequence=sample_index)
            require(Decimal(str(observation["duration_ms"])) == Decimal(str(evidence_run["raw_samples"][sample_index - 1])), f"web trace.runs[{index}] duration changed")
            artifact_identities.add(observation["artifact_sha256"])
    require(len(artifact_identities) == 1, "web trace artifact identity drifted")


def _validate_provenance_fixture(record: dict[str, Any], root: Path) -> None:
    """Bind samples to reviewed fixture bytes before trusting distributions.

    Recomputing a quantile proves only arithmetic coherence.  Comparing the
    complete run payload with an immutable, hashed fixture also proves that the
    samples came from the reviewed command and environment claim.
    """

    evidence_id = record["evidence_id"]
    if evidence_id == WEB_PRODUCTION_BUILD_EVIDENCE_ID:
        _validate_web_provenance(record, root)
        return
    fixture_bytes = _read_local_file(root, EXPECTED_FIXTURE_PATHS[evidence_id], "sample provenance fixture")
    require(
        hashlib.sha256(fixture_bytes).hexdigest() == record["revision"]["fixture_sha256"],
        "sample provenance fixture digest changed",
    )
    fixture = _parse_json_bytes(fixture_bytes)
    _walk_redaction(fixture)
    fixture = _strict_keys(fixture, ("schema", "evidence_id", "fixture_id", "fixture_version", "runs"), "sample provenance")
    require(fixture["schema"] == EXPECTED_FIXTURE_SCHEMAS[evidence_id], "sample provenance schema changed")
    require(fixture["evidence_id"] == evidence_id, "sample provenance evidence identity changed")
    require(fixture["fixture_id"] == record["revision"]["fixture_id"], "sample provenance fixture identity changed")
    require(fixture["fixture_version"] == record["revision"]["fixture_version"], "sample provenance fixture version changed")
    require(type(fixture["runs"]) is list, "sample provenance runs must be an array")
    for item in fixture["runs"]:
        require(type(item) is dict, "sample provenance run must be an object")
    expected_ids = tuple(EXPECTED_RUN_METADATA[evidence_id])
    require(tuple(item.get("id") for item in fixture["runs"]) == expected_ids, "sample provenance run inventory changed")
    for index, (fixture_run, record_run) in enumerate(zip(fixture["runs"], record["runs"])):
        provenance = _strict_keys(fixture_run, PROVENANCE_INPUT_KEYS, f"sample provenance.runs[{index}]")
        require(provenance == _provenance_input(record_run), f"sample provenance.runs[{index}] does not match evidence")
        require(
            record_run["sample_provenance_sha256"] == sample_provenance_digest(provenance),
            f"runs[{index}].sample_provenance_sha256 does not match provenance",
        )


def validate_evidence(
    value: Any,
    label: str = "evidence",
    *,
    root: Path = ROOT,
    verify_artifacts: bool = True,
    expected_id: str | None = EVIDENCE_ID,
) -> dict[str, Any]:
    """Validate one reviewed evidence record and its local provenance files."""

    validate_json_tree(value, label)
    require(type(value) is dict, f"{label} must be an object")
    _walk_redaction(value)
    record = _strict_keys(value, ROOT_KEYS, label)
    require(record["schema"] == SCHEMA, f"{label}.schema changed")
    evidence_id = _text(record["evidence_id"], f"{label}.evidence_id", pattern=IDENTIFIER_RE)
    require(evidence_id in EXPECTED_REVISIONS, f"{label}.evidence_id is not a reviewed identity")
    if expected_id is not None:
        require(evidence_id == expected_id, f"{label}.evidence_id is not the expected identity")
    _validate_revision(record["revision"], evidence_id)
    _validate_metric(record["metric"], evidence_id)
    _validate_method(record["method"])
    require(type(record["runs"]) is list, f"{label}.runs must be an array")
    expected_run_ids = tuple(EXPECTED_RUN_METADATA[evidence_id])
    require(tuple(item.get("id") if type(item) is dict else None for item in record["runs"]) == expected_run_ids, f"{label}.runs inventory changed")
    require(len(record["runs"]) == len(expected_run_ids), f"{label}.runs has an invalid count")
    seen_runs: set[str] = set()
    for index, item in enumerate(record["runs"]):
        run = _validate_run(item, index, evidence_id)
        require(run["id"] not in seen_runs, f"{label}.runs[{index}].id is duplicated")
        seen_runs.add(run["id"])
    artifacts = _validate_artifacts(record["artifacts"], f"{label}.artifacts")
    require(
        tuple(artifact["path"] for artifact in artifacts) == EXPECTED_ARTIFACT_PATHS[evidence_id],
        f"{label}.artifacts are not the reviewed set",
    )
    require(
        _reviewed_artifact_metadata(artifacts, evidence_id) == EXPECTED_ARTIFACT_METADATA[evidence_id],
        f"{label}.artifacts do not match the reviewed byte identities",
    )
    require(
        record["artifact_manifest_sha256"] == artifact_manifest_digest(artifacts),
        f"{label}.artifact_manifest_sha256 does not match artifacts",
    )
    validate_redaction(record["redaction"])
    require(record["threshold"] is None, f"{label}.threshold must remain null until review")
    require(record["budget"] is None, f"{label}.budget must remain null until review")
    _validate_provenance_fixture(record, root)
    if verify_artifacts:
        _validate_local_artifacts(artifacts, root)
    return record


def validate_baseline(value: Any, root: Path = ROOT) -> dict[str, Any]:
    record = validate_evidence(
        value,
        "baseline",
        root=root,
        verify_artifacts=True,
        expected_id=BASELINE_EVIDENCE_ID,
    )
    require(record["metric"] == {"name": "validator_duration", "unit": "ms", "clock": "monotonic"}, "baseline metric changed")
    require(len(record["runs"]) == 2, "baseline must contain normal and optimized runs")
    modes: set[str] = set()
    for index, run in enumerate(record["runs"]):
        label = f"baseline.runs[{index}]"
        require(run["platform"] == "shared", f"{label}.platform must be shared")
        require(run["state"] == "cold", f"{label}.state must be cold")
        require(run["build_mode"] == "not_applicable", f"{label}.build_mode must be N/A")
        require(run["optimization"] in {"normal", "optimized"}, f"{label}.optimization is invalid")
        mode = run["optimization"]
        require(mode not in modes, "baseline optimization mode is duplicated")
        modes.add(mode)
        require(run["command"] == BASELINE_COMMANDS[mode], f"{label}.command is not reproducible")
        require(run["repetitions"] == MIN_REPETITIONS, f"{label}.repetitions must be {MIN_REPETITIONS}")
    require(modes == {"normal", "optimized"}, "baseline optimization modes are incomplete")
    return record


def _redacted_error(message: object) -> str:
    text = str(message)
    for pattern in (PROVIDER_TOKEN_RE, BEARER_RE, SENSITIVE_ASSIGNMENT_RE, PRIVATE_KEY_RE, EMAIL_RE, ABSOLUTE_PATH_RE, URL_RE, HOSTNAME_RE, IPV4_RE, IPV6_RE):
        text = pattern.sub("<redacted>", text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > MAX_ERROR_OUTPUT:
        return text[: MAX_ERROR_OUTPUT - 3] + "..."
    return text


def _parse_args(argv: list[str]) -> tuple[Path, Path, bool]:
    evidence_path = EVIDENCE_PATH
    baseline_path = BASELINE_PATH
    skip_baseline = False
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument == "--skip-baseline":
            skip_baseline = True
            index += 1
            continue
        if argument in {"--evidence", "--baseline"}:
            if index + 1 >= len(argv) or argv[index + 1].startswith("--"):
                raise ValidationError("option value is missing")
            target = Path(argv[index + 1])
            if argument == "--evidence":
                evidence_path = target
            else:
                baseline_path = target
            index += 2
            continue
        raise ValidationError("unknown command option")
    return evidence_path, baseline_path, skip_baseline


def main(argv: list[str] | None = None) -> int:
    try:
        evidence_path, baseline_path, skip_baseline = _parse_args(list(sys.argv[1:] if argv is None else argv))
        evidence = load_json(evidence_path)
        if evidence_path.resolve() == WEB_EVIDENCE_PATH.resolve():
            evidence_root = WEB_BENCHMARK_ROOT
            expected_id = WEB_PRODUCTION_BUILD_EVIDENCE_ID
        else:
            evidence_root = ROOT
            expected_id = EVIDENCE_ID
        record = validate_evidence(evidence, root=evidence_root, expected_id=expected_id)
        if not skip_baseline:
            validate_baseline(load_json(baseline_path), ROOT)
        result = {
            "ok": True,
            "schema": SCHEMA,
            "evidence_id": record["evidence_id"],
            "run_count": len(record["runs"]),
            "baseline_checked": not skip_baseline,
        }
        print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
        return 0
    except Exception as error:  # Keep the command boundary one-line and traceback-free.
        result = {"ok": False, "error": {"code": ERROR_CODE, "message": _redacted_error(error)}}
        print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
