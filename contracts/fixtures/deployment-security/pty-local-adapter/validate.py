#!/usr/bin/env python3
"""Validate the offline synthetic PTY local byte-adapter proof.

The fixture models the WebSocket upgrade and byte/lifecycle boundaries only.  It
never opens a PTY, socket, proxy, Hermes process, or network connection.  Closed
schemas, explicit exceptions, and bounded diagnostics keep the proof active in
normal and optimized Python runs without treating a fixture as runtime code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import re
import statistics
import sys
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent
CASES_PATH = ROOT / "cases.json"
BASELINE_PATH = ROOT / "validation-baseline.json"
SCHEMA = "hermternal.deployment-security.pty-local-adapter.v1"
BASELINE_SCHEMA = "hermternal.deployment-security.pty-local-adapter-baseline.v1"
OPERATION = "DEP-10M"
CONTRACT = "dashboard-v0.0.1"
PINNED_HERMES_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
ROUTE = "WS /api/pty"
MAX_JSON_BYTES = 512 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 4096
MAX_JSON_OBJECT_KEYS = 64
MAX_JSON_ARRAY_LENGTH = 256
MAX_JSON_STRING_LENGTH = 4096
MAX_JSON_INTEGER_DIGITS = 4300
MAX_ERROR_OUTPUT = 240
MAX_BASELINE_TRACE = 30
REPLAY_CAPACITY = 1_048_576
DETACH_RETENTION = 1_800
MIN_COLS = 1
MAX_COLS = 2_000
MIN_ROWS = 1
MAX_ROWS = 1_000
REPLACEMENT_CLOSE = 4_409
PROCESS_EXIT_CLOSE = 4_410
CLEAN_DISCONNECT_CLOSE = 1_000
ARTIFACT_FILES = ("README.md", "cases.json", "validate.py")

# This marker is normalized before hashing so the source identity is not
# circular.  The final reviewed digest is filled after the owned files settle.
CANONICAL_SOURCE_SHA256 = "190d0553aefae2dfea22999e283f63b01a8d1a3c7515d661735b183052422f6c"
# README and cases are pinned independently of the mutable benchmark.  The
# validator source is authenticated by CANONICAL_SOURCE_SHA256 at runtime.
CANONICAL_ARTIFACT_IDENTITY = (
    ("README.md", 5520, "dbcd1ce2a8056bd964811418d14e4b6e27b7db5e89febcf5b4429a7ef7453ded"),
    ("cases.json", 19381, "30109752328dc021989e4ade2bae03c3710e2204c78d84972f3c8aa138090dae"),
)

DUPLICATE_JSON_KEY_ERROR = "duplicate JSON object key"
NONFINITE_JSON_NUMBER_ERROR = "non-finite JSON number is not allowed"
INTEGER_DIGIT_LIMIT_ERROR = "JSON integer digit limit exceeded"
ERROR_CODE = "pty_local_adapter_fixture_validation_error"

ROOT_KEYS = (
    "schema",
    "operation",
    "contract",
    "pinned_source_sha",
    "surface",
    "proof_mode",
    "synthetic_only",
    "network_access",
    "redaction",
    "constants",
    "evidence",
    "cases",
)
REDACTION_KEYS = (
    "synthetic_only",
    "raw_bytes_only_in_explicit_inputs",
    "raw_pty_bytes_logged",
    "action_payloads_replayed",
    "contains_credentials",
    "contains_live_data",
    "contains_public_hosts",
)
CONSTANT_KEYS = (
    "route",
    "resize_prefix_hex",
    "resize_suffix_hex",
    "min_cols",
    "max_cols",
    "min_rows",
    "max_rows",
    "replay_capacity_bytes",
    "detach_retention_seconds",
    "replacement_close_code",
    "process_exit_close_code",
    "clean_disconnect_close_code",
)
EVIDENCE_KEYS = ("accessibility", "security", "benchmark")
ACCESSIBILITY_KEYS = ("status", "reason", "preservation_reference")
SECURITY_KEYS = (
    "status",
    "synthetic_only",
    "live_integration",
    "real_pty",
    "raw_pty_bytes_logged",
    "action_payloads_replayed",
    "unsupported_hosts_blocked",
)
BENCHMARK_KEYS = (
    "status",
    "artifact",
    "approved_budget",
    "normal_samples",
    "optimized_samples",
    "threshold",
)
CASE_KEYS = ("id", "kind", "input", "expected")
EXPECTED_CASE_IDS = (
    "upgrade-success",
    "byte-preservation",
    "resize-bounds",
    "resize-rejection",
    "attach-reattach",
    "retained-output-race",
    "expiry",
    "no-input-replay",
    "no-pty-byte-logging",
    "close-codes",
    "unsupported-host",
)
EXPECTED_CASE_KINDS = {
    "upgrade-success": "upgrade",
    "byte-preservation": "byte-preservation",
    "resize-bounds": "resize-bounds",
    "resize-rejection": "resize-rejection",
    "attach-reattach": "attach-reattach",
    "retained-output-race": "retained-output-race",
    "expiry": "expiry",
    "no-input-replay": "no-input-replay",
    "no-pty-byte-logging": "no-pty-byte-logging",
    "close-codes": "close-codes",
    "unsupported-host": "unsupported-host",
}

SUPPORTED_HOST = "supported-synthetic"
UNSUPPORTED_HOST = "unsupported-synthetic"
SYNTHETIC_REF = re.compile(r"^synthetic-[a-z0-9-]+$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
HEX_RE = re.compile(r"^[0-9a-f]*$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
SENSITIVE_KEY_NAMES = frozenset(
    {
        "password",
        "passwd",
        "token",
        "secret",
        "authorization",
        "bearer",
        "credential",
        "credentials",
        "cookie",
        "cookievalue",
        "session",
        "sessionid",
        "sessiontoken",
        "sessionvalue",
        "ticket",
        "ticketid",
        "tickettoken",
        "ticketvalue",
        "apikey",
        "clientsecret",
        "csrf",
        "csrftoken",
        "pkce",
        "pkcetoken",
        "pkceverifier",
        "state",
        "statetoken",
        "accesstoken",
        "refreshtoken",
        "idtoken",
    }
)
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:password|passwd|token|secret|authorization|bearer|"
    r"api[_ .-]*key|client[_ .-]*secret|cookie(?:[_ .-]*(?:value|id))?|"
    r"session[_ .-]*(?:id|token|value)?|ticket[_ .-]*(?:id|token|value)?|"
    r"csrf(?:[_ .-]*token)?|pkce(?:[_ .-]*(?:token|verifier|challenge))?|"
    r"state(?:[_ .-]*(?:token|value|id))?|(?:access|refresh|id)[_ .-]*token)"
    r"\s*[:=]\s*(?:Bearer\s+)?[^\s,}\]]+",
    re.IGNORECASE,
)
SECRET_VALUE_PATTERNS = (
    re.compile(r"\b(?:ghp|github_pat|sk_live|AKIA)[A-Za-z0-9_-]+\b", re.IGNORECASE),
    re.compile(r"\bBearer\s+[^\s,}\]]+", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"(?:https?|ssh)://[^\s]+", re.IGNORECASE),
)
FORBIDDEN_TEXT = (
    "api_key",
    "api-key",
    "authorization",
    "bearer",
    "cookie",
    "credential",
    "password",
    "passwd",
    "secret",
    "ssh://",
    "http://",
    "https://",
    "private key",
)

BASELINE_ROOT_KEYS = (
    "schema",
    "validator",
    "fixture",
    "metric",
    "environment",
    "runs",
    "artifact",
    "threshold",
)
BASELINE_ENVIRONMENT_KEYS = ("platform", "python")
BASELINE_RUN_KEYS = ("mode", "command", "repetitions", "distribution", "trace")
BASELINE_DISTRIBUTION_KEYS = ("min_ms", "p50_ms", "p95_ms", "p99_ms", "max_ms", "mean_ms")
BASELINE_ARTIFACT_KEYS = ("files", "bytes", "sha256")
BASELINE_COMMANDS = {
    "normal": "python3 contracts/fixtures/deployment-security/pty-local-adapter/validate.py",
    "optimized": "python3 -O contracts/fixtures/deployment-security/pty-local-adapter/validate.py",
}

RESIZE_BOUNDARY_INPUTS = (
    (1, 1),
    (2000, 1000),
    (-1, 24),
    (0, 0),
    (80, -1),
    (2001, 24),
    (80, 1001),
    (2001, 1001),
)
RESIZE_REJECTION_SHAPES = (
    "fractional-number",
    "boolean-dimension",
    "string-dimension",
    "null-dimension",
    "non-finite-token",
    "malformed-frame",
    "fractional-number-rows",
    "non-finite-token-rows",
)
ACTION_INVENTORY = (
    ("input", "synthetic-action-input"),
    ("resize", "synthetic-action-resize"),
    ("prompt", "synthetic-action-prompt"),
    ("tool", "synthetic-action-tool"),
)
OUTPUT_INVENTORY = (
    ("synthetic-output-prompt", "prompt-output", "70726f6d70742d6f7574707574"),
    ("synthetic-output-tool", "tool-output", "746f6f6c2d6f7574707574"),
)
LOG_EVENT_ORDER = (
    "pty.output",
    "user.input",
    "terminal.resize",
    "prompt.submit",
    "tool.action",
)
LOG_FRAME_INVENTORY = (
    ("synthetic-log-frame-a", "00ff"),
    ("synthetic-log-frame-b", "1b5b"),
)


class FixtureJSONError(ValueError):
    """Raised when fixture JSON is malformed or exceeds parser limits."""


class ValidationError(ValueError):
    """Raised when a synthetic contract or evidence record is not canonical."""


class ControlledArgumentParser(argparse.ArgumentParser):
    """Prevent argparse from echoing caller-controlled paths and flags."""

    def __init__(self) -> None:
        super().__init__(add_help=False, allow_abbrev=False, argument_default=argparse.SUPPRESS, usage=argparse.SUPPRESS)

    def error(self, message: str) -> None:
        del message
        raise ValidationError("invalid command-line arguments")

    def exit(self, status: int = 0, message: str | None = None) -> None:
        del message
        if status:
            raise ValidationError("invalid command-line arguments")
        raise ValidationError("command-line help is not part of the validator output contract")


def compact_error(message: object) -> str:
    """Redact secret-shaped assignments before applying the output cap."""

    redacted = str(message)
    for pattern in SECRET_VALUE_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    redacted = SENSITIVE_ASSIGNMENT_RE.sub("[REDACTED]", redacted)
    if len(redacted) <= MAX_ERROR_OUTPUT:
        return redacted
    return redacted[: MAX_ERROR_OUTPUT - 3] + "..."


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(compact_error(message))


def strict_keys(value: Any, expected: tuple[str, ...], path: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ValidationError(f"{path}: must be an object")
    if tuple(value) != expected:
        missing = [key for key in expected if key not in value]
        extra = [key for key in value if key not in expected]
        detail: list[str] = []
        if missing:
            detail.append("missing keys")
        if extra:
            detail.append("unknown keys")
        if not detail and set(value) == set(expected):
            detail.append("key order changed")
        raise ValidationError(f"{path}: " + ", ".join(detail))
    return value


def expect_string(value: Any, path: str, expected: str | None = None, max_length: int = MAX_JSON_STRING_LENGTH) -> str:
    if type(value) is not str:
        raise ValidationError(f"{path}: must be a string")
    if len(value) > max_length:
        raise ValidationError(f"{path}: string is too long")
    if CONTROL_RE.search(value):
        raise ValidationError(f"{path}: control character is not allowed")
    if expected is not None and value != expected:
        raise ValidationError(f"{path}: value is not canonical")
    return value


def expect_bool(value: Any, path: str, expected: bool | None = None) -> bool:
    if type(value) is not bool:
        raise ValidationError(f"{path}: must be a boolean")
    if expected is not None and value is not expected:
        raise ValidationError(f"{path}: value is not canonical")
    return value


def expect_int(value: Any, path: str, expected: int | None = None) -> int:
    if type(value) is not int:
        raise ValidationError(f"{path}: must be an integer")
    if expected is not None and value != expected:
        raise ValidationError(f"{path}: value is not canonical")
    return value


def expect_number(value: Any, path: str) -> float:
    if type(value) not in (int, float) or type(value) is bool:
        raise ValidationError(f"{path}: must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise ValidationError(f"{path}: must be finite")
    return result


def expect_none(value: Any, path: str) -> None:
    if value is not None:
        raise ValidationError(f"{path}: must be null")
    return None


def expect_list(value: Any, path: str, length: int | None = None) -> list[Any]:
    if type(value) is not list:
        raise ValidationError(f"{path}: must be an array")
    if length is not None and len(value) != length:
        raise ValidationError(f"{path}: array length is not canonical")
    if len(value) > MAX_JSON_ARRAY_LENGTH:
        raise ValidationError(f"{path}: array is too long")
    return value


def expect_hex(value: Any, path: str, *, nonempty: bool = False) -> str:
    text = expect_string(value, path)
    if (nonempty and not text) or len(text) % 2 or HEX_RE.fullmatch(text) is None:
        raise ValidationError(f"{path}: must be lowercase hexadecimal with even length")
    return text


def expect_ref(value: Any, path: str) -> str:
    text = expect_string(value, path)
    if SYNTHETIC_REF.fullmatch(text) is None:
        raise ValidationError(f"{path}: must be a synthetic reference")
    suffix = text.removeprefix("synthetic-")
    if suffix and len(suffix) % 2 == 0 and HEX_RE.fullmatch(suffix) is not None:
        raise ValidationError(f"{path}: synthetic reference cannot encode payload bytes")
    return text


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FixtureJSONError(DUPLICATE_JSON_KEY_ERROR)
        result[key] = value
    return result


def _reject_nonfinite_json_constant(value: str) -> Any:
    del value
    raise FixtureJSONError(NONFINITE_JSON_NUMBER_ERROR)


def _parse_json_integer(value: str) -> int:
    digits = value.removeprefix("-").lstrip("0") or "0"
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise FixtureJSONError(INTEGER_DIGIT_LIMIT_ERROR)
    return int(value)


def _parse_json_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise FixtureJSONError(NONFINITE_JSON_NUMBER_ERROR)
    return result


def _validate_json_tree(value: Any) -> None:
    """Bound depth, node count, strings, arrays, and object fan-out."""

    stack: list[tuple[Any, int]] = [(value, 0)]
    seen_containers: set[int] = set()
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise FixtureJSONError("JSON node limit exceeded")
        if depth > MAX_JSON_DEPTH:
            raise FixtureJSONError("JSON nesting depth exceeded")
        if type(current) is dict:
            identity = id(current)
            if identity in seen_containers:
                raise FixtureJSONError("JSON contains a repeated or cyclic container")
            seen_containers.add(identity)
            if len(current) > MAX_JSON_OBJECT_KEYS:
                raise FixtureJSONError("JSON object key limit exceeded")
            for key, child in current.items():
                if type(key) is not str:
                    raise FixtureJSONError("JSON object keys must be strings")
                if len(key) > MAX_JSON_STRING_LENGTH or CONTROL_RE.search(key):
                    raise FixtureJSONError("JSON object key is invalid")
                stack.append((child, depth + 1))
        elif type(current) is list:
            identity = id(current)
            if identity in seen_containers:
                raise FixtureJSONError("JSON contains a repeated or cyclic container")
            seen_containers.add(identity)
            if len(current) > MAX_JSON_ARRAY_LENGTH:
                raise FixtureJSONError("JSON array length limit exceeded")
            for child in current:
                stack.append((child, depth + 1))
        elif type(current) is str:
            if len(current) > MAX_JSON_STRING_LENGTH or CONTROL_RE.search(current):
                raise FixtureJSONError("JSON string is invalid")
        elif type(current) is float:
            if not math.isfinite(current):
                raise FixtureJSONError(NONFINITE_JSON_NUMBER_ERROR)
        elif current is None or type(current) in (bool, int):
            continue
        else:
            raise FixtureJSONError("unsupported JSON value type")


def load_json(path: Path) -> Any:
    """Load one bounded, duplicate-free JSON document without echoing its path."""

    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise FixtureJSONError("fixture input unavailable") from exc
    if len(payload) > MAX_JSON_BYTES:
        raise FixtureJSONError("fixture JSON is too large")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FixtureJSONError("fixture JSON is not valid UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_int=_parse_json_integer,
            parse_float=_parse_json_float,
            parse_constant=_reject_nonfinite_json_constant,
        )
    except FixtureJSONError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise FixtureJSONError("fixture JSON is malformed") from exc
    _validate_json_tree(value)
    return value


def validate_redaction(value: Any) -> None:
    """Reject credential-shaped data while allowing explicit hex byte fields."""

    stack: list[Any] = [value]
    seen: set[int] = set()
    while stack:
        current = stack.pop()
        if type(current) is dict:
            identity = id(current)
            if identity in seen:
                raise ValidationError("redaction boundary changed")
            seen.add(identity)
            for key, child in current.items():
                normalized = re.sub(r"[^a-z0-9]", "", key.lower())
                if normalized in SENSITIVE_KEY_NAMES:
                    raise ValidationError("redaction boundary changed")
                stack.append(child)
        elif type(current) is list:
            identity = id(current)
            if identity in seen:
                raise ValidationError("redaction boundary changed")
            seen.add(identity)
            stack.extend(current)
        elif type(current) is str:
            lowered = current.lower()
            if any(token in lowered for token in FORBIDDEN_TEXT):
                raise ValidationError("redaction boundary changed")
            if SENSITIVE_ASSIGNMENT_RE.search(current):
                raise ValidationError("redaction boundary changed")
            for pattern in SECRET_VALUE_PATTERNS:
                if pattern.search(current):
                    raise ValidationError("redaction boundary changed")


def validate_evidence(root: dict[str, Any]) -> None:
    redaction = strict_keys(root["redaction"], REDACTION_KEYS, "redaction")
    expect_bool(redaction["synthetic_only"], "redaction.synthetic_only", True)
    expect_bool(redaction["raw_bytes_only_in_explicit_inputs"], "redaction.raw_bytes_only_in_explicit_inputs", True)
    expect_bool(redaction["raw_pty_bytes_logged"], "redaction.raw_pty_bytes_logged", False)
    expect_bool(redaction["action_payloads_replayed"], "redaction.action_payloads_replayed", False)
    expect_bool(redaction["contains_credentials"], "redaction.contains_credentials", False)
    expect_bool(redaction["contains_live_data"], "redaction.contains_live_data", False)
    expect_bool(redaction["contains_public_hosts"], "redaction.contains_public_hosts", False)

    evidence = strict_keys(root["evidence"], EVIDENCE_KEYS, "evidence")
    accessibility = strict_keys(evidence["accessibility"], ACCESSIBILITY_KEYS, "evidence.accessibility")
    expect_string(accessibility["status"], "evidence.accessibility.status", "not-applicable")
    expect_string(accessibility["reason"], "evidence.accessibility.reason")
    expect_string(accessibility["preservation_reference"], "evidence.accessibility.preservation_reference")

    security = strict_keys(evidence["security"], SECURITY_KEYS, "evidence.security")
    expect_string(security["status"], "evidence.security.status", "pass")
    for key in SECURITY_KEYS[1:]:
        expect_bool(security[key], f"evidence.security.{key}", False if key in {"live_integration", "real_pty", "raw_pty_bytes_logged", "action_payloads_replayed"} else True)

    benchmark = strict_keys(evidence["benchmark"], BENCHMARK_KEYS, "evidence.benchmark")
    expect_string(benchmark["status"], "evidence.benchmark.status", "baseline-only")
    expect_string(benchmark["artifact"], "evidence.benchmark.artifact", "validation-baseline.json")
    expect_none(benchmark["approved_budget"], "evidence.benchmark.approved_budget")
    expect_int(benchmark["normal_samples"], "evidence.benchmark.normal_samples", MAX_BASELINE_TRACE)
    expect_int(benchmark["optimized_samples"], "evidence.benchmark.optimized_samples", MAX_BASELINE_TRACE)
    expect_none(benchmark["threshold"], "evidence.benchmark.threshold")


def validate_constants(root: dict[str, Any]) -> dict[str, Any]:
    constants = strict_keys(root["constants"], CONSTANT_KEYS, "constants")
    expect_string(constants["route"], "constants.route", ROUTE)
    expect_hex(constants["resize_prefix_hex"], "constants.resize_prefix_hex", nonempty=True)
    expect_hex(constants["resize_suffix_hex"], "constants.resize_suffix_hex", nonempty=True)
    expected_ints = {
        "min_cols": MIN_COLS,
        "max_cols": MAX_COLS,
        "min_rows": MIN_ROWS,
        "max_rows": MAX_ROWS,
        "replay_capacity_bytes": REPLAY_CAPACITY,
        "detach_retention_seconds": DETACH_RETENTION,
        "replacement_close_code": REPLACEMENT_CLOSE,
        "process_exit_close_code": PROCESS_EXIT_CLOSE,
        "clean_disconnect_close_code": CLEAN_DISCONNECT_CLOSE,
    }
    for key, expected in expected_ints.items():
        expect_int(constants[key], f"constants.{key}", expected)
    return constants


def validate_upgrade(case: dict[str, Any]) -> None:
    input_row = strict_keys(case["input"], ("host_class", "route", "events"), "upgrade.input")
    expect_string(input_row["host_class"], "upgrade.input.host_class", SUPPORTED_HOST)
    expect_string(input_row["route"], "upgrade.input.route", ROUTE)
    events = expect_list(input_row["events"], "upgrade.input.events", 3)
    expected_events = (
        ("request.received", ("name", "host_class", "route")),
        ("upgrade.accepted", ("name", "route", "transport")),
        ("byte-adapter.ready", ("name", "mode")),
    )
    for index, (event, (expected_name, keys)) in enumerate(zip(events, expected_events)):
        item = strict_keys(event, keys, f"upgrade.input.events[{index}]")
        expect_string(item["name"], f"upgrade.input.events[{index}].name", expected_name)
        if expected_name == "request.received":
            expect_string(item["host_class"], f"upgrade.input.events[{index}].host_class", SUPPORTED_HOST)
            expect_string(item["route"], f"upgrade.input.events[{index}].route", ROUTE)
        elif expected_name == "upgrade.accepted":
            expect_string(item["route"], f"upgrade.input.events[{index}].route", ROUTE)
            expect_string(item["transport"], f"upgrade.input.events[{index}].transport", "binary")
        else:
            expect_string(item["mode"], f"upgrade.input.events[{index}].mode", "local-byte-adapter")
    expected = strict_keys(case["expected"], ("status", "socket_accepted", "adapter_mode", "process_spawned", "binary_transport"), "upgrade.expected")
    expect_string(expected["status"], "upgrade.expected.status", "accepted")
    expect_bool(expected["socket_accepted"], "upgrade.expected.socket_accepted", True)
    expect_string(expected["adapter_mode"], "upgrade.expected.adapter_mode", "local-byte-adapter")
    expect_bool(expected["process_spawned"], "upgrade.expected.process_spawned", False)
    expect_bool(expected["binary_transport"], "upgrade.expected.binary_transport", True)


def validate_byte_preservation(case: dict[str, Any]) -> None:
    input_row = strict_keys(case["input"], ("frames",), "byte-preservation.input")
    frames = expect_list(input_row["frames"], "byte-preservation.input.frames", 4)
    joined = ""
    refs: list[str] = []
    for index, frame in enumerate(frames):
        item = strict_keys(frame, ("frame_ref", "frame_hex", "wire_type"), f"byte-preservation.input.frames[{index}]")
        refs.append(expect_ref(item["frame_ref"], f"byte-preservation.input.frames[{index}].frame_ref"))
        joined += expect_hex(item["frame_hex"], f"byte-preservation.input.frames[{index}].frame_hex", nonempty=True)
        expect_string(item["wire_type"], f"byte-preservation.input.frames[{index}].wire_type", "binary")
    require(refs == ["synthetic-frame-utf8-a", "synthetic-frame-utf8-b", "synthetic-frame-incomplete", "synthetic-frame-invalid"], "byte-preservation frame inventory changed")
    expected = strict_keys(case["expected"], ("joined_hex", "frame_boundaries_preserved", "utf8_decode", "reencode", "raw_bytes_logged"), "byte-preservation.expected")
    expect_hex(expected["joined_hex"], "byte-preservation.expected.joined_hex", nonempty=True)
    require(expected["joined_hex"] == joined, "byte-preservation joined bytes changed")
    expect_bool(expected["frame_boundaries_preserved"], "byte-preservation.expected.frame_boundaries_preserved", True)
    expect_bool(expected["utf8_decode"], "byte-preservation.expected.utf8_decode", False)
    expect_bool(expected["reencode"], "byte-preservation.expected.reencode", False)
    expect_bool(expected["raw_bytes_logged"], "byte-preservation.expected.raw_bytes_logged", False)


def _clamp(value: int, lower: int, upper: int) -> int:
    return max(lower, min(upper, value))


def _resize_control(prefix_hex: str, cols: int, rows: int, suffix_hex: str) -> str:
    return prefix_hex + str(cols).encode("ascii").hex() + "3b" + str(rows).encode("ascii").hex() + suffix_hex


def validate_resize_bounds(case: dict[str, Any], constants: dict[str, Any]) -> None:
    input_row = strict_keys(case["input"], ("samples", "framing"), "resize-bounds.input")
    samples = expect_list(input_row["samples"], "resize-bounds.input.samples", len(RESIZE_BOUNDARY_INPUTS))
    framing = strict_keys(input_row["framing"], ("prefix_hex", "suffix_hex"), "resize-bounds.input.framing")
    expect_hex(framing["prefix_hex"], "resize-bounds.input.framing.prefix_hex", nonempty=True)
    expect_hex(framing["suffix_hex"], "resize-bounds.input.framing.suffix_hex", nonempty=True)
    require(framing["prefix_hex"] == constants["resize_prefix_hex"], "resize framing prefix changed")
    require(framing["suffix_hex"] == constants["resize_suffix_hex"], "resize framing suffix changed")
    seen: set[tuple[int, int]] = set()
    for index, sample in enumerate(samples):
        item = strict_keys(sample, ("cols", "rows", "effective_cols", "effective_rows", "control_hex"), f"resize-bounds.input.samples[{index}]")
        cols = expect_int(item["cols"], f"resize-bounds.input.samples[{index}].cols")
        rows = expect_int(item["rows"], f"resize-bounds.input.samples[{index}].rows")
        key = (cols, rows)
        require(key not in seen, "resize boundary samples must be unique")
        seen.add(key)
        require(key == RESIZE_BOUNDARY_INPUTS[index], "resize boundary inventory changed")
        effective_cols = expect_int(item["effective_cols"], f"resize-bounds.input.samples[{index}].effective_cols")
        effective_rows = expect_int(item["effective_rows"], f"resize-bounds.input.samples[{index}].effective_rows")
        require(effective_cols == _clamp(cols, constants["min_cols"], constants["max_cols"]), "resize column clamp changed")
        require(effective_rows == _clamp(rows, constants["min_rows"], constants["max_rows"]), "resize row clamp changed")
        control = expect_hex(item["control_hex"], f"resize-bounds.input.samples[{index}].control_hex", nonempty=True)
        require(control == _resize_control(framing["prefix_hex"], effective_cols, effective_rows, framing["suffix_hex"]), "resize control frame changed")
    expected = strict_keys(case["expected"], ("control_is_single_binary_message", "written_to_pty"), "resize-bounds.expected")
    expect_bool(expected["control_is_single_binary_message"], "resize-bounds.expected.control_is_single_binary_message", True)
    expect_bool(expected["written_to_pty"], "resize-bounds.expected.written_to_pty", False)


def validate_resize_rejection(case: dict[str, Any]) -> None:
    input_row = strict_keys(case["input"], ("candidates",), "resize-rejection.input")
    candidates = expect_list(input_row["candidates"], "resize-rejection.input.candidates", len(RESIZE_REJECTION_SHAPES))
    seen: set[str] = set()
    for index, candidate in enumerate(candidates):
        item = strict_keys(candidate, ("cols", "rows", "invalid_field", "wire_shape", "frame_text", "expected"), f"resize-rejection.input.candidates[{index}]")
        invalid_field = expect_string(item["invalid_field"], f"resize-rejection.input.candidates[{index}].invalid_field")
        require(invalid_field in {"cols", "rows", "frame"}, "resize rejection field changed")
        shape = expect_string(item["wire_shape"], f"resize-rejection.input.candidates[{index}].wire_shape")
        require(shape == RESIZE_REJECTION_SHAPES[index] and shape not in seen, "resize rejection inventory changed")
        seen.add(shape)
        expect_string(item["frame_text"], f"resize-rejection.input.candidates[{index}].frame_text")
        expect_string(item["expected"], f"resize-rejection.input.candidates[{index}].expected", "rejected")
        if invalid_field != "frame":
            value = item[invalid_field]
            require(type(value) is not int or type(value) is bool, "resize rejection candidate became an integer")
    expected = strict_keys(case["expected"], ("all_rejected_before_binary_send", "accepted_count"), "resize-rejection.expected")
    expect_bool(expected["all_rejected_before_binary_send"], "resize-rejection.expected.all_rejected_before_binary_send", True)
    expect_int(expected["accepted_count"], "resize-rejection.expected.accepted_count", 0)


def _identity_event(item: dict[str, Any], path: str, name: str, socket_ref: str | None, handle: str, session: str, process: str) -> None:
    expected_keys = ("name", "handle_ref", "session_ref", "process_ref", "socket_ref")
    row = strict_keys(item, expected_keys, path)
    expect_string(row["name"], f"{path}.name", name)
    expect_ref(row["handle_ref"], f"{path}.handle_ref")
    expect_ref(row["session_ref"], f"{path}.session_ref")
    expect_ref(row["process_ref"], f"{path}.process_ref")
    expect_ref(row["socket_ref"], f"{path}.socket_ref")
    require(row["handle_ref"] == handle and row["session_ref"] == session and row["process_ref"] == process, f"{path}: identity changed")
    if socket_ref is not None:
        require(row["socket_ref"] == socket_ref, f"{path}: socket identity changed")


def validate_attach_reattach(case: dict[str, Any]) -> None:
    input_row = strict_keys(case["input"], ("handle_ref", "session_ref", "process_ref", "first_socket_ref", "second_socket_ref", "events"), "attach-reattach.input")
    handle = expect_ref(input_row["handle_ref"], "attach-reattach.input.handle_ref")
    session = expect_ref(input_row["session_ref"], "attach-reattach.input.session_ref")
    process = expect_ref(input_row["process_ref"], "attach-reattach.input.process_ref")
    first_socket = expect_ref(input_row["first_socket_ref"], "attach-reattach.input.first_socket_ref")
    second_socket = expect_ref(input_row["second_socket_ref"], "attach-reattach.input.second_socket_ref")
    events = expect_list(input_row["events"], "attach-reattach.input.events", 9)
    first = strict_keys(events[0], ("name", "socket_ref"), "attach-reattach.input.events[0]")
    expect_string(first["name"], "attach-reattach.input.events[0].name", "socket.accept")
    expect_ref(first["socket_ref"], "attach-reattach.input.events[0].socket_ref")
    require(first["socket_ref"] == first_socket, "first socket identity changed")
    _identity_event(events[1], "attach-reattach.input.events[1]", "session.attach", first_socket, handle, session, process)
    disconnected = strict_keys(events[2], ("name", "socket_ref"), "attach-reattach.input.events[2]")
    expect_string(disconnected["name"], "attach-reattach.input.events[2].name", "socket.disconnect")
    require(expect_ref(disconnected["socket_ref"], "attach-reattach.input.events[2].socket_ref") == first_socket, "disconnect socket changed")
    retained = strict_keys(events[3], ("name", "handle_ref", "session_ref", "process_ref"), "attach-reattach.input.events[3]")
    expect_string(retained["name"], "attach-reattach.input.events[3].name", "registry.retain")
    for key, expected in (("handle_ref", handle), ("session_ref", session), ("process_ref", process)):
        require(expect_ref(retained[key], f"attach-reattach.input.events[3].{key}") == expected, "retained identity changed")
    second = strict_keys(events[4], ("name", "socket_ref"), "attach-reattach.input.events[4]")
    expect_string(second["name"], "attach-reattach.input.events[4].name", "socket.accept")
    require(expect_ref(second["socket_ref"], "attach-reattach.input.events[4].socket_ref") == second_socket, "second socket identity changed")
    _identity_event(events[5], "attach-reattach.input.events[5]", "session.reattach", second_socket, handle, session, process)
    _identity_event(events[6], "attach-reattach.input.events[6]", "registry.reuse", second_socket, handle, session, process)
    closed = strict_keys(events[7], ("name", "handle_ref", "session_ref", "process_ref", "socket_ref", "close_code"), "attach-reattach.input.events[7]")
    expect_string(closed["name"], "attach-reattach.input.events[7].name", "client.close")
    for key, expected in (("handle_ref", handle), ("session_ref", session), ("process_ref", process), ("socket_ref", second_socket)):
        require(expect_ref(closed[key], f"attach-reattach.input.events[7].{key}") == expected, "close identity changed")
    expect_int(closed["close_code"], "attach-reattach.input.events[7].close_code", CLEAN_DISCONNECT_CLOSE)
    _identity_event(events[8], "attach-reattach.input.events[8]", "registry.detach", second_socket, handle, session, process)
    expected = strict_keys(case["expected"], ("state_sequence", "spawn_count", "reattach_count", "identity_preserved", "process_terminated", "registry_reused"), "attach-reattach.expected")
    states = expect_list(expected["state_sequence"], "attach-reattach.expected.state_sequence", 4)
    require(states == ["attached", "detached", "reattached", "detached"], "attach lifecycle changed")
    expect_int(expected["spawn_count"], "attach-reattach.expected.spawn_count", 1)
    expect_int(expected["reattach_count"], "attach-reattach.expected.reattach_count", 1)
    expect_bool(expected["identity_preserved"], "attach-reattach.expected.identity_preserved", True)
    expect_bool(expected["process_terminated"], "attach-reattach.expected.process_terminated", False)
    expect_bool(expected["registry_reused"], "attach-reattach.expected.registry_reused", True)


def validate_retained_output_race(case: dict[str, Any]) -> None:
    input_row = strict_keys(case["input"], ("capacity_bytes", "segments", "retained_frame_ref", "live_frame_ref", "retained_hex", "live_hex", "separator_hex", "orders"), "retained-output-race.input")
    expect_int(input_row["capacity_bytes"], "retained-output-race.input.capacity_bytes", REPLAY_CAPACITY)
    segments = expect_list(input_row["segments"], "retained-output-race.input.segments", 2)
    segment_sizes: dict[str, int] = {}
    for index, segment in enumerate(segments):
        item = strict_keys(segment, ("segment_ref", "role", "byte_hex", "repeat"), f"retained-output-race.input.segments[{index}]")
        ref = expect_ref(item["segment_ref"], f"retained-output-race.input.segments[{index}].segment_ref")
        role = expect_string(item["role"], f"retained-output-race.input.segments[{index}].role")
        byte_hex = expect_hex(item["byte_hex"], f"retained-output-race.input.segments[{index}].byte_hex", nonempty=True)
        repeat = expect_int(item["repeat"], f"retained-output-race.input.segments[{index}].repeat")
        require(repeat > 0, "retained segment repeat must be positive")
        segment_sizes[ref] = len(byte_hex) // 2 * repeat
        require(role == ("evicted-prefix" if index == 0 else "retained-tail"), "retained segment roles changed")
    require(segment_sizes == {"synthetic-output-old": 12, "synthetic-output-new": REPLAY_CAPACITY}, "retained segment inventory changed")
    retained_ref = expect_ref(input_row["retained_frame_ref"], "retained-output-race.input.retained_frame_ref")
    live_ref = expect_ref(input_row["live_frame_ref"], "retained-output-race.input.live_frame_ref")
    require(retained_ref != live_ref, "retained and live frame references must differ")
    expect_hex(input_row["retained_hex"], "retained-output-race.input.retained_hex", nonempty=True)
    expect_hex(input_row["live_hex"], "retained-output-race.input.live_hex", nonempty=True)
    expect_hex(input_row["separator_hex"], "retained-output-race.input.separator_hex")
    require(input_row["separator_hex"] == "", "retained/live separator must be absent")
    orders = expect_list(input_row["orders"], "retained-output-race.input.orders", 2)
    seen_orders: set[str] = set()
    for index, order in enumerate(orders):
        item = strict_keys(order, ("order_id", "order", "frame_refs", "rendered_hex"), f"retained-output-race.input.orders[{index}]")
        expect_ref(item["order_id"], f"retained-output-race.input.orders[{index}].order_id")
        order_name = expect_string(item["order"], f"retained-output-race.input.orders[{index}].order")
        require(order_name in {"retained-first", "live-first"} and order_name not in seen_orders, "retained/live order inventory changed")
        seen_orders.add(order_name)
        refs = expect_list(item["frame_refs"], f"retained-output-race.input.orders[{index}].frame_refs", 2)
        refs = [expect_ref(ref, f"retained-output-race.input.orders[{index}].frame_refs[{ref_index}]") for ref_index, ref in enumerate(refs)]
        expected_refs = [retained_ref, live_ref] if order_name == "retained-first" else [live_ref, retained_ref]
        require(refs == expected_refs, "retained/live frame order changed")
        rendered = expect_hex(item["rendered_hex"], f"retained-output-race.input.orders[{index}].rendered_hex", nonempty=True)
        expected_hex = input_row["retained_hex"] + input_row["live_hex"] if order_name == "retained-first" else input_row["live_hex"] + input_row["retained_hex"]
        require(rendered == expected_hex, "retained/live rendered bytes changed")
    expected = strict_keys(case["expected"], ("retained_bytes", "retained_segment_ref", "evicted_segment_ref", "replay_refs", "older_output_may_be_missing", "exact_capacity_valid", "allowed_orders", "client_order", "replay_separator", "frame_boundaries_preserved"), "retained-output-race.expected")
    expect_int(expected["retained_bytes"], "retained-output-race.expected.retained_bytes", REPLAY_CAPACITY)
    require(expect_ref(expected["retained_segment_ref"], "retained-output-race.expected.retained_segment_ref") == "synthetic-output-new", "retained tail identity changed")
    require(expect_ref(expected["evicted_segment_ref"], "retained-output-race.expected.evicted_segment_ref") == "synthetic-output-old", "evicted prefix identity changed")
    refs = expect_list(expected["replay_refs"], "retained-output-race.expected.replay_refs", 1)
    require([expect_ref(ref, "retained-output-race.expected.replay_refs[0]") for ref in refs] == ["synthetic-output-new"], "replay tail references changed")
    expect_bool(expected["older_output_may_be_missing"], "retained-output-race.expected.older_output_may_be_missing", True)
    expect_bool(expected["exact_capacity_valid"], "retained-output-race.expected.exact_capacity_valid", True)
    allowed = expect_list(expected["allowed_orders"], "retained-output-race.expected.allowed_orders", 2)
    require(allowed == ["retained-first", "live-first"], "allowed retained/live orders changed")
    expect_string(expected["client_order"], "retained-output-race.expected.client_order", "receive-order")
    expect_string(expected["replay_separator"], "retained-output-race.expected.replay_separator", "none")
    expect_bool(expected["frame_boundaries_preserved"], "retained-output-race.expected.frame_boundaries_preserved", True)


def validate_expiry(case: dict[str, Any]) -> None:
    input_row = strict_keys(case["input"], ("handle_ref", "session_ref", "process_ref", "detached_state", "probes"), "expiry.input")
    for key in ("handle_ref", "session_ref", "process_ref"):
        expect_ref(input_row[key], f"expiry.input.{key}")
    expect_string(input_row["detached_state"], "expiry.input.detached_state", "detached")
    probes = expect_list(input_row["probes"], "expiry.input.probes", 3)
    expected_probes = ((1799, "reattach-allowed"), (1800, "reattach-allowed"), (1801, "reattach-expired"))
    for index, probe in enumerate(probes):
        item = strict_keys(probe, ("elapsed_seconds", "outcome"), f"expiry.input.probes[{index}]")
        elapsed = expect_int(item["elapsed_seconds"], f"expiry.input.probes[{index}].elapsed_seconds")
        outcome = expect_string(item["outcome"], f"expiry.input.probes[{index}].outcome")
        require((elapsed, outcome) == expected_probes[index], "expiry boundary changed")
    expected = strict_keys(case["expected"], ("retention_seconds", "predicate", "expired_only_after", "process_reaped_on_expiry"), "expiry.expected")
    expect_int(expected["retention_seconds"], "expiry.expected.retention_seconds", DETACH_RETENTION)
    expect_string(expected["predicate"], "expiry.expected.predicate", "elapsed <= retention_seconds")
    expect_int(expected["expired_only_after"], "expiry.expected.expired_only_after", DETACH_RETENTION)
    expect_bool(expected["process_reaped_on_expiry"], "expiry.expected.process_reaped_on_expiry", True)


def validate_no_input_replay(case: dict[str, Any]) -> None:
    input_row = strict_keys(case["input"], ("actions", "output_inventory", "retained_output_refs", "replay_refs", "replayed_action_refs"), "no-input-replay.input")
    actions = expect_list(input_row["actions"], "no-input-replay.input.actions", len(ACTION_INVENTORY))
    action_pairs: list[tuple[str, str]] = []
    for index, action in enumerate(actions):
        item = strict_keys(action, ("kind", "action_ref"), f"no-input-replay.input.actions[{index}]")
        action_pairs.append((expect_string(item["kind"], f"no-input-replay.input.actions[{index}].kind"), expect_ref(item["action_ref"], f"no-input-replay.input.actions[{index}].action_ref")))
    require(action_pairs == list(ACTION_INVENTORY), "action inventory changed")
    outputs = expect_list(input_row["output_inventory"], "no-input-replay.input.output_inventory", len(OUTPUT_INVENTORY))
    output_pairs: list[tuple[str, str, str]] = []
    for index, output in enumerate(outputs):
        item = strict_keys(output, ("output_ref", "role", "byte_hex"), f"no-input-replay.input.output_inventory[{index}]")
        output_pairs.append((expect_ref(item["output_ref"], f"no-input-replay.input.output_inventory[{index}].output_ref"), expect_string(item["role"], f"no-input-replay.input.output_inventory[{index}].role"), expect_hex(item["byte_hex"], f"no-input-replay.input.output_inventory[{index}].byte_hex", nonempty=True)))
    require(output_pairs == list(OUTPUT_INVENTORY), "output inventory changed")
    expected_refs = [item[0] for item in OUTPUT_INVENTORY]
    for key in ("retained_output_refs", "replay_refs"):
        refs = expect_list(input_row[key], f"no-input-replay.input.{key}", 2)
        require([expect_ref(ref, f"no-input-replay.input.{key}[{index}]") for index, ref in enumerate(refs)] == expected_refs, f"{key} changed")
    replayed = expect_list(input_row["replayed_action_refs"], "no-input-replay.input.replayed_action_refs", 0)
    del replayed
    expected = strict_keys(case["expected"], ("non_replayable_kinds", "replayed_action_refs", "retained_action_refs", "retained_output_refs", "replay_refs"), "no-input-replay.expected")
    kinds = expect_list(expected["non_replayable_kinds"], "no-input-replay.expected.non_replayable_kinds", 4)
    require(kinds == [item[0] for item in ACTION_INVENTORY], "non-replayable action inventory changed")
    for key in ("replayed_action_refs", "retained_action_refs"):
        refs = expect_list(expected[key], f"no-input-replay.expected.{key}", 0)
        del refs
    for key in ("retained_output_refs", "replay_refs"):
        refs = expect_list(expected[key], f"no-input-replay.expected.{key}", 2)
        require([expect_ref(ref, f"no-input-replay.expected.{key}[{index}]") for index, ref in enumerate(refs)] == expected_refs, f"expected {key} changed")


def _validate_log_record(item: Any, path: str, expected_event: str, expected_frame: str | None, expected_action: str | None) -> None:
    row = strict_keys(item, ("event", "frame_ref", "action_ref", "byte_payload_hex", "action_payload_hex"), path)
    expect_string(row["event"], f"{path}.event", expected_event)
    if expected_frame is None:
        expect_none(row["frame_ref"], f"{path}.frame_ref")
    else:
        require(expect_ref(row["frame_ref"], f"{path}.frame_ref") == expected_frame, f"{path}.frame_ref changed")
    if expected_action is None:
        expect_none(row["action_ref"], f"{path}.action_ref")
    else:
        require(expect_ref(row["action_ref"], f"{path}.action_ref") == expected_action, f"{path}.action_ref changed")
    expect_none(row["byte_payload_hex"], f"{path}.byte_payload_hex")
    expect_none(row["action_payload_hex"], f"{path}.action_payload_hex")


def validate_no_pty_byte_logging(case: dict[str, Any]) -> None:
    input_row = strict_keys(case["input"], ("frames", "actions", "logs", "retained_records"), "no-pty-byte-logging.input")
    frames = expect_list(input_row["frames"], "no-pty-byte-logging.input.frames", 2)
    frame_pairs: list[tuple[str, str]] = []
    for index, frame in enumerate(frames):
        item = strict_keys(frame, ("frame_ref", "byte_hex"), f"no-pty-byte-logging.input.frames[{index}]")
        frame_pairs.append((expect_ref(item["frame_ref"], f"no-pty-byte-logging.input.frames[{index}].frame_ref"), expect_hex(item["byte_hex"], f"no-pty-byte-logging.input.frames[{index}].byte_hex", nonempty=True)))
    require(frame_pairs == list(LOG_FRAME_INVENTORY), "logging frame inventory changed")
    actions = expect_list(input_row["actions"], "no-pty-byte-logging.input.actions", len(ACTION_INVENTORY))
    action_pairs: list[tuple[str, str]] = []
    for index, action in enumerate(actions):
        item = strict_keys(action, ("kind", "action_ref"), f"no-pty-byte-logging.input.actions[{index}]")
        action_pairs.append((expect_string(item["kind"], f"no-pty-byte-logging.input.actions[{index}].kind"), expect_ref(item["action_ref"], f"no-pty-byte-logging.input.actions[{index}].action_ref")))
    require(action_pairs == list(ACTION_INVENTORY), "logging action inventory changed")
    logs = expect_list(input_row["logs"], "no-pty-byte-logging.input.logs", len(LOG_EVENT_ORDER))
    expected_refs = (("synthetic-log-frame-a", None), (None, "synthetic-action-input"), (None, "synthetic-action-resize"), (None, "synthetic-action-prompt"), (None, "synthetic-action-tool"))
    for index, (event, (frame_ref, action_ref)) in enumerate(zip(LOG_EVENT_ORDER, expected_refs)):
        _validate_log_record(logs[index], f"no-pty-byte-logging.input.logs[{index}]", event, frame_ref, action_ref)
    records = expect_list(input_row["retained_records"], "no-pty-byte-logging.input.retained_records", 2)
    for index, record in enumerate(records):
        row = strict_keys(record, ("record_ref", "event", "frame_ref", "action_ref", "byte_payload_hex", "action_payload_hex"), f"no-pty-byte-logging.input.retained_records[{index}]")
        expect_ref(row["record_ref"], f"no-pty-byte-logging.input.retained_records[{index}].record_ref")
        expected_event = "pty.output" if index == 0 else "user.input"
        expected_frame = "synthetic-log-frame-a" if index == 0 else None
        expected_action = None if index == 0 else "synthetic-action-input"
        _validate_log_record(
            {key: row[key] for key in ("event", "frame_ref", "action_ref", "byte_payload_hex", "action_payload_hex")},
            f"no-pty-byte-logging.input.retained_records[{index}]",
            expected_event,
            expected_frame,
            expected_action,
        )
    expected = strict_keys(case["expected"], ("pty_bytes_logged", "action_payloads_logged", "raw_payload_fields", "event_order"), "no-pty-byte-logging.expected")
    expect_bool(expected["pty_bytes_logged"], "no-pty-byte-logging.expected.pty_bytes_logged", False)
    expect_bool(expected["action_payloads_logged"], "no-pty-byte-logging.expected.action_payloads_logged", False)
    fields = expect_list(expected["raw_payload_fields"], "no-pty-byte-logging.expected.raw_payload_fields", 2)
    require(fields == ["byte_payload_hex", "action_payload_hex"], "raw payload field inventory changed")
    order = expect_list(expected["event_order"], "no-pty-byte-logging.expected.event_order", len(LOG_EVENT_ORDER))
    require(order == list(LOG_EVENT_ORDER), "logging event order changed")


def validate_close_codes(case: dict[str, Any]) -> None:
    input_row = strict_keys(case["input"], ("events",), "close-codes.input")
    events = expect_list(input_row["events"], "close-codes.input.events", 5)
    first = strict_keys(events[0], ("name", "socket_ref", "close_code"), "close-codes.input.events[0]")
    expect_string(first["name"], "close-codes.input.events[0].name", "old_socket_close")
    expect_ref(first["socket_ref"], "close-codes.input.events[0].socket_ref")
    expect_int(first["close_code"], "close-codes.input.events[0].close_code", REPLACEMENT_CLOSE)
    assigned = strict_keys(events[1], ("name", "socket_ref"), "close-codes.input.events[1]")
    expect_string(assigned["name"], "close-codes.input.events[1].name", "replacement_assign")
    expect_ref(assigned["socket_ref"], "close-codes.input.events[1].socket_ref")
    stale = strict_keys(events[2], ("name", "socket_ref", "result"), "close-codes.input.events[2]")
    expect_string(stale["name"], "close-codes.input.events[2].name", "stale_cleanup")
    expect_ref(stale["socket_ref"], "close-codes.input.events[2].socket_ref")
    expect_string(stale["result"], "close-codes.input.events[2].result", "ignored")
    dead = strict_keys(events[3], ("name", "socket_ref", "close_code"), "close-codes.input.events[3]")
    expect_string(dead["name"], "close-codes.input.events[3].name", "process_exit_close")
    expect_ref(dead["socket_ref"], "close-codes.input.events[3].socket_ref")
    expect_int(dead["close_code"], "close-codes.input.events[3].close_code", PROCESS_EXIT_CLOSE)
    clean = strict_keys(events[4], ("name", "socket_ref", "close_code"), "close-codes.input.events[4]")
    expect_string(clean["name"], "close-codes.input.events[4].name", "legacy_disconnect_close")
    expect_ref(clean["socket_ref"], "close-codes.input.events[4].socket_ref")
    expect_int(clean["close_code"], "close-codes.input.events[4].close_code", CLEAN_DISCONNECT_CLOSE)
    expected = strict_keys(case["expected"], ("replacement_close_code", "process_exit_close_code", "clean_disconnect_close_code", "close_before_assignment", "stale_cleanup", "dead_process_retry"), "close-codes.expected")
    expect_int(expected["replacement_close_code"], "close-codes.expected.replacement_close_code", REPLACEMENT_CLOSE)
    expect_int(expected["process_exit_close_code"], "close-codes.expected.process_exit_close_code", PROCESS_EXIT_CLOSE)
    expect_int(expected["clean_disconnect_close_code"], "close-codes.expected.clean_disconnect_close_code", CLEAN_DISCONNECT_CLOSE)
    expect_bool(expected["close_before_assignment"], "close-codes.expected.close_before_assignment", True)
    expect_string(expected["stale_cleanup"], "close-codes.expected.stale_cleanup", "ignored")
    expect_bool(expected["dead_process_retry"], "close-codes.expected.dead_process_retry", False)


def validate_unsupported_host(case: dict[str, Any]) -> None:
    input_row = strict_keys(case["input"], ("host_class", "route", "events"), "unsupported-host.input")
    expect_string(input_row["host_class"], "unsupported-host.input.host_class", UNSUPPORTED_HOST)
    expect_string(input_row["route"], "unsupported-host.input.route", ROUTE)
    events = expect_list(input_row["events"], "unsupported-host.input.events", 2)
    first = strict_keys(events[0], ("name", "host_class", "route"), "unsupported-host.input.events[0]")
    expect_string(first["name"], "unsupported-host.input.events[0].name", "request.received")
    expect_string(first["host_class"], "unsupported-host.input.events[0].host_class", UNSUPPORTED_HOST)
    expect_string(first["route"], "unsupported-host.input.events[0].route", ROUTE)
    second = strict_keys(events[1], ("name", "reason"), "unsupported-host.input.events[1]")
    expect_string(second["name"], "unsupported-host.input.events[1].name", "host.rejected")
    expect_string(second["reason"], "unsupported-host.input.events[1].reason", "unsupported-host")
    expected = strict_keys(case["expected"], ("status", "reason", "upgrade_attempted", "socket_accepted", "adapter_ready", "process_spawned"), "unsupported-host.expected")
    expect_string(expected["status"], "unsupported-host.expected.status", "rejected")
    expect_string(expected["reason"], "unsupported-host.expected.reason", "unsupported-host")
    for key in ("upgrade_attempted", "socket_accepted", "adapter_ready", "process_spawned"):
        expect_bool(expected[key], f"unsupported-host.expected.{key}", False)


def validate_case(case: Any, index: int) -> None:
    row = strict_keys(case, CASE_KEYS, f"cases[{index}]")
    case_id = expect_string(row["id"], f"cases[{index}].id")
    kind = expect_string(row["kind"], f"cases[{index}].kind")
    require(index < len(EXPECTED_CASE_IDS) and case_id == EXPECTED_CASE_IDS[index], "case order or ID changed")
    require(EXPECTED_CASE_KINDS[case_id] == kind, "case kind changed")
    validators: dict[str, Callable[[dict[str, Any]], None]] = {
        "upgrade": validate_upgrade,
        "byte-preservation": validate_byte_preservation,
        "resize-bounds": lambda value: validate_resize_bounds(value, CURRENT_CONSTANTS),
        "resize-rejection": validate_resize_rejection,
        "attach-reattach": validate_attach_reattach,
        "retained-output-race": validate_retained_output_race,
        "expiry": validate_expiry,
        "no-input-replay": validate_no_input_replay,
        "no-pty-byte-logging": validate_no_pty_byte_logging,
        "close-codes": validate_close_codes,
        "unsupported-host": validate_unsupported_host,
    }
    validators[kind](row)


CURRENT_CONSTANTS: dict[str, Any] = {}


def validate_cases_document(document: Any) -> dict[str, Any]:
    _validate_json_tree(document)
    root = strict_keys(document, ROOT_KEYS, "fixture")
    expect_string(root["schema"], "fixture.schema", SCHEMA)
    expect_string(root["operation"], "fixture.operation", OPERATION)
    expect_string(root["contract"], "fixture.contract", CONTRACT)
    expect_string(root["pinned_source_sha"], "fixture.pinned_source_sha", PINNED_HERMES_SHA)
    expect_string(root["surface"], "fixture.surface", "web-only")
    expect_string(root["proof_mode"], "fixture.proof_mode", "offline-synthetic-byte-adapter")
    expect_bool(root["synthetic_only"], "fixture.synthetic_only", True)
    expect_bool(root["network_access"], "fixture.network_access", False)
    validate_evidence(root)
    constants = validate_constants(root)
    global CURRENT_CONSTANTS
    CURRENT_CONSTANTS = constants
    cases = expect_list(root["cases"], "cases", len(EXPECTED_CASE_IDS))
    for index, case in enumerate(cases):
        validate_case(case, index)
    return {"case_count": len(cases), "case_ids": list(EXPECTED_CASE_IDS)}


def _case(document: dict[str, Any], case_id: str) -> dict[str, Any]:
    return next(case for case in document["cases"] if case["id"] == case_id)


def mutation_inventory(document: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Return meaningful malformed candidates for the executable regression proof."""

    import copy

    mutations: list[tuple[str, dict[str, Any]]] = []

    def add(name: str, edit: Callable[[dict[str, Any]], None]) -> None:
        candidate = copy.deepcopy(document)
        edit(candidate)
        mutations.append((name, candidate))

    add("root-extra", lambda item: item.update({"unexpected": True}))
    add("schema-drift", lambda item: item.__setitem__("schema", "hermternal.deployment-security.pty-local-adapter.v0"))
    add("redaction-live", lambda item: item["redaction"].__setitem__("contains_live_data", True))
    add("benchmark-not-null", lambda item: item["evidence"]["benchmark"].__setitem__("threshold", 1.0))
    add("upgrade-no-binary", lambda item: _case(item, "upgrade-success")["expected"].__setitem__("binary_transport", False))
    add("upgrade-spawn", lambda item: _case(item, "upgrade-success")["expected"].__setitem__("process_spawned", True))
    add("byte-joined", lambda item: _case(item, "byte-preservation")["expected"].__setitem__("joined_hex", "00"))
    add("byte-decode", lambda item: _case(item, "byte-preservation")["expected"].__setitem__("utf8_decode", True))
    add("resize-clamp", lambda item: _case(item, "resize-bounds")["input"]["samples"][2].__setitem__("effective_cols", 2))
    add("resize-duplicate", lambda item: _case(item, "resize-bounds")["input"]["samples"].__setitem__(7, copy.deepcopy(_case(item, "resize-bounds")["input"]["samples"][6])))
    add("resize-accepted", lambda item: _case(item, "resize-rejection")["expected"].__setitem__("accepted_count", 1))
    add("resize-kind", lambda item: _case(item, "resize-rejection")["input"]["candidates"][0].__setitem__("wire_shape", "integer"))
    add("attach-spawn", lambda item: _case(item, "attach-reattach")["expected"].__setitem__("spawn_count", 2))
    add("attach-identity", lambda item: _case(item, "attach-reattach")["input"]["events"][5].__setitem__("process_ref", "synthetic-process-other"))
    add("attach-close", lambda item: _case(item, "attach-reattach")["input"]["events"][7].__setitem__("close_code", 1001))
    add("race-separator", lambda item: _case(item, "retained-output-race")["input"].__setitem__("separator_hex", "00"))
    add("race-tail-size", lambda item: _case(item, "retained-output-race")["expected"].__setitem__("retained_bytes", 1024))
    add("race-order", lambda item: _case(item, "retained-output-race")["input"]["orders"][0].__setitem__("rendered_hex", "4c52"))
    add("expiry-equality", lambda item: _case(item, "expiry")["input"]["probes"][1].__setitem__("outcome", "reattach-expired"))
    add("expiry-float", lambda item: _case(item, "expiry")["input"]["probes"][0].__setitem__("elapsed_seconds", 1799.0))
    add("replay-action", lambda item: _case(item, "no-input-replay")["input"].__setitem__("replayed_action_refs", ["synthetic-action-input"]))
    add("replay-output-alias", lambda item: _case(item, "no-input-replay")["input"]["replay_refs"].__setitem__(0, "synthetic-output-other"))
    add("logging-byte", lambda item: _case(item, "no-pty-byte-logging")["input"]["logs"][0].__setitem__("byte_payload_hex", "00ff"))
    add("logging-action", lambda item: _case(item, "no-pty-byte-logging")["input"]["logs"][1].__setitem__("action_payload_hex", "696e707574"))
    add("logging-event", lambda item: _case(item, "no-pty-byte-logging")["input"]["logs"][1].__setitem__("event", "pty.output"))
    add("close-replacement", lambda item: _case(item, "close-codes")["input"]["events"][0].__setitem__("close_code", CLEAN_DISCONNECT_CLOSE))
    add("close-process", lambda item: _case(item, "close-codes")["expected"].__setitem__("process_exit_close_code", 1001))
    add("unsupported-accept", lambda item: _case(item, "unsupported-host")["expected"].__setitem__("socket_accepted", True))
    add("unsupported-upgrade", lambda item: _case(item, "unsupported-host")["expected"].__setitem__("upgrade_attempted", True))
    return mutations


def validate_mutations(document: dict[str, Any]) -> int:
    mutations = mutation_inventory(document)
    for mutation_id, candidate in mutations:
        try:
            validate_cases_document(candidate)
        except (ValidationError, FixtureJSONError):
            continue
        raise ValidationError(f"mutation unexpectedly passed: {mutation_id}")
    return len(mutations)


def _artifact_digest(root: Path = ROOT) -> tuple[int, str]:
    """Return a path-bound digest over reviewed non-baseline artifacts."""

    digest = hashlib.sha256()
    total = 0
    for relative in ARTIFACT_FILES:
        try:
            data = (root / relative).read_bytes()
        except OSError as exc:
            raise ValidationError("benchmark artifact is unavailable") from exc
        total += len(data)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return total, digest.hexdigest()


def source_identity() -> dict[str, Any]:
    """Authenticate the executing validator without a circular source hash."""

    try:
        payload = (ROOT / "validate.py").read_bytes()
    except OSError as exc:
        raise ValidationError("validator source is unavailable") from exc
    marker = re.compile(rb'(?m)^CANONICAL_SOURCE_SHA256 = "[0-9a-f]{64}"$')
    normalized, replacements = marker.subn(b'CANONICAL_SOURCE_SHA256 = "' + (b"0" * 64) + b'"', payload, count=1)
    if replacements != 1 or marker.search(normalized) is None:
        raise ValidationError("validator source identity marker is invalid")
    digest = hashlib.sha256(normalized).hexdigest()
    if digest != CANONICAL_SOURCE_SHA256:
        raise ValidationError("validator source identity changed")
    return {"size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}


def canonical_artifact_metadata(source: dict[str, Any] | None = None) -> dict[str, tuple[int, str]]:
    if source is None:
        source = source_identity()
    metadata = {name: (size, digest) for name, size, digest in CANONICAL_ARTIFACT_IDENTITY}
    metadata["validate.py"] = (int(source["size"]), str(source["sha256"]))
    return metadata


def _round_ms(value: float) -> float:
    return float(f"{value:.3f}")


def _percentile(values: list[float], percentage: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentage / 100
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return _round_ms(ordered[lower])
    fraction = position - lower
    return _round_ms(ordered[lower] + (ordered[upper] - ordered[lower]) * fraction)


def _distribution(values: list[float]) -> dict[str, float]:
    return {
        "min_ms": _round_ms(min(values)),
        "p50_ms": _percentile(values, 50),
        "p95_ms": _percentile(values, 95),
        "p99_ms": _percentile(values, 99),
        "max_ms": _round_ms(max(values)),
        "mean_ms": _round_ms(statistics.fmean(values)),
    }


def validate_baseline(baseline: Any, root: Path = ROOT) -> dict[str, Any]:
    record = strict_keys(baseline, BASELINE_ROOT_KEYS, "baseline")
    expect_string(record["schema"], "baseline.schema", BASELINE_SCHEMA)
    expect_string(record["validator"], "baseline.validator", "contracts/fixtures/deployment-security/pty-local-adapter/validate.py")
    expect_string(record["fixture"], "baseline.fixture", "contracts/fixtures/deployment-security/pty-local-adapter/cases.json")
    expect_string(record["metric"], "baseline.metric", "validator_duration_ms")
    environment = strict_keys(record["environment"], BASELINE_ENVIRONMENT_KEYS, "baseline.environment")
    expect_string(environment["platform"], "baseline.environment.platform", max_length=160)
    expect_string(environment["python"], "baseline.environment.python", max_length=64)
    runs = expect_list(record["runs"], "baseline.runs", 2)
    seen_modes: set[str] = set()
    for index, raw_run in enumerate(runs):
        run = strict_keys(raw_run, BASELINE_RUN_KEYS, f"baseline.runs[{index}]")
        mode = expect_string(run["mode"], f"baseline.runs[{index}].mode")
        require(mode in {"normal", "optimized"} and mode not in seen_modes, "baseline modes are incomplete or duplicated")
        seen_modes.add(mode)
        expect_string(run["command"], f"baseline.runs[{index}].command", BASELINE_COMMANDS[mode], max_length=240)
        expect_int(run["repetitions"], f"baseline.runs[{index}].repetitions", MAX_BASELINE_TRACE)
        trace = expect_list(run["trace"], f"baseline.runs[{index}].trace", MAX_BASELINE_TRACE)
        values = [expect_number(value, f"baseline.runs[{index}].trace[{sample}]") for sample, value in enumerate(trace)]
        require(all(value > 0 for value in values), "baseline trace values must be positive")
        distribution = strict_keys(run["distribution"], BASELINE_DISTRIBUTION_KEYS, f"baseline.runs[{index}].distribution")
        expected = _distribution(values)
        for key in BASELINE_DISTRIBUTION_KEYS:
            actual = expect_number(distribution[key], f"baseline.runs[{index}].distribution.{key}")
            require(actual == expected[key], f"baseline.runs[{index}].distribution.{key} does not match the trace")
        require(expected["min_ms"] <= expected["p50_ms"] <= expected["p95_ms"] <= expected["p99_ms"] <= expected["max_ms"], "baseline distribution order changed")
    require(seen_modes == {"normal", "optimized"}, "baseline modes are incomplete")
    artifact = strict_keys(record["artifact"], BASELINE_ARTIFACT_KEYS, "baseline.artifact")
    files = expect_list(artifact["files"], "baseline.artifact.files", len(ARTIFACT_FILES))
    require(tuple(files) == ARTIFACT_FILES, "baseline artifact file set changed")
    expected_bytes, expected_digest = _artifact_digest(root)
    canonical = canonical_artifact_metadata()
    expect_int(artifact["bytes"], "baseline.artifact.bytes")
    expect_string(artifact["sha256"], "baseline.artifact.sha256")
    require(SHA256_RE.fullmatch(artifact["sha256"]) is not None, "baseline artifact digest is not SHA-256")
    require(artifact["bytes"] == expected_bytes and artifact["sha256"] == expected_digest, "baseline artifact digest changed")
    require(expected_bytes == sum(size for size, _ in canonical.values()), "canonical artifact size changed")
    require(expected_digest == _canonical_digest(root, canonical), "canonical artifact identity changed")
    expect_none(record["threshold"], "baseline.threshold")
    return {"artifact_bytes": expected_bytes, "sample_count": MAX_BASELINE_TRACE * 2}


def _canonical_digest(root: Path, canonical: dict[str, tuple[int, str]]) -> str:
    """Compute the checked-in digest from the canonical artifact bytes."""

    digest = hashlib.sha256()
    for relative in ARTIFACT_FILES:
        path = root / relative
        payload = path.read_bytes()
        expected_size, expected_sha = canonical[relative]
        require(len(payload) == expected_size and hashlib.sha256(payload).hexdigest() == expected_sha, "canonical artifact bytes changed")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(payload)
        digest.update(b"\0")
    return digest.hexdigest()


def validate_all(*, cases_path: Path = CASES_PATH, baseline_path: Path = BASELINE_PATH, root: Path = ROOT) -> tuple[int, int]:
    document = load_json(cases_path)
    validate_redaction(document)
    summary = validate_cases_document(document)
    baseline = load_json(baseline_path)
    validate_redaction(baseline)
    baseline_summary = validate_baseline(baseline, root)
    return summary["case_count"], baseline_summary["artifact_bytes"]


def _success_payload(case_count: int, artifact_bytes: int) -> str:
    return json.dumps({"ok": True, "schema": SCHEMA, "operation": OPERATION, "cases": case_count, "artifact_bytes": artifact_bytes, "threshold": None}, separators=(",", ":"), sort_keys=True)


def _failure_payload(error: object) -> str:
    return json.dumps({"ok": False, "error": {"code": ERROR_CODE, "message": compact_error(error)}}, separators=(",", ":"), sort_keys=True)


def main(argv: list[str] | None = None) -> int:
    try:
        parser = ControlledArgumentParser()
        parser.add_argument("--cases", type=Path, default=CASES_PATH)
        parser.add_argument("--baseline", type=Path, default=BASELINE_PATH)
        parser.add_argument("--skip-baseline", action="store_true")
        args = parser.parse_args(argv)
        document = load_json(args.cases)
        validate_redaction(document)
        summary = validate_cases_document(document)
        if getattr(args, "skip_baseline", False):
            artifact_bytes = 0
        else:
            source_identity()
            baseline = load_json(args.baseline)
            validate_redaction(baseline)
            baseline_summary = validate_baseline(baseline, ROOT)
            artifact_bytes = baseline_summary["artifact_bytes"]
        sys.stdout.write(_success_payload(summary["case_count"], artifact_bytes) + "\n")
        return 0
    except (Exception, SystemExit) as exc:
        sys.stdout.write(_failure_payload(exc) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
