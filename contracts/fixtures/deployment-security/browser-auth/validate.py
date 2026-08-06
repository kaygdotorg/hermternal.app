#!/usr/bin/env python3
"""Validate the synthetic browser-authentication boundary contract.

This module is a deliberately local proof.  It models provider discovery,
origin and return-target checks, symbolic browser-cookie state, CSRF handling,
logout, expiry, and storage failures without importing Hermes or contacting a
network service.  All outputs are bounded, redacted, and deterministic.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
CASES_PATH = ROOT / "cases.json"
BASELINE_PATH = ROOT / "validation-baseline.json"
SCHEMA = "hermternal.deployment-security.browser-auth.v1"
BASELINE_SCHEMA = "hermternal.deployment-security.browser-auth-baseline.v1"
OPERATION = "DEP-06M"
CONTRACT = "dashboard-v0.0.1"
PINNED_HERMES_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
ALLOWED_ORIGIN = "https://synthetic.hermternal.test"
MAX_JSON_BYTES = 512 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_INTEGER_DIGITS = 4300
MAX_JSON_NODES = 4096
MAX_OBJECT_KEYS = 64
MAX_ARRAY_LENGTH = 256
MAX_STRING_LENGTH = 4096
MAX_ERROR_OUTPUT = 240
MAX_BASELINE_TRACE = 30
ARTIFACT_FILES = ("README.md", "cases.json", "validate.py")

DUPLICATE_JSON_KEY_ERROR = "duplicate JSON object key"
NONFINITE_JSON_NUMBER_ERROR = "non-finite JSON number is not allowed"
INTEGER_DIGIT_LIMIT_ERROR = "JSON integer digit limit exceeded"
ERROR_CODE = "browser_auth_fixture_validation_error"

CASE_KEYS = ("id", "kind", "input", "expected")
CASES_ROOT_KEYS = (
    "schema",
    "operation",
    "contract",
    "pinned_source_sha",
    "synthetic_only",
    "network_access",
    "redaction",
    "cases",
)
REDACTION_KEYS = (
    "synthetic_only",
    "contains_credentials",
    "contains_raw_cookies",
    "contains_tokens",
    "contains_live_data",
    "contains_public_hosts",
)
OUTPUT_KEYS = (
    "status",
    "state",
    "reason",
    "redirect",
    "session_cookie",
    "cookie_cleanup",
    "provider_exchange",
    "providers",
    "diagnostic",
)
EXPECTED_CASE_IDS = (
    "provider-discovery",
    "provider-discovery-empty",
    "provider-discovery-filters-non-session",
    "login-start",
    "login-success",
    "callback-missing-state",
    "callback-csrf-mismatch",
    "callback-provider-error",
    "callback-malformed-code",
    "callback-pkce-expired",
    "logout-success",
    "logout-missing-csrf",
    "restore-expired-session",
    "restore-invalid-session",
    "wrong-origin",
    "external-return-target",
    "traversal-return-target",
    "storage-denied",
)

EXPECTED_INPUT_KEYS = {
    "discover": ("action", "origin", "registry", "storage"),
    "login_start": ("action", "origin", "registry", "return_target", "storage"),
    "callback": (
        "action",
        "callback",
        "cookies",
        "origin",
        "provider",
        "return_target",
        "storage",
    ),
    "logout": ("action", "callback", "cookies", "origin", "storage"),
    "restore": ("action", "cookies", "origin", "storage"),
}
EXPECTED_ACTIONS = {
    "discover": "discover",
    "login_start": "login_start",
    "callback": "callback",
    "logout": "logout",
    "restore": "restore",
}
COOKIE_STATES = frozenset({"present", "absent", "expired", "invalid"})
STORAGE_STATES = frozenset({"available", "denied"})
CALLBACK_CODE_STATES = frozenset({"present", "missing", "malformed"})
CALLBACK_STATE_STATES = frozenset({"match", "missing", "mismatch", "malformed"})
CALLBACK_CSRF_STATES = frozenset({"match", "missing", "mismatch", "malformed"})
CALLBACK_ERROR_STATES = frozenset({"absent", "provider"})
CLEANUP_STATES = frozenset({"none", "clear_ephemeral", "clear_session", "clear_all"})
EXCHANGE_STATES = frozenset({"not_applicable", "not_called", "called"})
OUTPUT_STATES = frozenset({"authenticated", "login_pending", "provider_available", "signed_out", "blocked"})
PROVIDER_ID_RE = re.compile(r"^[a-z][a-z0-9-]{2,31}$")
SYNTHETIC_ORIGIN_RE = re.compile(r"^https://[a-z0-9.-]+\.hermternal\.test(?::[0-9]{1,5})?$")
SYNTHETIC_URL_RE = re.compile(
    r"^https://[a-z0-9.-]+\.hermternal\.test(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~!$&'()*+,;=:@/%-]*)?$"
)
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
SENSITIVE_KEY_RE = re.compile(
    r"^(?:password|token|secret|authorization|bearer|access[_-]?key|cookie[_-]?value|client[_-]?secret)$",
    re.IGNORECASE,
)
SECRET_VALUE_PATTERNS = (
    re.compile(r"\b(?:ghp|github_pat|sk_live|AKIA)[A-Za-z0-9_\-]+\b", re.IGNORECASE),
    re.compile(r"\bBearer\s+[^\s,}\]]+", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----", re.IGNORECASE),
    re.compile(
        r"\b(?:password|token|authorization|api[_ -]?key|client[_ -]?secret)\s*[:=]\s*"
        r"(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,}\]]+)",
        re.IGNORECASE,
    ),
)
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"\b(?P<name>password|token|authorization|api[_ -]?key|client[_ -]?secret|bearer)\s*[:=]\s*"
    r"(?P<value>(?:Bearer\s+)?(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,}\]]+))",
    re.IGNORECASE,
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
BASELINE_RUN_KEYS = ("mode", "command", "repetitions", "distribution", "trace")
BASELINE_DISTRIBUTION_KEYS = ("min_ms", "p50_ms", "p95_ms", "p99_ms", "max_ms", "mean_ms")
BASELINE_ENVIRONMENT_KEYS = ("platform", "python")
BASELINE_ARTIFACT_KEYS = ("files", "bytes", "sha256")


class FixtureJSONError(ValueError):
    """Raised for malformed, oversized, or unsafe fixture JSON."""


class ValidationError(ValueError):
    """Raised when a fixture violates the closed browser-auth contract."""


def compact_error(message: object) -> str:
    """Redact credential-shaped diagnostics and cap one returned message."""

    redacted = str(message)
    for pattern in SECRET_VALUE_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)

    def redact_assignment(match: re.Match[str]) -> str:
        value_start = match.start("value") - match.start()
        return f"{match.group(0)[:value_start]}[REDACTED]"

    redacted = SENSITIVE_ASSIGNMENT_RE.sub(redact_assignment, redacted)
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
            raise FixtureJSONError(DUPLICATE_JSON_KEY_ERROR)
        result[key] = value
    return result


def _reject_nonfinite_json_constant(value: str) -> Any:
    raise FixtureJSONError(NONFINITE_JSON_NUMBER_ERROR)


def _reject_overflowing_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise FixtureJSONError(NONFINITE_JSON_NUMBER_ERROR)
    return parsed


def _reject_oversized_json_integer(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise FixtureJSONError(INTEGER_DIGIT_LIMIT_ERROR)
    try:
        return int(value)
    except ValueError:
        raise FixtureJSONError("invalid JSON integer") from None


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


def validate_json_tree(value: Any, label: str = "fixture", depth: int = 0) -> int:
    """Apply recursive node, size, type, and finite-number limits."""

    require(depth <= MAX_JSON_DEPTH, f"{label}: JSON depth exceeds the bounded limit")
    if type(value) is dict:
        require(len(value) <= MAX_OBJECT_KEYS, f"{label}: object has too many keys")
        nodes = 1
        for key, child in value.items():
            require(type(key) is str, f"{label}: object keys must be text")
            require(len(key) <= MAX_STRING_LENGTH, f"{label}: object key is too long")
            nodes += validate_json_tree(child, f"{label}.{key}", depth + 1)
            require(nodes <= MAX_JSON_NODES, f"{label}: JSON node count exceeds the bounded limit")
        return nodes
    if type(value) is list:
        require(len(value) <= MAX_ARRAY_LENGTH, f"{label}: array is too long")
        nodes = 1
        for index, child in enumerate(value):
            nodes += validate_json_tree(child, f"{label}[{index}]", depth + 1)
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
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise FixtureJSONError("fixture JSON is malformed") from exc
    validate_json_tree(value)
    return value


def _walk_redaction(value: Any, path: str = "$") -> None:
    if type(value) is dict:
        for key, child in value.items():
            normalized = re.sub(r"[_-]+", "_", key).lower()
            require(not SENSITIVE_KEY_RE.search(normalized), f"sensitive fixture field at {path}")
            _walk_redaction(child, f"{path}.{key}")
        return
    if type(value) is list:
        for index, child in enumerate(value):
            _walk_redaction(child, f"{path}[{index}]")
        return
    if type(value) is str:
        for pattern in SECRET_VALUE_PATTERNS:
            require(pattern.search(value) is None, f"secret-shaped fixture value at {path}")
        if "://" in value:
            require(SYNTHETIC_URL_RE.fullmatch(value) is not None, f"non-synthetic URL at {path}")
        return


def validate_redaction(value: Any) -> None:
    """Reject raw credential, cookie, token, host, and control material."""

    _walk_redaction(value)


def _strict_keys(value: Any, expected: tuple[str, ...], label: str) -> dict[str, Any]:
    require(type(value) is dict, f"{label} must be an object")
    require(tuple(value.keys()) == expected, f"{label} keys or ordering changed")
    return value


def _text(value: Any, label: str, *, max_length: int = MAX_STRING_LENGTH) -> str:
    require(type(value) is str, f"{label} must be text")
    require(0 < len(value) <= max_length, f"{label} has an invalid length")
    require(CONTROL_RE.search(value) is None, f"{label} contains control characters")
    return value


def _enum(value: Any, allowed: frozenset[str], label: str) -> str:
    result = _text(value, label)
    require(result in allowed, f"{label} has an unsupported value")
    return result


def _bool(value: Any, label: str) -> bool:
    require(type(value) is bool, f"{label} must be boolean")
    return value


def _status(value: Any, label: str) -> int:
    require(type(value) is int and type(value) is not bool, f"{label} must be an integer")
    require(100 <= value <= 599, f"{label} is outside HTTP status bounds")
    return value


def _validate_origin(value: Any, label: str) -> str:
    origin = _text(value, label, max_length=160)
    require(bool(SYNTHETIC_ORIGIN_RE.fullmatch(origin)), f"{label} must use the synthetic origin namespace")
    return origin


def _validate_registry(value: Any, label: str = "registry") -> list[dict[str, Any]]:
    require(type(value) is list, f"{label} must be an array")
    require(len(value) <= 16, f"{label} has too many providers")
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        row = _strict_keys(item, ("id", "label", "supports_password", "supports_session"), f"{label}[{index}]")
        provider_id = _text(row["id"], f"{label}[{index}].id", max_length=32)
        require(PROVIDER_ID_RE.fullmatch(provider_id) is not None, f"{label}[{index}].id is not a provider marker")
        require(provider_id not in seen, f"{label}[{index}].id is duplicated")
        seen.add(provider_id)
        _text(row["label"], f"{label}[{index}].label", max_length=64)
        _bool(row["supports_password"], f"{label}[{index}].supports_password")
        _bool(row["supports_session"], f"{label}[{index}].supports_session")
        result.append(row)
    return result


def _validate_cookies(value: Any, label: str = "cookies") -> dict[str, Any]:
    row = _strict_keys(value, ("session", "csrf", "pkce"), label)
    for key in ("session", "csrf", "pkce"):
        _enum(row[key], COOKIE_STATES, f"{label}.{key}")
    return row


def _validate_callback(value: Any, label: str = "callback") -> dict[str, Any]:
    row = _strict_keys(value, ("code", "state", "csrf", "error"), label)
    _enum(row["code"], CALLBACK_CODE_STATES, f"{label}.code")
    _enum(row["state"], CALLBACK_STATE_STATES, f"{label}.state")
    _enum(row["csrf"], CALLBACK_CSRF_STATES, f"{label}.csrf")
    _enum(row["error"], CALLBACK_ERROR_STATES, f"{label}.error")
    return row


def _validate_expected(value: Any, label: str = "expected") -> dict[str, Any]:
    row = _strict_keys(value, OUTPUT_KEYS, label)
    _status(row["status"], f"{label}.status")
    _enum(row["state"], OUTPUT_STATES, f"{label}.state")
    _text(row["reason"], f"{label}.reason", max_length=64)
    if row["redirect"] is not None:
        _text(row["redirect"], f"{label}.redirect", max_length=128)
        require(row["redirect"].startswith("/"), f"{label}.redirect must be a path")
    _enum(row["session_cookie"], COOKIE_STATES, f"{label}.session_cookie")
    _enum(row["cookie_cleanup"], CLEANUP_STATES, f"{label}.cookie_cleanup")
    _enum(row["provider_exchange"], EXCHANGE_STATES, f"{label}.provider_exchange")
    require(type(row["providers"]) is list, f"{label}.providers must be an array")
    require(all(type(item) is str for item in row["providers"]), f"{label}.providers must contain text")
    require(len(row["providers"]) <= 16, f"{label}.providers has too many entries")
    _text(row["diagnostic"], f"{label}.diagnostic", max_length=96)
    return row


def validate_case(case: Any, index: int) -> None:
    row = _strict_keys(case, CASE_KEYS, f"cases[{index}]")
    case_id = _text(row["id"], f"cases[{index}].id", max_length=64)
    kind = _enum(row["kind"], frozenset(EXPECTED_INPUT_KEYS), f"cases[{index}].kind")
    require(case_id == EXPECTED_CASE_IDS[index], f"cases[{index}].id is out of contract order")
    input_row = _strict_keys(row["input"], EXPECTED_INPUT_KEYS[kind], f"cases[{index}].input")
    require(input_row["action"] == EXPECTED_ACTIONS[kind], f"cases[{index}].input.action is wrong")
    _validate_origin(input_row["origin"], f"cases[{index}].input.origin")
    _enum(input_row["storage"], STORAGE_STATES, f"cases[{index}].input.storage")
    if kind in {"discover", "login_start"}:
        _validate_registry(input_row["registry"], f"cases[{index}].input.registry")
    if kind == "login_start":
        _text(input_row["return_target"], f"cases[{index}].input.return_target", max_length=256)
    if kind == "callback":
        _validate_callback(input_row["callback"], f"cases[{index}].input.callback")
        _validate_cookies(input_row["cookies"], f"cases[{index}].input.cookies")
        provider = _text(input_row["provider"], f"cases[{index}].input.provider", max_length=32)
        require(PROVIDER_ID_RE.fullmatch(provider) is not None, f"cases[{index}].input.provider is invalid")
        _text(input_row["return_target"], f"cases[{index}].input.return_target", max_length=256)
    if kind == "logout":
        _validate_callback(input_row["callback"], f"cases[{index}].input.callback")
        _validate_cookies(input_row["cookies"], f"cases[{index}].input.cookies")
    if kind == "restore":
        _validate_cookies(input_row["cookies"], f"cases[{index}].input.cookies")
    _validate_expected(row["expected"], f"cases[{index}].expected")


def validate_cases_document(document: Any) -> None:
    """Validate the closed fixture schema and every independent outcome."""

    root = _strict_keys(document, CASES_ROOT_KEYS, "cases")
    require(root["schema"] == SCHEMA, "cases schema changed")
    require(root["operation"] == OPERATION, "cases operation changed")
    require(root["contract"] == CONTRACT, "cases contract changed")
    require(root["pinned_source_sha"] == PINNED_HERMES_SHA, "pinned Hermes SHA changed")
    require(_bool(root["synthetic_only"], "cases.synthetic_only") is True, "cases must be synthetic")
    require(_bool(root["network_access"], "cases.network_access") is False, "network access must be disabled")
    redaction = _strict_keys(root["redaction"], REDACTION_KEYS, "cases.redaction")
    require(_bool(redaction["synthetic_only"], "redaction.synthetic_only") is True, "redaction scope changed")
    for key in REDACTION_KEYS[1:]:
        require(_bool(redaction[key], f"redaction.{key}") is False, f"redaction.{key} must remain false")
    cases = root["cases"]
    require(type(cases) is list, "cases.cases must be an array")
    require(len(cases) == len(EXPECTED_CASE_IDS), "case count changed")
    for index, case in enumerate(cases):
        validate_case(case, index)
        actual = evaluate_case(case)
        expected = case["expected"]
        require(actual == expected, f"cases[{index}] expected outcome does not match the boundary model")


def _outcome(
    *,
    status: int,
    state: str,
    reason: str,
    redirect: str | None = None,
    session_cookie: str = "absent",
    cookie_cleanup: str = "none",
    provider_exchange: str = "not_called",
    providers: list[str] | None = None,
    diagnostic: str,
) -> dict[str, Any]:
    result = {
        "status": status,
        "state": state,
        "reason": reason,
        "redirect": redirect,
        "session_cookie": session_cookie,
        "cookie_cleanup": cookie_cleanup,
        "provider_exchange": provider_exchange,
        "providers": list(providers or []),
        "diagnostic": diagnostic,
    }
    _validate_expected(result, "computed outcome")
    return result


def _origin_failure() -> dict[str, Any]:
    return _outcome(status=403, state="blocked", reason="wrong_origin", diagnostic="origin rejected")


def _storage_failure() -> dict[str, Any]:
    return _outcome(status=503, state="blocked", reason="storage_denied", diagnostic="browser storage unavailable")


def _return_target_result(target: str) -> tuple[bool, str]:
    if target.startswith("http://") or target.startswith("https://") or target.startswith("//"):
        return False, "external_return_target"
    if "\\" in target or CONTROL_RE.search(target):
        return False, "malformed_return_target"
    if "%" in target:
        return False, "encoded_return_target"
    segments = target.split("/")
    if ".." in segments:
        return False, "return_target_traversal"
    if target not in {"/", "/app", "/app/chat", "/settings", "/signed-out"}:
        return False, "unsafe_return_target"
    return True, "ok"


def _supported_providers(registry: list[dict[str, Any]]) -> list[str]:
    return [row["id"] for row in registry if row["supports_session"] is True]


def evaluate_case(case: Any) -> dict[str, Any]:
    """Evaluate one already-shaped case with fail-closed symbolic semantics."""

    require(type(case) is dict, "case must be an object")
    kind = case["kind"]
    request = case["input"]
    origin = request["origin"]
    if origin != ALLOWED_ORIGIN:
        return _origin_failure()
    if request["storage"] == "denied":
        return _storage_failure()

    if kind == "discover":
        providers = _supported_providers(request["registry"])
        if not providers:
            return _outcome(
                status=503,
                state="signed_out",
                reason="provider_unavailable",
                provider_exchange="not_applicable",
                diagnostic="provider unavailable",
            )
        return _outcome(
            status=200,
            state="provider_available",
            reason="provider_discovered",
            provider_exchange="not_applicable",
            providers=providers,
            diagnostic="provider discovery complete",
        )

    if kind == "login_start":
        safe, reason = _return_target_result(request["return_target"])
        if not safe:
            return _outcome(status=400, state="blocked", reason=reason, diagnostic="return target rejected")
        providers = _supported_providers(request["registry"])
        if not providers:
            return _outcome(
                status=503,
                state="signed_out",
                reason="provider_unavailable",
                provider_exchange="not_called",
                diagnostic="provider unavailable",
            )
        return _outcome(
            status=302,
            state="login_pending",
            reason="login_started",
            redirect="/auth/provider",
            provider_exchange="not_called",
            providers=providers,
            diagnostic="login start ready",
        )

    if kind == "callback":
        safe, reason = _return_target_result(request["return_target"])
        if not safe:
            return _outcome(status=400, state="blocked", reason=reason, diagnostic="return target rejected")
        callback = request["callback"]
        cookies = request["cookies"]
        if request["provider"] != "synthetic-browser":
            return _outcome(status=400, state="blocked", reason="unknown_provider", diagnostic="provider rejected")
        if cookies["pkce"] == "absent":
            return _outcome(status=400, state="blocked", reason="pkce_cookie_missing", diagnostic="callback rejected")
        if cookies["pkce"] == "expired":
            return _outcome(status=400, state="blocked", reason="pkce_cookie_expired", diagnostic="callback rejected")
        if cookies["pkce"] == "invalid":
            return _outcome(status=400, state="blocked", reason="pkce_cookie_invalid", diagnostic="callback rejected")
        if callback["error"] == "provider":
            return _outcome(status=400, state="blocked", reason="provider_error", diagnostic="callback rejected")
        if callback["state"] != "match":
            return _outcome(status=400, state="blocked", reason="csrf_state_mismatch", diagnostic="callback rejected")
        if cookies["csrf"] != "present":
            return _outcome(status=403, state="blocked", reason="csrf_cookie_missing", diagnostic="callback rejected")
        if callback["csrf"] != "match":
            return _outcome(status=403, state="blocked", reason="csrf_mismatch", diagnostic="callback rejected")
        if callback["code"] != "present":
            return _outcome(status=400, state="blocked", reason="malformed_callback", diagnostic="callback rejected")
        return _outcome(
            status=302,
            state="authenticated",
            reason="login_success",
            redirect=request["return_target"],
            session_cookie="present",
            cookie_cleanup="clear_ephemeral",
            provider_exchange="called",
            diagnostic="callback accepted",
        )

    if kind == "logout":
        callback = request["callback"]
        cookies = request["cookies"]
        if cookies["csrf"] != "present":
            return _outcome(status=403, state="blocked", reason="csrf_cookie_missing", diagnostic="logout rejected")
        if callback["csrf"] != "match":
            return _outcome(status=403, state="blocked", reason="csrf_mismatch", diagnostic="logout rejected")
        if cookies["session"] == "invalid":
            return _outcome(status=401, state="blocked", reason="invalid_session", diagnostic="logout rejected")
        if cookies["session"] == "present":
            return _outcome(status=204, state="signed_out", reason="logout", cookie_cleanup="clear_session", provider_exchange="not_applicable", diagnostic="session invalidated")
        return _outcome(status=204, state="signed_out", reason="already_signed_out", cookie_cleanup="clear_session", provider_exchange="not_applicable", diagnostic="already signed out")

    if kind == "restore":
        session = request["cookies"]["session"]
        if session == "present":
            return _outcome(status=200, state="authenticated", reason="session_restored", session_cookie="present", provider_exchange="not_applicable", diagnostic="session restored")
        if session == "expired":
            return _outcome(status=401, state="signed_out", reason="session_expired", cookie_cleanup="clear_session", provider_exchange="not_applicable", diagnostic="session unavailable")
        if session == "invalid":
            return _outcome(status=401, state="blocked", reason="invalid_session", cookie_cleanup="clear_session", provider_exchange="not_applicable", diagnostic="session unavailable")
        return _outcome(status=401, state="signed_out", reason="no_session", provider_exchange="not_applicable", diagnostic="session unavailable")

    raise ValidationError("unsupported browser-auth case kind")


def _artifact_digest(root: Path = ROOT) -> tuple[int, str]:
    """Return bytes and a path-bound digest for the reviewed fixture files."""

    digest = hashlib.sha256()
    total = 0
    for relative in ARTIFACT_FILES:
        path = root / relative
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise ValidationError("benchmark artifact is unavailable") from exc
        total += len(data)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return total, digest.hexdigest()


def _finite_number(value: Any, label: str) -> float:
    require(type(value) in {int, float} and type(value) is not bool, f"{label} must be numeric")
    result = float(value)
    require(math.isfinite(result) and result >= 0, f"{label} must be finite and non-negative")
    return result


def validate_baseline(baseline: Any, root: Path = ROOT) -> None:
    """Validate 30-run normal/optimized observations without a budget."""

    record = _strict_keys(baseline, BASELINE_ROOT_KEYS, "baseline")
    require(record["schema"] == BASELINE_SCHEMA, "baseline schema changed")
    require(record["validator"] == "contracts/fixtures/deployment-security/browser-auth/validate.py", "baseline validator path changed")
    require(record["fixture"] == "contracts/fixtures/deployment-security/browser-auth/cases.json", "baseline fixture path changed")
    require(record["metric"] == "validator_duration_ms", "baseline metric changed")
    environment = _strict_keys(record["environment"], BASELINE_ENVIRONMENT_KEYS, "baseline.environment")
    _text(environment["platform"], "baseline.environment.platform", max_length=160)
    _text(environment["python"], "baseline.environment.python", max_length=64)
    runs = record["runs"]
    require(type(runs) is list and len(runs) == 2, "baseline must contain normal and optimized runs")
    seen_modes: set[str] = set()
    for index, item in enumerate(runs):
        run = _strict_keys(item, BASELINE_RUN_KEYS, f"baseline.runs[{index}]")
        mode = _enum(run["mode"], frozenset({"normal", "optimized"}), f"baseline.runs[{index}].mode")
        require(mode not in seen_modes, "baseline run mode is duplicated")
        seen_modes.add(mode)
        _text(run["command"], f"baseline.runs[{index}].command", max_length=240)
        repetitions = run["repetitions"]
        require(type(repetitions) is int and type(repetitions) is not bool and repetitions == MAX_BASELINE_TRACE, f"baseline.runs[{index}].repetitions must be 30")
        distribution = _strict_keys(run["distribution"], BASELINE_DISTRIBUTION_KEYS, f"baseline.runs[{index}].distribution")
        trace = run["trace"]
        require(type(trace) is list and len(trace) == MAX_BASELINE_TRACE, f"baseline.runs[{index}].trace must contain 30 samples")
        values = [_finite_number(value, f"baseline.runs[{index}].trace[{sample}]") for sample, value in enumerate(trace)]
        require(all(value > 0 for value in values), f"baseline.runs[{index}].trace must be positive")
        for key in BASELINE_DISTRIBUTION_KEYS:
            _finite_number(distribution[key], f"baseline.runs[{index}].distribution.{key}")
        require(distribution["min_ms"] <= distribution["p50_ms"] <= distribution["p95_ms"] <= distribution["p99_ms"] <= distribution["max_ms"], f"baseline.runs[{index}] distribution order changed")
        require(distribution["min_ms"] <= min(values) + 1e-9, f"baseline.runs[{index}] min is not bounded by trace")
        require(distribution["max_ms"] >= max(values) - 1e-9, f"baseline.runs[{index}] max is not bounded by trace")
        require(distribution["mean_ms"] >= distribution["min_ms"] - 1e-9 and distribution["mean_ms"] <= distribution["max_ms"] + 1e-9, f"baseline.runs[{index}] mean is outside range")
    require(seen_modes == {"normal", "optimized"}, "baseline modes are incomplete")
    artifact = _strict_keys(record["artifact"], BASELINE_ARTIFACT_KEYS, "baseline.artifact")
    require(type(artifact["files"]) is list, "baseline artifact files must be an array")
    require(tuple(artifact["files"]) == ARTIFACT_FILES, "baseline artifact file set changed")
    require(type(artifact["bytes"]) is int and type(artifact["bytes"]) is not bool, "baseline artifact bytes must be an integer")
    require(artifact["bytes"] > 0, "baseline artifact bytes must be positive")
    digest = _text(artifact["sha256"], "baseline.artifact.sha256", max_length=64)
    require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "baseline artifact digest is not SHA-256")
    actual_bytes, actual_digest = _artifact_digest(root)
    require(artifact["bytes"] == actual_bytes, "baseline artifact size changed")
    require(digest == actual_digest, "baseline artifact digest changed")
    require(record["threshold"] is None, "baseline must not invent a performance threshold")


def validate_all(*, cases_path: Path = CASES_PATH, baseline_path: Path = BASELINE_PATH, root: Path = ROOT) -> tuple[int, int]:
    """Validate cases and baseline, returning case count and artifact bytes."""

    document = load_json(cases_path)
    validate_redaction(document)
    validate_cases_document(document)
    baseline = load_json(baseline_path)
    validate_redaction(baseline)
    validate_baseline(baseline, root)
    return len(document["cases"]), baseline["artifact"]["bytes"]


def _success_payload(case_count: int, artifact_bytes: int) -> str:
    return json.dumps(
        {
            "ok": True,
            "schema": SCHEMA,
            "operation": OPERATION,
            "cases": case_count,
            "artifact_bytes": artifact_bytes,
            "threshold": None,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def _failure_payload(error: Exception) -> str:
    return json.dumps(
        {"ok": False, "error": {"code": ERROR_CODE, "message": compact_error(error)}},
        separators=(",", ":"),
        sort_keys=True,
    )


def main(argv: list[str] | None = None) -> int:
    """Run the local validator and emit exactly one bounded JSON line."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=CASES_PATH)
    parser.add_argument("--baseline", type=Path, default=BASELINE_PATH)
    parser.add_argument("--skip-baseline", action="store_true")
    args = parser.parse_args(argv)
    try:
        document = load_json(args.cases)
        validate_redaction(document)
        validate_cases_document(document)
        if args.skip_baseline:
            case_count = len(document["cases"])
            artifact_bytes = 0
        else:
            baseline = load_json(args.baseline)
            validate_redaction(baseline)
            validate_baseline(baseline, ROOT)
            case_count = len(document["cases"])
            artifact_bytes = baseline["artifact"]["bytes"]
        sys.stdout.write(_success_payload(case_count, artifact_bytes) + "\n")
        return 0
    except Exception as exc:
        sys.stdout.write(_failure_payload(exc) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
