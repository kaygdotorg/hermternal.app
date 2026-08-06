#!/usr/bin/env python3
"""Validate the language-neutral Hermternal fixture registry offline.

This validator checks the aggregate registry, its language-neutral schema, every
listed artifact digest, and the observed benchmark evidence. It never imports or
runs a fixture validator, starts Hermes, opens a socket, follows a URL, or makes a
network request. Domain-specific validators remain responsible for their own
case semantics; this layer proves that the shared inventory is complete,
synthetic, redacted, deterministic, and safe to consume from Python, TypeScript,
and Swift.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import math
import re
import statistics
import tokenize
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit


FIXTURES_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = FIXTURES_ROOT.parents[1]
INDEX_PATH = FIXTURES_ROOT / "index.json"
SCHEMA_PATH = FIXTURES_ROOT / "schema.json"
BASELINE_PATH = FIXTURES_ROOT / "validator" / "validation-baseline.json"

INDEX_SCHEMA = "hermternal.fixture-index.v1"
SCHEMA_DOCUMENT_ID = "https://hermternal.invalid/schema/fixture-index.v1.json"
BASELINE_SCHEMA = "hermternal.fixture-validator-baseline.v1"
CONTRACT = "dashboard-v0.0.1"
HERMES_SOURCE_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"

PLATFORMS = ("web", "ios", "ipados", "macos")
STATE_IDS = ("pending", "empty", "success", "failure", "cancelled", "unknown")

INDEX_KEYS = (
    "schema",
    "contract",
    "hermes_source_sha",
    "synthetic_only",
    "live_claim",
    "evidence_status",
    "fixture_roots",
    "coverage",
    "parity",
    "states",
    "redaction",
    "benchmark",
)
SCHEMA_KEYS = (
    "$schema",
    "$id",
    "title",
    "type",
    "additionalProperties",
    "required",
    "properties",
    "$defs",
)
FIXTURE_KEYS = (
    "id",
    "path",
    "status",
    "contract",
    "hermes_source_sha",
    "synthetic_only",
    "live_claim",
    "platforms",
    "states",
    "coverage_ids",
    "validator",
    "files",
)
FILE_KEYS = ("path", "sha256", "size_bytes")
COVERAGE_KEYS = ("id", "status", "fixture_ids", "platforms", "required_states", "notes")
PARITY_KEYS = (
    "status",
    "fixture_source",
    "platforms",
    "pty_policy",
    "missing_result_policy",
    "result_equivalence",
    "live_claim",
)
STATE_KEYS = ("id", "evidence_state", "gate_decision", "safe_state", "retry_policy")
REDACTION_KEYS = (
    "synthetic_only",
    "contains_credentials",
    "contains_cookies",
    "contains_bearer_values",
    "contains_ticket_values",
    "contains_raw_pty_bytes",
    "contains_transcripts",
    "contains_live_hosts",
    "contains_user_data",
    "failure_output",
)
BENCHMARK_KEYS = ("path", "threshold", "evidence_mode", "build_mode")
BASELINE_KEYS = (
    "schema",
    "fixture_schema",
    "validator",
    "synthetic_only",
    "build_mode",
    "threshold",
    "environment",
    "artifact_manifest",
    "artifact_size_bytes",
    "normal",
    "optimized",
    "notes",
)
MEASUREMENT_KEYS = ("command", "repetitions", "samples_ms", "distribution_ms")
DISTRIBUTION_KEYS = ("min", "p50", "p95", "max", "mean")

MAX_JSON_BYTES = 512 * 1024
MAX_ARTIFACT_BYTES = 512 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 8 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 200_000
MAX_JSON_STRING_LENGTH = 4_096
MAX_JSON_KEY_LENGTH = 256
MAX_INTEGER_DIGITS = 100
MAX_INTEGER = 10**MAX_INTEGER_DIGITS - 1
MAX_ERROR_LENGTH = 240
BASELINE_REPETITIONS = 30
SCANNED_ARTIFACT_SUFFIXES = frozenset({".json", ".md", ".py", ".txt"})
# This trust anchor authenticates the canonical observed baseline content. The
# canonicalizer omits only this validator's own manifest digest and derived byte
# total, which would otherwise create a self-referential hash cycle.
BASELINE_SELF_MANIFEST_PATH = "contracts/fixtures/validator/validate.py"
CENTRAL_VALIDATOR_SOURCE_PATHS = frozenset({
    "contracts/fixtures/validator/test_validate.py",
    "contracts/fixtures/validator/validate.py",
})
# The separate aggregate test source carries the reviewed canonical validator
# digest. Keeping this anchor outside validate.py means a local mutation cannot
# refresh both the scanner and its self-manifest without changing an independent
# reviewed source boundary as well.
VALIDATOR_TRUST_ANCHOR_PATH = "contracts/fixtures/validator/test_validate.py"
BASELINE_CANONICAL_SHA256 = "22ffc0cb0af3fa48f1cd4b2649b73d770420150ba393d9c9e39d2afc76439bbf"

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SAFE_PATH = re.compile(r"^[A-Za-z0-9._/-]+$")
URL_PATTERN = re.compile(r"(?:https?|wss?)://[^\s\"'<>]+", re.IGNORECASE)
REGEX_HOST_LITERAL_PATTERN = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+"
)
UNSAFE_CONTROL_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
BASELINE_ANCHOR_PATTERN = re.compile(rb'^BASELINE_CANONICAL_SHA256 = "[0-9a-f]{64}"$', re.MULTILINE)
TRUST_ANCHOR_PATTERN = re.compile(
    r'^TRUSTED_VALIDATE_SOURCE_SHA256 = "([0-9a-f]{64})"$',
    re.MULTILINE,
)
PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----", re.IGNORECASE)
AWS_KEY_PATTERN = re.compile(r"\bAKIA[0-9A-Z]{16}\b", re.IGNORECASE)
PROVIDER_TOKEN_PATTERN = re.compile(r"\b(?:ghp|github_pat|glpat|sk|xox[baprs])[-_][A-Za-z0-9_-]{8,}\b", re.IGNORECASE)
BEARER_VALUE_PATTERN = re.compile(r"\bBearer\s+([A-Za-z0-9._~+/=-]{16,})\b", re.IGNORECASE)
BASIC_VALUE_PATTERN = re.compile(r"\bBasic\s+([A-Za-z0-9+/=_-]{16,})", re.IGNORECASE)
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
ASSIGNMENT_SECRET_PATTERN = re.compile(
    r"(?:[?&]|\b)(?:ticket|cookie|password|secret|token)\s*[=:]\s*([A-Za-z0-9._~+/=-]{8,})",
    re.IGNORECASE,
)
SENSITIVE_MARKER = re.compile(
    r"^(?:absent|present|expired|invalid|valid|issued|malformed|missing|none|unknown|redacted|blocked|"
    r"not_[a-z0-9_]+|no_[a-z0-9_]+|synthetic[-_][a-z0-9_-]+|"
    r"[a-z0-9]+(?:_[a-z0-9]+)+)$",
    re.IGNORECASE,
)

SENSITIVE_KEYS = frozenset(
    {
        "access_key",
        "access_key_id",
        "access_keys",
        "access_token",
        "accesskey",
        "accesskeyid",
        "accesstoken",
        "api_key",
        "api_key_value",
        "api_keys",
        "apikey",
        "apikeyvalue",
        "apikeys",
        "attach_handle",
        "attach_handles",
        "attach_id",
        "attach_ids",
        "authorization",
        "authorization_header",
        "authorization_headers",
        "auth_header",
        "auth_headers",
        "aws_access_key_id",
        "aws_access_key_ids",
        "aws_secret_access_key",
        "aws_secret_access_keys",
        "awsaccesskeyid",
        "awssecretaccesskey",
        "bearer",
        "bearers",
        "bearer_token",
        "bearer_tokens",
        "cookie",
        "cookies",
        "cookie_header",
        "cookie_headers",
        "credential",
        "credential_value",
        "credentials",
        "client_secret",
        "client_secrets",
        "clientsecret",
        "header_value",
        "host",
        "hostname",
        "input_bytes",
        "password",
        "prompt",
        "prompt_bytes",
        "prompt_text",
        "prompt_texts",
        "pty_bytes",
        "pty_input",
        "pty_inputs",
        "pty_output",
        "pty_outputs",
        "raw_bearer",
        "raw_cookie",
        "raw_ticket",
        "refresh_token",
        "refresh_tokens",
        "secret",
        "secret_key",
        "secret_keys",
        "secret_value",
        "session_cookie",
        "session_token",
        "set_cookie",
        "ticket",
        "ticket_fragment",
        "ticket_fragments",
        "ticket_query",
        "ticket_queries",
        "ticket_value",
        "token",
        "tokens",
        "transcript",
        "transcripts",
        "transcript_bytes",
        "websocket_ticket",
        "websocket_tickets",
        "provider_api_key",
        "provider_api_keys",
        "providerapikey",
        "providerapikeys",
        "secretkey",
        "x_api_key",
        "x_api_keys",
        "xapikey",
        "xapikeys",
    }
)
SENSITIVE_DESCRIPTOR_KEYS = frozenset({
    "classification",
    "csrf",
    "pkce",
    "present",
    "reference",
    "session",
})
ALLOWED_URL_HOSTS = frozenset({
    "github.com",
    "hermternal.invalid",
    "json-schema.org",
    "synthetic.invalid",
})
# These exact values are source-level negative-test vocabulary already present
# in domain validators. They are not accepted in JSON evidence or free text.
STRUCTURAL_SENSITIVE_MARKERS = frozenset({
    "abcdefgh",
    "abcdefghijkl",
    "live-value",
    "never-echo",
    "rawcookie",
    "rawticket",
    "session=secret",
    "sid=qwertyui",
    "super-secret-value",
})
# Only this already-registered test source contains the RFC 7617 sample as
# deliberate negative-test input. Keep its exact candidate out of the global
# marker set so validators and non-test artifacts cannot inherit the allowance.
TEST_NEGATIVE_BASIC_AUTH_PATHS = frozenset({
    "deployment-security/external-allowlist/test_validate.py",
})
TEST_NEGATIVE_RFC7617_TOKEN_PATHS = frozenset({
    # These indexed Python sources retain the exact token as deliberate
    # negative-test input. JSON, Markdown, text, and every other Python source
    # remain fail-closed for the same bytes.
    "deployment-security/external-allowlist/test_validate.py",
    "image-attachment-lifecycle/test_validate.py",
})
# These are the only registered Python sources whose retained strings are
# deliberate credential-shaped negative inputs. The allowance is path-scoped;
# every other source, including every production-shaped validator, stays
# fail-closed even when a value contains synthetic vocabulary.
SYNTHETIC_MARKER_PATHS = frozenset({
    "behavioral-probe/test_validate.py",
    "compatibility-attestation/test_validate.py",
    "deployment-security/browser-auth/test_validate.py",
    "deployment-security/external-allowlist/test_validate.py",
    "deployment-security/private-network-firewall/test_validate.py",
    "route-allowlist/test_route_allowlist.py",
    "session-lineage/test_validate.py",
    "session-persistence/test_validate.py",
    "source-audit/compatibility-gate/test_validate.py",
    "source-audit/model-options/test_model_options.py",
    "source-audit/native-bearer/test_native_bearer.py",
    "source-audit/native-password-provider/test_native_password_provider.py",
    "source-audit/oauth-browser/test_oauth_browser.py",
})
# This source-review fixture keeps a complete synthetic PEM example. Its
# header itself is intentionally realistic, so retain the full source value as
# an exact exception rather than allowing every private-key header in the file.
SYNTHETIC_FULL_VALUE_ALLOWANCES = {
    "source-audit/model-options/test_model_options.py": frozenset({
        "-----BEGIN RSA PRIVATE KEY-----\nsynthetic\n-----END RSA PRIVATE KEY-----",
    }),
}
TEST_NEGATIVE_BASIC_AUTH_CANDIDATE = "QWxhZGRpbjpvcGVuIHNlc2FtZQ" + "=="
TEST_NEGATIVE_BASIC_AUTH_CANDIDATES = frozenset({TEST_NEGATIVE_BASIC_AUTH_CANDIDATE})
EXACT_ASSIGNMENT_ALLOWANCES = {
    # These are retained source-review or negative-test fragments. Every
    # allowance is exact-path and exact-value; no caller can opt into a broad
    # dotted-value or synthetic credential exemption.
    "deployment-security/pty-local-adapter/test_validate.py": frozenset({"live-value"}),
    "deployment-security/ws-ticket/README.md": frozenset({"Abcdefgh"}),
    "deployment-security/ws-ticket/test_validate.py": frozenset({"Abcdefgh", "never-echo", "sid=qwertyui"}),
    "image-attachment-lifecycle/test_validate.py": frozenset({"session=secret"}),
    "source-audit/native-password-provider/source_audit.json": frozenset({"body.password"}),
    "source-audit/native-password-provider/validate.py": frozenset({"Abcdefgh", "body.password"}),
    "source-audit/oauth-browser/test_oauth_browser.py": frozenset({"request.get"}),
    "source-audit/pty-attach/validate.py": frozenset({"abcdefghijkl"}),
}
RAW_RFC7617_TOKEN_PATTERN = re.compile(re.escape(TEST_NEGATIVE_BASIC_AUTH_CANDIDATE), re.IGNORECASE)

SAFE_ERROR_MESSAGE = "fixture registry input rejected"


class ValidationError(ValueError):
    """Raised when checked-in registry evidence violates the shared contract."""

    def __init__(self, _detail: str = "") -> None:
        # Details can contain an untrusted path, key, or value. Keep direct API
        # errors bounded as well as the CLI's serialized failure marker.
        super().__init__(SAFE_ERROR_MESSAGE)


class DuplicateKeyError(ValidationError):
    """Raised before a duplicate JSON key can hide a fixture mutation."""


class ArgumentParseError(ValueError):
    """Raised for CLI syntax errors without echoing untrusted arguments."""


def require(condition: bool, message: str = "") -> None:
    if not condition:
        raise ValidationError(message)


def strict_keys(value: Any, expected: tuple[str, ...], label: str = "object") -> dict[str, Any]:
    require(type(value) is dict, f"{label} must be an object")
    require(tuple(value.keys()) == expected, f"{label} keys or ordering changed")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            # Never include the duplicate key in an error. It can be attacker-
            # controlled and must not escape through a test or CLI diagnostic.
            raise DuplicateKeyError()
        result[key] = value
    return result


def _parse_int(text: str) -> int:
    digits = text.lstrip("-")
    require(len(digits) <= MAX_INTEGER_DIGITS, "JSON integer is too large")
    value = int(text)
    require(abs(value) <= MAX_INTEGER, "JSON integer is too large")
    return value


def _parse_float(text: str) -> float:
    value = float(text)
    require(math.isfinite(value), "JSON number is not finite")
    return value


def _reject_constant(_text: str) -> Any:
    raise ValidationError()


def _read_bounded_bytes(path: Path, limit: int) -> bytes:
    try:
        if path.is_symlink() or not path.is_file():
            raise ValidationError()
        size = path.stat().st_size
        require(size <= limit, "input exceeds the byte limit")
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
    except ValidationError:
        raise
    except (OSError, ValueError) as exc:
        raise ValidationError() from exc
    require(len(data) <= limit, "input exceeds the byte limit")
    return data


def _validate_json_tree(
    value: Any,
    depth: int = 0,
    counter: list[int] | None = None,
    *,
    reject_nul: bool = True,
) -> None:
    if counter is None:
        counter = [0]
    counter[0] += 1
    require(counter[0] <= MAX_JSON_NODES, "JSON node count exceeds the safe limit")
    require(depth <= MAX_JSON_DEPTH, "JSON nesting exceeds the safe depth")
    if type(value) is dict:
        for key, child in value.items():
            require(type(key) is str, "JSON object key must be text")
            require(len(key) <= MAX_JSON_KEY_LENGTH and "\x00" not in key, "JSON object key is unsafe")
            _validate_json_tree(child, depth + 1, counter, reject_nul=reject_nul)
        return
    if type(value) is list:
        require(len(value) <= MAX_JSON_NODES, "JSON array exceeds the safe limit")
        for child in value:
            _validate_json_tree(child, depth + 1, counter, reject_nul=reject_nul)
        return
    if type(value) is str:
        require(len(value) <= MAX_JSON_STRING_LENGTH, "JSON string is unsafe")
        if reject_nul:
            require("\x00" not in value, "JSON string is unsafe")
        return
    if type(value) is float:
        require(math.isfinite(value), "JSON number is not finite")
        return
    if type(value) is int:
        require(abs(value) <= MAX_INTEGER, "JSON integer is too large")
        return
    require(value is None or type(value) is bool, "unsupported JSON value type")


def load_json(
    path: Path,
    *,
    require_object: bool = True,
    limit: int = MAX_JSON_BYTES,
    reject_nul: bool = True,
) -> Any:
    data = _read_bounded_bytes(path, limit)
    try:
        text = data.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_int=_parse_int,
            parse_float=_parse_float,
            parse_constant=_reject_constant,
        )
    except ValidationError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError, ValueError) as exc:
        raise ValidationError() from exc
    _validate_json_tree(value, reject_nul=reject_nul)
    if require_object:
        require(type(value) is dict, "top-level JSON value must be an object")
    return value


def _normalize_key(key: str) -> str:
    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
    return re.sub(r"[-.:/\s]+", "_", separated).casefold()


def _is_explicit_synthetic_marker(value: str) -> bool:
    lowered = value.casefold()
    return (
        lowered in STRUCTURAL_SENSITIVE_MARKERS
        or any(marker in lowered for marker in ("synthetic", "fixture", "example", "placeholder", "hidden", "audit", "nested", "signature-value"))
        or re.fullmatch(r"(?:akia)?(?:x|z|0){8,}", lowered) is not None
    )


def _is_placeholder(
    value: str,
    *,
    allow_synthetic_markers: bool = False,
    allow_structural_placeholders: bool = True,
) -> bool:
    lowered = value.casefold()
    structural = (
        "body." in lowered
        or "request." in lowered
        or "source." in lowered
        or lowered.endswith((".password", ".token", ".ticket", ".cookie"))
    )
    return (
        value.startswith("<")
        or lowered in {"false", "none", "null", "redacted", "not_recorded", "not_retained"}
        or (allow_structural_placeholders and structural)
        or (allow_synthetic_markers and _is_explicit_synthetic_marker(value))
    )


def _validate_sensitive_marker(value: Any, *, key: str = "") -> None:
    if value is None:
        return
    if type(value) is bool:
        require(value is False or key == "present", "sensitive field must be redacted")
        return
    if type(value) is str:
        require(len(value) <= 128, "sensitive marker is too long")
        require(SENSITIVE_MARKER.fullmatch(value) is not None or _is_placeholder(value), "sensitive value is not a marker")
        return
    if type(value) is list:
        require(len(value) <= 32, "sensitive marker list is too large")
        for child in value:
            _validate_sensitive_marker(child, key=key)
        return
    if type(value) is dict:
        for child_key, child in value.items():
            normalized = _normalize_key(child_key)
            require(normalized in SENSITIVE_DESCRIPTOR_KEYS, "sensitive descriptor key is not allowed")
            _validate_sensitive_marker(child, key=normalized)
        return
    raise ValidationError()


def _regex_host_literals(raw_url: str) -> tuple[str, ...]:
    scheme = re.match(r"(?:https?|wss?)://", raw_url, re.IGNORECASE)
    if scheme is None:
        return ()
    remainder = raw_url[scheme.end():]
    host_text = re.split(r"[/\\?#]", remainder, maxsplit=1)[0]
    # Escaped dots are literal punctuation in a detector regex. Character
    # classes and quantifiers remain syntax, while every concrete dotted host
    # fragment is still checked against the same allowlist as ordinary URLs.
    host_text = host_text.replace(r"\.", ".")
    return tuple(dict.fromkeys(REGEX_HOST_LITERAL_PATTERN.findall(host_text)))


def _require_allowed_url_host(host: str, *, allow_synthetic_markers: bool) -> None:
    lowered = host.casefold().replace(r"\.", ".").rstrip(".`'\"),]}>;:!? ")
    if lowered.startswith("<") and lowered.endswith(">"):
        return
    require(
        lowered.endswith(".test")
        or lowered.endswith(".invalid")
        or lowered.endswith(".example")
        or lowered.endswith(".example.com")
        or lowered == "host"
        or lowered in ALLOWED_URL_HOSTS
        or (allow_synthetic_markers and lowered == "localhost"),
        "live URL host is not allowed",
    )


def _validate_url_hosts(
    value: str,
    *,
    allow_synthetic_markers: bool = False,
    regex_pattern: bool = False,
) -> None:
    for match in URL_PATTERN.finditer(value):
        raw_url = match.group(0)
        if regex_pattern:
            for host in _regex_host_literals(raw_url):
                _require_allowed_url_host(host, allow_synthetic_markers=allow_synthetic_markers)
            continue
        try:
            parsed = urlsplit(raw_url)
            host = parsed.hostname
        except ValueError as exc:
            raise ValidationError() from exc
        if host:
            _require_allowed_url_host(host, allow_synthetic_markers=allow_synthetic_markers)


def _validate_text_value(
    value: str,
    *,
    check_assignments: bool = True,
    allow_synthetic_markers: bool = False,
    allowed_basic_auth_candidates: frozenset[str] = frozenset(),
    allowed_raw_rfc7617_tokens: frozenset[str] = frozenset(),
    allowed_assignment_values: frozenset[str] = frozenset(),
    allowed_synthetic_full_values: frozenset[str] = frozenset(),
    regex_pattern: bool = False,
) -> None:
    # Strip every C0/C1 control before matching. Retained fixtures may contain
    # malformed-input bytes, but controls must never split a credential or URL
    # into fragments that evade the shared scanners.
    scanned_value = UNSAFE_CONTROL_PATTERN.sub("", value)
    for match in PRIVATE_KEY_PATTERN.finditer(scanned_value):
        candidate = match.group(0)
        require(
            allow_synthetic_markers
            and (
                _is_explicit_synthetic_marker(candidate)
                or value in allowed_synthetic_full_values
            ),
            "private key material is not allowed",
        )
    for pattern, message in (
        (AWS_KEY_PATTERN, "provider key material is not allowed"),
        (PROVIDER_TOKEN_PATTERN, "provider token material is not allowed"),
    ):
        for match in pattern.finditer(scanned_value):
            candidate = match.group(0)
            require(
                allow_synthetic_markers
                and _is_placeholder(
                    candidate,
                    allow_synthetic_markers=True,
                    allow_structural_placeholders=False,
                ),
                message,
            )
    allowed_rfc7617_tokens = allowed_basic_auth_candidates | allowed_raw_rfc7617_tokens
    for match in RAW_RFC7617_TOKEN_PATTERN.finditer(scanned_value):
        candidate = match.group(0)
        require(candidate in allowed_rfc7617_tokens, "raw RFC 7617 token is not allowed")
    patterns = (BEARER_VALUE_PATTERN, BASIC_VALUE_PATTERN, JWT_PATTERN)
    if check_assignments:
        patterns += (ASSIGNMENT_SECRET_PATTERN,)
    for pattern in patterns:
        for match in pattern.finditer(scanned_value):
            candidate = match.group(1) if match.lastindex else match.group(0)
            exact_basic_allowance = (
                pattern is BASIC_VALUE_PATTERN
                and candidate in allowed_basic_auth_candidates
            )
            exact_assignment_allowance = (
                pattern is ASSIGNMENT_SECRET_PATTERN
                and candidate in allowed_assignment_values
            )
            # Synthetic marker vocabulary is useful only for path-scoped
            # negative fixtures, and never turns a Basic value into a marker.
            placeholder = _is_placeholder(
                candidate,
                allow_synthetic_markers=(allow_synthetic_markers and pattern is not BASIC_VALUE_PATTERN),
                # Dotted source expressions are allowed only by an exact
                # path/value assignment allowance. They must not make a
                # credential-shaped Bearer, Basic, JWT, or assignment value
                # look redacted merely because it resembles source syntax.
                allow_structural_placeholders=False,
            )
            require(
                exact_basic_allowance or exact_assignment_allowance or placeholder,
                "credential-shaped value is not allowed",
            )
    _validate_url_hosts(
        scanned_value,
        allow_synthetic_markers=allow_synthetic_markers,
        regex_pattern=regex_pattern,
    )


def _validate_redaction_tree(
    value: Any,
    *,
    allowed_assignment_values: frozenset[str] = frozenset(),
) -> None:
    if type(value) is dict:
        for key, child in value.items():
            # Object keys are retained input too. Scan them before treating a
            # normalized key as structural so nested credential-shaped keys
            # cannot bypass the value scanner.
            _validate_text_value(
                key,
                allowed_assignment_values=allowed_assignment_values,
            )
            normalized = _normalize_key(key)
            if normalized in SENSITIVE_KEYS:
                _validate_sensitive_marker(child, key=normalized)
            else:
                _validate_redaction_tree(
                    child,
                    allowed_assignment_values=allowed_assignment_values,
                    )
        return
    if type(value) is list:
        for child in value:
            _validate_redaction_tree(
                child,
                allowed_assignment_values=allowed_assignment_values,
            )
        return
    if type(value) is str:
        _validate_text_value(
            value,
            allowed_assignment_values=allowed_assignment_values,
        )


def _validate_text_file(
    path: Path,
    *,
    allowed_assignment_values: frozenset[str] = frozenset(),
) -> None:
    data = _read_bounded_bytes(path, MAX_ARTIFACT_BYTES)
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise ValidationError() from exc
    require(len(text) <= MAX_ARTIFACT_BYTES, "text artifact is too large")
    # Markdown and text are retained artifacts too; disabling assignment
    # matching here would let password=, token=, ticket=, cookie=, or secret=
    # values bypass the shared redaction boundary. One reviewed negative-test
    # fragment remains exact-path and exact-value scoped below.
    _validate_text_value(
        text,
        check_assignments=True,
        allowed_assignment_values=allowed_assignment_values,
    )


_STATIC_UNKNOWN = object()
# Unknown runtime fields are rendered as an explicit synthetic host/value. The
# pre-dot portion is long enough to trigger Basic detection, while the `.invalid`
# suffix remains an allowed host boundary for dynamic URL diagnostics.
_STATIC_DYNAMIC_VALUE = "syntheticinvalid.invalid"


def _static_scalar(value: Any) -> Any:
    if type(value) is str:
        return value
    if type(value) is bytes:
        try:
            return value.decode("utf-8")
        except UnicodeError:
            return _STATIC_UNKNOWN
    if type(value) in {int, float, bool} or value is None:
        return value
    return _STATIC_UNKNOWN


def _bounded_static_text(value: Any) -> Any:
    if type(value) is str and len(value) <= MAX_ARTIFACT_BYTES:
        return value
    return _STATIC_UNKNOWN


def _static_value(node: ast.AST, bindings: dict[str, Any]) -> Any:
    if isinstance(node, ast.Constant):
        return _static_scalar(node.value)
    if isinstance(node, ast.Name):
        return bindings.get(node.id, _STATIC_UNKNOWN)
    if isinstance(node, ast.JoinedStr):
        pieces: list[str] = []
        for part in node.values:
            if isinstance(part, ast.Constant):
                literal = _static_scalar(part.value)
                if type(literal) is not str:
                    return _STATIC_UNKNOWN
                pieces.append(literal)
                continue
            if not isinstance(part, ast.FormattedValue):
                return _STATIC_UNKNOWN
            formatted = _static_value(part.value, bindings)
            if formatted is _STATIC_UNKNOWN:
                return _STATIC_UNKNOWN
            if part.conversion == 115:
                formatted = str(formatted)
            elif part.conversion == 114:
                formatted = repr(formatted)
            elif part.conversion == 97:
                formatted = ascii(formatted)
            format_spec = ""
            if part.format_spec is not None:
                format_spec = _static_value(part.format_spec, bindings)
                if type(format_spec) is not str:
                    return _STATIC_UNKNOWN
            try:
                pieces.append(format(formatted, format_spec))
            except (TypeError, ValueError, OverflowError):
                return _STATIC_UNKNOWN
        return _bounded_static_text("".join(pieces))
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        left = _static_value(node.left, bindings)
        right = _static_value(node.right, bindings)
        if isinstance(node.op, ast.Add) and type(left) is str and type(right) is str:
            return _bounded_static_text(left + right)
        if isinstance(node.op, ast.Mod) and type(left) is str and right is not _STATIC_UNKNOWN:
            try:
                return _bounded_static_text(left % right)
            except (IndexError, KeyError, TypeError, ValueError, OverflowError):
                return _STATIC_UNKNOWN
        return _STATIC_UNKNOWN
    if isinstance(node, (ast.List, ast.Tuple)):
        values: list[Any] = []
        for child in node.elts:
            value = _static_value(child, bindings)
            if value is _STATIC_UNKNOWN:
                return _STATIC_UNKNOWN
            values.append(value)
        return values if isinstance(node, ast.List) else tuple(values)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        method = node.func.attr
        receiver = _static_value(node.func.value, bindings)
        if method == "format" and type(receiver) is str:
            args: list[Any] = []
            for argument in node.args:
                value = _static_value(argument, bindings)
                if value is _STATIC_UNKNOWN:
                    return _STATIC_UNKNOWN
                args.append(value)
            keywords: dict[str, Any] = {}
            for keyword in node.keywords:
                if keyword.arg is None:
                    return _STATIC_UNKNOWN
                value = _static_value(keyword.value, bindings)
                if value is _STATIC_UNKNOWN:
                    return _STATIC_UNKNOWN
                keywords[keyword.arg] = value
            try:
                return _bounded_static_text(receiver.format(*args, **keywords))
            except (IndexError, KeyError, ValueError, TypeError, OverflowError):
                return _STATIC_UNKNOWN
        if method == "join" and type(receiver) is str and len(node.args) == 1 and not node.keywords:
            values = _static_value(node.args[0], bindings)
            if isinstance(values, (list, tuple)) and all(type(value) is str for value in values):
                return _bounded_static_text(receiver.join(values))
    return _STATIC_UNKNOWN


def _conservative_text(node: ast.AST, bindings: dict[str, Any]) -> str:
    """Render unresolved string expressions with a credential-shaped sentinel."""
    value = _static_value(node, bindings)
    if type(value) is str:
        return value
    if isinstance(node, ast.Constant):
        literal = _static_scalar(node.value)
        return literal if type(literal) is str else _STATIC_DYNAMIC_VALUE
    if isinstance(node, ast.Name):
        bound = bindings.get(node.id, _STATIC_UNKNOWN)
        return bound if type(bound) is str else _STATIC_DYNAMIC_VALUE
    if isinstance(node, ast.JoinedStr):
        pieces: list[str] = []
        for part in node.values:
            if isinstance(part, ast.Constant):
                literal = _static_scalar(part.value)
                pieces.append(literal if type(literal) is str else _STATIC_DYNAMIC_VALUE)
            elif isinstance(part, ast.FormattedValue):
                pieces.append(_conservative_text(part.value, bindings))
            else:
                pieces.append(_STATIC_DYNAMIC_VALUE)
        return "".join(pieces)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        left = _conservative_text(node.left, bindings)
        right = _conservative_text(node.right, bindings)
        if isinstance(node.op, ast.Add):
            return left + right
        try:
            if isinstance(node.right, ast.Tuple):
                values = tuple(_conservative_text(child, bindings) for child in node.right.elts)
                return left % values
            return left % right
        except (IndexError, KeyError, TypeError, ValueError, OverflowError):
            return left + " " + right
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        method = node.func.attr
        receiver = _conservative_text(node.func.value, bindings)
        if method == "format":
            args = [_conservative_text(argument, bindings) for argument in node.args]
            keywords = {
                keyword.arg: _conservative_text(keyword.value, bindings)
                for keyword in node.keywords
                if keyword.arg is not None
            }
            try:
                return receiver.format(*args, **keywords)
            except (IndexError, KeyError, ValueError, TypeError, OverflowError):
                return receiver + " " + " ".join(args + list(keywords.values()))
        if method == "join" and len(node.args) == 1 and not node.keywords:
            sequence = node.args[0]
            if isinstance(sequence, (ast.List, ast.Tuple)):
                return receiver.join(_conservative_text(child, bindings) for child in sequence.elts)
            # Preserve the known separator and mark only the unknown payload.
            # A credential prefix in the receiver still fails closed, while an
            # unrelated dynamic join does not invent credential syntax that is
            # absent from the retained source.
            return receiver + _STATIC_DYNAMIC_VALUE
    return _STATIC_DYNAMIC_VALUE


def _collect_static_bindings(tree: ast.AST) -> dict[str, Any]:
    bindings: dict[str, Any] = {}
    # A few fixed passes resolve simple module/function-local chains without
    # executing source. Unresolved runtime values remain represented by the
    # conservative sentinel and therefore cannot hide a credential prefix.
    for _ in range(4):
        changed = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                value = _static_value(node.value, bindings)
                targets = node.targets
            elif isinstance(node, ast.AnnAssign):
                value = _static_value(node.value, bindings) if node.value is not None else _STATIC_UNKNOWN
                targets = (node.target,)
            elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
                value = _STATIC_UNKNOWN
                targets = (node.target,)
            else:
                continue
            if value is not _STATIC_UNKNOWN and not isinstance(value, (str, list, tuple)):
                value = _STATIC_UNKNOWN
            for target in targets:
                if isinstance(target, ast.Name) and bindings.get(target.id, _STATIC_UNKNOWN) != value:
                    bindings[target.id] = value
                    changed = True
        if not changed:
            break
    return bindings


def _regex_call_nodes(tree: ast.AST) -> set[int]:
    result: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "compile" or not isinstance(node.func.value, ast.Name) or node.func.value.id not in {"re", "regex"}:
            continue
        result.update(id(child) for child in ast.walk(node))
    return result


def _validate_python_file(
    path: Path,
    *,
    allow_synthetic_markers: bool = False,
    allow_test_negative_basic_auth: bool = False,
    allow_test_negative_rfc7617_token: bool = False,
    allowed_assignment_values: frozenset[str] = frozenset(),
    allowed_synthetic_full_values: frozenset[str] = frozenset(),
) -> None:
    """Scan Python literals, comments, and bounded string constructions.

    Fixture tests intentionally contain credential-shaped inputs to prove that
    their domain validators reject them. Regex-call arguments are still
    scanned for concrete credential data; only regex syntax is treated as such
    when checking URL hosts. The two exact negative-test allowances are passed
    by the manifest path, never inferred from a string's synthetic marker.
    """
    data = _read_bounded_bytes(path, MAX_ARTIFACT_BYTES)
    try:
        text = data.decode("utf-8")
        tree = ast.parse(text, filename=path.as_posix())
    except (UnicodeError, SyntaxError) as exc:
        raise ValidationError() from exc
    require(len(text) <= MAX_ARTIFACT_BYTES, "text artifact is too large")

    allowed_basic_auth_candidates = (
        TEST_NEGATIVE_BASIC_AUTH_CANDIDATES
        if allow_test_negative_basic_auth
        else frozenset()
    )
    allowed_raw_rfc7617_tokens = (
        TEST_NEGATIVE_BASIC_AUTH_CANDIDATES
        if allow_test_negative_rfc7617_token
        else frozenset()
    )
    bindings = _collect_static_bindings(tree)
    regex_nodes = _regex_call_nodes(tree)

    def scan(value: str, *, regex_pattern: bool = False) -> None:
        _validate_text_value(
            value,
            check_assignments=True,
            allow_synthetic_markers=allow_synthetic_markers,
            allowed_basic_auth_candidates=allowed_basic_auth_candidates,
            allowed_raw_rfc7617_tokens=allowed_raw_rfc7617_tokens,
            allowed_assignment_values=allowed_assignment_values,
            allowed_synthetic_full_values=allowed_synthetic_full_values,
            regex_pattern=regex_pattern,
        )

    for node in ast.walk(tree):
        regex_pattern = id(node) in regex_nodes
        if isinstance(node, ast.Constant):
            value = _static_scalar(node.value)
            if type(value) is str:
                scan(value, regex_pattern=regex_pattern)
        elif isinstance(node, (ast.JoinedStr, ast.BinOp, ast.Call)):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "compile":
                continue
            scan(_conservative_text(node, bindings), regex_pattern=regex_pattern)

    # Comments document detector rules and may contain source-shaped examples;
    # scan them too, with the same exact path-scoped allowances.
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.COMMENT:
                scan(token.string)
    except tokenize.TokenError as exc:
        raise ValidationError() from exc


def _safe_relative_path(value: Any, *, allow_directory: bool = False) -> str:
    require(type(value) is str and value and len(value) <= 240, "path is invalid")
    require("\x00" not in value and "\\" not in value and SAFE_PATH.fullmatch(value) is not None, "path is invalid")
    parts = value.split("/")
    require(all(part not in {"", ".", ".."} for part in parts), "path traversal is not allowed")
    if not allow_directory:
        require("." in parts[-1], "file path must name a file")
    return value


def _safe_child(root: Path, relative: str) -> Path:
    root_resolved = root.resolve()
    candidate = root / relative
    require(not candidate.is_symlink(), "artifact path must not be a symlink")
    try:
        child = candidate.resolve(strict=True)
        child.relative_to(root_resolved)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValidationError() from exc
    require(child.is_file(), "artifact path is not a regular file")
    return child


def _validate_digest(value: Any) -> str:
    require(type(value) is str and HEX64.fullmatch(value) is not None, "artifact digest is invalid")
    return value


def _canonical_validator_source_digest(data: bytes) -> str:
    matches = BASELINE_ANCHOR_PATTERN.findall(data)
    require(len(matches) == 1, "validator baseline anchor is missing")
    normalized = BASELINE_ANCHOR_PATTERN.sub(
        b'BASELINE_CANONICAL_SHA256 = "baseline-canonical-sha256"',
        data,
        count=1,
    )
    return hashlib.sha256(normalized).hexdigest()


def _trusted_validator_source_digest(repo_root: Path) -> str:
    anchor_path = _safe_child(repo_root.resolve(), VALIDATOR_TRUST_ANCHOR_PATH)
    try:
        source = _read_bounded_bytes(anchor_path, MAX_ARTIFACT_BYTES).decode("utf-8")
    except UnicodeError as exc:
        raise ValidationError() from exc
    matches = TRUST_ANCHOR_PATTERN.findall(source)
    require(len(matches) == 1, "validator trust anchor is missing")
    return matches[0]


def _validate_schema_document(schema: dict[str, Any]) -> None:
    strict_keys(schema, SCHEMA_KEYS, "schema")
    require(schema["$schema"] == "https://json-schema.org/draft/2020-12/schema", "schema dialect changed")
    require(schema["$id"] == SCHEMA_DOCUMENT_ID, "schema identifier changed")
    require(schema["title"] == "Hermternal language-neutral fixture index", "schema title changed")
    require(schema["type"] == "object" and schema["additionalProperties"] is False, "schema root changed")
    require(tuple(schema["required"]) == INDEX_KEYS, "schema required key order changed")
    properties = schema["properties"]
    require(type(properties) is dict and tuple(properties.keys()) == INDEX_KEYS, "schema properties changed")
    defs = schema["$defs"]
    expected_defs = ("path", "sha256", "platforms", "file", "fixture", "coverage", "parity", "state", "redaction", "benchmark")
    require(type(defs) is dict and tuple(defs.keys()) == expected_defs, "schema definitions changed")
    require(properties["schema"] == {"const": INDEX_SCHEMA}, "schema version rule changed")
    require(properties["contract"] == {"const": CONTRACT}, "schema contract rule changed")
    require(properties["synthetic_only"] == {"const": True}, "schema synthetic rule changed")
    require(properties["live_claim"] == {"const": False}, "schema live-claim rule changed")
    require(properties["evidence_status"] == {"enum": ["partial", "complete"]}, "schema evidence status changed")


def _validate_id(value: Any) -> str:
    require(type(value) is str and len(value) <= 120 and SAFE_ID.fullmatch(value) is not None, "identifier is invalid")
    return value


def _validate_string_list(value: Any, allowed: Iterable[str], *, nonempty: bool = True) -> tuple[str, ...]:
    require(type(value) is list, "list is required")
    if nonempty:
        require(bool(value), "list must not be empty")
    result: list[str] = []
    allowed_set = set(allowed)
    for item in value:
        require(type(item) is str and item in allowed_set, "list item is invalid")
        require(item not in result, "list contains a duplicate")
        result.append(item)
    return tuple(result)


def _validate_states(states: Any) -> tuple[str, ...]:
    require(type(states) is list, "state inventory must be a list")
    require(tuple(item.get("id") for item in states if type(item) is dict) == STATE_IDS, "state inventory changed")
    expected = {
        "pending": ("collection_in_progress", "blocked", "no_success_claim", "wait_or_cancel"),
        "empty": ("no_observations", "blocked", "no_success_claim", "collect_required_evidence"),
        "success": ("synthetic_fixture_validated", "blocked_live_compatibility", "artifact_only_no_live_claim", "not_applicable"),
        "failure": ("required_case_failed", "blocked", "retain_failure_evidence", "idempotent_collection_only"),
        "cancelled": ("cancelled_before_completion", "blocked", "no_outward_change", "resume_after_source_state_reread"),
        "unknown": ("result_unavailable", "blocked", "no_duplicate_prompt_session_ticket_or_pty_input", "reread_source_state_before_retry"),
    }
    for index, item in enumerate(states):
        record = strict_keys(item, STATE_KEYS, f"states[{index}]")
        identifier = _validate_id(record["id"])
        require(identifier == STATE_IDS[index], "state order changed")
        require(tuple(record[key] for key in STATE_KEYS[1:]) == expected[identifier], "state semantics changed")
        for key in STATE_KEYS[1:]:
            require(type(record[key]) is str and record[key], "state value is invalid")
    return STATE_IDS


def _validate_file_record(record: Any, index: int) -> tuple[str, str, int]:
    item = strict_keys(record, FILE_KEYS, f"files[{index}]")
    path = _safe_relative_path(item["path"])
    digest = _validate_digest(item["sha256"])
    require(type(item["size_bytes"]) is int and type(item["size_bytes"]) is not bool and item["size_bytes"] >= 0, "artifact size is invalid")
    return path, digest, item["size_bytes"]


def _validate_manifest_file(
    record: Any,
    *,
    fixtures_root: Path,
    fixture_relative_root: str,
    total_bytes: list[int],
) -> str:
    path, digest, size = _validate_file_record(record, 0)
    require(path == fixture_relative_root or path.startswith(fixture_relative_root + "/"), "artifact escapes fixture root")
    actual = _safe_child(fixtures_root, path)
    data = _read_bounded_bytes(actual, MAX_ARTIFACT_BYTES)
    require(size == len(data), "artifact size changed")
    require(digest == hashlib.sha256(data).hexdigest(), "artifact digest changed")
    total_bytes[0] += len(data)
    require(total_bytes[0] <= MAX_TOTAL_ARTIFACT_BYTES, "fixture artifacts exceed aggregate byte limit")
    relative_path = actual.relative_to(fixtures_root).as_posix()
    suffix = actual.suffix.casefold()
    # A registered file must have a scanner with defined semantics. Digesting
    # an unknown extension without inspecting its content would create an
    # unscanned credential boundary, so fail closed instead.
    require(suffix in SCANNED_ARTIFACT_SUFFIXES, "registered artifact extension is unsupported")
    allowed_assignment_values = EXACT_ASSIGNMENT_ALLOWANCES.get(relative_path, frozenset())
    allowed_synthetic_full_values = SYNTHETIC_FULL_VALUE_ALLOWANCES.get(relative_path, frozenset())
    if suffix == ".json":
        document = load_json(actual, require_object=False, limit=MAX_ARTIFACT_BYTES, reject_nul=False)
        _validate_redaction_tree(
            document,
            allowed_assignment_values=allowed_assignment_values,
        )
        _reject_live_claims(document)
    elif suffix == ".py":
        _validate_python_file(
            actual,
            allow_synthetic_markers=relative_path in SYNTHETIC_MARKER_PATHS,
            allow_test_negative_basic_auth=relative_path in TEST_NEGATIVE_BASIC_AUTH_PATHS,
            allow_test_negative_rfc7617_token=relative_path in TEST_NEGATIVE_RFC7617_TOKEN_PATHS,
            allowed_assignment_values=allowed_assignment_values,
            allowed_synthetic_full_values=allowed_synthetic_full_values,
        )
    else:
        _validate_text_file(
            actual,
            allowed_assignment_values=allowed_assignment_values,
        )
    return path


def _reject_live_claims(value: Any) -> None:
    if type(value) is dict:
        for key, child in value.items():
            normalized = _normalize_key(key)
            if normalized in {"live_claim", "live_run", "live_compatibility", "compatible"} and type(child) is bool:
                require(child is False, "fixture contains a live claim")
            _reject_live_claims(child)
    elif type(value) is list:
        for child in value:
            _reject_live_claims(child)


def _actual_fixture_files(relative_root: str, fixtures_root: Path) -> list[str]:
    candidate = fixtures_root / relative_root
    require(not candidate.is_symlink(), "fixture root must not be a symlink")
    directory = candidate.resolve()
    try:
        directory.relative_to(fixtures_root.resolve())
    except ValueError as exc:
        raise ValidationError() from exc
    require(directory.is_dir(), "fixture root is missing")
    files: list[str] = []
    for path in sorted(directory.rglob("*")):
        if path.is_dir():
            require(not path.is_symlink(), "fixture directory contains a symlink")
            continue
        if path.name == ".DS_Store" or "__pycache__" in path.parts or path.suffix.casefold() == ".pyc":
            continue
        require(not path.is_symlink() and path.is_file(), "fixture contains an unsafe file")
        files.append(path.relative_to(fixtures_root).as_posix())
    require(bool(files), "fixture root has no files")
    return files


def _validate_fixture_roots(
    document: dict[str, Any],
    state_ids: tuple[str, ...],
    coverage_ids: set[str],
    fixtures_root: Path,
) -> tuple[dict[str, str], set[str]]:
    roots = document["fixture_roots"]
    require(type(roots) is list and bool(roots), "fixture roots are missing")
    seen_ids: dict[str, str] = {}
    seen_paths: set[str] = set()
    owned_files: set[str] = set()
    total_bytes = [0]
    previous_id = ""
    for index, raw in enumerate(roots):
        item = strict_keys(raw, FIXTURE_KEYS, f"fixture_roots[{index}]")
        identifier = _validate_id(item["id"])
        require(identifier > previous_id, "fixture roots must be sorted and unique")
        previous_id = identifier
        require(identifier not in seen_ids, "fixture id is duplicated")
        seen_ids[identifier] = item["status"]
        path = _safe_relative_path(item["path"], allow_directory=True)
        require(path not in seen_paths, "fixture path is duplicated")
        seen_paths.add(path)
        require(item["status"] in {"ready", "pending"}, "fixture status is invalid")
        require(item["contract"] == CONTRACT, "fixture contract changed")
        require(item["hermes_source_sha"] == HERMES_SOURCE_SHA and HEX40.fullmatch(item["hermes_source_sha"]), "fixture source pin changed")
        require(item["synthetic_only"] is True and item["live_claim"] is False, "fixture live boundary changed")
        _validate_string_list(item["platforms"], PLATFORMS)
        states = _validate_string_list(item["states"], state_ids)
        require(tuple(sorted(states)) == states, "fixture states must be sorted")
        fixture_coverage = _validate_string_list(item["coverage_ids"], coverage_ids)
        require(tuple(sorted(fixture_coverage)) == fixture_coverage, "fixture coverage ids must be sorted")
        validator = item["validator"]
        if validator is not None:
            _safe_relative_path(validator)
        files = item["files"]
        require(type(files) is list, "fixture files must be a list")
        if item["status"] == "pending":
            require(validator is None and files == [], "pending fixture must not claim artifacts")
            continue
        require(bool(files), "ready fixture must list artifacts")
        actual_files = _actual_fixture_files(path, fixtures_root)
        listed: list[str] = []
        for file_index, file_record in enumerate(files):
            record_path, _, _ = _validate_file_record(file_record, file_index)
            require(record_path > (listed[-1] if listed else ""), "fixture files must be sorted and unique")
            listed.append(record_path)
            owned_files.add(record_path)
        require(tuple(listed) == tuple(actual_files), "fixture file manifest is incomplete or stale")
        if validator is not None:
            require(validator in {file.removeprefix(path + "/") for file in actual_files}, "fixture validator is not listed")
        for file_index, file_record in enumerate(files):
            _validate_manifest_file(file_record, fixtures_root=fixtures_root, fixture_relative_root=path, total_bytes=total_bytes)
    require(len(seen_ids) == len(roots), "fixture id inventory is inconsistent")
    return seen_ids, owned_files


def _validate_coverage(
    document: dict[str, Any],
    fixture_statuses: dict[str, str],
    state_ids: tuple[str, ...],
) -> tuple[set[str], set[str]]:
    coverage = document["coverage"]
    require(type(coverage) is list and bool(coverage), "coverage inventory is missing")
    seen: set[str] = set()
    previous = ""
    fixture_to_coverage: set[str] = set()
    for index, raw in enumerate(coverage):
        item = strict_keys(raw, COVERAGE_KEYS, f"coverage[{index}]")
        identifier = _validate_id(item["id"])
        require(identifier > previous, "coverage ids must be sorted and unique")
        previous = identifier
        require(identifier not in seen, "coverage id is duplicated")
        seen.add(identifier)
        status = item["status"]
        require(status in {"ready", "pending", "empty", "failure", "cancelled", "unknown"}, "coverage status is invalid")
        references = _validate_string_list(item["fixture_ids"], set(fixture_statuses), nonempty=False)
        require(tuple(sorted(references)) == references, "coverage fixture ids must be sorted")
        fixture_to_coverage.update(references)
        platforms = _validate_string_list(item["platforms"], PLATFORMS)
        require(tuple(sorted(platforms, key=PLATFORMS.index)) == platforms, "coverage platforms must use shared order")
        states = _validate_string_list(item["required_states"], state_ids)
        require(tuple(sorted(states, key=STATE_IDS.index)) == states, "coverage states must use shared order")
        require(type(item["notes"]) is str and 0 < len(item["notes"]) <= 512, "coverage note is invalid")
        _validate_text_value(item["notes"])
        if status == "ready":
            require(bool(references), "ready coverage must cite a fixture")
            require(
                all(fixture_statuses.get(reference) == "ready" for reference in references),
                "ready coverage cites a pending or missing fixture",
            )
    require(fixture_to_coverage, "fixture roots are not connected to coverage")
    return seen, fixture_to_coverage


def _validate_index_document(document: dict[str, Any], repo_root: Path) -> tuple[int, int]:
    fixtures_root = (repo_root / "contracts/fixtures").resolve()
    require(fixtures_root.is_dir(), "fixture root is missing")
    strict_keys(document, INDEX_KEYS, "index")
    require(document["schema"] == INDEX_SCHEMA, "index schema changed")
    require(document["contract"] == CONTRACT, "index contract changed")
    require(document["hermes_source_sha"] == HERMES_SOURCE_SHA and HEX40.fullmatch(document["hermes_source_sha"]), "index source pin changed")
    require(document["synthetic_only"] is True and document["live_claim"] is False, "index live boundary changed")
    require(document["evidence_status"] in {"partial", "complete"}, "index evidence status is invalid")

    state_ids = _validate_states(document["states"])
    parity = strict_keys(document["parity"], PARITY_KEYS, "parity")
    require(parity == {
        "status": "synthetic_observed",
        "fixture_source": "one_shared_registry",
        "platforms": list(PLATFORMS),
        "pty_policy": "web_only_apple_blocked",
        "missing_result_policy": "block",
        "result_equivalence": "semantic_outcomes_not_platform_specific_wire_bytes",
        "live_claim": False,
    }, "parity contract changed")
    redaction = strict_keys(document["redaction"], REDACTION_KEYS, "redaction")
    require(redaction == {
        "synthetic_only": True,
        "contains_credentials": False,
        "contains_cookies": False,
        "contains_bearer_values": False,
        "contains_ticket_values": False,
        "contains_raw_pty_bytes": False,
        "contains_transcripts": False,
        "contains_live_hosts": False,
        "contains_user_data": False,
        "failure_output": "one_bounded_semantic_json_line",
    }, "redaction contract changed")
    benchmark = strict_keys(document["benchmark"], BENCHMARK_KEYS, "benchmark")
    benchmark_path = _safe_relative_path(benchmark["path"])
    require(benchmark_path == "validator/validation-baseline.json", "benchmark path changed")
    require(benchmark["threshold"] is None, "benchmark threshold must remain null")
    require(benchmark["evidence_mode"] == "observed_worktree_only", "benchmark evidence mode changed")
    require(benchmark["build_mode"] == "N/A - no production or release executable", "benchmark build mode changed")
    _safe_child(fixtures_root, benchmark_path)

    fixture_statuses, owned_files = _validate_fixture_roots(
        document,
        state_ids,
        set(item["id"] for item in document["coverage"]),
        fixtures_root,
    )
    coverage_ids, referenced_fixtures = _validate_coverage(document, fixture_statuses, state_ids)
    require(referenced_fixtures == set(fixture_statuses), "every fixture root must be covered exactly at least once")
    require(document["evidence_status"] == ("complete" if not any(item["status"] != "ready" for item in document["coverage"]) else "partial"), "evidence status does not reflect pending coverage")
    if document["evidence_status"] == "complete":
        require(not any(item["status"] != "ready" for item in document["coverage"]), "complete index contains blocked coverage")
    else:
        require(any(item["status"] != "ready" for item in document["coverage"]), "partial index has no blocked coverage")

    all_owned_candidates: set[str] = set()
    for path in fixtures_root.rglob("*"):
        if not path.is_file() or path.is_symlink() or path.name == ".DS_Store" or "__pycache__" in path.parts or path.suffix.casefold() == ".pyc":
            continue
        relative = path.relative_to(fixtures_root).as_posix()
        if relative in {"README.md", "index.json", "schema.json"} or relative.startswith("validator/"):
            continue
        all_owned_candidates.add(relative)
    require(all_owned_candidates == owned_files, "unindexed fixture artifact exists")
    return len(fixture_statuses), len(coverage_ids)


def _validate_distribution(samples: list[Any], distribution: dict[str, Any]) -> None:
    require(len(samples) == BASELINE_REPETITIONS, "benchmark sample count changed")
    numeric: list[float] = []
    for sample in samples:
        require(type(sample) in {int, float} and type(sample) is not bool, "benchmark sample is not numeric")
        value = float(sample)
        require(math.isfinite(value) and 0 <= value <= 1_000_000, "benchmark sample is not bounded")
        numeric.append(value)
    strict_keys(distribution, DISTRIBUTION_KEYS, "benchmark distribution")
    values: list[float] = []
    for key in DISTRIBUTION_KEYS:
        value = distribution[key]
        require(type(value) in {int, float} and type(value) is not bool, "benchmark distribution is not numeric")
        converted = float(value)
        require(math.isfinite(converted) and 0 <= converted <= 1_000_000, "benchmark distribution is not bounded")
        values.append(converted)
    ordered = sorted(numeric)
    p50 = ordered[min(len(ordered) - 1, max(0, math.ceil(0.50 * len(ordered)) - 1))]
    p95 = ordered[min(len(ordered) - 1, max(0, math.ceil(0.95 * len(ordered)) - 1))]
    expected = {
        "min": min(numeric),
        "p50": p50,
        "p95": p95,
        "max": max(numeric),
        "mean": statistics.mean(numeric),
    }
    for key in DISTRIBUTION_KEYS:
        require(abs(float(distribution[key]) - expected[key]) < 0.001, "benchmark distribution does not match samples")
    require(values[0] <= values[1] <= values[2] <= values[3], "benchmark distribution is incoherent")


def _indexed_baseline_path(index: dict[str, Any], repo_root: Path) -> Path:
    """Resolve the one baseline path that the registry is allowed to consume."""
    benchmark = index.get("benchmark")
    require(type(benchmark) is dict, "benchmark metadata is missing")
    benchmark_path = _safe_relative_path(benchmark.get("path"))
    require(benchmark_path == "validator/validation-baseline.json", "benchmark path changed")
    fixtures_root = (repo_root / "contracts/fixtures").resolve()
    return _safe_child(fixtures_root, benchmark_path)


def _canonical_baseline_digest(document: dict[str, Any]) -> str:
    """Hash baseline evidence without recursing through this validator's digest."""
    normalized = dict(document)
    manifest: list[dict[str, Any]] = []
    self_size = 0
    for raw in document["artifact_manifest"]:
        record = dict(raw)
        if record.get("path") == BASELINE_SELF_MANIFEST_PATH:
            self_size = record["size_bytes"]
            record["sha256"] = "self-validator-sha256"
            record["size_bytes"] = 0
        manifest.append(record)
    normalized["artifact_manifest"] = manifest
    normalized["artifact_size_bytes"] = document["artifact_size_bytes"] - self_size
    encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_baseline(
    document: dict[str, Any],
    repo_root: Path,
    baseline_path: Path,
    *,
    canonical_baseline_path: Path | None = None,
) -> None:
    canonical = (canonical_baseline_path or (repo_root / "contracts/fixtures/validator/validation-baseline.json")).resolve()
    require(baseline_path.resolve() == canonical, "baseline path is not canonical")
    strict_keys(document, BASELINE_KEYS, "baseline")
    require(document["schema"] == BASELINE_SCHEMA, "baseline schema changed")
    require(document["fixture_schema"] == INDEX_SCHEMA, "baseline fixture schema changed")
    require(document["validator"] == "Python standard library only", "baseline validator changed")
    require(document["synthetic_only"] is True, "baseline synthetic flag changed")
    require(document["build_mode"] == "N/A - no production or release executable", "baseline build mode changed")
    require(document["threshold"] is None, "baseline threshold must remain null")
    environment = strict_keys(document["environment"], ("python", "implementation", "platform", "machine"), "baseline environment")
    for value in environment.values():
        require(type(value) is str and 0 < len(value) <= 128 and value.casefold() != "pending", "baseline environment is incomplete")
        _validate_text_value(value)
    require(type(document["artifact_manifest"]) is list and bool(document["artifact_manifest"]), "baseline artifact manifest is missing")
    listed: list[str] = []
    total = 0
    for index, raw in enumerate(document["artifact_manifest"]):
        path, digest, size = _validate_file_record(raw, index)
        require(path.startswith("contracts/fixtures/"), "baseline artifact escapes fixture root")
        require(path != baseline_path.resolve().relative_to(repo_root.resolve()).as_posix(), "baseline must not hash itself")
        require(path > (listed[-1] if listed else ""), "baseline artifact paths must be sorted and unique")
        listed.append(path)
        actual = _safe_child(repo_root.resolve(), path)
        data = _read_bounded_bytes(actual, MAX_ARTIFACT_BYTES)
        require(size == len(data) and digest == hashlib.sha256(data).hexdigest(), "baseline artifact manifest is stale")
        total += len(data)
    require(type(document["artifact_size_bytes"]) is int and type(document["artifact_size_bytes"]) is not bool and document["artifact_size_bytes"] == total, "baseline artifact size is stale")
    # The baseline manifest is the aggregate validator's source boundary. Keep
    # both central sources inside the immutable binding so a future edit cannot
    # silently become an unverified scanner hole. The separate aggregate test
    # source carries an independent canonical digest for validate.py; refreshing
    # this manifest and its self-referential baseline line cannot refresh that
    # reviewed source boundary locally.
    require(CENTRAL_VALIDATOR_SOURCE_PATHS.issubset(set(listed)), "central validator source is outside the baseline binding")
    validator_source = _read_bounded_bytes(
        _safe_child(repo_root.resolve(), BASELINE_SELF_MANIFEST_PATH),
        MAX_ARTIFACT_BYTES,
    )
    require(
        _canonical_validator_source_digest(validator_source) == _trusted_validator_source_digest(repo_root),
        "validator source trust anchor changed",
    )
    for mode in ("normal", "optimized"):
        measurement = strict_keys(document[mode], MEASUREMENT_KEYS, f"baseline.{mode}")
        expected_command = "python3 -O contracts/fixtures/validator/validate.py" if mode == "optimized" else "python3 contracts/fixtures/validator/validate.py"
        require(measurement["command"] == expected_command, "benchmark command changed")
        require(type(measurement["repetitions"]) is int and type(measurement["repetitions"]) is not bool and measurement["repetitions"] == BASELINE_REPETITIONS, "benchmark repetitions changed")
        _validate_distribution(measurement["samples_ms"], measurement["distribution_ms"])
    require(type(document["notes"]) is str and 0 < len(document["notes"]) <= 512, "baseline notes are missing")
    _validate_text_value(document["notes"])
    require(_canonical_baseline_digest(document) == BASELINE_CANONICAL_SHA256, "baseline canonical content changed")


def validate_schema_document(schema: dict[str, Any]) -> None:
    """Validate the language-neutral schema contract without I/O."""
    _validate_schema_document(schema)


def validate_index_document(index: dict[str, Any], repo_root: Path = REPO_ROOT) -> tuple[int, int]:
    """Validate the registry and every listed artifact under ``repo_root``."""
    return _validate_index_document(index, repo_root.resolve())


def validate_baseline_document(
    baseline: dict[str, Any],
    repo_root: Path = REPO_ROOT,
    baseline_path: Path = BASELINE_PATH,
) -> None:
    """Validate observed benchmark evidence without inventing a threshold."""
    root = repo_root.resolve()
    _validate_baseline(
        baseline,
        root,
        baseline_path.resolve(),
        canonical_baseline_path=(root / "contracts/fixtures/validator/validation-baseline.json"),
    )


def validate_all(
    index: dict[str, Any],
    schema: dict[str, Any],
    baseline: dict[str, Any],
    *,
    repo_root: Path = REPO_ROOT,
    baseline_path: Path = BASELINE_PATH,
) -> tuple[int, int]:
    _validate_schema_document(schema)
    root = repo_root.resolve()
    counts = _validate_index_document(index, root)
    canonical_baseline_path = _indexed_baseline_path(index, root)
    _validate_baseline(
        baseline,
        root,
        baseline_path.resolve(),
        canonical_baseline_path=canonical_baseline_path,
    )
    return counts


def format_failure(code: str) -> str:
    safe_code = code if code in {"fixture_validator_cli_invalid", "fixture_index_invalid"} else "fixture_index_invalid"
    payload = {
        "ok": False,
        "complete": False,
        "evidence_status": "blocked",
        "compatible": False,
        "live_claim": False,
        "error": {"code": safe_code, "message": SAFE_ERROR_MESSAGE},
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    require(len(encoded) <= MAX_ERROR_LENGTH, "failure marker is too long")
    return encoded


def emit_failure(code: str) -> None:
    print(format_failure(code))


class FailClosedArgumentParser(argparse.ArgumentParser):
    """Prevent argparse from echoing attacker-controlled arguments."""

    def error(self, _message: str) -> None:
        raise ArgumentParseError()


def main(argv: list[str] | None = None) -> int:
    parser = FailClosedArgumentParser(description=__doc__)
    parser.add_argument("--index", type=Path, default=INDEX_PATH)
    parser.add_argument("--schema", type=Path, default=SCHEMA_PATH)
    parser.add_argument("--baseline", type=Path, default=BASELINE_PATH)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    try:
        args = parser.parse_args(argv)
        repo_root = args.repo_root.resolve()
        index = load_json(args.index.resolve(), limit=MAX_JSON_BYTES)
        canonical_baseline_path = _indexed_baseline_path(index, repo_root)
        # A caller-selected copy must never replace the checked-in evidence named
        # by the registry, even when that copy is schema-valid and redacted.
        require(args.baseline.resolve() == canonical_baseline_path, "baseline path is not canonical")
        schema = load_json(args.schema.resolve(), limit=MAX_JSON_BYTES)
        baseline = load_json(canonical_baseline_path, limit=MAX_JSON_BYTES)
        require(type(index) is dict and type(schema) is dict and type(baseline) is dict, "registry documents must be objects")
        fixture_count, coverage_count = validate_all(
            index,
            schema,
            baseline,
            repo_root=repo_root,
            baseline_path=canonical_baseline_path,
        )
    except ArgumentParseError:
        emit_failure("fixture_validator_cli_invalid")
        return 2
    except Exception:
        # The CLI boundary is intentionally semantic-only. Never serialize an
        # exception, path, command line, key, or fixture value from external input.
        emit_failure("fixture_index_invalid")
        return 1
    print(json.dumps({
        "ok": True,
        "complete": index["evidence_status"] == "complete",
        "evidence_status": index["evidence_status"],
        "compatible": False,
        "live_claim": False,
        "fixture_count": fixture_count,
        "coverage_count": coverage_count,
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
