#!/usr/bin/env python3
"""Validate the synthetic DEP-02 external exposure allowlist.

This fixture is a local contract, not a reverse proxy and not a deployment
proof.  The evaluator never imports Hermes, opens a socket, resolves a host,
or contacts a provider.  It checks one frozen route matrix and evaluates
symbolic requests against an exact method/path/client/transport/auth boundary.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import platform
import re
import sys
from urllib.parse import unquote
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
CASES_PATH = ROOT / "cases.json"
BASELINE_PATH = ROOT / "validation-baseline.json"
SCHEMA = "hermternal.deployment-security.external-allowlist.v1"
BASELINE_SCHEMA = "hermternal.deployment-security.external-allowlist-baseline.v1"
OPERATION = "DEP-02"
CONTRACT = "dashboard-v0.0.1"
PINNED_HERMES_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
SOURCE_AUDIT_ID = "route-allowlist-c01-f5be9236"
SOURCE_CONTRACT_PATH = "contracts/fixtures/route-allowlist/route_allowlist.json"
PREFIX = "/hermes"
ARTIFACT_FILES = ("README.md", "cases.json", "validate.py")
# Evidence is pinned after the fixture is reviewed; a copied baseline cannot
# self-rebind its digest to a mutated README, manifest, or validator.
EXPECTED_ARTIFACT_BYTES = 126891
EXPECTED_ARTIFACT_SHA256 = "ea7df5493dc36471d43c63dbbad72fd3b7cb04327e019dd1ec47904d19b5536e"

MAX_JSON_BYTES = 512 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_INTEGER_DIGITS = 4300
MAX_JSON_NODES = 4096
MAX_OBJECT_KEYS = 96
MAX_ARRAY_LENGTH = 256
MAX_STRING_LENGTH = 4096
MAX_ERROR_OUTPUT = 240
MAX_BASELINE_TRACE = 30

ERROR_CODE = "external_allowlist_fixture_validation_error"
DUPLICATE_JSON_KEY_ERROR = "duplicate JSON object key"
NONFINITE_JSON_NUMBER_ERROR = "non-finite JSON number is not allowed"
INTEGER_DIGIT_LIMIT_ERROR = "JSON integer digit limit exceeded"
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
METHOD_RE = re.compile(r"^[A-Z][A-Z0-9-]{0,15}$")
HEADER_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
QUERY_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")
SESSION_ID_RE = re.compile(r"^(?:[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9._~-]{0,126}[A-Za-z0-9])$")

SENSITIVE_NORMALIZED_KEYS = frozenset(
    {
        "password",
        "token",
        "secret",
        "authorization",
        "bearer",
        "apikey",
        "accesskey",
        "clientsecret",
        "cookie",
        "cookievalue",
        "setcookie",
        "host",
        "hostname",
        "sessionid",
        "ticketid",
        "csrftoken",
        "pkceverifier",
        "privatekey",
    }
)
SENSITIVE_ASSIGNMENT_NAMES = (
    r"(?:password|token|secret|authorization|api[_\-. ]*key|"
    r"client[_\-. ]*secret|bearer|"
    r"cookie(?:[_\-. ]*(?:value|id))?|"
    r"set[_\-. ]*cookie|"
    r"host(?:[_\-. ]*name)?|"
    r"ticket(?:[_\-. ]*id)?|"
    r"csrf(?:[_\-. ]*token)?|"
    r"session(?:[_\-. ]*(?:cookie|token|value|id))?|"
    r"state(?:[_\-. ]*(?:token|value|id))?|"
    r"(?:access|refresh|id)[_\-. ]*token|"
    r"pkce(?:[_\-. ]*(?:token|verifier|challenge))?)"
)
SENSITIVE_ASSIGNMENT_RE = re.compile(
    rf"(?<![A-Za-z0-9])(?P<key>(?P<quote>[\"']?)(?P<name>{SENSITIVE_ASSIGNMENT_NAMES})"
    rf"(?P=quote)\s*[:=]\s*)"
    rf"(?P<value>(?:(?:Bearer|Basic)\s+)?(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,}}\]]+))",
    re.IGNORECASE,
)

# Retained-output redaction is deliberately bounded and local.  It never
# resolves or reads anything; the Base64 branch decodes only short candidates,
# re-encodes them to enforce canonical pad bits, and rejects material that could
# put a URL, credential, path, filename, host, or encoded payload into
# diagnostics.  The structural fields below are independently frozen by the
# contract validator, so their route syntax and evidence hashes are not
# mistaken for user data.
REDACTION_STRUCTURAL_FIELDS = frozenset(
    {
        "schema",
        "pinned_source_sha",
        "source_contract_path",
        "validator",
        "fixture",
        "command",
        "prefix",
        "platform",
        "files",
        "sha256",
    }
)
REDACTION_STRUCTURAL_EXEMPT_PATTERNS = frozenset(
    {
        "base64",
        "absolute_path",
        "windows_path",
        "relative_path",
        "filename",
        "hostname",
        "email",
        "ip_address",
    }
)
_BASE64_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9+/_%=-])"
    r"[A-Za-z0-9+/_=-]{2,}"
    r"(?![A-Za-z0-9+/_=-])"
)
RETAINED_VALUE_PATTERNS = (
    ("url", re.compile(r"\b(?:https?|wss?|ftp)://[^\s<>\"']+", re.IGNORECASE)),
    ("data_url", re.compile(r"(?<![A-Za-z0-9])data:[^\s<>\"']+", re.IGNORECASE)),
    ("basic_auth", re.compile(r"\bBasic\s+[A-Za-z0-9+/=_-]+", re.IGNORECASE)),
    ("cookie_header", re.compile(r"\b(?:Cookie|Set-Cookie)\s*:\s*[^\r\n]+", re.IGNORECASE)),
    ("secret", re.compile(r"\b(?:ghp|github_pat|sk_live|AKIA)[A-Za-z0-9_-]+\b", re.IGNORECASE)),
    ("bearer", re.compile(r"\bBearer\s+[^\s,}\]]+", re.IGNORECASE)),
    ("private_key", re.compile(r"-----BEGIN [A-Z0-9 ]+ PRIVATE KEY-----", re.IGNORECASE)),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    (
        "base64",
        # Candidate discovery is intentionally permissive; the bounded
        # canonical decoder below decides whether a run is plausible retained
        # payload.  Keeping padding in a separate terminal group lets the
        # decoder reject internal, excessive, or noncanonical padding rather
        # than silently accepting a regex-shaped example.
        _BASE64_CANDIDATE_RE,
    ),
    (
        "absolute_path",
        re.compile(r"(?<![A-Za-z0-9])/(?:[^\s<>\"'/]+(?:/[^\s<>\"']+)*)"),
    ),
    (
        "windows_path",
        re.compile(r"(?<![A-Za-z0-9])(?:[A-Za-z]:[\\/]|\\\\)[^\s<>\"']+"),
    ),
    (
        "relative_path",
        re.compile(
            r"(?<![A-Za-z0-9])(?:\.{0,2}[\\/])?"
            r"(?:[A-Za-z0-9._-]+[\\/])+[A-Za-z0-9._-]+"
            r"(?:\.[A-Za-z0-9_-]{1,16})?(?![A-Za-z0-9])"
        ),
    ),
    (
        "filename",
        re.compile(r"(?<![A-Za-z0-9])(?:[A-Za-z0-9_-]+\.)+[A-Za-z][A-Za-z0-9_-]{0,15}(?![A-Za-z0-9])"),
    ),
    (
        "hostname",
        re.compile(
            r"(?<![A-Za-z0-9._-])"
            r"(?:localhost|(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
            r"[A-Za-z]{2,63})"
            r"(?::[0-9]{1,5})?"
            r"(?![A-Za-z0-9._/-])",
            re.IGNORECASE,
        ),
    ),
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b", re.IGNORECASE),
    ),
    (
        "ip_address",
        re.compile(
            r"(?<![A-Za-z0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?"
            r"(?![A-Za-z0-9._/-])"
        ),
    ),
)
# Keep the old name available for callers while routing every check through
# the expanded retained-output policy.
SECRET_VALUE_PATTERNS = tuple(pattern for _, pattern in RETAINED_VALUE_PATTERNS)
README_REDACTION_PATTERN_NAMES = frozenset(
    {
        "url",
        "data_url",
        "basic_auth",
        "cookie_header",
        "secret",
        "bearer",
        "private_key",
        "jwt",
    }
)

BASELINE_COMMANDS = {
    "normal": "python3 contracts/fixtures/deployment-security/external-allowlist/validate.py",
    "optimized": "python3 -O contracts/fixtures/deployment-security/external-allowlist/validate.py",
}
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
    """Raised when the closed external allowlist contract is violated."""


def _base64_candidate_state(token: str) -> str | None:
    """Return the canonicality state of one bounded Base64 candidate.

    The standard-library decoder accepts nonzero unused pad bits, so decoding
    alone is not sufficient.  Re-encoding the bounded byte result enforces the
    canonical spelling for both alphabets and for padded versus unpadded input.
    """

    if len(token) > MAX_STRING_LENGTH:
        # Validation rejects oversized strings before this path; compact_error
        # still redacts an oversized payload-shaped run without decoding it.
        return "noncanonical"
    core = token.rstrip("=")
    padding = token[len(core) :]
    if len(core) < 2:
        return None
    if "=" in core:
        # An equals sign followed by more Base64 alphabet is malformed
        # internal/nonterminal padding.  Keep the complete run in scope so a
        # valid-looking suffix cannot be approved independently.
        return "noncanonical"
    if len(core) % 4 == 1:
        return None
    url_safe = "-" in core or "_" in core
    if url_safe and any(character in "+/" for character in core):
        return None
    required_padding = (-len(core)) % 4
    if len(padding) > 2:
        return "noncanonical"
    if padding and len(padding) != required_padding:
        return "noncanonical"

    padded = core + "=" * required_padding
    try:
        decoded = base64.b64decode(
            padded,
            altchars=b"-_" if url_safe else None,
            validate=True,
        )
    except (binascii.Error, ValueError):
        return None
    canonical = base64.b64encode(
        decoded,
        altchars=b"-_" if url_safe else None,
    ).decode("ascii")
    expected = canonical if padding else canonical.rstrip("=")
    return "canonical" if token == expected else "noncanonical"


def _malformed_base64_padding_is_plausible(
    value: str,
    match: re.Match[str],
    token: str,
    *,
    candidate_start: int | None = None,
) -> bool:
    """Recognize one complete run with internal or nonterminal padding."""

    core = token.rstrip("=")
    equals_index = core.find("=")
    if equals_index < 2:
        return False
    prefix = core[:equals_index]
    suffix = core[equals_index:].replace("=", "")
    if not suffix or len(prefix) % 4 == 1:
        return False
    url_safe = "-" in prefix or "_" in prefix or "-" in suffix or "_" in suffix
    if url_safe and any(character in "+/" for character in prefix + suffix):
        return False
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" if url_safe else "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    if any(character not in alphabet for character in prefix + suffix):
        return False
    if _base64_candidate_state(prefix) is None:
        return False

    start = match.start() if candidate_start is None else candidate_start
    preceding = value[start - 1] if start else ""
    assignment_context = bool(preceding) and preceding in "=:+,;"
    whole_token = token == value.strip()
    combined = prefix + suffix
    upper_count = sum(character.isupper() for character in combined)
    lower_count = sum(character.islower() for character in combined)
    payload_signal = any(character.isdigit() or character in "+/" for character in combined)
    return payload_signal or upper_count >= 2 or (
        (assignment_context or whole_token) and upper_count >= 1 and lower_count >= 1
    )


def _base64_candidate_is_plausible(
    value: str,
    match: re.Match[str],
    token: str,
    state: str,
    *,
    candidate_start: int | None = None,
    is_key: bool = False,
) -> bool:
    """Keep canonical detection bounded without classifying contract prose.

    Padded runs are unambiguous.  For unpadded runs, punctuation, digits, and
    a strong mixed-case signal identify payload-shaped material; ordinary words
    such as ``Provider`` and ``contract`` do not.  URL-safe detection requires
    an edge/repeated marker or an assignment-like context, which avoids treating
    method-override aliases and hyphenated route IDs as payloads.
    """

    if state not in {"canonical", "noncanonical"}:
        return False
    core = token.rstrip("=")
    if "=" in core:
        return _malformed_base64_padding_is_plausible(
            value,
            match,
            token,
            candidate_start=candidate_start,
        )
    padding = token[len(core) :]
    if len(core) < 2:
        return False
    start = match.start() if candidate_start is None else candidate_start
    preceding = value[start - 1] if start else ""
    assignment_context = bool(preceding) and preceding in "=:+,;"
    whole_token = token == value.strip()
    if padding:
        return True

    upper_count = sum(character.isupper() for character in core)
    lower_count = sum(character.islower() for character in core)
    digit_or_standard_symbol = any(character.isdigit() or character in "+/" for character in core)
    url_marker_count = sum(character in "-_" for character in core)
    if "-" in core or "_" in core:
        if (
            len(core) < 6
            and not assignment_context
            and not whole_token
            and not core.startswith(("-", "_"))
            and not core.endswith(("-", "_"))
        ):
            return False
        if is_key:
            return (
                ("_" in core and upper_count >= 2)
                or (core.startswith("-") and (url_marker_count >= 3 or whole_token))
            )
        return (
            ("_" in core and (upper_count >= 2 or digit_or_standard_symbol))
            or core.startswith(("-", "_"))
            or core.endswith(("-", "_"))
            or (assignment_context and url_marker_count >= 2 and (upper_count >= 2 or digit_or_standard_symbol))
        )

    if len(core) < 6 and not assignment_context and not whole_token:
        return False
    return (
        digit_or_standard_symbol
        or (upper_count >= 2 and lower_count >= 1)
        or upper_count >= 8
        or (len(core) < 6 and (assignment_context or whole_token) and upper_count >= 1 and lower_count >= 1)
    )


def _base64_prefix_has_payload_signal(prefix: str) -> bool:
    """Distinguish an assignment label from a Base64 payload prefix."""

    upper_count = sum(character.isupper() for character in prefix)
    lower_count = sum(character.islower() for character in prefix)
    return (
        any(character.isdigit() or character in "+/_-" for character in prefix)
        or upper_count >= 2
        or (upper_count >= 1 and lower_count >= 1 and len(prefix) < 6)
    )


def _base64_candidate_spans(
    value: str,
    *,
    field_name: str | None = None,
    is_key: bool = False,
) -> list[tuple[int, int]]:
    """Find plausible canonical or noncanonical Base64 runs in bounded text."""

    if _pattern_is_exempt("base64", field_name, value):
        return []
    spans: list[tuple[int, int]] = []
    for match in _BASE64_CANDIDATE_RE.finditer(value):
        candidate_start = match.start()
        token = match.group(0)
        if "=" in token:
            separator = token.find("=")
            prefix = token[:separator]
            if not _base64_prefix_has_payload_signal(prefix):
                candidate_start = match.start() + separator + 1
                token = value[candidate_start : match.end()]
        state = _base64_candidate_state(token)
        if state is not None and _base64_candidate_is_plausible(
            value,
            match,
            token,
            state,
            candidate_start=candidate_start,
            is_key=is_key,
        ):
            spans.append((candidate_start, match.end()))
    return spans


def _redact_base64_candidates(value: str) -> str:
    """Replace payload-shaped Base64 runs without decoding unbounded input."""

    for start, end in reversed(_base64_candidate_spans(value)):
        value = f"{value[:start]}[REDACTED]{value[end:]}"
    return value


def compact_error(message: object) -> str:
    """Return one bounded semantic diagnostic without retained user material."""

    redacted = str(message)
    for pattern_name, pattern in RETAINED_VALUE_PATTERNS:
        if pattern_name != "base64":
            redacted = pattern.sub("[REDACTED]", redacted)
    redacted = _redact_base64_candidates(redacted)

    def redact_assignment(match: re.Match[str]) -> str:
        del match
        return "[REDACTED]"

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
    del value
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
    """Apply recursive node, size, scalar, and finite-number limits."""

    if depth > MAX_JSON_DEPTH:
        raise FixtureJSONError(f"{label}: JSON depth exceeds the bounded limit")
    if type(value) is dict:
        if len(value) > MAX_OBJECT_KEYS:
            raise FixtureJSONError(f"{label}: object has too many keys")
        nodes = 1
        for key, child in value.items():
            if type(key) is not str:
                raise FixtureJSONError(f"{label}: object keys must be text")
            if len(key) > MAX_STRING_LENGTH:
                raise FixtureJSONError(f"{label}: object key is too long")
            nodes += validate_json_tree(child, f"{label}.<field>", depth + 1)
            if nodes > MAX_JSON_NODES:
                raise FixtureJSONError(f"{label}: JSON node count exceeds the bounded limit")
        return nodes
    if type(value) is list:
        if len(value) > MAX_ARRAY_LENGTH:
            raise FixtureJSONError(f"{label}: array is too long")
        nodes = 1
        for index, child in enumerate(value):
            nodes += validate_json_tree(child, f"{label}[]", depth + 1)
            if nodes > MAX_JSON_NODES:
                raise FixtureJSONError(f"{label}: JSON node count exceeds the bounded limit")
        return nodes
    if type(value) is str:
        if len(value) > MAX_STRING_LENGTH:
            raise FixtureJSONError(f"{label}: string is too long")
        if CONTROL_RE.search(value) is not None:
            raise FixtureJSONError(f"{label}: control character is not allowed")
        return 1
    if type(value) is float:
        if not math.isfinite(value):
            raise FixtureJSONError(f"{label}: non-finite JSON number is not allowed")
        return 1
    if value is not None and type(value) not in {bool, int}:
        raise FixtureJSONError(f"{label}: unsupported JSON value type")
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


def _normalize_sensitive_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", key.casefold())


def _is_independently_validated_path(value: str) -> bool:
    """Allow only route paths frozen by the route matrix or its session template."""

    if value in FROZEN_ROUTE_PATH_VALUES or value in FROZEN_CASE_PATH_VALUES:
        return True
    return any(
        "{session_id}" in route["path"] and _path_template_matches(route["path"], value)
        for route in EXPECTED_EXTERNAL_ROUTES
    )


def _pattern_is_exempt(
    pattern_name: str,
    field_name: str | None,
    value: str | None = None,
) -> bool:
    if field_name == "path":
        return (
            value is not None
            and _is_independently_validated_path(value)
            and pattern_name in REDACTION_STRUCTURAL_EXEMPT_PATTERNS
        )
    return (
        field_name in REDACTION_STRUCTURAL_FIELDS
        and pattern_name in REDACTION_STRUCTURAL_EXEMPT_PATTERNS
    )


def _check_retained_text(
    value: str,
    path: str,
    field_name: str | None = None,
    *,
    is_key: bool = False,
) -> None:
    for pattern_name, pattern in RETAINED_VALUE_PATTERNS:
        if pattern_name == "base64":
            continue
        if _pattern_is_exempt(pattern_name, field_name, value):
            continue
        require(pattern.search(value) is None, f"retained sensitive value at {path}")
    require(
        not _base64_candidate_spans(value, field_name=field_name, is_key=is_key),
        f"retained sensitive value at {path}",
    )
    require(SENSITIVE_ASSIGNMENT_RE.search(value) is None, f"retained sensitive value at {path}")


def _walk_redaction(value: Any, path: str = "$", *, field_name: str | None = None) -> None:
    """Walk untrusted retained data using fixed paths, never raw object keys."""

    if type(value) is dict:
        for key, child in value.items():
            _check_retained_text(key, f"{path}.<field-name>", field_name=key, is_key=True)
            normalized = _normalize_sensitive_key(key)
            require(normalized not in SENSITIVE_NORMALIZED_KEYS, f"sensitive fixture field at {path}.<field>")
            _walk_redaction(child, f"{path}.<field>", field_name=key)
        return
    if type(value) is list:
        for child in value:
            _walk_redaction(child, f"{path}[]", field_name=field_name)
        return
    if type(value) is str:
        _check_retained_text(value, path, field_name)


def validate_redaction(value: Any) -> None:
    """Reject raw credentials, URLs, encoded payloads, paths, hosts, and filenames."""

    _walk_redaction(value)


def validate_readme_redaction(root: Path = ROOT) -> None:
    """Apply the retained credential and live-endpoint rule to the README."""

    try:
        text = (root / "README.md").read_text(encoding="utf-8")
    except OSError as exc:
        raise ValidationError("README.md is unavailable") from exc
    require(len(text) <= MAX_JSON_BYTES, "README.md exceeds the bounded input limit")
    for pattern_name, pattern in RETAINED_VALUE_PATTERNS:
        if pattern_name in README_REDACTION_PATTERN_NAMES:
            require(pattern.search(text) is None, "README.md contains retained sensitive text")
    require(SENSITIVE_ASSIGNMENT_RE.search(text) is None, "README.md contains credential-shaped text")


def _strict_keys(value: Any, expected: tuple[str, ...], label: str) -> dict[str, Any]:
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


def _enum(value: Any, allowed: frozenset[str], label: str) -> str:
    result = _text(value, label)
    require(result in allowed, f"{label} has an unsupported value")
    return result


def _string_list(value: Any, allowed: frozenset[str], label: str) -> tuple[str, ...]:
    require(type(value) is list, f"{label} must be an array")
    require(0 < len(value) <= 8, f"{label} has an invalid length")
    result: list[str] = []
    for index, item in enumerate(value):
        item_text = _text(item, f"{label}[{index}]", max_length=64)
        require(item_text in allowed, f"{label}[{index}] has an unsupported value")
        require(item_text not in result, f"{label}[{index}] is duplicated")
        result.append(item_text)
    return tuple(result)


KNOWN_CLIENTS = frozenset({"browser", "native"})
KNOWN_TRANSPORTS = frozenset({"http", "websocket"})
KNOWN_AUTH_MODES = frozenset(
    {
        "public",
        "browser_cookie",
        "native_cookie",
        "native_bearer",
        "public_native_authorize",
        "public_native_loopback_code_pkce",
        "public_native_refresh_material",
        "fresh_single_use_ticket",
        "source_defined_query_token",
    }
)
C01_SOURCE_AUTH_MODES = frozenset(
    {
        "public",
        "browser_cookie_or_native_cookie",
        "browser_cookie_or_native_bearer",
        "public_native_authorize",
        "public_native_loopback_code_pkce",
        "public_native_refresh_material",
        "gated_ticket_or_non_gated_local_query_token",
    }
)
KNOWN_SURFACES = frozenset({"static_shell", "spa_deep_link", "dashboard_rest", "chat_websocket", "pty_websocket"})
KNOWN_METHODS = frozenset({"GET", "HEAD", "POST", "PATCH"})
KNOWN_REASONS = frozenset(
    {
        "static_route_allowed",
        "dashboard_route_allowed",
        "websocket_route_allowed",
        "default_deny",
        "method_not_allowlisted",
        "client_not_allowlisted",
        "transport_not_allowlisted",
        "auth_not_allowlisted",
        "method_override_denied",
        "path_prefix_required",
        "duplicate_prefix_denied",
        "encoded_path_denied",
        "path_traversal_denied",
        "path_shape_denied",
        "management_route_denied",
        "wildcard_denied",
    }
)


def _route(
    route_id: str,
    method: str,
    path: str,
    surface: str,
    transport: str,
    clients: tuple[str, ...],
    source_auth_mode: str,
    auth_bindings: tuple[tuple[str, tuple[str, ...]], ...],
    host_requirement: str,
    source_citation_id: str,
) -> dict[str, Any]:
    return {
        "id": route_id,
        "method": method,
        "path": path,
        "surface": surface,
        "transport": transport,
        "clients": list(clients),
        "source_auth_mode": source_auth_mode,
        "auth_bindings": {client: list(markers) for client, markers in auth_bindings},
        "host_requirement": host_requirement,
        "source_citation_id": source_citation_id,
    }


# These tuples are intentionally duplicated from the reviewed C-01 pairs.  A
# manifest edit cannot authorize a new route without changing this validator
# and its tests, which keeps DEP-02 default-deny and reviewable.
EXPECTED_STATIC_ROUTES = (
    _route("static-root-get", "GET", "/", "static_shell", "http", ("browser",), "public", (("browser", ("public",)),), "none", "static-spa-shell"),
    _route("static-root-head", "HEAD", "/", "static_shell", "http", ("browser",), "public", (("browser", ("public",)),), "none", "static-spa-shell"),
    _route("static-app", "GET", "/app", "spa_deep_link", "http", ("browser",), "public", (("browser", ("public",)),), "none", "static-spa-shell"),
    _route("static-app-chat", "GET", "/app/chat", "spa_deep_link", "http", ("browser",), "public", (("browser", ("public",)),), "none", "static-spa-shell"),
    _route("static-settings", "GET", "/settings", "spa_deep_link", "http", ("browser",), "public", (("browser", ("public",)),), "none", "static-spa-shell"),
    _route("static-signed-out", "GET", "/signed-out", "spa_deep_link", "http", ("browser",), "public", (("browser", ("public",)),), "none", "static-spa-shell"),
)
EXPECTED_EXTERNAL_ROUTES = (
    _route("hermes-login-get", "GET", "/hermes/login", "dashboard_rest", "http", ("browser",), "public", (("browser", ("public",)),), "none", "rest-auth-routes"),
    _route("hermes-auth-providers-get", "GET", "/hermes/api/auth/providers", "dashboard_rest", "http", ("browser", "native"), "public", (("browser", ("public",)), ("native", ("public",))), "none", "rest-auth-routes"),
    _route("hermes-auth-login-get", "GET", "/hermes/auth/login", "dashboard_rest", "http", ("browser",), "public", (("browser", ("public",)),), "none", "rest-auth-routes"),
    _route("hermes-auth-callback-get", "GET", "/hermes/auth/callback", "dashboard_rest", "http", ("browser",), "public", (("browser", ("public",)),), "none", "rest-auth-routes"),
    _route("hermes-auth-password-login-post", "POST", "/hermes/auth/password-login", "dashboard_rest", "http", ("browser", "native"), "public", (("browser", ("public",)), ("native", ("public",))), "none", "rest-auth-routes"),
    _route("hermes-auth-logout-post", "POST", "/hermes/auth/logout", "dashboard_rest", "http", ("browser", "native"), "browser_cookie_or_native_cookie", (("browser", ("browser_cookie",)), ("native", ("native_cookie",))), "none", "rest-auth-routes"),
    _route("hermes-auth-me-get", "GET", "/hermes/api/auth/me", "dashboard_rest", "http", ("browser", "native"), "browser_cookie_or_native_bearer", (("browser", ("browser_cookie",)), ("native", ("native_bearer",))), "none", "rest-auth-routes"),
    _route("hermes-auth-ws-ticket-post", "POST", "/hermes/api/auth/ws-ticket", "dashboard_rest", "http", ("browser", "native"), "browser_cookie_or_native_bearer", (("browser", ("browser_cookie",)), ("native", ("native_bearer",))), "none", "rest-auth-routes"),
    _route("hermes-auth-native-authorize-get", "GET", "/hermes/auth/native/authorize", "dashboard_rest", "http", ("native",), "public_native_authorize", (("native", ("public_native_authorize",)),), "none", "rest-auth-routes"),
    _route("hermes-auth-native-token-post", "POST", "/hermes/auth/native/token", "dashboard_rest", "http", ("native",), "public_native_loopback_code_pkce", (("native", ("public_native_loopback_code_pkce",)),), "none", "rest-auth-routes"),
    _route("hermes-auth-native-refresh-post", "POST", "/hermes/auth/native/refresh", "dashboard_rest", "http", ("native",), "public_native_refresh_material", (("native", ("public_native_refresh_material",)),), "none", "rest-auth-routes"),
    _route("hermes-sessions-get", "GET", "/hermes/api/sessions", "dashboard_rest", "http", ("browser", "native"), "browser_cookie_or_native_bearer", (("browser", ("browser_cookie",)), ("native", ("native_bearer",))), "none", "rest-session-routes"),
    _route("hermes-sessions-search-get", "GET", "/hermes/api/sessions/search", "dashboard_rest", "http", ("browser", "native"), "browser_cookie_or_native_bearer", (("browser", ("browser_cookie",)), ("native", ("native_bearer",))), "none", "rest-session-routes"),
    _route("hermes-session-get", "GET", "/hermes/api/sessions/{session_id}", "dashboard_rest", "http", ("browser", "native"), "browser_cookie_or_native_bearer", (("browser", ("browser_cookie",)), ("native", ("native_bearer",))), "none", "rest-session-routes"),
    _route("hermes-session-messages-get", "GET", "/hermes/api/sessions/{session_id}/messages", "dashboard_rest", "http", ("browser", "native"), "browser_cookie_or_native_bearer", (("browser", ("browser_cookie",)), ("native", ("native_bearer",))), "none", "rest-session-routes"),
    _route("hermes-session-patch", "PATCH", "/hermes/api/sessions/{session_id}", "dashboard_rest", "http", ("browser", "native"), "browser_cookie_or_native_bearer", (("browser", ("browser_cookie",)), ("native", ("native_bearer",))), "none", "rest-session-routes"),
    _route("hermes-image-upload-post", "POST", "/hermes/api/chat/image-upload", "dashboard_rest", "http", ("browser", "native"), "browser_cookie_or_native_bearer", (("browser", ("browser_cookie",)), ("native", ("native_bearer",))), "none", "rest-image-upload"),
    _route("hermes-chat-ws", "GET", "/hermes/api/ws", "chat_websocket", "websocket", ("browser", "native"), "gated_ticket_or_non_gated_local_query_token", (("browser", ("fresh_single_use_ticket", "source_defined_query_token")), ("native", ("fresh_single_use_ticket", "source_defined_query_token"))), "none", "chat-websocket"),
    _route("hermes-pty-ws", "GET", "/hermes/api/pty", "pty_websocket", "websocket", ("browser",), "gated_ticket_or_non_gated_local_query_token", (("browser", ("fresh_single_use_ticket", "source_defined_query_token")),), "attested_posix_or_wsl", "pty-websocket"),
)
ALL_ROUTES = EXPECTED_STATIC_ROUTES + EXPECTED_EXTERNAL_ROUTES
ROUTE_BY_ID = {route["id"]: route for route in ALL_ROUTES}
FROZEN_ROUTE_PATH_VALUES = frozenset(route["path"] for route in ALL_ROUTES)
EXPECTED_CASE_IDS = (
    "static-root-get",
    "static-root-head",
    "static-app",
    "static-app-chat",
    "static-settings",
    "static-signed-out",
    "external-login",
    "external-provider-discovery",
    "external-auth-login",
    "external-auth-callback",
    "external-password-login",
    "external-logout",
    "external-auth-me",
    "external-ws-ticket",
    "external-native-authorize",
    "external-native-token",
    "external-native-refresh",
    "external-sessions",
    "external-session-search",
    "external-session-get",
    "external-session-messages",
    "external-session-patch",
    "external-image-upload",
    "external-chat-websocket",
    "external-pty-websocket",
    "deny-unprefixed-chat-websocket",
    "deny-unprefixed-api-route",
    "deny-broad-hermes-wildcard",
    "deny-unknown-hermes-route",
    "deny-login-method-mutation",
    "deny-image-upload-method-mutation",
    "deny-trailing-slash",
    "deny-duplicate-prefix",
    "deny-encoded-slash",
    "deny-encoded-dot",
    "deny-encoded-prefix",
    "deny-traversal",
    "deny-pty-native-client",
    "deny-login-native-client",
    "deny-chat-wrong-transport",
    "deny-session-without-auth",
    "deny-method-override-header",
    "deny-method-override-header-alias",
    "deny-method-override-query",
    "deny-admin-config-defaults",
    "deny-admin-dashboard-plugins",
    "deny-admin-gateway-restart",
    "deny-admin-files",
    "deny-admin-ssh",
    "deny-admin-model-options",
    "deny-admin-pub",
    "deny-admin-events",
    "deny-admin-console",
    "deny-admin-cron",
    "deny-source-health",
    "deny-broad-api-wildcard",
    "deny-session-extra-segment",
    "deny-session-invalid-character",
    "deny-session-too-long",
    "deny-chat-wrong-method",
    "deny-native-token-browser",
    "external-logout-native-cookie",
    "deny-logout-native-bearer",
    "deny-auth-me-native-cookie",
    "deny-session-browser-native-bearer",
    "deny-session-native-browser-cookie",
    "deny-method-override-query-x-http-method",
    "deny-method-override-query-x-http-method-case",
    "deny-method-override-query-x-http-method-underscore",
    "deny-method-override-query-x-http-method-encoded",
    "deny-method-override-query-x-http-method-double-encoded",
)

# These request-path literals are the reviewed fixture probes.  Redaction may
# exempt only this frozen value set (or a route template validated below); a
# temporary manifest path such as /tmp is never structural by field name alone.
FROZEN_CASE_PATH_VALUES = frozenset(
    {
        "/",
        "/app",
        "/app/chat",
        "/app/",
        "/app/other",
        "/settings",
        "/signed-out",
        "/dashboard",
        "/app?route=chat",
        "/hermes/login",
        "/hermes/api/auth/providers",
        "/hermes/auth/login",
        "/hermes/auth/callback",
        "/hermes/auth/password-login",
        "/hermes/auth/logout",
        "/hermes/api/auth/me",
        "/hermes/api/auth/ws-ticket",
        "/hermes/auth/native/authorize",
        "/hermes/auth/native/token",
        "/hermes/auth/native/refresh",
        "/hermes/api/sessions",
        "/hermes/api/sessions/search",
        "/hermes/api/sessions/a7.session~2",
        "/hermes/api/sessions/a7.session~2/messages",
        "/hermes/api/sessions/s7",
        "/hermes/api/sessions/",
        "/hermes/api/sessions/.",
        "/hermes/api/sessions/..",
        "/hermes/api/sessions/a/b",
        "/hermes/api/sessions/_a",
        "/hermes/api/sessions/a_",
        "/hermes/api/chat/image-upload",
        "/hermes/api/ws",
        "/hermes/api/pty",
        "/api/ws",
        "/api/sessions",
        "/hermes/*",
        "/hermes/api/unknown",
        "/hermes/api/ws/",
        "/hermes/hermes/api/ws",
        "/hermes/api/sessions/a%2Fb",
        "/hermes/api/sessions/%2e%2e/auth/me",
        "/%68ermes/api/ws",
        "/hermes/api/sessions/../auth/me",
        "/hermes/api/config/defaults",
        "/hermes/api/dashboard/plugins",
        "/hermes/api/gateway/restart",
        "/hermes/api/files",
        "/hermes/api/ssh/ownership",
        "/hermes/api/model/options",
        "/hermes/api/pub",
        "/hermes/api/events",
        "/hermes/api/console",
        "/hermes/api/cron/fire",
        "/hermes/api/health",
        "/hermes/api/*",
        "/hermes/api/sessions/a7/extra",
        "/hermes/api/sessions/a$b",
        "/hermes/api/sessions/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    }
)

UNPREFIXED_PATHS = frozenset(
    route["path"].removeprefix(PREFIX) for route in EXPECTED_EXTERNAL_ROUTES
)
BLOCKED_MANAGEMENT_PATHS = frozenset(
    {
        "/hermes/api/health",
        "/hermes/api/status",
        "/hermes/api/config/defaults",
        "/hermes/api/config/schema",
        "/hermes/api/model/info",
        "/hermes/api/model/options",
        "/hermes/api/dashboard/themes",
        "/hermes/api/dashboard/plugins",
        "/hermes/api/cron/fire",
        "/hermes/api/gateway/restart",
        "/hermes/api/files",
        "/hermes/api/ssh/ownership",
        "/hermes/api/pub",
        "/hermes/api/events",
        "/hermes/api/console",
        "/hermes/api/mcp/oauth/callback/",
    }
)
BLOCKED_MANAGEMENT_PREFIXES = (
    "/hermes/api/config/",
    "/hermes/api/dashboard/",
    "/hermes/api/gateway/",
    "/hermes/api/cron/",
    "/hermes/api/mcp/",
    "/hermes/api/ssh/",
)

CASES_ROOT_KEYS = (
    "schema",
    "operation",
    "contract",
    "pinned_source_sha",
    "source_audit_id",
    "source_contract_path",
    "synthetic_only",
    "network_access",
    "proxy_neutral",
    "prefix",
    "policy",
    "redaction",
    "static_routes",
    "external_routes",
    "cases",
)
POLICY_KEYS = (
    "default_decision",
    "path_matching",
    "encoded_paths",
    "method_override",
    "broad_wildcards",
    "spa_fallback",
)
REDACTION_KEYS = (
    "synthetic_only",
    "contains_credentials",
    "contains_hosts",
    "contains_live_data",
    "contains_raw_cookies",
    "contains_tokens",
    "contains_transcripts",
    "contains_user_data",
)
ROUTE_KEYS = (
    "id",
    "method",
    "path",
    "surface",
    "transport",
    "clients",
    "source_auth_mode",
    "auth_bindings",
    "host_requirement",
    "source_citation_id",
)
CASE_KEYS = ("id", "description", "request", "expected")
REQUEST_KEYS = ("method", "path", "client", "transport", "auth", "headers", "query")
EXPECTED_KEYS = ("decision", "reason", "route_id", "surface")
SOURCE_CITATIONS = frozenset(
    {
        "static-spa-shell",
        "rest-auth-routes",
        "rest-session-routes",
        "rest-image-upload",
        "chat-websocket",
        "pty-websocket",
    }
)


def _validate_route(route: Any, expected: dict[str, Any], label: str) -> None:
    row = _strict_keys(route, ROUTE_KEYS, label)
    _text(row["id"], f"{label}.id", max_length=64)
    _enum(row["method"], KNOWN_METHODS, f"{label}.method")
    path = _text(row["path"], f"{label}.path", max_length=256)
    _enum(row["surface"], KNOWN_SURFACES, f"{label}.surface")
    _enum(row["transport"], KNOWN_TRANSPORTS, f"{label}.transport")
    clients = _string_list(row["clients"], KNOWN_CLIENTS, f"{label}.clients")
    _enum(row["source_auth_mode"], C01_SOURCE_AUTH_MODES, f"{label}.source_auth_mode")
    bindings = _strict_keys(row["auth_bindings"], clients, f"{label}.auth_bindings")
    for client in clients:
        _string_list(bindings[client], KNOWN_AUTH_MODES, f"{label}.auth_bindings.{client}")
    _enum(row["host_requirement"], frozenset({"none", "attested_posix_or_wsl"}), f"{label}.host_requirement")
    _enum(row["source_citation_id"], SOURCE_CITATIONS, f"{label}.source_citation_id")
    require("*" not in path, f"{label}.path cannot be a wildcard")
    require("?" not in path and "%" not in path, f"{label}.path cannot contain query or encoding")
    require("//" not in path, f"{label}.path cannot contain duplicate separators")
    if path != "/":
        require(not path.endswith("/"), f"{label}.path cannot have a trailing slash")
    require(row == expected, f"{label} differs from the frozen route matrix")


def _validate_route_list(value: Any, expected: tuple[dict[str, Any], ...], label: str) -> None:
    require(type(value) is list, f"{label} must be an array")
    require(len(value) == len(expected), f"{label} count changed")
    seen: set[tuple[str, str]] = set()
    for index, (route, expected_route) in enumerate(zip(value, expected)):
        _validate_route(route, expected_route, f"{label}[{index}]")
        pair = (route["method"], route["path"])
        require(pair not in seen, f"{label}[{index}] duplicates a method/path pair")
        seen.add(pair)


def _validate_headers(value: Any, label: str) -> dict[str, str]:
    require(type(value) is dict, f"{label} must be an object")
    require(len(value) <= 16, f"{label} has too many entries")
    result: dict[str, str] = {}
    for key, child in value.items():
        _text(key, f"{label} key", max_length=64)
        require(HEADER_KEY_RE.fullmatch(key) is not None, f"{label} key is malformed")
        result[key] = _text(child, f"{label}.{key}", max_length=256)
    return result


def _validate_query(value: Any, label: str) -> dict[str, str]:
    require(type(value) is dict, f"{label} must be an object")
    require(len(value) <= 16, f"{label} has too many entries")
    result: dict[str, str] = {}
    for key, child in value.items():
        _text(key, f"{label} key", max_length=64)
        if QUERY_KEY_RE.fullmatch(key) is None:
            require(_query_override_alias(key), f"{label} key is malformed")
        result[key] = _text(child, f"{label}.{key}", max_length=256)
    return result


def _validate_request(value: Any, label: str) -> dict[str, Any]:
    row = _strict_keys(value, REQUEST_KEYS, label)
    _walk_redaction(row, label)
    method = _text(row["method"], f"{label}.method", max_length=16)
    require(METHOD_RE.fullmatch(method) is not None, f"{label}.method is malformed")
    _text(row["path"], f"{label}.path", max_length=2048)
    _enum(row["client"], KNOWN_CLIENTS, f"{label}.client")
    _enum(row["transport"], KNOWN_TRANSPORTS, f"{label}.transport")
    _enum(row["auth"], KNOWN_AUTH_MODES, f"{label}.auth")
    _validate_headers(row["headers"], f"{label}.headers")
    _validate_query(row["query"], f"{label}.query")
    return row


def _validate_expected(value: Any, label: str) -> dict[str, Any]:
    row = _strict_keys(value, EXPECTED_KEYS, label)
    decision = _enum(row["decision"], frozenset({"allow", "deny"}), f"{label}.decision")
    _enum(row["reason"], KNOWN_REASONS, f"{label}.reason")
    if row["route_id"] is not None:
        route_id = _text(row["route_id"], f"{label}.route_id", max_length=64)
        require(route_id in ROUTE_BY_ID, f"{label}.route_id is unknown")
    surface = _enum(row["surface"], KNOWN_SURFACES | {"none"}, f"{label}.surface")
    if decision == "allow":
        require(row["route_id"] is not None, f"{label}.route_id is required for allow")
        require(surface != "none", f"{label}.surface is required for allow")
    else:
        require(row["route_id"] is None, f"{label}.route_id must be empty for deny")
        require(surface == "none", f"{label}.surface must be none for deny")
    return row


def _validate_policy(value: Any) -> None:
    policy = _strict_keys(value, POLICY_KEYS, "cases.policy")
    require(policy["default_decision"] == "deny", "default route decision must remain deny")
    require(policy["path_matching"] == "exact_raw_path_no_decode", "path matching policy changed")
    require(policy["encoded_paths"] == "deny", "encoded path policy changed")
    require(policy["method_override"] == "deny", "method override policy changed")
    require(_bool(policy["broad_wildcards"], "cases.policy.broad_wildcards") is False, "broad wildcards must remain disabled")
    require(policy["spa_fallback"] == "exact_list_only", "SPA fallback policy changed")


def _validate_redaction_flags(value: Any) -> None:
    redaction = _strict_keys(value, REDACTION_KEYS, "cases.redaction")
    require(_bool(redaction["synthetic_only"], "redaction.synthetic_only") is True, "redaction scope changed")
    for key in REDACTION_KEYS[1:]:
        require(_bool(redaction[key], f"redaction.{key}") is False, f"redaction.{key} must remain false")


def _path_template_matches(template: str, path: str) -> bool:
    marker = "{session_id}"
    if marker not in template:
        return template == path
    if template.count(marker) != 1:
        return False
    prefix, suffix = template.split(marker)
    if not path.startswith(prefix) or not path.endswith(suffix):
        return False
    end = len(path) - len(suffix) if suffix else len(path)
    value = path[len(prefix) : end]
    return bool(SESSION_ID_RE.fullmatch(value))


def _path_candidates(path: str) -> list[dict[str, Any]]:
    exact = [route for route in ALL_ROUTES if "{session_id}" not in route["path"] and route["path"] == path]
    if exact:
        return exact
    return [route for route in ALL_ROUTES if _path_template_matches(route["path"], path)]


QUERY_METHOD_OVERRIDE_ALIASES = frozenset(
    {
        "method",
        "_method",
        "method_override",
        "x_method_override",
        "x_http_method",
        "x_http_method_override",
    }
)
HEADER_METHOD_OVERRIDE_ALIASES = frozenset({"x-http-method-override", "x-method-override", "x-http-method"})


def _query_key_variants(key: str) -> frozenset[str]:
    """Return bounded raw/percent-decoded spellings for deny-before-match checks."""

    variants = {key}
    current = key
    for _ in range(3):
        if "%" not in current:
            break
        decoded = unquote(current)
        if decoded == current:
            break
        variants.add(decoded)
        current = decoded
    return frozenset(variants)


def _query_override_alias(key: str) -> bool:
    return any(candidate.casefold().replace("-", "_") in QUERY_METHOD_OVERRIDE_ALIASES for candidate in _query_key_variants(key))


def _header_override_alias(key: str) -> bool:
    return key.casefold().replace("_", "-") in HEADER_METHOD_OVERRIDE_ALIASES


def _override_present(request: dict[str, Any]) -> bool:
    for key in request["headers"]:
        if _header_override_alias(key):
            return True
    for key in request["query"]:
        if _query_override_alias(key):
            return True
    return False


def _raw_override_present(request: Any) -> bool:
    """Catch encoded or non-schema alias spellings before strict query parsing."""

    if type(request) is not dict:
        return False
    headers = request.get("headers")
    if type(headers) is dict and any(type(key) is str and _header_override_alias(key) for key in headers):
        return True
    query = request.get("query")
    if type(query) is dict and any(type(key) is str and _query_override_alias(key) for key in query):
        return True
    return False


def _path_precheck(path: str) -> str | None:
    if not path.startswith("/") or path.startswith("//"):
        return "path_shape_denied"
    if any(ord(character) > 127 for character in path) or "\\" in path or CONTROL_RE.search(path):
        return "path_shape_denied"
    if "%" in path:
        return "encoded_path_denied"
    if "?" in path or "#" in path:
        return "path_shape_denied"
    if "//" in path:
        return "path_shape_denied"
    segments = path.split("/")
    if "." in segments or ".." in segments:
        return "path_traversal_denied"
    if path != "/" and path.endswith("/"):
        return "path_shape_denied"
    if "*" in path:
        return "wildcard_denied"
    if path.startswith("/hermes/hermes/"):
        return "duplicate_prefix_denied"
    return None


def _unprefixed_or_management_reason(path: str) -> str:
    if path in UNPREFIXED_PATHS or path == "/api/ws" or path == "/api/pty" or path.startswith("/api/") or path.startswith("/auth/") or path == "/login":
        return "path_prefix_required"
    if path in BLOCKED_MANAGEMENT_PATHS or any(path.startswith(prefix) for prefix in BLOCKED_MANAGEMENT_PREFIXES):
        return "management_route_denied"
    return "default_deny"


def _deny(reason: str) -> dict[str, Any]:
    return {"decision": "deny", "reason": reason, "route_id": None, "surface": "none"}


def _allow(route: dict[str, Any]) -> dict[str, Any]:
    reason = "static_route_allowed" if route["surface"] in {"static_shell", "spa_deep_link"} else (
        "websocket_route_allowed" if route["transport"] == "websocket" else "dashboard_route_allowed"
    )
    return {"decision": "allow", "reason": reason, "route_id": route["id"], "surface": route["surface"]}


def evaluate_request(request: Any) -> dict[str, Any]:
    """Evaluate one synthetic request with default-deny semantics."""

    if _raw_override_present(request):
        return _deny("method_override_denied")
    row = _validate_request(request, "request")
    if _override_present(row):
        return _deny("method_override_denied")
    path = row["path"]
    precheck = _path_precheck(path)
    if precheck is not None:
        return _deny(precheck)
    candidates = _path_candidates(path)
    if not candidates:
        return _deny(_unprefixed_or_management_reason(path))
    method_candidates = [route for route in candidates if route["method"] == row["method"]]
    if not method_candidates:
        return _deny("method_not_allowlisted")
    transport_candidates = [route for route in method_candidates if route["transport"] == row["transport"]]
    if not transport_candidates:
        return _deny("transport_not_allowlisted")
    client_candidates = [route for route in transport_candidates if row["client"] in route["clients"]]
    if not client_candidates:
        return _deny("client_not_allowlisted")
    auth_candidates = [
        route
        for route in client_candidates
        if row["auth"] in route["auth_bindings"][row["client"]]
    ]
    if not auth_candidates:
        return _deny("auth_not_allowlisted")
    return _allow(auth_candidates[0])


def evaluate_case(case: Any) -> dict[str, Any]:
    """Evaluate a manifest case after its closed schema has been checked."""

    require(type(case) is dict, "case must be an object")
    return evaluate_request(case["request"])


def validate_cases_document(document: Any) -> None:
    """Validate the frozen matrix and independently compute every case result."""

    root = _strict_keys(document, CASES_ROOT_KEYS, "cases")
    require(root["schema"] == SCHEMA, "cases schema changed")
    require(root["operation"] == OPERATION, "cases operation changed")
    require(root["contract"] == CONTRACT, "cases contract changed")
    require(root["pinned_source_sha"] == PINNED_HERMES_SHA, "pinned Hermes SHA changed")
    require(root["source_audit_id"] == SOURCE_AUDIT_ID, "source audit identity changed")
    require(root["source_contract_path"] == SOURCE_CONTRACT_PATH, "source contract path changed")
    require(_bool(root["synthetic_only"], "cases.synthetic_only") is True, "cases must be synthetic")
    require(_bool(root["network_access"], "cases.network_access") is False, "network access must be disabled")
    require(_bool(root["proxy_neutral"], "cases.proxy_neutral") is True, "proxy-specific syntax is not allowed")
    require(root["prefix"] == PREFIX, "external prefix changed")
    _validate_policy(root["policy"])
    _validate_redaction_flags(root["redaction"])
    _validate_route_list(root["static_routes"], EXPECTED_STATIC_ROUTES, "cases.static_routes")
    _validate_route_list(root["external_routes"], EXPECTED_EXTERNAL_ROUTES, "cases.external_routes")
    cases = root["cases"]
    require(type(cases) is list, "cases.cases must be an array")
    require(len(cases) == len(EXPECTED_CASE_IDS), "case count changed")
    seen: set[str] = set()
    for index, case in enumerate(cases):
        row = _strict_keys(case, CASE_KEYS, f"cases.cases[{index}]")
        case_id = _text(row["id"], f"cases.cases[{index}].id", max_length=96)
        require(case_id == EXPECTED_CASE_IDS[index], f"cases.cases[{index}].id is out of contract order")
        require(case_id not in seen, f"cases.cases[{index}].id is duplicated")
        seen.add(case_id)
        _text(row["description"], f"cases.cases[{index}].description", max_length=240)
        _validate_request(row["request"], f"cases.cases[{index}].request")
        _validate_expected(row["expected"], f"cases.cases[{index}].expected")
        actual = evaluate_request(row["request"])
        require(actual == row["expected"], f"cases.cases[{index}] expected outcome does not match the boundary model")


def _round_ms(value: float) -> float:
    return round(value, 3)


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * weight


def _distribution(trace: list[float]) -> dict[str, float]:
    return {
        "min_ms": _round_ms(min(trace)),
        "p50_ms": _round_ms(_percentile(trace, 0.50)),
        "p95_ms": _round_ms(_percentile(trace, 0.95)),
        "p99_ms": _round_ms(_percentile(trace, 0.99)),
        "max_ms": _round_ms(max(trace)),
        "mean_ms": _round_ms(sum(trace) / len(trace)),
    }


def _current_environment() -> dict[str, str]:
    return {"platform": platform.platform(), "python": platform.python_version()}


def _canonical_artifact_content(relative: str, content: bytes) -> bytes:
    """Avoid a circular hash while keeping the validator in the evidence set."""

    if relative != "validate.py":
        return content
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError("validator artifact is not UTF-8") from exc
    text = re.sub(r"(?m)^EXPECTED_ARTIFACT_BYTES = [0-9]+$", "EXPECTED_ARTIFACT_BYTES = <pinned>", text)
    text = re.sub(
        r'(?m)^EXPECTED_ARTIFACT_SHA256 = "[0-9a-f]{64}"$',
        'EXPECTED_ARTIFACT_SHA256 = "<pinned>"',
        text,
    )
    return text.encode("utf-8")


def artifact_digest(root: Path = ROOT) -> tuple[int, str]:
    """Hash sorted artifact names and canonicalized artifact bytes."""

    digest = hashlib.sha256()
    total = 0
    for relative in ARTIFACT_FILES:
        try:
            content = (root / relative).read_bytes()
        except OSError as exc:
            raise ValidationError("fixture artifact is unavailable") from exc
        total += len(content)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(_canonical_artifact_content(relative, content))
        digest.update(b"\0")
    return total, digest.hexdigest()


def validate_baseline(baseline: Any, root: Path = ROOT) -> None:
    """Recompute every 30-sample distribution and bind the artifact digest."""

    document = _strict_keys(baseline, BASELINE_ROOT_KEYS, "baseline")
    require(document["schema"] == BASELINE_SCHEMA, "baseline schema changed")
    require(document["validator"] == "contracts/fixtures/deployment-security/external-allowlist/validate.py", "baseline validator changed")
    require(document["fixture"] == "contracts/fixtures/deployment-security/external-allowlist/cases.json", "baseline fixture changed")
    require(document["metric"] == "validator_duration_ms", "baseline metric changed")
    environment = _strict_keys(document["environment"], BASELINE_ENVIRONMENT_KEYS, "baseline.environment")
    require(environment == _current_environment(), "baseline environment is stale")
    runs = document["runs"]
    require(type(runs) is list and len(runs) == 2, "baseline must contain normal and optimized runs")
    expected_modes = ("normal", "optimized")
    for index, (run, expected_mode) in enumerate(zip(runs, expected_modes)):
        row = _strict_keys(run, BASELINE_RUN_KEYS, f"baseline.runs[{index}]")
        require(row["mode"] == expected_mode, f"baseline.runs[{index}] mode changed")
        require(row["command"] == BASELINE_COMMANDS[expected_mode], f"baseline.runs[{index}] command changed")
        repetitions = row["repetitions"]
        require(type(repetitions) is int and type(repetitions) is not bool and repetitions == MAX_BASELINE_TRACE, f"baseline.runs[{index}] repetitions must be 30")
        trace = row["trace"]
        require(type(trace) is list and len(trace) == MAX_BASELINE_TRACE, f"baseline.runs[{index}] trace must contain 30 samples")
        checked_trace: list[float] = []
        for sample_index, sample in enumerate(trace):
            require(type(sample) is float and math.isfinite(sample), f"baseline.runs[{index}].trace[{sample_index}] must be finite")
            require(0 < sample <= 60_000, f"baseline.runs[{index}].trace[{sample_index}] is outside bounds")
            checked_trace.append(sample)
        distribution = _strict_keys(row["distribution"], BASELINE_DISTRIBUTION_KEYS, f"baseline.runs[{index}].distribution")
        for key, value in distribution.items():
            require(type(value) is float and math.isfinite(value), f"baseline.runs[{index}].distribution.{key} must be finite")
            require(0 < value <= 60_000, f"baseline.runs[{index}].distribution.{key} is outside bounds")
        require(distribution == _distribution(checked_trace), f"baseline.runs[{index}] distribution does not match its trace")
    artifact = _strict_keys(document["artifact"], BASELINE_ARTIFACT_KEYS, "baseline.artifact")
    require(artifact["files"] == list(ARTIFACT_FILES), "baseline artifact file list changed")
    require(type(artifact["bytes"]) is int and type(artifact["bytes"]) is not bool, "baseline artifact bytes must be an integer")
    actual_bytes, actual_sha = artifact_digest(root)
    require(actual_bytes == EXPECTED_ARTIFACT_BYTES, "checked-in artifact byte evidence changed")
    require(actual_sha == EXPECTED_ARTIFACT_SHA256, "checked-in artifact digest evidence changed")
    require(artifact["bytes"] == actual_bytes, "baseline artifact byte count is stale")
    require(artifact["sha256"] == actual_sha, "baseline artifact digest is stale")
    require(document["threshold"] is None, "baseline threshold must remain null")


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


def _failure_payload(error: object) -> str:
    return json.dumps(
        {"ok": False, "error": {"code": ERROR_CODE, "message": compact_error(error)}},
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
    """Run the local validator and emit exactly one bounded JSON line."""

    try:
        parser = ControlledArgumentParser(add_help=False)
        parser.add_argument("--cases", type=Path, default=CASES_PATH)
        parser.add_argument("--baseline", type=Path, default=BASELINE_PATH)
        parser.add_argument("--skip-baseline", action="store_true")
        args = parser.parse_args(argv)
        document = load_json(args.cases)
        validate_redaction(document)
        validate_cases_document(document)
        validate_readme_redaction(ROOT)
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
    except (Exception, SystemExit) as exc:
        sys.stdout.write(_failure_payload(exc) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
