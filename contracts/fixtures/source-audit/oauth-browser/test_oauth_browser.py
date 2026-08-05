#!/usr/bin/env python3
"""Offline regression tests for the pinned browser OAuth contract.

The test data is synthetic. The source observations are checked against
immutable excerpts and immutable Git object identifiers from the pinned Hermes
revision before the callback cases are validated, so the suite does not merely
compare duplicated JSON metadata. It deliberately does not import Hermes or
contact a provider.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import math
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


FIXTURE_DIR = Path(__file__).resolve().parent
REPOSITORY_ROOT = FIXTURE_DIR.parents[3]
DOC_PATH = REPOSITORY_ROOT / "docs/security/authentication.md"
SOURCE_AUDIT_PATH = FIXTURE_DIR / "source_audit.json"
CASES_PATH = FIXTURE_DIR / "cases.json"
SOURCE_EXCERPT_DIR = FIXTURE_DIR / "source_excerpts"
PINNED_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
PINNED_TREE_SHA = "886db5eb1150f819344d67fedc81aef0caab09ff"
MAX_JSON_DEPTH = 128
MAX_JSON_INTEGER_DIGITS = 4300
MAX_ERROR_OUTPUT = 240
DUPLICATE_JSON_KEY_ERROR = "duplicate JSON object key"
NONFINITE_JSON_NUMBER_ERROR = "non-finite JSON number is not allowed"
INTEGER_DIGIT_LIMIT_ERROR = "JSON integer digit limit exceeded"
REQUIRED_CASES = {
    "success",
    "state-mismatch",
    "missing-state",
    "pkce-failure",
    "cancellation",
    "malformed-callback",
}
PROVIDER_HTTP_400_OBSERVATION = "token_exchange_http_400_maps_to_invalid_code_error"
PROVIDER_HTTP_400_CASES = {
    "pkce-failure": "rejected",
    "malformed-callback": "rejected_empty_code",
}
CASES_ROOT_KEYS = frozenset(
    {
        "fixture_id",
        "source_sha",
        "contract",
        "provider",
        "provider_mode",
        "provider_error_observation",
        "cases",
        "synthetic_only",
    }
)
AUDIT_ROOT_KEYS = frozenset(
    {
        "fixture_id",
        "contract",
        "flow",
        "source",
        "requirements",
        "failure_semantics",
        "redaction",
        "synthetic_only",
        "network_access",
        "apple_behavior",
        "superdesign_output",
    }
)
REQUIREMENTS_KEYS = frozenset({"scope", "state", "pkce", "nonce", "password_provider"})
STATE_REQUIREMENT_KEYS = frozenset({"required", "comparison"})
PKCE_REQUIREMENT_KEYS = frozenset({"required", "applies_to", "method", "comparison"})
NONCE_REQUIREMENT_KEYS = frozenset(
    {"policy", "global_requirement", "positive_requirements_require_compatibility_scope", "provider_scopes"}
)
NONCE_GLOBAL_KEYS = frozenset({"required", "scope"})
NONCE_PROVIDER_SCOPE_KEYS = frozenset({"provider", "scope", "required", "condition", "exposed"})
PASSWORD_REQUIREMENT_KEYS = frozenset(
    {"supports_password", "oauth_state_required", "pkce_required", "reason"}
)
FAILURE_SEMANTICS_KEYS = frozenset(
    {
        "missing_pkce_cookie",
        "missing_or_mismatched_state",
        "provider_cancellation",
        "provider_error",
        "pkce_or_code_rejection",
        "malformed_callback",
        "invalid_code_error",
        "provider_unreachable",
        "retry",
    }
)
FAILURE_ENTRY_KEYS = frozenset({"outcome", "source_ref", "markers"})
REDACTION_KEYS = frozenset(
    {
        "synthetic_cookie_shaped_values",
        "public_source_urls",
        "live_secrets",
        "live_cookie_contents",
        "live_host_data",
        "transcripts",
        "user_data",
    }
)

# The expected matrix is independent of each fixture's self-reported outcome.
# This prevents a case from changing its status, reason, exchange, or cleanup
# result without changing the regression contract as well.
EXPECTED_OUTCOME_MATRIX = {
    "success": {
        "expected": {
            "status": 302,
            "reason": "login_success",
            "session_cookie_issued": True,
            "pkce_cookie": "cleared",
            "separate_nonce_required": False,
        },
        "provider_exchange": {"called": True, "code_verifier": "cookie", "verifier_result": "accepted"},
    },
    "state-mismatch": {
        "expected": {
            "status": 400,
            "reason": "state_mismatch",
            "session_cookie_issued": False,
            "pkce_cookie": "retained_until_ttl",
            "separate_nonce_required": False,
        },
        "provider_exchange": {"called": False, "code_verifier": None, "verifier_result": "not_attempted"},
    },
    "missing-state": {
        "expected": {
            "status": 400,
            "reason": "state_mismatch",
            "session_cookie_issued": False,
            "pkce_cookie": "retained_until_ttl",
            "separate_nonce_required": False,
        },
        "provider_exchange": {"called": False, "code_verifier": None, "verifier_result": "not_attempted"},
    },
    "pkce-failure": {
        "expected": {
            "status": 400,
            "reason": "invalid_code_or_pkce",
            "session_cookie_issued": False,
            "pkce_cookie": "retained_until_ttl",
            "separate_nonce_required": False,
        },
        "provider_exchange": {"called": True, "code_verifier": "cookie", "verifier_result": "rejected"},
    },
    "cancellation": {
        "expected": {
            "status": 400,
            "reason": "idp_error",
            "session_cookie_issued": False,
            "pkce_cookie": "retained_until_ttl",
            "separate_nonce_required": False,
        },
        "provider_exchange": {"called": False, "code_verifier": None, "verifier_result": "not_attempted"},
    },
    "malformed-callback": {
        "expected": {
            "status": 400,
            "reason": "invalid_code_or_pkce",
            "session_cookie_issued": False,
            "pkce_cookie": "retained_until_ttl",
            "separate_nonce_required": False,
        },
        "provider_exchange": {
            "called": True,
            "code_verifier": "cookie",
            "verifier_result": "rejected_empty_code",
        },
    },
}

# Failure claims are independently pinned to source markers. The JSON copy is
# validated against this manifest, so changing a prose outcome or marker alone
# cannot make an unsupported failure path appear source-backed.
EXPECTED_FAILURE_SEMANTICS = {
    "missing_pkce_cookie": {
        "outcome": "reject callback",
        "source_ref": "hermes_cli/dashboard_auth/routes.py",
        "markers": ("if not pkce_raw:", 'detail="Missing PKCE state cookie"'),
    },
    "missing_or_mismatched_state": {
        "outcome": "reject callback before provider exchange",
        "source_ref": "hermes_cli/dashboard_auth/routes.py",
        "markers": (
            "if not state or state != expected_state:",
            'detail="OAuth state mismatch (CSRF check failed)"',
            "p.complete_login(",
        ),
    },
    "provider_cancellation": {
        "outcome": "reject callback without a session cookie",
        "source_ref": "hermes_cli/dashboard_auth/routes.py",
        "markers": ("if error:", 'detail=f"OAuth error from provider: {error} ({error_description})"'),
    },
    "provider_error": {
        "outcome": "reject callback without a session cookie",
        "source_ref": "hermes_cli/dashboard_auth/routes.py",
        "markers": (
            "if error:",
            "raise HTTPException(",
            'detail=f"OAuth error from provider: {error} ({error_description})"',
        ),
    },
    "pkce_or_code_rejection": {
        "outcome": "reject callback without a session cookie",
        "source_ref": "hermes_cli/dashboard_auth/routes.py",
        "markers": (
            "code_verifier=verifier,",
            "except InvalidCodeError as e:",
            'detail=f"Invalid code: {e}"',
        ),
    },
    "malformed_callback": {
        "outcome": "fail closed without a session cookie",
        "source_ref": "hermes_cli/dashboard_auth/routes.py",
        "markers": ('code: str = ""', "session = p.complete_login(", "except InvalidCodeError as e:"),
    },
    "invalid_code_error": {
        "outcome": "reject callback without a session cookie",
        "source_ref": "hermes_cli/dashboard_auth/routes.py",
        "markers": (
            "except InvalidCodeError as e:",
            "status_code=400",
            'detail=f"Invalid code: {e}"',
        ),
    },
    "provider_unreachable": {
        "outcome": "fail login start with provider-unreachable error",
        "source_ref": "hermes_cli/dashboard_auth/routes.py",
        "markers": (
            "except ProviderError as e:",
            'reason="provider_unreachable"',
            "status_code=503",
            'detail=f"Provider unreachable: {e}"',
        ),
    },
    "retry": {
        "outcome": "start a fresh login attempt",
        "source_ref": None,
        "markers": (),
    },
}

# These values are a separately reviewed provenance manifest, not values read
# from source_audit.json. The blob IDs are immutable Git objects from the
# pinned commit; the excerpt hashes bind the checked-in, narrow evidence files.
EXPECTED_SOURCE_REFS = (
    {
        "path": "hermes_cli/dashboard_auth/routes.py",
        "excerpt": "source_excerpts/routes_auth.py.txt",
        "excerpt_sha256": "7a748fc29acee3d055049f0b1a12bba9e7d8aa13bc4852827888a0ebaaa507b4",
        "blob_sha": "0c142963bcc83f38fddbdcec29c35608f14f7bc1",
        "url": "https://github.com/NousResearch/hermes-agent/blob/f5be9236e00ddf2f2a412697f267078fc4ee068e/hermes_cli/dashboard_auth/routes.py",
    },
    {
        "path": "plugins/dashboard_auth/nous/__init__.py",
        "excerpt": "source_excerpts/nous_provider.py.txt",
        "excerpt_sha256": "53f633d5e405459ad0d042470e06af545fad6d1d02b86f23a473ece283ce8c87",
        "blob_sha": "69acd18e36b545fd20df5578809de65afb0d4df4",
        "url": "https://github.com/NousResearch/hermes-agent/blob/f5be9236e00ddf2f2a412697f267078fc4ee068e/plugins/dashboard_auth/nous/__init__.py",
    },
    {
        "path": "hermes_cli/dashboard_auth/cookies.py",
        "excerpt": "source_excerpts/cookies.py.txt",
        "excerpt_sha256": "4061f5e075fee015151a14ab75c7b77661400bb2ec0fa402559c0d49cae36f3e",
        "blob_sha": "8bcd9db78eb6a8e9209e1b3087ab4e85b8997f1e",
        "url": "https://github.com/NousResearch/hermes-agent/blob/f5be9236e00ddf2f2a412697f267078fc4ee068e/hermes_cli/dashboard_auth/cookies.py",
    },
)
EXPECTED_SOURCE_REF_KEYS = frozenset(
    {"path", "excerpt", "excerpt_sha256", "blob_sha", "url", "observations"}
)
EXCERPT_FILES = {
    "routes": "routes_auth.py.txt",
    "nous": "nous_provider.py.txt",
    "cookies": "cookies.py.txt",
}

# Each source-audit observation is tied to source markers, including marker
# order where the source establishes a short-circuit or post-exchange action.
SOURCE_EVIDENCE = {
    "hermes_cli/dashboard_auth/routes.py": {
        "password_provider_short_circuits_oauth_start": [
            (
                "routes",
                (
                    'if getattr(p, "supports_password", False):',
                    "return RedirectResponse(url=login_url, status_code=302)",
                    "ls = p.start_login(",
                ),
            ),
        ],
        "oauth_start_returns_state_and_verifier_cookie_payload": [
            (
                "routes",
                ("ls.cookie_payload.get(\"hermes_session_pkce\"", "set_pkce_cookie("),
            ),
            (
                "nous",
                ('"hermes_session_pkce": f"state={state};verifier={code_verifier}"',),
            ),
        ],
        "callback_rejects_missing_or_mismatched_state_before_exchange": [
            (
                "routes",
                (
                    "if not state or state != expected_state:",
                    'detail="OAuth state mismatch (CSRF check failed)",',
                    "p.complete_login(",
                ),
            ),
        ],
        "callback_passes_cookie_verifier_to_complete_login": [
            ("routes", ("p.complete_login(", "code_verifier=verifier,")),
        ],
        "callback_issues_and_clears_session_only_after_exchange": [
            (
                "routes",
                ("session = p.complete_login(", "set_session_cookies(", "clear_pkce_cookie("),
            ),
        ],
    },
    "plugins/dashboard_auth/nous/__init__.py": {
        "authorization_params_include_state": [
            (
                "nous",
                ("params = {", '"state": state,', "urllib.parse.urlencode(params)"),
            ),
        ],
        "authorization_params_include_s256_pkce": [
            (
                "nous",
                ('"code_challenge": code_challenge,', '"code_challenge_method": "S256",'),
            ),
        ],
        "authorization_params_exclude_nonce": [("nous", ())],
        "cookie_payload_contains_state_and_verifier": [
            (
                "nous",
                ('"hermes_session_pkce": f"state={state};verifier={code_verifier}"',),
            ),
        ],
        "token_exchange_sends_code_verifier": [
            ("nous", ('"code_verifier": code_verifier,',)),
        ],
        PROVIDER_HTTP_400_OBSERVATION: [
            (
                "nous",
                (
                    "A 400 here means",
                    "surfaced as InvalidCodeError.",
                    "bad_request_exc=InvalidCodeError",
                ),
            ),
        ],
    },
    "hermes_cli/dashboard_auth/cookies.py": {
        "pkce_cookie_is_short_lived": [
            ("cookies", ('PKCE_COOKIE = "hermes_session_pkce"', "_PKCE_MAX_AGE = 10 * 60")),
        ],
        "pkce_cookie_is_http_only_lax_and_secure_for_https": [
            ("cookies", ('"httponly": True', '"samesite": "lax"', 'attrs["secure"] = True')),
        ],
        "csrf_nonce_label_is_state_not_provider_nonce": [
            ("cookies", ("CSRF nonce", "PKCE_COOKIE")),
        ],
    },
}

SYNTHETIC_IDENTIFIER = re.compile(r"^(?:fixture|synthetic)-[a-z0-9]+(?:-[a-z0-9]+)*$")
SYNTHETIC_STATE = re.compile(r"^fixture-state-[a-z0-9]+(?:-[a-z0-9]+)*$")
SYNTHETIC_VERIFIER = re.compile(r"^synthetic-verifier-[a-z0-9]+$")
SYNTHETIC_CODE = re.compile(r"^fixture-code(?:-[a-z0-9]+)*$")
SYNTHETIC_DESCRIPTION = re.compile(r"^fixture-[a-z0-9]+(?:-[a-z0-9]+)*$")
SYNTHETIC_CLIENT_ID = re.compile(r"^fixture-client(?:-[a-z0-9]+)*$")
SYNTHETIC_REDIRECT_URI = re.compile(r"^fixture-redirect-uri(?:-[a-z0-9]+)*$")
SYNTHETIC_SCOPE = re.compile(r"^fixture-scope(?:-[a-z0-9]+)*$")
CODE_CHALLENGE = re.compile(r"^[A-Za-z0-9_-]{43}$")
NONCE_POSITIVE = re.compile(
    r"(?:\b(?:must|should|apply|accept|check|require(?:s|d)?|enforce(?:s|d)?|include(?:s|d)?|"
    r"use(?:s|d)?|validate(?:s|d)?|verify(?:s|ied)?|need(?:s|ed)?|"
    r"mandatory|required|compulsory|requirement)\b[^.!?;\n]{0,120}\bnonce\b|"
    r"\bnonce\b[^.!?;\n]{0,120}\b(?:must|should|require(?:s|d)?|"
    r"enforce(?:s|d)?|include(?:s|d)?|use(?:s|d)?|validate(?:s|d)?|"
    r"verify(?:s|ied)?|need(?:s|ed)?|mandatory|required|compulsory|"
    r"requirement)\b)",
    re.IGNORECASE,
)
NONCE_PROHIBITION = re.compile(
    r"(?:\b(?:must|should|shall|may)\s+not\s+"
    r"(?:require|validate|enforce|include|use|accept|need|add|invent|impose|claim|expose)\b"
    r"[^.!?;\n]{0,120}\bnonce\b|"
    r"\b(?:does|do|did)\s+not\s+"
    r"(?:require|validate|enforce|include|use|accept|need|expose)\b"
    r"[^.!?;\n]{0,120}\bnonce\b|"
    r"\bno\s+(?:(?:separate|unscoped|global|positive|additional|distinct|"
    r"provider-specific|oauth/oidc)\s+){0,6}`?nonce`?\b"
    r"[^.!?;\n]{0,80}\b(?:required|needed|present|exposed|supported|"
    r"requirement|allowed)\b|"
    r"\b`?nonce`?\b[^.!?;\n]{0,80}\b(?:is|was|be)\s+not\s+"
    r"(?:required|needed|present|exposed|supported)\b)",
    re.IGNORECASE,
)
NONCE_SCOPE = re.compile(
    r"\b(?:provider-specific|reviewed(?:[- ]provider)?|compatibility\s+record|"
    r"pinned\s+Nous|only\s+when)\b",
    re.IGNORECASE,
)
NONCE_GLOBAL = re.compile(
    r"\b(?:global(?:ly)?|regardless|unconditionally|always|universally)\b"
    r"(?!\s+(?:nonce\s+)?requirement\s+(?:is|remains)\s+"
    r"(?:false|disabled|absent)\b)|"
    r"\b(?:all|every|each|any)\b(?!\s+(?:reviewed|provider-specific|pinned)\b)"
    r"[^.!?;\n]{0,80}\b(?:provider|callback|flow|client|request|authorization|login)\b|"
    r"\b(?:all|every|each|any)\s+providers?\b",
    re.IGNORECASE,
)
SENSITIVE_FIELD = re.compile(
    r"^(?:access[_ -]?token|refresh[_ -]?token|client[_ -]?secret|"
    r"cookie[_ -]?value|api[_ -]?key|authorization|bearer|password)$",
    re.IGNORECASE,
)
SENSITIVE_ASSIGNMENT = re.compile(
    r"\b(?:access[_ -]?token|refresh[_ -]?token|client[_ -]?secret|cookie[_ -]?value)"
    r"\s*[:=]\s*(?P<value>[^\s,}]+)",
    re.IGNORECASE,
)
SECRET_VALUE_PATTERNS = (
    re.compile(r"(?:ghp_live_|github_pat_|sk_live_|xox[baprs]-)[A-Za-z0-9_=-]+", re.IGNORECASE),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", re.IGNORECASE),
    re.compile(r"-----BEGIN\s+(?:RSA|EC|OPENSSH|PRIVATE)\s+KEY-----", re.IGNORECASE),
)
# Source excerpts contain legitimate code such as
# ``access_token=session.access_token``. Permit those expressions while still
# rejecting a sensitive assignment whose right-hand side looks like fixture
# credential material, for example ``cookie_value=fixture_live_cookie``.
EXCERPT_SAFE_ASSIGNMENT_RHS = re.compile(
    r"(?:[A-Za-z_]\w*(?:\.[A-Za-z_]\w+)+|[A-Za-z_]\w+\([^()\n]*\)|None|True|False|['\"]{2})"
)


def compact_error(message: object) -> str:
    """Redact credential-shaped text and cap one validation diagnostic."""

    redacted = str(message)
    for pattern in SECRET_VALUE_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)

    def redact_assignment(match: re.Match[str]) -> str:
        value = match.group("value")
        prefix = match.group(0)[: -len(value)]
        return f"{prefix}[REDACTED]"

    redacted = SENSITIVE_ASSIGNMENT.sub(redact_assignment, redacted)
    if len(redacted) > MAX_ERROR_OUTPUT:
        return f"{redacted[: MAX_ERROR_OUTPUT - 3]}..."
    return redacted


def require(condition: bool, message: str) -> None:
    """Raise an assertion that remains active even under ``python -O``."""
    if not condition:
        raise AssertionError(message)


class FixtureJSONError(ValueError):
    """Raised for malformed or unsafe JSON before schema/redaction checks run."""

    def __init__(self, message: object):
        super().__init__(compact_error(message))


def reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate keys without echoing attacker-controlled key text."""

    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FixtureJSONError(DUPLICATE_JSON_KEY_ERROR)
        result[key] = value
    return result


def reject_nonfinite_json_constant(value: str) -> Any:
    """Reject JSON extensions that can smuggle non-finite numbers."""

    raise FixtureJSONError(NONFINITE_JSON_NUMBER_ERROR)


def reject_overflowing_json_float(value: str) -> float:
    """Reject exponent overflow such as ``1e9999`` at parse time."""

    parsed = float(value)
    if not math.isfinite(parsed):
        raise FixtureJSONError(NONFINITE_JSON_NUMBER_ERROR)
    return parsed


def reject_oversized_json_integer(value: str) -> int:
    """Reject integers beyond the explicit bound before ``int`` can fail raw."""

    digits = value[1:] if value.startswith("-") else value
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise FixtureJSONError(INTEGER_DIGIT_LIMIT_ERROR)
    try:
        return int(value)
    except ValueError:
        raise FixtureJSONError("invalid JSON integer") from None


def scan_json_nesting(text: str) -> None:
    """Bound structural nesting before ``json`` can recurse on hostile input."""

    depth = 0
    in_string = False
    escaped = False
    for offset, character in enumerate(text):
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
                raise FixtureJSONError("maximum JSON nesting depth exceeded")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise FixtureJSONError("malformed JSON nesting")


def validate_json_tree(value: Any, label: str = "fixture", depth: int = 0) -> None:
    """Reject unsupported leaves, non-finite values, and post-parse deep trees."""

    if depth > MAX_JSON_DEPTH:
        raise FixtureJSONError(f"{label}: maximum JSON nesting depth exceeded")
    if type(value) is dict:
        for key, child in value.items():
            if type(key) is not str:
                raise FixtureJSONError(f"{label}: object key must be a string")
            validate_json_tree(child, f"{label}.{key}", depth + 1)
        return
    if type(value) is list:
        for index, child in enumerate(value):
            validate_json_tree(child, f"{label}[{index}]", depth + 1)
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise FixtureJSONError(f"{label}: non-finite JSON number is not allowed")
        return
    if value is None or type(value) in (bool, int, str):
        return
    raise FixtureJSONError(f"{label}: unsupported JSON value type")


def load_json(path: Path) -> dict[str, Any]:
    """Load every owned JSON artifact through one strict, fail-closed path."""

    try:
        text = path.read_text(encoding="utf-8")
        scan_json_nesting(text)
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicate_json_keys,
            parse_constant=reject_nonfinite_json_constant,
            parse_float=reject_overflowing_json_float,
            parse_int=reject_oversized_json_integer,
        )
        if type(value) is not dict:
            raise FixtureJSONError("fixture root must be an object")
        validate_json_tree(value)
        return value
    except (FixtureJSONError, OSError, UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise FixtureJSONError(f"invalid JSON input: {exc}") from None


def require_exact_keys(value: Any, expected: frozenset[str], label: str) -> dict[str, Any]:
    require(type(value) is dict, f"{label} must be an object")
    require(set(value) == expected, f"{label} keys changed")
    return value


def validate_no_live_secrets(
    value: Any,
    path: str = "$",
    *,
    scan_keys: bool = True,
    scan_assignments: bool = True,
) -> None:
    """Walk every nested fixture value, including lists and mapping keys."""
    if type(value) is dict:
        for key, child in value.items():
            key_path = f"{path}.{key}"
            if scan_keys:
                require(not SENSITIVE_FIELD.fullmatch(str(key)), f"sensitive fixture field: {key_path}")
            validate_no_live_secrets(
                child,
                key_path,
                scan_keys=scan_keys,
                scan_assignments=scan_assignments,
            )
        return
    if type(value) is list:
        for index, child in enumerate(value):
            validate_no_live_secrets(
                child,
                f"{path}[{index}]",
                scan_keys=scan_keys,
                scan_assignments=scan_assignments,
            )
        return
    if type(value) is str:
        for pattern in SECRET_VALUE_PATTERNS:
            require(pattern.search(value) is None, f"live secret-shaped fixture value at {path}")
        for match in SENSITIVE_ASSIGNMENT.finditer(value):
            rhs = match.group("value").strip()
            if not scan_assignments and EXCERPT_SAFE_ASSIGNMENT_RHS.fullmatch(rhs):
                continue
            require(False, f"live secret-shaped fixture assignment at {path}")


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def fixture_artifact_bytes() -> int:
    paths = [SOURCE_AUDIT_PATH, CASES_PATH]
    paths.extend(SOURCE_EXCERPT_DIR / filename for filename in EXCERPT_FILES.values())
    return sum(path.stat().st_size for path in paths)


def load_source_excerpts() -> dict[str, str]:
    excerpts: dict[str, str] = {}
    for key, filename in EXCERPT_FILES.items():
        path = SOURCE_EXCERPT_DIR / filename
        text = path.read_text(encoding="utf-8")
        actual_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        # This expected hash map is independent of source_audit.json. The
        # explicit filename-to-hash relationship keeps provenance readable.
        expected_hash = {
            "routes": EXPECTED_SOURCE_REFS[0]["excerpt_sha256"],
            "nous": EXPECTED_SOURCE_REFS[1]["excerpt_sha256"],
            "cookies": EXPECTED_SOURCE_REFS[2]["excerpt_sha256"],
        }[key]
        require(actual_hash == expected_hash, f"changed source excerpt: {key}")
        excerpts[key] = text
    return excerpts


def validate_fixture_documents(audit_path: Path, cases_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load and schema-check selected fixture paths before running unittest."""

    audit = load_json(audit_path)
    cases = load_json(cases_path)
    excerpts = load_source_excerpts()
    try:
        validate_audit_root(audit, excerpts)
        validate_cases_root(cases)
    except (AssertionError, AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
        raise FixtureJSONError(f"fixture schema validation failed: {exc}") from None
    return audit, cases


def assert_markers_in_order(text: str, markers: tuple[str, ...], label: str) -> None:
    if not markers:
        require("nonce" not in text, f"unexpected nonce marker in {label}")
        return
    cursor = -1
    for marker in markers:
        position = text.find(marker, cursor + 1)
        require(position >= 0, f"missing source marker {marker!r} in {label}")
        cursor = position


def validate_source_url(url: Any, expected: dict[str, str]) -> None:
    require(type(url) is str, f"source URL is not a string: {expected['path']}")
    require(url == expected["url"], f"source URL changed: {expected['path']}")
    parsed = urlparse(url)
    require(parsed.scheme == "https", f"source URL scheme is not HTTPS: {expected['path']}")
    require(parsed.netloc == "github.com", f"source URL host is not public GitHub: {expected['path']}")
    require(parsed.hostname == "github.com", f"source URL hostname changed: {expected['path']}")
    require(parsed.username is None, f"source URL contains userinfo: {expected['path']}")
    require(parsed.password is None, f"source URL contains password: {expected['path']}")
    require(not parsed.query, f"source URL contains query data: {expected['path']}")
    require(not parsed.fragment, f"source URL contains fragment data: {expected['path']}")
    require(not parsed.params, f"source URL contains path parameters: {expected['path']}")
    expected_path = f"/NousResearch/hermes-agent/blob/{PINNED_SHA}/{expected['path']}"
    require(parsed.path == expected_path, f"source URL path changed: {expected['path']}")


def validate_source_refs(audit: dict[str, Any]) -> dict[str, dict[str, Any]]:
    require(type(audit) is dict, "audit must be an object")
    source = audit.get("source")
    require(type(source) is dict, "source provenance must be an object")
    require(
        set(source) == {"repository", "sha", "tree_sha", "refs"},
        "source provenance shape changed",
    )
    require(source["repository"] == "NousResearch/hermes-agent", "source repository changed")
    require(source["sha"] == PINNED_SHA, "source commit changed")
    require(source["tree_sha"] == PINNED_TREE_SHA, "source tree changed")

    refs = source["refs"]
    require(type(refs) is list, "source refs must remain a list")
    require(len(refs) == len(EXPECTED_SOURCE_REFS), "source ref count changed")
    require(all(type(ref) is dict for ref in refs), "source refs must be objects")
    paths = [ref.get("path") for ref in refs]
    require(all(type(path) is str for path in paths), "source ref paths must be strings")
    require(len(paths) == len(set(paths)), "duplicate source ref path")
    expected_paths = {ref["path"] for ref in EXPECTED_SOURCE_REFS}
    require(set(paths) == expected_paths, "source ref path set changed")

    validated: dict[str, dict[str, Any]] = {}
    for expected in EXPECTED_SOURCE_REFS:
        matches = [ref for ref in refs if ref["path"] == expected["path"]]
        require(len(matches) == 1, f"source ref is not unique: {expected['path']}")
        ref = matches[0]
        require(set(ref) == EXPECTED_SOURCE_REF_KEYS, f"source ref shape changed: {expected['path']}")
        for field in ("path", "excerpt", "excerpt_sha256", "blob_sha"):
            require(ref[field] == expected[field], f"source ref {field} changed: {expected['path']}")
        validate_source_url(ref["url"], expected)
        validated[expected["path"]] = ref
    return validated


def validate_source_observations(
    audit: dict[str, Any], excerpts: dict[str, str]
) -> None:
    refs = validate_source_refs(audit)
    require(type(excerpts) is dict, "source excerpts must be an object")
    require(all(type(text) is str for text in excerpts.values()), "source excerpts must be text")
    require(set(refs) == set(SOURCE_EVIDENCE), "source reference set changed")

    for path, expected_observations in SOURCE_EVIDENCE.items():
        observations = refs[path]["observations"]
        require(type(observations) is dict, f"observations must be an object: {path}")
        require(
            set(observations) == set(expected_observations),
            f"observation IDs changed: {path}",
        )
        for observation, evidence in expected_observations.items():
            require(observations[observation] is True, f"false source observation: {observation}")
            for excerpt_key, markers in evidence:
                require(excerpt_key in excerpts, f"source excerpt is missing: {excerpt_key}")
                assert_markers_in_order(excerpts[excerpt_key], markers, excerpt_key)


def validate_provider_http_400_case_bindings(
    audit: dict[str, Any], cases: dict[str, Any], excerpts: dict[str, str]
) -> None:
    """Bind PKCE and empty-code outcomes to the pinned provider mapping."""
    validate_source_observations(audit, excerpts)
    refs = validate_source_refs(audit)
    nous_observations = refs["plugins/dashboard_auth/nous/__init__.py"]["observations"]
    require(type(nous_observations) is dict, "Nous observations must be an object")
    require(
        nous_observations.get(PROVIDER_HTTP_400_OBSERVATION) is True,
        "provider HTTP 400 observation is missing",
    )
    require(type(cases) is dict, "cases must be an object")
    provider_observation = cases.get("provider_error_observation")
    require(
        type(provider_observation) is str and provider_observation == PROVIDER_HTTP_400_OBSERVATION,
        "case provider error observation changed",
    )
    case_values = cases.get("cases")
    require(type(case_values) is list, "cases must be a list")
    require(all(type(case) is dict for case in case_values), "fixture cases must be objects")
    ids = [case.get("id") for case in case_values]
    require(all(type(case_id) is str for case_id in ids), "case IDs must be strings")

    by_id = {case_id: case for case_id, case in zip(ids, case_values)}
    for case_id, verifier_result in PROVIDER_HTTP_400_CASES.items():
        case = by_id.get(case_id)
        require(case is not None, f"provider error case is missing: {case_id}")
        expected = case.get("expected")
        require(type(expected) is dict, f"expected outcome must be an object: {case_id}")
        status = expected.get("status")
        require(type(status) is int and status == 400, f"provider error status changed: {case_id}")
        reason = expected.get("reason")
        require(
            type(reason) is str and reason == "invalid_code_or_pkce",
            f"provider error reason changed: {case_id}",
        )
        exchange = case.get("provider_exchange")
        require(type(exchange) is dict, f"provider exchange must be an object: {case_id}")
        require(exchange.get("called") is True, f"provider exchange skipped: {case_id}")
        exchange_result = exchange.get("verifier_result")
        require(
            type(exchange_result) is str and exchange_result == verifier_result,
            f"provider error result changed: {case_id}",
        )
        request = case.get("request")
        require(type(request) is dict, f"request must be an object: {case_id}")
        cookie = request.get("pkce_cookie")
        require(type(cookie) is dict, f"PKCE cookie must be an object: {case_id}")
        verifier = cookie.get("verifier")
        require(type(verifier) is str, f"provider verifier must be a string: {case_id}")
        require(
            exchange.get("code_verifier") == verifier,
            f"provider verifier binding changed: {case_id}",
        )


def validate_nonce_policy(requirements: dict[str, Any]) -> None:
    """Require a structured provider-scoped policy, never an implicit global one."""
    require(type(requirements) is dict, "requirements must be an object")
    nonce = require_exact_keys(requirements.get("nonce"), NONCE_REQUIREMENT_KEYS, "requirements.nonce")
    require(nonce["policy"] == "provider_scoped", "nonce policy must remain provider-scoped")
    require(nonce["positive_requirements_require_compatibility_scope"] is True, "nonce scope guard disabled")

    global_requirement = require_exact_keys(
        nonce["global_requirement"], NONCE_GLOBAL_KEYS, "requirements.nonce.global_requirement"
    )
    require(global_requirement["required"] is False, "unscoped global nonce requirement is forbidden")
    require(global_requirement["scope"] is None, "global nonce scope must be null")

    scopes = nonce["provider_scopes"]
    require(isinstance(scopes, list), "nonce provider scopes must be a list")
    require(len(scopes) == 2, "nonce provider scope count changed")
    for index, scope in enumerate(scopes):
        require_exact_keys(scope, NONCE_PROVIDER_SCOPE_KEYS, f"requirements.nonce.provider_scopes[{index}]")
        require(isinstance(scope["provider"], str), "nonce provider name must be a string")
        require(isinstance(scope["scope"], str) and scope["scope"], "nonce provider scope must be named")
        require(isinstance(scope["required"], bool), "nonce provider requirement must be boolean")
        require(scope["condition"] is None or isinstance(scope["condition"], str), "nonce condition must be nullable text")
        require(isinstance(scope["exposed"], bool), "nonce exposure flag must be boolean")

    by_provider = {scope["provider"]: scope for scope in scopes}
    require(set(by_provider) == {"pinned Nous", "reviewed OIDC provider"}, "nonce provider scopes changed")
    nous = by_provider["pinned Nous"]
    require(nous == {
        "provider": "pinned Nous",
        "scope": "pinned Nous browser OAuth flow only",
        "required": False,
        "condition": None,
        "exposed": False,
    }, "pinned Nous nonce policy changed")
    oidc = by_provider["reviewed OIDC provider"]
    require(oidc == {
        "provider": "reviewed OIDC provider",
        "scope": "reviewed OIDC compatibility record",
        "required": True,
        "condition": "only when compatibility record says so",
        "exposed": True,
    }, "reviewed OIDC nonce policy changed")


def validate_failure_semantics(audit: dict[str, Any], excerpts: dict[str, str]) -> None:
    require(type(audit) is dict, "audit must be an object")
    require(type(excerpts) is dict, "source excerpts must be an object")
    require(all(type(text) is str for text in excerpts.values()), "source excerpts must be text")
    semantics = require_exact_keys(audit.get("failure_semantics"), FAILURE_SEMANTICS_KEYS, "failure_semantics")
    for key, expected in EXPECTED_FAILURE_SEMANTICS.items():
        entry = require_exact_keys(semantics[key], FAILURE_ENTRY_KEYS, f"failure_semantics.{key}")
        require(entry["outcome"] == expected["outcome"], f"failure outcome changed: {key}")
        require(entry["source_ref"] == expected["source_ref"], f"failure source changed: {key}")
        require(isinstance(entry["markers"], list), f"failure markers must be a list: {key}")
        require(tuple(entry["markers"]) == expected["markers"], f"failure markers changed: {key}")
        if expected["source_ref"] is None:
            require(not entry["markers"], f"unbound failure markers: {key}")
        else:
            require(expected["source_ref"] == "hermes_cli/dashboard_auth/routes.py", f"unexpected failure source: {key}")
            require("routes" in excerpts, "route source excerpt is missing")
            assert_markers_in_order(excerpts["routes"], expected["markers"], f"failure_semantics.{key}")


def validate_audit_root(audit: dict[str, Any], excerpts: dict[str, str]) -> None:
    validate_no_live_secrets(audit)
    require_exact_keys(audit, AUDIT_ROOT_KEYS, "source_audit root")
    require(audit["fixture_id"] == "oauth-browser-source-audit-199", "audit fixture ID changed")
    require(audit["contract"] == "dashboard-v0.0.1", "audit contract changed")
    require(audit["flow"] == "browser-oauth", "audit flow changed")
    require(audit["synthetic_only"] is True, "audit must remain synthetic")
    require(audit["network_access"] is False, "audit network access must remain disabled")
    require(audit["apple_behavior"] is False, "audit Apple behavior must remain disabled")
    require(audit["superdesign_output"] is False, "audit must not include superdesign output")

    requirements = require_exact_keys(audit["requirements"], REQUIREMENTS_KEYS, "requirements")
    require(requirements["scope"] == "pinned Nous browser OAuth flow only", "requirements scope changed")
    state = require_exact_keys(requirements["state"], STATE_REQUIREMENT_KEYS, "requirements.state")
    require(state["required"] is True, "state requirement disabled")
    require(
        state["comparison"] == "callback state must equal the state stored in the server-managed PKCE cookie",
        "state comparison changed",
    )
    pkce = require_exact_keys(requirements["pkce"], PKCE_REQUIREMENT_KEYS, "requirements.pkce")
    require(pkce["required"] is True, "PKCE requirement disabled")
    require(pkce["applies_to"] == "reviewed OAuth or OIDC browser providers only", "PKCE scope changed")
    require(pkce["method"] == "S256", "PKCE method changed")
    require(
        pkce["comparison"] == "the provider exchange receives the verifier paired with the authorization request challenge",
        "PKCE comparison changed",
    )
    validate_nonce_policy(requirements)
    password = require_exact_keys(requirements["password_provider"], PASSWORD_REQUIREMENT_KEYS, "requirements.password_provider")
    require(password["supports_password"] is True, "password capability changed")
    require(password["oauth_state_required"] is False, "password provider inherited OAuth state")
    require(password["pkce_required"] is False, "password provider inherited PKCE")
    require(password["reason"] == "auth_login returns before provider.start_login for a password provider", "password branch reason changed")

    validate_source_observations(audit, excerpts)
    validate_failure_semantics(audit, excerpts)
    redaction = require_exact_keys(audit["redaction"], REDACTION_KEYS, "redaction")
    require(all(isinstance(value, bool) for value in redaction.values()), "redaction flags must be boolean")
    require(redaction["synthetic_cookie_shaped_values"] is True, "synthetic cookie evidence disabled")
    require(redaction["public_source_urls"] is True, "public source evidence disabled")
    for key in ("live_secrets", "live_cookie_contents", "live_host_data", "transcripts", "user_data"):
        require(redaction[key] is False, f"redaction boundary changed: {key}")


def validate_cases_root(cases: dict[str, Any]) -> None:
    validate_no_live_secrets(cases)
    require_exact_keys(cases, CASES_ROOT_KEYS, "cases root")
    require(cases["fixture_id"] == "oauth-browser-source-audit-199", "case fixture ID changed")
    require(cases["source_sha"] == PINNED_SHA, "case source commit changed")
    require(cases["contract"] == "dashboard-v0.0.1", "case contract changed")
    require(cases["provider"] == "synthetic-oauth", "case provider changed")
    require(cases["provider_mode"] == "reviewed_oauth_browser", "case provider mode changed")
    require(
        cases["provider_error_observation"] == PROVIDER_HTTP_400_OBSERVATION,
        "case provider error observation changed",
    )
    require(cases["synthetic_only"] is True, "cases must remain synthetic")
    require(type(cases["cases"]) is list, "cases must be a list")
    require(all(type(case) is dict for case in cases["cases"]), "fixture case must be an object")
    ids = [case.get("id") for case in cases["cases"]]
    require(all(type(case_id) is str for case_id in ids), "case IDs must be strings")
    require(set(ids) == REQUIRED_CASES, "case ID set changed")
    require(len(ids) == len(set(ids)), "duplicate case ID")
    for case in cases["cases"]:
        validate_synthetic_case_values(case)
        validate_oauth_case(case)


def require_synthetic(value: Any, pattern: re.Pattern[str], label: str) -> None:
    require(isinstance(value, str), f"{label} must be a string")
    require(pattern.fullmatch(value) is not None, f"{label} is not synthetic: {value!r}")


def validate_synthetic_case_values(case: dict[str, Any]) -> None:
    """Validate every fixture value before applying cross-field behavior rules."""
    require(type(case) is dict, "fixture case must be an object")
    case_id = case.get("id")
    require(type(case_id) is str, "case ID must be a string")
    require(
        set(case) == {"id", "request", "provider_exchange", "expected"},
        f"case shape changed: {case_id!r}",
    )
    require(re.fullmatch(r"[a-z0-9-]+", case_id) is not None, "case ID is not synthetic")

    request = case.get("request")
    require(type(request) is dict, "request must be an object")
    require(set(request) == {"pkce_cookie", "authorization_request", "callback"}, "request shape changed")

    cookie = request.get("pkce_cookie")
    require(type(cookie) is dict, "PKCE cookie must be an object")
    require(set(cookie) == {"provider", "state", "verifier"}, "PKCE cookie shape changed")
    require_synthetic(cookie.get("provider"), SYNTHETIC_IDENTIFIER, "pkce_cookie.provider")
    require_synthetic(cookie.get("state"), SYNTHETIC_STATE, "pkce_cookie.state")
    require_synthetic(cookie.get("verifier"), SYNTHETIC_VERIFIER, "pkce_cookie.verifier")

    authorization = request.get("authorization_request")
    require(type(authorization) is dict, "authorization request must be an object")
    require(set(authorization) == {"params"}, "authorization request shape changed")
    params = authorization.get("params")
    require(type(params) is dict, "authorization params must be an object")
    expected_params = {
        "response_type",
        "client_id",
        "redirect_uri",
        "scope",
        "state",
        "code_challenge",
        "code_challenge_method",
    }
    require(set(params) == expected_params, "authorization parameter set changed")
    require(params.get("response_type") == "code", "response_type changed")
    require_synthetic(params.get("client_id"), SYNTHETIC_CLIENT_ID, "authorization.params.client_id")
    require_synthetic(params.get("redirect_uri"), SYNTHETIC_REDIRECT_URI, "authorization.params.redirect_uri")
    require_synthetic(params.get("scope"), SYNTHETIC_SCOPE, "authorization.params.scope")
    require_synthetic(params.get("state"), SYNTHETIC_STATE, "authorization.params.state")
    require_synthetic(params.get("code_challenge"), CODE_CHALLENGE, "authorization.params.code_challenge")
    require(params.get("code_challenge_method") == "S256", "code_challenge_method changed")

    callback = request.get("callback")
    require(type(callback) is dict, "callback must be an object")
    expected_callback_keys = {"code", "state"}
    if case_id == "cancellation":
        expected_callback_keys |= {"error", "error_description"}
    require(set(callback) == expected_callback_keys, f"callback fields changed: {case_id}")
    callback_code = callback.get("code")
    callback_state = callback.get("state")
    require(type(callback_code) is str, "callback.code must be a string")
    require(type(callback_state) is str, "callback.state must be a string")
    require(callback_code == "" or SYNTHETIC_CODE.fullmatch(callback_code) is not None, "callback.code is not synthetic")
    require(callback_state == "" or SYNTHETIC_STATE.fullmatch(callback_state) is not None, "callback.state is not synthetic")
    if "error" in callback:
        require(callback.get("error") == "access_denied", "callback.error is not an allowed protocol value")
        require("error_description" in callback, "provider error description is required")
    if "error_description" in callback:
        require_synthetic(callback.get("error_description"), SYNTHETIC_DESCRIPTION, "callback.error_description")

    exchange = require_exact_keys(case.get("provider_exchange"), {"called", "code_verifier", "verifier_result"}, "provider_exchange")
    require(type(exchange["called"]) is bool, "provider_exchange.called must be boolean")
    code_verifier = exchange["code_verifier"]
    require(code_verifier is None or type(code_verifier) is str, "provider_exchange.code_verifier must be nullable text")
    require(
        code_verifier is None or SYNTHETIC_VERIFIER.fullmatch(code_verifier) is not None,
        "provider_exchange.code_verifier is not synthetic",
    )
    verifier_result = exchange["verifier_result"]
    require(type(verifier_result) is str, "provider_exchange.verifier_result must be a string")
    require(
        verifier_result in {"accepted", "rejected", "rejected_empty_code", "not_attempted"},
        "provider_exchange.verifier_result changed",
    )

    expected = require_exact_keys(
        case.get("expected"),
        {"status", "reason", "session_cookie_issued", "pkce_cookie", "separate_nonce_required"},
        "expected",
    )
    status = expected["status"]
    require(type(status) is int and status in {302, 400}, "expected status changed")
    reason = expected["reason"]
    require(type(reason) is str, "expected reason must be a string")
    require(reason in {"login_success", "state_mismatch", "invalid_code_or_pkce", "idp_error"}, "expected reason changed")
    require(type(expected["session_cookie_issued"]) is bool, "expected session flag must be boolean")
    expected_pkce_cookie = expected["pkce_cookie"]
    require(type(expected_pkce_cookie) is str, "expected PKCE cookie state must be a string")
    require(expected_pkce_cookie in {"cleared", "retained_until_ttl"}, "expected PKCE cookie state changed")
    require(type(expected["separate_nonce_required"]) is bool, "expected nonce flag must be boolean")

    matrix = EXPECTED_OUTCOME_MATRIX.get(case_id)
    require(matrix is not None, f"case is not in expected outcome matrix: {case_id}")
    require(expected == matrix["expected"], f"expected outcome changed: {case_id}")
    expected_exchange = dict(matrix["provider_exchange"])
    if expected_exchange["code_verifier"] == "cookie":
        expected_exchange["code_verifier"] = cookie["verifier"]
    require(exchange == expected_exchange, f"expected provider exchange changed: {case_id}")


def validate_oauth_case(case: dict[str, Any]) -> None:
    validate_synthetic_case_values(case)
    request = case["request"]
    cookie = request["pkce_cookie"]
    params = request["authorization_request"]["params"]
    callback = request["callback"]
    exchange = case["provider_exchange"]

    require("nonce" not in params, f"pinned Nous flow unexpectedly gained nonce: {case['id']}")
    require(params["state"] == cookie["state"], f"outbound state mismatch: {case['id']}")
    require(pkce_challenge(cookie["verifier"]) == params["code_challenge"], f"PKCE challenge mismatch: {case['id']}")
    require(case["expected"]["separate_nonce_required"] is False, f"nonce requirement changed: {case['id']}")

    if exchange["called"]:
        require(exchange["code_verifier"] == cookie["verifier"], f"provider verifier mismatch: {case['id']}")
    else:
        require(exchange["code_verifier"] is None, f"unexpected verifier on skipped exchange: {case['id']}")

    if callback.get("error") or callback["state"] != cookie["state"]:
        require(not exchange["called"], f"exchange was attempted after callback rejection: {case['id']}")


def assert_nonce_policy_is_scoped(documentation: str) -> None:
    """Reject every positive global nonce rule while allowing reviewed scopes."""
    clauses = re.split(r"[.!?;\n]+", documentation)
    for clause in clauses:
        if not re.search(r"\bnonce\b", clause, re.IGNORECASE):
            continue
        if NONCE_POSITIVE.search(clause) is None:
            continue
        if NONCE_PROHIBITION.search(clause):
            continue
        require(NONCE_GLOBAL.search(clause) is None, f"global nonce requirement: {clause.strip()!r}")
        require(
            NONCE_SCOPE.search(clause) is not None,
            f"unscoped positive nonce requirement: {clause.strip()!r}",
        )


class BrowserOAuthContractTests(unittest.TestCase):
    audit_path = SOURCE_AUDIT_PATH
    cases_path = CASES_PATH

    @classmethod
    def setUpClass(cls) -> None:
        cls.audit = load_json(cls.audit_path)
        cls.cases = load_json(cls.cases_path)
        cls.documentation = DOC_PATH.read_text(encoding="utf-8")
        cls.excerpts = load_source_excerpts()

    def _run_cli(
        self,
        fixture_path: Path,
        *,
        optimized: bool,
        option: str = "--cases",
    ) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend([str(Path(__file__)), option, str(fixture_path)])
        return subprocess.run(command, capture_output=True, text=True, check=False)

    def _assert_cli_parser_failure(
        self,
        payload: str,
        expected_message: str,
        *,
        option: str = "--cases",
    ) -> None:
        for optimized in (False, True):
            with self.subTest(optimized=optimized, message=expected_message):
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as stream:
                    stream.write(payload)
                    stream.flush()
                    result = self._run_cli(
                        Path(stream.name),
                        optimized=optimized,
                        option=option,
                    )
                self.assertEqual(result.returncode, 2, (optimized, result.stdout, result.stderr))
                self.assertNotIn("Traceback", result.stdout + result.stderr)
                self.assertLessEqual(len(result.stderr.rstrip("\n")), MAX_ERROR_OUTPUT)
                for pattern in SECRET_VALUE_PATTERNS:
                    self.assertIsNone(pattern.search(result.stderr), result.stderr)
                self.assertIn("validation error", result.stderr.lower())
                self.assertIn(expected_message, result.stderr)

    def test_source_pin_and_audit_shape(self) -> None:
        validate_audit_root(self.audit, self.excerpts)
        validate_cases_root(self.cases)
        validate_no_live_secrets(self.audit)
        validate_no_live_secrets(self.cases)
        validate_no_live_secrets(self.excerpts, scan_assignments=False)

    def test_strict_loader_rejects_duplicate_nonfinite_deep_and_malformed_json(self) -> None:
        for digits in (1000, MAX_JSON_INTEGER_DIGITS):
            with self.subTest(accepted_integer_digits=digits):
                payload = f'{{"value":{"7" * digits}}}'
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as stream:
                    stream.write(payload)
                    stream.flush()
                    parsed = load_json(Path(stream.name))
                self.assertEqual(len(str(parsed["value"])), digits)

        deep_document: dict[str, Any] = {}
        cursor = deep_document
        for _ in range(MAX_JSON_DEPTH + 1):
            child: dict[str, Any] = {}
            cursor["nested"] = child
            cursor = child
        payloads = (
            ('{"scope":"ghp_live_hidden_secret","scope":"safe_fixture_scope"}', DUPLICATE_JSON_KEY_ERROR),
            ('{"outer":{"scope":"ghp_live_nested_secret","scope":"safe_fixture_scope"}}', DUPLICATE_JSON_KEY_ERROR),
            ('{"value":NaN}', "non-finite JSON number"),
            ('{"value":Infinity}', "non-finite JSON number"),
            ('{"value":-Infinity}', "non-finite JSON number"),
            ('{"value":1e9999}', "non-finite JSON number"),
            (f'{{"value":{"7" * (MAX_JSON_INTEGER_DIGITS + 1)}}}', INTEGER_DIGIT_LIMIT_ERROR),
            (json.dumps(deep_document), "maximum JSON nesting depth"),
            ('{"cases":[}', "invalid JSON input"),
        )
        for payload, expected_message in payloads:
            with self.subTest(expected_message=expected_message):
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as stream:
                    stream.write(payload)
                    stream.flush()
                    with self.assertRaises(FixtureJSONError) as raised:
                        load_json(Path(stream.name))
                self.assertIn(expected_message, str(raised.exception))

        huge_key = "ghp_live_" + ("x" * 100_000)
        huge_duplicate = f"{{{json.dumps(huge_key)}:1,{json.dumps(huge_key)}:2}}"
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as stream:
            stream.write(huge_duplicate)
            stream.flush()
            with self.assertRaises(FixtureJSONError) as raised:
                load_json(Path(stream.name))
        error = str(raised.exception)
        self.assertIn(DUPLICATE_JSON_KEY_ERROR, error)
        self.assertLessEqual(len(error), MAX_ERROR_OUTPUT)
        self.assertNotIn(huge_key, error)
        self.assertNotIn("ghp_live_", error)

    def test_exact_type_confusion_is_rejected_by_closed_schema(self) -> None:
        for status in (True, 302.0, 400.0):
            with self.subTest(status=status):
                forged = copy.deepcopy(self.cases)
                forged["cases"][0]["expected"]["status"] = status
                with self.assertRaises(AssertionError):
                    validate_cases_root(forged)
                if status in (True, 400.0):
                    provider_forged = copy.deepcopy(self.cases)
                    provider_case = next(case for case in provider_forged["cases"] if case["id"] == "pkce-failure")
                    provider_case["expected"]["status"] = status
                    with self.assertRaises(AssertionError):
                        validate_provider_http_400_case_bindings(self.audit, provider_forged, self.excerpts)

    def test_temp_fixture_failures_are_controlled_in_normal_and_optimized_cli(self) -> None:
        cases_text = CASES_PATH.read_text(encoding="utf-8")
        duplicate_secret = cases_text.replace(
            '"scope": "fixture-scope",',
            '"scope": "ghp_live_hidden_secret",\n            "scope": "fixture-scope",',
            1,
        )
        self.assertNotEqual(duplicate_secret, cases_text)
        self._assert_cli_parser_failure(duplicate_secret, DUPLICATE_JSON_KEY_ERROR)
        self._assert_cli_parser_failure(
            '{"scope":"ghp_live_audit_secret","scope":"safe_fixture_scope"}',
            DUPLICATE_JSON_KEY_ERROR,
            option="--audit",
        )
        self._assert_cli_parser_failure(
            '{"outer":{"scope":"ghp_live_nested_secret","scope":"safe_fixture_scope"}}',
            DUPLICATE_JSON_KEY_ERROR,
        )
        huge_key = "ghp_live_" + ("x" * 100_000)
        huge_duplicate = f"{{{json.dumps(huge_key)}:1,{json.dumps(huge_key)}:2}}"
        self._assert_cli_parser_failure(huge_duplicate, DUPLICATE_JSON_KEY_ERROR)
        self._assert_cli_parser_failure('{"value":NaN}', "non-finite JSON number")
        self._assert_cli_parser_failure('{"value":Infinity}', "non-finite JSON number")
        self._assert_cli_parser_failure('{"value":-Infinity}', "non-finite JSON number")
        self._assert_cli_parser_failure('{"value":1e9999}', "non-finite JSON number")
        oversized_integer = f'{{"value":{"7" * (MAX_JSON_INTEGER_DIGITS + 1)}}}'
        self._assert_cli_parser_failure(oversized_integer, INTEGER_DIGIT_LIMIT_ERROR)

        deep_document: dict[str, Any] = {}
        cursor = deep_document
        for _ in range(MAX_JSON_DEPTH + 1):
            child: dict[str, Any] = {}
            cursor["nested"] = child
            cursor = child
        self._assert_cli_parser_failure(json.dumps(deep_document), "maximum JSON nesting depth")
        self._assert_cli_parser_failure('{"cases":[}', "invalid JSON input")

        case_mutations = (
            ("case-null", lambda forged: forged["cases"].__setitem__(0, None), "fixture case must be an object"),
            ("case-id-list", lambda forged: forged["cases"][0].__setitem__("id", []), "case IDs must be strings"),
            ("request-null", lambda forged: forged["cases"][0].__setitem__("request", None), "request must be an object"),
            ("cookie-null", lambda forged: forged["cases"][0]["request"].__setitem__("pkce_cookie", None), "PKCE cookie must be an object"),
            ("authorization-null", lambda forged: forged["cases"][0]["request"].__setitem__("authorization_request", None), "authorization request must be an object"),
            ("params-null", lambda forged: forged["cases"][0]["request"]["authorization_request"].__setitem__("params", None), "authorization params must be an object"),
            ("callback-null", lambda forged: forged["cases"][0]["request"].__setitem__("callback", None), "callback must be an object"),
            ("exchange-null", lambda forged: forged["cases"][0].__setitem__("provider_exchange", None), "provider_exchange must be an object"),
            ("verifier-list", lambda forged: forged["cases"][0]["provider_exchange"].__setitem__("code_verifier", []), "provider_exchange.code_verifier must be nullable text"),
            ("expected-null", lambda forged: forged["cases"][0].__setitem__("expected", None), "expected must be an object"),
            ("status-float", lambda forged: forged["cases"][0]["expected"].__setitem__("status", 302.0), "expected status changed"),
            ("reason-list", lambda forged: forged["cases"][0]["expected"].__setitem__("reason", []), "expected reason must be a string"),
        )
        for label, mutate, expected_message in case_mutations:
            with self.subTest(schema_case=label):
                forged = copy.deepcopy(self.cases)
                mutate(forged)
                payload = json.dumps(forged)
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as stream:
                    stream.write(payload)
                    stream.flush()
                    with self.assertRaises(FixtureJSONError) as raised:
                        validate_fixture_documents(SOURCE_AUDIT_PATH, Path(stream.name))
                self.assertIn(expected_message, str(raised.exception))
                self._assert_cli_parser_failure(payload, expected_message)

        audit_mutations = (
            ("source-null", lambda forged: forged.__setitem__("source", None), "source provenance must be an object"),
            ("source-path-list", lambda forged: forged["source"]["refs"][0].__setitem__("path", []), "source ref paths must be strings"),
            ("observations-null", lambda forged: forged["source"]["refs"][0].__setitem__("observations", None), "observations must be an object"),
            ("nonce-null", lambda forged: forged["requirements"].__setitem__("nonce", None), "requirements.nonce must be an object"),
            ("failure-null", lambda forged: forged.__setitem__("failure_semantics", None), "failure_semantics must be an object"),
        )
        for label, mutate, expected_message in audit_mutations:
            with self.subTest(schema_audit=label):
                forged = copy.deepcopy(self.audit)
                mutate(forged)
                payload = json.dumps(forged)
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as stream:
                    stream.write(payload)
                    stream.flush()
                    with self.assertRaises(FixtureJSONError) as raised:
                        validate_fixture_documents(Path(stream.name), CASES_PATH)
                self.assertIn(expected_message, str(raised.exception))
                self._assert_cli_parser_failure(payload, expected_message, option="--audit")

    def test_root_and_nested_schema_mutations_are_rejected(self) -> None:
        extra_case_root = copy.deepcopy(self.cases)
        extra_case_root["unexpected"] = {"nested": True}
        with self.assertRaises(AssertionError):
            validate_cases_root(extra_case_root)

        extra_audit_root = copy.deepcopy(self.audit)
        extra_audit_root["unexpected"] = []
        with self.assertRaises(AssertionError):
            validate_audit_root(extra_audit_root, self.excerpts)

        extra_nonce_scope = copy.deepcopy(self.audit)
        extra_nonce_scope["requirements"]["nonce"]["provider_scopes"][0]["unexpected"] = False
        with self.assertRaises(AssertionError):
            validate_audit_root(extra_nonce_scope, self.excerpts)

        extra_failure_field = copy.deepcopy(self.audit)
        extra_failure_field["failure_semantics"]["provider_unreachable"]["unexpected"] = "x"
        with self.assertRaises(AssertionError):
            validate_audit_root(extra_failure_field, self.excerpts)

    def test_source_refs_are_exact_unique_and_pinned(self) -> None:
        validate_source_refs(self.audit)

    def test_source_ref_mutations_are_rejected(self) -> None:
        duplicate = copy.deepcopy(self.audit)
        duplicate["source"]["refs"][1]["path"] = duplicate["source"]["refs"][0]["path"]
        with self.assertRaises(AssertionError):
            validate_source_refs(duplicate)

        wrong_excerpt = copy.deepcopy(self.audit)
        wrong_excerpt["source"]["refs"][0]["excerpt"] = "source_excerpts/nous_provider.py.txt"
        with self.assertRaises(AssertionError):
            validate_source_refs(wrong_excerpt)

        wrong_blob = copy.deepcopy(self.audit)
        wrong_blob["source"]["refs"][0]["blob_sha"] = "0" * 40
        with self.assertRaises(AssertionError):
            validate_source_refs(wrong_blob)

        wrong_url_path = copy.deepcopy(self.audit)
        wrong_url_path["source"]["refs"][0]["url"] = wrong_url_path["source"]["refs"][0]["url"].replace(
            "hermes_cli/dashboard_auth/routes.py", "hermes_cli/dashboard_auth/cookies.py"
        )
        with self.assertRaises(AssertionError):
            validate_source_refs(wrong_url_path)

    def test_source_url_mutations_are_rejected(self) -> None:
        for mutation in (
            lambda url: url + "?download=1",
            lambda url: url.replace("https://github.com", "https://attacker@github.com"),
            lambda url: url.replace(PINNED_SHA, "0" * 40),
        ):
            mutated = copy.deepcopy(self.audit)
            mutated["source"]["refs"][0]["url"] = mutation(mutated["source"]["refs"][0]["url"])
            with self.assertRaises(AssertionError):
                validate_source_refs(mutated)

        # Keep the expected string aligned only to exercise URL parsing itself;
        # the parser must still reject a query or userinfo-bearing URL.
        for mutation in (
            lambda url: url + "?download=1",
            lambda url: url.replace("https://github.com", "https://attacker@github.com"),
        ):
            expected = dict(EXPECTED_SOURCE_REFS[0])
            mutated_url = mutation(expected["url"])
            expected["url"] = mutated_url
            with self.assertRaises(AssertionError):
                validate_source_url(mutated_url, expected)

    def test_source_observations_are_backed_by_immutable_excerpts(self) -> None:
        validate_source_observations(self.audit, self.excerpts)

    def test_provider_http_400_observation_binds_pkce_and_empty_code_cases(self) -> None:
        validate_provider_http_400_case_bindings(self.audit, self.cases, self.excerpts)

        mutated_audit = copy.deepcopy(self.audit)
        mutated_audit["source"]["refs"][1]["observations"][PROVIDER_HTTP_400_OBSERVATION] = False
        with self.assertRaises(AssertionError):
            validate_provider_http_400_case_bindings(mutated_audit, self.cases, self.excerpts)

        mutated_cases = copy.deepcopy(self.cases)
        mutated_cases["provider_error_observation"] = "unbound-provider-observation"
        with self.assertRaises(AssertionError):
            validate_provider_http_400_case_bindings(self.audit, mutated_cases, self.excerpts)

    def test_false_source_observation_mutation_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.audit)
        mutated["source"]["refs"][0]["observations"][
            "password_provider_short_circuits_oauth_start"
        ] = False
        with self.assertRaises(AssertionError):
            validate_source_observations(mutated, self.excerpts)

    def test_source_excerpt_mutation_is_rejected(self) -> None:
        mutated = dict(self.excerpts)
        mutated["nous"] = mutated["nous"].replace(
            '"code_verifier": code_verifier,', '"wrong_verifier": code_verifier,'
        )
        with self.assertRaises(AssertionError):
            validate_source_observations(self.audit, mutated)

    def test_state_pkce_and_nonce_requirements_match_source(self) -> None:
        requirements = self.audit["requirements"]
        self.assertEqual(requirements["scope"], "pinned Nous browser OAuth flow only")
        self.assertTrue(requirements["state"]["required"])
        self.assertTrue(requirements["pkce"]["required"])
        self.assertEqual(requirements["pkce"]["method"], "S256")
        self.assertEqual(requirements["pkce"]["applies_to"], "reviewed OAuth or OIDC browser providers only")
        validate_nonce_policy(requirements)
        scopes = {scope["provider"]: scope for scope in requirements["nonce"]["provider_scopes"]}
        self.assertFalse(scopes["pinned Nous"]["required"])
        self.assertFalse(scopes["pinned Nous"]["exposed"])
        self.assertTrue(scopes["reviewed OIDC provider"]["required"])
        self.assertTrue(scopes["reviewed OIDC provider"]["exposed"])
        self.assertEqual(scopes["reviewed OIDC provider"]["condition"], "only when compatibility record says so")

    def test_nonce_policy_rejects_unscoped_global_mutations_and_allows_reviewed_scope(self) -> None:
        unscoped = copy.deepcopy(self.audit)
        unscoped["requirements"]["nonce"]["global_requirement"]["required"] = True
        with self.assertRaises(AssertionError):
            validate_nonce_policy(unscoped["requirements"])

        unscoped_scope = copy.deepcopy(self.audit)
        unscoped_scope["requirements"]["nonce"]["global_requirement"]["scope"] = "all providers"
        with self.assertRaises(AssertionError):
            validate_nonce_policy(unscoped_scope["requirements"])

        reviewed = copy.deepcopy(self.audit)
        validate_nonce_policy(reviewed["requirements"])

        # The structured record is exact, but the prose guard still allows a
        # provider-scoped OIDC requirement when its compatibility record names it.
        assert_nonce_policy_is_scoped(
            "A reviewed OIDC provider MUST require and validate a nonce only when its compatibility record says so."
        )

    def test_failure_semantics_are_exactly_pinned_to_route_markers(self) -> None:
        validate_failure_semantics(self.audit, self.excerpts)
        for key in EXPECTED_FAILURE_SEMANTICS:
            mutated = copy.deepcopy(self.audit)
            markers = mutated["failure_semantics"][key]["markers"]
            if markers:
                markers[0] = markers[0] + " mutated"
            else:
                mutated["failure_semantics"][key]["outcome"] += " mutated"
            with self.assertRaises(AssertionError, msg=key):
                validate_failure_semantics(mutated, self.excerpts)

    def test_password_provider_does_not_inherit_oauth_pkce(self) -> None:
        password = self.audit["requirements"]["password_provider"]
        self.assertTrue(password["supports_password"])
        self.assertFalse(password["oauth_state_required"])
        self.assertFalse(password["pkce_required"])
        self.assertIn("before provider.start_login", password["reason"])

    def test_required_cases_are_present_once(self) -> None:
        cases = self.cases["cases"]
        ids = [case["id"] for case in cases]
        self.assertEqual(set(ids), REQUIRED_CASES)
        self.assertEqual(len(ids), len(set(ids)))

    def test_source_compatible_cases_validate_from_nested_inputs(self) -> None:
        validate_cases_root(self.cases)

    def test_expected_outcome_matrix_rejects_case_mutations(self) -> None:
        for case_id in REQUIRED_CASES:
            mutated = copy.deepcopy(self._case(case_id))
            mutated["expected"]["status"] = 999
            with self.assertRaises(AssertionError, msg=case_id):
                validate_oauth_case(mutated)

        exchange_mutation = copy.deepcopy(self._case("cancellation"))
        exchange_mutation["provider_exchange"]["called"] = True
        with self.assertRaises(AssertionError):
            validate_oauth_case(exchange_mutation)

    def test_synthetic_value_schema_rejects_live_credential_shapes(self) -> None:
        mutations = (
            ("request", "pkce_cookie", "verifier"),
            ("request", "authorization_request", "params", "client_id"),
            ("request", "callback", "code"),
            ("provider_exchange", "code_verifier"),
        )
        for path in mutations:
            mutated = copy.deepcopy(self._case("success"))
            if path[-1] == "code" and path[1] == "callback":
                parent = mutated["request"]["callback"]
                parent["code"] = "ghp_live_fixture_not_a_code"
            elif path[-1] == "client_id":
                mutated["request"]["authorization_request"]["params"]["client_id"] = "ghp_live_fixture_client"
            elif path[-1] == "verifier" and path[1] == "pkce_cookie":
                mutated["request"]["pkce_cookie"]["verifier"] = "ghp_live_fixture_verifier"
            else:
                mutated["provider_exchange"]["code_verifier"] = "ghp_live_fixture_verifier"
            with self.assertRaises(AssertionError, msg=str(path)):
                validate_oauth_case(mutated)

    def test_pkce_challenge_and_state_inputs_are_deterministic(self) -> None:
        for case in self.cases["cases"]:
            request = case["request"]
            cookie = request["pkce_cookie"]
            params = request["authorization_request"]["params"]
            callback = request["callback"]

            self.assertEqual(params["code_challenge_method"], "S256")
            self.assertEqual(pkce_challenge(cookie["verifier"]), params["code_challenge"], case["id"])
            self.assertEqual(params["state"], cookie["state"], case["id"])
            self.assertNotIn("nonce", params)
            self.assertNotIn("nonce", callback)
            self.assertFalse(case["expected"]["separate_nonce_required"])

    def test_outbound_state_and_exchange_verifier_mutations_are_rejected(self) -> None:
        wrong_state = copy.deepcopy(self._case("success"))
        wrong_state["request"]["authorization_request"]["params"]["state"] = "fixture-wrong-state"
        with self.assertRaises(AssertionError):
            validate_oauth_case(wrong_state)

        wrong_verifier = copy.deepcopy(self._case("success"))
        wrong_verifier["provider_exchange"]["code_verifier"] = "fixture-wrong-verifier"
        with self.assertRaises(AssertionError):
            validate_oauth_case(wrong_verifier)

    def test_nested_nonce_mutation_is_rejected(self) -> None:
        mutated = copy.deepcopy(self._case("success"))
        mutated["request"]["authorization_request"]["params"]["nonce"] = "fixture-nonce"
        with self.assertRaises(AssertionError):
            validate_oauth_case(mutated)

    def test_success_requires_matching_state_and_verifier(self) -> None:
        case = self._case("success")
        request = case["request"]
        self.assertEqual(request["pkce_cookie"]["state"], request["callback"]["state"])
        self.assertEqual(case["provider_exchange"]["code_verifier"], request["pkce_cookie"]["verifier"])
        self.assertTrue(case["provider_exchange"]["called"])
        self.assertEqual(case["provider_exchange"]["verifier_result"], "accepted")
        self.assertEqual(case["expected"]["status"], 302)
        self.assertTrue(case["expected"]["session_cookie_issued"])
        self.assertEqual(case["expected"]["pkce_cookie"], "cleared")

    def test_state_failures_happen_before_provider_exchange(self) -> None:
        for case_id in ("state-mismatch", "missing-state"):
            case = self._case(case_id)
            request = case["request"]
            self.assertNotEqual(request["pkce_cookie"]["state"], request["callback"]["state"])
            self.assertFalse(case["provider_exchange"]["called"], case_id)
            self.assertIsNone(case["provider_exchange"]["code_verifier"], case_id)
            self.assertEqual(case["expected"]["status"], 400)
            self.assertFalse(case["expected"]["session_cookie_issued"])
            self.assertEqual(case["expected"]["reason"], "state_mismatch")

    def test_cancellation_and_malformed_callbacks_fail_closed(self) -> None:
        cancellation = self._case("cancellation")
        self.assertEqual(cancellation["request"]["callback"]["error"], "access_denied")
        self.assertFalse(cancellation["provider_exchange"]["called"])
        self.assertIsNone(cancellation["provider_exchange"]["code_verifier"])
        self.assertEqual(cancellation["expected"]["reason"], "idp_error")
        self.assertFalse(cancellation["expected"]["session_cookie_issued"])

        malformed = self._case("malformed-callback")
        self.assertEqual(malformed["request"]["callback"]["code"], "")
        self.assertTrue(malformed["provider_exchange"]["called"])
        self.assertEqual(malformed["provider_exchange"]["code_verifier"], malformed["request"]["pkce_cookie"]["verifier"])
        self.assertEqual(malformed["provider_exchange"]["verifier_result"], "rejected_empty_code")
        self.assertEqual(malformed["expected"]["status"], 400)
        self.assertFalse(malformed["expected"]["session_cookie_issued"])

    def test_pkce_failure_does_not_create_a_session(self) -> None:
        case = self._case("pkce-failure")
        self.assertTrue(case["provider_exchange"]["called"])
        self.assertEqual(case["provider_exchange"]["code_verifier"], case["request"]["pkce_cookie"]["verifier"])
        self.assertEqual(case["provider_exchange"]["verifier_result"], "rejected")
        self.assertEqual(case["expected"]["reason"], "invalid_code_or_pkce")
        self.assertEqual(case["expected"]["status"], 400)
        self.assertFalse(case["expected"]["session_cookie_issued"])

    def test_documentation_scopes_nonce_and_pkce_claims(self) -> None:
        documentation = self.documentation
        self.assertIn("PKCE is conditional on the reviewed provider mode", documentation)
        self.assertIn("does not enter the OAuth state or PKCE exchange", documentation)
        self.assertIn("pinned Nous OAuth browser flow", documentation)
        self.assertIn("provider-specific OIDC `nonce` requirement", documentation)
        self.assertIn("No separate OAuth/OIDC `nonce` is exposed or required by this pinned Nous flow", documentation)
        self.assertIn("Hermternal MUST NOT add nonce validation", documentation)
        self.assertNotIn("validate the authentication state and nonce", documentation)
        self.assertNotIn("browser OAuth or OIDC state, nonce", documentation)
        assert_nonce_policy_is_scoped(documentation)

    def test_unscoped_global_nonce_mutation_is_rejected(self) -> None:
        for sentence in (
            "The client MUST enforce a nonce for every provider.",
            "The client MUST require a nonce for every provider.",
            "Nonce is required for all providers.",
            "Every OAuth provider MUST include a nonce.",
            "A nonce MUST be present for each callback.",
            "All browser flows require a nonce.",
            "Nonce is required globally.",
            "The nonce requirement applies universally.",
        ):
            mutated = self.documentation + "\n" + sentence + "\n"
            with self.assertRaises(AssertionError):
                assert_nonce_policy_is_scoped(mutated)

    def test_reviewed_provider_nonce_mutation_is_allowed(self) -> None:
        for sentence in (
            "A reviewed OIDC provider MUST validate a nonce when its compatibility record requires it.",
            "A provider-specific OIDC flow SHOULD include a nonce only when compatibility record evidence requires it.",
        ):
            assert_nonce_policy_is_scoped(self.documentation + "\n" + sentence + "\n")

    def test_nonce_guard_distinguishes_prohibitions_from_incidental_words(self) -> None:
        for sentence in (
            "The client MUST require a nonce for every provider without checking its compatibility record.",
            "Every browser flow MUST require a nonce; omit provider-specific conditions.",
            "The nonce requirement applies to every provider, not only reviewed providers.",
        ):
            with self.assertRaises(AssertionError):
                assert_nonce_policy_is_scoped(self.documentation + "\n" + sentence + "\n")

        for sentence in (
            "The client MUST NOT require a nonce.",
            "The pinned browser flow does not require a nonce.",
            "No separate nonce is required by the pinned flow.",
        ):
            assert_nonce_policy_is_scoped(self.documentation + "\n" + sentence + "\n")

    def test_fixture_values_are_synthetic_and_redaction_is_explicit(self) -> None:
        validate_no_live_secrets(self.audit)
        validate_no_live_secrets(self.cases)
        validate_no_live_secrets(self.excerpts, scan_assignments=False)
        serialized_cases = json.dumps(self.cases, sort_keys=True).lower()
        self.assertNotIn("http://", serialized_cases)
        self.assertNotIn("https://", serialized_cases)
        self.assertNotIn("@", serialized_cases)

        nested_audit_secret = copy.deepcopy(self.audit)
        nested_audit_secret["requirements"]["nonce"]["provider_scopes"][1]["condition"] = "ghp_live_nested_fixture_secret"
        with self.assertRaises(AssertionError):
            validate_no_live_secrets(nested_audit_secret)

        nested_case_secret = copy.deepcopy(self.cases)
        nested_case_secret["cases"][0]["request"]["authorization_request"]["params"]["scope"] = "Bearer fixture_live_secret_value"
        with self.assertRaises(AssertionError):
            validate_no_live_secrets(nested_case_secret)

        nested_excerpt_secret = copy.deepcopy(self.excerpts)
        nested_excerpt_secret["routes"] += "\nAuthorization: Bearer fixture_live_secret_value\n"
        with self.assertRaises(AssertionError):
            validate_no_live_secrets(nested_excerpt_secret, scan_assignments=False)

        nested_excerpt_assignment_secret = copy.deepcopy(self.excerpts)
        nested_excerpt_assignment_secret["routes"] += "\ncookie_value=fixture_live_cookie\n"
        with self.assertRaises(AssertionError):
            validate_no_live_secrets(nested_excerpt_assignment_secret, scan_assignments=False)

        redaction = self.audit["redaction"]
        self.assertTrue(redaction["synthetic_cookie_shaped_values"])
        self.assertTrue(redaction["public_source_urls"])
        self.assertFalse(redaction["live_secrets"])
        self.assertFalse(redaction["live_cookie_contents"])
        self.assertFalse(redaction["live_host_data"])
        for expected in EXPECTED_SOURCE_REFS:
            self.assertRegex(expected["url"], r"^https://github\.com/NousResearch/hermes-agent/blob/")

    def _case(self, case_id: str) -> dict[str, Any]:
        for case in self.cases["cases"]:
            if case["id"] == case_id:
                return case
        self.fail(f"missing case: {case_id}")


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", type=Path, default=SOURCE_AUDIT_PATH)
    parser.add_argument("--cases", type=Path, default=CASES_PATH)
    args = parser.parse_args(argv)
    BrowserOAuthContractTests.audit_path = args.audit
    BrowserOAuthContractTests.cases_path = args.cases
    try:
        # Preflight through the same loader and closed-schema validators used by
        # the test lifecycle so malformed temporary fixtures fail as one
        # controlled CLI error, never a unittest traceback. The second read is
        # intentional: tests exercise the exact selected paths normally.
        validate_fixture_documents(args.audit, args.cases)
    except (
        FixtureJSONError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
        AssertionError,
        AttributeError,
        IndexError,
        KeyError,
        TypeError,
    ) as exc:
        print(compact_error(f"validation error: {exc}"), file=sys.stderr)
        return 2

    started = time.perf_counter()
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    elapsed_ms = (time.perf_counter() - started) * 1000
    print(f"fixture_validation_ms={elapsed_ms:.3f}")
    print(f"fixture_artifact_bytes={fixture_artifact_bytes()}")
    print("fixture_artifact_files=source_audit.json,cases.json,source_excerpts/*")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(run())
