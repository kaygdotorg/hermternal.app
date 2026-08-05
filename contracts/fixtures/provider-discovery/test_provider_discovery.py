#!/usr/bin/env python3
"""Strict offline validation for the C-02 provider-discovery contract.

The validator reads only committed synthetic JSON and source-audit metadata. It
never imports Hermes, opens a socket, contacts a provider, or follows a source
URL. Explicit exceptions are used instead of ``assert`` so optimized Python
runs exercise the same fail-closed checks.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import sys
import time
import unittest
from typing import Any
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent
CASES_PATH = ROOT / "cases.json"
AUDIT_PATH = ROOT / "source_audit.json"
PINNED_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
PINNED_TREE_SHA = "886db5eb1150f819344d67fedc81aef0caab09ff"
REPOSITORY = "NousResearch/hermes-agent"
REPOSITORY_URL = "https://github.com/NousResearch/hermes-agent"
AUDIT_ID = "provider-discovery-c02-f5be9236"
MAX_JSON_DEPTH = 64
EXPECTED_CASE_IDS = (
    "pending",
    "success-password-provider",
    "success-provider-neutral-order",
    "success-default-password-capability",
    "empty-registry",
    "session-filtered-registry",
    "malformed-provider-entry",
    "malformed-response-entry",
    "cancelled-discovery",
)
EXPECTED_CASE_KINDS = {
    "pending",
    "success",
    "empty",
    "malformed-provider",
    "malformed-response",
    "cancelled",
}
EXPECTED_CASE_KEYS = {
    "id",
    "synthetic",
    "kind",
    "request",
    "registered_providers",
    "response",
    "expected",
}
EXPECTED_REQUEST = {"method": "GET", "path": "/api/auth/providers"}
EXPECTED_PROVIDER_POLICY = {
    "response_keys": ["name", "display_name", "supports_password"],
    "registry_filter": "supports_session_truthy",
    "supports_session_default": True,
    "supports_password_default": False,
    "order": "registration",
    "provider_name_policy": "source-data-lowercase-stable-identifier",
    "provider_choice_policy": "provider-neutral",
}
EXPECTED_STATE_POLICY = {
    "pending": "discovering",
    "success": "signed_out",
    "empty": "provider_unavailable",
    "malformed": "provider_unavailable",
    "cancelled": "signed_out",
    "retry": "discovering_then_re_read",
}
EXPECTED_RECOVERY = {
    "discovery_is_idempotent": True,
    "retry_requires_explicit_user_action": True,
    "unknown_result": "re_read_source_state_before_retry",
    "duplicate_prompt_policy": "not_applicable_no_prompt_before_authenticated",
    "credential_policy": "no_credentials_in_fixture_or_retry",
    "retry_transition": ["provider_unavailable", "discovering", "signed_out"],
    "failure_transition": ["provider_unavailable", "discovering"],
}
EXPECTED_SOURCE_CITATIONS = [
    {
        "id": "provider-discovery-route",
        "path": "hermes_cli/dashboard_auth/routes.py",
        "lines": [152, 174],
        "markers": [
            '@router.get("/api/auth/providers", name="auth_providers")',
            "providers = list_session_providers()",
            '"detail": "no auth providers registered"',
            '"name": p.name',
            '"display_name": p.display_name',
            '"supports_password": bool(',
            'getattr(p, "supports_password", False)',
        ],
        "sha256": "d42be557b9b1ba798c038c91246cba0bf046e89ebe34a27db0c7803c517e9c20",
        "git_blob_sha": "0c142963bcc83f38fddbdcec29c35608f14f7bc1",
        "url": f"{REPOSITORY_URL}/blob/{PINNED_SHA}/hermes_cli/dashboard_auth/routes.py",
        "claim": "The pinned route returns only the three provider discovery fields and returns a precise 503 response when no interactive providers are registered.",
    },
    {
        "id": "provider-discovery-registry",
        "path": "hermes_cli/dashboard_auth/registry.py",
        "lines": [69, 75],
        "markers": [
            "def list_session_providers()",
            'if getattr(p, "supports_session", True)',
            'return [p for p in _providers.values() if getattr(p, "supports_session", True)]',
        ],
        "sha256": "b5083a1ec4e7d99bfdca57d3d6383a289b1e4ebc6740d878f0d5a8c8f1b79290",
        "git_blob_sha": "3f58090abf16d7239ec0ce24736a120a77f31fce",
        "url": f"{REPOSITORY_URL}/blob/{PINNED_SHA}/hermes_cli/dashboard_auth/registry.py",
        "claim": "Discovery includes interactive session providers only, defaults missing supports_session to true, and preserves registration order.",
    },
    {
        "id": "provider-capabilities",
        "path": "hermes_cli/dashboard_auth/base.py",
        "lines": [139, 185],
        "markers": [
            "Subclasses MUST set ``name`` (lowercase identifier, stable forever)",
            'name: str = ""',
            'display_name: str = ""',
            "supports_password: bool = False",
            "supports_session: bool = True",
        ],
        "sha256": "2307a97d6ac5f08cb3fd31ade22daa4be616a05f9faf53a40bd19ef0d7a58cb8",
        "git_blob_sha": "e8b8a7730b1d9c66c03b014751bbdc3a9c9cf802",
        "url": f"{REPOSITORY_URL}/blob/{PINNED_SHA}/hermes_cli/dashboard_auth/base.py",
        "claim": "Provider names and display labels are source-defined data; password and session capabilities have explicit boolean defaults.",
    },
]
EXPECTED_AUDIT_SCOPE = {
    "purpose": "Freeze the provider-neutral Dashboard discovery response and safe client state boundary from pinned source evidence.",
    "source_inventory_complete": False,
    "client_contract_complete": True,
    "live_compatibility": False,
    "integration_mode": "offline_synthetic_contract_only",
    "source_root_verification": "optional_pinned_checkout_or_content_snapshot",
    "unknown_policy": "fail_closed",
}
EXPECTED_CONTRACT_SURFACE = {
    "method": "GET",
    "path": "/api/auth/providers",
    "clients": ["browser", "native"],
    "success": {
        "status": 200,
        "body_keys": ["providers"],
        "provider_keys": ["name", "display_name", "supports_password"],
        "supports_password_rule": "bool(getattr(provider, 'supports_password', False))",
    },
    "empty": {
        "status": 503,
        "body": {"detail": "no auth providers registered"},
    },
    "registry": {
        "filter": "supports_session_truthy",
        "supports_session_default": True,
        "order": "registration",
    },
    "malformed": {
        "source_outcome": "handler-fails-before-response",
        "client_state": "provider_unavailable",
        "fail_closed": True,
        "invented_status": False,
    },
    "provider_policy": {
        "name_is_data": True,
        "display_name_is_data": True,
        "provider_specific_fallback": False,
        "arbitrary_origin_from_response": False,
    },
}
EXPECTED_REDACTION = {
    "synthetic_only": True,
    "raw_credentials": False,
    "raw_cookies": False,
    "raw_bearer_values": False,
    "raw_websocket_tickets": False,
    "transcripts": False,
    "hostnames": False,
    "user_data": False,
    "provider_data": False,
    "log_policy": "fixture contains classification and source citations only; never credential material",
}
EXPECTED_ACCESSIBILITY = {
    "status": "N/A",
    "reason": "C-02 freezes a protocol fixture and validator only; it adds no controls, focus order, semantic labels, Dynamic Type, VoiceOver, Switch Control, contrast, motion, transparency, or touch-target surface.",
    "preservation": "Later web and Apple clients must keep their existing accessibility contracts while rendering discovered provider labels.",
}
EXPECTED_BASELINE_COMMANDS = {
    "normal": "python3 contracts/fixtures/provider-discovery/test_provider_discovery.py",
    "optimized": "python3 -O contracts/fixtures/provider-discovery/test_provider_discovery.py",
    "discovery": "python3 -m unittest discover -s contracts/fixtures/provider-discovery -p 'test_*.py'",
    "compile": "python3 -m py_compile contracts/fixtures/provider-discovery/test_provider_discovery.py",
}
ALLOWED_METADATA_KEYS = {
    "credential_policy",
    "raw_credentials",
    "raw_cookies",
    "raw_bearer_values",
    "raw_websocket_tickets",
    "supports_password",
    "supports_password_rule",
    "supports_session",
    "supports_session_default",
}
FORBIDDEN_SENSITIVE_KEYS = {
    "accesskey",
    "apikey",
    "authorization",
    "authheader",
    "authtoken",
    "clientsecret",
    "cookie",
    "cookies",
    "credential",
    "credentials",
    "hostname",
    "idtoken",
    "password",
    "privatekey",
    "providerdata",
    "refreshtoken",
    "secret",
    "secrets",
    "ticket",
    "tickets",
    "token",
    "tokens",
    "transcript",
    "transcripts",
    "userdata",
}
FORBIDDEN_SENSITIVE_KEY_COMPONENTS = {
    "authorization",
    "credential",
    "credentials",
    "cookie",
    "cookies",
    "hostname",
    "private",
    "secret",
    "secrets",
    "ticket",
    "tickets",
    "token",
    "tokens",
    "transcript",
    "transcripts",
    "userdata",
}
FORBIDDEN_SENSITIVE_KEY_COMPOUNDS = (
    ("access", "key"),
    ("api", "key"),
    ("auth", "credential"),
    ("auth", "key"),
    ("auth", "token"),
)
FORBIDDEN_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b", re.IGNORECASE),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]+\b", re.IGNORECASE),
    re.compile(r"\bBearer\s+\S+", re.IGNORECASE),
    re.compile(r"\bBasic\s+\S+", re.IGNORECASE),
    re.compile(r"\b(?:sk-[A-Za-z0-9_-]+|ghp_[A-Za-z0-9_]+|xoxb-[A-Za-z0-9-]+|eyJ[A-Za-z0-9_-]{8,})\b", re.IGNORECASE),
)
GIT_REDIRECT_ENV_VARS = (
    "GIT_DIR",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
)


class ContractError(ValueError):
    """Raised when a fixture claims more than the pinned contract proves."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _strict_equal(actual: Any, expected: Any) -> bool:
    """Compare JSON-shaped values without Python bool/int coercion."""

    if type(actual) is not type(expected):
        return False
    if isinstance(actual, dict):
        return set(actual) == set(expected) and all(
            _strict_equal(actual[key], expected[key]) for key in expected
        )
    if isinstance(actual, list):
        return len(actual) == len(expected) and all(
            _strict_equal(left, right) for left, right in zip(actual, expected)
        )
    return actual == expected


def _reject_constant(value: str) -> None:
    raise ContractError(f"non-finite JSON constant is forbidden: {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _validate_depth(value: Any, depth: int = 0, path: str = "fixture") -> None:
    _require(depth <= MAX_JSON_DEPTH, f"{path}: JSON nesting is too deep")
    if isinstance(value, dict):
        for key, child in value.items():
            _validate_depth(child, depth + 1, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_depth(child, depth + 1, f"{path}[{index}]")


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as stream:
            value = json.load(
                stream,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_constant,
            )
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ContractError(f"{path.name}: invalid JSON: {exc}") from exc
    _require(isinstance(value, dict), f"{path.name}: top level must be an object")
    _validate_depth(value)
    return value


def _normalize_marker(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _key_tokens(value: str) -> tuple[str, ...]:
    return tuple(
        token.casefold()
        for token in re.findall(r"[A-Z]+(?=[A-Z][a-z]|$)|[A-Z]?[a-z]+|\d+", value)
    )


def _contains_compound(tokens: tuple[str, ...], compounds: tuple[tuple[str, ...], ...]) -> bool:
    return any(
        any(tokens[index : index + len(compound)] == compound for index in range(len(tokens)))
        for compound in compounds
    )


def _is_forbidden_sensitive_key(key: str) -> bool:
    if key in ALLOWED_METADATA_KEYS:
        return False
    normalized = _normalize_marker(key)
    if normalized in FORBIDDEN_SENSITIVE_KEYS:
        return True
    tokens = _key_tokens(key)
    return bool(set(tokens) & FORBIDDEN_SENSITIVE_KEY_COMPONENTS) or _contains_compound(
        tokens, FORBIDDEN_SENSITIVE_KEY_COMPOUNDS
    )


def _validate_redaction(value: Any, path: str = "fixture") -> None:
    """Reject credential-bearing keys and recognizable credential values."""

    if isinstance(value, dict):
        for key, child in value.items():
            _require(isinstance(key, str), f"{path}: object keys must be strings")
            _require(
                not _is_forbidden_sensitive_key(key),
                f"{path}.{key}: prohibited sensitive key marker",
            )
            _validate_redaction(child, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _validate_redaction(child, f"{path}[{index}]")
        return
    if isinstance(value, str):
        for pattern in FORBIDDEN_VALUE_PATTERNS:
            _require(
                pattern.search(value) is None,
                f"{path}: prohibited credential material",
            )


def _require_exact_keys(value: Any, expected: set[str], path: str) -> None:
    _require(isinstance(value, dict), f"{path}: expected an object")
    _require(set(value) == expected, f"{path}: unknown or missing keys")


def _validate_source_link(link: str, expected_path: str) -> None:
    parsed = urlsplit(link)
    _require(parsed.scheme == "https", "audit: source link must use HTTPS")
    _require(parsed.netloc == "github.com", "audit: source link has an unexpected host")
    _require(not parsed.username and not parsed.password, "audit: source link has userinfo")
    _require(not parsed.query and not parsed.fragment, "audit: source link has query or fragment")
    _require(
        link == f"{REPOSITORY_URL}/blob/{PINNED_SHA}/{expected_path}",
        "audit: source link is not the exact pinned path",
    )


def _validate_distribution(value: Any, label: str) -> None:
    _require(isinstance(value, dict), f"baseline: {label} must be an object")
    _require(set(value) == {"min", "median", "p95", "max", "mean"}, f"baseline: {label} keys changed")
    numbers: dict[str, float] = {}
    for key, number in value.items():
        _require(type(number) in (int, float), f"baseline: {label}.{key} must be numeric")
        number = float(number)
        _require(math.isfinite(number) and number > 0, f"baseline: {label}.{key} must be finite and positive")
        numbers[key] = number
    _require(numbers["min"] <= numbers["median"] <= numbers["p95"] <= numbers["max"], f"baseline: {label} order changed")
    _require(numbers["min"] <= numbers["mean"] <= numbers["max"], f"baseline: {label} mean is outside distribution")


def validate_audit(audit: dict[str, Any]) -> None:
    """Validate exact source provenance, policy, and reproducibility metadata."""

    expected_keys = {
        "schema",
        "contract",
        "audit_id",
        "hermes_repository",
        "hermes_repository_url",
        "hermes_source_sha",
        "hermes_tree_sha",
        "audit_scope",
        "fixture_paths",
        "source_citations",
        "contract_surface",
        "redaction",
        "accessibility",
        "baseline",
    }
    _require_exact_keys(audit, expected_keys, "audit")
    _require(audit["schema"] == "hermternal.source-audit.provider-discovery.v1", "audit: wrong schema")
    _require(audit["contract"] == "dashboard-v0.0.1", "audit: wrong contract")
    _require(audit["audit_id"] == AUDIT_ID, "audit: wrong audit id")
    _require(audit["hermes_repository"] == REPOSITORY, "audit: wrong repository")
    _require(audit["hermes_repository_url"] == REPOSITORY_URL, "audit: wrong repository URL")
    _require(audit["hermes_source_sha"] == PINNED_SHA, "audit: source SHA is not pinned")
    _require(audit["hermes_tree_sha"] == PINNED_TREE_SHA, "audit: tree SHA is not pinned")
    _require(_strict_equal(audit["audit_scope"], EXPECTED_AUDIT_SCOPE), "audit: scope changed")
    _require(
        _strict_equal(audit["fixture_paths"], ["cases.json", "test_provider_discovery.py", "README.md"]),
        "audit: fixture paths changed",
    )
    _require(_strict_equal(audit["source_citations"], EXPECTED_SOURCE_CITATIONS), "audit: source citations changed")
    _require(isinstance(audit["source_citations"], list), "audit: source citations must be a list")
    for citation in audit["source_citations"]:
        _validate_source_link(citation["url"], citation["path"])
        _require(len(citation["sha256"]) == 64 and re.fullmatch(r"[0-9a-f]{64}", citation["sha256"]), "audit: invalid source SHA-256")
        _require(len(citation["git_blob_sha"]) == 40 and re.fullmatch(r"[0-9a-f]{40}", citation["git_blob_sha"]), "audit: invalid source blob ID")
        _require(type(citation["lines"][0]) is int and type(citation["lines"][1]) is int, "audit: source lines must be integers")
        _require(citation["lines"][0] <= citation["lines"][1], "audit: source lines are reversed")
        _require(citation["markers"], "audit: source citation has no markers")
    _require(_strict_equal(audit["contract_surface"], EXPECTED_CONTRACT_SURFACE), "audit: contract surface changed")
    _require(_strict_equal(audit["redaction"], EXPECTED_REDACTION), "audit: redaction policy changed")
    _require(_strict_equal(audit["accessibility"], EXPECTED_ACCESSIBILITY), "audit: accessibility statement changed")

    baseline = audit["baseline"]
    _require_exact_keys(
        baseline,
        {
            "raw_commands",
            "validator",
            "build_mode",
            "source_verified",
            "repetitions",
            "normal_distribution_ms",
            "optimized_distribution_ms",
            "artifact_size_bytes",
            "environment",
            "threshold",
        },
        "audit.baseline",
    )
    _require(_strict_equal(baseline["raw_commands"], EXPECTED_BASELINE_COMMANDS), "baseline: commands changed")
    _require(baseline["validator"] == "Python standard library only", "baseline: validator changed")
    _require(baseline["build_mode"] == "N/A: fixture validator has no build artifact", "baseline: build mode changed")
    _require(baseline["source_verified"] is False, "baseline: source verification claim changed")
    _require(baseline["repetitions"] == 7, "baseline: repetitions must be seven")
    _validate_distribution(baseline["normal_distribution_ms"], "normal_distribution_ms")
    _validate_distribution(baseline["optimized_distribution_ms"], "optimized_distribution_ms")
    _require(type(baseline["artifact_size_bytes"]) is int and baseline["artifact_size_bytes"] > 0, "baseline: artifact size is invalid")
    _require_exact_keys(baseline["environment"], {"python", "implementation", "platform", "machine"}, "baseline.environment")
    _require(all(isinstance(value, str) and value for value in baseline["environment"].values()), "baseline: environment is incomplete")
    _require(baseline["threshold"] is None, "baseline: an unapproved threshold was invented")


def _validate_provider_name(value: Any, path: str) -> None:
    _require(isinstance(value, str) and value, f"{path}: provider name must be non-empty")
    _require(value.isascii() and value == value.casefold(), f"{path}: provider name must be lowercase ASCII data")


def _validate_registered_provider(provider: Any, path: str, malformed: bool = False) -> None:
    _require(isinstance(provider, dict), f"{path}: provider declaration must be an object")
    keys = set(provider)
    if malformed:
        _require(keys == {"display_name", "supports_session", "supports_password"}, f"{path}: malformed control changed")
        _require(isinstance(provider["display_name"], str) and provider["display_name"], f"{path}: malformed display label")
    else:
        _require(keys in ({"name", "display_name", "supports_session"}, {"name", "display_name", "supports_session", "supports_password"}), f"{path}: provider declaration keys changed")
        _validate_provider_name(provider["name"], f"{path}.name")
        _require(isinstance(provider["display_name"], str) and provider["display_name"], f"{path}.display_name: label must be non-empty")
    _require(type(provider["supports_session"]) is bool, f"{path}.supports_session: expected boolean")
    if "supports_password" in provider:
        _require(type(provider["supports_password"]) is bool, f"{path}.supports_password: expected boolean")


def _validate_response_provider(provider: Any, path: str, malformed: bool = False) -> None:
    _require(isinstance(provider, dict), f"{path}: response provider must be an object")
    _require(set(provider) == {"name", "display_name", "supports_password"}, f"{path}: response provider keys changed")
    _validate_provider_name(provider["name"], f"{path}.name")
    _require(isinstance(provider["display_name"], str) and provider["display_name"], f"{path}.display_name: label must be non-empty")
    if malformed:
        _require(provider["supports_password"] == "true", f"{path}.supports_password: malformed control changed")
    else:
        _require(type(provider["supports_password"]) is bool, f"{path}.supports_password: expected boolean")


def _validate_case_expected(expected: Any, path: str) -> None:
    _require_exact_keys(expected, {"state", "fail_closed", "usable", "retryable", "reason", "provider_names"}, path)
    _require(expected["state"] in {"discovering", "signed_out", "provider_unavailable"}, f"{path}.state: unknown state")
    for key in ("fail_closed", "usable", "retryable"):
        _require(type(expected[key]) is bool, f"{path}.{key}: expected boolean")
    _require(isinstance(expected["reason"], str) and expected["reason"], f"{path}.reason: expected reason")
    _require(isinstance(expected["provider_names"], list), f"{path}.provider_names: expected list")
    for index, name in enumerate(expected["provider_names"]):
        _validate_provider_name(name, f"{path}.provider_names[{index}]")


def validate_cases(cases: dict[str, Any], audit: dict[str, Any]) -> None:
    """Validate every synthetic case against the pinned route semantics."""

    _require_exact_keys(
        cases,
        {
            "schema",
            "contract",
            "audit_id",
            "hermes_source_sha",
            "client_scope",
            "synthetic",
            "route",
            "provider_policy",
            "state_policy",
            "recovery",
            "cases",
        },
        "cases",
    )
    _require(cases["schema"] == "hermternal.fixture.provider-discovery.v1", "cases: wrong schema")
    _require(cases["contract"] == "dashboard-v0.0.1", "cases: wrong contract")
    _require(cases["audit_id"] == audit["audit_id"] == AUDIT_ID, "cases: audit binding changed")
    _require(cases["hermes_source_sha"] == PINNED_SHA == audit["hermes_source_sha"], "cases: source SHA changed")
    _require(cases["client_scope"] == "shared", "cases: client scope changed")
    _require(cases["synthetic"] is True, "cases: data is not synthetic")
    _require(_strict_equal(cases["route"], {"method": "GET", "path": "/api/auth/providers", "clients": ["browser", "native"]}), "cases: route changed")
    _require(_strict_equal(cases["provider_policy"], EXPECTED_PROVIDER_POLICY), "cases: provider policy changed")
    _require(_strict_equal(cases["state_policy"], EXPECTED_STATE_POLICY), "cases: state policy changed")
    _require(_strict_equal(cases["recovery"], EXPECTED_RECOVERY), "cases: recovery policy changed")
    _validate_redaction(cases)

    fixture_cases = cases["cases"]
    _require(isinstance(fixture_cases, list), "cases: case inventory must be a list")
    _require(tuple(case.get("id") for case in fixture_cases) == EXPECTED_CASE_IDS, "cases: ordered case inventory changed")
    _require(len({case.get("id") for case in fixture_cases}) == len(EXPECTED_CASE_IDS), "cases: duplicate case IDs")

    for case in fixture_cases:
        case_id = case["id"]
        _require_exact_keys(case, EXPECTED_CASE_KEYS, f"case {case_id}")
        _require(case["synthetic"] is True, f"case {case_id}: not synthetic")
        _require(case["kind"] in EXPECTED_CASE_KINDS, f"case {case_id}: unknown kind")
        _require_exact_keys(case["request"], {"method", "path", "client"}, f"case {case_id}.request")
        _require(_strict_equal({"method": case["request"]["method"], "path": case["request"]["path"]}, EXPECTED_REQUEST), f"case {case_id}: route mutation")
        _require(case["request"]["client"] in {"browser", "native"}, f"case {case_id}: unknown client")
        _require(isinstance(case["registered_providers"], list), f"case {case_id}: registry must be a list")
        for index, provider in enumerate(case["registered_providers"]):
            _validate_registered_provider(provider, f"case {case_id}.registered_providers[{index}]", case["kind"] == "malformed-provider")
        _validate_case_expected(case["expected"], f"case {case_id}.expected")

        response = case["response"]
        kind = case["kind"]
        if kind in {"pending", "cancelled", "malformed-provider"}:
            _require(response is None, f"case {case_id}: response must be absent for {kind}")
        else:
            _require(isinstance(response, dict), f"case {case_id}: response must be an object")
            _require_exact_keys(response, {"status", "body"}, f"case {case_id}.response")
            _require(type(response["status"]) is int, f"case {case_id}: status must be an integer")
            _require(isinstance(response["body"], dict), f"case {case_id}: response body must be an object")

        expected = case["expected"]
        if kind == "pending":
            _require(_strict_equal(expected, {"state": "discovering", "fail_closed": False, "usable": False, "retryable": False, "reason": "discovery-pending", "provider_names": []}), f"case {case_id}: pending outcome changed")
        elif kind == "cancelled":
            _require(_strict_equal(expected, {"state": "signed_out", "fail_closed": False, "usable": False, "retryable": True, "reason": "cancelled-by-user", "provider_names": []}), f"case {case_id}: cancellation outcome changed")
        elif kind == "malformed-provider":
            _require(_strict_equal(expected, {"state": "provider_unavailable", "fail_closed": True, "usable": False, "retryable": True, "reason": "source-handler-failure", "provider_names": []}), f"case {case_id}: malformed provider outcome changed")
        elif kind == "malformed-response":
            _require(response["status"] == 200, f"case {case_id}: malformed response status changed")
            _require(set(response["body"]) == {"providers"}, f"case {case_id}: malformed response body keys changed")
            providers = response["body"]["providers"]
            _require(isinstance(providers, list) and len(providers) == 1, f"case {case_id}: malformed response provider count changed")
            _validate_response_provider(providers[0], f"case {case_id}.response.body.providers[0]", malformed=True)
            _require(_strict_equal(expected, {"state": "provider_unavailable", "fail_closed": True, "usable": False, "retryable": True, "reason": "invalid-response-shape", "provider_names": []}), f"case {case_id}: malformed response outcome changed")
        else:
            active = [provider for provider in case["registered_providers"] if provider.get("supports_session", True)]
            if not active:
                _require(response["status"] == 503, f"case {case_id}: empty registry must return 503")
                _require(_strict_equal(response["body"], {"detail": "no auth providers registered"}), f"case {case_id}: empty response changed")
                expected_reason = "no-auth-providers" if case_id == "empty-registry" else "no-session-providers"
                _require(_strict_equal(expected, {"state": "provider_unavailable", "fail_closed": True, "usable": False, "retryable": True, "reason": expected_reason, "provider_names": []}), f"case {case_id}: empty outcome changed")
            else:
                _require(response["status"] == 200, f"case {case_id}: successful discovery must return 200")
                _require(set(response["body"]) == {"providers"}, f"case {case_id}: success body keys changed")
                result_providers = response["body"]["providers"]
                _require(isinstance(result_providers, list) and result_providers, f"case {case_id}: success provider list must be non-empty")
                for index, provider in enumerate(result_providers):
                    _validate_response_provider(provider, f"case {case_id}.response.body.providers[{index}]")
                expected_providers = [
                    {
                        "name": provider["name"],
                        "display_name": provider["display_name"],
                        "supports_password": bool(provider.get("supports_password", False)),
                    }
                    for provider in active
                ]
                _require(_strict_equal(result_providers, expected_providers), f"case {case_id}: source order or capability default changed")
                _require(_strict_equal(expected, {"state": "signed_out", "fail_closed": False, "usable": True, "retryable": False, "reason": "providers-available", "provider_names": [provider["name"] for provider in active]}), f"case {case_id}: success outcome changed")


def _git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in GIT_REDIRECT_ENV_VARS:
        environment.pop(name, None)
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment["GIT_NO_LAZY_FETCH"] = "1"
    return environment


def _git_blob_sha(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def _run_git(root: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=False,
        capture_output=True,
        env=_git_environment(),
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise ContractError(f"source verification git command failed: {detail}")
    return result.stdout


def verify_source_root(source_root: Path, audit: dict[str, Any]) -> str:
    """Verify cited immutable bytes from a caller-provided source tree."""

    source_root = source_root.resolve()
    _require(source_root.is_dir(), "source verification: root is not a directory")
    git_checkout = (source_root / ".git").exists()
    if git_checkout:
        head = _run_git(source_root, "rev-parse", "HEAD").decode().strip()
        _require(head == PINNED_SHA, "source verification: checkout HEAD is not pinned")
        tree = _run_git(source_root, "rev-parse", f"{PINNED_SHA}^{{tree}}").decode().strip()
        _require(tree == PINNED_TREE_SHA, "source verification: checkout tree is not pinned")

    for citation in audit["source_citations"]:
        relative = citation["path"]
        if git_checkout:
            data = _run_git(source_root, "cat-file", "blob", f"{PINNED_SHA}:{relative}")
            _require(_git_blob_sha(data) == citation["git_blob_sha"], f"source verification: blob changed for {relative}")
        else:
            path = source_root / relative
            _require(path.is_file(), f"source verification: missing {relative}")
            data = path.read_bytes()
        _require(hashlib.sha256(data).hexdigest() == citation["sha256"], f"source verification: SHA-256 changed for {relative}")
        text = data.decode("utf-8")
        for marker in citation["markers"]:
            _require(marker in text, f"source verification: marker missing for {relative}: {marker}")
    return "git_checkout_verified" if git_checkout else "content_only_snapshot"


def artifact_size_bytes() -> int:
    return sum(path.stat().st_size for path in (ROOT / "README.md", CASES_PATH, ROOT / "test_provider_discovery.py"))


def validate_baseline_artifact_size(audit: dict[str, Any]) -> None:
    _require(audit["baseline"]["artifact_size_bytes"] == artifact_size_bytes(), "baseline: artifact size is stale")


def validate_set_for_baseline(cases: dict[str, Any], audit: dict[str, Any]) -> float:
    started = time.perf_counter_ns()
    validate_audit(audit)
    validate_cases(cases, audit)
    elapsed_ns = time.perf_counter_ns() - started
    return elapsed_ns / 1_000_000


class ProviderDiscoveryFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.audit = load_json(AUDIT_PATH)
        cls.cases = load_json(CASES_PATH)
        validate_audit(cls.audit)
        validate_cases(cls.cases, cls.audit)
        cls.by_id = {case["id"]: case for case in cls.cases["cases"]}

    def test_source_audit_is_pinned_and_exact(self) -> None:
        self.assertEqual(self.audit["hermes_source_sha"], PINNED_SHA)
        self.assertEqual(self.audit["hermes_tree_sha"], PINNED_TREE_SHA)
        self.assertEqual(self.audit["source_citations"], EXPECTED_SOURCE_CITATIONS)

    def test_all_cases_validate(self) -> None:
        validate_cases(self.cases, self.audit)

    def test_success_preserves_registration_order(self) -> None:
        case = self.by_id["success-provider-neutral-order"]
        names = [provider["name"] for provider in case["response"]["body"]["providers"]]
        self.assertEqual(names, ["synthetic-oauth", "synthetic-oidc"])

    def test_session_filter_and_capability_defaults_are_source_bound(self) -> None:
        filtered = self.by_id["session-filtered-registry"]
        self.assertEqual(filtered["response"]["status"], 503)
        defaulted = self.by_id["success-default-password-capability"]
        self.assertIs(defaulted["response"]["body"]["providers"][0]["supports_password"], False)

    def test_empty_registry_is_precise_503(self) -> None:
        for case_id in ("empty-registry", "session-filtered-registry"):
            with self.subTest(case_id=case_id):
                case = self.by_id[case_id]
                self.assertEqual(case["response"], {"status": 503, "body": {"detail": "no auth providers registered"}})
                self.assertTrue(case["expected"]["fail_closed"])

    def test_malformed_source_entry_has_no_invented_status(self) -> None:
        case = self.by_id["malformed-provider-entry"]
        self.assertIsNone(case["response"])
        self.assertEqual(case["expected"]["reason"], "source-handler-failure")
        self.assertTrue(case["expected"]["fail_closed"])

    def test_provider_names_are_data_not_policy(self) -> None:
        case = self.by_id["success-provider-neutral-order"]
        self.assertEqual(case["expected"]["provider_names"], ["synthetic-oauth", "synthetic-oidc"])
        self.assertFalse(self.audit["contract_surface"]["provider_policy"]["provider_specific_fallback"])

    def test_pending_cancel_and_recovery_states_are_safe(self) -> None:
        self.assertEqual(self.by_id["pending"]["expected"]["state"], "discovering")
        self.assertEqual(self.by_id["cancelled-discovery"]["expected"]["state"], "signed_out")
        self.assertEqual(self.cases["recovery"]["retry_transition"], ["provider_unavailable", "discovering", "signed_out"])
        self.assertTrue(self.cases["recovery"]["discovery_is_idempotent"])

    def test_route_mutation_is_rejected(self) -> None:
        forged = copy.deepcopy(self.cases)
        forged["route"]["path"] = "/api/auth/providers/"
        with self.assertRaises(ContractError):
            validate_cases(forged, self.audit)

    def test_unknown_case_and_extra_case_keys_are_rejected(self) -> None:
        forged = copy.deepcopy(self.cases)
        forged["cases"][0]["id"] = "new-case"
        with self.assertRaises(ContractError):
            validate_cases(forged, self.audit)
        forged = copy.deepcopy(self.cases)
        forged["cases"][0]["unexpected"] = True
        with self.assertRaises(ContractError):
            validate_cases(forged, self.audit)

    def test_empty_response_mutations_are_rejected(self) -> None:
        for mutation in (
            {"status": 200, "body": {"detail": "no auth providers registered"}},
            {"status": 503, "body": {"detail": "empty"}},
            {"status": 503, "body": {"detail": "no auth providers registered", "providers": []}},
        ):
            with self.subTest(mutation=mutation):
                forged = copy.deepcopy(self.cases)
                forged["cases"][4]["response"] = mutation
                with self.assertRaises(ContractError):
                    validate_cases(forged, self.audit)

    def test_boolean_capability_and_status_types_are_strict(self) -> None:
        forged = copy.deepcopy(self.cases)
        forged["cases"][1]["response"]["body"]["providers"][0]["supports_password"] = 1
        with self.assertRaises(ContractError):
            validate_cases(forged, self.audit)
        forged = copy.deepcopy(self.cases)
        forged["cases"][1]["response"]["status"] = True
        with self.assertRaises(ContractError):
            validate_cases(forged, self.audit)

    def test_provider_order_mutation_is_rejected(self) -> None:
        forged = copy.deepcopy(self.cases)
        providers = forged["cases"][2]["response"]["body"]["providers"]
        providers.reverse()
        with self.assertRaises(ContractError):
            validate_cases(forged, self.audit)

    def test_audit_hash_and_policy_mutations_are_rejected(self) -> None:
        forged = copy.deepcopy(self.audit)
        forged["hermes_source_sha"] = "0" * 40
        with self.assertRaises(ContractError):
            validate_audit(forged)
        forged = copy.deepcopy(self.audit)
        forged["source_citations"][0]["git_blob_sha"] = "0" * 40
        with self.assertRaises(ContractError):
            validate_audit(forged)
        forged = copy.deepcopy(self.audit)
        forged["contract_surface"]["empty"]["status"] = 200
        with self.assertRaises(ContractError):
            validate_audit(forged)

    def test_redaction_mutations_are_rejected(self) -> None:
        forged = copy.deepcopy(self.cases)
        forged["cases"][1]["response"]["body"]["password"] = "synthetic"
        with self.assertRaises(ContractError):
            validate_cases(forged, self.audit)
        forged = copy.deepcopy(self.cases)
        forged["cases"][1]["response"]["body"]["providers"][0]["display_name"] = "Bearer synthetic-value"
        with self.assertRaises(ContractError):
            validate_cases(forged, self.audit)

    def test_baseline_artifact_size_is_current(self) -> None:
        validate_baseline_artifact_size(self.audit)
        self.assertEqual(self.audit["baseline"]["repetitions"], 7)
        self.assertIsNone(self.audit["baseline"]["threshold"])

    def test_duplicate_and_nonfinite_json_controls(self) -> None:
        with self.assertRaises(ContractError):
            _reject_duplicate_keys([("providers", []), ("providers", [])])
        with self.assertRaises(ContractError):
            _reject_constant("NaN")
        with self.assertRaises(ContractError):
            _validate_depth([], MAX_JSON_DEPTH + 1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, help="optional already-pinned Hermes source root")
    args = parser.parse_args()

    audit = load_json(AUDIT_PATH)
    cases = load_json(CASES_PATH)
    validate_audit(audit)
    validate_cases(cases, audit)
    validate_baseline_artifact_size(audit)
    source_mode = "metadata_only"
    if args.source_root is not None:
        source_mode = verify_source_root(args.source_root, audit)

    duration_ms = validate_set_for_baseline(cases, audit)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ProviderDiscoveryFixtureTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.wasSuccessful():
        print(f"baseline.fixture_validation_ms={duration_ms:.3f}")
        print(f"baseline.fixture_artifact_bytes={artifact_size_bytes()}")
        print(f"baseline.fixture_count={len(cases['cases'])}")
        print(f"baseline.source_mode={source_mode}")
        print(f"baseline.python={platform.python_version()}")
        print(f"baseline.implementation={platform.python_implementation()}")
        print(f"baseline.platform={platform.platform()}")
        print(f"baseline.machine={platform.machine()}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
