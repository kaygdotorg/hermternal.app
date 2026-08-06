#!/usr/bin/env python3
"""Validate the synthetic DEP-01 private-network and firewall contract.

This module reads only checked-in synthetic JSON and local fixture metadata.  It
never starts a proxy or Hermes, opens a socket, invokes a firewall command, or
contacts a network service.  Explicit exceptions keep validation active under
both normal and optimized Python execution.
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
BASELINE_ANCHOR_PATH = ROOT / "validation-baseline-sha256.txt"
SCHEMA = "hermternal.deployment-security.private-network-firewall.v1"
BASELINE_SCHEMA = "hermternal.deployment-security.private-network-firewall-baseline.v1"
OPERATION = "DEP-01"
CONTRACT = "dashboard-v0.0.1"
PINNED_HERMES_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
MAX_JSON_BYTES = 512 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_INTEGER_DIGITS = 1024
MAX_JSON_NODES = 4096
MAX_OBJECT_KEYS = 64
MAX_ARRAY_LENGTH = 256
MAX_STRING_LENGTH = 4096
MAX_ERROR_OUTPUT = 240
BASELINE_REPETITIONS = 30
ARTIFACT_FILES = ("README.md", "cases.json", "validate.py", "test_validate.py")
ERROR_CODE = "private_network_firewall_fixture_validation_error"

ROOT_KEYS = (
    "schema",
    "operation",
    "contract",
    "pinned_source_sha",
    "synthetic_only",
    "network_access",
    "live_run",
    "compatible",
    "proof_status",
    "topology",
    "route_policy",
    "firewall_policy",
    "proxy_contract",
    "redaction",
    "cases",
)
TOPOLOGY_KEYS = (
    "origin_count",
    "public_origin",
    "static_client_path",
    "proxy_network_identity",
    "hermes_bind",
    "unknown_topology_policy",
)
HERMES_BIND_KEYS = (
    "bind_identity",
    "address_class",
    "port",
    "publicly_reachable",
    "loopback_only",
    "stability",
)
ROUTE_POLICY_KEYS = (
    "static_client_path",
    "reviewed_routes",
    "blocked_management_prefixes",
    "unknown_route_action",
)
ROUTE_KEYS = ("method", "path", "surface", "upstream", "exposure")
FIREWALL_KEYS = (
    "port",
    "default_action",
    "allow_protocol",
    "allow_source",
    "public_access",
    "direct_client_access",
    "broad_source",
    "unknown_source",
)
PROXY_KEYS = ("variants", "status", "equivalence", "implementation")
REDACTION_KEYS = (
    "synthetic_only",
    "contains_credentials",
    "contains_hosts",
    "contains_private_addresses",
    "contains_firewall_commands",
    "contains_live_urls",
    "contains_user_data",
    "log_policy",
)
CASE_KEYS = ("id", "kind", "input", "expected", "notes")
CASE_INPUT_KEYS = (
    "origin",
    "client_surface",
    "route",
    "network_path",
    "hermes_bind",
    "firewall_source",
    "topology_state",
    "firewall_rule",
)
CASE_EXPECTED_KEYS = (
    "decision",
    "route_action",
    "firewall_action",
    "upstream_reached",
    "observed_layer",
    "reason",
    "live_claim",
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

EXPECTED_CASE_IDS = (
    "topology-approved",
    "static-client-root-approved",
    "reviewed-chat-via-proxy-approved",
    "reviewed-pty-via-proxy-approved",
    "direct-public-private-denied",
    "direct-client-private-denied",
    "wrong-origin-denied",
    "second-origin-denied",
    "localhost-only-assumption-rejected",
    "public-hermes-bind-rejected",
    "wrong-hermes-port-rejected",
    "broad-firewall-source-denied",
    "unknown-network-identity-denied",
    "management-route-denied",
    "unknown-route-denied",
    "unknown-topology-blocked",
    "missing-firewall-rule-blocked",
    "malformed-topology-blocked",
)

EXPECTED_TOPOLOGY = {
    "origin_count": 1,
    "public_origin": "configured_public_https_origin",
    "static_client_path": "/",
    "proxy_network_identity": "approved_proxy_network_identity",
    "hermes_bind": {
        "bind_identity": "fixed_private_non_loopback_9119",
        "address_class": "private_non_loopback",
        "port": 9119,
        "publicly_reachable": False,
        "loopback_only": False,
        "stability": "fixed",
    },
    "unknown_topology_policy": "block",
}
EXPECTED_ROUTE_POLICY = {
    "static_client_path": "/",
    "reviewed_routes": [
        {
            "method": "GET",
            "path": "/api/auth/me",
            "surface": "hermes_api",
            "upstream": "hermes_private_9119",
            "exposure": "proxy_only",
        },
        {
            "method": "POST",
            "path": "/api/auth/ws-ticket",
            "surface": "hermes_api",
            "upstream": "hermes_private_9119",
            "exposure": "proxy_only",
        },
        {
            "method": "GET",
            "path": "/api/sessions",
            "surface": "hermes_api",
            "upstream": "hermes_private_9119",
            "exposure": "proxy_only",
        },
        {
            "method": "WS",
            "path": "/api/ws",
            "surface": "hermes_api",
            "upstream": "hermes_private_9119",
            "exposure": "proxy_only",
        },
        {
            "method": "WS",
            "path": "/api/pty",
            "surface": "hermes_api",
            "upstream": "hermes_private_9119",
            "exposure": "proxy_only_web",
        },
    ],
    "blocked_management_prefixes": [
        "/api/config",
        "/api/env",
        "/api/system",
        "/api/gateway",
        "/api/ops",
        "/api/logs",
        "/api/ssh",
    ],
    "unknown_route_action": "deny",
}
EXPECTED_FIREWALL_POLICY = {
    "port": 9119,
    "default_action": "deny",
    "allow_protocol": "tcp",
    "allow_source": "approved_proxy_network_identity",
    "public_access": "deny",
    "direct_client_access": "deny",
    "broad_source": "deny",
    "unknown_source": "deny",
}
EXPECTED_PROXY_CONTRACT = {
    "variants": ["caddy", "traefik"],
    "status": "not_run",
    "equivalence": "same_topology_route_and_firewall_invariants",
    "implementation": "neutral_contract_only",
}
EXPECTED_REDACTION = {
    "synthetic_only": True,
    "contains_credentials": False,
    "contains_hosts": False,
    "contains_private_addresses": False,
    "contains_firewall_commands": False,
    "contains_live_urls": False,
    "contains_user_data": False,
    "log_policy": "fixed_reason_markers_only",
}

ORIGINS = frozenset(
    {
        "configured_public_https_origin",
        "unconfigured_public_https_origin",
        "second_public_https_origin",
        "not_applicable",
        "malformed_origin",
    }
)
CLIENT_SURFACES = frozenset({"proof_harness", "public_browser", "proxy", "direct_client", "unknown_client"})
ROUTES = frozenset(
    {
        "/",
        "/api/auth/me",
        "/api/auth/ws-ticket",
        "/api/sessions",
        "/api/ws",
        "/api/pty",
        "/api/config",
        "/api/env",
        "/api/system",
        "/api/gateway",
        "/api/ops",
        "/api/logs",
        "/api/ssh",
        "/api/not-reviewed",
    }
)
NETWORK_PATHS = frozenset(
    {
        "offline_fixture",
        "public_https_to_proxy",
        "proxy_to_private_9119",
        "public_to_private_9119",
        "client_to_private_9119",
        "localhost_only",
        "unknown_path",
    }
)
HERMES_BINDS = frozenset(
    {
        "fixed_private_non_loopback_9119",
        "loopback_only_9119",
        "public_9119",
        "fixed_private_non_loopback_wrong_port",
        "unknown_bind",
    }
)
FIREWALL_SOURCES = frozenset(
    {
        "not_applicable",
        "approved_proxy_network_identity",
        "public_internet",
        "direct_client",
        "localhost_only",
        "unknown_network_identity",
    }
)
TOPOLOGY_STATES = frozenset(
    {
        "approved",
        "wrong_origin",
        "additional_origin",
        "localhost_only",
        "public_bind",
        "wrong_port",
        "broad_exposure",
        "unknown_network",
        "unknown",
        "missing_firewall_rule",
        "malformed",
    }
)
FIREWALL_RULES = frozenset({"present", "absent", "broad", "unknown"})
CASE_KINDS = frozenset({"topology", "positive", "negative", "incompatible", "malformed_input", "security"})
REASONS = frozenset(
    {
        "topology_approved",
        "topology_case_shape_invalid",
        "topology_state_not_approved",
        "static_client_at_root",
        "static_client_path_invalid",
        "proxy_to_private_hermes",
        "direct_public_access_denied",
        "direct_client_access_denied",
        "unconfigured_origin_denied",
        "additional_origin_denied",
        "localhost_only_assumption_rejected",
        "public_bind_rejected",
        "private_port_mismatch",
        "unknown_hermes_bind",
        "broad_firewall_source_denied",
        "firewall_rule_not_narrow",
        "unknown_network_identity",
        "management_route_not_exposed",
        "unknown_route_not_exposed",
        "unknown_topology_blocked",
        "firewall_rule_missing",
        "malformed_topology_blocked",
    }
)
SENSITIVE_NORMALIZED_KEYS = frozenset(
    {
        "password",
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
        "firewallcommand",
        "userdata",
    }
)
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?<![A-Za-z0-9])(?P<key>(?:password|token|secret|authorization|bearer|"
    r"cookie(?:[_ .-]*(?:value|id))?|credential|credentials|host(?:name)?|"
    r"(?:private[_ .-]*)?address|session(?:[_ .-]*(?:id|token|value))?|"
    r"ticket(?:[_ .-]*(?:id|value|fragment))?|firewall[_ .-]*command|"
    r"user[_ .-]*data)\s*[:=]\s*)"
    r"(?P<value>[^\s,}\]]+)",
    re.IGNORECASE,
)
SECRET_VALUE_PATTERNS = (
    re.compile(r"\b(?:ghp|github_pat|glpat|sk_live|AKIA)[A-Za-z0-9_\-]+\b", re.IGNORECASE),
    re.compile(r"\b(?:Bearer|Basic)\s+[^\s,}\]]+", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z0-9 ]+ PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"https?://[^\s,}\]]+", re.IGNORECASE),
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
)
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
HEX40_RE = re.compile(r"[0-9a-f]{40}")
HEX64_RE = re.compile(r"[0-9a-f]{64}")
BASELINE_COMMANDS = {
    "normal": "python3 contracts/fixtures/deployment-security/private-network-firewall/validate.py",
    "optimized": "python3 -O contracts/fixtures/deployment-security/private-network-firewall/validate.py",
}


class FixtureJSONError(ValueError):
    """Raised for malformed, oversized, or unsafe fixture JSON."""


class ValidationError(ValueError):
    """Raised when the frozen private-network contract is violated."""


def compact_error(message: object) -> str:
    """Redact untrusted diagnostics before applying the 240-character cap."""

    redacted = str(message)
    for pattern in SECRET_VALUE_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)

    def redact_assignment(match: re.Match[str]) -> str:
        return f"{match.group('key')}[REDACTED]"

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


def _walk_redaction(value: Any) -> None:
    if type(value) is dict:
        for key, child in value.items():
            require(type(key) is str, "redaction object key must be text")
            require(_normalize_sensitive_key(key) not in SENSITIVE_NORMALIZED_KEYS, "sensitive fixture field is not allowed")
            _walk_redaction(child)
        return
    if type(value) is list:
        for child in value:
            _walk_redaction(child)
        return
    if type(value) is str:
        for pattern in SECRET_VALUE_PATTERNS:
            require(pattern.search(value) is None, "secret-shaped fixture value is not allowed")
        require(SENSITIVE_ASSIGNMENT_RE.search(value) is None, "credential-shaped fixture value is not allowed")
        return


def validate_redaction(value: Any) -> None:
    """Reject raw credentials, hosts, private addresses, commands, or URLs."""

    _walk_redaction(value)


def validate_text_redaction(path: Path) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValidationError("redaction evidence is unavailable") from exc
    validate_redaction(text)


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


def _validate_root(document: Any) -> dict[str, Any]:
    root = strict_keys(document, ROOT_KEYS, "cases")
    require(root["schema"] == SCHEMA, "cases schema changed")
    require(root["operation"] == OPERATION, "cases operation changed")
    require(root["contract"] == CONTRACT, "cases contract changed")
    require(root["pinned_source_sha"] == PINNED_HERMES_SHA, "pinned Hermes SHA changed")
    require(HEX40_RE.fullmatch(root["pinned_source_sha"]) is not None, "pinned Hermes SHA is malformed")
    require(_bool(root["synthetic_only"], "cases.synthetic_only") is True, "cases must be synthetic")
    require(_bool(root["network_access"], "cases.network_access") is False, "network access must be disabled")
    require(_bool(root["live_run"], "cases.live_run") is False, "fixture cannot claim a live run")
    require(_bool(root["compatible"], "cases.compatible") is False, "fixture cannot claim compatibility")
    require(root["proof_status"] == "not_run", "proof status must remain not_run")
    strict_equal(root["topology"], EXPECTED_TOPOLOGY, "topology")
    strict_equal(root["route_policy"], EXPECTED_ROUTE_POLICY, "route policy")
    strict_equal(root["firewall_policy"], EXPECTED_FIREWALL_POLICY, "firewall policy")
    strict_equal(root["proxy_contract"], EXPECTED_PROXY_CONTRACT, "proxy contract")
    strict_equal(root["redaction"], EXPECTED_REDACTION, "redaction")
    return root


def _validate_case_shape(case: Any, index: int) -> dict[str, Any]:
    row = strict_keys(case, CASE_KEYS, f"cases[{index}]")
    require(type(row["id"]) is str and row["id"] == EXPECTED_CASE_IDS[index], "case inventory or order changed")
    _enum(row["kind"], CASE_KINDS, "case kind")
    request = strict_keys(row["input"], CASE_INPUT_KEYS, "case input")
    expected = strict_keys(row["expected"], CASE_EXPECTED_KEYS, "case expected")
    _enum(request["origin"], ORIGINS, "case origin")
    _enum(request["client_surface"], CLIENT_SURFACES, "case client surface")
    if request["route"] is not None:
        _enum(request["route"], ROUTES, "case route")
    _enum(request["network_path"], NETWORK_PATHS, "case network path")
    _enum(request["hermes_bind"], HERMES_BINDS, "case Hermes bind")
    _enum(request["firewall_source"], FIREWALL_SOURCES, "case firewall source")
    _enum(request["topology_state"], TOPOLOGY_STATES, "case topology state")
    _enum(request["firewall_rule"], FIREWALL_RULES, "case firewall rule")
    _text(row["notes"], "case notes", max_length=240)
    _enum(expected["decision"], frozenset({"allow", "deny"}), "case decision")
    _enum(
        expected["route_action"],
        frozenset(
            {
                "topology_validated",
                "serve_static",
                "proxy_reviewed_route",
                "deny_private_direct",
                "deny_origin",
                "deny_bind",
                "deny_firewall_rule",
                "deny_management_route",
                "deny_unknown_route",
                "block_topology",
            }
        ),
        "case route action",
    )
    _enum(expected["firewall_action"], frozenset({"allow", "deny", "not_applicable"}), "case firewall action")
    _bool(expected["upstream_reached"], "case upstream_reached")
    _enum(expected["observed_layer"], frozenset({"offline_validator", "proxy", "firewall"}), "case observed layer")
    _enum(expected["reason"], REASONS, "case reason")
    _bool(expected["live_claim"], "case live_claim")
    require(expected["live_claim"] is False, "case cannot claim live evidence")
    return row


def _outcome(
    *,
    decision: str,
    route_action: str,
    firewall_action: str,
    upstream_reached: bool,
    observed_layer: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "decision": decision,
        "route_action": route_action,
        "firewall_action": firewall_action,
        "upstream_reached": upstream_reached,
        "observed_layer": observed_layer,
        "reason": reason,
        "live_claim": False,
    }


def evaluate_case(case: Any) -> dict[str, Any]:
    """Evaluate one already-shaped case without trusting its case identifier."""

    request = case["input"]
    if request["topology_state"] in {"unknown", "malformed"}:
        return _outcome(
            decision="deny",
            route_action="block_topology",
            firewall_action="deny",
            upstream_reached=False,
            observed_layer="offline_validator",
            reason="unknown_topology_blocked" if request["topology_state"] == "unknown" else "malformed_topology_blocked",
        )
    if request["topology_state"] == "missing_firewall_rule" or request["firewall_rule"] == "absent":
        return _outcome(
            decision="deny",
            route_action="block_topology",
            firewall_action="deny",
            upstream_reached=False,
            observed_layer="offline_validator",
            reason="firewall_rule_missing",
        )
    if request["hermes_bind"] == "loopback_only_9119":
        return _outcome(
            decision="deny",
            route_action="deny_bind",
            firewall_action="deny",
            upstream_reached=False,
            observed_layer="offline_validator",
            reason="localhost_only_assumption_rejected",
        )
    if request["hermes_bind"] == "public_9119":
        return _outcome(
            decision="deny",
            route_action="deny_bind",
            firewall_action="deny",
            upstream_reached=False,
            observed_layer="offline_validator",
            reason="public_bind_rejected",
        )
    if request["hermes_bind"] == "fixed_private_non_loopback_wrong_port":
        return _outcome(
            decision="deny",
            route_action="deny_bind",
            firewall_action="deny",
            upstream_reached=False,
            observed_layer="offline_validator",
            reason="private_port_mismatch",
        )
    if request["hermes_bind"] == "unknown_bind":
        return _outcome(
            decision="deny",
            route_action="deny_bind",
            firewall_action="deny",
            upstream_reached=False,
            observed_layer="offline_validator",
            reason="unknown_hermes_bind",
        )
    if request["network_path"] == "public_to_private_9119":
        return _outcome(
            decision="deny",
            route_action="deny_private_direct",
            firewall_action="deny",
            upstream_reached=False,
            observed_layer="firewall",
            reason="direct_public_access_denied",
        )
    if request["network_path"] == "client_to_private_9119":
        return _outcome(
            decision="deny",
            route_action="deny_private_direct",
            firewall_action="deny",
            upstream_reached=False,
            observed_layer="firewall",
            reason="direct_client_access_denied",
        )
    if request["topology_state"] in {"broad_exposure", "unknown_network"} or request["firewall_source"] in {
        "public_internet",
        "unknown_network_identity",
    }:
        return _outcome(
            decision="deny",
            route_action="deny_firewall_rule",
            firewall_action="deny",
            upstream_reached=False,
            observed_layer="offline_validator",
            reason=(
                "broad_firewall_source_denied"
                if request["topology_state"] == "broad_exposure" or request["firewall_source"] == "public_internet"
                else "unknown_network_identity"
            ),
        )
    if request["firewall_rule"] in {"broad", "unknown"}:
        return _outcome(
            decision="deny",
            route_action="deny_firewall_rule",
            firewall_action="deny",
            upstream_reached=False,
            observed_layer="offline_validator",
            reason="firewall_rule_not_narrow",
        )
    if request["origin"] == "unconfigured_public_https_origin":
        return _outcome(
            decision="deny",
            route_action="deny_origin",
            firewall_action="deny",
            upstream_reached=False,
            observed_layer="proxy",
            reason="unconfigured_origin_denied",
        )
    if request["origin"] == "second_public_https_origin":
        return _outcome(
            decision="deny",
            route_action="deny_origin",
            firewall_action="deny",
            upstream_reached=False,
            observed_layer="proxy",
            reason="additional_origin_denied",
        )
    if request["origin"] != "configured_public_https_origin":
        return _outcome(
            decision="deny",
            route_action="deny_origin",
            firewall_action="deny",
            upstream_reached=False,
            observed_layer="proxy",
            reason="unconfigured_origin_denied",
        )
    if request["hermes_bind"] != "fixed_private_non_loopback_9119":
        return _outcome(
            decision="deny",
            route_action="deny_bind",
            firewall_action="deny",
            upstream_reached=False,
            observed_layer="offline_validator",
            reason="unknown_hermes_bind",
        )
    if request["topology_state"] != "approved":
        return _outcome(
            decision="deny",
            route_action="block_topology",
            firewall_action="deny",
            upstream_reached=False,
            observed_layer="offline_validator",
            reason="topology_state_not_approved",
        )
    if request["firewall_source"] != "approved_proxy_network_identity":
        return _outcome(
            decision="deny",
            route_action="deny_firewall_rule",
            firewall_action="deny",
            upstream_reached=False,
            observed_layer="offline_validator",
            reason="unknown_network_identity",
        )
    if request["firewall_rule"] != "present":
        return _outcome(
            decision="deny",
            route_action="deny_firewall_rule",
            firewall_action="deny",
            upstream_reached=False,
            observed_layer="offline_validator",
            reason="firewall_rule_not_narrow",
        )
    if request["route"] is None:
        if request["client_surface"] == "proof_harness" and request["network_path"] == "offline_fixture":
            return _outcome(
                decision="allow",
                route_action="topology_validated",
                firewall_action="allow",
                upstream_reached=False,
                observed_layer="offline_validator",
                reason="topology_approved",
            )
        return _outcome(
            decision="deny",
            route_action="block_topology",
            firewall_action="deny",
            upstream_reached=False,
            observed_layer="offline_validator",
            reason="topology_case_shape_invalid",
        )
    if request["route"] in EXPECTED_ROUTE_POLICY["blocked_management_prefixes"]:
        return _outcome(
            decision="deny",
            route_action="deny_management_route",
            firewall_action="not_applicable",
            upstream_reached=False,
            observed_layer="proxy",
            reason="management_route_not_exposed",
        )
    reviewed_paths = {item["path"] for item in EXPECTED_ROUTE_POLICY["reviewed_routes"]}
    if request["route"] not in reviewed_paths and request["route"] != "/":
        return _outcome(
            decision="deny",
            route_action="deny_unknown_route",
            firewall_action="not_applicable",
            upstream_reached=False,
            observed_layer="proxy",
            reason="unknown_route_not_exposed",
        )
    if request["route"] == "/":
        if request["client_surface"] == "public_browser" and request["network_path"] == "public_https_to_proxy":
            return _outcome(
                decision="allow",
                route_action="serve_static",
                firewall_action="not_applicable",
                upstream_reached=False,
                observed_layer="proxy",
                reason="static_client_at_root",
            )
        return _outcome(
            decision="deny",
            route_action="deny_origin",
            firewall_action="deny",
            upstream_reached=False,
            observed_layer="proxy",
            reason="static_client_path_invalid",
        )
    if request["client_surface"] == "proxy" and request["network_path"] == "proxy_to_private_9119":
        return _outcome(
            decision="allow",
            route_action="proxy_reviewed_route",
            firewall_action="allow",
            upstream_reached=True,
            observed_layer="proxy",
            reason="proxy_to_private_hermes",
        )
    return _outcome(
        decision="deny",
        route_action="deny_firewall_rule",
        firewall_action="deny",
        upstream_reached=False,
        observed_layer="firewall",
        reason="unknown_network_identity",
    )


def validate_cases_document(document: Any) -> None:
    root = _validate_root(document)
    cases = root["cases"]
    require(type(cases) is list, "cases.cases must be an array")
    require(len(cases) == len(EXPECTED_CASE_IDS), "case count changed")
    for index, case in enumerate(cases):
        row = _validate_case_shape(case, index)
        actual = evaluate_case(row)
        strict_equal(actual, row["expected"], "case outcome")


def _artifact_digest(root: Path = ROOT) -> tuple[int, str]:
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
    position = (len(ordered) - 1) * (percentage / 100)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return _round_milliseconds(ordered[lower])
    fraction = position - lower
    return _round_milliseconds(ordered[lower] + ((ordered[upper] - ordered[lower]) * fraction))


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
    actual = hashlib.sha256(_canonical_baseline_bytes(baseline)).hexdigest()
    require(anchor == actual, "baseline canonical digest changed")


def validate_baseline(baseline: Any, root: Path = ROOT, anchor_path: Path = BASELINE_ANCHOR_PATH) -> None:
    record = strict_keys(baseline, BASELINE_ROOT_KEYS, "baseline")
    require(record["schema"] == BASELINE_SCHEMA, "baseline schema changed")
    require(record["validator"] == BASELINE_COMMANDS["normal"].replace("python3 ", ""), "baseline validator path changed")
    require(record["fixture"] == "contracts/fixtures/deployment-security/private-network-firewall/cases.json", "baseline fixture path changed")
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
        command = _text(run["command"], "baseline command", max_length=240)
        require(command == BASELINE_COMMANDS[mode], "baseline command is not approved")
        repetitions = _int(run["repetitions"], "baseline repetitions")
        require(repetitions == BASELINE_REPETITIONS, "baseline repetitions must be 30")
        distribution = strict_keys(run["distribution"], BASELINE_DISTRIBUTION_KEYS, "baseline distribution")
        trace = run["trace"]
        require(type(trace) is list and len(trace) == BASELINE_REPETITIONS, "baseline trace must contain 30 samples")
        values = [_finite_number(value, "baseline trace sample") for value in trace]
        require(all(value > 0 for value in values), "baseline trace must be positive")
        expected_distribution = _expected_distribution(values)
        for key in BASELINE_DISTRIBUTION_KEYS:
            actual = _finite_number(distribution[key], "baseline distribution value")
            require(actual == expected_distribution[key], "baseline distribution does not match trace")
        require(
            distribution["min_ms"] <= distribution["p50_ms"] <= distribution["p95_ms"] <= distribution["p99_ms"] <= distribution["max_ms"],
            "baseline distribution order changed",
        )
    require(seen_modes == {"normal", "optimized"}, "baseline modes are incomplete")
    artifact = strict_keys(record["artifact"], BASELINE_ARTIFACT_KEYS, "baseline artifact")
    require(type(artifact["files"]) is list and tuple(artifact["files"]) == ARTIFACT_FILES, "baseline artifact files changed")
    require(type(artifact["bytes"]) is int and type(artifact["bytes"]) is not bool and artifact["bytes"] > 0, "baseline artifact bytes invalid")
    require(type(artifact["sha256"]) is str and HEX64_RE.fullmatch(artifact["sha256"]) is not None, "baseline artifact digest invalid")
    actual_bytes, actual_digest = _artifact_digest(root)
    require(artifact["bytes"] == actual_bytes, "baseline artifact size changed")
    require(artifact["sha256"] == actual_digest, "baseline artifact digest changed")
    require(record["threshold"] is None, "baseline must not invent a threshold")
    _validate_baseline_anchor(baseline, anchor_path)


def validate_all(
    *,
    cases_path: Path = CASES_PATH,
    baseline_path: Path = BASELINE_PATH,
    anchor_path: Path = BASELINE_ANCHOR_PATH,
    root: Path = ROOT,
) -> tuple[int, int]:
    document = load_json(cases_path)
    validate_redaction(document)
    validate_cases_document(document)
    validate_text_redaction(root / "README.md")
    baseline = load_json(baseline_path)
    validate_redaction(baseline)
    validate_baseline(baseline, root, anchor_path)
    return len(document["cases"]), baseline["artifact"]["bytes"]


def _success_payload(case_count: int, artifact_bytes: int) -> str:
    return json.dumps(
        {
            "ok": True,
            "schema": SCHEMA,
            "operation": OPERATION,
            "case_count": case_count,
            "artifact_bytes": artifact_bytes,
            "compatible": False,
            "live_run": False,
            "threshold": None,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


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
    """Run validation and emit one bounded JSON line."""

    try:
        parser = ControlledArgumentParser(add_help=False)
        parser.add_argument("--cases", type=Path, default=CASES_PATH)
        parser.add_argument("--baseline", type=Path, default=BASELINE_PATH)
        parser.add_argument("--baseline-anchor", type=Path, default=BASELINE_ANCHOR_PATH)
        parser.add_argument("--skip-baseline", action="store_true")
        args = parser.parse_args(argv)
        document = load_json(args.cases)
        validate_redaction(document)
        validate_cases_document(document)
        validate_text_redaction(ROOT / "README.md")
        if args.skip_baseline:
            case_count = len(document["cases"])
            artifact_bytes = 0
        else:
            baseline = load_json(args.baseline)
            validate_redaction(baseline)
            validate_baseline(baseline, ROOT, args.baseline_anchor)
            case_count = len(document["cases"])
            artifact_bytes = baseline["artifact"]["bytes"]
        sys.stdout.write(_success_payload(case_count, artifact_bytes) + "\n")
        return 0
    except (Exception, SystemExit) as exc:
        sys.stdout.write(_failure_payload(exc) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
