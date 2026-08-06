#!/usr/bin/env python3
"""Validate the bounded synthetic DEP-11 direct-port denial proof.

The validator reads checked-in files only. It never opens a socket, starts a
proxy or Hermes, changes a firewall, invokes a container, or contacts a host.
Explicit exceptions keep every check active under normal and optimized Python.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
CASES_PATH = ROOT / "cases.json"
BASELINE_PATH = ROOT / "validation-baseline.json"
BASELINE_ANCHOR_PATH = ROOT / "validation-baseline-sha256.txt"
SCHEMA = "hermternal.deployment-security.direct-port-denial.v1"
BASELINE_SCHEMA = "hermternal.deployment-security.direct-port-denial-baseline.v1"
OPERATION = "DEP-11"
CONTRACT = "dashboard-v0.0.1"
PINNED_HERMES_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
ERROR_CODE = "direct_port_denial_fixture_validation_error"
MAX_JSON_BYTES = 512 * 1024
MAX_TOTAL_RETAINED_BYTES = 2 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 4096
MAX_JSON_INTEGER_DIGITS = 1024
MAX_OBJECT_KEYS = 64
MAX_ARRAY_LENGTH = 256
MAX_STRING_LENGTH = 4096
MAX_ERROR_OUTPUT = 240
MAX_SIGNATURE_BYTES = 512
READ_CHUNK_BYTES = 64 * 1024
BASELINE_REPETITIONS = 30
ARTIFACT_FILES = ("README.md", "cases.json", "validate.py", "test_validate.py")
RETAINED_FILES = ARTIFACT_FILES + ("validation-baseline.json", "validation-baseline-sha256.txt")
# Immutable identities are code-pinned outside mutable benchmark metadata. A
# coordinated artifact, trace, anchor, or metadata rewrite cannot self-authorize.
PINNED_RETAINED_ARTIFACTS: dict[str, tuple[int, str]] = {
    "README.md": (6044, "030cbd97384a1c20accccc06f128191e43dfb96feacf54c3b485df98c520c706"),
    "cases.json": (20375, "a41e16a8ab50c6443710ea3f3811611c96cbb69702738d42581667eb1de3964c"),
    "test_validate.py": (22180, "f9ad863fdc6c52b42552abf8489381d581cabd5330d485646eaf5185d50873ce"),
}
PINNED_VALIDATOR_SOURCE_SHA256 = "7d495d8613a71170bc36bc4ecd82f5dc5cc4eb7853ab46a5b8644a1b83df0ddf"
PINNED_BASELINE_EVIDENCE_SHA256 = "563a88519ab056dc0fbf3e37879b4fe0cbaff89a800460deb04abe78b7efb2c9"
# The detached review signature is made with a discarded private key. Its public
# key fingerprint is published in the PR review record outside this mutable proof
# directory, so rewriting local pins and the local public key is independently
# detectable. The signature binds the reviewed artifacts and benchmark evidence.
REVIEW_PUBLIC_MODULUS = 26575087703041462118266599013404640572753706014341925698530469480269661383274384794888974895289416874384433292440295673343260980338456607961373272406777892359450019794800690509112642577648911682379402544154209216395662202751406959972616117980040081264936112777702083642952260175589253640518144117607243236330651300399215748783487423911449291593125871123521198254560114051599627296808592501949639132246314963614864823129503002245851839426729792107180390197306845379286803960978504240956904771952898657571703898351025187405440902280947598408321439399094544248627332438036020383834388141291968010572418440029640725463063
REVIEW_PUBLIC_EXPONENT = 65537
REVIEW_PUBLIC_KEY_FINGERPRINT = "689f33ddf748eb0fced4f9a8cf2ee6ba2a096f8c25e76cac95410c8d6ffd46dd"
PROXY_ATTESTATION = "6fa2dde11831a805a8ea7ef7e576e44b0fce69d130a7441d29b8822a0056f5b5"
VALIDATOR_IDENTITY_RE = re.compile(r'(?m)^PINNED_VALIDATOR_SOURCE_SHA256 = "[0-9a-f]{64}"$')
BASELINE_EVIDENCE_KEYS = ("schema", "validator", "fixture", "metric", "environment", "runs", "threshold")
HEX40_RE = re.compile(r"[0-9a-f]{40}")
HEX64_RE = re.compile(r"[0-9a-f]{64}")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
LIVE_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IPV4_RE = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
HOST_CANARY_RE = re.compile(r"(?i)(?:^|[^a-z0-9])(?:[a-z0-9-]+\.)+(?:invalid|example|test)(?:[^a-z0-9]|$)")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z0-9 ]+ PRIVATE KEY-----", re.IGNORECASE)
CREDENTIAL_ASSIGNMENT_RE = re.compile(
    r"(?i)(?:authorization|password|token|secret|cookie|credential|ticket|session)\s*[:=]\s*[^\s,}\]]+"
)
SENSITIVE_KEYS = frozenset(
    {
        "authorization",
        "password",
        "token",
        "secret",
        "cookie",
        "credential",
        "credentials",
        "ticket",
        "ticketvalue",
        "sessionid",
        "sessiontoken",
        "hostname",
        "ipaddress",
        "privateaddress",
        "firewallcommand",
        "userdata",
    }
)

ROOT_KEYS = (
    "schema",
    "operation",
    "contract",
    "pinned_source_sha",
    "synthetic_only",
    "network_access",
    "socket_operations",
    "firewall_changes",
    "live_infrastructure",
    "compatible",
    "proof_status",
    "cleanup",
    "boundary",
    "redaction",
    "cases",
)
BOUNDARY_KEYS = (
    "transport",
    "configured_proxy_identity",
    "configured_proxy_interface",
    "private_bind_identity",
    "private_bind_interface",
    "private_bind_port",
    "required_proxy_hops",
    "default_action",
)
REDACTION_KEYS = (
    "contains_credentials",
    "contains_real_hosts",
    "contains_real_addresses",
    "contains_live_urls",
    "contains_firewall_commands",
    "contains_user_data",
    "retained_hostile_values",
)
CASE_KEYS = ("id", "kind", "raw_network", "expected", "notes")
RAW_NETWORK_KEYS = (
    "transport",
    "source_identity",
    "source_interface",
    "destination_identity",
    "destination_interface",
    "destination_port",
    "proxy_hops",
    "firewall_rule",
    "proxy_attestation",
)
FIREWALL_RULE_KEYS = (
    "present",
    "action",
    "protocol",
    "source_identity",
    "source_interface",
    "destination_identity",
    "destination_interface",
    "destination_port",
)
EXPECTED_KEYS = (
    "decision",
    "network_action",
    "upstream_call",
    "observed_boundary",
    "reason",
    "retained_hostile_values",
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
BASELINE_ENVIRONMENT_KEYS = ("platform", "python")
BASELINE_RUN_KEYS = ("mode", "command", "repetitions", "distribution", "trace")
BASELINE_DISTRIBUTION_KEYS = ("min_ms", "p50_ms", "p95_ms", "p99_ms", "max_ms", "mean_ms")
BASELINE_ARTIFACT_KEYS = ("files", "bytes", "sha256")
EXPECTED_CASE_IDS = (
    "configured-proxy-path-allowed",
    "public-direct-path-denied",
    "browser-direct-path-denied",
    "client-network-direct-path-denied",
    "wrong-source-interface-denied",
    "wrong-destination-interface-denied",
    "wrong-destination-port-denied",
    "broad-firewall-source-denied",
    "missing-firewall-evidence-denied",
    "wrong-transport-denied",
    "unconfigured-proxy-identity-denied",
    "missing-proxy-hop-denied",
    "extra-proxy-hop-denied",
    "public-destination-bind-denied",
    "loopback-destination-bind-denied",
    "unknown-source-denied",
)
EXPECTED_BOUNDARY = {
    "transport": "tcp",
    "configured_proxy_identity": "configured_proxy",
    "configured_proxy_interface": "proxy_egress",
    "private_bind_identity": "hermes_private_bind",
    "private_bind_interface": "private_service",
    "private_bind_port": 9119,
    "required_proxy_hops": ["configured_proxy"],
    "default_action": "deny",
}
EXPECTED_REDACTION = {
    "contains_credentials": False,
    "contains_real_hosts": False,
    "contains_real_addresses": False,
    "contains_live_urls": False,
    "contains_firewall_commands": False,
    "contains_user_data": False,
    "retained_hostile_values": False,
}
EXPECTED_FIREWALL_RULE = {
    "present": True,
    "action": "allow",
    "protocol": "tcp",
    "source_identity": "configured_proxy",
    "source_interface": "proxy_egress",
    "destination_identity": "hermes_private_bind",
    "destination_interface": "private_service",
    "destination_port": 9119,
}
TRANSPORTS = frozenset({"tcp", "udp"})
SOURCE_IDENTITIES = frozenset(
    {"configured_proxy", "unconfigured_proxy", "public_gateway", "browser_runtime", "client_network", "unknown_source"}
)
SOURCE_INTERFACES = frozenset({"proxy_egress", "public_ingress", "browser_client", "client_ingress", "unknown_interface"})
DESTINATION_IDENTITIES = frozenset({"hermes_private_bind", "public_service_bind", "loopback_service_bind"})
DESTINATION_INTERFACES = frozenset({"private_service", "public_service", "loopback_service"})
PROXY_HOPS = frozenset({"configured_proxy", "unconfigured_proxy"})
FIREWALL_IDENTITIES = SOURCE_IDENTITIES | frozenset({"any_source"})
FIREWALL_INTERFACES = SOURCE_INTERFACES | frozenset({"any_interface"})
CASE_KINDS = frozenset({"positive", "negative", "security", "incompatible", "malformed_evidence"})
REASONS = frozenset(
    {
        "configured_proxy_path_exact",
        "public_source_direct_denied",
        "browser_source_direct_denied",
        "client_network_direct_denied",
        "source_identity_mismatch",
        "source_interface_mismatch",
        "destination_identity_mismatch",
        "destination_interface_mismatch",
        "destination_port_mismatch",
        "transport_mismatch",
        "proxy_path_mismatch",
        "proxy_attestation_missing",
        "proxy_attestation_mismatch",
        "firewall_evidence_missing",
        "firewall_rule_inactive",
        "firewall_action_mismatch",
        "firewall_protocol_mismatch",
        "firewall_source_not_exact",
        "firewall_destination_not_exact",
    }
)
BASELINE_COMMANDS = {
    "normal": "python3 contracts/fixtures/deployment-security/direct-port-denial/validate.py",
    "optimized": "python3 -O contracts/fixtures/deployment-security/direct-port-denial/validate.py",
}


class FixtureJSONError(ValueError):
    """Raised for malformed or resource-exhausting JSON evidence."""


class ValidationError(ValueError):
    """Raised when synthetic evidence violates the frozen contract."""


def compact_error(message: object) -> str:
    """Return one bounded diagnostic without retaining hostile values."""

    text = str(message)
    for pattern in (LIVE_URL_RE, IPV4_RE, HOST_CANARY_RE, PRIVATE_KEY_RE, CREDENTIAL_ASSIGNMENT_RE):
        text = pattern.sub("[REDACTED]", text)
    if len(text) > MAX_ERROR_OUTPUT:
        text = text[: MAX_ERROR_OUTPUT - 3] + "..."
    return text


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


def _parse_float(value: str) -> float:
    try:
        result = float(value)
    except (OverflowError, ValueError) as exc:
        raise FixtureJSONError("JSON float is outside the bounded range") from exc
    if not math.isfinite(result):
        raise FixtureJSONError("non-finite JSON number is not allowed")
    return result


def _parse_int(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise FixtureJSONError("JSON integer digit limit exceeded")
    try:
        return int(value)
    except (OverflowError, ValueError) as exc:
        raise FixtureJSONError("invalid JSON integer") from exc


def scan_json_nesting(text: str) -> None:
    """Reject excessive depth before the standard decoder can recurse."""

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


def validate_json_tree(value: Any) -> int:
    """Iteratively bound total nodes, depth, containers, strings, and types."""

    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        require(depth <= MAX_JSON_DEPTH, "JSON depth exceeds the bounded limit")
        nodes += 1
        require(nodes <= MAX_JSON_NODES, "JSON node count exceeds the bounded limit")
        if type(current) is dict:
            require(len(current) <= MAX_OBJECT_KEYS, "JSON object has too many keys")
            for key, child in current.items():
                require(type(key) is str, "JSON object key must be text")
                require(len(key) <= MAX_STRING_LENGTH, "JSON object key is too long")
                require(CONTROL_RE.search(key) is None, "JSON object key has a control character")
                stack.append((child, depth + 1))
        elif type(current) is list:
            require(len(current) <= MAX_ARRAY_LENGTH, "JSON array is too long")
            stack.extend((child, depth + 1) for child in reversed(current))
        elif type(current) is str:
            require(len(current) <= MAX_STRING_LENGTH, "JSON string is too long")
            require(CONTROL_RE.search(current) is None, "JSON string has a control character")
        elif type(current) is float:
            require(math.isfinite(current), "JSON number is not finite")
        else:
            require(current is None or type(current) in {bool, int}, "unsupported JSON value type")
    return nodes


def load_json(path: Path) -> Any:
    """Load one bounded strict UTF-8 JSON document."""

    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_JSON_BYTES + 1)
    except OSError as exc:
        raise FixtureJSONError("fixture file is unavailable") from exc
    if len(data) > MAX_JSON_BYTES:
        raise FixtureJSONError("fixture JSON exceeds the byte limit")
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
            parse_float=_parse_float,
            parse_int=_parse_int,
        )
    except FixtureJSONError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        raise FixtureJSONError("fixture JSON is malformed") from exc
    validate_json_tree(value)
    return value


def _normalize_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", key.casefold())


def validate_redaction(value: Any) -> None:
    """Iteratively reject sensitive keys and concrete hostile retained values."""

    stack = [value]
    nodes = 0
    while stack:
        current = stack.pop()
        nodes += 1
        require(nodes <= MAX_JSON_NODES, "redaction node count exceeds the bounded limit")
        if type(current) is dict:
            for key, child in current.items():
                require(_normalize_key(key) not in SENSITIVE_KEYS, "sensitive fixture field is not allowed")
                stack.append(child)
        elif type(current) is list:
            stack.extend(reversed(current))
        elif type(current) is str:
            for pattern in (LIVE_URL_RE, IPV4_RE, HOST_CANARY_RE, PRIVATE_KEY_RE, CREDENTIAL_ASSIGNMENT_RE):
                require(pattern.search(current) is None, "hostile retained value is not allowed")


def validate_retained_artifact_redaction(root: Path = ROOT) -> None:
    """Scan every retained artifact with one total byte bound."""

    total = 0
    for relative in RETAINED_FILES:
        remaining = MAX_TOTAL_RETAINED_BYTES - total
        require(remaining >= 0, "retained artifact byte limit exceeded")
        data = _read_artifact(root, relative, limit=remaining)
        total += len(data)
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValidationError("retained artifact is not UTF-8") from exc
        for pattern in (LIVE_URL_RE, IPV4_RE, HOST_CANARY_RE, PRIVATE_KEY_RE, CREDENTIAL_ASSIGNMENT_RE):
            require(pattern.search(text) is None, "hostile retained artifact value is not allowed")


def strict_keys(value: Any, expected: tuple[str, ...], label: str) -> dict[str, Any]:
    require(type(value) is dict, f"{label} must be an object")
    require(tuple(value.keys()) == expected, f"{label} keys or ordering changed")
    return value


def _text(value: Any, label: str, *, max_length: int = MAX_STRING_LENGTH) -> str:
    require(type(value) is str, f"{label} must be text")
    require(0 < len(value) <= max_length, f"{label} has an invalid length")
    require(CONTROL_RE.search(value) is None, f"{label} has a control character")
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
    """Iteratively compare exact types, key order, list order, and values."""

    stack: list[tuple[Any, Any]] = [(actual, expected)]
    nodes = 0
    while stack:
        left, right = stack.pop()
        nodes += 1
        require(nodes <= MAX_JSON_NODES, f"{label} comparison exceeds the node limit")
        require(type(left) is type(right), f"{label} type changed")
        if type(right) is dict:
            require(tuple(left.keys()) == tuple(right.keys()), f"{label} keys or ordering changed")
            stack.extend((left[key], right[key]) for key in reversed(tuple(right.keys())))
        elif type(right) is list:
            require(len(left) == len(right), f"{label} length changed")
            stack.extend(zip(reversed(left), reversed(right)))
        else:
            require(left == right, f"{label} value changed")


def _validate_root(document: Any) -> dict[str, Any]:
    root = strict_keys(document, ROOT_KEYS, "cases")
    require(root["schema"] == SCHEMA, "cases schema changed")
    require(root["operation"] == OPERATION, "cases operation changed")
    require(root["contract"] == CONTRACT, "cases contract changed")
    require(root["pinned_source_sha"] == PINNED_HERMES_SHA, "pinned source changed")
    require(HEX40_RE.fullmatch(root["pinned_source_sha"]) is not None, "pinned source is malformed")
    for key in ("synthetic_only",):
        require(_bool(root[key], key) is True, f"{key} must remain true")
    for key in ("network_access", "socket_operations", "firewall_changes", "live_infrastructure", "compatible"):
        require(_bool(root[key], key) is False, f"{key} must remain false")
    require(root["proof_status"] == "bounded_synthetic_model_pass", "proof status changed")
    require(root["cleanup"] == "not_applicable_no_state_created", "cleanup scope changed")
    strict_equal(strict_keys(root["boundary"], BOUNDARY_KEYS, "boundary"), EXPECTED_BOUNDARY, "boundary")
    strict_equal(strict_keys(root["redaction"], REDACTION_KEYS, "redaction"), EXPECTED_REDACTION, "redaction")
    return root


def _validate_firewall_rule(value: Any) -> None:
    if value is None:
        return
    rule = strict_keys(value, FIREWALL_RULE_KEYS, "firewall rule")
    _bool(rule["present"], "firewall present")
    _enum(rule["action"], frozenset({"allow", "deny"}), "firewall action")
    _enum(rule["protocol"], TRANSPORTS, "firewall protocol")
    _enum(rule["source_identity"], FIREWALL_IDENTITIES, "firewall source identity")
    _enum(rule["source_interface"], FIREWALL_INTERFACES, "firewall source interface")
    _enum(rule["destination_identity"], DESTINATION_IDENTITIES, "firewall destination identity")
    _enum(rule["destination_interface"], DESTINATION_INTERFACES, "firewall destination interface")
    port = _int(rule["destination_port"], "firewall destination port")
    require(0 <= port <= 65535, "firewall destination port is outside the bounded range")


def _validate_case_shape(case: Any, index: int) -> dict[str, Any]:
    row = strict_keys(case, CASE_KEYS, "case")
    require(row["id"] == EXPECTED_CASE_IDS[index], "case inventory or order changed")
    _enum(row["kind"], CASE_KINDS, "case kind")
    raw = strict_keys(row["raw_network"], RAW_NETWORK_KEYS, "raw network")
    _enum(raw["transport"], TRANSPORTS, "raw transport")
    _enum(raw["source_identity"], SOURCE_IDENTITIES, "raw source identity")
    _enum(raw["source_interface"], SOURCE_INTERFACES, "raw source interface")
    _enum(raw["destination_identity"], DESTINATION_IDENTITIES, "raw destination identity")
    _enum(raw["destination_interface"], DESTINATION_INTERFACES, "raw destination interface")
    port = _int(raw["destination_port"], "raw destination port")
    require(0 <= port <= 65535, "raw destination port is outside the bounded range")
    require(type(raw["proxy_hops"]) is list, "raw proxy hops must be an array")
    require(len(raw["proxy_hops"]) <= 4, "raw proxy hops exceed the bounded path length")
    for hop in raw["proxy_hops"]:
        _enum(hop, PROXY_HOPS, "raw proxy hop")
    _validate_firewall_rule(raw["firewall_rule"])
    if raw["proxy_attestation"] is not None:
        require(type(raw["proxy_attestation"]) is str, "proxy attestation must be text or null")
        require(HEX64_RE.fullmatch(raw["proxy_attestation"]) is not None, "proxy attestation is malformed")
    expected = strict_keys(row["expected"], EXPECTED_KEYS, "expected")
    _enum(expected["decision"], frozenset({"allow", "deny"}), "expected decision")
    _enum(expected["network_action"], frozenset({"represent_proxy_forward", "drop_without_upstream"}), "network action")
    _bool(expected["upstream_call"], "expected upstream call")
    _enum(expected["observed_boundary"], frozenset({"offline_model", "synthetic_firewall"}), "observed boundary")
    _enum(expected["reason"], REASONS, "expected reason")
    require(_bool(expected["retained_hostile_values"], "retained hostile values") is False, "hostile values cannot be retained")
    require(_bool(expected["live_claim"], "live claim") is False, "case cannot claim live evidence")
    _text(row["notes"], "case notes", max_length=240)
    return row


def _outcome(decision: str, action: str, upstream: bool, boundary: str, reason: str) -> dict[str, Any]:
    return {
        "decision": decision,
        "network_action": action,
        "upstream_call": upstream,
        "observed_boundary": boundary,
        "reason": reason,
        "retained_hostile_values": False,
        "live_claim": False,
    }


def _deny(reason: str, boundary: str = "offline_model") -> dict[str, Any]:
    return _outcome("deny", "drop_without_upstream", False, boundary, reason)


def evaluate_case(case: Any) -> dict[str, Any]:
    """Derive the result only from exact raw network and rule fields."""

    raw = case["raw_network"]
    if raw["source_identity"] == "public_gateway":
        return _deny("public_source_direct_denied", "synthetic_firewall")
    if raw["source_identity"] == "browser_runtime":
        return _deny("browser_source_direct_denied", "synthetic_firewall")
    if raw["source_identity"] == "client_network":
        return _deny("client_network_direct_denied", "synthetic_firewall")
    if raw["source_identity"] != EXPECTED_BOUNDARY["configured_proxy_identity"]:
        return _deny("source_identity_mismatch", "synthetic_firewall")
    if raw["source_interface"] != EXPECTED_BOUNDARY["configured_proxy_interface"]:
        return _deny("source_interface_mismatch", "synthetic_firewall")
    if raw["destination_identity"] != EXPECTED_BOUNDARY["private_bind_identity"]:
        return _deny("destination_identity_mismatch")
    if raw["destination_interface"] != EXPECTED_BOUNDARY["private_bind_interface"]:
        return _deny("destination_interface_mismatch")
    if raw["destination_port"] != EXPECTED_BOUNDARY["private_bind_port"]:
        return _deny("destination_port_mismatch")
    if raw["transport"] != EXPECTED_BOUNDARY["transport"]:
        return _deny("transport_mismatch")
    if raw["proxy_hops"] != EXPECTED_BOUNDARY["required_proxy_hops"]:
        return _deny("proxy_path_mismatch")
    if raw["proxy_attestation"] is None:
        return _deny("proxy_attestation_missing")
    if raw["proxy_attestation"] != PROXY_ATTESTATION:
        return _deny("proxy_attestation_mismatch")
    rule = raw["firewall_rule"]
    if rule is None:
        return _deny("firewall_evidence_missing")
    if rule["present"] is not True:
        return _deny("firewall_rule_inactive")
    if rule["action"] != "allow":
        return _deny("firewall_action_mismatch")
    if rule["protocol"] != EXPECTED_FIREWALL_RULE["protocol"]:
        return _deny("firewall_protocol_mismatch")
    if (
        rule["source_identity"] != EXPECTED_FIREWALL_RULE["source_identity"]
        or rule["source_interface"] != EXPECTED_FIREWALL_RULE["source_interface"]
    ):
        return _deny("firewall_source_not_exact")
    if (
        rule["destination_identity"] != EXPECTED_FIREWALL_RULE["destination_identity"]
        or rule["destination_interface"] != EXPECTED_FIREWALL_RULE["destination_interface"]
        or rule["destination_port"] != EXPECTED_FIREWALL_RULE["destination_port"]
    ):
        return _deny("firewall_destination_not_exact")
    return _outcome("allow", "represent_proxy_forward", True, "offline_model", "configured_proxy_path_exact")


def validate_cases_document(document: Any) -> None:
    root = _validate_root(document)
    cases = root["cases"]
    require(type(cases) is list, "cases must be an array")
    require(len(cases) == len(EXPECTED_CASE_IDS), "case count changed")
    allow_count = 0
    for index, case in enumerate(cases):
        row = _validate_case_shape(case, index)
        actual = evaluate_case(row)
        strict_equal(actual, row["expected"], "case outcome")
        if actual["decision"] == "allow":
            allow_count += 1
    require(allow_count == 1, "exactly one configured proxy path must be allowed")


def _read_artifact(root: Path, relative: str, *, limit: int = MAX_TOTAL_RETAINED_BYTES) -> bytes:
    """Read a regular non-symlink file without allocating past its limit."""

    path = root / relative
    try:
        metadata = path.lstat()
        require(stat.S_ISREG(metadata.st_mode), "retained artifact must be a regular file")
        require(not stat.S_ISLNK(metadata.st_mode), "retained artifact symlink is not allowed")
        require(metadata.st_size <= limit, "retained artifact byte limit exceeded")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            require(stat.S_ISREG(opened.st_mode), "retained artifact must remain a regular file")
            require(opened.st_dev == metadata.st_dev and opened.st_ino == metadata.st_ino, "retained artifact changed during open")
            require(opened.st_size <= limit, "retained artifact byte limit exceeded")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(READ_CHUNK_BYTES, limit - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                require(total <= limit, "retained artifact byte limit exceeded")
                chunks.append(chunk)
            require(total == opened.st_size, "retained artifact changed during read")
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    except ValidationError:
        raise
    except OSError as exc:
        raise ValidationError("retained artifact is unavailable") from exc


def _validator_source_digest(root: Path = ROOT) -> str:
    try:
        source = _read_artifact(root, "validate.py", limit=MAX_JSON_BYTES).decode("utf-8")
    except (ValidationError, UnicodeError) as exc:
        raise ValidationError("validator identity is unavailable") from exc
    canonical, replacements = VALIDATOR_IDENTITY_RE.subn(
        'PINNED_VALIDATOR_SOURCE_SHA256 = "<code-pinned>"', source
    )
    require(replacements == 1, "validator identity marker changed")
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _validate_pinned_artifacts(root: Path = ROOT) -> None:
    for relative, (expected_bytes, expected_digest) in PINNED_RETAINED_ARTIFACTS.items():
        data = _read_artifact(root, relative)
        require(len(data) == expected_bytes, "pinned retained artifact size changed")
        require(hashlib.sha256(data).hexdigest() == expected_digest, "pinned retained artifact digest changed")
    require(_validator_source_digest(root) == PINNED_VALIDATOR_SOURCE_SHA256, "pinned validator identity changed")


def _artifact_digest(root: Path = ROOT) -> tuple[int, str]:
    digest = hashlib.sha256()
    total = 0
    for relative in ARTIFACT_FILES:
        remaining = MAX_TOTAL_RETAINED_BYTES - total
        require(remaining >= 0, "artifact byte total exceeds the bounded limit")
        data = _read_artifact(root, relative, limit=remaining)
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
        raise ValidationError(f"{label} is outside the bounded range") from exc
    require(math.isfinite(result) and result > 0, f"{label} must be finite and positive")
    return result


def _round_ms(value: float) -> float:
    return float(f"{value:.3f}")


def _percentile(values: list[float], percentage: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentage / 100
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return _round_ms(ordered[lower])
    return _round_ms(ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower))


def _expected_distribution(values: list[float]) -> dict[str, float]:
    return {
        "min_ms": _round_ms(min(values)),
        "p50_ms": _percentile(values, 50),
        "p95_ms": _percentile(values, 95),
        "p99_ms": _percentile(values, 99),
        "max_ms": _round_ms(max(values)),
        "mean_ms": _round_ms(sum(values) / len(values)),
    }


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _canonical_baseline_evidence_bytes(baseline: dict[str, Any]) -> bytes:
    return _canonical_json_bytes({key: baseline[key] for key in BASELINE_EVIDENCE_KEYS})


def _review_signature_payload(baseline: dict[str, Any], root: Path = ROOT) -> bytes:
    """Bind the reviewed fixture bytes and canonical benchmark evidence."""

    artifact_bytes, artifact_digest = _artifact_digest(root)
    return b"\n".join(
        (
            b"hermternal.direct-port-denial.review.v1",
            str(artifact_bytes).encode("ascii"),
            artifact_digest.encode("ascii"),
            hashlib.sha256(_canonical_baseline_evidence_bytes(baseline)).hexdigest().encode("ascii"),
        )
    )


def _verify_review_signature(signature: bytes, payload: bytes) -> None:
    """Verify the detached RSA PKCS#1 v1.5 SHA-256 review signature."""

    require(REVIEW_PUBLIC_MODULUS > 0, "review public key is not configured")
    fingerprint = hashlib.sha256(
        f"rsa:{REVIEW_PUBLIC_MODULUS}:{REVIEW_PUBLIC_EXPONENT}".encode("ascii")
    ).hexdigest()
    require(fingerprint == REVIEW_PUBLIC_KEY_FINGERPRINT, "review public key fingerprint changed")
    modulus_bytes = (REVIEW_PUBLIC_MODULUS.bit_length() + 7) // 8
    require(len(signature) == modulus_bytes, "review signature length changed")
    encoded = pow(int.from_bytes(signature, "big"), REVIEW_PUBLIC_EXPONENT, REVIEW_PUBLIC_MODULUS).to_bytes(
        modulus_bytes, "big"
    )
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(payload).digest()
    padding_length = modulus_bytes - len(digest_info) - 3
    require(padding_length >= 8, "review public key is too short")
    expected = b"\x00\x01" + (b"\xff" * padding_length) + b"\x00" + digest_info
    require(encoded == expected, "external review signature changed")


def _validate_baseline_anchor(baseline: dict[str, Any], anchor_path: Path, root: Path = ROOT) -> None:
    try:
        encoded = _read_artifact(anchor_path.parent, anchor_path.name, limit=MAX_SIGNATURE_BYTES).strip()
        signature = base64.b64decode(encoded, validate=True)
    except (ValidationError, ValueError) as exc:
        raise ValidationError("external review signature is unavailable or malformed") from exc
    _verify_review_signature(signature, _review_signature_payload(baseline, root))


def validate_baseline(baseline: Any, root: Path = ROOT, anchor_path: Path = BASELINE_ANCHOR_PATH) -> None:
    record = strict_keys(baseline, BASELINE_ROOT_KEYS, "baseline")
    require(record["schema"] == BASELINE_SCHEMA, "baseline schema changed")
    require(record["validator"] == BASELINE_COMMANDS["normal"].replace("python3 ", ""), "baseline validator path changed")
    require(record["fixture"] == "contracts/fixtures/deployment-security/direct-port-denial/cases.json", "baseline fixture path changed")
    require(record["metric"] == "validator_duration_ms", "baseline metric changed")
    environment = strict_keys(record["environment"], BASELINE_ENVIRONMENT_KEYS, "baseline environment")
    _text(environment["platform"], "baseline platform", max_length=160)
    _text(environment["python"], "baseline Python", max_length=64)
    runs = record["runs"]
    require(type(runs) is list and len(runs) == 2, "baseline must contain two modes")
    seen: set[str] = set()
    for run_value in runs:
        run = strict_keys(run_value, BASELINE_RUN_KEYS, "baseline run")
        mode = _enum(run["mode"], frozenset({"normal", "optimized"}), "baseline mode")
        require(mode not in seen, "baseline mode is duplicated")
        seen.add(mode)
        require(run["command"] == BASELINE_COMMANDS[mode], "baseline command changed")
        require(_int(run["repetitions"], "baseline repetitions") == BASELINE_REPETITIONS, "baseline repetitions must be 30")
        distribution = strict_keys(run["distribution"], BASELINE_DISTRIBUTION_KEYS, "baseline distribution")
        trace = run["trace"]
        require(type(trace) is list and len(trace) == BASELINE_REPETITIONS, "baseline trace must contain 30 raw samples")
        values = [_finite_number(sample, "baseline sample") for sample in trace]
        expected = _expected_distribution(values)
        for key in BASELINE_DISTRIBUTION_KEYS:
            require(_finite_number(distribution[key], "baseline distribution value") == expected[key], "baseline distribution does not match raw samples")
        require(distribution["min_ms"] <= distribution["p50_ms"] <= distribution["p95_ms"] <= distribution["p99_ms"] <= distribution["max_ms"], "baseline distribution order changed")
    require(seen == {"normal", "optimized"}, "baseline modes are incomplete")
    require(hashlib.sha256(_canonical_baseline_evidence_bytes(record)).hexdigest() == PINNED_BASELINE_EVIDENCE_SHA256, "baseline evidence digest changed")
    _validate_pinned_artifacts(root)
    artifact = strict_keys(record["artifact"], BASELINE_ARTIFACT_KEYS, "baseline artifact")
    require(type(artifact["files"]) is list and tuple(artifact["files"]) == ARTIFACT_FILES, "baseline artifact files changed")
    require(type(artifact["bytes"]) is int and type(artifact["bytes"]) is not bool and artifact["bytes"] > 0, "baseline artifact bytes invalid")
    require(type(artifact["sha256"]) is str and HEX64_RE.fullmatch(artifact["sha256"]) is not None, "baseline artifact digest invalid")
    actual_bytes, actual_digest = _artifact_digest(root)
    require(artifact["bytes"] == actual_bytes, "baseline artifact size changed")
    require(artifact["sha256"] == actual_digest, "baseline artifact digest changed")
    require(record["threshold"] is None, "baseline must not invent a threshold")
    _validate_baseline_anchor(record, anchor_path, root)


def validate_all(
    cases_path: Path = CASES_PATH,
    baseline_path: Path = BASELINE_PATH,
    anchor_path: Path = BASELINE_ANCHOR_PATH,
    root: Path = ROOT,
) -> tuple[int, int]:
    document = load_json(cases_path)
    validate_redaction(document)
    validate_cases_document(document)
    baseline = load_json(baseline_path)
    validate_redaction(baseline)
    validate_baseline(baseline, root, anchor_path)
    validate_retained_artifact_redaction(root)
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
            "cleanup": "not_applicable_no_state_created",
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
    """Keep argument failures inside the bounded JSON output contract."""

    def error(self, message: str) -> None:
        del message
        raise ValidationError("invalid command-line arguments")

    def exit(self, status: int = 0, message: str | None = None) -> None:
        del status, message
        raise ValidationError("command-line help is not part of the output contract")


def main(argv: list[str] | None = None) -> int:
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
        if args.skip_baseline:
            count, artifact_bytes = len(document["cases"]), 0
        else:
            count, artifact_bytes = validate_all(args.cases, args.baseline, args.baseline_anchor, ROOT)
        sys.stdout.write(_success_payload(count, artifact_bytes) + "\n")
        return 0
    except (Exception, SystemExit) as exc:
        sys.stdout.write(_failure_payload(exc) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
