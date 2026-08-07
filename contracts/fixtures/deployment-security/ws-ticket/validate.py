#!/usr/bin/env python3
"""Validate the synthetic WebSocket-ticket boundary proof offline.

Only checked-in JSON, the local Dashboard manifest, and existing source-audit
fixtures are read. No Hermes process, proxy, socket, identity provider,
credential, or real ticket is used. All failures use one bounded redacted
marker, including when Python is run with ``-O``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import statistics
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
FIXTURE_PATH = ROOT / "ticket-fixtures.json"
BASELINE_PATH = ROOT / "probe-baseline.json"
REPO_ROOT = ROOT.parents[3]
MANIFEST_PATH = REPO_ROOT / "contracts/hermes-dashboard/manifest.md"
SCHEMA = "hermternal.deployment-security.ws-ticket.v1"
BASELINE_SCHEMA = "hermternal.deployment-security.ws-ticket-baseline.v1"
CONTRACT = "dashboard-v0.0.1"
HERMES_SOURCE_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
MANIFEST_RELATIVE = "contracts/hermes-dashboard/manifest.md"
MANIFEST_SHA256 = "0f2f1ea3af722cf2d14f6a43754a8430d20bae98d335b961c64b3f1229bd07c1"
EXPECTED_FIXTURE_CANONICAL_SHA256 = "ac65551d9b19d1bea5663f778aca95ecc7e453ff40de7d9f88f11a93de98b335"
EXPECTED_BASELINE_CANONICAL_SHA256 = "5b9030a0c8362f4b4d57187039e430dbf160d7cd65eabaf6ec73da1d87fed18e"
BASELINE_REPETITIONS = 30
# These limits are enforced by the byte scanner before json.loads allocates a
# Python tree. The approved source-audit JSON is well below them; the limits
# exist to make malformed fixture input fail closed without parser amplification.
MAX_JSON_BYTES = 256 * 1024
MAX_JSON_DEPTH = 48
MAX_JSON_TOKENS = 8192
MAX_JSON_NODES = 4096
MAX_JSON_OBJECT_KEYS = 128
MAX_JSON_ARRAY_ITEMS = 512
MAX_JSON_INTEGER_DIGITS = 100
MAX_JSON_INTEGER = 10**MAX_JSON_INTEGER_DIGITS - 1
MAX_JSON_FLOAT_TOKEN_LENGTH = 128
MAX_JSON_FLOAT_DIGITS = 64
MAX_JSON_FLOAT_EXPONENT = 308
MAX_STRING_LENGTH = 1024
MAX_JSON_STRING_BYTES = MAX_STRING_LENGTH * 4
MAX_ERROR_LENGTH = 240
SAFE_ERROR_MESSAGE = "WebSocket ticket input rejected"

STATE_IDS = ("pending", "success", "failure", "interrupted", "retry")
CASE_IDS = (
    "acquisition-pending",
    "acquisition-success",
    "acquisition-failure",
    "acquisition-interrupted",
    "acquisition-explicit-retry",
    "upgrade-query-only-success",
    "rest-ticket-query-rejected",
    "rest-ticket-header-rejected",
    "missing-ticket-rejected",
    "malformed-ticket-rejected",
    "expired-ticket-rejected",
    "reused-ticket-rejected",
    "expiry-boundary-fresh",
    "expiry-boundary-expired",
    "history-redaction",
    "log-redaction",
    "dom-redaction",
    "history-bounded-fragment-redaction",
    "log-bounded-fragment-redaction",
    "dom-bounded-fragment-redaction",
    "edge-origin-error-distinct",
    "edge-not-found-error-distinct",
    "upstream-auth-error-distinct",
    "upstream-handler-error-distinct",
)
REDaction_SURFACES = ("history", "logs", "dom")
ERROR_LAYER_IDS = ("edge", "upstream")
SOURCE_EVIDENCE_IDS = (
    "dashboard-manifest",
    "planning-auth-bootstrap",
    "planning-ticket-lifecycle",
    "ticket-fragment-source-anchor",
    "existing-ticket-fixtures",
    "existing-error-layer-fixtures",
)
PINNED_FORWARDING_SOURCE_SHA256 = "b52cc35523f891b6947fa59ac70516d955e47714877069e5ed3f06544b793c1a"
PINNED_FORWARDING_GIT_BLOB_SHA = "1fb3e6131629e7399ef12de78148ac6e7ec58d34"
PINNED_FORWARDING_EXCERPT = (
    "        except TicketInvalid as exc:",
    "            audit_log(",
    "                reason=str(exc),",
    "                path=ws.url.path,",
)
PINNED_FORWARDING_EXCERPT_SHA256 = "08cac9ae776a9ca2a1950f5735d004eb73102815170e1f9e825928013f12c5f8"
ROUTE_AUDIT_RELATIVE = "contracts/fixtures/route-allowlist/source_audit.json"
# Do not canonicalize this artifact: every citation, URL, marker, and claim
# participates in the source-evidence contract and must remain byte-identical.
PINNED_ROUTE_AUDIT_SIZE_BYTES = 20165
PINNED_ROUTE_AUDIT_SHA256 = "65a26cdea086d28ee90cc7e22d81c3e48715ea28a89f1bedb9f70c4a050aa78d"

EXPECTED_SOURCE_EVIDENCE = [
    {
        "id": "dashboard-manifest",
        "path": "contracts/hermes-dashboard/manifest.md",
        "kind": "normative_manifest",
        "markers": [
            "POST",
            "/api/auth/ws-ticket",
            "WS /api/ws",
            "single-use",
            "30-second time-to-live",
            "?ticket=...",
            "Neither the cookie nor bearer credential directly authenticates the gated upgrade",
        ],
    },
    {
        "id": "planning-auth-bootstrap",
        "path": "contracts/fixtures/source-audit/planning-reconciliation/planning_review.json",
        "kind": "source_audit_claim",
        "claim_id": "auth-bootstrap",
    },
    {
        "id": "planning-ticket-lifecycle",
        "path": "contracts/fixtures/source-audit/planning-reconciliation/planning_review.json",
        "kind": "source_audit_claim",
        "claim_id": "ticket-lifecycle",
    },
    {
        "id": "ticket-fragment-source-anchor",
        "path": "contracts/fixtures/route-allowlist/source_audit.json",
        "kind": "source_audit_anchor",
        "source_ids": ["ticket-lifecycle", "websocket-auth"],
        "ticket_source_file": "hermes_cli/dashboard_auth/ws_tickets.py",
        "ticket_lines": [90, 95],
        "ticket_markers": [
            "entry = _tickets.pop(ticket, None)",
            "truncated = (ticket[:8] + \"…\") if ticket else \"<empty>\"",
        ],
        "forwarding_source_file": "hermes_cli/web_server.py",
        "forwarding_lines": [14708, 14716],
        "forwarding_markers": ["audit_log(", "path=ws.url.path"],
        "forwarding_source_sha256": "b52cc35523f891b6947fa59ac70516d955e47714877069e5ed3f06544b793c1a",
        "forwarding_git_blob_sha": "1fb3e6131629e7399ef12de78148ac6e7ec58d34",
        "independent_forwarding_markers": [
            "except TicketInvalid as exc:",
            "reason=str(exc),",
            "path=ws.url.path,",
        ],
        "forwarding_source_excerpt": [
            "        except TicketInvalid as exc:",
            "            audit_log(",
            "                reason=str(exc),",
            "                path=ws.url.path,",
        ],
        "forwarding_source_excerpt_sha256": "08cac9ae776a9ca2a1950f5735d004eb73102815170e1f9e825928013f12c5f8",
    },
    {
        "id": "existing-ticket-fixtures",
        "path": "contracts/fixtures/behavioral-probe/probe-fixtures.json",
        "kind": "existing_synthetic_fixture",
        "case_ids": [
            "ws-chat-browser-fresh-ticket-approved",
            "ws-chat-missing-ticket-denied",
            "ws-chat-reused-ticket-denied",
            "ws-chat-expired-ticket-denied",
        ],
    },
    {
        "id": "existing-error-layer-fixtures",
        "path": "contracts/fixtures/behavioral-probe/probe-fixtures.json",
        "kind": "existing_synthetic_fixture",
        "case_ids": [
            "edge-wrong-public-origin-denied",
            "edge-unsupported-host-denied",
            "edge-unknown-path-404",
            "upstream-hermes-400-preserved",
            "upstream-hermes-4403-preserved",
        ],
    },
]

EXPECTED_STATES = [
    {
        "id": "pending",
        "meaning": "Acquisition or validation is incomplete.",
        "automatic_action": "none",
        "retry_policy": "wait_or_cancel",
    },
    {
        "id": "success",
        "meaning": "A synthetic semantic result passed the reviewed ticket boundary.",
        "automatic_action": "none",
        "retry_policy": "no_duplicate_use",
    },
    {
        "id": "failure",
        "meaning": "A known acquisition, upgrade, REST, edge, or upstream result was recorded safely.",
        "automatic_action": "none",
        "retry_policy": "explicit_idempotent_only",
    },
    {
        "id": "interrupted",
        "meaning": "The user or local adapter stopped before a result was complete.",
        "automatic_action": "preserve_last_verified_artifact",
        "retry_policy": "explicit_reread_then_retry",
    },
    {
        "id": "retry",
        "meaning": "An explicit retry reread the fixture and starts at most one idempotent local attempt.",
        "automatic_action": "none",
        "retry_policy": "coalesce_duplicate_activation",
    },
]

EXPECTED_CASE_META = {
    "acquisition-pending": ("pending", "pending", "ticket_acquisition"),
    "acquisition-success": ("success", "positive", "ticket_acquisition"),
    "acquisition-failure": ("failure", "negative", "ticket_acquisition"),
    "acquisition-interrupted": ("interrupted", "interruption", "ticket_acquisition"),
    "acquisition-explicit-retry": ("retry", "retry", "ticket_acquisition"),
    "upgrade-query-only-success": ("success", "positive", "websocket_upgrade"),
    "rest-ticket-query-rejected": ("failure", "negative", "rest"),
    "rest-ticket-header-rejected": ("failure", "negative", "rest"),
    "missing-ticket-rejected": ("failure", "negative", "websocket_upgrade"),
    "malformed-ticket-rejected": ("failure", "negative", "websocket_upgrade"),
    "expired-ticket-rejected": ("failure", "negative", "websocket_upgrade"),
    "reused-ticket-rejected": ("failure", "negative", "websocket_upgrade"),
    "expiry-boundary-fresh": ("success", "positive", "websocket_upgrade"),
    "expiry-boundary-expired": ("failure", "negative", "websocket_upgrade"),
    "history-redaction": ("success", "security", "history"),
    "log-redaction": ("success", "security", "logs"),
    "dom-redaction": ("success", "security", "dom"),
    "history-bounded-fragment-redaction": ("success", "security", "history"),
    "log-bounded-fragment-redaction": ("success", "security", "logs"),
    "dom-bounded-fragment-redaction": ("success", "security", "dom"),
    "edge-origin-error-distinct": ("failure", "negative", "edge"),
    "edge-not-found-error-distinct": ("failure", "negative", "edge"),
    "upstream-auth-error-distinct": ("failure", "negative", "upstream"),
    "upstream-handler-error-distinct": ("failure", "negative", "upstream"),
}

EXPECTED_CASE_RESULTS = {
    "acquisition-pending": {"decision": "hold", "route_result": "acquisition_pending", "ticket_action": "none", "rest_status": None, "close_code": None, "upstream_called": False, "retained_fields": ["state_class"], "automatic_retry": False, "interruption_safe": True, "error_layer": "none", "raw_value_retained": False},
    "acquisition-success": {"decision": "record_success", "route_result": "reviewed_acquisition", "ticket_action": "create_ephemeral_class", "rest_status": None, "close_code": None, "upstream_called": False, "retained_fields": ["ticket_state", "ttl_seconds", "route_class"], "automatic_retry": False, "interruption_safe": True, "error_layer": "none", "raw_value_retained": False},
    "acquisition-failure": {"decision": "record_failure", "route_result": "acquisition_rejected", "ticket_action": "none", "rest_status": 401, "close_code": None, "upstream_called": False, "retained_fields": ["error_class", "http_status"], "automatic_retry": False, "interruption_safe": True, "error_layer": "auth_boundary", "raw_value_retained": False},
    "acquisition-interrupted": {"decision": "record_interruption", "route_result": "acquisition_cancelled", "ticket_action": "discard_unverified_result", "rest_status": None, "close_code": None, "upstream_called": False, "retained_fields": ["state_class"], "automatic_retry": False, "interruption_safe": True, "error_layer": "none", "raw_value_retained": False},
    "acquisition-explicit-retry": {"decision": "start_one_attempt", "route_result": "retry_started", "ticket_action": "create_at_most_one_ephemeral_class", "rest_status": None, "close_code": None, "upstream_called": False, "retained_fields": ["state_class", "attempt_class"], "automatic_retry": False, "interruption_safe": True, "error_layer": "none", "raw_value_retained": False},
    "upgrade-query-only-success": {"decision": "allow_upgrade", "route_result": "reviewed_upgrade_query_only", "ticket_action": "consume_once", "rest_status": None, "close_code": None, "upstream_called": False, "retained_fields": ["route_class", "ticket_state", "upgrade_result"], "automatic_retry": False, "interruption_safe": True, "error_layer": "none", "raw_value_retained": False},
    "rest-ticket-query-rejected": {"decision": "deny_rest", "route_result": "ticket_not_rest_auth", "ticket_action": "do_not_consume", "rest_status": 403, "close_code": None, "upstream_called": False, "retained_fields": ["error_class", "http_status", "layer"], "automatic_retry": False, "interruption_safe": True, "error_layer": "client_boundary", "raw_value_retained": False},
    "rest-ticket-header-rejected": {"decision": "deny_rest", "route_result": "ticket_not_bearer_credential", "ticket_action": "do_not_consume", "rest_status": 403, "close_code": None, "upstream_called": False, "retained_fields": ["error_class", "http_status", "layer"], "automatic_retry": False, "interruption_safe": True, "error_layer": "client_boundary", "raw_value_retained": False},
    "missing-ticket-rejected": {"decision": "deny_upgrade", "route_result": "ticket_missing", "ticket_action": "mint_fresh_after_explicit_recovery", "rest_status": None, "close_code": 4401, "upstream_called": False, "retained_fields": ["error_class", "close_code"], "automatic_retry": False, "interruption_safe": True, "error_layer": "upgrade_boundary", "raw_value_retained": False},
    "malformed-ticket-rejected": {"decision": "deny_upgrade", "route_result": "ticket_malformed", "ticket_action": "discard_without_log_value", "rest_status": None, "close_code": 4401, "upstream_called": False, "retained_fields": ["error_class", "close_code"], "automatic_retry": False, "interruption_safe": True, "error_layer": "upgrade_boundary", "raw_value_retained": False},
    "expired-ticket-rejected": {"decision": "deny_upgrade", "route_result": "ticket_expired", "ticket_action": "discard_without_reuse", "rest_status": None, "close_code": 4401, "upstream_called": False, "retained_fields": ["error_class", "close_code", "ttl_seconds"], "automatic_retry": False, "interruption_safe": True, "error_layer": "upgrade_boundary", "raw_value_retained": False},
    "reused-ticket-rejected": {"decision": "deny_upgrade", "route_result": "ticket_reused", "ticket_action": "discard_without_reuse", "rest_status": None, "close_code": 4401, "upstream_called": False, "retained_fields": ["error_class", "close_code", "single_use"], "automatic_retry": False, "interruption_safe": True, "error_layer": "upgrade_boundary", "raw_value_retained": False},
    "expiry-boundary-fresh": {"decision": "allow_upgrade", "route_result": "ticket_within_ttl", "ticket_action": "consume_once", "rest_status": None, "close_code": None, "upstream_called": False, "retained_fields": ["ttl_seconds", "ticket_state"], "automatic_retry": False, "interruption_safe": True, "error_layer": "none", "raw_value_retained": False},
    "expiry-boundary-expired": {"decision": "deny_upgrade", "route_result": "ticket_expired_at_boundary", "ticket_action": "discard_without_reuse", "rest_status": None, "close_code": 4401, "upstream_called": False, "retained_fields": ["error_class", "close_code", "ttl_seconds"], "automatic_retry": False, "interruption_safe": True, "error_layer": "upgrade_boundary", "raw_value_retained": False},
    "history-redaction": {"decision": "redact", "route_result": "history_semantic_marker_only", "ticket_action": "remove_raw_value", "rest_status": None, "close_code": None, "upstream_called": False, "retained_fields": ["route_class", "result_class", "status_class"], "automatic_retry": False, "interruption_safe": True, "error_layer": "history", "raw_value_retained": False},
    "log-redaction": {"decision": "redact", "route_result": "log_semantic_marker_only", "ticket_action": "retain_bounded_reason_class", "rest_status": None, "close_code": None, "upstream_called": False, "retained_fields": ["error_class", "layer", "close_code"], "automatic_retry": False, "interruption_safe": True, "error_layer": "logs", "raw_value_retained": False},
    "dom-redaction": {"decision": "redact", "route_result": "dom_error_state_only", "ticket_action": "never_render_raw_value", "rest_status": None, "close_code": None, "upstream_called": False, "retained_fields": ["error_state_label", "retry_action_label"], "automatic_retry": False, "interruption_safe": True, "error_layer": "dom", "raw_value_retained": False},
    "history-bounded-fragment-redaction": {"decision": "redact", "route_result": "history_bounded_fragment_removed", "ticket_action": "remove_bounded_fragment", "rest_status": None, "close_code": None, "upstream_called": False, "retained_fields": ["route_class", "result_class", "status_class"], "automatic_retry": False, "interruption_safe": True, "error_layer": "history", "raw_value_retained": False},
    "log-bounded-fragment-redaction": {"decision": "redact", "route_result": "log_bounded_fragment_removed", "ticket_action": "remove_bounded_fragment", "rest_status": None, "close_code": None, "upstream_called": False, "retained_fields": ["error_class", "layer", "close_code"], "automatic_retry": False, "interruption_safe": True, "error_layer": "logs", "raw_value_retained": False},
    "dom-bounded-fragment-redaction": {"decision": "redact", "route_result": "dom_bounded_fragment_removed", "ticket_action": "remove_bounded_fragment", "rest_status": None, "close_code": None, "upstream_called": False, "retained_fields": ["error_state_label", "retry_action_label"], "automatic_retry": False, "interruption_safe": True, "error_layer": "dom", "raw_value_retained": False},
    "edge-origin-error-distinct": {"decision": "deny_edge", "route_result": "edge_origin_denied", "ticket_action": "do_not_consume", "rest_status": 403, "close_code": None, "upstream_called": False, "retained_fields": ["error_class", "http_status", "layer"], "automatic_retry": False, "interruption_safe": True, "error_layer": "edge", "raw_value_retained": False},
    "edge-not-found-error-distinct": {"decision": "deny_edge", "route_result": "edge_not_found", "ticket_action": "not_applicable", "rest_status": 404, "close_code": None, "upstream_called": False, "retained_fields": ["error_class", "http_status", "layer"], "automatic_retry": False, "interruption_safe": True, "error_layer": "edge", "raw_value_retained": False},
    "upstream-auth-error-distinct": {"decision": "preserve_upstream", "route_result": "upstream_auth_rejected", "ticket_action": "discard_without_reuse", "rest_status": None, "close_code": 4403, "upstream_called": True, "retained_fields": ["error_class", "close_code", "layer"], "automatic_retry": False, "interruption_safe": True, "error_layer": "upstream", "raw_value_retained": False},
    "upstream-handler-error-distinct": {"decision": "preserve_upstream", "route_result": "upstream_handler_error", "ticket_action": "do_not_reuse_without_source_result", "rest_status": 400, "close_code": None, "upstream_called": True, "retained_fields": ["error_class", "http_status", "layer"], "automatic_retry": False, "interruption_safe": True, "error_layer": "upstream", "raw_value_retained": False},
}

SAFE_FAILURE_CODES = frozenset({"ws_ticket_cli_invalid", "ws_ticket_fixture_invalid"})


class ContractError(ValueError):
    """Internal failure whose public representation contains no input detail."""

    def __init__(self, _detail: str = "") -> None:
        super().__init__(SAFE_ERROR_MESSAGE)


class ArgumentParseError(ContractError):
    """Safe command-line parse failure."""


class FailClosedArgumentParser(argparse.ArgumentParser):
    """Reject unknown flags without echoing the flag or usage text."""

    def error(self, _message: str) -> None:
        raise ArgumentParseError()


def require(condition: bool, detail: str = "") -> None:
    if not condition:
        raise ContractError(detail)


def _reject_constant(_value: str) -> None:
    raise ContractError()


def _parse_int(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    require(bool(digits) and len(digits) <= MAX_JSON_INTEGER_DIGITS)
    parsed = int(value)
    require(abs(parsed) <= MAX_JSON_INTEGER)
    return parsed


def _parse_float(value: str) -> float:
    require(len(value) <= MAX_JSON_FLOAT_TOKEN_LENGTH)
    mantissa, separator, exponent_text = value.lower().partition("e")
    digit_count = sum(character.isdigit() for character in mantissa)
    require(0 < digit_count <= MAX_JSON_FLOAT_DIGITS)
    if separator:
        require(bool(exponent_text))
        exponent = int(exponent_text)
        require(abs(exponent) <= MAX_JSON_FLOAT_EXPONENT)
    parsed = float(value)
    require(math.isfinite(parsed))
    return parsed


def _reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    require(len(pairs) <= MAX_JSON_OBJECT_KEYS)
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError()
        result[key] = value
    return result


class _BoundedJSONScanner:
    """Scan JSON syntax and resource bounds before the stdlib builds a tree."""

    _HEX = frozenset(b"0123456789abcdefABCDEF")
    _WHITESPACE = frozenset(b" \t\r\n")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.index = 0
        self.tokens = 0
        self.nodes = 0

    def _token(self) -> None:
        self.tokens += 1
        require(self.tokens <= MAX_JSON_TOKENS)

    def _node(self) -> None:
        self.nodes += 1
        require(self.nodes <= MAX_JSON_NODES)

    def _skip_whitespace(self) -> None:
        while self.index < len(self.data) and self.data[self.index] in self._WHITESPACE:
            self.index += 1

    def scan(self) -> None:
        self._skip_whitespace()
        require(self.index < len(self.data))
        self._parse_value(0)
        self._skip_whitespace()
        require(self.index == len(self.data))

    def _parse_value(self, depth: int) -> None:
        require(depth <= MAX_JSON_DEPTH and self.index < len(self.data))
        self._node()
        self._token()
        marker = self.data[self.index]
        if marker == ord("{"):
            self._parse_object(depth)
        elif marker == ord("["):
            self._parse_array(depth)
        elif marker == ord('"'):
            self._parse_string()
        elif marker in (ord("t"), ord("f"), ord("n")):
            self._parse_literal()
        elif marker == ord("-") or 48 <= marker <= 57:
            self._parse_number()
        else:
            raise ContractError()

    def _parse_object(self, depth: int) -> None:
        self.index += 1
        self._skip_whitespace()
        if self.index < len(self.data) and self.data[self.index] == ord("}"):
            self.index += 1
            return
        key_count = 0
        while True:
            key_count += 1
            require(key_count <= MAX_JSON_OBJECT_KEYS)
            self._skip_whitespace()
            require(self.index < len(self.data) and self.data[self.index] == ord('"'))
            self._token()
            self._parse_string()
            self._skip_whitespace()
            require(self.index < len(self.data) and self.data[self.index] == ord(":"))
            self.index += 1
            self._skip_whitespace()
            self._parse_value(depth + 1)
            self._skip_whitespace()
            require(self.index < len(self.data))
            delimiter = self.data[self.index]
            if delimiter == ord("}"):
                self.index += 1
                return
            require(delimiter == ord(","))
            self.index += 1

    def _parse_array(self, depth: int) -> None:
        self.index += 1
        self._skip_whitespace()
        if self.index < len(self.data) and self.data[self.index] == ord("]"):
            self.index += 1
            return
        item_count = 0
        while True:
            item_count += 1
            require(item_count <= MAX_JSON_ARRAY_ITEMS)
            self._skip_whitespace()
            self._parse_value(depth + 1)
            self._skip_whitespace()
            require(self.index < len(self.data))
            delimiter = self.data[self.index]
            if delimiter == ord("]"):
                self.index += 1
                return
            require(delimiter == ord(","))
            self.index += 1

    def _parse_string(self) -> None:
        require(self.data[self.index] == ord('"'))
        self.index += 1
        start = self.index
        while True:
            require(self.index < len(self.data))
            marker = self.data[self.index]
            if marker == ord('"'):
                require(self.index - start <= MAX_JSON_STRING_BYTES)
                self.index += 1
                return
            require(marker >= 0x20)
            if marker == ord("\\"):
                self.index += 1
                require(self.index < len(self.data))
                escaped = self.data[self.index]
                require(escaped in b'"\\/bfnrtu')
                if escaped == ord("u"):
                    require(self.index + 4 < len(self.data))
                    for offset in range(1, 5):
                        require(self.data[self.index + offset] in self._HEX)
                    self.index += 4
            self.index += 1
            require(self.index - start <= MAX_JSON_STRING_BYTES)

    def _parse_literal(self) -> None:
        for literal in (b"true", b"false", b"null"):
            if self.data.startswith(literal, self.index):
                self.index += len(literal)
                return
        raise ContractError()

    def _parse_number(self) -> None:
        start = self.index
        if self.data[self.index] == ord("-"):
            self.index += 1
            require(self.index < len(self.data))
        if self.data[self.index] == ord("0"):
            self.index += 1
            if self.index < len(self.data) and 48 <= self.data[self.index] <= 57:
                raise ContractError()
        else:
            require(49 <= self.data[self.index] <= 57)
            while self.index < len(self.data) and 48 <= self.data[self.index] <= 57:
                self.index += 1
        is_float = False
        if self.index < len(self.data) and self.data[self.index] == ord("."):
            is_float = True
            self.index += 1
            require(self.index < len(self.data) and 48 <= self.data[self.index] <= 57)
            while self.index < len(self.data) and 48 <= self.data[self.index] <= 57:
                self.index += 1
        if self.index < len(self.data) and self.data[self.index] in (ord("e"), ord("E")):
            is_float = True
            self.index += 1
            if self.index < len(self.data) and self.data[self.index] in (ord("+"), ord("-")):
                self.index += 1
            require(self.index < len(self.data) and 48 <= self.data[self.index] <= 57)
            while self.index < len(self.data) and 48 <= self.data[self.index] <= 57:
                self.index += 1
        token = self.data[start:self.index].decode("ascii")
        if is_float:
            _parse_float(token)
        else:
            _parse_int(token)


def load_json(path: Path) -> Any:
    try:
        raw = path.read_bytes()
        require(len(raw) <= MAX_JSON_BYTES)
        _BoundedJSONScanner(raw).scan()
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate,
            parse_constant=_reject_constant,
            parse_int=_parse_int,
            parse_float=_parse_float,
        )
    except ContractError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, OverflowError, ValueError) as exc:
        raise ContractError() from exc
    _validate_json_tree(value, 0)
    return value


def _validate_json_tree(value: Any, depth: int) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ContractError()
    if type(value) is dict:
        require(len(value) <= MAX_JSON_OBJECT_KEYS)
        for key, item in value.items():
            require(type(key) is str and bool(key) and len(key) <= MAX_STRING_LENGTH)
            _validate_json_tree(item, depth + 1)
    elif type(value) is list:
        require(len(value) <= MAX_JSON_ARRAY_ITEMS)
        for item in value:
            _validate_json_tree(item, depth + 1)
    elif type(value) is str:
        require(len(value) <= MAX_STRING_LENGTH and len(value.encode("utf-8")) <= MAX_JSON_STRING_BYTES and "\x00" not in value)
    elif type(value) is int:
        require(len(str(abs(value))) <= MAX_JSON_INTEGER_DIGITS and abs(value) <= MAX_JSON_INTEGER)
    elif type(value) is float:
        require(math.isfinite(value))
    else:
        require(value is None or type(value) is bool)


def exact_keys(value: Any, expected: tuple[str, ...]) -> None:
    require(type(value) is dict)
    require(tuple(value.keys()) == expected)


def string(value: Any) -> str:
    require(type(value) is str and bool(value) and len(value) <= MAX_STRING_LENGTH)
    return value


def nullable_string(value: Any) -> None:
    require(value is None or (type(value) is str and len(value) <= MAX_STRING_LENGTH))


def boolean(value: Any) -> bool:
    require(type(value) is bool)
    return value


def integer(value: Any) -> int:
    require(type(value) is int and abs(value) <= MAX_JSON_INTEGER)
    return value


def string_list(value: Any, *, allow_empty: bool = False) -> list[str]:
    require(type(value) is list)
    require(allow_empty or bool(value))
    result = [string(item) for item in value]
    require(len(set(result)) == len(result))
    return result


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise ContractError() from exc


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _load_pinned_route_audit(path: Path) -> Any:
    """Read route-audit evidence only after its full metadata bytes are pinned."""
    try:
        raw = path.read_bytes()
    except (OSError, UnicodeError) as exc:
        raise ContractError() from exc
    require(len(raw) == PINNED_ROUTE_AUDIT_SIZE_BYTES)
    require(hashlib.sha256(raw).hexdigest() == PINNED_ROUTE_AUDIT_SHA256)
    return load_json(path)


def _validate_source_evidence(value: Any) -> None:
    require(value == EXPECTED_SOURCE_EVIDENCE)
    require(tuple(item["id"] for item in value) == SOURCE_EVIDENCE_IDS)
    for entry in value:
        path_value = string(entry["path"])
        path = Path(path_value)
        require(not path.is_absolute() and ".." not in path.parts)
        root = REPO_ROOT.resolve()
        resolved = (root / path_value).resolve()
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise ContractError() from exc
        require(resolved.is_file())
        try:
            text = resolved.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise ContractError() from exc
        if entry["kind"] == "normative_manifest":
            for marker in entry["markers"]:
                require(marker in text)
        elif entry["kind"] == "source_audit_claim":
            review = load_json(resolved)
            require(type(review) is dict and type(review.get("claims")) is list)
            claim_ids = [item.get("id") for item in review["claims"] if type(item) is dict]
            require(entry["claim_id"] in claim_ids)
        elif entry["kind"] == "source_audit_anchor":
            audit = _load_pinned_route_audit(resolved)
            require(type(audit) is dict and audit.get("hermes_source_sha") == HERMES_SOURCE_SHA)
            citations = {item.get("id"): item for item in audit.get("source_citations", []) if type(item) is dict}
            require(tuple(entry["source_ids"]) == ("ticket-lifecycle", "websocket-auth"))
            ticket = citations.get("ticket-lifecycle")
            forwarding = citations.get("websocket-auth")
            require(type(ticket) is dict and type(forwarding) is dict)
            require(ticket["path"] == entry["ticket_source_file"])
            require(forwarding["path"] == entry["forwarding_source_file"])
            require(entry["ticket_lines"] == [90, 95] and entry["forwarding_lines"] == [14708, 14716])
            require(90 >= ticket["lines"][0] and 95 <= ticket["lines"][1])
            require(14708 >= forwarding["lines"][0] and 14716 <= forwarding["lines"][1])
            require(all(marker in ticket["markers"] for marker in entry["ticket_markers"]))
            require(all(marker in forwarding["markers"] for marker in entry["forwarding_markers"]))
            require(entry["forwarding_source_sha256"] == PINNED_FORWARDING_SOURCE_SHA256 == forwarding["sha256"])
            require(entry["forwarding_git_blob_sha"] == PINNED_FORWARDING_GIT_BLOB_SHA == forwarding["git_blob_sha"])
            require(tuple(entry["independent_forwarding_markers"]) == (
                "except TicketInvalid as exc:",
                "reason=str(exc),",
                "path=ws.url.path,",
            ))
            excerpt = tuple(entry["forwarding_source_excerpt"])
            require(excerpt == PINNED_FORWARDING_EXCERPT)
            require(entry["forwarding_source_excerpt_sha256"] == PINNED_FORWARDING_EXCERPT_SHA256)
            require(hashlib.sha256("\n".join(excerpt).encode("utf-8")).hexdigest() == PINNED_FORWARDING_EXCERPT_SHA256)
        else:
            existing = load_json(resolved)
            require(type(existing) is dict and type(existing.get("cases")) is list)
            existing_ids = {item.get("id") for item in existing["cases"] if type(item) is dict}
            require(set(entry["case_ids"]) <= existing_ids)


RETAINED_TEXT_KEYS = frozenset({
    "claim",
    "dom",
    "errorreason",
    "history",
    "log",
    "logs",
    "meaning",
    "message",
    "notes",
    "purpose",
    "reason",
    "retainedtext",
    "summary",
    "text",
})


BASE64_TOKEN_PATTERN = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{7,}(?:={1,2})?)(?![A-Za-z0-9+/=])")
# A padded token can be followed immediately by an alphanumeric suffix. Keep
# this separate from the delimiter-bounded matcher so `SGVsbG8=foo` cannot
# evade the retained-text boundary check.
PADDED_BASE64_SUFFIX_PATTERN = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{7,}={1,2})(?=[A-Za-z0-9+/])")
BASE64_CONTEXT_PATTERN = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])(?:base64|encoded|payload|token|fragment|credential|secret|value)\b\s*[:=]?\s*$"
)
SOURCE_TICKET_FRAGMENT_PATTERN = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])(?:unknown\s+ticket|ticket\s+fragment|ticket)\s*[:=]\s*[A-Za-z0-9_-]{8}(?:…|\.{3})?(?![A-Za-z0-9_-])"
)
RECOGNIZED_AUTHORIZATION_PATTERN = re.compile(
    r"(?i)(?:\bauthorization\s*:\s*(?:basic|bearer)\s+\S+|\bbearer\s+(?!(?:credential|credentials|fallback|value|values)\b)\S+|\bcookie\s*:\s*\S+)"
)


def _is_base64_token(value: str) -> bool:
    if len(value) < 7 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value):
        return False
    core = value.rstrip("=")
    padding = value[len(core):]
    if len(core) % 4 == 1:
        return False
    if padding and len(value) % 4 != 0:
        return False
    return True


def _looks_like_embedded_base64(value: str, match: re.Match[str]) -> bool:
    token = match.group(1)
    if not _is_base64_token(token):
        return False
    uppercase_count = sum(character.isupper() for character in token)
    if "=" in token or (uppercase_count >= 2 and any(character.islower() for character in token)):
        return True
    if token.islower() or token.isdigit():
        context = value[:match.start()]
        if BASE64_CONTEXT_PATTERN.search(context):
            return True
        if len(token) >= 8:
            if len(set(token)) == 1:
                return True
            deltas = [ord(next_character) - ord(character) for character, next_character in zip(token, token[1:])]
            if deltas and len(set(deltas)) == 1 and deltas[0] in {-1, 1}:
                return True
    return False


def _scan_retained_text(value: str) -> None:
    data_url_pattern = re.compile(r"(?i)(?:^|[\s(\"'=,:;|])data:[^\s,]+,")
    file_url_pattern = re.compile(r"(?i)\bfile://")
    absolute_path_pattern = re.compile(r"(?:^|(?<=[\s(\"'=,:;|]))/(?:[A-Za-z0-9._~+\-]+/)*[A-Za-z0-9._~+\-]+")
    windows_path_pattern = re.compile(r"(?:^|(?<=[\s(\"'=,:;|]))[A-Za-z]:[\\/][^\s,;|]+")
    relative_path_pattern = re.compile(r"(?:^|(?<=[\s(\"'=,:;|]))(?:\./|\.\./)?[A-Za-z0-9._~-]+(?:[/\\][A-Za-z0-9._~-]+)+")
    filename_pattern = re.compile(r"(?:^|(?<=[\s(\"'=,:;|]))(?:[A-Za-z0-9_-]+\.)+[A-Za-z0-9]{1,16}(?=$|[\s\"'),;|])")
    require(not data_url_pattern.search(value))
    require(not file_url_pattern.search(value))
    require(not absolute_path_pattern.search(value))
    require(not windows_path_pattern.search(value))
    require(not relative_path_pattern.search(value))
    require(not filename_pattern.search(value))
    require(not SOURCE_TICKET_FRAGMENT_PATTERN.search(value))
    for match in PADDED_BASE64_SUFFIX_PATTERN.finditer(value):
        require(not _is_base64_token(match.group(1)))

    stripped = value.strip()
    if not any(character.isspace() for character in stripped):
        # Retained text carries semantic copy only; arbitrary base64-shaped
        # payloads are forbidden even when padding or case makes them subtle.
        require(not _is_base64_token(stripped))
    for match in BASE64_TOKEN_PATTERN.finditer(value):
        if value[:match.start()].strip() or value[match.end():].strip():
            require(not _looks_like_embedded_base64(value, match))


def _scan_redaction(value: Any, *, retained_text: bool = False) -> None:
    forbidden_keys = {
        "rawticket",
        "rawticketvalue",
        "ticketvalue",
        "cookievalue",
        "bearervalue",
        "authorizationvalue",
        "credentialvalue",
        "password",
        "secret",
        "prompttext",
        "transcriptbytes",
        "hostname",
        "hostnames",
    }
    jwt_pattern = re.compile(r"^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$")
    secret_pattern = re.compile(r"\b(?:Bearer|Cookie)\s+[A-Za-z0-9._~+/=-]{12,}", re.IGNORECASE)
    if type(value) is dict:
        for key, item in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", key.lower())
            require(normalized not in forbidden_keys)
            item_is_retained_text = retained_text or normalized in RETAINED_TEXT_KEYS or "retained" in normalized
            _scan_redaction(item, retained_text=item_is_retained_text)
    elif type(value) is list:
        for item in value:
            _scan_redaction(item, retained_text=retained_text)
    elif type(value) is str:
        require(not jwt_pattern.fullmatch(value))
        require(not secret_pattern.search(value))
        if retained_text:
            require(not RECOGNIZED_AUTHORIZATION_PATTERN.search(value))
            _scan_retained_text(value)


def _validate_manifest_digest() -> None:
    try:
        data = MANIFEST_PATH.read_bytes()
    except OSError as exc:
        raise ContractError() from exc
    require(hashlib.sha256(data).hexdigest() == MANIFEST_SHA256)


def _validate_ticket_policy(value: Any) -> None:
    exact_keys(value, ("acquisition", "upgrade", "ttl_seconds", "expiry_boundary", "single_use", "reuse_policy", "fallback"))
    exact_keys(value["acquisition"], ("method", "path", "credential_context", "result", "failure_policy"))
    require(value["acquisition"] == {
        "method": "POST",
        "path": "/api/auth/ws-ticket",
        "credential_context": "authenticated_session_without_stored_value",
        "result": "ephemeral_ticket_class_only",
        "failure_policy": "fail_closed",
    })
    exact_keys(value["upgrade"], ("method", "path", "query_key", "query_value_representation", "cookie_direct_auth", "bearer_direct_auth", "rest_ticket_use", "required_headers"))
    require(value["upgrade"] == {
        "method": "GET",
        "path": "/api/ws",
        "query_key": "ticket",
        "query_value_representation": "synthetic_placeholder_only",
        "cookie_direct_auth": "forbidden",
        "bearer_direct_auth": "forbidden",
        "rest_ticket_use": "forbidden",
        "required_headers": ["Upgrade: websocket", "Connection: upgrade"],
    })
    require(integer(value["ttl_seconds"]) == 30)
    require(value["expiry_boundary"] == "age_seconds_less_than_30_is_fresh_age_seconds_at_or_above_30_is_expired")
    require(value["single_use"] is True)
    require(value["reuse_policy"] == "deny_and_mint_fresh_after_explicit_recovery")
    require(value["fallback"] == "none")


def _validate_case(item: Any) -> None:
    exact_keys(item, ("id", "state", "kind", "surface", "request", "expected", "notes"))
    case_id = string(item["id"])
    require(case_id in EXPECTED_CASE_META)
    state, kind, surface = EXPECTED_CASE_META[case_id]
    require(item["state"] == state and item["kind"] == kind and item["surface"] == surface)
    exact_keys(item["request"], ("method", "path", "layer", "query_keys", "query_value_representation", "ticket_state", "ticket_age_seconds", "credential_context", "upgrade_headers", "user_action"))
    string(item["request"]["method"])
    string(item["request"]["path"])
    string(item["request"]["layer"])
    string_list(item["request"]["query_keys"], allow_empty=True)
    string(item["request"]["query_value_representation"])
    string(item["request"]["ticket_state"])
    age = item["request"]["ticket_age_seconds"]
    require(age is None or (type(age) is int and 0 <= age <= 3600))
    string(item["request"]["credential_context"])
    string(item["request"]["upgrade_headers"])
    string(item["request"]["user_action"])
    exact_keys(item["expected"], ("decision", "route_result", "ticket_action", "rest_status", "close_code", "upstream_called", "retained_fields", "automatic_retry", "interruption_safe", "error_layer", "raw_value_retained", "bounded_fragment_retained"))
    expected_result = dict(EXPECTED_CASE_RESULTS[case_id])
    expected_result["bounded_fragment_retained"] = False
    require(item["expected"] == expected_result)
    nullable_string(item["expected"]["route_result"])
    for key in ("rest_status", "close_code"):
        value = item["expected"][key]
        require(value is None or type(value) is int)
    boolean(item["expected"]["upstream_called"])
    string_list(item["expected"]["retained_fields"], allow_empty=True)
    boolean(item["expected"]["automatic_retry"])
    boolean(item["expected"]["interruption_safe"])
    string(item["expected"]["error_layer"])
    boolean(item["expected"]["raw_value_retained"])
    boolean(item["expected"]["bounded_fragment_retained"])
    require(item["expected"]["bounded_fragment_retained"] is False)
    string(item["notes"])


def _validate_fixture_shape(fixture: Any) -> None:
    require(type(fixture) is dict)
    exact_keys(fixture, (
        "schema", "issue", "operation", "contract", "hermes_source_sha", "route_manifest", "route_manifest_sha256", "synthetic_only", "purpose", "proof", "source_evidence", "counts", "ticket_policy", "states", "cases", "redaction", "error_layers", "evidence_requirements", "accessibility",
    ))
    require(fixture["schema"] == SCHEMA)
    require(fixture["issue"] == "DEP-07M/#208")
    require(fixture["operation"] == "ticket_boundary_proof")
    require(fixture["contract"] == CONTRACT)
    require(fixture["hermes_source_sha"] == HERMES_SOURCE_SHA)
    require(fixture["route_manifest"] == MANIFEST_RELATIVE)
    require(fixture["route_manifest_sha256"] == MANIFEST_SHA256)
    require(fixture["synthetic_only"] is True)
    string(fixture["purpose"])
    exact_keys(fixture["proof"], ("status", "live_run", "compatible", "network_access", "hermes_process", "proxy_process", "credential_material", "real_ticket_values"))
    require(fixture["proof"] == {
        "status": "synthetic_only",
        "live_run": False,
        "compatible": False,
        "network_access": "forbidden",
        "hermes_process": "not_started",
        "proxy_process": "not_started",
        "credential_material": "absent",
        "real_ticket_values": "absent",
    })
    _validate_manifest_digest()
    _validate_source_evidence(fixture["source_evidence"])
    exact_keys(fixture["counts"], ("states", "cases", "redaction_surfaces", "error_layers"))
    for count_key in ("states", "cases", "redaction_surfaces", "error_layers"):
        integer(fixture["counts"][count_key])
    require(fixture["counts"] == {"states": 5, "cases": 24, "redaction_surfaces": 3, "error_layers": 2})
    _validate_ticket_policy(fixture["ticket_policy"])
    require(fixture["states"] == EXPECTED_STATES)
    for state in fixture["states"]:
        exact_keys(state, ("id", "meaning", "automatic_action", "retry_policy"))
        string(state["id"])
        string(state["meaning"])
        string(state["automatic_action"])
        string(state["retry_policy"])
    cases = fixture["cases"]
    require(type(cases) is list and tuple(item.get("id") for item in cases if type(item) is dict) == CASE_IDS)
    for item in cases:
        _validate_case(item)
    exact_keys(fixture["redaction"], ("synthetic_markers_only", "forbidden_data_classes", "retained_marker_classes", "history_policy", "log_policy", "dom_policy", "max_controlled_error_length", "no_raw_input_echo", "no_traceback"))
    integer(fixture["redaction"]["max_controlled_error_length"])
    require(fixture["redaction"] == {
        "synthetic_markers_only": True,
        "forbidden_data_classes": ["raw_ticket_values", "cookies", "bearer_values", "authorization_values", "credentials", "prompt_text", "transcript_bytes", "hostnames", "user_data", "bounded_ticket_fragments"],
        "retained_marker_classes": ["ticket_state", "ttl_seconds", "route_class", "result_class", "error_class", "http_status", "close_code", "layer"],
        "history_policy": "semantic_marker_only",
        "log_policy": "bounded_semantic_reason_only",
        "dom_policy": "semantic_error_state_only",
        "max_controlled_error_length": MAX_ERROR_LENGTH,
        "no_raw_input_echo": True,
        "no_traceback": True,
    })
    layers = fixture["error_layers"]
    require(type(layers) is list and tuple(item.get("id") for item in layers if type(item) is dict) == ERROR_LAYER_IDS)
    require(layers == [
        {"id": "edge", "statuses": [403, 404], "upstream_called": False, "meaning": "Public-origin, host, or route policy result before Hermes."},
        {"id": "upstream", "statuses": [400, 4403], "upstream_called": True, "meaning": "Synthetic result returned by the reviewed upstream boundary."},
    ])
    for layer in layers:
        exact_keys(layer, ("id", "statuses", "upstream_called", "meaning"))
        string_list([layer["id"]])
        require(type(layer["statuses"]) is list and all(type(status) is int for status in layer["statuses"]))
        boolean(layer["upstream_called"])
        string(layer["meaning"])
    require(fixture["evidence_requirements"] == [
        "acquisition_route_is_reviewed",
        "ticket_is_upgrade_query_only",
        "rest_ticket_use_is_rejected",
        "missing_malformed_expired_and_reused_cases_are_present",
        "exact_30_second_expiry_boundary_is_recorded",
        "edge_and_upstream_results_remain_distinct",
        "history_log_and_dom_redaction_are_recorded",
        "bounded_ticket_fragments_are_removed_from_history_logs_and_dom",
        "pending_success_failure_interruption_and_retry_states_are_present",
        "unknown_or_malformed_fixture_input_fails_closed",
        "no_real_ticket_or_credential_value_is_retained",
        "normal_and_optimized_baselines_have_no_threshold",
    ])
    exact_keys(fixture["accessibility"], ("status", "reason", "preserved_requirements"))
    require(fixture["accessibility"]["status"] == "not_applicable")
    string(fixture["accessibility"]["reason"])
    require(fixture["accessibility"]["preserved_requirements"] == ["keyboard_and_focus", "screen_reader_and_voiceover", "switch_control", "dynamic_type_and_browser_zoom", "contrast", "reduced_motion", "reduced_transparency", "44px_effective_touch_targets"])
    _scan_redaction(fixture)


def validate_fixture(fixture: dict[str, Any] | None = None) -> dict[str, int]:
    if fixture is None:
        fixture = load_json(FIXTURE_PATH)
    _validate_fixture_shape(fixture)
    require(canonical_sha256(fixture) == EXPECTED_FIXTURE_CANONICAL_SHA256)
    return {"case_count": len(fixture["cases"]), "state_count": len(fixture["states"])}


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(fraction * len(ordered)) - 1))
    return ordered[index]


def _summary(values: list[float]) -> dict[str, float]:
    return {
        "min": round(min(values), 3),
        "p50": round(_percentile(values, 0.50), 3),
        "p95": round(_percentile(values, 0.95), 3),
        "max": round(max(values), 3),
        "mean": round(statistics.mean(values), 3),
    }


def _validate_samples(value: Any) -> list[float]:
    require(type(value) is list and len(value) == BASELINE_REPETITIONS)
    samples: list[float] = []
    for item in value:
        require(type(item) in {int, float} and type(item) is not bool)
        numeric = float(item)
        require(math.isfinite(numeric) and 0 < numeric < 100000)
        samples.append(numeric)
    require(len(set(samples)) >= 3)
    return samples


def _baseline_canonical_payload(baseline: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": baseline["schema"],
        "fixture": baseline["fixture"],
        "threshold": baseline["threshold"],
        "workload": baseline["workload"],
        "observations": baseline["observations"],
        "environment": baseline["environment"],
        "integrity": {"fixture_canonical_sha256": baseline["integrity"]["fixture_canonical_sha256"]},
        "redaction": baseline["redaction"],
    }


def _artifact_manifest() -> list[dict[str, Any]]:
    paths = ("README.md", "probe-baseline.json", "ticket-fixtures.json", "test_validate.py", "validate.py")
    records: list[dict[str, Any]] = []
    for relative in paths:
        try:
            data = (ROOT / relative).read_bytes()
        except OSError as exc:
            raise ContractError() from exc
        if relative == "probe-baseline.json":
            records.append({"path": relative, "sha256": EXPECTED_BASELINE_CANONICAL_SHA256, "size_bytes": len(data)})
        else:
            records.append({"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)})
    return records


def validate_baseline(baseline: dict[str, Any] | None = None) -> dict[str, int]:
    if baseline is None:
        baseline = load_json(BASELINE_PATH)
    exact_keys(baseline, ("schema", "fixture", "threshold", "workload", "observations", "environment", "integrity", "redaction"))
    require(baseline["schema"] == BASELINE_SCHEMA)
    require(baseline["fixture"] == "ticket-fixtures.json")
    require(baseline["threshold"] is None)
    exact_keys(baseline["workload"], ("id", "metric", "synthetic_only", "repetitions"))
    integer(baseline["workload"]["repetitions"])
    require(baseline["workload"] == {"id": "ws-ticket-validator", "metric": "validation_duration_ms", "synthetic_only": True, "repetitions": 30})
    exact_keys(baseline["observations"], ("normal", "optimized"))
    for mode in ("normal", "optimized"):
        exact_keys(baseline["observations"][mode], ("samples_ms", "summary"))
        samples = _validate_samples(baseline["observations"][mode]["samples_ms"])
        exact_keys(baseline["observations"][mode]["summary"], ("min", "p50", "p95", "max", "mean"))
        require(baseline["observations"][mode]["summary"] == _summary(samples))
    exact_keys(baseline["environment"], ("python", "platform", "machine", "build_mode", "live_run"))
    for key in ("python", "platform", "machine"):
        string(baseline["environment"][key])
    require(baseline["environment"]["build_mode"] == "N/A")
    require(baseline["environment"]["live_run"] is False)
    exact_keys(baseline["integrity"], ("fixture_canonical_sha256", "baseline_canonical_sha256", "artifact_manifest_sha256", "artifact_manifest", "baseline_file_size_bytes"))
    require(baseline["integrity"]["fixture_canonical_sha256"] == EXPECTED_FIXTURE_CANONICAL_SHA256)
    require(baseline["integrity"]["baseline_canonical_sha256"] == EXPECTED_BASELINE_CANONICAL_SHA256)
    require(canonical_sha256(_baseline_canonical_payload(baseline)) == EXPECTED_BASELINE_CANONICAL_SHA256)
    manifest = baseline["integrity"]["artifact_manifest"]
    require(manifest == _artifact_manifest())
    require(baseline["integrity"]["artifact_manifest_sha256"] == canonical_sha256(manifest))
    require(integer(baseline["integrity"]["baseline_file_size_bytes"]) == BASELINE_PATH.stat().st_size)
    exact_keys(baseline["redaction"], ("synthetic_only", "contains_sensitive_values", "contains_raw_input"))
    require(baseline["redaction"] == {"synthetic_only": True, "contains_sensitive_values": False, "contains_raw_input": False})
    _scan_redaction(baseline)
    return {"normal_samples": 30, "optimized_samples": 30}


def format_failure(code: str) -> str:
    safe_code = code if code in SAFE_FAILURE_CODES else "ws_ticket_fixture_invalid"
    payload = {"ok": False, "compatible": False, "live_run": False, "error": {"code": safe_code, "message": SAFE_ERROR_MESSAGE}}
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    require(len(serialized) <= MAX_ERROR_LENGTH)
    return serialized


def _parser() -> argparse.ArgumentParser:
    parser = FailClosedArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=FIXTURE_PATH)
    parser.add_argument("--baseline", type=Path, default=BASELINE_PATH)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        fixture_path = args.fixture.resolve()
        baseline_path = args.baseline.resolve()
        fixture = load_json(fixture_path)
        fixture_summary = validate_fixture(fixture)
        previous_fixture = globals()["FIXTURE_PATH"]
        previous_baseline = globals()["BASELINE_PATH"]
        globals()["FIXTURE_PATH"] = fixture_path
        globals()["BASELINE_PATH"] = baseline_path
        try:
            baseline = load_json(baseline_path)
            baseline_summary = validate_baseline(baseline)
        finally:
            globals()["FIXTURE_PATH"] = previous_fixture
            globals()["BASELINE_PATH"] = previous_baseline
        print(json.dumps({"ok": True, "compatible": False, "live_run": False, "fixture": fixture_summary, "baseline": baseline_summary}, sort_keys=True, separators=(",", ":")))
        return 0
    except ArgumentParseError:
        print(format_failure("ws_ticket_cli_invalid"))
        return 2
    except Exception:
        print(format_failure("ws_ticket_fixture_invalid"))
        return 1


if __name__ == "__main__":
    sys.exit(main())
