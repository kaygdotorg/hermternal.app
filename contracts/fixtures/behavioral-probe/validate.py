#!/usr/bin/env python3
"""Validate the synthetic Hermes behavioral-probe contract offline.

The validator reads only checked-in JSON and the local route manifest. It never
starts Hermes, opens a socket, contacts a proxy, contacts an identity provider,
or treats fixture validation as live compatibility. Explicit exceptions keep the
same fail-closed behavior when Python is run with ``-O``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import statistics
import subprocess
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parent
FIXTURE_PATH = ROOT / "probe-fixtures.json"
BASELINE_PATH = ROOT / "probe-baseline.json"
REPO_ROOT = ROOT.parents[2]
MANIFEST_PATH = REPO_ROOT / "contracts/hermes-dashboard/manifest.md"
SCHEMA = "hermternal.behavioral-probe.v1"
CONTRACT = "dashboard-v0.0.1"
HERMES_SOURCE_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
ROUTE_MANIFEST = "contracts/hermes-dashboard/manifest.md"
ROUTE_MANIFEST_SHA256 = "3c6b44dc8dd90836f4fc5c5158d459959c569fb811db4b198e87d78ea5010197"
EXPECTED_FIXTURE_CANONICAL_SHA256 = "293756e6b2573f59b7747c38cc0cda0f6602236ed93aae442f0022ad850d40e7"
BASELINE_REPETITIONS = 30
MAX_JSON_DEPTH = 64

ROOT_KEYS = (
    "schema",
    "contract",
    "hermes_source_sha",
    "route_manifest",
    "route_manifest_sha256",
    "synthetic_only",
    "probe",
    "proof_run",
    "evidence_requirements",
    "attestation_observations",
    "proxy_observations",
    "platform_observations",
    "proxy_matrix",
    "parity",
    "probe_states",
    "pty_lifecycle",
    "cases",
    "redaction",
    "accessibility",
)
PROBE_KEYS = (
    "id",
    "mode",
    "live_run",
    "compatible",
    "unknown_result_policy",
    "retry_policy",
    "required_case_count",
    "required_state_count",
    "required_lifecycle_count",
    "required_proxy_pair_count",
)
PROOF_RUN_KEYS = (
    "status",
    "attestation_state",
    "proxy_variants",
    "host_class",
    "tool_versions",
    "live_result",
)
ATTESTATION_KEYS = (
    "id",
    "source_sha",
    "manifest_sha256",
    "observed_result",
    "gate_decision",
    "live_claim",
)
PROXY_OBSERVATION_KEYS = (
    "id",
    "proxy",
    "case_id",
    "request_outcome",
    "http_status",
    "mapped_headers",
    "upstream_called",
    "observed_result",
    "live_claim",
)
PLATFORM_OBSERVATION_KEYS = (
    "id",
    "platform",
    "case_id",
    "consumer_result",
    "pty_result",
    "live_claim",
)
PROXY_KEYS = ("id", "case_id", "variants", "expected_equivalence")
PARITY_KEYS = (
    "status",
    "fixture_source",
    "platforms",
    "pty_policy",
    "missing_result_policy",
    "result_equivalence",
)
STATE_KEYS = (
    "id",
    "input_state",
    "evidence_state",
    "gate_decision",
    "safe_state",
    "retry_policy",
)
LIFECYCLE_KEYS = ("id", "expected", "live_claim")
CASE_KEYS = ("id", "synthetic", "kind", "surface", "request", "expected", "notes")

EXPECTED_CASE_IDS = (
    "rest-browser-cookie-approved",
    "rest-native-password-cookie-approved",
    "rest-native-oauth-bearer-approved",
    "rest-invalid-bearer-no-cookie-fallback",
    "rest-missing-credentials-denied",
    "rest-method-mutation-denied",
    "rest-source-present-not-allowlisted",
    "ws-chat-browser-fresh-ticket-approved",
    "ws-chat-native-fresh-ticket-approved",
    "ws-chat-missing-ticket-denied",
    "ws-chat-reused-ticket-denied",
    "ws-chat-expired-ticket-denied",
    "ws-chat-legacy-token-denied",
    "ws-pty-browser-fresh-ticket-approved",
    "ws-pty-native-denied",
    "ws-pty-unattested-host-denied",
    "edge-wrong-public-origin-denied",
    "edge-unsupported-host-denied",
    "upstream-hermes-400-preserved",
    "upstream-hermes-4403-preserved",
    "rpc-prompt-submit-approved",
    "rpc-unknown-operation-denied",
    "rpc-config-key-denied",
    "rpc-malformed-json-rejected",
    "event-unknown-additive-noninteractive-ignored",
    "event-unknown-interactive-denied",
    "pty-log-redaction-only",
    "rest-provider-discovery-approved",
    "rest-password-login-approved",
    "rest-ws-ticket-password-cookie-approved",
    "rest-ws-ticket-native-bearer-approved",
    "rest-native-authorize-reviewed",
    "rest-native-token-reviewed",
    "rest-native-refresh-reviewed",
    "ws-chat-missing-upgrade-denied",
    "ws-chat-malformed-ticket-denied",
    "ws-pty-missing-upgrade-denied",
    "ws-pty-malformed-ticket-denied",
    "ws-pty-wsl-fresh-ticket-approved",
    "ws-pty-ios-denied",
    "ws-pty-ipados-denied",
    "ws-pty-macos-denied",
    "edge-unknown-path-404",
    "rpc-duplicate-key-rejected",
    "rpc-wrong-top-level-rejected",
    "rpc-invalid-utf8-rejected",
    "rpc-syntax-error-rejected",
    "rpc-oversized-integer-rejected",
    "rpc-deep-nesting-rejected",
    "rpc-secret-shaped-huge-key-rejected",
    "chat-reconnect-fresh-ticket-approved",
    "chat-close-detach-observed",
    "chat-session-resume-approved",
    "chat-connection-loss-uncertain-prompt",
    "attestation-pinned-match-observed",
    "attestation-source-mismatch-denied",
    "proxy-caddy-approved-mapped-headers-observed",
    "proxy-caddy-denied-edge-observed",
    "proxy-traefik-approved-mapped-headers-observed",
    "proxy-traefik-denied-edge-observed",
    "platform-web-consumer-observed",
    "platform-ios-consumer-observed",
    "platform-ipados-consumer-observed",
    "platform-macos-consumer-observed",
)
EXPECTED_CASE_DECISIONS = {
    "rest-browser-cookie-approved": "allow_reviewed_route",
    "rest-native-password-cookie-approved": "allow_reviewed_route",
    "rest-native-oauth-bearer-approved": "allow_reviewed_route",
    "rest-invalid-bearer-no-cookie-fallback": "allow_reviewed_route",
    "rest-missing-credentials-denied": "deny_authentication",
    "rest-method-mutation-denied": "deny_default",
    "rest-source-present-not-allowlisted": "deny_default",
    "ws-chat-browser-fresh-ticket-approved": "allow_reviewed_upgrade",
    "ws-chat-native-fresh-ticket-approved": "allow_reviewed_upgrade",
    "ws-chat-missing-ticket-denied": "deny_upgrade",
    "ws-chat-reused-ticket-denied": "deny_upgrade",
    "ws-chat-expired-ticket-denied": "deny_upgrade",
    "ws-chat-legacy-token-denied": "deny_upgrade",
    "ws-pty-browser-fresh-ticket-approved": "allow_reviewed_upgrade",
    "ws-pty-native-denied": "deny_default",
    "ws-pty-unattested-host-denied": "deny_incompatible_host",
    "edge-wrong-public-origin-denied": "deny_edge_policy",
    "edge-unsupported-host-denied": "deny_edge_policy",
    "upstream-hermes-400-preserved": "preserve_upstream_result",
    "upstream-hermes-4403-preserved": "preserve_upstream_result",
    "rpc-prompt-submit-approved": "allow_reviewed_operation",
    "rpc-unknown-operation-denied": "deny_operation",
    "rpc-config-key-denied": "deny_operation",
    "rpc-malformed-json-rejected": "reject_without_traceback",
    "event-unknown-additive-noninteractive-ignored": "ignore_additive_noninteractive",
    "event-unknown-interactive-denied": "deny_unsupported_interactive_event",
    "pty-log-redaction-only": "deny_upgrade",
    "rest-provider-discovery-approved": "allow_reviewed_route",
    "rest-password-login-approved": "allow_reviewed_route",
    "rest-ws-ticket-password-cookie-approved": "allow_reviewed_route",
    "rest-ws-ticket-native-bearer-approved": "allow_reviewed_route",
    "rest-native-authorize-reviewed": "allow_reviewed_route",
    "rest-native-token-reviewed": "allow_reviewed_route",
    "rest-native-refresh-reviewed": "allow_reviewed_route",
    "ws-chat-missing-upgrade-denied": "deny_upgrade",
    "ws-chat-malformed-ticket-denied": "deny_upgrade",
    "ws-pty-missing-upgrade-denied": "deny_upgrade",
    "ws-pty-malformed-ticket-denied": "deny_upgrade",
    "ws-pty-wsl-fresh-ticket-approved": "allow_reviewed_upgrade",
    "ws-pty-ios-denied": "deny_default",
    "ws-pty-ipados-denied": "deny_default",
    "ws-pty-macos-denied": "deny_default",
    "edge-unknown-path-404": "deny_edge_not_found",
    "rpc-duplicate-key-rejected": "reject_without_traceback",
    "rpc-wrong-top-level-rejected": "reject_without_traceback",
    "rpc-invalid-utf8-rejected": "reject_without_traceback",
    "rpc-syntax-error-rejected": "reject_without_traceback",
    "rpc-oversized-integer-rejected": "reject_without_traceback",
    "rpc-deep-nesting-rejected": "reject_without_traceback",
    "rpc-secret-shaped-huge-key-rejected": "reject_without_traceback",
    "chat-reconnect-fresh-ticket-approved": "allow_reconnect",
    "chat-close-detach-observed": "record_close",
    "chat-session-resume-approved": "allow_resume",
    "chat-connection-loss-uncertain-prompt": "preserve_uncertain_delivery",
    "attestation-pinned-match-observed": "record_synthetic_observation",
    "attestation-source-mismatch-denied": "deny_synthetic_observation",
    "proxy-caddy-approved-mapped-headers-observed": "record_synthetic_observation",
    "proxy-caddy-denied-edge-observed": "record_synthetic_observation",
    "proxy-traefik-approved-mapped-headers-observed": "record_synthetic_observation",
    "proxy-traefik-denied-edge-observed": "record_synthetic_observation",
    "platform-web-consumer-observed": "record_synthetic_observation",
    "platform-ios-consumer-observed": "record_synthetic_observation",
    "platform-ipados-consumer-observed": "record_synthetic_observation",
    "platform-macos-consumer-observed": "record_synthetic_observation",
}
EXPECTED_STATE_IDS = ("pending", "empty", "success", "failure", "cancelled", "unknown")
EXPECTED_LIFECYCLE_IDS = (
    "input-forwarded-not-replayed",
    "detach-retains-bounded-state",
    "ttl-reap-eventual",
)
EXPECTED_PROXY_IDS = (
    "edge-origin-denial",
    "edge-host-denial",
    "edge-404-preservation",
    "upstream-400-preservation",
    "upstream-4403-preservation",
)
EXPECTED_EVIDENCE_REQUIREMENTS = (
    "attestation_matches_pinned_sha",
    "route_manifest_matches_pinned_digest",
    "all_required_case_results_present",
    "edge_and_upstream_results_are_distinguished",
    "redaction_and_log_policy_passes",
    "shared_fixture_parity_is_recorded",
    "caddy_and_traefik_results_match",
    "synthetic_attestation_observations_are_recorded",
    "synthetic_proxy_observations_are_recorded",
    "synthetic_platform_observations_are_recorded",
    "measured_baseline_is_present",
)
EXPECTED_PLATFORMS = ("web", "ios", "ipados", "macos")
REST_REVIEWED_ROUTES = frozenset(
    {
        ("GET", "/login"),
        ("GET", "/api/auth/providers"),
        ("GET", "/auth/login"),
        ("GET", "/auth/callback"),
        ("POST", "/auth/password-login"),
        ("POST", "/auth/logout"),
        ("GET", "/api/auth/me"),
        ("POST", "/api/auth/ws-ticket"),
        ("GET", "/auth/native/authorize"),
        ("POST", "/auth/native/token"),
        ("POST", "/auth/native/refresh"),
        ("GET", "/api/sessions"),
    }
)
TICKET_TTL_SECONDS = 30
WARNING_MAX_LENGTH = 240
MAX_JSON_INTEGER = 10**308
EXPECTED_REVIEWED_COMMIT = "6ff29b05d12fa1efd3e7f49d0cb45f660da1d958"

CASE_SHAPES: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "rest": (
        ("method", "path", "applicability", "auth_mode", "credential_state", "cookie_state", "origin_policy"),
        ("decision", "route_class", "auth_result", "handler_result", "http_status", "fallback", "observed_layer"),
    ),
    "chat_websocket": (
        ("path", "applicability", "platform", "auth_mode", "credential_state", "origin_policy", "host_class", "framing", "source_result", "session_scope", "upgrade_header", "connection_header"),
        ("decision", "route_class", "upgrade_auth", "source_result", "close_code", "http_status", "ticket_policy", "ticket_ttl_seconds", "fallback", "observed_layer", "log_policy"),
    ),
    "pty_websocket": (
        ("path", "applicability", "platform", "auth_mode", "credential_state", "origin_policy", "host_class", "framing", "source_result", "session_scope", "attach_state", "upgrade_header", "connection_header"),
        ("decision", "route_class", "upgrade_auth", "source_result", "close_code", "http_status", "ticket_policy", "ticket_ttl_seconds", "fallback", "observed_layer", "log_policy"),
    ),
    "edge": (
        ("method", "path", "applicability", "origin_policy", "host_class", "auth_mode", "credential_state", "source_result", "upgrade_header", "connection_header"),
        ("decision", "observed_layer", "http_status", "upstream_called", "source_status", "mapped_headers", "fallback"),
    ),
    "json_rpc": (
        ("path", "applicability", "auth_mode", "credential_state", "operation", "config_key", "input_state", "warning_source"),
        ("decision", "operation_class", "fallback", "error", "ui_action", "traceback", "warning_payload_policy", "warning_marker", "warning_source_cap", "warning_retention"),
    ),
    "event": (
        ("path", "applicability", "auth_mode", "credential_state", "event_name"),
        ("decision", "event_class", "fallback", "ui_action", "traceback", "warning_payload_policy"),
    ),
    "chat_lifecycle": (
        ("path", "applicability", "platform", "event", "transport_state", "session_scope", "input_state"),
        ("decision", "session_result", "retry_policy", "duplicate_action", "close_semantics", "live_claim"),
    ),
    "observation": (
        ("observation_kind", "subject", "applicability", "variant", "input_state"),
        ("decision", "result", "gate_decision", "live_claim", "mapped_headers", "upstream_called", "http_status", "warning"),
    ),
}

EXPECTED_REDACTION = {
    "synthetic_only": True,
    "contains_credentials": False,
    "contains_cookies": False,
    "contains_bearer_values": False,
    "contains_ticket_values": False,
    "contains_raw_pty_bytes": False,
    "contains_transcripts": False,
    "contains_hostnames": False,
    "contains_user_data": False,
    "log_policy": "semantic_class_and_bounded_reason_only",
}
EXPECTED_ACCESSIBILITY = {
    "status": "N/A",
    "reason": "This issue creates a non-UI protocol fixture and standard-library validator; it adds no controls, focus order, semantic names, screen-reader or VoiceOver surface, Switch Control behavior, Dynamic Type or browser zoom layout, contrast, motion, transparency, or touch target.",
    "preservation": "The fixture does not remove downstream web or Apple accessibility obligations; later clients must preserve those checks while showing the blocked compatibility state safely.",
}
EXPECTED_PARITY = {
    "status": "synthetic_observed",
    "fixture_source": "one_shared_case_inventory",
    "platforms": list(EXPECTED_PLATFORMS),
    "pty_policy": "web_only_apple_blocked",
    "missing_result_policy": "block",
    "result_equivalence": "semantic_outcome_not_platform_specific_wire_bytes",
}
EXPECTED_STATES = (
    {
        "id": "pending",
        "input_state": "pending",
        "evidence_state": "collection_in_progress",
        "gate_decision": "blocked",
        "safe_state": "no_success_claim",
        "retry_policy": "wait_or_cancel",
    },
    {
        "id": "empty",
        "input_state": "empty",
        "evidence_state": "no_observations",
        "gate_decision": "blocked",
        "safe_state": "no_success_claim",
        "retry_policy": "collect_required_evidence",
    },
    {
        "id": "success",
        "input_state": "complete",
        "evidence_state": "synthetic_fixture_validated",
        "gate_decision": "blocked_live_compatibility",
        "safe_state": "artifact_only_no_live_claim",
        "retry_policy": "not_applicable",
    },
    {
        "id": "failure",
        "input_state": "failed",
        "evidence_state": "required_case_failed",
        "gate_decision": "blocked",
        "safe_state": "retain_failure_evidence",
        "retry_policy": "idempotent_collection_only",
    },
    {
        "id": "cancelled",
        "input_state": "cancelled",
        "evidence_state": "cancelled_before_completion",
        "gate_decision": "blocked",
        "safe_state": "no_outward_change",
        "retry_policy": "resume_after_source_state_reread",
    },
    {
        "id": "unknown",
        "input_state": "unknown",
        "evidence_state": "result_unavailable",
        "gate_decision": "blocked",
        "safe_state": "no_duplicate_prompt_session_ticket_or_pty_input",
        "retry_policy": "reread_source_state_before_retry",
    },
)
EXPECTED_LIFECYCLE = (
    {"id": "input-forwarded-not-replayed", "expected": "forward_input_without_replay_after_reattach", "live_claim": False},
    {"id": "detach-retains-bounded-state", "expected": "close_means_detach_for_attach_mode", "live_claim": False},
    {"id": "ttl-reap-eventual", "expected": "eventual_ttl_reap_without_immediate_kill_or_replay_guarantee", "live_claim": False},
)
EXPECTED_PROXY_MATRIX = (
    {"id": "edge-origin-denial", "case_id": "edge-wrong-public-origin-denied", "variants": ["caddy", "traefik"], "expected_equivalence": "same_edge_denial_without_upstream_call"},
    {"id": "edge-host-denial", "case_id": "edge-unsupported-host-denied", "variants": ["caddy", "traefik"], "expected_equivalence": "same_edge_denial_without_upstream_call"},
    {"id": "edge-404-preservation", "case_id": "edge-unknown-path-404", "variants": ["caddy", "traefik"], "expected_equivalence": "same_edge_not_found_without_upstream_call"},
    {"id": "upstream-400-preservation", "case_id": "upstream-hermes-400-preserved", "variants": ["caddy", "traefik"], "expected_equivalence": "same_upstream_status_and_mapped_headers"},
    {"id": "upstream-4403-preservation", "case_id": "upstream-hermes-4403-preserved", "variants": ["caddy", "traefik"], "expected_equivalence": "same_upstream_status_and_mapped_headers"},
)

EXPECTED_ATTESTATION_OBSERVATIONS = (
    {"id": "attestation-pinned-match", "source_sha": HERMES_SOURCE_SHA, "manifest_sha256": ROUTE_MANIFEST_SHA256, "observed_result": "match", "gate_decision": "blocked_live_compatibility", "live_claim": False},
    {"id": "attestation-source-mismatch", "source_sha": "mismatch_not_pinned", "manifest_sha256": ROUTE_MANIFEST_SHA256, "observed_result": "mismatch", "gate_decision": "blocked", "live_claim": False},
)
EXPECTED_PROXY_OBSERVATIONS = (
    {"id": "proxy-caddy-approved", "proxy": "caddy", "case_id": "proxy-caddy-approved-mapped-headers-observed", "request_outcome": "approved", "http_status": 101, "mapped_headers": "forwarded_host_origin_and_upgrade_only", "upstream_called": True, "observed_result": "synthetic_equivalent", "live_claim": False},
    {"id": "proxy-caddy-denied", "proxy": "caddy", "case_id": "proxy-caddy-denied-edge-observed", "request_outcome": "edge_denied", "http_status": 403, "mapped_headers": "none", "upstream_called": False, "observed_result": "synthetic_equivalent", "live_claim": False},
    {"id": "proxy-traefik-approved", "proxy": "traefik", "case_id": "proxy-traefik-approved-mapped-headers-observed", "request_outcome": "approved", "http_status": 101, "mapped_headers": "forwarded_host_origin_and_upgrade_only", "upstream_called": True, "observed_result": "synthetic_equivalent", "live_claim": False},
    {"id": "proxy-traefik-denied", "proxy": "traefik", "case_id": "proxy-traefik-denied-edge-observed", "request_outcome": "edge_denied", "http_status": 403, "mapped_headers": "none", "upstream_called": False, "observed_result": "synthetic_equivalent", "live_claim": False},
)
EXPECTED_PLATFORM_OBSERVATIONS = (
    {"id": "platform-web", "platform": "web", "case_id": "platform-web-consumer-observed", "consumer_result": "shared_fixture_consumed", "pty_result": "web_route_reviewed", "live_claim": False},
    {"id": "platform-ios", "platform": "ios", "case_id": "platform-ios-consumer-observed", "consumer_result": "shared_fixture_consumed", "pty_result": "pty_denied_no_request", "live_claim": False},
    {"id": "platform-ipados", "platform": "ipados", "case_id": "platform-ipados-consumer-observed", "consumer_result": "shared_fixture_consumed", "pty_result": "pty_denied_no_request", "live_claim": False},
    {"id": "platform-macos", "platform": "macos", "case_id": "platform-macos-consumer-observed", "consumer_result": "shared_fixture_consumed", "pty_result": "pty_denied_no_request", "live_claim": False},
)

FORBIDDEN_KEYS = frozenset(
    {
        "access_token",
        "attach_handle",
        "attach_handles",
        "attach_id",
        "attach_ids",
        "authorization",
        "authorization_header",
        "authorization_headers",
        "auth_header",
        "auth_headers",
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
    }
)
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b", re.IGNORECASE),
    re.compile(r"\b(?:ghp|github_pat|glpat|sk|xox[baprs])[-_][A-Za-z0-9_-]{8,}\b", re.IGNORECASE),
    re.compile(r"\bBearer\s+(?=[A-Za-z0-9._~+/=-]{20,}\b)[A-Za-z0-9._~+/=-]+\b", re.IGNORECASE),
    re.compile(r"\bBasic\s+[A-Za-z0-9+/=_-]{12,}", re.IGNORECASE),
    re.compile(r"\beyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\b", re.IGNORECASE),
    re.compile(r"\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"(?:[?&]ticket|ticket(?:_fragment|_query)?)\s*[=:]\s*[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
    re.compile(r"synthetic-(?:api-key|secret|ticket-value|ticket-fragment|bearer-value|cookie-value|password-value|pty-(?:input|output|handle))", re.IGNORECASE),
)
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


SAFE_ERROR_MESSAGE = "behavioral probe input rejected"


class ContractError(ValueError):
    """Raised when checked-in behavioral-probe evidence violates the contract."""

    def __init__(self, _detail: str = "") -> None:
        # Details may include attacker-controlled keys, values, or deep paths.
        # Keep direct API errors safe as well as the CLI's serialized marker.
        super().__init__(SAFE_ERROR_MESSAGE)


class DuplicateKeyError(ValueError):
    """Raised before duplicate JSON keys can hide a fixture mutation."""

    def __init__(self, _detail: str = "") -> None:
        super().__init__(SAFE_ERROR_MESSAGE)


class ArgumentParseError(ValueError):
    """Raised for CLI syntax errors without echoing untrusted arguments."""


class FailClosedArgumentParser(argparse.ArgumentParser):
    """Convert argparse diagnostics into a safe, controlled exception."""

    def error(self, message: str) -> None:
        # argparse normally writes usage and the offending argument to stderr.
        # Keep malformed input out of retained output and let ``main`` emit one
        # structured failure object with the conventional syntax-error status.
        raise ArgumentParseError("invalid command-line arguments")


def format_failure(code: str) -> str:
    """Serialize one bounded, semantic-only failure object."""
    safe_code = code if code in {"behavioral_probe_cli_invalid", "behavioral_probe_fixture_invalid"} else "behavioral_probe_fixture_invalid"
    payload = {"ok": False, "compatible": False, "live_run": False, "error": {"code": safe_code, "message": SAFE_ERROR_MESSAGE}}
    serialized = json.dumps(payload, sort_keys=True)
    require(len(serialized) <= WARNING_MAX_LENGTH, "failure marker exceeds safe bound")
    return serialized


def emit_failure(code: str) -> None:
    print(format_failure(code))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def strict_keys(value: Any, expected: tuple[str, ...], label: str) -> dict[str, Any]:
    require(type(value) is dict, f"{label} must be an object")
    require(tuple(value.keys()) == expected, f"{label} keys or ordering changed")
    return value


def strict_equal(actual: Any, expected: Any, label: str) -> None:
    require(type(actual) is type(expected), f"{label} type changed")
    if isinstance(expected, dict):
        require(tuple(actual.keys()) == tuple(expected.keys()), f"{label} keys or ordering changed")
        for key, expected_value in expected.items():
            strict_equal(actual[key], expected_value, f"{label}.{key}")
        return
    if isinstance(expected, list):
        require(len(actual) == len(expected), f"{label} length changed")
        for index, (actual_value, expected_value) in enumerate(zip(actual, expected)):
            strict_equal(actual_value, expected_value, f"{label}[{index}]")
        return
    require(actual == expected, f"{label} value changed")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError()
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> Any:
    raise ContractError()


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as stream:
            value = json.load(
                stream,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonfinite,
            )
    except (DuplicateKeyError, ContractError):
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError, OverflowError, ValueError) as exc:
        raise ContractError() from exc
    require(type(value) is dict, "top-level JSON value must be an object")
    _validate_json_tree(value)
    return value


def _validate_json_tree(value: Any, label: str = "document", depth: int = 0) -> None:
    require(depth <= MAX_JSON_DEPTH, "JSON nesting exceeds the safe depth")
    if type(value) is dict:
        for key, child in value.items():
            require(type(key) is str, "JSON object key must be text")
            _validate_json_tree(child, "nested JSON value", depth + 1)
        return
    if type(value) is list:
        for child in value:
            _validate_json_tree(child, "nested JSON value", depth + 1)
        return
    if type(value) is float:
        require(math.isfinite(value), "non-finite JSON number")
        return
    if type(value) is int:
        require(abs(value) <= MAX_JSON_INTEGER, "JSON integer exceeds the safe bound")
        return
    require(value is None or type(value) in (str, bool), "unsupported JSON value type")


def _normalize_sensitive_key(key: str) -> str:
    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
    return re.sub(r"[-.:/\s]+", "_", separated).casefold()


def _validate_redaction(value: Any, label: str = "fixture") -> None:
    if type(value) is dict:
        for key, child in value.items():
            require(type(key) is str, "JSON object key must be text")
            normalized = _normalize_sensitive_key(key)
            if not normalized.startswith("contains_"):
                require(normalized not in FORBIDDEN_KEYS, "prohibited sensitive key")
            _validate_redaction(child, "nested redaction value")
        return
    if type(value) is list:
        for child in value:
            _validate_redaction(child, "nested redaction value")
        return
    if type(value) is str:
        require("\x00" not in value, "embedded NUL is not allowed")
        for pattern in SECRET_PATTERNS:
            require(pattern.search(value) is None, "credential-shaped value")


def validate_warning_source(source: str) -> str:
    """Accept only a bounded, semantic malformed-input warning marker."""
    require(type(source) is str, "warning source must be text")
    require(len(source) <= WARNING_MAX_LENGTH, "warning source exceeds the safe bound")
    _validate_redaction(source, "warning source")
    return source


def _validate_text_redaction(path: Path) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ContractError() from exc
    _validate_redaction(text, "redaction evidence")


def _canonical_digest(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _validate_manifest(document: dict[str, Any], repo_root: Path) -> None:
    require(document["route_manifest"] == ROUTE_MANIFEST, "route manifest path changed")
    require(document["route_manifest_sha256"] == ROUTE_MANIFEST_SHA256, "route manifest digest changed")
    try:
        manifest = (repo_root / ROUTE_MANIFEST).resolve(strict=True)
        manifest.relative_to(repo_root.resolve())
    except (OSError, RuntimeError, ValueError) as exc:
        raise ContractError("route manifest is missing or escapes repository root") from exc
    actual = hashlib.sha256(manifest.read_bytes()).hexdigest()
    require(actual == ROUTE_MANIFEST_SHA256, "local route manifest bytes do not match pinned digest")


def _validate_case(case: Any, index: int) -> None:
    label = f"cases[{index}]"
    item = strict_keys(case, CASE_KEYS, label)
    case_id = item["id"]
    require(type(case_id) is str, "case id must be text")
    require(case_id == EXPECTED_CASE_IDS[index], "case id or order changed")
    require(item["synthetic"] is True, "case synthetic flag changed")
    require(type(item["kind"]) is str and item["kind"] in {"positive", "negative", "compatibility", "incompatible", "malformed_input", "security"}, "case kind changed")
    surface = item["surface"]
    require(type(surface) is str and surface in CASE_SHAPES, "case surface changed")
    request_keys, expected_keys = CASE_SHAPES[surface]
    request = strict_keys(item["request"], request_keys, "case request")
    expected = strict_keys(item["expected"], expected_keys, "case expected")
    require(type(item["notes"]) is str and item["notes"], "case notes must be non-empty text")
    require(expected["decision"] == EXPECTED_CASE_DECISIONS[case_id], "case decision is outside the closed semantic inventory")

    for value in request.values():
        require(value is None or type(value) is str, "case request values must be text or null")
    for key, value in expected.items():
        if key in {"http_status", "close_code", "source_status", "ticket_ttl_seconds"}:
            require(value is None or type(value) is int, "case numeric result must be an exact integer or null")
        elif key in {"upstream_called", "traceback", "live_claim"}:
            require(type(value) is bool, "case boolean result must be an exact boolean")
        else:
            require(value is None or type(value) is str, "case result values must be text or null")

    if surface in {"rest", "chat_websocket", "pty_websocket", "edge", "json_rpc", "event", "chat_lifecycle", "observation"}:
        require(request["applicability"] in {"browser", "native", "shared"}, "case applicability changed")
    if surface == "rest":
        require(request["origin_policy"] == "approved", "REST origin policy changed")
        if expected["decision"] == "allow_reviewed_route":
            require((request["method"], request["path"]) in REST_REVIEWED_ROUTES, "REST route is not in the reviewed allowlist")
    if surface in {"chat_websocket", "pty_websocket"}:
        require(request["path"] in {"/api/ws", "/api/pty"}, "WebSocket path changed")
        require(request["platform"] == ("web" if request["applicability"] == "browser" else request["platform"]), "WebSocket platform applicability changed")
        if request["applicability"] == "native":
            require(request["platform"] in {"ios", "ipados", "macos"}, "native WebSocket platform changed")
        require(request["upgrade_header"] is None or request["upgrade_header"] == "websocket", "Upgrade header semantics changed")
        require(request["connection_header"] is None or request["connection_header"] == "upgrade", "Connection header semantics changed")
        if expected["upgrade_auth"] in {"ticket_consumed_once", "ticket_invalid"} and request["credential_state"] != "malformed":
            require(expected["ticket_ttl_seconds"] == TICKET_TTL_SECONDS, "ticket lifetime boundary changed")
        if expected["upgrade_auth"] == "ticket_consumed_once":
            require(request["upgrade_header"] == "websocket" and request["connection_header"] == "upgrade", "approved upgrade lacks required HTTP headers")
        if expected["upgrade_auth"] == "missing_http_upgrade_headers":
            require(request["upgrade_header"] is None or request["connection_header"] is None, "missing-upgrade case has both required headers")
            require(expected["ticket_ttl_seconds"] is None, "missing-upgrade case must not claim ticket lifetime")
    if surface == "edge":
        require(request["method"] == "GET", "edge method changed")
        require(request["path"] in {"/api/ws", "/api/not-found"}, "edge path changed")
        require(expected["observed_layer"] in {"edge", "upstream"}, "edge result layer is not explicit")
        if case_id == "edge-unknown-path-404":
            require(request["path"] == "/api/not-found", "edge 404 path changed")
            require(expected["decision"] == "deny_edge_not_found" and expected["http_status"] == 404, "edge 404 result changed")
        if expected["observed_layer"] == "edge":
            require(expected["upstream_called"] is False and expected["source_status"] is None, "edge result reached upstream")
            require(expected["http_status"] in {403, 404, 421}, "edge status is not reviewed")
            require(expected["mapped_headers"] == "none", "edge denial must not map upstream headers")
        else:
            require(expected["upstream_called"] is True and expected["source_status"] in {400, 4403}, "upstream result is not preserved")
            require(expected["mapped_headers"] == "forwarded_host_origin_and_upgrade_only", "upstream mapped headers changed")
    if surface == "json_rpc":
        require(request["path"] == "/api/ws", "JSON-RPC path changed")
        if request["warning_source"] is not None:
            validate_warning_source(request["warning_source"])
            require(expected["warning_marker"] == "parse_error_-32700", "malformed warning marker changed")
            require(expected["warning_source_cap"] == "240", "malformed warning cap changed")
            require(expected["warning_retention"] == "marker_only_no_raw_source", "malformed warning retention changed")
        else:
            require(all(expected[key] is None for key in ("warning_marker", "warning_source_cap", "warning_retention")), "non-malformed case contains warning evidence")
    if surface == "event":
        require(request["path"] == "/api/ws", "event path changed")
    if surface == "chat_lifecycle":
        require(request["path"] == "/api/ws", "chat lifecycle path changed")
        require(request["platform"] in EXPECTED_PLATFORMS, "chat lifecycle platform changed")
        require(expected["live_claim"] is False, "chat lifecycle cannot claim live behavior")
    if surface == "observation":
        require(request["input_state"] == "synthetic_fixture", "observation input state changed")
        require(expected["live_claim"] is False, "synthetic observation cannot claim live behavior")


def _validate_cases(cases: Any) -> None:
    require(type(cases) is list, "cases must be a list")
    require(len(cases) == len(EXPECTED_CASE_IDS), "case count changed")
    seen: set[str] = set()
    for index, case in enumerate(cases):
        _validate_case(case, index)
        require(type(case) is dict, "case entry must be an object")
        case_id = case["id"]
        require(case_id not in seen, "duplicate case id")
        seen.add(case_id)
    require(seen == set(EXPECTED_CASE_IDS), "case inventory changed")


def _validate_ordered_inventory(value: Any, expected_ids: tuple[str, ...], label: str) -> list[dict[str, Any]]:
    require(type(value) is list, "inventory must be a list")
    entries: list[dict[str, Any]] = []
    for item in value:
        require(type(item) is dict, "inventory entry must be an object")
        entries.append(item)
    require(tuple(item.get("id") for item in entries) == expected_ids, "inventory order changed")
    return entries


def _validate_observation_inventory(value: Any, expected: tuple[dict[str, Any], ...], keys: tuple[str, ...]) -> None:
    entries = _validate_ordered_inventory(value, tuple(item["id"] for item in expected), "observation")
    require(len(entries) == len(expected), "observation count changed")
    for index, item in enumerate(entries):
        strict_keys(item, keys, f"observation[{index}]")
        strict_equal(item, expected[index], f"observation[{index}]")


def _finite_nonnegative_number(value: Any) -> bool:
    if type(value) is int:
        return abs(value) <= MAX_JSON_INTEGER and value >= 0
    return type(value) is float and math.isfinite(value) and value >= 0


BASELINE_ANCHOR_PATH = ROOT / "baseline-canonical-sha256.txt"
try:
    EXPECTED_BASELINE_CANONICAL_SHA256 = BASELINE_ANCHOR_PATH.read_text(encoding="ascii").strip()
except (OSError, UnicodeError):
    # A missing or unreadable trust anchor must fail validation, not enable a
    # fabricated baseline or surface an import-time traceback to the CLI.
    EXPECTED_BASELINE_CANONICAL_SHA256 = ""
EXPECTED_ARTIFACT_PATHS = ("README.md", "probe-fixtures.json", "validate.py", "test_validate.py")


def _baseline_canonical_bytes(baseline: dict[str, Any]) -> bytes:
    payload = dict(baseline)
    integrity = dict(payload["integrity"])
    for key in ("canonical_baseline_sha256", "canonical_baseline_size_bytes", "baseline_file_size_bytes"):
        integrity.pop(key, None)
    payload["integrity"] = integrity
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _artifact_manifest_digest(manifest: list[dict[str, Any]]) -> str:
    encoded = json.dumps(manifest, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _approved_commit_artifact_manifest(repo_root: Path, commit: str) -> list[dict[str, Any]]:
    """Read approved artifact bytes from the local Git object database.

    Worktree measurements are mutable, but the reviewed source evidence must be
    anchored to the exact approved remote head and the bytes that existed there.
    Git is read locally only; any missing object or command failure blocks the
    baseline without retaining command diagnostics.
    """
    require(type(commit) is str and HEX40.fullmatch(commit) is not None, "approved evidence commit is invalid")
    records: list[dict[str, Any]] = []
    for relative in EXPECTED_ARTIFACT_PATHS:
        try:
            git_path = f"contracts/fixtures/behavioral-probe/{relative}"
            completed = subprocess.run(
                ["git", "-C", str(repo_root), "show", f"{commit}:{git_path}"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        except (OSError, ValueError) as exc:
            raise ContractError() from exc
        require(completed.returncode == 0 and completed.stderr == b"", "approved evidence bytes are unavailable")
        data = completed.stdout
        records.append({"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)})
    return records


def _validate_baseline(baseline: dict[str, Any], repo_root: Path) -> None:
    expected_keys = (
        "schema",
        "fixture_schema",
        "validator",
        "synthetic_only",
        "build_mode",
        "threshold",
        "environment",
        "normal",
        "optimized",
        "artifact_paths",
        "artifact_size_bytes",
        "trace_artifact",
        "integrity",
    )
    strict_keys(baseline, expected_keys, "baseline")
    require(baseline["schema"] == "hermternal.behavioral-probe-baseline.v1", "baseline schema changed")
    require(baseline["fixture_schema"] == SCHEMA, "baseline fixture binding changed")
    require(baseline["validator"] == "Python standard library only", "baseline validator changed")
    require(baseline["synthetic_only"] is True, "baseline synthetic flag changed")
    require(baseline["build_mode"] == "N/A — no production or release executable", "baseline build mode changed")
    require(baseline["threshold"] is None, "baseline must not invent a threshold")
    environment = strict_keys(baseline["environment"], ("python", "implementation", "platform", "machine"), "baseline.environment")
    for value in environment.values():
        require(type(value) is str and value and value != "pending", "baseline environment is missing")

    integrity = strict_keys(
        baseline["integrity"],
        ("reviewed_commit", "reviewed_artifact_manifest_sha256", "reviewed_artifact_manifest", "evidence_mode", "immutable_evidence", "canonical_baseline_sha256", "canonical_baseline_size_bytes", "baseline_file_size_bytes", "artifact_manifest_sha256", "artifact_manifest"),
        "baseline.integrity",
    )
    require(integrity["reviewed_commit"] == EXPECTED_REVIEWED_COMMIT and HEX40.fullmatch(integrity["reviewed_commit"]) is not None, "baseline reviewed commit changed")
    require(integrity["evidence_mode"] == "worktree_recomputed_against_approved_commit", "baseline evidence mode changed")
    require(integrity["immutable_evidence"] is False, "worktree baseline cannot claim immutable evidence")

    reviewed_manifest = integrity["reviewed_artifact_manifest"]
    require(type(reviewed_manifest) is list and len(reviewed_manifest) == len(EXPECTED_ARTIFACT_PATHS), "approved artifact manifest changed")
    for index, record in enumerate(reviewed_manifest):
        record = strict_keys(record, ("path", "sha256", "size_bytes"), f"baseline.integrity.reviewed_artifact_manifest[{index}]")
        require(record["path"] == EXPECTED_ARTIFACT_PATHS[index], "approved artifact manifest path changed")
        require(type(record["sha256"]) is str and HEX64.fullmatch(record["sha256"]) is not None, "approved artifact digest is invalid")
        require(type(record["size_bytes"]) is int and record["size_bytes"] >= 0, "approved artifact size is invalid")
    approved_actual = _approved_commit_artifact_manifest(repo_root, integrity["reviewed_commit"])
    require(reviewed_manifest == approved_actual, "approved artifact bytes do not match reviewed commit")
    require(integrity["reviewed_artifact_manifest_sha256"] == _artifact_manifest_digest(reviewed_manifest), "approved artifact manifest digest does not match")
    require(type(integrity["canonical_baseline_sha256"]) is str and HEX64.fullmatch(integrity["canonical_baseline_sha256"]) is not None, "baseline canonical digest is invalid")
    canonical = _baseline_canonical_bytes(baseline)
    require(integrity["canonical_baseline_sha256"] == hashlib.sha256(canonical).hexdigest(), "baseline canonical digest does not match")
    require(integrity["canonical_baseline_sha256"] == EXPECTED_BASELINE_CANONICAL_SHA256, "baseline canonical digest is not the reviewed evidence")
    require(type(integrity["canonical_baseline_size_bytes"]) is int and integrity["canonical_baseline_size_bytes"] == len(canonical), "baseline canonical size does not match")
    require(type(integrity["baseline_file_size_bytes"]) is int and integrity["baseline_file_size_bytes"] == BASELINE_PATH.stat().st_size, "baseline file size is stale")

    artifact_paths = baseline["artifact_paths"]
    require(type(artifact_paths) is list and tuple(artifact_paths) == EXPECTED_ARTIFACT_PATHS, "baseline artifact paths changed")
    manifest = integrity["artifact_manifest"]
    require(type(manifest) is list and len(manifest) == len(EXPECTED_ARTIFACT_PATHS), "baseline artifact manifest changed")
    actual_sizes = []
    for index, record in enumerate(manifest):
        record = strict_keys(record, ("path", "sha256", "size_bytes"), f"baseline.integrity.artifact_manifest[{index}]")
        require(record["path"] == EXPECTED_ARTIFACT_PATHS[index], "baseline artifact manifest path changed")
        require(type(record["sha256"]) is str and HEX64.fullmatch(record["sha256"]) is not None, "baseline artifact digest is invalid")
        require(type(record["size_bytes"]) is int and record["size_bytes"] >= 0, "baseline artifact size is invalid")
        path = (ROOT / record["path"]).resolve()
        path.relative_to(ROOT.resolve())
        actual = path.read_bytes()
        actual_sizes.append(len(actual))
        require(record["size_bytes"] == len(actual), "baseline artifact size does not match")
        require(record["sha256"] == hashlib.sha256(actual).hexdigest(), "baseline artifact digest does not match")
    require(integrity["artifact_manifest_sha256"] == _artifact_manifest_digest(manifest), "baseline artifact manifest digest does not match")
    require(type(baseline["artifact_size_bytes"]) is int and baseline["artifact_size_bytes"] == sum(actual_sizes), "baseline artifact size is stale")
    require(baseline["trace_artifact"] == "local_command_output_only", "baseline trace policy changed")

    for mode in ("normal", "optimized"):
        sample_set = strict_keys(baseline[mode], ("command", "repetitions", "samples_ms", "distribution_ms"), f"baseline.{mode}")
        expected_command = f"python3 {'-O ' if mode == 'optimized' else ''}contracts/fixtures/behavioral-probe/validate.py"
        require(sample_set["command"] == expected_command, "baseline command changed")
        require(type(sample_set["repetitions"]) is int and sample_set["repetitions"] == BASELINE_REPETITIONS, "baseline repetitions changed")
        samples = sample_set["samples_ms"]
        require(type(samples) is list and len(samples) == BASELINE_REPETITIONS, "baseline sample count changed")
        for sample in samples:
            require(_finite_nonnegative_number(sample), "baseline sample is not a finite bounded number")
        distribution = strict_keys(sample_set["distribution_ms"], ("min", "p50", "p95", "max", "mean"), f"baseline.{mode}.distribution_ms")
        for value in distribution.values():
            require(_finite_nonnegative_number(value), "baseline distribution is not a finite bounded number")
        ordered = sorted(samples)
        p50 = ordered[min(len(ordered) - 1, max(0, math.ceil(0.50 * len(ordered)) - 1))]
        p95 = ordered[min(len(ordered) - 1, max(0, math.ceil(0.95 * len(ordered)) - 1))]
        require(abs(distribution["min"] - min(samples)) < 0.001, "baseline minimum does not match samples")
        require(abs(distribution["p50"] - p50) < 0.001, "baseline p50 does not match samples")
        require(abs(distribution["p95"] - p95) < 0.001, "baseline p95 does not match samples")
        require(abs(distribution["max"] - max(samples)) < 0.001, "baseline maximum does not match samples")
        require(abs(distribution["mean"] - statistics.mean(samples)) < 0.001, "baseline mean does not match samples")
        require(distribution["min"] <= distribution["p50"] <= distribution["p95"] <= distribution["max"], "baseline quantiles are incoherent")


def validate_document(document: dict[str, Any], repo_root: Path = REPO_ROOT, *, verify_digest: bool = True) -> None:
    strict_keys(document, ROOT_KEYS, "fixture")
    require(document["schema"] == SCHEMA, "fixture schema changed")
    require(document["contract"] == CONTRACT, "fixture contract changed")
    require(document["hermes_source_sha"] == HERMES_SOURCE_SHA and HEX40.fullmatch(document["hermes_source_sha"]) is not None, "Hermes source pin changed")
    require(document["synthetic_only"] is True, "fixture must remain synthetic")
    _validate_manifest(document, repo_root)

    probe = strict_keys(document["probe"], PROBE_KEYS, "probe")
    require(probe["id"] == "c-04a-behavioral-compatibility", "probe id changed")
    require(probe["mode"] == "offline_synthetic_contract", "probe mode changed")
    require(probe["live_run"] is False and probe["compatible"] is False, "fixture cannot claim live compatibility")
    require(probe["unknown_result_policy"] == "block_and_reread_source_state", "unknown result policy changed")
    require(probe["retry_policy"] == "retry_idempotent_collection_only_after_safe_state_reread", "retry policy changed")
    require(type(probe["required_case_count"]) is int and probe["required_case_count"] == len(EXPECTED_CASE_IDS), "required case count must be an exact integer")
    require(type(probe["required_state_count"]) is int and probe["required_state_count"] == len(EXPECTED_STATE_IDS), "required state count must be an exact integer")
    require(type(probe["required_lifecycle_count"]) is int and probe["required_lifecycle_count"] == len(EXPECTED_LIFECYCLE_IDS), "required lifecycle count must be an exact integer")
    require(type(probe["required_proxy_pair_count"]) is int and probe["required_proxy_pair_count"] == len(EXPECTED_PROXY_IDS), "required proxy pair count must be an exact integer")

    proof = strict_keys(document["proof_run"], PROOF_RUN_KEYS, "proof_run")
    strict_equal(proof, {"status": "synthetic_observed", "attestation_state": "synthetic_match_and_mismatch_recorded", "proxy_variants": ["caddy", "traefik"], "host_class": "synthetic_only", "tool_versions": "standard_library_only", "live_result": "not_recorded"}, "proof_run")
    require(tuple(document["evidence_requirements"]) == EXPECTED_EVIDENCE_REQUIREMENTS, "evidence requirements changed")
    _validate_observation_inventory(document["attestation_observations"], EXPECTED_ATTESTATION_OBSERVATIONS, ATTESTATION_KEYS)
    _validate_observation_inventory(document["proxy_observations"], EXPECTED_PROXY_OBSERVATIONS, PROXY_OBSERVATION_KEYS)
    _validate_observation_inventory(document["platform_observations"], EXPECTED_PLATFORM_OBSERVATIONS, PLATFORM_OBSERVATION_KEYS)

    proxy_matrix = _validate_ordered_inventory(document["proxy_matrix"], EXPECTED_PROXY_IDS, "proxy matrix")
    require(len(proxy_matrix) == len(EXPECTED_PROXY_MATRIX), "proxy matrix count changed")
    for index, item in enumerate(proxy_matrix):
        strict_keys(item, PROXY_KEYS, f"proxy_matrix[{index}]")
        strict_equal(item, EXPECTED_PROXY_MATRIX[index], f"proxy_matrix[{index}]")

    parity = strict_keys(document["parity"], PARITY_KEYS, "parity")
    strict_equal(parity, EXPECTED_PARITY, "parity")
    require(tuple(parity["platforms"]) == EXPECTED_PLATFORMS, "parity platforms changed")

    states = _validate_ordered_inventory(document["probe_states"], EXPECTED_STATE_IDS, "probe states")
    require(len(states) == len(EXPECTED_STATES), "probe state count changed")
    for index, state in enumerate(states):
        strict_keys(state, STATE_KEYS, f"probe_states[{index}]")
        strict_equal(state, EXPECTED_STATES[index], f"probe_states[{index}]")

    lifecycle = _validate_ordered_inventory(document["pty_lifecycle"], EXPECTED_LIFECYCLE_IDS, "PTY lifecycle")
    require(len(lifecycle) == len(EXPECTED_LIFECYCLE), "PTY lifecycle count changed")
    for index, item in enumerate(lifecycle):
        strict_keys(item, LIFECYCLE_KEYS, f"pty_lifecycle[{index}]")
        strict_equal(item, EXPECTED_LIFECYCLE[index], f"pty_lifecycle[{index}]")

    _validate_cases(document["cases"])
    strict_equal(document["redaction"], EXPECTED_REDACTION, "redaction")
    strict_equal(document["accessibility"], EXPECTED_ACCESSIBILITY, "accessibility")
    _validate_redaction(document)
    if verify_digest:
        require(_canonical_digest(document) == EXPECTED_FIXTURE_CANONICAL_SHA256, "fixture canonical digest changed")


def validate_baseline(baseline: dict[str, Any], repo_root: Path = REPO_ROOT) -> None:
    _validate_redaction(baseline, "baseline")
    _validate_baseline(baseline, repo_root)


def validate_all(
    document: dict[str, Any],
    baseline: dict[str, Any],
    repo_root: Path = REPO_ROOT,
    *,
    verify_digest: bool = True,
) -> None:
    validate_document(document, repo_root, verify_digest=verify_digest)
    validate_baseline(baseline, repo_root)
    _validate_text_redaction(ROOT / "README.md")


def main(argv: list[str] | None = None) -> int:
    parser = FailClosedArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, default=FIXTURE_PATH)
    parser.add_argument("--baseline", type=Path, default=BASELINE_PATH)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    try:
        args = parser.parse_args(argv)
        document = load_json(args.fixtures.resolve())
        baseline = load_json(args.baseline.resolve())
        validate_all(document, baseline, args.repo_root.resolve())
    except ArgumentParseError:
        emit_failure("behavioral_probe_cli_invalid")
        return 2
    except (ContractError, DuplicateKeyError, OSError, UnicodeError, TypeError, ValueError, OverflowError, RecursionError):
        emit_failure("behavioral_probe_fixture_invalid")
        return 1
    print(json.dumps({"ok": True, "compatible": False, "live_run": False, "case_count": len(document["cases"]), "state_count": len(document["probe_states"]), "proxy_pair_count": len(document["proxy_matrix"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
