#!/usr/bin/env python3
"""Validate the synthetic connection and restoration contract offline.

This fixture models connection lifecycle decisions without opening Hermes, a
Dashboard WebSocket, an identity provider, or a proxy. The reducer is a small
executable contract: it proves ordering barriers and safe recovery state, but it
does not implement a client runtime or the C-06 uncertain-resend decision.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import statistics
import sys
from typing import Any


ROOT = Path(__file__).resolve().parent
CASES_PATH = ROOT / "cases.json"
BASELINE_PATH = ROOT / "validation-baseline.json"
SCHEMA = "hermternal.connection-restoration.v1"
BASELINE_SCHEMA = "hermternal.connection-restoration-baseline.v1"
OPERATION = "C-05"
CONTRACT = "dashboard-v0.0.1"
HERMES_SOURCE_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
SURFACE = "shared-web-apple"

STATES = (
    "offline",
    "auth_required",
    "connecting",
    "handshaking",
    "ready",
    "restoring",
    "reconnecting",
    "delivery_uncertain",
    "incompatible",
    "failed",
    "closing",
)
RETRYABLE_METHODS = (
    "session.resume",
    "session.history",
    "session.status",
    "model.options",
)
KNOWN_CLOSE_CODES = {
    "4401": "auth_required",
    "4403": "incompatible",
    "4404": "incompatible",
    "4408": "failed",
    "4409": "failed",
    "4410": "failed",
    "1011": "failed",
}

MAX_JSON_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 4096
MAX_OBJECT_KEYS = 64
MAX_ARRAY_LENGTH = 256
MAX_STRING_LENGTH = 16 * 1024
MAX_INTEGER_DIGITS = 4096
MAX_ERROR_MESSAGE_LENGTH = 240
BASELINE_REPETITIONS = 30
APPROVED_BASELINE_COMMAND = "python3 contracts/fixtures/connection-restoration/validate.py"
APPROVED_BENCHMARK_COMMANDS = {
    "normal": APPROVED_BASELINE_COMMAND,
    "optimized": "python3 -O contracts/fixtures/connection-restoration/validate.py",
}
# This digest pins the benchmark evidence and command identity in executable code;
# mutable baseline JSON cannot replace the timing trace or command it claims to run.
BASELINE_CANONICAL_IDENTITY_SHA256 = "ca242b5b4684b9c6b30c313c4b8e645715cc6a00c221df5e4aece3ff9c7d4eb0"
BASELINE_IDENTITY_KEYS = (
    "schema",
    "validator",
    "command",
    "build_mode",
    "repetitions",
    "normal",
    "optimized",
    "threshold",
)
PROFILE_DRIFT_MARKER = "profile-marker-002"

ROOT_KEYS = (
    "schema",
    "operation",
    "contract",
    "hermes_source_sha",
    "synthetic_only",
    "surface",
    "states",
    "invariants",
    "cases",
    "redaction",
)
STATE_KEYS = ("id", "meaning", "allowed_actions", "terminal")
INVARIANT_KEYS = (
    "gateway_ready_required",
    "compatibility_gate",
    "restore_barrier",
    "retryable_methods",
    "prompt_policy",
    "session_policy",
    "cancellation_policy",
    "known_close_codes",
    "unknown_policy",
)
CASE_KEYS = ("id", "initial_state", "initial_context", "events", "expected", "notes")
CONTEXT_KEYS = (
    "authenticated",
    "selected_session",
    "selected_profile",
    "active_profile",
    "draft",
    "attestation",
    "probe",
    "gateway_ready",
    "ticket_generation",
    "prompt_delivery",
)
EXPECTED_KEYS = (
    "decision",
    "final_state",
    "trace",
    "effects",
    "selected_session",
    "selected_profile",
    "active_profile",
    "draft",
    "ticket_generations",
    "restore_barrier",
    "prompt_retry",
    "compatibility_gate",
    "transport_closed",
    "prompt_auto_resubmitted",
)
REDACTION_KEYS = (
    "synthetic_only",
    "contains_credentials",
    "contains_cookies",
    "contains_tickets",
    "contains_prompts",
    "contains_transcripts",
    "contains_hosts",
    "contains_user_data",
    "diagnostic_policy",
)
BASELINE_KEYS = (
    "schema",
    "validator",
    "command",
    "build_mode",
    "artifact_files",
    "artifact_bytes",
    "environment",
    "repetitions",
    "normal",
    "optimized",
    "threshold",
)
BENCHMARK_KEYS = ("command", "samples_ms", "distribution")
DISTRIBUTION_KEYS = ("min", "p50", "p95", "max", "mean")
ARTIFACT_KEYS = ("path", "sha256", "size_bytes")
BASELINE_ARTIFACTS = (
    "README.md",
    "cases.json",
    "validate.py",
    "test_validate.py",
)

EXPECTED_STATES = (
    {
        "id": "offline",
        "meaning": "No transport is open.",
        "allowed_actions": ["start_auth", "connect", "wait_network"],
        "terminal": False,
    },
    {
        "id": "auth_required",
        "meaning": "A verified identity or fresh ticket is required.",
        "allowed_actions": ["authenticate", "sign_out"],
        "terminal": False,
    },
    {
        "id": "connecting",
        "meaning": "The Dashboard transport is opening.",
        "allowed_actions": ["cancel", "wait"],
        "terminal": False,
    },
    {
        "id": "handshaking",
        "meaning": "The transport is open and waiting for gateway.ready plus compatibility evidence.",
        "allowed_actions": ["wait", "cancel"],
        "terminal": False,
    },
    {
        "id": "ready",
        "meaning": "The transport and selected surface are usable.",
        "allowed_actions": ["restore", "send", "retry_idempotent", "sign_out"],
        "terminal": False,
    },
    {
        "id": "restoring",
        "meaning": "Server-owned session history and status are being resolved.",
        "allowed_actions": ["wait", "cancel"],
        "terminal": False,
    },
    {
        "id": "reconnecting",
        "meaning": "The old transport ended and recovery is in progress.",
        "allowed_actions": ["fresh_ticket", "cancel", "authenticate"],
        "terminal": False,
    },
    {
        "id": "delivery_uncertain",
        "meaning": "A prompt may have reached the server, but its result is unknown.",
        "allowed_actions": ["restore", "cancel", "sign_out"],
        "terminal": False,
    },
    {
        "id": "incompatible",
        "meaning": "Required compatibility evidence or behavior is absent or mismatched.",
        "allowed_actions": ["stop", "sign_out"],
        "terminal": True,
    },
    {
        "id": "failed",
        "meaning": "A known connection or restoration attempt failed.",
        "allowed_actions": ["explicit_retry", "sign_out"],
        "terminal": False,
    },
    {
        "id": "closing",
        "meaning": "The transport is closing and cleanup is in progress.",
        "allowed_actions": ["finish_cleanup"],
        "terminal": True,
    },
)
EXPECTED_INVARIANTS = {
    "gateway_ready_required": {
        "event": "gateway.ready",
        "application_send_before": "blocked",
        "missing_result": "failed",
    },
    "compatibility_gate": {
        "requires": ["gateway.ready", "attestation.pass", "probe.pass"],
        "success_state": "ready",
        "missing_or_failed_state": "incompatible",
    },
    "restore_barrier": {
        "before_prompt_retry": "required_after_reconnect",
        "server_owned": True,
        "uncertain_prompt_next": "restore_session",
        "resend_decision_owner": "C-06",
    },
    "retryable_methods": list(RETRYABLE_METHODS),
    "prompt_policy": {
        "auto_resubmit": False,
        "uncertain_state": "delivery_uncertain",
        "preserve_draft": True,
    },
    "session_policy": {
        "selected_session_source": "server",
        "new_transport_is_new_session": False,
        "preserve_selected_session_on_reconnect": True,
        "preserve_draft_on_reconnect": True,
        "selected_profile_source": "configured",
        "preserve_selected_profile_on_reconnect": True,
        "preserve_active_profile_on_restore": True,
        "profile_drift_result": "incompatible",
    },
    "cancellation_policy": {
        "cancel_state": "closing",
        "sign_out_state": "closing",
        "reconnect_after_close": False,
        "sign_out_clears_session_reference": True,
        "sign_out_preserves_draft": True,
    },
    "known_close_codes": {
        "4401": "auth_required",
        "4403": "incompatible",
        "4404": "incompatible",
        "4408": "failed",
        "4409": "failed",
        "4410": "failed",
        "1011": "failed",
    },
    "unknown_policy": {
        "unknown_event": "incompatible",
        "unknown_close": "incompatible",
        "fallback": "none",
    },
}
EXPECTED_REDACTION = {
    "synthetic_only": True,
    "contains_credentials": False,
    "contains_cookies": False,
    "contains_tickets": False,
    "contains_prompts": False,
    "contains_transcripts": False,
    "contains_hosts": False,
    "contains_user_data": False,
    "diagnostic_policy": "semantic_markers_only",
}


class ContractError(ValueError):
    """Raised when the fixture or its executable result violates the contract."""


def _require(condition: bool, message: str = "contract validation failed") -> None:
    if not condition:
        raise ContractError(message)


def _strict_int(value: Any, label: str) -> None:
    _require(type(value) is int, f"{label} must be an integer")


def _strict_string(value: Any, label: str) -> None:
    _require(type(value) is str, f"{label} must be text")


def _strict_bool(value: Any, label: str) -> None:
    _require(type(value) is bool, f"{label} must be boolean")


def _strict_keys(value: Any, expected: tuple[str, ...], label: str) -> dict[str, Any]:
    _require(type(value) is dict, f"{label} must be an object")
    _require(tuple(value.keys()) == expected, f"{label} shape changed")
    return value


def _strict_equal(actual: Any, expected: Any, label: str) -> None:
    _require(type(actual) is type(expected), f"{label} type changed")
    if isinstance(expected, dict):
        _require(tuple(actual.keys()) == tuple(expected.keys()), f"{label} shape changed")
        for key, expected_value in expected.items():
            _strict_equal(actual[key], expected_value, f"{label}.{key}")
    elif isinstance(expected, list):
        _require(len(actual) == len(expected), f"{label} length changed")
        for index, (actual_value, expected_value) in enumerate(zip(actual, expected)):
            _strict_equal(actual_value, expected_value, f"{label}[{index}]")
    else:
        _require(actual == expected, f"{label} value changed")


def _reject_constant(value: str) -> None:
    raise ContractError("non-finite JSON number is not allowed")


def _parse_int(value: str) -> int:
    if len(value.lstrip("-")) > MAX_INTEGER_DIGITS:
        raise ContractError("JSON integer digit limit exceeded")
    return int(value)


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate JSON object key is not allowed")
        result[key] = value
    return result


def _validate_shape(value: Any, *, depth: int = 0) -> int:
    _require(depth <= MAX_JSON_DEPTH, "JSON nesting exceeds the bounded limit")
    if isinstance(value, dict):
        _require(len(value) <= MAX_OBJECT_KEYS, "JSON object is too wide")
        nodes = 1
        for key, child in value.items():
            _strict_string(key, "JSON object key")
            _require(len(key) <= MAX_STRING_LENGTH, "JSON object key is too long")
            nodes += _validate_shape(child, depth=depth + 1)
            _require(nodes <= MAX_JSON_NODES, "JSON node count exceeds the bounded limit")
        return nodes
    if isinstance(value, list):
        _require(len(value) <= MAX_ARRAY_LENGTH, "JSON array is too long")
        nodes = 1
        for child in value:
            nodes += _validate_shape(child, depth=depth + 1)
            _require(nodes <= MAX_JSON_NODES, "JSON node count exceeds the bounded limit")
        return nodes
    if isinstance(value, str):
        _require(len(value) <= MAX_STRING_LENGTH, "JSON string is too long")
    elif type(value) is float:
        _require(math.isfinite(value), "non-finite JSON number is not allowed")
    return 1


def _load_json(path: Path, label: str) -> Any:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ContractError(f"cannot read {label}") from exc
    _require(len(data) <= MAX_JSON_BYTES, f"{label} exceeds the JSON byte limit")
    try:
        text = data.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_constant=_reject_constant,
            parse_int=_parse_int,
        )
    except ContractError:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError, OverflowError, RecursionError) as exc:
        raise ContractError(f"invalid strict JSON in {label}") from exc
    _validate_shape(value)
    return value


def _iter_text(value: Any):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from _iter_text(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_text(child)
    elif isinstance(value, str):
        yield value


def _validate_redaction(value: Any) -> None:
    """Reject live-looking values while allowing semantic state vocabulary."""
    import re

    hostname_pattern = re.compile(
        r"(?<![A-Za-z0-9._-])(?:localhost|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})(?::\d{1,5})?(?![A-Za-z0-9._-])",
        re.IGNORECASE,
    )
    semantic_dotted_tokens = {
        "auth.required",
        "auth.success",
        "attestation.fail",
        "attestation.pass",
        "close.complete",
        "event.unknown",
        "gateway.ready",
        "gateway.ready.timeout",
        "model.options",
        "network.offline",
        "probe.fail",
        "probe.pass",
        "profile.drift",
        "prompt.auto_retry",
        "prompt.sent",
        "retry.prompt.submit",
        "retry.session.history",
        "retry.session.status",
        "session.empty",
        "session.history",
        "session.resume",
        "session.resume.ok",
        "session.resume.start",
        "session.status",
        "ticket.fresh",
        "ticket.reuse",
        "transport.loss",
        "transport.open",
        "user.cancel",
        "user.sign_out",
    }
    patterns = (
        re.compile(r"\b(?:https?|wss?|ftp)://", re.IGNORECASE),
        re.compile(r"\b(?:bearer|authorization|cookie|password|secret|api[_ -]?key)\s*[:=]", re.IGNORECASE),
        re.compile(r"\b(?:bearer|basic)\s+\S+", re.IGNORECASE),
        re.compile(r"\b(?:host|hostname)\s*[:=]\s*\S+", re.IGNORECASE),
        re.compile(r"(?:^|[\s=(])/[^\s\"'<>]+"),
        hostname_pattern,
        re.compile(
            r"(?<![A-Za-z0-9+/])"
            r"(?=[A-Za-z0-9+/]{8,24}={0,2}(?![A-Za-z0-9+/]))"
            r"(?=[A-Za-z0-9+/]*[0-9=])"
            r"[A-Za-z0-9+/]{8,24}={0,2}(?![A-Za-z0-9+/])"
        ),
        re.compile(r"\b(?:ghp|github_pat|sk|xox[baprs])[-_][A-Za-z0-9_-]{8,}\b", re.IGNORECASE),
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    )
    for text in _iter_text(value):
        _require("\x00" not in text and "\x1f" not in text, "control character is not allowed")
        for pattern in patterns:
            for match in pattern.finditer(text):
                if pattern is hostname_pattern and match.group(0).lower() in semantic_dotted_tokens:
                    continue
                raise ContractError("redaction boundary changed")


def _context(
    *,
    authenticated: bool = True,
    selected_session: str | None = "session-marker-001",
    selected_profile: str | None = "profile-marker-001",
    active_profile: str | None = "profile-marker-001",
    draft: str = "present",
    attestation: str = "pending",
    probe: str = "pending",
    gateway_ready: bool = False,
    ticket_generation: int = 1,
    prompt_delivery: str = "none",
) -> dict[str, Any]:
    return {
        "authenticated": authenticated,
        "selected_session": selected_session,
        "selected_profile": selected_profile,
        "active_profile": active_profile,
        "draft": draft,
        "attestation": attestation,
        "probe": probe,
        "gateway_ready": gateway_ready,
        "ticket_generation": ticket_generation,
        "prompt_delivery": prompt_delivery,
    }


def _case(
    case_id: str,
    initial_state: str,
    context: dict[str, Any],
    events: tuple[str, ...],
    notes: str,
) -> tuple[str, str, dict[str, Any], tuple[str, ...], str]:
    return case_id, initial_state, context, events, notes


CASE_DEFINITIONS = (
    _case("state-offline", "offline", _context(authenticated=False, selected_session=None, draft="empty", ticket_generation=0), (), "Offline is safe and has no transport side effect."),
    _case("state-auth-required", "auth_required", _context(authenticated=False, ticket_generation=0), (), "Authentication is required before a connection can open."),
    _case("initial-connect-ready", "connecting", _context(attestation="pending", probe="pending"), ("transport.open", "gateway.ready", "attestation.pass", "probe.pass", "session.resume.start", "session.resume.ok"), "Gateway readiness and both compatibility gates precede selected-session restoration."),
    _case("gateway-ready-barrier", "handshaking", _context(attestation="pending", probe="pending"), ("gateway.ready", "retry.session.status"), "Application methods cannot cross the gateway.ready barrier."),
    _case("gates-before-gateway", "handshaking", _context(attestation="pending", probe="pending"), ("attestation.pass", "probe.pass"), "Passing evidence without gateway.ready does not enable the connection."),
    _case("gateway-ready-timeout-fails", "handshaking", _context(attestation="pending", probe="pending"), ("attestation.pass", "probe.pass", "gateway.ready.timeout"), "A missing gateway.ready deadline closes the transport and reports a semantic handshake failure."),
    _case("attestation-mismatch-blocks", "handshaking", _context(attestation="pending", probe="pending"), ("gateway.ready", "attestation.fail"), "A missing or mismatched attestation blocks the surface."),
    _case("probe-failure-blocks", "handshaking", _context(attestation="pending", probe="pending"), ("gateway.ready", "attestation.pass", "probe.fail"), "A failed behavioral probe blocks the surface."),
    _case("state-ready", "ready", _context(attestation="passed", probe="passed", gateway_ready=True), (), "Ready is observable only after the compatibility gate has passed."),
    _case("profile-drift-at-initialization-blocked", "ready", _context(attestation="passed", probe="passed", gateway_ready=True, active_profile=PROFILE_DRIFT_MARKER), (), "A selected/active profile mismatch is rejected before a ready context can exist."),
    _case("profile-drift-before-readiness-blocked", "connecting", _context(attestation="pending", probe="pending"), ("profile.drift", "transport.open"), "A profile that drifts before transport readiness cannot reach ready."),
    _case("restore-selected-session", "ready", _context(attestation="passed", probe="passed", gateway_ready=True), ("session.resume.start", "session.resume.ok"), "Restoration resolves the selected server-owned session."),
    _case("restore-empty-session", "ready", _context(selected_session=None, draft="empty", attestation="passed", probe="passed", gateway_ready=True), ("session.resume.start", "session.empty"), "An empty restore result returns to ready without inventing a session."),
    _case("state-restoring", "restoring", _context(attestation="passed", probe="passed", gateway_ready=True), (), "Restoring is a barrier and does not permit prompt retry."),
    _case("state-reconnecting", "reconnecting", _context(attestation="pending", probe="pending", gateway_ready=False), (), "Reconnecting keeps local safe state while a new transport is pending."),
    _case("state-failed", "failed", _context(), (), "A known failure remains recoverable only through explicit user action."),
    _case("state-incompatible", "incompatible", _context(), (), "Incompatibility is terminal for this surface and has no fallback."),
    _case("reconnect-fresh-ticket-and-restore", "ready", _context(attestation="passed", probe="passed", gateway_ready=True), ("transport.loss", "ticket.fresh", "transport.open", "gateway.ready", "attestation.pass", "probe.pass", "session.resume.start", "session.resume.ok"), "Reconnect uses a new ticket and restores before recovery actions while preserving the configured profile."),
    _case("reconnect-profile-drift-rejected", "ready", _context(attestation="passed", probe="passed", gateway_ready=True), ("transport.loss", "ticket.fresh", "transport.open", "gateway.ready", "attestation.pass", "probe.pass", "session.resume.start", "profile.drift"), "Reconnect and restore reject an active profile that drifts from the selected configured profile."),
    _case("reconnect-without-fresh-ticket", "ready", _context(attestation="passed", probe="passed", gateway_ready=True), ("transport.loss", "transport.open"), "A reconnect cannot reuse the old upgrade credential."),
    _case("reconnect-ticket-reuse-blocked", "ready", _context(attestation="passed", probe="passed", gateway_ready=True), ("transport.loss", "ticket.reuse"), "A reused or consumed ticket enters authentication recovery."),
    _case("restore-profile-drift-rejected", "ready", _context(attestation="passed", probe="passed", gateway_ready=True), ("session.resume.start", "profile.drift"), "Restore rejects profile drift while preserving the selected configured profile."),
    _case("restore-before-idempotent-retry", "restoring", _context(attestation="passed", probe="passed", gateway_ready=True), ("retry.session.history",), "History retry is blocked until restore completes."),
    _case("idempotent-retry-after-restore", "restoring", _context(attestation="passed", probe="passed", gateway_ready=True), ("session.resume.ok", "retry.session.history"), "History is the only kind of retry represented after restore."),
    _case("non-idempotent-retry-blocked", "ready", _context(attestation="passed", probe="passed", gateway_ready=True), ("retry.prompt.submit",), "Prompt submission is not an idempotent retry."),
    _case("prompt-transport-loss-uncertain", "ready", _context(attestation="passed", probe="passed", gateway_ready=True), ("prompt.sent", "transport.loss"), "A lost result enters delivery_uncertain and preserves the draft."),
    _case("uncertain-restore-barrier", "delivery_uncertain", _context(attestation="passed", probe="passed", gateway_ready=True, prompt_delivery="uncertain"), ("session.resume.start", "session.resume.ok"), "C-05 stops after restore and defers resend choice to C-06."),
    _case("prompt-auto-resubmit-blocked", "delivery_uncertain", _context(attestation="passed", probe="passed", gateway_ready=True, prompt_delivery="uncertain"), ("prompt.auto_retry",), "The connection contract never auto-resubmits an uncertain prompt."),
    _case("cancel-connecting", "connecting", _context(), ("user.cancel", "close.complete"), "Cancellation closes cleanup and suppresses reconnect."),
    _case("cancel-restoring", "restoring", _context(attestation="passed", probe="passed", gateway_ready=True), ("user.cancel", "close.complete"), "Restore cancellation preserves safe local state."),
    _case("cancel-reconnecting", "reconnecting", _context(), ("user.cancel", "close.complete"), "Reconnect cancellation never schedules another reconnect."),
    _case("sign-out-clears-session-preserves-draft", "ready", _context(attestation="passed", probe="passed", gateway_ready=True), ("user.sign_out", "close.complete"), "Sign-out clears the selected server session but preserves the draft."),
    _case("state-closing", "closing", _context(), ("close.complete",), "Closing completes cleanup and does not reconnect."),
    _case("known-auth-close", "ready", _context(attestation="passed", probe="passed", gateway_ready=True), ("close.4401",), "Authentication rejection invalidates the connection path."),
    _case("known-host-close-incompatible", "handshaking", _context(), ("close.4403",), "Known host or origin rejection is incompatible for this surface."),
    _case("known-chat-disabled-close", "ready", _context(attestation="passed", probe="passed", gateway_ready=True), ("close.4404",), "A disabled embedded chat surface is incompatible."),
    _case("known-peer-rejected-close", "ready", _context(attestation="passed", probe="passed", gateway_ready=True), ("close.4408",), "A known peer rejection is a failed connection outcome."),
    _case("known-attachment-close", "ready", _context(attestation="passed", probe="passed", gateway_ready=True), ("close.4409",), "A superseded attachment is a failed operation, not an unknown close."),
    _case("known-pty-exited-close", "ready", _context(attestation="passed", probe="passed", gateway_ready=True), ("close.4410",), "A PTY exit is a known failed outcome; this fixture does not reconnect Terminal."),
    _case("known-backend-failure", "ready", _context(attestation="passed", probe="passed", gateway_ready=True), ("close.1011",), "A known backend failure is recoverable only by explicit retry."),
    _case("unknown-event-fails-closed", "ready", _context(attestation="passed", probe="passed", gateway_ready=True), ("event.unknown",), "Unknown events cannot become interactive behavior."),
    _case("unknown-close-fails-closed", "ready", _context(attestation="passed", probe="passed", gateway_ready=True), ("close.4999",), "Unknown close codes cannot trigger an unsafe fallback."),
    _case("auth-success-starts-connect", "auth_required", _context(authenticated=False, ticket_generation=0), ("auth.success", "ticket.fresh", "transport.open", "gateway.ready", "attestation.pass", "probe.pass"), "Authentication recovery mints a fresh ticket before opening the transport."),
    _case("offline-network-loss", "connecting", _context(), ("network.offline",), "A network loss returns to offline without claiming rejection."),
    _case("send-before-gateway-ready", "handshaking", _context(), ("prompt.sent",), "Prompt send before handshake readiness is blocked."),
    _case("session-and-draft-preserved-on-reconnect-cancel", "reconnecting", _context(), ("user.cancel", "close.complete"), "Selected session and draft remain local during explicit reconnect cancellation."),
    _case("sign-out-during-uncertain-delivery", "delivery_uncertain", _context(attestation="passed", probe="passed", gateway_ready=True, prompt_delivery="uncertain"), ("user.sign_out", "close.complete"), "Sign-out is safe even while prompt delivery remains uncertain."),
)


def _initial_state_context(initial_state: str, context: dict[str, Any]) -> dict[str, Any]:
    state = initial_state
    compatibility_gate = "passed" if state in {"ready", "restoring", "delivery_uncertain"} else "blocked" if state == "incompatible" else "pending"
    restore_barrier = "passed" if state == "ready" and context["prompt_delivery"] == "none" and context["selected_session"] is not None else "pending" if state in {"restoring", "reconnecting", "delivery_uncertain"} else "not_required"
    if state == "ready" and context["selected_session"] is None:
        restore_barrier = "not_required"
    runtime = {
        "state": state,
        "authenticated": context["authenticated"],
        "selected_session": context["selected_session"],
        "selected_profile": context["selected_profile"],
        "active_profile": context["active_profile"],
        "draft": context["draft"],
        "attestation": context["attestation"],
        "probe": context["probe"],
        "gateway_ready": context["gateway_ready"],
        "ticket_generation": context["ticket_generation"],
        "ticket_generations": [context["ticket_generation"]] if context["ticket_generation"] > 0 else [],
        "prompt_delivery": context["prompt_delivery"],
        "restore_barrier": restore_barrier,
        "prompt_retry": "deferred_to_C-06" if state == "delivery_uncertain" else "none",
        "compatibility_gate": compatibility_gate,
        "effects": [],
        "decision": "blocked" if state == "incompatible" else state,
        "required_ticket_generation": None,
        "auto_resubmitted": False,
        "transport_closed": False,
    }
    if runtime["selected_profile"] != runtime["active_profile"]:
        # Profile identity is an initialization barrier, not optional metadata.
        runtime["state"] = "incompatible"
        runtime["restore_barrier"] = "blocked"
        runtime["compatibility_gate"] = "blocked"
        runtime["decision"] = "profile_mismatch"
        runtime["transport_closed"] = True
        runtime["effects"].extend(["profile_drift_observed", "profile_drift_rejected", "transport_closed"])
    return runtime


def _fail_closed(runtime: dict[str, Any], effect: str) -> None:
    runtime["state"] = "incompatible"
    runtime["compatibility_gate"] = "blocked"
    runtime["decision"] = "blocked"
    runtime["effects"].append(effect)


def _reject_profile_drift(runtime: dict[str, Any]) -> None:
    """Reject a transport whose active profile differs from the configured selection."""
    runtime["state"] = "incompatible"
    runtime["restore_barrier"] = "blocked"
    runtime["compatibility_gate"] = "blocked"
    runtime["decision"] = "profile_mismatch"
    runtime["transport_closed"] = True
    if "profile_drift_observed" not in runtime["effects"]:
        runtime["effects"].append("profile_drift_observed")
    runtime["effects"].extend(["profile_drift_rejected", "transport_closed"])


def _maybe_ready(runtime: dict[str, Any]) -> None:
    if runtime["active_profile"] != runtime["selected_profile"]:
        _reject_profile_drift(runtime)
        return
    if runtime["state"] == "handshaking" and runtime["gateway_ready"] and runtime["attestation"] == "passed" and runtime["probe"] == "passed":

        runtime["state"] = "ready"
        runtime["compatibility_gate"] = "passed"
        runtime["restore_barrier"] = "not_required"
        runtime["decision"] = "ready"
        runtime["effects"].append("compatibility_gate_passed")


def _transition(runtime: dict[str, Any], event: str) -> None:
    state = runtime["state"]
    if event == "network.offline":
        if state == "closing":
            _fail_closed(runtime, "offline_after_close_blocked")
            return
        runtime["state"] = "offline"
        runtime["decision"] = "offline"
        runtime["effects"].append("transport_unavailable")
        return
    if event == "connect.start":
        if state not in {"offline", "auth_required", "failed"}:
            _fail_closed(runtime, "connect_from_invalid_state")
            return
        runtime["state"] = "connecting"
        runtime["decision"] = "connecting"
        runtime["effects"].append("connect_started")
        return
    if event == "auth.required":
        if state == "closing":
            _fail_closed(runtime, "auth_after_close_blocked")
            return
        runtime["state"] = "auth_required"
        runtime["authenticated"] = False
        runtime["decision"] = "auth_required"
        runtime["effects"].append("fresh_ticket_required")
        return
    if event == "auth.success":
        if state != "auth_required":
            _fail_closed(runtime, "auth_success_from_invalid_state")
            return
        runtime["state"] = "connecting"
        runtime["authenticated"] = True
        runtime["decision"] = "connecting"
        runtime["effects"].append("authenticated")
        return
    if event == "transport.open":
        if state not in {"connecting", "reconnecting"}:
            _fail_closed(runtime, "transport_open_out_of_order")
            return
        if state == "connecting" and runtime["ticket_generation"] <= 0:
            runtime["state"] = "auth_required"
            runtime["decision"] = "auth_required"
            runtime["effects"].append("fresh_ticket_required")
            return
        required = runtime["required_ticket_generation"]
        if state == "reconnecting" and (required is None or runtime["ticket_generation"] < required):
            runtime["state"] = "auth_required"
            runtime["decision"] = "auth_required"
            runtime["effects"].append("fresh_ticket_required")
            return
        if runtime["active_profile"] != runtime["selected_profile"]:
            _reject_profile_drift(runtime)
            return
        runtime["state"] = "handshaking"
        runtime["gateway_ready"] = False
        runtime["attestation"] = "pending"
        runtime["probe"] = "pending"
        runtime["compatibility_gate"] = "pending"
        runtime["decision"] = "handshaking"
        runtime["transport_closed"] = False
        runtime["effects"].append("transport_open")
        return
    if event == "gateway.ready.timeout":
        if state != "handshaking":
            _fail_closed(runtime, "gateway_ready_timeout_out_of_order")
            return
        runtime["transport_closed"] = True
        runtime["state"] = "failed"
        runtime["compatibility_gate"] = "blocked"
        runtime["decision"] = "handshake_failed"
        runtime["effects"].extend(["gateway_ready_timeout", "transport_closed", "handshake_failed"])
        return
    if event == "gateway.ready":
        if state != "handshaking":
            _fail_closed(runtime, "gateway_ready_out_of_order")
            return
        runtime["gateway_ready"] = True
        runtime["effects"].append("gateway_ready_received")
        _maybe_ready(runtime)
        return
    if event == "attestation.pass":
        if state != "handshaking":
            _fail_closed(runtime, "attestation_out_of_order")
            return
        runtime["attestation"] = "passed"
        runtime["effects"].append("attestation_verified")
        _maybe_ready(runtime)
        return
    if event == "attestation.fail":
        if state != "handshaking":
            _fail_closed(runtime, "attestation_out_of_order")
            return
        runtime["attestation"] = "failed"
        _fail_closed(runtime, "compatibility_attestation_failed")
        return
    if event == "probe.pass":
        if state != "handshaking":
            _fail_closed(runtime, "probe_out_of_order")
            return
        runtime["probe"] = "passed"
        runtime["effects"].append("behavioral_probe_passed")
        _maybe_ready(runtime)
        return
    if event == "probe.fail":
        if state != "handshaking":
            _fail_closed(runtime, "probe_out_of_order")
            return
        runtime["probe"] = "failed"
        _fail_closed(runtime, "behavioral_probe_failed")
        return
    if event == "session.resume.start":
        if state not in {"ready", "delivery_uncertain"}:
            _fail_closed(runtime, "restore_out_of_order")
            return
        if runtime["active_profile"] != runtime["selected_profile"]:
            _reject_profile_drift(runtime)
            return
        runtime["state"] = "restoring"
        runtime["restore_barrier"] = "pending"
        runtime["decision"] = "restoring"
        runtime["effects"].append("restore_started")
        return
    if event == "session.resume.ok":
        if state != "restoring":
            _fail_closed(runtime, "restore_result_out_of_order")
            return
        if runtime["active_profile"] != runtime["selected_profile"]:
            _reject_profile_drift(runtime)
            return
        runtime["state"] = "ready"
        runtime["restore_barrier"] = "passed"
        runtime["decision"] = "restored"
        runtime["effects"].append("server_session_restored")
        return
    if event == "session.empty":
        if state != "restoring":
            _fail_closed(runtime, "empty_restore_out_of_order")
            return
        if runtime["active_profile"] != runtime["selected_profile"]:
            _reject_profile_drift(runtime)
            return
        runtime["state"] = "ready"
        runtime["selected_session"] = None
        runtime["restore_barrier"] = "passed"
        runtime["decision"] = "restored_empty"
        runtime["effects"].append("server_session_empty")
        return
    if event == "profile.drift":
        if state not in {"connecting", "reconnecting", "handshaking", "restoring"}:
            _fail_closed(runtime, "profile_drift_out_of_order")
            return
        runtime["active_profile"] = PROFILE_DRIFT_MARKER
        if state in {"handshaking", "restoring"}:
            _reject_profile_drift(runtime)
        else:
            runtime["effects"].append("profile_drift_observed")
        return
    if event == "transport.loss":
        if state not in {"ready", "restoring", "handshaking"}:
            _fail_closed(runtime, "transport_loss_out_of_order")
            return
        runtime["required_ticket_generation"] = runtime["ticket_generation"] + 1
        runtime["restore_barrier"] = "pending"
        runtime["gateway_ready"] = False
        runtime["attestation"] = "pending"
        runtime["probe"] = "pending"
        runtime["transport_closed"] = True
        runtime["effects"].append("transport_lost")
        if runtime["prompt_delivery"] == "in_flight":
            runtime["state"] = "delivery_uncertain"
            runtime["prompt_delivery"] = "uncertain"
            runtime["prompt_retry"] = "deferred_to_C-06"
            runtime["decision"] = "delivery_uncertain"
            runtime["effects"].append("prompt_delivery_uncertain")
        else:
            runtime["state"] = "reconnecting"
            runtime["decision"] = "reconnecting"
            runtime["effects"].append("reconnect_started")
        return
    if event == "ticket.fresh":
        if state not in {"connecting", "reconnecting"}:
            _fail_closed(runtime, "fresh_ticket_out_of_order")
            return
        runtime["ticket_generation"] += 1
        runtime["ticket_generations"].append(runtime["ticket_generation"])
        runtime["effects"].append("fresh_ticket_minted")
        return
    if event == "ticket.reuse":
        if state != "reconnecting":
            _fail_closed(runtime, "ticket_reuse_out_of_order")
            return
        runtime["state"] = "auth_required"
        runtime["decision"] = "auth_required"
        runtime["effects"].append("reused_ticket_rejected")
        return
    if event.startswith("retry."):
        method = event.removeprefix("retry.")
        if state != "ready" or runtime["restore_barrier"] in {"pending", "blocked"}:
            _fail_closed(runtime, "retry_before_restore_blocked")
            return
        if method not in RETRYABLE_METHODS:
            _fail_closed(runtime, "non_idempotent_retry_blocked")
            return
        runtime["decision"] = "idempotent_retry"
        runtime["effects"].append(f"retry_idempotent_{method.replace('.', '_')}")
        return
    if event == "prompt.sent":
        if state != "ready" or runtime["restore_barrier"] in {"pending", "blocked"}:
            _fail_closed(runtime, "prompt_send_before_ready_blocked")
            return
        runtime["prompt_delivery"] = "in_flight"
        runtime["decision"] = "prompt_forwarded"
        runtime["effects"].append("prompt_forwarded")
        return
    if event in {"prompt.auto_retry", "retry.prompt.submit"}:
        _fail_closed(runtime, "prompt_auto_resubmit_blocked")
        return
    if event == "user.cancel":
        if state not in {"connecting", "handshaking", "restoring", "reconnecting", "delivery_uncertain"}:
            _fail_closed(runtime, "cancel_out_of_order")
            return
        runtime["state"] = "closing"
        runtime["decision"] = "cancelled"
        runtime["effects"].extend(["cancelled", "reconnect_suppressed"])
        return
    if event == "user.sign_out":
        if state == "closing":
            _fail_closed(runtime, "sign_out_after_close_blocked")
            return
        runtime["state"] = "closing"
        runtime["authenticated"] = False
        runtime["selected_session"] = None
        runtime["decision"] = "signed_out"
        runtime["effects"].extend(["signed_out", "session_reference_cleared"])
        if runtime["draft"] == "present":
            runtime["effects"].append("draft_preserved")
        return
    if event == "close.complete":
        if state != "closing":
            _fail_closed(runtime, "close_complete_out_of_order")
            return
        runtime["state"] = "offline"
        runtime["decision"] = "closed"
        runtime["effects"].append("cleanup_complete")
        return
    if event.startswith("close."):
        code = event.removeprefix("close.")
        if code not in KNOWN_CLOSE_CODES:
            _fail_closed(runtime, "unknown_close_code_blocked")
            return
        target = KNOWN_CLOSE_CODES[code]
        runtime["state"] = target
        runtime["decision"] = target
        if target == "auth_required":
            runtime["authenticated"] = False
            runtime["effects"].append("ticket_invalidated")
        elif target == "incompatible":
            runtime["compatibility_gate"] = "blocked"
            runtime["effects"].append("compatibility_close_blocked")
        else:
            runtime["effects"].append("known_backend_failure")
        return
    if event == "event.unknown":
        _fail_closed(runtime, "unknown_event_blocked")
        return
    _fail_closed(runtime, "unsupported_event_blocked")


def evaluate_case(case: dict[str, Any]) -> dict[str, Any]:
    """Run one closed synthetic event sequence through the reducer."""
    runtime = _initial_state_context(case["initial_state"], case["initial_context"])
    trace = [runtime["state"]]
    for event in case["events"]:
        _transition(runtime, event)
        if runtime["state"] != trace[-1]:
            trace.append(runtime["state"])
    return {
        "decision": runtime["decision"],
        "final_state": runtime["state"],
        "trace": trace,
        "effects": runtime["effects"],
        "selected_session": runtime["selected_session"],
        "selected_profile": runtime["selected_profile"],
        "active_profile": runtime["active_profile"],
        "draft": runtime["draft"],
        "ticket_generations": runtime["ticket_generations"],
        "restore_barrier": runtime["restore_barrier"],
        "prompt_retry": runtime["prompt_retry"],
        "compatibility_gate": runtime["compatibility_gate"],
        "transport_closed": runtime["transport_closed"],
        "prompt_auto_resubmitted": runtime["auto_resubmitted"],
    }


def _case_definition_map() -> dict[str, tuple[str, str, dict[str, Any], tuple[str, ...], str]]:
    return {definition[0]: definition for definition in CASE_DEFINITIONS}


def _validate_state_table(document: dict[str, Any]) -> None:
    states = document["states"]
    _require(type(states) is list, "states must be an array")
    _strict_equal(states, list(EXPECTED_STATES), "states")


def _validate_invariants(document: dict[str, Any]) -> None:
    _strict_equal(document["invariants"], EXPECTED_INVARIANTS, "invariants")


def validate_document(document: dict[str, Any]) -> None:
    _strict_keys(document, ROOT_KEYS, "document")
    _require(document["schema"] == SCHEMA, "schema changed")
    _require(document["operation"] == OPERATION, "operation changed")
    _require(document["contract"] == CONTRACT, "contract changed")
    _require(document["hermes_source_sha"] == HERMES_SOURCE_SHA, "source revision changed")
    _strict_bool(document["synthetic_only"], "synthetic_only")
    _require(document["synthetic_only"] is True, "fixture must remain synthetic")
    _require(document["surface"] == SURFACE, "surface changed")
    _validate_state_table(document)
    _validate_invariants(document)
    _strict_equal(document["redaction"], EXPECTED_REDACTION, "redaction")
    _validate_redaction(document)

    cases = document["cases"]
    _require(type(cases) is list, "cases must be an array")
    _require(len(cases) == len(CASE_DEFINITIONS), "case count changed")
    definitions = _case_definition_map()
    seen: set[str] = set()
    ordered_ids: list[str] = []
    for index, case in enumerate(cases):
        item = _strict_keys(case, CASE_KEYS, f"case[{index}]")
        _strict_string(item["id"], f"case[{index}].id")
        _require(item["id"] not in seen, "duplicate case id")
        seen.add(item["id"])
        ordered_ids.append(item["id"])
        _require(item["id"] in definitions, "unknown case id")
        expected_id, expected_state, expected_context, expected_events, expected_notes = definitions[item["id"]]
        _require(item["id"] == expected_id, "case order changed")
        _require(item["initial_state"] == expected_state, "case initial state changed")
        _strict_equal(item["initial_context"], expected_context, f"case[{index}].initial_context")
        _strict_equal(item["events"], list(expected_events), f"case[{index}].events")
        _require(item["notes"] == expected_notes, f"case[{index}].notes")
        _strict_keys(item["initial_context"], CONTEXT_KEYS, f"case[{index}].initial_context")
        _require(item["initial_state"] in STATES, "unknown initial state")
        _strict_bool(item["initial_context"]["authenticated"], "authenticated")
        selected = item["initial_context"]["selected_session"]
        _require(selected is None or type(selected) is str, "selected session must be text or null")
        for profile_key in ("selected_profile", "active_profile"):
            profile = item["initial_context"][profile_key]
            _require(profile is None or type(profile) is str, f"{profile_key} must be text or null")
        _require(item["initial_context"]["draft"] in {"empty", "present"}, "draft state changed")
        for key in ("attestation", "probe"):
            _require(item["initial_context"][key] in {"missing", "pending", "passed", "failed"}, f"{key} state changed")
        _strict_bool(item["initial_context"]["gateway_ready"], "gateway_ready")
        _strict_int(item["initial_context"]["ticket_generation"], "ticket_generation")
        _require(item["initial_context"]["ticket_generation"] >= 0, "ticket_generation must be non-negative")
        _require(item["initial_context"]["prompt_delivery"] in {"none", "in_flight", "uncertain"}, "prompt delivery state changed")
        _require(type(item["events"]) is list, "events must be an array")
        for event in item["events"]:
            _strict_string(event, "event")
        expected = evaluate_case(item)
        _strict_keys(item["expected"], EXPECTED_KEYS, f"case[{index}].expected")
        _strict_equal(item["expected"], expected, f"case[{index}].expected")
    _require(tuple(ordered_ids) == tuple(item[0] for item in CASE_DEFINITIONS), "case order changed")


def _dist(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    p95_index = max(0, math.ceil(len(ordered) * 0.95) - 1)
    return {
        "min": round(ordered[0], 6),
        "p50": round(statistics.median(ordered), 6),
        "p95": round(ordered[p95_index], 6),
        "max": round(ordered[-1], 6),
        "mean": round(statistics.mean(ordered), 6),
    }


def _validate_samples(value: Any, label: str) -> list[float]:
    _require(type(value) is list and len(value) == BASELINE_REPETITIONS, f"{label} sample count changed")
    samples: list[float] = []
    for sample in value:
        _require(type(sample) is float, f"{label} sample type changed")
        _require(math.isfinite(sample) and sample > 0, f"{label} sample is not finite")
        samples.append(sample)
    return samples


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def _baseline_identity_digest(baseline: dict[str, Any]) -> str:
    identity = {key: baseline[key] for key in BASELINE_IDENTITY_KEYS}
    return hashlib.sha256(_canonical_json_bytes(identity)).hexdigest()


def _validate_baseline(baseline: dict[str, Any]) -> int:
    _strict_keys(baseline, BASELINE_KEYS, "baseline")
    _require(baseline["schema"] == BASELINE_SCHEMA, "baseline schema changed")
    _require(baseline["validator"] == "contracts/fixtures/connection-restoration/validate.py", "baseline validator changed")
    _require(baseline["command"] == APPROVED_BASELINE_COMMAND, "baseline command changed")
    _require(baseline["build_mode"] == "N/A", "baseline build mode changed")
    _strict_int(baseline["repetitions"], "baseline repetitions")
    _require(baseline["repetitions"] == BASELINE_REPETITIONS, "baseline repetitions changed")
    _require(baseline["threshold"] is None, "baseline threshold must remain null")

    artifact_bytes = 0
    _require(type(baseline["artifact_files"]) is list and len(baseline["artifact_files"]) == len(BASELINE_ARTIFACTS), "baseline artifact list changed")
    for index, artifact in enumerate(baseline["artifact_files"]):
        _strict_keys(artifact, ARTIFACT_KEYS, f"baseline.artifact_files[{index}]")
        _require(artifact["path"] == BASELINE_ARTIFACTS[index], "baseline artifact path changed")
        _require(type(artifact["sha256"]) is str and len(artifact["sha256"]) == 64, "baseline artifact digest changed")
        _strict_int(artifact["size_bytes"], "baseline artifact size")
        path = ROOT / artifact["path"]
        _require(path.resolve().parent == ROOT.resolve(), "baseline artifact escaped fixture root")
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise ContractError("baseline artifact is missing") from exc
        _require(hashlib.sha256(data).hexdigest() == artifact["sha256"], "baseline artifact digest mismatch")
        _require(len(data) == artifact["size_bytes"], "baseline artifact size mismatch")
        artifact_bytes += len(data)
    _strict_int(baseline["artifact_bytes"], "baseline artifact bytes")
    _require(baseline["artifact_bytes"] == artifact_bytes, "baseline artifact bytes changed")

    environment = _strict_keys(baseline["environment"], ("platform", "python"), "baseline.environment")
    _strict_string(environment["platform"], "baseline platform")
    _strict_string(environment["python"], "baseline python")
    for mode in ("normal", "optimized"):
        benchmark = _strict_keys(baseline[mode], BENCHMARK_KEYS, f"baseline.{mode}")
        _strict_string(benchmark["command"], f"baseline.{mode}.command")
        _require(benchmark["command"] == APPROVED_BENCHMARK_COMMANDS[mode], f"baseline.{mode}.command changed")
        samples = _validate_samples(benchmark["samples_ms"], f"baseline.{mode}")
        _strict_keys(benchmark["distribution"], DISTRIBUTION_KEYS, f"baseline.{mode}.distribution")
        _strict_equal(benchmark["distribution"], _dist(samples), f"baseline.{mode}.distribution")
    _require(_baseline_identity_digest(baseline) == BASELINE_CANONICAL_IDENTITY_SHA256, "baseline canonical identity changed")
    return artifact_bytes


def validate_all(document: dict[str, Any], baseline: dict[str, Any]) -> tuple[int, int]:
    validate_document(document)
    artifact_bytes = _validate_baseline(baseline)
    return len(document["cases"]), artifact_bytes


def _parse_cli(argv: list[str]) -> tuple[Path, Path]:
    cases_path = CASES_PATH
    baseline_path = BASELINE_PATH
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument in {"--cases", "--baseline"}:
            if index + 1 >= len(argv):
                raise ContractError("unsupported CLI arguments")
            path = Path(argv[index + 1])
            if argument == "--cases":
                cases_path = path
            else:
                baseline_path = path
            index += 2
            continue
        raise ContractError("unsupported CLI arguments")
    return cases_path, baseline_path


def _error_line() -> str:
    return json.dumps({"error": {"code": "contract", "message": "connection restoration fixture rejected"}}, sort_keys=True)


def main(argv: list[str] | None = None) -> int:
    try:
        cases_path, baseline_path = _parse_cli(list(sys.argv[1:] if argv is None else argv))
        document = _load_json(cases_path, "cases")
        baseline = _load_json(baseline_path, "baseline")
        _require(type(document) is dict, "cases root must be an object")
        _require(type(baseline) is dict, "baseline root must be an object")
        case_count, artifact_bytes = validate_all(document, baseline)
    except (ContractError, OSError, UnicodeError, TypeError, ValueError, OverflowError, RecursionError):
        print(_error_line())
        return 1
    print(f"connection_restoration_validation=ok states={len(STATES)} cases={case_count} artifact_bytes={artifact_bytes}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
