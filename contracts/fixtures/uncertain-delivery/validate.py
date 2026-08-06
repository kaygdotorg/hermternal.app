#!/usr/bin/env python3
"""Validate the deterministic synthetic C-06 uncertain-delivery contract.

This is an offline reducer, not a Hermes client.  It reads only checked-in
semantic markers and never opens a WebSocket, calls a Dashboard, imports
Hermes, stores prompt text, or claims live compatibility.  Explicit
ContractError checks keep the fail-closed boundary active under ``python -O``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import statistics
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
CASES_PATH = ROOT / "cases.json"
BASELINE_PATH = ROOT / "validation-baseline.json"
SCHEMA = "hermternal.uncertain-delivery.v1"
BASELINE_SCHEMA = "hermternal.uncertain-delivery-baseline.v1"
OPERATION = "C-06"
CONTRACT = "dashboard-v0.0.1"
HERMES_SOURCE_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"

# These identities are deliberately outside the JSON baseline.  A mutable
# timing record or copied validator cannot authorize a different fixture,
# source file, or benchmark trace by rebinding its own metadata.
CANONICAL_CASES_SHA256 = "18a0224bdf0f358f477c4f7d8175654096ed9caf41ac83e8e1607f6c2df53fdd"
CANONICAL_SOURCE_SHA256 = "0cc43d8d93650678a5290813cbdb358dbe65e8d5d171cf2febbc1563b2d7645d"
CANONICAL_ARTIFACT_MANIFEST_SHA256 = "f6427e76a133bbf8d47d9c4a8ffa820b2c7cbb677833908e5c33543bd338a952"
CANONICAL_BENCHMARK_IDENTITY = {
    "normal": {
        "samples_sha256": "b4116c46e65bc2f7f5b5ae52ac4fe1b820c0dac67756533a91715fb9a84aad45",
        "distribution_sha256": "31e328fe5ee9915a1df40df58875e61c2cebc2c8e516ec99906ca8525ba26633",
    },
    "optimized": {
        "samples_sha256": "129da99bc35da4a93a4135453a1a40f12a8fc029ce85c7c5956ebf0ee4ca757a",
        "distribution_sha256": "add3c3fa0a6a6c150f7bddd9740c4dff29fc8221e660e555e8e791de872bbf78",
    },
}
CANONICAL_ARTIFACT_NAMES = ("README.md", "cases.json", "test_validate.py")
EXPECTED_ENVIRONMENT = {
    "platform": "Darwin-25.5.0-arm64",
    "python": "3.14.6",
    "device": "Mac14,6",
    "build_mode": "N/A",
}

STATES = (
    "empty",
    "ready",
    "submitting",
    "streaming",
    "awaiting_approval",
    "awaiting_clarification",
    "interrupting",
    "delivery_uncertain",
    "restoring",
    "completed",
    "failed",
)
TRANSPORT_STATES = (
    "offline",
    "reconnecting",
    "ready",
    "handshaking",
    "incompatible",
)
AUTOMATIC_RETRY_METHODS = (
    "session.resume",
    "session.history",
    "session.status",
    "model.options",
)
NEVER_AUTOMATIC_RETRY_METHODS = (
    "prompt.submit",
    "session.create",
    "session.interrupt",
)
UNCERTAIN_REASONS = ("timeout", "websocket_close", "app_suspension", "process_loss")
RESTORE_PROMPT_PRESENCE = ("not_observed", "present", "absent", "unknown")
RESTORE_TURN_STATES = ("not_observed", "running", "streaming", "completed", "idle", "rejected", "unknown")
SUBMIT_RESULTS = ("accepted", "pending", "rejected", "unknown")
SERVER_EVENTS = (
    "message.delta",
    "reasoning.delta",
    "thinking.delta",
    "message.complete",
    "tool.start",
    "tool.complete",
    "approval.request",
    "clarify.request",
)
USER_ACTIONS = ("resend", "keep_draft", "retry_after_rejection")
EVENT_KEYS = {
    "submit": ("kind", "request_ref", "result"),
    "server_event": ("kind", "name"),
    "transport_loss": ("kind", "reason"),
    "restore_begin": ("kind",),
    "restore_history": ("kind", "prompt_presence"),
    "restore_status": ("kind", "turn_state"),
    "user_decision": ("kind", "action"),
    "duplicate_submit": ("kind",),
    "automatic_retry": ("kind", "method"),
    "read_retry": ("kind", "method", "result"),
    "interrupt_request": ("kind",),
    "interrupt_result": ("kind", "result"),
    "cancel": ("kind", "where"),
    "sign_out": ("kind",),
    "compatibility_failure": ("kind", "reason"),
    "unknown_event": ("kind", "name"),
    "evidence_pending": ("kind",),
}
CASE_IDS = (
    "empty-session",
    "accepted-present",
    "timeout-present-after-restore",
    "websocket-close-absent-idle",
    "app-suspension-absent-idle-explicit-resend",
    "process-loss-present-running",
    "confirmed-rejection",
    "restore-inconclusive",
    "idempotent-read-retry",
    "automatic-prompt-retry-blocked",
    "duplicate-submit-blocked",
    "resend-unknown-no-third-send",
    "interrupt-confirmed",
    "interrupt-unknown-after-close",
    "cancel-before-submit",
    "sign-out-during-uncertainty",
    "pending-restore-evidence",
    "incompatible-evidence",
    "unknown-interactive-event",
    "explicit-keep-draft-after-absent-idle",
    "confirmed-rejection-explicit-retry",
    "accepted-event-before-close",
)
ROOT_KEYS = (
    "schema",
    "operation",
    "contract",
    "hermes_source_sha",
    "synthetic_only",
    "source_observations",
    "states",
    "policies",
    "cases",
    "redaction",
    "accessibility",
)
STATE_KEYS = ("id", "meaning", "terminal", "allowed_actions")
SOURCE_OBSERVATION_KEYS = ("file", "anchor", "rule")
POLICY_KEYS = (
    "automatic_retry_methods",
    "never_automatic_retry_methods",
    "uncertain_transport_reasons",
    "restore_evidence_order",
    "explicit_resend_gate",
    "draft_policy",
    "duplicate_policy",
    "source_result_rule",
)
CASE_KEYS = ("id", "initial", "events", "expected", "notes")
INITIAL_KEYS = ("chat_state", "transport_state", "session_ref", "draft_state", "submission_count")
EXPECTED_KEYS = (
    "trace",
    "final_state",
    "transport_trace",
    "final_transport_state",
    "selected_session",
    "draft_state",
    "submission_count",
    "duplicate_attempts",
    "restore_barrier",
    "prompt_retry",
    "automatic_retry",
    "explicit_action_required",
    "outward_changes",
    "idempotent_collection_retries",
    "server_prompt_presence",
    "server_turn_state",
    "decision",
    "contract_error",
)
REDACTION_KEYS = (
    "contains_prompt_text",
    "contains_transcript",
    "contains_credentials",
    "contains_hosts",
    "contains_paths",
    "contains_raw_transport",
    "diagnostic_max_chars",
)
ACCESSIBILITY_KEYS = ("applicable", "reason")

MAX_JSON_BYTES = 512 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 4096
MAX_OBJECT_KEYS = 96
MAX_ARRAY_LENGTH = 256
MAX_STRING_LENGTH = 16 * 1024
MAX_INTEGER_DIGITS = 1024
MAX_ERROR_LENGTH = 240
BENCHMARK_REPETITIONS = 30
APPROVED_COMMANDS = {
    "normal": "python3 contracts/fixtures/uncertain-delivery/validate.py",
    "optimized": "python3 -O contracts/fixtures/uncertain-delivery/validate.py",
}

SYNTHETIC_REF = re.compile(r"^(?:session|request)-marker-[0-9]{3}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
BASE64ISH = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN = re.compile(r"(?:^|[\s:=/])(?:[a-z0-9-]+\.)+(?:com|net|org|io|dev|test|local|example|invalid|internal)(?:$|[\s/:])", re.IGNORECASE)
FORBIDDEN_KEYS = frozenset(
    {
        "prompt_text",
        "prompt_bytes",
        "raw_prompt",
        "transcript",
        "transcript_text",
        "transcript_bytes",
        "credential",
        "credentials",
        "password",
        "authorization",
        "cookie",
        "cookies",
        "ticket",
        "refresh_token",
        "bearer",
        "attach_handle",
        "pty_input",
        "pty_output",
        "raw_transport",
        "host",
        "hostname",
        "url",
        "path",
        "file_path",
    }
)


class ContractError(Exception):
    """A bounded, non-sensitive contract failure."""

    def __init__(self, code: str = "contract_rejected") -> None:
        super().__init__(code)
        self.code = code


def _fail(code: str = "contract_rejected") -> None:
    raise ContractError(code)


def _reject_constant(_: str) -> None:
    _fail("non_finite_number")


def _parse_int(raw: str) -> int:
    digits = raw[1:] if raw.startswith("-") else raw
    if len(digits) > MAX_INTEGER_DIGITS:
        _fail("integer_too_large")
    try:
        return int(raw)
    except (TypeError, ValueError, OverflowError):
        _fail("invalid_integer")
    raise ContractError("invalid_integer")


def _parse_float(raw: str) -> float:
    try:
        value = float(raw)
    except (TypeError, ValueError, OverflowError):
        _fail("invalid_number")
    if not math.isfinite(value):
        _fail("non_finite_number")
    return value


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate_key")
        result[key] = value
    return result


def _check_bounds(value: Any, *, depth: int = 0, nodes: list[int] | None = None) -> None:
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if nodes[0] > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
        _fail("input_too_deep_or_large")
    if isinstance(value, str):
        if len(value) > MAX_STRING_LENGTH:
            _fail("string_too_large")
        return
    if isinstance(value, list):
        if len(value) > MAX_ARRAY_LENGTH:
            _fail("array_too_large")
        for child in value:
            _check_bounds(child, depth=depth + 1, nodes=nodes)
        return
    if isinstance(value, dict):
        if len(value) > MAX_OBJECT_KEYS:
            _fail("object_too_large")
        for key, child in value.items():
            if not isinstance(key, str):
                _fail("object_key_type")
            _check_bounds(child, depth=depth + 1, nodes=nodes)
        return
    if isinstance(value, float) and not math.isfinite(value):
        _fail("non_finite_number")
    if value is not None and type(value) not in (bool, int, float):
        _fail("unsupported_json_type")


def load_json(path: Path, label: str) -> Any:
    try:
        raw = path.read_bytes()
    except (OSError, ValueError):
        _fail("input_unavailable")
    if len(raw) > MAX_JSON_BYTES:
        _fail("input_too_large")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        _fail("invalid_utf8")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_int=_parse_int,
            parse_float=_parse_float,
            parse_constant=_reject_constant,
        )
    except ContractError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
        _fail("invalid_json")
    _check_bounds(value)
    if not isinstance(value, dict):
        _fail("root_shape")
    return value


def _keys(value: Any, expected: tuple[str, ...]) -> None:
    if not isinstance(value, dict) or tuple(value.keys()) != expected:
        _fail("schema_keys")


def _string(value: Any, code: str) -> str:
    if type(value) is not str:
        _fail(code)
    return value


def _bool(value: Any, code: str) -> bool:
    if type(value) is not bool:
        _fail(code)
    return value


def _int(value: Any, code: str) -> int:
    if type(value) is not int:
        _fail(code)
    return value


def _enum(value: Any, allowed: tuple[str, ...], code: str) -> str:
    value = _string(value, code + "_type")
    if value not in allowed:
        _fail(code)
    return value


def _nullable_string(value: Any, code: str) -> str | None:
    if value is None:
        return None
    return _string(value, code)


def _synthetic_ref(value: Any, code: str) -> str:
    value = _string(value, code + "_type")
    if SYNTHETIC_REF.fullmatch(value) is None:
        _fail(code)
    return value


def _distribution(samples: list[float]) -> dict[str, float | int]:
    if not samples:
        _fail("empty_benchmark")
    ordered = sorted(samples)
    p95_index = max(0, math.ceil(len(ordered) * 0.95) - 1)
    return {
        "count": len(samples),
        "minimum_ms": round(min(samples), 6),
        "maximum_ms": round(max(samples), 6),
        "mean_ms": round(statistics.fmean(samples), 6),
        "median_ms": round(statistics.median(samples), 6),
        "p95_ms": round(ordered[p95_index], 6),
    }


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    try:
        return _sha256_bytes(path.read_bytes())
    except (OSError, ValueError):
        _fail("artifact_unavailable")
    raise ContractError("artifact_unavailable")


def _normalized_source_digest(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        _fail("source_unavailable")
    text = re.sub(
        r'(CANONICAL_SOURCE_SHA256\s*=\s*")[0-9a-f]{64}("?)',
        r'\1<source-identity>\2',
        text,
    )
    return _sha256_bytes(text.encode("utf-8"))


def _artifact_manifest(fixture_dir: Path) -> tuple[dict[str, dict[str, int | str]], str]:
    artifacts: dict[str, dict[str, int | str]] = {}
    for name in CANONICAL_ARTIFACT_NAMES:
        path = fixture_dir / name
        try:
            raw = path.read_bytes()
        except (OSError, ValueError):
            _fail("artifact_unavailable")
        artifacts[name] = {"bytes": len(raw), "sha256": _sha256_bytes(raw)}
    material = "".join(f"{name}:{artifacts[name]['bytes']}:{artifacts[name]['sha256']}\n" for name in CANONICAL_ARTIFACT_NAMES)
    return artifacts, _sha256_bytes(material.encode("utf-8"))


def _validate_redaction(value: Any, *, in_source_observation: bool = False, key: str | None = None) -> None:
    if isinstance(value, dict):
        for child_key, child in value.items():
            normalized = child_key.casefold().replace("-", "_").replace(".", "_")
            if not in_source_observation and normalized in FORBIDDEN_KEYS:
                _fail("redaction_key")
            _validate_redaction(child, in_source_observation=in_source_observation or child_key == "source_observations", key=child_key)
        return
    if isinstance(value, list):
        for child in value:
            _validate_redaction(child, in_source_observation=in_source_observation, key=key)
        return
    if not isinstance(value, str):
        return
    if len(value) > MAX_STRING_LENGTH:
        _fail("redaction_value")
    if in_source_observation or value == HERMES_SOURCE_SHA:
        return
    lowered = value.casefold()
    if key == "notes" and any(marker in lowered for marker in ("prompt text", "transcript", "raw payload", "tool output")):
        _fail("redaction_value")
    if any(marker in lowered for marker in ("http://", "https://", "file://", "bearer ", "basic ", "cookie:", "authorization:", "password=")):
        _fail("redaction_value")
    if value.startswith(("/", "~/", "\\")) or IPV4.search(value) or DOMAIN.search(value):
        _fail("redaction_value")
    has_upper = any(character.isupper() for character in value)
    has_lower = any(character.islower() for character in value)
    has_digit = any(character.isdigit() for character in value)
    if BASE64ISH.fullmatch(value) and (
        "=" in value
        or (has_upper and has_lower and has_digit and len(value) >= 8)
        or (value.isdigit() and len(value) >= 8)
        or value in {"abcdef"}
    ) and "-" not in value and "_" not in value:
        _fail("redaction_value")


def validate_document(document: dict[str, Any]) -> None:
    _keys(document, ROOT_KEYS)
    if document["schema"] != SCHEMA or document["operation"] != OPERATION or document["contract"] != CONTRACT:
        _fail("identity_mismatch")
    if document["hermes_source_sha"] != HERMES_SOURCE_SHA or not HEX40.fullmatch(document["hermes_source_sha"]):
        _fail("source_mismatch")
    if _bool(document["synthetic_only"], "synthetic_only") is not True:
        _fail("synthetic_only")

    observations = document["source_observations"]
    if type(observations) is not list or len(observations) != 4:
        _fail("source_observations")
    expected_observations = (
        ("tui_gateway/ws.py", "gateway.ready", "ready_before_application_rpc"),
        ("tui_gateway/ws.py", "WebSocketDisconnect", "disconnect_detaches_transport"),
        ("tui_gateway/methods_prompt.py", "prompt.submit", "server_starts_prompt_turn"),
        ("tui_gateway/methods_session.py", "session.resume", "restore_server_owned_session"),
    )
    for observation, expected in zip(observations, expected_observations):
        _keys(observation, SOURCE_OBSERVATION_KEYS)
        actual = tuple(_string(observation[field], "source_observation_value") for field in SOURCE_OBSERVATION_KEYS)
        if actual != expected:
            _fail("source_observations")

    states = document["states"]
    if type(states) is not list or len(states) != len(STATES):
        _fail("states")
    state_ids: list[str] = []
    for state in states:
        _keys(state, STATE_KEYS)
        state_id = _enum(state["id"], STATES, "state_id")
        if state_id in state_ids:
            _fail("duplicate_state")
        state_ids.append(state_id)
        _string(state["meaning"], "state_meaning")
        _bool(state["terminal"], "state_terminal")
        actions = state["allowed_actions"]
        if type(actions) is not list or not actions or any(type(action) is not str for action in actions):
            _fail("state_actions")
    if tuple(state_ids) != STATES:
        _fail("state_inventory")

    policies = document["policies"]
    _keys(policies, POLICY_KEYS)
    for key in ("automatic_retry_methods", "never_automatic_retry_methods", "uncertain_transport_reasons", "restore_evidence_order", "explicit_resend_gate"):
        values = policies[key]
        if type(values) is not list or not values or any(type(item) is not str for item in values):
            _fail("policy_values")
    if tuple(policies["automatic_retry_methods"]) != AUTOMATIC_RETRY_METHODS:
        _fail("automatic_retry_inventory")
    if tuple(policies["never_automatic_retry_methods"]) != NEVER_AUTOMATIC_RETRY_METHODS:
        _fail("never_retry_inventory")
    if tuple(policies["uncertain_transport_reasons"]) != UNCERTAIN_REASONS:
        _fail("uncertain_reason_inventory")
    if tuple(policies["restore_evidence_order"]) != ("session.history", "session.status"):
        _fail("restore_order")
    if tuple(policies["explicit_resend_gate"]) != ("restore_complete", "prompt_absent", "turn_idle", "user_confirmed"):
        _fail("resend_gate")
    if policies["draft_policy"] != "preserve_original_until_server_presence_or_user_discard":
        _fail("draft_policy")
    if policies["duplicate_policy"] != "one_submission_per_explicit_send":
        _fail("duplicate_policy")
    if policies["source_result_rule"] != "correlate_reply_by_request_identifier_and_events_by_event_name":
        _fail("source_result_rule")

    cases = document["cases"]
    if type(cases) is not list or len(cases) != len(CASE_IDS):
        _fail("case_count")
    seen_ids: list[str] = []
    for case, expected_id in zip(cases, CASE_IDS):
        _keys(case, CASE_KEYS)
        _validate_redaction(case)
        case_id = _string(case["id"], "case_id")
        if case_id != expected_id or case_id in seen_ids:
            _fail("case_inventory")
        seen_ids.append(case_id)
        _validate_initial(case["initial"])
        _validate_events(case["events"])
        _validate_expected(case["expected"])
        _string(case["notes"], "case_notes")
        result = evaluate_case(case)
        if result != case["expected"]:
            _fail("case_semantics")

    redaction = document["redaction"]
    _keys(redaction, REDACTION_KEYS)
    for key in REDACTION_KEYS[:-1]:
        if _bool(redaction[key], "redaction_flag") is not False:
            _fail("redaction_flag")
    if _int(redaction["diagnostic_max_chars"], "diagnostic_max_chars") != MAX_ERROR_LENGTH:
        _fail("diagnostic_limit")
    accessibility = document["accessibility"]
    _keys(accessibility, ACCESSIBILITY_KEYS)
    if _bool(accessibility["applicable"], "accessibility_applicable") is not False:
        _fail("accessibility_scope")
    _string(accessibility["reason"], "accessibility_reason")
    _validate_redaction(document)


def _validate_initial(initial: Any) -> None:
    _keys(initial, INITIAL_KEYS)
    _enum(initial["chat_state"], STATES, "initial_chat_state")
    _enum(initial["transport_state"], TRANSPORT_STATES, "initial_transport_state")
    _nullable_string(initial["session_ref"], "session_ref")
    if initial["session_ref"] is not None:
        _synthetic_ref(initial["session_ref"], "session_ref")
    _enum(initial["draft_state"], ("present", "absent"), "draft_state")
    count = _int(initial["submission_count"], "submission_count")
    if count < 0 or count > 4:
        _fail("submission_count")
    if initial["chat_state"] != "empty" and initial["session_ref"] is None:
        _fail("session_required")
    if initial["chat_state"] == "empty" and initial["session_ref"] is not None:
        _fail("empty_session_reference")


def _validate_events(events: Any) -> None:
    if type(events) is not list or len(events) > 32:
        _fail("events")
    request_refs: set[str] = set()
    for event in events:
        if not isinstance(event, dict) or "kind" not in event:
            _fail("event_shape")
        kind = _string(event["kind"], "event_kind")
        if kind not in EVENT_KEYS:
            _fail("event_kind")
        _keys(event, EVENT_KEYS[kind])
        if kind == "submit":
            ref = _synthetic_ref(event["request_ref"], "request_ref")
            if ref in request_refs:
                _fail("duplicate_request_ref")
            request_refs.add(ref)
            _enum(event["result"], SUBMIT_RESULTS, "submit_result")
        elif kind == "server_event":
            _enum(event["name"], SERVER_EVENTS, "server_event_name")
        elif kind == "transport_loss":
            _enum(event["reason"], UNCERTAIN_REASONS, "transport_loss_reason")
        elif kind == "restore_history":
            _enum(event["prompt_presence"], RESTORE_PROMPT_PRESENCE[1:], "prompt_presence")
        elif kind == "restore_status":
            _enum(event["turn_state"], RESTORE_TURN_STATES[1:], "turn_state")
        elif kind == "user_decision":
            _enum(event["action"], USER_ACTIONS, "user_action")
        elif kind == "automatic_retry":
            _string(event["method"], "retry_method")
        elif kind == "read_retry":
            method = _string(event["method"], "read_method")
            if method not in AUTOMATIC_RETRY_METHODS:
                _fail("read_method")
            _enum(event["result"], ("transient_error", "success"), "read_result")
        elif kind == "interrupt_result":
            _enum(event["result"], ("confirmed", "rejected", "unknown"), "interrupt_result")
        elif kind == "cancel":
            _enum(event["where"], ("before_submit",), "cancel_where")
        elif kind == "compatibility_failure":
            _enum(event["reason"], ("attestation_mismatch", "probe_failure", "required_surface_missing"), "compatibility_reason")
        elif kind == "unknown_event":
            if event["name"] != "unknown.interactive":
                _fail("unknown_event_name")


def _validate_expected(expected: Any) -> None:
    _keys(expected, EXPECTED_KEYS)
    trace = expected["trace"]
    if type(trace) is not list or not trace or any(item not in STATES for item in trace):
        _fail("trace")
    _enum(expected["final_state"], STATES, "final_state")
    if expected["final_state"] != trace[-1]:
        _fail("trace_final_state")
    transport_trace = expected["transport_trace"]
    if type(transport_trace) is not list or not transport_trace or any(item not in TRANSPORT_STATES for item in transport_trace):
        _fail("transport_trace")
    _enum(expected["final_transport_state"], TRANSPORT_STATES, "final_transport_state")
    if expected["final_transport_state"] != transport_trace[-1]:
        _fail("transport_trace_final_state")
    _nullable_string(expected["selected_session"], "selected_session")
    if expected["selected_session"] is not None:
        _synthetic_ref(expected["selected_session"], "selected_session")
    _enum(expected["draft_state"], ("present", "absent"), "expected_draft_state")
    for key in ("submission_count", "duplicate_attempts", "outward_changes", "idempotent_collection_retries"):
        value = _int(expected[key], key)
        if value < 0 or value > 8:
            _fail(key)
    _enum(expected["restore_barrier"], ("not_required", "pending", "passed", "inconclusive"), "restore_barrier")
    _enum(expected["prompt_retry"], ("none", "explicit_user_only", "blocked"), "prompt_retry")
    _bool(expected["automatic_retry"], "automatic_retry")
    _bool(expected["explicit_action_required"], "explicit_action_required")
    _enum(expected["server_prompt_presence"], RESTORE_PROMPT_PRESENCE, "expected_prompt_presence")
    _enum(expected["server_turn_state"], RESTORE_TURN_STATES, "expected_turn_state")
    _string(expected["decision"], "decision")
    _nullable_string(expected["contract_error"], "contract_error")


def _append_state(trace: list[str], state: str) -> None:
    if trace[-1] != state:
        trace.append(state)


def _append_transport(trace: list[str], state: str) -> None:
    if trace[-1] != state:
        trace.append(state)


def evaluate_case(case: dict[str, Any]) -> dict[str, Any]:
    initial = case["initial"]
    state = initial["chat_state"]
    transport = initial["transport_state"]
    selected_session = initial["session_ref"]
    draft_state = initial["draft_state"]
    submission_count = initial["submission_count"]
    duplicate_attempts = 0
    restore_barrier = "pending" if state == "delivery_uncertain" else "not_required"
    prompt_retry = "none"
    automatic_retry = False
    explicit_action_required = False
    # An initial uncertain/active state represents an already-recorded outward
    # submission. New changes are counted only when this trace sends one.
    outward_changes = 1 if submission_count > 0 and state in ("delivery_uncertain", "streaming", "awaiting_approval", "awaiting_clarification", "interrupting") else 0
    idempotent_collection_retries = 0
    server_prompt_presence = "present" if state in ("streaming", "awaiting_approval", "awaiting_clarification", "interrupting") else "not_observed"
    server_turn_state = "running" if server_prompt_presence == "present" else "not_observed"
    decision = "pending"
    contract_error: str | None = None
    intent: str | None = "interrupt" if state == "interrupting" else ("prompt" if state in ("submitting", "streaming", "delivery_uncertain") else None)
    pending_result: str | None = None
    resend_armed = False
    rejection_retry_armed = False
    resend_reason: str | None = None
    duplicate_blocked = False
    seen_requests: set[str] = set()
    read_failed = False
    state_trace = [state]
    transport_trace = [transport]

    def transition(next_state: str) -> None:
        nonlocal state
        state = next_state
        _append_state(state_trace, next_state)

    def change_transport(next_transport: str) -> None:
        nonlocal transport
        transport = next_transport
        _append_transport(transport_trace, next_transport)

    def contract_failure(error: str) -> None:
        nonlocal contract_error, decision, prompt_retry
        contract_error = error
        prompt_retry = "blocked"
        decision = "automatic_prompt_retry_blocked" if error == "prompt_retry_requires_restore" else decision
        transition("failed")
        change_transport("incompatible")

    for event in case["events"]:
        kind = event["kind"]
        if contract_error is not None:
            _fail("events_after_contract_error")
        if kind == "submit":
            ref = event["request_ref"]
            if ref in seen_requests:
                _fail("duplicate_request_ref")
            seen_requests.add(ref)
            allowed = state == "ready" and (selected_session is not None)
            if not allowed:
                contract_failure("prompt_submit_not_ready")
                continue
            submission_count += 1
            outward_changes += 1
            intent = "prompt"
            pending_result = event["result"]
            transition("submitting")
            if event["result"] == "rejected":
                server_prompt_presence = "absent"
                server_turn_state = "rejected"
                prompt_retry = "explicit_user_only"
                explicit_action_required = True
                rejection_retry_armed = True
                decision = "confirmed_rejection"
                transition("failed")
            elif event["result"] == "accepted":
                server_prompt_presence = "present"
            elif event["result"] == "pending":
                server_prompt_presence = "not_observed"
            elif server_prompt_presence not in ("absent", "present"):
                server_prompt_presence = "unknown"
        elif kind == "server_event":
            name = event["name"]
            if name in ("message.delta", "reasoning.delta", "thinking.delta", "tool.start", "tool.complete"):
                server_prompt_presence = "present"
                server_turn_state = "running"
                if state in ("submitting", "delivery_uncertain", "restoring"):
                    transition("streaming")
                if decision == "pending":
                    decision = "accepted_present"
            elif name == "message.complete":
                server_prompt_presence = "present"
                server_turn_state = "completed"
                draft_state = "absent"
                transition("completed")
                if resend_reason == "absent_idle":
                    decision = "resent_after_absent_idle"
                elif resend_reason == "rejection":
                    decision = "accepted_after_confirmed_rejection"
                elif duplicate_blocked:
                    decision = "duplicate_blocked"
                elif state_trace.count("delivery_uncertain") > 0:
                    decision = "accepted_present_after_restore"
                else:
                    decision = "accepted_present"
            elif name == "approval.request":
                server_prompt_presence = "present"
                server_turn_state = "running"
                transition("awaiting_approval")
            elif name == "clarify.request":
                server_prompt_presence = "present"
                server_turn_state = "running"
                transition("awaiting_clarification")
        elif kind == "transport_loss":
            change_transport("reconnecting")
            if state in ("submitting", "streaming") and intent == "prompt":
                transition("delivery_uncertain")
                restore_barrier = "pending"
                draft_state = "present"
                server_prompt_presence = "unknown" if server_prompt_presence == "not_observed" else server_prompt_presence
                server_turn_state = "unknown" if server_turn_state == "not_observed" else server_turn_state
                pending_result = "unknown"
            elif state == "interrupting":
                restore_barrier = "pending"
            elif state in ("awaiting_approval", "awaiting_clarification"):
                contract_failure("interactive_result_unknown")
        elif kind == "restore_begin":
            if state not in ("delivery_uncertain", "interrupting", "restoring"):
                contract_failure("restore_not_required")
                continue
            change_transport("ready")
            transition("restoring")
            restore_barrier = "pending"
        elif kind == "read_retry":
            if state != "restoring":
                contract_failure("read_retry_without_restore")
                continue
            automatic_retry = True
            if event["result"] == "transient_error":
                read_failed = True
            elif read_failed:
                idempotent_collection_retries += 1
                read_failed = False
        elif kind == "restore_history":
            if state != "restoring":
                contract_failure("history_without_restore")
                continue
            server_prompt_presence = event["prompt_presence"]
        elif kind == "restore_status":
            if state != "restoring":
                contract_failure("status_without_restore")
                continue
            server_turn_state = event["turn_state"]
            if server_prompt_presence == "unknown" or server_turn_state == "unknown":
                restore_barrier = "inconclusive"
                transition("delivery_uncertain" if intent == "prompt" else "interrupting")
                decision = "restore_inconclusive"
            elif intent == "prompt" and server_prompt_presence == "present" and server_turn_state in ("running", "streaming"):
                restore_barrier = "passed"
                transition("streaming")
                decision = "accepted_present_after_restore"
            elif intent == "prompt" and server_prompt_presence == "present" and server_turn_state == "completed":
                restore_barrier = "passed"
                draft_state = "absent"
                transition("completed")
                decision = "accepted_present_after_restore"
            elif intent == "prompt" and server_prompt_presence == "absent" and server_turn_state == "idle":
                restore_barrier = "passed"
                transition("ready")
                prompt_retry = "explicit_user_only"
                explicit_action_required = True
                resend_armed = True
                decision = "absent_idle_wait_user"
            elif intent == "interrupt" and server_turn_state in ("running", "streaming"):
                restore_barrier = "passed"
                transition("streaming")
                decision = "interrupt_unknown_after_restore"
            elif intent == "interrupt" and server_turn_state in ("completed", "idle"):
                restore_barrier = "passed"
                transition("completed")
                decision = "interrupt_confirmed_after_restore"
            else:
                contract_failure("restore_evidence_mismatch")
        elif kind == "user_decision":
            action = event["action"]
            if action == "resend" and resend_armed:
                resend_armed = False
                resend_reason = "absent_idle"
                explicit_action_required = True
                transition("ready")
            elif action == "retry_after_rejection" and rejection_retry_armed:
                rejection_retry_armed = False
                resend_reason = "rejection"
                explicit_action_required = True
                transition("ready")
            elif action == "keep_draft" and resend_armed:
                resend_armed = False
                explicit_action_required = True
                decision = "user_kept_draft"
                transition("ready")
            else:
                contract_failure("user_decision_not_allowed")
        elif kind == "duplicate_submit":
            if state not in ("submitting", "streaming"):
                contract_failure("duplicate_submit_not_allowed")
                continue
            duplicate_attempts += 1
            duplicate_blocked = True
            decision = "duplicate_blocked"
        elif kind == "automatic_retry":
            method = event["method"]
            if method == "prompt.submit":
                explicit_action_required = False
                contract_failure("prompt_retry_requires_restore")
                continue
            if method not in AUTOMATIC_RETRY_METHODS:
                contract_failure("retry_method_not_idempotent")
                continue
            if state != "restoring":
                contract_failure("read_retry_without_restore")
                continue
            automatic_retry = True
        elif kind == "interrupt_request":
            if state != "streaming":
                contract_failure("interrupt_not_active")
                continue
            intent = "interrupt"
            outward_changes += 1
            transition("interrupting")
        elif kind == "interrupt_result":
            if state != "interrupting":
                contract_failure("interrupt_result_not_pending")
                continue
            if event["result"] == "confirmed":
                server_prompt_presence = "present"
                server_turn_state = "completed"
                transition("completed")
                decision = "interrupt_confirmed"
            elif event["result"] == "rejected":
                transition("failed")
                decision = "interrupt_rejected"
            else:
                decision = "interrupt_unknown"
        elif kind == "cancel":
            if event["where"] != "before_submit" or state != "ready" or submission_count != 0:
                contract_failure("cancel_not_safe")
                continue
            decision = "cancelled_before_submit"
        elif kind == "sign_out":
            selected_session = None
            change_transport("offline")
            transition("empty")
            decision = "signed_out_safe"
        elif kind == "compatibility_failure":
            contract_error = "compatibility_evidence_required"
            prompt_retry = "blocked"
            decision = "incompatible_evidence"
            transition("failed")
            change_transport("incompatible")
        elif kind == "unknown_event":
            contract_error = "unsupported_interactive_event"
            prompt_retry = "blocked"
            decision = "unknown_interactive_event_blocked"
            transition("failed")
            change_transport("incompatible")
        elif kind == "evidence_pending":
            if state != "restoring":
                contract_failure("evidence_not_pending")
                continue
            decision = "evidence_pending"
            transition("restoring")

    if decision == "pending":
        if state == "empty":
            decision = "empty_noop"
        elif state == "submitting":
            decision = "submission_pending"
        elif state == "delivery_uncertain":
            decision = "delivery_uncertain"
    if intent == "prompt" and state == "delivery_uncertain" and restore_barrier == "not_required":
        restore_barrier = "pending"
    if state == "delivery_uncertain" and prompt_retry == "none" and contract_error is None and decision != "restore_inconclusive":
        prompt_retry = "none"

    return {
        "trace": state_trace,
        "final_state": state,
        "transport_trace": transport_trace,
        "final_transport_state": transport,
        "selected_session": selected_session,
        "draft_state": draft_state,
        "submission_count": submission_count,
        "duplicate_attempts": duplicate_attempts,
        "restore_barrier": restore_barrier,
        "prompt_retry": prompt_retry,
        "automatic_retry": automatic_retry,
        "explicit_action_required": explicit_action_required,
        "outward_changes": outward_changes,
        "idempotent_collection_retries": idempotent_collection_retries,
        "server_prompt_presence": server_prompt_presence,
        "server_turn_state": server_turn_state,
        "decision": decision,
        "contract_error": contract_error,
    }


def validate_baseline(baseline: dict[str, Any], *, fixture_dir: Path | None = None) -> int:
    expected_keys = ("schema", "operation", "contract", "hermes_source_sha", "synthetic_only", "metric", "deterministic_fixture", "environment", "threshold", "artifacts", "artifact_manifest_sha256", "normal", "optimized")
    _keys(baseline, expected_keys)
    if baseline["schema"] != BASELINE_SCHEMA or baseline["operation"] != OPERATION or baseline["contract"] != CONTRACT:
        _fail("baseline_identity")
    if baseline["hermes_source_sha"] != HERMES_SOURCE_SHA or _bool(baseline["synthetic_only"], "baseline_synthetic_only") is not True:
        _fail("baseline_identity")
    if baseline["metric"] != "validator_process_duration_ms" or baseline["deterministic_fixture"] != "cases.json":
        _fail("baseline_metric")
    environment = baseline["environment"]
    if not isinstance(environment, dict) or tuple(environment.keys()) != tuple(EXPECTED_ENVIRONMENT.keys()):
        _fail("baseline_environment")
    for key, expected in EXPECTED_ENVIRONMENT.items():
        if environment[key] != expected:
            _fail("baseline_environment")
    if baseline["threshold"] is not None:
        _fail("baseline_threshold")
    artifacts = baseline["artifacts"]
    if not isinstance(artifacts, dict) or tuple(artifacts.keys()) != CANONICAL_ARTIFACT_NAMES:
        _fail("baseline_artifacts")
    for name in CANONICAL_ARTIFACT_NAMES:
        entry = artifacts[name]
        if not isinstance(entry, dict) or tuple(entry.keys()) != ("bytes", "sha256"):
            _fail("baseline_artifact_entry")
        if type(entry["bytes"]) is not int or entry["bytes"] <= 0 or not HEX64.fullmatch(str(entry["sha256"])):
            _fail("baseline_artifact_entry")
    if baseline["artifact_manifest_sha256"] != CANONICAL_ARTIFACT_MANIFEST_SHA256:
        _fail("baseline_artifact_manifest")
    directory = fixture_dir or ROOT
    actual_artifacts, actual_manifest = _artifact_manifest(directory)
    if actual_artifacts != artifacts or actual_manifest != baseline["artifact_manifest_sha256"]:
        _fail("baseline_artifacts")
    total_samples = 0
    for mode in ("normal", "optimized"):
        record = baseline[mode]
        if not isinstance(record, dict) or tuple(record.keys()) != ("command", "repetitions", "samples_ms", "distribution"):
            _fail("baseline_mode")
        if record["command"] != APPROVED_COMMANDS[mode] or record["repetitions"] != BENCHMARK_REPETITIONS:
            _fail("baseline_command")
        samples = record["samples_ms"]
        if type(samples) is not list or len(samples) != BENCHMARK_REPETITIONS:
            _fail("baseline_samples")
        if any(type(sample) is not float or not math.isfinite(sample) or sample <= 0 for sample in samples):
            _fail("baseline_samples")
        if record["distribution"] != _distribution(samples):
            _fail("baseline_distribution")
        sample_digest = _sha256_bytes(_canonical_json(samples))
        distribution_digest = _sha256_bytes(_canonical_json(record["distribution"]))
        identity = CANONICAL_BENCHMARK_IDENTITY[mode]
        if sample_digest != identity["samples_sha256"] or distribution_digest != identity["distribution_sha256"]:
            _fail("baseline_identity")
        total_samples += len(samples)
    return total_samples


def validate_canonical_identity(document: dict[str, Any], baseline: dict[str, Any], *, fixture_dir: Path | None = None) -> None:
    directory = fixture_dir or ROOT
    try:
        cases_bytes = (directory / "cases.json").read_bytes()
    except (OSError, ValueError):
        _fail("cases_unavailable")
    if _sha256_bytes(cases_bytes) != CANONICAL_CASES_SHA256:
        _fail("cases_identity")
    if _normalized_source_digest(directory / "validate.py") != CANONICAL_SOURCE_SHA256:
        _fail("source_identity")
    validate_baseline(baseline, fixture_dir=directory)
    if directory == ROOT and document is not None:
        artifacts, manifest = _artifact_manifest(directory)
        if manifest != CANONICAL_ARTIFACT_MANIFEST_SHA256:
            _fail("artifact_identity")
        if baseline["artifacts"] != artifacts:
            _fail("artifact_identity")


def validate_all(document: dict[str, Any], baseline: dict[str, Any], *, fixture_dir: Path | None = None) -> int:
    validate_document(document)
    validate_canonical_identity(document, baseline, fixture_dir=fixture_dir)
    return len(document["cases"])


class _SilentArgumentParser(argparse.ArgumentParser):
    """Keep invalid CLI input on the fixed, bounded diagnostic path."""

    def error(self, message: str) -> None:
        _fail("invalid_arguments")


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = _SilentArgumentParser(add_help=False)
    parser.add_argument("--cases", default=str(CASES_PATH))
    parser.add_argument("--baseline", default=str(BASELINE_PATH))
    parser.add_argument("--help", action="store_true")
    try:
        return parser.parse_args(argv)
    except SystemExit:
        _fail("invalid_arguments")
    raise ContractError("invalid_arguments")


def _error_line(code: str) -> str:
    # Keep errors stable and caller-independent.  Never include a path, flag,
    # parser detail, duplicate key, or untrusted semantic marker.
    return json.dumps({"error": {"code": "contract", "message": "uncertain delivery fixture rejected"}}, separators=(",", ":"))[:MAX_ERROR_LENGTH]


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parse_args(list(sys.argv[1:] if argv is None else argv))
        if args.help:
            return 0
        cases_path = Path(args.cases)
        baseline_path = Path(args.baseline)
        document = load_json(cases_path, "cases")
        baseline = load_json(baseline_path, "baseline")
        directory = cases_path.parent
        count = validate_all(document, baseline, fixture_dir=directory)
        print(f"uncertain_delivery_validation=ok cases={count} benchmark_samples={BENCHMARK_REPETITIONS * 2}")
        return 0
    except ContractError as exc:
        sys.stderr.write(_error_line(exc.code) + "\n")
        return 1
    except (OSError, ValueError, TypeError, RecursionError):
        sys.stderr.write(_error_line("contract_rejected") + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
