#!/usr/bin/env python3
"""Validate the synthetic C-07 session-persistence contract offline.

The reducer mirrors only the reviewed Hermes session boundary. It never imports
Hermes, opens a socket, reads a real state database, contacts a provider, or
stores a transcript. The checked-in JSON is executable evidence for creation,
first-turn persistence, reopen/resume, interruption, duplicate suppression,
and fail-closed recovery.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import re
import statistics
import sys
from typing import Any


ROOT = Path(__file__).resolve().parent
CASES_PATH = ROOT / "cases.json"
BASELINE_PATH = ROOT / "validation-baseline.json"
SCHEMA = "hermternal.session-persistence.v1"
BASELINE_SCHEMA = "hermternal.session-persistence-baseline.v1"
OPERATION = "C-07"
CONTRACT = "dashboard-v0.0.1"
HERMES_SOURCE_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
SURFACE = "shared-web-apple"

STATES = (
    "empty",
    "pending_create",
    "pending_persist",
    "ready",
    "restoring",
    "interrupted",
    "delivery_uncertain",
    "failed",
    "closed",
    "incompatible",
)

SESSION_MARKER = "session-marker-001"
STORED_SESSION_MARKER = "stored-session-marker-001"
FOREIGN_SESSION_MARKER = "foreign-session-marker-009"

MAX_JSON_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 4096
MAX_OBJECT_KEYS = 64
MAX_ARRAY_LENGTH = 256
MAX_STRING_LENGTH = 16 * 1024
MAX_INTEGER_DIGITS = 4096
BASELINE_REPETITIONS = 30
APPROVED_BASELINE_COMMAND = "python3 contracts/fixtures/session-persistence/validate.py"
APPROVED_BENCHMARK_COMMANDS = {
    "normal": APPROVED_BASELINE_COMMAND,
    "optimized": "python3 -O contracts/fixtures/session-persistence/validate.py",
}
# This is evidence for the checked-in benchmark only. It is not a portability
# claim or a product performance budget.
REVIEWED_BASELINE_PLATFORM = "macOS-26.5.2-arm64-arm-64bit-Mach-O"
REVIEWED_BASELINE_PYTHON = "3.14.6"
# The digest covers immutable benchmark identity, commands, and null threshold;
# it deliberately excludes mutable timing samples and artifact hashes.
BASELINE_CANONICAL_IDENTITY_SHA256 = "271f5efb69a77e484e554a61450973249bdd8a7bc3a1974261f06c630202ef6b"

ROOT_KEYS = (
    "schema",
    "operation",
    "contract",
    "hermes_source_sha",
    "synthetic_only",
    "surface",
    "source_observations",
    "states",
    "invariants",
    "cases",
    "redaction",
)
SOURCE_KEYS = ("id", "path", "anchor", "observation", "contract_relevance")
STATE_KEYS = ("id", "meaning", "allowed_actions", "terminal")
CASE_KEYS = ("id", "initial_state", "initial_context", "events", "expected", "notes")
CONTEXT_KEYS = (
    "selected_session",
    "stored_session",
    "durable_row",
    "draft",
    "prompt_in_flight",
    "transport",
    "persistence",
    "session_creations",
    "prompt_submissions",
    "persist_attempts",
    "resume_attempts",
    "history",
    "server_presence",
    "error_kind",
)
EXPECTED_KEYS = (
    "decision",
    "final_state",
    "trace",
    "effects",
    "selected_session",
    "stored_session",
    "durable_row",
    "draft",
    "prompt_in_flight",
    "history",
    "session_creations",
    "prompt_submissions",
    "persist_attempts",
    "resume_attempts",
    "restore_barrier",
    "prompt_retry",
    "transport_closed",
    "automatic_prompt_retry_attempted",
    "server_presence",
    "error_kind",
)
INVARIANT_KEYS = (
    "creation",
    "persistence",
    "resume",
    "empty",
    "interruption",
    "duplicates",
    "fail_closed",
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

EXPECTED_STATES = [
    {
        "id": "empty",
        "meaning": "An ephemeral session exists, but no durable row has been created.",
        "allowed_actions": ["edit_draft", "submit_prompt", "create_new"],
        "terminal": False,
    },
    {
        "id": "pending_create",
        "meaning": "session.create is pending and no durable session exists yet.",
        "allowed_actions": ["wait", "cancel"],
        "terminal": False,
    },
    {
        "id": "pending_persist",
        "meaning": "The first prompt is accepted locally while the session row write is pending.",
        "allowed_actions": ["wait", "interrupt", "cancel"],
        "terminal": False,
    },
    {
        "id": "ready",
        "meaning": "A durable server session is available for the next user action.",
        "allowed_actions": ["submit_prompt", "interrupt", "resume", "close"],
        "terminal": False,
    },
    {
        "id": "restoring",
        "meaning": "The client is reopening the stored session and reading server-owned history.",
        "allowed_actions": ["wait", "cancel"],
        "terminal": False,
    },
    {
        "id": "interrupted",
        "meaning": "A turn was stopped or safely cancelled without an automatic resend.",
        "allowed_actions": ["resume", "submit_prompt", "close"],
        "terminal": False,
    },
    {
        "id": "delivery_uncertain",
        "meaning": "A prompt outcome is unknown and the source state must be restored first.",
        "allowed_actions": ["resume", "cancel", "sign_out"],
        "terminal": False,
    },
    {
        "id": "failed",
        "meaning": "A known creation, persistence, or resume operation failed.",
        "allowed_actions": ["explicit_retry", "sign_out"],
        "terminal": False,
    },
    {
        "id": "closed",
        "meaning": "The live session is detached or closed while its durable row remains addressable.",
        "allowed_actions": ["resume", "create_new"],
        "terminal": False,
    },
    {
        "id": "incompatible",
        "meaning": "Evidence or an event is malformed, unknown, foreign, or unsafe to interpret.",
        "allowed_actions": ["stop", "sign_out"],
        "terminal": True,
    },
]

EXPECTED_SOURCE_OBSERVATIONS = [
    {
        "id": "create-lazy-row",
        "path": "tui_gateway/methods_session.py",
        "anchor": '@method("session.create")',
        "observation": "session.create returns an ephemeral live id and stored session key without eagerly inserting a database row.",
        "contract_relevance": "An abandoned empty draft must not become a durable session.",
    },
    {
        "id": "first-prompt-row",
        "path": "tui_gateway/methods_prompt.py",
        "anchor": "_ensure_session_db_row(session)",
        "observation": "prompt.submit persists the session row before deferred agent work starts; a storage error clears the running turn and returns an error.",
        "contract_relevance": "Persistence failure cannot be reported as accepted prompt success.",
    },
    {
        "id": "idempotent-row-upsert",
        "path": "hermes_state.py",
        "anchor": "def create_session(self, session_id: str, source: str, **kwargs)",
        "observation": "SessionDB create_session delegates to an idempotent row insert keyed by the stored session id.",
        "contract_relevance": "Retries of the same creation do not create a second durable session.",
    },
    {
        "id": "reopen-clears-ended",
        "path": "hermes_state.py",
        "anchor": "def reopen_session(self, session_id: str)",
        "observation": "reopen_session clears ended markers before a session resume reads server-owned history.",
        "contract_relevance": "Reopen resumes the same session identity rather than creating a replacement.",
    },
    {
        "id": "resume-history",
        "path": "tui_gateway/methods_session.py",
        "anchor": '@method("session.resume")',
        "observation": "session.resume reopens the stored row and loads the durable conversation projection; a missing id returns an error.",
        "contract_relevance": "Resume must fail closed on a missing session and must not fall back to a new one.",
    },
    {
        "id": "interrupt-safe",
        "path": "tui_gateway/methods_session.py",
        "anchor": '@method("session.interrupt")',
        "observation": "session.interrupt clears queued prompts, requests a hard interrupt for an active turn, and returns an interrupted status.",
        "contract_relevance": "Interruption preserves safe state and does not duplicate queued input.",
    },
    {
        "id": "detach-reconnect",
        "path": "tui_gateway/ws.py",
        "anchor": "_close_sessions_for_transport",
        "observation": "A WebSocket loss detaches ordinary sessions for a bounded reconnect window; resume can rebind the same live session.",
        "contract_relevance": "Transport loss is not proof of session loss or prompt rejection.",
    },
    {
        "id": "unknown-boundary",
        "path": "tui_gateway/ws.py",
        "anchor": "server.dispatch",
        "observation": "Dispatch and parse failures are explicit transport errors rather than successful method results.",
        "contract_relevance": "Malformed or incompatible session evidence must stop instead of invoking an unreviewed fallback.",
    },
]

EXPECTED_INVARIANTS = {
    "creation": {
        "method": "session.create",
        "live_identity": "ephemeral_session_id",
        "durable_identity": "stored_session_id",
        "empty_row": "not_created_until_first_prompt",
        "retry": "same_draft_no_duplicate",
    },
    "persistence": {
        "trigger": "prompt.submit",
        "ordering": "row_write_before_agent_build",
        "row_write": "idempotent_upsert",
        "known_failure": "preserve_draft_clear_running_return_error",
        "transcript_failure": "abort_turn",
    },
    "resume": {
        "method": "session.resume",
        "source_of_truth": "server_owned_history",
        "reopen": "clear_ended_markers",
        "missing": "failed_without_new_session",
        "duplicate": "reuse_or_deduplicate_same_stored_session",
    },
    "empty": {
        "create_without_prompt": "empty_ephemeral_only",
        "durable_row": "false",
        "automatic_new_session": "blocked",
    },
    "interruption": {
        "method": "session.interrupt",
        "queued_input": "cleared",
        "confirmed": "interrupted_without_resend",
        "unknown_result": "delivery_uncertain_restore_first",
    },
    "duplicates": {
        "create_retry": "same_durable_key",
        "prompt_while_pending": "blocked",
        "resume_while_restoring": "deduplicated",
        "automatic_prompt_retry": "blocked",
    },
    "fail_closed": {
        "unknown_event": "incompatible",
        "malformed_result": "incompatible",
        "foreign_session": "incompatible",
        "fallback": "no_new_session",
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
    "diagnostic_policy": "stable semantic errors only; retain no raw input, paths, or live values",
}


class ContractError(ValueError):
    """A bounded, redacted contract validation failure."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _strict_keys(value: Any, expected: tuple[str, ...], label: str) -> dict[str, Any]:
    _require(type(value) is dict, f"{label} must be an object")
    actual = tuple(value.keys())
    _require(actual == expected, f"{label} keys changed")
    return value


def _strict_string(value: Any, label: str) -> str:
    _require(type(value) is str, f"{label} must be text")
    _require(len(value) <= MAX_STRING_LENGTH, f"{label} is too long")
    return value


def _strict_bool(value: Any, label: str) -> bool:
    _require(type(value) is bool, f"{label} must be boolean")
    return value


def _strict_int(value: Any, label: str) -> int:
    _require(type(value) is int and type(value) is not bool, f"{label} must be integer")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate JSON key")
        result[key] = value
    return result


def _bounded_int(raw: str) -> int:
    if len(raw.lstrip("-+")) > MAX_INTEGER_DIGITS:
        raise ContractError("integer is too large")
    return int(raw)


def _bounded_float(raw: str) -> float:
    value = float(raw)
    if not math.isfinite(value):
        raise ContractError("non-finite number")
    return value


def _reject_constant(raw: str) -> Any:
    raise ContractError(f"unsupported JSON constant: {raw}")


def _check_bounds(value: Any, *, depth: int = 0, nodes: list[int] | None = None) -> None:
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    _require(nodes[0] <= MAX_JSON_NODES, "JSON node limit exceeded")
    _require(depth <= MAX_JSON_DEPTH, "JSON depth limit exceeded")
    if type(value) is str:
        _require(len(value) <= MAX_STRING_LENGTH, "JSON string limit exceeded")
    elif type(value) is list:
        _require(len(value) <= MAX_ARRAY_LENGTH, "JSON array limit exceeded")
        for item in value:
            _check_bounds(item, depth=depth + 1, nodes=nodes)
    elif type(value) is dict:
        _require(len(value) <= MAX_OBJECT_KEYS, "JSON object key limit exceeded")
        for key, item in value.items():
            _require(type(key) is str, "JSON object key must be text")
            _check_bounds(item, depth=depth + 1, nodes=nodes)


def _load_json(path: Path, label: str) -> Any:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ContractError(f"{label} unavailable") from exc
    _require(len(data) <= MAX_JSON_BYTES, f"{label} exceeds size limit")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError(f"{label} is not UTF-8") from exc
    try:
        value = json.loads(
            text,
            parse_int=_bounded_int,
            parse_float=_bounded_float,
            parse_constant=_reject_constant,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError) as exc:
        if isinstance(exc, ContractError):
            raise
        raise ContractError(f"{label} is not valid JSON") from exc
    _check_bounds(value)
    return value


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _baseline_identity_digest(baseline: dict[str, Any]) -> str:
    identity = {
        "schema": baseline["schema"],
        "validator": baseline["validator"],
        "command": baseline["command"],
        "build_mode": baseline["build_mode"],
        "environment": baseline["environment"],
        "repetitions": baseline["repetitions"],
        "normal_command": baseline["normal"]["command"],
        "optimized_command": baseline["optimized"]["command"],
        "threshold": baseline["threshold"],
    }
    return hashlib.sha256(_canonical_json_bytes(identity)).hexdigest()


def _semantic_string_is_safe(value: str) -> bool:
    lowered = value.lower()
    if "\x00" in value:
        return False
    if re.search(r"\b(?:https?|wss?)://", lowered):
        return False
    if re.search(r"\b(?:host|hostname)\s*[:=]", lowered):
        return False
    if re.search(r"\b(?:localhost|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:example|invalid))(?:\:\d+)?\b", lowered):
        return False
    if re.search(r"\b(?:bearer|basic)\s+[a-z0-9._~+/=-]{8,}", lowered):
        return False
    if re.search(r"(?:password|passwd|secret|cookie|ticket|token|authorization)\s*[=:]", lowered):
        return False
    if re.fullmatch(r"ey[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}", lowered):
        return False
    if re.search(r"(?:^|[\s=])/(?:users|private|tmp|var|home|etc)(?:/|$)", lowered):
        return False
    return True


def _validate_redaction(value: Any, label: str = "document") -> None:
    sensitive_keys = {
        "password",
        "passwords",
        "credential",
        "credentials",
        "cookie",
        "cookies",
        "ticket",
        "tickets",
        "token",
        "tokens",
        "secret",
        "secrets",
        "authorization",
        "bearer",
        "refresh_token",
        "api_key",
        "prompt_text",
        "transcript_text",
        "hostname",
        "user_data",
    }
    if type(value) is dict:
        for key, item in value.items():
            normalized = re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")
            _require(normalized not in sensitive_keys, f"{label} contains a sensitive key")
            _validate_redaction(item, f"{label}.{key}")
    elif type(value) is list:
        for index, item in enumerate(value):
            _validate_redaction(item, f"{label}[{index}]")
    elif type(value) is str:
        _require(_semantic_string_is_safe(value), f"{label} contains a sensitive value")


def _context(**overrides: Any) -> dict[str, Any]:
    value = {
        "selected_session": None,
        "stored_session": None,
        "durable_row": False,
        "draft": "empty",
        "prompt_in_flight": False,
        "transport": "connected",
        "persistence": "not_started",
        "session_creations": 0,
        "prompt_submissions": 0,
        "persist_attempts": 0,
        "resume_attempts": 0,
        "history": "none",
        "server_presence": "unknown",
        "error_kind": None,
    }
    value.update(overrides)
    return value


def _durable_context(**overrides: Any) -> dict[str, Any]:
    value = _context(
        selected_session=SESSION_MARKER,
        stored_session=STORED_SESSION_MARKER,
        durable_row=True,
        persistence="available",
        history="present",
        server_presence="present",
        session_creations=1,
    )
    value.update(overrides)
    return value


def _closed_context(**overrides: Any) -> dict[str, Any]:
    value = _durable_context(selected_session=None, transport="detached")
    value.update(overrides)
    return value


def _uncertain_context(**overrides: Any) -> dict[str, Any]:
    value = _durable_context(
        transport="detached",
        draft="present",
        prompt_in_flight=True,
        history="unknown",
        server_presence="unknown",
    )
    value.update(overrides)
    return value


def _set_state(runtime: dict[str, Any], state: str) -> None:
    runtime["state"] = state
    if runtime["trace"][-1] != state:
        runtime["trace"].append(state)


def _effect(runtime: dict[str, Any], value: str) -> None:
    if value not in runtime["effects"]:
        runtime["effects"].append(value)


def _incompatible(runtime: dict[str, Any], effect: str) -> None:
    _set_state(runtime, "incompatible")
    runtime["transport_closed"] = True
    runtime["error_kind"] = "incompatible"
    runtime["decision"] = "blocked_incompatible"
    _effect(runtime, effect)
    _effect(runtime, "no_new_session_fallback")


def _transition(runtime: dict[str, Any], event: str) -> None:
    state = runtime["state"]

    if event == "session.create.request":
        if state == "empty" and runtime["selected_session"] is None:
            runtime["session_creations"] += 1
            _set_state(runtime, "pending_create")
            runtime["decision"] = "create_pending"
            _effect(runtime, "create_requested")
        elif state == "pending_create":
            _effect(runtime, "duplicate_create_request_blocked")
        else:
            _incompatible(runtime, "create_in_wrong_state")
        return

    if event == "session.create.accepted":
        if state == "pending_create":
            runtime["selected_session"] = SESSION_MARKER
            runtime["stored_session"] = STORED_SESSION_MARKER
            runtime["server_presence"] = "present"
            runtime["persistence"] = "not_started"
            runtime["decision"] = "create_empty"
            _set_state(runtime, "empty")
            _effect(runtime, "ephemeral_session_created")
            _effect(runtime, "durable_row_deferred_until_prompt")
        elif state == "empty" and runtime["selected_session"] == SESSION_MARKER:
            _effect(runtime, "duplicate_create_ack_ignored")
        else:
            _incompatible(runtime, "create_ack_in_wrong_state")
        return

    if event == "session.create.retry":
        if state == "empty" and runtime["selected_session"] == SESSION_MARKER:
            runtime["decision"] = "duplicate_create_suppressed"
            _effect(runtime, "same_empty_session_reused")
            _effect(runtime, "no_second_durable_row")
        else:
            _incompatible(runtime, "create_retry_without_same_draft")
        return

    if event == "session.create.failed":
        if state == "pending_create":
            runtime["error_kind"] = "create_failed"
            runtime["decision"] = "creation_failed"
            _set_state(runtime, "failed")
            _effect(runtime, "creation_failed")
            _effect(runtime, "no_new_session_fallback")
        else:
            _incompatible(runtime, "create_failure_in_wrong_state")
        return

    if event == "prompt.submit.request":
        if state in {"empty", "interrupted"} and not runtime["prompt_in_flight"]:
            runtime["draft"] = "present"
            runtime["prompt_in_flight"] = True
            runtime["prompt_submissions"] += 1
            runtime["persist_attempts"] += 1
            runtime["persistence"] = "pending" if not runtime["durable_row"] else "available"
            runtime["decision"] = "prompt_pending"
            _effect(runtime, "prompt_delivery_started")
            if not runtime["durable_row"]:
                _set_state(runtime, "pending_persist")
            else:
                _effect(runtime, "existing_row_reused")
        elif state == "pending_persist" or runtime["prompt_in_flight"]:
            runtime["decision"] = "duplicate_prompt_blocked"
            _effect(runtime, "duplicate_prompt_blocked")
        elif state == "delivery_uncertain":
            runtime["decision"] = "restore_required_before_prompt"
            _effect(runtime, "prompt_blocked_until_restore")
        else:
            _incompatible(runtime, "prompt_submit_in_wrong_state")
        return

    if event == "prompt.submit.duplicate":
        if state in {"pending_persist", "ready", "delivery_uncertain"}:
            runtime["decision"] = "duplicate_prompt_blocked"
            _effect(runtime, "duplicate_prompt_blocked")
            if state == "delivery_uncertain":
                _effect(runtime, "restore_required_before_duplicate_decision")
        else:
            _incompatible(runtime, "duplicate_prompt_without_active_delivery")
        return

    if event in {"session.persist.ok", "session.persist.duplicate"}:
        if state == "pending_persist":
            runtime["durable_row"] = True
            runtime["persistence"] = "available"
            runtime["server_presence"] = "present"
            runtime["history"] = "present"
            runtime["prompt_in_flight"] = False
            runtime["decision"] = (
                "existing_row_reused" if event.endswith("duplicate") else "session_persisted"
            )
            _set_state(runtime, "ready")
            _effect(
                runtime,
                "duplicate_row_suppressed" if event.endswith("duplicate") else "session_row_persisted",
            )
            _effect(runtime, "prompt_not_automatically_repeated")
        elif state == "ready":
            runtime["decision"] = "duplicate_persist_ack_ignored"
            _effect(runtime, "duplicate_persist_ack_ignored")
        else:
            _incompatible(runtime, "persist_ack_in_wrong_state")
        return

    if event == "session.persist.failed":
        if state == "pending_persist":
            runtime["persistence"] = "failed"
            runtime["prompt_in_flight"] = False
            runtime["error_kind"] = "storage"
            runtime["decision"] = "persistence_failed"
            _set_state(runtime, "failed")
            _effect(runtime, "session_row_write_failed")
            _effect(runtime, "draft_preserved")
            _effect(runtime, "automatic_prompt_retry_blocked")
        else:
            _incompatible(runtime, "persist_failure_in_wrong_state")
        return

    if event == "session.persist.malformed":
        if state == "pending_persist":
            _incompatible(runtime, "malformed_persistence_result")
        else:
            _incompatible(runtime, "malformed_persistence_in_wrong_state")
        return

    if event == "session.persist.retry":
        if state == "failed" and runtime["error_kind"] == "storage":
            runtime["persist_attempts"] += 1
            runtime["persistence"] = "pending"
            runtime["prompt_in_flight"] = True
            runtime["decision"] = "explicit_idempotent_persist_retry"
            _set_state(runtime, "pending_persist")
            _effect(runtime, "explicit_retry_only")
        else:
            _incompatible(runtime, "persistence_retry_without_known_storage_failure")
        return

    if event == "turn.completed":
        if state == "ready" and runtime["durable_row"]:
            runtime["draft"] = "empty"
            runtime["history"] = "present"
            runtime["prompt_in_flight"] = False
            runtime["decision"] = "turn_persisted"
            _effect(runtime, "turn_persisted_once")
        else:
            _incompatible(runtime, "turn_completion_without_durable_session")
        return

    if event == "session.interrupt.request":
        if state in {"pending_persist", "ready"} and runtime["prompt_in_flight"]:
            runtime["prompt_in_flight"] = False
            runtime["decision"] = "interrupt_pending"
            _set_state(runtime, "interrupted")
            _effect(runtime, "interrupt_requested")
            _effect(runtime, "queued_prompt_cleared")
        elif state in {"ready", "interrupted"}:
            runtime["decision"] = "interrupt_no_active_turn"
            _effect(runtime, "no_active_turn_to_interrupt")
        else:
            _incompatible(runtime, "interrupt_in_wrong_state")
        return

    if event == "session.interrupt.ack":
        if state == "interrupted":
            runtime["decision"] = "interrupted"
            _effect(runtime, "interrupt_confirmed")
            _effect(runtime, "prompt_not_automatically_repeated")
        else:
            _incompatible(runtime, "interrupt_ack_in_wrong_state")
        return

    if event == "session.interrupt.unknown":
        if state in {"pending_persist", "ready", "interrupted"}:
            runtime["prompt_in_flight"] = False
            runtime["draft"] = "present"
            runtime["transport_closed"] = True
            runtime["restore_barrier"] = "pending"
            runtime["prompt_retry"] = "restore_before_user_decision"
            runtime["server_presence"] = "unknown"
            runtime["decision"] = "interrupt_outcome_unknown"
            _set_state(runtime, "delivery_uncertain")
            _effect(runtime, "delivery_uncertain")
            _effect(runtime, "restore_before_retry")
        else:
            _incompatible(runtime, "interrupt_unknown_in_wrong_state")
        return

    if event == "transport.lost":
        if state in {"pending_persist", "ready"} and runtime["prompt_in_flight"]:
            runtime["transport_closed"] = True
            runtime["draft"] = "present"
            runtime["prompt_in_flight"] = False
            runtime["restore_barrier"] = "pending"
            runtime["prompt_retry"] = "restore_before_user_decision"
            runtime["server_presence"] = "unknown"
            runtime["decision"] = "delivery_uncertain"
            _set_state(runtime, "delivery_uncertain")
            _effect(runtime, "delivery_uncertain")
            _effect(runtime, "restore_before_retry")
        elif state in {"ready", "interrupted"}:
            runtime["transport_closed"] = True
            runtime["decision"] = "session_detached"
            _set_state(runtime, "closed")
            _effect(runtime, "server_session_detached")
        else:
            _incompatible(runtime, "transport_loss_in_wrong_state")
        return

    if event == "session.close.detach":
        if state in {"empty", "ready", "interrupted", "delivery_uncertain", "failed", "pending_persist"}:
            runtime["transport_closed"] = True
            runtime["selected_session"] = None
            runtime["decision"] = "session_detached"
            _set_state(runtime, "closed")
            _effect(runtime, "server_session_detached")
            _effect(runtime, "no_reconnect_without_user_action")
        else:
            _incompatible(runtime, "close_in_wrong_state")
        return

    if event == "session.resume.request":
        if state in {"closed", "interrupted", "delivery_uncertain"} and runtime["stored_session"]:
            runtime["resume_attempts"] += 1
            runtime["transport_closed"] = False
            runtime["restore_barrier"] = "pending"
            runtime["decision"] = "resume_pending"
            _set_state(runtime, "restoring")
            _effect(runtime, "resume_same_stored_session")
        elif state == "restoring":
            runtime["decision"] = "duplicate_resume_blocked"
            _effect(runtime, "duplicate_resume_request_blocked")
        elif not runtime["stored_session"] or not runtime["durable_row"]:
            runtime["error_kind"] = "resume_without_durable_row"
            runtime["decision"] = "resume_failed_no_durable_row"
            _set_state(runtime, "failed")
            _effect(runtime, "resume_without_durable_row")
            _effect(runtime, "no_new_session_fallback")
        else:
            _incompatible(runtime, "resume_in_wrong_state")
        return

    if event == "session.reopen.present":
        if state == "restoring":
            runtime["selected_session"] = SESSION_MARKER
            runtime["durable_row"] = True
            runtime["persistence"] = "available"
            runtime["transport"] = "connected"
            runtime["transport_closed"] = False
            runtime["history"] = "present"
            runtime["server_presence"] = "present"
            runtime["restore_barrier"] = "passed"
            runtime["prompt_in_flight"] = False
            runtime["decision"] = "resume_restored"
            _set_state(runtime, "ready")
            _effect(runtime, "server_history_reloaded")
            if runtime.get("uncertain_delivery") or runtime["prompt_retry"] == "restore_before_user_decision":
                runtime["prompt_retry"] = "user_decision_after_source_reread"
                _effect(runtime, "duplicate_prompt_suppressed")
            else:
                runtime["prompt_retry"] = "none"
        else:
            _incompatible(runtime, "reopen_result_in_wrong_state")
        return

    if event == "session.reopen.empty":
        if state == "restoring":
            runtime["selected_session"] = SESSION_MARKER
            runtime["durable_row"] = True
            runtime["persistence"] = "available"
            runtime["transport"] = "connected"
            runtime["transport_closed"] = False
            runtime["history"] = "empty"
            runtime["server_presence"] = "empty"
            runtime["restore_barrier"] = "passed"
            runtime["prompt_in_flight"] = False
            runtime["decision"] = "resume_restored_empty"
            runtime["prompt_retry"] = (
                "user_decision_after_source_reread"
                if runtime.get("uncertain_delivery") or runtime["prompt_retry"] == "restore_before_user_decision"
                else "none"
            )
            _set_state(runtime, "ready")
            _effect(runtime, "server_history_empty")
            _effect(runtime, "no_automatic_prompt_retry")
        else:
            _incompatible(runtime, "empty_reopen_result_in_wrong_state")
        return

    if event == "session.reopen.missing":
        if state == "restoring":
            runtime["selected_session"] = None
            runtime["transport_closed"] = True
            runtime["server_presence"] = "missing"
            runtime["error_kind"] = "resume_missing"
            runtime["decision"] = "resume_failed_missing"
            _set_state(runtime, "failed")
            _effect(runtime, "stored_session_not_found")
            _effect(runtime, "no_new_session_fallback")
        else:
            _incompatible(runtime, "missing_reopen_result_in_wrong_state")
        return

    if event == "session.reopen.interrupted":
        if state == "restoring":
            runtime["transport_closed"] = True
            runtime["error_kind"] = "resume_interrupted"
            runtime["decision"] = "resume_interrupted"
            _set_state(runtime, "failed")
            _effect(runtime, "resume_interrupted_safe_state")
            _effect(runtime, "no_new_session_fallback")
        else:
            _incompatible(runtime, "interrupted_reopen_result_in_wrong_state")
        return

    if event == "session.reopen.foreign":
        if state == "restoring":
            _incompatible(runtime, "foreign_session_identity")
        else:
            _incompatible(runtime, "foreign_reopen_result_in_wrong_state")
        return

    if event == "prompt.submit.auto_retry":
        runtime["automatic_prompt_retry_attempted"] = True
        runtime["decision"] = "automatic_prompt_retry_blocked"
        _set_state(runtime, "incompatible")
        runtime["transport_closed"] = True
        runtime["error_kind"] = "incompatible"
        _effect(runtime, "automatic_prompt_retry_blocked")
        _effect(runtime, "no_new_session_fallback")
        return

    if event == "prompt.submit.after_empty_restore":
        if state == "ready" and runtime["history"] == "empty":
            runtime["prompt_in_flight"] = True
            runtime["prompt_submissions"] += 1
            runtime["decision"] = "new_prompt_requires_user_action"
            _effect(runtime, "new_prompt_requires_explicit_user_action")
        else:
            _incompatible(runtime, "prompt_after_nonempty_restore")
        return

    if event == "session.resume.foreign":
        _incompatible(runtime, "foreign_session_identity")
        return

    if event == "unknown.event":
        _incompatible(runtime, "unknown_event")
        return

    _incompatible(runtime, "unsupported_event")


def _initial_runtime(initial_state: str, context: dict[str, Any]) -> dict[str, Any]:
    runtime = dict(context)
    runtime.update(
        {
            "state": initial_state,
            "trace": [initial_state],
            "effects": [],
            "decision": "pending",
            "restore_barrier": "not_required",
            "prompt_retry": "none",
            "transport_closed": context["transport"] == "detached",
            "automatic_prompt_retry_attempted": False,
            "uncertain_delivery": initial_state == "delivery_uncertain",
        }
    )
    if initial_state == "delivery_uncertain":
        runtime["restore_barrier"] = "pending"
        runtime["prompt_retry"] = "restore_before_user_decision"
    return runtime


def evaluate_case(case: dict[str, Any]) -> dict[str, Any]:
    runtime = _initial_runtime(case["initial_state"], case["initial_context"])
    for event in case["events"]:
        _transition(runtime, event)
    return {
        "decision": runtime["decision"],
        "final_state": runtime["state"],
        "trace": runtime["trace"],
        "effects": runtime["effects"],
        "selected_session": runtime["selected_session"],
        "stored_session": runtime["stored_session"],
        "durable_row": runtime["durable_row"],
        "draft": runtime["draft"],
        "prompt_in_flight": runtime["prompt_in_flight"],
        "history": runtime["history"],
        "session_creations": runtime["session_creations"],
        "prompt_submissions": runtime["prompt_submissions"],
        "persist_attempts": runtime["persist_attempts"],
        "resume_attempts": runtime["resume_attempts"],
        "restore_barrier": runtime["restore_barrier"],
        "prompt_retry": runtime["prompt_retry"],
        "transport_closed": runtime["transport_closed"],
        "automatic_prompt_retry_attempted": runtime["automatic_prompt_retry_attempted"],
        "server_presence": runtime["server_presence"],
        "error_kind": runtime["error_kind"],
    }


def _case_definitions() -> list[tuple[str, str, dict[str, Any], tuple[str, ...], str]]:
    return [
        (
            "create-request-pending",
            "empty",
            _context(),
            ("session.create.request",),
            "A pending create exposes work without claiming a durable session.",
        ),
        (
            "create-empty-draft",
            "empty",
            _context(),
            ("session.create.request", "session.create.accepted"),
            "An accepted empty draft has only an ephemeral live identity.",
        ),
        (
            "create-failure-fails-closed",
            "empty",
            _context(),
            ("session.create.request", "session.create.failed"),
            "A known create failure does not silently create a replacement session.",
        ),
        (
            "create-retry-reuses-empty-draft",
            "empty",
            _context(),
            ("session.create.request", "session.create.accepted", "session.create.retry"),
            "A repeated create result reuses the same empty draft and stored key.",
        ),
        (
            "first-prompt-persists-session",
            "empty",
            _context(),
            ("session.create.request", "session.create.accepted", "prompt.submit.request", "session.persist.ok"),
            "The first prompt creates the durable row before agent work is reported ready.",
        ),
        (
            "persistence-failure-preserves-draft",
            "empty",
            _context(),
            ("session.create.request", "session.create.accepted", "prompt.submit.request", "session.persist.failed"),
            "A storage failure leaves the draft safe and reports failure instead of success.",
        ),
        (
            "persistence-retry-is-explicit",
            "empty",
            _context(),
            (
                "session.create.request",
                "session.create.accepted",
                "prompt.submit.request",
                "session.persist.failed",
                "session.persist.retry",
                "session.persist.ok",
            ),
            "Only an explicit idempotent persistence retry can recover a known storage failure.",
        ),
        (
            "duplicate-prompt-while-persisting",
            "empty",
            _context(),
            (
                "session.create.request",
                "session.create.accepted",
                "prompt.submit.request",
                "prompt.submit.duplicate",
            ),
            "A second prompt is blocked while the first session write is pending.",
        ),
        (
            "duplicate-persist-ack-is-ignored",
            "ready",
            _durable_context(prompt_in_flight=False),
            ("session.persist.duplicate",),
            "A stale persistence acknowledgement cannot create another row or turn.",
        ),
        (
            "resume-reopens-durable-session",
            "closed",
            _closed_context(),
            ("session.resume.request", "session.reopen.present"),
            "Resume reopens the same stored session and reloads server-owned history.",
        ),
        (
            "resume-empty-history",
            "closed",
            _closed_context(history="empty", server_presence="empty"),
            ("session.resume.request", "session.reopen.empty"),
            "An existing session with no messages returns a safe empty server projection.",
        ),
        (
            "resume-missing-fails-closed",
            "closed",
            _closed_context(),
            ("session.resume.request", "session.reopen.missing"),
            "A missing stored session fails without silently creating a new one.",
        ),
        (
            "resume-interrupted-fails-closed",
            "closed",
            _closed_context(),
            ("session.resume.request", "session.reopen.interrupted"),
            "Interrupted restore preserves a safe failure state and no replacement session.",
        ),
        (
            "duplicate-resume-request-is-deduplicated",
            "closed",
            _closed_context(),
            ("session.resume.request", "session.resume.request", "session.reopen.present"),
            "Concurrent resume requests share one restore barrier for one stored key.",
        ),
        (
            "close-detach-preserves-durable-session",
            "ready",
            _durable_context(),
            ("session.close.detach",),
            "Close detaches the live session but preserves the durable identity for resume.",
        ),
        (
            "confirmed-interruption-preserves-draft",
            "ready",
            _durable_context(draft="present", prompt_in_flight=True),
            ("session.interrupt.request", "session.interrupt.ack"),
            "A confirmed stop clears active work without automatically resending the draft.",
        ),
        (
            "unknown-interruption-requires-restore",
            "ready",
            _durable_context(draft="present", prompt_in_flight=True),
            ("session.interrupt.unknown",),
            "A lost interrupt result is delivery uncertainty, not a rejection or success.",
        ),
        (
            "transport-loss-enters-delivery-uncertain",
            "ready",
            _durable_context(draft="present", prompt_in_flight=True),
            ("transport.lost",),
            "Transport loss during delivery preserves the draft and opens a restore barrier.",
        ),
        (
            "uncertain-resume-present-suppresses-duplicate",
            "delivery_uncertain",
            _uncertain_context(),
            ("session.resume.request", "session.reopen.present"),
            "Restored server history wins and the uncertain prompt is not duplicated.",
        ),
        (
            "uncertain-resume-absent-needs-user-decision",
            "delivery_uncertain",
            _uncertain_context(),
            ("session.resume.request", "session.reopen.empty"),
            "An absent prompt remains a user decision after source state is reread.",
        ),
        (
            "uncertain-prompt-is-blocked-before-restore",
            "delivery_uncertain",
            _uncertain_context(),
            ("prompt.submit.request",),
            "A prompt cannot cross the restore barrier while delivery is uncertain.",
        ),
        (
            "automatic-prompt-retry-fails-closed",
            "delivery_uncertain",
            _uncertain_context(),
            ("prompt.submit.auto_retry",),
            "An automatic resend attempt is a compatibility failure, not a recovery path.",
        ),
        (
            "empty-restore-requires-explicit-new-prompt",
            "closed",
            _closed_context(history="empty", server_presence="empty"),
            ("session.resume.request", "session.reopen.empty", "prompt.submit.after_empty_restore"),
            "A new prompt after an empty restore is a new explicit user action.",
        ),
        (
            "foreign-resume-fails-closed",
            "closed",
            _closed_context(),
            ("session.resume.request", "session.reopen.foreign"),
            "A resume response for another session identity is rejected.",
        ),
        (
            "unknown-event-fails-closed",
            "ready",
            _durable_context(),
            ("unknown.event",),
            "Unknown session evidence never promotes into a recovery action.",
        ),
        (
            "malformed-persistence-result-fails-closed",
            "empty",
            _context(
                selected_session=SESSION_MARKER,
                stored_session=STORED_SESSION_MARKER,
                server_presence="present",
                session_creations=1,
            ),
            ("prompt.submit.request", "session.persist.malformed"),
            "Malformed storage evidence stops the operation without a fallback.",
        ),
        (
            "close-interrupted-session-does-not-reconnect",
            "interrupted",
            _durable_context(selected_session=SESSION_MARKER, transport="connected"),
            ("session.close.detach",),
            "Closing after interruption is terminal for the live transport and schedules no retry.",
        ),
    ]


def _case_definition_map() -> dict[str, tuple[str, str, dict[str, Any], tuple[str, ...], str]]:
    return {definition[0]: definition for definition in _case_definitions()}


def _validate_state_table(document: dict[str, Any]) -> None:
    _strict_equal(document["states"], EXPECTED_STATES, "states")


def _strict_equal(actual: Any, expected: Any, label: str) -> None:
    _require(actual == expected, f"{label} changed")


def _validate_source_observations(document: dict[str, Any]) -> None:
    observations = document["source_observations"]
    _require(type(observations) is list, "source_observations must be an array")
    _strict_equal(observations, EXPECTED_SOURCE_OBSERVATIONS, "source_observations")
    for index, observation in enumerate(observations):
        _strict_keys(observation, SOURCE_KEYS, f"source_observations[{index}]")
        for key in SOURCE_KEYS:
            _strict_string(observation[key], f"source_observations[{index}].{key}")


def _validate_context(context: dict[str, Any], label: str) -> None:
    _strict_keys(context, CONTEXT_KEYS, label)
    for key in ("selected_session", "stored_session", "error_kind"):
        value = context[key]
        _require(value is None or type(value) is str, f"{label}.{key} must be text or null")
    _strict_bool(context["durable_row"], f"{label}.durable_row")
    _strict_bool(context["prompt_in_flight"], f"{label}.prompt_in_flight")
    _strict_int(context["session_creations"], f"{label}.session_creations")
    _strict_int(context["prompt_submissions"], f"{label}.prompt_submissions")
    _strict_int(context["persist_attempts"], f"{label}.persist_attempts")
    _strict_int(context["resume_attempts"], f"{label}.resume_attempts")
    for key in ("session_creations", "prompt_submissions", "persist_attempts", "resume_attempts"):
        _require(context[key] >= 0, f"{label}.{key} must be non-negative")
    _require(context["draft"] in {"empty", "present"}, f"{label}.draft changed")
    _require(context["transport"] in {"connected", "detached"}, f"{label}.transport changed")
    _require(context["persistence"] in {"not_started", "pending", "available", "failed"}, f"{label}.persistence changed")
    _require(context["history"] in {"none", "present", "empty", "unknown"}, f"{label}.history changed")
    _require(context["server_presence"] in {"unknown", "present", "empty", "missing"}, f"{label}.server_presence changed")


def validate_document(document: dict[str, Any]) -> None:
    _strict_keys(document, ROOT_KEYS, "document")
    _require(document["schema"] == SCHEMA, "schema changed")
    _require(document["operation"] == OPERATION, "operation changed")
    _require(document["contract"] == CONTRACT, "contract changed")
    _require(document["hermes_source_sha"] == HERMES_SOURCE_SHA, "source revision changed")
    _require(type(document["synthetic_only"]) is bool and document["synthetic_only"], "fixture must remain synthetic")
    _require(document["surface"] == SURFACE, "surface changed")
    _validate_source_observations(document)
    _validate_state_table(document)
    _strict_equal(document["invariants"], EXPECTED_INVARIANTS, "invariants")
    _strict_equal(document["redaction"], EXPECTED_REDACTION, "redaction")
    _validate_redaction(document)

    cases = document["cases"]
    _require(type(cases) is list, "cases must be an array")
    definitions = _case_definitions()
    _require(len(cases) == len(definitions), "case count changed")
    for index, case in enumerate(cases):
        _strict_keys(case, CASE_KEYS, f"case[{index}]")
        case_id, expected_state, expected_context, expected_events, expected_notes = definitions[index]
        _require(case["id"] == case_id, f"case[{index}].id changed")
        _require(case["initial_state"] == expected_state, f"case[{index}].initial_state changed")
        _validate_context(case["initial_context"], f"case[{index}].initial_context")
        _strict_equal(case["initial_context"], expected_context, f"case[{index}].initial_context")
        _require(type(case["events"]) is list, f"case[{index}].events must be an array")
        _strict_equal(case["events"], list(expected_events), f"case[{index}].events")
        _strict_equal(case["notes"], expected_notes, f"case[{index}].notes")
        for event in case["events"]:
            _strict_string(event, f"case[{index}].event")
        expected = evaluate_case(case)
        _strict_keys(case["expected"], EXPECTED_KEYS, f"case[{index}].expected")
        _strict_equal(case["expected"], expected, f"case[{index}].expected")


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


def _validate_baseline(baseline: dict[str, Any]) -> int:
    _strict_keys(baseline, BASELINE_KEYS, "baseline")
    _require(baseline["schema"] == BASELINE_SCHEMA, "baseline schema changed")
    _require(baseline["validator"] == "contracts/fixtures/session-persistence/validate.py", "baseline validator changed")
    _require(baseline["command"] == APPROVED_BASELINE_COMMAND, "baseline command changed")
    _require(baseline["build_mode"] == "N/A", "baseline build mode changed")
    _strict_int(baseline["repetitions"], "baseline repetitions")
    _require(baseline["repetitions"] == BASELINE_REPETITIONS, "baseline repetitions changed")
    _require(baseline["threshold"] is None, "baseline threshold must remain null")
    environment = _strict_keys(baseline["environment"], ("platform", "python"), "baseline.environment")
    _require(environment["platform"] == REVIEWED_BASELINE_PLATFORM, "baseline platform changed")
    _require(environment["python"] == REVIEWED_BASELINE_PYTHON, "baseline python changed")

    artifact_bytes = 0
    artifacts = baseline["artifact_files"]
    _require(type(artifacts) is list and len(artifacts) == len(BASELINE_ARTIFACTS), "baseline artifact list changed")
    for index, artifact in enumerate(artifacts):
        _strict_keys(artifact, ARTIFACT_KEYS, f"baseline.artifact_files[{index}]")
        _require(artifact["path"] == BASELINE_ARTIFACTS[index], "baseline artifact path changed")
        _require(type(artifact["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"]) is not None, "baseline artifact digest changed")
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

    for mode in ("normal", "optimized"):
        benchmark = _strict_keys(baseline[mode], BENCHMARK_KEYS, f"baseline.{mode}")
        _require(benchmark["command"] == APPROVED_BENCHMARK_COMMANDS[mode], f"baseline.{mode}.command changed")
        samples = _validate_samples(benchmark["samples_ms"], f"baseline.{mode}")
        _strict_keys(benchmark["distribution"], DISTRIBUTION_KEYS, f"baseline.{mode}.distribution")
        _strict_equal(benchmark["distribution"], _dist(samples), f"baseline.{mode}.distribution")
    _require(_baseline_identity_digest(baseline) == BASELINE_CANONICAL_IDENTITY_SHA256, "baseline canonical identity changed")
    _validate_redaction(baseline, "baseline")
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
    return json.dumps(
        {
            "error": {
                "code": "contract",
                "message": "session persistence fixture rejected",
            }
        },
        sort_keys=True,
        separators=(",", ":"),
    )


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
    print(
        f"session_persistence_validation=ok states={len(STATES)} "
        f"cases={case_count} artifact_bytes={artifact_bytes}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
