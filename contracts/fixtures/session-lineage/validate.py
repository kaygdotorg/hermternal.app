#!/usr/bin/env python3
"""Validate the synthetic C-07B session-lineage contract offline.

This reducer models only Hermternal's reviewed lineage decisions. It never
imports Hermes, opens a socket, reads a server database, sends a prompt, or
stores a transcript. Parent and fork fields are synthetic contract metadata;
the pinned Dashboard source does not expose an approved lineage wire schema.
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
SCHEMA = "hermternal.session-lineage.v1"
BASELINE_SCHEMA = "hermternal.session-lineage-baseline.v1"
OPERATION = "C-07B"
CONTRACT = "dashboard-v0.0.1"
HERMES_SOURCE_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
SURFACE = "shared-web-apple"

STATES = (
    "empty",
    "pending_create",
    "ready",
    "restoring",
    "closed",
    "interrupted",
    "delivery_uncertain",
    "failed",
    "incompatible",
)

# These are deliberately complete synthetic opaque IDs. They are not prefixes,
# hashes of user data, or identifiers copied from a live Hermes instance.
ROOT_SESSION_ID = "session-root-0000000000000000000000000000000000000001"
BRANCH_SESSION_ID = "session-branch-0000000000000000000000000000000000000002"
CLOSED_BRANCH_SESSION_ID = "session-closed-branch-0000000000000000000000000000000000000003"
CYCLE_SESSION_ID = "session-cycle-0000000000000000000000000000000000000004"
FOREIGN_SESSION_ID = "session-foreign-0000000000000000000000000000000000000009"
ROOT_CREATE_KEY = "create-key-root-0000000000000000000000000000000000000001"
BRANCH_CREATE_KEY = "create-key-branch-0000000000000000000000000000000000000002"
CLOSED_BRANCH_CREATE_KEY = "create-key-closed-0000000000000000000000000000000000000003"
UNKNOWN_CREATE_KEY = "create-key-unknown-0000000000000000000000000000000000000004"
NEW_ROOT_CREATE_KEY = "create-key-explicit-0000000000000000000000000000000000000005"

FULL_ID_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._~-]{0,126}[A-Za-z0-9])?$")
MAX_IDENTIFIER_LENGTH = 128
MAX_JSON_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 4096
MAX_OBJECT_KEYS = 64
MAX_ARRAY_LENGTH = 256
MAX_STRING_LENGTH = 16 * 1024
MAX_INTEGER_DIGITS = 4096
BASELINE_REPETITIONS = 30
APPROVED_BASELINE_COMMAND = "python3 contracts/fixtures/session-lineage/validate.py"
APPROVED_BENCHMARK_COMMANDS = {
    "normal": APPROVED_BASELINE_COMMAND,
    "optimized": "python3 -O contracts/fixtures/session-lineage/validate.py",
}
# The benchmark describes only the reviewed local interpreter and machine. It
# is reproducibility evidence, not a portable budget or a production claim.
REVIEWED_BASELINE_PLATFORM = "macOS-26.5.2-arm64-arm-64bit-Mach-O"
REVIEWED_BASELINE_PYTHON = "3.14.6"
BASELINE_EVIDENCE_PATH = ROOT / "baseline-evidence.json"
BASELINE_EVIDENCE_SCHEMA = "hermternal.session-lineage-baseline-evidence.v1"
BASELINE_EVIDENCE_SHA256 = "1d74dd8b8aac106d8bb142fd10ca3e1304ed437e0103f62481365aa81aad40f1"
BASELINE_CANONICAL_IDENTITY_SHA256 = "510de031527e4eab98308df56345f9ddba5081979bb2a239e63ab4bb1c74e54c"

ROOT_KEYS = (
    "schema",
    "operation",
    "contract",
    "hermes_source_sha",
    "synthetic_only",
    "surface",
    "compatibility",
    "source_observations",
    "states",
    "invariants",
    "cases",
    "redaction",
)
COMPATIBILITY_KEYS = (
    "pinned_source_sha",
    "contract",
    "lineage_wire_schema",
    "unsupported_parent_policy",
    "unknown_result_policy",
    "new_session_policy",
    "live_claim",
)
SOURCE_KEYS = ("id", "path", "anchor", "observation", "contract_relevance")
STATE_KEYS = ("id", "meaning", "allowed_actions", "terminal")
INVARIANT_KEYS = (
    "identity",
    "creation",
    "lineage",
    "resume",
    "failure",
    "compatibility",
    "transcript",
)
CASE_KEYS = ("id", "initial_state", "initial_context", "events", "expected", "notes")
CONTEXT_KEYS = (
    "session_id",
    "root_id",
    "parent_id",
    "lineage_kind",
    "parent_state",
    "ancestor_ids",
    "durable",
    "deleted",
    "candidate_parent_state",
    "operation",
    "idempotency_key",
    "creation_attempts",
    "resume_attempts",
    "transport",
    "compatibility",
    "result",
)
EXPECTED_KEYS = (
    "decision",
    "final_state",
    "trace",
    "effects",
    "session_id",
    "root_id",
    "parent_id",
    "lineage_kind",
    "parent_state",
    "ancestor_ids",
    "durable",
    "deleted",
    "creation_attempts",
    "resume_attempts",
    "duplicate_suppressed",
    "transport_closed",
    "retry_policy",
    "compatibility",
    "error_kind",
    "transcript_mirror",
)
REDACTION_KEYS = (
    "synthetic_only",
    "contains_credentials",
    "contains_cookies",
    "contains_tickets",
    "contains_prompts",
    "contains_transcripts",
    "contains_transcript_mirror",
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
EVIDENCE_KEYS = ("schema", "normal", "optimized")
EVIDENCE_BENCHMARK_KEYS = ("samples_ms", "distribution")
DISTRIBUTION_KEYS = ("min", "p50", "p95", "max", "mean")
ARTIFACT_KEYS = ("path", "sha256", "size_bytes")
BASELINE_ARTIFACTS = (
    "README.md",
    "cases.json",
    "validate.py",
    "test_validate.py",
    "baseline-evidence.json",
)

EXPECTED_COMPATIBILITY = {
    "pinned_source_sha": HERMES_SOURCE_SHA,
    "contract": CONTRACT,
    "lineage_wire_schema": "not_defined_by_pinned_dashboard",
    "unsupported_parent_policy": "fail_closed_without_wire_fallback",
    "unknown_result_policy": "reconcile_server_state_before_retry",
    "new_session_policy": "explicit_user_action_only",
    "live_claim": False,
}

EXPECTED_STATES = [
    {
        "id": "empty",
        "meaning": "No lineage operation is active and no session identity is selected.",
        "allowed_actions": ["create_root", "resume_existing"],
        "terminal": False,
    },
    {
        "id": "pending_create",
        "meaning": "A root or branch identity request is pending.",
        "allowed_actions": ["wait", "interrupt", "cancel"],
        "terminal": False,
    },
    {
        "id": "ready",
        "meaning": "A selected session has a validated root and parent lineage.",
        "allowed_actions": ["create_branch", "resume", "close"],
        "terminal": False,
    },
    {
        "id": "restoring",
        "meaning": "The exact selected session identity is being resumed.",
        "allowed_actions": ["wait", "cancel"],
        "terminal": False,
    },
    {
        "id": "closed",
        "meaning": "The durable session is closed or detached but remains addressable.",
        "allowed_actions": ["resume", "create_branch", "create_root"],
        "terminal": False,
    },
    {
        "id": "interrupted",
        "meaning": "Creation or resume stopped before its result was safely known.",
        "allowed_actions": ["reconcile", "retry_idempotent", "sign_out"],
        "terminal": False,
    },
    {
        "id": "delivery_uncertain",
        "meaning": "A creation result is unknown and source state must be reread first.",
        "allowed_actions": ["reconcile", "cancel", "sign_out"],
        "terminal": False,
    },
    {
        "id": "failed",
        "meaning": "A known lineage or restore operation failed without a fallback.",
        "allowed_actions": ["explicit_retry", "create_root", "sign_out"],
        "terminal": False,
    },
    {
        "id": "incompatible",
        "meaning": "Lineage evidence is malformed, foreign, unsupported, or unsafe.",
        "allowed_actions": ["stop", "sign_out"],
        "terminal": True,
    },
]

EXPECTED_SOURCE_OBSERVATIONS = [
    {
        "id": "create-session-identity",
        "path": "tui_gateway/methods_session.py",
        "anchor": '@method("session.create")',
        "observation": "session.create allocates the live session identity used by later session operations; an empty create is not durable until the first prompt persistence boundary.",
        "contract_relevance": "A new root or branch must use one complete identity and must not be copied into a second implicit session.",
    },
    {
        "id": "resume-session-identity",
        "path": "tui_gateway/methods_session.py",
        "anchor": '@method("session.resume")',
        "observation": "session.resume reopens an addressable stored session and returns an error when the stored identity is missing.",
        "contract_relevance": "Resume reuses the exact session and root identities; a missing identity cannot become a new session fallback.",
    },
    {
        "id": "reopen-same-session",
        "path": "hermes_state.py",
        "anchor": "def reopen_session(self, session_id: str)",
        "observation": "reopen_session clears ended markers for the supplied session id before its durable history is read.",
        "contract_relevance": "A closed parent remains an addressable lineage anchor; reopening it must not change its root or parent identity.",
    },
    {
        "id": "idempotent-session-row",
        "path": "hermes_state.py",
        "anchor": "def create_session(self, session_id: str, source: str, **kwargs)",
        "observation": "SessionDB creation is keyed by the stored session id and is idempotent for a repeated create of the same row.",
        "contract_relevance": "Repeated lineage creation with the same idempotency key reuses one identity and records no second child.",
    },
    {
        "id": "session-close-detach",
        "path": "tui_gateway/ws.py",
        "anchor": "_close_sessions_for_transport",
        "observation": "Transport loss detaches sessions for bounded recovery rather than proving that the server session was deleted.",
        "contract_relevance": "Closed and interrupted lineage state must be reconciled or explicitly resumed, not silently replaced.",
    },
    {
        "id": "unknown-dispatch-result",
        "path": "tui_gateway/ws.py",
        "anchor": "server.dispatch",
        "observation": "Dispatch and parse failures are explicit errors rather than successful method results.",
        "contract_relevance": "Unknown or incompatible lineage evidence fails closed and cannot trigger an automatic new session.",
    },
]

EXPECTED_INVARIANTS = {
    "identity": {
        "session_id": "full_opaque_id_required",
        "root_id": "required_and_stable_for_every_created_session",
        "parent_id": "null_only_for_root",
        "display_or_prefix_id": "not_supported",
    },
    "creation": {
        "root": "explicit_create_without_parent",
        "branch": "explicit_create_with_durable_open_or_closed_parent",
        "empty_durability": "not_durable_until_persistence_boundary",
        "duplicate": "same_idempotency_key_reuses_one_identity",
        "implicit_fallback": "blocked",
    },
    "lineage": {
        "root_kind": "root",
        "branch_kind": "branch",
        "root_preservation": "branch_root_equals_parent_root",
        "parent_validation": ["present", "full_id", "not_self", "acyclic", "not_deleted"],
        "closed_parent": "addressable_fork_anchor",
    },
    "resume": {
        "same_session": "reuse_exact_session_id_and_lineage",
        "new_session": "separate_explicit_create",
        "missing": "failed_without_new_session",
        "deleted": "failed_without_new_session",
        "duplicate": "one_restore_attempt_per_identity",
    },
    "failure": {
        "interrupted": "safe_state_and_idempotent_retry_only",
        "unknown": "reconcile_server_state_before_retry",
        "cyclic_or_invalid_parent": "incompatible",
        "foreign_identity": "incompatible",
    },
    "compatibility": {
        "source_sha": HERMES_SOURCE_SHA,
        "parent_wire_field": "unsupported_without_new_contract",
        "missing_or_mismatched": "incompatible",
    },
    "history": {
        "source_of_truth": "server_owned_projection",
        "local_lineage_only": True,
        "mirror": False,
    },
}

EXPECTED_REDACTION = {
    "synthetic_only": True,
    "contains_credentials": False,
    "contains_cookies": False,
    "contains_tickets": False,
    "contains_prompts": False,
    "contains_transcripts": False,
    "contains_transcript_mirror": False,
    "contains_hosts": False,
    "contains_user_data": False,
    "diagnostic_policy": "stable semantic errors only; retain no raw values, paths, or payloads",
}


class ContractError(ValueError):
    """A bounded, redacted contract validation failure."""


def _require(condition: bool, message: str = "contract validation failed") -> None:
    if not condition:
        raise ContractError(message)


def _strict_keys(value: Any, expected: tuple[str, ...], label: str) -> dict[str, Any]:
    _require(type(value) is dict, f"{label} must be an object")
    _require(tuple(value.keys()) == expected, f"{label} keys changed")
    return value


def _strict_equal(actual: Any, expected: Any, label: str) -> None:
    _require(type(actual) is type(expected), f"{label} type changed")
    if isinstance(expected, dict):
        _require(tuple(actual.keys()) == tuple(expected.keys()), f"{label} keys changed")
        for key, expected_value in expected.items():
            _strict_equal(actual[key], expected_value, f"{label}.{key}")
        return
    if isinstance(expected, list):
        _require(len(actual) == len(expected), f"{label} length changed")
        for index, (actual_value, expected_value) in enumerate(zip(actual, expected)):
            _strict_equal(actual_value, expected_value, f"{label}[{index}]")
        return
    _require(actual == expected, f"{label} value changed")


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
        value = json.loads(
            text,
            parse_int=_bounded_int,
            parse_float=_bounded_float,
            parse_constant=_reject_constant,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except ContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError, OverflowError) as exc:
        raise ContractError(f"{label} is not valid JSON") from exc
    _check_bounds(value)
    return value


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def _normalize_redaction_key(key: str) -> str:
    split_acronym = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", key)
    split_camel = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", split_acronym)
    return re.sub(r"[^a-z0-9]+", "_", split_camel.lower()).strip("_")


def _semantic_string_is_safe(value: str) -> bool:
    lowered = value.lower()
    if "\x00" in value or any(ord(char) < 32 and char not in "\t\n\r" for char in value):
        return False
    if re.search(r"\b(?:https?|wss?)://", lowered):
        return False
    if re.search(r"\b(?:host|hostname|server|endpoint)\s*[:=]", lowered):
        return False
    if re.search(r"\b(?:localhost|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:example|invalid|local|internal|test))(?:\:\d+)?\b", lowered):
        return False
    if re.search(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?!\d)", lowered):
        return False
    if re.search(r"\b(?:bearer|basic)\s+[a-z0-9._~+/=-]{8,}", lowered):
        return False
    if re.search(
        r"(?:[\"']?\b(?:access[_-]?token|api[_-]?key|client[_-]?secret|refresh[_-]?token|password|passwd|secret|cookie|ticket|token|authorization|prompt(?:[_-]?text)?|transcript(?:[_-]?text)?|message(?:[_-]?body)?|tool[_-]?output)[\"']?)\s*[:=]",
        lowered,
    ):
        return False
    if re.fullmatch(r"ey[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}", lowered):
        return False
    if re.search(r"(?:^|[\s=(\"'])/(?:users|private|tmp|var|home|etc|opt)(?:/|$)", lowered):
        return False
    if re.search(r"(?:^|[\s=(\"'])~[\\/]", value):
        return False
    if re.search(r"\b[A-Za-z]:[\\/]", value):
        return False
    if re.search(r"(?:^|[\s=(\"'])\\\\", value):
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
        "access_token",
        "refresh_token",
        "secret",
        "secrets",
        "client_secret",
        "authorization",
        "bearer",
        "api_key",
        "prompt",
        "prompt_text",
        "transcript",
        "transcript_text",
        "message_body",
        "tool_output",
        "hostname",
        "host",
        "user_data",
    }
    if type(value) is dict:
        for key, item in value.items():
            normalized = _normalize_redaction_key(key)
            _require(normalized not in sensitive_keys, f"{label} contains a sensitive key")
            _validate_redaction(item, f"{label}.{key}")
    elif type(value) is list:
        for index, item in enumerate(value):
            _validate_redaction(item, f"{label}[{index}]")
    elif type(value) is str:
        _require(_semantic_string_is_safe(value), f"{label} contains a sensitive value")


def _validate_full_id(value: Any, label: str) -> str:
    _strict_string(value, label)
    _require(1 <= len(value) <= MAX_IDENTIFIER_LENGTH, f"{label} length changed")
    _require(FULL_ID_PATTERN.fullmatch(value) is not None, f"{label} is not a full opaque id")
    _require("..." not in value and "…" not in value, f"{label} is abbreviated")
    return value


def _validate_optional_id(value: Any, label: str) -> None:
    if value is not None:
        _validate_full_id(value, label)


def _context(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "session_id": None,
        "root_id": None,
        "parent_id": None,
        "lineage_kind": "none",
        "parent_state": "none",
        "ancestor_ids": [],
        "durable": False,
        "deleted": False,
        "candidate_parent_state": "none",
        "operation": "idle",
        "idempotency_key": None,
        "creation_attempts": 0,
        "resume_attempts": 0,
        "transport": "connected",
        "compatibility": "passed",
        "result": "none",
    }
    value.update(overrides)
    return value


def _root_context(
    *,
    state: str = "ready",
    candidate_parent_state: str = "open",
    deleted: bool = False,
    transport: str | None = None,
    ancestor_ids: list[str] | None = None,
) -> dict[str, Any]:
    if transport is None:
        transport = "detached" if state == "closed" else "connected"
    return _context(
        session_id=ROOT_SESSION_ID,
        root_id=ROOT_SESSION_ID,
        lineage_kind="root",
        ancestor_ids=[] if ancestor_ids is None else list(ancestor_ids),
        durable=True,
        deleted=deleted,
        candidate_parent_state=candidate_parent_state,
        transport=transport,
        result="present",
    )


def _branch_context(*, state: str = "closed", parent_state: str = "closed") -> dict[str, Any]:
    return _context(
        session_id=BRANCH_SESSION_ID,
        root_id=ROOT_SESSION_ID,
        parent_id=ROOT_SESSION_ID,
        lineage_kind="branch",
        parent_state=parent_state,
        ancestor_ids=[ROOT_SESSION_ID],
        durable=True,
        candidate_parent_state="none",
        transport="detached" if state == "closed" else "connected",
        result="present",
    )


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
    runtime["transport"] = "closed"
    runtime["compatibility"] = "failed"
    runtime["error_kind"] = "incompatible"
    runtime["decision"] = "blocked_incompatible"
    runtime["retry_policy"] = "none"
    _effect(runtime, effect)
    _effect(runtime, "no_new_session_fallback")


def _parse_parts(event: str, prefix: str, count: int) -> list[str] | None:
    if not event.startswith(prefix):
        return None
    parts = event[len(prefix) :].split(":")
    if len(parts) != count or any(part == "" for part in parts):
        return None
    return parts


def _lineage_payload(event: str, prefix: str) -> tuple[str, str, str | None, str] | None:
    parts = _parse_parts(event, prefix, 4)
    if parts is None:
        return None
    session_id, root_id, parent_token, lineage_kind = parts
    parent_id = None if parent_token == "none" else parent_token
    return session_id, root_id, parent_id, lineage_kind


def _payload_matches(
    runtime: dict[str, Any],
    payload: tuple[str, str, str | None, str],
    *,
    pending: bool = False,
) -> bool:
    session_id, root_id, parent_id, lineage_kind = payload
    if pending:
        return (
            session_id == runtime.get("pending_session_id")
            and root_id == runtime.get("pending_root_id")
            and parent_id == runtime.get("pending_parent_id")
            and lineage_kind == runtime.get("pending_lineage_kind")
        )
    return (
        session_id == runtime["session_id"]
        and root_id == runtime["root_id"]
        and parent_id == runtime["parent_id"]
        and lineage_kind == runtime["lineage_kind"]
    )


def _apply_created_identity(
    runtime: dict[str, Any],
    payload: tuple[str, str, str | None, str],
    *,
    reconciled: bool,
) -> None:
    session_id, root_id, parent_id, lineage_kind = payload
    runtime["session_id"] = session_id
    runtime["root_id"] = root_id
    runtime["parent_id"] = parent_id
    runtime["lineage_kind"] = lineage_kind
    runtime["ancestor_ids"] = list(runtime.get("pending_ancestor_ids", []))
    runtime["parent_state"] = runtime.get("pending_parent_state", "none")
    runtime["candidate_parent_state"] = "none"
    runtime["durable"] = reconciled
    runtime["deleted"] = False
    runtime["operation"] = "idle"
    runtime["idempotency_key"] = runtime.get("pending_idempotency_key")
    runtime["result"] = "present"
    runtime["transport"] = "connected"
    runtime["transport_closed"] = False
    runtime["retry_policy"] = "none"
    runtime["error_kind"] = None
    runtime["last_creation"] = {
        "payload": payload,
        "idempotency_key": runtime.get("pending_idempotency_key"),
    }
    runtime["pending_kind"] = None
    runtime["pending_session_id"] = None
    runtime["pending_root_id"] = None
    runtime["pending_parent_id"] = None
    runtime["pending_lineage_kind"] = None
    runtime["pending_parent_state"] = None
    runtime["pending_ancestor_ids"] = []
    runtime["pending_idempotency_key"] = None
    _set_state(runtime, "ready" if reconciled else "empty")
    runtime["decision"] = "creation_reconciled" if reconciled else (
        "root_created" if lineage_kind == "root" else "branch_created"
    )
    _effect(runtime, "same_creation_reconciled" if reconciled else (
        "root_identity_allocated" if lineage_kind == "root" else "branch_identity_allocated"
    ))
    if lineage_kind == "branch" and not reconciled:
        _effect(runtime, "parent_identity_bound")
    if reconciled:
        _effect(runtime, "no_duplicate_creation")


def _begin_root_creation(runtime: dict[str, Any], key: str, effect: str) -> None:
    runtime["pending_kind"] = "root"
    runtime["pending_session_id"] = ROOT_SESSION_ID
    runtime["pending_root_id"] = ROOT_SESSION_ID
    runtime["pending_parent_id"] = None
    runtime["pending_lineage_kind"] = "root"
    runtime["pending_parent_state"] = "none"
    runtime["pending_ancestor_ids"] = []
    runtime["pending_idempotency_key"] = key
    runtime["idempotency_key"] = key
    runtime["operation"] = "create"
    runtime["result"] = "pending"
    runtime["creation_attempts"] += 1
    runtime["transport"] = "connected"
    runtime["transport_closed"] = False
    runtime["retry_policy"] = "none"
    runtime["decision"] = "root_creation_pending"
    _set_state(runtime, "pending_create")
    _effect(runtime, effect)


def _begin_branch_creation(runtime: dict[str, Any], child_id: str, parent_id: str, key: str) -> None:
    runtime["pending_kind"] = "branch"
    runtime["pending_session_id"] = child_id
    runtime["pending_root_id"] = runtime["root_id"]
    runtime["pending_parent_id"] = parent_id
    runtime["pending_lineage_kind"] = "branch"
    runtime["pending_parent_state"] = runtime["candidate_parent_state"]
    runtime["pending_ancestor_ids"] = list(runtime["ancestor_ids"]) + [parent_id]
    runtime["pending_idempotency_key"] = key
    runtime["idempotency_key"] = key
    runtime["operation"] = "create"
    runtime["result"] = "pending"
    runtime["creation_attempts"] += 1
    runtime["transport"] = "connected"
    runtime["transport_closed"] = False
    runtime["retry_policy"] = "none"
    runtime["decision"] = "branch_creation_pending"
    _set_state(runtime, "pending_create")
    _effect(runtime, "branch_creation_requested")


def _transition(runtime: dict[str, Any], event: str) -> None:
    state = runtime["state"]

    root_request = _parse_parts(event, "session.create.root.request:", 1)
    if root_request is not None:
        key = root_request[0]
        if state == "empty" and runtime["session_id"] is None and runtime["compatibility"] == "passed":
            _begin_root_creation(runtime, key, "root_creation_requested")
        else:
            _incompatible(runtime, "root_create_in_wrong_state")
        return

    branch_request = _parse_parts(event, "session.create.branch.request:", 3)
    if branch_request is not None:
        child_id, parent_id, key = branch_request
        if state not in {"ready", "closed"} or not runtime["durable"]:
            _incompatible(runtime, "branch_parent_not_durable")
            return
        if runtime["compatibility"] != "passed":
            _incompatible(runtime, "compatibility_gate_failed")
            return
        if runtime["deleted"] or runtime["candidate_parent_state"] == "deleted":
            _incompatible(runtime, "parent_deleted")
            return
        if runtime["candidate_parent_state"] not in {"open", "closed"}:
            _incompatible(runtime, "parent_unavailable")
            return
        if parent_id != runtime["session_id"]:
            _incompatible(runtime, "parent_identity_mismatch")
            return
        if child_id == parent_id:
            _incompatible(runtime, "self_parent")
            return
        if child_id in runtime["ancestor_ids"]:
            _incompatible(runtime, "cyclic_parent")
            return
        _begin_branch_creation(runtime, child_id, parent_id, key)
        return

    missing_parent = _parse_parts(event, "session.create.branch.request.missing:", 2)
    if missing_parent is not None:
        _incompatible(runtime, "parent_missing")
        return

    invalid_parent = _parse_parts(event, "session.create.branch.request.bad:", 3)
    if invalid_parent is not None:
        _incompatible(runtime, "parent_invalid")
        return

    self_parent = _parse_parts(event, "session.create.branch.request.self:", 2)
    if self_parent is not None:
        _incompatible(runtime, "self_parent")
        return

    cyclic_parent = _parse_parts(event, "session.create.branch.request.cycle:", 3)
    if cyclic_parent is not None:
        _incompatible(runtime, "cyclic_parent")
        return

    deleted_parent = _parse_parts(event, "session.create.branch.request.deleted:", 3)
    if deleted_parent is not None:
        _incompatible(runtime, "parent_deleted")
        return

    accepted = _lineage_payload(event, "session.create.accepted:")
    if accepted is not None:
        if state != "pending_create" or not _payload_matches(runtime, accepted, pending=True):
            _incompatible(runtime, "create_ack_identity_mismatch")
        else:
            _apply_created_identity(runtime, accepted, reconciled=False)
        return

    duplicate = _parse_parts(event, "session.create.duplicate:", 5)
    if duplicate is not None:
        session_id, root_id, parent_token, lineage_kind, key = duplicate
        parent_id = None if parent_token == "none" else parent_token
        last = runtime.get("last_creation")
        if state == "empty" and last == {"payload": (session_id, root_id, parent_id, lineage_kind), "idempotency_key": key}:
            runtime["duplicate_suppressed"] = True
            runtime["decision"] = "duplicate_creation_reused"
            _effect(runtime, "duplicate_creation_suppressed")
        else:
            _incompatible(runtime, "duplicate_create_identity_mismatch")
        return

    persisted = _lineage_payload(event, "session.lineage.persisted:")
    if persisted is not None:
        if state == "empty" and _payload_matches(runtime, persisted):
            runtime["durable"] = True
            runtime["result"] = "present"
            runtime["decision"] = "lineage_persisted"
            _set_state(runtime, "ready")
            _effect(runtime, "durable_lineage_recorded")
        else:
            _incompatible(runtime, "persistence_identity_mismatch")
        return

    if event == "session.create.interrupted":
        if state == "pending_create":
            runtime["result"] = "interrupted"
            runtime["transport"] = "closed"
            runtime["transport_closed"] = True
            runtime["retry_policy"] = "reread_before_idempotent_retry"
            runtime["decision"] = "creation_interrupted"
            _set_state(runtime, "interrupted")
            _effect(runtime, "creation_interrupted_safe_state")
            _effect(runtime, "no_duplicate_creation")
        else:
            _incompatible(runtime, "interruption_out_of_order")
        return

    if event == "session.create.unknown":
        if state == "pending_create":
            runtime["result"] = "unknown"
            runtime["transport"] = "closed"
            runtime["transport_closed"] = True
            runtime["retry_policy"] = "reconcile_before_retry"
            runtime["decision"] = "creation_result_unknown"
            _set_state(runtime, "delivery_uncertain")
            _effect(runtime, "creation_result_unknown")
            _effect(runtime, "reconcile_before_retry")
        else:
            _incompatible(runtime, "unknown_creation_result_out_of_order")
        return

    retry = _parse_parts(event, "session.create.retry:", 1)
    if retry is not None:
        key = retry[0]
        if state == "interrupted" and runtime.get("pending_idempotency_key") == key:
            runtime["creation_attempts"] += 1
            runtime["result"] = "pending"
            runtime["transport"] = "connected"
            runtime["transport_closed"] = False
            runtime["retry_policy"] = "none"
            runtime["decision"] = "idempotent_creation_retry"
            _set_state(runtime, "pending_create")
            _effect(runtime, "idempotent_retry_only")
        elif state == "delivery_uncertain":
            _incompatible(runtime, "retry_before_reconcile")
        else:
            _incompatible(runtime, "creation_retry_identity_mismatch")
        return

    reconciled = _lineage_payload(event, "session.create.reconcile.present:")
    if reconciled is not None:
        if state == "delivery_uncertain" and _payload_matches(runtime, reconciled, pending=True):
            _apply_created_identity(runtime, reconciled, reconciled=True)
        else:
            _incompatible(runtime, "reconcile_identity_mismatch")
        return

    if event == "session.create.reconcile.missing":
        if state == "delivery_uncertain":
            runtime["session_id"] = None
            runtime["root_id"] = None
            runtime["parent_id"] = None
            runtime["lineage_kind"] = "none"
            runtime["ancestor_ids"] = []
            runtime["durable"] = False
            runtime["result"] = "missing"
            runtime["transport"] = "closed"
            runtime["transport_closed"] = True
            runtime["retry_policy"] = "explicit_new_session_only"
            runtime["error_kind"] = "unknown_creation_missing"
            runtime["decision"] = "creation_unknown_missing"
            _set_state(runtime, "failed")
            _effect(runtime, "creation_not_found_after_reread")
            _effect(runtime, "no_new_session_fallback")
        else:
            _incompatible(runtime, "reconcile_missing_out_of_order")
        return

    explicit_new = _parse_parts(event, "user.choose.new.root:", 1)
    if explicit_new is not None:
        if (
            state == "failed"
            and runtime["session_id"] is None
            and runtime["error_kind"] in {"resume_missing", "resume_deleted", "unknown_creation_missing"}
            and runtime["compatibility"] == "passed"
        ):
            _begin_root_creation(runtime, explicit_new[0], "explicit_new_session_requested")
            runtime["decision"] = "explicit_new_root_pending"
        else:
            _incompatible(runtime, "implicit_new_session_blocked")
        return

    if event == "session.close.request":
        if state == "ready" and runtime["durable"] and runtime["session_id"] is not None:
            runtime["transport"] = "closed"
            runtime["transport_closed"] = True
            runtime["decision"] = "session_closed"
            _set_state(runtime, "closed")
            _effect(runtime, "closed_identity_retained")
        else:
            _incompatible(runtime, "close_without_durable_identity")
        return

    resume_request = _parse_parts(event, "session.resume.request:", 1)
    if resume_request is not None:
        target_id = resume_request[0]
        if state == "restoring":
            if target_id == runtime.get("pending_resume_id"):
                runtime["decision"] = "duplicate_resume_reused"
                runtime["duplicate_suppressed"] = True
                _effect(runtime, "duplicate_resume_suppressed")
            else:
                _incompatible(runtime, "resume_identity_mismatch")
        elif state in {"closed", "interrupted", "delivery_uncertain"}:
            if not runtime["durable"] or runtime["deleted"] or target_id != runtime["session_id"]:
                _incompatible(runtime, "resume_identity_mismatch")
            else:
                runtime["pending_resume_id"] = target_id
                runtime["operation"] = "resume"
                runtime["resume_attempts"] += 1
                runtime["result"] = "pending"
                runtime["transport"] = "connected"
                runtime["transport_closed"] = False
                runtime["retry_policy"] = "none"
                runtime["decision"] = "resume_pending"
                _set_state(runtime, "restoring")
                _effect(runtime, "resume_same_identity_requested")
        else:
            _incompatible(runtime, "resume_in_wrong_state")
        return

    present = _lineage_payload(event, "session.resume.present:")
    if present is not None:
        if state == "restoring" and present[0] == runtime.get("pending_resume_id") and _payload_matches(runtime, present):
            runtime["operation"] = "idle"
            runtime["result"] = "present"
            runtime["transport"] = "connected"
            runtime["transport_closed"] = False
            runtime["retry_policy"] = "none"
            runtime["decision"] = "resume_same_session"
            _set_state(runtime, "ready")
            _effect(runtime, "same_session_identity_reused")
            runtime["pending_resume_id"] = None
        else:
            _incompatible(runtime, "resume_result_identity_mismatch")
        return

    if event == "session.resume.missing":
        if state == "restoring":
            runtime["session_id"] = None
            runtime["root_id"] = None
            runtime["parent_id"] = None
            runtime["lineage_kind"] = "none"
            runtime["ancestor_ids"] = []
            runtime["durable"] = False
            runtime["result"] = "missing"
            runtime["transport"] = "closed"
            runtime["transport_closed"] = True
            runtime["retry_policy"] = "explicit_new_session_only"
            runtime["error_kind"] = "resume_missing"
            runtime["decision"] = "resume_missing"
            _set_state(runtime, "failed")
            _effect(runtime, "stored_identity_missing")
            _effect(runtime, "no_new_session_fallback")
        else:
            _incompatible(runtime, "resume_missing_out_of_order")
        return

    if event == "session.resume.deleted":
        if state == "restoring":
            runtime["session_id"] = None
            runtime["root_id"] = None
            runtime["parent_id"] = None
            runtime["lineage_kind"] = "none"
            runtime["ancestor_ids"] = []
            runtime["durable"] = False
            runtime["result"] = "missing"
            runtime["transport"] = "closed"
            runtime["transport_closed"] = True
            runtime["retry_policy"] = "explicit_new_session_only"
            runtime["error_kind"] = "resume_deleted"
            runtime["decision"] = "resume_deleted"
            _set_state(runtime, "failed")
            _effect(runtime, "stored_identity_deleted")
            _effect(runtime, "no_new_session_fallback")
        else:
            _incompatible(runtime, "resume_deleted_out_of_order")
        return

    if event == "session.resume.interrupted":
        if state == "restoring":
            runtime["result"] = "interrupted"
            runtime["transport"] = "closed"
            runtime["transport_closed"] = True
            runtime["retry_policy"] = "reconcile_before_retry"
            runtime["error_kind"] = "resume_interrupted"
            runtime["decision"] = "resume_interrupted"
            _set_state(runtime, "interrupted")
            _effect(runtime, "resume_interrupted_safe_state")
        else:
            _incompatible(runtime, "resume_interrupted_out_of_order")
        return

    if event == "compatibility.fail":
        _incompatible(runtime, "compatibility_gate_failed")
        return

    if event == "unknown.event":
        _incompatible(runtime, "unknown_lineage_event")
        return

    if event == "session.malformed":
        _incompatible(runtime, "malformed_lineage_evidence")
        return

    _incompatible(runtime, "unsupported_lineage_event")


def _initial_runtime(initial_state: str, context: dict[str, Any]) -> dict[str, Any]:
    runtime = dict(context)
    runtime.update(
        {
            "state": initial_state,
            "trace": [initial_state],
            "effects": [],
            "decision": "pending" if initial_state != "incompatible" else "blocked_incompatible",
            "duplicate_suppressed": False,
            "transport_closed": context["transport"] in {"detached", "closed"},
            "retry_policy": "none",
            "error_kind": None,
            "transcript_mirror": False,
            "pending_kind": None,
            "pending_session_id": None,
            "pending_root_id": None,
            "pending_parent_id": None,
            "pending_lineage_kind": None,
            "pending_parent_state": None,
            "pending_ancestor_ids": [],
            "pending_idempotency_key": None,
            "pending_resume_id": None,
            "last_creation": None,
        }
    )
    if initial_state == "incompatible" or context["compatibility"] == "failed":
        runtime["state"] = "incompatible"
        runtime["decision"] = "blocked_incompatible"
        runtime["transport"] = "closed"
        runtime["transport_closed"] = True
        runtime["retry_policy"] = "none"
        runtime["error_kind"] = "incompatible"
        runtime["compatibility"] = "failed"
        runtime["effects"] = ["compatibility_gate_failed", "no_new_session_fallback"]
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
        "session_id": runtime["session_id"],
        "root_id": runtime["root_id"],
        "parent_id": runtime["parent_id"],
        "lineage_kind": runtime["lineage_kind"],
        "parent_state": runtime["parent_state"],
        "ancestor_ids": runtime["ancestor_ids"],
        "durable": runtime["durable"],
        "deleted": runtime["deleted"],
        "creation_attempts": runtime["creation_attempts"],
        "resume_attempts": runtime["resume_attempts"],
        "duplicate_suppressed": runtime["duplicate_suppressed"],
        "transport_closed": runtime["transport_closed"],
        "retry_policy": runtime["retry_policy"],
        "compatibility": runtime["compatibility"],
        "error_kind": runtime["error_kind"],
        "transcript_mirror": runtime["transcript_mirror"],
    }


def _case_definitions() -> list[tuple[str, str, dict[str, Any], tuple[str, ...], str]]:
    return [
        (
            "state-empty-no-session",
            "empty",
            _context(),
            (),
            "An empty state has no selected identity and no lineage side effect.",
        ),
        (
            "create-new-root-empty",
            "empty",
            _context(),
            (f"session.create.root.request:{ROOT_CREATE_KEY}", f"session.create.accepted:{ROOT_SESSION_ID}:{ROOT_SESSION_ID}:none:root"),
            "An explicit root create allocates one complete root identity but remains non-durable until persistence.",
        ),
        (
            "create-new-root-duplicate-idempotent",
            "empty",
            _context(),
            (
                f"session.create.root.request:{ROOT_CREATE_KEY}",
                f"session.create.accepted:{ROOT_SESSION_ID}:{ROOT_SESSION_ID}:none:root",
                f"session.create.duplicate:{ROOT_SESSION_ID}:{ROOT_SESSION_ID}:none:root:{ROOT_CREATE_KEY}",
            ),
            "A repeated root create acknowledgement reuses the same complete identity.",
        ),
        (
            "persist-new-root-lineage",
            "empty",
            _context(),
            (
                f"session.create.root.request:{ROOT_CREATE_KEY}",
                f"session.create.accepted:{ROOT_SESSION_ID}:{ROOT_SESSION_ID}:none:root",
                f"session.lineage.persisted:{ROOT_SESSION_ID}:{ROOT_SESSION_ID}:none:root",
            ),
            "The first persistence boundary makes the root addressable without changing its identity.",
        ),
        (
            "create-branch-from-open-root",
            "ready",
            _root_context(candidate_parent_state="open"),
            (
                f"session.create.branch.request:{BRANCH_SESSION_ID}:{ROOT_SESSION_ID}:{BRANCH_CREATE_KEY}",
                f"session.create.accepted:{BRANCH_SESSION_ID}:{ROOT_SESSION_ID}:{ROOT_SESSION_ID}:branch",
                f"session.lineage.persisted:{BRANCH_SESSION_ID}:{ROOT_SESSION_ID}:{ROOT_SESSION_ID}:branch",
            ),
            "A fork from an open durable parent preserves the root and binds the exact parent.",
        ),
        (
            "create-branch-from-closed-parent",
            "closed",
            _root_context(state="closed", candidate_parent_state="closed"),
            (
                f"session.create.branch.request:{CLOSED_BRANCH_SESSION_ID}:{ROOT_SESSION_ID}:{CLOSED_BRANCH_CREATE_KEY}",
                f"session.create.accepted:{CLOSED_BRANCH_SESSION_ID}:{ROOT_SESSION_ID}:{ROOT_SESSION_ID}:branch",
                f"session.lineage.persisted:{CLOSED_BRANCH_SESSION_ID}:{ROOT_SESSION_ID}:{ROOT_SESSION_ID}:branch",
            ),
            "A closed durable parent remains an addressable fork anchor; closing is not deletion.",
        ),
        (
            "create-branch-duplicate-idempotent",
            "ready",
            _root_context(candidate_parent_state="open"),
            (
                f"session.create.branch.request:{BRANCH_SESSION_ID}:{ROOT_SESSION_ID}:{BRANCH_CREATE_KEY}",
                f"session.create.accepted:{BRANCH_SESSION_ID}:{ROOT_SESSION_ID}:{ROOT_SESSION_ID}:branch",
                f"session.create.duplicate:{BRANCH_SESSION_ID}:{ROOT_SESSION_ID}:{ROOT_SESSION_ID}:branch:{BRANCH_CREATE_KEY}",
            ),
            "A repeated branch create does not create a second child or alter the parent link.",
        ),
        (
            "resume-existing-branch",
            "closed",
            _branch_context(state="closed", parent_state="open"),
            (
                f"session.resume.request:{BRANCH_SESSION_ID}",
                f"session.resume.present:{BRANCH_SESSION_ID}:{ROOT_SESSION_ID}:{ROOT_SESSION_ID}:branch",
            ),
            "Resume returns the same branch identity, root identity, parent identity, and lineage kind.",
        ),
        (
            "resume-closed-parent",
            "closed",
            _root_context(state="closed", candidate_parent_state="closed"),
            (
                f"session.resume.request:{ROOT_SESSION_ID}",
                f"session.resume.present:{ROOT_SESSION_ID}:{ROOT_SESSION_ID}:none:root",
            ),
            "Resuming a closed root reopens that root; it does not create a replacement.",
        ),
        (
            "duplicate-resume-is-idempotent",
            "closed",
            _branch_context(state="closed", parent_state="closed"),
            (
                f"session.resume.request:{BRANCH_SESSION_ID}",
                f"session.resume.request:{BRANCH_SESSION_ID}",
                f"session.resume.present:{BRANCH_SESSION_ID}:{ROOT_SESSION_ID}:{ROOT_SESSION_ID}:branch",
            ),
            "Concurrent resume requests share one restore attempt for one exact identity.",
        ),
        (
            "resume-missing-fails-closed",
            "closed",
            _branch_context(state="closed", parent_state="open"),
            (f"session.resume.request:{BRANCH_SESSION_ID}", "session.resume.missing"),
            "A missing stored identity fails without silently creating a new session.",
        ),
        (
            "resume-deleted-fails-closed",
            "closed",
            _root_context(state="closed", candidate_parent_state="closed"),
            (f"session.resume.request:{ROOT_SESSION_ID}", "session.resume.deleted"),
            "A deleted identity is not treated as a closed resumable identity.",
        ),
        (
            "branch-missing-parent-fails-closed",
            "ready",
            _root_context(candidate_parent_state="missing"),
            (f"session.create.branch.request.missing:{BRANCH_SESSION_ID}:{BRANCH_CREATE_KEY}",),
            "A branch without a parent reference is incompatible.",
        ),
        (
            "branch-invalid-parent-fails-closed",
            "ready",
            _root_context(candidate_parent_state="invalid"),
            (f"session.create.branch.request.bad:{BRANCH_SESSION_ID}:parent-prefix:{BRANCH_CREATE_KEY}",),
            "A parent reference that is not a complete opaque ID is incompatible.",
        ),
        (
            "branch-self-parent-fails-closed",
            "ready",
            _root_context(candidate_parent_state="open"),
            (f"session.create.branch.request.self:{ROOT_SESSION_ID}:{BRANCH_CREATE_KEY}",),
            "A session cannot name itself as its parent.",
        ),
        (
            "branch-cyclic-parent-fails-closed",
            "ready",
            _root_context(candidate_parent_state="open", ancestor_ids=[ROOT_SESSION_ID, CYCLE_SESSION_ID]),
            (f"session.create.branch.request.cycle:{CYCLE_SESSION_ID}:{ROOT_SESSION_ID}:{BRANCH_CREATE_KEY}",),
            "A parent graph that already contains the child is cyclic and stops.",
        ),
        (
            "branch-parent-identity-mismatch-fails-closed",
            "ready",
            _root_context(candidate_parent_state="open"),
            (f"session.create.branch.request:{BRANCH_SESSION_ID}:{FOREIGN_SESSION_ID}:{BRANCH_CREATE_KEY}",),
            "A branch request for a different parent identity cannot borrow the selected root.",
        ),
        (
            "branch-deleted-parent-fails-closed",
            "closed",
            _root_context(state="closed", candidate_parent_state="deleted", deleted=True),
            (f"session.create.branch.request.deleted:{BRANCH_SESSION_ID}:{ROOT_SESSION_ID}:{BRANCH_CREATE_KEY}",),
            "A deleted parent cannot be used for a new branch.",
        ),
        (
            "create-interrupted-preserves-parent",
            "ready",
            _root_context(candidate_parent_state="open"),
            (
                f"session.create.branch.request:{BRANCH_SESSION_ID}:{ROOT_SESSION_ID}:{BRANCH_CREATE_KEY}",
                "session.create.interrupted",
            ),
            "An interrupted fork keeps the existing parent selected and permits only an idempotent retry.",
        ),
        (
            "create-interrupted-idempotent-retry",
            "ready",
            _root_context(candidate_parent_state="open"),
            (
                f"session.create.branch.request:{BRANCH_SESSION_ID}:{ROOT_SESSION_ID}:{BRANCH_CREATE_KEY}",
                "session.create.interrupted",
                f"session.create.retry:{BRANCH_CREATE_KEY}",
                f"session.create.accepted:{BRANCH_SESSION_ID}:{ROOT_SESSION_ID}:{ROOT_SESSION_ID}:branch",
            ),
            "The same creation key may be retried after interruption without changing lineage.",
        ),
        (
            "create-unknown-enters-uncertain",
            "ready",
            _root_context(candidate_parent_state="open"),
            (
                f"session.create.branch.request:{BRANCH_SESSION_ID}:{ROOT_SESSION_ID}:{UNKNOWN_CREATE_KEY}",
                "session.create.unknown",
            ),
            "An unknown branch result is delivery uncertainty, not a failure or a new-session signal.",
        ),
        (
            "unknown-create-reconcile-present-no-duplicate",
            "ready",
            _root_context(candidate_parent_state="open"),
            (
                f"session.create.branch.request:{BRANCH_SESSION_ID}:{ROOT_SESSION_ID}:{UNKNOWN_CREATE_KEY}",
                "session.create.unknown",
                f"session.create.reconcile.present:{BRANCH_SESSION_ID}:{ROOT_SESSION_ID}:{ROOT_SESSION_ID}:branch",
            ),
            "Re-reading the server finds the original branch and prevents a duplicate creation.",
        ),
        (
            "unknown-create-reconcile-missing-fails-closed",
            "ready",
            _root_context(candidate_parent_state="open"),
            (
                f"session.create.branch.request:{BRANCH_SESSION_ID}:{ROOT_SESSION_ID}:{UNKNOWN_CREATE_KEY}",
                "session.create.unknown",
                "session.create.reconcile.missing",
            ),
            "A missing result after an unknown create remains failed until an explicit user choice.",
        ),
        (
            "unknown-create-retry-before-reconcile-fails-closed",
            "ready",
            _root_context(candidate_parent_state="open"),
            (
                f"session.create.branch.request:{BRANCH_SESSION_ID}:{ROOT_SESSION_ID}:{UNKNOWN_CREATE_KEY}",
                "session.create.unknown",
                f"session.create.retry:{UNKNOWN_CREATE_KEY}",
            ),
            "Retrying an unknown create before reconciliation is incompatible and cannot duplicate a child.",
        ),
        (
            "resume-interrupted-safe-state",
            "closed",
            _branch_context(state="closed", parent_state="open"),
            (
                f"session.resume.request:{BRANCH_SESSION_ID}",
                "session.resume.interrupted",
            ),
            "An interrupted resume preserves the exact stored lineage and requires a safe reread.",
        ),
        (
            "compatibility-failure-blocks-new-root",
            "empty",
            _context(compatibility="failed"),
            (f"session.create.root.request:{ROOT_CREATE_KEY}",),
            "Missing or mismatched compatibility evidence blocks root creation without a fallback.",
        ),
        (
            "compatibility-failure-blocks-branch",
            "ready",
            _context(
                session_id=ROOT_SESSION_ID,
                root_id=ROOT_SESSION_ID,
                lineage_kind="root",
                durable=True,
                candidate_parent_state="open",
                result="present",
                compatibility="failed",
            ),
            (f"session.create.branch.request:{BRANCH_SESSION_ID}:{ROOT_SESSION_ID}:{BRANCH_CREATE_KEY}",),
            "A compatibility failure blocks lineage expansion even when a parent identity exists.",
        ),
        (
            "unknown-lineage-event-fails-closed",
            "ready",
            _root_context(candidate_parent_state="open"),
            ("unknown.event",),
            "Unknown lineage evidence never becomes an implicit create or resume action.",
        ),
        (
            "malformed-lineage-event-fails-closed",
            "ready",
            _root_context(candidate_parent_state="open"),
            ("session.malformed",),
            "Malformed lineage evidence closes the operation with one semantic failure.",
        ),
        (
            "resume-foreign-full-id-fails-closed",
            "closed",
            _branch_context(state="closed", parent_state="open"),
            (f"session.resume.request:{FOREIGN_SESSION_ID}",),
            "A full but foreign session ID is rejected rather than mapped by prefix or similarity.",
        ),
        (
            "explicit-new-root-after-missing-resume",
            "closed",
            _branch_context(state="closed", parent_state="open"),
            (
                f"session.resume.request:{BRANCH_SESSION_ID}",
                "session.resume.missing",
                f"user.choose.new.root:{NEW_ROOT_CREATE_KEY}",
                f"session.create.accepted:{ROOT_SESSION_ID}:{ROOT_SESSION_ID}:none:root",
            ),
            "A new root is allowed only after an explicit user choice, never as automatic resume recovery.",
        ),
        (
            "new-root-never-inherits-parent",
            "empty",
            _context(),
            (
                f"session.create.root.request:{NEW_ROOT_CREATE_KEY}",
                f"session.create.accepted:{ROOT_SESSION_ID}:{ROOT_SESSION_ID}:none:root",
            ),
            "An explicit new root has a null parent and does not inherit a previous lineage.",
        ),
    ]


def _case_definition_map() -> dict[str, tuple[str, str, dict[str, Any], tuple[str, ...], str]]:
    return {definition[0]: definition for definition in _case_definitions()}


def _validate_context(context: dict[str, Any], label: str) -> None:
    _strict_keys(context, CONTEXT_KEYS, label)
    for key in ("session_id", "root_id", "parent_id", "idempotency_key"):
        value = context[key]
        if value is not None:
            _validate_full_id(value, f"{label}.{key}")
    _require(context["lineage_kind"] in {"none", "root", "branch"}, f"{label}.lineage_kind changed")
    _require(context["parent_state"] in {"none", "open", "closed", "deleted", "missing", "invalid", "cycle"}, f"{label}.parent_state changed")
    _require(context["candidate_parent_state"] in {"none", "open", "closed", "deleted", "missing", "invalid", "cycle"}, f"{label}.candidate_parent_state changed")
    _require(type(context["ancestor_ids"]) is list, f"{label}.ancestor_ids must be an array")
    _require(len(context["ancestor_ids"]) <= 64, f"{label}.ancestor_ids is too long")
    seen: set[str] = set()
    for index, value in enumerate(context["ancestor_ids"]):
        _validate_full_id(value, f"{label}.ancestor_ids[{index}]")
        _require(value not in seen, f"{label}.ancestor_ids contains a duplicate")
        seen.add(value)
    _strict_bool(context["durable"], f"{label}.durable")
    _strict_bool(context["deleted"], f"{label}.deleted")
    _require(context["operation"] in {"idle", "create", "resume"}, f"{label}.operation changed")
    _strict_int(context["creation_attempts"], f"{label}.creation_attempts")
    _strict_int(context["resume_attempts"], f"{label}.resume_attempts")
    _require(context["creation_attempts"] >= 0 and context["resume_attempts"] >= 0, f"{label} attempts must be non-negative")
    _require(context["transport"] in {"connected", "detached", "closed"}, f"{label}.transport changed")
    _require(context["compatibility"] in {"passed", "failed"}, f"{label}.compatibility changed")
    _require(context["result"] in {"none", "pending", "present", "missing", "interrupted", "unknown"}, f"{label}.result changed")


def _validate_expected(expected: dict[str, Any], label: str) -> None:
    _strict_keys(expected, EXPECTED_KEYS, label)
    for key in ("session_id", "root_id", "parent_id"):
        _validate_optional_id(expected[key], f"{label}.{key}")
    _require(expected["lineage_kind"] in {"none", "root", "branch"}, f"{label}.lineage_kind changed")
    _require(expected["parent_state"] in {"none", "open", "closed", "deleted", "missing", "invalid", "cycle"}, f"{label}.parent_state changed")
    _require(type(expected["ancestor_ids"]) is list, f"{label}.ancestor_ids must be an array")
    for index, value in enumerate(expected["ancestor_ids"]):
        _validate_full_id(value, f"{label}.ancestor_ids[{index}]")
    for key in ("durable", "deleted", "duplicate_suppressed", "transport_closed", "transcript_mirror"):
        _strict_bool(expected[key], f"{label}.{key}")
    for key in ("creation_attempts", "resume_attempts"):
        _strict_int(expected[key], f"{label}.{key}")
        _require(expected[key] >= 0, f"{label}.{key} must be non-negative")
    _require(expected["final_state"] in STATES, f"{label}.final_state changed")
    _require(type(expected["trace"]) is list and expected["trace"], f"{label}.trace changed")
    for state in expected["trace"]:
        _require(state in STATES, f"{label}.trace state changed")
    _require(type(expected["effects"]) is list, f"{label}.effects must be an array")
    for effect in expected["effects"]:
        _strict_string(effect, f"{label}.effect")
    _require(expected["retry_policy"] in {"none", "reread_before_idempotent_retry", "reconcile_before_retry", "explicit_new_session_only"}, f"{label}.retry_policy changed")
    _require(expected["compatibility"] in {"passed", "failed"}, f"{label}.compatibility changed")
    _require(expected["error_kind"] is None or type(expected["error_kind"]) is str, f"{label}.error_kind changed")


def _validate_source_observations(document: dict[str, Any]) -> None:
    observations = document["source_observations"]
    _require(type(observations) is list, "source_observations must be an array")
    _strict_equal(observations, EXPECTED_SOURCE_OBSERVATIONS, "source_observations")
    for index, observation in enumerate(observations):
        _strict_keys(observation, SOURCE_KEYS, f"source_observations[{index}]")
        for key in SOURCE_KEYS:
            _strict_string(observation[key], f"source_observations[{index}].{key}")


def validate_document(document: dict[str, Any]) -> None:
    _strict_keys(document, ROOT_KEYS, "document")
    _require(document["schema"] == SCHEMA, "schema changed")
    _require(document["operation"] == OPERATION, "operation changed")
    _require(document["contract"] == CONTRACT, "contract changed")
    _require(document["hermes_source_sha"] == HERMES_SOURCE_SHA, "source revision changed")
    _require(type(document["synthetic_only"]) is bool and document["synthetic_only"], "fixture must remain synthetic")
    _require(document["surface"] == SURFACE, "surface changed")
    compatibility = _strict_keys(document["compatibility"], COMPATIBILITY_KEYS, "compatibility")
    _strict_equal(compatibility, EXPECTED_COMPATIBILITY, "compatibility")
    _validate_source_observations(document)
    _strict_equal(document["states"], EXPECTED_STATES, "states")
    for index, state in enumerate(document["states"]):
        _strict_keys(state, STATE_KEYS, f"states[{index}]")
    _strict_equal(document["invariants"], EXPECTED_INVARIANTS, "invariants")
    redaction = _strict_keys(document["redaction"], REDACTION_KEYS, "redaction")
    _strict_equal(redaction, EXPECTED_REDACTION, "redaction")
    _validate_redaction(document)

    cases = document["cases"]
    definitions = _case_definitions()
    _require(type(cases) is list and len(cases) == len(definitions), "case count changed")
    for index, case in enumerate(cases):
        _strict_keys(case, CASE_KEYS, f"case[{index}]")
        case_id, initial_state, initial_context, events, notes = definitions[index]
        _require(case["id"] == case_id, f"case[{index}].id changed")
        _require(case["initial_state"] == initial_state, f"case[{index}].initial_state changed")
        _validate_context(case["initial_context"], f"case[{index}].initial_context")
        _strict_equal(case["initial_context"], initial_context, f"case[{index}].initial_context")
        _require(type(case["events"]) is list, f"case[{index}].events must be an array")
        _strict_equal(case["events"], list(events), f"case[{index}].events")
        for event in case["events"]:
            _strict_string(event, f"case[{index}].event")
        _require(case["notes"] == notes, f"case[{index}].notes changed")
        expected = evaluate_case(case)
        _validate_expected(case["expected"], f"case[{index}].expected")
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


def _load_canonical_baseline_evidence() -> dict[str, Any]:
    try:
        raw = BASELINE_EVIDENCE_PATH.read_bytes()
    except OSError as exc:
        raise ContractError("canonical baseline evidence unavailable") from exc
    _require(hashlib.sha256(raw).hexdigest() == BASELINE_EVIDENCE_SHA256, "canonical baseline evidence changed")
    value = _load_json(BASELINE_EVIDENCE_PATH, "canonical baseline evidence")
    _strict_keys(value, EVIDENCE_KEYS, "canonical baseline evidence")
    _require(value["schema"] == BASELINE_EVIDENCE_SCHEMA, "canonical baseline evidence schema changed")
    for mode in ("normal", "optimized"):
        _strict_keys(value[mode], EVIDENCE_BENCHMARK_KEYS, f"canonical baseline evidence.{mode}")
        samples = _validate_samples(value[mode]["samples_ms"], f"canonical baseline evidence.{mode}")
        _strict_keys(value[mode]["distribution"], DISTRIBUTION_KEYS, f"canonical baseline evidence.{mode}.distribution")
        _strict_equal(value[mode]["distribution"], _dist(samples), f"canonical baseline evidence.{mode}.distribution")
    return value


def _baseline_identity_digest(baseline: dict[str, Any]) -> str:
    identity = {
        "schema": baseline["schema"],
        "validator": baseline["validator"],
        "command": baseline["command"],
        "build_mode": baseline["build_mode"],
        "environment": baseline["environment"],
        "repetitions": baseline["repetitions"],
        "normal": baseline["normal"],
        "optimized": baseline["optimized"],
        "normal_command": baseline["normal"]["command"],
        "optimized_command": baseline["optimized"]["command"],
        "canonical_evidence_sha256": BASELINE_EVIDENCE_SHA256,
        "threshold": baseline["threshold"],
    }
    return hashlib.sha256(_canonical_json_bytes(identity)).hexdigest()


def _validate_baseline(baseline: dict[str, Any]) -> int:
    _strict_keys(baseline, BASELINE_KEYS, "baseline")
    _require(baseline["schema"] == BASELINE_SCHEMA, "baseline schema changed")
    _require(baseline["validator"] == "contracts/fixtures/session-lineage/validate.py", "baseline validator changed")
    _require(baseline["command"] == APPROVED_BASELINE_COMMAND, "baseline command changed")
    _require(baseline["build_mode"] == "N/A", "baseline build mode changed")
    _strict_int(baseline["repetitions"], "baseline repetitions")
    _require(baseline["repetitions"] == BASELINE_REPETITIONS, "baseline repetitions changed")
    _require(baseline["threshold"] is None, "baseline threshold must remain null")
    environment = _strict_keys(baseline["environment"], ("platform", "python"), "baseline.environment")
    _require(environment["platform"] == REVIEWED_BASELINE_PLATFORM, "baseline platform changed")
    _require(environment["python"] == REVIEWED_BASELINE_PYTHON, "baseline python changed")
    evidence = _load_canonical_baseline_evidence()

    artifact_bytes = 0
    artifacts = baseline["artifact_files"]
    _require(type(artifacts) is list and len(artifacts) == len(BASELINE_ARTIFACTS), "baseline artifact list changed")
    for index, artifact in enumerate(artifacts):
        _strict_keys(artifact, ARTIFACT_KEYS, f"baseline.artifact_files[{index}]")
        _require(artifact["path"] == BASELINE_ARTIFACTS[index], "baseline artifact path changed")
        _require(type(artifact["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"]) is not None, "baseline artifact digest changed")
        _strict_int(artifact["size_bytes"], "baseline artifact size")
        _require(artifact["size_bytes"] >= 0, "baseline artifact size changed")
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
        _strict_equal(samples, evidence[mode]["samples_ms"], f"baseline.{mode}.samples_ms")
        _strict_equal(benchmark["distribution"], evidence[mode]["distribution"], f"baseline.{mode}.distribution")
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
        {"error": {"code": "contract", "message": "session lineage fixture rejected"}},
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
        f"session_lineage_validation=ok states={len(STATES)} "
        f"cases={case_count} artifact_bytes={artifact_bytes}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
