#!/usr/bin/env python3
"""Validate the offline C-07A session-search fixture.

The reducer uses synthetic metadata only. It never opens Hermes, a network
connection, a session database, or a transcript store. Search results expose
only exact opaque session identities.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import statistics
import sys
from typing import Any

ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = ROOT.parents[2]
CASES_PATH = ROOT / "cases.json"
BASELINE_PATH = ROOT / "validation-baseline.json"
EVIDENCE_PATH = ROOT / "baseline-evidence.json"
SCHEMA = "hermternal.session-search.v1"
BASELINE_SCHEMA = "hermternal.session-search-baseline.v1"
EVIDENCE_SCHEMA = "hermternal.session-search-baseline-evidence.v1"
OPERATION = "C-07A"
CONTRACT = "dashboard-v0.0.1"
SOURCE_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"

# BEGIN REVIEWED TRUST ANCHORS
REVIEWED_ARTIFACT_SHA256 = {
    "README.md": "c5709e956d15fcd0de37cfc066f123faf47da96afa430a3d4da33b3a1cb02085",
    "cases.json": "286b9095a7f22c0e7bb97979ebc71668fddff22b54a30e2eb335157e12cf4621",
    "test_validate.py": "7eb0af17513354ab6f08b737651b010ad69eabd190b4cffacd1c8ef2b29f6b67",
    "baseline-evidence.json": "02ad8d3a0b4949d00596f7333a0ac1de9d633cfe4684947aebfe87583e951a5e",
}
REVIEWED_BASELINE_SHA256 = "cb7a950cde401b98e524cefa9d0ba4b64df8a70a0cbba7712e27b73777c7a51f"
REVIEWED_VALIDATOR_CANONICAL_SHA256 = "5df765f4e231654ac94260863c90ef30b04f5048d057a6584c1dd058353804d9"
# END REVIEWED TRUST ANCHORS

MAX_FILE_BYTES = 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 8192
MAX_OBJECT_KEYS = 64
MAX_ARRAY_ITEMS = 512
MAX_STRING_CHARS = 16 * 1024
MAX_INTEGER_DIGITS = 256
MAX_QUERY_BYTES = 256
MAX_CURSOR_BYTES = 512
MAX_PAGE_SIZE = 50
BASELINE_REPETITIONS = 30
ERROR_MESSAGE = "session search fixture rejected"
SUCCESS_PREFIX = "session-search fixture valid"
APPROVED_COMMANDS = {
    "normal": "python3 contracts/fixtures/session-search/validate.py",
    "optimized": "python3 -O contracts/fixtures/session-search/validate.py",
}
BASELINE_ARTIFACTS = (
    "README.md",
    "cases.json",
    "validate.py",
    "test_validate.py",
    "baseline-evidence.json",
)
OPAQUE_ID = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._~-]{0,126}[A-Za-z0-9])?$")
CURSOR_RE = re.compile(r"^c1\.[0-9a-f]{16}\.[0-9]+\.[A-Za-z0-9._~-]{16,128}$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
SENSITIVE_KEY_RE = re.compile(
    r"(?:authorization|cookie|password|secret|token|ticket|prompt|transcript|content|tool_output|host|url)",
    re.IGNORECASE,
)
SENSITIVE_VALUE_RE = re.compile(
    r"(?:bearer\s+|basic\s+|https?://|(?:password|secret|token|ticket|prompt|transcript|message|content|host)\s*[:=]|"
    r"(?:^|\s)(?:/Users/|/home/|~/|[A-Za-z]:[\\/]|\\\\)|(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?)",
    re.IGNORECASE,
)

DEPENDENCIES = [
    {
        "path": "contracts/fixtures/session-persistence/cases.json",
        "sha256": "59aec1f5b6eb83904f355df850b61379b737b64c6c214b47a909d0976acca6da",
        "use": "exact opaque identity and no transcript mirror boundary",
    },
    {
        "path": "contracts/fixtures/route-allowlist/route_allowlist.json",
        "sha256": "0d0e9b3d54eefd15abea8fd6869e4e7a95908c9bf057441979e980490bad4e69",
        "use": "approved authenticated GET /api/sessions/search surface",
    },
    {
        "path": "contracts/fixtures/route-allowlist/source_audit.json",
        "sha256": "65a26cdea086d28ee90cc7e22d81c3e48715ea28a89f1bedb9f70c4a050aa78d",
        "use": "pinned source path and search route anchor",
    },
]

SOURCE_OBSERVATIONS = [
    {
        "id": "search-route-present",
        "path": "hermes_cli/web_routers/sessions.py",
        "anchor": "@search_router.get(\"/api/sessions/search\")",
        "observation": "The pinned Dashboard exposes the authenticated session search route recorded by C-01.",
        "contract_relevance": "This fixture models that approved route offline and does not widen the route allowlist.",
    },
    {
        "id": "empty-query-strip-only",
        "path": "hermes_cli/web_routers/sessions.py",
        "anchor": "if not q or not q.strip():",
        "observation": "The pinned route treats a missing or Unicode-whitespace-only query as an empty result.",
        "contract_relevance": "Whitespace stripping is used only to classify an empty query; nonempty query text is otherwise preserved.",
    },
    {
        "id": "raw-id-query",
        "path": "hermes_cli/web_routers/sessions.py",
        "anchor": "db.search_sessions_by_id(q",
        "observation": "The pinned route passes the original query to the session-id helper before FTS preparation.",
        "contract_relevance": "Exact opaque ID lookup does not trim, lowercase, decode, or accept prefixes.",
    },
    {
        "id": "bounded-source-limit",
        "path": "hermes_cli/web_routers/sessions.py",
        "anchor": "safe_limit = max(1, min(int(limit or 20), 100))",
        "observation": "The pinned route bounds its effective helper limit but defines no cursor.",
        "contract_relevance": "Hermternal accepts only explicit integer page sizes in its narrower offline contract and defines a query-bound opaque cursor.",
    },
    {
        "id": "no-source-total-order",
        "path": "hermes_cli/web_routers/sessions.py",
        "anchor": "results = list(seen.values())[:safe_limit]",
        "observation": "The pinned route combines helper insertion order without an explicit total ordering or tie-breaker.",
        "contract_relevance": "Hermternal applies a deterministic metadata order before pagination and does not claim the order is upstream behavior.",
    },
]

RULES = {
    "query": {
        "modes": ["exact_id", "literal_text"],
        "empty": "missing_or_unicode_strip_empty_returns_empty",
        "normalization": "none_after_empty_classification",
        "literal_matching": "case_sensitive_unicode_scalar_subsequence",
        "maximum_utf8_bytes": MAX_QUERY_BYTES,
        "controls": "rejected",
    },
    "identity": {
        "session_id": "full_opaque_ascii_segment",
        "exact_lookup": "exact_code_unit_equality_only",
        "prefix_suffix_casefold_decode": "forbidden",
    },
    "ordering": {
        "primary": "updated_ms_descending",
        "tie_breaker": "session_id_ascii_ascending",
        "stable": True,
    },
    "pagination": {
        "page_size": "integer_1_through_50",
        "cursor": "opaque_query_mode_snapshot_and_last_row_binding",
        "total_count": "not_exposed",
        "snapshot_change": "invalid_cursor",
    },
    "privacy": {
        "unavailable_deleted_unauthorized": "same_absent_result_without_disclosure",
        "result_fields": ["session_id"],
        "redacted_metadata": "never_exposed",
        "local_transcript_mirror": False,
    },
    "recovery": {
        "interrupted_before_response": "no_cursor_advance_safe_same_request_retry",
        "unknown_response": "reconcile_before_same_request_retry",
        "automatic_retry": False,
        "repeatability": "same_snapshot_query_mode_limit_cursor_same_bytes",
    },
    "boundary": {
        "synthetic_only": True,
        "live_calls": False,
        "database_reads": False,
        "transcript_storage": False,
    },
}

REDACTION = {
    "synthetic_only": True,
    "contains_credentials": False,
    "contains_cookies": False,
    "contains_tickets": False,
    "contains_prompts": False,
    "contains_transcripts": False,
    "contains_message_content": False,
    "contains_hosts": False,
    "contains_user_data": False,
    "diagnostic_policy": "fixed controlled codes; no raw values, paths, payloads, counts, or existence details",
}

SESSION_A = "session-alpha-0000000000000001"
SESSION_B = "session-beta-0000000000000002"
SESSION_C = "session-gamma-0000000000000003"
SESSION_D = "session-delta-0000000000000004"
SESSION_HIDDEN = "session-hidden-0000000000000005"
SNAPSHOT = "snapshot-0000000000000001"
OTHER_SNAPSHOT = "snapshot-0000000000000002"


class ContractError(ValueError):
    """A controlled failure whose message never contains fixture input."""


def _require(condition: bool) -> None:
    if not condition:
        raise ContractError(ERROR_MESSAGE)


def _strict_type(value: Any, expected: type) -> bool:
    return type(value) is expected


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(ERROR_MESSAGE)
        result[key] = value
    return result


def _parse_int(raw: str) -> int:
    if len(raw.lstrip("-+")) > MAX_INTEGER_DIGITS:
        raise ContractError(ERROR_MESSAGE)
    return int(raw)


def _parse_float(raw: str) -> float:
    value = float(raw)
    if not math.isfinite(value):
        raise ContractError(ERROR_MESSAGE)
    return value


def _reject_constant(_raw: str) -> Any:
    raise ContractError(ERROR_MESSAGE)


def _check_bounds(root: Any) -> None:
    """Bound JSON iteratively so hostile depth cannot consume Python recursion."""
    stack: list[tuple[Any, int]] = [(root, 0)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        _require(nodes <= MAX_NODES and depth <= MAX_DEPTH)
        if type(value) is str:
            _require(len(value) <= MAX_STRING_CHARS)
        elif type(value) is list:
            _require(len(value) <= MAX_ARRAY_ITEMS)
            stack.extend((item, depth + 1) for item in value)
        elif type(value) is dict:
            _require(len(value) <= MAX_OBJECT_KEYS)
            for key, item in value.items():
                _require(type(key) is str and len(key) <= MAX_STRING_CHARS)
                stack.append((item, depth + 1))
        else:
            _require(value is None or type(value) in (bool, int, float))
            if type(value) is float:
                _require(math.isfinite(value))


def _load_json(path: Path) -> Any:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ContractError(ERROR_MESSAGE) from exc
    _require(len(raw) <= MAX_FILE_BYTES)
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_int=_parse_int,
            parse_float=_parse_float,
            parse_constant=_reject_constant,
        )
    except ContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, OverflowError, TypeError, ValueError) as exc:
        raise ContractError(ERROR_MESSAGE) from exc
    _check_bounds(value)
    return value


def _sha256(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ContractError(ERROR_MESSAGE) from exc
    _require(len(raw) <= MAX_FILE_BYTES)
    return hashlib.sha256(raw).hexdigest()


def _validate_dependencies() -> None:
    """Verify consumed contracts, not only their declarations in cases.json."""
    repository = REPOSITORY_ROOT.resolve()
    for dependency in DEPENDENCIES:
        _require(tuple(dependency.keys()) == ("path", "sha256", "use"))
        relative = Path(dependency["path"])
        _require(not relative.is_absolute() and ".." not in relative.parts)
        candidate = (repository / relative).resolve()
        try:
            candidate.relative_to(repository)
        except ValueError as exc:
            raise ContractError(ERROR_MESSAGE) from exc
        _require(candidate.is_file() and _sha256(candidate) == dependency["sha256"])


def _canonical_validator_sha256(path: Path | None = None) -> str:
    source = (path or Path(__file__)).read_text(encoding="utf-8")
    begin = source.index("# BEGIN REVIEWED TRUST ANCHORS")
    end = source.index("# END REVIEWED TRUST ANCHORS")
    block = source[begin:end]
    block = re.sub(r'"[0-9a-f]{64}"', '"' + ("0" * 64) + '"', block)
    normalized = source[:begin] + block + source[end:]
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _opaque_id(value: Any) -> bool:
    return type(value) is str and 16 <= len(value) <= 128 and OPAQUE_ID.fullmatch(value) is not None


def _query_digest(mode: str, query: str, snapshot: str) -> str:
    payload = json.dumps([mode, query, snapshot], ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def _cursor(mode: str, query: str, snapshot: str, updated_ms: int, session_id: str) -> str:
    return f"c1.{_query_digest(mode, query, snapshot)}.{updated_ms}.{session_id}"


def _catalog(*rows: dict[str, Any]) -> list[dict[str, Any]]:
    return list(rows)


def _row(
    session_id: str,
    title_key: str,
    updated_ms: int,
    *,
    available: bool = True,
    deleted: bool = False,
    authorized: bool = True,
    redacted: bool = False,
) -> dict[str, Any]:
    return {
        "session_id": session_id,
        "title_key": title_key,
        "updated_ms": updated_ms,
        "available": available,
        "deleted": deleted,
        "authorized": authorized,
        "redacted": redacted,
    }


def _request(
    query: Any,
    *,
    mode: Any = "literal_text",
    limit: Any = 20,
    cursor: Any = None,
    snapshot: Any = SNAPSHOT,
    backend: Any = "available",
    interruption: Any = "none",
    retry: Any = "fresh",
) -> dict[str, Any]:
    return {
        "query": query,
        "mode": mode,
        "limit": limit,
        "cursor": cursor,
        "snapshot": snapshot,
        "backend": backend,
        "interruption": interruption,
        "retry": retry,
    }


def _error(code: str, recovery: str) -> dict[str, Any]:
    return {
        "decision": "error",
        "results": [],
        "next_cursor": None,
        "error": {"code": code, "message": "Search unavailable"},
        "recovery": recovery,
        "transcript_mirror": False,
    }


def _execute(request: dict[str, Any], catalog: list[dict[str, Any]]) -> dict[str, Any]:
    required = ("query", "mode", "limit", "cursor", "snapshot", "backend", "interruption", "retry")
    if type(request) is not dict or tuple(request.keys()) != required:
        return _error("malformed_request", "correct_request")
    query = request["query"]
    mode = request["mode"]
    limit = request["limit"]
    cursor = request["cursor"]
    snapshot = request["snapshot"]
    backend = request["backend"]
    interruption = request["interruption"]
    retry = request["retry"]

    if type(query) is not str or type(mode) is not str or type(snapshot) is not str:
        return _error("malformed_request", "correct_request")
    if type(limit) is not int or type(limit) is bool or not 1 <= limit <= MAX_PAGE_SIZE:
        return _error("invalid_page_size", "correct_request")
    if cursor is not None and type(cursor) is not str:
        return _error("invalid_cursor", "restart_search")
    if backend not in ("available", "unavailable") or interruption not in (
        "none",
        "before_response",
        "unknown_response",
    ) or retry not in ("fresh", "same_request", "reconcile_then_same_request"):
        return _error("malformed_request", "correct_request")
    if len(query.encode("utf-8")) > MAX_QUERY_BYTES:
        return _error("invalid_query", "correct_request")
    # The pinned route classifies strip-empty input before FTS parsing. Preserve
    # that one source-backed normalization even when the whitespace is a control.
    query_is_empty = not query or not query.strip()
    if not query_is_empty and CONTROL_RE.search(query):
        return _error("invalid_query", "correct_request")
    if mode not in ("exact_id", "literal_text"):
        return _error("invalid_query", "correct_request")
    if not _opaque_id(snapshot):
        return _error("malformed_request", "correct_request")
    if backend == "unavailable":
        return _error("search_unavailable", "explicit_retry")
    if interruption == "before_response":
        return _error("interrupted", "same_request_retry")
    if interruption == "unknown_response" and retry != "reconcile_then_same_request":
        code = "delivery_uncertain" if retry == "fresh" else "retry_blocked"
        return _error(code, "reconcile_then_same_request")

    # Pinned source backs only the empty classification. Nonempty text is not
    # trimmed, case-folded, tokenized, decoded, or locale-normalized here.
    if not query or not query.strip():
        return {
            "decision": "empty",
            "results": [],
            "next_cursor": None,
            "error": None,
            "recovery": "none",
            "transcript_mirror": False,
        }
    if mode == "exact_id" and not _opaque_id(query):
        return {
            "decision": "no_results",
            "results": [],
            "next_cursor": None,
            "error": None,
            "recovery": "none",
            "transcript_mirror": False,
        }

    visible: list[dict[str, Any]] = []
    for row in catalog:
        if not row["available"] or row["deleted"] or not row["authorized"]:
            continue
        matched = query == row["session_id"] if mode == "exact_id" else (not row["redacted"] and query in row["title_key"])
        if matched:
            visible.append(row)
    visible.sort(key=lambda item: (-item["updated_ms"], item["session_id"].encode("ascii")))

    start = 0
    if cursor is not None:
        if len(cursor.encode("utf-8")) > MAX_CURSOR_BYTES or CURSOR_RE.fullmatch(cursor) is None:
            return _error("invalid_cursor", "restart_search")
        parts = cursor.split(".", 3)
        if parts[1] != _query_digest(mode, query, snapshot):
            return _error("invalid_cursor", "restart_search")
        marker = (int(parts[2]), parts[3])
        for index, row in enumerate(visible):
            if (row["updated_ms"], row["session_id"]) == marker:
                start = index + 1
                break
        else:
            return _error("invalid_cursor", "restart_search")

    page = visible[start : start + limit]
    next_cursor = None
    if start + limit < len(visible):
        last = page[-1]
        next_cursor = _cursor(mode, query, snapshot, last["updated_ms"], last["session_id"])
    return {
        "decision": "results" if page else "no_results",
        "results": [{"session_id": row["session_id"]} for row in page],
        "next_cursor": next_cursor,
        "error": None,
        "recovery": "none",
        "transcript_mirror": False,
    }


def _canonical_cases() -> list[dict[str, Any]]:
    alpha = _row(SESSION_A, "project atlas", 300)
    beta = _row(SESSION_B, "project atlas beta", 200)
    gamma = _row(SESSION_C, "Project Atlas", 200)
    delta = _row(SESSION_D, "東京 設計", 100)
    hidden_deleted = _row(SESSION_HIDDEN, "project atlas", 400, deleted=True)
    hidden_denied = _row(SESSION_HIDDEN, "project atlas", 400, authorized=False)
    hidden_unavailable = _row(SESSION_HIDDEN, "project atlas", 400, available=False)
    hidden_redacted = _row(SESSION_HIDDEN, "project atlas", 400, redacted=True)
    atlas = _catalog(alpha, beta, gamma, delta)
    first_cursor = _cursor("literal_text", "project", SNAPSHOT, alpha["updated_ms"], alpha["session_id"])
    beta_cursor = _cursor("literal_text", "project", SNAPSHOT, beta["updated_ms"], beta["session_id"])

    definitions: list[tuple[str, dict[str, Any], list[dict[str, Any]], str]] = [
        ("empty-query", _request(""), atlas, "Missing text returns the empty state."),
        ("whitespace-only-query", _request(" \t\n"), atlas, "Only source-backed strip-empty classification is applied."),
        ("no-result", _request("absent"), atlas, "No match is a successful empty result."),
        ("exact-opaque-id", _request(SESSION_A, mode="exact_id"), atlas, "A complete opaque ID matches exactly."),
        ("exact-id-prefix-rejected", _request(SESSION_A[:-1], mode="exact_id"), atlas, "Prefixes never identify a session."),
        ("exact-id-case-sensitive", _request(SESSION_A.upper(), mode="exact_id"), atlas, "Opaque IDs are not case-folded."),
        ("exact-id-leading-space-not-trimmed", _request(" " + SESSION_A, mode="exact_id"), atlas, "Nonempty exact-ID queries preserve whitespace."),
        ("literal-exact-subsequence", _request("atlas"), atlas, "Literal search is a code-point subsequence match."),
        ("literal-case-sensitive", _request("Atlas"), atlas, "Literal search is language-neutral and case-sensitive."),
        ("unicode-literal-language-neutral", _request("東京"), atlas, "Unicode text is preserved without stemming or locale rules."),
        ("newest-first-order", _request("project"), atlas, "Results order by descending update marker."),
        ("session-id-tie-break", _request("Atlas"), _catalog(gamma, _row(SESSION_B, "Project Atlas", 200)), "ASCII session ID is the stable tie-breaker."),
        ("first-page-with-cursor", _request("project", limit=1), atlas, "A partial page returns an opaque bound cursor."),
        ("second-page-from-cursor", _request("project", limit=1, cursor=first_cursor), atlas, "The cursor resumes strictly after its last row."),
        ("final-page-clears-cursor", _request("project", limit=2, cursor=first_cursor), atlas, "The final page has no continuation cursor."),
        ("cursor-query-mismatch", _request("atlas", limit=1, cursor=first_cursor), atlas, "A cursor cannot be replayed with another query."),
        ("cursor-snapshot-mismatch", _request("project", limit=1, cursor=first_cursor, snapshot=OTHER_SNAPSHOT), atlas, "A cursor cannot cross snapshots."),
        ("cursor-mode-mismatch", _request(SESSION_A, mode="exact_id", limit=1, cursor=first_cursor), atlas, "A cursor cannot cross search modes."),
        ("cursor-marker-missing", _request("project", limit=1, cursor=beta_cursor), _catalog(alpha), "A stale marker fails closed."),
        ("malformed-cursor", _request("project", cursor="not-a-cursor"), atlas, "Malformed cursors are controlled errors."),
        ("oversized-cursor", _request("project", cursor="c" * (MAX_CURSOR_BYTES + 1)), atlas, "Cursor bytes are bounded."),
        ("zero-page-size", _request("project", limit=0), atlas, "Falsey limits are rejected rather than rewritten."),
        ("oversized-page-size", _request("project", limit=MAX_PAGE_SIZE + 1), atlas, "Page sizes above the contract bound fail."),
        ("boolean-page-size", _request("project", limit=True), atlas, "JSON booleans are not integers."),
        ("malformed-query-control", _request("atlas" + chr(0) + ""), atlas, "Control-bearing queries fail closed."),
        ("oversized-query", _request("é" * 129), atlas, "The UTF-8 byte bound is enforced, not a character count."),
        ("invalid-mode", _request("atlas", mode="folded_text"), atlas, "Unapproved normalization modes fail closed."),
        ("deleted-session-nondisclosure", _request(SESSION_HIDDEN, mode="exact_id"), _catalog(hidden_deleted), "Deleted and absent identities are indistinguishable."),
        ("unauthorized-session-nondisclosure", _request(SESSION_HIDDEN, mode="exact_id"), _catalog(hidden_denied), "Unauthorized and absent identities are indistinguishable."),
        ("unavailable-session-nondisclosure", _request(SESSION_HIDDEN, mode="exact_id"), _catalog(hidden_unavailable), "Unavailable and absent identities are indistinguishable."),
        ("mixed-hidden-visible", _request("project"), _catalog(hidden_deleted, hidden_denied, hidden_unavailable, alpha), "Hidden rows do not affect visible ordering or counts."),
        ("redacted-metadata-not-searchable", _request("project"), _catalog(hidden_redacted), "Redacted metadata cannot become a text oracle."),
        ("redacted-exact-id-only", _request(SESSION_HIDDEN, mode="exact_id"), _catalog(hidden_redacted), "Exact authorized identity lookup returns only the opaque ID."),
        ("backend-unavailable", _request("project", backend="unavailable"), atlas, "Backend failure uses one controlled error."),
        ("interrupted-before-response", _request("project", interruption="before_response"), atlas, "No cursor advances before a known response."),
        ("interrupted-safe-retry", _request("project", interruption="none", retry="same_request"), atlas, "The same request can be retried after known pre-response interruption."),
        ("unknown-response", _request("project", interruption="unknown_response"), atlas, "Unknown delivery requires reconciliation."),
        ("unknown-response-direct-retry-blocked", _request("project", interruption="unknown_response", retry="same_request"), atlas, "Automatic retry after an unknown response is blocked."),
        ("unknown-response-reconciled-retry", _request("project", interruption="unknown_response", retry="reconcile_then_same_request"), atlas, "Reconciliation permits the same idempotent read."),
        ("stable-repeatability", _request("project", limit=2), atlas, "The same snapshot and request produce byte-identical output."),
    ]
    cases = []
    for case_id, request, catalog, notes in definitions:
        cases.append({"id": case_id, "request": request, "catalog": catalog, "expected": _execute(request, catalog), "notes": notes})
    return cases


def _document() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "operation": OPERATION,
        "contract": CONTRACT,
        "hermes_source_sha": SOURCE_SHA,
        "synthetic_only": True,
        "surface": "shared-web-apple",
        "dependencies": DEPENDENCIES,
        "source_observations": SOURCE_OBSERVATIONS,
        "rules": RULES,
        "cases": _canonical_cases(),
        "redaction": REDACTION,
    }


def _strict_equal(actual: Any, expected: Any) -> None:
    _require(type(actual) is type(expected))
    if type(expected) is dict:
        _require(tuple(actual.keys()) == tuple(expected.keys()))
        for key in expected:
            _strict_equal(actual[key], expected[key])
    elif type(expected) is list:
        _require(len(actual) == len(expected))
        for left, right in zip(actual, expected):
            _strict_equal(left, right)
    else:
        _require(actual == expected)


def _validate_redaction(root: Any) -> None:
    declared_boundary_keys = {
        "local_transcript_mirror",
        "transcript_mirror",
        "transcript_storage",
        "redacted_metadata",
    }
    stack = [root]
    while stack:
        value = stack.pop()
        if type(value) is dict:
            for key, item in value.items():
                # Controlled boolean boundary declarations are allowed. They
                # describe prohibited storage and never carry payload content.
                if not key.startswith("contains_") and key not in declared_boundary_keys:
                    _require(SENSITIVE_KEY_RE.search(key) is None)
                stack.append(item)
        elif type(value) is list:
            stack.extend(value)
        elif type(value) is str:
            _require(SENSITIVE_VALUE_RE.search(value) is None)


def validate_document(document: Any) -> int:
    expected = _document()
    _strict_equal(document, expected)
    _validate_redaction(document)
    ids = [case["id"] for case in document["cases"]]
    _require(len(ids) == len(set(ids)) and len(ids) >= 30)
    for case in document["cases"]:
        _strict_equal(_execute(case["request"], case["catalog"]), case["expected"])
        for row in case["catalog"]:
            _require(tuple(row.keys()) == ("session_id", "title_key", "updated_ms", "available", "deleted", "authorized", "redacted"))
            _require(_opaque_id(row["session_id"]))
            _require(type(row["title_key"]) is str and type(row["updated_ms"]) is int and type(row["updated_ms"]) is not bool)
            _require(all(type(row[key]) is bool for key in ("available", "deleted", "authorized", "redacted")))
    return len(ids)


def _distribution(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    p95_index = math.ceil(0.95 * len(ordered)) - 1
    return {
        "min": round(min(samples), 6),
        "p50": round(statistics.median(samples), 6),
        "p95": round(ordered[p95_index], 6),
        "max": round(max(samples), 6),
        "mean": round(statistics.fmean(samples), 6),
    }


def validate_baseline(baseline: Any) -> int:
    _require(type(baseline) is dict)
    expected_keys = (
        "schema", "validator", "command", "build_mode", "artifact_files", "artifact_bytes",
        "environment", "repetitions", "normal", "optimized", "threshold",
    )
    _require(tuple(baseline.keys()) == expected_keys)
    _require(baseline["schema"] == BASELINE_SCHEMA)
    _require(baseline["validator"] == "contracts/fixtures/session-search/validate.py")
    _require(baseline["command"] == APPROVED_COMMANDS["normal"] and baseline["build_mode"] == "N/A")
    _require(type(baseline["artifact_files"]) is list and len(baseline["artifact_files"]) == len(BASELINE_ARTIFACTS))
    artifact_bytes = 0
    for name, item in zip(BASELINE_ARTIFACTS, baseline["artifact_files"]):
        _require(type(item) is dict and tuple(item.keys()) == ("path", "sha256", "size_bytes"))
        _require(item["path"] == name and type(item["sha256"]) is str and len(item["sha256"]) == 64)
        _require(type(item["size_bytes"]) is int and type(item["size_bytes"]) is not bool and item["size_bytes"] > 0)
        path = ROOT / name
        expected_sha = _canonical_validator_sha256(path) if name == "validate.py" else _sha256(path)
        _require(item["sha256"] == expected_sha and item["size_bytes"] == len(path.read_bytes()))
        artifact_bytes += item["size_bytes"]
    _require(baseline["artifact_bytes"] == artifact_bytes)
    _require(type(baseline["environment"]) is dict and tuple(baseline["environment"].keys()) == ("platform", "python"))
    _require(all(type(value) is str and value for value in baseline["environment"].values()))
    _require(baseline["repetitions"] == BASELINE_REPETITIONS and baseline["threshold"] is None)
    evidence = _load_json(EVIDENCE_PATH)
    _require(type(evidence) is dict and tuple(evidence.keys()) == ("schema", "normal", "optimized"))
    _require(evidence["schema"] == EVIDENCE_SCHEMA)
    for mode in ("normal", "optimized"):
        item = baseline[mode]
        evidence_item = evidence[mode]
        _require(type(item) is dict and tuple(item.keys()) == ("command", "samples_ms", "distribution"))
        _require(type(evidence_item) is dict and tuple(evidence_item.keys()) == ("samples_ms", "distribution"))
        _require(item["command"] == APPROVED_COMMANDS[mode])
        samples = item["samples_ms"]
        _require(type(samples) is list and len(samples) == BASELINE_REPETITIONS)
        _require(all(type(sample) is float and math.isfinite(sample) and sample > 0 for sample in samples))
        _strict_equal(samples, evidence_item["samples_ms"])
        _strict_equal(item["distribution"], _distribution(samples))
        _strict_equal(item["distribution"], evidence_item["distribution"])
    return artifact_bytes


def validate_all(document: Any, baseline: Any, *, verify_trust: bool = True) -> tuple[int, int]:
    if verify_trust:
        _require(_canonical_validator_sha256() == REVIEWED_VALIDATOR_CANONICAL_SHA256)
        _require(_sha256(BASELINE_PATH) == REVIEWED_BASELINE_SHA256)
        for name, digest in REVIEWED_ARTIFACT_SHA256.items():
            _require(_sha256(ROOT / name) == digest)
    _validate_dependencies()
    return validate_document(document), validate_baseline(baseline)


def _emit_cases() -> None:
    print(json.dumps(_document(), ensure_ascii=False, indent=2) + "\n", end="")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--cases", default=str(CASES_PATH))
    parser.add_argument("--baseline", default=str(BASELINE_PATH))
    parser.add_argument("--emit-cases", action="store_true")
    try:
        args = parser.parse_args(argv)
        if args.emit_cases:
            _emit_cases()
            return 0
        document = _load_json(Path(args.cases))
        baseline = _load_json(Path(args.baseline))
        case_count, artifact_bytes = validate_all(document, baseline)
        print(f"{SUCCESS_PREFIX}: cases={case_count} artifacts={artifact_bytes}")
        return 0
    except (ContractError, OSError, UnicodeError, ValueError, TypeError, OverflowError, RecursionError):
        print(json.dumps({"error": {"code": "contract", "message": ERROR_MESSAGE}}, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
