#!/usr/bin/env python3
"""Validate the synthetic C-08 chat stream and completion fixture offline.

The reducer models ordering and correlation only. It never opens Hermes, replays
prompt content, or interprets tool payloads. Fail-closed results discard retained
synthetic segments so malformed ordering cannot become display state.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import statistics
import sys
from typing import Any

ROOT = Path(__file__).resolve().parent
CASES_PATH = ROOT / "cases.json"
SOURCE_AUDIT_PATH = ROOT / "source-audit.json"
BASELINE_PATH = ROOT / "validation-baseline.json"
SCHEMA = "hermternal.chat-stream-completion.v1"
SOURCE_AUDIT_SCHEMA = "hermternal.source-audit.chat-stream-completion.v1"
BASELINE_SCHEMA = "hermternal.chat-stream-completion-baseline.v1"
OPERATION = "C-08"
CONTRACT = "dashboard-v0.0.1"
HERMES_SOURCE_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
HERMES_TREE_SHA = "886db5eb1150f819344d67fedc81aef0caab09ff"
CASES_SHA256 = "7b19df2b8ad000f94f7521da12f30a0d013683f799244c470ae539cea8cae384"
SOURCE_AUDIT_SHA256 = "a4722049299599c6fefb42047d05f0304eeccc473d6066bb3d0492e8d2c7ff61"
BASELINE_CANONICAL_IDENTITY_SHA256 = "32f1e1043b13b2b68c905ecd5aca488b1ec796d031d9c8044773ad33a5740e46"

MAX_JSON_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 4096
MAX_OBJECT_KEYS = 64
MAX_ARRAY_LENGTH = 256
MAX_STRING_LENGTH = 16 * 1024
MAX_INTEGER_DIGITS = 4096
BASELINE_REPETITIONS = 30
REVIEWED_BASELINE_PLATFORM = "macOS-26.5.2-arm64-arm-64bit-Mach-O"
REVIEWED_BASELINE_PYTHON = "3.14.6"
APPROVED_BASELINE_COMMAND = "python3 contracts/fixtures/chat-stream-completion/validate.py"
APPROVED_BENCHMARK_COMMANDS = {
    "normal": APPROVED_BASELINE_COMMAND,
    "optimized": "python3 -O contracts/fixtures/chat-stream-completion/validate.py",
}
BASELINE_ARTIFACTS = ("README.md", "cases.json", "source-audit.json", "validate.py", "test_validate.py")

ROOT_KEYS = ("schema", "operation", "contract", "hermes_source_sha", "synthetic_only", "event_order", "cases", "redaction", "accessibility")
CASE_KEYS = ("id", "initial_state", "session_ref", "request_ref", "turn_ref", "events", "expected", "notes")
EXPECTED_KEYS = ("trace", "final_state", "segments", "open_tool", "completed_tools", "completion_status", "interrupted", "recoverable", "ignored_events", "decision", "contract_error")
REDACTION_KEYS = ("contains_prompt_text", "contains_transcript", "contains_tool_arguments", "contains_tool_results", "contains_credentials", "contains_hosts", "contains_user_data", "diagnostic_max_chars")
ACCESSIBILITY_KEYS = ("applicable", "reason")
SOURCE_ROOT_KEYS = ("schema", "operation", "contract", "hermes_repository", "hermes_source_sha", "hermes_tree_sha", "synthetic_only", "citations", "redaction")
CITATION_KEYS = ("id", "path", "lines", "sha256", "git_blob_sha", "markers", "claim")
SOURCE_REDACTION_KEYS = ("contains_prompt_text", "contains_transcript", "contains_tool_arguments", "contains_tool_results", "contains_credentials", "contains_hosts", "contains_user_data")
BASELINE_KEYS = ("schema", "validator", "command", "build_mode", "artifact_files", "artifact_bytes", "environment", "repetitions", "normal", "optimized", "threshold")
BASELINE_IDENTITY_KEYS = ("schema", "validator", "command", "build_mode", "environment", "repetitions", "normal", "optimized", "threshold")
BENCHMARK_KEYS = ("command", "samples_ms", "distribution")
DISTRIBUTION_KEYS = ("min", "p50", "p95", "max", "mean")
ARTIFACT_KEYS = ("path", "sha256", "size_bytes")
EVENT_ORDER = ("message.delta", "reasoning.delta", "thinking.delta", "tool.start", "tool.complete", "message.complete", "error", "interrupt.request", "interrupt.result")
TERMINAL_STATES = {"completed", "failed", "interrupted"}
EXPECTED_CASE_IDS = (
    "empty-idle", "delta-then-complete", "reasoning-thinking-message-complete", "tool-lifecycle-complete",
    "two-tools-ordered", "terminal-recoverable-error", "gateway-error-terminal", "interrupt-after-delta",
    "interrupt-abandons-open-tool", "interrupt-rejected-resumes", "unknown-additive-ignored",
    "late-delta-after-complete", "duplicate-completion", "ordinal-gap", "tool-complete-without-start",
    "overlapping-tool-start", "complete-with-open-tool", "wrong-session-frame", "wrong-request-frame",
    "wrong-turn-frame", "unknown-interactive-blocked", "interrupt-result-without-request",
)
SOURCE_IDENTITIES = (
    ("stream-buffer-order", "tui_gateway/ws.py", [50, 58], "2b1c772cb37c77a756325e4c298f6a5ee8947d6566cd7638f06f7a0421b8b5fd", "073c4ac1497c7a266209169176ebfff673ecbbcb"),
    ("stream-and-terminal-emission", "tui_gateway/server.py", [5292, 5363, 7580, 7612, 9600, 9856], "e4bd9009827ffd224cc85c8b17ad7baba0f560d643d688e265be5a06fe8ba29c", "9d5fd00ce7d0becfd4581a5a3867c516a6d3b20a"),
    ("interrupt-turn-boundary", "tui_gateway/methods_session.py", [2750, 2821], "1e70561f7c5ca08556e26216f9f6a553bbf25e4c8de3368ac9cb9634e57ea34e", "1a3e09f16e49c5c75a42ca94e4fbfd8f36c290f0"),
)


class ContractError(ValueError):
    """Raised when checked-in evidence violates the closed contract."""


def _require(condition: bool, message: str = "contract validation failed") -> None:
    if not condition:
        raise ContractError(message)


def _strict_keys(value: Any, keys: tuple[str, ...], label: str) -> dict[str, Any]:
    _require(type(value) is dict and tuple(value.keys()) == keys, f"{label} shape changed")
    return value


def _strict_equal(actual: Any, expected: Any, label: str) -> None:
    _require(type(actual) is type(expected), f"{label} type changed")
    if type(expected) is dict:
        _require(tuple(actual.keys()) == tuple(expected.keys()), f"{label} shape changed")
        for key in expected:
            _strict_equal(actual[key], expected[key], f"{label}.{key}")
    elif type(expected) is list:
        _require(len(actual) == len(expected), f"{label} length changed")
        for index, (left, right) in enumerate(zip(actual, expected)):
            _strict_equal(left, right, f"{label}[{index}]")
    else:
        _require(actual == expected, f"{label} value changed")


def _reject_constant(_: str) -> None:
    raise ContractError("non-finite JSON number is not allowed")


def _parse_int(raw: str) -> int:
    _require(len(raw.lstrip("-")) <= MAX_INTEGER_DIGITS, "JSON integer digit limit exceeded")
    return int(raw)


def _parse_float(raw: str) -> float:
    try:
        decimal_value = Decimal(raw)
        value = float(raw)
    except (InvalidOperation, ValueError, OverflowError) as exc:
        raise ContractError("invalid JSON number") from exc
    _require(math.isfinite(value), "non-finite JSON number is not allowed")
    # A syntactically nonzero decimal that rounds to zero is an underflow attack,
    # not benchmark evidence. Reject it identically in normal and -O modes.
    _require(not (decimal_value != 0 and value == 0.0), "underflow JSON number is not allowed")
    return value


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON object key is not allowed")
        result[key] = value
    return result


def _validate_shape(value: Any, depth: int = 0) -> int:
    _require(depth <= MAX_JSON_DEPTH, "JSON nesting exceeds the bounded limit")
    if type(value) is dict:
        _require(len(value) <= MAX_OBJECT_KEYS, "JSON object is too wide")
        nodes = 1
        for key, child in value.items():
            _require(type(key) is str and len(key) <= MAX_STRING_LENGTH, "JSON key changed")
            nodes += _validate_shape(child, depth + 1)
            _require(nodes <= MAX_JSON_NODES, "JSON node count exceeds the bounded limit")
        return nodes
    if type(value) is list:
        _require(len(value) <= MAX_ARRAY_LENGTH, "JSON array is too long")
        nodes = 1
        for child in value:
            nodes += _validate_shape(child, depth + 1)
            _require(nodes <= MAX_JSON_NODES, "JSON node count exceeds the bounded limit")
        return nodes
    if type(value) is str:
        _require(len(value) <= MAX_STRING_LENGTH, "JSON string is too long")
    if type(value) is float:
        _require(math.isfinite(value), "non-finite JSON number is not allowed")
    return 1


def _read_bounded_regular(path: Path, label: str) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise ContractError(f"cannot read {label}") from exc
    try:
        _require(stat.S_ISREG(os.fstat(descriptor).st_mode), f"{label} must be a regular file")
        data = bytearray()
        while len(data) <= MAX_JSON_BYTES:
            chunk = os.read(descriptor, min(8192, MAX_JSON_BYTES - len(data) + 1))
            if not chunk:
                return bytes(data)
            data.extend(chunk)
        raise ContractError(f"{label} exceeds the JSON byte limit")
    finally:
        os.close(descriptor)


def _load_json(path: Path, label: str) -> Any:
    data = _read_bounded_regular(path, label)
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_object_pairs, parse_constant=_reject_constant, parse_int=_parse_int, parse_float=_parse_float)
    except ContractError:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError, OverflowError, RecursionError) as exc:
        raise ContractError(f"invalid strict JSON in {label}") from exc
    _validate_shape(value)
    return value


def _validate_redaction(value: Any) -> None:
    patterns = (
        re.compile(r"\b(?:https?|wss?|ftp)://", re.I),
        re.compile(r"\b(?:bearer|authorization|cookie|password|secret|api[_ -]?key)\s*[:=]", re.I),
        re.compile(r"\b(?:bearer|basic)\s+\S+", re.I),
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
        re.compile(r"\b(?:ghp|github_pat|sk|xox[baprs])[-_][A-Za-z0-9_-]{8,}\b", re.I),
    )
    stack = [value]
    while stack:
        item = stack.pop()
        if type(item) is dict:
            stack.extend(item.keys())
            stack.extend(item.values())
        elif type(item) is list:
            stack.extend(item)
        elif type(item) is str:
            _require("\x00" not in item and "\x1f" not in item, "control character is not allowed")
            _require(not any(pattern.search(item) for pattern in patterns), "redaction boundary changed")


def _event_keys(kind: str, event: dict[str, Any]) -> tuple[str, ...]:
    common = ("kind", "session_ref", "request_ref", "turn_ref")
    if kind in {"message.delta", "reasoning.delta", "thinking.delta"}:
        return common + ("ordinal", "content_ref")
    if kind in {"tool.start", "tool.complete"}:
        return common + ("ordinal", "tool_ref")
    if kind == "message.complete":
        # Completion is a status-tagged union: only error carries recoverability.
        status = event.get("status")
        if status == "complete":
            return common + ("ordinal", "content_ref", "status")
        if status == "error":
            return common + ("ordinal", "content_ref", "status", "recoverable")
        raise ContractError("message.complete status changed")
    if kind == "error":
        return common + ("ordinal", "error_code", "recoverable")
    if kind == "interrupt.request":
        return common
    if kind == "interrupt.result":
        return common + ("status",)
    if kind in {"unknown.additive", "unknown.interactive"}:
        return common + ("ordinal", "name")
    raise ContractError("unsupported event kind")


def _fail_result(trace: list[str], code: str) -> dict[str, Any]:
    if trace[-1] != "failed":
        trace.append("failed")
    return {"trace": trace, "final_state": "failed", "segments": [], "open_tool": None, "completed_tools": [], "completion_status": "none", "interrupted": False, "recoverable": False, "ignored_events": 0, "decision": code, "contract_error": code}


def evaluate_case(case: dict[str, Any]) -> dict[str, Any]:
    """Reduce one already-shaped synthetic case into deterministic display state."""
    state = case["initial_state"]
    trace = [state]
    segments: list[str] = []
    completed_tools: list[str] = []
    open_tool: str | None = None
    expected_ordinal = 1
    ignored = 0
    interrupt_pending = False
    resume_state = state
    completion_status = "none"
    recoverable = False
    decision = "empty" if not case["events"] else "pending"

    def transition(next_state: str) -> None:
        nonlocal state
        state = next_state
        if trace[-1] != state:
            trace.append(state)

    for event in case["events"]:
        kind = event["kind"]
        if state in TERMINAL_STATES:
            return _fail_result(trace, "event_after_terminal")
        if any(event[key] != case[key] for key in ("session_ref", "request_ref", "turn_ref")):
            return _fail_result(trace, "event_not_correlated")
        # While confirmation is pending, only the unnumbered result can settle
        # the turn; accepting any ordinal-bearing frame would resume progress
        # from an unconfirmed interruption boundary.
        if interrupt_pending and "ordinal" in event:
            return _fail_result(trace, "event_while_interrupt_pending")
        if kind not in {"interrupt.request", "interrupt.result"}:
            if type(event.get("ordinal")) is not int or event["ordinal"] != expected_ordinal:
                return _fail_result(trace, "ordinal_not_monotonic")
            expected_ordinal += 1
        if kind in {"message.delta", "reasoning.delta", "thinking.delta"}:
            if interrupt_pending:
                return _fail_result(trace, "event_while_interrupt_pending")
            segments.append(event["content_ref"])
            transition("streaming")
        elif kind == "tool.start":
            if interrupt_pending:
                return _fail_result(trace, "event_while_interrupt_pending")
            if open_tool is not None:
                return _fail_result(trace, "tool_overlap")
            open_tool = event["tool_ref"]
            transition("tool_running")
        elif kind == "tool.complete":
            if open_tool is None or open_tool != event["tool_ref"]:
                return _fail_result(trace, "tool_complete_without_start")
            completed_tools.append(open_tool)
            open_tool = None
            transition("streaming")
        elif kind == "message.complete":
            if open_tool is not None:
                return _fail_result(trace, "completion_with_open_tool")
            segments.append(event["content_ref"])
            completion_status = event["status"]
            if completion_status == "complete":
                decision = "completed"
                transition("completed")
            elif completion_status == "error":
                recoverable = event["recoverable"]
                decision = "recoverable_error" if recoverable else "terminal_error"
                transition("failed")
            else:
                return _fail_result(trace, "unsupported_completion_status")
        elif kind == "error":
            completion_status = "error"
            recoverable = event["recoverable"]
            decision = "gateway_error"
            transition("failed")
        elif kind == "interrupt.request":
            if interrupt_pending:
                return _fail_result(trace, "interrupt_already_pending")
            interrupt_pending = True
            resume_state = state
            transition("interrupting")
        elif kind == "interrupt.result":
            if not interrupt_pending:
                return _fail_result(trace, "interrupt_result_not_pending")
            interrupt_pending = False
            if event["status"] == "interrupted":
                open_tool = None
                decision = "interrupted_confirmed"
                transition("interrupted")
            elif event["status"] == "rejected":
                transition(resume_state)
            else:
                return _fail_result(trace, "unsupported_interrupt_status")
        elif kind == "unknown.additive":
            ignored += 1
        elif kind == "unknown.interactive":
            return _fail_result(trace, "unsupported_interactive_event")
        else:
            return _fail_result(trace, "unsupported_event")
    if interrupt_pending:
        return _fail_result(trace, "interrupt_result_missing")
    return {"trace": trace, "final_state": state, "segments": segments, "open_tool": open_tool, "completed_tools": completed_tools, "completion_status": completion_status, "interrupted": state == "interrupted", "recoverable": recoverable, "ignored_events": ignored, "decision": decision, "contract_error": None}


def validate_document(document: dict[str, Any]) -> None:
    _strict_keys(document, ROOT_KEYS, "document")
    _require(document["schema"] == SCHEMA and document["operation"] == OPERATION and document["contract"] == CONTRACT, "fixture identity changed")
    _require(document["hermes_source_sha"] == HERMES_SOURCE_SHA and document["synthetic_only"] is True, "source binding changed")
    _strict_equal(document["event_order"], list(EVENT_ORDER), "event_order")
    _strict_keys(document["redaction"], REDACTION_KEYS, "redaction")
    _strict_equal(document["redaction"], {"contains_prompt_text": False, "contains_transcript": False, "contains_tool_arguments": False, "contains_tool_results": False, "contains_credentials": False, "contains_hosts": False, "contains_user_data": False, "diagnostic_max_chars": 240}, "redaction")
    _strict_keys(document["accessibility"], ACCESSIBILITY_KEYS, "accessibility")
    _require(document["accessibility"]["applicable"] is False and type(document["accessibility"]["reason"]) is str, "accessibility scope changed")
    cases = document["cases"]
    _require(type(cases) is list and tuple(case.get("id") for case in cases if type(case) is dict) == EXPECTED_CASE_IDS, "case inventory changed")
    for index, case_value in enumerate(cases):
        case = _strict_keys(case_value, CASE_KEYS, f"case[{index}]")
        for key in ("id", "initial_state", "session_ref", "request_ref", "turn_ref", "notes"):
            _require(type(case[key]) is str, f"case[{index}].{key} type changed")
        _require(case["initial_state"] == "idle", "initial state changed")
        _require(type(case["events"]) is list, "events must be an array")
        for event_index, event_value in enumerate(case["events"]):
            _require(type(event_value) is dict and type(event_value.get("kind")) is str, "event shape changed")
            event = _strict_keys(event_value, _event_keys(event_value["kind"], event_value), f"case[{index}].events[{event_index}]")
            for key in ("kind", "session_ref", "request_ref", "turn_ref"):
                _require(type(event[key]) is str, "event scalar type changed")
            if "ordinal" in event:
                _require(type(event["ordinal"]) is int and event["ordinal"] > 0, "event ordinal changed")
            for key in ("content_ref", "tool_ref", "error_code", "name", "status"):
                if key in event:
                    _require(type(event[key]) is str, "event marker type changed")
            if "recoverable" in event:
                _require(type(event["recoverable"]) is bool, "recoverable type changed")
        expected = _strict_keys(case["expected"], EXPECTED_KEYS, f"case[{index}].expected")
        _strict_equal(expected, evaluate_case(case), f"case[{index}].expected")
    _validate_redaction(document)


def validate_source_audit(audit: dict[str, Any]) -> None:
    _strict_keys(audit, SOURCE_ROOT_KEYS, "source audit")
    _require(audit["schema"] == SOURCE_AUDIT_SCHEMA and audit["operation"] == OPERATION and audit["contract"] == CONTRACT, "source audit identity changed")
    _require(audit["hermes_repository"] == "NousResearch/hermes-agent" and audit["hermes_source_sha"] == HERMES_SOURCE_SHA and audit["hermes_tree_sha"] == HERMES_TREE_SHA and audit["synthetic_only"] is True, "source audit binding changed")
    citations = audit["citations"]
    _require(type(citations) is list and len(citations) == len(SOURCE_IDENTITIES), "source citations changed")
    for index, citation_value in enumerate(citations):
        citation = _strict_keys(citation_value, CITATION_KEYS, f"citation[{index}]")
        identity = SOURCE_IDENTITIES[index]
        _strict_equal([citation["id"], citation["path"], citation["lines"], citation["sha256"], citation["git_blob_sha"]], list(identity), f"citation[{index}].identity")
        _require(type(citation["markers"]) is list and citation["markers"] and all(type(marker) is str for marker in citation["markers"]), "source markers changed")
        _require(type(citation["claim"]) is str, "source claim changed")
    _strict_keys(audit["redaction"], SOURCE_REDACTION_KEYS, "source audit redaction")
    _require(all(value is False for value in audit["redaction"].values()), "source audit redaction changed")
    _validate_redaction(audit)


def _dist(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    p95_index = max(0, math.ceil(len(ordered) * 0.95) - 1)
    return {"min": round(ordered[0], 6), "p50": round(statistics.median(ordered), 6), "p95": round(ordered[p95_index], 6), "max": round(ordered[-1], 6), "mean": round(statistics.mean(ordered), 6)}


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def _baseline_identity_digest(baseline: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json_bytes({key: baseline[key] for key in BASELINE_IDENTITY_KEYS})).hexdigest()


def _validate_baseline(baseline: dict[str, Any]) -> int:
    _strict_keys(baseline, BASELINE_KEYS, "baseline")
    _require(baseline["schema"] == BASELINE_SCHEMA and baseline["validator"] == "contracts/fixtures/chat-stream-completion/validate.py", "baseline identity changed")
    _require(baseline["command"] == APPROVED_BASELINE_COMMAND and baseline["build_mode"] == "N/A", "baseline command changed")
    _require(type(baseline["repetitions"]) is int and baseline["repetitions"] == BASELINE_REPETITIONS and baseline["threshold"] is None, "baseline policy changed")
    environment = _strict_keys(baseline["environment"], ("platform", "python"), "baseline.environment")
    _strict_equal(environment, {"platform": REVIEWED_BASELINE_PLATFORM, "python": REVIEWED_BASELINE_PYTHON}, "baseline.environment")
    artifact_bytes = 0
    _require(type(baseline["artifact_files"]) is list and len(baseline["artifact_files"]) == len(BASELINE_ARTIFACTS), "baseline artifact list changed")
    for index, artifact_value in enumerate(baseline["artifact_files"]):
        artifact = _strict_keys(artifact_value, ARTIFACT_KEYS, f"artifact[{index}]")
        _require(artifact["path"] == BASELINE_ARTIFACTS[index] and type(artifact["sha256"]) is str and len(artifact["sha256"]) == 64 and type(artifact["size_bytes"]) is int, "artifact identity changed")
        data = _read_bounded_regular(ROOT / artifact["path"], "artifact")
        _require(hashlib.sha256(data).hexdigest() == artifact["sha256"] and len(data) == artifact["size_bytes"], "artifact bytes changed")
        artifact_bytes += len(data)
    _require(type(baseline["artifact_bytes"]) is int and baseline["artifact_bytes"] == artifact_bytes, "artifact total changed")
    for mode in ("normal", "optimized"):
        benchmark = _strict_keys(baseline[mode], BENCHMARK_KEYS, f"baseline.{mode}")
        _require(benchmark["command"] == APPROVED_BENCHMARK_COMMANDS[mode], "benchmark command changed")
        samples = benchmark["samples_ms"]
        _require(type(samples) is list and len(samples) == BASELINE_REPETITIONS and all(type(sample) is float and math.isfinite(sample) and sample > 0 for sample in samples), "benchmark samples changed")
        _strict_keys(benchmark["distribution"], DISTRIBUTION_KEYS, f"baseline.{mode}.distribution")
        _strict_equal(benchmark["distribution"], _dist(samples), f"baseline.{mode}.distribution")
    _require(_baseline_identity_digest(baseline) == BASELINE_CANONICAL_IDENTITY_SHA256, "baseline canonical identity changed")
    return artifact_bytes


def validate_all(document: dict[str, Any], audit: dict[str, Any], baseline: dict[str, Any]) -> tuple[int, int]:
    validate_document(document)
    validate_source_audit(audit)
    return len(document["cases"]), _validate_baseline(baseline)


def _parse_cli(argv: list[str]) -> tuple[Path, Path, Path]:
    paths = {"--cases": CASES_PATH, "--source-audit": SOURCE_AUDIT_PATH, "--baseline": BASELINE_PATH}
    index = 0
    while index < len(argv):
        _require(argv[index] in paths and index + 1 < len(argv), "unsupported CLI arguments")
        paths[argv[index]] = Path(argv[index + 1])
        index += 2
    return paths["--cases"], paths["--source-audit"], paths["--baseline"]


def _error_line() -> str:
    return json.dumps({"error": {"code": "contract", "message": "chat stream completion fixture rejected"}}, sort_keys=True)


def main(argv: list[str] | None = None) -> int:
    try:
        cases_path, audit_path, baseline_path = _parse_cli(list(sys.argv[1:] if argv is None else argv))
        cases_bytes = _read_bounded_regular(cases_path, "cases")
        audit_bytes = _read_bounded_regular(audit_path, "source audit")
        # Canonical paths are byte-bound. Alternate paths remain useful for
        # adversarial CLI tests but cannot coordinate a semantic rewrite.
        _require(hashlib.sha256(cases_bytes).hexdigest() == CASES_SHA256, "cases bytes changed")
        _require(hashlib.sha256(audit_bytes).hexdigest() == SOURCE_AUDIT_SHA256, "source audit bytes changed")
        document = _load_json(cases_path, "cases")
        audit = _load_json(audit_path, "source audit")
        baseline = _load_json(baseline_path, "baseline")
        _require(type(document) is dict and type(audit) is dict and type(baseline) is dict, "root object changed")
        case_count, artifact_bytes = validate_all(document, audit, baseline)
    except (ContractError, OSError, UnicodeError, TypeError, ValueError, OverflowError, RecursionError):
        print(_error_line())
        return 1
    print(f"chat_stream_completion_validation=ok cases={case_count} artifact_bytes={artifact_bytes}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
