"""Validate the synthetic image attachment lifecycle contract.

This validator models the C-13 images-only boundary without importing Hermes,
opening a file picker, decoding an image, contacting a network service, or
retaining attachment material. Cases use semantic states and synthetic
references only; they never contain data URLs, base64 payloads, paths,
filenames, metadata values, hosts, credentials, prompts, transcripts, or user
data.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import re
import statistics
from typing import Any, Iterable


FIXTURE_DIR = Path(__file__).resolve().parent
CASES_PATH = FIXTURE_DIR / "cases.json"
BASELINE_PATH = FIXTURE_DIR / "baseline.json"
SCHEMA = "hermternal.fixture.image-attachment-lifecycle.v1"
BASELINE_SCHEMA = "hermternal.fixture.image-attachment-lifecycle-baseline.v1"
CONTRACT = "dashboard-v0.0.1"
C13_POLICY_REFERENCE = "attachment-policy-c13-f5be9236"
HERMES_SOURCE_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
MAX_IMAGE_BYTES = 25 * 1024 * 1024
DECLARED_FORMATS = frozenset({"png", "jpeg", "gif", "webp", "bmp"})
DETECTED_FORMATS = frozenset({"png", "jpeg", "gif87a", "gif89a", "webp", "bmp"})
SUPPORTED_FORMATS = DECLARED_FORMATS | DETECTED_FORMATS
MAX_JSON_BYTES = 512 * 1024
MAX_JSON_STRING_CHARS = 64 * 1024
MAX_JSON_ARRAY_ITEMS = 256
MAX_JSON_OBJECT_KEYS = 96
MAX_JSON_INTEGER_DIGITS = 1_024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 4_000
MAX_ERROR_OUTPUT_LENGTH = 240
MAX_PROGRESS_EVENTS = 16

EXPECTED_CASE_IDS = (
    "empty-selection",
    "local-preprocess-metadata-strip",
    "progress-uploading",
    "cancel-before-upload",
    "cancel-after-upload-start",
    "safe-retry-after-state-read",
    "success-transcript-reference",
    "declaration-content-mismatch",
    "malformed-base64",
    "malformed-data-url",
    "unsupported-format",
    "oversized-image",
    "network-interruption-before-upload",
    "network-interruption-after-upload",
    "uncertain-completion-no-duplicate",
    "incompatible-contract",
)

ROOT_KEYS = frozenset(
    {
        "schema",
        "contract",
        "policy_reference",
        "hermes_source_sha",
        "fixture_policy",
        "synthetic_only",
        "limits",
        "redaction",
        "cases",
    }
)
LIMIT_KEYS = frozenset({"max_bytes", "max_progress_events"})
REDACTION_KEYS = frozenset(
    {
        "raw_data_url_retained",
        "base64_retained",
        "paths_retained",
        "filenames_retained",
        "metadata_retained",
        "hosts_retained",
        "credentials_retained",
        "prompts_retained",
        "transcripts_retained",
        "user_data_retained",
    }
)
CASE_KEYS = frozenset({"id", "scenario", "input", "preprocess", "timeline", "progress", "expected", "notes"})
INPUT_KEYS = frozenset(
    {
        "selection",
        "declared_format",
        "detected_format",
        "data_url_state",
        "size_state",
        "metadata_state",
        "transport_state",
        "cancel_point",
        "contract",
        "state_read",
    }
)
PREPROCESS_KEYS = frozenset(
    {"performed", "orientation_normalized", "metadata_removed", "source_bytes_retained"}
)
PROGRESS_KEYS = frozenset({"phase", "percent"})
EXPECTED_KEYS = frozenset(
    {
        "decision",
        "attachment_state",
        "draft",
        "upload_started",
        "upload_attempts",
        "duplicate_uploads",
        "retry",
        "metadata_retained",
        "transcript_reference",
        "diagnostic",
    }
)
BASELINE_ROOT_KEYS = frozenset(
    {"schema", "synthetic_only", "build_mode", "threshold", "artifact_bytes", "artifact_file_count", "normal", "optimized"}
)
BASELINE_MODE_KEYS = frozenset({"repetitions", "samples_ms", "distribution"})
DISTRIBUTION_KEYS = frozenset({"min", "median", "p95", "max"})

SELECTIONS = frozenset({"none", "one_image"})
FORMATS = DECLARED_FORMATS | DETECTED_FORMATS | {"svg", "unknown"}
DATA_URL_STATES = frozenset({"absent", "synthetic_valid", "malformed_base64", "malformed_data_url", "unsupported_format"})
SIZE_STATES = frozenset({"not_applicable", "within_limit", "over_limit"})
METADATA_STATES = frozenset({"absent", "present"})
TRANSPORT_STATES = frozenset(
    {"not_started", "available", "interrupted_before_upload", "interrupted_after_upload_start", "response_lost_after_upload"}
)
CANCEL_POINTS = frozenset({"none", "before_upload_start", "after_upload_start"})
STATE_READS = frozenset({"not_required", "confirmed_no_upload", "required_before_retry"})
TIMELINE_EVENTS = frozenset(
    {
        "selection_empty",
        "selected",
        "preprocess_started",
        "metadata_removed",
        "preprocess_completed",
        "preprocess_interrupted",
        "cancelled_before_upload",
        "upload_started",
        "upload_progress",
        "upload_completed",
        "network_interrupted",
        "response_lost",
        "state_reread",
        "retry_started",
        "cancelled_after_upload_start",
        "rejected",
        "blocked",
        "transcript_reference_recorded",
    }
)
PROGRESS_PHASES = frozenset({"preprocess", "upload"})
DECISIONS = frozenset({"no_attachment", "ready", "pending", "cancelled", "accepted", "accepted_after_retry", "rejected", "interrupted", "unknown", "blocked"})
ATTACHMENT_STATES = frozenset({"empty", "preprocessed", "uploading", "cancelled", "uploaded", "failed", "interrupted", "unknown", "blocked"})
RETRY_POLICIES = frozenset({"none", "wait_or_cancel", "safe_after_state_read", "state_read_before_retry", "no_automatic_retry"})
DIAGNOSTIC_PATTERN = re.compile(r"^attachment\[[a-z0-9_;=.-]+\]$")
REFERENCE_PATTERN = re.compile(r"^synthetic-attachment-ref-[0-9]{3}$")
SCENARIO_PATTERN = re.compile(r"^[a-z0-9-]{3,64}$")
ID_PATTERN = re.compile(r"^[a-z0-9-]{3,64}$")


class ContractError(ValueError):
    """A controlled contract failure with no raw input attached."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def require(condition: bool, code: str) -> None:
    """Keep validation active under both normal and optimized Python."""
    if not condition:
        raise ContractError(code)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate_key")
        result[key] = value
    return result


def _reject_constant(_: str) -> Any:
    raise ContractError("nonfinite_number")


def _parse_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ContractError("nonfinite_number")
    return parsed


def _parse_int(value: str) -> int:
    digits = value.lstrip("-")
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise ContractError("integer_limit")
    return int(value)


def _scan_json_text(text: str) -> None:
    depth = 0
    nodes = 0
    in_string = False
    escaped = False
    string_length = 0
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
                string_length = 0
            else:
                string_length += 1
                if string_length > MAX_JSON_STRING_CHARS:
                    raise ContractError("string_limit")
            continue
        if character == '"':
            in_string = True
            string_length = 0
        elif character in "[{":
            depth += 1
            nodes += 1
            if depth > MAX_JSON_DEPTH:
                raise ContractError("depth_limit")
            if nodes > MAX_JSON_NODES:
                raise ContractError("node_limit")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise ContractError("malformed_json")
    if in_string or escaped or depth != 0:
        raise ContractError("malformed_json")


def _validate_json_tree(value: Any, depth: int = 0, nodes: list[int] | None = None) -> None:
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if nodes[0] > MAX_JSON_NODES:
        raise ContractError("node_limit")
    if depth > MAX_JSON_DEPTH:
        raise ContractError("depth_limit")
    if type(value) is dict:
        if len(value) > MAX_JSON_OBJECT_KEYS:
            raise ContractError("object_limit")
        for key, child in value.items():
            if type(key) is not str:
                raise ContractError("unsupported_type")
            _validate_json_tree(child, depth + 1, nodes)
        return
    if type(value) is list:
        if len(value) > MAX_JSON_ARRAY_ITEMS:
            raise ContractError("array_limit")
        for child in value:
            _validate_json_tree(child, depth + 1, nodes)
        return
    if type(value) is str:
        if len(value) > MAX_JSON_STRING_CHARS:
            raise ContractError("string_limit")
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ContractError("nonfinite_number")
        return
    if value is None or type(value) in (bool, int):
        return
    raise ContractError("unsupported_type")


def load_json(path: Path) -> dict[str, Any]:
    """Read a bounded JSON object through one strict, redaction-safe loader."""
    try:
        if path.stat().st_size > MAX_JSON_BYTES:
            raise ContractError("input_size_limit")
        raw = path.read_bytes()
        if len(raw) > MAX_JSON_BYTES:
            raise ContractError("input_size_limit")
        text = raw.decode("utf-8")
        _scan_json_text(text)
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
            parse_float=_parse_float,
            parse_int=_parse_int,
        )
        if type(value) is not dict:
            raise ContractError("root_type")
        _validate_json_tree(value)
        return value
    except ContractError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError, ValueError, MemoryError) as exc:
        del exc
        raise ContractError("malformed_json") from None


def _normalized_text(value: str) -> str:
    return value.casefold().replace("-", "_").replace(" ", "_")


def _scan_retained_text(value: Any) -> None:
    if type(value) is dict:
        for key, child in value.items():
            normalized = _normalized_text(key)
            require(
                normalized not in {"data_url", "base64_payload", "absolute_path", "filename_value", "host_value", "credential_value", "prompt_text", "transcript_text", "user_data"},
                "forbidden_key",
            )
            _scan_retained_text(child)
        return
    if type(value) is list:
        for child in value:
            _scan_retained_text(child)
        return
    if type(value) is not str:
        return
    lowered = value.casefold()
    require("data:" not in lowered, "raw_data_url")
    require("file://" not in lowered, "raw_path")
    require("http://" not in lowered and "https://" not in lowered, "host_value")
    require("/" not in value and "\\" not in value, "raw_path")
    require("@" not in value, "host_value")
    looks_like_base64 = (
        value != HERMES_SOURCE_SHA
        and len(value) >= 24
        and len(value) % 4 == 0
        and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value) is not None
    )
    require(not looks_like_base64, "raw_base64")
    require(
        re.fullmatch(r"[A-Za-z0-9_-]{1,128}\.(?:png|jpe?g|gif|webp|bmp|svg)", value, re.IGNORECASE) is None,
        "filename_value",
    )
    require(re.fullmatch(r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}", value) is None, "host_value")
    require(not re.search(r"(?:ghp_|sk_live_|Bearer\s+|AKIA[0-9A-Z]{16})", value, re.IGNORECASE), "credential_value")


def _exact_keys(value: Any, expected: frozenset[str], code: str) -> dict[str, Any]:
    require(type(value) is dict, code)
    require(frozenset(value) == expected, code)
    return value


def _exact_int(value: Any, code: str) -> int:
    require(type(value) is int, code)
    return value


def _exact_bool(value: Any, code: str) -> bool:
    require(type(value) is bool, code)
    return value


def _format_agrees(declared: str | None, detected: str | None) -> bool:
    """Match MIME family labels to the C-13 magic-signature families."""
    if declared == "gif":
        return detected in {"gif87a", "gif89a"}
    return declared == detected and declared in DECLARED_FORMATS


def _expected_for_case(case: dict[str, Any]) -> dict[str, Any]:
    input_value = case["input"]
    preprocess = case["preprocess"]
    expected = case["expected"]
    if input_value["contract"] != CONTRACT:
        return {**expected, "decision": "blocked", "attachment_state": "blocked", "upload_started": False, "upload_attempts": 0, "duplicate_uploads": 0, "retry": "none", "transcript_reference": None, "diagnostic": "attachment[blocked;reason=incompatible_contract]"}
    if input_value["selection"] == "none":
        return {**expected, "decision": "no_attachment", "attachment_state": "empty", "upload_started": False, "upload_attempts": 0, "duplicate_uploads": 0, "retry": "none", "transcript_reference": None, "diagnostic": "attachment[empty]"}
    if input_value["cancel_point"] == "before_upload_start":
        return {**expected, "decision": "cancelled", "attachment_state": "cancelled", "upload_started": False, "upload_attempts": 0, "duplicate_uploads": 0, "retry": "none", "transcript_reference": None, "diagnostic": "attachment[cancelled;before_upload]"}
    if input_value["data_url_state"] != "synthetic_valid":
        reason = {
            "malformed_base64": "malformed_base64",
            "malformed_data_url": "malformed_data_url",
            "unsupported_format": "unsupported_format",
        }[input_value["data_url_state"]]
        return {**expected, "decision": "rejected", "attachment_state": "failed", "upload_started": False, "upload_attempts": 0, "duplicate_uploads": 0, "retry": "none", "transcript_reference": None, "diagnostic": f"attachment[rejected;reason={reason}]"}
    if input_value["declared_format"] not in DECLARED_FORMATS:
        return {**expected, "decision": "rejected", "attachment_state": "failed", "upload_started": False, "upload_attempts": 0, "duplicate_uploads": 0, "retry": "none", "transcript_reference": None, "diagnostic": "attachment[rejected;reason=unsupported_format]"}
    if not _format_agrees(input_value["declared_format"], input_value["detected_format"]):
        return {**expected, "decision": "rejected", "attachment_state": "failed", "upload_started": False, "upload_attempts": 0, "duplicate_uploads": 0, "retry": "none", "transcript_reference": None, "diagnostic": "attachment[rejected;reason=declaration_content_mismatch]"}
    if input_value["size_state"] == "over_limit":
        return {**expected, "decision": "rejected", "attachment_state": "failed", "upload_started": False, "upload_attempts": 0, "duplicate_uploads": 0, "retry": "none", "transcript_reference": None, "diagnostic": "attachment[rejected;reason=too_large]"}
    if input_value["cancel_point"] == "after_upload_start":
        return {**expected, "decision": "cancelled", "attachment_state": "cancelled", "upload_started": True, "upload_attempts": 1, "duplicate_uploads": 0, "retry": "state_read_before_retry", "transcript_reference": None, "diagnostic": "attachment[cancelled;after_upload_start]"}
    if input_value["transport_state"] == "interrupted_before_upload":
        if input_value["state_read"] == "confirmed_no_upload":
            return {**expected, "decision": "accepted_after_retry", "attachment_state": "uploaded", "upload_started": True, "upload_attempts": 1, "duplicate_uploads": 0, "retry": "safe_after_state_read", "transcript_reference": None, "diagnostic": "attachment[uploaded;retry_safe]"}
        return {**expected, "decision": "interrupted", "attachment_state": "interrupted", "upload_started": False, "upload_attempts": 0, "duplicate_uploads": 0, "retry": "safe_after_state_read", "transcript_reference": None, "diagnostic": "attachment[interrupted]"}
    if input_value["transport_state"] == "interrupted_after_upload_start":
        return {**expected, "decision": "interrupted", "attachment_state": "interrupted", "upload_started": True, "upload_attempts": 1, "duplicate_uploads": 0, "retry": "state_read_before_retry", "transcript_reference": None, "diagnostic": "attachment[interrupted]"}
    if input_value["transport_state"] == "response_lost_after_upload":
        return {**expected, "decision": "unknown", "attachment_state": "unknown", "upload_started": True, "upload_attempts": 1, "duplicate_uploads": 0, "retry": "no_automatic_retry", "transcript_reference": None, "diagnostic": "attachment[unknown]"}
    if "upload_started" not in case["timeline"] and "preprocess_completed" in case["timeline"]:
        return {**expected, "decision": "ready", "attachment_state": "preprocessed", "upload_started": False, "upload_attempts": 0, "duplicate_uploads": 0, "retry": "wait_or_cancel", "transcript_reference": None, "diagnostic": "attachment[ready]"}
    if "upload_completed" not in case["timeline"]:
        return {**expected, "decision": "pending", "attachment_state": "uploading", "upload_started": True, "upload_attempts": 1, "duplicate_uploads": 0, "retry": "wait_or_cancel", "transcript_reference": None, "diagnostic": "attachment[pending]"}
    reference = "synthetic-attachment-ref-001" if case["id"] == "success-transcript-reference" else None
    return {**expected, "decision": "accepted", "attachment_state": "uploaded", "upload_started": True, "upload_attempts": 1, "duplicate_uploads": 0, "retry": "none", "transcript_reference": reference, "diagnostic": "attachment[uploaded]"}


def _validate_progress(progress: Any) -> None:
    require(type(progress) is list, "progress_type")
    require(len(progress) <= MAX_PROGRESS_EVENTS, "progress_limit")
    previous_phase = None
    previous_percent = -1
    for item in progress:
        row = _exact_keys(item, PROGRESS_KEYS, "progress_shape")
        require(row["phase"] in PROGRESS_PHASES, "progress_phase")
        percent = _exact_int(row["percent"], "progress_percent_type")
        require(0 <= percent <= 100, "progress_percent_range")
        if previous_phase == row["phase"]:
            require(percent >= previous_percent, "progress_regressed")
        elif previous_phase == "upload":
            require(row["phase"] == "upload", "progress_phase_order")
        previous_phase = row["phase"]
        previous_percent = percent


def _validate_case_shape(case: Any) -> None:
    case_value = _exact_keys(case, CASE_KEYS, "case_shape")
    require(type(case_value["id"]) is str and ID_PATTERN.fullmatch(case_value["id"]) is not None, "case_id")
    require(type(case_value["scenario"]) is str and SCENARIO_PATTERN.fullmatch(case_value["scenario"]) is not None, "scenario")
    input_value = _exact_keys(case_value["input"], INPUT_KEYS, "input_shape")
    require(input_value["selection"] in SELECTIONS, "selection")
    for field in ("declared_format", "detected_format"):
        value = input_value[field]
        require(value is None or value in FORMATS, field)
    require(input_value["data_url_state"] in DATA_URL_STATES, "data_url_state")
    require(input_value["size_state"] in SIZE_STATES, "size_state")
    require(input_value["metadata_state"] in METADATA_STATES, "metadata_state")
    require(input_value["transport_state"] in TRANSPORT_STATES, "transport_state")
    require(input_value["cancel_point"] in CANCEL_POINTS, "cancel_point")
    require(input_value["contract"] in {CONTRACT, "dashboard-v0.0.2"}, "contract")
    require(input_value["state_read"] in STATE_READS, "state_read")
    preprocess = _exact_keys(case_value["preprocess"], PREPROCESS_KEYS, "preprocess_shape")
    for key in PREPROCESS_KEYS:
        _exact_bool(preprocess[key], f"preprocess_{key}")
    require(type(case_value["timeline"]) is list and len(case_value["timeline"]) <= MAX_PROGRESS_EVENTS, "timeline_type")
    for event in case_value["timeline"]:
        require(type(event) is str and event in TIMELINE_EVENTS, "timeline_event")
    _validate_progress(case_value["progress"])
    expected = _exact_keys(case_value["expected"], EXPECTED_KEYS, "expected_shape")
    require(expected["decision"] in DECISIONS, "decision")
    require(expected["attachment_state"] in ATTACHMENT_STATES, "attachment_state")
    require(expected["draft"] == "preserved", "draft_policy")
    _exact_bool(expected["upload_started"], "upload_started_type")
    attempts = _exact_int(expected["upload_attempts"], "upload_attempts_type")
    duplicates = _exact_int(expected["duplicate_uploads"], "duplicate_uploads_type")
    require(attempts >= 0 and duplicates == 0 and duplicates <= attempts, "upload_duplicate_policy")
    require(expected["retry"] in RETRY_POLICIES, "retry_policy")
    _exact_bool(expected["metadata_retained"], "metadata_retained_type")
    reference = expected["transcript_reference"]
    require(reference is None or (type(reference) is str and REFERENCE_PATTERN.fullmatch(reference) is not None), "transcript_reference")
    require(type(expected["diagnostic"]) is str and DIAGNOSTIC_PATTERN.fullmatch(expected["diagnostic"]) is not None, "diagnostic")
    require(type(case_value["notes"]) is str and len(case_value["notes"]) <= MAX_JSON_STRING_CHARS, "notes")


def _validate_case_semantics(case: dict[str, Any]) -> None:
    input_value = case["input"]
    preprocess = case["preprocess"]
    expected = case["expected"]
    timeline = case["timeline"]
    calculated = _expected_for_case(case)
    require(expected == calculated, "semantic_drift")
    require(expected["metadata_retained"] is False, "metadata_retained")
    require(preprocess["source_bytes_retained"] is False, "source_bytes_retained")
    if input_value["metadata_state"] == "present" and preprocess["performed"]:
        require(preprocess["metadata_removed"] is True, "metadata_not_removed")
    if input_value["selection"] == "none":
        require(timeline == ["selection_empty"], "empty_timeline")
    if expected["upload_started"]:
        require(timeline.count("upload_started") == 1, "upload_start_count")
    else:
        require("upload_started" not in timeline, "upload_started_early")
    require(timeline.count("upload_completed") <= 1, "upload_complete_count")
    if expected["duplicate_uploads"] == 0:
        require(timeline.count("upload_started") <= 1, "duplicate_upload_timeline")
    if expected["attachment_state"] == "uploaded":
        require("upload_completed" in timeline, "uploaded_without_completion")
    if expected["decision"] == "unknown":
        require(input_value["transport_state"] == "response_lost_after_upload", "unknown_without_lost_response")
        require(expected["retry"] == "no_automatic_retry", "unknown_retry_policy")
    if expected["transcript_reference"] is not None:
        require(case["id"] == "success-transcript-reference", "unexpected_transcript_reference")
        require("transcript_reference_recorded" in timeline, "missing_transcript_reference_event")


def validate_document(document: dict[str, Any]) -> None:
    _exact_keys(document, ROOT_KEYS, "root_shape")
    require(document["schema"] == SCHEMA, "schema")
    require(document["contract"] == CONTRACT, "contract")
    require(document["policy_reference"] == C13_POLICY_REFERENCE, "policy_reference")
    require(document["hermes_source_sha"] == HERMES_SOURCE_SHA, "source_sha")
    require(document["fixture_policy"] == "synthetic_markers_only", "fixture_policy")
    _exact_bool(document["synthetic_only"], "synthetic_only_type")
    require(document["synthetic_only"] is True, "synthetic_only")
    limits = _exact_keys(document["limits"], LIMIT_KEYS, "limits_shape")
    require(_exact_int(limits["max_bytes"], "max_bytes_type") == MAX_IMAGE_BYTES, "max_bytes")
    require(_exact_int(limits["max_progress_events"], "max_progress_events_type") == MAX_PROGRESS_EVENTS, "max_progress_events")
    redaction = _exact_keys(document["redaction"], REDACTION_KEYS, "redaction_shape")
    for key, value in redaction.items():
        require(type(value) is bool and value is False, f"redaction_{key}")
    cases = document["cases"]
    require(type(cases) is list and len(cases) == len(EXPECTED_CASE_IDS), "cases_type")
    ids: list[str] = []
    for case in cases:
        _validate_case_shape(case)
        ids.append(case["id"])
    require(tuple(ids) == EXPECTED_CASE_IDS, "case_order")
    require(len(set(ids)) == len(ids), "duplicate_case_id")
    for case in cases:
        _validate_case_semantics(case)
    _scan_retained_text(document)


def _distribution(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    p95_index = max(0, math.ceil(len(ordered) * 0.95) - 1)
    return {
        "min": min(ordered),
        "median": statistics.median(ordered),
        "p95": ordered[p95_index],
        "max": max(ordered),
    }


def validate_baseline(baseline: dict[str, Any]) -> None:
    _exact_keys(baseline, BASELINE_ROOT_KEYS, "baseline_shape")
    require(baseline["schema"] == BASELINE_SCHEMA, "baseline_schema")
    _exact_bool(baseline["synthetic_only"], "baseline_synthetic_type")
    require(baseline["synthetic_only"] is True, "baseline_synthetic")
    require(baseline["build_mode"] == "not-applicable-no-production-executable", "baseline_build_mode")
    require(baseline["threshold"] is None, "baseline_threshold")
    artifact_paths = tuple(
        FIXTURE_DIR / name
        for name in ("README.md", "cases.json", "validate.py", "test_validate.py", "baseline.json")
    )
    _exact_int(baseline["artifact_bytes"], "baseline_artifact_bytes")
    _exact_int(baseline["artifact_file_count"], "baseline_artifact_file_count")
    require(all(path.is_file() for path in artifact_paths), "baseline_artifact_files")
    require(baseline["artifact_file_count"] == len(artifact_paths), "baseline_artifact_file_count_value")
    require(baseline["artifact_bytes"] == artifact_bytes(), "baseline_artifact_bytes_value")
    for mode in ("normal", "optimized"):
        record = _exact_keys(baseline[mode], BASELINE_MODE_KEYS, f"baseline_{mode}_shape")
        repetitions = _exact_int(record["repetitions"], f"baseline_{mode}_repetitions")
        require(repetitions == 30, f"baseline_{mode}_count")
        samples = record["samples_ms"]
        require(type(samples) is list and len(samples) == repetitions, f"baseline_{mode}_samples")
        for sample in samples:
            require(type(sample) is float and math.isfinite(sample) and sample >= 0, f"baseline_{mode}_sample_type")
        distribution = _exact_keys(record["distribution"], DISTRIBUTION_KEYS, f"baseline_{mode}_distribution_shape")
        expected = _distribution(samples)
        for key in DISTRIBUTION_KEYS:
            require(type(distribution[key]) is float and math.isfinite(distribution[key]), f"baseline_{mode}_{key}_type")
            require(math.isclose(distribution[key], expected[key], rel_tol=0, abs_tol=1e-9), f"baseline_{mode}_{key}")
    _scan_retained_text(baseline)


def artifact_bytes() -> int:
    return sum(path.stat().st_size for path in (FIXTURE_DIR / name for name in ("README.md", "cases.json", "validate.py", "test_validate.py", "baseline.json")))


def _print_error(code: str) -> None:
    payload = {"error": {"code": code, "message": "image attachment lifecycle validation failed", "synthetic_only": True}}
    line = json.dumps(payload, separators=(",", ":"))
    print(line[:MAX_ERROR_OUTPUT_LENGTH])


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _: str) -> None:
        raise ContractError("invalid_arguments")


def run(argv: Iterable[str] | None = None) -> int:
    parser = SafeArgumentParser(add_help=False)
    parser.add_argument("--cases", type=Path, default=CASES_PATH)
    parser.add_argument("--baseline", type=Path, default=BASELINE_PATH)
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
        document = load_json(args.cases)
        baseline = load_json(args.baseline)
        validate_document(document)
        validate_baseline(baseline)
    except (ContractError, OSError, UnicodeError, json.JSONDecodeError, RecursionError, ValueError, MemoryError):
        _print_error("contract")
        return 2
    print(f"image_attachment_lifecycle_validation=ok cases={len(document['cases'])} threshold=null artifact_bytes={artifact_bytes()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
