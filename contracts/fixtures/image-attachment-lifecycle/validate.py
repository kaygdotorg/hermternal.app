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
import base64
import binascii
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import statistics
from typing import Any, Iterable


FIXTURE_DIR = Path(__file__).resolve().parent
CASES_PATH = FIXTURE_DIR / "cases.json"
BASELINE_PATH = FIXTURE_DIR / "baseline.json"
C13_FIXTURE_DIR = FIXTURE_DIR.parent / "attachment-policy"
C13_CASES_PATH = C13_FIXTURE_DIR / "cases.json"
C13_VALIDATOR_PATH = C13_FIXTURE_DIR / "validate.py"
SCHEMA = "hermternal.fixture.image-attachment-lifecycle.v1"
BASELINE_SCHEMA = "hermternal.fixture.image-attachment-lifecycle-baseline.v1"
CONTRACT = "dashboard-v0.0.1"
C13_POLICY_REFERENCE = "attachment-policy-c13-f5be9236"
HERMES_SOURCE_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
C13_CASES_SHA256 = "1329316d990026ff00e1285cfc4c9516cba183af96505f4e4ac5a2b5cbd16e68"
C13_VALIDATOR_SHA256 = "5257fcdcd94b031a9f89e77f7b97e70936b22787f97efa5eaba563d30a7d3552"
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
ARTIFACT_NAMES = ("README.md", "cases.json", "validate.py", "test_validate.py", "baseline.json")
# The executable is the trust boundary and cannot self-hash. These four
# evidence artifacts plus the baseline are pinned outside the mutable baseline;
# editing an artifact and rebinding its local measurements therefore fails.
CANONICAL_ARTIFACTS: dict[str, dict[str, int | str]] = {
    "README.md": {"size_bytes": 7536, "sha256": "3ae61028fad8a039be12bad4f29261e578a2e399736e8e43ddb9e01f02fbc2b4"},
    "cases.json": {"size_bytes": 24084, "sha256": "2fb48a66e94c20d2133dd387746946643f16061b702566acaf4633fb55a7cd7f"},
    "test_validate.py": {"size_bytes": 23584, "sha256": "3f3190e582b02d69d2ab0314f7bce19666acf136edce0b4f20b745762deff025"},
    "baseline.json": {"size_bytes": 2252, "sha256": "1ea90ce6ce43a74ac813dc62dfc97282d6b7e469dfaa119af48bde1310bc5420"},
}
CANONICAL_BASELINE_CONTENT_SHA256 = "1295eb33e4036c47ba61d5bb555c112aa1950d087e43d3e2c5746f5908cda0a2"

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
        "c13_consistency",
        "cases",
    }
)
C13_CONSISTENCY_KEYS = frozenset(
    {
        "policy_reference",
        "source_sha",
        "c13_cases_sha256",
        "c13_validator_sha256",
        "rule",
        "c13_case_id",
        "c14_case_id",
        "c14_data_url_state",
        "expected_decision",
        "expected_attachment_state",
        "expected_diagnostic",
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
    {
        "schema",
        "synthetic_only",
        "build_mode",
        "threshold",
        "artifact_bytes",
        "artifact_file_count",
        "provenance",
        "normal",
        "optimized",
    }
)
BASELINE_MODE_KEYS = frozenset({"repetitions", "samples_ms", "distribution"})
DISTRIBUTION_KEYS = frozenset({"min", "median", "p95", "max"})
PROVENANCE_KEYS = frozenset({"environment", "device", "raw_trace"})
ENVIRONMENT_KEYS = frozenset({"os", "python", "architecture"})
DEVICE_KEYS = frozenset({"model", "architecture"})
RAW_TRACE_KEYS = frozenset(
    {
        "source",
        "format",
        "unit",
        "normal_samples_field",
        "optimized_samples_field",
        "normal_distribution_field",
        "optimized_distribution_field",
        "sample_count",
    }
)

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


_RETAINED_DATA_URL_RE = re.compile(r"(?i)\bdata:[^,\s]+,[^\s]+")
_RETAINED_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{8,}={1,2}(?![A-Za-z0-9+/])")
_RETAINED_BASE64_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{3,}={0,2}(?![A-Za-z0-9+/=])")
_RETAINED_PATH_RE = re.compile(
    r"(?i)(?:file://|(?<![A-Za-z0-9_/])/(?!/)[^\s\"'<>]+|(?<![A-Za-z0-9_])[a-z]:[\\/][^\s\"'<>]*|(?<![A-Za-z0-9_])\\\\[^\s\"'<>]+)"
)
_RETAINED_FILENAME_RE = re.compile(
    r"(?i)(?<![\w.-])(?:\.\.?[\\/][^\r\n]*|[a-z0-9_.-]+[\\/][^\r\n]*|[a-z0-9_.-]+)\.(?:png|jpg|jpeg|gif|webp|bmp|svg|tiff|pdf)(?![\w.-])"
)
_RETAINED_HOST_RE = re.compile(r"(?i)(?<![\w.-])(?:[a-z0-9-]+\.)+[a-z]{2,}(?![\w.-])")
_RETAINED_IPV4_RE = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
_RETAINED_AUTH_RE = re.compile(
    r"(?i)\b(?:basic|bearer|auth|authorization)\s*(?:(?::|=)\s*|\s+)\S+"
)
_RETAINED_CREDENTIAL_RE = re.compile(r"(?i)\b(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+")
_RETAINED_COOKIE_RE = re.compile(r"(?i)\bcookie\s*(?:(?::|=)\s*)\S+")
_RETAINED_BASE64_CONTEXT_RE = re.compile(
    r"(?i)(?:\b(?:payload|base64|encoded|data|token|value)\s*[:=]?\s*|[=:]\s*)$"
)


def _is_known_digest(value: str) -> bool:
    """Allow only the validator's own pinned digest strings through redaction."""
    return value == HERMES_SOURCE_SHA or value == CANONICAL_BASELINE_CONTENT_SHA256 or any(
        value == str(entry["sha256"]) for entry in CANONICAL_ARTIFACTS.values()
    )


def _looks_like_base64_token(token: str) -> bool:
    """Reject padded, unpadded, short, lowercase, and digit-only payload tokens."""
    raw = token.rstrip("=")
    if len(raw) < 4 or token.count("=") > 2 or ("=" in token and not token.endswith("=" * token.count("="))):
        return False
    if len(raw) % 4 == 1:
        return False
    padded = raw + "=" * (-len(raw) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return False
    canonical = base64.b64encode(decoded).decode("ascii")
    return canonical == token or canonical.rstrip("=") == token


def _contains_base64_like(value: str) -> bool:
    """Reject payload-like tokens without treating ordinary prose as payload.

    A short token is ambiguous in free text, so embedded tokens require an
    encoding label or delimiter. This still rejects ``payload YWJj`` and
    equals-form payloads while allowing ordinary fixture prose such as
    ``before`` and ``upload``.
    """
    stripped = value.strip()
    if _is_known_digest(stripped):
        return False
    for match in _RETAINED_BASE64_TOKEN_RE.finditer(value):
        token = match.group(0)
        raw_length = len(token.rstrip("="))
        if raw_length < 4 or raw_length % 4 == 1:
            continue
        if token == stripped:
            return True
        if not _looks_like_base64_token(token):
            continue
        context = value[: match.start()]
        if _RETAINED_BASE64_CONTEXT_RE.search(context):
            return True
        uppercase = sum(character.isupper() for character in token)
        lowercase = sum(character.islower() for character in token)
        if raw_length < 8 and (
            any(character.isdigit() or character in "+/" for character in token)
            or (uppercase >= 2 and lowercase > 0)
        ):
            return True
        if len(token) >= 8 and (
            any(character.isdigit() or character in "+/" for character in token)
            or uppercase >= 2
        ):
            return True
    return False


def _scan_retained_text(value: Any, field_name: str | None = None) -> None:
    if type(value) is dict:
        for key, child in value.items():
            normalized = _normalized_text(key)
            require(
                normalized not in {"data_url", "base64_payload", "absolute_path", "filename_value", "host_value", "credential_value", "prompt_text", "transcript_text", "user_data"},
                "forbidden_key",
            )
            _scan_retained_text(child, normalized)
        return
    if type(value) is list:
        for child in value:
            _scan_retained_text(child, field_name)
        return
    if type(value) is not str:
        return
    lowered = value.casefold()
    require(_RETAINED_DATA_URL_RE.search(value) is None and "data:" not in lowered, "raw_data_url")
    require(_RETAINED_PATH_RE.search(value) is None, "raw_path")
    require("file://" not in lowered, "raw_path")
    require("http://" not in lowered and "https://" not in lowered, "host_value")
    require("/" not in value and "\\" not in value, "raw_path")
    require("@" not in value, "host_value")
    require(_RETAINED_AUTH_RE.search(value) is None, "credential_value")
    require(_RETAINED_CREDENTIAL_RE.search(value) is None, "credential_value")
    require(_RETAINED_COOKIE_RE.search(value) is None, "credential_value")
    require(not re.search(r"(?:ghp_|sk_live_|AKIA[0-9A-Z]{16})", value, re.IGNORECASE), "credential_value")
    if field_name == "notes":
        require(not _contains_base64_like(value), "raw_base64")
    else:
        require(_RETAINED_BASE64_RE.search(value) is None, "raw_base64")
    require(_RETAINED_FILENAME_RE.search(value) is None, "filename_value")
    require(_RETAINED_HOST_RE.search(value) is None, "host_value")
    require(_RETAINED_IPV4_RE.search(value) is None, "host_value")
    require(re.search(r"(?i)\blocalhost\b", value) is None, "host_value")


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


def _exact_string(value: Any, code: str, allowed: frozenset[str] | None = None) -> str:
    """Check scalar type before membership so malformed JSON cannot raise TypeError."""
    require(type(value) is str, code)
    if allowed is not None:
        require(value in allowed, code)
    return value


def _optional_string(value: Any, code: str, allowed: frozenset[str] | None = None) -> str | None:
    if value is None:
        return None
    return _exact_string(value, code, allowed)


def _format_agrees(declared: str | None, detected: str | None) -> bool:
    """Match MIME family labels to the C-13 magic-signature families."""
    if declared == "gif":
        return detected in {"gif87a", "gif89a"}
    return declared == detected and declared in DECLARED_FORMATS


def _validate_marker_compatibility(case: dict[str, Any]) -> None:
    """Bind scalar markers to the lifecycle timeline before deriving outcomes."""
    input_value = case["input"]
    timeline = case["timeline"]
    selection = input_value["selection"]
    contract = input_value["contract"]
    data_url_state = input_value["data_url_state"]
    size_state = input_value["size_state"]
    transport_state = input_value["transport_state"]
    cancel_point = input_value["cancel_point"]
    upload_started = _event_index(timeline, "upload_started")

    require(len(timeline) == len(set(timeline)), "timeline_duplicate_event")
    if selection == "none":
        require(input_value["declared_format"] is None and input_value["detected_format"] is None, "empty_format_marker")
        require(data_url_state == "absent", "empty_data_url_marker")
        require(size_state == "not_applicable", "empty_size_marker")
        require(input_value["metadata_state"] == "absent", "empty_metadata_marker")
        require(transport_state == "not_started", "empty_transport_marker")
        require(cancel_point == "none", "empty_cancel_marker")
        require(input_value["state_read"] == "not_required", "empty_state_read_marker")
        return

    require(selection == "one_image", "selection_marker")
    if contract != CONTRACT:
        require(contract == "dashboard-v0.0.2", "contract_marker")
        require(data_url_state == "synthetic_valid", "blocked_data_url_marker")
        require(size_state == "within_limit", "blocked_size_marker")
        require(input_value["metadata_state"] == "absent", "blocked_metadata_marker")
        require(transport_state == "not_started", "blocked_transport_marker")
        require(cancel_point == "none", "blocked_cancel_marker")
        require(input_value["state_read"] == "not_required", "blocked_state_read_marker")
        require(upload_started is None and timeline == ["selected", "blocked"], "blocked_lifecycle")
        return

    # A selected attachment must carry an explicit data URL state. ``absent``
    # is reserved for empty selection; keeping it in the enum prevents a
    # parser/type bypass but this semantic guard prevents a mapping KeyError.
    require(data_url_state != "absent", "data_url_state_combination")
    require(size_state != "not_applicable", "size_state_combination")

    if data_url_state != "synthetic_valid":
        require(size_state == "within_limit", "invalid_data_size_marker")
        require(transport_state == "not_started", "invalid_data_transport_marker")
        require(cancel_point == "none", "invalid_data_cancel_marker")
        require(input_value["state_read"] == "not_required", "invalid_data_state_read_marker")
        require(upload_started is None, "invalid_data_upload_marker")

    if size_state == "over_limit":
        require(data_url_state == "synthetic_valid", "size_data_url_marker")
        require(_format_agrees(input_value["declared_format"], input_value["detected_format"]), "size_format_marker")
        require(transport_state == "not_started", "size_transport_marker")
        require(cancel_point == "none", "size_cancel_marker")
        require(upload_started is None, "size_upload_marker")

    if transport_state == "not_started":
        require(upload_started is None, "transport_upload_marker")
        require("network_interrupted" not in timeline and "response_lost" not in timeline, "transport_event_marker")
    elif transport_state == "available":
        require(upload_started is not None, "available_upload_marker")
        require("network_interrupted" not in timeline and "response_lost" not in timeline, "available_event_marker")
    elif transport_state == "interrupted_before_upload":
        interruption_index = _event_index(timeline, "network_interrupted")
        require(interruption_index is not None, "preflight_interrupt_marker")
        require(upload_started is None or interruption_index < upload_started, "preflight_order_marker")
    elif transport_state == "interrupted_after_upload_start":
        interruption_index = _event_index(timeline, "network_interrupted")
        require(upload_started is not None and interruption_index is not None, "post_start_interrupt_marker")
        require(upload_started < interruption_index, "post_start_interrupt_order")
    elif transport_state == "response_lost_after_upload":
        response_index = _event_index(timeline, "response_lost")
        require(upload_started is not None and response_index is not None, "response_lost_marker")
        require(upload_started < response_index, "response_lost_order_marker")

    if cancel_point == "none":
        require("cancelled_before_upload" not in timeline and "cancelled_after_upload_start" not in timeline, "cancel_marker")
    elif cancel_point == "before_upload_start":
        require(data_url_state == "synthetic_valid" and size_state == "within_limit", "cancel_before_input_marker")
        require(transport_state == "not_started" and upload_started is None, "cancel_before_transport_marker")
        require("cancelled_before_upload" in timeline, "cancel_before_timeline_marker")
    else:
        require(data_url_state == "synthetic_valid" and size_state == "within_limit", "cancel_after_input_marker")
        require(transport_state == "available" and upload_started is not None, "cancel_after_transport_marker")
        require(input_value["state_read"] == "required_before_retry", "cancel_state_read_policy")
        require("cancelled_after_upload_start" in timeline, "cancel_after_timeline_marker")

    if upload_started is not None:
        progress_index = _event_index(timeline, "upload_progress")
        require(progress_index is not None and upload_started < progress_index, "upload_progress_order")
        completed_index = _event_index(timeline, "upload_completed")
        if completed_index is not None:
            require(progress_index < completed_index, "upload_completion_order")
        reference_index = _event_index(timeline, "transcript_reference_recorded")
        if reference_index is not None:
            require(completed_index is not None and completed_index < reference_index, "transcript_reference_order")
    else:
        require("upload_progress" not in timeline and "upload_completed" not in timeline, "upload_event_without_start")

    if "transcript_reference_recorded" in timeline:
        require("upload_completed" in timeline, "transcript_without_completion")
    if "upload_completed" in timeline:
        require("upload_started" in timeline, "completion_without_start")
    if "network_interrupted" in timeline:
        _require_event_order(timeline, "preprocess_completed", "network_interrupted", "interrupt_preprocess_order")
    if "response_lost" in timeline:
        _require_event_order(timeline, "upload_started", "response_lost", "response_lost_upload_order")


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
        }.get(input_value["data_url_state"])
        require(reason is not None, "data_url_state_combination")
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
        phase = _exact_string(row["phase"], "progress_phase_type", PROGRESS_PHASES)
        percent = _exact_int(row["percent"], "progress_percent_type")
        require(0 <= percent <= 100, "progress_percent_range")
        if previous_phase == phase:
            require(percent >= previous_percent, "progress_regressed")
        elif previous_phase == "upload":
            require(phase == "upload", "progress_phase_order")
        previous_phase = phase
        previous_percent = percent


def _validate_case_shape(case: Any) -> None:
    case_value = _exact_keys(case, CASE_KEYS, "case_shape")
    require(type(case_value["id"]) is str and ID_PATTERN.fullmatch(case_value["id"]) is not None, "case_id")
    require(type(case_value["scenario"]) is str and SCENARIO_PATTERN.fullmatch(case_value["scenario"]) is not None, "scenario")
    input_value = _exact_keys(case_value["input"], INPUT_KEYS, "input_shape")
    _exact_string(input_value["selection"], "selection_type", SELECTIONS)
    for field in ("declared_format", "detected_format"):
        _optional_string(input_value[field], f"{field}_type", FORMATS)
    _exact_string(input_value["data_url_state"], "data_url_state", DATA_URL_STATES)
    _exact_string(input_value["size_state"], "size_state", SIZE_STATES)
    _exact_string(input_value["metadata_state"], "metadata_state", METADATA_STATES)
    _exact_string(input_value["transport_state"], "transport_state", TRANSPORT_STATES)
    _exact_string(input_value["cancel_point"], "cancel_point", CANCEL_POINTS)
    _exact_string(input_value["contract"], "contract", frozenset({CONTRACT, "dashboard-v0.0.2"}))
    _exact_string(input_value["state_read"], "state_read", STATE_READS)
    preprocess = _exact_keys(case_value["preprocess"], PREPROCESS_KEYS, "preprocess_shape")
    for key in PREPROCESS_KEYS:
        _exact_bool(preprocess[key], f"preprocess_{key}")
    require(type(case_value["timeline"]) is list and len(case_value["timeline"]) <= MAX_PROGRESS_EVENTS, "timeline_type")
    for event in case_value["timeline"]:
        _exact_string(event, "timeline_event", TIMELINE_EVENTS)
    _validate_progress(case_value["progress"])
    expected = _exact_keys(case_value["expected"], EXPECTED_KEYS, "expected_shape")
    _exact_string(expected["decision"], "decision", DECISIONS)
    _exact_string(expected["attachment_state"], "attachment_state", ATTACHMENT_STATES)
    _exact_string(expected["draft"], "draft_type", frozenset({"preserved"}))
    _exact_bool(expected["upload_started"], "upload_started_type")
    attempts = _exact_int(expected["upload_attempts"], "upload_attempts_type")
    duplicates = _exact_int(expected["duplicate_uploads"], "duplicate_uploads_type")
    require(attempts >= 0 and duplicates == 0 and duplicates <= attempts, "upload_duplicate_policy")
    _exact_string(expected["retry"], "retry_policy", RETRY_POLICIES)
    _exact_bool(expected["metadata_retained"], "metadata_retained_type")
    reference = expected["transcript_reference"]
    require(reference is None or (type(reference) is str and REFERENCE_PATTERN.fullmatch(reference) is not None), "transcript_reference")
    require(type(expected["diagnostic"]) is str and DIAGNOSTIC_PATTERN.fullmatch(expected["diagnostic"]) is not None, "diagnostic")
    require(type(case_value["notes"]) is str and len(case_value["notes"]) <= MAX_JSON_STRING_CHARS, "notes")


def _event_index(timeline: list[str], event: str) -> int | None:
    try:
        return timeline.index(event)
    except ValueError:
        return None


def _require_event_order(timeline: list[str], before: str, after: str, code: str) -> None:
    before_index = _event_index(timeline, before)
    after_index = _event_index(timeline, after)
    require(before_index is not None and after_index is not None and before_index < after_index, code)


def _validate_progress_semantics(case: dict[str, Any]) -> None:
    input_value = case["input"]
    preprocess = case["preprocess"]
    timeline = case["timeline"]
    progress = case["progress"]
    if input_value["selection"] == "none" or input_value["contract"] != CONTRACT:
        require(progress == [], "non_upload_progress")
        return
    require(preprocess["performed"] is True, "preprocess_required")
    require("preprocess_started" in timeline and "preprocess_completed" in timeline, "preprocess_timeline")
    preprocess_rows = [row for row in progress if row["phase"] == "preprocess"]
    upload_rows = [row for row in progress if row["phase"] == "upload"]
    require([row["percent"] for row in preprocess_rows] == [0, 100], "preprocess_progress")
    upload_index = _event_index(timeline, "upload_started")
    if upload_index is None:
        require(upload_rows == [], "upload_progress_without_start")
    else:
        require(len(upload_rows) >= 2, "upload_progress_missing")
        require(upload_rows[0]["percent"] == 0, "upload_progress_start")
        require("upload_progress" in timeline, "upload_progress_event_missing")
        if "upload_completed" in timeline:
            require(upload_rows[-1]["percent"] == 100, "upload_progress_completion")
    if "upload_progress" in timeline:
        require(upload_index is not None and upload_rows, "timeline_progress_mismatch")


def _validate_case_semantics(case: dict[str, Any]) -> None:
    input_value = case["input"]
    preprocess = case["preprocess"]
    expected = case["expected"]
    timeline = case["timeline"]
    _validate_marker_compatibility(case)
    calculated = _expected_for_case(case)
    require(expected == calculated, "semantic_drift")
    require(expected["metadata_retained"] is False, "metadata_retained")
    require(preprocess["source_bytes_retained"] is False, "source_bytes_retained")
    if input_value["selection"] == "none":
        require(timeline == ["selection_empty"], "empty_timeline")
        require(preprocess["performed"] is False, "empty_preprocess")
        _validate_progress_semantics(case)
        return
    if input_value["contract"] != CONTRACT:
        require(timeline == ["selected", "blocked"], "blocked_timeline")
        require(preprocess["performed"] is False, "blocked_preprocess")
        _validate_progress_semantics(case)
        return

    require(timeline and timeline[0] == "selected", "selection_timeline")
    require(timeline.count("preprocess_started") == 1, "preprocess_start_count")
    require(timeline.count("preprocess_completed") == 1, "preprocess_complete_count")
    _require_event_order(timeline, "selected", "preprocess_started", "preprocess_start_order")
    _require_event_order(timeline, "preprocess_started", "preprocess_completed", "preprocess_complete_order")
    require(preprocess["performed"] is True, "preprocess_required")
    if input_value["metadata_state"] == "present":
        require(preprocess["metadata_removed"] is True, "metadata_not_removed")
        require(timeline.count("metadata_removed") == 1, "metadata_event_missing")
        _require_event_order(timeline, "preprocess_started", "metadata_removed", "metadata_event_order")
        _require_event_order(timeline, "metadata_removed", "preprocess_completed", "metadata_completion_order")
    else:
        require(preprocess["metadata_removed"] is False, "unexpected_metadata_removal")
        require("metadata_removed" not in timeline, "unexpected_metadata_event")

    upload_index = _event_index(timeline, "upload_started")
    if expected["upload_started"]:
        require(upload_index is not None and timeline.count("upload_started") == 1, "upload_start_count")
        _require_event_order(timeline, "preprocess_completed", "upload_started", "upload_start_order")
    else:
        require(upload_index is None, "upload_started_early")
    require(timeline.count("upload_completed") <= 1, "upload_complete_count")
    if expected["duplicate_uploads"] == 0:
        require(timeline.count("upload_started") <= 1, "duplicate_upload_timeline")
    if expected["attachment_state"] == "uploaded":
        require("upload_completed" in timeline, "uploaded_without_completion")
    if expected["decision"] == "rejected":
        require(timeline.count("rejected") == 1, "rejection_event_missing")
        _require_event_order(timeline, "preprocess_completed", "rejected", "rejection_order")
    if input_value["cancel_point"] == "before_upload_start":
        require(timeline.count("cancelled_before_upload") == 1, "cancel_before_event_missing")
        _require_event_order(timeline, "preprocess_completed", "cancelled_before_upload", "cancel_before_order")
    if expected["decision"] == "unknown":
        require(input_value["transport_state"] == "response_lost_after_upload", "unknown_without_lost_response")
        require(expected["retry"] == "no_automatic_retry", "unknown_retry_policy")

    if input_value["transport_state"] == "interrupted_before_upload":
        require("network_interrupted" in timeline, "preflight_interrupt_event")
        if input_value["state_read"] == "confirmed_no_upload":
            _require_event_order(timeline, "network_interrupted", "state_reread", "retry_state_read_order")
            _require_event_order(timeline, "state_reread", "retry_started", "retry_start_order")
            _require_event_order(timeline, "retry_started", "upload_started", "retry_upload_order")
        else:
            require(input_value["state_read"] == "required_before_retry", "preflight_state_read_policy")
            require("state_reread" not in timeline and "retry_started" not in timeline, "unexpected_preflight_retry")
    if input_value["cancel_point"] == "after_upload_start":
        require(input_value["state_read"] == "required_before_retry", "cancel_state_read_policy")
        require(timeline.count("cancelled_after_upload_start") == 1, "cancel_after_event_missing")
        require(timeline.count("state_reread") == 1, "cancel_state_read_missing")
        _require_event_order(timeline, "upload_started", "cancelled_after_upload_start", "cancel_order")
        _require_event_order(timeline, "cancelled_after_upload_start", "state_reread", "cancel_state_read_order")
    if input_value["transport_state"] == "interrupted_after_upload_start":
        require(input_value["state_read"] == "required_before_retry", "post_start_state_read_policy")
        require(timeline.count("network_interrupted") == 1, "interrupt_event_missing")
        require(timeline.count("state_reread") == 1, "interrupt_state_read_missing")
        _require_event_order(timeline, "upload_started", "network_interrupted", "interrupt_order")
        _require_event_order(timeline, "network_interrupted", "state_reread", "interrupt_state_read_order")
    if input_value["transport_state"] == "response_lost_after_upload":
        require(input_value["state_read"] == "required_before_retry", "uncertain_state_read_policy")
        require(timeline.count("response_lost") == 1, "response_lost_event_missing")
        require(timeline.count("state_reread") == 1, "uncertain_state_read_missing")
        _require_event_order(timeline, "upload_started", "response_lost", "response_lost_order")
        _require_event_order(timeline, "response_lost", "state_reread", "uncertain_state_read_order")
    if "state_reread" in timeline:
        require(input_value["state_read"] != "not_required", "state_read_event_policy")
    if expected["transcript_reference"] is not None:
        require(case["id"] == "success-transcript-reference", "unexpected_transcript_reference")
        require("transcript_reference_recorded" in timeline, "missing_transcript_reference_event")
    _validate_progress_semantics(case)


def _validate_c13_consistency(document: dict[str, Any], cases: list[dict[str, Any]]) -> None:
    """Evaluate the pinned C-13 case instead of trusting copied identifiers."""
    consistency = _exact_keys(document["c13_consistency"], C13_CONSISTENCY_KEYS, "c13_consistency_shape")
    _exact_string(consistency["policy_reference"], "c13_consistency_policy", frozenset({C13_POLICY_REFERENCE}))
    _exact_string(consistency["source_sha"], "c13_consistency_source", frozenset({HERMES_SOURCE_SHA}))
    _exact_string(consistency["c13_cases_sha256"], "c13_consistency_cases_digest", frozenset({C13_CASES_SHA256}))
    _exact_string(consistency["c13_validator_sha256"], "c13_consistency_validator_digest", frozenset({C13_VALIDATOR_SHA256}))
    _exact_string(consistency["rule"], "c13_consistency_rule", frozenset({"noncanonical_base64_rejected_before_upload"}))
    _exact_string(consistency["c13_case_id"], "c13_consistency_c13_case", frozenset({"invalid-noncanonical-base64"}))
    _exact_string(consistency["c14_case_id"], "c13_consistency_c14_case", frozenset({"malformed-base64"}))
    _exact_string(consistency["c14_data_url_state"], "c13_consistency_state", frozenset({"malformed_base64"}))
    _exact_string(consistency["expected_decision"], "c13_consistency_decision", frozenset({"rejected"}))
    _exact_string(consistency["expected_attachment_state"], "c13_consistency_attachment", frozenset({"failed"}))
    _exact_string(consistency["expected_diagnostic"], "c13_consistency_diagnostic", frozenset({"attachment[rejected;reason=malformed_base64]"}))
    require(C13_CASES_PATH.is_file() and C13_VALIDATOR_PATH.is_file(), "c13_consistency_files")
    require(_file_sha256(C13_CASES_PATH) == C13_CASES_SHA256, "c13_consistency_cases_anchor")
    require(_file_sha256(C13_VALIDATOR_PATH) == C13_VALIDATOR_SHA256, "c13_consistency_validator_anchor")
    try:
        spec = importlib.util.spec_from_file_location("hermternal_c13_policy_validator", C13_VALIDATOR_PATH)
        require(spec is not None and spec.loader is not None, "c13_consistency_loader")
        c13_validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(c13_validator)
        c13_document = c13_validator.load_document(C13_CASES_PATH)
        c13_validator.validate_document(c13_document)
        c13_by_id = {case["id"]: case for case in c13_document["cases"]}
        c13_case = c13_by_id[consistency["c13_case_id"]]
        c13_result = c13_validator.evaluate_case(c13_case)
    except Exception:
        raise ContractError("c13_consistency_artifact") from None
    require(c13_case["state"] == "ready", "c13_consistency_state_link")
    require(c13_result == c13_case["expected"], "c13_consistency_outcome_link")
    require(c13_result["decision"] == "rejected", "c13_consistency_decision_result")
    require(c13_result["reason"] == "noncanonical_base64", "c13_consistency_reason_result")
    require(c13_result["attachment_state"] == "failed", "c13_consistency_attachment_result")
    by_id = {case["id"]: case for case in cases}
    linked = by_id[consistency["c14_case_id"]]
    require(linked["input"]["data_url_state"] == consistency["c14_data_url_state"], "c13_consistency_input")
    require(linked["expected"]["decision"] == consistency["expected_decision"], "c13_consistency_decision_link")
    require(linked["expected"]["attachment_state"] == consistency["expected_attachment_state"], "c13_consistency_attachment_link")
    require(linked["expected"]["diagnostic"] == consistency["expected_diagnostic"], "c13_consistency_diagnostic_link")


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
    _validate_c13_consistency(document, cases)
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


def _canonical_digest(value: Any) -> str:
    """Hash the semantic baseline object independently of its mutable file text."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_benchmark_provenance(provenance: Any) -> None:
    """Require environment, device, and inline raw-trace provenance."""
    root = _exact_keys(provenance, PROVENANCE_KEYS, "baseline_provenance_shape")
    environment = _exact_keys(root["environment"], ENVIRONMENT_KEYS, "baseline_environment_shape")
    device = _exact_keys(root["device"], DEVICE_KEYS, "baseline_device_shape")
    trace = _exact_keys(root["raw_trace"], RAW_TRACE_KEYS, "baseline_trace_shape")
    for key in ENVIRONMENT_KEYS:
        value = _exact_string(environment[key], f"baseline_environment_{key}")
        require(bool(value.strip()), f"baseline_environment_{key}_empty")
    for key in DEVICE_KEYS:
        value = _exact_string(device[key], f"baseline_device_{key}")
        require(bool(value.strip()), f"baseline_device_{key}_empty")
    _exact_string(trace["source"], "baseline_trace_source", frozenset({"real-cli-subprocess-wall-time"}))
    _exact_string(trace["format"], "baseline_trace_format", frozenset({"inline-json-raw-samples"}))
    _exact_string(trace["unit"], "baseline_trace_unit", frozenset({"milliseconds"}))
    _exact_string(trace["normal_samples_field"], "baseline_trace_normal_samples", frozenset({"normal_samples_ms"}))
    _exact_string(trace["optimized_samples_field"], "baseline_trace_optimized_samples", frozenset({"optimized_samples_ms"}))
    _exact_string(trace["normal_distribution_field"], "baseline_trace_normal_distribution", frozenset({"normal_distribution"}))
    _exact_string(trace["optimized_distribution_field"], "baseline_trace_optimized_distribution", frozenset({"optimized_distribution"}))
    require(_exact_int(trace["sample_count"], "baseline_trace_sample_count") == 60, "baseline_trace_sample_count_value")


def validate_baseline(
    baseline: dict[str, Any],
    baseline_path: Path | None = None,
    fixture_dir: Path = FIXTURE_DIR,
    cases_path: Path | None = None,
) -> None:
    _exact_keys(baseline, BASELINE_ROOT_KEYS, "baseline_shape")
    require(baseline["schema"] == BASELINE_SCHEMA, "baseline_schema")
    _exact_bool(baseline["synthetic_only"], "baseline_synthetic_type")
    require(baseline["synthetic_only"] is True, "baseline_synthetic")
    require(baseline["build_mode"] == "not-applicable-no-production-executable", "baseline_build_mode")
    require(baseline["threshold"] is None, "baseline_threshold")
    _validate_benchmark_provenance(baseline["provenance"])
    artifact_paths = tuple(fixture_dir / name for name in ARTIFACT_NAMES)
    _exact_int(baseline["artifact_bytes"], "baseline_artifact_bytes")
    _exact_int(baseline["artifact_file_count"], "baseline_artifact_file_count")
    require(all(path.is_file() for path in artifact_paths), "baseline_artifact_files")
    require(baseline["artifact_file_count"] == len(artifact_paths), "baseline_artifact_file_count_value")
    require(baseline["artifact_bytes"] == artifact_bytes(fixture_dir), "baseline_artifact_bytes_value")
    checked_cases_path = cases_path or fixture_dir / "cases.json"
    require(checked_cases_path.resolve() == (fixture_dir / "cases.json").resolve(), "baseline_cases_path_anchor")
    for name, expected_meta in CANONICAL_ARTIFACTS.items():
        path = fixture_dir / name
        require(path.stat().st_size == int(expected_meta["size_bytes"]), "baseline_artifact_size_anchor")
        require(_file_sha256(path) == str(expected_meta["sha256"]), "baseline_artifact_digest_anchor")
    checked_baseline_path = baseline_path or fixture_dir / "baseline.json"
    require(_file_sha256(checked_baseline_path) == str(CANONICAL_ARTIFACTS["baseline.json"]["sha256"]), "baseline_file_anchor")
    require(_canonical_digest(baseline) == CANONICAL_BASELINE_CONTENT_SHA256, "baseline_canonical_anchor")
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


def artifact_bytes(fixture_dir: Path = FIXTURE_DIR) -> int:
    return sum((fixture_dir / name).stat().st_size for name in ARTIFACT_NAMES)


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
        validate_baseline(baseline, baseline_path=args.baseline, fixture_dir=FIXTURE_DIR, cases_path=args.cases)
    except (ContractError, OSError, UnicodeError, json.JSONDecodeError, RecursionError, ValueError, TypeError, KeyError, IndexError, MemoryError):
        _print_error("contract")
        return 2
    print(f"image_attachment_lifecycle_validation=ok cases={len(document['cases'])} threshold=null artifact_bytes={artifact_bytes()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
