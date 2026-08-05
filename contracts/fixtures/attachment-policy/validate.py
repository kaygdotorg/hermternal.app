"""Validate the synthetic images-only attachment policy contract.

The validator models the pinned upload boundary without importing Hermes or a
client runtime. It decodes only synthetic data URLs, checks the reviewed magic
signatures and size cap, and keeps diagnostics semantic so fixture execution
cannot retain image bytes, paths, or user filenames.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Iterable


FIXTURE_DIR = Path(__file__).resolve().parent
DEFAULT_CASES_PATH = FIXTURE_DIR / "cases.json"
SCHEMA = "hermternal.fixture.attachment-policy.cases.v1"
CONTRACT = "dashboard-v0.0.1"
PINNED_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
PINNED_TREE = "886db5eb1150f819344d67fedc81aef0caab09ff"
SOURCE_PATH = "hermes_cli/web_server.py"
SOURCE_GIT_BLOB = "1fb3e6131629e7399ef12de78148ac6e7ec58d34"
SOURCE_FILE_SHA256 = "b52cc35523f891b6947fa59ac70516d955e47714877069e5ed3f06544b793c1a"
MAX_IMAGE_BYTES = 25 * 1024 * 1024
MAX_JSON_SCAN_DEPTH = 64
MAX_JSON_SCAN_NODES = 10_000
MAX_RETAINED_TEXT_LENGTH = 4_096
MAX_ERROR_MESSAGE_LENGTH = 240
RESPONSE_FIELDS = ["ok", "path", "name", "bytes", "mime_type"]
STORAGE_ROOT = "HERMES_HOME/images/"
SUPPORTED_IMAGE_MIME_FORMATS = {
    "image/png": frozenset({"png"}),
    "image/jpeg": frozenset({"jpeg"}),
    "image/gif": frozenset({"gif87a", "gif89a"}),
    "image/webp": frozenset({"webp"}),
    "image/bmp": frozenset({"bmp"}),
}

ROOT_KEYS = {
    "schema",
    "contract",
    "hermes_source_sha",
    "hermes_source_tree",
    "source_audit_id",
    "fixture_policy",
    "synthetic_only",
    "route",
    "limits",
    "storage",
    "redaction",
    "source_evidence",
    "cases",
}
ROUTE_KEYS = {"method", "path", "content_type", "body_fields"}
LIMIT_KEYS = {"max_bytes", "mime_prefix", "accepted_extensions", "magic_formats"}
FORMAT_KEYS = {"id", "extension", "prefix_hex"}
FORMAT_OPTIONAL_KEYS = {"offset", "offset_hex"}
STORAGE_KEYS = {"root", "response_fields", "path_policy"}
REDACTION_KEYS = {"diagnostic_format", "forbidden_raw_values", "transcript_policy"}
SOURCE_KEYS = {"path", "git_blob_sha", "file_sha256", "citations"}
CITATION_KEYS = {"id", "line", "marker", "claim"}
CASE_KEYS = {"id", "state", "request", "fixture", "expected", "notes"}
FIXTURE_KEYS = {"decoded_size_override"}
EXPECTED_KEYS = {
    "decision",
    "reason",
    "detected_extension",
    "attachment_state",
    "draft",
    "response_fields",
    "stored_under",
    "filename_stem",
    "diagnostic",
}

EXPECTED_CASE_IDS = (
    "empty-selection",
    "pending-upload",
    "valid-png",
    "valid-jpeg",
    "valid-gif87a",
    "valid-gif89a",
    "valid-webp",
    "valid-bmp",
    "invalid-unsupported-image-mime",
    "invalid-image-mime-mismatch",
    "valid-sanitized-filename",
    "valid-default-filename-omitted",
    "valid-null-filename",
    "invalid-missing-data-url",
    "invalid-non-data-url",
    "invalid-not-base64",
    "invalid-malformed-base64",
    "invalid-base64-parameter-suffix",
    "invalid-base64-parameter-extra",
    "invalid-base64-parameter-repeat",
    "invalid-base64-parameter-case",
    "invalid-noncanonical-base64",
    "invalid-non-image-mime",
    "invalid-empty-payload",
    "invalid-unknown-image-bytes",
    "invalid-png-pdf-polyglot",
    "invalid-jpeg-zip-polyglot",
    "invalid-gif-html-polyglot",
    "invalid-webp-html-polyglot",
    "invalid-bmp-html-polyglot",
    "invalid-oversize",
    "invalid-content-type",
    "invalid-filename-type",
    "interrupted-upload",
    "incompatible-contract",
)

EXPECTED_EXTENSIONS = [".bmp", ".gif", ".jpeg", ".jpg", ".png", ".webp"]
EXPECTED_FORMATS = [
    {
        "id": "webp",
        "extension": ".webp",
        "prefix_hex": "52494646",
        "offset": 8,
        "offset_hex": "57454250",
    },
    {"id": "png", "extension": ".png", "prefix_hex": "89504e470d0a1a0a"},
    {"id": "jpeg", "extension": ".jpg", "prefix_hex": "ffd8ff"},
    {"id": "gif87a", "extension": ".gif", "prefix_hex": "474946383761"},
    {"id": "gif89a", "extension": ".gif", "prefix_hex": "474946383961"},
    {"id": "bmp", "extension": ".bmp", "prefix_hex": "424d"},
]
EXPECTED_CITATIONS = [
    {
        "id": "image-limit",
        "line": 2264,
        "marker": "_CHAT_IMAGE_UPLOAD_MAX_BYTES = 25 * 1024 * 1024",
        "claim": "The selected image upload has a 25 MiB server cap.",
    },
    {
        "id": "image-extensions",
        "line": 2265,
        "marker": '_CHAT_IMAGE_ALLOWED_EXTENSIONS = frozenset({".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"})',
        "claim": "The selected image route permits only the reviewed image extension set.",
    },
    {
        "id": "image-magic",
        "line": 2266,
        "marker": "_CHAT_IMAGE_MAGIC: tuple[tuple[bytes, str], ...] = (",
        "claim": "The server classifies image bytes with fixed magic signatures.",
    },
    {
        "id": "image-decoder",
        "line": 2292,
        "marker": "def _decode_chat_image_upload(payload: ChatImageUpload) -> tuple[bytes, str, str]:",
        "claim": "The server requires an image MIME declaration, enforces the cap, and rejects unknown image bytes.",
    },
    {
        "id": "image-route",
        "line": 2306,
        "marker": '@app.post("/api/chat/image-upload")',
        "claim": "The selected client upload surface is one POST route.",
    },
    {
        "id": "image-response",
        "line": 2344,
        "marker": '"bytes": len(data),',
        "claim": "Successful uploads return status, server path/name, byte count, and declared MIME.",
    },
]

# The order mirrors the pinned implementation: WEBP is checked specially,
# followed by the fixed tuple of PNG, JPEG, GIF, and BMP signatures.
_FORMATS: tuple[tuple[str, bytes | None, int | None, bytes | None, str], ...] = (
    ("webp", b"RIFF", 8, b"WEBP", ".webp"),
    ("png", b"\x89PNG\r\n\x1a\n", None, None, ".png"),
    ("jpeg", b"\xff\xd8\xff", None, None, ".jpg"),
    ("gif87a", b"GIF87a", None, None, ".gif"),
    ("gif89a", b"GIF89a", None, None, ".gif"),
    ("bmp", b"BM", None, None, ".bmp"),
)
_DATA_URL_PAYLOAD_RE = re.compile(r"\A[A-Za-z0-9+/]*={0,2}\Z")
_FOREIGN_SIGNATURES = (
    b"%PDF-",
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"<html",
    b"<!doctype html",
    b"<script",
    b"<svg",
)
_FORMAT_HEADER_ENDS = {
    "png": 8,
    "jpeg": 3,
    "gif87a": 6,
    "gif89a": 6,
    "webp": 12,
    "bmp": 2,
}


class ContractError(ValueError):
    """Raised when fixture data or a policy result violates the contract."""


def _require(condition: bool, message: str) -> None:
    """Raise explicitly so validation remains active under ``python -O``."""

    if not condition:
        raise ContractError(message)


def _strict_equal(actual: Any, expected: Any) -> bool:
    """Compare JSON values without Python's bool/int coercion."""

    if type(actual) is not type(expected):
        return False
    if isinstance(actual, dict):
        return set(actual) == set(expected) and all(
            _strict_equal(actual[key], expected[key]) for key in expected
        )
    if isinstance(actual, list):
        return len(actual) == len(expected) and all(
            _strict_equal(left, right) for left, right in zip(actual, expected)
        )
    return actual == expected


def _check_keys(value: Any, expected: set[str], context: str) -> None:
    """Require an exact object shape and report both missing and extra keys."""

    _require(type(value) is dict, f"{context}: expected object")
    actual = set(value)
    _require(
        actual == expected,
        f"{context}: keys differ; missing={sorted(expected - actual)} extra={sorted(actual - expected)}",
    )


def _check_optional_keys(value: Any, required: set[str], optional: set[str], context: str) -> None:
    """Require all required keys while allowing only declared optional keys."""

    _require(type(value) is dict, f"{context}: expected object")
    actual = set(value)
    allowed = required | optional
    _require(required <= actual, f"{context}: missing required keys")
    _require(actual <= allowed, f"{context}: unknown keys")


def _strict_int(value: Any, context: str) -> None:
    _require(type(value) is int, f"{context}: expected integer")


def _strict_string(value: Any, context: str) -> None:
    _require(type(value) is str, f"{context}: expected string")


def _reject_constant(value: str) -> None:
    raise ContractError(f"non-finite JSON value is not allowed: {value}")


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON keys instead of silently keeping the last value."""

    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate JSON key")
        result[key] = value
    return result


def _scan_finite_json(value: Any) -> None:
    """Reject exponent overflow with bounded, iterative post-parse scanning."""

    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        _require(nodes <= MAX_JSON_SCAN_NODES, "JSON value graph exceeds bounded scan")
        _require(depth <= MAX_JSON_SCAN_DEPTH, "JSON nesting exceeds bounded scan")
        if type(current) is float:
            _require(math.isfinite(current), "non-finite JSON value is not allowed")
        elif type(current) is dict:
            for child in current.values():
                stack.append((child, depth + 1))
        elif type(current) is list:
            for child in current:
                stack.append((child, depth + 1))


def load_document(path: Path = DEFAULT_CASES_PATH) -> dict[str, Any]:
    """Load JSON with duplicate-key, parser-error, and finite-value rejection."""

    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError("invalid UTF-8") from exc
    except OSError as exc:
        raise ContractError("could not read fixture") from exc
    try:
        document = json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_constant=_reject_constant,
        )
    except ContractError:
        raise
    except json.JSONDecodeError as exc:
        raise ContractError("invalid JSON syntax") from exc
    except RecursionError as exc:
        raise ContractError("invalid JSON nesting") from exc
    except ValueError as exc:
        raise ContractError("invalid JSON value") from exc
    _scan_finite_json(document)
    _require(type(document) is dict, "document: expected object")
    return document


def _raw_format_from_bytes(data: bytes) -> tuple[str, str] | None:
    """Return the format selected by the pinned magic-byte checks."""

    head = data[:16]
    for format_id, prefix, offset, marker, extension in _FORMATS:
        if offset is not None:
            if prefix is not None and head.startswith(prefix) and head[offset : offset + len(marker or b"")] == marker:
                return format_id, extension
        elif prefix is not None and head.startswith(prefix):
            return format_id, extension
    return None


def _foreign_prefix(value: bytes) -> bool:
    """Identify only an obvious foreign payload at a structural boundary."""

    lowered = value[:32].lower()
    return any(lowered.startswith(marker.lower()) for marker in _FOREIGN_SIGNATURES)


def _validated_format_end(data: bytes, format_id: str) -> int | None:
    """Return a trusted image terminator, not an arbitrary trailing-byte offset."""

    if format_id == "png":
        cursor = 8
        while cursor + 12 <= len(data):
            length = int.from_bytes(data[cursor : cursor + 4], "big")
            end = cursor + 12 + length
            if end > len(data):
                return None
            if data[cursor + 4 : cursor + 8] == b"IEND" and length == 0:
                return end
            cursor = end
        return None
    if format_id == "jpeg":
        end = data.find(b"\xff\xd9", 3)
        return end + 2 if end >= 0 else None
    if format_id in {"gif87a", "gif89a"}:
        end = data.find(b"\x3b", 6)
        return end + 1 if end >= 0 else None
    if format_id == "webp" and len(data) >= 12:
        riff_size = int.from_bytes(data[4:8], "little")
        end = 8 + riff_size
        if 12 <= end <= len(data):
            return end
        return None
    if format_id == "bmp" and len(data) >= 6:
        file_size = int.from_bytes(data[2:6], "little")
        if 2 <= file_size <= len(data):
            return file_size
    return None


def _has_obvious_polyglot(data: bytes, format_id: str) -> bool:
    """Reject foreign bytes only at a suffix/terminator boundary.

    Valid format-internal chunks are not scanned for marker text. This keeps
    legitimate image payloads with arbitrary chunk contents accepted while
    rejecting the deterministic PNG+PDF, JPEG+ZIP, and image+HTML polyglots.
    """

    header_end = _FORMAT_HEADER_ENDS[format_id]
    if _foreign_prefix(data[header_end:]):
        return True
    terminal_end = _validated_format_end(data, format_id)
    return terminal_end is not None and _foreign_prefix(data[terminal_end:])


def _format_from_bytes(data: bytes) -> tuple[str, str] | None:
    """Return a recognized format only when it is not an obvious polyglot."""

    detected = _raw_format_from_bytes(data)
    if detected is None:
        return None
    format_id, extension = detected
    if _has_obvious_polyglot(data, format_id):
        return None
    return format_id, extension


def _sanitize_filename_stem(filename: str | None) -> str:
    """Mirror the pinned server's safe basename/stem policy without a path."""

    candidate = Path(str(filename or "").strip()).name
    candidate = re.sub(r"[\x00-\x1f]+", "_", candidate)
    candidate = candidate.strip().strip(".")
    candidate = candidate or "pasted-image"
    stem = Path(candidate).stem or "pasted-image"
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", stem).strip("._-")
    return stem or "pasted-image"


def _parse_data_url(data_url: Any) -> tuple[bytes, str] | tuple[None, str]:
    """Decode exactly ``data:image/<supported>;base64,<canonical>``."""

    if type(data_url) is not str:
        return None, "malformed_request"
    text = data_url
    if not text.startswith("data:") or "," not in text:
        return None, "invalid_data_url"
    header, encoded = text.split(",", 1)
    if not header.startswith("data:"):
        return None, "invalid_data_url"
    media = header[5:]
    mime_type = media.split(";", 1)[0]
    if not mime_type.startswith("image/"):
        if mime_type.lower().startswith("image/"):
            return None, "invalid_data_url"
        return None, "not_image"
    if mime_type not in SUPPORTED_IMAGE_MIME_FORMATS:
        if mime_type.lower() in SUPPORTED_IMAGE_MIME_FORMATS:
            return None, "invalid_data_url"
        return None, "unsupported_image_mime"
    parameters = media.split(";")
    if len(parameters) == 1:
        return None, "not_base64"
    if parameters != [mime_type, "base64"]:
        return None, "invalid_data_url"
    if _DATA_URL_PAYLOAD_RE.fullmatch(encoded) is None:
        return None, "invalid_base64"
    try:
        data = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return None, "invalid_base64"
    canonical = base64.b64encode(data).decode("ascii")
    if canonical != encoded:
        return None, "noncanonical_base64"
    return data, mime_type


def _state_outcome(
    decision: str,
    reason: str,
    attachment_state: str,
    draft: str,
    diagnostic: str,
) -> dict[str, Any]:
    return {
        "decision": decision,
        "reason": reason,
        "detected_extension": None,
        "attachment_state": attachment_state,
        "draft": draft,
        "response_fields": [],
        "stored_under": None,
        "filename_stem": None,
        "diagnostic": diagnostic,
    }


def _rejected(reason: str) -> dict[str, Any]:
    return _state_outcome(
        "rejected",
        reason,
        "failed",
        "preserved",
        f"attachment[rejected;reason={reason}]",
    )


def evaluate_case(case: dict[str, Any]) -> dict[str, Any]:
    """Compute one deterministic policy outcome from a synthetic case."""

    state = case["state"]
    if state == "empty":
        return _state_outcome(
            "no_attachment",
            "empty_selection",
            "empty",
            "unchanged",
            "attachment[empty]",
        )
    if state == "pending":
        return _state_outcome(
            "pending",
            "upload_pending",
            "pending",
            "preserved",
            "attachment[pending]",
        )
    if state == "interrupted":
        return _state_outcome(
            "interrupted",
            "upload_interrupted",
            "interrupted",
            "preserved",
            "attachment[interrupted]",
        )
    if state == "incompatible":
        return _state_outcome(
            "blocked",
            "incompatible_contract",
            "blocked",
            "preserved",
            "attachment[blocked;reason=incompatible_contract]",
        )

    _require(state == "ready", f"case {case['id']}: unknown state {state!r}")
    request = case["request"]
    _require(type(request) is dict, f"case {case['id']}: ready request must be an object")
    if type(request.get("content_type")) is not str:
        return _rejected("malformed_request")
    if request["content_type"] != "application/json":
        return _rejected("unsupported_content_type")
    filename = request.get("filename")
    if filename is not None and type(filename) is not str:
        return _rejected("malformed_request")

    data, parse_result = _parse_data_url(request.get("data_url"))
    if data is None:
        return _rejected(parse_result)
    if not parse_result.lower().startswith("image/"):
        return _rejected("not_image")

    override = case["fixture"]["decoded_size_override"]
    decoded_size = len(data) if override is None else override
    if decoded_size > MAX_IMAGE_BYTES:
        return _rejected("too_large")

    raw_detected = _raw_format_from_bytes(data)
    if raw_detected is None:
        return _rejected("unsupported_image_type")
    format_id, extension = raw_detected
    if _has_obvious_polyglot(data, format_id):
        return _rejected("polyglot_image")
    if format_id not in SUPPORTED_IMAGE_MIME_FORMATS[parse_result]:
        return _rejected("mime_mismatch")
    stem = _sanitize_filename_stem(filename)
    return {
        "decision": "accepted",
        "reason": "accepted",
        "detected_extension": extension,
        "attachment_state": "accepted",
        "draft": "unchanged",
        "response_fields": list(RESPONSE_FIELDS),
        "stored_under": STORAGE_ROOT,
        "filename_stem": stem,
        "diagnostic": f"attachment[accepted;format={format_id};bytes={decoded_size}]",
    }


def _iter_strings(value: Any) -> Iterable[str]:
    if type(value) is str:
        yield value
    elif type(value) is dict:
        for key, child in value.items():
            yield from _iter_strings(key)
            yield from _iter_strings(child)
    elif type(value) is list:
        for child in value:
            yield from _iter_strings(child)


_RETAINED_DATA_URL_RE = re.compile(
    r"(?i)\bdata:image/[a-z0-9.+-]+;base64,[A-Za-z0-9+/]+={0,2}"
)
_RETAINED_BASE64_RE = re.compile(
    r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{8,}={1,2}(?![A-Za-z0-9+/])"
)
_RETAINED_PATH_RE = re.compile(
    r"(?i)(?:file://|(?:^|[\s(\"'])/(?:users|private|tmp|var|home|etc|opt|root)(?:/|$)|(?:^|[\s(\"'])[a-z]:[\\/]|(?:^|[\s(\"'])\\\\)"
)
_RETAINED_FILENAME_RE = re.compile(
    r"(?i)(?<![\w.-])(?:\.\.?[\\/][^\r\n]*|[a-z0-9_.-]+[\\/][^\r\n]*|[a-z0-9_.-]+)\.(?:png|jpg|jpeg|gif|webp|bmp|tiff|pdf)(?![\w.-])"
)


def _validate_retained_text(value: Any, context: str) -> None:
    """Reject raw attachment/path material in retained free-form metadata."""

    _strict_string(value, context)
    _require(len(value) <= MAX_RETAINED_TEXT_LENGTH, f"{context}: retained text is too long")
    _require(_RETAINED_DATA_URL_RE.search(value) is None, f"{context}: raw data URL is not retained")
    _require(_RETAINED_BASE64_RE.search(value) is None, f"{context}: raw base64 is not retained")
    _require(_RETAINED_PATH_RE.search(value) is None, f"{context}: raw path is not retained")
    _require(_RETAINED_FILENAME_RE.search(value) is None, f"{context}: user filename is not retained")


def _validate_no_credential_material(document: dict[str, Any]) -> None:
    """Reject values that look like retained credentials or raw auth headers."""

    for value in _iter_strings(document):
        _require("Authorization:" not in value, "fixture contains an Authorization header")
        _require("Bearer " not in value, "fixture contains a bearer value")
        _require("Cookie:" not in value, "fixture contains a cookie header")
        _require(not re.search(r"\bsk-[A-Za-z0-9_-]{8,}\b", value), "fixture contains a secret-shaped value")
        _require(not re.search(r"\bgh[pousr]_[A-Za-z0-9]{12,}\b", value), "fixture contains a token-shaped value")


def validate_document(document: dict[str, Any]) -> None:
    """Validate the complete root schema, source metadata, cases, and outcomes."""

    _check_keys(document, ROOT_KEYS, "document")
    _require(document["schema"] == SCHEMA, "document.schema: wrong schema")
    _require(document["contract"] == CONTRACT, "document.contract: wrong contract")
    _require(document["hermes_source_sha"] == PINNED_SHA, "document.hermes_source_sha: wrong revision")
    _require(document["hermes_source_tree"] == PINNED_TREE, "document.hermes_source_tree: wrong tree")
    _require(document["source_audit_id"] == "attachment-policy-c13-f5be9236", "document.source_audit_id: wrong id")
    _require(document["fixture_policy"] == "synthetic_markers_only", "document.fixture_policy: wrong policy")
    _require(document["synthetic_only"] is True, "document.synthetic_only: must be true")

    _check_keys(document["route"], ROUTE_KEYS, "route")
    _require(document["route"]["method"] == "POST", "route.method: wrong method")
    _require(document["route"]["path"] == "/api/chat/image-upload", "route.path: wrong path")
    _require(document["route"]["content_type"] == "application/json", "route.content_type: wrong type")
    _require(document["route"]["body_fields"] == ["data_url", "filename"], "route.body_fields: wrong fields")

    _check_keys(document["limits"], LIMIT_KEYS, "limits")
    _strict_int(document["limits"]["max_bytes"], "limits.max_bytes")
    _require(document["limits"]["max_bytes"] == MAX_IMAGE_BYTES, "limits.max_bytes: wrong cap")
    _require(document["limits"]["mime_prefix"] == "image/", "limits.mime_prefix: wrong prefix")
    _require(document["limits"]["accepted_extensions"] == EXPECTED_EXTENSIONS, "limits.accepted_extensions: drift")
    _require(document["limits"]["magic_formats"] == EXPECTED_FORMATS, "limits.magic_formats: drift")
    for index, format_record in enumerate(document["limits"]["magic_formats"]):
        context = f"limits.magic_formats[{index}]"
        _require(type(format_record) is dict, f"{context}: expected object")
        _require(set(format_record) <= FORMAT_KEYS | FORMAT_OPTIONAL_KEYS, f"{context}: unknown format fields")
        _require(set(format_record) >= FORMAT_KEYS, f"{context}: missing shared format fields")
        _strict_string(format_record["id"], f"{context}.id")
        _strict_string(format_record["extension"], f"{context}.extension")
        _strict_string(format_record["prefix_hex"], f"{context}.prefix_hex")
        has_offset = "offset" in format_record
        has_offset_hex = "offset_hex" in format_record
        _require(has_offset == has_offset_hex, f"{context}: offset fields must appear together")
        if has_offset:
            _strict_int(format_record["offset"], f"{context}.offset")
            _strict_string(format_record["offset_hex"], f"{context}.offset_hex")

    _check_keys(document["storage"], STORAGE_KEYS, "storage")
    _require(document["storage"]["root"] == STORAGE_ROOT, "storage.root: wrong root")
    _require(document["storage"]["response_fields"] == RESPONSE_FIELDS, "storage.response_fields: drift")
    _require(
        document["storage"]["path_policy"] == "server_generated_timestamp_nonce_sanitized_stem_extension",
        "storage.path_policy: drift",
    )

    _check_keys(document["redaction"], REDACTION_KEYS, "redaction")
    _require(document["redaction"]["diagnostic_format"] == "semantic_only", "redaction.diagnostic_format: drift")
    _require(
        document["redaction"]["forbidden_raw_values"] == ["data_url", "absolute_path", "base64_payload", "user_filename"],
        "redaction.forbidden_raw_values: drift",
    )
    _require(document["redaction"]["transcript_policy"] == "image_bytes_not_stored", "redaction.transcript_policy: drift")

    _check_keys(document["source_evidence"], SOURCE_KEYS, "source_evidence")
    _require(document["source_evidence"]["path"] == SOURCE_PATH, "source_evidence.path: drift")
    _require(document["source_evidence"]["git_blob_sha"] == SOURCE_GIT_BLOB, "source_evidence.git_blob_sha: drift")
    _require(document["source_evidence"]["file_sha256"] == SOURCE_FILE_SHA256, "source_evidence.file_sha256: drift")
    _require(_strict_equal(document["source_evidence"]["citations"], EXPECTED_CITATIONS), "source_evidence.citations: drift")
    for index, citation in enumerate(document["source_evidence"]["citations"]):
        _check_keys(citation, CITATION_KEYS, f"source_evidence.citations[{index}]")
        _strict_int(citation["line"], f"source_evidence.citations[{index}].line")
        _require(citation["line"] > 0, f"source_evidence.citations[{index}].line: must be positive")
        _strict_string(citation["marker"], f"source_evidence.citations[{index}].marker")
        _validate_retained_text(citation["claim"], f"source_evidence.citations[{index}].claim")

    cases = document["cases"]
    _require(type(cases) is list, "cases: expected array")
    case_ids = tuple(case.get("id") if type(case) is dict else None for case in cases)
    _require(case_ids == EXPECTED_CASE_IDS, "cases: id order or inventory drift")
    for index, case in enumerate(cases):
        context = f"cases[{index}]"
        _check_keys(case, CASE_KEYS, context)
        _strict_string(case["id"], f"{context}.id")
        _strict_string(case["state"], f"{context}.state")
        _require(case["state"] in {"empty", "pending", "ready", "interrupted", "incompatible"}, f"{context}.state: unknown state")
        _check_keys(case["fixture"], FIXTURE_KEYS, f"{context}.fixture")
        override = case["fixture"]["decoded_size_override"]
        if override is not None:
            _strict_int(override, f"{context}.fixture.decoded_size_override")
            _require(override > 0, f"{context}.fixture.decoded_size_override: must be positive")
        _validate_retained_text(case["notes"], f"{context}.notes")
        _require(bool(case["notes"].strip()), f"{context}.notes: must not be empty")

        if case["state"] == "empty":
            _require(case["request"] is None, f"{context}.request: empty state must have no request")
        elif case["state"] == "ready":
            _check_optional_keys(
                case["request"],
                {"content_type", "data_url"},
                {"filename"},
                f"{context}.request",
            )
        elif case["state"] == "pending" or case["state"] == "interrupted":
            _check_keys(case["request"], {"phase"}, f"{context}.request")
            _strict_string(case["request"]["phase"], f"{context}.request.phase")
        else:
            _check_keys(case["request"], {"contract"}, f"{context}.request")
            _strict_string(case["request"]["contract"], f"{context}.request.contract")

        _check_keys(case["expected"], EXPECTED_KEYS, f"{context}.expected")
        _require(_strict_equal(evaluate_case(case), case["expected"]), f"{context}: expected outcome does not match policy")
        if case["id"] != "invalid-oversize":
            _require(override is None, f"{context}.fixture: only invalid-oversize may use a size override")
        else:
            _require(override == MAX_IMAGE_BYTES + 1, f"{context}.fixture: wrong size boundary")

    _validate_no_credential_material(document)


def _git_environment() -> dict[str, str]:
    """Prevent a source verification call from inheriting object indirection."""

    environment = dict(os.environ)
    for key in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "GIT_GRAFT_FILE",
        "GIT_SHALLOW_FILE",
        "GIT_IMPLICIT_WORK_TREE",
        "GIT_REPLACE_REF_BASE",
    ):
        environment.pop(key, None)
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment["GIT_NO_LAZY_FETCH"] = "1"
    return environment


def _run_git(root: Path, args: list[str], raw: bool = False) -> bytes | str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        env=_git_environment(),
    )
    if result.returncode != 0:
        raise ContractError("git verification failed")
    return result.stdout if raw else result.stdout.decode("utf-8").strip()


def validate_source(source_root: Path, document: dict[str, Any]) -> None:
    """Verify provenance and markers from immutable pinned Git blob bytes."""

    root = source_root.resolve()
    _require(root.is_dir(), "source root is not a directory")
    checkout_root = Path(_run_git(root, ["rev-parse", "--show-toplevel"])).resolve()
    _require(checkout_root == root, "source root is not the exact checkout root")
    commit = _run_git(root, ["rev-parse", "--verify", f"{PINNED_SHA}^{{commit}}"])
    _require(commit == PINNED_SHA, "source commit does not match the pinned revision")
    tree = _run_git(root, ["rev-parse", "--verify", f"{PINNED_SHA}^{{tree}}"])
    _require(tree == PINNED_TREE, "source tree does not match the pinned tree")
    blob = _run_git(root, ["rev-parse", "--verify", f"{PINNED_SHA}:{SOURCE_PATH}"])
    _require(blob == SOURCE_GIT_BLOB, "source blob does not match the recorded Git object")
    kind = _run_git(root, ["cat-file", "-t", blob])
    _require(kind == "blob", "source citation did not resolve to a blob")
    data = _run_git(root, ["cat-file", "blob", blob], raw=True)
    _require(hashlib.sha256(data).hexdigest() == SOURCE_FILE_SHA256, "source file digest mismatch")
    text = data.decode("utf-8")
    lines = text.splitlines()
    for citation in document["source_evidence"]["citations"]:
        occurrences = text.count(citation["marker"])
        _require(occurrences == 1, f"source marker is not unique: {citation['id']}")
        line_number = citation["line"]
        _require(
            1 <= line_number <= len(lines) and citation["marker"] in lines[line_number - 1],
            f"source marker line drifted: {citation['id']}",
        )
    _require(text.count('@app.post("/api/chat/image-upload")') == 1, "image route marker count drifted")


def validate_mutations(document: dict[str, Any]) -> int:
    """Run a small executable mutation inventory against the strict schema."""

    mutations: list[tuple[str, Any]] = []

    schema = json.loads(json.dumps(document))
    schema["schema"] = "hermternal.fixture.other/v1"
    mutations.append(("schema", schema))

    contract = json.loads(json.dumps(document))
    contract["contract"] = "dashboard-v0.0.2"
    mutations.append(("contract", contract))

    revision = json.loads(json.dumps(document))
    revision["hermes_source_sha"] = "0" * 40
    mutations.append(("revision", revision))

    synthetic = json.loads(json.dumps(document))
    synthetic["synthetic_only"] = False
    mutations.append(("synthetic", synthetic))

    route = json.loads(json.dumps(document))
    route["route"]["path"] = "/api/files"
    mutations.append(("route", route))

    cap = json.loads(json.dumps(document))
    cap["limits"]["max_bytes"] = True
    mutations.append(("cap", cap))

    format_data = json.loads(json.dumps(document))
    format_data["limits"]["magic_formats"].pop()
    mutations.append(("format", format_data))

    storage = json.loads(json.dumps(document))
    storage["storage"]["root"] = "/tmp/images/"
    mutations.append(("storage", storage))

    redaction = json.loads(json.dumps(document))
    redaction["redaction"]["transcript_policy"] = "stored"
    mutations.append(("redaction", redaction))

    source_marker = json.loads(json.dumps(document))
    source_marker["source_evidence"]["citations"][0]["marker"] = "wrong marker"
    mutations.append(("source-marker", source_marker))

    reordered = json.loads(json.dumps(document))
    reordered["cases"] = list(reversed(reordered["cases"]))
    mutations.append(("case-order", reordered))

    outcome = json.loads(json.dumps(document))
    outcome["cases"][2]["expected"]["reason"] = "rejected"
    mutations.append(("outcome", outcome))

    duplicate = json.loads(json.dumps(document))
    duplicate["cases"][3]["id"] = duplicate["cases"][2]["id"]
    mutations.append(("duplicate-id", duplicate))

    unknown = json.loads(json.dumps(document))
    unknown["unexpected"] = True
    mutations.append(("unknown-root", unknown))

    for name, mutated in mutations:
        try:
            validate_document(mutated)
        except ContractError:
            continue
        raise ContractError(f"mutation unexpectedly validated: {name}")
    return len(mutations)


def _parse_cli(argv: list[str]) -> tuple[Path, Path | None]:
    """Parse the two supported options without argparse stderr side effects."""

    cases_path = DEFAULT_CASES_PATH
    source_root: Path | None = None
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument in {"-h", "--help"}:
            raise ContractError("usage: validate.py [--cases PATH] [--source-root PATH]")
        if argument in {"--cases", "--source-root"}:
            if index + 1 >= len(argv):
                raise ContractError("cli-arguments: option needs a value")
            value = Path(argv[index + 1])
            if argument == "--cases":
                cases_path = value
            else:
                source_root = value
            index += 2
            continue
        raise ContractError("cli-arguments: unknown argument")
    return cases_path, source_root


def _print_structured_error(code: str, message: str) -> None:
    """Emit one bounded semantic error without raw paths or input material."""

    safe_message = " ".join(message.split())[:MAX_ERROR_MESSAGE_LENGTH]
    print(json.dumps({"error": {"code": code, "message": safe_message}}, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    """Validate the checked-in fixture and emit one controlled result line."""

    try:
        cases_path, source_root = _parse_cli(list(sys.argv[1:] if argv is None else argv))
        document = load_document(cases_path)
        validate_document(document)
        if source_root is not None:
            validate_source(source_root, document)
        mutation_count = validate_mutations(document)
        print(
            "attachment_policy_validation=ok "
            f"cases={len(document['cases'])} mutations={mutation_count}"
        )
        return 0
    except ContractError as exc:
        _print_structured_error("contract", str(exc))
        return 1
    except (OSError, TypeError, ValueError, UnicodeError, RecursionError):
        _print_structured_error("runtime", "validation failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
