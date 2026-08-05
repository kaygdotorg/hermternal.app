"""Strict validation for the offline synthetic /api/pty contract.

The fixture is deliberately a byte adapter proof, not a PTY implementation. Hex
keeps binary data lossless, while closed object schemas make contract drift fail
before a future web client can silently reinterpret it.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import re
import statistics
import sys
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent
DEFAULT_FIXTURE = ROOT / "pty-contract-fixtures.json"
DEFAULT_BASELINE = ROOT / "validation-baseline.json"
SOURCE_AUDIT_ROOT = ROOT.parent / "source-audit" / "pty-attach"
PINNED_HERMES_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
MAX_JSON_DEPTH = 128
MAX_ERROR_LENGTH = 240
ERROR_SUFFIX = "... [truncated]"
SYNTHETIC_REF = re.compile(r"^synthetic-[a-z0-9-]+$")
REPLAY_SEGMENT_PROVENANCE = (
    ("synthetic-output-old", "evicted-prefix"),
    ("synthetic-output-new", "retained-tail"),
)
HEX_VALUE = re.compile(r"^[0-9a-f]*$")
SHA1_VALUE = re.compile(r"^[0-9a-f]{40}$")
SHA256_VALUE = re.compile(r"^[0-9a-f]{64}$")
BASELINE_ARTIFACT_NAMES = ("README.md", "pty-contract-fixtures.json", "validate.py", "test_validate.py")
SOURCE_AUDIT_ARTIFACTS = {
    "README.md": (
        "contracts/fixtures/source-audit/pty-attach/README.md",
        "documentation",
        "3f1172482e5b0373ebbfbc9b4b5a85104a324fa801b9fe6f9da3a5b2a25e586b",
        7940,
    ),
    "pty-attach-fixtures.json": (
        "contracts/fixtures/source-audit/pty-attach/pty-attach-fixtures.json",
        "hermternal.fixture.pty-attach.v1",
        "0e32d184fa2ef693a126ecfc284eb6566fd2b0e55f662003c3f36f2209456d7a",
        16276,
    ),
    "source-evidence.json": (
        "contracts/fixtures/source-audit/pty-attach/source-evidence.json",
        "hermternal.source-audit.pty-attach.v1",
        "90291fcff446327a2c5f13758d3d6d78efe076ebbc78fb5fc72f1c5d7bd97fc3",
        10812,
    ),
}
FORBIDDEN_TEXT = (
    "api_key",
    "api-key",
    "authorization",
    "bearer",
    "cookie",
    "credential",
    "hostname",
    "password",
    "passwd",
    "secret",
    "ssh://",
    "http://",
    "https://",
)

EXPECTED_CASES = {
    "raw-bytes-preserve": "raw-bytes",
    "raw-bytes-boundaries": "raw-bytes-multiframe",
    "resize-bounds": "resize",
    "resize-rejection": "resize-rejection",
    "legacy-missing-attach": "legacy-lifecycle",
    "legacy-empty-attach": "legacy-lifecycle",
    "attach-keepalive": "attach-lifecycle",
    "replacement-4409": "replacement",
    "process-exit-4410": "process-exit",
    "detach-window": "detach-window",
    "registry-cap": "registry-cap",
    "replay-newest-tail": "replay-ring",
    "replay-action-exclusion": "replay-action-exclusion",
    "replay-live-race": "replay-live-race",
    "no-byte-logging": "no-byte-logging",
}


def bound_error(text: str) -> str:
    """Keep direct and CLI validation failures bounded for safe diagnostics."""

    if len(text) <= MAX_ERROR_LENGTH:
        return text
    keep = MAX_ERROR_LENGTH - len(ERROR_SUFFIX)
    prefix_length = keep // 2
    suffix_length = keep - prefix_length
    return text[:prefix_length] + ERROR_SUFFIX + text[-suffix_length:]


class ValidationError(ValueError):
    """A deterministic, user-facing fixture validation failure."""

    def __init__(self, message: object) -> None:
        super().__init__(bound_error(str(message)))


def fail(path: str, message: str) -> None:
    raise ValidationError(f"{path}: {message}")


def exact_keys(value: Any, keys: set[str], path: str) -> dict[str, Any]:
    if type(value) is not dict:
        fail(path, "must be an object")
    actual = set(value)
    if actual != keys:
        missing = sorted(keys - actual)
        extra = sorted(actual - keys)
        detail: list[str] = []
        if missing:
            detail.append(f"missing={missing}")
        if extra:
            detail.append(f"extra={extra}")
        fail(path, "object keys differ (" + ", ".join(detail) + ")")
    return value


def expect_string(value: Any, path: str, expected: str | None = None) -> str:
    if type(value) is not str:
        fail(path, "must be a string")
    if expected is not None and value != expected:
        fail(path, f"must equal {expected!r}")
    return value


def expect_bool(value: Any, path: str, expected: bool | None = None) -> bool:
    if type(value) is not bool:
        fail(path, "must be a boolean")
    if expected is not None and value is not expected:
        fail(path, f"must equal {expected!r}")
    return value


def expect_int(value: Any, path: str, expected: int | None = None) -> int:
    if type(value) is not int:
        fail(path, "must be an integer")
    if expected is not None and value != expected:
        fail(path, f"must equal {expected}")
    return value


def expect_float(value: Any, path: str) -> float:
    if type(value) is not float or not math.isfinite(value):
        fail(path, "must be a finite JSON number")
    return value


def expect_exact_value(value: Any, path: str, expected: Any) -> Any:
    """Compare a fixture value without Python bool/int/float coercion."""

    if type(value) is not type(expected) or value != expected:
        fail(path, f"must equal the exact JSON value {expected!r}")
    return value


def expect_none(value: Any, path: str) -> None:
    if value is not None:
        fail(path, "must be null")
    return None


def expect_list(value: Any, path: str) -> list[Any]:
    if type(value) is not list:
        fail(path, "must be an array")
    return value


def expect_hex(value: Any, path: str, *, one_byte: bool = False) -> str:
    text = expect_string(value, path)
    if len(text) % 2 or HEX_VALUE.fullmatch(text) is None:
        fail(path, "must be lowercase hexadecimal with an even length")
    if one_byte and len(text) != 2:
        fail(path, "must contain exactly one byte")
    return text


def expect_commit_sha(value: Any, path: str, expected: str | None = None) -> str:
    text = expect_string(value, path)
    if SHA1_VALUE.fullmatch(text) is None:
        fail(path, "must be a lowercase 40-character Git commit SHA")
    if expected is not None and text != expected:
        fail(path, f"must equal {expected!r}")
    return text


def expect_sha256(value: Any, path: str, expected: str | None = None) -> str:
    text = expect_string(value, path)
    if SHA256_VALUE.fullmatch(text) is None:
        fail(path, "must be a lowercase SHA-256 digest")
    if expected is not None and text != expected:
        fail(path, f"must equal {expected!r}")
    return text


def expect_synthetic_ref(value: Any, path: str) -> str:
    text = expect_string(value, path)
    if SYNTHETIC_REF.fullmatch(text) is None:
        fail(path, "must be a synthetic reference")
    suffix = text.removeprefix("synthetic-")
    if suffix and len(suffix) % 2 == 0 and HEX_VALUE.fullmatch(suffix) is not None:
        fail(path, "must not encode payload bytes in a synthetic reference")
    return text


def _validate_json_tree(value: Any, context: str = "document", depth: int = 0) -> None:
    """Reject unsupported or excessively deep JSON-shaped values before schemas."""

    if depth > MAX_JSON_DEPTH:
        fail(context, f"maximum JSON nesting depth exceeded ({MAX_JSON_DEPTH})")
    if type(value) is dict:
        for key, child in value.items():
            if type(key) is not str:
                fail(context, "object keys must be strings")
            _validate_json_tree(child, f"{context}.{key}", depth + 1)
        return
    if type(value) is list:
        for index, child in enumerate(value):
            _validate_json_tree(child, f"{context}[{index}]", depth + 1)
        return
    if type(value) is float:
        if not math.isfinite(value):
            fail(context, "non-finite number is not allowed")
        return
    if value is None or type(value) in (str, bool, int):
        return
    fail(context, f"unsupported JSON value type {type(value).__name__}")


def scan_for_forbidden_text(value: Any, path: str = "root") -> None:
    """Reject secret-shaped prose with bounded, cycle-safe traversal.

    Fixtures originate as JSON, but mutation tests pass Python objects directly.
    Iterative traversal keeps malformed deep structures from escaping as a
    ``RecursionError`` and rejects object cycles before they can loop forever.
    """

    stack: list[tuple[Any, str, int]] = [(value, path, 0)]
    seen_containers: set[int] = set()
    while stack:
        current, current_path, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            fail(current_path, f"exceeds maximum validation depth {MAX_JSON_DEPTH}")
        if type(current) is dict:
            identity = id(current)
            if identity in seen_containers:
                fail(current_path, "contains a repeated or cyclic container reference")
            seen_containers.add(identity)
            for key, child in reversed(list(current.items())):
                stack.append((child, f"{current_path}.{key}", depth + 1))
        elif type(current) is list:
            identity = id(current)
            if identity in seen_containers:
                fail(current_path, "contains a repeated or cyclic container reference")
            seen_containers.add(identity)
            for index in range(len(current) - 1, -1, -1):
                stack.append((current[index], f"{current_path}[{index}]", depth + 1))
        elif type(current) is str:
            lowered = current.lower()
            for marker in FORBIDDEN_TEXT:
                if marker in lowered:
                    fail(current_path, f"contains forbidden marker {marker!r}")


def clamp(value: int, lower: int, upper: int) -> int:
    return max(lower, min(upper, value))


def resize_control(prefix_hex: str, suffix_hex: str, cols: int, rows: int) -> str:
    return (
        bytes.fromhex(prefix_hex)
        + f"{cols};{rows}".encode("ascii")
        + bytes.fromhex(suffix_hex)
    ).hex()


def sha256_file(path: Path, context: str) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        fail(context, f"cannot read bound artifact: {exc}")
    raise AssertionError("unreachable")


def artifact_manifest_digest(file_digests: dict[str, str], file_sizes: dict[str, int]) -> str:
    manifest = "".join(
        f"{name}\0{file_digests[name]}\0{file_sizes[name]}\n" for name in BASELINE_ARTIFACT_NAMES
    )
    return hashlib.sha256(manifest.encode("utf-8")).hexdigest()


def validate_source_audit(value: Any) -> None:
    """Bind this byte contract to the checked-in immutable source-audit snapshot."""

    path = "source_audit"
    audit = exact_keys(value, {"directory", "pinned_commit", "artifacts"}, path)
    expect_string(audit["directory"], f"{path}.directory", "contracts/fixtures/source-audit/pty-attach")
    pinned = exact_keys(audit["pinned_commit"], {"sha", "snapshot"}, f"{path}.pinned_commit")
    expect_commit_sha(pinned["sha"], f"{path}.pinned_commit.sha", PINNED_HERMES_SHA)
    expect_string(pinned["snapshot"], f"{path}.pinned_commit.snapshot", "immutable-source-audit")

    artifacts = exact_keys(audit["artifacts"], set(SOURCE_AUDIT_ARTIFACTS), f"{path}.artifacts")
    for name, (relative_path, schema, expected_digest, expected_size) in SOURCE_AUDIT_ARTIFACTS.items():
        artifact_path = f"{path}.artifacts.{name}"
        descriptor = exact_keys(
            artifacts[name],
            {"path", "schema", "sha256", "size_bytes"},
            artifact_path,
        )
        expect_string(descriptor["path"], f"{artifact_path}.path", relative_path)
        expect_string(descriptor["schema"], f"{artifact_path}.schema", schema)
        expect_sha256(descriptor["sha256"], f"{artifact_path}.sha256", expected_digest)
        expect_int(descriptor["size_bytes"], f"{artifact_path}.size_bytes", expected_size)
        actual_path = SOURCE_AUDIT_ROOT / name
        actual_size = actual_path.stat().st_size if actual_path.exists() else -1
        if actual_size != expected_size:
            fail(f"{artifact_path}.size_bytes", f"must match the immutable artifact size {actual_size}")
        actual_digest = sha256_file(actual_path, artifact_path)
        if actual_digest != expected_digest:
            fail(f"{artifact_path}.sha256", "does not match the immutable artifact digest")

    source_evidence = load_fixture(SOURCE_AUDIT_ROOT / "source-evidence.json")
    evidence = exact_keys(
        source_evidence,
        {"schema", "contract", "source", "files", "observations", "redaction"},
        f"{path}.source_evidence",
    )
    expect_string(
        evidence["schema"],
        f"{path}.source_evidence.schema",
        "hermternal.source-audit.pty-attach.v1",
    )
    expect_string(evidence["contract"], f"{path}.source_evidence.contract", "dashboard-v0.0.1")
    source = exact_keys(
        evidence["source"],
        {"repository", "revision", "revision_url", "note"},
        f"{path}.source_evidence.source",
    )
    expect_string(source["repository"], f"{path}.source_evidence.source.repository", "NousResearch/hermes-agent")
    expect_string(source["revision"], f"{path}.source_evidence.source.revision", PINNED_HERMES_SHA)
    expect_string(
        source["revision_url"],
        f"{path}.source_evidence.source.revision_url",
        f"https://github.com/NousResearch/hermes-agent/commit/{PINNED_HERMES_SHA}",
    )
    expect_string(source["note"], f"{path}.source_evidence.source.note")

    attach_fixture = load_fixture(SOURCE_AUDIT_ROOT / "pty-attach-fixtures.json")
    attach = exact_keys(
        attach_fixture,
        {"schema", "contract", "source_revision", "surface", "synthetic", "redaction", "retention", "cases"},
        f"{path}.attach_fixture",
    )
    expect_string(attach["schema"], f"{path}.attach_fixture.schema", "hermternal.fixture.pty-attach.v1")
    expect_string(attach["contract"], f"{path}.attach_fixture.contract", "dashboard-v0.0.1")
    expect_string(attach["source_revision"], f"{path}.attach_fixture.source_revision", PINNED_HERMES_SHA)
    expect_string(attach["surface"], f"{path}.attach_fixture.surface", "web-only")
    expect_bool(attach["synthetic"], f"{path}.attach_fixture.synthetic", True)


def segment_bytes(segment: dict[str, Any], path: str) -> bytes:
    keys = {"ref", "byte_hex", "repeat"}
    if type(segment) is dict and "role" in segment:
        keys.add("role")
    exact_keys(segment, keys, path)
    expect_synthetic_ref(segment["ref"], f"{path}.ref")
    byte_hex = expect_hex(segment["byte_hex"], f"{path}.byte_hex", one_byte=True)
    repeat = expect_int(segment["repeat"], f"{path}.repeat")
    if repeat < 1 or repeat > 2_000_000:
        fail(f"{path}.repeat", "must be between 1 and 2000000")
    return bytes.fromhex(byte_hex) * repeat


def validate_raw_bytes(case: dict[str, Any]) -> None:
    path = case["id"]
    input_data = exact_keys(case["input"], {"frame_type", "frame_hex"}, f"{path}.input")
    expected = exact_keys(
        case["expected"],
        {"render_hex", "utf8_decode", "reencode", "pty_bytes_logged"},
        f"{path}.expected",
    )
    expect_string(input_data["frame_type"], f"{path}.input.frame_type", "binary")
    frame_hex = expect_hex(input_data["frame_hex"], f"{path}.input.frame_hex")
    expect_string(expected["render_hex"], f"{path}.expected.render_hex", frame_hex)
    expect_bool(expected["utf8_decode"], f"{path}.expected.utf8_decode", False)
    expect_bool(expected["reencode"], f"{path}.expected.reencode", False)
    expect_bool(expected["pty_bytes_logged"], f"{path}.expected.pty_bytes_logged", False)


def validate_raw_bytes_multiframe(case: dict[str, Any]) -> None:
    path = case["id"]
    input_data = exact_keys(case["input"], {"frames"}, f"{path}.input")
    expected = exact_keys(
        case["expected"],
        {
            "rendered_frame_hex",
            "rendered_frame_refs",
            "joined_hex",
            "split_codepoint_frames",
            "incomplete_fragment_ref",
            "invalid_fragment_ref",
            "utf8_decode",
            "reencode",
            "frame_boundaries_preserved",
            "pty_bytes_logged",
        },
        f"{path}.expected",
    )
    frames = expect_list(input_data["frames"], f"{path}.input.frames")
    if len(frames) != 4:
        fail(f"{path}.input.frames", "must contain split, incomplete, and invalid binary fragments")
    refs: list[str] = []
    fragment_kinds: list[str] = []
    frame_hexes: list[str] = []
    for index, frame in enumerate(frames):
        frame_path = f"{path}.input.frames[{index}]"
        frame = exact_keys(frame, {"frame_ref", "fragment_kind", "frame_type", "frame_hex"}, frame_path)
        frame_ref = expect_synthetic_ref(frame["frame_ref"], f"{frame_path}.frame_ref")
        if frame_ref in refs:
            fail(f"{frame_path}.frame_ref", "frame references must be unique")
        refs.append(frame_ref)
        fragment_kinds.append(expect_string(frame["fragment_kind"], f"{frame_path}.fragment_kind"))
        expect_string(frame["frame_type"], f"{frame_path}.frame_type", "binary")
        frame_hexes.append(expect_hex(frame["frame_hex"], f"{frame_path}.frame_hex"))
    expected_kinds = [
        "split-codepoint-leading",
        "split-codepoint-continuation",
        "incomplete-codepoint",
        "invalid-sequence",
    ]
    if fragment_kinds != expected_kinds:
        fail(f"{path}.input.frames", "must keep canonical UTF-8 boundary coverage order")
    expected_hexes = ["f0", "9f9880", "e282", "c328"]
    if frame_hexes != expected_hexes:
        fail(f"{path}.input.frames", "must preserve the exact split, incomplete, and invalid bytes")
    expected_refs = [
        "synthetic-utf8-split-leading",
        "synthetic-utf8-split-continuation",
        "synthetic-utf8-incomplete",
        "synthetic-utf8-invalid",
    ]
    if refs != expected_refs:
        fail(f"{path}.input.frames", "must use the canonical synthetic frame references")

    rendered_hex = expect_list(expected["rendered_frame_hex"], f"{path}.expected.rendered_frame_hex")
    if rendered_hex != frame_hexes:
        fail(f"{path}.expected.rendered_frame_hex", "must equal each received frame byte-for-byte")
    rendered_refs = expect_list(expected["rendered_frame_refs"], f"{path}.expected.rendered_frame_refs")
    if rendered_refs != refs:
        fail(f"{path}.expected.rendered_frame_refs", "must preserve frame order and identity")
    expect_string(expected["joined_hex"], f"{path}.expected.joined_hex", "f09f9880e282c328")
    split_frames = expect_list(expected["split_codepoint_frames"], f"{path}.expected.split_codepoint_frames")
    if split_frames != expected_refs[:2]:
        fail(f"{path}.expected.split_codepoint_frames", "must identify the adjacent split codepoint frames")
    expect_string(expected["incomplete_fragment_ref"], f"{path}.expected.incomplete_fragment_ref", expected_refs[2])
    expect_string(expected["invalid_fragment_ref"], f"{path}.expected.invalid_fragment_ref", expected_refs[3])
    expect_bool(expected["utf8_decode"], f"{path}.expected.utf8_decode", False)
    expect_bool(expected["reencode"], f"{path}.expected.reencode", False)
    expect_bool(expected["frame_boundaries_preserved"], f"{path}.expected.frame_boundaries_preserved", True)
    expect_bool(expected["pty_bytes_logged"], f"{path}.expected.pty_bytes_logged", False)
    if "".join(frame_hexes) != expected["joined_hex"]:
        fail(f"{path}.expected.joined_hex", "must concatenate raw bytes without text decoding")


def validate_resize(case: dict[str, Any], constants: dict[str, Any]) -> None:
    path = case["id"]
    input_data = exact_keys(case["input"], {"samples"}, f"{path}.input")
    expected = exact_keys(
        case["expected"],
        {"prefix_hex", "suffix_hex", "control_is_single_binary_message", "written_to_pty"},
        f"{path}.expected",
    )
    samples = expect_list(input_data["samples"], f"{path}.input.samples")
    if len(samples) != 8:
        fail(f"{path}.input.samples", "must contain the complete integer clamp matrix")
    expect_string(
        expected["prefix_hex"],
        f"{path}.expected.prefix_hex",
        constants["resize_prefix_hex"],
    )
    expect_string(
        expected["suffix_hex"],
        f"{path}.expected.suffix_hex",
        constants["resize_suffix_hex"],
    )
    expect_bool(
        expected["control_is_single_binary_message"],
        f"{path}.expected.control_is_single_binary_message",
        True,
    )
    expect_bool(expected["written_to_pty"], f"{path}.expected.written_to_pty", False)

    observed_bounds: list[tuple[int, int]] = []
    for index, sample in enumerate(samples):
        sample_path = f"{path}.input.samples[{index}]"
        sample = exact_keys(
            sample,
            {"cols", "rows", "effective_cols", "effective_rows", "control_hex"},
            sample_path,
        )
        cols = expect_int(sample["cols"], f"{sample_path}.cols")
        rows = expect_int(sample["rows"], f"{sample_path}.rows")
        effective_cols = expect_int(sample["effective_cols"], f"{sample_path}.effective_cols")
        effective_rows = expect_int(sample["effective_rows"], f"{sample_path}.effective_rows")
        control_hex = expect_hex(sample["control_hex"], f"{sample_path}.control_hex")
        expected_cols = clamp(cols, constants["min_cols"], constants["max_cols"])
        expected_rows = clamp(rows, constants["min_rows"], constants["max_rows"])
        if (effective_cols, effective_rows) != (expected_cols, expected_rows):
            fail(sample_path, "dimensions are not clamped to the contract bounds")
        expected_control = resize_control(
            constants["resize_prefix_hex"],
            constants["resize_suffix_hex"],
            expected_cols,
            expected_rows,
        )
        if control_hex != expected_control:
            fail(f"{sample_path}.control_hex", "does not match ESC [ RESIZE:<cols>;<rows> ]")
        observed_bounds.append((cols, rows))

    required_bounds = [
        (1, 1),
        (2000, 1000),
        (-1, 24),
        (0, 0),
        (80, -1),
        (2001, 24),
        (80, 1001),
        (2001, 1001),
    ]
    if observed_bounds != required_bounds:
        fail(f"{path}.input.samples", "must cover negative, zero, minimum, maximum, and high dimensions in order")


def validate_resize_rejection(case: dict[str, Any]) -> None:
    path = case["id"]
    input_data = exact_keys(case["input"], {"candidates"}, f"{path}.input")
    expected = exact_keys(
        case["expected"],
        {"rejected_before_binary_send", "error_mode", "pty_write"},
        f"{path}.expected",
    )
    candidates = expect_list(input_data["candidates"], f"{path}.input.candidates")
    if len(candidates) != 11:
        fail(f"{path}.input.candidates", "must cover invalid integer types, null, non-finite tokens, and syntax")
    expected_candidates = [
        (1001.0, 24, "ESC [RESIZE:1001.0;24]", "non-integer-number", "malformed-dimension-type"),
        (True, 24, "ESC [RESIZE:true;24]", "boolean-dimension", "malformed-dimension-type"),
        ("1001", 24, "ESC [RESIZE:1001;24]", "string-dimension", "malformed-dimension-type"),
        (None, 24, "ESC [RESIZE:null;24]", "null-dimension", "malformed-dimension-type"),
        ("NaN", 24, "ESC [RESIZE:NaN;24]", "non-finite-number-token", "non-finite-dimension"),
        (1001, 24, "ESC [RESIZE:1001;24", "malformed-frame", "malformed-syntax"),
        (80, 24.0, "ESC [RESIZE:80;24.0]", "non-integer-number", "malformed-dimension-type"),
        (80, True, "ESC [RESIZE:80;true]", "boolean-dimension", "malformed-dimension-type"),
        (80, "24", "ESC [RESIZE:80;24]", "string-dimension", "malformed-dimension-type"),
        (80, None, "ESC [RESIZE:80;null]", "null-dimension", "malformed-dimension-type"),
        (80, "Infinity", "ESC [RESIZE:80;Infinity]", "non-finite-number-token", "non-finite-dimension"),
    ]
    for index, candidate in enumerate(candidates):
        candidate_path = f"{path}.input.candidates[{index}]"
        candidate = exact_keys(
            candidate,
            {"cols", "rows", "frame", "wire_shape", "reason", "expected"},
            candidate_path,
        )
        expected_cols, expected_rows, expected_frame, expected_wire_shape, expected_reason = expected_candidates[index]
        expect_exact_value(candidate["cols"], f"{candidate_path}.cols", expected_cols)
        expect_exact_value(candidate["rows"], f"{candidate_path}.rows", expected_rows)
        expect_string(candidate["frame"], f"{candidate_path}.frame", expected_frame)
        expect_string(candidate["wire_shape"], f"{candidate_path}.wire_shape", expected_wire_shape)
        expect_string(candidate["reason"], f"{candidate_path}.reason", expected_reason)
        expect_string(candidate["expected"], f"{candidate_path}.expected", "rejected")
    expect_bool(expected["rejected_before_binary_send"], f"{path}.expected.rejected_before_binary_send", True)
    expect_string(expected["error_mode"], f"{path}.expected.error_mode", "safe-validation-failure")
    expect_bool(expected["pty_write"], f"{path}.expected.pty_write", False)


def validate_legacy(case: dict[str, Any], constants: dict[str, Any]) -> None:
    path = case["id"]
    input_data = exact_keys(
        case["input"], {"attach_query", "socket_ref", "process_ref", "events"}, f"{path}.input"
    )
    expected = exact_keys(
        case["expected"],
        {
            "mode",
            "trigger",
            "event_sequence",
            "disconnect_result",
            "close_result",
            "final_state",
            "registry_path",
            "reattach",
            "process_ref",
            "spawn_count",
        },
        f"{path}.expected",
    )
    if case["id"] == "legacy-missing-attach":
        expect_none(input_data["attach_query"], f"{path}.input.attach_query")
        trigger = "disconnect"
        expected_events = ["socket.accept", "socket.disconnect", "bridge.close", "process.terminate", "process.reap"]
        expected_disconnect = "child-terminated"
        expected_close = "not-exercised"
    else:
        expect_string(input_data["attach_query"], f"{path}.input.attach_query", "")
        trigger = "close"
        expected_events = ["socket.accept", "client.close", "bridge.close", "process.terminate", "process.reap"]
        expected_disconnect = "not-exercised"
        expected_close = "child-terminated"
    socket_ref = expect_synthetic_ref(input_data["socket_ref"], f"{path}.input.socket_ref")
    process_ref = expect_synthetic_ref(input_data["process_ref"], f"{path}.input.process_ref")
    events = expect_list(input_data["events"], f"{path}.input.events")
    if len(events) != len(expected_events):
        fail(f"{path}.input.events", "must independently prove the selected legacy termination timeline")
    observed_names: list[str] = []
    for index, event in enumerate(events):
        event_path = f"{path}.input.events[{index}]"
        expected_name = expected_events[index]
        if index < 3:
            event = exact_keys(event, {"step", "name", "socket_ref", "process_ref"}, event_path)
            expect_string(event["socket_ref"], f"{event_path}.socket_ref", socket_ref)
        else:
            event = exact_keys(event, {"step", "name", "process_ref"}, event_path)
        expect_int(event["step"], f"{event_path}.step", index + 1)
        expect_string(event["name"], f"{event_path}.name", expected_name)
        expect_string(event["process_ref"], f"{event_path}.process_ref", process_ref)
        observed_names.append(event["name"])
    expect_string(expected["mode"], f"{path}.expected.mode", "legacy")
    expect_string(expected["trigger"], f"{path}.expected.trigger", trigger)
    if expected["event_sequence"] != observed_names:
        fail(f"{path}.expected.event_sequence", "must equal the executable legacy event timeline")
    expect_list(expected["event_sequence"], f"{path}.expected.event_sequence")
    expect_string(expected["disconnect_result"], f"{path}.expected.disconnect_result", expected_disconnect)
    expect_string(expected["close_result"], f"{path}.expected.close_result", expected_close)
    expect_string(expected["final_state"], f"{path}.expected.final_state", "exited")
    expect_string(expected["registry_path"], f"{path}.expected.registry_path", "not-used")
    expect_string(expected["reattach"], f"{path}.expected.reattach", "prohibited")
    expect_string(expected["process_ref"], f"{path}.expected.process_ref", process_ref)
    expect_int(expected["spawn_count"], f"{path}.expected.spawn_count", 1)
    if constants["registry_max_entries"] != 16:
        fail("constants.registry_max_entries", "must remain 16 for the legacy proof")


def validate_attach(case: dict[str, Any], constants: dict[str, Any]) -> None:
    path = case["id"]
    input_data = exact_keys(
        case["input"],
        {"attach_query", "handle_ref", "session_ref", "process_ref", "registry_ref", "events"},
        f"{path}.input",
    )
    expected = exact_keys(
        case["expected"],
        {
            "mode",
            "disconnect_result",
            "close_result",
            "process_result",
            "registry_result",
            "reattach",
            "retention_seconds",
            "identity_preserved",
            "process_ref",
            "registry_ref",
            "handle_ref",
            "session_ref",
            "event_sequence",
            "state_sequence",
            "socket_sequence",
            "spawn_count",
            "registry_reuse_count",
        },
        f"{path}.expected",
    )
    attach_query = expect_synthetic_ref(input_data["attach_query"], f"{path}.input.attach_query")
    handle_ref = expect_synthetic_ref(input_data["handle_ref"], f"{path}.input.handle_ref")
    if attach_query != handle_ref:
        fail(f"{path}.input", "the query handle and identity handle must be the same exact value")
    session_ref = expect_synthetic_ref(input_data["session_ref"], f"{path}.input.session_ref")
    process_ref = expect_synthetic_ref(input_data["process_ref"], f"{path}.input.process_ref")
    registry_ref = expect_synthetic_ref(input_data["registry_ref"], f"{path}.input.registry_ref")
    events = expect_list(input_data["events"], f"{path}.input.events")
    expected_names = [
        "socket.accept",
        "registry.spawn",
        "session.attach",
        "socket.disconnect",
        "registry.detach",
        "socket.accept",
        "registry.reuse",
        "session.attach",
        "client.close",
        "registry.detach",
    ]
    expected_sockets = [
        "synthetic-socket-attach-a",
        None,
        None,
        "synthetic-socket-attach-a",
        "synthetic-socket-attach-a",
        "synthetic-socket-attach-b",
        None,
        "synthetic-socket-attach-b",
        "synthetic-socket-attach-b",
        "synthetic-socket-attach-b",
    ]
    if len(events) != len(expected_names):
        fail(f"{path}.input.events", "must prove spawn, detach, registry reuse, second-socket attach, and explicit Close")
    observed_names: list[str] = []
    observed_sockets: list[str] = []
    for index, event in enumerate(events):
        event_path = f"{path}.input.events[{index}]"
        event = exact_keys(
            event,
            {"step", "name", "socket_ref", "handle_ref", "session_ref", "process_ref"},
            event_path,
        )
        expect_int(event["step"], f"{event_path}.step", index + 1)
        expect_string(event["name"], f"{event_path}.name", expected_names[index])
        if expected_sockets[index] is None:
            expect_none(event["socket_ref"], f"{event_path}.socket_ref")
        else:
            expect_string(event["socket_ref"], f"{event_path}.socket_ref", expected_sockets[index])
        expect_string(event["handle_ref"], f"{event_path}.handle_ref", handle_ref)
        expect_string(event["session_ref"], f"{event_path}.session_ref", session_ref)
        expect_string(event["process_ref"], f"{event_path}.process_ref", process_ref)
        observed_names.append(event["name"])
        if expected_sockets[index] is not None and expected_sockets[index] not in observed_sockets:
            observed_sockets.append(expected_sockets[index])
    expect_string(expected["mode"], f"{path}.expected.mode", "attach")
    expect_string(expected["disconnect_result"], f"{path}.expected.disconnect_result", "socket-detached")
    expect_string(expected["close_result"], f"{path}.expected.close_result", "socket-detached")
    expect_string(expected["process_result"], f"{path}.expected.process_result", "kept-running")
    expect_string(expected["registry_result"], f"{path}.expected.registry_result", "retained")
    expect_string(expected["reattach"], f"{path}.expected.reattach", "same-handle")
    expect_int(expected["retention_seconds"], f"{path}.expected.retention_seconds", constants["detach_retention_seconds"])
    expect_bool(expected["identity_preserved"], f"{path}.expected.identity_preserved", True)
    expect_string(expected["process_ref"], f"{path}.expected.process_ref", process_ref)
    expect_string(expected["registry_ref"], f"{path}.expected.registry_ref", registry_ref)
    expect_string(expected["handle_ref"], f"{path}.expected.handle_ref", handle_ref)
    expect_string(expected["session_ref"], f"{path}.expected.session_ref", session_ref)
    if expected["event_sequence"] != observed_names:
        fail(f"{path}.expected.event_sequence", "must equal the executable attach timeline")
    expect_list(expected["event_sequence"], f"{path}.expected.event_sequence")
    expect_list(expected["state_sequence"], f"{path}.expected.state_sequence")
    if expected["state_sequence"] != ["attached", "detached", "attached", "detached"]:
        fail(f"{path}.expected.state_sequence", "must prove detach, reattach, and explicit Close detach")
    expect_list(expected["socket_sequence"], f"{path}.expected.socket_sequence")
    if expected["socket_sequence"] != observed_sockets:
        fail(f"{path}.expected.socket_sequence", "must preserve the first and second socket identities")
    expect_int(expected["spawn_count"], f"{path}.expected.spawn_count", 1)
    expect_int(expected["registry_reuse_count"], f"{path}.expected.registry_reuse_count", 1)
    if not attach_query:
        fail(f"{path}.input.attach_query", "must be non-empty for registry keep-alive")


def validate_replacement(case: dict[str, Any], constants: dict[str, Any]) -> None:
    path = case["id"]
    input_data = exact_keys(
        case["input"],
        {
            "attach_query",
            "handle_ref",
            "session_ref",
            "process_ref",
            "old_socket_ref",
            "new_socket_ref",
            "events",
        },
        f"{path}.input",
    )
    expected = exact_keys(
        case["expected"],
        {
            "stale_close_code",
            "close_before_assign",
            "replacement_active",
            "stale_cleanup_detaches_replacement",
            "active_socket_ref",
            "handle_ref",
            "session_ref",
            "process_ref",
            "identity_preserved",
        },
        f"{path}.expected",
    )
    attach_query = expect_synthetic_ref(input_data["attach_query"], f"{path}.input.attach_query")
    handle_ref = expect_synthetic_ref(input_data["handle_ref"], f"{path}.input.handle_ref")
    session_ref = expect_synthetic_ref(input_data["session_ref"], f"{path}.input.session_ref")
    process_ref = expect_synthetic_ref(input_data["process_ref"], f"{path}.input.process_ref")
    if attach_query != handle_ref:
        fail(f"{path}.input", "replacement must use the same exact handle identity")
    old_socket = expect_synthetic_ref(input_data["old_socket_ref"], f"{path}.input.old_socket_ref")
    new_socket = expect_synthetic_ref(input_data["new_socket_ref"], f"{path}.input.new_socket_ref")
    if old_socket == new_socket:
        fail(f"{path}.input", "replacement sockets must be distinct")
    events = expect_list(input_data["events"], f"{path}.input.events")
    if len(events) != 3:
        fail(f"{path}.input.events", "must contain close, assign, and stale cleanup")
    first = exact_keys(
        events[0],
        {"name", "socket_ref", "handle_ref", "session_ref", "process_ref", "code"},
        f"{path}.input.events[0]",
    )
    second = exact_keys(
        events[1],
        {"name", "socket_ref", "handle_ref", "session_ref", "process_ref"},
        f"{path}.input.events[1]",
    )
    third = exact_keys(
        events[2],
        {"name", "socket_ref", "handle_ref", "session_ref", "process_ref", "action", "result"},
        f"{path}.input.events[2]",
    )
    for index, event in enumerate((first, second, third)):
        expect_string(event["handle_ref"], f"{path}.input.events[{index}].handle_ref", handle_ref)
        expect_string(event["session_ref"], f"{path}.input.events[{index}].session_ref", session_ref)
        expect_string(event["process_ref"], f"{path}.input.events[{index}].process_ref", process_ref)
    expect_string(first["name"], f"{path}.input.events[0].name", "old_socket_close")
    expect_string(first["socket_ref"], f"{path}.input.events[0].socket_ref", old_socket)
    expect_int(first["code"], f"{path}.input.events[0].code", constants["replacement_close_code"])
    expect_string(second["name"], f"{path}.input.events[1].name", "replacement_assign")
    expect_string(second["socket_ref"], f"{path}.input.events[1].socket_ref", new_socket)
    expect_string(third["name"], f"{path}.input.events[2].name", "old_cleanup")
    expect_string(third["socket_ref"], f"{path}.input.events[2].socket_ref", old_socket)
    expect_string(third["action"], f"{path}.input.events[2].action", "detach")
    expect_string(third["result"], f"{path}.input.events[2].result", "ignored")
    expect_int(expected["stale_close_code"], f"{path}.expected.stale_close_code", constants["replacement_close_code"])
    expect_bool(expected["close_before_assign"], f"{path}.expected.close_before_assign", True)
    expect_bool(expected["replacement_active"], f"{path}.expected.replacement_active", True)
    expect_bool(expected["stale_cleanup_detaches_replacement"], f"{path}.expected.stale_cleanup_detaches_replacement", False)
    expect_string(expected["active_socket_ref"], f"{path}.expected.active_socket_ref", new_socket)
    expect_string(expected["handle_ref"], f"{path}.expected.handle_ref", handle_ref)
    expect_string(expected["session_ref"], f"{path}.expected.session_ref", session_ref)
    expect_string(expected["process_ref"], f"{path}.expected.process_ref", process_ref)
    expect_bool(expected["identity_preserved"], f"{path}.expected.identity_preserved", True)


def validate_process_exit(case: dict[str, Any], constants: dict[str, Any]) -> None:
    path = case["id"]
    input_data = exact_keys(case["input"], {"process_ref", "events"}, f"{path}.input")
    expected = exact_keys(
        case["expected"], {"close_code", "final_state", "retry", "process_ref"}, f"{path}.expected"
    )
    process_ref = expect_synthetic_ref(input_data["process_ref"], f"{path}.input.process_ref")
    events = expect_list(input_data["events"], f"{path}.input.events")
    if len(events) != 2:
        fail(f"{path}.input.events", "must contain process exit followed by socket close")
    exit_event = exact_keys(events[0], {"name", "process_ref", "exit_status"}, f"{path}.input.events[0]")
    close_event = exact_keys(events[1], {"name", "code"}, f"{path}.input.events[1]")
    expect_string(exit_event["name"], f"{path}.input.events[0].name", "process_exit")
    expect_string(exit_event["process_ref"], f"{path}.input.events[0].process_ref", process_ref)
    expect_int(exit_event["exit_status"], f"{path}.input.events[0].exit_status", 0)
    expect_string(close_event["name"], f"{path}.input.events[1].name", "socket_close")
    expect_int(close_event["code"], f"{path}.input.events[1].code", constants["process_exit_close_code"])
    expect_int(expected["close_code"], f"{path}.expected.close_code", constants["process_exit_close_code"])
    expect_string(expected["final_state"], f"{path}.expected.final_state", "exited")
    expect_string(expected["retry"], f"{path}.expected.retry", "prohibited")
    expect_string(expected["process_ref"], f"{path}.expected.process_ref", process_ref)


def validate_detach_window(case: dict[str, Any], constants: dict[str, Any]) -> None:
    path = case["id"]
    input_data = exact_keys(case["input"], {"detach_epoch_seconds", "probes"}, f"{path}.input")
    expected = exact_keys(
        case["expected"],
        {"retention_seconds", "within_window", "at_boundary", "after_window", "identity_preserved_during_window"},
        f"{path}.expected",
    )
    epoch = expect_int(input_data["detach_epoch_seconds"], f"{path}.input.detach_epoch_seconds")
    if epoch < 0:
        fail(f"{path}.input.detach_epoch_seconds", "must be a non-negative synthetic epoch")
    probes = expect_list(input_data["probes"], f"{path}.input.probes")
    if len(probes) != 3:
        fail(f"{path}.input.probes", "must include before, equality, and after retention probes")
    observed: dict[int, str] = {}
    for index, probe in enumerate(probes):
        probe_path = f"{path}.input.probes[{index}]"
        probe = exact_keys(probe, {"elapsed_seconds", "outcome"}, probe_path)
        elapsed = expect_int(probe["elapsed_seconds"], f"{probe_path}.elapsed_seconds")
        outcome = expect_string(probe["outcome"], f"{probe_path}.outcome")
        if elapsed < 0 or outcome not in {"reattach-allowed", "reattach-expired"}:
            fail(probe_path, "has an invalid retention probe")
        observed[elapsed] = outcome
    retention = constants["detach_retention_seconds"]
    if observed != {
        retention - 1: "reattach-allowed",
        retention: "reattach-allowed",
        retention + 1: "reattach-expired",
    }:
        fail(f"{path}.input.probes", "must prove 1799 allowed, exactly 1800 allowed, and 1801 expired")
    expect_int(expected["retention_seconds"], f"{path}.expected.retention_seconds", retention)
    expect_string(expected["within_window"], f"{path}.expected.within_window", "reattach-allowed")
    expect_string(expected["at_boundary"], f"{path}.expected.at_boundary", "reattach-allowed")
    expect_string(expected["after_window"], f"{path}.expected.after_window", "reattach-expired")
    expect_bool(expected["identity_preserved_during_window"], f"{path}.expected.identity_preserved_during_window", True)


def validate_registry_cap(case: dict[str, Any], constants: dict[str, Any]) -> None:
    path = case["id"]
    input_data = exact_keys(case["input"], {"requested_entries", "observed_sizes"}, f"{path}.input")
    expected = exact_keys(
        case["expected"], {"max_entries", "size_never_exceeds_cap", "overflow_behavior"}, f"{path}.expected"
    )
    expect_int(input_data["requested_entries"], f"{path}.input.requested_entries", constants["registry_max_entries"] + 1)
    sizes = expect_list(input_data["observed_sizes"], f"{path}.input.observed_sizes")
    if sizes != list(range(1, constants["registry_max_entries"] + 1)) + [constants["registry_max_entries"]]:
        fail(f"{path}.input.observed_sizes", "must show the registry reaching, then holding, the cap")
    for index, size in enumerate(sizes):
        expect_int(size, f"{path}.input.observed_sizes[{index}]")
    expect_int(expected["max_entries"], f"{path}.expected.max_entries", constants["registry_max_entries"])
    expect_bool(expected["size_never_exceeds_cap"], f"{path}.expected.size_never_exceeds_cap", True)
    expect_string(expected["overflow_behavior"], f"{path}.expected.overflow_behavior", "bounded-at-cap")
    if max(sizes) > constants["registry_max_entries"]:
        fail(f"{path}.input.observed_sizes", "exceeds the registry cap")


def validate_replay_ring(case: dict[str, Any], constants: dict[str, Any]) -> None:
    path = case["id"]
    input_data = exact_keys(case["input"], {"output_segments"}, f"{path}.input")
    expected = exact_keys(
        case["expected"],
        {"capacity_bytes", "tail_ref", "tail_length", "older_output", "frame_type"},
        f"{path}.expected",
    )
    segments = expect_list(input_data["output_segments"], f"{path}.input.output_segments")
    if len(segments) != 2:
        fail(f"{path}.input.output_segments", "must contain old and new deterministic output")
    refs: list[str] = []
    rendered: list[bytes] = []
    for index, segment in enumerate(segments):
        segment_path = f"{path}.input.output_segments[{index}]"
        segment = exact_keys(segment, {"ref", "role", "byte_hex", "repeat"}, segment_path)
        ref = expect_synthetic_ref(segment["ref"], f"{segment_path}.ref")
        role = expect_string(segment["role"], f"{segment_path}.role")
        expected_ref, expected_role = REPLAY_SEGMENT_PROVENANCE[index]
        expect_string(segment["ref"], f"{segment_path}.ref", expected_ref)
        expect_string(segment["role"], f"{segment_path}.role", expected_role)
        if ref in refs:
            fail(segment_path, "segment references must be unique")
        refs.append(ref)
        rendered.append(segment_bytes(segment, segment_path))
    output = b"".join(rendered)
    capacity = constants["replay_capacity_bytes"]
    tail = output[-capacity:]
    expect_int(expected["capacity_bytes"], f"{path}.expected.capacity_bytes", capacity)
    expect_string(expected["tail_ref"], f"{path}.expected.tail_ref", REPLAY_SEGMENT_PROVENANCE[-1][0])
    expect_int(expected["tail_length"], f"{path}.expected.tail_length", capacity)
    expect_string(expected["older_output"], f"{path}.expected.older_output", "may-be-missing")
    expect_string(expected["frame_type"], f"{path}.expected.frame_type", "binary")
    newest = rendered[-1]
    if len(newest) < capacity:
        fail(f"{path}.input.output_segments[1].repeat", "newest output must meet or exceed capacity")
    if tail != newest[-capacity:]:
        fail(path, "replay is not the newest byte tail")
    if len(tail) != capacity:
        fail(path, "replay tail length differs from the 1 MiB bound")
    old_segment_end = len(rendered[0])
    replay_start = len(output) - capacity
    if replay_start < old_segment_end:
        fail(path, "replay tail still overlaps the old output segment")
    # Segment offsets prove eviction even when old and new bytes have equal values.


def validate_action_exclusion(case: dict[str, Any]) -> None:
    path = case["id"]
    input_data = exact_keys(
        case["input"], {"actions", "retained_output_segments"}, f"{path}.input"
    )
    expected = exact_keys(
        case["expected"],
        {
            "snapshot_mode",
            "replayed_action_kinds",
            "retained_output_refs",
            "prompt_output_may_be_retained",
            "tool_output_may_be_retained",
        },
        f"{path}.expected",
    )
    actions = expect_list(input_data["actions"], f"{path}.input.actions")
    if len(actions) != 4:
        fail(f"{path}.input.actions", "must cover input, resize, prompt, and tool")
    action_kinds: list[str] = []
    action_refs: set[str] = set()
    for index, action in enumerate(actions):
        action_path = f"{path}.input.actions[{index}]"
        action = exact_keys(action, {"kind", "action_ref", "replayed"}, action_path)
        kind = expect_string(action["kind"], f"{action_path}.kind")
        if kind not in {"input", "resize", "prompt", "tool"}:
            fail(f"{action_path}.kind", "is not a non-replayable action kind")
        if kind in action_kinds:
            fail(f"{action_path}.kind", "action kinds must be unique")
        action_kinds.append(kind)
        action_ref = expect_synthetic_ref(action["action_ref"], f"{action_path}.action_ref")
        if action_ref in action_refs:
            fail(f"{action_path}.action_ref", "action references must be unique")
        action_refs.add(action_ref)
        expect_bool(action["replayed"], f"{action_path}.replayed", False)
    if action_kinds != ["input", "resize", "prompt", "tool"]:
        fail(f"{path}.input.actions", "must keep the canonical action coverage order")
    segments = expect_list(input_data["retained_output_segments"], f"{path}.input.retained_output_segments")
    refs: list[str] = []
    for index, segment in enumerate(segments):
        segment_path = f"{path}.input.retained_output_segments[{index}]"
        refs.append(expect_synthetic_ref(segment.get("ref"), f"{segment_path}.ref") if type(segment) is dict else "")
        segment_bytes(segment, segment_path)
    expected_refs = ["synthetic-prompt-output", "synthetic-tool-output"]
    if refs != expected_refs:
        fail(f"{path}.input.retained_output_segments", "must retain only output segment references")
    expect_string(expected["snapshot_mode"], f"{path}.expected.snapshot_mode", "output-only")
    replayed = expect_list(expected["replayed_action_kinds"], f"{path}.expected.replayed_action_kinds")
    if replayed != []:
        fail(f"{path}.expected.replayed_action_kinds", "must be empty")
    retained = expect_list(expected["retained_output_refs"], f"{path}.expected.retained_output_refs")
    if retained != expected_refs:
        fail(f"{path}.expected.retained_output_refs", "does not match retained output")
    expect_bool(expected["prompt_output_may_be_retained"], f"{path}.expected.prompt_output_may_be_retained", True)
    expect_bool(expected["tool_output_may_be_retained"], f"{path}.expected.tool_output_may_be_retained", True)


def validate_replay_race(case: dict[str, Any]) -> None:
    path = case["id"]
    input_data = exact_keys(
        case["input"], {"retained_segment", "live_segment", "schedules"}, f"{path}.input"
    )
    expected = exact_keys(
        case["expected"],
        {"allowed_orderings", "separator_hex", "replay_boundary_claim", "render_each_frame_as_received"},
        f"{path}.expected",
    )
    retained = segment_bytes(input_data["retained_segment"], f"{path}.input.retained_segment")
    live = segment_bytes(input_data["live_segment"], f"{path}.input.live_segment")
    if retained == live:
        fail(path, "retained and live segments must be distinguishable")
    schedules = expect_list(input_data["schedules"], f"{path}.input.schedules")
    if len(schedules) != 2:
        fail(f"{path}.input.schedules", "must include both race orderings")
    names: list[str] = []
    for index, schedule in enumerate(schedules):
        schedule_path = f"{path}.input.schedules[{index}]"
        schedule = exact_keys(schedule, {"name", "sequence"}, schedule_path)
        name = expect_string(schedule["name"], f"{schedule_path}.name")
        sequence = expect_list(schedule["sequence"], f"{schedule_path}.sequence")
        if name not in {"retained-before-live", "live-before-retained"}:
            fail(f"{schedule_path}.name", "is not an allowed race schedule")
        expected_sequence = ["retained", "live"] if name == "retained-before-live" else ["live", "retained"]
        if sequence != expected_sequence:
            fail(f"{schedule_path}.sequence", "does not match its schedule name")
        names.append(name)
    if names != ["retained-before-live", "live-before-retained"]:
        fail(f"{path}.input.schedules", "must cover both orderings in canonical order")
    expect_list(expected["allowed_orderings"], f"{path}.expected.allowed_orderings")
    if expected["allowed_orderings"] != names:
        fail(f"{path}.expected.allowed_orderings", "must allow both replay/live races")
    expect_none(expected["separator_hex"], f"{path}.expected.separator_hex")
    expect_string(expected["replay_boundary_claim"], f"{path}.expected.replay_boundary_claim", "none")
    expect_bool(expected["render_each_frame_as_received"], f"{path}.expected.render_each_frame_as_received", True)


def validate_no_byte_logging(case: dict[str, Any]) -> None:
    path = case["id"]
    input_data = exact_keys(case["input"], {"frames", "actions", "logs", "retained"}, f"{path}.input")
    expected = exact_keys(
        case["expected"],
        {
            "raw_bytes_logged",
            "action_payloads_logged",
            "payload_fields_are_null",
            "metadata_only",
            "retained_action_refs",
            "allowed_metadata",
        },
        f"{path}.expected",
    )
    frames = expect_list(input_data["frames"], f"{path}.input.frames")
    if len(frames) != 2:
        fail(f"{path}.input.frames", "must cover more than one synthetic PTY output frame")
    frame_refs: list[str] = []
    frame_lengths: dict[str, int] = {}
    for index, frame in enumerate(frames):
        frame_path = f"{path}.input.frames[{index}]"
        frame = exact_keys(frame, {"frame_ref", "frame_hex"}, frame_path)
        frame_ref = expect_synthetic_ref(frame["frame_ref"], f"{frame_path}.frame_ref")
        if frame_ref in frame_refs:
            fail(f"{frame_path}.frame_ref", "frame references must be unique")
        frame_refs.append(frame_ref)
        frame_hex = expect_hex(frame["frame_hex"], f"{frame_path}.frame_hex")
        frame_lengths[frame_ref] = len(bytes.fromhex(frame_hex))

    actions = expect_list(input_data["actions"], f"{path}.input.actions")
    if len(actions) != 4:
        fail(f"{path}.input.actions", "must cover input, resize, prompt, and tool payloads")
    action_refs: list[str] = []
    action_kinds: list[str] = []
    action_lengths: dict[str, int] = {}
    for index, action in enumerate(actions):
        action_path = f"{path}.input.actions[{index}]"
        action = exact_keys(action, {"kind", "action_ref", "payload_hex"}, action_path)
        kind = expect_string(action["kind"], f"{action_path}.kind")
        if kind not in {"input", "resize", "prompt", "tool"} or kind in action_kinds:
            fail(f"{action_path}.kind", "must cover each action kind exactly once")
        action_kinds.append(kind)
        action_ref = expect_synthetic_ref(action["action_ref"], f"{action_path}.action_ref")
        if action_ref in action_refs:
            fail(f"{action_path}.action_ref", "action references must be unique")
        action_refs.append(action_ref)
        payload_hex = expect_hex(action["payload_hex"], f"{action_path}.payload_hex")
        action_lengths[action_ref] = len(bytes.fromhex(payload_hex))
    if action_kinds != ["input", "resize", "prompt", "tool"]:
        fail(f"{path}.input.actions", "must keep canonical action order")

    retained = exact_keys(input_data["retained"], {"output_frame_refs", "action_refs"}, f"{path}.input.retained")
    retained_frames = expect_list(retained["output_frame_refs"], f"{path}.input.retained.output_frame_refs")
    if retained_frames != frame_refs:
        fail(f"{path}.input.retained.output_frame_refs", "may retain only semantic output references")
    retained_actions = expect_list(retained["action_refs"], f"{path}.input.retained.action_refs")
    if retained_actions != []:
        fail(f"{path}.input.retained.action_refs", "action payloads must not enter retained records")

    logs = expect_list(input_data["logs"], f"{path}.input.logs")
    if len(logs) != len(frames) + len(actions):
        fail(f"{path}.input.logs", "must contain one metadata record for every frame and action")
    for index, log in enumerate(logs):
        log_path = f"{path}.input.logs[{index}]"
        log = exact_keys(
            log,
            {
                "event",
                "record_kind",
                "frame_ref",
                "action_ref",
                "byte_payload_hex",
                "action_payload_hex",
                "byte_length",
                "metadata_only",
            },
            log_path,
        )
        record_kind = expect_string(log["record_kind"], f"{log_path}.record_kind")
        expect_none(log["byte_payload_hex"], f"{log_path}.byte_payload_hex")
        expect_none(log["action_payload_hex"], f"{log_path}.action_payload_hex")
        expect_bool(log["metadata_only"], f"{log_path}.metadata_only", True)
        if index < len(frames):
            frame_ref = expect_synthetic_ref(log["frame_ref"], f"{log_path}.frame_ref")
            if record_kind != "pty-output" or log["event"] != "pty.frame.received" or frame_ref != frame_refs[index]:
                fail(log_path, "PTY records must contain only ordered semantic frame metadata")
            expect_none(log["action_ref"], f"{log_path}.action_ref")
            expect_int(log["byte_length"], f"{log_path}.byte_length", frame_lengths[frame_ref])
        else:
            action_index = index - len(frames)
            action_ref = expect_synthetic_ref(log["action_ref"], f"{log_path}.action_ref")
            if record_kind != "action" or log["event"] != "action.received" or action_ref != action_refs[action_index]:
                fail(log_path, "action records must contain only ordered semantic metadata")
            expect_none(log["frame_ref"], f"{log_path}.frame_ref")
            expect_none(log["byte_length"], f"{log_path}.byte_length")

    expect_bool(expected["raw_bytes_logged"], f"{path}.expected.raw_bytes_logged", False)
    expect_bool(expected["action_payloads_logged"], f"{path}.expected.action_payloads_logged", False)
    expect_bool(expected["payload_fields_are_null"], f"{path}.expected.payload_fields_are_null", True)
    expect_bool(expected["metadata_only"], f"{path}.expected.metadata_only", True)
    retained_action_refs = expect_list(expected["retained_action_refs"], f"{path}.expected.retained_action_refs")
    if retained_action_refs != []:
        fail(f"{path}.expected.retained_action_refs", "must remain empty")
    allowed_metadata = expect_list(expected["allowed_metadata"], f"{path}.expected.allowed_metadata")
    if allowed_metadata != ["event", "record_kind", "frame_ref", "action_ref", "byte_length", "metadata_only"]:
        fail(f"{path}.expected.allowed_metadata", "must stay metadata-only")


def validate_case(case: Any, constants: dict[str, Any]) -> None:
    if type(case) is not dict:
        fail("cases", "every case must be an object")
    exact_keys(case, {"id", "kind", "input", "expected"}, "case")
    case_id = expect_string(case["id"], "case.id")
    kind = expect_string(case["kind"], f"{case_id}.kind")
    if case_id not in EXPECTED_CASES:
        fail(f"{case_id}.id", "is not a canonical fixture id")
    if EXPECTED_CASES[case_id] != kind:
        fail(f"{case_id}.kind", f"must equal {EXPECTED_CASES[case_id]!r}")
    if kind == "raw-bytes":
        validate_raw_bytes(case)
    elif kind == "raw-bytes-multiframe":
        validate_raw_bytes_multiframe(case)
    elif kind == "resize":
        validate_resize(case, constants)
    elif kind == "resize-rejection":
        validate_resize_rejection(case)
    elif kind == "legacy-lifecycle":
        validate_legacy(case, constants)
    elif kind == "attach-lifecycle":
        validate_attach(case, constants)
    elif kind == "replacement":
        validate_replacement(case, constants)
    elif kind == "process-exit":
        validate_process_exit(case, constants)
    elif kind == "detach-window":
        validate_detach_window(case, constants)
    elif kind == "registry-cap":
        validate_registry_cap(case, constants)
    elif kind == "replay-ring":
        validate_replay_ring(case, constants)
    elif kind == "replay-action-exclusion":
        validate_action_exclusion(case)
    elif kind == "replay-live-race":
        validate_replay_race(case)
    elif kind == "no-byte-logging":
        validate_no_byte_logging(case)
    else:
        fail(f"{case_id}.kind", "is unsupported")


def validate_contract(data: Any) -> dict[str, Any]:
    """Validate the complete fixture and return a small deterministic summary."""

    _validate_json_tree(data)
    scan_for_forbidden_text(data)
    root = exact_keys(
        data,
        {"schema_version", "contract", "constants", "evidence", "source_audit", "cases"},
        "root",
    )
    expect_string(root["schema_version"], "schema_version", "pty-contract-v1")
    validate_source_audit(root["source_audit"])

    contract = exact_keys(
        root["contract"],
        {
            "route",
            "surface",
            "proof_mode",
            "pinned_hermes_sha",
            "source_of_truth",
            "output_encoding",
            "attach_rule",
            "replay_rule",
            "logging_rule",
        },
        "contract",
    )
    expect_string(contract["route"], "contract.route", "WS /api/pty")
    expect_string(contract["surface"], "contract.surface", "web-only")
    expect_string(contract["proof_mode"], "contract.proof_mode", "offline-synthetic-byte-adapter")
    expect_string(contract["pinned_hermes_sha"], "contract.pinned_hermes_sha", PINNED_HERMES_SHA)
    source_of_truth = expect_list(contract["source_of_truth"], "contract.source_of_truth")
    if source_of_truth != [
        "contracts/state-models/terminal.md",
        "contracts/fixtures/source-audit/pty-attach/README.md",
    ]:
        fail("contract.source_of_truth", "must use the reviewed PTY contract documents")
    expect_string(contract["output_encoding"], "contract.output_encoding", "raw-bytes")
    expect_string(contract["attach_rule"], "contract.attach_rule", "missing-or-empty-legacy; non-empty-registry")
    expect_string(contract["replay_rule"], "contract.replay_rule", "newest-1MiB-output-only; live-race-allowed")
    expect_string(contract["logging_rule"], "contract.logging_rule", "no-pty-byte-logging")

    constants = exact_keys(
        root["constants"],
        {
            "resize_prefix_hex",
            "resize_suffix_hex",
            "min_cols",
            "max_cols",
            "min_rows",
            "max_rows",
            "replay_capacity_bytes",
            "detach_retention_seconds",
            "registry_max_entries",
            "replacement_close_code",
            "process_exit_close_code",
        },
        "constants",
    )
    expect_hex(constants["resize_prefix_hex"], "constants.resize_prefix_hex")
    expect_hex(constants["resize_suffix_hex"], "constants.resize_suffix_hex")
    expect_string(constants["resize_prefix_hex"], "constants.resize_prefix_hex", "1b5b524553495a453a")
    expect_string(constants["resize_suffix_hex"], "constants.resize_suffix_hex", "5d")
    expect_int(constants["min_cols"], "constants.min_cols", 1)
    expect_int(constants["max_cols"], "constants.max_cols", 2000)
    expect_int(constants["min_rows"], "constants.min_rows", 1)
    expect_int(constants["max_rows"], "constants.max_rows", 1000)
    expect_int(constants["replay_capacity_bytes"], "constants.replay_capacity_bytes", 1048576)
    expect_int(constants["detach_retention_seconds"], "constants.detach_retention_seconds", 1800)
    expect_int(constants["registry_max_entries"], "constants.registry_max_entries", 16)
    expect_int(constants["replacement_close_code"], "constants.replacement_close_code", 4409)
    expect_int(constants["process_exit_close_code"], "constants.process_exit_close_code", 4410)

    evidence = exact_keys(root["evidence"], {"accessibility", "security", "benchmark"}, "evidence")
    accessibility = exact_keys(
        evidence["accessibility"], {"status", "reason", "preservation_reference"}, "evidence.accessibility"
    )
    expect_string(accessibility["status"], "evidence.accessibility.status", "not-applicable")
    expect_string(accessibility["reason"], "evidence.accessibility.reason", "Protocol-only fixture; no UI nodes or interaction code changed.")
    expect_string(accessibility["preservation_reference"], "evidence.accessibility.preservation_reference", "contracts/state-models/terminal.md")
    security = exact_keys(
        evidence["security"], {"status", "synthetic_only", "raw_pty_bytes_logged", "live_integration"}, "evidence.security"
    )
    expect_string(security["status"], "evidence.security.status", "pass")
    expect_bool(security["synthetic_only"], "evidence.security.synthetic_only", True)
    expect_bool(security["raw_pty_bytes_logged"], "evidence.security.raw_pty_bytes_logged", False)
    expect_bool(security["live_integration"], "evidence.security.live_integration", False)
    benchmark = exact_keys(
        evidence["benchmark"], {"status", "artifact", "approved_budget"}, "evidence.benchmark"
    )
    expect_string(benchmark["status"], "evidence.benchmark.status", "baseline-only")
    expect_string(benchmark["artifact"], "evidence.benchmark.artifact", "validation-baseline.json")
    expect_none(benchmark["approved_budget"], "evidence.benchmark.approved_budget")

    cases = expect_list(root["cases"], "cases")
    if len(cases) != len(EXPECTED_CASES):
        fail("cases", f"must contain exactly {len(EXPECTED_CASES)} canonical cases")
    ids: list[str] = []
    for case in cases:
        case_id = case.get("id") if type(case) is dict else None
        if type(case_id) is not str:
            fail("cases", "case ids must be strings before uniqueness checks")
        if case_id in ids:
            fail("cases", f"duplicate case id {case_id!r}")
        ids.append(case_id)
        validate_case(case, constants)
    if set(ids) != set(EXPECTED_CASES):
        fail("cases", "canonical case set differs")
    if ids != list(EXPECTED_CASES):
        fail("cases", "canonical case order differs")
    return {"case_count": len(cases), "case_ids": ids}


def validate_baseline(data: Any) -> dict[str, Any]:
    """Validate the measured baseline as a closed, derived artifact schema."""

    _validate_json_tree(data, "baseline")
    scan_for_forbidden_text(data, "baseline")
    root = exact_keys(
        data,
        {
            "schema_version",
            "fixture",
            "metric",
            "environment",
            "runs",
            "artifact_size_bytes",
            "artifact_content_sha256",
            "approved_budget",
            "notes",
        },
        "baseline",
    )
    expect_string(root["schema_version"], "baseline.schema_version", "pty-contract-baseline-v1")
    expect_string(root["fixture"], "baseline.fixture", "pty-contract-fixtures.json")
    expect_string(root["metric"], "baseline.metric", "validator_wall_clock_ms")

    environment = exact_keys(
        root["environment"], {"os", "arch", "python", "runtime"}, "baseline.environment"
    )
    expect_string(environment["os"], "baseline.environment.os", "Darwin")
    expect_string(environment["arch"], "baseline.environment.arch", "arm64")
    expect_string(environment["python"], "baseline.environment.python", "3.14.6")
    expect_string(environment["runtime"], "baseline.environment.runtime", "CPython")

    runs = expect_list(root["runs"], "baseline.runs")
    if len(runs) != 2:
        fail("baseline.runs", "must contain normal and optimized observations")
    expected_runs = [
        ("normal", "python3 validate.py"),
        ("optimized", "python3 -O validate.py"),
    ]
    for index, run in enumerate(runs):
        run_path = f"baseline.runs[{index}]"
        run = exact_keys(run, {"mode", "command", "samples_ms", "distribution"}, run_path)
        expected_mode, expected_command = expected_runs[index]
        expect_string(run["mode"], f"{run_path}.mode", expected_mode)
        expect_string(run["command"], f"{run_path}.command", expected_command)
        samples = expect_list(run["samples_ms"], f"{run_path}.samples_ms")
        if len(samples) != 10:
            fail(f"{run_path}.samples_ms", "must contain exactly ten timing samples")
        sample_values: list[float] = []
        for sample_index, sample in enumerate(samples):
            value = expect_float(sample, f"{run_path}.samples_ms[{sample_index}]")
            if value <= 0:
                fail(f"{run_path}.samples_ms[{sample_index}]", "must be positive")
            sample_values.append(value)
        ordered = sorted(sample_values)
        p95_index = min(len(ordered) - 1, math.ceil(len(ordered) * 0.95) - 1)
        expected_distribution = {
            "min_ms": round(min(sample_values), 3),
            "median_ms": round(statistics.median(sample_values), 3),
            "p95_ms": ordered[p95_index],
            "max_ms": max(sample_values),
        }
        distribution = exact_keys(
            run["distribution"],
            {"min_ms", "median_ms", "p95_ms", "max_ms"},
            f"{run_path}.distribution",
        )
        for field, expected_value in expected_distribution.items():
            actual = expect_float(distribution[field], f"{run_path}.distribution.{field}")
            if actual != expected_value:
                fail(
                    f"{run_path}.distribution.{field}",
                    f"must equal the derived observation {expected_value}",
                )
        if not (
            expected_distribution["min_ms"]
            <= expected_distribution["median_ms"]
            <= expected_distribution["p95_ms"]
            <= expected_distribution["max_ms"]
        ):
            fail(run_path, "distribution ordering is invalid")

    artifact_sizes = exact_keys(
        root["artifact_size_bytes"], {"scope", "files", "total"}, "baseline.artifact_size_bytes"
    )
    expect_string(
        artifact_sizes["scope"],
        "baseline.artifact_size_bytes.scope",
        "owned fixture files excluding this mutable baseline record",
    )
    files = exact_keys(
        artifact_sizes["files"],
        {"README.md", "pty-contract-fixtures.json", "validate.py", "test_validate.py"},
        "baseline.artifact_size_bytes.files",
    )
    file_total = 0
    for name, size in files.items():
        size_value = expect_int(size, f"baseline.artifact_size_bytes.files.{name}")
        if size_value <= 0:
            fail(f"baseline.artifact_size_bytes.files.{name}", "must be positive")
        file_path = ROOT / name
        try:
            actual_size = file_path.stat().st_size
        except OSError as exc:
            fail(f"baseline.artifact_size_bytes.files.{name}", f"cannot measure artifact: {exc}")
        if actual_size != size_value:
            fail(
                f"baseline.artifact_size_bytes.files.{name}",
                f"must match the measured artifact size {actual_size}",
            )
        file_total += size_value
    expect_int(artifact_sizes["total"], "baseline.artifact_size_bytes.total", file_total)

    content_hashes = exact_keys(
        root["artifact_content_sha256"],
        {"files", "manifest"},
        "baseline.artifact_content_sha256",
    )
    recorded_digests = exact_keys(
        content_hashes["files"],
        set(BASELINE_ARTIFACT_NAMES),
        "baseline.artifact_content_sha256.files",
    )
    measured_digests: dict[str, str] = {}
    measured_sizes: dict[str, int] = {}
    for name in BASELINE_ARTIFACT_NAMES:
        file_path = ROOT / name
        measured_size = file_path.stat().st_size
        measured_digest = sha256_file(file_path, f"baseline.artifact_content_sha256.files.{name}")
        expect_sha256(
            recorded_digests[name],
            f"baseline.artifact_content_sha256.files.{name}",
            measured_digest,
        )
        measured_digests[name] = measured_digest
        measured_sizes[name] = measured_size
    expect_sha256(
        content_hashes["manifest"],
        "baseline.artifact_content_sha256.manifest",
        artifact_manifest_digest(measured_digests, measured_sizes),
    )
    expect_none(root["approved_budget"], "baseline.approved_budget")
    expect_string(
        root["notes"],
        "baseline.notes",
        "Observation only; no approved performance threshold exists. This is fixture-validator timing, not PTY runtime latency.",
    )
    return {"run_count": len(runs), "artifact_size_bytes": file_total}


def case_by_id(data: dict[str, Any], case_id: str) -> dict[str, Any]:
    for case in data["cases"]:
        if type(case) is dict and case.get("id") == case_id:
            return case
    raise AssertionError(f"missing fixture case {case_id}")


def mutation_inventory(data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Return a closed, named set of invalid mutations for regression coverage."""

    mutations: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
        ("root-schema", lambda item: item.__setitem__("schema_version", "pty-contract-v0")),
        ("root-extra-field", lambda item: item.__setitem__("unexpected", True)),
        ("contract-surface", lambda item: item["contract"].__setitem__("surface", "apple")),
        ("contract-pinned-sha", lambda item: item["contract"].__setitem__("pinned_hermes_sha", "0" * 40)),
        ("raw-frame-type", lambda item: case_by_id(item, "raw-bytes-preserve")["input"].__setitem__("frame_type", "text")),
        ("raw-reencode", lambda item: case_by_id(item, "raw-bytes-preserve")["expected"].__setitem__("reencode", True)),
        ("raw-boundary", lambda item: case_by_id(item, "raw-bytes-boundaries")["expected"].__setitem__("frame_boundaries_preserved", False)),
        ("resize-prefix", lambda item: case_by_id(item, "resize-bounds")["expected"].__setitem__("prefix_hex", "00")),
        ("resize-bound", lambda item: case_by_id(item, "resize-bounds")["input"]["samples"][0].__setitem__("effective_cols", 2)),
        ("resize-rejection-accepts", lambda item: case_by_id(item, "resize-rejection")["input"]["candidates"][0].__setitem__("expected", "clamped")),
        ("resize-rejection-writes", lambda item: case_by_id(item, "resize-rejection")["expected"].__setitem__("pty_write", True)),
        ("resize-rejection-float", lambda item: case_by_id(item, "resize-rejection")["input"]["candidates"][1].__setitem__("cols", 80.0)),
        ("resize-rejection-bool", lambda item: case_by_id(item, "resize-rejection")["input"]["candidates"][1].__setitem__("rows", True)),
        ("resize-rejection-float-coerced", lambda item: case_by_id(item, "resize-rejection")["input"]["candidates"][0].__setitem__("cols", 1001)),
        ("resize-rejection-bool-coerced", lambda item: case_by_id(item, "resize-rejection")["input"]["candidates"][1].__setitem__("cols", 1)),
        ("resize-rejection-string-coerced", lambda item: case_by_id(item, "resize-rejection")["input"]["candidates"][2].__setitem__("cols", 1001)),
        ("legacy-missing-close", lambda item: case_by_id(item, "legacy-missing-attach")["expected"].__setitem__("close_result", "socket-detached")),
        ("legacy-missing-timeline", lambda item: case_by_id(item, "legacy-missing-attach")["input"]["events"][4].__setitem__("name", "process.exit")),
        ("legacy-empty-mode", lambda item: case_by_id(item, "legacy-empty-attach")["expected"].__setitem__("mode", "attach")),
        ("legacy-empty-timeline", lambda item: case_by_id(item, "legacy-empty-attach")["input"]["events"][1].__setitem__("name", "socket.disconnect")),
        ("attach-close-kills", lambda item: case_by_id(item, "attach-keepalive")["expected"].__setitem__("close_result", "child-terminated")),
        ("attach-reuse-event", lambda item: case_by_id(item, "attach-keepalive")["input"]["events"][6].__setitem__("name", "registry.spawn")),
        ("attach-identity", lambda item: case_by_id(item, "attach-keepalive")["input"]["events"][7].__setitem__("process_ref", "synthetic-process-other")),
        ("replacement-code", lambda item: case_by_id(item, "replacement-4409")["input"]["events"][0].__setitem__("code", 4410)),
        ("replacement-order", lambda item: case_by_id(item, "replacement-4409")["input"]["events"].__setitem__(slice(0, 2), reversed(case_by_id(item, "replacement-4409")["input"]["events"][0:2]))),
        ("replacement-identity", lambda item: case_by_id(item, "replacement-4409")["input"]["events"][1].__setitem__("session_ref", "synthetic-session-other")),
        ("process-exit-code", lambda item: case_by_id(item, "process-exit-4410")["input"]["events"][1].__setitem__("code", 4409)),
        ("detach-retention", lambda item: case_by_id(item, "detach-window")["expected"].__setitem__("retention_seconds", 60)),
        ("detach-boundary", lambda item: case_by_id(item, "detach-window")["input"]["probes"][1].__setitem__("outcome", "reattach-expired")),
        ("registry-cap", lambda item: case_by_id(item, "registry-cap")["expected"].__setitem__("max_entries", 15)),
        ("replay-capacity", lambda item: case_by_id(item, "replay-newest-tail")["expected"].__setitem__("capacity_bytes", 1024)),
        ("replay-old-retained", lambda item: case_by_id(item, "replay-newest-tail")["expected"].__setitem__("tail_ref", "synthetic-output-old")),
        ("action-input-replayed", lambda item: case_by_id(item, "replay-action-exclusion")["input"]["actions"][0].__setitem__("replayed", True)),
        ("action-tool-replayed", lambda item: case_by_id(item, "replay-action-exclusion")["expected"].__setitem__("replayed_action_kinds", ["tool"])),
        ("race-order-missing", lambda item: case_by_id(item, "replay-live-race")["expected"].__setitem__("allowed_orderings", ["retained-before-live"])),
        ("race-separator", lambda item: case_by_id(item, "replay-live-race")["expected"].__setitem__("separator_hex", "00")),
        ("logging-payload", lambda item: case_by_id(item, "no-byte-logging")["input"]["logs"][0].__setitem__("byte_payload_hex", "4f4b0a")),
        ("logging-action-payload", lambda item: case_by_id(item, "no-byte-logging")["input"]["logs"][2].__setitem__("action_payload_hex", "696e707574")),
        ("logging-metadata", lambda item: case_by_id(item, "no-byte-logging")["input"]["logs"][0].__setitem__("metadata_only", False)),
        ("source-audit-digest", lambda item: item["source_audit"]["artifacts"]["source-evidence.json"].__setitem__("sha256", "0" * 64)),
        ("source-audit-size", lambda item: item["source_audit"]["artifacts"]["source-evidence.json"].__setitem__("size_bytes", 1)),
        ("source-audit-revision", lambda item: item["source_audit"]["pinned_commit"].__setitem__("sha", "0" * 40)),
        ("unknown-case-kind", lambda item: case_by_id(item, "raw-bytes-preserve").__setitem__("kind", "unknown")),
        ("duplicate-case-id", lambda item: item["cases"][1].__setitem__("id", item["cases"][0]["id"])),
        ("malformed-input-object", lambda item: case_by_id(item, "raw-bytes-preserve").__setitem__("input", None)),
        ("malformed-expected-object", lambda item: case_by_id(item, "raw-bytes-preserve").__setitem__("expected", None)),
    ]
    result: list[tuple[str, dict[str, Any]]] = []
    for mutation_id, mutation in mutations:
        candidate = copy.deepcopy(data)
        mutation(candidate)
        result.append((mutation_id, candidate))
    return result


def validate_mutations(data: dict[str, Any]) -> int:
    mutations = mutation_inventory(data)
    seen: set[str] = set()
    for mutation_id, candidate in mutations:
        if mutation_id in seen:
            raise ValidationError(f"mutation inventory: duplicate id {mutation_id!r}")
        seen.add(mutation_id)
        try:
            validate_contract(candidate)
        except ValidationError:
            continue
        raise ValidationError(f"mutation inventory: {mutation_id} was accepted")
    return len(mutations)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON object keys instead of silently taking the last value."""

    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def reject_non_finite(value: str) -> None:
    """Reject JSON NaN/Infinity extensions before schema validation sees them."""

    raise ValueError(f"non-finite JSON number {value}")


def load_fixture(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(
                handle,
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=reject_non_finite,
            )
    except (OSError, ValueError, RecursionError) as exc:
        raise ValidationError(f"cannot read JSON fixture: {exc}") from None
    if type(value) is not dict:
        fail("root", "fixture JSON must be an object")
    return value


def artifact_bytes() -> int:
    """Measure stable owned artifacts without making the baseline self-referential."""

    paths = [ROOT / name for name in BASELINE_ARTIFACT_NAMES]
    return sum(path.stat().st_size for path in paths if path.exists())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    args = parser.parse_args(argv)
    try:
        data = load_fixture(args.fixture)
        summary = validate_contract(data)
        baseline = load_fixture(args.baseline)
        baseline_summary = validate_baseline(baseline)
        mutation_count = validate_mutations(data)
    except (ValidationError, OSError, TypeError, RecursionError) as exc:
        print(bound_error(f"validation failed: {exc}"), file=sys.stderr)
        return 1
    print(
        "validated "
        f"cases={summary['case_count']} "
        f"mutation_checks={mutation_count} "
        f"fixture_artifact_bytes={artifact_bytes()} "
        f"baseline_artifact_bytes={baseline_summary['artifact_size_bytes']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
