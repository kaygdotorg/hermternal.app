"""Strict validation for the offline synthetic /api/pty contract.

The fixture is deliberately a byte adapter proof, not a PTY implementation. Hex
keeps binary data lossless, while closed object schemas make contract drift fail
before a future web client can silently reinterpret it.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent
DEFAULT_FIXTURE = ROOT / "pty-contract-fixtures.json"
PINNED_HERMES_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
SYNTHETIC_REF = re.compile(r"^synthetic-[a-z0-9-]+$")
HEX_VALUE = re.compile(r"^[0-9a-f]*$")
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


class ValidationError(ValueError):
    """A deterministic, user-facing fixture validation failure."""


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


def expect_synthetic_ref(value: Any, path: str) -> str:
    text = expect_string(value, path)
    if SYNTHETIC_REF.fullmatch(text) is None:
        fail(path, "must be a synthetic reference")
    return text


def scan_for_forbidden_text(value: Any, path: str = "root") -> None:
    """Reject secret-shaped prose while allowing explicit synthetic byte data."""

    if type(value) is dict:
        for key, child in value.items():
            scan_for_forbidden_text(child, f"{path}.{key}")
    elif type(value) is list:
        for index, child in enumerate(value):
            scan_for_forbidden_text(child, f"{path}[{index}]")
    elif type(value) is str:
        lowered = value.lower()
        for marker in FORBIDDEN_TEXT:
            if marker in lowered:
                fail(path, f"contains forbidden marker {marker!r}")


def clamp(value: int, lower: int, upper: int) -> int:
    return max(lower, min(upper, value))


def resize_control(prefix_hex: str, suffix_hex: str, cols: int, rows: int) -> str:
    return (
        bytes.fromhex(prefix_hex)
        + f"{cols};{rows}".encode("ascii")
        + bytes.fromhex(suffix_hex)
    ).hex()


def segment_bytes(segment: dict[str, Any], path: str) -> bytes:
    exact_keys(segment, {"ref", "byte_hex", "repeat"}, path)
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


def validate_resize(case: dict[str, Any], constants: dict[str, Any]) -> None:
    path = case["id"]
    input_data = exact_keys(case["input"], {"samples"}, f"{path}.input")
    expected = exact_keys(
        case["expected"],
        {"prefix_hex", "suffix_hex", "control_is_single_binary_message", "written_to_pty"},
        f"{path}.expected",
    )
    samples = expect_list(input_data["samples"], f"{path}.input.samples")
    if len(samples) != 4:
        fail(f"{path}.input.samples", "must contain the four boundary samples")
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

    required_bounds = {(1, 1), (2000, 1000), (0, 0), (2001, 1001)}
    if set(observed_bounds) != required_bounds:
        fail(f"{path}.input.samples", "must cover minimum, maximum, underflow, and overflow")


def validate_resize_rejection(case: dict[str, Any]) -> None:
    path = case["id"]
    input_data = exact_keys(case["input"], {"candidates"}, f"{path}.input")
    expected = exact_keys(
        case["expected"],
        {"rejected_before_binary_send", "error_mode", "pty_write"},
        f"{path}.expected",
    )
    candidates = expect_list(input_data["candidates"], f"{path}.input.candidates")
    if len(candidates) != 4:
        fail(f"{path}.input.candidates", "must cover malformed and out-of-range dimensions")
    expected_candidates = [
        ("wide", 24, "malformed"),
        (80, "tall", "malformed"),
        (-1, 24, "out-of-range"),
        (80, 1001, "out-of-range"),
    ]
    for index, candidate in enumerate(candidates):
        candidate_path = f"{path}.input.candidates[{index}]"
        candidate = exact_keys(candidate, {"cols", "rows", "reason", "expected"}, candidate_path)
        expected_cols, expected_rows, expected_reason = expected_candidates[index]
        if candidate["cols"] != expected_cols:
            fail(f"{candidate_path}.cols", "does not match the canonical invalid input")
        if candidate["rows"] != expected_rows:
            fail(f"{candidate_path}.rows", "does not match the canonical invalid input")
        expect_string(candidate["reason"], f"{candidate_path}.reason", expected_reason)
        expect_string(candidate["expected"], f"{candidate_path}.expected", "rejected")
    expect_bool(expected["rejected_before_binary_send"], f"{path}.expected.rejected_before_binary_send", True)
    expect_string(expected["error_mode"], f"{path}.expected.error_mode", "safe-validation-failure")
    expect_bool(expected["pty_write"], f"{path}.expected.pty_write", False)


def validate_legacy(case: dict[str, Any], constants: dict[str, Any]) -> None:
    path = case["id"]
    input_data = exact_keys(
        case["input"], {"attach_query", "process_ref", "events"}, f"{path}.input"
    )
    expected = exact_keys(
        case["expected"],
        {
            "mode",
            "disconnect_result",
            "close_result",
            "final_state",
            "registry_path",
            "reattach",
            "process_ref",
        },
        f"{path}.expected",
    )
    if case["id"] == "legacy-missing-attach":
        expect_none(input_data["attach_query"], f"{path}.input.attach_query")
    else:
        expect_string(input_data["attach_query"], f"{path}.input.attach_query", "")
    process_ref = expect_synthetic_ref(input_data["process_ref"], f"{path}.input.process_ref")
    events = expect_list(input_data["events"], f"{path}.input.events")
    if events != ["disconnect", "close"]:
        fail(f"{path}.input.events", "must exercise disconnect and explicit Close")
    expect_string(expected["mode"], f"{path}.expected.mode", "legacy")
    expect_string(expected["disconnect_result"], f"{path}.expected.disconnect_result", "child-terminated")
    expect_string(expected["close_result"], f"{path}.expected.close_result", "child-terminated")
    expect_string(expected["final_state"], f"{path}.expected.final_state", "exited")
    expect_string(expected["registry_path"], f"{path}.expected.registry_path", "not-used")
    expect_string(expected["reattach"], f"{path}.expected.reattach", "prohibited")
    expect_string(expected["process_ref"], f"{path}.expected.process_ref", process_ref)
    if constants["registry_max_entries"] != 16:
        fail("constants.registry_max_entries", "must remain 16 for the legacy proof")


def validate_attach(case: dict[str, Any], constants: dict[str, Any]) -> None:
    path = case["id"]
    input_data = exact_keys(
        case["input"],
        {"attach_query", "process_ref", "registry_ref", "events"},
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
        },
        f"{path}.expected",
    )
    attach_query = expect_synthetic_ref(input_data["attach_query"], f"{path}.input.attach_query")
    process_ref = expect_synthetic_ref(input_data["process_ref"], f"{path}.input.process_ref")
    registry_ref = expect_synthetic_ref(input_data["registry_ref"], f"{path}.input.registry_ref")
    if input_data["events"] != ["disconnect", "close"]:
        fail(f"{path}.input.events", "must exercise disconnect and explicit Close")
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
    if not attach_query:
        fail(f"{path}.input.attach_query", "must be non-empty for registry keep-alive")


def validate_replacement(case: dict[str, Any], constants: dict[str, Any]) -> None:
    path = case["id"]
    input_data = exact_keys(
        case["input"],
        {"attach_query", "old_socket_ref", "new_socket_ref", "events"},
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
        },
        f"{path}.expected",
    )
    expect_synthetic_ref(input_data["attach_query"], f"{path}.input.attach_query")
    old_socket = expect_synthetic_ref(input_data["old_socket_ref"], f"{path}.input.old_socket_ref")
    new_socket = expect_synthetic_ref(input_data["new_socket_ref"], f"{path}.input.new_socket_ref")
    if old_socket == new_socket:
        fail(f"{path}.input", "replacement sockets must be distinct")
    events = expect_list(input_data["events"], f"{path}.input.events")
    if len(events) != 3:
        fail(f"{path}.input.events", "must contain close, assign, and stale cleanup")
    first = exact_keys(events[0], {"name", "socket_ref", "code"}, f"{path}.input.events[0]")
    second = exact_keys(events[1], {"name", "socket_ref"}, f"{path}.input.events[1]")
    third = exact_keys(events[2], {"name", "socket_ref", "action", "result"}, f"{path}.input.events[2]")
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
        {"retention_seconds", "within_window", "after_window", "identity_preserved_during_window"},
        f"{path}.expected",
    )
    epoch = expect_int(input_data["detach_epoch_seconds"], f"{path}.input.detach_epoch_seconds")
    if epoch < 0:
        fail(f"{path}.input.detach_epoch_seconds", "must be a non-negative synthetic epoch")
    probes = expect_list(input_data["probes"], f"{path}.input.probes")
    if len(probes) != 2:
        fail(f"{path}.input.probes", "must include before and after retention probes")
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
    if observed != {retention - 1: "reattach-allowed", retention + 1: "reattach-expired"}:
        fail(f"{path}.input.probes", "must prove both sides of the 30-minute window")
    expect_int(expected["retention_seconds"], f"{path}.expected.retention_seconds", retention)
    expect_string(expected["within_window"], f"{path}.expected.within_window", "reattach-allowed")
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
        ref = expect_synthetic_ref(segment.get("ref"), f"{segment_path}.ref") if type(segment) is dict else ""
        if ref in refs:
            fail(segment_path, "segment references must be unique")
        refs.append(ref)
        rendered.append(segment_bytes(segment, segment_path))
    output = b"".join(rendered)
    capacity = constants["replay_capacity_bytes"]
    tail = output[-capacity:]
    expect_int(expected["capacity_bytes"], f"{path}.expected.capacity_bytes", capacity)
    expect_string(expected["tail_ref"], f"{path}.expected.tail_ref", refs[-1])
    expect_int(expected["tail_length"], f"{path}.expected.tail_length", capacity)
    expect_string(expected["older_output"], f"{path}.expected.older_output", "may-be-missing")
    expect_string(expected["frame_type"], f"{path}.expected.frame_type", "binary")
    newest = rendered[-1]
    if len(newest) <= capacity:
        fail(f"{path}.input.output_segments[1].repeat", "newest output must exceed capacity")
    if tail != newest[-capacity:]:
        fail(path, "replay is not the newest byte tail")
    if len(tail) != capacity:
        fail(path, "replay tail length differs from the 1 MiB bound")
    if rendered[0] and rendered[0][:1] not in tail:
        return
    if rendered[0] and rendered[0][:1] == tail[:1]:
        fail(path, "old output unexpectedly survives in the deterministic newest tail")


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
    input_data = exact_keys(case["input"], {"frames", "logs"}, f"{path}.input")
    expected = exact_keys(
        case["expected"],
        {"raw_bytes_logged", "payload_fields_are_null", "metadata_only", "allowed_metadata"},
        f"{path}.expected",
    )
    frames = expect_list(input_data["frames"], f"{path}.input.frames")
    logs = expect_list(input_data["logs"], f"{path}.input.logs")
    if len(frames) != 1 or len(logs) != 1:
        fail(path, "must contain one synthetic frame and one metadata record")
    frame = exact_keys(frames[0], {"frame_ref", "frame_hex"}, f"{path}.input.frames[0]")
    frame_ref = expect_synthetic_ref(frame["frame_ref"], f"{path}.input.frames[0].frame_ref")
    frame_hex = expect_hex(frame["frame_hex"], f"{path}.input.frames[0].frame_hex")
    log = exact_keys(
        logs[0],
        {"event", "frame_ref", "byte_payload_hex", "byte_length", "metadata_only"},
        f"{path}.input.logs[0]",
    )
    expect_string(log["event"], f"{path}.input.logs[0].event", "pty.frame.received")
    expect_string(log["frame_ref"], f"{path}.input.logs[0].frame_ref", frame_ref)
    expect_none(log["byte_payload_hex"], f"{path}.input.logs[0].byte_payload_hex")
    expect_int(log["byte_length"], f"{path}.input.logs[0].byte_length", len(bytes.fromhex(frame_hex)))
    expect_bool(log["metadata_only"], f"{path}.input.logs[0].metadata_only", True)
    expect_bool(expected["raw_bytes_logged"], f"{path}.expected.raw_bytes_logged", False)
    expect_bool(expected["payload_fields_are_null"], f"{path}.expected.payload_fields_are_null", True)
    expect_bool(expected["metadata_only"], f"{path}.expected.metadata_only", True)
    allowed_metadata = expect_list(expected["allowed_metadata"], f"{path}.expected.allowed_metadata")
    if allowed_metadata != ["event", "frame_ref", "byte_length", "metadata_only"]:
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

    scan_for_forbidden_text(data)
    root = exact_keys(data, {"schema_version", "contract", "constants", "evidence", "cases"}, "root")
    expect_string(root["schema_version"], "schema_version", "pty-contract-v1")

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
        ("resize-prefix", lambda item: case_by_id(item, "resize-bounds")["expected"].__setitem__("prefix_hex", "00")),
        ("resize-bound", lambda item: case_by_id(item, "resize-bounds")["input"]["samples"][0].__setitem__("effective_cols", 2)),
        ("resize-rejection-accepts", lambda item: case_by_id(item, "resize-rejection")["input"]["candidates"][0].__setitem__("expected", "clamped")),
        ("resize-rejection-writes", lambda item: case_by_id(item, "resize-rejection")["expected"].__setitem__("pty_write", True)),
        ("legacy-missing-close", lambda item: case_by_id(item, "legacy-missing-attach")["expected"].__setitem__("close_result", "socket-detached")),
        ("legacy-empty-mode", lambda item: case_by_id(item, "legacy-empty-attach")["expected"].__setitem__("mode", "attach")),
        ("attach-close-kills", lambda item: case_by_id(item, "attach-keepalive")["expected"].__setitem__("close_result", "child-terminated")),
        ("replacement-code", lambda item: case_by_id(item, "replacement-4409")["input"]["events"][0].__setitem__("code", 4410)),
        ("replacement-order", lambda item: case_by_id(item, "replacement-4409")["input"]["events"].__setitem__(slice(0, 2), reversed(case_by_id(item, "replacement-4409")["input"]["events"][0:2]))),
        ("process-exit-code", lambda item: case_by_id(item, "process-exit-4410")["input"]["events"][1].__setitem__("code", 4409)),
        ("detach-retention", lambda item: case_by_id(item, "detach-window")["expected"].__setitem__("retention_seconds", 60)),
        ("registry-cap", lambda item: case_by_id(item, "registry-cap")["expected"].__setitem__("max_entries", 15)),
        ("replay-capacity", lambda item: case_by_id(item, "replay-newest-tail")["expected"].__setitem__("capacity_bytes", 1024)),
        ("replay-old-retained", lambda item: case_by_id(item, "replay-newest-tail")["expected"].__setitem__("tail_ref", "synthetic-output-old")),
        ("action-input-replayed", lambda item: case_by_id(item, "replay-action-exclusion")["input"]["actions"][0].__setitem__("replayed", True)),
        ("action-tool-replayed", lambda item: case_by_id(item, "replay-action-exclusion")["expected"].__setitem__("replayed_action_kinds", ["tool"])),
        ("race-order-missing", lambda item: case_by_id(item, "replay-live-race")["expected"].__setitem__("allowed_orderings", ["retained-before-live"])),
        ("race-separator", lambda item: case_by_id(item, "replay-live-race")["expected"].__setitem__("separator_hex", "00")),
        ("logging-payload", lambda item: case_by_id(item, "no-byte-logging")["input"]["logs"][0].__setitem__("byte_payload_hex", "4f4b0a")),
        ("logging-metadata", lambda item: case_by_id(item, "no-byte-logging")["input"]["logs"][0].__setitem__("metadata_only", False)),
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
    except (OSError, ValueError) as exc:
        raise ValidationError(f"cannot read JSON fixture: {exc}") from None
    if type(value) is not dict:
        fail("root", "fixture JSON must be an object")
    return value


def artifact_bytes() -> int:
    """Measure stable owned artifacts without making the baseline self-referential."""

    paths = [
        ROOT / "README.md",
        ROOT / "pty-contract-fixtures.json",
        ROOT / "validate.py",
        ROOT / "test_validate.py",
    ]
    return sum(path.stat().st_size for path in paths if path.exists())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    args = parser.parse_args(argv)
    try:
        data = load_fixture(args.fixture)
        summary = validate_contract(data)
        mutation_count = validate_mutations(data)
    except (ValidationError, OSError, TypeError) as exc:
        print(f"validation failed: {exc}", file=sys.stderr)
        return 1
    print(
        "validated "
        f"cases={summary['case_count']} "
        f"mutation_checks={mutation_count} "
        f"fixture_artifact_bytes={artifact_bytes()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
