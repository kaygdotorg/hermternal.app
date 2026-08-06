#!/usr/bin/env python3
"""Strict validation for the offline synthetic C-18 PTY lifecycle fixtures.

This is contract evidence, not a PTY implementation. Closed schemas and
identity-bound timelines make detach, replay, truncation, and redaction drift
fail before a future client can silently reinterpret the behavior.
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
DEFAULT_FIXTURE = ROOT / "pty-detach-race-fixtures.json"
DEFAULT_BASELINE = ROOT / "validation-baseline.json"
SCHEMA_VERSION = "pty-detach-race-v1"
BASELINE_SCHEMA_VERSION = "pty-detach-race-baseline-v1"
MAX_JSON_DEPTH = 128
MAX_DOCUMENT_BYTES = 2_000_000
MAX_ERROR_LENGTH = 240
ERROR_SUFFIX = "... [truncated]"
REPLAY_CAPACITY = 1_048_576
DETACH_RETENTION = 1_800
REGISTRY_MAX = 16
MIN_COLS = 1
MAX_COLS = 2_000
MIN_ROWS = 1
MAX_ROWS = 1_000
REPLACEMENT_CLOSE = 4_409
SYNTHETIC_REF = re.compile(r"^synthetic-[a-z0-9-]+$")
HEX_VALUE = re.compile(r"^[0-9a-f]*$")
ARTIFACT_NAMES = (
    "README.md",
    "pty-detach-race-fixtures.json",
    "validate.py",
    "test_validate.py",
)
# Pin reviewed evidence outside the mutable baseline. The source digest uses a
# fixed identity-marker placeholder so this file can authenticate its own bytes;
# changing executable code changes the normalized digest. Benchmark trace and
# distribution digests are code-pinned and cannot be rebound through JSON.
CANONICAL_SOURCE_SHA256 = "32de2c3590036fd0277b7ef20c42633e63bda0baa613e3765594ef0818d58400"
CANONICAL_BENCHMARK_IDENTITY = (
    (
        "normal",
        "7472ce2fe8c2e5795e1e9df4abeeaa9dc535e2438e88f0225eeb45e4e2d2a1e3",
        "9dc165ac98f282c93aca83a86159d4342da8efb3eee4ba8200d1b06965abf8dd",
    ),
    (
        "optimized",
        "8e658e4726fd786b78010fe6e2d9661568cc536426188130212a0ac94fd41b3e",
        "2bf31014724bfc43ab80cfc90da2d06824c8d45fa91776e4218325fa1b0053e9",
    ),
)
CANONICAL_ARTIFACT_IDENTITY = (
    ("README.md", 7355, "7d83fbadcc32a7bea5e1e111384ea03988498ab4a597eb72f6b2664fb4d3d4d0"),
    (
        "pty-detach-race-fixtures.json",
        19319,
        "ee8211b672e5a78d1d069c1ca4df4155aecbce951058579e3a985cfb6de06227",
    ),
    ("test_validate.py", 20275, "88f6f732f5d024beb5a668e7b34876b1c544212166eeee3f85adb2789d040223"),
)
CANONICAL_BASELINE_IDENTITY = {
    "schema_version": "pty-detach-race-baseline-v1",
    "fixture_schema_version": "pty-detach-race-v1",
    "artifact_paths": (
        "contracts/fixtures/pty-detach-race/README.md",
        "contracts/fixtures/pty-detach-race/pty-detach-race-fixtures.json",
        "contracts/fixtures/pty-detach-race/validate.py",
        "contracts/fixtures/pty-detach-race/test_validate.py",
    ),
}
FORBIDDEN_TEXT = (
    "api_key",
    "api-key",
    "authorization",
    "bearer",
    "cookie",
    "credential",
    "password",
    "passwd",
    "secret",
    "ssh://",
    "http://",
    "https://",
)
EXPECTED_CASES = {
    "detach-ttl": "detach-ttl",
    "registry-cap": "registry-cap",
    "replay-newest-tail": "replay-newest-tail",
    "replay-live-race": "replay-live-race",
    "superseded-attachment": "supersession",
    "explicit-close": "explicit-close",
    "unsupported-host": "unsupported-host",
    "resize-bounds": "resize-bounds",
    "resize-rejection": "resize-rejection",
    "reconnect-truncation": "reconnect-truncation",
    "no-input-replay": "no-input-replay",
    "no-byte-logging": "no-byte-logging",
}
CANONICAL_OUTPUT_INVENTORY = (
    ("synthetic-output-prompt", "prompt-output", "70726f6d70742d6f7574707574"),
    ("synthetic-output-tool", "tool-output", "746f6f6c2d6f7574707574"),
)
RESIZE_BOUNDARY_SAMPLES = (
    (1, 1, 1, 1),
    (2000, 1000, 2000, 1000),
    (-1, 24, 1, 24),
    (0, 0, 1, 1),
    (80, -1, 80, 1),
    (2001, 24, 2000, 24),
    (80, 1001, 80, 1000),
    (2001, 1001, 2000, 1000),
)
RESIZE_REJECTION_CLASSES = (
    ("cols", "fractional-number"),
    ("cols", "boolean-dimension"),
    ("cols", "string-dimension"),
    ("cols", "null-dimension"),
    ("cols", "non-finite-token"),
    ("frame", "malformed-frame"),
    ("rows", "fractional-number"),
    ("rows", "non-finite-token"),
)
LOG_EVENT_ORDER = ("pty.output", "user.input", "terminal.resize", "prompt.submit", "tool.action")
ACTION_KINDS = ("input", "resize", "prompt", "tool")
CANONICAL_ACTION_INVENTORY = (
    ("input", "synthetic-action-input"),
    ("resize", "synthetic-action-resize"),
    ("prompt", "synthetic-action-prompt"),
    ("tool", "synthetic-action-tool"),
)
CANONICAL_LOG_FRAME_INVENTORY = (
    ("synthetic-output-log-a", "00ff"),
    ("synthetic-output-log-b", "1b5b"),
)


class ValidationError(ValueError):
    """A deterministic, bounded fixture validation failure."""

    def __init__(self, message: object) -> None:
        super().__init__(bound_error(str(message)))


class CommandLineError(Exception):
    """An argparse failure whose caller-controlled details stay private."""


class ControlledArgumentParser(argparse.ArgumentParser):
    """Parse only the supported options without printing paths or flags."""

    def __init__(self) -> None:
        super().__init__(
            add_help=False,
            allow_abbrev=False,
            argument_default=argparse.SUPPRESS,
            usage=argparse.SUPPRESS,
        )

    def error(self, message: str) -> None:
        del message
        raise CommandLineError


def bound_error(text: str) -> str:
    """Bound diagnostics so malformed fixtures cannot exfiltrate large values."""

    if len(text) <= MAX_ERROR_LENGTH:
        return text
    keep = MAX_ERROR_LENGTH - len(ERROR_SUFFIX)
    prefix = keep // 2
    suffix = keep - prefix
    return text[:prefix] + ERROR_SUFFIX + text[-suffix:]


def fail(path: str, message: str) -> None:
    raise ValidationError(f"{path}: {message}")


def exact_keys(value: Any, keys: set[str], path: str) -> dict[str, Any]:
    if type(value) is not dict:
        fail(path, "must be an object")
    actual = set(value)
    if actual != keys:
        missing = sorted(keys - actual)
        extra = sorted(actual - keys)
        details: list[str] = []
        if missing:
            details.append(f"missing={missing}")
        if extra:
            details.append(f"extra={extra}")
        fail(path, "object keys differ (" + ", ".join(details) + ")")
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
        fail(path, "must be a finite number")
    return value


def expect_none(value: Any, path: str) -> None:
    if value is not None:
        fail(path, "must be null")
    return None


def expect_list(value: Any, path: str) -> list[Any]:
    if type(value) is not list:
        fail(path, "must be an array")
    return value


def expect_hex(value: Any, path: str) -> str:
    text = expect_string(value, path)
    if len(text) % 2 or HEX_VALUE.fullmatch(text) is None:
        fail(path, "must be lowercase hexadecimal with an even length")
    return text


def expect_ref(value: Any, path: str) -> str:
    text = expect_string(value, path)
    if SYNTHETIC_REF.fullmatch(text) is None:
        fail(path, "must be a synthetic reference")
    suffix = text.removeprefix("synthetic-")
    if suffix and len(suffix) % 2 == 0 and HEX_VALUE.fullmatch(suffix) is not None:
        fail(path, "must not encode payload bytes in a synthetic reference")
    return text


def _validate_json_tree(value: Any) -> None:
    """Walk iteratively so hostile depth cannot trigger an uncaught traceback."""

    stack: list[tuple[Any, str, int]] = [(value, "document", 0)]
    while stack:
        current, path, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            fail(path, f"maximum JSON nesting depth exceeded ({MAX_JSON_DEPTH})")
        if type(current) is dict:
            for key, child in reversed(list(current.items())):
                if type(key) is not str:
                    fail(path, "object keys must be strings")
                stack.append((child, f"{path}.{key}", depth + 1))
        elif type(current) is list:
            for index, child in reversed(list(enumerate(current))):
                stack.append((child, f"{path}[{index}]", depth + 1))
        elif type(current) is float:
            if not math.isfinite(current):
                fail(path, "non-finite number is not allowed")
        elif current is None or type(current) in (str, bool, int):
            continue
        else:
            fail(path, f"unsupported JSON value type {type(current).__name__}")


def scan_for_forbidden_text(value: Any) -> None:
    """Reject secret-shaped prose without traversing recursively."""

    stack: list[tuple[Any, str]] = [(value, "document")]
    while stack:
        current, path = stack.pop()
        if type(current) is dict:
            for key, child in current.items():
                lowered_key = key.lower()
                if any(token in lowered_key for token in FORBIDDEN_TEXT):
                    fail(path, "contains forbidden text")
                stack.append((child, f"{path}.{key}"))
        elif type(current) is list:
            stack.extend((child, f"{path}[{index}]") for index, child in enumerate(current))
        elif type(current) is str:
            lowered = current.lower()
            if any(token in lowered for token in FORBIDDEN_TEXT):
                fail(path, "contains forbidden text")


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            # Key names can carry credential-shaped data; the reusable loader
            # must preserve the rejection without returning that attacker input.
            del key
            fail("document", "duplicate JSON key rejected")
        result[key] = value
    return result


def reject_non_finite(token: str) -> None:
    raise ValidationError("document: non-finite JSON number is not allowed")


def load_json(path: Path) -> Any:
    try:
        raw = path.read_bytes()
    except OSError:
        raise
    if len(raw) > MAX_DOCUMENT_BYTES:
        fail("document", f"input exceeds {MAX_DOCUMENT_BYTES} bytes")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=reject_non_finite,
        )
    except ValidationError:
        raise
    except UnicodeDecodeError:
        fail("document", "must be UTF-8 JSON")
    except json.JSONDecodeError as exc:
        fail("document", f"invalid JSON at line {exc.lineno} column {exc.colno}")
    except RecursionError:
        fail("document", "JSON nesting exceeds parser safety limit")
    except ValueError:
        fail("document", "invalid JSON value")
    _validate_json_tree(value)
    scan_for_forbidden_text(value)
    return value


def load_fixture(path: Path = DEFAULT_FIXTURE) -> Any:
    return load_json(path)


def load_baseline(path: Path = DEFAULT_BASELINE) -> Any:
    return load_json(path)


def check_refs_unique(values: list[Any], path: str) -> list[str]:
    refs = [expect_ref(value, f"{path}[{index}]") for index, value in enumerate(values)]
    if len(set(refs)) != len(refs):
        fail(path, "references must be unique")
    return refs


def expect_exact_list(value: Any, path: str, expected: list[Any]) -> list[Any]:
    values = expect_list(value, path)
    if type(values) is not list or values != expected:
        fail(path, f"must equal {expected!r}")
    return values


def clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))


def segment_size(segment: dict[str, Any], path: str) -> int:
    raw = bytes.fromhex(expect_hex(segment["byte_hex"], f"{path}.byte_hex"))
    repeat = expect_int(segment["repeat"], f"{path}.repeat")
    if repeat < 1 or repeat > REPLAY_CAPACITY * 2:
        fail(f"{path}.repeat", "is outside the bounded synthetic range")
    return len(raw) * repeat


def validate_detach_ttl(case: dict[str, Any], constants: dict[str, Any]) -> None:
    path = "cases.detach-ttl"
    input_value = exact_keys(case["input"], {"handle_ref", "session_ref", "process_ref", "detached_state", "probes"}, f"{path}.input")
    expected = exact_keys(case["expected"], {"retention_seconds", "predicate", "state_sequence", "expired_only_after"}, f"{path}.expected")
    for key in ("handle_ref", "session_ref", "process_ref"):
        expect_ref(input_value[key], f"{path}.input.{key}")
    expect_string(input_value["detached_state"], f"{path}.input.detached_state", "detached")
    probes = expect_list(input_value["probes"], f"{path}.input.probes")
    if len(probes) != 3:
        fail(f"{path}.input.probes", "must contain exactly three boundary probes")
    expected_elapsed = [1799, 1800, 1801]
    expected_outcomes = ["reattach-allowed", "reattach-allowed", "reattach-expired"]
    for index, probe in enumerate(probes):
        item = exact_keys(probe, {"elapsed_seconds", "outcome"}, f"{path}.input.probes[{index}]")
        expect_int(item["elapsed_seconds"], f"{path}.input.probes[{index}].elapsed_seconds", expected_elapsed[index])
        expect_string(item["outcome"], f"{path}.input.probes[{index}].outcome", expected_outcomes[index])
        actual_expired = item["elapsed_seconds"] > constants["detach_retention_seconds"]
        if actual_expired != (item["outcome"] == "reattach-expired"):
            fail(f"{path}.input.probes[{index}]", "outcome does not follow strict elapsed > retention predicate")
    expect_int(expected["retention_seconds"], f"{path}.expected.retention_seconds", constants["detach_retention_seconds"])
    expect_string(expected["predicate"], f"{path}.expected.predicate", "elapsed <= retention_seconds")
    expect_exact_list(expected["state_sequence"], f"{path}.expected.state_sequence", ["attached", "detached", "reattached", "expired"])
    expect_int(expected["expired_only_after"], f"{path}.expected.expired_only_after", constants["detach_retention_seconds"])


def validate_registry_cap(case: dict[str, Any], constants: dict[str, Any]) -> None:
    path = "cases.registry-cap"
    input_value = exact_keys(case["input"], {"entry_refs", "attempted_entry_ref", "attempted_state"}, f"{path}.input")
    expected = exact_keys(case["expected"], {"max_entries", "existing_count", "new_entry", "eviction"}, f"{path}.expected")
    refs = expect_list(input_value["entry_refs"], f"{path}.input.entry_refs")
    if len(refs) != constants["registry_max_entries"]:
        fail(f"{path}.input.entry_refs", "must contain exactly the registry maximum")
    refs = check_refs_unique(refs, f"{path}.input.entry_refs")
    attempted = expect_ref(input_value["attempted_entry_ref"], f"{path}.input.attempted_entry_ref")
    if attempted in refs:
        fail(f"{path}.input.attempted_entry_ref", "must be distinct from existing entries")
    expect_string(input_value["attempted_state"], f"{path}.input.attempted_state", "detached")
    expect_int(expected["max_entries"], f"{path}.expected.max_entries", constants["registry_max_entries"])
    expect_int(expected["existing_count"], f"{path}.expected.existing_count", constants["registry_max_entries"])
    expect_string(expected["new_entry"], f"{path}.expected.new_entry", "rejected")
    expect_string(expected["eviction"], f"{path}.expected.eviction", "none")


def validate_replay_newest_tail(case: dict[str, Any], constants: dict[str, Any]) -> None:
    path = "cases.replay-newest-tail"
    input_value = exact_keys(case["input"], {"capacity_bytes", "segments"}, f"{path}.input")
    expected = exact_keys(case["expected"], {"retained_segment_ref", "evicted_segment_ref", "retained_bytes", "replay_refs", "older_output_may_be_missing", "exact_capacity_valid"}, f"{path}.expected")
    capacity = expect_int(input_value["capacity_bytes"], f"{path}.input.capacity_bytes", constants["replay_capacity_bytes"])
    segments = expect_list(input_value["segments"], f"{path}.input.segments")
    if len(segments) != 2:
        fail(f"{path}.input.segments", "must contain the evicted prefix and newest tail")
    sizes: list[int] = []
    refs: list[str] = []
    roles = ["evicted-prefix", "retained-tail"]
    for index, segment in enumerate(segments):
        item = exact_keys(segment, {"segment_ref", "role", "byte_hex", "repeat"}, f"{path}.input.segments[{index}]")
        refs.append(expect_ref(item["segment_ref"], f"{path}.input.segments[{index}].segment_ref"))
        expect_string(item["role"], f"{path}.input.segments[{index}].role", roles[index])
        sizes.append(segment_size(item, f"{path}.input.segments[{index}]"))
    if len(set(refs)) != 2:
        fail(f"{path}.input.segments", "segment references must be distinct")
    if sizes[0] >= capacity or sizes[1] != capacity or sum(sizes) <= capacity:
        fail(f"{path}.input.segments", "must prove an older prefix followed by an exactly-capacity newest tail")
    expect_ref(expected["retained_segment_ref"], f"{path}.expected.retained_segment_ref")
    expect_ref(expected["evicted_segment_ref"], f"{path}.expected.evicted_segment_ref")
    if expected["retained_segment_ref"] != refs[1] or expected["evicted_segment_ref"] != refs[0]:
        fail(f"{path}.expected", "segment provenance does not match ordered input segments")
    expect_int(expected["retained_bytes"], f"{path}.expected.retained_bytes", capacity)
    replay_refs = expect_exact_list(expected["replay_refs"], f"{path}.expected.replay_refs", [refs[1]])
    if replay_refs != [refs[1]]:
        fail(f"{path}.expected.replay_refs", "replay must contain only the newest segment")
    expect_bool(expected["older_output_may_be_missing"], f"{path}.expected.older_output_may_be_missing", True)
    expect_bool(expected["exact_capacity_valid"], f"{path}.expected.exact_capacity_valid", True)


def validate_replay_live_race(case: dict[str, Any]) -> None:
    path = "cases.replay-live-race"
    input_value = exact_keys(case["input"], {"retained_frame_ref", "live_frame_ref", "retained_hex", "live_hex", "separator_hex", "orders"}, f"{path}.input")
    expected = exact_keys(case["expected"], {"allowed_orders", "client_order", "replay_separator", "frame_boundaries_preserved"}, f"{path}.expected")
    retained_ref = expect_ref(input_value["retained_frame_ref"], f"{path}.input.retained_frame_ref")
    live_ref = expect_ref(input_value["live_frame_ref"], f"{path}.input.live_frame_ref")
    if retained_ref == live_ref:
        fail(f"{path}.input", "retained and live references must be distinct")
    retained_hex = expect_hex(input_value["retained_hex"], f"{path}.input.retained_hex")
    live_hex = expect_hex(input_value["live_hex"], f"{path}.input.live_hex")
    expect_hex(input_value["separator_hex"], f"{path}.input.separator_hex")
    if input_value["separator_hex"] != "":
        fail(f"{path}.input.separator_hex", "must be empty")
    orders = expect_list(input_value["orders"], f"{path}.input.orders")
    if len(orders) != 2:
        fail(f"{path}.input.orders", "must contain both race orders")
    observed_orders: list[str] = []
    for index, order in enumerate(orders):
        item = exact_keys(order, {"order_id", "order", "frame_refs", "rendered_hex"}, f"{path}.input.orders[{index}]")
        expect_ref(item["order_id"], f"{path}.input.orders[{index}].order_id")
        order_name = expect_string(item["order"], f"{path}.input.orders[{index}].order")
        observed_orders.append(order_name)
        refs = expect_exact_list(item["frame_refs"], f"{path}.input.orders[{index}].frame_refs", [retained_ref, live_ref] if order_name == "retained-first" else [live_ref, retained_ref])
        if order_name not in {"retained-first", "live-first"}:
            fail(f"{path}.input.orders[{index}].order", "unknown race order")
        expected_hex = retained_hex + live_hex if order_name == "retained-first" else live_hex + retained_hex
        expect_hex(item["rendered_hex"], f"{path}.input.orders[{index}].rendered_hex")
        if item["rendered_hex"] != expected_hex:
            fail(f"{path}.input.orders[{index}].rendered_hex", "must preserve receive order without a separator")
        if len(refs) != 2:
            fail(f"{path}.input.orders[{index}].frame_refs", "must contain two frame references")
    if sorted(observed_orders) != ["live-first", "retained-first"]:
        fail(f"{path}.input.orders", "must contain each race order exactly once")
    expect_exact_list(expected["allowed_orders"], f"{path}.expected.allowed_orders", ["retained-first", "live-first"])
    expect_string(expected["client_order"], f"{path}.expected.client_order", "receive-order")
    expect_string(expected["replay_separator"], f"{path}.expected.replay_separator", "none")
    expect_bool(expected["frame_boundaries_preserved"], f"{path}.expected.frame_boundaries_preserved", True)


def validate_supersession(case: dict[str, Any], constants: dict[str, Any]) -> None:
    path = "cases.superseded-attachment"
    input_value = exact_keys(case["input"], {"handle_ref", "session_ref", "process_ref", "old_socket_ref", "replacement_socket_ref", "events"}, f"{path}.input")
    expected = exact_keys(case["expected"], {"old_close_code", "close_before_assignment", "active_socket_ref", "stale_cleanup", "identity_preserved", "active_attachment_count"}, f"{path}.expected")
    refs = {key: expect_ref(input_value[key], f"{path}.input.{key}") for key in ("handle_ref", "session_ref", "process_ref", "old_socket_ref", "replacement_socket_ref")}
    if refs["old_socket_ref"] == refs["replacement_socket_ref"]:
        fail(f"{path}.input", "old and replacement socket references must differ")
    events = expect_list(input_value["events"], f"{path}.input.events")
    if len(events) != 4:
        fail(f"{path}.input.events", "must contain close, assign, stale cleanup, and active send")
    first = exact_keys(events[0], {"name", "socket_ref", "close_code"}, f"{path}.input.events[0]")
    expect_string(first["name"], f"{path}.input.events[0].name", "old_socket_close")
    expect_ref(first["socket_ref"], f"{path}.input.events[0].socket_ref")
    expect_int(first["close_code"], f"{path}.input.events[0].close_code", constants["replacement_close_code"])
    if first["socket_ref"] != refs["old_socket_ref"]:
        fail(f"{path}.input.events[0].socket_ref", "must close the old socket")
    second = exact_keys(events[1], {"name", "socket_ref"}, f"{path}.input.events[1]")
    expect_string(second["name"], f"{path}.input.events[1].name", "replacement_assign")
    expect_ref(second["socket_ref"], f"{path}.input.events[1].socket_ref")
    if second["socket_ref"] != refs["replacement_socket_ref"]:
        fail(f"{path}.input.events[1].socket_ref", "must assign the replacement socket")
    third = exact_keys(events[2], {"name", "socket_ref", "result"}, f"{path}.input.events[2]")
    expect_string(third["name"], f"{path}.input.events[2].name", "stale_cleanup")
    expect_ref(third["socket_ref"], f"{path}.input.events[2].socket_ref")
    expect_string(third["result"], f"{path}.input.events[2].result", "ignored")
    fourth = exact_keys(events[3], {"name", "socket_ref"}, f"{path}.input.events[3]")
    expect_string(fourth["name"], f"{path}.input.events[3].name", "active_send")
    expect_ref(fourth["socket_ref"], f"{path}.input.events[3].socket_ref")
    if fourth["socket_ref"] != refs["replacement_socket_ref"]:
        fail(f"{path}.input.events[3].socket_ref", "stale cleanup detached the replacement")
    expect_int(expected["old_close_code"], f"{path}.expected.old_close_code", constants["replacement_close_code"])
    expect_bool(expected["close_before_assignment"], f"{path}.expected.close_before_assignment", True)
    expect_ref(expected["active_socket_ref"], f"{path}.expected.active_socket_ref")
    if expected["active_socket_ref"] != refs["replacement_socket_ref"]:
        fail(f"{path}.expected.active_socket_ref", "must identify the replacement socket")
    expect_string(expected["stale_cleanup"], f"{path}.expected.stale_cleanup", "ignored")
    expect_bool(expected["identity_preserved"], f"{path}.expected.identity_preserved", True)
    expect_int(expected["active_attachment_count"], f"{path}.expected.active_attachment_count", 1)


def validate_explicit_close(case: dict[str, Any]) -> None:
    path = "cases.explicit-close"
    input_value = exact_keys(case["input"], {"mode", "handle_ref", "session_ref", "process_ref", "socket_ref", "events"}, f"{path}.input")
    expected = exact_keys(case["expected"], {"state_sequence", "process_state", "process_terminated", "reattach"}, f"{path}.expected")
    expect_string(input_value["mode"], f"{path}.input.mode", "attach")
    refs = {key: expect_ref(input_value[key], f"{path}.input.{key}") for key in ("handle_ref", "session_ref", "process_ref", "socket_ref")}
    events = expect_list(input_value["events"], f"{path}.input.events")
    if len(events) != 5:
        fail(f"{path}.input.events", "must contain accept, attach, close, detach, and retain")
    schemas = [
        ({"name", "socket_ref"}, "socket.accept"),
        ({"name", "handle_ref", "session_ref", "process_ref", "socket_ref"}, "session.attach"),
        ({"name", "socket_ref", "close_code"}, "client.close"),
        ({"name", "handle_ref", "session_ref", "process_ref", "socket_ref"}, "registry.detach"),
        ({"name", "handle_ref", "session_ref", "process_ref"}, "registry.retain"),
    ]
    for index, (keys, name) in enumerate(schemas):
        item = exact_keys(events[index], keys, f"{path}.input.events[{index}]")
        expect_string(item["name"], f"{path}.input.events[{index}].name", name)
        for key in ("handle_ref", "session_ref", "process_ref", "socket_ref"):
            if key in item:
                expect_ref(item[key], f"{path}.input.events[{index}].{key}")
                if item[key] != refs[key]:
                    fail(f"{path}.input.events[{index}].{key}", "identity changed across explicit Close")
        if name == "client.close":
            expect_int(item["close_code"], f"{path}.input.events[{index}].close_code", 1000)
    expect_exact_list(expected["state_sequence"], f"{path}.expected.state_sequence", ["attached", "detached"])
    expect_string(expected["process_state"], f"{path}.expected.process_state", "retained")
    expect_bool(expected["process_terminated"], f"{path}.expected.process_terminated", False)
    expect_string(expected["reattach"], f"{path}.expected.reattach", "allowed")


def validate_unsupported_host(case: dict[str, Any]) -> None:
    path = "cases.unsupported-host"
    input_value = exact_keys(case["input"], {"host_kind", "events"}, f"{path}.input")
    expected = exact_keys(case["expected"], {"result", "reason", "socket_accepted", "process_spawned"}, f"{path}.expected")
    expect_string(input_value["host_kind"], f"{path}.input.host_kind", "unsupported-host")
    events = expect_list(input_value["events"], f"{path}.input.events")
    if len(events) != 2:
        fail(f"{path}.input.events", "must reject before any accept or spawn")
    first = exact_keys(events[0], {"name"}, f"{path}.input.events[0]")
    second = exact_keys(events[1], {"name", "reason"}, f"{path}.input.events[1]")
    expect_string(first["name"], f"{path}.input.events[0].name", "client.validate_host")
    expect_string(second["name"], f"{path}.input.events[1].name", "client.reject_without_upgrade")
    expect_string(second["reason"], f"{path}.input.events[1].reason", "unsupported-host")
    expect_string(expected["result"], f"{path}.expected.result", "rejected")
    expect_string(expected["reason"], f"{path}.expected.reason", "unsupported-host")
    expect_bool(expected["socket_accepted"], f"{path}.expected.socket_accepted", False)
    expect_bool(expected["process_spawned"], f"{path}.expected.process_spawned", False)


def validate_resize_bounds(case: dict[str, Any], constants: dict[str, Any]) -> None:
    path = "cases.resize-bounds"
    input_value = exact_keys(case["input"], {"samples", "framing"}, f"{path}.input")
    expected = exact_keys(case["expected"], {"control_is_single_binary_message", "written_to_pty"}, f"{path}.expected")
    framing = exact_keys(input_value["framing"], {"prefix_hex", "suffix_hex"}, f"{path}.input.framing")
    prefix = expect_hex(framing["prefix_hex"], f"{path}.input.framing.prefix_hex")
    suffix = expect_hex(framing["suffix_hex"], f"{path}.input.framing.suffix_hex")
    if prefix != "1b5b524553495a453a" or suffix != "5d":
        fail(f"{path}.input.framing", "does not use the exact resize framing")
    samples = expect_list(input_value["samples"], f"{path}.input.samples")
    if len(samples) != len(RESIZE_BOUNDARY_SAMPLES):
        fail(f"{path}.input.samples", "must contain the complete resize boundary set")
    observed_boundaries: list[tuple[int, int, int, int]] = []
    for index, sample in enumerate(samples):
        item = exact_keys(sample, {"cols", "rows", "effective_cols", "effective_rows", "control_hex"}, f"{path}.input.samples[{index}]")
        cols = expect_int(item["cols"], f"{path}.input.samples[{index}].cols")
        rows = expect_int(item["rows"], f"{path}.input.samples[{index}].rows")
        effective_cols = expect_int(item["effective_cols"], f"{path}.input.samples[{index}].effective_cols")
        effective_rows = expect_int(item["effective_rows"], f"{path}.input.samples[{index}].effective_rows")
        boundary = (cols, rows, effective_cols, effective_rows)
        observed_boundaries.append(boundary)
        if boundary != RESIZE_BOUNDARY_SAMPLES[index]:
            fail(f"{path}.input.samples[{index}]", "required lower, upper, and out-of-range boundary drifted")
        if effective_cols != clamp(cols, constants["min_cols"], constants["max_cols"]):
            fail(f"{path}.input.samples[{index}].effective_cols", "does not apply integer column clamping")
        if effective_rows != clamp(rows, constants["min_rows"], constants["max_rows"]):
            fail(f"{path}.input.samples[{index}].effective_rows", "does not apply integer row clamping")
        expected_hex = prefix + f"{effective_cols};{effective_rows}".encode().hex() + suffix
        if expect_hex(item["control_hex"], f"{path}.input.samples[{index}].control_hex") != expected_hex:
            fail(f"{path}.input.samples[{index}].control_hex", "does not match exact clamped resize framing")
    if tuple(observed_boundaries) != RESIZE_BOUNDARY_SAMPLES or len(set(observed_boundaries)) != len(RESIZE_BOUNDARY_SAMPLES):
        fail(f"{path}.input.samples", "resize boundary samples must be complete and unique")
    expect_bool(expected["control_is_single_binary_message"], f"{path}.expected.control_is_single_binary_message", True)
    expect_bool(expected["written_to_pty"], f"{path}.expected.written_to_pty", False)


def validate_resize_rejection(case: dict[str, Any]) -> None:
    path = "cases.resize-rejection"
    input_value = exact_keys(case["input"], {"candidates"}, f"{path}.input")
    expected = exact_keys(case["expected"], {"all_rejected_before_binary_send", "accepted_count"}, f"{path}.expected")
    candidates = expect_list(input_value["candidates"], f"{path}.input.candidates")
    if len(candidates) != len(RESIZE_REJECTION_CLASSES):
        fail(f"{path}.input.candidates", "must cover every malformed dimension and framing class")
    observed_classes: list[tuple[str, str]] = []
    for index, candidate in enumerate(candidates):
        item = exact_keys(candidate, {"cols", "rows", "invalid_field", "wire_shape", "frame", "expected"}, f"{path}.input.candidates[{index}]")
        invalid_field = expect_string(item["invalid_field"], f"{path}.input.candidates[{index}].invalid_field")
        shape = expect_string(item["wire_shape"], f"{path}.input.candidates[{index}].wire_shape")
        observed_classes.append((invalid_field, shape))
        if (invalid_field, shape) != RESIZE_REJECTION_CLASSES[index]:
            fail(f"{path}.input.candidates[{index}]", "required malformed/type rejection class drifted or duplicated")
        for key in ("cols", "rows"):
            value = item[key]
            if value is not None and type(value) not in (str, bool, int, float):
                fail(f"{path}.input.candidates[{index}].{key}", "must use a scalar JSON dimension")
            if type(value) is float and not math.isfinite(value):
                fail(f"{path}.input.candidates[{index}].{key}", "non-finite dimension is not allowed")
        expect_string(item["frame"], f"{path}.input.candidates[{index}].frame")
        expect_string(item["expected"], f"{path}.input.candidates[{index}].expected", "rejected")
    if tuple(observed_classes) != RESIZE_REJECTION_CLASSES or len(set(observed_classes)) != len(RESIZE_REJECTION_CLASSES):
        fail(f"{path}.input.candidates", "malformed/type rejection classes must be complete and unique")
    expect_bool(expected["all_rejected_before_binary_send"], f"{path}.expected.all_rejected_before_binary_send", True)
    expect_int(expected["accepted_count"], f"{path}.expected.accepted_count", 0)


def validate_reconnect_truncation(case: dict[str, Any], constants: dict[str, Any]) -> None:
    path = "cases.reconnect-truncation"
    input_value = exact_keys(case["input"], {"handle_ref", "session_ref", "process_ref", "first_socket_ref", "second_socket_ref", "events", "output_sizes"}, f"{path}.input")
    expected = exact_keys(case["expected"], {"state_sequence", "identity_reused", "older_output_may_be_missing", "snapshot_segment_ref"}, f"{path}.expected")
    refs = {key: expect_ref(input_value[key], f"{path}.input.{key}") for key in ("handle_ref", "session_ref", "process_ref", "first_socket_ref", "second_socket_ref")}
    if refs["first_socket_ref"] == refs["second_socket_ref"]:
        fail(f"{path}.input", "reconnect sockets must be distinct")
    events = expect_list(input_value["events"], f"{path}.input.events")
    if len(events) != 9:
        fail(f"{path}.input.events", "must contain the full reconnect and truncation timeline")
    expected_names = ["socket.accept", "session.attach", "socket.disconnect", "registry.retain", "output.append", "ring.truncate_oldest", "socket.accept", "session.reattach", "attach.snapshot_send"]
    actual_names: list[str] = []
    for index, event in enumerate(events):
        if type(event) is not dict or "name" not in event:
            fail(f"{path}.input.events[{index}]", "must be an event object with a name")
        actual_names.append(expect_string(event["name"], f"{path}.input.events[{index}].name"))
    if actual_names != expected_names:
        fail(f"{path}.input.events", "event order does not prove reconnect and truncation")
    first = exact_keys(events[0], {"name", "socket_ref"}, f"{path}.input.events[0]")
    expect_ref(first["socket_ref"], f"{path}.input.events[0].socket_ref")
    if first["socket_ref"] != refs["first_socket_ref"]:
        fail(f"{path}.input.events[0].socket_ref", "wrong first socket")
    attach = exact_keys(events[1], {"name", "handle_ref", "session_ref", "process_ref", "socket_ref"}, f"{path}.input.events[1]")
    disconnect = exact_keys(events[2], {"name", "socket_ref"}, f"{path}.input.events[2]")
    retain = exact_keys(events[3], {"name", "handle_ref", "session_ref", "process_ref"}, f"{path}.input.events[3]")
    for item, item_path in ((attach, f"{path}.input.events[1]"), (retain, f"{path}.input.events[3]")):
        for key in ("handle_ref", "session_ref", "process_ref"):
            expect_ref(item[key], f"{item_path}.{key}")
            if item[key] != refs[key]:
                fail(f"{item_path}.{key}", "identity changed before reconnect")
    expect_ref(attach["socket_ref"], f"{path}.input.events[1].socket_ref")
    if attach["socket_ref"] != refs["first_socket_ref"]:
        fail(f"{path}.input.events[1].socket_ref", "wrong attached socket")
    expect_ref(disconnect["socket_ref"], f"{path}.input.events[2].socket_ref")
    if disconnect["socket_ref"] != refs["first_socket_ref"]:
        fail(f"{path}.input.events[2].socket_ref", "wrong disconnected socket")
    append = exact_keys(events[4], {"name", "segment_ref", "bytes"}, f"{path}.input.events[4]")
    expect_ref(append["segment_ref"], f"{path}.input.events[4].segment_ref")
    expect_int(append["bytes"], f"{path}.input.events[4].bytes", 4)
    truncate = exact_keys(events[5], {"name", "dropped_segment_ref", "retained_segment_ref", "retained_bytes"}, f"{path}.input.events[5]")
    expect_ref(truncate["dropped_segment_ref"], f"{path}.input.events[5].dropped_segment_ref")
    expect_ref(truncate["retained_segment_ref"], f"{path}.input.events[5].retained_segment_ref")
    expect_int(truncate["retained_bytes"], f"{path}.input.events[5].retained_bytes", constants["replay_capacity_bytes"])
    second = exact_keys(events[6], {"name", "socket_ref"}, f"{path}.input.events[6]")
    expect_ref(second["socket_ref"], f"{path}.input.events[6].socket_ref")
    if second["socket_ref"] != refs["second_socket_ref"]:
        fail(f"{path}.input.events[6].socket_ref", "wrong reconnect socket")
    reattach = exact_keys(events[7], {"name", "handle_ref", "session_ref", "process_ref", "socket_ref"}, f"{path}.input.events[7]")
    snapshot = exact_keys(events[8], {"name", "handle_ref", "session_ref", "process_ref", "socket_ref", "segment_ref"}, f"{path}.input.events[8]")
    for item, item_path in ((reattach, f"{path}.input.events[7]"), (snapshot, f"{path}.input.events[8]")):
        for key in ("handle_ref", "session_ref", "process_ref"):
            expect_ref(item[key], f"{item_path}.{key}")
            if item[key] != refs[key]:
                fail(f"{item_path}.{key}", "identity changed during reconnect")
        expect_ref(item["socket_ref"], f"{item_path}.socket_ref")
        if item["socket_ref"] != refs["second_socket_ref"]:
            fail(f"{item_path}.socket_ref", "replacement socket was not active")
    expect_ref(snapshot["segment_ref"], f"{path}.input.events[8].segment_ref")
    if snapshot["segment_ref"] != truncate["retained_segment_ref"]:
        fail(f"{path}.input.events[8].segment_ref", "snapshot must use retained tail")
    sizes = exact_keys(input_value["output_sizes"], {"written_bytes", "retained_bytes", "older_bytes_dropped"}, f"{path}.input.output_sizes")
    expect_int(sizes["written_bytes"], f"{path}.input.output_sizes.written_bytes", constants["replay_capacity_bytes"] + 4)
    expect_int(sizes["retained_bytes"], f"{path}.input.output_sizes.retained_bytes", constants["replay_capacity_bytes"])
    expect_int(sizes["older_bytes_dropped"], f"{path}.input.output_sizes.older_bytes_dropped", 4)
    expect_exact_list(expected["state_sequence"], f"{path}.expected.state_sequence", ["attached", "detached", "reattached"])
    expect_bool(expected["identity_reused"], f"{path}.expected.identity_reused", True)
    expect_bool(expected["older_output_may_be_missing"], f"{path}.expected.older_output_may_be_missing", True)
    expect_ref(expected["snapshot_segment_ref"], f"{path}.expected.snapshot_segment_ref")
    if expected["snapshot_segment_ref"] != truncate["retained_segment_ref"]:
        fail(f"{path}.expected.snapshot_segment_ref", "wrong replay provenance")


def validate_no_input_replay(case: dict[str, Any]) -> None:
    path = "cases.no-input-replay"
    input_value = exact_keys(case["input"], {"actions", "output_inventory", "retained_output_refs", "replay_refs", "replayed_action_refs"}, f"{path}.input")
    expected = exact_keys(case["expected"], {"non_replayable_kinds", "replayed_action_refs", "prompt_tool_output_allowed", "input_replay"}, f"{path}.expected")
    actions = expect_list(input_value["actions"], f"{path}.input.actions")
    if len(actions) != len(ACTION_KINDS):
        fail(f"{path}.input.actions", "must cover input, resize, prompt, and tool actions")
    kinds: list[str] = []
    action_refs: list[str] = []
    for index, action in enumerate(actions):
        item = exact_keys(action, {"kind", "action_ref", "payload_hex"}, f"{path}.input.actions[{index}]")
        kind = expect_string(item["kind"], f"{path}.input.actions[{index}].kind")
        kinds.append(kind)
        action_ref = expect_ref(item["action_ref"], f"{path}.input.actions[{index}].action_ref")
        action_refs.append(action_ref)
        expected_kind, expected_ref = CANONICAL_ACTION_INVENTORY[index]
        if (kind, action_ref) != (expected_kind, expected_ref):
            fail(f"{path}.input.actions[{index}]", "action inventory is not canonical")
        expect_hex(item["payload_hex"], f"{path}.input.actions[{index}].payload_hex")
    if tuple(kinds) != ACTION_KINDS:
        fail(f"{path}.input.actions", "action coverage must be input, resize, prompt, tool")
    if len(set(action_refs)) != len(ACTION_KINDS):
        fail(f"{path}.input.actions", "action references must be unique")

    inventory = expect_list(input_value["output_inventory"], f"{path}.input.output_inventory")
    if len(inventory) != len(CANONICAL_OUTPUT_INVENTORY):
        fail(f"{path}.input.output_inventory", "must contain the complete canonical output inventory")
    canonical_refs: list[str] = []
    for index, output in enumerate(inventory):
        item = exact_keys(output, {"output_ref", "output_kind", "byte_hex"}, f"{path}.input.output_inventory[{index}]")
        output_ref = expect_ref(item["output_ref"], f"{path}.input.output_inventory[{index}].output_ref")
        output_kind = expect_string(item["output_kind"], f"{path}.input.output_inventory[{index}].output_kind")
        byte_hex = expect_hex(item["byte_hex"], f"{path}.input.output_inventory[{index}].byte_hex")
        expected_ref, expected_kind, expected_hex = CANONICAL_OUTPUT_INVENTORY[index]
        if (output_ref, output_kind, byte_hex) != (expected_ref, expected_kind, expected_hex):
            fail(f"{path}.input.output_inventory[{index}]", "canonical output inventory changed")
        canonical_refs.append(output_ref)

    retained_refs = check_refs_unique(input_value["retained_output_refs"], f"{path}.input.retained_output_refs")
    replay_refs = expect_exact_list(input_value["replay_refs"], f"{path}.input.replay_refs", retained_refs)
    if retained_refs != canonical_refs or replay_refs != canonical_refs:
        fail(f"{path}.input", "retained and replay refs must match canonical PTY output inventory")
    if set(retained_refs) & set(action_refs):
        fail(f"{path}.input", "input, resize, prompt, and tool action refs cannot be replayed as output")
    if any(ref not in canonical_refs for ref in retained_refs + replay_refs):
        fail(f"{path}.input", "replay refs must be canonical output refs")
    replayed = expect_list(input_value["replayed_action_refs"], f"{path}.input.replayed_action_refs")
    if replayed != []:
        fail(f"{path}.input.replayed_action_refs", "must be empty")
    expect_exact_list(expected["non_replayable_kinds"], f"{path}.expected.non_replayable_kinds", list(ACTION_KINDS))
    expect_exact_list(expected["replayed_action_refs"], f"{path}.expected.replayed_action_refs", [])
    expect_bool(expected["prompt_tool_output_allowed"], f"{path}.expected.prompt_tool_output_allowed", True)
    expect_string(expected["input_replay"], f"{path}.expected.input_replay", "prohibited")


def validate_no_byte_logging(case: dict[str, Any]) -> None:
    path = "cases.no-byte-logging"
    input_value = exact_keys(case["input"], {"frames", "logs", "retained_records"}, f"{path}.input")
    expected = exact_keys(case["expected"], {"raw_byte_fields_null", "action_payload_fields_null", "metadata_only", "pty_bytes_logged"}, f"{path}.expected")
    frames = expect_list(input_value["frames"], f"{path}.input.frames")
    if len(frames) != 2:
        fail(f"{path}.input.frames", "must contain two synthetic PTY frames")
    frame_refs: list[str] = []
    for index, frame in enumerate(frames):
        item = exact_keys(frame, {"frame_ref", "frame_hex"}, f"{path}.input.frames[{index}]")
        frame_ref = expect_ref(item["frame_ref"], f"{path}.input.frames[{index}].frame_ref")
        frame_hex = expect_hex(item["frame_hex"], f"{path}.input.frames[{index}].frame_hex")
        if (frame_ref, frame_hex) != CANONICAL_LOG_FRAME_INVENTORY[index]:
            fail(f"{path}.input.frames[{index}]", "canonical output frame inventory changed")
        frame_refs.append(frame_ref)
    if tuple(frame_refs) != tuple(ref for ref, _ in CANONICAL_LOG_FRAME_INVENTORY):
        fail(f"{path}.input.frames", "frame references must be canonical and ordered")
    logs = expect_list(input_value["logs"], f"{path}.input.logs")
    if len(logs) != len(LOG_EVENT_ORDER):
        fail(f"{path}.input.logs", "must contain exactly output plus every sensitive action category")
    record_refs: list[str] = []
    observed_events: list[str] = []
    observed_action_refs: list[str] = []
    action_refs_by_kind = dict(CANONICAL_ACTION_INVENTORY)
    for index, log in enumerate(logs):
        item = exact_keys(log, {"record_ref", "event", "frame_ref", "action_ref", "byte_payload_hex", "action_payload_hex"}, f"{path}.input.logs[{index}]")
        record_refs.append(expect_ref(item["record_ref"], f"{path}.input.logs[{index}].record_ref"))
        event = expect_string(item["event"], f"{path}.input.logs[{index}].event")
        observed_events.append(event)
        if event not in LOG_EVENT_ORDER:
            fail(f"{path}.input.logs[{index}].event", "unknown diagnostic event")
        frame_ref = item["frame_ref"]
        action_ref = item["action_ref"]
        if event == "pty.output":
            if frame_ref is None:
                fail(f"{path}.input.logs[{index}].frame_ref", "output log must carry a canonical frame reference")
            expect_ref(frame_ref, f"{path}.input.logs[{index}].frame_ref")
            if frame_ref not in frame_refs:
                fail(f"{path}.input.logs[{index}].frame_ref", "output log reference is not in the frame inventory")
            expect_none(action_ref, f"{path}.input.logs[{index}].action_ref")
        else:
            expect_none(frame_ref, f"{path}.input.logs[{index}].frame_ref")
            if action_ref is None:
                fail(f"{path}.input.logs[{index}].action_ref", "sensitive action log must carry a canonical action reference")
            action_ref = expect_ref(action_ref, f"{path}.input.logs[{index}].action_ref")
            expected_kind = {"user.input": "input", "terminal.resize": "resize", "prompt.submit": "prompt", "tool.action": "tool"}[event]
            if action_ref != action_refs_by_kind[expected_kind]:
                fail(f"{path}.input.logs[{index}].action_ref", "action log reference is not canonical for its category")
            observed_action_refs.append(action_ref)
        expect_none(item["byte_payload_hex"], f"{path}.input.logs[{index}].byte_payload_hex")
        expect_none(item["action_payload_hex"], f"{path}.input.logs[{index}].action_payload_hex")
    if tuple(observed_events) != LOG_EVENT_ORDER or len(set(observed_events)) != len(LOG_EVENT_ORDER):
        fail(f"{path}.input.logs", "logging evidence must include each category exactly once")
    if set(observed_action_refs) != set(action_refs_by_kind.values()):
        fail(f"{path}.input.logs", "logging evidence must reference every sensitive action exactly once")
    if len(set(record_refs)) != len(record_refs):
        fail(f"{path}.input.logs", "record references must be unique")
    records = expect_list(input_value["retained_records"], f"{path}.input.retained_records")
    if len(records) != 1:
        fail(f"{path}.input.retained_records", "must contain one metadata-only record")
    record = exact_keys(records[0], {"record_ref", "byte_payload_hex", "action_payload_hex"}, f"{path}.input.retained_records[0]")
    expect_ref(record["record_ref"], f"{path}.input.retained_records[0].record_ref")
    expect_none(record["byte_payload_hex"], f"{path}.input.retained_records[0].byte_payload_hex")
    expect_none(record["action_payload_hex"], f"{path}.input.retained_records[0].action_payload_hex")
    expect_bool(expected["raw_byte_fields_null"], f"{path}.expected.raw_byte_fields_null", True)
    expect_bool(expected["action_payload_fields_null"], f"{path}.expected.action_payload_fields_null", True)
    expect_bool(expected["metadata_only"], f"{path}.expected.metadata_only", True)
    expect_bool(expected["pty_bytes_logged"], f"{path}.expected.pty_bytes_logged", False)


def validate_contract(data: Any) -> dict[str, Any]:
    _validate_json_tree(data)
    scan_for_forbidden_text(data)
    root = exact_keys(data, {"schema_version", "contract", "constants", "evidence", "cases"}, "root")
    expect_string(root["schema_version"], "schema_version", SCHEMA_VERSION)
    contract = exact_keys(root["contract"], {"route", "surface", "proof_mode", "scope", "source_of_truth", "detach_rule", "replay_rule", "resize_rule", "logging_rule"}, "contract")
    expect_string(contract["route"], "contract.route", "WS /api/pty")
    expect_string(contract["surface"], "contract.surface", "web-only")
    expect_string(contract["proof_mode"], "contract.proof_mode", "offline-synthetic-pty-lifecycle")
    expect_string(contract["scope"], "contract.scope", "C-18")
    expect_exact_list(contract["source_of_truth"], "contract.source_of_truth", ["contracts/state-models/terminal.md", "contracts/fixtures/source-audit/pty-attach/README.md"])
    expect_string(contract["detach_rule"], "contract.detach_rule", "reattach allowed when elapsed <= 1800; expired when elapsed > 1800")
    expect_string(contract["replay_rule"], "contract.replay_rule", "newest-1MiB-pty-output-only; retained-live-race-allowed")
    expect_string(contract["resize_rule"], "contract.resize_rule", "integer clamp then exact binary resize frame")
    expect_string(contract["logging_rule"], "contract.logging_rule", "no-pty-bytes-or-action-payloads")
    constants = exact_keys(root["constants"], {"resize_prefix_hex", "resize_suffix_hex", "min_cols", "max_cols", "min_rows", "max_rows", "replay_capacity_bytes", "detach_retention_seconds", "registry_max_entries", "replacement_close_code", "process_exit_close_code"}, "constants")
    expect_hex(constants["resize_prefix_hex"], "constants.resize_prefix_hex")
    expect_hex(constants["resize_suffix_hex"], "constants.resize_suffix_hex")
    expected_constants = {"min_cols": 1, "max_cols": 2000, "min_rows": 1, "max_rows": 1000, "replay_capacity_bytes": REPLAY_CAPACITY, "detach_retention_seconds": DETACH_RETENTION, "registry_max_entries": REGISTRY_MAX, "replacement_close_code": REPLACEMENT_CLOSE, "process_exit_close_code": 4410}
    for key, expected_value in expected_constants.items():
        expect_int(constants[key], f"constants.{key}", expected_value)
    evidence = exact_keys(root["evidence"], {"accessibility", "security", "benchmark"}, "evidence")
    accessibility = exact_keys(evidence["accessibility"], {"status", "reason", "preservation_reference"}, "evidence.accessibility")
    expect_string(accessibility["status"], "evidence.accessibility.status", "not-applicable")
    expect_string(accessibility["reason"], "evidence.accessibility.reason")
    expect_string(accessibility["preservation_reference"], "evidence.accessibility.preservation_reference")
    security = exact_keys(evidence["security"], {"status", "synthetic_only", "live_integration", "raw_pty_bytes_logged", "action_payloads_replayed"}, "evidence.security")
    expect_string(security["status"], "evidence.security.status", "pass")
    expect_bool(security["synthetic_only"], "evidence.security.synthetic_only", True)
    expect_bool(security["live_integration"], "evidence.security.live_integration", False)
    expect_bool(security["raw_pty_bytes_logged"], "evidence.security.raw_pty_bytes_logged", False)
    expect_bool(security["action_payloads_replayed"], "evidence.security.action_payloads_replayed", False)
    benchmark = exact_keys(evidence["benchmark"], {"status", "artifact", "approved_budget", "normal_samples", "optimized_samples", "threshold"}, "evidence.benchmark")
    expect_string(benchmark["status"], "evidence.benchmark.status", "baseline-only")
    expect_string(benchmark["artifact"], "evidence.benchmark.artifact", "validation-baseline.json")
    expect_none(benchmark["approved_budget"], "evidence.benchmark.approved_budget")
    expect_int(benchmark["normal_samples"], "evidence.benchmark.normal_samples", 30)
    expect_int(benchmark["optimized_samples"], "evidence.benchmark.optimized_samples", 30)
    expect_none(benchmark["threshold"], "evidence.benchmark.threshold")
    cases = expect_list(root["cases"], "cases")
    if len(cases) != len(EXPECTED_CASES):
        fail("cases", f"must contain exactly {len(EXPECTED_CASES)} cases")
    actual_ids: list[str] = []
    validators: dict[str, Callable[[dict[str, Any]], None]] = {
        "detach-ttl": lambda case: validate_detach_ttl(case, constants),
        "registry-cap": lambda case: validate_registry_cap(case, constants),
        "replay-newest-tail": lambda case: validate_replay_newest_tail(case, constants),
        "replay-live-race": validate_replay_live_race,
        "superseded-attachment": lambda case: validate_supersession(case, constants),
        "explicit-close": validate_explicit_close,
        "unsupported-host": validate_unsupported_host,
        "resize-bounds": lambda case: validate_resize_bounds(case, constants),
        "resize-rejection": validate_resize_rejection,
        "reconnect-truncation": lambda case: validate_reconnect_truncation(case, constants),
        "no-input-replay": validate_no_input_replay,
        "no-byte-logging": validate_no_byte_logging,
    }
    for index, raw_case in enumerate(cases):
        case = exact_keys(raw_case, {"id", "kind", "input", "expected"}, f"cases[{index}]")
        case_id = expect_string(case["id"], f"cases[{index}].id")
        kind = expect_string(case["kind"], f"cases[{index}].kind")
        actual_ids.append(case_id)
        if case_id not in EXPECTED_CASES or EXPECTED_CASES[case_id] != kind:
            fail(f"cases[{index}]", "case ID or kind is not part of the closed inventory")
        validators[case_id](case)
    if actual_ids != list(EXPECTED_CASES):
        fail("cases", "case order or IDs differ from the closed inventory")
    return {"case_count": len(cases), "case_ids": actual_ids}


def _case(data: dict[str, Any], case_id: str) -> dict[str, Any]:
    return next(case for case in data["cases"] if case["id"] == case_id)


def mutation_inventory(data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Return deterministic malformed candidates for the executable proof."""

    mutations: list[tuple[str, dict[str, Any]]] = []

    def add(name: str, edit: Callable[[dict[str, Any]], None]) -> None:
        candidate = copy.deepcopy(data)
        edit(candidate)
        mutations.append((name, candidate))

    add("root-extra", lambda item: item.update({"unexpected": True}))
    add("schema-version", lambda item: item.__setitem__("schema_version", "pty-detach-race-v0"))
    add("contract-extra", lambda item: item["contract"].update({"extra": True}))
    add("detach-rule-drift", lambda item: item["contract"].__setitem__("detach_rule", "elapsed >= retention_seconds"))
    add("constant-capacity", lambda item: item["constants"].__setitem__("replay_capacity_bytes", 1024))
    add("constant-boolean", lambda item: item["constants"].__setitem__("registry_max_entries", True))
    add("evidence-live", lambda item: item["evidence"]["security"].__setitem__("live_integration", True))
    add("benchmark-threshold", lambda item: item["evidence"]["benchmark"].__setitem__("threshold", 1.0))
    add("detach-probe-expired-at-equality", lambda item: _case(item, "detach-ttl")["input"]["probes"][1].__setitem__("outcome", "reattach-expired"))
    add("detach-probe-float", lambda item: _case(item, "detach-ttl")["input"]["probes"][0].__setitem__("elapsed_seconds", 1799.0))
    add("detach-probe-extra", lambda item: _case(item, "detach-ttl")["input"]["probes"][0].update({"extra": True}))
    add("registry-count", lambda item: _case(item, "registry-cap")["input"]["entry_refs"].pop())
    add("registry-duplicate", lambda item: _case(item, "registry-cap")["input"]["entry_refs"].__setitem__(1, "synthetic-entry-00"))
    add("registry-attempted-existing", lambda item: _case(item, "registry-cap")["input"].__setitem__("attempted_entry_ref", "synthetic-entry-00"))
    add("replay-capacity", lambda item: _case(item, "replay-newest-tail")["input"].__setitem__("capacity_bytes", 1048575))
    add("replay-exact-tail-invalid", lambda item: _case(item, "replay-newest-tail")["input"]["segments"][1].__setitem__("repeat", 1048577))
    add("replay-role", lambda item: _case(item, "replay-newest-tail")["input"]["segments"][1].__setitem__("role", "evicted-prefix"))
    add("replay-provenance", lambda item: _case(item, "replay-newest-tail")["expected"].__setitem__("replay_refs", ["synthetic-output-old"]))
    add("race-separator", lambda item: _case(item, "replay-live-race")["input"].__setitem__("separator_hex", "00"))
    add("race-rendered-order", lambda item: _case(item, "replay-live-race")["input"]["orders"][0].__setitem__("rendered_hex", "4c52"))
    add("race-duplicate-order", lambda item: _case(item, "replay-live-race")["input"]["orders"][1].__setitem__("order", "retained-first"))
    add("supersession-close-code", lambda item: _case(item, "superseded-attachment")["input"]["events"][0].__setitem__("close_code", 1000))
    add("supersession-order", lambda item: _case(item, "superseded-attachment")["input"]["events"].reverse())
    add("supersession-stale-active", lambda item: _case(item, "superseded-attachment")["input"]["events"][2].__setitem__("result", "active"))
    add("supersession-two-active", lambda item: _case(item, "superseded-attachment")["expected"].__setitem__("active_attachment_count", 2))
    add("explicit-close-legacy", lambda item: _case(item, "explicit-close")["input"].__setitem__("mode", "legacy"))
    add("explicit-close-terminates", lambda item: _case(item, "explicit-close")["expected"].__setitem__("process_terminated", True))
    add("explicit-close-identity", lambda item: _case(item, "explicit-close")["input"]["events"][3].__setitem__("process_ref", "synthetic-process-other"))
    add("unsupported-host-accepts", lambda item: _case(item, "unsupported-host")["expected"].__setitem__("socket_accepted", True))
    add("unsupported-host-event", lambda item: _case(item, "unsupported-host")["input"]["events"][1].__setitem__("name", "socket.accept"))
    add("resize-bool", lambda item: _case(item, "resize-bounds")["input"]["samples"][0].__setitem__("cols", True))
    add("resize-effective", lambda item: _case(item, "resize-bounds")["input"]["samples"][2].__setitem__("effective_cols", 2))
    add("resize-prefix", lambda item: _case(item, "resize-bounds")["input"]["framing"].__setitem__("prefix_hex", "00"))
    add("resize-boundary-duplicate", lambda item: _case(item, "resize-bounds")["input"]["samples"].__setitem__(7, copy.deepcopy(_case(item, "resize-bounds")["input"]["samples"][6])))
    add("resize-boundary-valid-drift", lambda item: _case(item, "resize-bounds")["input"]["samples"][3].update({"cols": 1, "rows": 2, "effective_cols": 1, "effective_rows": 2, "control_hex": "1b5b524553495a453a313b325d"}))
    add("resize-rejection-accepted", lambda item: _case(item, "resize-rejection")["expected"].__setitem__("accepted_count", 1))
    add("resize-rejection-kind", lambda item: _case(item, "resize-rejection")["input"]["candidates"][0].__setitem__("wire_shape", "integer"))
    add("resize-rejection-duplicate-class", lambda item: _case(item, "resize-rejection")["input"]["candidates"][6].update({"invalid_field": "cols", "wire_shape": "fractional-number"}))
    add("resize-rejection-missing-class", lambda item: _case(item, "resize-rejection")["input"]["candidates"].pop())
    add("reconnect-identity", lambda item: _case(item, "reconnect-truncation")["input"]["events"][7].__setitem__("process_ref", "synthetic-process-other"))
    add("reconnect-retained-size", lambda item: _case(item, "reconnect-truncation")["input"]["output_sizes"].__setitem__("retained_bytes", 4))
    add("reconnect-snapshot-old", lambda item: _case(item, "reconnect-truncation")["input"]["events"][8].__setitem__("segment_ref", "synthetic-output-old"))
    add("action-order", lambda item: _case(item, "no-input-replay")["input"]["actions"].reverse())
    add("action-replay", lambda item: _case(item, "no-input-replay")["input"].__setitem__("replayed_action_refs", ["synthetic-action-input"]))
    add("action-retained", lambda item: _case(item, "no-input-replay")["input"]["replay_refs"].append("synthetic-action-input"))
    add("action-alias-input", lambda item: _case(item, "no-input-replay")["input"]["replay_refs"].__setitem__(0, "synthetic-action-input"))
    add("action-alias-resize", lambda item: _case(item, "no-input-replay")["input"]["replay_refs"].__setitem__(0, "synthetic-action-resize"))
    add("action-alias-prompt", lambda item: _case(item, "no-input-replay")["input"]["replay_refs"].__setitem__(0, "synthetic-action-prompt"))
    add("action-alias-tool", lambda item: _case(item, "no-input-replay")["input"]["replay_refs"].__setitem__(0, "synthetic-action-tool"))
    add("output-inventory-drift", lambda item: _case(item, "no-input-replay")["input"]["output_inventory"][0].__setitem__("output_ref", "synthetic-output-alias"))
    add("logging-byte-payload", lambda item: _case(item, "no-byte-logging")["input"]["logs"][0].__setitem__("byte_payload_hex", "00ff"))
    add("logging-action-payload", lambda item: _case(item, "no-byte-logging")["input"]["logs"][1].__setitem__("action_payload_hex", "696e707574"))
    add("logging-collapsed-categories", lambda item: [log.__setitem__("event", "pty.output") for log in _case(item, "no-byte-logging")["input"]["logs"][1:]])
    add("logging-null-output-ref", lambda item: _case(item, "no-byte-logging")["input"]["logs"][0].__setitem__("frame_ref", None))
    add("logging-null-action-ref", lambda item: _case(item, "no-byte-logging")["input"]["logs"][1].__setitem__("action_ref", None))
    add("logging-output-alias", lambda item: _case(item, "no-byte-logging")["input"]["logs"][0].__setitem__("frame_ref", "synthetic-output-alias"))
    add("logging-action-alias", lambda item: _case(item, "no-byte-logging")["input"]["logs"][1].__setitem__("action_ref", "synthetic-action-alias"))
    add("logging-record-extra", lambda item: _case(item, "no-byte-logging")["input"]["retained_records"][0].update({"frame_hex": "00ff"}))
    add("logging-status", lambda item: _case(item, "no-byte-logging")["expected"].__setitem__("pty_bytes_logged", True))
    return mutations


def validate_mutations(data: dict[str, Any]) -> int:
    mutations = mutation_inventory(data)
    for mutation_id, candidate in mutations:
        try:
            validate_contract(candidate)
        except ValidationError:
            continue
        fail("mutations", f"mutation unexpectedly passed: {mutation_id}")
    return len(mutations)


def artifact_digest(path: Path) -> tuple[int, str]:
    payload = path.read_bytes()
    return len(payload), hashlib.sha256(payload).hexdigest()


def validate_fixture_identity(path: Path) -> None:
    """Bind the bytes selected by --fixture to the reviewed canonical fixture."""

    expected = {
        name: (size_bytes, sha256)
        for name, size_bytes, sha256 in CANONICAL_ARTIFACT_IDENTITY
    }["pty-detach-race-fixtures.json"]
    if artifact_digest(path) != expected:
        fail("fixture_identity", "selected fixture does not match immutable reviewed identity")


def canonical_json_digest(value: Any) -> str:
    """Hash a stable JSON representation for reviewed evidence identities."""

    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def expect_sha256(value: Any, path: str) -> str:
    digest = expect_string(value, path)
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        fail(path, "must be a lowercase SHA-256 digest")
    return digest


def manifest_digest(artifacts: dict[str, dict[str, Any]]) -> str:
    manifest = "".join(f"{name}:{artifacts[name]['size_bytes']}:{artifacts[name]['sha256']}\n" for name in ARTIFACT_NAMES)
    return hashlib.sha256(manifest.encode("utf-8")).hexdigest()


def source_identity() -> dict[str, Any]:
    """Authenticate executable bytes without making the source hash circular."""

    payload = (ROOT / "validate.py").read_bytes()
    marker = re.compile(rb'(?m)^CANONICAL_SOURCE_SHA256 = "[0-9a-f]{64}"$')
    normalized, replacements = marker.subn(
        b'CANONICAL_SOURCE_SHA256 = "' + (b"0" * 64) + b'"',
        payload,
        count=1,
    )
    if replacements != 1:
        fail("source_identity", "identity marker is missing or duplicated")
    normalized_sha = hashlib.sha256(normalized).hexdigest()
    if normalized_sha != CANONICAL_SOURCE_SHA256:
        fail("source_identity", "executing validator does not match immutable reviewed identity")
    return {"size_bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}


def canonical_artifact_metadata(source: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    """Resolve the immutable artifact identity used by baseline validation."""

    if source is None:
        source = source_identity()
    pinned = {
        name: {"size_bytes": size, "sha256": sha256}
        for name, size, sha256 in CANONICAL_ARTIFACT_IDENTITY
    }
    pinned["validate.py"] = source
    metadata: dict[str, dict[str, Any]] = {}
    for index, name in enumerate(ARTIFACT_NAMES):
        expected = pinned[name]
        metadata[name] = {
            "path": CANONICAL_BASELINE_IDENTITY["artifact_paths"][index],
            "size_bytes": expected["size_bytes"],
            "sha256": expected["sha256"],
        }
    return metadata


def rounded(value: float) -> float:
    return round(value, 6)


def validate_distribution(run: dict[str, Any], path: str) -> None:
    value = exact_keys(run, {"sample_count", "samples_ms", "distribution"}, path)
    count = expect_int(value["sample_count"], f"{path}.sample_count", 30)
    samples = expect_list(value["samples_ms"], f"{path}.samples_ms")
    if len(samples) != count or count != 30:
        fail(f"{path}.samples_ms", "must contain exactly 30 samples")
    numbers = [expect_float(sample, f"{path}.samples_ms[{index}]") for index, sample in enumerate(samples)]
    if any(sample < 0 for sample in numbers):
        fail(f"{path}.samples_ms", "durations must be non-negative")
    distribution = exact_keys(value["distribution"], {"count", "minimum_ms", "maximum_ms", "mean_ms", "median_ms", "p95_ms"}, f"{path}.distribution")
    expect_int(distribution["count"], f"{path}.distribution.count", count)
    ordered = sorted(numbers)
    derived = {
        "minimum_ms": rounded(min(ordered)),
        "maximum_ms": rounded(max(ordered)),
        "mean_ms": rounded(statistics.fmean(ordered)),
        "median_ms": rounded(statistics.median(ordered)),
        "p95_ms": rounded(ordered[int((len(ordered) - 1) * 0.95)]),
    }
    for key, expected in derived.items():
        actual = expect_float(distribution[key], f"{path}.distribution.{key}")
        if not math.isclose(actual, expected, rel_tol=0, abs_tol=0.000001):
            fail(f"{path}.distribution.{key}", "does not match the recorded sample distribution")


def validate_benchmark_identity(benchmark: dict[str, Any]) -> None:
    """Bind both benchmark modes and their derived distributions to review."""

    expected_by_mode = {
        mode: {"samples_sha256": samples_sha, "distribution_sha256": distribution_sha}
        for mode, samples_sha, distribution_sha in CANONICAL_BENCHMARK_IDENTITY
    }
    for mode in ("normal", "optimized"):
        run = benchmark[mode]
        validate_distribution(run, f"baseline.benchmark.{mode}")
        expected = expected_by_mode[mode]
        if canonical_json_digest(run["samples_ms"]) != expected["samples_sha256"]:
            fail(f"baseline.benchmark.{mode}.samples_ms", "does not match immutable reviewed identity")
        if canonical_json_digest(run["distribution"]) != expected["distribution_sha256"]:
            fail(f"baseline.benchmark.{mode}.distribution", "does not match immutable reviewed identity")


def validate_baseline(baseline: Any, source: dict[str, Any] | None = None) -> dict[str, Any]:
    if source is None:
        source = source_identity()
    root = exact_keys(baseline, {"schema_version", "fixture_schema_version", "artifacts", "benchmark", "manifest_sha256"}, "baseline")
    expect_string(root["schema_version"], "baseline.schema_version", CANONICAL_BASELINE_IDENTITY["schema_version"])
    expect_string(root["fixture_schema_version"], "baseline.fixture_schema_version", CANONICAL_BASELINE_IDENTITY["fixture_schema_version"])
    artifacts = exact_keys(root["artifacts"], set(ARTIFACT_NAMES), "baseline.artifacts")
    canonical = canonical_artifact_metadata(source)
    for name in ARTIFACT_NAMES:
        item = exact_keys(artifacts[name], {"path", "size_bytes", "sha256"}, f"baseline.artifacts.{name}")
        expected = canonical[name]
        expect_string(item["path"], f"baseline.artifacts.{name}.path", expected["path"])
        expect_int(item["size_bytes"], f"baseline.artifacts.{name}.size_bytes")
        expect_sha256(item["sha256"], f"baseline.artifacts.{name}.sha256")
        path = ROOT / name
        actual_size, actual_sha = artifact_digest(path)
        if item["size_bytes"] != actual_size or item["sha256"] != actual_sha:
            fail(f"baseline.artifacts.{name}", "size or SHA-256 does not match the checked-in artifact")
        if item["size_bytes"] != expected["size_bytes"] or item["sha256"] != expected["sha256"]:
            fail(f"baseline.artifacts.{name}", "does not match immutable canonical artifact identity")
    benchmark = exact_keys(root["benchmark"], {"normal", "optimized", "threshold"}, "baseline.benchmark")
    validate_benchmark_identity(benchmark)
    expect_none(benchmark["threshold"], "baseline.benchmark.threshold")
    expect_string(root["manifest_sha256"], "baseline.manifest_sha256")
    if not re.fullmatch(r"[0-9a-f]{64}", root["manifest_sha256"]):
        fail("baseline.manifest_sha256", "must be a lowercase SHA-256 digest")
    if root["manifest_sha256"] != manifest_digest(canonical):
        fail("baseline.manifest_sha256", "does not match immutable canonical artifact manifest")
    return {"artifact_count": len(ARTIFACT_NAMES), "sample_count": 60}


def main(argv: list[str] | None = None) -> int:
    parser = ControlledArgumentParser()
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    try:
        args = parser.parse_args(argv)
    except (CommandLineError, SystemExit):
        print("validation failed: invalid command-line arguments", file=sys.stderr)
        return 2
    try:
        source = source_identity()
        validate_fixture_identity(args.fixture)
        data = load_fixture(args.fixture)
        summary = validate_contract(data)
        mutation_count = validate_mutations(data)
        baseline_summary = validate_baseline(load_baseline(args.baseline), source)
    except ValidationError:
        print("validation failed: fixture contract rejected", file=sys.stderr)
        return 1
    except OSError:
        print("validation failed: fixture input unavailable", file=sys.stderr)
        return 1
    except (TypeError, RecursionError, ValueError):
        print("validation failed: malformed fixture", file=sys.stderr)
        return 1
    print(
        "validated "
        f"cases={summary['case_count']} "
        f"mutation_checks={mutation_count} "
        f"baseline_artifacts={baseline_summary['artifact_count']} "
        f"benchmark_samples={baseline_summary['sample_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
