#!/usr/bin/env python3
"""Validate the web-only PTY attach contract with Python's standard library.

The repository is intentionally not a Hermes runtime dependency. The default
run validates the checked-in, synthetic fixture set and recorded source
fingerprints without network access. ``--source-root`` is an optional audit
mode for a local checkout of the exact pinned Hermes revision; it verifies the
recorded full-file and line-range hashes before the fixture assertions run.

The assertions below are deliberately narrow and encode the source-correct
lifecycle split: missing attach is legacy and terminates on disconnect; a
previously accepted opaque handle keeps the PTY alive; retained output can
race live output; prompt/tool output bytes may be retained; and no user input
or action is replayed. Invalid handles are rejected
before the source registry can interpret them as a new key.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import platform
import re
import sys
import time
from pathlib import Path
from typing import Any, Iterable


REVISION = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
CONTRACT = "dashboard-v0.0.1"
ARTIFACT_FILES = (
    "source-evidence.json",
    "pty-attach-fixtures.json",
    "validate.py",
    "README.md",
)
REQUIRED_CASES = {
    "missing-attach-selects-legacy",
    "legacy-disconnect-terminates",
    "attach-detach-reattach",
    "malformed-attach-fails-closed",
    "expired-attach-fails-closed",
    "superseded-socket-fails-closed",
    "retained-output-race",
    "retained-output-truncation",
    "no-input-replay",
}
REQUIRED_AUDIT_FILES = frozenset(
    {
        "hermes_cli/pty_bridge.py",
        "hermes_cli/pty_session.py",
        "hermes_cli/web_server.py",
    }
)
REQUIRED_OBSERVATIONS = frozenset(
    {
        "legacy-disconnect-terminates",
        "attach-detach-reattach",
        "malformed-expired-fail-closed",
        "superseded-socket-fail-closed",
        "retained-output-race",
        "no-input-replay",
    }
)
SOURCE_RANGE_RE = re.compile(r"^(?P<path>[^:]+):(?P<start>[1-9][0-9]*)-(?P<end>[1-9][0-9]*)$")
PREFLIGHT_ALLOWED_EVENTS = {
    "malformed-attach-fails-closed": (
        "client.validate_handle",
        "client.reject_without_upgrade",
    ),
    "expired-attach-fails-closed": (
        "reaper.reap",
        "client.observe_expired_handle",
        "client.reject_without_upgrade",
    ),
}
PREFLIGHT_FORBIDDEN_EVENTS = frozenset(
    {
        "socket.accept",
        "socket.disconnect",
        "socket.close",
        "websocket.accept",
        "websocket.upgrade",
        "websocket.close",
        "route.dispatch",
        "route.open",
        "route.request",
        "registry.lookup",
        "registry.attach",
        "registry.detach",
        "registry.spawn",
        "registry.reuse",
        "session.attach",
        "session.detach",
        "pty.spawn",
        "bridge.close",
    }
)
SNAPSHOT_EVENT_FIELDS = frozenset(
    {
        "step",
        "event",
        "payload_ref",
        "payload",
        "handle_ref",
        "session_ref",
        "process_ref",
        "socket",
    }
)
SNAPSHOT_PAYLOAD_FIELDS = frozenset({"kind", "bytes_ref"})
NON_REPLAYABLE_SEND_EVENTS = {
    "input": "input.send",
    "resize": "resize.send",
    "prompt": "prompt.submit",
    "tool_action": "tool.action.send",
}
NON_REPLAYABLE_REPLAY_EVENTS = {
    "input": frozenset({"input.replay"}),
    "resize": frozenset({"resize.replay"}),
    "prompt": frozenset({"prompt.replay"}),
    "tool_action": frozenset({"tool.action.replay", "tool_action.replay", "tool.replay", "action.replay"}),
}
OBSERVATION_EXPECTATIONS = {
    "legacy-disconnect-terminates": {
        "source_ranges": frozenset(
            {
                "hermes_cli/web_server.py:14416-14500",
                "hermes_cli/web_server.py:15720-15797",
                "hermes_cli/pty_bridge.py:250-286",
            }
        ),
        "source_observation": {
            "summary": "Missing or empty attach selects _legacy_pump; its finally block closes the bridge, and PtyBridge.close terminates the child.",
            "assertions": {
                "attach_selection": "missing_or_empty_selects_legacy_pump",
                "disconnect_operation": "bridge_close",
                "child_lifecycle": "terminate_and_reap",
            },
        },
        "contract_result": {
            "summary": "A legacy socket disconnect enters exited and cannot reattach.",
            "assertions": {
                "mode": "legacy",
                "disconnect_state": "exited",
                "reattach": "prohibited",
            },
        },
    },
    "attach-detach-reattach": {
        "source_ranges": frozenset(
            {
                "hermes_cli/web_server.py:15720-15797",
                "hermes_cli/pty_session.py:42-105",
                "hermes_cli/pty_session.py:139-191",
            }
        ),
        "source_observation": {
            "summary": "A non-empty attach key is registry-backed; socket teardown calls detach while the session drain task and PTY remain alive until exit or reaper cleanup.",
            "assertions": {
                "attach_selection": "non_empty_registry_key",
                "disconnect_operation": "detach_socket_only",
                "pty_lifetime": "alive_until_exit_or_reaper_cleanup",
            },
        },
        "contract_result": {
            "summary": "A valid exact handle may reattach during the retention window and keeps server-owned PTY identity.",
            "assertions": {
                "handle": "same_exact_handle",
                "socket_lifecycle": "attached_detached_attached",
                "session_identity": "preserved",
                "retention": "reattach_during_retention_window",
            },
        },
    },
    "malformed-expired-fail-closed": {
        "source_ranges": frozenset(
            {
                "hermes_cli/web_server.py:15720-15797",
                "hermes_cli/pty_session.py:139-191",
            }
        ),
        "source_observation": {
            "summary": "The source accepts any non-empty string as a registry key and does not expose a handle grammar or explicit expired-handle rejection; after reaping, a stale key can be used to spawn a new PTY.",
            "assertions": {
                "query_validation": "any_non_empty_string_is_accepted",
                "expiry_rejection": "not_exposed_by_pinned_source",
                "post_reap_behavior": "stale_key_can_spawn_fresh_pty",
            },
        },
        "contract_result": {
            "summary": "Client and fixture gates reject malformed or expired handles before opening the route, with no legacy fallback and no replacement spawn.",
            "assertions": {
                "preflight": "reject_before_api_pty_open",
                "fallback": "none",
                "replacement_spawn": "none",
                "retry": "none",
            },
        },
    },
    "superseded-socket-fail-closed": {
        "source_ranges": frozenset(
            {
                "hermes_cli/pty_session.py:42-105",
                "hermes_cli/web_server.py:15720-15797",
            }
        ),
        "source_observation": {
            "summary": "A replacement attach closes the old socket with 4409; the old handler's later detach is ignored unless it is still the current socket.",
            "assertions": {
                "replacement_close": "old_socket_4409",
                "stale_cleanup": "detach_ignored_when_not_current",
            },
        },
        "contract_result": {
            "summary": "The replacement attaches first; the already-open stale socket then receives 4409, stops reading, and never retries or detaches the active replacement.",
            "assertions": {
                "ordering": "replacement_attach_before_4409_close",
                "stale_socket": "stop_reading_no_retry",
                "active_socket": "replacement_remains_attached",
                "close_code": 4409,
            },
        },
    },
    "retained-output-race": {
        "source_ranges": frozenset({"hermes_cli/pty_session.py:42-105"}),
        "source_observation": {
            "summary": "The drain task appends and sends live chunks while attach snapshots and sends retained bytes; no replay boundary or replay-before-live ordering is provided.",
            "assertions": {
                "retained_send": "attach_snapshot_sends_buffer",
                "live_send": "drain_sends_live_chunks",
                "ordering": "no_boundary_or_order_guarantee",
            },
        },
        "contract_result": {
            "summary": "Render receive order, allow retained/live race, and do not claim a complete ordered transcript.",
            "assertions": {
                "render": "receive_order",
                "complete_replay": False,
                "transcript": False,
            },
        },
    },
    "no-input-replay": {
        "source_ranges": frozenset(
            {
                "hermes_cli/web_server.py:15720-15797",
                "hermes_cli/pty_bridge.py:208-223",
                "hermes_cli/pty_session.py:42-105",
            }
        ),
        "source_observation": {
            "summary": "Writer input is forwarded directly to the bridge; attach sends only the output buffer snapshot and never replays prior input.",
            "assertions": {
                "input_path": "direct_bridge_write",
                "snapshot_payload": "output_buffer_only",
                "input_replay": "not_provided_by_attach",
            },
        },
        "contract_result": {
            "summary": "Reconnect must not resend input, resize controls, prompts, or tool actions; prompt and tool output bytes may still appear in retained PTY output.",
            "assertions": {
                "input": "not_replayed",
                "resize": "not_replayed",
                "prompt": "not_replayed",
                "tool_action": "not_replayed",
                "output": "may_be_retained",
                "retry": "new_explicit_user_action",
            },
        },
    },
}
FORBIDDEN_REDACTION_KEYS = {
    "access_token",
    "attach_token",
    "cookie_value",
    "credential",
    "live_transcript",
    "password",
    "raw_attach_handle",
    "raw_handle",
    "raw_token",
    "refresh_token",
    "secret",
    "session_token",
    "ticket_value",
    "user_data",
    "websocket_ticket",
}


def fail(message: str) -> None:
    raise AssertionError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read JSON {path}: {exc}")
    require(isinstance(value, dict), f"{path} must contain a JSON object")
    return value


def hex_string(value: Any, length: int, label: str) -> None:
    require(isinstance(value, str), f"{label} must be a string")
    require(len(value) == length, f"{label} must have {length} hex characters")
    require(all(char in "0123456789abcdef" for char in value), f"{label} is not lowercase hex")


def git_blob_sha(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def parse_source_range(value: Any, label: str) -> tuple[str, int, int]:
    require(isinstance(value, str), f"{label} must be a source range string")
    match = SOURCE_RANGE_RE.fullmatch(value)
    require(match is not None, f"{label} has invalid source range syntax")
    start = int(match.group("start"))
    end = int(match.group("end"))
    require(start <= end, f"{label} has reversed source range")
    return match.group("path"), start, end


def walk_fixture_values(value: Any, path: str = "fixture") -> Iterable[tuple[str, Any]]:
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from walk_fixture_values(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk_fixture_values(child, f"{path}[{index}]")


def validate_redaction(document: dict[str, Any], label: str) -> None:
    redaction = document.get("redaction")
    require(isinstance(redaction, dict), f"{label} redaction policy is required")
    require(
        set(redaction) == {"raw_handles", "live_data", "credentials", "transcript_mirror"},
        f"{label} redaction policy changed",
    )
    for key in ("raw_handles", "live_data", "credentials", "transcript_mirror"):
        require(redaction.get(key) is False, f"{label} redaction.{key} must be false")

    for path, value in walk_fixture_values(document):
        if isinstance(value, dict):
            for key, child in value.items():
                lowered_key = key.lower()
                require(
                    lowered_key not in FORBIDDEN_REDACTION_KEYS,
                    f"forbidden {label} key at {path}.{key}",
                )
                if isinstance(child, str) and (
                    "handle" in lowered_key
                    or lowered_key.endswith("_token")
                    or lowered_key in {"reference", "websocket_ticket"}
                ):
                    require(
                        child.startswith("synthetic-") or child == "same_exact_handle",
                        f"raw handle-like {label} value at {path}.{key}",
                    )
        if isinstance(value, str):
            # These markers catch accidental pasting of common credential forms
            # without rejecting the deliberately synthetic references and source hashes.
            lowered = value.lower()
            for marker in ("eyj", "ghp_", "sk-", "xoxb-"):
                require(not lowered.startswith(marker), f"credential-like {label} value at {path}")


def events(case: dict[str, Any]) -> list[dict[str, Any]]:
    timeline = case.get("timeline")
    require(isinstance(timeline, list), f"{case.get('id')}: timeline is required")
    require(all(isinstance(item, dict) for item in timeline), f"{case.get('id')}: timeline items must be objects")
    return timeline


def event_names(case: dict[str, Any]) -> list[str]:
    result = []
    for item in events(case):
        name = item.get("event")
        require(isinstance(name, str), f"{case.get('id')}: event name is required")
        result.append(name)
    return result


def assert_order(names: list[str], before: str, after: str, case_id: str) -> None:
    require(before in names, f"{case_id}: missing event {before}")
    require(after in names, f"{case_id}: missing event {after}")
    require(names.index(before) < names.index(after), f"{case_id}: {before} must precede {after}")


def event_items(case: dict[str, Any], event: str) -> list[dict[str, Any]]:
    return [item for item in events(case) if item.get("event") == event]


def expect_fixture_failure(fixtures: dict[str, Any], mutation: str, mutate: Any) -> None:
    mutated = copy.deepcopy(fixtures)
    mutate(mutated)
    try:
        validate_fixtures(mutated)
    except AssertionError:
        return
    fail(f"mutation check accepted unsafe fixture: {mutation}")


def expect_source_failure(evidence: dict[str, Any], mutation: str, mutate: Any) -> None:
    mutated = copy.deepcopy(evidence)
    mutate(mutated)
    try:
        validate_source_evidence(mutated, None)
    except AssertionError:
        return
    fail(f"source mutation check accepted unsafe audit evidence: {mutation}")


def valid_handle(case: dict[str, Any]) -> dict[str, str]:
    case_id = case.get("id")
    handle = case.get("attach_handle")
    require(isinstance(handle, dict), f"{case_id}: attach_handle is required")
    require(handle.get("present") is True, f"{case_id}: handle must be present")
    require(handle.get("classification") == "valid_exact_opaque_handle", f"{case_id}: handle is not exact opaque")
    reference = handle.get("reference")
    require(isinstance(reference, str) and reference.startswith("synthetic-"), f"{case_id}: handle reference must be synthetic")
    identity = case.get("identity")
    require(isinstance(identity, dict), f"{case_id}: lifecycle identity is required")
    require(set(identity) == {"handle_ref", "session_ref", "process_ref"}, f"{case_id}: lifecycle identity fields changed")
    require(identity.get("handle_ref") == reference, f"{case_id}: attach handle does not match expected handle")
    for field in ("handle_ref", "session_ref", "process_ref"):
        value = identity.get(field)
        require(isinstance(value, str) and value.startswith("synthetic-"), f"{case_id}: {field} must be synthetic")
    return identity


def require_identity(
    event: dict[str, Any],
    identity: dict[str, str],
    case_id: str,
    event_name: str,
    socket: str | None = None,
) -> None:
    require(event.get("event") == event_name, f"{case_id}: expected {event_name} identity event")
    for field in ("handle_ref", "session_ref", "process_ref"):
        require(event.get(field) == identity[field], f"{case_id}: {event_name} {field} changed")
    if socket is not None:
        require(event.get("socket") == socket, f"{case_id}: {event_name} socket identity changed")


def validate_preflight(case_id: str, names: list[str]) -> None:
    allowed = PREFLIGHT_ALLOWED_EVENTS.get(case_id)
    require(allowed is not None, f"{case_id}: preflight schema is missing")
    require(tuple(names) == allowed, f"{case_id}: preflight event schema changed")
    require(not any(name in PREFLIGHT_FORBIDDEN_EVENTS for name in names), f"{case_id}: route activity occurred before rejection")
    require(names[-1] == "client.reject_without_upgrade", f"{case_id}: rejection must be terminal")


def action_counts(names: list[str]) -> tuple[dict[str, int], dict[str, int]]:
    sent = {
        kind: names.count(event_name)
        for kind, event_name in NON_REPLAYABLE_SEND_EVENTS.items()
    }
    replayed = {
        kind: sum(names.count(event_name) for event_name in event_names)
        for kind, event_names in NON_REPLAYABLE_REPLAY_EVENTS.items()
    }
    return sent, replayed


def missing_handle(case: dict[str, Any]) -> None:
    handle = case.get("attach_handle")
    require(isinstance(handle, dict), f"{case.get('id')}: attach_handle is required")
    require(handle.get("present") is False, f"{case.get('id')}: handle must be absent")
    require(handle.get("classification") == "missing", f"{case.get('id')}: missing classification is required")


def validate_case(case: dict[str, Any]) -> None:
    case_id = case.get("id")
    kind = case.get("kind")
    require(isinstance(case_id, str), "every case needs a string id")
    require(isinstance(kind, str), f"{case_id}: every case needs a kind")
    names = event_names(case)
    _, replayed_counts = action_counts(names)
    require(all(count == 0 for count in replayed_counts.values()), f"{case_id}: non-replayable action replay is forbidden")
    expected = case.get("expected")
    require(isinstance(expected, dict), f"{case_id}: expected object is required")

    if case_id == "missing-attach-selects-legacy":
        missing_handle(case)
        require(kind == "legacy_selection", f"{case_id}: wrong kind")
        require(expected == {"mode": "legacy", "keep_alive": False, "fallback_to_attach": False}, f"{case_id}: legacy selection changed")
        require(names == ["request.prepare", "legacy.branch.selected"], f"{case_id}: non-deterministic selection timeline")
        return

    if case_id == "legacy-disconnect-terminates":
        missing_handle(case)
        require(kind == "legacy_disconnect", f"{case_id}: wrong kind")
        identity = case.get("identity")
        require(identity == {"process_ref": "synthetic-legacy-pty", "socket_ref": "legacy-a"}, f"{case_id}: legacy identity changed")
        require(set(names).isdisjoint({"registry.attach", "registry.spawn", "registry.detach", "registry.reuse", "session.attach"}), f"{case_id}: legacy path entered registry")
        accepts = event_items(case, "socket.accept")
        spawns = event_items(case, "pty.spawn")
        disconnects = event_items(case, "socket.disconnect")
        closes = event_items(case, "bridge.close")
        require(len(accepts) == len(spawns) == len(disconnects) == len(closes) == 1, f"{case_id}: legacy lifecycle must have one accept, spawn, disconnect, and close")
        require(accepts[0].get("socket") == identity["socket_ref"], f"{case_id}: accepted socket identity changed")
        require(disconnects[0].get("socket") == identity["socket_ref"], f"{case_id}: disconnect socket identity changed")
        require(spawns[0].get("socket") == identity["socket_ref"], f"{case_id}: spawned socket identity changed")
        require(spawns[0].get("process_ref") == identity["process_ref"], f"{case_id}: spawned process identity changed")
        require(closes[0].get("process_ref") == spawns[0].get("process_ref"), f"{case_id}: bridge closed a different process")
        assert_order(names, "socket.disconnect", "bridge.close", case_id)
        require(expected.get("state_after_disconnect") == "exited", f"{case_id}: disconnect must exit")
        require(expected.get("process_lifetime") == "terminated", f"{case_id}: bridge must terminate")
        require(expected.get("reattach") == "prohibited", f"{case_id}: legacy reattach must be prohibited")
        require(expected.get("spawn_count") == len(spawns) == 1, f"{case_id}: expected one spawn")
        require(expected.get("input_replay_count") == 0, f"{case_id}: input replay is forbidden")
        return

    if case_id == "attach-detach-reattach":
        identity = valid_handle(case)
        require(kind == "attach_detach_reattach", f"{case_id}: wrong kind")
        attach_positions = [index for index, name in enumerate(names) if name == "session.attach"]
        require(len(attach_positions) == 2, f"{case_id}: expected initial and reattach events")
        assert_order(names, "registry.spawn", "session.attach", case_id)
        assert_order(names, "socket.disconnect", "registry.detach", case_id)
        assert_order(names, "registry.detach", "registry.reuse", case_id)
        require(names.index("registry.reuse") < attach_positions[1], f"{case_id}: registry reuse must precede reattach")
        accepts = event_items(case, "socket.accept")
        spawn_events = event_items(case, "registry.spawn")
        reuse_events = event_items(case, "registry.reuse")
        attach_events = event_items(case, "session.attach")
        disconnects = event_items(case, "socket.disconnect")
        detaches = event_items(case, "registry.detach")
        require(len(accepts) == 2 and len(spawn_events) == len(reuse_events) == 1, f"{case_id}: expected two accepts, one spawn, and one reuse")
        require(len(disconnects) == len(detaches) == 1, f"{case_id}: expected one detach sequence")
        for event, name, socket in (
            (accepts[0], "socket.accept", "attach-a"),
            (accepts[1], "socket.accept", "attach-b"),
            (attach_events[0], "session.attach", "attach-a"),
            (attach_events[1], "session.attach", "attach-b"),
            (disconnects[0], "socket.disconnect", "attach-a"),
            (detaches[0], "registry.detach", "attach-a"),
            (spawn_events[0], "registry.spawn", None),
            (reuse_events[0], "registry.reuse", None),
        ):
            require_identity(event, identity, case_id, name, socket)
        require(spawn_events[0].get("session_ref") == reuse_events[0].get("session_ref"), f"{case_id}: registry reuse changed the PTY session identity")
        require(spawn_events[0].get("process_ref") == reuse_events[0].get("process_ref"), f"{case_id}: registry reuse changed the PTY process identity")
        require("bridge.close" not in names, f"{case_id}: detach must not close the bridge")
        require(expected.get("state_sequence") == ["attached", "detached", "attached"], f"{case_id}: state sequence changed")
        require(expected.get("process_lifetime_during_detach") == "alive", f"{case_id}: PTY must survive detach")
        require(expected.get("session_identity_preserved") is True, f"{case_id}: identity must survive reattach")
        require(expected.get("spawn_count") == len(spawn_events) == 1, f"{case_id}: reattach must reuse one spawn")
        require(expected.get("reattach") == "same_exact_handle", f"{case_id}: handle replacement is unsafe")
        require(expected.get("input_replay_count") == 0, f"{case_id}: input replay is forbidden")
        return

    if case_id in {"malformed-attach-fails-closed", "expired-attach-fails-closed"}:
        require(kind in {"malformed_handle", "expired_handle"}, f"{case_id}: wrong kind")
        handle = case.get("attach_handle")
        require(isinstance(handle, dict) and handle.get("present") is True, f"{case_id}: invalid handle must be represented")
        require(handle.get("classification") == ("malformed" if case_id.startswith("malformed") else "expired"), f"{case_id}: classification changed")
        reference = handle.get("reference")
        require(isinstance(reference, str) and reference.startswith("synthetic-"), f"{case_id}: invalid handle reference must be synthetic")
        validate_preflight(case_id, names)
        require(expected.get("state") == "failed", f"{case_id}: invalid handle must fail")
        require(expected.get("client_action") == "reject_without_open", f"{case_id}: invalid handle action changed")
        require(expected.get("spawn_count") == 0, f"{case_id}: invalid handle must not spawn")
        require(expected.get("legacy_fallback") is False, f"{case_id}: invalid handle must not fall back to legacy")
        require(expected.get("retry_same_handle") is False, f"{case_id}: invalid handle must not retry")
        if case_id.startswith("expired"):
            require(expected.get("fresh_session_implicit") is False, f"{case_id}: stale handle must not create a fresh session")
        return

    if case_id == "superseded-socket-fails-closed":
        identity = valid_handle(case)
        require(kind == "superseded_socket", f"{case_id}: wrong kind")
        attach_events = event_items(case, "session.attach")
        require(len(attach_events) == 2, f"{case_id}: expected old and replacement attaches")
        stale_attach, replacement_attach = attach_events
        require_identity(stale_attach, identity, case_id, "session.attach", "attach-a")
        require_identity(replacement_attach, identity, case_id, "session.attach", "attach-b")
        close_events = event_items(case, "socket.close")
        require(len(close_events) == 1, f"{case_id}: expected one superseded close")
        close_event = close_events[0]
        require_identity(close_event, identity, case_id, "socket.close", "attach-a")
        require(close_event.get("close_code") == 4409, f"{case_id}: close code must be 4409")
        ignored_events = event_items(case, "stale_socket.detach_ignored")
        finally_events = event_items(case, "stale_socket.finally")
        require(len(ignored_events) == len(finally_events) == 1, f"{case_id}: stale cleanup events are required")
        require_identity(finally_events[0], identity, case_id, "stale_socket.finally", "attach-a")
        require_identity(ignored_events[0], identity, case_id, "stale_socket.detach_ignored", "attach-a")
        names_indexes = {
            "stale_attach": names.index("session.attach"),
            "replacement_attach": names.index("session.attach", names.index("session.attach") + 1),
            "socket.close": names.index("socket.close"),
            "stale_socket.detach_ignored": names.index("stale_socket.detach_ignored"),
        }
        require(names_indexes["stale_attach"] < names_indexes["replacement_attach"], f"{case_id}: replacement attach must follow stale attach")
        require(names_indexes["replacement_attach"] < names_indexes["socket.close"], f"{case_id}: replacement must attach before stale close")
        require(names_indexes["socket.close"] < names_indexes["stale_socket.detach_ignored"], f"{case_id}: stale cleanup must follow superseded close")
        require(expected.get("active_socket") == "attach-b", f"{case_id}: replacement must remain active")
        require(expected.get("active_session_state") == "attached", f"{case_id}: replacement must remain attached")
        require(expected.get("stale_socket_action") == "stop_without_retry", f"{case_id}: stale socket must fail closed")
        require(expected.get("close_code") == 4409, f"{case_id}: expected superseded close code")
        require(expected.get("active_detach_count") == 0, f"{case_id}: stale finally detached the replacement")
        return

    if case_id == "retained-output-race":
        identity = valid_handle(case)
        require(kind == "retained_output_race", f"{case_id}: wrong kind")
        payloads = case.get("payloads")
        require(payloads == {"retained_hex": "52", "live_hex": "4c"}, f"{case_id}: payload markers changed")
        schedules = case.get("schedule_variants")
        require(isinstance(schedules, list) and len(schedules) == 2, f"{case_id}: two race schedules are required")
        received = [item.get("receive_order") for item in schedules]
        allowed = [["retained", "live"], ["live", "retained"]]
        require(received == allowed, f"{case_id}: race orders must remain explicit and bounded")
        attach_events = event_items(case, "session.attach")
        snapshot_events = event_items(case, "attach.snapshot_send")
        live_events = event_items(case, "drain.live_send")
        require(len(attach_events) == len(snapshot_events) == len(live_events) == 1, f"{case_id}: retained/live identity events are required")
        require_identity(attach_events[0], identity, case_id, "session.attach")
        require_identity(snapshot_events[0], identity, case_id, "attach.snapshot_send")
        require_identity(live_events[0], identity, case_id, "drain.live_send")
        require(expected.get("allowed_receive_orders") == allowed, f"{case_id}: allowed orders changed")
        require(expected.get("client_visible_boundary") is False, f"{case_id}: source has no replay boundary")
        require(expected.get("render_policy") == "receive_order", f"{case_id}: render policy changed")
        require(expected.get("complete_replay_claim") is False, f"{case_id}: complete replay claim is unsafe")
        require(expected.get("retained_bytes_are_transcript") is False, f"{case_id}: retained bytes are not a transcript")
        return

    if case_id == "retained-output-truncation":
        identity = valid_handle(case)
        require(kind == "retained_output_cap", f"{case_id}: wrong kind")
        observation = case.get("retention_observation")
        require(observation == {"buffer_cap_bytes": 1048576, "appended_bytes": 1048577, "oldest_bytes_dropped": 1}, f"{case_id}: ring-buffer workload changed")
        assert_order(names, "drain.append_output", "ring_buffer.truncate_oldest", case_id)
        assert_order(names, "ring_buffer.truncate_oldest", "session.attach", case_id)
        attach_events = event_items(case, "session.attach")
        require(len(attach_events) == 1, f"{case_id}: one attach identity event is required")
        for event in events(case):
            require_identity(event, identity, case_id, event["event"])
        require(expected.get("truncated") is True, f"{case_id}: truncation must be observable to the validator")
        require(expected.get("oldest_output_may_be_missing") is True, f"{case_id}: oldest output may be missing")
        require(expected.get("complete_replay_claim") is False, f"{case_id}: complete replay claim is unsafe")
        require(expected.get("client_blocks_on_replay") is False, f"{case_id}: replay must not block close")
        return

    if case_id == "no-input-replay":
        identity = valid_handle(case)
        require(kind == "no_input_replay", f"{case_id}: wrong kind")
        sent_counts, replayed_counts = action_counts(names)
        expected_sent = {
            "input": expected.get("input_sent_count"),
            "resize": expected.get("resize_sent_count"),
            "prompt": expected.get("prompt_sent_count"),
            "tool_action": expected.get("tool_action_sent_count"),
        }
        require(sent_counts == expected_sent, f"{case_id}: action send counts changed")
        expected_replayed = {
            "input": expected.get("input_replayed_count"),
            "resize": expected.get("resize_replayed_count"),
            "prompt": expected.get("prompt_replayed_count"),
            "tool_action": expected.get("tool_action_replayed_count"),
        }
        require(replayed_counts == expected_replayed, f"{case_id}: action replay counts changed")
        require(all(count == 0 for count in replayed_counts.values()), f"{case_id}: non-replayable action replay is forbidden")
        attach_index = names.index("session.attach")
        for kind_name, event_name in NON_REPLAYABLE_SEND_EVENTS.items():
            require(event_name in names, f"{case_id}: required action event {event_name} is missing")
            require(names.index(event_name) < attach_index, f"{case_id}: prior action must precede reattach")
            action_items = event_items(case, event_name)
            require(len(action_items) == sent_counts[kind_name], f"{case_id}: action event count changed")
            for event in action_items:
                require_identity(event, identity, case_id, event_name, "attach-a")
        snapshot_events = event_items(case, "attach.snapshot_send")
        attach_events = event_items(case, "session.attach")
        disconnect_events = event_items(case, "socket.disconnect")
        require(len(attach_events) == len(disconnect_events) == len(snapshot_events) == 1, f"{case_id}: exactly one detach and reattach sequence is required")
        require_identity(disconnect_events[0], identity, case_id, "socket.disconnect", "attach-a")
        require_identity(attach_events[0], identity, case_id, "session.attach", "attach-b")
        snapshot = snapshot_events[0]
        require_identity(snapshot, identity, case_id, "attach.snapshot_send", "attach-b")
        require(set(snapshot) == SNAPSHOT_EVENT_FIELDS, f"{case_id}: snapshot has extra or missing fields")
        snapshot_payload_ref = snapshot.get("payload_ref")
        require(snapshot_payload_ref == "output-only", f"{case_id}: reattach snapshot must contain output bytes only")
        require(isinstance(snapshot_payload_ref, str), f"{case_id}: snapshot payload reference is required")
        for marker in ("input", "resize", "prompt", "tool", "action", "command"):
            require(marker not in snapshot_payload_ref.lower(), f"{case_id}: snapshot payload reference contains a replayable {marker}")
        payload = snapshot.get("payload")
        require(isinstance(payload, dict), f"{case_id}: snapshot payload metadata is required")
        require(set(payload) == SNAPSHOT_PAYLOAD_FIELDS, f"{case_id}: snapshot payload has extra or missing fields")
        require(payload.get("kind") == "output", f"{case_id}: snapshot payload kind must be output")
        bytes_ref = payload.get("bytes_ref")
        require(bytes_ref == "synthetic-output-bytes", f"{case_id}: snapshot payload must reference output bytes")
        require(isinstance(bytes_ref, str), f"{case_id}: snapshot byte reference is required")
        for marker in ("input", "resize", "prompt", "tool", "action", "command"):
            require(marker not in bytes_ref.lower(), f"{case_id}: snapshot bytes contain a replayable {marker}")
        require(expected.get("output_snapshot_may_be_sent") is True, f"{case_id}: output snapshot behavior changed")
        require(expected.get("new_user_action_required") is True, f"{case_id}: retry must be explicit")
        return

    fail(f"unrecognized fixture case {case_id}")


def validate_fixtures(fixtures: dict[str, Any]) -> int:
    require(fixtures.get("schema") == "hermternal.fixture.pty-attach.v1", "fixture schema changed")
    require(fixtures.get("contract") == CONTRACT, "fixture contract changed")
    require(fixtures.get("source_revision") == REVISION, "fixture source revision changed")
    require(fixtures.get("surface") == "web-only", "PTY fixture surface must remain web-only")
    require(fixtures.get("synthetic") is True, "fixtures must be synthetic")
    retention = fixtures.get("retention")
    require(retention == {"ttl_seconds": 1800, "buffer_cap_bytes": 1048576}, "retention contract changed")
    validate_redaction(fixtures, "fixture")

    cases = fixtures.get("cases")
    require(isinstance(cases, list), "fixtures.cases must be a list")
    ids = [case.get("id") for case in cases if isinstance(case, dict)]
    require(len(ids) == len(set(ids)), "fixture case ids must be unique")
    require(REQUIRED_CASES.issubset(set(ids)), f"missing required cases: {sorted(REQUIRED_CASES - set(ids))}")
    for case in cases:
        require(isinstance(case, dict), "fixture cases must be objects")
        validate_case(case)
    return len(cases)


def fixture_case(fixtures: dict[str, Any], case_id: str) -> dict[str, Any]:
    cases = fixtures.get("cases")
    require(isinstance(cases, list), "fixtures.cases must be a list")
    matches = [case for case in cases if isinstance(case, dict) and case.get("id") == case_id]
    require(len(matches) == 1, f"mutation target {case_id!r} must exist exactly once")
    return matches[0]


def run_mutation_checks(evidence: dict[str, Any], fixtures: dict[str, Any]) -> int:
    """Prove the validator rejects known source, identity, preflight, and replay bypasses."""
    def source_files(mutated: dict[str, Any]) -> list[dict[str, Any]]:
        files = mutated.get("files")
        require(isinstance(files, list), "source mutation target must have a files list")
        require(all(isinstance(record, dict) for record in files), "source mutation records must be objects")
        return files

    def source_observations(mutated: dict[str, Any]) -> list[dict[str, Any]]:
        observations = mutated.get("observations")
        require(isinstance(observations, list) and observations, "source mutation target must have observations")
        require(all(isinstance(item, dict) for item in observations), "source mutation observations must be objects")
        return observations

    def observation(mutated: dict[str, Any], observation_id: str = "legacy-disconnect-terminates") -> dict[str, Any]:
        matches = [item for item in source_observations(mutated) if item.get("id") == observation_id]
        require(len(matches) == 1, f"source mutation target {observation_id!r} must exist exactly once")
        return matches[0]

    def mutate_duplicate_session_file(mutated: dict[str, Any]) -> None:
        files = source_files(mutated)
        session = next(record for record in files if record.get("path") == "hermes_cli/pty_session.py")
        files.append(copy.deepcopy(session))

    def mutate_omit_bridge_file(mutated: dict[str, Any]) -> None:
        files = source_files(mutated)
        mutated["files"] = [record for record in files if record.get("path") != "hermes_cli/pty_bridge.py"]

    def mutate_unbound_observation_range(mutated: dict[str, Any]) -> None:
        observation(mutated)["source_ranges"].append("hermes_cli/pty_session.py:1-2")

    def mutate_wrong_valid_observation_range(mutated: dict[str, Any]) -> None:
        observation(mutated)["source_ranges"][0] = "hermes_cli/pty_session.py:42-105"

    def mutate_missing_source_observation(mutated: dict[str, Any]) -> None:
        observation(mutated).pop("source_observation")

    def mutate_false_source_prose(mutated: dict[str, Any]) -> None:
        observation(mutated)["source_observation"]["summary"] = "The source always keeps legacy PTYs alive after disconnect."

    def mutate_missing_contract_result(mutated: dict[str, Any]) -> None:
        observation(mutated).pop("contract_result")

    def mutate_false_contract_prose(mutated: dict[str, Any]) -> None:
        observation(mutated)["contract_result"]["summary"] = "Legacy disconnects are always reattachable."

    def mutate_false_structured_contract_assertion(mutated: dict[str, Any]) -> None:
        observation(mutated)["contract_result"]["assertions"]["reattach"] = "allowed"

    def mutate_source_redaction_flag(mutated: dict[str, Any]) -> None:
        mutated["redaction"]["raw_handles"] = True

    def mutate_source_raw_handle_key(mutated: dict[str, Any]) -> None:
        mutated["raw_handle"] = "synthetic-raw-handle"

    def mutate_reused_session_identity(mutated: dict[str, Any]) -> None:
        case = fixture_case(mutated, "attach-detach-reattach")
        reuse = event_items(case, "registry.reuse")
        require(len(reuse) == 1, "mutation target must have one registry.reuse event")
        reuse[0]["session_ref"] = "synthetic-session-b"

    def mutate_attach_handle_reference(mutated: dict[str, Any]) -> None:
        case = fixture_case(mutated, "attach-detach-reattach")
        case["attach_handle"]["reference"] = "synthetic-handle-b"

    def mutate_detach_socket_identity(mutated: dict[str, Any]) -> None:
        case = fixture_case(mutated, "attach-detach-reattach")
        detach = event_items(case, "registry.detach")
        require(len(detach) == 1, "mutation target must have one registry.detach event")
        detach[0]["socket"] = "attach-b"

    def mutate_legacy_bridge_process_identity(mutated: dict[str, Any]) -> None:
        case = fixture_case(mutated, "legacy-disconnect-terminates")
        close = event_items(case, "bridge.close")
        require(len(close) == 1, "mutation target must have one bridge.close event")
        close[0]["process_ref"] = "synthetic-other-pty"

    def mutate_attach_process_identity(mutated: dict[str, Any]) -> None:
        case = fixture_case(mutated, "attach-detach-reattach")
        reuse = event_items(case, "registry.reuse")
        require(len(reuse) == 1, "mutation target must have one registry.reuse event")
        reuse[0]["process_ref"] = "synthetic-other-pty"

    def mutate_legacy_registry_event(event_name: str) -> Any:
        def mutate(mutated: dict[str, Any]) -> None:
            case = fixture_case(mutated, "legacy-disconnect-terminates")
            case["timeline"].insert(2, {"step": 99, "event": event_name})
        return mutate

    def snapshot_event(mutated: dict[str, Any]) -> dict[str, Any]:
        case = fixture_case(mutated, "no-input-replay")
        snapshot = event_items(case, "attach.snapshot_send")
        require(len(snapshot) == 1, "mutation target must have one attach snapshot event")
        return snapshot[0]

    def mutate_input_snapshot_ref(mutated: dict[str, Any]) -> None:
        snapshot_event(mutated)["payload_ref"] = "synthetic-input-a"

    def mutate_tool_action_snapshot_ref(mutated: dict[str, Any]) -> None:
        snapshot_event(mutated)["payload_ref"] = "synthetic-tool-action-a"

    def mutate_extra_snapshot_input_field(mutated: dict[str, Any]) -> None:
        snapshot_event(mutated)["input_ref"] = "synthetic-input-a"

    def mutate_nested_snapshot_input_field(mutated: dict[str, Any]) -> None:
        snapshot_event(mutated)["payload"]["input_ref"] = "synthetic-input-a"

    def mutate_nested_snapshot_tool_action_field(mutated: dict[str, Any]) -> None:
        snapshot_event(mutated)["payload"]["tool_action_ref"] = "synthetic-tool-action-a"

    def mutate_malformed_event(event_name: str) -> Any:
        def mutate(mutated: dict[str, Any]) -> None:
            case = fixture_case(mutated, "malformed-attach-fails-closed")
            case["timeline"].insert(1, {"step": 99, "event": event_name})
        return mutate

    def mutate_replay_event(event_name: str) -> Any:
        def mutate(mutated: dict[str, Any]) -> None:
            case = fixture_case(mutated, "no-input-replay")
            disconnect_index = next(index for index, item in enumerate(case["timeline"]) if item.get("event") == "socket.disconnect")
            case["timeline"].insert(disconnect_index, {"step": 99, "event": event_name})
        return mutate

    def mutate_superseded_close_binding(mutated: dict[str, Any]) -> None:
        case = fixture_case(mutated, "superseded-socket-fails-closed")
        close = event_items(case, "socket.close")
        require(len(close) == 1, "mutation target must have one socket.close event")
        close[0]["socket"] = "attach-b"

    def mutate_superseded_close_order(mutated: dict[str, Any]) -> None:
        case = fixture_case(mutated, "superseded-socket-fails-closed")
        timeline = case["timeline"]
        close_index = next(index for index, item in enumerate(timeline) if item.get("event") == "socket.close")
        replacement_index = next(
            index for index, item in enumerate(timeline)
            if item.get("event") == "session.attach" and item.get("socket") == "attach-b"
        )
        close_event = timeline.pop(close_index)
        timeline.insert(replacement_index - (1 if close_index < replacement_index else 0), close_event)

    expect_source_failure(evidence, "duplicate pty_session audit record", mutate_duplicate_session_file)
    expect_source_failure(evidence, "omitted pty_bridge audit record", mutate_omit_bridge_file)
    expect_source_failure(evidence, "observation references an unaudited source range", mutate_unbound_observation_range)
    expect_source_failure(evidence, "observation references a different audited range", mutate_wrong_valid_observation_range)
    expect_source_failure(evidence, "observation omits source_observation semantics", mutate_missing_source_observation)
    expect_source_failure(evidence, "observation contains false source prose", mutate_false_source_prose)
    expect_source_failure(evidence, "observation omits contract_result semantics", mutate_missing_contract_result)
    expect_source_failure(evidence, "observation contains false contract prose", mutate_false_contract_prose)
    expect_source_failure(evidence, "observation contains false structured semantics", mutate_false_structured_contract_assertion)
    expect_source_failure(evidence, "source redaction flag permits raw handles", mutate_source_redaction_flag)
    expect_source_failure(evidence, "source evidence contains a raw handle key", mutate_source_raw_handle_key)
    expect_fixture_failure(fixtures, "registry reuse points at a different PTY session", mutate_reused_session_identity)
    expect_fixture_failure(fixtures, "attach handle reference differs from expected identity", mutate_attach_handle_reference)
    expect_fixture_failure(fixtures, "registry detach targets the replacement socket", mutate_detach_socket_identity)
    expect_fixture_failure(fixtures, "legacy bridge closes a different process", mutate_legacy_bridge_process_identity)
    expect_fixture_failure(fixtures, "registry reuse points at a different PTY process", mutate_attach_process_identity)
    for event_name in ("registry.attach", "registry.spawn"):
        expect_fixture_failure(fixtures, f"legacy path enters {event_name}", mutate_legacy_registry_event(event_name))
    expect_fixture_failure(fixtures, "reattach snapshot includes synthetic input in payload_ref", mutate_input_snapshot_ref)
    expect_fixture_failure(fixtures, "reattach snapshot includes a tool action in payload_ref", mutate_tool_action_snapshot_ref)
    expect_fixture_failure(fixtures, "reattach snapshot adds an extra top-level input field", mutate_extra_snapshot_input_field)
    expect_fixture_failure(fixtures, "reattach snapshot adds a nested input field", mutate_nested_snapshot_input_field)
    expect_fixture_failure(fixtures, "reattach snapshot adds a nested tool-action field", mutate_nested_snapshot_tool_action_field)
    for event_name in ("socket.accept", "websocket.accept", "registry.lookup", "route.dispatch", "session.attach"):
        expect_fixture_failure(fixtures, f"malformed preflight permits {event_name}", mutate_malformed_event(event_name))
    for event_name in ("input.replay", "resize.replay", "prompt.replay", "tool.action.replay"):
        expect_fixture_failure(fixtures, f"reattach replays {event_name}", mutate_replay_event(event_name))
    expect_fixture_failure(fixtures, "superseded close code binds to the replacement socket", mutate_superseded_close_binding)
    expect_fixture_failure(fixtures, "superseded close precedes replacement attach", mutate_superseded_close_order)
    return 34


def validate_source_evidence(evidence: dict[str, Any], source_root: Path | None) -> int:
    require(evidence.get("schema") == "hermternal.source-audit.pty-attach.v1", "source audit schema changed")
    require(evidence.get("contract") == CONTRACT, "source audit contract changed")
    source = evidence.get("source")
    require(isinstance(source, dict), "source audit metadata is required")
    require(source.get("repository") == "NousResearch/hermes-agent", "source repository changed")
    require(source.get("revision") == REVISION, "source revision changed")
    validate_redaction(evidence, "source audit")

    files = evidence.get("files")
    require(isinstance(files, list), "source audit files are required")
    require(len(files) == len(REQUIRED_AUDIT_FILES), "source audit file set must have exactly three records")
    require(all(isinstance(record, dict) for record in files), "source audit file records must be objects")
    paths = [record.get("path") for record in files]
    require(all(isinstance(path_value, str) for path_value in paths), "source audit paths must be strings")
    require(len(paths) == len(set(paths)), "source audit file paths must be unique")
    require(set(paths) == REQUIRED_AUDIT_FILES, f"source audit file set changed: {sorted(set(paths))}")

    records_by_path = {record["path"]: record for record in files}
    ranges_by_path: dict[str, set[tuple[int, int]]] = {}
    for path_value, record in records_by_path.items():
        require(path_value.startswith("hermes_cli/"), "source audit path must be a Hermes path")
        hex_string(record.get("git_blob_sha"), 40, f"{path_value}.git_blob_sha")
        hex_string(record.get("sha256"), 64, f"{path_value}.sha256")
        size = record.get("size_bytes")
        require(isinstance(size, int) and size > 0, f"{path_value}.size_bytes must be positive")
        ranges = record.get("ranges")
        require(isinstance(ranges, list) and ranges, f"{path_value}.ranges are required")
        range_keys: set[tuple[int, int]] = set()
        for line_range in ranges:
            require(isinstance(line_range, dict), f"{path_value}: line range must be an object")
            start = line_range.get("start")
            end = line_range.get("end")
            require(isinstance(start, int) and isinstance(end, int) and 1 <= start <= end, f"{path_value}: invalid line range")
            require((start, end) not in range_keys, f"{path_value}:{start}-{end}: duplicate source range")
            range_keys.add((start, end))
            hex_string(line_range.get("sha256"), 64, f"{path_value}:{start}-{end}.sha256")
            markers = line_range.get("markers")
            require(isinstance(markers, list) and markers and all(isinstance(marker, str) and marker for marker in markers), f"{path_value}:{start}-{end}.markers are required")

        ranges_by_path[path_value] = range_keys
        if source_root is None:
            continue
        local_path = source_root / path_value
        try:
            data = local_path.read_bytes()
        except OSError as exc:
            fail(f"source audit cannot read {local_path}: {exc}")
        require(len(data) == size, f"{path_value}: source size differs")
        require(hashlib.sha256(data).hexdigest() == record["sha256"], f"{path_value}: source sha256 differs")
        require(git_blob_sha(data) == record["git_blob_sha"], f"{path_value}: git blob sha differs")
        lines = data.splitlines(keepends=True)
        for line_range in ranges:
            start = line_range["start"]
            end = line_range["end"]
            require(end <= len(lines), f"{path_value}:{start}-{end}: source is too short")
            chunk = b"".join(lines[start - 1 : end])
            require(hashlib.sha256(chunk).hexdigest() == line_range["sha256"], f"{path_value}:{start}-{end}: range sha differs")
            text = chunk.decode("utf-8")
            for marker in line_range["markers"]:
                require(marker in text, f"{path_value}:{start}-{end}: missing marker {marker!r}")

    observations = evidence.get("observations")
    require(isinstance(observations, list), "source audit observations are required")
    require(len(observations) == len(REQUIRED_OBSERVATIONS), "source audit observations must be complete and unique")
    observation_ids = [item.get("id") for item in observations if isinstance(item, dict)]
    require(len(observation_ids) == len(observations), "source audit observation records must be objects")
    require(len(observation_ids) == len(set(observation_ids)), "source audit observation ids must be unique")
    require(set(observation_ids) == REQUIRED_OBSERVATIONS, "source audit observations are incomplete or unexpected")
    for observation in observations:
        observation_id = observation["id"]
        expected = OBSERVATION_EXPECTATIONS.get(observation_id)
        require(expected is not None, f"{observation_id}: observation expectations are missing")
        source_ranges = observation.get("source_ranges")
        require(isinstance(source_ranges, list) and source_ranges, f"{observation_id}: source ranges are required")
        parsed_ranges = []
        for index, raw_range in enumerate(source_ranges):
            path_value, start, end = parse_source_range(raw_range, f"{observation_id}.source_ranges[{index}]")
            require(path_value in records_by_path, f"{observation_id}: source range references an unaudited file")
            require((start, end) in ranges_by_path[path_value], f"{observation_id}: source range is not an audited range")
            parsed_ranges.append(raw_range)
        require(len(parsed_ranges) == len(set(parsed_ranges)), f"{observation_id}: source ranges must be unique")
        require(set(parsed_ranges) == expected["source_ranges"], f"{observation_id}: source range set changed")
        require(observation.get("source_observation") == expected["source_observation"], f"{observation_id}: source observation semantics changed")
        require(observation.get("contract_result") == expected["contract_result"], f"{observation_id}: contract result semantics changed")
    return len(files)


def artifact_size(root: Path) -> int:
    total = 0
    for relative in ARTIFACT_FILES:
        path = root / relative
        require(path.is_file(), f"missing artifact for size baseline: {relative}")
        total += path.stat().st_size
    return total


def write_baseline(path: Path, root: Path, duration_ns: int, case_count: int, mutation_count: int, source_verified: bool) -> None:
    baseline = {
        "schema": "hermternal.fixture-validation-baseline.v1",
        "command": (
            "python3 validate.py --source-root <pinned-checkout>"
            if source_verified else "python3 validate.py"
        ),
        "exit_status": 0,
        "source_verified": source_verified,
        "case_count": case_count,
        "mutation_check_count": mutation_count,
        "fixture_artifact_bytes": artifact_size(root),
        "validation_duration_ns": duration_ns,
        "validation_duration_ms": round(duration_ns / 1_000_000, 3),
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "threshold": None,
    }
    path.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, help="optional local checkout of the pinned Hermes source")
    parser.add_argument("--baseline-output", type=Path, help="write one measured baseline JSON artifact")
    args = parser.parse_args(argv)

    root = Path(__file__).resolve().parent
    started = time.perf_counter_ns()
    try:
        evidence = load_json(root / "source-evidence.json")
        fixtures = load_json(root / "pty-attach-fixtures.json")
        file_count = validate_source_evidence(evidence, args.source_root)
        case_count = validate_fixtures(fixtures)
        mutation_count = run_mutation_checks(evidence, fixtures)
        duration_ns = time.perf_counter_ns() - started
        bytes_count = artifact_size(root)
        if args.baseline_output is not None:
            write_baseline(
                args.baseline_output,
                root,
                duration_ns,
                case_count,
                mutation_count,
                args.source_root is not None,
            )
    except AssertionError as exc:
        print(f"validation failed: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"validation failed: {exc}", file=sys.stderr)
        return 1

    print(
        f"validated source_files={file_count} cases={case_count} "
        f"mutation_checks={mutation_count} "
        f"fixture_artifact_bytes={bytes_count} "
        f"duration_ms={duration_ns / 1_000_000:.3f} "
        f"source_checkout_verified={args.source_root is not None}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
