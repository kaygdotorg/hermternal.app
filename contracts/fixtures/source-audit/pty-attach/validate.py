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
before the source registry can interpret them as a new key. Case IDs are bound
to exact scenario kinds and required leaves use closed type/value checks so
malformed object-shaped JSON fails deterministically before set or string
operations can raise.
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
    "legacy-close-terminates",
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


def event_schema(event: str, *fields: str) -> tuple[str, frozenset[str]]:
    return event, frozenset({"step", "event", *fields})


TIMELINE_SCHEMAS = {
    "missing-attach-selects-legacy": (
        event_schema("request.prepare"),
        event_schema("legacy.branch.selected"),
    ),
    "legacy-disconnect-terminates": (
        event_schema("socket.accept", "socket"),
        event_schema("pty.spawn", "process_ref", "socket"),
        event_schema("socket.disconnect", "socket"),
        event_schema("bridge.close", "process_ref"),
    ),
    "legacy-close-terminates": (
        event_schema("socket.accept", "socket"),
        event_schema("pty.spawn", "process_ref", "socket"),
        event_schema("client.close", "socket"),
        event_schema("bridge.close", "process_ref"),
    ),
    "attach-detach-reattach": (
        event_schema("socket.accept", "handle_ref", "process_ref", "session_ref", "socket"),
        event_schema("registry.spawn", "handle_ref", "process_ref", "session_ref"),
        event_schema("session.attach", "handle_ref", "process_ref", "session_ref", "socket"),
        event_schema("socket.disconnect", "handle_ref", "process_ref", "session_ref", "socket"),
        event_schema("registry.detach", "handle_ref", "process_ref", "session_ref", "socket"),
        event_schema("socket.accept", "handle_ref", "process_ref", "session_ref", "socket"),
        event_schema("registry.reuse", "handle_ref", "process_ref", "session_ref"),
        event_schema("session.attach", "handle_ref", "process_ref", "session_ref", "socket"),
    ),
    "malformed-attach-fails-closed": (
        event_schema("client.validate_handle"),
        event_schema("client.reject_without_upgrade", "reason"),
    ),
    "expired-attach-fails-closed": (
        event_schema("reaper.reap", "elapsed_seconds"),
        event_schema("client.observe_expired_handle"),
        event_schema("client.reject_without_upgrade", "reason"),
    ),
    "superseded-socket-fails-closed": (
        event_schema("session.attach", "handle_ref", "process_ref", "session_ref", "socket"),
        event_schema("socket.close", "close_code", "handle_ref", "process_ref", "session_ref", "socket"),
        event_schema("session.attach", "handle_ref", "process_ref", "session_ref", "socket"),
        event_schema("stale_socket.finally", "handle_ref", "process_ref", "session_ref", "socket"),
        event_schema("stale_socket.detach_ignored", "handle_ref", "process_ref", "session_ref", "socket"),
    ),
    "retained-output-race": (
        event_schema("session.attach", "handle_ref", "process_ref", "session_ref"),
        event_schema("attach.snapshot_send", "handle_ref", "payload_ref", "process_ref", "session_ref"),
        event_schema("drain.live_send", "handle_ref", "payload_ref", "process_ref", "session_ref"),
    ),
    "retained-output-truncation": (
        event_schema("drain.append_output", "handle_ref", "process_ref", "session_ref"),
        event_schema("ring_buffer.truncate_oldest", "handle_ref", "process_ref", "session_ref"),
        event_schema("session.attach", "handle_ref", "process_ref", "session_ref"),
    ),
    "no-input-replay": (
        event_schema("input.send", "handle_ref", "input_ref", "process_ref", "session_ref", "socket"),
        event_schema("resize.send", "handle_ref", "process_ref", "resize_ref", "session_ref", "socket"),
        event_schema("prompt.submit", "handle_ref", "process_ref", "prompt_ref", "session_ref", "socket"),
        event_schema("tool.action.send", "handle_ref", "process_ref", "session_ref", "socket", "tool_action_ref"),
        event_schema("socket.disconnect", "handle_ref", "process_ref", "session_ref", "socket"),
        event_schema("session.attach", "handle_ref", "process_ref", "session_ref", "socket"),
        event_schema("attach.snapshot_send", "handle_ref", "payload", "payload_ref", "process_ref", "session_ref", "socket"),
    ),
}
EVENT_VOCABULARY = frozenset(event for schema in TIMELINE_SCHEMAS.values() for event, _ in schema)
TIMELINE_EXACT_VALUES = {
    "missing-attach-selects-legacy": ({}, {}),
    "legacy-disconnect-terminates": (
        {"socket": "synthetic-socket-legacy-a"},
        {"process_ref": "synthetic-legacy-pty", "socket": "synthetic-socket-legacy-a"},
        {"socket": "synthetic-socket-legacy-a"},
        {"process_ref": "synthetic-legacy-pty"},
    ),
    "legacy-close-terminates": (
        {"socket": "synthetic-socket-legacy-close"},
        {"process_ref": "synthetic-legacy-close-pty", "socket": "synthetic-socket-legacy-close"},
        {"socket": "synthetic-socket-legacy-close"},
        {"process_ref": "synthetic-legacy-close-pty"},
    ),
    "attach-detach-reattach": (
        {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty", "socket": "synthetic-socket-attach-a"},
        {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty"},
        {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty", "socket": "synthetic-socket-attach-a"},
        {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty", "socket": "synthetic-socket-attach-a"},
        {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty", "socket": "synthetic-socket-attach-a"},
        {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty", "socket": "synthetic-socket-attach-b"},
        {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty"},
        {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty", "socket": "synthetic-socket-attach-b"},
    ),
    "malformed-attach-fails-closed": ({}, {"reason": "malformed_attach_handle"}),
    "expired-attach-fails-closed": ({"elapsed_seconds": 1801}, {}, {"reason": "expired_attach_handle"}),
    "superseded-socket-fails-closed": (
        {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty", "socket": "synthetic-socket-attach-a"},
        {"close_code": 4409, "handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty", "socket": "synthetic-socket-attach-a"},
        {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty", "socket": "synthetic-socket-attach-b"},
        {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty", "socket": "synthetic-socket-attach-a"},
        {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty", "socket": "synthetic-socket-attach-a"},
    ),
    "retained-output-race": (
        {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty"},
        {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty", "payload_ref": "synthetic-retained-output"},
        {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty", "payload_ref": "synthetic-live-output"},
    ),
    "retained-output-truncation": (
        {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty"},
        {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty"},
        {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty"},
    ),
    "no-input-replay": (
        {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty", "socket": "synthetic-socket-attach-a", "input_ref": "synthetic-input-a"},
        {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty", "socket": "synthetic-socket-attach-a", "resize_ref": "synthetic-resize-a"},
        {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty", "socket": "synthetic-socket-attach-a", "prompt_ref": "synthetic-prompt-a"},
        {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty", "socket": "synthetic-socket-attach-a", "tool_action_ref": "synthetic-tool-action-a"},
        {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty", "socket": "synthetic-socket-attach-a"},
        {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty", "socket": "synthetic-socket-attach-b"},
        {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty", "socket": "synthetic-socket-attach-b", "payload_ref": "synthetic-output-only", "payload": {"kind": "output", "bytes_ref": "synthetic-output-bytes"}},
    ),
}
CASE_ROOT_FIELDS = {
    "missing-attach-selects-legacy": frozenset({"id", "kind", "attach_handle", "timeline", "expected"}),
    "legacy-disconnect-terminates": frozenset({"id", "kind", "attach_handle", "timeline", "expected", "identity"}),
    "legacy-close-terminates": frozenset({"id", "kind", "attach_handle", "timeline", "expected", "identity"}),
    "attach-detach-reattach": frozenset({"id", "kind", "attach_handle", "timeline", "expected", "identity"}),
    "malformed-attach-fails-closed": frozenset({"id", "kind", "attach_handle", "timeline", "expected"}),
    "expired-attach-fails-closed": frozenset({"id", "kind", "attach_handle", "timeline", "source_hazard", "expected"}),
    "superseded-socket-fails-closed": frozenset({"id", "kind", "attach_handle", "timeline", "expected", "identity"}),
    "retained-output-race": frozenset({"id", "kind", "attach_handle", "timeline", "expected", "identity", "payloads", "schedule_variants"}),
    "retained-output-truncation": frozenset({"id", "kind", "attach_handle", "timeline", "expected", "identity", "retention_observation"}),
    "no-input-replay": frozenset({"id", "kind", "attach_handle", "timeline", "expected", "identity"}),
}
FIXTURE_ROOT_FIELDS = frozenset({"schema", "contract", "source_revision", "surface", "synthetic", "redaction", "retention", "cases"})
RETENTION_FIELDS = frozenset({"ttl_seconds", "buffer_cap_bytes"})
PAYLOAD_FIELDS = frozenset({"retained_hex", "live_hex"})
SCHEDULE_FIELDS = frozenset({"name", "receive_order"})
RETENTION_OBSERVATION_FIELDS = frozenset({"buffer_cap_bytes", "appended_bytes", "oldest_bytes_dropped"})
PINNED_REVISION_URL = f"https://github.com/NousResearch/hermes-agent/commit/{REVISION}"
SYNTHETIC_REF_RE = re.compile(r"^synthetic-[a-z0-9]+(?:-[a-z0-9]+)*$")
SECRET_SHAPED_PATTERNS = (
    re.compile(r"(?i)(?:^|\b)eyj[a-z0-9_-]{8,}\.[a-z0-9_-]{4,}\.[a-z0-9_-]{4,}"),
    re.compile(r"(?i)(?:^|\b)(?:ghp|github_pat|glpat|sk|xoxb|xoxp)-[a-z0-9_-]{8,}"),
    re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{12,}"),
    re.compile(r"(?i)\b(?:api[_ -]?key|access[_ -]?token|refresh[_ -]?token|password|secret)\s*[:=]\s*\S+"),
)
CANONICAL_SOURCE_FINGERPRINTS = {
    "hermes_cli/pty_bridge.py": {
        "git_blob_sha": "cf4a4e60a75eab4490fa718db8651c079c5ff828",
        "sha256": "e24515762a8ee3c9089369b7ecba20307af62c7cfb6d02abf04261ecacaa6095",
        "size_bytes": 11287,
        "ranges": {
            (208, 223): {
                "sha256": "b47ef01af464b50c8ea8547f2a6172f2a30b951762157fa53430d50f14517edb",
                "markers": ("def write(self, data: bytes) -> None:", "if self._closed or not data:", "os.write(self._fd, view)"),
                "why": "Input is written directly to the PTY and is not a retained-session replay source.",
            },
            (250, 286): {
                "sha256": "7e7a52539df866e073afb4f20c607d9225a62b64d7e857098a6b55446396fb36",
                "markers": ("def close(self) -> None:", "signal.SIGHUP", "signal.SIGTERM", "signal.SIGKILL"),
                "why": "The bridge close path terminates and reaps the child used by the legacy socket path.",
            },
        },
    },
    "hermes_cli/pty_session.py": {
        "git_blob_sha": "43910be9deb4655c6eb2dbad62b0b4aa1d81c0fa",
        "sha256": "617448d953ec978f1b3287b02ac0dd2ad61c255d3366e0ca45efdf829146d8c5",
        "size_bytes": 6769,
        "ranges": {
            (19, 39): {
                "sha256": "5377a211167f9a94202f241728b650dabeede5aeed7261554c4aaf5cae6c8161",
                "markers": ("class RingBuffer:", "self._buf.extend(data)", "self._truncated = True"),
                "why": "Detached output is bounded to the newest configured bytes and may be truncated.",
            },
            (42, 105): {
                "sha256": "7eb9380f292579da9f9f272cb3dea00b792d9977cb965566a191d57dfb989636",
                "markers": ("class PtySession:", "await ws.send_bytes(snap)", "await ws.send_bytes(chunk)", "WS_CLOSE_SUPERSEDED", "if self._ws is not ws:"),
                "why": "A valid handle keeps one PTY alive across socket detach, sends retained bytes on attach, races live sends without a boundary, and protects the replacement socket from a stale detach.",
            },
            (139, 191): {
                "sha256": "24751a22ce6d297089cee6599c0219a33bc88a92b105d157c1ffae5aff09a6f3",
                "markers": ("class PtySessionRegistry:", "if existing is not None and existing.alive:", "if (not s.alive)", "(now - s.last_detached_at) > self._ttl"),
                "why": "The registry reuses live sessions, reaps expired detached entries, and otherwise can spawn a new session for a key that the client must no longer reuse.",
            },
        },
    },
    "hermes_cli/web_server.py": {
        "git_blob_sha": "1fb3e6131629e7399ef12de78148ac6e7ec58d34",
        "sha256": "b52cc35523f891b6947fa59ac70516d955e47714877069e5ed3f06544b793c1a",
        "size_bytes": 703915,
        "ranges": {
            (14416, 14500): {
                "sha256": "8d941a08e658821446b8eeb321d27a946982d49c6253faa7ff2ae38de04b56ff",
                "markers": ('async def _legacy_pump(ws: "WebSocket", bridge) -> None:', "await asyncio.to_thread(bridge.close)", 'if msg.get("type") == "websocket.disconnect"'),
                "why": "The no-handle path is one socket to one bridge and closes the bridge when the socket ends.",
            },
            (15720, 15797): {
                "sha256": "62954abe342c1737e4c987520ccea14f98f2dc8e9dd8735fc0705f20418a719d",
                "markers": ('attach_token = ws.query_params.get("attach") or None', "if attach_token is None:", "await PTY_REGISTRY.attach_or_spawn(", "await session.attach(ws)", "PTY_REGISTRY.detach(attach_token, ws)"),
                "why": "The query-value presence split selects legacy termination or registry-backed detach/reattach. The source does not validate a client-visible handle grammar.",
            },
        },
    },
}

EXPECTED_FIELDS_BY_CASE = {
    "missing-attach-selects-legacy": frozenset({"mode", "keep_alive", "fallback_to_attach"}),
    "legacy-disconnect-terminates": frozenset({"state_after_disconnect", "process_lifetime", "reattach", "spawn_count", "input_replay_count"}),
    "legacy-close-terminates": frozenset({"state_after_close", "process_lifetime", "close_action", "reattach", "spawn_count"}),
    "attach-detach-reattach": frozenset({"state_sequence", "process_lifetime_during_detach", "session_identity_preserved", "spawn_count", "reattach", "input_replay_count"}),
    "malformed-attach-fails-closed": frozenset({"state", "client_action", "spawn_count", "legacy_fallback", "retry_same_handle"}),
    "expired-attach-fails-closed": frozenset({"state", "client_action", "spawn_count", "legacy_fallback", "retry_same_handle", "fresh_session_implicit"}),
    "superseded-socket-fails-closed": frozenset({"state", "active_socket", "active_session_state", "stale_socket_action", "close_code", "active_detach_count"}),
    "retained-output-race": frozenset({"allowed_receive_orders", "client_visible_boundary", "render_policy", "complete_replay_claim", "retained_bytes_are_transcript"}),
    "retained-output-truncation": frozenset({"truncated", "oldest_output_may_be_missing", "complete_replay_claim", "client_blocks_on_replay"}),
    "no-input-replay": frozenset({"input_sent_count", "resize_sent_count", "prompt_sent_count", "tool_action_sent_count", "input_replayed_count", "resize_replayed_count", "prompt_replayed_count", "tool_action_replayed_count", "output_snapshot_may_be_sent", "new_user_action_required"}),
}
CASE_KIND_BY_ID = {
    "missing-attach-selects-legacy": "legacy_selection",
    "legacy-disconnect-terminates": "legacy_disconnect",
    "legacy-close-terminates": "legacy_close",
    "attach-detach-reattach": "attach_detach_reattach",
    "malformed-attach-fails-closed": "malformed_handle",
    "expired-attach-fails-closed": "expired_handle",
    "superseded-socket-fails-closed": "superseded_socket",
    "retained-output-race": "retained_output_race",
    "retained-output-truncation": "retained_output_cap",
    "no-input-replay": "no_input_replay",
}
EXPECTED_VALUES_BY_CASE = {
    "missing-attach-selects-legacy": {"mode": "legacy", "keep_alive": False, "fallback_to_attach": False},
    "legacy-disconnect-terminates": {"state_after_disconnect": "exited", "process_lifetime": "terminated", "reattach": "prohibited", "spawn_count": 1, "input_replay_count": 0},
    "legacy-close-terminates": {"state_after_close": "exited", "process_lifetime": "terminated", "close_action": "terminate_bridge", "reattach": "prohibited", "spawn_count": 1},
    "attach-detach-reattach": {"state_sequence": ["attached", "detached", "attached"], "process_lifetime_during_detach": "alive", "session_identity_preserved": True, "spawn_count": 1, "reattach": "same_exact_handle", "input_replay_count": 0},
    "malformed-attach-fails-closed": {"state": "failed", "client_action": "reject_without_open", "spawn_count": 0, "legacy_fallback": False, "retry_same_handle": False},
    "expired-attach-fails-closed": {"state": "failed", "client_action": "reject_without_open", "spawn_count": 0, "legacy_fallback": False, "retry_same_handle": False, "fresh_session_implicit": False},
    "superseded-socket-fails-closed": {"state": "detached", "active_socket": "synthetic-socket-attach-b", "active_session_state": "attached", "stale_socket_action": "stop_without_retry", "close_code": 4409, "active_detach_count": 0},
    "retained-output-race": {"allowed_receive_orders": [["retained", "live"], ["live", "retained"]], "client_visible_boundary": False, "render_policy": "receive_order", "complete_replay_claim": False, "retained_bytes_are_transcript": False},
    "retained-output-truncation": {"truncated": True, "oldest_output_may_be_missing": True, "complete_replay_claim": False, "client_blocks_on_replay": False},
    "no-input-replay": {"input_sent_count": 1, "resize_sent_count": 1, "prompt_sent_count": 1, "tool_action_sent_count": 1, "input_replayed_count": 0, "resize_replayed_count": 0, "prompt_replayed_count": 0, "tool_action_replayed_count": 0, "output_snapshot_may_be_sent": True, "new_user_action_required": True},
}
HANDLE_VALUES_BY_CASE = {
    "missing-attach-selects-legacy": {"present": False, "classification": "missing"},
    "legacy-disconnect-terminates": {"present": False, "classification": "missing"},
    "legacy-close-terminates": {"present": False, "classification": "missing"},
    "attach-detach-reattach": {"present": True, "classification": "valid_exact_opaque_handle", "reference": "synthetic-handle-a"},
    "malformed-attach-fails-closed": {"present": True, "classification": "malformed", "reference": "synthetic-malformed-handle"},
    "expired-attach-fails-closed": {"present": True, "classification": "expired", "reference": "synthetic-expired-handle"},
    "superseded-socket-fails-closed": {"present": True, "classification": "valid_exact_opaque_handle", "reference": "synthetic-handle-a"},
    "retained-output-race": {"present": True, "classification": "valid_exact_opaque_handle", "reference": "synthetic-handle-a"},
    "retained-output-truncation": {"present": True, "classification": "valid_exact_opaque_handle", "reference": "synthetic-handle-a"},
    "no-input-replay": {"present": True, "classification": "valid_exact_opaque_handle", "reference": "synthetic-handle-a"},
}
IDENTITY_VALUES_BY_CASE = {
    "legacy-disconnect-terminates": {"process_ref": "synthetic-legacy-pty", "socket_ref": "synthetic-socket-legacy-a"},
    "legacy-close-terminates": {"process_ref": "synthetic-legacy-close-pty", "socket_ref": "synthetic-socket-legacy-close"},
    "attach-detach-reattach": {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty"},
    "superseded-socket-fails-closed": {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty"},
    "retained-output-race": {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty"},
    "retained-output-truncation": {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty"},
    "no-input-replay": {"handle_ref": "synthetic-handle-a", "session_ref": "synthetic-session-a", "process_ref": "synthetic-attach-pty"},
}
SOURCE_HAZARD_VALUES_BY_CASE = {
    "expired-attach-fails-closed": "Calling the pinned registry with the stale key after reap could spawn a fresh PTY; the client guard prevents that call.",
}
PAYLOAD_VALUES_BY_CASE = {
    "retained-output-race": {"retained_hex": "52", "live_hex": "4c"},
}
SCHEDULE_VALUES_BY_CASE = {
    "retained-output-race": [
        {"name": "snapshot-first", "receive_order": ["retained", "live"]},
        {"name": "live-first", "receive_order": ["live", "retained"]},
    ],
}
RETENTION_OBSERVATION_VALUES_BY_CASE = {
    "retained-output-truncation": {"buffer_cap_bytes": 1048576, "appended_bytes": 1048577, "oldest_bytes_dropped": 1},
}
HANDLE_FIELDS = frozenset({"present", "classification", "reference"})
MISSING_HANDLE_FIELDS = frozenset({"present", "classification"})
IDENTITY_FIELDS = frozenset({"handle_ref", "session_ref", "process_ref"})
LEGACY_IDENTITY_FIELDS = frozenset({"process_ref", "socket_ref"})
SOURCE_EVIDENCE_FIELDS = frozenset({"schema", "contract", "source", "files", "observations", "redaction"})
SOURCE_METADATA_FIELDS = frozenset({"repository", "revision", "revision_url", "note"})
SOURCE_FILE_FIELDS = frozenset({"path", "git_blob_sha", "sha256", "size_bytes", "ranges"})
SOURCE_RANGE_FIELDS = frozenset({"start", "end", "sha256", "markers", "why"})
OBSERVATION_FIELDS = frozenset({"id", "source_ranges", "source_observation", "contract_result"})
SEMANTIC_FIELDS = frozenset({"summary", "assertions"})
REDACTION_FIELDS = frozenset({"raw_handles", "live_data", "credentials", "transcript_mirror"})
REF_LIKE_KEYS = frozenset({"reference", "socket", "socket_ref", "active_socket"})
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
            "summary": "PtySession.attach closes the old socket with 4409 before assigning the replacement WebSocket; the old handler's later detach is ignored unless it is still the current socket.",
            "assertions": {
                "replacement_close": "old_socket_4409",
                "replacement_order": "close_old_before_assign_new",
                "stale_cleanup": "detach_ignored_when_not_current",
            },
        },
        "contract_result": {
            "summary": "The already-open stale socket receives 4409 before the replacement is assigned; the replacement then becomes active, and the stale handler never retries or detaches it.",
            "assertions": {
                "ordering": "4409_close_before_replacement_assign",
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


def require_keys(value: Any, expected: frozenset[str], label: str) -> dict[str, Any]:
    require(type(value) is dict, f"{label} must be an object")
    require(set(value) == expected, f"{label} fields changed")
    return value


def validate_exact_value(value: Any, expected: Any, label: str) -> None:
    """Require the fixture leaf to have the canonical type and allowed value."""
    require(type(value) is type(expected), f"{label} has the wrong leaf type")
    if type(expected) is dict:
        require(set(value) == set(expected), f"{label} fields changed")
        for key, expected_child in expected.items():
            validate_exact_value(value[key], expected_child, f"{label}.{key}")
        return
    if type(expected) is list:
        require(len(value) == len(expected), f"{label} length changed")
        for index, (actual_child, expected_child) in enumerate(zip(value, expected)):
            validate_exact_value(actual_child, expected_child, f"{label}[{index}]")
        return
    require(value == expected, f"{label} allowed value changed")


def require_synthetic_ref(value: Any, label: str) -> str:
    require(type(value) is str and SYNTHETIC_REF_RE.fullmatch(value) is not None, f"{label} must be a sanitized synthetic reference")
    return value


def validate_event_leaf_types(event: dict[str, Any], label: str) -> None:
    require(type(event) is dict, f"{label} must be an object")
    for field, value in event.items():
        require(type(field) is str, f"{label} field names must be text")
        field_label = f"{label}.{field}"
        if field in {"step", "close_code", "elapsed_seconds"}:
            require(type(value) is int, f"{field_label} must be an integer")
        elif field in {"event", "reason"}:
            require(type(value) is str and value, f"{field_label} must be non-empty text")
        elif field == "payload":
            payload = require_keys(value, SNAPSHOT_PAYLOAD_FIELDS, field_label)
            require(type(payload.get("kind")) is str and payload["kind"] == "output", f"{field_label}.kind must be output")
            require_synthetic_ref(payload.get("bytes_ref"), f"{field_label}.bytes_ref")
        elif field.endswith("_ref") or field in REF_LIKE_KEYS:
            require_synthetic_ref(value, field_label)
        else:
            fail(f"{field_label} has no closed leaf type")


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
    require(type(document) is dict, f"{label} must be an object")
    redaction = require_keys(document.get("redaction"), REDACTION_FIELDS, f"{label} redaction policy")
    for key in REDACTION_FIELDS:
        require(redaction.get(key) is False, f"{label} redaction.{key} must be false")

    for path, value in walk_fixture_values(document):
        if isinstance(value, dict):
            for key, child in value.items():
                require(type(key) is str, f"{label} object keys must be text at {path}")
                lowered_key = key.lower()
                require(
                    lowered_key not in FORBIDDEN_REDACTION_KEYS,
                    f"forbidden {label} key at {path}.{key}",
                )
                ref_like = (
                    not (path.endswith(".assertions") or ".assertions." in path)
                    and (
                        lowered_key.endswith("_ref")
                        or lowered_key in {key_name.lower() for key_name in REF_LIKE_KEYS}
                    )
                )
                if ref_like:
                    require_synthetic_ref(child, f"{label} reference at {path}.{key}")
        if isinstance(value, str):
            for pattern in SECRET_SHAPED_PATTERNS:
                require(pattern.search(value) is None, f"secret-shaped {label} prose at {path}")


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


def replay_alias_kind(event_name: str) -> str | None:
    """Classify replay aliases even when clients add separators or versions."""
    normalized = re.sub(r"[-_]+", ".", event_name.lower())
    parts = [part for part in normalized.split(".") if part]
    if not parts:
        return None
    if parts[-1].startswith("v") and parts[-1][1:].isdigit():
        parts.pop()
    elif parts[-1].startswith("version") and parts[-1][7:].isdigit():
        parts.pop()
    elif len(parts) >= 2 and parts[-2] in {"v", "version"} and parts[-1].isdigit():
        parts = parts[:-2]
    if not parts or parts[-1] != "replay":
        return None
    prefix = parts[:-1]
    if not prefix:
        return None
    if prefix[0] == "input":
        return "input"
    if prefix[0] == "resize":
        return "resize"
    if prefix[0] == "prompt":
        return "prompt"
    if prefix[0] in {"tool", "action"}:
        return "tool_action"
    return None


def validate_timeline_schema(case_id: str, timeline: list[dict[str, Any]]) -> None:
    schema = TIMELINE_SCHEMAS.get(case_id)
    exact_values = TIMELINE_EXACT_VALUES.get(case_id)
    require(schema is not None and exact_values is not None, f"{case_id}: closed timeline schema is missing")
    require(len(timeline) == len(schema) == len(exact_values), f"{case_id}: timeline event count changed")
    for index, (expected_event, expected_fields) in enumerate(schema, start=1):
        event = timeline[index - 1]
        require(type(event) is dict, f"{case_id}: timeline event must be an object")
        actual_event = event.get("event")
        require(type(actual_event) is str, f"{case_id}: event name must be text")
        require(actual_event in EVENT_VOCABULARY, f"{case_id}: unknown event vocabulary")
        require(replay_alias_kind(actual_event) is None, f"{case_id}: replay alias is forbidden")
        require(actual_event == expected_event, f"{case_id}: event {index} changed")
        require(set(event) == expected_fields, f"{case_id}: {expected_event} fields changed")
        require(event.get("step") == index, f"{case_id}: timeline step {index} changed")
        validate_event_leaf_types(event, f"{case_id}.timeline[{index - 1}]")
        for field, expected_value in exact_values[index - 1].items():
            require(event.get(field) == expected_value, f"{case_id}: {expected_event}.{field} changed")


def assert_order(names: list[str], before: str, after: str, case_id: str) -> None:
    require(before in names, f"{case_id}: missing event {before}")
    require(after in names, f"{case_id}: missing event {after}")
    require(names.index(before) < names.index(after), f"{case_id}: {before} must precede {after}")


def event_items(case: dict[str, Any], event: str) -> list[dict[str, Any]]:
    return [item for item in events(case) if item.get("event") == event]


VALIDATION_FAILURES = (AssertionError, AttributeError, IndexError, KeyError, TypeError, ValueError)


def expect_fixture_failure(fixtures: dict[str, Any], mutation: str, mutate: Any) -> None:
    mutated = copy.deepcopy(fixtures)
    mutate(mutated)
    try:
        validate_fixtures(mutated)
    except VALIDATION_FAILURES:
        return
    fail(f"mutation check accepted unsafe fixture: {mutation}")


def expect_source_failure(evidence: dict[str, Any], mutation: str, mutate: Any) -> None:
    mutated = copy.deepcopy(evidence)
    mutate(mutated)
    try:
        validate_source_evidence(mutated, None)
    except VALIDATION_FAILURES:
        return
    fail(f"source mutation check accepted unsafe audit evidence: {mutation}")


def valid_handle(case: dict[str, Any]) -> dict[str, str]:
    case_id = case.get("id")
    handle = require_keys(case.get("attach_handle"), HANDLE_FIELDS, f"{case_id} attach_handle")
    require(handle.get("present") is True, f"{case_id}: handle must be present")
    require(handle.get("classification") == "valid_exact_opaque_handle", f"{case_id}: handle is not exact opaque")
    reference = require_synthetic_ref(handle.get("reference"), f"{case_id}: handle reference")
    identity = case.get("identity")
    require(isinstance(identity, dict), f"{case_id}: lifecycle identity is required")
    require(set(identity) == {"handle_ref", "session_ref", "process_ref"}, f"{case_id}: lifecycle identity fields changed")
    require(identity.get("handle_ref") == reference, f"{case_id}: attach handle does not match expected handle")
    for field in ("handle_ref", "session_ref", "process_ref"):
        require_synthetic_ref(identity.get(field), f"{case_id}: {field}")
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


def validate_replay_alias_unit_cases() -> None:
    aliases = {
        "input.replay.v2": "input",
        "resize_replay_version-2": "resize",
        "prompt-replay-version_2": "prompt",
        "tool_action.replay.v2": "tool_action",
        "action-replay-version_2": "tool_action",
    }
    for alias, expected_kind in aliases.items():
        require(replay_alias_kind(alias) == expected_kind, f"replay alias classifier missed {alias}")
    for ordinary_event in EVENT_VOCABULARY:
        require(replay_alias_kind(ordinary_event) is None, f"replay alias classifier misclassified {ordinary_event}")


def missing_handle(case: dict[str, Any]) -> None:
    case_id = case.get("id")
    handle = require_keys(case.get("attach_handle"), MISSING_HANDLE_FIELDS, f"{case_id} attach_handle")
    require(handle.get("present") is False, f"{case_id}: handle must be absent")
    require(handle.get("classification") == "missing", f"{case_id}: missing classification is required")


def validate_case(case: dict[str, Any]) -> None:
    case_id = case.get("id")
    kind = case.get("kind")
    require(type(case_id) is str, "every case needs a string id")
    require(type(kind) is str, f"{case_id}: every case needs a kind")
    require(case_id in CASE_ROOT_FIELDS, f"{case_id}: case schema is missing")
    require(set(case) == CASE_ROOT_FIELDS[case_id], f"{case_id}: case fields changed")
    require(kind == CASE_KIND_BY_ID.get(case_id), f"{case_id}: scenario kind changed")
    validate_exact_value(case.get("attach_handle"), HANDLE_VALUES_BY_CASE[case_id], f"{case_id}.attach_handle")
    if case_id in IDENTITY_VALUES_BY_CASE:
        validate_exact_value(case.get("identity"), IDENTITY_VALUES_BY_CASE[case_id], f"{case_id}.identity")
    if case_id in SOURCE_HAZARD_VALUES_BY_CASE:
        validate_exact_value(case.get("source_hazard"), SOURCE_HAZARD_VALUES_BY_CASE[case_id], f"{case_id}.source_hazard")
    if case_id in PAYLOAD_VALUES_BY_CASE:
        validate_exact_value(case.get("payloads"), PAYLOAD_VALUES_BY_CASE[case_id], f"{case_id}.payloads")
    if case_id in SCHEDULE_VALUES_BY_CASE:
        validate_exact_value(case.get("schedule_variants"), SCHEDULE_VALUES_BY_CASE[case_id], f"{case_id}.schedule_variants")
    if case_id in RETENTION_OBSERVATION_VALUES_BY_CASE:
        validate_exact_value(case.get("retention_observation"), RETENTION_OBSERVATION_VALUES_BY_CASE[case_id], f"{case_id}.retention_observation")
    timeline = events(case)
    validate_timeline_schema(case_id, timeline)
    names = [item["event"] for item in timeline]
    for name in names:
        require(replay_alias_kind(name) is None, f"{case_id}: non-replayable action replay is forbidden")
    _, replayed_counts = action_counts(names)
    require(all(count == 0 for count in replayed_counts.values()), f"{case_id}: non-replayable action replay is forbidden")
    expected = require_keys(case.get("expected"), EXPECTED_FIELDS_BY_CASE[case_id], f"{case_id} expected")
    validate_exact_value(expected, EXPECTED_VALUES_BY_CASE[case_id], f"{case_id}.expected")

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
        require(identity == {"process_ref": "synthetic-legacy-pty", "socket_ref": "synthetic-socket-legacy-a"}, f"{case_id}: legacy identity changed")
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
        require(expected.get("input_replay_count") == replayed_counts["input"], f"{case_id}: input replay count changed")
        return

    if case_id == "legacy-close-terminates":
        missing_handle(case)
        require(kind == "legacy_close", f"{case_id}: wrong kind")
        identity = case.get("identity")
        require(identity == {"process_ref": "synthetic-legacy-close-pty", "socket_ref": "synthetic-socket-legacy-close"}, f"{case_id}: legacy Close identity changed")
        require(set(names).isdisjoint({"registry.attach", "registry.spawn", "registry.detach", "registry.reuse", "session.attach"}), f"{case_id}: legacy Close entered registry")
        accepts = event_items(case, "socket.accept")
        spawns = event_items(case, "pty.spawn")
        closes = event_items(case, "client.close")
        bridges = event_items(case, "bridge.close")
        require(len(accepts) == len(spawns) == len(closes) == len(bridges) == 1, f"{case_id}: legacy Close must have one accept, spawn, client close, and bridge close")
        require(accepts[0]["socket"] == identity["socket_ref"], f"{case_id}: accepted socket identity changed")
        require(spawns[0]["socket"] == identity["socket_ref"], f"{case_id}: spawned socket identity changed")
        require(closes[0]["socket"] == identity["socket_ref"], f"{case_id}: Close socket identity changed")
        require(spawns[0]["process_ref"] == identity["process_ref"], f"{case_id}: spawned process identity changed")
        require(bridges[0]["process_ref"] == spawns[0]["process_ref"], f"{case_id}: Close bridge identity changed")
        assert_order(names, "client.close", "bridge.close", case_id)
        require(expected.get("state_after_close") == "exited", f"{case_id}: Close must exit legacy mode")
        require(expected.get("process_lifetime") == "terminated", f"{case_id}: legacy Close must terminate")
        require(expected.get("close_action") == "terminate_bridge", f"{case_id}: Close action changed")
        require(expected.get("reattach") == "prohibited", f"{case_id}: legacy Close reattach must be prohibited")
        require(expected.get("spawn_count") == len(spawns) == 1, f"{case_id}: expected one spawn")
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
            (accepts[0], "socket.accept", "synthetic-socket-attach-a"),
            (accepts[1], "socket.accept", "synthetic-socket-attach-b"),
            (attach_events[0], "session.attach", "synthetic-socket-attach-a"),
            (attach_events[1], "session.attach", "synthetic-socket-attach-b"),
            (disconnects[0], "socket.disconnect", "synthetic-socket-attach-a"),
            (detaches[0], "registry.detach", "synthetic-socket-attach-a"),
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
        require(expected.get("input_replay_count") == replayed_counts["input"], f"{case_id}: input replay count changed")
        return

    if case_id in {"malformed-attach-fails-closed", "expired-attach-fails-closed"}:
        require(kind in {"malformed_handle", "expired_handle"}, f"{case_id}: wrong kind")
        handle = require_keys(case.get("attach_handle"), HANDLE_FIELDS, f"{case_id} attach_handle")
        require(handle.get("present") is True, f"{case_id}: invalid handle must be represented")
        require(handle.get("classification") == ("malformed" if case_id.startswith("malformed") else "expired"), f"{case_id}: classification changed")
        reference = require_synthetic_ref(handle.get("reference"), f"{case_id}: invalid handle reference")
        validate_preflight(case_id, names)
        spawn_count = len(event_items(case, "pty.spawn")) + len(event_items(case, "registry.spawn"))
        require(expected.get("state") == "failed", f"{case_id}: invalid handle must fail")
        require(expected.get("client_action") == "reject_without_open", f"{case_id}: invalid handle action changed")
        require(expected.get("spawn_count") == spawn_count == 0, f"{case_id}: invalid handle must not spawn")
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
        require_identity(stale_attach, identity, case_id, "session.attach", "synthetic-socket-attach-a")
        require_identity(replacement_attach, identity, case_id, "session.attach", "synthetic-socket-attach-b")
        close_events = event_items(case, "socket.close")
        require(len(close_events) == 1, f"{case_id}: expected one superseded close")
        close_event = close_events[0]
        require_identity(close_event, identity, case_id, "socket.close", "synthetic-socket-attach-a")
        require(close_event.get("close_code") == 4409, f"{case_id}: close code must be 4409")
        ignored_events = event_items(case, "stale_socket.detach_ignored")
        finally_events = event_items(case, "stale_socket.finally")
        require(len(ignored_events) == len(finally_events) == 1, f"{case_id}: stale cleanup events are required")
        require_identity(finally_events[0], identity, case_id, "stale_socket.finally", "synthetic-socket-attach-a")
        require_identity(ignored_events[0], identity, case_id, "stale_socket.detach_ignored", "synthetic-socket-attach-a")
        names_indexes = {
            "stale_attach": names.index("session.attach"),
            "replacement_attach": names.index("session.attach", names.index("session.attach") + 1),
            "socket.close": names.index("socket.close"),
            "stale_socket.finally": names.index("stale_socket.finally"),
            "stale_socket.detach_ignored": names.index("stale_socket.detach_ignored"),
        }
        require(
            names_indexes["stale_attach"]
            < names_indexes["socket.close"]
            < names_indexes["replacement_attach"]
            < names_indexes["stale_socket.finally"]
            < names_indexes["stale_socket.detach_ignored"],
            f"{case_id}: stale close must precede replacement assignment and stale cleanup",
        )
        require(expected.get("active_socket") == "synthetic-socket-attach-b", f"{case_id}: replacement must remain active")
        require(expected.get("active_session_state") == "attached", f"{case_id}: replacement must remain attached")
        require(expected.get("stale_socket_action") == "stop_without_retry", f"{case_id}: stale socket must fail closed")
        require(expected.get("close_code") == 4409, f"{case_id}: expected superseded close code")
        active_detach_count = sum(
            1 for event in event_items(case, "registry.detach")
            if event.get("socket") == expected.get("active_socket")
        )
        require(expected.get("active_detach_count") == active_detach_count == 0, f"{case_id}: stale finally detached the replacement")
        return

    if case_id == "retained-output-race":
        identity = valid_handle(case)
        require(kind == "retained_output_race", f"{case_id}: wrong kind")
        payloads = require_keys(case.get("payloads"), PAYLOAD_FIELDS, f"{case_id} payloads")
        require(payloads == {"retained_hex": "52", "live_hex": "4c"}, f"{case_id}: payload markers changed")
        schedules = case.get("schedule_variants")
        require(isinstance(schedules, list) and len(schedules) == 2, f"{case_id}: two race schedules are required")
        for index, schedule in enumerate(schedules):
            require_keys(schedule, SCHEDULE_FIELDS, f"{case_id} schedule_variants[{index}]")
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
        observation = require_keys(case.get("retention_observation"), RETENTION_OBSERVATION_FIELDS, f"{case_id} retention_observation")
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
                require_identity(event, identity, case_id, event_name, "synthetic-socket-attach-a")
        snapshot_events = event_items(case, "attach.snapshot_send")
        attach_events = event_items(case, "session.attach")
        disconnect_events = event_items(case, "socket.disconnect")
        require(len(attach_events) == len(disconnect_events) == len(snapshot_events) == 1, f"{case_id}: exactly one detach and reattach sequence is required")
        require_identity(disconnect_events[0], identity, case_id, "socket.disconnect", "synthetic-socket-attach-a")
        require_identity(attach_events[0], identity, case_id, "session.attach", "synthetic-socket-attach-b")
        snapshot = snapshot_events[0]
        require_identity(snapshot, identity, case_id, "attach.snapshot_send", "synthetic-socket-attach-b")
        require(set(snapshot) == SNAPSHOT_EVENT_FIELDS, f"{case_id}: snapshot has extra or missing fields")
        snapshot_payload_ref = snapshot.get("payload_ref")
        require(snapshot_payload_ref == "synthetic-output-only", f"{case_id}: reattach snapshot must contain output bytes only")
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
    require(type(fixtures) is dict, "fixtures must be an object")
    require(set(fixtures) == FIXTURE_ROOT_FIELDS, "fixture root fields changed")
    validate_exact_value(fixtures.get("schema"), "hermternal.fixture.pty-attach.v1", "fixture.schema")
    validate_exact_value(fixtures.get("contract"), CONTRACT, "fixture.contract")
    validate_exact_value(fixtures.get("source_revision"), REVISION, "fixture.source_revision")
    validate_exact_value(fixtures.get("surface"), "web-only", "fixture.surface")
    validate_exact_value(fixtures.get("synthetic"), True, "fixture.synthetic")
    retention = require_keys(fixtures.get("retention"), RETENTION_FIELDS, "fixture retention")
    validate_exact_value(retention, {"ttl_seconds": 1800, "buffer_cap_bytes": 1048576}, "fixture.retention")
    validate_exact_value(fixtures.get("redaction"), {"raw_handles": False, "live_data": False, "credentials": False, "transcript_mirror": False}, "fixture.redaction")
    validate_redaction(fixtures, "fixture")

    cases = fixtures.get("cases")
    require(isinstance(cases, list), "fixtures.cases must be a list")
    ids = [case.get("id") for case in cases if isinstance(case, dict)]
    require(all(type(case_id) is str for case_id in ids), "fixture case ids must be text")
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


def validate_mutation_inventory(
    executed_ids: set[str],
    expected_ids: frozenset[str],
    reported_count: int | None = None,
) -> int:
    """Require the mutation result to match the executable mutation inventory."""
    require(len(executed_ids) == len(expected_ids), "mutation inventory count changed")
    require(executed_ids == set(expected_ids), "mutation inventory membership changed")
    count = len(executed_ids)
    if reported_count is not None:
        require(reported_count == count, "mutation report count changed")
    return count


def run_mutation_checks(evidence: dict[str, Any], fixtures: dict[str, Any]) -> int:
    """Prove the validator rejects known source, identity, schema, and replay bypasses."""
    mutation_inventory = frozenset(
        {
            "source.duplicate_session_file",
            "source.omit_bridge_file",
            "source.unbound_observation_range",
            "source.wrong_valid_observation_range",
            "source.missing_source_observation",
            "source.false_source_prose",
            "source.missing_contract_result",
            "source.false_contract_prose",
            "source.false_structured_contract_assertion",
            "source.redaction_flag",
            "source.raw_handle_key",
            "source.extra_root_field",
            "source.extra_metadata_field",
            "source.extra_file_field",
            "source.extra_range_field",
            "source.extra_observation_field",
            "source.extra_semantic_field",
            "source.wrong_revision_url",
            "source.canonical_file_sha256",
            "source.canonical_git_blob_sha",
            "source.canonical_file_size",
            "source.canonical_range_sha256",
            "source.canonical_range_marker",
            "source.canonical_range_rationale",
            "source.secret_shaped_prose",
            "fixture.kind_mismatch_malformed",
            "fixture.kind_mismatch_expired",
            "fixture.source_hazard_none",
            "fixture.source_hazard_object",
            "fixture.expected_state_none",
            "fixture.expected_state_object",
            "fixture.schedule_name_none",
            "fixture.schedule_name_object",
            "fixture.object_event_name",
            "fixture.reused_session_identity",
            "fixture.attach_handle_reference",
            "fixture.detach_socket_identity",
            "fixture.legacy_bridge_process_identity",
            "fixture.attach_process_identity",
            "fixture.legacy_registry_attach",
            "fixture.legacy_registry_spawn",
            "fixture.input_snapshot_ref",
            "fixture.tool_action_snapshot_ref",
            "fixture.extra_snapshot_input_field",
            "fixture.nested_snapshot_input_field",
            "fixture.nested_snapshot_tool_action_field",
            "fixture.malformed_socket_accept",
            "fixture.malformed_websocket_accept",
            "fixture.malformed_registry_lookup",
            "fixture.malformed_route_dispatch",
            "fixture.malformed_session_attach",
            "fixture.replay_input",
            "fixture.replay_resize",
            "fixture.replay_prompt",
            "fixture.replay_tool_action",
            "fixture.replay_input_v2",
            "fixture.replay_resize_v2",
            "fixture.replay_prompt_v2",
            "fixture.replay_tool_action_v2",
            "fixture.superseded_close_binding",
            "fixture.superseded_close_order",
            "fixture.extra_active_replacement_detach",
            "fixture.superseded_client_retry",
            "fixture.superseded_session_detach",
            "fixture.superseded_client_validate_handle",
            "fixture.extra_pty_spawn",
            "fixture.mismatched_identity_event",
            "fixture.non_synthetic_ref",
            "fixture.none_leaf_value",
            "fixture.object_reference_value",
            "fixture.invalid_payload_leaf",
            "fixture.wrong_exact_reference",
            "fixture.secret_shaped_prose",
            "fixture.attach_bridge_close",
            "fixture.legacy_close_missing_bridge",
            "fixture.attach_close_terminated",
            "fixture.extra_case_field",
        }
    )
    executed_ids: set[str] = set()

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
        mutated["source"]["raw_handle"] = "synthetic-raw-handle"

    def mutate_source_extra_root_field(mutated: dict[str, Any]) -> None:
        mutated["unexpected"] = "synthetic-extra"

    def mutate_source_extra_metadata_field(mutated: dict[str, Any]) -> None:
        mutated["source"]["unexpected"] = "synthetic-extra"

    def mutate_source_extra_file_field(mutated: dict[str, Any]) -> None:
        mutated["files"][0]["unexpected"] = "synthetic-extra"

    def mutate_source_extra_range_field(mutated: dict[str, Any]) -> None:
        mutated["files"][0]["ranges"][0]["unexpected"] = "synthetic-extra"

    def mutate_source_extra_observation_field(mutated: dict[str, Any]) -> None:
        observation(mutated)["unexpected"] = "synthetic-extra"

    def mutate_source_extra_semantic_field(mutated: dict[str, Any]) -> None:
        observation(mutated)["source_observation"]["unexpected"] = "synthetic-extra"

    def mutate_wrong_revision_url(mutated: dict[str, Any]) -> None:
        mutated["source"]["revision_url"] = "https://github.com/NousResearch/hermes-agent/tree/main"

    def source_record(mutated: dict[str, Any], path: str) -> dict[str, Any]:
        records = [record for record in source_files(mutated) if record.get("path") == path]
        require(len(records) == 1, f"source mutation target {path!r} must exist exactly once")
        return records[0]

    def source_range_record(mutated: dict[str, Any], path: str, start: int, end: int) -> dict[str, Any]:
        ranges = source_record(mutated, path).get("ranges")
        require(isinstance(ranges, list), f"source mutation target {path!r} must have ranges")
        matches = [item for item in ranges if isinstance(item, dict) and item.get("start") == start and item.get("end") == end]
        require(len(matches) == 1, f"source mutation target {path}:{start}-{end} must exist exactly once")
        return matches[0]

    def mutate_canonical_file_sha256(mutated: dict[str, Any]) -> None:
        source_record(mutated, "hermes_cli/pty_bridge.py")["sha256"] = "0" * 64

    def mutate_canonical_git_blob_sha(mutated: dict[str, Any]) -> None:
        source_record(mutated, "hermes_cli/pty_bridge.py")["git_blob_sha"] = "0" * 40

    def mutate_canonical_file_size(mutated: dict[str, Any]) -> None:
        source_record(mutated, "hermes_cli/pty_bridge.py")["size_bytes"] = 11288

    def mutate_canonical_range_sha256(mutated: dict[str, Any]) -> None:
        source_range_record(mutated, "hermes_cli/pty_bridge.py", 208, 223)["sha256"] = "0" * 64

    def mutate_canonical_range_marker(mutated: dict[str, Any]) -> None:
        source_range_record(mutated, "hermes_cli/pty_bridge.py", 208, 223)["markers"][0] = "def write(self, payload: bytes) -> None:"

    def mutate_canonical_range_rationale(mutated: dict[str, Any]) -> None:
        source_range_record(mutated, "hermes_cli/pty_bridge.py", 208, 223)["why"] = "The source uses an unrelated input path."

    def mutate_source_secret_shaped_prose(mutated: dict[str, Any]) -> None:
        mutated["source"]["note"] = "Bearer abcdefghijkl"

    def mutate_kind_mismatch(mutated: dict[str, Any], case_id: str, wrong_kind: str) -> None:
        fixture_case(mutated, case_id)["kind"] = wrong_kind

    def mutate_source_hazard_none(mutated: dict[str, Any]) -> None:
        fixture_case(mutated, "expired-attach-fails-closed")["source_hazard"] = None

    def mutate_source_hazard_object(mutated: dict[str, Any]) -> None:
        fixture_case(mutated, "expired-attach-fails-closed")["source_hazard"] = {"text": "synthetic-hazard"}

    def mutate_expected_state(mutated: dict[str, Any], value: Any) -> None:
        fixture_case(mutated, "malformed-attach-fails-closed")["expected"]["state"] = value

    def mutate_schedule_name(mutated: dict[str, Any], value: Any) -> None:
        fixture_case(mutated, "retained-output-race")["schedule_variants"][0]["name"] = value

    def mutate_object_event_name(mutated: dict[str, Any]) -> None:
        fixture_case(mutated, "malformed-attach-fails-closed")["timeline"][0]["event"] = {"name": "client.validate_handle"}

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
        detach[0]["socket"] = "synthetic-socket-attach-b"

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
        close[0]["socket"] = "synthetic-socket-attach-b"

    def mutate_superseded_close_order(mutated: dict[str, Any]) -> None:
        case = fixture_case(mutated, "superseded-socket-fails-closed")
        timeline = case["timeline"]
        close_index = next(index for index, item in enumerate(timeline) if item.get("event") == "socket.close")
        close_event = timeline.pop(close_index)
        replacement_index = next(
            index for index, item in enumerate(timeline)
            if item.get("event") == "session.attach" and item.get("socket") == "synthetic-socket-attach-b"
        )
        timeline.insert(replacement_index + 1, close_event)
        for step, event in enumerate(timeline, start=1):
            event["step"] = step

    def supersession_case(mutated: dict[str, Any]) -> dict[str, Any]:
        return fixture_case(mutated, "superseded-socket-fails-closed")

    def mutate_extra_active_replacement_detach(mutated: dict[str, Any]) -> None:
        case = supersession_case(mutated)
        event = copy.deepcopy(event_items(case, "stale_socket.detach_ignored")[0])
        event["event"] = "registry.detach"
        event["step"] = 99
        event["socket"] = "synthetic-socket-attach-b"
        case["timeline"].insert(3, event)

    def mutate_superseded_client_retry(mutated: dict[str, Any]) -> None:
        case = supersession_case(mutated)
        case["timeline"].insert(3, {"step": 99, "event": "client.retry"})

    def mutate_superseded_session_detach(mutated: dict[str, Any]) -> None:
        case = supersession_case(mutated)
        event = copy.deepcopy(event_items(case, "stale_socket.detach_ignored")[0])
        event["event"] = "session.detach"
        event["step"] = 99
        case["timeline"].insert(3, event)

    def mutate_superseded_client_validate_handle(mutated: dict[str, Any]) -> None:
        case = supersession_case(mutated)
        case["timeline"].insert(1, {"step": 99, "event": "client.validate_handle"})

    def mutate_extra_pty_spawn(mutated: dict[str, Any]) -> None:
        case = fixture_case(mutated, "attach-detach-reattach")
        case["timeline"].insert(2, {
            "step": 99,
            "event": "pty.spawn",
            "process_ref": "synthetic-extra-pty",
            "socket": "synthetic-socket-attach-a",
        })

    def mutate_mismatched_identity_event(mutated: dict[str, Any]) -> None:
        case = supersession_case(mutated)
        replacement = event_items(case, "session.attach")[1]
        replacement["process_ref"] = "synthetic-other-pty"

    def mutate_non_synthetic_ref(mutated: dict[str, Any]) -> None:
        case = fixture_case(mutated, "legacy-disconnect-terminates")
        event_items(case, "socket.accept")[0]["socket"] = "socket-raw"

    def mutate_none_leaf_value(mutated: dict[str, Any]) -> None:
        case = fixture_case(mutated, "superseded-socket-fails-closed")
        event_items(case, "socket.close")[0]["close_code"] = None

    def mutate_object_reference_value(mutated: dict[str, Any]) -> None:
        case = fixture_case(mutated, "legacy-disconnect-terminates")
        event_items(case, "socket.accept")[0]["socket"] = {"value": "synthetic-socket-legacy-a"}

    def mutate_invalid_payload_leaf(mutated: dict[str, Any]) -> None:
        snapshot = snapshot_event(mutated)
        snapshot["payload"]["bytes_ref"] = {"value": "synthetic-output-bytes"}

    def mutate_wrong_exact_reference(mutated: dict[str, Any]) -> None:
        case = fixture_case(mutated, "legacy-close-terminates")
        event_items(case, "bridge.close")[0]["process_ref"] = "synthetic-other-pty"

    def mutate_fixture_secret_shaped_prose(mutated: dict[str, Any]) -> None:
        case = fixture_case(mutated, "expired-attach-fails-closed")
        case["source_hazard"] = "password: abcdefghijkl"

    def mutate_attach_bridge_close(mutated: dict[str, Any]) -> None:
        case = fixture_case(mutated, "attach-detach-reattach")
        case["timeline"].append({"step": 9, "event": "bridge.close", "process_ref": "synthetic-attach-pty"})

    def mutate_legacy_close_missing_bridge(mutated: dict[str, Any]) -> None:
        case = fixture_case(mutated, "legacy-close-terminates")
        timeline = case["timeline"]
        case["timeline"] = [event for event in timeline if event.get("event") != "bridge.close"]

    def mutate_attach_close_terminated(mutated: dict[str, Any]) -> None:
        case = fixture_case(mutated, "attach-detach-reattach")
        case["expected"]["process_lifetime_during_detach"] = "terminated"

    def mutate_extra_case_field(mutated: dict[str, Any]) -> None:
        fixture_case(mutated, "missing-attach-selects-legacy")["unexpected"] = "synthetic-extra"

    def expect_fixture(mutation_id: str, description: str, mutate: Any) -> None:
        require(mutation_id in mutation_inventory, f"unlisted fixture mutation {mutation_id}")
        require(mutation_id not in executed_ids, f"duplicate fixture mutation {mutation_id}")
        expect_fixture_failure(fixtures, description, mutate)
        executed_ids.add(mutation_id)

    def expect_source(mutation_id: str, description: str, mutate: Any) -> None:
        require(mutation_id in mutation_inventory, f"unlisted source mutation {mutation_id}")
        require(mutation_id not in executed_ids, f"duplicate source mutation {mutation_id}")
        expect_source_failure(evidence, description, mutate)
        executed_ids.add(mutation_id)

    expect_source("source.duplicate_session_file", "duplicate pty_session audit record", mutate_duplicate_session_file)
    expect_source("source.omit_bridge_file", "omitted pty_bridge audit record", mutate_omit_bridge_file)
    expect_source("source.unbound_observation_range", "observation references an unaudited source range", mutate_unbound_observation_range)
    expect_source("source.wrong_valid_observation_range", "observation references a different audited range", mutate_wrong_valid_observation_range)
    expect_source("source.missing_source_observation", "observation omits source_observation semantics", mutate_missing_source_observation)
    expect_source("source.false_source_prose", "observation contains false source prose", mutate_false_source_prose)
    expect_source("source.missing_contract_result", "observation omits contract_result semantics", mutate_missing_contract_result)
    expect_source("source.false_contract_prose", "observation contains false contract prose", mutate_false_contract_prose)
    expect_source("source.false_structured_contract_assertion", "observation contains false structured semantics", mutate_false_structured_contract_assertion)
    expect_source("source.redaction_flag", "source redaction flag permits raw handles", mutate_source_redaction_flag)
    expect_source("source.raw_handle_key", "source evidence contains an extra raw-handle field", mutate_source_raw_handle_key)
    expect_source("source.extra_root_field", "source evidence contains an unknown root field", mutate_source_extra_root_field)
    expect_source("source.extra_metadata_field", "source evidence contains an unknown source field", mutate_source_extra_metadata_field)
    expect_source("source.extra_file_field", "source evidence contains an unknown file field", mutate_source_extra_file_field)
    expect_source("source.extra_range_field", "source evidence contains an unknown range field", mutate_source_extra_range_field)
    expect_source("source.extra_observation_field", "source evidence contains an unknown observation field", mutate_source_extra_observation_field)
    expect_source("source.extra_semantic_field", "source evidence contains an unknown semantic field", mutate_source_extra_semantic_field)
    expect_source("source.wrong_revision_url", "source evidence uses an unpinned revision URL", mutate_wrong_revision_url)
    expect_source("source.canonical_file_sha256", "source evidence forges a full-file SHA-256", mutate_canonical_file_sha256)
    expect_source("source.canonical_git_blob_sha", "source evidence forges a Git blob SHA", mutate_canonical_git_blob_sha)
    expect_source("source.canonical_file_size", "source evidence forges a full-file size", mutate_canonical_file_size)
    expect_source("source.canonical_range_sha256", "source evidence forges a range SHA-256", mutate_canonical_range_sha256)
    expect_source("source.canonical_range_marker", "source evidence forges a range marker", mutate_canonical_range_marker)
    expect_source("source.canonical_range_rationale", "source evidence forges a range rationale", mutate_canonical_range_rationale)
    expect_source("source.secret_shaped_prose", "source evidence contains secret-shaped free prose", mutate_source_secret_shaped_prose)

    expect_fixture("fixture.kind_mismatch_malformed", "malformed case uses the expired scenario kind", lambda mutated: mutate_kind_mismatch(mutated, "malformed-attach-fails-closed", "expired_handle"))
    expect_fixture("fixture.kind_mismatch_expired", "expired case uses the malformed scenario kind", lambda mutated: mutate_kind_mismatch(mutated, "expired-attach-fails-closed", "malformed_handle"))
    expect_fixture("fixture.source_hazard_none", "expired case omits source hazard text", mutate_source_hazard_none)
    expect_fixture("fixture.source_hazard_object", "expired case uses an object source hazard", mutate_source_hazard_object)
    expect_fixture("fixture.expected_state_none", "malformed case omits expected state", lambda mutated: mutate_expected_state(mutated, None))
    expect_fixture("fixture.expected_state_object", "malformed case uses an object expected state", lambda mutated: mutate_expected_state(mutated, {"state": "failed"}))
    expect_fixture("fixture.schedule_name_none", "race schedule omits its name", lambda mutated: mutate_schedule_name(mutated, None))
    expect_fixture("fixture.schedule_name_object", "race schedule uses an object name", lambda mutated: mutate_schedule_name(mutated, {"name": "snapshot-first"}))
    expect_fixture("fixture.object_event_name", "timeline event name is an object", mutate_object_event_name)

    expect_fixture("fixture.reused_session_identity", "registry reuse points at a different PTY session", mutate_reused_session_identity)
    expect_fixture("fixture.attach_handle_reference", "attach handle reference differs from expected identity", mutate_attach_handle_reference)
    expect_fixture("fixture.detach_socket_identity", "registry detach targets the replacement socket", mutate_detach_socket_identity)
    expect_fixture("fixture.legacy_bridge_process_identity", "legacy bridge closes a different process", mutate_legacy_bridge_process_identity)
    expect_fixture("fixture.attach_process_identity", "registry reuse points at a different PTY process", mutate_attach_process_identity)
    expect_fixture("fixture.legacy_registry_attach", "legacy path enters registry.attach", mutate_legacy_registry_event("registry.attach"))
    expect_fixture("fixture.legacy_registry_spawn", "legacy path enters registry.spawn", mutate_legacy_registry_event("registry.spawn"))
    expect_fixture("fixture.input_snapshot_ref", "reattach snapshot includes synthetic input in payload_ref", mutate_input_snapshot_ref)
    expect_fixture("fixture.tool_action_snapshot_ref", "reattach snapshot includes a tool action in payload_ref", mutate_tool_action_snapshot_ref)
    expect_fixture("fixture.extra_snapshot_input_field", "reattach snapshot adds an extra top-level input field", mutate_extra_snapshot_input_field)
    expect_fixture("fixture.nested_snapshot_input_field", "reattach snapshot adds a nested input field", mutate_nested_snapshot_input_field)
    expect_fixture("fixture.nested_snapshot_tool_action_field", "reattach snapshot adds a nested tool-action field", mutate_nested_snapshot_tool_action_field)
    expect_fixture("fixture.malformed_socket_accept", "malformed preflight permits socket.accept", mutate_malformed_event("socket.accept"))
    expect_fixture("fixture.malformed_websocket_accept", "malformed preflight permits websocket.accept", mutate_malformed_event("websocket.accept"))
    expect_fixture("fixture.malformed_registry_lookup", "malformed preflight permits registry.lookup", mutate_malformed_event("registry.lookup"))
    expect_fixture("fixture.malformed_route_dispatch", "malformed preflight permits route.dispatch", mutate_malformed_event("route.dispatch"))
    expect_fixture("fixture.malformed_session_attach", "malformed preflight permits session.attach", mutate_malformed_event("session.attach"))
    expect_fixture("fixture.replay_input", "reattach replays input.replay", mutate_replay_event("input.replay"))
    expect_fixture("fixture.replay_resize", "reattach replays resize.replay", mutate_replay_event("resize.replay"))
    expect_fixture("fixture.replay_prompt", "reattach replays prompt.replay", mutate_replay_event("prompt.replay"))
    expect_fixture("fixture.replay_tool_action", "reattach replays tool.action.replay", mutate_replay_event("tool.action.replay"))
    expect_fixture("fixture.replay_input_v2", "reattach replays input.replay.v2", mutate_replay_event("input.replay.v2"))
    expect_fixture("fixture.replay_resize_v2", "reattach replays resize_replay_v2", mutate_replay_event("resize_replay_v2"))
    expect_fixture("fixture.replay_prompt_v2", "reattach replays prompt-replay-v2", mutate_replay_event("prompt-replay-v2"))
    expect_fixture("fixture.replay_tool_action_v2", "reattach replays tool_action.replay.v2", mutate_replay_event("tool_action.replay.v2"))
    expect_fixture("fixture.superseded_close_binding", "superseded close code binds to the replacement socket", mutate_superseded_close_binding)
    expect_fixture("fixture.superseded_close_order", "superseded close precedes replacement attach", mutate_superseded_close_order)
    expect_fixture("fixture.extra_active_replacement_detach", "supersession detaches the active replacement", mutate_extra_active_replacement_detach)
    expect_fixture("fixture.superseded_client_retry", "superseded stale socket retries after 4409", mutate_superseded_client_retry)
    expect_fixture("fixture.superseded_session_detach", "stale cleanup detaches after reattach", mutate_superseded_session_detach)
    expect_fixture("fixture.superseded_client_validate_handle", "supersession validates a handle after attach", mutate_superseded_client_validate_handle)
    expect_fixture("fixture.extra_pty_spawn", "attach timeline spawns an extra PTY", mutate_extra_pty_spawn)
    expect_fixture("fixture.mismatched_identity_event", "supersession event changes process identity", mutate_mismatched_identity_event)
    expect_fixture("fixture.non_synthetic_ref", "fixture contains a non-synthetic reference", mutate_non_synthetic_ref)
    expect_fixture("fixture.none_leaf_value", "fixture contains a None leaf value", mutate_none_leaf_value)
    expect_fixture("fixture.object_reference_value", "fixture contains an object reference leaf", mutate_object_reference_value)
    expect_fixture("fixture.invalid_payload_leaf", "snapshot payload contains an object byte reference", mutate_invalid_payload_leaf)
    expect_fixture("fixture.wrong_exact_reference", "fixture changes an exact process reference", mutate_wrong_exact_reference)
    expect_fixture("fixture.secret_shaped_prose", "fixture contains secret-shaped free prose", mutate_fixture_secret_shaped_prose)
    expect_fixture("fixture.attach_bridge_close", "attach mode closes the bridge", mutate_attach_bridge_close)
    expect_fixture("fixture.legacy_close_missing_bridge", "legacy Close omits bridge termination", mutate_legacy_close_missing_bridge)
    expect_fixture("fixture.attach_close_terminated", "attach Close incorrectly terminates the PTY", mutate_attach_close_terminated)
    expect_fixture("fixture.extra_case_field", "fixture case contains an unknown field", mutate_extra_case_field)

    reported_count = len(executed_ids)
    validate_mutation_inventory(executed_ids, mutation_inventory, reported_count)
    missing_id = next(iter(mutation_inventory))
    try:
        validate_mutation_inventory(executed_ids - {missing_id}, mutation_inventory, reported_count - 1)
    except AssertionError:
        pass
    else:
        fail("mutation inventory regression accepted a removed mutation")
    try:
        validate_mutation_inventory(executed_ids, mutation_inventory, reported_count - 1)
    except AssertionError:
        pass
    else:
        fail("mutation inventory regression accepted a count mismatch")
    return validate_mutation_inventory(executed_ids, mutation_inventory)

def validate_canonical_fingerprint(path_value: str, record: dict[str, Any]) -> None:
    canonical = CANONICAL_SOURCE_FINGERPRINTS.get(path_value)
    require(canonical is not None, f"{path_value}: canonical fingerprint is missing")
    require(record.get("git_blob_sha") == canonical["git_blob_sha"], f"{path_value}: git blob fingerprint changed")
    require(record.get("sha256") == canonical["sha256"], f"{path_value}: file sha256 fingerprint changed")
    require(record.get("size_bytes") == canonical["size_bytes"], f"{path_value}: file size fingerprint changed")
    canonical_ranges = canonical["ranges"]
    ranges = record.get("ranges")
    require(isinstance(ranges, list), f"{path_value}: ranges must be a list")
    require({(item.get("start"), item.get("end")) for item in ranges if isinstance(item, dict)} == set(canonical_ranges), f"{path_value}: canonical range set changed")
    for item in ranges:
        key = (item["start"], item["end"])
        expected = canonical_ranges[key]
        require(item.get("sha256") == expected["sha256"], f"{path_value}:{key[0]}-{key[1]}: range sha fingerprint changed")
        require(tuple(item.get("markers", ())) == expected["markers"], f"{path_value}:{key[0]}-{key[1]}: range markers changed")
        require(item.get("why") == expected["why"], f"{path_value}:{key[0]}-{key[1]}: range rationale changed")


def validate_source_evidence(evidence: dict[str, Any], source_root: Path | None) -> int:
    require_keys(evidence, SOURCE_EVIDENCE_FIELDS, "source audit root")
    require(evidence.get("schema") == "hermternal.source-audit.pty-attach.v1", "source audit schema changed")
    require(evidence.get("contract") == CONTRACT, "source audit contract changed")
    source = require_keys(evidence.get("source"), SOURCE_METADATA_FIELDS, "source audit metadata")
    require(source.get("repository") == "NousResearch/hermes-agent", "source repository changed")
    require(source.get("revision") == REVISION, "source revision changed")
    require(source.get("revision_url") == PINNED_REVISION_URL, "source revision URL changed")
    require(isinstance(source.get("note"), str) and source["note"], "source audit note is required")
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
        record = require_keys(record, SOURCE_FILE_FIELDS, f"{path_value} source file")
        require(path_value.startswith("hermes_cli/"), "source audit path must be a Hermes path")
        hex_string(record.get("git_blob_sha"), 40, f"{path_value}.git_blob_sha")
        hex_string(record.get("sha256"), 64, f"{path_value}.sha256")
        size = record.get("size_bytes")
        require(isinstance(size, int) and size > 0, f"{path_value}.size_bytes must be positive")
        ranges = record.get("ranges")
        require(isinstance(ranges, list) and ranges, f"{path_value}.ranges are required")
        range_keys: set[tuple[int, int]] = set()
        for line_range in ranges:
            line_range = require_keys(line_range, SOURCE_RANGE_FIELDS, f"{path_value} source range")
            start = line_range.get("start")
            end = line_range.get("end")
            require(isinstance(start, int) and isinstance(end, int) and 1 <= start <= end, f"{path_value}: invalid line range")
            require((start, end) not in range_keys, f"{path_value}:{start}-{end}: duplicate source range")
            range_keys.add((start, end))
            hex_string(line_range.get("sha256"), 64, f"{path_value}:{start}-{end}.sha256")
            markers = line_range.get("markers")
            require(isinstance(markers, list) and markers and all(isinstance(marker, str) and marker for marker in markers), f"{path_value}:{start}-{end}.markers are required")
            require(isinstance(line_range.get("why"), str) and line_range["why"], f"{path_value}:{start}-{end}.why is required")

        validate_canonical_fingerprint(path_value, record)
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
    require(all(type(observation_id) is str for observation_id in observation_ids), "source audit observation ids must be text")
    require(len(observation_ids) == len(set(observation_ids)), "source audit observation ids must be unique")
    require(set(observation_ids) == REQUIRED_OBSERVATIONS, "source audit observations are incomplete or unexpected")
    for observation in observations:
        observation = require_keys(observation, OBSERVATION_FIELDS, "source audit observation")
        observation_id = observation["id"]
        expected = OBSERVATION_EXPECTATIONS.get(observation_id)
        require(expected is not None, f"{observation_id}: observation expectations are missing")
        source_semantics = require_keys(observation.get("source_observation"), SEMANTIC_FIELDS, f"{observation_id} source_observation")
        contract_semantics = require_keys(observation.get("contract_result"), SEMANTIC_FIELDS, f"{observation_id} contract_result")
        require(isinstance(source_semantics.get("summary"), str), f"{observation_id}: source summary must be text")
        require(isinstance(contract_semantics.get("summary"), str), f"{observation_id}: contract summary must be text")
        require(isinstance(source_semantics.get("assertions"), dict), f"{observation_id}: source assertions must be an object")
        require(isinstance(contract_semantics.get("assertions"), dict), f"{observation_id}: contract assertions must be an object")
        validate_exact_value(source_semantics, expected["source_observation"], f"{observation_id}.source_observation")
        validate_exact_value(contract_semantics, expected["contract_result"], f"{observation_id}.contract_result")
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
        validate_replay_alias_unit_cases()
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
    except VALIDATION_FAILURES as exc:
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
