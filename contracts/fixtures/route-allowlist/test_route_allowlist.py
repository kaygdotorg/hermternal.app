#!/usr/bin/env python3
"""Validate the frozen C-01 Dashboard route and operation allowlist.

This validator is intentionally offline and standard-library-only. It reads
synthetic JSON, never imports Hermes, never opens a socket, and never calls a
provider. Source-root mode verifies the pinned Git commit/tree, recorded blob
IDs and SHA-256 files, and citation markers against an independently obtained
checkout or content-only snapshot.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import platform
import re
import statistics
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent
ALLOWLIST_PATH = ROOT / "route_allowlist.json"
AUDIT_PATH = ROOT / "source_audit.json"
CASES_PATH = ROOT / "cases.json"
PINNED_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
PINNED_TREE_SHA = "886db5eb1150f819344d67fedc81aef0caab09ff"
REPOSITORY = "NousResearch/hermes-agent"
REPOSITORY_URL = "https://github.com/NousResearch/hermes-agent"
AUDIT_ID = "route-allowlist-c01-f5be9236"
BASELINE_REPETITIONS = 7
README_PATH = ROOT / "README.md"
MANIFEST_PATH = ROOT.parent.parent / "hermes-dashboard" / "manifest.md"
SESSION_ID_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._~-]{0,126}[A-Za-z0-9])?\Z")


EXPECTED_AUDIT_SCOPE = {
    "purpose": "Freeze the reviewed Hermternal client Dashboard route, upgrade, JSON-RPC operation, and event allowlist from pinned source evidence.",
    "source_inventory_complete": False,
    "client_allowlist_complete": True,
    "future_external_proxy_allowlist": "not_frozen",
    "live_compatibility": False,
    "integration_mode": "mock_and_proof_only",
    "source_root_verification": "optional_git_checkout_or_content_only_snapshot",
    "unknown_policy": "default_deny",
}
EXPECTED_REDACTION = {
    "synthetic_only": True,
    "raw_credentials": False,
    "raw_cookies": False,
    "raw_bearer_values": False,
    "raw_websocket_tickets": False,
    "raw_pty_handles": False,
    "transcripts": False,
    "hostnames": False,
    "user_data": False,
    "log_policy": "record credential class and bounded rejection reason only; never raw ticket, bearer, PTY input, PTY output, or transcript",
}
EXPECTED_ACCESSIBILITY = {
    "status": "N/A",
    "reason": "C-01 freezes protocol and source-audit artifacts only; it adds no UI, interaction, focus order, semantics, Dynamic Type, VoiceOver, Switch Control, browser zoom, contrast, motion, transparency, or touch-target surface.",
    "preservation": "The allowlist does not remove or redefine the existing web and native accessibility obligations in the Hermternal product contracts.",
}
EXPECTED_FUTURE_PROXY_NOTE = "A reverse proxy or external gateway must receive a separate reviewed allowlist; this client contract is not proxy authorization and does not grant broader upstream access."
VALID_APPLICABILITIES = frozenset({"browser", "native"})


class ContractError(ValueError):
    """Raised when a fixture claims more than the reviewed contract proves."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _strict_equal(actual: Any, expected: Any) -> bool:
    """Compare JSON-shaped values without Python bool/int coercion."""

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


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_nonfinite_json_constant(value: str) -> Any:
    raise ContractError(f"non-finite JSON number is not allowed: {value}")


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as stream:
            value = json.load(
                stream,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonfinite_json_constant,
            )
    except (ContractError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"{path}: invalid JSON input: {exc}") from None
    _require(isinstance(value, dict), f"{path}: top level must be an object")
    return value


def _validate_json_tree(value: Any, context: str = "document") -> None:
    """Reject non-JSON objects and non-finite floats before schema checks."""

    if type(value) is dict:
        for key, child in value.items():
            _require(type(key) is str, f"{context}: object key must be string")
            _validate_json_tree(child, f"{context}.{key}")
        return
    if type(value) is list:
        for index, child in enumerate(value):
            _validate_json_tree(child, f"{context}[{index}]")
        return
    if type(value) is float:
        _require(math.isfinite(value), f"{context}: non-finite number is not allowed")
        return
    _require(value is None or type(value) in (str, bool, int), f"{context}: unsupported JSON value type")


def _keyset(value: dict[str, Any], expected: set[str], context: str) -> None:
    _require(type(value) is dict, f"{context}: expected object")
    _require(set(value) == expected, f"{context}: schema keys changed")


def _string(value: Any, context: str) -> str:
    _require(type(value) is str, f"{context}: expected string")
    return value


def _bool(value: Any, context: str) -> bool:
    _require(type(value) is bool, f"{context}: expected boolean")
    return value


def _int(value: Any, context: str) -> int:
    _require(type(value) is int, f"{context}: expected integer")
    return value


def _nonnegative_int(value: Any, context: str) -> int:
    result = _int(value, context)
    _require(result >= 0, f"{context}: expected non-negative integer")
    return result


def _sha(value: Any, context: str) -> str:
    result = _string(value, context)
    _require(re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", result) is not None, f"{context}: invalid digest")
    return result


EXPECTED_PUBLIC_API_PATHS = [
    "/api/health",
    "/api/status",
    "/api/config/defaults",
    "/api/config/schema",
    "/api/model/info",
    "/api/dashboard/themes",
    "/api/dashboard/plugins",
    "/api/cron/fire",
]
EXPECTED_GATE_PUBLIC_PREFIXES = [
    "/auth/login",
    "/auth/callback",
    "/auth/native/authorize",
    "/auth/native/token",
    "/auth/native/refresh",
    "/auth/password-login",
    "/auth/logout",
    "/login",
    "/api/auth/providers",
    "/api/mcp/oauth/callback/",
    "/assets/",
    "/favicon.ico",
    "/ds-assets/",
    "/fonts/",
    "/fonts-terminal/",
]


def _rest(method: str, path: str, auth: str, applicability: list[str], citation: str) -> dict[str, Any]:
    return {
        "method": method,
        "path": path,
        "auth_mode": auth,
        "applicability": applicability,
        "source_citation_id": citation,
    }


EXPECTED_CLIENT_REST = [
    _rest("GET", "/login", "public", ["browser"], "rest-auth-routes"),
    _rest("GET", "/api/auth/providers", "public", ["browser", "native"], "rest-auth-routes"),
    _rest("GET", "/auth/login", "public", ["browser"], "rest-auth-routes"),
    _rest("GET", "/auth/callback", "public", ["browser"], "rest-auth-routes"),
    _rest("POST", "/auth/password-login", "public", ["browser", "native"], "rest-auth-routes"),
    _rest("POST", "/auth/logout", "browser_cookie_or_native_cookie", ["browser", "native"], "rest-auth-routes"),
    _rest("GET", "/api/auth/me", "browser_cookie_or_native_bearer", ["browser", "native"], "rest-auth-routes"),
    _rest("POST", "/api/auth/ws-ticket", "browser_cookie_or_native_bearer", ["browser", "native"], "rest-auth-routes"),
    _rest("GET", "/auth/native/authorize", "public_native_authorize", ["native"], "rest-auth-routes"),
    _rest("POST", "/auth/native/token", "public_native_loopback_code_pkce", ["native"], "rest-auth-routes"),
    _rest("POST", "/auth/native/refresh", "public_native_refresh_material", ["native"], "rest-auth-routes"),
    _rest("GET", "/api/sessions", "browser_cookie_or_native_bearer", ["browser", "native"], "rest-session-routes"),
    _rest("GET", "/api/sessions/search", "browser_cookie_or_native_bearer", ["browser", "native"], "rest-session-routes"),
    _rest("GET", "/api/sessions/{session_id}", "browser_cookie_or_native_bearer", ["browser", "native"], "rest-session-routes"),
    _rest("GET", "/api/sessions/{session_id}/messages", "browser_cookie_or_native_bearer", ["browser", "native"], "rest-session-routes"),
    _rest("PATCH", "/api/sessions/{session_id}", "browser_cookie_or_native_bearer", ["browser", "native"], "rest-session-routes"),
    _rest("POST", "/api/chat/image-upload", "browser_cookie_or_native_bearer", ["browser", "native"], "rest-image-upload"),
]

EXPECTED_CLIENT_WS = [
    {
        "path": "/api/ws",
        "surface": "structured_chat",
        "auth_mode": "gated_ticket_or_non_gated_local_query_token",
        "gated_auth": "fresh_single_use_ticket",
        "non_gated_local_auth": "source_defined_query_token",
        "applicability": ["browser", "native"],
        "source_citation_id": "chat-websocket",
    },
    {
        "path": "/api/pty",
        "surface": "full_hermes_tui",
        "auth_mode": "gated_ticket_or_non_gated_local_query_token",
        "gated_auth": "fresh_single_use_ticket",
        "non_gated_local_auth": "source_defined_query_token",
        "applicability": ["browser"],
        "host_requirement": "attested_posix_or_wsl",
        "native_policy": "not_applicable_and_blocked",
        "source_citation_id": "pty-websocket",
    },
]

EXPECTED_RPC_OPERATIONS = [
    {"name": "session.create", "group": "session", "source_citation_id": "rpc-session-methods"},
    {"name": "session.resume", "group": "session", "source_citation_id": "rpc-session-methods"},
    {"name": "session.list", "group": "session", "source_citation_id": "rpc-session-methods"},
    {"name": "session.active_list", "group": "session", "source_citation_id": "rpc-session-methods"},
    {"name": "session.most_recent", "group": "session", "source_citation_id": "rpc-session-methods"},
    {"name": "session.history", "group": "session", "source_citation_id": "rpc-session-methods"},
    {"name": "session.status", "group": "session", "source_citation_id": "rpc-session-methods"},
    {"name": "session.close", "group": "session", "source_citation_id": "rpc-session-methods"},
    {"name": "session.interrupt", "group": "control", "source_citation_id": "rpc-session-methods"},
    {"name": "prompt.submit", "group": "prompt", "source_citation_id": "rpc-prompt-methods"},
    {"name": "approval.respond", "group": "human_input", "source_citation_id": "rpc-prompt-methods"},
    {"name": "clarify.respond", "group": "human_input", "source_citation_id": "rpc-prompt-methods"},
    {"name": "model.options", "group": "model", "source_citation_id": "rpc-model-options"},
    {"name": "config.set", "group": "model", "key_policy": "model_only", "source_citation_id": "rpc-config-set"},
]
EXPECTED_RPC_EVENTS = [
    {"name": "gateway.ready", "class": "connection", "source_citation_id": "chat-events"},
    {"name": "session.info", "class": "session", "source_citation_id": "chat-events"},
    {"name": "message.delta", "class": "streaming_noninteractive", "source_citation_id": "chat-events"},
    {"name": "reasoning.delta", "class": "streaming_noninteractive", "source_citation_id": "chat-events"},
    {"name": "thinking.delta", "class": "streaming_noninteractive", "source_citation_id": "chat-events"},
    {"name": "message.complete", "class": "message", "source_citation_id": "chat-events"},
    {"name": "tool.start", "class": "tool_noninteractive", "source_citation_id": "chat-events"},
    {"name": "tool.complete", "class": "tool_noninteractive", "source_citation_id": "chat-events"},
    {"name": "approval.request", "class": "interactive_approval", "source_citation_id": "chat-events"},
    {"name": "clarify.request", "class": "interactive_clarification", "source_citation_id": "chat-events"},
    {"name": "error", "class": "terminal_error", "source_citation_id": "chat-events"},
]
EXPECTED_SOURCE_REST = [
    {"method": "GET", "path": "/login", "status": "source_present_reviewed_client_allowlisted", "source_citation_id": "rest-auth-routes"},
    {"method": "GET", "path": "/api/auth/providers", "status": "source_present_reviewed_client_allowlisted", "source_citation_id": "rest-auth-routes"},
    {"method": "GET", "path": "/auth/login", "status": "source_present_reviewed_client_allowlisted", "source_citation_id": "rest-auth-routes"},
    {"method": "GET", "path": "/auth/callback", "status": "source_present_reviewed_client_allowlisted", "source_citation_id": "rest-auth-routes"},
    {"method": "POST", "path": "/auth/password-login", "status": "source_present_reviewed_client_allowlisted", "source_citation_id": "rest-auth-routes"},
    {"method": "POST", "path": "/auth/logout", "status": "source_present_reviewed_client_allowlisted", "source_citation_id": "rest-auth-routes"},
    {"method": "GET", "path": "/api/auth/me", "status": "source_present_reviewed_client_allowlisted", "source_citation_id": "rest-auth-routes"},
    {"method": "POST", "path": "/api/auth/ws-ticket", "status": "source_present_reviewed_client_allowlisted", "source_citation_id": "rest-auth-routes"},
    {"method": "GET", "path": "/auth/native/authorize", "status": "source_present_reviewed_client_allowlisted", "source_citation_id": "rest-auth-routes"},
    {"method": "POST", "path": "/auth/native/token", "status": "source_present_reviewed_client_allowlisted", "source_citation_id": "rest-auth-routes"},
    {"method": "POST", "path": "/auth/native/refresh", "status": "source_present_reviewed_client_allowlisted", "source_citation_id": "rest-auth-routes"},
    {"method": "GET", "path": "/api/sessions", "status": "source_present_reviewed_client_allowlisted", "source_citation_id": "rest-session-routes"},
    {"method": "GET", "path": "/api/sessions/search", "status": "source_present_reviewed_client_allowlisted", "source_citation_id": "rest-session-routes"},
    {"method": "GET", "path": "/api/sessions/{session_id}", "status": "source_present_reviewed_client_allowlisted", "source_citation_id": "rest-session-routes"},
    {"method": "GET", "path": "/api/sessions/{session_id}/messages", "status": "source_present_reviewed_client_allowlisted", "source_citation_id": "rest-session-routes"},
    {"method": "PATCH", "path": "/api/sessions/{session_id}", "status": "source_present_reviewed_client_allowlisted", "source_citation_id": "rest-session-routes"},
    {"method": "POST", "path": "/api/chat/image-upload", "status": "source_present_reviewed_client_allowlisted", "source_citation_id": "rest-image-upload"},
    {"method": "GET", "path": "/api/model/options", "status": "source_present_not_client_allowlisted", "source_citation_id": "rest-model-options"},
    {"method": "GET", "path": "/api/config/defaults", "status": "source_present_public_but_client_blocked", "source_citation_id": "source-public-paths"},
    {"method": "GET", "path": "/api/config/schema", "status": "source_present_public_but_client_blocked", "source_citation_id": "source-public-paths"},
    {"method": "GET", "path": "/api/dashboard/plugins", "status": "source_present_public_but_client_blocked", "source_citation_id": "source-public-paths"},
    {"method": "POST", "path": "/api/gateway/restart", "status": "source_present_management_blocked", "source_citation_id": "blocked-management-routes"},
    {"method": "GET", "path": "/api/files", "status": "source_present_filesystem_blocked", "source_citation_id": "blocked-management-routes"},
    {"method": "GET", "path": "/api/ssh/ownership", "status": "source_present_ssh_blocked", "source_citation_id": "blocked-management-routes"},
]
EXPECTED_SOURCE_UPGRADES = [
    {"path": "/api/ws", "transport": "websocket", "status": "source_present_reviewed_client_allowlisted", "source_citation_id": "chat-websocket"},
    {"path": "/api/pty", "transport": "websocket", "status": "source_present_reviewed_web_only", "source_citation_id": "pty-websocket"},
    {"path": "/api/pub", "transport": "websocket", "status": "source_present_not_client_allowlisted", "source_citation_id": "source-sidecar-surfaces"},
    {"path": "/api/events", "transport": "websocket", "status": "source_present_not_client_allowlisted", "source_citation_id": "source-sidecar-surfaces"},
    {"path": "/api/console", "transport": "websocket", "status": "source_present_not_client_allowlisted", "source_citation_id": "rest-auth-routes"},
]
EXPECTED_SOURCE_OPERATIONS = [
    "session.create", "session.resume", "session.list", "session.active_list",
    "session.most_recent", "session.history", "session.status", "session.close",
    "session.interrupt", "prompt.submit", "approval.respond", "clarify.respond",
    "model.options", "config.set", "session.delete", "session.activate", "session.title",
    "message.react", "llm.oneshot", "model.save_key", "model.disconnect", "complete.path",
    "complete.slash", "sudo.respond", "secret.respond", "terminal.read.respond", "file.attach",
]
EXPECTED_SOURCE_EVENTS = [
    "gateway.ready", "session.info", "message.delta", "reasoning.delta", "thinking.delta",
    "message.complete", "tool.start", "tool.complete", "approval.request", "clarify.request", "error",
]

EXPECTED_CITATION_FILES = {
    "rest-auth-routes": ("hermes_cli/dashboard_auth/routes.py", [132, 894], "d42be557b9b1ba798c038c91246cba0bf046e89ebe34a27db0c7803c517e9c20", "0c142963bcc83f38fddbdcec29c35608f14f7bc1"),
    "rest-session-routes": ("hermes_cli/web_routers/sessions.py", [50, 662], "f8debdab79430829245352ebdb7f50603c3a42c11d4609eb3287c35b9a2bf0ba", "c692d7b21e1ace3d5a9828c67caf2ee4aa561c4d"),
    "rest-image-upload": ("hermes_cli/web_server.py", [2306, 2306], "b52cc35523f891b6947fa59ac70516d955e47714877069e5ed3f06544b793c1a", "1fb3e6131629e7399ef12de78148ac6e7ec58d34"),
    "rest-model-options": ("hermes_cli/web_server.py", [6238, 6280], "b52cc35523f891b6947fa59ac70516d955e47714877069e5ed3f06544b793c1a", "1fb3e6131629e7399ef12de78148ac6e7ec58d34"),
    "source-public-paths": ("hermes_cli/dashboard_auth/public_paths.py", [33, 60], "18dad29df79d0ee6111926249d859704b2afc61ffa974ae4589d3667c7fa02ce", "befedb1070a2bb193ffa292b8a87340aa8686f9b"),
    "source-public-prefixes": ("hermes_cli/dashboard_auth/middleware.py", [49, 85], "a7ed66ee8334458a53029ee2ca8ad59682ac830b1e65c881cde486752d212d4e", "5b11e98cf2b161a6b98f3d27fa68e83e89883295"),
    "native-bearer": ("hermes_cli/dashboard_auth/middleware.py", [346, 373], "a7ed66ee8334458a53029ee2ca8ad59682ac830b1e65c881cde486752d212d4e", "5b11e98cf2b161a6b98f3d27fa68e83e89883295"),
    "ticket-lifecycle": ("hermes_cli/dashboard_auth/ws_tickets.py", [42, 99], "b66e29a067002ad8a345b49281d30c75d6ec2bb177d58214611db66925bb4429", "118a988e142adf3a904d2a553698b38da22f34fc"),
    "websocket-auth": ("hermes_cli/web_server.py", [14634, 14725], "b52cc35523f891b6947fa59ac70516d955e47714877069e5ed3f06544b793c1a", "1fb3e6131629e7399ef12de78148ac6e7ec58d34"),
    "chat-websocket": ("hermes_cli/web_server.py", [15811, 15827], "b52cc35523f891b6947fa59ac70516d955e47714877069e5ed3f06544b793c1a", "1fb3e6131629e7399ef12de78148ac6e7ec58d34"),
    "pty-websocket": ("hermes_cli/web_server.py", [14401, 15797], "b52cc35523f891b6947fa59ac70516d955e47714877069e5ed3f06544b793c1a", "1fb3e6131629e7399ef12de78148ac6e7ec58d34"),
    "source-sidecar-surfaces": ("hermes_cli/web_server.py", [15831, 15900], "b52cc35523f891b6947fa59ac70516d955e47714877069e5ed3f06544b793c1a", "1fb3e6131629e7399ef12de78148ac6e7ec58d34"),
    "blocked-management-routes": ("hermes_cli/web_server.py", [2029, 4000], "b52cc35523f891b6947fa59ac70516d955e47714877069e5ed3f06544b793c1a", "1fb3e6131629e7399ef12de78148ac6e7ec58d34"),
    "pty-resize": ("hermes_cli/pty_bridge.py", [58, 60], "e24515762a8ee3c9089369b7ecba20307af62c7cfb6d02abf04261ecacaa6095", "cf4a4e60a75eab4490fa718db8651c079c5ff828"),
    "pty-lifecycle": ("hermes_cli/pty_session.py", [15, 179], "617448d953ec978f1b3287b02ac0dd2ad61c255d3366e0ca45efdf829146d8c5", "43910be9deb4655c6eb2dbad62b0b4aa1d81c0fa"),
    "chat-transport": ("tui_gateway/ws.py", [10, 404], "2b1c772cb37c77a756325e4c298f6a5ee8947d6566cd7638f06f7a0421b8b5fd", "073c4ac1497c7a266209169176ebfff673ecbbcb"),
    "rpc-session-methods": ("tui_gateway/methods_session.py", [14, 2750], "1e70561f7c5ca08556e26216f9f6a553bbf25e4c8de3368ac9cb9634e57ea34e", "1a3e09f16e49c5c75a42ca94e4fbfd8f36c290f0"),
    "rpc-prompt-methods": ("tui_gateway/methods_prompt.py", [67, 907], "96363dbf53a484f6445750c99a40e0624a9e43966be8fb29d8e47883a3ec5f51", "7e3157544e0d4dce2c94193c38a0951af30a12c9"),
    "rpc-model-options": ("tui_gateway/methods_complete.py", [327, 327], "87ef05379c694cf7b6995095eb7acd5a4111eb275eb4c77b6e040da41033a8cf", "701c11f0eaed4d09b045c7046db3aa8443332db4"),
    "rpc-config-set": ("tui_gateway/server.py", [10468, 10473], "e4bd9009827ffd224cc85c8b17ad7baba0f560d643d688e265be5a06fe8ba29c", "9d5fd00ce7d0becfd4581a5a3867c516a6d3b20a"),
    "model-options-builder": ("hermes_cli/inventory.py", [276, 313], "5c48dfb6ae1973c00eb5b50c6f92381e49b3f2fc66983dd958cda913f81800e0", "4e95665d481f881be9885edd4997925d0cec78d6"),
    "chat-events": ("tui_gateway/server.py", [1726, 5604], "e4bd9009827ffd224cc85c8b17ad7baba0f560d643d688e265be5a06fe8ba29c", "9d5fd00ce7d0becfd4581a5a3867c516a6d3b20a"),
}

EXPECTED_CITATION_SEMANTICS: dict[str, tuple[tuple[str, ...], str]] = {
    "rest-auth-routes": (
        (
            '@router.get("/login"', '@router.get("/api/auth/providers"',
            '@router.get("/auth/login"', '@router.get("/auth/native/authorize"',
            '@router.get("/auth/callback"', '@router.post("/auth/password-login"',
            '@router.post("/auth/logout"', '@router.get("/api/auth/me"',
            '@router.post("/api/auth/ws-ticket"', '@router.post("/auth/native/token"',
            '@router.post("/auth/native/refresh"', "/api/console",
        ),
        "The selected authentication and identity REST route decorators are present; the ticket doc names additional source-sidecar upgrade paths that are not client allowlisted.",
    ),
    "rest-session-routes": (
        (
            '@list_router.get("/api/sessions")', '@search_router.get("/api/sessions/search")',
            '@manage_router.get("/api/sessions/{session_id}")',
            '@manage_router.get("/api/sessions/{session_id}/messages")',
            '@manage_router.patch("/api/sessions/{session_id}")',
        ),
        "The five selected session REST method/path pairs are present; neighboring source routes such as delete and latest-descendant remain outside the client allowlist.",
    ),
    "rest-image-upload": (
        ('@app.post("/api/chat/image-upload")',),
        "The selected image-only upload route is present. Arbitrary file, filesystem, and media routes are not granted by this evidence.",
    ),
    "rest-model-options": (
        ('@app.get("/api/model/options")', 'REST equivalent of the ``model.options`` JSON-RPC'),
        "A source-present REST equivalent exists, but the focused client fixture freezes the JSON-RPC operation and does not add this REST transport to the Hermternal allowlist.",
    ),
    "source-public-paths": (
        (
            "PUBLIC_API_PATHS", '"/api/health"', '"/api/status"', '"/api/config/defaults"',
            '"/api/config/schema"', '"/api/model/info"', '"/api/dashboard/themes"',
            '"/api/dashboard/plugins"', '"/api/cron/fire"',
        ),
        "The pinned source's exact public API bypass inventory is recorded as source evidence; public does not mean client-approved.",
    ),
    "source-public-prefixes": (
        ('_GATE_PUBLIC_PREFIXES', '"/api/mcp/oauth/callback/"', '"/assets/"', 'path == prefix or path.startswith(prefix)'),
        "Source public-prefix matching uses exact equality or source prefix semantics; client route matching remains exact and default-deny.",
    ),
    "native-bearer": (
        ('Authorization: Bearer <access_token>', 'if bearer:', 'return _unauth_response(request, reason="invalid_or_expired_session")'),
        "Reviewed native bearer requests use the provider stack; a presented invalid bearer is rejected without cookie fallback.",
    ),
    "ticket-lifecycle": (
        ('TTL_SECONDS = 30', 'entry = _tickets.pop(ticket, None)', 'truncated = (ticket[:8] + "…") if ticket else "<empty>"', 'raise TicketInvalid("expired")'),
        "Gated WebSocket tickets are 30-second, single-use values and invalid-ticket diagnostics retain only a bounded fragment.",
    ),
    "websocket-auth": (
        ('def _ws_auth_mode()', '?ticket=<single-use>', '?internal=<process-credential>', 'The legacy ``?token=`` path is unconditionally rejected in gated mode', 'audit_log(', 'path=ws.url.path'),
        "Gated upgrades accept a fresh ticket or server-internal credential; the legacy query token is only for non-gated local mode, and audit logging identifies credential type without recording the raw ticket.",
    ),
    "chat-websocket": (
        ('@app.websocket("/api/ws")', 'await handle_ws(ws)'),
        "The selected structured chat upgrade is the Dashboard /api/ws WebSocket.",
    ),
    "pty-websocket": (
        ('_RESIZE_RE = re.compile(rb"\\x1b\\[RESIZE:(\\d+);(\\d+)\\]")', 'ttl=30 * 60', 'buffer_cap=1 * 1024 * 1024', '@app.websocket("/api/pty")', 'attach_token = ws.query_params.get("attach") or None', 'PTY_REGISTRY.detach(attach_token, ws)'),
        "The full PTY upgrade is web-only, source-defined as an attachable POSIX/WSL surface with bounded replay and detach behavior; native clients do not use it in v0.0.1.",
    ),
    "source-sidecar-surfaces": (
        ('/api/pub', '/api/events', '@app.websocket("/api/pub")', '@app.websocket("/api/events")'),
        "Source-sidecar pub/events channels exist for the embedded TUI but are outside the direct Hermternal client route allowlist.",
    ),
    "blocked-management-routes": (
        ('@app.get("/api/media")', '@app.get("/api/files")', '@app.get("/api/ssh/ownership")', '@app.post("/api/gateway/restart")', '@app.post("/api/gateway/drain")'),
        "Source-present filesystem, SSH, media, and gateway-management routes are blocked from the Hermternal client allowlist; conditional drain behavior remains covered by the native-bearer audit instead.",
    ),
    "pty-resize": (
        ('_MIN_DIMENSION = 1', '_MAX_COLS = 2000', '_MAX_ROWS = 1000'),
        "The source bounds PTY dimensions to 1-2000 columns and 1-1000 rows.",
    ),
    "pty-lifecycle": (
        ('WS_CLOSE_PROCESS_EXITED = 4410', 'WS_CLOSE_SUPERSEDED = 4409', 'await ws.send_bytes(snap)', 'if self._ws is not ws:', '(now - s.last_detached_at) > self._ttl'),
        "The source retains bounded output, supersedes stale sockets with 4409, preserves a valid attach session, and reaps detached sessions after the TTL.",
    ),
    "chat-transport": (
        ('newline-delimited JSON-RPC', '@app.websocket("/api/ws")', '"message.delta"', '"reasoning.delta"', '"thinking.delta"', 'gateway.ready', '"parse error"', '"internal error"'),
        "The selected chat transport uses JSON-RPC over /api/ws and exposes the ready, streaming, and parse/dispatch error observations frozen by the client contract.",
    ),
    "rpc-session-methods": (
        ('@method("session.create")', '@method("session.list")', '@method("session.most_recent")', '@method("session.resume")', '@method("session.active_list")', '@method("session.status")', '@method("session.history")', '@method("session.close")', '@method("session.interrupt")'),
        "The selected session and interrupt JSON-RPC decorators are present; adjacent session-management methods are not client-approved.",
    ),
    "rpc-prompt-methods": (
        ('@method("prompt.submit")', '@method("clarify.respond")', '@method("approval.respond")', '@method("sudo.respond")', '@method("secret.respond")'),
        "Prompt submission and approval/clarification responses are selected; terminal-read, sudo, secret, and other adjacent operations are not approved.",
    ),
    "rpc-model-options": (
        ('@method("model.options")',),
        "The pinned gateway registers model.options; the fixture uses this JSON-RPC operation rather than inventing a REST dependency.",
    ),
    "rpc-config-set": (
        ('@method("config.set")', 'if key == "model":'),
        "config.set is selected only with the source-defined model key; other configuration keys are blocked.",
    ),
    "model-options-builder": (
        ('"providers": rows', '"model": ctx.current_model', '"provider": ctx.current_provider', 'def build_model_options_payload('),
        "The shared model-options builder supplies the source-defined providers/model/provider result shape.",
    ),
    "chat-events": (
        ('"session.info"', '"approval.request"', '"clarify.request"', '"error"', '"tool.start"', '"tool.complete"', '"message.complete"'),
        "The selected session, tool, approval, clarification, completion, and error event emissions are present.",
    ),
}


def _validate_source_citations(audit: dict[str, Any]) -> None:
    citations = audit["source_citations"]
    _require(isinstance(citations, list), "audit: source_citations must be a list")
    _require(len(citations) == len(EXPECTED_CITATION_FILES), "audit: citation count changed")
    ids = [citation.get("id") for citation in citations]
    _require(len(ids) == len(set(ids)), "audit: citation ids must be unique")
    _require(set(ids) == set(EXPECTED_CITATION_FILES), "audit: citation inventory changed")
    for citation in citations:
        context = f"audit citation {citation.get('id')!r}"
        _keyset(citation, {"id", "path", "lines", "markers", "sha256", "git_blob_sha", "url", "claim"}, context)
        citation_id = _string(citation["id"], f"{context}.id")
        expected_path, expected_lines, expected_sha, expected_blob = EXPECTED_CITATION_FILES[citation_id]
        expected_markers, expected_claim = EXPECTED_CITATION_SEMANTICS[citation_id]
        _require(type(citation["path"]) is str and citation["path"] == expected_path, f"{context}: path changed")
        _require(_strict_equal(citation["lines"], expected_lines), f"{context}: line range changed")
        _require(type(citation["sha256"]) is str and citation["sha256"] == expected_sha, f"{context}: source digest changed")
        _require(type(citation["git_blob_sha"]) is str and citation["git_blob_sha"] == expected_blob, f"{context}: Git blob changed")
        _require(type(citation["url"]) is str and citation["url"] == f"{REPOSITORY_URL}/blob/{PINNED_SHA}/{expected_path}", f"{context}: pinned URL changed")
        _require(_strict_equal(citation["markers"], list(expected_markers)), f"{context}: markers changed")
        _require(type(citation["claim"]) is str and citation["claim"] == expected_claim, f"{context}: claim changed")
        parsed = urlsplit(citation["url"])
        _require(parsed.scheme == "https" and parsed.netloc == "github.com", f"{context}: untrusted source URL")
        _require(not parsed.query and not parsed.fragment, f"{context}: source URL has query or fragment")
    # Multiple claims can cite different line ranges in one pinned source file;
    # uniqueness belongs to citation IDs, not URLs.


def validate_audit(audit: dict[str, Any]) -> None:
    _keyset(audit, {"schema", "contract", "audit_id", "hermes_repository", "hermes_repository_url", "hermes_source_sha", "hermes_tree_sha", "audit_scope", "source_citations", "blocked_examples", "redaction", "accessibility", "baseline"}, "audit")
    _require(audit["schema"] == "hermternal.source-audit.route-allowlist.v1", "audit: schema changed")
    _require(audit["contract"] == "dashboard-v0.0.1", "audit: contract changed")
    _require(audit["audit_id"] == AUDIT_ID, "audit: audit id changed")
    _require(audit["hermes_repository"] == REPOSITORY, "audit: repository changed")
    _require(audit["hermes_repository_url"] == REPOSITORY_URL, "audit: repository URL changed")
    _require(audit["hermes_source_sha"] == PINNED_SHA, "audit: source SHA changed")
    _require(audit["hermes_tree_sha"] == PINNED_TREE_SHA, "audit: tree SHA changed")
    _keyset(audit["audit_scope"], set(EXPECTED_AUDIT_SCOPE), "audit scope")
    _require(_strict_equal(audit["audit_scope"], EXPECTED_AUDIT_SCOPE), "audit: scope semantics changed")
    _validate_source_citations(audit)
    _keyset(audit["blocked_examples"], {"rest_management", "json_rpc_sensitive", "reason"}, "blocked examples")
    _require(_strict_equal(audit["blocked_examples"]["rest_management"], ["GET /api/config/defaults", "GET /api/config/schema", "GET /api/dashboard/plugins", "POST /api/gateway/restart", "GET /api/files", "GET /api/ssh/ownership"]), "audit: blocked REST examples changed")
    _require(_strict_equal(audit["blocked_examples"]["json_rpc_sensitive"], ["session.delete", "session.activate", "session.title", "message.react", "llm.oneshot", "model.save_key", "model.disconnect", "complete.path", "complete.slash", "sudo.respond", "secret.respond", "terminal.read.respond", "file.attach"]), "audit: blocked JSON-RPC examples changed")
    _keyset(audit["redaction"], set(EXPECTED_REDACTION), "redaction")
    _require(_strict_equal(audit["redaction"], EXPECTED_REDACTION), "redaction: semantics changed")
    _keyset(audit["accessibility"], set(EXPECTED_ACCESSIBILITY), "accessibility")
    _require(_strict_equal(audit["accessibility"], EXPECTED_ACCESSIBILITY), "accessibility: semantics changed")
    _validate_baseline(audit["baseline"])


def _finite_nonnegative_number(value: Any, context: str) -> int | float:
    _require(type(value) in (int, float) and not isinstance(value, bool), f"{context}: expected numeric value")
    try:
        finite = math.isfinite(value)
    except (OverflowError, TypeError):
        finite = False
    _require(finite, f"{context}: expected finite value")
    _require(value >= 0, f"{context}: expected non-negative value")
    return value


def _validate_baseline(baseline: dict[str, Any]) -> None:
    _keyset(baseline, {"raw_command", "validator", "build_mode", "source_verified", "repetitions", "distribution_ms", "artifact_size_bytes", "environment", "threshold"}, "baseline")
    _require(_string(baseline["raw_command"], "baseline.raw_command") == "python3 contracts/fixtures/route-allowlist/test_route_allowlist.py", "baseline: raw command changed")
    _require(_string(baseline["validator"], "baseline.validator") == "Python standard library only", "baseline: validator changed")
    _require(_string(baseline["build_mode"], "baseline.build_mode").startswith("N/A"), "baseline: build mode must be N/A")
    _require(_bool(baseline["source_verified"], "baseline.source_verified") is False, "baseline: source verification must be explicit")
    repetitions = _int(baseline["repetitions"], "baseline.repetitions")
    _require(repetitions == BASELINE_REPETITIONS, f"baseline: repetitions must equal {BASELINE_REPETITIONS}")
    _keyset(baseline["distribution_ms"], {"min", "median", "p95", "max", "mean"}, "baseline distribution")
    distribution = {
        key: _finite_nonnegative_number(baseline["distribution_ms"][key], f"baseline.distribution_ms.{key}")
        for key in ("min", "median", "p95", "max", "mean")
    }
    _require(distribution["min"] <= distribution["median"] <= distribution["p95"] <= distribution["max"], "baseline: quantile ordering is incoherent")
    _require(distribution["min"] <= distribution["mean"] <= distribution["max"], "baseline: mean is outside observed range")
    _nonnegative_int(baseline["artifact_size_bytes"], "baseline.artifact_size_bytes")
    _keyset(baseline["environment"], {"python", "implementation", "platform", "machine"}, "baseline environment")
    for key, value in baseline["environment"].items():
        _require(type(value) is str and value and value != "pending", f"baseline environment {key}: missing observed value")
    _require(baseline["threshold"] is None, "baseline: no invented threshold is allowed")


def validate_allowlist(allowlist: dict[str, Any], audit: dict[str, Any]) -> None:
    _keyset(allowlist, {"schema", "contract", "hermes_source_sha", "source_audit_id", "policy", "source_present", "client_allowlist", "future_external_proxy_allowlist"}, "allowlist")
    _require(allowlist["schema"] == "hermternal.dashboard.route-allowlist.v1", "allowlist: schema changed")
    _require(allowlist["contract"] == "dashboard-v0.0.1", "allowlist: contract changed")
    _require(allowlist["hermes_source_sha"] == PINNED_SHA, "allowlist: source SHA changed")
    _require(allowlist["source_audit_id"] == AUDIT_ID == audit["audit_id"], "allowlist: source audit binding changed")
    _keyset(allowlist["policy"], {"default_route_decision", "default_operation_decision", "unknown_event_policy", "source_inventory_complete", "client_allowlist_is_conservative", "future_proxy_allowlist_separate", "live_compatibility_claim"}, "allowlist policy")
    _require(_strict_equal(allowlist["policy"], {"default_route_decision": "deny", "default_operation_decision": "deny", "unknown_event_policy": "ignore_additive_noninteractive_only", "source_inventory_complete": False, "client_allowlist_is_conservative": True, "future_proxy_allowlist_separate": True, "live_compatibility_claim": False}), "allowlist: policy changed")

    source = allowlist["source_present"]
    _keyset(source, {"inventory_status", "public_bypass_inventory_complete", "public_api_exact_paths", "gate_public_prefixes", "selected_rest_routes", "selected_upgrade_surfaces", "selected_json_rpc_operations", "selected_json_rpc_events"}, "source-present")
    _require(source["inventory_status"] == "selected_review_evidence_not_complete_upstream_inventory", "source-present: completeness claim changed")
    _require(source["public_bypass_inventory_complete"] is True, "source-present: public inventory completeness changed")
    _require(source["public_api_exact_paths"] == EXPECTED_PUBLIC_API_PATHS, "source-present: public API paths changed")
    _require(source["gate_public_prefixes"] == EXPECTED_GATE_PUBLIC_PREFIXES, "source-present: public prefixes changed")
    _require(_strict_equal(source["selected_rest_routes"], EXPECTED_SOURCE_REST), "source-present: selected REST evidence changed")
    _require(_strict_equal(source["selected_upgrade_surfaces"], EXPECTED_SOURCE_UPGRADES), "source-present: upgrade evidence changed")
    _require(source["selected_json_rpc_operations"] == EXPECTED_SOURCE_OPERATIONS, "source-present: operation evidence changed")
    _require(source["selected_json_rpc_events"] == EXPECTED_SOURCE_EVENTS, "source-present: event evidence changed")

    client = allowlist["client_allowlist"]
    _keyset(client, {"rest", "websocket_upgrades", "json_rpc", "default_deny"}, "client allowlist")
    _require(_strict_equal(client["rest"], EXPECTED_CLIENT_REST), "client allowlist: REST set widened or mutated")
    _require(_strict_equal(client["websocket_upgrades"], EXPECTED_CLIENT_WS), "client allowlist: WebSocket set widened or mutated")
    rpc = client["json_rpc"]
    _keyset(rpc, {"transport_path", "framing", "operations", "events", "error_codes", "unknown_operation", "unknown_interactive_event"}, "JSON-RPC allowlist")
    _require(rpc["transport_path"] == "/api/ws", "JSON-RPC: transport path changed")
    _require(rpc["framing"] == "one_text_json_rpc_object_per_websocket_message", "JSON-RPC: framing changed")
    _require(_strict_equal(rpc["operations"], EXPECTED_RPC_OPERATIONS), "JSON-RPC: operation set widened or mutated")
    _require(_strict_equal(rpc["events"], EXPECTED_RPC_EVENTS), "JSON-RPC: event set widened or mutated")
    _require(_strict_equal(rpc["error_codes"], {"parse_error": -32700, "dispatch_error": -32603}), "JSON-RPC: error codes changed")
    _require(rpc["unknown_operation"] == "deny_without_fallback", "JSON-RPC: unknown operation policy changed")
    _require(rpc["unknown_interactive_event"] == "never_promote_to_approval_or_clarification", "JSON-RPC: unknown event policy changed")
    _keyset(client["default_deny"], {"unknown_rest_method_or_path", "source_present_not_client_allowlisted", "unknown_json_rpc_operation", "unknown_interactive_event", "unknown_noninteractive_event"}, "default deny")
    _require(_strict_equal(client["default_deny"], {"unknown_rest_method_or_path": "deny", "source_present_not_client_allowlisted": "deny", "unknown_json_rpc_operation": "deny_without_fallback", "unknown_interactive_event": "surface_as_unsupported_and_do_not_act", "unknown_noninteractive_event": "ignore_only_when_additive_and_noninteractive"}), "default deny policy changed")

    proxy = allowlist["future_external_proxy_allowlist"]
    _keyset(proxy, {"status", "rest", "websocket_upgrades", "json_rpc_operations", "json_rpc_events", "note"}, "future proxy allowlist")
    _require(proxy["status"] == "not_frozen_future_review_required", "future proxy: status changed")
    for key in ("rest", "websocket_upgrades", "json_rpc_operations", "json_rpc_events"):
        _require(proxy[key] == [], f"future proxy: {key} must remain empty")
    _require(type(proxy["note"]) is str and proxy["note"] == EXPECTED_FUTURE_PROXY_NOTE, "future proxy: note semantics changed")


def _is_canonical_rest_path(path: Any) -> bool:
    if type(path) is not str or not path.startswith("/"):
        return False
    if any(ord(character) < 0x21 or ord(character) > 0x7E for character in path):
        return False
    if any(marker in path for marker in ("?", "#", "%", "\\")):
        return False
    segments = path.split("/")
    return segments[0] == "" and all(segment not in ("", ".", "..") for segment in segments[1:])


def _is_safe_session_id(value: Any) -> bool:
    if type(value) is not str or "ticket" in value.casefold():
        return False
    return SESSION_ID_RE.fullmatch(value) is not None


def _route_template_for_path(path: Any) -> str | None:
    """Match exact paths without decoding, stripping, or resolving segments."""

    if not _is_canonical_rest_path(path):
        return None
    if path == "/api/sessions/search":
        return path
    segments = path.split("/")
    if len(segments) == 4 and segments[:3] == ["", "api", "sessions"] and _is_safe_session_id(segments[3]):
        return "/api/sessions/{session_id}"
    if len(segments) == 5 and segments[:3] == ["", "api", "sessions"] and segments[4] == "messages" and _is_safe_session_id(segments[3]):
        return "/api/sessions/{session_id}/messages"
    return path


def _is_valid_applicability(value: Any) -> bool:
    """Require explicit browser/native context for every REST decision."""

    return type(value) is str and value in VALID_APPLICABILITIES


def route_is_allowlisted(allowlist: dict[str, Any], method: str, path: str, applicability: str) -> bool:
    """Authorize one REST method/path only with explicit platform context."""

    if type(method) is not str or not _is_valid_applicability(applicability):
        return False
    template = _route_template_for_path(path)
    if template is None:
        return False
    for route in allowlist["client_allowlist"]["rest"]:
        if route["method"] != method or template != route["path"]:
            continue
        if applicability not in route["applicability"]:
            continue
        return True
    return False


def operation_is_allowlisted(allowlist: dict[str, Any], operation: str) -> bool:
    return any(item["name"] == operation for item in allowlist["client_allowlist"]["json_rpc"]["operations"])


def _rest_policy_for_request(allowlist: dict[str, Any], method: str, path: str, applicability: str) -> dict[str, Any] | None:
    """Resolve a REST policy only when platform applicability is explicit."""

    if type(method) is not str or not _is_valid_applicability(applicability):
        return None
    template = _route_template_for_path(path)
    if template is None:
        return None
    for route in allowlist["client_allowlist"]["rest"]:
        if route["method"] == method and route["path"] == template and applicability in route["applicability"]:
            return route
    return None


def _validate_rest_case_auth(case_id: str, request: dict[str, Any], expected: dict[str, Any], allowlist: dict[str, Any]) -> None:
    _require(_is_valid_applicability(request.get("applicability")), f"{case_id}: REST applicability must be browser or native")
    mode = request["auth_mode"]
    _require(mode in {"browser_cookie", "native_bearer", "native_cookie", "public"}, f"{case_id}: REST auth mode is not a client REST mode")
    policy = _rest_policy_for_request(allowlist, request["method"], request["path"], request["applicability"])
    if policy is None:
        _require(mode != "public", f"{case_id}: unmatched REST public mode is invalid")
        _require(expected["route_class"] != "client_allowlist", f"{case_id}: expected client route has no matching policy")
        return
    _require(expected["route_class"] == "client_allowlist", f"{case_id}: matched route must be classified as client allowlist")
    policy_mode = policy["auth_mode"]
    if mode == "native_bearer":
        _require(policy_mode == "browser_cookie_or_native_bearer" and request["applicability"] == "native", f"{case_id}: native bearer is not approved for this REST pair")
    elif mode == "browser_cookie":
        _require(policy_mode in {"browser_cookie_or_native_bearer", "browser_cookie_or_native_cookie"} and request["applicability"] == "browser", f"{case_id}: browser cookie is not approved for this REST pair")
    elif mode == "native_cookie":
        _require(policy_mode == "browser_cookie_or_native_cookie" and request["applicability"] == "native", f"{case_id}: native cookie is not approved for this REST pair")
    else:
        _require(policy_mode.startswith("public"), f"{case_id}: public auth does not match the REST policy")


ALLOWED_SENSITIVE_METADATA_KEYS = frozenset({"user_data"})
FORBIDDEN_SENSITIVE_KEYS = frozenset({
    "token", "ticket", "cookie", "authorization", "bearer", "secret", "password",
    "credential", "transcript", "hostname", "user_data", "pty_handle", "raw_ticket",
    "raw_bearer", "raw_cookie", "raw_password", "raw_secret",
})
CREDENTIAL_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b", re.IGNORECASE),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]+\b", re.IGNORECASE),
    re.compile(r"\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{16,}\b", re.IGNORECASE),
    re.compile(r"\b(?:authorization|cookie|password|secret|ticket|token|bearer)\s*[:=]\s*[A-Za-z0-9._~+/=-]{8,}\b", re.IGNORECASE),
    re.compile(r"\b(?:sk-|ghp_|xoxb-|eyJ)[A-Za-z0-9_-]{8,}\b", re.IGNORECASE),
    re.compile(r"synthetic-(?:api-key|secret|ticket-value|bearer-value|cookie-value|password-value|pty-(?:input|output|handle))", re.IGNORECASE),
    re.compile(r"my-secret-value", re.IGNORECASE),
)


def _validate_redaction(value: Any, path: str = "fixture") -> None:
    """Scan all fixture values while allowing public protocol terminology."""

    if type(value) is dict:
        for key, child in value.items():
            _require(type(key) is str, f"{path}: object key must be string")
            normalized = key.casefold()
            _require(normalized in ALLOWED_SENSITIVE_METADATA_KEYS or normalized not in FORBIDDEN_SENSITIVE_KEYS, f"{path}.{key}: sensitive key is not allowed")
            _validate_redaction(child, f"{path}.{key}")
    elif type(value) is list:
        for index, child in enumerate(value):
            _validate_redaction(child, f"{path}[{index}]")
    elif type(value) is str:
        for pattern in CREDENTIAL_VALUE_PATTERNS:
            _require(pattern.search(value) is None, f"{path}: credential-like value is not allowed")
    elif type(value) is float:
        _require(math.isfinite(value), f"{path}: non-finite number is not allowed")
    else:
        _require(value is None or type(value) in (bool, int), f"{path}: unsupported fixture value type")


def _validate_text_evidence(path: Path) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ContractError(f"{path}: unable to read evidence: {exc}") from None
    _validate_redaction(text, str(path))


EXPECTED_CASE_IDS = {
    "rest-approved-native-bearer", "rest-approved-browser-cookie", "rest-invalid-bearer-no-cookie-fallback",
    "rest-method-mutation-denied", "rest-prefix-confusion-denied", "rest-source-present-not-client-allowlisted",
    "rest-management-admin-denied", "ws-chat-browser-ticket", "ws-chat-native-ticket", "ws-chat-ticket-reused-denied",
    "ws-chat-ticket-expired-denied", "ws-gated-token-fallback-denied", "ws-pty-web-only", "ws-pty-native-denied",
    "rpc-approved-prompt", "rpc-config-key-mutation-denied", "rpc-unknown-operation-denied", "rpc-sensitive-operation-denied",
    "event-unknown-additive-noninteractive", "event-unknown-interactive-not-promoted", "pty-log-redaction", "malformed-input-control",
}

CASE_SHAPES = {
    "rest-approved-native-bearer": ({"method", "path", "applicability", "auth_mode", "credential_state"}, {"decision", "route_class", "auth_result", "handler_result"}),
    "rest-approved-browser-cookie": ({"method", "path", "applicability", "auth_mode", "credential_state"}, {"decision", "route_class", "auth_result", "handler_result"}),
    "rest-invalid-bearer-no-cookie-fallback": ({"method", "path", "applicability", "auth_mode", "credential_state", "cookie_state"}, {"decision", "route_class", "auth_result", "http_status"}),
    "rest-method-mutation-denied": ({"method", "path", "applicability", "auth_mode", "credential_state"}, {"decision", "route_class", "auth_result", "http_status"}),
    "rest-prefix-confusion-denied": ({"method", "path", "applicability", "auth_mode", "credential_state"}, {"decision", "route_class", "auth_result", "http_status"}),
    "rest-source-present-not-client-allowlisted": ({"method", "path", "applicability", "auth_mode", "credential_state"}, {"decision", "route_class", "auth_result", "http_status"}),
    "rest-management-admin-denied": ({"method", "path", "applicability", "auth_mode", "credential_state"}, {"decision", "route_class", "auth_result", "http_status"}),
    "ws-chat-browser-ticket": ({"path", "applicability", "auth_mode", "credential_state", "framing"}, {"decision", "upgrade_auth", "route_class", "source_result"}),
    "ws-chat-native-ticket": ({"path", "applicability", "auth_mode", "credential_state", "framing"}, {"decision", "upgrade_auth", "route_class", "source_result"}),
    "ws-chat-ticket-reused-denied": ({"path", "applicability", "auth_mode", "credential_state"}, {"decision", "upgrade_auth", "close_code", "retry"}),
    "ws-chat-ticket-expired-denied": ({"path", "applicability", "auth_mode", "credential_state"}, {"decision", "upgrade_auth", "close_code", "retry"}),
    "ws-gated-token-fallback-denied": ({"path", "applicability", "auth_mode", "credential_state"}, {"decision", "upgrade_auth", "close_code", "retry"}),
    "ws-pty-web-only": ({"path", "applicability", "auth_mode", "credential_state", "host_class", "attach_state"}, {"decision", "route_class", "native_policy", "pty_input_policy", "pty_logging_policy"}),
    "ws-pty-native-denied": ({"path", "applicability", "auth_mode", "credential_state", "host_class"}, {"decision", "route_class", "upgrade_auth", "retry"}),
    "rpc-approved-prompt": ({"path", "applicability", "auth_mode", "credential_state", "operation"}, {"decision", "operation_class", "fallback"}),
    "rpc-config-key-mutation-denied": ({"path", "applicability", "auth_mode", "credential_state", "operation", "config_key"}, {"decision", "operation_class", "fallback", "error"}),
    "rpc-unknown-operation-denied": ({"path", "applicability", "auth_mode", "credential_state", "operation"}, {"decision", "operation_class", "fallback", "error"}),
    "rpc-sensitive-operation-denied": ({"path", "applicability", "auth_mode", "credential_state", "operation"}, {"decision", "operation_class", "fallback", "error"}),
    "event-unknown-additive-noninteractive": ({"path", "applicability", "auth_mode", "credential_state", "event_name"}, {"decision", "event_class", "fallback"}),
    "event-unknown-interactive-not-promoted": ({"path", "applicability", "auth_mode", "credential_state", "event_name"}, {"decision", "event_class", "fallback", "ui_action"}),
    "pty-log-redaction": ({"path", "applicability", "auth_mode", "credential_state", "host_class", "attach_state"}, {"decision", "close_code", "logging"}),
    "malformed-input-control": ({"encoding", "input_state"}, {"decision", "exit_status", "stderr_policy", "fallback"}),
}


def _validate_case_leaf_types(case_id: str, request: dict[str, Any], expected: dict[str, Any]) -> None:
    request_keys, expected_keys = CASE_SHAPES[case_id]
    _keyset(request, request_keys, f"{case_id}.request")
    _keyset(expected, expected_keys, f"{case_id}.expected")
    for key, value in request.items():
        _string(value, f"{case_id}.request.{key}")
    for key, value in expected.items():
        if key in {"http_status", "close_code", "exit_status"}:
            _int(value, f"{case_id}.expected.{key}")
        elif key == "logging":
            _keyset(value, {"credential_class", "path_observed", "bounded_reason_observed", "sensitive_values_recorded", "pty_bytes_recorded"}, f"{case_id}.expected.logging")
            _string(value["credential_class"], f"{case_id}.expected.logging.credential_class")
            for logging_key in ("path_observed", "bounded_reason_observed", "sensitive_values_recorded", "pty_bytes_recorded"):
                _bool(value[logging_key], f"{case_id}.expected.logging.{logging_key}")
        else:
            _string(value, f"{case_id}.expected.{key}")


def validate_cases(cases: dict[str, Any], allowlist: dict[str, Any], audit: dict[str, Any]) -> None:
    _keyset(cases, {"schema", "contract", "hermes_source_sha", "source_audit_id", "fixture_policy", "synthetic_only", "cases"}, "cases")
    _require(cases["schema"] == "hermternal.fixture.route-allowlist.cases.v1", "cases: schema changed")
    _require(cases["contract"] == "dashboard-v0.0.1", "cases: contract changed")
    _require(cases["hermes_source_sha"] == PINNED_SHA, "cases: source SHA changed")
    _require(cases["source_audit_id"] == AUDIT_ID == audit["audit_id"], "cases: source audit binding changed")
    _require(cases["fixture_policy"] == "synthetic_markers_only" and cases["synthetic_only"] is True, "cases: synthetic policy changed")
    _require(isinstance(cases["cases"], list) and len(cases["cases"]) == len(EXPECTED_CASE_IDS), "cases: case count changed")
    _require({case.get("id") for case in cases["cases"]} == EXPECTED_CASE_IDS, "cases: case inventory changed")
    _validate_redaction(cases)
    by_id: dict[str, dict[str, Any]] = {}
    for case in cases["cases"]:
        _keyset(case, {"id", "kind", "surface", "request", "expected", "notes"}, f"case {case.get('id')!r}")
        case_id = _string(case["id"], "case.id")
        _require(case_id not in by_id, f"cases: duplicate id {case_id}")
        by_id[case_id] = case
        _string(case["kind"], f"{case_id}.kind")
        _string(case["surface"], f"{case_id}.surface")
        _require(isinstance(case["request"], dict), f"{case_id}: request must be an object")
        _require(isinstance(case["expected"], dict), f"{case_id}: expected must be an object")
        _validate_case_leaf_types(case_id, case["request"], case["expected"])
        _string(case["notes"], f"{case_id}.notes")
        if case["surface"] == "rest":
            _validate_rest_case_auth(case_id, case["request"], case["expected"], allowlist)

    _require(by_id["rest-approved-native-bearer"]["request"] == {"method": "GET", "path": "/api/sessions/synthetic-session-001", "applicability": "native", "auth_mode": "native_bearer", "credential_state": "valid"}, "cases: native route fixture changed")
    _require(route_is_allowlisted(allowlist, "GET", "/api/sessions/synthetic-session-001", "native"), "cases: approved native route does not match")
    _require(route_is_allowlisted(allowlist, "GET", "/api/auth/me", "browser"), "cases: approved browser route does not match")
    _require(by_id["rest-invalid-bearer-no-cookie-fallback"]["expected"]["auth_result"] == "401_invalid_or_expired_without_cookie_fallback", "cases: bearer fallback guard changed")
    _require(not route_is_allowlisted(allowlist, "POST", "/api/auth/me", "native"), "cases: method mutation widened route")
    _require(not route_is_allowlisted(allowlist, "GET", "/api/sessions/synthetic-session-001/messages/extra", "native"), "cases: suffix widened route")
    _require(not route_is_allowlisted(allowlist, "GET", "/api/model/options", "browser"), "cases: source-only REST equivalent widened client route")
    _require(not route_is_allowlisted(allowlist, "POST", "/api/gateway/restart", "browser"), "cases: management route widened client route")

    for case_id in ("ws-chat-browser-ticket", "ws-chat-native-ticket", "ws-pty-web-only"):
        _require(by_id[case_id]["expected"]["decision"] == "allow_reviewed_upgrade", f"{case_id}: approved upgrade changed")
    _require(by_id["ws-chat-ticket-reused-denied"]["request"]["credential_state"] == "already_consumed", "cases: ticket reuse state changed")
    _require(by_id["ws-chat-ticket-expired-denied"]["request"]["credential_state"] == "expired", "cases: ticket expiry state changed")
    _require(by_id["ws-gated-token-fallback-denied"]["request"]["auth_mode"] == "gated_legacy_query_token", "cases: gated query-token state changed")
    for case_id in ("ws-chat-ticket-reused-denied", "ws-chat-ticket-expired-denied", "ws-gated-token-fallback-denied"):
        _require(by_id[case_id]["expected"]["decision"] == "deny_upgrade", f"{case_id}: ticket misuse changed")
        _require(by_id[case_id]["expected"]["close_code"] == 4401, f"{case_id}: close code changed")
    _require(by_id["ws-pty-native-denied"]["expected"]["decision"] == "deny_default", "cases: native PTY policy changed")
    _require(by_id["ws-pty-web-only"]["request"]["applicability"] == "browser", "cases: PTY applicability widened")

    approved_operations = {item["name"] for item in EXPECTED_RPC_OPERATIONS}
    _require(operation_is_allowlisted(allowlist, "prompt.submit"), "cases: approved operation missing")
    _require(by_id["rpc-config-key-mutation-denied"]["request"]["config_key"] != "model", "cases: config key mutation control changed")
    _require(by_id["rpc-unknown-operation-denied"]["request"]["operation"] not in approved_operations, "cases: unknown operation became approved")
    _require(by_id["rpc-sensitive-operation-denied"]["request"]["operation"] not in approved_operations, "cases: sensitive operation became approved")
    _require(by_id["event-unknown-additive-noninteractive"]["expected"]["decision"] == "ignore_additive_noninteractive", "cases: additive event policy changed")
    _require(by_id["event-unknown-interactive-not-promoted"]["expected"]["ui_action"] == "never_treat_as_approval_or_clarification", "cases: interactive event policy changed")

    logging_case = by_id["pty-log-redaction"]["expected"]["logging"]
    _keyset(logging_case, {"credential_class", "path_observed", "bounded_reason_observed", "sensitive_values_recorded", "pty_bytes_recorded"}, "PTY logging case")
    _require(logging_case == {"credential_class": "ticket", "path_observed": True, "bounded_reason_observed": True, "sensitive_values_recorded": False, "pty_bytes_recorded": False}, "cases: PTY logging policy changed")
    malformed = by_id["malformed-input-control"]["expected"]
    _require(malformed["decision"] == "reject_without_traceback" and malformed["exit_status"] == 2, "cases: malformed-input policy changed")


def _git_blob_sha_for_path(source_root: Path, relative_path: str) -> str:
    """Resolve one immutable blob object from the pinned checkout tree."""

    try:
        result = subprocess.run(
            ["git", "-C", str(source_root), "rev-parse", "--verify", f"HEAD:{relative_path}"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ContractError(f"source root: Git blob is missing for {relative_path}: {exc}") from None
    blob_sha = result.stdout.strip()
    _require(re.fullmatch(r"[0-9a-f]{40}", blob_sha) is not None, f"source root: invalid Git blob for {relative_path}")
    return blob_sha


def _validate_git_blob_ids(audit: dict[str, Any], source_root: Path) -> None:
    """Bind every recorded blob ID to the pinned checkout's HEAD tree."""

    for citation in audit["source_citations"]:
        actual_blob = _git_blob_sha_for_path(source_root, citation["path"])
        _require(actual_blob == citation["git_blob_sha"], f"source root: Git blob mismatch for {citation['id']}")


def _validate_source_root(audit: dict[str, Any], source_root: Path) -> str:
    mode = "content_only_snapshot"
    git_dir = source_root / ".git"
    if git_dir.exists():
        try:
            head = subprocess.run(["git", "-C", str(source_root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
            tree = subprocess.run(["git", "-C", str(source_root), "rev-parse", "HEAD^{tree}"], capture_output=True, text=True, check=True).stdout.strip()
        except (OSError, subprocess.CalledProcessError) as exc:
            raise ContractError(f"source root: unable to verify Git HEAD/tree: {exc}") from None
        _require(head == PINNED_SHA, "source root: Git HEAD is not the pinned Hermes revision")
        _require(tree == PINNED_TREE_SHA, "source root: Git tree is not the pinned Hermes tree")
        _validate_git_blob_ids(audit, source_root)
        mode = "git_checkout_verified"
    for citation in audit["source_citations"]:
        path = source_root / citation["path"]
        _require(path.is_file(), f"source root: missing {citation['path']}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        _require(digest == citation["sha256"], f"source root: digest mismatch for {citation['path']}")
        lines = path.read_text(encoding="utf-8").splitlines()
        start, end = citation["lines"]
        _require(1 <= start <= end <= len(lines), f"source root: invalid range for {citation['id']}")
        excerpt = "\n".join(lines[start - 1:end])
        expected_markers, _ = EXPECTED_CITATION_SEMANTICS[citation["id"]]
        for marker in expected_markers:
            _require(marker in excerpt, f"source root: marker missing for {citation['id']}: {marker}")
    return mode


def artifact_size_bytes() -> int:
    # Exclude source_audit.json because it stores this measurement; include the
    # reviewed fixture, validator, and nearby rationale as the artifact.
    return sum(
        path.stat().st_size
        for path in (ROOT / "README.md", ALLOWLIST_PATH, CASES_PATH, Path(__file__))
    )


def validate_all(allowlist: dict[str, Any], audit: dict[str, Any], cases: dict[str, Any], source_root: Path | None = None) -> str | None:
    _validate_json_tree(allowlist, "route_allowlist")
    _validate_json_tree(audit, "source_audit")
    _validate_json_tree(cases, "cases")
    _validate_redaction(allowlist, "route_allowlist")
    _validate_redaction(audit, "source_audit")
    _validate_redaction(cases, "cases")
    _validate_text_evidence(README_PATH)
    _validate_text_evidence(MANIFEST_PATH)
    validate_audit(audit)
    validate_allowlist(allowlist, audit)
    validate_cases(cases, allowlist, audit)
    if source_root is not None:
        return _validate_source_root(audit, source_root)
    _require(audit["baseline"]["artifact_size_bytes"] == artifact_size_bytes(), "baseline: artifact size is stale")
    return None


class RouteAllowlistTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.allowlist = load_json(ALLOWLIST_PATH)
        cls.audit = load_json(AUDIT_PATH)
        cls.cases = load_json(CASES_PATH)
        validate_all(cls.allowlist, cls.audit, cls.cases)

    def test_checked_in_fixtures_validate(self) -> None:
        validate_all(self.allowlist, self.audit, self.cases)

    def test_duplicate_json_keys_fail_closed(self) -> None:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as stream:
            stream.write('{"schema": 1, "schema": 2}')
            stream.flush()
            with self.assertRaises(ContractError):
                load_json(Path(stream.name))

    def test_schema_type_and_bool_integer_regressions(self) -> None:
        forged = copy.deepcopy(self.cases)
        forged["cases"][2]["expected"]["http_status"] = True
        with self.assertRaises(ContractError):
            validate_cases(forged, self.allowlist, self.audit)

        forged_audit = copy.deepcopy(self.audit)
        forged_audit["baseline"]["repetitions"] = True
        with self.assertRaises(ContractError):
            validate_audit(forged_audit)

        forged_allowlist = copy.deepcopy(self.allowlist)
        forged_allowlist["client_allowlist"]["json_rpc"]["operations"] = {"prompt.submit": True}
        with self.assertRaises(ContractError):
            validate_allowlist(forged_allowlist, self.audit)

        forged_allowlist = copy.deepcopy(self.allowlist)
        forged_allowlist["policy"]["source_inventory_complete"] = 0
        with self.assertRaises(ContractError):
            validate_allowlist(forged_allowlist, self.audit)

    def test_nonfinite_json_and_baseline_metrics_fail_closed(self) -> None:
        for literal in ("NaN", "Infinity", "-Infinity"):
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as stream:
                stream.write('{"value": ' + literal + "}")
                stream.flush()
                with self.assertRaises(ContractError):
                    load_json(Path(stream.name))

        for metric in ("mean", "p95"):
            for forged_value in (float("nan"), float("inf"), float("-inf")):
                forged = copy.deepcopy(self.audit)
                forged["baseline"]["distribution_ms"][metric] = forged_value
                with self.assertRaises(ContractError):
                    validate_all(self.allowlist, forged, self.cases)
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as stream:
                    json.dump(forged, stream)
                    stream.flush()
                    for optimized in (False, True):
                        command = [sys.executable]
                        if optimized:
                            command.append("-O")
                        command.extend([str(Path(__file__)), "--audit", stream.name])
                        result = subprocess.run(command, capture_output=True, text=True)
                        self.assertEqual(result.returncode, 2, (metric, forged_value, optimized, result.stderr))
                        self.assertNotIn("Traceback", result.stderr + result.stdout)

    def test_baseline_repetitions_ordering_and_numeric_types_are_frozen(self) -> None:
        forged = copy.deepcopy(self.audit)
        forged["baseline"]["repetitions"] = BASELINE_REPETITIONS - 1
        with self.assertRaises(ContractError):
            validate_audit(forged)

        for mutation in (
            {"min": -1.0},
            {"median": 0.0},
            {"p95": 0.0},
            {"max": 0.0},
            {"mean": -1.0},
            {"mean": True},
        ):
            forged = copy.deepcopy(self.audit)
            forged["baseline"]["distribution_ms"].update(mutation)
            with self.assertRaises(ContractError):
                validate_audit(forged)

    def test_rest_paths_reject_noncanonical_components_and_tickets(self) -> None:
        valid_paths = (
            "/api/sessions/a",
            "/api/sessions/Ab_-.~9",
            "/api/sessions/synthetic-session-001/messages",
        )
        for path in valid_paths:
            self.assertTrue(route_is_allowlisted(self.allowlist, "GET", path, "native"), path)

        invalid_paths = (
            "/api/sessions/foo?ticket=synthetic-ticket-value",
            "/api/sessions/foo#fragment",
            "/api/sessions/foo%2Fbar",
            "/api/sessions/foo%",
            "/api/sessions/.",
            "/api/sessions/..",
            "/api/sessions/foo\\\\bar",
            "/api/sessions/foo" + "\x00" + "bar",
            "/api/sessions/café",
            "/api/sessions/",
            "/api/sessions//foo",
            "/api/sessions/foo/",
            "/api/sessions/ticket-value",
            "/api/sessions/foo/messages?ticket=synthetic-ticket-value",
            "/api/sessions/foo/messages//",
        )
        for path in invalid_paths:
            self.assertFalse(route_is_allowlisted(self.allowlist, "GET", path, "native"), path)

    def test_route_applicability_is_mandatory_and_platform_bound(self) -> None:
        # Native-only, shared, and browser-only routes each require their
        # matching platform context; omitted or malformed context denies.
        self.assertTrue(route_is_allowlisted(self.allowlist, "GET", "/auth/native/authorize", "native"))
        self.assertFalse(route_is_allowlisted(self.allowlist, "GET", "/auth/native/authorize", "browser"))
        self.assertTrue(route_is_allowlisted(self.allowlist, "GET", "/api/auth/me", "native"))
        self.assertTrue(route_is_allowlisted(self.allowlist, "GET", "/api/auth/me", "browser"))
        self.assertTrue(route_is_allowlisted(self.allowlist, "GET", "/login", "browser"))
        self.assertFalse(route_is_allowlisted(self.allowlist, "GET", "/login", "native"))

        for invalid in (None, "", "desktop", True, 1, {}, []):
            self.assertFalse(route_is_allowlisted(self.allowlist, "GET", "/api/auth/me", invalid), invalid)
            self.assertIsNone(_rest_policy_for_request(self.allowlist, "GET", "/api/auth/me", invalid))

        with self.assertRaises(TypeError):
            route_is_allowlisted(self.allowlist, "GET", "/api/auth/me")

        forged = copy.deepcopy(self.cases)
        browser_case = next(item for item in forged["cases"] if item["id"] == "rest-approved-browser-cookie")
        for invalid in ("", {}, [], None):
            browser_case["request"]["applicability"] = invalid
            with self.assertRaises(ContractError):
                validate_cases(forged, self.allowlist, self.audit)
            browser_case["request"]["applicability"] = "browser"

    def test_route_widening_and_prefix_confusion_fail(self) -> None:
        forged = copy.deepcopy(self.allowlist)
        forged["client_allowlist"]["rest"][13]["path"] = "/api/sessions/{session_id}/"
        with self.assertRaises(ContractError):
            validate_allowlist(forged, self.audit)

        self.assertFalse(route_is_allowlisted(self.allowlist, "GET", "/api/sessions/synthetic-session-001/messages/extra", "native"))
        self.assertFalse(route_is_allowlisted(self.allowlist, "GET", "/api/sessionsleak", "native"))
        self.assertFalse(route_is_allowlisted(self.allowlist, "GET", "/api/auth/me/extra", "native"))

    def test_method_mutation_is_denied(self) -> None:
        self.assertFalse(route_is_allowlisted(self.allowlist, "POST", "/api/auth/me", "native"))
        forged = copy.deepcopy(self.allowlist)
        forged["client_allowlist"]["rest"][6]["method"] = "POST"
        with self.assertRaises(ContractError):
            validate_allowlist(forged, self.audit)

    def test_auth_fallback_and_ticket_misuse_are_denied(self) -> None:
        case = next(item for item in self.cases["cases"] if item["id"] == "rest-invalid-bearer-no-cookie-fallback")
        self.assertEqual(case["expected"]["auth_result"], "401_invalid_or_expired_without_cookie_fallback")
        forged = copy.deepcopy(self.cases)
        forged["cases"][2]["expected"]["auth_result"] = "cookie_fallback"
        with self.assertRaises(ContractError):
            validate_cases(forged, self.allowlist, self.audit)

        forged = copy.deepcopy(self.cases)
        forged["cases"][10]["request"]["credential_state"] = "fresh_single_use"
        with self.assertRaises(ContractError):
            validate_cases(forged, self.allowlist, self.audit)

    def test_rest_auth_modes_bind_to_exact_route_policy(self) -> None:
        _validate_rest_case_auth(
            "public-native-provider-discovery",
            {"method": "GET", "path": "/api/auth/providers", "applicability": "native", "auth_mode": "public"},
            {"route_class": "client_allowlist"},
            self.allowlist,
        )
        _validate_rest_case_auth(
            "native-cookie-logout",
            {"method": "POST", "path": "/auth/logout", "applicability": "native", "auth_mode": "native_cookie"},
            {"route_class": "client_allowlist"},
            self.allowlist,
        )

        for ticket_mode in ("gated_ticket", "raw_ticket"):
            forged = copy.deepcopy(self.cases)
            forged["cases"][0]["request"]["auth_mode"] = ticket_mode
            with self.assertRaises(ContractError):
                validate_cases(forged, self.allowlist, self.audit)

        forged = copy.deepcopy(self.cases)
        native_case = next(item for item in forged["cases"] if item["id"] == "rest-approved-native-bearer")
        native_case["request"]["auth_mode"] = "browser_cookie"
        with self.assertRaises(ContractError):
            validate_cases(forged, self.allowlist, self.audit)

        forged = copy.deepcopy(self.cases)
        browser_case = next(item for item in forged["cases"] if item["id"] == "rest-approved-browser-cookie")
        browser_case["request"].update({"path": "/login", "applicability": "native", "auth_mode": "native_bearer"})
        with self.assertRaises(ContractError):
            validate_cases(forged, self.allowlist, self.audit)

        forged = copy.deepcopy(self.cases)
        browser_case = next(item for item in forged["cases"] if item["id"] == "rest-approved-browser-cookie")
        browser_case["request"].update({"path": "/auth/native/authorize", "applicability": "browser", "auth_mode": "browser_cookie"})
        with self.assertRaises(ContractError):
            validate_cases(forged, self.allowlist, self.audit)

        forged = copy.deepcopy(self.cases)
        invalid_bearer = next(item for item in forged["cases"] if item["id"] == "rest-invalid-bearer-no-cookie-fallback")
        invalid_bearer["request"]["auth_mode"] = "browser_cookie"
        with self.assertRaises(ContractError):
            validate_cases(forged, self.allowlist, self.audit)

    def test_management_admin_and_sensitive_surfaces_remain_blocked(self) -> None:
        self.assertFalse(route_is_allowlisted(self.allowlist, "POST", "/api/gateway/restart", "browser"))
        self.assertFalse(operation_is_allowlisted(self.allowlist, "sudo.respond"))
        forged = copy.deepcopy(self.allowlist)
        forged["client_allowlist"]["json_rpc"]["operations"].append({"name": "session.delete", "group": "session", "source_citation_id": "rpc-session-methods"})
        with self.assertRaises(ContractError):
            validate_allowlist(forged, self.audit)

    def test_pty_logging_cannot_record_sensitive_values(self) -> None:
        forged = copy.deepcopy(self.cases)
        forged["cases"][20]["expected"]["logging"]["sensitive_values_recorded"] = True
        with self.assertRaises(ContractError):
            validate_cases(forged, self.allowlist, self.audit)

        forged = copy.deepcopy(self.cases)
        forged["cases"][20]["expected"]["logging"]["pty_bytes_recorded"] = True
        with self.assertRaises(ContractError):
            validate_cases(forged, self.allowlist, self.audit)

    def test_unknown_operation_and_event_controls_fail_closed(self) -> None:
        self.assertFalse(operation_is_allowlisted(self.allowlist, "session.export"))
        forged = copy.deepcopy(self.cases)
        forged["cases"][16]["request"]["operation"] = "prompt.submit"
        with self.assertRaises(ContractError):
            validate_cases(forged, self.allowlist, self.audit)

        self.assertEqual(next(item for item in self.cases["cases"] if item["id"] == "event-unknown-interactive-not-promoted")["expected"]["ui_action"], "never_treat_as_approval_or_clarification")

    def test_provenance_and_source_scope_are_immutable(self) -> None:
        forged = copy.deepcopy(self.audit)
        forged["hermes_source_sha"] = "0" * 40
        with self.assertRaises(ContractError):
            validate_audit(forged)

        forged = copy.deepcopy(self.audit)
        forged["source_citations"][0]["url"] = "https://evil.example/hermes-agent"
        with self.assertRaises(ContractError):
            validate_audit(forged)

        forged = copy.deepcopy(self.allowlist)
        forged["source_present"]["inventory_status"] = "complete_upstream_inventory"
        with self.assertRaises(ContractError):
            validate_allowlist(forged, self.audit)

    def test_git_checkout_blob_ids_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_root = Path(directory)
            subprocess.run(["git", "-C", str(source_root), "init", "-q"], check=True, capture_output=True, text=True)
            fixture = source_root / "fixture.txt"
            fixture.write_text("pinned fixture\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(source_root), "add", "fixture.txt"], check=True, capture_output=True, text=True)
            subprocess.run(
                [
                    "git", "-C", str(source_root),
                    "-c", "user.name=Hermternal Test", "-c", "user.email=test@example.invalid",
                    "commit", "-qm", "fixture",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            blob = _git_blob_sha_for_path(source_root, "fixture.txt")
            audit = {"source_citations": [{"id": "fixture", "path": "fixture.txt", "git_blob_sha": blob}]}
            _validate_git_blob_ids(audit, source_root)

            forged = copy.deepcopy(audit)
            forged["source_citations"][0]["git_blob_sha"] = "0" * 40
            with self.assertRaises(ContractError):
                _validate_git_blob_ids(forged, source_root)

            missing = {"source_citations": [{"id": "missing", "path": "missing.txt", "git_blob_sha": blob}]}
            with self.assertRaises(ContractError):
                _validate_git_blob_ids(missing, source_root)

    def test_redaction_policy_rejects_credential_material(self) -> None:
        forged = copy.deepcopy(self.cases)
        forged["cases"][0]["request"]["token"] = "synthetic-ticket-value"
        with self.assertRaises(ContractError):
            validate_cases(forged, self.allowlist, self.audit)

        forged = copy.deepcopy(self.cases)
        forged["cases"][0]["request"]["marker"] = "Bearer synthetic-bearer-value"
        with self.assertRaises(ContractError):
            validate_cases(forged, self.allowlist, self.audit)

    def test_provenance_redaction_and_free_text_guards_are_recursive(self) -> None:
        for value in (False, 1, float("inf"), {}, [], None, "Bearer synthetic-bearer-value"):
            forged = copy.deepcopy(self.audit)
            forged["audit_scope"]["purpose"] = value
            with self.assertRaises(ContractError):
                validate_all(self.allowlist, forged, self.cases)

        for value in ("none", False, 1, float("nan"), {}, [], None):
            forged = copy.deepcopy(self.audit)
            forged["audit_scope"]["source_root_verification"] = value
            with self.assertRaises(ContractError):
                validate_all(self.allowlist, forged, self.cases)

        forged = copy.deepcopy(self.audit)
        forged["source_citations"][0]["markers"] = ["placeholder-marker"]
        with self.assertRaises(ContractError):
            validate_all(self.allowlist, forged, self.cases)

        forged = copy.deepcopy(self.audit)
        forged["source_citations"][0]["claim"] = "secret=synthetic-secret-value"
        with self.assertRaises(ContractError):
            validate_all(self.allowlist, forged, self.cases)

        for redaction_value in (
            "record ticket: synthetic-ticket-value",
            "Bearer synthetic-bearer-value",
            "cookie=synthetic-cookie-value",
            "password=synthetic-password-value",
            "secret=synthetic-secret-value",
            "PTY input synthetic-pty-input",
            "PTY output synthetic-pty-output",
        ):
            forged = copy.deepcopy(self.audit)
            forged["redaction"]["log_policy"] = redaction_value
            with self.assertRaises(ContractError):
                validate_all(self.allowlist, forged, self.cases)

        forged = copy.deepcopy(self.allowlist)
        forged["future_external_proxy_allowlist"]["note"] = "Bearer synthetic-bearer-value"
        with self.assertRaises(ContractError):
            validate_all(forged, self.audit, self.cases)

        forged = copy.deepcopy(self.allowlist)
        forged["future_external_proxy_allowlist"]["credential"] = "synthetic-secret-value"
        with self.assertRaises(ContractError):
            validate_all(forged, self.audit, self.cases)

        forged = copy.deepcopy(self.audit)
        forged["source_citations"][0]["claim"] = "cookie=synthetic-cookie-value"
        with self.assertRaises(ContractError):
            validate_all(self.allowlist, forged, self.cases)

        forged = copy.deepcopy(self.cases)
        forged["cases"][0]["request"]["password"] = "synthetic-password-value"
        with self.assertRaises(ContractError):
            validate_all(self.allowlist, self.audit, forged)

        for evidence in (
            "ticket=synthetic-ticket-value",
            "Bearer synthetic-bearer-value",
            "cookie=synthetic-cookie-value",
            "password=synthetic-password-value",
            "secret=synthetic-secret-value",
            "PTY input synthetic-pty-input",
            "PTY output synthetic-pty-output",
        ):
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".txt") as stream:
                stream.write(evidence)
                stream.flush()
                with self.assertRaises(ContractError):
                    _validate_text_evidence(Path(stream.name))

    def test_future_proxy_allowlist_is_not_silently_filled(self) -> None:
        forged = copy.deepcopy(self.allowlist)
        forged["future_external_proxy_allowlist"]["rest"].append({"method": "GET", "path": "/api/ws"})
        with self.assertRaises(ContractError):
            validate_allowlist(forged, self.audit)

    def test_malformed_document_types_are_controlled_in_both_modes(self) -> None:
        document_specs = (
            ("allowlist", self.allowlist, "policy", "--allowlist"),
            ("audit", self.audit, "audit_scope", "--audit"),
            ("cases", self.cases, "cases", "--cases"),
        )
        for label, document, field, option in document_specs:
            for replacement in (True, {}, [], None):
                forged = copy.deepcopy(document)
                forged[field] = replacement
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as stream:
                    json.dump(forged, stream)
                    stream.flush()
                    for optimized in (False, True):
                        command = [sys.executable]
                        if optimized:
                            command.append("-O")
                        command.extend([str(Path(__file__)), option, stream.name])
                        result = subprocess.run(command, capture_output=True, text=True)
                        self.assertEqual(result.returncode, 2, (label, replacement, optimized, result.stderr))
                        self.assertNotIn("Traceback", result.stderr + result.stdout)
                        self.assertIn("validation error", result.stderr.lower())

        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as stream:
            forged = copy.deepcopy(self.audit)
            forged["redaction"]["log_policy"] = True
            json.dump(forged, stream)
            stream.flush()
            for optimized in (False, True):
                command = [sys.executable]
                if optimized:
                    command.append("-O")
                command.extend([str(Path(__file__)), "--audit", stream.name])
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2, ("audit.redaction.log_policy", optimized, result.stderr))
                self.assertNotIn("Traceback", result.stderr + result.stdout)
                self.assertIn("validation error", result.stderr.lower())

    def test_malformed_cli_input_has_no_traceback(self) -> None:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as stream:
            stream.write('{"cases": [}')
            stream.flush()
            result = subprocess.run(
                [sys.executable, str(Path(__file__)), "--cases", stream.name],
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr + result.stdout)
        self.assertIn("validation error", result.stderr.lower())


def _measure_baseline(allowlist: dict[str, Any], audit: dict[str, Any], cases: dict[str, Any], repetitions: int = 7) -> list[float]:
    samples: list[float] = []
    for _ in range(repetitions):
        started = time.perf_counter_ns()
        validate_all(allowlist, audit, cases)
        samples.append((time.perf_counter_ns() - started) / 1_000_000)
    return samples


def _baseline_payload(samples: list[float]) -> dict[str, Any]:
    ordered = sorted(samples)
    p95_index = min(len(ordered) - 1, max(0, int((len(ordered) * 0.95 + 0.999999) // 1) - 1))
    return {
        "min": min(samples),
        "median": statistics.median(samples),
        "p95": ordered[p95_index],
        "max": max(samples),
        "mean": statistics.mean(samples),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allowlist", type=Path, default=ALLOWLIST_PATH)
    parser.add_argument("--audit", type=Path, default=AUDIT_PATH)
    parser.add_argument("--cases", type=Path, default=CASES_PATH)
    parser.add_argument("--source-root", type=Path)
    args = parser.parse_args(argv)
    try:
        allowlist = load_json(args.allowlist)
        audit = load_json(args.audit)
        cases = load_json(args.cases)
        source_mode = validate_all(allowlist, audit, cases, args.source_root)
    except (ContractError, KeyError, TypeError, ValueError, OSError, UnicodeError) as exc:
        print(f"validation error: {exc}", file=sys.stderr)
        return 2

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RouteAllowlistTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        return 1
    samples = _measure_baseline(allowlist, audit, cases)
    print(f"baseline.fixture_validation_ms={statistics.median(samples):.3f}")
    print(f"baseline.fixture_validation_distribution_ms={json.dumps(_baseline_payload(samples), sort_keys=True)}")
    print(f"baseline.fixture_artifact_bytes={artifact_size_bytes()}")
    print(f"baseline.fixture_count={len(cases['cases'])}")
    if source_mode:
        print(f"baseline.source_mode={source_mode}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
