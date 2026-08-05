#!/usr/bin/env python3
"""Validate the P0-01 planning review without network or live Hermes access.

The review is source evidence, not a deployment probe. Keeping the validator
stdlib-only and local makes a missing checkout, changed source file, or missing
planning reference fail closed instead of silently accepting an unreviewed
revision.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import urlsplit


EXPECTED_SOURCE_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
EXPECTED_CONTRACT = "dashboard-v0.0.1"
EXPECTED_FORMAT_VERSION = 1
EXPECTED_OPERATION = "P0-01"
EXPECTED_PURPOSE = (
    "Reconcile source-derived v0.0.1 planning claims with the pinned Hermes "
    "checkout without contacting a live service."
)
REVIEW_NAME = "planning_review.json"
EXPECTED_PLANNING_DOCS = [
    "README.md",
    "apps/apple/README.md",
    "apps/web/README.md",
    "contracts/README.md",
    "contracts/design-tokens/README.md",
    "contracts/fixtures/README.md",
    "contracts/hermes-dashboard/README.md",
    "contracts/hermes-dashboard/manifest.md",
    "contracts/state-models/README.md",
    "contracts/state-models/authentication.md",
    "contracts/state-models/chat.md",
    "contracts/state-models/connection.md",
    "contracts/state-models/terminal.md",
    "contracts/fixtures/source-audit/planning-reconciliation/README.md",
    "docs/architecture/README.md",
    "docs/architecture/deep-links.md",
    "docs/deployment/README.md",
    "docs/deployment/proof-matrix.md",
    "docs/product/README.md",
    "docs/product/roadmap.md",
    "docs/product/v0.0.1.md",
    "docs/protocol/README.md",
    "docs/protocol/compatibility.md",
    "docs/security/authentication.md",
    "docs/security/README.md",
    "prototypes/README.md",
    "scripts/README.md",
]
EXPECTED_REQUIRED_LINKS = [
    {
        "path": "contracts/fixtures/README.md",
        "target": "source-audit/planning-reconciliation/planning_review.json",
    },
    {
        "path": "contracts/hermes-dashboard/README.md",
        "target": "../fixtures/source-audit/planning-reconciliation/planning_review.json",
    },
    {
        "path": "contracts/hermes-dashboard/manifest.md",
        "target": "../fixtures/source-audit/planning-reconciliation/planning_review.json",
    },
    {
        "path": "docs/product/v0.0.1.md",
        "target": "../../contracts/fixtures/source-audit/planning-reconciliation/planning_review.json",
    },
    {
        "path": "docs/protocol/compatibility.md",
        "target": "../../contracts/fixtures/source-audit/planning-reconciliation/planning_review.json",
    },
]
EXPECTED_SOURCE_FILES = [
    {
        "path": "hermes_cli/dashboard_auth/routes.py",
        "sha256": "d42be557b9b1ba798c038c91246cba0bf046e89ebe34a27db0c7803c517e9c20",
        "anchors": [
            {"id": "login-page", "literal": "@router.get(\"/login\", name=\"login_page\")", "line": 132},
            {"id": "provider-discovery", "literal": "@router.get(\"/api/auth/providers\", name=\"auth_providers\")", "line": 152},
            {"id": "browser-login", "literal": "@router.get(\"/auth/login\", name=\"auth_login\")", "line": 182},
            {"id": "native-authorize", "literal": "@router.get(\"/auth/native/authorize\", name=\"auth_native_authorize\")", "line": 289},
            {"id": "oauth-callback", "literal": "@router.get(\"/auth/callback\", name=\"auth_callback\")", "line": 379},
            {"id": "logout", "literal": "@router.post(\"/auth/logout\", name=\"auth_logout\")", "line": 742},
            {"id": "identity-probe", "literal": "@router.get(\"/api/auth/me\", name=\"auth_me\")", "line": 778},
            {"id": "ws-ticket", "literal": "@router.post(\"/api/auth/ws-ticket\", name=\"auth_ws_ticket\")", "line": 799},
            {"id": "native-token", "literal": "@router.post(\"/auth/native/token\", name=\"auth_native_token\")", "line": 841},
            {"id": "native-refresh", "literal": "@router.post(\"/auth/native/refresh\", name=\"auth_native_refresh\")", "line": 894},
        ],
    },
    {
        "path": "hermes_cli/dashboard_auth/ws_tickets.py",
        "sha256": "b66e29a067002ad8a345b49281d30c75d6ec2bb177d58214611db66925bb4429",
        "anchors": [
            {"id": "ticket-ttl", "literal": "TTL_SECONDS = 30", "line": 42},
            {"id": "ticket-consumer", "literal": "def consume_ticket(ticket: str)", "line": 81},
            {"id": "single-use-pop", "literal": "entry = _tickets.pop(ticket, None)", "line": 90},
            {"id": "bounded-ticket-log", "literal": "truncated = (ticket[:8] + \"…\") if ticket else \"<empty>\"", "line": 94},
        ],
    },
    {
        "path": "hermes_cli/web_routers/sessions.py",
        "sha256": "f8debdab79430829245352ebdb7f50603c3a42c11d4609eb3287c35b9a2bf0ba",
        "anchors": [
            {"id": "session-list", "literal": "@list_router.get(\"/api/sessions\")", "line": 50},
            {"id": "session-search", "literal": "@search_router.get(\"/api/sessions/search\")", "line": 166},
            {"id": "session-read", "literal": "@manage_router.get(\"/api/sessions/{session_id}\")", "line": 552},
            {"id": "session-messages", "literal": "@manage_router.get(\"/api/sessions/{session_id}/messages\")", "line": 598},
            {"id": "session-patch", "literal": "@manage_router.patch(\"/api/sessions/{session_id}\")", "line": 661},
        ],
    },
    {
        "path": "hermes_cli/web_server.py",
        "sha256": "b52cc35523f891b6947fa59ac70516d955e47714877069e5ed3f06544b793c1a",
        "anchors": [
            {"id": "image-upload", "literal": "@app.post(\"/api/chat/image-upload\")", "line": 2306},
            {"id": "pty-resize-format", "literal": "_RESIZE_RE = re.compile(rb\"\\x1b\\[RESIZE:(\\d+);(\\d+)\\]\")", "line": 14401},
            {"id": "pty-ttl", "literal": "ttl=30 * 60", "line": 14409},
            {"id": "pty-replay-cap", "literal": "buffer_cap=1 * 1024 * 1024", "line": 14411},
            {"id": "pty-route", "literal": "@app.websocket(\"/api/pty\")", "line": 15624},
            {"id": "chat-websocket-route", "literal": "@app.websocket(\"/api/ws\")", "line": 15811},
            {"id": "pty-detach", "literal": "PTY_REGISTRY.detach(attach_token, ws)", "line": 15797},
        ],
        "absent": ["hermes_source_sha"],
        "exceptions": [
            {
                "route": "/api/ssh/ownership",
                "field": "protocolVersion",
                "status": "blocked",
                "reason": (
                    "The route exposes a separate SSH ownership protocol and is "
                    "outside the selected Dashboard surface."
                ),
            }
        ],
    },
    {
        "path": "hermes_cli/pty_bridge.py",
        "sha256": "e24515762a8ee3c9089369b7ecba20307af62c7cfb6d02abf04261ecacaa6095",
        "anchors": [
            {"id": "pty-min-dimension", "literal": "_MIN_DIMENSION = 1", "line": 58},
            {"id": "pty-max-cols", "literal": "_MAX_COLS = 2000", "line": 59},
            {"id": "pty-max-rows", "literal": "_MAX_ROWS = 1000", "line": 60},
        ],
    },
    {
        "path": "hermes_cli/pty_session.py",
        "sha256": "617448d953ec978f1b3287b02ac0dd2ad61c255d3366e0ca45efdf829146d8c5",
        "anchors": [
            {"id": "pty-process-exited-code", "literal": "WS_CLOSE_PROCESS_EXITED = 4410", "line": 15},
            {"id": "pty-superseded-code", "literal": "WS_CLOSE_SUPERSEDED = 4409", "line": 16},
            {"id": "pty-detached-reap", "literal": "and (now - s.last_detached_at) > self._ttl", "line": 179},
        ],
    },
    {
        "path": "tui_gateway/ws.py",
        "sha256": "2b1c772cb37c77a756325e4c298f6a5ee8947d6566cd7638f06f7a0421b8b5fd",
        "anchors": [
            {"id": "gateway-route-contract", "literal": "@app.websocket(\"/api/ws\")", "line": 19},
            {"id": "message-delta", "literal": "\"message.delta\"", "line": 54},
            {"id": "reasoning-delta", "literal": "\"reasoning.delta\"", "line": 55},
            {"id": "thinking-delta", "literal": "\"thinking.delta\"", "line": 56},
            {"id": "gateway-ready", "literal": "\"gateway.ready\"", "line": 319},
            {"id": "parse-error", "literal": "\"error\": {\"code\": -32700, \"message\": \"parse error\"}", "line": 373},
            {"id": "dispatch-error", "literal": "\"error\": {\"code\": -32603, \"message\": \"internal error\"}", "line": 404},
        ],
    },
    {
        "path": "tui_gateway/methods_prompt.py",
        "sha256": "96363dbf53a484f6445750c99a40e0624a9e43966be8fb29d8e47883a3ec5f51",
        "anchors": [
            {"id": "prompt-submit", "literal": "@method(\"prompt.submit\")", "line": 67},
            {"id": "clarify-response", "literal": "@method(\"clarify.respond\")", "line": 879},
            {"id": "approval-response", "literal": "@method(\"approval.respond\")", "line": 907},
        ],
    },
    {
        "path": "tui_gateway/methods_session.py",
        "sha256": "1e70561f7c5ca08556e26216f9f6a553bbf25e4c8de3368ac9cb9634e57ea34e",
        "anchors": [
            {"id": "session-create", "literal": "@method(\"session.create\")", "line": 14},
            {"id": "session-list-rpc", "literal": "@method(\"session.list\")", "line": 162},
            {"id": "session-most-recent", "literal": "@method(\"session.most_recent\")", "line": 214},
            {"id": "session-resume", "literal": "@method(\"session.resume\")", "line": 306},
            {"id": "session-active-list", "literal": "@method(\"session.active_list\")", "line": 750},
            {"id": "session-status", "literal": "@method(\"session.status\")", "line": 2207},
            {"id": "session-history", "literal": "@method(\"session.history\")", "line": 2283},
            {"id": "session-close", "literal": "@method(\"session.close\")", "line": 2586},
            {"id": "session-interrupt", "literal": "@method(\"session.interrupt\")", "line": 2750},
        ],
    },
    {
        "path": "tui_gateway/methods_complete.py",
        "sha256": "87ef05379c694cf7b6995095eb7acd5a4111eb275eb4c77b6e040da41033a8cf",
        "anchors": [
            {"id": "model-options", "literal": "@method(\"model.options\")", "line": 327},
        ],
    },
    {
        "path": "tui_gateway/server.py",
        "sha256": "e4bd9009827ffd224cc85c8b17ad7baba0f560d643d688e265be5a06fe8ba29c",
        "anchors": [
            {"id": "config-set", "literal": "@method(\"config.set\")", "line": 10468},
            {"id": "model-key", "literal": "if key == \"model\":", "line": 10473},
            {"id": "pending-switch-pop", "literal": "pending = session.pop(\"pending_model_switch\", None)", "line": 4583},
            {"id": "pending-confirmation-drop", "literal": "surface the warning and drop the", "line": 4594},
            {"id": "tool-start", "literal": "_emit(\"tool.start\", sid, payload)", "line": 5316},
            {"id": "tool-complete", "literal": "_emit(\"tool.complete\", sid, payload)", "line": 5363},
            {"id": "message-complete", "literal": "_emit(\"message.complete\", csid, {\"text\": summary})", "line": 5604},
            {"id": "approval-request", "literal": "_emit(\"approval.request\", sid, payload)", "line": 1808},
            {"id": "clarify-request", "literal": "\"clarify.request\"", "line": 3136},
            {"id": "session-info", "literal": "_emit(\"session.info\", sid, info)", "line": 1726},
            {"id": "error-event", "literal": "_emit(\"error\", sid, {\"message\": f\"agent init failed: {e}\"})", "line": 2239},
        ],
    },
]
EXPECTED_CLAIMS = [
    {
        "id": "auth-bootstrap",
        "status": "verified",
        "source_files": ["hermes_cli/dashboard_auth/routes.py"],
        "evidence": [
            {
                "source_file": "hermes_cli/dashboard_auth/routes.py",
                "sha256": "d42be557b9b1ba798c038c91246cba0bf046e89ebe34a27db0c7803c517e9c20",
                "anchors": [
                    "login-page",
                    "provider-discovery",
                    "browser-login",
                    "native-authorize",
                    "oauth-callback",
                    "logout",
                    "identity-probe",
                    "ws-ticket",
                    "native-token",
                    "native-refresh",
                ],
            }
        ],
        "docs": [
            "contracts/hermes-dashboard/manifest.md",
            "docs/product/v0.0.1.md",
            "docs/protocol/compatibility.md",
        ],
        "summary": "The pinned source exposes the reviewed browser, provider-discovery, native authorization, identity, logout, ticket, and native-token route names.",
    },
    {
        "id": "ticket-lifecycle",
        "status": "verified",
        "source_files": [
            "hermes_cli/dashboard_auth/ws_tickets.py",
            "hermes_cli/dashboard_auth/routes.py",
        ],
        "evidence": [
            {
                "source_file": "hermes_cli/dashboard_auth/ws_tickets.py",
                "sha256": "b66e29a067002ad8a345b49281d30c75d6ec2bb177d58214611db66925bb4429",
                "anchors": [
                    "ticket-ttl",
                    "ticket-consumer",
                    "single-use-pop",
                    "bounded-ticket-log",
                ],
            },
            {
                "source_file": "hermes_cli/dashboard_auth/routes.py",
                "sha256": "d42be557b9b1ba798c038c91246cba0bf046e89ebe34a27db0c7803c517e9c20",
                "anchors": ["ws-ticket"],
            },
        ],
        "docs": [
            "contracts/hermes-dashboard/manifest.md",
            "docs/protocol/compatibility.md",
            "contracts/fixtures/README.md",
        ],
        "summary": "Gated WebSocket tickets are 30-second, single-use values; invalid-ticket diagnostics retain only an eight-character fragment.",
    },
    {
        "id": "session-rest-surface",
        "status": "verified",
        "source_files": ["hermes_cli/web_routers/sessions.py"],
        "evidence": [
            {
                "source_file": "hermes_cli/web_routers/sessions.py",
                "sha256": "f8debdab79430829245352ebdb7f50603c3a42c11d4609eb3287c35b9a2bf0ba",
                "anchors": [
                    "session-list",
                    "session-search",
                    "session-read",
                    "session-messages",
                    "session-patch",
                ],
            }
        ],
        "docs": [
            "contracts/hermes-dashboard/manifest.md",
            "docs/product/v0.0.1.md",
        ],
        "summary": "The selected list, search, read, messages, and metadata-patch REST routes exist at the pinned source.",
    },
    {
        "id": "chat-rpc-surface",
        "status": "verified",
        "source_files": [
            "tui_gateway/ws.py",
            "tui_gateway/methods_prompt.py",
            "tui_gateway/methods_session.py",
            "tui_gateway/methods_complete.py",
            "tui_gateway/server.py",
        ],
        "evidence": [
            {
                "source_file": "tui_gateway/ws.py",
                "sha256": "2b1c772cb37c77a756325e4c298f6a5ee8947d6566cd7638f06f7a0421b8b5fd",
                "anchors": [
                    "gateway-route-contract",
                    "message-delta",
                    "reasoning-delta",
                    "thinking-delta",
                    "gateway-ready",
                    "parse-error",
                    "dispatch-error",
                ],
            },
            {
                "source_file": "tui_gateway/methods_prompt.py",
                "sha256": "96363dbf53a484f6445750c99a40e0624a9e43966be8fb29d8e47883a3ec5f51",
                "anchors": ["prompt-submit", "clarify-response", "approval-response"],
            },
            {
                "source_file": "tui_gateway/methods_session.py",
                "sha256": "1e70561f7c5ca08556e26216f9f6a553bbf25e4c8de3368ac9cb9634e57ea34e",
                "anchors": [
                    "session-create",
                    "session-list-rpc",
                    "session-most-recent",
                    "session-resume",
                    "session-active-list",
                    "session-status",
                    "session-history",
                    "session-close",
                    "session-interrupt",
                ],
            },
            {
                "source_file": "tui_gateway/methods_complete.py",
                "sha256": "87ef05379c694cf7b6995095eb7acd5a4111eb275eb4c77b6e040da41033a8cf",
                "anchors": ["model-options"],
            },
            {
                "source_file": "tui_gateway/server.py",
                "sha256": "e4bd9009827ffd224cc85c8b17ad7baba0f560d643d688e265be5a06fe8ba29c",
                "anchors": [
                    "tool-start",
                    "tool-complete",
                    "message-complete",
                    "approval-request",
                    "clarify-request",
                    "session-info",
                    "error-event",
                ],
            },
        ],
        "docs": [
            "contracts/hermes-dashboard/manifest.md",
            "docs/protocol/compatibility.md",
            "contracts/state-models/chat.md",
        ],
        "summary": "The reviewed JSON-RPC method, stream-event, ready-event, and parse/dispatch error anchors exist in the pinned gateway.",
    },
    {
        "id": "model-switch",
        "status": "verified",
        "source_files": ["tui_gateway/methods_complete.py", "tui_gateway/server.py"],
        "evidence": [
            {
                "source_file": "tui_gateway/methods_complete.py",
                "sha256": "87ef05379c694cf7b6995095eb7acd5a4111eb275eb4c77b6e040da41033a8cf",
                "anchors": ["model-options"],
            },
            {
                "source_file": "tui_gateway/server.py",
                "sha256": "e4bd9009827ffd224cc85c8b17ad7baba0f560d643d688e265be5a06fe8ba29c",
                "anchors": [
                    "config-set",
                    "model-key",
                    "pending-switch-pop",
                    "pending-confirmation-drop",
                ],
            },
        ],
        "docs": [
            "contracts/hermes-dashboard/manifest.md",
            "docs/product/v0.0.1.md",
            "contracts/state-models/chat.md",
        ],
        "summary": "Model options are exposed, config.set recognizes the model key, and a pending switch is consumed with an expensive-choice warning instead of being silently applied.",
    },
    {
        "id": "pty-lifecycle",
        "status": "verified",
        "source_files": [
            "hermes_cli/web_server.py",
            "hermes_cli/pty_bridge.py",
            "hermes_cli/pty_session.py",
        ],
        "evidence": [
            {
                "source_file": "hermes_cli/web_server.py",
                "sha256": "b52cc35523f891b6947fa59ac70516d955e47714877069e5ed3f06544b793c1a",
                "anchors": [
                    "pty-resize-format",
                    "pty-ttl",
                    "pty-replay-cap",
                    "pty-route",
                    "pty-detach",
                ],
            },
            {
                "source_file": "hermes_cli/pty_bridge.py",
                "sha256": "e24515762a8ee3c9089369b7ecba20307af62c7cfb6d02abf04261ecacaa6095",
                "anchors": ["pty-min-dimension", "pty-max-cols", "pty-max-rows"],
            },
            {
                "source_file": "hermes_cli/pty_session.py",
                "sha256": "617448d953ec978f1b3287b02ac0dd2ad61c255d3366e0ca45efdf829146d8c5",
                "anchors": [
                    "pty-process-exited-code",
                    "pty-superseded-code",
                    "pty-detached-reap",
                ],
            },
        ],
        "docs": [
            "contracts/hermes-dashboard/manifest.md",
            "docs/product/v0.0.1.md",
            "docs/protocol/compatibility.md",
            "contracts/state-models/terminal.md",
        ],
        "summary": "The web-only PTY route, resize bounds, 30-minute detached TTL, 1 MiB replay cap, detach behavior, and observable close codes are present at the pinned source.",
    },
    {
        "id": "image-attachment-boundary",
        "status": "verified",
        "source_files": ["hermes_cli/web_server.py"],
        "evidence": [
            {
                "source_file": "hermes_cli/web_server.py",
                "sha256": "b52cc35523f891b6947fa59ac70516d955e47714877069e5ed3f06544b793c1a",
                "anchors": ["image-upload"],
            }
        ],
        "docs": [
            "contracts/hermes-dashboard/manifest.md",
            "docs/product/v0.0.1.md",
        ],
        "summary": "The selected image upload route exists; arbitrary file and filesystem routes remain outside this source review's allowlist.",
    },
    {
        "id": "source-identity",
        "status": "verified",
        "source_files": ["hermes_cli/web_server.py"],
        "evidence": [
            {
                "source_file": "hermes_cli/web_server.py",
                "sha256": "b52cc35523f891b6947fa59ac70516d955e47714877069e5ed3f06544b793c1a",
                "anchors": ["image-upload", "pty-route", "chat-websocket-route"],
            }
        ],
        "exceptions": [
            {
                "source_file": "hermes_cli/web_server.py",
                "route": "/api/ssh/ownership",
                "field": "protocolVersion",
                "status": "blocked",
            }
        ],
        "docs": [
            "contracts/hermes-dashboard/manifest.md",
            "docs/protocol/compatibility.md",
        ],
        "summary": "The selected Dashboard surface exposes no server-observable Hermes source SHA or stable protocol-version field. The separate /api/ssh/ownership protocolVersion response is explicitly blocked and remains outside this contract, so deployment attestation remains out of band.",
    },
]
EXPECTED_DEFERRED = [
    {
        "owner": "#200 / PR #220",
        "scope": "native bearer route allowlist and its source-audit fixtures",
        "reason": "This operation does not duplicate the focused bearer-auth route audit.",
    },
    {
        "owner": "PR #216",
        "scope": "PTY attach fixture set and terminal-state changes",
        "reason": "This operation records only the source anchors needed to reconcile existing planning claims and does not edit reserved terminal files.",
    },
    {
        "owner": "PR #218",
        "scope": "browser OAuth state and PKCE fixture set",
        "reason": "This operation does not duplicate the focused browser OAuth audit or edit its reserved authentication document.",
    },
    {
        "owner": "PR #219",
        "scope": "model-options fixture set",
        "reason": "This operation records the existing model-switch contract anchors but does not edit the reserved model-options paths.",
    },
    {
        "owner": "P0-02 and deployment-proof issues",
        "scope": "live deployment attestation, Caddy or Traefik behavior, and behavioral probes",
        "reason": "Source inspection is necessary evidence, but it is not a live integration or deployment proof.",
    },
]


def load_review(path: Path) -> dict[str, Any]:
    """Load and structurally validate the review record before using it."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read review record {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("review record must be a JSON object")
    return value


def _git_head(source_root: Path) -> str | None:
    """Read a local checkout's HEAD; never fetch or consult a remote."""
    try:
        result = subprocess.run(
            ["git", "-C", str(source_root), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _git_status(source_root: Path) -> str | None:
    """Return all tracked, untracked, and ignored worktree changes."""
    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(source_root),
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--ignored=matching",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return result.stdout


def _git_blob(source_root: Path, head: str, relative: str) -> bytes | None:
    """Read a source file from immutable Git storage without lazy fetching."""
    env = os.environ.copy()
    env["GIT_NO_LAZY_FETCH"] = "1"
    try:
        result = subprocess.run(
            ["git", "-C", str(source_root), "cat-file", "blob", f"{head}:{relative}"],
            check=False,
            capture_output=True,
            env=env,
        )
    except OSError:
        return None
    if result.returncode != 0 or not isinstance(result.stdout, bytes):
        return None
    return result.stdout


def _git_index_flags(source_root: Path) -> list[str] | None:
    """Return tracked paths marked assume-unchanged or skip-worktree."""
    try:
        result = subprocess.run(
            ["git", "-C", str(source_root), "ls-files", "-v"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if result.returncode != 0 or not isinstance(result.stdout, str):
        return None
    flagged: list[str] = []
    for line in result.stdout.splitlines():
        if line[:1] in {"h", "s", "S"}:
            flagged.append(line[2:] if len(line) > 2 else "<unknown>")
    return flagged


_MARKDOWN_LINK_RE = re.compile(r"(?<!!)\[[^\]\n]+\]\(([^)\s]+)(?:\s+[^)]*)?\)")


def _line_numbers(text: str, literal: str) -> list[int]:
    return [
        number
        for number, line in enumerate(text.splitlines(), start=1)
        if literal in line
    ]


def _markdown_link_targets(text: str) -> list[str]:
    """Extract actual Markdown link destinations, excluding image syntax."""
    return _MARKDOWN_LINK_RE.findall(text)


def _is_unsafe_relative_path(value: str) -> bool:
    """Reject platform-specific absolute paths and lexical parent traversal."""
    posix = PurePosixPath(value.replace("\\", "/"))
    windows = PureWindowsPath(value)
    return (
        Path(value).is_absolute()
        or posix.is_absolute()
        or windows.is_absolute()
        or any(part == ".." for part in posix.parts)
        or any(part == ".." for part in windows.parts)
    )


def _resolve_under_root(
    root: Path,
    relative: str,
    label: str,
    errors: list[str],
) -> Path | None:
    """Resolve a metadata path and reject symlinks that escape its approved root."""
    if not relative or _is_unsafe_relative_path(relative):
        errors.append(
            f"{label} must be relative, contain no '..', and remain under its approved root: {relative!r}"
        )
        return None
    try:
        resolved_root = root.resolve(strict=False)
        resolved = (resolved_root / relative).resolve(strict=False)
        resolved.relative_to(resolved_root)
    except (OSError, RuntimeError, ValueError):
        errors.append(f"{label} resolves outside its approved root: {relative!r}")
        return None
    return resolved


def _validate_claims(review: dict[str, Any], errors: list[str]) -> None:
    if "claims" not in review:
        errors.append("review.claims is required")
        return
    claims = review["claims"]
    if not isinstance(claims, list) or not claims:
        errors.append("review.claims must be a non-empty list")
        return

    expected_by_id = {claim["id"]: claim for claim in EXPECTED_CLAIMS}
    allowed_ids = frozenset(expected_by_id)
    allowed_statuses = frozenset(claim["status"] for claim in EXPECTED_CLAIMS)
    expected_id_order = tuple(claim["id"] for claim in EXPECTED_CLAIMS)
    source_records = review.get("source_files")
    included_source_records = (
        {
            entry["path"]: entry
            for entry in source_records
            if isinstance(entry, dict) and isinstance(entry.get("path"), str)
        }
        if isinstance(source_records, list)
        else {}
    )
    planning_docs = review.get("planning_docs")
    included_planning_docs = (
        {item for item in planning_docs if isinstance(item, str)}
        if isinstance(planning_docs, list)
        else set()
    )

    claim_ids: list[str] = []
    for claim in claims:
        if not isinstance(claim, dict):
            errors.append("review.claims contains a non-object")
            continue
        claim_id = claim.get("id")
        if claim_id not in allowed_ids:
            errors.append(f"review.claims contains an unknown id: {claim_id!r}")
            continue
        claim_ids.append(claim_id)
        status = claim.get("status")
        if status not in allowed_statuses:
            errors.append(f"claim {claim_id!r} has a disallowed status: {status!r}")
        expected = expected_by_id[claim_id]
        if status != expected["status"]:
            errors.append(
                f"claim {claim_id!r} status does not match the pinned review: "
                f"expected {expected['status']!r}, found {status!r}"
            )

        source_refs = claim.get("source_files")
        if not isinstance(source_refs, list) or not source_refs or not all(
            isinstance(item, str) and item in included_source_records for item in source_refs
        ):
            errors.append(f"claim {claim_id!r} references an excluded source record")
        doc_refs = claim.get("docs")
        if not isinstance(doc_refs, list) or not doc_refs or not all(
            isinstance(item, str) and item in included_planning_docs for item in doc_refs
        ):
            errors.append(f"claim {claim_id!r} references an excluded planning document")

        evidence = claim.get("evidence")
        evidence_sources: set[str] = set()
        if not isinstance(evidence, list) or not evidence:
            errors.append(f"claim {claim_id!r} evidence must be a non-empty list")
        else:
            for item in evidence:
                if not isinstance(item, dict):
                    errors.append(f"claim {claim_id!r} evidence contains a non-object")
                    continue
                source_file = item.get("source_file")
                if isinstance(source_file, str):
                    evidence_sources.add(source_file)
                source_record = (
                    included_source_records.get(source_file)
                    if isinstance(source_file, str)
                    else None
                )
                if source_record is None:
                    errors.append(
                        f"claim {claim_id!r} evidence references an excluded source record"
                    )
                    continue
                if item.get("sha256") != source_record.get("sha256"):
                    errors.append(
                        f"claim {claim_id!r} evidence digest does not match {source_file}"
                    )
                anchors = item.get("anchors")
                source_anchors = source_record.get("anchors", [])
                expected_anchor_ids = {
                    anchor.get("id")
                    for anchor in source_anchors
                    if isinstance(anchor, dict) and isinstance(anchor.get("id"), str)
                } if isinstance(source_anchors, list) else set()
                if not isinstance(anchors, list) or not anchors or not all(
                    isinstance(anchor_id, str) and anchor_id in expected_anchor_ids
                    for anchor_id in anchors
                ):
                    errors.append(
                        f"claim {claim_id!r} evidence anchors do not match {source_file}"
                    )
        if isinstance(source_refs, list) and evidence_sources != set(source_refs):
            errors.append(f"claim {claim_id!r} evidence/source coverage does not match")
        exceptions = claim.get("exceptions", [])
        if not isinstance(exceptions, list) or not all(
            isinstance(item, dict) for item in exceptions
        ):
            errors.append(f"claim {claim_id!r} exceptions must be a list of objects")
        else:
            for exception in exceptions:
                source_file = exception.get("source_file")
                source_record = (
                    included_source_records.get(source_file)
                    if isinstance(source_file, str)
                    else None
                )
                if source_record is None:
                    errors.append(
                        f"claim {claim_id!r} exception references an excluded source record"
                    )
                    continue
                source_exceptions = source_record.get("exceptions", [])
                if not isinstance(source_exceptions, list) or not any(
                    isinstance(recorded, dict)
                    and all(
                        exception.get(field) == recorded.get(field)
                        for field in ("route", "field", "status")
                    )
                    for recorded in source_exceptions
                ):
                    errors.append(
                        f"claim {claim_id!r} exception is not recorded in source metadata"
                    )

        if claim != expected:
            errors.append(f"claim {claim_id!r} content does not match the pinned review")

    if tuple(claim_ids) != expected_id_order:
        errors.append("review.claims ids/order do not match the pinned review")


def _validate_shape(review: dict[str, Any], errors: list[str]) -> None:
    if review.get("format_version") != EXPECTED_FORMAT_VERSION:
        errors.append("review.format_version does not match the pinned schema")
    if review.get("operation") != EXPECTED_OPERATION:
        errors.append("review.operation does not match P0-01")
    if review.get("purpose") != EXPECTED_PURPOSE:
        errors.append("review.purpose does not match the pinned review")
    if review.get("deferred") != EXPECTED_DEFERRED:
        errors.append("review.deferred does not match the pinned ownership boundaries")

    source = review.get("source")
    if not isinstance(source, dict):
        errors.append("review.source must be an object")
    else:
        if source.get("repository") != "NousResearch/hermes-agent":
            errors.append("review.source.repository is not the pinned Hermes repository")
        if source.get("sha") != EXPECTED_SOURCE_SHA:
            errors.append("review.source.sha does not match the contract pin")
    if review.get("contract") != EXPECTED_CONTRACT:
        errors.append("review.contract is not dashboard-v0.0.1")

    planning_docs = review.get("planning_docs")
    if not isinstance(planning_docs, list) or not planning_docs or not all(
        isinstance(item, str) and item for item in planning_docs
    ):
        errors.append("review.planning_docs must be a non-empty list of paths")
    else:
        if len(set(planning_docs)) != len(planning_docs):
            errors.append("review.planning_docs contains duplicate paths")
        if planning_docs != EXPECTED_PLANNING_DOCS:
            errors.append("review.planning_docs does not match the exact ordered coverage")
        for relative in planning_docs:
            if _is_unsafe_relative_path(relative):
                errors.append(
                    f"planning document path must remain under the repo root: {relative!r}"
                )

    required_links = review.get("required_links")
    if required_links is None:
        errors.append("review.required_links is required")
    elif not isinstance(required_links, list):
        errors.append("review.required_links must be a list")
    elif required_links != EXPECTED_REQUIRED_LINKS:
        errors.append("review.required_links does not match the exact expected links")

    source_files = review.get("source_files")
    if not isinstance(source_files, list) or not source_files:
        errors.append("review.source_files must be a non-empty list")
    else:
        seen: set[str] = set()
        for entry in source_files:
            if not isinstance(entry, dict):
                errors.append("review.source_files contains a non-object")
                continue
            path = entry.get("path")
            if not isinstance(path, str) or not path or _is_unsafe_relative_path(path):
                errors.append(
                    f"source entry path must remain under the pinned source root: {path!r}"
                )
            elif path in seen:
                errors.append(f"review.source_files duplicates {path}")
            else:
                seen.add(path)
            digest = entry.get("sha256")
            if not isinstance(digest, str) or len(digest) != 64:
                errors.append(f"review.source_files[{path!r}] has an invalid sha256")
            anchors = entry.get("anchors", [])
            if not isinstance(anchors, list):
                errors.append(f"review.source_files[{path!r}].anchors must be a list")
                anchors = []
            for anchor in anchors:
                if not isinstance(anchor, dict) or not all(
                    isinstance(anchor.get(field), expected_type)
                    for field, expected_type in (
                        ("id", str),
                        ("literal", str),
                        ("line", int),
                    )
                ):
                    errors.append(f"review.source_files[{path!r}] has an invalid anchor")
            absent = entry.get("absent", [])
            if not isinstance(absent, list) or not all(
                isinstance(item, str) and item for item in absent
            ):
                errors.append(f"review.source_files[{path!r}].absent must be a list")
            exceptions = entry.get("exceptions", [])
            if not isinstance(exceptions, list):
                errors.append(f"review.source_files[{path!r}].exceptions must be a list")
                exceptions = []
            for exception in exceptions:
                if not isinstance(exception, dict) or not all(
                    isinstance(exception.get(field), str) and exception.get(field)
                    for field in ("route", "field", "status", "reason")
                ):
                    errors.append(
                        f"review.source_files[{path!r}] has an invalid exception"
                    )
        if source_files != EXPECTED_SOURCE_FILES:
            errors.append("review.source_files metadata does not match the exact pinned coverage")

    _validate_claims(review, errors)


def _validate_docs(repo_root: Path, review: dict[str, Any], errors: list[str]) -> None:
    planning_docs = review.get("planning_docs", [])
    if isinstance(planning_docs, list):
        for relative in planning_docs:
            if not isinstance(relative, str):
                continue
            path = _resolve_under_root(repo_root, relative, "planning document path", errors)
            if path is None:
                continue
            if not path.is_file():
                errors.append(f"missing planning document: {relative}")

    links = review.get("required_links", [])
    if not isinstance(links, list):
        return
    for link in links:
        if not isinstance(link, dict):
            continue
        relative = link.get("path")
        target = link.get("target")
        if not isinstance(relative, str) or not isinstance(target, str):
            errors.append("required link must contain string path and target")
            continue
        path = _resolve_under_root(repo_root, relative, "required-link path", errors)
        if path is None:
            continue
        if not path.is_file():
            errors.append(f"required-link document is missing: {relative}")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            errors.append(f"cannot read required-link document {relative}: {exc}")
            continue
        if target not in _markdown_link_targets(text):
            errors.append(f"{relative} does not contain Markdown link target {target!r}")
            continue
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or target.startswith("//") or not parsed.path:
            errors.append(f"required link target is not a local path: {target!r}")
            continue
        try:
            target_path = (path.parent / parsed.path).resolve()
            target_path.relative_to(repo_root.resolve())
        except (OSError, RuntimeError, ValueError):
            errors.append(f"required link target escapes the repository: {target!r}")
            continue
        if not target_path.is_file():
            errors.append(f"required link target is missing: {target!r}")


def _validate_source_paths(
    source_root: Path, review: dict[str, Any], errors: list[str]
) -> None:
    """Validate source path containment without reading source content."""
    if not source_root.is_dir():
        errors.append(f"source root is missing: {source_root}")
        return
    source_files = review.get("source_files", [])
    if not isinstance(source_files, list):
        return
    for entry in source_files:
        if not isinstance(entry, dict):
            continue
        relative = entry.get("path")
        if isinstance(relative, str):
            _resolve_under_root(source_root, relative, "source entry path", errors)


def _validate_source(
    source_root: Path, review: dict[str, Any], errors: list[str]
) -> str | None:
    _validate_source_paths(source_root, review, errors)
    if not source_root.is_dir():
        return None

    head = _git_head(source_root)
    if head != EXPECTED_SOURCE_SHA:
        found = head or "unavailable"
        errors.append(
            "source checkout HEAD does not match "
            f"{EXPECTED_SOURCE_SHA} (found {found})"
        )

    status = _git_status(source_root)
    if status is None:
        errors.append("source checkout status is unavailable")
    elif status:
        errors.append("source checkout is dirty; immutable HEAD blobs cannot be trusted")

    index_flags = _git_index_flags(source_root)
    if index_flags is None:
        errors.append("source index flags are unavailable")
    elif index_flags:
        errors.append(
            "source checkout uses assume-unchanged or skip-worktree flags: "
            + ", ".join(index_flags)
        )

    if (
        head != EXPECTED_SOURCE_SHA
        or status is None
        or status
        or index_flags is None
        or index_flags
    ):
        return head

    source_files = review.get("source_files", [])
    if not isinstance(source_files, list):
        return head
    for entry in source_files:
        if not isinstance(entry, dict):
            continue
        relative = entry.get("path")
        if not isinstance(relative, str):
            continue
        path = _resolve_under_root(source_root, relative, "source entry path", errors)
        if path is None:
            continue
        blob = _git_blob(source_root, head, relative)
        if blob is None:
            errors.append(f"missing pinned source blob at HEAD: {relative}")
            continue
        actual_digest = hashlib.sha256(blob).hexdigest()
        expected_digest = entry.get("sha256")
        if actual_digest != expected_digest:
            errors.append(
                f"source digest mismatch for {relative}: "
                f"expected {expected_digest}, found {actual_digest}"
            )
        try:
            text = blob.decode("utf-8")
        except UnicodeDecodeError as exc:
            errors.append(f"cannot decode pinned source blob {relative}: {exc}")
            continue
        anchors = entry.get("anchors", [])
        if isinstance(anchors, list):
            for anchor in anchors:
                if not isinstance(anchor, dict):
                    continue
                literal = anchor.get("literal")
                if not isinstance(literal, str):
                    continue
                locations = _line_numbers(text, literal)
                if not locations:
                    errors.append(
                        f"missing source anchor {anchor.get('id', literal)!r} in {relative}"
                    )
                elif isinstance(anchor.get("line"), int) and anchor["line"] not in locations:
                    errors.append(
                        f"source anchor {anchor.get('id', literal)!r} moved in {relative}: "
                        f"expected line {anchor['line']}, found {locations}"
                    )
        absent = entry.get("absent", [])
        if isinstance(absent, list):
            for literal in absent:
                if isinstance(literal, str) and literal in text:
                    errors.append(f"forbidden source field {literal!r} found in {relative}")
    return head


def validate_review(
    repo_root: Path,
    review_path: Path,
    source_root: Path | None,
    *,
    require_source: bool = True,
) -> tuple[list[str], str | None, float]:
    """Return errors, observed source HEAD, and local validation duration."""
    started = time.perf_counter()
    errors: list[str] = []
    try:
        review = load_review(review_path)
    except ValueError as exc:
        return [str(exc)], None, (time.perf_counter() - started) * 1000

    head = None
    try:
        _validate_shape(review, errors)
        _validate_docs(repo_root, review, errors)
        if source_root is None:
            if require_source:
                errors.append("source root is required for full validation")
        elif require_source:
            head = _validate_source(source_root, review, errors)
        else:
            _validate_source_paths(source_root, review, errors)
    except Exception as exc:  # pragma: no cover - regression exercised through CLI
        errors.append(
            f"unexpected validation error: {type(exc).__name__}: {exc}"
        )
    return errors, head, (time.perf_counter() - started) * 1000


def _default_repo_root() -> Path:
    # validate.py lives four directories below the repository root.
    return Path(__file__).resolve().parents[4]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=_default_repo_root(),
        help="Hermternal checkout containing the planning documents",
    )
    parser.add_argument(
        "--review",
        type=Path,
        default=None,
        help="review JSON path (defaults to this directory's planning_review.json)",
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        default=None,
        help="local Hermes checkout at the pinned SHA; no network is used",
    )
    parser.add_argument(
        "--check-docs-only",
        action="store_true",
        help="check document links without source validation",
    )
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()
    review_path = (
        args.review.resolve()
        if args.review is not None
        else Path(__file__).resolve().with_name(REVIEW_NAME)
    )
    source_root = args.source_root.resolve() if args.source_root is not None else None
    started = time.perf_counter()
    try:
        errors, head, duration_ms = validate_review(
            repo_root,
            review_path,
            source_root,
            require_source=not args.check_docs_only,
        )
    except Exception as exc:  # Keep the command-line contract structured.
        errors = [f"unexpected validation error: {type(exc).__name__}: {exc}"]
        head = None
        duration_ms = (time.perf_counter() - started) * 1000
    result = {
        "ok": not errors,
        "review": str(review_path),
        "source_head": head,
        "duration_ms": round(duration_ms, 3),
        "errors": errors,
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
