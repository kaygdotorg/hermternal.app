#!/usr/bin/env python3
"""Render and validate the disposable Caddy proof boundary.

This module is intentionally a proof fixture, not a production deployment
configuration. It keeps the reviewed method/path surface explicit so a future
runtime cannot silently replace it with ``/api/*`` or ``/hermes/*``. The
renderer receives only disposable paths and ports from the proof harness; it
never reads credentials, cookies, tickets, transcripts, or provider state. Its
local Caddy checks are synthetic edge evidence, not a live Hermes browser proof.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import math
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any


SCHEMA = "hermternal.caddy-proof.v1"
RUNTIME_INPUT_SCHEMA = "hermternal.caddy-proof.runtime-inputs.v1"
DEFAULT_HOST = "caddy-156.test"
DEFAULT_HTTPS_PORT = 19443
DEFAULT_HERMES_PORT = 19256

# A browser journey is a separate claim from this local edge proof. Keep its
# evidence contract bounded and provenance-bound so a caller cannot turn an
# arbitrary status string or event map into a result for a different run.
BROWSER_EVIDENCE_SCHEMA = "hermternal.caddy-proof.browser-evidence.v1"
BROWSER_EVIDENCE_MAX_BYTES = 4096
RETAINED_EVIDENCE_MAX_BYTES = 64 * 1024
RETAINED_EVIDENCE_ANCHOR_MAX_BYTES = 128
JSON_MAX_DEPTH = 32
JSON_MAX_NODES = 1024
JSON_MAX_OBJECT_KEYS = 256
JSON_MAX_ARRAY_LENGTH = 256
JSON_MAX_STRING_BYTES = 2048
JSON_MAX_TOTAL_STRING_BYTES = 32 * 1024
STATIC_MAX_FILES = 4096
STATIC_MAX_PER_FILE_BYTES = 8 * 1024 * 1024
STATIC_MAX_TOTAL_BYTES = 64 * 1024 * 1024
STATIC_MAX_DEPTH = 32
STATIC_DIGEST_DEADLINE_SECONDS = 10
# The residual regression suite uses the longer names to make the scope of a
# budget explicit. Keep both names public, and let the digest implementation
# honor either name when a caller patches a test seam.
STATIC_BUILD_MAX_FILES = STATIC_MAX_FILES
STATIC_BUILD_MAX_FILE_BYTES = STATIC_MAX_PER_FILE_BYTES
STATIC_BUILD_MAX_TOTAL_BYTES = STATIC_MAX_TOTAL_BYTES
STATIC_BUILD_MAX_DEPTH = STATIC_MAX_DEPTH
STATIC_BUILD_MAX_DEADLINE_SECONDS = STATIC_DIGEST_DEADLINE_SECONDS
STATIC_BUILD_DEADLINE_SECONDS = STATIC_BUILD_MAX_DEADLINE_SECONDS
STATIC_BUILD_MAX_DEADLINE = STATIC_BUILD_MAX_DEADLINE_SECONDS
GIT_COMMAND_TIMEOUT_SECONDS = 5
GIT_OUTPUT_MAX_BYTES = 4096
GIT_CONFIG_MAX_BYTES = 64 * 1024
GIT_PACK_ENTRY_MAX = 4096
GIT_METADATA_ENTRY_MAX = 65_536
# Git object and pack trees are bound recursively. Keep the trust scan
# deterministic and bounded even when a caller supplies a hostile repository;
# ordinary loose objects and the reviewed local pack set remain below these
# limits. A byte snapshot is retained for every regular entry so an in-place
# same-inode mutation cannot pass on metadata alone.
GIT_METADATA_FILE_MAX_BYTES = 64 * 1024 * 1024
GIT_METADATA_TOTAL_CONTENT_MAX_BYTES = 64 * 1024 * 1024
GIT_METADATA_MAX_DEPTH = 32
TRUSTED_GIT_EXECUTABLE = Path("/usr/bin/git")
TRUSTED_HELPER_PATH = "/usr/bin:/bin"
GIT_REDIRECT_ENV_VARS = (
    "GIT_DIR",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_REPLACE_REF_BASE",
    "GIT_PROMISOR_REMOTE",
)
GIT_FORBIDDEN_METADATA = (
    "objects/info/alternates",
    "objects/info/http-alternates",
    "info/grafts",
    "shallow",
)
GIT_METADATA_PIN_FILES = (
    "HEAD",
    "commondir",
    "config",
    "config.worktree",
    "packed-refs",
    *GIT_FORBIDDEN_METADATA,
)
# These are intentionally the two non-overlapping recursive security trees.
# Their descendants cover loose objects, pack metadata, every nested ref, and
# refs/replace without reading the same pack bytes repeatedly.
GIT_METADATA_PIN_DIRECTORIES = (
    "objects",
    "refs",
)
HEX40_RE = re.compile(r"[0-9a-f]{40}")
HEX64_RE = re.compile(r"[0-9a-f]{64}")
PROJECT_ROOT = Path(__file__).resolve().parents[1]
# Kept only as a narrow compatibility seam for the pre-hardening unit tests
# that inject malformed CompletedProcess values. Normal execution always uses
# the bounded Popen collector below.
_ORIGINAL_SUBPROCESS_RUN = subprocess.run
_RETAINED_LOADER_TOKEN = object()
RETAINED_EVIDENCE_PATH = PROJECT_ROOT / "tests/integration/hermes-caddy/caddy-proof-evidence.json"
RETAINED_EVIDENCE_ANCHOR_PATH = PROJECT_ROOT / "tests/integration/hermes-caddy/caddy-proof-evidence-sha256.txt"
# This source-pinned digest prevents a caller from replacing both the retained
# JSON and its adjacent checksum file to create a new historical trust root.
RETAINED_EVIDENCE_ANCHOR = "fefbf385921a2c156e2c4cd7397e7ef3e003707f4f8fcf25e3b2b3ed3d36ec33"
BROWSER_NON_EXECUTION_MODE = "historical_non_execution"
BROWSER_NON_EXECUTION_STATUS = "not_proven"
STATIC_BUILD_REQUIRED_FILES = (
    "index.html",
    "200.html",
    "manifest.webmanifest",
    "service-worker.js",
)
# Kept as the documented event vocabulary for callers and tests. A fixed map
# is intentionally not accepted as execution proof by this local verifier.
BROWSER_COMPLETION_EVIDENCE = {
    "gateway.ready": "proven",
    "session.resume": "proven",
    "prompt.submit": "proven",
    "message.delta": "proven",
    "message.complete": "complete",
}
BROWSER_EVIDENCE_ROOT_KEYS = ("schema", "status", "provenance", "observations")
BROWSER_EVIDENCE_PROVENANCE_KEYS = (
    "build_sha",
    "build_digest",
    "caddyfile_digest",
    "runtime_inputs_sha256",
)
BROWSER_BLOCKED_JOURNEYS = {"blocked_provider", "blocked_empty_session"}
BROWSER_JOURNEYS = {"passed", *BROWSER_BLOCKED_JOURNEYS, "failed"}
BROWSER_BLOCKER_CODES = {
    "blocked_provider": "provider_unavailable",
    "blocked_empty_session": "empty_session",
}
BROWSER_FAILURE_CODE = "browser_assertion_failed"

# These are deterministic proof paths, not operator or user home paths. Keeping
# them committed makes the retained runtime digest reproducible without storing
# the disposable VM's filesystem layout in evidence.
DEFAULT_RUNTIME_INPUTS: dict[str, object] = {
    "host": DEFAULT_HOST,
    "https_port": DEFAULT_HTTPS_PORT,
    "hermes_port": DEFAULT_HERMES_PORT,
    "site_root": "/opt/hermternal/caddy-proof/site",
    "cert_path": "/opt/hermternal/caddy-proof/tls.crt",
    "key_path": "/opt/hermternal/caddy-proof/tls.key",
    "storage_root": "/opt/hermternal/caddy-proof",
}

STATIC_PATHS = (
    "/",
    "/index.html",
    "/200.html",
    "/_app/*",
    "/service-worker.js",
    "/manifest.webmanifest",
    "/icon.svg",
)

# The client and worker intentionally share this exact grammar. Caddy's
# ``path_regexp`` is lexical and therefore cannot normalize or decode IDs.
CLIENT_ROUTE_PATTERN = rf"^/v1/c/[A-Za-z0-9._~-]{{16,}}(?:/m/[A-Za-z0-9._~-]{{16,}})?$"
CLIENT_ROUTE_PREFIX_PATTERN = r"^/v1/c/.*$"

EXACT_REST_ROUTES = (
    ("GET", "/login"),
    ("GET", "/api/auth/providers"),
    ("GET", "/auth/login"),
    ("GET", "/auth/callback"),
    ("POST", "/auth/password-login"),
    ("POST", "/auth/logout"),
    ("GET", "/api/auth/me"),
    ("POST", "/api/auth/ws-ticket"),
    ("GET", "/auth/native/authorize"),
    ("POST", "/auth/native/token"),
    ("POST", "/auth/native/refresh"),
    ("GET", "/api/sessions"),
    ("GET", "/api/sessions/search"),
    ("POST", "/api/chat/image-upload"),
)

SESSION_ID_PATTERN = r"(?:[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9._~-]{0,126}[A-Za-z0-9])"
SESSION_ROUTES = (
    ("GET", "/api/sessions/{session_id}"),
    ("GET", "/api/sessions/{session_id}/messages"),
    ("PATCH", "/api/sessions/{session_id}"),
)
WEBSOCKET_ROUTES = (
    "/api/ws",
    "/api/pty",
)

# No percent decoding or path normalization is accepted at the edge. The
# strict guard is deliberately conservative: all reviewed ticket and route
# values are ASCII-safe, so a percent sign is never needed by this proof lane.
# Dot checks are segment-bounded so opaque IDs containing two consecutive dots
# remain valid. The shared deep-link contract separately rejects the ellipsis
# marker, so three consecutive dots remain an explicit edge denial. The raw URI
# check also rejects a bare trailing query marker because Caddy's uri.query
# placeholder is empty for both no query and a request ending in `?`.
RAW_URI_GUARD = (
    "{http.request.orig_uri}.contains('%') || "
    "{http.request.orig_uri}.contains('\\\\') || "
    "{http.request.orig_uri}.contains('//') || "
    "{http.request.orig_uri}.contains('...') || "
    "{http.request.orig_uri}.matches('.*\\\\?$') || "
    "{http.request.orig_uri}.matches('(?:^|/)(?:\\\\.|\\\\.\\\\.)(?:/|\\\\?|$)')"
)
NO_QUERY_GUARD = "{http.request.uri.query} == ''"
QUERY_PRESENT_GUARD = "{http.request.uri.query} != ''"
ROOT_SCENARIO_QUERY_GUARD = "{http.request.uri.query}.matches('^scenario=(?:success|empty|failure)$')"
ROOT_QUERY_GUARD = f"({NO_QUERY_GUARD} || {ROOT_SCENARIO_QUERY_GUARD})"
# Every REST route is query-free except the OAuth callback. The callback's
# source-owned handler receives either the reviewed code/state pair or the
# reviewed provider-error triple; keeping those forms explicit prevents an
# arbitrary callback query from becoming a proxy bypass.
REST_QUERY_GUARD = NO_QUERY_GUARD
AUTH_CALLBACK_CODE_STATE_PATTERN = (
    rf"^code=[A-Za-z0-9._~-]{{1,512}}&state=[A-Za-z0-9._~-]{{1,512}}$"
)
AUTH_CALLBACK_STATE_CODE_PATTERN = (
    rf"^state=[A-Za-z0-9._~-]{{1,512}}&code=[A-Za-z0-9._~-]{{1,512}}$"
)
AUTH_CALLBACK_ERROR_DESCRIPTION_PATTERN = r"[A-Za-z0-9._~-]{1,512}"
AUTH_CALLBACK_STATE_PATTERN = r"[A-Za-z0-9._~-]{1,512}"
AUTH_CALLBACK_ERROR_QUERY_PATTERNS = (
    rf"^error=access_denied&error_description={AUTH_CALLBACK_ERROR_DESCRIPTION_PATTERN}&state={AUTH_CALLBACK_STATE_PATTERN}$",
    rf"^error=access_denied&state={AUTH_CALLBACK_STATE_PATTERN}&error_description={AUTH_CALLBACK_ERROR_DESCRIPTION_PATTERN}$",
    rf"^error_description={AUTH_CALLBACK_ERROR_DESCRIPTION_PATTERN}&error=access_denied&state={AUTH_CALLBACK_STATE_PATTERN}$",
    rf"^error_description={AUTH_CALLBACK_ERROR_DESCRIPTION_PATTERN}&state={AUTH_CALLBACK_STATE_PATTERN}&error=access_denied$",
    rf"^state={AUTH_CALLBACK_STATE_PATTERN}&error=access_denied&error_description={AUTH_CALLBACK_ERROR_DESCRIPTION_PATTERN}$",
    rf"^state={AUTH_CALLBACK_STATE_PATTERN}&error_description={AUTH_CALLBACK_ERROR_DESCRIPTION_PATTERN}&error=access_denied$",
)
AUTH_CALLBACK_QUERY_PATTERNS = (
    AUTH_CALLBACK_CODE_STATE_PATTERN,
    AUTH_CALLBACK_STATE_CODE_PATTERN,
    *AUTH_CALLBACK_ERROR_QUERY_PATTERNS,
)
AUTH_CALLBACK_QUERY_GUARD = " || ".join(
    f"{{http.request.uri.query}}.matches('{pattern}')" for pattern in AUTH_CALLBACK_QUERY_PATTERNS
)
CHAT_TICKET_VALUE_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._~-]{0,511}"
CHAT_TICKET_QUERY_GUARD = f"{{http.request.uri.query}}.matches('^ticket={CHAT_TICKET_VALUE_PATTERN}$')"
PTY_TICKET_VALUE_PATTERN = CHAT_TICKET_VALUE_PATTERN
PTY_RESUME_VALUE_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._~-]{0,127}"
PTY_ATTACH_VALUE_PATTERN = PTY_TICKET_VALUE_PATTERN
PTY_QUERY_PARAMETER_PATTERNS = {
    "ticket": rf"ticket={PTY_TICKET_VALUE_PATTERN}",
    "resume": rf"resume={PTY_RESUME_VALUE_PATTERN}",
    "attach": rf"attach={PTY_ATTACH_VALUE_PATTERN}",
}


def _pty_query_patterns() -> tuple[str, ...]:
    """Return every order-independent exact PTY key-set permutation."""

    two_keys = (
        ("ticket", "resume"),
        ("resume", "ticket"),
    )
    three_keys = (
        ("ticket", "resume", "attach"),
        ("ticket", "attach", "resume"),
        ("resume", "ticket", "attach"),
        ("resume", "attach", "ticket"),
        ("attach", "ticket", "resume"),
        ("attach", "resume", "ticket"),
    )
    patterns = []
    for keys in (*two_keys, *three_keys):
        body = "&".join(PTY_QUERY_PARAMETER_PATTERNS[key] for key in keys)
        patterns.append(rf"^{body}$")
    return tuple(patterns)


PTY_QUERY_PATTERNS = _pty_query_patterns()
PTY_QUERY_GUARD = " || ".join(
    f"{{http.request.uri.query}}.matches('{pattern}')" for pattern in PTY_QUERY_PATTERNS
)
# Kept as a compatibility alias for callers of the original proof fixture.
TICKET_QUERY_GUARD = CHAT_TICKET_QUERY_GUARD

HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?$")


def _validate_host(host: str) -> str:
    if type(host) is not str or not HOST_RE.fullmatch(host) or ".." in host or host.endswith("."):
        raise ValueError("host must be a concrete lowercase DNS label")
    return host


def _validate_port(value: int, name: str) -> int:
    if type(value) is not int or not 1024 <= value <= 65535:
        raise ValueError(f"{name} must be a TCP port")
    return value


def _validate_path(value: str, name: str) -> str:
    """Validate a path before interpolating it into a quoted Caddyfile value.

    Rejecting rather than escaping keeps the rendered proof byte-for-byte
    deterministic and prevents a future caller from changing Caddy's parser
    context with a quote, backslash, placeholder, or control character. Path
    inputs are literal filesystem names; Caddy placeholders are not accepted.
    """

    if type(value) is not str:
        raise ValueError(f"{name} must be an absolute path")
    path = Path(value)
    if not value or not path.is_absolute():
        raise ValueError(f"{name} must be an absolute path")
    if any(character in value for character in ('"', "'", "\\")):
        raise ValueError(f"{name} must not contain Caddy quotes or backslashes")
    if "{" in value or "}" in value:
        raise ValueError(f"{name} must use a literal path without Caddy placeholders")
    if any(ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F for character in value):
        raise ValueError(f"{name} must not contain Caddy control characters")
    return value


def _validate_runtime_inputs(value: Mapping[str, object]) -> dict[str, object]:
    """Validate the complete non-sensitive renderer input contract."""

    if not isinstance(value, Mapping) or set(value) != set(DEFAULT_RUNTIME_INPUTS):
        raise ValueError("runtime_inputs must contain the exact renderer input keys")
    return {
        "host": _validate_host(value["host"]),
        "https_port": _validate_port(value["https_port"], "https_port"),
        "hermes_port": _validate_port(value["hermes_port"], "hermes_port"),
        "site_root": _validate_path(value["site_root"], "site_root"),
        "cert_path": _validate_path(value["cert_path"], "cert_path"),
        "key_path": _validate_path(value["key_path"], "key_path"),
        "storage_root": _validate_path(value["storage_root"], "storage_root"),
    }


def reconstruction_inputs() -> dict[str, object]:
    """Return the committed, safe inputs used to reconstruct retained evidence."""

    return dict(DEFAULT_RUNTIME_INPUTS)


def runtime_input_digest(value: Mapping[str, object]) -> str:
    """Hash normalized renderer inputs without retaining the rendered config."""

    normalized = _validate_runtime_inputs(value)
    encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return digest_bytes(encoded)


PARITY_FIXTURE_PATHS = {
    "static_route_grammar": "apps/web/src/lib/static-route-grammar.mjs",
    "deep_link_cases": "contracts/fixtures/deep-link-grammar/cases.json",
}


def parity_fixture_manifest() -> dict[str, dict[str, str]]:
    """Return relative source identities used by the local Caddy parity proof."""

    project_root = Path(__file__).resolve().parents[1]
    return {
        name: {
            "path": relative_path,
            "sha256": digest_bytes((project_root / relative_path).read_bytes()),
        }
        for name, relative_path in PARITY_FIXTURE_PATHS.items()
    }


def _proxy_snippet(name: str, hermes_port: int, *, prefix: str) -> list[str]:
    upstream = f"127.0.0.1:{hermes_port}"
    lines = [
        f"({name}) {{",
        # Caddy's request_header handler runs before reverse_proxy. Keeping the
        # wildcard deletion outside header_up is important: Caddy coalesces
        # header_up deletes and sets into one operation map, so deleting and
        # rebuilding the same field there would silently drop the trusted value.
        "    request_header -Forwarded",
        "    request_header -X-Forwarded-*",
        "    request_header -X-Real-IP",
        "    reverse_proxy " + upstream + " {",
        f"        header_up Host {upstream}",
        f"        header_up Origin http://{upstream}",
        "        header_up Forwarded \"for={http.request.remote.host};host={http.request.host};proto=https\"",
        "        header_up X-Forwarded-For {http.request.remote.host}",
        "        header_up X-Forwarded-Host {http.request.host}",
        "        header_up X-Forwarded-Proto https",
        "        header_up X-Real-IP {http.request.remote.host}",
    ]
    if prefix:
        lines.append("        header_up X-Forwarded-Prefix " + prefix)
    lines.extend(
        [
            '        header_down Set-Cookie "(?i)(.*)" "$1; Secure"',
            "    }",
            "}",
        ]
    )
    return lines


def _exact_matcher(
    name: str,
    method: str,
    paths: Iterable[str],
    *,
    websocket: bool = False,
    query_guard: str | None = None,
) -> list[str]:
    lines = [
        f"        @{name} {{",
        f"            method {method}",
        "            path " + " ".join(paths),
    ]
    if websocket:
        lines.extend(
            [
                "            header Upgrade websocket",
                "            header Connection *Upgrade*",
                f"            expression `{query_guard or CHAT_TICKET_QUERY_GUARD}`",
            ]
        )
    else:
        lines.append(f"            expression `{query_guard or REST_QUERY_GUARD}`")
    lines.append("        }")
    return lines


def _session_matcher(
    name: str,
    method: str,
    suffix: str,
    *,
    prefix: str = "/api",
) -> list[str]:
    expression = f"^{prefix}/sessions/{SESSION_ID_PATTERN}{suffix}$"
    return [
        f"        @{name} {{",
        f"            method {method}",
        f"            path_regexp {name} {expression}",
        f"            expression `{REST_QUERY_GUARD}`",
        "        }",
    ]


def _handler(name: str, snippet: str, *, strip_prefix: bool = False) -> list[str]:
    lines = [f"        handle @{name} {{"]
    if strip_prefix:
        lines.append("            uri strip_prefix /hermes")
    lines.append(f"            import {snippet}")
    lines.append("        }")
    return lines


def render_caddyfile(
    *,
    host: str,
    https_port: int,
    hermes_port: int,
    site_root: str,
    cert_path: str,
    key_path: str,
    storage_root: str,
) -> str:
    """Return the exact disposable Caddyfile for one proof run."""

    host = _validate_host(host)
    https_port = _validate_port(https_port, "https_port")
    hermes_port = _validate_port(hermes_port, "hermes_port")
    site_root = _validate_path(site_root, "site_root")
    cert_path = _validate_path(cert_path, "cert_path")
    key_path = _validate_path(key_path, "key_path")
    storage_root = _validate_path(storage_root, "storage_root")

    lines = [
        "{",
        "    auto_https disable_redirects",
        f'    storage file_system "{storage_root}/storage"',
        "}",
        "",
        *_proxy_snippet("root_hermes", hermes_port, prefix=""),
        "",
        *_proxy_snippet("dashboard_hermes", hermes_port, prefix="/hermes"),
        "",
        f"https://:{https_port} {{",
        "    bind 127.0.0.1",
        f'    tls "{cert_path}" "{key_path}"',
        f'    root * "{site_root}"',
        "    route {",
        f"        @bad_host expression `{{http.request.host}} != '{host}'`",
        '        respond @bad_host "host denied" 421',
        f"        @unsafe_raw expression `{RAW_URI_GUARD}`",
        '        respond @unsafe_raw "not found" 404',
        "",
        "        @bad_ws_origin {",
        "            method GET",
        "            path /api/ws /hermes/api/ws /api/pty /hermes/api/pty",
        "            header Upgrade websocket",
        "            not header Origin https://" + host + f":{https_port}",
        "        }",
        '        respond @bad_ws_origin "origin denied" 403',
        "",
    ]

    root_get = [
        path for method, path in EXACT_REST_ROUTES if method == "GET" and path != "/auth/callback"
    ]
    root_post = [path for method, path in EXACT_REST_ROUTES if method == "POST"]
    root_patch = [path for method, path in EXACT_REST_ROUTES if method == "PATCH"]
    lines.extend(_exact_matcher("root_rest_get", "GET", root_get))
    lines.extend(_handler("root_rest_get", "root_hermes"))
    lines.extend(
        _exact_matcher(
            "root_auth_callback",
            "GET",
            ("/auth/callback",),
            query_guard=AUTH_CALLBACK_QUERY_GUARD,
        )
    )
    lines.extend(_handler("root_auth_callback", "root_hermes"))
    lines.extend(_exact_matcher("root_rest_post", "POST", root_post))
    lines.extend(_handler("root_rest_post", "root_hermes"))
    if root_patch:
        lines.extend(_exact_matcher("root_rest_patch", "PATCH", root_patch))
        lines.extend(_handler("root_rest_patch", "root_hermes"))
    lines.extend(_session_matcher("root_session_get", "GET", ""))
    lines.extend(_handler("root_session_get", "root_hermes"))
    lines.extend(_session_matcher("root_messages_get", "GET", "/messages"))
    lines.extend(_handler("root_messages_get", "root_hermes"))
    lines.extend(_session_matcher("root_session_patch", "PATCH", ""))
    lines.extend(_handler("root_session_patch", "root_hermes"))

    lines.extend(_exact_matcher("root_chat_ws", "GET", ("/api/ws",), websocket=True, query_guard=CHAT_TICKET_QUERY_GUARD))
    lines.extend(_handler("root_chat_ws", "root_hermes"))
    lines.extend(_exact_matcher("root_pty_ws", "GET", ("/api/pty",), websocket=True, query_guard=PTY_QUERY_GUARD))
    lines.extend(_handler("root_pty_ws", "root_hermes"))

    dashboard_get = [
        f"/hermes{path}"
        for method, path in EXACT_REST_ROUTES
        if method == "GET" and path != "/auth/callback"
    ]
    dashboard_post = [f"/hermes{path}" for method, path in EXACT_REST_ROUTES if method == "POST"]
    dashboard_patch = [f"/hermes{path}" for method, path in EXACT_REST_ROUTES if method == "PATCH"]
    lines.extend(_exact_matcher("dashboard_rest_get", "GET", dashboard_get))
    lines.extend(_handler("dashboard_rest_get", "dashboard_hermes", strip_prefix=True))
    lines.extend(
        _exact_matcher(
            "dashboard_auth_callback",
            "GET",
            ("/hermes/auth/callback",),
            query_guard=AUTH_CALLBACK_QUERY_GUARD,
        )
    )
    lines.extend(_handler("dashboard_auth_callback", "dashboard_hermes", strip_prefix=True))
    lines.extend(_exact_matcher("dashboard_rest_post", "POST", dashboard_post))
    lines.extend(_handler("dashboard_rest_post", "dashboard_hermes", strip_prefix=True))
    if dashboard_patch:
        lines.extend(_exact_matcher("dashboard_rest_patch", "PATCH", dashboard_patch))
        lines.extend(_handler("dashboard_rest_patch", "dashboard_hermes", strip_prefix=True))
    lines.extend(_session_matcher("dashboard_session_get", "GET", "", prefix="/hermes/api"))
    lines.extend(_handler("dashboard_session_get", "dashboard_hermes", strip_prefix=True))
    lines.extend(_session_matcher("dashboard_messages_get", "GET", "/messages", prefix="/hermes/api"))
    lines.extend(_handler("dashboard_messages_get", "dashboard_hermes", strip_prefix=True))
    lines.extend(_session_matcher("dashboard_session_patch", "PATCH", "", prefix="/hermes/api"))
    lines.extend(_handler("dashboard_session_patch", "dashboard_hermes", strip_prefix=True))

    lines.extend(_exact_matcher("dashboard_chat_ws", "GET", ("/hermes/api/ws",), websocket=True, query_guard=CHAT_TICKET_QUERY_GUARD))
    lines.extend(_handler("dashboard_chat_ws", "dashboard_hermes", strip_prefix=True))
    lines.extend(_exact_matcher("dashboard_pty_ws", "GET", ("/hermes/api/pty",), websocket=True, query_guard=PTY_QUERY_GUARD))
    lines.extend(_handler("dashboard_pty_ws", "dashboard_hermes", strip_prefix=True))

    # Root is the one reviewed static exception that may carry a synthetic
    # scenario query. All other assets and canonical client routes are strictly
    # query-free and never fall through to a shell rewrite.
    static_asset_paths = tuple(path for path in STATIC_PATHS if path != "/")
    lines.extend(
        [
            "",
            "        @root_static {",
            "            method GET HEAD",
            "            path /",
            f"            expression `{ROOT_QUERY_GUARD}`",
            "        }",
            "        handle @root_static {",
            "            file_server",
            "        }",
            "",
            "        @static_query_mutation {",
            "            method GET HEAD",
            "            path " + " ".join(static_asset_paths),
            f"            expression `{QUERY_PRESENT_GUARD}`",
            "        }",
            '        respond @static_query_mutation "not found" 404',
            "",
            "        @client_query_mutation {",
            "            method GET HEAD",
            f"            path_regexp client_query_mutation {CLIENT_ROUTE_PREFIX_PATTERN}",
            f"            expression `{QUERY_PRESENT_GUARD}`",
            "        }",
            '        respond @client_query_mutation "not found" 404',
            "",
            "        @client_deep_link {",
            "            method GET HEAD",
            f"            path_regexp client_deep_link {CLIENT_ROUTE_PATTERN}",
            f"            expression `{NO_QUERY_GUARD}`",
            "        }",
            "        handle @client_deep_link {",
            "            rewrite * /200.html",
            "            file_server",
            "        }",
            "",
            "        @static {",
            "            method GET HEAD",
            "            path " + " ".join(static_asset_paths),
            f"            expression `{NO_QUERY_GUARD}`",
            "        }",
            "        handle @static {",
            "            file_server",
            "        }",
            "",
            "        handle {",
            '            respond "not found" 404',
            "        }",
            "    }",
            "}",
            "",
        ]
    )
    # Caddy's canonical formatter uses tabs for indentation. Emit that form
    # directly so the digest covers the exact runtime file, not an equivalent
    # but differently formatted pre-format source.
    formatted: list[str] = []
    for line in lines:
        if not line:
            formatted.append("")
            continue
        leading = len(line) - len(line.lstrip(" "))
        if leading % 4:
            raise ValueError("renderer indentation must use four-space levels")
        formatted.append("\t" * (leading // 4) + line[leading:])
    return "\n".join(formatted)


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def render_from_inputs(value: Mapping[str, object]) -> str:
    """Render the exact Caddyfile represented by a safe input manifest."""

    inputs = _validate_runtime_inputs(value)
    return render_caddyfile(**inputs)


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate object members before JSON semantics can collapse them."""

    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_nonfinite_json_constant(value: str) -> object:
    """Reject Python's non-standard NaN and Infinity JSON extensions."""

    raise ValueError(f"non-finite JSON constant: {value}")


def _scan_json_budgets(text: str, label: str) -> None:
    """Preflight JSON structure iteratively before the recursive stdlib decode."""

    index = 0
    length = len(text)
    stack: list[list[object]] = []
    root_done = False
    nodes = 0
    object_keys = 0
    total_string_bytes = 0

    def skip_whitespace(position: int) -> int:
        while position < length and text[position] in " \t\r\n":
            position += 1
        return position

    def record_string(value: str) -> None:
        nonlocal total_string_bytes
        size = len(value.encode("utf-8", "surrogatepass"))
        if size > JSON_MAX_STRING_BYTES:
            raise ValueError(f"{label} exceeds JSON string-bytes budget")
        total_string_bytes += size
        if total_string_bytes > JSON_MAX_TOTAL_STRING_BYTES:
            raise ValueError(f"{label} exceeds JSON total-string budget")

    def consume_value(position: int) -> tuple[int, bool]:
        nonlocal nodes
        if position >= length:
            raise ValueError(f"{label} is not valid JSON")
        character = text[position]
        if character == '"':
            try:
                value, end = json.decoder.scanstring(text, position + 1, True)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{label} is not valid JSON") from exc
            record_string(value)
            nodes += 1
            if nodes > JSON_MAX_NODES:
                raise ValueError(f"{label} exceeds JSON node budget")
            return end, False
        if character in "[{":
            nodes += 1
            if nodes > JSON_MAX_NODES:
                raise ValueError(f"{label} exceeds JSON node budget")
            depth = len(stack) + 1
            if depth > JSON_MAX_DEPTH:
                raise ValueError(f"{label} exceeds JSON depth budget")
            if character == "{":
                stack.append(["object", "key_or_end", 0])
            else:
                stack.append(["array", "value_or_end", 0])
            return position + 1, True
        start = position
        while position < length and text[position] not in " \t\r\n,]}:":
            position += 1
        if position == start:
            raise ValueError(f"{label} is not valid JSON")
        if position - start > JSON_MAX_STRING_BYTES:
            raise ValueError(f"{label} exceeds JSON string-bytes budget")
        nodes += 1
        if nodes > JSON_MAX_NODES:
            raise ValueError(f"{label} exceeds JSON node budget")
        return position, False

    while True:
        # Whitespace is legal after every delimiter, including while an
        # object or array frame is active. Skipping it here keeps the
        # preflight parser iterative and aligned with json.loads().
        index = skip_whitespace(index)
        if not stack:
            if root_done:
                if index != length:
                    raise ValueError(f"{label} is not valid JSON")
                return
            index, _ = consume_value(index)
            if not stack:
                root_done = True
            continue

        context = stack[-1]
        kind = context[0]
        state = context[1]
        if kind == "object":
            if state in {"key_or_end", "key"}:
                if text[index:index + 1] == "}" and state == "key_or_end":
                    stack.pop()
                    index += 1
                    if not stack:
                        root_done = True
                    continue
                if text[index:index + 1] != '"':
                    raise ValueError(f"{label} is not valid JSON")
                try:
                    key, index = json.decoder.scanstring(text, index + 1, True)
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"{label} is not valid JSON") from exc
                record_string(key)
                object_keys += 1
                context[2] = int(context[2]) + 1
                if object_keys > JSON_MAX_OBJECT_KEYS or int(context[2]) > JSON_MAX_OBJECT_KEYS:
                    raise ValueError(f"{label} exceeds JSON object-key budget")
                context[1] = "colon"
                continue
            if state == "colon":
                if text[index:index + 1] != ":":
                    raise ValueError(f"{label} is not valid JSON")
                context[1] = "value"
                index += 1
                continue
            if state == "value":
                index, _ = consume_value(index)
                context[1] = "comma_or_end"
                continue
            if state == "comma_or_end":
                character = text[index:index + 1]
                if character == ",":
                    context[1] = "key"
                    index += 1
                    continue
                if character == "}":
                    stack.pop()
                    index += 1
                    if not stack:
                        root_done = True
                    continue
                raise ValueError(f"{label} is not valid JSON")
            raise ValueError(f"{label} is not valid JSON")

        if kind == "array":
            if state in {"value_or_end", "value"}:
                if text[index:index + 1] == "]" and state == "value_or_end":
                    stack.pop()
                    index += 1
                    if not stack:
                        root_done = True
                    continue
                context[2] = int(context[2]) + 1
                if int(context[2]) > JSON_MAX_ARRAY_LENGTH:
                    raise ValueError(f"{label} exceeds JSON array-length budget")
                index, _ = consume_value(index)
                context[1] = "comma_or_end"
                continue
            if state == "comma_or_end":
                character = text[index:index + 1]
                if character == ",":
                    context[1] = "value"
                    index += 1
                    continue
                if character == "]":
                    stack.pop()
                    index += 1
                    if not stack:
                        root_done = True
                    continue
                raise ValueError(f"{label} is not valid JSON")
            raise ValueError(f"{label} is not valid JSON")
        raise ValueError(f"{label} is not valid JSON")


def _parse_json_float(value: str) -> float:
    """Reject exponent overflow instead of allowing Python's ``inf`` result."""

    try:
        parsed = float(value)
    except (OverflowError, ValueError) as exc:
        raise ValueError(f"non-finite JSON number: {value}") from exc
    if not math.isfinite(parsed):
        raise ValueError(f"non-finite JSON number: {value}")
    return parsed


def _parse_json_int(value: str) -> int:
    """Keep integer conversion bounded independently of the byte cap."""

    digits = value[1:] if value.startswith("-") else value
    if len(digits) > JSON_MAX_STRING_BYTES:
        raise ValueError("JSON integer exceeds string-bytes budget")
    return int(value)


def _decode_bounded_json(raw: bytes, label: str) -> object:
    """Decode bounded UTF-8 JSON with iterative resource validation."""

    if type(raw) is not bytes:
        raise ValueError(f"{label} is not valid bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not valid UTF-8") from exc
    try:
        _scan_json_budgets(text, label)
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonfinite_json_constant,
            parse_float=_parse_json_float,
            parse_int=_parse_json_int,
        )
    except ValueError as exc:
        message = str(exc)
        if message.startswith(f"{label} exceeds JSON "):
            raise
        if message == "duplicate JSON object key":
            raise ValueError(f"{label} contains a duplicate JSON object key") from exc
        if message.startswith("non-finite JSON"):
            raise ValueError(f"{label} contains a non-finite JSON number") from exc
        if message.startswith("JSON integer exceeds"):
            raise ValueError(f"{label} exceeds JSON integer budget") from exc
        raise ValueError(f"{label} is not valid JSON") from exc


def _metadata_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int]:
    """Bind filesystem identity, including mutation timestamps."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_size,
        metadata.st_nlink,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _metadata_pin_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int]:
    """Bind stable descriptor identity, including type and size."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_size,
    )


def _metadata_parent_pin_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    """Bind parent lookup identity without volatile directory size."""

    return (metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode))


def _new_git_operation_deadline() -> float:
    """Start the one bounded budget shared by metadata validation and Git."""

    return time.monotonic() + GIT_COMMAND_TIMEOUT_SECONDS


class _GitOperationTimeout(ValueError):
    """Identify deadline failures so trust wrappers cannot relabel them."""


def _check_git_operation_deadline(deadline: float | None, phase: str) -> None:
    """Fail closed when any pre/post Git trust phase overruns its budget."""

    if deadline is not None and time.monotonic() >= deadline:
        raise _GitOperationTimeout(f"Git provenance operation timed out during {phase}")


class _BoundGitCommand(list[str]):
    """List-shaped Git argv carrying the descriptor-bound working directory."""

    __slots__ = ("cwd_fd", "deadline")

    def __init__(
        self,
        values: Iterable[str],
        *,
        cwd_fd: int | None = None,
        deadline: float | None = None,
    ) -> None:
        super().__init__(values)
        self.cwd_fd = cwd_fd
        self.deadline = deadline


class _GitMetadataPin:
    """Keep one descriptor-relative Git metadata entry pinned for a command."""

    __slots__ = (
        "path",
        "parent_fd",
        "parent_identity",
        "name",
        "descriptor",
        "identity",
        "content",
        "entries",
        "label",
    )

    def __init__(
        self,
        *,
        path: Path,
        parent_fd: int,
        parent_identity: tuple[int, int, int],
        name: str,
        descriptor: int | None,
        identity: tuple[int, int, int, int] | None,
        content: bytes | None,
        entries: tuple[
            tuple[str, tuple[int, int, int, int, int, int, int, int], str | None], ...
        ] | None,
        label: str,
    ) -> None:
        self.path = path
        self.parent_fd = parent_fd
        self.parent_identity = parent_identity
        self.name = name
        self.descriptor = descriptor
        self.identity = identity
        self.content = content
        self.entries = entries
        self.label = label

    def close(self) -> None:
        descriptor = self.descriptor
        self.descriptor = None
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        parent_fd = self.parent_fd
        self.parent_fd = -1
        if parent_fd >= 0:
            try:
                os.close(parent_fd)
            except OSError:
                pass



def _verify_regular_metadata(
    metadata: os.stat_result,
    *,
    limit: int | None,
    label: str,
    allow_hard_links: bool = False,
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} is not a regular file")
    if metadata.st_uid != os.geteuid():
        raise ValueError(f"{label} has an unexpected owner")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ValueError(f"{label} is writable by group or other users")
    if metadata.st_mode & (stat.S_ISUID | stat.S_ISGID):
        raise ValueError(f"{label} has unsafe mode bits")
    if not allow_hard_links and metadata.st_nlink != 1:
        raise ValueError(f"{label} has unexpected hard links")
    if limit is not None and metadata.st_size > limit:
        raise ValueError(f"{label} exceeds the bounded input size")


def _open_verified_regular_file_at(
    parent_fd: int,
    name: str,
    *,
    limit: int | None,
    label: str,
    allow_hard_links: bool = False,
    deadline: float | None = None,
) -> tuple[int, os.stat_result]:
    """Open one directory entry with no-follow and race-checked identity."""

    if type(name) is not str or not name or name in {".", ".."} or "/" in name:
        raise ValueError(f"{label} has an invalid pathname component")
    _check_git_operation_deadline(deadline, f"opening {label}")
    try:
        pre_open = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _check_git_operation_deadline(deadline, f"opening {label}")
        _verify_regular_metadata(
            pre_open,
            limit=limit,
            label=label,
            allow_hard_links=allow_hard_links,
        )
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        descriptor = os.open(name, flags, dir_fd=parent_fd)
        try:
            _check_git_operation_deadline(deadline, f"opening {label}")
            post_open = os.fstat(descriptor)
            _check_git_operation_deadline(deadline, f"opening {label}")
            _verify_regular_metadata(
                post_open,
                limit=limit,
                label=label,
                allow_hard_links=allow_hard_links,
            )
            if _metadata_identity(pre_open) != _metadata_identity(post_open):
                raise ValueError(f"{label} changed during open")
            return descriptor, post_open
        except BaseException:
            os.close(descriptor)
            raise
    except ValueError:
        raise
    except (OSError, RuntimeError, TypeError) as exc:
        raise ValueError(f"{label} could not be opened safely") from exc


def _open_verified_directory_at(
    parent_fd: int,
    name: str,
    *,
    label: str,
    deadline: float | None = None,
) -> int:
    """Open one directory component without following symlink races."""

    if type(name) is not str or not name or name in {".", ".."} or "/" in name:
        raise ValueError(f"{label} has an invalid pathname component")
    _check_git_operation_deadline(deadline, f"opening {label}")
    try:
        pre_open = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _check_git_operation_deadline(deadline, f"opening {label}")
        if not stat.S_ISDIR(pre_open.st_mode):
            raise ValueError(f"{label} is not a directory")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        descriptor = os.open(name, flags, dir_fd=parent_fd)
        try:
            _check_git_operation_deadline(deadline, f"opening {label}")
            post_open = os.fstat(descriptor)
            _check_git_operation_deadline(deadline, f"opening {label}")
            if not stat.S_ISDIR(post_open.st_mode):
                raise ValueError(f"{label} is not a directory")
            if (pre_open.st_dev, pre_open.st_ino) != (post_open.st_dev, post_open.st_ino):
                raise ValueError(f"{label} changed during open")
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise
    except ValueError:
        raise
    except (OSError, RuntimeError, TypeError) as exc:
        raise ValueError(f"{label} could not be opened safely") from exc


def _open_verified_parent(
    path: Path,
    *,
    label: str,
    deadline: float | None = None,
    resolve_parent_aliases: bool = True,
) -> tuple[int, str]:
    """Walk parent descriptors with O_NOFOLLOW for every opened component.

    Generic disposable inputs may be presented through a platform alias such
    as macOS's ``/var`` symlink, so only their parent spelling is normalized.
    The retained loader passes ``resolve_parent_aliases=False`` and compares
    the raw canonical pathname before this walk, making aliases ineligible.
    """

    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    if resolve_parent_aliases:
        try:
            candidate = candidate.parent.resolve(strict=True) / candidate.name
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise ValueError(f"{label} parent could not be resolved") from exc
    parts = candidate.parts
    if len(parts) < 2 or parts[0] != "/" or any(part in {"", ".", ".."} for part in parts[1:]):
        raise ValueError(f"{label} has a non-canonical pathname")
    try:
        _check_git_operation_deadline(deadline, f"opening {label} parent")
        current_fd = os.open(
            "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        _check_git_operation_deadline(deadline, f"opening {label} parent")
        for component in parts[1:-1]:
            _check_git_operation_deadline(deadline, f"opening {label} parent")
            next_fd = _open_verified_directory_at(
                current_fd,
                component,
                label=f"{label} parent",
                deadline=deadline,
            )
            os.close(current_fd)
            current_fd = next_fd
        _check_git_operation_deadline(deadline, f"opening {label} parent")
        return current_fd, parts[-1]
    except BaseException:
        try:
            os.close(current_fd)
        except (OSError, UnboundLocalError):
            pass
        raise


def _snapshot_git_metadata_tree(
    descriptor: int,
    *,
    label: str,
    content_budget: list[int] | None = None,
    deadline: float | None = None,
) -> tuple[
    tuple[str, tuple[int, int, int, int, int, int, int, int], str | None], ...
]:
    """Snapshot a bounded metadata tree without following any nested link.

    Git selects commits through ``HEAD`` and refs, then reads loose objects and
    pack files. Pinning only the top-level directory entries leaves a same-name
    nested ref, loose object, or pack sidecar free to change in place. This
    descriptor-relative walk records every descendant's relative path, full
    type/identity/size tuple, and SHA-256 digest of bounded content. Directory
    entries retain ``None`` content; regular entries retain their content
    digest. Any symlink or special file fails closed.
    """

    entries: list[
        tuple[str, tuple[int, int, int, int, int, int, int, int], str | None]
    ] = []
    if content_budget is None:
        content_budget = [0]

    def read_children(directory_fd: int) -> list[Any]:
        _check_git_operation_deadline(deadline, f"scanning {label}")
        try:
            with os.scandir(directory_fd) as iterator:
                children = list(iterator)
        except (OSError, RuntimeError, TypeError) as exc:
            raise ValueError(f"{label} could not be inspected") from exc
        _check_git_operation_deadline(deadline, f"scanning {label}")
        if len(children) > GIT_METADATA_ENTRY_MAX:
            raise ValueError(f"{label} exceeds the bounded entry count")
        children.sort(key=lambda item: item.name)
        return children

    # Keep only one descriptor per recursive level. Directory children are
    # materialized as bounded names, then their descriptor is closed as soon as
    # that frame is exhausted; a large refs tree cannot exhaust the fd table.
    stack: list[tuple[int, tuple[str, ...], list[Any], int, bool]] = [
        (descriptor, (), read_children(descriptor), 0, False)
    ]
    try:
        while stack:
            _check_git_operation_deadline(deadline, f"scanning {label}")
            directory_fd, prefix, children, index, owned = stack[-1]
            if index >= len(children):
                stack.pop()
                if owned:
                    os.close(directory_fd)
                continue
            child = children[index]
            stack[-1] = (directory_fd, prefix, children, index + 1, owned)
            name = child.name
            if not isinstance(name, str) or not name or name in {".", ".."} or "/" in name:
                raise ValueError(f"{label} contains an invalid pathname entry")
            relative_parts = (*prefix, name)
            if len(relative_parts) > GIT_METADATA_MAX_DEPTH:
                raise ValueError(f"{label} exceeds the bounded depth")
            relative = "/".join(relative_parts)
            _check_git_operation_deadline(deadline, f"scanning {label}")
            try:
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                _check_git_operation_deadline(deadline, f"scanning {label}")
            except _GitOperationTimeout:
                raise
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                raise ValueError(f"{label} entry could not be inspected") from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError(f"{label} contains a symlink: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                child_fd = _open_verified_directory_at(
                    directory_fd,
                    name,
                    label=f"{label} directory",
                    deadline=deadline,
                )
                try:
                    _check_git_operation_deadline(deadline, f"scanning {label}")
                    child_metadata = os.fstat(child_fd)
                    _check_git_operation_deadline(deadline, f"scanning {label}")
                    if _metadata_identity(child_metadata) != _metadata_identity(metadata):
                        raise ValueError(f"{label} directory changed during pinning")
                    child_children = read_children(child_fd)
                except BaseException:
                    os.close(child_fd)
                    raise
                entries.append((relative, _metadata_identity(child_metadata), None))
                if len(entries) > GIT_METADATA_ENTRY_MAX:
                    os.close(child_fd)
                    raise ValueError(f"{label} exceeds the bounded entry count")
                stack.append((child_fd, relative_parts, child_children, 0, True))
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"{label} contains a special file: {relative}")
            descriptor_for_file, descriptor_metadata = _open_verified_regular_file_at(
                directory_fd,
                name,
                limit=GIT_METADATA_FILE_MAX_BYTES,
                label=f"{label} file",
                allow_hard_links=True,
                deadline=deadline,
            )
            try:
                if _metadata_identity(descriptor_metadata) != _metadata_identity(metadata):
                    raise ValueError(f"{label} file changed during pinning")
                _check_git_operation_deadline(deadline, f"reading {label}")
                content = _read_bounded_fd(
                    descriptor_for_file,
                    GIT_METADATA_FILE_MAX_BYTES,
                    f"{label} file",
                    deadline=deadline,
                )
                _check_git_operation_deadline(deadline, f"reading {label}")
                after_read = os.fstat(descriptor_for_file)
                _check_git_operation_deadline(deadline, f"reading {label}")
                if _metadata_identity(after_read) != _metadata_identity(descriptor_metadata):
                    raise ValueError(f"{label} file changed during pinning")
                if len(content) != after_read.st_size:
                    raise ValueError(f"{label} file changed during pinning")
            finally:
                os.close(descriptor_for_file)
            _check_git_operation_deadline(deadline, f"reading {label}")
            content_budget[0] += len(content)
            if content_budget[0] > GIT_METADATA_TOTAL_CONTENT_MAX_BYTES:
                raise ValueError(f"{label} exceeds the bounded content size")
            entries.append((relative, _metadata_identity(descriptor_metadata), digest_bytes(content)))
            _check_git_operation_deadline(deadline, f"reading {label}")
            if len(entries) > GIT_METADATA_ENTRY_MAX:
                raise ValueError(f"{label} exceeds the bounded entry count")
    finally:
        for directory_fd, _prefix, _children, _index, owned in reversed(stack):
            if owned:
                try:
                    os.close(directory_fd)
                except OSError:
                    pass
    entries.sort(key=lambda item: item[0])
    return tuple(entries)


def _open_git_metadata_pin_parent(
    path: Path,
    *,
    label: str,
    deadline: float | None = None,
) -> tuple[int, str]:
    """Open the deepest existing parent and pin the first missing component."""

    candidate = Path(path)
    if not candidate.is_absolute():
        raise ValueError(f"{label} has a non-absolute pathname")
    parts = candidate.parts
    if len(parts) < 2 or parts[0] != "/" or any(
        part in {"", ".", ".."} or "/" in part for part in parts[1:]
    ):
        raise ValueError(f"{label} has a non-canonical pathname")
    current_fd: int | None = None
    try:
        _check_git_operation_deadline(deadline, f"opening {label} parent")
        current_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        _check_git_operation_deadline(deadline, f"opening {label} parent")
        for component in parts[1:-1]:
            _check_git_operation_deadline(deadline, f"opening {label} parent")
            try:
                metadata = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
                _check_git_operation_deadline(deadline, f"opening {label} parent")
            except FileNotFoundError:
                _check_git_operation_deadline(deadline, f"opening {label} parent")
                return current_fd, component
            except _GitOperationTimeout:
                raise
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                raise ValueError(f"{label} parent could not be inspected") from exc
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise ValueError(f"{label} parent is unsafe")
            next_fd = _open_verified_directory_at(
                current_fd,
                component,
                label=f"{label} parent",
                deadline=deadline,
            )
            os.close(current_fd)
            current_fd = next_fd
        _check_git_operation_deadline(deadline, f"opening {label} parent")
        return current_fd, parts[-1]
    except BaseException:
        if current_fd is not None:
            try:
                os.close(current_fd)
            except OSError:
                pass
        raise


def _pin_git_metadata_path(
    path: Path,
    *,
    label: str,
    pin_content: bool,
    pin_entries: bool,
    content_budget: list[int] | None = None,
    deadline: float | None = None,
) -> _GitMetadataPin:
    """Retain descriptor, identity, and bounded bytes for one Git path."""

    _check_git_operation_deadline(deadline, f"pinning {label}")
    parent_fd, name = _open_git_metadata_pin_parent(path, label=label, deadline=deadline)
    descriptor: int | None = None
    try:
        _check_git_operation_deadline(deadline, f"pinning {label}")
        parent_identity = _metadata_parent_pin_identity(os.fstat(parent_fd))
        _check_git_operation_deadline(deadline, f"pinning {label}")
        try:
            entry_metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            _check_git_operation_deadline(deadline, f"pinning {label}")
        except FileNotFoundError:
            _check_git_operation_deadline(deadline, f"pinning {label}")
            return _GitMetadataPin(
                path=path,
                parent_fd=parent_fd,
                parent_identity=parent_identity,
                name=name,
                descriptor=None,
                identity=None,
                content=None,
                entries=None,
                label=label,
            )
        if stat.S_ISLNK(entry_metadata.st_mode):
            raise ValueError(f"{label} must not be a symlink")
        if stat.S_ISDIR(entry_metadata.st_mode):
            descriptor = _open_verified_directory_at(
                parent_fd,
                name,
                label=label,
                deadline=deadline,
            )
        elif stat.S_ISREG(entry_metadata.st_mode):
            descriptor, entry_metadata = _open_verified_regular_file_at(
                parent_fd,
                name,
                limit=GIT_CONFIG_MAX_BYTES if pin_content else None,
                label=label,
                deadline=deadline,
            )
        else:
            raise ValueError(f"{label} is not a regular file or directory")
        _check_git_operation_deadline(deadline, f"pinning {label}")
        descriptor_metadata = os.fstat(descriptor)
        _check_git_operation_deadline(deadline, f"pinning {label}")
        identity = _metadata_pin_identity(descriptor_metadata)
        if identity != _metadata_pin_identity(entry_metadata):
            raise ValueError(f"{label} changed during pinning")
        content: bytes | None = None
        entries: tuple[
            tuple[str, tuple[int, int, int, int, int, int, int, int], str | None], ...
        ] | None = None
        if stat.S_ISDIR(descriptor_metadata.st_mode):
            if pin_entries:
                entries = _snapshot_git_metadata_tree(
                    descriptor,
                    label=label,
                    content_budget=content_budget,
                    deadline=deadline,
                )
        elif pin_content:
            _check_git_operation_deadline(deadline, f"reading {label}")
            content = _read_bounded_fd(
                descriptor,
                GIT_CONFIG_MAX_BYTES,
                label,
                deadline=deadline,
            )
            _check_git_operation_deadline(deadline, f"reading {label}")
            if len(content) != descriptor_metadata.st_size:
                raise ValueError(f"{label} changed during pinning")
            if content_budget is not None:
                content_budget[0] += len(content)
                if content_budget[0] > GIT_METADATA_TOTAL_CONTENT_MAX_BYTES:
                    raise ValueError(f"{label} exceeds the bounded content size")
        _check_git_operation_deadline(deadline, f"pinning {label}")
        return _GitMetadataPin(
            path=path,
            parent_fd=parent_fd,
            parent_identity=parent_identity,
            name=name,
            descriptor=descriptor,
            identity=identity,
            content=content,
            entries=entries,
            label=label,
        )
    except BaseException:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            os.close(parent_fd)
        except OSError:
            pass
        raise


def _assert_git_metadata_pin(
    pin: _GitMetadataPin,
    *,
    phase: str,
    deadline: float | None = None,
) -> None:
    """Fail closed when a pinned Git entry or its bytes changed."""

    _check_git_operation_deadline(deadline, f"checking {pin.label} {phase}")
    try:
        parent_metadata = os.fstat(pin.parent_fd)
        _check_git_operation_deadline(deadline, f"checking {pin.label} {phase}")
    except _GitOperationTimeout:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ValueError(f"Git metadata {pin.label} parent changed {phase}") from exc
    if _metadata_parent_pin_identity(parent_metadata) != pin.parent_identity:
        raise ValueError(f"Git metadata {pin.label} parent changed {phase}")
    try:
        current = os.stat(pin.name, dir_fd=pin.parent_fd, follow_symlinks=False)
        _check_git_operation_deadline(deadline, f"checking {pin.label} {phase}")
    except FileNotFoundError as exc:
        _check_git_operation_deadline(deadline, f"checking {pin.label} {phase}")
        if pin.identity is None:
            return
        raise ValueError(f"Git metadata {pin.label} disappeared {phase}") from exc
    except _GitOperationTimeout:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ValueError(f"Git metadata {pin.label} could not be checked {phase}") from exc
    current_identity = _metadata_pin_identity(current)
    if pin.identity is None:
        raise ValueError(f"Git metadata {pin.label} appeared {phase}")
    if current_identity != pin.identity:
        raise ValueError(f"Git metadata {pin.label} identity changed {phase}")
    if pin.descriptor is None:
        raise ValueError(f"Git metadata {pin.label} descriptor is missing")
    try:
        descriptor_metadata = os.fstat(pin.descriptor)
        _check_git_operation_deadline(deadline, f"checking {pin.label} {phase}")
    except _GitOperationTimeout:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ValueError(f"Git metadata {pin.label} descriptor changed {phase}") from exc
    if _metadata_pin_identity(descriptor_metadata) != pin.identity:
        raise ValueError(f"Git metadata {pin.label} descriptor changed {phase}")
    if pin.entries is not None:
        try:
            current_entries = _snapshot_git_metadata_tree(
                pin.descriptor,
                label=pin.label,
                deadline=deadline,
            )
            _check_git_operation_deadline(deadline, f"checking {pin.label} {phase}")
        except _GitOperationTimeout:
            raise
        except ValueError as exc:
            raise ValueError(f"Git metadata {pin.path} entries changed {phase}") from exc
        if current_entries != pin.entries:
            raise ValueError(f"Git metadata {pin.path} entries changed {phase}")
    if pin.content is not None:
        if descriptor_metadata.st_size != len(pin.content):
            raise ValueError(f"Git metadata {pin.label} byte length changed {phase}")
        pread = getattr(os, "pread", None)
        if not callable(pread):
            raise ValueError(f"Git metadata {pin.label} bytes cannot be checked")
        offset = 0
        while offset < len(pin.content):
            _check_git_operation_deadline(deadline, f"checking {pin.label} {phase}")
            try:
                chunk = pread(
                    pin.descriptor,
                    min(64 * 1024, len(pin.content) - offset),
                    offset,
                )
            except (OSError, RuntimeError, TypeError) as exc:
                raise ValueError(f"Git metadata {pin.label} bytes could not be checked") from exc
            if not chunk or chunk != pin.content[offset : offset + len(chunk)]:
                raise ValueError(f"Git metadata {pin.label} bytes changed {phase}")
            offset += len(chunk)
            _check_git_operation_deadline(deadline, f"checking {pin.label} {phase}")


def _assert_git_metadata_pins(
    pins: tuple[_GitMetadataPin, ...],
    *,
    phase: str,
    deadline: float | None = None,
) -> None:
    for pin in pins:
        _check_git_operation_deadline(deadline, f"checking Git metadata {phase}")
        _assert_git_metadata_pin(pin, phase=phase, deadline=deadline)


def _close_git_metadata_pins(pins: tuple[_GitMetadataPin, ...]) -> None:
    for pin in reversed(pins):
        pin.close()


def _run_with_git_metadata_pins(
    pins: tuple[_GitMetadataPin, ...],
    operation: Any,
    *,
    deadline: float | None = None,
) -> Any:
    """Run one provenance command with descriptor and byte pins held."""

    _assert_git_metadata_pins(pins, phase="before command", deadline=deadline)
    operation_error: Exception | None = None
    result: Any = None
    try:
        result = operation()
    except Exception as exc:
        operation_error = exc
    try:
        _assert_git_metadata_pins(pins, phase="after command", deadline=deadline)
    except _GitOperationTimeout:
        raise
    except ValueError as exc:
        raise ValueError("Git metadata changed during provenance command") from exc
    if operation_error is not None:
        raise operation_error
    return result


def _read_bounded_fd(
    descriptor: int,
    limit: int,
    label: str,
    *,
    deadline: float | None = None,
) -> bytes:
    """Read at most limit+1 bytes from a stable descriptor.

    A deadline check follows every ``os.read`` call, including the EOF read, so
    a slow kernel/filesystem operation cannot return accepted data after the
    caller's end-to-end budget has expired.
    """

    if type(limit) is not int or limit < 0:
        raise ValueError(f"{label} has an invalid bounded input size")
    chunks = bytearray()
    while len(chunks) <= limit:
        if deadline is not None and time.monotonic() >= deadline:
            raise _GitOperationTimeout(f"{label} read deadline exceeded")
        remaining = limit + 1 - len(chunks)
        try:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
        except (OSError, RuntimeError, TypeError) as exc:
            raise ValueError(f"{label} could not be read") from exc
        if deadline is not None and time.monotonic() >= deadline:
            raise _GitOperationTimeout(f"{label} read deadline exceeded")
        if not chunk:
            break
        chunks.extend(chunk)
        if len(chunks) > limit:
            raise ValueError(f"{label} exceeds the bounded input size")
    if deadline is not None and time.monotonic() >= deadline:
        raise _GitOperationTimeout(f"{label} read deadline exceeded")
    return bytes(chunks)


def _verify_fd_content_identity(
    descriptor: int,
    expected: bytes,
    label: str,
    *,
    deadline: float,
) -> None:
    """Compare a second bounded descriptor view with the bytes being hashed.

    Timestamps catch ordinary in-place replacement races. The second
    descriptor-relative pass also binds the content itself, so a filesystem
    that preserves or restores timestamps cannot silently change same-sized
    bytes between the first read and the acceptance checks.
    """

    pread = getattr(os, "pread", None)
    if not callable(pread):
        raise ValueError(f"{label} content identity cannot be verified")
    offset = 0
    while offset < len(expected):
        if time.monotonic() >= deadline:
            raise _GitOperationTimeout(f"{label} read deadline exceeded")
        try:
            chunk = pread(descriptor, min(64 * 1024, len(expected) - offset), offset)
        except (OSError, RuntimeError, TypeError) as exc:
            raise ValueError(f"{label} content identity could not be read") from exc
        if time.monotonic() >= deadline:
            raise _GitOperationTimeout(f"{label} read deadline exceeded")
        if not chunk or chunk != expected[offset : offset + len(chunk)]:
            raise ValueError(f"{label} content changed during read")
        offset += len(chunk)
    if time.monotonic() >= deadline:
        raise _GitOperationTimeout(f"{label} read deadline exceeded")


def _read_verified_file_path(
    path: Path,
    limit: int,
    label: str,
    *,
    deadline: float | None = None,
) -> bytes:
    """Read a bounded regular file while honoring the caller's total budget."""

    _check_git_operation_deadline(deadline, f"opening {label}")
    parent_fd, name = _open_verified_parent(path, label=label, deadline=deadline)
    descriptor: int | None = None
    try:
        _check_git_operation_deadline(deadline, f"opening {label}")
        descriptor, metadata = _open_verified_regular_file_at(
            parent_fd,
            name,
            limit=limit,
            label=label,
            deadline=deadline,
        )
        _check_git_operation_deadline(deadline, f"reading {label}")
        data = _read_bounded_fd(descriptor, limit, label, deadline=deadline)
        _check_git_operation_deadline(deadline, f"reading {label}")
        after_read = os.fstat(descriptor)
        _check_git_operation_deadline(deadline, f"reading {label}")
        if _metadata_identity(metadata) != _metadata_identity(after_read):
            raise ValueError(f"{label} changed during read")
        try:
            after_entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            _check_git_operation_deadline(deadline, f"reading {label}")
            _verify_regular_metadata(after_entry, limit=limit, label=label)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            if isinstance(exc, ValueError):
                raise
            raise ValueError(f"{label} changed after read") from exc
        if _metadata_identity(metadata) != _metadata_identity(after_entry):
            raise ValueError(f"{label} changed after read")
        _check_git_operation_deadline(deadline, f"reading {label}")
        return data
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)


def _read_bounded_bytes(path: Path, limit: int, label: str) -> bytes:
    """Read one bounded regular file through stable descriptor metadata."""

    return _read_verified_file_path(Path(path), limit, label)


def _load_bounded_json(path: Path, *, limit: int, label: str) -> object:
    """Decode one bounded UTF-8 JSON document with duplicate-key rejection."""

    return _decode_bounded_json(_read_bounded_bytes(path, limit, label), label)


def _trusted_git_path() -> Path:
    """Use one validated absolute Git executable, never caller-controlled PATH."""

    path = TRUSTED_GIT_EXECUTABLE
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError("trusted Git executable is not absolute")
    try:
        metadata = os.lstat(path)
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ValueError("trusted Git executable is unavailable") from exc
    if resolved != path or not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111:
        raise ValueError("trusted Git executable is unsafe")
    if metadata.st_uid not in {0, os.geteuid()} or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ValueError("trusted Git executable is unsafe")
    return path


def _strict_git_environment() -> dict[str, str]:
    """Keep Git local, deterministic, non-fetching, and free of redirects."""

    environment = os.environ.copy()
    for variable in tuple(environment):
        if variable.startswith("GIT_"):
            environment.pop(variable, None)
    for variable in GIT_REDIRECT_ENV_VARS:
        environment.pop(variable, None)
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_COUNT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1",
            # Leave graft/alternate selectors unset; repository metadata checks
            # below reject those files rather than pointing Git at /dev/null,
            # which itself is interpreted as a graft file on some Git builds.
            "PATH": TRUSTED_HELPER_PATH,
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    return environment


def _close_git_stream(selector: selectors.BaseSelector | None, stream: Any) -> None:
    if selector is not None:
        try:
            selector.unregister(stream)
        except (KeyError, OSError, ValueError):
            pass
    try:
        stream.close()
    except (AttributeError, OSError, ValueError):
        pass


def _signal_git_group(process: subprocess.Popen[bytes], signal_number: int) -> None:
    try:
        os.killpg(process.pid, signal_number)
        return
    except (AttributeError, OSError, RuntimeError, ValueError):
        pass
    try:
        if signal_number == signal.SIGKILL:
            process.kill()
        else:
            process.terminate()
    except (AttributeError, OSError, RuntimeError, ValueError, subprocess.SubprocessError):
        pass


def _git_process_group_exists(process: subprocess.Popen[bytes]) -> bool:
    """Return whether a started Git process group still has a live member."""

    pid = getattr(process, "pid", None)
    if type(pid) is not int or pid <= 0:
        raise ValueError("Git process group identity is malformed")
    try:
        os.killpg(pid, 0)
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return False
        if exc.errno in {errno.EPERM, errno.EACCES}:
            return True
        raise ValueError("Git process group liveness could not be checked") from exc
    except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
        raise ValueError("Git process group liveness could not be checked") from exc
    return True


def _ensure_git_process_group_quiescent(
    process: subprocess.Popen[bytes],
    deadline: float,
) -> None:
    """Kill remaining descendants before accepting direct-child success."""

    if not _git_process_group_exists(process):
        return
    _signal_git_group(process, signal.SIGTERM)
    while _git_process_group_exists(process):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            process.wait(timeout=min(0.01, remaining))
        except (AttributeError, OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            pass
        time.sleep(min(0.005, max(0.0, remaining)))
    if not _git_process_group_exists(process):
        raise ValueError("Git process group had live descendants")
    _signal_git_group(process, signal.SIGKILL)
    while _git_process_group_exists(process):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("Git process group did not exit within deadline")
        try:
            process.wait(timeout=min(0.01, remaining))
        except (AttributeError, OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            pass
        time.sleep(min(0.005, max(0.0, remaining)))
    raise ValueError("Git process group had live descendants")


def _terminate_and_drain_git(
    process: subprocess.Popen[bytes] | None,
    selector: selectors.BaseSelector | None,
    streams: tuple[Any, ...] = (),
    *,
    deadline: float | None = None,
) -> None:
    cleanup_deadline = deadline if deadline is not None else time.monotonic() + 1.0
    if process is not None:
        _signal_git_group(process, signal.SIGTERM)
        try:
            timeout = 0.25 if deadline is None else max(0.0, min(0.25, deadline - time.monotonic()))
            process.wait(timeout=timeout)
        except (AttributeError, OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            pass
        _signal_git_group(process, signal.SIGKILL)
        try:
            # Reap the direct child even when the shared command budget has
            # already expired; descendants remain covered by the group kill.
            process.wait(timeout=0.25)
        except (AttributeError, OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            pass
    if selector is not None:
        while True:
            try:
                registered = selector.get_map()
            except (OSError, RuntimeError, ValueError):
                break
            if not registered or time.monotonic() >= cleanup_deadline:
                break
            try:
                events = selector.select(max(0.0, cleanup_deadline - time.monotonic()))
            except (OSError, RuntimeError, ValueError):
                break
            for key, _ in events:
                stream = key.fileobj
                try:
                    while os.read(stream.fileno(), 64 * 1024):
                        pass
                    _close_git_stream(selector, stream)
                except (AttributeError, BlockingIOError, OSError, RuntimeError, ValueError):
                    _close_git_stream(selector, stream)
        try:
            remaining = [key.fileobj for key in selector.get_map().values()]
        except (OSError, RuntimeError, ValueError):
            remaining = []
        for stream in remaining:
            _close_git_stream(selector, stream)
    for stream in streams:
        if stream is not None:
            _close_git_stream(None, stream)


class _ForkedGitProcess:
    """Small Popen-compatible wait wrapper for a descriptor-bound fork."""

    __slots__ = ("pid", "stdout", "stderr", "_returncode")

    def __init__(self, pid: int, stdout_fd: int, stderr_fd: int) -> None:
        self.pid = pid
        self.stdout = os.fdopen(stdout_fd, "rb", buffering=0)
        self.stderr = os.fdopen(stderr_fd, "rb", buffering=0)
        self._returncode: int | None = None

    def poll(self) -> int | None:
        if self._returncode is not None:
            return self._returncode
        waited, status = os.waitpid(self.pid, os.WNOHANG)
        if waited == 0:
            return None
        self._returncode = os.waitstatus_to_exitcode(status)
        return self._returncode

    def wait(self, timeout: float | None = None) -> int:
        if self._returncode is not None:
            return self._returncode
        deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)
        while True:
            returncode = self.poll()
            if returncode is not None:
                return returncode
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(["git"], timeout)
                time.sleep(min(0.005, remaining))
            else:
                time.sleep(0.005)

    def terminate(self) -> None:
        os.kill(self.pid, signal.SIGTERM)

    def kill(self) -> None:
        os.kill(self.pid, signal.SIGKILL)


def _fork_exec_git(command: list[str], environment: dict[str, str]) -> _ForkedGitProcess:
    """Fork, fchdir, and exec without ever rediscovering the root pathname."""

    cwd_fd = getattr(command, "cwd_fd", None)
    if cwd_fd is not None:
        if type(cwd_fd) is not int or cwd_fd < 0:
            raise ValueError("Git working-directory descriptor is malformed")
        try:
            metadata = os.fstat(cwd_fd)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise ValueError("Git working-directory descriptor is unavailable") from exc
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("Git working-directory descriptor is not a directory")
    stdin_fd = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
    stdout_read, stdout_write = os.pipe()
    stderr_read, stderr_write = os.pipe()
    try:
        pid = os.fork()
    except BaseException:
        for descriptor in (stdin_fd, stdout_read, stdout_write, stderr_read, stderr_write):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise
    if pid == 0:
        try:
            os.setsid()
            os.dup2(stdin_fd, 0)
            os.dup2(stdout_write, 1)
            os.dup2(stderr_write, 2)
            if cwd_fd is not None:
                os.fchdir(cwd_fd)
            os.closerange(3, max(256, int(os.sysconf("SC_OPEN_MAX"))))
            os.execve(command[0], command, environment)
        except BaseException:
            try:
                os.write(2, b"Git child setup or exec failed\n")
            except OSError:
                pass
            os._exit(127)
    for descriptor in (stdin_fd, stdout_write, stderr_write):
        os.close(descriptor)
    return _ForkedGitProcess(pid, stdout_read, stderr_read)


def _run_bounded_git(command: list[str], environment: dict[str, str]) -> tuple[int, bytes, bytes]:
    """Collect both pipes and execute from a descriptor-bound checkout root.

    ``git -C /path`` re-discovers the path in the child after the caller's
    validation window. The explicit fork performs ``fchdir`` on the retained
    root descriptor before ``execve``; no root pathname is passed to Git.
    """

    process: _ForkedGitProcess | None = None
    selector: selectors.BaseSelector | None = None
    streams: tuple[Any, ...] = ()
    command_deadline = getattr(command, "deadline", None)
    if command_deadline is not None and type(command_deadline) is not float:
        raise ValueError("Git operation deadline is malformed")
    deadline: float | None = (
        command_deadline
        if command_deadline is not None
        else time.monotonic() + GIT_COMMAND_TIMEOUT_SECONDS
    )
    buffers: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        # The command budget begins before metadata validation and includes
        # fork/setup, descriptor-bound fchdir, and pipe collection after exec.
        _check_git_operation_deadline(deadline, "spawning Git")
        process = _fork_exec_git(command, environment)
        streams = (process.stdout, process.stderr)
        selector = selectors.DefaultSelector()
        labeled_streams = ((process.stdout, "stdout"), (process.stderr, "stderr"))
        for stream, label in labeled_streams:
            if stream is None:
                raise ValueError(f"Git {label} stream is malformed")
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("Git provenance command timed out")
            events = selector.select(remaining)
            if not events:
                raise ValueError("Git provenance command timed out")
            for key, _ in events:
                stream = key.fileobj
                label = key.data
                try:
                    chunk = os.read(
                        stream.fileno(),
                        min(64 * 1024, GIT_OUTPUT_MAX_BYTES + 1 - len(buffers[label])),
                    )
                except BlockingIOError:
                    continue
                if not chunk:
                    _close_git_stream(selector, stream)
                    continue
                buffers[label].extend(chunk)
                if len(buffers[label]) > GIT_OUTPUT_MAX_BYTES:
                    raise ValueError(f"Git {label} exceeds the bounded output size")
        try:
            returncode = process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            # Both pipes may close before a hostile child process exits. Keep
            # that path inside the bounded proof error contract; the outer
            # handler still terminates and reaps the complete process group.
            raise ValueError("Git provenance command timed out") from exc
        if type(returncode) is not int:
            raise ValueError("Git process result is malformed")
        _ensure_git_process_group_quiescent(process, deadline)
        return returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"])
    except (OSError, RuntimeError, TypeError, ValueError, subprocess.SubprocessError):
        _terminate_and_drain_git(process, selector, streams, deadline=deadline)
        raise
    finally:
        if selector is not None:
            try:
                remaining = [key.fileobj for key in selector.get_map().values()]
            except (OSError, RuntimeError, ValueError):
                remaining = []
            for stream in remaining:
                _close_git_stream(selector, stream)
            try:
                selector.close()
            except (OSError, RuntimeError, ValueError):
                pass
        for stream in streams:
            if stream is not None:
                _close_git_stream(None, stream)


def _git_output_bounded(command: list[str], environment: dict[str, str]) -> tuple[int, bytes, bytes]:
    """Stable alias for callers that need the bounded Git process primitive."""

    return _run_bounded_git(command, environment)


def _git_metadata_roots(
    root: Path,
    *,
    deadline: float | None = None,
) -> tuple[Path, ...]:
    """Resolve reviewed worktree metadata without following nested links."""

    _check_git_operation_deadline(deadline, "discovering Git metadata")
    try:
        root = Path(root).resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ValueError("Git repository root is unavailable") from exc
    _check_git_operation_deadline(deadline, "discovering Git metadata")
    if not root.is_dir():
        raise ValueError("Git repository root is unavailable")
    git_entry = root / ".git"
    _check_git_operation_deadline(deadline, "discovering Git metadata")
    try:
        git_entry_metadata = os.lstat(git_entry)
        _check_git_operation_deadline(deadline, "discovering Git metadata")
    except _GitOperationTimeout:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ValueError("Git metadata root is unavailable") from exc
    if stat.S_ISLNK(git_entry_metadata.st_mode):
        raise ValueError("Git metadata root must not be a symlink")
    if stat.S_ISDIR(git_entry_metadata.st_mode):
        git_dir = git_entry
    elif stat.S_ISREG(git_entry_metadata.st_mode):
        _check_git_operation_deadline(deadline, "reading Git worktree pointer")
        pointer = _read_verified_file_path(
            git_entry,
            4096,
            "Git worktree pointer",
            deadline=deadline,
        )
        _check_git_operation_deadline(deadline, "reading Git worktree pointer")
        try:
            text = pointer.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Git worktree pointer is malformed") from exc
        if not text.startswith("gitdir: ") or not text.endswith("\n"):
            raise ValueError("Git worktree pointer is malformed")
        target_text = text[8:-1]
        if not target_text:
            raise ValueError("Git worktree pointer is malformed")
        target = Path(target_text)
        git_dir = target if target.is_absolute() else root / target
    else:
        raise ValueError("Git metadata root is unavailable")

    git_fd, git_dir = _open_verified_directory_path(
        git_dir,
        label="Git metadata root",
        deadline=deadline,
        resolve_parent_aliases=False,
    )
    _check_git_operation_deadline(deadline, "discovering Git metadata")
    os.close(git_fd)
    roots = [git_dir]

    common_file = git_dir / "commondir"
    _check_git_operation_deadline(deadline, "discovering Git common-dir metadata")
    try:
        common_metadata = os.lstat(common_file)
        _check_git_operation_deadline(deadline, "discovering Git common-dir metadata")
    except FileNotFoundError:
        common_metadata = None
    except _GitOperationTimeout:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ValueError("Git common-dir pointer is unavailable") from exc
    if common_metadata is not None:
        if not stat.S_ISREG(common_metadata.st_mode):
            raise ValueError("Git common-dir pointer is unsafe")
        _check_git_operation_deadline(deadline, "reading Git common-dir pointer")
        common_bytes = _read_verified_file_path(
            common_file,
            4096,
            "Git common-dir pointer",
            deadline=deadline,
        )
        _check_git_operation_deadline(deadline, "reading Git common-dir pointer")
        try:
            common_text = common_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Git common-dir pointer is malformed") from exc
        if not common_text.endswith("\n"):
            raise ValueError("Git common-dir pointer is malformed")
        common_text = common_text[:-1]
        if not common_text:
            raise ValueError("Git common-dir pointer is malformed")
        common = Path(common_text)
        common_target = common if common.is_absolute() else git_dir / common
        common_fd, common_dir = _open_verified_directory_path(
            common_target,
            label="Git common metadata root",
            deadline=deadline,
            resolve_parent_aliases=False,
        )
        _check_git_operation_deadline(deadline, "discovering Git common-dir metadata")
        os.close(common_fd)
        roots.append(common_dir)

    unique_roots: list[Path] = []
    seen_identity: set[tuple[int, int]] = set()
    for candidate in roots:
        _check_git_operation_deadline(deadline, "deduplicating Git metadata roots")
        candidate_fd, _canonical = _open_verified_directory_path(
            candidate,
            label="Git metadata root",
            deadline=deadline,
            resolve_parent_aliases=False,
        )
        try:
            metadata = os.fstat(candidate_fd)
            _check_git_operation_deadline(deadline, "deduplicating Git metadata roots")
            identity = (metadata.st_dev, metadata.st_ino)
        finally:
            os.close(candidate_fd)
        if identity in seen_identity:
            continue
        seen_identity.add(identity)
        unique_roots.append(candidate)
    _check_git_operation_deadline(deadline, "discovering Git metadata")
    return tuple(unique_roots)


def _reject_git_metadata_links(
    metadata_root: Path,
    *,
    deadline: float | None = None,
) -> None:
    """Reject nested metadata links with descriptor-relative DFS.

    The reviewed checkout may use a ``.git`` file and a regular ``commondir``
    pointer for linked worktrees. Once those roots are resolved, Git metadata
    itself must be a descriptor-safe tree: a moved ``objects`` or ``refs``
    directory, or a deeper link below either, would otherwise redirect object
    and ref reads outside the reviewed repository. Each DFS frame owns only its
    current directory descriptor; exhausted subtrees close before the next
    sibling opens, so the live descriptor count is O(depth), not O(entries).
    """

    _check_git_operation_deadline(deadline, "opening Git metadata root")
    root_fd, _canonical = _open_verified_directory_path(
        metadata_root,
        label="Git metadata root",
        deadline=deadline,
        resolve_parent_aliases=False,
    )
    _check_git_operation_deadline(deadline, "scanning Git metadata")
    entries_seen = 0

    def read_children(directory_fd: int) -> list[Any]:
        _check_git_operation_deadline(deadline, "scanning Git metadata")
        try:
            with os.scandir(directory_fd) as iterator:
                entries = []
                for entry in iterator:
                    entries.append(entry)
                    if len(entries) > GIT_METADATA_ENTRY_MAX:
                        raise ValueError("Git metadata exceeds the bounded entry count")
        except ValueError:
            raise
        except (OSError, RuntimeError, TypeError) as exc:
            raise ValueError("Git metadata directory could not be inspected") from exc
        _check_git_operation_deadline(deadline, "scanning Git metadata")
        entries.sort(key=lambda entry: entry.name)
        return entries

    # Materialize only the names for each active frame. Child descriptors are
    # closed as soon as their frame is exhausted, keeping a wide fanout from
    # consuming one descriptor per sibling.
    stack: list[tuple[int, tuple[str, ...], list[Any], int, bool]] = []
    try:
        stack.append((root_fd, (), read_children(root_fd), 0, False))
        while stack:
            _check_git_operation_deadline(deadline, "scanning Git metadata")
            directory_fd, prefix, entries, index, owned = stack[-1]
            if index >= len(entries):
                stack.pop()
                if owned:
                    try:
                        os.close(directory_fd)
                    except OSError:
                        pass
                continue
            entry = entries[index]
            stack[-1] = (directory_fd, prefix, entries, index + 1, owned)
            name = entry.name
            if not isinstance(name, str) or not name or name in {".", ".."} or "/" in name:
                raise ValueError("Git metadata contains an invalid pathname entry")
            entries_seen += 1
            if entries_seen > GIT_METADATA_ENTRY_MAX:
                raise ValueError("Git metadata exceeds the bounded entry count")
            _check_git_operation_deadline(deadline, "scanning Git metadata")
            try:
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                _check_git_operation_deadline(deadline, "scanning Git metadata")
            except _GitOperationTimeout:
                raise
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                raise ValueError("Git metadata entry could not be inspected") from exc
            relative_parts = (*prefix, name)
            if stat.S_ISLNK(metadata.st_mode):
                relative = "/".join(relative_parts)
                raise ValueError(f"Git metadata contains a symlink: {relative}")
            if not stat.S_ISDIR(metadata.st_mode):
                continue
            child_fd = _open_verified_directory_at(
                directory_fd,
                name,
                label="Git metadata directory",
                deadline=deadline,
            )
            try:
                child_entries = read_children(child_fd)
            except BaseException:
                os.close(child_fd)
                raise
            stack.append((child_fd, relative_parts, child_entries, 0, True))
    finally:
        for directory_fd, _prefix, _entries, _index, owned in reversed(stack):
            if owned:
                try:
                    os.close(directory_fd)
                except OSError:
                    pass
        try:
            os.close(root_fd)
        except OSError:
            pass


def _read_git_config(metadata_root: Path, filename: str) -> str | None:
    """Read one optional local config file through a stable descriptor."""

    if filename not in {"config", "config.worktree"}:
        raise ValueError("Git config filename is unsupported")
    path = metadata_root / filename
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return None
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ValueError("Git config could not be inspected") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("Git config is not a regular file")
    raw = _read_verified_file_path(path, GIT_CONFIG_MAX_BYTES, f"Git {filename}")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Git config is malformed") from exc


def _git_config_metadata_flags(text: str) -> tuple[bool, bool]:
    """Return unsafe-config and active-worktree-config flags.

    This is intentionally a small fail-closed parser. It recognizes the
    section/key forms Git writes, including key-only booleans, but never
    expands ``include`` or ``includeIf`` input. Any promisor/partial-clone key
    is rejected regardless of its value so a future Git spelling cannot turn
    this local trust check into a fetch-capable proof.
    """

    unsafe = False
    worktree_config_active = False
    section = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if "\x00" in line or line.endswith("\\"):
            raise ValueError("Git config is malformed")
        if line.startswith("["):
            if not line.endswith("]") or len(line) < 3:
                raise ValueError("Git config is malformed")
            section = line[1:-1].strip().lower()
            if not section:
                raise ValueError("Git config is malformed")
            if section == "include" or section.startswith("includeif"):
                raise ValueError("Git config includes are not permitted")
            continue
        key, separator, raw_value = line.partition("=")
        key = key.strip().lower()
        if not key:
            raise ValueError("Git config is malformed")
        compact_key = key.replace(" ", "")
        compact_section = section.replace('"', "").replace(" ", "")
        if compact_key.startswith("include") or compact_section.startswith("include"):
            raise ValueError("Git config includes are not permitted")
        full_key = f"{compact_section}.{compact_key}" if compact_section else compact_key
        if "promisor" in full_key or "partialclone" in full_key:
            unsafe = True
        if full_key == "extensions.worktreeconfig":
            if not separator:
                worktree_config_active = True
                continue
            normalized_value = raw_value.strip().lower()
            if normalized_value in {"true", "yes", "on", "1"}:
                worktree_config_active = True
            elif normalized_value not in {"false", "no", "off", "0"}:
                raise ValueError("Git worktreeConfig boolean is malformed")
    return unsafe, worktree_config_active


def _git_config_has_lazy_metadata(text: str) -> bool:
    """Return whether bounded local config contains unsafe Git selectors."""

    unsafe, _worktree_config_active = _git_config_metadata_flags(text)
    return unsafe


def _reject_packed_replacement_refs(metadata_root: Path) -> None:
    """Reject replacement refs retained in bounded ``packed-refs`` output."""

    packed_refs = metadata_root / "packed-refs"
    if not packed_refs.exists() and not packed_refs.is_symlink():
        return
    raw = _read_verified_file_path(packed_refs, GIT_CONFIG_MAX_BYTES, "Git packed-refs")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Git packed-refs is malformed") from exc
    for raw_line in text.splitlines():
        fields = raw_line.strip().split()
        if len(fields) >= 2 and fields[1].startswith("refs/replace/"):
            raise ValueError("Git metadata uses replacement refs")


def _reject_promisor_pack_sidecars(metadata_root: Path) -> None:
    """Reject bounded ``objects/pack/*.promisor`` sidecars independently."""

    pack_directory = metadata_root / "objects" / "pack"
    if not pack_directory.exists() and not pack_directory.is_symlink():
        return
    try:
        metadata = os.lstat(pack_directory)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("Git pack metadata directory is unsafe")
        with os.scandir(pack_directory) as entries:
            count = 0
            for entry in entries:
                count += 1
                if count > GIT_PACK_ENTRY_MAX:
                    raise ValueError("Git pack metadata exceeds the bounded entry count")
                if isinstance(entry.name, str) and entry.name.endswith(".promisor"):
                    raise ValueError("Git metadata uses a promisor pack sidecar")
    except ValueError:
        raise
    except (OSError, RuntimeError, TypeError) as exc:
        raise ValueError("Git pack metadata could not be inspected") from exc


def _validated_git_metadata(
    root: Path,
    *,
    deadline: float | None = None,
) -> tuple[_GitMetadataPin, ...]:
    """Validate and retain the local Git metadata trust surface."""

    _check_git_operation_deadline(deadline, "validating Git metadata")
    try:
        root = Path(root).resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ValueError("Git repository root is unavailable") from exc
    _check_git_operation_deadline(deadline, "validating Git metadata")
    pins: list[_GitMetadataPin] = []
    metadata_content_budget = [0]
    try:
        # Retain the checkout root itself. Git must later chdir through this
        # descriptor; the pathname is only a diagnostic and race witness.
        pins.append(
            _pin_git_metadata_path(
                root,
                label="Git repository root",
                pin_content=False,
                pin_entries=False,
                deadline=deadline,
            )
        )
        _check_git_operation_deadline(deadline, "discovering Git metadata")
        metadata_roots = _git_metadata_roots(root, deadline=deadline)
        for metadata_root in metadata_roots:
            _check_git_operation_deadline(deadline, "scanning Git metadata")
            _reject_git_metadata_links(metadata_root, deadline=deadline)

        specs: list[tuple[Path, bool, bool, str]] = [
            (Path(root) / ".git", True, False, "Git worktree metadata entry"),
        ]
        for metadata_root in metadata_roots:
            specs.append((metadata_root, False, False, "Git metadata root"))
            for relative in GIT_METADATA_PIN_DIRECTORIES:
                specs.append((metadata_root / relative, False, True, f"Git metadata {relative}"))
            for relative in GIT_METADATA_PIN_FILES:
                specs.append((metadata_root / relative, True, False, f"Git metadata {relative}"))
        seen: set[str] = set()
        for path, pin_content, pin_entries, label in specs:
            _check_git_operation_deadline(deadline, "pinning Git metadata")
            key = os.fspath(path)
            if key in seen:
                continue
            seen.add(key)
            pins.append(
                _pin_git_metadata_path(
                    path,
                    label=label,
                    pin_content=pin_content,
                    pin_entries=pin_entries,
                    content_budget=metadata_content_budget,
                    deadline=deadline,
                )
            )
        _check_git_operation_deadline(deadline, "validating Git metadata")
        retained = tuple(pins)
        _assert_git_metadata_pins(retained, phase="validation", deadline=deadline)
        pins_by_path = {pin.path: pin for pin in retained}

        def require_pin(path: Path, label: str) -> _GitMetadataPin | None:
            return pins_by_path.get(path)

        def pinned_text(pin: _GitMetadataPin | None, label: str) -> str | None:
            if pin is None or pin.identity is None:
                return None
            if pin.content is None:
                raise ValueError(f"{label} is not a regular file")
            try:
                return pin.content.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError(f"{label} is malformed") from exc

        for metadata_root in metadata_roots:
            _check_git_operation_deadline(deadline, "validating Git metadata")
            for relative in GIT_FORBIDDEN_METADATA:
                forbidden = require_pin(metadata_root / relative, f"Git metadata {relative}")
                if forbidden is not None and forbidden.identity is not None:
                    raise ValueError(f"Git metadata uses forbidden {relative}")
            replacement = require_pin(metadata_root / "refs" / "replace", "Git replacement refs")
            if replacement is not None and replacement.identity is not None:
                raise ValueError("Git metadata uses replacement refs")

            packed_refs = require_pin(metadata_root / "packed-refs", "Git packed-refs")
            packed_text = pinned_text(packed_refs, "Git packed-refs")
            if packed_text is not None:
                for raw_line in packed_text.splitlines():
                    _check_git_operation_deadline(deadline, "validating Git metadata")
                    fields = raw_line.strip().split()
                    if len(fields) >= 2 and fields[1].startswith("refs/replace/"):
                        raise ValueError("Git metadata uses replacement refs")

            objects_directory = require_pin(metadata_root / "objects", "Git object metadata")
            if objects_directory is not None and objects_directory.entries is not None:
                for relative, _identity, _content in objects_directory.entries:
                    _check_git_operation_deadline(deadline, "validating Git metadata")
                    if relative.startswith("pack/") and relative.endswith(".promisor"):
                        raise ValueError("Git metadata uses a promisor pack sidecar")

        worktree_config_active = False
        for metadata_root in metadata_roots:
            _check_git_operation_deadline(deadline, "validating Git configuration")
            config = require_pin(metadata_root / "config", "Git config")
            config_text = pinned_text(config, "Git config")
            if config_text is None:
                continue
            unsafe, active = _git_config_metadata_flags(config_text)
            if unsafe:
                raise ValueError("Git repository uses lazy, promisor, partial, or included metadata")
            worktree_config_active = worktree_config_active or active

        if worktree_config_active:
            for metadata_root in metadata_roots:
                _check_git_operation_deadline(deadline, "validating Git configuration")
                worktree_config = require_pin(metadata_root / "config.worktree", "Git worktree config")
                worktree_text = pinned_text(worktree_config, "Git worktree config")
                if worktree_text is None:
                    continue
                unsafe, _active = _git_config_metadata_flags(worktree_text)
                if unsafe:
                    raise ValueError(
                        "Git repository uses lazy, promisor, partial, or included worktree metadata"
                    )
        _check_git_operation_deadline(deadline, "validating Git configuration")
        _assert_git_metadata_pins(retained, phase="validation", deadline=deadline)
        return retained
    except BaseException:
        _close_git_metadata_pins(tuple(pins))
        raise


def _validate_git_metadata(root: Path) -> None:
    """Validate Git metadata without retaining command-lifetime descriptors."""

    deadline = _new_git_operation_deadline()
    pins = _validated_git_metadata(root, deadline=deadline)
    _close_git_metadata_pins(pins)


def _bound_git_command(
    executable: Path,
    root_fd: int,
    *arguments: str,
    deadline: float | None = None,
) -> _BoundGitCommand:
    """Build Git argv with no pathname-based repository rediscovery."""

    return _BoundGitCommand(
        [
            str(executable),
            "--no-replace-objects",
            "--no-lazy-fetch",
            "--no-optional-locks",
            *arguments,
        ],
        cwd_fd=root_fd,
        deadline=deadline,
    )


def _git_root_descriptor(pins: tuple[_GitMetadataPin, ...], root: Path) -> int:
    """Return the retained checkout-root descriptor for one command."""

    for pin in pins:
        if pin.path == root and pin.label == "Git repository root":
            descriptor = pin.descriptor
            if descriptor is None:
                break
            return descriptor
    raise ValueError("Git repository root descriptor is unavailable")


def _verify_git_repository(repository_root: Path) -> None:
    """Reject shallow, redirected, replacement, and promisor repositories."""

    deadline = _new_git_operation_deadline()
    _check_git_operation_deadline(deadline, "resolving Git repository root")
    try:
        root = Path(repository_root).resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ValueError("Git repository root is unavailable") from exc
    _check_git_operation_deadline(deadline, "resolving Git repository root")
    if not root.is_dir():
        raise ValueError("Git repository root is unavailable")
    _check_git_operation_deadline(deadline, "validating Git repository root")
    pins = _validated_git_metadata(root, deadline=deadline)
    try:
        _check_git_operation_deadline(deadline, "checking trusted Git executable")
        executable = _trusted_git_path()
        _check_git_operation_deadline(deadline, "checking trusted Git executable")
        _check_git_operation_deadline(deadline, "preparing Git environment")
        environment = _strict_git_environment()
        _check_git_operation_deadline(deadline, "preparing Git environment")
        _check_git_operation_deadline(deadline, "retaining Git root descriptor")
        root_fd = _git_root_descriptor(pins, root)
        _check_git_operation_deadline(deadline, "retaining Git root descriptor")
        _check_git_operation_deadline(deadline, "starting Git provenance")
        command = _bound_git_command(
            executable,
            root_fd,
            "rev-parse",
            "--is-shallow-repository",
            deadline=deadline,
        )
        returncode, stdout, stderr = _run_with_git_metadata_pins(
            pins,
            lambda: _run_bounded_git(command, environment),
            deadline=deadline,
        )
        if type(returncode) is not int or returncode != 0:
            raise ValueError("Git repository trust could not be checked")
        if type(stdout) is not bytes or stdout != b"false\n":
            raise ValueError("Git repository is shallow or malformed")
        if type(stderr) is not bytes or stderr:
            raise ValueError("Git repository diagnostics are malformed")
    finally:
        _close_git_metadata_pins(pins)


_verify_git_repository_integrity = _verify_git_repository


def _validated_git_context(repository_root: Path) -> dict[str, object]:
    """Return a trusted executable, sanitized environment, and local Git root."""

    deadline = _new_git_operation_deadline()
    _check_git_operation_deadline(deadline, "resolving Git repository root")
    try:
        root = Path(repository_root).resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ValueError("Git repository root is unavailable") from exc
    _check_git_operation_deadline(deadline, "resolving Git repository root")
    if not root.is_dir():
        raise ValueError("Git repository root is unavailable")
    _check_git_operation_deadline(deadline, "validating Git repository root")
    _check_git_operation_deadline(deadline, "checking trusted Git executable")
    executable = _trusted_git_path()
    _check_git_operation_deadline(deadline, "checking trusted Git executable")
    _check_git_operation_deadline(deadline, "preparing Git environment")
    environment = _strict_git_environment()
    _check_git_operation_deadline(deadline, "preparing Git environment")
    _check_git_operation_deadline(deadline, "preparing Git provenance")
    pins = _validated_git_metadata(root, deadline=deadline)
    _check_git_operation_deadline(deadline, "retaining Git root descriptor")
    root_fd = _git_root_descriptor(pins, root)
    _check_git_operation_deadline(deadline, "retaining Git root descriptor")
    return {
        "root": root,
        "executable": executable,
        "environment": environment,
        "pins": pins,
        "root_fd": root_fd,
        "deadline": deadline,
    }


def _git(repo_root: Path, *arguments: str) -> bytes:
    """Read bounded local Git output without replacement refs or lazy fetch."""

    context = _validated_git_context(repo_root)
    root = context["root"]
    executable = context["executable"]
    environment = context["environment"]
    pins = context["pins"]
    root_fd = context["root_fd"]
    deadline = context["deadline"]
    if (
        not isinstance(root, Path)
        or not isinstance(executable, Path)
        or not isinstance(environment, dict)
        or not isinstance(pins, tuple)
        or type(root_fd) is not int
        or type(deadline) is not float
    ):
        raise ValueError("Git context is malformed")
    try:
        _check_git_operation_deadline(deadline, "starting Git provenance")
        command = _bound_git_command(executable, root_fd, *arguments, deadline=deadline)
        returncode, stdout, stderr = _run_with_git_metadata_pins(
            pins,
            lambda: _git_output_bounded(command, environment),
            deadline=deadline,
        )
        if type(returncode) is not int or returncode != 0:
            raise ValueError("Git provenance could not be checked")
        if type(stdout) is not bytes or len(stdout) > GIT_OUTPUT_MAX_BYTES:
            raise ValueError("Git provenance output is malformed")
        if type(stderr) is not bytes:
            raise ValueError("Git provenance diagnostics are malformed")
        if stderr:
            raise ValueError("Git provenance output is malformed")
        return stdout
    finally:
        _close_git_metadata_pins(pins)


def _git_text(repository_root: Path, *arguments: str) -> str:
    """Read one bounded, exact ASCII Git value from the trust root.

    The normal path is the streaming fork/exec collector. The small alternate
    branch exists only for legacy tests that replace ``subprocess.run`` with a
    malformed ``CompletedProcess`` seam; it never runs in an unmodified
    process and still uses the trusted executable and sanitized environment.
    """

    context = _validated_git_context(repository_root)
    root = context["root"]
    executable = context["executable"]
    environment = context["environment"]
    pins = context["pins"]
    root_fd = context["root_fd"]
    deadline = context["deadline"]
    if (
        not isinstance(root, Path)
        or not isinstance(executable, Path)
        or not isinstance(environment, dict)
        or not isinstance(pins, tuple)
        or type(root_fd) is not int
        or type(deadline) is not float
    ):
        raise ValueError("Git context is malformed")
    _check_git_operation_deadline(deadline, "starting Git provenance")
    command = _bound_git_command(executable, root_fd, *arguments, deadline=deadline)
    try:
        if subprocess.run is not _ORIGINAL_SUBPROCESS_RUN:
            def legacy_run() -> Any:
                _check_git_operation_deadline(deadline, "starting Git provenance")
                try:
                    return subprocess.run(
                        command,
                        check=False,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=False,
                        timeout=max(0.0, deadline - time.monotonic()),
                        env=environment,
                    )
                except (
                    OSError,
                    RuntimeError,
                    TypeError,
                    UnicodeError,
                    ValueError,
                    subprocess.SubprocessError,
                ) as exc:
                    raise ValueError("Git provenance could not be checked") from exc

            result = _run_with_git_metadata_pins(pins, legacy_run, deadline=deadline)
            try:
                returncode = result.returncode
                output = result.stdout
                diagnostics = result.stderr
            except AttributeError as exc:
                raise ValueError("Git provenance result is malformed") from exc
            if type(returncode) is not int or returncode != 0:
                raise ValueError("Git provenance could not be checked")
            if type(diagnostics) is not bytes:
                raise ValueError("Git provenance diagnostics are malformed")
            if diagnostics:
                raise ValueError("Git provenance output is malformed")
            if type(output) is not bytes or len(output) > GIT_OUTPUT_MAX_BYTES:
                raise ValueError("Git provenance output is malformed")
        else:
            returncode, output, diagnostics = _run_with_git_metadata_pins(
                pins,
                lambda: _git_output_bounded(command, environment),
                deadline=deadline,
            )
            if type(returncode) is not int or returncode != 0:
                raise ValueError("Git provenance could not be checked")
            if type(diagnostics) is not bytes:
                raise ValueError("Git provenance diagnostics are malformed")
            if diagnostics:
                raise ValueError("Git provenance output is malformed")
            if type(output) is not bytes or len(output) > GIT_OUTPUT_MAX_BYTES:
                raise ValueError("Git provenance output is malformed")
        try:
            text = output.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("Git provenance output is malformed") from exc
        if text.endswith("\n"):
            text = text[:-1]
        if not text or "\n" in text or "\r" in text or text != text.strip():
            raise ValueError("Git provenance output is malformed")
        return text
    finally:
        _close_git_metadata_pins(pins)


def _git_head(repository_root: Path = PROJECT_ROOT) -> str:
    """Return the full checked-out commit, never a caller-provided alias."""

    _verify_git_repository(repository_root)
    head = _git_text(repository_root, "rev-parse", "--verify", "HEAD^{commit}")
    if HEX40_RE.fullmatch(head) is None:
        raise ValueError("Git HEAD is not a full commit SHA")
    return head


def _verify_git_commit(build_sha: str, repository_root: Path = PROJECT_ROOT) -> None:
    """Require a real local commit reachable from this checkout's HEAD."""

    if type(build_sha) is not str or HEX40_RE.fullmatch(build_sha) is None:
        raise ValueError("build_sha must be a lowercase commit SHA")
    resolved = _git_text(repository_root, "rev-parse", "--verify", f"{build_sha}^{{commit}}")
    if resolved != build_sha:
        raise ValueError("build_sha is not an exact Git commit")
    head = _git_head(repository_root)
    if build_sha == head:
        return
    output = _git(repository_root, "merge-base", "--is-ancestor", build_sha, head)
    if output != b"":
        raise ValueError("Git ancestry output is malformed")


def _validate_build_digest(build_digest: object) -> str:
    if type(build_digest) is not str or HEX64_RE.fullmatch(build_digest) is None:
        raise ValueError("build_digest must be a SHA-256 digest")
    return build_digest


def _derive_git_static_build_provenance(
    static_build_root: Path,
    repository_root: Path = PROJECT_ROOT,
) -> dict[str, str]:
    """Identify a plain local static artifact without following links."""

    supplied_root = Path(static_build_root)
    if supplied_root.is_symlink():
        raise ValueError("static build root must not be a symlink")
    root = supplied_root.resolve()
    if not root.is_dir():
        raise ValueError("static build root is unavailable")
    for relative_path in STATIC_BUILD_REQUIRED_FILES:
        entry = root / relative_path
        if entry.is_symlink() or not entry.is_file():
            raise ValueError("static build is missing a reviewed entry point")
    build_sha = _git_head(repository_root)
    build_digest = _build_static_digest(root)
    return {"build_sha": build_sha, "build_digest": build_digest}


def _canonical_retained_path(path: Path) -> Path:
    """Require the exact raw pathname and stable descriptor identity."""

    try:
        raw = os.fspath(path)
    except TypeError as exc:
        raise ValueError("retained input path is malformed") from exc
    if isinstance(raw, bytes):
        raise ValueError("retained input path is malformed")
    requested = Path(raw)
    expected = Path(RETAINED_EVIDENCE_PATH)
    if not requested.is_absolute() or not expected.is_absolute():
        raise ValueError("retained input must use the canonical committed evidence path")
    if "//" in raw or any(part in {"", ".", ".."} for part in raw[1:].split("/")):
        raise ValueError("retained input must use the canonical committed evidence path")
    if requested.parts != expected.parts or str(requested) != str(expected):
        raise ValueError("retained input must use the canonical committed evidence path")
    parent_fd: int | None = None
    descriptor: int | None = None
    try:
        parent_fd, name = _open_verified_parent(
            requested,
            label="retained input",
            resolve_parent_aliases=False,
        )
        descriptor, _metadata = _open_verified_regular_file_at(
            parent_fd,
            name,
            limit=RETAINED_EVIDENCE_MAX_BYTES,
            label="retained input",
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        if isinstance(exc, ValueError) and "canonical committed evidence path" in str(exc):
            raise
        raise ValueError("retained input path could not be resolved safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent_fd is not None:
            os.close(parent_fd)
    return expected


def _retained_anchor() -> str:
    """Read and source-validate the fixed one-line digest."""

    anchor_path = Path(RETAINED_EVIDENCE_ANCHOR_PATH)
    parent_fd: int | None = None
    descriptor: int | None = None
    try:
        parent_fd, name = _open_verified_parent(
            anchor_path,
            label="committed retained evidence anchor",
            resolve_parent_aliases=True,
        )
        descriptor, metadata = _open_verified_regular_file_at(
            parent_fd,
            name,
            limit=RETAINED_EVIDENCE_ANCHOR_MAX_BYTES,
            label="committed retained evidence anchor",
        )
        raw = _read_bounded_fd(
            descriptor,
            RETAINED_EVIDENCE_ANCHOR_MAX_BYTES,
            "committed retained evidence anchor",
        )
        after_read = os.fstat(descriptor)
        if _metadata_identity(metadata) != _metadata_identity(after_read):
            raise ValueError("committed retained evidence anchor changed during read")
        after_entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _verify_regular_metadata(
            after_entry,
            limit=RETAINED_EVIDENCE_ANCHOR_MAX_BYTES,
            label="committed retained evidence anchor",
        )
        if _metadata_identity(metadata) != _metadata_identity(after_entry):
            raise ValueError("committed retained evidence anchor changed after read")
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ValueError("committed retained evidence anchor could not be read safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent_fd is not None:
            os.close(parent_fd)
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("committed retained evidence anchor is malformed or stale") from exc
    # The committed anchor is exactly one lowercase SHA-256 line. Do not use
    # strip() here: accepting extra bytes would weaken the fixed trust boundary.
    if text != f"{RETAINED_EVIDENCE_ANCHOR}\n":
        raise ValueError("committed retained evidence anchor is malformed or stale")
    return RETAINED_EVIDENCE_ANCHOR


def _read_verified_retained_bytes(path: Path) -> bytes:
    """Verify path, bounded bytes, and the fixed hash before parsing any fields."""

    canonical_path = _canonical_retained_path(path)
    evidence_bytes = _read_bounded_bytes(
        canonical_path,
        RETAINED_EVIDENCE_MAX_BYTES,
        "committed retained evidence",
    )
    if digest_bytes(evidence_bytes) != _retained_anchor():
        raise ValueError("committed retained evidence anchor does not match")
    return evidence_bytes


def _committed_retained_build_provenance() -> dict[str, str]:
    """Read the reviewed historical build pair without trusting CLI strings."""

    evidence_bytes = _read_verified_retained_bytes(RETAINED_EVIDENCE_PATH)
    try:
        evidence = _decode_bounded_json(evidence_bytes, "committed retained evidence")
    except ValueError as exc:
        raise ValueError("committed retained evidence is malformed") from exc
    if not isinstance(evidence, Mapping):
        raise ValueError("committed retained evidence must be an object")
    product = evidence.get("product")
    if not isinstance(product, Mapping):
        raise ValueError("committed retained evidence product is malformed")
    build_sha = product.get("build_commit")
    build_digest = product.get("static_manifest_sha256")
    if type(build_sha) is not str or type(build_digest) is not str:
        raise ValueError("committed retained build provenance is malformed")
    if HEX40_RE.fullmatch(build_sha) is None or HEX64_RE.fullmatch(build_digest) is None:
        raise ValueError("committed retained build provenance is malformed")
    return {"build_sha": build_sha, "build_digest": build_digest}


def _verify_build_provenance(
    *,
    build_sha: str,
    build_digest: str,
    mode: str,
    static_build_root: Path | None = None,
    repository_root: Path = PROJECT_ROOT,
) -> None:
    """Verify build provenance; neither mode verifies browser execution."""

    _validate_build_digest(build_digest)
    if mode == "standalone":
        if static_build_root is None:
            raise ValueError("standalone evidence requires a static build root")
        derived = _derive_git_static_build_provenance(static_build_root, repository_root)
        if {"build_sha": build_sha, "build_digest": build_digest} != derived:
            raise ValueError("CLI build provenance does not match Git and static-build bytes")
    elif mode == "retained":
        expected = _committed_retained_build_provenance()
        if {"build_sha": build_sha, "build_digest": build_digest} != expected:
            raise ValueError("retained build provenance does not match committed evidence")
    elif mode == "untrusted":
        # Direct library callers may inspect a rendered manifest, but their
        # supplied identity is not an anchored historical or current-build
        # proof. The output labels that split explicitly below.
        return
    else:
        raise ValueError("unsupported build provenance mode")
    _verify_git_commit(build_sha, repository_root)


def _browser_evidence_provenance(
    *,
    build_sha: str,
    build_digest: str,
    caddyfile_digest: str,
    runtime_inputs_sha256: str,
) -> dict[str, str]:
    """Return the immutable run identity a browser artifact must match."""

    return {
        "build_sha": build_sha,
        "build_digest": build_digest,
        "caddyfile_digest": caddyfile_digest,
        "runtime_inputs_sha256": runtime_inputs_sha256,
    }


def _resolve_browser_journey(
    browser_journey: str | None,
    browser_evidence: Mapping[str, object] | None,
    expected_provenance: Mapping[str, str],
) -> tuple[str, dict[str, object]]:
    """Derive a browser status from one bounded, exact-run evidence map.

    ``browser_journey`` is accepted only as an optional assertion for callers
    migrating from the original fixture API. It is never a source of status.
    Negative statuses have fixed observation shapes and the provenance must
    match the build, static manifest, rendered Caddyfile, and runtime-input
    digest for this exact proof run. A complete event map is not an execution
    receipt, so ``passed`` is rejected until a separately trusted receipt
    verifier exists.
    """

    if browser_evidence is None:
        raise ValueError("browser evidence is required for every journey status")
    if not isinstance(browser_evidence, Mapping):
        raise ValueError("browser evidence must be a mapping")
    if browser_journey is not None and (
        type(browser_journey) is not str or browser_journey not in BROWSER_JOURNEYS
    ):
        raise ValueError("browser_journey is outside the fixed proof vocabulary")
    if set(browser_evidence) != set(BROWSER_EVIDENCE_ROOT_KEYS):
        raise ValueError("browser evidence must contain the closed root key set")
    if browser_evidence["schema"] != BROWSER_EVIDENCE_SCHEMA:
        raise ValueError("browser evidence schema is unsupported")

    status = browser_evidence["status"]
    if type(status) is not str or status not in BROWSER_JOURNEYS:
        raise ValueError("browser evidence status is unsupported")
    if browser_journey is not None and browser_journey != status:
        raise ValueError("browser_journey does not match browser evidence")
    provenance = browser_evidence["provenance"]
    if not isinstance(provenance, Mapping) or set(provenance) != set(BROWSER_EVIDENCE_PROVENANCE_KEYS):
        raise ValueError("browser evidence provenance keys are incomplete")
    normalized_provenance = {
        key: provenance[key] for key in BROWSER_EVIDENCE_PROVENANCE_KEYS
    }
    if normalized_provenance != dict(expected_provenance):
        raise ValueError("browser evidence provenance is stale or mismatched")

    observations = browser_evidence["observations"]
    if not isinstance(observations, Mapping):
        raise ValueError("browser evidence observations must be a mapping")
    if status == "passed":
        # Validate the closed shape for useful diagnostics, but never treat it
        # as execution. This local fixture has no signed attestation or
        # verifier-generated receipt, so even a complete map fails closed.
        if set(observations) != {"events"}:
            raise ValueError("passed browser evidence must contain only events")
        events = observations["events"]
        if not isinstance(events, Mapping) or set(events) != set(BROWSER_COMPLETION_EVIDENCE):
            raise ValueError("passed browser evidence must contain the closed event set")
        normalized_events = {
            event: events[event] for event in BROWSER_COMPLETION_EVIDENCE
        }
        if normalized_events != BROWSER_COMPLETION_EVIDENCE:
            raise ValueError("passed browser evidence does not prove a complete journey")
        raise ValueError("passed browser evidence requires a trusted execution receipt")
    if status in BROWSER_BLOCKED_JOURNEYS:
        if set(observations) != {"blocker"}:
            raise ValueError("blocked browser evidence must contain only a blocker")
        if observations["blocker"] != BROWSER_BLOCKER_CODES[status]:
            raise ValueError("blocked browser evidence does not match its status")
        normalized_observations = {"blocker": BROWSER_BLOCKER_CODES[status]}
    else:
        if set(observations) != {"failure"}:
            raise ValueError("failed browser evidence must contain only a failure")
        if observations["failure"] != BROWSER_FAILURE_CODE:
            raise ValueError("failed browser evidence does not match its status")
        normalized_observations = {"failure": BROWSER_FAILURE_CODE}

    return status, {
        "schema": BROWSER_EVIDENCE_SCHEMA,
        "status": status,
        "provenance": dict(expected_provenance),
        "observations": normalized_observations,
    }


def render_manifest(
    *,
    build_sha: str,
    build_digest: str,
    caddyfile_digest: str,
    browser_journey: str | None = None,
    browser_evidence: Mapping[str, object] | None = None,
    runtime_inputs: Mapping[str, object] | None = None,
    provenance_mode: str = "untrusted",
    static_build_root: Path | None = None,
    repository_root: Path = PROJECT_ROOT,
    retained_loader_token: object | None = None,
) -> dict[str, object]:
    """Create redacted evidence metadata; values are never request material.

    The CLI retained workflow uses a private loader token after the canonical
    path and source-pinned anchor have been checked. Direct library callers
    default to explicitly untrusted provenance and cannot select ``retained``
    without that token. Standalone evidence must instead provide a static tree
    so Git HEAD and its exact bytes are derived locally; caller-supplied identity
    flags are only checked assertions and never establish provenance. Neither
    workflow treats caller JSON, a fixed event map, or local Caddy traffic as
    browser execution; ``passed`` requires a separate trusted receipt and is
    rejected here.
    """

    if not HEX40_RE.fullmatch(build_sha):
        raise ValueError("build_sha must be a lowercase commit SHA")
    _validate_build_digest(build_digest)
    if not HEX64_RE.fullmatch(caddyfile_digest):
        raise ValueError("caddyfile_digest must be a SHA-256 digest")
    if browser_evidence is None:
        raise ValueError("browser evidence is required for every journey status")
    if not isinstance(browser_evidence, Mapping):
        raise ValueError("browser evidence must be a mapping")
    if provenance_mode == "retained" and retained_loader_token is not _RETAINED_LOADER_TOKEN:
        raise ValueError("retained provenance requires the canonical retained loader token")
    normalized_inputs = _validate_runtime_inputs(
        reconstruction_inputs() if runtime_inputs is None else runtime_inputs
    )
    rendered_digest = digest_bytes(render_from_inputs(normalized_inputs).encode("utf-8"))
    if caddyfile_digest != rendered_digest:
        raise ValueError("caddyfile_digest does not match the committed runtime inputs")
    _verify_build_provenance(
        build_sha=build_sha,
        build_digest=build_digest,
        mode=provenance_mode,
        static_build_root=static_build_root,
        repository_root=repository_root,
    )
    runtime_inputs_sha256 = runtime_input_digest(normalized_inputs)
    resolved_journey, normalized_evidence = _resolve_browser_journey(
        browser_journey,
        browser_evidence,
        _browser_evidence_provenance(
            build_sha=build_sha,
            build_digest=build_digest,
            caddyfile_digest=caddyfile_digest,
            runtime_inputs_sha256=runtime_inputs_sha256,
        ),
    )

    # A VM-reported binary version or image digest is not an immutable local
    # trust root. Retain only renderer output, deterministic inputs, and fixed
    # browser status markers; deployment identity must be separately collected
    # and validated before a real deployment claim is made. Current Git/static
    # provenance and historical retained evidence remain separate identities;
    # task-244 parity fixtures are historical inputs, not a current binding.
    provenance_split = {
        "current_git_static": {
            "status": "verified" if provenance_mode == "standalone" else "not_bound",
            "build_sha": build_sha if provenance_mode == "standalone" else None,
            "build_digest": build_digest if provenance_mode == "standalone" else None,
        },
        "historical_retained": {
            "status": "anchored" if provenance_mode == "retained" else "not_bound",
            "source": "committed_retained_evidence" if provenance_mode == "retained" else None,
        },
        "task_244_parity": {
            "status": "historical_fixture_only",
            "current_binding": "not_proven",
        },
    }
    manifest: dict[str, object] = {
        "provenance": provenance_split,
        "schema": SCHEMA,
        "contract": "dashboard-v0.0.1",
        "hermes_source_sha": "f5be9236e00ddf2f2a412697f267078fc4ee068e",
        "deployment": {
            "proxy": "caddy",
            "runtime_config_sha256": caddyfile_digest,
            "runtime_inputs_schema": RUNTIME_INPUT_SCHEMA,
            "runtime_inputs": normalized_inputs,
            "runtime_inputs_sha256": runtime_inputs_sha256,
            "parity_fixtures": parity_fixture_manifest(),
        },
        "product": {
            "build_commit": build_sha,
            "static_manifest_sha256": build_digest,
        },
        "browser_journey": resolved_journey,
        "browser_evidence": normalized_evidence,
        # JSON observations are historical/non-execution data. Keep this
        # machine-readable so downstream tooling cannot mistake them for a
        # verifier-controlled browser receipt.
        "browser_execution": {
            "mode": BROWSER_NON_EXECUTION_MODE,
            "status": BROWSER_NON_EXECUTION_STATUS,
        },
        "retention": {
            "credentials": "redacted",
            "cookies": "redacted",
            "tickets": "redacted",
            "ticket_fragments": "redacted",
            "queries": "redacted",
            "provider_state": "redacted",
            "transcripts": "redacted",
        },
    }
    return manifest


def _effective_static_budget(primary: str, alias: str, default: int | float) -> int | float:
    """Honor either public budget spelling without silently widening limits."""

    primary_value = globals()[primary]
    alias_value = globals()[alias]
    if primary_value != default:
        return primary_value
    return alias_value


def _lexically_normalize_absolute_path(path: Path) -> Path:
    """Normalize ``.`` and ``..`` without following any filesystem link."""

    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    if not candidate.parts or candidate.parts[0] != "/":
        raise ValueError("path must be absolute")
    components: list[str] = []
    for component in candidate.parts[1:]:
        if component in {"", "."}:
            continue
        if component == "..":
            if not components:
                raise ValueError("path escapes the filesystem root")
            components.pop()
            continue
        components.append(component)
    return Path("/").joinpath(*components)


def _open_verified_directory_path(
    path: Path,
    *,
    label: str,
    deadline: float | None = None,
    resolve_parent_aliases: bool = True,
) -> tuple[int, Path]:
    """Open a directory with optional deadline and no-follow resolution."""

    def check_deadline() -> None:
        if deadline is not None and time.monotonic() >= deadline:
            raise ValueError(f"{label} deadline exceeded")

    check_deadline()
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    if candidate.is_symlink():
        raise ValueError(f"{label} must not be a symlink")
    try:
        if resolve_parent_aliases:
            candidate = candidate.resolve(strict=True)
        else:
            candidate = _lexically_normalize_absolute_path(candidate)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ValueError(f"{label} is unavailable") from exc
    check_deadline()
    parent_fd, name = _open_verified_parent(
        candidate,
        label=label,
        deadline=deadline,
        resolve_parent_aliases=False,
    )
    descriptor: int | None = None
    try:
        check_deadline()
        descriptor = _open_verified_directory_at(
            parent_fd,
            name,
            label=label,
            deadline=deadline,
        )
        check_deadline()
        return descriptor, candidate
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        os.close(parent_fd)


def _build_static_digest(site_root: Path) -> str:
    """Hash a bounded static tree through stable descriptor-relative reads."""

    file_limit = int(_effective_static_budget("STATIC_BUILD_MAX_FILES", "STATIC_MAX_FILES", 4096))
    per_file_limit = int(
        _effective_static_budget(
            "STATIC_BUILD_MAX_FILE_BYTES",
            "STATIC_MAX_PER_FILE_BYTES",
            8 * 1024 * 1024,
        )
    )
    total_limit = int(
        _effective_static_budget(
            "STATIC_BUILD_MAX_TOTAL_BYTES",
            "STATIC_MAX_TOTAL_BYTES",
            64 * 1024 * 1024,
        )
    )
    depth_limit = int(
        _effective_static_budget("STATIC_BUILD_MAX_DEPTH", "STATIC_MAX_DEPTH", 32)
    )
    deadline_budget = float(
        _effective_static_budget(
            "STATIC_BUILD_MAX_DEADLINE_SECONDS",
            "STATIC_DIGEST_DEADLINE_SECONDS",
            10,
        )
    )
    if STATIC_BUILD_DEADLINE_SECONDS != 10:
        deadline_budget = float(STATIC_BUILD_DEADLINE_SECONDS)
    if min(file_limit, per_file_limit, total_limit, depth_limit) <= 0 or deadline_budget <= 0:
        raise ValueError("static build budgets must be positive")

    deadline = time.monotonic() + deadline_budget

    def check_deadline() -> None:
        if time.monotonic() >= deadline:
            raise ValueError("static build digest deadline exceeded")

    raw_root = Path(site_root)
    if not raw_root.is_absolute():
        raw_root = Path.cwd() / raw_root
    root_fd, canonical_root = _open_verified_directory_path(
        site_root,
        label="static build root",
        deadline=deadline,
    )
    check_deadline()
    open_directories: list[int] = [root_fd]
    stack: list[tuple[int, tuple[str, ...], int]] = [(root_fd, (), 0)]
    files_seen = 0
    total_bytes = 0
    hasher = hashlib.sha256()

    try:
        while stack:
            check_deadline()
            directory_fd, prefix, depth = stack.pop()
            try:
                with os.scandir(directory_fd) as iterator:
                    entries = []
                    for entry in iterator:
                        entries.append(entry)
                        if len(entries) > file_limit:
                            raise ValueError("static build exceeds file-count budget")
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                if isinstance(exc, ValueError):
                    raise
                raise ValueError("static build directory could not be scanned") from exc
            # Scandir can block even when it yields no entries. The deadline
            # therefore applies after the iterator closes, not only before it.
            check_deadline()

            entries.sort(key=lambda item: item.name)
            for entry in reversed(entries):
                check_deadline()
                name = entry.name
                if not isinstance(name, str) or not name or name in {".", ".."} or "/" in name:
                    raise ValueError("static build contains an invalid pathname entry")
                display_path = raw_root.joinpath(*prefix, name)
                try:
                    # The absolute lstat is an additional race witness for
                    # callers that replace an entry between enumeration and
                    # open; the descriptor-relative stat remains authoritative.
                    displayed = os.lstat(display_path)
                    relative_metadata = os.stat(
                        name,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                except (OSError, RuntimeError, TypeError, ValueError) as exc:
                    raise ValueError("static build entry could not be inspected") from exc
                check_deadline()
                if stat.S_ISLNK(displayed.st_mode):
                    raise ValueError("static build must not contain symlinks")
                if not (
                    stat.S_ISDIR(displayed.st_mode)
                    or stat.S_ISREG(displayed.st_mode)
                ):
                    raise ValueError("static build contains a non-regular special file")
                if _metadata_identity(displayed) != _metadata_identity(relative_metadata):
                    raise ValueError("static build entry changed during inspection")
                if stat.S_ISDIR(displayed.st_mode):
                    if depth + 1 > depth_limit:
                        raise ValueError("static build exceeds depth budget")
                    child_fd = _open_verified_directory_at(
                        directory_fd,
                        name,
                        label="static build directory",
                        deadline=deadline,
                    )
                    child_metadata = os.fstat(child_fd)
                    check_deadline()
                    if (child_metadata.st_dev, child_metadata.st_ino) != (
                        relative_metadata.st_dev,
                        relative_metadata.st_ino,
                    ):
                        os.close(child_fd)
                        raise ValueError("static build directory changed during open")
                    open_directories.append(child_fd)
                    stack.append((child_fd, (*prefix, name), depth + 1))
                    continue
                if not stat.S_ISREG(displayed.st_mode):
                    raise ValueError("static build contains a non-regular special file")
                files_seen += 1
                if files_seen > file_limit:
                    raise ValueError("static build exceeds file-count budget")
                descriptor, metadata = _open_verified_regular_file_at(
                    directory_fd,
                    name,
                    limit=per_file_limit,
                    label="static build file",
                    deadline=deadline,
                )
                try:
                    check_deadline()
                    if _metadata_identity(metadata) != _metadata_identity(relative_metadata):
                        raise ValueError("static build file changed during open")
                    content = _read_bounded_fd(
                        descriptor,
                        per_file_limit,
                        "static build file",
                        deadline=deadline,
                    )
                    check_deadline()
                    _verify_fd_content_identity(
                        descriptor,
                        content,
                        "static build file",
                        deadline=deadline,
                    )
                    check_deadline()
                    after_read = os.fstat(descriptor)
                    check_deadline()
                    if _metadata_identity(metadata) != _metadata_identity(after_read):
                        raise ValueError("static build file changed during read")
                    after_entry = os.stat(
                        name,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                    check_deadline()
                    _verify_regular_metadata(
                        after_entry,
                        limit=per_file_limit,
                        label="static build file",
                    )
                    if _metadata_identity(metadata) != _metadata_identity(after_entry):
                        raise ValueError("static build file changed after read")
                    check_deadline()
                finally:
                    os.close(descriptor)
                check_deadline()
                if total_bytes + len(content) > total_limit:
                    raise ValueError("static build exceeds aggregate byte budget")
                total_bytes += len(content)
                relative = "/".join((*prefix, name)).encode("utf-8")
                hasher.update(relative)
                hasher.update(b"\0")
                hasher.update(str(len(content)).encode("ascii"))
                hasher.update(b"\0")
                hasher.update(content)
                check_deadline()
        check_deadline()
        digest = hasher.hexdigest()
        check_deadline()
        return digest
    finally:
        for descriptor in reversed(open_directories):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _load_retained_input(path: Path) -> dict[str, object]:
    """Load only the canonical, hash-anchored historical manifest."""

    # Verify the canonical path and exact bounded bytes before parsing any
    # caller-visible field. A copied JSON file must not become a new trust root.
    retained_bytes = _read_verified_retained_bytes(path)
    value = _decode_bounded_json(retained_bytes, "retained input")
    if not isinstance(value, Mapping):
        raise ValueError("retained input must be an object")
    product = value.get("product")
    deployment = value.get("deployment")
    browser_evidence = value.get("browser_evidence")
    if not isinstance(product, Mapping) or not isinstance(deployment, Mapping):
        raise ValueError("retained input is missing product or deployment provenance")
    if not isinstance(browser_evidence, Mapping):
        raise ValueError("retained input is missing browser evidence")
    build_sha = product.get("build_commit")
    build_digest = product.get("static_manifest_sha256")
    caddyfile_digest = deployment.get("runtime_config_sha256")
    runtime_inputs = deployment.get("runtime_inputs")
    if type(build_sha) is not str or type(build_digest) is not str or type(caddyfile_digest) is not str:
        raise ValueError("retained input provenance is malformed")
    if not isinstance(runtime_inputs, Mapping):
        raise ValueError("retained input runtime inputs are malformed")
    return {
        "build_sha": build_sha,
        "build_digest": build_digest,
        "caddyfile_digest": caddyfile_digest,
        "runtime_inputs": runtime_inputs,
        "browser_evidence": browser_evidence,
        "browser_journey": value.get("browser_journey"),
        "retained_loader_token": _RETAINED_LOADER_TOKEN,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    render = subparsers.add_parser("render")
    render.add_argument("--host", default=DEFAULT_HOST)
    render.add_argument("--https-port", type=int, default=DEFAULT_HTTPS_PORT)
    render.add_argument("--hermes-port", type=int, default=DEFAULT_HERMES_PORT)
    render.add_argument("--site-root", required=True)
    render.add_argument("--cert-path", required=True)
    render.add_argument("--key-path", required=True)
    render.add_argument("--storage-root", required=True)
    render.add_argument("--output", type=Path)
    digest = subparsers.add_parser("digest")
    digest.add_argument("--input", type=Path)
    build = subparsers.add_parser("build-digest")
    build.add_argument("site_root", type=Path)
    evidence = subparsers.add_parser("evidence")
    evidence_sources = evidence.add_mutually_exclusive_group(required=True)
    evidence_sources.add_argument("--browser-evidence", type=Path)
    evidence_sources.add_argument("--retained-input", type=Path)
    evidence.add_argument(
        "--static-build-root",
        "--build-root",
        dest="static_build_root",
        type=Path,
        help="standalone mode: derive Git HEAD and the static-tree digest from this output",
    )
    # These flags remain optional compatibility assertions. They are checked
    # against derived or committed provenance and never serve as trust roots.
    evidence.add_argument("--build-sha")
    evidence.add_argument("--build-digest")
    evidence.add_argument("--caddyfile-digest")
    evidence.add_argument("--browser-journey")
    args = parser.parse_args(argv)

    if args.command == "render":
        content = render_caddyfile(
            host=args.host,
            https_port=args.https_port,
            hermes_port=args.hermes_port,
            site_root=args.site_root,
            cert_path=args.cert_path,
            key_path=args.key_path,
            storage_root=args.storage_root,
        )
        if args.output:
            args.output.write_text(content, encoding="utf-8")
        else:
            sys.stdout.write(content)
        return 0
    if args.command == "digest":
        content = args.input.read_bytes() if args.input else sys.stdin.buffer.read()
        print(digest_bytes(content))
        return 0
    if args.command == "build-digest":
        print(_build_static_digest(args.site_root))
        return 0
    if args.command == "evidence":
        if args.retained_input is not None:
            if any(
                value is not None
                for value in (
                    args.static_build_root,
                    args.build_sha,
                    args.build_digest,
                    args.caddyfile_digest,
                    args.browser_journey,
                )
            ):
                raise ValueError("retained input cannot be combined with standalone assertions")
            retained = _load_retained_input(args.retained_input)
            manifest = render_manifest(
                build_sha=retained["build_sha"],  # type: ignore[arg-type]
                build_digest=retained["build_digest"],  # type: ignore[arg-type]
                caddyfile_digest=retained["caddyfile_digest"],  # type: ignore[arg-type]
                browser_journey=retained["browser_journey"],  # type: ignore[arg-type]
                browser_evidence=retained["browser_evidence"],  # type: ignore[arg-type]
                runtime_inputs=retained["runtime_inputs"],  # type: ignore[arg-type]
                provenance_mode="retained",
                retained_loader_token=retained["retained_loader_token"],
            )
        else:
            if args.static_build_root is None:
                raise ValueError("standalone evidence requires --static-build-root")
            if args.caddyfile_digest is None:
                raise ValueError("standalone evidence requires --caddyfile-digest")
            derived = _derive_git_static_build_provenance(args.static_build_root)
            build_sha = derived["build_sha"]
            build_digest = derived["build_digest"]
            if args.build_sha is not None and args.build_sha != build_sha:
                raise ValueError("--build-sha does not match derived Git HEAD")
            if args.build_digest is not None and args.build_digest != build_digest:
                raise ValueError("--build-digest does not match the static build bytes")
            browser_evidence = _load_bounded_json(
                args.browser_evidence,
                limit=BROWSER_EVIDENCE_MAX_BYTES,
                label="browser evidence",
            )
            manifest = render_manifest(
                build_sha=build_sha,
                build_digest=build_digest,
                caddyfile_digest=args.caddyfile_digest,
                browser_journey=args.browser_journey,
                browser_evidence=browser_evidence,  # type: ignore[arg-type]
                provenance_mode="standalone",
                static_build_root=args.static_build_root,
            )
        print(json.dumps(manifest, sort_keys=True, separators=(",", ":")))
        return 0
    raise AssertionError("unreachable")


def _cli_entrypoint(argv: list[str] | None = None) -> int:
    """Return deterministic CLI failures without exposing tracebacks."""

    try:
        return main(argv)
    except (ValueError, OSError, RuntimeError, TypeError, UnicodeError, RecursionError, MemoryError, subprocess.SubprocessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(_cli_entrypoint())
