#!/usr/bin/env python3
"""Render and validate the disposable Caddy proof boundary.

This module is intentionally a proof fixture, not a production deployment
configuration. It keeps the reviewed method/path surface explicit so a future
runtime cannot silently replace it with ``/api/*`` or ``/hermes/*``. The
renderer receives only disposable paths and ports from the proof harness; it
never reads credentials, cookies, tickets, transcripts, or provider state.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path


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
GIT_COMMAND_TIMEOUT_SECONDS = 5
HEX40_RE = re.compile(r"[0-9a-f]{40}")
HEX64_RE = re.compile(r"[0-9a-f]{64}")
PROJECT_ROOT = Path(__file__).resolve().parents[1]
RETAINED_EVIDENCE_PATH = PROJECT_ROOT / "tests/integration/hermes-caddy/caddy-proof-evidence.json"
RETAINED_EVIDENCE_ANCHOR_PATH = PROJECT_ROOT / "tests/integration/hermes-caddy/caddy-proof-evidence-sha256.txt"
STATIC_BUILD_REQUIRED_FILES = (
    "index.html",
    "200.html",
    "manifest.webmanifest",
    "service-worker.js",
)
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
    context with a quote, backslash, or control character.
    """

    if type(value) is not str:
        raise ValueError(f"{name} must be an absolute path")
    path = Path(value)
    if not value or not path.is_absolute():
        raise ValueError(f"{name} must be an absolute path")
    if any(character in value for character in ('"', "'", "\\")):
        raise ValueError(f"{name} must not contain Caddy quotes or backslashes")
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


def _read_bounded_bytes(path: Path, limit: int, label: str) -> bytes:
    """Read at most one byte beyond a fixture limit before rejecting it."""

    try:
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
    except OSError as exc:
        raise ValueError(f"{label} could not be read") from exc
    if len(data) > limit:
        raise ValueError(f"{label} exceeds the bounded input size")
    return data


def _load_bounded_json(path: Path, *, limit: int, label: str) -> object:
    """Decode one bounded UTF-8 JSON document with duplicate-key rejection."""

    raw = _read_bounded_bytes(path, limit, label)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not valid UTF-8") from exc
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_json_keys)
    except ValueError as exc:
        if str(exc) == "duplicate JSON object key":
            raise ValueError(f"{label} contains a duplicate JSON object key") from exc
        raise ValueError(f"{label} is not valid JSON") from exc


def _git_text(repository_root: Path, *arguments: str) -> str:
    """Read one bounded, exact Git value from the repository trust root."""

    root = Path(repository_root).resolve()
    if not root.is_dir():
        raise ValueError("Git repository root is unavailable")
    try:
        result = subprocess.run(
            ("git", "-C", str(root), *arguments),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="ascii",
            timeout=GIT_COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
        raise ValueError("Git provenance could not be checked") from exc
    if result.returncode != 0:
        raise ValueError("Git provenance could not be checked")
    value = result.stdout.strip()
    if not value or "\\n" in value or "\\r" in value:
        raise ValueError("Git provenance output is malformed")
    return value


def _git_head(repository_root: Path = PROJECT_ROOT) -> str:
    """Return the full checked-out commit, never a caller-provided alias."""

    head = _git_text(repository_root, "rev-parse", "--verify", "HEAD^{commit}")
    if HEX40_RE.fullmatch(head) is None:
        raise ValueError("Git HEAD is not a full commit SHA")
    return head


def _verify_git_commit(build_sha: str, repository_root: Path = PROJECT_ROOT) -> None:
    """Require a real commit reachable from this checkout's current HEAD."""

    if type(build_sha) is not str or HEX40_RE.fullmatch(build_sha) is None:
        raise ValueError("build_sha must be a lowercase commit SHA")
    resolved = _git_text(repository_root, "rev-parse", "--verify", f"{build_sha}^{{commit}}")
    if resolved != build_sha:
        raise ValueError("build_sha is not an exact Git commit")
    head = _git_head(repository_root)
    if build_sha == head:
        return
    root = Path(repository_root).resolve()
    try:
        result = subprocess.run(
            ("git", "-C", str(root), "merge-base", "--is-ancestor", build_sha, head),
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=GIT_COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("Git build ancestry could not be checked") from exc
    if result.returncode != 0:
        raise ValueError("build_sha is not an ancestor of the checked-out Git HEAD")


def _validate_build_digest(build_digest: object) -> str:
    if type(build_digest) is not str or HEX64_RE.fullmatch(build_digest) is None:
        raise ValueError("build_digest must be a SHA-256 digest")
    return build_digest


def _derive_git_static_build_provenance(
    static_build_root: Path,
    repository_root: Path = PROJECT_ROOT,
) -> dict[str, str]:
    """Derive the build identity from Git and the actual static tree bytes."""

    root = Path(static_build_root).resolve()
    if not root.is_dir():
        raise ValueError("static build root is unavailable")
    for relative_path in STATIC_BUILD_REQUIRED_FILES:
        if not (root / relative_path).is_file():
            raise ValueError("static build is missing a reviewed entry point")
    build_sha = _git_head(repository_root)
    build_digest = _build_static_digest(root)
    return {"build_sha": build_sha, "build_digest": build_digest}


def _committed_retained_build_provenance() -> dict[str, str]:
    """Read the reviewed historical build pair without trusting CLI strings."""

    evidence_bytes = _read_bounded_bytes(
        RETAINED_EVIDENCE_PATH,
        RETAINED_EVIDENCE_MAX_BYTES,
        "committed retained evidence",
    )
    try:
        evidence = json.loads(
            evidence_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (UnicodeDecodeError, ValueError) as exc:
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
    try:
        anchor = RETAINED_EVIDENCE_ANCHOR_PATH.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise ValueError("committed retained evidence anchor is unavailable") from exc
    if HEX64_RE.fullmatch(anchor) is None or digest_bytes(evidence_bytes) != anchor:
        raise ValueError("committed retained evidence anchor does not match")
    return {"build_sha": build_sha, "build_digest": build_digest}


def _verify_build_provenance(
    *,
    build_sha: str,
    build_digest: str,
    mode: str,
    static_build_root: Path | None = None,
    repository_root: Path = PROJECT_ROOT,
) -> None:
    """Verify derived standalone or anchored retained build identity."""

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
    Every status has a fixed observation shape and the provenance must match
    the build, static manifest, rendered Caddyfile, and runtime-input digest
    for this exact proof run.
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
        normalized_observations: dict[str, object] = {"events": normalized_events}
    elif status in BROWSER_BLOCKED_JOURNEYS:
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
    provenance_mode: str = "retained",
    static_build_root: Path | None = None,
    repository_root: Path = PROJECT_ROOT,
) -> dict[str, object]:
    """Create redacted evidence metadata; values are never request material.

    Retained evidence uses the committed historical build anchor. Standalone
    browser evidence must instead provide a static tree so Git HEAD and its
    exact bytes are derived locally; caller-supplied identity flags are only
    checked assertions and never establish provenance.
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
    # and validated before a real deployment claim is made.
    manifest: dict[str, object] = {
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


def _build_static_digest(site_root: Path) -> str:
    entries: list[bytes] = []
    for path in sorted(p for p in site_root.rglob("*") if p.is_file()):
        relative = path.relative_to(site_root).as_posix().encode("utf-8")
        content = path.read_bytes()
        entries.append(relative + b"\0" + str(len(content)).encode("ascii") + b"\0" + content)
    return digest_bytes(b"".join(entries))


def _load_retained_input(path: Path) -> dict[str, object]:
    """Load a complete retained manifest for the explicit historical workflow."""

    value = _load_bounded_json(path, limit=RETAINED_EVIDENCE_MAX_BYTES, label="retained input")
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


if __name__ == "__main__":
    raise SystemExit(main())
