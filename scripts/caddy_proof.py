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
    browser_completion_evidence: Mapping[str, object] | None = None,
    runtime_inputs: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Create redacted evidence metadata; values are never request material."""

    if not re.fullmatch(r"[0-9a-f]{40}", build_sha):
        raise ValueError("build_sha must be a lowercase commit SHA")
    for name, value in (("build_digest", build_digest), ("caddyfile_digest", caddyfile_digest)):
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError(f"{name} must be a SHA-256 digest")

    if browser_evidence is not None and browser_completion_evidence is not None:
        raise ValueError("browser evidence was supplied twice")
    evidence = browser_evidence if browser_evidence is not None else browser_completion_evidence
    normalized_inputs = _validate_runtime_inputs(
        reconstruction_inputs() if runtime_inputs is None else runtime_inputs
    )
    rendered_digest = digest_bytes(render_from_inputs(normalized_inputs).encode("utf-8"))
    if caddyfile_digest != rendered_digest:
        raise ValueError("caddyfile_digest does not match the committed runtime inputs")
    runtime_inputs_sha256 = runtime_input_digest(normalized_inputs)
    resolved_journey, normalized_evidence = _resolve_browser_journey(
        browser_journey,
        evidence,
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
    evidence.add_argument("--build-sha", required=True)
    evidence.add_argument("--build-digest", required=True)
    evidence.add_argument("--caddyfile-digest", required=True)
    evidence.add_argument("--browser-evidence", type=Path, required=True)
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
        evidence_bytes = args.browser_evidence.read_bytes()
        if len(evidence_bytes) > BROWSER_EVIDENCE_MAX_BYTES:
            raise ValueError("browser evidence exceeds the bounded input size")
        try:
            browser_evidence = json.loads(evidence_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("browser evidence is not valid JSON") from exc
        print(
            json.dumps(
                render_manifest(
                    build_sha=args.build_sha,
                    build_digest=args.build_digest,
                    caddyfile_digest=args.caddyfile_digest,
                    browser_journey=args.browser_journey,
                    browser_evidence=browser_evidence,
                ),
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    raise AssertionError("unreachable")


if __name__ == "__main__":
    raise SystemExit(main())
