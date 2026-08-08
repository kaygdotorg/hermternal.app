#!/usr/bin/env python3
"""Render the disposable Traefik HTTPS and prefix-routing proof.

This module emits a deterministic Traefik static/dynamic configuration bundle
for a local proof only.  It is not a production deployment file: a small,
local forward-auth policy service is required because Traefik's native query
matchers cannot express a closed raw-query grammar.  The policy service is the
edge gate; Hermes and the static server remain separate local upstreams.

No credentials, cookies, tickets, transcripts, provider state, live URLs, or
private deployment addresses are read or retained by this renderer.  The
loopback listeners and synthetic authorities are the disposable issue #92
exception, not the production private-network topology.
"""

from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import math
import os
import re
import stat
import sys
import time
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from types import MappingProxyType
from urllib.parse import urlsplit


SCHEMA = "hermternal.traefik-proof.v4"
RUNTIME_INPUT_SCHEMA = "hermternal.traefik-proof.runtime-inputs.v1"
BROWSER_EVIDENCE_SCHEMA = "hermternal.traefik-proof.browser-evidence.v1"
TRAEFIK_RUNTIME_STATUS = "not_run"
TRAEFIK_RUNTIME_VERSION = "not_recorded"
TRAEFIK_RUNTIME_REQUIRED_MINIMUM_VERSION = "v3.7.6"
TRAEFIK_RUNTIME_VALIDATION = "not_run; configuration and rule compatibility are not claimed"
TRAEFIK_RULE_SYNTAX = "Traefik v3 HeaderRegexp model only; v3.7.6 syntax compatibility is not validated"
DEFAULT_HOST = "traefik-92.test"
DEFAULT_HTTPS_PORT = 19444
DEFAULT_HERMES_PORT = 19257
DEFAULT_STATIC_PORT = 19258
DEFAULT_POLICY_PORT = 19259

BROWSER_EVIDENCE_MAX_BYTES = 4096
BROWSER_COMPLETION_EVIDENCE = MappingProxyType(
    {
        "gateway.ready": "proven",
        "session.resume": "proven",
        "prompt.submit": "proven",
        "message.delta": "proven",
        "message.complete": "complete",
    }
)
BROWSER_EVIDENCE_ROOT_KEYS = ("schema", "status", "provenance", "observations")
BROWSER_EVIDENCE_PROVENANCE_KEYS = (
    "build_sha",
    "build_digest",
    "traefik_config_digest",
    "runtime_inputs_sha256",
)
BROWSER_BLOCKED_JOURNEYS = frozenset({"blocked_provider", "blocked_empty_session"})
BROWSER_JOURNEYS = frozenset({"passed", *BROWSER_BLOCKED_JOURNEYS, "failed"})
BROWSER_BLOCKER_CODES = MappingProxyType(
    {
        "blocked_provider": "provider_unavailable",
        "blocked_empty_session": "empty_session",
    }
)
BROWSER_FAILURE_CODE = "browser_assertion_failed"

# Route cases and browser evidence are local fixture observations. Keep their
# deployment meaning explicit: this renderer cannot authorize a live run or
# turn loopback mocks into proof of the private non-loopback Hermes topology.
PROOF_RUN_STATUS = "synthetic_observed"
PROOF_RUN_SCOPE = "synthetic_local"
PROOF_RUN_TOPOLOGY = "loopback_only_disposable"
PROOF_RUN_REQUIRED_TOPOLOGY = "private_non_loopback_hermes_9119_default_deny_proxy_identity"
PROOF_RUN_COMPLETION_GATE = "exact_reviewed_merged_commit_authorized_real_hermes"

# The real deployment boundary is intentionally separate from this disposable
# loopback fixture.  Keep the private Hermes port and bind class explicit so a
# future proof cannot accidentally turn the synthetic service ports into a
# public listener or claim that loopback is production-compatible.
REQUIRED_HERMES_PORT = 9119
REQUIRED_HERMES_BIND_CLASS = "private_non_loopback"
PUBLIC_HERMES_EXPOSURE = False

# Authentication and lifecycle observations below are synthetic models only.
# They make the redaction, one-shot ticket, and PTY cleanup contracts executable
# without retaining a credential, starting Hermes, or contacting a provider.
TICKET_TTL_SECONDS = 30
PTY_DETACHED_TTL_SECONDS = 30 * 60
# Match the web transport's bounded Unix-second representation. This upper
# bound is below 2**53, so accepted integers remain exact when compared with
# finite floats; never coerce an arbitrary integer through float first.
MAX_PTY_TIMESTAMP_SECONDS = 4_294_967_295
UPGRADE_RETRY_POLICY = MappingProxyType({"chat": "disabled", "pty": "disabled"})
SYNTHETIC_COOKIE_PREFIX = "__Host-"
SYNTHETIC_COOKIE_SCOPE = "/hermes"
SYNTHETIC_COOKIE_ATTRIBUTES = ("Secure", "HttpOnly", "SameSite=Lax", "Path=/")

# These are deterministic proof paths, not operator or user home paths.  The
# dynamic file is part of the validated runtime manifest so the static file
# provider always names the file the renderer emits.
DEFAULT_RUNTIME_INPUTS = MappingProxyType(
    {
        "host": DEFAULT_HOST,
        "https_port": DEFAULT_HTTPS_PORT,
        "hermes_port": DEFAULT_HERMES_PORT,
        "static_port": DEFAULT_STATIC_PORT,
        "policy_port": DEFAULT_POLICY_PORT,
        "site_root": "/opt/hermternal/traefik-proof/site",
        "cert_path": "/opt/hermternal/traefik-proof/tls.crt",
        "key_path": "/opt/hermternal/traefik-proof/tls.key",
        "storage_root": "/opt/hermternal/traefik-proof",
        "dynamic_filename": "/opt/hermternal/traefik-proof/traefik-dynamic.json",
    }
)

MAX_REQUEST_TARGET_BYTES = 8192
MAX_FORWARD_HEADER_BYTES = 16384
MAX_FORWARD_HEADER_COUNT = 32
MAX_POLICY_BODY_BYTES = 4096
MAX_RUNTIME_PATH_BYTES = 512
MAX_DIGEST_FILES = 128
MAX_DIGEST_DIRECTORIES = 64
MAX_DIGEST_ENTRIES = 256
MAX_DIGEST_PENDING_DIRECTORIES = 64
MAX_DIGEST_DEPTH = 8
MAX_DIGEST_PATH_BYTES = 512
MAX_DIGEST_FILE_BYTES = 1 << 20
MAX_DIGEST_TOTAL_BYTES = 4 << 20
MAX_DIGEST_CHUNK_BYTES = 64 << 10
MAX_DIGEST_INPUT_BYTES = MAX_DIGEST_TOTAL_BYTES
MAX_DIGEST_SECONDS = 2.0

# Traefik ForwardAuth supplies these generated metadata headers for the pinned
# safe-version range, including the HTTPS entrypoint port. ``authRequestHeaders``
# only selects additional original request headers; this fixture copies Origin
# for the edge Origin policy. No separate raw target, path, query, Upgrade,
# Connection, or original Host field is claimed here.
TRAEFIK_FORWARDAUTH_GENERATED_HEADERS = (
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Forwarded-Method",
    "X-Forwarded-Port",
    "X-Forwarded-Proto",
    "X-Forwarded-Uri",
)
FORWARD_AUTH_HEADERS = ("Origin",)
TRAEFIK_FORWARDAUTH_HEADERS = TRAEFIK_FORWARDAUTH_GENERATED_HEADERS + FORWARD_AUTH_HEADERS
# A ForwardAuth HTTP request also has transport framing that the policy does
# not authorize or forward. Keep this set explicit: Host is the auth-service
# authority, Content-Length only frames the bounded empty/body request, the
# user-agent and compression hints are ignored, and Connection permits close
# only. Application headers such as Authorization and Cookie are not transport
# exceptions and fail closed at the adapter boundary.
FORWARD_AUTH_TRANSPORT_HEADERS = (
    "Host",
    "Content-Length",
    "User-Agent",
    "Accept-Encoding",
    "Connection",
)
HERMES_FORWARDING_ALLOWLIST = (
    "Connection",
    "Forwarded",
    "Host",
    "Origin",
    "Upgrade",
    "X-Forwarded-Connection",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Forwarded-Method",
    "X-Forwarded-Path",
    "X-Forwarded-Port",
    "X-Forwarded-Prefix",
    "X-Forwarded-Proto",
    "X-Forwarded-Query",
    "X-Forwarded-Raw-Target",
    "X-Forwarded-Upgrade",
    "X-Forwarded-Uri",
    "X-Real-IP",
)
HOP_BY_HOP_HEADERS = (
    "Connection",
    "Keep-Alive",
    "Proxy-Authenticate",
    "Proxy-Authorization",
    "TE",
    "Trailer",
    "Transfer-Encoding",
    "Upgrade",
)
STATIC_PATHS = (
    "/",
    "/index.html",
    "/200.html",
    "/_app/*",
    "/service-worker.js",
    "/manifest.webmanifest",
    "/icon.svg",
)
CLIENT_ROUTE_PATTERN = r"^/v1/c/[A-Za-z0-9._~-]{16,}(?:/m/[A-Za-z0-9._~-]{16,})?$"
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
WEBSOCKET_ROUTES = ("/api/ws", "/api/pty")

RAW_UNSAFE_RE = re.compile(r"(?:%|\\|//|\.\.\.)")
DOT_SEGMENT_RE = re.compile(r"(?:^|/)(?:\.|\.\.)(?:/|\?|$)")
AUTH_CALLBACK_CODE_STATE_PATTERN = r"^code=[A-Za-z0-9._~-]{1,512}&state=[A-Za-z0-9._~-]{1,512}$"
AUTH_CALLBACK_STATE_CODE_PATTERN = r"^state=[A-Za-z0-9._~-]{1,512}&code=[A-Za-z0-9._~-]{1,512}$"
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
CHAT_TICKET_VALUE_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._~-]{0,511}"
CHAT_TICKET_QUERY_PATTERN = rf"^ticket={CHAT_TICKET_VALUE_PATTERN}$"
PTY_TICKET_VALUE_PATTERN = CHAT_TICKET_VALUE_PATTERN
PTY_RESUME_VALUE_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._~-]{0,127}"
PTY_ATTACH_VALUE_PATTERN = PTY_TICKET_VALUE_PATTERN
PTY_QUERY_PARAMETER_PATTERNS = {
    "ticket": rf"ticket={PTY_TICKET_VALUE_PATTERN}",
    "resume": rf"resume={PTY_RESUME_VALUE_PATTERN}",
    "attach": rf"attach={PTY_ATTACH_VALUE_PATTERN}",
}


def _pty_query_patterns() -> tuple[str, ...]:
    permutations = (
        ("ticket", "resume"),
        ("resume", "ticket"),
        ("ticket", "resume", "attach"),
        ("ticket", "attach", "resume"),
        ("resume", "ticket", "attach"),
        ("resume", "attach", "ticket"),
        ("attach", "ticket", "resume"),
        ("attach", "resume", "ticket"),
    )
    return tuple(rf"^{'&'.join(PTY_QUERY_PARAMETER_PATTERNS[key] for key in keys)}$" for keys in permutations)


PTY_QUERY_PATTERNS = _pty_query_patterns()

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
    """Reject parser-context changes before a path enters JSON configuration."""

    if type(value) is not str or not value:
        raise ValueError(f"{name} must be an absolute path")
    if len(value) > MAX_RUNTIME_PATH_BYTES:
        raise ValueError(f"{name} exceeds the path size limit")
    encoded = value.encode("utf-8")
    if len(encoded) > MAX_RUNTIME_PATH_BYTES:
        raise ValueError(f"{name} exceeds the path size limit")
    if not Path(value).is_absolute():
        raise ValueError(f"{name} must be an absolute path")
    if any(character in value for character in ('"', "'", "\\")):
        raise ValueError(f"{name} must not contain quotes or backslashes")
    if any(ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F for character in value):
        raise ValueError(f"{name} must not contain control characters")
    return value


def _validate_runtime_inputs(value: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError("runtime_inputs must contain the exact renderer input keys")
    expected_keys = tuple(DEFAULT_RUNTIME_INPUTS)
    try:
        declared_count = len(value)
    except (TypeError, ValueError):
        declared_count = None
    if declared_count is not None and declared_count > len(expected_keys):
        raise ValueError("runtime_inputs must contain the exact renderer input keys")
    keys: list[object] = []
    try:
        for index, key in enumerate(value):
            if index >= len(expected_keys):
                raise ValueError("runtime_inputs must contain the exact renderer input keys")
            keys.append(key)
    except (TypeError, ValueError) as exc:
        if isinstance(exc, ValueError) and str(exc).startswith("runtime_inputs"):
            raise
        raise ValueError("runtime_inputs must contain the exact renderer input keys") from exc
    try:
        exact_keys = frozenset(keys)
    except TypeError as exc:
        raise ValueError("runtime_inputs must contain the exact renderer input keys") from exc
    if len(keys) != len(expected_keys) or exact_keys != frozenset(expected_keys):
        raise ValueError("runtime_inputs must contain the exact renderer input keys")
    normalized = {
        "host": _validate_host(value["host"]),
        "https_port": _validate_port(value["https_port"], "https_port"),
        "hermes_port": _validate_port(value["hermes_port"], "hermes_port"),
        "static_port": _validate_port(value["static_port"], "static_port"),
        "policy_port": _validate_port(value["policy_port"], "policy_port"),
        "site_root": _validate_path(value["site_root"], "site_root"),
        "cert_path": _validate_path(value["cert_path"], "cert_path"),
        "key_path": _validate_path(value["key_path"], "key_path"),
        "storage_root": _validate_path(value["storage_root"], "storage_root"),
        "dynamic_filename": _validate_path(value["dynamic_filename"], "dynamic_filename"),
    }
    storage_root = Path(str(normalized["storage_root"])).resolve()
    dynamic_filename = Path(str(normalized["dynamic_filename"])).resolve()
    if dynamic_filename.parent != storage_root:
        raise ValueError("dynamic_filename must be directly under storage_root")
    if dynamic_filename.name != "traefik-dynamic.json":
        raise ValueError("dynamic_filename must be traefik-dynamic.json")
    return normalized


def reconstruction_inputs() -> dict[str, object]:
    """Return safe inputs used to reconstruct retained evidence."""

    return dict(DEFAULT_RUNTIME_INPUTS)


def _require_exact_mapping_keys(value: Mapping[str, object], expected: Sequence[str], label: str) -> None:
    """Validate a small closed mapping without materializing unbounded keys."""

    try:
        iterator = iter(value)
    except TypeError as exc:
        raise ValueError(f"{label} must be a mapping") from exc
    keys: list[object] = []
    for index, key in enumerate(iterator):
        if index >= len(expected):
            raise ValueError(f"{label} keys are outside the closed contract")
        keys.append(key)
    try:
        exact_keys = frozenset(keys)
    except TypeError as exc:
        raise ValueError(f"{label} keys are malformed") from exc
    if len(keys) != len(expected) or exact_keys != frozenset(expected):
        raise ValueError(f"{label} keys are outside the closed contract")


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def runtime_input_digest(value: Mapping[str, object]) -> str:
    normalized = _validate_runtime_inputs(value)
    return digest_bytes(json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8"))


PARITY_FIXTURE_PATHS = {
    "static_route_grammar": "apps/web/src/lib/static-route-grammar.mjs",
    "deep_link_cases": "contracts/fixtures/deep-link-grammar/cases.json",
}


def parity_fixture_manifest() -> dict[str, dict[str, str]]:
    """Bind Traefik vectors to bounded, regular source files."""

    project_root = Path(__file__).resolve().parents[1]
    return {
        name: {"path": relative_path, "sha256": _digest_regular_file(project_root / relative_path)}
        for name, relative_path in PARITY_FIXTURE_PATHS.items()
    }


def _authority(inputs: Mapping[str, object]) -> str:
    normalized = _validate_runtime_inputs(inputs)
    return f"{normalized['host']}:{normalized['https_port']}"


def _host_rule(authority: str) -> str:
    return f"Host(`{authority}`)"


def _path_rule(paths: Iterable[str]) -> str:
    return " || ".join(f"Path(`{path}`)" for path in paths)


def _method_path_rule(host: str, method: str, paths: Iterable[str]) -> str:
    return f"{_host_rule(host)} && Method(`{method}`) && ({_path_rule(paths)})"


def _websocket_rule(host: str, path: str) -> str:
    """Require the client handshake at the Traefik router boundary.

    ForwardAuth does not guarantee Upgrade or Connection metadata at its
    service boundary, so those hop-by-hop checks belong in the router matcher,
    not in the executable policy adapter.
    """

    return (
        f"{_host_rule(host)} && Method(`GET`) && Path(`{path}`) && "
        "HeaderRegexp(`Upgrade`, `(?i)^websocket$`) && "
        "HeaderRegexp(`Connection`, `(?i)(^|.*,\\s*)Upgrade(\\s*,.*|$)`)"
    )


def _session_path_rule(prefix: str, suffix: str) -> str:
    return f"PathRegexp(`^{prefix}/sessions/{SESSION_ID_PATTERN}{suffix}$`)"


def _router(
    *,
    rule: str,
    priority: int,
    middlewares: list[str],
    service: str,
) -> dict[str, object]:
    return {
        "entryPoints": ["websecure"],
        "rule": rule,
        "priority": priority,
        "middlewares": middlewares,
        "service": service,
        "tls": {},
    }


def render_static_config(value: Mapping[str, object]) -> dict[str, object]:
    """Render the Traefik static config, including the loopback boundary."""

    inputs = _validate_runtime_inputs(value)
    return {
        "entryPoints": {
            "websecure": {
                "address": f"127.0.0.1:{inputs['https_port']}",
                "forwardedHeaders": {"insecure": False},
                "http": {"tls": {}},
            }
        },
        "providers": {
            "file": {
                "filename": str(inputs["dynamic_filename"]),
                "watch": False,
            }
        },
        "log": {"level": "ERROR", "format": "json"},
        "accessLog": {"format": "json", "filters": {"statusCodes": ["400-599"]}},
    }


def _request_headers(
    authority: str,
    public_port: int,
    hermes_port: int,
    prefix: str,
    *,
    websocket: bool = False,
) -> dict[str, str]:
    """Build the finite known-field override map for the Hermes contract.

    Traefik's Headers middleware supports overrides for explicitly named
    headers, not a wildcard delete. Empty values express the intended finite
    removal map, but this offline fixture does not prove Traefik's runtime
    deletion, RFC hop-by-hop handling, or Connection-token behavior. It also
    does not claim that arbitrary unknown inbound headers are removed.
    """

    private_authority = f"127.0.0.1:{hermes_port}"
    headers = {
        "Forwarded": f"for=127.0.0.1;host={authority};proto=https",
        "Host": private_authority,
        "Origin": f"http://{private_authority}",
        "X-Forwarded-For": "127.0.0.1",
        "X-Forwarded-Host": authority,
        "X-Forwarded-Port": str(public_port),
        "X-Forwarded-Prefix": prefix,
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Upgrade": "websocket" if websocket else "",
        "X-Forwarded-Connection": "Upgrade" if websocket else "",
        "X-Real-IP": "127.0.0.1",
    }
    for name in HOP_BY_HOP_HEADERS:
        headers[name] = ""
    if websocket:
        headers["Upgrade"] = "websocket"
        headers["Connection"] = "Upgrade"
    return headers


def render_dynamic_config(value: Mapping[str, object]) -> dict[str, object]:
    """Render routes and local policy middleware for one proof run.

    Traefik's native Query/QueryRegexp matchers permit extra unknown query
    keys. Every router therefore runs the local ForwardAuth policy first; that
    policy parses Traefik's standard X-Forwarded-Uri into the closed query
    grammar in ``policy_decision``. WebSocket Upgrade and Connection checks are
    router-level matchers because ForwardAuth does not guarantee those headers.
    This keeps edge denials before either Hermes or static upstream access.
    """

    inputs = _validate_runtime_inputs(value)
    host = str(inputs["host"])
    authority = _authority(inputs)
    https_port = int(inputs["https_port"])
    hermes_port = int(inputs["hermes_port"])
    static_port = int(inputs["static_port"])
    policy_port = int(inputs["policy_port"])
    # Traefik's Host matcher uses the normalized host name; the ForwardAuth
    # policy separately requires the exact host-plus-port authority.
    host_rule = _host_rule(host)

    routers: dict[str, dict[str, object]] = {
        # A wrong authority must produce the policy's 421 before a service is
        # selected.  The service is a harmless local policy endpoint fallback.
        "wrong_host": _router(
            rule=f"!{host_rule}",
            priority=10000,
            middlewares=["edge-policy"],
            service="policy-deny",
        ),
    }

    root_get = [path for method, path in EXACT_REST_ROUTES if method == "GET" and path != "/auth/callback"]
    root_post = [path for method, path in EXACT_REST_ROUTES if method == "POST"]
    root_patch = [path for method, path in EXACT_REST_ROUTES if method == "PATCH"]
    if root_get:
        routers["root_rest_get"] = _router(
            rule=_method_path_rule(host, "GET", root_get),
            priority=700,
            middlewares=["edge-policy", "root-hermes-headers"],
            service="hermes",
        )
    routers["root_auth_callback"] = _router(
        rule=_method_path_rule(host, "GET", ("/auth/callback",)),
        priority=710,
        middlewares=["edge-policy", "root-hermes-headers"],
        service="hermes",
    )
    if root_post:
        routers["root_rest_post"] = _router(
            rule=_method_path_rule(host, "POST", root_post),
            priority=700,
            middlewares=["edge-policy", "root-hermes-headers"],
            service="hermes",
        )
    if root_patch:
        routers["root_rest_patch"] = _router(
            rule=_method_path_rule(host, "PATCH", root_patch),
            priority=700,
            middlewares=["edge-policy", "root-hermes-headers"],
            service="hermes",
        )

    for name, method, suffix in (
        ("root_session_get", "GET", ""),
        ("root_messages_get", "GET", "/messages"),
        ("root_session_patch", "PATCH", ""),
    ):
        routers[name] = _router(
            rule=f"{host_rule} && Method(`{method}`) && {_session_path_rule('/api', suffix)}",
            priority=705,
            middlewares=["edge-policy", "root-hermes-headers"],
            service="hermes",
        )

    routers["root_chat_ws"] = _router(
        rule=_websocket_rule(host, "/api/ws"),
        priority=720,
        middlewares=["edge-policy", "root-websocket-hermes-headers"],
        service="hermes",
    )
    routers["root_pty_ws"] = _router(
        rule=_websocket_rule(host, "/api/pty"),
        priority=720,
        middlewares=["edge-policy", "root-websocket-hermes-headers"],
        service="hermes",
    )
    # A path-only deny router prevents malformed handshakes and non-GET
    # requests from falling through to the generic static host router. The
    # positive HeaderRegexp routers above remain the only path to Hermes.
    for name, path in (
        ("root_chat_ws_deny", "/api/ws"),
        ("root_pty_ws_deny", "/api/pty"),
    ):
        routers[name] = _router(
            rule=f"{host_rule} && Path(`{path}`)",
            priority=710,
            middlewares=["edge-deny"],
            service="policy-deny",
        )
    routers["client_deep_link"] = _router(
        rule=f"{host_rule} && Method(`GET`, `HEAD`) && PathRegexp(`{CLIENT_ROUTE_PATTERN}`)",
        priority=650,
        middlewares=["edge-policy", "client-deep-link-fallback"],
        service="static",
    )

    for name, path in (("dashboard_chat_ws", "/hermes/api/ws"), ("dashboard_pty_ws", "/hermes/api/pty")):
        routers[name] = _router(
            rule=_websocket_rule(host, path),
            priority=720,
            middlewares=["edge-policy", "strip-hermes", "dashboard-websocket-hermes-headers"],
            service="hermes",
        )
    for name, path in (
        ("dashboard_chat_ws_deny", "/hermes/api/ws"),
        ("dashboard_pty_ws_deny", "/hermes/api/pty"),
    ):
        routers[name] = _router(
            rule=f"{host_rule} && Path(`{path}`)",
            priority=710,
            middlewares=["edge-deny"],
            service="policy-deny",
        )

    # The /hermes prefix is routed to the same Hermes service only after the
    # policy gate has accepted the post-prefix path and exact query grammar.
    routers["dashboard_prefix"] = _router(
        rule=f"{host_rule} && PathPrefix(`/hermes`)",
        priority=600,
        middlewares=["edge-policy", "strip-hermes", "dashboard-hermes-headers"],
        service="hermes",
    )

    # The lowest-priority host router is the static catch-all.  The policy
    # service rejects unknown paths, methods, and query mutations before the
    # static upstream is contacted; it is not a shell fallback.
    routers["static"] = _router(
        rule=host_rule,
        priority=1,
        middlewares=["edge-policy"],
        service="static",
    )

    dynamic = {
        "http": {
            "routers": routers,
            "middlewares": {
                "edge-policy": {
                    "forwardAuth": {
                        "address": f"http://127.0.0.1:{policy_port}/check",
                        "trustForwardHeader": False,
                        # Traefik supplies the six X-Forwarded-* metadata
                        # fields itself; only Origin is copied from the client.
                        "authRequestHeaders": list(FORWARD_AUTH_HEADERS),
                    }
                },
                # Invalid WebSocket handshakes must not fall through to the
                # generic host router. The deny endpoint always returns 404,
                # so these path-only exclusion routers never reach Hermes or
                # the static service.
                "edge-deny": {
                    "forwardAuth": {
                        "address": f"http://127.0.0.1:{policy_port}/deny",
                        "trustForwardHeader": False,
                        "authRequestHeaders": [],
                    }
                },
                "strip-hermes": {
                    "stripPrefix": {"prefixes": ["/hermes"], "forceSlash": False}
                },
                "client-deep-link-fallback": {
                    "replacePathRegex": {
                        "regex": CLIENT_ROUTE_PATTERN,
                        "replacement": "/200.html",
                    }
                },
                "root-hermes-headers": {
                    "headers": {"customRequestHeaders": _request_headers(authority, https_port, hermes_port, "")}
                },
                "root-websocket-hermes-headers": {
                    "headers": {
                        "customRequestHeaders": _request_headers(
                            authority, https_port, hermes_port, "", websocket=True
                        )
                    }
                },
                "dashboard-websocket-hermes-headers": {
                    "headers": {
                        "customRequestHeaders": _request_headers(
                            authority, https_port, hermes_port, "/hermes", websocket=True
                        )
                    }
                },
                "dashboard-hermes-headers": {
                    "headers": {"customRequestHeaders": _request_headers(authority, https_port, hermes_port, "/hermes")}
                },
            },
            "services": {
                "hermes": {
                    "loadBalancer": {
                        "passHostHeader": False,
                        "servers": [{"url": f"http://127.0.0.1:{hermes_port}"}],
                    }
                },
                "static": {
                    "loadBalancer": {
                        "passHostHeader": False,
                        "servers": [{"url": f"http://127.0.0.1:{static_port}"}],
                    }
                },
                "policy-deny": {
                    "loadBalancer": {
                        "passHostHeader": False,
                        "servers": [{"url": f"http://127.0.0.1:{policy_port}"}],
                    }
                },
            },
        },
        "tls": {
            "options": {"default": {"minVersion": "VersionTLS12"}},
            "certificates": [
                {"certFile": inputs["cert_path"], "keyFile": inputs["key_path"]}
            ],
        },
    }
    return dynamic


def render_bundle(value: Mapping[str, object] | None = None) -> dict[str, object]:
    inputs = _validate_runtime_inputs(reconstruction_inputs() if value is None else value)
    return {
        "static": render_static_config(inputs),
        "dynamic": render_dynamic_config(inputs),
    }


def rendered_config_digest(value: Mapping[str, object] | None = None) -> str:
    bundle = render_bundle(value)
    encoded = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return digest_bytes(encoded)


def _browser_evidence_provenance(
    *, build_sha: str, build_digest: str, traefik_config_digest: str, runtime_inputs_sha256: str
) -> dict[str, str]:
    return {
        "build_sha": build_sha,
        "build_digest": build_digest,
        "traefik_config_digest": traefik_config_digest,
        "runtime_inputs_sha256": runtime_inputs_sha256,
    }


def _resolve_browser_journey(
    browser_journey: str | None,
    browser_evidence: Mapping[str, object] | None,
    expected_provenance: Mapping[str, str],
) -> tuple[str, dict[str, object]]:
    if browser_evidence is None:
        raise ValueError("browser evidence is required for every journey status")
    if not isinstance(browser_evidence, Mapping):
        raise ValueError("browser evidence must be a mapping")
    if browser_journey is not None and (type(browser_journey) is not str or browser_journey not in BROWSER_JOURNEYS):
        raise ValueError("browser_journey is outside the fixed proof vocabulary")
    _require_exact_mapping_keys(browser_evidence, BROWSER_EVIDENCE_ROOT_KEYS, "browser evidence")
    if browser_evidence["schema"] != BROWSER_EVIDENCE_SCHEMA:
        raise ValueError("browser evidence schema is unsupported")
    status = browser_evidence["status"]
    if type(status) is not str or status not in BROWSER_JOURNEYS:
        raise ValueError("browser evidence status is unsupported")
    if browser_journey is not None and browser_journey != status:
        raise ValueError("browser_journey does not match browser evidence")
    provenance = browser_evidence["provenance"]
    if not isinstance(provenance, Mapping):
        raise ValueError("browser evidence provenance keys are incomplete")
    _require_exact_mapping_keys(provenance, BROWSER_EVIDENCE_PROVENANCE_KEYS, "browser evidence provenance")
    if dict(provenance) != dict(expected_provenance):
        raise ValueError("browser evidence provenance is stale or mismatched")
    observations = browser_evidence["observations"]
    if not isinstance(observations, Mapping):
        raise ValueError("browser evidence observations must be a mapping")
    if status == "passed":
        _require_exact_mapping_keys(observations, ("events",), "passed browser evidence")
        events = observations["events"]
        if not isinstance(events, Mapping):
            raise ValueError("passed browser evidence must contain the closed event set")
        _require_exact_mapping_keys(events, tuple(BROWSER_COMPLETION_EVIDENCE), "browser completion events")
        normalized_events = {event: events[event] for event in BROWSER_COMPLETION_EVIDENCE}
        if normalized_events != BROWSER_COMPLETION_EVIDENCE:
            raise ValueError("passed browser evidence does not prove a complete journey")
        normalized_observations: dict[str, object] = {"events": normalized_events}
    elif status in BROWSER_BLOCKED_JOURNEYS:
        _require_exact_mapping_keys(observations, ("blocker",), "blocked browser evidence")
        if observations["blocker"] != BROWSER_BLOCKER_CODES[status]:
            raise ValueError("blocked browser evidence does not match its status")
        normalized_observations = {"blocker": BROWSER_BLOCKER_CODES[status]}
    else:
        _require_exact_mapping_keys(observations, ("failure",), "failed browser evidence")
        if observations["failure"] != BROWSER_FAILURE_CODE:
            raise ValueError("failed browser evidence does not match its status")
        normalized_observations = {"failure": BROWSER_FAILURE_CODE}
    return status, {
        "schema": BROWSER_EVIDENCE_SCHEMA,
        "status": status,
        "provenance": dict(expected_provenance),
        "observations": normalized_observations,
    }


def _synthetic_proof_run() -> dict[str, object]:
    """Reconstruct the fixed boundary from immutable scalar constants."""

    return {
        "status": PROOF_RUN_STATUS,
        "scope": PROOF_RUN_SCOPE,
        "live_run": False,
        "compatible": False,
        "topology": PROOF_RUN_TOPOLOGY,
        "required_live_topology": PROOF_RUN_REQUIRED_TOPOLOGY,
        "completion_gate": PROOF_RUN_COMPLETION_GATE,
    }


def _annotated_cases(cases: Iterable[Mapping[str, object]]) -> list[dict[str, object]]:
    """Attach the observation level without turning model cases into runtime proof."""

    annotated: list[dict[str, object]] = []
    for case in cases:
        case_id = str(case.get("id", ""))
        if case_id in {"ws_upgrade", "pty_upgrade", "malformed_upgrade"}:
            proof_level = "model_plus_router_rule"
            observed_by = "policy_model;traefik_runtime_not_run"
        elif case_id == "direct_private_port":
            proof_level = "model_boundary_only"
            observed_by = "offline_model_only"
        else:
            proof_level = "model"
            observed_by = "offline_policy_model"
        annotated.append({**dict(case), "proof_level": proof_level, "observed_by": observed_by})
    return annotated


def render_manifest(
    *,
    build_sha: str,
    build_digest: str,
    traefik_config_digest: str,
    browser_journey: str | None = None,
    browser_evidence: Mapping[str, object] | None = None,
    runtime_inputs: Mapping[str, object] | None = None,
) -> dict[str, object]:
    if not re.fullmatch(r"[0-9a-f]{40}", build_sha):
        raise ValueError("build_sha must be a lowercase commit SHA")
    for name, value in (("build_digest", build_digest), ("traefik_config_digest", traefik_config_digest)):
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError(f"{name} must be a SHA-256 digest")
    normalized_inputs = _validate_runtime_inputs(reconstruction_inputs() if runtime_inputs is None else runtime_inputs)
    if traefik_config_digest != rendered_config_digest(normalized_inputs):
        raise ValueError("traefik_config_digest does not match the committed runtime inputs")
    runtime_inputs_sha256 = runtime_input_digest(normalized_inputs)
    resolved_journey, normalized_evidence = _resolve_browser_journey(
        browser_journey,
        browser_evidence,
        _browser_evidence_provenance(
            build_sha=build_sha,
            build_digest=build_digest,
            traefik_config_digest=traefik_config_digest,
            runtime_inputs_sha256=runtime_inputs_sha256,
        ),
    )
    return {
        "schema": SCHEMA,
        "issue": "92",
        "contract": "dashboard-v0.0.1",
        "deployment": {
            "proxy": "traefik",
            "hermes_source_sha": "f5be9236e00ddf2f2a412697f267078fc4ee068e",
            "runtime_config_sha256": traefik_config_digest,
            "runtime_inputs_schema": RUNTIME_INPUT_SCHEMA,
            "runtime_inputs": normalized_inputs,
            "runtime_inputs_sha256": runtime_inputs_sha256,
            "parity_fixtures": parity_fixture_manifest(),
            # These fields distinguish the disposable loopback fixture from the
            # required production boundary. The fixture must never be treated
            # as proof that Hermes may bind publicly or on a different port.
            "hermes_listener": "loopback-only",
            "required_hermes_port": REQUIRED_HERMES_PORT,
            "required_hermes_bind_class": REQUIRED_HERMES_BIND_CLASS,
            "public_hermes_exposure": PUBLIC_HERMES_EXPOSURE,
            "production_topology": PROOF_RUN_REQUIRED_TOPOLOGY,
            "public_listener": "loopback-only-disposable",
            "edge_policy": "local-forward-auth-closed-query-gate",
        },
        "traefik_runtime": {
            "status": TRAEFIK_RUNTIME_STATUS,
            "version": TRAEFIK_RUNTIME_VERSION,
            "required_minimum_version": TRAEFIK_RUNTIME_REQUIRED_MINIMUM_VERSION,
            "runtime_validation": TRAEFIK_RUNTIME_VALIDATION,
            "rule_syntax": TRAEFIK_RULE_SYNTAX,
        },
        "forward_auth_contract": {
            "generated_headers": list(TRAEFIK_FORWARDAUTH_GENERATED_HEADERS),
            "copied_headers": list(FORWARD_AUTH_HEADERS),
            "transport_headers": list(FORWARD_AUTH_TRANSPORT_HEADERS),
            "auth_request_host": "transport-only-auth-service-authority-not-public-authority",
            "port": "X-Forwarded-Port must equal the configured HTTPS entrypoint port",
            "uri": "X-Forwarded-Uri includes query; it is not raw-target evidence",
            "websocket": "router-matcher-only; Upgrade and Connection are not ForwardAuth observations",
            "hop_by_hop": "direct injected hop-by-hop fields are rejected; only transport Connection: close is tolerated",
            "runtime_observed": False,
        },
        "product": {
            "build_commit": build_sha,
            "static_manifest_sha256": build_digest,
        },
        # This renderer never upgrades synthetic observations into deployment
        # compatibility. A separately reviewed live run must exercise the exact
        # merged commit against authorized Hermes in the required topology.
        "proof_run": _synthetic_proof_run(),
        "browser_journey": resolved_journey,
        "browser_evidence": normalized_evidence,
        # Return defensive copies so a caller cannot mutate the retained
        # evidence vocabulary used by a later manifest render.
        "positive_cases": _annotated_cases(POSITIVE_CASES),
        "negative_cases": _annotated_cases(NEGATIVE_CASES),
        "model_assertions": {
            "scope": "pure Traefik renderer and policy model assertions",
            "route_vectors": "shared static-route grammar and deep-link fixture identities",
            "assertions": [
                "valid session and message deep links are accepted by the model",
                "root-only scenario query is accepted by the model",
                "static, client, and non-callback REST query mutations are model-denied",
                "OAuth callback accepts only the reviewed code/state or provider-error query forms",
                "standard Traefik ForwardAuth metadata is accepted: X-Forwarded-For, X-Forwarded-Host, X-Forwarded-Method, X-Forwarded-Port, X-Forwarded-Proto, and X-Forwarded-Uri",
                "X-Forwarded-Port must equal the configured HTTPS entrypoint port",
                "only Origin is selected as an additional original request header; the auth request Host is transport-only and not the public authority",
                "the adapter accepts only the generated ForwardAuth set, Origin, and explicit bounded transport headers; Authorization, Cookie, and unknown headers are denied",
                "X-Forwarded-Uri is parsed for path and query policy but is not raw-target evidence",
                "request paths and targets reject C0, DEL, and C1 control characters before route matching",
                "WebSocket Upgrade and Connection enforcement is represented only by router HeaderRegexp matchers",
                "finite known fields are overridden, while Traefik runtime deletion of RFC hop-by-hop and Connection-listed tokens remains unproven",
                "arbitrary inbound forwarding aliases are outside the finite Traefik override claim and require separate live deployment proof",
                "the v3.7.6 minimum and HeaderRegexp rule syntax are recorded requirements, not runtime compatibility evidence",
                "chat and PTY upgrade grammars remain distinct in the model",
                "the /hermes prefix is stripped exactly once; duplicated and near-prefix paths are denied",
                "SPA fallback maps only canonical client deep links to /200.html",
                "the synthetic __Host- cookie canary requires Secure, HttpOnly, SameSite=Lax, Path=/, and no Domain",
                "WebSocket tickets are single-use with a 30-second TTL and retained request material is redacted",
                "PTY timestamps are finite non-negative bounded Unix seconds and monotonic against stored lifecycle events; reattach rejects elapsed time beyond the 30-minute TTL before periodic cleanup, while reap deletes the stale handle after the boundary without retaining input bytes",
                "Chat and PTY WebSocket retries are disabled",
                "the required Hermes boundary is private non-loopback TCP 9119 with no public exposure",
                "blocked edge and direct-port vectors retain upstream_request=false",
            ],
            "request_material": "redacted",
        },
        "offline_harness": {
            "status": "regression_tested",
            "scope": "loopback-only executable ForwardAuth adapter; no Traefik or Hermes process",
            "traefik_runtime": "not_run; configuration and rule compatibility are not claimed",
            "assertions": [
                "actual HTTP requests reach the bounded closed-contract ForwardAuth adapter",
                "X-Forwarded-Port is checked against the configured HTTPS entrypoint port",
                "accepted requests return ForwardAuth 200 and denied requests return bounded edge status",
                "C0, DEL, and C1 request-target controls are denied before route matching",
                "X-Forwarded-Uri path/query parsing is executable locally; raw-target and WebSocket handshake observation are not claimed",
                "blocked edge and network vectors retain upstream_request=false in the annotated evidence",
            ],
            "no_upstream_observation": "edge_no_upstream evidence is reconstructed from bounded negative case metadata",
        },
        "cookie_proof": {
            "status": "not_proven",
            "reason": "Traefik renderer output does not prove HttpOnly, SameSite, Path, or Secure on a real Set-Cookie response",
            "synthetic_model": secure_prefixed_cookie_observation(
                "__Host-fixture=synthetic; Secure; HttpOnly; SameSite=Lax; Path=/"
            ),
        },
        "ticket_lifecycle": synthetic_ticket_lifecycle_observation(),
        "pty_lifecycle": synthetic_pty_lifecycle_observation(),
        "upgrade_retry_policy": upgrade_retry_policy(),
        "hermes_boundary": private_hermes_boundary_observation(),
        "edge_no_upstream": edge_no_upstream_observation(),
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


def _check_digest_budget(started: float, *, files: int, total_bytes: int) -> None:
    if time.monotonic() - started > MAX_DIGEST_SECONDS:
        raise ValueError("static digest exceeded its time budget")
    if files > MAX_DIGEST_FILES:
        raise ValueError("static digest exceeded its file-count budget")
    if total_bytes > MAX_DIGEST_TOTAL_BYTES:
        raise ValueError("static digest exceeded its byte budget")


def _check_digest_path(path: Path, label: str) -> None:
    """Apply the digest path budget to roots, directories, and files."""

    try:
        path_bytes = len(os.fsencode(str(path)))
    except (TypeError, UnicodeError) as exc:
        raise ValueError(f"{label} path cannot be encoded") from exc
    if path_bytes > MAX_DIGEST_PATH_BYTES:
        raise ValueError(f"{label} path exceeds the digest limit")


def _regular_stat(path: Path, label: str) -> os.stat_result:
    _check_digest_path(path, label)
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise ValueError(f"{label} cannot be inspected") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} must be a regular non-symlink file")
    if metadata.st_size > MAX_DIGEST_FILE_BYTES:
        raise ValueError(f"{label} exceeds the per-file digest limit")
    return metadata


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _stream_regular_file(
    path: Path,
    *,
    aggregate: object | None = None,
    started: float | None = None,
    file_count: int = 1,
    total_before: int = 0,
) -> tuple[str, int]:
    """Stream one bounded regular file into local and optional aggregate hashes."""

    started = time.monotonic() if started is None else started
    before = _regular_stat(path, "digest input")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError("digest input cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _file_identity(opened) != _file_identity(before):
            raise ValueError("digest input changed before reading")
        hasher = hashlib.sha256()
        total = 0
        while True:
            _check_digest_budget(started, files=file_count, total_bytes=total_before + total)
            chunk = os.read(descriptor, MAX_DIGEST_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_DIGEST_FILE_BYTES or total_before + total > MAX_DIGEST_TOTAL_BYTES:
                raise ValueError("digest input exceeded its byte limit")
            hasher.update(chunk)
            if aggregate is not None:
                aggregate.update(chunk)  # type: ignore[attr-defined]
        after = os.fstat(descriptor)
        current = _regular_stat(path, "digest input")
        if (
            _file_identity(after) != _file_identity(before)
            or _file_identity(current) != _file_identity(before)
            or total != before.st_size
        ):
            raise ValueError("digest input changed while reading")
        return hasher.hexdigest(), total
    finally:
        os.close(descriptor)


def _digest_regular_file(path: Path) -> str:
    """Hash a bounded regular file without following replacement links."""

    return _stream_regular_file(path)[0]


def _read_bounded_regular_file(path: Path, limit: int, label: str) -> bytes:
    """Read a small regular file without following links or unbounded growth."""

    if type(limit) is not int or limit < 0:
        raise ValueError("bounded file limit must be non-negative")
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise ValueError(f"{label} cannot be inspected") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError(f"{label} must be a regular non-symlink file")
    if before.st_size > limit:
        raise ValueError(f"{label} exceeds the bounded input size")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{label} cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _file_identity(opened) != _file_identity(before):
            raise ValueError(f"{label} changed before reading")
        content = bytearray()
        while True:
            chunk = os.read(descriptor, min(MAX_DIGEST_CHUNK_BYTES, limit - len(content) + 1))
            if not chunk:
                break
            content.extend(chunk)
            if len(content) > limit:
                raise ValueError(f"{label} exceeds the bounded input size")
        after = os.fstat(descriptor)
        try:
            current = os.lstat(path)
        except OSError as exc:
            raise ValueError(f"{label} disappeared after reading") from exc
        if (
            _file_identity(after) != _file_identity(before)
            or _file_identity(current) != _file_identity(before)
            or len(content) != before.st_size
        ):
            raise ValueError(f"{label} changed while reading")
        return bytes(content)
    finally:
        os.close(descriptor)


def _digest_stdin(stream: object, *, limit: int = MAX_DIGEST_INPUT_BYTES) -> str:
    """Hash stdin incrementally and stop before retaining oversized input."""

    if type(limit) is not int or limit < 0:
        raise ValueError("stdin digest limit must be non-negative")
    effective_limit = min(limit, MAX_DIGEST_TOTAL_BYTES)
    hasher = hashlib.sha256()
    total = 0
    started = time.monotonic()
    while True:
        _check_digest_budget(started, files=1, total_bytes=total)
        remaining = effective_limit - total
        if remaining < 0:
            raise ValueError("stdin digest exceeded its byte limit")
        try:
            chunk = stream.read(min(MAX_DIGEST_CHUNK_BYTES, remaining + 1))  # type: ignore[attr-defined]
        except (AttributeError, TypeError) as exc:
            raise ValueError("stdin digest input is not readable") from exc
        if not isinstance(chunk, (bytes, bytearray)):
            raise ValueError("stdin digest input must provide bytes")
        if not chunk:
            break
        total += len(chunk)
        if total > effective_limit:
            raise ValueError("stdin digest exceeded its byte limit")
        hasher.update(chunk)
    return hasher.hexdigest()


def _open_directory(path: Path, expected: os.stat_result | None = None) -> tuple[int, os.stat_result]:
    _check_digest_path(path, "static digest directory")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError("static digest directory cannot be opened safely") from exc
    opened = os.fstat(descriptor)
    if not stat.S_ISDIR(opened.st_mode) or (expected is not None and _file_identity(opened) != _file_identity(expected)):
        os.close(descriptor)
        raise ValueError("static digest directory changed before reading")
    return descriptor, opened


def _collect_static_files(site_root: Path) -> list[tuple[Path, os.stat_result]]:
    started = time.monotonic()
    _check_digest_path(site_root, "site_root")
    try:
        root_metadata = os.lstat(site_root)
    except OSError as exc:
        raise ValueError("site_root cannot be inspected") from exc
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise ValueError("site_root must be a regular directory")
    collected: list[tuple[Path, os.stat_result]] = []
    stack: list[tuple[Path, int, os.stat_result]] = [(site_root, 0, root_metadata)]
    total_bytes = 0
    directory_count = 1
    entry_count = 0
    while stack:
        _check_digest_budget(started, files=len(collected), total_bytes=total_bytes)
        if len(stack) > MAX_DIGEST_PENDING_DIRECTORIES:
            raise ValueError("static digest exceeded its pending-directory budget")
        directory, depth, expected = stack.pop()
        if depth > MAX_DIGEST_DEPTH:
            raise ValueError("static digest exceeded its directory-depth budget")
        descriptor, opened = _open_directory(directory, expected)
        entries: list[tuple[str, os.stat_result]] = []
        try:
            try:
                with os.scandir(descriptor) as iterator:
                    for entry in iterator:
                        entry_count += 1
                        if entry_count > MAX_DIGEST_ENTRIES:
                            raise ValueError("static digest exceeded its directory-entry budget")
                        _check_digest_budget(started, files=len(collected), total_bytes=total_bytes)
                        try:
                            metadata = entry.stat(follow_symlinks=False)
                        except OSError as exc:
                            raise ValueError("static digest entry cannot be inspected") from exc
                        entries.append((entry.name, metadata))
            except ValueError:
                raise
            except OSError as exc:
                raise ValueError("site_root cannot be traversed safely") from exc
        finally:
            os.close(descriptor)
        try:
            after_directory = os.lstat(directory)
        except OSError as exc:
            raise ValueError("static digest directory disappeared") from exc
        if _file_identity(after_directory) != _file_identity(opened):
            raise ValueError("static digest directory changed while traversing")
        for name, metadata in sorted(entries, key=lambda item: item[0]):
            entry_path = directory / name
            _check_digest_path(
                entry_path,
                "static digest directory" if stat.S_ISDIR(metadata.st_mode) else "static digest entry",
            )
            relative = entry_path.relative_to(site_root).as_posix()
            if len(os.fsencode(relative)) > MAX_DIGEST_PATH_BYTES:
                raise ValueError("static digest entry path exceeds the digest limit")
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError("static digest rejects symlinks")
            if stat.S_ISDIR(metadata.st_mode):
                if directory_count >= MAX_DIGEST_DIRECTORIES:
                    raise ValueError("static digest exceeded its directory-count budget")
                if len(stack) >= MAX_DIGEST_PENDING_DIRECTORIES:
                    raise ValueError("static digest exceeded its pending-directory budget")
                if depth + 1 > MAX_DIGEST_DEPTH:
                    raise ValueError("static digest exceeded its directory-depth budget")
                directory_count += 1
                stack.append((entry_path, depth + 1, metadata))
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("static digest rejects special files")
            if metadata.st_size > MAX_DIGEST_FILE_BYTES:
                raise ValueError("static digest entry exceeds the per-file limit")
            if len(collected) >= MAX_DIGEST_FILES:
                raise ValueError("static digest exceeded its file-count budget")
            if total_bytes + metadata.st_size > MAX_DIGEST_TOTAL_BYTES:
                raise ValueError("static digest exceeded its byte budget")
            collected.append((entry_path, metadata))
            total_bytes += metadata.st_size
            _check_digest_budget(started, files=len(collected), total_bytes=total_bytes)
    try:
        final_root = os.lstat(site_root)
    except OSError as exc:
        raise ValueError("site_root disappeared after traversal") from exc
    if _file_identity(final_root) != _file_identity(root_metadata):
        raise ValueError("site_root changed while traversing")
    return sorted(collected, key=lambda item: item[0].relative_to(site_root).as_posix())


def _build_static_digest(site_root: Path) -> str:
    """Hash bounded static files incrementally and fail closed on races."""

    started = time.monotonic()
    files = _collect_static_files(site_root)
    hasher = hashlib.sha256()
    total_bytes = 0
    for index, (path, metadata) in enumerate(files, 1):
        relative = path.relative_to(site_root).as_posix().encode("utf-8")
        hasher.update(relative + b"\0" + str(metadata.st_size).encode("ascii") + b"\0")
        _, read_bytes = _stream_regular_file(
            path,
            aggregate=hasher,
            started=started,
            file_count=index,
            total_before=total_bytes,
        )
        total_bytes += read_bytes
        _check_digest_budget(started, files=index, total_bytes=total_bytes)
    return hasher.hexdigest()


def _header_items(headers: Mapping[str, str] | Sequence[tuple[str, str]] | None) -> list[tuple[str, str]]:
    """Copy only a bounded, validated header sequence."""

    if headers is None:
        return []
    try:
        declared_count = len(headers)
    except (TypeError, ValueError):
        declared_count = None
    if declared_count is not None and declared_count > MAX_FORWARD_HEADER_COUNT:
        raise ValueError("forwarded request has too many headers")
    try:
        iterator = iter(headers.items() if isinstance(headers, Mapping) else headers)
    except (AttributeError, TypeError) as exc:
        raise ValueError("forwarded request headers are not iterable") from exc
    total = 0
    normalized: list[tuple[str, str]] = []
    for index, item in enumerate(iterator):
        if index >= MAX_FORWARD_HEADER_COUNT:
            raise ValueError("forwarded request has too many headers")
        try:
            name, value = item
        except (TypeError, ValueError) as exc:
            raise ValueError("forwarded request contains malformed headers") from exc
        if type(name) is not str or type(value) is not str or not name or "\r" in name or "\n" in name:
            raise ValueError("forwarded request contains malformed headers")
        if "\r" in value or "\n" in value:
            raise ValueError("forwarded request contains malformed header values")
        total += len(name.encode("utf-8")) + len(value.encode("utf-8"))
        if total > MAX_FORWARD_HEADER_BYTES:
            raise ValueError("forwarded request headers exceed the size limit")
        normalized.append((name, value))
    return normalized


def _header_values(headers: Sequence[tuple[str, str]], name: str) -> list[str]:
    try:
        declared_count = len(headers)
    except (TypeError, ValueError):
        declared_count = None
    if declared_count is not None and declared_count > MAX_FORWARD_HEADER_COUNT:
        raise ValueError("forwarded request has too many headers")
    wanted = name.lower()
    values: list[str] = []
    for index, item in enumerate(headers):
        if index >= MAX_FORWARD_HEADER_COUNT:
            raise ValueError("forwarded request has too many headers")
        try:
            key, value = item
        except (TypeError, ValueError) as exc:
            raise ValueError("forwarded request contains malformed headers") from exc
        if type(key) is not str or type(value) is not str:
            raise ValueError("forwarded request contains malformed headers")
        if key.lower() == wanted:
            values.append(value)
    return values


def _single_header(headers: Sequence[tuple[str, str]], name: str, *, required: bool = False) -> str | None:
    values = _header_values(headers, name)
    if len(values) > 1 or (required and len(values) != 1):
        raise ValueError(f"forwarded request requires one {name} header")
    return values[0] if values else None


def _header_value(headers: Mapping[str, str] | Sequence[tuple[str, str]] | None, name: str) -> str:
    try:
        values = _header_values(_header_items(headers), name)
    except ValueError:
        return ""
    return values[0] if values else ""


def _query_matches(query: str, patterns: Iterable[str]) -> bool:
    return any(re.fullmatch(pattern, query) for pattern in patterns)


def map_public_path(path: str) -> dict[str, object] | None:
    """Return the one-prefix mapping used by the synthetic route proof.

    Traefik's ``stripPrefix`` middleware is configured separately from this
    model. Keeping the mapping executable here prevents a broad ``/hermes``
    rule from silently accepting a duplicated prefix or a near-prefix such as
    ``/hermesx``.
    """

    if type(path) is not str or not path.startswith("/") or _contains_request_controls(path):
        return None
    # Keep prefix mapping structural: encoded separators, dot segments, and
    # raw-target obfuscation must be denied before stripPrefix can run.
    if _unsafe_target(path, "", path):
        return None
    if path == "/hermes":
        return {"public_prefix": "/hermes", "upstream_path": "/", "stripped": True}
    if path.startswith("/hermes/"):
        upstream_path = path[len("/hermes") :]
        if upstream_path == "/hermes" or upstream_path.startswith("/hermes/"):
            return None
        return {"public_prefix": "/hermes", "upstream_path": upstream_path, "stripped": True}
    if path.startswith("/hermes"):
        return None
    return {"public_prefix": "", "upstream_path": path, "stripped": False}


def spa_fallback_path(path: str) -> str | None:
    """Return the reviewed shell path for one canonical client deep link."""

    if type(path) is not str or _contains_request_controls(path):
        return None
    return "/200.html" if re.fullmatch(CLIENT_ROUTE_PATTERN, path) else None


def secure_prefixed_cookie_observation(set_cookie: str) -> dict[str, object]:
    """Validate a redacted synthetic ``__Host-`` cookie canary.

    Traefik is not started by this lane, so this is deliberately a model
    observation rather than a real ``Set-Cookie`` proof. The value is accepted
    only long enough to validate the grammar and is never returned.
    """

    if type(set_cookie) is not str or not set_cookie or len(set_cookie.encode("utf-8")) > 4096:
        raise ValueError("synthetic Set-Cookie canary is malformed")
    if _contains_request_controls(set_cookie):
        raise ValueError("synthetic Set-Cookie canary contains controls")
    parts = [part.strip() for part in set_cookie.split(";")]
    if not parts or "=" not in parts[0]:
        raise ValueError("synthetic Set-Cookie canary is missing its name")
    name, value = parts[0].split("=", 1)
    if not name.startswith(SYNTHETIC_COOKIE_PREFIX) or not value:
        raise ValueError("synthetic cookie is outside the __Host- prefix contract")
    attributes: dict[str, str | None] = {}
    for part in parts[1:]:
        if not part:
            raise ValueError("synthetic cookie has an empty attribute")
        key, separator, raw_value = part.partition("=")
        key = key.strip().lower()
        if key in attributes or not key:
            raise ValueError("synthetic cookie has a duplicate or empty attribute")
        if key in {"secure", "httponly"}:
            if separator:
                raise ValueError("boolean cookie attributes must not have values")
            attributes[key] = None
        elif key in {"samesite", "path"}:
            if not separator or not raw_value:
                raise ValueError("cookie attribute value is missing")
            attributes[key] = raw_value.strip()
        elif key == "domain":
            raise ValueError("__Host- cookies must not declare Domain")
        else:
            raise ValueError("synthetic cookie attribute is outside the closed contract")
    if set(attributes) != {"secure", "httponly", "samesite", "path"}:
        raise ValueError("synthetic cookie security attributes are incomplete")
    if attributes["path"] != "/" or str(attributes["samesite"]).lower() != "lax":
        raise ValueError("synthetic cookie scope or SameSite policy is unsafe")
    return {
        "status": "synthetic_observed",
        "name_prefix": SYNTHETIC_COOKIE_PREFIX,
        "scope": SYNTHETIC_COOKIE_SCOPE,
        "attributes": list(SYNTHETIC_COOKIE_ATTRIBUTES),
        "value": "redacted",
    }


def redact_ticket_material(path: str, query: str) -> dict[str, str]:
    """Remove the full upgrade target and bounded ticket fragment from logs."""

    if type(path) is not str or type(query) is not str or not path.startswith("/"):
        raise ValueError("ticket request material is malformed")
    if _contains_request_controls(path) or _contains_request_controls(query):
        raise ValueError("ticket request material contains controls")
    if not any(part.partition("=")[0] == "ticket" for part in query.split("&")):
        raise ValueError("ticket request material does not contain a ticket")
    # Never return the input path or query. The caller can retain only these
    # fixed markers, which also covers Hermes' bounded first-eight fragment.
    return {
        "request_target": "redacted",
        "query": "redacted",
        "ticket": "redacted",
        "ticket_fragment": "redacted",
    }


class SyntheticTicketLedger:
    """Model the pinned single-use, short-lived ticket boundary in memory."""

    def __init__(self, ttl_seconds: int = TICKET_TTL_SECONDS) -> None:
        if type(ttl_seconds) is not int or ttl_seconds <= 0:
            raise ValueError("ticket TTL must be a positive integer")
        self.ttl_seconds = ttl_seconds
        self._issued: dict[str, float] = {}
        self._consumed: set[str] = set()

    def issue(self, token: str, *, now: float) -> None:
        if type(token) is not str or not re.fullmatch(CHAT_TICKET_VALUE_PATTERN, token):
            raise ValueError("ticket token is outside the bounded synthetic grammar")
        if type(now) not in {int, float} or isinstance(now, bool):
            raise ValueError("ticket timestamp is malformed")
        self._issued[token] = float(now)

    def consume(self, token: str, *, now: float) -> str:
        if type(token) is not str or not re.fullmatch(CHAT_TICKET_VALUE_PATTERN, token):
            return "invalid"
        if type(now) not in {int, float} or isinstance(now, bool):
            raise ValueError("ticket timestamp is malformed")
        issued_at = self._issued.get(token)
        if issued_at is None:
            return "invalid"
        if token in self._consumed:
            return "reused"
        self._consumed.add(token)
        if float(now) - issued_at >= self.ttl_seconds:
            return "expired"
        return "accepted"


def synthetic_ticket_lifecycle_observation() -> dict[str, object]:
    """Return labels for one synthetic ticket, without retaining its value."""

    ledger = SyntheticTicketLedger()
    ledger.issue("fixtureTicket", now=0)
    first_use = ledger.consume("fixtureTicket", now=1)
    reused = ledger.consume("fixtureTicket", now=2)
    ledger.issue("expiredTicket", now=0)
    expired = ledger.consume("expiredTicket", now=TICKET_TTL_SECONDS + 1)
    invalid = ledger.consume("unknownTicket", now=1)
    return {
        "status": "synthetic_observed",
        "ttl_seconds": TICKET_TTL_SECONDS,
        "first_use": first_use,
        "reused_use": reused,
        "expired_use": expired,
        "invalid_use": invalid,
        "retry": UPGRADE_RETRY_POLICY["chat"],
        "redaction": redact_ticket_material("/api/ws", "ticket=fixtureTicket"),
    }


def _validate_pty_timestamp(now: object) -> int | float:
    """Validate a finite, bounded timestamp without lossy integer coercion."""

    if type(now) is int:
        if 0 <= now <= MAX_PTY_TIMESTAMP_SECONDS:
            return now
    elif type(now) is float:
        if math.isfinite(now) and 0 <= now <= MAX_PTY_TIMESTAMP_SECONDS:
            return now
    raise ValueError(
        f"PTY timestamp must be a finite number in [0, {MAX_PTY_TIMESTAMP_SECONDS}]"
    )


class SyntheticPtyLifecycle:
    """Model monotonic detach plus eventual TTL cleanup without retaining PTY bytes."""

    def __init__(self, ttl_seconds: int = PTY_DETACHED_TTL_SECONDS) -> None:
        if type(ttl_seconds) is not int or ttl_seconds <= 0:
            raise ValueError("PTY TTL must be a positive integer")
        self.ttl_seconds = ttl_seconds
        self._states: dict[str, int | float | None] = {}
        self._last_event_at: dict[str, int | float] = {}

    def attach(self, attach_id: str, *, now: int | float) -> str:
        if type(attach_id) is not str or not re.fullmatch(PTY_ATTACH_VALUE_PATTERN, attach_id):
            raise ValueError("PTY attach identity is malformed")
        timestamp = _validate_pty_timestamp(now)
        previous = self._last_event_at.get(attach_id)
        if previous is not None and timestamp < previous:
            raise ValueError("PTY timestamp precedes stored lifecycle timestamp")
        self._states[attach_id] = None
        self._last_event_at[attach_id] = timestamp
        return "attached"

    def send_input(self, attach_id: str, payload: bytes) -> str:
        if attach_id not in self._states or self._states[attach_id] is not None:
            raise ValueError("PTY is not attached")
        if not isinstance(payload, bytes):
            raise ValueError("PTY input must be bytes")
        # The payload is intentionally not stored or logged.
        return "forwarded"

    def detach(self, attach_id: str, *, now: int | float) -> str:
        timestamp = _validate_pty_timestamp(now)
        if attach_id not in self._states or self._states[attach_id] is not None:
            raise ValueError("PTY is not attached")
        attached_at = self._last_event_at[attach_id]
        if timestamp < attached_at:
            raise ValueError("PTY timestamp precedes stored lifecycle timestamp")
        self._states[attach_id] = timestamp
        self._last_event_at[attach_id] = timestamp
        return "detached"

    def reattach(self, attach_id: str, *, now: int | float) -> str:
        """Reattach only at a monotonic time within the strict TTL boundary."""

        timestamp = _validate_pty_timestamp(now)
        if type(attach_id) is not str or not re.fullmatch(PTY_ATTACH_VALUE_PATTERN, attach_id):
            raise ValueError("PTY attach identity is malformed")
        if attach_id not in self._states:
            raise ValueError("PTY attachment has been reaped")
        detached_at = self._states[attach_id]
        if detached_at is None:
            if timestamp < self._last_event_at[attach_id]:
                raise ValueError("PTY timestamp precedes stored lifecycle timestamp")
            return "already_attached"
        # Reattach eligibility is checked independently of periodic cleanup so a
        # stale handle cannot be reused while its detached resource still exists.
        if timestamp < detached_at:
            raise ValueError("PTY timestamp precedes stored lifecycle timestamp")
        if timestamp - detached_at > self.ttl_seconds:
            raise ValueError("PTY attachment has exceeded retention TTL")
        self._states[attach_id] = None
        self._last_event_at[attach_id] = timestamp
        return "reattached"

    def reap(self, *, now: int | float) -> int:
        timestamp = _validate_pty_timestamp(now)
        for detached_at in self._states.values():
            if detached_at is not None and timestamp < detached_at:
                raise ValueError("PTY timestamp precedes stored lifecycle timestamp")
        expired = [
            attach_id
            for attach_id, detached_at in self._states.items()
            # Keep the handle reattachable at exactly the retention boundary;
            # reattach() enforces the same strict eligibility check immediately,
            # while this periodic pass deletes only already-ineligible handles.
            if detached_at is not None and timestamp - detached_at > self.ttl_seconds
        ]
        for attach_id in expired:
            del self._states[attach_id]
            del self._last_event_at[attach_id]
        return len(expired)


def synthetic_pty_lifecycle_observation() -> dict[str, object]:
    """Return detach and eventual-reap labels with all PTY material redacted."""

    lifecycle = SyntheticPtyLifecycle()
    attached = lifecycle.attach("fixtureAttach", now=0)
    forwarded = lifecycle.send_input("fixtureAttach", b"synthetic-input")
    detached = lifecycle.detach("fixtureAttach", now=0)
    # Probe the exact boundary rather than an offset timestamp: the handle
    # remains present and can reconnect at 1800 seconds, then a separate
    # detached handle proves cleanup at 1801 seconds.
    boundary_reap = lifecycle.reap(now=PTY_DETACHED_TTL_SECONDS)
    boundary_reattach = lifecycle.reattach("fixtureAttach", now=PTY_DETACHED_TTL_SECONDS)
    expired = SyntheticPtyLifecycle()
    expired.attach("fixtureExpired", now=0)
    expired.detach("fixtureExpired", now=0)
    try:
        expired.reattach("fixtureExpired", now=PTY_DETACHED_TTL_SECONDS + 1)
    except ValueError:
        expired_reattach_before_reap = "rejected"
    else:
        expired_reattach_before_reap = "accepted"
    after_ttl = expired.reap(now=PTY_DETACHED_TTL_SECONDS + 1)
    return {
        "status": "synthetic_observed",
        "host_requirement": "posix_or_wsl",
        "attach": attached,
        "input": forwarded,
        "detach": detached,
        "boundary_elapsed_seconds": PTY_DETACHED_TTL_SECONDS,
        "boundary_reap": boundary_reap,
        "boundary_reattach": boundary_reattach,
        "expired_elapsed_seconds": PTY_DETACHED_TTL_SECONDS + 1,
        "expired_reattach_before_reap": expired_reattach_before_reap,
        "before_ttl_reap": boundary_reap,
        "ttl_reap": after_ttl,
        "retry": UPGRADE_RETRY_POLICY["pty"],
        "kill": "not_claimed",
        "replay_before_live": "not_claimed",
        "retained_material": "redacted",
    }


def private_hermes_boundary_observation(source_identity: str = "untrusted") -> dict[str, object]:
    """Describe the fixed private :9119 boundary without opening a socket."""

    if source_identity not in {"proxy_identity", "untrusted"}:
        raise ValueError("source identity is outside the synthetic firewall vocabulary")
    return {
        "status": "synthetic_observed",
        "port": REQUIRED_HERMES_PORT,
        "bind_class": REQUIRED_HERMES_BIND_CLASS,
        "public_exposure": PUBLIC_HERMES_EXPOSURE,
        "source_identity": source_identity,
        "direct_result": "connection_denied" if source_identity == "untrusted" else "proxy_only",
    }


def upgrade_retry_policy() -> dict[str, str]:
    """Return the fixed no-retry contract for both WebSocket routes."""

    return dict(UPGRADE_RETRY_POLICY)


def edge_no_upstream_observation(
    cases: Iterable[Mapping[str, object]] | None = None,
) -> dict[str, object]:
    """Summarize blocked vectors that must stop before any upstream request.

    The case identities and booleans are safe fixture metadata. No request
    target, query, credential, or upstream payload is retained. Network-layer
    direct-port denial is included because it is also a pre-upstream block.
    """

    selected = NEGATIVE_CASES if cases is None else cases
    blocked_ids: list[str] = []
    layers: set[str] = set()
    for case in selected:
        if not isinstance(case, Mapping):
            raise ValueError("edge no-upstream cases must be mappings")
        case_id = case.get("id")
        layer = case.get("layer")
        if type(case_id) is not str or not case_id:
            raise ValueError("edge no-upstream case identity is malformed")
        if case.get("upstream_request") is not False:
            continue
        if layer not in {"edge", "network"}:
            raise ValueError("edge no-upstream case layer is outside the closed vocabulary")
        blocked_ids.append(case_id)
        layers.add(str(layer))
    if not blocked_ids:
        raise ValueError("edge no-upstream evidence requires at least one blocked case")
    return {
        "status": "synthetic_observed",
        "scope": "annotated policy and network-boundary model",
        "blocked_case_count": len(blocked_ids),
        "blocked_case_ids": blocked_ids,
        "blocked_layers": sorted(layers),
        "all_blocked_cases_have_no_upstream_request": True,
        "upstream_request": False,
        "retained_request_material": "redacted",
    }


def _contains_request_controls(value: str) -> bool:
    """Reject C0, DEL, and C1 code points before URI policy can allow them."""

    return any(
        ord(character) <= 0x1F
        or ord(character) == 0x7F
        or 0x80 <= ord(character) <= 0x9F
        for character in value
    )


def _bounded_request_uri(path: str, query: str) -> str:
    """Compose a request URI only after checking direct caller sizes."""

    if type(path) is not str or type(query) is not str:
        raise ValueError("request path and query must be strings")
    if _contains_request_controls(path) or _contains_request_controls(query):
        raise ValueError("request path or query contains control characters")
    if len(path) > MAX_REQUEST_TARGET_BYTES or len(query) > MAX_REQUEST_TARGET_BYTES:
        raise ValueError("request path or query is oversized")
    if not path.startswith("/"):
        raise ValueError("request path must be origin-form")
    path_bytes = len(path.encode("utf-8"))
    query_bytes = len(query.encode("utf-8"))
    total = path_bytes + (1 + query_bytes if query else 0)
    if total > MAX_REQUEST_TARGET_BYTES:
        raise ValueError("request target is oversized")
    return path + ("?" + query if query else "")


def _unsafe_target(path: str, query: str, raw_target: str) -> bool:
    if type(path) is not str or type(query) is not str or type(raw_target) is not str:
        return True
    if len(raw_target) > MAX_REQUEST_TARGET_BYTES:
        return True
    try:
        expected = _bounded_request_uri(path, query)
        if len(raw_target.encode("utf-8")) > MAX_REQUEST_TARGET_BYTES:
            return True
    except (UnicodeError, ValueError):
        return True
    if (
        not raw_target
        or not path.startswith("/")
        or raw_target.endswith("?")
        or "#" in raw_target
        or _contains_request_controls(raw_target)
    ):
        return True
    try:
        parsed = urlsplit(raw_target)
    except ValueError:
        return True
    if parsed.scheme or parsed.netloc or parsed.fragment:
        return True
    if parsed.path != path or parsed.query != query or raw_target != expected:
        return True
    return bool(RAW_UNSAFE_RE.search(raw_target) or DOT_SEGMENT_RE.search(raw_target))


def _parse_forwarded_uri(uri: str) -> tuple[str, str]:
    """Parse only Traefik's standard X-Forwarded-Uri field.

    This is a URI policy check, not a raw-target proof. ForwardAuth does not
    provide separate path, query, or raw-target fields, so callers must not
    label this parsed value as raw request-target evidence.
    """

    if type(uri) is not str or not uri or len(uri) > MAX_REQUEST_TARGET_BYTES:
        raise ValueError("ForwardAuth URI is missing or oversized")
    if len(uri.encode("utf-8")) > MAX_REQUEST_TARGET_BYTES:
        raise ValueError("ForwardAuth URI is missing or oversized")
    if "#" in uri:
        raise ValueError("ForwardAuth URI contains a fragment")
    try:
        parsed = urlsplit(uri)
    except ValueError as exc:
        raise ValueError("ForwardAuth URI is malformed") from exc
    if parsed.scheme or parsed.netloc or parsed.fragment or not parsed.path.startswith("/"):
        raise ValueError("ForwardAuth URI must be an origin-form path")
    path = parsed.path
    query = parsed.query
    if _unsafe_target(path, query, uri):
        raise ValueError("ForwardAuth URI is outside the reviewed path grammar")
    return path, query


def _session_route(method: str, path: str) -> bool:
    for route_method, template in SESSION_ROUTES:
        if route_method != method:
            continue
        suffix = template.split("{session_id}", 1)[1]
        pattern = rf"^/api/sessions/{SESSION_ID_PATTERN}{re.escape(suffix)}$"
        if re.fullmatch(pattern, path):
            return True
    return False


def _canonical_upgrade_headers(headers: Sequence[tuple[str, str]]) -> tuple[str, str]:
    upgrade = (_single_header(headers, "Upgrade") or "").strip().lower()
    connection = (_single_header(headers, "Connection") or "").strip().lower()
    if upgrade not in {"", "websocket"} or connection not in {"", "upgrade"}:
        raise ValueError("upgrade headers are outside the fixed contract")
    if bool(upgrade) != bool(connection):
        raise ValueError("upgrade and connection must be supplied together")
    return ("websocket", "Upgrade") if upgrade else ("", "")


def _validate_forward_auth_header_names(headers: Sequence[tuple[str, str]]) -> None:
    """Enforce the closed adapter contract before any policy decision."""

    try:
        declared_count = len(headers)
    except (TypeError, ValueError):
        declared_count = None
    if declared_count is not None and declared_count > MAX_FORWARD_HEADER_COUNT:
        raise ValueError("forwarded request has too many headers")
    allowed = {
        name.lower() for name in (*TRAEFIK_FORWARDAUTH_HEADERS, *FORWARD_AUTH_TRANSPORT_HEADERS)
    }
    for index, item in enumerate(headers):
        if index >= MAX_FORWARD_HEADER_COUNT:
            raise ValueError("forwarded request has too many headers")
        try:
            name, _value = item
        except (TypeError, ValueError) as exc:
            raise ValueError("forwarded request contains malformed headers") from exc
        if type(name) is not str:
            raise ValueError("forwarded request contains malformed headers")
        if name.lower() not in allowed:
            raise ValueError("header is outside the closed ForwardAuth contract")


def _validate_forward_auth_transport_headers(headers: Sequence[tuple[str, str]]) -> None:
    """Validate transport-only headers without treating them as policy input."""

    host = _single_header(headers, "Host")
    if host is not None and (not host or _contains_request_controls(host)):
        raise ValueError("ForwardAuth transport Host is malformed")
    content_length = _single_header(headers, "Content-Length")
    if content_length is not None and not content_length.isdigit():
        raise ValueError("ForwardAuth Content-Length is malformed")
    for name in ("User-Agent", "Accept-Encoding"):
        value = _single_header(headers, name)
        if value is not None and _contains_request_controls(value):
            raise ValueError(f"ForwardAuth transport {name} is malformed")
    connection = _single_header(headers, "Connection")
    if connection is not None and connection.strip().lower() not in {"", "close"}:
        raise ValueError("ForwardAuth transport Connection must be close")


def policy_decision(
    *,
    runtime_inputs: Mapping[str, object],
    method: str,
    path: str,
    query: str = "",
    headers: Mapping[str, str] | Sequence[tuple[str, str]] | None = None,
    raw_target: str | None = None,
    require_websocket_headers: bool = True,
) -> dict[str, object]:
    """Model the local policy without retaining request material.

    ``raw_target`` is an optional model-only input. The executable ForwardAuth
    adapter does not receive it; it consumes only Traefik's X-Forwarded-Uri.
    Likewise, WebSocket handshake headers are required only by the model when
    supplied directly. The generated Traefik router enforces them before the
    adapter because ForwardAuth does not guarantee Upgrade or Connection.
    """

    inputs = _validate_runtime_inputs(runtime_inputs)
    authority = _authority(inputs)
    expected_origin = f"https://{authority}"
    if type(method) is not str or not method or len(method) > MAX_REQUEST_TARGET_BYTES:
        return {"status": 404, "layer": "edge", "upstream_request": False}
    try:
        _bounded_request_uri(path, query)
    except (UnicodeError, ValueError):
        return {"status": 404, "layer": "edge", "upstream_request": False}
    try:
        header_items = _header_items(headers)
        host_values = _header_values(header_items, "Host")
        forwarded_host_values = _header_values(header_items, "X-Forwarded-Host")
        forwarded_port_values = _header_values(header_items, "X-Forwarded-Port")
        forwarded_proto_values = _header_values(header_items, "X-Forwarded-Proto")
        expected_port = str(inputs["https_port"])
        if host_values and (len(host_values) != 1 or host_values[0] != authority):
            return {"status": 421, "layer": "edge", "upstream_request": False}
        if len(forwarded_host_values) != 1 or forwarded_host_values[0] != authority:
            return {"status": 421, "layer": "edge", "upstream_request": False}
        if len(forwarded_port_values) != 1 or forwarded_port_values[0] != expected_port:
            return {"status": 421, "layer": "edge", "upstream_request": False}
        if len(forwarded_proto_values) != 1 or forwarded_proto_values[0] != "https":
            return {"status": 421, "layer": "edge", "upstream_request": False}
        origin = _single_header(header_items, "Origin")
    except ValueError:
        return {"status": 421, "layer": "edge", "upstream_request": False}
    try:
        upgrade, connection = _canonical_upgrade_headers(header_items)
    except ValueError:
        return {"status": 404, "layer": "edge", "upstream_request": False}
    if raw_target is not None and _unsafe_target(path, query, raw_target):
        return {"status": 404, "layer": "edge", "upstream_request": False}

    dashboard = path.startswith("/hermes")
    upstream_path = path[len("/hermes") :] if dashboard else path
    if dashboard and not upstream_path:
        upstream_path = "/"
    if dashboard and upstream_path.startswith("/hermes"):
        return {"status": 404, "layer": "edge", "upstream_request": False}

    if upstream_path in WEBSOCKET_ROUTES:
        if method != "GET":
            return {"status": 404, "layer": "edge", "upstream_request": False}
        if require_websocket_headers and (upgrade != "websocket" or connection != "Upgrade"):
            return {"status": 404, "layer": "edge", "upstream_request": False}
        if origin != expected_origin:
            return {"status": 403, "layer": "edge", "upstream_request": False}
        if upstream_path == "/api/ws":
            accepted = bool(re.fullmatch(CHAT_TICKET_QUERY_PATTERN, query))
        else:
            accepted = _query_matches(query, PTY_QUERY_PATTERNS)
        if not accepted:
            return {"status": 404, "layer": "edge", "upstream_request": False}
        return {
            "status": 101 if require_websocket_headers else 200,
            "layer": "hermes",
            "upstream_request": True,
            "websocket_headers": "verified" if require_websocket_headers else "not_observed",
        }

    if any(route_method == method and route_path == upstream_path for route_method, route_path in EXACT_REST_ROUTES):
        accepted_query = (
            _query_matches(query, AUTH_CALLBACK_QUERY_PATTERNS)
            if upstream_path == "/auth/callback"
            else query == ""
        )
        if accepted_query:
            return {"status": 200, "layer": "hermes", "upstream_request": True}
        return {"status": 404, "layer": "edge", "upstream_request": False}
    if upgrade or connection:
        return {"status": 404, "layer": "edge", "upstream_request": False}

    if _session_route(method, upstream_path) and query == "":
        return {"status": 200, "layer": "hermes", "upstream_request": True}

    if not dashboard and method in {"GET", "HEAD"}:
        if upstream_path == "/" and query in {"", "scenario=success", "scenario=empty", "scenario=failure"}:
            return {"status": 200, "layer": "static", "upstream_request": True}
        if any(_static_path_matches(upstream_path, pattern) for pattern in STATIC_PATHS[1:]) and query == "":
            return {"status": 200, "layer": "static", "upstream_request": True}
        if re.fullmatch(CLIENT_ROUTE_PATTERN, upstream_path) and query == "":
            return {"status": 200, "layer": "static", "upstream_request": True}

    return {"status": 404, "layer": "edge", "upstream_request": False}


def build_traefik_forward_auth_headers(
    runtime_inputs: Mapping[str, object],
    *,
    method: str,
    path: str,
    query: str,
    headers: Mapping[str, str] | Sequence[tuple[str, str]] | None = None,
) -> list[tuple[str, str]]:
    """Build only the metadata standard Traefik ForwardAuth supplies."""

    inputs = _validate_runtime_inputs(runtime_inputs)
    authority = _authority(inputs)
    original = _header_items(headers)
    host_values = _header_values(original, "Host")
    if len(host_values) != 1 or host_values[0] != authority:
        raise ValueError("original request requires one exact Host authority")
    for name, _value in original:
        lowered = name.lower()
        if lowered == "forwarded" or lowered.startswith("x-forwarded-") or lowered == "x-real-ip":
            raise ValueError("inbound forwarding metadata is not trusted")
    origin = _single_header(original, "Origin")
    uri = _bounded_request_uri(path, query)
    _parse_forwarded_uri(uri)
    if type(method) is not str or not method or len(method) > MAX_REQUEST_TARGET_BYTES or "\r" in method or "\n" in method:
        raise ValueError("original request method is not canonical")
    result = [
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Forwarded-Host", authority),
        ("X-Forwarded-Method", method),
        ("X-Forwarded-Port", str(inputs["https_port"])),
        ("X-Forwarded-Proto", "https"),
        ("X-Forwarded-Uri", uri),
    ]
    if origin is not None:
        result.append(("Origin", origin))
    return result


def _forward_auth_policy_input(
    runtime_inputs: Mapping[str, object],
    headers: Sequence[tuple[str, str]],
) -> tuple[str, str, str, list[tuple[str, str]]]:
    inputs = _validate_runtime_inputs(runtime_inputs)
    authority = _authority(inputs)
    _validate_forward_auth_header_names(headers)
    _validate_forward_auth_transport_headers(headers)
    required = {
        name: _single_header(headers, name, required=True)
        for name in TRAEFIK_FORWARDAUTH_GENERATED_HEADERS
    }
    if (
        required["X-Forwarded-Host"] != authority
        or required["X-Forwarded-Port"] != str(inputs["https_port"])
        or required["X-Forwarded-Proto"] != "https"
    ):
        raise ValueError("ForwardAuth authority, port, or scheme is not canonical")
    if not required["X-Forwarded-For"]:
        raise ValueError("ForwardAuth client address is missing")
    method = str(required["X-Forwarded-Method"])
    path, query = _parse_forwarded_uri(str(required["X-Forwarded-Uri"]))
    origin = _single_header(headers, "Origin") or ""
    policy_headers = [
        ("X-Forwarded-Host", authority),
        ("X-Forwarded-Port", str(inputs["https_port"])),
        ("X-Forwarded-Proto", "https"),
        ("Origin", origin),
    ]
    return method, path, query, policy_headers


class _HeaderLimitExceeded(ValueError):
    pass


class _BoundedHeaderReader:
    """Limit header bytes while delegating body reads to the real socket."""

    def __init__(self, raw: object, limit: int) -> None:
        self.raw = raw
        self.limit = limit
        self.total = 0

    def readline(self, size: int = -1) -> bytes:
        remaining = self.limit - self.total
        if remaining <= 0:
            raise _HeaderLimitExceeded("request headers exceed the byte limit")
        requested = remaining + 1 if size < 0 else min(size, remaining + 1)
        line = self.raw.readline(requested)  # type: ignore[attr-defined]
        self.total += len(line)
        if self.total > self.limit:
            raise _HeaderLimitExceeded("request headers exceed the byte limit")
        return line


class _ForwardAuthHandler(http.server.BaseHTTPRequestHandler):
    runtime_inputs: Mapping[str, object] = DEFAULT_RUNTIME_INPUTS
    protocol_version = "HTTP/1.0"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(1.0)

    def handle_one_request(self) -> None:
        self.close_connection = True
        try:
            self.raw_requestline = self.rfile.readline(MAX_REQUEST_TARGET_BYTES + 1)
            if len(self.raw_requestline) > MAX_REQUEST_TARGET_BYTES:
                self.requestline = ""
                self.request_version = "HTTP/1.0"
                self.command = None
                self._respond(414, "deny")
                return
            if not self.raw_requestline:
                return
            if not self.parse_request():
                return
            method_name = "do_" + str(self.command)
            if not hasattr(self, method_name):
                self._respond(405, "deny")
                return
            getattr(self, method_name)()
            self.wfile.flush()
        except (TimeoutError, OSError):
            self.close_connection = True

    def parse_request(self) -> bool:
        raw = self.rfile
        bounded = _BoundedHeaderReader(raw, MAX_FORWARD_HEADER_BYTES)
        self.rfile = bounded  # type: ignore[assignment]
        try:
            return super().parse_request()
        except _HeaderLimitExceeded:
            self._respond(431, "deny")
            self.close_connection = True
            return False
        finally:
            self.rfile = raw

    def _respond(self, status: int, decision: str) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("X-Hermternal-Policy", decision)
        self.end_headers()

    def _handle_policy(self) -> None:
        if self.path != "/check":
            self._respond(404, "deny")
            return
        try:
            headers = _header_items(list(self.headers.raw_items()))
            content_length = _single_header(headers, "Content-Length")
            if content_length is not None:
                if not content_length.isdigit() or int(content_length) > MAX_POLICY_BODY_BYTES:
                    self._respond(413, "deny")
                    return
                body_length = int(content_length)
                if body_length and len(self.rfile.read(body_length)) != body_length:
                    self._respond(400, "deny")
                    return
            method, path, query, policy_headers = _forward_auth_policy_input(
                self.runtime_inputs, headers
            )
            result = policy_decision(
                runtime_inputs=self.runtime_inputs,
                method=method,
                path=path,
                query=query,
                headers=policy_headers,
                require_websocket_headers=False,
            )
        except (ValueError, UnicodeError):
            self._respond(400, "deny")
            return
        allowed = bool(result["upstream_request"])
        status = 200 if allowed else int(result["status"]) if isinstance(result["status"], int) else 404
        self._respond(status, "allow" if allowed else "deny")

    do_GET = _handle_policy
    do_HEAD = _handle_policy
    do_POST = _handle_policy
    do_PATCH = _handle_policy

    def log_message(self, _format: str, *_args: object) -> None:
        return


def make_forward_auth_server(runtime_inputs: Mapping[str, object]) -> http.server.ThreadingHTTPServer:
    """Create a loopback-only bounded adapter for offline black-box tests."""

    inputs = _validate_runtime_inputs(runtime_inputs)
    handler = type("BoundForwardAuthHandler", (_ForwardAuthHandler,), {"runtime_inputs": inputs})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    server.timeout = 0.25
    return server


def _static_path_matches(path: str, pattern: str) -> bool:
    if pattern.endswith("/*"):
        return path.startswith(pattern[:-1])
    return path == pattern


POSITIVE_CASES = [
    {"id": "root_static", "status": 200, "layer": "static", "upstream_request": True},
    {"id": "root_scenario_static", "status": 200, "layer": "static", "upstream_request": True, "query_policy": "reviewed scenario selector only"},
    {"id": "deep_link_session", "status": 200, "layer": "static", "upstream_request": True, "fallback": "/200.html"},
    {"id": "deep_link_message", "status": 200, "layer": "static", "upstream_request": True, "fallback": "/200.html"},
    {"id": "dashboard_provider_discovery", "status": 200, "layer": "hermes", "upstream_request": True},
    {"id": "password_login", "status": 200, "layer": "hermes", "upstream_request": True},
    {"id": "oauth_callback", "status": 200, "layer": "hermes", "upstream_request": True, "query_policy": "reviewed code/state or provider-error forms; order-independent"},
    {"id": "ws_ticket", "status": 200, "layer": "hermes", "upstream_request": True},
    {"id": "ws_upgrade", "status": 101, "layer": "hermes", "upstream_request": True, "query_policy": "chat ticket-only"},
    {"id": "pty_upgrade", "status": 101, "layer": "hermes", "upstream_request": True, "query_policy": "ticket plus resume with optional attach; order-independent"},
    {"id": "mock_upstream_header_rebuild", "status": 200, "layer": "hermes", "upstream_request": True, "forwarding_policy": "forward-auth gate plus trusted header middleware", "prefix_policy": "single /hermes prefix"},
]

NEGATIVE_CASES = [
    {"id": "wrong_host", "status": 421, "layer": "edge", "upstream_request": False},
    {"id": "wrong_websocket_origin", "status": 403, "layer": "edge", "upstream_request": False},
    {"id": "unknown_route", "status": 404, "layer": "edge", "upstream_request": False},
    {"id": "unknown_method", "status": 404, "layer": "edge", "upstream_request": False},
    {"id": "duplicate_prefix", "status": 404, "layer": "edge", "upstream_request": False},
    {"id": "traversal", "status": 404, "layer": "edge", "upstream_request": False},
    {"id": "encoded_separator", "status": 404, "layer": "edge", "upstream_request": False},
    {"id": "encoded_dot", "status": 404, "layer": "edge", "upstream_request": False},
    {"id": "malformed_upgrade", "status": 404, "layer": "edge", "upstream_request": False},
    {"id": "missing_ticket", "status": 404, "layer": "edge", "upstream_request": False},
    {"id": "root_query_mutation", "status": 404, "layer": "edge", "upstream_request": False},
    {"id": "static_asset_query_mutation", "status": 404, "layer": "edge", "upstream_request": False},
    {"id": "client_route_query_mutation", "status": 404, "layer": "edge", "upstream_request": False},
    {"id": "rest_query_mutation", "status": 404, "layer": "edge", "upstream_request": False},
    {"id": "pty_missing_resume", "status": 404, "layer": "edge", "upstream_request": False},
    {"id": "pty_extra_parameter", "status": 404, "layer": "edge", "upstream_request": False},
    {"id": "pty_duplicate_parameter", "status": 404, "layer": "edge", "upstream_request": False},
    {"id": "pty_empty_value", "status": 404, "layer": "edge", "upstream_request": False},
    {"id": "pty_fresh_parameter", "status": 404, "layer": "edge", "upstream_request": False},
    {"id": "invalid_ticket", "status": 400, "layer": "hermes", "upstream_request": True},
    {"id": "ticket_expired", "status": 403, "layer": "hermes", "upstream_request": True},
    {"id": "ticket_reuse", "status": 403, "layer": "hermes", "upstream_request": True},
    {"id": "direct_private_port", "status": "connection_denied", "layer": "network", "upstream_request": False},
]


def render_to_directory(output_dir: Path) -> tuple[dict[str, object], dict[str, object]]:
    """Emit a self-contained local bundle whose provider path matches its files."""

    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    inputs = reconstruction_inputs()
    inputs.update(
        {
            "site_root": str(output_dir / "site"),
            "cert_path": str(output_dir / "tls.crt"),
            "key_path": str(output_dir / "tls.key"),
            "storage_root": str(output_dir),
            "dynamic_filename": str(output_dir / "traefik-dynamic.json"),
        }
    )
    bundle = render_bundle(inputs)
    (output_dir / "traefik-static.json").write_text(
        json.dumps(bundle["static"], sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    (output_dir / "traefik-dynamic.json").write_text(
        json.dumps(bundle["dynamic"], sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return inputs, bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    render = subparsers.add_parser("render")
    render.add_argument("--output-dir", type=Path)
    digest = subparsers.add_parser("digest")
    digest.add_argument("--input", type=Path)
    build = subparsers.add_parser("build-digest")
    build.add_argument("site_root", type=Path)
    evidence = subparsers.add_parser("evidence")
    evidence.add_argument("--build-sha", required=True)
    evidence.add_argument("--build-digest", required=True)
    evidence.add_argument("--traefik-config-digest", required=True)
    evidence.add_argument("--browser-evidence", type=Path, required=True)
    evidence.add_argument("--browser-journey")
    args = parser.parse_args(argv)

    if args.command == "render":
        if args.output_dir is None:
            print(json.dumps(render_bundle(), sort_keys=True, separators=(",", ":")))
        else:
            render_to_directory(args.output_dir)
        return 0
    if args.command == "digest":
        if args.input is not None:
            print(_digest_regular_file(args.input))
        else:
            print(_digest_stdin(sys.stdin.buffer))
        return 0
    if args.command == "build-digest":
        print(_build_static_digest(args.site_root))
        return 0
    if args.command == "evidence":
        evidence_bytes = _read_bounded_regular_file(
            args.browser_evidence,
            BROWSER_EVIDENCE_MAX_BYTES,
            "browser evidence",
        )
        try:
            browser_evidence = json.loads(evidence_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("browser evidence is not valid JSON") from exc
        print(
            json.dumps(
                render_manifest(
                    build_sha=args.build_sha,
                    build_digest=args.build_digest,
                    traefik_config_digest=args.traefik_config_digest,
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
