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
import json
import re
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from urllib.parse import urlsplit


SCHEMA = "hermternal.traefik-proof.v1"
RUNTIME_INPUT_SCHEMA = "hermternal.traefik-proof.runtime-inputs.v1"
BROWSER_EVIDENCE_SCHEMA = "hermternal.traefik-proof.browser-evidence.v1"
DEFAULT_HOST = "traefik-92.test"
DEFAULT_HTTPS_PORT = 19444
DEFAULT_HERMES_PORT = 19257
DEFAULT_STATIC_PORT = 19258
DEFAULT_POLICY_PORT = 19259

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
    "traefik_config_digest",
    "runtime_inputs_sha256",
)
BROWSER_BLOCKED_JOURNEYS = {"blocked_provider", "blocked_empty_session"}
BROWSER_JOURNEYS = {"passed", *BROWSER_BLOCKED_JOURNEYS, "failed"}
BROWSER_BLOCKER_CODES = {
    "blocked_provider": "provider_unavailable",
    "blocked_empty_session": "empty_session",
}
BROWSER_FAILURE_CODE = "browser_assertion_failed"

# These are deterministic proof paths, not operator or user home paths.  The
# dynamic file is derived from storage_root and is never taken from input.
DEFAULT_RUNTIME_INPUTS: dict[str, object] = {
    "host": DEFAULT_HOST,
    "https_port": DEFAULT_HTTPS_PORT,
    "hermes_port": DEFAULT_HERMES_PORT,
    "static_port": DEFAULT_STATIC_PORT,
    "policy_port": DEFAULT_POLICY_PORT,
    "site_root": "/opt/hermternal/traefik-proof/site",
    "cert_path": "/opt/hermternal/traefik-proof/tls.crt",
    "key_path": "/opt/hermternal/traefik-proof/tls.key",
    "storage_root": "/opt/hermternal/traefik-proof",
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

    if type(value) is not str or not value or not Path(value).is_absolute():
        raise ValueError(f"{name} must be an absolute path")
    if any(character in value for character in ('"', "'", "\\")):
        raise ValueError(f"{name} must not contain quotes or backslashes")
    if any(ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F for character in value):
        raise ValueError(f"{name} must not contain control characters")
    return value


def _validate_runtime_inputs(value: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != set(DEFAULT_RUNTIME_INPUTS):
        raise ValueError("runtime_inputs must contain the exact renderer input keys")
    return {
        "host": _validate_host(value["host"]),
        "https_port": _validate_port(value["https_port"], "https_port"),
        "hermes_port": _validate_port(value["hermes_port"], "hermes_port"),
        "static_port": _validate_port(value["static_port"], "static_port"),
        "policy_port": _validate_port(value["policy_port"], "policy_port"),
        "site_root": _validate_path(value["site_root"], "site_root"),
        "cert_path": _validate_path(value["cert_path"], "cert_path"),
        "key_path": _validate_path(value["key_path"], "key_path"),
        "storage_root": _validate_path(value["storage_root"], "storage_root"),
    }


def reconstruction_inputs() -> dict[str, object]:
    """Return safe inputs used to reconstruct retained evidence."""

    return dict(DEFAULT_RUNTIME_INPUTS)


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
    """Bind Traefik vectors to the same source-owned Caddy parity inputs."""

    project_root = Path(__file__).resolve().parents[1]
    return {
        name: {"path": relative_path, "sha256": digest_bytes((project_root / relative_path).read_bytes())}
        for name, relative_path in PARITY_FIXTURE_PATHS.items()
    }


def _host_rule(host: str) -> str:
    return f"Host(`{host}`)"


def _path_rule(paths: Iterable[str]) -> str:
    return " || ".join(f"Path(`{path}`)" for path in paths)


def _method_path_rule(host: str, method: str, paths: Iterable[str]) -> str:
    return f"{_host_rule(host)} && Method(`{method}`) && ({_path_rule(paths)})"


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
    }


def render_static_config(value: Mapping[str, object]) -> dict[str, object]:
    """Render the Traefik static config, including the loopback boundary."""

    inputs = _validate_runtime_inputs(value)
    storage_root = str(inputs["storage_root"])
    return {
        "entryPoints": {
            "websecure": {
                "address": f"127.0.0.1:{inputs['https_port']}",
                "forwardedHeaders": {"insecure": False},
            }
        },
        "providers": {
            "file": {
                "filename": f"{storage_root}/dynamic.json",
                "watch": False,
            }
        },
        "log": {"level": "ERROR", "format": "json"},
        "accessLog": {"format": "json", "filters": {"statusCodes": ["400-599"]}},
    }


def _request_headers(host: str, hermes_port: int, prefix: str) -> dict[str, str]:
    """Override trusted fields and explicitly remove the retained debug field."""

    return {
        "Forwarded": f"for=127.0.0.1;host={host};proto=https",
        "Origin": f"http://127.0.0.1:{hermes_port}",
        "X-Forwarded-For": "127.0.0.1",
        "X-Forwarded-Host": host,
        "X-Forwarded-Prefix": prefix,
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Debug": "",
        "X-Real-IP": "127.0.0.1",
    }


def render_dynamic_config(value: Mapping[str, object]) -> dict[str, object]:
    """Render routes and local policy middleware for one proof run.

    Traefik's native Query/QueryRegexp matchers permit extra unknown query
    keys.  Every router therefore runs the local forward-auth policy first;
    that policy applies the closed raw-query grammar in ``policy_decision``.
    This keeps edge denials before either Hermes or static upstream access.
    """

    inputs = _validate_runtime_inputs(value)
    host = str(inputs["host"])
    hermes_port = int(inputs["hermes_port"])
    static_port = int(inputs["static_port"])
    policy_port = int(inputs["policy_port"])
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
        rule=f"{host_rule} && Method(`GET`) && Path(`/api/ws`)",
        priority=720,
        middlewares=["edge-policy", "root-hermes-headers"],
        service="hermes",
    )
    routers["root_pty_ws"] = _router(
        rule=f"{host_rule} && Method(`GET`) && Path(`/api/pty`)",
        priority=720,
        middlewares=["edge-policy", "root-hermes-headers"],
        service="hermes",
    )
    routers["client_deep_link"] = _router(
        rule=f"{host_rule} && Method(`GET`, `HEAD`) && PathRegexp(`{CLIENT_ROUTE_PATTERN}`)",
        priority=650,
        middlewares=["edge-policy", "client-deep-link-fallback"],
        service="static",
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
                        "authRequestHeaders": [
                            "Host",
                            "Origin",
                            "Forwarded",
                            "X-Forwarded-For",
                            "X-Forwarded-Host",
                            "X-Forwarded-Method",
                            "X-Forwarded-Proto",
                            "X-Forwarded-Uri",
                            "X-Real-IP",
                        ],
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
                    "headers": {"customRequestHeaders": _request_headers(host, hermes_port, "")}
                },
                "dashboard-hermes-headers": {
                    "headers": {"customRequestHeaders": _request_headers(host, hermes_port, "/hermes")}
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
    if dict(provenance) != dict(expected_provenance):
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
        normalized_events = {event: events[event] for event in BROWSER_COMPLETION_EVIDENCE}
        if normalized_events != BROWSER_COMPLETION_EVIDENCE:
            raise ValueError("passed browser evidence does not prove a complete journey")
        normalized_observations: dict[str, object] = {"events": normalized_events}
    elif status in BROWSER_BLOCKED_JOURNEYS:
        if set(observations) != {"blocker"} or observations["blocker"] != BROWSER_BLOCKER_CODES[status]:
            raise ValueError("blocked browser evidence does not match its status")
        normalized_observations = {"blocker": BROWSER_BLOCKER_CODES[status]}
    else:
        if set(observations) != {"failure"} or observations["failure"] != BROWSER_FAILURE_CODE:
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
            "hermes_listener": "loopback-only",
            "public_listener": "loopback-only-disposable",
            "edge_policy": "local-forward-auth-closed-query-gate",
        },
        "product": {
            "build_commit": build_sha,
            "static_manifest_sha256": build_digest,
        },
        "browser_journey": resolved_journey,
        "browser_evidence": normalized_evidence,
        "positive_cases": POSITIVE_CASES,
        "negative_cases": NEGATIVE_CASES,
        "black_box": {
            "scope": "local Traefik plus recording static, policy, and Hermes mocks only",
            "route_vectors": "shared static-route grammar and deep-link fixture identities",
            "assertions": [
                "valid session and message deep links reach the static upstream",
                "root-only scenario query is accepted by the policy gate",
                "static, client, and non-callback REST query mutations are edge 404",
                "OAuth callback accepts only the reviewed code/state or provider-error query forms",
                "mock Hermes receives exact path, query, body, and one /hermes prefix",
                "spoofed forwarding fields do not survive the trusted header middleware",
                "chat and PTY upgrades use separate exact query grammars",
            ],
            "request_material": "redacted",
        },
        "cookie_proof": {
            "status": "not_proven",
            "reason": "Traefik renderer output does not prove HttpOnly, SameSite, Path, or Secure on a real Set-Cookie response",
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


def _build_static_digest(site_root: Path) -> str:
    entries: list[bytes] = []
    for path in sorted(p for p in site_root.rglob("*") if p.is_file()):
        relative = path.relative_to(site_root).as_posix().encode("utf-8")
        content = path.read_bytes()
        entries.append(relative + b"\0" + str(len(content)).encode("ascii") + b"\0" + content)
    return digest_bytes(b"".join(entries))


def _header_value(headers: Mapping[str, str] | None, name: str) -> str:
    if headers is None:
        return ""
    wanted = name.lower()
    return next((str(value) for key, value in headers.items() if key.lower() == wanted), "")


def _query_matches(query: str, patterns: Iterable[str]) -> bool:
    return any(re.fullmatch(pattern, query) for pattern in patterns)


def _unsafe_target(path: str, query: str, raw_target: str | None) -> bool:
    target = raw_target if raw_target is not None else path + ("?" + query if query else "")
    return bool(RAW_UNSAFE_RE.search(target) or DOT_SEGMENT_RE.search(target) or target.endswith("?"))


def _session_route(method: str, path: str) -> bool:
    for route_method, template in SESSION_ROUTES:
        if route_method != method:
            continue
        suffix = template.split("{session_id}", 1)[1]
        pattern = rf"^/api/sessions/{SESSION_ID_PATTERN}{re.escape(suffix)}$"
        if re.fullmatch(pattern, path):
            return True
    return False


def policy_decision(
    *,
    host: str,
    https_port: int,
    method: str,
    path: str,
    query: str = "",
    headers: Mapping[str, str] | None = None,
    raw_target: str | None = None,
) -> dict[str, object]:
    """Model the local forward-auth policy without retaining request material."""

    host = _validate_host(host)
    https_port = _validate_port(https_port, "https_port")
    expected_origin = f"https://{host}:{https_port}"
    upgrade = _header_value(headers, "Upgrade").lower() == "websocket"
    if _header_value(headers, "Host") and _header_value(headers, "Host") != host:
        return {"status": 421, "layer": "edge", "upstream_request": False}
    if _unsafe_target(path, query, raw_target):
        return {"status": 404, "layer": "edge", "upstream_request": False}

    dashboard = path.startswith("/hermes")
    upstream_path = path[len("/hermes") :] if dashboard else path
    if dashboard and not upstream_path:
        upstream_path = "/"
    if dashboard and upstream_path.startswith("/hermes"):
        return {"status": 404, "layer": "edge", "upstream_request": False}

    if upstream_path in WEBSOCKET_ROUTES:
        if method != "GET" or not upgrade or "upgrade" not in _header_value(headers, "Connection").lower():
            return {"status": 404, "layer": "edge", "upstream_request": False}
        if _header_value(headers, "Origin") != expected_origin:
            return {"status": 403, "layer": "edge", "upstream_request": False}
        if upstream_path == "/api/ws":
            accepted = bool(re.fullmatch(CHAT_TICKET_QUERY_PATTERN, query))
        else:
            accepted = _query_matches(query, PTY_QUERY_PATTERNS)
        if not accepted:
            return {"status": 404, "layer": "edge", "upstream_request": False}
        return {"status": 101, "layer": "hermes", "upstream_request": True}

    if any(route_method == method and route_path == upstream_path for route_method, route_path in EXACT_REST_ROUTES):
        accepted_query = (
            _query_matches(query, AUTH_CALLBACK_QUERY_PATTERNS)
            if upstream_path == "/auth/callback"
            else query == ""
        )
        if accepted_query:
            return {"status": 200, "layer": "hermes", "upstream_request": True}
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
        bundle = render_bundle()
        if args.output_dir is None:
            print(json.dumps(bundle, sort_keys=True, separators=(",", ":")))
        else:
            args.output_dir.mkdir(parents=True, exist_ok=True)
            (args.output_dir / "traefik-static.json").write_text(
                json.dumps(bundle["static"], sort_keys=True, indent=2) + "\n", encoding="utf-8"
            )
            (args.output_dir / "traefik-dynamic.json").write_text(
                json.dumps(bundle["dynamic"], sort_keys=True, indent=2) + "\n", encoding="utf-8"
            )
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
