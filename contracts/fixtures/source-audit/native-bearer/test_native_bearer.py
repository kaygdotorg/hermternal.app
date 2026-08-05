#!/usr/bin/env python3
"""Validate the frozen native bearer source-audit fixture.

This standard-library-only validator checks contract data, source citation
bindings, public-path semantics, conditional drain authentication, provider
stacking, and mutation regressions. It never imports Hermes or sends a request.
Pass ``--source-root`` when the pinned Hermes checkout is available to verify
all recorded SHA-256 source-file digests as well as the checked-in metadata.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent
REVISION = "f5be9236e00ddf2f2a412697f267078fc4ee068e6"

EXPECTED_NATIVE_ROUTES = {
    ("GET", "/api/auth/me"),
    ("POST", "/api/auth/ws-ticket"),
    ("GET", "/api/sessions"),
    ("GET", "/api/sessions/search"),
    ("GET", "/api/sessions/{session_id}"),
    ("GET", "/api/sessions/{session_id}/messages"),
    ("PATCH", "/api/sessions/{session_id}"),
    ("POST", "/api/chat/image-upload"),
}

EXPECTED_PUBLIC_API_PATHS = {
    "/api/health",
    "/api/status",
    "/api/config/defaults",
    "/api/config/schema",
    "/api/model/info",
    "/api/dashboard/themes",
    "/api/dashboard/plugins",
    "/api/cron/fire",
}

EXPECTED_GATE_PUBLIC_PREFIXES = {
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
}

EXPECTED_PUBLIC_AUTH_ROUTES = {
    ("GET", "/login"),
    ("GET", "/api/auth/providers"),
    ("GET", "/auth/login"),
    ("GET", "/auth/native/authorize"),
    ("GET", "/auth/callback"),
    ("POST", "/auth/password-login"),
    ("POST", "/auth/logout"),
    ("POST", "/auth/native/token"),
    ("POST", "/auth/native/refresh"),
}

EXPECTED_DRAIN_ROUTE = ("POST", "/api/gateway/drain")

EXPECTED_SOURCE_DIGESTS = {
    "hermes_cli/dashboard_auth/middleware.py": "a7ed66ee8334458a53029ee2ca8ad59682ac830b1e65c881cde486752d212d4e",
    "hermes_cli/dashboard_auth/public_paths.py": "18dad29df79d0ee6111926249d859704b2afc61ffa974ae4589d3667c7fa02ce",
    "hermes_cli/dashboard_auth/routes.py": "d42be557b9b1ba798c038c91246cba0bf046e89ebe34a27db0c7803c517e9c20",
    "hermes_cli/web_routers/sessions.py": "f8debdab79430829245352ebdb7f50603c3a42c11d4609eb3287c35b9a2bf0ba",
    "hermes_cli/web_server.py": "b52cc35523f891b6947fa59ac70516d955e47714877069e5ed3f06544b793c1a",
    "hermes_cli/dashboard_auth/token_auth.py": "c3f5a3b17f28371f6d4fd794540e15b6a05010d308b9ff6a905a9cf1dc24bd09",
    "plugins/dashboard_auth/drain/__init__.py": "3b737b4964df2f509f536a413a502a620a4fae3ca5f03acad74887e4f003afbc",
}

EXPECTED_EVIDENCE = {
    "middleware-public-gate": ("hermes_cli/dashboard_auth/middleware.py", "49-86"),
    "public-api-inventory": ("hermes_cli/dashboard_auth/public_paths.py", "33-60"),
    "middleware-bearer-verification": ("hermes_cli/dashboard_auth/middleware.py", "281-320"),
    "middleware-gated-bearer": ("hermes_cli/dashboard_auth/middleware.py", "323-373"),
    "routes-auth-public": ("hermes_cli/dashboard_auth/routes.py", "132-182"),
    "routes-native-authorize": ("hermes_cli/dashboard_auth/routes.py", "289-289"),
    "routes-auth-callback": ("hermes_cli/dashboard_auth/routes.py", "379-379"),
    "routes-password-login": ("hermes_cli/dashboard_auth/routes.py", "650-650"),
    "routes-logout": ("hermes_cli/dashboard_auth/routes.py", "742-742"),
    "routes-auth-rest": ("hermes_cli/dashboard_auth/routes.py", "778-817"),
    "routes-native-token-refresh": ("hermes_cli/dashboard_auth/routes.py", "841-894"),
    "sessions-list": ("hermes_cli/web_routers/sessions.py", "50-51"),
    "sessions-search": ("hermes_cli/web_routers/sessions.py", "166-167"),
    "sessions-detail": ("hermes_cli/web_routers/sessions.py", "552-553"),
    "sessions-messages": ("hermes_cli/web_routers/sessions.py", "598-599"),
    "sessions-patch": ("hermes_cli/web_routers/sessions.py", "661-662"),
    "image-upload": ("hermes_cli/web_server.py", "2306-2306"),
    "token-route-registration": ("hermes_cli/dashboard_auth/token_auth.py", "54-75"),
    "token-route-decisions": ("hermes_cli/dashboard_auth/token_auth.py", "144-183"),
    "drain-route-conditional-doc": ("hermes_cli/web_server.py", "4000-4011"),
    "drain-plugin-registration": ("plugins/dashboard_auth/drain/__init__.py", "229-291"),
}

REQUIRED_CASES = {
    "positive-auth-me",
    "positive-auth-ws-ticket",
    "positive-session-list",
    "positive-session-search",
    "positive-session-detail",
    "positive-session-messages",
    "positive-session-patch",
    "positive-image-upload",
    "public-api-health",
    "public-api-status",
    "public-api-config-defaults",
    "public-api-config-schema",
    "public-api-model-info",
    "public-api-dashboard-themes",
    "public-api-dashboard-plugins",
    "public-api-cron-fire",
    "public-login-page",
    "public-auth-login",
    "public-auth-callback",
    "public-native-authorize",
    "public-native-token",
    "public-native-refresh",
    "public-password-login",
    "public-logout",
    "public-provider-discovery",
    "public-mcp-oauth-callback",
    "public-assets-file",
    "public-favicon",
    "public-ds-assets-file",
    "public-font-file",
    "public-terminal-font-file",
    "negative-assets-boundary",
    "negative-ds-assets-boundary",
    "negative-fonts-boundary",
    "negative-terminal-fonts-boundary",
    "negative-public-api-extension",
    "negative-mcp-callback-boundary",
    "negative-invalid-bearer",
    "negative-expired-bearer",
    "negative-invalid-bearer-valid-cookie-no-fallback",
    "negative-expired-bearer-valid-cookie-no-fallback",
    "negative-provider-stack-accept-after-outage",
    "negative-provider-stack-all-reachable-invalid",
    "negative-provider-stack-invalid-and-outage",
    "negative-missing-bearer",
    "positive-missing-bearer-valid-cookie",
    "negative-wrong-auth-scheme",
    "positive-drain-plugin-registered-service-token",
    "negative-drain-plugin-registered-invalid-token-cookie-no-fallback",
    "negative-drain-plugin-registered-provider-outage",
    "negative-drain-plugin-registered-missing-cookie-no-fallback",
    "positive-drain-plugin-unregistered-cookie-gated",
    "negative-drain-plugin-unregistered-native-bearer-unreviewed",
    "negative-drain-plugin-unregistered-invalid-bearer-cookie-no-fallback",
    "negative-drain-plugin-unregistered-loopback-cookie-gate",
    "negative-drain-plugin-unregistered-service-token-not-registered",
    "negative-unverified-health-method",
    "negative-unverified-session-export",
    "negative-unverified-wrong-method",
    "negative-unverified-message-suffix",
}

LINE_RANGE = re.compile(r"^(\d+)(?:-(\d+))?$")


class ValidationError(AssertionError):
    """A contract fixture assertion failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def parse_lines(value: Any, label: str) -> tuple[int, int]:
    require(isinstance(value, str) and value.strip(), f"{label} must have a non-empty line range")
    match = LINE_RANGE.fullmatch(value.strip())
    require(match is not None, f"{label} has invalid line range: {value!r}")
    start = int(match.group(1))
    end = int(match.group(2) or match.group(1))
    require(start > 0 and end >= start, f"{label} has invalid line order")
    return start, end


def load_json(name: str) -> dict[str, Any]:
    with (ROOT / name).open(encoding="utf-8") as handle:
        value = json.load(handle)
    require(isinstance(value, dict), f"{name} must contain a JSON object")
    return value


def route_matches(template: str, path: str) -> bool:
    """Match exact paths or one non-empty segment per placeholder."""
    template_parts = template.split("/")
    path_parts = path.split("/")
    if len(template_parts) != len(path_parts):
        return False
    for template_part, path_part in zip(template_parts, path_parts):
        if template_part.startswith("{") and template_part.endswith("}"):
            if not path_part or "/" in path_part:
                return False
        elif template_part != path_part:
            return False
    return True


def validate_source_provenance(audit: dict[str, Any]) -> None:
    require(audit.get("hermes_revision") == REVISION, "audit revision is not pinned")
    provenance = audit.get("source_provenance")
    require(isinstance(provenance, dict), "source_provenance is required")
    require(provenance.get("pinned_revision") == REVISION, "source provenance revision is not pinned")
    require(
        provenance.get("verification") == "sha256_file_digests_are_verifiable_against_the_pinned_checkout",
        "source provenance verification rule changed",
    )
    files = provenance.get("files")
    require(isinstance(files, list), "source provenance files must be a list")
    actual: dict[str, str] = {}
    for item in files:
        require(isinstance(item, dict), "source provenance file must be an object")
        path = item.get("path")
        digest = item.get("sha256")
        require(isinstance(path, str) and path, "source provenance path must be non-empty")
        require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None, f"invalid source digest: {path}")
        require(path not in actual, f"duplicate source provenance path: {path}")
        actual[path] = digest
    require(actual == EXPECTED_SOURCE_DIGESTS, "source provenance digest inventory changed")


def evidence_map(audit: dict[str, Any]) -> dict[str, dict[str, Any]]:
    records = audit.get("source_evidence")
    require(isinstance(records, list), "source_evidence must be a list")
    result: dict[str, dict[str, Any]] = {}
    for record in records:
        require(isinstance(record, dict), "source evidence record must be an object")
        evidence_id = record.get("id")
        require(isinstance(evidence_id, str) and evidence_id, "source evidence id must be non-empty")
        require(evidence_id not in result, f"duplicate source evidence id: {evidence_id}")
        file_path = record.get("file")
        require(file_path in EXPECTED_SOURCE_DIGESTS, f"source evidence file is not provenance-pinned: {evidence_id}")
        parse_lines(record.get("lines"), f"source evidence {evidence_id}")
        result[evidence_id] = record
    require(set(result) == set(EXPECTED_EVIDENCE), "source evidence inventory changed")
    for evidence_id, (expected_file, expected_lines) in EXPECTED_EVIDENCE.items():
        record = result[evidence_id]
        require(record.get("file") == expected_file, f"source evidence file changed: {evidence_id}")
        require(record.get("lines") == expected_lines, f"source evidence range changed: {evidence_id}")
    return result


def validate_citation(citation: Any, evidence: dict[str, dict[str, Any]], label: str) -> None:
    require(isinstance(citation, dict), f"{label} source citation is required")
    evidence_id = citation.get("evidence_id")
    require(isinstance(evidence_id, str) and evidence_id, f"{label} citation evidence id is required")
    require(evidence_id in evidence, f"{label} cites unknown source evidence: {evidence_id}")
    citation_start, citation_end = parse_lines(citation.get("lines"), f"{label} citation")
    evidence_start, evidence_end = parse_lines(evidence[evidence_id].get("lines"), f"source evidence {evidence_id}")
    require(
        evidence_start <= citation_start <= citation_end <= evidence_end,
        f"{label} citation range is outside source evidence {evidence_id}",
    )


def route_pairs(routes: Any, set_name: str, evidence: dict[str, dict[str, Any]]) -> set[tuple[str, str]]:
    require(isinstance(routes, list), f"route set {set_name} must be a list")
    pairs: set[tuple[str, str]] = set()
    for index, route in enumerate(routes):
        label = f"{set_name}[{index}]"
        require(isinstance(route, dict), f"{label} must be an object")
        method = route.get("method")
        path = route.get("path")
        require(isinstance(method, str) and method.isupper(), f"{label} has invalid method")
        require(isinstance(path, str) and path.startswith("/"), f"{label} has invalid path")
        validate_citation(route.get("source_citation"), evidence, label)
        pair = (method, path)
        require(pair not in pairs, f"duplicate route in {set_name}: {pair}")
        pairs.add(pair)
    return pairs


def inventory_paths(items: Any, name: str, evidence: dict[str, dict[str, Any]]) -> set[str]:
    require(isinstance(items, list), f"{name} must be a list")
    paths: set[str] = set()
    for index, item in enumerate(items):
        label = f"{name}[{index}]"
        require(isinstance(item, dict), f"{label} must be an object")
        path = item.get("path")
        require(isinstance(path, str) and path.startswith("/"), f"{label} has invalid path")
        validate_citation(item.get("source_citation"), evidence, label)
        require(path not in paths, f"duplicate path in {name}: {path}")
        paths.add(path)
    return paths


def validate_audit(audit: dict[str, Any]) -> None:
    require(audit.get("schema") == "hermternal.source-audit.native-bearer.v2", "unexpected audit schema")
    require(audit.get("contract_version") == "dashboard-v0.0.1", "unexpected contract version")
    scope = audit.get("scope")
    require(isinstance(scope, dict), "audit scope is required")
    require(scope.get("unverified_route_policy") == "blocked_unverified", "audit must fail closed")
    require(scope.get("source_middleware_behavior") == "gated_auth_attempts_bearer_on_every_non_public_path", "source bearer scope was narrowed incorrectly")
    require(scope.get("supported_route_policy") == "conservative_reviewed_allowlist", "supported route policy changed")
    require(scope.get("supported_route_inventory_complete") is False, "supported route inventory must remain conservative")
    validate_source_provenance(audit)
    evidence = evidence_map(audit)

    bypass = audit.get("public_bypass_inventory")
    require(isinstance(bypass, dict), "public_bypass_inventory is required")
    exact_paths = inventory_paths(bypass.get("public_api_exact_paths"), "public_api_exact_paths", evidence)
    prefixes = inventory_paths(bypass.get("gate_public_prefixes"), "gate_public_prefixes", evidence)
    require(exact_paths == EXPECTED_PUBLIC_API_PATHS, "public API exact inventory changed")
    require(prefixes == EXPECTED_GATE_PUBLIC_PREFIXES, "gate public prefix inventory changed")
    require(
        bypass.get("matching") == "exact_paths_use_membership; prefixes_use_path_equals_prefix_or_path_startswith_prefix",
        "public path matching semantics changed",
    )

    route_sets = audit.get("route_sets")
    require(isinstance(route_sets, dict), "route_sets is required")
    native = route_pairs(route_sets.get("native_bearer_supported"), "native_bearer_supported", evidence)
    public_auth = route_pairs(route_sets.get("public_auth_routes"), "public_auth_routes", evidence)
    require(native == EXPECTED_NATIVE_ROUTES, "native supported route inventory changed without review")
    require(public_auth == EXPECTED_PUBLIC_AUTH_ROUTES, "public auth route inventory changed")
    require(native.isdisjoint(public_auth), "native and public auth routes overlap")

    drain_routes = route_sets.get("conditional_service_token")
    require(isinstance(drain_routes, list) and len(drain_routes) == 1, "drain route must have one conditional record")
    drain = drain_routes[0]
    require(isinstance(drain, dict), "drain route record must be an object")
    require((drain.get("method"), drain.get("path")) == EXPECTED_DRAIN_ROUTE, "drain route changed")
    require(drain.get("registration_mode") == "plugin_conditional", "drain route must be conditional")
    validate_citation(drain.get("source_citation"), evidence, "conditional_service_token[0]")
    validate_citation(drain.get("registration_citation"), evidence, "conditional_service_token[0].registration")
    require("native_bearer" not in drain, "drain must not claim unconditional native/service auth")


def public_path_class(audit: dict[str, Any], path: str) -> str | None:
    bypass = audit["public_bypass_inventory"]
    if path in {item["path"] for item in bypass["public_api_exact_paths"]}:
        return "public_bypass_exact"
    if any(path == item["path"] or path.startswith(item["path"]) for item in bypass["gate_public_prefixes"]):
        return "public_bypass_prefix"
    return None


def classify_route(audit: dict[str, Any], method: str, path: str) -> str:
    public_class = public_path_class(audit, path)
    if public_class is not None:
        return public_class
    route_sets = audit["route_sets"]
    if any(route["method"] == method and route_matches(route["path"], path) for route in route_sets["native_bearer_supported"]):
        return "native_bearer_supported"
    if any(route["method"] == method and route_matches(route["path"], path) for route in route_sets["conditional_service_token"]):
        return "conditional_service_token"
    return "blocked_unverified"


def provider_stack_decision(outcomes: Any) -> str:
    require(isinstance(outcomes, list) and outcomes, "provider_stack requires non-empty outcomes")
    require(all(outcome in {"accept", "invalid", "unreachable"} for outcome in outcomes), "invalid provider outcome")
    if "accept" in outcomes:
        return "pass_through"
    if "unreachable" in outcomes:
        return "503_auth_provider_unreachable"
    return "401_invalid_or_expired_session"


def native_decision(request: dict[str, Any]) -> str:
    bearer_state = request["bearer_state"]
    if bearer_state == "valid":
        return "pass_through"
    if bearer_state in {"invalid", "expired"}:
        return "401_invalid_or_expired_session"
    if bearer_state == "provider_unavailable":
        return "503_auth_provider_unreachable"
    if bearer_state == "provider_stack":
        return provider_stack_decision(request.get("provider_outcomes"))
    if bearer_state in {"missing", "wrong_scheme"}:
        if request["session_cookie"] == "valid":
            return "cookie_session_pass_through"
        return "401_without_authenticated_cookie"
    return "native_bearer_not_proven"


def drain_decision(request: dict[str, Any]) -> str:
    registered = request.get("auth_mode") == "plugin_registered"
    bearer_state = request["bearer_state"]
    if registered:
        if bearer_state == "service_valid":
            return "service_token_pass_through"
        if bearer_state in {"provider_unavailable", "provider_stack"}:
            if bearer_state == "provider_stack":
                return "503_service_token_provider_unreachable" if "unreachable" in request.get("provider_outcomes", []) and "accept" not in request.get("provider_outcomes", []) else "service_token_pass_through"
            return "503_service_token_provider_unreachable"
        return "401_service_token_only"

    if request.get("bind_mode", "gated") == "loopback":
        if request["session_cookie"] == "valid":
            return "legacy_session_gate_pass_through"
        return "401_legacy_session_gate"
    if bearer_state == "valid":
        return "source_bearer_pass_unreviewed"
    if bearer_state in {"invalid", "expired"}:
        return "401_invalid_or_expired_session"
    if bearer_state == "provider_unavailable":
        return "503_auth_provider_unreachable"
    if bearer_state == "provider_stack":
        decision = provider_stack_decision(request.get("provider_outcomes"))
        return "source_bearer_pass_unreviewed" if decision == "pass_through" else decision
    if bearer_state in {"missing", "wrong_scheme"} and request["session_cookie"] == "valid":
        return "cookie_session_pass_through"
    return "401_without_authenticated_cookie"


def expected_decision(audit: dict[str, Any], request: dict[str, Any], route_class: str) -> str:
    if route_class.startswith("public_bypass"):
        return "bypass_native_bearer_gate"
    if route_class == "native_bearer_supported":
        return native_decision(request)
    if route_class == "conditional_service_token":
        return drain_decision(request)
    return "blocked_unverified"


def validate_cases(audit: dict[str, Any], cases_doc: dict[str, Any]) -> int:
    require(cases_doc.get("schema") == "hermternal.source-audit.native-bearer.cases.v2", "unexpected case schema")
    require(cases_doc.get("contract_version") == "dashboard-v0.0.1", "case contract version mismatch")
    require(cases_doc.get("hermes_revision") == REVISION, "cases are not pinned")
    cases = cases_doc.get("cases")
    require(isinstance(cases, list) and cases, "cases must be a non-empty list")

    ids: set[str] = set()
    positive_route_coverage: set[tuple[str, str]] = set()
    for case in cases:
        require(isinstance(case, dict), "each case must be an object")
        case_id = case.get("id")
        kind = case.get("kind")
        request = case.get("request")
        expected = case.get("expected")
        require(isinstance(case_id, str) and case_id not in ids, f"duplicate or invalid case id: {case_id}")
        ids.add(case_id)
        require(kind in {"positive", "negative", "public"}, f"invalid case kind: {case_id}")
        require(isinstance(request, dict) and isinstance(expected, dict), f"malformed case: {case_id}")
        method = request.get("method")
        path = request.get("path")
        bearer_state = request.get("bearer_state")
        session_cookie = request.get("session_cookie")
        require(isinstance(method, str) and method.isupper(), f"invalid case method: {case_id}")
        require(isinstance(path, str) and path.startswith("/"), f"invalid case path: {case_id}")
        require(
            bearer_state in {"valid", "invalid", "expired", "provider_unavailable", "provider_stack", "missing", "wrong_scheme", "service_valid"},
            f"invalid bearer state: {case_id}",
        )
        require(session_cookie in {"absent", "valid"}, f"invalid session cookie state: {case_id}")
        if bearer_state == "provider_stack":
            provider_stack_decision(request.get("provider_outcomes"))
        if path == "/api/gateway/drain":
            require(request.get("auth_mode") in {"plugin_registered", "plugin_unregistered"}, f"drain auth mode missing: {case_id}")
            if request.get("auth_mode") == "plugin_unregistered":
                require(request.get("bind_mode", "gated") in {"gated", "loopback"}, f"drain bind mode invalid: {case_id}")

        route_class = classify_route(audit, method, path)
        decision = expected_decision(audit, request, route_class)
        require(expected.get("route_class") == route_class, f"route classification mismatch: {case_id}")
        require(expected.get("native_bearer_decision") == decision, f"bearer decision mismatch: {case_id}")

        if kind == "positive" and bearer_state == "valid" and route_class == "native_bearer_supported":
            matching = [
                route["path"]
                for route in sorted(
                    audit["route_sets"]["native_bearer_supported"],
                    key=lambda route: route["path"].count("{"),
                )
                if route["method"] == method and route_matches(route["path"], path)
            ]
            require(matching, f"positive route does not map to a native route: {case_id}")
            positive_route_coverage.add((method, matching[0]))

        if route_class == "blocked_unverified":
            require(expected.get("handler_status") == "not_asserted", f"unverified route must be blocked: {case_id}")
        if decision.startswith("401_"):
            require(expected.get("http_status") == 401, f"401 decision missing status: {case_id}")
        if decision.startswith("503_"):
            require(expected.get("http_status") == 503, f"503 decision missing status: {case_id}")
        if bearer_state in {"invalid", "expired"} and session_cookie == "valid":
            require(expected.get("cookie_fallback") is False, f"present invalid bearer fell back to cookie: {case_id}")
        if route_class == "conditional_service_token" and request.get("auth_mode") == "plugin_unregistered":
            require(expected.get("conditional_result") in {"cookie_gate_owns_route", "gated_auth_attempts_native_bearer", "legacy_session_token_gate", "token_seam_passes_through"}, f"unregistered drain mode is not modeled: {case_id}")
            if request.get("bind_mode", "gated") == "gated" and bearer_state == "valid":
                require(expected.get("contract_route_policy") == "blocked_unverified", f"unregistered drain bearer claim must remain conservative: {case_id}")

    require(positive_route_coverage == EXPECTED_NATIVE_ROUTES, "positive cases do not cover every native supported route")
    require(REQUIRED_CASES <= ids, "required source-audit regression case is missing")
    return len(cases)


def expect_rejected(label: str, callback: Callable[[], None]) -> None:
    try:
        callback()
    except ValidationError:
        return
    raise ValidationError(f"mutation was accepted: {label}")


def validate_mutation_regressions(audit: dict[str, Any], cases: dict[str, Any]) -> int:
    mutations = 0

    citation_missing = copy.deepcopy(audit)
    del citation_missing["route_sets"]["native_bearer_supported"][0]["source_citation"]
    expect_rejected("missing native route citation", lambda: validate_audit(citation_missing))
    mutations += 1

    citation_unbound = copy.deepcopy(audit)
    citation_unbound["route_sets"]["native_bearer_supported"][0]["source_citation"]["lines"] = "1"
    expect_rejected("citation outside source evidence range", lambda: validate_audit(citation_unbound))
    mutations += 1

    citation_unknown = copy.deepcopy(audit)
    citation_unknown["route_sets"]["native_bearer_supported"][0]["source_citation"]["evidence_id"] = "unknown"
    expect_rejected("citation to unknown evidence", lambda: validate_audit(citation_unknown))
    mutations += 1

    digest_mutation = copy.deepcopy(audit)
    digest_mutation["source_provenance"]["files"][0]["sha256"] = "0" * 64
    expect_rejected("source digest mutation", lambda: validate_audit(digest_mutation))
    mutations += 1

    route_mutation = copy.deepcopy(audit)
    route_mutation["route_sets"]["native_bearer_supported"][0]["path"] = "/api/auth/me/extra"
    expect_rejected("native route expansion", lambda: validate_audit(route_mutation))
    mutations += 1

    public_mutation = copy.deepcopy(audit)
    public_mutation["public_bypass_inventory"]["public_api_exact_paths"].remove(
        next(item for item in public_mutation["public_bypass_inventory"]["public_api_exact_paths"] if item["path"] == "/api/status")
    )
    expect_rejected("public exact path removal", lambda: validate_audit(public_mutation))
    mutations += 1

    drain_mutation = copy.deepcopy(audit)
    drain_mutation["route_sets"]["conditional_service_token"][0]["registration_mode"] = "always_registered"
    expect_rejected("unconditional drain seam", lambda: validate_audit(drain_mutation))
    mutations += 1

    cookie_mutation = copy.deepcopy(cases)
    invalid_case = next(item for item in cookie_mutation["cases"] if item["id"] == "negative-invalid-bearer-valid-cookie-no-fallback")
    invalid_case["expected"]["cookie_fallback"] = True
    expect_rejected("invalid bearer cookie fallback", lambda: validate_cases(audit, cookie_mutation))
    mutations += 1

    provider_mutation = copy.deepcopy(cases)
    provider_case = next(item for item in provider_mutation["cases"] if item["id"] == "negative-provider-stack-invalid-and-outage")
    provider_case["request"]["provider_outcomes"] = ["invalid", "invalid"]
    expect_rejected("provider outage erased", lambda: validate_cases(audit, provider_mutation))
    mutations += 1

    boundary_mutation = copy.deepcopy(cases)
    boundary_case = next(item for item in boundary_mutation["cases"] if item["id"] == "negative-assets-boundary")
    boundary_case["expected"]["native_bearer_decision"] = "bypass_native_bearer_gate"
    expect_rejected("asset prefix boundary widened", lambda: validate_cases(audit, boundary_mutation))
    mutations += 1

    return mutations


def verify_source_root(audit: dict[str, Any], source_root: Path) -> int:
    files = audit["source_provenance"]["files"]
    verified = 0
    for item in files:
        path = source_root / item["path"]
        require(path.is_file(), f"pinned source file is missing: {item['path']}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        require(digest == item["sha256"], f"pinned source digest mismatch: {item['path']}")
        verified += 1
    return verified


def artifact_size() -> int:
    return sum(path.stat().st_size for path in ROOT.iterdir() if path.is_file())


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, help="optional pinned Hermes checkout root for SHA-256 verification")
    args = parser.parse_args(argv)
    started = time.perf_counter()
    audit = load_json("source_audit.json")
    cases = load_json("cases.json")
    validate_audit(audit)
    case_count = validate_cases(audit, cases)
    mutation_count = validate_mutation_regressions(audit, cases)
    provenance = "metadata_only"
    verified_files = 0
    if args.source_root is not None:
        verified_files = verify_source_root(audit, args.source_root)
        provenance = f"source_files_verified={verified_files}"
    duration_ms = (time.perf_counter() - started) * 1000
    print(
        "native bearer audit valid: "
        f"revision={REVISION} "
        f"native_routes={len(EXPECTED_NATIVE_ROUTES)} "
        f"cases={case_count} "
        f"mutations={mutation_count} "
        f"provenance={provenance} "
        f"duration_ms={duration_ms:.3f} "
        f"artifact_bytes={artifact_size()}"
    )


if __name__ == "__main__":
    main()
