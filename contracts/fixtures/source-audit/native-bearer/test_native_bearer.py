#!/usr/bin/env python3
"""Validate the frozen native bearer source-audit fixture.

This is intentionally a small standard-library-only validator. It checks the
contract data and route-shape policy; it does not import Hermes, make network
requests, or attempt to verify a credential.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


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

EXPECTED_PUBLIC_ROUTES = {
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

EXPECTED_SERVICE_ROUTES = {
    ("POST", "/api/gateway/drain"),
}

REQUIRED_NEGATIVE_CASES = {
    "negative-public-provider-discovery",
    "negative-public-native-authorize",
    "negative-public-native-token",
    "negative-public-native-refresh",
    "negative-service-token-drain",
    "negative-unverified-health",
    "negative-unverified-session-export",
    "negative-unverified-wrong-method",
    "negative-unverified-message-suffix",
    "negative-invalid-bearer",
    "negative-provider-outage",
    "negative-missing-bearer",
    "negative-wrong-auth-scheme",
}


class ValidationError(AssertionError):
    """A contract fixture assertion failed."""


def load_json(name: str) -> dict[str, Any]:
    with (ROOT / name).open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValidationError(f"{name} must contain a JSON object")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def route_matches(template: str, path: str) -> bool:
    """Match only exact paths or one non-empty segment per placeholder."""
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


def route_pairs(audit: dict[str, Any], set_name: str) -> set[tuple[str, str]]:
    routes = audit["route_sets"][set_name]
    require(isinstance(routes, list), f"route set {set_name} must be a list")
    pairs: set[tuple[str, str]] = set()
    for route in routes:
        require(isinstance(route, dict), f"route in {set_name} must be an object")
        method = route.get("method")
        path = route.get("path")
        require(isinstance(method, str) and method.isupper(), f"invalid method in {set_name}")
        require(isinstance(path, str) and path.startswith("/"), f"invalid path in {set_name}")
        pair = (method, path)
        require(pair not in pairs, f"duplicate route in {set_name}: {pair}")
        pairs.add(pair)
    return pairs


def validate_audit(audit: dict[str, Any]) -> None:
    require(audit.get("schema") == "hermternal.source-audit.native-bearer.v1", "unexpected audit schema")
    require(audit.get("contract_version") == "dashboard-v0.0.1", "unexpected contract version")
    require(audit.get("hermes_revision") == REVISION, "audit is not pinned to the required Hermes revision")
    require(
        audit.get("scope", {}).get("unverified_route_policy") == "blocked_unverified",
        "audit must fail closed for unverified routes",
    )
    native = route_pairs(audit, "native_bearer_authenticated")
    public = route_pairs(audit, "public_bootstrap_or_issuance")
    service = route_pairs(audit, "separate_service_token")
    require(native == EXPECTED_NATIVE_ROUTES, "native route inventory changed without validator review")
    require(public == EXPECTED_PUBLIC_ROUTES, "public route inventory changed without validator review")
    require(service == EXPECTED_SERVICE_ROUTES, "service-token route inventory changed without validator review")
    require(native.isdisjoint(public), "native and public route inventories overlap")
    require(native.isdisjoint(service), "native and service route inventories overlap")
    require(public.isdisjoint(service), "public and service route inventories overlap")
    drain = next(route for route in audit["route_sets"]["separate_service_token"] if route["path"] == "/api/gateway/drain")
    require(drain.get("native_bearer") is False, "drain route must remain separate from native bearer auth")


def classify_route(audit: dict[str, Any], method: str, path: str) -> str:
    """Return the contract class, preferring literal routes over templates."""
    route_sets = (
        ("native_bearer_authenticated", audit["route_sets"]["native_bearer_authenticated"]),
        ("public_bootstrap_or_issuance", audit["route_sets"]["public_bootstrap_or_issuance"]),
        ("separate_service_token", audit["route_sets"]["separate_service_token"]),
    )
    for route_class, routes in route_sets:
        ordered = sorted(routes, key=lambda route: route["path"].count("{"))
        if any(route["method"] == method and route_matches(route["path"], path) for route in ordered):
            return route_class
    return "blocked_unverified"


def expected_bearer_decision(route_class: str, bearer_state: str, session_cookie: str) -> str:
    if route_class == "native_bearer_authenticated":
        if bearer_state == "valid":
            return "pass_through"
        if bearer_state in {"invalid_or_expired", "provider_unavailable"}:
            return {
                "invalid_or_expired": "401_invalid_or_expired_session",
                "provider_unavailable": "503_auth_provider_unreachable",
            }[bearer_state]
        if bearer_state in {"missing", "wrong_scheme"} and session_cookie == "absent":
            return "401_without_authenticated_cookie"
        return "native_bearer_not_proven"
    if route_class == "public_bootstrap_or_issuance":
        return "bypass_native_bearer_gate"
    if route_class == "separate_service_token":
        return "separate_service_token_only"
    return "blocked_unverified"


def validate_cases(audit: dict[str, Any], cases_doc: dict[str, Any]) -> int:
    require(cases_doc.get("schema") == "hermternal.source-audit.native-bearer.cases.v1", "unexpected case schema")
    require(cases_doc.get("contract_version") == "dashboard-v0.0.1", "case contract version mismatch")
    require(cases_doc.get("hermes_revision") == REVISION, "cases are not pinned to the required Hermes revision")
    cases = cases_doc.get("cases")
    require(isinstance(cases, list) and cases, "cases must be a non-empty list")

    ids: set[str] = set()
    positive_route_coverage: set[tuple[str, str]] = set()
    negative_ids: set[str] = set()
    for case in cases:
        require(isinstance(case, dict), "each case must be an object")
        case_id = case.get("id")
        kind = case.get("kind")
        request = case.get("request")
        expected = case.get("expected")
        require(isinstance(case_id, str) and case_id not in ids, f"duplicate or invalid case id: {case_id}")
        ids.add(case_id)
        require(kind in {"positive", "negative"}, f"invalid case kind: {case_id}")
        require(isinstance(request, dict) and isinstance(expected, dict), f"malformed case: {case_id}")
        method = request.get("method")
        path = request.get("path")
        bearer_state = request.get("bearer_state")
        session_cookie = request.get("session_cookie")
        require(isinstance(method, str) and method.isupper(), f"invalid case method: {case_id}")
        require(isinstance(path, str) and path.startswith("/"), f"invalid case path: {case_id}")
        require(
            bearer_state in {"valid", "invalid_or_expired", "provider_unavailable", "missing", "wrong_scheme"},
            f"invalid bearer state: {case_id}",
        )
        require(session_cookie in {"absent", "present"}, f"invalid cookie state: {case_id}")

        route_class = classify_route(audit, method, path)
        decision = expected_bearer_decision(route_class, bearer_state, session_cookie)
        require(expected.get("route_class") == route_class, f"route classification mismatch: {case_id}")
        require(expected.get("native_bearer_decision") == decision, f"bearer decision mismatch: {case_id}")

        if kind == "positive":
            require(route_class == "native_bearer_authenticated", f"positive case is not a native route: {case_id}")
            require(bearer_state == "valid", f"positive case must use a valid synthetic state: {case_id}")
            positive_route_coverage.add((method, next(
                route["path"]
                for route in audit["route_sets"]["native_bearer_authenticated"]
                if route["method"] == method and route_matches(route["path"], path)
            )))
        else:
            negative_ids.add(case_id)

        if decision == "401_invalid_or_expired_session":
            require(expected.get("http_status") == 401, f"invalid bearer must be 401: {case_id}")
        elif decision == "503_auth_provider_unreachable":
            require(expected.get("http_status") == 503, f"provider outage must be 503: {case_id}")
        elif decision == "401_without_authenticated_cookie":
            require(expected.get("http_status") == 401, f"missing bearer without cookie must be 401: {case_id}")
        elif route_class == "blocked_unverified":
            require(expected.get("handler_status") == "not_asserted", f"unverified route must be blocked: {case_id}")

    require(len(positive_route_coverage) == len(EXPECTED_NATIVE_ROUTES), "positive cases do not cover every native route")
    require(positive_route_coverage == EXPECTED_NATIVE_ROUTES, "positive route coverage changed without review")
    require(REQUIRED_NEGATIVE_CASES <= negative_ids, "required negative case is missing")
    return len(cases)


def artifact_size() -> int:
    return sum(path.stat().st_size for path in ROOT.iterdir() if path.is_file())


def main() -> None:
    started = time.perf_counter()
    audit = load_json("source_audit.json")
    cases = load_json("cases.json")
    validate_audit(audit)
    case_count = validate_cases(audit, cases)
    duration_ms = (time.perf_counter() - started) * 1000
    print(
        "native bearer audit valid: "
        f"revision={REVISION} "
        f"native_routes={len(EXPECTED_NATIVE_ROUTES)} "
        f"cases={case_count} "
        f"duration_ms={duration_ms:.3f} "
        f"artifact_bytes={artifact_size()}"
    )


if __name__ == "__main__":
    main()
