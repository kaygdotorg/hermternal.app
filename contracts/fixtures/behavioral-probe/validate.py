#!/usr/bin/env python3
"""Validate the synthetic Hermes behavioral-probe contract offline.

The validator reads only checked-in JSON and the local route manifest. It never
starts Hermes, opens a socket, contacts a proxy, contacts an identity provider,
or treats fixture validation as live compatibility. Explicit exceptions keep the
same fail-closed behavior when Python is run with ``-O``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import statistics
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parent
FIXTURE_PATH = ROOT / "probe-fixtures.json"
BASELINE_PATH = ROOT / "probe-baseline.json"
REPO_ROOT = ROOT.parents[2]
MANIFEST_PATH = REPO_ROOT / "contracts/hermes-dashboard/manifest.md"
SCHEMA = "hermternal.behavioral-probe.v1"
CONTRACT = "dashboard-v0.0.1"
HERMES_SOURCE_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
ROUTE_MANIFEST = "contracts/hermes-dashboard/manifest.md"
ROUTE_MANIFEST_SHA256 = "3c6b44dc8dd90836f4fc5c5158d459959c569fb811db4b198e87d78ea5010197"
EXPECTED_FIXTURE_CANONICAL_SHA256 = "d59eeafd4747923ca6fa4e276bb14b94f54d3e9b5b0604a60929c1808e7fafe3"
BASELINE_REPETITIONS = 30
MAX_JSON_DEPTH = 64

ROOT_KEYS = (
    "schema",
    "contract",
    "hermes_source_sha",
    "route_manifest",
    "route_manifest_sha256",
    "synthetic_only",
    "probe",
    "proof_run",
    "evidence_requirements",
    "proxy_matrix",
    "parity",
    "probe_states",
    "pty_lifecycle",
    "cases",
    "redaction",
    "accessibility",
)
PROBE_KEYS = (
    "id",
    "mode",
    "live_run",
    "compatible",
    "unknown_result_policy",
    "retry_policy",
    "required_case_count",
    "required_state_count",
    "required_lifecycle_count",
    "required_proxy_pair_count",
)
PROOF_RUN_KEYS = (
    "status",
    "attestation_state",
    "proxy_variants",
    "host_class",
    "tool_versions",
    "live_result",
)
PROXY_KEYS = ("id", "case_id", "variants", "expected_equivalence")
PARITY_KEYS = (
    "status",
    "fixture_source",
    "platforms",
    "pty_policy",
    "missing_result_policy",
    "result_equivalence",
)
STATE_KEYS = (
    "id",
    "input_state",
    "evidence_state",
    "gate_decision",
    "safe_state",
    "retry_policy",
)
LIFECYCLE_KEYS = ("id", "expected", "live_claim")
CASE_KEYS = ("id", "synthetic", "kind", "surface", "request", "expected", "notes")

EXPECTED_CASE_IDS = (
    "rest-browser-cookie-approved",
    "rest-native-password-cookie-approved",
    "rest-native-oauth-bearer-approved",
    "rest-invalid-bearer-no-cookie-fallback",
    "rest-missing-credentials-denied",
    "rest-method-mutation-denied",
    "rest-source-present-not-allowlisted",
    "ws-chat-browser-fresh-ticket-approved",
    "ws-chat-native-fresh-ticket-approved",
    "ws-chat-missing-ticket-denied",
    "ws-chat-reused-ticket-denied",
    "ws-chat-expired-ticket-denied",
    "ws-chat-legacy-token-denied",
    "ws-pty-browser-fresh-ticket-approved",
    "ws-pty-native-denied",
    "ws-pty-unattested-host-denied",
    "edge-wrong-public-origin-denied",
    "edge-unsupported-host-denied",
    "upstream-hermes-400-preserved",
    "upstream-hermes-4403-preserved",
    "rpc-prompt-submit-approved",
    "rpc-unknown-operation-denied",
    "rpc-config-key-denied",
    "rpc-malformed-json-rejected",
    "event-unknown-additive-noninteractive-ignored",
    "event-unknown-interactive-denied",
    "pty-log-redaction-only",
)
EXPECTED_STATE_IDS = ("pending", "empty", "success", "failure", "cancelled", "unknown")
EXPECTED_LIFECYCLE_IDS = (
    "input-forwarded-not-replayed",
    "detach-retains-bounded-state",
    "ttl-reap-eventual",
)
EXPECTED_PROXY_IDS = (
    "edge-origin-denial",
    "edge-host-denial",
    "upstream-400-preservation",
    "upstream-4403-preservation",
)
EXPECTED_EVIDENCE_REQUIREMENTS = (
    "attestation_matches_pinned_sha",
    "route_manifest_matches_pinned_digest",
    "all_required_case_results_present",
    "edge_and_upstream_results_are_distinguished",
    "redaction_and_log_policy_passes",
    "shared_fixture_parity_is_recorded",
    "caddy_and_traefik_results_match",
    "measured_baseline_is_present",
)
EXPECTED_PLATFORMS = ("web", "ios", "ipados", "macos")

CASE_SHAPES: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "rest": (
        ("method", "path", "applicability", "auth_mode", "credential_state", "cookie_state", "origin_policy"),
        ("decision", "route_class", "auth_result", "handler_result", "http_status", "fallback", "observed_layer"),
    ),
    "chat_websocket": (
        ("path", "applicability", "auth_mode", "credential_state", "origin_policy", "host_class", "framing", "source_result", "session_scope"),
        ("decision", "route_class", "upgrade_auth", "source_result", "close_code", "http_status", "ticket_policy", "fallback", "observed_layer", "log_policy"),
    ),
    "pty_websocket": (
        ("path", "applicability", "auth_mode", "credential_state", "origin_policy", "host_class", "framing", "source_result", "session_scope", "attach_state"),
        ("decision", "route_class", "upgrade_auth", "source_result", "close_code", "http_status", "ticket_policy", "fallback", "observed_layer", "log_policy"),
    ),
    "edge": (
        ("path", "applicability", "origin_policy", "host_class", "auth_mode", "credential_state", "source_result"),
        ("decision", "observed_layer", "http_status", "upstream_called", "source_status", "fallback"),
    ),
    "json_rpc": (
        ("path", "applicability", "auth_mode", "credential_state", "operation", "config_key", "input_state"),
        ("decision", "operation_class", "fallback", "error", "ui_action", "traceback", "warning_payload_policy"),
    ),
    "event": (
        ("path", "applicability", "auth_mode", "credential_state", "event_name"),
        ("decision", "event_class", "fallback", "ui_action", "traceback", "warning_payload_policy"),
    ),
}

EXPECTED_REDACTION = {
    "synthetic_only": True,
    "contains_credentials": False,
    "contains_cookies": False,
    "contains_bearer_values": False,
    "contains_ticket_values": False,
    "contains_raw_pty_bytes": False,
    "contains_transcripts": False,
    "contains_hostnames": False,
    "contains_user_data": False,
    "log_policy": "semantic_class_and_bounded_reason_only",
}
EXPECTED_ACCESSIBILITY = {
    "status": "N/A",
    "reason": "This issue creates a non-UI protocol fixture and standard-library validator; it adds no controls, focus order, semantic names, screen-reader or VoiceOver surface, Switch Control behavior, Dynamic Type or browser zoom layout, contrast, motion, transparency, or touch target.",
    "preservation": "The fixture does not remove downstream web or Apple accessibility obligations; later clients must preserve those checks while showing the blocked compatibility state safely.",
}
EXPECTED_PARITY = {
    "status": "not_run",
    "fixture_source": "one_shared_case_inventory",
    "platforms": list(EXPECTED_PLATFORMS),
    "pty_policy": "web_only_apple_blocked",
    "missing_result_policy": "block",
    "result_equivalence": "semantic_outcome_not_platform_specific_wire_bytes",
}
EXPECTED_STATES = (
    {
        "id": "pending",
        "input_state": "pending",
        "evidence_state": "collection_in_progress",
        "gate_decision": "blocked",
        "safe_state": "no_success_claim",
        "retry_policy": "wait_or_cancel",
    },
    {
        "id": "empty",
        "input_state": "empty",
        "evidence_state": "no_observations",
        "gate_decision": "blocked",
        "safe_state": "no_success_claim",
        "retry_policy": "collect_required_evidence",
    },
    {
        "id": "success",
        "input_state": "complete",
        "evidence_state": "synthetic_fixture_validated",
        "gate_decision": "blocked_live_compatibility",
        "safe_state": "artifact_only_no_live_claim",
        "retry_policy": "not_applicable",
    },
    {
        "id": "failure",
        "input_state": "failed",
        "evidence_state": "required_case_failed",
        "gate_decision": "blocked",
        "safe_state": "retain_failure_evidence",
        "retry_policy": "idempotent_collection_only",
    },
    {
        "id": "cancelled",
        "input_state": "cancelled",
        "evidence_state": "cancelled_before_completion",
        "gate_decision": "blocked",
        "safe_state": "no_outward_change",
        "retry_policy": "resume_after_source_state_reread",
    },
    {
        "id": "unknown",
        "input_state": "unknown",
        "evidence_state": "result_unavailable",
        "gate_decision": "blocked",
        "safe_state": "no_duplicate_prompt_session_ticket_or_pty_input",
        "retry_policy": "reread_source_state_before_retry",
    },
)
EXPECTED_LIFECYCLE = (
    {"id": "input-forwarded-not-replayed", "expected": "forward_input_without_replay_after_reattach", "live_claim": False},
    {"id": "detach-retains-bounded-state", "expected": "close_means_detach_for_attach_mode", "live_claim": False},
    {"id": "ttl-reap-eventual", "expected": "eventual_ttl_reap_without_immediate_kill_or_replay_guarantee", "live_claim": False},
)
EXPECTED_PROXY_MATRIX = (
    {"id": "edge-origin-denial", "case_id": "edge-wrong-public-origin-denied", "variants": ["caddy", "traefik"], "expected_equivalence": "same_edge_denial_without_upstream_call"},
    {"id": "edge-host-denial", "case_id": "edge-unsupported-host-denied", "variants": ["caddy", "traefik"], "expected_equivalence": "same_edge_denial_without_upstream_call"},
    {"id": "upstream-400-preservation", "case_id": "upstream-hermes-400-preserved", "variants": ["caddy", "traefik"], "expected_equivalence": "same_upstream_status_and_mapped_headers"},
    {"id": "upstream-4403-preservation", "case_id": "upstream-hermes-4403-preserved", "variants": ["caddy", "traefik"], "expected_equivalence": "same_upstream_status_and_mapped_headers"},
)

FORBIDDEN_KEYS = frozenset(
    {
        "access_token",
        "authorization",
        "bearer",
        "cookie",
        "credential",
        "credentials",
        "host",
        "hostname",
        "password",
        "prompt",
        "pty_bytes",
        "raw_bearer",
        "raw_cookie",
        "raw_ticket",
        "secret",
        "session_token",
        "ticket",
        "ticket_value",
        "token",
        "transcript",
        "user_data",
    }
)
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b", re.IGNORECASE),
    re.compile(r"\b(?:ghp|github_pat|glpat|sk|xox[baprs])[-_][A-Za-z0-9_-]{8,}\b", re.IGNORECASE),
    # Require a long token-shaped alphabet after Bearer so prose such as
    # "bearer class" is allowed while opaque or JWT-like credentials fail closed.
    re.compile(r"\bBearer\s+(?=[A-Za-z0-9._~+/=-]{20,}\b)[A-Za-z0-9._~+/=-]+\b", re.IGNORECASE),
    re.compile(r"\bBasic\s+[A-Za-z0-9+/=_-]{12,}", re.IGNORECASE),
    re.compile(r"synthetic-(?:api-key|secret|ticket-value|bearer-value|cookie-value|password-value|pty-(?:input|output|handle))", re.IGNORECASE),
)
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ContractError(ValueError):
    """Raised when checked-in behavioral-probe evidence violates the contract."""


class DuplicateKeyError(ValueError):
    """Raised before duplicate JSON keys can hide a fixture mutation."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def strict_keys(value: Any, expected: tuple[str, ...], label: str) -> dict[str, Any]:
    require(type(value) is dict, f"{label} must be an object")
    require(tuple(value.keys()) == expected, f"{label} keys or ordering changed")
    return value


def strict_equal(actual: Any, expected: Any, label: str) -> None:
    require(type(actual) is type(expected), f"{label} type changed")
    if isinstance(expected, dict):
        require(tuple(actual.keys()) == tuple(expected.keys()), f"{label} keys or ordering changed")
        for key, expected_value in expected.items():
            strict_equal(actual[key], expected_value, f"{label}.{key}")
        return
    if isinstance(expected, list):
        require(len(actual) == len(expected), f"{label} length changed")
        for index, (actual_value, expected_value) in enumerate(zip(actual, expected)):
            strict_equal(actual_value, expected_value, f"{label}[{index}]")
        return
    require(actual == expected, f"{label} value changed")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> Any:
    raise ContractError(f"non-finite JSON number is not allowed: {value}")


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as stream:
            value = json.load(
                stream,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonfinite,
            )
    except (DuplicateKeyError, ContractError):
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ContractError(f"cannot load {path}: {exc}") from exc
    require(type(value) is dict, f"{path}: top level must be an object")
    _validate_json_tree(value)
    return value


def _validate_json_tree(value: Any, label: str = "document", depth: int = 0) -> None:
    require(depth <= MAX_JSON_DEPTH, f"{label}: maximum JSON depth exceeded")
    if type(value) is dict:
        for key, child in value.items():
            require(type(key) is str, f"{label}: object key must be text")
            _validate_json_tree(child, f"{label}.{key}", depth + 1)
        return
    if type(value) is list:
        for index, child in enumerate(value):
            _validate_json_tree(child, f"{label}[{index}]", depth + 1)
        return
    if type(value) is float:
        require(math.isfinite(value), f"{label}: non-finite number is not allowed")
        return
    require(value is None or type(value) in (str, bool, int), f"{label}: unsupported JSON value type")


def _validate_redaction(value: Any, label: str = "fixture") -> None:
    if type(value) is dict:
        for key, child in value.items():
            require(type(key) is str, f"{label}: object key must be text")
            normalized = key.casefold().replace("-", "_")
            if not normalized.startswith("contains_"):
                require(normalized not in FORBIDDEN_KEYS, f"{label}.{key}: prohibited sensitive key")
            _validate_redaction(child, f"{label}.{key}")
        return
    if type(value) is list:
        for index, child in enumerate(value):
            _validate_redaction(child, f"{label}[{index}]")
        return
    if type(value) is str:
        require("\x00" not in value, f"{label}: embedded NUL is not allowed")
        for pattern in SECRET_PATTERNS:
            require(pattern.search(value) is None, f"{label}: credential-shaped value")


def _validate_text_redaction(path: Path) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ContractError(f"cannot read redaction evidence {path}: {exc}") from exc
    _validate_redaction(text, str(path))


def _canonical_digest(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _validate_manifest(document: dict[str, Any], repo_root: Path) -> None:
    require(document["route_manifest"] == ROUTE_MANIFEST, "route manifest path changed")
    require(document["route_manifest_sha256"] == ROUTE_MANIFEST_SHA256, "route manifest digest changed")
    try:
        manifest = (repo_root / ROUTE_MANIFEST).resolve(strict=True)
        manifest.relative_to(repo_root.resolve())
    except (OSError, RuntimeError, ValueError) as exc:
        raise ContractError("route manifest is missing or escapes repository root") from exc
    actual = hashlib.sha256(manifest.read_bytes()).hexdigest()
    require(actual == ROUTE_MANIFEST_SHA256, "local route manifest bytes do not match pinned digest")


def _validate_case(case: Any, index: int) -> None:
    label = f"cases[{index}]"
    item = strict_keys(case, CASE_KEYS, label)
    case_id = item["id"]
    require(type(case_id) is str, f"{label}.id must be text")
    require(case_id == EXPECTED_CASE_IDS[index], f"{label}.id/order changed")
    require(item["synthetic"] is True, f"{case_id}: synthetic flag changed")
    require(type(item["kind"]) is str and item["kind"] in {"positive", "negative", "compatibility", "incompatible", "malformed_input", "security"}, f"{case_id}: invalid kind")
    surface = item["surface"]
    require(type(surface) is str and surface in CASE_SHAPES, f"{case_id}: invalid surface")
    request_keys, expected_keys = CASE_SHAPES[surface]
    request = strict_keys(item["request"], request_keys, f"{case_id}.request")
    expected = strict_keys(item["expected"], expected_keys, f"{case_id}.expected")
    require(type(item["notes"]) is str and item["notes"], f"{case_id}.notes must be non-empty text")

    for key, value in request.items():
        require(value is None or type(value) is str, f"{case_id}.request.{key} must be text or null")
    for key, value in expected.items():
        if key in {"http_status", "close_code", "source_status"}:
            require(value is None or (type(value) is int and not isinstance(value, bool)), f"{case_id}.expected.{key} must be integer or null")
        elif key in {"upstream_called", "traceback"}:
            require(type(value) is bool, f"{case_id}.expected.{key} must be boolean")
        else:
            require(value is None or type(value) is str, f"{case_id}.expected.{key} must be text or null")

    if surface in {"rest", "chat_websocket", "pty_websocket", "edge", "json_rpc", "event"}:
        require(request["applicability"] in {"browser", "native"}, f"{case_id}: applicability must be browser or native")
    if surface == "rest":
        require(request["path"].startswith("/api/"), f"{case_id}: REST path is not canonical")
        require(request["origin_policy"] == "approved", f"{case_id}: REST origin policy changed")
    if surface in {"chat_websocket", "pty_websocket"}:
        require(request["path"] in {"/api/ws", "/api/pty"}, f"{case_id}: WebSocket path is not approved")
    if surface == "edge":
        require(request["path"] == "/api/ws", f"{case_id}: edge path changed")
        require(expected["observed_layer"] in {"edge", "upstream"}, f"{case_id}: result layer is not explicit")
        if expected["observed_layer"] == "edge":
            require(expected["upstream_called"] is False and expected["source_status"] is None, f"{case_id}: edge result reached upstream")
        else:
            require(expected["upstream_called"] is True and expected["source_status"] in {400, 4403}, f"{case_id}: upstream result is not preserved")
    if surface == "json_rpc":
        require(request["path"] == "/api/ws", f"{case_id}: JSON-RPC path changed")
    if surface == "event":
        require(request["path"] == "/api/ws", f"{case_id}: event path changed")


def _validate_cases(cases: Any) -> None:
    require(type(cases) is list, "cases must be a list")
    require(len(cases) == len(EXPECTED_CASE_IDS), "case count changed")
    seen: set[str] = set()
    for index, case in enumerate(cases):
        _validate_case(case, index)
        case_id = case["id"]
        require(case_id not in seen, f"duplicate case id: {case_id}")
        seen.add(case_id)
    require(seen == set(EXPECTED_CASE_IDS), "case inventory changed")


def _validate_baseline(baseline: dict[str, Any], repo_root: Path) -> None:
    expected_keys = (
        "schema",
        "fixture_schema",
        "validator",
        "synthetic_only",
        "build_mode",
        "threshold",
        "environment",
        "normal",
        "optimized",
        "artifact_paths",
        "artifact_size_bytes",
        "trace_artifact",
    )
    strict_keys(baseline, expected_keys, "baseline")
    require(baseline["schema"] == "hermternal.behavioral-probe-baseline.v1", "baseline schema changed")
    require(baseline["fixture_schema"] == SCHEMA, "baseline fixture binding changed")
    require(baseline["validator"] == "Python standard library only", "baseline validator changed")
    require(baseline["synthetic_only"] is True, "baseline synthetic flag changed")
    require(baseline["build_mode"] == "N/A — no production or release executable", "baseline build mode changed")
    require(baseline["threshold"] is None, "baseline must not invent a threshold")
    environment = strict_keys(baseline["environment"], ("python", "implementation", "platform", "machine"), "baseline.environment")
    for key, value in environment.items():
        require(type(value) is str and value and value != "pending", f"baseline.environment.{key} is missing")

    artifact_paths = baseline["artifact_paths"]
    require(type(artifact_paths) is list and tuple(artifact_paths) == ("README.md", "probe-fixtures.json", "validate.py", "test_validate.py"), "baseline artifact paths changed")
    expected_size = sum((ROOT / relative).stat().st_size for relative in artifact_paths)
    require(type(baseline["artifact_size_bytes"]) is int and baseline["artifact_size_bytes"] == expected_size, "baseline artifact size is stale")
    require(baseline["trace_artifact"] == "local_command_output_only", "baseline trace policy changed")

    for mode in ("normal", "optimized"):
        sample_set = strict_keys(baseline[mode], ("command", "repetitions", "samples_ms", "distribution_ms"), f"baseline.{mode}")
        expected_command = f"python3 {'-O ' if mode == 'optimized' else ''}contracts/fixtures/behavioral-probe/validate.py"
        require(sample_set["command"] == expected_command, f"baseline.{mode}.command changed")
        require(type(sample_set["repetitions"]) is int and not isinstance(sample_set["repetitions"], bool) and sample_set["repetitions"] == BASELINE_REPETITIONS, f"baseline.{mode}.repetitions changed")
        samples = sample_set["samples_ms"]
        require(type(samples) is list and len(samples) == BASELINE_REPETITIONS, f"baseline.{mode}.samples_ms count changed")
        for sample in samples:
            require(type(sample) in (int, float) and not isinstance(sample, bool) and math.isfinite(sample) and sample >= 0, f"baseline.{mode}.samples_ms contains invalid value")
        distribution = strict_keys(sample_set["distribution_ms"], ("min", "p50", "p95", "max", "mean"), f"baseline.{mode}.distribution_ms")
        for value in distribution.values():
            require(type(value) in (int, float) and not isinstance(value, bool) and math.isfinite(value) and value >= 0, f"baseline.{mode}.distribution_ms contains invalid value")
        ordered = sorted(samples)
        p50 = ordered[min(len(ordered) - 1, max(0, math.ceil(0.50 * len(ordered)) - 1))]
        p95 = ordered[min(len(ordered) - 1, max(0, math.ceil(0.95 * len(ordered)) - 1))]
        require(abs(distribution["min"] - min(samples)) < 0.001, f"baseline.{mode}.minimum does not match samples")
        require(abs(distribution["p50"] - p50) < 0.001, f"baseline.{mode}.p50 does not match samples")
        require(abs(distribution["p95"] - p95) < 0.001, f"baseline.{mode}.p95 does not match samples")
        require(abs(distribution["max"] - max(samples)) < 0.001, f"baseline.{mode}.maximum does not match samples")
        require(abs(distribution["mean"] - statistics.mean(samples)) < 0.001, f"baseline.{mode}.mean does not match samples")
        require(distribution["min"] <= distribution["p50"] <= distribution["p95"] <= distribution["max"], f"baseline.{mode} quantiles are incoherent")


def validate_document(document: dict[str, Any], repo_root: Path = REPO_ROOT, *, verify_digest: bool = True) -> None:
    strict_keys(document, ROOT_KEYS, "fixture")
    require(document["schema"] == SCHEMA, "fixture schema changed")
    require(document["contract"] == CONTRACT, "fixture contract changed")
    require(document["hermes_source_sha"] == HERMES_SOURCE_SHA and HEX40.fullmatch(document["hermes_source_sha"]) is not None, "Hermes source pin changed")
    require(document["synthetic_only"] is True, "fixture must remain synthetic")
    _validate_manifest(document, repo_root)

    probe = strict_keys(document["probe"], PROBE_KEYS, "probe")
    require(probe["id"] == "c-04a-behavioral-compatibility", "probe id changed")
    require(probe["mode"] == "offline_synthetic_contract", "probe mode changed")
    require(probe["live_run"] is False and probe["compatible"] is False, "fixture cannot claim live compatibility")
    require(probe["unknown_result_policy"] == "block_and_reread_source_state", "unknown result policy changed")
    require(probe["retry_policy"] == "retry_idempotent_collection_only_after_safe_state_reread", "retry policy changed")
    require(probe["required_case_count"] == len(EXPECTED_CASE_IDS), "required case count changed")
    require(probe["required_state_count"] == len(EXPECTED_STATE_IDS), "required state count changed")
    require(probe["required_lifecycle_count"] == len(EXPECTED_LIFECYCLE_IDS), "required lifecycle count changed")
    require(probe["required_proxy_pair_count"] == len(EXPECTED_PROXY_IDS), "required proxy pair count changed")

    proof = strict_keys(document["proof_run"], PROOF_RUN_KEYS, "proof_run")
    strict_equal(proof, {"status": "not_run", "attestation_state": "absent", "proxy_variants": ["caddy", "traefik"], "host_class": "synthetic_only", "tool_versions": "not_recorded", "live_result": "not_recorded"}, "proof_run")
    require(tuple(document["evidence_requirements"]) == EXPECTED_EVIDENCE_REQUIREMENTS, "evidence requirements changed")

    proxy_matrix = document["proxy_matrix"]
    require(type(proxy_matrix) is list and tuple(item.get("id") for item in proxy_matrix) == EXPECTED_PROXY_IDS, "proxy matrix inventory changed")
    for index, item in enumerate(proxy_matrix):
        strict_keys(item, PROXY_KEYS, f"proxy_matrix[{index}]")
        strict_equal(item, EXPECTED_PROXY_MATRIX[index], f"proxy_matrix[{index}]")

    parity = strict_keys(document["parity"], PARITY_KEYS, "parity")
    strict_equal(parity, EXPECTED_PARITY, "parity")
    require(tuple(parity["platforms"]) == EXPECTED_PLATFORMS, "parity platforms changed")

    states = document["probe_states"]
    require(type(states) is list and tuple(item.get("id") for item in states) == EXPECTED_STATE_IDS, "probe state inventory changed")
    for index, state in enumerate(states):
        strict_keys(state, STATE_KEYS, f"probe_states[{index}]")
        strict_equal(state, EXPECTED_STATES[index], f"probe_states[{index}]")

    lifecycle = document["pty_lifecycle"]
    require(type(lifecycle) is list and tuple(item.get("id") for item in lifecycle) == EXPECTED_LIFECYCLE_IDS, "PTY lifecycle inventory changed")
    for index, item in enumerate(lifecycle):
        strict_keys(item, LIFECYCLE_KEYS, f"pty_lifecycle[{index}]")
        strict_equal(item, EXPECTED_LIFECYCLE[index], f"pty_lifecycle[{index}]")

    _validate_cases(document["cases"])
    strict_equal(document["redaction"], EXPECTED_REDACTION, "redaction")
    strict_equal(document["accessibility"], EXPECTED_ACCESSIBILITY, "accessibility")
    _validate_redaction(document)
    if verify_digest:
        require(_canonical_digest(document) == EXPECTED_FIXTURE_CANONICAL_SHA256, "fixture canonical digest changed")


def validate_baseline(baseline: dict[str, Any], repo_root: Path = REPO_ROOT) -> None:
    _validate_redaction(baseline, "baseline")
    _validate_baseline(baseline, repo_root)


def validate_all(
    document: dict[str, Any],
    baseline: dict[str, Any],
    repo_root: Path = REPO_ROOT,
    *,
    verify_digest: bool = True,
) -> None:
    validate_document(document, repo_root, verify_digest=verify_digest)
    validate_baseline(baseline, repo_root)
    _validate_text_redaction(ROOT / "README.md")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, default=FIXTURE_PATH)
    parser.add_argument("--baseline", type=Path, default=BASELINE_PATH)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)
    try:
        document = load_json(args.fixtures.resolve())
        baseline = load_json(args.baseline.resolve())
        validate_all(document, baseline, args.repo_root.resolve())
    except (ContractError, DuplicateKeyError, OSError, UnicodeError, TypeError, ValueError) as exc:
        print(json.dumps({"ok": False, "compatible": False, "live_run": False, "error": {"code": "behavioral_probe_fixture_invalid", "message": str(exc) or exc.__class__.__name__}}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, "compatible": False, "live_run": False, "case_count": len(document["cases"]), "state_count": len(document["probe_states"]), "proxy_pair_count": len(document["proxy_matrix"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
