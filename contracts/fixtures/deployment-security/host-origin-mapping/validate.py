#!/usr/bin/env python3
"""Validate the offline DEP-03 Host and Origin mapping proof.

The model intentionally uses semantic input classes instead of retaining hostile
header bytes. The edge decision is recomputed here so a fixture cannot authorize
itself by changing expected output beside changed request input.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import re
import sys
from typing import Any

ROOT = Path(__file__).resolve().parent
CASES_PATH = ROOT / "cases.json"
BASELINE_PATH = ROOT / "validation-baseline.json"
ARTIFACT_FILES = ("README.md", "cases.json", "validate.py", "test_validate.py")
MAX_INPUT_BYTES = 256_000
MAX_DEPTH = 16
MAX_NODES = 10_000
MAX_STRING = 4_096
MAX_ARRAY = 128
MAX_OBJECT = 64
FAILURE_LIMIT = 240
PINNED_CASES_SHA256 = "b40ed43df37646d8036fd891eb7ee27aff5978bf812dddfcdc32463d80009ac9"
PINNED_BASELINE_SHA256 = "bcfc10820ff7c3dd9724212104dc1d2376035741012e35b6db3128cbd02bb194"

ROOT_KEYS = (
    "schema",
    "fixture_id",
    "issue",
    "contract",
    "hermes_source_sha",
    "synthetic_only",
    "live_claim",
    "proof_mode",
    "mapping",
    "policy",
    "evidence_contract",
    "cases",
)
MAPPING_KEYS = (
    "configured_public_scheme",
    "configured_public_host",
    "configured_public_origin",
    "hermes_bound_authority",
    "hermes_required_origin",
    "mapping_source",
    "request_values_never_select_upstream",
)
POLICY_KEYS = (
    "route",
    "method",
    "transport",
    "host_rejection_status",
    "origin_rejection_status",
    "host_precedes_origin",
    "rejection_upstream_called",
    "accepted_action",
)
EVIDENCE_KEYS = (
    "retained_fields",
    "forbidden_retained_classes",
    "maximum_failure_line_characters",
    "maximum_retained_evidence_bytes",
    "failure_output",
)
CASE_KEYS = ("id", "request", "expected")
REQUEST_KEYS = ("public_host", "public_origin", "upstream_override")
EXPECTED_KEYS = (
    "decision",
    "status",
    "responding_layer",
    "upstream_called",
    "public_host_result",
    "public_origin_result",
    "mapped_host_marker",
    "mapped_origin_marker",
)
RETAINED_FIELDS = (
    "case_id",
    "decision",
    "responding_layer",
    "upstream_called",
    "public_host_result",
    "public_origin_result",
    "mapped_host_marker",
    "mapped_origin_marker",
)
EXPECTED_CASE_IDS = (
    "accept-exact-browser-mapping",
    "reject-mismatched-host",
    "reject-hostile-host-syntax",
    "reject-missing-host",
    "reject-mismatched-origin",
    "reject-hostile-origin-syntax",
    "reject-null-origin",
    "reject-wildcard-origin",
    "reject-missing-browser-origin",
    "reject-request-host-override",
    "reject-request-origin-override",
    "reject-host-and-origin-before-mapping",
)
EXPECTED_MAPPING = {
    "configured_public_scheme": "https",
    "configured_public_host": "configured_public_host",
    "configured_public_origin": "configured_public_https_origin",
    "hermes_bound_authority": "fixed_private_non_loopback_9119",
    "hermes_required_origin": "mapped_private_http_origin",
    "mapping_source": "trusted_edge_configuration_only",
    "request_values_never_select_upstream": True,
}
EXPECTED_POLICY = {
    "route": "/hermes/api/ws",
    "method": "GET",
    "transport": "websocket",
    "host_rejection_status": 421,
    "origin_rejection_status": 403,
    "host_precedes_origin": True,
    "rejection_upstream_called": False,
    "accepted_action": "forward_with_configured_mapping",
}
EXPECTED_EVIDENCE = {
    "retained_fields": list(RETAINED_FIELDS),
    "forbidden_retained_classes": [
        "raw_header_values",
        "credentials",
        "cookies",
        "bearer_values",
        "ticket_values",
        "live_hosts",
        "private_addresses",
        "user_data",
        "transcripts",
    ],
    "maximum_failure_line_characters": 240,
    "maximum_retained_evidence_bytes": 4096,
    "failure_output": "one_bounded_semantic_json_line",
}
HOST_RESULTS = {
    "exact_configured": "accepted_exact",
    "mismatched_public_host": "rejected_mismatch",
    "hostile_host_syntax": "rejected_hostile",
    "missing": "rejected_missing",
}
ORIGIN_RESULTS = {
    "exact_configured_https": "accepted_exact",
    "mismatched_public_origin": "rejected_mismatch",
    "hostile_origin_syntax": "rejected_hostile",
    "null_origin": "rejected_null",
    "wildcard_origin": "rejected_wildcard",
    "missing": "rejected_missing",
}
OVERRIDE_STATES = {
    "absent",
    "request_supplied_host",
    "request_supplied_origin",
    "request_supplied_both",
}

SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)(?:password|passwd|secret|token|ticket|cookie|authorization|api[_-]?key)\s*[:=]\s*\S+"
)
CREDENTIAL_HEADER = re.compile(r"(?i)\b(?:basic|bearer)\s+[A-Za-z0-9._~+/-]{4,}")
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
IPV4 = re.compile(r"(?<![A-Za-z0-9_])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9_])")
EMAIL = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
LIVE_URL = re.compile(r"(?i)\b(?:https?|wss?)://")
HOSTNAME = re.compile(r"(?i)(?<![A-Za-z0-9_])(?:[a-z0-9-]+\.)+(?:com|net|org|io|dev|app|local)(?::\d{1,5})?(?![A-Za-z0-9_])")
ABSOLUTE_PATH = re.compile(r"(?:^|[\s'\"])(?:/[A-Za-z0-9._-]+){2,}(?:/|\b)")


class ValidationError(Exception):
    """A bounded semantic contract failure."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def exact_keys(value: Any, expected: tuple[str, ...], label: str) -> dict[str, Any]:
    require(type(value) is dict, f"{label} must be an object")
    require(tuple(value) == expected, f"{label} keys changed")
    return value


def strict_equal(actual: Any, expected: Any, label: str) -> None:
    require(type(actual) is type(expected) and actual == expected, f"{label} changed")


def no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("JSON contains a duplicate object key")
        result[key] = value
    return result


def reject_constant(_: str) -> None:
    raise ValidationError("JSON contains a non-finite number")


def reject_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValidationError("JSON contains a non-finite number")
    return parsed


def reject_int(value: str) -> int:
    if len(value.lstrip("-")) > 18:
        raise ValidationError("JSON integer literal is too large")
    return int(value)


def inspect_shape(value: Any) -> None:
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        require(nodes <= MAX_NODES, "JSON node limit exceeded")
        require(depth <= MAX_DEPTH, "JSON nesting limit exceeded")
        if type(current) is str:
            require(len(current) <= MAX_STRING, "JSON string limit exceeded")
            require(not any(ord(char) < 32 for char in current), "JSON string contains a control character")
        elif type(current) is list:
            require(len(current) <= MAX_ARRAY, "JSON array limit exceeded")
            stack.extend((item, depth + 1) for item in current)
        elif type(current) is dict:
            require(len(current) <= MAX_OBJECT, "JSON object limit exceeded")
            for key, item in current.items():
                require(type(key) is str, "JSON object key must be text")
                require(len(key) <= MAX_STRING, "JSON key limit exceeded")
                require(not any(ord(char) < 32 for char in key), "JSON key contains a control character")
                stack.append((item, depth + 1))
        else:
            require(current is None or type(current) in (bool, int, float), "JSON scalar type is unsupported")


def load_json(path: Path) -> tuple[Any, bytes]:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise ValidationError("required JSON artifact is unavailable") from exc
    require(len(payload) <= MAX_INPUT_BYTES, "JSON artifact byte limit exceeded")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError("JSON artifact is not valid UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=no_duplicate_keys,
            parse_constant=reject_constant,
            parse_float=reject_float,
            parse_int=reject_int,
        )
    except ValidationError:
        raise
    except (ValueError, RecursionError) as exc:
        raise ValidationError("JSON artifact is malformed") from exc
    inspect_shape(value)
    return value, payload


def scan_text(value: str, *, structural: bool = False) -> None:
    require(not SENSITIVE_ASSIGNMENT.search(value), "retained data contains sensitive assignment material")
    require(not CREDENTIAL_HEADER.search(value), "retained data contains credential header material")
    require(not PRIVATE_KEY.search(value), "retained data contains private key material")
    require(not LIVE_URL.search(value), "retained data contains a live URL")
    require(not IPV4.search(value), "retained data contains an IP address")
    require(not EMAIL.search(value), "retained data contains an email address")
    require(not HOSTNAME.search(value), "retained data contains a hostname")
    if not structural:
        require(not ABSOLUTE_PATH.search(value), "retained data contains a filesystem path")


def scan_tree(value: Any, *, structural_values: set[str] | None = None) -> None:
    structural_values = structural_values or set()
    stack = [value]
    while stack:
        current = stack.pop()
        if type(current) is str:
            scan_text(current, structural=current in structural_values)
        elif type(current) is list:
            stack.extend(current)
        elif type(current) is dict:
            for key, item in current.items():
                scan_text(key)
                stack.append(item)


def evaluate_case(case: dict[str, Any]) -> dict[str, Any]:
    request = exact_keys(case["request"], REQUEST_KEYS, "case request")
    host_state = request["public_host"]
    origin_state = request["public_origin"]
    override_state = request["upstream_override"]
    require(type(host_state) is str and host_state in HOST_RESULTS, "public Host classification is unsupported")
    require(type(origin_state) is str and origin_state in ORIGIN_RESULTS, "public Origin classification is unsupported")
    require(type(override_state) is str and override_state in OVERRIDE_STATES, "upstream override classification is unsupported")

    host_result = HOST_RESULTS[host_state]
    if host_result != "accepted_exact":
        return {
            "decision": "reject_public_host",
            "status": 421,
            "responding_layer": "edge",
            "upstream_called": False,
            "public_host_result": host_result,
            "public_origin_result": "not_evaluated",
            "mapped_host_marker": None,
            "mapped_origin_marker": None,
        }

    origin_result = ORIGIN_RESULTS[origin_state]
    if origin_result != "accepted_exact":
        return {
            "decision": "reject_public_origin",
            "status": 403,
            "responding_layer": "edge",
            "upstream_called": False,
            "public_host_result": host_result,
            "public_origin_result": origin_result,
            "mapped_host_marker": None,
            "mapped_origin_marker": None,
        }

    if override_state != "absent":
        status = 421 if override_state in ("request_supplied_host", "request_supplied_both") else 403
        return {
            "decision": "reject_upstream_override",
            "status": status,
            "responding_layer": "edge",
            "upstream_called": False,
            "public_host_result": host_result,
            "public_origin_result": origin_result,
            "mapped_host_marker": None,
            "mapped_origin_marker": None,
        }

    return {
        "decision": "forward_with_configured_mapping",
        "status": None,
        "responding_layer": "upstream",
        "upstream_called": True,
        "public_host_result": host_result,
        "public_origin_result": origin_result,
        "mapped_host_marker": EXPECTED_MAPPING["hermes_bound_authority"],
        "mapped_origin_marker": EXPECTED_MAPPING["hermes_required_origin"],
    }


def validate_document(root: Any) -> list[dict[str, Any]]:
    document = exact_keys(root, ROOT_KEYS, "fixture root")
    strict_equal(document["schema"], "hermternal.deployment.host-origin-mapping.v1", "fixture schema")
    strict_equal(document["fixture_id"], "host-origin-mapping-dep-03-f5be9236", "fixture id")
    strict_equal(document["issue"], "DEP-03", "fixture issue")
    strict_equal(document["contract"], "dashboard-v0.0.1", "fixture contract")
    strict_equal(document["hermes_source_sha"], "f5be9236e00ddf2f2a412697f267078fc4ee068e", "Hermes source pin")
    strict_equal(document["synthetic_only"], True, "synthetic-only flag")
    strict_equal(document["live_claim"], False, "live-claim flag")
    strict_equal(document["proof_mode"], "offline_disposable_mapping_model", "proof mode")
    mapping = exact_keys(document["mapping"], MAPPING_KEYS, "mapping")
    policy = exact_keys(document["policy"], POLICY_KEYS, "policy")
    evidence_contract = exact_keys(document["evidence_contract"], EVIDENCE_KEYS, "evidence contract")
    strict_equal(mapping, EXPECTED_MAPPING, "mapping contract")
    strict_equal(policy, EXPECTED_POLICY, "edge policy")
    strict_equal(evidence_contract, EXPECTED_EVIDENCE, "evidence contract")

    cases = document["cases"]
    require(type(cases) is list and len(cases) == len(EXPECTED_CASE_IDS), "case inventory changed")
    retained: list[dict[str, Any]] = []
    for index, raw_case in enumerate(cases):
        case = exact_keys(raw_case, CASE_KEYS, "case")
        strict_equal(case["id"], EXPECTED_CASE_IDS[index], "case id or order")
        expected = exact_keys(case["expected"], EXPECTED_KEYS, "case expected result")
        computed = evaluate_case(case)
        strict_equal(expected, computed, "computed case outcome")
        retained.append(
            {
                "case_id": case["id"],
                "decision": computed["decision"],
                "responding_layer": computed["responding_layer"],
                "upstream_called": computed["upstream_called"],
                "public_host_result": computed["public_host_result"],
                "public_origin_result": computed["public_origin_result"],
                "mapped_host_marker": computed["mapped_host_marker"],
                "mapped_origin_marker": computed["mapped_origin_marker"],
            }
        )

    require(any(item["upstream_called"] for item in retained), "accepted mapping evidence is missing")
    require(all(not item["upstream_called"] for item in retained[1:]), "rejection reached upstream")
    accepted = retained[0]
    strict_equal(accepted["mapped_host_marker"], EXPECTED_MAPPING["hermes_bound_authority"], "accepted mapped Host")
    strict_equal(accepted["mapped_origin_marker"], EXPECTED_MAPPING["hermes_required_origin"], "accepted mapped Origin")
    for item in retained[1:]:
        require(item["mapped_host_marker"] is None and item["mapped_origin_marker"] is None, "rejection retained mapped values")

    retained_bytes = json.dumps(retained, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    require(len(retained_bytes) <= EXPECTED_EVIDENCE["maximum_retained_evidence_bytes"], "retained evidence byte limit exceeded")
    scan_tree(
        document,
        structural_values={EXPECTED_POLICY["route"]},
    )
    scan_tree(retained)
    return retained


def normalized_artifact_bytes(path: Path) -> bytes:
    payload = path.read_bytes()
    if path.name == "validate.py":
        text = payload.decode("utf-8")
        text = re.sub(
            r'PINNED_CASES_SHA256 = "[^"]+"',
            'PINNED_CASES_SHA256 = "<normalized-cases-pin>"',
            text,
            count=1,
        )
        text = re.sub(
            r'PINNED_BASELINE_SHA256 = "[^"]+"',
            'PINNED_BASELINE_SHA256 = "<normalized-baseline-pin>"',
            text,
            count=1,
        )
        payload = text.encode("utf-8")
    return payload


def artifact_manifest() -> dict[str, Any]:
    digest = hashlib.sha256()
    files: list[dict[str, Any]] = []
    total = 0
    for name in sorted(ARTIFACT_FILES):
        path = ROOT / name
        try:
            raw = path.read_bytes()
            normalized = normalized_artifact_bytes(path)
        except OSError as exc:
            raise ValidationError("retained proof artifact is unavailable") from exc
        total += len(raw)
        file_digest = hashlib.sha256(normalized).hexdigest()
        files.append({"path": name, "bytes": len(raw), "sha256": file_digest})
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(normalized)
        digest.update(b"\0")
    return {"files": files, "bytes": total, "sha256": digest.hexdigest()}


def percentile(samples: list[float], fraction: float) -> float:
    ordered = sorted(samples)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def distribution(samples: list[float]) -> dict[str, float]:
    return {
        "min": min(samples),
        "p50": percentile(samples, 0.50),
        "p95": percentile(samples, 0.95),
        "p99": percentile(samples, 0.99),
        "max": max(samples),
        "mean": sum(samples) / len(samples),
    }


def validate_baseline(root: Any, payload: bytes) -> None:
    require(hashlib.sha256(payload).hexdigest() == PINNED_BASELINE_SHA256, "benchmark evidence identity changed")
    baseline = exact_keys(
        root,
        ("schema", "fixture_id", "samples_per_mode", "unit", "threshold", "environment", "commands", "normal", "optimized", "artifact"),
        "benchmark root",
    )
    strict_equal(baseline["schema"], "hermternal.validation-baseline.v1", "benchmark schema")
    strict_equal(baseline["fixture_id"], "host-origin-mapping-dep-03-f5be9236", "benchmark fixture id")
    strict_equal(baseline["samples_per_mode"], 30, "benchmark sample count")
    strict_equal(baseline["unit"], "seconds", "benchmark unit")
    require(baseline["threshold"] is None, "benchmark threshold must remain null")
    environment = exact_keys(baseline["environment"], ("platform", "python", "machine"), "benchmark environment")
    require(all(type(value) is str and 1 <= len(value) <= 160 for value in environment.values()), "benchmark environment is invalid")
    commands = exact_keys(baseline["commands"], ("normal", "optimized"), "benchmark commands")
    strict_equal(commands["normal"], "python3 contracts/fixtures/deployment-security/host-origin-mapping/validate.py --skip-baseline", "normal benchmark command")
    strict_equal(commands["optimized"], "python3 -O contracts/fixtures/deployment-security/host-origin-mapping/validate.py --skip-baseline", "optimized benchmark command")
    for mode in ("normal", "optimized"):
        evidence = exact_keys(baseline[mode], ("samples", "distribution"), f"{mode} benchmark evidence")
        samples = evidence["samples"]
        require(type(samples) is list and len(samples) == 30, f"{mode} sample count changed")
        require(all(type(sample) is float and 0 < sample < 60 for sample in samples), f"{mode} samples are invalid")
        expected_distribution = distribution(samples)
        actual_distribution = exact_keys(evidence["distribution"], ("min", "p50", "p95", "p99", "max", "mean"), f"{mode} distribution")
        for key, expected in expected_distribution.items():
            require(type(actual_distribution[key]) is float and abs(actual_distribution[key] - expected) <= 1e-12, f"{mode} distribution changed")
    strict_equal(baseline["artifact"], artifact_manifest(), "benchmark artifact manifest")
    scan_tree(baseline, structural_values=set(ARTIFACT_FILES) | set(commands.values()))


def validate(cases_path: Path = CASES_PATH, *, skip_baseline: bool = False) -> list[dict[str, Any]]:
    root, cases_payload = load_json(cases_path)
    if cases_path.resolve() == CASES_PATH.resolve():
        require(hashlib.sha256(cases_payload).hexdigest() == PINNED_CASES_SHA256, "fixture identity changed")
    retained = validate_document(root)
    if not skip_baseline:
        baseline, baseline_payload = load_json(BASELINE_PATH)
        validate_baseline(baseline, baseline_payload)
    return retained


def parse_cli(argv: list[str]) -> tuple[Path, bool]:
    cases_path = CASES_PATH
    skip_baseline = False
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument == "--skip-baseline":
            require(not skip_baseline, "CLI option repeated")
            skip_baseline = True
            index += 1
        elif argument == "--cases":
            require(index + 1 < len(argv), "CLI cases input is missing")
            require(cases_path == CASES_PATH, "CLI option repeated")
            cases_path = Path(argv[index + 1])
            index += 2
        else:
            raise ValidationError("CLI option is unsupported")
    return cases_path, skip_baseline


def bounded_failure(message: str) -> str:
    safe = message if message in {
        "required JSON artifact is unavailable",
        "JSON artifact byte limit exceeded",
        "JSON artifact is not valid UTF-8",
        "JSON artifact is malformed",
        "JSON contains a duplicate object key",
        "JSON contains a non-finite number",
        "JSON integer literal is too large",
        "JSON node limit exceeded",
        "JSON nesting limit exceeded",
        "JSON string limit exceeded",
        "JSON array limit exceeded",
        "JSON object limit exceeded",
        "JSON string contains a control character",
        "JSON key contains a control character",
        "CLI option repeated",
        "CLI cases input is missing",
        "CLI option is unsupported",
    } else message
    line = json.dumps({"status": "failure", "reason": safe}, separators=(",", ":"), ensure_ascii=True)
    if len(line) > FAILURE_LIMIT:
        line = json.dumps({"status": "failure", "reason": "validation failed"}, separators=(",", ":"))
    return line


def main(argv: list[str] | None = None) -> int:
    try:
        cases_path, skip_baseline = parse_cli(list(sys.argv[1:] if argv is None else argv))
        retained = validate(cases_path, skip_baseline=skip_baseline)
        result = {
            "status": "ok",
            "fixture_id": "host-origin-mapping-dep-03-f5be9236",
            "cases": len(retained),
            "accepted": sum(1 for item in retained if item["upstream_called"]),
            "rejected": sum(1 for item in retained if not item["upstream_called"]),
            "synthetic_only": True,
            "live_claim": False,
        }
        print(json.dumps(result, separators=(",", ":"), ensure_ascii=True))
        return 0
    except (ValidationError, OSError) as exc:
        print(bounded_failure(str(exc)))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
