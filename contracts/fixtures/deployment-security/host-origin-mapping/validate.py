#!/usr/bin/env python3
"""Validate the offline DEP-03 raw Host and Origin mapping proof.

Raw synthetic request values are classified here, independently from fixture
expectations. Retained evidence contains only bounded semantic results; the raw
scheme, Host, Origin, and override values never enter output evidence.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import re
import sys
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
CASES_PATH = ROOT / "cases.json"
BASELINE_PATH = ROOT / "validation-baseline.json"
ARTIFACT_FILES = ("README.md", "cases.json", "test_validate.py", "validate.py", "validation-baseline.json")
BENCHMARK_SOURCE_FILES = ("README.md", "cases.json", "test_validate.py", "validate.py")
MAX_INPUT_BYTES = 256_000
MAX_DEPTH = 16
MAX_NODES = 20_000
MAX_STRING = 8_192
MAX_ARRAY = 256
MAX_OBJECT = 80
FAILURE_LIMIT = 240
PINNED_CASES_SHA256 = "0add954ec72a8d0b0dd16fa384e909ef16f930372e5fae80a0ff98339fb7d9fa"
PINNED_BASELINE_SHA256 = "0f1d9523c06896da7f796ce540d3bd85de2828445ba11d3a36db36facc09f16d"
PINNED_SEMANTICS_SHA256 = "0e26c71d426d0f7c1018afed7f22531bcc9c9fce4889f18aeefe14d7e2da457e"

ROOT_KEYS = ("schema", "fixture_id", "issue", "contract", "hermes_source_sha", "synthetic_only", "live_claim", "proof_mode", "mapping", "policy", "evidence_contract", "cases")
MAPPING_KEYS = ("configured_public_scheme", "configured_public_host", "configured_public_origin", "hermes_bound_authority", "hermes_required_origin", "mapping_source", "request_values_never_select_upstream")
POLICY_KEYS = ("route", "method", "transport", "host_rejection_status", "origin_rejection_status", "host_precedes_origin", "rejection_upstream_called", "accepted_action")
EVIDENCE_KEYS = ("retained_fields", "forbidden_retained_classes", "structural_exemptions", "maximum_failure_line_characters", "maximum_retained_evidence_bytes", "failure_output")
CASE_KEYS = ("id", "request", "expected")
REQUEST_KEYS = ("scheme", "host_values", "origin_values", "upstream_host_override", "upstream_origin_override")
EXPECTED_KEYS = ("decision", "status", "responding_layer", "upstream_called", "public_scheme_result", "public_host_result", "public_origin_result", "mapped_host_marker", "mapped_origin_marker")
RETAINED_FIELDS = ("case_id", "decision", "responding_layer", "upstream_called", "public_scheme_result", "public_host_result", "public_origin_result", "mapped_host_marker", "mapped_origin_marker")

EXPECTED_MAPPING = {
    "configured_public_scheme": "https",
    "configured_public_host": "chat.public.invalid",
    "configured_public_origin": "https://chat.public.invalid",
    "hermes_bound_authority": "fixed_private_non_loopback_9119",
    "hermes_required_origin": "mapped_private_http_origin",
    "mapping_source": "trusted_edge_configuration_only",
    "request_values_never_select_upstream": True,
}
EXPECTED_POLICY = {
    "route": "/hermes/api/ws", "method": "GET", "transport": "websocket",
    "host_rejection_status": 421, "origin_rejection_status": 403,
    "host_precedes_origin": True, "rejection_upstream_called": False,
    "accepted_action": "forward_with_configured_mapping",
}
EXPECTED_EVIDENCE = {
    "retained_fields": list(RETAINED_FIELDS),
    "forbidden_retained_classes": ["raw_request_values", "credentials", "cookies", "bearer_values", "ticket_values", "live_hosts", "private_addresses", "filesystem_paths", "user_data", "transcripts"],
    "structural_exemptions": ["reserved_invalid_fixture_authorities", "exact_validator_command_paths", "exact_artifact_filenames", "reviewed_route_path"],
    "maximum_failure_line_characters": 240, "maximum_retained_evidence_bytes": 12288,
    "failure_output": "one_bounded_semantic_json_line",
}
EXPECTED_CASE_IDS = (
    "accept-exact-browser-mapping", "reject-http-scheme", "reject-scheme-case", "reject-missing-scheme",
    "reject-host-port", "reject-host-case", "reject-host-trailing-dot", "reject-host-multiple-values",
    "reject-host-leading-whitespace", "reject-host-trailing-whitespace", "reject-host-userinfo",
    "reject-host-scheme-prefix", "reject-host-empty-label", "reject-host-missing", "reject-origin-http",
    "reject-origin-port", "reject-origin-host-case", "reject-origin-scheme-case", "reject-origin-trailing-dot",
    "reject-origin-trailing-slash", "reject-origin-multiple-values", "reject-origin-leading-whitespace",
    "reject-origin-trailing-whitespace", "reject-origin-userinfo", "reject-origin-query", "reject-origin-null",
    "reject-origin-wildcard", "reject-origin-missing", "reject-host-override", "reject-origin-override",
    "reject-both-overrides", "reject-host-before-hostile-origin-and-overrides",
)

# Exact RFC 2606 `.invalid` values are the only host-shaped strings allowed in
# this synthetic raw-input proof. They cannot resolve and are replaced before
# generic retained-artifact host and URL detection.
STRUCTURAL_HOSTS = ("chat.public.invalid", "chat.public.invalid.", "other.public.invalid", "attacker.private.invalid", "CHAT.PUBLIC.INVALID", "chat..public.invalid")
STRUCTURAL_URLS = (
    "https://chat.public.invalid", "http://chat.public.invalid", "https://CHAT.PUBLIC.INVALID",
    "HTTPS://chat.public.invalid", "https://chat.public.invalid.", "https://chat.public.invalid/",
    "https://other.public.invalid", "https://user@chat.public.invalid", "http://attacker.private.invalid",
)
STRUCTURAL_PATHS = ("/hermes/api/ws",)

SENSITIVE_ASSIGNMENT = re.compile(r"(?i)(?:password|passwd|secret|token|ticket|cookie|authorization|api[_-]?key)\s*[:=]\s*[^\s,;}]+")
CREDENTIAL_HEADER = re.compile(r"(?i)\bauthorization\s*:\s*(?:basic|bearer)\s+[A-Za-z0-9._~+/-]{4,}")
COOKIE_HEADER = re.compile(r"(?i)\bcookie\s*:\s*[^\s,;}]+")
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
IPV4 = re.compile(r"(?<![A-Za-z0-9_])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9_])")
IPV6 = re.compile(r"(?i)(?<![A-Za-z0-9_])(?:[0-9a-f]{0,4}:){2,}[0-9a-f:]{0,4}(?![A-Za-z0-9_])")
EMAIL = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
LIVE_URL = re.compile(r"(?i)\b(?:https?|wss?)://[^\s'\"<>)]+")
HOSTNAME = re.compile(r"(?i)(?<![A-Za-z0-9_])(?:[a-z0-9-]+\.)+(?:com|net|org|io|dev|app|local|invalid)(?::\d{1,5})?(?![A-Za-z0-9_])")
ABSOLUTE_PATH = re.compile(r"(?:^|[\s'\"=])(?:/(?:tmp|private|Users|home|var|etc|opt|root)(?:/[A-Za-z0-9._-]+)+)")


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
        current, depth = stack.pop(); nodes += 1
        require(nodes <= MAX_NODES, "JSON node limit exceeded"); require(depth <= MAX_DEPTH, "JSON nesting limit exceeded")
        if type(current) is str:
            require(len(current) <= MAX_STRING, "JSON string limit exceeded")
            require(not any(ord(char) < 32 for char in current), "JSON string contains a control character")
        elif type(current) is list:
            require(len(current) <= MAX_ARRAY, "JSON array limit exceeded"); stack.extend((item, depth + 1) for item in current)
        elif type(current) is dict:
            require(len(current) <= MAX_OBJECT, "JSON object limit exceeded")
            for key, item in current.items():
                require(type(key) is str and len(key) <= MAX_STRING, "JSON object key is invalid")
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
        value = json.loads(text, object_pairs_hook=no_duplicate_keys, parse_constant=reject_constant, parse_float=reject_float, parse_int=reject_int)
    except ValidationError:
        raise
    except (ValueError, RecursionError) as exc:
        raise ValidationError("JSON artifact is malformed") from exc
    inspect_shape(value)
    return value, payload


def classify_scheme(value: Any) -> str:
    if value is None: return "rejected_missing"
    if type(value) is not str or not value.isascii() or any(ord(c) <= 32 or ord(c) == 127 for c in value): return "rejected_malformed"
    return "accepted_exact" if value == EXPECTED_MAPPING["configured_public_scheme"] else "rejected_mismatch"


def classify_host(value: Any) -> str:
    if value is None: return "rejected_missing"
    if type(value) is not str or not value: return "rejected_malformed"
    if not value.isascii() or any(ord(c) <= 32 or ord(c) == 127 for c in value): return "rejected_whitespace"
    if "," in value: return "rejected_multiple"
    if any(c in value for c in ("/", "\\", "@", "?", "#", "[", "]", "%")) or "://" in value: return "rejected_malformed"
    try:
        parsed = urlsplit("//" + value); port = parsed.port
    except ValueError:
        return "rejected_malformed"
    if parsed.netloc != value or parsed.path or parsed.query or parsed.fragment or parsed.username is not None or parsed.password is not None or not parsed.hostname:
        return "rejected_malformed"
    labels = parsed.hostname.rstrip(".").split(".")
    if not labels or any(not label or not re.fullmatch(r"[A-Za-z0-9-]+", label) or label.startswith("-") or label.endswith("-") or len(label) > 63 for label in labels): return "rejected_malformed"
    if port is not None: return "rejected_mismatch"
    return "accepted_exact" if value == EXPECTED_MAPPING["configured_public_host"] else "rejected_mismatch"


def classify_origin(value: Any) -> str:
    if value is None: return "rejected_missing"
    if type(value) is not str or not value: return "rejected_malformed"
    if value == "null": return "rejected_null"
    if value == "*": return "rejected_wildcard"
    if not value.isascii() or any(ord(c) <= 32 or ord(c) == 127 for c in value): return "rejected_whitespace"
    if "," in value: return "rejected_multiple"
    if "\\" in value or "%" in value: return "rejected_malformed"
    try:
        parsed = urlsplit(value); port = parsed.port
    except ValueError:
        return "rejected_malformed"
    if not parsed.scheme or not parsed.netloc or parsed.username is not None or parsed.password is not None: return "rejected_malformed"
    if parsed.path or parsed.query or parsed.fragment: return "rejected_malformed"
    if port is not None: return "rejected_mismatch"
    return "accepted_exact" if value == EXPECTED_MAPPING["configured_public_origin"] else "rejected_mismatch"


def classify_header_values(values: Any, classifier: Any) -> str:
    if type(values) is not list:
        return "rejected_malformed"
    if not values:
        return "rejected_missing"
    if len(values) != 1:
        return "rejected_multiple"
    return classifier(values[0])


def outcome(decision: str, status: int | None, scheme_result: str, host_result: str, origin_result: str, *, upstream: bool = False) -> dict[str, Any]:
    return {"decision": decision, "status": status, "responding_layer": "upstream" if upstream else "edge", "upstream_called": upstream, "public_scheme_result": scheme_result, "public_host_result": host_result, "public_origin_result": origin_result, "mapped_host_marker": EXPECTED_MAPPING["hermes_bound_authority"] if upstream else None, "mapped_origin_marker": EXPECTED_MAPPING["hermes_required_origin"] if upstream else None}


def evaluate_case(case: dict[str, Any]) -> dict[str, Any]:
    request = exact_keys(case["request"], REQUEST_KEYS, "case request")
    scheme_result = classify_scheme(request["scheme"])
    if scheme_result != "accepted_exact": return outcome("reject_public_scheme", 421, scheme_result, "not_evaluated", "not_evaluated")
    host_result = classify_header_values(request["host_values"], classify_host)
    if host_result != "accepted_exact": return outcome("reject_public_host", 421, scheme_result, host_result, "not_evaluated")
    origin_result = classify_header_values(request["origin_values"], classify_origin)
    if origin_result != "accepted_exact": return outcome("reject_public_origin", 403, scheme_result, host_result, origin_result)
    if request["upstream_host_override"] is not None: return outcome("reject_upstream_override", 421, scheme_result, host_result, origin_result)
    if request["upstream_origin_override"] is not None: return outcome("reject_upstream_override", 403, scheme_result, host_result, origin_result)
    return outcome("forward_with_configured_mapping", None, scheme_result, host_result, origin_result, upstream=True)


def semantics_payload(document: dict[str, Any]) -> bytes:
    canonical = {"schema": document["schema"], "mapping": document["mapping"], "policy": document["policy"], "evidence_contract": document["evidence_contract"], "case_ids": [case["id"] for case in document["cases"]], "requests": [case["request"] for case in document["cases"]], "computed": [evaluate_case(case) for case in document["cases"]]}
    return json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def validate_document(root: Any) -> list[dict[str, Any]]:
    document = exact_keys(root, ROOT_KEYS, "fixture root")
    strict_equal(document["schema"], "hermternal.deployment.host-origin-mapping.v2", "fixture schema")
    strict_equal(document["fixture_id"], "host-origin-mapping-dep-03-f5be9236", "fixture id")
    strict_equal(document["issue"], "DEP-03", "fixture issue"); strict_equal(document["contract"], "dashboard-v0.0.1", "fixture contract")
    strict_equal(document["hermes_source_sha"], "f5be9236e00ddf2f2a412697f267078fc4ee068e", "Hermes source pin")
    strict_equal(document["synthetic_only"], True, "synthetic-only flag"); strict_equal(document["live_claim"], False, "live-claim flag")
    strict_equal(document["proof_mode"], "offline_disposable_raw_request_mapping_model", "proof mode")
    strict_equal(exact_keys(document["mapping"], MAPPING_KEYS, "mapping"), EXPECTED_MAPPING, "mapping contract")
    strict_equal(exact_keys(document["policy"], POLICY_KEYS, "policy"), EXPECTED_POLICY, "edge policy")
    strict_equal(exact_keys(document["evidence_contract"], EVIDENCE_KEYS, "evidence contract"), EXPECTED_EVIDENCE, "evidence contract")
    cases = document["cases"]; require(type(cases) is list and len(cases) == len(EXPECTED_CASE_IDS), "case inventory changed")
    retained = []
    for index, raw_case in enumerate(cases):
        case = exact_keys(raw_case, CASE_KEYS, "case"); strict_equal(case["id"], EXPECTED_CASE_IDS[index], "case id or order")
        expected = exact_keys(case["expected"], EXPECTED_KEYS, "case expected result"); computed = evaluate_case(case)
        strict_equal(expected, computed, "computed case outcome")
        retained.append({"case_id": case["id"], **{key: computed[key] for key in RETAINED_FIELDS if key != "case_id"}})
    require(hashlib.sha256(semantics_payload(document)).hexdigest() == PINNED_SEMANTICS_SHA256, "validator semantics identity changed")
    require(sum(1 for item in retained if item["upstream_called"]) == 1, "accepted mapping evidence changed")
    for item in retained:
        if not item["upstream_called"]: require(item["mapped_host_marker"] is None and item["mapped_origin_marker"] is None, "rejection retained mapped values")
    evidence = json.dumps(retained, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    require(len(evidence) <= EXPECTED_EVIDENCE["maximum_retained_evidence_bytes"], "retained evidence byte limit exceeded")
    scan_artifact_bytes("cases.json", evidence)
    return retained


def normalized_artifact_bytes(path: Path) -> bytes:
    payload = path.read_bytes()
    if path.name == "validate.py":
        text = payload.decode()
        for name in ("PINNED_CASES_SHA256", "PINNED_BASELINE_SHA256", "PINNED_SEMANTICS_SHA256"):
            text = re.sub(rf'{name} = "[^"]+"', f'{name} = "<normalized-{name.lower()}>"', text, count=1)
        payload = text.encode()
    return payload


def artifact_manifest() -> dict[str, Any]:
    digest = hashlib.sha256(); files = []; total = 0
    for name in sorted(BENCHMARK_SOURCE_FILES):
        path = ROOT / name
        try: raw = path.read_bytes(); normalized = normalized_artifact_bytes(path)
        except OSError as exc: raise ValidationError("retained proof artifact is unavailable") from exc
        total += len(raw); files.append({"path": name, "bytes": len(raw), "sha256": hashlib.sha256(normalized).hexdigest()})
        digest.update(name.encode()); digest.update(b"\0"); digest.update(normalized); digest.update(b"\0")
    return {"files": files, "bytes": total, "sha256": digest.hexdigest()}


def _normalize_structural_text(text: str) -> str:
    normalized = text
    for value in sorted(STRUCTURAL_URLS, key=len, reverse=True):
        normalized = re.sub(rf"(?<![A-Za-z0-9._~:/?#@!$&'()*+,;=%-]){re.escape(value)}(?![A-Za-z0-9._~:/?#@!$&'()*+,;=%-])", "<reserved-invalid-url>", normalized)
    for value in sorted(STRUCTURAL_HOSTS, key=len, reverse=True):
        normalized = re.sub(rf"(?<![A-Za-z0-9.-]){re.escape(value)}(?![A-Za-z0-9.-])", "<reserved-invalid-host>", normalized)
    for value in STRUCTURAL_PATHS:
        normalized = re.sub(rf"(?<![A-Za-z0-9._/-]){re.escape(value)}(?![A-Za-z0-9._/-])", "<reviewed-route>", normalized)
    # Detector definitions and explicit negative-test canaries are security-test
    # syntax. Exempt only their complete source lines, never adjacent content.
    normalized = re.sub(r"(?m)^[A-Z_]+ = re\.compile\(.*$", "<detector-definition>", normalized)
    normalized = re.sub(r"(?m)^\s*mutations = \[.*$", "<parser-negative-matrix>", normalized)
    normalized = re.sub(r"(?m)^\s*payloads = \(b'.*$", "<malformed-json-negative-canary>", normalized)
    normalized = re.sub(r"(?m)^\s*for arguments in \(\[\"--unknown\".*$", "<cli-negative-canary>", normalized)
    normalized = re.sub(r"(?m)^\s*for value in \(\"evilchat\.public\.invalid\".*$", "<structural-boundary-negative-canary>", normalized)
    normalized = re.sub(r"(?m)^\s*[\"'](?:credential|bearer|cookie|ticket|url|host|ipv4|ipv6|path|email|key)[\"']:\s.*$", "<redaction-negative-canary>", normalized)
    normalized = re.sub(r"(?m)^.*<negative-test-canary>.*$", "<negative-test-detector-definition>", normalized)
    return normalized


def scan_artifact_bytes(name: str, payload: bytes) -> None:
    require(name in ARTIFACT_FILES, "artifact scanner target is unsupported")
    try: text = payload.decode("utf-8")
    except UnicodeDecodeError as exc: raise ValidationError("retained artifact is not valid UTF-8") from exc
    normalized = _normalize_structural_text(text)
    for pattern, label in ((SENSITIVE_ASSIGNMENT, "credential assignment"), (CREDENTIAL_HEADER, "credential header"), (COOKIE_HEADER, "cookie header"), (PRIVATE_KEY, "private key"), (LIVE_URL, "URL"), (IPV4, "IPv4 address"), (IPV6, "IPv6 address"), (EMAIL, "email address"), (HOSTNAME, "hostname"), (ABSOLUTE_PATH, "filesystem path")):
        require(not pattern.search(normalized), f"retained artifact contains forbidden {label}")


def scan_all_artifacts() -> None:
    for name in ARTIFACT_FILES:
        try: payload = (ROOT / name).read_bytes()
        except OSError as exc: raise ValidationError("retained proof artifact is unavailable") from exc
        scan_artifact_bytes(name, payload)


def percentile(samples: list[float], fraction: float) -> float:
    ordered = sorted(samples); position = (len(ordered) - 1) * fraction; lower = math.floor(position); upper = math.ceil(position)
    return ordered[lower] if lower == upper else ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def distribution(samples: list[float]) -> dict[str, float]:
    return {"min": min(samples), "p50": percentile(samples, .50), "p95": percentile(samples, .95), "p99": percentile(samples, .99), "max": max(samples), "mean": sum(samples) / len(samples)}


def validate_baseline(root: Any, payload: bytes) -> None:
    require(hashlib.sha256(payload).hexdigest() == PINNED_BASELINE_SHA256, "benchmark evidence identity changed")
    baseline = exact_keys(root, ("schema", "fixture_id", "samples_per_mode", "unit", "threshold", "environment", "commands", "normal", "optimized", "semantics_sha256", "artifact"), "benchmark root")
    strict_equal(baseline["schema"], "hermternal.validation-baseline.v1", "benchmark schema"); strict_equal(baseline["fixture_id"], "host-origin-mapping-dep-03-f5be9236", "benchmark fixture id")
    strict_equal(baseline["samples_per_mode"], 30, "benchmark sample count"); strict_equal(baseline["unit"], "seconds", "benchmark unit"); require(baseline["threshold"] is None, "benchmark threshold must remain null")
    environment = exact_keys(baseline["environment"], ("platform", "python", "machine"), "benchmark environment"); require(all(type(value) is str and 1 <= len(value) <= 160 for value in environment.values()), "benchmark environment is invalid")
    commands = exact_keys(baseline["commands"], ("normal", "optimized"), "benchmark commands")
    strict_equal(commands["normal"], "python3 contracts/fixtures/deployment-security/host-origin-mapping/validate.py --skip-baseline", "normal benchmark command")
    strict_equal(commands["optimized"], "python3 -O contracts/fixtures/deployment-security/host-origin-mapping/validate.py --skip-baseline", "optimized benchmark command")
    strict_equal(baseline["semantics_sha256"], PINNED_SEMANTICS_SHA256, "benchmark semantics identity")
    for mode in ("normal", "optimized"):
        evidence = exact_keys(baseline[mode], ("samples", "distribution"), f"{mode} benchmark evidence"); samples = evidence["samples"]
        require(type(samples) is list and len(samples) == 30 and all(type(sample) is float and 0 < sample < 60 for sample in samples), f"{mode} samples are invalid")
        actual = exact_keys(evidence["distribution"], ("min", "p50", "p95", "p99", "max", "mean"), f"{mode} distribution")
        for key, expected in distribution(samples).items(): require(type(actual[key]) is float and abs(actual[key] - expected) <= 1e-12, f"{mode} distribution changed")
    strict_equal(baseline["artifact"], artifact_manifest(), "benchmark artifact manifest")


def validate(cases_path: Path = CASES_PATH, *, skip_baseline: bool = False, scan_artifacts: bool = True) -> list[dict[str, Any]]:
    root, cases_payload = load_json(cases_path)
    if cases_path.resolve() == CASES_PATH.resolve(): require(hashlib.sha256(cases_payload).hexdigest() == PINNED_CASES_SHA256, "fixture identity changed")
    retained = validate_document(root)
    if not skip_baseline:
        baseline, payload = load_json(BASELINE_PATH); validate_baseline(baseline, payload)
    if scan_artifacts and cases_path.resolve() == CASES_PATH.resolve(): scan_all_artifacts()
    return retained


def parse_cli(argv: list[str]) -> tuple[Path, bool]:
    cases_path = CASES_PATH; skip_baseline = False; index = 0
    while index < len(argv):
        argument = argv[index]
        if argument == "--skip-baseline": require(not skip_baseline, "CLI option repeated"); skip_baseline = True; index += 1
        elif argument == "--cases": require(index + 1 < len(argv), "CLI cases input is missing"); require(cases_path == CASES_PATH, "CLI option repeated"); cases_path = Path(argv[index + 1]); index += 2
        else: raise ValidationError("CLI option is unsupported")
    return cases_path, skip_baseline


def bounded_failure(message: str) -> str:
    safe = message if len(message) <= 120 and re.fullmatch(r"[A-Za-z0-9 -]+", message) else "validation failed"
    line = json.dumps({"status": "failure", "reason": safe}, separators=(",", ":"), ensure_ascii=True)
    return line if len(line) <= FAILURE_LIMIT else json.dumps({"status": "failure", "reason": "validation failed"}, separators=(",", ":"))


def main(argv: list[str] | None = None) -> int:
    try:
        cases_path, skip_baseline = parse_cli(list(sys.argv[1:] if argv is None else argv)); retained = validate(cases_path, skip_baseline=skip_baseline)
        result = {"status": "ok", "fixture_id": "host-origin-mapping-dep-03-f5be9236", "cases": len(retained), "accepted": sum(1 for item in retained if item["upstream_called"]), "rejected": sum(1 for item in retained if not item["upstream_called"]), "synthetic_only": True, "live_claim": False}
        print(json.dumps(result, separators=(",", ":"), ensure_ascii=True)); return 0
    except (ValidationError, OSError) as exc:
        print(bounded_failure(str(exc))); return 2


if __name__ == "__main__":
    raise SystemExit(main())
