#!/usr/bin/env python3
"""Validate the offline DEP-03 raw Host, Origin, and forwarding proof.

Raw synthetic request values are classified independently from fixture
expectations. Inbound forwarding headers are treated as untrusted input and
are stripped before semantic proxy-generated markers are retained. Evidence is
captured once from canonical files so parsing, hashing, and redaction cannot
observe different bytes.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tokenize
from types import MappingProxyType
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
CASES_PATH = ROOT / "cases.json"
BASELINE_PATH = ROOT / "validation-baseline.json"
ARTIFACT_FILES = ("README.md", "cases.json", "test_validate.py", "validate.py", "validation-baseline.json")
BENCHMARK_SOURCE_FILES = ("README.md", "cases.json", "test_validate.py", "validate.py")
RETAINED_FILES = ARTIFACT_FILES
MAX_INPUT_BYTES = 256_000
MAX_TOTAL_RETAINED_BYTES = 2 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024
MAX_DEPTH = 16
MAX_NODES = 20_000
MAX_STRING = 8_192
MAX_ARRAY = 256
MAX_OBJECT = 80
MAX_REVIEWED_SOURCE_BYTES = 128 * 1024
FAILURE_LIMIT = 240

# These identities are local reproducibility pins. The aggregate registry is
# the later integration trust root; the reviewed proof-matrix Git object below
# independently binds the source contract used by each synthetic observation.
PINNED_CASES_SHA256 = "0cf4f545eef2b9dba17792cef04fb8bfee1f785ada06c44d53a8e116a66b0b34"
PINNED_BASELINE_SHA256 = "b79897e192b320157af65a130df442f5d48c52b0d1058a506a1d93dc5b3dfbc2"
PINNED_SEMANTICS_SHA256 = "0d2cab9a0a709f9f1bf88ff91c53053af3d12c3d1cc5eb3dd0e227a02f71372f"
PINNED_BASELINE_EVIDENCE_SHA256 = "5d988329644b6fc400b71d074f6d19ee3511deed6bfab23580f0f58366841e4e"
PINNED_VALIDATOR_SOURCE_SHA256 = "adc43a0e3e7414d35d888cacc14ef10d503ff32e51bd6c15a0eb62b4c245ea12"
PINNED_RETAINED_ARTIFACTS: dict[str, tuple[int, str]] = {
    "README.md": (8253, "0ff1ee8c929dc0ac70292b7ed4876cbf96ff93f84d68e3799b3adb82607c7f40"),
    "cases.json": (52421, "0cf4f545eef2b9dba17792cef04fb8bfee1f785ada06c44d53a8e116a66b0b34"),
    "test_validate.py": (16401, "eb7e6c3290f3643235f56822245f245c9f5b46a7ff9703d197c18556da667f1e"),
}

# The deployment proof matrix is an immutable, local Git source contract. It
# supplies the forwarding-header and public-to-private mapping requirements;
# the per-row binding below prevents copying an allow request into another row.
REVIEWED_PROOF_MATRIX_COMMIT = "fbaebbcf445d89e0b3968c884d0ae4ccb40744cb"
REVIEWED_PROOF_MATRIX_PATH = "docs/deployment/proof-matrix.md"
REVIEWED_PROOF_MATRIX_BYTES = 16167
REVIEWED_PROOF_MATRIX_SHA256 = "52fb8d0fb9f21ee7a80c5796343c3893a7f715c93fd47e832f5be098bc865212"

ROOT_KEYS = ("schema", "fixture_id", "issue", "contract", "hermes_source_sha", "synthetic_only", "live_claim", "proof_mode", "mapping", "policy", "evidence_contract", "cases")
MAPPING_KEYS = (
    "configured_public_scheme", "configured_public_host", "configured_public_origin",
    "hermes_bound_authority", "hermes_required_origin", "mapping_source",
    "forwarded_host_marker", "forwarded_proto_marker", "forwarded_prefix_marker",
    "forwarded_for_marker", "strip_inbound_forwarded_headers", "request_values_never_select_upstream",
)
POLICY_KEYS = (
    "route", "method", "transport", "host_rejection_status", "origin_rejection_status",
    "forwarded_rejection_status", "host_precedes_origin", "origin_precedes_forwarded",
    "forwarded_precedes_overrides", "rejection_upstream_called", "forwarded_headers_policy",
    "accepted_action",
)
EVIDENCE_KEYS = (
    "retained_fields", "forbidden_retained_classes", "structural_exemptions",
    "maximum_failure_line_characters", "maximum_retained_evidence_bytes", "failure_output",
)
CASE_KEYS = ("id", "source_evidence", "request", "expected")
SOURCE_EVIDENCE_KEYS = ("observation_index", "contract_path", "contract_commit", "contract_sha256", "case_binding_sha256")
REQUEST_KEYS = ("scheme", "host_values", "origin_values", "inbound_forwarded", "upstream_host_override", "upstream_origin_override")
FORWARDED_KEYS = ("x_forwarded_host", "x_forwarded_proto", "x_forwarded_prefix", "x_forwarded_for")
EXPECTED_KEYS = (
    "decision", "status", "responding_layer", "upstream_called", "public_scheme_result",
    "public_host_result", "public_origin_result", "forwarded_result", "mapped_host_marker",
    "mapped_origin_marker", "forwarded_host_marker", "forwarded_proto_marker",
    "forwarded_prefix_marker", "forwarded_for_marker",
)
RETAINED_FIELDS = (
    "case_id", "decision", "responding_layer", "upstream_called", "public_scheme_result",
    "public_host_result", "public_origin_result", "forwarded_result", "mapped_host_marker",
    "mapped_origin_marker", "forwarded_host_marker", "forwarded_proto_marker",
    "forwarded_prefix_marker", "forwarded_for_marker",
)

EXPECTED_MAPPING = {
    "configured_public_scheme": "https",
    "configured_public_host": "chat.public.invalid",
    "configured_public_origin": "https://chat.public.invalid",
    "hermes_bound_authority": "fixed_private_non_loopback_9119",
    "hermes_required_origin": "mapped_private_http_origin",
    "mapping_source": "trusted_edge_configuration_only",
    "forwarded_host_marker": "public_host_from_edge_validation",
    "forwarded_proto_marker": "https_from_edge_transport",
    "forwarded_prefix_marker": "reviewed_route_prefix_only",
    "forwarded_for_marker": "proxy_generated_client_chain",
    "strip_inbound_forwarded_headers": True,
    "request_values_never_select_upstream": True,
}
EXPECTED_POLICY = {
    "route": "/hermes/api/ws", "method": "GET", "transport": "websocket",
    "host_rejection_status": 421, "origin_rejection_status": 403,
    "forwarded_rejection_status": 421, "host_precedes_origin": True,
    "origin_precedes_forwarded": True, "forwarded_precedes_overrides": True,
    "rejection_upstream_called": False,
    "forwarded_headers_policy": "strip_inbound_then_rebuild",
    "accepted_action": "forward_with_configured_mapping",
}
EXPECTED_EVIDENCE = {
    "retained_fields": list(RETAINED_FIELDS),
    "forbidden_retained_classes": ["raw_request_values", "forwarded_headers", "credentials", "cookies", "bearer_values", "ticket_values", "live_hosts", "private_addresses", "filesystem_paths", "user_data", "transcripts"],
    "structural_exemptions": ["reserved_invalid_fixture_authorities", "exact_validator_command_paths", "exact_artifact_filenames", "reviewed_route_path"],
    "maximum_failure_line_characters": 240, "maximum_retained_evidence_bytes": 16384,
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
    "reject-both-overrides", "reject-host-before-hostile-origin-and-overrides", "reject-forwarded-malformed",
)

# Exact RFC 2606 `.invalid` values are the only host-shaped strings allowed in
# this synthetic raw-input proof. They cannot resolve and are replaced before
# generic retained-artifact host and URL detection.
STRUCTURAL_HOSTS = (
    "chat.public.invalid", "chat.public.invalid.", "other.public.invalid",
    "attacker.private.invalid", "CHAT.PUBLIC.INVALID", "chat..public.invalid",
)
STRUCTURAL_URLS = (
    "https://chat.public.invalid", "http://chat.public.invalid", "https://CHAT.PUBLIC.INVALID",
    "HTTPS://chat.public.invalid", "https://chat.public.invalid.", "https://chat.public.invalid/",
    "https://other.public.invalid", "https://user@chat.public.invalid", "http://attacker.private.invalid",
)
STRUCTURAL_PATHS = ("/hermes/api/ws",)
STRUCTURAL_FILENAMES = (
    "README.md", "cases.json", "test_validate.py", "validate.py", "validation-baseline.json",
    "proof-matrix.md", "index.json",
)

SENSITIVE_ASSIGNMENT = re.compile(r"(?i)(?:password|passwd|secret|token|ticket|cookie|authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key)\s*[:=]\s*[^\s,;}]+")
CREDENTIAL_HEADER = re.compile(r"(?i)\bauthorization\s*:\s*(?:basic|bearer)\s+[A-Za-z0-9._~+/-]{4,}")
COOKIE_HEADER = re.compile(r"(?i)\bcookie\s*:\s*[^\s,;}]+")
STRUCTURED_CREDENTIAL_KEY = re.compile(r"(?i)[\"'](?:password|passwd|secret|token|ticket|cookie|authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key|credential|credentials)[\"']\s*:\s*")
STRUCTURED_USER_DATA = re.compile(r"(?i)[\"'](?:user[_-]?data|user[_-]?content|personal[_-]?data|prompt|message|content)[\"']\s*:\s*")
STRUCTURED_TRANSCRIPT = re.compile(r"(?i)[\"'](?:transcript|transcripts|conversation|chat[_-]?history|messages|turns|tool[_-]?output)[\"']\s*:\s*")
USER_ROLE = re.compile(r"(?i)[\"']role[\"']\s*:\s*[\"']user[\"']")
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
IPV4 = re.compile(r"(?<![A-Za-z0-9_])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9_])")
IPV6 = re.compile(r"(?i)(?<![A-Za-z0-9_])(?=[0-9a-f:]*[0-9a-f])(?:[0-9a-f]{0,4}:){2,}[0-9a-f:]{0,4}(?![A-Za-z0-9_])")
EMAIL = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
LIVE_URL = re.compile(r"(?i)\b(?:https?|wss?)://[^\s'\"<>)]+")
HOSTNAME = re.compile(r"(?i)(?<![A-Za-z0-9._-])(?:localhost|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})(?::\d{1,5})?(?![A-Za-z0-9._/-])")
ABSOLUTE_PATH = re.compile(r"(?<![A-Za-z0-9_])/(?:srv|tmp|private|Users|home|var|etc|opt|root|run|System|Library)(?:/[A-Za-z0-9._~+-]+)+(?![A-Za-z0-9_/-])")
VALIDATOR_PIN_LINE = re.compile(r"(?m)^PINNED_(?:CASES|BASELINE|SEMANTICS|BASELINE_EVIDENCE|VALIDATOR_SOURCE)_SHA256 = \"[0-9a-f]{64}\"$")
REDACTION_DETECTOR_NAMES = frozenset({
    "SENSITIVE_ASSIGNMENT", "CREDENTIAL_HEADER", "COOKIE_HEADER", "STRUCTURED_CREDENTIAL_KEY",
    "STRUCTURED_USER_DATA", "STRUCTURED_TRANSCRIPT", "USER_ROLE", "PRIVATE_KEY", "IPV4", "IPV6",
    "EMAIL", "LIVE_URL", "HOSTNAME", "ABSOLUTE_PATH", "VALIDATOR_PIN_LINE",
})
SENSITIVE_STRUCTURED_KEYS = frozenset({
    "password", "passwd", "secret", "token", "ticket", "cookie", "authorization", "api_key",
    "access_token", "refresh_token", "client_secret", "private_key", "credential", "credentials",
})
USER_DATA_STRUCTURED_KEYS = frozenset({"user", "user_data", "user_content", "personal_data", "prompt", "message", "content"})
TRANSCRIPT_STRUCTURED_KEYS = frozenset({"transcript", "transcripts", "conversation", "chat_history", "messages", "turns", "tool_output"})


class ValidationError(Exception):
    """A bounded semantic contract failure."""


class CapturedArtifacts:
    """Immutable bytes captured once from each canonical retained path."""

    __slots__ = ("root", "files")

    def __init__(self, root: Path, files: Mapping[str, bytes]) -> None:
        self.root = root
        self.files = MappingProxyType(dict(files))


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


def scan_json_nesting(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            require(depth <= MAX_DEPTH, "JSON nesting limit exceeded")
        elif character in "]}":
            depth -= 1
            require(depth >= 0, "JSON structure is malformed")
    require(not in_string and not escaped and depth == 0, "JSON structure is malformed")


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
                require(type(key) is str and len(key) <= MAX_STRING, "JSON object key is invalid")
                require(not any(ord(char) < 32 for char in key), "JSON key contains a control character")
                stack.append((item, depth + 1))
        else:
            require(current is None or type(current) in (bool, int, float), "JSON scalar type is unsupported")


def parse_json_bytes(payload: bytes) -> Any:
    require(len(payload) <= MAX_INPUT_BYTES, "JSON artifact byte limit exceeded")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError("JSON artifact is not valid UTF-8") from exc
    scan_json_nesting(text)
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
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValidationError("JSON artifact is malformed") from exc
    inspect_shape(value)
    return value


def _read_artifact(
    root: Path,
    relative: str,
    *,
    limit: int = MAX_TOTAL_RETAINED_BYTES,
    before_open: Callable[[Path], None] | None = None,
) -> bytes:
    """Capture one regular file without blocking on a raced special file."""

    path = root / relative
    try:
        metadata = path.lstat()
        require(stat.S_ISREG(metadata.st_mode), "retained artifact must be a regular file")
        require(not stat.S_ISLNK(metadata.st_mode), "retained artifact symlink is not allowed")
        require(metadata.st_size <= limit, "retained artifact byte limit exceeded")
        require(hasattr(os, "O_NONBLOCK"), "nonblocking retained artifact open is unavailable")
        flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        if before_open is not None:
            before_open(path)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            require(stat.S_ISREG(opened.st_mode), "retained artifact must remain a regular file")
            require(opened.st_dev == metadata.st_dev and opened.st_ino == metadata.st_ino, "retained artifact changed during open")
            current = path.lstat()
            require(stat.S_ISREG(current.st_mode), "retained artifact path must remain a regular file")
            require(current.st_dev == opened.st_dev and current.st_ino == opened.st_ino, "retained artifact path identity changed during open")
            require(opened.st_size <= limit, "retained artifact byte limit exceeded")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(READ_CHUNK_BYTES, limit - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                require(total <= limit, "retained artifact byte limit exceeded")
                chunks.append(chunk)
            final = os.fstat(descriptor)
            require(final.st_dev == opened.st_dev and final.st_ino == opened.st_ino and final.st_size == opened.st_size, "retained artifact changed during read")
            require(total == opened.st_size, "retained artifact changed during read")
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    except ValidationError:
        raise
    except OSError as exc:
        raise ValidationError("retained proof artifact is unavailable") from exc


def _capture_retained_artifacts(root: Path = ROOT) -> CapturedArtifacts:
    """Open every canonical retained artifact once and freeze its bytes."""

    files: dict[str, bytes] = {}
    total = 0
    for relative in RETAINED_FILES:
        remaining = MAX_TOTAL_RETAINED_BYTES - total
        require(remaining >= 0, "retained artifact byte limit exceeded")
        data = _read_artifact(root, relative, limit=remaining)
        total += len(data)
        files[relative] = data
    return CapturedArtifacts(root=root.resolve(), files=MappingProxyType(files))


def load_json(path: Path) -> tuple[Any, bytes]:
    payload = _read_artifact(path.parent, path.name, limit=MAX_INPUT_BYTES)
    return parse_json_bytes(payload), payload


def classify_scheme(value: Any) -> str:
    if value is None:
        return "rejected_missing"
    if type(value) is not str or not value.isascii() or any(ord(char) <= 32 or ord(char) == 127 for char in value):
        return "rejected_malformed"
    return "accepted_exact" if value == EXPECTED_MAPPING["configured_public_scheme"] else "rejected_mismatch"


def classify_host(value: Any) -> str:
    if value is None:
        return "rejected_missing"
    if type(value) is not str or not value:
        return "rejected_malformed"
    if not value.isascii() or any(ord(char) <= 32 or ord(char) == 127 for char in value):
        return "rejected_whitespace"
    if "," in value:
        return "rejected_multiple"
    if any(char in value for char in ("/", "\\", "@", "?", "#", "[", "]", "%")) or "://" in value:
        return "rejected_malformed"
    try:
        parsed = urlsplit("//" + value)
        port = parsed.port
    except ValueError:
        return "rejected_malformed"
    if parsed.netloc != value or parsed.path or parsed.query or parsed.fragment or parsed.username is not None or parsed.password is not None or not parsed.hostname:
        return "rejected_malformed"
    labels = parsed.hostname.rstrip(".").split(".")
    if not labels or any(not label or not re.fullmatch(r"[A-Za-z0-9-]+", label) or label.startswith("-") or label.endswith("-") or len(label) > 63 for label in labels):
        return "rejected_malformed"
    if port is not None:
        return "rejected_mismatch"
    return "accepted_exact" if value == EXPECTED_MAPPING["configured_public_host"] else "rejected_mismatch"


def classify_origin(value: Any) -> str:
    if value is None:
        return "rejected_missing"
    if type(value) is not str or not value:
        return "rejected_malformed"
    if value == "null":
        return "rejected_null"
    if value == "*":
        return "rejected_wildcard"
    if not value.isascii() or any(ord(char) <= 32 or ord(char) == 127 for char in value):
        return "rejected_whitespace"
    if "," in value:
        return "rejected_multiple"
    if "\\" in value or "%" in value:
        return "rejected_malformed"
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return "rejected_malformed"
    if not parsed.scheme or not parsed.netloc or parsed.username is not None or parsed.password is not None:
        return "rejected_malformed"
    if parsed.path or parsed.query or parsed.fragment:
        return "rejected_malformed"
    if port is not None:
        return "rejected_mismatch"
    return "accepted_exact" if value == EXPECTED_MAPPING["configured_public_origin"] else "rejected_mismatch"


def classify_header_values(values: Any, classifier: Any) -> str:
    if type(values) is not list:
        return "rejected_malformed"
    if not values:
        return "rejected_missing"
    if len(values) != 1:
        return "rejected_multiple"
    return classifier(values[0])


def classify_forwarded_headers(value: Any) -> str:
    """Validate only the shape; values are never used to build forwarding."""

    if type(value) is not dict or tuple(value) != FORWARDED_KEYS:
        return "rejected_malformed"
    for values in value.values():
        if type(values) is not list:
            return "rejected_malformed"
        for item in values:
            if type(item) is not str or not item.isascii() or any(ord(char) <= 32 or ord(char) == 127 for char in item):
                return "rejected_malformed"
    return "stripped_and_rebuilt"


def outcome(
    decision: str,
    status: int | None,
    scheme_result: str,
    host_result: str,
    origin_result: str,
    forwarded_result: str,
    *,
    upstream: bool = False,
) -> dict[str, Any]:
    return {
        "decision": decision,
        "status": status,
        "responding_layer": "upstream" if upstream else "edge",
        "upstream_called": upstream,
        "public_scheme_result": scheme_result,
        "public_host_result": host_result,
        "public_origin_result": origin_result,
        "forwarded_result": forwarded_result,
        "mapped_host_marker": EXPECTED_MAPPING["hermes_bound_authority"] if upstream else None,
        "mapped_origin_marker": EXPECTED_MAPPING["hermes_required_origin"] if upstream else None,
        "forwarded_host_marker": EXPECTED_MAPPING["forwarded_host_marker"] if upstream else None,
        "forwarded_proto_marker": EXPECTED_MAPPING["forwarded_proto_marker"] if upstream else None,
        "forwarded_prefix_marker": EXPECTED_MAPPING["forwarded_prefix_marker"] if upstream else None,
        "forwarded_for_marker": EXPECTED_MAPPING["forwarded_for_marker"] if upstream else None,
    }


def evaluate_case(case: dict[str, Any]) -> dict[str, Any]:
    request = exact_keys(case["request"], REQUEST_KEYS, "case request")
    scheme_result = classify_scheme(request["scheme"])
    if scheme_result != "accepted_exact":
        return outcome("reject_public_scheme", 421, scheme_result, "not_evaluated", "not_evaluated", "not_evaluated")
    host_result = classify_header_values(request["host_values"], classify_host)
    if host_result != "accepted_exact":
        return outcome("reject_public_host", 421, scheme_result, host_result, "not_evaluated", "not_evaluated")
    origin_result = classify_header_values(request["origin_values"], classify_origin)
    if origin_result != "accepted_exact":
        return outcome("reject_public_origin", 403, scheme_result, host_result, origin_result, "not_evaluated")
    forwarded_result = classify_forwarded_headers(request["inbound_forwarded"])
    if forwarded_result != "stripped_and_rebuilt":
        return outcome("reject_forwarded_headers", EXPECTED_POLICY["forwarded_rejection_status"], scheme_result, host_result, origin_result, forwarded_result)
    if request["upstream_host_override"] is not None:
        return outcome("reject_upstream_override", 421, scheme_result, host_result, origin_result, "stripped_not_forwarded")
    if request["upstream_origin_override"] is not None:
        return outcome("reject_upstream_override", 403, scheme_result, host_result, origin_result, "stripped_not_forwarded")
    return outcome("forward_with_configured_mapping", None, scheme_result, host_result, origin_result, forwarded_result, upstream=True)


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def case_binding_sha256(index: int, case_id: str, request: dict[str, Any], contract_sha256: str) -> str:
    return hashlib.sha256(canonical_json_bytes({"observation_index": index, "case_id": case_id, "request": request, "contract_sha256": contract_sha256})).hexdigest()


def expected_source_evidence(index: int, case_id: str, request: dict[str, Any], contract_sha256: str) -> dict[str, Any]:
    return {
        "observation_index": index,
        "contract_path": REVIEWED_PROOF_MATRIX_PATH,
        "contract_commit": REVIEWED_PROOF_MATRIX_COMMIT,
        "contract_sha256": contract_sha256,
        "case_binding_sha256": case_binding_sha256(index, case_id, request, contract_sha256),
    }


def semantics_payload(document: dict[str, Any]) -> bytes:
    canonical = {
        "schema": document["schema"],
        "mapping": document["mapping"],
        "policy": document["policy"],
        "evidence_contract": document["evidence_contract"],
        "case_ids": [case["id"] for case in document["cases"]],
        "source_evidence": [case["source_evidence"] for case in document["cases"]],
        "requests": [case["request"] for case in document["cases"]],
        "computed": [evaluate_case(case) for case in document["cases"]],
    }
    return canonical_json_bytes(canonical)


def _repo_root(root: Path) -> Path:
    completed = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    require(completed.returncode == 0 and completed.stderr == b"", "repository identity is unavailable")
    try:
        value = completed.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise ValidationError("repository identity is unavailable") from exc
    require(value != "" and len(value) <= MAX_STRING, "repository identity is unavailable")
    return Path(value)


def _read_reviewed_git_artifact(repo_root: Path, commit: str, path: str, expected_bytes: int, expected_digest: str) -> bytes:
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None, "reviewed contract commit is malformed")
    require(0 < expected_bytes <= MAX_REVIEWED_SOURCE_BYTES, "reviewed contract size is invalid")
    object_name = f"{commit}:{path}"
    size_result = subprocess.run(
        ["git", "-C", str(repo_root), "cat-file", "-s", object_name],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    require(size_result.returncode == 0 and size_result.stderr == b"", "reviewed contract is unavailable")
    try:
        size = int(size_result.stdout.decode("ascii").strip())
    except (UnicodeError, ValueError) as exc:
        raise ValidationError("reviewed contract size is malformed") from exc
    require(size == expected_bytes, "reviewed contract size changed")
    completed = subprocess.run(
        ["git", "-C", str(repo_root), "show", object_name],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    require(completed.returncode == 0 and completed.stderr == b"", "reviewed contract is unavailable")
    require(len(completed.stdout) == expected_bytes, "reviewed contract bytes changed")
    require(hashlib.sha256(completed.stdout).hexdigest() == expected_digest, "reviewed contract digest changed")
    return completed.stdout


def load_reviewed_proof_matrix(root: Path = ROOT) -> str:
    repo_root = _repo_root(root)
    data = _read_reviewed_git_artifact(repo_root, REVIEWED_PROOF_MATRIX_COMMIT, REVIEWED_PROOF_MATRIX_PATH, REVIEWED_PROOF_MATRIX_BYTES, REVIEWED_PROOF_MATRIX_SHA256)
    return hashlib.sha256(data).hexdigest()


def validate_document(root: Any, proof_matrix_sha256: str | None = None) -> list[dict[str, Any]]:
    document = exact_keys(root, ROOT_KEYS, "fixture root")
    strict_equal(document["schema"], "hermternal.deployment.host-origin-mapping.v3", "fixture schema")
    strict_equal(document["fixture_id"], "host-origin-mapping-dep-03-f5be9236", "fixture id")
    strict_equal(document["issue"], "DEP-03", "fixture issue")
    strict_equal(document["contract"], "dashboard-v0.0.1", "fixture contract")
    strict_equal(document["hermes_source_sha"], "f5be9236e00ddf2f2a412697f267078fc4ee068e", "Hermes source pin")
    strict_equal(document["synthetic_only"], True, "synthetic-only flag")
    strict_equal(document["live_claim"], False, "live-claim flag")
    strict_equal(document["proof_mode"], "offline_disposable_raw_request_mapping_model", "proof mode")
    strict_equal(exact_keys(document["mapping"], MAPPING_KEYS, "mapping"), EXPECTED_MAPPING, "mapping contract")
    strict_equal(exact_keys(document["policy"], POLICY_KEYS, "policy"), EXPECTED_POLICY, "edge policy")
    strict_equal(exact_keys(document["evidence_contract"], EVIDENCE_KEYS, "evidence contract"), EXPECTED_EVIDENCE, "evidence contract")
    contract_sha256 = proof_matrix_sha256 or load_reviewed_proof_matrix(ROOT)
    require(contract_sha256 == REVIEWED_PROOF_MATRIX_SHA256, "reviewed contract identity changed")
    cases = document["cases"]
    require(type(cases) is list and len(cases) == len(EXPECTED_CASE_IDS), "case inventory changed")
    retained: list[dict[str, Any]] = []
    for index, raw_case in enumerate(cases):
        case = exact_keys(raw_case, CASE_KEYS, "case")
        strict_equal(case["id"], EXPECTED_CASE_IDS[index], "case id or order")
        request = exact_keys(case["request"], REQUEST_KEYS, "case request")
        source_evidence = exact_keys(case["source_evidence"], SOURCE_EVIDENCE_KEYS, "source evidence")
        strict_equal(source_evidence, expected_source_evidence(index, case["id"], request, contract_sha256), "source evidence")
        expected = exact_keys(case["expected"], EXPECTED_KEYS, "case expected result")
        computed = evaluate_case(case)
        strict_equal(expected, computed, "computed case outcome")
        retained.append({"case_id": case["id"], **{key: computed[key] for key in RETAINED_FIELDS if key != "case_id"}})
    require(hashlib.sha256(semantics_payload(document)).hexdigest() == PINNED_SEMANTICS_SHA256, "validator semantics identity changed")
    require(sum(1 for item in retained if item["upstream_called"]) == 1, "accepted mapping evidence changed")
    for item in retained:
        if not item["upstream_called"]:
            for key in ("mapped_host_marker", "mapped_origin_marker", "forwarded_host_marker", "forwarded_proto_marker", "forwarded_prefix_marker", "forwarded_for_marker"):
                require(item[key] is None, "rejection retained mapped values")
    evidence = canonical_json_bytes(retained)
    require(len(evidence) <= EXPECTED_EVIDENCE["maximum_retained_evidence_bytes"], "retained evidence byte limit exceeded")
    scan_artifact_bytes("cases.json", evidence)
    return retained


def normalized_artifact_bytes(name: str, payload: bytes) -> bytes:
    if name != "validate.py":
        return payload
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError("retained proof artifact is not valid UTF-8") from exc
    text, replacements = VALIDATOR_PIN_LINE.subn("<normalized-validator-pin>", text)
    require(replacements == 5, "validator identity markers changed")
    return text.encode("utf-8")


def artifact_manifest(captured: CapturedArtifacts | None = None) -> dict[str, Any]:
    artifacts = captured or _capture_retained_artifacts(ROOT)
    digest = hashlib.sha256()
    files = []
    total = 0
    for name in sorted(BENCHMARK_SOURCE_FILES):
        raw = artifacts.files[name]
        normalized = normalized_artifact_bytes(name, raw)
        total += len(raw)
        require(total <= MAX_TOTAL_RETAINED_BYTES, "retained artifact byte limit exceeded")
        files.append({"path": name, "bytes": len(raw), "sha256": hashlib.sha256(normalized).hexdigest()})
        digest.update(name.encode("utf-8")); digest.update(b"\0"); digest.update(normalized); digest.update(b"\0")
    return {"files": files, "bytes": total, "sha256": digest.hexdigest()}


def _normalize_python_code_members(text: str) -> str:
    """Hide only dotted Python identifiers outside strings and comments.

    The hostname detector also matches ordinary module/member syntax. Tokenizing
    code avoids a broad text exemption: literals
    and comments remain unchanged, so a host, credential, or path payload in a
    source string still reaches the fail-closed scanner.
    """

    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (IndentationError, SyntaxError, tokenize.TokenError):
        return text
    lines = text.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))

    def absolute(position: tuple[int, int]) -> int:
        line, column = position
        return offsets[line - 1] + column

    spans: list[tuple[int, int]] = []
    index = 0
    while index + 2 < len(tokens):
        first, dot, last = tokens[index : index + 3]
        if first.type != tokenize.NAME or dot.string != "." or last.type != tokenize.NAME:
            index += 1
            continue
        end = index + 3
        while end + 1 < len(tokens) and tokens[end].string == "." and tokens[end + 1].type == tokenize.NAME:
            end += 2
        spans.append((absolute(first.start), absolute(tokens[end - 1].end)))
        index = end
    for start, end in reversed(spans):
        text = text[:start] + "<python-code-member>" + text[end:]
    return text


def _normalize_structural_text(text: str, *, source_name: str | None = None) -> str:
    normalized = text
    for value in sorted(STRUCTURAL_URLS, key=len, reverse=True):
        normalized = re.sub(rf"(?<![A-Za-z0-9._~:/?#@!$&'()*+,;=%-]){re.escape(value)}(?![A-Za-z0-9._~:/?#@!$&'()*+,;=%-])", "<reserved-invalid-url>", normalized)
    for value in sorted(STRUCTURAL_HOSTS, key=len, reverse=True):
        normalized = re.sub(rf"(?<![A-Za-z0-9.-]){re.escape(value)}(?![A-Za-z0-9.-])", "<reserved-invalid-host>", normalized)
    for value in STRUCTURAL_PATHS:
        normalized = re.sub(rf"(?<![A-Za-z0-9._/-]){re.escape(value)}(?![A-Za-z0-9._/-])", "<reviewed-route>", normalized)
    # Detector definitions are security-test syntax, but a definition with an
    # adjacent payload must remain visible. Normalize only a complete assignment
    # line whose final parenthesis is the end of that line; appended credentials,
    # hosts, user data, or paths are intentionally left for the scanner.
    lines: list[str] = []
    for line in normalized.splitlines(keepends=True):
        if re.fullmatch(rf"\s*(?:{'|'.join(sorted(REDACTION_DETECTOR_NAMES))})\s*=\s*re\.compile\(.*\)(?:,\s*re\.[A-Za-z]+)?\s*\n?", line):
            lines.append("<detector-definition>\n" if line.endswith("\n") else "<detector-definition>")
        else:
            lines.append(line)
    normalized = "".join(lines)
    for value in STRUCTURAL_FILENAMES:
        normalized = re.sub(rf"(?<![A-Za-z0-9._-]){re.escape(value)}(?![A-Za-z0-9._-])", "<reviewed-artifact-name>", normalized)
    if source_name is not None and source_name.endswith(".py"):
        normalized = _normalize_python_code_members(normalized)

    # The remaining exemptions are exact, named negative-test source forms. Do
    # not use a wildcard line exemption: mixed-line payload regressions must be
    # scanned even when they share a line with a test helper.
    normalized = re.sub(r"(?m)^\s*mutations = \[.*\]\s*$", "<parser-negative-matrix>", normalized)
    normalized = re.sub(r"(?m)^\s*payloads = \(b'.*\)\s*$", "<malformed-json-negative-canary>", normalized)
    normalized = re.sub(r"(?m)^\s*for arguments in \(\[\"--unknown\".*\)\s*$", "<cli-negative-canary>", normalized)
    normalized = re.sub(r"(?m)^\s*for value in \(\"evilchat\.public\.invalid\".*\)\s*$", "<structural-boundary-negative-canary>", normalized)
    normalized = re.sub(r"(?m)^.*<negative-test-canary>\s*$", "<negative-test-detector-definition>", normalized)
    return normalized


def _normalize_redaction_key(key: str) -> str:
    split_acronym = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", key)
    split_camel = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", split_acronym)
    return re.sub(r"[^a-z0-9]+", "_", split_camel.lower()).strip("_")


def _scan_structured_json(value: Any, path: str = "$") -> None:
    """Reject sensitive object keys and user/transcript payload shapes.

    Raw regexes catch textual artifacts, but JSON keys can otherwise hide a
    credential or conversation payload behind harmless-looking values. Walk
    parsed JSON with bounded parser limits and reject normalized key aliases so
    camelCase, hyphenated, and underscored spellings share one fail-closed rule.
    """

    if type(value) is dict:
        for key, child in value.items():
            normalized = _normalize_redaction_key(key)
            require(normalized not in SENSITIVE_STRUCTURED_KEYS, f"retained artifact contains forbidden structured credential at {path}")
            require(normalized not in USER_DATA_STRUCTURED_KEYS, f"retained artifact contains forbidden user data at {path}")
            require(normalized not in TRANSCRIPT_STRUCTURED_KEYS, f"retained artifact contains forbidden transcript data at {path}")
            if normalized == "role" and child == "user":
                raise ValidationError(f"retained artifact contains forbidden user transcript at {path}")
            _scan_structured_json(child, f"{path}.<field>")
        return
    if type(value) is list:
        for child in value:
            _scan_structured_json(child, f"{path}[]")


def scan_artifact_bytes(name: str, payload: bytes) -> None:
    require(name in ARTIFACT_FILES, "artifact scanner target is unsupported")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError("retained artifact is not valid UTF-8") from exc
    if name.endswith(".json"):
        _scan_structured_json(parse_json_bytes(payload))
    normalized = _normalize_structural_text(text, source_name=name)
    for pattern, label in (
        (SENSITIVE_ASSIGNMENT, "credential assignment"), (CREDENTIAL_HEADER, "credential header"),
        (COOKIE_HEADER, "cookie header"), (STRUCTURED_CREDENTIAL_KEY, "structured credential"),
        (STRUCTURED_USER_DATA, "structured user data"), (STRUCTURED_TRANSCRIPT, "structured transcript"),
        (USER_ROLE, "user transcript"), (PRIVATE_KEY, "private key"), (LIVE_URL, "URL"),
        (IPV4, "IPv4 address"), (IPV6, "IPv6 address"), (EMAIL, "email address"),
        (HOSTNAME, "hostname"), (ABSOLUTE_PATH, "filesystem path"),
    ):
        require(not pattern.search(normalized), f"retained artifact contains forbidden {label}")


def scan_all_artifacts(captured: CapturedArtifacts | None = None) -> None:
    artifacts = captured or _capture_retained_artifacts(ROOT)
    for name in ARTIFACT_FILES:
        scan_artifact_bytes(name, artifacts.files[name])


def _validator_source_digest(captured: CapturedArtifacts) -> str:
    return hashlib.sha256(normalized_artifact_bytes("validate.py", captured.files["validate.py"])).hexdigest()


def _validate_pinned_artifacts(captured: CapturedArtifacts) -> None:
    for name, (expected_bytes, expected_digest) in PINNED_RETAINED_ARTIFACTS.items():
        data = captured.files[name]
        require(len(data) == expected_bytes, "pinned retained artifact size changed")
        require(hashlib.sha256(data).hexdigest() == expected_digest, "pinned retained artifact digest changed")
    require(_validator_source_digest(captured) == PINNED_VALIDATOR_SOURCE_SHA256, "pinned validator identity changed")


def percentile(samples: list[float], fraction: float) -> float:
    ordered = sorted(samples)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    return ordered[lower] if lower == upper else ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def distribution(samples: list[float]) -> dict[str, float]:
    return {"min": min(samples), "p50": percentile(samples, .50), "p95": percentile(samples, .95), "p99": percentile(samples, .99), "max": max(samples), "mean": sum(samples) / len(samples)}


def baseline_evidence_bytes(baseline: dict[str, Any]) -> bytes:
    return canonical_json_bytes({key: baseline[key] for key in ("schema", "fixture_id", "samples_per_mode", "unit", "threshold", "environment", "commands", "normal", "optimized", "semantics_sha256")})


def validate_baseline(root: Any, payload: bytes, captured: CapturedArtifacts | None = None) -> None:
    require(hashlib.sha256(payload).hexdigest() == PINNED_BASELINE_SHA256, "benchmark evidence identity changed")
    baseline = exact_keys(root, ("schema", "fixture_id", "samples_per_mode", "unit", "threshold", "environment", "commands", "normal", "optimized", "semantics_sha256", "artifact"), "benchmark root")
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
    strict_equal(baseline["semantics_sha256"], PINNED_SEMANTICS_SHA256, "benchmark semantics identity")
    for mode in ("normal", "optimized"):
        evidence = exact_keys(baseline[mode], ("samples", "distribution"), f"{mode} benchmark evidence")
        samples = evidence["samples"]
        require(type(samples) is list and len(samples) == 30 and all(type(sample) is float and 0 < sample < 60 for sample in samples), f"{mode} samples are invalid")
        actual = exact_keys(evidence["distribution"], ("min", "p50", "p95", "p99", "max", "mean"), f"{mode} distribution")
        for key, expected in distribution(samples).items():
            require(type(actual[key]) is float and abs(actual[key] - expected) <= 1e-12, f"{mode} distribution changed")
    artifacts = captured or _capture_retained_artifacts(ROOT)
    require(hashlib.sha256(baseline_evidence_bytes(baseline)).hexdigest() == PINNED_BASELINE_EVIDENCE_SHA256, "benchmark evidence binding changed")
    _validate_pinned_artifacts(artifacts)
    strict_equal(baseline["artifact"], artifact_manifest(artifacts), "benchmark artifact manifest")


def validate(cases_path: Path = CASES_PATH, *, skip_baseline: bool = False, scan_artifacts: bool = True) -> list[dict[str, Any]]:
    require(cases_path.resolve() == CASES_PATH.resolve(), "cases input must be the canonical artifact")
    captured = _capture_retained_artifacts(ROOT)
    cases_payload = captured.files["cases.json"]
    root = parse_json_bytes(cases_payload)
    require(hashlib.sha256(cases_payload).hexdigest() == PINNED_CASES_SHA256, "fixture identity changed")
    proof_matrix_sha256 = load_reviewed_proof_matrix(ROOT)
    retained = validate_document(root, proof_matrix_sha256)
    if not skip_baseline:
        baseline_payload = captured.files["validation-baseline.json"]
        baseline = parse_json_bytes(baseline_payload)
        validate_baseline(baseline, baseline_payload, captured)
    if scan_artifacts:
        scan_all_artifacts(captured)
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
            candidate = Path(argv[index + 1])
            require(candidate.resolve() == CASES_PATH.resolve(), "cases input must be the canonical artifact")
            cases_path = CASES_PATH
            index += 2
        else:
            raise ValidationError("CLI option is unsupported")
    return cases_path, skip_baseline


def bounded_failure(message: object) -> str:
    text = str(message)
    safe = text if len(text) <= 120 and re.fullmatch(r"[A-Za-z0-9 -]+", text) else "validation failed"
    line = json.dumps({"status": "failure", "reason": safe}, separators=(",", ":"), ensure_ascii=True)
    return line if len(line) <= FAILURE_LIMIT else json.dumps({"status": "failure", "reason": "validation failed"}, separators=(",", ":"))


def main(argv: list[str] | None = None) -> int:
    try:
        cases_path, skip_baseline = parse_cli(list(sys.argv[1:] if argv is None else argv))
        retained = validate(cases_path, skip_baseline=skip_baseline)
        result = {"status": "ok", "fixture_id": "host-origin-mapping-dep-03-f5be9236", "cases": len(retained), "accepted": sum(1 for item in retained if item["upstream_called"]), "rejected": sum(1 for item in retained if not item["upstream_called"]), "synthetic_only": True, "live_claim": False}
        print(json.dumps(result, separators=(",", ":"), ensure_ascii=True))
        return 0
    except Exception as exc:
        print(bounded_failure(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
