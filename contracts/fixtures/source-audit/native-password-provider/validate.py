#!/usr/bin/env python3
"""Validate the frozen native password-provider cookie and ticket contract.

This validator is standard-library-only and offline. It checks strict JSON,
source citations, cookie lifecycle classifications, native REST/WebSocket
credential boundaries, synthetic redaction, and mutation regressions. It never
imports Hermes, opens a socket, or contacts a provider. ``--source-root`` may
point to a pinned Hermes checkout or to a content-only source snapshot.

A Git checkout is immutable evidence only when its commit, tree, source blobs,
and file bytes all match the pinned source metadata. A directory without Git
metadata is deliberately reported as content-only and never as checkout proof.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent
REVISION = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
TREE = "886db5eb1150f819344d67fedc81aef0caab09ff"
MAX_JSON_BYTES = 1024 * 1024
JSON_READ_CHUNK_BYTES = 64 * 1024
MAX_STRING_LENGTH = 16 * 1024
MAX_ARRAY_LENGTH = 256
MAX_OBJECT_KEYS = 64
MAX_JSON_NODES = 4096
MAX_INTEGER_BITS = 4096
MAX_ERROR_MESSAGE_LENGTH = 512

EXPECTED_SOURCE_FILES = {
    "hermes_cli/dashboard_auth/routes.py": {
        "sha256": "d42be557b9b1ba798c038c91246cba0bf046e89ebe34a27db0c7803c517e9c20",
        "git_blob": "0c142963bcc83f38fddbdcec29c35608f14f7bc1",
    },
    "hermes_cli/dashboard_auth/cookies.py": {
        "sha256": "a87cd352864fab9d8fc46ec25efe7d6cc8e58eb92caaa8c82245ea50c4a42b3d",
        "git_blob": "8bcd9db78eb6a8e9209e1b3087ab4e85b8997f1e",
    },
    "plugins/dashboard_auth/basic/__init__.py": {
        "sha256": "81da36adae712bb133d522a5df1d66ccefcf5f9803e7bc90b226d4f096ac4cba",
        "git_blob": "12ec0fe51355caa7f5657d514bbb5513a8318704",
    },
    "hermes_cli/dashboard_auth/ws_tickets.py": {
        "sha256": "b66e29a067002ad8a345b49281d30c75d6ec2bb177d58214611db66925bb4429",
        "git_blob": "118a988e142adf3a904d2a553698b38da22f34fc",
    },
    "hermes_cli/web_server.py": {
        "sha256": "b52cc35523f891b6947fa59ac70516d955e47714877069e5ed3f06544b793c1a",
        "git_blob": "1fb3e6131629e7399ef12de78148ac6e7ec58d34",
    },
}

EXPECTED_EVIDENCE = {
    "basic-provider-capability": (
        "plugins/dashboard_auth/basic/__init__.py",
        "201-259",
        "supports_password = True",
    ),
    "basic-provider-refresh": (
        "plugins/dashboard_auth/basic/__init__.py",
        "273-283",
        "def refresh_session",
    ),
    "password-login-route": (
        "hermes_cli/dashboard_auth/routes.py",
        "650-739",
        '@router.post("/auth/password-login", name="auth_password_login")',
    ),
    "password-login-failures": (
        "hermes_cli/dashboard_auth/routes.py",
        "660-716",
        "status_code=429",
    ),
    "password-login-cookie-tail": (
        "hermes_cli/dashboard_auth/routes.py",
        "727-739",
        "set_session_cookies(",
    ),
    "logout-route": (
        "hermes_cli/dashboard_auth/routes.py",
        "742-770",
        "clear_session_cookies(",
    ),
    "cookie-prefix-selection": (
        "hermes_cli/dashboard_auth/cookies.py",
        "107-145",
        'return f"__Secure-{bare}"',
    ),
    "cookie-setter": (
        "hermes_cli/dashboard_auth/cookies.py",
        "166-212",
        "def set_session_cookies(",
    ),
    "cookie-clearer": (
        "hermes_cli/dashboard_auth/cookies.py",
        "215-237",
        "max_age=0",
    ),
    "ws-ticket-route": (
        "hermes_cli/dashboard_auth/routes.py",
        "799-828",
        "mint_ticket(user_id=sess.user_id, provider=sess.provider)",
    ),
    "ws-ticket-lifetime": (
        "hermes_cli/dashboard_auth/ws_tickets.py",
        "39-42",
        "TTL_SECONDS = 30",
    ),
    "ws-ticket-consume": (
        "hermes_cli/dashboard_auth/ws_tickets.py",
        "81-99",
        "entry = _tickets.pop(ticket, None)",
    ),
    "ws-gated-ticket-policy": (
        "hermes_cli/web_server.py",
        "14644-14725",
        "The legacy ``?token=`` path is unconditionally rejected in gated mode",
    ),
    "ws-gated-ticket-consume": (
        "hermes_cli/web_server.py",
        "14704-14718",
        "consume_ticket(ticket)",
    ),
    "pty-web-only": (
        "hermes_cli/web_server.py",
        "14361-14372",
        "/api/pty — PTY-over-WebSocket bridge",
    ),
}

REQUIRED_CASES = {
    "provider-password-capability",
    "login-success-native-cookie",
    "login-wrong-password",
    "login-unknown-provider",
    "login-provider-unavailable",
    "login-rate-limited",
    "cookie-http-bare",
    "cookie-https-host-prefix",
    "cookie-https-secure-prefix",
    "cookie-refresh-omitted",
    "cookie-app-isolated-store",
    "cookie-expired-access-refresh",
    "cookie-expired-no-refresh",
    "logout-clears-cookie-variants",
    "native-rest-cookie-no-ticket",
    "native-ws-ticket-mint",
    "native-ws-upgrade-ticket-only",
    "native-ws-cookie-direct-denied",
    "native-ws-missing-ticket-denied",
    "native-ws-malformed-ticket-denied",
    "native-ws-expired-ticket-denied",
    "native-ws-reused-ticket-denied",
    "native-ws-legacy-token-denied",
    "native-ws-fresh-ticket-retry",
    "native-pty-route-forbidden",
    "native-no-retained-credentials",
}

FORBIDDEN_KEY_NAMES = {
    "password",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "cookie_value",
    "raw_cookie",
    "raw_ticket",
    "ticket_value",
    "bearer_value",
    "session_token",
}


class ValidationError(AssertionError):
    """A contract fixture assertion failed."""


class DuplicateKeyError(ValidationError):
    """A strict JSON object repeated a key."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def _bounded_error_message(exc: BaseException) -> str:
    """Keep CLI output bounded even when malformed input controls an error."""
    try:
        message = str(exc)
    except Exception:
        return "validation failed"
    if len(message) <= MAX_ERROR_MESSAGE_LENGTH:
        return message
    return message[: MAX_ERROR_MESSAGE_LENGTH - 3] + "..."


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            # Do not echo the duplicate key: it may be attacker-controlled.
            raise DuplicateKeyError("duplicate JSON object key is not allowed")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValidationError("non-finite JSON number is not allowed")


def _bounded_int(value: str) -> int:
    digits = value.lstrip("-")
    require(len(digits) <= MAX_INTEGER_BITS, "JSON integer exceeds the bit limit")
    return int(value)


def _read_bounded_stream(stream: Any, label: str) -> bytes:
    """Read at most the JSON limit plus one byte from an untrusted stream."""
    chunks: list[bytes] = []
    total = 0
    while total <= MAX_JSON_BYTES:
        chunk = stream.read(min(JSON_READ_CHUNK_BYTES, MAX_JSON_BYTES + 1 - total))
        if not chunk:
            return b"".join(chunks)
        require(type(chunk) is bytes, f"strict JSON {label} stream returned non-bytes")
        total += len(chunk)
        if total > MAX_JSON_BYTES:
            raise ValidationError(f"strict JSON {label} exceeds the input byte limit")
        chunks.append(chunk)
    raise ValidationError(f"strict JSON {label} exceeds the input byte limit")


def _scan_json(value: Any, path: str = "$", state: list[int] | None = None) -> None:
    if state is None:
        state = [0]
    state[0] += 1
    require(state[0] <= MAX_JSON_NODES, "strict JSON exceeds the node limit")
    if isinstance(value, dict):
        require(len(value) <= MAX_OBJECT_KEYS, f"{path}: object exceeds key limit")
        for key, child in value.items():
            require(type(key) is str, f"{path}: JSON object key must be a string")
            require(len(key) <= MAX_STRING_LENGTH, f"{path}: object key is too long")
            _scan_json(child, f"{path}.{key}", state)
    elif isinstance(value, list):
        require(len(value) <= MAX_ARRAY_LENGTH, f"{path}: array exceeds length limit")
        for index, child in enumerate(value):
            _scan_json(child, f"{path}[{index}]", state)
    elif type(value) is str:
        require(len(value) <= MAX_STRING_LENGTH, f"{path}: string is too long")
    elif type(value) is int:
        require(value.bit_length() <= MAX_INTEGER_BITS, f"{path}: integer exceeds bit limit")
    elif type(value) is float:
        require(math.isfinite(value), f"{path}: non-finite number is not allowed")
    elif value is None or type(value) is bool:
        return
    else:
        raise ValidationError(f"{path}: unsupported JSON value type")


def load_json(name: str) -> dict[str, Any]:
    path = ROOT / name
    with path.open("rb") as stream:
        raw = _read_bounded_stream(stream, name)
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_int=_bounded_int,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError) as exc:
        raise ValidationError(f"strict JSON {name}: {_bounded_error_message(exc)}") from exc
    _scan_json(value)
    require(isinstance(value, dict), f"{name} must contain a JSON object")
    return value


def exact_keys(value: Any, required: set[str], optional: set[str], label: str) -> None:
    require(isinstance(value, dict), f"{label} must be an object")
    keys = set(value)
    require(required <= keys, f"{label} is missing required keys: {sorted(required - keys)}")
    require(keys <= required | optional, f"{label} has unknown keys: {sorted(keys - required - optional)}")


def parse_lines(value: Any, label: str) -> tuple[int, int]:
    require(isinstance(value, str) and value.strip(), f"{label} must have a non-empty line range")
    match = re.fullmatch(r"(\d+)(?:-(\d+))?", value.strip())
    require(match is not None, f"{label} has invalid line range")
    start = int(match.group(1))
    end = int(match.group(2) or match.group(1))
    require(start > 0 and end >= start, f"{label} has invalid line order")
    return start, end


def normalize_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_")


def validate_synthetic_keys(value: Any, path: str = "$") -> None:
    """Reject fields that could retain credential material, not classifications."""
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = normalize_key(key)
            if normalized in FORBIDDEN_KEY_NAMES:
                # A false boolean is a retention classification, not secret
                # material. Any non-boolean value under these names is rejected.
                require(type(child) is bool and child is False, f"{path}: prohibited sensitive field")
            validate_synthetic_keys(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            validate_synthetic_keys(child, f"{path}[{index}]")
    elif type(value) is str:
        require(not re.search(r"(?i)\b(?:bearer|basic)\s+\S+", value), f"{path}: credential value is not allowed")
        require(not re.search(r"(?i)(?:password|secret|cookie|ticket|token)\s*=\s*[^\s,]+", value), f"{path}: inline credential value is not allowed")


def validate_baseline(audit: dict[str, Any]) -> None:
    baseline = audit.get("validation_baseline")
    exact_keys(baseline, {"measurement", "threshold_ms", "normal", "optimized", "artifact_bytes", "artifacts"}, set(), "validation_baseline")
    require(baseline["measurement"] == "developer_observation", "baseline measurement policy changed")
    require(baseline["threshold_ms"] is None, "baseline must not invent a performance threshold")
    for name in ("normal", "optimized"):
        sample = baseline[name]
        exact_keys(sample, {"samples_ms", "mean_ms"}, set(), f"validation_baseline.{name}")
        require(isinstance(sample["samples_ms"], list), f"baseline {name} samples must be a list")
        require(len(sample["samples_ms"]) <= 64, f"baseline {name} has too many samples")
        for value in sample["samples_ms"]:
            require(type(value) in {int, float} and math.isfinite(value) and value >= 0, f"baseline {name} sample is invalid")
        if sample["samples_ms"]:
            require(type(sample["mean_ms"]) in {int, float} and math.isfinite(sample["mean_ms"]), f"baseline {name} mean is required")
            expected_mean = sum(sample["samples_ms"]) / len(sample["samples_ms"])
            require(abs(sample["mean_ms"] - expected_mean) <= 0.001, f"baseline {name} mean is inconsistent")
        else:
            require(sample["mean_ms"] is None, f"baseline {name} empty samples require null mean")
    artifacts = baseline["artifacts"]
    require(isinstance(artifacts, list), "baseline artifacts must be a list")
    require(type(baseline["artifact_bytes"]) is int and baseline["artifact_bytes"] >= 0, "baseline artifact byte total is invalid")
    artifact_paths = {"README.md", "cases.json", "validate.py", "test_native_password_provider.py"}
    total_bytes = 0
    for item in artifacts:
        exact_keys(item, {"path", "bytes", "sha256"}, set(), "baseline artifact")
        require(isinstance(item["path"], str) and item["path"] in artifact_paths, "baseline artifact path is not fixture-owned")
        require(type(item["bytes"]) is int and item["bytes"] >= 0, "baseline artifact size is invalid")
        require(isinstance(item["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None, "baseline artifact digest is invalid")
        artifact_path = ROOT / item["path"]
        require(artifact_path.is_file(), f"baseline artifact is missing: {item['path']}")
        artifact_bytes = artifact_path.read_bytes()
        require(len(artifact_bytes) == item["bytes"], f"baseline artifact size changed: {item['path']}")
        require(hashlib.sha256(artifact_bytes).hexdigest() == item["sha256"], f"baseline artifact digest changed: {item['path']}")
        total_bytes += item["bytes"]
    if artifacts:
        require({item["path"] for item in artifacts} == artifact_paths, "baseline artifact inventory is incomplete")
    require(baseline["artifact_bytes"] == total_bytes, "baseline artifact byte total is inconsistent")


def validate_source_provenance(audit: dict[str, Any]) -> None:
    exact_keys(audit, {"schema", "contract_version", "hermes_revision", "scope", "source_provenance", "source_evidence", "validation_baseline"}, set(), "source audit")
    require(audit["schema"] == "hermternal.source-audit.native-password-provider.v1", "unexpected audit schema")
    require(audit["contract_version"] == "dashboard-v0.0.1", "unexpected contract version")
    require(audit["hermes_revision"] == REVISION and re.fullmatch(r"[0-9a-f]{40}", audit["hermes_revision"]), "audit revision is not pinned")
    scope = audit["scope"]
    exact_keys(scope, {"platform", "auth_family", "source_checkout", "integration_mode", "fail_closed_unknown_case", "native_cookie_policy", "native_rest_policy", "native_websocket_policy", "native_pty_policy", "ticket_session_binding"}, set(), "audit scope")
    require(scope == {
        "platform": "web_and_native_policy",
        "auth_family": "native_password_cookie_session",
        "source_checkout": "git_checkout_or_content_only_snapshot",
        "integration_mode": "mock_and_proof_only",
        "fail_closed_unknown_case": True,
        "native_cookie_policy": "app_isolated_protected_store",
        "native_rest_policy": "cookie_only_no_ticket",
        "native_websocket_policy": "fresh_single_use_ticket_only",
        "native_pty_policy": "forbidden_web_only_route",
        "ticket_session_binding": "not_assumed",
    }, "audit scope policy changed")

    provenance = audit["source_provenance"]
    exact_keys(provenance, {"pinned_revision", "pinned_tree", "verification", "source_root_modes", "citation_marker_policy", "files"}, set(), "source_provenance")
    require(provenance["pinned_revision"] == REVISION and provenance["pinned_tree"] == TREE, "source provenance pin changed")
    require(provenance["verification"] == "sha256_digests_git_head_tree_and_blob_when_git_metadata_present", "source provenance verification rule changed")
    require(provenance["source_root_modes"] == {
        "git_checkout": "git_head_and_tree_must_equal_pinned_revision",
        "content_only_snapshot": "sha256_only_never_checkout_verified",
    }, "source root mode policy changed")
    require(provenance["citation_marker_policy"] == "marker_must_occur_in_cited_source_range_when_source_root_is_supplied", "citation marker policy changed")

    files = provenance["files"]
    require(isinstance(files, list) and len(files) == len(EXPECTED_SOURCE_FILES), "source provenance files are incomplete")
    actual: dict[str, dict[str, str]] = {}
    for item in files:
        exact_keys(item, {"path", "sha256", "git_blob"}, set(), "source provenance file")
        path = item["path"]
        require(isinstance(path, str) and path not in actual, f"duplicate source provenance path: {path}")
        require(isinstance(item["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]), f"invalid source digest: {path}")
        require(isinstance(item["git_blob"], str) and re.fullmatch(r"[0-9a-f]{40}", item["git_blob"]), f"invalid source blob: {path}")
        actual[path] = {"sha256": item["sha256"], "git_blob": item["git_blob"]}
    require(actual == EXPECTED_SOURCE_FILES, "source provenance inventory changed")

    evidence = audit["source_evidence"]
    require(isinstance(evidence, list) and len(evidence) == len(EXPECTED_EVIDENCE), "source evidence inventory is incomplete")
    seen: set[str] = set()
    for record in evidence:
        exact_keys(record, {"id", "file", "lines", "marker", "claim"}, set(), "source evidence record")
        evidence_id = record["id"]
        require(isinstance(evidence_id, str) and evidence_id not in seen, f"duplicate source evidence id: {evidence_id}")
        seen.add(evidence_id)
        require(evidence_id in EXPECTED_EVIDENCE, f"unknown source evidence id: {evidence_id}")
        expected_file, expected_lines, expected_marker = EXPECTED_EVIDENCE[evidence_id]
        require(record["file"] == expected_file, f"source evidence file changed: {evidence_id}")
        require(record["lines"] == expected_lines, f"source evidence range changed: {evidence_id}")
        require(record["marker"] == expected_marker, f"source evidence marker changed: {evidence_id}")
        parse_lines(record["lines"], f"source evidence {evidence_id}")
        require(isinstance(record["claim"], str) and record["claim"], f"source evidence claim missing: {evidence_id}")
    require(seen == set(EXPECTED_EVIDENCE), "source evidence inventory changed")
    validate_baseline(audit)


def evidence_map(audit: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {record["id"]: record for record in audit["source_evidence"]}


def validate_source_markers(audit: dict[str, Any], source_root: Path) -> None:
    evidence = evidence_map(audit)
    source_lines: dict[str, list[str]] = {}
    for evidence_id, (_file, _lines, marker) in EXPECTED_EVIDENCE.items():
        record = evidence[evidence_id]
        source_path = source_root / record["file"]
        require(source_path.is_file(), f"source marker file is missing: {record['file']}")
        if record["file"] not in source_lines:
            source_lines[record["file"]] = source_path.read_text(encoding="utf-8").splitlines()
        start, end = parse_lines(record["lines"], f"source evidence {evidence_id}")
        require(end <= len(source_lines[record["file"]]), f"source evidence range exceeds file: {evidence_id}")
        cited_text = "\n".join(source_lines[record["file"]][start - 1:end])
        require(marker in cited_text, f"source marker is absent from cited source text: {evidence_id}")


def _git(source_root: Path, *args: str) -> str:
    try:
        result = subprocess.run(["git", "-C", str(source_root), *args], check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValidationError("source Git metadata could not be verified") from exc
    return result.stdout.strip()


def verify_source_root(audit: dict[str, Any], source_root: Path) -> tuple[int, str]:
    files = audit["source_provenance"]["files"]
    git_metadata = source_root / ".git"
    if git_metadata.exists():
        head = _git(source_root, "rev-parse", "--verify", "HEAD^{commit}")
        require(head == REVISION, f"source Git HEAD {head!r} does not equal pinned revision")
        tree = _git(source_root, "rev-parse", "--verify", "HEAD^{tree}")
        require(tree == TREE, f"source Git tree {tree!r} does not equal pinned tree")
        require(_git(source_root, "cat-file", "-t", f"{REVISION}^{{commit}}") == "commit", "pinned revision is not a commit object")
        provenance = "git_checkout_verified"
    else:
        provenance = "content_only_snapshot"

    verified = 0
    for item in files:
        path = source_root / item["path"]
        require(path.is_file(), f"pinned source file is missing: {item['path']}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        require(digest == item["sha256"], f"pinned source digest mismatch: {item['path']}")
        if git_metadata.exists():
            blob = _git(source_root, "rev-parse", "--verify", f"{REVISION}:{item['path']}")
            require(blob == item["git_blob"], f"pinned source blob mismatch: {item['path']}")
            require(_git(source_root, "cat-file", "-t", blob) == "blob", f"pinned source object is not a blob: {item['path']}")
        verified += 1
    validate_source_markers(audit, source_root)
    return verified, provenance


def _validate_login(case_id: str, request: dict[str, Any], expected: dict[str, Any]) -> None:
    exact_keys(request, {"method", "path", "provider_state", "credential_state", "transport", "cookie_store"}, set(), case_id + ".request")
    exact_keys(expected, {"http_status", "session_cookie", "refresh_cookie", "provider_cookie", "password_retained"}, {"error_shape", "rest_auth"}, case_id + ".expected")
    require(type(expected["http_status"]) is int and type(expected["password_retained"]) is bool, f"{case_id}: login result types changed")
    require(request["method"] == "POST" and request["path"] == "/auth/password-login", f"{case_id}: login route changed")
    require(request["transport"] == "https" and request["cookie_store"] == "native_isolated", f"{case_id}: native login transport/store changed")
    state = request["credential_state"]
    require(request["provider_state"] in {"registered_password", "unknown", "unavailable"}, f"{case_id}: invalid provider state")
    expected_shape = {
        "valid": (200, "issued", "issued", "issued", None),
        "wrong_password": (401, "absent", "absent", "absent", "generic_invalid_credentials"),
        "not_attempted": (404 if request["provider_state"] == "unknown" else 503, "absent", "absent", "absent", "generic_unknown_provider" if request["provider_state"] == "unknown" else "provider_unreachable"),
        "rate_limited": (429, "absent", "absent", "absent", "rate_limited"),
    }
    require(state in expected_shape, f"{case_id}: invalid credential state")
    status, access, refresh, provider, error_shape = expected_shape[state]
    require(expected["http_status"] == status, f"{case_id}: login status changed")
    require((expected["session_cookie"], expected["refresh_cookie"], expected["provider_cookie"]) == (access, refresh, provider), f"{case_id}: cookie issuance changed")
    require(expected["password_retained"] is False, f"{case_id}: password retention is not fail-closed")
    if error_shape is not None:
        require(expected.get("error_shape") == error_shape, f"{case_id}: error shape changed")
    else:
        require(expected.get("rest_auth") == "native_cookie", f"{case_id}: successful login must hand off to native cookie REST")


def _validate_cookie(case_id: str, request: dict[str, Any], expected: dict[str, Any]) -> None:
    if case_id in {"cookie-http-bare", "cookie-https-host-prefix", "cookie-https-secure-prefix"}:
        exact_keys(request, {"transport", "deployment", "cookie_store"}, {"path_prefix"}, case_id + ".request")
        exact_keys(expected, {"access_name", "refresh_name", "provider_name", "secure", "httponly", "samesite", "path", "domain"}, set(), case_id + ".expected")
        require(all(type(expected[name]) is str for name in ("access_name", "refresh_name", "provider_name", "samesite", "path", "domain")), f"{case_id}: cookie text types changed")
        require(type(expected["secure"]) is bool and type(expected["httponly"]) is bool, f"{case_id}: cookie flag types changed")
        require(request["cookie_store"] == "native_isolated", f"{case_id}: store is not native isolated")
        require(expected["httponly"] is True and expected["samesite"] == "lax" and expected["domain"] == "absent", f"{case_id}: cookie hardening changed")
        require(expected["secure"] is (request["transport"] == "https"), f"{case_id}: Secure policy changed")
        if case_id == "cookie-http-bare":
            require(request == {"transport": "http", "deployment": "direct", "cookie_store": "native_isolated"}, f"{case_id}: request changed")
            prefix = ""
            path = "/"
        elif case_id == "cookie-https-host-prefix":
            require(request == {"transport": "https", "deployment": "direct", "cookie_store": "native_isolated"}, f"{case_id}: request changed")
            prefix = "__Host-"
            path = "/"
        else:
            require(request["transport"] == "https" and request["deployment"] == "prefixed" and isinstance(request.get("path_prefix"), str) and request["path_prefix"].startswith("/"), f"{case_id}: prefix deployment changed")
            prefix = "__Secure-"
            path = request["path_prefix"]
        require(expected["access_name"] == prefix + "hermes_session_at", f"{case_id}: access cookie name changed")
        require(expected["refresh_name"] == prefix + "hermes_session_rt", f"{case_id}: refresh cookie name changed")
        require(expected["provider_name"] == prefix + "hermes_session_provider", f"{case_id}: provider cookie name changed")
        require(expected["path"] == path, f"{case_id}: cookie path changed")
        return
    if case_id == "cookie-refresh-omitted":
        exact_keys(request, {"transport", "deployment", "refresh_material", "cookie_store"}, set(), case_id + ".request")
        exact_keys(expected, {"access_cookie", "refresh_cookie", "provider_cookie", "session_mode"}, set(), case_id + ".expected")
        require(request == {"transport": "https", "deployment": "direct", "refresh_material": "provider_omits_refresh", "cookie_store": "native_isolated"}, f"{case_id}: request changed")
        require(expected == {"access_cookie": "issued", "refresh_cookie": "not_written", "provider_cookie": "issued", "session_mode": "access_only_until_expiry"}, f"{case_id}: omitted refresh behavior changed")
        return
    raise ValidationError(f"unknown cookie case: {case_id}")


def _validate_case(case: dict[str, Any]) -> None:
    exact_keys(case, {"id", "kind", "request", "expected"}, set(), "case")
    case_id = case["id"]
    kind = case["kind"]
    request = case["request"]
    expected = case["expected"]
    require(isinstance(case_id, str) and case_id in REQUIRED_CASES, f"unknown case id: {case_id}")
    require(isinstance(kind, str) and isinstance(request, dict) and isinstance(expected, dict), f"malformed case: {case_id}")

    if kind == "provider":
        exact_keys(request, {"provider_state", "capability", "oauth_redirect"}, set(), case_id + ".request")
        exact_keys(expected, {"provider", "decision", "oauth_redirect"}, set(), case_id + ".expected")
        require(type(expected["oauth_redirect"]) is bool, f"{case_id}: provider flag type changed")
        require(request == {"provider_state": "registered_password", "capability": "supports_password", "oauth_redirect": "absent"}, f"{case_id}: provider handoff changed")
        require(expected == {"provider": "basic", "decision": "password_login_eligible", "oauth_redirect": False}, f"{case_id}: provider decision changed")
    elif kind == "login":
        _validate_login(case_id, request, expected)
    elif kind == "cookie":
        _validate_cookie(case_id, request, expected)
    elif kind == "isolation":
        exact_keys(request, {"client", "cookie_store", "browser_store"}, set(), case_id + ".request")
        exact_keys(expected, {"cookie_store_decision", "shared_browser_store_used", "password_persisted", "cookie_copied_to_keychain", "cookie_copied_to_logs"}, set(), case_id + ".expected")
        require(all(type(expected[name]) is bool for name in ("shared_browser_store_used", "password_persisted", "cookie_copied_to_keychain", "cookie_copied_to_logs")), f"{case_id}: isolation flag types changed")
        require(request == {"client": "native", "cookie_store": "app_isolated_protected", "browser_store": "shared_browser_store"}, f"{case_id}: isolation request changed")
        require(expected == {"cookie_store_decision": "use_app_isolated_protected_store", "shared_browser_store_used": False, "password_persisted": False, "cookie_copied_to_keychain": False, "cookie_copied_to_logs": False}, f"{case_id}: isolation decision changed")
    elif case_id == "cookie-expired-access-refresh":
        exact_keys(request, {"session_state", "cookie_store", "operation"}, set(), case_id + ".request")
        exact_keys(expected, {"decision", "ticket_on_rest", "store_remains_isolated"}, set(), case_id + ".expected")
        require(type(expected["ticket_on_rest"]) is bool and type(expected["store_remains_isolated"]) is bool, f"{case_id}: refresh flag types changed")
        require(request == {"session_state": "access_expired_refresh_valid", "cookie_store": "native_isolated", "operation": "reviewed_rest_request"}, f"{case_id}: refresh request changed")
        require(expected == {"decision": "refresh_then_retry_with_cookie", "ticket_on_rest": False, "store_remains_isolated": True}, f"{case_id}: refresh decision changed")
    elif case_id == "cookie-expired-no-refresh":
        exact_keys(request, {"session_state", "cookie_store", "operation"}, set(), case_id + ".request")
        exact_keys(expected, {"http_status", "decision", "clear_cookie_store", "ticket_on_rest"}, set(), case_id + ".expected")
        require(type(expected["http_status"]) is int and type(expected["clear_cookie_store"]) is bool and type(expected["ticket_on_rest"]) is bool, f"{case_id}: expiry result types changed")
        require(request == {"session_state": "access_expired_refresh_expired", "cookie_store": "native_isolated", "operation": "reviewed_rest_request"}, f"{case_id}: expiry request changed")
        require(expected == {"http_status": 401, "decision": "fail_closed_and_clear_store", "clear_cookie_store": True, "ticket_on_rest": False}, f"{case_id}: expiry decision changed")
    elif case_id == "logout-clears-cookie-variants":
        exact_keys(request, {"method", "path", "cookie_store", "deployment"}, set(), case_id + ".request")
        exact_keys(expected, {"redirect", "clear_cookie_store", "max_age", "deleted_variants", "deleted_cookie_families"}, set(), case_id + ".expected")
        require(type(expected["clear_cookie_store"]) is bool and type(expected["max_age"]) is int, f"{case_id}: logout result scalar types changed")
        require(type(expected["deleted_variants"]) is list and type(expected["deleted_cookie_families"]) is list, f"{case_id}: logout result list types changed")
        require(all(type(value) is str for value in expected["deleted_variants"] + expected["deleted_cookie_families"]), f"{case_id}: logout result text types changed")
        require(request == {"method": "POST", "path": "/auth/logout", "cookie_store": "native_isolated", "deployment": "any_reviewed_shape"}, f"{case_id}: logout request changed")
        require(expected == {"redirect": "login", "clear_cookie_store": True, "max_age": 0, "deleted_variants": ["bare", "__Host-", "__Secure-"], "deleted_cookie_families": ["access", "refresh", "provider"]}, f"{case_id}: logout deletion changed")
    elif case_id == "native-rest-cookie-no-ticket":
        exact_keys(request, {"method", "path", "cookie_state", "bearer_state", "ws_ticket_state"}, set(), case_id + ".request")
        exact_keys(expected, {"auth_source", "http_status", "ticket_on_rest", "cookie_store"}, set(), case_id + ".expected")
        require(type(expected["ticket_on_rest"]) is bool, f"{case_id}: REST flag type changed")
        require(request == {"method": "GET", "path": "/api/auth/me", "cookie_state": "valid_native_password_cookie", "bearer_state": "absent", "ws_ticket_state": "absent"}, f"{case_id}: REST request changed")
        require(expected == {"auth_source": "native_password_cookie", "http_status": "handler_dependent", "ticket_on_rest": False, "cookie_store": "app_isolated_protected"}, f"{case_id}: REST cookie policy changed")
    elif case_id == "native-ws-ticket-mint":
        exact_keys(request, {"method", "path", "cookie_state", "bearer_state", "cookie_store"}, set(), case_id + ".request")
        exact_keys(expected, {"auth_source", "ticket_issuance", "ttl_seconds", "ticket_persisted", "ticket_logged"}, set(), case_id + ".expected")
        require(type(expected["ttl_seconds"]) is int and type(expected["ticket_persisted"]) is bool and type(expected["ticket_logged"]) is bool, f"{case_id}: ticket result types changed")
        require(request == {"method": "POST", "path": "/api/auth/ws-ticket", "cookie_state": "valid_native_password_cookie", "bearer_state": "absent", "cookie_store": "app_isolated_protected"}, f"{case_id}: ticket mint request changed")
        require(expected == {"auth_source": "native_password_cookie", "ticket_issuance": "fresh_single_use", "ttl_seconds": 30, "ticket_persisted": False, "ticket_logged": False}, f"{case_id}: ticket mint policy changed")
    elif kind == "ws_upgrade":
        _validate_ws_upgrade(case_id, request, expected)
    elif kind == "native_policy":
        exact_keys(request, {"client", "path", "operation"}, set(), case_id + ".request")
        exact_keys(expected, {"decision", "native_allowed", "fresh_ticket_rule"}, set(), case_id + ".expected")
        require(type(expected["native_allowed"]) is bool, f"{case_id}: native policy flag type changed")
        require(request == {"client": "native", "path": "/api/pty", "operation": "websocket_upgrade"}, f"{case_id}: PTY request changed")
        require(expected == {"decision": "must_not_invoke_web_only_route", "native_allowed": False, "fresh_ticket_rule": "not_applicable"}, f"{case_id}: PTY policy changed")
    elif kind == "retention":
        exact_keys(request, {"evidence_surface"}, set(), case_id + ".request")
        exact_keys(expected, {"password", "cookie_contents", "refresh_material", "bearer", "ticket", "ticket_fragment", "callback_url", "provider_state"}, set(), case_id + ".expected")
        require(request == {"evidence_surface": "fixture_logs_links_history_source_control"}, f"{case_id}: retention surface changed")
        require(all(value is False for value in expected.values()), f"{case_id}: retained sensitive material is not fail-closed")
    else:
        raise ValidationError(f"unsupported case kind: {kind}")


def _validate_ws_upgrade(case_id: str, request: dict[str, Any], expected: dict[str, Any]) -> None:
    require(request.get("path") == "/api/ws" and request.get("auth_mode") == "gated", f"{case_id}: gated chat WebSocket shape changed")
    if case_id == "native-ws-upgrade-ticket-only":
        exact_keys(request, {"method", "path", "auth_mode", "ticket_state", "cookie_state", "query_credential"}, set(), case_id + ".request")
        exact_keys(expected, {"decision", "credential_source", "cookie_on_upgrade", "ticket_consumed_once"}, set(), case_id + ".expected")
        require(type(expected["cookie_on_upgrade"]) is bool and type(expected["ticket_consumed_once"]) is bool, f"{case_id}: acceptance flag types changed")
        require(request == {"method": "GET", "path": "/api/ws", "auth_mode": "gated", "ticket_state": "fresh_single_use", "cookie_state": "not_sent", "query_credential": "ticket_only"}, f"{case_id}: request changed")
        require(expected == {"decision": "accept", "credential_source": "ephemeral_ticket", "cookie_on_upgrade": False, "ticket_consumed_once": True}, f"{case_id}: acceptance policy changed")
    elif case_id in {"native-ws-cookie-direct-denied", "native-ws-missing-ticket-denied", "native-ws-legacy-token-denied"}:
        exact_keys(request, {"method", "path", "auth_mode", "ticket_state", "cookie_state", "query_credential"}, set(), case_id + ".request")
        exact_keys(expected, {"decision", "credential_source", "cookie_on_upgrade"}, set(), case_id + ".expected")
        require(type(expected["cookie_on_upgrade"]) is bool, f"{case_id}: rejection flag type changed")
        if case_id == "native-ws-cookie-direct-denied":
            required_request = {"method": "GET", "path": "/api/ws", "auth_mode": "gated", "ticket_state": "absent", "cookie_state": "valid_native_password_cookie", "query_credential": "none"}
        elif case_id == "native-ws-missing-ticket-denied":
            required_request = {"method": "GET", "path": "/api/ws", "auth_mode": "gated", "ticket_state": "missing", "cookie_state": "not_sent", "query_credential": "none"}
        else:
            required_request = {"method": "GET", "path": "/api/ws", "auth_mode": "gated", "ticket_state": "absent", "cookie_state": "not_sent", "query_credential": "legacy_token"}
        require(request == required_request, f"{case_id}: request changed")
        required_decision = "reject_legacy_token_in_gated_mode" if case_id == "native-ws-legacy-token-denied" else "reject_missing_credential"
        require(expected == {"decision": required_decision, "credential_source": "none", "cookie_on_upgrade": False}, f"{case_id}: rejection policy changed")
    elif case_id in {"native-ws-malformed-ticket-denied", "native-ws-expired-ticket-denied", "native-ws-reused-ticket-denied"}:
        exact_keys(request, {"method", "path", "auth_mode", "ticket_state", "cookie_state", "query_credential"}, set(), case_id + ".request")
        exact_keys(expected, {"decision", "credential_source", "cookie_on_upgrade", "ticket_consumed_once"}, set(), case_id + ".expected")
        require(type(expected["cookie_on_upgrade"]) is bool and type(expected["ticket_consumed_once"]) is bool, f"{case_id}: rejection flag types changed")
        state = {"native-ws-malformed-ticket-denied": "malformed", "native-ws-expired-ticket-denied": "expired", "native-ws-reused-ticket-denied": "reused"}[case_id]
        require(request == {"method": "GET", "path": "/api/ws", "auth_mode": "gated", "ticket_state": state, "cookie_state": "not_sent", "query_credential": "ticket_only"}, f"{case_id}: request changed")
        decision = {"malformed": "reject_invalid_ticket", "expired": "reject_expired_ticket", "reused": "reject_unknown_or_reused_ticket"}[state]
        consumed = state == "reused"
        require(expected == {"decision": decision, "credential_source": "ephemeral_ticket", "cookie_on_upgrade": False, "ticket_consumed_once": consumed}, f"{case_id}: rejection policy changed")
    elif case_id == "native-ws-fresh-ticket-retry":
        exact_keys(request, {"path", "auth_mode", "first_ticket_state", "replacement_ticket_state", "cookie_state", "query_credential"}, set(), case_id + ".request")
        exact_keys(expected, {"first_upgrade", "replacement_upgrade", "same_ticket_reused", "cookie_on_upgrade"}, set(), case_id + ".expected")
        require(type(expected["same_ticket_reused"]) is bool and type(expected["cookie_on_upgrade"]) is bool, f"{case_id}: retry flag types changed")
        require(request == {"path": "/api/ws", "auth_mode": "gated", "first_ticket_state": "consumed", "replacement_ticket_state": "fresh_single_use", "cookie_state": "not_sent", "query_credential": "ticket_only"}, f"{case_id}: request changed")
        require(expected == {"first_upgrade": "one_use_only", "replacement_upgrade": "accept", "same_ticket_reused": False, "cookie_on_upgrade": False}, f"{case_id}: fresh retry policy changed")
    else:
        raise ValidationError(f"unknown WebSocket case: {case_id}")


def validate_cases(cases_doc: dict[str, Any]) -> int:
    exact_keys(cases_doc, {"schema", "contract_version", "hermes_revision", "fixture_policy", "cases"}, set(), "cases document")
    require(cases_doc["schema"] == "hermternal.source-audit.native-password-provider.cases.v1", "unexpected cases schema")
    require(cases_doc["contract_version"] == "dashboard-v0.0.1" and cases_doc["hermes_revision"] == REVISION, "cases are not pinned")
    require(cases_doc["fixture_policy"] == "synthetic_markers_only", "fixture policy changed")
    cases = cases_doc["cases"]
    require(isinstance(cases, list) and cases, "cases must be a non-empty list")
    ids: set[str] = set()
    for case in cases:
        require(isinstance(case, dict), "each case must be an object")
        case_id = case.get("id")
        require(isinstance(case_id, str) and case_id not in ids, f"duplicate or invalid case id: {case_id}")
        ids.add(case_id)
        _validate_case(case)
        validate_synthetic_keys(case)
    require(ids == REQUIRED_CASES, "required C-03 case inventory changed")
    return len(cases)


def expect_rejected(label: str, callback: Callable[[], None]) -> None:
    try:
        callback()
    except ValidationError:
        return
    raise ValidationError(f"mutation was accepted: {label}")


def validate_mutation_regressions(audit: dict[str, Any], cases: dict[str, Any]) -> int:
    mutations = 0

    audit_marker = copy.deepcopy(audit)
    audit_marker["source_evidence"][0]["marker"] = "supports_password = False"
    expect_rejected("source marker rebinding", lambda: validate_source_provenance(audit_marker))
    mutations += 1

    audit_digest = copy.deepcopy(audit)
    audit_digest["source_provenance"]["files"][0]["sha256"] = "0" * 64
    expect_rejected("source digest mutation", lambda: validate_source_provenance(audit_digest))
    mutations += 1

    audit_tree = copy.deepcopy(audit)
    audit_tree["source_provenance"]["pinned_tree"] = "0" * 40
    expect_rejected("source tree mutation", lambda: validate_source_provenance(audit_tree))
    mutations += 1

    artifact_mutation = copy.deepcopy(audit)
    artifact_mutation["validation_baseline"]["artifacts"][0]["sha256"] = "0" * 64
    expect_rejected("baseline artifact digest mutation", lambda: validate_source_provenance(artifact_mutation))
    mutations += 1

    login_mutation = copy.deepcopy(cases)
    login_case = next(item for item in login_mutation["cases"] if item["id"] == "login-success-native-cookie")
    login_case["expected"]["http_status"] = 401
    expect_rejected("successful password login status mutation", lambda: validate_cases(login_mutation))
    mutations += 1

    isolation_mutation = copy.deepcopy(cases)
    isolation_case = next(item for item in isolation_mutation["cases"] if item["id"] == "cookie-app-isolated-store")
    isolation_case["expected"]["shared_browser_store_used"] = True
    expect_rejected("shared browser cookie store", lambda: validate_cases(isolation_mutation))
    mutations += 1

    ticket_mutation = copy.deepcopy(cases)
    ticket_case = next(item for item in ticket_mutation["cases"] if item["id"] == "native-ws-reused-ticket-denied")
    ticket_case["expected"]["decision"] = "accept"
    expect_rejected("reused WebSocket ticket accepted", lambda: validate_cases(ticket_mutation))
    mutations += 1

    expiry_mutation = copy.deepcopy(cases)
    expiry_case = next(item for item in expiry_mutation["cases"] if item["id"] == "native-ws-expired-ticket-denied")
    expiry_case["expected"]["decision"] = "accept"
    expect_rejected("expired WebSocket ticket accepted", lambda: validate_cases(expiry_mutation))
    mutations += 1

    retention_mutation = copy.deepcopy(cases)
    retention_case = next(item for item in retention_mutation["cases"] if item["id"] == "native-no-retained-credentials")
    retention_case["expected"]["ticket"] = True
    expect_rejected("retained ticket evidence", lambda: validate_cases(retention_mutation))
    mutations += 1

    unknown_key = copy.deepcopy(cases)
    unknown_key["cases"][0]["request"]["raw_ticket"] = "synthetic"
    expect_rejected("unknown sensitive request field", lambda: validate_cases(unknown_key))
    mutations += 1

    return mutations


def artifact_inventory() -> list[dict[str, Any]]:
    paths = ["README.md", "cases.json", "source_audit.json", "validate.py", "test_native_password_provider.py"]
    return [
        {"path": name, "bytes": (ROOT / name).stat().st_size, "sha256": hashlib.sha256((ROOT / name).read_bytes()).hexdigest()}
        for name in paths
    ]


def artifact_size() -> int:
    return sum(item["bytes"] for item in artifact_inventory())


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, help="optional pinned Hermes checkout or content snapshot root")
    args = parser.parse_args(argv)
    started = time.perf_counter()
    try:
        audit = load_json("source_audit.json")
        cases = load_json("cases.json")
        validate_source_provenance(audit)
        case_count = validate_cases(cases)
        mutation_count = validate_mutation_regressions(audit, cases)
        provenance = "metadata_only"
        verified_files = 0
        if args.source_root is not None:
            verified_files, root_mode = verify_source_root(audit, args.source_root)
            provenance = f"{root_mode},source_files_verified={verified_files}"
        duration_ms = (time.perf_counter() - started) * 1000
        print(
            "native password-provider audit valid: "
            f"revision={REVISION} cases={case_count} mutations={mutation_count} "
            f"provenance={provenance} duration_ms={duration_ms:.3f} artifact_bytes={artifact_size()}"
        )
    except (ValidationError, OSError, UnicodeError) as exc:
        raise SystemExit(_bounded_error_message(exc)) from exc


if __name__ == "__main__":
    main()
