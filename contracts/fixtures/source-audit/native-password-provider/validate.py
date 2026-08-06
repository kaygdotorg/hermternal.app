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
import os
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
MAX_JSON_DEPTH = 256
MAX_INTEGER_BITS = 4096
MAX_ERROR_MESSAGE_LENGTH = 512
MAX_SOURCE_BLOB_BYTES = 16 * 1024 * 1024
SAFE_ERROR_MESSAGE = "native password-provider audit validation failed"

# Do not inherit Git's ambient object/config/working-tree redirects. The
# source-root proof must describe the supplied checkout, not a caller's
# environment or a replacement/lazy-fetch view of it.
_GIT_REDIRECT_KEYS = {
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_GLOBAL",
    "GIT_DIR",
    "GIT_GRAFT_FILE",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_REPLACE_REF_BASE",
    "GIT_SHALLOW_FILE",
    "GIT_WORK_TREE",
}

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
    "hermes_cli/dashboard_auth/audit.py": {
        "sha256": "c566a10a6c18b27debd3787e0072e1b25fc661d0c55cda0ffcb098ae02d35690",
        "git_blob": "937fa95a75ba9ecbe37d48b2b9d0858ffd2809de",
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
    "password-login-body-auth-scheme": (
        "hermes_cli/dashboard_auth/routes.py",
        "692-695",
        "password=body.password",
    ),
    "password-provider-error-detail": (
        "hermes_cli/dashboard_auth/routes.py",
        "709-716",
        "detail=f\"Provider unreachable: {e}\"",
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
    "ws-ticket-route-session-auth": (
        "hermes_cli/dashboard_auth/routes.py",
        "799-828",
        "sess = getattr(request.state, \"session\", None)",
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
    "ws-ticket-fragment-source": (
        "hermes_cli/dashboard_auth/ws_tickets.py",
        "92-95",
        "truncated = (ticket[:8] + \"…\") if ticket else \"<empty>\"",
    ),
    "ws-ticket-audit-forward": (
        "hermes_cli/web_server.py",
        "14708-14716",
        "reason=str(exc),",
    ),
    "audit-log-field-redaction": (
        "hermes_cli/dashboard_auth/audit.py",
        "71-87",
        "if k not in _REDACTED_FIELDS",
    ),
    "pty-web-only": (
        "hermes_cli/web_server.py",
        "14361-14372",
        "/api/pty — PTY-over-WebSocket bridge",
    ),
}

REQUIRED_CASES = {
    "provider-password-capability",
    "basic-provider-not-http-basic",
    "login-success-native-cookie",
    "native-login-no-http-basic",
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
    "native-rest-no-http-basic",
    "native-ws-ticket-mint",
    "native-ws-ticket-no-http-basic",
    "native-ws-upgrade-ticket-only",
    "native-ws-upgrade-no-http-basic",
    "native-ws-cookie-direct-denied",
    "native-ws-missing-ticket-denied",
    "native-ws-malformed-ticket-denied",
    "native-ws-expired-ticket-denied",
    "native-ws-reused-ticket-denied",
    "native-ws-legacy-token-denied",
    "native-ws-fresh-ticket-retry",
    "native-pty-route-forbidden",
    "native-no-retained-credentials",
    "native-ws-ticket-fragment-no-retention",
    "native-provider-error-no-retention",
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

_SAFE_CASE_ID_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_JWT_RE = re.compile(r"[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
_SCHEME_VALUE_RE = re.compile(
    r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"
)
_BASIC_HEADER_RE = re.compile(
    r"(?i)\bauthorization\s*:\s*basic\s+[A-Za-z0-9._~+/=-]{8,}"
)
_COOKIE_HEADER_RE = re.compile(
    r"(?i)\bcookie\s*:\s*[A-Za-z0-9._~+/=-]{8,}"
)
_NAMED_SECRET_RE = re.compile(
    r"(?i)\b(?:authorization|cookie|ticket|token|password|secret|"
    r"access[_ -]?token|refresh[_ -]?token)\s*[:=]\s*"
    r"[A-Za-z0-9._~+/=-]{8,}"
)
_RAW_SECRET_PATH_RE = re.compile(
    r"(?i)(?:file://|/(?:users|home|private|tmp|var|srv|etc|opt|root)/|"
    r"[a-z]:[\\\\/]|\\\\\\\\)"
)
# Source and retained diagnostics use both labels; block either form before
# it can reach history, logs, or the DOM.
_TICKET_FRAGMENT_RE = re.compile(
    r"(?i)\b(?:unknown ticket|ticket fragment)\s*[:=]\s*"
    r"[A-Za-z0-9_-]{8,}(?:…|\b)"
)
_PROVIDER_EXCEPTION_RE = re.compile(
    r"(?i)\bprovider\s+unreachable\s*:\s*"
    r"(?!\{[A-Za-z_][A-Za-z0-9_]*\})(?:\S+)"
)
_AUTHORIZATION_HEADER_RE = re.compile(
    r"(?i)\bauthorization\s*:\s*"
    r"(?:[A-Za-z][A-Za-z0-9_-]*\s+)?[A-Za-z0-9._~+/=-]{8,}"
)
_TICKET_VALUE_RE = re.compile(
    r"(?i)\bticket\s*[:=]\s*[A-Za-z0-9_-]{8,}(?:…|\b)"
)

# These are the fixture's retained-equivalent surfaces. Their raw bytes are
# additionally bound to code-pinned canonical digests so a caller cannot edit
# a README, case, or audit claim and then recompute only self-authored metadata.
RETAINED_ARTIFACT_PATHS = ("README.md", "cases.json", "source_audit.json")
EXPECTED_CANONICAL_ARTIFACTS = {
    "README.md": {"bytes": 7817, "sha256": "dd48adfdf5f29efa95e0c2e597ab135ef7dd756c946053ecc7d2ae8dc65c8b5b"},
    "cases.json": {"bytes": 13939, "sha256": "961cb83fc91f32fdb4b969d47620b8ca9cbaa4a05bf4006b18239e2b7864ffcf"},
    "source_audit.json": {"bytes": 8071, "sha256": "ac754edef22fc4f2eaee8e20c9c1fcc006e960b0283bbfdce888df0fc655c164"},
    "test_native_password_provider.py": {"bytes": 16437, "sha256": "08ab58022f90cac2adfb457be02ef1811ecf57e469f74cbfc130fea3aa7aaffb"},
}
_RETAINED_TEXT_PATTERNS = (
    _SCHEME_VALUE_RE,
    _BASIC_HEADER_RE,
    _COOKIE_HEADER_RE,
    _AUTHORIZATION_HEADER_RE,
    _PROVIDER_EXCEPTION_RE,
    _TICKET_FRAGMENT_RE,
    _TICKET_VALUE_RE,
    _RAW_SECRET_PATH_RE,
)


def validate_untrusted_text(value: Any, *, identifier: bool = False) -> None:
    """Reject secrets, paths, and token-shaped claims before retention."""
    require(type(value) is str and "\x00" not in value, "unsafe text")
    if identifier:
        require(_SAFE_CASE_ID_RE.fullmatch(value) is not None, "unsafe identifier")
    require(_JWT_RE.search(value) is None, "credential-shaped text")
    require(_SCHEME_VALUE_RE.search(value) is None, "credential-shaped text")
    require(_BASIC_HEADER_RE.search(value) is None, "credential-shaped text")
    require(_COOKIE_HEADER_RE.search(value) is None, "credential-shaped text")
    require(_AUTHORIZATION_HEADER_RE.search(value) is None, "credential-shaped text")
    require(_NAMED_SECRET_RE.search(value) is None, "credential-shaped text")
    require(_PROVIDER_EXCEPTION_RE.search(value) is None, "provider exception text")
    require(_TICKET_FRAGMENT_RE.search(value) is None, "ticket fragment")
    require(_TICKET_VALUE_RE.search(value) is None, "ticket value")
    require(_RAW_SECRET_PATH_RE.search(value) is None, "absolute source path")


class ValidationError(AssertionError):
    """A contract fixture assertion failed."""


class DuplicateKeyError(ValidationError):
    """A strict JSON object repeated a key."""


def require(condition: bool, message: str) -> None:
    """Raise one fixed error so untrusted labels never reach diagnostics."""
    if not condition:
        raise ValidationError(SAFE_ERROR_MESSAGE)


def _bounded_error_message(exc: BaseException) -> str:
    """Return a bounded, source- and credential-redacted CLI error."""
    # JSON parser text, Git stderr, case IDs, source claims, and paths can all
    # be attacker-controlled. A fixed message is safer than trying to classify
    # every future parser or subprocess error at the presentation boundary.
    return SAFE_ERROR_MESSAGE[:MAX_ERROR_MESSAGE_LENGTH]


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
            raise ValidationError(SAFE_ERROR_MESSAGE)
        chunks.append(chunk)
    raise ValidationError(SAFE_ERROR_MESSAGE)


def _scan_json(value: Any, path: str = "$", state: list[int] | None = None) -> None:
    """Scan parsed JSON without using Python recursion on attacker depth."""
    if state is None:
        state = [0]
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        state[0] += 1
        require(state[0] <= MAX_JSON_NODES, "strict JSON exceeds the node limit")
        require(depth <= MAX_JSON_DEPTH, "strict JSON exceeds the nesting limit")
        if isinstance(current, dict):
            require(len(current) <= MAX_OBJECT_KEYS, "strict JSON object exceeds the key limit")
            for key, child in reversed(list(current.items())):
                require(type(key) is str, "strict JSON object key must be a string")
                require(len(key) <= MAX_STRING_LENGTH, "strict JSON object key is too long")
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            require(len(current) <= MAX_ARRAY_LENGTH, "strict JSON array exceeds the length limit")
            for child in reversed(current):
                stack.append((child, depth + 1))
        elif type(current) is str:
            require(len(current) <= MAX_STRING_LENGTH, "strict JSON string is too long")
        elif type(current) is int:
            require(current.bit_length() <= MAX_INTEGER_BITS, "strict JSON integer exceeds the bit limit")
        elif type(current) is float:
            require(math.isfinite(current), "strict JSON number is not finite")
        elif current is None or type(current) is bool:
            continue
        else:
            raise ValidationError(SAFE_ERROR_MESSAGE)


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
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValidationError, ValueError) as exc:
        raise ValidationError(SAFE_ERROR_MESSAGE) from exc
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
            validate_untrusted_text(key)
            normalized = normalize_key(key)
            if normalized in FORBIDDEN_KEY_NAMES:
                # A false boolean is a retention classification, not secret
                # material. Any non-boolean value under these names is rejected.
                require(type(child) is bool and child is False, "prohibited sensitive field")
            validate_synthetic_keys(child, path)
    elif isinstance(value, list):
        for child in value:
            validate_synthetic_keys(child, path)
    elif type(value) is str:
        validate_untrusted_text(value)


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


def _canonical_artifact_bytes(name: str, raw: bytes) -> bytes:
    """Normalize only self-authored timing metadata before canonical hashing."""
    if name != "source_audit.json":
        return raw
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_int=_bounded_int,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValidationError, ValueError) as exc:
        raise ValidationError(SAFE_ERROR_MESSAGE) from exc
    require(isinstance(value, dict), "canonical source audit must be an object")
    value = copy.deepcopy(value)
    # Baseline timings and raw artifact metadata are observations, not the
    # immutable source/retention evidence. Ignore only that self-authored block.
    value["validation_baseline"] = {"canonicalized": True}
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def validate_immutable_artifacts() -> None:
    """Bind retained fixture artifacts to digests outside mutable JSON metadata."""
    for name, expected in EXPECTED_CANONICAL_ARTIFACTS.items():
        path = ROOT / name
        require(path.is_file() and not path.is_symlink(), "canonical fixture artifact is missing")
        try:
            canonical = _canonical_artifact_bytes(name, path.read_bytes())
        except OSError as exc:
            raise ValidationError(SAFE_ERROR_MESSAGE) from exc
        require(len(canonical) == expected["bytes"], "canonical fixture artifact size changed")
        require(hashlib.sha256(canonical).hexdigest() == expected["sha256"], "canonical fixture artifact digest changed")


def validate_retained_artifacts() -> None:
    """Reject provider, ticket, and authorization values on retained surfaces."""
    for name in RETAINED_ARTIFACT_PATHS:
        path = ROOT / name
        require(path.is_file() and not path.is_symlink(), "retained fixture artifact is missing")
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise ValidationError(SAFE_ERROR_MESSAGE) from exc
        require("\x00" not in text, "retained artifact contains a control character")
        for pattern in _RETAINED_TEXT_PATTERNS:
            require(pattern.search(text) is None, "retained artifact contains sensitive text")


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
    require(provenance["verification"] == "git_head_tree_complete_blob_reads_and_sha256_when_git_metadata_present", "source provenance verification rule changed")
    require(provenance["source_root_modes"] == {
        "git_checkout": "exact_non_bare_clean_checkout_with_local_metadata_and_pinned_commit_tree",
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
        validate_untrusted_text(record["claim"])
    require(seen == set(EXPECTED_EVIDENCE), "source evidence inventory changed")
    validate_immutable_artifacts()
    validate_retained_artifacts()
    validate_baseline(audit)


def evidence_map(audit: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {record["id"]: record for record in audit["source_evidence"]}


def validate_source_markers(
    audit: dict[str, Any],
    source_root: Path,
    source_texts: dict[str, str] | None = None,
) -> None:
    evidence = evidence_map(audit)
    source_lines: dict[str, list[str]] = {}
    for evidence_id, (_file, _lines, marker) in EXPECTED_EVIDENCE.items():
        record = evidence[evidence_id]
        source_path = source_root / record["file"]
        require(source_path.is_file(), "source marker file is missing")
        if record["file"] not in source_lines:
            if source_texts is not None:
                require(record["file"] in source_texts, "source marker blob is missing")
                text = source_texts[record["file"]]
            else:
                text = source_path.read_text(encoding="utf-8")
            source_lines[record["file"]] = text.splitlines()
        start, end = parse_lines(record["lines"], "source evidence range")
        require(end <= len(source_lines[record["file"]]), "source evidence range exceeds file")
        cited_text = "\n".join(source_lines[record["file"]][start - 1:end])
        require(marker in cited_text, "source marker is absent from cited source text")


def _git_env(source_root: Path) -> dict[str, str]:
    """Build a neutral Git environment for source-root attestation."""
    env = dict(os.environ)
    # Remove every inherited Git config/object/work-tree redirect, including
    # numbered config pairs. Restore only neutral values below.
    for key in list(env):
        if key.startswith("GIT_") or key in _GIT_REDIRECT_KEYS:
            env.pop(key, None)
    env.update({
        "HOME": str(source_root),
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_COUNT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
    })
    return env


def _git_bytes(source_root: Path, *args: str, input_data: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(source_root), *args],
            check=True,
            capture_output=True,
            input=input_data,
            env=_git_env(source_root),
            timeout=15,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise ValidationError(SAFE_ERROR_MESSAGE) from exc
    require(type(result.stdout) is bytes, "Git returned non-bytes output")
    return result.stdout


def _git(source_root: Path, *args: str) -> str:
    try:
        return _git_bytes(source_root, *args).decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise ValidationError(SAFE_ERROR_MESSAGE) from exc


def _git_optional(source_root: Path, *args: str) -> str | None:
    """Read optional local Git config without hiding command failures."""
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(source_root), *args],
            check=False,
            capture_output=True,
            env=_git_env(source_root),
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValidationError(SAFE_ERROR_MESSAGE) from exc
    if result.returncode == 1 and not result.stdout and not result.stderr:
        return None
    if result.returncode != 0:
        raise ValidationError(SAFE_ERROR_MESSAGE)
    try:
        return result.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise ValidationError(SAFE_ERROR_MESSAGE) from exc


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _reject_nested_git_symlinks(git_dir: Path, source_root: Path) -> None:
    """Reject every symlink below local Git metadata, including objects/refs."""
    pending = [git_dir]
    while pending:
        current = pending.pop()
        try:
            with os.scandir(current) as entries:
                children = list(entries)
        except OSError as exc:
            raise ValidationError(SAFE_ERROR_MESSAGE) from exc
        for entry in children:
            child = Path(entry.path)
            require(not entry.is_symlink(), "nested Git metadata symlinks are not allowed")
            try:
                resolved = child.resolve(strict=False)
            except OSError as exc:
                raise ValidationError(SAFE_ERROR_MESSAGE) from exc
            require(_within(resolved, source_root), "nested Git metadata escapes source root")
            try:
                if entry.is_dir(follow_symlinks=False):
                    pending.append(child)
            except OSError as exc:
                raise ValidationError(SAFE_ERROR_MESSAGE) from exc


def _reject_repository_local_alternates(source_root: Path) -> Path:
    """Require checkout-style metadata rooted inside the supplied checkout."""
    marker = source_root / ".git"
    require(not marker.is_symlink(), "Git metadata must not be a symlink")
    require(marker.is_dir() or marker.is_file(), "source root is not a checkout")
    if marker.is_dir():
        git_dir = marker.resolve()
    else:
        try:
            lines = marker.read_text(encoding="ascii").splitlines()
        except (OSError, UnicodeError) as exc:
            raise ValidationError(SAFE_ERROR_MESSAGE) from exc
        require(len(lines) == 1 and lines[0].startswith("gitdir:"), "invalid Git metadata")
        raw_git_dir = lines[0][7:].strip()
        require(raw_git_dir and not Path(raw_git_dir).is_absolute(), "linked Git metadata is not allowed")
        git_dir = (source_root / raw_git_dir).resolve()
    require(_within(git_dir, source_root) and git_dir.is_dir(), "Git metadata escapes source root")
    require(all((git_dir / name).is_file() and not (git_dir / name).is_symlink() for name in ("HEAD", "config", "index")), "checkout metadata is incomplete")
    objects = git_dir / "objects"
    refs = git_dir / "refs"
    require(objects.is_dir() and not objects.is_symlink(), "checkout objects are invalid")
    require(refs.is_dir() and not refs.is_symlink(), "checkout refs are invalid")
    _reject_nested_git_symlinks(git_dir, source_root)

    # A linked worktree can redirect its common object/ref metadata outside
    # the supplied root. It is not an attested standalone checkout.
    commondir = git_dir / "commondir"
    if commondir.exists() or commondir.is_symlink():
        require(not commondir.is_symlink() and commondir.is_file(), "linked Git metadata is not allowed")
        raw_common = commondir.read_text(encoding="ascii").strip()
        common_dir = (git_dir / raw_common).resolve()
        require(_within(common_dir, source_root) and common_dir.is_dir(), "common Git metadata escapes source root")

    for name in ("alternates", "http-alternates"):
        alternate = objects / "info" / name
        require(not alternate.exists() and not alternate.is_symlink(), "Git object alternates are not allowed")
    return git_dir


def _reject_bare_shape(source_root: Path) -> None:
    """Reject bare and disguised-bare roots before treating them as snapshots."""
    marker = source_root / ".git"
    if marker.exists() or marker.is_symlink():
        return
    bare_markers = (source_root / "HEAD", source_root / "config", source_root / "objects", source_root / "refs")
    require(not all(path.exists() for path in bare_markers), "bare Git roots are not allowed")
    for ancestor in source_root.parents:
        require(not (ancestor / ".git").exists(), "source root must be the checkout top-level")


def _verify_git_checkout(source_root: Path, git_dir: Path, files: list[dict[str, Any]]) -> dict[str, bytes]:
    require(_git(source_root, "rev-parse", "--show-toplevel") == str(source_root), "source root is not the checkout top-level")
    require(_git(source_root, "rev-parse", "--is-bare-repository") == "false", "bare Git roots are not allowed")
    bare_setting = _git_optional(source_root, "config", "--local", "--get", "core.bare")
    require(bare_setting in {None, "false", "False", "0", "no"}, "checkout is configured as bare")
    worktree_setting = _git_optional(source_root, "config", "--local", "--get", "core.worktree")
    if worktree_setting:
        worktree = Path(worktree_setting)
        resolved_worktree = (git_dir / worktree if not worktree.is_absolute() else worktree).resolve()
        require(resolved_worktree == source_root, "checkout worktree is redirected")
    require(_git(source_root, "status", "--porcelain=v2", "--untracked-files=all", "--ignored=matching") == "", "source checkout is not clean")
    require(_git(source_root, "for-each-ref", "--format=%(refname)", "refs/replace") == "", "Git replacement refs are not allowed")
    require(_git_optional(source_root, "config", "--local", "--get-regexp", r"^extensions\.partialClone$") in {None, ""}, "lazy Git fetch is not allowed")
    require(_git_optional(source_root, "config", "--local", "--get-regexp", r"^remote\..*\.promisor$") in {None, ""}, "promisor Git objects are not allowed")

    head = _git(source_root, "rev-parse", "--verify", "HEAD^{commit}")
    require(head == REVISION, "source Git revision is not pinned")
    tree = _git(source_root, "rev-parse", "--verify", f"{head}^{{tree}}")
    require(tree == TREE, "source Git tree is not pinned")
    require(_git(source_root, "cat-file", "-t", head) == "commit", "pinned revision is not a commit object")
    require(_git(source_root, "cat-file", "-t", tree) == "tree", "pinned tree is not a tree object")

    requested_paths = [item["path"] for item in files]
    tree_listing = _git_bytes(source_root, "ls-tree", "-r", "-z", "--full-tree", head, "--", *requested_paths)
    entries: dict[str, tuple[bytes, bytes, bytes]] = {}
    for record in tree_listing.split(b"\0"):
        if not record:
            continue
        try:
            header, path_bytes = record.split(b"\t", 1)
            mode, object_type, object_id = header.split(b" ", 2)
            path = path_bytes.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValidationError(SAFE_ERROR_MESSAGE) from exc
        require(path not in entries, "duplicate Git tree entry")
        entries[path] = (mode, object_type, object_id)
    require(set(entries) == set(requested_paths), "pinned source tree inventory changed")

    immutable: dict[str, bytes] = {}
    for item in files:
        path_name = item["path"]
        mode, object_type, object_id = entries[path_name]
        require(mode == b"100644" and object_type == b"blob", "pinned source object type changed")
        require(object_id.decode("ascii") == item["git_blob"], "pinned source blob is not pinned")
        request = object_id + b"\n"
        batch = _git_bytes(source_root, "cat-file", "--batch", input_data=request)
        try:
            header, payload = batch.split(b"\n", 1)
            returned_id, kind, size_text = header.split(b" ", 2)
            size = int(size_text)
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValidationError(SAFE_ERROR_MESSAGE) from exc
        require(kind == b"blob" and returned_id == object_id and 0 <= size <= MAX_SOURCE_BLOB_BYTES, "Git blob header is invalid")
        require(len(payload) == size + 1 and payload[-1:] == b"\n", "Git blob read was incomplete")
        blob = payload[:size]
        require(hashlib.sha256(blob).hexdigest() == item["sha256"], "pinned source blob digest changed")
        immutable[path_name] = blob
    return immutable


def verify_source_root(audit: dict[str, Any], source_root: Path) -> tuple[int, str]:
    files = audit["source_provenance"]["files"]
    try:
        source_root = source_root.resolve(strict=True)
    except OSError as exc:
        raise ValidationError(SAFE_ERROR_MESSAGE) from exc
    require(source_root.is_dir() and source_root.name != ".git", "source root must be a directory")
    marker = source_root / ".git"
    has_checkout_metadata = marker.exists() or marker.is_symlink()
    immutable: dict[str, bytes] | None = None
    if has_checkout_metadata:
        git_dir = _reject_repository_local_alternates(source_root)
        immutable = _verify_git_checkout(source_root, git_dir, files)
        provenance = "git_checkout_verified"
    else:
        _reject_bare_shape(source_root)
        provenance = "content_only_snapshot"

    verified = 0
    source_texts: dict[str, str] = {}
    for item in files:
        path = source_root / item["path"]
        require(not path.is_symlink() and path.is_file(), "pinned source file is missing")
        working = path.read_bytes()
        digest = hashlib.sha256(working).hexdigest()
        require(digest == item["sha256"], "pinned source digest mismatch")
        if immutable is not None:
            require(working == immutable[item["path"]], "working tree differs from pinned blob")
            source_bytes = immutable[item["path"]]
        else:
            source_bytes = working
        try:
            source_texts[item["path"]] = source_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValidationError(SAFE_ERROR_MESSAGE) from exc
        verified += 1
    validate_source_markers(audit, source_root, source_texts)
    return verified, provenance


def _validate_login(case_id: str, request: dict[str, Any], expected: dict[str, Any]) -> None:
    exact_keys(request, {"method", "path", "provider_state", "credential_state", "transport", "cookie_store", "auth_scheme"}, set(), case_id + ".request")
    exact_keys(expected, {"http_status", "session_cookie", "refresh_cookie", "provider_cookie", "password_retained", "http_authorization_basic"}, {"error_shape", "rest_auth"}, case_id + ".expected")
    require(type(expected["http_status"]) is int and type(expected["password_retained"]) is bool and type(expected["http_authorization_basic"]) is bool, f"{case_id}: login result types changed")
    require(request["method"] == "POST" and request["path"] == "/auth/password-login", f"{case_id}: login route changed")
    require(request["transport"] == "https" and request["cookie_store"] == "native_isolated" and request["auth_scheme"] == "password_form", f"{case_id}: native login transport/store/auth scheme changed")
    require(expected["http_authorization_basic"] is False, f"{case_id}: HTTP Basic login fallback appeared")
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
    raise ValidationError(SAFE_ERROR_MESSAGE)


def _validate_case(case: dict[str, Any]) -> None:
    exact_keys(case, {"id", "kind", "request", "expected"}, set(), "case")
    case_id = case["id"]
    kind = case["kind"]
    request = case["request"]
    expected = case["expected"]
    validate_untrusted_text(case_id, identifier=True)
    require(case_id in REQUIRED_CASES, "unknown case id")
    require(isinstance(kind, str) and isinstance(request, dict) and isinstance(expected, dict), f"malformed case: {case_id}")

    if kind == "provider":
        exact_keys(request, {"provider_state", "capability", "oauth_redirect"}, set(), case_id + ".request")
        exact_keys(expected, {"provider", "decision", "oauth_redirect"}, set(), case_id + ".expected")
        require(type(expected["oauth_redirect"]) is bool, f"{case_id}: provider flag type changed")
        require(request == {"provider_state": "registered_password", "capability": "supports_password", "oauth_redirect": "absent"}, f"{case_id}: provider handoff changed")
        require(expected == {"provider": "basic", "decision": "password_login_eligible", "oauth_redirect": False}, f"{case_id}: provider decision changed")
    elif kind == "auth_scheme":
        _validate_auth_scheme(case_id, request, expected)
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
        exact_keys(request, {"method", "path", "cookie_state", "bearer_state", "ws_ticket_state", "auth_scheme", "authorization_header"}, set(), case_id + ".request")
        exact_keys(expected, {"auth_source", "http_status", "ticket_on_rest", "cookie_store", "http_authorization_basic"}, set(), case_id + ".expected")
        require(type(expected["ticket_on_rest"]) is bool and type(expected["http_authorization_basic"]) is bool, f"{case_id}: REST flag type changed")
        require(request == {"method": "GET", "path": "/api/auth/me", "cookie_state": "valid_native_password_cookie", "bearer_state": "absent", "ws_ticket_state": "absent", "auth_scheme": "session_cookie", "authorization_header": "absent"}, f"{case_id}: REST request changed")
        require(expected == {"auth_source": "native_password_cookie", "http_status": "handler_dependent", "ticket_on_rest": False, "cookie_store": "app_isolated_protected", "http_authorization_basic": False}, f"{case_id}: REST cookie policy changed")
    elif case_id == "native-ws-ticket-mint":
        exact_keys(request, {"method", "path", "cookie_state", "bearer_state", "cookie_store", "auth_scheme", "authorization_header"}, set(), case_id + ".request")
        exact_keys(expected, {"auth_source", "ticket_issuance", "ttl_seconds", "ticket_persisted", "ticket_logged", "http_authorization_basic"}, set(), case_id + ".expected")
        require(type(expected["ttl_seconds"]) is int and type(expected["ticket_persisted"]) is bool and type(expected["ticket_logged"]) is bool and type(expected["http_authorization_basic"]) is bool, f"{case_id}: ticket result types changed")
        require(request == {"method": "POST", "path": "/api/auth/ws-ticket", "cookie_state": "valid_native_password_cookie", "bearer_state": "absent", "cookie_store": "app_isolated_protected", "auth_scheme": "session_cookie", "authorization_header": "absent"}, f"{case_id}: ticket mint request changed")
        require(expected == {"auth_source": "native_password_cookie", "ticket_issuance": "fresh_single_use", "ttl_seconds": 30, "ticket_persisted": False, "ticket_logged": False, "http_authorization_basic": False}, f"{case_id}: ticket mint policy changed")
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
    elif kind == "retention_source":
        _validate_source_retention(case_id, request, expected)
    else:
        raise ValidationError(SAFE_ERROR_MESSAGE)


def _validate_auth_scheme(case_id: str, request: dict[str, Any], expected: dict[str, Any]) -> None:
    """Keep provider names separate from HTTP Authorization schemes."""
    if case_id == "basic-provider-not-http-basic":
        exact_keys(request, {"provider", "operation", "provider_auth_scheme", "authorization_header"}, set(), "auth scheme request")
        exact_keys(expected, {"provider_auth_scheme", "http_authorization_basic", "decision"}, set(), "auth scheme expected")
        require(request == {"provider": "basic", "operation": "password_login", "provider_auth_scheme": "password_form", "authorization_header": "absent"}, "provider auth scheme changed")
        require(expected == {"provider_auth_scheme": "password_form", "http_authorization_basic": False, "decision": "provider_name_never_selects_http_basic"}, "provider/HTTP auth distinction changed")
        return
    if case_id == "native-login-no-http-basic":
        exact_keys(request, {"method", "path", "provider", "auth_scheme", "authorization_header"}, set(), "login auth scheme request")
        exact_keys(expected, {"http_authorization_basic", "session_result"}, set(), "login auth scheme expected")
        require(request == {"method": "POST", "path": "/auth/password-login", "provider": "basic", "auth_scheme": "password_form", "authorization_header": "absent"}, "password login auth scheme changed")
        require(expected == {"http_authorization_basic": False, "session_result": "shared_session_cookie_only_on_success"}, "password login HTTP Basic fallback appeared")
        return
    if case_id == "native-rest-no-http-basic":
        exact_keys(request, {"method", "path", "auth_scheme", "cookie_state", "bearer_state", "authorization_header"}, set(), "REST auth scheme request")
        exact_keys(expected, {"http_authorization_basic", "auth_source"}, set(), "REST auth scheme expected")
        require(request == {"method": "GET", "path": "/api/auth/me", "auth_scheme": "session_cookie", "cookie_state": "valid_native_password_cookie", "bearer_state": "absent", "authorization_header": "absent"}, "REST auth scheme changed")
        require(expected == {"http_authorization_basic": False, "auth_source": "native_password_cookie"}, "REST HTTP Basic fallback appeared")
        return
    if case_id == "native-ws-ticket-no-http-basic":
        exact_keys(request, {"method", "path", "auth_scheme", "cookie_state", "authorization_header"}, set(), "ticket auth scheme request")
        exact_keys(expected, {"http_authorization_basic", "ticket_source"}, set(), "ticket auth scheme expected")
        require(request == {"method": "POST", "path": "/api/auth/ws-ticket", "auth_scheme": "session_cookie", "cookie_state": "valid_native_password_cookie", "authorization_header": "absent"}, "ticket acquisition auth scheme changed")
        require(expected == {"http_authorization_basic": False, "ticket_source": "authenticated_session_cookie"}, "ticket HTTP Basic fallback appeared")
        return
    if case_id == "native-ws-upgrade-no-http-basic":
        exact_keys(request, {"method", "path", "auth_scheme", "query_credential", "authorization_header"}, set(), "upgrade auth scheme request")
        exact_keys(expected, {"http_authorization_basic", "credential_source"}, set(), "upgrade auth scheme expected")
        require(request == {"method": "GET", "path": "/api/ws", "auth_scheme": "query_ticket", "query_credential": "ticket_only", "authorization_header": "absent"}, "WebSocket upgrade auth scheme changed")
        require(expected == {"http_authorization_basic": False, "credential_source": "ephemeral_ticket_only"}, "WebSocket HTTP Basic fallback appeared")
        return
    raise ValidationError("unknown auth-scheme case")


def _validate_source_retention(case_id: str, request: dict[str, Any], expected: dict[str, Any]) -> None:
    if case_id == "native-ws-ticket-fragment-no-retention":
        exact_keys(request, {"source_flow", "forwarded_surface", "source_evidence"}, set(), "ticket retention request")
        exact_keys(expected, {"ticket_fragment", "history", "logs", "dom"}, set(), "ticket retention expected")
        require(request == {"source_flow": "ws_tickets_ticket_prefix_fragment", "forwarded_surface": "web_server_audit_reason", "source_evidence": ["ws-ticket-fragment-source", "ws-ticket-audit-forward", "audit-log-field-redaction"]}, "ticket fragment source path changed")
        require(expected == {"ticket_fragment": False, "history": False, "logs": False, "dom": False}, "ticket fragment retention is not fail-closed")
        return
    if case_id == "native-provider-error-no-retention":
        exact_keys(request, {"source_flow", "forwarded_surface", "source_evidence"}, set(), "provider error retention request")
        exact_keys(expected, {"provider_exception_text", "history", "logs", "dom"}, set(), "provider error retention expected")
        require(request == {"source_flow": "password_login_provider_exception", "forwarded_surface": "503_detail", "source_evidence": ["password-provider-error-detail"]}, "provider error source path changed")
        require(expected == {"provider_exception_text": False, "history": False, "logs": False, "dom": False}, "provider exception retention is not fail-closed")
        return
    raise ValidationError("unknown source-retention case")


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
        raise ValidationError(SAFE_ERROR_MESSAGE)


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
        require(isinstance(case_id, str), "invalid case id")
        validate_untrusted_text(case_id, identifier=True)
        require(case_id not in ids, "duplicate case id")
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
    raise ValidationError(SAFE_ERROR_MESSAGE)


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

    injected_case_id = copy.deepcopy(cases)
    injected_case_id["cases"][0]["id"] = "case\nAuthorization: Basic dGVzdC1jcmVk"
    expect_rejected("attacker case identifier", lambda: validate_cases(injected_case_id))
    mutations += 1

    basic_fallback = copy.deepcopy(cases)
    basic_case = next(item for item in basic_fallback["cases"] if item["id"] == "native-login-no-http-basic")
    basic_case["expected"]["http_authorization_basic"] = True
    expect_rejected("HTTP Basic login fallback", lambda: validate_cases(basic_fallback))
    mutations += 1

    fragment_retention = copy.deepcopy(cases)
    fragment_case = next(item for item in fragment_retention["cases"] if item["id"] == "native-ws-ticket-fragment-no-retention")
    fragment_case["expected"]["logs"] = True
    expect_rejected("ticket fragment retained in logs", lambda: validate_cases(fragment_retention))
    mutations += 1

    provider_error_retention = copy.deepcopy(cases)
    provider_error_case = next(item for item in provider_error_retention["cases"] if item["id"] == "native-provider-error-no-retention")
    provider_error_case["expected"]["dom"] = True
    expect_rejected("provider exception retained in DOM", lambda: validate_cases(provider_error_retention))
    mutations += 1

    claim_mutation = copy.deepcopy(audit)
    claim_mutation["source_evidence"][0]["claim"] = "Authorization: Basic dGVzdC1jcmVk"
    expect_rejected("credential-shaped source claim", lambda: validate_source_provenance(claim_mutation))
    mutations += 1

    provider_claim_mutation = copy.deepcopy(audit)
    provider_record = next(item for item in provider_claim_mutation["source_evidence"] if item["id"] == "password-provider-error-detail")
    provider_record["claim"] = "Provider unreachable: synthetic-provider-exception"
    expect_rejected("provider exception source claim", lambda: validate_source_provenance(provider_claim_mutation))
    mutations += 1

    ticket_claim_mutation = copy.deepcopy(audit)
    ticket_record = next(item for item in ticket_claim_mutation["source_evidence"] if item["id"] == "ws-ticket-fragment-source")
    ticket_record["claim"] = "unknown ticket: Abcdefgh…"
    expect_rejected("ticket fragment source claim", lambda: validate_source_provenance(ticket_claim_mutation))
    mutations += 1

    authorization_claim_mutation = copy.deepcopy(audit)
    authorization_record = next(item for item in authorization_claim_mutation["source_evidence"] if item["id"] == "password-login-body-auth-scheme")
    authorization_record["claim"] = "Authorization: Basic dGVzdC1jcmVk"
    expect_rejected("authorization source claim", lambda: validate_source_provenance(authorization_claim_mutation))
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
    except (RecursionError, ValidationError, OSError, UnicodeError) as exc:
        raise SystemExit(_bounded_error_message(exc)) from exc


if __name__ == "__main__":
    main()
