#!/usr/bin/env python3
"""Validate the language-neutral Hermternal fixture registry offline.

This validator checks the aggregate registry, its language-neutral schema, every
listed artifact digest, and the observed benchmark evidence. It never imports or
runs a fixture validator, starts Hermes, opens a socket, follows a URL, or makes a
network request. Domain-specific validators remain responsible for their own
case semantics; this layer proves that the shared inventory is complete,
synthetic, redacted, deterministic, and safe to consume from Python, TypeScript,
and Swift.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import math
import os
import re
import stat
import statistics
import subprocess
import sys
import tokenize
import types
from dataclasses import dataclass
import unicodedata
from pathlib import Path
from typing import Any, Iterable, Iterator
from urllib.parse import urlsplit


FIXTURES_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = FIXTURES_ROOT.parents[1]
INDEX_PATH = FIXTURES_ROOT / "index.json"
SCHEMA_PATH = FIXTURES_ROOT / "schema.json"
BASELINE_PATH = FIXTURES_ROOT / "validator" / "validation-baseline.json"

INDEX_SCHEMA = "hermternal.fixture-index.v1"
SCHEMA_DOCUMENT_ID = "https://hermternal.invalid/schema/fixture-index.v1.json"
BASELINE_SCHEMA = "hermternal.fixture-validator-baseline.v1"
CONTRACT = "dashboard-v0.0.1"
HERMES_SOURCE_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"

PLATFORMS = ("web", "ios", "ipados", "macos")
STATE_IDS = ("pending", "empty", "success", "failure", "cancelled", "unknown")

INDEX_KEYS = (
    "schema",
    "contract",
    "hermes_source_sha",
    "synthetic_only",
    "live_claim",
    "evidence_status",
    "fixture_roots",
    "coverage",
    "parity",
    "states",
    "redaction",
    "benchmark",
)
SCHEMA_KEYS = (
    "$schema",
    "$id",
    "title",
    "type",
    "additionalProperties",
    "required",
    "properties",
    "$defs",
)
FIXTURE_KEYS = (
    "id",
    "path",
    "status",
    "contract",
    "hermes_source_sha",
    "synthetic_only",
    "live_claim",
    "platforms",
    "states",
    "coverage_ids",
    "validator",
    "files",
)
FILE_KEYS = ("path", "sha256", "size_bytes")
COVERAGE_KEYS = ("id", "status", "fixture_ids", "platforms", "required_states", "notes")
PARITY_KEYS = (
    "status",
    "fixture_source",
    "platforms",
    "pty_policy",
    "missing_result_policy",
    "result_equivalence",
    "live_claim",
)
STATE_KEYS = ("id", "evidence_state", "gate_decision", "safe_state", "retry_policy")
REDACTION_KEYS = (
    "synthetic_only",
    "contains_credentials",
    "contains_cookies",
    "contains_bearer_values",
    "contains_ticket_values",
    "contains_raw_pty_bytes",
    "contains_transcripts",
    "contains_live_hosts",
    "contains_user_data",
    "failure_output",
)
BENCHMARK_KEYS = ("path", "threshold", "evidence_mode", "build_mode")
BASELINE_KEYS = (
    "schema",
    "fixture_schema",
    "validator",
    "synthetic_only",
    "build_mode",
    "threshold",
    "environment",
    "artifact_manifest",
    "artifact_size_bytes",
    "normal",
    "optimized",
    "notes",
)
MEASUREMENT_KEYS = ("command", "repetitions", "samples_ms", "distribution_ms")
DISTRIBUTION_KEYS = ("min", "p50", "p95", "max", "mean")

MAX_JSON_BYTES = 512 * 1024
MAX_ARTIFACT_BYTES = 512 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 8 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 200_000
MAX_JSON_STRING_LENGTH = 4_096
MAX_JSON_KEY_LENGTH = 256
# Filesystem inventory is metadata too. Bound cardinality and retained path
# storage independently of artifact byte budgets so empty entries cannot consume
# unbounded Python lists/sets before a later content check runs.
MAX_FIXTURE_TRAVERSAL_ENTRIES = 2_048
MAX_FIXTURE_TRAVERSAL_DIRECTORIES = 512
MAX_FIXTURE_TRAVERSAL_FILES = 1_024
MAX_FIXTURE_TRAVERSAL_DEPTH = 64
MAX_FIXTURE_PATH_STORAGE_BYTES = 512 * 1024
MAX_INTEGER_DIGITS = 100
MAX_INTEGER = 10**MAX_INTEGER_DIGITS - 1
MAX_ERROR_LENGTH = 240
BASELINE_REPETITIONS = 30
SCANNED_ARTIFACT_SUFFIXES = frozenset({".json", ".md", ".py", ".txt"})
# This trust anchor authenticates the canonical observed baseline content. The
# canonicalizer omits only this validator's own manifest digest and derived byte
# total, which would otherwise create a self-referential hash cycle.
BASELINE_SELF_MANIFEST_PATH = "contracts/fixtures/validator/validate.py"
CENTRAL_VALIDATOR_SOURCE_PATHS = frozenset({
    "contracts/fixtures/validator/test_validate.py",
    "contracts/fixtures/validator/validate.py",
})
CENTRAL_VALIDATOR_ARTIFACTS = frozenset({
    "validator/test_validate.py",
    "validator/validate.py",
    "validator/validation-baseline.json",
})
# This reviewed digest is authority for its domain fixture, not a canonical
# fixture root. Keep the exemption exact so another review-anchor artifact still
# fails the aggregate unindexed-file boundary.
INTENTIONALLY_SEPARATE_ARTIFACTS = frozenset({
    "review-anchors/deep-link-resolution.sha256",
})
# The historical final authority remains immutable evidence. Corrected scanner
# bytes use a distinct path introduced after a new source predecessor; the old
# path cannot be overwritten because its introduction commit is fixed forever.
HISTORICAL_VALIDATOR_AUTHORITY_PATH = "scripts/fixture_registry_authority.v2.final.json"
VALIDATOR_AUTHORITY_PATH = "scripts/fixture_registry_authority.v2.hardened.json"
VALIDATOR_AUTHORITY_SCHEMA = "hermternal.fixture-registry-authority.v2"
VALIDATOR_AUTHORITY_ROLE = "aggregate_predecessor"
# These historical pins are external to the authority JSON and anchor the new
# rotation to the reviewed chain without attempting a self-referential intro hash.
EXPECTED_HISTORICAL_AUTHORITY_COMMIT = "285acdcf9c11c049180a7844e689eee0f1490de4"
EXPECTED_HISTORICAL_SOURCE_COMMIT = "263cb75adcf153d6fe252636b064e5fbc3e3f877"
# The active rotation is pinned by the protected runtime environment rather
# than by source bytes that would need to contain their own future commit OID.
# Missing or malformed pins fail closed; they are never inferred from HEAD.
ACTIVE_AUTHORITY_COMMIT_ENV = "HERMTERNAL_FIXTURE_AUTHORITY_COMMIT"
ACTIVE_SOURCE_COMMIT_ENV = "HERMTERNAL_FIXTURE_AUTHORITY_SOURCE_COMMIT"
# The standalone verifier is executed only after its exact bytes are captured
# through a stable descriptor and match this source-level pin. It is not imported
# by path, so a checkout edit cannot execute before authentication.
HARDENED_AUTHORITY_VERIFIER_PATH = "scripts/verify_fixture_registry_authority.py"
HARDENED_AUTHORITY_VERIFIER_SHA256 = "ac33cb2bfc0d0e4d06dadad0e09f46e31883fa36368062aa3acc65b9d0ab8561"
HARDENED_AUTHORITY_VERIFIER_MAX_BYTES = 256 * 1024
# Temporary-directory roots on macOS may expose /tmp through one of these
# system aliases. All other ancestors stay no-follow descriptor anchored.
TRUSTED_PATH_ALIASES = frozenset({Path("/tmp"), Path("/var"), Path("/var/folders"), Path("/var/tmp")})
AUTHORITY_KEYS = (
    "schema",
    "role",
    "source_commit",
    "artifact_manifest",
    "canonicalization",
    "synthetic_only",
    "live_claim",
)
AUTHORITY_RECORD_KEYS = ("path", "blob_oid", "sha256", "size_bytes")
AUTHORITY_ARTIFACT_PATHS = (
    "contracts/fixtures/index.json",
    "contracts/fixtures/validator/test_validate.py",
    "contracts/fixtures/validator/validate.py",
    "contracts/fixtures/validator/validation-baseline.json",
)
BASELINE_CANONICAL_SHA256 = "b6e75e19fbf265746ad3a0fbdf1615850fa5b3d37652d23118ef9c93642882a9"

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SAFE_PATH = re.compile(r"^[A-Za-z0-9._/-]+$")
URL_PATTERN = re.compile(r"(?:https?|wss?)://[^\s\"'<>]+", re.IGNORECASE)
# Regex source may contain whitespace, comments, character classes, or escaped
# letters in the authority. Capture the scheme first, then classify the
# bounded authority conservatively instead of stopping at the first backslash
# or whitespace and silently losing a live host.
REGEX_SCHEME_PATTERN = re.compile(r"(?:https?|wss?)://", re.IGNORECASE)
REGEX_HOST_LITERAL_PATTERN = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+"
)
# Normalize every C0/C1 control before content scanning, including layout
# controls such as HT, LF, and CR. Retained malformed-input fixtures may keep
# these bytes, but they cannot split credential or URL tokens at scan time.
UNSAFE_CONTROL_PATTERN = re.compile(r"[\x00-\x1f\x7f-\x9f]")
BASELINE_ANCHOR_PATTERN = re.compile(rb'^BASELINE_CANONICAL_SHA256 = "[0-9a-f]{64}"$', re.MULTILINE)
PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----", re.IGNORECASE)
AWS_KEY_PATTERN = re.compile(r"\bAKIA[0-9A-Z]{16}\b", re.IGNORECASE)
PROVIDER_TOKEN_PATTERN = re.compile(r"\b(?:ghp|github_pat|glpat|sk|xox[baprs])[-_][A-Za-z0-9_-]{8,}\b", re.IGNORECASE)
BEARER_VALUE_PATTERN = re.compile(r"\bBearer\s+([A-Za-z0-9._~+/=-]{16,})\b", re.IGNORECASE)
BASIC_VALUE_PATTERN = re.compile(r"\bBasic\s+([A-Za-z0-9+/=_-]{16,})", re.IGNORECASE)
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
# Assignment/query scanning deliberately matches a bounded key/value shape,
# then routes the key through the same normalized credential-family table used
# for JSON and Python AST targets. This keeps aliases such as ``x-api-key`` and
# ``refresh_token`` in one fail-closed boundary without treating every ordinary
# ``name=value`` example as a credential.
# Assignment values may be bare protocol tokens or quoted source/text values.
# Keep the quoted branch bounded and line-local: decoding arbitrary source syntax
# would turn this scanner into an interpreter and could retain unbounded text.
ASSIGNMENT_SECRET_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])(?P<key>[A-Za-z][A-Za-z0-9_.:/-]{0,64})\s*[=:]\s*"
    r"(?P<value>\"[^\"\r\n]{8,128}\"|'[^'\r\n]{8,128}'|[A-Za-z0-9._~+/=%-]{8,128})",
    re.IGNORECASE,
)
MAX_URL_LENGTH = 8 * 1024
MAX_URL_COMPONENT_LENGTH = 4 * 1024
MAX_URL_QUERY_PAIRS = 128
# Sensitive JSON fields accept only reviewed semantic markers. A broad shape
# such as arbitrary snake_case or `synthetic-*` can disguise provider tokens,
# URLs, or newly introduced credential values under a sensitive key.
SENSITIVE_MARKERS = frozenset({
    "absent",
    "blocked",
    "expired",
    "fixture-client",
    "invalid",
    "issued",
    "malformed",
    "missing",
    "none",
    "not_replayed",
    "present",
    "redacted",
    "synthetic-expired-handle",
    "synthetic-handle-a",
    "synthetic-malformed-handle",
    "unknown",
    "valid",
    "valid_exact_opaque_handle",
})

SENSITIVE_KEYS = frozenset(
    {
        "access_key",
        "access_key_id",
        "access_keys",
        "access_token",
        "accesskey",
        "accesskeyid",
        "accesstoken",
        "api_key",
        "api_key_value",
        "api_keys",
        "apikey",
        "apikeyvalue",
        "apikeys",
        "attach_handle",
        "attach_handles",
        "attach_id",
        "attach_ids",
        "authorization",
        "authorization_header",
        "authorization_headers",
        "auth_header",
        "auth_headers",
        "aws_access_key_id",
        "aws_access_key_ids",
        "aws_secret_access_key",
        "aws_secret_access_keys",
        "awsaccesskeyid",
        "awssecretaccesskey",
        "bearer",
        "bearers",
        "bearer_token",
        "bearer_tokens",
        "cookie",
        "cookies",
        "cookie_header",
        "cookie_headers",
        "credential",
        "credential_value",
        "credentials",
        "client_secret",
        "client_secrets",
        "clientsecret",
        "header_value",
        "host",
        "hostname",
        "input_bytes",
        "password",
        "prompt",
        "prompt_bytes",
        "prompt_text",
        "prompt_texts",
        "pty_bytes",
        "pty_input",
        "pty_inputs",
        "pty_output",
        "pty_outputs",
        "raw_bearer",
        "raw_cookie",
        "raw_ticket",
        "refresh_token",
        "refresh_tokens",
        "secret",
        "secret_key",
        "secret_keys",
        "secret_value",
        "session_cookie",
        "session_token",
        "set_cookie",
        "ticket",
        "ticket_fragment",
        "ticket_fragments",
        "ticket_query",
        "ticket_queries",
        "ticket_value",
        "token",
        "tokens",
        "transcript",
        "transcripts",
        "transcript_bytes",
        "websocket_ticket",
        "websocket_tickets",
        "provider_api_key",
        "provider_api_keys",
        "providerapikey",
        "providerapikeys",
        "secretkey",
        "x_api_key",
        "x_api_keys",
        "xapikey",
        "xapikeys",
        "api_token",
        "api_tokens",
        "apitoken",
        "apitokens",
        "client_id",
        "client_ids",
        "clientid",
        "clientids",
        "x_api_token",
        "x_api_tokens",
        "xapitoken",
        "xapitokens",
    }
)

# Retained-content aliases are broader than credential fields. Some fixture
# schemas use these names for structural booleans or finite provider labels, so
# route them through a contract-aware policy instead of treating every value as
# a sensitive marker and rejecting legitimate protocol shape.
RETAINED_CONTENT_ALIASES = frozenset({
    "messages",
    "conversation",
    "chat_history",
    "terminal",
    "terminal_output",
    "tool_output",
    "provider",
    "provider_state",
    "user_data",
    "transcript_text",
    "pty_transcript",
})
SAFE_PROVIDER_LABELS = frozenset({
    "pinned Nous",
    "reviewed OIDC provider",
})
SAFE_PROVIDER_VALUE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,63}$")

# These are credential-bearing names, kept separate from broader redaction
# fields such as ``prompt`` or ``host``. The compact form is used only for
# alias routing: values still pass the finite marker and generic scanners.
CREDENTIAL_KEY_FAMILIES = frozenset({
    "access_key",
    "access_token",
    "api_key",
    "api_token",
    "authorization",
    "auth_header",
    "aws_access_key_id",
    "aws_secret_access_key",
    "bearer",
    "client_id",
    "client_secret",
    "cookie",
    "password",
    "provider_api_key",
    "refresh_token",
    "secret",
    "secret_key",
    "session_cookie",
    "session_token",
    "ticket",
    "token",
    "x_api_key",
    "x_api_token",
})

SENSITIVE_DESCRIPTOR_KEYS = frozenset({
    "classification",
    "csrf",
    "pkce",
    "present",
    "reference",
    "session",
})
ALLOWED_URL_HOSTS = frozenset({
    "github.com",
    "hermternal.invalid",
    "json-schema.org",
    "synthetic.invalid",
})
# These exact values are source-level negative-test vocabulary already present
# in domain validators. They are not accepted in JSON evidence or free text.
STRUCTURAL_SENSITIVE_MARKERS = frozenset({
    "abcdefgh",
    "abcdefghijkl",
    "live-value",
    "never-echo",
    "rawcookie",
    "rawticket",
    "session=secret",
    "sid=qwertyui",
    "super-secret-value",
})
# Only this already-registered test source contains the RFC 7617 sample as
# deliberate negative-test input. Keep its exact candidate out of the global
# marker set so validators and non-test artifacts cannot inherit the allowance.
TEST_NEGATIVE_BASIC_AUTH_PATHS = frozenset({
    "deployment-security/external-allowlist/test_validate.py",
})
TEST_NEGATIVE_RFC7617_TOKEN_PATHS = frozenset({
    # These indexed Python sources retain the exact token as deliberate
    # negative-test input. JSON, Markdown, text, and every other Python source
    # remain fail-closed for the same bytes.
    "deployment-security/external-allowlist/test_validate.py",
    "image-attachment-lifecycle/test_validate.py",
})
# These are the only registered Python sources whose retained strings are
# deliberate credential-shaped negative inputs. The allowance is path-scoped;
# every other source, including every production-shaped validator, stays
# fail-closed even when a value contains synthetic vocabulary.
SYNTHETIC_MARKER_PATHS = frozenset({
    "behavioral-probe/test_validate.py",
    "compatibility-attestation/test_validate.py",
    "deployment-security/browser-auth/test_validate.py",
    "deployment-security/direct-port-denial/test_validate.py",
    "deployment-security/external-allowlist/test_validate.py",
    "deployment-security/private-network-firewall/test_validate.py",
    "deployment-security/host-origin-mapping/test_validate.py",
    "chat-stream-completion/test_validate.py",
    "route-allowlist/test_route_allowlist.py",
    "session-lineage/test_validate.py",
    "session-persistence/test_validate.py",
    "session-search/test_validate.py",
    "source-audit/compatibility-gate/test_validate.py",
    "source-audit/model-options/test_model_options.py",
    "source-audit/native-bearer/test_native_bearer.py",
    "source-audit/native-password-provider/test_native_password_provider.py",
    "source-audit/oauth-browser/test_oauth_browser.py",
    "uncertain-delivery/test_validate.py",
})
# This source-review fixture keeps a complete synthetic PEM example. Its
# header itself is intentionally realistic, so retain the full source value as
# an exact exception rather than allowing every private-key header in the file.
SYNTHETIC_FULL_VALUE_ALLOWANCES = {
    "source-audit/model-options/test_model_options.py": frozenset({
        "-----BEGIN RSA PRIVATE KEY-----\nsynthetic\n-----END RSA PRIVATE KEY-----",
    }),
    # C-06 retains these public credential-shaped negative samples only to prove
    # that its domain validator rejects them. No other path inherits them.
    "uncertain-delivery/test_validate.py": frozenset({
        "api_key=sk_test_123456789",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature",
        "ghp_1234567890abcdefghijk",
        "sk-proj-1234567890abcdef",
    }),
}
TEST_NEGATIVE_BASIC_AUTH_CANDIDATE = "QWxhZGRpbjpvcGVuIHNlc2FtZQ" + "=="
TEST_NEGATIVE_BASIC_AUTH_CANDIDATES = frozenset({TEST_NEGATIVE_BASIC_AUTH_CANDIDATE})
# The AST renderer uses this non-secret candidate only as a bounded probe when
# an unknown dynamic value appears in an Authorization construction. Permit it
# beside the reviewed Basic sample only in the one registered negative-test
# source that intentionally exercises that path.
DYNAMIC_AUTHORIZATION_PROBE_CANDIDATE = "A" * 16
# Host/Origin keeps a bounded set of malformed and reserved authorities as
# negative-test source data. These values are structural vocabulary, not a
# generic ``.invalid`` exemption: the allowance is exact, path-scoped, and
# includes the comma-joined and IPv6 canaries assembled by its test source.
STRUCTURAL_URL_ALLOWANCES = {
    "deployment-security/host-origin-mapping/README.md": frozenset({
        "https://chat.public.invalid`.",
        "https://chat.public.invalid`.These",
    }),
    "deployment-security/host-origin-mapping/cases.json": frozenset({
        "https://chat.public.invalid",
        "http://chat.public.invalid",
        "https://chat.public.invalid:443",
        "https://CHAT.PUBLIC.INVALID",
        "HTTPS://chat.public.invalid",
        "https://chat.public.invalid.",
        "https://chat.public.invalid/",
        "https://other.public.invalid",
        "https://user@chat.public.invalid",
        "https://chat.public.invalid?x",
        "http://attacker.private.invalid",
    }),
    "deployment-security/host-origin-mapping/test_validate.py": frozenset({
        "https://chat.public.invalid",
        "https://other.public.invalid",
        "http://chat.public.invalid",
        "HTTPS://chat.public.invalid",
        "https://CHAT.PUBLIC.INVALID",
        "https://chat.public.invalid.",
        "https://chat.public.invalid:443",
        "https://chat.public.invalid:0443",
        "https://chat.public.invalid:abc",
        "https://chat.public.invalid:65536",
        "https://chat.public.invalid/",
        "https://chat.public.invalid/path",
        "https://chat.public.invalid?x",
        "https://chat.public.invalid#x",
        "https://user@chat.public.invalid",
        "https://@chat.public.invalid",
        "https://chat..public.invalid",
        "https://chat.é.invalid",
        "https://chat.public.invalid,https://other.public.invalid",
        "https://[::1]",
        "https://unsafe.xyz",
        "https://user@unsafe.xyz",
        "https://README.md",
        "https://chat.public.invalid\\evil",
        "https://chat.public.invalid]evil",
        "https://chat.public.invalid^evil",
        "https://chat%2epublic.invalid",
        "https://chat.public.invalid\\",
        "https://chat.public.invalid,",
        "https://unsafe\\u002eexample/path",
    }),
    "deployment-security/host-origin-mapping/validate.py": frozenset({
        "https://chat.public.invalid",
        "http://chat.public.invalid",
        "https://CHAT.PUBLIC.INVALID",
        "HTTPS://chat.public.invalid",
        "https://chat.public.invalid.",
        "https://chat.public.invalid/",
        "https://other.public.invalid",
        "https://user@chat.public.invalid",
        "http://attacker.private.invalid",
        "https://chat.public.invalid:443",
        "https://chat.public.invalid?x",
    }),
    # DEP-11 keeps this reserved host only as a negative input for the focused
    # validator. Its string is assembled in Python, so the allowance applies to
    # the exact conservative URL result rather than to every ``.invalid`` host.
    "deployment-security/direct-port-denial/test_validate.py": frozenset({
        "https://retained.invalid",
        "https://retained.invalid/",
        "https://retained.invalid/synthetic.invalid",
    }),
    # This reviewed source keeps an indirect regular-expression URL literal;
    # preserve that exact escaped-dot pattern without reopening backslash
    # handling for ordinary URL text.
    "source-audit/oauth-browser/test_oauth_browser.py": frozenset({
        "https://github\\.com/NousResearch/hermes-agent/blob/",
    }),
}
EXACT_ASSIGNMENT_ALLOWANCES = {
    # These are retained source-review or negative-test fragments. Every
    # allowance is exact-path and exact-value; no caller can opt into a broad
    # dotted-value or synthetic credential exemption.
    "deployment-security/pty-local-adapter/test_validate.py": frozenset({"live-value", "synthetic-value"}),
    "deployment-security/ws-ticket/README.md": frozenset({"Abcdefgh"}),
    "deployment-security/ws-ticket/test_validate.py": frozenset({"Abcdefgh", "never-echo", "sid=qwertyui"}),
    "deployment-security/host-origin-mapping/test_validate.py": frozenset({
        "adjacent-canary",
        "adjacent-canarymutations",
        "authorization",
        "credential",
        "credentials",
        "do-not-echo",
        "password",
        "redaction-canary",
    }),
    "image-attachment-lifecycle/test_validate.py": frozenset({"session=secret"}),
    "source-audit/native-password-provider/source_audit.json": frozenset({"body.password"}),
    "source-audit/native-password-provider/validate.py": frozenset({"Abcdefgh", "body.password"}),
    "source-audit/oauth-browser/source_excerpts/routes_auth.py.txt": frozenset({"session.access_token", "session.refresh_token"}),
    "source-audit/oauth-browser/test_oauth_browser.py": frozenset({"request.get", "session.access_token", "session.refresh_token"}),
    "source-audit/pty-attach/validate.py": frozenset({"abcdefghijkl"}),
    # These exact loop-local values are redaction-test inputs, not retained
    # credentials. Keep the new target-flow scanner narrow without treating
    # synthetic or generic values as globally safe.
    "deployment-security/browser-auth/test_validate.py": frozenset({
        "raw-cookie-json",
        "raw-csrf-json",
        "raw-pkce-json",
        "raw-session-id",
        "raw-session-json",
        "raw-state-json",
        "raw-ticket-id",
        "raw-ticket-json",
        "synthetic.invalid",
        "untrusted-value",
    }),
    "deployment-security/private-network-firewall/test_validate.py": frozenset({"iptables"}),
    "deployment-security/pty-local-adapter/validate.py": frozenset({"synthetic.invalid"}),
    "provider-discovery/test_provider_discovery.py": frozenset({"synthetic.invalid"}),
    "pty-detach-race/test_validate.py": frozenset({"-Infinity", "Infinity"}),
    "pty-detach-race/validate.py": frozenset({"synthetic.invalid"}),
}
# Host/Origin's focused test source intentionally keeps exact private-key and
# detector canaries to prove its own scanner rejects them. The aggregate layer
# allows only those exact retained values in that one test artifact.
SYNTHETIC_FULL_VALUE_ALLOWANCES["chat-stream-completion/test_validate.py"] = frozenset({
    "ghp_abcdefghijk",
})
SYNTHETIC_FULL_VALUE_ALLOWANCES["deployment-security/host-origin-mapping/test_validate.py"] = frozenset({
    "-----BEGIN PRIVATE KEY-----",
    "bearer=authorization: Bearer redaction-canary",
    "authorization: Bearer redaction-canary",
    "Cookie: redaction-canary",
})
RAW_RFC7617_TOKEN_PATTERN = re.compile(re.escape(TEST_NEGATIVE_BASIC_AUTH_CANDIDATE), re.IGNORECASE)

SAFE_ERROR_MESSAGE = "fixture registry input rejected"


class ValidationError(ValueError):
    """Raised when checked-in registry evidence violates the shared contract."""

    def __init__(self, _detail: str = "") -> None:
        # Details can contain an untrusted path, key, or value. Keep direct API
        # errors bounded as well as the CLI's serialized failure marker.
        super().__init__(SAFE_ERROR_MESSAGE)


class DuplicateKeyError(ValidationError):
    """Raised before a duplicate JSON key can hide a fixture mutation."""


class ArgumentParseError(ValueError):
    """Raised for CLI syntax errors without echoing untrusted arguments."""


def require(condition: bool, message: str = "") -> None:
    if not condition:
        raise ValidationError(message)


def strict_keys(value: Any, expected: tuple[str, ...], label: str = "object") -> dict[str, Any]:
    require(type(value) is dict, f"{label} must be an object")
    require(tuple(value.keys()) == expected, f"{label} keys or ordering changed")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            # Never include the duplicate key in an error. It can be attacker-
            # controlled and must not escape through a test or CLI diagnostic.
            raise DuplicateKeyError()
        result[key] = value
    return result


def _parse_int(text: str) -> int:
    digits = text.lstrip("-")
    require(len(digits) <= MAX_INTEGER_DIGITS, "JSON integer is too large")
    value = int(text)
    require(abs(value) <= MAX_INTEGER, "JSON integer is too large")
    return value


def _parse_float(text: str) -> float:
    value = float(text)
    require(math.isfinite(value), "JSON number is not finite")
    return value


def _reject_constant(_text: str) -> Any:
    raise ValidationError()


def _read_bounded_bytes(path: Path, limit: int) -> bytes:
    try:
        if path.is_symlink() or not path.is_file():
            raise ValidationError()
        size = path.stat().st_size
        require(size <= limit, "input exceeds the byte limit")
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
    except ValidationError:
        raise
    except (OSError, ValueError) as exc:
        raise ValidationError() from exc
    require(len(data) <= limit, "input exceeds the byte limit")
    return data


def _validate_json_tree(
    value: Any,
    depth: int = 0,
    counter: list[int] | None = None,
    *,
    reject_nul: bool = True,
) -> None:
    if counter is None:
        counter = [0]
    counter[0] += 1
    require(counter[0] <= MAX_JSON_NODES, "JSON node count exceeds the safe limit")
    require(depth <= MAX_JSON_DEPTH, "JSON nesting exceeds the safe depth")
    if type(value) is dict:
        for key, child in value.items():
            require(type(key) is str, "JSON object key must be text")
            require(len(key) <= MAX_JSON_KEY_LENGTH and "\x00" not in key, "JSON object key is unsafe")
            _validate_json_tree(child, depth + 1, counter, reject_nul=reject_nul)
        return
    if type(value) is list:
        require(len(value) <= MAX_JSON_NODES, "JSON array exceeds the safe limit")
        for child in value:
            _validate_json_tree(child, depth + 1, counter, reject_nul=reject_nul)
        return
    if type(value) is str:
        require(len(value) <= MAX_JSON_STRING_LENGTH, "JSON string is unsafe")
        if reject_nul:
            require("\x00" not in value, "JSON string is unsafe")
        return
    if type(value) is float:
        require(math.isfinite(value), "JSON number is not finite")
        return
    if type(value) is int:
        require(abs(value) <= MAX_INTEGER, "JSON integer is too large")
        return
    require(value is None or type(value) is bool, "unsupported JSON value type")


def _parse_json_bytes(
    data: bytes,
    *,
    require_object: bool = True,
    reject_nul: bool = True,
) -> Any:
    """Parse already captured bytes with the aggregate strict JSON contract."""

    require(len(data) <= MAX_JSON_BYTES, "input exceeds the byte limit")
    try:
        text = data.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_int=_parse_int,
            parse_float=_parse_float,
            parse_constant=_reject_constant,
        )
    except ValidationError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError, ValueError) as exc:
        raise ValidationError() from exc
    _validate_json_tree(value, reject_nul=reject_nul)
    if require_object:
        require(type(value) is dict, "top-level JSON value must be an object")
    return value


def load_json(
    path: Path,
    *,
    require_object: bool = True,
    limit: int = MAX_JSON_BYTES,
    reject_nul: bool = True,
) -> Any:
    data = _read_bounded_bytes(path, limit)
    return _parse_json_bytes(data, require_object=require_object, reject_nul=reject_nul)


_FULLWIDTH_ASCII_TRANSLATION = str.maketrans(
    {chr(code): chr(code - 0xFEE0) for code in range(0xFF01, 0xFF5F)}
    | {"　": " "}
)


def _normalize_key(key: str) -> str:
    # Compatibility forms can spell both credential aliases and separators with
    # full-width Unicode. Normalize before case/separator folding so JSON keys
    # cannot evade sensitive-field routing through presentation variants.
    normalized = unicodedata.normalize("NFKC", key)
    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", normalized)
    return re.sub(r"[-.:/\s]+", "_", separated).casefold()


def _compact_key_alias(key: str) -> str:
    normalized = unicodedata.normalize("NFKC", key).casefold()
    return re.sub(r"[^a-z0-9]", "", normalized)


CREDENTIAL_KEY_COMPACT_ALIASES = frozenset(
    _compact_key_alias(key) for key in CREDENTIAL_KEY_FAMILIES
)
REVIEWED_KEY_SEPARATOR_PATTERN = re.compile(r"[A-Za-z0-9_.:/\-\s]+")


def _validated_key_for_routing(key: str) -> str:
    """Normalize a retained key without hiding format/control aliases."""

    require(type(key) is str, "JSON object key is unsafe")
    # JSON evidence may retain malformed-input text, but a key containing a
    # control or format character is never structural metadata. Reject it
    # before NFKC/separator folding so U+200B/U+2060 and C0/C1 cannot disguise
    # a credential alias as an ordinary object field.
    require(
        all(unicodedata.category(character) not in {"Cc", "Cf"} for character in key),
        "sensitive key contains an unsafe Unicode control",
    )
    normalized = _normalize_key(key)
    if _compact_key_alias(key) in CREDENTIAL_KEY_COMPACT_ALIASES:
        # Only the separators explicitly reviewed by the aggregate contract
        # may spell a credential key. Punctuation such as ``@`` or ``=`` is
        # rejected even when removing it would produce ``api_key``.
        require(REVIEWED_KEY_SEPARATOR_PATTERN.fullmatch(key) is not None, "sensitive key separator is not reviewed")
    return normalized


def _is_credential_key_alias(key: str) -> bool:
    return _compact_key_alias(key) in CREDENTIAL_KEY_COMPACT_ALIASES


def _normalize_scanned_text(value: str, *, preserve_controls: bool = False) -> str:
    # Translate only full-width ASCII forms. Whole-string NFKC would turn a
    # reviewed Unicode ellipsis into three ASCII periods and change exact
    # negative-test allowances. Scan both a compact form (which catches a
    # credential split by a control) and a boundary-preserving form (which
    # keeps a preceding word from swallowing a new ``token=`` key). JSON keys
    # use ``_validated_key_for_routing`` and reject controls/format characters.
    cleaned = "".join(
        " " if preserve_controls and unicodedata.category(character) in {"Cc", "Cf"} else character
        for character in value
        if preserve_controls or unicodedata.category(character) not in {"Cc", "Cf"}
    )
    return cleaned.translate(_FULLWIDTH_ASCII_TRANSLATION)


def _is_explicit_synthetic_marker(value: str) -> bool:
    lowered = value.casefold()
    return (
        lowered in STRUCTURAL_SENSITIVE_MARKERS
        or any(marker in lowered for marker in ("synthetic", "fixture", "example", "placeholder", "hidden", "audit", "nested", "signature-value"))
        or re.fullmatch(r"(?:akia)?(?:x|z|0){8,}", lowered) is not None
    )


def _is_placeholder(
    value: str,
    *,
    allow_synthetic_markers: bool = False,
    allow_structural_placeholders: bool = True,
) -> bool:
    lowered = value.casefold()
    structural = (
        "body." in lowered
        or "request." in lowered
        or "source." in lowered
        or lowered.endswith((".password", ".token", ".ticket", ".cookie"))
        or (
            "." in lowered
            and _is_credential_key_alias(lowered.rsplit(".", 1)[-1])
        )
    )
    return (
        value.startswith("<")
        or lowered in {"false", "none", "null", "redacted", "not_recorded", "not_retained"}
        or (allow_structural_placeholders and structural)
        or (allow_synthetic_markers and _is_explicit_synthetic_marker(value))
    )


def _validate_retained_content_alias(value: Any, *, key: str) -> None:
    """Reject retained transcript/content values while preserving shape fields."""

    if key == "terminal":
        require(type(value) is bool, "terminal content must remain a structural boolean")
        return
    if key in {"provider", "provider_state"}:
        # Protocol fixtures use null, empty, or false to represent an absent
        # provider slot. Those structural sentinels are not retained content.
        if value is None or value is False or value == "":
            return
        require(type(value) is str, "provider metadata must remain a bounded label")
        _validate_text_value(value)
        require(
            SAFE_PROVIDER_VALUE_PATTERN.fullmatch(value) is not None or value in SAFE_PROVIDER_LABELS,
            "provider metadata must not retain content",
        )
        return
    if value is None or type(value) is bool:
        require(value is False or value is None, "retained content must be absent")
        return
    if type(value) is str:
        _validate_text_value(value)
        require(
            value.casefold() in SENSITIVE_MARKERS
            or _is_placeholder(value, allow_structural_placeholders=True)
            or _is_explicit_synthetic_marker(value),
            "retained content is not a reviewed marker",
        )
        return
    if type(value) is list:
        require(len(value) <= 128, "retained content list is too large")
        for child in value:
            _validate_retained_content_alias(child, key=key)
        return
    if type(value) is dict:
        require(len(value) <= 64, "retained content object is too large")
        for child in value.values():
            _validate_retained_content_alias(child, key=key)
        return
    raise ValidationError()


def _validate_sensitive_marker(value: Any, *, key: str = "") -> None:
    if value is None:
        return
    if type(value) is bool:
        require(value is False or key == "present", "sensitive field must be redacted")
        return
    if type(value) is str:
        require(len(value) <= 128, "sensitive marker is too long")
        # A sensitive key does not exempt its retained value from the generic
        # credential, assignment, control, and live-host scanners.
        _validate_text_value(value)
        require(value.casefold() in SENSITIVE_MARKERS, "sensitive value is not a reviewed marker")
        return
    if type(value) is list:
        require(len(value) <= 32, "sensitive marker list is too large")
        for child in value:
            _validate_sensitive_marker(child, key=key)
        return
    if type(value) is dict:
        for child_key, child in value.items():
            normalized = _validated_key_for_routing(child_key)
            require(normalized in SENSITIVE_DESCRIPTOR_KEYS, "sensitive descriptor key is not allowed")
            _validate_sensitive_marker(child, key=normalized)
        return
    raise ValidationError()


def _decode_regex_escape(text: str, index: int) -> tuple[str, int, bool]:
    """Decode one bounded regex escape, preserving uncertainty explicitly."""

    if index + 1 >= len(text) or text[index] != "\\":
        return text[index:index + 1], index + 1, False
    marker = text[index + 1]
    if marker in ".-":
        return marker, index + 2, False
    lengths = {"x": 2, "u": 4, "U": 8}
    if marker in lengths:
        end = index + 2 + lengths[marker]
        digits = text[index + 2:end]
        if re.fullmatch(r"[0-9A-Fa-f]+", digits) is None:
            return "?", min(len(text), end), True
        codepoint = int(digits, 16)
        if codepoint > 0x7F:
            return "?", end, True
        return chr(codepoint), end, False
    if marker == "N":
        end = text.find("}", index + 3)
        if end < 0:
            return "?", len(text), True
        name = text[index + 3:end]
        try:
            character = unicodedata.lookup(name)
        except KeyError:
            return "?", end + 1, True
        if ord(character) > 0x7F:
            return "?", end + 1, True
        return character, end + 1, False
    if marker in "01234567":
        end = index + 1
        while end < len(text) and end < index + 4 and text[end] in "01234567":
            end += 1
        return chr(int(text[index + 1:end], 8)), end, False
    # Escaped letters, backreferences, and regex assertions cannot be recovered
    # as a concrete hostname without executing the regex engine.
    return "?", index + 2, True


def _decode_regex_host(text: str) -> tuple[str, bool]:
    decoded: list[str] = []
    uncertain = False
    index = 0
    while index < len(text):
        character = text[index]
        if character == "\\":
            value, index, was_uncertain = _decode_regex_escape(text, index)
            decoded.append(value)
            uncertain = uncertain or was_uncertain
            continue
        if character == "[":
            end = text.find("]", index + 1)
            if end < 0:
                return "?", True
            body = text[index + 1:end]
            if len(body) == 1:
                decoded.append(body)
            elif body.startswith("\\"):
                value, consumed, was_uncertain = _decode_regex_escape(body, 0)
                if consumed == len(body) and not was_uncertain:
                    decoded.append(value)
                else:
                    decoded.append("?")
                    uncertain = True
            else:
                decoded.append("?")
                uncertain = True
            index = end + 1
            continue
        if character.isspace() or character == "#":
            # Verbose-mode spacing/comments can change the matched authority;
            # do not silently remove them and bless a host we did not recover.
            return "?", True
        if character in "(){}+*?|^$":
            decoded.append("?")
            uncertain = True
        else:
            decoded.append(character)
        index += 1
    return "".join(decoded), uncertain


def _regex_host_literals(raw_url: str) -> tuple[str, ...]:
    scheme = re.match(r"(?:https?|wss?)://", raw_url, re.IGNORECASE)
    if scheme is None:
        return ()
    remainder = raw_url[scheme.end():]
    host_text = re.split(r"[/#?]", remainder, maxsplit=1)[0]
    decoded, uncertain = _decode_regex_host(host_text)
    if "@" in decoded:
        userinfo, decoded = decoded.rsplit("@", 1)
        if ":" in userinfo:
            _scheme, password = userinfo.split(":", 1)
            require(
                not password or _is_explicit_synthetic_marker(password),
                "regex URL userinfo is not allowed",
            )
    concrete = tuple(dict.fromkeys(REGEX_HOST_LITERAL_PATTERN.findall(decoded)))
    if uncertain:
        # Dynamic labels are acceptable only when the recovered literal suffix
        # is already a non-live synthetic domain. Otherwise fail closed rather
        # than guessing what a character class/escape/verbose expression means.
        suffixes = [
            candidate
            for candidate in concrete
            if candidate.casefold().endswith((".test", ".example"))
            or candidate.casefold() in ALLOWED_URL_HOSTS
        ]
        require(bool(suffixes), "regex URL host cannot be recovered safely")
    return concrete


def _require_allowed_url_host(host: str, *, allow_synthetic_markers: bool) -> None:
    lowered = host.casefold().replace(r"\.", ".").rstrip(".`'\"),]}>;:!? ")
    if lowered.startswith("<") and lowered.endswith(">"):
        return
    require(
        lowered.endswith(".test")
        or lowered.endswith(".example")
        or lowered.endswith(".example.com")
        or lowered == "host"
        or lowered in ALLOWED_URL_HOSTS
        or (allow_synthetic_markers and lowered == "localhost"),
        "live URL host is not allowed",
    )


def _assignment_candidate_from_match(match: re.Match[str]) -> str:
    candidate = match.group("value")
    if len(candidate) >= 2 and candidate[0] == candidate[-1] and candidate[0] in "'\"":
        return candidate[1:-1]
    return candidate


def _validate_assignment_candidate(
    key: str,
    candidate: str,
    *,
    allow_synthetic_markers: bool,
    allowed_assignment_values: frozenset[str],
    exact_full_allowance: bool = False,
) -> None:
    if not _is_credential_key_alias(key):
        return
    exact_assignment_allowance = candidate in allowed_assignment_values
    placeholder = _is_placeholder(
        candidate,
        allow_synthetic_markers=allow_synthetic_markers,
        allow_structural_placeholders=False,
    )
    require(
        exact_assignment_allowance or exact_full_allowance or placeholder,
        "credential-shaped value is not allowed",
    )


def _decode_url_component(component: str, *, plus_as_space: bool) -> str:
    """Decode one bounded URL component without accepting malformed escapes."""

    require(len(component) <= MAX_URL_COMPONENT_LENGTH, "URL component is too large")
    decoded = bytearray()
    index = 0
    while index < len(component):
        character = component[index]
        if character == "%":
            require(index + 2 < len(component), "URL escape is incomplete")
            digits = component[index + 1:index + 3]
            require(re.fullmatch(r"[0-9A-Fa-f]{2}", digits) is not None, "URL escape is malformed")
            decoded.append(int(digits, 16))
            index += 3
            continue
        if plus_as_space and character == "+":
            character = " "
        try:
            encoded = character.encode("utf-8")
        except UnicodeError as exc:
            raise ValidationError() from exc
        decoded.extend(encoded)
        require(len(decoded) <= MAX_URL_COMPONENT_LENGTH, "decoded URL component is too large")
        index += 1
    try:
        result = bytes(decoded).decode("utf-8")
    except UnicodeError as exc:
        raise ValidationError() from exc
    require(len(result) <= MAX_URL_COMPONENT_LENGTH, "decoded URL component is too large")
    return result


def _url_authority(raw_url: str) -> str:
    separator = raw_url.find("://")
    require(separator > 0, "URL scheme is missing")
    start = separator + 3
    end = len(raw_url)
    for marker in "/?#":
        candidate = raw_url.find(marker, start)
        if candidate >= 0:
            end = min(end, candidate)
    authority = raw_url[start:end]
    require(authority, "URL authority is missing")
    return authority


def _validate_url_query(
    query: str,
    *,
    allow_synthetic_markers: bool,
    allowed_assignment_values: frozenset[str],
    allowed_synthetic_full_values: frozenset[str],
    source_value: str,
) -> None:
    require(len(query) <= MAX_URL_COMPONENT_LENGTH, "URL query is too large")
    pairs = re.split(r"[&;]", query)
    require(len(pairs) <= MAX_URL_QUERY_PAIRS, "URL query has too many fields")
    exact_full_allowance = source_value in allowed_synthetic_full_values
    for pair in pairs:
        if not pair:
            continue
        key_text, separator, value_text = pair.partition("=")
        if not separator:
            continue
        key = _decode_url_component(key_text, plus_as_space=True)
        candidate = _decode_url_component(value_text, plus_as_space=True)
        _validate_assignment_candidate(
            key,
            candidate,
            allow_synthetic_markers=allow_synthetic_markers,
            allowed_assignment_values=allowed_assignment_values,
            exact_full_allowance=exact_full_allowance,
        )


def _validate_url_hosts(
    value: str,
    *,
    allow_synthetic_markers: bool = False,
    regex_pattern: bool = False,
    allowed_structural_urls: frozenset[str] = frozenset(),
    allowed_assignment_values: frozenset[str] = frozenset(),
    allowed_synthetic_full_values: frozenset[str] = frozenset(),
) -> None:
    if regex_pattern:
        for match in REGEX_SCHEME_PATTERN.finditer(value):
            raw_url = value[match.start():]
            for host in _regex_host_literals(raw_url):
                _require_allowed_url_host(host, allow_synthetic_markers=allow_synthetic_markers)
        return
    for match in URL_PATTERN.finditer(value):
        raw_url = match.group(0)
        require(len(raw_url) <= MAX_URL_LENGTH, "URL is too large")
        # Domain validators retain exact malformed and reserved URL values as
        # negative-test vocabulary. Do not generalize the allowance to a host
        # suffix: a path-scoped exact token is the only structural bypass.
        if raw_url in allowed_structural_urls:
            continue
        authority = _url_authority(raw_url)
        # Backslash is a special-scheme authority separator under WHATWG URL
        # parsing. Reject it before Python's urlsplit can reinterpret an evil
        # host as an allowlisted path/userinfo combination.
        require("\\" not in authority, "ambiguous URL authority is not allowed")
        if "@" in authority:
            raw_userinfo = authority.rsplit("@", 1)[0]
            decoded_userinfo = _decode_url_component(raw_userinfo, plus_as_space=False)
            if ":" in decoded_userinfo:
                _username, password = decoded_userinfo.split(":", 1)
                require(
                    not password or _is_explicit_synthetic_marker(password),
                    "URL userinfo is not allowed",
                )
        try:
            parsed = urlsplit(raw_url)
            host = parsed.hostname
        except ValueError as exc:
            raise ValidationError() from exc
        _validate_url_query(
            parsed.query,
            allow_synthetic_markers=allow_synthetic_markers,
            allowed_assignment_values=allowed_assignment_values,
            allowed_synthetic_full_values=allowed_synthetic_full_values,
            source_value=value,
        )
        if host:
            _require_allowed_url_host(host, allow_synthetic_markers=allow_synthetic_markers)


def _validate_text_value(
    value: str,
    *,
    check_assignments: bool = True,
    allow_synthetic_markers: bool = False,
    allowed_basic_auth_candidates: frozenset[str] = frozenset(),
    allowed_raw_rfc7617_tokens: frozenset[str] = frozenset(),
    allowed_assignment_values: frozenset[str] = frozenset(),
    allowed_synthetic_full_values: frozenset[str] = frozenset(),
    regex_pattern: bool = False,
    allowed_structural_urls: frozenset[str] = frozenset(),
) -> None:
    # Scan both a compact representation and one that preserves control
    # boundaries. The compact form catches ``Bearer abc\x00def``; the preserved
    # form prevents a preceding prose word from swallowing a new ``token=``
    # assignment after a line break or zero-width separator.
    scan_values = tuple(dict.fromkeys((
        _normalize_scanned_text(value),
        _normalize_scanned_text(value, preserve_controls=True),
    )))
    for scanned_value in scan_values:
        for match in PRIVATE_KEY_PATTERN.finditer(scanned_value):
            candidate = match.group(0)
            require(
                allow_synthetic_markers
                and (
                    _is_explicit_synthetic_marker(candidate)
                    or value in allowed_synthetic_full_values
                ),
                "private key material is not allowed",
            )
        for pattern, message in (
            (AWS_KEY_PATTERN, "provider key material is not allowed"),
            (PROVIDER_TOKEN_PATTERN, "provider token material is not allowed"),
        ):
            for match in pattern.finditer(scanned_value):
                candidate = match.group(0)
                require(
                    allow_synthetic_markers
                    and (
                        value in allowed_synthetic_full_values
                        or _is_placeholder(
                            candidate,
                            allow_synthetic_markers=True,
                            allow_structural_placeholders=False,
                        )
                    ),
                    message,
                )
        allowed_rfc7617_tokens = allowed_basic_auth_candidates | allowed_raw_rfc7617_tokens
        for match in RAW_RFC7617_TOKEN_PATTERN.finditer(scanned_value):
            candidate = match.group(0)
            require(candidate in allowed_rfc7617_tokens, "raw RFC 7617 token is not allowed")
        patterns = (BEARER_VALUE_PATTERN, BASIC_VALUE_PATTERN, JWT_PATTERN)
        if check_assignments:
            patterns += (ASSIGNMENT_SECRET_PATTERN,)
        for pattern in patterns:
            for match in pattern.finditer(scanned_value):
                if pattern is ASSIGNMENT_SECRET_PATTERN:
                    _validate_assignment_candidate(
                        match.group("key"),
                        _assignment_candidate_from_match(match),
                        allow_synthetic_markers=allow_synthetic_markers,
                        allowed_assignment_values=allowed_assignment_values,
                        exact_full_allowance=value in allowed_synthetic_full_values,
                    )
                    continue
                candidate = match.group(1) if match.lastindex else match.group(0)
                exact_basic_allowance = (
                    pattern is BASIC_VALUE_PATTERN
                    and candidate in allowed_basic_auth_candidates
                )
                exact_full_allowance = value in allowed_synthetic_full_values
                # Synthetic marker vocabulary is useful only for path-scoped
                # negative fixtures, and never turns a Basic value into a marker.
                placeholder = _is_placeholder(
                    candidate,
                    allow_synthetic_markers=(allow_synthetic_markers and pattern is not BASIC_VALUE_PATTERN),
                    # Dotted source expressions are allowed only by an exact
                    # path/value assignment allowance. They must not make a
                    # credential-shaped Bearer, Basic, JWT, or assignment value
                    # look redacted merely because it resembles source syntax.
                    allow_structural_placeholders=False,
                )
                require(
                    exact_basic_allowance
                    or exact_full_allowance
                    or placeholder,
                    "credential-shaped value is not allowed",
                )
        _validate_url_hosts(
            scanned_value,
            allow_synthetic_markers=allow_synthetic_markers,
            regex_pattern=regex_pattern,
            allowed_structural_urls=allowed_structural_urls,
            allowed_assignment_values=allowed_assignment_values,
            allowed_synthetic_full_values=allowed_synthetic_full_values,
        )


def _validate_redaction_tree(
    value: Any,
    *,
    allowed_assignment_values: frozenset[str] = frozenset(),
    allowed_structural_urls: frozenset[str] = frozenset(),
) -> None:
    if type(value) is dict:
        for key, child in value.items():
            # Object keys are retained input too. Scan them before treating a
            # normalized key as structural so nested credential-shaped keys
            # cannot bypass the value scanner.
            _validate_text_value(
                key,
                allowed_assignment_values=allowed_assignment_values,
                allowed_structural_urls=allowed_structural_urls,
            )
            normalized = _validated_key_for_routing(key)
            if normalized in RETAINED_CONTENT_ALIASES:
                _validate_retained_content_alias(child, key=normalized)
            if normalized in SENSITIVE_KEYS:
                _validate_sensitive_marker(child, key=normalized)
            else:
                _validate_redaction_tree(
                    child,
                    allowed_assignment_values=allowed_assignment_values,
                    allowed_structural_urls=allowed_structural_urls,
                    )
        return
    if type(value) is list:
        for child in value:
            _validate_redaction_tree(
                child,
                allowed_assignment_values=allowed_assignment_values,
                allowed_structural_urls=allowed_structural_urls,
            )
        return
    if type(value) is str:
        _validate_text_value(
            value,
            allowed_assignment_values=allowed_assignment_values,
            allowed_structural_urls=allowed_structural_urls,
        )


def _validate_text_file(
    path: Path,
    *,
    data: bytes | None = None,
    allowed_assignment_values: frozenset[str] = frozenset(),
    allowed_structural_urls: frozenset[str] = frozenset(),
) -> None:
    data = _read_bounded_bytes(path, MAX_ARTIFACT_BYTES) if data is None else data
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise ValidationError() from exc
    require(len(text) <= MAX_ARTIFACT_BYTES, "text artifact is too large")
    # Markdown and text are retained artifacts too; disabling assignment
    # matching here would let password=, token=, ticket=, cookie=, or secret=
    # values bypass the shared redaction boundary. One reviewed negative-test
    # fragment remains exact-path and exact-value scoped below.
    _validate_text_value(
        text,
        check_assignments=True,
        allowed_assignment_values=allowed_assignment_values,
        allowed_structural_urls=allowed_structural_urls,
    )


_STATIC_UNKNOWN = object()
# Unknown runtime fields are rendered as the one exact synthetic host already
# accepted by the URL policy. This keeps dynamic URL probes deterministic without
# turning arbitrary ``.invalid`` suffixes into a global structural allowance.
_STATIC_DYNAMIC_VALUE = "synthetic.invalid"


def _static_scalar(value: Any) -> Any:
    if type(value) is str:
        return value
    if type(value) is bytes:
        try:
            return value.decode("utf-8")
        except UnicodeError:
            return _STATIC_UNKNOWN
    if type(value) in {int, float, bool} or value is None:
        return value
    return _STATIC_UNKNOWN


def _bounded_static_text(value: Any) -> Any:
    if type(value) is str and len(value) <= MAX_ARTIFACT_BYTES:
        return value
    return _STATIC_UNKNOWN


def _contains_static_unknown(value: Any) -> bool:
    if value is _STATIC_UNKNOWN:
        return True
    if isinstance(value, (list, tuple)):
        return any(_contains_static_unknown(child) for child in value)
    if isinstance(value, dict):
        return any(_contains_static_unknown(child) for child in value.values())
    return False


def _static_value(node: ast.AST, bindings: dict[str, Any]) -> Any:
    if isinstance(node, ast.Constant):
        return _static_scalar(node.value)
    if isinstance(node, ast.Name):
        return bindings.get(node.id, _STATIC_UNKNOWN)
    if isinstance(node, ast.Dict):
        result: dict[Any, Any] = {}
        for key_node, value_node in zip(node.keys, node.values):
            if key_node is None:
                return _STATIC_UNKNOWN
            key = _static_value(key_node, bindings)
            value = _static_value(value_node, bindings)
            if key is _STATIC_UNKNOWN:
                return _STATIC_UNKNOWN
            try:
                result[key] = value
            except (TypeError, ValueError):
                return _STATIC_UNKNOWN
        return result
    if isinstance(node, ast.Subscript):
        container = _static_value(node.value, bindings)
        key = _static_value(node.slice, bindings)
        if container is _STATIC_UNKNOWN or key is _STATIC_UNKNOWN:
            return _STATIC_UNKNOWN
        try:
            return container[key]
        except (IndexError, KeyError, TypeError):
            return _STATIC_UNKNOWN
    if isinstance(node, ast.JoinedStr):
        pieces: list[str] = []
        for part in node.values:
            if isinstance(part, ast.Constant):
                literal = _static_scalar(part.value)
                if type(literal) is not str:
                    return _STATIC_UNKNOWN
                pieces.append(literal)
                continue
            if not isinstance(part, ast.FormattedValue):
                return _STATIC_UNKNOWN
            formatted = _static_value(part.value, bindings)
            if formatted is _STATIC_UNKNOWN:
                return _STATIC_UNKNOWN
            if part.conversion == 115:
                formatted = str(formatted)
            elif part.conversion == 114:
                formatted = repr(formatted)
            elif part.conversion == 97:
                formatted = ascii(formatted)
            format_spec = ""
            if part.format_spec is not None:
                format_spec = _static_value(part.format_spec, bindings)
                if type(format_spec) is not str:
                    return _STATIC_UNKNOWN
            try:
                pieces.append(format(formatted, format_spec))
            except (TypeError, ValueError, OverflowError):
                return _STATIC_UNKNOWN
        return _bounded_static_text("".join(pieces))
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        left = _static_value(node.left, bindings)
        right = _static_value(node.right, bindings)
        if isinstance(node.op, ast.Add) and type(left) is str and type(right) is str:
            return _bounded_static_text(left + right)
        if isinstance(node.op, ast.Mod) and type(left) is str and not _contains_static_unknown(right):
            try:
                return _bounded_static_text(left % right)
            except (IndexError, KeyError, TypeError, ValueError, OverflowError):
                return _STATIC_UNKNOWN
        return _STATIC_UNKNOWN
    if isinstance(node, (ast.List, ast.Tuple)):
        values: list[Any] = []
        for child in node.elts:
            value = _static_value(child, bindings)
            if value is _STATIC_UNKNOWN:
                return _STATIC_UNKNOWN
            values.append(value)
        return values if isinstance(node, ast.List) else tuple(values)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        method = node.func.attr
        receiver = _static_value(node.func.value, bindings)
        if method == "format" and type(receiver) is str:
            args: list[Any] = []
            for argument in node.args:
                value = _static_value(argument, bindings)
                if value is _STATIC_UNKNOWN:
                    return _STATIC_UNKNOWN
                args.append(value)
            keywords: dict[str, Any] = {}
            for keyword in node.keywords:
                if keyword.arg is None:
                    return _STATIC_UNKNOWN
                value = _static_value(keyword.value, bindings)
                if value is _STATIC_UNKNOWN:
                    return _STATIC_UNKNOWN
                keywords[keyword.arg] = value
            try:
                return _bounded_static_text(receiver.format(*args, **keywords))
            except (IndexError, KeyError, ValueError, TypeError, OverflowError):
                return _STATIC_UNKNOWN
        if method == "format_map" and type(receiver) is str and len(node.args) == 1 and not node.keywords:
            mapping = _static_value(node.args[0], bindings)
            if not isinstance(mapping, dict) or _contains_static_unknown(mapping):
                return _STATIC_UNKNOWN
            try:
                return _bounded_static_text(receiver.format_map(mapping))
            except (IndexError, KeyError, ValueError, TypeError, OverflowError):
                return _STATIC_UNKNOWN
        if method == "join" and type(receiver) is str and len(node.args) == 1 and not node.keywords:
            values = _static_value(node.args[0], bindings)
            if isinstance(values, (list, tuple)) and all(type(value) is str for value in values):
                return _bounded_static_text(receiver.join(values))
    return _STATIC_UNKNOWN


def _percent_mapping_probe(key: Any) -> str:
    normalized = re.sub(r"[^a-z0-9]", "", str(key).casefold())
    if "scheme" in normalized or normalized in {"auth", "authorization"}:
        return "Basic"
    return "AAAAAAAAAAAAAAAA"


def _mapping_probe_from_template(template: str, *, format_map: bool = False) -> dict[str, str]:
    """Build a bounded mapping probe for unresolved source expressions.

    A runtime mapping is not executed, but known template fields still reveal
    where credential-shaped values can flow. Probe scheme-like fields as Basic
    and all other fields with detector-length data so mapping syntax cannot
    erase an Authorization header from the conservative scan.
    """
    if format_map:
        fields = re.findall(r"{([^{}!:]+)(?:![^}:]+)?(?:\s*:[^}]*)?}", template)
    else:
        fields = re.findall(r"%\(([^()]+)\)", template)
    return {field: _percent_mapping_probe(field) for field in dict.fromkeys(fields)}


def _percent_probe_value(
    node: ast.AST,
    bindings: dict[str, Any],
    *,
    template: str = "",
) -> Any:
    """Render unresolved percent operands as credential-shaped probes.

    Positional operands can occupy an authorization-scheme slot. Mapping
    operands additionally preserve their keys so scheme fields become `Basic`
    while token/secret fields become a detector-length candidate. For an
    unresolved mapping name, the percent template supplies the bounded field
    inventory without executing retained source.
    """
    if isinstance(node, ast.Dict):
        result: dict[Any, Any] = {}
        for key_node, value_node in zip(node.keys, node.values):
            if key_node is None:
                continue
            key = _static_value(key_node, bindings)
            if key is _STATIC_UNKNOWN:
                continue
            value = _static_value(value_node, bindings)
            result[key] = _percent_mapping_probe(key) if value is _STATIC_UNKNOWN else value
        return result
    value = _static_value(node, bindings)
    if isinstance(value, dict):
        return {
            key: _percent_mapping_probe(key) if child is _STATIC_UNKNOWN else child
            for key, child in value.items()
        }
    if value is not _STATIC_UNKNOWN:
        return value
    if isinstance(node, ast.Tuple):
        return tuple(_percent_probe_value(child, bindings) for child in node.elts)
    if template and "%(" in template:
        return _mapping_probe_from_template(template)
    return "Basic"


def _addition_parts(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _addition_parts(node.left) + _addition_parts(node.right)
    return [node]


def _dynamic_authorization_scheme(node: ast.AST, bindings: dict[str, Any]) -> bool:
    if isinstance(node, ast.JoinedStr):
        for index, part in enumerate(node.values[:-1]):
            if not isinstance(part, ast.Constant) or type(part.value) is not str:
                continue
            if re.search(r"authorization\s*:\s*$", part.value, re.IGNORECASE) is None:
                continue
            following = node.values[index + 1]
            if isinstance(following, ast.FormattedValue) and _static_value(following.value, bindings) is _STATIC_UNKNOWN:
                return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        static_prefix = ""
        for part in _addition_parts(node):
            literal = _static_value(part, bindings)
            if type(literal) is str:
                static_prefix = (static_prefix + literal)[-128:]
                continue
            if literal is _STATIC_UNKNOWN and re.search(
                r"authorization\s*:\s*$",
                static_prefix,
                re.IGNORECASE,
            ):
                return True
            static_prefix = ""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        receiver = _static_value(node.func.value, bindings)
        if type(receiver) is not str:
            return False
        method = node.func.attr
        if method in {"format", "format_map"}:
            match = re.search(
                r"authorization\s*:\s*\{([^{}!:]*)(?:![^}:]+)?(?::[^}]*)?\}",
                receiver,
                re.IGNORECASE,
            )
            if match is None:
                return False
            field = match.group(1)
            if field == "":
                return bool(node.args) and _static_value(node.args[0], bindings) is _STATIC_UNKNOWN
            if field.isdigit():
                index = int(field)
                return index < len(node.args) and _static_value(node.args[index], bindings) is _STATIC_UNKNOWN
            if method == "format_map" and len(node.args) == 1:
                mapping = _static_value(node.args[0], bindings)
                if mapping is _STATIC_UNKNOWN:
                    return True
                if isinstance(mapping, dict):
                    return mapping.get(field, _STATIC_UNKNOWN) is _STATIC_UNKNOWN
                return True
            for keyword in node.keywords:
                if keyword.arg == field:
                    return _static_value(keyword.value, bindings) is _STATIC_UNKNOWN
            return True
        # Unsupported string methods cannot be evaluated, but a statically
        # visible Authorization prefix still identifies the unknown result as a
        # credential-bearing construction. This is narrower than probing every
        # dynamic string that happens to contain a completed Authorization sample.
        return re.search(r"authorization\s*:\s*$", receiver, re.IGNORECASE) is not None
    return False


def _with_dynamic_authorization_probe(node: ast.AST, bindings: dict[str, Any], rendered: str) -> str:
    """Fail closed when an unknown expression can construct Authorization.

    The dynamic value sentinel is an exact synthetic URL host, so it cannot by
    itself satisfy the Basic detector's contiguous-token rule. When an unknown
    expression is rendered in an Authorization-bearing construction, append a
    bounded Basic probe explicitly instead of weakening the host allowlist or
    using an arbitrary globally allowed ``.invalid`` label.
    """
    dynamic_header_value = (
        _STATIC_DYNAMIC_VALUE in rendered
        and re.search(r"authorization\s*:", rendered, re.IGNORECASE) is not None
    )
    if _dynamic_authorization_scheme(node, bindings) or dynamic_header_value:
        return rendered + " Authorization: Basic AAAAAAAAAAAAAAAA"
    return rendered


def _conservative_text(node: ast.AST, bindings: dict[str, Any]) -> str:
    """Render unresolved string expressions with credential-shaped probes."""
    value = _static_value(node, bindings)
    if type(value) is str:
        return value
    if isinstance(node, ast.Constant):
        literal = _static_scalar(node.value)
        return literal if type(literal) is str else _STATIC_DYNAMIC_VALUE
    if isinstance(node, ast.Name):
        bound = bindings.get(node.id, _STATIC_UNKNOWN)
        return bound if type(bound) is str else _STATIC_DYNAMIC_VALUE
    if isinstance(node, ast.JoinedStr):
        pieces: list[str] = []
        for part in node.values:
            if isinstance(part, ast.Constant):
                literal = _static_scalar(part.value)
                pieces.append(literal if type(literal) is str else _STATIC_DYNAMIC_VALUE)
            elif isinstance(part, ast.FormattedValue):
                pieces.append(_conservative_text(part.value, bindings))
            else:
                pieces.append(_STATIC_DYNAMIC_VALUE)
        return _with_dynamic_authorization_probe(node, bindings, "".join(pieces))
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        left = _conservative_text(node.left, bindings)
        right = _conservative_text(node.right, bindings)
        if isinstance(node.op, ast.Add):
            return _with_dynamic_authorization_probe(node, bindings, left + right)
        try:
            if isinstance(node.right, ast.Tuple):
                values = tuple(_conservative_text(child, bindings) for child in node.right.elts)
                rendered = left % values
            else:
                rendered = left % right
        except (IndexError, KeyError, TypeError, ValueError, OverflowError):
            rendered = left + " " + right
        try:
            credential_probe = left % _percent_probe_value(node.right, bindings, template=left)
        except (IndexError, KeyError, TypeError, ValueError, OverflowError):
            credential_probe = left
        # Scan both ordinary conservative rendering and the auth-scheme probe.
        # This preserves known template context without letting an unresolved
        # `%s` choose `Basic` or another credential scheme only at runtime.
        return _with_dynamic_authorization_probe(node, bindings, rendered + " " + credential_probe)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        method = node.func.attr
        receiver = _conservative_text(node.func.value, bindings)
        if method == "format":
            args = [_conservative_text(argument, bindings) for argument in node.args]
            keywords = {
                keyword.arg: _conservative_text(keyword.value, bindings)
                for keyword in node.keywords
                if keyword.arg is not None
            }
            try:
                rendered = receiver.format(*args, **keywords)
            except (IndexError, KeyError, ValueError, TypeError, OverflowError):
                rendered = receiver + " " + " ".join(args + list(keywords.values()))
            return _with_dynamic_authorization_probe(node, bindings, rendered)
        if method == "format_map" and len(node.args) == 1 and not node.keywords:
            mapping = _static_value(node.args[0], bindings)
            if isinstance(mapping, dict) and not _contains_static_unknown(mapping):
                try:
                    return _with_dynamic_authorization_probe(
                        node,
                        bindings,
                        receiver.format_map(mapping),
                    )
                except (IndexError, KeyError, ValueError, TypeError, OverflowError):
                    pass
            probe = _mapping_probe_from_template(receiver, format_map=True)
            try:
                rendered = receiver.format_map(probe)
            except (IndexError, KeyError, ValueError, TypeError, OverflowError):
                rendered = receiver + " " + " ".join(probe.values())
            return _with_dynamic_authorization_probe(node, bindings, rendered)
        if method == "join" and len(node.args) == 1 and not node.keywords:
            sequence = node.args[0]
            if isinstance(sequence, (ast.List, ast.Tuple)):
                rendered = receiver.join(_conservative_text(child, bindings) for child in sequence.elts)
                return _with_dynamic_authorization_probe(node, bindings, rendered)
            # Preserve the known separator and mark only the unknown payload.
            # A credential prefix in the receiver still fails closed, while an
            # unrelated dynamic join does not invent credential syntax that is
            # absent from the retained source.
            return _with_dynamic_authorization_probe(
                node,
                bindings,
                receiver + _STATIC_DYNAMIC_VALUE,
            )
        # Unsupported string methods retain any statically visible prefix. If
        # that prefix is an Authorization header, the unknown method result gets
        # a bounded Basic probe instead of disappearing into a safe sentinel.
        return _with_dynamic_authorization_probe(
            node,
            bindings,
            receiver + " " + _STATIC_DYNAMIC_VALUE,
        )
    return _STATIC_DYNAMIC_VALUE


def _ast_name_value_pairs(target: ast.AST, value_node: ast.AST) -> tuple[tuple[str, ast.AST], ...]:
    if isinstance(target, ast.Name):
        return ((target.id, value_node),)
    if isinstance(target, ast.Starred):
        return _ast_name_value_pairs(target.value, value_node)
    if isinstance(target, (ast.Tuple, ast.List)):
        values = value_node.elts if isinstance(value_node, (ast.Tuple, ast.List)) else ()
        pairs: list[tuple[str, ast.AST]] = []
        for index, child in enumerate(target.elts):
            child_value = values[index] if index < len(values) else value_node
            pairs.extend(_ast_name_value_pairs(child, child_value))
        return tuple(pairs)
    return ()


def _collect_static_bindings(tree: ast.AST) -> dict[str, Any]:
    bindings: dict[str, Any] = {}
    # A few fixed passes resolve simple module/function-local chains without
    # executing source. Once a name has both a known and an unknown assignment,
    # keep it unknown permanently. This conservative join prevents a later
    # redacted reassignment from sanitizing an earlier forged Authorization value.
    for _ in range(4):
        changed = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                value_node = node.value
                targets = node.targets
            elif isinstance(node, ast.AnnAssign):
                value_node = node.value
                targets = (node.target,)
            elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
                value_node = None
                targets = (node.target,)
            elif isinstance(node, ast.NamedExpr):
                value_node = node.value
                targets = (node.target,)
            else:
                continue
            for target in targets:
                if value_node is None:
                    pairs = ((target.id, target),) if isinstance(target, ast.Name) else ()
                else:
                    pairs = _ast_name_value_pairs(target, value_node)
                for name, source_node in pairs:
                    value = _STATIC_UNKNOWN if value_node is None else _static_value(source_node, bindings)
                    if value is not _STATIC_UNKNOWN and not isinstance(value, (str, list, tuple, dict)):
                        value = _STATIC_UNKNOWN
                    previous = bindings.get(name)
                    if previous is None and name not in bindings:
                        merged = value
                    elif previous is _STATIC_UNKNOWN or value is _STATIC_UNKNOWN:
                        merged = _STATIC_UNKNOWN
                    elif previous == value:
                        merged = previous
                    else:
                        merged = _STATIC_UNKNOWN
                    if name not in bindings or bindings[name] != merged:
                        bindings[name] = merged
                        changed = True
        if not changed:
            break
    return bindings


def _regex_call_nodes(tree: ast.AST) -> set[int]:
    result: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "compile" or not isinstance(node.func.value, ast.Name) or node.func.value.id not in {"re", "regex"}:
            continue
        result.update(id(child) for child in ast.walk(node))
    return result


DYNAMIC_CREDENTIAL_TARGET = "__dynamic_credential_target__"
SENSITIVE_MAPPING_BASE_NAMES = frozenset({
    "auth",
    "body",
    "cookies",
    "credentials",
    "data",
    "document",
    "headers",
    "json",
    "kwargs",
    "mapping",
    "metadata",
    "options",
    "params",
    "payload",
    "query",
    "request",
})
DYNAMIC_SENSITIVE_MAPPING_BASE_NAMES = frozenset({
    "auth",
    "cookies",
    "credentials",
    "headers",
    "params",
    "payload",
    "query",
    "request",
})


def _ast_root_name(node: ast.AST) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _ast_target_names(node: ast.AST, bindings: dict[str, Any]) -> tuple[str, ...]:
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, ast.Starred):
        return _ast_target_names(node.value, bindings)
    if isinstance(node, (ast.Tuple, ast.List)):
        names: list[str] = []
        for child in node.elts:
            names.extend(_ast_target_names(child, bindings))
        return tuple(names)
    if isinstance(node, ast.Attribute):
        return (node.attr,)
    if isinstance(node, ast.Subscript):
        key = _static_value(node.slice, bindings)
        root_name = _ast_root_name(node.value)
        if type(key) is str:
            # Nested fixture-test mutation helpers use arbitrary mapping roots
            # such as ``forged`` and ``mutated``. Route direct or explicitly
            # request-like containers, while keeping those helper mutations out
            # of the retained-source credential boundary.
            if root_name is not None and root_name.casefold() in SENSITIVE_MAPPING_BASE_NAMES:
                return (key,)
            return ()
        # An unknown subscript key is only a credential target when its direct
        # mapping receiver has a reviewed request-like role. Do not classify
        # every dynamic dictionary mutation as ``api_key``: fixture test helpers
        # commonly mutate an arbitrary ``request[key]`` field, while
        # ``headers[key]`` and ``params[key]`` must fail closed for runtime
        # credential values.
        root_name = _ast_root_name(node.value)
        if root_name is not None and root_name.casefold() in DYNAMIC_SENSITIVE_MAPPING_BASE_NAMES:
            return (DYNAMIC_CREDENTIAL_TARGET,)
        return ()
    return ()


def _ast_target_value_pairs(
    target: ast.AST,
    value_node: ast.AST,
    bindings: dict[str, Any],
) -> tuple[tuple[str, ast.AST], ...]:
    """Keep destructured target names paired with their source expressions."""

    if isinstance(target, ast.Starred):
        target = target.value
    if isinstance(target, (ast.Tuple, ast.List)):
        values = value_node.elts if isinstance(value_node, (ast.Tuple, ast.List)) else ()
        pairs: list[tuple[str, ast.AST]] = []
        for index, child in enumerate(target.elts):
            child_value = values[index] if index < len(values) else value_node
            pairs.extend(_ast_target_value_pairs(child, child_value, bindings))
        return tuple(pairs)
    return tuple((key, value_node) for key in _ast_target_names(target, bindings))


def _ast_iteration_value_pairs(
    target: ast.AST,
    iterable: ast.AST,
    bindings: dict[str, Any],
) -> tuple[tuple[str, ast.AST], ...]:
    """Pair literal loop elements with target names without executing source."""

    if isinstance(iterable, (ast.List, ast.Tuple, ast.Set)):
        pairs: list[tuple[str, ast.AST]] = []
        for element in iterable.elts:
            pairs.extend(_ast_target_value_pairs(target, element, bindings))
        return tuple(pairs)
    return _ast_target_value_pairs(target, iterable, bindings)


def _is_nonretained_ast_value(node: ast.AST) -> bool:
    """Recognize source-extraction expressions without executing them.

    Fixture validators often assign ``match.group(...)`` or ``request.get(...)``
    to a local named ``token`` before validating the value. The local name is
    worth routing when it reaches a retained Authorization construction, but
    the extraction expression itself is not a fixture credential. Keep this
    exemption structural and narrow; direct names such as ``runtime_secret``
    still receive the conservative credential probe.
    """

    if isinstance(node, ast.Constant):
        return type(node.value) not in {str, bytes}
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return node.func.attr in {
            "decode",
            "digest",
            "encode",
            "get",
            "group",
            "hexdigest",
            "read",
            "read_bytes",
            "read_text",
            "strip",
        }
    # Deterministic fixture validators may derive opaque handles from an
    # in-memory test secret (for example HMAC/base64 issuance). The expression
    # is source construction, not retained credential material; its string
    # literals are still visited independently by the AST scanner.
    if isinstance(node, (ast.BinOp, ast.JoinedStr)):
        for child in ast.walk(node):
            if not isinstance(child, ast.Call) or not isinstance(child.func, ast.Attribute):
                continue
            if child.func.attr in {"b64encode", "urlsafe_b64encode", "digest", "hexdigest"}:
                return True
    return False


def _validate_ast_sensitive_assignment(
    key: str,
    value_node: ast.AST,
    bindings: dict[str, Any],
    scan: Any,
) -> None:
    if key != DYNAMIC_CREDENTIAL_TARGET and not _is_credential_key_alias(key):
        return
    rendered = _conservative_text(value_node, bindings)
    # Source expressions such as ``session.access_token`` are structural
    # references, not retained values. Keep that narrow allowance local to AST
    # target routing; free text and JSON still require exact reviewed markers.
    if _is_nonretained_ast_value(value_node) or _is_placeholder(
        rendered,
        allow_structural_placeholders=True,
    ) or (
        key != DYNAMIC_CREDENTIAL_TARGET
        and isinstance(value_node, ast.Name)
        and _compact_key_alias(key) == _compact_key_alias(value_node.id)
    ):
        return
    # Unknown request-like keys are routed through a representative credential
    # family. This bounded probe catches ``headers[key] = runtime_secret`` while
    # avoiding a false positive for unrelated dynamic mappings.
    routed_key = "api_key" if key == DYNAMIC_CREDENTIAL_TARGET else key
    scan(f"{routed_key}={rendered}")


def _validate_python_file(
    path: Path,
    *,
    data: bytes | None = None,
    allow_synthetic_markers: bool = False,
    allow_test_negative_basic_auth: bool = False,
    allow_test_negative_rfc7617_token: bool = False,
    allowed_assignment_values: frozenset[str] = frozenset(),
    allowed_synthetic_full_values: frozenset[str] = frozenset(),
    allowed_structural_urls: frozenset[str] = frozenset(),
) -> None:
    """Scan Python literals, comments, and bounded string constructions.

    Fixture tests intentionally contain credential-shaped inputs to prove that
    their domain validators reject them. Regex-call arguments are still
    scanned for concrete credential data; only regex syntax is treated as such
    when checking URL hosts. The two exact negative-test allowances are passed
    by the manifest path, never inferred from a string's synthetic marker.
    """
    data = _read_bounded_bytes(path, MAX_ARTIFACT_BYTES) if data is None else data
    try:
        text = data.decode("utf-8")
        tree = ast.parse(text, filename=path.as_posix())
    except (UnicodeError, SyntaxError) as exc:
        raise ValidationError() from exc
    require(len(text) <= MAX_ARTIFACT_BYTES, "text artifact is too large")

    allowed_basic_auth_candidates = (
        TEST_NEGATIVE_BASIC_AUTH_CANDIDATES
        | frozenset({DYNAMIC_AUTHORIZATION_PROBE_CANDIDATE})
        if allow_test_negative_basic_auth
        else frozenset()
    )
    allowed_raw_rfc7617_tokens = (
        TEST_NEGATIVE_BASIC_AUTH_CANDIDATES
        if allow_test_negative_rfc7617_token
        else frozenset()
    )
    bindings = _collect_static_bindings(tree)
    regex_nodes = _regex_call_nodes(tree)

    def scan(value: str, *, regex_pattern: bool = False) -> None:
        _validate_text_value(
            value,
            check_assignments=True,
            allow_synthetic_markers=allow_synthetic_markers,
            allowed_basic_auth_candidates=allowed_basic_auth_candidates,
            allowed_raw_rfc7617_tokens=allowed_raw_rfc7617_tokens,
            allowed_assignment_values=allowed_assignment_values,
            allowed_synthetic_full_values=allowed_synthetic_full_values,
            regex_pattern=regex_pattern,
            allowed_structural_urls=allowed_structural_urls,
        )

    # Route credential-named Python targets, keyword arguments, and literal
    # mapping keys through the same assignment scanner as text and URLs. This
    # closes ``api_key = runtime_value`` and ``headers["x-api-key"] = ...``
    # without executing source.
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                for key, value_node in _ast_target_value_pairs(target, node.value, bindings):
                    _validate_ast_sensitive_assignment(key, value_node, bindings, scan)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            for key, value_node in _ast_target_value_pairs(node.target, node.value, bindings):
                _validate_ast_sensitive_assignment(key, value_node, bindings, scan)
        elif isinstance(node, ast.AugAssign):
            for key, value_node in _ast_target_value_pairs(node.target, node.value, bindings):
                _validate_ast_sensitive_assignment(key, value_node, bindings, scan)
        elif isinstance(node, ast.NamedExpr):
            for key, value_node in _ast_target_value_pairs(node.target, node.value, bindings):
                _validate_ast_sensitive_assignment(key, value_node, bindings, scan)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            for key, value_node in _ast_iteration_value_pairs(node.target, node.iter, bindings):
                _validate_ast_sensitive_assignment(key, value_node, bindings, scan)
        elif isinstance(node, ast.comprehension):
            for key, value_node in _ast_iteration_value_pairs(node.target, node.iter, bindings):
                _validate_ast_sensitive_assignment(key, value_node, bindings, scan)
        elif isinstance(node, ast.keyword) and node.arg is not None:
            _validate_ast_sensitive_assignment(node.arg, node.value, bindings, scan)
        elif isinstance(node, ast.Dict):
            for key_node, value_node in zip(node.keys, node.values):
                if isinstance(key_node, ast.Constant) and type(key_node.value) is str:
                    _validate_ast_sensitive_assignment(key_node.value, value_node, bindings, scan)

    for node in ast.walk(tree):
        regex_pattern = id(node) in regex_nodes
        if isinstance(node, ast.Constant):
            value = _static_scalar(node.value)
            if type(value) is str:
                scan(value, regex_pattern=regex_pattern)
        elif isinstance(node, (ast.JoinedStr, ast.BinOp, ast.Call)):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "compile":
                continue
            scan(_conservative_text(node, bindings), regex_pattern=regex_pattern)

    # Comments document detector rules and may contain source-shaped examples;
    # scan them too, with the same exact path-scoped allowances.
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.COMMENT:
                scan(token.string)
    except tokenize.TokenError as exc:
        raise ValidationError() from exc


def _safe_relative_path(value: Any, *, allow_directory: bool = False) -> str:
    require(type(value) is str and value and len(value) <= 240, "path is invalid")
    require("\x00" not in value and "\\" not in value and SAFE_PATH.fullmatch(value) is not None, "path is invalid")
    parts = value.split("/")
    require(all(part not in {"", ".", ".."} for part in parts), "path traversal is not allowed")
    if not allow_directory:
        require("." in parts[-1], "file path must name a file")
    return value


def _safe_child(root: Path, relative: str) -> Path:
    root_resolved = root.resolve()
    candidate = root / relative
    require(not candidate.is_symlink(), "artifact path must not be a symlink")
    try:
        child = candidate.resolve(strict=True)
        child.relative_to(root_resolved)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValidationError() from exc
    require(child.is_file(), "artifact path is not a regular file")
    return child


def _validate_digest(value: Any) -> str:
    require(type(value) is str and HEX64.fullmatch(value) is not None, "artifact digest is invalid")
    return value


def _canonical_validator_source_digest(data: bytes) -> str:
    matches = BASELINE_ANCHOR_PATTERN.findall(data)
    require(len(matches) == 1, "validator baseline anchor is missing")
    normalized = BASELINE_ANCHOR_PATTERN.sub(
        b'BASELINE_CANONICAL_SHA256 = "baseline-canonical-sha256"',
        data,
        count=1,
    )
    return hashlib.sha256(normalized).hexdigest()


def _open_stable_directory(root: Path) -> int:
    """Open a directory chain without following caller-controlled ancestors."""

    root = Path(root)
    require(root.is_absolute(), "stable root must be absolute")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    require(
        type(no_follow) is int and type(directory_flag) is int and type(nonblock) is int,
        "descriptor flags unavailable",
    )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | no_follow | nonblock | directory_flag
    current: int | None = None
    current_path = Path(root.anchor)
    transferred = False
    try:
        current = os.open(root.anchor, flags)
        for component in root.parts[1:]:
            candidate = current_path / component
            try:
                next_descriptor = os.open(component, flags, dir_fd=current)
            except OSError:
                require(candidate in TRUSTED_PATH_ALIASES, "unstable path ancestor")
                next_descriptor = os.open(component, flags & ~no_follow, dir_fd=current)
            os.close(current)
            current = next_descriptor
            current_path = candidate
        require(current is not None and stat.S_ISDIR(os.fstat(current).st_mode), "stable root is not a directory")
        transferred = True
        return current
    except ValidationError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValidationError() from exc
    finally:
        if current is not None and not transferred:
            try:
                os.close(current)
            except OSError:
                pass


def _stable_file_bytes(root: Path, relative_path: str, limit: int) -> bytes:
    """Capture one regular checkout file through stable directory descriptors."""

    parts = relative_path.split("/")
    require(parts and all(part not in {"", ".", ".."} for part in parts), "authority helper path is invalid")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    require(type(no_follow) is int and type(directory_flag) is int and type(nonblock) is int, "descriptor flags unavailable")
    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | no_follow | nonblock | directory_flag
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | no_follow | nonblock
    descriptors: list[int] = []
    file_descriptor: int | None = None
    try:
        current = _open_stable_directory(Path(root))
        descriptors.append(current)
        for part in parts[:-1]:
            current = os.open(part, directory_flags, dir_fd=current)
            descriptors.append(current)
        file_descriptor = os.open(parts[-1], file_flags, dir_fd=current)
        before = os.fstat(file_descriptor)
        require(stat.S_ISREG(before.st_mode), "authority helper is not a regular file")
        require(0 <= before.st_size <= limit, "authority helper exceeds the byte limit")
        data = bytearray()
        while len(data) < limit + 1:
            chunk = os.read(file_descriptor, min(64 * 1024, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        require(len(data) <= limit, "authority helper exceeds the byte limit")
        after = os.fstat(file_descriptor)
        require(
            (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            "authority helper changed during capture",
        )
        return bytes(data)
    except ValidationError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValidationError() from exc
    finally:
        if file_descriptor is not None:
            try:
                os.close(file_descriptor)
            except OSError:
                pass
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _authenticated_authority_verifier(repo_root: Path) -> types.ModuleType:
    """Execute only the standalone verifier bytes authenticated before compile."""

    source = _stable_file_bytes(repo_root, HARDENED_AUTHORITY_VERIFIER_PATH, HARDENED_AUTHORITY_VERIFIER_MAX_BYTES)
    require(
        HARDENED_AUTHORITY_VERIFIER_SHA256 != "__pending__"
        and hashlib.sha256(source).hexdigest() == HARDENED_AUTHORITY_VERIFIER_SHA256,
        "authority verifier source changed",
    )
    module_name = "_hermternal_authenticated_fixture_authority"
    module = types.ModuleType(module_name)
    module.__file__ = f"<authenticated:{HARDENED_AUTHORITY_VERIFIER_PATH}>"
    sys.modules[module_name] = module
    try:
        exec(compile(source, module.__file__, "exec"), module.__dict__)
    except (OSError, RuntimeError, TypeError, ValueError, SyntaxError) as exc:
        sys.modules.pop(module_name, None)
        raise ValidationError() from exc
    return module


def _git(repo_root: Path, *arguments: str) -> bytes:
    """Expose only the authenticated verifier's bounded Git command for tests."""

    verifier = _authenticated_authority_verifier(repo_root)
    try:
        return verifier._git(repo_root, *arguments)
    except Exception as exc:
        raise ValidationError() from exc


def _authority_commit(repo_root: Path, object_repo: Path | None = None) -> str:
    """Return the active authority introduction from the plain object repository."""

    require(object_repo is not None, "a separate plain object repository is required")
    return _trusted_authority(repo_root, object_repo)["authority_commit"]


def _git_blob(repo_root: Path, revision: str, path: str, object_repo: Path | None = None) -> tuple[str, bytes]:
    """Read one blob only through the authenticated verifier boundary."""

    require(object_repo is not None, "a separate plain object repository is required")
    verifier = _authenticated_authority_verifier(repo_root)
    try:
        with verifier._validate_object_repository(object_repo) as isolated_repo:
            return verifier._git_blob(isolated_repo, revision, path)
    except Exception as exc:
        raise ValidationError() from exc


def _validate_authority_manifest(authority: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    """Validate the exact final v2 predecessor shape without a v1 fallback."""

    strict_keys(authority, AUTHORITY_KEYS, "validator authority")
    require(authority["schema"] == VALIDATOR_AUTHORITY_SCHEMA, "validator authority schema changed")
    require(authority["role"] == VALIDATOR_AUTHORITY_ROLE, "validator authority role changed")
    source_commit = authority["source_commit"]
    require(type(source_commit) is str and HEX40.fullmatch(source_commit) is not None, "validator authority source is invalid")
    require(authority["canonicalization"] == "exact_bytes", "validator authority canonicalization changed")
    require(authority["synthetic_only"] is True and authority["live_claim"] is False, "validator authority live boundary changed")
    manifest = authority["artifact_manifest"]
    require(type(manifest) is list and len(manifest) == len(AUTHORITY_ARTIFACT_PATHS), "validator authority manifest is invalid")
    paths: list[str] = []
    records: list[dict[str, Any]] = []
    for index, raw in enumerate(manifest):
        record = strict_keys(raw, AUTHORITY_RECORD_KEYS, f"validator authority artifact[{index}]")
        path = record["path"]
        require(type(path) is str and path in AUTHORITY_ARTIFACT_PATHS, "validator authority artifact path is invalid")
        require(path not in paths, "validator authority artifact is duplicated")
        paths.append(path)
        require(type(record["blob_oid"]) is str and HEX40.fullmatch(record["blob_oid"]) is not None, "validator authority blob is invalid")
        _validate_digest(record["sha256"])
        require(
            type(record["size_bytes"]) is int
            and type(record["size_bytes"]) is not bool
            and 0 < record["size_bytes"] <= MAX_ARTIFACT_BYTES,
            "validator authority artifact size is invalid",
        )
        records.append(record)
    require(tuple(paths) == AUTHORITY_ARTIFACT_PATHS, "validator authority artifact order changed")
    return source_commit, records


def _active_authority_pins() -> tuple[str, str]:
    """Read exact active authority pins from the protected runtime boundary."""

    authority_commit = os.environ.get(ACTIVE_AUTHORITY_COMMIT_ENV)
    source_commit = os.environ.get(ACTIVE_SOURCE_COMMIT_ENV)
    require(
        type(authority_commit) is str and HEX40.fullmatch(authority_commit) is not None,
        "active authority introduction pin is missing",
    )
    require(
        type(source_commit) is str and HEX40.fullmatch(source_commit) is not None,
        "active authority source pin is missing",
    )
    return authority_commit, source_commit


def _trusted_authority(repo_root: Path, object_repo: Path | None = None) -> dict[str, Any]:
    """Load the active v2 authority through authenticated plain-repo Git code."""

    require(object_repo is not None, "a separate plain object repository is required")
    checkout_root = repo_root.resolve()
    object_root = object_repo.resolve()
    require(checkout_root != object_root, "checkout and object repository must be separate")
    verifier = _authenticated_authority_verifier(checkout_root)
    expected_authority_commit, expected_source_commit = _active_authority_pins()
    try:
        verifier.load_trusted_authority(
            object_root,
            authority_path=HISTORICAL_VALIDATOR_AUTHORITY_PATH,
            expected_authority_commit=EXPECTED_HISTORICAL_AUTHORITY_COMMIT,
            expected_source_commit=EXPECTED_HISTORICAL_SOURCE_COMMIT,
        )
        # The hardened authority is independently exact-pinned. Its direct
        # predecessor rule is checked below by the authenticated verifier; it
        # need not be a descendant of the historical final pin because the
        # current branch was restacked onto a separate reviewed base.
        authority = verifier.load_trusted_authority(
            object_root,
            authority_path=VALIDATOR_AUTHORITY_PATH,
            expected_authority_commit=expected_authority_commit,
            expected_source_commit=expected_source_commit,
        )
    except verifier.AuthorityError as exc:
        raise ValidationError() from exc
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ValidationError() from exc
    require(authority["schema"] == VALIDATOR_AUTHORITY_SCHEMA, "validator authority schema changed")
    require(authority["authority_path"] == VALIDATOR_AUTHORITY_PATH, "validator authority path changed")
    authority["role"] = VALIDATOR_AUTHORITY_ROLE
    return authority


def _validate_schema_document(schema: dict[str, Any]) -> None:
    strict_keys(schema, SCHEMA_KEYS, "schema")
    require(schema["$schema"] == "https://json-schema.org/draft/2020-12/schema", "schema dialect changed")
    require(schema["$id"] == SCHEMA_DOCUMENT_ID, "schema identifier changed")
    require(schema["title"] == "Hermternal language-neutral fixture index", "schema title changed")
    require(schema["type"] == "object" and schema["additionalProperties"] is False, "schema root changed")
    require(tuple(schema["required"]) == INDEX_KEYS, "schema required key order changed")
    properties = schema["properties"]
    require(type(properties) is dict and tuple(properties.keys()) == INDEX_KEYS, "schema properties changed")
    defs = schema["$defs"]
    expected_defs = ("path", "sha256", "platforms", "file", "fixture", "coverage", "parity", "state", "redaction", "benchmark")
    require(type(defs) is dict and tuple(defs.keys()) == expected_defs, "schema definitions changed")
    require(properties["schema"] == {"const": INDEX_SCHEMA}, "schema version rule changed")
    require(properties["contract"] == {"const": CONTRACT}, "schema contract rule changed")
    require(properties["synthetic_only"] == {"const": True}, "schema synthetic rule changed")
    require(properties["live_claim"] == {"const": False}, "schema live-claim rule changed")
    require(properties["evidence_status"] == {"enum": ["partial", "complete"]}, "schema evidence status changed")


def _validate_id(value: Any) -> str:
    require(type(value) is str and len(value) <= 120 and SAFE_ID.fullmatch(value) is not None, "identifier is invalid")
    return value


def _validate_string_list(value: Any, allowed: Iterable[str], *, nonempty: bool = True) -> tuple[str, ...]:
    require(type(value) is list, "list is required")
    if nonempty:
        require(bool(value), "list must not be empty")
    result: list[str] = []
    allowed_set = set(allowed)
    for item in value:
        require(type(item) is str and item in allowed_set, "list item is invalid")
        require(item not in result, "list contains a duplicate")
        result.append(item)
    return tuple(result)


def _validate_states(states: Any) -> tuple[str, ...]:
    require(type(states) is list, "state inventory must be a list")
    require(tuple(item.get("id") for item in states if type(item) is dict) == STATE_IDS, "state inventory changed")
    expected = {
        "pending": ("collection_in_progress", "blocked", "no_success_claim", "wait_or_cancel"),
        "empty": ("no_observations", "blocked", "no_success_claim", "collect_required_evidence"),
        "success": ("synthetic_fixture_validated", "blocked_live_compatibility", "artifact_only_no_live_claim", "not_applicable"),
        "failure": ("required_case_failed", "blocked", "retain_failure_evidence", "idempotent_collection_only"),
        "cancelled": ("cancelled_before_completion", "blocked", "no_outward_change", "resume_after_source_state_reread"),
        "unknown": ("result_unavailable", "blocked", "no_duplicate_prompt_session_ticket_or_pty_input", "reread_source_state_before_retry"),
    }
    for index, item in enumerate(states):
        record = strict_keys(item, STATE_KEYS, f"states[{index}]")
        identifier = _validate_id(record["id"])
        require(identifier == STATE_IDS[index], "state order changed")
        require(tuple(record[key] for key in STATE_KEYS[1:]) == expected[identifier], "state semantics changed")
        for key in STATE_KEYS[1:]:
            require(type(record[key]) is str and record[key], "state value is invalid")
    return STATE_IDS


def _validate_file_record(record: Any, index: int) -> tuple[str, str, int]:
    item = strict_keys(record, FILE_KEYS, f"files[{index}]")
    path = _safe_relative_path(item["path"])
    digest = _validate_digest(item["sha256"])
    require(type(item["size_bytes"]) is int and type(item["size_bytes"]) is not bool and item["size_bytes"] >= 0, "artifact size is invalid")
    return path, digest, item["size_bytes"]


def _validate_manifest_file(
    record: Any,
    *,
    fixtures_root: Path,
    fixture_relative_root: str,
    total_bytes: list[int],
) -> str:
    path, digest, size = _validate_file_record(record, 0)
    require(path == fixture_relative_root or path.startswith(fixture_relative_root + "/"), "artifact escapes fixture root")
    actual = _safe_child(fixtures_root, path)
    # Hashing, parsing, and redaction scanning must consume the same
    # descriptor-anchored bytes. Reopening ``actual`` after hashing would let a
    # replacement race authorize one file and scan another.
    relative_path = actual.relative_to(fixtures_root).as_posix()
    data = _stable_file_bytes(fixtures_root, relative_path, MAX_ARTIFACT_BYTES)
    require(size == len(data), "artifact size changed")
    require(digest == hashlib.sha256(data).hexdigest(), "artifact digest changed")
    total_bytes[0] += len(data)
    require(total_bytes[0] <= MAX_TOTAL_ARTIFACT_BYTES, "fixture artifacts exceed aggregate byte limit")
    suffix = Path(relative_path).suffix.casefold()
    # A registered file must have a scanner with defined semantics. Digesting
    # an unknown extension without inspecting its content would create an
    # unscanned credential boundary, so fail closed instead.
    require(suffix in SCANNED_ARTIFACT_SUFFIXES, "registered artifact extension is unsupported")
    allowed_assignment_values = EXACT_ASSIGNMENT_ALLOWANCES.get(relative_path, frozenset())
    allowed_synthetic_full_values = SYNTHETIC_FULL_VALUE_ALLOWANCES.get(relative_path, frozenset())
    allowed_structural_urls = STRUCTURAL_URL_ALLOWANCES.get(relative_path, frozenset())
    if suffix == ".json":
        document = _parse_json_bytes(data, require_object=False, reject_nul=False)
        _validate_redaction_tree(
            document,
            allowed_assignment_values=allowed_assignment_values,
            allowed_structural_urls=allowed_structural_urls,
        )
        _reject_live_claims(document)
    elif suffix == ".py":
        _validate_python_file(
            actual,
            data=data,
            allow_synthetic_markers=relative_path in SYNTHETIC_MARKER_PATHS,
            allow_test_negative_basic_auth=relative_path in TEST_NEGATIVE_BASIC_AUTH_PATHS,
            allow_test_negative_rfc7617_token=relative_path in TEST_NEGATIVE_RFC7617_TOKEN_PATHS,
            allowed_assignment_values=allowed_assignment_values,
            allowed_synthetic_full_values=allowed_synthetic_full_values,
            allowed_structural_urls=allowed_structural_urls,
        )
    else:
        _validate_text_file(
            actual,
            data=data,
            allowed_assignment_values=allowed_assignment_values,
            allowed_structural_urls=allowed_structural_urls,
        )
    return path


def _reject_live_claims(value: Any) -> None:
    if type(value) is dict:
        for key, child in value.items():
            normalized = _validated_key_for_routing(key)
            if normalized in {"live_claim", "live_run", "live_compatibility", "compatible"} and type(child) is bool:
                require(child is False, "fixture contains a live claim")
            _reject_live_claims(child)
    elif type(value) is list:
        for child in value:
            _reject_live_claims(child)


@dataclass
class _FixtureTraversalBudget:
    entries: int = 0
    directories: int = 0
    files: int = 0
    path_storage_bytes: int = 0

    def account(self, relative: str, *, directory: bool, depth: int) -> None:
        self.entries += 1
        require(self.entries <= MAX_FIXTURE_TRAVERSAL_ENTRIES, "fixture entry count exceeds the safe limit")
        require(depth <= MAX_FIXTURE_TRAVERSAL_DEPTH, "fixture traversal is too deep")
        try:
            path_bytes = len(os.fsencode(relative)) + 1
        except (OSError, UnicodeError, ValueError) as exc:
            raise ValidationError() from exc
        self.path_storage_bytes += path_bytes
        require(
            self.path_storage_bytes <= MAX_FIXTURE_PATH_STORAGE_BYTES,
            "fixture path storage exceeds the safe limit",
        )
        if directory:
            self.directories += 1
            require(
                self.directories <= MAX_FIXTURE_TRAVERSAL_DIRECTORIES,
                "fixture directory count exceeds the safe limit",
            )
        else:
            self.files += 1
            require(
                self.files <= MAX_FIXTURE_TRAVERSAL_FILES,
                "fixture file count exceeds the safe limit",
            )


def _iter_fixture_tree(
    directory: Path,
    *,
    relative_root: str,
    budget: _FixtureTraversalBudget,
) -> Iterator[tuple[str, bool]]:
    """Yield fixture entries lazily while bounding names and descriptors."""

    try:
        root_metadata = os.lstat(directory)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValidationError() from exc
    require(stat.S_ISDIR(root_metadata.st_mode), "fixture root is missing")
    pending: list[tuple[Path, str, int]] = [(directory, relative_root, 0)]
    while pending:
        current, current_relative, depth = pending.pop()
        try:
            with os.scandir(current) as entries:
                while True:
                    try:
                        entry = next(entries)
                    except StopIteration:
                        break
                    except OSError as exc:
                        raise ValidationError() from exc
                    name = entry.name
                    require(name not in {"", ".", ".."}, "fixture entry name is invalid")
                    relative = f"{current_relative}/{name}" if current_relative else name
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                    except (OSError, RuntimeError, ValueError) as exc:
                        raise ValidationError() from exc
                    mode = metadata.st_mode
                    if stat.S_ISLNK(mode):
                        raise ValidationError()
                    if stat.S_ISDIR(mode):
                        budget.account(relative, directory=True, depth=depth + 1)
                        yield relative, True
                        pending.append((current / name, relative, depth + 1))
                        continue
                    require(stat.S_ISREG(mode), "fixture contains an unsafe file")
                    budget.account(relative, directory=False, depth=depth + 1)
                    yield relative, False
        except ValidationError:
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            raise ValidationError() from exc


def _actual_fixture_files(
    relative_root: str,
    fixtures_root: Path,
    *,
    traversal_budget: _FixtureTraversalBudget | None = None,
) -> list[str]:
    candidate = fixtures_root / relative_root
    require(not candidate.is_symlink(), "fixture root must not be a symlink")
    # Use one canonical root for containment and relative paths. The lazy walk
    # below intentionally replaces Path.rglob so no directory listing or path
    # list is materialized before the finite metadata budget is checked.
    root = fixtures_root.resolve()
    directory = candidate.resolve()
    try:
        directory.relative_to(root)
    except ValueError as exc:
        raise ValidationError() from exc
    require(directory.is_dir(), "fixture root is missing")
    budget = traversal_budget or _FixtureTraversalBudget()
    files = [
        relative
        for relative, is_directory in _iter_fixture_tree(
            directory,
            relative_root=relative_root,
            budget=budget,
        )
        if not is_directory
    ]
    files.sort()
    require(bool(files), "fixture root has no files")
    return files


SUPPORTED_VALIDATOR_ROLE_PATTERN = re.compile(r"(?:validate|test_[A-Za-z0-9_]+)\.py$")
SUPPORTED_EXECUTABLE_MAIN_PATTERN = re.compile(
    r"if\s+__name__\s*==\s*['\"]__main__['\"]\s*:",
)


def _validate_validator_role(
    validator: str,
    *,
    fixture_root: str,
    actual_files: list[str],
    fixtures_root: Path,
) -> None:
    """Require a reviewed executable Python validator role, not a data file."""

    _safe_relative_path(validator)
    require(validator.endswith(".py"), "validator extension is unsupported")
    require(SUPPORTED_VALIDATOR_ROLE_PATTERN.fullmatch(validator) is not None, "validator role is unsupported")
    relative = f"{fixture_root}/{validator}"
    require(relative in actual_files, "validator is not a listed artifact")
    actual = _safe_child(fixtures_root, relative)
    data = _read_bounded_bytes(actual, MAX_ARTIFACT_BYTES)
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise ValidationError() from exc
    require(SUPPORTED_EXECUTABLE_MAIN_PATTERN.search(text) is not None, "validator is not executable")


def _validate_fixture_roots(
    document: dict[str, Any],
    state_ids: tuple[str, ...],
    coverage_ids: set[str],
    fixtures_root: Path,
    traversal_budget: _FixtureTraversalBudget,
) -> tuple[dict[str, str], dict[str, dict[str, frozenset[str]]], set[str]]:
    roots = document["fixture_roots"]
    require(type(roots) is list and bool(roots), "fixture roots are missing")
    seen_ids: dict[str, str] = {}
    fixture_details: dict[str, dict[str, frozenset[str]]] = {}
    seen_paths: set[str] = set()
    owned_files: set[str] = set()
    total_bytes = [0]
    previous_id = ""
    for index, raw in enumerate(roots):
        item = strict_keys(raw, FIXTURE_KEYS, f"fixture_roots[{index}]")
        identifier = _validate_id(item["id"])
        require(identifier > previous_id, "fixture roots must be sorted and unique")
        previous_id = identifier
        require(identifier not in seen_ids, "fixture id is duplicated")
        seen_ids[identifier] = item["status"]
        path = _safe_relative_path(item["path"], allow_directory=True)
        require(path not in seen_paths, "fixture path is duplicated")
        seen_paths.add(path)
        require(item["status"] in {"ready", "pending"}, "fixture status is invalid")
        require(item["contract"] == CONTRACT, "fixture contract changed")
        require(item["hermes_source_sha"] == HERMES_SOURCE_SHA and HEX40.fullmatch(item["hermes_source_sha"]), "fixture source pin changed")
        require(item["synthetic_only"] is True and item["live_claim"] is False, "fixture live boundary changed")
        platforms = _validate_string_list(item["platforms"], PLATFORMS)
        states = _validate_string_list(item["states"], state_ids)
        require(tuple(sorted(states)) == states, "fixture states must be sorted")
        fixture_coverage = _validate_string_list(item["coverage_ids"], coverage_ids)
        require(tuple(sorted(fixture_coverage)) == fixture_coverage, "fixture coverage ids must be sorted")
        fixture_details[identifier] = {
            "platforms": frozenset(platforms),
            "states": frozenset(states),
            "coverage_ids": frozenset(fixture_coverage),
        }
        validator = item["validator"]
        if validator is not None:
            _safe_relative_path(validator)
        files = item["files"]
        require(type(files) is list, "fixture files must be a list")
        if item["status"] == "pending":
            require(validator is None and files == [], "pending fixture must not claim artifacts")
            continue
        # Ready roots are executable evidence, not merely artifact folders. A
        # missing validator would let a root claim ready coverage without an
        # entry point that can validate its listed cases.
        require(type(validator) is str and bool(validator), "ready fixture must name a validator")
        require(bool(files), "ready fixture must list artifacts")
        actual_files = _actual_fixture_files(
            path,
            fixtures_root,
            traversal_budget=traversal_budget,
        )
        listed: list[str] = []
        for file_index, file_record in enumerate(files):
            record_path, _, _ = _validate_file_record(file_record, file_index)
            require(record_path > (listed[-1] if listed else ""), "fixture files must be sorted and unique")
            listed.append(record_path)
            owned_files.add(record_path)
        require(tuple(listed) == tuple(actual_files), "fixture file manifest is incomplete or stale")
        if validator is not None:
            _validate_validator_role(
                validator,
                fixture_root=path,
                actual_files=actual_files,
                fixtures_root=fixtures_root,
            )
        for file_index, file_record in enumerate(files):
            _validate_manifest_file(file_record, fixtures_root=fixtures_root, fixture_relative_root=path, total_bytes=total_bytes)
    require(len(seen_ids) == len(roots), "fixture id inventory is inconsistent")
    return seen_ids, fixture_details, owned_files


def _validate_coverage(
    document: dict[str, Any],
    fixture_statuses: dict[str, str],
    fixture_details: dict[str, dict[str, frozenset[str]]],
    state_ids: tuple[str, ...],
) -> tuple[set[str], set[str]]:
    coverage = document["coverage"]
    require(type(coverage) is list and bool(coverage), "coverage inventory is missing")
    seen: set[str] = set()
    previous = ""
    fixture_to_coverage: set[str] = set()
    reciprocal_links: set[tuple[str, str]] = set()
    for index, raw in enumerate(coverage):
        item = strict_keys(raw, COVERAGE_KEYS, f"coverage[{index}]")
        identifier = _validate_id(item["id"])
        require(identifier > previous, "coverage ids must be sorted and unique")
        previous = identifier
        require(identifier not in seen, "coverage id is duplicated")
        seen.add(identifier)
        status = item["status"]
        require(status in {"ready", "pending", "empty", "failure", "cancelled", "unknown"}, "coverage status is invalid")
        references = _validate_string_list(item["fixture_ids"], set(fixture_statuses), nonempty=False)
        require(tuple(sorted(references)) == references, "coverage fixture ids must be sorted")
        fixture_to_coverage.update(references)
        platforms = _validate_string_list(item["platforms"], PLATFORMS)
        require(tuple(sorted(platforms, key=PLATFORMS.index)) == platforms, "coverage platforms must use shared order")
        states = _validate_string_list(item["required_states"], state_ids)
        require(tuple(sorted(states, key=STATE_IDS.index)) == states, "coverage states must use shared order")
        for reference in references:
            reciprocal_links.add((reference, identifier))
            details = fixture_details[reference]
            require(identifier in details["coverage_ids"], "coverage reference is not reciprocal")
            require(set(platforms).issubset(details["platforms"]), "coverage platform exceeds fixture support")
            require(set(states).issubset(details["states"]), "coverage state exceeds fixture support")
        require(type(item["notes"]) is str and 0 < len(item["notes"]) <= 512, "coverage note is invalid")
        _validate_text_value(item["notes"])
        if status == "ready":
            require(bool(references), "ready coverage must cite a fixture")
            require(
                all(fixture_statuses.get(reference) == "ready" for reference in references),
                "ready coverage cites a pending or missing fixture",
            )
    expected_links = {
        (fixture_id, coverage_id)
        for fixture_id, details in fixture_details.items()
        for coverage_id in details["coverage_ids"]
    }
    require(reciprocal_links == expected_links, "fixture and coverage links are not reciprocal")
    require(fixture_to_coverage, "fixture roots are not connected to coverage")
    return seen, fixture_to_coverage


def _validate_index_document(document: dict[str, Any], repo_root: Path) -> tuple[int, int]:
    fixtures_root = (repo_root / "contracts/fixtures").resolve()
    require(fixtures_root.is_dir(), "fixture root is missing")
    strict_keys(document, INDEX_KEYS, "index")
    require(document["schema"] == INDEX_SCHEMA, "index schema changed")
    require(document["contract"] == CONTRACT, "index contract changed")
    require(document["hermes_source_sha"] == HERMES_SOURCE_SHA and HEX40.fullmatch(document["hermes_source_sha"]), "index source pin changed")
    require(document["synthetic_only"] is True and document["live_claim"] is False, "index live boundary changed")
    require(document["evidence_status"] in {"partial", "complete"}, "index evidence status is invalid")

    state_ids = _validate_states(document["states"])
    parity = strict_keys(document["parity"], PARITY_KEYS, "parity")
    require(parity == {
        "status": "synthetic_observed",
        "fixture_source": "one_shared_registry",
        "platforms": list(PLATFORMS),
        "pty_policy": "web_only_apple_blocked",
        "missing_result_policy": "block",
        "result_equivalence": "semantic_outcomes_not_platform_specific_wire_bytes",
        "live_claim": False,
    }, "parity contract changed")
    redaction = strict_keys(document["redaction"], REDACTION_KEYS, "redaction")
    require(redaction == {
        "synthetic_only": True,
        "contains_credentials": False,
        "contains_cookies": False,
        "contains_bearer_values": False,
        "contains_ticket_values": False,
        "contains_raw_pty_bytes": False,
        "contains_transcripts": False,
        "contains_live_hosts": False,
        "contains_user_data": False,
        "failure_output": "one_bounded_semantic_json_line",
    }, "redaction contract changed")
    benchmark = strict_keys(document["benchmark"], BENCHMARK_KEYS, "benchmark")
    benchmark_path = _safe_relative_path(benchmark["path"])
    require(benchmark_path == "validator/validation-baseline.json", "benchmark path changed")
    require(benchmark["threshold"] is None, "benchmark threshold must remain null")
    require(benchmark["evidence_mode"] == "observed_worktree_only", "benchmark evidence mode changed")
    require(benchmark["build_mode"] == "N/A - no production or release executable", "benchmark build mode changed")
    _safe_child(fixtures_root, benchmark_path)

    traversal_budget = _FixtureTraversalBudget()
    fixture_statuses, fixture_details, owned_files = _validate_fixture_roots(
        document,
        state_ids,
        set(item["id"] for item in document["coverage"]),
        fixtures_root,
        traversal_budget,
    )
    coverage_ids, referenced_fixtures = _validate_coverage(
        document,
        fixture_statuses,
        fixture_details,
        state_ids,
    )
    require(referenced_fixtures == set(fixture_statuses), "every fixture root must be covered exactly at least once")
    require(document["evidence_status"] == ("complete" if not any(item["status"] != "ready" for item in document["coverage"]) else "partial"), "evidence status does not reflect pending coverage")
    if document["evidence_status"] == "complete":
        require(not any(item["status"] != "ready" for item in document["coverage"]), "complete index contains blocked coverage")
    else:
        require(any(item["status"] != "ready" for item in document["coverage"]), "partial index has no blocked coverage")

    # The central validator is outside fixture_roots, so bind its directory to
    # one exact reviewed artifact set. Caches, dotfiles, binaries, sockets, and
    # future helper files must be reviewed and explicitly added before use.
    validator_root = fixtures_root / "validator"
    actual_central: set[str] = set()
    for relative, is_directory in _iter_fixture_tree(
        validator_root,
        relative_root="validator",
        budget=traversal_budget,
    ):
        if is_directory:
            continue
        actual_central.add(relative)
    require(actual_central == CENTRAL_VALIDATOR_ARTIFACTS, "central validator artifact inventory changed")

    all_owned_candidates: set[str] = set()
    separate_artifacts: set[str] = set()
    for relative, is_directory in _iter_fixture_tree(
        fixtures_root,
        relative_root="",
        budget=traversal_budget,
    ):
        if is_directory:
            continue
        # Do not skip hidden files, cache contents, bytecode, binaries, or
        # special entries. They are either explicitly rejected by the lazy
        # walker or become an unowned manifest entry and fail closed below.
        if relative in INTENTIONALLY_SEPARATE_ARTIFACTS:
            separate_artifacts.add(relative)
            continue
        if relative in {"README.md", "index.json", "schema.json"} or relative.startswith("validator/"):
            continue
        all_owned_candidates.add(relative)
    require(separate_artifacts == INTENTIONALLY_SEPARATE_ARTIFACTS, "separate authority artifact inventory changed")
    require(all_owned_candidates == owned_files, "unindexed fixture artifact exists")
    return len(fixture_statuses), len(coverage_ids)


def _validate_distribution(samples: list[Any], distribution: dict[str, Any]) -> None:
    require(len(samples) == BASELINE_REPETITIONS, "benchmark sample count changed")
    numeric: list[float] = []
    for sample in samples:
        require(type(sample) in {int, float} and type(sample) is not bool, "benchmark sample is not numeric")
        value = float(sample)
        require(math.isfinite(value) and 0 <= value <= 1_000_000, "benchmark sample is not bounded")
        numeric.append(value)
    strict_keys(distribution, DISTRIBUTION_KEYS, "benchmark distribution")
    values: list[float] = []
    for key in DISTRIBUTION_KEYS:
        value = distribution[key]
        require(type(value) in {int, float} and type(value) is not bool, "benchmark distribution is not numeric")
        converted = float(value)
        require(math.isfinite(converted) and 0 <= converted <= 1_000_000, "benchmark distribution is not bounded")
        values.append(converted)
    ordered = sorted(numeric)
    p50 = ordered[min(len(ordered) - 1, max(0, math.ceil(0.50 * len(ordered)) - 1))]
    p95 = ordered[min(len(ordered) - 1, max(0, math.ceil(0.95 * len(ordered)) - 1))]
    expected = {
        "min": min(numeric),
        "p50": p50,
        "p95": p95,
        "max": max(numeric),
        "mean": statistics.mean(numeric),
    }
    for key in DISTRIBUTION_KEYS:
        require(abs(float(distribution[key]) - expected[key]) < 0.001, "benchmark distribution does not match samples")
    require(values[0] <= values[1] <= values[2] <= values[3], "benchmark distribution is incoherent")


def _indexed_baseline_path(index: dict[str, Any], repo_root: Path) -> Path:
    """Resolve the one baseline path that the registry is allowed to consume."""
    benchmark = index.get("benchmark")
    require(type(benchmark) is dict, "benchmark metadata is missing")
    benchmark_path = _safe_relative_path(benchmark.get("path"))
    require(benchmark_path == "validator/validation-baseline.json", "benchmark path changed")
    fixtures_root = (repo_root / "contracts/fixtures").resolve()
    return _safe_child(fixtures_root, benchmark_path)


def _canonical_baseline_digest(document: dict[str, Any]) -> str:
    """Hash baseline evidence without recursing through this validator's digest."""
    normalized = dict(document)
    manifest: list[dict[str, Any]] = []
    self_size = 0
    for raw in document["artifact_manifest"]:
        record = dict(raw)
        if record.get("path") == BASELINE_SELF_MANIFEST_PATH:
            self_size = record["size_bytes"]
            record["sha256"] = "self-validator-sha256"
            record["size_bytes"] = 0
        manifest.append(record)
    normalized["artifact_manifest"] = manifest
    normalized["artifact_size_bytes"] = document["artifact_size_bytes"] - self_size
    encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_baseline(
    document: dict[str, Any],
    repo_root: Path,
    baseline_path: Path,
    *,
    canonical_baseline_path: Path | None = None,
    object_repo: Path | None = None,
) -> None:
    canonical = (canonical_baseline_path or (repo_root / "contracts/fixtures/validator/validation-baseline.json")).resolve()
    require(baseline_path.resolve() == canonical, "baseline path is not canonical")
    authority = _trusted_authority(repo_root, object_repo)
    authority_records = {record["path"]: record for record in authority["artifact_manifest"]}
    baseline_record = authority_records["contracts/fixtures/validator/validation-baseline.json"]
    baseline_bytes = _read_bounded_bytes(canonical, MAX_JSON_BYTES)
    require(
        len(baseline_bytes) == baseline_record["size_bytes"]
        and hashlib.sha256(baseline_bytes).hexdigest() == baseline_record["sha256"],
        "baseline bytes changed outside the reviewed trust root",
    )
    strict_keys(document, BASELINE_KEYS, "baseline")
    require(document["schema"] == BASELINE_SCHEMA, "baseline schema changed")
    require(document["fixture_schema"] == INDEX_SCHEMA, "baseline fixture schema changed")
    require(document["validator"] == "Python standard library only", "baseline validator changed")
    require(document["synthetic_only"] is True, "baseline synthetic flag changed")
    require(document["build_mode"] == "N/A - no production or release executable", "baseline build mode changed")
    require(document["threshold"] is None, "baseline threshold must remain null")
    environment = strict_keys(document["environment"], ("python", "implementation", "platform", "machine"), "baseline environment")
    for value in environment.values():
        require(type(value) is str and 0 < len(value) <= 128 and value.casefold() != "pending", "baseline environment is incomplete")
        _validate_text_value(value)
    require(type(document["artifact_manifest"]) is list and bool(document["artifact_manifest"]), "baseline artifact manifest is missing")
    listed: list[str] = []
    total = 0
    for index, raw in enumerate(document["artifact_manifest"]):
        path, digest, size = _validate_file_record(raw, index)
        require(path.startswith("contracts/fixtures/"), "baseline artifact escapes fixture root")
        require(path != baseline_path.resolve().relative_to(repo_root.resolve()).as_posix(), "baseline must not hash itself")
        require(path > (listed[-1] if listed else ""), "baseline artifact paths must be sorted and unique")
        listed.append(path)
        actual = _safe_child(repo_root.resolve(), path)
        data = _read_bounded_bytes(actual, MAX_ARTIFACT_BYTES)
        require(size == len(data) and digest == hashlib.sha256(data).hexdigest(), "baseline artifact manifest is stale")
        total += len(data)
    require(type(document["artifact_size_bytes"]) is int and type(document["artifact_size_bytes"]) is not bool and document["artifact_size_bytes"] == total, "baseline artifact size is stale")
    # The manifest binds validate.py for local reproducibility, while immutable
    # Git-object authority outside the fixture tree pins its exact bytes and the
    # exact baseline bytes. Rebinding scanner, manifests, baseline, anchor, and
    # checkout tests together therefore cannot rewrite the historical authority.
    require(CENTRAL_VALIDATOR_SOURCE_PATHS.issubset(set(listed)), "central validator source is outside the baseline binding")
    validator_source = _read_bounded_bytes(
        _safe_child(repo_root.resolve(), BASELINE_SELF_MANIFEST_PATH),
        MAX_ARTIFACT_BYTES,
    )
    validator_record = authority_records[BASELINE_SELF_MANIFEST_PATH]
    require(
        len(validator_source) == validator_record["size_bytes"]
        and hashlib.sha256(validator_source).hexdigest() == validator_record["sha256"],
        "validator source trust anchor changed",
    )
    for mode in ("normal", "optimized"):
        measurement = strict_keys(document[mode], MEASUREMENT_KEYS, f"baseline.{mode}")
        expected_command = "python3 -O contracts/fixtures/validator/validate.py" if mode == "optimized" else "python3 contracts/fixtures/validator/validate.py"
        require(measurement["command"] == expected_command, "benchmark command changed")
        require(type(measurement["repetitions"]) is int and type(measurement["repetitions"]) is not bool and measurement["repetitions"] == BASELINE_REPETITIONS, "benchmark repetitions changed")
        _validate_distribution(measurement["samples_ms"], measurement["distribution_ms"])
    require(type(document["notes"]) is str and 0 < len(document["notes"]) <= 512, "baseline notes are missing")
    _validate_text_value(document["notes"])
    require(_canonical_baseline_digest(document) == BASELINE_CANONICAL_SHA256, "baseline canonical content changed")


def validate_schema_document(schema: dict[str, Any]) -> None:
    """Validate the language-neutral schema contract without I/O."""
    _validate_schema_document(schema)


def validate_index_document(index: dict[str, Any], repo_root: Path = REPO_ROOT) -> tuple[int, int]:
    """Validate the registry and every listed artifact under ``repo_root``."""
    return _validate_index_document(index, repo_root.resolve())


def validate_baseline_document(
    baseline: dict[str, Any],
    repo_root: Path = REPO_ROOT,
    baseline_path: Path = BASELINE_PATH,
    *,
    object_repo: Path | None = None,
) -> None:
    """Validate observed benchmark evidence without inventing a threshold."""
    root = repo_root.resolve()
    _validate_baseline(
        baseline,
        root,
        baseline_path.resolve(),
        canonical_baseline_path=(root / "contracts/fixtures/validator/validation-baseline.json"),
        object_repo=object_repo,
    )


def validate_all(
    index: dict[str, Any],
    schema: dict[str, Any],
    baseline: dict[str, Any],
    *,
    repo_root: Path = REPO_ROOT,
    baseline_path: Path = BASELINE_PATH,
    object_repo: Path | None = None,
) -> tuple[int, int]:
    _validate_schema_document(schema)
    root = repo_root.resolve()
    # ``validate_all`` is a public API used by tests and tooling as well as the
    # CLI. Do not let a caller mutate a previously parsed index and bypass the
    # canonical checkout binding that protects the on-disk CLI path. Read the
    # canonical bytes through the stable descriptor helper before consuming the
    # caller object; equality is intentional, so semantic-but-different inputs
    # remain rejected while the file itself stays protected against replacement
    # races.
    canonical_index = _parse_json_bytes(
        _stable_file_bytes(root, "contracts/fixtures/index.json", MAX_JSON_BYTES),
    )
    require(index == canonical_index, "index object is not canonical")
    counts = _validate_index_document(index, root)
    canonical_baseline_path = _indexed_baseline_path(index, root)
    _validate_baseline(
        baseline,
        root,
        baseline_path.resolve(),
        canonical_baseline_path=canonical_baseline_path,
        object_repo=object_repo,
    )
    return counts


def format_failure(code: str) -> str:
    safe_code = code if code in {"fixture_validator_cli_invalid", "fixture_index_invalid"} else "fixture_index_invalid"
    payload = {
        "ok": False,
        "complete": False,
        "evidence_status": "blocked",
        "compatible": False,
        "live_claim": False,
        "error": {"code": safe_code, "message": SAFE_ERROR_MESSAGE},
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    require(len(encoded) <= MAX_ERROR_LENGTH, "failure marker is too long")
    return encoded


def emit_failure(code: str) -> None:
    print(format_failure(code))


class FailClosedArgumentParser(argparse.ArgumentParser):
    """Prevent argparse from echoing attacker-controlled arguments."""

    def error(self, _message: str) -> None:
        raise ArgumentParseError()


def main(argv: list[str] | None = None) -> int:
    parser = FailClosedArgumentParser(description=__doc__)
    parser.add_argument("--index", type=Path, default=INDEX_PATH)
    parser.add_argument("--schema", type=Path, default=SCHEMA_PATH)
    parser.add_argument("--baseline", type=Path, default=BASELINE_PATH)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--object-repo", type=Path, default=None)
    try:
        args = parser.parse_args(argv)
        repo_root = args.repo_root.resolve()
        object_repo = args.object_repo.resolve() if args.object_repo is not None else None
        require(object_repo is not None, "a separate plain object repository is required")
        require(object_repo != repo_root, "checkout and object repository must be separate")
        canonical_index_path = (repo_root / "contracts/fixtures/index.json").resolve()
        canonical_schema_path = (repo_root / "contracts/fixtures/schema.json").resolve()
        require(args.index.resolve() == canonical_index_path, "index path is not canonical")
        require(args.schema.resolve() == canonical_schema_path, "schema path is not canonical")
        index = load_json(canonical_index_path, limit=MAX_JSON_BYTES)
        canonical_baseline_path = _indexed_baseline_path(index, repo_root)
        # A caller-selected copy must never replace the checked-in evidence named
        # by the registry, even when that copy is schema-valid and redacted.
        require(args.baseline.resolve() == canonical_baseline_path, "baseline path is not canonical")
        schema = load_json(canonical_schema_path, limit=MAX_JSON_BYTES)
        baseline = load_json(canonical_baseline_path, limit=MAX_JSON_BYTES)
        require(type(index) is dict and type(schema) is dict and type(baseline) is dict, "registry documents must be objects")
        fixture_count, coverage_count = validate_all(
            index,
            schema,
            baseline,
            repo_root=repo_root,
            baseline_path=canonical_baseline_path,
            object_repo=object_repo,
        )
    except ArgumentParseError:
        emit_failure("fixture_validator_cli_invalid")
        return 2
    except Exception:
        # The CLI boundary is intentionally semantic-only. Never serialize an
        # exception, path, command line, key, or fixture value from external input.
        emit_failure("fixture_index_invalid")
        return 1
    print(json.dumps({
        "ok": True,
        "complete": index["evidence_status"] == "complete",
        "evidence_status": index["evidence_status"],
        "compatible": False,
        "live_claim": False,
        "fixture_count": fixture_count,
        "coverage_count": coverage_count,
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
