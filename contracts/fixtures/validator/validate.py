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
import binascii
import hashlib
import io
import json
import math
import os
import re
import stat
import statistics
import string
import struct
import tokenize
import unicodedata
from dataclasses import dataclass
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
SCANNED_ARTIFACT_SUFFIXES = frozenset({".json", ".md", ".py", ".txt"})
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
# Temporary-directory roots on macOS may expose /tmp through one of these
# system aliases. All other ancestors stay no-follow descriptor anchored.
TRUSTED_PATH_ALIASES = frozenset({Path("/tmp"), Path("/var"), Path("/var/folders"), Path("/var/tmp")})
# This reviewed digest is authority for its domain fixture, not a canonical
# fixture root. Keep the exemption exact so another review-anchor artifact still
# fails the aggregate unindexed-file boundary.
BASELINE_CANONICAL_SHA256 = "3b9078ce4d311b53d0493613b308402e4e2c2434d0582aa00f591803d003be02"

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SAFE_PATH = re.compile(r"^[A-Za-z0-9._/-]+$")
URL_PATTERN = re.compile(r"(?:https?|wss?)://[^\s\"'<>]+", re.IGNORECASE)
REGEX_HOST_LITERAL_PATTERN = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+"
)
PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----", re.IGNORECASE)
AWS_KEY_PATTERN = re.compile(r"\bAKIA[0-9A-Z]{16}\b", re.IGNORECASE)
PROVIDER_TOKEN_PATTERN = re.compile(r"\b(?:ghp|github_pat|glpat|sk|xox[baprs])[-_][A-Za-z0-9_-]{8,}\b", re.IGNORECASE)
BEARER_VALUE_PATTERN = re.compile(r"\bBearer\s+([A-Za-z0-9._~+/=-]{16,})\b", re.IGNORECASE)
BASIC_VALUE_PATTERN = re.compile(r"\bBasic\s+([A-Za-z0-9+/=_-]{16,})", re.IGNORECASE)
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
# Assignment/query scanning uses one bounded key/value grammar, then routes
# only credential-family aliases through the same redaction policy.
ASSIGNMENT_SECRET_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])(?P<key>[A-Za-z][A-Za-z0-9_.:/-]{0,64})\s*[=:]\s*"
    r"(?P<value>\"[^\"\r\n]{8,128}\"|'[^'\r\n]{8,128}'|[A-Za-z0-9._~+/=%-]{8,128})",
    re.IGNORECASE,
)
ASSIGNMENT_KEY_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])(?P<key>[A-Za-z][A-Za-z0-9_.:/-]{0,64})\s*(?P<separator>[=:])\s*",
    re.IGNORECASE,
)
MAX_ASSIGNMENT_VALUE_BYTES = 128
MAX_URL_LENGTH = 8 * 1024
MAX_URL_COMPONENT_LENGTH = 4 * 1024
MAX_URL_QUERY_PAIRS = 128
MAX_STATIC_RENDER_BYTES = MAX_ARTIFACT_BYTES
MAX_STATIC_RENDER_PARTS = 8_192
MAX_STATIC_COLLECTION_ITEMS = 256
MAX_STATIC_MAPPING_FIELDS = 128
MAX_STATIC_FORMAT_SPEC_BYTES = 256
MAX_STATIC_FORMAT_FIELD_WIDTH = MAX_ARTIFACT_BYTES
MAX_STATIC_FORMAT_NESTING = 64
DYNAMIC_AUTHORIZATION_PROBE_CANDIDATE = "A" * 16
# Sensitive JSON fields accept only reviewed semantic markers. A broad shape
# such as arbitrary snake_case or ``synthetic-*`` can disguise provider tokens,
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
SENSITIVE_DESCRIPTOR_KEYS = frozenset({
    "classification",
    "csrf",
    "pkce",
    "present",
    "reference",
    "session",
})

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

# These aliases are used by Python/text/query scanners only. Keep the
# aggregate redaction key set above unchanged so this correction does not
# widen the audited short trust surface for JSON shape fields.
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
# These exact negative-test values are retained only in the named source
# artifacts below. Path-scoping prevents the aggregate scanner from learning a
# global provider-token or Basic-auth exemption from one domain fixture.
TEST_NEGATIVE_BASIC_AUTH_CANDIDATE = "QWxhZGRpbjpvcGVuIHNlc2FtZQ" + "=="
TEST_NEGATIVE_BASIC_AUTH_CANDIDATES = frozenset({TEST_NEGATIVE_BASIC_AUTH_CANDIDATE})
TEST_NEGATIVE_BASIC_AUTH_PATHS = frozenset({
    "deployment-security/external-allowlist/test_validate.py",
})
TEST_NEGATIVE_RFC7617_TOKEN_PATHS = frozenset({
    "deployment-security/external-allowlist/test_validate.py",
    "image-attachment-lifecycle/test_validate.py",
})
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
RAW_RFC7617_TOKEN_PATTERN = re.compile(re.escape(TEST_NEGATIVE_BASIC_AUTH_CANDIDATE), re.IGNORECASE)
SYNTHETIC_FULL_VALUE_ALLOWANCES = {
    "chat-stream-completion/test_validate.py": frozenset({
        "ghp_abcdefghijk",
    }),
    "source-audit/model-options/test_model_options.py": frozenset({
        "-----BEGIN RSA PRIVATE KEY-----\nsynthetic\n-----END RSA PRIVATE KEY-----",
    }),
    "uncertain-delivery/test_validate.py": frozenset({
        "api_key=sk_test_123456789",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature",
        "ghp_1234567890abcdefghijk",
        "sk-proj-1234567890abcdef",
    }),
    "deployment-security/host-origin-mapping/test_validate.py": frozenset({
        "-----BEGIN PRIVATE KEY-----",
        "bearer=authorization: Bearer redaction-canary",
        "authorization: Bearer redaction-canary",
        "Cookie: redaction-canary",
    }),
}
# These exact malformed or reserved URL values are retained only in the named
# host/origin negative-test artifacts. A suffix or domain-wide allowance would
# turn structural test vocabulary into a live-host bypass.
# Two historical domain fixtures intentionally preserve one NUL-bearing parser
# input. They cannot be rewritten in this source-only commit because their bytes
# are part of the indexed negative-test corpus. Keep each exception bound to the
# canonical artifact path, exact JSON pointer/value, and reviewed ancestry:
# root dict -> ``cases`` list -> case dict -> ``request`` dict -> field. The
# ancestry check prevents a numeric object key from reproducing a list pointer.
_NUL_CHARACTER = chr(0)
NUL_FIELD_ALLOWANCES: dict[
    str,
    dict[str, tuple[str, tuple[tuple[str, str | int], ...]]],
] = {
    "attachment-policy/cases.json": {
        "/cases/10/request/filename": (
            "../unsafe name" + _NUL_CHARACTER + ".png",
            (("dict", "cases"), ("list", 10), ("dict", "request"), ("dict", "filename")),
        ),
    },
    "session-search/cases.json": {
        "/cases/28/request/query": (
            "atlas" + _NUL_CHARACTER,
            (("dict", "cases"), ("list", 28), ("dict", "request"), ("dict", "query")),
        ),
    },
}
# The aggregate scanner must preserve reviewed parser, signature, delimiter, and
# negative-test controls without turning any control byte into a generic source
# exemption. Values are UTF-8/bytes hex so this policy does not add new decoded
# controls to the validator source that it governs. The structural role includes
# the enclosing scope, callee or binding path, and an occurrence ordinal for
# repeated identical helper calls; line numbers are intentionally not authority.
# Dynamic rows use ``unknown`` only for reviewed opaque operands whose exact
# bytes cannot be recovered statically; a resolver/API name is never a blanket
# allowance, and every decoded construction receives an exact kind and hex row.
_PYTHON_CONTROL_LITERAL_ROWS: tuple[tuple[str, str, str, str, int], ...] = (
    ('attachment-policy/test_attachment_policy.py', 'bytes', '00', 'fn:AttachmentPolicyTests.test_filename_control_byte_is_escaped_and_omitted_or_null_defaults|call:self.assertNotIn|arg:0|path:direct', 0),
    ('attachment-policy/test_attachment_policy.py', 'bytes', '00', 'fn:AttachmentPolicyTests.test_gif_and_jpeg_metadata_terminators_are_opaque|assign:gif_comment|path:value/left/left/left/left/right/left', 0),
    ('attachment-policy/test_attachment_policy.py', 'bytes', '00', 'fn:AttachmentPolicyTests.test_polyglots_fail_closed_but_foreign_text_inside_a_valid_chunk_does_not|assign:chunk|path:value/right/left', 0),
    ('attachment-policy/test_attachment_policy.py', 'bytes', '00', 'fn:AttachmentPolicyTests.test_polyglots_fail_closed_but_foreign_text_inside_a_valid_chunk_does_not|assign:iend|path:value/right/left', 0),
    ('attachment-policy/test_attachment_policy.py', 'bytes', '0000000049454e44', 'fn:AttachmentPolicyTests.test_polyglots_fail_closed_but_foreign_text_inside_a_valid_chunk_does_not|assign:iend|path:value/left', 0),
    ('attachment-policy/test_attachment_policy.py', 'bytes', '003b', 'fn:AttachmentPolicyTests.test_gif_and_jpeg_metadata_terminators_are_opaque|assign:gif_comment|path:value/right', 0),
    ('attachment-policy/test_attachment_policy.py', 'bytes', '89504e470d0a1a0a', 'fn:AttachmentPolicyTests.test_polyglots_fail_closed_but_foreign_text_inside_a_valid_chunk_does_not|call:validate._format_from_bytes|arg:0|path:left', 0),
    ('attachment-policy/test_attachment_policy.py', 'bytes', '89504e470d0a1a0a', 'fn:AttachmentPolicyTests.test_polyglots_fail_closed_but_foreign_text_inside_a_valid_chunk_does_not|call:validate._format_from_bytes|arg:0|path:left/left', 0),
    ('attachment-policy/test_attachment_policy.py', 'str', '00', 'fn:AttachmentPolicyTests.test_filename_control_byte_is_escaped_and_omitted_or_null_defaults|call:self.assertIn|arg:0|path:direct', 0),
    ('attachment-policy/validate.py', 'bytes', '504b0304', 'fn:module|assign:_FOREIGN_SIGNATURES|path:value/elts[1]', 0),
    ('attachment-policy/validate.py', 'bytes', '504b0506', 'fn:module|assign:_FOREIGN_SIGNATURES|path:value/elts[2]', 0),
    ('attachment-policy/validate.py', 'bytes', '504b0708', 'fn:module|assign:_FOREIGN_SIGNATURES|path:value/elts[3]', 0),
    ('attachment-policy/validate.py', 'bytes', '89504e470d0a1a0a', 'fn:module|annassign:_FORMATS|path:value/elts[1]/elts[1]', 0),
    ('behavioral-probe/validate.py', 'str', '00', 'fn:_validate_redaction|call:require|arg:0|path:left', 0),
    ('chat-stream-completion/validate.py', 'str', '00', 'fn:_validate_redaction|call:_require|arg:0|path:values[0]/left', 0),
    ('chat-stream-completion/validate.py', 'str', '1f', 'fn:_validate_redaction|call:_require|arg:0|path:values[1]/left', 0),
    ('compatibility-attestation/test_validate.py', 'str', '636f6e74726f6c016d61726b6572', 'fn:RevisionAttestationValidationTests.test_baseline_text_redaction_rejects_hosts_material_and_controls|assign:mutations|path:value/elts[5]/elts[1]', 0),
    ('compatibility-attestation/test_validate.py', 'str', '6e756c006d61726b6572', 'fn:RevisionAttestationValidationTests.test_baseline_text_redaction_rejects_hosts_material_and_controls|assign:mutations|path:value/elts[6]/elts[1]', 0),
    ('connection-restoration/validate.py', 'str', '00', 'fn:_validate_redaction|call:_require|arg:0|path:values[0]/left', 0),
    ('connection-restoration/validate.py', 'str', '1f', 'fn:_validate_redaction|call:_require|arg:0|path:values[1]/left', 0),
    ('deep-link-grammar/test_validate.py', 'str', '01', 'fn:DeepLinkGrammarTests.test_all_lexical_rejections_fail_closed|assign:controls|path:value/keys[2]', 0),
    ('deep-link-grammar/validate.py', 'str', '01', 'fn:module|annassign:_EXPECTED_CASES|path:value/values[18]/values[0]/values[3]', 0),
    ('deployment-security/browser-auth/validate.py', 'bytes', '00', 'fn:_artifact_digest|call:digest.update|arg:0|path:direct', 0),
    ('deployment-security/browser-auth/validate.py', 'bytes', '00', 'fn:_artifact_digest|call:digest.update|arg:0|path:direct', 1),
    ('deployment-security/direct-port-denial/validate.py', 'bytes', '00', 'fn:_artifact_digest|call:digest.update|arg:0|path:direct', 0),
    ('deployment-security/direct-port-denial/validate.py', 'bytes', '00', 'fn:_artifact_digest|call:digest.update|arg:0|path:direct', 1),
    ('deployment-security/external-allowlist/validate.py', 'bytes', '00', 'fn:artifact_digest|call:digest.update|arg:0|path:direct', 0),
    ('deployment-security/external-allowlist/validate.py', 'bytes', '00', 'fn:artifact_digest|call:digest.update|arg:0|path:direct', 1),
    ('deployment-security/host-origin-mapping/test_validate.py', 'bytes', '6c696e65206f6e650a096c696e652074776f0d0a', 'fn:HostOriginMappingProofTests.test_text_artifacts_reject_controls_but_preserve_reviewed_whitespace|call:validate.scan_artifact_bytes|arg:1|path:direct', 0),
    ('deployment-security/host-origin-mapping/test_validate.py', 'str', '636861742e7075626c69632e696e76616c696409', 'fn:HostOriginMappingProofTests.test_exact_host_serialization_and_cardinality|assign:mutations|path:value/elts[27]/elts[0]', 0),
    ('deployment-security/host-origin-mapping/test_validate.py', 'str', '687474707309', 'fn:HostOriginMappingProofTests.test_exact_scheme_serialization|assign:rejected|path:value/elts[6]', 0),
    ('deployment-security/private-network-firewall/validate.py', 'bytes', '00', 'fn:_artifact_digest|call:digest.update|arg:0|path:direct', 0),
    ('deployment-security/private-network-firewall/validate.py', 'bytes', '00', 'fn:_artifact_digest|call:digest.update|arg:0|path:direct', 1),
    ('deployment-security/pty-local-adapter/validate.py', 'bytes', '00', 'fn:_artifact_digest|call:digest.update|arg:0|path:direct', 0),
    ('deployment-security/pty-local-adapter/validate.py', 'bytes', '00', 'fn:_artifact_digest|call:digest.update|arg:0|path:direct', 1),
    ('deployment-security/pty-local-adapter/validate.py', 'bytes', '00', 'fn:_canonical_digest|call:digest.update|arg:0|path:direct', 0),
    ('deployment-security/pty-local-adapter/validate.py', 'bytes', '00', 'fn:_canonical_digest|call:digest.update|arg:0|path:direct', 1),
    ('deployment-security/ws-ticket/validate.py', 'bytes', '20090d0a', 'fn:_BoundedJSONScanner|call:frozenset|arg:0|path:direct', 0),
    ('deployment-security/ws-ticket/validate.py', 'str', '00', 'fn:_validate_json_tree|call:require|arg:0|path:values[2]/left', 0),
    ('provider-discovery/test_provider_discovery.py', 'str', '00', 'fn:_git_blob_sha|assign:header|path:value/func/value/values[2]', 0),
    ('pty-contract/validate.py', 'str', '00', 'fn:artifact_manifest_digest|call:Constant.join|arg:0|path:elt/values[1]', 0),
    ('pty-contract/validate.py', 'str', '00', 'fn:artifact_manifest_digest|call:Constant.join|arg:0|path:elt/values[3]', 0),
    ('route-allowlist/test_route_allowlist.py', 'str', '00', 'fn:RouteAllowlistTests.test_rest_paths_reject_noncanonical_components_and_tickets|assign:invalid_paths|path:value/elts[7]/left/right', 0),
    ('session-lineage/validate.py', 'str', '00', 'fn:_semantic_string_is_safe|compare:In|path:left', 0),
    ('session-lineage/validate.py', 'str', '090a0d', 'fn:_semantic_string_is_safe|call:any|arg:0|path:elt/values[1]/comparators[0]', 0),
    ('session-persistence/validate.py', 'str', '00', 'fn:_semantic_string_is_safe|compare:In|path:left', 0),
    ('session-search/validate.py', 'str', '20090a', 'fn:_canonical_cases|call:_request|arg:0|path:direct', 0),
    ('source-audit/compatibility-gate/validate.py', 'str', '00', 'fn:_artifact_set_digest|assign:canonical|path:value/values[1]', 0),
    ('source-audit/compatibility-gate/validate.py', 'str', '00', 'fn:_artifact_set_digest|assign:canonical|path:value/values[3]', 0),
    ('source-audit/compatibility-gate/validate.py', 'str', '00', 'fn:_is_unsafe_relative_path|compare:In|path:left', 0),
    ('source-audit/compatibility-gate/validate.py', 'str', '00', 'fn:_validate_redaction|call:require|arg:0|path:left', 0),
    ('source-audit/native-password-provider/test_native_password_provider.py', 'str', '5b636f72655d0a0962617265203d2066616c73650a09776f726b74726565203d202f746d702f61747461636b65722d776f726b747265650a', 'fn:NativePasswordProviderFixtureTests.test_source_root_rejects_redirects_bare_and_child_shapes|call:BinOp.write_text|arg:0|path:direct', 0),
    ('source-audit/native-password-provider/test_native_password_provider.py', 'str', '7361666500636c61696d', 'fn:NativePasswordProviderFixtureTests.test_source_claim_and_ticket_fragment_redaction_fail_closed|call:validate.validate_synthetic_keys|arg:0|path:values[0]', 0),
    ('source-audit/native-password-provider/validate.py', 'bytes', '00', 'fn:_verify_git_checkout|call:tree_listing.split|arg:0|path:direct', 0),
    ('source-audit/native-password-provider/validate.py', 'bytes', '09', 'fn:_verify_git_checkout|call:record.split|arg:0|path:direct', 0),
    ('source-audit/native-password-provider/validate.py', 'str', '00', 'fn:validate_retained_artifacts|call:require|arg:0|path:left', 0),
    ('source-audit/native-password-provider/validate.py', 'str', '00', 'fn:validate_untrusted_text|call:require|arg:0|path:values[1]/left', 0),
    ('source-audit/pty-attach/validate.py', 'str', '00', 'fn:git_blob_sha|assign:header|path:value/func/value/values[2]', 0),
    ('uncertain-delivery/validate.py', 'str', '00', 'fn:_reject_repository_metadata|call:local_config.endswith|arg:0|path:direct', 0),
    ('uncertain-delivery/validate.py', 'str', '00', 'fn:_reject_repository_metadata|call:local_config.split|arg:0|path:direct', 0),
    ('validator/test_validate.py', 'str', '6c6976655f636c61696d00', 'fn:RegistryTests.test_invalid_unicode_live_claim_key_fails_before_normalization|call:validate._reject_live_claims|arg:0|path:keys[0]', 0),
    ('validator/validate.py', 'str', '00', 'fn:_safe_relative_path|call:require|arg:0|path:values[0]/left', 0),
    ('validator/validate.py', 'str', '00', 'fn:_validate_json_tree|call:require|arg:0|path:left', 0),
    ('validator/validate.py', 'str', '00', 'fn:_validate_json_tree|call:require|arg:0|path:values[1]/left', 0),
    ('validator/validate.py', 'str', '00', 'fn:_validate_redaction_tree|call:value.replace|arg:0|path:direct', 0),
    ('validator/validate.py', 'str', '00', 'fn:_validate_text_value|call:require|arg:0|path:left', 0),
    ('validator/validate.py', 'str', '0d', 'fn:_validate_regex_literal|compare:In|path:left', 0),
    ('validator/validate.py', 'str', '0d0a', 'fn:_scan_assignment_candidates|compare:In|path:comparators[0]', 0),
)

# Dynamic constructors are a separate finite policy. ``unknown`` is used only
# for reviewed chr(variable) generators whose exact call role is itself the
# negative-test or parser implementation boundary.
_PYTHON_CONTROL_CONSTRUCTION_ROWS: tuple[tuple[str, str, str, str, str, int], ...] = (
    ('attachment-policy/test_attachment_policy.py', 'bytes', '07', 'bytes', 'fn:AttachmentPolicyTests.test_gif_and_jpeg_metadata_terminators_are_opaque|assign:gif_comment|path:value/left/left/right', 0),
    ('chat-stream-completion/validate.py', 'unknown', '', 'bytes', 'fn:_read_bounded_regular|module-path', 0),
    ('deployment-security/host-origin-mapping/test_validate.py', 'bytes', '00', 'bytes', 'fn:HostOriginMappingProofTests.test_text_artifacts_reject_controls_but_preserve_reviewed_whitespace|container:Tuple|path:elts[0]/left/right', 0),
    ('deployment-security/host-origin-mapping/test_validate.py', 'bytes', '7f', 'bytes', 'fn:HostOriginMappingProofTests.test_text_artifacts_reject_controls_but_preserve_reviewed_whitespace|container:Tuple|path:elts[1]/left/right', 0),
    ('deployment-security/host-origin-mapping/validate.py', 'bytes', '00', 'bytes', 'fn:artifact_manifest|call:digest.update|arg:0|path:direct', 0),
    ('deployment-security/host-origin-mapping/validate.py', 'bytes', '00', 'bytes', 'fn:artifact_manifest|call:digest.update|arg:0|path:direct', 1),
    ('pty-contract/validate.py', 'unknown', '', 'bytes.fromhex', 'fn:resize_control|module-path', 0),
    ('pty-contract/validate.py', 'unknown', '', 'bytes.fromhex', 'fn:resize_control|module-path', 1),
    ('pty-contract/validate.py', 'unknown', '', 'bytes.fromhex', 'fn:segment_bytes|module-path', 0),
    ('pty-contract/validate.py', 'unknown', '', 'bytes.fromhex', 'fn:validate_no_byte_logging|call:len|arg:0|path:direct', 0),
    ('pty-contract/validate.py', 'unknown', '', 'bytes.fromhex', 'fn:validate_no_byte_logging|call:len|arg:0|path:direct', 1),
    ('pty-detach-race/validate.py', 'unknown', '', 'bytes.fromhex', 'fn:segment_size|assign:raw|path:value', 0),
    ('session-search/test_validate.py', 'unknown', '', 'chr', 'fn:SessionSearchTests.test_missing_empty_and_source_backed_normalization|call:validate._is_empty_query|arg:0|path:direct', 0),
    ('session-search/test_validate.py', 'unknown', '', 'chr', 'fn:SessionSearchTests.test_missing_empty_and_source_backed_normalization|call:validate._request|arg:0|path:direct', 0),
    ('session-search/validate.py', 'str', '00', 'chr', 'fn:_canonical_cases|call:_request|arg:0|path:right', 0),
    ('session-search/validate.py', 'str', '1c', 'chr', 'fn:_canonical_cases|call:_request|arg:0|path:direct', 0),
    ('session-search/validate.py', 'str', '1f', 'chr', 'fn:_canonical_cases|call:_request|arg:0|path:direct', 0),
    ('session-search/validate.py', 'unknown', '', 'chr', 'fn:module|call:frozenset|arg:0|path:elt', 0),
    ('uncertain-delivery/preflight.py', 'unknown', '', 'bytes', 'fn:_git|module-path', 0),
    ('uncertain-delivery/validate.py', 'unknown', '', 'bytes', 'fn:_run_git|container:Tuple|path:elts[1]', 0),
    ('uncertain-delivery/validate.py', 'unknown', '', 'bytes', 'fn:_run_git|container:Tuple|path:elts[2]', 0),
    ('validator/test_validate.py', 'str', '00', 'chr', 'fn:CliTests.test_historical_nul_parser_inputs_are_exactly_scoped|assign:nul|path:value', 0),
    ('validator/validate.py', 'str', '00', 'chr', 'fn:module|assign:_NUL_CHARACTER|path:value', 0),
    ('validator/validate.py', 'unknown', '', 'bytes', 'fn:_decode_url_component|assign:result|path:value/func/value', 0),
    ('validator/validate.py', 'unknown', '', 'bytes', 'fn:_stable_file_bytes|module-path', 0),
    ('validator/validate.py', 'unknown', '', 'chr', 'fn:_decode_regex_escape|container:Tuple|path:elts[0]', 0),
    ('validator/validate.py', 'unknown', '', 'chr', 'fn:_decode_regex_escape|container:Tuple|path:elts[0]', 1),
    ('validator/validate.py', 'unknown', '', 'chr', 'fn:_regex_class_prefix_result|call:values.update|arg:0|path:elt', 0),
    ('validator/validate.py', 'unknown', '', 'chr', 'fn:module|call:str.maketrans|arg:0|path:left/key', 0),
    ('validator/validate.py', 'unknown', '', 'chr', 'fn:module|call:str.maketrans|arg:0|path:left/value', 0),
)

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
    "deployment-security/direct-port-denial/test_validate.py": frozenset({
        "https://retained.invalid",
        "https://retained.invalid/",
        "https://retained.invalid/synthetic.invalid",
    }),
    "source-audit/oauth-browser/test_oauth_browser.py": frozenset({
        "https://github\\.com/NousResearch/hermes-agent/blob/",
    }),
}
# These exact short values are retained source-review or negative-test
# fragments. They are never generalized to a key family or path suffix.
EXACT_ASSIGNMENT_ALLOWANCES = {
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
    "deployment-security/external-allowlist/test_validate.py": frozenset({"raw-value"}),
    "deployment-security/private-network-firewall/test_validate.py": frozenset({"iptables"}),
    "deployment-security/pty-local-adapter/validate.py": frozenset({"synthetic.invalid"}),
    "provider-discovery/test_provider_discovery.py": frozenset({"synthetic.invalid"}),
    "pty-detach-race/test_validate.py": frozenset({"-Infinity", "Infinity"}),
    "pty-detach-race/validate.py": frozenset({"synthetic.invalid"}),
    "validator/test_validate.py": frozenset({"sk_test_123456789"}),
    "validator/validate.py": frozenset({"synthetic.invalid"}),
}
# One retained README documents a deliberately empty legacy query shape. Keep
# this as an exact complete line so it cannot authorize ``token=`` in source,
# JSON, another document, or a modified sentence.
EXACT_EMPTY_ASSIGNMENT_LINES = {
    "route-allowlist/README.md": frozenset({
        "  WebSocket. Non-gated local mode may use the source-defined `?token=` path;",
    }),
    "source-audit/native-password-provider/README.md": frozenset({
        "  WebSocket upgrades accept the ephemeral `?ticket=` value and reject the legacy",
    }),
}
# These complete retained values contain reviewed empty query or marker syntax.
# Keep them separate from ordinary full-value allowances: an exact credential
# allowance must never make ``token=`` or ``password=`` acceptable elsewhere.
EXACT_EMPTY_ASSIGNMENT_VALUES = {
    "route-allowlist/source_audit.json": frozenset({
        "?ticket=<single-use>",
        "The legacy ``?token=`` path is unconditionally rejected in gated mode",
    }),
    "route-allowlist/test_route_allowlist.py": frozenset({
        "?ticket=<single-use>",
        "The legacy ``?token=`` path is unconditionally rejected in gated mode",
    }),
    "source-audit/native-password-provider/source_audit.json": frozenset({
        "The legacy ``?token=`` path is unconditionally rejected in gated mode",
    }),
    "source-audit/native-password-provider/validate.py": frozenset({
        "The legacy ``?token=`` path is unconditionally rejected in gated mode",
    }),
    "uncertain-delivery/validate.py": frozenset({
        "password=",
        "api_key=",
        "api-key=",
        "api_token=",
        "api-token=",
    }),
}
# This review anchor has its own authority record. It is deliberately not a
# fixture root, but every other unindexed artifact must remain a hard failure.
INTENTIONALLY_SEPARATE_ARTIFACTS = frozenset({
    "review-anchors/deep-link-resolution.sha256",
})

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
    """Parse one already-captured byte snapshot under the strict JSON contract."""

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
    normalized = unicodedata.normalize("NFKC", key)
    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", normalized)
    return re.sub(r"[-.:/\s]+", "_", separated).casefold()


def _compact_key_alias(key: str) -> str:
    normalized = unicodedata.normalize("NFKC", key).casefold()
    return re.sub(r"[^a-z0-9]", "", normalized)


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


CREDENTIAL_KEY_COMPACT_ALIASES = frozenset(
    _compact_key_alias(key) for key in CREDENTIAL_KEY_FAMILIES
)


def _is_credential_key_alias(key: str) -> bool:
    return _compact_key_alias(key) in CREDENTIAL_KEY_COMPACT_ALIASES


def _normalize_scanned_text(value: str, *, preserve_controls: bool = False) -> str:
    # Scan both a compact representation and a boundary-preserving form. The
    # first catches credentials split by controls; the second keeps a preceding
    # word from swallowing a new assignment after a line break or separator.
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
        or ("." in lowered and _is_credential_key_alias(lowered.rsplit(".", 1)[-1]))
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


MAX_REGEX_ESCAPE_SOURCE_LENGTH = 64


def _decode_regex_escape(text: str, index: int) -> tuple[str, int, bool]:
    """Decode one bounded regex escape, preserving uncertainty explicitly."""

    if index + 1 >= len(text) or text[index] != "\\":
        return text[index:index + 1], index + 1, False
    marker = text[index + 1]
    # These escapes are URL syntax once the regex is evaluated. Decode them
    # before authority, path, and query policy so ``\\x3f`` cannot hide a query
    # delimiter or ``\\x5c`` can hide an authority backslash.
    if marker in ".-/:?#\\@&;=%":
        return marker, index + 2, False
    lengths = {"x": 2, "u": 4, "U": 8}
    if marker in lengths:
        end = index + 2 + lengths[marker]
        digits = text[index + 2:end]
        if re.fullmatch(r"[0-9A-Fa-f]+", digits) is None:
            return "?", min(len(text), end), True
        codepoint = int(digits, 16)
        if codepoint > 0x7F:
            return "?", min(len(text), end), True
        return chr(codepoint), min(len(text), end), False
    if marker == "N":
        # Never search an unbounded source for a closing brace. A malformed
        # named escape must consume a bounded prefix and let the caller fail
        # closed without rescanning the same long suffix.
        search_end = min(len(text), index + 3 + MAX_REGEX_ESCAPE_SOURCE_LENGTH)
        end = text.find("}", index + 3, search_end)
        if end < 0:
            return "?", search_end, True
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


REGEX_SCHEME_CANDIDATES = ("https://", "http://", "wss://", "ws://")
MAX_REGEX_SCHEME_SOURCE_LENGTH = 64
# Use the explicit ASCII intersection of Python and ECMAScript group names;
# accepting arbitrary header text could hide a URL or unknown regex escape.
REGEX_GROUP_NAME_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
# Scheme inference stays tightly bounded, but structural group discovery needs
# enough room to inspect reviewed long regexes whose literal prefix has already
# diverged from every supported URL scheme. Keep this ceiling independent so a
# longer group cannot make a possible scheme escape nested scanning.
MAX_REGEX_GROUP_SOURCE_LENGTH = 128


def _regex_scheme_token(text: str, index: int, expected: str) -> int | None:
    """Decode one bounded regex token while matching a fixed scheme character.

    Regex URL scanning must recognize escaped slashes without normalizing the
    whole pattern. Only a literal, one-character escape, or singleton character
    class can prove the expected scheme byte; ranges, alternation, and dynamic
    classes remain non-matches rather than becoming guessed URL authorities.
    """

    if index >= len(text):
        return None
    character = text[index]
    if character.casefold() == expected.casefold():
        return index + 1
    if character == "\\":
        if index + 1 >= len(text):
            return None
        marker = text[index + 1]
        if marker in {"/", ":"}:
            decoded, consumed, uncertain = marker, index + 2, False
        else:
            decoded, consumed, uncertain = _decode_regex_escape(text, index)
        if not uncertain and decoded.casefold() == expected.casefold():
            return consumed
        return None
    if character != "[":
        return None
    closing = text.find("]", index + 1, index + MAX_REGEX_SCHEME_SOURCE_LENGTH + 1)
    if closing < 0:
        return None
    body = text[index + 1:closing]
    if not body or body.startswith("^"):
        return None
    if len(body) == 1:
        decoded, uncertain = body, False
    elif body == r"\/" or body == r"\:":
        decoded, uncertain = body[1], False
    elif body.startswith("\\"):
        decoded, consumed, uncertain = _decode_regex_escape(body, 0)
        if consumed != len(body):
            return None
    else:
        return None
    if not uncertain and decoded.casefold() == expected.casefold():
        return closing + 1
    return None


def _regex_literal_sequence_end(text: str, index: int, expected: str) -> int | None:
    cursor = index
    for character in expected:
        if cursor - index >= MAX_REGEX_SCHEME_SOURCE_LENGTH:
            return None
        next_cursor = _regex_scheme_token(text, cursor, character)
        if next_cursor is None:
            return None
        cursor = next_cursor
    return cursor


def _regex_scheme_delimiter_end(text: str, index: int) -> int | None:
    cursor = _regex_scheme_token(text, index, ":")
    if cursor is None:
        return None
    cursor = _regex_scheme_token(text, cursor, "/")
    if cursor is None:
        return None
    return _regex_scheme_token(text, cursor, "/")


def _regex_class_span(text: str, index: int) -> tuple[int, str] | None:
    """Return one bounded character-class span without an unbounded search."""

    if index >= len(text) or text[index] != "[":
        return None
    cursor = index + 1
    limit = min(len(text), index + MAX_REGEX_SCHEME_SOURCE_LENGTH + 1)
    while cursor < limit:
        character = text[cursor]
        if character == "\\":
            _decoded, consumed, _uncertain = _decode_regex_escape(text, cursor)
            if consumed <= cursor:
                return None
            cursor = min(consumed, limit)
            continue
        if character == "]":
            return cursor + 1, text[index + 1:cursor]
        cursor += 1
    return None


def _regex_scheme_match_at(text: str, index: int) -> int | None:
    """Return the end of one literal-equivalent regex URL scheme."""

    for candidate in REGEX_SCHEME_CANDIDATES:
        cursor = index
        matched = True
        for expected in candidate:
            if cursor - index >= MAX_REGEX_SCHEME_SOURCE_LENGTH:
                matched = False
                break
            next_cursor = _regex_scheme_token(text, cursor, expected)
            if next_cursor is None or next_cursor - index > MAX_REGEX_SCHEME_SOURCE_LENGTH:
                matched = False
                break
            cursor = next_cursor
        if matched:
            return cursor
    return None


MAX_REGEX_SCHEME_PREFIX_OUTPUT_LENGTH = 5
MAX_REGEX_SCHEME_PREFIX_OUTPUTS = 128
# Nested regex constructs are inspected structurally, but only within these
# bounded budgets. A malformed or over-budget construct must never become a
# reason to skip a possible URL hidden in its body.
MAX_REGEX_NESTED_SCAN_DEPTH = 16
MAX_REGEX_NESTED_SCAN_NODES = 2_048
_REGEX_SCHEME_TARGETS = ("http", "https", "ws", "wss")


@dataclass(frozen=True)
class _RegexSchemePrefixResult:
    outputs: frozenset[tuple[str | None, ...]]
    end: int
    uncertain: bool = False
    construct: bool = False


@dataclass(frozen=True)
class _RegexSchemeProbe:
    scheme_end: int | None
    skip_end: int


def _regex_unknown_prefix_outputs(*, variable_length: bool) -> frozenset[tuple[str | None, ...]]:
    lengths = range(MAX_REGEX_SCHEME_PREFIX_OUTPUT_LENGTH + 1) if variable_length else (1,)
    return frozenset(tuple(None for _ in range(length)) for length in lengths)


def _regex_prefix_matches_target(pattern: tuple[str | None, ...], target: str) -> bool:
    if len(pattern) != len(target):
        return False
    return all(character is None or character == target[index] for index, character in enumerate(pattern))


def _regex_prefix_can_start_target(pattern: tuple[str | None, ...]) -> bool:
    return any(
        len(pattern) <= len(target)
        and all(character is None or character == target[index] for index, character in enumerate(pattern))
        for target in _REGEX_SCHEME_TARGETS
    )


def _regex_prefix_union(
    left: frozenset[tuple[str | None, ...]],
    right: frozenset[tuple[str | None, ...]],
) -> frozenset[tuple[str | None, ...]]:
    merged = set(left)
    merged.update(right)
    if len(merged) <= MAX_REGEX_SCHEME_PREFIX_OUTPUTS:
        return frozenset(merged)
    return _regex_unknown_prefix_outputs(variable_length=True)


def _regex_prefix_concat(
    left: frozenset[tuple[str | None, ...]],
    right: frozenset[tuple[str | None, ...]],
) -> frozenset[tuple[str | None, ...]]:
    merged: set[tuple[str | None, ...]] = set()
    for left_pattern in left:
        for right_pattern in right:
            pattern = left_pattern + right_pattern
            if len(pattern) <= MAX_REGEX_SCHEME_PREFIX_OUTPUT_LENGTH:
                merged.add(pattern)
            else:
                # Retain a bounded prefix one byte longer than every supported
                # scheme. It proves that this branch cannot equal a scheme,
                # while keeping shorter alternatives available for a real URL.
                # Replacing the branch with unknown outputs would make a
                # proven non-match look like a possible live scheme.
                merged.add(pattern[: MAX_REGEX_SCHEME_PREFIX_OUTPUT_LENGTH + 1])
            if len(merged) > MAX_REGEX_SCHEME_PREFIX_OUTPUTS:
                return _regex_unknown_prefix_outputs(variable_length=True)
    return frozenset(merged)


def _regex_prefix_result(
    outputs: frozenset[tuple[str | None, ...]],
    end: int,
    *,
    uncertain: bool = False,
    construct: bool = False,
) -> _RegexSchemePrefixResult:
    return _RegexSchemePrefixResult(outputs, end, uncertain, construct)


def _regex_class_atom_values(
    text: str,
    index: int,
) -> tuple[set[str] | None, int, bool]:
    if index >= len(text):
        return None, index, True
    if text[index] != "\\":
        return {text[index]}, index + 1, False
    if index + 1 >= len(text):
        return None, index + 1, True
    marker = text[index + 1]
    if marker == "d":
        return set(string.digits), index + 2, False
    if marker == "s":
        return set(" \\t\\r\\n\\f\\v"), index + 2, False
    if marker == "w":
        return set(string.ascii_letters + string.digits + "_"), index + 2, False
    if marker in "DSW":
        return None, index + 2, True
    if marker in "abfnrtv":
        return {bytes("\\" + marker, "ascii").decode("unicode_escape")}, index + 2, False
    decoded, consumed, uncertain = _decode_regex_escape(text, index)
    if not uncertain and len(decoded) == 1:
        return {decoded}, consumed, False
    return None, max(index + 1, consumed), True


def _regex_class_prefix_result(text: str, index: int) -> _RegexSchemePrefixResult:
    span = _regex_class_span(text, index)
    if span is None:
        return _regex_prefix_result(
            _regex_unknown_prefix_outputs(variable_length=False),
            min(len(text), index + MAX_REGEX_SCHEME_SOURCE_LENGTH),
            uncertain=True,
            construct=True,
        )
    end, body = span
    if not body or body.startswith("^"):
        return _regex_prefix_result(
            _regex_unknown_prefix_outputs(variable_length=False),
            end,
            uncertain=True,
            construct=True,
        )
    values: set[str] = set()
    cursor = 0
    uncertain = False
    while cursor < len(body):
        first, first_end, first_uncertain = _regex_class_atom_values(body, cursor)
        if first_end <= cursor:
            uncertain = True
            break
        cursor = first_end
        if cursor < len(body) - 1 and body[cursor] == "-":
            second, second_end, second_uncertain = _regex_class_atom_values(body, cursor + 1)
            if first is not None and second is not None and len(first) == 1 and len(second) == 1:
                start = ord(next(iter(first)))
                finish = ord(next(iter(second)))
                if start <= finish and finish - start <= MAX_REGEX_SCHEME_PREFIX_OUTPUTS:
                    values.update(chr(codepoint) for codepoint in range(start, finish + 1))
                    cursor = second_end
                else:
                    uncertain = True
                    cursor = max(cursor + 1, second_end)
            else:
                uncertain = True
                cursor = max(cursor + 1, second_end)
            uncertain = uncertain or first_uncertain or second_uncertain
            continue
        values.update(first or ())
        uncertain = uncertain or first_uncertain
    if uncertain or not values:
        return _regex_prefix_result(
            _regex_unknown_prefix_outputs(variable_length=False),
            end,
            uncertain=True,
            construct=True,
        )
    outputs = frozenset((character.casefold(),) for character in values if len(character.casefold()) == 1)
    if not outputs:
        outputs = _regex_unknown_prefix_outputs(variable_length=False)
        uncertain = True
    return _regex_prefix_result(outputs, end, uncertain=uncertain, construct=True)


def _regex_bounded_group_span(
    text: str,
    index: int,
    *,
    max_length: int = MAX_REGEX_GROUP_SOURCE_LENGTH,
) -> tuple[int, bool]:
    """Return a bounded group end and whether the closing delimiter was seen.

    Nested constructs keep the short structural bound, while one top-level
    regex group may span the bounded static-render input. This prevents a
    retained detector expression from being rejected before its full body is
    scanned for a late live authority.
    """

    require(max_length > 0, "regex group bound is invalid")
    limit = min(len(text), index + max_length)
    depth = 0
    in_class = False
    cursor = index
    while cursor < limit:
        character = text[cursor]
        if character == "\\":
            _decoded, consumed, _uncertain = _decode_regex_escape(text, cursor)
            cursor = max(cursor + 1, min(consumed, limit))
            continue
        if in_class:
            if character == "]":
                in_class = False
            cursor += 1
            continue
        if character == "[":
            in_class = True
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth <= 0:
                return cursor + 1, True
        cursor += 1
    return limit, False


def _regex_group_end(text: str, index: int) -> int:
    return _regex_bounded_group_span(text, index)[0]


def _regex_has_top_level_alternation(text: str, start: int, end: int) -> bool:
    """Return whether one bounded group body has a top-level branch join."""

    parenthesis_depth = 0
    in_class = False
    index = start
    while index < end:
        character = text[index]
        if character == "\\":
            _decoded, consumed, _uncertain = _decode_regex_escape(text, index)
            require(consumed <= end, "regex escape crosses group boundary")
            index = max(index + 1, consumed)
            continue
        if in_class:
            if character == "]":
                in_class = False
            index += 1
            continue
        if character == "[":
            in_class = True
        elif character == "(":
            parenthesis_depth += 1
        elif character == ")":
            if parenthesis_depth:
                parenthesis_depth -= 1
        elif character == "|" and parenthesis_depth == 0:
            return True
        index += 1
    return False


def _regex_has_regex_construct(text: str, start: int, end: int) -> bool:
    """Return whether a long group body contains bounded regex syntax."""

    return any(character in r"\\[]{}*+?^$|" for character in text[start:end])


def _regex_group_body_start(text: str, index: int) -> tuple[int | None, int, bool]:
    """Return bounded group-body start, assertion mode, and recognition status."""

    if not text.startswith("(", index):
        return None, 0, False
    if text.startswith("(?:", index) or text.startswith("(?>", index):
        return index + 3, 0, True
    if text.startswith("(?=", index):
        return index + 3, 1, True
    if text.startswith("(?!", index):
        return index + 3, -1, True
    if text.startswith("(?<=", index):
        return index + 4, 1, True
    if text.startswith("(?<!", index):
        return index + 4, -1, True
    if text.startswith("(?P<", index):
        header_start = index + 4
    elif text.startswith("(?<", index):
        header_start = index + 3
    else:
        header_start = None
    if header_start is not None:
        limit = min(len(text), index + MAX_REGEX_GROUP_SOURCE_LENGTH)
        closing = text.find(">", header_start, limit)
        require(closing >= 0, "named regex group header is incomplete")
        name = text[header_start:closing]
        require(REGEX_GROUP_NAME_PATTERN.fullmatch(name) is not None, "named regex group header is malformed")
        return closing + 1, 0, True
    if text.startswith("(?", index):
        limit = min(len(text), index + MAX_REGEX_GROUP_SOURCE_LENGTH)
        colon = text.find(":", index + 2, limit)
        if colon >= 0:
            flags = text[index + 2:colon]
            if flags and all(character.isalpha() or character == "-" for character in flags):
                return colon + 1, 0, True
        return None, 0, False
    return index + 1, 0, True


def _regex_parse_source_prefix(
    text: str,
    index: int,
    depth: int,
    required_length: int,
) -> frozenset[tuple[str | None, ...]]:
    """Parse only a bounded upcoming prefix for lookahead assertions."""

    values: frozenset[tuple[str | None, ...]] = frozenset({()})
    cursor = index
    limit = min(len(text), index + MAX_REGEX_SCHEME_SOURCE_LENGTH)
    while cursor < limit and max((len(pattern) for pattern in values), default=0) < required_length:
        atom = _regex_apply_quantifier(text, _regex_parse_atom(text, cursor, depth))
        if atom.end <= cursor:
            break
        values = _regex_prefix_concat(values, atom.outputs)
        cursor = min(atom.end, limit)
    return values


def _regex_suffix_concat(
    left: frozenset[tuple[str | None, ...]],
    right: frozenset[tuple[str | None, ...]],
    required_length: int,
) -> frozenset[tuple[str | None, ...]]:
    """Keep only bounded suffixes needed to reason about lookbehind input."""

    merged: set[tuple[str | None, ...]] = set()
    for left_pattern in left:
        for right_pattern in right:
            combined = left_pattern + right_pattern
            if len(combined) > required_length:
                combined = combined[-required_length:] if required_length else ()
            merged.add(combined)
            if len(merged) > MAX_REGEX_SCHEME_PREFIX_OUTPUTS:
                return _regex_unknown_prefix_outputs(variable_length=True)
    return frozenset(merged)


def _regex_parse_source_suffix(
    text: str,
    end: int,
    depth: int,
    required_length: int,
) -> frozenset[tuple[str | None, ...]]:
    """Parse a bounded suffix of source immediately preceding a lookbehind."""

    if end <= 0:
        # No preceding source is insufficient evidence for a contradiction;
        # callers must still inspect a positive lookbehind body for hidden URLs.
        return frozenset()
    if required_length <= 0:
        return frozenset({()})
    values: frozenset[tuple[str | None, ...]] = frozenset({()})
    cursor = 0
    limit = min(end, MAX_REGEX_SCHEME_SOURCE_LENGTH)
    while cursor < limit:
        if text[cursor] == "|":
            # Branch joins require a full regex grammar; keep the suffix
            # uncertain rather than pretending one branch is authoritative.
            return _regex_unknown_prefix_outputs(variable_length=True)
        atom = _regex_apply_quantifier(text, _regex_parse_atom(text, cursor, depth))
        if atom.end <= cursor or atom.end > end:
            return _regex_unknown_prefix_outputs(variable_length=True)
        values = _regex_suffix_concat(values, atom.outputs, required_length)
        cursor = atom.end
    if cursor != end:
        return _regex_unknown_prefix_outputs(variable_length=True)
    return values


def _regex_assertion_group_start(text: str, index: int) -> int | None:
    """Find a nearby lookbehind group when callers provide its closing index."""

    if text.startswith("(?<=", index) or text.startswith("(?<!", index):
        return index
    search_start = max(0, index - MAX_REGEX_GROUP_SOURCE_LENGTH)
    for marker in ("(?<=", "(?<!"):
        candidate = text.rfind(marker, search_start, index)
        if candidate >= 0 and _regex_group_end(text, candidate) == index:
            return candidate
    return None


def _regex_assertion_is_contradictory(
    text: str,
    index: int,
    assertion_outputs: frozenset[tuple[str | None, ...]],
    mode: int,
    depth: int,
    *,
    lookbehind: bool | None = None,
) -> bool:
    """Check assertion satisfiability against the correct side of input.

    Lookaheads compare against source after the assertion. Lookbehinds compare
    against the bounded source suffix before the assertion; using following
    source for a lookbehind can incorrectly discard a satisfiable live URL.
    """

    exact_outputs = tuple(
        output for output in assertion_outputs
        if output and all(character is not None for character in output)
    )
    if not exact_outputs:
        return False
    required_length = max(len(output) for output in exact_outputs)
    assertion_start = _regex_assertion_group_start(text, index)
    if lookbehind is None:
        lookbehind = assertion_start is not None
    if lookbehind:
        if assertion_start is None:
            return False
        context = _regex_parse_source_suffix(text, assertion_start, depth, required_length)
        if not context or any(len(pattern) < required_length for pattern in context):
            # A short or missing prefix cannot prove either assertion mode;
            # external input may complete the positive lookbehind body.
            return False
        if mode == 1:
            return not any(
                any(
                    len(pattern) >= len(output)
                    and all(
                        pattern[-len(output) + position] is None
                        or pattern[-len(output) + position] == output[position]
                        for position in range(len(output))
                    )
                    for output in exact_outputs
                )
                for pattern in context
            )
        return all(
            any(
                len(pattern) == len(output)
                and all(
                    pattern[position] is not None and pattern[position] == output[position]
                    for position in range(len(output))
                )
                for output in exact_outputs
            )
            for pattern in context
        )

    upcoming = _regex_parse_source_prefix(text, index, depth, required_length)
    if not upcoming or any(len(pattern) < required_length for pattern in upcoming):
        # A short or missing suffix cannot prove either assertion mode;
        # external input may complete the positive lookahead body.
        return False
    if mode == 1:
        return not any(
            any(
                len(pattern) >= len(output)
                and all(
                    pattern[position] is None or pattern[position] == output[position]
                    for position in range(len(output))
                )
                for output in exact_outputs
            )
            for pattern in upcoming
        )
    return all(
        any(
            len(pattern) == len(output)
            and all(
                pattern[position] is not None and pattern[position] == output[position]
                for position in range(len(output))
            )
            for output in exact_outputs
        )
        for pattern in upcoming
    )


def _regex_parse_atom(text: str, index: int, depth: int) -> _RegexSchemePrefixResult:
    if depth > 16 or index >= len(text):
        return _regex_prefix_result(
            _regex_unknown_prefix_outputs(variable_length=True),
            min(len(text), index + 1),
            uncertain=True,
            construct=True,
        )
    character = text[index]
    if character == "[":
        return _regex_class_prefix_result(text, index)
    if character == "(":
        body_start, assertion_mode, recognized = _regex_group_body_start(text, index)
        lookbehind = text.startswith("(?<=", index) or text.startswith("(?<!", index)
        group_end = _regex_group_end(text, index)
        if body_start is None:
            # Unknown group syntax is itself a potential dynamic construct. Do
            # not descend into it and later rediscover a hidden URL prefix.
            return _regex_prefix_result(
                _regex_unknown_prefix_outputs(variable_length=True),
                group_end,
                uncertain=True,
                construct=True,
            )
        result = _regex_parse_alternation(text, body_start, depth + 1)
        if assertion_mode:
            contradictory = _regex_assertion_is_contradictory(
                text,
                index if lookbehind else result.end,
                result.outputs,
                assertion_mode,
                depth + 1,
                lookbehind=lookbehind,
            )
            return _regex_prefix_result(
                frozenset() if contradictory else frozenset({()}),
                result.end,
                uncertain=not contradictory,
                construct=True,
            )
        return _regex_prefix_result(
            result.outputs,
            result.end,
            uncertain=result.uncertain or not recognized,
            construct=True,
        )
    if character == "\\":
        if index + 1 >= len(text):
            return _regex_prefix_result(
                _regex_unknown_prefix_outputs(variable_length=False),
                index + 1,
                uncertain=True,
                construct=True,
            )
        marker = text[index + 1]
        if marker in "bBAZzG":
            return _regex_prefix_result(frozenset({()}), index + 2, uncertain=True, construct=True)
        if marker == "d":
            return _regex_prefix_result(
                frozenset((digit,) for digit in string.digits), index + 2, construct=True
            )
        if marker == "s":
            return _regex_prefix_result(
                frozenset((character,) for character in " \\t\\r\\n\\f\\v"), index + 2, construct=True
            )
        if marker == "w":
            return _regex_prefix_result(
                frozenset((character.casefold(),) for character in string.ascii_letters + string.digits + "_"),
                index + 2,
                construct=True,
            )
        if marker in "DSW":
            return _regex_prefix_result(
                _regex_unknown_prefix_outputs(variable_length=False),
                index + 2,
                uncertain=True,
                construct=True,
            )
        decoded, consumed, uncertain = _decode_regex_escape(text, index)
        if not uncertain and len(decoded) == 1:
            return _regex_prefix_result(
                frozenset({(decoded.casefold(),)}), consumed, construct=True
            )
        return _regex_prefix_result(
            _regex_unknown_prefix_outputs(variable_length=True),
            max(index + 1, consumed),
            uncertain=True,
            construct=True,
        )
    if character == ".":
        return _regex_prefix_result(
            _regex_unknown_prefix_outputs(variable_length=False), index + 1, uncertain=True, construct=True
        )
    if character in "^$":
        return _regex_prefix_result(frozenset({()}), index + 1, uncertain=True, construct=True)
    if character in "|)":
        return _regex_prefix_result(frozenset({()}), index, uncertain=False)
    if character in "*+?{}":
        return _regex_prefix_result(
            _regex_unknown_prefix_outputs(variable_length=True), index + 1, uncertain=True, construct=True
        )
    return _regex_prefix_result(frozenset({(character.casefold(),)}), index + 1)


def _regex_quantifier(text: str, index: int) -> tuple[tuple[int, ...] | None, int, bool]:
    if index >= len(text):
        return None, index, False
    marker = text[index]
    if marker == "?":
        end = index + 1
        if end < len(text) and text[end] == "?":
            end += 1
        return (0, 1), end, True
    if marker == "*":
        end = index + 1
        if end < len(text) and text[end] == "?":
            end += 1
        return tuple(range(MAX_REGEX_SCHEME_PREFIX_OUTPUT_LENGTH + 1)), end, True
    if marker == "+":
        end = index + 1
        if end < len(text) and text[end] == "?":
            end += 1
        return tuple(range(1, MAX_REGEX_SCHEME_PREFIX_OUTPUT_LENGTH + 1)), end, True
    if marker != "{":
        return None, index, False
    closing = text.find("}", index + 1, min(len(text), index + MAX_REGEX_SCHEME_SOURCE_LENGTH))
    if closing < 0:
        return None, index + 1, True
    body = text[index + 1:closing]
    match = re.fullmatch(r"([0-9]{1,3})(?:,([0-9]{0,3}))?", body)
    if match is None:
        return None, closing + 1, True
    minimum = int(match.group(1))
    maximum_text = match.group(2)
    maximum = minimum if maximum_text is None else (
        MAX_REGEX_SCHEME_PREFIX_OUTPUT_LENGTH if maximum_text == "" else int(maximum_text)
    )
    maximum = min(maximum, MAX_REGEX_SCHEME_PREFIX_OUTPUT_LENGTH)
    end = closing + 1
    if end < len(text) and text[end] == "?":
        end += 1
    return tuple(range(minimum, maximum + 1)), end, True


def _regex_apply_quantifier(text: str, result: _RegexSchemePrefixResult) -> _RegexSchemePrefixResult:
    counts, end, is_quantifier = _regex_quantifier(text, result.end)
    if not is_quantifier:
        return result
    if counts is None:
        return _regex_prefix_result(
            _regex_unknown_prefix_outputs(variable_length=True),
            end,
            uncertain=True,
            construct=True,
        )
    outputs: set[tuple[str | None, ...]] = set()
    overflow = False
    for count in counts:
        for pattern in result.outputs:
            repeated = pattern * count
            if len(repeated) <= MAX_REGEX_SCHEME_PREFIX_OUTPUT_LENGTH:
                outputs.add(repeated)
            else:
                # Keep a sentinel-length prefix so exact targets remain
                # distinguishable from branches that are already too long.
                outputs.add(repeated[: MAX_REGEX_SCHEME_PREFIX_OUTPUT_LENGTH + 1])
                overflow = True
    return _regex_prefix_result(
        frozenset(outputs),
        end,
        uncertain=result.uncertain or overflow,
        construct=True,
    )


def _regex_parse_sequence(text: str, index: int, depth: int) -> _RegexSchemePrefixResult:
    values = frozenset({()})
    cursor = index
    uncertain = False
    construct = False
    limit = min(len(text), index + MAX_REGEX_SCHEME_SOURCE_LENGTH)
    while cursor < limit and text[cursor] not in "|)":
        atom = _regex_apply_quantifier(text, _regex_parse_atom(text, cursor, depth))
        if atom.end <= cursor:
            return _regex_prefix_result(values, cursor + 1, uncertain=True, construct=True)
        values = _regex_prefix_concat(values, atom.outputs)
        uncertain = uncertain or atom.uncertain
        construct = construct or atom.construct
        cursor = min(atom.end, limit)
    return _regex_prefix_result(values, cursor, uncertain=uncertain, construct=construct)


def _regex_parse_alternation(text: str, index: int, depth: int) -> _RegexSchemePrefixResult:
    values: frozenset[tuple[str | None, ...]] = frozenset()
    cursor = index
    uncertain = False
    construct = True
    limit = min(len(text), index + MAX_REGEX_SCHEME_SOURCE_LENGTH)
    while cursor < limit:
        branch = _regex_parse_sequence(text, cursor, depth)
        values = _regex_prefix_union(values, branch.outputs)
        uncertain = uncertain or branch.uncertain
        cursor = branch.end
        if cursor >= limit:
            uncertain = True
            break
        if text[cursor] == "|":
            cursor += 1
            continue
        if text[cursor] == ")":
            return _regex_prefix_result(values, cursor + 1, uncertain=uncertain, construct=construct)
        uncertain = True
        break
    if not values:
        if not uncertain:
            # A contradictory assertion can consume a whole branch. Preserve
            # that empty language instead of turning it into unknown output,
            # which would make the following literal URL look reachable.
            return _regex_prefix_result(
                frozenset(),
                max(index + 1, cursor),
                uncertain=False,
                construct=construct,
            )
        values = _regex_unknown_prefix_outputs(variable_length=True)
    return _regex_prefix_result(values, max(index + 1, cursor), uncertain=uncertain, construct=construct)


def _regex_dynamic_scheme_probe_at(text: str, index: int) -> _RegexSchemeProbe | None:
    if index >= len(text) or text[index] not in "hHwW[(\\":
        return None
    values: frozenset[tuple[str | None, ...]] = frozenset({()})
    cursor = index
    uncertain = False
    construct = False
    uncertain_class = False
    limit = min(len(text), index + MAX_REGEX_SCHEME_SOURCE_LENGTH)
    while cursor < limit:
        if text[cursor].isspace() or text[cursor] in "\"'<>":
            break
        if text[cursor] in "|)":
            break
        atom = _regex_apply_quantifier(text, _regex_parse_atom(text, cursor, 0))
        if atom.end <= cursor:
            break
        if text[cursor] == "[" and atom.uncertain:
            uncertain_class = True
        values = _regex_prefix_concat(values, atom.outputs)
        uncertain = uncertain or atom.uncertain
        construct = construct or atom.construct
        cursor = min(atom.end, limit)
        for target in _REGEX_SCHEME_TARGETS:
            if any(_regex_prefix_matches_target(pattern, target) for pattern in values):
                delimiter_end = _regex_scheme_delimiter_end(text, cursor)
                if delimiter_end is not None:
                    return _RegexSchemeProbe(delimiter_end, cursor)
        if not uncertain and not any(_regex_prefix_can_start_target(pattern) for pattern in values):
            break
    possible_target = any(_regex_prefix_can_start_target(pattern) for pattern in values)
    if construct and text[index].casefold() in {"h", "w"} and (
        uncertain_class or (uncertain and possible_target)
    ):
        # An unknown class, escape, assertion, or quantifier that can still
        # form a target scheme cannot prove that the pattern is harmless. An
        # uncertain class is rejected even when the surrounding spelling is
        # shorter than a complete scheme because malformed ranges must fail
        # closed rather than becoming an apparent non-match.
        raise ValidationError()
    if construct:
        skip_end = max(index + 1, cursor)
        proven_nonmatch = not uncertain and not any(
            _regex_prefix_can_start_target(pattern) for pattern in values
        )
        if proven_nonmatch:
            # A failed assertion or an impossible branch may be followed by a
            # literal-looking ``https`` suffix. Consume that suffix with the
            # failed construct so the scanner cannot rediscover it as a URL.
            suffix_end = _regex_scheme_match_at(text, skip_end)
            if suffix_end is not None:
                skip_end = suffix_end
        return _RegexSchemeProbe(None, skip_end)
    return None


def _regex_dynamic_scheme_match_at(text: str, index: int) -> int | None:
    """Return a bounded dynamic scheme end without scanning inside unknown syntax."""

    probe = _regex_dynamic_scheme_probe_at(text, index)
    return None if probe is None else probe.scheme_end


def _regex_dynamic_authority_is_live(text: str, scheme_end: int) -> bool:
    """Reject dynamic schemes when their recovered authority is live or unsafe.

    Detector expressions such as ``https?://[^\\s]+`` are source syntax, not a
    concrete URL that this scanner can classify. Keep those bounded patterns
    compatible, but do not let a dynamic scheme hide a concrete live host,
    malformed port, authority backslash, or userinfo password. The same
    distinction lets synthetic host patterns continue to exercise their local
    validators without weakening the authority policy.
    """

    authority_marker = _regex_component_delimiter(text, scheme_end)
    authority_end = authority_marker[0] if authority_marker is not None else len(text)
    authority = text[scheme_end:authority_end]
    # A detector prefix may intentionally stop at ``://`` without carrying an
    # authority. A regex branch separator or closing group immediately after
    # the delimiter is the same empty-authority boundary; the following source
    # belongs to another branch or enclosing construct, not this URL.
    if not authority or authority[0] in "|)":
        return False
    decoded_authority, uncertain = _decode_regex_host(authority)
    policy_authority, class_flags, policy_uncertain = _regex_decoded_component_tokens(authority)
    if "\\" in decoded_authority or any(
        character == "\\" and not class_flags[index]
        for index, character in enumerate(policy_authority)
    ):
        return True
    if "@" in decoded_authority:
        userinfo, host_port = decoded_authority.rsplit("@", 1)
        if ":" in userinfo:
            _username, password = userinfo.split(":", 1)
            if password and not _is_explicit_synthetic_marker(password):
                return True
    else:
        host_port = decoded_authority
    try:
        port = _regex_authority_port_text(policy_authority)
    except ValidationError:
        return True
    if port is not None:
        decoded_port, port_uncertain = _decode_regex_host(port)
        if port_uncertain:
            return True
        try:
            _validate_port_text(decoded_port)
        except ValidationError:
            return True
        raw_host_port = policy_authority.rsplit("@", 1)[-1]
        if raw_host_port.startswith("["):
            closing = raw_host_port.find("]")
            raw_host = raw_host_port[1:closing] if closing >= 0 else raw_host_port
        else:
            raw_host = raw_host_port[:-(len(port) + 1)]
        host_text, _host_uncertain = _decode_regex_host(raw_host)
    else:
        host_text = host_port
    if policy_uncertain and not uncertain:
        return True
    if "%" in host_text:
        return True
    concrete = tuple(dict.fromkeys(REGEX_HOST_LITERAL_PATTERN.findall(host_text)))
    if not concrete:
        return False
    if not uncertain:
        # A dynamic protocol over a literal authority is still ambiguous even
        # when that authority is synthetic; it must not become a safe URL by
        # choosing one branch of the scheme.
        return True
    # A recovered literal suffix can still prove that a dynamic host is
    # synthetic. Any other concrete label remains live/ambiguous.
    for host in concrete:
        try:
            _require_allowed_url_host(host, allow_synthetic_markers=False)
        except ValidationError:
            return True
    try:
        _validate_regex_url_candidate(
            "https://" + text[scheme_end:],
            allow_synthetic_markers=False,
            allowed_assignment_values=frozenset(),
            allowed_synthetic_full_values=frozenset(),
            source_value=text,
        )
    except ValidationError:
        return True
    return False


def _regex_nested_scheme_matches(
    text: str,
    start: int,
    end: int,
    *,
    depth: int = 0,
    budget: list[int] | None = None,
    scan_schemes: bool = True,
) -> tuple[tuple[int, int], ...]:
    """Find URL schemes nested in one bounded regex construct.

    Prefix inference is useful for scheme construction, but it cannot retain a
    complete URL body. Walk recognized groups recursively before the caller
    skips them, while treating negative assertions as non-consuming constraints
    and rejecting malformed or over-budget structure rather than guessing.
    """

    if budget is None:
        budget = [MAX_REGEX_NESTED_SCAN_NODES]
    if depth > MAX_REGEX_NESTED_SCAN_DEPTH or end < start:
        raise ValidationError()
    if end - start > MAX_REGEX_GROUP_SOURCE_LENGTH:
        if depth == 0 and text[start:start + 1] == "(":
            body_start, _assertion_mode, _recognized = _regex_group_body_start(text, start)
            alternation_start = start + 1 if body_start is None else body_start
            alternation_end = end - 1 if text[end - 1:end] == ")" else end
        else:
            alternation_start = start
            alternation_end = end
        if not (
            _regex_has_top_level_alternation(text, alternation_start, alternation_end)
            or _regex_has_regex_construct(text, alternation_start, alternation_end)
        ):
            raise ValidationError()
    matches: list[tuple[int, int]] = []
    index = start
    while index < end:
        budget[0] -= 1
        if budget[0] < 0:
            raise ValidationError()
        character = text[index]
        if character == "(":
            group_end, complete = _regex_bounded_group_span(
                text,
                index,
                max_length=MAX_STATIC_RENDER_BYTES,
            )
            if not complete or group_end > end:
                raise ValidationError()
            body_start, assertion_mode, _recognized = _regex_group_body_start(text, index)
            if body_start is None:
                body_start = index + 1
            body_end = group_end - 1
            scan_body = assertion_mode != -1
            lookbehind = text.startswith("(?<=", index) or text.startswith("(?<!", index)
            if scan_body and assertion_mode == 1 and body_start < body_end:
                result = _regex_parse_alternation(text, body_start, depth + 1)
                if _regex_assertion_is_contradictory(
                    text,
                    index if lookbehind else result.end,
                    result.outputs,
                    assertion_mode,
                    depth + 1,
                    lookbehind=lookbehind,
                ):
                    scan_body = False
            if scan_body and body_start < body_end:
                matches.extend(
                    _regex_nested_scheme_matches(
                        text,
                        body_start,
                        body_end,
                        depth=depth + 1,
                        budget=budget,
                        scan_schemes=scan_schemes,
                    )
                )
            index = group_end
            continue
        if character == "[":
            span = _regex_class_span(text, index)
            if span is None or span[0] > end:
                raise ValidationError()
            index = span[0]
            continue
        if character == "\\":
            _decoded, consumed, _uncertain = _decode_regex_escape(text, index)
            if consumed > end:
                raise ValidationError()
            index = max(index + 1, consumed)
            continue
        if not scan_schemes:
            index += 1
            continue
        match_end = _regex_scheme_match_at(text, index)
        if match_end is not None and match_end <= end:
            matches.append((index, match_end))
            index = match_end
            continue
        probe = _regex_dynamic_scheme_probe_at(text, index)
        if probe is not None:
            if probe.scheme_end is not None and probe.scheme_end <= end:
                if _regex_dynamic_authority_is_live(text, probe.scheme_end):
                    raise ValidationError()
                index = probe.scheme_end
            else:
                index = min(end, max(index + 1, probe.skip_end))
            continue
        index += 1
    return tuple(matches)


def _validate_regex_structure(text: str) -> None:
    """Validate bounded regex structure without interpreting URL schemes."""

    index = 0
    in_class = False
    budget = [MAX_REGEX_NESTED_SCAN_NODES]
    while index < len(text):
        character = text[index]
        if not in_class and character == "(":
            group_end, complete = _regex_bounded_group_span(
                text,
                index,
                max_length=MAX_STATIC_RENDER_BYTES,
            )
            if not complete:
                raise ValidationError()
            _regex_nested_scheme_matches(
                text,
                index,
                group_end,
                budget=budget,
                scan_schemes=False,
            )
            index = group_end
            continue
        if in_class:
            if character == "\\":
                _decoded, consumed, _uncertain = _decode_regex_escape(text, index)
                index = max(index + 1, consumed)
            elif character == "]":
                in_class = False
                index += 1
            else:
                index += 1
            continue
        if character == "[":
            in_class = True
            index += 1
        elif character == "\\":
            _decoded, consumed, _uncertain = _decode_regex_escape(text, index)
            index = max(index + 1, consumed)
        else:
            index += 1
    if in_class:
        raise ValidationError()


def _regex_scheme_matches(text: str) -> Iterator[tuple[int, int]]:
    """Yield deterministic scheme spans and reject dynamic scheme syntax."""

    index = 0
    in_class = False
    nested_budget = [MAX_REGEX_NESTED_SCAN_NODES]
    while index < len(text):
        character = text[index]
        if not in_class:
            if character == "(":
                group_end, complete = _regex_bounded_group_span(
                    text,
                    index,
                    max_length=MAX_STATIC_RENDER_BYTES,
                )
                if not complete:
                    raise ValidationError()
                for nested_start, nested_end in _regex_nested_scheme_matches(
                    text,
                    index,
                    group_end,
                    budget=nested_budget,
                ):
                    yield nested_start, nested_end
            # Singleton classes and deterministic escapes remain ordinary URL
            # matches. Dynamic parsing follows only after this proof attempt so
            # a safe ``[h]ttps`` cannot be reclassified as an ambiguous scheme.
            match_end = _regex_scheme_match_at(text, index)
            if match_end is not None:
                yield index, match_end
                index = match_end
                continue
            probe = _regex_dynamic_scheme_probe_at(text, index)
            if probe is not None:
                if probe.scheme_end is not None:
                    if _regex_dynamic_authority_is_live(text, probe.scheme_end):
                        raise ValidationError()
                    index = probe.scheme_end
                else:
                    # Consume the whole bounded group/class/quantifier probe.
                    # Never advance one byte and rediscover a URL hidden inside
                    # a regex construct that the prefix parser could not prove.
                    index = max(index + 1, probe.skip_end)
                continue
        if in_class:
            if character == "\\":
                _decoded, consumed, _uncertain = _decode_regex_escape(text, index)
                index = max(index + 1, consumed)
            elif character == "]":
                in_class = False
                index += 1
            else:
                index += 1
            continue
        if character == "[":
            in_class = True
            index += 1
        elif character == "\\":
            _decoded, consumed, _uncertain = _decode_regex_escape(text, index)
            index = max(index + 1, consumed)
        else:
            index += 1


def _regex_decoded_component_tokens(component: str) -> tuple[str, tuple[bool, ...], bool]:
    """Decode deterministic regex escapes while retaining class boundaries."""

    decoded: list[str] = []
    in_class: list[bool] = []
    uncertain = False
    class_depth = False
    index = 0
    while index < len(component):
        character = component[index]
        if character == "\\":
            value, consumed, was_uncertain = _decode_regex_escape(component, index)
            require(consumed > index, "regex URL escape is incomplete")
            if was_uncertain:
                source = component[index:consumed]
                decoded.extend(source)
                in_class.extend([class_depth] * len(source))
                uncertain = True
            else:
                decoded.append(value)
                in_class.append(class_depth)
            index = consumed
            continue
        decoded.append(character)
        in_class.append(class_depth)
        if character == "[":
            class_depth = True
        elif character == "]" and class_depth:
            class_depth = False
        index += 1
    return "".join(decoded), tuple(in_class), uncertain


def _validate_decoded_regex_percent_escapes(component: str) -> None:
    """Validate percent bytes after deterministic regex escapes are decoded."""

    decoded, class_flags, _uncertain = _regex_decoded_component_tokens(component)
    index = 0
    while index < len(decoded):
        if class_flags[index] or decoded[index] != "%":
            index += 1
            continue
        require(index + 2 < len(decoded), "URL escape is incomplete")
        require(
            not class_flags[index + 1]
            and not class_flags[index + 2]
            and re.fullmatch(r"[0-9A-Fa-f]{2}", decoded[index + 1:index + 3]) is not None,
            "URL escape is malformed",
        )
        index += 3


def _regex_decoded_component(component: str, *, require_concrete: bool = False) -> str:
    decoded, _class_flags, uncertain = _regex_decoded_component_tokens(component)
    if require_concrete:
        require(not uncertain, "regex URL escape is ambiguous")
    return decoded


def _regex_host_literals(raw_url: str) -> tuple[str, ...]:
    scheme_end = _regex_scheme_match_at(raw_url, 0)
    if scheme_end is None:
        return ()
    remainder = raw_url[scheme_end:]
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


def _assignment_byte_length(value: str) -> int:
    """Return a bounded UTF-8 size without retaining an oversized value."""

    total = 0
    for character in value:
        try:
            total += len(character.encode("utf-8"))
        except UnicodeError as exc:
            raise ValidationError() from exc
        require(total <= MAX_ASSIGNMENT_VALUE_BYTES, "assignment value is too large")
    return total


def _scan_assignment_candidates(
    text: str,
    *,
    allow_synthetic_markers: bool,
    allowed_assignment_values: frozenset[str],
    exact_full_allowance: bool,
    allowed_empty_assignment_lines: frozenset[str] = frozenset(),
    allowed_empty_assignment_values: frozenset[str] = frozenset(),
) -> None:
    """Parse credential assignments conservatively after the regex fast path.

    Quoted source syntax is deliberately not decoded. Any backslash, embedded
    line break, missing quote, or non-delimiter suffix makes the assignment
    ambiguous and fails closed. Bare values retain the historical token grammar
    so prose such as ``Authorization: Basic`` and typed parameters do not become
    false credential assignments.
    """

    bare_characters = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~+/=%-")
    trailing_delimiters = frozenset(",;)]}#")

    def reviewed_empty_line(match_start: int) -> bool:
        line_start = text.rfind("\n", 0, match_start) + 1
        line_end = text.find("\n", match_start)
        if line_end < 0:
            line_end = len(text)
        return text[line_start:line_end] in allowed_empty_assignment_lines

    exact_empty_value = text in allowed_empty_assignment_values

    for match in ASSIGNMENT_KEY_PATTERN.finditer(text):
        key = match.group("key")
        if not _is_credential_key_alias(key):
            continue
        separator = match.group("separator")
        index = match.end()
        if index >= len(text):
            # A trailing bare ``=`` is a complete empty credential candidate and
            # must fail closed. A trailing ``:`` remains compatible with typed
            # annotations and prose labels that provide no credential value.
            if separator == "=" and not reviewed_empty_line(match.start()) and not exact_empty_value:
                _validate_assignment_candidate(
                    key,
                    "",
                    allow_synthetic_markers=allow_synthetic_markers,
                    allowed_assignment_values=allowed_assignment_values,
                    exact_full_allowance=exact_full_allowance,
                )
            continue
        if text[index] in "'\"":
            quote = text[index]
            content_start = index + 1
            content_index = content_start
            byte_count = 0
            while content_index < len(text):
                character = text[content_index]
                if character in "\r\n":
                    raise ValidationError()
                if character == "\\":
                    # Escaped quotes and escaped bytes are source syntax, not a
                    # safely recoverable credential value for this scanner.
                    raise ValidationError()
                if character == quote:
                    candidate = text[content_start:content_index]
                    trailing = content_index + 1
                    while trailing < len(text) and text[trailing].isspace():
                        trailing += 1
                    if trailing < len(text) and text[trailing] not in trailing_delimiters:
                        # Do not let an allowed first literal hide a second
                        # concatenated or suffixed credential value.
                        raise ValidationError()
                    _assignment_byte_length(candidate)
                    _validate_assignment_candidate(
                        key,
                        candidate,
                        allow_synthetic_markers=allow_synthetic_markers,
                        allowed_assignment_values=allowed_assignment_values,
                        exact_full_allowance=exact_full_allowance,
                    )
                    break
                try:
                    byte_count += len(character.encode("utf-8"))
                except UnicodeError as exc:
                    raise ValidationError() from exc
                require(byte_count <= MAX_ASSIGNMENT_VALUE_BYTES, "assignment value is too large")
                content_index += 1
            else:
                raise ValidationError()
            continue

        value_start = index
        value_index = value_start
        byte_count = 0
        while value_index < len(text):
            character = text[value_index]
            if character.isspace() or character in trailing_delimiters:
                break
            if character in "'\"":
                # A closing quote can delimit a bare assignment embedded in a
                # JSON/string example. Treat it as a delimiter only when the
                # following byte also closes the surrounding value; a quote
                # followed by payload remains an ambiguous concatenation.
                if value_index > value_start:
                    trailing = value_index + 1
                    if trailing < len(text) and not (
                        text[trailing].isspace() or text[trailing] in trailing_delimiters
                    ):
                        raise ValidationError()
                    break
                break
            if character == "\\":
                # An escape after a bare prefix is source syntax we cannot
                # decode safely. Reject it only once a credential-shaped prefix
                # is present; short prose/header schemes remain compatible.
                if value_index > value_start:
                    raise ValidationError()
                break
            if character not in bare_characters:
                break
            try:
                byte_count += len(character.encode("utf-8"))
            except UnicodeError as exc:
                raise ValidationError() from exc
            require(byte_count <= MAX_ASSIGNMENT_VALUE_BYTES, "assignment value is too large")
            value_index += 1
        candidate = text[value_start:value_index]
        if not candidate:
            # A bare separator is commonly an intermediate result of a static
            # string construction (``"password" + "="``). It has no value to
            # classify; quoted empties below remain fail-closed because they
            # are complete, credential-shaped syntax.
            if separator == "=" and not reviewed_empty_line(match.start()) and not exact_empty_value:
                _validate_assignment_candidate(
                    key,
                    candidate,
                    allow_synthetic_markers=allow_synthetic_markers,
                    allowed_assignment_values=allowed_assignment_values,
                    exact_full_allowance=exact_full_allowance,
                )
            continue
        # Existing prose and typed annotations intentionally use short words
        # after a colon (``token: str`` or ``Authorization: Basic``). Only a
        # detector-length bare token, a reviewed marker, or an exact allowance
        # enters the shared assignment policy.
        if len(candidate) < 8 and not (
            candidate in allowed_assignment_values
            or _is_placeholder(
                candidate,
                allow_synthetic_markers=allow_synthetic_markers,
                allow_structural_placeholders=False,
            )
        ):
            continue
        _validate_assignment_candidate(
            key,
            candidate,
            allow_synthetic_markers=allow_synthetic_markers,
            allowed_assignment_values=allowed_assignment_values,
            exact_full_allowance=exact_full_allowance,
        )


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
    # Empty bare ``=`` candidates are never retained values. Do this before
    # consulting path-scoped allowances so an exact full-value exception cannot
    # turn ``api_key=`` or ``token=`` into an accepted credential shape.
    require(candidate != "", "empty credential assignment is not allowed")
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


def _url_components(raw_url: str) -> tuple[str, str, str, str]:
    """Split one bounded URL without normalizing away suspicious delimiters."""

    require(len(raw_url) <= MAX_URL_LENGTH, "URL is too large")
    authority = _url_authority(raw_url)
    separator = raw_url.find("://")
    authority_end = separator + 3 + len(authority)
    remainder = raw_url[authority_end:]
    fragment_index = remainder.find("#")
    if fragment_index >= 0:
        fragment = remainder[fragment_index + 1:]
        remainder = remainder[:fragment_index]
    else:
        fragment = ""
    query_index = remainder.find("?")
    if query_index >= 0:
        query = remainder[query_index + 1:]
        path = remainder[:query_index]
    else:
        query = ""
        path = remainder
    for component in (authority, path, query, fragment):
        require(len(component) <= MAX_URL_COMPONENT_LENGTH, "URL component is too large")
    return authority, path, query, fragment


def _regex_component_delimiter(
    value: str,
    start: int,
    *,
    markers: frozenset[str] = frozenset("/?#"),
) -> tuple[int, str, int] | None:
    """Find one URL delimiter without mistaking regex syntax for URL syntax.

    Regex URL authorities commonly contain non-capturing groups such as
    ``(?::[0-9]{1,5})?`` and character classes containing URL punctuation.
    The raw URL splitter must not see the group's ``?`` or ``:`` as a query or
    port delimiter. Escapes and character classes are skipped; a ``?`` after a
    completed regex atom is treated as its optional quantifier rather than a
    query marker. The result is deliberately conservative: unknown authority
    syntax is still passed to the regex-host policy instead of being normalized.
    """

    escaped = False
    in_class = False
    parenthesis_depth = 0
    index = start
    while index < len(value):
        character = value[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if character == "\\":
            decoded, consumed, _uncertain = _decode_regex_escape(value, index)
            if decoded in markers and not _uncertain:
                return index, decoded, consumed
            index = max(index + 1, consumed)
            continue
        if in_class:
            if character == "]":
                in_class = False
            index += 1
            continue
        if character == "[":
            in_class = True
            index += 1
            continue
        if character == "(":
            parenthesis_depth += 1
            index += 1
            continue
        if character == ")":
            if parenthesis_depth:
                parenthesis_depth -= 1
            index += 1
            continue
        if character == "/" and "/" in markers:
            # A slash inside a regex path group (``(?:/path)?``) still marks
            # the URL path. Slashes in classes and escapes were skipped above.
            return index, character, index + 1
        if character == "#" and "#" in markers and parenthesis_depth == 0:
            return index, character, index + 1
        if character == "?" and "?" in markers and parenthesis_depth == 0:
            previous = value[index - 1] if index > start else ""
            if not previous or previous not in ")]}>*+?":
                return index, character, index + 1
        index += 1
    return None


def _regex_url_components(raw_url: str) -> tuple[str, str, str, str]:
    """Split a bounded regex URL while preserving regex punctuation."""

    require(len(raw_url) <= MAX_URL_LENGTH, "URL is too large")
    scheme_end = _regex_scheme_match_at(raw_url, 0)
    require(scheme_end is not None, "URL scheme is missing")
    start = scheme_end
    authority_marker = _regex_component_delimiter(raw_url, start)
    authority_end = authority_marker[0] if authority_marker is not None else len(raw_url)
    authority = raw_url[start:authority_end]
    require(authority, "URL authority is missing")

    remainder_start = authority_end
    query_marker = _regex_component_delimiter(raw_url, remainder_start, markers=frozenset("?#"))
    if query_marker is None:
        path = raw_url[remainder_start:]
        query = ""
        fragment = ""
    elif query_marker[1] == "#":
        path = raw_url[remainder_start:query_marker[0]]
        query = ""
        fragment = raw_url[query_marker[2]:]
    elif query_marker[1] == "?":
        path = raw_url[remainder_start:query_marker[0]]
        fragment_marker = _regex_component_delimiter(
            raw_url,
            query_marker[2],
            markers=frozenset("#"),
        )
        if fragment_marker is None or fragment_marker[1] != "#":
            query = raw_url[query_marker[2]:]
            fragment = ""
        else:
            query = raw_url[query_marker[2]:fragment_marker[0]]
            fragment = raw_url[fragment_marker[2]:]
    else:
        path = raw_url[remainder_start:query_marker[0]]
        query = ""
        fragment = raw_url[query_marker[0] + 1:]
    for component in (authority, path, query, fragment):
        require(len(component) <= MAX_URL_COMPONENT_LENGTH, "URL component is too large")
    return authority, path, query, fragment


def _validate_percent_escapes(component: str) -> None:
    """Reject malformed percent escapes even in non-key/value URL fields."""

    index = 0
    while index < len(component):
        if component[index] == "%":
            require(index + 2 < len(component), "URL escape is incomplete")
            require(
                re.fullmatch(r"[0-9A-Fa-f]{2}", component[index + 1:index + 3]) is not None,
                "URL escape is malformed",
            )
            index += 3
            continue
        index += 1


def _validate_regex_percent_escapes(component: str) -> None:
    """Validate URL escapes outside regex classes without rejecting literals."""

    escaped = False
    in_class = False
    index = 0
    while index < len(component):
        character = component[index]
        if escaped:
            # A regex escape for ``%`` still produces a malformed URL byte;
            # rejecting it keeps the regex and raw URL policies fail-closed.
            require(character != "%", "URL escape is malformed")
            escaped = False
            index += 1
            continue
        if character == "\\":
            escaped = True
            index += 1
            continue
        if in_class:
            if character == "]":
                in_class = False
            index += 1
            continue
        if character == "[":
            in_class = True
            index += 1
            continue
        if character == "%":
            require(index + 2 < len(component), "URL escape is incomplete")
            require(
                re.fullmatch(r"[0-9A-Fa-f]{2}", component[index + 1:index + 3]) is not None,
                "URL escape is malformed",
            )
            index += 3
            continue
        index += 1
    require(not escaped, "URL escape is incomplete")


def _validate_port_text(port: str) -> None:
    """Apply one explicit-port policy to raw and regex-derived authorities."""

    require(port and len(port) <= 5 and port.isascii() and port.isdecimal(), "URL port is malformed")
    number = int(port)
    require(1 <= number <= 65535, "URL port is out of range")


def _authority_port_text(authority: str) -> str | None:
    host_port = authority.rsplit("@", 1)[-1]
    if host_port.startswith("["):
        closing = host_port.find("]")
        require(closing >= 0, "URL IPv6 authority is malformed")
        suffix = host_port[closing + 1:]
        if not suffix:
            return None
        require(suffix.startswith(":"), "URL authority is malformed")
        return suffix[1:]
    if ":" not in host_port:
        return None
    require(host_port.count(":") == 1, "URL authority is malformed")
    return host_port.rsplit(":", 1)[1]


def _regex_authority_port_text(authority: str) -> str | None:
    """Find a literal regex-authority port outside groups and classes."""

    host_port = authority.rsplit("@", 1)[-1]
    if host_port.startswith("["):
        closing = host_port.find("]")
        require(closing >= 0, "regex URL IPv6 authority is malformed")
        bracket_host = host_port[1:closing]
        # An unescaped ``[... ]`` is usually a regex character class. Treat
        # only a plain hexadecimal/colon body as bracketed IPv6; otherwise
        # continue with the regex-aware top-level colon scan below.
        if ":" in bracket_host and re.fullmatch(r"[0-9A-Fa-f:]+", bracket_host):
            suffix = host_port[closing + 1:]
            if not suffix:
                return None
            if suffix.startswith(":"):
                return suffix[1:]
            # An optional regex port group is not one explicit port value. It
            # remains subject to the conservative host policy, but must not be
            # mistaken for malformed literal authority punctuation.
            if suffix.startswith("("):
                return None
            raise ValidationError()

    colon_positions: list[int] = []
    escaped = False
    in_class = False
    parenthesis_depth = 0
    for index, character in enumerate(host_port):
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if in_class:
            if character == "]":
                in_class = False
            continue
        if character == "[":
            in_class = True
            continue
        if character == "(":
            parenthesis_depth += 1
            continue
        if character == ")":
            if parenthesis_depth:
                parenthesis_depth -= 1
            continue
        if character == ":" and parenthesis_depth == 0:
            colon_positions.append(index)
    if not colon_positions:
        return None
    require(len(colon_positions) == 1, "URL authority is malformed")
    return host_port[colon_positions[0] + 1:]


def _validate_url_path_components(path: str, fragment: str) -> None:
    # Decoding is used only as a bounded validity/size check. The scanner does
    # not route paths or fragments through assignment semantics.
    _decode_url_component(path, plus_as_space=False)
    _decode_url_component(fragment, plus_as_space=False)


def _validate_regex_url_path_components(path: str, fragment: str) -> None:
    # Validate both source percent escapes and escapes that decode to percent.
    # Class contents remain regex syntax, but a deterministic ``\\x25`` outside
    # a class must still satisfy ordinary URL percent policy.
    for component in (path, fragment):
        require(len(component) <= MAX_URL_COMPONENT_LENGTH, "URL component is too large")
        _validate_regex_percent_escapes(component)
        _validate_decoded_regex_percent_escapes(component)


def _validate_url_query(
    query: str,
    *,
    allow_synthetic_markers: bool,
    allowed_assignment_values: frozenset[str],
    allowed_synthetic_full_values: frozenset[str],
    source_value: str,
    regex_pattern: bool = False,
) -> None:
    require(len(query) <= MAX_URL_COMPONENT_LENGTH, "URL query is too large")
    if regex_pattern:
        _validate_regex_percent_escapes(query)
    else:
        _validate_percent_escapes(query)
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


def _validate_raw_url_candidate(
    raw_url: str,
    *,
    allow_synthetic_markers: bool,
    allowed_assignment_values: frozenset[str],
    allowed_synthetic_full_values: frozenset[str],
    source_value: str,
) -> None:
    authority, path, query, fragment = _url_components(raw_url)
    # Backslash is a special-scheme authority separator under WHATWG URL
    # parsing. Reject it before Python's urlsplit can reinterpret an evil host
    # as an allowlisted path/userinfo combination.
    require("\\" not in authority, "ambiguous URL authority is not allowed")
    _validate_url_path_components(path, fragment)
    port = _authority_port_text(authority)
    if port is not None:
        _validate_port_text(port)
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
        # Accessing .port is intentional: urllib defers malformed and
        # out-of-range explicit-port errors until this property is read.
        _ = parsed.port
    except ValueError as exc:
        raise ValidationError() from exc
    if host:
        # Percent-encoded host delimiters are ambiguous authority syntax. Path,
        # query, and userinfo are decoded explicitly; host escapes are rejected.
        require("%" not in host, "URL host escape is not allowed")
        _require_allowed_url_host(host, allow_synthetic_markers=allow_synthetic_markers)
    _validate_url_query(
        query,
        allow_synthetic_markers=allow_synthetic_markers,
        allowed_assignment_values=allowed_assignment_values,
        allowed_synthetic_full_values=allowed_synthetic_full_values,
        source_value=source_value,
    )


def _validate_regex_authority_escapes(authority: str) -> None:
    """Allow only regex escapes that recover a concrete authority character."""

    index = 0
    while index < len(authority):
        if authority[index] != "\\":
            index += 1
            continue
        _value, consumed, uncertain = _decode_regex_escape(authority, index)
        require(not uncertain, "regex URL authority escape is ambiguous")
        require(consumed > index, "regex URL authority escape is incomplete")
        index = consumed


def _regex_decoded_port(authority: str) -> str | None:
    port = _regex_authority_port_text(authority)
    if port is None:
        return None
    decoded, uncertain = _decode_regex_host(port)
    require(not uncertain, "regex URL port is ambiguous")
    _validate_port_text(decoded)
    return decoded


def _validate_regex_url_candidate(
    raw_url: str,
    *,
    allow_synthetic_markers: bool,
    allowed_assignment_values: frozenset[str],
    allowed_synthetic_full_values: frozenset[str],
    source_value: str,
) -> None:
    authority, path, query, fragment = _regex_url_components(raw_url)
    _validate_regex_authority_escapes(authority)
    decoded_authority = _regex_decoded_component(authority, require_concrete=True)
    require("\\" not in decoded_authority, "ambiguous URL authority is not allowed")
    _validate_regex_url_path_components(path, fragment)
    _regex_decoded_port(decoded_authority)
    raw_host_port = decoded_authority.rsplit("@", 1)[-1]
    bracket_host = ""
    if raw_host_port.startswith("["):
        closing = raw_host_port.find("]")
        require(closing >= 0, "regex URL IPv6 authority is malformed")
        bracket_host = raw_host_port[1:closing]
    if bracket_host and ":" in bracket_host and re.fullmatch(r"[0-9A-Fa-f:]+", bracket_host):
        host_text = bracket_host
    else:
        port = _regex_authority_port_text(decoded_authority)
        host_text = raw_host_port if port is None else raw_host_port[:-(len(port) + 1)]
    require("%" not in host_text, "regex URL host escape is not allowed")
    if "@" in decoded_authority:
        raw_userinfo = decoded_authority.rsplit("@", 1)[0]
        decoded_userinfo, uncertain = _decode_regex_host(raw_userinfo)
        require(not uncertain, "regex URL userinfo is ambiguous")
        decoded_userinfo = _decode_url_component(decoded_userinfo, plus_as_space=False)
        if ":" in decoded_userinfo:
            _username, password = decoded_userinfo.split(":", 1)
            require(
                not password or _is_explicit_synthetic_marker(password),
                "regex URL userinfo is not allowed",
            )
    decoded_host, uncertain = _decode_regex_host(host_text)
    concrete = tuple(dict.fromkeys(REGEX_HOST_LITERAL_PATTERN.findall(decoded_host)))
    if uncertain:
        suffixes = [
            candidate
            for candidate in concrete
            if candidate.casefold().endswith((".test", ".example"))
            or candidate.casefold() in ALLOWED_URL_HOSTS
        ]
        require(bool(suffixes), "regex URL host cannot be recovered safely")
    require(bool(concrete), "regex URL host is missing")
    for host in concrete:
        _require_allowed_url_host(host, allow_synthetic_markers=allow_synthetic_markers)
    _validate_url_query(
        query,
        allow_synthetic_markers=allow_synthetic_markers,
        allowed_assignment_values=allowed_assignment_values,
        allowed_synthetic_full_values=allowed_synthetic_full_values,
        source_value=source_value,
        regex_pattern=True,
    )
    decoded_query = _regex_decoded_component(query)
    if decoded_query != query:
        # Re-run ordinary query policy on the decoded representation so escaped
        # ``?``, ``&``, ``=``, and credential-key/value bytes cannot remain
        # invisible to the assignment scanner.
        _validate_url_query(
            decoded_query,
            allow_synthetic_markers=allow_synthetic_markers,
            allowed_assignment_values=allowed_assignment_values,
            allowed_synthetic_full_values=allowed_synthetic_full_values,
            source_value=source_value,
        )


def _regex_url_segment(value: str, start: int) -> str:
    """Capture one regex URL without stopping inside classes or escapes."""

    end = start
    escaped = False
    in_class = False
    while end < len(value):
        character = value[end]
        if escaped:
            escaped = False
            end += 1
            continue
        if character == "\\":
            escaped = True
            end += 1
            continue
        if in_class:
            if character == "]":
                in_class = False
            end += 1
            continue
        if character == "[":
            in_class = True
            end += 1
            continue
        if character.isspace() or character in "\"'<>":
            break
        end += 1
    return value[start:end]


def _regex_url_hint(value: str) -> bool:
    """Return whether a regex value can contain a URL delimiter or scheme."""

    lowered = value.casefold()
    if (
        "://" in value
        or "\\/" in value
        or "\\x" in lowered
        or "\\u" in lowered
        or "\\N{" in value
        or re.search(r"\\[0-7]{1,3}", value) is not None
    ):
        return True
    # Keep ordinary route words such as ``ws-ticket`` out of the structural
    # URL parser. A contiguous scheme stem plus a colon remains a useful hint
    # for delimiter character classes and escaped-colon constructions.
    return any(scheme in lowered for scheme in ("http", "https", "ws", "wss")) and ":" in value


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
        if not _regex_url_hint(value):
            _validate_regex_structure(value)
            return
        scheme_matches = tuple(_regex_scheme_matches(value))
        for match_start, _match_end in scheme_matches:
            segment = _regex_url_segment(value, match_start)
            if not segment:
                continue
            # A protocol-prefix check (``startswith("https://")``) is not a
            # URL candidate. Raw URL matching already excludes this shape;
            # keep regex scanning aligned without weakening real authorities.
            # Deterministic escaped scheme letters (for example ``\\u0068``)
            # are equivalent prefixes; uncertain escapes must not inherit this
            # exemption because they may conceal a different live scheme.
            decoded_segment = _regex_decoded_component(segment)
            if segment.casefold() in {"http://", "https://", "ws://", "wss://"} or (
                decoded_segment.casefold() in {"http://", "https://", "ws://", "wss://"}
            ):
                continue
            # Preserve exact path-scoped negative-test vocabulary before
            # splitting adjacent regex URL examples into individual candidates.
            if segment in allowed_structural_urls:
                continue
            starts = [match_start]
            for nested_start, _nested_end in _regex_scheme_matches(segment):
                if nested_start > 0:
                    starts.append(match_start + nested_start)
            for index, start in enumerate(starts):
                end = starts[index + 1] if index + 1 < len(starts) else match_start + len(segment)
                raw_url = value[start:end]
                if raw_url in allowed_structural_urls:
                    continue
                _validate_regex_url_candidate(
                    raw_url,
                    allow_synthetic_markers=allow_synthetic_markers,
                    allowed_assignment_values=allowed_assignment_values,
                    allowed_synthetic_full_values=allowed_synthetic_full_values,
                    source_value=value,
                )
        return
    for match in URL_PATTERN.finditer(value):
        raw_url = match.group(0)
        # Domain validators retain exact malformed and reserved URL values as
        # negative-test vocabulary. Do not generalize the allowance to a host
        # suffix: a path-scoped exact token is the only structural bypass.
        if raw_url in allowed_structural_urls:
            continue
        _validate_raw_url_candidate(
            raw_url,
            allow_synthetic_markers=allow_synthetic_markers,
            allowed_assignment_values=allowed_assignment_values,
            allowed_synthetic_full_values=allowed_synthetic_full_values,
            source_value=value,
        )


def _is_exact_dynamic_basic_probe(value: str, candidate: str) -> bool:
    """Allow only the scanner's own isolated dynamic Basic probe.

    The probe is generated while rendering an unresolved Authorization value.
    A literal source that appends any second credential must not inherit that
    allowance merely because one later token happens to use the probe bytes.
    """

    normalized = value.strip()
    probe = f"Authorization: Basic {DYNAMIC_AUTHORIZATION_PROBE_CANDIDATE}"
    return (
        candidate == DYNAMIC_AUTHORIZATION_PROBE_CANDIDATE
        and (
            normalized == probe
            or normalized.endswith(f"synthetic.invalid {probe}")
        )
    )


def _validate_text_value(
    value: str,
    *,
    allow_nul: bool = False,
    check_assignments: bool = True,
    allow_synthetic_markers: bool = False,
    allowed_basic_auth_candidates: frozenset[str] = frozenset(),
    allowed_raw_rfc7617_tokens: frozenset[str] = frozenset(),
    allowed_assignment_values: frozenset[str] = frozenset(),
    allowed_synthetic_full_values: frozenset[str] = frozenset(),
    regex_pattern: bool = False,
    allowed_structural_urls: frozenset[str] = frozenset(),
    allowed_empty_assignment_lines: frozenset[str] = frozenset(),
    allowed_empty_assignment_values: frozenset[str] = frozenset(),
) -> None:
    if not allow_nul:
        require("\x00" not in value, "text contains an embedded NUL")
    # Scan both a compact representation and one that preserves control
    # boundaries. The compact form catches ``Bearer abc\x00def``; the preserved
    # form prevents a preceding prose word from swallowing a new ``token=``
    # assignment after a line break or zero-width separator.
    if allowed_empty_assignment_lines or allowed_empty_assignment_values:
        # Exact line and complete-value allowances require original boundaries.
        # Do not run compact forms first, because they would erase the context
        # that proves the reviewed fragment is the complete retained value.
        scan_values = (value,)
    else:
        scan_values = tuple(dict.fromkeys((
            _normalize_scanned_text(value),
            _normalize_scanned_text(value, preserve_controls=True),
        )))
    for scanned_value in scan_values:
        if check_assignments:
            _scan_assignment_candidates(
                scanned_value,
                allow_synthetic_markers=allow_synthetic_markers,
                allowed_assignment_values=allowed_assignment_values,
                exact_full_allowance=(
                    value in allowed_synthetic_full_values
                ),
                allowed_empty_assignment_lines=allowed_empty_assignment_lines,
                allowed_empty_assignment_values=allowed_empty_assignment_values,
            )
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
                    and (
                        candidate != DYNAMIC_AUTHORIZATION_PROBE_CANDIDATE
                        or _is_exact_dynamic_basic_probe(scanned_value, candidate)
                    )
                )
                # A reviewed full source may contain several credential-shaped
                # substrings (for example ``bearer=... Bearer ...``). Allow all
                # matches only when the complete scanned value is that exact
                # path-scoped source; a later token in any other value remains
                # independently enforced.
                exact_full_allowance = (
                    value in allowed_synthetic_full_values
                )
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



def _json_pointer_child(pointer: str, segment: str | int) -> str:
    token = str(segment).replace("~", "~0").replace("/", "~1")
    return f"{pointer}/{token}"


def _validate_redaction_tree(
    value: Any,
    *,
    allowed_assignment_values: frozenset[str] = frozenset(),
    allowed_structural_urls: frozenset[str] = frozenset(),
    allowed_empty_assignment_values: frozenset[str] = frozenset(),
    allowed_nul_fields: dict[str, tuple[str, tuple[tuple[str, str | int], ...]]] | None = None,
    json_pointer: str = "",
    json_ancestry: tuple[tuple[str, str | int], ...] = (),
) -> None:
    if allowed_nul_fields is None:
        allowed_nul_fields = {}
    if type(value) is dict:
        for key, child in value.items():
            # Object keys are retained input too. Scan them before treating a
            # normalized key as structural so nested credential-shaped keys
            # cannot bypass the value scanner. Keys never use the NUL-field
            # exception; JSON key validation remains unconditionally strict.
            _validate_text_value(
                key,
                allowed_assignment_values=allowed_assignment_values,
                allowed_structural_urls=allowed_structural_urls,
            )
            normalized = _validated_key_for_routing(key)
            child_pointer = _json_pointer_child(json_pointer, key)
            if normalized in RETAINED_CONTENT_ALIASES:
                _validate_retained_content_alias(child, key=normalized)
            if normalized in SENSITIVE_KEYS:
                _validate_sensitive_marker(child, key=normalized)
            else:
                _validate_redaction_tree(
                    child,
                    allowed_assignment_values=allowed_assignment_values,
                    allowed_structural_urls=allowed_structural_urls,
                    allowed_empty_assignment_values=allowed_empty_assignment_values,
                    allowed_nul_fields=allowed_nul_fields,
                    json_pointer=child_pointer,
                    json_ancestry=json_ancestry + (("dict", key),),
                )
        return
    if type(value) is list:
        for index, child in enumerate(value):
            _validate_redaction_tree(
                child,
                allowed_assignment_values=allowed_assignment_values,
                allowed_structural_urls=allowed_structural_urls,
                allowed_empty_assignment_values=allowed_empty_assignment_values,
                allowed_nul_fields=allowed_nul_fields,
                json_pointer=_json_pointer_child(json_pointer, index),
                json_ancestry=json_ancestry + (("list", index),),
            )
        return
    if type(value) is str:
        allowance = allowed_nul_fields.get(json_pointer)
        if allowance is not None:
            allowed_nul_value, allowed_ancestry = allowance
            # Pointer text alone is not authority: a numeric object key can
            # reproduce a list index. Require the exact reviewed container
            # ancestry as well as the canonical value before projecting NUL.
            require(value == allowed_nul_value, "NUL field value is not reviewed")
            require(json_ancestry == allowed_ancestry, "NUL field ancestry is not reviewed")
            _validate_text_value(
                value.replace("\x00", ""),
                allowed_assignment_values=allowed_assignment_values,
                allowed_structural_urls=allowed_structural_urls,
                allowed_empty_assignment_values=allowed_empty_assignment_values,
            )
            return
        _validate_text_value(
            value,
            allowed_assignment_values=allowed_assignment_values,
            allowed_structural_urls=allowed_structural_urls,
            allowed_empty_assignment_values=allowed_empty_assignment_values,
        )


def _validate_text_file(
    path: Path,
    *,
    data: bytes | None = None,
    allowed_assignment_values: frozenset[str] = frozenset(),
    allowed_structural_urls: frozenset[str] = frozenset(),
    allowed_empty_assignment_lines: frozenset[str] = frozenset(),
    allowed_empty_assignment_values: frozenset[str] = frozenset(),
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
        allowed_empty_assignment_lines=allowed_empty_assignment_lines,
        allowed_empty_assignment_values=allowed_empty_assignment_values,
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
    if type(value) is str and len(value) <= MAX_STATIC_RENDER_BYTES:
        return value
    return _STATIC_UNKNOWN


def _bounded_text_concat(parts: Iterable[str], *, separator: str = "") -> Any:
    """Join known text only after bounding count and final output size."""

    pieces: list[str] = []
    total = 0
    for index, part in enumerate(parts):
        if index >= MAX_STATIC_RENDER_PARTS or type(part) is not str:
            return _STATIC_UNKNOWN
        if index:
            total += len(separator)
        total += len(part)
        if total > MAX_STATIC_RENDER_BYTES:
            return _STATIC_UNKNOWN
        pieces.append(part)
    return separator.join(pieces)


def _conservative_text_concat(parts: Iterable[str], *, separator: str = "") -> str:
    """Keep a bounded prefix when an unknown construction would overflow."""

    pieces: list[str] = []
    total = 0
    truncated = False
    for index, part in enumerate(parts):
        if index >= MAX_STATIC_RENDER_PARTS or type(part) is not str:
            truncated = True
            break
        extra = len(separator) if index else 0
        if total + extra + len(part) > MAX_STATIC_RENDER_BYTES:
            truncated = True
            break
        if extra:
            pieces.append(separator)
            total += extra
        pieces.append(part)
        total += len(part)
    if truncated and total + len(_STATIC_DYNAMIC_VALUE) <= MAX_STATIC_RENDER_BYTES:
        pieces.append(_STATIC_DYNAMIC_VALUE)
    return "".join(pieces)


def _decimal_exceeds_limit(digits: str, limit: int) -> bool:
    """Compare decimal width text without converting an attacker-sized integer."""

    normalized = digits.lstrip("0") or "0"
    limit_text = str(limit)
    return len(normalized) > len(limit_text) or (
        len(normalized) == len(limit_text) and normalized > limit_text
    )


def _bounded_format_spec(format_spec: str) -> bool:
    if len(format_spec) > MAX_STATIC_FORMAT_SPEC_BYTES or "{" in format_spec or "}" in format_spec:
        return False
    return not any(
        _decimal_exceeds_limit(digits, MAX_STATIC_FORMAT_FIELD_WIDTH)
        for digits in re.findall(r"\d+", format_spec)
    )


def _bounded_scalar_length(value: Any, conversion: str | None = None) -> int | None:
    if value is _STATIC_UNKNOWN:
        return None
    if type(value) is str:
        length = len(value)
        if conversion in {"r", "a"}:
            if length > (MAX_STATIC_RENDER_BYTES - 2) // 2:
                return None
            return length * 2 + 2
        return length
    if type(value) in {int, float, bool} or value is None:
        try:
            return len(repr(value) if conversion in {"r", "a"} else str(value))
        except (TypeError, ValueError, OverflowError):
            return None
    return None


def _bounded_format_template(
    template: str,
    args: tuple[Any, ...] | list[Any],
    keywords: dict[str, Any],
    *,
    mapping: dict[str, Any] | None = None,
) -> Any:
    """Preflight format fields before allowing Python to allocate output."""

    if type(template) is not str or len(template) > MAX_STATIC_RENDER_BYTES:
        return _STATIC_UNKNOWN
    formatter = string.Formatter()
    total = 0
    fields = 0
    auto_index = 0
    try:
        for literal, field_name, format_spec, conversion in formatter.parse(template):
            fields += 1
            if fields > MAX_STATIC_RENDER_PARTS:
                return _STATIC_UNKNOWN
            total += len(literal)
            if total > MAX_STATIC_RENDER_BYTES:
                return _STATIC_UNKNOWN
            if field_name is None:
                continue
            if format_spec and not _bounded_format_spec(format_spec):
                return _STATIC_UNKNOWN
            if field_name == "":
                field_name = str(auto_index)
                auto_index += 1
            value, _ = formatter.get_field(field_name, args, mapping if mapping is not None else keywords)
            field_length = _bounded_scalar_length(value, conversion)
            if field_length is None:
                return _STATIC_UNKNOWN
            width = max((int(digits) for digits in re.findall(r"\d+", format_spec)), default=0)
            total += max(field_length, width)
            if total > MAX_STATIC_RENDER_BYTES:
                return _STATIC_UNKNOWN
    except (IndexError, KeyError, AttributeError, TypeError, ValueError, OverflowError):
        return _STATIC_UNKNOWN
    try:
        if mapping is not None:
            rendered = template.format_map(mapping)
        else:
            rendered = template.format(*args, **keywords)
    except (IndexError, KeyError, AttributeError, TypeError, ValueError, OverflowError):
        return _STATIC_UNKNOWN
    return _bounded_static_text(rendered)


def _bounded_format_value(value: Any, format_spec: str, conversion: str | None = None) -> Any:
    if type(format_spec) is not str or not _bounded_format_spec(format_spec):
        return _STATIC_UNKNOWN
    if conversion == "s":
        try:
            value = str(value)
        except (TypeError, ValueError, OverflowError):
            return _STATIC_UNKNOWN
    elif conversion == "r":
        try:
            value = repr(value)
        except (TypeError, ValueError, OverflowError):
            return _STATIC_UNKNOWN
    elif conversion == "a":
        try:
            value = ascii(value)
        except (TypeError, ValueError, OverflowError):
            return _STATIC_UNKNOWN
    field_length = _bounded_scalar_length(value)
    if field_length is None:
        return _STATIC_UNKNOWN
    width = max((int(digits) for digits in re.findall(r"\d+", format_spec)), default=0)
    if max(field_length, width) > MAX_STATIC_RENDER_BYTES:
        return _STATIC_UNKNOWN
    try:
        return _bounded_static_text(format(value, format_spec))
    except (TypeError, ValueError, OverflowError):
        return _STATIC_UNKNOWN


_PERCENT_CONVERSIONS = frozenset("diouxXeEfFgGrsca")
_PERCENT_FLAGS = frozenset("#0- +")


def _bounded_percent_format(template: str) -> bool:
    """Preflight every percent directive before Python can render it.

    The percent operator consumes ``*`` width and precision operands from a
    tuple. Those values are runtime-controlled and can request a huge string
    before the scanner gets a chance to inspect the result, so dynamic fields
    are always unknown. Parsing also avoids the old regex blind spot where
    ``%*s`` and ``%.*f`` were not inspected at all.
    """

    index = 0
    conversions = 0
    while index < len(template):
        if template[index] != "%":
            index += 1
            continue
        if index + 1 >= len(template):
            return False
        if template[index + 1] == "%":
            index += 2
            continue
        index += 1
        if index < len(template) and template[index] == "(":
            closing = template.find(")", index + 1, index + MAX_STATIC_FORMAT_SPEC_BYTES + 1)
            if closing < 0:
                return False
            index = closing + 1
        while index < len(template) and template[index] in _PERCENT_FLAGS:
            index += 1
        if index < len(template) and template[index] == "*":
            return False
        width_start = index
        while index < len(template) and template[index].isdigit():
            index += 1
        if width_start < index and _decimal_exceeds_limit(
            template[width_start:index], MAX_STATIC_FORMAT_FIELD_WIDTH
        ):
            return False
        if index < len(template) and template[index] == ".":
            index += 1
            if index >= len(template) or template[index] == "*":
                return False
            precision_start = index
            while index < len(template) and template[index].isdigit():
                index += 1
            if precision_start == index or _decimal_exceeds_limit(
                template[precision_start:index], MAX_STATIC_FORMAT_FIELD_WIDTH
            ):
                return False
        if index < len(template) and template[index] in "hlL":
            index += 1
        if index >= len(template) or template[index] not in _PERCENT_CONVERSIONS:
            return False
        conversions += 1
        if conversions > MAX_STATIC_RENDER_PARTS:
            return False
        index += 1
    return conversions > 0


def _bounded_percent_operand(
    value: Any,
    depth: int = 0,
    seen: set[int] | None = None,
) -> bool:
    """Bound percent operands without calling repr/str on untrusted shapes."""

    if depth > MAX_STATIC_FORMAT_NESTING:
        return False
    if value is _STATIC_UNKNOWN:
        return False
    if type(value) is str:
        return len(value) <= MAX_STATIC_RENDER_BYTES
    if type(value) is int:
        # Comparing directly avoids converting an attacker-sized integer to a
        # decimal string while deciding whether formatting is safe.
        return -MAX_INTEGER <= value <= MAX_INTEGER
    if type(value) is float:
        return math.isfinite(value) and _bounded_scalar_length(value) is not None
    if type(value) in {bool, type(None)}:
        return True
    if seen is None:
        seen = set()
    if type(value) in {tuple, list}:
        if len(value) > MAX_STATIC_COLLECTION_ITEMS or id(value) in seen:
            return False
        seen.add(id(value))
        try:
            return all(_bounded_percent_operand(child, depth + 1, seen) for child in value)
        finally:
            seen.remove(id(value))
    if type(value) is dict:
        if len(value) > MAX_STATIC_MAPPING_FIELDS or id(value) in seen:
            return False
        seen.add(id(value))
        try:
            return all(
                type(key) is str
                and len(key) <= MAX_STATIC_FORMAT_SPEC_BYTES
                and _bounded_percent_operand(child, depth + 1, seen)
                for key, child in value.items()
            )
        finally:
            seen.remove(id(value))
    return False


def _bounded_percent_value_length(
    value: Any,
    *,
    conversion: str,
    precision: int | None = None,
    depth: int = 0,
    seen: set[int] | None = None,
) -> int | None:
    """Estimate one percent field without invoking its formatter."""

    if depth > MAX_STATIC_FORMAT_NESTING:
        return None
    if value is _STATIC_UNKNOWN:
        return None
    if type(value) is str:
        if conversion in {"r", "a"}:
            # ``repr``/``ascii`` can expand control and non-ASCII code points
            # substantially. Use a fixed worst-case multiplier without calling
            # either formatter on untrusted source text.
            if len(value) > (MAX_STATIC_RENDER_BYTES - 2) // 10:
                return None
            length = len(value) * 10 + 2
        else:
            length = len(value)
    elif type(value) is int:
        if not -MAX_INTEGER <= value <= MAX_INTEGER:
            return None
        length = len(str(value))
    elif type(value) is float:
        if not math.isfinite(value):
            return None
        length = max(len(str(value)), len(repr(value)))
    elif type(value) in {bool, type(None)}:
        length = len(str(value))
    elif type(value) in {tuple, list}:
        if len(value) > MAX_STATIC_COLLECTION_ITEMS:
            return None
        if seen is None:
            seen = set()
        if id(value) in seen:
            return None
        seen.add(id(value))
        try:
            total = 2
            for index, child in enumerate(value):
                child_length = _bounded_percent_value_length(
                    child,
                    conversion="r",
                    depth=depth + 1,
                    seen=seen,
                )
                if child_length is None:
                    return None
                total += child_length + (2 if index else 0)
                if total > MAX_STATIC_RENDER_BYTES:
                    return None
            length = total
        finally:
            seen.remove(id(value))
    elif type(value) is dict:
        if len(value) > MAX_STATIC_MAPPING_FIELDS:
            return None
        if seen is None:
            seen = set()
        if id(value) in seen:
            return None
        seen.add(id(value))
        try:
            total = 2
            for index, (key, child) in enumerate(value.items()):
                if type(key) is not str:
                    return None
                child_length = _bounded_percent_value_length(
                    child,
                    conversion="r",
                    depth=depth + 1,
                    seen=seen,
                )
                if child_length is None:
                    return None
                key_length = _bounded_percent_value_length(
                    key,
                    conversion="r",
                    depth=depth + 1,
                    seen=seen,
                )
                if key_length is None:
                    return None
                total += key_length + child_length + (4 if index else 0)
                if total > MAX_STATIC_RENDER_BYTES:
                    return None
            length = total
        finally:
            seen.remove(id(value))
    else:
        return None
    if conversion in "eEfFgG":
        length = max(length, (6 if precision is None else precision) + 8)
    elif conversion in "diouxX" and precision is not None:
        length = max(length, precision + 8)
    elif conversion in "sra" and precision is not None:
        length = min(length, precision)
    if conversion == "c":
        if not ((type(value) is int and -MAX_INTEGER <= value <= MAX_INTEGER) or type(value) is str):
            return None
        length = 1
    return length


def _bounded_percent_estimate(template: str, value: Any) -> int | None:
    """Bound aggregate percent output before Python's ``%`` operation."""

    index = 0
    literal_total = 0
    conversions = 0
    operand_index = 0
    mapping = value if type(value) is dict else None
    positional = value if type(value) in {tuple, list} else None
    total = 0
    while index < len(template):
        if template[index] != "%":
            literal_start = index
            while index < len(template) and template[index] != "%":
                index += 1
            literal_total += index - literal_start
            total += index - literal_start
            if total > MAX_STATIC_RENDER_BYTES:
                return None
            continue
        if index + 1 >= len(template):
            return None
        if template[index + 1] == "%":
            total += 1
            if total > MAX_STATIC_RENDER_BYTES:
                return None
            index += 2
            continue
        index += 1
        field_name: str | None = None
        if index < len(template) and template[index] == "(":
            closing = template.find(")", index + 1, index + MAX_STATIC_FORMAT_SPEC_BYTES + 1)
            if closing < 0:
                return None
            field_name = template[index + 1:closing]
            index = closing + 1
        while index < len(template) and template[index] in _PERCENT_FLAGS:
            index += 1
        if index < len(template) and template[index] == "*":
            return None
        width_start = index
        while index < len(template) and template[index].isdigit():
            index += 1
        if width_start < index:
            width_text = template[width_start:index]
            if _decimal_exceeds_limit(width_text, MAX_STATIC_FORMAT_FIELD_WIDTH):
                return None
            width = int(width_text)
        else:
            width = 0
        precision: int | None = None
        if index < len(template) and template[index] == ".":
            index += 1
            if index >= len(template) or template[index] == "*":
                return None
            precision_start = index
            while index < len(template) and template[index].isdigit():
                index += 1
            if precision_start == index:
                return None
            precision_text = template[precision_start:index]
            if _decimal_exceeds_limit(precision_text, MAX_STATIC_FORMAT_FIELD_WIDTH):
                return None
            precision = int(precision_text)
        if index < len(template) and template[index] in "hlL":
            index += 1
        if index >= len(template) or template[index] not in _PERCENT_CONVERSIONS:
            return None
        conversion = template[index]
        index += 1
        conversions += 1
        if conversions > MAX_STATIC_RENDER_PARTS:
            return None
        if field_name is not None:
            if mapping is None or field_name not in mapping:
                return None
            operand = mapping[field_name]
        elif positional is not None and conversions > 1:
            if operand_index >= len(positional):
                return None
            operand = positional[operand_index]
            operand_index += 1
        else:
            operand = value
        field_length = _bounded_percent_value_length(
            operand,
            conversion=conversion,
            precision=precision,
        )
        if field_length is None:
            return None
        total += max(width, field_length)
        if total > MAX_STATIC_RENDER_BYTES:
            return None
    return total if conversions else None


def _bounded_percent(template: str, value: Any) -> Any:
    if type(template) is not str or len(template) > MAX_STATIC_RENDER_BYTES:
        return _STATIC_UNKNOWN
    # Both syntax and operands are checked before invoking ``%``. In
    # particular, a mapping-fed tuple must not reach formatting merely because
    # its mapping lookup was statically recoverable. The aggregate estimate is
    # also bounded so repeated literal widths cannot exceed the output budget
    # one field at a time.
    if not _bounded_percent_format(template) or not _bounded_percent_operand(value):
        return _STATIC_UNKNOWN
    if _bounded_percent_estimate(template, value) is None:
        return _STATIC_UNKNOWN
    try:
        return _bounded_static_text(template % value)
    except (IndexError, KeyError, TypeError, ValueError, OverflowError):
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
        if len(node.keys) > MAX_STATIC_COLLECTION_ITEMS:
            return _STATIC_UNKNOWN
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
        if len(node.values) > MAX_STATIC_RENDER_PARTS:
            return _STATIC_UNKNOWN
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
            conversion = {
                -1: None,
                115: "s",
                114: "r",
                97: "a",
            }.get(part.conversion)
            if part.conversion not in {-1, 115, 114, 97}:
                return _STATIC_UNKNOWN
            format_spec = ""
            if part.format_spec is not None:
                format_spec = _static_value(part.format_spec, bindings)
                if type(format_spec) is not str:
                    return _STATIC_UNKNOWN
            rendered = _bounded_format_value(formatted, format_spec, conversion)
            if rendered is _STATIC_UNKNOWN:
                return _STATIC_UNKNOWN
            pieces.append(rendered)
        return _bounded_text_concat(pieces)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        left = _static_value(node.left, bindings)
        right = _static_value(node.right, bindings)
        if isinstance(node.op, ast.Add) and type(left) is str and type(right) is str:
            return _bounded_text_concat((left, right))
        if isinstance(node.op, ast.Mod) and type(left) is str and not _contains_static_unknown(right):
            return _bounded_percent(left, right)
        return _STATIC_UNKNOWN
    if isinstance(node, (ast.List, ast.Tuple)):
        if len(node.elts) > MAX_STATIC_COLLECTION_ITEMS:
            return _STATIC_UNKNOWN
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
            return _bounded_format_template(receiver, args, keywords)
        if method == "format_map" and type(receiver) is str and len(node.args) == 1 and not node.keywords:
            mapping = _static_value(node.args[0], bindings)
            if not isinstance(mapping, dict) or _contains_static_unknown(mapping):
                return _STATIC_UNKNOWN
            return _bounded_format_template(receiver, (), {}, mapping=mapping)
        if method == "join" and type(receiver) is str and len(node.args) == 1 and not node.keywords:
            values = _static_value(node.args[0], bindings)
            if isinstance(values, (list, tuple)) and all(type(value) is str for value in values):
                return _bounded_text_concat(values, separator=receiver)
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
    if len(template) > MAX_STATIC_RENDER_BYTES:
        return {}
    pattern = (
        r"{([^{}!:]+)(?:![^}:]+)?(?:\s*:[^}]*)?}"
        if format_map
        else r"%\(([^()]+)\)"
    )
    fields: list[str] = []
    seen: set[str] = set()
    for match in re.finditer(pattern, template):
        field = match.group(1)
        if field in seen:
            continue
        if len(fields) >= MAX_STATIC_MAPPING_FIELDS:
            break
        seen.add(field)
        fields.append(field)
    return {field: _percent_mapping_probe(field) for field in fields}


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
        return _conservative_text_concat((rendered, " Authorization: Basic AAAAAAAAAAAAAAAA"))
    return rendered[:MAX_STATIC_RENDER_BYTES]


def _conservative_text(node: ast.AST, bindings: dict[str, Any]) -> str:
    """Render unresolved string expressions with credential-shaped probes."""
    value = _static_value(node, bindings)
    if type(value) is str:
        return value[:MAX_STATIC_RENDER_BYTES]
    if isinstance(node, ast.Constant):
        literal = _static_scalar(node.value)
        return literal[:MAX_STATIC_RENDER_BYTES] if type(literal) is str else _STATIC_DYNAMIC_VALUE
    if isinstance(node, ast.Name):
        bound = bindings.get(node.id, _STATIC_UNKNOWN)
        return bound[:MAX_STATIC_RENDER_BYTES] if type(bound) is str else _STATIC_DYNAMIC_VALUE
    if isinstance(node, ast.JoinedStr):
        if len(node.values) > MAX_STATIC_RENDER_PARTS:
            return _with_dynamic_authorization_probe(node, bindings, _STATIC_DYNAMIC_VALUE)
        pieces: list[str] = []
        for part in node.values:
            if isinstance(part, ast.Constant):
                literal = _static_scalar(part.value)
                pieces.append(literal if type(literal) is str else _STATIC_DYNAMIC_VALUE)
            elif isinstance(part, ast.FormattedValue):
                formatted = _conservative_text(part.value, bindings)
                conversion = {
                    -1: None,
                    115: "s",
                    114: "r",
                    97: "a",
                }.get(part.conversion)
                if part.conversion not in {-1, 115, 114, 97}:
                    pieces.append(_STATIC_DYNAMIC_VALUE)
                    continue
                format_spec = ""
                if part.format_spec is not None:
                    format_spec = _conservative_text(part.format_spec, bindings)
                rendered = _bounded_format_value(formatted, format_spec, conversion)
                pieces.append(rendered if rendered is not _STATIC_UNKNOWN else _STATIC_DYNAMIC_VALUE)
            else:
                pieces.append(_STATIC_DYNAMIC_VALUE)
        return _with_dynamic_authorization_probe(
            node,
            bindings,
            _conservative_text_concat(pieces),
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        left = _conservative_text(node.left, bindings)
        right = _conservative_text(node.right, bindings)
        if isinstance(node.op, ast.Add):
            rendered = _conservative_text_concat((left, right))
            return _with_dynamic_authorization_probe(node, bindings, rendered)
        if isinstance(node.right, ast.Tuple) and len(node.right.elts) <= MAX_STATIC_COLLECTION_ITEMS:
            values = tuple(_conservative_text(child, bindings) for child in node.right.elts)
            rendered = _bounded_percent(left, values)
        else:
            rendered = _bounded_percent(left, right)
        if rendered is _STATIC_UNKNOWN:
            rendered = _conservative_text_concat((left, right), separator=" ")
        probe_value = _percent_probe_value(node.right, bindings, template=left)
        credential_probe = _bounded_percent(left, probe_value)
        if credential_probe is _STATIC_UNKNOWN:
            credential_probe = left
        # Scan both ordinary conservative rendering and the auth-scheme probe.
        # This preserves known template context without letting an unresolved
        # `%s` choose `Basic` or another credential scheme only at runtime.
        combined = _conservative_text_concat((rendered, credential_probe), separator=" ")
        return _with_dynamic_authorization_probe(node, bindings, combined)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        method = node.func.attr
        receiver = _conservative_text(node.func.value, bindings)
        if method == "format":
            if len(node.args) > MAX_STATIC_COLLECTION_ITEMS or len(node.keywords) > MAX_STATIC_COLLECTION_ITEMS:
                return _with_dynamic_authorization_probe(
                    node,
                    bindings,
                    _conservative_text_concat((receiver, _STATIC_DYNAMIC_VALUE), separator=" "),
                )
            args = [_conservative_text(argument, bindings) for argument in node.args]
            keywords = {
                keyword.arg: _conservative_text(keyword.value, bindings)
                for keyword in node.keywords
                if keyword.arg is not None
            }
            rendered = _bounded_format_template(receiver, args, keywords)
            if rendered is _STATIC_UNKNOWN:
                rendered = _conservative_text_concat((receiver, *args, *keywords.values()), separator=" ")
            return _with_dynamic_authorization_probe(node, bindings, rendered)
        if method == "format_map" and len(node.args) == 1 and not node.keywords:
            mapping = _static_value(node.args[0], bindings)
            rendered = _STATIC_UNKNOWN
            if isinstance(mapping, dict) and not _contains_static_unknown(mapping):
                rendered = _bounded_format_template(receiver, (), {}, mapping=mapping)
            if rendered is _STATIC_UNKNOWN:
                probe = _mapping_probe_from_template(receiver, format_map=True)
                rendered = _bounded_format_template(receiver, (), {}, mapping=probe)
                if rendered is _STATIC_UNKNOWN:
                    rendered = _conservative_text_concat((receiver, *probe.values()), separator=" ")
            return _with_dynamic_authorization_probe(node, bindings, rendered)
        if method == "join" and len(node.args) == 1 and not node.keywords:
            sequence = node.args[0]
            if isinstance(sequence, (ast.List, ast.Tuple)) and len(sequence.elts) <= MAX_STATIC_COLLECTION_ITEMS:
                values = [_conservative_text(child, bindings) for child in sequence.elts]
                rendered = _conservative_text_concat(values, separator=receiver)
                return _with_dynamic_authorization_probe(node, bindings, rendered)
            # Preserve the known separator and mark only the unknown payload.
            # A credential prefix in the receiver still fails closed, while an
            # unrelated dynamic join does not invent credential syntax that is
            # absent from the retained source.
            return _with_dynamic_authorization_probe(
                node,
                bindings,
                _conservative_text_concat((receiver, _STATIC_DYNAMIC_VALUE)),
            )
        # Unsupported string methods retain any statically visible prefix. If
        # that prefix is an Authorization header, the unknown method result gets
        # a bounded Basic probe instead of disappearing into a safe sentinel.
        return _with_dynamic_authorization_probe(
            node,
            bindings,
            _conservative_text_concat((receiver, _STATIC_DYNAMIC_VALUE), separator=" "),
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


def _regex_target_names(node: ast.AST) -> tuple[str, ...]:
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, ast.Starred):
        return _regex_target_names(node.value)
    if isinstance(node, (ast.Tuple, ast.List)):
        names: list[str] = []
        for child in node.elts:
            names.extend(_regex_target_names(child))
        return tuple(names)
    return ()


def _regex_reference_kind(
    node: ast.AST,
    *,
    module_names: set[str],
    compile_names: set[str],
) -> str | None:
    if isinstance(node, ast.Name):
        if node.id in module_names:
            return "module"
        if node.id in compile_names:
            return "compiler"
        return None
    if isinstance(node, ast.Attribute) and node.attr == "compile":
        if isinstance(node.value, ast.Name) and node.value.id in module_names:
            return "compiler"
        return None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) == 2
        and not node.keywords
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id in module_names
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value == "compile"
    ):
        return "compiler"
    return None


def _regex_import_bindings(tree: ast.AST) -> tuple[frozenset[str], frozenset[str]]:
    """Discover approved regex module/compiler aliases without execution.

    Alias edges are indexed once and then resolved with a worklist. This keeps
    long, bounded source files linear instead of repeatedly walking the full AST
    for every reverse-chain hop.
    """

    nodes = tuple(ast.walk(tree))
    module_names = {"re", "regex"}
    compile_names: set[str] = set()
    edges: dict[str, set[tuple[str, str]]] = {}

    def add_edge(source: str, target_kind: str, target: str) -> None:
        edges.setdefault(source, set()).add((target_kind, target))

    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in {"re", "regex"}:
                    module_names.add(alias.asname or alias.name)
            continue
        if isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module in {"re", "regex"}:
                for alias in node.names:
                    if alias.name == "compile":
                        compile_names.add(alias.asname or alias.name)
            continue
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = (node.target,)
            value = node.value
        else:
            continue
        target_names = tuple(
            name
            for target in targets
            for name in _regex_target_names(target)
        )
        if not target_names:
            continue
        if isinstance(value, ast.Name):
            for target in target_names:
                add_edge(value.id, "module", target)
                add_edge(value.id, "compiler", target)
        elif isinstance(value, ast.Attribute) and value.attr == "compile" and isinstance(value.value, ast.Name):
            for target in target_names:
                add_edge(value.value.id, "compiler", target)
        elif (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "getattr"
            and len(value.args) == 2
            and not value.keywords
            and isinstance(value.args[0], ast.Name)
            and isinstance(value.args[1], ast.Constant)
            and value.args[1].value == "compile"
        ):
            for target in target_names:
                add_edge(value.args[0].id, "compiler", target)

    queue: list[tuple[str, str]] = [
        *(("module", name) for name in module_names),
        *(("compiler", name) for name in compile_names),
    ]
    seen: set[tuple[str, str]] = set()
    cursor = 0
    while cursor < len(queue):
        kind, source = queue[cursor]
        cursor += 1
        marker = (kind, source)
        if marker in seen:
            continue
        seen.add(marker)
        for target_kind, target in edges.get(source, ()):
            target_set = module_names if target_kind == "module" else compile_names
            if target not in target_set:
                target_set.add(target)
                queue.append((target_kind, target))
    return frozenset(module_names), frozenset(compile_names)


def _is_regex_compile_callable(
    callable_node: ast.AST,
    module_names: frozenset[str],
    compile_names: frozenset[str],
) -> bool:
    if isinstance(callable_node, ast.Attribute):
        return (
            callable_node.attr == "compile"
            and isinstance(callable_node.value, ast.Name)
            and callable_node.value.id in module_names
        )
    if isinstance(callable_node, ast.Name):
        return callable_node.id in compile_names
    if (
        isinstance(callable_node, ast.Call)
        and isinstance(callable_node.func, ast.Name)
        and callable_node.func.id == "getattr"
        and not callable_node.keywords
        and len(callable_node.args) == 2
        and isinstance(callable_node.args[0], ast.Name)
        and callable_node.args[0].id in module_names
        and isinstance(callable_node.args[1], ast.Constant)
        and callable_node.args[1].value == "compile"
    ):
        return True
    return False


def _regex_compile_call_nodes(tree: ast.AST) -> tuple[ast.Call, ...]:
    module_names, compile_names = _regex_import_bindings(tree)
    return tuple(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _is_regex_compile_callable(node.func, module_names, compile_names)
    )


def _regex_call_nodes(tree: ast.AST) -> set[int]:
    result: set[int] = set()
    for node in _regex_compile_call_nodes(tree):
        result.update(id(child) for child in ast.walk(node))
    return result


def _regex_pattern_node(call: ast.Call) -> ast.AST:
    positional = call.args[0] if call.args else None
    keyword_patterns = [keyword.value for keyword in call.keywords if keyword.arg == "pattern"]
    require(len(keyword_patterns) <= 1, "regex pattern argument is duplicated")
    require(positional is None or not keyword_patterns, "regex pattern argument is duplicated")
    pattern = positional if positional is not None else (keyword_patterns[0] if keyword_patterns else None)
    require(pattern is not None and not isinstance(pattern, ast.Starred), "regex pattern argument is unsupported")
    # ``**kwargs`` can hide a second pattern or compiler flag. Fail closed.
    require(all(keyword.arg is not None for keyword in call.keywords), "regex keyword arguments are unsupported")
    return pattern


def _resolve_regex_pattern(call: ast.Call, bindings: dict[str, Any]) -> str | object:
    """Resolve a bounded regex pattern without executing source expressions.

    Unknown runtime pattern operands are returned as a sentinel so their literal
    descendants can still be scanned conservatively. The caller continues to
    reject malformed compiler syntax and oversized statically known patterns.
    """

    value = _static_value(_regex_pattern_node(call), bindings)
    if value is _STATIC_UNKNOWN:
        return _STATIC_UNKNOWN
    require(type(value) is str, "regex pattern type is unsupported")
    require(len(value) <= MAX_STATIC_RENDER_BYTES, "regex pattern is too large")
    return value


def _regex_static_source_bindings(tree: ast.AST) -> dict[str, ast.AST | None]:
    """Track unique literal assignment sources for compile-node exclusion."""

    sources: dict[str, ast.AST | None] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = (node.target,)
            value = node.value
        else:
            continue
        for target in targets:
            for name in _regex_target_names(target):
                if name not in sources:
                    sources[name] = value
                elif sources[name] is not value:
                    sources[name] = None
    return sources


def _regex_pattern_constant_nodes(
    node: ast.AST,
    sources: dict[str, ast.AST | None],
    seen_names: set[str] | None = None,
) -> set[int]:
    """Return source literal nodes consumed by one compile pattern."""

    if seen_names is None:
        seen_names = set()
    if isinstance(node, ast.Constant) and type(node.value) in {str, bytes}:
        return {id(node)}
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return (
            _regex_pattern_constant_nodes(node.left, sources, seen_names)
            | _regex_pattern_constant_nodes(node.right, sources, seen_names)
        )
    if isinstance(node, ast.JoinedStr):
        result: set[int] = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and type(child.value) in {str, bytes}:
                result.add(id(child))
        return result
    if isinstance(node, ast.Name) and node.id not in seen_names:
        source = sources.get(node.id)
        if source is not None:
            return _regex_pattern_constant_nodes(source, sources, seen_names | {node.id})
    return set()


def _validate_regex_literal(
    value: str,
    *,
    allow_synthetic_markers: bool = False,
    allowed_assignment_values: frozenset[str] = frozenset(),
    allowed_synthetic_full_values: frozenset[str] = frozenset(),
    allowed_structural_urls: frozenset[str] = frozenset(),
) -> None:
    """Scan regex-shaped literals that are not passed to a compiler call.

    Fixture source can retain a detector pattern in a plain ``VALUE`` literal.
    It still needs regex URL policy, but compile arguments are handled once by
    the resolved-pattern path in ``_validate_python_file``. Large multiline
    source snippets are retained text rather than one regex pattern; their
    ordinary scanner pass still checks every URL and credential match.
    """

    if len(value) > MAX_REGEX_GROUP_SOURCE_LENGTH and ("\n" in value or "\r" in value):
        return
    has_url_hint = _regex_url_hint(value)
    if not has_url_hint or not any(
        marker in value for marker in ("\\", "[", "]", "(", ")", "{", "}", "|", "*", "+", "?", "^", "$")
    ):
        return
    _validate_url_hosts(
        value,
        allow_synthetic_markers=allow_synthetic_markers,
        regex_pattern=True,
        allowed_structural_urls=allowed_structural_urls,
        allowed_assignment_values=allowed_assignment_values,
        allowed_synthetic_full_values=allowed_synthetic_full_values,
    )
    supported_starts = {start for start, _end in _regex_scheme_matches(value)}
    dynamic = re.compile(r"(?i)(?<![A-Za-z])(?:h|w)[^\s<>'\"]{0,63}://")
    for match in dynamic.finditer(value):
        if match.start() in supported_starts:
            continue
        remainder = value[match.end():]
        authority = re.split(r"[/#?\s<>'\"]", remainder, maxsplit=1)[0]
        # A detector branch may end at the protocol delimiter immediately
        # before a sibling branch or enclosing group. That regex punctuation is
        # not an authority for this prefix; any other recovered body remains
        # fail-closed.
        if authority and authority[0] not in "|)":
            raise ValidationError()


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


def _control_parent_map(tree: ast.AST) -> dict[int, tuple[ast.AST, str, int | None]]:
    """Index AST parents once so policy roles do not depend on source lines."""

    parents: dict[int, tuple[ast.AST, str, int | None]] = {}
    for parent in ast.walk(tree):
        for field, child in ast.iter_fields(parent):
            if isinstance(child, ast.AST):
                parents[id(child)] = (parent, field, None)
            elif isinstance(child, list):
                for index, item in enumerate(child):
                    if isinstance(item, ast.AST):
                        parents[id(item)] = (parent, field, index)
    return parents


def _control_dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _control_dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return type(node).__name__


def _control_target_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        return _control_dotted_name(node)
    if isinstance(node, (ast.Tuple, ast.List)):
        return "[" + ",".join(_control_target_name(child) for child in node.elts) + "]"
    return type(node).__name__


def _control_path_from(
    parents: dict[int, tuple[ast.AST, str, int | None]],
    node: ast.AST,
    ancestor: ast.AST,
) -> list[str] | None:
    steps: list[str] = []
    current = node
    while current is not ancestor:
        relation = parents.get(id(current))
        if relation is None:
            return None
        parent, field, index = relation
        steps.append(f"{field}[{index}]" if index is not None else field)
        current = parent
    return list(reversed(steps))


def _control_scope(
    parents: dict[int, tuple[ast.AST, str, int | None]],
    node: ast.AST,
) -> str:
    # A bare function name is not authority: methods and nested helpers often
    # reuse the same local name. Preserve every enclosing class/function in
    # source order so a reviewed row cannot be moved to a same-local-name site.
    scopes: list[str] = []
    current = node
    while id(current) in parents:
        parent, _field, _index = parents[id(current)]
        if isinstance(parent, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            scopes.append(parent.name)
        current = parent
    return ".".join(reversed(scopes)) if scopes else "module"


def _control_role(
    parents: dict[int, tuple[ast.AST, str, int | None]],
    node: ast.AST,
) -> str:
    function = _control_scope(parents, node)
    current = node
    while id(current) in parents:
        parent, _field, _index = parents[id(current)]
        if isinstance(parent, ast.Call):
            path = _control_path_from(parents, node, parent) or []
            if path and path[0].startswith("args["):
                argument = path[0].split("[", 1)[1].rstrip("]")
                return (
                    f"fn:{function}|call:{_control_dotted_name(parent.func)}|"
                    f"arg:{argument}|path:{'/'.join(path[1:]) or 'direct'}"
                )
            if path and path[0].startswith("keywords["):
                keyword_index = int(path[0].split("[", 1)[1].rstrip("]"))
                keyword = parent.keywords[keyword_index]
                return (
                    f"fn:{function}|call:{_control_dotted_name(parent.func)}|"
                    f"kw:{keyword.arg or '**'}|path:{'/'.join(path[1:]) or 'direct'}"
                )
        current = parent

    current = node
    while id(current) in parents:
        parent, _field, _index = parents[id(current)]
        if isinstance(parent, ast.Assign):
            path = _control_path_from(parents, node, parent) or []
            return (
                f"fn:{function}|assign:{','.join(_control_target_name(target) for target in parent.targets)}|"
                f"path:{'/'.join(path)}"
            )
        if isinstance(parent, ast.AnnAssign):
            path = _control_path_from(parents, node, parent) or []
            return f"fn:{function}|annassign:{_control_target_name(parent.target)}|path:{'/'.join(path)}"
        if isinstance(parent, ast.NamedExpr):
            path = _control_path_from(parents, node, parent) or []
            return f"fn:{function}|namedexpr:{_control_target_name(parent.target)}|path:{'/'.join(path)}"
        current = parent

    current = node
    while id(current) in parents:
        parent, _field, _index = parents[id(current)]
        if isinstance(parent, (ast.Dict, ast.List, ast.Tuple, ast.Set)):
            path = _control_path_from(parents, node, parent) or []
            return f"fn:{function}|container:{type(parent).__name__}|path:{'/'.join(path)}"
        if isinstance(parent, ast.Compare):
            path = _control_path_from(parents, node, parent) or []
            operators = ",".join(type(operator).__name__ for operator in parent.ops)
            return f"fn:{function}|compare:{operators}|path:{'/'.join(path)}"
        if isinstance(parent, ast.Assert):
            path = _control_path_from(parents, node, parent) or []
            return f"fn:{function}|assert|path:{'/'.join(path)}"
        current = parent
    return f"fn:{function}|module-path"


def _control_literal_hex(value: str | bytes) -> str:
    try:
        return value.hex() if type(value) is bytes else value.encode("utf-8").hex()
    except UnicodeError as exc:
        raise ValidationError() from exc


def _control_literal_record(
    node: ast.Constant,
    parents: dict[int, tuple[ast.AST, str, int | None]],
    occurrences: dict[tuple[str, str, str], int],
) -> tuple[str, str, str, int] | None:
    value = node.value
    if type(value) not in {str, bytes}:
        return None
    controls = (
        {code for code in value if code < 32 or code == 127}
        if type(value) is bytes
        else {ord(character) for character in value if ord(character) < 32 or ord(character) == 127}
    )
    if not controls or controls == {10}:
        return None
    kind = "bytes" if type(value) is bytes else "str"
    value_hex = _control_literal_hex(value)
    role = _control_role(parents, node)
    key = (kind, value_hex, role)
    ordinal = occurrences.get(key, 0)
    occurrences[key] = ordinal + 1
    return kind, value_hex, role, ordinal


def _control_free_projection(value: str | bytes) -> str | None:
    if type(value) is bytes:
        try:
            value = value.decode("utf-8")
        except UnicodeError:
            return None
    return "".join(
        character
        for character in value
        if ord(character) >= 32 and ord(character) != 127
    )


def _control_projection_from_hex(kind: str, value_hex: str) -> str | None:
    try:
        value = struct.pack(
            f"{len(value_hex) // 2}B",
            *(int(value_hex[index:index + 2], 16) for index in range(0, len(value_hex), 2)),
        )
    except (struct.error, ValueError) as exc:
        raise ValidationError() from exc
    if kind not in {"str", "bytes"}:
        return None
    return _control_free_projection(value)


def _control_static_int(node: ast.AST) -> int | None:
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    return None


def _control_static_bytes_hex(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and type(node.value) is bytes:
        return node.value.hex()
    if isinstance(node, (ast.List, ast.Tuple)) and len(node.elts) <= MAX_STATIC_COLLECTION_ITEMS:
        values: list[int] = []
        for child in node.elts:
            value = _control_static_int(child)
            if value is None or not 0 <= value <= 255:
                return None
            values.append(value)
        return "".join(format(value, "02x") for value in values)
    return None


_CONTROL_MODULE_PREFIX = "module:"
_CONTROL_INVALID = object()
_CONTROL_GETATTR_SELECTOR = object()
_CONTROL_DIRECT_APIS = frozenset({"chr", "bytes", "bytearray"})
_CONTROL_MODULES = frozenset({"builtins", "binascii", "codecs"})
_CONTROL_DYNAMIC_SELECTORS = frozenset({"getattr"})
_CONTROL_RESERVED_NAMES = _CONTROL_DIRECT_APIS | _CONTROL_MODULES | _CONTROL_DYNAMIC_SELECTORS
_CONTROL_CANONICAL_APIS = frozenset({
    "chr",
    "bytes",
    "bytearray",
    "bytes.fromhex",
    "bytearray.fromhex",
    "binascii.unhexlify",
    "binascii.a2b_hex",
    "codecs.decode",
})
_CONTROL_SOURCE_APIS = {
    "chr": "chr",
    "bytes": "bytes",
    "bytearray": "bytearray",
    "builtins.chr": "chr",
    "builtins.bytes": "bytes",
    "builtins.bytearray": "bytearray",
    "bytes.fromhex": "bytes.fromhex",
    "bytearray.fromhex": "bytearray.fromhex",
    "builtins.bytes.fromhex": "bytes.fromhex",
    "builtins.bytearray.fromhex": "bytearray.fromhex",
    "binascii.unhexlify": "binascii.unhexlify",
    "binascii.a2b_hex": "binascii.a2b_hex",
    "codecs.decode": "codecs.decode",
}


def _control_scope_chain(scope: str) -> tuple[str, ...]:
    if scope == "module":
        return ("module",)
    parts = scope.split(".")
    return tuple(
        [".".join(parts[:index]) for index in range(len(parts), 0, -1)]
        + ["module"]
    )


def _control_lookup_binding(
    bindings: dict[tuple[str, str], object],
    scope: str,
    name: str,
) -> tuple[bool, object | None]:
    for candidate in _control_scope_chain(scope):
        key = (candidate, name)
        if key in bindings:
            value = bindings[key]
            return True, value
    if name in _CONTROL_DIRECT_APIS:
        return True, name
    if name in _CONTROL_MODULES:
        return True, f"{_CONTROL_MODULE_PREFIX}{name}"
    if name in _CONTROL_DYNAMIC_SELECTORS:
        return True, _CONTROL_GETATTR_SELECTOR
    return False, None


def _control_resolve_expression(
    node: ast.AST,
    scope: str,
    bindings: dict[tuple[str, str], object],
) -> object | None:
    if isinstance(node, ast.Name):
        _found, value = _control_lookup_binding(bindings, scope, node.id)
        return value
    if not isinstance(node, ast.Attribute):
        return None
    base = _control_resolve_expression(node.value, scope, bindings)
    if base is _CONTROL_INVALID:
        return _CONTROL_INVALID
    if base == f"{_CONTROL_MODULE_PREFIX}builtins" and node.attr in _CONTROL_DIRECT_APIS:
        return node.attr
    if base == f"{_CONTROL_MODULE_PREFIX}builtins" and node.attr in _CONTROL_DYNAMIC_SELECTORS:
        return _CONTROL_GETATTR_SELECTOR
    if base == f"{_CONTROL_MODULE_PREFIX}binascii" and node.attr in {"unhexlify", "a2b_hex"}:
        return f"binascii.{node.attr}"
    if base == f"{_CONTROL_MODULE_PREFIX}codecs" and node.attr == "decode":
        return "codecs.decode"
    if base in {"bytes", "bytearray"} and node.attr == "fromhex":
        return f"{base}.fromhex"
    return None


def _control_bind_name(
    bindings: dict[tuple[str, str], object],
    scope: str,
    name: str,
    value: object,
    *,
    force: bool = False,
) -> None:
    key = (scope, name)
    if force:
        bindings[key] = value
    elif key in bindings:
        bindings[key] = _CONTROL_INVALID
    else:
        bindings[key] = value


def _control_target_names_for_binding(node: ast.AST) -> tuple[str, ...]:
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, (ast.Tuple, ast.List)):
        names: list[str] = []
        for child in node.elts:
            names.extend(_control_target_names_for_binding(child))
        return tuple(names)
    return ()


def _control_alias_bindings(
    tree: ast.AST,
    parents: dict[int, tuple[ast.AST, str, int | None]],
) -> dict[tuple[str, str], object]:
    """Resolve only bounded import/simple-alias chains for control APIs.

    This is deliberately not a general constant-propagation engine. A second
    binding, shadowing parameter, dynamic assignment, or unknown imported API
    invalidates a known alias; the caller then fails closed before generic AST
    text handling can hide a constructed control value.
    """
    bindings: dict[tuple[str, str], object] = {}
    nodes = sorted(ast.walk(tree), key=lambda item: (getattr(item, "lineno", -1), getattr(item, "col_offset", -1)))

    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            parent_scope = _control_scope(parents, node)
            if node.name in _CONTROL_RESERVED_NAMES or (parent_scope, node.name) in bindings:
                _control_bind_name(bindings, parent_scope, node.name, _CONTROL_INVALID)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                local_scope = node.name if parent_scope == "module" else f"{parent_scope}.{node.name}"
                # Ordinary parameters such as ``data`` and ``self`` must not
                # make unrelated method calls look like shadowed constructors;
                # invalidate only names that could hide a known control alias.
                outer_scopes = _control_scope_chain(parent_scope)
                for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
                    if (
                        argument.arg in _CONTROL_RESERVED_NAMES
                        or any((candidate, argument.arg) in bindings for candidate in outer_scopes)
                    ):
                        _control_bind_name(bindings, local_scope, argument.arg, _CONTROL_INVALID, force=True)
                if node.args.vararg is not None and (
                    node.args.vararg.arg in _CONTROL_RESERVED_NAMES
                    or any((candidate, node.args.vararg.arg) in bindings for candidate in outer_scopes)
                ):
                    _control_bind_name(bindings, local_scope, node.args.vararg.arg, _CONTROL_INVALID, force=True)
                if node.args.kwarg is not None and (
                    node.args.kwarg.arg in _CONTROL_RESERVED_NAMES
                    or any((candidate, node.args.kwarg.arg) in bindings for candidate in outer_scopes)
                ):
                    _control_bind_name(bindings, local_scope, node.args.kwarg.arg, _CONTROL_INVALID, force=True)
        elif isinstance(node, ast.Import):
            scope = _control_scope(parents, node)
            for alias in node.names:
                bound = alias.asname or alias.name.split(".", 1)[0]
                if alias.name in _CONTROL_MODULES:
                    _control_bind_name(bindings, scope, bound, f"{_CONTROL_MODULE_PREFIX}{alias.name}")
                elif bound in _CONTROL_RESERVED_NAMES:
                    _control_bind_name(bindings, scope, bound, _CONTROL_INVALID)
        elif isinstance(node, ast.ImportFrom):
            scope = _control_scope(parents, node)
            module = node.module or ""
            for alias in node.names:
                bound = alias.asname or alias.name
                canonical: object = _CONTROL_INVALID
                if module == "builtins" and alias.name in _CONTROL_DIRECT_APIS:
                    canonical = alias.name
                elif module == "builtins" and alias.name in _CONTROL_DYNAMIC_SELECTORS:
                    canonical = _CONTROL_GETATTR_SELECTOR
                elif module == "binascii" and alias.name in {"unhexlify", "a2b_hex"}:
                    canonical = f"binascii.{alias.name}"
                elif module == "codecs" and alias.name == "decode":
                    canonical = "codecs.decode"
                elif alias.name in _CONTROL_RESERVED_NAMES:
                    canonical = _CONTROL_INVALID
                if canonical is not _CONTROL_INVALID or bound in _CONTROL_RESERVED_NAMES:
                    _control_bind_name(bindings, scope, bound, canonical)
        elif isinstance(node, ast.Assign):
            scope = _control_scope(parents, node)
            resolved = _control_resolve_expression(node.value, scope, bindings)
            for target in node.targets:
                for name in _control_target_names_for_binding(target):
                    if name in _CONTROL_RESERVED_NAMES or (scope, name) in bindings:
                        _control_bind_name(bindings, scope, name, _CONTROL_INVALID)
                    elif resolved is _CONTROL_GETATTR_SELECTOR or resolved in _CONTROL_CANONICAL_APIS or (isinstance(resolved, str) and resolved.startswith(_CONTROL_MODULE_PREFIX)):
                        _control_bind_name(bindings, scope, name, resolved)
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
            scope = _control_scope(parents, node)
            target = node.target if isinstance(node, ast.AnnAssign) else node.target
            resolved = _control_resolve_expression(node.value, scope, bindings) if node.value is not None else None
            for name in _control_target_names_for_binding(target):
                if name in _CONTROL_RESERVED_NAMES or (scope, name) in bindings:
                    _control_bind_name(bindings, scope, name, _CONTROL_INVALID)
                elif resolved is _CONTROL_GETATTR_SELECTOR or resolved in _CONTROL_CANONICAL_APIS or (isinstance(resolved, str) and resolved.startswith(_CONTROL_MODULE_PREFIX)):
                    _control_bind_name(bindings, scope, name, resolved)
        elif isinstance(node, (ast.AugAssign, ast.For, ast.AsyncFor)):
            scope = _control_scope(parents, node)
            target = node.target
            for name in _control_target_names_for_binding(target):
                if name in _CONTROL_RESERVED_NAMES or (scope, name) in bindings:
                    _control_bind_name(bindings, scope, name, _CONTROL_INVALID)
    return bindings


def _control_static_scalar(node: ast.AST) -> str | bytes | None:
    if isinstance(node, ast.Constant) and type(node.value) in {str, bytes}:
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _control_static_scalar(node.left)
        right = _control_static_scalar(node.right)
        if type(left) is type(right) and left is not None and len(left) + len(right) <= MAX_ARTIFACT_BYTES:
            return left + right
    return None


def _control_static_hex_payload(node: ast.AST) -> str | None:
    value = _control_static_scalar(node)
    if value is None:
        return None
    if type(value) is bytes:
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValidationError() from exc
    payload = "".join(value.split())
    if any(character not in "0123456789abcdefABCDEF" for character in payload) or len(payload) % 2:
        raise ValidationError()
    try:
        return "".join(
            f"{int(payload[index:index + 2], 16):02x}"
            for index in range(0, len(payload), 2)
        )
    except ValueError as exc:
        raise ValidationError() from exc


def _control_has_static_controls(node: ast.Call, canonical: str) -> bool:
    """Detect control evidence before rejecting an otherwise ordinary call shape.

    Fixture code also uses ``bytes(text, encoding)`` and ``bytearray()`` for
    ordinary serialization. Only reject a wrong-arity form when its static
    operands prove that it is attempting to construct a control-bearing value;
    fully valid control forms still fail closed below when their operands are
    dynamic or malformed.
    """
    operands = [argument for argument in node.args]
    operands.extend(keyword.value for keyword in node.keywords)
    if canonical == "chr":
        return any(
            (code := _control_static_int(operand)) is not None
            and (code < 32 or code == 127)
            for operand in operands
        )
    if canonical in {"bytes", "bytearray"}:
        for operand in operands:
            value_hex = _control_static_bytes_hex(operand)
            if value_hex is None:
                continue
            if any(
                int(value_hex[index:index + 2], 16) < 32
                or int(value_hex[index:index + 2], 16) == 127
                for index in range(0, len(value_hex), 2)
            ):
                return True
        return False
    if canonical in {
        "bytes.fromhex",
        "bytearray.fromhex",
        "binascii.unhexlify",
        "binascii.a2b_hex",
        "codecs.decode",
    }:
        for operand in operands[:1]:
            value_hex = _control_static_hex_payload(operand)
            if value_hex is None:
                continue
            if any(
                int(value_hex[index:index + 2], 16) < 32
                or int(value_hex[index:index + 2], 16) == 127
                for index in range(0, len(value_hex), 2)
            ):
                return True
    return False


def _control_dynamic_constructor(
    node: ast.AST,
    parents: dict[int, tuple[ast.AST, str, int | None]],
    bindings: dict[tuple[str, str], object],
) -> tuple[str, str, str, str] | None:
    if not isinstance(node, ast.Call):
        return None
    name = _control_dotted_name(node.func)
    scope = _control_scope(parents, node)
    resolved = _control_resolve_expression(node.func, scope, bindings)
    if isinstance(node.func, ast.Call):
        selector = _control_resolve_expression(node.func.func, scope, bindings)
        # Dynamic constructor selection cannot be proven without executing the
        # retained source. Reject direct and statically aliased ``getattr``
        # calls before their runtime-selected result can hide a control byte.
        if selector is _CONTROL_GETATTR_SELECTOR or _control_dotted_name(node.func.func) == "getattr":
            raise ValidationError()
    canonical = resolved if isinstance(resolved, str) else _CONTROL_SOURCE_APIS.get(name)
    if resolved is _CONTROL_INVALID:
        raise ValidationError()
    if canonical not in _CONTROL_CANONICAL_APIS:
        return None
    role = _control_role(parents, node)
    if canonical == "chr":
        if len(node.args) != 1 or node.keywords:
            if _control_has_static_controls(node, canonical):
                raise ValidationError()
            return None
        code = _control_static_int(node.args[0])
        if code is None:
            return ("unknown", "", canonical, role)
        if not 0 <= code <= 0x10FFFF:
            raise ValidationError()
        if code < 32 or code == 127:
            if code == 10:
                return None
            return ("str", format(code, "02x"), canonical, role)
        return None
    if canonical in {"bytes", "bytearray"}:
        if len(node.args) != 1 or node.keywords:
            if _control_has_static_controls(node, canonical):
                raise ValidationError()
            return None
        value_hex = _control_static_bytes_hex(node.args[0])
        if value_hex is None:
            return ("unknown", "", canonical, role)
        controls = {
            int(value_hex[index:index + 2], 16)
            for index in range(0, len(value_hex), 2)
            if int(value_hex[index:index + 2], 16) < 32
            or int(value_hex[index:index + 2], 16) == 127
        }
        if controls and controls != {10}:
            return ("bytes", value_hex, canonical, role)
        return None
    if canonical in {"bytes.fromhex", "bytearray.fromhex", "binascii.unhexlify", "binascii.a2b_hex"}:
        if len(node.args) != 1 or node.keywords:
            if _control_has_static_controls(node, canonical):
                raise ValidationError()
            return None
        value_hex = _control_static_hex_payload(node.args[0])
        if value_hex is None:
            return ("unknown", "", canonical, role)
        controls = {
            int(value_hex[index:index + 2], 16)
            for index in range(0, len(value_hex), 2)
            if int(value_hex[index:index + 2], 16) < 32
            or int(value_hex[index:index + 2], 16) == 127
        }
        if controls and controls != {10}:
            return ("bytes", value_hex, canonical, role)
        return None
    if canonical == "codecs.decode":
        if len(node.args) != 2 or node.keywords:
            if _control_has_static_controls(node, canonical):
                raise ValidationError()
            return None
        encoding = node.args[1]
        if not isinstance(encoding, ast.Constant) or type(encoding.value) is not str:
            raise ValidationError()
        if encoding.value.casefold() not in {"hex", "hex_codec"}:
            raise ValidationError()
        value_hex = _control_static_hex_payload(node.args[0])
        if value_hex is None:
            return ("unknown", "", canonical, role)
        controls = {
            int(value_hex[index:index + 2], 16)
            for index in range(0, len(value_hex), 2)
            if int(value_hex[index:index + 2], 16) < 32
            or int(value_hex[index:index + 2], 16) == 127
        }
        if controls and controls != {10}:
            return ("bytes", value_hex, canonical, role)
        return None
    return None


def _control_policy_path(
    path: Path,
    explicit: str | None,
    *,
    fixtures_root: Path = FIXTURES_ROOT,
) -> str | None:
    # The registry may be validated from an isolated copied repository. The
    # caller's root is the containment boundary; comparing against the module's
    # import-time checkout would reject the same canonical relative artifact.
    try:
        actual = path.resolve().relative_to(fixtures_root.resolve()).as_posix()
    except (OSError, RuntimeError, ValueError):
        actual = None
    if explicit is not None:
        require(actual is not None and explicit == actual, "control policy path is not canonical")
        return explicit
    return actual


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
    allowed_empty_assignment_values: frozenset[str] = frozenset(),
    control_policy_path: str | None = None,
    control_policy_root: Path | None = None,
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
    control_bindings = _control_alias_bindings(tree, _control_parent_map(tree))
    policy_root = FIXTURES_ROOT if control_policy_root is None else control_policy_root
    policy_path = _control_policy_path(path, control_policy_path, fixtures_root=policy_root)
    parents = _control_parent_map(tree)
    literal_occurrences: dict[tuple[str, str, str], int] = {}
    literal_control_records: list[tuple[ast.Constant, str | bytes]] = []
    literal_control_ids: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant):
            continue
        record = _control_literal_record(node, parents, literal_occurrences)
        if record is None:
            continue
        kind, value_hex, role, ordinal = record
        row = (policy_path or "", kind, value_hex, role, ordinal)
        require(row in _PYTHON_CONTROL_LITERAL_ROWS, "unreviewed Python control literal")
        literal_control_records.append((node, node.value))
        literal_control_ids.add(id(node))

    dynamic_control_occurrences: dict[tuple[str, str, str], int] = {}
    dynamic_control_records: list[tuple[ast.Call, str, str]] = []
    dynamic_control_ids: set[int] = set()
    for node in ast.walk(tree):
        construction = _control_dynamic_constructor(node, parents, control_bindings)
        if construction is None:
            continue
        kind, value_hex, constructor, role = construction
        if kind == "unknown":
            key = (kind, constructor, role)
            ordinal = dynamic_control_occurrences.get(key, 0)
            dynamic_control_occurrences[key] = ordinal + 1
        else:
            key = (kind, value_hex, role)
            ordinal = literal_occurrences.get(key, 0)
            literal_occurrences[key] = ordinal + 1
        row = (policy_path or "", kind, value_hex, constructor, role, ordinal)
        require(row in _PYTHON_CONTROL_CONSTRUCTION_ROWS, "unreviewed Python control construction")
        if kind != "unknown":
            dynamic_control_records.append((node, kind, value_hex))
            dynamic_control_ids.add(id(node))

    control_expression_ids: set[int] = set()
    nodes_by_id = {id(node): node for node in ast.walk(tree)}
    for control_id in literal_control_ids | dynamic_control_ids:
        current = nodes_by_id[control_id]
        while id(current) in parents:
            parent, _field, _index = parents[id(current)]
            if isinstance(parent, (ast.BinOp, ast.JoinedStr, ast.Call)):
                control_expression_ids.add(id(parent))
            current = parent

    regex_calls = _regex_compile_call_nodes(tree)
    regex_call_ids = {id(node) for node in regex_calls}
    regex_nodes = _regex_call_nodes(tree)
    regex_sources = _regex_static_source_bindings(tree)
    resolved_regex_patterns: dict[int, str] = {}
    resolved_regex_literal_ids: set[int] = set()
    for call in regex_calls:
        resolved = _resolve_regex_pattern(call, bindings)
        if resolved is _STATIC_UNKNOWN:
            # Runtime-built patterns are not executed. Their literal
            # descendants remain in the ordinary AST walk below, where each is
            # scanned as regex syntax; only a fully static pattern is collapsed
            # into one authoritative scan.
            continue
        resolved_regex_patterns[id(call)] = resolved
        pattern_node = _regex_pattern_node(call)
        resolved_regex_literal_ids.update(_regex_pattern_constant_nodes(pattern_node, regex_sources))

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
            allowed_empty_assignment_values=allowed_empty_assignment_values,
        )

    for node, value in literal_control_records:
        projected = _control_free_projection(value)
        if projected is None:
            continue
        scan(projected)
        _validate_regex_literal(
            projected,
            allow_synthetic_markers=allow_synthetic_markers,
            allowed_assignment_values=allowed_assignment_values,
            allowed_synthetic_full_values=allowed_synthetic_full_values,
            allowed_structural_urls=allowed_structural_urls,
        )
    for _node, kind, value_hex in dynamic_control_records:
        projected = _control_projection_from_hex(kind, value_hex)
        if projected is None:
            continue
        scan(projected)
        _validate_regex_literal(
            projected,
            allow_synthetic_markers=allow_synthetic_markers,
            allowed_assignment_values=allowed_assignment_values,
            allowed_synthetic_full_values=allowed_synthetic_full_values,
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
        node_id = id(node)
        if node_id in literal_control_ids or node_id in dynamic_control_ids:
            continue
        if node_id in resolved_regex_patterns:
            # Regex syntax needs the full statically resolved pattern. A literal
            # or concatenated fragment alone cannot prove the authority policy.
            scan(resolved_regex_patterns[node_id], regex_pattern=True)
            continue
        if node_id in regex_nodes:
            # Unknown runtime-built compiler calls still expose any literal
            # fragments to the regex-aware scanner. Fully resolved calls skip
            # only the exact source constants already covered above.
            if node_id in resolved_regex_literal_ids:
                continue
            if isinstance(node, ast.Constant):
                value = _static_scalar(node.value)
                if type(value) is str:
                    scan(value, regex_pattern=True)
            elif isinstance(node, (ast.JoinedStr, ast.BinOp, ast.Call)):
                rendered = _conservative_text(node, bindings)
                if node_id in control_expression_ids:
                    projected = _control_free_projection(rendered)
                    if projected is None:
                        continue
                    rendered = projected
                scan(rendered, regex_pattern=True)
            continue
        if node_id in control_expression_ids:
            projected = _control_free_projection(_conservative_text(node, bindings))
            if projected is not None:
                scan(projected)
            continue
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            relation = parents.get(node_id)
            if relation is not None and isinstance(relation[0], ast.BinOp) and isinstance(relation[0].op, ast.Add):
                # Scan the complete outer construction. The inner ``token=``
                # fragment is not a credential value until its suffix arrives;
                # standalone ``token=`` literals still reach the strict scanner.
                continue
        if isinstance(node, ast.Constant):
            if node_id in resolved_regex_literal_ids:
                continue
            value = _static_scalar(node.value)
            if type(value) is str:
                scan(value)
                _validate_regex_literal(
                    value,
                    allow_synthetic_markers=allow_synthetic_markers,
                    allowed_assignment_values=allowed_assignment_values,
                    allowed_synthetic_full_values=allowed_synthetic_full_values,
                    allowed_structural_urls=allowed_structural_urls,
                )
        elif isinstance(node, (ast.JoinedStr, ast.BinOp, ast.Call)):
            scan(_conservative_text(node, bindings))

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
    require(parts and all(part not in {"", ".", ".."} for part in parts), "stable file path is invalid")
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
        require(stat.S_ISREG(before.st_mode), "stable artifact is not a regular file")
        require(0 <= before.st_size <= limit, "stable artifact exceeds the byte limit")
        data = bytearray()
        while len(data) < limit + 1:
            chunk = os.read(file_descriptor, min(64 * 1024, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        require(len(data) <= limit, "stable artifact exceeds the byte limit")
        after = os.fstat(file_descriptor)
        require(
            (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            "stable artifact changed during capture",
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


def _validate_digest(value: Any) -> str:
    require(type(value) is str and HEX64.fullmatch(value) is not None, "artifact digest is invalid")
    return value


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
    require(suffix in SCANNED_ARTIFACT_SUFFIXES, "registered artifact extension is unsupported")
    allowed_assignment_values = EXACT_ASSIGNMENT_ALLOWANCES.get(relative_path, frozenset())
    allowed_synthetic_full_values = SYNTHETIC_FULL_VALUE_ALLOWANCES.get(relative_path, frozenset())
    allowed_structural_urls = STRUCTURAL_URL_ALLOWANCES.get(relative_path, frozenset())
    allowed_empty_assignment_lines = EXACT_EMPTY_ASSIGNMENT_LINES.get(relative_path, frozenset())
    allowed_empty_assignment_values = EXACT_EMPTY_ASSIGNMENT_VALUES.get(relative_path, frozenset())
    if suffix == ".json":
        document = _parse_json_bytes(data, require_object=False, reject_nul=False)
        _validate_redaction_tree(
            document,
            allowed_assignment_values=allowed_assignment_values,
            allowed_structural_urls=allowed_structural_urls,
            allowed_empty_assignment_values=allowed_empty_assignment_values,
            allowed_nul_fields=NUL_FIELD_ALLOWANCES.get(relative_path, {}),
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
            allowed_empty_assignment_values=allowed_empty_assignment_values,
            control_policy_path=relative_path,
            control_policy_root=fixtures_root,
        )
    else:
        _validate_text_file(
            actual,
            data=data,
            allowed_assignment_values=allowed_assignment_values,
            allowed_structural_urls=allowed_structural_urls,
            allowed_empty_assignment_lines=allowed_empty_assignment_lines,
            allowed_empty_assignment_values=allowed_empty_assignment_values,
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


def _validate_fixture_roots(
    document: dict[str, Any],
    state_ids: tuple[str, ...],
    coverage_ids: set[str],
    fixtures_root: Path,
    traversal_budget: _FixtureTraversalBudget,
) -> tuple[dict[str, str], set[str]]:
    roots = document["fixture_roots"]
    require(type(roots) is list and bool(roots), "fixture roots are missing")
    seen_ids: dict[str, str] = {}
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
        _validate_string_list(item["platforms"], PLATFORMS)
        states = _validate_string_list(item["states"], state_ids)
        require(tuple(sorted(states)) == states, "fixture states must be sorted")
        fixture_coverage = _validate_string_list(item["coverage_ids"], coverage_ids)
        require(tuple(sorted(fixture_coverage)) == fixture_coverage, "fixture coverage ids must be sorted")
        validator = item["validator"]
        if validator is not None:
            _safe_relative_path(validator)
        files = item["files"]
        require(type(files) is list, "fixture files must be a list")
        if item["status"] == "pending":
            require(validator is None and files == [], "pending fixture must not claim artifacts")
            continue
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
            require(validator in {file.removeprefix(path + "/") for file in actual_files}, "fixture validator is not listed")
        for file_index, file_record in enumerate(files):
            _validate_manifest_file(file_record, fixtures_root=fixtures_root, fixture_relative_root=path, total_bytes=total_bytes)
    require(len(seen_ids) == len(roots), "fixture id inventory is inconsistent")
    return seen_ids, owned_files


def _validate_coverage(
    document: dict[str, Any],
    fixture_statuses: dict[str, str],
    state_ids: tuple[str, ...],
) -> tuple[set[str], set[str]]:
    coverage = document["coverage"]
    require(type(coverage) is list and bool(coverage), "coverage inventory is missing")
    seen: set[str] = set()
    previous = ""
    fixture_to_coverage: set[str] = set()
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
        require(type(item["notes"]) is str and 0 < len(item["notes"]) <= 512, "coverage note is invalid")
        _validate_text_value(item["notes"])
        if status == "ready":
            require(bool(references), "ready coverage must cite a fixture")
            require(
                all(fixture_statuses.get(reference) == "ready" for reference in references),
                "ready coverage cites a pending or missing fixture",
            )
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
    fixture_statuses, owned_files = _validate_fixture_roots(
        document,
        state_ids,
        set(item["id"] for item in document["coverage"]),
        fixtures_root,
        traversal_budget,
    )
    coverage_ids, referenced_fixtures = _validate_coverage(document, fixture_statuses, state_ids)
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
) -> None:
    canonical = (canonical_baseline_path or (repo_root / "contracts/fixtures/validator/validation-baseline.json")).resolve()
    require(baseline_path.resolve() == canonical, "baseline path is not canonical")
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
        data = _stable_file_bytes(repo_root.resolve(), path, MAX_ARTIFACT_BYTES)
        require(size == len(data) and digest == hashlib.sha256(data).hexdigest(), "baseline artifact manifest is stale")
        total += len(data)
    require(type(document["artifact_size_bytes"]) is int and type(document["artifact_size_bytes"]) is not bool and document["artifact_size_bytes"] == total, "baseline artifact size is stale")
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
) -> None:
    """Validate observed benchmark evidence without inventing a threshold."""
    root = repo_root.resolve()
    _validate_baseline(
        baseline,
        root,
        baseline_path.resolve(),
        canonical_baseline_path=(root / "contracts/fixtures/validator/validation-baseline.json"),
    )


def validate_all(
    index: dict[str, Any],
    schema: dict[str, Any],
    baseline: dict[str, Any],
    *,
    repo_root: Path = REPO_ROOT,
    baseline_path: Path = BASELINE_PATH,
) -> tuple[int, int]:
    root = repo_root.resolve()
    # ``validate_all`` is a public API used by tests and tooling as well as the
    # CLI. Do not let a caller mutate a previously parsed index or schema and
    # bypass the canonical checkout binding that protects the on-disk paths.
    canonical_index = _parse_json_bytes(
        _stable_file_bytes(root, "contracts/fixtures/index.json", MAX_JSON_BYTES),
    )
    canonical_schema = _parse_json_bytes(
        _stable_file_bytes(root, "contracts/fixtures/schema.json", MAX_JSON_BYTES),
    )
    require(index == canonical_index, "index object is not canonical")
    require(schema == canonical_schema, "schema object is not canonical")
    _validate_schema_document(schema)
    counts = _validate_index_document(index, root)
    canonical_baseline_path = _indexed_baseline_path(index, root)
    canonical_baseline = _parse_json_bytes(
        _stable_file_bytes(
            root,
            canonical_baseline_path.relative_to(root).as_posix(),
            MAX_JSON_BYTES,
        ),
    )
    require(baseline == canonical_baseline, "baseline object is not canonical")
    _validate_baseline(
        baseline,
        root,
        baseline_path.resolve(),
        canonical_baseline_path=canonical_baseline_path,
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
    try:
        args = parser.parse_args(argv)
        repo_root = args.repo_root.resolve()
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
