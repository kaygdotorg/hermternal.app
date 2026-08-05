#!/usr/bin/env python3
"""Offline validation for the pinned active-model options fixtures.

The validator intentionally reads only committed JSON. It does not import
Hermes, open a socket, fetch a catalog, or infer a provider list. That keeps
source-audit evidence reproducible while making an absent or changed operation
fail closed.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
import re
import time
import unittest
from typing import Any
from urllib.parse import urlsplit


PINNED_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
EXPECTED_OPERATION = "model.options"
EXPECTED_REPOSITORY = "NousResearch/hermes-agent"
EXPECTED_REPOSITORY_URL = "https://github.com/NousResearch/hermes-agent"
EXPECTED_SOURCE_BLOB_SHA = "701c11f0eaed4d09b045c7046db3aa8443332db4"
EXPECTED_PAYLOAD_BUILDER_BLOB_SHA = "4e95665d481f881be9885edd4997925d0cec78d6"
EXPECTED_REQUEST_PARAMETERS = (
    "session_id",
    "explicit_only",
    "include_unconfigured",
    "refresh",
)
EXPECTED_REQUEST_KEYS_BY_CASE = {
    "present": ("session_id", "explicit_only", "include_unconfigured", "refresh"),
    "absent": (),
    "empty": ("explicit_only",),
    "malformed": (),
    "unknown-operation": (),
}
EXPECTED_FIXTURE_SURFACE = {
    "transport": "json-rpc",
    "operation": "model.options",
    "source_path": "tui_gateway/methods_complete.py",
    "source_lines": [327, 347],
    "source_blob_sha": EXPECTED_SOURCE_BLOB_SHA,
    "handler_calls": "hermes_cli.inventory.build_model_options_payload",
    "request_parameters": list(EXPECTED_REQUEST_PARAMETERS),
    "response_shape_source_path": "hermes_cli/inventory.py",
    "response_shape_source_lines": [276, 280],
    "payload_builder_path": "hermes_cli/inventory.py",
    "payload_builder_lines": [283, 313],
    "payload_builder_blob_sha": EXPECTED_PAYLOAD_BUILDER_BLOB_SHA,
    "required_result_keys": ["providers", "model", "provider"],
    "provider_rows": "source-defined; fixture rows are synthetic only",
}
EXPECTED_REST_EQUIVALENT = {
    "method": "GET",
    "path": "/api/model/options",
    "source_path": "hermes_cli/web_server.py",
    "source_lines": [6238, 6280],
    "source_blob_sha": "1fb3e6131629e7399ef12de78148ac6e7ec58d34",
    "uses_same_builder": True,
    "included_in_fixture_surface": False,
}
EXPECTED_REGISTRY_EVIDENCE = {
    "source_path": "tui_gateway/server.py",
    "source_lines": [223, 228],
    "source_blob_sha": "9d5fd00ce7d0becfd4581a5a3867c516a6d3b20a",
    "operation_is_routed_off_reader_thread": True,
}
EXPECTED_NEGATIVE_CONTROLS = {
    "absent": "synthetic replacement-gateway control only; it does not describe the pinned source",
    "empty": "valid source operation with no available provider rows",
    "malformed": "synthetic invalid result shape",
    "unknown_operation": "synthetic method-not-found control",
}
EXPECTED_SOURCE_LINKS = (
    f"{EXPECTED_REPOSITORY_URL}/blob/{PINNED_SHA}/tui_gateway/methods_complete.py",
    f"{EXPECTED_REPOSITORY_URL}/blob/{PINNED_SHA}/hermes_cli/inventory.py",
    f"{EXPECTED_REPOSITORY_URL}/blob/{PINNED_SHA}/hermes_cli/web_server.py",
    f"{EXPECTED_REPOSITORY_URL}/blob/{PINNED_SHA}/tui_gateway/server.py",
)
EXPECTED_CASES = set(EXPECTED_REQUEST_KEYS_BY_CASE)
ALLOWED_METADATA_KEYS = {"authenticated", "auth_type"}
FORBIDDEN_SENSITIVE_KEYS = {
    "accesskey",
    "apikey",
    "auth",
    "authentication",
    "authheader",
    "authtoken",
    "authorization",
    "clientsecret",
    "cookie",
    "cookies",
    "credential",
    "credentials",
    "hostname",
    "idtoken",
    "password",
    "privatekey",
    "providerdata",
    "refreshtoken",
    "secret",
    "secrets",
    "ticket",
    "tickets",
    "token",
    "tokens",
    "transcript",
    "transcripts",
    "userdata",
}
FORBIDDEN_SENSITIVE_KEY_COMPONENTS = {
    "authorization",
    "credential",
    "credentials",
    "cookie",
    "cookies",
    "hostname",
    "password",
    "private",
    "secret",
    "secrets",
    "ticket",
    "tickets",
    "token",
    "tokens",
    "transcript",
    "transcripts",
}
FORBIDDEN_SENSITIVE_KEY_COMPOUNDS = (
    ("access", "key"),
    ("api", "key"),
    ("auth", "credential"),
    ("auth", "key"),
    ("auth", "token"),
)
FORBIDDEN_VALUE_COMPONENTS = {
    "access",
    "apikey",
    "authorization",
    "auth",
    "authentication",
    "cookie",
    "cookies",
    "credential",
    "credentials",
    "hostname",
    "password",
    "providerdata",
    "secret",
    "secrets",
    "ticket",
    "tickets",
    "token",
    "tokens",
    "transcript",
    "transcripts",
    "userdata",
}
FORBIDDEN_VALUE_COMPOUNDS = (
    ("access", "key"),
    ("access", "token"),
    ("api", "key"),
    ("auth", "credential"),
    ("auth", "key"),
    ("auth", "token"),
)
FORBIDDEN_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b", re.IGNORECASE),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]+\b", re.IGNORECASE),
    re.compile(r"\bBearer\s+\S+", re.IGNORECASE),
    re.compile(r"\bBasic\s+\S+", re.IGNORECASE),
    re.compile(r"\b(?:sk-[A-Za-z0-9_-]+|ghp_[A-Za-z0-9_]+|xoxb-[A-Za-z0-9-]+|eyJ[A-Za-z0-9_-]{8,})\b", re.IGNORECASE),
)
FIXTURE_DIR = Path(__file__).resolve().parent
AUDIT_PATH = FIXTURE_DIR.parents[2] / "hermes-dashboard" / "model-options" / "source-audit.json"


class ContractError(ValueError):
    """Raised when a fixture claims more than the pinned source proves."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _strict_equal(actual: Any, expected: Any) -> bool:
    """Compare JSON-shaped values without Python bool/int coercion."""

    if type(actual) is not type(expected):
        return False
    if isinstance(actual, dict):
        if set(actual) != set(expected):
            return False
        return all(_strict_equal(actual[key], expected[key]) for key in expected)
    if isinstance(actual, list):
        return len(actual) == len(expected) and all(
            _strict_equal(actual_item, expected_item)
            for actual_item, expected_item in zip(actual, expected)
        )
    return actual == expected


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    _require(isinstance(value, dict), f"{path.name}: top level must be an object")
    return value


def validate_audit(audit: dict[str, Any]) -> None:
    """Validate immutable source evidence and the exact request contract."""

    _require(audit["contract"] == "dashboard-v0.0.1", "audit: wrong contract")
    _require(audit["hermes_repository"] == EXPECTED_REPOSITORY, "audit: wrong repository")
    _require(
        audit["hermes_repository_url"] == EXPECTED_REPOSITORY_URL,
        "audit: wrong repository URL",
    )
    _require(audit["hermes_source_sha"] == PINNED_SHA, "audit: SHA is not pinned")
    _require(audit["operation_present"] is True, "audit: model.options is not proven")
    _require(audit["conclusion"] == "present", "audit: conclusion is not present")

    surface = audit.get("fixture_surface")
    _require(isinstance(surface, dict), "audit: fixture surface must be an object")
    _require(
        _strict_equal(surface, EXPECTED_FIXTURE_SURFACE),
        "audit: complete fixture surface provenance changed",
    )

    _require(
        _strict_equal(audit["rest_equivalent"], EXPECTED_REST_EQUIVALENT),
        "audit: REST provenance changed",
    )
    _require(
        _strict_equal(audit["registry_evidence"], EXPECTED_REGISTRY_EVIDENCE),
        "audit: registry provenance changed",
    )
    _require(
        _strict_equal(audit["negative_controls"], EXPECTED_NEGATIVE_CONTROLS),
        "audit: negative controls changed",
    )

    source_links = audit.get("source_links")
    _require(
        _strict_equal(source_links, list(EXPECTED_SOURCE_LINKS)),
        "audit: source links changed",
    )
    _require(len(source_links) == len(set(source_links)), "audit: source links are not unique")
    for link in source_links:
        parsed = urlsplit(link)
        _require(parsed.scheme == "https", "audit: source link must use HTTPS")
        _require(parsed.netloc == "github.com", "audit: source link has an unexpected host")
        _require(not parsed.query and not parsed.fragment, "audit: source link has query or fragment")
        _require(
            link.startswith(f"{EXPECTED_REPOSITORY_URL}/blob/{PINNED_SHA}/"),
            "audit: source link is not an expected pinned path",
        )


def load_audit() -> dict[str, Any]:
    audit = load_json(AUDIT_PATH)
    validate_audit(audit)
    return audit


def _normalize_marker(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _key_tokens(value: str) -> tuple[str, ...]:
    return tuple(
        token.casefold()
        for token in re.findall(r"[A-Z]+(?=[A-Z][a-z]|$)|[A-Z]?[a-z]+|\d+", value)
    )


def _contains_compound(tokens: tuple[str, ...], compounds: tuple[tuple[str, ...], ...]) -> bool:
    return any(
        any(tokens[index : index + len(compound)] == compound for index in range(len(tokens)))
        for compound in compounds
    )


def _is_forbidden_sensitive_key(key: str) -> bool:
    if key.casefold() in ALLOWED_METADATA_KEYS:
        return False
    normalized_key = _normalize_marker(key)
    if normalized_key in FORBIDDEN_SENSITIVE_KEYS:
        return True
    tokens = _key_tokens(key)
    return bool(set(tokens) & FORBIDDEN_SENSITIVE_KEY_COMPONENTS) or _contains_compound(
        tokens,
        FORBIDDEN_SENSITIVE_KEY_COMPOUNDS,
    )


def _is_forbidden_sensitive_value(value: str) -> bool:
    tokens = _key_tokens(value)
    return bool(set(tokens) & FORBIDDEN_VALUE_COMPONENTS) or _contains_compound(
        tokens,
        FORBIDDEN_VALUE_COMPOUNDS,
    )


def _validate_redaction(value: Any, path: str = "fixture") -> None:
    """Reject explicit sensitive keys and representative credential material.

    The policy is intentionally explicit rather than a broad substring search:
    source metadata such as ``authenticated`` and ``auth_type`` is legitimate,
    while credential-bearing keys and recognizable PEM, AWS, GitHub, bearer, or
    basic-auth material fail closed.
    """

    if isinstance(value, dict):
        for key, child in value.items():
            _require(isinstance(key, str), f"{path}: object keys must be strings")
            _require(
                not _is_forbidden_sensitive_key(key),
                f"{path}.{key}: prohibited sensitive key marker",
            )
            _validate_redaction(child, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _validate_redaction(child, f"{path}[{index}]")
        return
    if isinstance(value, str):
        _require(
            not _is_forbidden_sensitive_value(value),
            f"{path}: prohibited sensitive value marker",
        )
        for pattern in FORBIDDEN_VALUE_PATTERNS:
            _require(
                pattern.search(value) is None,
                f"{path}: prohibited credential material",
            )


def _result_is_valid(result: Any) -> bool:
    if not isinstance(result, dict):
        return False
    if not isinstance(result.get("providers"), list):
        return False
    if not isinstance(result.get("model"), str):
        return False
    if not isinstance(result.get("provider"), str):
        return False
    for row in result["providers"]:
        if not isinstance(row, dict):
            return False
        if not isinstance(row.get("name"), str) or not isinstance(row.get("slug"), str):
            return False
        if not isinstance(row.get("models"), list):
            return False
        if not all(isinstance(model, str) for model in row["models"]):
            return False
        if "total_models" in row and type(row["total_models"]) is not int:
            return False
    return True


def validate_fixture(fixture: dict[str, Any], audit: dict[str, Any]) -> None:
    """Validate one fixture against the source audit without network access."""

    # Callers cannot smuggle an unverified SHA, repository, operation, or source
    # record through this helper; every direct audit argument must pass the same
    # immutable checks used when loading the committed audit file.
    validate_audit(audit)
    _require(fixture.get("contract") == "dashboard-v0.0.1", "fixture: wrong contract")
    _require(fixture.get("hermes_source_sha") == PINNED_SHA, "fixture: wrong SHA")
    _require(fixture.get("source_audit_id") == audit["audit_id"], "fixture: wrong audit id")
    _require(fixture.get("client_scope") == "shared", "fixture: wrong client scope")
    _require(fixture.get("synthetic") is True, "fixture: data is not marked synthetic")

    case = fixture.get("case")
    _require(case in EXPECTED_CASES, f"fixture: unknown case {case!r}")
    request = fixture.get("request")
    response = fixture.get("response")
    expected = fixture.get("expected")
    _require(isinstance(request, dict), f"{case}: request must be an object")
    _require(isinstance(response, dict), f"{case}: response must be an object")
    _require(isinstance(expected, dict), f"{case}: expected must be an object")
    _require(request.get("jsonrpc") == "2.0", f"{case}: request is not JSON-RPC 2.0")
    _require(response.get("jsonrpc") == "2.0", f"{case}: response is not JSON-RPC 2.0")
    _require(request.get("id") == response.get("id"), f"{case}: response id mismatch")
    _require(expected.get("classification") == case, f"{case}: wrong classification")
    _validate_redaction(fixture)

    params = request.get("params")
    _require(isinstance(params, dict), f"{case}: params must be an object")
    allowed_parameters = set(audit["fixture_surface"]["request_parameters"])
    parameter_keys = set(params)
    _require(
        parameter_keys <= allowed_parameters,
        f"{case}: request contains invented model.options parameters",
    )
    expected_parameter_keys = expected.get("request_parameter_keys")
    _require(
        isinstance(expected_parameter_keys, list)
        and all(isinstance(key, str) for key in expected_parameter_keys),
        f"{case}: exact request parameter keys are required",
    )
    frozen_parameter_keys = EXPECTED_REQUEST_KEYS_BY_CASE[case]
    _require(
        tuple(expected_parameter_keys) == frozen_parameter_keys,
        f"{case}: fixture metadata changed the frozen request keys",
    )
    _require(
        parameter_keys == set(frozen_parameter_keys),
        f"{case}: request parameter keys do not match the frozen contract",
    )

    operation = audit["fixture_surface"]["operation"]
    request_method = request.get("method")
    _require(isinstance(request_method, str), f"{case}: missing request method")

    # A fixture may use the operation only while the audit proves it. This is
    # the regression guard against silently inventing model.options.
    if case in {"present", "empty"}:
        _require(
            audit.get("operation_present") is True,
            f"{case}: rejected dependency on unproven {operation}",
        )
        _require(request_method == operation, f"{case}: wrong source operation")
        _require(
            fixture.get("source_observation") == "pinned-source-present",
            f"{case}: missing pinned-source observation",
        )
    elif case == "malformed":
        _require(
            audit.get("operation_present") is True,
            "malformed: rejected source operation evidence",
        )
        _require(request_method == operation, "malformed: wrong source operation")
        _require(
            fixture.get("source_observation") == "synthetic-malformed-control",
            "malformed: control must not masquerade as pinned evidence",
        )
    elif case == "absent":
        _require(request_method == operation, "absent: control must name the candidate operation")
        _require(
            fixture.get("source_observation") == "synthetic-absent-control",
            "absent: control must not masquerade as pinned evidence",
        )
    else:
        _require(request_method != operation, "unknown-operation: operation unexpectedly accepted")
        _require(
            fixture.get("source_observation") == "synthetic-unknown-operation-control",
            "unknown-operation: missing negative-control observation",
        )

    if case == "present":
        result = response.get("result")
        _require(_result_is_valid(result), "present: invalid source result shape")
        _require(bool(result["providers"]), "present: provider list must be non-empty")
        _require(bool(result["model"]) and bool(result["provider"]), "present: active choice is empty")
        _require(expected.get("usable") is True, "present: fixture is not usable")
        _require(expected.get("fail_closed") is False, "present: unexpected fail-closed result")
        _require(expected.get("provider_count") == len(result["providers"]), "present: provider count mismatch")
        _require(expected.get("active_model") == result["model"], "present: model mismatch")
        _require(expected.get("active_provider") == result["provider"], "present: provider mismatch")
    elif case == "empty":
        result = response.get("result")
        _require(_result_is_valid(result), "empty: invalid source result shape")
        _require(result["providers"] == [], "empty: provider list is not empty")
        _require(result["model"] == "" and result["provider"] == "", "empty: active choice is not empty")
        _require(expected.get("usable") is False, "empty: empty options became usable")
        _require(expected.get("fail_closed") is True, "empty: no-options state is not fail-closed")
    elif case == "malformed":
        _require(not _result_is_valid(response.get("result")), "malformed: invalid shape was accepted")
        _require(expected.get("usable") is False, "malformed: malformed result became usable")
        _require(expected.get("fail_closed") is True, "malformed: malformed result was not fail-closed")
    else:
        error = response.get("error")
        _require(isinstance(error, dict), f"{case}: missing JSON-RPC error")
        _require(error.get("code") == -32601, f"{case}: wrong method-not-found code")
        _require("result" not in response, f"{case}: error response included a result")
        _require(expected.get("usable") is False, f"{case}: negative control became usable")
        _require(expected.get("fail_closed") is True, f"{case}: negative control was not fail-closed")



def load_fixtures() -> list[dict[str, Any]]:
    paths = sorted(FIXTURE_DIR.glob("*.json"))
    _require(len(paths) == len(EXPECTED_CASES), "fixture set: expected five JSON cases")
    fixtures = [load_json(path) for path in paths]
    _require(
        {fixture.get("case") for fixture in fixtures} == EXPECTED_CASES,
        "fixture set: present/absent/empty/malformed/unknown cases are incomplete",
    )
    return fixtures


class ModelOptionsFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.audit = load_audit()
        cls.fixtures = load_fixtures()
        cls.by_case = {fixture["case"]: fixture for fixture in cls.fixtures}

    def test_source_audit_proves_the_operation(self) -> None:
        self.assertTrue(self.audit["operation_present"])
        self.assertEqual(self.audit["fixture_surface"]["operation"], EXPECTED_OPERATION)
        self.assertEqual(
            self.audit["fixture_surface"]["handler_calls"],
            "hermes_cli.inventory.build_model_options_payload",
        )

    def test_all_fixtures_validate_against_the_pinned_audit(self) -> None:
        for fixture in self.fixtures:
            with self.subTest(case=fixture["case"]):
                validate_fixture(fixture, self.audit)

    def test_empty_is_valid_but_fail_closed(self) -> None:
        empty = self.by_case["empty"]
        self.assertFalse(empty["expected"]["usable"])
        self.assertTrue(empty["expected"]["fail_closed"])

    def test_unknown_operation_cannot_fallback(self) -> None:
        unknown = self.by_case["unknown-operation"]
        self.assertNotEqual(unknown["request"]["method"], EXPECTED_OPERATION)
        self.assertEqual(unknown["response"]["error"]["code"], -32601)
        self.assertNotIn("result", unknown["response"])

    def test_invented_model_options_dependency_is_rejected(self) -> None:
        forged_audit = copy.deepcopy(self.audit)
        forged_audit["operation_present"] = False
        with self.assertRaises(ContractError):
            validate_fixture(self.by_case["present"], forged_audit)

    def test_request_parameter_contract_cannot_be_forged_with_metadata(self) -> None:
        forged_fixture = copy.deepcopy(self.by_case["present"])
        forged_fixture["request"]["params"] = {}
        forged_fixture["expected"]["request_parameter_keys"] = []
        with self.assertRaises(ContractError):
            validate_fixture(forged_fixture, self.audit)

        forged_fixture = copy.deepcopy(self.by_case["present"])
        forged_fixture["request"]["params"]["unexpected"] = False
        forged_fixture["expected"]["request_parameter_keys"] = ["unexpected"]
        with self.assertRaises(ContractError):
            validate_fixture(forged_fixture, self.audit)

    def test_boolean_total_models_is_rejected(self) -> None:
        forged_fixture = copy.deepcopy(self.by_case["present"])
        forged_fixture["response"]["result"]["providers"][0]["total_models"] = True
        with self.assertRaises(ContractError):
            validate_fixture(forged_fixture, self.audit)

    def test_legitimate_auth_metadata_is_allowed(self) -> None:
        forged_fixture = copy.deepcopy(self.by_case["present"])
        result = forged_fixture["response"]["result"]
        result["authenticated"] = True
        result["auth_type"] = "oauth"
        validate_fixture(forged_fixture, self.audit)

    def test_sensitive_keys_and_values_are_rejected(self) -> None:
        validate_fixture(self.by_case["present"], self.audit)

        for key in (
            "token",
            "credential",
            "auth",
            "api_key",
            "provider_api_key",
            "x_authorization_value",
            "api_key_value",
            "cookie",
            "secret",
        ):
            with self.subTest(key=key):
                forged_fixture = copy.deepcopy(self.by_case["present"])
                forged_fixture["response"]["result"][key] = "synthetic-marker"
                with self.assertRaises(ContractError):
                    validate_fixture(forged_fixture, self.audit)

        for value in (
            "-----BEGIN RSA PRIVATE KEY-----\nsynthetic\n-----END RSA PRIVATE KEY-----",
            "AKIAZZZZZZZZZZZZZZZZ",
            "github_pat_synthetic_marker",
            "Bearer synthetic-credential",
            "Basic c3ludGhldGlj",
            "sk-synthetic-marker",
            "synthetic-api-key",
            "my-secret-value",
        ):
            with self.subTest(value=value):
                forged_fixture = copy.deepcopy(self.by_case["present"])
                forged_fixture["request"]["params"]["session_id"] = value
                with self.assertRaises(ContractError):
                    validate_fixture(forged_fixture, self.audit)

    def test_source_blob_hashes_must_match_exact_pinned_values(self) -> None:
        for evidence_key in ("source_blob_sha", "payload_builder_blob_sha"):
            with self.subTest(evidence_key=evidence_key):
                forged_audit = copy.deepcopy(self.audit)
                forged_audit["fixture_surface"][evidence_key] = "0" * 40
                with self.assertRaises(ContractError):
                    validate_audit(forged_audit)

    def test_complete_fixture_surface_is_exactly_bound(self) -> None:
        for field, expected_value in EXPECTED_FIXTURE_SURFACE.items():
            with self.subTest(field=field):
                forged_audit = copy.deepcopy(self.audit)
                if isinstance(expected_value, list):
                    forged_audit["fixture_surface"][field] = [*expected_value, "forged"]
                elif isinstance(expected_value, str):
                    forged_audit["fixture_surface"][field] = f"{expected_value}-forged"
                else:
                    forged_audit["fixture_surface"][field] = None
                with self.assertRaises(ContractError):
                    validate_audit(forged_audit)

    def test_validate_fixture_rejects_unvalidated_audit_arguments(self) -> None:
        mutations = (
            ("source SHA", {"hermes_source_sha": "0" * 40}),
            ("repository", {"hermes_repository": "evil/example"}),
            ("source blob", {"fixture_surface": {"source_blob_sha": "0" * 40}}),
            ("operation", {"fixture_surface": {"operation": "model.options.forged"}}),
        )
        for description, mutation in mutations:
            with self.subTest(description=description):
                forged_audit = copy.deepcopy(self.audit)
                for field, value in mutation.items():
                    if field == "fixture_surface":
                        forged_audit[field].update(value)
                    else:
                        forged_audit[field] = value
                with self.assertRaises(ContractError):
                    validate_fixture(self.by_case["present"], forged_audit)

    def test_all_machine_readable_provenance_is_exactly_bound(self) -> None:
        forged_audit = copy.deepcopy(self.audit)
        forged_audit["hermes_repository"] = "evil/example"
        with self.assertRaises(ContractError):
            validate_audit(forged_audit)

        forged_audit = copy.deepcopy(self.audit)
        forged_audit["hermes_repository_url"] = "https://evil.example/hermes-agent"
        with self.assertRaises(ContractError):
            validate_audit(forged_audit)

        for field in ("rest_equivalent", "registry_evidence"):
            with self.subTest(field=field):
                forged_audit = copy.deepcopy(self.audit)
                forged_audit[field]["source_blob_sha"] = "0" * 40
                with self.assertRaises(ContractError):
                    validate_audit(forged_audit)

        for field, forged_value in (
            ("uses_same_builder", 1),
            ("included_in_fixture_surface", 0),
        ):
            with self.subTest(field=field):
                forged_audit = copy.deepcopy(self.audit)
                forged_audit["rest_equivalent"][field] = forged_value
                with self.assertRaises(ContractError):
                    validate_audit(forged_audit)

        forged_audit = copy.deepcopy(self.audit)
        forged_audit["registry_evidence"]["operation_is_routed_off_reader_thread"] = 1
        with self.assertRaises(ContractError):
            validate_audit(forged_audit)

        for forged_negative_controls in (
            None,
            {**EXPECTED_NEGATIVE_CONTROLS, "absent": "credential-bearing"},
        ):
            with self.subTest(negative_controls=forged_negative_controls):
                forged_audit = copy.deepcopy(self.audit)
                forged_audit["negative_controls"] = forged_negative_controls
                with self.assertRaises(ContractError):
                    validate_audit(forged_audit)

        forged_source_links = (
            [],
            [EXPECTED_SOURCE_LINKS[0]],
            [*EXPECTED_SOURCE_LINKS[:-1], EXPECTED_SOURCE_LINKS[0]],
            [link + "?evil=1" for link in EXPECTED_SOURCE_LINKS],
            [link + "#line=1" for link in EXPECTED_SOURCE_LINKS],
            ["https://evil.example/blob/" + PINNED_SHA + "/tui_gateway/server.py"],
        )
        for source_links in forged_source_links:
            with self.subTest(source_links=source_links):
                forged_audit = copy.deepcopy(self.audit)
                forged_audit["source_links"] = source_links
                with self.assertRaises(ContractError):
                    validate_audit(forged_audit)


def validate_set_for_baseline(audit: dict[str, Any], fixtures: list[dict[str, Any]]) -> float:
    started = time.perf_counter_ns()
    for fixture in fixtures:
        validate_fixture(fixture, audit)
    elapsed_ns = time.perf_counter_ns() - started
    return elapsed_ns / 1_000_000


def artifact_size_bytes() -> int:
    paths = [AUDIT_PATH, *sorted(FIXTURE_DIR.glob("*.json"))]
    return sum(path.stat().st_size for path in paths)


def main() -> int:
    audit = load_audit()
    fixtures = load_fixtures()
    duration_ms = validate_set_for_baseline(audit, fixtures)

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ModelOptionsFixtureTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.wasSuccessful():
        print(f"baseline.fixture_validation_ms={duration_ms:.3f}")
        print(f"baseline.fixture_artifact_bytes={artifact_size_bytes()}")
        print(f"baseline.fixture_count={len(fixtures)}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
