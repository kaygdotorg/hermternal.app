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
import time
import unittest
from typing import Any


PINNED_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
EXPECTED_OPERATION = "model.options"
EXPECTED_CASES = {
    "present",
    "absent",
    "empty",
    "malformed",
    "unknown-operation",
}
SENSITIVE_MARKERS = (
    "password",
    "cookie",
    "secret",
    "access_token",
    "api_key",
    "ticket",
    "transcript",
    "hostname",
)
FIXTURE_DIR = Path(__file__).resolve().parent
AUDIT_PATH = FIXTURE_DIR.parents[2] / "hermes-dashboard" / "model-options" / "source-audit.json"


class ContractError(ValueError):
    """Raised when a fixture claims more than the pinned source proves."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    _require(isinstance(value, dict), f"{path.name}: top level must be an object")
    return value


def load_audit() -> dict[str, Any]:
    audit = load_json(AUDIT_PATH)
    _require(audit["contract"] == "dashboard-v0.0.1", "audit: wrong contract")
    _require(audit["hermes_source_sha"] == PINNED_SHA, "audit: SHA is not pinned")
    _require(audit["operation_present"] is True, "audit: model.options is not proven")
    _require(audit["conclusion"] == "present", "audit: conclusion is not present")

    surface = audit["fixture_surface"]
    _require(surface["transport"] == "json-rpc", "audit: fixtures must use JSON-RPC")
    _require(surface["operation"] == EXPECTED_OPERATION, "audit: wrong operation")
    _require(
        surface["handler_calls"] == "hermes_cli.inventory.build_model_options_payload",
        "audit: fixture source is not the shared payload builder",
    )
    _require(
        surface["required_result_keys"] == ["providers", "model", "provider"],
        "audit: observable result shape changed",
    )
    _require(surface["source_lines"] == [327, 347], "audit: handler evidence moved")
    _require(surface["payload_builder_lines"] == [283, 313], "audit: builder evidence moved")

    for link in audit["source_links"]:
        _require(PINNED_SHA in link, "audit: source link is not pinned")
    for evidence_key in ("source_blob_sha", "payload_builder_blob_sha"):
        _require(
            len(surface[evidence_key]) == 40,
            f"audit: {evidence_key} is not a full blob SHA",
        )
    return audit


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
        if "total_models" in row and not isinstance(row["total_models"], int):
            return False
    return True


def validate_fixture(fixture: dict[str, Any], audit: dict[str, Any]) -> None:
    """Validate one fixture against the source audit without network access."""

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

    encoded = json.dumps(fixture, sort_keys=True).lower()
    for marker in SENSITIVE_MARKERS:
        _require(marker not in encoded, f"{case}: prohibited marker {marker!r} present")


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
