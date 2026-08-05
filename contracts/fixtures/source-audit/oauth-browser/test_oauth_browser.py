#!/usr/bin/env python3
"""Offline regression tests for the pinned browser OAuth contract.

The test data is synthetic and records source observations at the pinned
Hermes revision. It deliberately does not import Hermes or contact a provider;
source-compatible behavior is validated from the reviewed, commit-pinned audit
record and deterministic callback cases.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
import time
import unittest
from pathlib import Path
from typing import Any


FIXTURE_DIR = Path(__file__).resolve().parent
REPOSITORY_ROOT = FIXTURE_DIR.parents[3]
DOC_PATH = REPOSITORY_ROOT / "docs/security/authentication.md"
SOURCE_AUDIT_PATH = FIXTURE_DIR / "source_audit.json"
CASES_PATH = FIXTURE_DIR / "cases.json"
PINNED_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
REQUIRED_CASES = {
    "success",
    "state-mismatch",
    "missing-state",
    "pkce-failure",
    "cancellation",
    "malformed-callback",
}


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise TypeError(f"fixture root must be an object: {path}")
    return value


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def fixture_artifact_bytes() -> int:
    return sum(path.stat().st_size for path in (SOURCE_AUDIT_PATH, CASES_PATH))


class BrowserOAuthContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.audit = load_json(SOURCE_AUDIT_PATH)
        cls.cases = load_json(CASES_PATH)
        cls.documentation = DOC_PATH.read_text(encoding="utf-8")

    def test_source_pin_and_audit_shape(self) -> None:
        self.assertEqual(self.audit["contract"], "dashboard-v0.0.1")
        self.assertEqual(self.audit["source"]["repository"], "NousResearch/hermes-agent")
        self.assertEqual(self.audit["source"]["sha"], PINNED_SHA)
        self.assertEqual(self.cases["source_sha"], PINNED_SHA)
        self.assertTrue(self.audit["synthetic_only"])
        self.assertFalse(self.audit["network_access"])
        self.assertFalse(self.audit["apple_behavior"])
        self.assertFalse(self.audit["superdesign_output"])

        paths = {ref["path"] for ref in self.audit["source"]["refs"]}
        self.assertEqual(
            paths,
            {
                "hermes_cli/dashboard_auth/routes.py",
                "plugins/dashboard_auth/nous/__init__.py",
                "hermes_cli/dashboard_auth/cookies.py",
            },
        )

    def test_state_pkce_and_nonce_requirements_match_source(self) -> None:
        requirements = self.audit["requirements"]
        self.assertTrue(requirements["state"]["required"])
        self.assertTrue(requirements["pkce"]["required"])
        self.assertEqual(requirements["pkce"]["method"], "S256")
        self.assertFalse(requirements["nonce"]["required"])
        self.assertFalse(requirements["nonce"]["exposed_by_pinned_browser_flow"])

        # The regression is specifically against adding a nonce requirement to
        # a flow whose reviewed source exposes state and PKCE only.
        self.assertIn("no separate nonce", requirements["nonce"]["reason"])

    def test_required_cases_are_present_once(self) -> None:
        cases = self.cases["cases"]
        ids = [case["id"] for case in cases]
        self.assertEqual(set(ids), REQUIRED_CASES)
        self.assertEqual(len(ids), len(set(ids)))

    def test_pkce_challenge_and_state_inputs_are_deterministic(self) -> None:
        for case in self.cases["cases"]:
            request = case["request"]
            cookie = request["pkce_cookie"]
            authorization = request["authorization_request"]
            callback = request["callback"]

            self.assertEqual(authorization["code_challenge_method"], "S256")
            self.assertEqual(
                pkce_challenge(cookie["verifier"]),
                authorization["code_challenge"],
                case["id"],
            )
            self.assertNotIn("nonce", request)
            self.assertNotIn("nonce", callback)
            self.assertFalse(case["expected"]["separate_nonce_required"])

    def test_success_requires_matching_state_and_issues_session(self) -> None:
        case = self._case("success")
        request = case["request"]
        self.assertEqual(
            request["pkce_cookie"]["state"], request["callback"]["state"]
        )
        self.assertTrue(case["provider_exchange"]["called"])
        self.assertEqual(case["provider_exchange"]["verifier_result"], "accepted")
        self.assertEqual(case["expected"]["status"], 302)
        self.assertTrue(case["expected"]["session_cookie_issued"])
        self.assertEqual(case["expected"]["pkce_cookie"], "cleared")

    def test_state_failures_happen_before_provider_exchange(self) -> None:
        for case_id in ("state-mismatch", "missing-state"):
            case = self._case(case_id)
            request = case["request"]
            self.assertNotEqual(
                request["pkce_cookie"]["state"], request["callback"]["state"]
            )
            self.assertFalse(case["provider_exchange"]["called"], case_id)
            self.assertEqual(case["expected"]["status"], 400)
            self.assertFalse(case["expected"]["session_cookie_issued"])
            self.assertEqual(case["expected"]["reason"], "state_mismatch")

    def test_cancellation_and_malformed_callbacks_fail_closed(self) -> None:
        cancellation = self._case("cancellation")
        self.assertEqual(cancellation["request"]["callback"]["error"], "access_denied")
        self.assertFalse(cancellation["provider_exchange"]["called"])
        self.assertEqual(cancellation["expected"]["reason"], "idp_error")
        self.assertFalse(cancellation["expected"]["session_cookie_issued"])

        malformed = self._case("malformed-callback")
        self.assertEqual(malformed["request"]["callback"]["code"], "")
        self.assertTrue(malformed["provider_exchange"]["called"])
        self.assertEqual(
            malformed["provider_exchange"]["verifier_result"],
            "rejected_empty_code",
        )
        self.assertEqual(malformed["expected"]["status"], 400)
        self.assertFalse(malformed["expected"]["session_cookie_issued"])

    def test_pkce_failure_does_not_create_a_session(self) -> None:
        case = self._case("pkce-failure")
        self.assertTrue(case["provider_exchange"]["called"])
        self.assertEqual(case["provider_exchange"]["verifier_result"], "rejected")
        self.assertEqual(case["expected"]["reason"], "invalid_code_or_pkce")
        self.assertEqual(case["expected"]["status"], 400)
        self.assertFalse(case["expected"]["session_cookie_issued"])

    def test_documentation_does_not_reintroduce_nonce_requirement(self) -> None:
        documentation = self.documentation
        self.assertIn("state against the server-managed PKCE state", documentation)
        self.assertIn("validate the PKCE verifier", documentation)
        self.assertIn("No separate browser `nonce` is exposed or required", documentation)
        self.assertIn("MUST NOT add nonce validation", documentation)
        self.assertNotIn("validate the authentication state and nonce", documentation)
        self.assertNotIn("browser OAuth or OIDC state, nonce", documentation)

        # Allow explanatory negative language, but reject a new positive
        # requirement such as "must validate nonce" or "require a nonce".
        positive_nonce_requirement = re.compile(
            r"(?i)\b(?:must|should)\s+(?!not\b)(?:validate|require|include|accept)\b[^\n.]{0,80}\bnonce\b"
        )
        self.assertIsNone(positive_nonce_requirement.search(documentation))

    def test_fixture_values_are_synthetic_and_non_networked(self) -> None:
        serialized = json.dumps(self.cases, sort_keys=True).lower()
        self.assertNotIn("http://", serialized)
        self.assertNotIn("https://", serialized)
        self.assertNotIn("@", serialized)
        self.assertNotIn("access_token", serialized)
        self.assertNotIn("refresh_token", serialized)
        self.assertNotIn("cookie_value", serialized)
        allowed_protocol_values = {"", "access_denied"}
        for case in self.cases["cases"]:
            for value in case["request"]["callback"].values():
                self.assertTrue(
                    value in allowed_protocol_values
                    or str(value).startswith("fixture-")
                )

    def _case(self, case_id: str) -> dict[str, Any]:
        for case in self.cases["cases"]:
            if case["id"] == case_id:
                return case
        self.fail(f"missing case: {case_id}")


def run() -> int:
    started = time.perf_counter()
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    elapsed_ms = (time.perf_counter() - started) * 1000
    print(f"fixture_validation_ms={elapsed_ms:.3f}")
    print(f"fixture_artifact_bytes={fixture_artifact_bytes()}")
    print("fixture_artifact_files=source_audit.json,cases.json")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(run())
