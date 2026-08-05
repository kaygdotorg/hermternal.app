#!/usr/bin/env python3
"""Offline regression tests for the pinned browser OAuth contract.

The test data is synthetic. The source observations are checked against
immutable excerpts from the pinned Hermes revision before the callback cases
are validated, so the suite does not merely compare duplicated JSON metadata.
It deliberately does not import Hermes or contact a provider.
"""

from __future__ import annotations

import base64
import copy
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
SOURCE_EXCERPT_DIR = FIXTURE_DIR / "source_excerpts"
PINNED_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
REQUIRED_CASES = {
    "success",
    "state-mismatch",
    "missing-state",
    "pkce-failure",
    "cancellation",
    "malformed-callback",
}

# These hashes are the lock for the supplied excerpts. A changed excerpt must
# be reviewed against the pinned source before the audit can pass again.
PINNED_EXCERPT_HASHES = {
    "routes": "7a748fc29acee3d055049f0b1a12bba9e7d8aa13bc4852827888a0ebaaa507b4",
    "nous": "7cc9ddc1f29753a15858b1072a814c7472b31b9d48b9344e0a49406c0a4fc01d",
    "cookies": "4061f5e075fee015151a14ab75c7b77661400bb2ec0fa402559c0d49cae36f3e",
}
EXCERPT_FILES = {
    "routes": "routes_auth.py.txt",
    "nous": "nous_provider.py.txt",
    "cookies": "cookies.py.txt",
}

# Each source-audit observation is tied to source markers, including marker
# order where the source establishes a short-circuit or post-exchange action.
SOURCE_EVIDENCE = {
    "hermes_cli/dashboard_auth/routes.py": {
        "password_provider_short_circuits_oauth_start": [
            ("routes", (
                'if getattr(p, "supports_password", False):',
                "return RedirectResponse(url=login_url, status_code=302)",
                "ls = p.start_login(",
            )),
        ],
        "oauth_start_returns_state_and_verifier_cookie_payload": [
            ("routes", ("ls.cookie_payload.get(\"hermes_session_pkce\"", "set_pkce_cookie(")),
            ("nous", ('"hermes_session_pkce": f"state={state};verifier={code_verifier}"',)),
        ],
        "callback_rejects_missing_or_mismatched_state_before_exchange": [
            ("routes", (
                "if not state or state != expected_state:",
                'detail="OAuth state mismatch (CSRF check failed)",',
                "p.complete_login(",
            )),
        ],
        "callback_passes_cookie_verifier_to_complete_login": [
            ("routes", ("p.complete_login(", "code_verifier=verifier,")),
        ],
        "callback_issues_and_clears_session_only_after_exchange": [
            ("routes", ("session = p.complete_login(", "set_session_cookies(", "clear_pkce_cookie(")),
        ],
    },
    "plugins/dashboard_auth/nous/__init__.py": {
        "authorization_params_include_state": [
            ("nous", (
                "params = {",
                '"state": state,',
                'urllib.parse.urlencode(params)',
            )),
        ],
        "authorization_params_include_s256_pkce": [
            ("nous", (
                '"code_challenge": code_challenge,',
                '"code_challenge_method": "S256",',
            )),
        ],
        "authorization_params_exclude_nonce": [
            ("nous", ()),
        ],
        "cookie_payload_contains_state_and_verifier": [
            ("nous", ('"hermes_session_pkce": f"state={state};verifier={code_verifier}"',)),
        ],
        "token_exchange_sends_code_verifier": [
            ("nous", ('"code_verifier": code_verifier,',)),
        ],
    },
    "hermes_cli/dashboard_auth/cookies.py": {
        "pkce_cookie_is_short_lived": [
            ("cookies", ("PKCE_COOKIE = \"hermes_session_pkce\"", "_PKCE_MAX_AGE = 10 * 60")),
        ],
        "pkce_cookie_is_http_only_lax_and_secure_for_https": [
            ("cookies", ('"httponly": True', '"samesite": "lax"', 'attrs["secure"] = True')),
        ],
        "csrf_nonce_label_is_state_not_provider_nonce": [
            ("cookies", ("CSRF nonce", "PKCE_COOKIE")),
        ],
    },
}


def require(condition: bool, message: str) -> None:
    """Raise an assertion that remains active even under ``python -O``."""
    if not condition:
        raise AssertionError(message)


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
    paths = [SOURCE_AUDIT_PATH, CASES_PATH]
    paths.extend(SOURCE_EXCERPT_DIR / filename for filename in EXCERPT_FILES.values())
    return sum(path.stat().st_size for path in paths)


def load_source_excerpts() -> dict[str, str]:
    excerpts: dict[str, str] = {}
    for key, filename in EXCERPT_FILES.items():
        path = SOURCE_EXCERPT_DIR / filename
        text = path.read_text(encoding="utf-8")
        actual_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        require(actual_hash == PINNED_EXCERPT_HASHES[key], f"changed source excerpt: {key}")
        excerpts[key] = text
    return excerpts


def assert_markers_in_order(text: str, markers: tuple[str, ...], label: str) -> None:
    if not markers:
        require("nonce" not in text, f"unexpected nonce marker in {label}")
        return
    cursor = -1
    for marker in markers:
        position = text.find(marker, cursor + 1)
        require(position >= 0, f"missing source marker {marker!r} in {label}")
        cursor = position


def validate_source_observations(
    audit: dict[str, Any], excerpts: dict[str, str]
) -> None:
    refs = {ref["path"]: ref for ref in audit["source"]["refs"]}
    require(set(refs) == set(SOURCE_EVIDENCE), "source reference set changed")

    for path, expected_observations in SOURCE_EVIDENCE.items():
        ref = refs[path]
        observations = ref["observations"]
        require(set(observations) == set(expected_observations), f"observation IDs changed: {path}")
        require(ref["excerpt_sha256"] == PINNED_EXCERPT_HASHES[{
            "hermes_cli/dashboard_auth/routes.py": "routes",
            "plugins/dashboard_auth/nous/__init__.py": "nous",
            "hermes_cli/dashboard_auth/cookies.py": "cookies",
        }[path]], f"excerpt hash metadata changed: {path}")
        for observation, evidence in expected_observations.items():
            require(observations[observation] is True, f"false source observation: {observation}")
            for excerpt_key, markers in evidence:
                assert_markers_in_order(excerpts[excerpt_key], markers, excerpt_key)



def validate_oauth_case(case: dict[str, Any]) -> None:
    request = case["request"]
    cookie = request["pkce_cookie"]
    authorization = request["authorization_request"]
    params = authorization["params"]
    callback = request["callback"]
    exchange = case["provider_exchange"]

    require(set(authorization) == {"params"}, f"authorization shape changed: {case['id']}")
    require("nonce" not in params, f"pinned Nous flow unexpectedly gained nonce: {case['id']}")
    require(params["state"] == cookie["state"], f"outbound state mismatch: {case['id']}")
    require(params["code_challenge_method"] == "S256", f"PKCE method changed: {case['id']}")
    require(
        pkce_challenge(cookie["verifier"]) == params["code_challenge"],
        f"PKCE challenge mismatch: {case['id']}",
    )
    require(case["expected"]["separate_nonce_required"] is False, f"nonce requirement changed: {case['id']}")

    if exchange["called"]:
        require(
            exchange["code_verifier"] == cookie["verifier"],
            f"provider verifier mismatch: {case['id']}",
        )
    else:
        require(exchange["code_verifier"] is None, f"unexpected verifier on skipped exchange: {case['id']}")

    if callback.get("error") or callback["state"] != cookie["state"]:
        require(not exchange["called"], f"exchange was attempted after callback rejection: {case['id']}")


class BrowserOAuthContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.audit = load_json(SOURCE_AUDIT_PATH)
        cls.cases = load_json(CASES_PATH)
        cls.documentation = DOC_PATH.read_text(encoding="utf-8")
        cls.excerpts = load_source_excerpts()

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

    def test_source_observations_are_backed_by_immutable_excerpts(self) -> None:
        validate_source_observations(self.audit, self.excerpts)

    def test_false_source_observation_mutation_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.audit)
        mutated["source"]["refs"][0]["observations"][
            "password_provider_short_circuits_oauth_start"
        ] = False
        with self.assertRaises(AssertionError):
            validate_source_observations(mutated, self.excerpts)

    def test_source_excerpt_mutation_is_rejected(self) -> None:
        mutated = dict(self.excerpts)
        mutated["nous"] = mutated["nous"].replace(
            '"code_verifier": code_verifier,', '"wrong_verifier": code_verifier,'
        )
        with self.assertRaises(AssertionError):
            validate_source_observations(self.audit, mutated)

    def test_state_pkce_and_nonce_requirements_match_source(self) -> None:
        requirements = self.audit["requirements"]
        self.assertEqual(requirements["scope"], "pinned Nous browser OAuth flow only")
        self.assertTrue(requirements["state"]["required"])
        self.assertTrue(requirements["pkce"]["required"])
        self.assertEqual(requirements["pkce"]["method"], "S256")
        self.assertEqual(
            requirements["pkce"]["applies_to"],
            "reviewed OAuth or OIDC browser providers only",
        )
        self.assertFalse(requirements["nonce"]["required"])
        self.assertFalse(requirements["nonce"]["exposed_by_pinned_browser_flow"])
        self.assertEqual(requirements["nonce"]["scope"], "pinned Nous browser OAuth flow only")
        self.assertIn("may require nonce", requirements["nonce"]["reviewed_oidc_providers"])

    def test_password_provider_does_not_inherit_oauth_pkce(self) -> None:
        password = self.audit["requirements"]["password_provider"]
        self.assertTrue(password["supports_password"])
        self.assertFalse(password["oauth_state_required"])
        self.assertFalse(password["pkce_required"])
        self.assertIn("before provider.start_login", password["reason"])

    def test_required_cases_are_present_once(self) -> None:
        cases = self.cases["cases"]
        ids = [case["id"] for case in cases]
        self.assertEqual(set(ids), REQUIRED_CASES)
        self.assertEqual(len(ids), len(set(ids)))

    def test_source_compatible_cases_validate_from_nested_inputs(self) -> None:
        for case in self.cases["cases"]:
            validate_oauth_case(case)

    def test_pkce_challenge_and_state_inputs_are_deterministic(self) -> None:
        for case in self.cases["cases"]:
            request = case["request"]
            cookie = request["pkce_cookie"]
            params = request["authorization_request"]["params"]
            callback = request["callback"]

            self.assertEqual(params["code_challenge_method"], "S256")
            self.assertEqual(pkce_challenge(cookie["verifier"]), params["code_challenge"], case["id"])
            self.assertEqual(params["state"], cookie["state"], case["id"])
            self.assertNotIn("nonce", params)
            self.assertNotIn("nonce", callback)
            self.assertFalse(case["expected"]["separate_nonce_required"])

    def test_outbound_state_and_exchange_verifier_mutations_are_rejected(self) -> None:
        wrong_state = copy.deepcopy(self._case("success"))
        wrong_state["request"]["authorization_request"]["params"]["state"] = "fixture-wrong-state"
        with self.assertRaises(AssertionError):
            validate_oauth_case(wrong_state)

        wrong_verifier = copy.deepcopy(self._case("success"))
        wrong_verifier["provider_exchange"]["code_verifier"] = "fixture-wrong-verifier"
        with self.assertRaises(AssertionError):
            validate_oauth_case(wrong_verifier)

    def test_nested_nonce_mutation_is_rejected(self) -> None:
        mutated = copy.deepcopy(self._case("success"))
        mutated["request"]["authorization_request"]["params"]["nonce"] = "fixture-nonce"
        with self.assertRaises(AssertionError):
            validate_oauth_case(mutated)

    def test_success_requires_matching_state_and_verifier(self) -> None:
        case = self._case("success")
        request = case["request"]
        self.assertEqual(request["pkce_cookie"]["state"], request["callback"]["state"])
        self.assertEqual(
            case["provider_exchange"]["code_verifier"],
            request["pkce_cookie"]["verifier"],
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
            self.assertNotEqual(request["pkce_cookie"]["state"], request["callback"]["state"])
            self.assertFalse(case["provider_exchange"]["called"], case_id)
            self.assertIsNone(case["provider_exchange"]["code_verifier"], case_id)
            self.assertEqual(case["expected"]["status"], 400)
            self.assertFalse(case["expected"]["session_cookie_issued"])
            self.assertEqual(case["expected"]["reason"], "state_mismatch")

    def test_cancellation_and_malformed_callbacks_fail_closed(self) -> None:
        cancellation = self._case("cancellation")
        self.assertEqual(cancellation["request"]["callback"]["error"], "access_denied")
        self.assertFalse(cancellation["provider_exchange"]["called"])
        self.assertIsNone(cancellation["provider_exchange"]["code_verifier"])
        self.assertEqual(cancellation["expected"]["reason"], "idp_error")
        self.assertFalse(cancellation["expected"]["session_cookie_issued"])

        malformed = self._case("malformed-callback")
        self.assertEqual(malformed["request"]["callback"]["code"], "")
        self.assertTrue(malformed["provider_exchange"]["called"])
        self.assertEqual(
            malformed["provider_exchange"]["code_verifier"],
            malformed["request"]["pkce_cookie"]["verifier"],
        )
        self.assertEqual(
            malformed["provider_exchange"]["verifier_result"],
            "rejected_empty_code",
        )
        self.assertEqual(malformed["expected"]["status"], 400)
        self.assertFalse(malformed["expected"]["session_cookie_issued"])

    def test_pkce_failure_does_not_create_a_session(self) -> None:
        case = self._case("pkce-failure")
        self.assertTrue(case["provider_exchange"]["called"])
        self.assertEqual(
            case["provider_exchange"]["code_verifier"],
            case["request"]["pkce_cookie"]["verifier"],
        )
        self.assertEqual(case["provider_exchange"]["verifier_result"], "rejected")
        self.assertEqual(case["expected"]["reason"], "invalid_code_or_pkce")
        self.assertEqual(case["expected"]["status"], 400)
        self.assertFalse(case["expected"]["session_cookie_issued"])

    def test_documentation_scopes_nonce_and_pkce_claims(self) -> None:
        documentation = self.documentation
        self.assertIn("PKCE is conditional on the reviewed provider mode", documentation)
        self.assertIn("does not enter the OAuth state or PKCE exchange", documentation)
        self.assertIn("pinned Nous OAuth browser flow", documentation)
        self.assertIn("provider-specific OIDC `nonce` requirement", documentation)
        self.assertIn("No separate OAuth/OIDC `nonce` is exposed or required by this pinned Nous flow", documentation)
        self.assertIn("Hermternal MUST NOT add nonce validation", documentation)
        self.assertNotIn("validate the authentication state and nonce", documentation)
        self.assertNotIn("browser OAuth or OIDC state, nonce", documentation)

        # Allow scoped explanatory language, but reject a new positive global
        # requirement such as "must validate nonce" or "require a nonce".
        positive_nonce_requirement = re.compile(
            r"(?i)\b(?:must|should)\s+(?!not\b)(?:validate|require|include|accept)\b[^\n.]{0,80}\bnonce\b"
        )
        self.assertIsNone(positive_nonce_requirement.search(documentation))

    def test_fixture_values_are_synthetic_and_redaction_is_explicit(self) -> None:
        serialized_cases = json.dumps(self.cases, sort_keys=True).lower()
        self.assertNotIn("http://", serialized_cases)
        self.assertNotIn("https://", serialized_cases)
        self.assertNotIn("@", serialized_cases)
        self.assertNotIn("access_token", serialized_cases)
        self.assertNotIn("refresh_token", serialized_cases)
        self.assertNotIn("cookie_value", serialized_cases)
        for case in self.cases["cases"]:
            for value in case["request"]["callback"].values():
                self.assertTrue(
                    value in {"", "access_denied"}
                    or str(value).startswith("fixture-"),
                    value,
                )

        redaction = self.audit["redaction"]
        self.assertTrue(redaction["synthetic_cookie_shaped_values"])
        self.assertTrue(redaction["public_source_urls"])
        self.assertFalse(redaction["live_secrets"])
        self.assertFalse(redaction["live_cookie_contents"])
        self.assertFalse(redaction["live_host_data"])
        for ref in self.audit["source"]["refs"]:
            self.assertRegex(ref["url"], r"^https://github\.com/NousResearch/hermes-agent/blob/" + PINNED_SHA)

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
    print("fixture_artifact_files=source_audit.json,cases.json,source_excerpts/*")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(run())
