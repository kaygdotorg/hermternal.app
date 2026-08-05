#!/usr/bin/env python3
"""Offline regression tests for the pinned browser OAuth contract.

The test data is synthetic. The source observations are checked against
immutable excerpts and immutable Git object identifiers from the pinned Hermes
revision before the callback cases are validated, so the suite does not merely
compare duplicated JSON metadata. It deliberately does not import Hermes or
contact a provider.
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
from urllib.parse import urlparse


FIXTURE_DIR = Path(__file__).resolve().parent
REPOSITORY_ROOT = FIXTURE_DIR.parents[3]
DOC_PATH = REPOSITORY_ROOT / "docs/security/authentication.md"
SOURCE_AUDIT_PATH = FIXTURE_DIR / "source_audit.json"
CASES_PATH = FIXTURE_DIR / "cases.json"
SOURCE_EXCERPT_DIR = FIXTURE_DIR / "source_excerpts"
PINNED_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
PINNED_TREE_SHA = "886db5eb1150f819344d67fedc81aef0caab09ff"
REQUIRED_CASES = {
    "success",
    "state-mismatch",
    "missing-state",
    "pkce-failure",
    "cancellation",
    "malformed-callback",
}

# These values are a separately reviewed provenance manifest, not values read
# from source_audit.json. The blob IDs are immutable Git objects from the
# pinned commit; the excerpt hashes bind the checked-in, narrow evidence files.
EXPECTED_SOURCE_REFS = (
    {
        "path": "hermes_cli/dashboard_auth/routes.py",
        "excerpt": "source_excerpts/routes_auth.py.txt",
        "excerpt_sha256": "7a748fc29acee3d055049f0b1a12bba9e7d8aa13bc4852827888a0ebaaa507b4",
        "blob_sha": "0c142963bcc83f38fddbdcec29c35608f14f7bc1",
        "url": "https://github.com/NousResearch/hermes-agent/blob/f5be9236e00ddf2f2a412697f267078fc4ee068e/hermes_cli/dashboard_auth/routes.py",
    },
    {
        "path": "plugins/dashboard_auth/nous/__init__.py",
        "excerpt": "source_excerpts/nous_provider.py.txt",
        "excerpt_sha256": "7cc9ddc1f29753a15858b1072a814c7472b31b9d48b9344e0a49406c0a4fc01d",
        "blob_sha": "69acd18e36b545fd20df5578809de65afb0d4df4",
        "url": "https://github.com/NousResearch/hermes-agent/blob/f5be9236e00ddf2f2a412697f267078fc4ee068e/plugins/dashboard_auth/nous/__init__.py",
    },
    {
        "path": "hermes_cli/dashboard_auth/cookies.py",
        "excerpt": "source_excerpts/cookies.py.txt",
        "excerpt_sha256": "4061f5e075fee015151a14ab75c7b77661400bb2ec0fa402559c0d49cae36f3e",
        "blob_sha": "8bcd9db78eb6a8e9209e1b3087ab4e85b8997f1e",
        "url": "https://github.com/NousResearch/hermes-agent/blob/f5be9236e00ddf2f2a412697f267078fc4ee068e/hermes_cli/dashboard_auth/cookies.py",
    },
)
EXPECTED_SOURCE_REF_KEYS = frozenset(
    {"path", "excerpt", "excerpt_sha256", "blob_sha", "url", "observations"}
)
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
            (
                "routes",
                (
                    'if getattr(p, "supports_password", False):',
                    "return RedirectResponse(url=login_url, status_code=302)",
                    "ls = p.start_login(",
                ),
            ),
        ],
        "oauth_start_returns_state_and_verifier_cookie_payload": [
            (
                "routes",
                ("ls.cookie_payload.get(\"hermes_session_pkce\"", "set_pkce_cookie("),
            ),
            (
                "nous",
                ('"hermes_session_pkce": f"state={state};verifier={code_verifier}"',),
            ),
        ],
        "callback_rejects_missing_or_mismatched_state_before_exchange": [
            (
                "routes",
                (
                    "if not state or state != expected_state:",
                    'detail="OAuth state mismatch (CSRF check failed)",',
                    "p.complete_login(",
                ),
            ),
        ],
        "callback_passes_cookie_verifier_to_complete_login": [
            ("routes", ("p.complete_login(", "code_verifier=verifier,")),
        ],
        "callback_issues_and_clears_session_only_after_exchange": [
            (
                "routes",
                ("session = p.complete_login(", "set_session_cookies(", "clear_pkce_cookie("),
            ),
        ],
    },
    "plugins/dashboard_auth/nous/__init__.py": {
        "authorization_params_include_state": [
            (
                "nous",
                ("params = {", '"state": state,', "urllib.parse.urlencode(params)"),
            ),
        ],
        "authorization_params_include_s256_pkce": [
            (
                "nous",
                ('"code_challenge": code_challenge,', '"code_challenge_method": "S256",'),
            ),
        ],
        "authorization_params_exclude_nonce": [("nous", ())],
        "cookie_payload_contains_state_and_verifier": [
            (
                "nous",
                ('"hermes_session_pkce": f"state={state};verifier={code_verifier}"',),
            ),
        ],
        "token_exchange_sends_code_verifier": [
            ("nous", ('"code_verifier": code_verifier,',)),
        ],
    },
    "hermes_cli/dashboard_auth/cookies.py": {
        "pkce_cookie_is_short_lived": [
            ("cookies", ('PKCE_COOKIE = "hermes_session_pkce"', "_PKCE_MAX_AGE = 10 * 60")),
        ],
        "pkce_cookie_is_http_only_lax_and_secure_for_https": [
            ("cookies", ('"httponly": True', '"samesite": "lax"', 'attrs["secure"] = True')),
        ],
        "csrf_nonce_label_is_state_not_provider_nonce": [
            ("cookies", ("CSRF nonce", "PKCE_COOKIE")),
        ],
    },
}

SYNTHETIC_IDENTIFIER = re.compile(r"^(?:fixture|synthetic)-[a-z0-9]+(?:-[a-z0-9]+)*$")
SYNTHETIC_STATE = re.compile(r"^fixture-state-[a-z0-9]+(?:-[a-z0-9]+)*$")
SYNTHETIC_VERIFIER = re.compile(r"^synthetic-verifier-[a-z0-9]+$")
SYNTHETIC_CODE = re.compile(r"^fixture-code(?:-[a-z0-9]+)*$")
SYNTHETIC_DESCRIPTION = re.compile(r"^fixture-[a-z0-9]+(?:-[a-z0-9]+)*$")
SYNTHETIC_CLIENT_ID = re.compile(r"^fixture-client(?:-[a-z0-9]+)*$")
SYNTHETIC_REDIRECT_URI = re.compile(r"^fixture-redirect-uri(?:-[a-z0-9]+)*$")
SYNTHETIC_SCOPE = re.compile(r"^fixture-scope(?:-[a-z0-9]+)*$")
CODE_CHALLENGE = re.compile(r"^[A-Za-z0-9_-]{43}$")
NONCE_MODAL_POSITIVE = re.compile(r"\b(?:MUST|SHOULD)\b(?!\s+NOT\b)", re.IGNORECASE)
NONCE_ACTION = re.compile(
    r"\b(?:apply|accept|check|enforce|include|require|use|validate|verify)\w*\b"
    r"[^.!?;\n]{0,100}\bnonce\b",
    re.IGNORECASE,
)
NONCE_NEGATION = re.compile(
    r"\b(?:no|not|never|without|does\s+not|do\s+not|isn't|aren't)\b",
    re.IGNORECASE,
)
NONCE_SCOPE = re.compile(
    r"\b(?:provider-specific|reviewed(?:[- ]provider)?|compatibility\s+record|"
    r"pinned\s+Nous|only\s+when)\b",
    re.IGNORECASE,
)


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
        # This expected hash map is independent of source_audit.json. The
        # explicit filename-to-hash relationship keeps provenance readable.
        expected_hash = {
            "routes": EXPECTED_SOURCE_REFS[0]["excerpt_sha256"],
            "nous": EXPECTED_SOURCE_REFS[1]["excerpt_sha256"],
            "cookies": EXPECTED_SOURCE_REFS[2]["excerpt_sha256"],
        }[key]
        require(actual_hash == expected_hash, f"changed source excerpt: {key}")
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


def validate_source_url(url: Any, expected: dict[str, str]) -> None:
    require(isinstance(url, str), f"source URL is not a string: {expected['path']}")
    require(url == expected["url"], f"source URL changed: {expected['path']}")
    parsed = urlparse(url)
    require(parsed.scheme == "https", f"source URL scheme is not HTTPS: {expected['path']}")
    require(parsed.netloc == "github.com", f"source URL host is not public GitHub: {expected['path']}")
    require(parsed.hostname == "github.com", f"source URL hostname changed: {expected['path']}")
    require(parsed.username is None, f"source URL contains userinfo: {expected['path']}")
    require(parsed.password is None, f"source URL contains password: {expected['path']}")
    require(not parsed.query, f"source URL contains query data: {expected['path']}")
    require(not parsed.fragment, f"source URL contains fragment data: {expected['path']}")
    require(not parsed.params, f"source URL contains path parameters: {expected['path']}")
    expected_path = f"/NousResearch/hermes-agent/blob/{PINNED_SHA}/{expected['path']}"
    require(parsed.path == expected_path, f"source URL path changed: {expected['path']}")


def validate_source_refs(audit: dict[str, Any]) -> dict[str, dict[str, Any]]:
    source = audit["source"]
    require(
        set(source) == {"repository", "sha", "tree_sha", "refs"},
        "source provenance shape changed",
    )
    require(source["repository"] == "NousResearch/hermes-agent", "source repository changed")
    require(source["sha"] == PINNED_SHA, "source commit changed")
    require(source["tree_sha"] == PINNED_TREE_SHA, "source tree changed")

    refs = source["refs"]
    require(isinstance(refs, list), "source refs must remain a list")
    require(len(refs) == len(EXPECTED_SOURCE_REFS), "source ref count changed")
    require(all(isinstance(ref, dict) for ref in refs), "source refs must be objects")
    paths = [ref.get("path") for ref in refs]
    require(len(paths) == len(set(paths)), "duplicate source ref path")
    expected_paths = {ref["path"] for ref in EXPECTED_SOURCE_REFS}
    require(set(paths) == expected_paths, "source ref path set changed")

    validated: dict[str, dict[str, Any]] = {}
    for expected in EXPECTED_SOURCE_REFS:
        matches = [ref for ref in refs if ref.get("path") == expected["path"]]
        require(len(matches) == 1, f"source ref is not unique: {expected['path']}")
        ref = matches[0]
        require(set(ref) == EXPECTED_SOURCE_REF_KEYS, f"source ref shape changed: {expected['path']}")
        for field in ("path", "excerpt", "excerpt_sha256", "blob_sha"):
            require(ref[field] == expected[field], f"source ref {field} changed: {expected['path']}")
        validate_source_url(ref["url"], expected)
        validated[expected["path"]] = ref
    return validated


def validate_source_observations(
    audit: dict[str, Any], excerpts: dict[str, str]
) -> None:
    refs = validate_source_refs(audit)
    require(set(refs) == set(SOURCE_EVIDENCE), "source reference set changed")

    for path, expected_observations in SOURCE_EVIDENCE.items():
        observations = refs[path]["observations"]
        require(
            set(observations) == set(expected_observations),
            f"observation IDs changed: {path}",
        )
        for observation, evidence in expected_observations.items():
            require(observations[observation] is True, f"false source observation: {observation}")
            for excerpt_key, markers in evidence:
                assert_markers_in_order(excerpts[excerpt_key], markers, excerpt_key)


def require_synthetic(value: Any, pattern: re.Pattern[str], label: str) -> None:
    require(isinstance(value, str), f"{label} must be a string")
    require(pattern.fullmatch(value) is not None, f"{label} is not synthetic: {value!r}")


def validate_synthetic_case_values(case: dict[str, Any]) -> None:
    """Validate every fixture value before applying cross-field behavior rules."""
    require(
        set(case) == {"id", "request", "provider_exchange", "expected"},
        f"case shape changed: {case.get('id')!r}",
    )
    require(re.fullmatch(r"[a-z0-9-]+", case["id"]) is not None, "case ID is not synthetic")

    request = case["request"]
    require(set(request) == {"pkce_cookie", "authorization_request", "callback"}, "request shape changed")

    cookie = request["pkce_cookie"]
    require(set(cookie) == {"provider", "state", "verifier"}, "PKCE cookie shape changed")
    require_synthetic(cookie["provider"], SYNTHETIC_IDENTIFIER, "pkce_cookie.provider")
    require_synthetic(cookie["state"], SYNTHETIC_STATE, "pkce_cookie.state")
    require_synthetic(cookie["verifier"], SYNTHETIC_VERIFIER, "pkce_cookie.verifier")

    authorization = request["authorization_request"]
    require(set(authorization) == {"params"}, "authorization request shape changed")
    params = authorization["params"]
    expected_params = {
        "response_type",
        "client_id",
        "redirect_uri",
        "scope",
        "state",
        "code_challenge",
        "code_challenge_method",
    }
    require(set(params) == expected_params, "authorization parameter set changed")
    require(params["response_type"] == "code", "response_type changed")
    require_synthetic(params["client_id"], SYNTHETIC_CLIENT_ID, "authorization.params.client_id")
    require_synthetic(params["redirect_uri"], SYNTHETIC_REDIRECT_URI, "authorization.params.redirect_uri")
    require_synthetic(params["scope"], SYNTHETIC_SCOPE, "authorization.params.scope")
    require_synthetic(params["state"], SYNTHETIC_STATE, "authorization.params.state")
    require_synthetic(params["code_challenge"], CODE_CHALLENGE, "authorization.params.code_challenge")
    require(params["code_challenge_method"] == "S256", "code_challenge_method changed")

    callback = request["callback"]
    require(set(callback).issubset({"code", "state", "error", "error_description"}), "callback fields changed")
    require(set(callback).issuperset({"code", "state"}), "callback must include code and state")
    require(callback["code"] == "" or SYNTHETIC_CODE.fullmatch(callback["code"]) is not None, "callback.code is not synthetic")
    require(callback["state"] == "" or SYNTHETIC_STATE.fullmatch(callback["state"]) is not None, "callback.state is not synthetic")
    if "error" in callback:
        require(callback["error"] in {"", "access_denied"}, "callback.error is not an allowed protocol value")
    if "error_description" in callback:
        require_synthetic(callback["error_description"], SYNTHETIC_DESCRIPTION, "callback.error_description")

    exchange = case["provider_exchange"]
    require(set(exchange) == {"called", "code_verifier", "verifier_result"}, "provider exchange shape changed")
    require(isinstance(exchange["called"], bool), "provider_exchange.called must be boolean")
    require(
        exchange["code_verifier"] is None
        or SYNTHETIC_VERIFIER.fullmatch(exchange["code_verifier"]) is not None,
        "provider_exchange.code_verifier is not synthetic",
    )
    require(
        exchange["verifier_result"] in {"accepted", "rejected", "rejected_empty_code", "not_attempted"},
        "provider_exchange.verifier_result changed",
    )

    expected = case["expected"]
    require(
        set(expected) == {"status", "reason", "session_cookie_issued", "pkce_cookie", "separate_nonce_required"},
        "expected case shape changed",
    )
    require(expected["status"] in {302, 400}, "expected status changed")
    require(expected["reason"] in {"login_success", "state_mismatch", "invalid_code_or_pkce", "idp_error"}, "expected reason changed")
    require(isinstance(expected["session_cookie_issued"], bool), "expected session flag must be boolean")
    require(expected["pkce_cookie"] in {"cleared", "retained_until_ttl"}, "expected PKCE cookie state changed")
    require(isinstance(expected["separate_nonce_required"], bool), "expected nonce flag must be boolean")


def validate_oauth_case(case: dict[str, Any]) -> None:
    validate_synthetic_case_values(case)
    request = case["request"]
    cookie = request["pkce_cookie"]
    params = request["authorization_request"]["params"]
    callback = request["callback"]
    exchange = case["provider_exchange"]

    require("nonce" not in params, f"pinned Nous flow unexpectedly gained nonce: {case['id']}")
    require(params["state"] == cookie["state"], f"outbound state mismatch: {case['id']}")
    require(pkce_challenge(cookie["verifier"]) == params["code_challenge"], f"PKCE challenge mismatch: {case['id']}")
    require(case["expected"]["separate_nonce_required"] is False, f"nonce requirement changed: {case['id']}")

    if exchange["called"]:
        require(exchange["code_verifier"] == cookie["verifier"], f"provider verifier mismatch: {case['id']}")
    else:
        require(exchange["code_verifier"] is None, f"unexpected verifier on skipped exchange: {case['id']}")

    if callback.get("error") or callback["state"] != cookie["state"]:
        require(not exchange["called"], f"exchange was attempted after callback rejection: {case['id']}")


def assert_nonce_policy_is_scoped(documentation: str) -> None:
    """Reject positive nonce requirements unless their provider scope is explicit."""
    clauses = re.split(r"[.!?;\n]+", documentation)
    for clause in clauses:
        if not re.search(r"\bnonce\b", clause, re.IGNORECASE):
            continue
        positive_modal = NONCE_MODAL_POSITIVE.search(clause) is not None
        positive_action = NONCE_ACTION.search(clause) is not None
        if not (positive_modal or positive_action):
            continue
        if positive_modal and re.search(r"\b(?:MUST|SHOULD)\b\s+NOT\b", clause, re.IGNORECASE):
            continue
        if not positive_modal and NONCE_NEGATION.search(clause):
            continue
        require(
            NONCE_SCOPE.search(clause) is not None,
            f"unscoped positive nonce requirement: {clause.strip()!r}",
        )


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
        self.assertEqual(self.audit["source"]["tree_sha"], PINNED_TREE_SHA)
        self.assertEqual(self.cases["source_sha"], PINNED_SHA)
        self.assertTrue(self.audit["synthetic_only"])
        self.assertFalse(self.audit["network_access"])
        self.assertFalse(self.audit["apple_behavior"])
        self.assertFalse(self.audit["superdesign_output"])

        paths = {ref["path"] for ref in self.audit["source"]["refs"]}
        self.assertEqual(paths, {ref["path"] for ref in EXPECTED_SOURCE_REFS})

    def test_source_refs_are_exact_unique_and_pinned(self) -> None:
        validate_source_refs(self.audit)

    def test_source_ref_mutations_are_rejected(self) -> None:
        duplicate = copy.deepcopy(self.audit)
        duplicate["source"]["refs"][1]["path"] = duplicate["source"]["refs"][0]["path"]
        with self.assertRaises(AssertionError):
            validate_source_refs(duplicate)

        wrong_excerpt = copy.deepcopy(self.audit)
        wrong_excerpt["source"]["refs"][0]["excerpt"] = "source_excerpts/nous_provider.py.txt"
        with self.assertRaises(AssertionError):
            validate_source_refs(wrong_excerpt)

        wrong_blob = copy.deepcopy(self.audit)
        wrong_blob["source"]["refs"][0]["blob_sha"] = "0" * 40
        with self.assertRaises(AssertionError):
            validate_source_refs(wrong_blob)

        wrong_url_path = copy.deepcopy(self.audit)
        wrong_url_path["source"]["refs"][0]["url"] = wrong_url_path["source"]["refs"][0]["url"].replace(
            "hermes_cli/dashboard_auth/routes.py", "hermes_cli/dashboard_auth/cookies.py"
        )
        with self.assertRaises(AssertionError):
            validate_source_refs(wrong_url_path)

    def test_source_url_mutations_are_rejected(self) -> None:
        for mutation in (
            lambda url: url + "?download=1",
            lambda url: url.replace("https://github.com", "https://attacker@github.com"),
            lambda url: url.replace(PINNED_SHA, "0" * 40),
        ):
            mutated = copy.deepcopy(self.audit)
            mutated["source"]["refs"][0]["url"] = mutation(mutated["source"]["refs"][0]["url"])
            with self.assertRaises(AssertionError):
                validate_source_refs(mutated)

        # Keep the expected string aligned only to exercise URL parsing itself;
        # the parser must still reject a query or userinfo-bearing URL.
        for mutation in (
            lambda url: url + "?download=1",
            lambda url: url.replace("https://github.com", "https://attacker@github.com"),
        ):
            expected = dict(EXPECTED_SOURCE_REFS[0])
            mutated_url = mutation(expected["url"])
            expected["url"] = mutated_url
            with self.assertRaises(AssertionError):
                validate_source_url(mutated_url, expected)

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
        self.assertEqual(requirements["pkce"]["applies_to"], "reviewed OAuth or OIDC browser providers only")
        self.assertEqual(requirements["nonce"]["policy"], "provider_scoped")
        self.assertFalse(requirements["nonce"]["global_positive_requirement"])
        self.assertTrue(requirements["nonce"]["positive_requirements_require_compatibility_scope"])
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

    def test_synthetic_value_schema_rejects_live_credential_shapes(self) -> None:
        mutations = (
            ("request", "pkce_cookie", "verifier"),
            ("request", "authorization_request", "params", "client_id"),
            ("request", "callback", "code"),
            ("provider_exchange", "code_verifier"),
        )
        for path in mutations:
            mutated = copy.deepcopy(self._case("success"))
            if path[-1] == "code" and path[1] == "callback":
                parent = mutated["request"]["callback"]
                parent["code"] = "ghp_live_fixture_not_a_code"
            elif path[-1] == "client_id":
                mutated["request"]["authorization_request"]["params"]["client_id"] = "ghp_live_fixture_client"
            elif path[-1] == "verifier" and path[1] == "pkce_cookie":
                mutated["request"]["pkce_cookie"]["verifier"] = "ghp_live_fixture_verifier"
            else:
                mutated["provider_exchange"]["code_verifier"] = "ghp_live_fixture_verifier"
            with self.assertRaises(AssertionError, msg=str(path)):
                validate_oauth_case(mutated)

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
        self.assertEqual(case["provider_exchange"]["code_verifier"], request["pkce_cookie"]["verifier"])
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
        self.assertEqual(malformed["provider_exchange"]["code_verifier"], malformed["request"]["pkce_cookie"]["verifier"])
        self.assertEqual(malformed["provider_exchange"]["verifier_result"], "rejected_empty_code")
        self.assertEqual(malformed["expected"]["status"], 400)
        self.assertFalse(malformed["expected"]["session_cookie_issued"])

    def test_pkce_failure_does_not_create_a_session(self) -> None:
        case = self._case("pkce-failure")
        self.assertTrue(case["provider_exchange"]["called"])
        self.assertEqual(case["provider_exchange"]["code_verifier"], case["request"]["pkce_cookie"]["verifier"])
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
        assert_nonce_policy_is_scoped(documentation)

    def test_unscoped_global_nonce_mutation_is_rejected(self) -> None:
        for sentence in (
            "The client MUST enforce a nonce for every provider.",
            "The client MUST require a nonce for every provider.",
        ):
            mutated = self.documentation + "\n" + sentence + "\n"
            with self.assertRaises(AssertionError):
                assert_nonce_policy_is_scoped(mutated)

    def test_fixture_values_are_synthetic_and_redaction_is_explicit(self) -> None:
        serialized_cases = json.dumps(self.cases, sort_keys=True).lower()
        self.assertNotIn("http://", serialized_cases)
        self.assertNotIn("https://", serialized_cases)
        self.assertNotIn("@", serialized_cases)
        self.assertNotIn("access_token", serialized_cases)
        self.assertNotIn("refresh_token", serialized_cases)
        self.assertNotIn("cookie_value", serialized_cases)

        redaction = self.audit["redaction"]
        self.assertTrue(redaction["synthetic_cookie_shaped_values"])
        self.assertTrue(redaction["public_source_urls"])
        self.assertFalse(redaction["live_secrets"])
        self.assertFalse(redaction["live_cookie_contents"])
        self.assertFalse(redaction["live_host_data"])
        for expected in EXPECTED_SOURCE_REFS:
            self.assertRegex(expected["url"], r"^https://github\.com/NousResearch/hermes-agent/blob/")

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
