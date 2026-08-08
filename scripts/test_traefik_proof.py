#!/usr/bin/env python3
"""Regression tests for the disposable issue #92 Traefik proof fixture.

The tests exercise the renderer and the local forward-auth policy model only.
They never contact Hermes, a provider, a VM, a public address, or a real
credential service.  An optional Traefik executable is not required: native
Traefik configuration cannot enforce exact raw-query key sets by itself, so
this proof keeps the closed query policy explicit and tests it before any
upstream would be selected.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import traefik_proof  # noqa: E402


EVIDENCE_PATH = ROOT / "tests/integration/hermes-traefik/traefik-proof-evidence.json"
EVIDENCE_ANCHOR_PATH = ROOT / "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt"
EXPECTED_BUILD_SHA = "521ede32b904a42e22eebb279fd7d404074cd318"
EXPECTED_BUILD_DIGEST = "77f6d0e8bb4977c16eb1f1eaec32000f84f346ddec9f474ebd873d7b9a833d21"
EXPECTED_CONFIG_DIGEST = "9e84bb9fe37996341dfdb675e98b928e5203a9adc793c69edb52e1f28f927e3b"


class TraefikRendererTests(unittest.TestCase):
    """Keep the Traefik route bundle finite, private, and default-deny."""

    def setUp(self) -> None:
        self.inputs = traefik_proof.reconstruction_inputs()
        self.bundle = traefik_proof.render_bundle(self.inputs)
        self.static = self.bundle["static"]
        self.dynamic = self.bundle["dynamic"]
        self.http = self.dynamic["http"]
        self.routers = self.http["routers"]
        self.middlewares = self.http["middlewares"]
        self.services = self.http["services"]

    def test_renderer_inputs_reject_ambiguous_hosts_ports_and_paths(self) -> None:
        self.assertEqual(traefik_proof._validate_host("traefik-92.test"), "traefik-92.test")
        with self.assertRaises(ValueError):
            traefik_proof._validate_host("traefik..test")
        with self.assertRaises(ValueError):
            traefik_proof._validate_host(123)  # type: ignore[arg-type]
        self.assertEqual(traefik_proof._validate_port(19444, "https_port"), 19444)
        with self.assertRaises(ValueError):
            traefik_proof._validate_port(443, "https_port")
        with self.assertRaises(ValueError):
            traefik_proof._validate_path("relative/site", "site_root")
        with self.assertRaises(ValueError):
            traefik_proof._validate_runtime_inputs({})

    def test_static_config_is_loopback_only_and_does_not_trust_forwarded_headers(self) -> None:
        entrypoint = self.static["entryPoints"]["websecure"]
        self.assertEqual(entrypoint["address"], "127.0.0.1:19444")
        self.assertEqual(entrypoint["forwardedHeaders"], {"insecure": False})
        self.assertEqual(self.static["providers"]["file"]["watch"], False)
        self.assertNotIn("0.0.0.0", json.dumps(self.static))
        self.assertNotIn("::", json.dumps(self.static))

    def test_routes_are_finite_and_prefix_is_explicit(self) -> None:
        for method, path in traefik_proof.EXACT_REST_ROUTES:
            if path == "/auth/callback":
                self.assertIn("root_auth_callback", self.routers)
            else:
                self.assertIn(path, json.dumps(self.routers))
        self.assertIn("dashboard_prefix", self.routers)
        self.assertEqual(self.routers["dashboard_prefix"]["rule"], "Host(`traefik-92.test`) && PathPrefix(`/hermes`)")
        self.assertEqual(self.middlewares["strip-hermes"], {"stripPrefix": {"prefixes": ["/hermes"], "forceSlash": False}})
        self.assertEqual(
            self.routers["client_deep_link"]["middlewares"],
            ["edge-policy", "client-deep-link-fallback"],
        )
        self.assertEqual(
            self.middlewares["client-deep-link-fallback"],
            {"replacePathRegex": {"regex": traefik_proof.CLIENT_ROUTE_PATTERN, "replacement": "/200.html"}},
        )
        self.assertNotIn("PathPrefix(`/api`)", json.dumps(self.routers))
        self.assertNotIn("/hermes/*", json.dumps(self.routers))

    def test_policy_gate_precedes_every_service_and_wrong_host_has_421_route(self) -> None:
        self.assertEqual(self.routers["wrong_host"]["rule"], "!Host(`traefik-92.test`)")
        for name, router in self.routers.items():
            with self.subTest(router=name):
                self.assertEqual(router["entryPoints"], ["websecure"])
                self.assertEqual(router["middlewares"][0], "edge-policy")
        policy = self.middlewares["edge-policy"]["forwardAuth"]
        self.assertEqual(policy["address"], "http://127.0.0.1:19259/check")
        self.assertFalse(policy["trustForwardHeader"])
        self.assertIn("X-Forwarded-Uri", policy["authRequestHeaders"])
        self.assertNotIn("https://", policy["address"])

    def test_upstream_services_are_private_and_static_is_separate_from_hermes(self) -> None:
        hermes = self.services["hermes"]["loadBalancer"]
        static = self.services["static"]["loadBalancer"]
        self.assertEqual(hermes["servers"], [{"url": "http://127.0.0.1:19257"}])
        self.assertEqual(static["servers"], [{"url": "http://127.0.0.1:19258"}])
        self.assertFalse(hermes["passHostHeader"])
        self.assertFalse(static["passHostHeader"])
        self.assertIn("policy-deny", self.services)
        self.assertNotIn("public", json.dumps(self.services).lower())

    def test_trusted_forwarding_headers_override_spoofable_values(self) -> None:
        root_headers = self.middlewares["root-hermes-headers"]["headers"]["customRequestHeaders"]
        dashboard_headers = self.middlewares["dashboard-hermes-headers"]["headers"]["customRequestHeaders"]
        self.assertEqual(root_headers["X-Forwarded-Prefix"], "")
        self.assertEqual(dashboard_headers["X-Forwarded-Prefix"], "/hermes")
        for headers in (root_headers, dashboard_headers):
            self.assertEqual(headers["Forwarded"], "for=127.0.0.1;host=traefik-92.test;proto=https")
            self.assertEqual(headers["Origin"], "http://127.0.0.1:19257")
            self.assertEqual(headers["X-Forwarded-Proto"], "https")
            self.assertEqual(headers["X-Real-IP"], "127.0.0.1")
            self.assertEqual(headers["X-Forwarded-Debug"], "")

    def test_websocket_query_grammars_are_distinct_and_exact(self) -> None:
        self.assertTrue(re.fullmatch(traefik_proof.CHAT_TICKET_QUERY_PATTERN, "ticket=fixtureTicket"))
        self.assertFalse(re.fullmatch(traefik_proof.CHAT_TICKET_QUERY_PATTERN, "ticket=fixtureTicket&resume=fixtureResume"))
        self.assertEqual(len(traefik_proof.PTY_QUERY_PATTERNS), 8)
        accepted = {
            "ticket=fixtureTicket&resume=fixtureResume",
            "resume=fixtureResume&ticket=fixtureTicket",
            "ticket=fixtureTicket&resume=fixtureResume&attach=fixtureAttach",
            "attach=fixtureAttach&ticket=fixtureTicket&resume=fixtureResume",
        }
        rejected = {
            "ticket=fixtureTicket",
            "ticket=fixtureTicket&resume=fixtureResume&fresh=1",
            "ticket=fixtureTicket&resume=fixtureResume&ticket=otherTicket",
            "ticket=&resume=fixtureResume",
            "ticket=fixtureTicket&resume=",
            "ticket=fixtureTicket&resume=fixtureResume&attach=",
            "ticket=fixtureTicket&resume=fixtureResume&extra=value",
            "ticket=fixture%2DTicket&resume=fixtureResume",
        }
        for query in accepted:
            self.assertTrue(any(re.fullmatch(pattern, query) for pattern in traefik_proof.PTY_QUERY_PATTERNS), query)
        for query in rejected:
            self.assertFalse(any(re.fullmatch(pattern, query) for pattern in traefik_proof.PTY_QUERY_PATTERNS), query)

    def test_policy_allows_static_and_prefix_routes_without_normalizing_paths(self) -> None:
        host = "traefik-92.test"
        common = {"Host": host}
        allowed = (
            ("GET", "/", ""),
            ("GET", "/", "scenario=success"),
            ("GET", "/v1/c/abcdefghijklmnop", ""),
            ("GET", "/v1/c/abcdefghijklmnop/m/qrstuvwxyzabcdef", ""),
            ("GET", "/hermes/api/auth/providers", ""),
            ("POST", "/hermes/api/auth/ws-ticket", ""),
            ("GET", "/api/sessions/abcdefghijklmnop", ""),
            ("GET", "/hermes/api/sessions/abcdefghijklmnop/messages", ""),
            ("PATCH", "/api/sessions/abcdefghijklmnop", ""),
        )
        for method, path, query in allowed:
            with self.subTest(method=method, path=path, query=query):
                result = traefik_proof.policy_decision(
                    host=host,
                    https_port=19444,
                    method=method,
                    path=path,
                    query=query,
                    headers=common,
                )
                self.assertEqual(result["status"], 200)
                self.assertTrue(result["upstream_request"])
        denied = (
            ("GET", "/v1/c/short", ""),
            ("GET", "/hermes/hermes/api/auth/providers", ""),
            ("GET", "/v1/c/abcdefghijklmnop", "cache=synthetic"),
            ("POST", "/hermes/api/auth/ws-ticket", "cache=synthetic"),
            ("GET", "/unknown", ""),
            ("POST", "/api/auth/providers", ""),
            ("GET", "/api/sessions/abcdefghijklmnop", "cache=synthetic"),
            ("GET", "/api/sessions/abcdefghijklmnop/messages", "cache=synthetic"),
        )
        for method, path, query in denied:
            with self.subTest(method=method, path=path, query=query):
                result = traefik_proof.policy_decision(
                    host=host,
                    https_port=19444,
                    method=method,
                    path=path,
                    query=query,
                    headers=common,
                )
                self.assertEqual((result["status"], result["layer"], result["upstream_request"]), (404, "edge", False))

    def test_policy_keeps_host_origin_and_ticket_layers_separate(self) -> None:
        host = "traefik-92.test"
        upgrade = {
            "Host": host,
            "Origin": f"https://{host}:19444",
            "Upgrade": "websocket",
            "Connection": "Upgrade",
        }
        cases = (
            ("/api/ws", "ticket=fixtureTicket", 101, "hermes", True),
            ("/hermes/api/pty", "ticket=fixtureTicket&resume=fixtureResume", 101, "hermes", True),
            ("/api/ws", "", 404, "edge", False),
            ("/api/pty", "ticket=fixtureTicket", 404, "edge", False),
        )
        for path, query, status, layer, upstream in cases:
            with self.subTest(path=path, query=query):
                result = traefik_proof.policy_decision(
                    host=host,
                    https_port=19444,
                    method="GET",
                    path=path,
                    query=query,
                    headers=upgrade,
                )
                self.assertEqual((result["status"], result["layer"], result["upstream_request"]), (status, layer, upstream))

        wrong_host = traefik_proof.policy_decision(
            host=host,
            https_port=19444,
            method="GET",
            path="/api/ws",
            query="ticket=fixtureTicket",
            headers={**upgrade, "Host": "evil.example"},
        )
        self.assertEqual((wrong_host["status"], wrong_host["layer"], wrong_host["upstream_request"]), (421, "edge", False))
        wrong_origin = traefik_proof.policy_decision(
            host=host,
            https_port=19444,
            method="GET",
            path="/api/ws",
            query="ticket=fixtureTicket",
            headers={**upgrade, "Origin": "https://evil.example"},
        )
        self.assertEqual((wrong_origin["status"], wrong_origin["layer"], wrong_origin["upstream_request"]), (403, "edge", False))

        # Syntactically accepted ticket material reaches Hermes; invalid,
        # expired, and reused outcomes are not edge claims.
        accepted = traefik_proof.policy_decision(
            host=host,
            https_port=19444,
            method="GET",
            path="/api/ws",
            query="ticket=fixtureTicket",
            headers=upgrade,
        )
        self.assertEqual((accepted["layer"], accepted["upstream_request"]), ("hermes", True))

    def test_policy_rejects_raw_path_obfuscation_and_bare_query_marker(self) -> None:
        host = "traefik-92.test"
        headers = {"Host": host}
        for path, raw_target in (
            ("/v1/c/abcdefghijklmnop", "/v1/c/abcdefghijklmnop?"),
            ("/v1/c/abcdefghijklmnop", "/v1/c/abcdefghijkl%2Fmnop"),
            ("/v1/c/abcdefghijklmnop", "/v1/c/abcdefghijkl\\mnop"),
            ("/v1/c/abcdefghijklmnop", "/v1/c/abcdefghijklmnop/../x"),
            ("/v1/c/abcdefghijklmnop", "/v1/c/.../abcdefghijklmnop"),
        ):
            with self.subTest(raw_target=raw_target):
                result = traefik_proof.policy_decision(
                    host=host,
                    https_port=19444,
                    method="GET",
                    path=path,
                    headers=headers,
                    raw_target=raw_target,
                )
                self.assertEqual((result["status"], result["layer"], result["upstream_request"]), (404, "edge", False))

    def test_runtime_digest_is_stable_and_evidence_is_redacted(self) -> None:
        self.assertEqual(traefik_proof.rendered_config_digest(self.inputs), EXPECTED_CONFIG_DIGEST)
        self.assertEqual(
            traefik_proof.rendered_config_digest(self.inputs),
            traefik_proof.rendered_config_digest(dict(reversed(tuple(self.inputs.items())))),
        )
        evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        self.assertEqual(evidence["schema"], traefik_proof.SCHEMA)
        self.assertEqual(evidence["deployment"]["runtime_config_sha256"], EXPECTED_CONFIG_DIGEST)
        self.assertEqual(evidence["deployment"]["runtime_inputs"], self.inputs)
        self.assertEqual(evidence["deployment"]["runtime_inputs_sha256"], traefik_proof.runtime_input_digest(self.inputs))
        self.assertEqual(evidence["browser_journey"], "blocked_provider")
        self.assertEqual(evidence["cookie_proof"]["status"], "not_proven")
        self.assertTrue(all(value == "redacted" for value in evidence["retention"].values()))
        raw = EVIDENCE_PATH.read_text(encoding="utf-8")
        for forbidden in ("?ticket=", "Cookie:", "Set-Cookie:", "Authorization:", "Bearer ", "password=", "api_key="):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, raw)
        for event in traefik_proof.BROWSER_COMPLETION_EVIDENCE:
            self.assertNotIn(f'"{event}"', raw)

    def test_evidence_anchor_matches_retained_bytes(self) -> None:
        expected = EVIDENCE_ANCHOR_PATH.read_text(encoding="utf-8").strip()
        actual = hashlib.sha256(EVIDENCE_PATH.read_bytes()).hexdigest()
        self.assertEqual(expected, actual)


class TraefikEvidenceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))

    def _browser_evidence(self, status: str, *, provenance: dict[str, str] | None = None) -> dict[str, object]:
        expected = {
            "build_sha": EXPECTED_BUILD_SHA,
            "build_digest": EXPECTED_BUILD_DIGEST,
            "traefik_config_digest": EXPECTED_CONFIG_DIGEST,
            "runtime_inputs_sha256": traefik_proof.runtime_input_digest(traefik_proof.reconstruction_inputs()),
        }
        if provenance:
            expected.update(provenance)
        if status == "passed":
            observations: dict[str, object] = {"events": dict(traefik_proof.BROWSER_COMPLETION_EVIDENCE)}
        elif status in traefik_proof.BROWSER_BLOCKED_JOURNEYS:
            observations = {"blocker": traefik_proof.BROWSER_BLOCKER_CODES[status]}
        else:
            observations = {"failure": traefik_proof.BROWSER_FAILURE_CODE}
        return {
            "schema": traefik_proof.BROWSER_EVIDENCE_SCHEMA,
            "status": status,
            "provenance": expected,
            "observations": observations,
        }

    def test_evidence_shape_is_closed(self) -> None:
        self.assertEqual(
            set(self.evidence),
            {
                "schema",
                "issue",
                "contract",
                "deployment",
                "product",
                "browser_journey",
                "browser_evidence",
                "positive_cases",
                "negative_cases",
                "black_box",
                "cookie_proof",
                "retention",
            },
        )
        deployment = self.evidence["deployment"]
        self.assertEqual(
            set(deployment),
            {
                "proxy",
                "hermes_source_sha",
                "runtime_config_sha256",
                "runtime_inputs_schema",
                "runtime_inputs",
                "runtime_inputs_sha256",
                "parity_fixtures",
                "hermes_listener",
                "public_listener",
                "edge_policy",
            },
        )
        self.assertEqual(set(deployment["runtime_inputs"]), set(traefik_proof.DEFAULT_RUNTIME_INPUTS))
        self.assertEqual(set(deployment["parity_fixtures"]), {"static_route_grammar", "deep_link_cases"})
        self.assertEqual(set(self.evidence["browser_evidence"]), set(traefik_proof.BROWSER_EVIDENCE_ROOT_KEYS))
        self.assertEqual(self.evidence["browser_evidence"]["observations"], {"blocker": "provider_unavailable"})
        self.assertEqual(len(self.evidence["positive_cases"]), 11)
        self.assertEqual(len(self.evidence["negative_cases"]), 23)

    def test_render_manifest_requires_provenance_bound_browser_evidence(self) -> None:
        with self.assertRaisesRegex(ValueError, "browser evidence is required"):
            traefik_proof.render_manifest(
                build_sha=EXPECTED_BUILD_SHA,
                build_digest=EXPECTED_BUILD_DIGEST,
                traefik_config_digest=EXPECTED_CONFIG_DIGEST,
                browser_journey="passed",
            )
        with self.assertRaisesRegex(ValueError, "stale or mismatched"):
            traefik_proof.render_manifest(
                build_sha=EXPECTED_BUILD_SHA,
                build_digest=EXPECTED_BUILD_DIGEST,
                traefik_config_digest=EXPECTED_CONFIG_DIGEST,
                browser_evidence=self._browser_evidence("blocked_provider", provenance={"build_sha": "0" * 40}),
            )
        incomplete = self._browser_evidence("passed")
        incomplete["observations"] = {"events": {"message.complete": "complete"}}
        with self.assertRaisesRegex(ValueError, "closed event set"):
            traefik_proof.render_manifest(
                build_sha=EXPECTED_BUILD_SHA,
                build_digest=EXPECTED_BUILD_DIGEST,
                traefik_config_digest=EXPECTED_CONFIG_DIGEST,
                browser_journey="passed",
                browser_evidence=incomplete,
            )

    def test_blocked_and_failed_journeys_keep_fixed_observations(self) -> None:
        blocked = traefik_proof.render_manifest(
            build_sha=EXPECTED_BUILD_SHA,
            build_digest=EXPECTED_BUILD_DIGEST,
            traefik_config_digest=EXPECTED_CONFIG_DIGEST,
            browser_evidence=self._browser_evidence("blocked_provider"),
        )
        self.assertEqual(blocked["browser_journey"], "blocked_provider")
        failed = traefik_proof.render_manifest(
            build_sha=EXPECTED_BUILD_SHA,
            build_digest=EXPECTED_BUILD_DIGEST,
            traefik_config_digest=EXPECTED_CONFIG_DIGEST,
            browser_evidence=self._browser_evidence("failed"),
        )
        self.assertEqual(failed["browser_evidence"]["observations"], {"failure": "browser_assertion_failed"})


if __name__ == "__main__":
    unittest.main()
