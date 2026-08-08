#!/usr/bin/env python3
"""Offline regression tests for the disposable issue #92 Traefik proof.

The tests exercise the renderer, the bounded executable ForwardAuth adapter, and
bounded static-file hashing only. They never contact Hermes, a provider, a VM,
a public address, a firewall, or a real credential service. A Traefik binary
check is optional and is reported as skipped when unavailable.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import traefik_proof  # noqa: E402


EVIDENCE_PATH = ROOT / "tests/integration/hermes-traefik/traefik-proof-evidence.json"
EVIDENCE_ANCHOR_PATH = ROOT / "tests/integration/hermes-traefik/traefik-proof-evidence-sha256.txt"
EXPECTED_BUILD_SHA = "521ede32b904a42e22eebb279fd7d404074cd318"
EXPECTED_BUILD_DIGEST = "77f6d0e8bb4977c16eb1f1eaec32000f84f346ddec9f474ebd873d7b9a833d21"
EXPECTED_CONFIG_DIGEST = "8e2a8c90f843079e9831cead252a93f6e1ffdbae0667f80bd26ae5d428ae165a"


class TraefikRendererTests(unittest.TestCase):
    """Keep the Traefik route bundle finite, private, and default-deny."""

    def setUp(self) -> None:
        self.inputs = traefik_proof.reconstruction_inputs()
        self.authority = "traefik-92.test:19444"
        self.bundle = traefik_proof.render_bundle(self.inputs)
        self.static = self.bundle["static"]
        self.dynamic = self.bundle["dynamic"]
        self.http = self.dynamic["http"]
        self.routers = self.http["routers"]
        self.middlewares = self.http["middlewares"]
        self.services = self.http["services"]

    def _headers(self, *extra: tuple[str, str]) -> list[tuple[str, str]]:
        return [("Host", self.authority), ("X-Forwarded-Host", self.authority), *extra]

    def _policy(
        self,
        method: str,
        path: str,
        query: str = "",
        *,
        headers: list[tuple[str, str]] | None = None,
        raw_target: str | None = None,
    ) -> dict[str, object]:
        return traefik_proof.policy_decision(
            runtime_inputs=self.inputs,
            method=method,
            path=path,
            query=query,
            raw_target=path + (f"?{query}" if query else "") if raw_target is None else raw_target,
            headers=self._headers() if headers is None else headers,
        )

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
        with self.assertRaisesRegex(ValueError, "directly under"):
            bad = dict(self.inputs)
            bad["dynamic_filename"] = "/tmp/traefik-dynamic.json"
            traefik_proof._validate_runtime_inputs(bad)

    def test_static_config_is_loopback_tls_and_provider_path_is_exact(self) -> None:
        entrypoint = self.static["entryPoints"]["websecure"]
        self.assertEqual(entrypoint["address"], "127.0.0.1:19444")
        self.assertEqual(entrypoint["forwardedHeaders"], {"insecure": False})
        self.assertEqual(entrypoint["http"], {"tls": {}})
        self.assertEqual(self.static["providers"]["file"]["filename"], self.inputs["dynamic_filename"])
        self.assertFalse(self.static["providers"]["file"]["watch"])
        self.assertNotIn("0.0.0.0", json.dumps(self.static))
        self.assertNotIn("::", json.dumps(self.static))

    def test_render_to_directory_is_json_loadable_and_provider_path_matches(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            inputs, bundle = traefik_proof.render_to_directory(output_dir)
            static_path = output_dir / "traefik-static.json"
            dynamic_path = output_dir / "traefik-dynamic.json"
            self.assertEqual(inputs["dynamic_filename"], str(dynamic_path.resolve()))
            self.assertEqual(bundle["static"]["providers"]["file"]["filename"], str(dynamic_path.resolve()))
            self.assertEqual(json.loads(static_path.read_text()), bundle["static"])
            self.assertEqual(json.loads(dynamic_path.read_text()), bundle["dynamic"])
            self.assertEqual(bundle["dynamic"]["tls"]["certificates"][0]["certFile"], inputs["cert_path"])

    def test_routes_are_finite_tls_enabled_and_prefix_is_explicit(self) -> None:
        for method, path in traefik_proof.EXACT_REST_ROUTES:
            if path == "/auth/callback":
                self.assertIn("root_auth_callback", self.routers)
            else:
                self.assertIn(path, json.dumps(self.routers))
        self.assertIn("dashboard_prefix", self.routers)
        self.assertEqual(
            self.routers["dashboard_prefix"]["rule"],
            "Host(`traefik-92.test`) && PathPrefix(`/hermes`)",
        )
        self.assertEqual(
            self.middlewares["strip-hermes"],
            {"stripPrefix": {"prefixes": ["/hermes"], "forceSlash": False}},
        )
        self.assertEqual(
            self.routers["client_deep_link"]["middlewares"],
            ["edge-policy", "client-deep-link-fallback"],
        )
        for name, router in self.routers.items():
            with self.subTest(router=name):
                self.assertEqual(router["entryPoints"], ["websecure"])
                self.assertEqual(router["tls"], {})
                self.assertEqual(router["middlewares"][0], "edge-policy")
        self.assertNotIn("PathPrefix(`/api`)", json.dumps(self.routers))
        self.assertNotIn("/hermes/*", json.dumps(self.routers))

    def test_policy_gate_precedes_every_service_and_wrong_host_has_authority_route(self) -> None:
        self.assertEqual(self.routers["wrong_host"]["rule"], "!Host(`traefik-92.test`)")
        policy = self.middlewares["edge-policy"]["forwardAuth"]
        self.assertEqual(policy["address"], "http://127.0.0.1:19259/check")
        self.assertFalse(policy["trustForwardHeader"])
        self.assertEqual(policy["authRequestHeaders"], list(traefik_proof.FORWARD_AUTH_HEADERS))
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

    def test_trusted_forwarding_headers_use_a_finite_known_field_override_map(self) -> None:
        root = self.middlewares["root-hermes-headers"]["headers"]["customRequestHeaders"]
        dashboard = self.middlewares["dashboard-hermes-headers"]["headers"]["customRequestHeaders"]
        websocket = self.middlewares["root-websocket-hermes-headers"]["headers"]["customRequestHeaders"]
        dashboard_websocket = self.middlewares["dashboard-websocket-hermes-headers"]["headers"]["customRequestHeaders"]
        self.assertEqual(root["X-Forwarded-Prefix"], "")
        self.assertEqual(dashboard["X-Forwarded-Prefix"], "/hermes")
        self.assertEqual(dashboard_websocket["X-Forwarded-Prefix"], "/hermes")
        for headers in (root, dashboard):
            self.assertEqual(headers["Forwarded"], "for=127.0.0.1;host=traefik-92.test:19444;proto=https")
            self.assertEqual(headers["Host"], "127.0.0.1:19257")
            self.assertEqual(headers["Origin"], "http://127.0.0.1:19257")
            self.assertEqual(headers["X-Forwarded-Proto"], "https")
            self.assertEqual(headers["X-Real-IP"], "127.0.0.1")
            self.assertNotIn("X-Forwarded-Debug", headers)
            self.assertTrue(
                {
                    name
                    for name, value in headers.items()
                    if value
                }
                <= set(traefik_proof.HERMES_FORWARDING_ALLOWLIST)
            )
            for name in traefik_proof.HOP_BY_HOP_HEADERS:
                with self.subTest(route="normal", header=name):
                    self.assertEqual(headers[name], "")
        self.assertEqual(websocket["Host"], "127.0.0.1:19257")
        self.assertEqual(websocket["Upgrade"], "websocket")
        self.assertEqual(websocket["Connection"], "Upgrade")
        for name in traefik_proof.HOP_BY_HOP_HEADERS:
            with self.subTest(route="websocket", header=name):
                expected = "websocket" if name == "Upgrade" else "Upgrade" if name == "Connection" else ""
                self.assertEqual(websocket[name], expected)

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
                result = self._policy(method, path, query)
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
        )
        for method, path, query in denied:
            with self.subTest(method=method, path=path, query=query):
                result = self._policy(method, path, query)
                self.assertEqual((result["status"], result["layer"], result["upstream_request"]), (404, "edge", False))

    def test_policy_requires_exact_host_authority_and_rejects_duplicates(self) -> None:
        cases = (
            [],
            [("Host", self.authority)],
            [("Host", self.authority), ("X-Forwarded-Host", "traefik-92.test")],
            [("Host", "traefik-92.test"), ("X-Forwarded-Host", self.authority)],
            [("Host", self.authority), ("host", self.authority), ("X-Forwarded-Host", self.authority)],
            [("Host", self.authority), ("X-Forwarded-Host", self.authority), ("x-forwarded-host", self.authority)],
        )
        for headers in cases:
            with self.subTest(headers=headers):
                result = self._policy("GET", "/", headers=headers)
                self.assertEqual((result["status"], result["layer"], result["upstream_request"]), (421, "edge", False))

    def test_policy_keeps_host_origin_ticket_and_upgrade_layers_separate(self) -> None:
        upgrade = self._headers(
            ("Origin", f"https://{self.authority}"),
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
        )
        cases = (
            ("/api/ws", "ticket=fixtureTicket", 101, "hermes", True),
            ("/hermes/api/pty", "ticket=fixtureTicket&resume=fixtureResume", 101, "hermes", True),
            ("/api/ws", "", 404, "edge", False),
            ("/api/pty", "ticket=fixtureTicket", 404, "edge", False),
        )
        for path, query, status, layer, upstream in cases:
            with self.subTest(path=path, query=query):
                result = self._policy("GET", path, query, headers=upgrade)
                self.assertEqual((result["status"], result["layer"], result["upstream_request"]), (status, layer, upstream))
        wrong_origin = self._policy(
            "GET",
            "/api/ws",
            "ticket=fixtureTicket",
            headers=self._headers(
                ("Origin", "https://evil.example"),
                ("Upgrade", "websocket"),
                ("Connection", "Upgrade"),
            ),
        )
        self.assertEqual((wrong_origin["status"], wrong_origin["layer"], wrong_origin["upstream_request"]), (403, "edge", False))
        malformed_upgrade = self._policy(
            "GET",
            "/api/ws",
            "ticket=fixtureTicket",
            headers=self._headers(("Upgrade", "websocket")),
        )
        self.assertEqual((malformed_upgrade["status"], malformed_upgrade["layer"]), (404, "edge"))
        non_websocket_upgrade = self._policy(
            "GET",
            "/",
            headers=self._headers(("Upgrade", "websocket"), ("Connection", "Upgrade")),
        )
        self.assertEqual((non_websocket_upgrade["status"], non_websocket_upgrade["layer"]), (404, "edge"))

    def test_policy_rejects_raw_path_obfuscation_mismatch_and_bare_query_marker(self) -> None:
        for path, query, raw_target in (
            ("/v1/c/abcdefghijklmnop", "", "/v1/c/abcdefghijklmnop?"),
            ("/v1/c/abcdefghijklmnop", "", "/v1/c/abcdefghijkl%2Fmnop"),
            ("/v1/c/abcdefghijklmnop", "", "/v1/c/abcdefghijkl\\mnop"),
            ("/v1/c/abcdefghijklmnop", "", "/v1/c/abcdefghijklmnop/../x"),
            ("/v1/c/abcdefghijklmnop", "", "/v1/c/.../abcdefghijklmnop"),
            ("/v1/c/abcdefghijklmnop", "scenario=success", "/v1/c/abcdefghijklmnop"),
        ):
            with self.subTest(raw_target=raw_target):
                result = self._policy("GET", path, query, raw_target=raw_target)
                self.assertEqual((result["status"], result["layer"], result["upstream_request"]), (404, "edge", False))

    def test_adapter_header_builder_reconstructs_exact_contract(self) -> None:
        original = [("Host", self.authority)]
        headers = traefik_proof.build_forward_auth_headers(
            self.inputs,
            method="GET",
            path="/v1/c/abcdefghijklmnop",
            query="",
            raw_target="/v1/c/abcdefghijklmnop",
            headers=original,
        )
        self.assertEqual(dict(headers)["Host"], self.authority)
        self.assertEqual(dict(headers)["X-Forwarded-Host"], self.authority)
        self.assertEqual(dict(headers)["X-Forwarded-Raw-Target"], "/v1/c/abcdefghijklmnop")
        with self.assertRaises(ValueError):
            traefik_proof.build_forward_auth_headers(
                self.inputs,
                method="GET",
                path="/v1/c/abcdefghijklmnop",
                query="",
                raw_target="/v1/c/abcdefghijklmnop?",
                headers=original,
            )
        with self.assertRaises(ValueError):
            traefik_proof.build_forward_auth_headers(
                self.inputs,
                method="GET",
                path="/",
                query="",
                raw_target="/",
                headers=[("Host", self.authority), ("X-Forwarded-Host", "spoof")],
            )

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
        self.assertEqual(evidence["offline_harness"]["traefik_check_config"], "skipped_unavailable")
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

    def test_bounded_static_digest_streams_content_and_rejects_unsafe_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "index.html").write_bytes(b"index")
            (root / "nested").mkdir()
            (root / "nested" / "app.js").write_bytes(b"app")
            actual = traefik_proof._build_static_digest(root)
            expected_hash = hashlib.sha256()
            for relative, content in (("index.html", b"index"), ("nested/app.js", b"app")):
                expected_hash.update(relative.encode() + b"\0" + str(len(content)).encode() + b"\0" + content)
            self.assertEqual(actual, expected_hash.hexdigest())
            if hasattr(os, "symlink"):
                (root / "link").symlink_to(root / "index.html")
                with self.assertRaisesRegex(ValueError, "symlinks"):
                    traefik_proof._build_static_digest(root)

    def test_bounded_static_digest_rejects_fifo_and_all_resource_limits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "one").write_bytes(b"one")
            (root / "two").write_bytes(b"two")
            if hasattr(os, "mkfifo"):
                os.mkfifo(root / "pipe")
                with self.assertRaisesRegex(ValueError, "special files"):
                    traefik_proof._build_static_digest(root)
            (root / "pipe").unlink(missing_ok=True)
            with mock.patch.object(traefik_proof, "MAX_DIGEST_FILES", 1):
                with self.assertRaisesRegex(ValueError, "file-count"):
                    traefik_proof._build_static_digest(root)
            with mock.patch.object(traefik_proof, "MAX_DIGEST_TOTAL_BYTES", 2):
                with self.assertRaisesRegex(ValueError, "byte"):
                    traefik_proof._build_static_digest(root)
            with mock.patch.object(traefik_proof, "MAX_DIGEST_FILE_BYTES", 2):
                with self.assertRaisesRegex(ValueError, "per-file"):
                    traefik_proof._build_static_digest(root)
            with mock.patch.object(traefik_proof, "MAX_DIGEST_PATH_BYTES", 2):
                with self.assertRaisesRegex(ValueError, "path"):
                    traefik_proof._build_static_digest(root)
            (root / "deep").mkdir()
            (root / "deep" / "asset").write_bytes(b"x")
            with mock.patch.object(traefik_proof, "MAX_DIGEST_DEPTH", 0):
                with self.assertRaisesRegex(ValueError, "depth"):
                    traefik_proof._build_static_digest(root)
            with mock.patch.object(traefik_proof, "MAX_DIGEST_SECONDS", 0):
                with self.assertRaisesRegex(ValueError, "time budget"):
                    traefik_proof._build_static_digest(root)

    def test_bounded_static_digest_rejects_replacement_race(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "asset.js"
            path.write_bytes(b"original")
            real_read = traefik_proof.os.read
            replaced = False

            def replacing_read(descriptor: int, size: int) -> bytes:
                nonlocal replaced
                chunk = real_read(descriptor, size)
                if chunk and not replaced:
                    replaced = True
                    path.write_bytes(b"changed!")
                return chunk

            with mock.patch.object(traefik_proof.os, "read", side_effect=replacing_read):
                with self.assertRaisesRegex(ValueError, "changed while reading"):
                    traefik_proof._digest_regular_file(path)

    def test_optional_traefik_check_is_explicitly_skipped_when_binary_is_unavailable(self) -> None:
        binary = traefik_proof.find_traefik_binary()
        if binary is None:
            self.skipTest("Traefik binary unavailable; check-config is explicitly skipped")
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            traefik_proof.render_to_directory(output_dir)
            result = traefik_proof.run_traefik_check_config(binary, output_dir)
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)


class ForwardAuthAdapterTests(unittest.TestCase):
    """Exercise actual bounded HTTP requests against the local adapter."""

    def setUp(self) -> None:
        self.inputs = traefik_proof.reconstruction_inputs()
        self.authority = "traefik-92.test:19444"
        self.server = traefik_proof.make_forward_auth_server(self.inputs)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()

    def _send(self, headers: list[tuple[str, str]], *, body: bytes = b"", request_target: str = "/check") -> tuple[int, dict[str, str]]:
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=2)
        try:
            connection.connect()
            connection.putrequest("POST", request_target, skip_host=True, skip_accept_encoding=True)
            sent_names = {name.lower() for name, _ in headers}
            for name, value in headers:
                connection.putheader(name, value)
            if body and "content-length" not in sent_names:
                connection.putheader("Content-Length", str(len(body)))
            connection.endheaders(body if body else None)
            response = connection.getresponse()
            response.read()
            return response.status, {key.lower(): value for key, value in response.getheaders()}
        finally:
            connection.close()

    def _forwarded(self, *, method: str = "GET", path: str = "/", query: str = "", websocket: bool = False) -> list[tuple[str, str]]:
        original: list[tuple[str, str]] = [("Host", self.authority)]
        if websocket:
            original.extend(
                [
                    ("Origin", f"https://{self.authority}"),
                    ("Upgrade", "websocket"),
                    ("Connection", "Upgrade"),
                ]
            )
        return traefik_proof.build_forward_auth_headers(
            self.inputs,
            method=method,
            path=path,
            query=query,
            raw_target=path + (f"?{query}" if query else ""),
            headers=original,
        )

    def test_actual_http_requests_allow_and_deny_at_adapter(self) -> None:
        allowed_status, allowed_headers = self._send(self._forwarded())
        self.assertEqual(allowed_status, 200)
        self.assertEqual(allowed_headers["x-hermternal-policy"], "allow")
        denied = self._forwarded(path="/", query="", method="GET")
        denied = [(name, "/?" if name == "X-Forwarded-Raw-Target" else value) for name, value in denied]
        denied = [(name, "/?" if name == "X-Forwarded-Uri" else value) for name, value in denied]
        denied_status, denied_headers = self._send(denied)
        self.assertEqual(denied_status, 404)
        self.assertEqual(denied_headers["x-hermternal-policy"], "deny")

    def test_adapter_proves_forwarded_websocket_fields_and_rejects_hop_by_hop_spoofing(self) -> None:
        status, headers = self._send(self._forwarded(path="/api/ws", query="ticket=fixtureTicket", websocket=True))
        self.assertEqual(status, 200)
        self.assertEqual(headers["x-hermternal-policy"], "allow")
        malformed = self._forwarded(path="/api/ws", query="ticket=fixtureTicket", websocket=True)
        malformed = [(name, "") if name == "X-Forwarded-Connection" else (name, value) for name, value in malformed]
        status, _ = self._send(malformed)
        self.assertEqual(status, 400)
        direct_hop = self._forwarded()
        direct_hop.append(("Connection", "Upgrade"))
        status, _ = self._send(direct_hop)
        self.assertEqual(status, 400)

    def test_adapter_rejects_duplicate_authority_unknown_metadata_and_unbounded_body(self) -> None:
        headers = self._forwarded()
        headers.append(("host", self.authority))
        status, _ = self._send(headers)
        self.assertEqual(status, 400)
        headers = self._forwarded()
        headers.append(("X-Forwarded-Host", self.authority))
        status, _ = self._send(headers)
        self.assertEqual(status, 400)
        headers = self._forwarded()
        headers.append(("X-Forwarded-Unknown", "spoof"))
        status, _ = self._send(headers)
        self.assertEqual(status, 400)
        status, _ = self._send(self._forwarded(), body=b"x" * (traefik_proof.MAX_POLICY_BODY_BYTES + 1))
        self.assertEqual(status, 413)

    def test_adapter_bounds_request_line_header_count_and_header_bytes(self) -> None:
        too_many = self._forwarded()
        too_many.extend((f"X-Extra-{index}", "x") for index in range(traefik_proof.MAX_FORWARD_HEADER_COUNT))
        status, _ = self._send(too_many)
        self.assertEqual(status, 400)
        too_large = self._forwarded()
        too_large.append(("X-Noise", "x" * traefik_proof.MAX_FORWARD_HEADER_BYTES))
        status, _ = self._send(too_large)
        self.assertIn(status, {400, 431})
        status, _ = self._send(
            self._forwarded(),
            request_target="/" + "x" * traefik_proof.MAX_REQUEST_TARGET_BYTES,
        )
        self.assertEqual(status, 414)

    def test_adapter_rejects_missing_raw_target_and_malformed_authority(self) -> None:
        headers = [(name, value) for name, value in self._forwarded() if name != "X-Forwarded-Raw-Target"]
        status, _ = self._send(headers)
        self.assertEqual(status, 400)
        headers = self._forwarded()
        headers = [(name, "traefik-92.test") if name == "Host" else (name, value) for name, value in headers]
        status, _ = self._send(headers)
        self.assertEqual(status, 400)


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

    def test_evidence_shape_is_closed_and_honest(self) -> None:
        self.assertEqual(
            set(self.evidence),
            {
                "schema",
                "issue",
                "contract",
                "deployment",
                "product",
                "proof_run",
                "browser_journey",
                "browser_evidence",
                "positive_cases",
                "negative_cases",
                "model_assertions",
                "offline_harness",
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
        self.assertEqual(self.evidence["proof_run"], traefik_proof._synthetic_proof_run())
        self.assertEqual(self.evidence["offline_harness"]["status"], "regression_tested")
        self.assertEqual(self.evidence["offline_harness"]["traefik_check_config"], "skipped_unavailable")
        self.assertEqual(len(self.evidence["positive_cases"]), 11)
        self.assertEqual(len(self.evidence["negative_cases"]), 23)

    def test_proof_run_is_reconstructed_and_not_caller_mutable(self) -> None:
        first = traefik_proof._synthetic_proof_run()
        first["status"] = "live"
        self.assertEqual(traefik_proof._synthetic_proof_run()["status"], "synthetic_observed")
        with self.assertRaises(TypeError):
            traefik_proof.DEFAULT_RUNTIME_INPUTS["host"] = "evil"  # type: ignore[index]

    def test_render_manifest_requires_provenance_bound_browser_evidence(self) -> None:
        with self.assertRaisesRegex(ValueError, "browser evidence is required"):
            traefik_proof.render_manifest(
                build_sha=EXPECTED_BUILD_SHA,
                build_digest=EXPECTED_BUILD_DIGEST,
                traefik_config_digest=EXPECTED_CONFIG_DIGEST,
            )
        with self.assertRaisesRegex(ValueError, "stale or mismatched"):
            traefik_proof.render_manifest(
                build_sha=EXPECTED_BUILD_SHA,
                build_digest=EXPECTED_BUILD_DIGEST,
                traefik_config_digest=EXPECTED_CONFIG_DIGEST,
                browser_evidence=self._browser_evidence("blocked_provider", provenance={"build_sha": "0" * 40}),
            )

    def test_browser_events_do_not_upgrade_synthetic_deployment_claim(self) -> None:
        manifest = traefik_proof.render_manifest(
            build_sha=EXPECTED_BUILD_SHA,
            build_digest=EXPECTED_BUILD_DIGEST,
            traefik_config_digest=EXPECTED_CONFIG_DIGEST,
            browser_journey="passed",
            browser_evidence=self._browser_evidence("passed"),
        )
        self.assertEqual(manifest["browser_journey"], "passed")
        self.assertEqual(manifest["proof_run"], traefik_proof._synthetic_proof_run())
        self.assertFalse(manifest["proof_run"]["live_run"])
        self.assertFalse(manifest["proof_run"]["compatible"])


if __name__ == "__main__":
    unittest.main()
