#!/usr/bin/env python3
"""Offline regression tests for the disposable issue #92 Traefik proof.

The tests exercise the renderer, the bounded executable ForwardAuth adapter, and
bounded static-file hashing only. They never contact Hermes, a provider, a VM,
a public address, a firewall, or a real credential service. Traefik itself is
not started or validated by this offline lane.
"""

from __future__ import annotations

import hashlib
import http.client
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager, redirect_stdout
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
EXPECTED_CONFIG_DIGEST = "3da2c93e74b4c205cac0aee16fcbed93cb6e87948b59e4592e1247a426da5e36"
RETAINED_PARSER_COMMIT = "a9d323b522438fe6d3bf6839c0c249eba0e3645d"
RETAINED_PARSER_BLOB = "f2d60fe74ff8343ab6c1466ff9f38abcfc2dd657"
RETAINED_PARSER_SOURCE_SHA256 = "683cd633311c0314bda5433265077dce3c182616bec2099bae57a8c519b9c325"
RETAINED_PARSER_TEST_SHA256 = "24d40f7a810ad251fb00e6632a3c60928cfb450e74064e2a8731e30fd0f7a1df"
RETAINED_RUNTIME_INPUTS_SHA256 = "4880b6d1ca97fe22b2f0015dce5d5f446354969edf42a282eed1237ce96c0114"
RETAINED_STATIC_ROUTE_SHA256 = "f0542d97b363b8e2a921e93001d72dd0f56d5f30001f15e95bbca5b2f4165165"
RETAINED_DEEP_LINK_SHA256 = "91fad69ec110ea8042678b963076056b4474072d24f9698067ed8bfc10c03d96"


def _run_git(cwd: Path, *arguments: str, input_data: bytes | None = None) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        input=input_data,
        check=True,
        capture_output=True,
        text=input_data is None,
    )
    return completed.stdout.decode("utf-8").strip() if input_data is not None else completed.stdout.strip()


def _create_parser_repo(root: Path, *, object_format: str = "sha1") -> tuple[bytes, bytes, str]:
    scripts_root = root / "scripts"
    scripts_root.mkdir(parents=True)
    implementation = (ROOT / traefik_proof.PARSER_IMPLEMENTATION_PATH).read_bytes()
    test_source = (ROOT / traefik_proof.PARSER_TEST_PATH).read_bytes()
    (scripts_root / "traefik_proof.py").write_bytes(implementation)
    (scripts_root / "test_traefik_proof.py").write_bytes(test_source)
    init_args = ["init", "--quiet"]
    if object_format == "sha256":
        init_args.append("--object-format=sha256")
    _run_git(root, *init_args)
    _run_git(root, "config", "user.name", "Hermternal test")
    _run_git(root, "config", "user.email", "hermternal-test@example.invalid")
    _run_git(root, "add", "scripts")
    _run_git(root, "commit", "--quiet", "-m", "parser source")
    source_commit = _run_git(root, "rev-parse", "HEAD")
    return implementation, test_source, source_commit


def _append_fast_history(root: Path, count: int) -> None:
    """Create many unchanged descendants in one import process for the budget test."""

    if count < 1:
        return
    parent = _run_git(root, "rev-parse", "HEAD")
    stream = bytearray()
    for index in range(1, count + 1):
        message = f"evidence {index}\n".encode("ascii")
        timestamp = 1_700_000_000 + index
        stream.extend(
            f"commit refs/heads/fast-history\nmark :{index}\nauthor Hermternal test <hermternal-test@example.invalid> {timestamp} +0000\ncommitter Hermternal test <hermternal-test@example.invalid> {timestamp} +0000\ndata {len(message)}\n".encode("ascii")
        )
        stream.extend(message)
        stream.extend(f"from {parent if index == 1 else ':' + str(index - 1)}\n".encode("ascii"))
    stream.extend(b"done\n")
    subprocess.run(["git", "fast-import"], cwd=root, input=bytes(stream), check=True, capture_output=True)
    _run_git(root, "reset", "--quiet", "--hard", "fast-history")


@contextmanager
def _same_path_copy(path: Path):
    """Replace one metadata path at the same name, then restore the original."""

    replacement = path.with_name(f".{path.name}.replacement")
    original = path.with_name(f".{path.name}.original")
    if path.is_dir():
        shutil.copytree(path, replacement)
    else:
        shutil.copy2(path, replacement)
    path.rename(original)
    replacement.rename(path)
    try:
        yield
    finally:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        elif path.exists() or path.is_symlink():
            path.unlink()
        original.rename(path)


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
        return [
            ("Host", self.authority),
            ("X-Forwarded-Host", self.authority),
            ("X-Forwarded-Port", "19444"),
            ("X-Forwarded-Proto", "https"),
            *extra,
        ]

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

    def test_all_retained_route_cases_execute_private_vectors(self) -> None:
        cases = [*traefik_proof.POSITIVE_CASES, *traefik_proof.NEGATIVE_CASES]
        case_ids = [case["id"] for case in cases]
        self.assertEqual(case_ids, list(traefik_proof.ROUTE_CASE_VECTORS))
        self.assertEqual([case["vector_id"] for case in cases], case_ids)
        self.assertEqual(len(case_ids), 34)

        executed: dict[str, dict[str, object]] = {}
        for case in cases:
            case_id = str(case["id"])
            vector = traefik_proof.ROUTE_CASE_VECTORS[case_id]
            with self.subTest(case=case_id):
                if vector["kind"] != "network":
                    policy_observed = traefik_proof.policy_decision_for_case(case, self.inputs)
                    expected_policy = vector.get(
                        "policy_expected",
                        {
                            "status": case["status"],
                            "layer": case["layer"],
                            "upstream_request": case["upstream_request"],
                        },
                    )
                    self.assertEqual(
                        {key: policy_observed[key] for key in ("status", "layer", "upstream_request")},
                        expected_policy,
                    )
                observed = traefik_proof.route_case_observation(case, self.inputs)
                self.assertEqual(
                    {key: observed[key] for key in ("status", "layer", "upstream_request")},
                    {key: case[key] for key in ("status", "layer", "upstream_request")},
                )
                executed[case_id] = observed

        for case_id in ("deep_link_session", "deep_link_message"):
            vector = traefik_proof.ROUTE_CASE_VECTORS[case_id]
            self.assertEqual(traefik_proof.spa_fallback_path(str(vector["path"])), "/200.html")
        self.assertEqual(
            self.middlewares["dashboard-hermes-headers"]["headers"]["customRequestHeaders"],
            traefik_proof._request_headers("traefik-92.test:19444", 19444, 19257, "/hermes"),
        )

        ticket_ledger = traefik_proof.SyntheticTicketLedger()
        self.assertEqual(ticket_ledger.consume("unknown", now=0), "invalid")
        ticket_ledger.issue("expired", now=0)
        self.assertEqual(ticket_ledger.consume("expired", now=traefik_proof.TICKET_TTL_SECONDS), "expired")
        ticket_ledger.issue("reuse", now=0)
        self.assertEqual(ticket_ledger.consume("reuse", now=1), "accepted")
        self.assertEqual(ticket_ledger.consume("reuse", now=2), "reused")

        blocked_ids = [
            case_id
            for case_id, result in executed.items()
            if result["upstream_request"] is False
        ]
        no_upstream = traefik_proof.edge_no_upstream_observation()
        self.assertEqual(no_upstream["blocked_case_ids"], blocked_ids)
        self.assertEqual(no_upstream["blocked_case_count"], 20)
        self.assertEqual(no_upstream["blocked_layers"], ["edge", "network"])
        self.assertFalse(no_upstream["upstream_request"])

    def test_renderer_inputs_reject_ambiguous_hosts_ports_and_paths(self) -> None:
        self.assertEqual(traefik_proof._validate_host("traefik-92.test"), "traefik-92.test")
        self.assertEqual(traefik_proof._validate_host("a" * 63 + ".test"), "a" * 63 + ".test")
        with self.assertRaises(ValueError):
            traefik_proof._validate_host("traefik..test")
        with self.assertRaises(ValueError):
            traefik_proof._validate_host(123)  # type: ignore[arg-type]
        for malformed_host in (
            "wrong-.test",
            "wrong.-test",
            "a.-.b",
            "a" * 64 + ".test",
            "a.test.",
            "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 62 + "e",
        ):
            with self.subTest(host=malformed_host):
                bad = dict(self.inputs)
                bad["host"] = malformed_host
                with self.assertRaises(ValueError):
                    traefik_proof._validate_runtime_inputs(bad)
                with self.assertRaises(ValueError):
                    traefik_proof.render_bundle(bad)
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
        with self.assertRaisesRegex(ValueError, "path size"):
            too_long = dict(self.inputs)
            too_long["site_root"] = "/" + "x" * traefik_proof.MAX_RUNTIME_PATH_BYTES
            traefik_proof._validate_runtime_inputs(too_long)

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
            expected_static = (json.dumps(bundle["static"], sort_keys=True, indent=2) + "\n").encode("utf-8")
            expected_dynamic = (json.dumps(bundle["dynamic"], sort_keys=True, indent=2) + "\n").encode("utf-8")
            self.assertEqual(static_path.read_bytes(), expected_static)
            self.assertEqual(dynamic_path.read_bytes(), expected_dynamic)
            self.assertEqual(json.loads(static_path.read_text()), bundle["static"])
            self.assertEqual(json.loads(dynamic_path.read_text()), bundle["dynamic"])
            self.assertEqual(bundle["dynamic"]["tls"]["certificates"][0]["certFile"], inputs["cert_path"])

    def test_render_cli_compact_stdout_is_canonical(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(traefik_proof.main(["render"]), 0)
        expected = (
            json.dumps(traefik_proof.render_bundle(), sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        self.assertEqual(output.getvalue().encode("utf-8"), expected)

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
                expected_first_middleware = "edge-deny" if name.endswith("_deny") else "edge-policy"
                self.assertEqual(router["middlewares"][0], expected_first_middleware)
        self.assertNotIn("PathPrefix(`/api`)", json.dumps(self.routers))
        self.assertNotIn("/hermes/*", json.dumps(self.routers))

    def test_websocket_routers_require_client_handshake_headers(self) -> None:
        websocket_routers = (
            "root_chat_ws",
            "root_pty_ws",
            "dashboard_chat_ws",
            "dashboard_pty_ws",
        )
        expected_matchers = (
            "HeaderRegexp(`Upgrade`, `(?i)^websocket$`)",
            "HeaderRegexp(`Connection`, `(?i)(^|.*,\\s*)Upgrade(\\s*,.*|$)`)",
        )
        for name in websocket_routers:
            with self.subTest(router=name):
                rule = self.routers[name]["rule"]
                for matcher in expected_matchers:
                    self.assertIn(matcher, rule)
                self.assertNotIn("HeadersRegexp", rule)

    def test_malformed_websocket_paths_have_explicit_deny_routers(self) -> None:
        for name, path in (
            ("root_chat_ws_deny", "/api/ws"),
            ("root_pty_ws_deny", "/api/pty"),
            ("dashboard_chat_ws_deny", "/hermes/api/ws"),
            ("dashboard_pty_ws_deny", "/hermes/api/pty"),
        ):
            with self.subTest(router=name):
                router = self.routers[name]
                self.assertEqual(router["rule"], f"Host(`traefik-92.test`) && Path(`{path}`)")
                self.assertEqual(router["priority"], 710)
                self.assertEqual(router["middlewares"], ["edge-deny"])
                self.assertEqual(router["service"], "policy-deny")
        self.assertEqual(
            self.middlewares["edge-deny"]["forwardAuth"]["address"],
            "http://127.0.0.1:19259/deny",
        )

    def test_policy_gate_precedes_every_service_and_wrong_host_has_authority_route(self) -> None:
        self.assertEqual(self.routers["wrong_host"]["rule"], "!Host(`traefik-92.test`)")
        policy = self.middlewares["edge-policy"]["forwardAuth"]
        self.assertEqual(policy["address"], "http://127.0.0.1:19259/check")
        self.assertFalse(policy["trustForwardHeader"])
        self.assertEqual(policy["authRequestHeaders"], list(traefik_proof.FORWARD_AUTH_HEADERS))
        self.assertNotIn("https://", policy["address"])

    def test_forward_auth_config_matches_adapter_header_contract(self) -> None:
        policy = self.middlewares["edge-policy"]["forwardAuth"]
        forwarded = traefik_proof.build_traefik_forward_auth_headers(
            self.inputs,
            method="GET",
            path="/",
            query="",
            headers=[("Host", self.authority), ("Origin", f"https://{self.authority}")],
        )
        configured_names = [
            *traefik_proof.TRAEFIK_FORWARDAUTH_GENERATED_HEADERS,
            *policy["authRequestHeaders"],
        ]
        self.assertEqual([name for name, _value in forwarded], configured_names)
        self.assertEqual(set(configured_names), set(traefik_proof.TRAEFIK_FORWARDAUTH_HEADERS))
        method, path, query, policy_headers = traefik_proof._forward_auth_policy_input(
            self.inputs, forwarded
        )
        self.assertEqual((method, path, query), ("GET", "/", ""))
        self.assertEqual(
            policy_headers,
            [
                ("X-Forwarded-Host", self.authority),
                ("X-Forwarded-Port", "19444"),
                ("X-Forwarded-Proto", "https"),
                ("Origin", f"https://{self.authority}"),
            ],
        )

    def test_wrong_host_vector_preserves_noncanonical_forwarded_authority(self) -> None:
        vector = traefik_proof.ROUTE_CASE_VECTORS["wrong_host"]
        headers = traefik_proof._route_case_headers(self.inputs, vector)
        self.assertEqual(
            dict(headers)["X-Forwarded-Host"],
            "wrong.test:19444",
        )
        self.assertEqual(
            traefik_proof.policy_decision_for_case(
                {"id": "wrong_host"}, self.inputs
            ),
            {"status": 421, "layer": "edge", "upstream_request": False},
        )

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
            self.assertEqual(headers["X-Forwarded-Port"], "19444")
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

    def test_policy_requires_exact_forwarded_port(self) -> None:
        wrong_port = self._headers()
        wrong_port = [
            (name, "443") if name == "X-Forwarded-Port" else (name, value)
            for name, value in wrong_port
        ]
        result = self._policy("GET", "/", headers=wrong_port)
        self.assertEqual((result["status"], result["layer"], result["upstream_request"]), (421, "edge", False))
        missing_port = [
            (name, value) for name, value in self._headers() if name != "X-Forwarded-Port"
        ]
        result = self._policy("GET", "/", headers=missing_port)
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

    def test_policy_rejects_c0_del_and_c1_request_target_controls(self) -> None:
        controls = ("\x00", "\x1f", "\x7f", "\x80", "\x9f")
        for control in controls:
            with self.subTest(control=ord(control)):
                path = f"/_app/foo{control}X"
                result = self._policy("GET", path, raw_target=path)
                self.assertEqual(
                    (result["status"], result["layer"], result["upstream_request"]),
                    (404, "edge", False),
                )
                with self.assertRaisesRegex(ValueError, "control"):
                    traefik_proof._bounded_request_uri(path, "")
                query = f"scenario=success{control}X"
                result = self._policy("GET", "/", query, raw_target=f"/?{query}")
                self.assertEqual(
                    (result["status"], result["layer"], result["upstream_request"]),
                    (404, "edge", False),
                )
                raw_target = f"/_app/foo{control}X"
                result = self._policy("GET", "/_app/fooX", raw_target=raw_target)
                self.assertEqual(
                    (result["status"], result["layer"], result["upstream_request"]),
                    (404, "edge", False),
                )

    def test_adapter_header_builder_reconstructs_standard_traefik_contract(self) -> None:
        original = [
            ("Host", self.authority),
            ("Origin", f"https://{self.authority}"),
        ]
        headers = traefik_proof.build_traefik_forward_auth_headers(
            self.inputs,
            method="GET",
            path="/v1/c/abcdefghijklmnop",
            query="",
            headers=original,
        )
        self.assertEqual(
            headers,
            [
                ("X-Forwarded-For", "127.0.0.1"),
                ("X-Forwarded-Host", self.authority),
                ("X-Forwarded-Method", "GET"),
                ("X-Forwarded-Port", "19444"),
                ("X-Forwarded-Proto", "https"),
                ("X-Forwarded-Uri", "/v1/c/abcdefghijklmnop"),
                ("Origin", f"https://{self.authority}"),
            ],
        )
        self.assertEqual(
            [name for name, _value in headers],
            [
                *traefik_proof.TRAEFIK_FORWARDAUTH_GENERATED_HEADERS,
                *traefik_proof.FORWARD_AUTH_HEADERS,
            ],
        )
        self.assertNotIn("Host", {name for name, _value in headers})
        with self.assertRaises(ValueError):
            traefik_proof.build_traefik_forward_auth_headers(
                self.inputs,
                method="GET",
                path="/",
                query="",
                headers=[("Host", self.authority), ("host", self.authority)],
            )

    def test_prefix_mapping_and_spa_fallback_are_exactly_bounded(self) -> None:
        self.assertEqual(
            traefik_proof.map_public_path("/hermes"),
            {"public_prefix": "/hermes", "upstream_path": "/", "stripped": True},
        )
        self.assertEqual(
            traefik_proof.map_public_path("/hermes/api/auth/providers"),
            {"public_prefix": "/hermes", "upstream_path": "/api/auth/providers", "stripped": True},
        )
        self.assertEqual(
            traefik_proof.map_public_path("/api/auth/providers"),
            {"public_prefix": "", "upstream_path": "/api/auth/providers", "stripped": False},
        )
        for path in (
            "/hermes/hermes/api/ws",
            "/hermes/hermes",
            "/hermesx/api/ws",
            "/hermes/../api/ws",
            "/hermes/%2Fapi/ws",
            "/hermes\x00/api/ws",
        ):
            with self.subTest(path=path):
                self.assertIsNone(traefik_proof.map_public_path(path))
        self.assertEqual(traefik_proof.spa_fallback_path("/v1/c/abcdefghijklmnop"), "/200.html")
        self.assertEqual(
            traefik_proof.spa_fallback_path("/v1/c/abcdefghijklmnop/m/qrstuvwxyzabcdef"),
            "/200.html",
        )
        for path in ("/v1/c/short", "/v1/c/abcdefghijklmnop?x", "/_app/app.js", "/v1/c/foo\x7f"):
            with self.subTest(path=path):
                self.assertIsNone(traefik_proof.spa_fallback_path(path))

    def test_secure_prefixed_cookie_canary_is_synthetic_and_closed(self) -> None:
        observed = traefik_proof.secure_prefixed_cookie_observation(
            "__Host-fixture=synthetic; Secure; HttpOnly; SameSite=Lax; Path=/"
        )
        self.assertEqual(observed["status"], "synthetic_observed")
        self.assertEqual(observed["name_prefix"], "__Host-")
        self.assertEqual(observed["scope"], "/hermes")
        self.assertEqual(observed["attributes"], ["Secure", "HttpOnly", "SameSite=Lax", "Path=/"])
        self.assertEqual(observed["value"], "redacted")
        invalid = (
            "__Host-fixture=synthetic; HttpOnly; SameSite=Lax; Path=/",
            "__Host-fixture=synthetic; Secure; SameSite=Lax; Path=/",
            "__Host-fixture=synthetic; Secure; HttpOnly; SameSite=None; Path=/",
            "__Host-fixture=synthetic; Secure; HttpOnly; SameSite=Lax; Path=/hermes",
            "__Host-fixture=synthetic; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=example.test",
            "__Host-fixture=synthetic; Secure; HttpOnly; SameSite=Lax; Path=/; Secure",
            "__Host-fixture=synthetic; Secure; HttpOnly; SameSite=Lax; Path=/; Priority=High",
        )
        for header in invalid:
            with self.subTest(header=header):
                with self.assertRaises(ValueError):
                    traefik_proof.secure_prefixed_cookie_observation(header)

    def test_ticket_lifecycle_is_single_use_expiring_and_redacted(self) -> None:
        ledger = traefik_proof.SyntheticTicketLedger(ttl_seconds=30)
        ledger.issue("fixtureTicket", now=0)
        self.assertEqual(ledger.consume("fixtureTicket", now=1), "accepted")
        self.assertEqual(ledger.consume("fixtureTicket", now=2), "reused")
        ledger.issue("expiredTicket", now=0)
        self.assertEqual(ledger.consume("expiredTicket", now=30), "expired")
        self.assertEqual(ledger.consume("unknownTicket", now=1), "invalid")
        redacted = traefik_proof.redact_ticket_material("/api/ws", "ticket=fixtureTicket")
        self.assertEqual(
            redacted,
            {
                "request_target": "redacted",
                "query": "redacted",
                "ticket": "redacted",
                "ticket_fragment": "redacted",
            },
        )
        self.assertNotIn("fixtureTicket", json.dumps(redacted))
        observation = traefik_proof.synthetic_ticket_lifecycle_observation()
        self.assertEqual(observation["first_use"], "accepted")
        self.assertEqual(observation["reused_use"], "reused")
        self.assertEqual(observation["expired_use"], "expired")
        self.assertEqual(observation["invalid_use"], "invalid")
        self.assertEqual(observation["retry"], "disabled")

    def test_pty_lifecycle_detaches_and_reaps_without_retaining_input(self) -> None:
        ttl_seconds = traefik_proof.PTY_DETACHED_TTL_SECONDS
        before_boundary = traefik_proof.SyntheticPtyLifecycle(ttl_seconds=ttl_seconds)
        self.assertEqual(before_boundary.attach("fixtureBeforeBoundary", now=0), "attached")
        self.assertEqual(before_boundary.detach("fixtureBeforeBoundary", now=0), "detached")
        self.assertEqual(
            before_boundary.reattach("fixtureBeforeBoundary", now=ttl_seconds - 1),
            "reattached",
        )

        boundary = traefik_proof.SyntheticPtyLifecycle(ttl_seconds=ttl_seconds)
        self.assertEqual(boundary.attach("fixtureAttach", now=0), "attached")
        self.assertEqual(boundary.send_input("fixtureAttach", b"synthetic-input"), "forwarded")
        self.assertEqual(boundary.detach("fixtureAttach", now=0), "detached")
        # Exactly 1800 seconds remains eligible for reattach before reap.
        self.assertEqual(boundary.reap(now=ttl_seconds), 0)
        self.assertEqual(boundary.reattach("fixtureAttach", now=ttl_seconds), "reattached")
        self.assertEqual(boundary.send_input("fixtureAttach", b"after-reattach"), "forwarded")

        expired = traefik_proof.SyntheticPtyLifecycle(ttl_seconds=ttl_seconds)
        self.assertEqual(expired.attach("fixtureExpired", now=0), "attached")
        self.assertEqual(expired.detach("fixtureExpired", now=0), "detached")
        # Reattach rejects 1801 seconds even when periodic cleanup has not run.
        with self.assertRaisesRegex(ValueError, "exceeded retention TTL"):
            expired.reattach("fixtureExpired", now=ttl_seconds + 1)
        # Periodic cleanup still starts strictly after the 1800-second boundary.
        self.assertEqual(expired.reap(now=ttl_seconds + 1), 1)
        with self.assertRaises(ValueError):
            expired.reattach("fixtureExpired", now=ttl_seconds + 1)

        observation = traefik_proof.synthetic_pty_lifecycle_observation()
        self.assertEqual(observation["boundary_elapsed_seconds"], ttl_seconds)
        self.assertEqual(observation["boundary_reap"], 0)
        self.assertEqual(observation["boundary_reattach"], "reattached")
        self.assertEqual(observation["expired_elapsed_seconds"], ttl_seconds + 1)
        self.assertEqual(observation["expired_reattach_before_reap"], "rejected")
        self.assertEqual(observation["before_ttl_reap"], 0)
        self.assertEqual(observation["ttl_reap"], 1)
        self.assertEqual(observation["retry"], "disabled")
        self.assertEqual(observation["retained_material"], "redacted")

    def test_pty_lifecycle_rejects_invalid_timestamps_on_every_operation(self) -> None:
        invalid_timestamps = (
            float("nan"),
            float("inf"),
            float("-inf"),
            True,
            False,
            "0",
            None,
            -1,
            traefik_proof.MAX_PTY_TIMESTAMP_SECONDS + 1,
            1 << 100,
            -(1 << 100),
        )
        for operation in ("attach", "detach", "reattach", "reap"):
            for value in invalid_timestamps:
                with self.subTest(operation=operation, value=repr(value)):
                    lifecycle = traefik_proof.SyntheticPtyLifecycle()
                    if operation == "attach":
                        call = lambda: lifecycle.attach("fixtureInvalid", now=value)
                    elif operation == "detach":
                        lifecycle.attach("fixtureInvalid", now=0)
                        call = lambda: lifecycle.detach("fixtureInvalid", now=value)
                    elif operation == "reattach":
                        lifecycle.attach("fixtureInvalid", now=0)
                        lifecycle.detach("fixtureInvalid", now=0)
                        call = lambda: lifecycle.reattach("fixtureInvalid", now=value)
                    else:
                        lifecycle.attach("fixtureInvalid", now=0)
                        lifecycle.detach("fixtureInvalid", now=0)
                        call = lambda: lifecycle.reap(now=value)
                    with self.assertRaisesRegex(ValueError, "finite number"):
                        call()

    def test_pty_lifecycle_rejects_backward_time(self) -> None:
        lifecycle = traefik_proof.SyntheticPtyLifecycle()
        lifecycle.attach("fixtureAttach", now=10)
        with self.assertRaisesRegex(ValueError, "precedes stored"):
            lifecycle.attach("fixtureAttach", now=9)

        lifecycle = traefik_proof.SyntheticPtyLifecycle()
        lifecycle.attach("fixtureAttach", now=10)
        with self.assertRaisesRegex(ValueError, "precedes stored"):
            lifecycle.detach("fixtureAttach", now=9)

        lifecycle = traefik_proof.SyntheticPtyLifecycle()
        lifecycle.attach("fixtureAttach", now=10)
        lifecycle.detach("fixtureAttach", now=10)
        with self.assertRaisesRegex(ValueError, "precedes stored"):
            lifecycle.reattach("fixtureAttach", now=9)

        lifecycle = traefik_proof.SyntheticPtyLifecycle()
        lifecycle.attach("fixtureAttach", now=10)
        with self.assertRaisesRegex(ValueError, "precedes stored"):
            lifecycle.reattach("fixtureAttach", now=9)

        lifecycle = traefik_proof.SyntheticPtyLifecycle()
        lifecycle.attach("fixtureAttach", now=10)
        lifecycle.detach("fixtureAttach", now=10)
        with self.assertRaisesRegex(ValueError, "precedes stored"):
            lifecycle.reap(now=9)

    def test_pty_lifecycle_advances_active_reattach_clock_and_preserves_same_time_idempotence(self) -> None:
        lifecycle = traefik_proof.SyntheticPtyLifecycle()
        self.assertEqual(lifecycle.attach("fixtureActive", now=10), "attached")
        self.assertEqual(lifecycle.reattach("fixtureActive", now=20), "already_attached")
        self.assertEqual(lifecycle.reattach("fixtureActive", now=20), "already_attached")
        with self.assertRaisesRegex(ValueError, "precedes stored"):
            lifecycle.detach("fixtureActive", now=15)
        self.assertEqual(lifecycle.detach("fixtureActive", now=20), "detached")

    def test_pty_lifecycle_reap_preflights_all_clocks_and_is_atomic(self) -> None:
        active = traefik_proof.SyntheticPtyLifecycle()
        active.attach("fixtureActive", now=10)
        states_before = dict(active._states)
        clocks_before = dict(active._last_event_at)
        with self.assertRaisesRegex(ValueError, "precedes stored"):
            active.reap(now=9)
        self.assertEqual(active._states, states_before)
        self.assertEqual(active._last_event_at, clocks_before)

        mixed = traefik_proof.SyntheticPtyLifecycle()
        mixed.attach("fixtureFuture", now=2000)
        mixed.attach("fixtureDetached", now=0)
        mixed.detach("fixtureDetached", now=0)
        states_before = dict(mixed._states)
        clocks_before = dict(mixed._last_event_at)
        with self.assertRaisesRegex(ValueError, "precedes stored"):
            mixed.reap(now=1801)
        self.assertEqual(mixed._states, states_before)
        self.assertEqual(mixed._last_event_at, clocks_before)

        survivors = traefik_proof.SyntheticPtyLifecycle()
        survivors.attach("fixtureDetached", now=0)
        survivors.detach("fixtureDetached", now=0)
        self.assertEqual(survivors.reap(now=traefik_proof.PTY_DETACHED_TTL_SECONDS), 0)
        with self.assertRaisesRegex(ValueError, "precedes stored"):
            survivors.reattach("fixtureDetached", now=traefik_proof.PTY_DETACHED_TTL_SECONDS - 1)
        self.assertEqual(
            survivors.reattach("fixtureDetached", now=traefik_proof.PTY_DETACHED_TTL_SECONDS),
            "reattached",
        )

    def test_pty_lifecycle_rejects_duplicate_attach_without_reviving_retained_state(self) -> None:
        lifecycle = traefik_proof.SyntheticPtyLifecycle()
        lifecycle.attach("fixtureDuplicate", now=0)
        lifecycle.detach("fixtureDuplicate", now=0)
        states_before = dict(lifecycle._states)
        clocks_before = dict(lifecycle._last_event_at)
        with self.assertRaisesRegex(ValueError, "already exists"):
            lifecycle.attach("fixtureDuplicate", now=traefik_proof.PTY_DETACHED_TTL_SECONDS + 1)
        self.assertEqual(lifecycle._states, states_before)
        self.assertEqual(lifecycle._last_event_at, clocks_before)
        with self.assertRaisesRegex(ValueError, "exceeded retention TTL"):
            lifecycle.reattach("fixtureDuplicate", now=traefik_proof.PTY_DETACHED_TTL_SECONDS + 1)
        self.assertEqual(lifecycle.reap(now=traefik_proof.PTY_DETACHED_TTL_SECONDS + 1), 1)
        with self.assertRaisesRegex(ValueError, "has been reaped"):
            lifecycle.reattach("fixtureDuplicate", now=traefik_proof.PTY_DETACHED_TTL_SECONDS + 1)
        # A fully reaped ID is a new identity; only retained IDs are unique.
        self.assertEqual(
            lifecycle.attach("fixtureDuplicate", now=traefik_proof.PTY_DETACHED_TTL_SECONDS + 1),
            "attached",
        )
        with self.assertRaisesRegex(ValueError, "has been reaped"):
            lifecycle.reattach("fixtureUnknown", now=0)

    def test_pty_lifecycle_accepts_zero_maximum_subsecond_and_near_ttl_timestamps(self) -> None:
        lifecycle = traefik_proof.SyntheticPtyLifecycle()
        self.assertEqual(lifecycle.attach("fixtureZero", now=0), "attached")
        self.assertEqual(lifecycle.detach("fixtureZero", now=0), "detached")
        self.assertEqual(lifecycle.reattach("fixtureZero", now=0), "reattached")
        self.assertEqual(
            lifecycle.attach("fixtureMaximum", now=traefik_proof.MAX_PTY_TIMESTAMP_SECONDS),
            "attached",
        )

        fractional = traefik_proof.SyntheticPtyLifecycle()
        fractional.attach("fixtureFractional", now=0.25)
        fractional.detach("fixtureFractional", now=0.5)
        self.assertEqual(fractional.reattach("fixtureFractional", now=1799.75), "reattached")

        near_ttl = traefik_proof.SyntheticPtyLifecycle()
        near_ttl.attach("fixtureNearTtl", now=0)
        near_ttl.detach("fixtureNearTtl", now=0)
        self.assertEqual(near_ttl.reattach("fixtureNearTtl", now=1799.999), "reattached")

    def test_private_boundary_no_retry_and_no_upstream_observation_are_explicit(self) -> None:
        boundary = traefik_proof.private_hermes_boundary_observation()
        self.assertEqual(boundary["port"], 9119)
        self.assertEqual(boundary["bind_class"], "private_non_loopback")
        self.assertFalse(boundary["public_exposure"])
        self.assertEqual(boundary["direct_result"], "connection_denied")
        self.assertEqual(traefik_proof.upgrade_retry_policy(), {"chat": "disabled", "pty": "disabled"})
        no_upstream = traefik_proof.edge_no_upstream_observation()
        self.assertEqual(no_upstream["blocked_case_count"], 20)
        self.assertTrue(no_upstream["all_blocked_cases_have_no_upstream_request"])
        self.assertFalse(no_upstream["upstream_request"])
        self.assertIn("network", no_upstream["blocked_layers"])
        self.assertIn("direct_private_port", no_upstream["blocked_case_ids"])

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
        self.assertEqual(
            evidence["offline_harness"]["traefik_runtime"],
            "not_run; configuration and rule compatibility are not claimed",
        )
        self.assertEqual(evidence["traefik_runtime"]["required_minimum_version"], "v3.7.6")
        self.assertEqual(evidence["traefik_runtime"]["runtime_validation"], traefik_proof.TRAEFIK_RUNTIME_VALIDATION)
        raw = EVIDENCE_PATH.read_text(encoding="utf-8")
        for forbidden in (
            "?ticket=",
            "Cookie:",
            "Set-Cookie:",
            "Authorization:",
            "Bearer ",
            "password=",
            "api_key=",
        ):
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

    def test_bounded_static_digest_rejects_collected_ancestor_symlink(self) -> None:
        """A directory replaced after collection cannot redirect hashing outside the site."""

        with tempfile.TemporaryDirectory() as temporary:
            sandbox = Path(temporary)
            root = sandbox / "site"
            nested = root / "nested"
            outside = sandbox / "outside"
            root.mkdir()
            nested.mkdir()
            outside.mkdir()
            (nested / "app.js").write_bytes(b"inside-static-content")
            (outside / "app.js").write_bytes(b"outside-attacker-content")
            real_collect = traefik_proof._collect_static_files
            swapped = False

            def collect_then_swap(site_root: Path) -> object:
                nonlocal swapped
                result = real_collect(site_root)
                nested.rename(root / "nested-original")
                nested.symlink_to(outside, target_is_directory=True)
                swapped = True
                return result

            try:
                with mock.patch.object(traefik_proof, "_collect_static_files", side_effect=collect_then_swap):
                    with self.assertRaisesRegex(ValueError, "symlinked path component|ancestor changed|site_root changed"):
                        traefik_proof._build_static_digest(root)
            finally:
                if swapped:
                    nested.unlink()
                    (root / "nested-original").rename(nested)

    def test_bounded_static_digest_rejects_collected_site_root_symlink(self) -> None:
        """A site-root replacement after collection cannot redirect hashing outside the site."""

        with tempfile.TemporaryDirectory() as temporary:
            sandbox = Path(temporary)
            root = sandbox / "site"
            outside = sandbox / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "app.js").write_bytes(b"inside-static-content")
            (outside / "app.js").write_bytes(b"outside-attacker-content")
            real_collect = traefik_proof._collect_static_files
            swapped = False

            def collect_then_swap(site_root: Path) -> object:
                nonlocal swapped
                result = real_collect(site_root)
                root.rename(sandbox / "site-original")
                root.symlink_to(outside, target_is_directory=True)
                swapped = True
                return result

            try:
                with mock.patch.object(traefik_proof, "_collect_static_files", side_effect=collect_then_swap):
                    with self.assertRaisesRegex(ValueError, "symlinked path component|site_root"):
                        traefik_proof._build_static_digest(root)
            finally:
                if swapped:
                    root.unlink()
                    (sandbox / "site-original").rename(root)

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

    def test_bounded_static_digest_checks_root_and_empty_directory_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root_limit = len(os.fsencode(str(root)))
            self.assertIsInstance(traefik_proof._build_static_digest(root), str)
            with mock.patch.object(traefik_proof, "MAX_DIGEST_PATH_BYTES", root_limit - 1):
                with self.assertRaisesRegex(ValueError, "site_root path"):
                    traefik_proof._build_static_digest(root)
            empty_child = root / "empty-directory"
            empty_child.mkdir()
            child_limit = len(os.fsencode(str(empty_child)))
            with mock.patch.object(traefik_proof, "MAX_DIGEST_PATH_BYTES", child_limit - 1):
                with self.assertRaisesRegex(ValueError, "directory path"):
                    traefik_proof._build_static_digest(root)

    def test_bounded_static_digest_rejects_traversal_breadth_and_pending_limits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index in range(3):
                (root / f"asset-{index}.js").write_bytes(b"x")
            with mock.patch.object(traefik_proof, "MAX_DIGEST_ENTRIES", 2):
                with self.assertRaisesRegex(ValueError, "directory-entry"):
                    traefik_proof._build_static_digest(root)

            (root / "asset-0.js").unlink()
            (root / "asset-1.js").unlink()
            (root / "asset-2.js").unlink()
            (root / "empty-a").mkdir()
            (root / "empty-b").mkdir()
            with mock.patch.object(traefik_proof, "MAX_DIGEST_DIRECTORIES", 2):
                with self.assertRaisesRegex(ValueError, "directory-count"):
                    traefik_proof._build_static_digest(root)
            with mock.patch.object(traefik_proof, "MAX_DIGEST_PENDING_DIRECTORIES", 1):
                with self.assertRaisesRegex(ValueError, "pending-directory"):
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

    def test_bounded_evidence_and_digest_readers_reject_oversize_and_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence.json"
            evidence.write_bytes(b"x" * (traefik_proof.BROWSER_EVIDENCE_MAX_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "bounded input size"):
                traefik_proof._read_bounded_regular_file(
                    evidence,
                    traefik_proof.BROWSER_EVIDENCE_MAX_BYTES,
                    "browser evidence",
                )
            digest_input = root / "digest.bin"
            digest_input.write_bytes(b"x" * (traefik_proof.MAX_DIGEST_FILE_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "per-file digest limit"):
                traefik_proof._digest_regular_file(digest_input)
            if hasattr(os, "symlink"):
                link = root / "link.json"
                link.symlink_to(evidence)
                with self.assertRaisesRegex(ValueError, "regular non-symlink"):
                    traefik_proof._read_bounded_regular_file(link, 10, "browser evidence")

    def test_bounded_stdin_digest_reads_incrementally_and_rejects_overflow(self) -> None:
        class RecordingStream:
            def __init__(self, content: bytes) -> None:
                self.content = content
                self.offset = 0
                self.read_sizes: list[int] = []

            def read(self, size: int) -> bytes:
                self.read_sizes.append(size)
                start = self.offset
                self.offset += size
                return self.content[start : start + size]

        stream = RecordingStream(b"fixture")
        self.assertEqual(
            traefik_proof._digest_stdin(stream, limit=32),
            hashlib.sha256(b"fixture").hexdigest(),
        )
        self.assertTrue(stream.read_sizes)
        self.assertLessEqual(max(stream.read_sizes), traefik_proof.MAX_DIGEST_CHUNK_BYTES)
        overflow = RecordingStream(b"12345")
        with self.assertRaisesRegex(ValueError, "stdin digest exceeded"):
            traefik_proof._digest_stdin(overflow, limit=4)
        self.assertTrue(all(size <= 5 for size in overflow.read_sizes))
        with mock.patch.object(traefik_proof, "MAX_DIGEST_TOTAL_BYTES", 4):
            global_overflow = RecordingStream(b"12345")
            with self.assertRaisesRegex(ValueError, "stdin digest exceeded"):
                traefik_proof._digest_stdin(global_overflow, limit=16)

    def test_direct_header_and_runtime_mapping_inputs_are_bounded(self) -> None:
        with self.assertRaisesRegex(ValueError, "too many headers"):
            traefik_proof._header_items(
                ((f"X-Extra-{index}", "x") for index in range(traefik_proof.MAX_FORWARD_HEADER_COUNT + 1))
            )
        with self.assertRaisesRegex(ValueError, "too many headers"):
            traefik_proof._header_values(
                ((f"X-Extra-{index}", "x") for index in range(traefik_proof.MAX_FORWARD_HEADER_COUNT + 1)),
                "Host",
            )
        oversized = dict(self.inputs)
        oversized.update({f"extra-{index}": index for index in range(128)})
        with self.assertRaisesRegex(ValueError, "exact renderer input keys"):
            traefik_proof._validate_runtime_inputs(oversized)

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

    def _send_raw_x_forwarded_host(
        self,
        value: bytes,
        *,
        forwarded_for: bytes = b"127.0.0.1",
        forwarded_method: bytes = b"GET",
        forwarded_port: bytes = b"19444",
        forwarded_proto: bytes = b"https",
        origin: bytes | None = None,
        folded_suffix: bytes = b"",
    ) -> tuple[int, dict[str, str]]:
        """Send raw authority bytes before BaseHTTPRequestHandler normalization."""

        port = str(self.server.server_address[1]).encode("ascii")
        origin_line = b"" if origin is None else b"Origin: " + origin + b"\r\n"
        request = b"".join(
            (
                b"POST /check HTTP/1.0\r\n",
                b"Host: 127.0.0.1:" + port + b"\r\n",
                b"X-Forwarded-For: " + forwarded_for + b"\r\n",
                b"X-Forwarded-Host: " + value + b"\r\n",
                folded_suffix,
                b"X-Forwarded-Method: " + forwarded_method + b"\r\n",
                b"X-Forwarded-Port: " + forwarded_port + b"\r\n",
                b"X-Forwarded-Proto: " + forwarded_proto + b"\r\n",
                b"X-Forwarded-Uri: /\r\n",
                origin_line,
                b"\r\n",
            )
        )
        connection = socket.create_connection(("127.0.0.1", self.server.server_address[1]), timeout=2)
        try:
            connection.sendall(request)
            response = http.client.HTTPResponse(connection)
            response.begin()
            response.read()
            return response.status, {key.lower(): value for key, value in response.getheaders()}
        finally:
            connection.close()

    def _forwarded(
        self,
        *,
        method: str = "GET",
        path: str = "/",
        query: str = "",
        origin: str | None = None,
    ) -> list[tuple[str, str]]:
        original: list[tuple[str, str]] = [("Host", self.authority)]
        if origin is not None:
            original.append(("Origin", origin))
        return traefik_proof.build_traefik_forward_auth_headers(
            self.inputs,
            method=method,
            path=path,
            query=query,
            headers=original,
        )

    def test_actual_http_requests_allow_and_deny_at_adapter(self) -> None:
        allowed_status, allowed_headers = self._send(self._forwarded())
        self.assertEqual(allowed_status, 200)
        self.assertEqual(allowed_headers["x-hermternal-policy"], "allow")
        denied = self._forwarded(path="/", query="", method="GET")
        denied = [(name, "/unknown" if name == "X-Forwarded-Uri" else value) for name, value in denied]
        denied_status, denied_headers = self._send(denied)
        self.assertEqual(denied_status, 404)
        self.assertEqual(denied_headers["x-hermternal-policy"], "deny")
        wrong_host = [
            (name, "wrong.test:19444") if name == "X-Forwarded-Host" else (name, value)
            for name, value in self._forwarded()
        ]
        wrong_status, wrong_headers = self._send(wrong_host)
        self.assertEqual(wrong_status, 421)
        self.assertEqual(wrong_headers["x-hermternal-policy"], "deny")

    def test_adapter_allows_only_explicit_transport_headers_beside_forwardauth(self) -> None:
        transport_headers = self._forwarded() + [
            ("Host", "127.0.0.1:19259"),
            ("Content-Length", "0"),
            ("User-Agent", "Traefik/3.7.6"),
            ("Accept-Encoding", "gzip"),
            ("Connection", "close"),
        ]
        status, response_headers = self._send(transport_headers)
        self.assertEqual(status, 200)
        self.assertEqual(response_headers["x-hermternal-policy"], "allow")
        for forbidden in (
            ("Authorization", "Bearer synthetic-token"),
            ("Cookie", "session=synthetic-cookie"),
            ("Accept", "application/json"),
            ("X-Forwarded-Unknown", "spoof"),
        ):
            with self.subTest(header=forbidden[0]):
                status, _ = self._send(self._forwarded() + [forbidden])
                self.assertEqual(status, 400)

    def test_adapter_rejects_c0_del_and_c1_forwarded_uri_controls(self) -> None:
        for control in ("\x00", "\x1f", "\x7f", "\x80", "\x9f"):
            with self.subTest(control=ord(control)):
                forwarded = self._forwarded()
                forwarded = [
                    (name, f"/_app/foo{control}X") if name == "X-Forwarded-Uri" else (name, value)
                    for name, value in forwarded
                ]
                status, _ = self._send(forwarded)
                self.assertEqual(status, 400)

    def test_adapter_accepts_websocket_uri_without_claiming_handshake_metadata(self) -> None:
        forwarded = self._forwarded(
            path="/api/ws",
            query="ticket=fixtureTicket",
            origin=f"https://{self.authority}",
        )
        names = {name for name, _value in forwarded}
        self.assertNotIn("Upgrade", names)
        self.assertNotIn("Connection", names)
        self.assertEqual(
            names,
            set(traefik_proof.TRAEFIK_FORWARDAUTH_HEADERS),
        )
        status, headers = self._send(forwarded)
        self.assertEqual(status, 200)
        self.assertEqual(headers["x-hermternal-policy"], "allow")
        deny_status, deny_headers = self._send(self._forwarded(), request_target="/deny")
        self.assertEqual(deny_status, 404)
        self.assertEqual(deny_headers["x-hermternal-policy"], "deny")

    def test_adapter_rejects_duplicate_forwarded_metadata_and_unbounded_body(self) -> None:
        headers = self._forwarded()
        headers.append(("X-Forwarded-Host", self.authority))
        status, _ = self._send(headers)
        self.assertEqual(status, 400)
        headers = self._forwarded()
        headers.append(("X-Forwarded-Uri", "/"))
        status, _ = self._send(headers)
        self.assertEqual(status, 400)
        headers = self._forwarded()
        headers.append(("X-Forwarded-Unknown", "spoof"))
        status, _ = self._send(headers)
        self.assertEqual(status, 400)
        headers = [
            (name, "443") if name == "X-Forwarded-Port" else (name, value)
            for name, value in self._forwarded()
        ]
        status, _ = self._send(headers)
        self.assertEqual(status, 400)
        headers = self._forwarded()
        headers.append(("Connection", "Upgrade"))
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

    def test_adapter_rejects_missing_uri_and_malformed_authority(self) -> None:
        headers = [(name, value) for name, value in self._forwarded() if name != "X-Forwarded-Uri"]
        status, _ = self._send(headers)
        self.assertEqual(status, 400)
        headers = [
            (name, "traefik-92.test") if name == "X-Forwarded-Host" else (name, value)
            for name, value in self._forwarded()
        ]
        status, response_headers = self._send(headers)
        self.assertEqual(status, 400)
        self.assertEqual(response_headers["x-hermternal-policy"], "deny")

    def test_adapter_raw_authority_vectors_keep_valid_wrong_host_at_421(self) -> None:
        max_host = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61)).encode("ascii")
        invalid_authorities = (
            ("empty", b""),
            ("space", b" "),
            ("nul", b"\x00"),
            ("c0", b"\x1f"),
            ("del", b"\x7f"),
            ("missing_port", b"wrong.test"),
            ("empty_port", b"wrong.test:"),
            ("non_numeric_port", b"wrong.test:notaport"),
            ("zero_port", b"wrong.test:0"),
            ("zero_padded_port", b"wrong.test:00001"),
            ("short_padded_port", b"wrong.test:01"),
            ("out_of_range_port", b"wrong.test:65536"),
            ("trailing_label_hyphen", b"wrong-.test:19444"),
            ("leading_label_hyphen", b"wrong.-test:19444"),
            ("hyphen_only_label", b"a.-.b:19444"),
            ("empty_label", b"wrong..test:19444"),
            ("trailing_dot", b"wrong.test.:19444"),
            ("label_over_63", b"a" * 64 + b".test:19444"),
            ("host_over_253", max_host + b"e:19444"),
            ("malformed_bracket", b"[::1:19444"),
            ("unbracketed_ipv6", b"::1:19444"),
            ("bracket_without_separator", b"[::1]19444"),
            ("userinfo", b"user@wrong.test:19444"),
        )
        for label, authority in invalid_authorities:
            with self.subTest(authority=label):
                status, response_headers = self._send_raw_x_forwarded_host(authority)
                self.assertEqual(status, 400)
                self.assertEqual(response_headers["x-hermternal-policy"], "deny")

        valid_authorities = (
            ("canonical", b"traefik-92.test:19444", 200, "allow"),
            ("valid_wrong", b"wrong.test:19444", 421, "deny"),
            ("valid_bracketed_ipv6", b"[::1]:19444", 421, "deny"),
            ("valid_max_label", b"a" * 63 + b".test:19444", 421, "deny"),
            ("valid_max_host", max_host + b":19444", 421, "deny"),
            ("max_port", b"wrong.test:65535", 421, "deny"),
        )
        for label, authority, expected_status, expected_policy in valid_authorities:
            with self.subTest(authority=label):
                status, response_headers = self._send_raw_x_forwarded_host(authority)
                self.assertEqual(status, expected_status)
                self.assertEqual(response_headers["x-hermternal-policy"], expected_policy)

    def test_adapter_preserves_leading_ows_and_rejects_other_ows_before_policy(self) -> None:
        leading_ows = b" \t"
        status, response_headers = self._send_raw_x_forwarded_host(
            leading_ows + b"traefik-92.test:19444",
            forwarded_for=leading_ows + b"127.0.0.1",
            forwarded_port=leading_ows + b"19444",
            forwarded_proto=leading_ows + b"https",
            origin=leading_ows + b"https://traefik-92.test:19444",
        )
        self.assertEqual(status, 200)
        self.assertEqual(response_headers["x-hermternal-policy"], "allow")

        for label, kwargs in (
            ("host_trailing_ows", {"value": b"traefik-92.test:19444 "}),
            ("host_internal_ows", {"value": b"traefik-92.test: 19444"}),
            ("xff_internal_ows", {"value": b"traefik-92.test:19444", "forwarded_for": b"127.0.0.1 10.0.0.1"}),
            ("xff_only_ows", {"value": b"traefik-92.test:19444", "forwarded_for": b" \t"}),
            ("port_trailing_ows", {"value": b"traefik-92.test:19444", "forwarded_port": b"19444 "}),
            ("proto_internal_ows", {"value": b"traefik-92.test:19444", "forwarded_proto": b"ht tps"}),
            ("origin_trailing_ows", {"value": b"traefik-92.test:19444", "origin": b"https://traefik-92.test:19444 "}),
        ):
            with self.subTest(authority=label):
                status, response_headers = self._send_raw_x_forwarded_host(**kwargs)
                self.assertEqual(status, 400)
                self.assertEqual(response_headers["x-hermternal-policy"], "deny")

        for label, forwarded_for in (
            ("xff_trailing_ows", b"127.0.0.1 "),
            ("xff_comma_ows_chain", b"127.0.0.1, \t10.0.0.1"),
            ("xff_ipv6", b"::1"),
        ):
            with self.subTest(authority=label):
                status, response_headers = self._send_raw_x_forwarded_host(
                    b"traefik-92.test:19444",
                    forwarded_for=forwarded_for,
                )
                self.assertEqual(status, 200)
                self.assertEqual(response_headers["x-hermternal-policy"], "allow")

        for label, kwargs in (
            ("empty_method", {"value": b"traefik-92.test:19444", "forwarded_method": b""}),
            ("ows_only_method", {"value": b"traefik-92.test:19444", "forwarded_method": b" \t"}),
            ("malformed_method", {"value": b"traefik-92.test:19444", "forwarded_method": b"GET /"}),
            ("garbage_xff", {"value": b"traefik-92.test:19444", "forwarded_for": b"not-an-ip"}),
            ("comma_garbage_xff", {"value": b"traefik-92.test:19444", "forwarded_for": b"127.0.0.1,garbage"}),
            ("trailing_comma_xff", {"value": b"traefik-92.test:19444", "forwarded_for": b"127.0.0.1,"}),
            ("ows_only_origin", {"value": b"traefik-92.test:19444", "origin": b" \t"}),
            ("malformed_origin", {"value": b"traefik-92.test:19444", "origin": b"not-an-origin"}),
        ):
            with self.subTest(authority=label):
                status, response_headers = self._send_raw_x_forwarded_host(**kwargs)
                self.assertEqual(status, 400)
                self.assertEqual(response_headers["x-hermternal-policy"], "deny")

        for label, authority in (
            ("canonical_obs_fold", b"traefik-92.test:19444"),
            ("wrong_obs_fold", b"wrong.test:19444"),
        ):
            with self.subTest(authority=label):
                status, response_headers = self._send_raw_x_forwarded_host(
                    authority,
                    folded_suffix=b"\t\r\n",
                )
                self.assertEqual(status, 400)
                self.assertEqual(response_headers["x-hermternal-policy"], "deny")


class TraefikEvidenceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))

    def _parser_provenance(self) -> dict[str, str]:
        return dict(self.evidence["forward_auth_contract"]["parser_provenance"])

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
                "traefik_runtime",
                "forward_auth_contract",
                "product",
                "proof_run",
                "browser_journey",
                "browser_evidence",
                "positive_cases",
                "negative_cases",
                "model_assertions",
                "offline_harness",
                "cookie_proof",
                "ticket_lifecycle",
                "pty_lifecycle",
                "upgrade_retry_policy",
                "hermes_boundary",
                "edge_no_upstream",
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
                "required_hermes_port",
                "required_hermes_bind_class",
                "public_hermes_exposure",
                "production_topology",
            },
        )
        self.assertEqual(set(deployment["runtime_inputs"]), set(traefik_proof.DEFAULT_RUNTIME_INPUTS))
        self.assertEqual(set(deployment["parity_fixtures"]), {"static_route_grammar", "deep_link_cases"})
        self.assertEqual(
            self.evidence["traefik_runtime"],
            {
                "status": traefik_proof.TRAEFIK_RUNTIME_STATUS,
                "version": traefik_proof.TRAEFIK_RUNTIME_VERSION,
                "required_minimum_version": traefik_proof.TRAEFIK_RUNTIME_REQUIRED_MINIMUM_VERSION,
                "runtime_validation": traefik_proof.TRAEFIK_RUNTIME_VALIDATION,
                "rule_syntax": traefik_proof.TRAEFIK_RULE_SYNTAX,
            },
        )
        contract = self.evidence["forward_auth_contract"]
        self.assertEqual(
            set(contract["parser_provenance"]),
            {
                "implementation_path",
                "implementation_commit",
                "implementation_blob",
                "implementation_sha256",
                "test_path",
                "test_source_sha256",
            },
        )
        self.assertEqual(contract["parser_provenance"]["implementation_path"], traefik_proof.PARSER_IMPLEMENTATION_PATH)
        self.assertEqual(contract["parser_provenance"]["test_path"], traefik_proof.PARSER_TEST_PATH)
        self.assertEqual(contract["generated_headers"], list(traefik_proof.TRAEFIK_FORWARDAUTH_GENERATED_HEADERS))
        self.assertEqual(contract["copied_headers"], list(traefik_proof.FORWARD_AUTH_HEADERS))
        self.assertEqual(contract["transport_headers"], list(traefik_proof.FORWARD_AUTH_TRANSPORT_HEADERS))
        self.assertIn("transport-only", contract["auth_request_host"])
        self.assertFalse(contract["runtime_observed"])
        self.assertIn("configured HTTPS entrypoint port", contract["port"])
        self.assertIn("not raw-target", contract["uri"])
        self.assertIn("router-matcher-only", contract["websocket"])
        self.assertIn("rejected", contract["hop_by_hop"])
        self.assertEqual(set(self.evidence["browser_evidence"]), set(traefik_proof.BROWSER_EVIDENCE_ROOT_KEYS))
        self.assertEqual(self.evidence["browser_evidence"]["observations"], {"blocker": "provider_unavailable"})
        self.assertEqual(self.evidence["proof_run"], traefik_proof._synthetic_proof_run())
        self.assertEqual(deployment["required_hermes_port"], traefik_proof.REQUIRED_HERMES_PORT)
        self.assertEqual(deployment["required_hermes_bind_class"], traefik_proof.REQUIRED_HERMES_BIND_CLASS)
        self.assertFalse(deployment["public_hermes_exposure"])
        self.assertEqual(deployment["production_topology"], traefik_proof.PROOF_RUN_REQUIRED_TOPOLOGY)
        self.assertEqual(self.evidence["offline_harness"]["status"], "declared")
        self.assertEqual(
            self.evidence["offline_harness"]["traefik_runtime"],
            "not_run; configuration and rule compatibility are not claimed",
        )
        self.assertIn("no_upstream_observation", self.evidence["offline_harness"])
        self.assertEqual(self.evidence["cookie_proof"]["status"], "not_proven")
        self.assertEqual(self.evidence["cookie_proof"]["synthetic_model"]["value"], "redacted")
        self.assertEqual(self.evidence["ticket_lifecycle"]["retry"], "disabled")
        self.assertEqual(self.evidence["pty_lifecycle"]["expired_reattach_before_reap"], "rejected")
        self.assertEqual(self.evidence["pty_lifecycle"]["duplicate_attach"], "rejected")
        self.assertEqual(self.evidence["pty_lifecycle"]["ttl_reap"], 1)
        self.assertEqual(self.evidence["upgrade_retry_policy"], {"chat": "disabled", "pty": "disabled"})
        self.assertEqual(self.evidence["hermes_boundary"], traefik_proof.private_hermes_boundary_observation())
        self.assertEqual(self.evidence["edge_no_upstream"]["blocked_case_count"], 20)
        self.assertEqual(len(self.evidence["positive_cases"]), 11)
        self.assertEqual(len(self.evidence["negative_cases"]), 23)
        retained_cases = [*self.evidence["positive_cases"], *self.evidence["negative_cases"]]
        self.assertEqual(
            [case["id"] for case in retained_cases],
            [case["id"] for case in [*traefik_proof.POSITIVE_CASES, *traefik_proof.NEGATIVE_CASES]],
        )
        self.assertEqual([case["vector_id"] for case in retained_cases], list(traefik_proof.ROUTE_CASE_VECTORS))
        for case in retained_cases:
            with self.subTest(case=case["id"]):
                self.assertIn(case["proof_level"], {"model", "model_plus_router_rule", "model_boundary_only"})
                self.assertIn("observed_by", case)
                self.assertNotIn("method", case)
                self.assertNotIn("path", case)
                self.assertNotIn("query", case)
                self.assertNotIn("headers", case)

    def test_evidence_binds_parser_commit_blob_and_test_source(self) -> None:
        """Retained evidence stays bound to its approved historical source commit."""

        provenance = self._parser_provenance()
        committed_source = subprocess.check_output(
            ["git", "show", f"{provenance['implementation_commit']}:{provenance['implementation_path']}"],
            cwd=ROOT,
        )
        committed_tests = subprocess.check_output(
            ["git", "show", f"{provenance['implementation_commit']}:{provenance['test_path']}"],
            cwd=ROOT,
        )
        self.assertEqual(
            hashlib.sha256(committed_source).hexdigest(),
            provenance["implementation_sha256"],
        )
        self.assertEqual(
            hashlib.sha256(committed_tests).hexdigest(),
            provenance["test_source_sha256"],
        )
        blob = subprocess.check_output(
            ["git", "rev-parse", f"{provenance['implementation_commit']}:{provenance['implementation_path']}"],
            cwd=ROOT,
            text=True,
        ).strip()
        self.assertEqual(blob, provenance["implementation_blob"])

    def _repo_with_evidence(self, root: Path) -> tuple[bytes, bytes, str, str]:
        implementation, test_source, source_commit = _create_parser_repo(root)
        (root / "retained-evidence.json").write_text("{}\n", encoding="utf-8")
        _run_git(root, "add", "retained-evidence.json")
        _run_git(root, "commit", "--quiet", "-m", "evidence only")
        return implementation, test_source, source_commit, _run_git(root, "rev-parse", "HEAD")

    def test_retained_contract_binds_reviewed_values(self) -> None:
        """The retained JSON is checked against reviewed values, not only its self-hash."""

        parser = self.evidence["forward_auth_contract"]["parser_provenance"]
        self.assertEqual(self.evidence["product"], {"build_commit": EXPECTED_BUILD_SHA, "static_manifest_sha256": EXPECTED_BUILD_DIGEST})
        self.assertEqual(self.evidence["browser_evidence"]["provenance"]["build_sha"], EXPECTED_BUILD_SHA)
        self.assertEqual(self.evidence["browser_evidence"]["provenance"]["build_digest"], EXPECTED_BUILD_DIGEST)
        self.assertEqual(self.evidence["browser_evidence"]["provenance"]["traefik_config_digest"], EXPECTED_CONFIG_DIGEST)
        self.assertEqual(self.evidence["browser_evidence"]["provenance"]["runtime_inputs_sha256"], RETAINED_RUNTIME_INPUTS_SHA256)
        self.assertEqual(self.evidence["deployment"]["runtime_inputs_sha256"], RETAINED_RUNTIME_INPUTS_SHA256)
        self.assertEqual(parser["implementation_commit"], RETAINED_PARSER_COMMIT)
        self.assertEqual(parser["implementation_blob"], RETAINED_PARSER_BLOB)
        self.assertEqual(parser["implementation_sha256"], RETAINED_PARSER_SOURCE_SHA256)
        self.assertEqual(parser["test_source_sha256"], RETAINED_PARSER_TEST_SHA256)
        self.assertEqual(self.evidence["deployment"]["parity_fixtures"]["static_route_grammar"]["path"], traefik_proof.PARITY_FIXTURE_PATHS["static_route_grammar"])
        self.assertEqual(self.evidence["deployment"]["parity_fixtures"]["deep_link_cases"]["path"], traefik_proof.PARITY_FIXTURE_PATHS["deep_link_cases"])
        self.assertEqual(self.evidence["deployment"]["parity_fixtures"]["static_route_grammar"]["sha256"], RETAINED_STATIC_ROUTE_SHA256)
        self.assertEqual(self.evidence["deployment"]["parity_fixtures"]["deep_link_cases"]["sha256"], RETAINED_DEEP_LINK_SHA256)
        self.assertEqual(
            EVIDENCE_ANCHOR_PATH.read_text(encoding="ascii").strip(),
            hashlib.sha256(EVIDENCE_PATH.read_bytes()).hexdigest(),
        )

    def test_tampering_retained_json_and_anchor_does_not_self_authorize(self) -> None:
        """Recomputing the self-hash cannot replace the reviewed retained contract."""

        tampered = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        tampered["product"]["build_commit"] = "0" * 40
        tampered["browser_evidence"]["provenance"]["build_sha"] = "0" * 40
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "evidence.json"
            anchor = Path(temporary) / "evidence.sha256"
            encoded = (json.dumps(tampered, sort_keys=True, indent=2) + "\n").encode("utf-8")
            path.write_bytes(encoded)
            anchor.write_text(hashlib.sha256(encoded).hexdigest() + "\n", encoding="ascii")
            loaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(anchor.read_text(encoding="ascii").strip(), hashlib.sha256(path.read_bytes()).hexdigest())
            with self.assertRaises(AssertionError):
                self.assertEqual(loaded["product"]["build_commit"], EXPECTED_BUILD_SHA)
            with self.assertRaises(AssertionError):
                self.assertEqual(loaded["browser_evidence"]["provenance"]["build_sha"], EXPECTED_BUILD_SHA)

    def test_external_build_sha_contract_accepts_sha1_and_sha256(self) -> None:
        """Product build identity is cross-repository and supports both hash widths."""

        for width in (40, 64):
            self.assertEqual(traefik_proof._validate_external_git_oid("a" * width, "build_sha"), "a" * width)
        for value in ("A" * 40, "a" * 39, "a" * 63, "a" * 65):
            with self.assertRaises(ValueError):
                traefik_proof._validate_external_git_oid(value, "build_sha")

    def test_shallow_clone_with_evidence_descendant_fails_closed(self) -> None:
        """A depth-one clone cannot promote its evidence-only tip to source identity."""

        with tempfile.TemporaryDirectory() as temporary:
            source_root = Path(temporary) / "source"
            clone_root = Path(temporary) / "clone"
            source_root.mkdir()
            _create_parser_repo(source_root)
            (source_root / "retained-evidence.json").write_text("{}\n", encoding="utf-8")
            _run_git(source_root, "add", "retained-evidence.json")
            _run_git(source_root, "commit", "--quiet", "-m", "evidence only")
            subprocess.run(
                ["git", "clone", "--quiet", "--depth=1", f"file://{source_root}", str(clone_root)],
                check=True,
                capture_output=True,
            )
            with self.assertRaisesRegex(ValueError, "shallow"):
                traefik_proof._current_parser_provenance(clone_root)

    def test_linked_worktree_shallow_metadata_fails_closed(self) -> None:
        """The shared shallow marker is rejected when a linked worktree is inspected."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            linked = Path(temporary) / "linked"
            root.mkdir()
            _implementation, _tests, source_commit = _create_parser_repo(root)
            _run_git(root, "worktree", "add", "--quiet", "-b", "linked", str(linked))
            (root / ".git" / "shallow").write_text(source_commit + "\n", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "shallow"):
                traefik_proof._current_parser_provenance(linked)

    def test_malformed_history_and_git_failure_fail_closed(self) -> None:
        """Malformed topology and Git failures are never interpreted as source history."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.mkdir(exist_ok=True)
            self._repo_with_evidence(root)
            real_output = traefik_proof._git_output

            def malformed(project: Path, *arguments: str, **kwargs: object) -> bytes:
                if arguments and arguments[0] == "log":
                    return b"not-a-valid-history\n"
                return real_output(project, *arguments, **kwargs)

            with mock.patch.object(traefik_proof, "_git_output", side_effect=malformed):
                with self.assertRaisesRegex(ValueError, "invalid Git object ID"):
                    traefik_proof._current_parser_provenance(root)

            def failed(project: Path, *arguments: str, **kwargs: object) -> bytes:
                if arguments and arguments[0] == "log":
                    raise ValueError("synthetic Git failure")
                return real_output(project, *arguments, **kwargs)

            with mock.patch.object(traefik_proof, "_git_output", side_effect=failed):
                with self.assertRaisesRegex(ValueError, "synthetic Git failure"):
                    traefik_proof._current_parser_provenance(root)

    def test_topology_mutation_after_initial_preflight_fails_closed(self) -> None:
        """Forbidden topology added after preflight is caught by the final snapshot."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._repo_with_evidence(root)
            real_output = traefik_proof._git_output
            show_count = 0

            def mutate_after_preflight(project: Path, *arguments: str, **kwargs: object) -> bytes:
                nonlocal show_count
                result = real_output(project, *arguments, **kwargs)
                if arguments and arguments[0] == "show":
                    show_count += 1
                    if show_count == 2:
                        (root / ".git" / "shallow").write_text("0" * 40 + "\n", encoding="ascii")
                return result

            with mock.patch.object(traefik_proof, "_git_output", side_effect=mutate_after_preflight):
                with self.assertRaisesRegex(ValueError, "shallow|topology changed"):
                    traefik_proof._current_parser_provenance(root)

    def _assert_metadata_swap_after_show(self, project_root: Path, target: Path) -> None:
        """Keep one same-path replacement active until the retained pin rejects it."""

        real_output = traefik_proof._git_output
        replacement = _same_path_copy(target)
        swapped = False

        def mutate_after_show(project: Path, *arguments: str, **kwargs: object) -> bytes:
            nonlocal swapped
            result = real_output(project, *arguments, **kwargs)
            if arguments and arguments[0] == "show" and not swapped:
                replacement.__enter__()
                swapped = True
            return result

        try:
            with mock.patch.object(traefik_proof, "_git_output", side_effect=mutate_after_show):
                with self.assertRaisesRegex(ValueError, "identity changed|topology changed"):
                    traefik_proof._current_parser_provenance(project_root)
        finally:
            if swapped:
                replacement.__exit__(None, None, None)

    def test_metadata_regular_component_swap_between_lstat_and_open_fails_closed(self) -> None:
        """A directory replaced after lstat cannot pass the open identity check."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._repo_with_evidence(root)
            target = root / ".git"
            replacement = root / ".git.replacement"
            original = root / ".git.original"
            shutil.copytree(target, replacement)
            real_open = traefik_proof.os.open
            swapped = False

            def swap_before_open(path: object, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
                nonlocal swapped
                if path == ".git" and not swapped:
                    target.rename(original)
                    replacement.rename(target)
                    swapped = True
                return real_open(path, flags, mode, dir_fd=dir_fd)

            try:
                with mock.patch.object(traefik_proof.os, "open", side_effect=swap_before_open):
                    with self.assertRaisesRegex(ValueError, "changed between inspection and open"):
                        traefik_proof._parser_open_metadata_path(
                            Path("/"), str(root.resolve() / ".git" / "config"), "deterministic metadata swap"
                        )
            finally:
                if swapped:
                    shutil.rmtree(target)
                    original.rename(target)
                elif replacement.exists():
                    shutil.rmtree(replacement)

    def test_metadata_pin_rejects_marker_replacement_after_git_call(self) -> None:
        """A linked-worktree gitfile replacement cannot change the authenticated marker."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            linked = Path(temporary) / "linked"
            root.mkdir()
            _create_parser_repo(root)
            _run_git(root, "worktree", "add", "--quiet", "-b", "marker-swap", str(linked))
            self._assert_metadata_swap_after_show(linked, linked / ".git")

    def test_metadata_pin_rejects_config_replacement_after_git_call(self) -> None:
        """A same-path common config replacement cannot change the authenticated bytes."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._repo_with_evidence(root)
            self._assert_metadata_swap_after_show(root, root / ".git" / "config")

    def test_metadata_pin_rejects_git_directory_replacement_after_git_call(self) -> None:
        """A same-path .git replacement cannot change the authenticated repository."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._repo_with_evidence(root)
            self._assert_metadata_swap_after_show(root, root / ".git")

    def test_metadata_pin_rejects_objects_directory_replacement_after_git_call(self) -> None:
        """A same-path objects replacement cannot change the authenticated object store."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._repo_with_evidence(root)
            self._assert_metadata_swap_after_show(root, root / ".git" / "objects")

    def test_project_root_symlink_alias_is_rejected(self) -> None:
        """A symlink alias for the caller root cannot select a different root identity."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            alias = Path(temporary) / "repo-alias"
            root.mkdir()
            self._repo_with_evidence(root)
            alias.symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink alias"):
                traefik_proof._current_parser_provenance(alias)

    def _assert_first_git_command_rejects_metadata_swap(self, root: Path, target: Path, pattern: str) -> None:
        """Mutate pinned metadata after preparation but before the first Git call."""

        real_snapshot = traefik_proof._parser_source_snapshot
        replacement = _same_path_copy(target)
        swapped = False

        def mutate_after_sources(project: Path, relative: str, label: str, budget: object) -> object:
            nonlocal swapped
            result = real_snapshot(project, relative, label, budget)
            if label == "parser test source" and not swapped:
                replacement.__enter__()
                swapped = True
            return result

        try:
            with mock.patch.object(traefik_proof, "_parser_source_snapshot", side_effect=mutate_after_sources):
                with self.assertRaisesRegex(ValueError, pattern):
                    traefik_proof._current_parser_provenance(root)
        finally:
            if swapped:
                replacement.__exit__(None, None, None)

    def test_first_git_command_is_fenced_by_common_config_pin(self) -> None:
        """Common config replacement before rev-parse cannot evade the metadata fence."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._repo_with_evidence(root)
            self._assert_first_git_command_rejects_metadata_swap(
                root,
                root / ".git" / "config",
                "Git common config (identity|bytes) changed",
            )

    def test_first_git_command_is_fenced_by_objects_pin(self) -> None:
        """Objects-directory replacement before rev-parse cannot evade the metadata fence."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._repo_with_evidence(root)
            self._assert_first_git_command_rejects_metadata_swap(
                root,
                root / ".git" / "objects",
                "Git objects directory identity changed",
            )

    def test_pack_metadata_entry_bound_fails_closed(self) -> None:
        """A huge objects/pack directory cannot consume unbounded scan time."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._repo_with_evidence(root)
            pack_dir = root / ".git" / "objects" / "pack"
            pack_dir.mkdir(parents=True, exist_ok=True)
            for index in range(10_000):
                (pack_dir / f"entry-{index:05d}").touch()
            with self.assertRaisesRegex(ValueError, "pack metadata exceeds"):
                traefik_proof._current_parser_provenance(root)

    def test_source_ancestor_symlink_escape_fails_closed(self) -> None:
        """A source ancestor symlink cannot redirect reads outside the repository."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            outside = Path(temporary) / "outside"
            root.mkdir()
            outside.mkdir()
            implementation, test_source, _source_commit = _create_parser_repo(root)
            (outside / "traefik_proof.py").write_bytes(implementation)
            (outside / "test_traefik_proof.py").write_bytes(test_source)
            (root / "scripts").rename(root / "scripts-real")
            (root / "scripts").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlinked path component"):
                traefik_proof._current_parser_provenance(root)

    def test_relative_linked_worktree_gitdir_is_supported_and_escape_rejected(self) -> None:
        """Linked-worktree gitdir paths resolve relative to the .git file parent."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            linked = Path(temporary) / "linked"
            root.mkdir()
            _create_parser_repo(root)
            _run_git(root, "worktree", "add", "--quiet", "-b", "relative-linked", str(linked))
            marker = linked / ".git"
            original = marker.read_text(encoding="ascii").strip()
            absolute_git_dir = Path(original.split(":", 1)[1].strip()).resolve()
            relative_git_dir = os.path.relpath(absolute_git_dir, start=marker.parent.resolve())
            marker.write_text(f"gitdir: {relative_git_dir}\n", encoding="ascii")
            self.assertEqual(_run_git(linked, "rev-parse", "--show-toplevel"), str(linked.resolve()))
            provenance = traefik_proof._current_parser_provenance(linked)
            self.assertEqual(len(provenance["implementation_commit"]), 40)

            marker.write_text("gitdir: ../outside-gitdir\n", encoding="ascii")
            with self.assertRaises(ValueError):
                traefik_proof._current_parser_provenance(linked)

    def test_external_common_copy_is_rejected_even_when_git_accepts_it(self) -> None:
        """Copied common metadata outside the trusted ancestor cannot authorize ancestry."""

        with tempfile.TemporaryDirectory() as temporary:
            sandbox = Path(temporary)
            root = sandbox / "repo"
            linked = Path(temporary) / "linked"
            root.mkdir()
            _create_parser_repo(root)
            _run_git(root, "worktree", "add", "--quiet", "-b", "external-common", str(linked))
            marker = linked / ".git"
            original = marker.read_text(encoding="ascii").strip()
            original_git_dir = Path(original.split(":", 1)[1].strip()).resolve()
            external_common = sandbox / "external-common"
            shutil.copytree(root / ".git", external_common)
            evil = external_common / "worktrees" / "evil"
            shutil.copytree(original_git_dir, evil)
            (evil / "commondir").write_text("../..\n", encoding="ascii")
            (evil / "gitdir").write_text(os.path.relpath(marker, start=evil) + "\n", encoding="ascii")
            marker.write_text(f"gitdir: {os.path.relpath(evil, start=marker.parent)}\n", encoding="ascii")

            self.assertEqual(_run_git(linked, "rev-parse", "--show-toplevel"), str(linked.resolve()))
            self.assertEqual(Path(_run_git(linked, "rev-parse", "--git-common-dir")).resolve(), external_common.resolve())
            with self.assertRaisesRegex(ValueError, "trusted repository metadata root|outside"):
                traefik_proof._current_parser_provenance(linked)

    def test_relative_gitdir_symlink_escape_fails_closed(self) -> None:
        """Git metadata references cannot follow a relative symlink redirect."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            linked = Path(temporary) / "linked"
            root.mkdir()
            _create_parser_repo(root)
            _run_git(root, "worktree", "add", "--quiet", "-b", "relative-symlink", str(linked))
            marker = linked / ".git"
            original = marker.read_text(encoding="ascii").strip()
            target = Path(original.split(":", 1)[1].strip()).resolve()
            (linked / "redirect").symlink_to(target, target_is_directory=True)
            marker.write_text("gitdir: redirect\n", encoding="ascii")

            self.assertEqual(_run_git(linked, "rev-parse", "--show-toplevel"), str(linked.resolve()))
            with self.assertRaisesRegex(ValueError, "symlinked path component"):
                traefik_proof._current_parser_provenance(linked)

    def test_separate_git_dir_is_explicitly_unsupported(self) -> None:
        """A standalone separate-git-dir checkout has no trusted ancestor metadata root."""

        with tempfile.TemporaryDirectory() as temporary:
            sandbox = Path(temporary)
            root = sandbox / "repo"
            metadata = sandbox / "separate.git"
            root.mkdir()
            scripts_root = root / "scripts"
            scripts_root.mkdir()
            (scripts_root / "traefik_proof.py").write_bytes((ROOT / traefik_proof.PARSER_IMPLEMENTATION_PATH).read_bytes())
            (scripts_root / "test_traefik_proof.py").write_bytes((ROOT / traefik_proof.PARSER_TEST_PATH).read_bytes())
            _run_git(sandbox, "init", "--quiet", f"--separate-git-dir={metadata}", str(root))
            _run_git(root, "config", "user.name", "Hermternal test")
            _run_git(root, "config", "user.email", "hermternal-test@example.invalid")
            _run_git(root, "add", "scripts")
            _run_git(root, "commit", "--quiet", "-m", "parser source")

            self.assertEqual(_run_git(root, "rev-parse", "--show-toplevel"), str(root.resolve()))
            with self.assertRaisesRegex(ValueError, "trusted repository metadata root|unsupported"):
                traefik_proof._current_parser_provenance(root)

    def test_git_metadata_indirections_fail_closed(self) -> None:
        """Repository-local indirection and partial-clone markers cannot authorize ancestry."""

        metadata_cases = (
            ("shallow", lambda git_dir: (git_dir / "shallow").write_text("0" * 40 + "\n", encoding="ascii")),
            ("graft", lambda git_dir: (git_dir / "info" / "grafts").write_text("\n", encoding="ascii")),
            ("alternate", lambda git_dir: (git_dir / "objects" / "info" / "alternates").write_text("/tmp\n", encoding="ascii")),
            ("http alternate", lambda git_dir: (git_dir / "objects" / "info" / "http-alternates").write_text("https://invalid/\n", encoding="ascii")),
            ("replacement", lambda git_dir: (git_dir / "refs" / "replace").mkdir(parents=True)),
            ("promisor", lambda git_dir: (git_dir / "objects" / "pack" / "test.promisor").write_text("", encoding="ascii")),
        )
        for label, install in metadata_cases:
            with self.subTest(metadata=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self._repo_with_evidence(root)
                install(root / ".git")
                with self.assertRaisesRegex(ValueError, "rejects|shallow|alternate|promisor|replacement"):
                    traefik_proof._current_parser_provenance(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._repo_with_evidence(root)
            _run_git(root, "config", "extensions.partialClone", "blob:none")
            with self.assertRaisesRegex(ValueError, "partial"):
                traefik_proof._current_parser_provenance(root)

    def test_git_redirect_environment_is_sanitized(self) -> None:
        """Caller-controlled Git directory and object redirects do not cross the trust boundary."""

        redirect_names = (
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_NAMESPACE",
            "GIT_GRAFT_FILE",
            "GIT_SHALLOW_FILE",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_KEY_0",
            "GIT_CONFIG_VALUE_0",
        )
        malicious = {name: "/tmp/attacker" for name in redirect_names}
        malicious["GIT_CONFIG_COUNT"] = "1"
        with mock.patch.dict(os.environ, malicious, clear=False):
            environment = traefik_proof._parser_git_environment()
        for name in redirect_names:
            if name == "GIT_CONFIG_COUNT":
                self.assertEqual(environment[name], "0")
            elif name.startswith("GIT_CONFIG_"):
                self.assertNotIn(name, environment)
            else:
                self.assertNotIn(name, environment)
        self.assertEqual(environment["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertEqual(environment["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(environment["PATH"], traefik_proof.PARSER_GIT_HELPER_PATH)

    def test_bounded_git_output_and_stderr_overflow_are_reaped(self) -> None:
        """Both output streams are capped while the process group is terminated."""

        environment = traefik_proof._parser_git_environment()
        for stream in ("stdout", "stderr"):
            code = f"import sys; sys.{stream}.write('x' * 4096); sys.{stream}.flush()"
            with self.subTest(stream=stream):
                with self.assertRaisesRegex(ValueError, "output exceeds"):
                    traefik_proof._run_bounded_git(
                        [sys.executable, "-c", code],
                        deadline=traefik_proof.time.monotonic() + 5,
                        output_limit=1024,
                        environment=environment,
                    )

    def test_git_timeout_kills_process_group_descendants(self) -> None:
        """Timeout cleanup targets descendants, not only the Git parent."""

        with tempfile.TemporaryDirectory() as temporary:
            pid_path = Path(temporary) / "child.pid"
            code = (
                "import pathlib, subprocess, sys, time; "
                f"child=subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
                f"pathlib.Path({str(pid_path)!r}).write_text(str(child.pid)); time.sleep(30)"
            )
            with self.assertRaisesRegex(ValueError, "overall time budget exhausted"):
                traefik_proof._run_bounded_git(
                    [sys.executable, "-c", code],
                    deadline=traefik_proof.time.monotonic() + 0.2,
                    output_limit=1024,
                    environment=traefik_proof._parser_git_environment(),
                )
            if pid_path.exists():
                child_pid = int(pid_path.read_text(encoding="ascii"))
                for _ in range(20):
                    try:
                        os.kill(child_pid, 0)
                    except OSError:
                        break
                    time.sleep(0.05)
                else:
                    self.fail("Git descendant survived timeout cleanup")

    def test_source_provenance_rechecks_final_source_bytes(self) -> None:
        """A source edit after the first Git call fails the final identity check."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            implementation, _tests, _source, _evidence = self._repo_with_evidence(root)
            real_output = traefik_proof._git_output
            mutated = False

            def mutate_after_git(project: Path, *arguments: str, **kwargs: object) -> bytes:
                nonlocal mutated
                result = real_output(project, *arguments, **kwargs)
                if not mutated:
                    (root / traefik_proof.PARSER_IMPLEMENTATION_PATH).write_bytes(implementation + b"mutation")
                    mutated = True
                return result

            with mock.patch.object(traefik_proof, "_git_output", side_effect=mutate_after_git):
                with self.assertRaisesRegex(ValueError, "final parser sources|source predecessor"):
                    traefik_proof._current_parser_provenance(root)

    def test_symlink_source_mode_fails_closed(self) -> None:
        """A symlink blob is never equivalent to a regular source file."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scripts = root / "scripts"
            scripts.mkdir()
            implementation = b"current\n"
            test_source = b"test\n"
            implementation_path = scripts / "traefik_proof.py"
            test_path = scripts / "test_traefik_proof.py"
            implementation_path.write_bytes(implementation)
            test_path.write_bytes(test_source)
            _run_git(root, "init", "--quiet")
            _run_git(root, "config", "user.name", "Hermternal test")
            _run_git(root, "config", "user.email", "hermternal-test@example.invalid")
            _run_git(root, "add", "scripts")
            _run_git(root, "commit", "--quiet", "-m", "regular source")
            implementation_path.unlink()
            implementation_path.symlink_to("current\n")
            _run_git(root, "add", "-A", "scripts")
            _run_git(root, "commit", "--quiet", "-m", "symlink source")
            implementation_path.unlink()
            implementation_path.write_bytes(implementation)
            with self.assertRaisesRegex(ValueError, "non-regular source file"):
                traefik_proof._current_parser_provenance(root)

    def test_valid_history_beyond_subprocess_ceiling_uses_batched_reads(self) -> None:
        """A valid 2,050-commit history stays below the subprocess ceiling."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._repo_with_evidence(root)
            _append_fast_history(root, 2050)
            real_output = traefik_proof._git_output
            calls = 0

            def count_calls(project: Path, *arguments: str, **kwargs: object) -> bytes:
                nonlocal calls
                calls += 1
                return real_output(project, *arguments, **kwargs)

            started = traefik_proof.time.monotonic()
            with mock.patch.object(traefik_proof, "_git_output", side_effect=count_calls):
                provenance = traefik_proof._current_parser_provenance(root)
            elapsed = traefik_proof.time.monotonic() - started
            self.assertEqual(len(provenance["implementation_commit"]), 40)
            self.assertLess(calls, 20)
            self.assertLess(elapsed, traefik_proof.PARSER_SOURCE_MAX_SECONDS)

    def test_source_pair_only_update_selects_unique_predecessor(self) -> None:
        """A source pair update, not an evidence descendant, selects its commit."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _implementation, test_source, _source, _evidence = self._repo_with_evidence(root)
            test_path = root / traefik_proof.PARSER_TEST_PATH
            test_path.write_bytes(test_source + b"pair update")
            _run_git(root, "add", str(test_path.relative_to(root)))
            _run_git(root, "commit", "--quiet", "-m", "pair update")
            selected = _run_git(root, "rev-parse", "HEAD")
            provenance = traefik_proof._current_parser_provenance(root)
            self.assertEqual(provenance["implementation_commit"], selected)

    def test_cli_normalizes_parser_provenance_once_and_reuses_result(self) -> None:
        """The evidence CLI shares one provenance result across validation and rendering."""

        fake = {
            "implementation_path": traefik_proof.PARSER_IMPLEMENTATION_PATH,
            "implementation_commit": "a" * 40,
            "implementation_blob": "b" * 40,
            "implementation_sha256": "c" * 64,
            "test_path": traefik_proof.PARSER_TEST_PATH,
            "test_source_sha256": "d" * 64,
        }
        with tempfile.TemporaryDirectory() as temporary:
            browser_path = Path(temporary) / "browser.json"
            browser_path.write_text(json.dumps(self._browser_evidence("blocked_provider")), encoding="utf-8")
            output = io.StringIO()
            with mock.patch.object(traefik_proof, "_current_parser_provenance", return_value=fake) as current:
                with redirect_stdout(output):
                    self.assertEqual(
                        traefik_proof.main(
                            [
                                "evidence",
                                "--build-sha",
                                EXPECTED_BUILD_SHA,
                                "--build-digest",
                                EXPECTED_BUILD_DIGEST,
                                "--traefik-config-digest",
                                EXPECTED_CONFIG_DIGEST,
                                "--browser-evidence",
                                str(browser_path),
                            ]
                        ),
                        0,
                    )
            self.assertEqual(current.call_count, 1)
            self.assertEqual(json.loads(output.getvalue())["forward_auth_contract"]["parser_provenance"], fake)

    def test_source_provenance_fails_closed_on_overall_budget(self) -> None:
        """A per-command timeout cannot permit unbounded aggregate Git work."""

        with mock.patch.object(traefik_proof, "PARSER_SOURCE_MAX_SUBPROCESSES", 1):
            with self.assertRaisesRegex(ValueError, "subprocess budget exhausted"):
                traefik_proof._current_parser_provenance(ROOT)
        with mock.patch.object(traefik_proof, "PARSER_SOURCE_MAX_SECONDS", 0.0):
            with self.assertRaisesRegex(ValueError, "overall time budget exhausted"):
                traefik_proof._current_parser_provenance(ROOT)

    def test_source_provenance_uses_repository_object_format(self) -> None:
        """Commit and blob validation must follow a SHA-256 repository."""

        with tempfile.TemporaryDirectory() as temporary:
            project_root = Path(temporary)
            scripts_root = project_root / "scripts"
            scripts_root.mkdir()
            implementation = (ROOT / traefik_proof.PARSER_IMPLEMENTATION_PATH).read_bytes()
            test_source = (ROOT / traefik_proof.PARSER_TEST_PATH).read_bytes()
            (scripts_root / "traefik_proof.py").write_bytes(implementation)
            (scripts_root / "test_traefik_proof.py").write_bytes(test_source)

            def git(*arguments: str) -> str:
                completed = subprocess.run(
                    ["git", "-C", str(project_root), *arguments],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return completed.stdout.strip()

            git("init", "--quiet", "--object-format=sha256")
            git("config", "user.name", "Hermternal test")
            git("config", "user.email", "hermternal-test@example.invalid")
            git("add", "scripts")
            git("commit", "--quiet", "-m", "parser source")
            source_commit = git("rev-parse", "HEAD")
            (project_root / "retained-evidence.json").write_text("{}\n", encoding="utf-8")
            git("add", "retained-evidence.json")
            git("commit", "--quiet", "-m", "evidence only")

            self.assertEqual(git("rev-parse", "--show-object-format"), "sha256")
            provenance = traefik_proof._current_parser_provenance(project_root)
            oid_width = hashlib.sha256().digest_size * 2
            self.assertEqual(len(source_commit), oid_width)
            self.assertEqual(len(provenance["implementation_commit"]), oid_width)
            self.assertEqual(len(provenance["implementation_blob"]), oid_width)
            self.assertEqual(
                provenance["implementation_blob"],
                git("rev-parse", f"{source_commit}:{traefik_proof.PARSER_IMPLEMENTATION_PATH}"),
            )

        with mock.patch.object(traefik_proof, "_git_output", return_value=b"sha512\n"):
            with self.assertRaisesRegex(ValueError, "object format is unsupported"):
                traefik_proof._git_object_format(ROOT)

    def test_source_predecessor_ignores_mode_only_history(self) -> None:
        """Changing executable mode alone must not move parser source identity."""

        with tempfile.TemporaryDirectory() as temporary:
            project_root = Path(temporary)
            scripts_root = project_root / "scripts"
            scripts_root.mkdir()
            implementation = (ROOT / traefik_proof.PARSER_IMPLEMENTATION_PATH).read_bytes()
            test_source = (ROOT / traefik_proof.PARSER_TEST_PATH).read_bytes()
            implementation_path = scripts_root / "traefik_proof.py"
            test_path = scripts_root / "test_traefik_proof.py"
            implementation_path.write_bytes(implementation)
            test_path.write_bytes(test_source)

            def git(*arguments: str) -> str:
                completed = subprocess.run(
                    ["git", "-C", str(project_root), *arguments],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return completed.stdout.strip()

            git("init", "--quiet")
            git("config", "user.name", "Hermternal test")
            git("config", "user.email", "hermternal-test@example.invalid")
            git("add", "scripts")
            git("commit", "--quiet", "-m", "parser source")
            source_commit = git("rev-parse", "HEAD")
            implementation_path.chmod(0o755)
            git("add", "scripts/traefik_proof.py")
            git("commit", "--quiet", "-m", "mode only")
            (project_root / "retained-evidence.json").write_text("{}\n", encoding="utf-8")
            git("add", "retained-evidence.json")
            git("commit", "--quiet", "-m", "evidence only")

            provenance = traefik_proof._current_parser_provenance(project_root)
            self.assertEqual(provenance["implementation_commit"], source_commit)

    def test_source_predecessor_rejects_incomparable_equal_byte_merge_candidates(self) -> None:
        """A merge of equal-byte source commits must not choose Git log order."""

        with tempfile.TemporaryDirectory() as temporary:
            project_root = Path(temporary)
            scripts_root = project_root / "scripts"
            scripts_root.mkdir()
            implementation = (ROOT / traefik_proof.PARSER_IMPLEMENTATION_PATH).read_bytes()
            test_source = (ROOT / traefik_proof.PARSER_TEST_PATH).read_bytes()
            implementation_path = scripts_root / "traefik_proof.py"
            test_path = scripts_root / "test_traefik_proof.py"

            def git(*arguments: str) -> str:
                completed = subprocess.run(
                    ["git", "-C", str(project_root), *arguments],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return completed.stdout.strip()

            git("init", "--quiet")
            git("config", "user.name", "Hermternal test")
            git("config", "user.email", "hermternal-test@example.invalid")
            implementation_path.write_bytes(b"parser base\n")
            test_path.write_bytes(b"test base\n")
            git("add", "scripts")
            git("commit", "--quiet", "-m", "base")
            base_commit = git("rev-parse", "HEAD")

            git("checkout", "-b", "left", "--quiet")
            implementation_path.write_bytes(implementation)
            test_path.write_bytes(test_source)
            git("add", "scripts")
            git("commit", "--quiet", "-m", "source left")
            left_source = git("rev-parse", "HEAD")
            (project_root / "left-marker").write_text("left\n", encoding="utf-8")
            git("add", "left-marker")
            git("commit", "--quiet", "-m", "left marker")

            git("checkout", "-b", "right", base_commit, "--quiet")
            (project_root / "right-marker").write_text("right\n", encoding="utf-8")
            git("add", "right-marker")
            git("commit", "--quiet", "-m", "right marker")
            git("cherry-pick", "--quiet", left_source)
            git("checkout", "left", "--quiet")
            git("merge", "--no-ff", "right", "--quiet", "-m", "merge equal source")

            with self.assertRaisesRegex(ValueError, "source predecessor is ambiguous"):
                traefik_proof._current_parser_provenance(project_root)

    def test_source_predecessor_ignores_evidence_descendant_and_rejects_drift(self) -> None:
        """Evidence-only descendants keep the source commit; source drift fails closed."""

        with tempfile.TemporaryDirectory() as temporary:
            project_root = Path(temporary)
            scripts_root = project_root / "scripts"
            scripts_root.mkdir()
            implementation = (ROOT / traefik_proof.PARSER_IMPLEMENTATION_PATH).read_bytes()
            test_source = (ROOT / traefik_proof.PARSER_TEST_PATH).read_bytes()
            (scripts_root / "traefik_proof.py").write_bytes(implementation)
            (scripts_root / "test_traefik_proof.py").write_bytes(test_source)

            def git(*arguments: str) -> str:
                completed = subprocess.run(
                    ["git", "-C", str(project_root), *arguments],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return completed.stdout.strip()

            git("init", "--quiet")
            git("config", "user.name", "Hermternal test")
            git("config", "user.email", "hermternal-test@example.invalid")
            git("add", "scripts")
            git("commit", "--quiet", "-m", "parser source")
            source_commit = git("rev-parse", "HEAD")
            (project_root / "retained-evidence.json").write_text("{}\n", encoding="utf-8")
            git("add", "retained-evidence.json")
            git("commit", "--quiet", "-m", "evidence only")
            evidence_commit = git("rev-parse", "HEAD")

            provenance = traefik_proof._current_parser_provenance(project_root)
            self.assertEqual(provenance["implementation_commit"], source_commit)
            self.assertNotEqual(provenance["implementation_commit"], evidence_commit)
            self.assertEqual(provenance["implementation_sha256"], hashlib.sha256(implementation).hexdigest())
            self.assertEqual(provenance["test_source_sha256"], hashlib.sha256(test_source).hexdigest())

            (scripts_root / "traefik_proof.py").write_bytes(implementation + b"\n")
            with self.assertRaisesRegex(ValueError, "source predecessor"):
                traefik_proof._current_parser_provenance(project_root)

        forged = self._parser_provenance()
        forged["implementation_commit"] = "0" * len(forged["implementation_commit"])
        with self.assertRaisesRegex(ValueError, "does not match committed parser sources"):
            traefik_proof._normalize_parser_provenance(forged)

    def test_evidence_is_exact_canonical_cli_output(self) -> None:
        current_provenance = traefik_proof._current_parser_provenance(ROOT)
        manifest = traefik_proof.render_manifest(
            build_sha=EXPECTED_BUILD_SHA,
            build_digest=EXPECTED_BUILD_DIGEST,
            traefik_config_digest=EXPECTED_CONFIG_DIGEST,
            browser_journey="blocked_provider",
            browser_evidence=self._browser_evidence("blocked_provider"),
            parser_provenance=current_provenance,
        )
        expected_pretty = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode("utf-8")
        # The retained artifact is intentionally not regenerated before this
        # source change is independently approved; its historical anchor must
        # still verify against the bytes that remain on disk.
        self.assertNotEqual(EVIDENCE_PATH.read_bytes(), expected_pretty)
        self.assertEqual(
            EVIDENCE_ANCHOR_PATH.read_bytes(),
            (hashlib.sha256(EVIDENCE_PATH.read_bytes()).hexdigest() + "\n").encode("ascii"),
        )
        with self.assertRaisesRegex(ValueError, "does not match committed parser sources"):
            traefik_proof.render_manifest(
                build_sha=EXPECTED_BUILD_SHA,
                build_digest=EXPECTED_BUILD_DIGEST,
                traefik_config_digest=EXPECTED_CONFIG_DIGEST,
                browser_journey="blocked_provider",
                browser_evidence=self._browser_evidence("blocked_provider"),
                parser_provenance=self._parser_provenance(),
            )
        with tempfile.TemporaryDirectory() as temporary:
            browser_path = Path(temporary) / "browser-evidence.json"
            browser_path.write_text(
                json.dumps(self._browser_evidence("blocked_provider"), sort_keys=True),
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/traefik_proof.py"),
                    "evidence",
                    "--build-sha",
                    EXPECTED_BUILD_SHA,
                    "--build-digest",
                    EXPECTED_BUILD_DIGEST,
                    "--traefik-config-digest",
                    EXPECTED_CONFIG_DIGEST,
                    "--browser-evidence",
                    str(browser_path),
                ],
                check=True,
                capture_output=True,
            )
        self.assertEqual(json.loads(completed.stdout.decode("utf-8")), manifest)
        self.assertEqual(
            completed.stdout,
            (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"),
        )
        oid_width = len(current_provenance["implementation_commit"])
        forged = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/traefik_proof.py"),
                "evidence",
                "--build-sha",
                EXPECTED_BUILD_SHA,
                "--build-digest",
                EXPECTED_BUILD_DIGEST,
                "--traefik-config-digest",
                EXPECTED_CONFIG_DIGEST,
                "--parser-implementation-commit",
                "0" * oid_width,
                "--parser-implementation-blob",
                "1" * oid_width,
                "--parser-implementation-sha256",
                "2" * 64,
                "--parser-test-sha256",
                "3" * 64,
                "--browser-evidence",
                str(browser_path),
            ],
            check=False,
            capture_output=True,
        )
        self.assertNotEqual(forged.returncode, 0)
        self.assertIn(b"parser provenance", forged.stderr.lower())

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
                browser_evidence=self._browser_evidence(
                    "blocked_provider",
                    provenance={"build_sha": "0" * len(EXPECTED_BUILD_SHA)},
                ),
            )

    def test_browser_events_do_not_upgrade_synthetic_deployment_claim(self) -> None:
        manifest = traefik_proof.render_manifest(
            build_sha=EXPECTED_BUILD_SHA,
            build_digest=EXPECTED_BUILD_DIGEST,
            traefik_config_digest=EXPECTED_CONFIG_DIGEST,
            browser_journey="passed",
            browser_evidence=self._browser_evidence("passed"),
            parser_provenance=traefik_proof._current_parser_provenance(ROOT),
        )
        self.assertEqual(manifest["browser_journey"], "passed")
        self.assertEqual(manifest["proof_run"], traefik_proof._synthetic_proof_run())
        self.assertFalse(manifest["proof_run"]["live_run"])
        self.assertFalse(manifest["proof_run"]["compatible"])


if __name__ == "__main__":
    unittest.main()
