#!/usr/bin/env python3
"""Regression tests for the disposable issue #156 Caddy proof fixture.

These tests protect the reviewed edge boundary without starting Caddy or
contacting Hermes. The live status matrix is retained separately as redacted
evidence; this file proves that the renderer cannot silently widen it. The
retained-evidence checks also reject unverified runtime identity, cookie
attribute, and browser-event claims.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import caddy_proof  # noqa: E402


EVIDENCE_PATH = ROOT / "tests/integration/hermes-caddy/caddy-proof-evidence.json"
EVIDENCE_ANCHOR_PATH = ROOT / "tests/integration/hermes-caddy/caddy-proof-evidence-sha256.txt"
EXPECTED_BUILD_SHA = "521ede32b904a42e22eebb279fd7d404074cd318"
EXPECTED_BUILD_DIGEST = "77f6d0e8bb4977c16eb1f1eaec32000f84f346ddec9f474ebd873d7b9a833d21"
EXPECTED_CADDYFILE_DIGEST = "342952687f19e425bd47126a47b5d17767c27aed99942252d6a6711b2b94f15c"


class CaddyProofRendererTests(unittest.TestCase):
    """Keep the Caddy proof exact, private, and default-deny."""

    def _render(self) -> str:
        return caddy_proof.render_caddyfile(
            host="caddy-156.test",
            https_port=19443,
            hermes_port=19256,
            site_root="/tmp/caddy-proof-site",
            cert_path="/tmp/caddy-proof/tls.crt",
            key_path="/tmp/caddy-proof/tls.key",
            storage_root="/tmp/caddy-proof",
        )

    def test_renderer_inputs_reject_ambiguous_hosts_ports_and_paths(self) -> None:
        self.assertEqual(caddy_proof._validate_host("caddy-156.test"), "caddy-156.test")
        with self.assertRaises(ValueError):
            caddy_proof._validate_host("caddy..test")
        with self.assertRaises(ValueError):
            caddy_proof._validate_host(123)  # type: ignore[arg-type]
        self.assertEqual(caddy_proof._validate_port(19443, "https_port"), 19443)
        with self.assertRaises(ValueError):
            caddy_proof._validate_port(443, "https_port")
        with self.assertRaises(ValueError):
            caddy_proof._validate_path("relative/site", "site_root")
        with self.assertRaises(ValueError):
            caddy_proof._validate_runtime_inputs({})

    def test_renderer_rejects_caddy_path_string_injection(self) -> None:
        fields = ("site_root", "cert_path", "key_path", "storage_root")
        forbidden_values = (
            "/tmp/caddy-proof/quote\"path",
            "/tmp/caddy-proof/single'quote",
            "/tmp/caddy-proof/back\\slash",
            "/tmp/caddy-proof/new\nline",
            "/tmp/caddy-proof/carriage\rreturn",
            "/tmp/caddy-proof/tab\tpath",
            "/tmp/caddy-proof/nul\x00path",
            "/tmp/caddy-proof/delete\x7fpath",
            "/tmp/caddy-proof/c1\x80path",
            "/tmp/caddy-proof/{http.request.uri.path}",
            "/tmp/caddy-proof/unmatched}",
        )
        for field in fields:
            for value in forbidden_values:
                inputs = {
                    "host": "caddy-156.test",
                    "https_port": 19443,
                    "hermes_port": 19256,
                    "site_root": "/tmp/caddy-proof-site",
                    "cert_path": "/tmp/caddy-proof/tls.crt",
                    "key_path": "/tmp/caddy-proof/tls.key",
                    "storage_root": "/tmp/caddy-proof",
                }
                inputs[field] = value
                with self.subTest(field=field, value=repr(value)):
                    with self.assertRaises(ValueError):
                        caddy_proof.render_caddyfile(**inputs)

    def test_host_origin_and_raw_uri_denials_are_explicit(self) -> None:
        rendered = self._render()
        self.assertIn("respond @bad_host \"host denied\" 421", rendered)
        self.assertIn("respond @bad_ws_origin \"origin denied\" 403", rendered)
        self.assertIn("respond @unsafe_raw \"not found\" 404", rendered)
        self.assertIn('respond "not found" 404', rendered)

    def test_every_reviewed_rest_route_is_exact_at_both_origins(self) -> None:
        rendered = self._render()
        for method, path in caddy_proof.EXACT_REST_ROUTES:
            with self.subTest(method=method, path=path):
                self.assertIn(path, rendered)
                self.assertIn(f"/hermes{path}", rendered)
        self.assertIn(caddy_proof.SESSION_ID_PATTERN, rendered)
        self.assertNotIn("/api/*", rendered)
        self.assertNotIn("/hermes/*", rendered)

    def test_static_surface_and_prefix_mapping_are_finite(self) -> None:
        rendered = self._render()
        for path in caddy_proof.STATIC_PATHS:
            with self.subTest(path=path):
                self.assertIn(path, rendered)
        self.assertIn("uri strip_prefix /hermes", rendered)
        self.assertIn("header_up X-Forwarded-Prefix /hermes", rendered)
        self.assertNotIn("try_files", rendered)

    def test_root_and_client_route_queries_are_exact(self) -> None:
        rendered = self._render()
        self.assertIn(caddy_proof.ROOT_SCENARIO_QUERY_GUARD, rendered)
        self.assertIn(caddy_proof.ROOT_QUERY_GUARD, rendered)
        self.assertIn(caddy_proof.CLIENT_ROUTE_PATTERN, rendered)
        self.assertIn(caddy_proof.CLIENT_ROUTE_PREFIX_PATTERN, rendered)
        self.assertIn(caddy_proof.QUERY_PRESENT_GUARD, rendered)
        self.assertIn("rewrite * /200.html", rendered)
        self.assertNotIn("path /v1/c/*", rendered)

    def test_oauth_callback_query_allowlist_is_narrow_and_order_independent(self) -> None:
        rendered = self._render()
        self.assertEqual(rendered.count(caddy_proof.AUTH_CALLBACK_QUERY_GUARD), 2)
        accepted = {
            "code=fixture-code-success&state=fixture-state-success",
            "state=fixture-state-success&code=fixture-code-success",
            "error=access_denied&error_description=fixture-user-cancelled&state=fixture-state-cancelled",
            "error=access_denied&state=fixture-state-cancelled&error_description=fixture-user-cancelled",
            "error_description=fixture-user-cancelled&error=access_denied&state=fixture-state-cancelled",
            "error_description=fixture-user-cancelled&state=fixture-state-cancelled&error=access_denied",
            "state=fixture-state-cancelled&error=access_denied&error_description=fixture-user-cancelled",
            "state=fixture-state-cancelled&error_description=fixture-user-cancelled&error=access_denied",
            "code=" + ("A" * 512) + "&state=" + ("B" * 512),
        }
        rejected = {
            "",
            "code=",
            "state=",
            "code=&state=fixture-state-malformed",
            "state=&code=fixture-code-missing-state",
            "code=fixture-code-success",
            "state=fixture-state-success",
            "code=fixture-code-success&state=fixture-state-success&extra=value",
            "code=fixture-code-success&code=other-code&state=fixture-state-success",
            "error=access_denied&state=fixture-state-cancelled",
            "error=access_denied&error_description=&state=fixture-state-cancelled",
            "error=access_denied&error_description=fixture-user-cancelled&state=",
            "error=provider_failure&error_description=fixture-user-cancelled&state=fixture-state-cancelled",
            "error=access_denied&error_description=fixture-user-cancelled&state=fixture-state-cancelled&code=extra",
            "code=fixture%2Dcode&state=fixture-state-success",
            "code=fixture/code&state=fixture-state-success",
            "code=" + ("A" * 513) + "&state=fixture-state-success",
            "code=fixture-code-success&state=" + ("B" * 513),
            "error=access_denied&error_description=" + ("D" * 513) + "&state=fixture-state-cancelled",
        }
        for query in accepted:
            self.assertTrue(any(re.fullmatch(pattern, query) for pattern in caddy_proof.AUTH_CALLBACK_QUERY_PATTERNS), query)
        for query in rejected:
            self.assertFalse(any(re.fullmatch(pattern, query) for pattern in caddy_proof.AUTH_CALLBACK_QUERY_PATTERNS), query)
        self.assertIn("/auth/callback", rendered)
        self.assertIn("/hermes/auth/callback", rendered)
        self.assertNotIn("/auth/callback /api/auth/me", rendered)

    def test_websocket_boundary_has_distinct_chat_and_pty_queries(self) -> None:
        rendered = self._render()
        self.assertEqual(rendered.count(caddy_proof.CHAT_TICKET_QUERY_GUARD), 2)
        self.assertEqual(rendered.count(caddy_proof.PTY_QUERY_GUARD), 2)
        self.assertIn("resume=", rendered)
        self.assertIn("attach=", rendered)
        self.assertNotIn("fresh=", rendered)
        self.assertIn("header Upgrade websocket", rendered)
        self.assertIn("header Connection *Upgrade*", rendered)
        self.assertNotIn("lb_retries", rendered)
        self.assertNotIn("lb_try_duration", rendered)

    def test_pty_query_patterns_are_exact_and_order_independent(self) -> None:
        self.assertTrue(re.fullmatch(caddy_proof.CHAT_TICKET_VALUE_PATTERN, "A" * 512))
        self.assertFalse(re.fullmatch(caddy_proof.CHAT_TICKET_VALUE_PATTERN, "A" * 513))
        self.assertEqual(len(caddy_proof.PTY_QUERY_PATTERNS), 8)
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
        }
        for query in accepted:
            self.assertTrue(any(re.fullmatch(pattern, query) for pattern in caddy_proof.PTY_QUERY_PATTERNS))
        for query in rejected:
            self.assertFalse(any(re.fullmatch(pattern, query) for pattern in caddy_proof.PTY_QUERY_PATTERNS))

    def test_normative_pty_docs_match_current_browser_query(self) -> None:
        manifest = (ROOT / "contracts/hermes-dashboard/manifest.md").read_text(encoding="utf-8")
        terminal = (ROOT / "contracts/state-models/terminal.md").read_text(encoding="utf-8")
        self.assertIn("`ticket` plus `resume`", manifest)
        self.assertIn("optional non-empty `attach`", manifest)
        self.assertIn("must not send a `fresh` query parameter", terminal)
        self.assertNotIn("`fresh=1`", manifest)
        self.assertNotIn("`fresh=1`", terminal)

    def test_upstream_authority_and_cookie_policy_are_fixed(self) -> None:
        rendered = self._render()
        self.assertEqual(rendered.count("header_up Host 127.0.0.1:19256"), 2)
        self.assertEqual(rendered.count("header_up Origin http://127.0.0.1:19256"), 2)
        self.assertEqual(rendered.count("header_up X-Forwarded-Proto https"), 2)
        self.assertEqual(rendered.count("header_up X-Forwarded-Host {http.request.host}"), 2)
        self.assertEqual(rendered.count('header_down Set-Cookie "(?i)(.*)" "$1; Secure"'), 2)
        self.assertNotIn("header_up -Origin", rendered)
        self.assertEqual(rendered.count("request_header -Forwarded"), 2)
        self.assertEqual(rendered.count("request_header -X-Forwarded-*"), 2)
        self.assertEqual(rendered.count("request_header -X-Real-IP"), 2)

    def test_static_digest_is_order_independent_and_content_bound(self) -> None:
        with tempfile.TemporaryDirectory() as first_dir, tempfile.TemporaryDirectory() as second_dir:
            first = Path(first_dir)
            second = Path(second_dir)
            (first / "z.txt").write_text("z", encoding="utf-8")
            (first / "a.txt").write_text("a", encoding="utf-8")
            (second / "a.txt").write_text("a", encoding="utf-8")
            (second / "z.txt").write_text("z", encoding="utf-8")
            self.assertEqual(caddy_proof._build_static_digest(first), caddy_proof._build_static_digest(second))
            (second / "z.txt").write_text("changed", encoding="utf-8")
            self.assertNotEqual(caddy_proof._build_static_digest(first), caddy_proof._build_static_digest(second))


class CaddyProofEvidenceTests(unittest.TestCase):
    """Ensure retained live observations are redacted and digest-bound."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))

    def browser_evidence(
        self,
        status: str,
        *,
        provenance: dict[str, str] | None = None,
        observations: dict[str, object] | None = None,
    ) -> dict[str, object]:
        expected_provenance = {
            "build_sha": EXPECTED_BUILD_SHA,
            "build_digest": EXPECTED_BUILD_DIGEST,
            "caddyfile_digest": EXPECTED_CADDYFILE_DIGEST,
            "runtime_inputs_sha256": caddy_proof.runtime_input_digest(
                caddy_proof.reconstruction_inputs()
            ),
        }
        if provenance is not None:
            expected_provenance.update(provenance)
        if observations is None:
            if status == "passed":
                observations = {"events": dict(caddy_proof.BROWSER_COMPLETION_EVIDENCE)}
            elif status in caddy_proof.BROWSER_BLOCKED_JOURNEYS:
                observations = {"blocker": caddy_proof.BROWSER_BLOCKER_CODES[status]}
            else:
                observations = {"failure": caddy_proof.BROWSER_FAILURE_CODE}
        return {
            "schema": caddy_proof.BROWSER_EVIDENCE_SCHEMA,
            "status": status,
            "provenance": expected_provenance,
            "observations": observations,
        }

    def render_manifest(self, *, browser_evidence: dict[str, object], browser_journey: str | None = None) -> dict[str, object]:
        return caddy_proof.render_manifest(
            build_sha=EXPECTED_BUILD_SHA,
            build_digest=EXPECTED_BUILD_DIGEST,
            caddyfile_digest=EXPECTED_CADDYFILE_DIGEST,
            browser_journey=browser_journey,
            browser_evidence=browser_evidence,
        )

    def test_evidence_anchor_matches_retained_bytes(self) -> None:
        expected = EVIDENCE_ANCHOR_PATH.read_text(encoding="utf-8").strip()
        actual = hashlib.sha256(EVIDENCE_PATH.read_bytes()).hexdigest()
        self.assertEqual(expected, actual)

    def test_evidence_binds_exact_build_and_runtime_config(self) -> None:
        self.assertEqual(self.evidence["schema"], caddy_proof.SCHEMA)
        self.assertEqual(self.evidence["product"]["build_commit"], EXPECTED_BUILD_SHA)
        self.assertEqual(self.evidence["product"]["static_manifest_sha256"], EXPECTED_BUILD_DIGEST)
        self.assertEqual(self.evidence["deployment"]["runtime_config_sha256"], EXPECTED_CADDYFILE_DIGEST)
        self.assertEqual(self.evidence["browser_journey"], "blocked_provider")
        self.assertEqual(self.evidence["browser_evidence"]["status"], "blocked_provider")
        self.assertEqual(
            self.evidence["browser_evidence"]["provenance"]["runtime_inputs_sha256"],
            caddy_proof.runtime_input_digest(caddy_proof.reconstruction_inputs()),
        )

    def test_runtime_digest_reconstructs_exact_generated_bytes(self) -> None:
        deployment = self.evidence["deployment"]
        runtime_inputs = deployment["runtime_inputs"]
        rendered = caddy_proof.render_from_inputs(runtime_inputs)
        self.assertEqual(
            caddy_proof.digest_bytes(rendered.encode("utf-8")),
            EXPECTED_CADDYFILE_DIGEST,
        )
        self.assertEqual(
            caddy_proof.digest_bytes(rendered.encode("utf-8")),
            deployment["runtime_config_sha256"],
        )
        self.assertEqual(rendered, caddy_proof.render_from_inputs(caddy_proof.reconstruction_inputs()))

    def test_rendered_evidence_does_not_claim_unverified_runtime_identity(self) -> None:
        manifest = caddy_proof.render_manifest(
            build_sha=EXPECTED_BUILD_SHA,
            build_digest=EXPECTED_BUILD_DIGEST,
            caddyfile_digest=EXPECTED_CADDYFILE_DIGEST,
            browser_journey="blocked_provider",
            browser_evidence=self.browser_evidence("blocked_provider"),
        )
        deployment = manifest["deployment"]
        self.assertNotIn("caddy_version", deployment)
        self.assertNotIn("official_image_digest", deployment)

    def test_render_manifest_rejects_missing_and_json_only_pass_evidence(self) -> None:
        with self.assertRaisesRegex(ValueError, "browser evidence is required"):
            caddy_proof.render_manifest(
                build_sha=EXPECTED_BUILD_SHA,
                build_digest=EXPECTED_BUILD_DIGEST,
                caddyfile_digest=EXPECTED_CADDYFILE_DIGEST,
                browser_journey="passed",
            )
        complete = self.browser_evidence("passed")
        with self.assertRaisesRegex(ValueError, "trusted execution receipt"):
            self.render_manifest(browser_evidence=complete, browser_journey="passed")
        for observations in (
            {"events": {"message.complete": "error"}},
            {"events": {**caddy_proof.BROWSER_COMPLETION_EVIDENCE, "message.complete": "error"}},
        ):
            forged = self.browser_evidence("passed", observations=observations)
            with self.subTest(observations=observations):
                with self.assertRaisesRegex(
                    ValueError,
                    "closed event set|complete journey|trusted execution receipt",
                ):
                    self.render_manifest(browser_evidence=forged, browser_journey="passed")

    def test_render_manifest_labels_json_only_evidence_as_non_execution(self) -> None:
        manifest = self.render_manifest(
            browser_evidence=self.browser_evidence("blocked_provider"),
        )
        self.assertEqual(manifest["browser_journey"], "blocked_provider")
        self.assertEqual(
            manifest["browser_execution"],
            {"mode": caddy_proof.BROWSER_NON_EXECUTION_MODE, "status": "not_proven"},
        )
        self.assertEqual(manifest["provenance"]["current_git_static"]["status"], "not_bound")
        self.assertEqual(manifest["provenance"]["historical_retained"]["status"], "not_bound")

    def test_direct_retained_mode_requires_loader_token(self) -> None:
        with self.assertRaisesRegex(ValueError, "canonical retained loader token"):
            caddy_proof.render_manifest(
                build_sha=EXPECTED_BUILD_SHA,
                build_digest=EXPECTED_BUILD_DIGEST,
                caddyfile_digest=EXPECTED_CADDYFILE_DIGEST,
                browser_journey="blocked_provider",
                browser_evidence=self.browser_evidence("blocked_provider"),
                runtime_inputs=caddy_proof.reconstruction_inputs(),
                provenance_mode="retained",
            )

    def test_render_manifest_requires_matching_blocked_and_failed_evidence(self) -> None:
        blocked = self.render_manifest(browser_evidence=self.browser_evidence("blocked_provider"))
        self.assertEqual(blocked["browser_journey"], "blocked_provider")
        with self.assertRaisesRegex(ValueError, "does not match its status"):
            self.render_manifest(
                browser_evidence=self.browser_evidence(
                    "blocked_provider", observations={"blocker": "empty_session"}
                )
            )
        failed = self.render_manifest(browser_evidence=self.browser_evidence("failed"))
        self.assertEqual(failed["browser_journey"], "failed")
        with self.assertRaisesRegex(ValueError, "does not match its status"):
            self.render_manifest(
                browser_evidence=self.browser_evidence(
                    "failed", observations={"failure": "provider_unavailable"}
                )
            )

    def test_render_manifest_rejects_stale_or_mismatched_evidence_maps(self) -> None:
        for key, value in {
            "build_sha": "0" * 40,
            "build_digest": "0" * 64,
            "caddyfile_digest": "1" * 64,
            "runtime_inputs_sha256": "2" * 64,
        }.items():
            stale = self.browser_evidence("passed", provenance={key: value})
            with self.subTest(provenance=key):
                with self.assertRaisesRegex(ValueError, "stale or mismatched"):
                    self.render_manifest(browser_evidence=stale)
        mismatch = self.browser_evidence("blocked_provider")
        with self.assertRaisesRegex(ValueError, "does not match browser evidence"):
            self.render_manifest(browser_evidence=mismatch, browser_journey="failed")
        malformed = self.browser_evidence("blocked_provider")
        malformed["unexpected"] = "rejected"
        with self.assertRaisesRegex(ValueError, "closed root key set"):
            self.render_manifest(browser_evidence=malformed)

    def test_json_cannot_smuggle_harness_runtime_or_source_identity(self) -> None:
        for field in ("harness_sha", "browser_version", "source_sha", "run_id"):
            forged = self.browser_evidence("passed")
            forged["provenance"][field] = "caller-controlled"  # type: ignore[index]
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "provenance keys are incomplete"):
                    self.render_manifest(browser_evidence=forged, browser_journey="passed")

    def test_retained_evidence_schema_narrows_unverified_claims(self) -> None:
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
        self.assertNotIn("caddy_version", deployment)
        self.assertNotIn("official_image_digest", deployment)
        self.assertEqual(
            self.evidence["cookie_proof"],
            {
                "status": "not_proven",
                "reason": "local mock emitted no Set-Cookie; renderer-only Secure rewriting is not a complete cookie-attribute proof",
            },
        )

    def test_statuses_and_docs_do_not_claim_unproven_browser_events(self) -> None:
        self.assertEqual(self.evidence["browser_journey"], "blocked_provider")
        self.assertEqual(self.evidence["cookie_proof"]["status"], "not_proven")
        raw_evidence = EVIDENCE_PATH.read_text(encoding="utf-8")
        for event in (
            "gateway.ready",
            "session.resume",
            "prompt.submit",
            "message.delta",
            "message.complete",
        ):
            with self.subTest(event=event):
                self.assertNotIn(f'"{event}"', raw_evidence)

        caddy_readme = (ROOT / "tests/integration/hermes-caddy/README.md").read_text(encoding="utf-8")
        scripts_readme = (ROOT / "scripts/README.md").read_text(encoding="utf-8")
        for document in (caddy_readme, scripts_readme):
            with self.subTest(document=document[:32]):
                self.assertIn("blocked_provider", document)
                self.assertIn("message.complete", document)
                self.assertIn("not_proven", document)
        self.assertIn("No browser event payload is", caddy_readme)
        self.assertIn("contains no browser event payload", scripts_readme)
        self.assertIn("HttpOnly", caddy_readme)
        self.assertIn("SameSite", caddy_readme)
        self.assertIn("Path", caddy_readme)

    def test_retained_evidence_nested_shapes_are_closed(self) -> None:
        """Reject unsupported fields inside retained evidence collections."""

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
            },
        )
        self.assertEqual(
            set(deployment["runtime_inputs"]),
            {"host", "https_port", "hermes_port", "site_root", "cert_path", "key_path", "storage_root"},
        )
        self.assertEqual(set(deployment["parity_fixtures"]), {"static_route_grammar", "deep_link_cases"})
        for fixture in deployment["parity_fixtures"].values():
            self.assertEqual(set(fixture), {"path", "sha256"})

        browser_evidence = self.evidence["browser_evidence"]
        self.assertEqual(set(browser_evidence), set(caddy_proof.BROWSER_EVIDENCE_ROOT_KEYS))
        self.assertEqual(
            set(browser_evidence["provenance"]),
            set(caddy_proof.BROWSER_EVIDENCE_PROVENANCE_KEYS),
        )
        self.assertEqual(set(browser_evidence["observations"]), {"blocker"})
        self.assertEqual(browser_evidence["observations"]["blocker"], "provider_unavailable")

        positive_key_sets = {
            "root_static": {"id", "status", "layer", "upstream_request"},
            "root_scenario_static": {"id", "status", "layer", "upstream_request", "query_policy"},
            "deep_link_session": {"id", "status", "layer", "upstream_request", "fallback"},
            "deep_link_message": {"id", "status", "layer", "upstream_request", "fallback"},
            "dashboard_provider_discovery": {"id", "status", "layer", "upstream_request"},
            "password_login": {"id", "status", "layer", "upstream_request"},
            "oauth_callback": {"id", "status", "layer", "upstream_request", "query_policy"},
            "ws_ticket": {"id", "status", "layer", "upstream_request"},
            "ws_upgrade": {"id", "status", "layer", "upstream_request", "query_policy"},
            "pty_upgrade": {"id", "status", "layer", "upstream_request", "query_policy"},
            "mock_upstream_header_rebuild": {
                "id",
                "status",
                "layer",
                "upstream_request",
                "forwarding_policy",
                "prefix_policy",
            },
        }
        positive_cases = {item["id"]: item for item in self.evidence["positive_cases"]}
        self.assertEqual(set(positive_cases), set(positive_key_sets))
        self.assertEqual(len(positive_cases), len(self.evidence["positive_cases"]))
        for case_id, expected_keys in positive_key_sets.items():
            self.assertEqual(set(positive_cases[case_id]), expected_keys, case_id)

        negative_cases = self.evidence["negative_cases"]
        self.assertEqual(len(negative_cases), 23)
        self.assertEqual(
            {item["id"] for item in negative_cases},
            {
                "wrong_host",
                "wrong_websocket_origin",
                "unknown_route",
                "unknown_method",
                "duplicate_prefix",
                "traversal",
                "encoded_separator",
                "encoded_dot",
                "malformed_upgrade",
                "missing_ticket",
                "root_query_mutation",
                "static_asset_query_mutation",
                "client_route_query_mutation",
                "rest_query_mutation",
                "pty_missing_resume",
                "pty_extra_parameter",
                "pty_duplicate_parameter",
                "pty_empty_value",
                "pty_fresh_parameter",
                "invalid_ticket",
                "ticket_expired",
                "ticket_reuse",
                "direct_private_port",
            },
        )
        for case in negative_cases:
            self.assertEqual(set(case), {"id", "status", "layer", "upstream_request"}, case["id"])

        self.assertEqual(set(self.evidence["black_box"]), {"scope", "route_vectors", "assertions", "request_material"})
        self.assertIsInstance(self.evidence["black_box"]["assertions"], list)
        self.assertTrue(all(isinstance(assertion, str) for assertion in self.evidence["black_box"]["assertions"]))

    def test_evidence_reconstructs_runtime_and_parity_inputs(self) -> None:
        deployment = self.evidence["deployment"]
        self.assertEqual(deployment["runtime_inputs_schema"], caddy_proof.RUNTIME_INPUT_SCHEMA)
        self.assertEqual(deployment["runtime_inputs"], caddy_proof.reconstruction_inputs())
        self.assertEqual(
            deployment["runtime_inputs_sha256"],
            caddy_proof.runtime_input_digest(caddy_proof.reconstruction_inputs()),
        )
        self.assertEqual(deployment["parity_fixtures"], caddy_proof.parity_fixture_manifest())
        self.assertNotIn("/Users/", json.dumps(deployment, sort_keys=True))

    def test_edge_negative_matrix_has_no_upstream_request(self) -> None:
        expected = {
            "wrong_host": (421, "edge"),
            "wrong_websocket_origin": (403, "edge"),
            "unknown_route": (404, "edge"),
            "unknown_method": (404, "edge"),
            "duplicate_prefix": (404, "edge"),
            "traversal": (404, "edge"),
            "encoded_separator": (404, "edge"),
            "encoded_dot": (404, "edge"),
            "malformed_upgrade": (404, "edge"),
            "missing_ticket": (404, "edge"),
        }
        cases = {item["id"]: item for item in self.evidence["negative_cases"]}
        for case_id, (status, layer) in expected.items():
            with self.subTest(case=case_id):
                case = cases[case_id]
                self.assertEqual(case["status"], status)
                self.assertEqual(case["layer"], layer)
                self.assertFalse(case["upstream_request"])

    def test_upstream_ticket_and_network_results_keep_layers_separate(self) -> None:
        cases = {item["id"]: item for item in self.evidence["negative_cases"]}
        self.assertEqual((cases["invalid_ticket"]["status"], cases["invalid_ticket"]["layer"]), (400, "hermes"))
        self.assertEqual((cases["ticket_expired"]["status"], cases["ticket_expired"]["layer"]), (403, "hermes"))
        self.assertEqual((cases["ticket_reuse"]["status"], cases["ticket_reuse"]["layer"]), (403, "hermes"))
        self.assertEqual(cases["direct_private_port"]["status"], "connection_denied")
        self.assertEqual(cases["direct_private_port"]["layer"], "network")
        self.assertFalse(cases["direct_private_port"]["upstream_request"])

    def test_retained_evidence_contains_no_request_material(self) -> None:
        raw = EVIDENCE_PATH.read_text(encoding="utf-8")
        for forbidden in ("?ticket=", "Cookie:", "Set-Cookie:", "Authorization:", "Bearer ", "password=", "api_key="):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, raw)
        retention = self.evidence["retention"]
        self.assertTrue(all(value == "redacted" for value in retention.values()))


class CaddyProofEvidenceCliTests(unittest.TestCase):
    """Exercise the standalone-derived and committed-retained CLI workflows."""

    def _static_root(self, root: Path) -> Path:
        for relative_path in caddy_proof.STATIC_BUILD_REQUIRED_FILES:
            path = root / relative_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"{relative_path}\\n", encoding="utf-8")
        return root

    def _browser_evidence(self, static_root: Path) -> dict[str, object]:
        provenance = caddy_proof._derive_git_static_build_provenance(static_root)
        return {
            "schema": caddy_proof.BROWSER_EVIDENCE_SCHEMA,
            "status": "passed",
            "provenance": {
                **provenance,
                "caddyfile_digest": EXPECTED_CADDYFILE_DIGEST,
                "runtime_inputs_sha256": caddy_proof.runtime_input_digest(
                    caddy_proof.reconstruction_inputs()
                ),
            },
            "observations": {"events": dict(caddy_proof.BROWSER_COMPLETION_EVIDENCE)},
        }

    def _run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(ROOT / "scripts/caddy_proof.py"), "evidence", *arguments],
            capture_output=True,
            text=True,
            check=False,
            cwd=ROOT,
        )

    def test_git_provenance_rejects_nonzero_timeout_and_malformed_output(self) -> None:
        cases = (
            subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"git failure"),
            subprocess.CompletedProcess([], 0, stdout=b"deadbeef\n", stderr=b"diagnostic"),
            subprocess.CompletedProcess([], 0, stdout=b"deadbeef\nsecond\n", stderr=b""),
            subprocess.CompletedProcess([], 0, stdout=b"\xff\n", stderr=b""),
        )
        for completed in cases:
            with self.subTest(stdout=completed.stdout, returncode=completed.returncode):
                with mock.patch.object(caddy_proof.subprocess, "run", return_value=completed):
                    with self.assertRaisesRegex(ValueError, "Git provenance"):
                        caddy_proof._git_text(ROOT, "rev-parse", "HEAD")
        with mock.patch.object(
            caddy_proof.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(["git"], caddy_proof.GIT_COMMAND_TIMEOUT_SECONDS),
        ):
            with self.assertRaisesRegex(ValueError, "Git provenance"):
                caddy_proof._git_text(ROOT, "rev-parse", "HEAD")

    def test_cli_rejects_complete_hand_authored_events_from_arbitrary_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            static_root = self._static_root(Path(directory) / "build")
            provenance = caddy_proof._derive_git_static_build_provenance(static_root)
            evidence_path = Path(directory) / "browser.json"
            evidence_path.write_text(json.dumps(self._browser_evidence(static_root)), encoding="utf-8")
            result = self._run_cli(
                "--static-build-root",
                str(static_root),
                "--build-sha",
                provenance["build_sha"],
                "--build-digest",
                provenance["build_digest"],
                "--caddyfile-digest",
                EXPECTED_CADDYFILE_DIGEST,
                "--browser-evidence",
                str(evidence_path),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("trusted execution receipt", result.stderr)

    def test_cli_rejects_browser_evidence_after_static_tree_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            static_root = self._static_root(Path(directory) / "build")
            provenance = caddy_proof._derive_git_static_build_provenance(static_root)
            evidence_path = Path(directory) / "browser.json"
            evidence_path.write_text(json.dumps(self._browser_evidence(static_root)), encoding="utf-8")
            (static_root / "index.html").write_text("drifted\n", encoding="utf-8")
            result = self._run_cli(
                "--static-build-root",
                str(static_root),
                "--build-sha",
                provenance["build_sha"],
                "--build-digest",
                provenance["build_digest"],
                "--caddyfile-digest",
                EXPECTED_CADDYFILE_DIGEST,
                "--browser-evidence",
                str(evidence_path),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not match", result.stderr)

    def test_cli_rejects_static_tree_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            static_root = self._static_root(Path(directory) / "build")
            target = Path(directory) / "outside.txt"
            target.write_text("outside\n", encoding="utf-8")
            (static_root / "extra.txt").symlink_to(target)
            result = self._run_cli(
                "--static-build-root",
                str(static_root),
                "--caddyfile-digest",
                EXPECTED_CADDYFILE_DIGEST,
                "--browser-evidence",
                str(Path(directory) / "missing.json"),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("symlink", result.stderr)

    def test_cli_rejects_exact_zero_and_one_forged_build_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            static_root = self._static_root(Path(directory) / "build")
            evidence = self._browser_evidence(static_root)
            evidence_path = Path(directory) / "browser.json"
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            derived = caddy_proof._derive_git_static_build_provenance(static_root)
            forged_values = (
                ("0" * 40, derived["build_digest"]),
                ("1" * 40, derived["build_digest"]),
                (derived["build_sha"], "0" * 64),
                (derived["build_sha"], "1" * 64),
            )
            for forged_sha, forged_digest in forged_values:
                with self.subTest(build_sha=forged_sha[0], build_digest=forged_digest[0]):
                    result = self._run_cli(
                        "--static-build-root",
                        str(static_root),
                        "--build-sha",
                        forged_sha,
                        "--build-digest",
                        forged_digest,
                        "--caddyfile-digest",
                        EXPECTED_CADDYFILE_DIGEST,
                        "--browser-evidence",
                        str(evidence_path),
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("does not match", result.stderr)

    def test_cli_rejects_duplicate_browser_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            static_root = self._static_root(Path(directory) / "build")
            evidence_path = Path(directory) / "browser.json"
            duplicate_payloads = (
                '{"schema":"%s","schema":"%s"}'
                % (caddy_proof.BROWSER_EVIDENCE_SCHEMA, caddy_proof.BROWSER_EVIDENCE_SCHEMA),
                '{"provenance":{"build_sha":"%s","build_sha":"%s"}}'
                % ("0" * 40, "1" * 40),
            )
            for payload in duplicate_payloads:
                with self.subTest(payload=payload):
                    evidence_path.write_text(payload, encoding="utf-8")
                    result = self._run_cli(
                        "--static-build-root",
                        str(static_root),
                        "--caddyfile-digest",
                        EXPECTED_CADDYFILE_DIGEST,
                        "--browser-evidence",
                        str(evidence_path),
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("duplicate JSON object key", result.stderr)

    def test_cli_rejects_oversize_browser_json_before_full_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            static_root = self._static_root(Path(directory) / "build")
            evidence_path = Path(directory) / "browser.json"
            evidence_path.write_bytes(b"{}" + b" " * caddy_proof.BROWSER_EVIDENCE_MAX_BYTES)
            result = self._run_cli(
                "--static-build-root",
                str(static_root),
                "--caddyfile-digest",
                EXPECTED_CADDYFILE_DIGEST,
                "--browser-evidence",
                str(evidence_path),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("bounded input size", result.stderr)

    def test_cli_accepts_exact_browser_json_size_boundary_for_blocked_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            static_root = self._static_root(Path(directory) / "build")
            evidence = self._browser_evidence(static_root)
            evidence["status"] = "blocked_provider"
            evidence["observations"] = {"blocker": "provider_unavailable"}
            raw = json.dumps(evidence, separators=(",", ":")).encode("utf-8")
            self.assertLessEqual(len(raw), caddy_proof.BROWSER_EVIDENCE_MAX_BYTES)
            evidence_path = Path(directory) / "browser.json"
            evidence_path.write_bytes(raw + b" " * (caddy_proof.BROWSER_EVIDENCE_MAX_BYTES - len(raw)))
            result = self._run_cli(
                "--static-build-root",
                str(static_root),
                "--caddyfile-digest",
                EXPECTED_CADDYFILE_DIGEST,
                "--browser-evidence",
                str(evidence_path),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["browser_journey"], "blocked_provider")

    def test_cli_rejects_malformed_utf8_and_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            static_root = self._static_root(Path(directory) / "build")
            evidence_path = Path(directory) / "browser.json"
            for payload, message in ((b"\xff", "valid UTF-8"), (b"{", "valid JSON")):
                evidence_path.write_bytes(payload)
                result = self._run_cli(
                    "--static-build-root",
                    str(static_root),
                    "--caddyfile-digest",
                    EXPECTED_CADDYFILE_DIGEST,
                    "--browser-evidence",
                    str(evidence_path),
                )
                with self.subTest(message=message):
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(message, result.stderr)

    def test_cli_accepts_committed_retained_input_without_local_static_files(self) -> None:
        result = self._run_cli("--retained-input", str(EVIDENCE_PATH))
        self.assertEqual(result.returncode, 0, result.stderr)
        retained = json.loads(result.stdout)
        self.assertEqual(retained["browser_journey"], "blocked_provider")
        self.assertEqual(retained["product"]["build_commit"], EXPECTED_BUILD_SHA)
        self.assertEqual(retained["deployment"]["runtime_inputs"], caddy_proof.reconstruction_inputs())
        self.assertEqual(
            retained["browser_execution"],
            {"mode": caddy_proof.BROWSER_NON_EXECUTION_MODE, "status": "not_proven"},
        )

    def test_cli_rejects_relative_retained_input_path(self) -> None:
        relative = EVIDENCE_PATH.relative_to(ROOT)
        result = self._run_cli("--retained-input", str(relative))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("canonical committed evidence path", result.stderr)

    def test_readme_retained_example_constructs_absolute_canonical_path(self) -> None:
        readme = (ROOT / "scripts/README.md").read_text(encoding="utf-8")
        self.assertIn('REPO_ROOT="$(git rev-parse --show-toplevel)"', readme)
        self.assertIn(
            '--retained-input "$REPO_ROOT/tests/integration/hermes-caddy/caddy-proof-evidence.json"',
            readme,
        )
        self.assertNotIn(
            "--retained-input tests/integration/hermes-caddy/caddy-proof-evidence.json",
            readme,
        )

    def test_cli_rejects_changed_retained_copy_before_consuming_browser_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "caddy-proof-evidence.json"
            copied.write_bytes(EVIDENCE_PATH.read_bytes().replace(b'"blocked_provider"', b'"passed________"', 1))
            result = self._run_cli("--retained-input", str(copied))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("canonical committed evidence path", result.stderr)

    def test_cli_rejects_retained_copy_even_when_json_is_malformed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "caddy-proof-evidence.json"
            copied.write_bytes(b"\xff")
            result = self._run_cli("--retained-input", str(copied))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("canonical committed evidence path", result.stderr)

    def test_retained_anchor_is_fixed_not_caller_supplied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            anchor = Path(directory) / "anchor.txt"
            anchor.write_text("0" * 64 + "\n", encoding="ascii")
            with mock.patch.object(caddy_proof, "RETAINED_EVIDENCE_ANCHOR_PATH", anchor):
                with self.assertRaisesRegex(ValueError, "malformed or stale"):
                    caddy_proof._read_verified_retained_bytes(EVIDENCE_PATH)


class CaddyProofInputBoundaryTests(unittest.TestCase):
    """Keep bounded JSON and Git trust-root helpers reject-by-default."""

    def test_bounded_json_accepts_exact_limit_and_rejects_one_byte_over(self) -> None:
        for limit, label in (
            (caddy_proof.BROWSER_EVIDENCE_MAX_BYTES, "browser evidence"),
            (caddy_proof.RETAINED_EVIDENCE_MAX_BYTES, "retained input"),
        ):
            with self.subTest(limit=limit):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "fixture.json"
                    path.write_bytes(b"{}" + b" " * (limit - 2))
                    self.assertEqual(
                        caddy_proof._load_bounded_json(path, limit=limit, label=label),
                        {},
                    )
                    path.write_bytes(b"{}" + b" " * (limit - 1))
                    with self.assertRaisesRegex(ValueError, "bounded input size"):
                        caddy_proof._load_bounded_json(path, limit=limit, label=label)

    def test_bounded_json_rejects_duplicate_keys_nonfinite_malformed_input(self) -> None:
        payloads = (
            (b'{"x":1,"x":2}', "duplicate JSON object key"),
            (b'{"x":NaN}', "non-finite JSON number"),
            (b"\x80", "not valid UTF-8"),
            (b"{", "not valid JSON"),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.json"
            for payload, error_fragment in payloads:
                with self.subTest(payload=payload):
                    path.write_bytes(payload)
                    with self.assertRaisesRegex(ValueError, error_fragment):
                        caddy_proof._load_bounded_json(
                            path,
                            limit=caddy_proof.BROWSER_EVIDENCE_MAX_BYTES,
                            label="browser evidence",
                        )


class CaddyProofJsonBudgetTests(unittest.TestCase):
    """Keep parser resource limits independent from the outer byte cap."""

    def _budget(self, name: str) -> int:
        value = getattr(caddy_proof, name, None)
        self.assertIsInstance(value, int, f"caddy_proof must expose {name}")
        self.assertGreater(value, 0, f"caddy_proof.{name} must be positive")
        return value

    def _assert_rejected_under_byte_cap(self, raw: bytes, message: str) -> None:
        self.assertLess(len(raw), caddy_proof.BROWSER_EVIDENCE_MAX_BYTES)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.json"
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, message):
                caddy_proof._load_bounded_json(
                    path,
                    limit=caddy_proof.BROWSER_EVIDENCE_MAX_BYTES,
                    label="browser evidence",
                )

    def test_parse_float_rejects_positive_and_negative_exponent_overflow(self) -> None:
        for raw in (b"1e999", b"-1e999"):
            with self.subTest(raw=raw):
                self._assert_rejected_under_byte_cap(raw, "finite|overflow|number")

    def test_json_depth_budget_is_enforced_below_byte_cap(self) -> None:
        depth = self._budget("JSON_MAX_DEPTH")
        value: object = 0
        for _ in range(depth + 1):
            value = {"x": value}
        raw = json.dumps(value, separators=(",", ":")).encode("ascii")
        self._assert_rejected_under_byte_cap(raw, "depth|nesting")

    def test_json_total_node_budget_is_enforced_below_byte_cap(self) -> None:
        node_limit = self._budget("JSON_MAX_NODES")
        key_limit = self._budget("JSON_MAX_OBJECT_KEYS")
        array_limit = self._budget("JSON_MAX_ARRAY_LENGTH")
        keys = min(key_limit, 8)
        width = min(array_limit, max(1, (node_limit // keys) + 1))
        value = {f"k{index}": [0] * width for index in range(keys)}
        node_count = 1 + sum(1 + width for _ in range(keys))
        self.assertGreater(node_count, node_limit)
        raw = json.dumps(value, separators=(",", ":")).encode("ascii")
        self._assert_rejected_under_byte_cap(raw, "node|budget")

    def test_json_object_key_budget_is_enforced_below_byte_cap(self) -> None:
        key_limit = self._budget("JSON_MAX_OBJECT_KEYS")
        value = {f"k{index}": 0 for index in range(key_limit + 1)}
        raw = json.dumps(value, separators=(",", ":")).encode("ascii")
        self._assert_rejected_under_byte_cap(raw, "object key|keys|budget")

    def test_json_array_length_budget_is_enforced_below_byte_cap(self) -> None:
        array_limit = self._budget("JSON_MAX_ARRAY_LENGTH")
        raw = json.dumps([0] * (array_limit + 1), separators=(",", ":")).encode("ascii")
        self._assert_rejected_under_byte_cap(raw, "array|length|budget")

    def test_json_string_budget_is_enforced_below_byte_cap(self) -> None:
        string_limit = self._budget("JSON_MAX_STRING_BYTES")
        raw = json.dumps("x" * (string_limit + 1), separators=(",", ":")).encode("ascii")
        self._assert_rejected_under_byte_cap(raw, "string|length|budget")


class CaddyProofStaticDigestBoundaryTests(unittest.TestCase):
    """Keep static-tree hashing finite and regular-file-only."""

    def _write(self, root: Path, relative: str, content: bytes = b"x") -> Path:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def _limit(self, name: str) -> int:
        value = getattr(caddy_proof, name, None)
        self.assertIsInstance(value, int, f"caddy_proof must expose {name}")
        self.assertGreater(value, 0, f"caddy_proof.{name} must be positive")
        return value

    def test_static_digest_rejects_file_count_overflow(self) -> None:
        self._limit("STATIC_BUILD_MAX_FILES")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "site"
            root.mkdir()
            with mock.patch.object(caddy_proof, "STATIC_BUILD_MAX_FILES", 2):
                for index in range(3):
                    self._write(root, f"file-{index}")
                with self.assertRaisesRegex(ValueError, "file|count|budget"):
                    caddy_proof._build_static_digest(root)

    def test_static_digest_rejects_per_file_and_aggregate_byte_overflow(self) -> None:
        self._limit("STATIC_BUILD_MAX_FILE_BYTES")
        self._limit("STATIC_BUILD_MAX_TOTAL_BYTES")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "site"
            root.mkdir()
            with mock.patch.object(caddy_proof, "STATIC_BUILD_MAX_FILE_BYTES", 4):
                self._write(root, "oversized", b"12345")
                with self.assertRaisesRegex(ValueError, "file|bytes|budget"):
                    caddy_proof._build_static_digest(root)

            for child in root.iterdir():
                child.unlink()
            with mock.patch.object(caddy_proof, "STATIC_BUILD_MAX_TOTAL_BYTES", 8):
                self._write(root, "first", b"12345")
                self._write(root, "second", b"67890")
                with self.assertRaisesRegex(ValueError, "aggregate|total|bytes|budget"):
                    caddy_proof._build_static_digest(root)

    def test_static_digest_rejects_depth_overflow(self) -> None:
        self._limit("STATIC_BUILD_MAX_DEPTH")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "site"
            root.mkdir()
            with mock.patch.object(caddy_proof, "STATIC_BUILD_MAX_DEPTH", 2):
                self._write(root, "one/two/three/file.txt")
                with self.assertRaisesRegex(ValueError, "depth|budget"):
                    caddy_proof._build_static_digest(root)

    def test_static_digest_aborts_after_deadline(self) -> None:
        self._limit("STATIC_BUILD_DEADLINE_SECONDS")
        self.assertTrue(hasattr(caddy_proof, "time"), "static digest must expose its monotonic clock")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "site"
            root.mkdir()
            self._write(root, "file.txt")
            ticks = iter((0.0, 1.0))
            with (
                mock.patch.object(caddy_proof, "STATIC_BUILD_DEADLINE_SECONDS", 0.5),
                mock.patch.object(caddy_proof.time, "monotonic", side_effect=lambda: next(ticks, 1.0)),
            ):
                with self.assertRaisesRegex(ValueError, "deadline|timed out|budget"):
                    caddy_proof._build_static_digest(root)

    def test_static_digest_deadline_covers_root_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "site"
            root.mkdir()
            self._write(root, "file.txt")
            real_resolve = Path.resolve
            clock = [0.0]

            def slow_resolve(path: Path, *args: object, **kwargs: object) -> Path:
                resolved = real_resolve(path, *args, **kwargs)
                clock[0] = 1.0
                return resolved

            with (
                mock.patch.object(caddy_proof, "STATIC_BUILD_DEADLINE_SECONDS", 0.5),
                mock.patch.object(caddy_proof.time, "monotonic", side_effect=lambda: clock[0]),
                mock.patch.object(Path, "resolve", autospec=True, side_effect=slow_resolve),
            ):
                with self.assertRaisesRegex(ValueError, "deadline|timed out|budget"):
                    caddy_proof._build_static_digest(root)

    def test_static_digest_deadline_covers_final_hexdigest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "site"
            root.mkdir()
            self._write(root, "file.txt")
            real_sha256 = caddy_proof.hashlib.sha256
            clock = [0.0]

            class SlowHasher:
                def __init__(self) -> None:
                    self._delegate = real_sha256()

                def update(self, value: bytes) -> None:
                    self._delegate.update(value)

                def hexdigest(self) -> str:
                    clock[0] = 1.0
                    return self._delegate.hexdigest()

            with (
                mock.patch.object(caddy_proof, "STATIC_BUILD_DEADLINE_SECONDS", 0.5),
                mock.patch.object(caddy_proof.time, "monotonic", side_effect=lambda: clock[0]),
                mock.patch.object(caddy_proof.hashlib, "sha256", return_value=SlowHasher()),
            ):
                with self.assertRaisesRegex(ValueError, "deadline|timed out|budget"):
                    caddy_proof._build_static_digest(root)

    def test_static_digest_rejects_scandir_that_finishes_after_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "site"
            root.mkdir()
            clock = [0.0]

            class SlowEmptyScan:
                def __enter__(self):
                    clock[0] = 1.0
                    return iter(())

                def __exit__(self, exc_type, exc_value, traceback):
                    return False

            with (
                mock.patch.object(caddy_proof, "STATIC_BUILD_DEADLINE_SECONDS", 0.5),
                mock.patch.object(caddy_proof.time, "monotonic", side_effect=lambda: clock[0]),
                mock.patch.object(caddy_proof.os, "scandir", return_value=SlowEmptyScan()),
            ):
                with self.assertRaisesRegex(ValueError, "deadline|timed out|budget"):
                    caddy_proof._build_static_digest(root)

    def test_static_digest_rejects_slow_final_eof_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "site"
            root.mkdir()
            self._write(root, "file.txt", b"content")
            real_read = caddy_proof.os.read
            clock = [0.0]
            reads = [0]

            def slow_eof_read(descriptor: int, size: int) -> bytes:
                reads[0] += 1
                chunk = real_read(descriptor, size)
                if not chunk:
                    clock[0] = 1.0
                return chunk

            with (
                mock.patch.object(caddy_proof, "STATIC_BUILD_DEADLINE_SECONDS", 0.5),
                mock.patch.object(caddy_proof.time, "monotonic", side_effect=lambda: clock[0]),
                mock.patch.object(caddy_proof.os, "read", side_effect=slow_eof_read),
            ):
                with self.assertRaisesRegex(ValueError, "deadline|timed out|budget"):
                    caddy_proof._build_static_digest(root)
            self.assertGreaterEqual(reads[0], 2)

    def test_static_digest_rejects_same_size_in_place_mutation_during_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "site"
            root.mkdir()
            path = self._write(root, "file.txt", b"AAAA")
            real_read = caddy_proof.os.read
            mutated = [False]

            def racing_read(descriptor: int, size: int) -> bytes:
                if not mutated[0]:
                    path.write_bytes(b"BBBB")
                    mutated[0] = True
                return real_read(descriptor, size)

            with mock.patch.object(caddy_proof.os, "read", side_effect=racing_read):
                with self.assertRaisesRegex(ValueError, "changed|identity|content"):
                    caddy_proof._build_static_digest(root)

    def test_static_digest_rejects_fifo_and_unix_socket(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "site"
            root.mkdir()
            fifo = root / "pipe"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, "special|regular|FIFO|file"):
                caddy_proof._build_static_digest(root)

            fifo.unlink()
            unix_socket = root / "socket"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.addCleanup(listener.close)
            listener.bind(str(unix_socket))
            with self.assertRaisesRegex(ValueError, "special|regular|socket|file"):
                caddy_proof._build_static_digest(root)

    def test_static_digest_rejects_character_device_entry(self) -> None:
        """Use a lstat seam when an unprivileged runner cannot create a device node."""

        self.assertTrue(hasattr(caddy_proof, "os"), "static digest must inspect lstat metadata")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "site"
            root.mkdir()
            device = self._write(root, "device")
            real_rglob = Path.rglob
            real_lstat = os.lstat
            fake_mode = stat.S_IFCHR | 0o600
            fake_stat = os.stat_result((fake_mode, 0, 0, 1, 0, 0, 0, 0, 0, 0))

            def fake_rglob(path: Path, pattern: str):
                if path == root:
                    return iter((device,))
                return real_rglob(path, pattern)

            def fake_lstat(path: os.PathLike[str] | str, *args: object, **kwargs: object):
                if Path(path) == device:
                    return fake_stat
                return real_lstat(path, *args, **kwargs)

            with (
                mock.patch.object(Path, "rglob", side_effect=fake_rglob),
                mock.patch.object(caddy_proof.os, "lstat", side_effect=fake_lstat),
            ):
                with self.assertRaisesRegex(ValueError, "special|regular|device|file"):
                    caddy_proof._build_static_digest(root)


class CaddyProofRetainedPathBoundaryTests(unittest.TestCase):
    """Keep the retained evidence trust root lexical and race-resistant."""

    def _assert_rejected(self, path: Path) -> None:
        with self.assertRaisesRegex(ValueError, "canonical|retained|resolved|path"):
            caddy_proof._canonical_retained_path(path)

    def test_canonical_retained_path_rejects_lexical_parent_components(self) -> None:
        lexical_parent = EVIDENCE_PATH.parent / ".." / EVIDENCE_PATH.parent.name / EVIDENCE_PATH.name
        self.assertIn("..", lexical_parent.parts)
        self._assert_rejected(lexical_parent)

    def test_canonical_retained_path_rejects_symlinked_parent_and_final_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent_link = root / "parent-link"
            parent_link.symlink_to(EVIDENCE_PATH.parent, target_is_directory=True)
            self._assert_rejected(parent_link / EVIDENCE_PATH.name)

            final_link = root / "evidence-link.json"
            final_link.symlink_to(EVIDENCE_PATH)
            self._assert_rejected(final_link)

    def test_canonical_retained_path_rejects_hardlink_and_copy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hardlink = root / "evidence-hardlink.json"
            os.link(EVIDENCE_PATH, hardlink)
            self._assert_rejected(hardlink)

            copied = root / "evidence-copy.json"
            shutil.copyfile(EVIDENCE_PATH, copied)
            self._assert_rejected(copied)

    def test_verified_retained_read_rejects_replacement_after_path_precheck(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence.json"
            anchor = root / "evidence.sha256"
            original = b'{"trusted":true}\n'
            replacement = root / "replacement.json"
            evidence.write_bytes(original)
            anchor.write_text(caddy_proof.digest_bytes(original) + "\n", encoding="ascii")
            canonical = caddy_proof._canonical_retained_path

            def replace_after_precheck(path: Path) -> Path:
                resolved = canonical(path)
                replacement.write_bytes(b'{"trusted":false}\n')
                os.replace(replacement, resolved)
                return resolved

            with (
                mock.patch.object(caddy_proof, "RETAINED_EVIDENCE_PATH", evidence),
                mock.patch.object(caddy_proof, "RETAINED_EVIDENCE_ANCHOR_PATH", anchor),
                mock.patch.object(caddy_proof, "RETAINED_EVIDENCE_ANCHOR", caddy_proof.digest_bytes(original)),
                mock.patch.object(caddy_proof, "_canonical_retained_path", side_effect=replace_after_precheck),
            ):
                with self.assertRaisesRegex(ValueError, "anchor|changed|race|retained"):
                    caddy_proof._read_verified_retained_bytes(evidence)


class CaddyProofGitBoundaryTests(unittest.TestCase):
    """Keep Git provenance local, deterministic, and non-fetching."""

    def _strict_git_environment(self) -> dict[str, str]:
        helper = getattr(caddy_proof, "_strict_git_environment", None)
        self.assertTrue(callable(helper), "implementation must expose _strict_git_environment")
        value = helper()
        self.assertIsInstance(value, dict)
        return value

    def test_git_text_rejects_none_stderr_as_malformed(self) -> None:
        completed = subprocess.CompletedProcess(
            [], 0, stdout=(b"0" * 40) + b"\n", stderr=None
        )
        with mock.patch.object(caddy_proof.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(ValueError, "stderr|diagnostics|malformed"):
                caddy_proof._git_text(ROOT, "rev-parse", "HEAD")

    def test_git_environment_removes_fake_path_config_and_object_redirects(self) -> None:
        hostile = {
            "PATH": "/tmp/fake-git-bin",
            "GIT_CONFIG_NOSYSTEM": "0",
            "GIT_CONFIG_GLOBAL": "/tmp/hostile-global",
            "GIT_CONFIG_SYSTEM": "/tmp/hostile-system",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/tmp/hostile-alternates",
            "GIT_OBJECT_DIRECTORY": "/tmp/hostile-objects",
            "GIT_GRAFT_FILE": "/tmp/hostile-grafts",
            "GIT_REPLACE_REF_BASE": "refs/replace-hostile",
            "GIT_NO_REPLACE_OBJECTS": "0",
            "GIT_NO_LAZY_FETCH": "0",
        }
        with mock.patch.dict(os.environ, hostile, clear=False):
            environment = self._strict_git_environment()
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertEqual(environment["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(environment["GIT_CONFIG_SYSTEM"], os.devnull)
        self.assertNotEqual(environment["PATH"], hostile["PATH"])
        for variable in (
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_OBJECT_DIRECTORY",
            "GIT_GRAFT_FILE",
            "GIT_REPLACE_REF_BASE",
        ):
            self.assertNotIn(variable, environment)

    def test_git_commands_disable_replace_and_lazy_fetch(self) -> None:
        reader = getattr(caddy_proof, "_git", None)
        runner = getattr(caddy_proof, "_run_bounded_git", None)
        self.assertTrue(callable(reader), "implementation must expose _git")
        self.assertTrue(callable(runner), "implementation must expose _run_bounded_git")
        with mock.patch.object(
            caddy_proof,
            "_run_bounded_git",
            return_value=(0, (b"0" * 40) + b"\n", b""),
        ) as run:
            reader(ROOT, "rev-parse", "--verify", "HEAD^{commit}")
        call = run.call_args
        command = call.args[0] if call.args else call.kwargs["command"]
        environment = call.args[1] if len(call.args) > 1 else call.kwargs["environment"]
        self.assertIn("--no-replace-objects", command)
        self.assertIn("--no-lazy-fetch", command)
        self.assertIn("--no-optional-locks", command)
        self.assertNotIn("-C", command)
        self.assertIsInstance(getattr(command, "cwd_fd", None), int)
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertEqual(environment["GIT_NO_LAZY_FETCH"], "1")

    def test_fake_path_cannot_intercept_git_provenance(self) -> None:
        expected = caddy_proof._git_head(ROOT)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            marker = root / "fake-git-used"
            shim = fake_bin / "git"
            shim.write_text(
                f"#!/bin/sh\nprintf used > '{marker}'\nprintf '%040d\\n' 0\n",
                encoding="ascii",
            )
            shim.chmod(0o755)
            with mock.patch.dict(
                os.environ,
                {"PATH": str(fake_bin), "GIT_CONFIG_NOSYSTEM": "0"},
                clear=False,
            ):
                try:
                    observed = caddy_proof._git_head(ROOT)
                except ValueError:
                    observed = None
            self.assertFalse(marker.exists())
            if observed is not None:
                self.assertEqual(observed, expected)

    def test_shallow_repository_is_rejected_by_git_trust_check(self) -> None:
        verifier = getattr(caddy_proof, "_verify_git_repository", None)
        if verifier is None:
            verifier = getattr(caddy_proof, "_verify_git_repository_integrity", None)
        self.assertTrue(callable(verifier), "implementation must expose a repository trust check")
        with tempfile.TemporaryDirectory() as directory:
            shallow = Path(directory) / "shallow"
            subprocess.run(
                ["git", "clone", "--no-local", "--depth", "1", "--quiet", ROOT.as_uri(), str(shallow)],
                check=True,
                capture_output=True,
            )
            self.assertTrue((shallow / ".git" / "shallow").is_file())
            with self.assertRaisesRegex(ValueError, "shallow|history|repository"):
                verifier(shallow)

    def _init_repository(self, root: Path) -> Path:
        subprocess.run(["git", "init", "--quiet", str(root)], check=True, capture_output=True)
        self.assertTrue((root / ".git").is_dir())
        return root

    def _commit_fixture(self, repository: Path, name: str, content: str) -> str:
        path = repository / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        subprocess.run(["git", "-C", str(repository), "add", name], check=True, capture_output=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "-c",
                "user.name=fixture",
                "-c",
                "user.email=fixture@example.test",
                "commit",
                "--quiet",
                "-m",
                f"fixture {name}",
            ],
            check=True,
            capture_output=True,
        )
        return subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def _run_git_with_real_subprocess_mutation(
        self,
        repository: Path,
        mutation_script: str,
        mutation_args: tuple[Path, ...],
        *git_arguments: str,
    ) -> list[tuple[int, bytes, bytes]]:
        """Mutate metadata in a child before the real Git subprocess starts."""

        marker = repository.parent / f"mutation-{os.getpid()}-{time.monotonic_ns()}.ready"
        mutation = [
            sys.executable,
            "-c",
            mutation_script,
            *(str(path) for path in mutation_args),
            str(marker),
        ]
        observed: list[tuple[int, bytes, bytes]] = []
        real_runner = caddy_proof._run_bounded_git

        def run_after_mutation(command, environment):
            child = subprocess.Popen(
                mutation,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                deadline = time.monotonic() + 3.0
                while not marker.exists():
                    if child.poll() is not None:
                        stdout, stderr = child.communicate()
                        self.fail(
                            "metadata mutation subprocess failed: "
                            + (stderr or stdout).decode("utf-8", "replace")
                        )
                    if time.monotonic() >= deadline:
                        child.kill()
                        child.communicate()
                        self.fail("metadata mutation subprocess did not signal readiness")
                    time.sleep(0.005)
                result = real_runner(command, environment)
                observed.append(result)
                return result
            finally:
                try:
                    child.communicate(timeout=3.0)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.communicate(timeout=3.0)
                marker.unlink(missing_ok=True)

        with mock.patch.object(caddy_proof, "_run_bounded_git", side_effect=run_after_mutation):
            with self.assertRaisesRegex(ValueError, "metadata changed|changed|symlink|content|identity"):
                caddy_proof._git_text(repository, *git_arguments)
        return observed

    def test_promisor_and_partial_clone_config_are_rejected(self) -> None:
        verifier = caddy_proof._verify_git_repository
        for key in ("extensions.partialClone", "remote.origin.promisor"):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                repository = self._init_repository(Path(directory) / "repo")
                subprocess.run(
                    ["git", "-C", str(repository), "config", key, "true"],
                    check=True,
                    capture_output=True,
                )
                with self.assertRaisesRegex(ValueError, "promisor|lazy|partial"):
                    verifier(repository)

    def test_key_only_partial_promisor_and_include_config_are_rejected(self) -> None:
        configs = (
            "[extensions]\n\tpartialClone\n",
            "[remote \"origin\"]\n\tpromisor\n",
            "[include]\n\tpath = /tmp/hostile-config\n",
            "[includeIf \"gitdir:/tmp\"]\n\tpath = /tmp/hostile-config\n",
        )
        for config_fragment in configs:
            with self.subTest(config=config_fragment), tempfile.TemporaryDirectory() as directory:
                repository = self._init_repository(Path(directory) / "repo")
                config = repository / ".git" / "config"
                config.write_text(config.read_text(encoding="utf-8") + config_fragment, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "include|promisor|partial|lazy"):
                    caddy_proof._verify_git_repository(repository)

    def test_active_worktree_config_promisor_metadata_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = self._init_repository(Path(directory) / "repo")
            config = repository / ".git" / "config"
            config.write_text(
                config.read_text(encoding="utf-8")
                + "[extensions]\n\tworktreeConfig = true\n",
                encoding="utf-8",
            )
            (repository / ".git" / "config.worktree").write_text(
                "[remote \"origin\"]\n\tpromisor\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "promisor|partial|lazy|worktree"):
                caddy_proof._verify_git_repository(repository)

    def test_git_whole_root_replacement_is_descriptor_bound_and_rejected(self) -> None:
        mutation = (
            "from pathlib import Path; import sys; "
            "root,moved,replacement,marker=map(Path,sys.argv[1:]); "
            "root.rename(moved); replacement.rename(root); marker.write_text('ready')"
        )
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            repository = self._init_repository(parent / "repo")
            original_sha = self._commit_fixture(repository, "original.txt", "original\n")
            replacement = self._init_repository(parent / "replacement")
            replacement_sha = self._commit_fixture(replacement, "replacement.txt", "replacement\n")
            moved = parent / "moved-original"
            observed = self._run_git_with_real_subprocess_mutation(
                repository,
                mutation,
                (repository, moved, replacement),
                "rev-parse",
                "HEAD",
            )
            self.assertEqual(observed[0][1], f"{original_sha}\n".encode("ascii"))
            self.assertNotEqual(observed[0][1], f"{replacement_sha}\n".encode("ascii"))

    def test_git_nested_ref_regular_replacement_is_rejected(self) -> None:
        mutation = (
            "from pathlib import Path; import os,sys; "
            "target,replacement,marker=map(Path,sys.argv[1:]); "
            "os.replace(replacement,target); marker.write_text('ready')"
        )
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            repository = self._init_repository(parent / "repo")
            first_sha = self._commit_fixture(repository, "first.txt", "first\n")
            nested_ref = repository / ".git" / "refs" / "heads" / "nested" / "topic"
            nested_ref.parent.mkdir(parents=True)
            nested_ref.write_text(f"{first_sha}\n", encoding="ascii")
            second_sha = self._commit_fixture(repository, "second.txt", "second\n")
            replacement = parent / "replacement-ref"
            replacement.write_text(f"{second_sha}\n", encoding="ascii")
            observed = self._run_git_with_real_subprocess_mutation(
                repository,
                mutation,
                (nested_ref, replacement),
                "rev-parse",
                "--verify",
                "refs/heads/nested/topic^{commit}",
            )
            self.assertEqual(observed[0][1], f"{second_sha}\n".encode("ascii"))

    def test_git_same_inode_head_rewrite_is_rejected(self) -> None:
        mutation = """
from pathlib import Path
import os
import sys

target, replacement, marker = map(Path, sys.argv[1:])
content = replacement.read_bytes()
with target.open("r+b") as handle:
    if handle.seek(0, os.SEEK_END) != len(content):
        raise RuntimeError("same-inode mutation changed the target size")
    handle.seek(0)
    handle.write(content)
    handle.flush()
    os.fsync(handle.fileno())
marker.write_text("ready")
"""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            repository = self._init_repository(parent / "repo")
            head = self._commit_fixture(repository, "fixture.txt", "fixture\n")
            subprocess.run(["git", "-C", str(repository), "branch", "-M", "topic-a"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(repository), "branch", "topic-b"], check=True, capture_output=True)
            replacement = parent / "replacement-head"
            replacement.write_bytes(b"ref: refs/heads/topic-b\n")
            target = repository / ".git" / "HEAD"
            self.assertEqual(target.stat().st_size, replacement.stat().st_size)
            observed = self._run_git_with_real_subprocess_mutation(
                repository,
                mutation,
                (target, replacement),
                "rev-parse",
                "HEAD",
            )
            self.assertEqual(observed[0][1], f"{head}\n".encode("ascii"))

    def test_git_same_inode_nested_ref_rewrite_is_rejected(self) -> None:
        mutation = """
from pathlib import Path
import os
import sys

target, replacement, marker = map(Path, sys.argv[1:])
content = replacement.read_bytes()
with target.open("r+b") as handle:
    if handle.seek(0, os.SEEK_END) != len(content):
        raise RuntimeError("same-inode mutation changed the target size")
    handle.seek(0)
    handle.write(content)
    handle.flush()
    os.fsync(handle.fileno())
marker.write_text("ready")
"""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            repository = self._init_repository(parent / "repo")
            first_sha = self._commit_fixture(repository, "first.txt", "first\n")
            nested_ref = repository / ".git" / "refs" / "heads" / "nested" / "topic"
            nested_ref.parent.mkdir(parents=True)
            nested_ref.write_text(f"{first_sha}\n", encoding="ascii")
            second_sha = self._commit_fixture(repository, "second.txt", "second\n")
            replacement = parent / "replacement-ref"
            replacement.write_text(f"{second_sha}\n", encoding="ascii")
            self.assertEqual(nested_ref.stat().st_size, replacement.stat().st_size)
            observed = self._run_git_with_real_subprocess_mutation(
                repository,
                mutation,
                (nested_ref, replacement),
                "rev-parse",
                "--verify",
                "refs/heads/nested/topic^{commit}",
            )
            self.assertEqual(observed[0][1], f"{second_sha}\n".encode("ascii"))

    def test_git_nested_ref_symlink_replacement_is_rejected(self) -> None:
        mutation = (
            "from pathlib import Path; import sys; "
            "target,moved,marker=map(Path,sys.argv[1:]); "
            "target.rename(moved); target.symlink_to(moved); marker.write_text('ready')"
        )
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            repository = self._init_repository(parent / "repo")
            head = self._commit_fixture(repository, "fixture.txt", "fixture\n")
            nested_ref = repository / ".git" / "refs" / "heads" / "nested" / "topic"
            nested_ref.parent.mkdir(parents=True)
            nested_ref.write_text(f"{head}\n", encoding="ascii")
            moved = parent / "moved-nested-ref"
            observed = self._run_git_with_real_subprocess_mutation(
                repository,
                mutation,
                (nested_ref, moved),
                "rev-parse",
                "--verify",
                "refs/heads/nested/topic^{commit}",
            )
            self.assertEqual(observed[0][1], f"{head}\n".encode("ascii"))

    def test_git_pack_index_in_place_bytes_are_rejected(self) -> None:
        mutation = """
from pathlib import Path
import os
import sys

target, replacement, marker = map(Path, sys.argv[1:])
content = replacement.read_bytes()
with target.open("r+b") as handle:
    if handle.seek(0, os.SEEK_END) != len(content):
        raise RuntimeError("same-inode mutation changed the target size")
    handle.seek(0)
    handle.write(content)
    handle.flush()
    os.fsync(handle.fileno())
marker.write_text("ready")
"""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            repository = self._init_repository(parent / "repo")
            head = self._commit_fixture(repository, "fixture.txt", "fixture\n")
            subprocess.run(
                ["git", "-C", str(repository), "repack", "-ad"],
                check=True,
                capture_output=True,
            )
            indexes = sorted((repository / ".git" / "objects" / "pack").glob("*.idx"))
            self.assertTrue(indexes)
            target = indexes[0]
            target.chmod(0o600)
            replacement = parent / "replacement-index"
            original = target.read_bytes()
            self.assertTrue(original)
            mutated = bytes([original[0] ^ 1]) + original[1:]
            replacement.write_bytes(mutated)
            observed = self._run_git_with_real_subprocess_mutation(
                repository,
                mutation,
                (target, replacement),
                "cat-file",
                "-p",
                head,
            )
            self.assertIsInstance(observed[0][0], int)

    def test_git_metadata_depth_and_aggregate_caps_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            repository = self._init_repository(parent / "repo")
            nested = repository / ".git" / "refs" / "heads"
            for index in range(caddy_proof.GIT_METADATA_MAX_DEPTH):
                nested = nested / f"d{index}"
                nested.mkdir()
            (nested / "topic").write_text(f"{'0' * 40}\n", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "depth"):
                caddy_proof._validate_git_metadata(repository)

        with tempfile.TemporaryDirectory() as directory:
            repository = self._init_repository(Path(directory) / "repo")
            with mock.patch.object(caddy_proof, "GIT_METADATA_TOTAL_CONTENT_MAX_BYTES", 1):
                with self.assertRaisesRegex(ValueError, "content size|bounded"):
                    caddy_proof._validate_git_metadata(repository)

    def test_git_loose_object_in_place_bytes_are_rejected(self) -> None:
        mutation = """
from pathlib import Path
import os
import sys

target, marker = map(Path, sys.argv[1:])
with target.open("r+b") as handle:
    data = handle.read(1)
    handle.seek(0)
    handle.write(bytes([data[0] ^ 1]))
    handle.flush()
    os.fsync(handle.fileno())
marker.write_text("ready")
"""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            repository = self._init_repository(parent / "repo")
            self._commit_fixture(repository, "fixture.txt", "fixture\n")
            blob = subprocess.run(
                ["git", "-C", str(repository), "hash-object", "-w", "--stdin"],
                input=b"loose-object-fixture\n",
                check=True,
                capture_output=True,
            ).stdout.decode("ascii").strip()
            loose_object = repository / ".git" / "objects" / blob[:2] / blob[2:]
            self.assertTrue(loose_object.is_file())
            loose_object.chmod(0o600)
            observed = self._run_git_with_real_subprocess_mutation(
                repository,
                mutation,
                (loose_object,),
                "cat-file",
                "-p",
                blob,
            )
            self.assertIsInstance(observed[0][0], int)

    def test_git_config_swap_after_validation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = self._init_repository(Path(directory) / "repo")
            config = repository / ".git" / "config"
            replacement = Path(directory) / "replacement-config"
            replacement.write_text(
                config.read_text(encoding="utf-8") + '[remote "origin"]\n\tpromisor = true\n',
                encoding="utf-8",
            )
            real_runner = caddy_proof._run_bounded_git
            swapped = [False]

            def swap_before_command(command, environment):
                if not swapped[0]:
                    os.replace(replacement, config)
                    swapped[0] = True
                return real_runner(command, environment)

            with mock.patch.object(caddy_proof, "_run_bounded_git", side_effect=swap_before_command):
                with self.assertRaisesRegex(ValueError, "metadata changed|promisor|lazy|partial"):
                    caddy_proof._verify_git_repository(repository)
            self.assertTrue(swapped[0])

    def test_git_objects_swap_after_validation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = self._init_repository(Path(directory) / "repo")
            objects = repository / ".git" / "objects"
            moved = Path(directory) / "moved-objects"
            real_runner = caddy_proof._run_bounded_git
            swapped = [False]

            def swap_before_command(command, environment):
                if not swapped[0]:
                    objects.rename(moved)
                    objects.symlink_to(moved, target_is_directory=True)
                    swapped[0] = True
                return real_runner(command, environment)

            with mock.patch.object(caddy_proof, "_run_bounded_git", side_effect=swap_before_command):
                with self.assertRaisesRegex(ValueError, "metadata changed|symlink|identity"):
                    caddy_proof._verify_git_repository(repository)
            self.assertTrue(swapped[0])

    def test_git_rejects_installation_of_absent_metadata_entry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = self._init_repository(Path(directory) / "repo")
            target = repository / ".git" / "config.worktree"
            self.assertFalse(target.exists())
            real_runner = caddy_proof._run_bounded_git
            installed = [False]

            def install_before_command(command, environment):
                if not installed[0]:
                    target.write_text('[remote "origin"]\n\tpromisor = true\n', encoding="utf-8")
                    installed[0] = True
                return real_runner(command, environment)

            with mock.patch.object(caddy_proof, "_run_bounded_git", side_effect=install_before_command):
                with self.assertRaisesRegex(ValueError, "metadata changed|appeared|promisor|lazy|partial"):
                    caddy_proof._verify_git_repository(repository)
            self.assertTrue(installed[0])

    def test_git_rejects_live_forked_descendant_after_parent_success(self) -> None:
        script = (
            "import os,time; "
            "child=os.fork(); os.close(1); os.close(2); "
            "(time.sleep(30) if child == 0 else os._exit(0))"
        )
        with mock.patch.object(caddy_proof, "GIT_COMMAND_TIMEOUT_SECONDS", 1.0):
            with self.assertRaisesRegex(ValueError, "descendants|process group"):
                caddy_proof._run_bounded_git(
                    [sys.executable, "-c", script],
                    caddy_proof._strict_git_environment(),
                )

    def test_git_metadata_link_scan_bounds_live_fds_for_wide_object_fanout(self) -> None:
        """The topology scan must close sibling directories before the next open."""

        with tempfile.TemporaryDirectory() as directory:
            repository = self._init_repository(Path(directory) / "repo")
            objects = repository / ".git" / "objects"
            sibling_directories = [objects / f"{index:02x}" for index in range(256)]
            for sibling in sibling_directories:
                sibling.mkdir()

            original_open = caddy_proof.os.open
            original_close = caddy_proof.os.close
            live_descriptors: set[int] = set()
            peak = 0

            def tracked_open(*args: object, **kwargs: object) -> int:
                nonlocal peak
                descriptor = original_open(*args, **kwargs)  # type: ignore[arg-type]
                live_descriptors.add(descriptor)
                peak = max(peak, len(live_descriptors))
                return descriptor

            def tracked_close(descriptor: int) -> None:
                live_descriptors.discard(descriptor)
                original_close(descriptor)

            with mock.patch.object(caddy_proof.os, "open", side_effect=tracked_open):
                with mock.patch.object(caddy_proof.os, "close", side_effect=tracked_close):
                    caddy_proof._reject_git_metadata_links((repository / ".git").resolve())

            self.assertFalse(live_descriptors)
            self.assertGreaterEqual(peak, 2)
            # The rejected implementation retained one descriptor per sibling;
            # this bound stays independent of the 256-way fanout and fails that
            # implementation while allowing the root/path traversal descriptors.
            self.assertLessEqual(peak, 64)

    def test_git_metadata_deadline_covers_slow_scan_before_spawn(self) -> None:
        """A real slow scandir must time out before Git can spawn."""

        with tempfile.TemporaryDirectory() as directory:
            repository = self._init_repository(Path(directory) / "repo")
            clock = [0.0]
            scan_count = [0]
            close_calls: list[int] = []
            real_scandir = caddy_proof.os.scandir
            real_close = caddy_proof._close_git_metadata_pins

            class SlowScan:
                def __init__(self, iterator: object) -> None:
                    self.iterator = iterator

                def __enter__(self) -> "SlowScan":
                    scan_count[0] += 1
                    self.iterator.__enter__()  # type: ignore[attr-defined]
                    return self

                def __exit__(self, *args: object) -> object:
                    # Expire only after the real iterator has been consumed;
                    # the post-with deadline check must classify the timeout.
                    clock[0] = 2.0
                    return self.iterator.__exit__(*args)  # type: ignore[attr-defined]

                def __iter__(self) -> "SlowScan":
                    return self

                def __next__(self) -> object:
                    return next(self.iterator)  # type: ignore[arg-type]

            def slow_scandir(*args: object, **kwargs: object) -> SlowScan:
                return SlowScan(real_scandir(*args, **kwargs))  # type: ignore[arg-type]

            def fake_monotonic() -> float:
                return clock[0]

            def track_close(pins: tuple[object, ...]) -> None:
                close_calls.append(len(pins))
                real_close(pins)  # type: ignore[arg-type]

            with (
                mock.patch.object(caddy_proof, "GIT_COMMAND_TIMEOUT_SECONDS", 1.0),
                mock.patch.object(caddy_proof.time, "monotonic", side_effect=fake_monotonic),
                mock.patch.object(caddy_proof.os, "scandir", side_effect=slow_scandir),
                mock.patch.object(caddy_proof, "_close_git_metadata_pins", side_effect=track_close),
                mock.patch.object(
                    caddy_proof,
                    "_fork_exec_git",
                    side_effect=AssertionError("Git spawn reached"),
                ) as spawn,
                mock.patch.object(
                    caddy_proof.subprocess,
                    "Popen",
                    side_effect=AssertionError("Popen reached"),
                ) as popen,
            ):
                with self.assertRaisesRegex(ValueError, "timed out|deadline"):
                    caddy_proof._verify_git_repository(repository)

            self.assertGreater(scan_count[0], 0)
            spawn.assert_not_called()
            popen.assert_not_called()
            self.assertTrue(close_calls)
            self.assertGreater(close_calls[0], 0)

    def test_nested_git_metadata_links_are_rejected(self) -> None:
        for relative in (Path("objects"), Path("refs"), Path("objects") / "pack"):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as directory:
                repository = self._init_repository(Path(directory) / "repo")
                target = repository / ".git" / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.mkdir(exist_ok=True)
                outside = Path(directory) / "moved-metadata"
                target.rename(outside)
                target.symlink_to(outside, target_is_directory=True)
                with self.assertRaisesRegex(ValueError, "symlink|metadata|link"):
                    caddy_proof._verify_git_repository(repository)

    def test_descriptor_bound_linked_worktree_root_and_relative_metadata_survive_root_swap(self) -> None:
        mutation = (
            "from pathlib import Path; import sys; "
            "root,moved,replacement,marker=map(Path,sys.argv[1:]); "
            "root.rename(moved); replacement.rename(root); marker.write_text('ready')"
        )
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = self._init_repository(parent / "repo")
            first_sha = self._commit_fixture(root, "first.txt", "first\n")
            second_sha = self._commit_fixture(root, "second.txt", "second\n")
            subprocess.run(
                ["git", "-C", str(root), "config", "extensions.worktreeConfig", "true"],
                check=True,
                capture_output=True,
            )
            linked = parent / "linked"
            subprocess.run(
                ["git", "-C", str(root), "worktree", "add", "--detach", "--quiet", str(linked), "HEAD"],
                check=True,
                capture_output=True,
            )
            linked_git_pointer = linked / ".git"
            metadata_root = Path(linked_git_pointer.read_text(encoding="ascii").split(": ", 1)[1].strip())
            linked_git_pointer.write_text(
                f"gitdir: {os.path.relpath(metadata_root, linked.resolve())}\n",
                encoding="ascii",
            )
            (metadata_root / "commondir").write_text("../..\n", encoding="ascii")
            (metadata_root / "config.worktree").write_text("[core]\n\tbare = false\n", encoding="ascii")
            subprocess.run(
                ["git", "-C", str(root), "repack", "-ad"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "-C", str(root), "pack-refs", "--all", "--prune"],
                check=True,
                capture_output=True,
            )
            replacement = parent / "replacement-linked"
            subprocess.run(
                ["git", "-C", str(root), "worktree", "add", "--detach", "--quiet", str(replacement), first_sha],
                check=True,
                capture_output=True,
            )
            moved = parent / "moved-linked"
            observed = self._run_git_with_real_subprocess_mutation(
                linked,
                mutation,
                (linked, moved, replacement),
                "rev-parse",
                "HEAD",
            )
            self.assertEqual(observed[0][1], f"{second_sha}\n".encode("ascii"))
            self.assertNotEqual(observed[0][1], f"{first_sha}\n".encode("ascii"))

    def test_linked_worktree_metadata_topology_remains_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self._init_repository(Path(directory) / "repo")
            (root / "fixture.txt").write_text("fixture\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "fixture.txt"], check=True, capture_output=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "-c",
                    "user.name=fixture",
                    "-c",
                    "user.email=fixture@example.test",
                    "commit",
                    "--quiet",
                    "-m",
                    "fixture",
                ],
                check=True,
                capture_output=True,
            )
            linked = Path(directory) / "linked"
            subprocess.run(
                ["git", "-C", str(root), "worktree", "add", "--detach", "--quiet", str(linked), "HEAD"],
                check=True,
                capture_output=True,
            )
            caddy_proof._verify_git_repository(linked)

    def test_closed_git_stream_timeout_is_a_bounded_proof_error(self) -> None:
        with mock.patch.object(caddy_proof, "GIT_COMMAND_TIMEOUT_SECONDS", 0.01):
            with self.assertRaisesRegex(ValueError, "Git provenance command timed out"):
                caddy_proof._run_bounded_git(
                    [
                        sys.executable,
                        "-c",
                        "import os,time; os.close(1); os.close(2); time.sleep(30)",
                    ],
                    caddy_proof._strict_git_environment(),
                )

    def test_clean_repository_remains_accepted_by_metadata_checks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = self._init_repository(Path(directory) / "repo")
            caddy_proof._verify_git_repository(repository)

    def test_packed_replacement_refs_are_rejected_without_loose_refs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = self._init_repository(Path(directory) / "repo")
            git_dir = repository / ".git"
            packed_refs = git_dir / "packed-refs"
            packed_refs.write_text(
                f"{'0' * 40} refs/replace/{'1' * 40}\n",
                encoding="ascii",
            )
            self.assertFalse((git_dir / "refs" / "replace").exists())
            with self.assertRaisesRegex(ValueError, "replacement refs|packed"):
                caddy_proof._validate_git_metadata(repository)

    def test_promisor_pack_sidecar_is_rejected_without_promisor_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = self._init_repository(Path(directory) / "repo")
            pack_directory = repository / ".git" / "objects" / "pack"
            pack_directory.mkdir(parents=True, exist_ok=True)
            (pack_directory / "pack-deadbeef.promisor").write_bytes(b"")
            with self.assertRaisesRegex(ValueError, "promisor|sidecar|pack"):
                caddy_proof._verify_git_repository(repository)

    def test_non_promisor_pack_entry_remains_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = self._init_repository(Path(directory) / "repo")
            pack_directory = repository / ".git" / "objects" / "pack"
            pack_directory.mkdir(parents=True, exist_ok=True)
            (pack_directory / "pack-deadbeef.pack").write_bytes(b"")
            caddy_proof._verify_git_repository(repository)


class CaddyBlackBoxToolAvailabilityTests(unittest.TestCase):
    """Do not turn missing black-box binaries into a green skipped suite."""

    def test_caddy_black_box_tools_are_available_without_skip(self) -> None:
        missing = [tool for tool in ("caddy", "openssl") if shutil.which(tool) is None]
        self.assertEqual(missing, [], f"Caddy black-box tools are unavailable: {missing}")
        self.assertFalse(getattr(CaddyBlackBoxTests, "__unittest_skip__", False))


def _validated_tool_path(name: str) -> str:
    """Resolve a required black-box tool once and reject unsafe binaries."""

    located = shutil.which(name)
    if located is None:
        raise AssertionError(f"required black-box tool is unavailable: {name}")
    path = Path(located).resolve(strict=True)
    metadata = os.stat(path)
    if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111:
        raise AssertionError(f"required black-box tool is not executable: {name}")
    if metadata.st_uid not in {0, os.geteuid()} or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise AssertionError(f"required black-box tool is unsafe: {name}")
    return str(path)


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _RecordingMockUpstream(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, server_address, request_handler):
        super().__init__(server_address, request_handler)
        self.records: list[dict[str, object]] = []
        self.record_lock = threading.Lock()


class _MockUpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _handle_request(self) -> None:
        parsed = urlsplit(self.path)
        content_length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(content_length)
        record = {
            "method": self.command,
            "path": parsed.path,
            "query": parsed.query,
            "headers": {key.lower(): value for key, value in self.headers.items()},
            "body": body,
        }
        with self.server.record_lock:  # type: ignore[attr-defined]
            self.server.records.append(record)  # type: ignore[attr-defined]

        if self.headers.get("Upgrade", "").lower() == "websocket":
            self.send_response(101, "Switching Protocols")
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.end_headers()
            return

        payload = f"upstream:{parsed.path}".encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = _handle_request
    do_HEAD = _handle_request
    do_POST = _handle_request
    do_PATCH = _handle_request

    def log_message(self, _format: str, *_args: object) -> None:
        return


def _https_request(
    port: int,
    host: str,
    target: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, dict[str, str], bytes]:
    context = ssl._create_unverified_context()
    connection = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=3)
    request_headers = {"Host": host, "Connection": "close"}
    if headers:
        request_headers.update(headers)
    try:
        connection.request(method, target, body=body, headers=request_headers)
        response = connection.getresponse()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        response_body = b"" if response.status == 101 else response.read()
        return response.status, response_headers, response_body
    finally:
        connection.close()


class CaddyBlackBoxTests(unittest.TestCase):
    """Exercise the rendered boundary against Caddy and a recording upstream."""

    host = "caddy-156.test"

    @classmethod
    def setUpClass(cls) -> None:
        # Availability is a hard prerequisite. A missing binary must fail this
        # proof lane, not turn it green through unittest's skip machinery.
        cls.caddy_executable = _validated_tool_path("caddy")
        cls.openssl_executable = _validated_tool_path("openssl")
        cls.tempdir = tempfile.TemporaryDirectory(prefix="caddy-proof-black-box-")
        root = Path(cls.tempdir.name)
        cls.site_root = root / "site"
        cls.site_root.mkdir()
        (cls.site_root / "_app").mkdir()
        (cls.site_root / "index.html").write_text("INDEX-SHELL", encoding="utf-8")
        (cls.site_root / "200.html").write_text("CLIENT-SHELL", encoding="utf-8")
        (cls.site_root / "_app" / "app.js").write_text("static-app", encoding="utf-8")
        (cls.site_root / "service-worker.js").write_text("addEventListener", encoding="utf-8")
        (cls.site_root / "manifest.webmanifest").write_text("{}", encoding="utf-8")
        (cls.site_root / "icon.svg").write_text("<svg/>", encoding="utf-8")

        cls.upstream = _RecordingMockUpstream(("127.0.0.1", 0), _MockUpstreamHandler)
        cls.upstream_thread = threading.Thread(target=cls.upstream.serve_forever, daemon=True)
        cls.upstream_thread.start()
        cls.upstream_port = int(cls.upstream.server_address[1])

        cls.caddy_port = _free_tcp_port()
        cls.cert_path = root / "tls.crt"
        cls.key_path = root / "tls.key"
        cls.storage_root = root / "storage"
        cls.storage_root.mkdir()
        subprocess.run(
            [
                cls.openssl_executable,
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(cls.key_path),
                "-out",
                str(cls.cert_path),
                "-days",
                "1",
                "-subj",
                f"/CN={cls.host}",
                "-addext",
                f"subjectAltName=DNS:{cls.host}",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        cls.caddyfile_path = root / "Caddyfile"
        cls.caddyfile_path.write_text(
            caddy_proof.render_caddyfile(
                host=cls.host,
                https_port=cls.caddy_port,
                hermes_port=cls.upstream_port,
                site_root=str(cls.site_root),
                cert_path=str(cls.cert_path),
                key_path=str(cls.key_path),
                storage_root=str(cls.storage_root),
            ),
            encoding="utf-8",
        )
        format_result = subprocess.run(
            [cls.caddy_executable, "fmt", "--overwrite", str(cls.caddyfile_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if format_result.returncode != 0:
            raise RuntimeError("Caddy formatter rejected the rendered proof file")
        cls.caddyfile = cls.caddyfile_path.read_text(encoding="utf-8")
        validate_result = subprocess.run(
            [cls.caddy_executable, "validate", "--config", str(cls.caddyfile_path), "--adapter", "caddyfile"],
            capture_output=True,
            text=True,
            check=False,
        )
        if validate_result.returncode != 0:
            raise RuntimeError("Caddy validation rejected the formatted proof file")
        cls.caddy_process = subprocess.Popen(
            [cls.caddy_executable, "run", "--config", str(cls.caddyfile_path), "--adapter", "caddyfile"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(50):
            if cls.caddy_process.poll() is not None:
                raise RuntimeError("Caddy exited before the black-box listener became ready")
            try:
                status, _headers, _body = _https_request(cls.caddy_port, cls.host, "/")
            except (OSError, http.client.HTTPException):
                time.sleep(0.1)
                continue
            if status == 200:
                return
            time.sleep(0.1)
        raise RuntimeError("Caddy black-box listener did not become ready")

    @classmethod
    def tearDownClass(cls) -> None:
        process = getattr(cls, "caddy_process", None)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        upstream = getattr(cls, "upstream", None)
        if upstream is not None:
            upstream.shutdown()
            upstream.server_close()
        thread = getattr(cls, "upstream_thread", None)
        if thread is not None:
            thread.join(timeout=3)
        tempdir = getattr(cls, "tempdir", None)
        if tempdir is not None:
            tempdir.cleanup()

    def _request(self, target: str, **kwargs: object) -> tuple[int, dict[str, str], bytes]:
        return _https_request(self.caddy_port, self.host, target, **kwargs)  # type: ignore[arg-type]

    def _record_count(self) -> int:
        with self.upstream.record_lock:
            return len(self.upstream.records)

    def _record_after(self, previous_count: int) -> dict[str, object]:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            with self.upstream.record_lock:
                if len(self.upstream.records) > previous_count:
                    return self.upstream.records[previous_count]
            time.sleep(0.01)
        self.fail("expected the allowed request to reach the mock upstream")
        raise AssertionError("unreachable")

    def test_formatted_renderer_output_passes_caddy_validate(self) -> None:
        result = subprocess.run(
            [self.caddy_executable, "validate", "--config", str(self.caddyfile_path), "--adapter", "caddyfile"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_deep_link_fixture_vectors_match_edge_results(self) -> None:
        fixture_path = ROOT / caddy_proof.PARITY_FIXTURE_PATHS["deep_link_cases"]
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        before = self._record_count()
        probed = 0
        for case in fixture["cases"]:
            expected = case["expected"]
            parsed = urlsplit(case["link"])
            reasons = set(expected["reasons"])
            if (
                expected.get("kind") != "web"
                or parsed.netloc != "synthetic.hermternal.test"
                or parsed.username is not None
                or parsed.password is not None
                or "fragment" in reasons
                or reasons.intersection({"authority", "origin", "scheme"})
                or any(ord(character) < 0x20 or ord(character) > 0x7e for character in case["link"])
            ):
                continue
            target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
            status, _headers, _body = self._request(target)
            expected_status = 200 if expected["valid"] else 404
            with self.subTest(case=case["id"], target=target):
                self.assertEqual(status, expected_status)
            probed += 1
        self.assertGreaterEqual(probed, 15)
        self.assertEqual(self._record_count(), before)

    def test_static_and_deep_link_boundary_is_query_exact(self) -> None:
        cases = (
            ("/", 200, b"INDEX-SHELL"),
            ("/?", 404, b"not found"),
            ("/?scenario=success", 200, b"INDEX-SHELL"),
            ("/?scenario=empty", 200, b"INDEX-SHELL"),
            ("/?scenario=failure", 200, b"INDEX-SHELL"),
            ("/?cache=synthetic", 404, b"not found"),
            ("/?scenario=success&cache=synthetic", 404, b"not found"),
            ("/manifest.webmanifest", 200, b"{}"),
            ("/manifest.webmanifest?", 404, b"not found"),
            ("/manifest.webmanifest?cache=synthetic", 404, b"not found"),
            ("/service-worker.js?cache=synthetic", 404, b"not found"),
            ("/_app/app.js?cache=synthetic", 404, b"not found"),
            ("/v1/c/abcdefghijklmnop", 200, b"CLIENT-SHELL"),
            ("/v1/c/abcdefghijkl..mnop", 200, b"CLIENT-SHELL"),
            ("/v1/c/abcdefghijklmnop/m/qrstuvwxyzabcdef", 200, b"CLIENT-SHELL"),
            ("/v1/c/abcdefghijklmnop?", 404, b"not found"),
            ("/v1/c/abcdefghijklmnop?cache=synthetic", 404, b"not found"),
            ("/v1/c/short", 404, b"not found"),
            ("/v1/c/abcdefghijklmnop/", 404, b"not found"),
            ("/v1/c/abcdefghijklmnop/m/qrstuvwxyzabcdef/extra", 404, b"not found"),
            ("/apiary/v1/c/abcdefghijklmnop", 404, b"not found"),
        )
        before = self._record_count()
        for target, expected_status, expected_body in cases:
            with self.subTest(target=target):
                status, _headers, body = self._request(target)
                self.assertEqual(status, expected_status)
                self.assertEqual(body, expected_body)
        self.assertEqual(self._record_count(), before)

    def test_allowed_rest_request_rebuilds_trusted_headers_and_body(self) -> None:
        spoofed = {
            "Forwarded": "for=spoof;host=evil;proto=http",
            "X-Forwarded-For": "spoof",
            "X-Forwarded-Host": "evil",
            "X-Forwarded-Proto": "http",
            "X-Forwarded-Prefix": "/evil",
            "X-Forwarded-Debug": "spoof",
            "X-Real-IP": "spoof",
        }
        before = self._record_count()
        status, _headers, body = self._request(
            "/hermes/api/auth/ws-ticket",
            method="POST",
            headers=spoofed,
            body=b"{}",
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, b"upstream:/api/auth/ws-ticket")
        record = self._record_after(before)
        self.assertEqual(record["method"], "POST")
        self.assertEqual(record["path"], "/api/auth/ws-ticket")
        self.assertEqual(record["query"], "")
        self.assertEqual(record["body"], b"{}")
        upstream_headers = record["headers"]
        self.assertEqual(upstream_headers["host"], f"127.0.0.1:{self.upstream_port}")
        self.assertEqual(upstream_headers["origin"], f"http://127.0.0.1:{self.upstream_port}")
        self.assertEqual(upstream_headers["x-forwarded-host"], self.host)
        self.assertEqual(upstream_headers["x-forwarded-proto"], "https")
        self.assertEqual(upstream_headers["x-forwarded-prefix"], "/hermes")
        self.assertEqual(upstream_headers["x-real-ip"], "127.0.0.1")
        self.assertIn(f"host={self.host}", upstream_headers["forwarded"])
        self.assertIn("proto=https", upstream_headers["forwarded"])
        for value in ("spoof", "evil", "/evil"):
            self.assertNotIn(value, " ".join(upstream_headers.values()))
        self.assertNotIn("x-forwarded-debug", upstream_headers)

        denied_before = self._record_count()
        status, _headers, body = self._request("/hermes/api/auth/ws-ticket?cache=synthetic", method="POST", body=b"{}")
        self.assertEqual((status, body), (404, b"not found"))
        self.assertEqual(self._record_count(), denied_before)

    def test_oauth_callback_queries_reach_upstream_only_for_reviewed_forms(self) -> None:
        accepted = (
            "/auth/callback?code=fixture-code-success&state=fixture-state-success",
            "/hermes/auth/callback?state=fixture-state-success&code=fixture-code-success",
            "/auth/callback?error=access_denied&error_description=fixture-user-cancelled&state=fixture-state-cancelled",
        )
        for target in accepted:
            with self.subTest(target=target):
                before = self._record_count()
                status, _headers, body = self._request(target)
                self.assertEqual((status, body), (200, b"upstream:/auth/callback"))
                record = self._record_after(before)
                self.assertEqual(record["path"], "/auth/callback")
                self.assertEqual(record["query"], target.split("?", 1)[1])

        denied_queries = (
            "/auth/callback?",
            "/auth/callback?code=fixture-code-success",
            "/auth/callback?state=fixture-state-success",
            "/auth/callback?code=fixture-code-success&state=fixture-state-success&extra=value",
            "/auth/callback?code=fixture-code-success&code=other-code&state=fixture-state-success",
            "/auth/callback?error=access_denied&state=fixture-state-cancelled",
            "/auth/callback?error=access_denied&error_description=&state=fixture-state-cancelled",
            "/auth/callback?error=access_denied&error_description=fixture-user-cancelled&state=",
            "/auth/callback?error=provider_failure&error_description=fixture-user-cancelled&state=fixture-state-cancelled",
            "/auth/callback?code=&state=fixture-state-malformed",
            "/auth/callback?state=&code=fixture-code-missing-state",
            "/auth/callback?code=fixture%2Dcode&state=fixture-state-success",
            "/hermes/auth/callback?code=fixture-code-success&state=fixture-code-success&ticket=extra",
        )
        for target in denied_queries:
            with self.subTest(target=target):
                before = self._record_count()
                status, _headers, body = self._request(target)
                self.assertEqual((status, body), (404, b"not found"))
                self.assertEqual(self._record_count(), before)

    def test_every_rest_query_mutation_is_edge_denied(self) -> None:
        targets: list[tuple[str, str]] = []
        for method, path in caddy_proof.EXACT_REST_ROUTES:
            if path == "/auth/callback":
                continue
            for prefix in ("", "/hermes"):
                targets.append((method, f"{prefix}{path}?"))
                targets.append((method, f"{prefix}{path}?cache=synthetic"))
                targets.append((method, f"{prefix}{path}?ticket=synthetic"))
        for method, path in caddy_proof.SESSION_ROUTES:
            suffix = path.replace("{session_id}", "abcdefghijklmnop")
            for prefix in ("", "/hermes"):
                targets.append((method, f"{prefix}{suffix}?"))
                targets.append((method, f"{prefix}{suffix}?cache=synthetic"))
                targets.append((method, f"{prefix}{suffix}?ticket=synthetic"))

        for method, target in targets:
            with self.subTest(method=method, target=target):
                before = self._record_count()
                body = b"{}" if method in {"POST", "PATCH"} else None
                status, _headers, response_body = self._request(target, method=method, body=body)
                self.assertEqual((status, response_body), (404, b"not found"))
                self.assertEqual(self._record_count(), before)

    def test_chat_and_pty_upgrade_queries_are_distinct_and_edge_denied(self) -> None:
        upgrade_headers = {
            "Origin": f"https://{self.host}:{self.caddy_port}",
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        }
        before = self._record_count()
        status, _headers, _body = self._request(
            "/api/ws?ticket=fixtureTicket",
            headers=upgrade_headers,
        )
        self.assertEqual(status, 101)
        chat_record = self._record_after(before)
        self.assertEqual((chat_record["path"], chat_record["query"]), ("/api/ws", "ticket=fixtureTicket"))
        self.assertEqual(chat_record["headers"]["origin"], f"http://127.0.0.1:{self.upstream_port}")

        before = self._record_count()
        status, _headers, _body = self._request(
            "/hermes/api/pty?attach=fixtureAttach&ticket=fixtureTicket&resume=fixtureResume",
            headers=upgrade_headers,
        )
        self.assertEqual(status, 101)
        pty_record = self._record_after(before)
        self.assertEqual(pty_record["path"], "/api/pty")
        self.assertEqual(pty_record["query"], "attach=fixtureAttach&ticket=fixtureTicket&resume=fixtureResume")
        self.assertEqual(pty_record["headers"]["x-forwarded-prefix"], "/hermes")

        denied_queries = (
            "/api/ws?",
            "/api/ws?ticket=fixtureTicket&resume=fixtureResume",
            "/api/ws?ticket=fixtureTicket&ticket=otherTicket",
            "/api/ws?ticket=",
            "/api/ws?ticket=" + ("A" * 513),
            "/api/pty?",
            "/api/pty?ticket=fixtureTicket",
            "/api/pty?ticket=fixtureTicket&resume=fixtureResume&fresh=1",
            "/api/pty?ticket=fixtureTicket&resume=fixtureResume&ticket=otherTicket",
            "/api/pty?ticket=&resume=fixtureResume",
            "/api/pty?ticket=fixtureTicket&resume=fixtureResume&extra=value",
        )
        for target in denied_queries:
            with self.subTest(target=target):
                denied_before = self._record_count()
                status, _headers, body = self._request(target, headers=upgrade_headers)
                self.assertEqual((status, body), (404, b"not found"))
                self.assertEqual(self._record_count(), denied_before)

        denied_before = self._record_count()
        status, _headers, body = self._request(
            "/api/ws?ticket=fixtureTicket",
            headers={"Origin": f"https://{self.host}:{self.caddy_port}"},
        )
        self.assertEqual((status, body), (404, b"not found"))
        self.assertEqual(self._record_count(), denied_before)

        status, _headers, body = _https_request(
            self.caddy_port,
            "evil.example",
            "/api/ws?ticket=fixtureTicket",
            headers=upgrade_headers,
        )
        self.assertEqual((status, body), (421, b"host denied"))
        self.assertEqual(self._record_count(), denied_before)

        status, _headers, body = self._request(
            "/api/ws?ticket=fixtureTicket",
            headers={**upgrade_headers, "Origin": "https://evil.example"},
        )
        self.assertEqual((status, body), (403, b"origin denied"))
        self.assertEqual(self._record_count(), denied_before)


if __name__ == "__main__":
    unittest.main()
