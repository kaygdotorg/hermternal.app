#!/usr/bin/env python3
"""Regression tests for the disposable issue #156 Caddy proof fixture.

These tests protect the reviewed edge boundary without starting Caddy or
contacting Hermes. The live status matrix is retained separately as redacted
evidence; this file proves that the renderer cannot silently widen it.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import caddy_proof  # noqa: E402


EVIDENCE_PATH = ROOT / "tests/integration/hermes-caddy/caddy-proof-evidence.json"
EVIDENCE_ANCHOR_PATH = ROOT / "tests/integration/hermes-caddy/caddy-proof-evidence-sha256.txt"
EXPECTED_BUILD_SHA = "521ede32b904a42e22eebb279fd7d404074cd318"
EXPECTED_BUILD_DIGEST = "77f6d0e8bb4977c16eb1f1eaec32000f84f346ddec9f474ebd873d7b9a833d21"
EXPECTED_CADDYFILE_DIGEST = "b3585c4b91d7656d5bcb6adedda29af63d60ca488ec99ef162ec4f74e2611e82"


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
        with self.assertRaises(ValueError):
            caddy_proof._validate_host("caddy..test")
        with self.assertRaises(ValueError):
            caddy_proof._validate_port(443, "https_port")
        with self.assertRaises(ValueError):
            caddy_proof._validate_path("relative/site", "site_root")

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

    def test_websocket_boundary_requires_one_ticket_and_one_upgrade(self) -> None:
        rendered = self._render()
        self.assertEqual(rendered.count(caddy_proof.TICKET_QUERY_GUARD), 4)
        self.assertIn("header Upgrade websocket", rendered)
        self.assertIn("header Connection *Upgrade*", rendered)
        self.assertNotIn("lb_retries", rendered)
        self.assertNotIn("lb_try_duration", rendered)

    def test_upstream_authority_and_cookie_policy_are_fixed(self) -> None:
        rendered = self._render()
        self.assertEqual(rendered.count("header_up Host 127.0.0.1:19256"), 2)
        self.assertEqual(rendered.count("header_up Origin http://127.0.0.1:19256"), 2)
        self.assertEqual(rendered.count("header_up X-Forwarded-Proto https"), 2)
        self.assertEqual(rendered.count("header_up X-Forwarded-Host {http.request.host}"), 2)
        self.assertEqual(rendered.count('header_down Set-Cookie "(?i)(.*)" "$1; Secure"'), 2)
        self.assertIn("header_up -Origin", rendered)
        self.assertIn("header_up -X-Forwarded-Host", rendered)
        self.assertIn("header_up -X-Forwarded-Proto", rendered)
        self.assertIn("header_up -X-Forwarded-Prefix", rendered)

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


if __name__ == "__main__":
    unittest.main()
