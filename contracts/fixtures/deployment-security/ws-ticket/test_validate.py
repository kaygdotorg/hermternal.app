"""Regression tests for the synthetic WebSocket-ticket boundary validator."""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import validate


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[3]


class WsTicketValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = validate.load_json(validate.FIXTURE_PATH)
        self.baseline = validate.load_json(validate.BASELINE_PATH)

    def test_fixture_and_baseline_validate(self) -> None:
        self.assertEqual(validate.validate_fixture(self.fixture), {"case_count": 24, "state_count": 5})
        self.assertEqual(validate.validate_baseline(self.baseline), {"normal_samples": 30, "optimized_samples": 30})

    def test_ticket_boundary_is_upgrade_only(self) -> None:
        policy = self.fixture["ticket_policy"]
        self.assertEqual(policy["acquisition"]["path"], "/api/auth/ws-ticket")
        self.assertEqual(policy["upgrade"]["path"], "/api/ws")
        self.assertEqual(policy["upgrade"]["query_key"], "ticket")
        self.assertEqual(policy["upgrade"]["rest_ticket_use"], "forbidden")
        self.assertTrue(policy["single_use"])
        self.assertEqual(policy["ttl_seconds"], 30)

    def test_required_denials_and_error_layers_are_present(self) -> None:
        by_id = {item["id"]: item for item in self.fixture["cases"]}
        for case_id in (
            "rest-ticket-query-rejected",
            "rest-ticket-header-rejected",
            "missing-ticket-rejected",
            "malformed-ticket-rejected",
            "expired-ticket-rejected",
            "reused-ticket-rejected",
        ):
            self.assertFalse(by_id[case_id]["expected"]["raw_value_retained"])
        self.assertEqual(by_id["edge-origin-error-distinct"]["expected"]["error_layer"], "edge")
        self.assertEqual(by_id["edge-not-found-error-distinct"]["expected"]["rest_status"], 404)
        self.assertEqual(by_id["upstream-auth-error-distinct"]["expected"]["error_layer"], "upstream")
        self.assertTrue(by_id["upstream-auth-error-distinct"]["expected"]["upstream_called"])
        self.assertEqual(by_id["upstream-handler-error-distinct"]["expected"]["rest_status"], 400)

    def test_expiry_boundary_is_29_fresh_and_30_expired(self) -> None:
        by_id = {item["id"]: item for item in self.fixture["cases"]}
        self.assertEqual(by_id["expiry-boundary-fresh"]["request"]["ticket_age_seconds"], 29)
        self.assertEqual(by_id["expiry-boundary-fresh"]["expected"]["decision"], "allow_upgrade")
        self.assertEqual(by_id["expiry-boundary-expired"]["request"]["ticket_age_seconds"], 30)
        self.assertEqual(by_id["expiry-boundary-expired"]["expected"]["decision"], "deny_upgrade")

    def test_redaction_surfaces_never_retain_raw_value(self) -> None:
        for case in self.fixture["cases"]:
            if case["surface"] in {"history", "logs", "dom"}:
                self.assertFalse(case["expected"]["raw_value_retained"])
                self.assertFalse(case["expected"]["bounded_fragment_retained"])
        self.assertEqual(self.fixture["redaction"]["max_controlled_error_length"], 240)
        self.assertTrue(self.fixture["redaction"]["no_raw_input_echo"])
        self.assertTrue(self.fixture["redaction"]["no_traceback"])

    def test_bounded_fragment_source_and_cases_are_explicit(self) -> None:
        evidence = next(item for item in self.fixture["source_evidence"] if item["id"] == "ticket-fragment-source-anchor")
        self.assertEqual(evidence["ticket_source_file"], "hermes_cli/dashboard_auth/ws_tickets.py")
        self.assertEqual(evidence["ticket_lines"], [90, 95])
        self.assertIn("truncated = (ticket[:8] + \"…\") if ticket else \"<empty>\"", evidence["ticket_markers"])
        self.assertEqual(evidence["forwarding_source_file"], "hermes_cli/web_server.py")
        self.assertEqual(evidence["forwarding_lines"], [14708, 14716])
        self.assertEqual(evidence["forwarding_source_sha256"], validate.PINNED_FORWARDING_SOURCE_SHA256)
        self.assertEqual(evidence["forwarding_git_blob_sha"], validate.PINNED_FORWARDING_GIT_BLOB_SHA)
        self.assertEqual(evidence["independent_forwarding_markers"], [
            "except TicketInvalid as exc:",
            "reason=str(exc),",
            "path=ws.url.path,",
        ])
        self.assertEqual(evidence["forwarding_source_excerpt"], list(validate.PINNED_FORWARDING_EXCERPT))
        self.assertEqual(evidence["forwarding_source_excerpt_sha256"], validate.PINNED_FORWARDING_EXCERPT_SHA256)
        by_id = {item["id"]: item for item in self.fixture["cases"]}
        for case_id in ("history-bounded-fragment-redaction", "log-bounded-fragment-redaction", "dom-bounded-fragment-redaction"):
            self.assertEqual(by_id[case_id]["request"]["ticket_state"], "bounded_fragment_candidate")
            self.assertFalse(by_id[case_id]["expected"]["bounded_fragment_retained"])
            self.assertFalse(by_id[case_id]["expected"]["raw_value_retained"])
            self.assertIn("source-bounded ticket fragment", by_id[case_id]["notes"])

    def test_source_audit_references_are_checked(self) -> None:
        ids = [item["id"] for item in self.fixture["source_evidence"]]
        self.assertEqual(ids, list(validate.SOURCE_EVIDENCE_IDS))
        self.assertEqual(self.fixture["route_manifest_sha256"], validate.MANIFEST_SHA256)

    def test_semantic_case_mutation_fails_without_digest_check(self) -> None:
        mutated = copy.deepcopy(self.fixture)
        for case in mutated["cases"]:
            if case["id"] == "rest-ticket-query-rejected":
                case["expected"]["decision"] = "allow_rest"
                break
        with self.assertRaises(validate.ContractError):
            validate._validate_fixture_shape(mutated)

    def test_exact_integer_count_rejects_float(self) -> None:
        mutated = copy.deepcopy(self.fixture)
        mutated["counts"]["cases"] = 21.0
        with self.assertRaises(validate.ContractError):
            validate._validate_fixture_shape(mutated)

    def test_duplicate_keys_and_nonfinite_numbers_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            duplicate = Path(directory) / "duplicate.json"
            duplicate.write_text('{"a": 1, "a": 2}', encoding="utf-8")
            with self.assertRaises(validate.ContractError):
                validate.load_json(duplicate)
            nonfinite = Path(directory) / "nonfinite.json"
            nonfinite.write_text('{"a": NaN}', encoding="utf-8")
            with self.assertRaises(validate.ContractError):
                validate.load_json(nonfinite)

    def test_oversized_integer_and_deep_json_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            oversized = Path(directory) / "oversized.json"
            oversized.write_text('{"a": 1' + ("0" * 110) + '}', encoding="utf-8")
            with self.assertRaises(validate.ContractError):
                validate.load_json(oversized)
            deep = Path(directory) / "deep.json"
            deep.write_text("[" * 60 + "0" + "]" * 60, encoding="utf-8")
            with self.assertRaises(validate.ContractError):
                validate.load_json(deep)

    def test_preparse_byte_token_container_node_integer_and_float_limits(self) -> None:
        def reject(directory: str, name: str, payload: bytes) -> None:
            candidate = Path(directory) / name
            candidate.write_bytes(payload)
            with self.assertRaises(validate.ContractError):
                validate.load_json(candidate)

        with tempfile.TemporaryDirectory() as directory:
            reject(directory, "bytes.json", b" " * (validate.MAX_JSON_BYTES + 1) + b"0")
            reject(directory, "array-items.json", b"[" + b",".join(b"0" for _ in range(validate.MAX_JSON_ARRAY_ITEMS + 1)) + b"]")
            object_items = b"{" + b",".join((f'\"k{index}\":0'.encode("ascii") for index in range(validate.MAX_JSON_OBJECT_KEYS + 1))) + b"}"
            reject(directory, "object-keys.json", object_items)
            def tree(depth: int):
                return 0 if depth == 0 else [tree(depth - 1), tree(depth - 1)]
            reject(directory, "nodes.json", json.dumps(tree(12)).encode("ascii"))
            reject(directory, "integer-digits.json", b"{\"a\":" + b"9" * (validate.MAX_JSON_INTEGER_DIGITS + 1) + b"}")
            reject(directory, "float-token.json", b"{\"a\":1e309}")

    def test_sensitive_key_and_jwt_like_value_fail_closed(self) -> None:
        with self.assertRaises(validate.ContractError):
            validate._scan_redaction({"raw_ticket_value": "not-retained"})
        with self.assertRaises(validate.ContractError):
            validate._scan_redaction({"marker": "abcdefghijk.lmnopqrstuv.wxyz0123456"})

    def test_retained_text_bypasses_are_rejected(self) -> None:
        bypasses = (
            "data:image/png;base64,SGVsbG8=",
            "data:text/plain,hello",
            "/etc/passwd",
            "prefix=/srv/secret",
            "file:///srv/secret",
            "SGVsbG8",
            "aGVsbG8",
            "YWJjZGVm",
            "aaaaaaaa",
            "00000000",
            "secret.txt",
        )
        for value in bypasses:
            with self.subTest(value=value):
                with self.assertRaises(validate.ContractError):
                    validate._scan_redaction({"notes": value})

    def test_embedded_base64_and_source_fragments_are_rejected_on_each_surface(self) -> None:
        embedded = (
            "prefix SGVsbG8=",
            "prefix SGVsbG8",
            "prefix SGVsbG8=foo",
            "prefix=SGVsbG8=foo",
            "(SGVsbG8=)",
            "payload abcdefgh",
            "payload 01234567",
            "prefix aaaaaaaa",
            "prefix 00000000",
            "prefix abcdefgh",
            "prefix 01234567",
        )
        fragments = (
            "unknown ticket: Abcdefgh…",
            "ticket fragment: Abcdefgh",
        )
        for surface in ("history", "logs", "dom"):
            for value in embedded + fragments:
                with self.subTest(surface=surface, value=value):
                    with self.assertRaises(validate.ContractError):
                        validate._scan_redaction({surface: value})

    def test_embedded_scanner_preserves_ordinary_retained_copy(self) -> None:
        for value in ("ordinary words remain readable", "prefix ordinary", "state: ready"):
            with self.subTest(value=value):
                validate._scan_redaction({"notes": value})

    def test_short_recognized_authorization_forms_are_rejected(self) -> None:
        values = (
            "Authorization: Basic test1234",
            "Authorization: Bearer x",
            "Bearer qwertyui",
            "Cookie: sid=qwertyui",
        )
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(validate.ContractError):
                    validate._scan_redaction({"notes": value})

    def test_embedded_base64_and_source_fragments_fail_closed_in_normal_and_optimized_cli(self) -> None:
        candidates = (
            "prefix SGVsbG8=",
            "prefix SGVsbG8",
            "prefix SGVsbG8=foo",
            "prefix=SGVsbG8=foo",
            "(SGVsbG8=)",
            "payload abcdefgh",
            "payload 01234567",
            "prefix aaaaaaaa",
            "prefix 00000000",
            "prefix abcdefgh",
            "prefix 01234567",
            "unknown ticket: Abcdefgh…",
            "ticket fragment: Abcdefgh",
            "Authorization: Basic test1234",
            "Authorization: Bearer x",
            "Bearer qwertyui",
            "Cookie: sid=qwertyui",
        )
        for surface in ("history", "logs", "dom"):
            for value in candidates:
                with self.subTest(surface=surface, value=value), tempfile.TemporaryDirectory() as directory:
                    mutated = copy.deepcopy(self.fixture)
                    target = next(case for case in mutated["cases"] if case["surface"] == surface)
                    target["notes"] = value
                    fixture_path = Path(directory) / "adversarial-fixture.json"
                    fixture_path.write_text(json.dumps(mutated, indent=2) + "\n", encoding="utf-8")
                    for optimized in (False, True):
                        command = [sys.executable] + (["-O"] if optimized else []) + [str(ROOT / "validate.py"), "--fixture", str(fixture_path)]
                        completed = subprocess.run(command, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
                        self.assertEqual(completed.returncode, 1)
                        self.assertNotIn(value, completed.stdout)
                        self.assertNotIn(str(fixture_path), completed.stdout)
                        self.assertEqual(json.loads(completed.stdout)["live_run"], False)

    def test_forwarding_reason_marker_is_load_bearing(self) -> None:
        mutated = copy.deepcopy(self.fixture)
        evidence = next(item for item in mutated["source_evidence"] if item["id"] == "ticket-fragment-source-anchor")
        evidence["independent_forwarding_markers"].remove("reason=str(exc),")
        with self.assertRaises(validate.ContractError):
            validate._validate_fixture_shape(mutated)

    def test_mutated_route_audit_cannot_authorize_source_evidence_in_both_modes(self) -> None:
        copied_files = (
            "contracts/fixtures/deployment-security/ws-ticket/README.md",
            "contracts/fixtures/deployment-security/ws-ticket/probe-baseline.json",
            "contracts/fixtures/deployment-security/ws-ticket/ticket-fixtures.json",
            "contracts/fixtures/deployment-security/ws-ticket/test_validate.py",
            "contracts/fixtures/deployment-security/ws-ticket/validate.py",
            "contracts/fixtures/route-allowlist/source_audit.json",
            "contracts/fixtures/source-audit/planning-reconciliation/planning_review.json",
            "contracts/fixtures/behavioral-probe/probe-fixtures.json",
            "contracts/hermes-dashboard/manifest.md",
        )
        with tempfile.TemporaryDirectory() as directory:
            isolated_root = Path(directory) / "repo"
            for relative in copied_files:
                source = REPO_ROOT / relative
                target = isolated_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
            route_audit = isolated_root / "contracts/fixtures/route-allowlist/source_audit.json"
            original = route_audit.read_text(encoding="utf-8")
            mutated = original.replace(
                "Gated upgrades accept a fresh ticket or server-internal credential; the legacy query token is only for non-gated local mode, and audit logging identifies credential type without recording the raw ticket.",
                "mutated source-audit claim",
                1,
            )
            self.assertNotEqual(mutated, original)
            route_audit.write_text(mutated, encoding="utf-8")
            validator = isolated_root / "contracts/fixtures/deployment-security/ws-ticket/validate.py"
            for optimized in (False, True):
                command = [sys.executable] + (["-O"] if optimized else []) + [str(validator)]
                completed = subprocess.run(command, cwd=isolated_root, capture_output=True, text=True, check=False)
                self.assertEqual(completed.returncode, 1)
                self.assertNotIn(str(isolated_root), completed.stdout)
                payload = json.loads(completed.stdout)
                self.assertFalse(payload["compatible"])
                self.assertFalse(payload["live_run"])

    def test_uniform_fabricated_baseline_fails(self) -> None:
        fabricated = copy.deepcopy(self.baseline)
        samples = [1.0] * 30
        fabricated["observations"]["normal"]["samples_ms"] = samples
        fabricated["observations"]["normal"]["summary"] = {"min": 1.0, "p50": 1.0, "p95": 1.0, "max": 1.0, "mean": 1.0}
        with self.assertRaises(validate.ContractError):
            validate.validate_baseline(fabricated)

    def test_nonuniform_fabricated_baseline_cannot_validate_after_recomputed_metadata(self) -> None:
        mutated = copy.deepcopy(self.baseline)
        for mode in ("normal", "optimized"):
            samples = [100.0 + index / 10 for index in range(30)]
            mutated["observations"][mode]["samples_ms"] = samples
            mutated["observations"][mode]["summary"] = validate._summary(samples)
        with self.assertRaises(validate.ContractError):
            validate.validate_baseline(mutated)
        with tempfile.TemporaryDirectory() as directory:
            baseline_path = Path(directory) / "fabricated-baseline.json"
            for _ in range(4):
                baseline_path.write_text(json.dumps(mutated, indent=2) + "\n", encoding="utf-8")
                manifest = copy.deepcopy(mutated["integrity"]["artifact_manifest"])
                baseline_record = next(item for item in manifest if item["path"] == "probe-baseline.json")
                baseline_record["size_bytes"] = baseline_path.stat().st_size
                mutated["integrity"]["artifact_manifest"] = manifest
                mutated["integrity"]["artifact_manifest_sha256"] = validate.canonical_sha256(manifest)
                mutated["integrity"]["baseline_file_size_bytes"] = baseline_path.stat().st_size
            baseline_path.write_text(json.dumps(mutated, indent=2) + "\n", encoding="utf-8")
            for optimized in (False, True):
                command = [sys.executable] + (["-O"] if optimized else []) + [str(ROOT / "validate.py"), "--baseline", str(baseline_path)]
                completed = subprocess.run(command, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
                self.assertEqual(completed.returncode, 1)
                self.assertNotIn(str(baseline_path), completed.stdout)
                self.assertEqual(json.loads(completed.stdout)["compatible"], False)

    def test_baseline_artifact_manifest_is_bound(self) -> None:
        mutated = copy.deepcopy(self.baseline)
        mutated["integrity"]["artifact_manifest"][0]["sha256"] = "0" * 64
        with self.assertRaises(validate.ContractError):
            validate.validate_baseline(mutated)

    def test_controlled_cli_unknown_flag_normal(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(ROOT / "validate.py"), "--raw-ticket=never-echo"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertNotIn("never-echo", completed.stdout)
        self.assertNotIn("Traceback", completed.stdout)
        payload = json.loads(completed.stdout)
        self.assertFalse(payload["compatible"])
        self.assertFalse(payload["live_run"])
        self.assertLessEqual(len(completed.stdout.strip()), 240)

    def test_controlled_cli_unknown_flag_optimized(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-O", str(ROOT / "validate.py"), "--raw-ticket=never-echo"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertNotIn("never-echo", completed.stdout)
        self.assertNotIn("Traceback", completed.stdout)
        self.assertEqual(json.loads(completed.stdout), json.loads(
            subprocess.run(
                [sys.executable, str(ROOT / "validate.py"), "--raw-ticket=never-echo"],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
            ).stdout
        ))

    def test_retained_text_bypasses_fail_closed_in_normal_and_optimized_cli(self) -> None:
        bypasses = (
            "data:image/png;base64,SGVsbG8=",
            "data:text/plain,hello",
            "/etc/passwd",
            "prefix=/srv/secret",
            "file:///srv/secret",
            "SGVsbG8",
            "aGVsbG8",
            "YWJjZGVm",
            "aaaaaaaa",
            "00000000",
            "secret.txt",
        )
        for value in bypasses:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                mutated = copy.deepcopy(self.fixture)
                mutated["cases"][0]["notes"] = value
                fixture_path = Path(directory) / "adversarial-fixture.json"
                fixture_path.write_text(json.dumps(mutated, indent=2) + "\n", encoding="utf-8")
                for optimized in (False, True):
                    command = [sys.executable] + (["-O"] if optimized else []) + [str(ROOT / "validate.py"), "--fixture", str(fixture_path)]
                    completed = subprocess.run(command, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
                    self.assertEqual(completed.returncode, 1)
                    self.assertNotIn(value, completed.stdout)
                    self.assertNotIn(str(fixture_path), completed.stdout)
                    self.assertEqual(json.loads(completed.stdout)["live_run"], False)

    def test_preparse_limits_fail_closed_in_normal_and_optimized_cli(self) -> None:
        payloads = {
            "bytes.json": b" " * (validate.MAX_JSON_BYTES + 1) + b"0",
            "array.json": b"[" + b",".join(b"0" for _ in range(validate.MAX_JSON_ARRAY_ITEMS + 1)) + b"]",
            "object.json": b"{" + b",".join((f'\"k{index}\":0'.encode("ascii") for index in range(validate.MAX_JSON_OBJECT_KEYS + 1))) + b"}",
            "integer.json": b"{\"a\":" + b"9" * (validate.MAX_JSON_INTEGER_DIGITS + 1) + b"}",
            "float.json": b"{\"a\":1e309}",
        }
        with tempfile.TemporaryDirectory() as directory:
            for name, payload in payloads.items():
                fixture_path = Path(directory) / name
                fixture_path.write_bytes(payload)
                for optimized in (False, True):
                    command = [sys.executable] + (["-O"] if optimized else []) + [str(ROOT / "validate.py"), "--fixture", str(fixture_path)]
                    completed = subprocess.run(command, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
                    self.assertEqual(completed.returncode, 1)
                    self.assertNotIn(str(fixture_path), completed.stdout)
                    self.assertNotIn("Traceback", completed.stdout)
                    self.assertLessEqual(len(completed.stdout.strip()), 240)

    def test_malformed_fixture_cli_is_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            malformed = Path(directory) / "bad.json"
            malformed.write_text('{"schema": NaN}', encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(ROOT / "validate.py"), "--fixture", str(malformed)],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 1)
        self.assertNotIn(str(malformed), completed.stdout)
        self.assertNotIn("Traceback", completed.stdout)
        self.assertLessEqual(len(completed.stdout.strip()), 240)


if __name__ == "__main__":
    unittest.main()
