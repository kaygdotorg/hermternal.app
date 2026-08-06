"""Regression tests for the offline pinned Hermes rootless-init fixture."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import validate


FIXTURE_DIR = Path(__file__).resolve().parent
FIXTURE_PATH = FIXTURE_DIR / "cases.json"


class RootlessInitValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = validate.load_fixture(FIXTURE_PATH)

    def assert_rejected(self, fixture: dict[str, object]) -> None:
        with self.assertRaises(validate.ValidationError):
            validate.validate_fixture(fixture)

    def test_checked_in_fixture_distinguishes_all_required_classes(self) -> None:
        summary = validate.validate_fixture(self.fixture)
        self.assertEqual(summary["case_count"], 6)
        self.assertEqual(
            summary["classifications"],
            {
                "cleanup_complete": 1,
                "harness_defect": 1,
                "pinned_boundary_incompatibility": 1,
                "pinned_rootless_incompatibility": 1,
                "unsafe_workaround_rejected": 2,
            },
        )
        self.assertFalse(summary["live_execution"])
        self.assertTrue(summary["cleanup_complete"])

    def test_real_cli_passes_in_normal_and_optimized_python(self) -> None:
        outputs: list[dict[str, object]] = []
        for optimized in (False, True):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.extend([str(validate.__file__)])
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, (optimized, result.stderr))
            self.assertNotIn("Traceback", result.stdout + result.stderr)
            parsed = json.loads(result.stdout)
            self.assertTrue(parsed["ok"])
            self.assertEqual(parsed["case_count"], 6)
            self.assertEqual(parsed["errors"], [])
            outputs.append(parsed)
        self.assertEqual(outputs[0], outputs[1])

    def test_real_cli_rejects_mutated_fixture_without_echoing_input(self) -> None:
        mutated = copy.deepcopy(self.fixture)
        mutated["capability_matrix"]["entries"][0]["required_caps"] = ["CAP_SYS_ADMIN"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mutated.json"
            path.write_text(json.dumps(mutated), encoding="utf-8")
            for optimized in (False, True):
                command = [sys.executable]
                if optimized:
                    command.append("-O")
                command.extend([str(validate.__file__), "--fixture", str(path)])
                result = subprocess.run(command, capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 1, (optimized, result.stderr))
                self.assertNotIn("Traceback", result.stdout + result.stderr)
                parsed = json.loads(result.stdout)
                self.assertFalse(parsed["ok"])
                self.assertEqual(parsed["errors"], ["validation_failed"])
                self.assertNotIn(str(path), result.stdout)
                self.assertNotIn("CAP_SYS_ADMIN", result.stdout)

    def test_duplicate_keys_are_rejected_before_schema_validation(self) -> None:
        with self.assertRaises(validate.DuplicateKeyError):
            validate._load_fixture_bytes(b'{"schema":"one","schema":"two"}')
        with self.assertRaises(validate.DuplicateKeyError):
            validate._load_fixture_bytes(b'{"nested":{"key":1,"key":2}}')

    def test_strict_json_rejects_nonfinite_oversized_and_deep_values(self) -> None:
        for text in (
            b'{"value":NaN}',
            b'{"value":Infinity}',
            b'{"value":1e9999}',
            b'{"value":9999999999999}',
        ):
            with self.subTest(text=text):
                with self.assertRaises(validate.ValidationError):
                    validate._load_fixture_bytes(text)

        oversized = b'{"value":"' + b"x" * (validate.MAX_JSON_STRING_BYTES + 1) + b'"}'
        with self.assertRaises(validate.ValidationError):
            validate._load_fixture_bytes(oversized)

        value: dict[str, object] = {}
        cursor = value
        for _ in range(validate.MAX_JSON_DEPTH + 2):
            child: dict[str, object] = {}
            cursor["nested"] = child
            cursor = child
        with self.assertRaises(validate.ValidationError):
            validate._load_fixture_bytes(json.dumps(value).encode("utf-8"))

    def test_capability_matrix_fails_closed_for_extra_privilege(self) -> None:
        mutated = copy.deepcopy(self.fixture)
        mutated["capability_matrix"]["entries"][0]["required_caps"] = [
            "CAP_CHOWN",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_DAC_OVERRIDE",
        ]
        self.assert_rejected(mutated)

        mutated = copy.deepcopy(self.fixture)
        mutated["capability_matrix"]["entries"][1]["not_source_justified"].remove("CAP_SYS_ADMIN")
        self.assert_rejected(mutated)

    def test_source_identity_and_boundary_mismatch_fail_closed(self) -> None:
        for field in ("commit", "tree"):
            mutated = copy.deepcopy(self.fixture)
            mutated["pinned_source"][field] = "0" * 40
            with self.subTest(field=field):
                self.assert_rejected(mutated)

        mutated = copy.deepcopy(self.fixture)
        mutated["approved_boundary"]["no_new_privileges"] = False
        self.assert_rejected(mutated)

        mutated = copy.deepcopy(self.fixture)
        mutated["approved_boundary"]["host_network"] = True
        self.assert_rejected(mutated)

    def test_runtime_exit_classification_does_not_blame_supervise_warning_alone(self) -> None:
        mutated = copy.deepcopy(self.fixture)
        podman = next(
            case for case in mutated["cases"] if case["id"] == "podman-rootless-supervise-perms-exit-2"
        )
        podman["runtime"]["exit_code"] = 0
        with self.assertRaises(validate.ValidationError):
            validate.validate_fixture(mutated)

        docker = next(
            case for case in self.fixture["cases"] if case["id"] == "docker-cap-drop-all-exit-126"
        )
        self.assertEqual(
            validate._validate_runtime_case(docker),
            "pinned_boundary_incompatibility",
        )

    def test_cleanup_requires_recognized_project_and_zero_leftovers(self) -> None:
        mutated = copy.deepcopy(self.fixture)
        cleanup = next(
            case for case in mutated["cases"] if case["id"] == "cleanup-after-failed-readiness"
        )["cleanup"]
        cleanup["leftover_volumes"] = 1
        self.assert_rejected(mutated)

        mutated = copy.deepcopy(self.fixture)
        cleanup = next(
            case for case in mutated["cases"] if case["id"] == "cleanup-after-failed-readiness"
        )["cleanup"]
        cleanup["project_scope"] = "unrecognized_project"
        self.assert_rejected(mutated)

    def test_harness_volume_assertion_stays_separate_from_host_bind_policy(self) -> None:
        harness_case = next(
            case for case in self.fixture["cases"] if case["id"] == "harness-hostconfig-binds-volume-assertion"
        )
        self.assertEqual(validate._validate_harness_case(harness_case), "harness_defect")
        self.assertEqual(
            harness_case["observed"]["mounts"][0]["source_kind"],
            "named",
        )
        self.assertFalse(self.fixture["approved_boundary"]["host_profile_bind"])

    def test_redaction_is_bounded_and_removes_sensitive_shapes(self) -> None:
        hostile = (
            "Authorization: Bearer live-secret-token "
            "Cookie: session=private-cookie "
            "https://private.example.test/path?token=secret "
            "/Users/operator/private/transcript.txt "
            "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        )
        redacted = validate.redact_diagnostic(hostile)
        self.assertLessEqual(len(redacted.encode("utf-8")), validate.MAX_ERROR_MESSAGE_BYTES)
        self.assertNotIn("live-secret-token", redacted)
        self.assertNotIn("private-cookie", redacted)
        self.assertNotIn("https://private.example.test", redacted)
        self.assertNotIn("/Users/operator", redacted)
        self.assertNotIn("QWxhZGRpbjpvcGVu", redacted)
        self.assertIn("[REDACTED]", redacted)

    def test_proposed_run_is_rootless_podman_and_preserves_boundary(self) -> None:
        proposal = self.fixture["proposed_one_run"]
        self.assertEqual(proposal["executor"], "podman")
        self.assertEqual(proposal["compose_provider"], "podman-compose")
        self.assertEqual(proposal["account"], "hermternal-test")
        self.assertTrue(proposal["rootless"])
        self.assertEqual(proposal["cap_drop"], ["ALL"])
        self.assertEqual(proposal["cap_add"], ["CAP_CHOWN", "CAP_SETGID", "CAP_SETUID"])
        self.assertEqual(proposal["published_ports"], [])
        self.assertEqual(proposal["binds"], [])
        self.assertTrue(proposal["approval_required"])

    def test_no_live_candidate_claim_can_be_added(self) -> None:
        mutated = copy.deepcopy(self.fixture)
        mutated["live_execution"] = True
        self.assert_rejected(mutated)

        mutated = copy.deepcopy(self.fixture)
        mutated["proposed_one_run"]["approval_required"] = False
        self.assert_rejected(mutated)


if __name__ == "__main__":
    unittest.main(verbosity=2)
