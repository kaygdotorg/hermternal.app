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
PYTHON_MODES = (("normal", False), ("optimized", True))
REDACTION_SAMPLES = (
    ("authorization_token", "Authorization: Token live-secret-token", ("live-secret-token",)),
    ("authorization_bearer", "Authorization: Bearer live-bearer-token", ("live-bearer-token",)),
    ("authorization_assignment", "Authorization=Bearer live-assignment-token", ("live-assignment-token",)),
    ("api_header", "X-API-Key: live-api-key", ("live-api-key",)),
    ("api_assignment", "api_key=live-api-key", ("live-api-key",)),
    ("quoted_json_api_key", '\"api_key\": \"live-json-key\"', ("live-json-key",)),
    ("access_assignment", "access_key: 'live-access-key'", ("live-access-key",)),
    ("token_assignment", "token=\"live-assignment-token\"", ("live-assignment-token",)),
    ("password_assignment", "password=live-password", ("live-password",)),
    ("client_secret_assignment", "client_secret=live-client-secret", ("live-client-secret",)),
    ("cookie", "Cookie: session=private-cookie", ("private-cookie",)),
    ("url", "https://private.example.test/path?token=secret", ("https://private.example.test", "secret")),
    (
        "mac_spaced_path",
        "/Applications/Private App/data",
        ("/Applications/Private App/data", "Private App/data", "App/data", "data"),
    ),
    (
        "unix_spaced_path",
        "/Users/operator/Private Folder/transcript.txt",
        (
            "/Users/operator/Private Folder/transcript.txt",
            "Private Folder/transcript.txt",
            "Folder/transcript.txt",
            "transcript.txt",
        ),
    ),
    (
        "windows_spaced_path",
        r"C:\Users\operator\Private Folder\token.txt",
        (
            r"C:\Users\operator\Private Folder\token.txt",
            r"Private Folder\token.txt",
            r"Folder\token.txt",
            "token.txt",
        ),
    ),
    (
        "unc_spaced_path",
        r"\\server\share\Private Folder\secret.txt",
        (
            r"\\server\share\Private Folder\secret.txt",
            r"share\Private Folder\secret.txt",
            r"Private Folder\secret.txt",
            "secret.txt",
        ),
    ),
    ("base64_blob", "QWxhZGRpbjpvcGVuIHNlc2FtZQ==", ("QWxhZGRpbjpvcGVu",)),
    ("short_base64", "c2VjcmV0", ("c2VjcmV0",)),
    ("urlsafe_base64", "c2VjcmV0LXNlY3JldA", ("c2VjcmV0LXNlY3JldA",)),
)


class RootlessInitValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = validate.load_fixture(FIXTURE_PATH)

    def assert_rejected(self, fixture: dict[str, object]) -> None:
        with self.assertRaises(validate.ValidationError):
            validate.validate_fixture(fixture)

    def run_cli(self, path: Path = FIXTURE_PATH, *, optimized: bool = False) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend([str(validate.__file__), "--fixture", str(path)])
        return subprocess.run(command, capture_output=True, text=True, check=False)

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
        for mode, optimized in PYTHON_MODES:
            with self.subTest(mode=mode):
                result = self.run_cli(optimized=optimized)
                self.assertEqual(result.returncode, 0, (mode, result.stderr))
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
            for mode, optimized in PYTHON_MODES:
                with self.subTest(mode=mode):
                    result = self.run_cli(path, optimized=optimized)
                    self.assertEqual(result.returncode, 1, (mode, result.stderr))
                    self.assertNotIn("Traceback", result.stdout + result.stderr)
                    parsed = json.loads(result.stdout)
                    self.assertFalse(parsed["ok"])
                    self.assertEqual(parsed["errors"], ["validation_failed"])
                    self.assertNotIn(str(path), result.stdout)
                    self.assertNotIn("CAP_SYS_ADMIN", result.stdout)

    def test_real_cli_rejects_nearby_mutations_in_both_python_modes(self) -> None:
        def duplicate_docker(value: dict[str, object]) -> None:
            entry = value["capability_matrix"]["entries"][1]
            entry["executor"] = "docker"
            entry["user_namespace"] = "rootful"
            entry.pop("preconditions")

        def duplicate_podman(value: dict[str, object]) -> None:
            entry = value["capability_matrix"]["entries"][0]
            entry["executor"] = "podman"
            entry["user_namespace"] = "rootless"
            entry["preconditions"] = [
                "subuid_mapping_includes_hermes_uid",
                "subgid_mapping_includes_hermes_gid",
                "rootless_user_namespace",
            ]

        def docker_preconditions(value: dict[str, object]) -> None:
            value["capability_matrix"]["entries"][0]["preconditions"] = ["unexpected"]

        def wrong_reason(value: dict[str, object]) -> None:
            case = next(item for item in value["cases"] if item["id"] == "unsafe-workaround-capability-escalation")
            case["expected"]["reason_codes"] = ["not-a-real-reason"]

        def reordered_reasons(value: dict[str, object]) -> None:
            case = next(item for item in value["cases"] if item["id"] == "unsafe-workaround-capability-escalation")
            case["expected"]["reason_codes"] = list(reversed(case["expected"]["reason_codes"]))

        def missing_reason(value: dict[str, object]) -> None:
            case = next(item for item in value["cases"] if item["id"] == "unsafe-workaround-capability-escalation")
            case["expected"]["reason_codes"] = case["expected"]["reason_codes"][:-1]

        def extra_reason(value: dict[str, object]) -> None:
            case = next(item for item in value["cases"] if item["id"] == "unsafe-workaround-capability-escalation")
            case["expected"]["reason_codes"].append("not-a-real-reason")

        def runtime_irrelevant_field(value: dict[str, object]) -> None:
            case = next(item for item in value["cases"] if item["id"] == "docker-cap-drop-all-exit-126")
            case["mutation"] = {}

        def harness_irrelevant_field(value: dict[str, object]) -> None:
            case = next(item for item in value["cases"] if item["id"] == "harness-hostconfig-binds-volume-assertion")
            case["runtime"] = {}

        def policy_irrelevant_field(value: dict[str, object]) -> None:
            case = next(item for item in value["cases"] if item["id"] == "unsafe-workaround-arbitrary-user")
            case["boundary"] = {}

        def cleanup_irrelevant_field(value: dict[str, object]) -> None:
            case = next(item for item in value["cases"] if item["id"] == "cleanup-after-failed-readiness")
            case["observed"] = {}

        def live_claim(value: dict[str, object]) -> None:
            value["live_execution"] = True

        mutations = (
            ("duplicate_docker", duplicate_docker),
            ("duplicate_podman", duplicate_podman),
            ("docker_preconditions", docker_preconditions),
            ("wrong_reason", wrong_reason),
            ("reordered_reasons", reordered_reasons),
            ("missing_reason", missing_reason),
            ("extra_reason", extra_reason),
            ("runtime_irrelevant_field", runtime_irrelevant_field),
            ("harness_irrelevant_field", harness_irrelevant_field),
            ("policy_irrelevant_field", policy_irrelevant_field),
            ("cleanup_irrelevant_field", cleanup_irrelevant_field),
            ("live_claim", live_claim),
        )
        for label, mutate in mutations:
            mutated = copy.deepcopy(self.fixture)
            mutate(mutated)
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / f"{label}.json"
                path.write_text(json.dumps(mutated), encoding="utf-8")
                for mode, optimized in PYTHON_MODES:
                    with self.subTest(mutation=label, mode=mode):
                        result = self.run_cli(path, optimized=optimized)
                        self.assertEqual(result.returncode, 1, (label, mode, result.stderr))
                        self.assertNotIn("Traceback", result.stdout + result.stderr)
                        parsed = json.loads(result.stdout)
                        self.assertFalse(parsed["ok"])
                        self.assertEqual(parsed["errors"], ["validation_failed"])
                        self.assertNotIn(str(path), result.stdout)

    def test_real_cli_rejects_every_approved_boundary_key_deletion(self) -> None:
        boundary_keys = tuple(validate.APPROVED_BOUNDARY) + ("resource_limits",)
        resource_keys = ("cpus", "memory", "pids")
        mutations: list[tuple[str, tuple[str, ...]]] = [(key, (key,)) for key in boundary_keys]
        mutations.extend((f"resource_limits.{key}", ("resource_limits", key)) for key in resource_keys)
        for label, key_path in mutations:
            mutated = copy.deepcopy(self.fixture)
            cursor = mutated["approved_boundary"]
            for key in key_path[:-1]:
                cursor = cursor[key]
            del cursor[key_path[-1]]
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / f"boundary-delete-{label.replace('.', '-')}.json"
                path.write_text(json.dumps(mutated), encoding="utf-8")
                for mode, optimized in PYTHON_MODES:
                    with self.subTest(field=label, mode=mode):
                        result = self.run_cli(path, optimized=optimized)
                        self.assertEqual(result.returncode, 1, (label, mode, result.stderr))
                        self.assertNotIn("Traceback", result.stdout + result.stderr)
                        self.assertNotIn(str(path), result.stdout)
                        self.assertEqual(
                            json.loads(result.stdout),
                            {
                                "candidate_status": "unknown",
                                "case_count": 0,
                                "classifications": {},
                                "cleanup_complete": False,
                                "errors": ["validation_failed"],
                                "live_execution": False,
                                "ok": False,
                                "redacted": True,
                                "schema": validate.SCHEMA,
                            },
                        )

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
        for label, hostile, forbidden_values in REDACTION_SAMPLES:
            with self.subTest(shape=label):
                redacted = validate.redact_diagnostic(hostile)
                self.assertLessEqual(len(redacted.encode("utf-8")), validate.MAX_ERROR_MESSAGE_BYTES)
                for forbidden in forbidden_values:
                    self.assertNotIn(forbidden, redacted)
                self.assertIn("[REDACTED", redacted)

        combined = " ".join(sample[1] for sample in REDACTION_SAMPLES)
        redacted = validate.redact_diagnostic(combined)
        self.assertLessEqual(len(redacted.encode("utf-8")), validate.MAX_ERROR_MESSAGE_BYTES)
        for _, _, forbidden_values in REDACTION_SAMPLES:
            for forbidden in forbidden_values:
                self.assertNotIn(forbidden, redacted)
        self.assertIn("[REDACTED", redacted)

    def test_real_cli_rejects_sensitive_mutations_without_echoing_them(self) -> None:
        for label, hostile, forbidden_values in REDACTION_SAMPLES:
            mutated = copy.deepcopy(self.fixture)
            mutated["approved_boundary"]["volume_kind"] = hostile
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / f"sensitive-boundary-{label}.json"
                path.write_text(json.dumps(mutated), encoding="utf-8")
                for mode, optimized in PYTHON_MODES:
                    with self.subTest(shape=label, mode=mode):
                        result = self.run_cli(path, optimized=optimized)
                        output = result.stdout + result.stderr
                        self.assertEqual(result.returncode, 1, (label, mode, result.stderr))
                        self.assertNotIn("Traceback", output)
                        self.assertNotIn(str(path), output)
                        for forbidden in forbidden_values:
                            self.assertNotIn(forbidden, output)
                        self.assertEqual(json.loads(result.stdout)["errors"], ["validation_failed"])

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
