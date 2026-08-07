#!/usr/bin/env python3
"""Regression tests for the shared benchmark evidence contract.

The suite uses only synthetic JSON and the Python standard library.  It never
starts Hermes, opens a network connection, invokes a browser, or reads live
machine identifiers.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


FIXTURE_DIR = Path(__file__).resolve().parent
if str(FIXTURE_DIR) not in sys.path:
    sys.path.insert(0, str(FIXTURE_DIR))

import validate  # noqa: E402


class BenchmarkEvidenceTests(unittest.TestCase):
    """Keep the closed format, method, and redaction boundary aligned."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.document = validate.load_json(validate.EVIDENCE_PATH)
        validate.validate_evidence(cls.document)
        cls.web_document = validate.load_json(validate.WEB_EVIDENCE_PATH)
        validate.validate_evidence(
            cls.web_document,
            root=validate.WEB_BENCHMARK_ROOT,
            expected_id=validate.WEB_PRODUCTION_BUILD_EVIDENCE_ID,
        )

    def _run_cli(
        self,
        raw: bytes,
        *,
        optimized: bool = False,
        extra: tuple[str, ...] = ("--skip-baseline",),
        baseline_raw: bytes | None = None,
        script_path: Path = FIXTURE_DIR / "validate.py",
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.NamedTemporaryFile(suffix=".json") as evidence_handle:
            evidence_handle.write(raw)
            evidence_handle.flush()
            baseline_handle = None
            try:
                arguments = list(extra)
                if baseline_raw is not None:
                    arguments = [argument for argument in arguments if argument != "--skip-baseline"]
                    baseline_handle = tempfile.NamedTemporaryFile(suffix=".json")
                    baseline_handle.write(baseline_raw)
                    baseline_handle.flush()
                    arguments.extend(("--baseline", baseline_handle.name))
                command = [sys.executable]
                if optimized:
                    command.append("-O")
                command.extend([str(script_path), "--evidence", evidence_handle.name, *arguments])
                return subprocess.run(command, check=False, capture_output=True, text=True)
            finally:
                if baseline_handle is not None:
                    baseline_handle.close()

    def _run_document(self, document: object, *, optimized: bool = False) -> subprocess.CompletedProcess[str]:
        return self._run_cli(json.dumps(document, separators=(",", ":")).encode(), optimized=optimized)

    def _assert_rejected(self, document: object) -> None:
        with self.assertRaises(validate.ValidationError):
            validate.validate_evidence(document)

    def _assert_cli_failure(
        self,
        raw: bytes,
        secret: str | None = None,
        *,
        baseline_raw: bytes | None = None,
        script_path: Path = FIXTURE_DIR / "validate.py",
    ) -> None:
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                completed = self._run_cli(
                    raw,
                    optimized=optimized,
                    extra=() if baseline_raw is not None else ("--skip-baseline",),
                    baseline_raw=baseline_raw,
                    script_path=script_path,
                )
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stderr, "")
                lines = [line for line in completed.stdout.splitlines() if line.strip()]
                self.assertEqual(len(lines), 1)
                payload = json.loads(lines[0])
                self.assertFalse(payload["ok"])
                self.assertEqual(payload["error"]["code"], validate.ERROR_CODE)
                self.assertLessEqual(len(payload["error"]["message"]), validate.MAX_ERROR_OUTPUT)
                self.assertNotIn("Traceback", completed.stdout + completed.stderr)
                if secret is not None:
                    self.assertNotIn(secret, completed.stdout + completed.stderr)

    def _assert_cli_document_failure(self, document: object, secret: str | None = None) -> None:
        self._assert_cli_failure(json.dumps(document, separators=(",", ":")).encode(), secret)

    @staticmethod
    def _recompute_run(run: dict[str, object]) -> None:
        expected = validate.expected_distribution(run["raw_samples"])
        run["distribution"] = {key: float(value) for key, value in expected.items()}
        run["sample_provenance_sha256"] = validate.sample_provenance_digest(run)

    def test_checked_in_format_has_all_platform_and_state_examples(self) -> None:
        self.assertEqual(self.document["schema"], validate.SCHEMA)
        self.assertEqual(
            {run["platform"] for run in self.document["runs"]},
            {"web", "ios"},
        )
        self.assertEqual(
            {(run["platform"], run["state"]) for run in self.document["runs"]},
            {("web", "cold"), ("web", "warm"), ("ios", "cold"), ("ios", "warm")},
        )
        self.assertTrue(all(run["repetitions"] == len(run["raw_samples"]) == 30 for run in self.document["runs"]))
        self.assertIsNone(self.document["threshold"])
        self.assertIsNone(self.document["budget"])

    def test_canonical_distribution_is_recomputed_for_every_run(self) -> None:
        for run in self.document["runs"]:
            with self.subTest(run=run["id"]):
                expected = validate.expected_distribution(run["raw_samples"])
                for key, value in expected.items():
                    self.assertEqual(validate.Decimal(str(run["distribution"][key])), value)

    def test_percentile_method_is_inclusive_linear_interpolation(self) -> None:
        distribution = validate.expected_distribution(list(range(1, 31)))
        self.assertEqual(distribution["p50"], validate.Decimal("15.500"))
        self.assertEqual(distribution["p95"], validate.Decimal("28.550"))
        self.assertEqual(distribution["p99"], validate.Decimal("29.710"))
        method = self.document["method"]
        self.assertEqual(method["percentile_method"], "inclusive_linear_interpolation_r7")
        self.assertEqual(method["position_formula"], "(n - 1) * q")
        self.assertEqual(method["rounding"], "half_even_to_3_decimal_places")

    def test_missing_unknown_and_reordered_keys_fail_closed(self) -> None:
        missing = copy.deepcopy(self.document)
        del missing["budget"]
        self._assert_rejected(missing)

        unknown = copy.deepcopy(self.document)
        unknown["unexpected"] = "synthetic"
        self._assert_rejected(unknown)

        reordered = copy.deepcopy(self.document)
        reordered["threshold"], reordered["budget"] = reordered["budget"], reordered["threshold"]
        reordered = {key: reordered[key] for key in reversed(tuple(reordered))}
        self._assert_rejected(reordered)

    def test_repetitions_and_raw_samples_are_bound(self) -> None:
        mismatch = copy.deepcopy(self.document)
        mismatch["runs"][0]["repetitions"] = 29
        self._assert_rejected(mismatch)

        too_few = copy.deepcopy(self.document)
        too_few["runs"][0]["raw_samples"] = [1.0]
        too_few["runs"][0]["repetitions"] = 1
        self._assert_rejected(too_few)

        bool_sample = copy.deepcopy(self.document)
        bool_sample["runs"][0]["raw_samples"][0] = True
        self._assert_rejected(bool_sample)

    def test_cold_warm_and_build_mode_values_are_closed(self) -> None:
        invalid_state = copy.deepcopy(self.document)
        invalid_state["runs"][0]["state"] = "reused"
        self._assert_rejected(invalid_state)

        invalid_build = copy.deepcopy(self.document)
        invalid_build["runs"][0]["build_mode"] = "debug"
        self._assert_rejected(invalid_build)

        wrong_platform_build = copy.deepcopy(self.document)
        wrong_platform_build["runs"][0]["build_mode"] = "release"
        self._assert_rejected(wrong_platform_build)

        invalid_optimization = copy.deepcopy(self.document)
        invalid_optimization["runs"][0]["optimization"] = "debug"
        self._assert_rejected(invalid_optimization)

    def test_distribution_mutation_is_detected(self) -> None:
        mutated = copy.deepcopy(self.document)
        mutated["runs"][0]["distribution"]["p99"] += 1
        self._assert_rejected(mutated)

        nonfinite = copy.deepcopy(self.document)
        nonfinite["runs"][0]["raw_samples"][0] = float("inf")
        self._assert_rejected(nonfinite)

    def test_revision_and_artifact_identity_are_strict(self) -> None:
        bad_commit = copy.deepcopy(self.document)
        bad_commit["revision"]["commit_sha"] = "not-a-commit"
        self._assert_rejected(bad_commit)

        bad_version = copy.deepcopy(self.document)
        bad_version["revision"]["fixture_version"] = "latest"
        self._assert_rejected(bad_version)

        bad_hash = copy.deepcopy(self.document)
        bad_hash["artifacts"][0]["sha256"] = "0" * 64
        self._assert_rejected(bad_hash)

        bad_manifest = copy.deepcopy(self.document)
        bad_manifest["artifact_manifest_sha256"] = "0" * 64
        self._assert_rejected(bad_manifest)

    def test_web_toolchain_identity_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for portable_path in validate.EXPECTED_ARTIFACT_PATHS[validate.WEB_PRODUCTION_BUILD_EVIDENCE_ID]:
                source = validate.WEB_BENCHMARK_ROOT / portable_path
                destination = root / portable_path
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            trace_path = root / "evidence" / "raw-trace.json"
            trace = validate.load_json(trace_path)
            trace["toolchain"]["vite"]["sha256"] = "0" * 64
            trace_path.write_text(json.dumps(trace, separators=(",", ":")), encoding="utf-8")
            with self.assertRaises(validate.ValidationError):
                validate.validate_evidence(
                    self.web_document,
                    root=root,
                    expected_id=validate.WEB_PRODUCTION_BUILD_EVIDENCE_ID,
                )

        traversal = copy.deepcopy(self.document)
        traversal["artifacts"][0]["path"] = "../outside.json"
        self._assert_rejected(traversal)

    def test_canonical_identity_and_forged_samples_fail_in_both_cli_modes(self) -> None:
        mutations: tuple[tuple[str, object, str | None], ...] = (
            (
                "environment identity",
                lambda document: document["runs"][0]["environment"].__setitem__("platform", "attacker-platform"),
                None,
            ),
            (
                "source commit identity",
                lambda document: document["revision"].__setitem__("commit_sha", "0" * 40),
                None,
            ),
            (
                "fixture identity",
                lambda document: document["revision"].__setitem__("fixture_id", "attacker-fixture"),
                None,
            ),
            (
                "fixture digest identity",
                lambda document: document["revision"].__setitem__("fixture_sha256", "0" * 64),
                None,
            ),
            (
                "permitted artifact set",
                lambda document: (
                    document.__setitem__(
                        "artifacts",
                        [{
                            "path": "validation-baseline.json",
                            "bytes": validate.BASELINE_PATH.stat().st_size,
                            "sha256": hashlib.sha256(validate.BASELINE_PATH.read_bytes()).hexdigest(),
                        }],
                    ),
                    document.__setitem__("artifact_manifest_sha256", validate.artifact_manifest_digest(document["artifacts"])),
                ),
                None,
            ),
        )
        for label, mutate, secret in mutations:
            candidate = copy.deepcopy(self.document)
            mutate(candidate)
            with self.subTest(mutation=label):
                self._assert_cli_document_failure(candidate, secret)

        forged = copy.deepcopy(self.document)
        forged_run = forged["runs"][0]
        forged_run["raw_samples"][0] = 1.0
        self._recompute_run(forged_run)
        self._assert_cli_document_failure(forged)

        baseline = validate.load_json(validate.BASELINE_PATH)
        forged_baseline = copy.deepcopy(baseline)
        forged_baseline_run = forged_baseline["runs"][0]
        forged_baseline_run["raw_samples"][0] = 1.0
        self._recompute_run(forged_baseline_run)
        self._assert_cli_failure(
            validate.EVIDENCE_PATH.read_bytes(),
            baseline_raw=json.dumps(forged_baseline, separators=(",", ":")).encode(),
        )

    def test_redaction_boundary_rejects_hosts_ips_bearer_and_api_key_in_both_cli_modes(self) -> None:
        values = (
            ("bare hostname", "evil.xyz", None),
            ("multi-label hostname", "evil.co.uk", None),
            ("IPv4 address", "127.0.0.1", None),
            ("localhost", "localhost", None),
            ("bearer secret", "Bearer raw-secret", "raw-secret"),
            ("API key assignment", "api_key=raw-secret", "raw-secret"),
        )
        for label, value, secret in values:
            candidate = copy.deepcopy(self.document)
            candidate["runs"][0]["command"] = value
            with self.subTest(mutation=label):
                self._assert_cli_document_failure(candidate, secret)

    def test_provider_token_shapes_fail_across_text_fields_in_both_cli_modes(self) -> None:
        """Reject provider credentials even in otherwise-valid text fields."""
        tokens = (
            ("GitHub classic token", "ghp_" + ("a" * 36)),
            ("OpenAI or Stripe token", "sk-" + ("b" * 32)),
            ("Slack bot token", "xoxb-" + ("c" * 24)),
        )
        fields = (
            ("metric.name", lambda document, token: document["metric"].__setitem__("name", token)),
            ("run.command", lambda document, token: document["runs"][0].__setitem__("command", token)),
            (
                "environment.device",
                lambda document, token: document["runs"][0]["environment"].__setitem__("device", token),
            ),
        )
        for field_label, set_value in fields:
            for token_label, token in tokens:
                candidate = copy.deepcopy(self.document)
                set_value(candidate, token)
                with self.subTest(field=field_label, token=token_label):
                    self._assert_cli_document_failure(candidate, token)

    def test_registered_web_evidence_passes_normal_and_optimized_cli(self) -> None:
        for optimized in (False, True):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.extend((str(validate.EVIDENCE_PATH.with_name("validate.py")), "--evidence", str(validate.WEB_EVIDENCE_PATH), "--skip-baseline"))
            completed = subprocess.run(command, check=False, capture_output=True, text=True)
            with self.subTest(optimized=optimized):
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                self.assertEqual(completed.stderr, "")
                payload = json.loads(completed.stdout)
                self.assertEqual(payload["evidence_id"], validate.WEB_PRODUCTION_BUILD_EVIDENCE_ID)

    def test_web_evidence_cannot_rebind_its_canonical_root(self) -> None:
        raw = validate.WEB_EVIDENCE_PATH.read_bytes()
        self._assert_cli_failure(raw)

    def test_web_evidence_descendant_scope_is_ancestry_and_path_bound(self) -> None:
        source = "a" * 40
        head = "b" * 40
        record = {"revision": {"commit_sha": source}}
        common = [
            subprocess.CompletedProcess([], 0, stdout=f"{head}\n".encode(), stderr=b""),
            subprocess.CompletedProcess([], 0, stdout=b"", stderr=b""),
        ]
        with patch.object(
            validate.subprocess,
            "run",
            side_effect=common + [
                subprocess.CompletedProcess([], 0, stdout=b"apps/web/benchmarks/production-build/evidence/new.json\0", stderr=b"")
            ],
        ):
            validate._validate_web_evidence_revision(record, validate.WEB_BENCHMARK_ROOT)

        with patch.object(
            validate.subprocess,
            "run",
            side_effect=common + [
                subprocess.CompletedProcess([], 0, stdout=b"apps/web/src/unreviewed.ts\0", stderr=b"")
            ],
        ):
            with self.assertRaises(validate.ValidationError):
                validate._validate_web_evidence_revision(record, validate.WEB_BENCHMARK_ROOT)

    def test_web_trace_replacement_and_symlink_escape_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            copied_root = Path(directory) / "production-build"
            shutil.copytree(validate.WEB_BENCHMARK_ROOT, copied_root)
            trace_path = copied_root / "evidence" / "raw-trace.json"
            trace_path.write_bytes(b'{"schema":"hermternal.web-production-build-trace.v1"}')
            with self.assertRaises(validate.ValidationError):
                validate.validate_evidence(
                    copy.deepcopy(self.web_document),
                    root=copied_root,
                    expected_id=validate.WEB_PRODUCTION_BUILD_EVIDENCE_ID,
                )

            trace_path.unlink()
            external = Path(directory) / "external.json"
            external.write_bytes(validate.WEB_BENCHMARK_ROOT.joinpath("evidence/raw-trace.json").read_bytes())
            trace_path.symlink_to(external)
            with self.assertRaises(validate.ValidationError):
                validate.validate_evidence(
                    copy.deepcopy(self.web_document),
                    root=copied_root,
                    expected_id=validate.WEB_PRODUCTION_BUILD_EVIDENCE_ID,
                )

    def test_missing_recorded_artifact_fails_in_both_cli_modes(self) -> None:
        """Exercise local artifact absence without mutating the checkout.

        The validator resolves artifacts beside its own script, so a copied
        benchmark directory gives the subprocess a realistic root while keeping
        normal and optimized test processes safe to run concurrently.
        """
        with tempfile.TemporaryDirectory() as directory:
            copied_root = Path(directory) / "benchmarks"
            shutil.copytree(FIXTURE_DIR, copied_root)
            (copied_root / "synthetic" / "trace.json").unlink()
            self._assert_cli_failure(
                validate.EVIDENCE_PATH.read_bytes(),
                script_path=copied_root / "validate.py",
            )

    def test_rebound_trace_bytes_and_manifest_fail_in_both_cli_modes(self) -> None:
        """Reject coordinated trace replacement and candidate metadata rebinding.

        A local file check alone would accept replacement bytes after the
        evidence record's byte count, hash, and manifest were recomputed.  The
        subprocess uses a copied root to exercise that mutation without
        changing checked-in artifacts or racing another test process.
        """
        with tempfile.TemporaryDirectory() as directory:
            copied_root = Path(directory) / "benchmarks"
            shutil.copytree(FIXTURE_DIR, copied_root)
            replacement = b'{"schema":"hermternal.benchmark-trace.v1","events":[]}'
            (copied_root / "synthetic" / "trace.json").write_bytes(replacement)

            candidate = copy.deepcopy(self.document)
            trace_artifact = candidate["artifacts"][1]
            trace_artifact["bytes"] = len(replacement)
            trace_artifact["sha256"] = hashlib.sha256(replacement).hexdigest()
            candidate["artifact_manifest_sha256"] = validate.artifact_manifest_digest(candidate["artifacts"])
            self._assert_cli_failure(
                json.dumps(candidate, separators=(",", ":")).encode(),
                script_path=copied_root / "validate.py",
            )

    def test_threshold_and_budget_cannot_become_unreviewed_limits(self) -> None:
        for key in ("threshold", "budget"):
            mutated = copy.deepcopy(self.document)
            mutated[key] = 100
            with self.subTest(key=key):
                self._assert_rejected(mutated)

    def test_redaction_rejects_sensitive_fields_and_values(self) -> None:
        sensitive_value = copy.deepcopy(self.document)
        sensitive_value["runs"][0]["command"] = "token=raw-synthetic-secret"
        self._assert_rejected(sensitive_value)

        sensitive_key = copy.deepcopy(self.document)
        sensitive_key["runs"][0]["raw_token"] = "synthetic"
        self._assert_rejected(sensitive_key)

        redaction_flag = copy.deepcopy(self.document)
        redaction_flag["redaction"]["contains_tokens"] = True
        self._assert_rejected(redaction_flag)

        host_value = copy.deepcopy(self.document)
        host_value["runs"][0]["environment"]["device"] = "https://live.example.test"
        self._assert_rejected(host_value)

    def test_duplicate_keys_nonfinite_numbers_and_invalid_utf8_are_controlled(self) -> None:
        self._assert_cli_failure(b'{"schema":1,"schema":2}')
        self._assert_cli_failure(b'{"schema":NaN}')
        self._assert_cli_failure(b'{"schema":1e999}')
        self._assert_cli_failure(b"\xff\xfe\xfd")

    def test_load_json_rejects_oversized_input_after_bounded_descriptor_read(self) -> None:
        with tempfile.NamedTemporaryFile() as handle:
            handle.write(b"{" + b"x" * (validate.MAX_JSON_BYTES - 1))
            handle.flush()
            requested: list[int] = []
            original_read = validate.os.read

            def bounded_read(descriptor: int, count: int) -> bytes:
                requested.append(count)
                return original_read(descriptor, count)

            with patch.object(validate.os, "read", side_effect=bounded_read):
                with self.assertRaises(validate.ValidationError):
                    validate.load_json(Path(handle.name))
            self.assertTrue(requested)
            self.assertTrue(all(count <= validate.MAX_JSON_BYTES + 1 for count in requested))

    def test_load_json_rejects_append_after_first_read(self) -> None:
        with tempfile.NamedTemporaryFile() as handle:
            handle.write(b"{}")
            handle.flush()
            original_read = validate.os.read
            calls = 0

            def growing_read(descriptor: int, count: int) -> bytes:
                nonlocal calls
                result = original_read(descriptor, count)
                calls += 1
                if calls == 1:
                    with open(handle.name, "ab") as replacement:
                        replacement.write(b" ")
                return result

            with patch.object(validate.os, "read", side_effect=growing_read):
                with self.assertRaises(validate.ValidationError):
                    validate.load_json(Path(handle.name))

    def test_load_json_rejects_growth_from_an_initially_empty_file(self) -> None:
        with tempfile.NamedTemporaryFile() as handle:
            handle.flush()
            original_fstat = validate.os.fstat
            calls = 0

            def growing_fstat(descriptor: int):
                nonlocal calls
                calls += 1
                result = original_fstat(descriptor)
                if calls == 1:
                    with open(handle.name, "wb") as replacement:
                        replacement.write(b"{}")
                return result

            with patch.object(validate.os, "fstat", side_effect=growing_fstat):
                with self.assertRaises(validate.ValidationError):
                    validate.load_json(Path(handle.name))

    def test_local_file_reader_rejects_append_after_first_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_bytes(b"{}")
            original_read = validate.os.read
            calls = 0

            def growing_read(descriptor: int, count: int) -> bytes:
                nonlocal calls
                result = original_read(descriptor, count)
                calls += 1
                if calls == 1:
                    with path.open("ab") as replacement:
                        replacement.write(b" ")
                return result

            with patch.object(validate.os, "read", side_effect=growing_read):
                with self.assertRaises(validate.ValidationError):
                    validate._read_local_file(Path(directory), "evidence.json", "local file")

    def test_local_file_reader_rejects_growth_from_an_initially_empty_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_bytes(b"")
            original_fstat = validate.os.fstat
            calls = 0

            def growing_fstat(descriptor: int):
                nonlocal calls
                calls += 1
                result = original_fstat(descriptor)
                if calls == 1:
                    path.write_bytes(b"{}")
                return result

            with patch.object(validate.os, "fstat", side_effect=growing_fstat):
                with self.assertRaises(validate.ValidationError):
                    validate._read_local_file(Path(directory), "evidence.json", "local file")

    def test_runtime_anchor_selection_fails_closed_for_unanchored_linux(self) -> None:
        darwin = {"darwin": {"node": {}, "bun": {}, "python": {}, "sandbox": {}}}
        self.assertIs(validate._runtime_anchor_for_environment(darwin, "darwin-25.5.0"), darwin["darwin"])
        with self.assertRaises(validate.ValidationError):
            validate._runtime_anchor_for_environment(darwin, "linux-6.1.0")

    def test_runtime_anchor_selection_binds_linux_to_linux_identity(self) -> None:
        darwin = {"node": {"bytes": 1, "sha256": "a" * 64}, "bun": {"bytes": 2, "sha256": "b" * 64}, "python": {"bytes": 3, "sha256": "c" * 64}, "sandbox": {"bytes": 4, "sha256": "d" * 64}}
        linux = {"node": {"bytes": 5, "sha256": "e" * 64}, "bun": {"bytes": 6, "sha256": "f" * 64}, "python": {"bytes": 7, "sha256": "0" * 64}, "sandbox": {"bytes": 8, "sha256": "1" * 64}}
        anchors = {"darwin": darwin, "linux": linux}
        self.assertIs(validate._runtime_anchor_for_environment(anchors, "linux-6.1.0"), linux)
        self.assertIsNot(validate._runtime_anchor_for_environment(anchors, "linux-6.1.0"), darwin)

    def test_error_output_does_not_echo_sensitive_arguments_or_values(self) -> None:
        for optimized in (False, True):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.extend([str(FIXTURE_DIR / "validate.py"), "--token=raw-synthetic-secret"])
            completed = subprocess.run(command, check=False, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(completed.stderr, "")
            self.assertNotIn("raw-synthetic-secret", completed.stdout)
            self.assertNotIn("usage:", completed.stdout.lower())
            self.assertLessEqual(len(completed.stdout), validate.MAX_ERROR_OUTPUT + 128)

        raw = json.dumps(
            {"schema": "x", "command": "token=raw-synthetic-secret"},
            separators=(",", ":"),
        ).encode()
        self._assert_cli_failure(raw, "raw-synthetic-secret")

    def test_cli_succeeds_in_normal_and_optimized_modes(self) -> None:
        raw = validate.EVIDENCE_PATH.read_bytes()
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                completed = self._run_cli(raw, optimized=optimized)
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                self.assertEqual(completed.stderr, "")
                payload = json.loads(completed.stdout)
                self.assertTrue(payload["ok"])
                self.assertFalse(payload["baseline_checked"])

    def test_checked_in_validator_baseline_is_reproducible(self) -> None:
        baseline = validate.load_json(validate.BASELINE_PATH)
        validate.validate_baseline(baseline)
        self.assertEqual(baseline["evidence_id"], validate.BASELINE_EVIDENCE_ID)
        self.assertEqual({run["optimization"] for run in baseline["runs"]}, {"normal", "optimized"})
        self.assertTrue(all(run["repetitions"] == 30 for run in baseline["runs"]))
        self.assertIsNone(baseline["threshold"])
        self.assertIsNone(baseline["budget"])

    def test_baseline_mutations_fail_closed(self) -> None:
        baseline = validate.load_json(validate.BASELINE_PATH)
        for mutation in ("threshold", "budget"):
            candidate = copy.deepcopy(baseline)
            candidate[mutation] = 1
            with self.subTest(mutation=mutation):
                with self.assertRaises(validate.ValidationError):
                    validate.validate_baseline(candidate)

        candidate = copy.deepcopy(baseline)
        candidate["runs"][0]["distribution"]["p95"] += 0.001
        with self.assertRaises(validate.ValidationError):
            validate.validate_baseline(candidate)

    def test_only_standard_library_imports_are_used(self) -> None:
        tree = ast.parse(validate.EVIDENCE_PATH.with_name("validate.py").read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        stdlib = set(getattr(sys, "stdlib_module_names", ()))
        self.assertTrue(imported <= stdlib, sorted(imported - stdlib))
        self.assertNotIn("assert", validate.EVIDENCE_PATH.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
