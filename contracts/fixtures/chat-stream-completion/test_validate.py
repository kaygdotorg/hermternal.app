#!/usr/bin/env python3
"""Regression tests for the synthetic C-08 stream/completion contract."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import validate  # noqa: E402


class ChatStreamCompletionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = validate._load_json(validate.CASES_PATH, "cases")
        cls.audit = validate._load_json(validate.SOURCE_AUDIT_PATH, "source audit")
        cls.baseline = validate._load_json(validate.BASELINE_PATH, "baseline")
        validate.validate_all(cls.document, cls.audit, cls.baseline)
        cls.cases = {case["id"]: case for case in cls.document["cases"]}

    def run_cli(self, optimized: bool = False, *extra: str) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend([str(ROOT / "validate.py"), *extra])
        return subprocess.run(command, check=False, capture_output=True, text=True)

    def evaluate_subprocess(self, case_id: str, optimized: bool) -> dict[str, object]:
        script = """
import importlib.util, json, sys
from pathlib import Path
root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('fixture_validate', root / 'validate.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
document = module._load_json(root / 'cases.json', 'cases')
case = next(item for item in document['cases'] if item['id'] == sys.argv[2])
print(json.dumps(module.evaluate_case(case), sort_keys=True))
"""
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend(["-c", script, str(ROOT), case_id])
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        return json.loads(result.stdout)

    def evaluate_case_subprocess(self, case: dict[str, object], optimized: bool) -> dict[str, object]:
        script = """
import importlib.util, json, sys
from pathlib import Path
root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('fixture_validate', root / 'validate.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
case = json.loads(sys.argv[2])
print(json.dumps(module.evaluate_case(case), sort_keys=True))
"""
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend(["-c", script, str(ROOT), json.dumps(case, separators=(",", ":"))])
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        return json.loads(result.stdout)

    def validate_document_subprocess(self, document: dict[str, object], optimized: bool) -> bool:
        script = """
import importlib.util, json, sys
from pathlib import Path
root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('fixture_validate', root / 'validate.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
document = json.loads(sys.argv[2])
try:
    module.validate_document(document)
except module.ContractError:
    print('rejected')
else:
    print('accepted')
"""
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.extend(["-c", script, str(ROOT), json.dumps(document, separators=(",", ":"))])
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout.strip(), "rejected")
        return True

    def test_checked_in_evidence_validates(self) -> None:
        case_count, artifact_bytes = validate.validate_all(self.document, self.audit, self.baseline)
        self.assertEqual(case_count, 22)
        self.assertGreater(artifact_bytes, 0)
        self.assertEqual(self.baseline["repetitions"], 30)
        self.assertIsNone(self.baseline["threshold"])
        self.assertEqual(tuple(self.cases), validate.EXPECTED_CASE_IDS)

    def test_normal_and_optimized_cli_are_identical(self) -> None:
        normal = self.run_cli()
        optimized = self.run_cli(True)
        self.assertEqual(normal.returncode, 0, normal.stdout)
        self.assertEqual(optimized.returncode, 0, optimized.stdout)
        self.assertEqual(normal.stdout, optimized.stdout)
        self.assertEqual(normal.stderr, "")
        self.assertEqual(optimized.stderr, "")
        self.assertIn("cases=22", normal.stdout)

    def test_every_case_matches_in_normal_and_optimized_subprocesses(self) -> None:
        for case_id, case in self.cases.items():
            for optimized in (False, True):
                with self.subTest(case_id=case_id, optimized=optimized):
                    self.assertEqual(self.evaluate_subprocess(case_id, optimized), case["expected"])

    def test_success_tool_error_and_interruption_ordering(self) -> None:
        complete = self.cases["tool-lifecycle-complete"]["expected"]
        self.assertEqual(complete["trace"], ["idle", "streaming", "tool_running", "streaming", "completed"])
        self.assertEqual(complete["completed_tools"], ["tool-marker-001"])
        self.assertEqual(complete["completion_status"], "complete")

        recoverable = self.cases["terminal-recoverable-error"]["expected"]
        self.assertEqual(recoverable["final_state"], "failed")
        self.assertTrue(recoverable["recoverable"])
        self.assertEqual(recoverable["decision"], "recoverable_error")

        interrupted = self.cases["interrupt-abandons-open-tool"]["expected"]
        self.assertEqual(interrupted["final_state"], "interrupted")
        self.assertIsNone(interrupted["open_tool"])
        self.assertEqual(interrupted["completed_tools"], [])

        rejected = self.cases["interrupt-rejected-resumes"]["expected"]
        self.assertEqual(rejected["trace"], ["idle", "streaming", "interrupting", "streaming", "completed"])

    def test_fail_closed_cases_discard_retained_display_state(self) -> None:
        negative_ids = validate.EXPECTED_CASE_IDS[11:]
        for case_id in negative_ids:
            with self.subTest(case_id=case_id):
                expected = self.cases[case_id]["expected"]
                self.assertEqual(expected["final_state"], "failed")
                self.assertIsNotNone(expected["contract_error"])
                self.assertEqual(expected["segments"], [])
                self.assertEqual(expected["completed_tools"], [])

    def test_missing_interrupt_result_and_progress_while_pending_fail_closed(self) -> None:
        base = copy.deepcopy(self.cases["interrupt-after-delta"])
        base["events"] = base["events"][:-1]
        self.assertEqual(validate.evaluate_case(base)["contract_error"], "interrupt_result_missing")

        pending = copy.deepcopy(base)
        pending["events"].append({
            "kind": "message.delta", "session_ref": pending["session_ref"],
            "request_ref": pending["request_ref"], "turn_ref": pending["turn_ref"],
            "ordinal": 2, "content_ref": "content-marker-late",
        })
        self.assertEqual(validate.evaluate_case(pending)["contract_error"], "event_while_interrupt_pending")

    def test_every_ordinal_frame_is_rejected_while_interrupt_pending_in_both_modes(self) -> None:
        base = copy.deepcopy(self.cases["interrupt-after-delta"])
        base["events"] = base["events"][:-1]
        common = {
            "session_ref": base["session_ref"],
            "request_ref": base["request_ref"],
            "turn_ref": base["turn_ref"],
            "ordinal": 2,
        }
        frames = [
            {**common, "kind": "message.delta", "content_ref": "content-marker-late"},
            {**common, "kind": "reasoning.delta", "content_ref": "reasoning-marker-late"},
            {**common, "kind": "thinking.delta", "content_ref": "thinking-marker-late"},
            {**common, "kind": "tool.start", "tool_ref": "tool-marker-late"},
            {**common, "kind": "tool.complete", "tool_ref": "tool-marker-late"},
            {**common, "kind": "message.complete", "content_ref": "content-marker-final", "status": "complete"},
            {**common, "kind": "error", "error_code": "error-marker-late", "recoverable": False},
            {**common, "kind": "unknown.additive", "name": "telemetry-marker-late"},
            {**common, "kind": "unknown.interactive", "name": "secret.request-late"},
        ]
        for frame in frames:
            pending = copy.deepcopy(base)
            pending["events"].append(frame)
            for optimized in (False, True):
                with self.subTest(kind=frame["kind"], optimized=optimized):
                    result = self.evaluate_case_subprocess(pending, optimized)
                    self.assertEqual(result["contract_error"], "event_while_interrupt_pending")
                    self.assertEqual(result["segments"], [])
                    self.assertEqual(result["completed_tools"], [])

    def test_message_complete_schema_is_strictly_status_dependent_in_both_modes(self) -> None:
        mutations = []
        complete_with_recoverable = copy.deepcopy(self.document)
        complete_with_recoverable["cases"][1]["events"][1]["recoverable"] = False
        mutations.append(complete_with_recoverable)

        error_without_recoverable = copy.deepcopy(self.document)
        error_without_recoverable["cases"][5]["events"][1].pop("recoverable")
        mutations.append(error_without_recoverable)

        unsupported_status = copy.deepcopy(self.document)
        unsupported_status["cases"][1]["events"][1]["status"] = "pending"
        mutations.append(unsupported_status)

        for index, document in enumerate(mutations):
            for optimized in (False, True):
                with self.subTest(mutation=index, optimized=optimized):
                    self.validate_document_subprocess(document, optimized)

    def test_document_rejects_shape_type_order_and_inventory_mutations(self) -> None:
        mutations = []
        extra = copy.deepcopy(self.document)
        extra["unexpected"] = "marker"
        mutations.append(extra)
        wrong_type = copy.deepcopy(self.document)
        wrong_type["cases"][1]["events"][0]["ordinal"] = True
        mutations.append(wrong_type)
        duplicate = copy.deepcopy(self.document)
        duplicate["cases"][1]["id"] = duplicate["cases"][0]["id"]
        mutations.append(duplicate)
        reordered = copy.deepcopy(self.document)
        reordered["cases"][0] = {key: reordered["cases"][0][key] for key in reversed(reordered["cases"][0])}
        mutations.append(reordered)
        for document in mutations:
            with self.subTest():
                with self.assertRaises(validate.ContractError):
                    validate.validate_document(document)

    def test_source_audit_identities_are_closed(self) -> None:
        for field, replacement in (("sha256", "0" * 64), ("git_blob_sha", "0" * 40), ("path", "other.py")):
            audit = copy.deepcopy(self.audit)
            audit["citations"][0][field] = replacement
            with self.subTest(field=field):
                with self.assertRaises(validate.ContractError):
                    validate.validate_source_audit(audit)

    def test_strict_json_rejects_duplicate_numbers_utf8_and_bounds(self) -> None:
        mutations: dict[str, bytes] = {
            "duplicate": b'{"value":1,"value":2}',
            "nan": b'{"value":NaN}',
            "infinity": b'{"value":Infinity}',
            "overflow": b'{"value":1e9999}',
            "underflow": b'{"value":1e-9999}',
            "negative-underflow": b'{"value":-1e-9999}',
            "invalid-utf8": b'{"value":"\xff"}',
            "huge-int": ('{"value":1' + ('0' * validate.MAX_INTEGER_DIGITS) + '}').encode(),
            "deep": (("[" * (validate.MAX_JSON_DEPTH + 2)) + "0" + ("]" * (validate.MAX_JSON_DEPTH + 2))).encode(),
            "wide": json.dumps({str(index): index for index in range(validate.MAX_OBJECT_KEYS + 1)}).encode(),
            "array": json.dumps(list(range(validate.MAX_ARRAY_LENGTH + 1))).encode(),
            "string": json.dumps("x" * (validate.MAX_STRING_LENGTH + 1)).encode(),
        }
        with tempfile.TemporaryDirectory() as directory:
            for name, data in mutations.items():
                path = Path(directory) / name
                path.write_bytes(data)
                with self.subTest(name=name):
                    with self.assertRaises(validate.ContractError):
                        validate._load_json(path, "synthetic input")

    def test_bounded_reader_rejects_oversize_symlink_and_nonregular_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oversized = root / "oversized.json"
            oversized.write_bytes(b" " * (validate.MAX_JSON_BYTES + 1))
            with self.assertRaises(validate.ContractError):
                validate._read_bounded_regular(oversized, "oversized")
            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            link = root / "link.json"
            link.symlink_to(target)
            with self.assertRaises(validate.ContractError):
                validate._read_bounded_regular(link, "link")
            with self.assertRaises(validate.ContractError):
                validate._read_bounded_regular(root, "directory")

    def test_redaction_rejects_live_looking_values_in_both_modes(self) -> None:
        values = ["Bearer marker-token", "password=marker", "https://internal.example", "alice@example.com", "10.0.0.1", "ghp_abcdefghijk"]
        script = """
import importlib.util, json, sys
from pathlib import Path
root = Path(sys.argv[1]); values = json.loads(sys.argv[2])
spec = importlib.util.spec_from_file_location('fixture_validate', root / 'validate.py')
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
out=[]
for value in values:
    try: module._validate_redaction({'value': value})
    except module.ContractError: out.append(False)
    else: out.append(True)
print(json.dumps(out))
"""
        for optimized in (False, True):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.extend(["-c", script, str(ROOT), json.dumps(values)])
            result = subprocess.run(command, check=False, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), [False] * len(values))

    def test_baseline_rejects_timing_command_environment_and_artifact_tampering(self) -> None:
        mutations = []
        for mode in ("normal", "optimized"):
            forged = copy.deepcopy(self.baseline)
            forged[mode]["samples_ms"] = [1.0] * validate.BASELINE_REPETITIONS
            forged[mode]["distribution"] = validate._dist(forged[mode]["samples_ms"])
            mutations.append(forged)
            forged = copy.deepcopy(self.baseline)
            forged[mode]["command"] = "python3 other.py"
            mutations.append(forged)
        environment = copy.deepcopy(self.baseline)
        environment["environment"]["python"] = "3.13.0"
        mutations.append(environment)
        artifact = copy.deepcopy(self.baseline)
        artifact["artifact_files"][0]["sha256"] = "0" * 64
        mutations.append(artifact)
        for baseline in mutations:
            with self.subTest():
                with self.assertRaises(validate.ContractError):
                    validate._validate_baseline(baseline)

    def test_cli_failure_is_one_fixed_redacted_line_in_both_modes(self) -> None:
        marker = "synthetic-sensitive-marker"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / marker
            path.write_text('{"schema":"' + marker + '"}', encoding="utf-8")
            for optimized in (False, True):
                result = self.run_cli(optimized, "--cases", str(path))
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr, "")
                self.assertEqual(len(result.stdout.splitlines()), 1)
                self.assertNotIn(marker, result.stdout)
                self.assertEqual(json.loads(result.stdout), {"error": {"code": "contract", "message": "chat stream completion fixture rejected"}})

    def test_compile_succeeds_with_normal_and_optimized_interpreters(self) -> None:
        for optimized in (False, True):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.extend(["-m", "py_compile", str(ROOT / "validate.py"), str(ROOT / "test_validate.py")])
            result = subprocess.run(command, check=False, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
