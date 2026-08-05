#!/usr/bin/env python3
"""Regression tests for the offline implementation proof-gate validator.

All mutations are local text.  The tests never contact GitHub, Paper, Hermes,
a proxy, a browser, or a deployment.  The checked-in checklist is the only
fixture, so the tests detect contract drift without aggregate or live data.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Callable, Iterable, List

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_proof_gates.py"
CHECKLIST = ROOT / "docs" / "product" / "implementation-proof-gates.md"
TEMPLATE = ROOT / ".github" / "ISSUE_TEMPLATE" / "roadmap.md"

spec = importlib.util.spec_from_file_location("validate_proof_gates", SCRIPT)
if spec is None or spec.loader is None:
    raise RuntimeError(f"Could not load {SCRIPT}")
validator = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = validator
spec.loader.exec_module(validator)


class ProofGateValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.checklist_bytes = CHECKLIST.read_bytes()
        cls.checklist_text = cls.checklist_bytes.decode("utf-8")

    def result(self, text: str):
        return validator.validate_text(text, path="fixture/implementation-proof-gates.md")

    @staticmethod
    def codes(result) -> set[str]:
        return {error["code"] for error in result["errors"]}

    def assertCode(self, result, code: str) -> None:
        self.assertFalse(result["ok"], result)
        self.assertIn(code, self.codes(result), result)
        matching = [error for error in result["errors"] if error["code"] == code]
        self.assertTrue(matching, result)
        self.assertTrue(all(error["line"] is None or isinstance(error["line"], int) for error in matching), result)

    @staticmethod
    def replace_once(text: str, old: str, new: str) -> str:
        if text.count(old) != 1:
            raise AssertionError(f"Expected one occurrence of {old!r}, got {text.count(old)}")
        return text.replace(old, new, 1)

    @classmethod
    def table_row(cls, text: str, key: str) -> str:
        rows = [
            line
            for line in text.splitlines()
            if line.startswith(f"| `{key}` |")
        ]
        if len(rows) != 1:
            raise AssertionError(f"Expected one row for {key}, got {rows}")
        return rows[0]

    @classmethod
    def replace_gate_cell(cls, text: str, key: str, old: str, new: str) -> str:
        row = cls.table_row(text, key)
        return cls.replace_once(text, row, row.replace(old, new, 1))

    @classmethod
    def section_block(cls, text: str, heading: str) -> tuple[List[str], int, int]:
        lines = text.splitlines(keepends=True)
        starts = [index for index, line in enumerate(lines) if line == f"## {heading}\n"]
        if len(starts) != 1:
            raise AssertionError(f"Expected one section {heading}, got {starts}")
        start = starts[0]
        end = next(
            (index for index in range(start + 1, len(lines)) if lines[index].startswith("## ")),
            len(lines),
        )
        return lines, start, end

    @classmethod
    def remove_section(cls, text: str, heading: str) -> str:
        lines, start, end = cls.section_block(text, heading)
        return "".join(lines[:start] + lines[end:])

    @classmethod
    def duplicate_section(cls, text: str, heading: str) -> str:
        lines, start, end = cls.section_block(text, heading)
        return "".join(lines[:end] + lines[start:end] + lines[end:])

    @classmethod
    def swap_sections(cls, text: str, first: str, second: str) -> str:
        lines, first_start, first_end = cls.section_block(text, first)
        _, second_start, second_end = cls.section_block(text, second)
        first_block = lines[first_start:first_end]
        second_block = lines[second_start:second_end]
        if first_start > second_start:
            raise AssertionError("swap_sections expects first before second")
        return "".join(
            lines[:first_start]
            + second_block
            + lines[first_end:second_start]
            + first_block
            + lines[second_end:]
        )

    @staticmethod
    def line_swap(text: str, first: str, second: str) -> str:
        lines = text.splitlines(keepends=True)
        first_index = lines.index(first)
        second_index = lines.index(second)
        lines[first_index], lines[second_index] = lines[second_index], lines[first_index]
        return "".join(lines)

    @classmethod
    def visible_template_dod(cls) -> tuple[str, ...]:
        visible = False
        values: List[str] = []
        for line in TEMPLATE.read_text(encoding="utf-8").splitlines():
            if line == "## 10. Definition of done":
                visible = True
                continue
            if visible and line.startswith("## "):
                break
            if visible and line.startswith("- [ ] "):
                values.append(line.removeprefix("- [ ] "))
        return tuple(values)

    def test_checked_in_checklist_is_valid(self) -> None:
        result = validator.validate_file(CHECKLIST)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["errors"], [])

    def test_cli_emits_one_strict_json_object(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), str(CHECKLIST)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertEqual(completed.stdout.count("\n"), 1, completed.stdout)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload, {"errors": [], "ok": True, "path": str(CHECKLIST)})

    def test_cli_unknown_argument_is_one_json_object_without_traceback(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--unknown-flag"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stderr, "")
        self.assertEqual(completed.stdout.count("\n"), 1, completed.stdout)
        self.assertNotIn("Traceback", completed.stdout + completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["path"], None)
        self.assertEqual(payload["errors"][0]["code"], "cli-arguments")

    def test_hidden_comments_and_arbitrary_fences_do_not_count(self) -> None:
        hidden = (
            "<!--\n"
            "## 0. Hidden section\n"
            "| `G-99` | SCAFFOLD | decoy | [P0-01](https://github.com/kaygdotorg/hermternal/issues/40) | None | `E-99` | [x] |\n"
            "-->\n"
            "```markdown\n"
            "## 0. Backtick section\n"
            "### Hidden subsection\n"
            "````\n"
            "~~~~yaml\n"
            "| `G-98` | decoy |\n"
            "~~~~~\n"
        )
        mutated = self.replace_once(self.checklist_text, "## 1. Scope and dependency policy\n", hidden + "## 1. Scope and dependency policy\n")
        self.assertTrue(self.result(mutated)["ok"], self.result(mutated))

    def test_hidden_content_can_span_visible_line_fragments(self) -> None:
        hidden = "visible before <!-- hidden\n## 0. Decoy\n--> visible after\n"
        mutated = self.replace_once(self.checklist_text, "## 1. Scope and dependency policy\n", hidden + "## 1. Scope and dependency policy\n")
        self.assertTrue(self.result(mutated)["ok"], self.result(mutated))

    def test_unclosed_comment_and_fence_fail_closed(self) -> None:
        self.assertCode(self.result("<!--\n" + self.checklist_text), "comment-unclosed")
        self.assertCode(self.result("~~~markdown\n" + self.checklist_text), "fence-unclosed")

    def test_gate_missing_duplicate_unknown_and_reordered(self) -> None:
        row = self.table_row(self.checklist_text, "G-04")
        self.assertCode(self.result(self.checklist_text.replace(row + "\n", "", 1)), "gate-missing")
        duplicate = self.checklist_text.replace(row + "\n", row + "\n" + row + "\n", 1)
        self.assertCode(self.result(duplicate), "gate-duplicate")
        unknown = self.checklist_text.replace(row, row.replace("`G-04`", "`G-99`", 1), 1)
        self.assertCode(self.result(unknown), "gate-unknown")
        moved = self.checklist_text.replace(row + "\n", "", 1)
        next_row = self.table_row(moved, "G-05")
        moved = moved.replace(next_row + "\n", next_row + "\n" + row + "\n", 1)
        self.assertCode(self.result(moved), "gate-reordered")

    def test_evidence_missing_duplicate_unknown_and_reordered(self) -> None:
        row = self.table_row(self.checklist_text, "E-04")
        self.assertCode(self.result(self.checklist_text.replace(row + "\n", "", 1)), "evidence-missing")
        duplicate = self.checklist_text.replace(row + "\n", row + "\n" + row + "\n", 1)
        self.assertCode(self.result(duplicate), "evidence-duplicate")
        unknown = self.checklist_text.replace(row, row.replace("`E-04`", "`E-99`", 1), 1)
        self.assertCode(self.result(unknown), "evidence-unknown")
        moved = self.checklist_text.replace(row + "\n", "", 1)
        next_row = self.table_row(moved, "E-05")
        moved = moved.replace(next_row + "\n", next_row + "\n" + row + "\n", 1)
        self.assertCode(self.result(moved), "evidence-reordered")

    def test_issue_key_and_link_validation(self) -> None:
        wrong_number = self.replace_gate_cell(
            self.checklist_text,
            "G-01",
            "issues/40",
            "issues/41",
        )
        self.assertCode(self.result(wrong_number), "issue-link-mismatch")
        wrong_domain = self.replace_gate_cell(
            self.checklist_text,
            "G-01",
            "https://github.com/kaygdotorg/hermternal/issues/40",
            "https://github.com/example/not-hermternal/issues/40",
        )
        self.assertCode(self.result(wrong_domain), "issue-link-domain")
        unknown_key = self.replace_gate_cell(
            self.checklist_text,
            "G-01",
            "[P0-01](https://github.com/kaygdotorg/hermternal/issues/40)",
            "[P0-99](https://github.com/kaygdotorg/hermternal/issues/40)",
        )
        self.assertCode(self.result(unknown_key), "issue-key-unknown")

    def test_dependency_direction_and_stale_m0_blockers_fail(self) -> None:
        downstream_owner = self.replace_gate_cell(
            self.checklist_text,
            "G-04",
            "[P0-06](https://github.com/kaygdotorg/hermternal/issues/46)",
            "[W-01](https://github.com/kaygdotorg/hermternal/issues/114)",
        )
        result = self.result(downstream_owner)
        self.assertCode(result, "stale-blocker")
        self.assertCode(result, "dependency-direction")

        downstream_dependency = self.replace_gate_cell(
            self.checklist_text,
            "G-04",
            "[P0-05](https://github.com/kaygdotorg/hermternal/issues/45)",
            "[W-01](https://github.com/kaygdotorg/hermternal/issues/114)",
        )
        result = self.result(downstream_dependency)
        self.assertCode(result, "stale-blocker")
        self.assertCode(result, "dependency-direction")

    def test_gate_status_checked_waived_and_unknown_fail(self) -> None:
        checked = self.replace_gate_cell(self.checklist_text, "G-01", "[ ]", "[x]")
        self.assertCode(self.result(checked), "gate-checked")
        waived = self.replace_gate_cell(self.checklist_text, "G-01", "[ ]", "waived")
        self.assertCode(self.result(waived), "gate-waived")
        unknown = self.replace_gate_cell(self.checklist_text, "G-01", "[ ]", "pending")
        self.assertCode(self.result(unknown), "gate-status")

    def test_required_fields_duplicate_reordered_and_unknown_fail(self) -> None:
        old = "- **Metric:** Artifact bytes and local validator duration only; product latency, memory, bundle, render, and startup budgets are not measured here.\n"
        missing = self.replace_once(self.checklist_text, old, "")
        self.assertCode(self.result(missing), "field-missing")
        duplicate = self.replace_once(self.checklist_text, old, old + old)
        self.assertCode(self.result(duplicate), "field-duplicate")
        unknown = self.replace_once(self.checklist_text, old, "- **Unknown field:** no\n" + old)
        self.assertCode(self.result(unknown), "field-unknown")
        reordered = self.checklist_text.replace(
            "- **Deterministic fixture:** The checked-in `implementation-proof-gates.md` fixture and the standard-library validator's valid JSON result.\n- **Metric:** Artifact bytes and local validator duration only; product latency, memory, bundle, render, and startup budgets are not measured here.\n",
            "- **Metric:** Artifact bytes and local validator duration only; product latency, memory, bundle, render, and startup budgets are not measured here.\n- **Deterministic fixture:** The checked-in `implementation-proof-gates.md` fixture and the standard-library validator's valid JSON result.\n",
            1,
        )
        self.assertCode(self.result(reordered), "field-reordered")

    def test_na_requires_a_reason(self) -> None:
        bad = self.checklist_text.replace("N/A — this is a planning/tooling artifact", "N/A", 1)
        self.assertCode(self.result(bad), "na-rationale")
        good = self.checklist_text.replace("N/A — this is a planning/tooling artifact", "N/A: this is a planning/tooling artifact", 1)
        self.assertNotIn("na-rationale", self.codes(self.result(good)))

    def test_no_invented_performance_threshold(self) -> None:
        original = "- **Metric:** Artifact bytes and local validator duration only; product latency, memory, bundle, render, and startup budgets are not measured here."
        variants = (
            "p95 target is 50 ms.",
            "latency budget: 50 ms.",
            "performance SLO < 200 ms.",
            "startup limit 2 s.",
            "response time should be within 500 ms.",
            "latency must be under 50 ms.",
        )
        for variant in variants:
            with self.subTest(variant=variant):
                mutated = self.checklist_text.replace(
                    original,
                    f"- **Metric:** {variant}",
                    1,
                )
                self.assertCode(self.result(mutated), "invented-performance-threshold")
                self.assertCode(self.result(mutated), "threshold-statement")

    def test_measured_evidence_rejects_embedded_target_but_accepts_observation(self) -> None:
        original = "- **Validator-duration evidence:** Same checkout; ten samples `62.864, 64.096, 63.412, 63.918, 62.889, 63.695, 62.094, 62.994, 63.942, 63.373` ms; min `62.094` ms, mean `63.328` ms, median `63.393` ms, p95 `64.027` ms, and max `64.096` ms; p99 is not meaningful for ten samples and no threshold is inferred."
        observation = self.checklist_text.replace(
            original,
            "- **Validator-duration evidence:** Same checkout; ten samples; min 56 ms, mean 57 ms, median 57 ms, p95 was 58.664 ms, and max 58.807 ms; no threshold is inferred.",
            1,
        )
        self.assertTrue(self.result(observation)["ok"], self.result(observation))
        target = self.checklist_text.replace(
            original,
            "- **Validator-duration evidence:** Same checkout; ten samples; min 56 ms, mean 57 ms, median 57 ms, p95 target is 50 ms, and max 58.807 ms; no threshold is inferred.",
            1,
        )
        self.assertCode(self.result(target), "invented-performance-threshold")
        self.assertCode(self.result(target), "threshold-statement")

    def test_live_or_production_success_claim_fails_by_clause(self) -> None:
        review_line = "- **Review result:** Review records the exact command, exit status, output artifact, and remaining limitation; a failed or unrun command is not reported as passed."
        for claim in (
            "No live claim is allowed; production deployment passed.",
            "Production release shipped.",
            "Live integration works.",
            "Live integration remains blocked, but production deployment is complete.",
            "Live integration remains blocked, however production deployment is complete.",
            "Live integration remains blocked yet production deployment is complete.",
            "Live integration remains blocked and production deployment is complete.",
        ):
            with self.subTest(claim=claim):
                mutated = self.checklist_text.replace(
                    review_line,
                    f"- **Review result:** {claim}",
                    1,
                )
                self.assertCode(self.result(mutated), "live-production-claim")
        for boundary in (
            "No live or production success is asserted; the mock boundary remains blocked.",
            "Live integration remains blocked, but production deployment is not complete.",
            "No live service is contacted and production deployment is not complete.",
        ):
            negative = self.checklist_text.replace(
                review_line,
                f"- **Review result:** {boundary}",
                1,
            )
            with self.subTest(boundary=boundary):
                self.assertNotIn("live-production-claim", self.codes(self.result(negative)))

    def test_preservation_evidence_requires_concrete_surface_and_reason(self) -> None:
        original = "- **Preservation evidence:** The checklist and validator preserve keyboard/focus, semantic-name, screen-reader/VoiceOver, Switch Control, zoom/Dynamic Type, contrast, reduced-motion/transparency, and touch-target behavior requirements because they only read bytes and emit diagnostics; missing evidence stays blocked."
        for weak_value in (
            "no.",
            "behavior remains preserved because evidence is required.",
            "accessibility requirement remains preserved because the requirement remains required.",
            "preserves keyboard behavior because behavior remains required.",
            "preserves keyboard behavior because evidence is required.",
        ):
            weak = self.checklist_text.replace(
                original,
                f"- **Preservation evidence:** {weak_value}",
                1,
            )
            with self.subTest(weak_value=weak_value):
                self.assertCode(self.result(weak), "preservation-evidence")

    def test_template_definition_of_done_is_exact_and_each_phrase_is_guarded(self) -> None:
        visible_template = self.visible_template_dod()
        self.assertEqual(visible_template, validator.TEMPLATE_DOD)
        self.assertEqual(len(visible_template), 12)
        for index, expected in enumerate(visible_template, start=1):
            key = f"D-{index:02d}"
            row = self.table_row(self.checklist_text, key)
            mutated = self.replace_once(
                self.checklist_text,
                row,
                row.replace(expected, expected + " [mutated]", 1),
            )
            with self.subTest(key=key):
                self.assertCode(self.result(mutated), "parity-dod-value")

    def test_parity_tables_reject_missing_duplicate_unknown_and_reorder(self) -> None:
        row = "| `F-01` | `Owner` | One responsible owner remains named. |\n"
        self.assertCode(self.result(self.checklist_text.replace(row, "", 1)), "parity-field-missing")
        self.assertCode(self.result(self.checklist_text.replace(row, row + row, 1)), "parity-field-duplicate")
        self.assertCode(self.result(self.checklist_text.replace(row, row.replace("F-01", "F-99", 1), 1)), "parity-field-unknown")
        reordered = self.checklist_text.replace(
            "| `F-01` | `Owner` | One responsible owner remains named. |\n| `F-02` | `Assigned subagent` | One assigned implementation unit remains named. |\n",
            "| `F-02` | `Assigned subagent` | One assigned implementation unit remains named. |\n| `F-01` | `Owner` | One responsible owner remains named. |\n",
            1,
        )
        self.assertCode(self.result(reordered), "parity-field-reordered")

    def test_definition_of_done_parity_rejects_checked_item(self) -> None:
        mutated = self.checklist_text.replace(
            "| `D-01` | The one operation is complete. |",
            "| `D-01` | Changed item. |",
            1,
        )
        self.assertCode(self.result(mutated), "parity-dod-value")
        checklist_dod = self.checklist_text.replace(
            "- [ ] The M0 prerequisite set contains only",
            "- [x] The M0 prerequisite set contains only",
            1,
        )
        self.assertCode(self.result(checklist_dod), "checklist-dod-checked")

    def test_section_and_subsection_structure_is_strict(self) -> None:
        self.assertCode(self.result(self.remove_section(self.checklist_text, "6. Atomic issue-template parity")), "section-missing")
        self.assertCode(self.result(self.duplicate_section(self.checklist_text, "6. Atomic issue-template parity")), "section-duplicate")
        self.assertCode(self.result(self.swap_sections(self.checklist_text, "5. No-network and privacy", "6. Atomic issue-template parity")), "section-reordered")
        unknown = self.checklist_text.replace("## 9. Reproduction\n", "## 9. Unknown\n", 1)
        self.assertCode(self.result(unknown), "section-unknown")
        missing_subsection = self.checklist_text.replace("### Offline rule\n", "", 1)
        self.assertCode(self.result(missing_subsection), "subsection-missing")
        duplicate_subsection = self.checklist_text.replace("### Offline rule\n", "### Offline rule\n### Offline rule\n", 1)
        self.assertCode(self.result(duplicate_subsection), "subsection-duplicate")
        unknown_subsection = self.checklist_text.replace("### Offline rule\n", "### Unknown rule\n", 1)
        self.assertCode(self.result(unknown_subsection), "subsection-unknown")

    def test_line_endings_and_invalid_utf8_fail_closed(self) -> None:
        crlf = self.checklist_text.replace("\n", "\r\n")
        self.assertTrue(validator.validate_text(crlf)["ok"], validator.validate_text(crlf))
        mixed = self.checklist_text.replace("\n", "\r\n", 10)
        self.assertCode(self.result(mixed), "mixed-line-endings")
        lone_cr = self.checklist_text.replace("\n", "\r")
        self.assertCode(self.result(lone_cr), "invalid-line-ending")
        invalid = self.checklist_bytes[:100] + b"\xff" + self.checklist_bytes[100:]
        result = validator.validate_bytes(invalid, path="fixture/checklist.md")
        self.assertCode(result, "invalid-utf8")
        self.assertEqual(result["errors"][0]["line"], 4)

    def test_read_error_is_structured(self) -> None:
        result = validator.validate_file(ROOT / "does-not-exist-proof-gates.md")
        self.assertCode(result, "read-error")
        self.assertEqual(result["path"], str(ROOT / "does-not-exist-proof-gates.md"))

    def test_bool_and_wrong_type_inputs_are_rejected_without_traceback(self) -> None:
        for result in (
            validator.validate_bytes(True),
            validator.validate_bytes("text"),
            validator.validate_text(True),
            validator.validate_text(b"text"),
            validator.validate_file(True),
            validator.validate_file(1),
        ):
            self.assertCode(result, "input-type")
        self.assertEqual(validator.main("not-a-sequence"), 2)

    def test_main_defensive_failure_is_one_json_object(self) -> None:
        class BrokenPath:
            def __fspath__(self):
                raise RuntimeError("synthetic path failure")

        result = validator.validate_file(BrokenPath())
        self.assertCode(result, "input-type")

    def test_no_live_network_symbols_are_needed(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for token in ("urllib", "requests", "socket", "http.client"):
            self.assertNotIn(token, source)

    def test_fixture_is_utf8_and_has_final_newline(self) -> None:
        self.assertTrue(self.checklist_bytes.endswith(b"\n"))
        self.checklist_bytes.decode("utf-8")


if __name__ == "__main__":
    unittest.main()
