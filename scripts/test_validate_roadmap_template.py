#!/usr/bin/env python3
"""Unit tests for the offline roadmap-template validator.

The mutation families intentionally exercise the checked-in template as a
fixture. They do not contact GitHub, Paper, Hermes, or any other service.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Iterable, List

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_roadmap_template.py"
TEMPLATE = ROOT / ".github" / "ISSUE_TEMPLATE" / "roadmap.md"


spec = importlib.util.spec_from_file_location("validate_roadmap_template", SCRIPT)
if spec is None or spec.loader is None:
    raise RuntimeError(f"Could not load {SCRIPT}")
validator = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = validator
spec.loader.exec_module(validator)


class RoadmapTemplateValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.template_bytes = TEMPLATE.read_bytes()
        cls.template_text = cls.template_bytes.decode("utf-8")

    def result(self, text: str):
        return validator.validate_bytes(text.encode("utf-8"), path="fixture/roadmap.md")

    def codes(self, result) -> set[str]:
        return {error["code"] for error in result["errors"]}

    def assertCode(self, result, code: str) -> None:
        self.assertFalse(result["ok"], result)
        self.assertIn(code, self.codes(result), result)
        matching = [error for error in result["errors"] if error["code"] == code]
        self.assertTrue(matching)
        self.assertTrue(all(isinstance(error["line"], int) for error in matching), result)

    @staticmethod
    def replace_once(text: str, old: str, new: str) -> str:
        if text.count(old) != 1:
            raise AssertionError(f"Expected one occurrence of {old!r}, got {text.count(old)}")
        return text.replace(old, new, 1)

    @staticmethod
    def section_block(text: str, title: str) -> tuple[List[str], int, int]:
        lines = text.splitlines(keepends=True)
        heading = f"## {title}\n"
        starts = [index for index, line in enumerate(lines) if line == heading]
        if len(starts) != 1:
            raise AssertionError(f"Expected one section heading {heading!r}, got {starts}")
        start = starts[0]
        end = next(
            (index for index in range(start + 1, len(lines)) if lines[index].startswith("## ")),
            len(lines),
        )
        return lines, start, end

    @classmethod
    def remove_section(cls, text: str, title: str) -> str:
        lines, start, end = cls.section_block(text, title)
        return "".join(lines[:start] + lines[end:])

    @classmethod
    def duplicate_section(cls, text: str, title: str) -> str:
        lines, start, end = cls.section_block(text, title)
        block = lines[start:end]
        return "".join(lines[:end] + block + lines[end:])

    @classmethod
    def swap_sections(cls, text: str, first: str, second: str) -> str:
        lines, first_start, first_end = cls.section_block(text, first)
        second_start = next(
            index for index in range(first_end, len(lines)) if lines[index] == f"## {second}\n"
        )
        second_end = next(
            (index for index in range(second_start + 1, len(lines)) if lines[index].startswith("## ")),
            len(lines),
        )
        first_block = lines[first_start:first_end]
        second_block = lines[second_start:second_end]
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

    def test_real_template_is_valid(self) -> None:
        result = validator.validate_file(TEMPLATE)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["errors"], [])

    def test_cli_emits_structured_json(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), str(TEMPLATE)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["ok"], True)
        self.assertEqual(payload["errors"], [])

    def test_missing_file_is_structured(self) -> None:
        result = validator.validate_file(ROOT / "does-not-exist.md")
        self.assertCode(result, "read-error")

    # Mutation family 1: missing exact front matter.
    def test_mutation_front_matter_missing(self) -> None:
        mutated = self.template_text.replace("---\nname:", "name:", 1)
        self.assertCode(self.result(mutated), "front-matter-missing")

    # Mutation family 2: duplicate front-matter field or block.
    def test_mutation_front_matter_duplicate(self) -> None:
        mutated = self.replace_once(
            self.template_text,
            "name: Hermternal roadmap operation\n",
            "name: Hermternal roadmap operation\nname: Hermternal roadmap operation\n",
        )
        self.assertCode(self.result(mutated), "front-matter-duplicate")

    # Mutation family 3: reordered front-matter fields.
    def test_mutation_front_matter_reordered(self) -> None:
        mutated = self.replace_once(
            self.template_text,
            "name: Hermternal roadmap operation\nabout: Plan one independently verifiable v0.0.1 operation\n",
            "about: Plan one independently verifiable v0.0.1 operation\nname: Hermternal roadmap operation\n",
        )
        self.assertCode(self.result(mutated), "front-matter-reordered")

    # Mutation family 4: unknown front-matter field.
    def test_mutation_front_matter_unknown(self) -> None:
        mutated = self.replace_once(self.template_text, "labels: []\n", "draft: false\nlabels: []\n")
        self.assertCode(self.result(mutated), "front-matter-unknown")

    # Mutation family 5: malformed front-matter syntax.
    def test_mutation_front_matter_malformed(self) -> None:
        mutated = self.replace_once(self.template_text, "labels: []\n", "labels []\n")
        self.assertCode(self.result(mutated), "front-matter-malformed")

    # Mutation family 6: missing, duplicate, reordered, and unknown H2 sections.
    def test_mutation_sections(self) -> None:
        self.assertCode(self.result(self.remove_section(self.template_text, "6. Accessibility")), "section-missing")
        self.assertCode(self.result(self.duplicate_section(self.template_text, "6. Accessibility")), "section-duplicate")
        reordered = self.swap_sections(self.template_text, "5. Contract and tests", "6. Accessibility")
        self.assertCode(self.result(reordered), "section-reordered")
        unknown = self.replace_once(self.template_text, "## 6. Accessibility\n", "## 6. Unknown\n")
        self.assertCode(self.result(unknown), "section-unknown")

    # Mutation family 7: missing, duplicate, reordered, and unknown required slots.
    def test_mutation_subsections_and_fields(self) -> None:
        missing_subsection = self.replace_once(self.template_text, "### Hard blockers\n", "")
        self.assertCode(self.result(missing_subsection), "subsection-missing")
        duplicate_subsection = self.replace_once(
            self.template_text,
            "### Hard blockers\n",
            "### Hard blockers\n### Hard blockers\n",
        )
        self.assertCode(self.result(duplicate_subsection), "subsection-duplicate")
        reordered_subsection = self.line_swap(
            self.template_text, "### Hard blockers\n", "### Soft sequence\n"
        )
        self.assertCode(self.result(reordered_subsection), "subsection-reordered")
        unknown_subsection = self.replace_once(
            self.template_text, "### Hard blockers\n", "### Unknown\n"
        )
        self.assertCode(self.result(unknown_subsection), "subsection-unknown")

        missing_field = self.replace_once(
            self.template_text,
            "- Paper file: https://app.paper.design/file/01KZ6BB66KCWR2C4J2TSWQGDM7/1-0\n",
            "",
        )
        self.assertCode(self.result(missing_field), "field-missing")
        duplicate_field = self.replace_once(
            self.template_text,
            "- Owner: Unassigned until implementation starts.\n",
            "- Owner: Unassigned until implementation starts.\n- Owner: duplicate\n",
        )
        self.assertCode(self.result(duplicate_field), "field-duplicate")
        reordered_field = self.line_swap(
            self.template_text, "- Artboards:\n", "- Static states:\n"
        )
        self.assertCode(self.result(reordered_field), "field-reordered")
        unknown_field = self.replace_once(
            self.template_text,
            "- Static states:\n",
            "- Unknown: nope\n- Static states:\n",
        )
        self.assertCode(self.result(unknown_field), "field-unknown")

    # Mutation family 8: malformed required field syntax.
    def test_mutation_required_field_malformed(self) -> None:
        mutated = self.replace_once(self.template_text, "- Static states:\n", "- Static states\n")
        self.assertCode(self.result(mutated), "field-malformed")

    # Mutation family 9: missing, duplicate, wrong-language, and unclosed fence.
    def test_mutation_command_fence(self) -> None:
        wrong_language = self.replace_once(self.template_text, "```text\n", "```bash\n")
        self.assertCode(self.result(wrong_language), "command-fence-malformed")
        unclosed = self.replace_once(self.template_text, "```\n\n## 9. Evidence", "\n\n## 9. Evidence")
        self.assertCode(self.result(unclosed), "command-fence-unclosed")
        missing = self.replace_once(self.template_text, "```text\n", "")
        self.assertCode(self.result(missing), "command-fence-missing")
        duplicate = self.replace_once(
            self.template_text,
            "```text\n# Add exact commands and expected artifacts.\n```\n",
            "```text\n# Add exact commands and expected artifacts.\n```\n```text\n# Add exact commands and expected artifacts.\n```\n",
        )
        self.assertCode(self.result(duplicate), "command-fence-duplicate")

    # Mutation family 10: missing definition-of-done item.
    def test_mutation_dod_missing(self) -> None:
        mutated = self.replace_once(self.template_text, "- [ ] The one operation is complete.\n", "")
        self.assertCode(self.result(mutated), "dod-missing")

    # Mutation family 11: duplicate definition-of-done item.
    def test_mutation_dod_duplicate(self) -> None:
        mutated = self.replace_once(
            self.template_text,
            "- [ ] The one operation is complete.\n",
            "- [ ] The one operation is complete.\n- [ ] The one operation is complete.\n",
        )
        self.assertCode(self.result(mutated), "dod-duplicate")

    # Mutation family 12: reordered definition-of-done items.
    def test_mutation_dod_reordered(self) -> None:
        mutated = self.replace_once(
            self.template_text,
            "- [ ] The one operation is complete.\n- [ ] Required normal and failure states pass.\n",
            "- [ ] Required normal and failure states pass.\n- [ ] The one operation is complete.\n",
        )
        self.assertCode(self.result(mutated), "dod-reordered")

    # Mutation family 13: unknown, checked, and malformed DoD entries.
    def test_mutation_dod_unknown_checked_malformed(self) -> None:
        unknown = self.replace_once(
            self.template_text,
            "- [ ] The one operation is complete.\n",
            "- [ ] Unknown item.\n",
        )
        self.assertCode(self.result(unknown), "dod-unknown")
        checked = self.replace_once(
            self.template_text,
            "- [ ] The one operation is complete.\n",
            "- [x] The one operation is complete.\n",
        )
        self.assertCode(self.result(checked), "dod-checked")
        malformed = self.replace_once(
            self.template_text,
            "- [ ] The one operation is complete.\n",
            "- [] The one operation is complete.\n",
        )
        self.assertCode(self.result(malformed), "dod-malformed")

    # Mutation family 14: CRLF, mixed/lone-CR endings, and invalid UTF-8.
    def test_mutation_line_endings_and_invalid_utf8(self) -> None:
        crlf = self.template_text.replace("\n", "\r\n")
        self.assertTrue(self.result(crlf)["ok"], self.result(crlf))
        mixed = self.template_text.replace("\n", "\r\n", 10)
        self.assertCode(self.result(mixed), "mixed-line-endings")
        lone_cr = self.template_text.replace("\n", "\r")
        self.assertCode(self.result(lone_cr), "invalid-line-ending")
        invalid = self.template_bytes[:100] + b"\xff" + self.template_bytes[100:]
        result = validator.validate_bytes(invalid, path="fixture/roadmap.md")
        self.assertCode(result, "invalid-utf8")
        self.assertEqual(result["errors"][0]["line"], 4)

    def test_multiline_html_comments_hide_all_structural_content(self) -> None:
        hidden = (
            "<!--\n"
            "## 0. Hidden section\n"
            "### Hidden subsection\n"
            "- Hidden: field\n"
            "```text\n"
            "# Add exact commands and expected artifacts.\n"
            "```\n"
            "-->\n"
        )
        mutated = self.replace_once(
            self.template_text,
            "## 1. One operation\n",
            hidden + "## 1. One operation\n",
        )
        result = self.result(mutated)
        self.assertTrue(result["ok"], result)

    def test_backtick_and_tilde_fences_hide_structural_content(self) -> None:
        backtick = (
            "```\n"
            "## 0. Hidden section\n"
            "### Hidden subsection\n"
            "- Hidden: field\n"
            "- [ ] hidden DoD\n"
            "```\n"
        )
        tilde = (
            "~~~~markdown\n"
            "## 0. Hidden tilde section\n"
            "### Hidden tilde subsection\n"
            "- Hidden: tilde field\n"
            "- [ ] hidden tilde DoD\n"
            "~~~~\n"
        )
        mutated = self.replace_once(
            self.template_text,
            "## 1. One operation\n",
            backtick + tilde + "## 1. One operation\n",
        )
        result = self.result(mutated)
        self.assertTrue(result["ok"], result)

    def test_hidden_dod_checkboxes_do_not_count(self) -> None:
        hidden = "<!--\n- [ ] The one operation is complete.\n- [ ] Hidden DoD.\n-->\n"
        mutated = self.replace_once(
            self.template_text,
            "## 10. Definition of done\n",
            "## 10. Definition of done\n" + hidden,
        )
        result = self.result(mutated)
        self.assertTrue(result["ok"], result)

    def test_hidden_command_fence_is_ignored_but_visible_fence_is_required(self) -> None:
        hidden = (
            "<!--\n"
            "```text\n"
            "# Add exact commands and expected artifacts.\n"
            "```\n"
            "-->\n"
        )
        with_visible = self.replace_once(
            self.template_text,
            "## 8. Verification commands\n",
            "## 8. Verification commands\n" + hidden,
        )
        result = self.result(with_visible)
        self.assertTrue(result["ok"], result)

        without_visible = self.replace_once(
            with_visible,
            hidden + "\n```text\n# Add exact commands and expected artifacts.\n```\n",
            hidden + "\n",
        )
        self.assertCode(self.result(without_visible), "command-fence-missing")

    def test_unknown_cli_args_emit_one_json_object_without_traceback(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--unknown-flag"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stderr, "")
        self.assertNotIn("Traceback", completed.stdout + completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["path"], None)
        self.assertEqual(payload["errors"][0]["code"], "cli-arguments")


if __name__ == "__main__":
    unittest.main()
