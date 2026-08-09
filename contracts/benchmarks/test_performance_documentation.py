#!/usr/bin/env python3
"""Regression tests for the normative B-01 performance coverage contract.

The test parses the checked-in Markdown matrix instead of searching the whole
file. This keeps missing rows or metrics visible while remaining offline and
independent of benchmark evidence JSON or renderer implementations.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DOCUMENT = REPOSITORY_ROOT / "docs/product/performance-benchmarking.md"
DOCUMENT_PATH = Path(os.environ.get("HERMTERNAL_PERFORMANCE_DOCUMENT", DEFAULT_DOCUMENT)).resolve()


def parse_coverage_rows(document: str) -> dict[str, str]:
    """Parse the required coverage table under its normative section."""

    lines = document.splitlines()
    section = next(
        (index for index, line in enumerate(lines) if line.strip() == "### Required coverage matrix"),
        None,
    )
    if section is None:
        raise AssertionError("required coverage matrix section is missing")

    header = next(
        (
            index
            for index in range(section + 1, len(lines))
            if lines[index].strip() == "| Surface | Required synthetic operation families | Example recorded metric units |"
        ),
        None,
    )
    if header is None:
        raise AssertionError("coverage table header is missing")

    rows: dict[str, str] = {}
    for line in lines[header + 2 :]:
        stripped = line.strip()
        if not stripped.startswith("|"):
            break
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) != 3 or not cells[0]:
            raise AssertionError(f"malformed coverage table row: {line!r}")
        if cells[0] in rows:
            raise AssertionError(f"duplicate coverage table row: {cells[0]}")
        rows[cells[0]] = cells[1]
    return rows


class PerformanceDocumentationTests(unittest.TestCase):
    """Keep the B-01 matrix complete without touching measured evidence."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.document = DOCUMENT_PATH.read_text(encoding="utf-8")
        cls.rows = parse_coverage_rows(cls.document)

    def assert_row_contains(self, row: str, terms: tuple[str, ...]) -> None:
        self.assertIn(row, self.rows, f"coverage row is missing: {row}")
        text = self.rows[row].lower()
        for term in terms:
            with self.subTest(row=row, term=term):
                self.assertIn(term.lower(), text, f"{row} is missing required metric: {term}")

    def test_required_web_chat_metrics_are_explicit(self) -> None:
        self.assert_row_contains(
            "Web chat",
            (
                "startup",
                "bundle evidence",
                "stream rendering",
                "reconnect and restoration",
                "scroll",
                "memory",
            ),
        )

    def test_required_web_terminal_metrics_are_explicit(self) -> None:
        self.assert_row_contains(
            "Web Terminal",
            ("first glyph", "throughput", "replay", "input echo", "resize", "memory"),
        )

    def test_required_apple_metrics_are_explicit(self) -> None:
        self.assert_row_contains(
            "Apple: iOS, iPadOS, macOS",
            ("launch", "resume", "stream", "scroll", "render", "scene", "memory"),
        )

if __name__ == "__main__":
    unittest.main()
