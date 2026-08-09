#!/usr/bin/env python3
"""Regression test for the privacy audit's renderer-backed terminal boundary.

This test reads only the checked-in audit text. It uses no network, credentials,
Hermes process, browser state, transcript, or deployment data.
"""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "docs" / "security" / "privacy-audit.md"
BOUNDED_RENDERER_CLAIM = (
    "The application has no application-level transcript mirror or diagnostic byte store; "
    "renderer-local Ghostty scrollback is bounded to 64 KiB by default and clamped to a 1 MiB maximum."
)
ABSOLUTE_PTY_CLAIM = "Terminal handling has no local PTY byte store."


class PrivacyAuditDocumentationTests(unittest.TestCase):
    def test_terminal_boundary_uses_bounded_renderer_claim(self) -> None:
        text = AUDIT.read_text(encoding="utf-8")
        self.assertIn(BOUNDED_RENDERER_CLAIM, text)
        self.assertNotIn(ABSOLUTE_PTY_CLAIM, text)


if __name__ == "__main__":
    raise SystemExit(unittest.main(verbosity=2))
