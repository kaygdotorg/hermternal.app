#!/usr/bin/env python3
"""Deterministic regressions for the sandbox supervisor's Linux process parser."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("sandbox-runner.py")
SPEC = importlib.util.spec_from_file_location("sandbox_runner", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("sandbox supervisor module could not be loaded")
sandbox_runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = sandbox_runner
SPEC.loader.exec_module(sandbox_runner)


class SandboxRunnerParserTests(unittest.TestCase):
    def test_linux_stat_parser_handles_spaces_and_right_parentheses_in_comm(self) -> None:
        stat_line = "321 (worker ) child with spaces) S 123 1 2 3"
        self.assertEqual(sandbox_runner._linux_parent_pid(stat_line), 123)

    def test_linux_children_uses_the_final_comm_parenthesis(self) -> None:
        stat_line = "321 (worker ) child with spaces) S 123 1 2 3"
        with (
            patch.object(sandbox_runner.sys, "platform", "linux"),
            patch.object(sandbox_runner.os, "listdir", return_value=["321"]),
            patch.object(sandbox_runner.Path, "read_text", return_value=stat_line),
        ):
            self.assertEqual(sandbox_runner._children(123), {321})


if __name__ == "__main__":
    unittest.main()
