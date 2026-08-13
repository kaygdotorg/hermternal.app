#!/usr/bin/env python3
"""Focused regressions for strict LF records and Git ranges."""

import hashlib
import importlib.util
from pathlib import Path

BASE = Path(__file__).resolve().parent
GENERATOR = BASE / "f932bc703a5e-task464-candidate5-generator.py"
EXPECTED_INITIAL_STABLE_TEST_SHA256 = "11c09beaf250e0dc6d2b59193ddcda7b320cd83771283c82d4c5f4c594e65e9c"


def load_generator():
    spec = importlib.util.spec_from_file_location("candidate5_framing_range", GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rejects(callable_, value):
    try:
        callable_(value)
    except (ValueError, SystemExit):
        return
    raise AssertionError(f"accepted invalid value: {value!r}")


def main():
    generator = load_generator()

    valid_record = b"one-record\n"
    assert generator.parse_single_record_lf(valid_record) == b"one-record"
    assert generator.restore_command_substitution_lf("one-record") == b"one-record"
    for invalid in (
        b"",
        b"one-record",
        b"one-record\r\n",
        b"one\rrecord\n",
        b"one-record\n\n",
        b"one\ntwo\n",
    ):
        rejects(generator.parse_single_record_lf, invalid)
    rejects(generator.restore_command_substitution_lf, "")
    rejects(generator.restore_command_substitution_lf, "one\ntwo")
    rejects(generator.restore_command_substitution_lf, "one\rrecord")

    left = "0123456789abcdef" * 2 + "01234567"
    right = "fedcba9876543210" * 2 + "fedcba98"
    valid_range = f"{left}..{right}"
    assert generator.parse_git_range(valid_range) == valid_range
    for invalid in (
        valid_range.upper(),
        valid_range[1:],
        valid_range + "0",
        valid_range[:39] + "g" + valid_range[40:],
        valid_range.replace("..", "."),
        valid_range.replace("..", "..."),
        "x" + valid_range,
        valid_range + "x",
    ):
        rejects(generator.parse_git_range, invalid)

    print("strict framing and range regressions passed")


if __name__ == "__main__":
    main()
