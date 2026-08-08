#!/usr/bin/env python3
"""Extract launcher result metadata without printing credential contents.

``hermes_agent.py`` returns public metadata under ``.result``. This helper reads
that JSON from stdin and emits only the requested endpoint or credential-file
path, so live-proof commands use the launcher-owned instance rather than a
remembered or inferred port.
"""

from __future__ import annotations

import json
import sys
from typing import Mapping, Sequence


FIELDS = frozenset({"endpoint", "credential-file"})
MAX_RESULT_TEXT = 2048


class LauncherResultError(Exception):
    """Stable parse failure that never includes launcher output."""

    def __init__(self, code: str = "launcher_result_invalid") -> None:
        self.code = code
        super().__init__(code)


def _metadata(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_RESULT_TEXT:
        raise LauncherResultError()
    if any(ord(character) < 0x20 for character in value):
        raise LauncherResultError()
    return value


def parse_launcher_result(raw: bytes | str) -> Mapping[str, str]:
    """Return the public endpoint and credential-file metadata under ``result``."""

    try:
        document = json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
        raise LauncherResultError() from None
    if not isinstance(document, dict) or document.get("ok") is not True:
        raise LauncherResultError()
    result = document.get("result")
    if not isinstance(result, dict):
        raise LauncherResultError()
    return {
        "endpoint": _metadata(result.get("endpoint")),
        "credential-file": _metadata(result.get("credential_file")),
    }


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1 or arguments[0] not in FIELDS:
        print("usage_invalid", file=sys.stderr)
        return 1

    try:
        value = parse_launcher_result(sys.stdin.buffer.read())[arguments[0]]
    except LauncherResultError as error:
        print(error.code, file=sys.stderr)
        return 1
    print(value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
