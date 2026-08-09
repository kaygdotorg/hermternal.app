#!/usr/bin/env python3
"""Extract launcher result metadata without printing credential contents.

``hermes_agent.py`` returns public metadata under ``.result``. This helper reads
that JSON from stdin and emits only the requested endpoint or credential-file
path, so live-proof commands use the launcher-owned instance and its explicit
port rather than a remembered or inferred port.
"""

from __future__ import annotations

import json
import sys
from typing import Mapping, Sequence
from urllib.parse import urlsplit


FIELDS = frozenset({"endpoint", "credential-file"})
MAX_RESULT_TEXT = 2048
# The helper is only a bridge from the freshly verified ``endpoint`` operation
# into the child-environment credential handoff. Keeping this shape closed
# prevents a ready ``start`` response or retained metadata from bypassing it.
VERIFIED_ENDPOINT_RESULT_KEYS = frozenset(
    {"instance", "container", "endpoint", "image", "data_path", "credential_file", "status"}
)


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


def _endpoint(value: object) -> str:
    endpoint = _metadata(value)
    try:
        parsed = urlsplit(endpoint)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise LauncherResultError() from None
    # This parser consumes launcher handoff output, not a general proxy target.
    # Keep the selected endpoint on the exact IPv4 loopback form the launcher
    # freshly proved; no alternate host can cross into credential handoff.
    if (
        parsed.scheme != "http"
        or hostname != "127.0.0.1"
        or port is None
        or port < 1
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise LauncherResultError()
    return endpoint


def parse_launcher_result(raw: bytes | str) -> Mapping[str, str]:
    """Return metadata only from the closed, freshly verified endpoint result."""

    try:
        document = json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
        raise LauncherResultError() from None
    if (
        not isinstance(document, dict)
        or set(document) != {"ok", "operation", "result"}
        or document.get("ok") is not True
        or document.get("operation") != "endpoint"
    ):
        raise LauncherResultError()
    result = document.get("result")
    if (
        not isinstance(result, dict)
        or set(result) != VERIFIED_ENDPOINT_RESULT_KEYS
        or result.get("status") != "running"
    ):
        raise LauncherResultError()
    # Validate every public field in the closed response. This prevents callers
    # from silently treating a partly retained or substituted result as proof.
    for field in ("instance", "container", "image", "data_path"):
        _metadata(result.get(field))
    return {
        "endpoint": _endpoint(result.get("endpoint")),
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
