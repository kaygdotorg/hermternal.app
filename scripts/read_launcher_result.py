#!/usr/bin/env python3
"""Extract verified launcher handoff metadata without printing credentials.

``hermes_agent.py endpoint`` returns one bounded result only after it has
revalidated the caller-selected marker, pinned container, loopback mapping, and
credential identity. This helper accepts that exact closed result and emits
only the requested endpoint or ownership path for the transient local handoff.
It never selects a run, reads a marker, or infers a port.
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Mapping, Sequence


FIELDS = frozenset(
    {"endpoint", "marker-path", "run-id", "credential-file", "credential-identity"}
)
MAX_RESULT_TEXT = 2048
MAX_RESULT_BYTES = 4096
MAX_NUMERIC_DIGITS = 64
MAX_JSON_DEPTH = 32
_ENDPOINT_PATTERN = re.compile(r"http://127\.0\.0\.1:(?P<port>[0-9]{1,5})\Z")
RUN_ID_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
GENERATION_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
CREDENTIAL_IDENTITY_KEYS = frozenset(
    {"device", "inode", "mode", "size", "nlink", "generation"}
)
VERIFIED_ENDPOINT_RESULT_KEYS = frozenset(
    {"status", "endpoint", "marker_path", "run_id", "credential_file", "credential_identity"}
)


class LauncherResultError(Exception):
    """Stable parse failure that never includes launcher output."""

    def __init__(self, code: str = "launcher_result_invalid") -> None:
        self.code = code
        super().__init__(code)


def _bounded_text(value: object, maximum: int) -> str:
    if type(value) is not str or not value:
        raise LauncherResultError()
    try:
        if len(value.encode("utf-8")) > maximum:
            raise LauncherResultError()
    except UnicodeEncodeError:
        raise LauncherResultError() from None
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise LauncherResultError()
    return value


def _metadata(value: object) -> str:
    return _bounded_text(value, MAX_RESULT_TEXT)


def _path(value: object) -> str:
    path = _metadata(value)
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        raise LauncherResultError()
    return path


def _run_id(value: object) -> str:
    run_id = _metadata(value)
    if RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise LauncherResultError()
    return run_id


def _credential_identity(value: object) -> str:
    if not isinstance(value, dict) or set(value) != CREDENTIAL_IDENTITY_KEYS:
        raise LauncherResultError()
    numeric = [value[key] for key in ("device", "inode", "mode", "size", "nlink")]
    if any(type(item) is not int or item < 0 for item in numeric):
        raise LauncherResultError()
    if value["mode"] != 0o600 or not 1 <= value["size"] <= 256 or value["nlink"] != 1:
        raise LauncherResultError()
    generation = value["generation"]
    if not isinstance(generation, str) or GENERATION_PATTERN.fullmatch(generation) is None:
        raise LauncherResultError()
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _endpoint(value: object) -> str:
    endpoint = _metadata(value)
    # Do not use a URL parser here: URL parsers intentionally normalize some
    # spellings, while this handoff requires the producer's exact grammar.
    match = _ENDPOINT_PATTERN.fullmatch(endpoint)
    if match is None:
        raise LauncherResultError()
    try:
        port = int(match.group("port"))
    except (TypeError, ValueError, OverflowError):
        raise LauncherResultError() from None
    if not 1 <= port <= 65535:
        raise LauncherResultError()
    return endpoint


def _json_load(raw: bytes | str) -> object:
    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise LauncherResultError()
            document[key] = value
        return document

    def reject_constant(value: str) -> None:
        del value
        raise LauncherResultError()

    def bounded_int(value: str) -> int:
        if len(value.lstrip("-")) > MAX_NUMERIC_DIGITS:
            raise LauncherResultError()
        try:
            return int(value)
        except (ValueError, OverflowError):
            raise LauncherResultError() from None

    def reject_float(value: str) -> None:
        del value
        raise LauncherResultError()

    if isinstance(raw, bytes):
        if len(raw) > MAX_RESULT_BYTES:
            raise LauncherResultError()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise LauncherResultError() from None
    elif isinstance(raw, str):
        try:
            if len(raw.encode("utf-8")) > MAX_RESULT_BYTES:
                raise LauncherResultError()
        except UnicodeEncodeError:
            raise LauncherResultError() from None
        text = raw
    else:
        raise LauncherResultError()

    try:
        depth = 0
        in_string = False
        escaped = False
        for character in text:
            if in_string:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    in_string = False
                continue
            if character == '"':
                in_string = True
            elif character in "[{":
                depth += 1
                if depth > MAX_JSON_DEPTH:
                    raise LauncherResultError()
            elif character in "]}":
                depth -= 1
                if depth < 0:
                    raise LauncherResultError()
        return json.loads(
            text,
            object_pairs_hook=reject_duplicate,
            parse_constant=reject_constant,
            parse_int=bounded_int,
            parse_float=reject_float,
        )
    except LauncherResultError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError, RecursionError, MemoryError):
        raise LauncherResultError() from None


def parse_launcher_result(raw: bytes | str) -> Mapping[str, str]:
    """Return only metadata from a closed, freshly verified endpoint result."""

    document = _json_load(raw)
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
    return {
        "endpoint": _endpoint(result.get("endpoint")),
        "marker-path": _path(result.get("marker_path")),
        "run-id": _run_id(result.get("run_id")),
        "credential-file": _path(result.get("credential_file")),
        "credential-identity": _credential_identity(result.get("credential_identity")),
    }


def _read_bounded_stdin() -> bytes:
    try:
        stream = sys.stdin.buffer
        raw = stream.read(MAX_RESULT_BYTES + 1)
    except (AttributeError, OSError, ValueError):
        raise LauncherResultError() from None
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_RESULT_BYTES:
        raise LauncherResultError()
    return bytes(raw)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1 or arguments[0] not in FIELDS:
        print("usage_invalid", file=sys.stderr)
        return 1

    try:
        value = parse_launcher_result(_read_bounded_stdin())[arguments[0]]
    except LauncherResultError as error:
        print(error.code, file=sys.stderr)
        return 1
    print(value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
