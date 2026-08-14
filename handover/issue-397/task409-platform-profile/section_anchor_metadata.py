#!/usr/bin/env python3
"""Validate the one canonical README section-anchor metadata value.

This policy is intentionally small and reusable.  It rejects malformed JSON
before a generated replay artifact can treat a visible ``\\n`` as an LF.
All callers use it for both the generator intake and generated JSON output.
"""
from __future__ import annotations

import copy
import json
from typing import Any

ANCHOR_PATH = ("live_overlap", "scripts_readme", "section_anchor")
CANONICAL_ANCHOR = "## Disposable Caddy proof renderer\n"
LEGACY_DOUBLE_ESCAPED_ANCHOR = "## Disposable Caddy proof renderer\\n"


class Reject(Exception):
    """Reject metadata that cannot safely identify the README section."""


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in items:
        if key in value:
            raise Reject(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def strict_document(raw: bytes, label: str) -> dict[str, Any]:
    """Decode one JSON object while rejecting duplicate keys and invalid UTF-8."""
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except Reject:
        raise
    except Exception as error:
        raise Reject(f"{label} is not strict UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise Reject(f"{label} root is not an object")
    return value


def anchor_value(document: dict[str, Any], label: str) -> str:
    """Return the sole metadata value only when its shape and LF are exact."""
    current: Any = document
    for key in ANCHOR_PATH[:-1]:
        if not isinstance(current, dict) or key not in current:
            raise Reject(f"{label} is missing {'.'.join(ANCHOR_PATH)}")
        current = current[key]
    if not isinstance(current, dict) or ANCHOR_PATH[-1] not in current:
        raise Reject(f"{label} is missing {'.'.join(ANCHOR_PATH)}")
    value = current[ANCHOR_PATH[-1]]
    if not isinstance(value, str):
        raise Reject(f"{label} section anchor is not a string")
    if value != CANONICAL_ANCHOR:
        raise Reject(f"{label} section anchor is not the canonical LF value")
    return value


def repair_legacy(document: dict[str, Any]) -> dict[str, Any]:
    """Correct exactly the known legacy value and reject every other input."""
    result = copy.deepcopy(document)
    current: Any = result
    for key in ANCHOR_PATH[:-1]:
        if not isinstance(current, dict) or key not in current:
            raise Reject(f"legacy intake is missing {'.'.join(ANCHOR_PATH)}")
        current = current[key]
    if not isinstance(current, dict) or set(current).isdisjoint({ANCHOR_PATH[-1]}):
        raise Reject(f"legacy intake is missing {'.'.join(ANCHOR_PATH)}")
    value = current.get(ANCHOR_PATH[-1])
    if value != LEGACY_DOUBLE_ESCAPED_ANCHOR:
        raise Reject("legacy intake does not contain the exact double-escaped anchor")
    current[ANCHOR_PATH[-1]] = CANONICAL_ANCHOR
    anchor_value(result, "repaired intake")
    return result


def strict_one_field_diff(before: dict[str, Any], after: dict[str, Any]) -> None:
    """Require the metadata repair to be the only semantic document change."""
    expected = repair_legacy(before)
    if expected != after:
        raise Reject("metadata successor changed more than the section anchor")

