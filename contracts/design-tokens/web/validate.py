#!/usr/bin/env python3
"""Validate the bounded Paper-to-code web artboard manifest offline.

The manifest is a planning contract, not a runtime integration or a live
compatibility claim. This validator keeps the mapping deterministic: every
Paper artboard in the Runtime and Authentication pages is named exactly once,
shipped states require all four light/dark desktop/narrow variants, and known
v0.0.1 gaps remain explicitly blocked instead of being guessed. It uses only
Python's standard library and never opens Paper, Hermes, a socket, or a URL.
"""

from __future__ import annotations

import json
import math
import re
import sys
from pathlib import Path
from typing import Any


MANIFEST_PATH = Path(__file__).resolve().with_name("artboards.json")
SCHEMA = "hermternal.web-paper-artboard-manifest.v1"
CONTRACT = "dashboard-v0.0.1"
PAPER_FILE_ID = "01KZ6BB66KCWR2C4J2TSWQGDM7"
PAPER_TOKEN_CONTENT_HASH = "cb15f2b1"
VARIANT_ORDER = ("light.desktop", "light.narrow", "dark.desktop", "dark.narrow")
APPEARANCES = ("light", "dark")
VIEWPORTS = ("desktop", "narrow")
MAX_JSON_BYTES = 256 * 1024
MAX_JSON_DEPTH = 24
MAX_JSON_NODES = 8_000
MAX_STRING_LENGTH = 512
MAX_INTEGER_DIGITS = 18
MAX_ERROR_LENGTH = 220
SAFE_ID = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")

TOP_LEVEL_KEYS = (
    "schema",
    "contract",
    "evidence_status",
    "live_claim",
    "paper",
    "scope",
    "tokens",
    "token_sets",
    "states",
)
PAPER_KEYS = ("file_id", "file_name", "token_content_hash", "pages")
PAGE_KEYS = ("id", "name", "artboard_count")
SCOPE_KEYS = ("release", "platform", "appearances", "viewports", "variant_order", "excluded")
VIEWPORT_KEYS = ("id", "width", "height_policy")
EXCLUDED_KEYS = ("id", "status", "target_release", "reason")
TOKEN_KEYS = ("name", "value", "scope")
TOKEN_SET_KEYS = ("id", "tokens")
STATE_KEYS = ("id", "family", "status", "release", "token_set", "variants", "missing_variants", "notes")
VARIANT_KEYS = ("id", "artboard_id", "name", "width", "height")


class ValidationError(ValueError):
    """Raised for any malformed, incomplete, or guessed manifest evidence."""

    def __init__(self, _detail: str = "") -> None:
        super().__init__("web Paper manifest rejected")


class DuplicateKeyError(ValidationError):
    """Raised before a duplicate JSON key can replace a mapping entry."""


SAFE_FAILURE = {
    "ok": False,
    "schema": SCHEMA,
    "evidence_status": "blocked",
    "live_claim": False,
    "error": "web_paper_manifest_invalid",
}


def require(condition: bool, message: str = "") -> None:
    if not condition:
        raise ValidationError(message)


def strict_keys(value: Any, expected: tuple[str, ...], _label: str) -> dict[str, Any]:
    require(type(value) is dict)
    require(tuple(value.keys()) == expected)
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError()
        result[key] = value
    return result


def _parse_int(text: str) -> int:
    digits = text.lstrip("-")
    require(len(digits) <= MAX_INTEGER_DIGITS)
    return int(text)


def _parse_float(text: str) -> float:
    value = float(text)
    require(math.isfinite(value))
    return value


def _reject_constant(_text: str) -> Any:
    raise ValidationError()


def _read_bounded(path: Path) -> bytes:
    try:
        require(not path.is_symlink() and path.is_file())
        require(path.stat().st_size <= MAX_JSON_BYTES)
        with path.open("rb") as stream:
            data = stream.read(MAX_JSON_BYTES + 1)
    except ValidationError:
        raise
    except (OSError, ValueError) as exc:
        raise ValidationError() from exc
    require(len(data) <= MAX_JSON_BYTES)
    return data


def _validate_tree(value: Any, depth: int = 0, count: list[int] | None = None) -> None:
    if count is None:
        count = [0]
    count[0] += 1
    require(count[0] <= MAX_JSON_NODES)
    require(depth <= MAX_JSON_DEPTH)
    if type(value) is dict:
        for key, child in value.items():
            require(type(key) is str and len(key) <= MAX_STRING_LENGTH and "\x00" not in key)
            _validate_tree(child, depth + 1, count)
        return
    if type(value) is list:
        require(len(value) <= MAX_JSON_NODES)
        for child in value:
            _validate_tree(child, depth + 1, count)
        return
    if type(value) is str:
        require(len(value) <= MAX_STRING_LENGTH and "\x00" not in value)
        return
    if type(value) is float:
        require(math.isfinite(value))
        return
    if type(value) is int:
        require(abs(value) <= 10**MAX_INTEGER_DIGITS - 1)
        return
    require(value is None or type(value) is bool)


def load_json(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    data = _read_bounded(path)
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_int=_parse_int,
            parse_float=_parse_float,
            parse_constant=_reject_constant,
        )
    except ValidationError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError, ValueError) as exc:
        raise ValidationError() from exc
    _validate_tree(value)
    require(type(value) is dict)
    return value


def _text(value: Any) -> str:
    require(type(value) is str and 0 < len(value) <= MAX_STRING_LENGTH)
    require("\x00" not in value)
    return value


def _id(value: Any) -> str:
    require(type(value) is str and SAFE_ID.fullmatch(value) is not None)
    return value


def _list_of_strings(value: Any, allowed: tuple[str, ...], *, nonempty: bool = True) -> tuple[str, ...]:
    require(type(value) is list)
    if nonempty:
        require(bool(value))
    result: list[str] = []
    for item in value:
        require(type(item) is str and item in allowed and item not in result)
        result.append(item)
    return tuple(result)


def desktop(variant_id: str, artboard_id: str, name: str, height: int) -> tuple[str, str, str, int, int]:
    return (variant_id, artboard_id, name, 1440, height)


def narrow(variant_id: str, artboard_id: str, name: str) -> tuple[str, str, str, int, int]:
    return (variant_id, artboard_id, name, 390, 844)


def state(
    identifier: str,
    family: str,
    status: str,
    release: str,
    token_set: str,
    variants: tuple[tuple[str, str, str, int, int], ...],
    missing: tuple[str, ...],
) -> tuple[str, str, str, str, str, tuple[tuple[str, str, str, int, int], ...], tuple[str, ...]]:
    return (identifier, family, status, release, token_set, variants, missing)


# Expected state inventory is intentionally duplicated in code. The manifest is
# user-facing data; this fixed table prevents a changed artboard ID/name from
# authorizing a new implementation target without a validator change and review.
EXPECTED_STATES = (
    state("runtime.interrupted-response", "runtime", "ready", "v0.0.1", "runtime", (desktop("light.desktop", "59J-0", "Light / Desktop — interrupted response", 960), narrow("light.narrow", "5M9-0", "Light / Mobile — interrupted response"), desktop("dark.desktop", "5QL-0", "Dark / Desktop — interrupted response", 960), narrow("dark.narrow", "63B-0", "Dark / Mobile — interrupted response")), ()),
    state("runtime.loading-session", "runtime", "ready", "v0.0.1", "runtime", (desktop("light.desktop", "3RD-0", "Light / Desktop — loading session", 960), narrow("light.narrow", "BAX-0", "Light / Mobile — loading session"), desktop("dark.desktop", "3ZW-0", "Dark / Desktop — loading session", 960), narrow("dark.narrow", "BDA-0", "Dark / Mobile — loading session")), ()),
    state("runtime.offline", "runtime", "ready", "v0.0.1", "runtime", (desktop("light.desktop", "5FW-0", "Light / Desktop — offline", 960), narrow("light.narrow", "5OF-0", "Light / Mobile — offline"), desktop("dark.desktop", "5WY-0", "Dark / Desktop — offline", 960), narrow("dark.narrow", "65H-0", "Dark / Mobile — offline")), ()),
    state("runtime.empty-session", "runtime", "ready", "v0.0.1", "runtime", (desktop("light.desktop", "A7H-0", "Light / Desktop — empty session", 960), narrow("light.narrow", "3XQ-0", "Light / Mobile — empty session"), desktop("dark.desktop", "AE1-0", "Dark / Desktop — empty session", 960), narrow("dark.narrow", "469-0", "Dark / Mobile — empty session")), ()),
    state("runtime.retryable-failure", "runtime", "ready", "v0.0.1", "runtime", (desktop("light.desktop", "AKL-0", "Light / Desktop — retryable failure", 960), narrow("light.narrow", "4L5-0", "Light / Mobile — retryable failure"), desktop("dark.desktop", "AR6-0", "Dark / Desktop — retryable failure", 960), narrow("dark.narrow", "527-0", "Dark / Mobile — retryable failure")), ()),
    state("runtime.permanent-failure", "runtime", "ready", "v0.0.1", "runtime", (desktop("light.desktop", "AXR-0", "Light / Desktop — permanent failure", 960), narrow("light.narrow", "4NB-0", "Light / Mobile — permanent failure"), desktop("dark.desktop", "B4C-0", "Dark / Desktop — permanent failure", 960), narrow("dark.narrow", "54D-0", "Dark / Mobile — permanent failure")), ()),
    state("runtime.compatibility-check-failed", "runtime", "ready", "v0.0.1", "runtime-gate", (desktop("light.desktop", "7I1-0", "Light / Desktop — compatibility check failed", 960), narrow("light.narrow", "7V7-0", "Light / Mobile — compatibility check failed"), desktop("dark.desktop", "7OM-0", "Dark / Desktop — compatibility check failed", 960), narrow("dark.narrow", "7XM-0", "Dark / Mobile — compatibility check failed")), ()),
    state("runtime.unsupported-version", "runtime", "ready", "v0.0.1", "runtime-gate", (desktop("light.desktop", "6JF-0", "Light / Desktop — unsupported version", 960), narrow("light.narrow", "6WL-0", "Light / Mobile — unsupported version"), desktop("dark.desktop", "6Q0-0", "Dark / Desktop — unsupported version", 960), narrow("dark.narrow", "6Z0-0", "Dark / Mobile — unsupported version")), ()),
    state("runtime.streaming-response", "runtime", "ready", "v0.0.1", "runtime", (desktop("light.desktop", "48F-0", "Light / Desktop — streaming response", 960), narrow("light.narrow", "BFN-0", "Light / Mobile — streaming response"), desktop("dark.desktop", "4PH-0", "Dark / Desktop — streaming response", 960), narrow("dark.narrow", "BI0-0", "Dark / Mobile — streaming response")), ()),
    state("runtime.reconnecting", "runtime", "ready", "v0.0.1", "runtime", (desktop("light.desktop", "4ES-0", "Light / Desktop — reconnecting", 960), narrow("light.narrow", "BKD-0", "Light / Mobile — reconnecting"), desktop("dark.desktop", "4VU-0", "Dark / Desktop — reconnecting", 960), narrow("dark.narrow", "BMQ-0", "Dark / Mobile — reconnecting")), ()),
    state("auth.provider-selection", "authentication", "ready", "v0.0.1", "auth", (desktop("light.desktop", "3JJ-0", "Light / Desktop — provider selection", 900), narrow("light.narrow", "3JN-0", "Light / Mobile — provider selection"), desktop("dark.desktop", "3NU-0", "Dark / Desktop — provider selection", 900), narrow("dark.narrow", "3PU-0", "Dark / Mobile — provider selection")), ()),
    state("auth.password-sign-in", "authentication", "blocked", "v0.0.1", "auth", (desktop("light.desktop", "3JK-0", "Light / Desktop — password sign in", 900), desktop("dark.desktop", "3OH-0", "Dark / Desktop — password sign in", 900)), ("light.narrow", "dark.narrow")),
    state("auth.oauth-callback", "authentication", "blocked", "v0.0.1", "auth", (desktop("light.desktop", "3JL-0", "Light / Desktop — OAuth callback", 900), desktop("dark.desktop", "3P1-0", "Dark / Desktop — OAuth callback", 900)), ("light.narrow", "dark.narrow")),
    state("auth.authentication-failure", "authentication", "blocked", "v0.0.1", "auth-gate", (desktop("light.desktop", "3JM-0", "Light / Desktop — authentication failure", 900), desktop("dark.desktop", "3PE-0", "Dark / Desktop — authentication failure", 900)), ("light.narrow", "dark.narrow")),
    state("auth.session-expired", "authentication", "blocked", "v0.0.1", "auth-gate", (narrow("light.narrow", "3JO-0", "Light / Mobile — session expired"), narrow("dark.narrow", "3QO-0", "Dark / Mobile — session expired")), ("light.desktop", "dark.desktop")),
    state("auth.provider-discovery-retry", "authentication", "ready", "v0.0.1", "auth-gate", (desktop("light.desktop", "C2A-0", "Light / Desktop — provider discovery retry", 900), narrow("light.narrow", "C36-0", "Light / Mobile — provider discovery retry"), desktop("dark.desktop", "C2Q-0", "Dark / Desktop — provider discovery retry", 900), narrow("dark.narrow", "C40-0", "Dark / Mobile — provider discovery retry")), ()),
    state("auth.provider-unavailable-fail-closed", "authentication", "ready", "v0.0.1", "auth-gate", (desktop("light.desktop", "BZQ-0", "Light / Desktop — provider unavailable / fail closed", 900), narrow("light.narrow", "C0M-0", "Light / Mobile — provider unavailable / fail closed"), desktop("dark.desktop", "C06-0", "Dark / Desktop — provider unavailable / fail closed", 900), narrow("dark.narrow", "C1G-0", "Dark / Mobile — provider unavailable / fail closed")), ()),
    state("auth.provider-discovery-pending", "authentication", "ready", "v0.0.1", "auth-gate", (desktop("light.desktop", "BWS-0", "Light / Desktop — provider discovery pending", 900), narrow("light.narrow", "BY2-0", "Light / Mobile — provider discovery pending"), desktop("dark.desktop", "BXF-0", "Dark / Desktop — provider discovery pending", 900), narrow("dark.narrow", "BYW-0", "Dark / Mobile — provider discovery pending")), ()),
    state("auth.password-submitting", "authentication", "ready", "v0.0.1", "auth", (desktop("light.desktop", "C94-0", "Light / Desktop — password submitting", 900), narrow("light.narrow", "C96-0", "Light / Mobile — password submitting"), desktop("dark.desktop", "C95-0", "Dark / Desktop — password submitting", 900), narrow("dark.narrow", "C97-0", "Dark / Mobile — password submitting")), ()),
    state("auth.interaction-states", "authentication", "blocked", "v0.0.1", "auth", (desktop("light.desktop", "69V-0", "Light / Desktop — authentication interaction states", 900), desktop("dark.desktop", "69W-0", "Dark / Desktop — authentication interaction states", 900)), ("light.narrow", "dark.narrow")),
    state("auth.provider-selection-200-percent-zoom", "authentication", "blocked", "v0.0.1", "auth", (narrow("light.narrow", "6G3-0", "Light / Mobile — provider selection at 200% zoom"), narrow("dark.narrow", "6HR-0", "Dark / Mobile — provider selection at 200% zoom")), ("light.desktop", "dark.desktop")),
    state("auth.provider-localization-growth", "authentication", "blocked", "v0.0.1", "auth", (narrow("light.narrow", "6GX-0", "Light / Mobile — provider localization growth"), narrow("dark.narrow", "6IL-0", "Dark / Mobile — provider localization growth")), ("light.desktop", "dark.desktop")),
    state("runtime.private-deep-link-primary", "runtime", "deferred", "v0.0.2", "deep-link-deferred", (desktop("light.desktop", "71F-0", "Light / Desktop — private deep link / primary", 960), narrow("light.narrow", "71J-0", "Light / Mobile — private deep link / primary"), desktop("dark.desktop", "71G-0", "Dark / Desktop — private deep link / primary", 960), narrow("dark.narrow", "71K-0", "Dark / Mobile — private deep link / primary")), ()),
    state("runtime.private-deep-link-failures", "runtime", "deferred", "v0.0.2", "deep-link-deferred", (desktop("light.desktop", "71H-0", "Light / Desktop — private deep link / failures", 960), narrow("light.narrow", "71L-0", "Light / Mobile — private deep link / failures"), desktop("dark.desktop", "71I-0", "Dark / Desktop — private deep link / failures", 960), narrow("dark.narrow", "71M-0", "Dark / Mobile — private deep link / failures")), ()),
    state("runtime.session-search-results", "runtime", "deferred", "v0.0.2", "search-deferred", (desktop("light.desktop", "71N-0", "Light / Desktop — Session Search · results", 960), narrow("light.narrow", "85I-0", "Light / Mobile — Session Search · results"), desktop("dark.desktop", "96O-0", "Dark / Desktop — Session Search · results", 960), narrow("dark.narrow", "9AG-0", "Dark / Mobile — Session Search · results")), ()),
    state("runtime.session-search-query", "runtime", "deferred", "v0.0.2", "search-deferred", (desktop("light.desktop", "8IG-0", "Light / Desktop — Session Search · query", 960), narrow("light.narrow", "8XK-0", "Light / Mobile — Session Search · query"), desktop("dark.desktop", "9F1-0", "Dark / Desktop — Session Search · query", 960), narrow("dark.narrow", "9YD-0", "Dark / Mobile — Session Search · query")), ()),
    state("runtime.session-search-loading", "runtime", "deferred", "v0.0.2", "search-deferred", (desktop("light.desktop", "8M8-0", "Light / Desktop — Session Search · loading", 960), narrow("light.narrow", "8ZU-0", "Light / Mobile — Session Search · loading"), desktop("dark.desktop", "9IT-0", "Dark / Desktop — Session Search · loading", 960), narrow("dark.narrow", "A0N-0", "Dark / Mobile — Session Search · loading")), ()),
    state("runtime.session-search-no-results", "runtime", "deferred", "v0.0.2", "search-deferred", (desktop("light.desktop", "8Q0-0", "Light / Desktop — Session Search · no results", 960), narrow("light.narrow", "924-0", "Light / Mobile — Session Search · no results"), desktop("dark.desktop", "9ML-0", "Dark / Desktop — Session Search · no results", 960), narrow("dark.narrow", "A2X-0", "Dark / Mobile — Session Search · no results")), ()),
    state("runtime.session-search-failure", "runtime", "deferred", "v0.0.2", "search-deferred", (desktop("light.desktop", "8TS-0", "Light / Desktop — Session Search · failure", 960), narrow("light.narrow", "94E-0", "Light / Mobile — Session Search · failure"), desktop("dark.desktop", "9QD-0", "Dark / Desktop — Session Search · failure", 960), narrow("dark.narrow", "A57-0", "Dark / Mobile — Session Search · failure")), ()),
)

TOKEN_RECORDS = (
    ("--color-canvas", "#F3F5F8", "shipped"),
    ("--color-paper", "#FFFFFF", "shipped"),
    ("--color-ink", "#16181D", "shipped"),
    ("--color-muted", "#667080", "shipped"),
    ("--color-line", "#D8DDE5", "shipped"),
    ("--color-signal", "#4C6FFF", "shipped"),
    ("--color-courier", "#E88A2A", "shipped"),
    ("--color-success", "#2DA568", "shipped"),
    ("--color-danger", "#D94A4A", "shipped"),
    ("--color-dark-canvas", "#0D1117", "shipped"),
    ("--color-dark-paper", "#171C24", "shipped"),
    ("--color-dark-ink", "#F4F6FA", "shipped"),
    ("--color-dark-muted", "#A7B0BF", "shipped"),
    ("--color-dark-line", "#343C49", "shipped"),
    ("--color-dark-signal", "#6F88FF", "shipped"),
    ("--color-dark-courier", "#F0A451", "shipped"),
    ("--color-dark-success", "#4CC989", "shipped"),
    ("--color-dark-danger", "#F06A6A", "shipped"),
    ("--color-auth-signal", "#3157C7", "shipped"),
    ("--color-auth-danger", "#AB3838", "shipped"),
    ("--color-gate-light-action", "#2748C8", "shipped"),
    ("--color-gate-light-action-ink", "var(--color-paper)", "shipped"),
    ("--color-gate-light-state-surface", "#EEF2FF", "shipped"),
    ("--color-gate-light-state-ink", "#2340A8", "shipped"),
    ("--color-gate-light-focus", "#2348C7", "shipped"),
    ("--color-gate-light-error-surface", "#FFF1F2", "shipped"),
    ("--color-gate-light-error-ink", "#A52B38", "shipped"),
    ("--color-gate-light-error-border", "#C44B57", "shipped"),
    ("--color-gate-dark-action", "#3B57D0", "shipped"),
    ("--color-gate-dark-action-ink", "var(--color-dark-ink)", "shipped"),
    ("--color-gate-dark-state-surface", "#202A50", "shipped"),
    ("--color-gate-dark-state-ink", "#C2CCFF", "shipped"),
    ("--color-gate-dark-focus", "#C2CCFF", "shipped"),
    ("--color-gate-dark-error-surface", "#351F26", "shipped"),
    ("--color-gate-dark-error-ink", "#FFB7C0", "shipped"),
    ("--color-gate-dark-error-border", "#FF7581", "shipped"),
    ("--color-deeplink-light-courier", "#8A4B00", "deferred"),
    ("--color-deeplink-light-success", "#0B6B4B", "deferred"),
    ("--color-deeplink-light-signal", "#2348C7", "deferred"),
    ("--color-deeplink-light-danger", "#A52B38", "deferred"),
    ("--color-deeplink-light-muted", "#4D5765", "deferred"),
    ("--color-deeplink-light-action", "#2748C8", "deferred"),
    ("--color-deeplink-light-action-ink", "var(--color-paper)", "deferred"),
    ("--color-deeplink-dark-courier", "var(--color-dark-courier)", "deferred"),
    ("--color-deeplink-dark-success", "var(--color-dark-success)", "deferred"),
    ("--color-deeplink-dark-signal", "var(--color-dark-signal)", "deferred"),
    ("--color-deeplink-dark-danger", "var(--color-dark-danger)", "deferred"),
    ("--color-deeplink-dark-muted", "var(--color-dark-muted)", "deferred"),
    ("--color-deeplink-dark-action", "var(--color-dark-signal)", "deferred"),
    ("--color-deeplink-dark-action-ink", "var(--color-dark-paper)", "deferred"),
    ("--color-search-light-courier", "#8A4B00", "deferred"),
    ("--color-search-light-success", "#0B6B4B", "deferred"),
    ("--color-search-light-signal", "#2348C7", "deferred"),
    ("--font-ui", "Instrument Sans", "shipped"),
    ("--text-meta", "12px", "shipped"),
    ("--text-control", "14px", "shipped"),
    ("--text-body", "15px", "shipped"),
    ("--text-title", "20px", "shipped"),
    ("--weight-regular", 400, "shipped"),
    ("--weight-medium", 500, "shipped"),
    ("--weight-semibold", 600, "shipped"),
    ("--leading-meta", "16px", "shipped"),
    ("--leading-control", "18px", "shipped"),
    ("--leading-body", "23px", "shipped"),
    ("--leading-title", "26px", "shipped"),
    ("--space-1", "4px", "shipped"),
    ("--space-2", "8px", "shipped"),
    ("--space-3", "12px", "shipped"),
    ("--space-4", "16px", "shipped"),
    ("--space-6", "24px", "shipped"),
    ("--space-8", "32px", "shipped"),
    ("--radius-nested", "var(--radius-nested-glass)", "shipped"),
    ("--radius-structural", "var(--radius-glass)", "shipped"),
    ("--radius-pill", "999px", "shipped"),
    ("--radius-input", "12px", "shipped"),
    ("--radius-nested-glass", "14px", "shipped"),
    ("--radius-card", "17px", "shipped"),
    ("--radius-popover", "18px", "shipped"),
    ("--radius-glass", "22px", "shipped"),
)

COLOR_BASE_TOKENS = tuple(item[0] for item in TOKEN_RECORDS[:18])
TYPOGRAPHY_TOKENS = tuple(item[0] for item in TOKEN_RECORDS[53:])
BASE_TOKENS = COLOR_BASE_TOKENS + TYPOGRAPHY_TOKENS
AUTH_EXTRA = ("--color-auth-signal", "--color-auth-danger")
GATE_EXTRA = (
    "--color-gate-light-action", "--color-gate-light-action-ink", "--color-gate-light-state-surface", "--color-gate-light-state-ink", "--color-gate-light-focus", "--color-gate-light-error-surface", "--color-gate-light-error-ink", "--color-gate-light-error-border",
    "--color-gate-dark-action", "--color-gate-dark-action-ink", "--color-gate-dark-state-surface", "--color-gate-dark-state-ink", "--color-gate-dark-focus", "--color-gate-dark-error-surface", "--color-gate-dark-error-ink", "--color-gate-dark-error-border",
)
DEEPLINK_EXTRA = tuple(item[0] for item in TOKEN_RECORDS[36:50])
SEARCH_EXTRA = tuple(item[0] for item in TOKEN_RECORDS[50:53])
TOKEN_SETS = (
    ("runtime", COLOR_BASE_TOKENS + TYPOGRAPHY_TOKENS),
    ("runtime-gate", COLOR_BASE_TOKENS + (TYPOGRAPHY_TOKENS[0],) + GATE_EXTRA + TYPOGRAPHY_TOKENS[1:]),
    ("auth", COLOR_BASE_TOKENS + AUTH_EXTRA + TYPOGRAPHY_TOKENS),
    ("auth-gate", COLOR_BASE_TOKENS + AUTH_EXTRA + GATE_EXTRA + TYPOGRAPHY_TOKENS),
    ("deep-link-deferred", COLOR_BASE_TOKENS + DEEPLINK_EXTRA + TYPOGRAPHY_TOKENS),
    ("search-deferred", COLOR_BASE_TOKENS + SEARCH_EXTRA + TYPOGRAPHY_TOKENS),
)


def _expected_token_sets() -> dict[str, tuple[str, ...]]:
    return dict(TOKEN_SETS)


def _validate_paper(document: dict[str, Any]) -> None:
    paper = strict_keys(document["paper"], PAPER_KEYS, "paper")
    require(paper == {
        "file_id": PAPER_FILE_ID,
        "file_name": "Hermternal",
        "token_content_hash": PAPER_TOKEN_CONTENT_HASH,
        "pages": paper["pages"],
    })
    pages = paper["pages"]
    require(type(pages) is list and len(pages) == 2)
    expected_pages = (
        ("3-0", "Web states — Authentication", 34),
        ("4-0", "Web states — Runtime", 68),
    )
    for raw, expected in zip(pages, expected_pages):
        item = strict_keys(raw, PAGE_KEYS, "paper page")
        require(tuple(item.values()) == expected)


def _validate_scope(document: dict[str, Any]) -> None:
    scope = strict_keys(document["scope"], SCOPE_KEYS, "scope")
    require(scope["release"] == "v0.0.1")
    require(scope["platform"] == "web")
    require(tuple(scope["appearances"]) == APPEARANCES)
    require(tuple(scope["variant_order"]) == VARIANT_ORDER)
    viewports = scope["viewports"]
    require(type(viewports) is list and len(viewports) == 2)
    expected_viewports = (("desktop", 1440, "paper_exact"), ("narrow", 390, "paper_exact"))
    for raw, expected in zip(viewports, expected_viewports):
        item = strict_keys(raw, VIEWPORT_KEYS, "viewport")
        require(tuple(item.values()) == expected)
    excluded = scope["excluded"]
    require(type(excluded) is list and len(excluded) == 2)
    expected_excluded = (
        ("private-deep-links", "deferred", "v0.0.2"),
        ("session-search", "deferred", "v0.0.2"),
    )
    seen: set[str] = set()
    for raw, expected in zip(excluded, expected_excluded):
        item = strict_keys(raw, EXCLUDED_KEYS, "excluded family")
        _id(item["id"])
        require(item["id"] not in seen)
        seen.add(item["id"])
        require((item["id"], item["status"], item["target_release"]) == expected)
        _text(item["reason"])


def _validate_tokens(document: dict[str, Any]) -> None:
    tokens = document["tokens"]
    require(type(tokens) is list and len(tokens) == len(TOKEN_RECORDS))
    seen: set[str] = set()
    for raw, expected in zip(tokens, TOKEN_RECORDS):
        item = strict_keys(raw, TOKEN_KEYS, "token")
        name, value, scope = expected
        require(item == {"name": name, "value": value, "scope": scope})
        require(item["name"] not in seen)
        seen.add(item["name"])
    token_sets = document["token_sets"]
    require(type(token_sets) is list and len(token_sets) == len(TOKEN_SETS))
    expected_sets = _expected_token_sets()
    seen_sets: set[str] = set()
    allowed = {item[0] for item in TOKEN_RECORDS}
    for raw, (identifier, expected) in zip(token_sets, TOKEN_SETS):
        item = strict_keys(raw, TOKEN_SET_KEYS, "token set")
        require(item["id"] == identifier and item["id"] not in seen_sets)
        seen_sets.add(item["id"])
        tokens_in_set = _list_of_strings(item["tokens"], tuple(allowed))
        require(tokens_in_set == expected)
    require(seen_sets == set(expected_sets))


def _validate_variant(raw: Any, expected: tuple[str, str, str, int, int]) -> str:
    item = strict_keys(raw, VARIANT_KEYS, "variant")
    require(tuple(item.values()) == expected)
    require(item["id"] in VARIANT_ORDER)
    require(type(item["width"]) is int and type(item["width"]) is not bool)
    require(type(item["height"]) is int and type(item["height"]) is not bool)
    return item["artboard_id"]


def _validate_states(document: dict[str, Any]) -> tuple[int, int, int]:
    states = document["states"]
    require(type(states) is list and len(states) == len(EXPECTED_STATES))
    all_artboards: list[str] = []
    ready = blocked = deferred = 0
    for raw, expected in zip(states, EXPECTED_STATES):
        identifier, family, status, release, token_set, expected_variants, expected_missing = expected
        item = strict_keys(raw, STATE_KEYS, "state")
        require(tuple(item[key] for key in ("id", "family", "status", "release", "token_set")) == (identifier, family, status, release, token_set))
        require(item["id"] not in {state_id for state_id, *_ in EXPECTED_STATES if state_id != identifier})
        _id(item["id"])
        _id(item["token_set"])
        variants = item["variants"]
        require(type(variants) is list and len(variants) == len(expected_variants))
        variant_ids: list[str] = []
        for raw_variant, expected_variant in zip(variants, expected_variants):
            artboard_id = _validate_variant(raw_variant, expected_variant)
            variant_ids.append(raw_variant["id"])
            require(artboard_id not in all_artboards)
            all_artboards.append(artboard_id)
        require(tuple(variant_ids) == tuple(expected_variant[0] for expected_variant in expected_variants))
        missing = _list_of_strings(item["missing_variants"], VARIANT_ORDER, nonempty=False)
        require(missing == expected_missing)
        require(set(variant_ids).isdisjoint(set(missing)))
        require(set(variant_ids) | set(missing) == set(VARIANT_ORDER))
        _text(item["notes"])
        if status == "ready":
            ready += 1
            require(release == "v0.0.1" and not missing and tuple(variant_ids) == VARIANT_ORDER)
        elif status == "blocked":
            blocked += 1
            require(release == "v0.0.1" and bool(missing))
        elif status == "deferred":
            deferred += 1
            require(release == "v0.0.2" and not missing and tuple(variant_ids) == VARIANT_ORDER)
        else:
            raise ValidationError()
    require(len(all_artboards) == len(set(all_artboards)))
    require(len(all_artboards) == 102)
    return ready, blocked, deferred


def validate_manifest(document: dict[str, Any]) -> tuple[int, int, int]:
    strict_keys(document, TOP_LEVEL_KEYS, "manifest")
    require(document["schema"] == SCHEMA)
    require(document["contract"] == CONTRACT)
    require(document["evidence_status"] == "complete")
    require(document["live_claim"] is False)
    _validate_paper(document)
    _validate_scope(document)
    _validate_tokens(document)
    return _validate_states(document)


def _failure() -> str:
    encoded = json.dumps(SAFE_FAILURE, sort_keys=True, separators=(",", ":"))
    require(len(encoded) <= MAX_ERROR_LENGTH)
    return encoded


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        if len(args) != 2 or args[0] != "--manifest":
            print(_failure())
            return 2
        path = Path(args[1])
    else:
        path = MANIFEST_PATH
    try:
        ready, blocked, deferred = validate_manifest(load_json(path))
    except Exception:
        print(_failure())
        return 1
    payload = {
        "ok": True,
        "schema": SCHEMA,
        "evidence_status": "complete",
        "live_claim": False,
        "state_count": len(EXPECTED_STATES),
        "ready_state_count": ready,
        "blocked_state_count": blocked,
        "deferred_state_count": deferred,
        "artboard_count": 102,
    }
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
