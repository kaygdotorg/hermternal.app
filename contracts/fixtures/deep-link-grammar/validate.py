"""Offline validator for the synthetic Hermternal deep-link grammar fixtures.

This module is deliberately self-contained.  It parses strings only; it does
not follow links, resolve DNS, contact Hermes, or import a client runtime.
The parser keeps every opaque ID byte-for-byte and returns stable, ordered
reasons so callers can fail closed without normalising an untrusted target.
"""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
import json
from pathlib import Path
import posixpath
import re
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit


SCHEMA = "hermternal.deep-link-grammar/v1"
CONTRACT = "dashboard-v0.0.1"
DEFAULT_ORIGIN = "https://synthetic.hermternal.test"
MIN_FULL_ID_LENGTH = 16

# The order is part of the contract.  Do not derive it from a set or a parser
# exception: diagnostics must remain stable when several rules are violated.
REASON_ORDER = (
    "type",
    "control",
    "non_ascii",
    "percent_escape",
    "backslash",
    "query",
    "fragment",
    "trailing_slash",
    "scheme",
    "authority",
    "origin",
    "version",
    "path",
    "traversal",
    "normalization",
    "segment",
    "id_character",
    "full_id",
)
_REASON_INDEX = {reason: index for index, reason in enumerate(REASON_ORDER)}
_HARD_REASONS = frozenset(
    {
        "control",
        "non_ascii",
        "percent_escape",
        "backslash",
        "query",
        "fragment",
        "trailing_slash",
    }
)
_UNRESERVED = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789-._~"
)
_HOST_RE = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\Z")
_VERSION_RE = re.compile(r"^/v[0-9]+(?:/|\Z)")


class ContractError(ValueError):
    """Raised when a fixture or parser result violates the frozen contract."""


@dataclass(frozen=True)
class LinkResult:
    """The safe, structured result of parsing one candidate link.

    ``session_id`` and ``message_id`` are only useful after ``valid`` is true.
    They remain exact opaque strings; no case folding, decoding, truncation, or
    path normalisation occurs here.
    """

    valid: bool
    kind: str | None
    session_id: str | None
    message_id: str | None
    reasons: tuple[str, ...]
    diagnostic: str

    @property
    def reason(self) -> str:
        """Return the first stable reason, or ``ok`` for a valid link."""

        return self.reasons[0] if self.reasons else "ok"

    def as_dict(self) -> dict[str, Any]:
        """Return the JSON-shaped representation used by the fixtures."""

        return {
            "valid": self.valid,
            "kind": self.kind,
            "session_id": self.session_id,
            "message_id": self.message_id,
            "reasons": list(self.reasons),
            "diagnostic": self.diagnostic,
        }

    def __getitem__(self, key: str) -> Any:
        """Allow small callers and tests to use mapping-style access."""

        return self.as_dict()[key]


def _require(condition: bool, message: str) -> None:
    """Raise explicitly instead of using ``assert``, including under ``-O``."""

    if not condition:
        raise ContractError(message)


def _strict_equal(actual: Any, expected: Any) -> bool:
    """Compare JSON values without Python's bool/int coercion."""

    if type(actual) is not type(expected):
        return False
    if isinstance(actual, dict):
        return set(actual) == set(expected) and all(
            _strict_equal(actual[key], expected[key]) for key in expected
        )
    if isinstance(actual, list):
        return len(actual) == len(expected) and all(
            _strict_equal(item, expected_item)
            for item, expected_item in zip(actual, expected)
        )
    return actual == expected


def _ordered_reasons(reasons: set[str]) -> tuple[str, ...]:
    """Return reasons in the frozen order and reject accidental new names."""

    _require(
        reasons <= _REASON_INDEX.keys(),
        f"unknown parser reason(s): {sorted(reasons - _REASON_INDEX.keys())}",
    )
    return tuple(sorted(reasons, key=_REASON_INDEX.__getitem__))


def _contains_forbidden_codepoint(value: str) -> tuple[bool, bool]:
    """Return ``(has_control, has_non_ascii)`` without Unicode normalisation."""

    has_control = False
    has_non_ascii = False
    for character in value:
        codepoint = ord(character)
        # Include C0, DEL, and C1 controls.  The URI grammar is ASCII only.
        if codepoint < 0x20 or 0x7F <= codepoint <= 0x9F:
            has_control = True
        if codepoint > 0x7F:
            has_non_ascii = True
    return has_control, has_non_ascii


def is_canonical_origin(origin: Any) -> bool:
    """Return whether ``origin`` is an exact configured HTTPS origin.

    The origin is intentionally stricter than general URL parsing: it has no
    user information, path, query, fragment, trailing slash, Unicode, or
    defaulted/normalised spelling.  An explicit numeric port is allowed.
    """

    if type(origin) is not str or not origin.startswith("https://"):
        return False
    has_control, has_non_ascii = _contains_forbidden_codepoint(origin)
    if has_control or has_non_ascii or any(marker in origin for marker in ("%", "\\", "?", "#")):
        return False
    if origin.endswith("/"):
        return False
    try:
        parts = urlsplit(origin)
        port = parts.port
    except ValueError:
        return False
    if parts.scheme != "https" or not parts.netloc or parts.username or parts.password:
        return False
    if parts.path or parts.query or parts.fragment:
        return False
    if parts.hostname is None or not _HOST_RE.fullmatch(parts.hostname):
        return False
    if parts.hostname != parts.hostname.lower():
        return False
    if port is not None and not 1 <= port <= 65535:
        return False
    canonical_netloc = parts.hostname
    if port is not None:
        canonical_netloc += f":{port}"
    return origin == f"https://{canonical_netloc}"


def _candidate_kind(link: str, scheme: str | None) -> str | None:
    """Identify a candidate surface without treating it as valid."""

    if link.startswith("https://") or scheme == "https":
        return "web"
    if link.startswith("hermternal://") or scheme == "hermternal":
        return "native"
    return None


def redact_link(link: Any) -> str:
    """Return a non-reversible semantic diagnostic with no raw link material.

    The output intentionally omits the configured origin, every ID, query,
    fragment, and invalid suffix.  It records only the candidate surface and
    whether route-shaped session/message markers were present.
    """

    if type(link) is not str:
        return "deep-link[unknown;session=absent;message=absent]"
    try:
        scheme = urlsplit(link).scheme
    except ValueError:
        scheme = None
    kind = _candidate_kind(link, scheme) or "unknown"
    try:
        path = urlsplit(link).path
    except ValueError:
        path = ""
    route_shaped = path.startswith("/v1/c/")
    session = "present" if route_shaped else "absent"
    message = "present" if route_shaped and "/m/" in path else "absent"
    return f"deep-link[{kind};session={session};message={message}]"


def _raw_web_origin(parts: Any, link: str) -> str | None:
    """Extract the raw web origin without applying URL normalisation."""

    if not link.startswith("https://"):
        return None
    authority = link[len("https://") :].split("/", 1)[0]
    if not authority:
        return None
    return f"https://{authority}"


def _path_reason(path: str, reasons: set[str]) -> tuple[str | None, str | None]:
    """Validate route shape and return exact opaque IDs when available."""

    # A normalisation comparison is diagnostic only.  The original path is
    # never replaced with ``normpath`` and is never used for lookup.
    if posixpath.normpath(path) != path:
        reasons.add("normalization")

    if not path.startswith("/v1/c/"):
        if _VERSION_RE.match(path) and not path.startswith("/v1/"):
            reasons.add("version")
        else:
            reasons.add("path")
        return None, None

    tail = path[len("/v1/c/") :]
    segments = tail.split("/")
    if any(segment in {".", ".."} for segment in segments):
        reasons.add("traversal")
        # Dot segments are rejected before any ID extraction.  This avoids
        # accidentally treating a normalised target as the user's target.
        return None, None
    if any(segment == "" for segment in segments):
        reasons.add("segment")
        return None, None
    if len(segments) == 1:
        id_segments = (segments[0],)
    elif len(segments) == 3 and segments[1] == "m":
        id_segments = (segments[0], segments[2])
    else:
        reasons.add("path")
        return None, None

    validated: list[str] = []
    for value in id_segments:
        if not value or any(character not in _UNRESERVED for character in value):
            reasons.add("id_character")
            continue
        if len(value) < MIN_FULL_ID_LENGTH or "..." in value:
            reasons.add("full_id")
            continue
        validated.append(value)

    if reasons & {"id_character", "full_id", "normalization"}:
        # A normalisation violation is not a usable opaque target even if the
        # visible segments happen to look like IDs.
        return None, None
    if len(validated) == 1:
        return validated[0], None
    if len(validated) == 2:
        return validated[0], validated[1]
    return None, None


def parse_link(link: Any, configured_origin: str = DEFAULT_ORIGIN) -> LinkResult:
    """Parse one link without following it or normalising its components."""

    if type(link) is not str:
        return LinkResult(
            False,
            None,
            None,
            None,
            ("type",),
            redact_link(link),
        )

    reasons: set[str] = set()
    has_control, has_non_ascii = _contains_forbidden_codepoint(link)
    if has_control:
        reasons.add("control")
    if has_non_ascii:
        reasons.add("non_ascii")
    if "%" in link:
        reasons.add("percent_escape")
    if "\\" in link:
        reasons.add("backslash")
    if "?" in link:
        reasons.add("query")
    if "#" in link:
        reasons.add("fragment")

    try:
        parts = urlsplit(link)
        scheme = parts.scheme
    except ValueError:
        parts = None
        scheme = None
        reasons.add("authority")

    kind = _candidate_kind(link, scheme)
    if kind is None:
        reasons.add("scheme")
    elif kind == "web":
        if not link.startswith("https://"):
            reasons.add("scheme")
        if parts is None or not parts.netloc or parts.username or parts.password:
            reasons.add("authority")
        else:
            try:
                _ = parts.port
            except ValueError:
                reasons.add("authority")
        raw_origin = _raw_web_origin(parts, link) if parts is not None else None
        if link.startswith("https://") and (
            raw_origin != configured_origin or not is_canonical_origin(configured_origin)
        ):
            reasons.add("origin")
    else:  # native
        if not link.startswith("hermternal://"):
            reasons.add("scheme")
        if parts is None or parts.netloc != "open" or parts.username or parts.password:
            reasons.add("authority")
        else:
            try:
                if parts.port is not None:
                    reasons.add("authority")
            except ValueError:
                reasons.add("authority")

    path = parts.path if parts is not None else ""
    if path.endswith("/") or (link and link.endswith("/")):
        reasons.add("trailing_slash")

    ordered = _ordered_reasons(reasons)
    # These lexical violations are terminal.  Continuing would inspect or
    # partially decode an input that the grammar explicitly rejects.
    if reasons & _HARD_REASONS:
        return LinkResult(False, kind, None, None, ordered, redact_link(link))

    session_id: str | None = None
    message_id: str | None = None
    if parts is not None:
        session_id, message_id = _path_reason(path, reasons)
    ordered = _ordered_reasons(reasons)
    valid = not ordered
    return LinkResult(valid, kind, session_id, message_id, ordered, redact_link(link))


SESSION_1 = "synthetic-session-0001"
SESSION_2 = "synthetic-session-0002"
MESSAGE_1 = "synthetic-message-0001"
MESSAGE_2 = "synthetic-message-0002"

# These links and expected outcomes are frozen in code so changing both a
# fixture value and its expected result cannot make a mutation pass.
_EXPECTED_CASES: dict[str, dict[str, Any]] = {
    "valid-web-session": {
        "link": f"{DEFAULT_ORIGIN}/v1/c/{SESSION_1}",
        "expected": {
            "valid": True,
            "kind": "web",
            "session_id": SESSION_1,
            "message_id": None,
            "reasons": [],
            "diagnostic": "deep-link[web;session=present;message=absent]",
        },
    },
    "valid-web-message": {
        "link": f"{DEFAULT_ORIGIN}/v1/c/{SESSION_1}/m/{MESSAGE_1}",
        "expected": {
            "valid": True,
            "kind": "web",
            "session_id": SESSION_1,
            "message_id": MESSAGE_1,
            "reasons": [],
            "diagnostic": "deep-link[web;session=present;message=present]",
        },
    },
    "valid-native-session": {
        "link": f"hermternal://open/v1/c/{SESSION_2}",
        "expected": {
            "valid": True,
            "kind": "native",
            "session_id": SESSION_2,
            "message_id": None,
            "reasons": [],
            "diagnostic": "deep-link[native;session=present;message=absent]",
        },
    },
    "valid-native-message": {
        "link": f"hermternal://open/v1/c/{SESSION_2}/m/{MESSAGE_2}",
        "expected": {
            "valid": True,
            "kind": "native",
            "session_id": SESSION_2,
            "message_id": MESSAGE_2,
            "reasons": [],
            "diagnostic": "deep-link[native;session=present;message=present]",
        },
    },
    "wrong-origin": {
        "link": f"https://other.hermternal.test/v1/c/{SESSION_1}",
        "expected": {
            "valid": False,
            "kind": "web",
            "session_id": SESSION_1,
            "message_id": None,
            "reasons": ["origin"],
            "diagnostic": "deep-link[web;session=present;message=absent]",
        },
    },
    "native-authority": {
        "link": f"hermternal://not-open/v1/c/{SESSION_1}",
        "expected": {
            "valid": False,
            "kind": "native",
            "session_id": SESSION_1,
            "message_id": None,
            "reasons": ["authority"],
            "diagnostic": "deep-link[native;session=present;message=absent]",
        },
    },
    "wrong-scheme": {
        "link": f"http://synthetic.hermternal.test/v1/c/{SESSION_1}",
        "expected": {
            "valid": False,
            "kind": None,
            "session_id": SESSION_1,
            "message_id": None,
            "reasons": ["scheme"],
            "diagnostic": "deep-link[unknown;session=present;message=absent]",
        },
    },
    "uppercase-scheme": {
        "link": f"HTTPS://synthetic.hermternal.test/v1/c/{SESSION_1}",
        "expected": {
            "valid": False,
            "kind": "web",
            "session_id": SESSION_1,
            "message_id": None,
            "reasons": ["scheme"],
            "diagnostic": "deep-link[web;session=present;message=absent]",
        },
    },
    "unknown-version": {
        "link": f"{DEFAULT_ORIGIN}/v2/c/{SESSION_1}",
        "expected": {
            "valid": False,
            "kind": "web",
            "session_id": None,
            "message_id": None,
            "reasons": ["version"],
            "diagnostic": "deep-link[web;session=absent;message=absent]",
        },
    },
    "wrong-collection": {
        "link": f"{DEFAULT_ORIGIN}/v1/x/{SESSION_1}",
        "expected": {
            "valid": False,
            "kind": "web",
            "session_id": None,
            "message_id": None,
            "reasons": ["path"],
            "diagnostic": "deep-link[web;session=absent;message=absent]",
        },
    },
    "extra-segment": {
        "link": f"{DEFAULT_ORIGIN}/v1/c/{SESSION_1}/m/{MESSAGE_1}/extra",
        "expected": {
            "valid": False,
            "kind": "web",
            "session_id": None,
            "message_id": None,
            "reasons": ["path"],
            "diagnostic": "deep-link[web;session=present;message=present]",
        },
    },
    "short-session-id": {
        "link": f"{DEFAULT_ORIGIN}/v1/c/short",
        "expected": {
            "valid": False,
            "kind": "web",
            "session_id": None,
            "message_id": None,
            "reasons": ["full_id"],
            "diagnostic": "deep-link[web;session=present;message=absent]",
        },
    },
    "id-character": {
        "link": f"{DEFAULT_ORIGIN}/v1/c/{SESSION_1}+plus",
        "expected": {
            "valid": False,
            "kind": "web",
            "session_id": None,
            "message_id": None,
            "reasons": ["id_character"],
            "diagnostic": "deep-link[web;session=present;message=absent]",
        },
    },
    "percent-escape": {
        "link": f"{DEFAULT_ORIGIN}/v1/c/{SESSION_1}%2F",
        "expected": {
            "valid": False,
            "kind": "web",
            "session_id": None,
            "message_id": None,
            "reasons": ["percent_escape"],
            "diagnostic": "deep-link[web;session=present;message=absent]",
        },
    },
    "backslash": {
        "link": f"{DEFAULT_ORIGIN}/v1/c/{SESSION_1}\\bad",
        "expected": {
            "valid": False,
            "kind": "web",
            "session_id": None,
            "message_id": None,
            "reasons": ["backslash"],
            "diagnostic": "deep-link[web;session=present;message=absent]",
        },
    },
    "control": {
        "link": f"{DEFAULT_ORIGIN}/v1/c/{SESSION_1}",
        "expected": {
            "valid": False,
            "kind": "web",
            "session_id": None,
            "message_id": None,
            "reasons": ["control"],
            "diagnostic": "deep-link[web;session=present;message=absent]",
        },
    },
    "non-ascii": {
        "link": f"{DEFAULT_ORIGIN}/v1/c/synthetic-séssion-0001",
        "expected": {
            "valid": False,
            "kind": "web",
            "session_id": None,
            "message_id": None,
            "reasons": ["non_ascii"],
            "diagnostic": "deep-link[web;session=present;message=absent]",
        },
    },
    "query": {
        "link": f"{DEFAULT_ORIGIN}/v1/c/{SESSION_1}?mode=synthetic",
        "expected": {
            "valid": False,
            "kind": "web",
            "session_id": None,
            "message_id": None,
            "reasons": ["query"],
            "diagnostic": "deep-link[web;session=present;message=absent]",
        },
    },
    "fragment": {
        "link": f"hermternal://open/v1/c/{SESSION_2}#synthetic",
        "expected": {
            "valid": False,
            "kind": "native",
            "session_id": None,
            "message_id": None,
            "reasons": ["fragment"],
            "diagnostic": "deep-link[native;session=present;message=absent]",
        },
    },
    "query-and-fragment": {
        "link": f"{DEFAULT_ORIGIN}/v1/c/{SESSION_1}?mode=synthetic#anchor",
        "expected": {
            "valid": False,
            "kind": "web",
            "session_id": None,
            "message_id": None,
            "reasons": ["query", "fragment"],
            "diagnostic": "deep-link[web;session=present;message=absent]",
        },
    },
    "web-trailing-slash": {
        "link": f"{DEFAULT_ORIGIN}/v1/c/{SESSION_1}/",
        "expected": {
            "valid": False,
            "kind": "web",
            "session_id": None,
            "message_id": None,
            "reasons": ["trailing_slash"],
            "diagnostic": "deep-link[web;session=present;message=absent]",
        },
    },
    "native-trailing-slash": {
        "link": f"hermternal://open/v1/c/{SESSION_2}/",
        "expected": {
            "valid": False,
            "kind": "native",
            "session_id": None,
            "message_id": None,
            "reasons": ["trailing_slash"],
            "diagnostic": "deep-link[native;session=present;message=absent]",
        },
    },
    "traversal": {
        "link": f"{DEFAULT_ORIGIN}/v1/c/../m/{MESSAGE_1}",
        "expected": {
            "valid": False,
            "kind": "web",
            "session_id": None,
            "message_id": None,
            "reasons": ["traversal", "normalization"],
            "diagnostic": "deep-link[web;session=present;message=present]",
        },
    },
    "normalization": {
        "link": f"{DEFAULT_ORIGIN}/v1//c/{SESSION_1}",
        "expected": {
            "valid": False,
            "kind": "web",
            "session_id": None,
            "message_id": None,
            "reasons": ["path", "normalization"],
            "diagnostic": "deep-link[web;session=absent;message=absent]",
        },
    },
    "empty-session": {
        "link": f"{DEFAULT_ORIGIN}/v1/c//m/{MESSAGE_1}",
        "expected": {
            "valid": False,
            "kind": "web",
            "session_id": None,
            "message_id": None,
            "reasons": ["normalization", "segment"],
            "diagnostic": "deep-link[web;session=present;message=present]",
        },
    },
    "missing-message-id": {
        "link": f"{DEFAULT_ORIGIN}/v1/c/{SESSION_1}/m/",
        "expected": {
            "valid": False,
            "kind": "web",
            "session_id": None,
            "message_id": None,
            "reasons": ["trailing_slash"],
            "diagnostic": "deep-link[web;session=present;message=present]",
        },
    },
    "missing-anchor": {
        "link": f"{DEFAULT_ORIGIN}/v1/c/{SESSION_1}/m",
        "expected": {
            "valid": False,
            "kind": "web",
            "session_id": None,
            "message_id": None,
            "reasons": ["path"],
            "diagnostic": "deep-link[web;session=present;message=absent]",
        },
    },
    "origin-path": {
        "link": f"{DEFAULT_ORIGIN}/base/v1/c/{SESSION_1}",
        "expected": {
            "valid": False,
            "kind": "web",
            "session_id": None,
            "message_id": None,
            "reasons": ["path"],
            "diagnostic": "deep-link[web;session=absent;message=absent]",
        },
    },
}
EXPECTED_CASE_IDS = tuple(_EXPECTED_CASES)

_ROOT_KEYS = frozenset(
    {
        "schema",
        "contract",
        "synthetic",
        "configured_origin",
        "id_policy",
        "reason_order",
        "redaction",
        "cases",
    }
)
_ID_POLICY = {
    "alphabet": "unreserved-ascii",
    "minimum_length": MIN_FULL_ID_LENGTH,
    "opaque": True,
}
_REDACTION_POLICY = {
    "mode": "semantic-only",
    "raw_link": False,
    "origin": False,
    "ids": "omitted",
}


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Make duplicate JSON keys fail closed instead of silently overwriting."""

    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_document(path: Path | str = Path(__file__).with_name("cases.json")) -> dict[str, Any]:
    """Load one strict JSON document without network or source access."""

    path = Path(path)
    try:
        with path.open(encoding="utf-8") as stream:
            value = json.load(
                stream,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ContractError(f"non-finite JSON value: {value}")
                ),
            )
    except ContractError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"cannot load {path}: {exc}") from exc
    _require(type(value) is dict, "fixture root must be an object")
    return value


def _validate_expected_shape(expected: Any, path: str) -> None:
    _require(type(expected) is dict, f"{path} must be an object")
    required = {"valid", "kind", "session_id", "message_id", "reasons", "diagnostic"}
    _require(set(expected) == required, f"{path} has non-canonical keys")
    _require(type(expected["valid"]) is bool, f"{path}.valid must be boolean")
    _require(expected["kind"] is None or expected["kind"] in {"web", "native"}, f"{path}.kind invalid")
    for key in ("session_id", "message_id"):
        _require(expected[key] is None or type(expected[key]) is str, f"{path}.{key} invalid")
    _require(type(expected["reasons"]) is list, f"{path}.reasons must be a list")
    _require(all(type(reason) is str for reason in expected["reasons"]), f"{path}.reasons entries must be strings")
    _require(type(expected["diagnostic"]) is str, f"{path}.diagnostic must be a string")


def validate_case(case: Any) -> None:
    """Validate one fixture case against the frozen case inventory."""

    _require(type(case) is dict, "case must be an object")
    _require(set(case) == {"id", "synthetic", "link", "expected"}, "case has non-canonical keys")
    case_id = case["id"]
    _require(type(case_id) is str, "case.id must be a string")
    _require(case_id in _EXPECTED_CASES, f"unknown case id: {case_id!r}")
    _require(case["synthetic"] is True, f"{case_id}: fixture is not synthetic")
    _require(type(case["link"]) is str, f"{case_id}: link must be a string")
    _validate_expected_shape(case["expected"], f"{case_id}.expected")

    frozen = _EXPECTED_CASES[case_id]
    _require(case["link"] == frozen["link"], f"{case_id}: link changed from frozen fixture")
    _require(_strict_equal(case["expected"], frozen["expected"]), f"{case_id}: expected result changed")

    actual = parse_link(case["link"], DEFAULT_ORIGIN).as_dict()
    _require(_strict_equal(actual, case["expected"]), f"{case_id}: parser result mismatch")
    _require(case["expected"]["diagnostic"] == redact_link(case["link"]), f"{case_id}: unsafe diagnostic")
    for identifier in (case["expected"]["session_id"], case["expected"]["message_id"]):
        if identifier is not None:
            _require(identifier not in case["expected"]["diagnostic"], f"{case_id}: raw ID in diagnostic")


def validate_document(document: Mapping[str, Any]) -> None:
    """Validate the complete strict recursive fixture schema."""

    _require(type(document) is dict, "fixture root must be an object")
    _require(set(document) == _ROOT_KEYS, "fixture root has non-canonical keys")
    _require(document["schema"] == SCHEMA, "fixture schema is not pinned")
    _require(document["contract"] == CONTRACT, "fixture contract is not pinned")
    _require(document["synthetic"] is True, "fixture set must be synthetic")
    _require(document["configured_origin"] == DEFAULT_ORIGIN, "configured origin changed")
    _require(is_canonical_origin(document["configured_origin"]), "configured origin is not canonical")
    _require(_strict_equal(document["id_policy"], _ID_POLICY), "ID policy changed")
    _require(_strict_equal(document["redaction"], _REDACTION_POLICY), "redaction policy changed")
    _require(document["reason_order"] == list(REASON_ORDER), "reason order changed")

    cases = document["cases"]
    _require(type(cases) is list, "fixture cases must be a list")
    _require([case.get("id") if type(case) is dict else None for case in cases] == list(EXPECTED_CASE_IDS), "case inventory/order changed")
    for index, case in enumerate(cases):
        validate_case(case)
        _require(case["id"] == EXPECTED_CASE_IDS[index], f"cases[{index}] changed order")


def validate_mutations(document: Mapping[str, Any]) -> int:
    """Run executable mutation regressions against the frozen schema."""

    mutations: tuple[tuple[str, Callable[[dict[str, Any]], None]], ...] = (
        ("root extra key", lambda value: value.update({"extra": True})),
        ("root synthetic false", lambda value: value.update({"synthetic": False})),
        ("origin mutation", lambda value: value.update({"configured_origin": "https://evil.test"})),
        ("ID bool mutation", lambda value: value["id_policy"].update({"minimum_length": True})),
        ("reason order mutation", lambda value: value["reason_order"].reverse()),
        ("redaction mutation", lambda value: value["redaction"].update({"raw_link": True})),
        ("case order mutation", lambda value: value["cases"].reverse()),
        ("case extra key", lambda value: value["cases"][0].update({"extra": "synthetic"})),
        ("case synthetic false", lambda value: value["cases"][0].update({"synthetic": False})),
        ("link mutation", lambda value: value["cases"][0].update({"link": value["cases"][0]["link"] + "/"})),
        ("expected valid mutation", lambda value: value["cases"][0]["expected"].update({"valid": False})),
        ("expected reason mutation", lambda value: value["cases"][4]["expected"].update({"reasons": ["path"]})),
        ("diagnostic raw link", lambda value: value["cases"][0]["expected"].update({"diagnostic": value["cases"][0]["link"]})),
        ("nested expected key", lambda value: value["cases"][0]["expected"].update({"raw": "synthetic"})),
        ("case ID mutation", lambda value: value["cases"][0].update({"id": "renamed"})),
    )
    completed = 0
    for label, mutate in mutations:
        mutated = copy.deepcopy(dict(document))
        mutate(mutated)
        try:
            validate_document(mutated)
        except ContractError:
            completed += 1
        else:
            raise ContractError(f"mutation accepted: {label}")
    return completed


def main(argv: list[str] | None = None) -> int:
    """Validate fixtures and mutation controls for normal or ``-O`` runs."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=Path(__file__).with_name("cases.json"))
    args = parser.parse_args(argv)
    document = load_document(args.cases)
    validate_document(document)
    mutation_count = validate_mutations(document)
    print(f"deep_link_cases={len(document['cases'])}")
    print(f"deep_link_mutation_checks={mutation_count}")
    print("deep_link_validation=ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
