#!/usr/bin/env python3
"""Inventory the web prototype's dependencies without contacting any service.

The audit deliberately reads only ``apps/web/package.json`` and ``apps/web/bun.lock``.
It reports what those local artifacts prove: exact declarations, resolved lock
records, dependency reachability, and Bun integrity strings. License and privacy
results are review gaps when the local artifacts do not carry that evidence; they
are not conclusions about package behavior or legal status. The terminal check
keeps W-Term/Ghostty in the web-only runtime boundary, while leaving source and
runtime behavior to the existing terminal proof.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import errno
import hashlib
import json
import os
import re
import stat
import sys
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence


SCHEMA = "hermternal.dependency-audit.v1"
DEFAULT_MANIFEST = Path("apps/web/package.json")
DEFAULT_LOCKFILE = Path("apps/web/bun.lock")
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MAX_INPUT_BYTES = 1 * 1024 * 1024
MAX_PACKAGE_COUNT = 4_096
MAX_DEPENDENCY_EDGES = 65_536
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_SECONDS = 10.0
MAX_STRING_LENGTH = 8_192
MAX_PACKAGE_NAME_LENGTH = 256
MAX_SPEC_LENGTH = 512

LIMITS = {
    "max_input_bytes_each": MAX_INPUT_BYTES,
    "max_package_count": MAX_PACKAGE_COUNT,
    "max_dependency_edges": MAX_DEPENDENCY_EDGES,
    "max_output_bytes": MAX_OUTPUT_BYTES,
    "max_seconds": MAX_SECONDS,
}

SEMVER_NUMERIC = re.compile(r"^(?:0|[1-9][0-9]*)$")
SEMVER_IDENTIFIER = re.compile(r"^[0-9A-Za-z-]+$")
PACKAGE_NAME = re.compile(r"^@?[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)?$")
# Bun v1 uses virtual locator keys such as
# ``@testing-library/dom/aria-query`` when two versions coexist. Those keys
# are not npm names, but their path segments remain bounded and package-like.
LOCK_KEY = re.compile(r"^[A-Za-z0-9@._~+-]+(?:/[A-Za-z0-9@._~+-]+)*$")
INTEGRITY = re.compile(r"^sha(?:1|256|384|512)-[A-Za-z0-9+/]+={0,2}$")
INTEGRITY_DIGEST_LENGTHS = {"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}
SAFE_OUTPUT_TOKEN = re.compile(r"[^A-Za-z0-9@._+:/~*^<>=| -]")

DEPENDENCY_FIELDS = ("dependencies", "optionalDependencies", "peerDependencies")
TERMINAL_PACKAGES = ("@wterm/dom", "@wterm/ghostty")

REASONS = {
    "manifest-read-failed": "The manifest could not be read as a bounded local file.",
    "lockfile-read-failed": "The lockfile could not be read as a bounded local file.",
    "manifest-path-invalid": "The manifest path was outside the approved repository tree or used a symlink.",
    "lockfile-path-invalid": "The lockfile path was outside the approved repository tree or used a symlink.",
    "manifest-not-regular": "The manifest path was not a regular file.",
    "lockfile-not-regular": "The lockfile path was not a regular file.",
    "manifest-too-large": "The manifest exceeded the local input bound.",
    "lockfile-too-large": "The lockfile exceeded the local input bound.",
    "manifest-invalid-utf8": "The manifest was not valid UTF-8.",
    "lockfile-invalid-utf8": "The lockfile was not valid UTF-8.",
    "manifest-json-invalid": "The manifest was not valid JSON or supported Bun JSON5 syntax.",
    "lockfile-json-invalid": "The lockfile was not valid JSON or supported Bun JSON5 syntax.",
    "manifest-json5-unsupported": "The manifest used valid Bun JSON5 syntax outside this bounded parser subset.",
    "lockfile-json5-unsupported": "The lockfile used valid Bun JSON5 syntax outside this bounded parser subset.",
    "manifest-duplicate-key": "The manifest contained a duplicate object key.",
    "lockfile-duplicate-key": "The lockfile contained a duplicate object key.",
    "manifest-shape-invalid": "The manifest dependency sections had an invalid shape.",
    "lockfile-shape-invalid": "The lockfile workspace or package records had an invalid shape.",
    "unsupported-lock-version": "The audit supports only Bun lockfile version 1.",
    "invalid-config-version": "The Bun lockfile configVersion was not a bounded non-negative integer.",
    "manifest-lock-mismatch": "Manifest dependency declarations did not match the lockfile workspace root.",
    "manifest-unpinned": "A direct manifest dependency does not use an exact version or exact npm alias.",
    "lock-entry-unpinned": "A lockfile package record does not resolve to an exact semantic version.",
    "missing-integrity": "A lockfile package record has no integrity string.",
    "invalid-integrity": "A lockfile package record has an unrecognised integrity string.",
    "package-resolution-missing": "A declared dependency has no matching local lockfile package record.",
    "package-resolution-ambiguous": "A dependency matched more than one local lockfile package record.",
    "dependency-edge-limit": "The dependency graph exceeded the local edge bound.",
    "package-count-limit": "The lockfile exceeded the local package-count bound.",
    "audit-time-limit": "The offline audit exceeded its local time bound.",
    "unreachable-lock-entry": "A lockfile package was not reachable from the workspace dependency roots.",
    "terminal-boundary-role-mismatch": "A W-Term package is not declared as a web runtime dependency.",
    "license-review-metadata-missing": "The local dependency artifacts do not contain complete license review metadata.",
    "privacy-review-metadata-missing": "The web workspace does not contain a machine-readable dependency privacy review register.",
    "terminal-runtime-proof-not-inventory-scope": "The inventory cannot prove source-level lazy loading or runtime-only terminal behavior.",
    "output-too-large": "The sanitized audit report exceeded its output bound.",
    "cli-error": "The command line did not match the supported local audit shape.",
    "internal-error": "The local audit stopped without exposing implementation details.",
}


class AuditError(ValueError):
    """Stable internal failure code; caller-visible text comes from ``REASONS``."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class DuplicateKeyError(ValueError):
    pass


class Budget:
    """Bound graph work as well as bytes so hostile local fixtures cannot loop forever."""

    def __init__(self) -> None:
        self.deadline = time.monotonic() + MAX_SECONDS
        self.edges = 0

    def check_time(self) -> None:
        if time.monotonic() > self.deadline:
            raise AuditError("audit-time-limit")

    def add_edge(self) -> None:
        self.edges += 1
        if self.edges > MAX_DEPENDENCY_EDGES:
            raise AuditError("dependency-edge-limit")
        self.check_time()


@dataclass(frozen=True)
class LockPackage:
    key: str
    resolved_name: str
    version: str
    metadata: Mapping[str, Any]
    integrity: Optional[str]
    integrity_valid: bool
    dependencies: Mapping[str, Mapping[str, str]]
    optional_peers: frozenset[str]


@dataclass(frozen=True)
class SemVer:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()

    @property
    def core(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)


@dataclass(frozen=True)
class RangeTerm:
    operator: str
    version: SemVer
    wildcards: tuple[bool, bool, bool] = (False, False, False)


@dataclass(frozen=True)
class ParsedInputs:
    manifest: Mapping[str, Any]
    lockfile: Mapping[str, Any]
    config_version: int
    packages: Mapping[str, LockPackage]
    manifest_dependencies: Mapping[str, str]
    manifest_dev_dependencies: Mapping[str, str]
    manifest_optional_dependencies: Mapping[str, str]
    lock_dependencies: Mapping[str, str]
    lock_dev_dependencies: Mapping[str, str]
    lock_optional_dependencies: Mapping[str, str]


def _reject_constant(_value: str) -> Any:
    raise ValueError("non-finite-number")


def _object_from_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(key)
        result[key] = value
    return result


def _strip_bun_json5(text: str) -> str:
    """Strip the supported Bun JSON5 subset without silently rewriting others.

    Bun lockfiles use JSON with comments and trailing commas. A string-aware pass
    avoids the common unsafe regex mistake of changing a package name or
    integrity string that happens to contain punctuation resembling a trailing
    comma. Other valid JSON5 forms are rejected explicitly rather than being
    silently normalized into a different document.
    """

    output: list[str] = []
    index = 0
    length = len(text)
    in_string = False
    while index < length:
        char = text[index]
        if in_string:
            output.append(char)
            if char == "\\":
                index += 1
                if index >= length:
                    raise ValueError("unterminated-escape")
                output.append(text[index])
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            output.append(char)
            index += 1
            continue
        if char == "'":
            raise ValueError("unsupported-json5")
        if (
            (char == "+" and not (index > 0 and text[index - 1] in "eE" and index + 1 < length and text[index + 1].isdigit()))
            or (
                char == "."
                and index + 1 < length
                and text[index + 1].isdigit()
                and (index == 0 or not text[index - 1].isdigit())
            )
            or (
                char == "."
                and index > 0
                and text[index - 1].isdigit()
                and (
                    index + 1 == length
                    or text[index + 1] in " \t\r\n,}]"
                    or text[index + 1] in "eE"
                )
            )
        ):
            raise ValueError("unsupported-json5")
        if char == "-" and index + 1 < length and text[index + 1] == ".":
            raise ValueError("unsupported-json5")
        if char == "0" and index + 1 < length and text[index + 1] in "xX":
            raise ValueError("unsupported-json5")
        if char.isalpha() or char in "_$":
            token_end = index + 1
            while token_end < length and (text[token_end].isalnum() or text[token_end] in "_$"):
                token_end += 1
            token = text[index:token_end]
            lookahead = token_end
            while lookahead < length and text[lookahead] in " \t\r\n":
                lookahead += 1
            if token in {"Infinity", "NaN"} or (lookahead < length and text[lookahead] == ":"):
                raise ValueError("unsupported-json5")
        if char == "/" and index + 1 < length and text[index + 1] in ("/", "*"):
            if text[index + 1] == "/":
                index += 2
                while index < length and text[index] not in "\r\n":
                    index += 1
                continue
            end = text.find("*/", index + 2)
            if end < 0:
                raise ValueError("unterminated-comment")
            index = end + 2
            continue
        if char == ",":
            lookahead = index + 1
            while lookahead < length and text[lookahead] in " \t\r\n":
                lookahead += 1
            if lookahead < length and text[lookahead] in "}]":
                index += 1
                continue
        output.append(char)
        index += 1
    if in_string:
        raise ValueError("unterminated-string")
    return "".join(output)


def _parse_document(data: bytes, input_name: str) -> Mapping[str, Any]:
    if len(data) > MAX_INPUT_BYTES:
        raise AuditError(f"{input_name}-too-large")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AuditError(f"{input_name}-invalid-utf8") from error
    try:
        normalized = _strip_bun_json5(text)
        parsed = json.loads(
            normalized,
            object_pairs_hook=_object_from_pairs,
            parse_constant=_reject_constant,
        )
    except DuplicateKeyError as error:
        raise AuditError(f"{input_name}-duplicate-key") from error
    except ValueError as error:
        if str(error) == "unsupported-json5":
            raise AuditError(f"{input_name}-json5-unsupported") from error
        raise AuditError(f"{input_name}-json-invalid") from error
    except (TypeError, RecursionError) as error:
        raise AuditError(f"{input_name}-json-invalid") from error
    if not isinstance(parsed, dict):
        raise AuditError(f"{input_name}-shape-invalid")
    return parsed


def _require_string(value: Any, *, max_length: int) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise AuditError("lockfile-shape-invalid")
    if any(ord(char) < 0x20 for char in value):
        raise AuditError("lockfile-shape-invalid")
    return value


def _require_package_name(name: Any) -> str:
    if not isinstance(name, str) or len(name) > MAX_PACKAGE_NAME_LENGTH or not PACKAGE_NAME.fullmatch(name):
        raise AuditError("lockfile-shape-invalid")
    return name


def _require_lock_key(name: Any) -> str:
    if not isinstance(name, str) or len(name) > MAX_PACKAGE_NAME_LENGTH or not LOCK_KEY.fullmatch(name):
        raise AuditError("lockfile-shape-invalid")
    if any(segment in {"", ".", ".."} for segment in name.split("/")):
        raise AuditError("lockfile-shape-invalid")
    return name


def _valid_integrity(value: str) -> bool:
    match = INTEGRITY.fullmatch(value)
    if match is None:
        return False
    algorithm, encoded = value.split("-", 1)
    try:
        digest = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(digest) == INTEGRITY_DIGEST_LENGTHS[algorithm]


def _require_config_version(value: Any) -> int:
    if type(value) is not int or value < 0 or value > (2**31 - 1):
        raise AuditError("invalid-config-version")
    return value


def _require_dependency_map(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise AuditError("lockfile-shape-invalid")
    if len(value) > MAX_PACKAGE_COUNT:
        raise AuditError("package-count-limit")
    result: dict[str, str] = {}
    for raw_name, raw_spec in value.items():
        name = _require_package_name(raw_name)
        if not isinstance(raw_spec, str) or not raw_spec or len(raw_spec) > MAX_SPEC_LENGTH:
            raise AuditError("lockfile-shape-invalid")
        result[name] = raw_spec
    return result


def _parse_manifest(document: Mapping[str, Any]) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    dependencies = _require_dependency_map(document.get("dependencies", {}))
    dev_dependencies = _require_dependency_map(document.get("devDependencies", {}))
    optional_dependencies = _require_dependency_map(document.get("optionalDependencies", {}))
    return dependencies, dev_dependencies, optional_dependencies


def _split_descriptor(descriptor: str, fallback_name: str) -> tuple[str, str]:
    if "@" not in descriptor:
        return fallback_name, ""
    separator = descriptor.rfind("@")
    if separator <= 0 or separator == len(descriptor) - 1:
        return fallback_name, ""
    descriptor_name = descriptor[:separator]
    version = descriptor[separator + 1 :]
    if descriptor_name.startswith("npm:"):
        descriptor_name = descriptor_name[4:]
    return descriptor_name, version


def _parse_lock_packages(document: Mapping[str, Any]) -> dict[str, LockPackage]:
    lock_version = document.get("lockfileVersion")
    # Python considers True equal to 1, so the type check is part of the
    # lockfile contract rather than a cosmetic validation detail.
    if type(lock_version) is not int or lock_version != 1:
        raise AuditError("unsupported-lock-version")
    workspaces = document.get("workspaces")
    if not isinstance(workspaces, dict) or not isinstance(workspaces.get(""), dict):
        raise AuditError("lockfile-shape-invalid")
    packages_value = document.get("packages")
    if not isinstance(packages_value, dict):
        raise AuditError("lockfile-shape-invalid")
    if len(packages_value) > MAX_PACKAGE_COUNT:
        raise AuditError("package-count-limit")

    packages: dict[str, LockPackage] = {}
    for raw_key, raw_record in packages_value.items():
        key = _require_lock_key(raw_key)
        if not isinstance(raw_record, list) or len(raw_record) < 3:
            raise AuditError("lockfile-shape-invalid")
        descriptor = raw_record[0]
        if not isinstance(descriptor, str) or len(descriptor) > MAX_STRING_LENGTH:
            raise AuditError("lockfile-shape-invalid")
        resolved_name, version = _split_descriptor(descriptor, key)
        if not PACKAGE_NAME.fullmatch(resolved_name):
            raise AuditError("lockfile-shape-invalid")
        metadata = raw_record[2]
        if not isinstance(metadata, dict):
            raise AuditError("lockfile-shape-invalid")
        dependencies: dict[str, Mapping[str, str]] = {}
        for field in DEPENDENCY_FIELDS:
            dependencies[field] = _require_dependency_map(metadata.get(field, {}))
        optional_peers_value = metadata.get("optionalPeers", [])
        if not isinstance(optional_peers_value, list):
            raise AuditError("lockfile-shape-invalid")
        optional_peers = frozenset(_require_package_name(name) for name in optional_peers_value)

        raw_integrity = raw_record[3] if len(raw_record) > 3 else None
        if raw_integrity is None or raw_integrity == "":
            integrity = None
            integrity_valid = False
        elif not isinstance(raw_integrity, str):
            raise AuditError("lockfile-shape-invalid")
        else:
            integrity = raw_integrity
            integrity_valid = _valid_integrity(raw_integrity)
        if key in packages:
            raise AuditError("lockfile-shape-invalid")
        packages[key] = LockPackage(
            key=key,
            resolved_name=resolved_name,
            version=version,
            metadata=metadata,
            integrity=integrity,
            integrity_valid=integrity_valid,
            dependencies=dependencies,
            optional_peers=optional_peers,
        )
    return packages


def _parse_inputs(manifest_document: Mapping[str, Any], lockfile_document: Mapping[str, Any]) -> ParsedInputs:
    manifest_dependencies, manifest_dev_dependencies, manifest_optional_dependencies = _parse_manifest(manifest_document)
    config_version = _require_config_version(lockfile_document.get("configVersion"))
    packages = _parse_lock_packages(lockfile_document)
    workspaces = lockfile_document["workspaces"]
    root = workspaces[""]
    if not isinstance(root, dict):
        raise AuditError("lockfile-shape-invalid")
    lock_dependencies = _require_dependency_map(root.get("dependencies", {}))
    lock_dev_dependencies = _require_dependency_map(root.get("devDependencies", {}))
    lock_optional_dependencies = _require_dependency_map(root.get("optionalDependencies", {}))
    return ParsedInputs(
        manifest=manifest_document,
        lockfile=lockfile_document,
        config_version=config_version,
        packages=packages,
        manifest_dependencies=manifest_dependencies,
        manifest_dev_dependencies=manifest_dev_dependencies,
        manifest_optional_dependencies=manifest_optional_dependencies,
        lock_dependencies=lock_dependencies,
        lock_dev_dependencies=lock_dev_dependencies,
        lock_optional_dependencies=lock_optional_dependencies,
    )


def _parse_semver(value: str, *, allow_v: bool = False) -> Optional[SemVer]:
    if not isinstance(value, str) or not value:
        return None
    token = value
    if token.startswith("v"):
        if not allow_v or token.startswith("vv"):
            return None
        token = token[1:]
    if "+" in token:
        if token.count("+") != 1:
            return None
        token, build = token.split("+", 1)
        if not build or any(not SEMVER_IDENTIFIER.fullmatch(part) for part in build.split(".")):
            return None
    if "-" in token:
        core, prerelease_text = token.split("-", 1)
        prerelease = tuple(prerelease_text.split("."))
        if not prerelease_text or any(
            not SEMVER_IDENTIFIER.fullmatch(part)
            or (part.isdigit() and not SEMVER_NUMERIC.fullmatch(part))
            for part in prerelease
        ):
            return None
    else:
        core = token
        prerelease = ()
    parts = core.split(".")
    if len(parts) != 3 or any(not SEMVER_NUMERIC.fullmatch(part) for part in parts):
        return None
    return SemVer(*(int(part) for part in parts), prerelease=prerelease)


def _is_pinned_spec(spec: str) -> bool:
    if _parse_semver(spec) is not None:
        return True
    if not spec.startswith("npm:"):
        return False
    alias = spec[4:]
    separator = alias.rfind("@")
    return separator > 0 and _parse_semver(alias[separator + 1 :]) is not None


def _expected_alias_target(spec: str) -> Optional[str]:
    if not spec.startswith("npm:"):
        return None
    alias = spec[4:]
    separator = alias.rfind("@")
    if separator <= 0:
        return None
    target = alias[:separator]
    return target if PACKAGE_NAME.fullmatch(target) else None


def _expected_alias_version(spec: str) -> Optional[str]:
    if not spec.startswith("npm:"):
        return None
    separator = spec.rfind("@")
    if separator <= 4:
        return None
    version = spec[separator + 1 :]
    return version if _parse_semver(version) is not None else None


def _expected_exact_version(spec: str) -> Optional[str]:
    return spec if _parse_semver(spec) is not None else _expected_alias_version(spec)


def _numeric_version(value: str) -> Optional[tuple[int, int, int]]:
    """Return the numeric semver core used by bounded local resolution."""

    parsed = _parse_semver(value)
    return parsed.core if parsed is not None else None


def _parse_range_version(value: str) -> tuple[SemVer, tuple[bool, bool, bool]]:
    token = value.strip()
    if not token:
        raise ValueError("range-version")
    if token.startswith("v"):
        if token.startswith("vv"):
            raise ValueError("range-version")
        token = token[1:]
    if "+" in token:
        if token.count("+") != 1:
            raise ValueError("range-version")
        token, _build = token.split("+", 1)
        if not _build:
            raise ValueError("range-version")
    if "-" in token:
        parsed = _parse_semver(token)
        if parsed is None:
            raise ValueError("range-version")
        return parsed, (False, False, False)
    parts = token.split(".")
    if not 1 <= len(parts) <= 3:
        raise ValueError("range-version")
    numbers: list[int] = []
    wildcards: list[bool] = []
    wildcard_seen = False
    for part in parts:
        if part.lower() in {"x", "*"}:
            wildcard_seen = True
            numbers.append(0)
            wildcards.append(True)
        elif SEMVER_NUMERIC.fullmatch(part) and not wildcard_seen:
            numbers.append(int(part))
            wildcards.append(False)
        else:
            raise ValueError("range-version")
    while len(numbers) < 3:
        numbers.append(0)
        wildcards.append(True)
    return SemVer(*numbers), tuple(wildcards)  # type: ignore[return-value]


def _compare_semver(left: SemVer, right: SemVer) -> int:
    if left.core != right.core:
        return (left.core > right.core) - (left.core < right.core)
    if not left.prerelease and not right.prerelease:
        return 0
    if not left.prerelease:
        return 1
    if not right.prerelease:
        return -1
    for left_part, right_part in zip(left.prerelease, right.prerelease):
        if left_part == right_part:
            continue
        left_numeric = left_part.isdigit()
        right_numeric = right_part.isdigit()
        if left_numeric and right_numeric:
            return (int(left_part) > int(right_part)) - (int(left_part) < int(right_part))
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return (left_part > right_part) - (left_part < right_part)
    return (len(left.prerelease) > len(right.prerelease)) - (len(left.prerelease) < len(right.prerelease))


def _parse_range_alternative(expression: str) -> list[RangeTerm]:
    expression = expression.strip()
    if not expression:
        raise ValueError("range-alternative")
    if expression.startswith("^") or expression.startswith("~"):
        if len(expression) == 1 or any(char.isspace() for char in expression[1:]):
            raise ValueError("range-alternative")
        version, wildcards = _parse_range_version(expression[1:])
        return [RangeTerm(expression[0], version, wildcards)]
    tokens = expression.split()
    if not tokens:
        raise ValueError("range-alternative")
    terms: list[RangeTerm] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        operator = "="
        if token in {">=", ">", "<=", "<", "="}:
            operator = token
            index += 1
            if index >= len(tokens):
                raise ValueError("range-comparator")
            token = tokens[index]
        else:
            match = re.fullmatch(r"(>=|<=|>|<|=)(.+)", token)
            if match:
                operator, token = match.groups()
        version, wildcards = _parse_range_version(token)
        terms.append(RangeTerm(operator, version, wildcards))
        index += 1
    return terms


def _caret_upper(version: SemVer, wildcards: tuple[bool, bool, bool]) -> tuple[int, int, int]:
    if wildcards[0]:
        return (version.major + 1, 0, 0)
    if version.major > 0:
        return (version.major + 1, 0, 0)
    if wildcards[1] or version.minor > 0:
        return (0, version.minor + 1, 0)
    return (0, 0, version.patch + 1)


def _tilde_upper(version: SemVer, wildcards: tuple[bool, bool, bool]) -> tuple[int, int, int]:
    if wildcards[0]:
        return (version.major + 1, 0, 0)
    if wildcards[1]:
        return (version.major + 1, 0, 0)
    return (version.major, version.minor + 1, 0)


def _matches_wildcards(actual: SemVer, version: SemVer, wildcards: tuple[bool, bool, bool]) -> bool:
    return all(wildcards[index] or actual.core[index] == version.core[index] for index in range(3))


def _matches_term(actual: SemVer, term: RangeTerm) -> bool:
    if term.operator == "*":
        return _matches_wildcards(actual, term.version, term.wildcards)
    if term.operator == "=":
        if any(term.wildcards):
            return _matches_wildcards(actual, term.version, term.wildcards)
        return _compare_semver(actual, term.version) == 0
    if term.operator in {">=", ">", "<", "<="}:
        comparison = _compare_semver(actual, term.version)
        return {
            ">=": comparison >= 0,
            ">": comparison > 0,
            "<": comparison < 0,
            "<=": comparison <= 0,
        }[term.operator]
    if term.operator in {"^", "~"}:
        lower = _compare_semver(actual, term.version) >= 0
        upper_core = _caret_upper(term.version, term.wildcards) if term.operator == "^" else _tilde_upper(term.version, term.wildcards)
        upper = actual.core < upper_core
        return lower and upper
    return False


def _range_matches(version: str, specification: str) -> bool:
    """Match a strict bounded subset of npm semver ranges.

    The parser accepts only exact numeric components, one optional ``v`` prefix,
    caret/tilde ranges, comparator sets, wildcard forms, and unions of those
    forms. Every union arm must parse. Prerelease candidates are excluded unless
    that arm contains an explicit prerelease identifier.
    """

    actual = _parse_semver(version)
    if actual is None:
        return False
    alternatives = specification.split("||")
    if any(not alternative.strip() for alternative in alternatives):
        return False
    parsed_alternatives: list[list[RangeTerm]] = []
    for alternative in alternatives:
        try:
            parsed_alternatives.append(_parse_range_alternative(alternative))
        except ValueError:
            # A union is only supported when every arm is understood. Do not
            # accept a valid arm while silently ignoring unsupported syntax.
            return False
    for terms in parsed_alternatives:
        if actual.prerelease and not any(term.version.prerelease for term in terms):
            continue
        if all(_matches_term(actual, term) for term in terms):
            return True
    return False


def _resolve_package(
    name: str,
    spec: str,
    packages: Mapping[str, LockPackage],
    *,
    parent_key: Optional[str] = None,
) -> LockPackage:
    alias_target = _expected_alias_target(spec)
    if spec.startswith("npm:"):
        if alias_target is None:
            raise AuditError("package-resolution-missing")
        # An npm alias is identified by the dependency name in the lock key,
        # while its descriptor carries the target package name. Bind both
        # identities before applying the exact target version below.
        candidates = [
            record
            for key, record in packages.items()
            if key == name and record.resolved_name == alias_target
        ]
    else:
        candidates = [record for key, record in packages.items() if key == name or record.resolved_name == name]
    expected_version = _expected_exact_version(spec)
    if expected_version is not None:
        candidates = [record for record in candidates if record.version == expected_version]
    else:
        # An unsupported or unsatisfied range is not evidence for the highest
        # local version. An empty match must remain empty so resolution fails
        # closed instead of silently inventing a package-manager decision.
        candidates = [record for record in candidates if _range_matches(record.version, spec)]
    # Bun records a parent-scoped virtual key when a range resolves to a
    # version different from the workspace's top-level copy. Prefer that key
    # before applying the deterministic highest-version choice below.
    if parent_key is not None:
        scoped_key = f"{parent_key}/{name}"
        scoped = [record for record in candidates if record.key == scoped_key]
        if len(scoped) == 1:
            return scoped[0]
    if not candidates:
        raise AuditError("package-resolution-missing")
    candidates.sort(key=lambda record: (_numeric_version(record.version) or (-1, -1, -1), record.key), reverse=True)
    return candidates[0]


def _safe_token(value: Any, *, max_length: int = MAX_STRING_LENGTH, fallback: str = "<invalid>") -> str:
    if not isinstance(value, str):
        return fallback
    token = SAFE_OUTPUT_TOKEN.sub("?", value)
    if not token:
        return fallback
    return token[:max_length]


def _safe_label(label: Any, fallback: str) -> str:
    if not isinstance(label, str) or not label or len(label) > MAX_STRING_LENGTH:
        return fallback
    normalized = label.replace("\\", "/")
    if normalized.startswith("/") or ".." in normalized.split("/"):
        return fallback
    pieces = [piece for piece in normalized.split("/") if piece]
    if not pieces or any(not re.fullmatch(r"[A-Za-z0-9._-]+", piece) for piece in pieces):
        return fallback
    return "/".join(pieces)


def _input_record(label: str, data: Optional[bytes]) -> dict[str, Any]:
    return {
        "path": label,
        "bytes": len(data) if data is not None else None,
        "sha256": hashlib.sha256(data).hexdigest() if data is not None else None,
    }


def _base_result(manifest_record: dict[str, Any], lock_record: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": "fail",
        "ok": False,
        "review_required": False,
        "completed": False,
        "offline": True,
        "network_access": False,
        "online_vulnerability_scan": "not_run",
        "claims": {"vulnerabilities": "not_assessed_offline", "online_cve_audit": "not_run"},
        "inputs": {"manifest": manifest_record, "lockfile": lock_record},
        "limits": dict(LIMITS),
        "summary": {
            "direct_runtime": 0,
            "direct_dev": 0,
            "direct_optional": 0,
            "transitive": 0,
            "reachable": 0,
            "locked": 0,
            "unreachable": 0,
        },
        "inventory": {"direct": {"runtime": [], "dev": [], "optional": []}, "transitive": []},
        "lockfile": {
            "lockfile_version": None,
            "config_version": None,
            "optional_dependencies": {},
            "package_count": 0,
            "integrity_present": 0,
            "integrity_missing": [],
            "integrity_invalid": [],
            "unpinned": [],
            "unreachable": [],
            "dependency_edges": 0,
            "peer_dependency_gaps": [],
        },
        "terminal_boundary": {
            "boundary": "web-only-terminal",
            "scope": "apps/web",
            "excluded_clients": ["ios", "ipados", "macos"],
            "assessment": "not_assessed",
            "packages": {},
            "source_behavior": "not_assessed_by_dependency_inventory",
        },
        "findings": [],
    }


def _finding(code: str, severity: str, *, package: Optional[str] = None, count: Optional[int] = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "code": code,
        "severity": severity,
        "reason": REASONS.get(code, REASONS["internal-error"]),
    }
    if package is not None:
        result["package"] = _safe_token(package, max_length=MAX_PACKAGE_NAME_LENGTH)
    if count is not None:
        result["count"] = max(0, int(count))
    return result


def _dedupe_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[tuple[Any, ...], dict[str, Any]] = {}
    for finding in findings:
        key = (finding.get("severity"), finding.get("code"), finding.get("package"), finding.get("count"))
        unique[key] = finding
    severity_order = {"blocking": 0, "review": 1}
    return sorted(
        unique.values(),
        key=lambda item: (
            severity_order.get(str(item.get("severity")), 2),
            str(item.get("code", "")),
            str(item.get("package", "")),
            int(item.get("count", 0)),
        ),
    )


def _package_output(record: LockPackage, *, requested: Optional[str] = None, roles: Sequence[str] = ()) -> dict[str, Any]:
    dependency_counts = {
        field: len(record.dependencies.get(field, {})) for field in DEPENDENCY_FIELDS
    }
    result: dict[str, Any] = {
        "name": record.key,
        "resolved_name": record.resolved_name,
        "resolved_version": _safe_token(record.version, max_length=MAX_SPEC_LENGTH),
        "integrity": _safe_token(record.integrity, max_length=MAX_STRING_LENGTH, fallback="<missing>") if record.integrity is not None else None,
        "integrity_present": record.integrity is not None and record.integrity_valid,
        "dependency_counts": dependency_counts,
        "roles": sorted(set(roles)),
    }
    if requested is not None:
        result["requested"] = _safe_token(requested, max_length=MAX_SPEC_LENGTH)
        result["pinned"] = _is_pinned_spec(requested)
    return result


def _assess_terminal_boundary(
    inputs: ParsedInputs,
    direct_records: Mapping[str, Mapping[str, LockPackage]],
    reachable: Mapping[str, set[str]],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    packages: dict[str, Any] = {}
    all_present = True
    runtime_ok = True
    for name in TERMINAL_PACKAGES:
        record = inputs.packages.get(name)
        runtime_record = direct_records.get("runtime", {}).get(name)
        dev_record = direct_records.get("dev", {}).get(name)
        if record is None:
            all_present = False
            packages[name] = {
                "declared": False,
                "web_runtime": False,
                "status": "not_present",
            }
            continue
        is_runtime = runtime_record is not None
        runtime_ok = runtime_ok and is_runtime
        if not is_runtime:
            findings.append(_finding("terminal-boundary-role-mismatch", "blocking", package=name))
        packages[name] = {
            "declared": True,
            "web_runtime": is_runtime,
            "dev_only": dev_record is not None and not is_runtime,
            "requested": _safe_token(
                inputs.manifest_dependencies.get(name, inputs.manifest_dev_dependencies.get(name, "<not-declared>")),
                max_length=MAX_SPEC_LENGTH,
            ),
            "resolved_version": _safe_token(record.version, max_length=MAX_SPEC_LENGTH),
            "integrity_present": record.integrity is not None and record.integrity_valid,
            "reachable_roles": sorted(reachable.get(name, set())),
            "status": "pinned_runtime" if is_runtime and _is_pinned_spec(inputs.manifest_dependencies.get(name, "")) else "review",
        }
    core = inputs.packages.get("@wterm/core")
    core_reachable = core is not None and "@wterm/core" in reachable
    assessment = "pinned_web_runtime" if all_present and runtime_ok and core_reachable else "review"
    if all_present and runtime_ok:
        # The inventory has no source parser by design. Keep this residual explicit
        # instead of converting the manifest/lock evidence into a lazy-loading claim.
        findings.append(_finding("terminal-runtime-proof-not-inventory-scope", "review"))
    return {
        "boundary": "web-only-terminal",
        "scope": "apps/web",
        "excluded_clients": ["ios", "ipados", "macos"],
        "assessment": assessment,
        "packages": packages,
        "transitive_support": {"@wterm/core": core_reachable},
        "source_behavior": "not_assessed_by_dependency_inventory",
    }


def _audit_parsed(inputs: ParsedInputs, manifest_record: dict[str, Any], lock_record: dict[str, Any]) -> dict[str, Any]:
    result = _base_result(manifest_record, lock_record)
    findings: list[dict[str, Any]] = []
    budget = Budget()

    if (
        dict(inputs.manifest_dependencies) != dict(inputs.lock_dependencies)
        or dict(inputs.manifest_dev_dependencies) != dict(inputs.lock_dev_dependencies)
        or dict(inputs.manifest_optional_dependencies) != dict(inputs.lock_optional_dependencies)
    ):
        findings.append(_finding("manifest-lock-mismatch", "blocking"))

    for role, dependencies in (
        ("runtime", inputs.manifest_dependencies),
        ("dev", inputs.manifest_dev_dependencies),
        ("optional", inputs.manifest_optional_dependencies),
    ):
        for name, spec in sorted(dependencies.items()):
            budget.check_time()
            if not _is_pinned_spec(spec):
                findings.append(_finding("manifest-unpinned", "blocking", package=name))

    integrity_missing: list[str] = []
    integrity_invalid: list[str] = []
    unpinned: list[str] = []
    for key, record in sorted(inputs.packages.items()):
        budget.check_time()
        if record.integrity is None:
            integrity_missing.append(key)
            findings.append(_finding("missing-integrity", "blocking", package=key))
        elif not record.integrity_valid:
            integrity_invalid.append(key)
            findings.append(_finding("invalid-integrity", "blocking", package=key))
        if _parse_semver(record.version) is None:
            unpinned.append(key)
            findings.append(_finding("lock-entry-unpinned", "blocking", package=key))

    direct_records: dict[str, dict[str, LockPackage]] = {"runtime": {}, "dev": {}, "optional": {}}
    root_specs: dict[str, dict[str, str]] = {
        "runtime": dict(inputs.manifest_dependencies),
        "dev": dict(inputs.manifest_dev_dependencies),
        "optional": dict(inputs.manifest_optional_dependencies),
    }
    reachable: dict[str, set[str]] = {}
    queue: deque[tuple[str, str]] = deque()
    for role in ("runtime", "dev", "optional"):
        for name, spec in sorted(root_specs[role].items()):
            try:
                record = _resolve_package(name, spec, inputs.packages)
            except AuditError as error:
                findings.append(_finding(error.code, "blocking", package=name))
                continue
            direct_records[role][name] = record
            if record.key not in reachable:
                reachable[record.key] = set()
            reachable[record.key].add(role)
            queue.append((record.key, role))

    peer_gaps: list[dict[str, Any]] = []
    while queue:
        budget.check_time()
        current_key, role = queue.popleft()
        current = inputs.packages[current_key]
        for field in DEPENDENCY_FIELDS:
            for dependency_name, dependency_spec in sorted(current.dependencies.get(field, {}).items()):
                budget.add_edge()
                try:
                    target = _resolve_package(
                        dependency_name,
                        dependency_spec,
                        inputs.packages,
                        parent_key=current.key,
                    )
                except AuditError as error:
                    is_optional_peer = field == "peerDependencies" and dependency_name in current.optional_peers
                    if field == "peerDependencies":
                        peer_gaps.append(
                            {
                                "package": current.key,
                                "dependency": dependency_name,
                                "optional": is_optional_peer,
                                "status": error.code,
                            }
                        )
                    if not is_optional_peer:
                        findings.append(_finding(error.code, "blocking", package=dependency_name))
                    continue
                target_roles = reachable.setdefault(target.key, set())
                was_new_role = role not in target_roles
                target_roles.add(role)
                if was_new_role:
                    queue.append((target.key, role))

    unreachable = sorted(set(inputs.packages) - set(reachable))
    for key in unreachable:
        findings.append(_finding("unreachable-lock-entry", "review", package=key))
        # Reachability controls inventory membership, not resource accounting.
        # Count every parsed edge, including edges on records that are already
        # unreachable, so an adversarial disconnected graph cannot bypass the
        # global traversal budget.
        record = inputs.packages[key]
        for field in DEPENDENCY_FIELDS:
            for _dependency_name in record.dependencies.get(field, {}):
                budget.add_edge()

    license_missing = sum(
        1
        for record in inputs.packages.values()
        if not record.metadata.get("license") and not record.metadata.get("licenses")
    )
    if license_missing:
        findings.append(_finding("license-review-metadata-missing", "review", count=license_missing))

    privacy_keys = ("privacyReview", "privacy_review", "dataFlow", "data_flow")
    if not any(key in inputs.manifest for key in privacy_keys):
        findings.append(_finding("privacy-review-metadata-missing", "review"))

    result["terminal_boundary"] = _assess_terminal_boundary(inputs, direct_records, reachable, findings)
    result["findings"] = _dedupe_findings(findings)
    result["review_required"] = any(item["severity"] == "review" for item in result["findings"])
    blocking = [item for item in result["findings"] if item["severity"] == "blocking"]
    result["ok"] = not blocking
    result["status"] = "fail" if blocking else ("review" if result["review_required"] else "pass")
    result["completed"] = True

    direct_output: dict[str, list[dict[str, Any]]] = {"runtime": [], "dev": [], "optional": []}
    for role in ("runtime", "dev", "optional"):
        for name in sorted(root_specs[role]):
            record = direct_records[role].get(name)
            if record is None:
                direct_output[role].append(
                    {
                        "name": _safe_token(name, max_length=MAX_PACKAGE_NAME_LENGTH),
                        "requested": _safe_token(root_specs[role][name], max_length=MAX_SPEC_LENGTH),
                        "pinned": _is_pinned_spec(root_specs[role][name]),
                        "resolution": "missing",
                    }
                )
            else:
                direct_output[role].append(
                    _package_output(record, requested=root_specs[role][name], roles=(role,))
                )
    transitive_output = [
        _package_output(inputs.packages[key], roles=tuple(sorted(reachable[key])))
        for key in sorted(reachable)
        if key not in {record.key for records in direct_records.values() for record in records.values()}
    ]

    result["summary"] = {
        "direct_runtime": len(inputs.manifest_dependencies),
        "direct_dev": len(inputs.manifest_dev_dependencies),
        "direct_optional": len(inputs.manifest_optional_dependencies),
        "transitive": len(transitive_output),
        "reachable": len(reachable),
        "locked": len(inputs.packages),
        "unreachable": len(unreachable),
    }
    result["inventory"] = {"direct": direct_output, "transitive": transitive_output}
    result["lockfile"] = {
        "lockfile_version": inputs.lockfile.get("lockfileVersion"),
        "config_version": inputs.config_version,
        "optional_dependencies": {
            _safe_token(name, max_length=MAX_PACKAGE_NAME_LENGTH): _safe_token(
                spec,
                max_length=MAX_SPEC_LENGTH,
            )
            for name, spec in sorted(inputs.lock_optional_dependencies.items())
        },
        "package_count": len(inputs.packages),
        "integrity_present": len(inputs.packages) - len(integrity_missing) - len(integrity_invalid),
        "integrity_missing": integrity_missing,
        "integrity_invalid": integrity_invalid,
        "unpinned": unpinned,
        "unreachable": unreachable,
        "dependency_edges": budget.edges,
        "peer_dependency_gaps": sorted(peer_gaps, key=lambda item: (item["package"], item["dependency"])),
    }
    return result


def _fallback_failure(
    code: str,
    *,
    manifest_record: Optional[dict[str, Any]] = None,
    lock_record: Optional[dict[str, Any]] = None,
    input_name: Optional[str] = None,
) -> dict[str, Any]:
    result = _base_result(
        manifest_record or _input_record("apps/web/package.json", None),
        lock_record or _input_record("apps/web/bun.lock", None),
    )
    result["findings"] = [
        _finding(code, "blocking", package=input_name) if input_name else _finding(code, "blocking")
    ]
    result["completed"] = False
    result["status"] = "fail"
    result["ok"] = False
    return result


def audit_bytes(
    manifest_bytes: bytes,
    lockfile_bytes: bytes,
    *,
    manifest_label: str = "apps/web/package.json",
    lockfile_label: str = "apps/web/bun.lock",
) -> dict[str, Any]:
    """Audit bounded synthetic or checked-in bytes; no filesystem or network access occurs."""

    manifest_record = _input_record(_safe_label(manifest_label, "apps/web/package.json"), manifest_bytes)
    lock_record = _input_record(_safe_label(lockfile_label, "apps/web/bun.lock"), lockfile_bytes)
    try:
        manifest_document = _parse_document(manifest_bytes, "manifest")
    except AuditError as error:
        return _fallback_failure(error.code, manifest_record=manifest_record, lock_record=lock_record, input_name="manifest")
    try:
        lockfile_document = _parse_document(lockfile_bytes, "lockfile")
    except AuditError as error:
        return _fallback_failure(error.code, manifest_record=manifest_record, lock_record=lock_record, input_name="lockfile")
    try:
        inputs = _parse_inputs(manifest_document, lockfile_document)
        result = _audit_parsed(inputs, manifest_record, lock_record)
    except AuditError as error:
        return _fallback_failure(error.code, manifest_record=manifest_record, lock_record=lock_record)
    except (KeyError, TypeError, ValueError, RecursionError):
        return _fallback_failure("internal-error", manifest_record=manifest_record, lock_record=lock_record)
    return result


def _relative_input_parts(path: Path, input_name: str) -> tuple[str, ...]:
    candidate = path if path.is_absolute() else REPOSITORY_ROOT / path
    try:
        relative = candidate.relative_to(REPOSITORY_ROOT)
    except ValueError as error:
        raise AuditError(f"{input_name}-path-invalid") from error
    parts = relative.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise AuditError(f"{input_name}-path-invalid")
    return parts


def _read_bounded(path: Path, input_name: str) -> bytes:
    parts = _relative_input_parts(path, input_name)
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        parent_fd = os.open(REPOSITORY_ROOT, directory_flags)
    except OSError as error:
        raise AuditError(f"{input_name}-read-failed") from error
    try:
        for part in parts[:-1]:
            try:
                child_fd = os.open(part, directory_flags, dir_fd=parent_fd)
            except OSError as error:
                if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise AuditError(f"{input_name}-path-invalid") from error
                raise AuditError(f"{input_name}-read-failed") from error
            os.close(parent_fd)
            parent_fd = child_fd
        try:
            file_fd = os.open(parts[-1], file_flags, dir_fd=parent_fd)
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise AuditError(f"{input_name}-path-invalid") from error
            raise AuditError(f"{input_name}-read-failed") from error
        try:
            if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                raise AuditError(f"{input_name}-not-regular")
            chunks: list[bytes] = []
            remaining = MAX_INPUT_BYTES + 1
            while remaining:
                chunk = os.read(file_fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
        except AuditError:
            raise
        except (OSError, ValueError) as error:
            raise AuditError(f"{input_name}-read-failed") from error
        finally:
            os.close(file_fd)
    finally:
        os.close(parent_fd)
    if len(data) > MAX_INPUT_BYTES:
        raise AuditError(f"{input_name}-too-large")
    return data


def audit_files(manifest_path: Path = DEFAULT_MANIFEST, lockfile_path: Path = DEFAULT_LOCKFILE) -> dict[str, Any]:
    manifest_label = "apps/web/package.json" if manifest_path.name == "package.json" else "input/package.json"
    lock_label = "apps/web/bun.lock" if lockfile_path.name == "bun.lock" else "input/bun.lock"
    try:
        manifest_bytes = _read_bounded(manifest_path, "manifest")
    except AuditError as error:
        return _fallback_failure(error.code, manifest_record=_input_record(manifest_label, None), lock_record=_input_record(lock_label, None), input_name="manifest")
    try:
        lockfile_bytes = _read_bounded(lockfile_path, "lockfile")
    except AuditError as error:
        return _fallback_failure(error.code, manifest_record=_input_record(manifest_label, manifest_bytes), lock_record=_input_record(lock_label, None), input_name="lockfile")
    return audit_bytes(manifest_bytes, lockfile_bytes, manifest_label=manifest_label, lockfile_label=lock_label)


def _serialise_with_limit(result: Mapping[str, Any]) -> tuple[str, bool]:
    text = json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    if len(text.encode("utf-8")) <= MAX_OUTPUT_BYTES:
        return text, False
    fallback = _fallback_failure("output-too-large")
    return json.dumps(fallback, ensure_ascii=True, sort_keys=True, separators=(",", ":")), True


def _serialise(result: Mapping[str, Any]) -> str:
    return _serialise_with_limit(result)[0]


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise AuditError("cli-error")


def _parse_arguments(argv: Optional[Sequence[str]]) -> tuple[Path, Path]:
    parser = _ArgumentParser(add_help=False)
    parser.add_argument("manifest", nargs="?")
    parser.add_argument("lockfile", nargs="?")
    try:
        namespace = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as error:
        raise AuditError("cli-error") from error
    if namespace.manifest is None:
        manifest = DEFAULT_MANIFEST
    else:
        manifest = Path(namespace.manifest)
    if namespace.lockfile is None:
        lockfile = DEFAULT_LOCKFILE
    else:
        lockfile = Path(namespace.lockfile)
    return manifest, lockfile


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        manifest_path, lockfile_path = _parse_arguments(argv)
        result = audit_files(manifest_path, lockfile_path)
    except AuditError as error:
        result = _fallback_failure(error.code)
    except (OSError, ValueError, TypeError, RecursionError):
        result = _fallback_failure("internal-error")
    text, output_limited = _serialise_with_limit(result)
    print(text)
    return 1 if output_limited or result.get("status") == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
