#!/usr/bin/env python3
"""Validate the P0-01 planning review without network or live Hermes access.

The review is source evidence, not a deployment probe. Keeping the validator
stdlib-only and local makes a missing checkout, changed source file, or missing
planning reference fail closed instead of silently accepting an unreviewed
revision.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any


EXPECTED_SOURCE_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
EXPECTED_CONTRACT = "dashboard-v0.0.1"
REVIEW_NAME = "planning_review.json"
EXPECTED_REQUIRED_LINKS = [
    {
        "path": "contracts/fixtures/README.md",
        "literal": "source-audit/planning-reconciliation/planning_review.json",
    },
    {
        "path": "contracts/hermes-dashboard/README.md",
        "literal": "source-audit/planning-reconciliation/planning_review.json",
    },
    {
        "path": "contracts/hermes-dashboard/manifest.md",
        "literal": "source-audit/planning-reconciliation/planning_review.json",
    },
    {
        "path": "docs/product/v0.0.1.md",
        "literal": "source-audit/planning-reconciliation/planning_review.json",
    },
    {
        "path": "docs/protocol/compatibility.md",
        "literal": "source-audit/planning-reconciliation/planning_review.json",
    },
]
EXPECTED_CLAIMS = [
    {
        "id": "auth-bootstrap",
        "status": "verified",
        "source_files": ["hermes_cli/dashboard_auth/routes.py"],
        "docs": [
            "contracts/hermes-dashboard/manifest.md",
            "docs/product/v0.0.1.md",
            "docs/protocol/compatibility.md",
        ],
        "summary": "The pinned source exposes the reviewed browser, provider-discovery, native authorization, identity, logout, ticket, and native-token route names.",
    },
    {
        "id": "ticket-lifecycle",
        "status": "verified",
        "source_files": [
            "hermes_cli/dashboard_auth/ws_tickets.py",
            "hermes_cli/dashboard_auth/routes.py",
        ],
        "docs": [
            "contracts/hermes-dashboard/manifest.md",
            "docs/protocol/compatibility.md",
            "contracts/fixtures/README.md",
        ],
        "summary": "Gated WebSocket tickets are 30-second, single-use values; invalid-ticket diagnostics retain only an eight-character fragment.",
    },
    {
        "id": "session-rest-surface",
        "status": "verified",
        "source_files": ["hermes_cli/web_routers/sessions.py"],
        "docs": [
            "contracts/hermes-dashboard/manifest.md",
            "docs/product/v0.0.1.md",
        ],
        "summary": "The selected list, search, read, messages, and metadata-patch REST routes exist at the pinned source.",
    },
    {
        "id": "chat-rpc-surface",
        "status": "verified",
        "source_files": [
            "tui_gateway/ws.py",
            "tui_gateway/methods_prompt.py",
            "tui_gateway/methods_session.py",
            "tui_gateway/methods_complete.py",
            "tui_gateway/server.py",
        ],
        "docs": [
            "contracts/hermes-dashboard/manifest.md",
            "docs/protocol/compatibility.md",
            "contracts/state-models/chat.md",
        ],
        "summary": "The reviewed JSON-RPC method, stream-event, ready-event, and parse/dispatch error anchors exist in the pinned gateway.",
    },
    {
        "id": "model-switch",
        "status": "verified",
        "source_files": ["tui_gateway/methods_complete.py", "tui_gateway/server.py"],
        "docs": [
            "contracts/hermes-dashboard/manifest.md",
            "docs/product/v0.0.1.md",
            "contracts/state-models/chat.md",
        ],
        "summary": "Model options are exposed, config.set recognizes the model key, and a pending switch is consumed with an expensive-choice warning instead of being silently applied.",
    },
    {
        "id": "pty-lifecycle",
        "status": "verified",
        "source_files": [
            "hermes_cli/web_server.py",
            "hermes_cli/pty_bridge.py",
            "hermes_cli/pty_session.py",
        ],
        "docs": [
            "contracts/hermes-dashboard/manifest.md",
            "docs/product/v0.0.1.md",
            "docs/protocol/compatibility.md",
            "contracts/state-models/terminal.md",
        ],
        "summary": "The web-only PTY route, resize bounds, 30-minute detached TTL, 1 MiB replay cap, detach behavior, and observable close codes are present at the pinned source.",
    },
    {
        "id": "image-attachment-boundary",
        "status": "verified",
        "source_files": ["hermes_cli/web_server.py"],
        "docs": [
            "contracts/hermes-dashboard/manifest.md",
            "docs/product/v0.0.1.md",
        ],
        "summary": "The selected image upload route exists; arbitrary file and filesystem routes remain outside this source review's allowlist.",
    },
    {
        "id": "source-identity",
        "status": "verified",
        "source_files": ["hermes_cli/web_server.py"],
        "docs": [
            "contracts/hermes-dashboard/manifest.md",
            "docs/protocol/compatibility.md",
        ],
        "summary": "The reviewed Dashboard source contains no server-observable Hermes source-SHA or dashboard protocol-version field, so deployment attestation remains out of band.",
    },
]
EXPECTED_CLAIMS_BY_ID = {claim["id"]: claim for claim in EXPECTED_CLAIMS}
ALLOWED_CLAIM_IDS = frozenset(EXPECTED_CLAIMS_BY_ID)
ALLOWED_CLAIM_STATUSES = frozenset(claim["status"] for claim in EXPECTED_CLAIMS)
EXPECTED_CLAIM_ID_ORDER = tuple(claim["id"] for claim in EXPECTED_CLAIMS)


def load_review(path: Path) -> dict[str, Any]:
    """Load and structurally validate the review record before using it."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read review record {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("review record must be a JSON object")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_head(source_root: Path) -> str | None:
    """Read a local checkout's HEAD; never fetch or consult a remote."""
    try:
        result = subprocess.run(
            ["git", "-C", str(source_root), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _line_numbers(text: str, literal: str) -> list[int]:
    return [
        number
        for number, line in enumerate(text.splitlines(), start=1)
        if literal in line
    ]


def _is_unsafe_relative_path(value: str) -> bool:
    """Reject platform-specific absolute paths and lexical parent traversal."""
    posix = PurePosixPath(value.replace("\\", "/"))
    windows = PureWindowsPath(value)
    return (
        Path(value).is_absolute()
        or posix.is_absolute()
        or windows.is_absolute()
        or any(part == ".." for part in posix.parts)
        or any(part == ".." for part in windows.parts)
    )


def _resolve_under_root(
    root: Path,
    relative: str,
    label: str,
    errors: list[str],
) -> Path | None:
    """Resolve a metadata path and reject symlinks that escape its approved root."""
    if not relative or _is_unsafe_relative_path(relative):
        errors.append(
            f"{label} must be relative, contain no '..', and remain under its approved root: {relative!r}"
        )
        return None
    try:
        resolved_root = root.resolve(strict=False)
        resolved = (resolved_root / relative).resolve(strict=False)
        resolved.relative_to(resolved_root)
    except (OSError, RuntimeError, ValueError):
        errors.append(f"{label} resolves outside its approved root: {relative!r}")
        return None
    return resolved


def _validate_claims(review: dict[str, Any], errors: list[str]) -> None:
    if "claims" not in review:
        errors.append("review.claims is required")
        return
    claims = review["claims"]
    if not isinstance(claims, list) or not claims:
        errors.append("review.claims must be a non-empty list")
        return

    claim_ids: list[str] = []
    for claim in claims:
        if not isinstance(claim, dict):
            errors.append("review.claims contains a non-object")
            continue
        claim_id = claim.get("id")
        if claim_id not in ALLOWED_CLAIM_IDS:
            errors.append(f"review.claims contains an unknown id: {claim_id!r}")
            continue
        claim_ids.append(claim_id)
        status = claim.get("status")
        if status not in ALLOWED_CLAIM_STATUSES:
            errors.append(f"claim {claim_id!r} has a disallowed status: {status!r}")
        expected = EXPECTED_CLAIMS_BY_ID[claim_id]
        if status != expected["status"]:
            errors.append(
                f"claim {claim_id!r} status does not match the pinned review: "
                f"expected {expected['status']!r}, found {status!r}"
            )
        if claim != expected:
            errors.append(f"claim {claim_id!r} content does not match the pinned review")

    if tuple(claim_ids) != EXPECTED_CLAIM_ID_ORDER:
        errors.append("review.claims ids/order do not match the pinned review")


def _validate_shape(review: dict[str, Any], errors: list[str]) -> None:
    source = review.get("source")
    if not isinstance(source, dict):
        errors.append("review.source must be an object")
    else:
        if source.get("repository") != "NousResearch/hermes-agent":
            errors.append("review.source.repository is not the pinned Hermes repository")
        if source.get("sha") != EXPECTED_SOURCE_SHA:
            errors.append("review.source.sha does not match the contract pin")
    if review.get("contract") != EXPECTED_CONTRACT:
        errors.append("review.contract is not dashboard-v0.0.1")

    planning_docs = review.get("planning_docs")
    if not isinstance(planning_docs, list) or not planning_docs or not all(
        isinstance(item, str) and item for item in planning_docs
    ):
        errors.append("review.planning_docs must be a non-empty list of paths")
    else:
        if len(set(planning_docs)) != len(planning_docs):
            errors.append("review.planning_docs contains duplicate paths")
        for relative in planning_docs:
            if _is_unsafe_relative_path(relative):
                errors.append(
                    f"planning document path must remain under the repo root: {relative!r}"
                )

    required_links = review.get("required_links")
    if required_links is None:
        errors.append("review.required_links is required")
    elif not isinstance(required_links, list):
        errors.append("review.required_links must be a list")
    elif required_links != EXPECTED_REQUIRED_LINKS:
        errors.append("review.required_links does not match the exact expected links")

    source_files = review.get("source_files")
    if not isinstance(source_files, list) or not source_files:
        errors.append("review.source_files must be a non-empty list")
    else:
        seen: set[str] = set()
        for entry in source_files:
            if not isinstance(entry, dict):
                errors.append("review.source_files contains a non-object")
                continue
            path = entry.get("path")
            if not isinstance(path, str) or not path or _is_unsafe_relative_path(path):
                errors.append(
                    f"source entry path must remain under the pinned source root: {path!r}"
                )
            elif path in seen:
                errors.append(f"review.source_files duplicates {path}")
            else:
                seen.add(path)
            digest = entry.get("sha256")
            if not isinstance(digest, str) or len(digest) != 64:
                errors.append(f"review.source_files[{path!r}] has an invalid sha256")
            anchors = entry.get("anchors", [])
            if not isinstance(anchors, list):
                errors.append(f"review.source_files[{path!r}].anchors must be a list")
            for anchor in anchors:
                if not isinstance(anchor, dict) or not isinstance(
                    anchor.get("literal"), str
                ):
                    errors.append(f"review.source_files[{path!r}] has an invalid anchor")
            absent = entry.get("absent", [])
            if not isinstance(absent, list) or not all(
                isinstance(item, str) and item for item in absent
            ):
                errors.append(f"review.source_files[{path!r}].absent must be a list")

    _validate_claims(review, errors)


def _validate_docs(repo_root: Path, review: dict[str, Any], errors: list[str]) -> None:
    for relative in review.get("planning_docs", []):
        if not isinstance(relative, str):
            continue
        path = _resolve_under_root(repo_root, relative, "planning document path", errors)
        if path is None:
            continue
        if not path.is_file():
            errors.append(f"missing planning document: {relative}")

    links = review.get("required_links", [])
    if not isinstance(links, list):
        return
    for link in links:
        if not isinstance(link, dict):
            continue
        relative = link.get("path")
        literal = link.get("literal")
        if not isinstance(relative, str) or not isinstance(literal, str):
            continue
        path = _resolve_under_root(repo_root, relative, "required-link path", errors)
        if path is None:
            continue
        if not path.is_file():
            errors.append(f"required-link document is missing: {relative}")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            errors.append(f"cannot read required-link document {relative}: {exc}")
            continue
        if literal not in text:
            errors.append(f"{relative} does not link the planning review record")


def _validate_source(
    source_root: Path, review: dict[str, Any], errors: list[str]
) -> str | None:
    if not source_root.is_dir():
        errors.append(f"source root is missing: {source_root}")
        return None

    head = _git_head(source_root)
    if head != EXPECTED_SOURCE_SHA:
        found = head or "unavailable"
        errors.append(
            "source checkout HEAD does not match "
            f"{EXPECTED_SOURCE_SHA} (found {found})"
        )

    for entry in review.get("source_files", []):
        if not isinstance(entry, dict):
            continue
        relative = entry.get("path")
        if not isinstance(relative, str):
            continue
        path = _resolve_under_root(source_root, relative, "source entry path", errors)
        if path is None:
            continue
        if not path.is_file():
            errors.append(f"missing pinned source file: {relative}")
            continue
        actual_digest = _sha256(path)
        expected_digest = entry.get("sha256")
        if actual_digest != expected_digest:
            errors.append(
                f"source digest mismatch for {relative}: "
                f"expected {expected_digest}, found {actual_digest}"
            )
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"cannot read pinned source file {relative}: {exc}")
            continue
        for anchor in entry.get("anchors", []):
            if not isinstance(anchor, dict):
                continue
            literal = anchor.get("literal")
            if not isinstance(literal, str):
                continue
            locations = _line_numbers(text, literal)
            if not locations:
                errors.append(
                    f"missing source anchor {anchor.get('id', literal)!r} in {relative}"
                )
            elif isinstance(anchor.get("line"), int) and anchor["line"] not in locations:
                errors.append(
                    f"source anchor {anchor.get('id', literal)!r} moved in {relative}: "
                    f"expected line {anchor['line']}, found {locations}"
                )
        for literal in entry.get("absent", []):
            if literal in text:
                errors.append(f"forbidden source field {literal!r} found in {relative}")
    return head


def validate_review(
    repo_root: Path,
    review_path: Path,
    source_root: Path | None,
    *,
    require_source: bool = True,
) -> tuple[list[str], str | None, float]:
    """Return errors, observed source HEAD, and local validation duration."""
    started = time.perf_counter()
    errors: list[str] = []
    try:
        review = load_review(review_path)
    except ValueError as exc:
        return [str(exc)], None, (time.perf_counter() - started) * 1000

    _validate_shape(review, errors)
    _validate_docs(repo_root, review, errors)
    head = None
    if require_source:
        if source_root is None:
            errors.append("source root is required for full validation")
        else:
            head = _validate_source(source_root, review, errors)
    return errors, head, (time.perf_counter() - started) * 1000


def _default_repo_root() -> Path:
    # validate.py lives four directories below the repository root.
    return Path(__file__).resolve().parents[4]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=_default_repo_root(),
        help="Hermternal checkout containing the planning documents",
    )
    parser.add_argument(
        "--review",
        type=Path,
        default=None,
        help="review JSON path (defaults to this directory's planning_review.json)",
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        default=None,
        help="local Hermes checkout at the pinned SHA; no network is used",
    )
    parser.add_argument(
        "--check-docs-only",
        action="store_true",
        help="check document links without source validation",
    )
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()
    review_path = (
        args.review.resolve()
        if args.review is not None
        else Path(__file__).resolve().with_name(REVIEW_NAME)
    )
    source_root = None if args.check_docs_only else (
        args.source_root.resolve() if args.source_root is not None else None
    )
    errors, head, duration_ms = validate_review(
        repo_root,
        review_path,
        source_root,
        require_source=not args.check_docs_only,
    )
    result = {
        "ok": not errors,
        "review": str(review_path),
        "source_head": head,
        "duration_ms": round(duration_ms, 3),
        "errors": errors,
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
