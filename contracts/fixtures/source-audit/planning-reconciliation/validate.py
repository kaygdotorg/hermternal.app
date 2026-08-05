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
from pathlib import Path
from typing import Any


EXPECTED_SOURCE_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
EXPECTED_CONTRACT = "dashboard-v0.0.1"
REVIEW_NAME = "planning_review.json"


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


def _validate_shape(review: dict[str, Any], errors: list[str]) -> None:
    source = review.get("source")
    if not isinstance(source, dict):
        errors.append("review.source must be an object")
        return
    if source.get("repository") != "NousResearch/hermes-agent":
        errors.append("review.source.repository is not the pinned Hermes repository")
    if source.get("sha") != EXPECTED_SOURCE_SHA:
        errors.append("review.source.sha does not match the contract pin")
    if review.get("contract") != EXPECTED_CONTRACT:
        errors.append("review.contract is not dashboard-v0.0.1")

    planning_docs = review.get("planning_docs")
    if not isinstance(planning_docs, list) or not all(
        isinstance(item, str) and item for item in planning_docs
    ):
        errors.append("review.planning_docs must be a non-empty list of paths")
    elif len(set(planning_docs)) != len(planning_docs):
        errors.append("review.planning_docs contains duplicate paths")

    source_files = review.get("source_files")
    if not isinstance(source_files, list) or not source_files:
        errors.append("review.source_files must be a non-empty list")
        return
    seen: set[str] = set()
    for entry in source_files:
        if not isinstance(entry, dict):
            errors.append("review.source_files contains a non-object")
            continue
        path = entry.get("path")
        if not isinstance(path, str) or not path or Path(path).is_absolute():
            errors.append("review.source_files contains an invalid path")
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


def _validate_docs(repo_root: Path, review: dict[str, Any], errors: list[str]) -> None:
    for relative in review.get("planning_docs", []):
        path = repo_root / relative
        if not path.is_file():
            errors.append(f"missing planning document: {relative}")

    links = review.get("required_links", [])
    if not isinstance(links, list):
        errors.append("review.required_links must be a list")
        return
    for link in links:
        if not isinstance(link, dict):
            errors.append("review.required_links contains a non-object")
            continue
        relative = link.get("path")
        literal = link.get("literal")
        if not isinstance(relative, str) or not isinstance(literal, str):
            errors.append("review.required_links contains an invalid entry")
            continue
        path = repo_root / relative
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
        path = source_root / relative
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
