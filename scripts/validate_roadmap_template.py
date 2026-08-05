#!/usr/bin/env python3
"""Validate the checked-in atomic roadmap issue template.

The validator intentionally uses only the Python standard library. It checks the
scaffold rather than attempting to parse arbitrary Markdown, so a malformed
heading or field cannot quietly satisfy a required slot. The template is a
source artifact: validation must stay offline and must never contact GitHub,
Paper, Hermes, or another service.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

DEFAULT_TEMPLATE_PATH = Path(".github/ISSUE_TEMPLATE/roadmap.md")
PAPER_URL = "https://app.paper.design/file/01KZ6BB66KCWR2C4J2TSWQGDM7/1-0"

FRONT_MATTER: Tuple[Tuple[str, str], ...] = (
    ("name", "Hermternal roadmap operation"),
    ("about", "Plan one independently verifiable v0.0.1 operation"),
    ("title", '"[KEY] "'),
    ("labels", "[]"),
    ("assignees", "[]"),
)

SECTIONS: Tuple[str, ...] = (
    "1. One operation",
    "2. Ownership and dependencies",
    "3. Exact behavior",
    "4. Paper evidence",
    "5. Contract and tests",
    "6. Accessibility",
    "7. Benchmark",
    "8. Verification commands",
    "9. Evidence",
    "10. Definition of done",
)

SUBSECTIONS: Dict[str, Tuple[str, ...]] = {
    "2. Ownership and dependencies": ("Hard blockers", "Soft sequence"),
    "3. Exact behavior": (
        "Normal",
        "Loading or pending",
        "Empty",
        "Success",
        "Failure",
        "Interruption or cancellation",
        "Retry and recovery",
    ),
}

FIELDS: Dict[str, Tuple[str, ...]] = {
    "2. Ownership and dependencies": (
        "Owner",
        "Assigned subagent",
        "Reviewer",
        "Child issues",
    ),
    "4. Paper evidence": ("Paper file", "Artboards", "Static states"),
    "5. Contract and tests": (
        "Contract paths",
        "Contract version or pinned Hermes SHA",
        "Fixture IDs",
        "Unit tests",
        "Component or UI tests",
        "Integration or deployment tests",
        "Parity tests",
        "Negative tests",
        "Regression tests",
    ),
    "6. Accessibility": (
        "Keyboard and focus",
        "Semantic name",
        "Screen reader or VoiceOver",
        "Switch Control",
        "Dynamic Type or browser zoom",
        "Contrast",
        "Reduced motion and reduced transparency",
        "Touch target",
    ),
    "7. Benchmark": (
        "Deterministic fixture",
        "Metric",
        "Environment and device",
        "Build mode",
        "Repetitions and distribution",
        "Trace artifact",
        "Baseline or approved budget",
    ),
    "9. Evidence": (
        "Pull request",
        "Commit SHA",
        "Paper review",
        "Fixture diff",
        "Test output",
        "Accessibility result",
        "Benchmark trace",
        "Proxy or integration trace",
        "Security and redaction review",
    ),
}

COMMAND_FENCE_BODY = "# Add exact commands and expected artifacts."

DOD_ITEMS: Tuple[str, ...] = (
    "The one operation is complete.",
    "Required normal and failure states pass.",
    "Regression tests exist and pass.",
    "Matching contracts, comments, and nearby documentation are updated.",
    "Paper matches the implementation, or an approved N/A reason is recorded.",
    "Accessibility checks pass where applicable.",
    "Measured performance evidence is attached.",
    "Security and privacy boundaries pass where applicable.",
    "`rtk diff` was reviewed.",
    "`code-review-graph update --brief` and change impact review are complete.",
    "The assigned subagent left a final issue comment with the current state, completed work, verification results, remaining limitations, and child issues.",
    "The focused commit and pull request are reviewed and integrated into `dev`.",
)

_FRONT_FIELD_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_-]*): (.*)$")
_H2_RE = re.compile(r"^## (.+)$")
_H3_RE = re.compile(r"^### (.+)$")
_CHECKBOX_RE = re.compile(r"^- \[([ xX])\] (.*)$")
_FIELD_BULLET_RE = re.compile(r"^\s*-\s+(.+)$")
_FENCE_CANDIDATE_RE = re.compile(r"^( {0,3})([`~]{3,})(.*)$")
_FENCE_CLOSE_RE = re.compile(r"^( {0,3})([`~]{3,})[ \t]*$")


@dataclass(frozen=True)
class ValidationError:
    """One deterministic, line-addressable validation failure."""

    code: str
    line: Optional[int]
    message: str

    def as_dict(self) -> Dict[str, object]:
        return {"code": self.code, "line": self.line, "message": self.message}


@dataclass(frozen=True)
class SourceLine:
    number: int
    text: str
    ending: str


@dataclass(frozen=True)
class MarkdownLine:
    """One source line after the stateful comment and fence scan."""

    source: SourceLine
    text: str
    hidden: bool
    fence_role: Optional[str] = None
    fence_char: Optional[str] = None
    fence_length: Optional[int] = None
    fence_info: str = ""


@dataclass(frozen=True)
class Heading:
    title: Optional[str]
    line: SourceLine
    kind: str


@dataclass(frozen=True)
class Fence:
    char: str
    length: int
    info: str


class _CliArgumentError(ValueError):
    """Raised without argparse printing usage before structured JSON output."""


def _error(code: str, line: Optional[int], message: str) -> ValidationError:
    return ValidationError(code=code, line=line, message=message)


def _split_lines(text: str) -> Tuple[List[SourceLine], set[str], bool]:
    """Return logical lines, observed endings, and whether a final newline exists."""

    if not text:
        return [], set(), False

    result: List[SourceLine] = []
    endings: set[str] = set()
    for number, raw in enumerate(text.splitlines(keepends=True), start=1):
        if raw.endswith("\r\n"):
            body, ending = raw[:-2], "\r\n"
        elif raw.endswith("\n"):
            body, ending = raw[:-1], "\n"
        elif raw.endswith("\r"):
            body, ending = raw[:-1], "\r"
        else:
            body, ending = raw, ""
        result.append(SourceLine(number=number, text=body, ending=ending))
        if ending:
            endings.add(ending)

    final_newline = bool(result and bool(result[-1].ending))
    return result, endings, final_newline


def _strip_html_comments(text: str, in_comment: bool) -> Tuple[str, bool]:
    """Remove HTML comments while preserving visible text before and after them."""

    visible: List[str] = []
    position = 0
    while position < len(text):
        if in_comment:
            close = text.find("-->", position)
            if close < 0:
                return "".join(visible), True
            position = close + 3
            in_comment = False
            continue

        opening = text.find("<!--", position)
        if opening < 0:
            visible.append(text[position:])
            break
        visible.append(text[position:opening])
        position = opening + 4
        in_comment = True
    return "".join(visible), in_comment


def _parse_fence_open(text: str) -> Optional[Fence]:
    match = _FENCE_CANDIDATE_RE.fullmatch(text)
    if not match:
        return None
    run, info = match.group(2), match.group(3)
    if len(set(run)) != 1:
        return None
    return Fence(char=run[0], length=len(run), info=info)


def _parse_fence_close(text: str, fence: Fence) -> bool:
    match = _FENCE_CLOSE_RE.fullmatch(text)
    if not match:
        return False
    run = match.group(2)
    return len(set(run)) == 1 and run[0] == fence.char and len(run) >= fence.length


def _scan_markdown(lines: Sequence[SourceLine]) -> List[MarkdownLine]:
    """Scan comments and arbitrary backtick/tilde fences in one stateful pass.

    A full-document scan is required: slicing a section and rescanning it would
    lose whether that slice starts inside a multiline HTML comment or fence.
    Visible fence delimiters are retained for the section-8 command contract;
    all fence contents and comment contents are hidden from structural checks.
    """

    scanned: List[MarkdownLine] = []
    in_comment = False
    active_fence: Optional[Fence] = None

    for source_line in lines:
        if active_fence is not None:
            if _parse_fence_close(source_line.text, active_fence):
                scanned.append(
                    MarkdownLine(
                        source=source_line,
                        text=source_line.text,
                        hidden=False,
                        fence_role="close",
                        fence_char=active_fence.char,
                        fence_length=len(
                            _FENCE_CLOSE_RE.fullmatch(source_line.text).group(2)  # type: ignore[union-attr]
                        ),
                    )
                )
                active_fence = None
            else:
                scanned.append(MarkdownLine(source=source_line, text="", hidden=True))
            continue

        visible_text, in_comment = _strip_html_comments(source_line.text, in_comment)
        opening = _parse_fence_open(visible_text)
        if opening is not None:
            scanned.append(
                MarkdownLine(
                    source=source_line,
                    text=visible_text,
                    hidden=False,
                    fence_role="open",
                    fence_char=opening.char,
                    fence_length=opening.length,
                    fence_info=opening.info,
                )
            )
            active_fence = opening
            continue

        comment_only = bool(source_line.text.strip()) and not visible_text.strip()
        scanned.append(
            MarkdownLine(source=source_line, text=visible_text, hidden=comment_only)
        )

    return scanned


def _front_matter_end(lines: Sequence[SourceLine]) -> Optional[int]:
    if not lines or lines[0].text != "---":
        return None
    for index in range(1, len(lines)):
        if lines[index].text == "---":
            return index
    return None


def _validate_line_endings(
    lines: Sequence[SourceLine], endings: set[str], final_newline: bool
) -> List[ValidationError]:
    errors: List[ValidationError] = []
    if "\r" in endings:
        line = next((item.number for item in lines if item.ending == "\r"), 1)
        errors.append(
            _error(
                "invalid-line-ending",
                line,
                "Use LF or CRLF line endings; a lone CR is not valid Markdown input.",
            )
        )
    if len(endings - {""}) > 1:
        line = next(
            (item.number for item in lines if item.ending and item.ending != lines[0].ending),
            1,
        )
        errors.append(
            _error(
                "mixed-line-endings",
                line,
                "The template must use one line-ending style throughout.",
            )
        )
    if lines and not final_newline:
        errors.append(
            _error(
                "missing-final-newline",
                lines[-1].number,
                "The template must end with a newline.",
            )
        )
    return errors


def _validate_front_matter(lines: Sequence[SourceLine]) -> List[ValidationError]:
    errors: List[ValidationError] = []
    if not lines or lines[0].text != "---":
        errors.append(
            _error(
                "front-matter-missing",
                1,
                "The template must start with the exact YAML front-matter delimiter `---`.",
            )
        )
        return errors

    end = _front_matter_end(lines)
    if end is None:
        errors.append(
            _error(
                "front-matter-unclosed",
                lines[0].number,
                "The YAML front matter is missing its closing `---` delimiter.",
            )
        )
        return errors

    expected_keys = [key for key, _ in FRONT_MATTER]
    expected_values = dict(FRONT_MATTER)
    observed_keys: List[str] = []
    key_lines: Dict[str, int] = {}

    for source_line in lines[1:end]:
        match = _FRONT_FIELD_RE.fullmatch(source_line.text)
        if not match:
            errors.append(
                _error(
                    "front-matter-malformed",
                    source_line.number,
                    "Each front-matter field must use `key: value` syntax with one space after the colon.",
                )
            )
            continue
        key, value = match.groups()
        observed_keys.append(key)
        if key in key_lines:
            errors.append(
                _error(
                    "front-matter-duplicate",
                    source_line.number,
                    f"Front-matter field `{key}` appears more than once.",
                )
            )
        else:
            key_lines[key] = source_line.number
        if key not in expected_values:
            errors.append(
                _error(
                    "front-matter-unknown",
                    source_line.number,
                    f"Front-matter field `{key}` is not part of the roadmap template contract.",
                )
            )
        elif value != expected_values[key]:
            errors.append(
                _error(
                    "front-matter-value",
                    source_line.number,
                    f"Front-matter field `{key}` must be exactly `{expected_values[key]}`.",
                )
            )

    for key in expected_keys:
        if key not in key_lines:
            errors.append(
                _error(
                    "front-matter-missing",
                    lines[end].number,
                    f"Required front-matter field `{key}` is missing.",
                )
            )

    if (
        not any(error.code == "front-matter-malformed" for error in errors)
        and not any(error.code == "front-matter-unknown" for error in errors)
        and len(observed_keys) == len(expected_keys)
        and observed_keys != expected_keys
    ):
        first_difference = next(
            index
            for index, (actual, expected) in enumerate(zip(observed_keys, expected_keys))
            if actual != expected
        )
        errors.append(
            _error(
                "front-matter-reordered",
                key_lines.get(observed_keys[first_difference], lines[1].number),
                "Front-matter fields must remain in the canonical order.",
            )
        )

    for source_line in lines[end + 1 :]:
        if source_line.text == "---":
            errors.append(
                _error(
                    "front-matter-duplicate",
                    source_line.number,
                    "The template may contain only one front-matter block.",
                )
            )
            break
    return errors


def _collect_headings(
    scanned: Sequence[MarkdownLine],
) -> Tuple[List[Heading], List[Heading], List[ValidationError]]:
    h2: List[Heading] = []
    h3: List[Heading] = []
    errors: List[ValidationError] = []

    for scanned_line in scanned:
        if scanned_line.hidden or scanned_line.fence_role is not None:
            continue
        source_line = scanned_line.source
        text = scanned_line.text
        if text.startswith("# "):
            title = text[2:]
            if title in SECTIONS:
                errors.append(
                    _error(
                        "section-malformed",
                        source_line.number,
                        "Level-two headings must use exactly `## ` followed by the section title.",
                    )
                )
            elif any(title in names for names in SUBSECTIONS.values()):
                errors.append(
                    _error(
                        "subsection-malformed",
                        source_line.number,
                        "Level-three headings must use exactly `### ` followed by the subsection title.",
                    )
                )
        elif text.startswith("##") and not text.startswith("###"):
            match = _H2_RE.fullmatch(text)
            if match and match.group(1) == match.group(1).rstrip():
                h2.append(Heading(title=match.group(1), line=source_line, kind="h2"))
            else:
                h2.append(Heading(title=None, line=source_line, kind="h2"))
                errors.append(
                    _error(
                        "section-malformed",
                        source_line.number,
                        "Level-two headings must use exactly `## ` followed by the section title.",
                    )
                )
        elif text.startswith("###"):
            match = _H3_RE.fullmatch(text)
            if match and not text.startswith("####") and match.group(1) == match.group(1).rstrip():
                if match.group(1) in SECTIONS:
                    errors.append(
                        _error(
                            "section-malformed",
                            source_line.number,
                            "A section heading must use level two, not level three.",
                        )
                    )
                h3.append(Heading(match.group(1), source_line, "h3"))
            else:
                h3.append(Heading(title=None, line=source_line, kind="h3"))
                errors.append(
                    _error(
                        "subsection-malformed",
                        source_line.number,
                        "Level-three headings must use exactly `### ` followed by the subsection title.",
                    )
                )
    return h2, h3, errors


def _validate_h2_sections(h2: Sequence[Heading]) -> List[ValidationError]:
    errors: List[ValidationError] = []
    expected = list(SECTIONS)
    observed = [heading.title for heading in h2 if heading.title is not None]

    for heading in h2:
        if heading.title is None:
            continue
        if heading.title not in SECTIONS:
            errors.append(
                _error(
                    "section-unknown",
                    heading.line.number,
                    f"Unknown level-two section `{heading.title}`.",
                )
            )

    positions: Dict[str, List[Heading]] = {title: [] for title in expected}
    for heading in h2:
        if heading.title in positions:
            positions[heading.title].append(heading)

    for title in expected:
        matches = positions[title]
        if not matches:
            errors.append(
                _error(
                    "section-missing",
                    h2[-1].line.number if h2 else 1,
                    f"Required level-two section `{title}` is missing.",
                )
            )
        elif len(matches) > 1:
            for duplicate in matches[1:]:
                errors.append(
                    _error(
                        "section-duplicate",
                        duplicate.line.number,
                        f"Level-two section `{title}` appears more than once.",
                    )
                )

    if (
        not any(
            error.code in {"section-missing", "section-duplicate", "section-unknown"}
            for error in errors
        )
        and observed != expected
    ):
        first_difference = next(
            index
            for index, (actual, expected_title) in enumerate(zip(observed, expected))
            if actual != expected_title
        )
        errors.append(
            _error(
                "section-reordered",
                h2[first_difference].line.number,
                "The ten level-two sections must remain in the canonical order.",
            )
        )
    return errors


def _section_ranges(
    h2: Sequence[Heading], scanned: Sequence[MarkdownLine]
) -> Iterable[Tuple[Heading, Sequence[MarkdownLine]]]:
    for index, heading in enumerate(h2):
        end = h2[index + 1].line.number - 1 if index + 1 < len(h2) else len(scanned)
        yield heading, scanned[heading.line.number : end]


def _validate_subsections_and_fields(
    h2: Sequence[Heading], scanned: Sequence[MarkdownLine]
) -> List[ValidationError]:
    errors: List[ValidationError] = []
    for heading, body in _section_ranges(h2, scanned):
        title = heading.title
        if title is None or title not in SECTIONS:
            continue
        expected_subsections = list(SUBSECTIONS.get(title, ()))
        expected_fields = list(FIELDS.get(title, ()))
        visible_body = [
            line
            for line in body
            if not line.hidden and line.fence_role is None
        ]

        observed_subsections: List[Heading] = []
        subsection_errors: List[ValidationError] = []
        for scanned_line in visible_body:
            text = scanned_line.text
            if not text.startswith("###"):
                continue
            match = _H3_RE.fullmatch(text)
            if match and not text.startswith("####") and match.group(1) == match.group(1).rstrip():
                observed_subsections.append(Heading(match.group(1), scanned_line.source, "h3"))
            else:
                observed_subsections.append(Heading(None, scanned_line.source, "h3"))
                subsection_errors.append(
                    _error(
                        "subsection-malformed",
                        scanned_line.source.number,
                        "Level-three headings must use exactly `### ` followed by the subsection title.",
                    )
                )

        if expected_subsections:
            for subsection in observed_subsections:
                if subsection.title is not None and subsection.title not in expected_subsections:
                    subsection_errors.append(
                        _error(
                            "subsection-unknown",
                            subsection.line.number,
                            f"Unknown subsection `{subsection.title}` in `{title}`.",
                        )
                    )
            locations: Dict[str, List[Heading]] = {name: [] for name in expected_subsections}
            for subsection in observed_subsections:
                if subsection.title in locations:
                    locations[subsection.title].append(subsection)
            for name in expected_subsections:
                matches = locations[name]
                if not matches:
                    subsection_errors.append(
                        _error(
                            "subsection-missing",
                            heading.line.number,
                            f"Required subsection `{name}` is missing from `{title}`.",
                        )
                    )
                elif len(matches) > 1:
                    for duplicate in matches[1:]:
                        subsection_errors.append(
                            _error(
                                "subsection-duplicate",
                                duplicate.line.number,
                                f"Subsection `{name}` appears more than once in `{title}`.",
                            )
                        )
            observed_names = [item.title for item in observed_subsections if item.title is not None]
            if not subsection_errors and observed_names != expected_subsections:
                first_difference = next(
                    index
                    for index, (actual, expected_name) in enumerate(zip(observed_names, expected_subsections))
                    if actual != expected_name
                )
                subsection_errors.append(
                    _error(
                        "subsection-reordered",
                        observed_subsections[first_difference].line.number,
                        f"Subsections in `{title}` must remain in the canonical order.",
                    )
                )
        elif observed_subsections:
            for subsection in observed_subsections:
                subsection_errors.append(
                    _error(
                        "subsection-unknown",
                        subsection.line.number,
                        f"Section `{title}` does not allow subsections.",
                    )
                )
        errors.extend(subsection_errors)

        field_records: List[Tuple[str, SourceLine]] = []
        field_errors: List[ValidationError] = []
        for scanned_line in visible_body:
            match = _FIELD_BULLET_RE.fullmatch(scanned_line.text)
            if not match:
                continue
            bullet = match.group(1)
            if ":" in bullet:
                label = bullet.split(":", 1)[0].strip()
                field_records.append((label, scanned_line.source))
                if label not in expected_fields:
                    field_errors.append(
                        _error(
                            "field-unknown",
                            scanned_line.source.number,
                            f"Unknown field `{label}` in `{title}`.",
                        )
                    )
            elif expected_fields and any(
                bullet == expected or bullet.startswith(expected + " ")
                for expected in expected_fields
            ):
                field_errors.append(
                    _error(
                        "field-malformed",
                        scanned_line.source.number,
                        "Required fields must use `- Label: value` syntax.",
                    )
                )

        if expected_fields:
            locations = {name: [] for name in expected_fields}
            for label, source_line in field_records:
                if label in locations:
                    locations[label].append(source_line)
            for name in expected_fields:
                matches = locations[name]
                if not matches:
                    field_errors.append(
                        _error(
                            "field-missing",
                            heading.line.number,
                            f"Required field `{name}` is missing from `{title}`.",
                        )
                    )
                elif len(matches) > 1:
                    for duplicate in matches[1:]:
                        field_errors.append(
                            _error(
                                "field-duplicate",
                                duplicate.number,
                                f"Field `{name}` appears more than once in `{title}`.",
                            )
                        )

            observed_fields = [label for label, _ in field_records if label in expected_fields]
            if not field_errors and observed_fields != expected_fields:
                first_difference = next(
                    index
                    for index, (actual, expected_name) in enumerate(zip(observed_fields, expected_fields))
                    if actual != expected_name
                )
                field_errors.append(
                    _error(
                        "field-reordered",
                        locations[observed_fields[first_difference]][0].number,
                        f"Fields in `{title}` must remain in the canonical order.",
                    )
                )

            if title == "4. Paper evidence":
                for paper_line in locations.get("Paper file", []):
                    value = paper_line.text.split(":", 1)[1].strip()
                    if value != PAPER_URL:
                        field_errors.append(
                            _error(
                                "paper-url",
                                paper_line.number,
                                f"`Paper file` must use the canonical URL `{PAPER_URL}`.",
                            )
                        )
        errors.extend(field_errors)
    return errors


def _validate_command_fence(
    h2: Sequence[Heading], scanned: Sequence[MarkdownLine]
) -> List[ValidationError]:
    errors: List[ValidationError] = []
    target = next((heading for heading in h2 if heading.title == "8. Verification commands"), None)
    if target is None:
        return errors
    body = next((body for heading, body in _section_ranges(h2, scanned) if heading is target), ())
    visible_openings = [
        line for line in body if not line.hidden and line.fence_role == "open"
    ]
    openings = [line for line in visible_openings if line.text == "```text"]
    for line in visible_openings:
        if line.text != "```text":
            errors.append(
                _error(
                    "command-fence-malformed",
                    line.source.number,
                    "The verification block must open with exactly ```text and close with exactly ```.",
                )
            )

    if not openings:
        errors.append(
            _error(
                "command-fence-missing",
                target.line.number,
                "Section 8 must contain one visible fenced block with the `text` language.",
            )
        )
        return errors
    if len(openings) > 1:
        for duplicate in openings[1:]:
            errors.append(
                _error(
                    "command-fence-duplicate",
                    duplicate.source.number,
                    "Section 8 may contain only one visible command fence.",
                )
            )

    opening = openings[0]
    closing = next(
        (
            line
            for line in body
            if line.source.number > opening.source.number and line.fence_role == "close"
        ),
        None,
    )
    if closing is None:
        errors.append(
            _error(
                "command-fence-unclosed",
                opening.source.number,
                "The visible section 8 command fence is not closed.",
            )
        )
        return errors

    body_lines = [
        line.source.text
        for line in body
        if opening.source.number < line.source.number < closing.source.number
    ]
    if body_lines != [COMMAND_FENCE_BODY]:
        errors.append(
            _error(
                "command-fence-content",
                opening.source.number,
                "The visible text command fence must contain the canonical placeholder comment.",
            )
        )
    return errors


def _validate_definition_of_done(
    h2: Sequence[Heading], scanned: Sequence[MarkdownLine]
) -> List[ValidationError]:
    errors: List[ValidationError] = []
    target = next((heading for heading in h2 if heading.title == "10. Definition of done"), None)
    if target is None:
        return errors
    body = next((body for heading, body in _section_ranges(h2, scanned) if heading is target), ())
    observed: List[Tuple[str, SourceLine, str]] = []
    malformed_lines: List[SourceLine] = []
    for scanned_line in body:
        if scanned_line.hidden or scanned_line.fence_role is not None:
            continue
        text = scanned_line.text
        if text.startswith("-"):
            match = _CHECKBOX_RE.fullmatch(text)
            if match:
                state, item = match.groups()
                observed.append((item, scanned_line.source, state))
            elif text.strip():
                malformed_lines.append(scanned_line.source)
    for source_line in malformed_lines:
        errors.append(
            _error(
                "dod-malformed",
                source_line.number,
                "Definition-of-done entries must use `- [ ] text` syntax.",
            )
        )

    expected = list(DOD_ITEMS)
    locations: Dict[str, List[Tuple[SourceLine, str]]] = {item: [] for item in expected}
    for item, source_line, state in observed:
        if item not in locations:
            errors.append(
                _error(
                    "dod-unknown",
                    source_line.number,
                    f"Unknown definition-of-done item `{item}`.",
                )
            )
        else:
            locations[item].append((source_line, state))
            if state != " ":
                errors.append(
                    _error(
                        "dod-checked",
                        source_line.number,
                        "Definition-of-done items must be unchecked in the template.",
                    )
                )

    for item in expected:
        matches = locations[item]
        if not matches:
            errors.append(
                _error(
                    "dod-missing",
                    target.line.number,
                    f"Required definition-of-done item `{item}` is missing.",
                )
            )
        elif len(matches) > 1:
            for duplicate, _state in matches[1:]:
                errors.append(
                    _error(
                        "dod-duplicate",
                        duplicate.number,
                        f"Definition-of-done item `{item}` appears more than once.",
                    )
                )

    observed_known = [item for item, _line, _state in observed if item in locations]
    if (
        not any(error.code in {"dod-missing", "dod-duplicate", "dod-unknown", "dod-malformed"} for error in errors)
        and observed_known != expected
    ):
        first_difference = next(
            index
            for index, (actual, expected_item) in enumerate(zip(observed_known, expected))
            if actual != expected_item
        )
        line = next(line for item, line, _state in observed if item == observed_known[first_difference])
        errors.append(
            _error(
                "dod-reordered",
                line.number,
                "The twelve definition-of-done items must remain in the canonical order.",
            )
        )
    return errors


def _invalid_utf8_error(data: bytes, exc: UnicodeDecodeError) -> ValidationError:
    line = data[: exc.start].count(b"\n") + 1
    return _error(
        "invalid-utf8",
        line,
        f"Template bytes are not valid UTF-8 at byte offset {exc.start}.",
    )


def _result(
    path: Optional[Union[str, Path]], errors: Iterable[ValidationError]
) -> Dict[str, object]:
    ordered = sorted(
        errors,
        key=lambda item: (
            item.line is None,
            item.line if item.line is not None else 0,
            item.code,
            item.message,
        ),
    )
    return {
        "ok": not ordered,
        "path": str(path) if path is not None else None,
        "errors": [item.as_dict() for item in ordered],
    }


def validate_bytes(data: bytes, path: Union[str, Path] = DEFAULT_TEMPLATE_PATH) -> Dict[str, object]:
    """Validate UTF-8 template bytes and return a JSON-serializable result."""

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        return _result(path, [_invalid_utf8_error(data, exc)])

    lines, endings, final_newline = _split_lines(text)
    errors: List[ValidationError] = []
    errors.extend(_validate_line_endings(lines, endings, final_newline))
    errors.extend(_validate_front_matter(lines))
    scanned = _scan_markdown(lines)
    h2, _h3, heading_errors = _collect_headings(scanned)
    errors.extend(heading_errors)
    errors.extend(_validate_h2_sections(h2))
    errors.extend(_validate_subsections_and_fields(h2, scanned))
    errors.extend(_validate_command_fence(h2, scanned))
    errors.extend(_validate_definition_of_done(h2, scanned))
    return _result(path, errors)


def validate_text(text: str, path: Union[str, Path] = DEFAULT_TEMPLATE_PATH) -> Dict[str, object]:
    """Validate already-decoded template text."""

    return validate_bytes(text.encode("utf-8"), path=path)


def validate_file(path: Union[str, Path] = DEFAULT_TEMPLATE_PATH) -> Dict[str, object]:
    """Read and validate one local template without network access."""

    template_path = Path(path)
    try:
        data = template_path.read_bytes()
    except OSError as exc:
        return _result(
            path,
            [
                _error(
                    "read-error",
                    1,
                    f"Could not read template `{template_path}`: {exc}",
                )
            ],
        )
    return validate_bytes(data, path=path)


def validate(path: Union[str, Path] = DEFAULT_TEMPLATE_PATH) -> Dict[str, object]:
    """Compatibility alias for callers that prefer a short validator name."""

    return validate_file(path)


class _JsonArgumentParser(argparse.ArgumentParser):
    """Keep parse failures on the validator's one-object JSON output path."""

    def error(self, message: str) -> None:
        raise _CliArgumentError(message)


def _parser() -> argparse.ArgumentParser:
    parser = _JsonArgumentParser(description=__doc__)
    parser.add_argument(
        "path",
        nargs="?",
        default=str(DEFAULT_TEMPLATE_PATH),
        help=f"template path (default: {DEFAULT_TEMPLATE_PATH})",
    )
    return parser


def _write_result(result: Dict[str, object]) -> None:
    json.dump(result, sys.stdout, ensure_ascii=False, sort_keys=True)
    sys.stdout.write("\n")


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        args = _parser().parse_args(argv)
        result = validate_file(args.path)
        _write_result(result)
        return 0 if bool(result["ok"]) else 1
    except _CliArgumentError as exc:
        _write_result(
            _result(
                None,
                [_error("cli-arguments", None, f"Invalid command-line arguments: {exc}")],
            )
        )
        return 2
    except Exception as exc:  # pragma: no cover - defensive CLI boundary.
        _write_result(
            _result(
                None,
                [
                    _error(
                        "cli-failure",
                        None,
                        f"Validator failed without a traceback: {type(exc).__name__}: {exc}",
                    )
                ],
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
