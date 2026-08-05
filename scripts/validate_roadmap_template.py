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
class Heading:
    title: Optional[str]
    line: SourceLine
    kind: str


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


def _is_fence_line(text: str) -> bool:
    return text.startswith("```")


def _fenced_line_numbers(lines: Sequence[SourceLine]) -> set[int]:
    """Mark code-fence contents so decoy headings and fields do not validate."""

    fenced: set[int] = set()
    in_fence = False
    for source_line in lines:
        if _is_fence_line(source_line.text):
            fenced.add(source_line.number)
            in_fence = not in_fence
        elif in_fence:
            fenced.add(source_line.number)
    return fenced


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

    # A second delimiter block is never valid in this fixed scaffold. This
    # catches a duplicated whole front matter block without treating its fields
    # as unrelated document prose.
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
    lines: Sequence[SourceLine],
) -> Tuple[List[Heading], List[Heading], List[ValidationError]]:
    h2: List[Heading] = []
    h3: List[Heading] = []
    errors: List[ValidationError] = []
    fenced = _fenced_line_numbers(lines)

    for source_line in lines:
        if source_line.number in fenced:
            continue
        text = source_line.text
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
                h3.append(Heading(title=match.group(1), line=source_line, kind="h3"))
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
        heading = h2[first_difference]
        errors.append(
            _error(
                "section-reordered",
                heading.line.number,
                "The ten level-two sections must remain in the canonical order.",
            )
        )
    return errors


def _section_ranges(
    h2: Sequence[Heading], lines: Sequence[SourceLine]
) -> Iterable[Tuple[Heading, Sequence[SourceLine]]]:
    for index, heading in enumerate(h2):
        end = h2[index + 1].line.number - 1 if index + 1 < len(h2) else len(lines)
        yield heading, lines[heading.line.number : end]


def _validate_subsections_and_fields(
    h2: Sequence[Heading], lines: Sequence[SourceLine]
) -> List[ValidationError]:
    errors: List[ValidationError] = []
    for heading, body in _section_ranges(h2, lines):
        title = heading.title
        if title is None or title not in SECTIONS:
            continue
        expected_subsections = list(SUBSECTIONS.get(title, ()))
        expected_fields = list(FIELDS.get(title, ()))
        fenced = _fenced_line_numbers(body)

        observed_subsections: List[Heading] = []
        for source_line in body:
            if source_line.number in fenced or not source_line.text.startswith("###"):
                continue
            match = _H3_RE.fullmatch(source_line.text)
            if match and not source_line.text.startswith("####"):
                observed_subsections.append(Heading(match.group(1), source_line, "h3"))
            else:
                observed_subsections.append(Heading(None, source_line, "h3"))

        if expected_subsections:
            for subsection in observed_subsections:
                if subsection.title is None:
                    continue
                if subsection.title not in expected_subsections:
                    errors.append(
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
                    errors.append(
                        _error(
                            "subsection-missing",
                            heading.line.number,
                            f"Required subsection `{name}` is missing from `{title}`.",
                        )
                    )
                elif len(matches) > 1:
                    for duplicate in matches[1:]:
                        errors.append(
                            _error(
                                "subsection-duplicate",
                                duplicate.line.number,
                                f"Subsection `{name}` appears more than once in `{title}`.",
                            )
                        )
            observed_names = [item.title for item in observed_subsections if item.title is not None]
            section_structure_error = any(
                error.code
                in {"subsection-missing", "subsection-duplicate", "subsection-unknown"}
                and error.line is not None
                and error.line >= heading.line.number
                for error in errors
            )
            if not section_structure_error and observed_names != expected_subsections:
                first_difference = next(
                    index
                    for index, (actual, expected_name) in enumerate(zip(observed_names, expected_subsections))
                    if actual != expected_name
                )
                errors.append(
                    _error(
                        "subsection-reordered",
                        observed_subsections[first_difference].line.number,
                        f"Subsections in `{title}` must remain in the canonical order.",
                    )
                )
        elif observed_subsections:
            for subsection in observed_subsections:
                errors.append(
                    _error(
                        "subsection-unknown",
                        subsection.line.number,
                        f"Section `{title}` does not allow subsections.",
                    )
                )

        field_records: List[Tuple[str, SourceLine]] = []
        for source_line in body:
            if source_line.number in fenced:
                continue
            match = _FIELD_BULLET_RE.fullmatch(source_line.text)
            if not match:
                continue
            bullet = match.group(1)
            if ":" in bullet:
                label = bullet.split(":", 1)[0].strip()
                field_records.append((label, source_line))
                if label not in expected_fields:
                    errors.append(
                        _error(
                            "field-unknown",
                            source_line.number,
                            f"Unknown field `{label}` in `{title}`.",
                        )
                    )
            elif expected_fields and any(
                bullet == expected or bullet.startswith(expected + " ")
                for expected in expected_fields
            ):
                errors.append(
                    _error(
                        "field-malformed",
                        source_line.number,
                        "Required fields must use `- Label: value` syntax.",
                    )
                )

        if not expected_fields:
            continue

        locations: Dict[str, List[SourceLine]] = {name: [] for name in expected_fields}
        for label, source_line in field_records:
            if label in locations:
                locations[label].append(source_line)
        for name in expected_fields:
            matches = locations[name]
            if not matches:
                errors.append(
                    _error(
                        "field-missing",
                        heading.line.number,
                        f"Required field `{name}` is missing from `{title}`.",
                    )
                )
            elif len(matches) > 1:
                for duplicate in matches[1:]:
                    errors.append(
                        _error(
                            "field-duplicate",
                            duplicate.number,
                            f"Field `{name}` appears more than once in `{title}`.",
                        )
                    )

        observed_fields = [label for label, _ in field_records if label in expected_fields]
        field_structure_error = any(
            error.code in {"field-missing", "field-duplicate", "field-unknown", "field-malformed"}
            and error.line is not None
            and error.line >= heading.line.number
            for error in errors
        )
        if not field_structure_error and observed_fields != expected_fields:
            first_difference = next(
                index
                for index, (actual, expected_name) in enumerate(zip(observed_fields, expected_fields))
                if actual != expected_name
            )
            errors.append(
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
                    errors.append(
                        _error(
                            "paper-url",
                            paper_line.number,
                            f"`Paper file` must use the canonical URL `{PAPER_URL}`.",
                        )
                    )
    return errors


def _validate_command_fence(
    h2: Sequence[Heading], lines: Sequence[SourceLine]
) -> List[ValidationError]:
    errors: List[ValidationError] = []
    target = next((heading for heading in h2 if heading.title == "8. Verification commands"), None)
    if target is None:
        return errors
    body = next((body for heading, body in _section_ranges(h2, lines) if heading is target), ())
    fence_lines = [line for line in body if line.text.startswith("```")]
    openings = [line for line in fence_lines if line.text == "```text"]
    closings = [line for line in fence_lines if line.text == "```"]
    malformed = [line for line in fence_lines if line.text not in {"```text", "```"}]

    for line in malformed:
        errors.append(
            _error(
                "command-fence-malformed",
                line.number,
                "The verification block must open with exactly ```text and close with exactly ```.",
            )
        )
    if not openings:
        errors.append(
            _error(
                "command-fence-missing",
                target.line.number,
                "Section 8 must contain one fenced block with the `text` language.",
            )
        )
        return errors
    if len(openings) > 1:
        for duplicate in openings[1:]:
            errors.append(
                _error(
                    "command-fence-duplicate",
                    duplicate.number,
                    "Section 8 may contain only one command fence.",
                )
            )
    opening = openings[0]
    following_closings = [line for line in closings if line.number > opening.number]
    if not following_closings:
        errors.append(
            _error(
                "command-fence-unclosed",
                opening.number,
                "The section 8 command fence is not closed.",
            )
        )
        return errors
    closing = following_closings[0]
    if len(following_closings) > 1:
        for duplicate in following_closings[1:]:
            errors.append(
                _error(
                    "command-fence-duplicate",
                    duplicate.number,
                    "Section 8 may contain only one command fence.",
                )
            )
    body_lines = [line.text for line in body if opening.number < line.number < closing.number]
    if body_lines != [COMMAND_FENCE_BODY]:
        errors.append(
            _error(
                "command-fence-content",
                body[0].number if body else target.line.number,
                "The text command fence must contain the canonical placeholder comment.",
            )
        )
    return errors


def _validate_definition_of_done(
    h2: Sequence[Heading], lines: Sequence[SourceLine]
) -> List[ValidationError]:
    errors: List[ValidationError] = []
    target = next((heading for heading in h2 if heading.title == "10. Definition of done"), None)
    if target is None:
        return errors
    body = next((body for heading, body in _section_ranges(h2, lines) if heading is target), ())
    observed: List[Tuple[str, SourceLine, str]] = []
    malformed_lines: List[SourceLine] = []
    for source_line in body:
        text = source_line.text
        if text.startswith("- [") or text.startswith("-"):
            match = _CHECKBOX_RE.fullmatch(text)
            if match:
                state, item = match.groups()
                observed.append((item, source_line, state))
            elif text.strip():
                malformed_lines.append(source_line)
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


def _result(path: Union[str, Path], errors: Iterable[ValidationError]) -> Dict[str, object]:
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
        "path": str(path),
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
    h2, _h3, heading_errors = _collect_headings(lines)
    errors.extend(heading_errors)
    errors.extend(_validate_h2_sections(h2))
    errors.extend(_validate_subsections_and_fields(h2, lines))
    errors.extend(_validate_command_fence(h2, lines))
    errors.extend(_validate_definition_of_done(h2, lines))
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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "path",
        nargs="?",
        default=str(DEFAULT_TEMPLATE_PATH),
        help=f"template path (default: {DEFAULT_TEMPLATE_PATH})",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    result = validate_file(args.path)
    json.dump(result, sys.stdout, ensure_ascii=False, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if bool(result["ok"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
