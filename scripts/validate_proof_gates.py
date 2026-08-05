#!/usr/bin/env python3
"""Validate the implementation proof-gate checklist without network access.

The checklist is a planning artifact, not a runtime or deployment proof.  This
validator deliberately parses only the visible structure of the checked-in
Markdown.  A single stateful scan hides multiline HTML comments and arbitrary
backtick or tilde fences before any heading, table, field, or claim check runs.
That prevents a disabled or fenced decoy from satisfying a fail-closed gate.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

DEFAULT_CHECKLIST_PATH = Path("docs/product/implementation-proof-gates.md")
PAPER_URL = "https://app.paper.design/file/01KZ6BB66KCWR2C4J2TSWQGDM7/1-0"
REPOSITORY = "kaygdotorg/hermternal"
PINNED_HERMES_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"

CHECKLIST_TITLE = "Hermternal implementation proof-gate checklist"

METADATA: Tuple[Tuple[str, str], ...] = (
    ("Status", "approved fail-closed planning contract"),
    ("Roadmap key", "P0-06"),
    ("Integration branch", "dev"),
    ("Source contract", "dashboard-v0.0.1"),
    ("Pinned Hermes SHA", PINNED_HERMES_SHA),
    ("Paper file", f"[Paper design source of truth]({PAPER_URL})"),
    ("Validator", "scripts/validate_proof_gates.py"),
)

SECTIONS: Tuple[str, ...] = (
    "1. Scope and dependency policy",
    "2. Fail-closed gate order",
    "3. Required evidence",
    "4. Accessibility and performance",
    "5. No-network and privacy",
    "6. Atomic issue-template parity",
    "7. Review and dev integration",
    "8. Definition of done",
    "9. Reproduction",
)

SUBSECTIONS: Dict[str, Tuple[str, ...]] = {
    "1. Scope and dependency policy": (
        "Scaffolding boundary",
        "Live integration boundary",
        "Dependency direction",
    ),
    "2. Fail-closed gate order": (),
    "3. Required evidence": (),
    "4. Accessibility and performance": (
        "Non-UI accessibility",
        "Reproducible benchmark evidence",
    ),
    "5. No-network and privacy": ("Offline rule", "Redaction rule"),
    "6. Atomic issue-template parity": (
        "Section parity",
        "Field parity",
        "Definition-of-done parity",
    ),
    "7. Review and dev integration": ("Review evidence", "Dev integration"),
    "8. Definition of done": (),
    "9. Reproduction": (),
}

# These are the only roadmap issues referenced by the published checklist.  The
# numbers are copied from the approved roadmap; the validator never queries
# GitHub, so a changed URL fails locally instead of silently drifting.
ROADMAP_ISSUES: Dict[str, int] = {
    "P0-01": 40,
    "P0-02": 41,
    "P0-05": 45,
    "P0-06": 46,
    "C-01": 47,
    "C-02": 48,
    "C-02A": 49,
    "C-03": 50,
    "C-04": 51,
    "C-04A": 52,
    "C-05": 53,
    "C-06": 54,
    "C-08": 58,
    "C-13": 63,
    "C-15": 65,
    "C-17": 67,
    "C-18": 68,
    "C-19": 69,
    "C-20": 70,
    "C-21": 71,
    "D-01": 72,
    "D-02": 73,
    "D-03": 74,
    "D-04": 75,
    "D-04A": 76,
    "D-05": 77,
    "D-06": 78,
    "D-07": 79,
    "D-08": 80,
    "D-09": 81,
    "D-10": 82,
    "D-11": 83,
    "D-12": 84,
    "D-13": 85,
    "D-14": 86,
    "D-15": 87,
    "D-14W": 205,
    "D-15W": 206,
    "DEP-01": 88,
    "DEP-02": 89,
    "DEP-04": 91,
    "DEP-05": 92,
    "DEP-06M": 207,
    "DEP-06": 93,
    "DEP-07M": 208,
    "DEP-07": 94,
    "DEP-08": 95,
    "DEP-09": 96,
    "DEP-10M": 209,
    "DEP-10": 97,
    "DEP-11": 98,
    "DEP-11A": 99,
    "DEP-12": 100,
    "DEP-13": 101,
    "B-01": 102,
    "B-03": 107,
    "B-04": 108,
    "W-01": 114,
    "W-02": 115,
    "W-02A": 116,
    "W-20": 138,
    "W-21": 139,
    "W-21A": 140,
    "W-21B": 141,
    "W-21C": 142,
    "W-24": 146,
    "W-25": 147,
    "W-25A": 148,
    "A-07": 156,
    "A-10": 160,
    "A-10A": 161,
    "A-17": 169,
    "A-18": 170,
    "A-18A": 171,
    "A-18B": 172,
    "A-19": 173,
    "A-20": 174,
    "A-20A": 175,
    "A-20B": 176,
    "A-21": 177,
    "A-21A": 178,
    "A-21B": 179,
    "A-21C": 180,
    "A-22": 181,
    "A-22A": 182,
    "R-01": 183,
    "R-01A": 184,
    "R-02": 185,
    "R-03": 186,
    "R-04": 187,
    "R-05": 188,
    "R-06": 189,
    "R-06A": 190,
    "R-07": 191,
    "R-07A": 192,
    "R-07B": 193,
    "R-07C": 194,
    "R-08": 195,
}

MILESTONE_RANK = {"P0": 0, "C": 1, "D": 2, "DEP": 3, "B": 4, "W": 5, "A": 6, "R": 7}
M0_KEYS = frozenset({"P0-01", "P0-02", "P0-05", "P0-06"})


@dataclass(frozen=True)
class GateSpec:
    key: str
    phase: str
    description: str
    owners: Tuple[str, ...]
    dependencies: Tuple[str, ...]
    evidence: Tuple[str, ...]


GATES: Tuple[GateSpec, ...] = (
    GateSpec(
        "G-01",
        "M0",
        "Approved planning reconciliation is present and names the pinned source, repository scope, and planning-only boundary.",
        ("P0-01",),
        (),
        ("E-01",),
    ),
    GateSpec(
        "G-02",
        "M0",
        "The source-audit and compatibility policy is pinned, fail-closed, and uses synthetic or redacted evidence.",
        ("P0-02",),
        ("P0-01",),
        ("E-02",),
    ),
    GateSpec(
        "G-03",
        "M0",
        "The atomic issue-template contract is present and its required sections, evidence, and definition-of-done order are unchanged.",
        ("P0-05",),
        ("P0-01",),
        ("E-03",),
    ),
    GateSpec(
        "G-04",
        "M0",
        "This checklist is validated offline before any application scaffolding or live integration.",
        ("P0-06",),
        ("P0-02", "P0-05"),
        ("E-04",),
    ),
    GateSpec(
        "G-05",
        "SCAFFOLD",
        "The approved Dashboard route and method allowlist is the only route surface available to a scaffold.",
        ("C-01",),
        ("P0-02",),
        ("E-05",),
    ),
    GateSpec(
        "G-06",
        "SCAFFOLD",
        "Language-neutral synthetic fixtures, negative cases, and web/Apple parity cover the approved contract.",
        ("C-19",),
        ("C-02", "C-02A", "C-03", "C-05", "C-08", "C-13", "C-15", "C-17"),
        ("E-06",),
    ),
    GateSpec(
        "G-07",
        "SCAFFOLD",
        "The Paper web manifest and semantic tokens cover the scaffold states; Apple boards remain a later shared-design dependency.",
        ("D-15W",),
        ("D-01", "D-02", "D-03", "D-04", "D-04A", "D-05", "D-06", "D-07", "D-08", "D-11", "D-13", "D-14W"),
        ("E-07",),
    ),
    GateSpec(
        "G-08",
        "SCAFFOLD",
        "Benchmark method and web or Apple harness scaffolds exist with artifact evidence and no final performance threshold.",
        ("B-01", "B-03", "B-04"),
        ("C-19",),
        ("E-08",),
    ),
    GateSpec(
        "G-09",
        "SCAFFOLD",
        "Accessibility design inputs preserve keyboard, screen-reader, VoiceOver, Switch Control, zoom, contrast, motion, and touch-target requirements.",
        ("D-11", "D-12", "D-13"),
        ("D-01", "D-02", "D-09", "D-10"),
        ("E-09",),
    ),
    GateSpec(
        "G-10",
        "SCAFFOLD",
        "The application scaffold uses mock-only network boundaries and cannot contact any external Hermes or deployment service.",
        ("W-01",),
        ("C-20", "D-14W", "B-03"),
        ("E-10",),
    ),
    GateSpec(
        "G-11",
        "SCAFFOLD",
        "Synthetic deployment and security boundary proofs cover cookies, tickets, host/origin policy, PTY scope, and redaction before client integration.",
        ("DEP-06M", "DEP-07M", "DEP-10M"),
        ("C-02", "C-02A", "C-17", "C-18"),
        ("E-11",),
    ),
    GateSpec(
        "G-12",
        "INTEGRATION",
        "Caddy and Traefik normalized deployment and security proofs match before live-adjacent integration is enabled.",
        ("DEP-13",),
        ("DEP-04", "DEP-05", "DEP-06", "DEP-07", "DEP-08", "DEP-09", "DEP-10", "DEP-11", "DEP-11A", "DEP-12"),
        ("E-12",),
    ),
    GateSpec(
        "G-13",
        "INTEGRATION",
        "The pinned disposable Hermes integration proof passes only after compatibility, proxy, parity, and client gates are complete.",
        ("R-02",),
        ("C-04", "C-04A", "DEP-13", "R-01", "R-01A", "W-02", "W-02A", "A-07"),
        ("E-13",),
    ),
    GateSpec(
        "G-14",
        "INTEGRATION",
        "Cross-platform accessibility, performance, and visual evidence is attached without inventing a budget before approved baseline review.",
        ("R-05", "R-06", "R-06A"),
        (
            "W-21",
            "W-21A",
            "W-21B",
            "W-21C",
            "A-21",
            "A-21A",
            "A-21B",
            "A-21C",
            "W-24",
            "W-25",
            "W-25A",
            "A-22",
            "A-22A",
            "R-01",
            "R-01A",
        ),
        ("E-14",),
    ),
    GateSpec(
        "G-15",
        "RELEASE",
        "Review, evidence, security audits, and one focused dev integration record are complete before any release promotion.",
        ("R-08",),
        ("R-03", "R-04", "R-05", "R-06", "R-06A", "R-07", "R-07A", "R-07B", "R-07C"),
        ("E-15",),
    ),
)

EVIDENCE: Tuple[Tuple[str, str, str], ...] = (
    ("E-01", "G-01", "Planning record"),
    ("E-02", "G-02", "Source-audit and compatibility record"),
    ("E-03", "G-03", "Issue-template parity result"),
    ("E-04", "G-04", "Checklist validator result"),
    ("E-05", "G-05", "Route manifest and default-deny fixture diff"),
    ("E-06", "G-06", "Synthetic fixture and parity result"),
    ("E-07", "G-07", "Paper artboard and token manifest review"),
    ("E-08", "G-08", "Benchmark method and harness evidence"),
    ("E-09", "G-09", "Accessibility applicability and preservation result"),
    ("E-10", "G-10", "No-network mock-scope result"),
    ("E-11", "G-11", "Synthetic deployment, security, and redaction result"),
    ("E-12", "G-12", "Caddy and Traefik normalized proof result"),
    ("E-13", "G-13", "Pinned disposable integration trace"),
    ("E-14", "G-14", "Cross-platform accessibility and performance matrix"),
    ("E-15", "G-15", "Review, evidence, and dev-integration record"),
)

PARITY_SECTIONS: Tuple[str, ...] = (
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

# This is the ordered slot inventory from .github/ISSUE_TEMPLATE/roadmap.md.
# Keeping it here makes parity checkable offline and prevents a checklist from
# quietly dropping a required issue-body field.
PARITY_FIELDS: Tuple[str, ...] = (
    "Owner",
    "Assigned subagent",
    "Reviewer",
    "Child issues",
    "Hard blockers",
    "Soft sequence",
    "Normal",
    "Loading or pending",
    "Empty",
    "Success",
    "Failure",
    "Interruption or cancellation",
    "Retry and recovery",
    "Paper file",
    "Artboards",
    "Static states",
    "Contract paths",
    "Contract version or pinned Hermes SHA",
    "Fixture IDs",
    "Unit tests",
    "Component or UI tests",
    "Integration or deployment tests",
    "Parity tests",
    "Negative tests",
    "Regression tests",
    "Keyboard and focus",
    "Semantic name",
    "Screen reader or VoiceOver",
    "Switch Control",
    "Dynamic Type or browser zoom",
    "Contrast",
    "Reduced motion and reduced transparency",
    "Touch target",
    "Deterministic fixture",
    "Metric",
    "Environment and device",
    "Build mode",
    "Repetitions and distribution",
    "Trace artifact",
    "Baseline or approved budget",
    "Pull request",
    "Commit SHA",
    "Paper review",
    "Fixture diff",
    "Test output",
    "Accessibility result",
    "Benchmark trace",
    "Proxy or integration trace",
    "Security and redaction review",
)

# Exact visible unchecked lines from .github/ISSUE_TEMPLATE/roadmap.md.  Keep
# this local copy synchronized so checklist parity fails closed when the atomic
# issue contract changes, including its required verification-results evidence.
TEMPLATE_DOD: Tuple[str, ...] = (
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

CHECKLIST_DOD: Tuple[str, ...] = (
    "The M0 prerequisite set contains only `P0-01`, `P0-02`, `P0-05`, and `P0-06`.",
    "Application scaffolding remains blocked until every earlier scaffold gate is checked with its required evidence.",
    "Live integration remains blocked until every integration and release gate is checked with its required evidence.",
    "Every exception field contains an inline reason and no performance threshold is invented.",
    "The validator, template validator, focused tests, and graph checks have reproducible outputs.",
    "The focused pull request is reviewed and integrated into `dev`; publication does not merge or close the issue.",
)

SECTION_FIELDS: Dict[str, Tuple[str, ...]] = {
    "4. Accessibility and performance": (
        "Paper applicability",
        "Preservation evidence",
        "Deterministic fixture",
        "Metric",
        "Environment",
        "Build mode",
        "Repetitions and distribution",
        "Trace artifact",
        "Raw command",
        "Artifact-size evidence",
        "Validator-duration evidence",
        "Threshold statement",
    ),
    "5. No-network and privacy": (
        "No-network result",
        "Live integration posture",
        "Redaction result",
    ),
    "7. Review and dev integration": (
        "Review commands",
        "Review result",
        "Pull request",
        "Commit SHA",
        "Paper review",
        "Fixture diff",
        "Test output",
        "Accessibility result",
        "Benchmark trace",
        "Proxy or integration trace",
        "Security and redaction review",
        "Dev integration result",
        "Issue comment",
    ),
    "9. Reproduction": (
        "Validator command",
        "Template validator command",
        "Focused test command",
        "Strict JSON check",
        "Graph check",
    ),
}


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
class Fence:
    char: str
    length: int
    info: str


@dataclass(frozen=True)
class MarkdownLine:
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
class ScanResult:
    lines: Tuple[MarkdownLine, ...]
    errors: Tuple[ValidationError, ...]


class _CliArgumentError(ValueError):
    """Raised without argparse printing usage before structured JSON output."""


_FRONT_FIELD_RE = re.compile(r"^\*\*([^*]+):\*\* (.+)$")
_H2_RE = re.compile(r"^## (.+)$")
_H3_RE = re.compile(r"^### (.+)$")
_BULLET_FIELD_RE = re.compile(r"^- (?:\*\*)?([A-Za-z][A-Za-z0-9 /+.-]*):(?:\*\*)? (.*)$")
_CHECKBOX_RE = re.compile(r"^- \[([ xX])\] (.*)$")
_FENCE_OPEN_RE = re.compile(r"^( {0,3})([`~]{3,})(.*)$")
_FENCE_CLOSE_RE = re.compile(r"^( {0,3})([`~]{3,})[ \t]*$")
_ISSUE_LINK_RE = re.compile(
    r"\[([A-Z][A-Z0-9]*-[0-9]+[A-Z]*)\]\(https://github\.com/"
    + re.escape(REPOSITORY)
    + r"/issues/([0-9]+)\)"
)
_ANY_ISSUE_URL_RE = re.compile(r"https?://github\.com/[^\s)]+/issues/[0-9]+")
_EVIDENCE_RE = re.compile(r"`(E-[0-9]{2})`")
_GATE_RE = re.compile(r"`(G-[0-9]{2})`")
_TABLE_SEPARATOR_RE = re.compile(r"^\|\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)+\|$")
_BARE_GATE_RE = re.compile(r"\bG-[0-9]{2}\b")
_BARE_EVIDENCE_RE = re.compile(r"\bE-[0-9]{2}\b")


def _error(code: str, line: Optional[int], message: str) -> ValidationError:
    return ValidationError(code=code, line=line, message=message)


def _split_lines(text: str) -> Tuple[List[SourceLine], set[str], bool]:
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
    return result, endings, bool(result and result[-1].ending)


def _strip_html_comments(text: str, in_comment: bool) -> Tuple[str, bool]:
    """Remove all comment spans on one line while retaining visible fragments."""

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
    match = _FENCE_OPEN_RE.fullmatch(text)
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


def _scan_markdown(lines: Sequence[SourceLine]) -> ScanResult:
    """Hide comments and arbitrary fences in one stateful document pass."""

    scanned: List[MarkdownLine] = []
    errors: List[ValidationError] = []
    in_comment = False
    active_fence: Optional[Fence] = None
    fence_open_line: Optional[int] = None

    for source_line in lines:
        if active_fence is not None:
            if _parse_fence_close(source_line.text, active_fence):
                match = _FENCE_CLOSE_RE.fullmatch(source_line.text)
                close_length = len(match.group(2)) if match else active_fence.length
                scanned.append(
                    MarkdownLine(
                        source=source_line,
                        text=source_line.text,
                        hidden=False,
                        fence_role="close",
                        fence_char=active_fence.char,
                        fence_length=close_length,
                    )
                )
                active_fence = None
                fence_open_line = None
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
            fence_open_line = source_line.number
            continue

        comment_only = bool(source_line.text.strip()) and not visible_text.strip()
        scanned.append(
            MarkdownLine(source=source_line, text=visible_text, hidden=comment_only)
        )

    if active_fence is not None:
        errors.append(
            _error(
                "fence-unclosed",
                fence_open_line,
                "A backtick or tilde fence opens without a matching closing fence.",
            )
        )
    if in_comment:
        errors.append(
            _error(
                "comment-unclosed",
                lines[-1].number if lines else 1,
                "An HTML comment opens without a closing `-->`.",
            )
        )
    return ScanResult(tuple(scanned), tuple(errors))


def _visible(scanned: Sequence[MarkdownLine]) -> List[MarkdownLine]:
    return [line for line in scanned if not line.hidden and line.fence_role is None]


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
                "The checklist must use one line-ending style throughout.",
            )
        )
    if lines and not final_newline:
        errors.append(
            _error(
                "missing-final-newline",
                lines[-1].number,
                "The checklist must end with a newline.",
            )
        )
    return errors


def _validate_title_and_metadata(scanned: Sequence[MarkdownLine]) -> List[ValidationError]:
    errors: List[ValidationError] = []
    visible = _visible(scanned)
    h2_line = next((index for index, line in enumerate(visible) if line.text.startswith("## ")), len(visible))
    preamble = visible[:h2_line]
    titles = [line for line in preamble if line.text.startswith("#")]
    h1 = [line for line in titles if line.text.startswith("# ")]
    if not h1:
        errors.append(_error("title-missing", 1, f"The checklist must start with `# {CHECKLIST_TITLE}`."))
    else:
        if h1[0].text != f"# {CHECKLIST_TITLE}":
            errors.append(_error("title-value", h1[0].source.number, f"The title must be exactly `{CHECKLIST_TITLE}`."))
        for duplicate in h1[1:]:
            errors.append(_error("title-duplicate", duplicate.source.number, "The checklist may contain only one level-one title."))
    for line in titles:
        if not line.text.startswith("# "):
            errors.append(_error("title-malformed", line.source.number, "Only one exact level-one title is allowed."))

    expected = dict(METADATA)
    observed: Dict[str, List[Tuple[SourceLine, str]]] = {key: [] for key, _value in METADATA}
    for line in preamble:
        match = _FRONT_FIELD_RE.fullmatch(line.text)
        if not match:
            continue
        label, value = match.groups()
        if label not in expected:
            errors.append(_error("metadata-unknown", line.source.number, f"Unknown metadata field `{label}`."))
            continue
        observed[label].append((line.source, value))
        if value != expected[label]:
            errors.append(_error("metadata-value", line.source.number, f"Metadata field `{label}` must be exactly `{expected[label]}`."))
    for label, _value in METADATA:
        matches = observed[label]
        if not matches:
            errors.append(_error("metadata-missing", h1[0].source.number if h1 else 1, f"Required metadata field `{label}` is missing."))
        elif len(matches) > 1:
            for source_line, _value in matches[1:]:
                errors.append(_error("metadata-duplicate", source_line.number, f"Metadata field `{label}` appears more than once."))
    observed_order = [line.text.split(":", 1)[0][2:] for line in preamble if _FRONT_FIELD_RE.fullmatch(line.text)]
    expected_order = [label for label, _value in METADATA]
    if not any(error.code.startswith("metadata-") and error.code in {"metadata-missing", "metadata-duplicate", "metadata-unknown"} for error in errors):
        if observed_order != expected_order:
            line = next((line.source.number for line in preamble if _FRONT_FIELD_RE.fullmatch(line.text)), 1)
            errors.append(_error("metadata-reordered", line, "Metadata fields must remain in canonical order."))
    return errors


def _collect_headings(scanned: Sequence[MarkdownLine]) -> Tuple[List[Heading], List[Heading], List[ValidationError]]:
    h2: List[Heading] = []
    h3: List[Heading] = []
    errors: List[ValidationError] = []
    for line in scanned:
        if line.hidden or line.fence_role is not None:
            continue
        text = line.text
        if text.startswith("#"):
            if text.startswith("##") and not text.startswith("###"):
                match = _H2_RE.fullmatch(text)
                if match and match.group(1) == match.group(1).rstrip():
                    h2.append(Heading(match.group(1), line.source, "h2"))
                else:
                    h2.append(Heading(None, line.source, "h2"))
                    errors.append(_error("section-malformed", line.source.number, "Level-two headings must use exactly `## ` followed by a section title."))
            elif text.startswith("###"):
                match = _H3_RE.fullmatch(text)
                if match and not text.startswith("####") and match.group(1) == match.group(1).rstrip():
                    h3.append(Heading(match.group(1), line.source, "h3"))
                else:
                    h3.append(Heading(None, line.source, "h3"))
                    errors.append(_error("subsection-malformed", line.source.number, "Level-three headings must use exactly `### ` followed by a subsection title."))
            elif text.startswith("# "):
                continue
            else:
                errors.append(_error("heading-malformed", line.source.number, "Headings must use the published level and exact spacing."))
    return h2, h3, errors


def _validate_sections(h2: Sequence[Heading]) -> List[ValidationError]:
    errors: List[ValidationError] = []
    expected = list(SECTIONS)
    observed = [heading.title for heading in h2 if heading.title is not None]
    for heading in h2:
        if heading.title is not None and heading.title not in expected:
            errors.append(_error("section-unknown", heading.line.number, f"Unknown level-two section `{heading.title}`."))
    locations: Dict[str, List[Heading]] = {title: [] for title in expected}
    for heading in h2:
        if heading.title in locations:
            locations[heading.title].append(heading)
    for title in expected:
        matches = locations[title]
        if not matches:
            errors.append(_error("section-missing", h2[-1].line.number if h2 else 1, f"Required section `{title}` is missing."))
        elif len(matches) > 1:
            for duplicate in matches[1:]:
                errors.append(_error("section-duplicate", duplicate.line.number, f"Section `{title}` appears more than once."))
    if not any(error.code in {"section-missing", "section-duplicate", "section-unknown"} for error in errors) and observed != expected:
        first = next(index for index, (actual, wanted) in enumerate(zip(observed, expected)) if actual != wanted)
        errors.append(_error("section-reordered", h2[first].line.number, "Sections must remain in the canonical order."))
    return errors


def _section_body(h2: Sequence[Heading], title: str, scanned: Sequence[MarkdownLine]) -> Tuple[Optional[Heading], List[MarkdownLine]]:
    for index, heading in enumerate(h2):
        if heading.title != title:
            continue
        end_line = h2[index + 1].line.number if index + 1 < len(h2) else len(scanned) + 1
        return heading, [line for line in scanned if heading.line.number < line.source.number < end_line]
    return None, []


def _validate_subsections(h2: Sequence[Heading], h3: Sequence[Heading], scanned: Sequence[MarkdownLine]) -> List[ValidationError]:
    errors: List[ValidationError] = []
    for section, expected_tuple in SUBSECTIONS.items():
        expected = list(expected_tuple)
        heading, body = _section_body(h2, section, scanned)
        if heading is None:
            continue
        next_h2_line = next(
            (next_heading.line.number for next_heading in h2 if next_heading.line.number > heading.line.number),
            len(scanned) + 1,
        )
        observed = [
            item
            for item in h3
            if heading.line.number < item.line.number < next_h2_line
        ]
        for item in observed:
            if item.title is None:
                continue
            if item.title not in expected:
                errors.append(_error("subsection-unknown", item.line.number, f"Unknown subsection `{item.title}` in `{section}`."))
        locations: Dict[str, List[Heading]] = {name: [] for name in expected}
        for item in observed:
            if item.title in locations:
                locations[item.title].append(item)
        for name in expected:
            matches = locations[name]
            if not matches:
                errors.append(_error("subsection-missing", heading.line.number, f"Required subsection `{name}` is missing from `{section}."))
            elif len(matches) > 1:
                for duplicate in matches[1:]:
                    errors.append(_error("subsection-duplicate", duplicate.line.number, f"Subsection `{name}` appears more than once in `{section}."))
        observed_known = [item.title for item in observed if item.title in locations]
        if not any(error.code in {"subsection-missing", "subsection-duplicate", "subsection-unknown"} for error in errors if error.line is not None and error.line >= heading.line.number) and observed_known != expected:
            first = next(index for index, (actual, wanted) in enumerate(zip(observed_known, expected)) if actual != wanted)
            line = next(item.line.number for item in observed if item.title == observed_known[first])
            errors.append(_error("subsection-reordered", line, f"Subsections in `{section}` must remain in canonical order."))
        if not expected and observed:
            for item in observed:
                errors.append(_error("subsection-unknown", item.line.number, f"Section `{section}` does not allow subsections."))
    return errors


def _split_table_row(text: str) -> Optional[List[str]]:
    if not text.startswith("|") or not text.endswith("|"):
        return None
    return [cell.strip() for cell in text[1:-1].split("|")]


def _table_after_header(body: Sequence[MarkdownLine], header: str, columns: int, code: str) -> Tuple[List[Tuple[SourceLine, List[str]]], List[ValidationError]]:
    errors: List[ValidationError] = []
    visible = _visible(body)
    positions = [index for index, line in enumerate(visible) if line.text == header]
    if not positions:
        return [], [_error(f"{code}-missing", body[0].source.number if body else 1, f"Required table header `{header}` is missing.")]
    if len(positions) > 1:
        for duplicate in positions[1:]:
            errors.append(_error(f"{code}-duplicate", visible[duplicate].source.number, f"Table header `{header}` appears more than once."))
    start = positions[0]
    if start + 1 >= len(visible) or not _TABLE_SEPARATOR_RE.fullmatch(visible[start + 1].text):
        errors.append(_error(f"{code}-malformed", visible[start].source.number, "A table header must be followed by a Markdown separator row."))
        return [], errors
    rows: List[Tuple[SourceLine, List[str]]] = []
    for line in visible[start + 2 :]:
        if not line.text.startswith("|"):
            if rows:
                break
            continue
        cells = _split_table_row(line.text)
        if cells is None or len(cells) != columns:
            errors.append(_error(f"{code}-row-malformed", line.source.number, f"Rows after `{header}` must contain exactly {columns} cells."))
            continue
        rows.append((line.source, cells))
    if not rows:
        errors.append(_error(f"{code}-empty", visible[start].source.number, f"Table `{header}` must contain rows."))
    return rows, errors


def _issue_milestone(key: str) -> Optional[int]:
    prefix = key.split("-", 1)[0]
    return MILESTONE_RANK.get(prefix)


def _parse_issue_links(cell: str, line: int, errors: List[ValidationError]) -> Tuple[str, ...]:
    keys: List[str] = []
    for match in _ISSUE_LINK_RE.finditer(cell):
        key, number_text = match.groups()
        number = int(number_text)
        if key not in ROADMAP_ISSUES:
            errors.append(_error("issue-key-unknown", line, f"Issue key `{key}` is not in the approved roadmap index."))
        elif ROADMAP_ISSUES[key] != number:
            errors.append(_error("issue-link-mismatch", line, f"Issue link for `{key}` must target `#{ROADMAP_ISSUES[key]}`, not `#{number}."))
        keys.append(key)
    if re.search(r"/issues/", cell) and not _ISSUE_LINK_RE.search(cell):
        errors.append(_error("issue-link-malformed", line, "Roadmap issue links must use the canonical GitHub URL and key form."))
    return tuple(keys)


def _parse_evidence_refs(cell: str, line: int, errors: List[ValidationError]) -> Tuple[str, ...]:
    refs = tuple(_EVIDENCE_RE.findall(cell))
    bare = [token for token in _BARE_EVIDENCE_RE.findall(cell) if f"`{token}`" not in cell]
    if bare:
        errors.append(_error("evidence-ref-malformed", line, "Evidence references must use backtick-wrapped `E-##` keys."))
    return refs


def _validate_issue_urls(scanned: Sequence[MarkdownLine]) -> List[ValidationError]:
    errors: List[ValidationError] = []
    for line in _visible(scanned):
        for url_match in _ANY_ISSUE_URL_RE.finditer(line.text):
            url = url_match.group(0)
            if not re.fullmatch(
                r"https://github\.com/" + re.escape(REPOSITORY) + r"/issues/[0-9]+",
                url,
            ):
                errors.append(_error("issue-link-domain", line.source.number, "Issue links must point to the Hermternal repository."))
    return errors


def _validate_gate_table(h2: Sequence[Heading], scanned: Sequence[MarkdownLine]) -> List[ValidationError]:
    header = "| Gate | Phase | Requirement | Owner roadmap issue(s) | Depends on | Required evidence | Status |"
    heading, body = _section_body(h2, "2. Fail-closed gate order", scanned)
    if heading is None:
        return []
    rows, errors = _table_after_header(body, header, 7, "gate-table")
    expected = {gate.key: gate for gate in GATES}
    records: List[Tuple[str, SourceLine, List[str]]] = []
    for source_line, cells in rows:
        gate_match = _GATE_RE.fullmatch(cells[0])
        key = gate_match.group(1) if gate_match else cells[0].strip("`")
        if key not in expected:
            errors.append(_error("gate-unknown", source_line.number, f"Unknown gate `{key}`."))
        records.append((key, source_line, cells))
    locations: Dict[str, List[Tuple[SourceLine, List[str]]]] = {gate.key: [] for gate in GATES}
    for key, source_line, cells in records:
        if key in locations:
            locations[key].append((source_line, cells))
    for gate in GATES:
        matches = locations[gate.key]
        if not matches:
            errors.append(_error("gate-missing", heading.line.number, f"Required gate `{gate.key}` is missing."))
        elif len(matches) > 1:
            for duplicate, _cells in matches[1:]:
                errors.append(_error("gate-duplicate", duplicate.number, f"Gate `{gate.key}` appears more than once."))
    observed_known = [key for key, _line, _cells in records if key in expected]
    expected_order = [gate.key for gate in GATES]
    if not any(error.code in {"gate-missing", "gate-duplicate", "gate-unknown", "gate-table-row-malformed"} for error in errors) and observed_known != expected_order:
        first = next(index for index, (actual, wanted) in enumerate(zip(observed_known, expected_order)) if actual != wanted)
        source_line = next(line for key, line, _cells in records if key == observed_known[first])
        errors.append(_error("gate-reordered", source_line.number, "Gate rows must remain in canonical order."))

    for key, source_line, cells in records:
        gate = expected.get(key)
        if gate is None:
            continue
        if cells[1] != gate.phase:
            errors.append(_error("gate-phase", source_line.number, f"Gate `{key}` must use phase `{gate.phase}`."))
        if cells[2] != gate.description:
            errors.append(_error("gate-requirement", source_line.number, f"Gate `{key}` requirement text does not match the approved checklist."))
        owner_keys = _parse_issue_links(cells[3], source_line.number, errors)
        if owner_keys != gate.owners:
            errors.append(_error("gate-owner", source_line.number, f"Gate `{key}` must name owners {gate.owners}."))
        dependency_keys = _parse_issue_links(cells[4], source_line.number, errors)
        if dependency_keys != gate.dependencies:
            errors.append(_error("gate-dependencies", source_line.number, f"Gate `{key}` must use the approved upstream dependency order."))
        evidence_refs = _parse_evidence_refs(cells[5], source_line.number, errors)
        if evidence_refs != gate.evidence:
            errors.append(_error("gate-evidence", source_line.number, f"Gate `{key}` must name evidence {gate.evidence}."))
        status = cells[6]
        if status == "[ ]":
            pass
        elif status.casefold() in {"[x]", "[x]"}:
            errors.append(_error("gate-checked", source_line.number, f"Gate `{key}` is checked in the published contract; evidence must remain pending."))
        elif "waiv" in status.casefold() or "n/a" in status.casefold() or status.casefold() in {"skip", "optional"}:
            errors.append(_error("gate-waived", source_line.number, f"Gate `{key}` cannot be waived or marked N/A."))
        else:
            errors.append(_error("gate-status", source_line.number, f"Gate `{key}` status must be exactly `[ ]`."))

        # Run dependency checks against the row's parsed values, not the
        # expected spec.  A mutated owner or dependency must produce a
        # directional failure before the exact-row mismatch is considered.
        owner_ranks = [
            rank for owner in owner_keys if (rank := _issue_milestone(owner)) is not None
        ]
        for dependency in dependency_keys:
            rank = _issue_milestone(dependency)
            if rank is None:
                continue
            if owner_ranks and rank > max(owner_ranks):
                errors.append(
                    _error(
                        "dependency-direction",
                        source_line.number,
                        f"Dependency `{dependency}` is downstream of gate `{key}`.",
                    )
                )
            if gate.phase == "M0" and dependency not in M0_KEYS:
                errors.append(
                    _error(
                        "stale-blocker",
                        source_line.number,
                        f"M0 gate `{key}` cannot depend on downstream issue `{dependency}`.",
                    )
                )
        if gate.phase == "M0" and any(owner not in M0_KEYS for owner in owner_keys):
            errors.append(
                _error(
                    "stale-blocker",
                    source_line.number,
                    f"M0 gate `{key}` cannot be owned by a downstream runtime issue.",
                )
            )
            errors.append(
                _error(
                    "dependency-direction",
                    source_line.number,
                    f"M0 gate `{key}` cannot be owned by a downstream runtime issue.",
                )
            )
    return errors


def _validate_evidence_table(h2: Sequence[Heading], scanned: Sequence[MarkdownLine]) -> List[ValidationError]:
    header = "| Evidence | Owning gate | Required field | Fail-closed requirement |"
    heading, body = _section_body(h2, "3. Required evidence", scanned)
    if heading is None:
        return []
    rows, errors = _table_after_header(body, header, 4, "evidence-table")
    expected = {evidence_id: (gate, field) for evidence_id, gate, field in EVIDENCE}
    records: List[Tuple[str, SourceLine, List[str]]] = []
    for source_line, cells in rows:
        key = cells[0].strip("`")
        if key not in expected:
            errors.append(_error("evidence-unknown", source_line.number, f"Unknown evidence key `{key}`."))
        records.append((key, source_line, cells))
    locations: Dict[str, List[Tuple[SourceLine, List[str]]]] = {key: [] for key, _gate, _field in EVIDENCE}
    for key, source_line, cells in records:
        if key in locations:
            locations[key].append((source_line, cells))
    for key, _gate, _field in EVIDENCE:
        matches = locations[key]
        if not matches:
            errors.append(_error("evidence-missing", heading.line.number, f"Required evidence row `{key}` is missing."))
        elif len(matches) > 1:
            for duplicate, _cells in matches[1:]:
                errors.append(_error("evidence-duplicate", duplicate.number, f"Evidence row `{key}` appears more than once."))
    observed = [key for key, _line, _cells in records if key in locations]
    expected_order = [key for key, _gate, _field in EVIDENCE]
    if not any(error.code in {"evidence-missing", "evidence-duplicate", "evidence-unknown", "evidence-table-row-malformed"} for error in errors) and observed != expected_order:
        first = next(index for index, (actual, wanted) in enumerate(zip(observed, expected_order)) if actual != wanted)
        source_line = next(line for key, line, _cells in records if key == observed[first])
        errors.append(_error("evidence-reordered", source_line.number, "Evidence rows must remain in canonical order."))
    for key, source_line, cells in records:
        expected_record = expected.get(key)
        if expected_record is None:
            continue
        owner, field = expected_record
        if cells[1].strip("`") != owner:
            errors.append(_error("evidence-owner", source_line.number, f"Evidence `{key}` must belong to gate `{owner}`."))
        if cells[2].strip("`") != field:
            errors.append(_error("evidence-field", source_line.number, f"Evidence `{key}` must use required field `{field}`."))
        if not cells[3].strip():
            errors.append(_error("evidence-empty", source_line.number, f"Evidence `{key}` requires a non-empty fail-closed requirement."))
    return errors


def _collect_bullet_fields(body: Sequence[MarkdownLine], expected: Sequence[str]) -> Tuple[List[Tuple[str, SourceLine, str]], List[ValidationError]]:
    records: List[Tuple[str, SourceLine, str]] = []
    errors: List[ValidationError] = []
    expected_set = set(expected)
    for line in _visible(body):
        match = _BULLET_FIELD_RE.fullmatch(line.text)
        if not match:
            if line.text.startswith("- ") and ":" in line.text:
                errors.append(_error("field-malformed", line.source.number, "Required fields must use `- Label: value` syntax."))
            continue
        label, value = match.groups()
        if label not in expected_set:
            errors.append(_error("field-unknown", line.source.number, f"Unknown field `{label}`."))
        records.append((label, line.source, value))
    locations: Dict[str, List[Tuple[SourceLine, str]]] = {label: [] for label in expected}
    for label, source_line, value in records:
        if label in locations:
            locations[label].append((source_line, value))
    for label in expected:
        matches = locations[label]
        if not matches:
            errors.append(_error("field-missing", body[0].source.number if body else 1, f"Required field `{label}` is missing."))
        elif len(matches) > 1:
            for duplicate, _value in matches[1:]:
                errors.append(_error("field-duplicate", duplicate.number, f"Field `{label}` appears more than once."))
        elif not matches[0][1].strip():
            errors.append(_error("field-empty", matches[0][0].number, f"Field `{label}` must not be empty."))
    observed = [label for label, _line, _value in records if label in expected_set]
    if not any(error.code in {"field-missing", "field-duplicate", "field-unknown", "field-malformed"} for error in errors) and observed != list(expected):
        first = next(index for index, (actual, wanted) in enumerate(zip(observed, expected)) if actual != wanted)
        source_line = next(line for label, line, _value in records if label == observed[first])
        errors.append(_error("field-reordered", source_line.number, "Fields must remain in canonical order."))
    return records, errors


def _validate_section_fields(h2: Sequence[Heading], scanned: Sequence[MarkdownLine]) -> List[ValidationError]:
    errors: List[ValidationError] = []
    for section, expected in SECTION_FIELDS.items():
        heading, body = _section_body(h2, section, scanned)
        if heading is None:
            continue
        records, field_errors = _collect_bullet_fields(body, expected)
        errors.extend(field_errors)
        values = {label: value for label, _line, value in records}
        if section == "4. Accessibility and performance":
            if "Paper applicability" in values and not values["Paper applicability"].startswith("N/A"):
                errors.append(_error("paper-na", next(line.number for label, line, _value in records if label == "Paper applicability"), "This non-UI artifact must record Paper applicability as N/A with a reason."))
            if "Preservation evidence" in values:
                preservation = values["Preservation evidence"]
                preservation_line = next(
                    line.number
                    for label, line, _value in records
                    if label == "Preservation evidence"
                )
                has_preservation_semantics = bool(
                    re.search(
                        r"\b(?:preserv\w*|retain\w*|keep\w*|does not (?:rewrite|remove|alter|drop)|never (?:rewrite|remove|alter|drop))\b",
                        preservation,
                        re.I,
                    )
                )
                has_accessibility_surface = bool(
                    re.search(
                        r"\b(?:keyboard|focus|semantic[- ]names?|screen[- ]reader|voiceover|switch control|"
                        r"(?:200%[ -])?(?:browser[ -])?zoom|dynamic type|contrast|"
                        r"reduced[- ]motion|reduced[- ]transparency|touch[- ]targets?)\b",
                        preservation,
                        re.I,
                    )
                )
                has_reason_connector = bool(
                    re.search(
                        r"\b(?:because|since|so that|by|without)\b",
                        preservation,
                        re.I,
                    )
                )
                has_mechanism = bool(
                    re.search(
                        r"\b(?:read(?:s)? bytes|emit(?:s)? diagnostics|only read(?:s)?|"
                        r"does not (?:rewrite|remove|alter|drop)|never (?:rewrite|remove|alter|drop)|"
                        r"non[- ]UI|no direct UI|downstream (?:design|paper) source|tooling artifact)\b",
                        preservation,
                        re.I,
                    )
                )
                if not (
                    has_preservation_semantics
                    and has_accessibility_surface
                    and has_reason_connector
                    and has_mechanism
                ):
                    errors.append(
                        _error(
                            "preservation-evidence",
                            preservation_line,
                            "Preservation evidence must state which accessibility behavior is preserved or not removed and why.",
                        )
                    )
            if "Build mode" in values and not values["Build mode"].startswith("N/A"):
                errors.append(_error("benchmark-build-mode", next(line.number for label, line, _value in records if label == "Build mode"), "Build mode must be N/A with a tooling reason."))
            repetitions = values.get("Repetitions and distribution", "").casefold()
            if not all(
                token in repetitions
                for token in ("10", "min", "mean", "median", "p95", "max", "all ten")
            ):
                errors.append(
                    _error(
                        "benchmark-distribution",
                        heading.line.number,
                        "Benchmark evidence must name ten samples, min, mean, median, p95, max, and all ten values.",
                    )
                )
            raw_command = values.get("Raw command", "").casefold()
            if (
                "python3" not in raw_command
                or "validate_proof_gates.py" not in raw_command
                or "mean" not in raw_command
                or "p95" not in raw_command
                or "samples" not in raw_command
            ):
                errors.append(
                    _error(
                        "benchmark-command",
                        heading.line.number,
                        "Benchmark evidence must include a local raw command that records samples, mean, and p95.",
                    )
                )
            size_evidence = values.get("Artifact-size evidence", "").casefold()
            if "bytes" not in size_evidence or "validate_proof_gates.py" not in size_evidence or "test_validate_proof_gates.py" not in size_evidence:
                errors.append(_error("artifact-size-evidence", heading.line.number, "Artifact-size evidence must name both proof-gate scripts and byte sizes."))
            duration = values.get("Validator-duration evidence", "").casefold()
            if not all(
                token in duration
                for token in ("min", "mean", "median", "p95", "max", "ms", "samples")
            ):
                errors.append(
                    _error(
                        "validator-duration-evidence",
                        heading.line.number,
                        "Validator-duration evidence must include all samples, min, mean, median, p95, max, and milliseconds.",
                    )
                )
            threshold = values.get("Threshold statement", "").casefold()
            if threshold != "no threshold is claimed.":
                errors.append(_error("threshold-statement", heading.line.number, "The benchmark section must state exactly `No threshold is claimed.`."))
        if section == "5. No-network and privacy":
            network = values.get("No-network result", "").casefold()
            if not any(token in network for token in ("standard library", "local", "never contacts")):
                errors.append(_error("no-network-evidence", heading.line.number, "No-network evidence must describe local standard-library execution."))
        if section == "7. Review and dev integration":
            review = values.get("Review commands", "")
            if "rtk diff" not in review or "code-review-graph update --brief" not in review or "code-review-graph detect-changes" not in review:
                errors.append(_error("review-commands", heading.line.number, "Review evidence must name rtk diff and both code-review-graph commands."))
            if values.get("Dev integration result", "").casefold().find("dev") < 0:
                errors.append(_error("dev-integration-field", heading.line.number, "Dev integration evidence must target the `dev` branch."))
    return errors


def _strip_code_ticks(value: str) -> str:
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == "`" and stripped[-1] == "`":
        return stripped[1:-1]
    return stripped


def _validate_parity_tables(h2: Sequence[Heading], h3: Sequence[Heading], scanned: Sequence[MarkdownLine]) -> List[ValidationError]:
    errors: List[ValidationError] = []
    heading, body = _section_body(h2, "6. Atomic issue-template parity", scanned)
    if heading is None:
        return errors
    expected_subsections = ["Section parity", "Field parity", "Definition-of-done parity"]
    subsection_map: Dict[str, Tuple[Optional[Heading], List[MarkdownLine]]] = {}
    for subsection in expected_subsections:
        subheading = next((item for item in h3 if item.title == subsection and heading.line.number < item.line.number), None)
        if subheading is None:
            subsection_map[subsection] = (None, [])
        else:
            end_line = next((item.line.number for item in h3 if item.line.number > subheading.line.number), len(scanned) + 1)
            subsection_map[subsection] = (subheading, [line for line in scanned if subheading.line.number < line.source.number < end_line and line.source.number < (next((next_h2.line.number for next_h2 in h2 if next_h2.line.number > heading.line.number), len(scanned) + 1))])

    section_header = "| Order | Atomic issue-template item | Checklist preservation |"
    section_rows, section_errors = _table_after_header(subsection_map["Section parity"][1], section_header, 3, "parity-section")
    errors.extend(section_errors)
    _validate_ordered_simple_table(section_rows, [f"{index:02d}" for index in range(1, 11)], list(PARITY_SECTIONS), errors, "parity-section", "Atomic issue-template sections")

    field_header = "| Order | Template field | Checklist preservation |"
    field_rows, field_errors = _table_after_header(subsection_map["Field parity"][1], field_header, 3, "parity-field")
    errors.extend(field_errors)
    _validate_ordered_simple_table(field_rows, [f"F-{index:02d}" for index in range(1, len(PARITY_FIELDS) + 1)], list(PARITY_FIELDS), errors, "parity-field", "Atomic issue-template fields")

    dod_header = "| Order | Definition-of-done item | Checklist preservation |"
    dod_rows, dod_errors = _table_after_header(subsection_map["Definition-of-done parity"][1], dod_header, 3, "parity-dod")
    errors.extend(dod_errors)
    _validate_ordered_simple_table(dod_rows, [f"D-{index:02d}" for index in range(1, len(TEMPLATE_DOD) + 1)], [f"{value}" for value in TEMPLATE_DOD], errors, "parity-dod", "Definition-of-done items")
    return errors


def _validate_ordered_simple_table(
    rows: Sequence[Tuple[SourceLine, List[str]]],
    expected_ids: Sequence[str],
    expected_values: Sequence[str],
    errors: List[ValidationError],
    code: str,
    label: str,
) -> None:
    records: List[Tuple[str, str, SourceLine, List[str]]] = []
    expected_id_set = set(expected_ids)
    for source_line, cells in rows:
        key = _strip_code_ticks(cells[0])
        value = _strip_code_ticks(cells[1])
        if key not in expected_id_set:
            errors.append(_error(f"{code}-unknown", source_line.number, f"Unknown {label} row `{key}`."))
        records.append((key, value, source_line, cells))
    locations: Dict[str, List[Tuple[SourceLine, List[str]]]] = {key: [] for key in expected_ids}
    for key, _value, source_line, cells in records:
        if key in locations:
            locations[key].append((source_line, cells))
    for key in expected_ids:
        matches = locations[key]
        if not matches:
            errors.append(_error(f"{code}-missing", rows[0][0].number if rows else 1, f"Required {label} row `{key}` is missing."))
        elif len(matches) > 1:
            for duplicate, _cells in matches[1:]:
                errors.append(_error(f"{code}-duplicate", duplicate.number, f"{label} row `{key}` appears more than once."))
    observed = [key for key, _value, _line, _cells in records if key in locations]
    if not any(error.code in {f"{code}-missing", f"{code}-duplicate", f"{code}-unknown", f"{code}-row-malformed"} for error in errors) and observed != list(expected_ids):
        first = next(index for index, (actual, wanted) in enumerate(zip(observed, expected_ids)) if actual != wanted)
        line = next(source_line.number for key, _value, source_line, _cells in records if key == observed[first])
        errors.append(_error(f"{code}-reordered", line, f"{label} rows must remain in canonical order."))
    expected_value_map = dict(zip(expected_ids, expected_values))
    for key, value, source_line, cells in records:
        expected_value = expected_value_map.get(key)
        if expected_value is None:
            continue
        if value != expected_value:
            errors.append(_error(f"{code}-value", source_line.number, f"{label} row `{key}` does not match the atomic contract."))
        if not cells[2].strip():
            errors.append(_error(f"{code}-empty", source_line.number, f"{label} row `{key}` needs a preservation requirement."))


def _validate_checklist_dod(h2: Sequence[Heading], scanned: Sequence[MarkdownLine]) -> List[ValidationError]:
    errors: List[ValidationError] = []
    heading, body = _section_body(h2, "8. Definition of done", scanned)
    if heading is None:
        return errors
    observed: List[Tuple[str, SourceLine, str]] = []
    for line in _visible(body):
        if line.text.startswith("-"):
            match = _CHECKBOX_RE.fullmatch(line.text)
            if not match:
                errors.append(_error("checklist-dod-malformed", line.source.number, "Checklist definition-of-done entries must use `- [ ] text` syntax."))
            else:
                state, item = match.groups()
                observed.append((item, line.source, state))
    expected = list(CHECKLIST_DOD)
    locations: Dict[str, List[Tuple[SourceLine, str]]] = {item: [] for item in expected}
    for item, source_line, state in observed:
        if item not in locations:
            errors.append(_error("checklist-dod-unknown", source_line.number, f"Unknown checklist definition-of-done item `{item}`."))
        else:
            locations[item].append((source_line, state))
            if state != " ":
                errors.append(_error("checklist-dod-checked", source_line.number, "Checklist definition-of-done items must remain unchecked."))
    for item in expected:
        matches = locations[item]
        if not matches:
            errors.append(_error("checklist-dod-missing", heading.line.number, f"Required checklist definition-of-done item `{item}` is missing."))
        elif len(matches) > 1:
            for duplicate, _state in matches[1:]:
                errors.append(_error("checklist-dod-duplicate", duplicate.number, f"Checklist definition-of-done item `{item}` appears more than once."))
    observed_known = [item for item, _line, _state in observed if item in locations]
    if not any(error.code in {"checklist-dod-missing", "checklist-dod-duplicate", "checklist-dod-unknown", "checklist-dod-malformed"} for error in errors) and observed_known != expected:
        first = next(index for index, (actual, wanted) in enumerate(zip(observed_known, expected)) if actual != wanted)
        line = next(source_line.number for item, source_line, _state in observed if item == observed_known[first])
        errors.append(_error("checklist-dod-reordered", line, "Checklist definition-of-done items must remain in canonical order."))
    return errors


def _validate_semantic_rules(scanned: Sequence[MarkdownLine]) -> List[ValidationError]:
    errors: List[ValidationError] = []
    live_claim_patterns = (
        re.compile(
            r"\b(?:live|production)\s+(?:integration|deployment|environment|traffic|service|credentials?|release)\s+"
            r"(?:is|are|has|have|passes?|passed|verified|approved|ready|complete|successful|succeeded|works?|working|shipped|deployed|released)\b",
            re.I,
        ),
        re.compile(
            r"\b(?:passes?|passed|verified|approved|ready|complete|successful|succeeded|works?|working|shipped|deployed|released)\s+"
            r"(?:in|for)\s+(?:live|production)\b",
            re.I,
        ),
        re.compile(r"\b(?:deploy|release|ship|promote)\w*\s+(?:to|in)\s+production\b", re.I),
    )
    performance_terms = r"(?:p(?:50|75|90|95|99)|latency|memory|bundle|startup|render(?:ing)?|response(?:\s+time)?|throughput|performance|duration|slo)"
    numeric_value = r"\d+(?:\.\d+)?(?:\s*(?:ms|s|sec|mib|mb|kb|%))?\b"
    threshold_patterns = (
        re.compile(
            r"\b"
            + performance_terms
            + r"\b[^|\n]{0,80}\b(?:target|budget|slo|limit|ceiling|threshold)\b"
            r"[^|\n]{0,24}?(?:is|of|at|must be|should be|:|=|<|<=|>|>=)?\s*"
            r"(?:under|below|within|at most|no more than|less than(?: or equal to)?)?\s*"
            + numeric_value,
            re.I,
        ),
        re.compile(
            r"\b"
            + performance_terms
            + r"\b[^|\n]{0,60}\b(?:under|below|within|at most|no more than|less than(?: or equal to)?)\s*"
            + numeric_value,
            re.I,
        ),
        re.compile(
            r"\b(?:target|budget|slo|limit|ceiling|threshold)\b\s*(?::|=)\s*"
            + numeric_value,
            re.I,
        ),
        re.compile(
            r"\b"
            + performance_terms
            + r"\b[^|\n]{0,24}(?:<|<=|>|>=|=)\s*"
            + numeric_value,
            re.I,
        ),
    )
    for line in _visible(scanned):
        text = line.text
        if re.search(
            r"\b(?:gate|status|checklist item)\b[^\n]{0,40}\b(?:waiv(?:e|ed|er)|skip(?:ping)?|optional)\b"
            r"|\b(?:waiv(?:e|ed|er)|skip(?:ping)?|optional)\b[^\n]{0,40}\b(?:gate|status|checklist item)\b",
            text,
            re.I,
        ):
            errors.append(_error("gate-waived", line.source.number, "A proof gate cannot be waived, skipped, or made optional."))
        # Evaluate punctuation and conjunction-delimited clauses
        # independently. A negated boundary clause must not suppress a later
        # positive live claim on the same Markdown line.
        clauses = [
            part.strip()
            for sentence in re.split(r"[;.!?]+", text)
            for part in re.split(
                r",?\s+\b(?:but|however|yet|and)\b",
                sentence,
                flags=re.I,
            )
            if part.strip()
        ]
        for clause in clauses:
            negative_context = bool(
                re.search(
                    r"\b(?:no|not|never|cannot|can't|does not|do not|must not|without|blocked|pending|remains blocked|not yet|has not|have not|is not|are not)\b",
                    clause,
                    re.I,
                )
            )
            if negative_context:
                continue
            for pattern in live_claim_patterns:
                if pattern.search(clause):
                    errors.append(
                        _error(
                            "live-production-claim",
                            line.source.number,
                            "The checklist must not claim live or production success.",
                        )
                    )
                    break

        # Measured evidence fields may report numeric observations, but they
        # do not exempt target, budget, SLO, limit, or bound prose in the same
        # value. The patterns distinguish observations such as `p95 58 ms`
        # from claims such as `p95 target is 50 ms`.
        for pattern in threshold_patterns:
            if pattern.search(text):
                errors.append(
                    _error(
                        "invented-performance-threshold",
                        line.source.number,
                        "Do not invent a numeric performance threshold or budget in the planning checklist.",
                    )
                )
                # A numeric budget also contradicts the explicit no-threshold
                # record, even when the mutation leaves that field untouched.
                errors.append(
                    _error(
                        "threshold-statement",
                        line.source.number,
                        "The benchmark section must state exactly `No threshold is claimed.` and contain no numeric budget.",
                    )
                )
                break

        # Match executable command/import/call shapes, not prose literals.  The
        # module names are assembled from fragments so this validator remains a
        # dependency-free source audit rather than containing live-client names.
        network_modules = "(?:" + "request" + "s" + "|" + "url" + "lib" + "|" + "sock" + "et" + ")"
        network_pattern = re.compile(
            r"(?:\b(?:curl|wget|gh\s+api|ssh|nc)\b\s+\S+|"
            r"\b(?:import|from)\s+" + network_modules + r"\b|"
            r"\b" + network_modules + r"\s*\.\s*(?:get|post|request|open|create_connection)\b)",
            re.I,
        )
        if network_pattern.search(text):
            errors.append(
                _error(
                    "network-command",
                    line.source.number,
                    "The checklist and validator must use local, no-network evidence only.",
                )
            )

        na_suffix: Optional[str] = None
        field_match = _BULLET_FIELD_RE.fullmatch(text)
        if field_match:
            value = field_match.group(2)
            na_match = re.match(r"N/A\b", value, re.I)
            if na_match:
                na_suffix = value[na_match.end() :]
        else:
            cells = _split_table_row(text)
            if cells is not None:
                for cell in cells[1:]:
                    na_match = re.match(r"N/A\b", cell, re.I)
                    if na_match:
                        na_suffix = cell[na_match.end() :]
                        break
        if na_suffix is not None and not re.match(
            r"\s*(?:—|:|reason\b)\s*\S", na_suffix, re.I
        ):
            errors.append(
                _error(
                    "na-rationale",
                    line.source.number,
                    "Every N/A value must include an inline rationale.",
                )
            )
    return errors


def _validate_fence_and_key_decoys(scanned: Sequence[MarkdownLine]) -> List[ValidationError]:
    """Reject visible bare gate/evidence tokens that could bypass table checks."""

    errors: List[ValidationError] = []
    for line in _visible(scanned):
        if line.text.startswith("|"):
            continue
        if _BARE_GATE_RE.search(line.text) and "`G-" not in line.text and not line.text.startswith("#"):
            # Prose can name a gate in a sentence; only reject a row-looking
            # token, while table validation remains the authoritative check.
            if re.match(r"^\s*(?:[-*]|[A-Z])", line.text) and "gate" not in line.text.casefold():
                errors.append(_error("gate-key-context", line.source.number, "Gate keys must appear in the canonical gate table."))
        if _BARE_EVIDENCE_RE.search(line.text) and not line.text.startswith("#") and "evidence" not in line.text.casefold():
            errors.append(_error("evidence-key-context", line.source.number, "Evidence keys must appear in the canonical evidence table or gate row."))
    return errors


def _invalid_utf8_error(data: bytes, exc: UnicodeDecodeError) -> ValidationError:
    line = data[: exc.start].count(b"\n") + 1
    # A malformed byte inserted immediately before a line ending belongs to the
    # rejected boundary, so report the following logical line consistently.
    if data[exc.start + 1 : exc.start + 2] in {b"\n", b"\r"}:
        line += 1
    return _error(
        "invalid-utf8",
        line,
        f"Checklist bytes are not valid UTF-8 at byte offset {exc.start}.",
    )


def _result(path: Optional[Union[str, Path]], errors: Iterable[ValidationError]) -> Dict[str, object]:
    ordered = sorted(errors, key=lambda item: (item.line is None, item.line if item.line is not None else 0, item.code, item.message))
    if path is None:
        path_value: Optional[str] = None
    elif isinstance(path, (str, Path)) and not isinstance(path, bool):
        path_value = str(path)
    else:
        path_value = None
    return {"ok": not ordered, "path": path_value, "errors": [item.as_dict() for item in ordered]}


def validate_bytes(data: bytes, path: Union[str, Path] = DEFAULT_CHECKLIST_PATH) -> Dict[str, object]:
    """Validate one UTF-8 checklist byte string and return JSON data."""

    if isinstance(data, bool) or not isinstance(data, (bytes, bytearray)):
        return _result(path if isinstance(path, (str, Path)) and not isinstance(path, bool) else None, [_error("input-type", None, "Checklist input must be bytes or bytearray, not a boolean or another type.")])
    raw = bytes(data)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return _result(path, [_invalid_utf8_error(raw, exc)])
    return validate_text(text, path=path)


def validate_text(text: str, path: Union[str, Path] = DEFAULT_CHECKLIST_PATH) -> Dict[str, object]:
    """Validate already-decoded checklist text."""

    if isinstance(text, bool) or not isinstance(text, str):
        return _result(path if isinstance(path, (str, Path)) and not isinstance(path, bool) else None, [_error("input-type", None, "Checklist input must be text, not a boolean or another type.")])
    try:
        lines, endings, final_newline = _split_lines(text)
    except Exception as exc:  # defensive library boundary
        return _result(path, [_error("input-type", None, f"Could not split checklist text: {type(exc).__name__}.")])
    errors: List[ValidationError] = []
    errors.extend(_validate_line_endings(lines, endings, final_newline))
    scan = _scan_markdown(lines)
    errors.extend(scan.errors)
    errors.extend(_validate_title_and_metadata(scan.lines))
    h2, h3, heading_errors = _collect_headings(scan.lines)
    errors.extend(heading_errors)
    errors.extend(_validate_sections(h2))
    errors.extend(_validate_subsections(h2, h3, scan.lines))
    errors.extend(_validate_issue_urls(scan.lines))
    errors.extend(_validate_gate_table(h2, scan.lines))
    errors.extend(_validate_evidence_table(h2, scan.lines))
    errors.extend(_validate_section_fields(h2, scan.lines))
    errors.extend(_validate_parity_tables(h2, h3, scan.lines))
    errors.extend(_validate_checklist_dod(h2, scan.lines))
    errors.extend(_validate_semantic_rules(scan.lines))
    errors.extend(_validate_fence_and_key_decoys(scan.lines))
    return _result(path, errors)


def validate_file(path: Union[str, Path] = DEFAULT_CHECKLIST_PATH) -> Dict[str, object]:
    """Read and validate one local checklist without network access."""

    if isinstance(path, bool) or not isinstance(path, (str, Path)):
        return _result(None, [_error("input-type", None, "Checklist path must be a string or pathlib.Path, not a boolean or another type.")])
    checklist_path = Path(path)
    try:
        data = checklist_path.read_bytes()
    except OSError as exc:
        return _result(path, [_error("read-error", 1, f"Could not read checklist `{checklist_path}`: {exc}")])
    return validate_bytes(data, path=path)


def validate(path: Union[str, Path] = DEFAULT_CHECKLIST_PATH) -> Dict[str, object]:
    """Compatibility alias for callers that prefer a short validator name."""

    return validate_file(path)


class _JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise _CliArgumentError(message)


def _parser() -> argparse.ArgumentParser:
    parser = _JsonArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", default=str(DEFAULT_CHECKLIST_PATH), help=f"checklist path (default: {DEFAULT_CHECKLIST_PATH})")
    return parser


def _write_result(result: Dict[str, object]) -> None:
    json.dump(result, sys.stdout, ensure_ascii=False, sort_keys=True)
    sys.stdout.write("\n")


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        if argv is not None and (isinstance(argv, (str, bytes, bytearray, bool)) or not isinstance(argv, Sequence)):
            raise _CliArgumentError("argv must be a sequence of command-line strings")
        args = _parser().parse_args(argv)
        result = validate_file(args.path)
        _write_result(result)
        return 0 if result.get("ok") is True else 1
    except _CliArgumentError as exc:
        _write_result(_result(None, [_error("cli-arguments", None, f"Invalid command-line arguments: {exc}")]))
        return 2
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        _write_result(_result(None, [_error("cli-failure", None, f"Validator failed without a traceback: {type(exc).__name__}: {exc}")]))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
