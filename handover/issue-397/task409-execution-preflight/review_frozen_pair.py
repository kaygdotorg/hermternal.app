#!/usr/bin/env python3
"""Read-only exact-hash review helper for the frozen Task #409 pair.

This helper must be run only after the sole writer declares both artifacts
frozen. It opens the pair with O_RDONLY|O_NOFOLLOW, detects descriptor
mutation, and writes no repository, artifact, or temporary files. It never
executes the embedded shell driver, Git, replay, or live operations.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Iterable

STALE_DRIVER = "/private/tmp/hermternal-task409-approved-driver.sh"
OLD_BINDING_SHA = "0be7d21cfcb06cbf4ee65509dae974290eca70fa849530643f69f89c3119e97e"
OLD_MATRIX_PATHS = (
    "/tmp/hermternal-task409-final-execution-matrix.md",
    "/tmp/hermternal-task409-final-execution-matrix.json",
)
EXPECTED_IDENTITY_DECLARATION_COUNT = 2

SECTION = b"## Canonical machine-readable ordered execution driver\n"
BASH_OPEN = b"```bash\n"
JSON_OPEN = b"```json\n"
FENCE_CLOSE = b"```"

EXPECTED_ARGV = [
    "/usr/bin/env",
    "-i",
    "PATH=/usr/bin:/bin",
    "HOME=/dev/null",
    "LANG=C",
    "LC_ALL=C",
    "GIT_CONFIG_NOSYSTEM=1",
    "GIT_CONFIG_GLOBAL=/dev/null",
    "GIT_CONFIG_SYSTEM=/dev/null",
    "GIT_TERMINAL_PROMPT=0",
    "GIT_OPTIONAL_LOCKS=0",
    "GIT_NO_REPLACE_OBJECTS=1",
    "/bin/bash",
    "-euo",
    "pipefail",
    "-s",
]
EXPECTED_ENV_ALLOWLIST = [
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_TERMINAL_PROMPT",
    "GIT_OPTIONAL_LOCKS",
    "GIT_NO_REPLACE_OBJECTS",
    "PWD",
    "GIT_NO_LAZY_FETCH",
    "SHLVL",
    "_",
]
EXPECTED_ENV_REJECT_PATTERNS = [
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_KEY_*",
    "GIT_CONFIG_VALUE_*",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "PYTHONUSERBASE",
    "PYTHONINSPECT",
    "PYTHONWARNINGS",
    "BASH_ENV",
    "ENV",
    "CDPATH",
    "NODE_OPTIONS",
    "RUBYOPT",
    "PERL5OPT",
    "DYLD_*",
    "LD_*",
]
EXPECTED_GIT_ENV = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_NO_LAZY_FETCH": "1",
}


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def require_equal(left: Any, right: Any, label: str) -> None:
    if left != right:
        fail(f"{label} differs")


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        stat.S_IMODE(value.st_mode),
        value.st_size,
        value.st_nlink,
    )


def _parent_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_uid, stat.S_IMODE(value.st_mode), value.st_nlink)


def read_stable(path: Path) -> tuple[bytes, os.stat_result]:
    """Read exact bytes through held no-follow parent/child descriptors.

    The final directory-entry checks close the pathname substitution window that
    a pathname-only ``O_NOFOLLOW`` read would leave open. This remains read-only
    and does not execute or import either artifact's embedded driver.
    """
    path = Path(path)
    path_text = os.fspath(path)
    require(path.is_absolute(), f"{path} is not absolute")
    require(os.path.realpath(path_text) == path_text, f"{path} is not canonical")
    parent = path.parent
    require(os.path.realpath(os.fspath(parent)) == os.fspath(parent), f"{parent} is not canonical")
    try:
        parent_fd = os.open(
            os.fspath(parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
    except OSError as exc:
        fail(f"cannot open parent of {path} read-only without following symlinks: {exc}")
    fd: int | None = None
    try:
        parent_first = os.fstat(parent_fd)
        require(stat.S_ISDIR(parent_first.st_mode), f"{parent} is not a directory")
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        except OSError as exc:
            fail(f"cannot open {path} relative to its held parent: {exc}")
        child_first = os.fstat(fd)
        require(stat.S_ISREG(child_first.st_mode), f"{path} is not a regular file")
        require(child_first.st_nlink == 1, f"{path} must have exactly one hard link")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        child_second = os.fstat(fd)
        child_final = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        parent_second = os.fstat(parent_fd)
        parent_final = os.stat(parent, follow_symlinks=False)
    except OSError as exc:
        fail(f"stable read failed for {path}: {exc}")
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent_fd)

    require(_parent_identity(parent_first) == _parent_identity(parent_second), f"{path} parent changed while being read")
    require(_parent_identity(parent_first) == _parent_identity(parent_final), f"{path} parent pathname was substituted")
    require(_file_identity(child_first) == _file_identity(child_second), f"{path} changed while being read")
    require(_file_identity(child_first) == _file_identity(child_final), f"{path} final directory entry was substituted")
    require(stat.S_ISREG(child_final.st_mode), f"{path} final entry is not a regular file")
    require(child_final.st_nlink == 1, f"{path} final entry must have exactly one hard link")
    require(os.path.realpath(path_text) == path_text, f"{path} became non-canonical while being read")
    raw = b"".join(chunks)
    require(len(raw) == child_first.st_size, f"{path} byte count disagrees with fstat")
    return raw, child_first


def read_pair_stable(markdown: Path, json_path: Path) -> tuple[bytes, bytes]:
    """Read both exact files twice so a writer change fails closed."""
    md_one, md_stat_one = read_stable(markdown)
    js_one, js_stat_one = read_stable(json_path)
    md_two, md_stat_two = read_stable(markdown)
    js_two, js_stat_two = read_stable(json_path)
    require(md_one == md_two, "Markdown bytes changed during pair review")
    require(js_one == js_two, "JSON bytes changed during pair review")
    for label, first, second in (
        ("Markdown", md_stat_one, md_stat_two),
        ("JSON", js_stat_one, js_stat_two),
    ):
        require(_file_identity(first) == _file_identity(second), f"{label} identity changed during pair review")
    return md_one, js_one


def parse_json(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception as exc:
        fail(f"JSON parse failed: {exc}")


def get(document: Any, *path: str) -> Any:
    value = document
    for key in path:
        require(isinstance(value, dict) and key in value, f"missing JSON path /{'/'.join(path)}")
        value = value[key]
    return value


def extract_fenced(raw: bytes, heading: bytes, opening: bytes) -> bytes:
    heading_at = raw.find(heading)
    require(heading_at >= 0, f"missing exact heading {heading!r}")
    opening_at = raw.find(opening, heading_at + len(heading))
    require(opening_at >= 0, f"missing exact opening fence {opening!r}")
    body_start = opening_at + len(opening)
    closing_at = raw.find(FENCE_CLOSE, body_start)
    require(closing_at >= 0, "missing exact closing fence")
    return raw[body_start:closing_at]


def normalized_json_sha256(raw: bytes, expected: str) -> str:
    """Mirror the driver's byte-preserving normalization, not JSON reserialization."""
    require(re.fullmatch(r"[0-9a-f]{64}", expected) is not None, "invalid normalized SHA-256 token")
    normalized = raw.replace(expected.encode("ascii"), b"0" * 64)
    for key in (
        b'"shell_sha256": "',
        b'"driver_shell_sha256": "',
        b'"expected_body_sha256": "',
    ):
        normalized = re.sub(
            re.escape(key) + rb"[0-9a-f]{64}(?=\")",
            lambda match: match.group(0)[: len(key)] + b"0" * 64,
            normalized,
        )
    return hashlib.sha256(normalized).hexdigest()


def json_pointer(parts: Iterable[str]) -> str:
    escaped = [part.replace("~", "~0").replace("/", "~1") for part in parts]
    return "/" + "/".join(escaped)


def collect_appendix_mirrors(
    value: Any,
    parts: tuple[str, ...] = (),
    historical: list[dict[str, Any]] | None = None,
    targets: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if historical is None:
        historical = []
    if targets is None:
        targets = []
    if isinstance(value, dict):
        pointer = json_pointer(parts)
        if "changed_paths" in value:
            historical.append(
                {"changed_paths": value["changed_paths"], "json_pointer": pointer}
            )
        if "target_states" in value:
            targets.append(
                {
                    "changed_paths": value.get("changed_paths", []),
                    "json_pointer": pointer,
                    "target_states": value["target_states"],
                }
            )
        for key, child in value.items():
            collect_appendix_mirrors(child, parts + (key,), historical, targets)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            collect_appendix_mirrors(child, parts + (str(index),), historical, targets)
    return historical, targets


def require_markdown_literal(raw: bytes, literal: str, label: str) -> None:
    require(literal.encode("utf-8") in raw, f"Markdown is missing {label}: {literal}")


def markdown_identity_declarations(raw: bytes) -> list[tuple[str, str, int]]:
    """Parse every load-bearing normalized-identity declaration in Markdown.

    The two declaration forms intentionally have different prose labels. A
    reviewer that searches only for the fresh-extraction phrase can miss a
    stale ``Matrix identity:`` token, so both forms are enumerated and counted.
    """
    declarations: list[tuple[str, str, int]] = []
    for line_number, line in enumerate(raw.splitlines(), 1):
        if b"normalized JSON identity" in line:
            match = re.search(rb"normalized JSON identity `([0-9a-f]{64})`", line)
            require(match is not None, f"malformed normalized JSON identity declaration on line {line_number}")
            declarations.append(("fresh extraction", match.group(1).decode("ascii"), line_number))
        if b"Matrix identity:" in line:
            match = re.search(rb"Matrix identity:.*?normalized SHA-256 `([0-9a-f]{64})`", line)
            require(match is not None, f"malformed Matrix identity declaration on line {line_number}")
            declarations.append(("matrix", match.group(1).decode("ascii"), line_number))
    require(
        len(declarations) == EXPECTED_IDENTITY_DECLARATION_COUNT,
        f"Markdown normalized-identity declaration cardinality is {len(declarations)}, expected {EXPECTED_IDENTITY_DECLARATION_COUNT}",
    )
    require(
        sum(kind == "fresh extraction" for kind, _token, _line in declarations) == 1,
        "Markdown must contain exactly one fresh-extraction normalized identity declaration",
    )
    require(
        sum(kind == "matrix" for kind, _token, _line in declarations) == 1,
        "Markdown must contain exactly one Matrix identity declaration",
    )
    return declarations


def check_markdown_metadata(md_raw: bytes, doc: dict[str, Any], shell_sha: str, normalized_sha: str) -> None:
    """Cross-check human-readable metadata and every identity declaration."""
    vc = get(doc, "validation_contract")
    ed = get(doc, "execution_driver")
    declarations = markdown_identity_declarations(md_raw)
    for kind, token, line_number in declarations:
        require(token == normalized_sha, f"Markdown {kind} identity on line {line_number} differs from raw JSON identity")
    require_markdown_literal(md_raw, f"Driver schema: `{vc['driver_schema']}`", "driver schema")
    require_markdown_literal(md_raw, f"Driver shell SHA-256: `{shell_sha}`", "driver shell SHA")
    require_markdown_literal(md_raw, f"normalized JSON identity `{normalized_sha}`", "normalized JSON identity")
    shell_size = ed["shell_size_metadata"]
    require_markdown_literal(md_raw, f"Shell body bytes | `{shell_size['body_bytes']}`", "shell byte count")
    require_markdown_literal(md_raw, f"Shell body lines | `{shell_size['body_lines']}`", "shell line count")
    require_markdown_literal(
        md_raw,
        f"body and JSON shell are `{shell_size['body_bytes']}` bytes, SHA-256 `{shell_sha}`, terminal byte `{shell_size['terminal_byte_hex']}`",
        "combined shell hash/size/terminal metadata",
    )
    require_markdown_literal(md_raw, f"Target-state mirror entries | `{vc['markdown_parity_appendix']['target_state_entry_count']}`", "target-state entry count")
    require_markdown_literal(md_raw, f"Target-state mirror paths | `{vc['markdown_parity_appendix']['target_state_path_count']}`", "target-state path count")
    require_markdown_literal(md_raw, f"Historical changed-path mirror entries | `{vc['markdown_parity_appendix']['historical_changed_path_entry_count']}`", "historical entry count")
    require_markdown_literal(md_raw, f"Historical changed-path mirror paths | `{vc['markdown_parity_appendix']['historical_changed_path_count']}`", "historical path count")

    invocation_json = json.dumps(ed["argv"], separators=(",", ":"))
    require_markdown_literal(md_raw, f"Invocation argv: {invocation_json}", "invocation argv")
    future_invocation = " ".join(ed["argv"])
    require_markdown_literal(md_raw, f"Future-only invocation: {future_invocation}", "future-only invocation")


def check_matrix_identity(doc: dict[str, Any], json_path: Path) -> None:
    """Validate both matrix-identity copies and their stable-read contract."""
    vc = get(doc, "validation_contract")
    ed = get(doc, "execution_driver")
    matrix_vc = get(vc, "matrix_identity")
    matrix_ed = get(ed, "matrix_identity")
    require_equal(matrix_vc, matrix_ed, "duplicated matrix identity contract")
    require(matrix_vc["source_path"] == str(json_path), "matrix identity source_path differs from supplied JSON path")
    algorithm = matrix_vc.get("algorithm")
    require(isinstance(algorithm, str), "matrix identity normalization algorithm is missing")
    for phrase in (
        "SHA-256 of exact JSON bytes",
        "expected_normalized_sha256 token",
        "shell_sha256",
        "driver_shell_sha256",
        "expected_body_sha256",
        "no whitespace",
        "no JSON reserialization",
    ):
        require(phrase in algorithm, f"matrix identity algorithm omits {phrase}")
    require_equal(matrix_vc.get("source_open_flags"), ["O_RDONLY", "O_NOFOLLOW"], "matrix source open flags")
    require_equal(
        matrix_vc.get("snapshot_open_flags"),
        ["O_WRONLY", "O_CREAT", "O_EXCL", "O_NOFOLLOW"],
        "matrix snapshot open flags",
    )
    snapshot_fields = matrix_vc.get("snapshot_identity_fields")
    require(isinstance(snapshot_fields, list), "matrix snapshot identity fields are missing")
    for field in ("st_dev", "st_ino", "st_size", "realpath"):
        require(field in snapshot_fields, f"matrix snapshot identity fields omit {field}")
    require_equal(matrix_vc.get("snapshot_mode"), "0600", "matrix snapshot mode")
    require_equal(matrix_vc.get("snapshot_path_template"), "$REPLAY_ROOT/matrix.snapshot.json", "matrix snapshot path template")
    boundary = matrix_vc.get("boundary_rule")
    require(isinstance(boundary, str), "matrix identity boundary rule is missing")
    for phrase in ("every mutation boundary", "O_NOFOLLOW", "device", "inode", "size", "canonical path", "exact bytes", "normalized SHA-256"):
        require(phrase in boundary, f"matrix identity boundary rule omits {phrase}")


def check_environment_and_invocation(doc: dict[str, Any], shell: bytes) -> None:
    vc = get(doc, "validation_contract")
    ed = get(doc, "execution_driver")
    argv = get(ed, "argv")
    require_equal(argv, EXPECTED_ARGV, "exact execution_driver.argv")
    if "invocation_argv" in vc:
        require_equal(get(vc, "invocation_argv"), argv, "duplicated invocation argv")

    require_equal(get(vc, "strict_environment_allowlist"), EXPECTED_ENV_ALLOWLIST, "validation environment allowlist")
    require_equal(get(ed, "strict_git_environment", "allowlist"), EXPECTED_ENV_ALLOWLIST, "driver environment allowlist")
    require_equal(get(vc, "forbidden_inherited_environment_patterns"), EXPECTED_ENV_REJECT_PATTERNS, "validation rejected environment patterns")
    require_equal(get(ed, "strict_git_environment", "reject_inherited_patterns"), EXPECTED_ENV_REJECT_PATTERNS, "driver rejected environment patterns")
    require_equal(get(ed, "strict_git_environment", "set"), EXPECTED_GIT_ENV, "driver Git environment set")

    shell_text = shell.decode("utf-8")
    require("assert_environment()" in shell_text, "driver has no inherited-environment assertion")
    require("exec \"$ENV\" -i" not in shell_text, "driver body must not self-invoke a second driver")
    require("GIT_NO_LAZY_FETCH=1" in shell_text, "driver body omits GIT_NO_LAZY_FETCH=1")
    require("--no-lazy-fetch" in shell_text, "driver body omits --no-lazy-fetch")
    for field in EXPECTED_ENV_ALLOWLIST:
        require(field in shell_text, f"driver body omits allowlisted environment field {field}")
    for pattern in EXPECTED_ENV_REJECT_PATTERNS:
        require(pattern.rstrip("*") in shell_text, f"driver body omits rejected environment pattern {pattern}")


def check_clean_primary_metadata(doc: dict[str, Any], md_raw: bytes) -> None:
    vc = get(doc, "validation_contract")
    ed = get(doc, "execution_driver")
    require_equal(
        get(vc, "clean_primary_storage_identity"),
        get(ed, "clean_primary_storage_identity"),
        "duplicated clean-primary storage identity",
    )
    require_equal(
        get(vc, "replay_root_identity"),
        get(ed, "replay_root_identity"),
        "duplicated replay-root identity",
    )
    require_equal(
        get(vc, "fresh_shell_requirement"),
        get(ed, "fresh_shell_requirement"),
        "duplicated fresh-shell requirement",
    )
    require_equal(
        get(vc, "matrix_identity", "expected_normalized_sha256"),
        get(ed, "matrix_identity", "expected_normalized_sha256"),
        "duplicated normalized JSON identity",
    )
    require_equal(
        get(vc, "clean_primary_root_template"),
        get(ed, "clean_primary_root_template"),
        "duplicated clean-primary root template",
    )
    require_equal(
        get(vc, "clean_primary_repository_template"),
        get(ed, "clean_primary_repository_template"),
        "duplicated clean-primary repository template",
    )
    require(
        get(ed, "clean_primary_root_template_normalized") == get(ed, "clean_primary_root_template"),
        "normalized clean-primary root template differs",
    )

    storage = get(vc, "clean_primary_storage_identity")
    require(storage["required_st_nlink"] == 1, "clean-primary copied object files are not pinned to st_nlink == 1")
    require(storage["no_objects_info_alternates"] is True, "clean-primary alternates are not forbidden")
    status = get(vc, "clean_primary_whole_worktree_status")
    require(status["required_status"] == "empty", "clean-primary status is not required empty")
    require(
        "--untracked-files=all --ignored=traditional" in status["status_command"],
        "clean-primary status omits exact ignored/untracked policy",
    )
    require("git diff --no-ext-diff --quiet" in status["unstaged_diff_command"], "unstaged clean-primary diff gate changed")
    require("git diff --cached --no-ext-diff --quiet" in status["staged_diff_command"], "staged clean-primary diff gate changed")
    for field in (
        "canonical path",
        "owner",
        "mode",
        "st_dev",
        "st_ino",
        "Git common directory",
        "object-store directory",
    ):
        require(field in get(vc, "source_identity_fields"), f"source identity omits {field}")
    for field in (
        "canonical path",
        "owner",
        "mode",
        "st_dev",
        "st_ino",
        "Git common directory",
        "object-store directory",
        "no objects/info/alternates",
        "object store distinct from SOURCE",
        "common directory distinct from SOURCE",
        "regular object/pack/index/info files st_nlink == 1",
        "no shared hardlinked copied object files",
    ):
        require(field in get(vc, "clean_primary_identity_fields"), f"clean-primary identity omits {field}")
    require("never find ." in md_raw.decode("utf-8"), "Markdown does not prohibit broad cleanup")
    require("/bin/rm -rf -- \"$CLEAN_PRIMARY_ROOT\"" in md_raw.decode("utf-8"), "Markdown omits explicit clean-primary cleanup command")


def check_appendix(md_raw: bytes, doc: dict[str, Any]) -> None:
    vc = get(doc, "validation_contract")
    appendix_meta = get(vc, "markdown_parity_appendix")
    appendix_raw = extract_fenced(md_raw, b"## Machine-readable parity appendix\n", JSON_OPEN)
    try:
        appendix = json.loads(appendix_raw.decode("utf-8"))
    except Exception as exc:
        fail(f"Markdown parity appendix JSON parse failed: {exc}")
    require(set(appendix) == {"historical_changed_paths", "target_states"}, "parity appendix keys differ")
    expected_historical, expected_targets = collect_appendix_mirrors(doc)
    require_equal(appendix["historical_changed_paths"], expected_historical, "historical changed-path appendix")
    require_equal(appendix["target_states"], expected_targets, "target-state appendix")
    require(len(expected_targets) == appendix_meta["target_state_entry_count"], "target-state appendix entry count mismatch")
    require(
        sum(len(item["target_states"]) for item in expected_targets) == appendix_meta["target_state_path_count"],
        "target-state appendix path count mismatch",
    )
    require(len(expected_historical) == appendix_meta["historical_changed_path_entry_count"], "historical appendix entry count mismatch")
    require(
        sum(len(item["changed_paths"]) for item in expected_historical) == appendix_meta["historical_changed_path_count"],
        "historical appendix path count mismatch",
    )


def check_duplicated_shell_metadata(doc: dict[str, Any], shell: bytes, shell_sha: str) -> None:
    """Require every JSON and validation copy to describe the exact shell bytes."""
    ed = get(doc, "execution_driver")
    vc = get(doc, "validation_contract")
    body_bytes = len(shell)
    body_lines = shell.count(b"\n")
    terminal = shell[-1:].hex()
    expected_size = {"body_bytes": body_bytes, "body_lines": body_lines, "terminal_byte_hex": terminal}
    require_equal(ed.get("shell_size_metadata"), expected_size, "execution shell size metadata")
    require_equal(vc.get("shell_size_metadata"), expected_size, "validation shell size metadata")
    require_equal(ed.get("markdown_fence_extraction"), vc.get("markdown_fence_extraction"), "duplicated Markdown fence metadata")
    fence = get(ed, "markdown_fence_extraction")
    require_equal(fence.get("section_heading"), SECTION.decode("utf-8"), "fence section heading")
    require_equal(fence.get("opening_fence"), BASH_OPEN.decode("utf-8"), "fence opening delimiter")
    require_equal(fence.get("closing_fence"), FENCE_CLOSE.decode("utf-8"), "fence closing delimiter")
    require(fence.get("body_rule") == "exact bytes strictly between the first exact opening and first exact closing delimiter", "fence body rule differs")
    require_equal(fence.get("expected_body_bytes"), body_bytes, "fence byte count")
    require_equal(fence.get("expected_body_lines"), body_lines, "fence line count")
    require_equal(fence.get("expected_terminal_byte_hex"), terminal, "fence terminal byte")
    require_equal(fence.get("expected_body_sha256"), shell_sha, "fence shell SHA-256")
    require_equal(vc.get("driver_shell_sha256"), shell_sha, "validation shell SHA-256")
    require_equal(vc.get("driver_shell_body_bytes"), body_bytes, "validation shell byte duplicate")
    require_equal(vc.get("driver_shell_body_lines"), body_lines, "validation shell line duplicate")


def check_stale_references(md_raw: bytes, js_raw: bytes, doc: dict[str, Any], shell: bytes, markdown: Path, json_path: Path) -> None:
    md_text = md_raw.decode("utf-8")
    js_text = js_raw.decode("utf-8")
    shell_text = shell.decode("utf-8")
    ed = get(doc, "execution_driver")
    vc = get(doc, "validation_contract")

    require(get(ed, "source_of_truth") == "/execution_driver/shell", "execution source_of_truth is stale or non-canonical")
    require(get(ed, "matrix_path") == str(json_path), "execution matrix_path differs from supplied JSON path")
    require(STALE_DRIVER not in shell_text, "stale standalone driver appears in executable shell body")
    require(OLD_BINDING_SHA not in shell_text, "old matrix binding hash appears in executable shell body")
    for stale_path in OLD_MATRIX_PATHS:
        require(stale_path not in shell_text, f"superseded matrix path appears in executable shell body: {stale_path}")
        require(stale_path not in js_text, f"superseded matrix path appears in JSON metadata: {stale_path}")
    require(get(doc, "artifact_paths", "markdown") == str(markdown), "Markdown artifact path differs from supplied Markdown path")
    require(get(doc, "artifact_paths", "json") == str(json_path), "JSON artifact path differs from supplied JSON path")

    stale_entries = get(vc, "non_authoritative_standalone_scripts")
    require(any(item.get("path") == STALE_DRIVER for item in stale_entries), "stale standalone driver is not recorded")
    for item in stale_entries:
        if item.get("path") == STALE_DRIVER:
            status = str(item.get("status", "")).lower()
            action = str(item.get("required_action", "")).lower()
            require("stale" in status and "non-authoritative" in status, "stale driver status is not explicit")
            require("do not execute" in status, "stale driver status does not forbid execution")
            require("fresh extraction" in action, "stale driver action does not require fresh extraction")

    # The stale path may be documented only as stale/non-authoritative. Any
    # occurrence in the pair must have a nearby explicit non-execution context.
    combined = (md_text + "\n" + js_text).lower()
    if STALE_DRIVER.lower() in combined:
        contexts = re.findall(r".{0,180}" + re.escape(STALE_DRIVER.lower()) + r".{0,240}", combined, flags=re.DOTALL)
        for context in contexts:
            require(
                any(token in context for token in ("stale", "non-authoritative", "do not execute", "never reuse", "ignore")),
                "stale standalone path occurs without an explicit non-execution context",
            )

    # Reject active-source phrases that indicate the previous standalone script
    # or an old binding is still authoritative. Historical/rejection IDs remain
    # allowed because they are explicitly represented under rejection objects.
    for phrase in (
        '"source_of_truth": "/private/tmp/hermternal-task409-approved-driver.sh"',
        "execute /private/tmp/hermternal-task409-approved-driver.sh",
        "reuse /private/tmp/hermternal-task409-approved-driver.sh",
        "MATRIX_EXPECTED_BINDING_SHA256='" + OLD_BINDING_SHA + "'",
    ):
        require(phrase not in md_text and phrase not in js_text, f"stale active reference found: {phrase}")


def parse_args(argv: list[str]) -> tuple[Path, Path]:
    parser = argparse.ArgumentParser(
        description="Read-only structural parity review; never executes embedded shell"
    )
    parser.add_argument("markdown", type=Path, help="absolute Markdown artifact path")
    parser.add_argument("json_path", type=Path, help="absolute JSON artifact path")
    args = parser.parse_args(argv)
    require(args.markdown.is_absolute(), "Markdown argument must be absolute")
    require(args.json_path.is_absolute(), "JSON argument must be absolute")
    require(args.markdown != args.json_path, "Markdown and JSON paths must differ")
    return args.markdown, args.json_path


def main(argv: list[str] | None = None) -> int:
    markdown, json_path = parse_args(sys.argv[1:] if argv is None else argv)
    md_raw, js_raw = read_pair_stable(markdown, json_path)
    document = parse_json(js_raw)
    require(isinstance(document, dict), "JSON root is not an object")

    require(get(document, "artifact_paths", "markdown") == str(markdown), "Markdown artifact path mismatch")
    require(get(document, "artifact_paths", "json") == str(json_path), "JSON artifact path mismatch")
    require(get(document, "authority", "no_repository_files_changed") is True, "repository-change boundary is not true")
    require(get(document, "execution_driver", "immutable") is True, "execution driver is not immutable")

    shell = extract_fenced(md_raw, SECTION, BASH_OPEN)
    json_shell = get(document, "execution_driver", "shell")
    require(isinstance(json_shell, str), "execution_driver.shell is not a string")
    json_shell_bytes = json_shell.encode("utf-8")
    shell_sha = hashlib.sha256(shell).hexdigest()
    json_shell_sha = hashlib.sha256(json_shell_bytes).hexdigest()
    require_equal(shell_sha, get(document, "execution_driver", "shell_sha256"), "Markdown-fenced shell SHA-256")
    require_equal(json_shell_sha, get(document, "execution_driver", "shell_sha256"), "JSON shell SHA-256")
    # Current writer state may still be settling. A frozen review must require
    # this exact equality; do not normalize, trim, or approve a mismatch.
    require_equal(shell, json_shell_bytes, "Markdown fenced shell bytes vs JSON shell bytes")
    require(shell.endswith(b"\n"), "driver shell does not terminate with LF")
    require_equal(shell_sha, get(document, "execution_driver", "shell_sha256"), "driver shell SHA-256")
    require_equal(shell_sha, get(document, "validation_contract", "driver_shell_sha256"), "duplicated driver shell SHA-256")

    check_duplicated_shell_metadata(document, shell, shell_sha)

    matrix_vc = get(document, "validation_contract", "matrix_identity")
    normalized_expected = matrix_vc["expected_normalized_sha256"]
    require(normalized_json_sha256(js_raw, normalized_expected) == normalized_expected, "normalized JSON SHA-256")
    check_matrix_identity(document, json_path)

    check_environment_and_invocation(document, shell)
    check_clean_primary_metadata(document, md_raw)
    check_appendix(md_raw, document)
    check_markdown_metadata(md_raw, document, shell_sha, normalized_expected)
    check_stale_references(md_raw, js_raw, document, shell, markdown, json_path)

    print("PASS: frozen-pair read-only parity review checks passed")
    print(f"shell_bytes={len(shell)} shell_sha256={shell_sha}")
    print(f"normalized_json_sha256={normalized_expected}")
    print("approval=not claimed; this helper only reports structural consistency")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
