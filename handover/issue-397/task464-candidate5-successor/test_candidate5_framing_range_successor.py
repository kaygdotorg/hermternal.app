#!/usr/bin/env python3
"""Regression tests for the candidate-five successor range checkpoint."""

import ast
import copy
import importlib.util
import json
import re
from pathlib import Path


BASE = Path(__file__).resolve().parents[1]
SUCCESSOR = Path(__file__).with_name("candidate5_framing_range_successor.py")
INPUT_JSON = BASE / "task464-inputs" / "task464-working-input.json"
INPUT_SHELL = BASE / "task464-inputs" / "task464-source-shell-current.txt"
HEREDOC_MARKER = "<<'PY'\n"
EXPECTED_DURABLE_RANGES = {
    "renderer-lifecycle.range",
    "static-manifest-chain.range",
    "authentication-design-token-manifest.range",
    "fixture-registry-authority.range",
    "apple-benchmark-range.range",
    "proxy-deployment-proof.range",
    "launcher-semantic-projection.source_ancestry_audit",
    "live-proof-semantic-projection.source_ancestry_audit",
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def rejects(callable_, value, message):
    try:
        callable_(value)
    except (ValueError, SystemExit):
        return
    raise AssertionError(message)


def load_successor():
    spec = importlib.util.spec_from_file_location("candidate5_range_successor", SUCCESSOR)
    require(
        spec is not None and spec.loader is not None,
        "successor loader is unavailable",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def mutate(record, key, value):
    changed = copy.deepcopy(record)
    changed[key] = value
    return changed


def emitted_heredocs(shell):
    """Return each exact Python heredoc body from the generated shell."""
    bodies = []
    position = 0
    while True:
        start = shell.find(HEREDOC_MARKER, position)
        if start < 0:
            return bodies
        body_start = start + len(HEREDOC_MARKER)
        end = shell.find("\nPY", body_start)
        require(end >= 0, "generated shell has an unterminated Python heredoc")
        bodies.append(shell[body_start:end])
        position = end + len("\nPY")


def test_all_durable_ranges(successor, frozen):
    document = json.loads(INPUT_JSON.read_bytes().decode("utf-8"))
    document = frozen.expand_exact_git_references(document)
    records = []
    for lane in document["ordered_lanes"]:
        for key in ("range", "source_ancestry_audit"):
            if lane.get(key):
                records.append((f"{lane['id']}.{key}", lane[key]))
    require(
        {label for label, _record in records} == EXPECTED_DURABLE_RANGES,
        "the durable range record set changed",
    )
    for label, record in records:
        left, right, notation = successor.parse_inclusive_git_range(record, label)
        require(left == record["left"], f"{label}: left endpoint changed")
        require(right == record["right"], f"{label}: right endpoint changed")
        require(notation == f"{left}..{right}", f"{label}: notation is not bound")
    return records


def test_rejections(successor, record):
    left = record["left"]
    right = record["right"]
    other_left = ("0" if left[0] != "0" else "1") + left[1:]
    other_right = ("0" if right[0] != "0" else "1") + right[1:]
    invalid_records = (
        mutate(record, "left", other_left),
        mutate(record, "right", other_right),
        mutate(record, "notation", f"{other_left}..{right}"),
        mutate(record, "notation", f"{left}..{other_right}"),
        mutate(record, "left", left + "^"),
        mutate(record, "notation", record["notation"].replace("^..", "^^..")),
        mutate(record, "left", left.upper()),
        mutate(record, "right", right.upper()),
        mutate(record, "notation", record["notation"].upper()),
        mutate(record, "left", left[1:]),
        mutate(record, "right", right[1:]),
        mutate(record, "notation", record["notation"].replace("^..", "^...")),
        mutate(record, "left", "--not-a-ref^"),
        mutate(record, "right", "--not-a-ref"),
        mutate(record, "notation", "--not-a-ref^.." + right),
    )
    for index, invalid in enumerate(invalid_records):
        rejects(
            successor.parse_inclusive_git_range,
            invalid,
            f"accepted invalid range mutation {index}: {invalid!r}",
        )

    invalid_notations = (
        record["notation"].replace("^..", ".."),
        record["notation"].replace("^..", "^^.."),
        record["notation"].replace("^..", "^..."),
        record["notation"].upper(),
        record["notation"][1:],
        "--not-a-ref^.." + right,
    )
    for notation in invalid_notations:
        rejects(
            successor.parse_git_range,
            notation,
            f"accepted invalid inclusive notation: {notation!r}",
        )

    auth_left = left[:-1]
    auth_right = right
    require(
        successor.parse_commit_range(f"{auth_left}..{auth_right}")
        == (auth_left, auth_right),
        "the authentication range endpoints changed",
    )
    for invalid in (
        f"{auth_left.upper()}..{auth_right}",
        f"{auth_left[1:]}..{auth_right}",
        f"{auth_left}...{auth_right}",
        f"--not-a-ref..{auth_right}",
    ):
        rejects(
            successor.parse_commit_range,
            invalid,
            f"accepted invalid authentication range: {invalid!r}",
        )


def test_embedded_helpers(successor, records):
    namespace = {"re": re}
    exec(successor.STRICT_RECORD_HELPERS, namespace)
    parser = namespace["strict_inclusive_git_range"]
    for label, record in records:
        require(
            parser(record, label) == (
                record["left"],
                record["right"],
                record["notation"],
            ),
            f"{label}: embedded helper changed the bound range",
        )
    mismatch = mutate(records[0][1], "right", "0" * 40)
    rejects(parser, mismatch, "embedded helper accepted a substituted endpoint")


def test_generated_validator(successor, frozen):
    shell = frozen.patch_shell(INPUT_SHELL.read_bytes().decode("utf-8"))
    bodies = emitted_heredocs(shell)
    require(len(bodies) == 41, f"expected 41 Python heredocs, found {len(bodies)}")
    for index, body in enumerate(bodies, 1):
        tree = ast.parse(body, filename=f"<candidate5-successor-heredoc-{index}>")
        compile(tree, f"<candidate5-successor-heredoc-{index}>", "exec")
    required = (
        "strict_inclusive_git_range(",
        "range_left, range_right, notation = strict_inclusive_git_range(",
        "audit_left, audit_right, notation = strict_inclusive_git_range(",
        "patch_id(range_left, range_right, r['path_allowlist'])",
        "patch_id(audit_left, audit_right, audit['path_allowlist'])",
        "strict_git_commit_range(",
    )
    for token in required:
        require(token in shell, f"generated shell lacks validated range token: {token}")

    forbidden = (
        "out('rev-list', '--reverse', r['notation'])",
        "out('rev-list', '--merges', '--count', r['notation'])",
        "patch_id(r['left'], r['right']",
        "out('rev-list', '--reverse', audit['notation'])",
        "out('rev-list', '--merges', '--count', audit['notation'])",
        "patch_id(audit['left'], audit['right']",
        "authentication_range'].split('..')",
    )
    for token in forbidden:
        require(token not in shell, f"generated shell retains raw range use: {token}")


def main():
    successor = load_successor()
    frozen = successor.install_successor()
    records = test_all_durable_ranges(successor, frozen)
    test_rejections(successor, records[0][1])
    test_embedded_helpers(successor, records)
    test_generated_validator(successor, frozen)
    print(f"candidate-five successor range checks passed for {len(records)} durable ranges")


if __name__ == "__main__":
    main()
