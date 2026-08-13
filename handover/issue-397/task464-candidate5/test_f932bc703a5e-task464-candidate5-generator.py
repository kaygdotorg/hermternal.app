#!/usr/bin/env python3
"""Focused regression test for candidate5's emitted Python byte semantics."""

import ast
import importlib.util
from pathlib import Path
from types import SimpleNamespace


BASE = Path(__file__).resolve().parent
GENERATOR = BASE / "f932bc703a5e-task464-candidate5-generator.py"
SOURCE_MARKDOWN = Path("/private/tmp/task464-working-input.md")
HEREDOC_MARKER = "<<'PY'\n"


def load_generator():
    spec = importlib.util.spec_from_file_location("candidate5_generator", GENERATOR)
    if spec is None or spec.loader is None:
        raise AssertionError(f"could not load {GENERATOR}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def emitted_heredocs(shell):
    bodies = []
    position = 0
    while True:
        start = shell.find(HEREDOC_MARKER, position)
        if start < 0:
            return bodies
        body_start = start + len(HEREDOC_MARKER)
        end = shell.find("\nPY", body_start)
        if end < 0:
            raise AssertionError("unterminated emitted Python heredoc")
        bodies.append(shell[body_start:end])
        position = end + len("\nPY")


def join_separators(tree):
    separators = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "join" or not isinstance(node.func.value, ast.Constant):
            continue
        if isinstance(node.func.value.value, str):
            separators.append(node.func.value.value)
    return separators


def expected_alternate_value(tree):
    assignment = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "expected_alternate" for target in node.targets)
    )
    fake_os = SimpleNamespace(path=SimpleNamespace(realpath=lambda value: value))
    return eval(
        compile(ast.Expression(assignment.value), "<expected_alternate>", "eval"),
        {"os": fake_os, "clean_objects": "/clean/objects"},
    )


def main():
    generator = load_generator()
    markdown = SOURCE_MARKDOWN.read_bytes()
    source_shell = generator.extract_fenced(
        markdown,
        "## Canonical machine-readable ordered execution driver\n",
        "```bash\n",
        "focused delimiter regression source",
    ).decode("utf-8")
    emitted_shell = generator.patch_shell(source_shell)
    bodies = emitted_heredocs(emitted_shell)
    assert len(bodies) == 41, len(bodies)

    trees = []
    for index, body in enumerate(bodies, 1):
        tree = ast.parse(body, filename=f"<candidate5-heredoc-{index}>")
        compile(tree, f"<candidate5-heredoc-{index}>", "exec")
        trees.append(tree)

    separators = [separator for tree in trees for separator in join_separators(tree)]
    assert separators.count("\t") >= 5, separators
    assert separators.count("\x1f") >= 3, separators
    assert "\\t" not in separators, separators
    assert "\\x1f" not in separators, separators
    assert all(separator.encode() != bytes.fromhex("5c74") for separator in separators)
    assert all(separator.encode() != bytes.fromhex("5c783166") for separator in separators)
    assert all(separator.encode() != bytes.fromhex("5c6e") for separator in separators)

    closure_tree = next(
        tree
        for tree in trees
        if any(
            isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "expected_alternate" for target in node.targets)
            for node in ast.walk(tree)
        )
    )
    alternate = expected_alternate_value(closure_tree)
    assert alternate == b"/clean/objects\n", alternate
    assert alternate != bytes.fromhex("2f636c65616e2f6f626a656374735c6e")
    assert b"\\n" not in alternate

    print(f"heredocs={len(bodies)} tab={separators.count(chr(9))} unit_separator={separators.count(chr(31))} alternate={alternate.hex()}")


if __name__ == "__main__":
    main()
