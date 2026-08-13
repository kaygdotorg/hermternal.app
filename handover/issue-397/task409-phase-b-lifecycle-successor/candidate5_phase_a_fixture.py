#!/usr/bin/env python3
"""Build local candidate-five mock bytes for genuine Phase A lifecycle tests.

This helper adapts the approved framing successor to a fresh private test root.
It does not approve or publish a final triad. It does not run Git, replay, the
generated shell, a network operation, credentials, sockets, or Hermes.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import stat
import sys
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
FRAMING_PATH = BASE / "task464-candidate5-successor" / "candidate5_framing_range_successor.py"
INPUT_JSON = BASE / "task464-inputs" / "task464-working-input.json"
INPUT_MARKDOWN = BASE / "task464-inputs" / "task464-working-input.md"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load fixture dependency: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _publish(paths: tuple[Path, ...], payloads: tuple[bytes, ...], final_validate=None):
    """Create fixture files once; final genuine Phase A validates all bytes."""
    adjusted = list(payloads)
    markdown = adjusted[1]
    heading = b"## Canonical machine-readable ordered execution driver\n"
    opening = b"```bash\n"
    body_start = markdown.index(opening, markdown.index(heading)) + len(opening)
    closing = markdown.index(b"```", body_start)
    # Frozen v3 Phase A permits exactly one standalone close. The source mock
    # has later prose fences, so use tilde fences after the authoritative shell.
    adjusted[1] = markdown[: closing + 3] + markdown[closing + 3 :].replace(b"\n```\n", b"\n~~~\n")
    for path, raw in zip(paths, adjusted):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            offset = 0
            while offset < len(raw):
                offset += os.write(fd, raw[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
    return tuple(adjusted)


def build(authority_root: Path, phase_a: Any) -> tuple[dict[str, Any], dict[str, Path]]:
    """Create exact role names and return a full durable Phase A manifest."""
    root = Path(authority_root)
    paths = {
        "markdown": root / "candidate-five.md",
        "json": root / "candidate-five.json",
        "shell": root / "candidate-five.sh",
    }
    input_json = root / "source-input.json"
    input_markdown = root / "source-input.md"
    input_json.write_bytes(INPUT_JSON.read_bytes())
    input_markdown.write_bytes(INPUT_MARKDOWN.read_bytes())
    input_json.chmod(0o600)
    input_markdown.chmod(0o600)
    framing = _load("issue397_phase_b_fixture_framing", FRAMING_PATH)
    generator = framing.install_successor()
    generator.canonical_target = lambda value, _label: Path(value).resolve()
    generator.reject_target_set = lambda targets: None
    generator.publish_once = _publish
    with redirect_stdout(io.StringIO()):
        generator.main(
            [
                "--input-json", str(input_json),
                "--input-markdown", str(input_markdown),
                "--output-json", str(paths["json"]),
                "--output-markdown", str(paths["markdown"]),
                "--output-shell", str(paths["shell"]),
            ]
        )

    def identity(path: Path) -> str:
        st = os.lstat(path)
        values = []
        for field in phase_a.IDENTITY_FIELDS:
            value = stat.S_IMODE(st.st_mode) if field == "st_mode" else int(getattr(st, field))
            values.append(str(value))
        return ",".join(values)

    raw = {role: path.read_bytes() for role, path in paths.items()}
    document = json.loads(raw["json"].decode("utf-8"))
    normalized = document["validation_contract"]["matrix_identity"]["expected_normalized_sha256"]
    facts = [
        str(paths["markdown"]), str(paths["json"]), str(paths["shell"]),
        hashlib.sha256(raw["markdown"]).hexdigest(), hashlib.sha256(raw["json"]).hexdigest(), hashlib.sha256(raw["shell"]).hexdigest(),
        normalized, identity(paths["markdown"]), identity(paths["json"]), identity(paths["shell"]),
        str(len(raw["shell"])), str(raw["shell"].count(b"\n")), raw["shell"][-1:].hex(),
        phase_a.LANE, "sha1", phase_a.BASE_REF, phase_a.BASE_COMMIT, phase_a.BASE_TREE, phase_a.MAIN_REF, phase_a.MAIN_COMMIT,
    ]
    return phase_a._manifest_from_wrapper(facts), paths
