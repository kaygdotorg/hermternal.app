#!/usr/bin/env python3
"""Share the Linux replay Git-config policy with generation and #400.

The generated object-closure validator inspects repository-local records. A
remote URL is metadata, not a protocol permission. Only protocol allow keys
use the ``never`` value rule. The frozen #400 reviewer stays authoritative for
the exact replay repository config bytes.
"""
from __future__ import annotations

import re
from types import ModuleType

PROTOCOL_NAMESPACE = "protocol."
PROTOCOL_KEY = PROTOCOL_NAMESPACE + "allow"
PROTOCOL_VALUE = "never"
PROTOCOL_OVERRIDE = f"{PROTOCOL_KEY}={PROTOCOL_VALUE}"
CONFIG_QUERY = rf"^(extensions\.partialClone|remote\..*|{re.escape(PROTOCOL_KEY)}|{re.escape(PROTOCOL_NAMESPACE)}.*\.allow)$"

CANONICAL_RECORDS = (
    ("core.repositoryformatversion", "0"),
    ("core.filemode", "true"),
    ("core.bare", "false"),
    ("core.logallrefupdates", "true"),
    ("core.hookspath", "/dev/null"),
    (PROTOCOL_KEY, PROTOCOL_VALUE),
)
CANONICAL_CONFIG = (
    b"[core]\n"
    b"\trepositoryformatversion = 0\n"
    b"\tfilemode = true\n"
    b"\tbare = false\n"
    b"\tlogallrefupdates = true\n"
    b"\thooksPath = /dev/null\n"
    b"[protocol]\n"
    + f"\tallow = {PROTOCOL_VALUE}\n".encode("ascii")
)

# This source is embedded unchanged in the derived stdin and compiled here for
# unit checks. Keeping one source prevents the generator and tests from using
# different protocol-key rules.
PREDICATE_SOURCE = f"""def repository_config_rejection(key, value):
    normalized_key = key.strip().lower()
    normalized_value = value.strip().lower()
    if (normalized_key == 'extensions.partialclone'
            or normalized_key.endswith('.promisor')
            or normalized_key.endswith('.vcs')):
        return 'repository contains partial-clone, promisor, or custom-helper configuration'
    is_protocol_allow = (normalized_key == {PROTOCOL_KEY!r}
                         or (normalized_key.startswith({PROTOCOL_NAMESPACE!r})
                             and normalized_key.endswith('.allow')))
    if is_protocol_allow and normalized_value not in ({PROTOCOL_VALUE!r}, ''):
        return 'repository contains an unsafe protocol transport policy'
    return None
"""
_PREDICATE_NAMESPACE: dict[str, object] = {}
exec(compile(PREDICATE_SOURCE, "<issue397-git-config-policy>", "exec"), _PREDICATE_NAMESPACE)
repository_config_rejection = _PREDICATE_NAMESPACE["repository_config_rejection"]

OLD_OBJECT_CLOSURE_BLOCK = b"""    config = run('config', '--local', '--get-regexp', r'^(extensions\\.partialClone|remote\\..*|protocol\\..*\\.allow)$', check=False)
    for line in config.stdout.decode().splitlines():
        key, _, value = line.partition(' ')
        if key.lower() == 'extensions.partialclone' or key.lower().endswith('.promisor') or key.lower().endswith('.vcs'):
            raise SystemExit('repository contains partial-clone, promisor, or custom-helper configuration')
        if value.strip().lower() not in ('never', ''):
            raise SystemExit('repository contains an unsafe protocol transport policy')
"""


def _new_object_closure_block() -> bytes:
    predicate = "\n".join("    " + line if line else "" for line in PREDICATE_SOURCE.rstrip("\n").split("\n"))
    loop = f"""    config = run('config', '--local', '--get-regexp', {CONFIG_QUERY!r}, check=False)
    for line in config.stdout.decode().splitlines():
        key, _, value = line.partition(' ')
        rejection = repository_config_rejection(key, value)
        if rejection is not None:
            raise SystemExit(rejection)
"""
    return (predicate + "\n" + loop).encode("utf-8")


NEW_OBJECT_CLOSURE_BLOCK = _new_object_closure_block()


def repair_generated_validator(stdin: bytes) -> bytes:
    """Replace one authenticated faulty block in the generated driver."""
    if stdin.count(OLD_OBJECT_CLOSURE_BLOCK) != 1 or stdin.count(NEW_OBJECT_CLOSURE_BLOCK) != 0:
        raise RuntimeError("repository config policy anchor differs")
    repaired = stdin.replace(OLD_OBJECT_CLOSURE_BLOCK, NEW_OBJECT_CLOSURE_BLOCK, 1)
    if repaired.count(OLD_OBJECT_CLOSURE_BLOCK) != 0 or repaired.count(NEW_OBJECT_CLOSURE_BLOCK) != 1:
        raise RuntimeError("repository config policy replacement differs")
    return repaired


def validate_generated_records(raw: bytes) -> None:
    """Apply the embedded predicate to exact ``git config`` output bytes."""
    if not isinstance(raw, bytes) or b"\x00" in raw or b"\r" in raw:
        raise ValueError("repository config output is not LF text")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("repository config output is not UTF-8") from exc
    for line in lines:
        key, separator, value = line.partition(" ")
        if not key or not separator:
            raise ValueError("repository config output record differs")
        rejection = repository_config_rejection(key, value)
        if rejection is not None:
            raise ValueError(rejection)


def validate_git_successor_contract(successor: ModuleType) -> None:
    """Bind the shared policy to the exact frozen #400 successor API."""
    if successor.CANONICAL_CONFIG != CANONICAL_CONFIG:
        raise RuntimeError("#400 canonical Git config bytes differ")
    if tuple(successor.CANONICAL_RECORDS) != CANONICAL_RECORDS:
        raise RuntimeError("#400 canonical Git config records differ")
    overrides = tuple(successor.GIT_CONFIG_OVERRIDES)
    if overrides != (
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        PROTOCOL_OVERRIDE,
    ):
        raise RuntimeError("#400 per-command Git config policy differs")
    successor.validate_canonical_config(CANONICAL_CONFIG, "shared canonical Git config")
