#!/usr/bin/env python3
"""Verify and plan one normal non-force update of origin/dev."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

BASE_DEV = "729f2613af2b78d58b07918478e9102d5716f367"
PROTECTED_MAIN = "3ebf8b3fe4767442490ab3053c0c1ccf84e8019f"
OFFLINE_SCHEMA = "hermternal.issue-397.offline-gates.v1"
OID_RE = re.compile(r"[0-9a-f]{40}\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
SAFE_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/dev/null", "LANG": "C", "LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}


class Reject(Exception):
    """A deliberate fail-closed dev-update rejection."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Reject(message)


def strict_json(raw: bytes, label: str) -> dict[str, Any]:
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, f"{label} has duplicate key {key}"); result[key] = value
        return result
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except Reject: raise
    except Exception as exc: raise Reject(f"{label} is invalid JSON: {exc}") from exc
    require(isinstance(value, dict), f"{label} is not an object")
    return value


@dataclass(frozen=True)
class Candidate:
    """Candidate identity authenticated by approved #406 evidence."""
    commit: str
    tree: str
    evidence_sha256: str


def validate_offline_evidence(raw: bytes) -> Candidate:
    """Accept only a complete approved #406 PASS summary."""
    value = strict_json(raw, "#406 evidence")
    keys = {"schema", "status", "offline", "credentials", "network", "repository", "final_head", "final_tree", "main_unchanged", "dev_target", "gates"}
    require(set(value) == keys and value["schema"] == OFFLINE_SCHEMA and value["status"] == "passed", "#406 evidence schema or status differs")
    require(value["offline"] is True and value["credentials"] == "not-used" and value["network"] == "not-used", "#406 safety fields differ")
    require(value["main_unchanged"] == PROTECTED_MAIN and value["dev_target"] == value["final_head"], "#406 main or dev identity differs")
    require(OID_RE.fullmatch(value["final_head"]) is not None and OID_RE.fullmatch(value["final_tree"]) is not None, "#406 candidate OID differs")
    gates = value["gates"]
    require(isinstance(gates, list) and len(gates) >= 14 and all(item.get("status") == "passed" for item in gates), "#406 gate set is incomplete")
    require(len({item.get("id") for item in gates}) == len(gates), "#406 gate IDs are duplicate")
    return Candidate(value["final_head"], value["final_tree"], hashlib.sha256(raw).hexdigest())


def validate_refspec(refspec: str, candidate: Candidate) -> tuple[str, ...]:
    """Return the only permitted normal dev push argv."""
    expected = f"{candidate.commit}:refs/heads/dev"
    require(refspec == expected, "push refspec differs from exact candidate-to-dev update")
    for token in ("+", "*", "^", "--force", "--force-with-lease", "--delete", "refs/heads/main", "refs/tags/"):
        require(token not in refspec, "push refspec contains force, wildcard, deletion, or another ref")
    return ("/usr/bin/git", "push", "--porcelain", "origin", expected)


def _git(run: Callable[..., subprocess.CompletedProcess[bytes]], repository: Path, args: Sequence[str]) -> str:
    result = run(("/usr/bin/git", "-C", str(repository), *args), cwd=repository, env=dict(SAFE_ENV), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False)
    require(result.returncode == 0, f"Git observation failed: {' '.join(args)}")
    return bytes(result.stdout or b"").decode("ascii", "strict").strip()


def preflight(candidate: Candidate, repository: Path, run: Callable[..., subprocess.CompletedProcess[bytes]]) -> dict[str, Any]:
    """Prove every read-only gate before a caller can obtain push argv."""
    repository = Path(repository).resolve(strict=True)
    observed = {
        "dev": _git(run, repository, ("rev-parse", "refs/remotes/origin/dev^{commit}")),
        "main": _git(run, repository, ("rev-parse", "refs/remotes/origin/main^{commit}")),
        "candidate": _git(run, repository, ("rev-parse", f"{candidate.commit}^{{commit}}")),
        "tree": _git(run, repository, ("rev-parse", f"{candidate.commit}^{{tree}}")),
        "status": _git(run, repository, ("status", "--porcelain=v1", "--untracked-files=all")),
        "ancestor": _git(run, repository, ("merge-base", "--is-ancestor", BASE_DEV, candidate.commit)),
    }
    require(observed == {"dev": BASE_DEV, "main": PROTECTED_MAIN, "candidate": candidate.commit, "tree": candidate.tree, "status": "", "ancestor": ""}, "preflight repository identity differs")
    return {"schema": "hermternal.issue-397.dev-update-plan.v1", "status": "ready", "candidate": candidate.commit, "tree": candidate.tree, "expected_dev_before": BASE_DEV, "expected_main": PROTECTED_MAIN, "offline_evidence_sha256": candidate.evidence_sha256, "push_argv": list(validate_refspec(f"{candidate.commit}:refs/heads/dev", candidate)), "push_executed": False}


def verify_post_push(plan: Mapping[str, Any], repository: Path, run: Callable[..., subprocess.CompletedProcess[bytes]]) -> dict[str, Any]:
    """Verify remote readback after an external normal push."""
    require(plan.get("schema") == "hermternal.issue-397.dev-update-plan.v1" and plan.get("status") == "ready" and plan.get("push_executed") is False, "dev update plan differs")
    candidate = plan["candidate"]
    dev = _git(run, repository, ("ls-remote", "--refs", "origin", "refs/heads/dev"))
    main = _git(run, repository, ("ls-remote", "--refs", "origin", "refs/heads/main"))
    require(dev == f"{candidate}\trefs/heads/dev", "origin/dev readback differs")
    require(main == f"{PROTECTED_MAIN}\trefs/heads/main", "origin/main changed")
    return {"schema": "hermternal.issue-397.dev-update-evidence.v1", "status": "passed", "candidate": candidate, "tree": plan["tree"], "dev_before": BASE_DEV, "dev_after": candidate, "main_before": PROTECTED_MAIN, "main_after": PROTECTED_MAIN, "push_mode": "normal-non-force", "refspec": f"{candidate}:refs/heads/dev", "offline_evidence_sha256": plan["offline_evidence_sha256"]}
