#!/usr/bin/env python3
"""Adversarial regressions for candidate-five Git-config authority."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path


SUCCESSOR = Path(__file__).with_name("candidate5_git_config_successor.py")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def rejects(callable_, *args):
    try:
        callable_(*args)
    except AssertionError:
        raise
    except Exception:
        return
    raise AssertionError(f"accepted invalid input: {args!r}")


def load_successor():
    spec = importlib.util.spec_from_file_location("candidate5_git_config_successor", SUCCESSOR)
    require(spec is not None and spec.loader is not None, "successor loader is missing")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def mutate(raw, old, new):
    require(old in raw, f"mutation source is absent: {old!r}")
    return raw.replace(old, new, 1)


def test_closed_raw_contract(successor):
    canonical = successor.CANONICAL_CONFIG
    successor.validate_canonical_config(canonical)
    hostile = (
        canonical[:-1],
        canonical + b"\n",
        canonical.replace(b"\n", b"\r\n"),
        canonical + b"\x00",
        b"# comment\n" + canonical,
        mutate(canonical, b"[core]", b"[Core]"),
        mutate(canonical, b"hooksPath", b"hookspath"),
        mutate(canonical, b"/dev/null", b'"/dev/null"'),
        mutate(canonical, b"\tfilemode = true\n", b"\tfilemode = true\\\n\tfalse\n"),
        canonical + b"[core]\n\tpager = cat\n",
        canonical + b"[core]\n\thooksPath = /dev/null\n",
        canonical + b"[core]\n\tattributesFile = /tmp/attributes\n",
        canonical + b"[core]\n\texcludesFile = /tmp/excludes\n",
        canonical + b"[merge \"hostile\"]\n\tdriver = /tmp/run\n",
        canonical + b"[gpg]\n\tprogram = /tmp/run\n",
        canonical + b"[extensions]\n\tobjectFormat = sha256\n",
    )
    for raw in hostile:
        rejects(successor.validate_canonical_config, raw, "hostile config")


def test_verified_byte_loader(successor):
    trusted = successor.FROZEN_REVIEWER.read_bytes()
    original_path = successor.FROZEN_REVIEWER
    original_hash = successor.FROZEN_REVIEWER_SHA256
    original_reader = successor._read_frozen_reviewer
    with tempfile.TemporaryDirectory(prefix="candidate5-git-reviewer-") as directory:
        victim = Path(directory) / "reviewer.py"
        replacement = Path(directory) / "replacement.py"
        victim.write_bytes(trusted)
        replacement.write_bytes(b"REPLACEMENT_EXECUTED = True\n")
        successor.FROZEN_REVIEWER = victim
        successor.FROZEN_REVIEWER_SHA256 = hashlib.sha256(trusted).hexdigest()

        def read_then_swap():
            raw = original_reader()
            os.replace(replacement, victim)
            return raw

        successor._read_frozen_reviewer = read_then_swap
        try:
            reviewer = successor._load_verified_reviewer(successor._read_frozen_reviewer())
            require(not hasattr(reviewer, "REPLACEMENT_EXECUTED"), "replacement bytes ran")
            require(hasattr(reviewer, "inspect_metadata"), "verified reviewer did not run")
            require(reviewer.__loader__ is None, "reviewer retained a path loader")
        finally:
            successor._read_frozen_reviewer = original_reader
            successor.FROZEN_REVIEWER = original_path
            successor.FROZEN_REVIEWER_SHA256 = original_hash


def configure_repository(successor, root):
    subprocess.run(
        ["/usr/bin/git", "init", "-q", os.fspath(root)],
        env=dict(successor.SAFE_ENV),
        check=True,
    )
    subprocess.run(
        ["/usr/bin/git", "-C", os.fspath(root), "config", "--local", "core.hooksPath", "/dev/null"],
        env=dict(successor.SAFE_ENV),
        check=True,
    )
    subprocess.run(
        ["/usr/bin/git", "-C", os.fspath(root), "config", "--local", "protocol.allow", "never"],
        env=dict(successor.SAFE_ENV),
        check=True,
    )


def test_real_semantic_gate(successor):
    reviewer = successor.install_successor()
    with tempfile.TemporaryDirectory(prefix="candidate5-git-config-") as directory:
        root = Path(directory).resolve() / "repo"
        configure_repository(successor, root)
        require((root / ".git/config").read_bytes() == successor.CANONICAL_CONFIG, "Git init serialization differs")
        identity = reviewer.inspect_metadata(root, "fixture")
        calls = []
        original = subprocess.run

        def counted(argv, **kwargs):
            if "config" in argv:
                calls.append(tuple(argv))
            return original(argv, **kwargs)

        subprocess.run = counted
        try:
            guard = reviewer.RepoGuard(identity)
            require(len(calls) == 1, "semantic config must run exactly once after guard creation")
            require(calls[0] == tuple(successor.git_argv(root, ["config", "--local", "--show-origin", "--null", "--list"])), "semantic config argv differs")
            guard.assert_stable()
        finally:
            subprocess.run = original


def test_metadata_and_semantic_swaps_reject(successor):
    reviewer = successor.install_successor()
    with tempfile.TemporaryDirectory(prefix="candidate5-git-swaps-") as directory:
        root = Path(directory).resolve() / "repo"
        configure_repository(successor, root)
        identity = reviewer.inspect_metadata(root, "swap fixture")
        config = root / ".git/config"
        replacement = root / ".git/config.replacement"
        replacement.write_bytes(successor.CANONICAL_CONFIG)
        os.replace(replacement, config)
        try:
            reviewer.RepoGuard(identity)
        except reviewer.Reject:
            pass
        else:
            raise AssertionError("metadata replacement before guard was accepted")

    reviewer = successor.install_successor()
    with tempfile.TemporaryDirectory(prefix="candidate5-git-semantic-") as directory:
        root = Path(directory).resolve() / "repo"
        configure_repository(successor, root)
        identity = reviewer.inspect_metadata(root, "semantic fixture")
        original = subprocess.run

        def wrong_semantics(argv, **kwargs):
            if "config" in argv:
                return subprocess.CompletedProcess(argv, 0, b"file:.git/config\x00core.pager\ncat\x00", b"")
            return original(argv, **kwargs)

        subprocess.run = wrong_semantics
        try:
            try:
                reviewer.RepoGuard(identity)
            except reviewer.Reject:
                pass
            else:
                raise AssertionError("different semantic config records were accepted")
        finally:
            subprocess.run = original

    reviewer = successor.install_successor()
    with tempfile.TemporaryDirectory(prefix="candidate5-git-inflight-") as directory:
        root = Path(directory).resolve() / "repo"
        configure_repository(successor, root)
        identity = reviewer.inspect_metadata(root, "in-flight fixture")
        config = root / ".git/config"
        replacement = root / ".git/config.replacement"
        replacement.write_bytes(successor.CANONICAL_CONFIG)
        original = subprocess.run

        def swap_during_semantic(argv, **kwargs):
            if "config" in argv:
                result = original(argv, **kwargs)
                os.replace(replacement, config)
                return result
            return original(argv, **kwargs)

        subprocess.run = swap_during_semantic
        try:
            try:
                reviewer.RepoGuard(identity)
            except reviewer.Reject:
                pass
            else:
                raise AssertionError("in-flight config replacement was accepted")
        finally:
            subprocess.run = original


def test_fixed_process_boundary(successor):
    reviewer = successor.install_successor()
    with tempfile.TemporaryDirectory(prefix="candidate5-git-argv-") as directory:
        root = Path(directory).resolve()
        expected = successor.git_argv(
            root,
            [
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--ignored=traditional",
                "--ignore-submodules=none",
            ],
        )
        require(tuple(expected[:4]) == successor.GIT_PREFIX, "Git executable prefix differs")
        require(tuple(expected[6:12]) == successor.GIT_CONFIG_OVERRIDES, "Git overrides differ")
        rejects(successor.git_argv, Path("relative"), ["status"])
        rejects(successor.git_argv, root, [""])
        rejects(successor.git_argv, root, ["status\x00bad"])

        observed = {}
        original_subprocess_run = subprocess.run

        def fake_run(argv, **kwargs):
            observed["argv"] = list(argv)
            observed.update(kwargs)
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        subprocess.run = fake_run
        try:
            reviewer._run_process(expected, timeout=3)
        finally:
            subprocess.run = original_subprocess_run
        require(observed["argv"] == expected, "subprocess argv differs")
        require(observed["env"] == successor.SAFE_ENV, "subprocess environment differs")
        require(observed["cwd"] == "/", "subprocess cwd differs")
        require(observed["check"] is False, "subprocess check mode differs")
        rejects(lambda: reviewer._run_process([*successor.GIT_PREFIX, "version"], timeout=3))
        reviewer.SAFE_ENV["GIT_CONFIG_COUNT"] = "1"
        try:
            rejects(lambda: reviewer._run_process(expected, timeout=3))
        finally:
            reviewer.SAFE_ENV.pop("GIT_CONFIG_COUNT")


def test_public_git_boundary_rejects_injection_without_process(successor):
    reviewer = successor.install_successor()
    with tempfile.TemporaryDirectory(prefix="candidate5-git-reject-") as directory:
        root = Path(directory).resolve()
        hostile = (
            ["-c", "core.hooksPath=/tmp/hooks", "status"],
            ["status", "-c", "protocol.allow=always"],
            ["--config-env=credential.helper=HELPER", "status"],
            ["--config-env", "credential.helper=HELPER", "status"],
            ["-C", "/tmp", "status"],
            ["--git-dir=/tmp/git", "status"],
            ["--work-tree=/tmp/tree", "status"],
            ["--namespace=hostile", "status"],
            ["--super-prefix=hostile", "status"],
            ["--exec-path=/tmp", "status"],
            ["--bare", "status"],
            ["--replace-objects", "status"],
            ["--lazy-fetch", "status"],
            ["--optional-locks", "status"],
            ["--no-replace-object", "status"],
            ["--config-en=credential.helper=HELPER", "status"],
            ["status", "--porcelain=v1", "--untracked-files=all", "--ignored=traditional", "--ignore-submodules=none", "-c", "core.hooksPath=/tmp"],
            ["credential", "fill"],
            ["config", "--global", "credential.helper", "/tmp/helper"],
            ["config", "--local", "--show-origin", "--null", "--list", "--includes"],
            ["rev-parse", "--verify", "--end-of-options", "--help"],
        )
        calls = []
        original = subprocess.run

        def counted(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        subprocess.run = counted
        try:
            for args in hostile:
                rejects(lambda args=args: reviewer.run_git(root, args))
                require(not calls, f"hostile Git args reached subprocess: {args!r}")
                full = [*successor.GIT_PREFIX, "-C", str(root), *successor.GIT_CONFIG_OVERRIDES, *args]
                rejects(lambda full=full: reviewer._run_process(full, timeout=3))
                require(not calls, f"hostile full argv reached subprocess: {args!r}")
        finally:
            subprocess.run = original


def test_complete_review_command_grammar(successor):
    oid = "1" * 40
    allowed = (
        ["config", "--local", "--show-origin", "--null", "--list"],
        ["worktree", "list", "--porcelain"],
        ["status", "--porcelain=v1", "--untracked-files=all", "--ignored=traditional", "--ignore-submodules=none"],
        ["ls-files", "--others", "--ignored", "--exclude-standard", "-z"],
        ["ls-files", "--stage", "-z"],
        ["ls-files", "-v", "-z"],
        ["diff", "--no-ext-diff", "--no-textconv", "--quiet"],
        ["diff", "--cached", "--no-ext-diff", "--no-textconv", "--quiet"],
        ["cat-file", "-t", oid],
        ["cat-file", "--batch-check"],
        ["rev-parse", "--verify", "--end-of-options", f"{oid}^{{tree}}"],
        ["rev-parse", "--verify", "--end-of-options", "refs/remotes/origin/dev^{commit}"],
        ["rev-parse", "--is-bare-repository"],
        ["rev-parse", "--is-shallow-repository"],
        ["rev-parse", "--show-object-format"],
        ["rev-parse", "--show-toplevel"],
        ["rev-parse", "--git-dir"],
        ["rev-parse", "--git-common-dir"],
        ["rev-parse", "--git-path", "objects"],
        ["merge-base", "--is-ancestor", oid, oid],
        ["fsck", "--strict", "--full", "--no-reflogs", "--no-progress"],
        ["rev-list", "--objects", "--all", "--missing=error"],
        ["rev-list", "--objects", "--missing=error", oid],
        ["rev-list", "--parents", "-n", "1", oid],
        ["symbolic-ref", "-q", "HEAD"],
    )
    for args in allowed:
        successor.validate_git_args(args)


def test_pre_post_executable_guards(successor):
    reviewer = successor.install_successor()
    root = Path("/")
    argv = successor.git_argv(root, ["rev-parse", "--show-toplevel"])
    calls = []
    original_assert = successor._assert_git_stable
    original_process = subprocess.run

    def counted(binding):
        calls.append(binding)

    def fake_run(arguments, **kwargs):
        return subprocess.CompletedProcess(arguments, 0, b"git version test\n", b"")

    successor._assert_git_stable = counted
    subprocess.run = fake_run
    try:
        reviewer._run_process(argv, timeout=3)
    finally:
        successor._assert_git_stable = original_assert
        subprocess.run = original_process
    require(len(calls) == 2, "trusted Git must rebound before and after each process")

    successor._assert_git_stable = lambda _binding: (_ for _ in ()).throw(RuntimeError("swap"))
    subprocess.run = fake_run
    try:
        rejects(lambda: reviewer._run_process(argv, timeout=3))
    finally:
        successor._assert_git_stable = original_assert
        subprocess.run = original_process


def main():
    successor = load_successor()
    test_closed_raw_contract(successor)
    test_verified_byte_loader(successor)
    test_real_semantic_gate(successor)
    test_metadata_and_semantic_swaps_reject(successor)
    test_fixed_process_boundary(successor)
    test_public_git_boundary_rejects_injection_without_process(successor)
    test_complete_review_command_grammar(successor)
    test_pre_post_executable_guards(successor)
    print("candidate-five Git-config successor checks passed")


if __name__ == "__main__":
    main()
