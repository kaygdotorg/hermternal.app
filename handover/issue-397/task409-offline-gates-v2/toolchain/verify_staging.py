#!/usr/bin/env python3
"""Verify the closed Linux toolchain staging root without network access."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any

HERE = Path(__file__).resolve().parent
MANIFEST_PATH = HERE / "staging-manifest.json"
PACKAGES_PATH = HERE / "debian-packages.tsv"
REPOSITORY = HERE.parents[3]
MAX_JSON_BYTES = 32 * 1024
SAFE_ENV = {"HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
PODMAN_ENV = {
    **SAFE_ENV,
    # Rootless Podman needs its existing storage and run root. These paths are
    # not mounted in the toolchain container and no registry command can run.
    "HOME": os.environ.get("HOME", ""),
    "XDG_RUNTIME_DIR": os.environ.get("XDG_RUNTIME_DIR", ""),
}


class Reject(RuntimeError):
    """Reject staging data that is not the reviewed closed input set."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Reject(message)


def strict_json(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    require(len(raw) <= MAX_JSON_BYTES, "manifest is too large")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            require(key not in value, "manifest has a duplicate key")
            value[key] = item
        return value

    value = json.loads(raw, object_pairs_hook=pairs)
    require(isinstance(value, dict), "manifest root differs")
    return value


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def md5(path: Path) -> str:
    value = hashlib.md5(usedforsecurity=False)
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def regular_file(root: Path, relative: str, expected: dict[str, Any]) -> Path:
    path = root / relative
    require(path.resolve() == path and path.is_relative_to(root), f"{relative} path differs")
    metadata = os.lstat(path)
    require(stat.S_ISREG(metadata.st_mode), f"{relative} is not a regular file")
    require(metadata.st_uid == os.getuid() and metadata.st_nlink == 1, f"{relative} ownership differs")
    require(metadata.st_size == expected["bytes"] and sha256(path) == expected["sha256"], f"{relative} content differs")
    return path


def require_epoch_tree(root: Path) -> None:
    require(root.is_dir() and not root.is_symlink(), f"{root.name} tree differs")
    resolved = root.resolve()
    for directory, names, files in os.walk(root, followlinks=False):
        for name in (*names, *files):
            path = Path(directory) / name
            metadata = os.lstat(path)
            require(metadata.st_uid == os.getuid() and metadata.st_mtime_ns == 0, f"{path.name} context metadata differs")
            require(stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode), f"{path.name} context type differs")
            if stat.S_ISLNK(metadata.st_mode):
                target = path.resolve(strict=True)
                require(target == resolved or target.is_relative_to(resolved), f"{path.name} symlink escapes")


def package_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as source:
        return list(csv.DictReader(source, delimiter="\t"))


def verify_packages(root: Path, manifest: dict[str, Any]) -> None:
    debian = manifest["debian"]
    package_manifest = debian["package_manifest"]
    require(PACKAGES_PATH.stat().st_size == package_manifest["committed_bytes"], "committed package manifest size differs")
    require(sha256(PACKAGES_PATH) == package_manifest["committed_sha256"], "committed package manifest differs")
    staged = root / package_manifest["staged_path"]
    require(sha256(staged) == package_manifest["staged_sha256"], "staged package manifest differs")
    rows = package_rows(PACKAGES_PATH)
    require(len(rows) == debian["package_count"], "package count differs")
    require(staged.read_text(encoding="utf-8").splitlines() == ["\t".join(row.values()) for row in rows], "staged package rows differ")
    index_path = regular_file(root, debian["packages_index"]["path"], debian["packages_index"])
    inrelease = (root / debian["inrelease"]["path"]).read_bytes()
    binding = f" {debian['packages_index']['sha256']}  {debian['packages_index']['bytes']} main/binary-amd64/Packages.xz\n".encode()
    require(binding in inrelease, "Packages.xz is not bound to signed InRelease")
    paragraphs = lzma.decompress(index_path.read_bytes()).decode("utf-8").strip().split("\n\n")
    index: dict[tuple[str, str, str], dict[str, str]] = {}
    for paragraph in paragraphs:
        fields = dict(line.split(": ", 1) for line in paragraph.splitlines() if ": " in line)
        if all(key in fields for key in ("Package", "Version", "Architecture", "Size", "SHA256")):
            key = (fields["Package"], fields["Version"], fields["Architecture"])
            require(key not in index, "Packages.xz has a duplicate package identity")
            index[key] = fields
    for row in rows:
        path = root / "snapshot" / "debs" / row["filename"]
        regular_file(root, path.relative_to(root).as_posix(), {"bytes": int(row["file_size_bytes"]), "sha256": row["sha256"]})
        fields = index.get((row["package"], row["version"], row["architecture"]))
        require(fields is not None and fields["Size"] == row["file_size_bytes"] and fields["SHA256"] == row["sha256"], f"{row['package']} is not bound to Packages.xz")


def local_base(manifest: dict[str, Any]) -> None:
    base = manifest["base_image"]
    reference = f"docker.io/library/node@sha256:{base['manifest_sha256']}"
    info = subprocess.run(("/usr/bin/podman", "info", "--format", "{{.Host.Security.Rootless}} {{.Host.Arch}}"), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=PODMAN_ENV, cwd="/", timeout=30, check=False)
    require(info.returncode == 0 and info.stdout.strip() == b"true amd64", "Podman is not rootless amd64")
    result = subprocess.run(("/usr/bin/podman", "image", "inspect", reference), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=PODMAN_ENV, cwd="/", timeout=30, check=False)
    require(result.returncode == 0 and len(result.stdout) <= MAX_JSON_BYTES, "pinned base image is unavailable")
    values = json.loads(result.stdout)
    require(isinstance(values, list) and len(values) == 1, "base inspection differs")
    value = values[0]
    require(value.get("Architecture") == "amd64", "base architecture differs")
    require(str(value.get("Id", "")).removeprefix("sha256:") == base["config_sha256"], "base config differs")
    require(reference in value.get("RepoDigests", []), "base RepoDigest differs")


def verify_inrelease(root: Path, manifest: dict[str, Any]) -> None:
    base = manifest["base_image"]
    reference = f"docker.io/library/node@sha256:{base['manifest_sha256']}"
    command = (
        "/usr/bin/podman", "run", "--rm", "--pull=never", "--network=none",
        "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--mount", f"type=bind,src={root},dst=/stage,ro=true,relabel=private",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=8m", reference,
        "sqv", "--keyring", "/stage/snapshot/debian-archive-keyring.gpg",
        "--output", "/tmp/authenticated", "--cleartext", "/stage/snapshot/trixie-InRelease",
    )
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=PODMAN_ENV, cwd="/", timeout=60, check=False)
    require(result.returncode == 0, "Debian InRelease signature differs")


def local_image(image: str, repo_digest: str, manifest: dict[str, Any]) -> None:
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", repo_digest) is not None, "image RepoDigest syntax differs")
    require("@" not in image and image.startswith("localhost/"), "local image name differs")
    result = subprocess.run(("/usr/bin/podman", "image", "inspect", image), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=PODMAN_ENV, cwd="/", timeout=30, check=False)
    require(result.returncode == 0 and len(result.stdout) <= MAX_JSON_BYTES, "local toolchain image is unavailable")
    values = json.loads(result.stdout)
    require(isinstance(values, list) and len(values) == 1, "toolchain image inspection differs")
    value = values[0]
    require(value.get("Architecture") == "amd64" and f"{image}@{repo_digest}" in value.get("RepoDigests", []), "toolchain image RepoDigest differs")
    labels = value.get("Labels") or value.get("Config", {}).get("Labels") or {}
    expected = {
        "org.hermternal.bun": manifest["bun"]["version"],
        "org.hermternal.node": "26.7.0",
        "org.hermternal.playwright": manifest["playwright"]["version"],
        "org.hermternal.dependencies-sha256": manifest["dependencies"]["tree"]["sha256"],
        "org.hermternal.bun-archive-sha256": manifest["bun"]["archive"]["sha256"],
        "org.hermternal.browser-archive-sha256": manifest["playwright"]["headless_shell_archive"]["sha256"],
        "org.hermternal.debian-packages-sha256": manifest["debian"]["package_manifest"]["staged_sha256"],
    }
    require(all(labels.get(key) == expected_value for key, expected_value in expected.items()), "toolchain image labels differ")


def tree_identities(root: Path, manifest: dict[str, Any]) -> None:
    source = manifest["dependencies"]["tree_identity_source"]
    source_path = REPOSITORY / source["path"]
    require(sha256(source_path) == source["sha256"], "tree identity source differs")
    bun = root / manifest["bun"]["binary"]["path"]
    browser = root / manifest["playwright"]["headless_shell_tree"]["path"]
    dependencies = root / manifest["dependencies"]["path"]
    result = subprocess.run((os.fspath(bun), os.fspath(HERE / "tree_identity.ts"), os.fspath(browser), os.fspath(dependencies)), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={**SAFE_ENV, "BUN_INSTALL": os.fspath(root / "bun")}, cwd="/", timeout=120, check=False)
    require(result.returncode == 0 and len(result.stdout) <= MAX_JSON_BYTES, "tree identity calculation failed")
    value = json.loads(result.stdout)
    expected_browser = dict(manifest["playwright"]["headless_shell_tree"])
    expected_browser.pop("path")
    require(value.get("browser") == expected_browser, "browser tree differs")
    require(value.get("dependencies") == manifest["dependencies"]["tree"], "dependency tree differs")


def verify(root: Path, image: str | None = None, repo_digest: str | None = None) -> None:
    root = root.absolute()
    metadata = os.lstat(root)
    require(root.resolve() == root and stat.S_ISDIR(metadata.st_mode), "staging root path differs")
    require(metadata.st_uid == os.getuid() and stat.S_IMODE(metadata.st_mode) == 0o700, "staging root privacy differs")
    manifest = strict_json(MANIFEST_PATH)
    require(manifest.get("schema") == "hermternal.issue-397.offline-toolchain-staging/v1" and manifest.get("status") == "authenticated-inputs", "staging manifest differs")
    require(manifest.get("architecture") == "linux/amd64", "staging architecture differs")
    regular_file(root, manifest["bun"]["archive"]["path"], manifest["bun"]["archive"])
    regular_file(root, manifest["bun"]["binary"]["path"], manifest["bun"]["binary"])
    browser_archive = regular_file(root, manifest["playwright"]["headless_shell_archive"]["path"], manifest["playwright"]["headless_shell_archive"])
    require(md5(browser_archive) == manifest["playwright"]["headless_shell_archive"]["md5"], "browser archive MD5 differs")
    regular_file(root, manifest["debian"]["inrelease"]["path"], manifest["debian"]["inrelease"])
    regular_file(root, manifest["debian"]["archive_keyring"]["path"], manifest["debian"]["archive_keyring"])
    for relative in (manifest["bun"]["binary"]["path"], manifest["playwright"]["headless_shell_tree"]["path"], manifest["dependencies"]["path"], "snapshot/debs"):
        require_epoch_tree(root / relative if relative.endswith("node_modules") or relative.endswith("chrome-headless-shell-linux64") or relative == "snapshot/debs" else (root / relative).parent)
    verify_packages(root, manifest)
    tree_identities(root, manifest)
    local_base(manifest)
    verify_inrelease(root, manifest)
    require((image is None) == (repo_digest is None), "image and RepoDigest must be supplied together")
    if image is not None and repo_digest is not None:
        local_image(image, repo_digest, manifest)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--image")
    parser.add_argument("--repo-digest")
    args = parser.parse_args()
    try:
        verify(args.root, args.image, args.repo_digest)
    except (OSError, ValueError, KeyError, json.JSONDecodeError, subprocess.TimeoutExpired, Reject) as error:
        print(json.dumps({"ok": False, "error": str(error)}, separators=(",", ":")))
        return 2
    print(json.dumps({"ok": True, "status": "authenticated-inputs", "image_output": "verified" if args.image else "deferred"}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
