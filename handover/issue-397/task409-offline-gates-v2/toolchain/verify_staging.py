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
ATOMIC_RENAME_PROBE = """\
import ctypes
import errno
import hashlib
import os
import platform
import stat
import sys

root = '/tmp/atomic-rename-probe'
source_name = b'source'
destination_name = b'destination'
os.mkdir(root, 0o700)
os.mkdir(f'{root}/source', 0o700)
with open(f'{root}/source/fixture', 'wb') as fixture:
    fixture.write(b'fixture')
parent_fd = os.open(root, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
try:
    source_stat = os.stat(f'{root}/source', follow_symlinks=False)
    fixture_stat = os.stat(f'{root}/source/fixture', follow_symlinks=False)
    if not stat.S_ISDIR(source_stat.st_mode) or not stat.S_ISREG(fixture_stat.st_mode):
        raise OSError(errno.EINVAL, 'atomic rename fixture differs')
    with open(f'{root}/source/fixture', 'rb') as fixture:
        if hashlib.sha256(fixture.read()).hexdigest() != 'f16d05ec6b29248d2c61adb1e9263f78e4f7bace1b955014a2d17872cfe4064d':
            raise OSError(errno.EINVAL, 'atomic rename fixture content differs')
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, 'renameat2', None)
    if rename is not None:
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        result = rename(parent_fd, source_name, parent_fd, destination_name, 0x00000001)
    else:
        syscall_number = {'x86_64': 316, 'aarch64': 276, 'arm64': 276}.get(platform.machine())
        if syscall_number is None:
            raise OSError(errno.ENOTSUP, 'renameat2 is unavailable')
        result = libc.syscall(syscall_number, parent_fd, source_name, parent_fd, destination_name, 0x00000001)
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number or errno.EIO, 'renameat2 failed')
    if os.path.exists(f'{root}/source') or not os.path.isfile(f'{root}/destination/fixture'):
        raise OSError(errno.EIO, 'atomic rename result differs')
finally:
    os.close(parent_fd)
"""


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


def verify_git_closure(rows: list[dict[str, str]], manifest: dict[str, Any]) -> None:
    """Bind the required Git runtime to exact signed-index package rows."""
    git = manifest["git"]
    names = git["packages"]
    require(isinstance(names, list) and names and all(isinstance(name, str) for name in names), "Git package closure differs")
    require(len(names) == len(set(names)), "Git package closure has a duplicate")
    by_name = {row["package"]: row for row in rows}
    require(len(by_name) == len(rows), "package manifest has a duplicate package name")
    require(all(name in by_name for name in names), "Git package closure is incomplete")
    require(by_name["git"]["version"] == git["debian_version"], "Git Debian version differs")


def verify_python_closure(rows: list[dict[str, str]], manifest: dict[str, Any]) -> None:
    """Bind Python and its standard library to exact signed-index rows."""
    names = manifest["python"]["packages"]
    require(isinstance(names, list) and names and len(names) == len(set(names)), "Python package closure differs")
    by_name = {row["package"]: row for row in rows}
    require(all(name in by_name for name in names), "Python package closure is incomplete")
    source = manifest["python"]
    source_row = by_name[source["source_package"]]
    require(source_row["version"] == source["source_package_version"] and source_row["sha256"] == source["source_deb_sha256"], "Python executable source package differs")


def verify_packages(root: Path, manifest: dict[str, Any]) -> None:
    debian = manifest["debian"]
    package_manifest = debian["package_manifest"]
    require(PACKAGES_PATH.stat().st_size == package_manifest["committed_bytes"], "committed package manifest size differs")
    require(sha256(PACKAGES_PATH) == package_manifest["committed_sha256"], "committed package manifest differs")
    staged = root / package_manifest["staged_path"]
    require(sha256(staged) == package_manifest["staged_sha256"], "staged package manifest differs")
    rows = package_rows(PACKAGES_PATH)
    require(len(rows) == debian["package_count"], "package count differs")
    verify_git_closure(rows, manifest)
    verify_python_closure(rows, manifest)
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
    # OCI repository digests bind a repository name, not its mutable tag.
    # Remove only a tag in the final path component so registry ports stay valid.
    prefix, separator, leaf = image.rpartition("/")
    repository = f"{prefix}{separator}{leaf.rsplit(':', 1)[0]}"
    expected_output = manifest["image_output"]
    require(image == expected_output["image"] and repo_digest == expected_output["repo_digest"], "toolchain image output pin differs")
    require(str(value.get("Id", "")).removeprefix("sha256:") == expected_output["image_id"].removeprefix("sha256:"), "toolchain image ID differs")
    require(value.get("Architecture") == "amd64" and f"{repository}@{repo_digest}" in value.get("RepoDigests", []), "toolchain image RepoDigest differs")
    require(value.get("Config", {}).get("User") == manifest["runtime_contract"]["container_user"], "toolchain image user differs")
    labels = value.get("Labels") or value.get("Config", {}).get("Labels") or {}
    expected = {
        "org.hermternal.bun": manifest["bun"]["version"],
        "org.hermternal.bun-cache-sha256": manifest["bun"]["cache"]["tree"]["sha256"],
        "org.hermternal.git": manifest["git"]["version"],
        "org.hermternal.node": "26.7.0",
        "org.hermternal.playwright": manifest["playwright"]["version"],
        "org.hermternal.python": manifest["python"]["version"],
        "org.hermternal.python-sha256": manifest["python"]["canonical_sha256"],
        "org.hermternal.dependencies-sha256": manifest["dependencies"]["tree"]["sha256"],
        "org.hermternal.bun-archive-sha256": manifest["bun"]["archive"]["sha256"],
        "org.hermternal.browser-archive-sha256": manifest["playwright"]["headless_shell_archive"]["sha256"],
        "org.hermternal.chromium-archive-sha256": manifest["playwright"]["chromium"]["archive"]["sha256"],
        "org.hermternal.chromium-tree-sha256": manifest["playwright"]["chromium"]["tree"]["sha256"],
        "org.hermternal.debian-packages-sha256": manifest["debian"]["package_manifest"]["staged_sha256"],
    }
    require(all(labels.get(key) == expected_value for key, expected_value in expected.items()), "toolchain image labels differ")

    # Inspect the package database and execute the same local Git operations as
    # the web tests. Both probes keep the image read-only and offline.
    package_rows_by_name = {row["package"]: row for row in package_rows(PACKAGES_PATH)}
    package_names = manifest["git"]["packages"] + manifest["python"]["packages"] + list(manifest["python"]["base_dependencies"])
    package_command = (
        "/usr/bin/podman", "run", "--rm", "--pull=never", "--network=none",
        "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
        image, "dpkg-query", "--show", "--showformat=${Package}\t${Version}\n",
        *package_names,
    )
    packages = subprocess.run(package_command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=PODMAN_ENV, cwd="/", timeout=60, check=False)
    expected_versions = {name: package_rows_by_name[name]["version"] for name in manifest["git"]["packages"] + manifest["python"]["packages"]}
    expected_versions.update(manifest["python"]["base_dependencies"])
    expected_packages = sorted(f"{name}\t{expected_versions[name]}" for name in package_names)
    require(packages.returncode == 0 and sorted(packages.stdout.decode().splitlines()) == expected_packages, "runtime package closure differs")

    smoke = (
        'test "$(git --version)" = "git version ' + manifest["git"]["version"] + '"\n'
        'test "$(bun --version)" = "' + manifest["bun"]["version"] + '"\n'
        'test "$(node --version)" = "v26.7.0"\n'
        'test "$(python3 --version)" = "Python ' + manifest["python"]["version"] + '"\n'
        'test ! -L ' + manifest["python"]["executable_path"] + '\n'
        'test "$(readlink -f ' + manifest["python"]["executable_path"] + ')" = "' + manifest["python"]["canonical_path"] + '"\n'
        'test "$(stat -c "%F %u:%g %a %h %s" ' + manifest["python"]["executable_path"] + ')" = "regular file 0:0 ' + manifest["python"]["canonical_mode"].removeprefix("0") + ' ' + str(manifest["python"]["executable_nlink"]) + ' ' + str(manifest["python"]["canonical_bytes"]) + '"\n'
        'test "$(sha256sum ' + manifest["python"]["canonical_path"] + ' | cut -d " " -f 1)" = "' + manifest["python"]["canonical_sha256"] + '"\n'
        'test "$(stat -c "%F %u:%g %a %h %s" ' + manifest["python"]["source_path"] + ')" = "regular file 0:0 ' + manifest["python"]["source_mode"].removeprefix("0") + ' ' + str(manifest["python"]["source_nlink"]) + ' ' + str(manifest["python"]["source_bytes"]) + '"\n'
        'test "$(sha256sum ' + manifest["python"]["source_path"] + ' | cut -d " " -f 1)" = "' + manifest["python"]["source_sha256"] + '"\n'
        'python3 -c "import ctypes, errno, hashlib, os, platform, stat, sys"\n'
        'test "$(node -p "require(\'/opt/hermternal/node_modules/playwright/package.json\').version")" = "' + manifest["playwright"]["version"] + '"\n'
        'cd /opt/hermternal\n'
        'test "$(node --input-type=module -e "import { chromium } from \'playwright\'; process.stdout.write(chromium.executablePath())")" = "' + manifest["playwright"]["selected_executable"] + '"\n'
        'cd /tmp\n'
        'test "$(/ms-playwright/chromium_headless_shell-1234/chrome-headless-shell-linux64/chrome-headless-shell --version)" = "Google Chrome for Testing ' + manifest["playwright"]["browser_version"] + '"\n'
        'test "$(stat -c "%u:%g %a %s" ' + manifest["playwright"]["chromium"]["executable_path"] + ')" = "1001:1001 755 ' + str(manifest["playwright"]["chromium"]["executable_bytes"]) + '"\n'
        'test "$(sha256sum ' + manifest["playwright"]["chromium"]["executable_path"] + ' | cut -d " " -f 1)" = "' + manifest["playwright"]["chromium"]["executable_sha256"] + '"\n'
        'test -z "$(find /ms-playwright/chromium-1234/chrome-linux64 /usr/local/install/cache \\( ! -user 1001 -o ! -group 1001 \\) -print -quit)"\n'
        'git init -q repo\n'
        'printf fixture > repo/fixture\n'
        'git -C repo add fixture\n'
        'git -C repo -c user.name=fixture -c user.email=fixture@example.invalid commit -qm fixture\n'
        'test "$(git -C repo show --format= --name-only HEAD)" = fixture\n'
        'test "$(git -C repo log -1 --format=%s)" = fixture\n'
        'git -C repo rev-parse --verify "HEAD^{commit}" >/dev/null\n'
        'test "$(git -C repo archive HEAD | tar -tf -)" = fixture\n'
        'mkdir -p cache-probe/cache\n'
        'cp -a /usr/local/install/cache/. cache-probe/cache/\n'
        'cp /source/apps/web/package.json /source/apps/web/bun.lock cache-probe/\n'
        'cd cache-probe\n'
        'bun install --silent --frozen-lockfile --ignore-scripts --prefer-offline --cache-dir="$PWD/cache" --registry=http://127.0.0.1:1\n'
        'bun ' + manifest["dependencies"]["tree_identity_driver"]["image_path"] + ' /ms-playwright/chromium-1234/chrome-linux64 /usr/local/install/cache\n'
        'bun ' + manifest["dependencies"]["tree_identity_driver"]["image_path"] + ' /ms-playwright/chromium-1234/chrome-linux64 node_modules\n'
    )
    smoke_command = (
        "/usr/bin/podman", "run", "--rm", "--pull=never", "--network=none",
        "--userns=keep-id",
        "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--workdir=/tmp", "--env=HOME=/tmp",
        "--mount", f"type=bind,src={REPOSITORY},dst=/source,ro=true,relabel=private",
        "--mount", "type=tmpfs,dst=/tmp,tmpfs-size=805306368,tmpfs-mode=0700,U=true", image,
        "sh", "-ceu", smoke,
    )
    runtime = subprocess.run(smoke_command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=PODMAN_ENV, cwd="/", timeout=180, check=False)
    require(runtime.returncode == 0, "toolchain runtime smoke differs")
    identities = [json.loads(line) for line in runtime.stdout.decode().splitlines()]
    chromium_tree = dict(manifest["playwright"]["chromium"]["tree"])
    chromium_tree.pop("path")
    require(identities == [
        {"browser": chromium_tree, "dependencies": manifest["bun"]["cache"]["tree"]},
        {"browser": chromium_tree, "dependencies": manifest["dependencies"]["tree"]},
    ], "toolchain runtime trees differ")

    atomic_command = (
        "/usr/bin/podman", "run", "--rm", "--pull=never", "--network=none",
        "--userns=keep-id", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--workdir=/tmp", "--env=HOME=/tmp", "--env=PYTHONNOUSERSITE=1",
        "--mount", "type=tmpfs,dst=/tmp,tmpfs-size=8388608,tmpfs-mode=0700,U=true",
        image, manifest["python"]["executable_path"], "-c", ATOMIC_RENAME_PROBE,
    )
    atomic = subprocess.run(atomic_command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=PODMAN_ENV, cwd="/", timeout=60, check=False)
    require(atomic.returncode == 0, "Python atomic rename probe differs")


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
    chromium = root / manifest["playwright"]["chromium"]["tree"]["path"]
    cache = root / manifest["bun"]["cache"]["path"]
    result = subprocess.run((os.fspath(bun), os.fspath(HERE / "tree_identity.ts"), os.fspath(chromium), os.fspath(cache)), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={**SAFE_ENV, "BUN_INSTALL": os.fspath(root / "bun")}, cwd="/", timeout=120, check=False)
    require(result.returncode == 0 and len(result.stdout) <= MAX_JSON_BYTES, "extended tree identity calculation failed")
    value = json.loads(result.stdout)
    expected_chromium = dict(manifest["playwright"]["chromium"]["tree"])
    expected_chromium.pop("path")
    require(value.get("browser") == expected_chromium, "Chromium tree differs")
    require(value.get("dependencies") == manifest["bun"]["cache"]["tree"], "Bun cache tree differs")


def historical_dependency_sources(manifest: dict[str, Any]) -> None:
    """Bind the cache probe to the exact renderer archive dependency inputs."""
    cache = manifest["bun"]["cache"]
    commit = cache["source_commit"]
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None, "cache source commit differs")
    for name in ("package.json", "bun.lock"):
        result = subprocess.run(
            ("/usr/bin/git", "show", f"{commit}:apps/web/{name}"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=SAFE_ENV,
            cwd=REPOSITORY,
            timeout=30,
            check=False,
        )
        require(result.returncode == 0, f"historical {name} is unavailable")
        require(hashlib.sha256(result.stdout).hexdigest() == manifest["dependencies"]["source"][name], f"historical {name} differs")


def verify(root: Path, image: str | None = None, repo_digest: str | None = None) -> None:
    root = root.absolute()
    metadata = os.lstat(root)
    require(root.resolve() == root and stat.S_ISDIR(metadata.st_mode), "staging root path differs")
    require(metadata.st_uid == os.getuid() and stat.S_IMODE(metadata.st_mode) == 0o700, "staging root privacy differs")
    manifest = strict_json(MANIFEST_PATH)
    require(manifest.get("schema") == "hermternal.issue-397.offline-toolchain-staging/v1" and manifest.get("status") == "authenticated-inputs", "staging manifest differs")
    require(manifest.get("architecture") == "linux/amd64", "staging architecture differs")
    historical_dependency_sources(manifest)
    regular_file(root, manifest["bun"]["archive"]["path"], manifest["bun"]["archive"])
    regular_file(root, manifest["bun"]["binary"]["path"], manifest["bun"]["binary"])
    regular_file(root, manifest["playwright"]["chromium"]["archive"]["path"], manifest["playwright"]["chromium"]["archive"])
    chromium_executable = regular_file(root, manifest["playwright"]["chromium"]["staged_executable_path"], {"bytes": manifest["playwright"]["chromium"]["executable_bytes"], "sha256": manifest["playwright"]["chromium"]["executable_sha256"]})
    executable_metadata = os.lstat(chromium_executable)
    require(executable_metadata.st_uid == manifest["playwright"]["chromium"]["uid"] and executable_metadata.st_gid == manifest["playwright"]["chromium"]["gid"] and stat.S_IMODE(executable_metadata.st_mode) == int(manifest["playwright"]["chromium"]["mode"], 8), "Chromium executable metadata differs")
    browser_archive = regular_file(root, manifest["playwright"]["headless_shell_archive"]["path"], manifest["playwright"]["headless_shell_archive"])
    require(md5(browser_archive) == manifest["playwright"]["headless_shell_archive"]["md5"], "browser archive MD5 differs")
    regular_file(root, manifest["debian"]["inrelease"]["path"], manifest["debian"]["inrelease"])
    regular_file(root, manifest["debian"]["archive_keyring"]["path"], manifest["debian"]["archive_keyring"])
    driver = manifest["dependencies"]["tree_identity_driver"]
    regular_file(root, driver["staged_path"], driver)
    source = manifest["dependencies"]["tree_identity_source"]
    regular_file(root, source["staged_path"], {"bytes": source["staged_bytes"], "sha256": source["sha256"]})
    for name, expected_sha256 in manifest["dependencies"]["source"].items():
        require(sha256(REPOSITORY / "apps/web" / name) == expected_sha256, f"{name} dependency source differs")
    for relative in (manifest["bun"]["binary"]["path"], manifest["playwright"]["headless_shell_tree"]["path"], manifest["dependencies"]["path"], "snapshot/debs"):
        require_epoch_tree(root / relative if relative.endswith("node_modules") or relative.endswith("chrome-headless-shell-linux64") or relative == "snapshot/debs" else (root / relative).parent)
    require_epoch_tree(root / manifest["playwright"]["chromium"]["tree"]["path"])
    require_epoch_tree(root / manifest["bun"]["cache"]["path"])
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
