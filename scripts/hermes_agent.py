#!/usr/bin/env python3
"""Launch disposable official Hermes Agent instances with rootless Podman.

This command is a test-lane helper. It preserves the official image entrypoint,
uses the upstream ``gateway run`` command, and publishes the Dashboard only on
VM loopback. It deliberately does not apply custom capability or resource
policies: frontend tests need normal upstream behavior and the dedicated VM may
use its available resources.
"""

from __future__ import annotations

import argparse
import contextlib
import contextvars
import ctypes
import errno
import json
import math
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Mapping, Sequence


if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
import live_run_marker


DEFAULT_IMAGE = (
    "docker.io/nousresearch/hermes-agent:v2026.8.3@"
    "sha256:16788311e2fa3035456bdc1bafb8ec2b1777db64ebf020af9bb7eb73c3712c9e"
)
# Keep the execution image allowlist source-bound. A caller-provided digest is
# not evidence of trust; every accepted image must be this reviewed tag+digest.
TRUSTED_IMAGE_REPO_DIGESTS = {
    DEFAULT_IMAGE: "docker.io/nousresearch/hermes-agent@"
    "sha256:16788311e2fa3035456bdc1bafb8ec2b1777db64ebf020af9bb7eb73c3712c9e",
}
IMAGE_PATTERN = re.compile(
    r"^docker\.io/nousresearch/hermes-agent:"
    r"(?P<tag>[a-z0-9][a-z0-9._-]{0,127})@sha256:(?P<digest>[0-9a-f]{64})$"
)
INSTANCE_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$")
CONTAINER_PREFIX = "hermternal-hermes-"
MANAGED_LABEL = "io.hermternal.hermes-launcher"
MANAGED_VERSION = "v1"
DASHBOARD_PORT = 9119
DEFAULT_USERNAME = "hermternal-test"
MAX_PROVIDER_BYTES = 64 * 1024
MAX_STATE_BYTES = 16 * 1024
MAX_COMMAND_BYTES = 64 * 1024
CONTAINER_ACTION_TIMEOUT = 60
# A cleanup_failed tombstone may exist even when the engine raised before its
# cidfile was readable. This valid-but-unproven ID is never sent to Podman.
UNPROVEN_CONTAINER_ID = "0" * 64

Runner = Callable[[Sequence[str], Mapping[str, str], float], "CommandResult"]
ReadinessChecker = Callable[[str, int, float], None]
PortChecker = Callable[[int], bool]


FileIdentity = tuple[int, int, int, int, int]
DirectoryIdentity = tuple[int, int, int]
ParentIdentity = tuple[int, int, int]
# A private root must be a caller-specific descendant, never a shared system
# anchor. The minimum component depth below is a second lexical guard; this
# explicit set keeps policy reviewable when a platform exposes more anchors.
_PRIVATE_BROAD_ANCHORS = frozenset(
    {
        Path("/"),
        Path("/tmp"),
        Path("/var"),
        Path("/private/tmp"),
        Path("/private/var"),
        Path("/usr/local"),
    }
)
_RENAME_EXPECTED: contextvars.ContextVar[
    tuple[int, str, str, FileIdentity, str, str | None, int | None] | None
] = contextvars.ContextVar(
    "hermes_rename_expected",
    default=None,
)


@dataclass(frozen=True)
class ParentLease:
    """One operation's held runs directory and entry-time identity."""

    marker_path: Path
    parent_fd: int
    identity: ParentIdentity


_ACTIVE_PARENT_LEASE: contextvars.ContextVar[ParentLease | None] = contextvars.ContextVar(
    "hermes_active_parent_lease",
    default=None,
)


class LauncherError(Exception):
    """One stable failure code that contains no secret or raw engine output."""

    def __init__(
        self,
        code: str,
        *,
        secondary: "LauncherError | None" = None,
        partial_results: Sequence[dict[str, object]] | None = None,
    ) -> None:
        self.code = code
        self.secondary = secondary
        self.partial_results = tuple(partial_results or ())
        super().__init__(code)


class OwnedFileError(LauncherError):
    """A private-file failure that carries only its exact owned identity."""

    def __init__(self, code: str, *, path: Path, identity: FileIdentity) -> None:
        self.path = path
        self.identity = identity
        super().__init__(code)


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True)
class Roots:
    state: Path
    data: Path
    # Retained for CLI compatibility with older callers. Live credentials are
    # marker siblings and never use this root.
    credentials: Path


@dataclass(frozen=True)
class InstanceSpec:
    instance: str
    port: int
    image: str
    username: str
    roots: Roots

    @property
    def container(self) -> str:
        return f"{CONTAINER_PREFIX}{self.instance}"

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def data_dir(self) -> Path:
        return self.roots.data / self.instance

    @property
    def credential_dir(self) -> Path:
        """Legacy compatibility path; live runs use marker siblings."""

        return self.roots.credentials / self.instance

    @property
    def credential_file(self) -> Path:
        """Legacy compatibility path, never used for live credentials."""

        return self.credential_dir / "password"

    @property
    def state_file(self) -> Path:
        return self.roots.state / f"{self.instance}.json"

    def public(self) -> dict[str, object]:
        return {
            "instance": self.instance,
            "container": self.container,
            "endpoint": self.endpoint,
            "image": self.image,
            "data_path": str(self.data_dir),
            "credential_file": str(self.credential_file),
        }


@dataclass(frozen=True)
class RecoverySnapshot:
    """Safe identity projection used immediately around lifecycle mutations."""

    container_id: str
    name: str
    image: str
    data_source: str
    status: str


@dataclass(frozen=True)
class LauncherState:
    """One exact marker plus state record used by lifecycle operations.

    The two file identities and the data-directory identity are captured while
    their records are read. Cleanup receives these immutable snapshots directly;
    it must not reload a pathname and accidentally adopt a replacement inode or
    directory tree.
    """

    spec: InstanceSpec
    marker: live_run_marker.RunMarker
    marker_identity: FileIdentity | None = None
    state_identity: FileIdentity | None = None
    data_identity: DirectoryIdentity | None = None
    marker_generation: str | None = None
    state_generation: str | None = None

    @property
    def container_id(self) -> str:
        return self.marker.container_id

    @property
    def run_id(self) -> str:
        return self.marker.run_id

    @property
    def marker_path(self) -> Path:
        return self.marker.marker_path


def default_roots() -> Roots:
    home = Path.home()
    return Roots(
        state=home / ".local" / "state" / "hermternal" / "hermes-agent",
        data=home / ".local" / "share" / "hermternal-tests" / "hermes-agent",
        credentials=home / ".config" / "hermternal-tests" / "hermes-agent",
    )


def validate_image(image: str) -> tuple[str, str]:
    if type(image) is not str or image not in TRUSTED_IMAGE_REPO_DIGESTS:
        raise LauncherError("image_not_immutable_official")
    match = IMAGE_PATTERN.fullmatch(image)
    if match is None or match.group("tag") == "latest":
        raise LauncherError("image_not_immutable_official")
    return match.group("tag"), f"sha256:{match.group('digest')}"


def validate_instance(instance: str) -> str:
    if type(instance) is not str or INSTANCE_PATTERN.fullmatch(instance) is None:
        raise LauncherError("instance_invalid")
    return instance


def validate_port(port: int) -> int:
    if type(port) is not int or not 1024 <= port <= 65535:
        raise LauncherError("port_invalid")
    return port


def _canonical_private_path(path: Path, *, code: str = "owned_path_invalid") -> Path:
    """Accept only absolute lexical paths before descriptor-bound traversal.

    ``Path.resolve`` and ``abspath`` are deliberately not used here: resolving
    or collapsing ``..`` before checking would let a symlink component disappear
    from the spelling that is later handed to the engine. Darwin's ``/tmp`` and
    ``/var`` aliases, alternate double-slash spellings, and broad anchors are
    rejected before the later ``O_NOFOLLOW`` walk; only sufficiently nested
    canonical private descendants are eligible.
    """

    if not isinstance(path, Path):
        raise LauncherError(code)
    try:
        raw = os.fspath(path)
        if type(raw) is not str or not raw or "\x00" in raw:
            raise LauncherError(code)
        # POSIX permits an implementation-defined double-slash prefix. It is
        # not one of the launcher's canonical spellings and must not bypass the
        # explicit private-root policy through an alternate lexical alias.
        if raw.startswith("//"):
            raise LauncherError(code)
        if not os.path.isabs(raw) or os.path.normpath(raw) != raw:
            raise LauncherError(code)
        canonical = Path(raw)
        # A broad anchor such as /private/tmp, /private/var, or /usr/local is
        # not an owned private directory. Require at least one caller-specific
        # descendant so validation never chmods or treats a shared system root
        # as private.
        if (
            not canonical.is_absolute()
            or canonical in _PRIVATE_BROAD_ANCHORS
            or len(canonical.parts) < 4
        ):
            raise LauncherError(code)
        return canonical
    except LauncherError:
        raise
    except (OSError, TypeError, ValueError):
        raise LauncherError(code) from None


def _validate_private_root_policy(path: Path) -> Path:
    """Reject filesystem/system anchors before any private-directory operation."""

    return _canonical_private_path(path)


def _canonical_roots(roots: Roots) -> Roots:
    if type(roots) is not Roots or any(
        not isinstance(path, Path)
        for path in (roots.state, roots.data, roots.credentials)
    ):
        raise LauncherError("instance_spec_invalid")
    return Roots(
        state=_canonical_private_path(roots.state),
        data=_validate_private_root_policy(roots.data),
        credentials=_canonical_private_path(roots.credentials),
    )


def make_spec(
    instance: str,
    port: int,
    *,
    image: str = DEFAULT_IMAGE,
    username: str = DEFAULT_USERNAME,
    roots: Roots | None = None,
) -> InstanceSpec:
    validate_instance(instance)
    validate_port(port)
    validate_image(image)
    try:
        username_bytes = len(username.encode("utf-8"))
    except (AttributeError, UnicodeEncodeError):
        raise LauncherError("username_invalid") from None
    if not username or username_bytes > 128 or any(ord(char) < 0x20 for char in username):
        raise LauncherError("username_invalid")
    canonical_roots = _canonical_roots(roots if roots is not None else default_roots())
    return InstanceSpec(instance, port, image, username, canonical_roots)


def _validate_start_spec(spec: InstanceSpec) -> None:
    """Validate caller-provided spec scalars before acquiring a lifecycle lease."""

    if type(spec) is not InstanceSpec:
        raise LauncherError("instance_spec_invalid")
    if type(spec.roots) is not Roots or any(
        not isinstance(path, Path)
        for path in (spec.roots.state, spec.roots.data, spec.roots.credentials)
    ):
        raise LauncherError("instance_spec_invalid")
    # Reuse the constructor's strict scalar and canonical-root checks without
    # touching the filesystem. This keeps direct callers from bypassing CLI
    # validation before marker, Podman, or data-root work begins.
    make_spec(
        spec.instance,
        spec.port,
        image=spec.image,
        username=spec.username,
        roots=spec.roots,
    )


def clean_environment(source: Mapping[str, str] | None = None) -> dict[str, str]:
    values = dict(os.environ if source is None else source)
    if values.get("CONTAINER_HOST") or values.get("CONTAINER_CONNECTION"):
        raise LauncherError("remote_podman_rejected")
    blocked_exact = {
        "CONTAINER_HOST",
        "CONTAINER_CONNECTION",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
        "COMPOSE_FILE",
        "COMPOSE_PROJECT_NAME",
        "COMPOSE_PROFILES",
        "HERMES_PROVIDER",
        "HERMES_PROVIDER_NAME",
        "HERMES_PROVIDER_URL",
        "HERMES_PROVIDER_CONFIG",
    }
    for name in tuple(values):
        upper = name.upper()
        if (
            upper in blocked_exact
            or upper.startswith("DOCKER_")
            or upper.startswith("COMPOSE_")
            or upper.startswith("HERMES_PROVIDER_")
            or upper.endswith("_API_KEY")
            or upper.endswith("_API_TOKEN")
            or upper.endswith("_ACCESS_TOKEN")
        ):
            values.pop(name, None)
    return values


def _validate_command_vector(command: Sequence[str]) -> tuple[str, ...]:
    """Reject malformed subprocess argv before the process boundary."""

    if isinstance(command, (str, bytes)) or not isinstance(command, Sequence):
        raise LauncherError("command_invalid")
    try:
        values = tuple(command)
    except (MemoryError, TypeError, ValueError):
        raise LauncherError("command_invalid") from None
    if not values:
        raise LauncherError("command_invalid")
    for index, value in enumerate(values):
        if type(value) is not str or not value or "\x00" in value:
            raise LauncherError("executable_invalid" if index == 0 else "command_invalid")
    return values


def _bounded_text(raw: bytes) -> str:
    return raw[:MAX_COMMAND_BYTES].decode("utf-8", errors="replace")


def run_command(command: Sequence[str], environment: Mapping[str, str], timeout: float) -> CommandResult:
    values = _validate_command_vector(command)
    try:
        completed = subprocess.run(
            list(values),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=dict(environment),
            timeout=timeout,
        )
    except (OSError, ValueError, subprocess.TimeoutExpired):
        # ``subprocess`` raises ``ValueError`` for malformed command strings,
        # including embedded NULs. Keep that adapter boundary bounded and
        # secret-free instead of leaking Python's raw exception text.
        return CommandResult(124, "")
    return CommandResult(completed.returncode, _bounded_text(completed.stdout))


def _attach_secondary_failure(primary: BaseException, secondary: BaseException) -> None:
    """Preserve cleanup/revalidation failures without replacing the primary error."""

    if isinstance(secondary, live_run_marker.MarkerError):
        normalized = LauncherError(secondary.code)
    elif isinstance(secondary, LauncherError):
        normalized = secondary
    else:
        normalized = LauncherError("runs_dir_replaced")
    if isinstance(primary, LauncherError):
        primary.secondary = normalized
    else:
        try:
            setattr(primary, "secondary", normalized)
        except Exception:
            pass


def _revalidate_active_parent() -> None:
    lease = _ACTIVE_PARENT_LEASE.get()
    if lease is not None:
        _revalidate_private_parent_path(
            lease.marker_path,
            lease.parent_fd,
            expected=lease.identity,
            code="runs_dir",
        )


def _validate_command_result(result: object, *, failure_code: str) -> CommandResult:
    """Normalize every untrusted runner result before any caller reads it."""

    # Reject subclasses before touching fields: an injected adapter can expose
    # properties that raise or change between reads, while the exact dataclass
    # has only ordinary immutable fields. Return a base snapshot so callers do
    # not retain an adapter-owned object after this boundary.
    if type(result) is not CommandResult:
        raise LauncherError(failure_code)
    try:
        returncode = result.returncode
        stdout = result.stdout
        stderr = result.stderr
        if type(returncode) is not int or not -255 <= returncode <= 255:
            raise LauncherError(failure_code)
        for output in (stdout, stderr):
            if type(output) is not str or len(output.encode("utf-8")) > MAX_COMMAND_BYTES:
                raise LauncherError(failure_code)
    except LauncherError:
        raise
    except (AttributeError, MemoryError, UnicodeEncodeError, ValueError):
        raise LauncherError(failure_code) from None
    return CommandResult(returncode, stdout, stderr)


def invoke_runner(
    runner: Runner,
    command: Sequence[str],
    environment: Mapping[str, str],
    timeout: float,
    *,
    failure_code: str,
    private_path: Path | None = None,
    private_identity: DirectoryIdentity | None = None,
) -> CommandResult:
    """Treat every injected engine boundary as an untrusted bounded call.

    Podman accepts a pathname rather than a held directory descriptor. Callers
    that dispatch a bind therefore pass the descriptor snapshot for an
    immediate pre/post pathname identity check; a replacement becomes a
    bounded launcher failure instead of silently changing the host tree.
    """

    _revalidate_active_parent()
    if private_path is not None or private_identity is not None:
        if private_path is None or private_identity is None:
            raise LauncherError(failure_code)
        _revalidate_private_directory_identity(private_path, private_identity)
    try:
        result = runner(command, environment, timeout)
    except BaseException:
        # Recheck even when the adapter raises: a runner can replace the
        # private parent after creating a resource and before reporting error.
        try:
            _revalidate_active_parent()
            if private_path is not None and private_identity is not None:
                _revalidate_private_directory_identity(private_path, private_identity)
        except BaseException as secondary:
            primary = LauncherError(failure_code)
            _attach_secondary_failure(primary, secondary)
            raise primary from None
        raise LauncherError(failure_code) from None
    _revalidate_active_parent()
    if private_path is not None and private_identity is not None:
        _revalidate_private_directory_identity(private_path, private_identity)
    return _validate_command_result(result, failure_code=failure_code)


def podman_path() -> str:
    executable = shutil.which("podman")
    if executable is None or not os.path.isabs(executable):
        raise LauncherError("podman_unavailable")
    return executable


def podman_preflight(runner: Runner, environment: Mapping[str, str], executable: str) -> None:
    result = invoke_runner(
        runner,
        (executable, "info", "--format", "{{.Host.Security.Rootless}}"),
        environment,
        15,
        failure_code="podman_preflight_failed",
    )
    if result.returncode != 0 or result.stdout.strip() != "true":
        raise LauncherError("rootless_podman_required")


def expected_repo_digest(image: str) -> str:
    validate_image(image)
    return TRUSTED_IMAGE_REPO_DIGESTS[image]


def verify_image(
    image: str,
    runner: Runner,
    environment: Mapping[str, str],
    executable: str,
) -> None:
    # Keep direct callers fail-closed too; no pull is evidence of trust.
    validate_image(image)
    pulled = invoke_runner(
        runner,
        (executable, "pull", image),
        environment,
        300,
        failure_code="image_pull_failed",
    )
    if pulled.returncode != 0:
        raise LauncherError("image_pull_failed")
    inspected = invoke_runner(
        runner,
        (executable, "image", "inspect", image, "--format", "json"),
        environment,
        30,
        failure_code="image_inspect_failed",
    )
    if inspected.returncode != 0:
        raise LauncherError("image_inspect_failed")
    try:
        document = json.loads(inspected.stdout)
        if not isinstance(document, list) or len(document) != 1 or not isinstance(document[0], dict):
            raise ValueError
        repo_digests = document[0].get("RepoDigests")
        if not isinstance(repo_digests, list) or any(type(value) is not str for value in repo_digests):
            raise ValueError
    except (json.JSONDecodeError, ValueError):
        raise LauncherError("image_inspect_invalid") from None
    if expected_repo_digest(image) not in repo_digests:
        raise LauncherError("image_digest_mismatch")


def is_port_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def _required_private_flag(name: str) -> int:
    value = getattr(os, name, None)
    if type(value) is not int or value <= 0:
        raise LauncherError("owned_path_invalid")
    return value


def _private_directory_flags() -> int:
    nofollow = _required_private_flag("O_NOFOLLOW")
    directory = _required_private_flag("O_DIRECTORY")
    _required_private_flag("O_CLOEXEC")
    supports_dir_fd = getattr(os, "supports_dir_fd", ())
    supports_follow_symlinks = getattr(os, "supports_follow_symlinks", ())
    if (
        os.open not in supports_dir_fd
        or os.mkdir not in supports_dir_fd
        or os.stat not in supports_dir_fd
        or os.stat not in supports_follow_symlinks
        or not hasattr(os, "fchmod")
    ):
        # A lexical lstat/mkdir fallback is not equivalent: a same-user writer
        # can replace an ancestor between those operations. Fail closed on
        # platforms that cannot hold, compare, and mutate descriptor-bound
        # directories. Cleanup does not require ``os.rmdir`` support: Python
        # exposes no descriptor-atomic exact-directory deletion operation, so
        # failed-create cleanup preserves the leaf and reports bounded evidence.
        raise LauncherError("owned_path_invalid")
    return os.O_RDONLY | directory | nofollow | _required_private_flag("O_CLOEXEC")


def _close_fd_best_effort(descriptor: int) -> LauncherError | None:
    """Close one owned fd with bounded retry and report persistent failure."""

    for _ in range(3):
        try:
            os.close(descriptor)
            return None
        except OSError:
            continue
    return LauncherError("descriptor_close_failed")


def _directory_identity(descriptor: int, *, code: str) -> DirectoryIdentity:
    try:
        info = os.fstat(descriptor)
    except OSError:
        raise LauncherError(code) from None
    if not stat.S_ISDIR(info.st_mode):
        raise LauncherError(code)
    return (info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode))


def _directory_entry_identity(parent_fd: int, name: str, *, code: str) -> DirectoryIdentity:
    """Stat one child through its held parent without following a symlink."""

    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        raise LauncherError(code) from None
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise LauncherError(code)
    return (info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode))


@contextlib.contextmanager
def _private_directory_walk(path: Path, *, create: bool):
    """Walk one canonical directory through held no-follow descriptors.

    The stack retains every descriptor until the walk exits, including when a
    child open or close fails. Newly created components retain their exact
    descriptor identity; failed-create cleanup rechecks the entry but does not
    issue a racy name-based directory removal because Python exposes no
    descriptor-atomic ``unlinkat(AT_REMOVEDIR)`` primitive. A replacement is
    preserved and reported as bounded secondary cleanup evidence, never deleted
    by pathname.
    """

    canonical = _canonical_private_path(path)
    flags = _private_directory_flags()
    created: list[tuple[int, str, DirectoryIdentity]] = []
    close_failures: list[LauncherError] = []
    succeeded = False

    def close_descriptor(descriptor: int) -> None:
        failure = _close_fd_best_effort(descriptor)
        if failure is not None:
            close_failures.append(failure)

    with contextlib.ExitStack() as stack:
        primary_error: BaseException | None = None
        try:
            descriptor = os.open(canonical.anchor, flags)
            stack.callback(close_descriptor, descriptor)
            current = descriptor
            final: int | None = descriptor
            for component in canonical.parts[1:]:
                created_here = False
                try:
                    child = os.open(component, flags, dir_fd=current)
                except FileNotFoundError:
                    if not create:
                        final = None
                        break
                    try:
                        os.mkdir(component, mode=0o700, dir_fd=current)
                    except FileExistsError:
                        # The entry was absent for openat but appeared before
                        # mkdirat completed. Never adopt a pre-existing or raced
                        # directory as if this invocation created it.
                        raise LauncherError("owned_path_replaced") from None
                    except OSError:
                        raise LauncherError("owned_path_invalid") from None
                    created_here = True
                    try:
                        # Open the new entry before inspecting its pathname. A
                        # replacement after mkdir is then compared with the held
                        # original fd instead of becoming the recorded identity.
                        child = os.open(component, flags, dir_fd=current)
                    except OSError:
                        raise LauncherError("owned_path_invalid") from None
                except (OSError, TypeError, ValueError):
                    raise LauncherError("owned_path_invalid") from None
                stack.callback(close_descriptor, child)
                _after_private_directory_open(current, component, child, created_here)
                opened_identity = _directory_identity(child, code="owned_path_invalid")
                entry_identity = _directory_entry_identity(
                    current,
                    component,
                    code="owned_path_replaced",
                )
                if created_here:
                    # Keep the held creation identity even when the pathname
                    # comparison fails, so failed-create cleanup can prove a
                    # replacement and report bounded secondary evidence without
                    # deleting it.
                    created.append((current, component, opened_identity))
                if opened_identity != entry_identity:
                    raise LauncherError("owned_path_replaced")
                current = child
                final = child
            yield canonical, final, tuple(created)
            succeeded = True
        except BaseException as error:
            primary_error = error

        if primary_error is not None:
            try:
                if not succeeded and create:
                    cleanup_error: LauncherError | None = None
                    for parent_fd, component, expected_identity in reversed(created):
                        try:
                            current_identity = _directory_entry_identity(
                                parent_fd,
                                component,
                                code="owned_path_cleanup_failed",
                            )
                            if current_identity != expected_identity:
                                cleanup_error = LauncherError("owned_path_cleanup_failed")
                                continue
                            # Python has no descriptor-atomic exact-directory
                            # deletion operation here. A final identity check
                            # cannot make a pathname syscall atomic: a same-name
                            # replacement could arrive inside os.rmdir and be
                            # deleted. Preserve the created entry and report
                            # bounded cleanup evidence instead of entering that
                            # unprovable deletion boundary.
                            _before_private_directory_rmdir(parent_fd, component, expected_identity)
                            final_identity = _directory_entry_identity(
                                parent_fd,
                                component,
                                code="owned_path_cleanup_failed",
                            )
                            if final_identity != expected_identity:
                                cleanup_error = LauncherError("owned_path_cleanup_failed")
                                continue
                            cleanup_error = LauncherError("owned_path_cleanup_failed")
                        except OSError:
                            cleanup_error = LauncherError("owned_path_cleanup_failed")
                        except LauncherError as cleanup:
                            cleanup_error = cleanup
                    if cleanup_error is not None:
                        _attach_secondary_failure(primary_error, cleanup_error)
            except BaseException as cleanup:
                _attach_secondary_failure(primary_error, cleanup)
            finally:
                # Close callbacks before re-raising so persistent descriptor
                # failures can be attached to the primary lifecycle error.
                stack.close()
            if close_failures:
                _attach_secondary_failure(primary_error, close_failures[0])
            raise primary_error

        stack.close()
        if close_failures:
            raise close_failures[0]


def _validate_private_directory_path(path: Path) -> Path:
    """Reject broad, noncanonical, symlinked, or non-directory ancestors."""

    with _private_directory_walk(path, create=False) as (canonical, _final, _created):
        return canonical


def _revalidate_private_directory_identity(path: Path, expected: DirectoryIdentity) -> Path:
    """Require the canonical pathname to still name the opened directory."""

    try:
        with _private_directory_walk(path, create=False) as (canonical, final, _created):
            if final is None or _directory_identity(final, code="owned_path_replaced") != expected:
                raise LauncherError("owned_path_replaced")
            return canonical
    except LauncherError as error:
        if error.code in {"owned_path_replaced", "descriptor_close_failed"}:
            raise
        raise LauncherError("owned_path_replaced") from None


def _ensure_private_directory_with_identity(path: Path) -> tuple[Path, DirectoryIdentity]:
    """Create/open one private leaf without pathname mkdir/chmod races."""

    with _private_directory_walk(path, create=True) as (canonical, final, _created):
        if final is None:
            raise LauncherError("owned_path_invalid")
        try:
            os.fchmod(final, 0o700)
        except OSError:
            raise LauncherError("owned_path_invalid") from None
        identity = _directory_identity(final, code="owned_path_invalid")
        if identity[2] != 0o700:
            raise LauncherError("owned_path_invalid")
        # The pathname may have been swapped while mkdir was in progress. The
        # descriptor remains safe, but do not hand a detached or replaced path
        # to Podman; fail before any engine bind/start boundary.
        _revalidate_private_directory_identity(canonical, identity)
        return canonical, identity


@contextlib.contextmanager
def _private_child_directory(
    parent_path: Path,
    parent_fd: int,
    parent_identity: DirectoryIdentity,
    child_path: Path,
):
    """Create one data leaf relative to a retained, identity-pinned parent.

    The engine receives ``child_path`` later as a pathname, so creation must be
    relative to the held data-root descriptor and the root pathname must be
    checked again before and after the child boundary. A replacement root can
    therefore never redirect this invocation's child creation. Failed cleanup
    preserves the child because Python exposes no descriptor-atomic exact
    directory deletion equivalent to ``unlinkat(AT_REMOVEDIR)``; this adapter
    never attempts a pathname ``rmdir`` after an identity check.
    """

    if child_path.parent != parent_path or child_path.name in {"", ".", ".."}:
        raise LauncherError("owned_path_invalid")
    flags = _private_directory_flags()
    if _parent_identity(parent_fd, code="owned_path_invalid") != parent_identity:
        raise LauncherError("owned_path_replaced")
    child_fd = -1
    created = False
    created_identity: DirectoryIdentity | None = None
    primary_error: BaseException | None = None
    try:
        # Revalidate both the held descriptor and its lexical parent immediately
        # before the relative open/mkdir boundary.
        _revalidate_private_directory_identity(parent_path, parent_identity)
        try:
            child_fd = os.open(child_path.name, flags, dir_fd=parent_fd)
        except FileNotFoundError:
            try:
                os.mkdir(child_path.name, mode=0o700, dir_fd=parent_fd)
            except FileExistsError:
                # The entry appeared between openat and mkdirat. Never adopt it
                # as the child created by this transaction.
                raise LauncherError("owned_path_replaced") from None
            except OSError:
                raise LauncherError("owned_path_invalid") from None
            created = True
            try:
                child_fd = os.open(child_path.name, flags, dir_fd=parent_fd)
            except OSError:
                raise LauncherError("owned_path_invalid") from None
        except (OSError, TypeError, ValueError):
            raise LauncherError("owned_path_invalid") from None
        _after_private_directory_open(parent_fd, child_path.name, child_fd, created)
        opened_identity = _directory_identity(child_fd, code="owned_path_invalid")
        if created:
            created_identity = opened_identity
        entry_identity = _directory_entry_identity(
            parent_fd,
            child_path.name,
            code="owned_path_replaced",
        )
        if opened_identity != entry_identity:
            raise LauncherError("owned_path_replaced")
        try:
            os.fchmod(child_fd, 0o700)
        except OSError:
            raise LauncherError("owned_path_invalid") from None
        identity = _directory_identity(child_fd, code="owned_path_invalid")
        if identity[2] != 0o700:
            raise LauncherError("owned_path_invalid")
        if _parent_identity(parent_fd, code="owned_path_invalid") != parent_identity:
            raise LauncherError("owned_path_replaced")
        _revalidate_private_directory_identity(parent_path, parent_identity)
        _revalidate_private_directory_identity(child_path, identity)
        yield child_path, identity
    except BaseException as error:
        primary_error = error
        if created:
            cleanup_error: LauncherError | None = None
            try:
                current_identity = _directory_entry_identity(
                    parent_fd,
                    child_path.name,
                    code="owned_path_cleanup_failed",
                )
                if created_identity is not None and current_identity == created_identity:
                    # The final comparison is useful evidence, but it cannot
                    # make the pathname-based rmdir atomic. Preserve the child
                    # rather than risk deleting a same-name replacement that
                    # arrives inside os.rmdir.
                    _before_private_directory_rmdir(parent_fd, child_path.name, current_identity)
                    final_identity = _directory_entry_identity(
                        parent_fd,
                        child_path.name,
                        code="owned_path_cleanup_failed",
                    )
                    cleanup_error = LauncherError("owned_path_cleanup_failed")
                    if final_identity != current_identity:
                        cleanup_error = LauncherError("owned_path_cleanup_failed")
                else:
                    cleanup_error = LauncherError("owned_path_cleanup_failed")
            except (OSError, LauncherError):
                cleanup_error = LauncherError("owned_path_cleanup_failed")
            if cleanup_error is not None:
                _attach_secondary_failure(primary_error, cleanup_error)
        raise
    finally:
        if child_fd >= 0:
            close_failure = _close_fd_best_effort(child_fd)
            if close_failure is not None:
                if primary_error is not None:
                    _attach_secondary_failure(primary_error, close_failure)
                else:
                    raise close_failure


def _ensure_private_data_directory_with_parent(
    root_path: Path,
    child_path: Path,
) -> tuple[Path, DirectoryIdentity]:
    """Securely create/open a data leaf beneath a retained data-root fd."""

    if child_path.parent != root_path:
        raise LauncherError("owned_path_invalid")
    with _private_directory_walk(root_path, create=True) as (_root, root_fd, _created):
        if root_fd is None:
            raise LauncherError("owned_path_invalid")
        try:
            os.fchmod(root_fd, 0o700)
        except OSError:
            raise LauncherError("owned_path_invalid") from None
        root_identity = _directory_identity(root_fd, code="owned_path_invalid")
        if root_identity[2] != 0o700:
            raise LauncherError("owned_path_invalid")
        _revalidate_private_directory_identity(root_path, root_identity)
        with _private_child_directory(root_path, root_fd, root_identity, child_path) as result:
            return result


def _ensure_private_directory(path: Path) -> Path:
    canonical, _identity = _ensure_private_directory_with_identity(path)
    return canonical


def _current_private_directory_identity(path: Path) -> DirectoryIdentity:
    """Capture one private directory identity through the secure walk."""

    with _private_directory_walk(path, create=False) as (_canonical, final, _created):
        if final is None:
            raise LauncherError("owned_path_invalid")
        return _directory_identity(final, code="owned_path_invalid")


def _directory_identity_document(identity: DirectoryIdentity) -> dict[str, int]:
    return {
        "device": identity[0],
        "inode": identity[1],
        "mode": identity[2],
    }


def _directory_identity_from_document(value: object) -> DirectoryIdentity:
    if not isinstance(value, dict) or set(value) != {"device", "inode", "mode"}:
        raise LauncherError("instance_state_invalid")
    values = tuple(value[key] for key in ("device", "inode", "mode"))
    if any(type(item) is not int or item < 0 for item in values):
        raise LauncherError("instance_state_invalid")
    identity = values  # type: ignore[assignment]
    if identity[2] != 0o700:
        raise LauncherError("instance_state_invalid")
    return identity


STATE_SCHEMA = "hermternal.live-run-state.v1"
STATE_KEYS = frozenset(
    {
        "schema",
        "status",
        "marker_path",
        "run_id",
        "instance",
        "container_id",
        "container_name",
        "image",
        "endpoint",
        "state_path",
        "credential_path",
        "credential_identity",
        "username",
        "data_path",
        "data_identity",
    }
)


def _marker_paths(marker_path: str | Path) -> live_run_marker.MarkerPaths:
    try:
        return live_run_marker.marker_paths(marker_path, validate_parent=False)
    except live_run_marker.MarkerError as error:
        raise LauncherError(error.code) from None


def _write_all(descriptor: int, content: bytes, code: str) -> None:
    view = memoryview(content)
    while view:
        try:
            written = os.write(descriptor, view)
        except OSError:
            raise LauncherError(code) from None
        if written <= 0:
            raise LauncherError(code)
        view = view[written:]


def _sync_parent(path: Path, code: str, *, parent_fd: int | None = None) -> None:
    """Sync only the directory descriptor already held by the operation."""

    del path
    if parent_fd is None:
        raise LauncherError(code)
    try:
        os.fsync(parent_fd)
    except OSError:
        raise LauncherError(code) from None


def _private_file_identity_from_stat(info: os.stat_result) -> FileIdentity:
    return (info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode), info.st_size, info.st_nlink)


def _fd_file_identity(descriptor: int) -> FileIdentity:
    return _private_file_identity_from_stat(os.fstat(descriptor))


def _best_effort_fd_identity(descriptor: int) -> FileIdentity | None:
    try:
        return _fd_file_identity(descriptor)
    except OSError:
        return None


def _before_rename_syscall(parent_fd: int, source_name: str, target_name: str) -> None:
    """Deterministic boundary immediately before quarantine rename."""

    del parent_fd, source_name, target_name


def _after_private_directory_open(
    parent_fd: int,
    component: str,
    descriptor: int,
    created: bool,
) -> None:
    """Deterministic boundary after opening a private directory component."""

    del parent_fd, component, descriptor, created


def _before_private_directory_rmdir(
    parent_fd: int,
    component: str,
    expected_identity: DirectoryIdentity,
) -> None:
    """Deterministic boundary before fail-closed created-directory cleanup.

    The hook exists for race regressions. The production path performs a final
    descriptor-relative identity check and then preserves the entry because
    pathname ``os.rmdir`` is not atomic with that check on this adapter.
    """

    del parent_fd, component, expected_identity


def _before_public_return(operation: str) -> None:
    """Deterministic boundary before a successful public lifecycle return."""

    del operation


def _before_stop_evidence_cleanup() -> None:
    """Deterministic boundary before stop erases launcher-owned evidence."""



def _rename_noreplace(parent_fd: int, source_name: str, target_name: str) -> None:
    """Atomically claim one directory entry without replacing its destination."""

    source = os.fsencode(source_name)
    target = os.fsencode(target_name)
    expected_claim = _RENAME_EXPECTED.get()
    if expected_claim is not None:
        (
            expected_parent,
            expected_source,
            expected_target,
            expected_identity,
            expected_code,
            expected_generation,
            generation_maximum,
        ) = expected_claim
        if (expected_parent, expected_source, expected_target) == (parent_fd, source_name, target_name):
            descriptor = -1
            try:
                descriptor = os.open(
                    source_name,
                    os.O_RDONLY
                    | _required_private_flag("O_NOFOLLOW")
                    | _required_private_flag("O_NONBLOCK")
                    | _required_private_flag("O_CLOEXEC"),
                    dir_fd=parent_fd,
                )
                current = _validated_fd_identity(descriptor, code=expected_code)
                if current != expected_identity:
                    raise LauncherError(f"{expected_code}_replaced")
                if expected_generation is not None and generation_maximum is not None:
                    _require_descriptor_generation(
                        descriptor,
                        expected_generation,
                        maximum=generation_maximum,
                        replacement_code=f"{expected_code}_replaced",
                    )
            except FileNotFoundError:
                pass
            finally:
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
        _before_rename_syscall(parent_fd, source_name, target_name)
        descriptor = -1
        try:
            descriptor = os.open(
                source_name,
                os.O_RDONLY
                | _required_private_flag("O_NOFOLLOW")
                | _required_private_flag("O_NONBLOCK")
                | _required_private_flag("O_CLOEXEC"),
                dir_fd=parent_fd,
            )
            current = _validated_fd_identity(descriptor, code=expected_code)
            if current != expected_identity:
                raise LauncherError(f"{expected_code}_replaced")
            if expected_generation is not None and generation_maximum is not None:
                _require_descriptor_generation(
                    descriptor,
                    expected_generation,
                    maximum=generation_maximum,
                    replacement_code=f"{expected_code}_replaced",
                )
        except FileNotFoundError:
            raise LauncherError(f"{expected_code}_replaced") from None
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin" and hasattr(libc, "renameatx_np"):
        operation = libc.renameatx_np
        operation.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        operation.restype = ctypes.c_int
        result = operation(parent_fd, source, parent_fd, target, 0x00000004)
    elif hasattr(libc, "renameat2"):
        operation = libc.renameat2
        operation.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        operation.restype = ctypes.c_int
        result = operation(parent_fd, source, parent_fd, target, 0x00000001)
    else:
        raise LauncherError("atomic_quarantine_unavailable")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        raise LauncherError("quarantine_exists")
    if error_number == errno.ENOENT:
        raise LauncherError("file_missing")
    raise LauncherError("atomic_quarantine_failed")


def _best_effort_remove_owned_file(path: Path, identity: FileIdentity) -> None:
    """Remove only an exact private inode; never delete a replacement."""

    try:
        _remove_exact_file(
            path,
            code="owned_file_remove_failed",
            expected=identity,
            missing_ok=True,
        )
    except BaseException:
        return


def _create_private_file(
    path: Path,
    content: bytes,
    *,
    code: str,
    parent_fd: int | None = None,
) -> FileIdentity:
    # Keep the validated parent fd for create, sync, and close; a pathname
    # parent can otherwise be replaced between the file write and fsync. A
    # caller may hold one lease across the full marker transaction.
    owns_parent = parent_fd is None
    if parent_fd is None:
        parent_fd = _open_private_parent(path, code=code)
    else:
        _validate_private_parent_fd(parent_fd, code=code)
    descriptor = -1
    identity: FileIdentity | None = None
    try:
        try:
            descriptor = os.open(
                path.name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | _required_private_flag("O_NOFOLLOW")
                | _required_private_flag("O_CLOEXEC"),
                0o600,
                dir_fd=parent_fd,
            )
        except FileExistsError:
            raise LauncherError(f"{code}_exists") from None
        except OSError:
            raise LauncherError(code) from None

        try:
            identity = _fd_file_identity(descriptor)
            _write_all(descriptor, content, code)
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            identity = _fd_file_identity(descriptor)
        except (LauncherError, OSError) as error:
            identity = _best_effort_fd_identity(descriptor) or identity
            if identity is not None:
                failure_code = error.code if isinstance(error, LauncherError) else code
                raise OwnedFileError(failure_code, path=path, identity=identity) from None
            if isinstance(error, LauncherError):
                raise
            raise LauncherError(code) from None

        try:
            os.close(descriptor)
        except OSError:
            descriptor = -1
            raise OwnedFileError(f"{code}_close_failed", path=path, identity=identity) from None
        descriptor = -1
        try:
            _sync_parent(path, code.replace("write", "sync"), parent_fd=parent_fd)
        except (LauncherError, OSError):
            assert identity is not None
            raise OwnedFileError(code.replace("write", "sync"), path=path, identity=identity) from None
        assert identity is not None
        return identity
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if owns_parent:
            try:
                os.close(parent_fd)
            except OSError:
                pass


def _read_private_file_record(
    path: Path,
    *,
    maximum: int,
    code: str,
    parent_fd: int | None = None,
) -> tuple[bytes, FileIdentity]:
    """Read one private record through a held parent and entry descriptor."""

    owns_parent = parent_fd is None
    if parent_fd is None:
        parent_fd = _open_private_parent(path, code=code)
    else:
        _validate_private_parent_fd(parent_fd, code=code)
    descriptor = -1
    try:
        try:
            descriptor = os.open(
                path.name,
                os.O_RDONLY
                | _required_private_flag("O_NOFOLLOW")
                | _required_private_flag("O_NONBLOCK")
                | _required_private_flag("O_CLOEXEC"),
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            raise LauncherError(f"{code}_missing") from None
        except OSError:
            raise LauncherError(code) from None
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size > maximum
        ):
            raise LauncherError(code)
        raw = bytearray()
        while len(raw) <= maximum:
            chunk = os.read(descriptor, maximum + 1 - len(raw))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        before_identity = _private_file_identity_from_stat(before)
        after_identity = _private_file_identity_from_stat(after)
        if before_identity != after_identity:
            raise LauncherError(f"{code}_replaced")
        if len(raw) > maximum:
            raise LauncherError(f"{code}_oversized")
        return bytes(raw), after_identity
    except OSError:
        raise LauncherError(code) from None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if owns_parent:
            try:
                os.close(parent_fd)
            except OSError:
                pass


def _read_private_file(path: Path, *, maximum: int, code: str) -> bytes:
    raw, _ = _read_private_file_record(path, maximum=maximum, code=code)
    return raw


def create_run_credential(
    marker_path: str | Path,
    *,
    parent_fd: int | None = None,
) -> tuple[str, live_run_marker.CredentialIdentity]:
    """Create one fresh run-scoped credential with exclusive creation."""

    paths = _marker_paths(marker_path)
    password = secrets.token_hex(24)
    try:
        created_identity = _create_private_file(
            paths.credential,
            (password + "\n").encode("ascii"),
            code="credential_file_write_failed",
            parent_fd=parent_fd,
        )
    except OwnedFileError:
        raise
    identity = live_run_marker.CredentialIdentity(
        created_identity[0],
        created_identity[1],
        created_identity[2],
        created_identity[3],
        created_identity[4],
        live_run_marker.content_generation((password + "\n").encode("ascii")),
    )
    return password, identity


def read_or_create_password(spec: InstanceSpec, *, marker_path: str | Path | None = None) -> str:
    """Compatibility name retained for callers; every new run is exclusive."""

    del spec
    if marker_path is None:
        raise LauncherError("marker_required")
    password, _ = create_run_credential(marker_path)
    return password


def validate_container_id(value: object) -> str:
    """Accept only Podman's immutable hexadecimal container identity."""

    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{12,64}", value) is None:
        raise LauncherError("instance_state_invalid")
    return value


def container_id_from_run_result(result: CommandResult) -> str:
    """Parse only the one immutable ID emitted by this exact detached run."""

    if result.returncode != 0:
        raise LauncherError("container_start_failed")
    raw = result.stdout
    candidate = raw.rstrip("\r\n")
    if not candidate or raw not in {candidate, candidate + "\n", candidate + "\r\n"}:
        raise LauncherError("container_id_unproven")
    try:
        return validate_container_id(candidate)
    except LauncherError:
        raise LauncherError("container_id_unproven") from None


def state_document(
    spec: InstanceSpec,
    binding: live_run_marker.RunMarker,
    *,
    data_identity: DirectoryIdentity | None = None,
) -> dict[str, object]:
    """Serialize state with the exact data directory identity.

    Lifecycle callers pass the identity captured before their engine boundary.
    The optional recapture is retained only for standalone compatibility helpers;
    recovery code must never use it in place of persisted state evidence.
    """

    if data_identity is None:
        data_identity = _current_private_directory_identity(spec.data_dir)
    if binding.data_identity is not None and binding.data_identity != data_identity:
        # The marker is an independently retained lifecycle witness. A state
        # record may not authorize a different data tree by rewriting its own
        # identity document.
        raise LauncherError("instance_state_binding_mismatch")
    return {
        "schema": STATE_SCHEMA,
        "status": binding.status,
        "marker_path": str(binding.marker_path),
        "run_id": binding.run_id,
        "instance": spec.instance,
        "container_id": validate_container_id(binding.container_id),
        "container_name": binding.container_name,
        "image": binding.image,
        "endpoint": binding.endpoint,
        "state_path": str(binding.state_path),
        "credential_path": str(binding.credential_path),
        "credential_identity": binding.credential_identity.document(),
        "username": spec.username,
        "data_path": str(spec.data_dir),
        "data_identity": _directory_identity_document(data_identity),
    }


def write_state(
    spec: InstanceSpec,
    binding: live_run_marker.RunMarker,
    *,
    replace: bool = False,
    expected: FileIdentity | None = None,
    expected_generation: str | None = None,
    parent_fd: int | None = None,
    data_identity: DirectoryIdentity | None = None,
) -> FileIdentity:
    # Every lifecycle caller supplies ``data_identity`` from its trusted
    # snapshot. ``state_document`` retains a compatibility fallback for direct
    # fixture helpers, but recovery never recaptures a replacement pathname.
    paths = _marker_paths(binding.marker_path)
    if binding.state_path != paths.state:
        raise LauncherError("state_path_invalid")
    content = (
        json.dumps(
            state_document(spec, binding, data_identity=data_identity),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    if len(content) > MAX_STATE_BYTES:
        raise LauncherError("instance_state_too_large")
    if replace:
        if expected is None:
            expected = _file_identity(paths.state, code="state_write_failed")
        # Remove only the caller-pinned inode, then publish with O_EXCL. A
        # replacement that appears in the gap makes publication fail closed;
        # it is never overwritten by an os.replace pathname race. The content
        # generation closes the same-inode, same-size mutation window before
        # the old state is claimed.
        try:
            _remove_exact_file(
                paths.state,
                code="state_write_failed",
                expected=expected,
                expected_generation=expected_generation,
                generation_maximum=MAX_STATE_BYTES,
                parent_fd=parent_fd,
            )
        except LauncherError as error:
            if error.code == "state_write_failed_replaced":
                raise LauncherError("state_replaced") from None
            raise
    return _create_private_file(paths.state, content, code="state_write_failed", parent_fd=parent_fd)


def _read_bounded_private_descriptor(descriptor: int, *, maximum: int, code: str) -> bytes:
    """Read bounded rollback bytes from the held state inode."""

    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        raw = bytearray()
        while len(raw) <= maximum:
            chunk = os.read(descriptor, maximum + 1 - len(raw))
            if not chunk:
                break
            raw.extend(chunk)
    except OSError:
        raise LauncherError(code) from None
    if len(raw) > maximum:
        raise LauncherError(f"{code}_oversized")
    return bytes(raw)


def _require_descriptor_generation(
    descriptor: int,
    expected_generation: str,
    *,
    maximum: int,
    replacement_code: str,
) -> None:
    """Require one held private record to retain its captured bytes."""

    try:
        raw = _read_bounded_private_descriptor(
            descriptor,
            maximum=maximum,
            code=replacement_code,
        )
        generation = live_run_marker.content_generation(
            raw,
            maximum=maximum,
            code=replacement_code,
        )
    except (LauncherError, live_run_marker.MarkerError):
        raise LauncherError(replacement_code) from None
    if generation != expected_generation:
        raise LauncherError(replacement_code)


def _rewrite_state_exact(
    spec: InstanceSpec,
    binding: live_run_marker.RunMarker,
    expected: FileIdentity,
    *,
    expected_generation: str | None = None,
    parent_fd: int,
    data_identity: DirectoryIdentity | None = None,
) -> FileIdentity:
    """Rewrite one owned state inode with descriptor-backed rollback.

    Quarantine is preferred because it gives publication atomicity. When the
    finite quarantine budget is exhausted, cleanup must not create another
    retained inode or leave a removed container represented as ``running``.
    This fallback keeps the old bounded bytes on hand, gates the inode while it
    is rewritten, and restores those bytes if writing, syncing, or pathname
    validation fails. A replacement pathname is only detection evidence; it is
    never overwritten by rollback.
    """

    paths = _marker_paths(binding.marker_path)
    if binding.state_path != paths.state:
        raise LauncherError("state_path_invalid")
    content = (
        json.dumps(
            state_document(spec, binding, data_identity=data_identity),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    if len(content) > MAX_STATE_BYTES:
        raise LauncherError("instance_state_too_large")
    _validate_private_parent_fd(parent_fd, code="state_rewrite_failed")
    descriptor = -1
    pathname_fd = -1
    old_content: bytes | None = None
    before: FileIdentity | None = None

    def restore() -> None:
        if old_content is None:
            return
        try:
            os.fchmod(descriptor, 0)
            os.ftruncate(descriptor, 0)
            os.lseek(descriptor, 0, os.SEEK_SET)
            _write_all(descriptor, old_content, "state_rollback_failed")
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            restored = _validated_fd_identity(descriptor, code="state_rollback_failed")
            if before is None or restored[:3] != before[:3] or restored[4] != before[4]:
                raise LauncherError("state_rollback_failed")
            if _read_bounded_private_descriptor(
                descriptor,
                maximum=MAX_STATE_BYTES,
                code="state_rollback_failed",
            ) != old_content:
                raise LauncherError("state_rollback_failed")
        except (LauncherError, OSError):
            raise LauncherError("state_rollback_failed") from None

    try:
        descriptor = _open_private_entry(parent_fd, paths.state.name, writable=True, code="state_rewrite_failed")
        before = _validated_fd_identity(descriptor, code="state_rewrite_failed")
        if before != expected:
            raise LauncherError("state_replaced")
        old_content = _read_bounded_private_descriptor(
            descriptor,
            maximum=MAX_STATE_BYTES,
            code="state_rewrite_failed",
        )
        if expected_generation is not None:
            _require_descriptor_generation(
                descriptor,
                expected_generation,
                maximum=MAX_STATE_BYTES,
                replacement_code="state_replaced",
            )
        try:
            if expected_generation is not None:
                _require_descriptor_generation(
                    descriptor,
                    expected_generation,
                    maximum=MAX_STATE_BYTES,
                    replacement_code="state_replaced",
                )
            os.fchmod(descriptor, 0)
            os.ftruncate(descriptor, 0)
            os.lseek(descriptor, 0, os.SEEK_SET)
            _write_all(descriptor, content, "state_rewrite_failed")
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        except LauncherError:
            raise
        except OSError:
            raise LauncherError("state_rewrite_failed") from None
        after = _validated_fd_identity(descriptor, code="state_rewrite_failed")
        if after[:3] != before[:3] or after[4] != before[4] or after[3] != len(content):
            raise LauncherError("state_replaced")
        pathname_fd = _open_private_entry(parent_fd, paths.state.name, writable=False, code="state_rewrite_failed")
        pathname_identity = _validated_fd_identity(pathname_fd, code="state_rewrite_failed")
        if pathname_identity != after or _read_bounded_private_descriptor(
            pathname_fd,
            maximum=MAX_STATE_BYTES,
            code="state_rewrite_failed",
        ) != content:
            raise LauncherError("state_replaced")
        try:
            os.fsync(parent_fd)
        except OSError:
            raise LauncherError("state_sync_failed") from None
        return after
    except BaseException as error:
        primary = error if isinstance(error, LauncherError) else LauncherError("state_rewrite_failed")
        try:
            restore()
        except BaseException as rollback:
            _attach_secondary_failure(primary, rollback)
        raise primary from None
    finally:
        if pathname_fd >= 0:
            try:
                os.close(pathname_fd)
            except OSError:
                pass
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _state_document(raw: bytes) -> dict[str, object]:
    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise LauncherError("instance_state_duplicate_key")
            document[key] = value
        return document

    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate)
    except LauncherError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
        raise LauncherError("instance_state_invalid") from None
    if not isinstance(document, dict) or set(document) != STATE_KEYS:
        raise LauncherError("instance_state_invalid")
    return document


def load_launcher_state(
    marker_path: str | Path,
    roots: Roots,
    *,
    parent_fd: int | None = None,
) -> LauncherState:
    """Load one exact marker and its exact state file; never infer a run."""

    try:
        marker, marker_identity, marker_generation = live_run_marker.load_marker_with_identity_and_generation(
            marker_path,
            parent_fd=parent_fd,
        )
    except live_run_marker.MarkerError as error:
        raise LauncherError(error.code) from None
    state_raw, state_identity = _read_private_file_record(
        marker.state_path,
        maximum=MAX_STATE_BYTES,
        code="instance_state_invalid",
        parent_fd=parent_fd,
    )
    try:
        state_generation = live_run_marker.content_generation(
            state_raw,
            maximum=MAX_STATE_BYTES,
            code="instance_state_invalid",
        )
    except live_run_marker.MarkerError as error:
        raise LauncherError(error.code) from None
    document = _state_document(state_raw)
    expected = {
        "schema": STATE_SCHEMA,
        "status": marker.status,
        "marker_path": str(marker.marker_path),
        "run_id": marker.run_id,
        "instance": marker.instance,
        "container_id": marker.container_id,
        "container_name": marker.container_name,
        "image": marker.image,
        "endpoint": marker.endpoint,
        "state_path": str(marker.state_path),
        "credential_path": str(marker.credential_path),
        "credential_identity": marker.credential_identity.document(),
    }
    for key, value in expected.items():
        if document.get(key) != value:
            raise LauncherError("instance_state_binding_mismatch")
    username = document.get("username")
    data_path = document.get("data_path")
    data_identity = _directory_identity_from_document(document.get("data_identity"))
    # State identity is not self-authorizing. New lifecycle markers carry an
    # independently captured witness; a state-only rewrite must disagree with
    # that exact marker record before any pathname is adopted or cleaned up.
    if marker.data_identity is None:
        raise LauncherError("instance_state_binding_mismatch")
    if marker.data_identity != data_identity:
        raise LauncherError("instance_state_binding_mismatch")
    if not isinstance(username, str) or not username or not isinstance(data_path, str):
        raise LauncherError("instance_state_invalid")
    try:
        parsed = urllib.parse.urlsplit(marker.endpoint)
        port = parsed.port
    except (TypeError, ValueError):
        raise LauncherError("instance_state_invalid") from None
    if port is None:
        raise LauncherError("instance_state_invalid")
    spec = make_spec(marker.instance, port, image=marker.image, username=username, roots=roots)
    if data_path != str(spec.data_dir) or marker.container_name != spec.container:
        raise LauncherError("instance_state_binding_mismatch")
    state = LauncherState(
        spec,
        marker,
        marker_identity=marker_identity,
        state_identity=state_identity,
        data_identity=data_identity,
        marker_generation=marker_generation,
        state_generation=state_generation,
    )
    # Loading a future lifecycle record is itself a trust boundary. Do not
    # return a state object that points at a replacement tree under the same
    # persisted pathname; recovery must fail before Podman or credential use.
    _revalidate_state_data_directory(state)
    return state


def load_state(instance: str, roots: Roots) -> InstanceSpec:
    """Reject the legacy instance-only lookup; callers must pass one marker."""

    del instance, roots
    raise LauncherError("marker_required")


def container_exists(
    spec: InstanceSpec,
    runner: Runner,
    environment: Mapping[str, str],
    executable: str,
) -> bool:
    result = invoke_runner(
        runner,
        (executable, "container", "exists", spec.container),
        environment,
        10,
        failure_code="container_lookup_failed",
    )
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise LauncherError("container_lookup_failed")


def inspect_container(
    spec: InstanceSpec,
    runner: Runner,
    environment: Mapping[str, str],
    executable: str,
    *,
    target: str | None = None,
    private_path: Path | None = None,
    private_identity: DirectoryIdentity | None = None,
) -> dict[str, object]:
    result = invoke_runner(
        runner,
        (executable, "container", "inspect", target or spec.container, "--format", "json"),
        environment,
        20,
        failure_code="container_inspect_failed",
        private_path=private_path,
        private_identity=private_identity,
    )
    if result.returncode != 0:
        raise LauncherError("container_inspect_failed")
    try:
        document = json.loads(result.stdout)
        if not isinstance(document, list) or len(document) != 1 or not isinstance(document[0], dict):
            raise ValueError
        return document[0]
    except (json.JSONDecodeError, ValueError):
        raise LauncherError("container_inspect_invalid") from None


def _labels_from_inspect(document: dict[str, object]) -> dict[str, str]:
    config = document.get("Config")
    if not isinstance(config, dict):
        raise LauncherError("container_inspect_invalid")
    labels = config.get("Labels")
    if not isinstance(labels, dict) or any(type(key) is not str or type(value) is not str for key, value in labels.items()):
        raise LauncherError("container_inspect_invalid")
    return labels


def require_owned_container(
    spec: InstanceSpec,
    document: dict[str, object],
    *,
    run_id: str | None = None,
) -> None:
    labels = _labels_from_inspect(document)
    expected = {
        MANAGED_LABEL: MANAGED_VERSION,
        "io.hermternal.instance": spec.instance,
        "io.hermternal.port": str(spec.port),
        "io.hermternal.image": spec.image,
    }
    if run_id is not None:
        expected["io.hermternal.run-id"] = run_id
    if any(labels.get(key) != value for key, value in expected.items()):
        raise LauncherError("container_not_launcher_owned")


def container_status(document: dict[str, object]) -> str:
    state = document.get("State")
    status = state.get("Status") if isinstance(state, dict) else None
    if type(status) is not str or not status:
        raise LauncherError("container_inspect_invalid")
    return status


def recovery_snapshot(
    spec: InstanceSpec,
    document: dict[str, object],
    *,
    run_id: str | None = None,
) -> RecoverySnapshot:
    """Validate only the exact identity needed before a destructive action.

    Ordinary reuse keeps the historical label-only compatibility boundary. A
    stop or start is different: it needs a fresh inspect projection so a
    replaced container cannot inherit the launcher-owned name and labels.
    """

    require_owned_container(spec, document, run_id=run_id)
    container_id = document.get("Id")
    name = document.get("Name")
    image = document.get("ImageName")
    if (
        type(container_id) is not str
        or not container_id
        or type(name) is not str
        or name not in {spec.container, f"/{spec.container}"}
        or type(image) is not str
        or image not in {spec.image, expected_repo_digest(spec.image)}
    ):
        raise LauncherError("container_identity_unproven")

    mounts = document.get("Mounts")
    if not isinstance(mounts, list):
        raise LauncherError("container_identity_unproven")
    managed_mounts = [
        mount
        for mount in mounts
        if isinstance(mount, dict) and mount.get("Destination") == "/opt/data"
    ]
    if len(managed_mounts) != 1:
        raise LauncherError("container_identity_unproven")
    managed_mount = managed_mounts[0]
    if (
        managed_mount.get("Type") != "bind"
        or managed_mount.get("Source") != str(spec.data_dir)
    ):
        raise LauncherError("container_identity_unproven")
    # The published port/socket mapping is deliberately not an identity
    # rejection criterion: this lifecycle action is the narrowly scoped rebind.
    # Port availability is preflighted, while the exact container state is what
    # rollback restores; no mapping or listener is edited by this launcher.

    return RecoverySnapshot(
        container_id=container_id,
        name=name,
        image=image,
        data_source=str(spec.data_dir),
        status=container_status(document),
    )


def require_same_recovery_snapshot(
    spec: InstanceSpec,
    expected: RecoverySnapshot,
    document: dict[str, object],
) -> RecoverySnapshot:
    current = recovery_snapshot(spec, document)
    if (
        current.container_id != expected.container_id
        or current.name != expected.name
        or current.image != expected.image
        or current.data_source != expected.data_source
    ):
        raise LauncherError("container_recovery_race")
    return current


def require_loopback_endpoint_mapping(spec: InstanceSpec, document: dict[str, object]) -> None:
    """Require the selected port to be this container's sole Dashboard mapping."""

    network = document.get("NetworkSettings")
    ports = network.get("Ports") if isinstance(network, dict) else None
    expected_key = f"{DASHBOARD_PORT}/tcp"
    if not isinstance(ports, dict) or set(ports) != {expected_key}:
        raise LauncherError("container_endpoint_unproven")
    binding = ports.get(expected_key)
    if not isinstance(binding, list) or len(binding) != 1 or not isinstance(binding[0], dict):
        raise LauncherError("container_endpoint_unproven")
    host_ip = binding[0].get("HostIp")
    host_port = binding[0].get("HostPort")
    # Accept only the launcher-created IPv4 loopback binding. A wildcard, IPv6,
    # extra mapping, missing mapping, or substituted port fails before the
    # credential file is read by the live-proof handoff.
    if host_ip != "127.0.0.1" or host_port != str(spec.port):
        raise LauncherError("container_endpoint_unproven")


def verify_handoff_endpoint(
    state: LauncherState,
    *,
    runner: Runner = run_command,
    executable: str | None = None,
    source_environment: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Freshly prove the running launcher container owns its exact endpoint.

    This is intentionally invoked by ``endpoint`` immediately before the
    credential handoff. It inspects the persisted immutable ID, never a mutable
    name, and exposes only public metadata on success.
    """

    with _operation_lease(state.marker_path, code="marker_path_invalid") as lease:
        _revalidate_state_records(state, parent_fd=lease.parent_fd)
        if state.marker.status != live_run_marker.STATUS_RUNNING:
            raise LauncherError("marker_not_selectable")
        environment = clean_environment(source_environment)
        podman = executable or podman_path()
        podman_preflight(runner, environment, podman)
        _revalidate_state_data_directory(state)
        document = inspect_container(
            state.spec,
            runner,
            environment,
            podman,
            target=state.container_id,
            private_path=state.spec.data_dir,
            private_identity=state.data_identity,
        )
        _revalidate_state_data_directory(state)
        _revalidate_private_parent_path(state.marker_path, lease.parent_fd, expected=lease.identity, code="runs_dir")
        snapshot = recovery_snapshot(state.spec, document, run_id=state.run_id)
        if snapshot.container_id != state.container_id:
            raise LauncherError("container_replaced")
        if snapshot.status != "running":
            raise LauncherError("container_not_running")
        require_loopback_endpoint_mapping(state.spec, document)
        try:
            live_run_marker.verify_credential_identity(
                state.marker,
                parent_fd=lease.parent_fd,
            )
        except live_run_marker.MarkerError as error:
            raise LauncherError(error.code) from None
        _revalidate_private_parent_path(state.marker_path, lease.parent_fd, expected=lease.identity, code="runs_dir")
        _revalidate_state_records(state, parent_fd=lease.parent_fd)
        _revalidate_credential_identity(state.marker, parent_fd=lease.parent_fd)
        _revalidate_private_parent_path(state.marker_path, lease.parent_fd, expected=lease.identity, code="runs_dir")
        # The hook is an adversarial boundary. Fence every exact record and the
        # immutable container again before releasing credential handoff metadata.
        _before_public_return("endpoint")
        _revalidate_public_state(
            state,
            parent_fd=lease.parent_fd,
            runner=runner,
            environment=environment,
            executable=podman,
            require_running=True,
            require_endpoint=True,
        )
        # Keep the handoff result bounded. It is the only operation that releases
        # the exact marker and credential paths to a transient local helper.
        return {
            "status": "running",
            "endpoint": state.marker.endpoint,
            "marker_path": str(state.marker.marker_path),
            "run_id": state.marker.run_id,
            "credential_file": str(state.marker.credential_path),
            "credential_identity": state.marker.credential_identity.document(),
        }


def _run_container_action(
    target: str,
    action: str,
    runner: Runner,
    environment: Mapping[str, str],
    executable: str,
    failure_code: str,
    *,
    private_path: Path | None = None,
    private_identity: DirectoryIdentity | None = None,
) -> None:
    result = invoke_runner(
        runner,
        (executable, action, target),
        environment,
        CONTAINER_ACTION_TIMEOUT,
        failure_code=failure_code,
        private_path=private_path,
        private_identity=private_identity,
    )
    if result.returncode != 0:
        raise LauncherError(failure_code)


def run_arguments(
    spec: InstanceSpec,
    executable: str,
    run_id: str,
    *,
    cidfile: str | Path | None = None,
    data_path: Path | None = None,
) -> tuple[str, ...]:
    if type(executable) is not str or not executable or "\x00" in executable:
        raise LauncherError("executable_invalid")
    _validate_start_spec(spec)
    if live_run_marker.RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise LauncherError("run_id_invalid")
    bind_path = _canonical_private_path(data_path if data_path is not None else spec.data_dir)
    if bind_path != spec.data_dir:
        raise LauncherError("owned_path_invalid")
    arguments: list[str] = [executable, "run", "--detach"]
    if cidfile is not None:
        try:
            cidfile_path = live_run_marker.canonical_path(cidfile, code="cidfile_path_invalid")
        except live_run_marker.MarkerError as error:
            raise LauncherError(error.code) from None
        arguments.extend(("--cidfile", str(cidfile_path)))
    arguments.extend(
        (
            "--name",
            spec.container,
            "--restart",
            "unless-stopped",
            "--label",
            f"{MANAGED_LABEL}={MANAGED_VERSION}",
            "--label",
            f"io.hermternal.instance={spec.instance}",
            "--label",
            f"io.hermternal.port={spec.port}",
            "--label",
            f"io.hermternal.image={spec.image}",
            "--label",
            f"io.hermternal.run-id={run_id}",
            "--volume",
            f"{bind_path}:/opt/data",
            "--publish",
            f"127.0.0.1:{spec.port}:{DASHBOARD_PORT}",
            "--env",
            "HERMES_DASHBOARD",
            "--env",
            "HERMES_DASHBOARD_BASIC_AUTH_USERNAME",
            "--env",
            "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD",
            "--pull",
            "never",
            spec.image,
            "gateway",
            "run",
        )
    )
    return _validate_command_vector(arguments)


def read_cidfile(path: str | Path, *, parent_fd: int | None = None) -> tuple[str, FileIdentity]:
    """Read one engine-emitted ID through a held private parent and entry fd."""

    try:
        cidfile = live_run_marker.canonical_path(path, code="cidfile_path_invalid")
    except live_run_marker.MarkerError as error:
        raise LauncherError(error.code) from None
    owns_parent = parent_fd is None
    if parent_fd is None:
        parent_fd = _open_private_parent(cidfile, code="cidfile_invalid")
    else:
        _validate_private_parent_fd(parent_fd, code="cidfile_invalid")
    descriptor = -1
    before_identity: FileIdentity | None = None
    try:
        try:
            descriptor = os.open(
                cidfile.name,
                os.O_RDONLY
                | _required_private_flag("O_NOFOLLOW")
                | _required_private_flag("O_NONBLOCK")
                | _required_private_flag("O_CLOEXEC"),
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            raise LauncherError("cidfile_missing") from None
        except OSError:
            raise LauncherError("cidfile_invalid") from None
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > 66
        ):
            raise LauncherError("cidfile_invalid")
        before_identity = _private_file_identity_from_stat(before)
        raw = bytearray()
        while len(raw) <= 66:
            chunk = os.read(descriptor, 67 - len(raw))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        after_identity = (
            after.st_dev,
            after.st_ino,
            stat.S_IMODE(after.st_mode),
            after.st_size,
            after.st_nlink,
        )
        if before_identity != after_identity or len(raw) > 66:
            raise LauncherError("cidfile_replaced")
        try:
            text = bytes(raw).decode("ascii")
        except UnicodeDecodeError:
            raise LauncherError("cidfile_invalid") from None
        candidate = text.rstrip("\r\n")
        if not candidate or text not in {candidate, candidate + "\n", candidate + "\r\n"}:
            raise LauncherError("cidfile_invalid")
        try:
            container_id = validate_container_id(candidate)
        except LauncherError:
            raise LauncherError("cidfile_invalid") from None
        return container_id, after_identity
    except OwnedFileError:
        raise
    except LauncherError as error:
        if before_identity is not None:
            raise OwnedFileError(error.code, path=cidfile, identity=before_identity) from None
        raise
    except OSError:
        if before_identity is not None:
            raise OwnedFileError("cidfile_read_failed", path=cidfile, identity=before_identity) from None
        raise LauncherError("cidfile_read_failed") from None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if owns_parent and parent_fd is not None:
            try:
                os.close(parent_fd)
            except OSError:
                pass


def _validate_readiness_options(attempts: int, interval: float) -> None:
    """Reject non-finite or out-of-range readiness controls before side effects."""

    if type(attempts) is not int or attempts < 1 or attempts > 600:
        raise LauncherError("readiness_attempts_invalid")
    if (
        not isinstance(interval, (int, float))
        or isinstance(interval, bool)
        or not math.isfinite(interval)
        or interval < 0
        or interval > 30
    ):
        raise LauncherError("readiness_interval_invalid")


def check_provider_readiness(endpoint: str, attempts: int, interval: float) -> None:
    _validate_readiness_options(attempts, interval)
    url = f"{endpoint}/api/auth/providers"
    for attempt in range(attempts):
        try:
            request = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(request, timeout=2) as response:
                if response.status != 200:
                    raise LauncherError("provider_readiness_unavailable")
                raw = response.read(MAX_PROVIDER_BYTES + 1)
            if len(raw) > MAX_PROVIDER_BYTES:
                raise LauncherError("provider_readiness_invalid")
            document = json.loads(raw.decode("utf-8"))
            providers = document.get("providers") if isinstance(document, dict) else None
            if not isinstance(providers, list):
                raise LauncherError("provider_readiness_invalid")
            for provider in providers:
                if (
                    isinstance(provider, dict)
                    and provider.get("name") == "basic"
                    and provider.get("supports_password") is True
                ):
                    return
            raise LauncherError("basic_provider_missing")
        except LauncherError as exc:
            if exc.code in {"provider_readiness_invalid", "basic_provider_missing"}:
                raise
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, UnicodeDecodeError):
            pass
        if attempt + 1 < attempts:
            time.sleep(interval)
    raise LauncherError("provider_readiness_timeout")


def _public_run_result(spec: InstanceSpec, binding: live_run_marker.RunMarker, *, status: str, created: bool) -> dict[str, object]:
    return {
        "instance": spec.instance,
        "status": status,
        "marker_path": str(binding.marker_path),
        "created": created,
    }


def _cleanup_binding(
    paths: live_run_marker.MarkerPaths,
    spec: InstanceSpec,
    *,
    run_id: str,
    container_id: str,
    credential_identity: live_run_marker.CredentialIdentity,
    data_identity: DirectoryIdentity | None = None,
) -> live_run_marker.RunMarker:
    """Build an unpublishing cleanup projection without marker validation.

    The normal marker constructor validates publication inputs. Cleanup must not
    lose an already-proven immutable container or file identity merely because a
    patched or raced publication constructor fails; this projection never gets
    published and is consumed only by exact-ID cleanup.
    """

    return live_run_marker.RunMarker(
        marker_path=paths.marker,
        status=live_run_marker.STATUS_RUNNING,
        run_id=run_id,
        instance=spec.instance,
        container_id=container_id,
        container_name=spec.container,
        image=spec.image,
        endpoint=spec.endpoint,
        state_path=paths.state,
        credential_path=paths.credential,
        credential_identity=credential_identity,
        data_identity=data_identity,
    )


def _load_bound_state(
    marker_path: str | Path,
    roots: Roots,
    *,
    parent_fd: int | None = None,
) -> LauncherState:
    return load_launcher_state(marker_path, roots, parent_fd=parent_fd)


def _inspect_bound_container(
    state: LauncherState,
    runner: Runner,
    environment: Mapping[str, str],
    executable: str,
    *,
    private_path: Path | None = None,
    private_identity: DirectoryIdentity | None = None,
) -> tuple[dict[str, object], RecoverySnapshot]:
    if private_path is None and private_identity is None:
        private_path = state.spec.data_dir
        private_identity = state.data_identity
    if private_path is None or private_identity is None:
        raise LauncherError("ownership_snapshot_missing")
    # The inspecter's mount ``Source`` string is only a consistency field; it
    # is not host inode proof. The descriptor-bound identity check in
    # ``invoke_runner`` brackets the pathname-based Podman call instead.
    _revalidate_private_directory_identity(private_path, private_identity)
    document = inspect_container(
        state.spec,
        runner,
        environment,
        executable,
        target=state.container_id,
        private_path=private_path,
        private_identity=private_identity,
    )
    if private_path is not None and private_identity is not None:
        _revalidate_private_directory_identity(private_path, private_identity)
    snapshot = recovery_snapshot(state.spec, document, run_id=state.run_id)
    if snapshot.container_id != state.container_id:
        raise LauncherError("container_replaced")
    return document, snapshot


def _require_running_container(
    state: LauncherState,
    runner: Runner,
    environment: Mapping[str, str],
    executable: str,
) -> None:
    """Refresh the immutable container projection immediately before return."""

    _revalidate_state_data_directory(state)
    _, snapshot = _inspect_bound_container(state, runner, environment, executable)
    _revalidate_state_data_directory(state)
    if snapshot.status != "running":
        raise LauncherError("container_not_running")


def _file_identity(
    path: Path,
    *,
    code: str,
    parent_fd: int | None = None,
) -> FileIdentity:
    if parent_fd is not None:
        _validate_private_parent_fd(parent_fd, code=code)
        descriptor = _open_private_entry(parent_fd, path.name, writable=False, code=code)
        try:
            return _validated_fd_identity(descriptor, code=code)
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise LauncherError(f"{code}_missing") from None
    except OSError:
        raise LauncherError(code) from None
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise LauncherError(f"{code}_invalid")
    return _private_file_identity_from_stat(info)


def _private_parent_identity(info: os.stat_result, *, code: str) -> ParentIdentity:
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise LauncherError(f"{code}_invalid")
    return (info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode))


def _parent_identity(parent_fd: int, *, code: str) -> ParentIdentity:
    try:
        return _private_parent_identity(os.fstat(parent_fd), code=code)
    except OSError:
        raise LauncherError(code) from None


def _validate_private_parent_fd(
    parent_fd: int,
    *,
    code: str,
    expected: ParentIdentity | None = None,
) -> None:
    """Validate a caller-held private runs directory without reopening its path."""

    _private_directory_flags()
    current = _parent_identity(parent_fd, code=code)
    active = _ACTIVE_PARENT_LEASE.get()
    if expected is not None and current != expected:
        raise LauncherError(f"{code}_replaced")
    if active is not None and current != active.identity:
        raise LauncherError(f"{code}_replaced")


def _revalidate_private_parent_path(
    path: Path,
    parent_fd: int,
    *,
    expected: ParentIdentity | None = None,
    code: str = "runs_dir",
) -> None:
    """Reject a runs-directory pathname replacement while retaining the old fd."""

    held = _parent_identity(parent_fd, code=code)
    try:
        info = path.parent.lstat()
    except OSError:
        raise LauncherError(f"{code}_replaced") from None
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise LauncherError(f"{code}_replaced")
    current = (info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode))
    active = _ACTIVE_PARENT_LEASE.get()
    expected_identity = expected if expected is not None else (active.identity if active is not None else None)
    if current != held or (expected_identity is not None and held != expected_identity):
        raise LauncherError(f"{code}_replaced")


def _open_private_parent(path: Path, *, code: str) -> int:
    """Hold the validated private parent while claiming one child entry.

    Marker and lifecycle helpers must not fall back to pathname-only opens. The
    shared capability gate rejects platforms that cannot enforce no-follow,
    directory-only, and descriptor-relative identity checks before any lock or
    record operation is attempted.
    """

    flags = _private_directory_flags()
    try:
        descriptor = os.open(path.parent, flags)
        try:
            _validate_private_parent_fd(descriptor, code=code)
        except LauncherError:
            os.close(descriptor)
            raise
        return descriptor
    except LauncherError:
        raise
    except OSError:
        raise LauncherError(code) from None


@contextlib.contextmanager
def _operation_lease(marker_path: str | Path, *, code: str = "marker_path_invalid"):
    """Hold one parent fd and an inter-process lifecycle lease across the operation."""

    paths = _marker_paths(marker_path)
    active = _ACTIVE_PARENT_LEASE.get()
    if active is not None:
        if active.marker_path.parent != paths.marker.parent:
            raise LauncherError("runs_dir_replaced")
        _revalidate_private_parent_path(
            paths.marker,
            active.parent_fd,
            expected=active.identity,
            code="runs_dir",
        )
        yield active
        return

    parent_fd = _open_private_parent(paths.marker, code=code)
    identity = _parent_identity(parent_fd, code=code)
    lease = ParentLease(paths.marker, parent_fd, identity)
    active_token = _ACTIVE_PARENT_LEASE.set(lease)
    expected_token = live_run_marker._set_expected_parent_identity(identity)
    primary_error: BaseException | None = None
    try:
        _revalidate_private_parent_path(paths.marker, parent_fd, expected=identity, code="runs_dir")
        with live_run_marker.exclusive_lifecycle_lease(parent_fd):
            yield lease
    except live_run_marker.MarkerError as error:
        normalized = LauncherError(error.code)
        if isinstance(error.secondary, live_run_marker.MarkerError):
            normalized.secondary = LauncherError(error.secondary.code)
        primary_error = normalized
        raise normalized from None
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            try:
                _revalidate_private_parent_path(paths.marker, parent_fd, expected=identity, code="runs_dir")
            except BaseException as secondary:
                if primary_error is not None:
                    _attach_secondary_failure(primary_error, secondary)
                else:
                    raise
        finally:
            live_run_marker._reset_expected_parent_identity(expected_token)
            _ACTIVE_PARENT_LEASE.reset(active_token)
            close_failure = _close_fd_best_effort(parent_fd)
            if close_failure is not None:
                active_error = sys.exc_info()[1]
                if primary_error is not None:
                    _attach_secondary_failure(primary_error, close_failure)
                elif isinstance(active_error, BaseException):
                    _attach_secondary_failure(active_error, close_failure)
                else:
                    raise close_failure


def _open_private_entry(parent_fd: int, name: str, *, writable: bool, code: str) -> int:
    flags = (
        (os.O_RDWR if writable else os.O_RDONLY)
        | _required_private_flag("O_NOFOLLOW")
        | _required_private_flag("O_NONBLOCK")
        | _required_private_flag("O_CLOEXEC")
    )
    try:
        return os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        raise LauncherError(f"{code}_missing") from None
    except OSError:
        raise LauncherError(f"{code}_invalid") from None


def _validated_fd_identity(descriptor: int, *, code: str) -> FileIdentity:
    try:
        info = os.fstat(descriptor)
    except OSError:
        raise LauncherError(code) from None
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise LauncherError(f"{code}_invalid")
    return _private_file_identity_from_stat(info)


def _revalidate_private_identity(
    path: Path,
    expected: FileIdentity,
    *,
    code: str,
    replacement_code: str | None = None,
    parent_fd: int | None = None,
) -> None:
    """Recheck an exact sibling through one held parent and entry descriptor."""

    owns_parent = parent_fd is None
    if parent_fd is None:
        parent_fd = _open_private_parent(path, code=code)
    else:
        _validate_private_parent_fd(parent_fd, code=code)
    descriptor = -1
    try:
        descriptor = _open_private_entry(parent_fd, path.name, writable=False, code=code)
        before = _validated_fd_identity(descriptor, code=code)
        after = _validated_fd_identity(descriptor, code=code)
        if before != after or after != expected:
            raise LauncherError(replacement_code or f"{code}_replaced")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if owns_parent:
            try:
                os.close(parent_fd)
            except OSError:
                pass


def _private_record_snapshot(
    path: Path,
    *,
    maximum: int,
    code: str,
    parent_fd: int,
) -> tuple[FileIdentity, str]:
    """Capture identity plus a one-way hash from one exact descriptor read."""

    raw, identity = _read_private_file_record(
        path,
        maximum=maximum,
        code=code,
        parent_fd=parent_fd,
    )
    try:
        generation = live_run_marker.content_generation(
            raw,
            maximum=maximum,
            code=code,
        )
    except live_run_marker.MarkerError as error:
        raise LauncherError(error.code) from None
    return identity, generation


def _revalidate_private_generation(
    path: Path,
    expected: FileIdentity,
    expected_generation: str | None,
    *,
    maximum: int,
    code: str,
    replacement_code: str,
    parent_fd: int,
) -> None:
    """Recheck exact file identity and bounded bytes through one descriptor.

    Stat identity detects pathname replacement; the one-way generation closes
    the same-inode, same-size mutation gap without retaining marker or state
    contents in launcher state.
    """

    if expected_generation is None:
        raise LauncherError("ownership_snapshot_missing")
    try:
        raw, current = _read_private_file_record(
            path,
            maximum=maximum,
            code=code,
            parent_fd=parent_fd,
        )
    except LauncherError as error:
        if error.code == f"{code}_replaced":
            raise LauncherError(replacement_code) from None
        raise
    if current != expected:
        raise LauncherError(replacement_code)
    try:
        generation = live_run_marker.content_generation(
            raw,
            maximum=maximum,
            code=code,
        )
    except live_run_marker.MarkerError as error:
        raise LauncherError(error.code) from None
    if generation != expected_generation:
        raise LauncherError(replacement_code)


def _revalidate_state_data_directory(state: LauncherState) -> None:
    """Require the persisted state identity to still name the data directory."""

    if state.data_identity is None:
        raise LauncherError("ownership_snapshot_missing")
    _revalidate_private_directory_identity(state.spec.data_dir, state.data_identity)


def _revalidate_state_records(
    state: LauncherState,
    *,
    parent_fd: int,
    include_credential: bool = True,
) -> None:
    """Revalidate data and published records before or after lifecycle actions."""

    _revalidate_state_data_directory(state)
    if state.marker_identity is None or state.state_identity is None:
        raise LauncherError("ownership_snapshot_missing")
    _revalidate_private_generation(
        state.marker_path,
        state.marker_identity,
        state.marker_generation,
        maximum=live_run_marker.MAX_MARKER_BYTES,
        code="marker_identity",
        replacement_code="marker_replaced",
        parent_fd=parent_fd,
    )
    _revalidate_private_generation(
        state.marker.state_path,
        state.state_identity,
        state.state_generation,
        maximum=MAX_STATE_BYTES,
        code="state_identity",
        replacement_code="state_replaced",
        parent_fd=parent_fd,
    )
    if include_credential:
        _revalidate_credential_identity(state.marker, parent_fd=parent_fd)


def _revalidate_credential_identity(
    marker: live_run_marker.RunMarker,
    *,
    parent_fd: int,
) -> live_run_marker.CredentialIdentity:
    """Recheck credential inode and content generation before exposure or cleanup."""

    try:
        return live_run_marker.verify_credential_identity(marker, parent_fd=parent_fd)
    except live_run_marker.MarkerError as error:
        raise LauncherError(error.code) from None


def _revalidate_public_state(
    state: LauncherState,
    *,
    parent_fd: int,
    runner: Runner | None = None,
    environment: Mapping[str, str] | None = None,
    executable: str | None = None,
    require_running: bool = False,
    require_endpoint: bool = False,
    absent_names: Sequence[tuple[str, str]] = (),
) -> RecoverySnapshot | None:
    """Fence every exact record and, when supplied, the immutable container.

    A final-return hook is an adversarial scheduling boundary. Rechecking only
    the data directory is insufficient: a same-name marker, state, credential,
    cidfile, parent, or container replacement could otherwise be published in
    the returned metadata. The helper brackets an optional exact-ID inspect with
    parent, record, credential, and data checks; failed-create and stop callers
    use ``absent_names`` to prove removed evidence stayed absent.
    """

    _revalidate_private_parent_path(
        state.marker_path,
        parent_fd,
        expected=_ACTIVE_PARENT_LEASE.get().identity if _ACTIVE_PARENT_LEASE.get() is not None else None,
        code="runs_dir",
    )
    _revalidate_state_records(state, parent_fd=parent_fd)
    snapshot: RecoverySnapshot | None = None
    if runner is not None:
        if environment is None or executable is None:
            raise LauncherError("ownership_snapshot_missing")
        document, snapshot = _inspect_bound_container(
            state,
            runner,
            environment,
            executable,
        )
        if require_running and snapshot.status != "running":
            raise LauncherError("container_not_running")
        if require_endpoint:
            require_loopback_endpoint_mapping(state.spec, document)
    _revalidate_private_parent_path(
        state.marker_path,
        parent_fd,
        expected=_ACTIVE_PARENT_LEASE.get().identity if _ACTIVE_PARENT_LEASE.get() is not None else None,
        code="runs_dir",
    )
    _revalidate_state_records(state, parent_fd=parent_fd)
    for name, code in absent_names:
        _require_exact_entry_absent(parent_fd, name, code=code)
    return snapshot


def _credential_descriptor_snapshot(descriptor: int) -> live_run_marker.CredentialIdentity:
    """Hash one held credential inode without consulting a mutable pathname."""

    def identity_from_stat(info: os.stat_result) -> FileIdentity:
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size < 1
            or info.st_size > live_run_marker.MAX_CREDENTIAL_BYTES
            or info.st_nlink not in {0, 1}
        ):
            raise LauncherError("credential_identity_mismatch")
        return (
            info.st_dev,
            info.st_ino,
            stat.S_IMODE(info.st_mode),
            info.st_size,
            info.st_nlink,
        )

    try:
        before = os.fstat(descriptor)
        before_identity = identity_from_stat(before)
        os.lseek(descriptor, 0, os.SEEK_SET)
        raw = bytearray()
        while len(raw) <= live_run_marker.MAX_CREDENTIAL_BYTES:
            chunk = os.read(descriptor, live_run_marker.MAX_CREDENTIAL_BYTES + 1 - len(raw))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        after_identity = identity_from_stat(after)
    except LauncherError:
        raise
    except OSError:
        raise LauncherError("credential_identity_mismatch") from None
    if before_identity[:4] != after_identity[:4] or len(raw) != after_identity[3]:
        raise LauncherError("credential_identity_mismatch")
    generation = live_run_marker.content_generation(
        bytes(raw),
        maximum=live_run_marker.MAX_CREDENTIAL_BYTES,
        code="credential_identity_mismatch",
    )
    return live_run_marker.CredentialIdentity(
        after_identity[0],
        after_identity[1],
        after_identity[2],
        after_identity[3],
        after_identity[4],
        generation,
    )


def _require_credential_descriptor_generation(
    descriptor: int,
    expected: live_run_marker.CredentialIdentity,
    *,
    replacement_code: str,
) -> None:
    """Require the expected generation immediately before credential erasure."""

    if not expected.generation:
        raise LauncherError(replacement_code)
    try:
        current = _credential_descriptor_snapshot(descriptor)
    except LauncherError:
        raise LauncherError(replacement_code) from None
    if current.file_identity()[:4] != expected.file_identity()[:4] or current.generation != expected.generation:
        raise LauncherError(replacement_code)


def _erase_credential_descriptor(descriptor: int) -> None:
    """Finish verified zeroing, truncation, and sync on the held credential inode."""

    last_error: OSError | None = None
    for _ in range(4):
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
                raise OSError("credential inode invalid")
            target_size = min(live_run_marker.MAX_CREDENTIAL_BYTES, max(0, info.st_size))
            os.lseek(descriptor, 0, os.SEEK_SET)
            zeros = b"\x00" * 64
            written_total = 0
            while written_total < target_size:
                chunk = zeros[: min(len(zeros), target_size - written_total)]
                written = os.write(descriptor, chunk)
                if written <= 0:
                    raise OSError("credential erase made no progress")
                written_total += written
            os.ftruncate(descriptor, 0)
            os.fsync(descriptor)
            verified = os.fstat(descriptor)
            if verified.st_size != 0:
                raise OSError("credential erase left readable bytes")
            return
        except OSError as error:
            last_error = error
    del last_error
    raise LauncherError("credential_erase_failed") from None


def _rename_exact_noreplace(
    parent_fd: int,
    source_name: str,
    target_name: str,
    expected: FileIdentity,
    *,
    expected_generation: str | None = None,
    generation_maximum: int | None = None,
    code: str,
) -> None:
    """Validate identity and captured bytes inside the no-replace boundary."""

    token = _RENAME_EXPECTED.set(
        (
            parent_fd,
            source_name,
            target_name,
            expected,
            code,
            expected_generation,
            generation_maximum,
        )
    )
    try:
        _rename_noreplace(parent_fd, source_name, target_name)
    finally:
        _RENAME_EXPECTED.reset(token)


def _remove_exact_file(
    path: Path,
    *,
    code: str,
    expected: FileIdentity | live_run_marker.CredentialIdentity | None = None,
    expected_generation: str | None = None,
    generation_maximum: int | None = None,
    missing_ok: bool = False,
    erase: bool = False,
    parent_fd: int | None = None,
    held_descriptor: int | None = None,
) -> None:
    """Claim one exact inode into bounded no-replace quarantine evidence.

    The source descriptor is held before the quarantine claim and checked again
    immediately before the pathname syscall. When supplied, the captured
    bounded-content generation is checked at both points as well; this closes
    same-inode, same-size mutation without retaining record bytes in state. The
    moved destination is opened and compared with that held identity before any
    erase. A foreign source or destination is never erased or restored over; its
    pathname/evidence remains private and the operation fails closed.
    """

    if expected_generation is not None and generation_maximum is None:
        raise LauncherError("ownership_snapshot_missing")

    expected_credential = expected if isinstance(expected, live_run_marker.CredentialIdentity) else None
    if expected_credential is not None:
        expected_tuple: FileIdentity | None = expected_credential.file_identity()
    else:
        expected_tuple = expected

    owns_parent = parent_fd is None
    source_fd = held_descriptor if held_descriptor is not None else -1
    source_owned = held_descriptor is None
    moved_fd = -1
    quarantine: str | None = None
    erased = False
    erase_attempted = False
    try:
        if parent_fd is None:
            parent_fd = _open_private_parent(path, code=code)
        else:
            _validate_private_parent_fd(parent_fd, code=code)
        with live_run_marker.quarantine_exclusive(parent_fd):
            if source_fd < 0:
                source_fd = _open_private_entry(parent_fd, path.name, writable=erase, code=code)
            source_identity = _validated_fd_identity(source_fd, code=code)
            if expected_tuple is not None and source_identity != expected_tuple:
                raise LauncherError(f"{code}_replaced")
            expected_tuple = source_identity
            if expected_generation is not None:
                _require_descriptor_generation(
                    source_fd,
                    expected_generation,
                    maximum=generation_maximum,
                    replacement_code=f"{code}_replaced",
                )
            if expected_credential is not None:
                _require_credential_descriptor_generation(
                    source_fd,
                    expected_credential,
                    replacement_code=f"{code}_replaced",
                )

            for _ in range(live_run_marker.QUARANTINE_SLOT_COUNT):
                try:
                    candidate = live_run_marker.reserve_quarantine_slot(
                        parent_fd,
                        "cleanup",
                        expected_tuple[3],
                    )
                except live_run_marker.MarkerError as error:
                    raise LauncherError(error.code) from None
                try:
                    _rename_exact_noreplace(
                        parent_fd,
                        path.name,
                        candidate,
                        expected_tuple,
                        expected_generation=expected_generation,
                        generation_maximum=generation_maximum,
                        code=code,
                    )
                except LauncherError as error:
                    if error.code == "quarantine_exists":
                        continue
                    if erase:
                        try:
                            if expected_credential is not None:
                                _require_credential_descriptor_generation(
                                    source_fd,
                                    expected_credential,
                                    replacement_code=f"{code}_replaced",
                                )
                            erase_attempted = True
                            _erase_credential_descriptor(source_fd)
                            erased = True
                        except LauncherError as erase_error:
                            error.secondary = erase_error
                    raise
                quarantine = candidate
                break
            if quarantine is None:
                raise LauncherError("quarantine_quota_exceeded")
            moved_fd = _open_private_entry(parent_fd, quarantine, writable=erase, code=code)
            moved_identity = _validated_fd_identity(moved_fd, code=code)
            if moved_identity != expected_tuple:
                if erase:
                    try:
                        if expected_credential is not None:
                            _require_credential_descriptor_generation(
                                source_fd,
                                expected_credential,
                                replacement_code=f"{code}_replaced",
                            )
                        erase_attempted = True
                        _erase_credential_descriptor(source_fd)
                        erased = True
                    except LauncherError as erase_error:
                        raise erase_error from None
                raise LauncherError(f"{code}_replaced")

            if expected_generation is not None:
                _require_descriptor_generation(
                    moved_fd,
                    expected_generation,
                    maximum=generation_maximum,
                    replacement_code=f"{code}_replaced",
                )
            if erase:
                if expected_credential is not None:
                    _require_credential_descriptor_generation(
                        moved_fd,
                        expected_credential,
                        replacement_code=f"{code}_replaced",
                    )
                erase_attempted = True
                try:
                    _erase_credential_descriptor(moved_fd)
                except LauncherError:
                    _erase_credential_descriptor(source_fd)
                erased = True
            try:
                os.fsync(parent_fd)
            except OSError:
                raise LauncherError(code.replace("remove", "sync")) from None
    except LauncherError as error:
        if missing_ok and error.code == f"{code}_missing":
            return
        if erase and source_fd >= 0 and not erased:
            try:
                if not erase_attempted and expected_credential is not None:
                    _require_credential_descriptor_generation(
                        source_fd,
                        expected_credential,
                        replacement_code=f"{code}_replaced",
                    )
                erase_attempted = True
                _erase_credential_descriptor(source_fd)
            except LauncherError as erase_error:
                error.secondary = erase_error
        raise
    finally:
        if moved_fd >= 0:
            try:
                os.close(moved_fd)
            except OSError:
                pass
        if source_owned and source_fd >= 0:
            try:
                os.close(source_fd)
            except OSError:
                pass
        if owns_parent and parent_fd is not None and parent_fd >= 0:
            try:
                os.close(parent_fd)
            except OSError:
                pass


def _remove_bound_container(
    state: LauncherState,
    runner: Runner,
    environment: Mapping[str, str],
    executable: str,
) -> None:
    _revalidate_state_data_directory(state)
    try:
        _inspect_bound_container(
            state,
            runner,
            environment,
            executable,
            private_path=state.spec.data_dir,
            private_identity=state.data_identity,
        )
    except LauncherError as error:
        if error.code != "container_inspect_failed":
            raise
        # A retry after a successful exact rm may find no container. Query only
        # the pinned immutable ID so cleanup can finish without adopting a name
        # or scanning the engine for a substitute.
        _revalidate_state_data_directory(state)
        exists = invoke_runner(
            runner,
            (executable, "container", "exists", state.container_id),
            environment,
            CONTAINER_ACTION_TIMEOUT,
            failure_code="container_lookup_failed",
            private_path=state.spec.data_dir,
            private_identity=state.data_identity,
        )
        _revalidate_state_data_directory(state)
        if exists.returncode == 1:
            return
        if exists.returncode != 0:
            raise LauncherError("container_lookup_failed")
        raise
    _revalidate_state_data_directory(state)
    result = invoke_runner(
        runner,
        (executable, "rm", "--force", state.container_id),
        environment,
        CONTAINER_ACTION_TIMEOUT,
        failure_code="container_remove_failed",
        private_path=state.spec.data_dir,
        private_identity=state.data_identity,
    )
    _revalidate_state_data_directory(state)
    if result.returncode != 0:
        raise LauncherError("container_remove_failed")


def _require_exact_entry_absent(parent_fd: int, name: str, *, code: str) -> None:
    """Require one exact parent-relative entry to remain absent."""

    descriptor = -1
    try:
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY
                | _required_private_flag("O_NOFOLLOW")
                | _required_private_flag("O_NONBLOCK")
                | _required_private_flag("O_CLOEXEC"),
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            return
        except OSError:
            raise LauncherError(code) from None
        raise LauncherError(code)
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _require_absent(path: Path, *, code: str) -> None:
    """Reject a pre-existing run-scoped sibling without scanning or replacing it."""

    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError:
        raise LauncherError(code) from None
    raise LauncherError(f"{code}_exists")


def _require_absent_entry(parent_fd: int, name: str, *, code: str) -> None:
    """Check one child name through the already-held private parent fd."""

    try:
        descriptor = os.open(
            name,
            os.O_RDONLY
            | _required_private_flag("O_NOFOLLOW")
            | _required_private_flag("O_NONBLOCK")
            | _required_private_flag("O_CLOEXEC"),
            dir_fd=parent_fd,
        )
    except FileNotFoundError:
        return
    except OSError:
        raise LauncherError(code) from None
    try:
        raise LauncherError(f"{code}_exists")
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _validate_existing_start_state(
    state: LauncherState,
    spec: InstanceSpec,
    *,
    parent_fd: int,
) -> None:
    """Validate an existing marker transaction before any engine boundary."""

    _revalidate_state_records(state, parent_fd=parent_fd)
    if (
        state.spec.instance != spec.instance
        or state.spec.port != spec.port
        or state.spec.image != spec.image
        or state.spec.username != spec.username
    ):
        raise LauncherError("marker_spec_mismatch")
    if state.marker.status != live_run_marker.STATUS_RUNNING:
        raise LauncherError("cleanup_incomplete")
    _revalidate_credential_identity(state.marker, parent_fd=parent_fd)


def _prevalidate_start_marker(
    spec: InstanceSpec,
    marker_path: str | Path,
    *,
    port_checker: PortChecker = is_port_available,
) -> live_run_marker.MarkerPaths:
    """Preflight one marker's private records without Podman or publication."""

    paths = _marker_paths(marker_path)
    _validate_private_directory_path(spec.roots.data)
    _validate_private_directory_path(spec.data_dir)
    active = _ACTIVE_PARENT_LEASE.get()
    owns_parent = active is None
    if active is not None:
        if active.marker_path.parent != paths.marker.parent:
            raise LauncherError("runs_dir_replaced")
        _revalidate_private_parent_path(
            paths.marker,
            active.parent_fd,
            expected=active.identity,
            code="runs_dir",
        )
        parent_fd = active.parent_fd
    else:
        parent_fd = _open_private_parent(paths.marker, code="marker_path_invalid")
    primary_error: BaseException | None = None
    try:
        try:
            state = _load_bound_state(paths.marker, spec.roots, parent_fd=parent_fd)
        except LauncherError as error:
            if error.code != "marker_missing":
                raise
            # A markerless sibling set is not a fresh transaction. Reject it
            # before the first batch start rather than creating credentials and
            # relying on cleanup to discover stale private records later.
            _require_absent_entry(parent_fd, paths.state.name, code="state_path_invalid")
            _require_absent_entry(parent_fd, paths.credential.name, code="credential_path_invalid")
            _require_absent_entry(parent_fd, paths.cidfile.name, code="cidfile_path_invalid")
            if not port_checker(spec.port):
                raise LauncherError("port_unavailable")
            return paths
        _validate_existing_start_state(state, spec, parent_fd=parent_fd)
        return paths
    except BaseException as error:
        primary_error = error
        raise
    finally:
        if owns_parent:
            close_failure = _close_fd_best_effort(parent_fd)
            if close_failure is not None:
                if primary_error is not None:
                    _attach_secondary_failure(primary_error, close_failure)
                else:
                    raise close_failure


def _prevalidate_existing_start_containers(
    specs: Sequence[InstanceSpec],
    marker_paths: Sequence[Path],
    *,
    runner: Runner,
    executable: str | None,
    source_environment: Mapping[str, str] | None,
    port_checker: PortChecker,
) -> None:
    """Inspect all existing exact IDs before a batch can mutate one run."""

    existing: list[LauncherState] = []
    for spec, marker_path in zip(specs, marker_paths):
        paths = _marker_paths(marker_path)
        active = _ACTIVE_PARENT_LEASE.get()
        owns_parent = active is None
        if active is not None:
            if active.marker_path.parent != paths.marker.parent:
                raise LauncherError("runs_dir_replaced")
            _revalidate_private_parent_path(
                paths.marker,
                active.parent_fd,
                expected=active.identity,
                code="runs_dir",
            )
            parent_fd = active.parent_fd
        else:
            parent_fd = _open_private_parent(paths.marker, code="marker_path_invalid")
        primary_error: BaseException | None = None
        try:
            try:
                state = _load_bound_state(paths.marker, spec.roots, parent_fd=parent_fd)
            except LauncherError as error:
                if error.code == "marker_missing":
                    continue
                raise
            _validate_existing_start_state(state, spec, parent_fd=parent_fd)
            existing.append(state)
        except BaseException as error:
            primary_error = error
            raise
        finally:
            if owns_parent:
                close_failure = _close_fd_best_effort(parent_fd)
                if close_failure is not None:
                    if primary_error is not None:
                        _attach_secondary_failure(primary_error, close_failure)
                    else:
                        raise close_failure

    if not existing:
        return
    environment = clean_environment(source_environment)
    podman = executable or podman_path()
    podman_preflight(runner, environment, podman)
    for state in existing:
        _revalidate_state_data_directory(state)
        _, snapshot = _inspect_bound_container(state, runner, environment, podman)
        _revalidate_state_data_directory(state)
        if snapshot.status not in {"running", "configured", "created", "stopped", "exited", "dead"}:
            raise LauncherError("container_state_unrecoverable")
        if snapshot.status != "running" and not port_checker(state.spec.port):
            raise LauncherError("port_unavailable")


def _retain_cleanup_failed_in_place(
    state: LauncherState,
    tombstone: live_run_marker.RunMarker,
    *,
    expected_marker: FileIdentity | None,
    expected_state: FileIdentity | None,
    marker_generation: str | None,
    state_generation: str | None,
    parent_fd: int | None,
) -> None:
    """Retain cleanup evidence without allocating after quota saturation."""

    try:
        # Validate every still-present record before rewriting either sibling.
        # This prevents a same-inode mutation in the second record from being
        # hidden after the first record has already become a tombstone. Missing
        # records remain eligible for the historical recreation path.
        if parent_fd is None:
            return
        if expected_state is not None and state_generation is not None:
            try:
                _revalidate_private_generation(
                    state.marker.state_path,
                    expected_state,
                    state_generation,
                    maximum=MAX_STATE_BYTES,
                    code="state_identity",
                    replacement_code="state_replaced",
                    parent_fd=parent_fd,
                )
            except LauncherError as error:
                if error.code != "state_identity_missing":
                    return
        if expected_marker is not None and marker_generation is not None:
            try:
                _revalidate_private_generation(
                    state.marker_path,
                    expected_marker,
                    marker_generation,
                    maximum=live_run_marker.MAX_MARKER_BYTES,
                    code="marker_identity",
                    replacement_code="marker_replaced",
                    parent_fd=parent_fd,
                )
            except LauncherError as error:
                if error.code != "marker_identity_missing":
                    return

        if expected_state is not None:
            try:
                _rewrite_state_exact(
                    state.spec,
                    tombstone,
                    expected_state,
                    expected_generation=state_generation,
                    parent_fd=parent_fd,
                    data_identity=state.data_identity,
                )
            except LauncherError as error:
                if not error.code.endswith("_missing"):
                    return
                write_state(
                    state.spec,
                    tombstone,
                    parent_fd=parent_fd,
                    data_identity=state.data_identity,
                )
        else:
            try:
                _file_identity(state.marker.state_path, code="state", parent_fd=parent_fd)
            except LauncherError as error:
                if error.code != "state_missing":
                    return
                write_state(
                    state.spec,
                    tombstone,
                    parent_fd=parent_fd,
                    data_identity=state.data_identity,
                )
            else:
                return

        if expected_marker is not None:
            try:
                live_run_marker.rewrite_marker_exact(
                    tombstone,
                    expected_marker,
                    expected_generation=marker_generation,
                    parent_fd=parent_fd,
                )
            except live_run_marker.MarkerError as error:
                if error.code != "marker_missing":
                    return
                live_run_marker.create_marker(tombstone, parent_fd=parent_fd)
        else:
            try:
                _file_identity(state.marker_path, code="marker", parent_fd=parent_fd)
            except LauncherError as error:
                if error.code != "marker_missing":
                    return
                live_run_marker.create_marker(tombstone, parent_fd=parent_fd)
            else:
                return
    except BaseException:
        # The fallback is still descriptor-identity pinned. A raced or missing
        # inode remains untouched rather than turning quota recovery into an
        # adoption path.
        return


def _retain_cleanup_failed(
    state: LauncherState,
    *,
    expected_marker: FileIdentity | None = None,
    expected_state: FileIdentity | None = None,
    marker_generation: str | None = None,
    state_generation: str | None = None,
    parent_fd: int | None = None,
) -> None:
    """Retain a bounded tombstone without adopting raced pathnames.

    Existing entries are claimed with the same no-replace quarantine protocol
    used for final cleanup. A replacement is never overwritten; if claiming it
    fails, the private replacement or quarantine remains as evidence.
    """

    tombstone = live_run_marker.cleanup_failed(state.marker)
    try:
        if expected_state is None:
            try:
                _file_identity(state.marker.state_path, code="state", parent_fd=parent_fd)
            except LauncherError as error:
                if error.code != "state_missing":
                    return
            else:
                return
        else:
            _remove_exact_file(
                state.marker.state_path,
                code="state_remove_failed",
                expected=expected_state,
                expected_generation=state_generation,
                generation_maximum=MAX_STATE_BYTES,
                missing_ok=True,
                parent_fd=parent_fd,
            )
        write_state(
            state.spec,
            tombstone,
            replace=False,
            parent_fd=parent_fd,
            data_identity=state.data_identity,
        )

        if expected_marker is None:
            try:
                _file_identity(state.marker_path, code="marker", parent_fd=parent_fd)
            except LauncherError as error:
                if error.code != "marker_missing":
                    return
            else:
                return
        else:
            _remove_exact_file(
                state.marker_path,
                code="marker_remove_failed",
                expected=expected_marker,
                expected_generation=marker_generation,
                generation_maximum=live_run_marker.MAX_MARKER_BYTES,
                missing_ok=True,
                parent_fd=parent_fd,
            )
        live_run_marker.create_marker(tombstone, parent_fd=parent_fd)
    except LauncherError as error:
        if error.code == "quarantine_quota_exceeded" and parent_fd is not None:
            _retain_cleanup_failed_in_place(
                state,
                tombstone,
                expected_marker=expected_marker,
                expected_state=expected_state,
                marker_generation=marker_generation,
                state_generation=state_generation,
                parent_fd=parent_fd,
            )
        # Cleanup evidence is best effort, but it must never turn an original
        # bounded launcher error into a traceback or overwrite a replacement.
        return
    except BaseException:
        # Cleanup evidence is best effort, but it must never turn an original
        # bounded launcher error into a traceback or overwrite a replacement.
        return


def _cleanup_started_run(
    spec: InstanceSpec,
    binding: live_run_marker.RunMarker,
    *,
    marker_identity: FileIdentity | None,
    state_identity: FileIdentity | None,
    marker_generation: str | None = None,
    state_generation: str | None = None,
    cidfile_identity: FileIdentity | None,
    data_identity: DirectoryIdentity | None = None,
    runner: Runner,
    executable: str,
    source_environment: Mapping[str, str] | None,
    parent_fd: int | None = None,
) -> None:
    """Clean a just-created run by exact identities, even before publication.

    Lifecycle callers pass the identity captured before Podman dispatch. The
    fallback exists only for older direct test/utility callers; recovery paths
    load and require the persisted identity instead of taking this fallback.
    """

    if data_identity is None:
        data_identity = _current_private_directory_identity(spec.data_dir)
    state = LauncherState(
        spec=spec,
        marker=binding,
        marker_identity=marker_identity,
        state_identity=state_identity,
        data_identity=data_identity,
        marker_generation=marker_generation,
        state_generation=state_generation,
    )
    cleanup_error: LauncherError | None = None
    credential_proof_failed = False
    container_unproven = False
    data_path_unproven = False
    try:
        environment = clean_environment(source_environment)
    except BaseException:
        environment = {}
        cleanup_error = LauncherError("cleanup_environment_failed")

    if cleanup_error is None:
        try:
            _revalidate_credential_identity(binding, parent_fd=parent_fd)
        except BaseException as error:
            credential_proof_failed = True
            cleanup_error = LauncherError(
                error.code if isinstance(error, LauncherError) else "credential_identity_mismatch"
            )

    if cleanup_error is None or credential_proof_failed:
        # A swapped credential is evidence of an unsafe publication, but it
        # does not invalidate the immutable container ID or stable data witness
        # captured by this transaction. Attempt exact-ID removal anyway; if the
        # data proof or engine ownership is also lost, retain bounded evidence
        # instead of leaving a running child without a manageable tombstone.
        try:
            _remove_bound_container(state, runner, environment, executable)
            if marker_identity is not None or state_identity is not None:
                if parent_fd is None:
                    raise LauncherError("ownership_snapshot_missing")
                if marker_identity is not None:
                    _revalidate_private_generation(
                        binding.marker_path,
                        marker_identity,
                        marker_generation,
                        maximum=live_run_marker.MAX_MARKER_BYTES,
                        code="marker_identity",
                        replacement_code="marker_replaced",
                        parent_fd=parent_fd,
                    )
                if state_identity is not None:
                    _revalidate_private_generation(
                        binding.state_path,
                        state_identity,
                        state_generation,
                        maximum=MAX_STATE_BYTES,
                        code="state_identity",
                        replacement_code="state_replaced",
                        parent_fd=parent_fd,
                    )
        except BaseException as error:
            if cleanup_error is None:
                cleanup_error = error if isinstance(error, LauncherError) else LauncherError("container_remove_failed")
            if isinstance(error, LauncherError) and error.code in {
                "container_not_launcher_owned",
                "container_identity_unproven",
                "container_replaced",
            }:
                container_unproven = True
            if isinstance(error, LauncherError) and error.code in {
                "owned_path_replaced",
                "ownership_snapshot_missing",
            }:
                data_path_unproven = True

    if cidfile_identity is not None:
        try:
            _remove_exact_file(
                binding.marker_path.with_name(f"{binding.marker_path.stem}.cidfile"),
                code="cidfile_remove_failed",
                expected=cidfile_identity,
                parent_fd=parent_fd,
            )
        except BaseException:
            if cleanup_error is None:
                cleanup_error = LauncherError("cidfile_remove_failed")

    if cleanup_error is None or data_path_unproven:
        try:
            # Exact launcher-owned records may still be removed when the data
            # pathname is unproven; this never touches the replacement tree.
            # If that proof failure leaves the container running, the final
            # cleanup_failed tombstone below preserves bounded exact-ID evidence
            # so a later data restoration can retry removal safely.
            _remove_exact_file(
                binding.credential_path,
                code="credential_remove_failed",
                expected=binding.credential_identity,
                erase=True,
                parent_fd=parent_fd,
            )
            if state_identity is not None:
                _remove_exact_file(
                    binding.state_path,
                    code="state_remove_failed",
                    expected=state_identity,
                    expected_generation=state_generation,
                    generation_maximum=MAX_STATE_BYTES,
                    parent_fd=parent_fd,
                )
            if marker_identity is not None:
                _remove_marker_last(
                    state,
                    marker_identity,
                    expected_generation=marker_generation,
                    parent_fd=parent_fd,
                )
        except BaseException as error:
            cleanup_error = error if isinstance(error, LauncherError) else LauncherError("cleanup_failed")
            # Exact record cleanup failure requires bounded tombstone evidence;
            # do not suppress it merely because the data identity also failed.
            data_path_unproven = False

    if cleanup_error is not None:
        tombstone_state = state
        if container_unproven:
            tombstone_state = LauncherState(
                spec=spec,
                marker=binding.with_container_id(UNPROVEN_CONTAINER_ID),
                marker_identity=marker_identity,
                state_identity=state_identity,
                data_identity=data_identity,
                marker_generation=marker_generation,
                state_generation=state_generation,
            )
        _retain_cleanup_failed(
            tombstone_state,
            expected_marker=marker_identity,
            expected_state=state_identity,
            marker_generation=marker_generation,
            state_generation=state_generation,
            parent_fd=parent_fd,
        )


def _start_instance_with_parent(
    spec: InstanceSpec,
    *,
    marker_path: str | Path,
    paths: live_run_marker.MarkerPaths,
    runs_parent_fd: int,
    runner: Runner = run_command,
    readiness: ReadinessChecker = check_provider_readiness,
    port_checker: PortChecker = is_port_available,
    attempts: int = 60,
    interval: float = 1,
    executable: str | None = None,
    source_environment: Mapping[str, str] | None = None,
) -> tuple[dict[str, object], bool]:
    _validate_start_spec(spec)
    _validate_readiness_options(attempts, interval)
    environment = clean_environment(source_environment)
    _revalidate_private_parent_path(paths.marker, runs_parent_fd, code="runs_dir")
    _validate_private_directory_path(spec.roots.data)
    data_path = _validate_private_directory_path(spec.data_dir)

    try:
        state = _load_bound_state(paths.marker, spec.roots, parent_fd=runs_parent_fd)
    except LauncherError as error:
        if error.code != "marker_missing":
            raise
        state = None

    data_identity: DirectoryIdentity | None = None
    if state is not None:
        _validate_existing_start_state(state, spec, parent_fd=runs_parent_fd)
        data_identity = state.data_identity
        if data_identity is None:
            raise LauncherError("ownership_snapshot_missing")
    else:
        # The selected port is a pure preflight for a new run. Do it before
        # rootless Podman checks, image pull/inspect, or any data-root mkdir.
        if not port_checker(spec.port):
            raise LauncherError("port_unavailable")
        _require_absent_entry(runs_parent_fd, paths.state.name, code="state_path_invalid")
        _require_absent_entry(runs_parent_fd, paths.credential.name, code="credential_path_invalid")
        _require_absent_entry(runs_parent_fd, paths.cidfile.name, code="cidfile_path_invalid")

    if state is None:
        # New-run data creation is still pure descriptor-bound preflight. Hold
        # the validated data-root descriptor while claiming the instance leaf;
        # a replacement root cannot redirect the child to a new tree between
        # lexical preflight and the relative mkdir/open boundary.
        data_path, data_identity = _ensure_private_data_directory_with_parent(
            spec.roots.data,
            data_path,
        )
        _revalidate_private_directory_identity(data_path, data_identity)

    podman = executable or podman_path()
    podman_preflight(runner, environment, podman)
    if state is not None:
        # Classify the exact retained container before image work. A stopped
        # owned record gets its port check before pull/inspect; a running record
        # is exempt because its own container necessarily owns that port.
        _revalidate_state_data_directory(state)
        document, current = _inspect_bound_container(state, runner, environment, podman)
        _revalidate_state_data_directory(state)
        original_status = current.status
        if original_status not in {"running", "configured", "created", "stopped", "exited", "dead"}:
            raise LauncherError("container_state_unrecoverable")
        if original_status != "running" and not port_checker(spec.port):
            raise LauncherError("port_unavailable")
    verify_image(spec.image, runner, environment, podman)
    if state is not None:
        # Existing records carry the only trusted data-directory identity. Do
        # not recapture the current pathname here: a replacement tree must fail
        # rather than become the new recovery target after image work.
        assert data_identity is not None
        _revalidate_private_directory_identity(data_path, data_identity)

    if state is not None:
        if original_status == "running":
            _revalidate_state_data_directory(state)
            readiness(state.marker.endpoint, attempts, interval)
            _revalidate_state_data_directory(state)
            _require_running_container(state, runner, environment, podman)
            _revalidate_private_parent_path(paths.marker, runs_parent_fd, code="runs_dir")
            _revalidate_state_records(state, parent_fd=runs_parent_fd)
            published_state_identity = write_state(
                state.spec,
                state.marker,
                replace=True,
                expected=state.state_identity,
                expected_generation=state.state_generation,
                parent_fd=runs_parent_fd,
                data_identity=state.data_identity,
            )
            current_state_identity, current_state_generation = _private_record_snapshot(
                state.marker.state_path,
                maximum=MAX_STATE_BYTES,
                code="state_identity",
                parent_fd=runs_parent_fd,
            )
            if current_state_identity != published_state_identity:
                raise LauncherError("state_replaced")
            _revalidate_private_generation(
                state.marker_path,
                state.marker_identity,
                state.marker_generation,
                maximum=live_run_marker.MAX_MARKER_BYTES,
                code="marker_identity",
                replacement_code="marker_replaced",
                parent_fd=runs_parent_fd,
            )
            _revalidate_private_generation(
                state.marker.state_path,
                current_state_identity,
                current_state_generation,
                maximum=MAX_STATE_BYTES,
                code="state_identity",
                replacement_code="state_replaced",
                parent_fd=runs_parent_fd,
            )
            _revalidate_credential_identity(state.marker, parent_fd=runs_parent_fd)
            _revalidate_private_parent_path(paths.marker, runs_parent_fd, code="runs_dir")
            _revalidate_state_data_directory(state)
            published_state = replace(
                state,
                state_identity=current_state_identity,
                state_generation=current_state_generation,
            )
            _before_public_return("start-running")
            _revalidate_public_state(
                published_state,
                parent_fd=runs_parent_fd,
                runner=runner,
                environment=environment,
                executable=podman,
                require_running=True,
                require_endpoint=True,
                absent_names=((paths.cidfile.name, "cidfile_replaced"),),
            )
            return _public_run_result(spec, published_state.marker, status="ready", created=False), False
        if original_status not in {"configured", "created", "stopped", "exited", "dead"}:
            raise LauncherError("container_state_unrecoverable")
        if not port_checker(spec.port):
            raise LauncherError("port_unavailable")
        _revalidate_state_data_directory(state)
        fresh = _inspect_bound_container(state, runner, environment, podman)[1]
        _revalidate_state_data_directory(state)
        if fresh.status != original_status:
            raise LauncherError("container_recovery_race")
        recovery_attempted = False
        final_fence_attempted = False
        published_state = state
        try:
            recovery_attempted = True
            _revalidate_state_data_directory(state)
            _run_container_action(
                state.container_id,
                "start",
                runner,
                environment,
                podman,
                "container_start_failed",
                private_path=state.spec.data_dir,
                private_identity=state.data_identity,
            )
            _revalidate_state_data_directory(state)
            readiness(state.marker.endpoint, attempts, interval)
            _revalidate_state_data_directory(state)
            _require_running_container(state, runner, environment, podman)
            _revalidate_private_parent_path(paths.marker, runs_parent_fd, code="runs_dir")
            _revalidate_state_records(state, parent_fd=runs_parent_fd)
            published_state_identity = write_state(
                state.spec,
                state.marker,
                replace=True,
                expected=state.state_identity,
                expected_generation=state.state_generation,
                parent_fd=runs_parent_fd,
                data_identity=state.data_identity,
            )
            current_state_identity, current_state_generation = _private_record_snapshot(
                state.marker.state_path,
                maximum=MAX_STATE_BYTES,
                code="state_identity",
                parent_fd=runs_parent_fd,
            )
            if current_state_identity != published_state_identity:
                raise LauncherError("state_replaced")
            _revalidate_private_generation(
                state.marker_path,
                state.marker_identity,
                state.marker_generation,
                maximum=live_run_marker.MAX_MARKER_BYTES,
                code="marker_identity",
                replacement_code="marker_replaced",
                parent_fd=runs_parent_fd,
            )
            _revalidate_private_generation(
                state.marker.state_path,
                current_state_identity,
                current_state_generation,
                maximum=MAX_STATE_BYTES,
                code="state_identity",
                replacement_code="state_replaced",
                parent_fd=runs_parent_fd,
            )
            _revalidate_credential_identity(state.marker, parent_fd=runs_parent_fd)
            _revalidate_private_parent_path(paths.marker, runs_parent_fd, code="runs_dir")
            published_state = replace(
                state,
                state_identity=current_state_identity,
                state_generation=current_state_generation,
            )
            # Keep the final publication fence inside the recovery try block so
            # a post-state-write record, credential, parent, container, or data
            # swap enters exact-ID rollback instead of returning ready metadata.
            final_fence_attempted = True
            _before_public_return("start-recovery")
            _revalidate_public_state(
                published_state,
                parent_fd=runs_parent_fd,
                runner=runner,
                environment=environment,
                executable=podman,
                require_running=True,
                require_endpoint=True,
                absent_names=((paths.cidfile.name, "cidfile_replaced"),),
            )
        except BaseException as exc:
            rollback_error: LauncherError | None = None
            if recovery_attempted:
                try:
                    rollback_state = _inspect_bound_container(state, runner, environment, podman)[1]
                    if rollback_state.status == "running":
                        _revalidate_state_data_directory(state)
                        _run_container_action(
                            state.container_id,
                            "stop",
                            runner,
                            environment,
                            podman,
                            "container_recovery_rollback_failed",
                            private_path=state.spec.data_dir,
                            private_identity=state.data_identity,
                        )
                        _revalidate_state_data_directory(state)
                    elif rollback_state.status != original_status:
                        rollback_error = LauncherError("container_recovery_rollback_failed")
                except LauncherError as rollback:
                    rollback_error = rollback
            if final_fence_attempted and rollback_error is not None:
                try:
                    _retain_cleanup_failed(
                        published_state,
                        expected_marker=published_state.marker_identity,
                        expected_state=published_state.state_identity,
                        marker_generation=published_state.marker_generation,
                        state_generation=published_state.state_generation,
                        parent_fd=runs_parent_fd,
                    )
                except BaseException:
                    # The exact replacement or unavailable parent remains
                    # evidence; never turn bounded cleanup into adoption.
                    pass
            if isinstance(exc, LauncherError):
                if rollback_error is not None:
                    _attach_secondary_failure(exc, rollback_error)
                raise
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            if rollback_error is not None:
                raise LauncherError("container_recovery_failed", secondary=rollback_error) from None
            raise LauncherError("container_recovery_failed") from None
        return _public_run_result(spec, published_state.marker, status="ready", created=False), False

    # A container under the deterministic name without its exact marker is not
    # adoptable. In particular, a stopped or foreign object is never started or
    # removed merely because its name resembles this instance.
    if container_exists(spec, runner, environment, podman):
        raise LauncherError("marker_missing")
    # Repeat immediately before publication to narrow the port TOCTOU window.
    # This path is only for a new marker; valid running records skip port checks
    # because their own retained container already owns the selected port.
    if not port_checker(spec.port):
        raise LauncherError("port_unavailable")

    # Generate the opaque run identity before the first container-start command.
    # The engine-emitted cidfile is the private immutable handoff for both a
    # normal return and a runner that raises after creating the container.
    run_id = live_run_marker.new_run_id()
    credential_identity: live_run_marker.CredentialIdentity | None = None
    cidfile_identity: FileIdentity | None = None
    binding: live_run_marker.RunMarker | None = None
    marker_identity: FileIdentity | None = None
    state_identity: FileIdentity | None = None
    marker_generation: str | None = None
    state_generation: str | None = None
    run_container_id: str | None = None
    try:
        _require_absent_entry(runs_parent_fd, paths.cidfile.name, code="cidfile_path_invalid")
        try:
            password, credential_identity = create_run_credential(paths.marker, parent_fd=runs_parent_fd)
        except OwnedFileError as error:
            credential_identity = live_run_marker.CredentialIdentity(
                error.identity[0], error.identity[1], error.identity[2], error.identity[3], error.identity[4]
            )
            raise
        child_environment = dict(environment)
        child_environment.update(
            {
                "HERMES_DASHBOARD": "1",
                "HERMES_DASHBOARD_BASIC_AUTH_USERNAME": spec.username,
                "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD": password,
            }
        )

        # Keep invocation itself inside the transaction. A synchronous runner
        # may raise after the engine has created a container and written cidfile.
        try:
            started = invoke_runner(
                runner,
                run_arguments(spec, podman, run_id, cidfile=paths.cidfile, data_path=data_path),
                child_environment,
                300,
                failure_code="container_start_failed",
                private_path=data_path,
                private_identity=data_identity,
            )
        except LauncherError as runner_error:
            # The runner may raise after Podman has already written cidfile.
            # Recover only that immutable engine-emitted ID; never inspect or
            # adopt a mutable container name from this failure path. A malformed
            # cidfile carries its exact inode for safe disposal but never proves
            # a container identity.
            _revalidate_private_parent_path(paths.marker, runs_parent_fd, code="runs_dir")
            try:
                run_container_id, cidfile_identity = read_cidfile(paths.cidfile, parent_fd=runs_parent_fd)
            except OwnedFileError as error:
                cidfile_identity = error.identity
                raise runner_error
            except LauncherError:
                raise runner_error
            raise runner_error
        _revalidate_private_parent_path(paths.marker, runs_parent_fd, code="runs_dir")
        try:
            run_container_id, cidfile_identity = read_cidfile(paths.cidfile, parent_fd=runs_parent_fd)
        except OwnedFileError as error:
            cidfile_identity = error.identity
            raise
        if started.returncode != 0:
            raise LauncherError("container_start_failed")

        try:
            binding = live_run_marker.new_marker(
                paths.marker,
                run_id=run_id,
                instance=spec.instance,
                container_id=run_container_id,
                container_name=spec.container,
                image=spec.image,
                endpoint=spec.endpoint,
                credential_identity=credential_identity,
                data_identity=data_identity,
            )
        except live_run_marker.MarkerError as error:
            raise LauncherError(error.code) from None
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException:
            raise LauncherError("marker_build_failed") from None
        try:
            state_identity = write_state(
                spec,
                binding,
                parent_fd=runs_parent_fd,
                data_identity=data_identity,
            )
        except OwnedFileError as error:
            # write_state returns only after its parent sync succeeds. If that
            # sync fails after creation, retain the exact created inode here so
            # cleanup cannot orphan the state sibling. Capture its generation
            # from the same exact pathname before handing it to cleanup; a
            # missing snapshot remains fail-closed evidence rather than an
            # identity-only deletion path.
            state_identity = error.identity
            try:
                captured_state_identity, state_generation = _private_record_snapshot(
                    paths.state,
                    maximum=MAX_STATE_BYTES,
                    code="state_identity",
                    parent_fd=runs_parent_fd,
                )
                if captured_state_identity != state_identity:
                    state_generation = None
            except LauncherError:
                state_generation = None
            raise

        assert credential_identity is not None
        assert state_identity is not None
        captured_state_identity, state_generation = _private_record_snapshot(
            paths.state,
            maximum=MAX_STATE_BYTES,
            code="state_identity",
            parent_fd=runs_parent_fd,
        )
        if captured_state_identity != state_identity:
            raise LauncherError("state_replaced")
        _revalidate_credential_identity(binding, parent_fd=runs_parent_fd)
        _revalidate_private_generation(
            paths.state,
            state_identity,
            state_generation,
            maximum=MAX_STATE_BYTES,
            code="state_identity",
            replacement_code="state_replaced",
            parent_fd=runs_parent_fd,
        )
        _revalidate_private_parent_path(paths.marker, runs_parent_fd, code="runs_dir")
        try:
            marker_identity = live_run_marker.create_marker(binding, parent_fd=runs_parent_fd)
        except live_run_marker.OwnedMarkerError as error:
            marker_identity = error.identity
            raise LauncherError(error.code) from None
        except live_run_marker.MarkerError as error:
            raise LauncherError(error.code) from None
        captured_marker_identity, marker_generation = _private_record_snapshot(
            paths.marker,
            maximum=live_run_marker.MAX_MARKER_BYTES,
            code="marker_identity",
            parent_fd=runs_parent_fd,
        )
        if captured_marker_identity != marker_identity:
            raise LauncherError("marker_replaced")

        _revalidate_private_generation(
            paths.marker,
            marker_identity,
            marker_generation,
            maximum=live_run_marker.MAX_MARKER_BYTES,
            code="marker_identity",
            replacement_code="marker_replaced",
            parent_fd=runs_parent_fd,
        )
        _revalidate_private_generation(
            paths.state,
            state_identity,
            state_generation,
            maximum=MAX_STATE_BYTES,
            code="state_identity",
            replacement_code="state_replaced",
            parent_fd=runs_parent_fd,
        )
        _revalidate_credential_identity(binding, parent_fd=runs_parent_fd)
        _revalidate_private_parent_path(paths.marker, runs_parent_fd, code="runs_dir")

        # Every post-run check targets the immutable ID emitted above. A
        # wildcard or otherwise mismatched mapping can therefore use the same
        # exact cleanup path without adopting a replacement under the name.
        document = inspect_container(
            spec,
            runner,
            environment,
            podman,
            target=run_container_id,
            private_path=data_path,
            private_identity=data_identity,
        )
        _revalidate_private_directory_identity(data_path, data_identity)
        snapshot = recovery_snapshot(spec, document, run_id=run_id)
        if snapshot.container_id != run_container_id:
            raise LauncherError("container_replaced")
        if snapshot.status != "running":
            raise LauncherError("container_not_running")
        require_loopback_endpoint_mapping(spec, document)
        _revalidate_private_directory_identity(data_path, data_identity)
        readiness(binding.endpoint, attempts, interval)
        _revalidate_private_directory_identity(data_path, data_identity)
        final_document = inspect_container(
            spec,
            runner,
            environment,
            podman,
            target=run_container_id,
            private_path=data_path,
            private_identity=data_identity,
        )
        _revalidate_private_directory_identity(data_path, data_identity)
        final_snapshot = recovery_snapshot(spec, final_document, run_id=run_id)
        if final_snapshot.container_id != run_container_id:
            raise LauncherError("container_replaced")
        if final_snapshot.status != "running":
            raise LauncherError("container_not_running")
        require_loopback_endpoint_mapping(spec, final_document)
        _revalidate_private_generation(
            paths.marker,
            marker_identity,
            marker_generation,
            maximum=live_run_marker.MAX_MARKER_BYTES,
            code="marker_identity",
            replacement_code="marker_replaced",
            parent_fd=runs_parent_fd,
        )
        _revalidate_private_generation(
            paths.state,
            state_identity,
            state_generation,
            maximum=MAX_STATE_BYTES,
            code="state_identity",
            replacement_code="state_replaced",
            parent_fd=runs_parent_fd,
        )
        _revalidate_credential_identity(binding, parent_fd=runs_parent_fd)
        _revalidate_private_parent_path(paths.marker, runs_parent_fd, code="runs_dir")
        if cidfile_identity is not None:
            _remove_exact_file(
                paths.cidfile,
                code="cidfile_remove_failed",
                expected=cidfile_identity,
                parent_fd=runs_parent_fd,
            )
            cidfile_identity = None
            # Cidfile removal is the last injected filesystem boundary before
            # publication. Recheck the exact data directory after it; a swap
            # here must fail and enter exact cleanup instead of returning a
            # ready marker for a replacement pathname.
            _revalidate_private_directory_identity(data_path, data_identity)
        _revalidate_private_parent_path(paths.marker, runs_parent_fd, code="runs_dir")
        _revalidate_private_generation(
            paths.marker,
            marker_identity,
            marker_generation,
            maximum=live_run_marker.MAX_MARKER_BYTES,
            code="marker_identity",
            replacement_code="marker_replaced",
            parent_fd=runs_parent_fd,
        )
        _revalidate_private_generation(
            paths.state,
            state_identity,
            state_generation,
            maximum=MAX_STATE_BYTES,
            code="state_identity",
            replacement_code="state_replaced",
            parent_fd=runs_parent_fd,
        )
        _revalidate_credential_identity(binding, parent_fd=runs_parent_fd)
        _revalidate_private_parent_path(paths.marker, runs_parent_fd, code="runs_dir")
        final_state = LauncherState(
            spec,
            binding,
            marker_identity=marker_identity,
            state_identity=state_identity,
            data_identity=data_identity,
            marker_generation=marker_generation,
            state_generation=state_generation,
        )
        # Keep the final publication fence inside the exact-ID cleanup
        # transaction. A record, credential, parent, container, cidfile, or data
        # swap after this hook must not return ready for an unmanaged run.
        _before_public_return("start-new")
        _revalidate_public_state(
            final_state,
            parent_fd=runs_parent_fd,
            runner=runner,
            environment=environment,
            executable=podman,
            require_running=True,
            require_endpoint=True,
            absent_names=((paths.cidfile.name, "cidfile_replaced"),),
        )
    except BaseException:
        if credential_identity is not None and run_container_id is not None:
            if binding is None:
                # Do not invoke the validating publication constructor from an
                # error path. Its failure must not mask the original exception
                # or prevent cleanup of the already-proven exact identities.
                binding = _cleanup_binding(
                    paths,
                    spec,
                    run_id=run_id,
                    container_id=run_container_id,
                    credential_identity=credential_identity,
                    data_identity=data_identity,
                )
            try:
                _cleanup_started_run(
                    spec,
                    binding,
                    marker_identity=marker_identity,
                    state_identity=state_identity,
                    data_identity=data_identity,
                    marker_generation=marker_generation,
                    state_generation=state_generation,
                    cidfile_identity=cidfile_identity,
                    runner=runner,
                    executable=podman,
                    source_environment=source_environment,
                    parent_fd=runs_parent_fd,
                )
            except BaseException:
                try:
                    _retain_cleanup_failed(
                        LauncherState(
                            spec,
                            binding,
                            marker_identity=marker_identity,
                            state_identity=state_identity,
                            data_identity=data_identity,
                            marker_generation=marker_generation,
                            state_generation=state_generation,
                        ),
                        expected_marker=marker_identity,
                        expected_state=state_identity,
                        marker_generation=marker_generation,
                        state_generation=state_generation,
                        parent_fd=runs_parent_fd,
                    )
                except BaseException:
                    pass
        elif credential_identity is not None:
            # No immutable ID exists: never rediscover or adopt by mutable
            # name. Erase only the credential and retain a private sentinel
            # tombstone as bounded evidence of the unknown engine outcome.
            if cidfile_identity is not None:
                try:
                    _remove_exact_file(
                        paths.cidfile,
                        code="cidfile_remove_failed",
                        expected=cidfile_identity,
                        parent_fd=runs_parent_fd,
                    )
                except BaseException:
                    pass
            try:
                _remove_exact_file(
                    paths.credential,
                    code="credential_remove_failed",
                    expected=credential_identity,
                    erase=True,
                    parent_fd=runs_parent_fd,
                )
            except BaseException:
                pass
            try:
                unknown = _cleanup_binding(
                    paths,
                    spec,
                    run_id=run_id,
                    container_id=UNPROVEN_CONTAINER_ID,
                    credential_identity=credential_identity,
                    data_identity=data_identity,
                )
                _retain_cleanup_failed(
                    LauncherState(spec, unknown, data_identity=data_identity),
                    parent_fd=runs_parent_fd,
                )
            except BaseException:
                pass
        raise
    assert binding is not None
    return _public_run_result(spec, binding, status="ready", created=True), True


def start_instance(
    spec: InstanceSpec,
    *,
    marker_path: str | Path | None = None,
    runner: Runner = run_command,
    readiness: ReadinessChecker = check_provider_readiness,
    port_checker: PortChecker = is_port_available,
    attempts: int = 60,
    interval: float = 1,
    executable: str | None = None,
    source_environment: Mapping[str, str] | None = None,
) -> tuple[dict[str, object], bool]:
    """Run one lifecycle transaction under one pinned runs-directory fd."""

    _validate_start_spec(spec)
    _validate_readiness_options(attempts, interval)
    if marker_path is None:
        raise LauncherError("marker_required")
    # Validate injected adapters before marker-path preflight or the shared
    # lifecycle lease. A malformed runner must not create a lock, data root,
    # credential, state record, or any engine boundary.
    if not callable(runner):
        raise LauncherError("runner_invalid")
    if not callable(port_checker):
        raise LauncherError("port_checker_invalid")
    if executable is not None and type(executable) is not str:
        raise LauncherError("executable_invalid")
    if source_environment is not None and not isinstance(source_environment, Mapping):
        raise LauncherError("environment_invalid")
    paths = _marker_paths(marker_path)
    # Perform the advisory pure-record/data-root/port pass before creating the
    # lifecycle lock. The descriptor-bound transaction below repeats every
    # check after acquiring its lease and remains the authoritative gate.
    _prevalidate_start_marker(spec, paths.marker, port_checker=port_checker)
    with _operation_lease(paths.marker, code="marker_path_invalid") as lease:
        return _start_instance_with_parent(
            spec,
            marker_path=paths.marker,
            paths=paths,
            runs_parent_fd=lease.parent_fd,
            runner=runner,
            readiness=readiness,
            port_checker=port_checker,
            attempts=attempts,
            interval=interval,
            executable=executable,
            source_environment=source_environment,
        )


def start_many(
    specs: Sequence[InstanceSpec],
    marker_paths: Sequence[str | Path] | None = None,
    **kwargs: object,
) -> list[dict[str, object]]:
    if not specs:
        raise LauncherError("instance_count_invalid")
    attempts = kwargs.get("attempts", 60)
    interval = kwargs.get("interval", 1)
    _validate_readiness_options(attempts, interval)  # type: ignore[arg-type]
    for spec in specs:
        _validate_start_spec(spec)
    if marker_paths is None or len(marker_paths) != len(specs):
        raise LauncherError("marker_count_invalid")
    if len({spec.instance for spec in specs}) != len(specs) or len({spec.port for spec in specs}) != len(specs):
        raise LauncherError("batch_not_unique")
    try:
        canonical_marker_paths = tuple(_marker_paths(path).marker for path in marker_paths)
    except LauncherError:
        raise
    if len(set(canonical_marker_paths)) != len(canonical_marker_paths):
        raise LauncherError("marker_not_unique")
    canonical_marker_parents = {path.parent for path in canonical_marker_paths}
    if len(canonical_marker_parents) != 1:
        # A batch is one caller-selected private runs directory transaction;
        # reject split parents before opening either directory or dispatching a
        # lifecycle operation.
        raise LauncherError("marker_parent_mismatch")

    # Validate injected callables and scalar adapters before opening the shared
    # lease. Invalid runner input is pure validation failure and must not create
    # ``.lifecycle.lock`` or any other marker-parent side effect.
    port_checker = kwargs.get("port_checker", is_port_available)
    if not callable(port_checker):
        raise LauncherError("port_checker_invalid")
    runner = kwargs.get("runner", run_command)
    if not callable(runner):
        raise LauncherError("runner_invalid")
    executable = kwargs.get("executable")
    if executable is not None and type(executable) is not str:
        raise LauncherError("executable_invalid")
    source_environment = kwargs.get("source_environment")
    if source_environment is not None and not isinstance(source_environment, Mapping):
        raise LauncherError("environment_invalid")

    # Reject split parents before opening either directory. After that pure
    # comparison, keep one descriptor-bound parent lease for the advisory
    # preflight and every per-marker transaction. This is still non-atomic:
    # earlier markers remain published when a later marker fails, but a parent
    # identity replacement cannot redirect the next marker to a new directory.
    with _operation_lease(canonical_marker_paths[0], code="marker_path_invalid"):
        exact_marker_paths = tuple(
            _prevalidate_start_marker(spec, marker_path, port_checker=port_checker)
            .marker
            for spec, marker_path in zip(specs, canonical_marker_paths)
        )
        _prevalidate_existing_start_containers(
            specs,
            exact_marker_paths,
            runner=runner,  # type: ignore[arg-type]
            executable=executable,  # type: ignore[arg-type]
            source_environment=source_environment,  # type: ignore[arg-type]
            port_checker=port_checker,
        )

        results: list[dict[str, object]] = []
        try:
            for spec, marker_path in zip(specs, exact_marker_paths):
                active = _ACTIVE_PARENT_LEASE.get()
                if active is None:
                    raise LauncherError("runs_dir_replaced")
                _revalidate_private_parent_path(
                    marker_path,
                    active.parent_fd,
                    expected=active.identity,
                    code="runs_dir",
                )
                result, _was_created = start_instance(spec, marker_path=marker_path, **kwargs)
                results.append(result)
        except BaseException as error:
            # ``start-many`` is advisory and non-atomic. Preserve earlier exact
            # marker results instead of broad rollback/discovery; expose only a
            # bounded partial-result witness so callers can stop remaining runs
            # by their caller-selected markers and observe any cleanup failure.
            if isinstance(error, LauncherError):
                error.partial_results = tuple(results)
                if results and error.secondary is None:
                    error.secondary = LauncherError("batch_partial_results")
            raise
        return results


def status_instance(
    marker_path: str | Path,
    *,
    roots: Roots | None = None,
    runner: Runner = run_command,
    executable: str | None = None,
    source_environment: Mapping[str, str] | None = None,
) -> dict[str, object]:
    with _operation_lease(marker_path, code="marker_path_invalid") as lease:
        state = _load_bound_state(marker_path, roots or default_roots(), parent_fd=lease.parent_fd)
        _revalidate_private_parent_path(state.marker_path, lease.parent_fd, expected=lease.identity, code="runs_dir")
        _revalidate_state_records(state, parent_fd=lease.parent_fd)
        if state.marker.status != live_run_marker.STATUS_RUNNING:
            _before_public_return("status")
            _revalidate_public_state(state, parent_fd=lease.parent_fd)
            return {"status": state.marker.status, "marker_path": str(state.marker.marker_path)}
        environment = clean_environment(source_environment)
        podman = executable or podman_path()
        podman_preflight(runner, environment, podman)
        _revalidate_state_data_directory(state)
        _, snapshot = _inspect_bound_container(state, runner, environment, podman)
        _revalidate_state_data_directory(state)
        _revalidate_private_parent_path(state.marker_path, lease.parent_fd, expected=lease.identity, code="runs_dir")
        _revalidate_state_records(state, parent_fd=lease.parent_fd)
        _revalidate_private_parent_path(state.marker_path, lease.parent_fd, expected=lease.identity, code="runs_dir")
        _before_public_return("status")
        final_snapshot = _revalidate_public_state(
            state,
            parent_fd=lease.parent_fd,
            runner=runner,
            environment=environment,
            executable=podman,
        )
        if final_snapshot is None:
            raise LauncherError("container_inspect_invalid")
        return {
            "instance": state.spec.instance,
            "status": final_snapshot.status,
            "marker_path": str(state.marker.marker_path),
        }


def _remove_marker_last(
    state: LauncherState,
    expected: FileIdentity,
    *,
    expected_generation: str | None = None,
    parent_fd: int | None = None,
) -> None:
    """Remove the marker through the same pinned quarantine protocol."""

    try:
        _remove_exact_file(
            state.marker_path,
            code="marker_remove_failed",
            expected=expected,
            expected_generation=expected_generation,
            generation_maximum=live_run_marker.MAX_MARKER_BYTES,
            parent_fd=parent_fd,
        )
    except LauncherError as error:
        if error.code == "marker_remove_failed_replaced":
            raise LauncherError("marker_replaced") from None
        raise


def stop_instance(
    marker_path: str | Path,
    *,
    roots: Roots | None = None,
    purge_data: bool = False,
    runner: Runner = run_command,
    executable: str | None = None,
    source_environment: Mapping[str, str] | None = None,
) -> dict[str, object]:
    if purge_data:
        raise LauncherError("purge_not_supported")
    with _operation_lease(marker_path, code="marker_path_invalid") as lease:
        state = _load_bound_state(marker_path, roots or default_roots(), parent_fd=lease.parent_fd)
        marker_identity = state.marker_identity
        state_identity = state.state_identity
        if marker_identity is None or state_identity is None:
            raise LauncherError("ownership_snapshot_missing")
        _revalidate_private_parent_path(state.marker_path, lease.parent_fd, expected=lease.identity, code="runs_dir")
        # Cleanup-failed tombstones may intentionally have an already-erased
        # credential; the transaction below verifies it when present and keeps
        # replacement failures inside the bounded cleanup error path.
        _revalidate_state_records(state, parent_fd=lease.parent_fd, include_credential=False)

        try:
            environment = clean_environment(source_environment)
            unknown_container = (
                state.marker.status == live_run_marker.STATUS_CLEANUP_FAILED
                and state.marker.container_id == UNPROVEN_CONTAINER_ID
            )
            podman = executable or ""
            if not unknown_container:
                podman = executable or podman_path()
                podman_preflight(runner, environment, podman)

            credential_missing_after_failed_cleanup = False
            if state.marker.status == live_run_marker.STATUS_CLEANUP_FAILED:
                try:
                    _file_identity(
                        state.marker.credential_path,
                        code="credential",
                        parent_fd=lease.parent_fd,
                    )
                except LauncherError as credential_error:
                    if credential_error.code == "credential_missing":
                        # A prior exact cleanup may already have erased and
                        # removed the credential before marker/state disposal
                        # failed. Replacements still fail closed.
                        credential_missing_after_failed_cleanup = True
                    else:
                        raise
            if not credential_missing_after_failed_cleanup:
                try:
                    live_run_marker.verify_credential_identity(
                        state.marker,
                        parent_fd=lease.parent_fd,
                    )
                except live_run_marker.MarkerError as error:
                    raise LauncherError(error.code) from None
            credential_identity = state.marker.credential_identity
            if not unknown_container:
                _remove_bound_container(state, runner, environment, podman)
            _revalidate_private_parent_path(state.marker_path, lease.parent_fd, expected=lease.identity, code="runs_dir")
            _revalidate_state_records(state, parent_fd=lease.parent_fd, include_credential=False)
            if not credential_missing_after_failed_cleanup:
                _revalidate_credential_identity(state.marker, parent_fd=lease.parent_fd)
            # Do not erase valid marker/state/credential evidence until the
            # persisted data directory is still proven. A replacement must
            # fail before cleanup can touch any launcher-owned record.
            _revalidate_state_data_directory(state)
            _before_stop_evidence_cleanup()
            _revalidate_state_data_directory(state)
            _remove_exact_file(
                state.marker.credential_path,
                code="credential_remove_failed",
                expected=credential_identity,
                missing_ok=state.marker.status == live_run_marker.STATUS_CLEANUP_FAILED,
                erase=True,
                parent_fd=lease.parent_fd,
            )
            _remove_exact_file(
                state.marker.state_path,
                code="state_remove_failed",
                expected=state_identity,
                expected_generation=state.state_generation,
                generation_maximum=MAX_STATE_BYTES,
                missing_ok=state.marker.status == live_run_marker.STATUS_CLEANUP_FAILED,
                parent_fd=lease.parent_fd,
            )
            _remove_marker_last(
                state,
                marker_identity,
                expected_generation=state.marker_generation,
                parent_fd=lease.parent_fd,
            )
            # Stop has removed the original evidence. Keep its final hook inside
            # the cleanup transaction and prove every exact sibling remains
            # absent; a replacement must not be reported as successful removal.
            _before_public_return("stop")
            _revalidate_private_parent_path(
                state.marker_path,
                lease.parent_fd,
                expected=lease.identity,
                code="runs_dir",
            )
            _revalidate_state_data_directory(state)
            for evidence_path in (
                state.marker_path,
                state.marker.state_path,
                state.marker.credential_path,
                state.marker_path.with_name(f"{state.marker_path.stem}.cidfile"),
            ):
                _require_exact_entry_absent(
                    lease.parent_fd,
                    evidence_path.name,
                    code="stop_evidence_replaced",
                )
        except BaseException as error:
            if isinstance(error, live_run_marker.MarkerError):
                normalized = LauncherError(error.code)
            elif isinstance(error, LauncherError):
                normalized = error
            else:
                normalized = LauncherError("cleanup_failed")
            _retain_cleanup_failed(
                state,
                expected_marker=marker_identity,
                expected_state=state_identity,
                marker_generation=state.marker_generation,
                state_generation=state.state_generation,
                parent_fd=lease.parent_fd,
            )
            raise normalized
        return {
            "instance": state.spec.instance,
            "status": "removed",
            "marker_path": str(state.marker.marker_path),
        }


def specs_for_batch(
    prefix: str,
    count: int,
    base_port: int,
    *,
    image: str,
    username: str,
    roots: Roots,
) -> tuple[InstanceSpec, ...]:
    validate_instance(prefix)
    if type(count) is not int or count < 1 or count > 64512:
        raise LauncherError("instance_count_invalid")
    if base_port + count - 1 > 65535:
        raise LauncherError("port_range_invalid")
    return tuple(
        make_spec(
            f"{prefix}-{index}",
            base_port + index - 1,
            image=image,
            username=username,
            roots=roots,
        )
        for index in range(1, count + 1)
    )


def roots_from_args(args: argparse.Namespace) -> Roots:
    defaults = default_roots()
    return Roots(
        state=Path(args.state_root).expanduser() if args.state_root else defaults.state,
        data=Path(args.data_root).expanduser() if args.data_root else defaults.data,
        credentials=(
            Path(args.credential_root).expanduser()
            if args.credential_root
            else defaults.credentials
        ),
    )


def add_roots(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--state-root")
    parser.add_argument("--data-root")
    parser.add_argument("--credential-root")


def add_start_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--username", default=DEFAULT_USERNAME)
    parser.add_argument("--readiness-attempts", type=int, default=60)
    parser.add_argument("--readiness-interval", type=float, default=1)
    add_roots(parser)


class RejectDuplicateMarkerAction(argparse.Action):
    """Reject duplicate single-operation markers before any boundary access."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str,
        option_string: str | None = None,
    ) -> None:
        del parser, option_string
        if getattr(namespace, self.dest, None) is not None:
            # A repeated single-marker option used to silently select the last
            # value, which could redirect an exact-marker operation before its
            # filesystem or engine boundary. Batch commands keep append
            # semantics and validate their complete marker set separately.
            raise LauncherError("marker_not_unique")
        setattr(namespace, self.dest, values)


def add_marker(parser: argparse.ArgumentParser, *, many: bool = False) -> None:
    parser.add_argument(
        "--marker",
        action="append" if many else RejectDuplicateMarkerAction,
        required=True,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)

    start = subparsers.add_parser("start")
    start.add_argument("--instance", required=True)
    start.add_argument("--port", required=True, type=int)
    add_marker(start)
    add_start_options(start)

    start_many_parser = subparsers.add_parser("start-many")
    start_many_parser.add_argument("--prefix", required=True)
    start_many_parser.add_argument("--count", required=True, type=int)
    start_many_parser.add_argument("--base-port", required=True, type=int)
    add_marker(start_many_parser, many=True)
    add_start_options(start_many_parser)

    for operation in ("status", "endpoint", "stop"):
        command = subparsers.add_parser(operation)
        add_marker(command)
        if operation == "stop":
            command.add_argument("--purge-data", action="store_true")
        add_roots(command)

    return parser


def execute(args: argparse.Namespace) -> dict[str, object]:
    roots = roots_from_args(args)
    if args.operation == "start":
        # Build and validate pure scalar inputs before start_instance acquires
        # the marker lease; rejected CLI input must not create lock state.
        spec = make_spec(args.instance, args.port, image=args.image, username=args.username, roots=roots)
        result, _ = start_instance(
            spec,
            marker_path=args.marker,
            attempts=args.readiness_attempts,
            interval=args.readiness_interval,
        )
        return {"ok": True, "operation": "start", "result": result}
    if args.operation == "start-many":
        if len(args.marker) != args.count:
            raise LauncherError("marker_count_invalid")
        specs = specs_for_batch(
            args.prefix,
            args.count,
            args.base_port,
            image=args.image,
            username=args.username,
            roots=roots,
        )
        results = start_many(
            specs,
            args.marker,
            attempts=args.readiness_attempts,
            interval=args.readiness_interval,
        )
        return {"ok": True, "operation": "start-many", "results": results}
    if args.operation == "endpoint":
        with _operation_lease(args.marker, code="marker_path_invalid") as lease:
            state = _load_bound_state(args.marker, roots, parent_fd=lease.parent_fd)
            result = verify_handoff_endpoint(state)
            return {"ok": True, "operation": args.operation, "result": result}
    if args.operation == "status":
        # status_instance owns the lease; avoid nesting a redundant lock around
        # its pure marker-path validation and exact-record inspection.
        return {
            "ok": True,
            "operation": "status",
            "result": status_instance(args.marker, roots=roots),
        }
    if args.operation == "stop":
        # stop_instance rejects unsupported purge input before acquiring its
        # lease, so invalid CLI input cannot leave lifecycle-lock state behind.
        return {
            "ok": True,
            "operation": "stop",
            "result": stop_instance(args.marker, roots=roots, purge_data=args.purge_data),
        }
    raise LauncherError("operation_unknown")


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        payload = execute(args)
        status = 0
    except LauncherError as exc:
        error_document: dict[str, object] = {"code": exc.code}
        if exc.secondary is not None:
            error_document["secondary"] = {"code": exc.secondary.code}
        if exc.partial_results:
            error_document["partial_results"] = list(exc.partial_results)
        payload = {"ok": False, "error": error_document}
        status = 2
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
