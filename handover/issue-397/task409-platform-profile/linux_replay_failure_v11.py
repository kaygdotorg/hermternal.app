#!/usr/bin/env python3
"""Repair the public v11 loader without changing approved Phase A bytes.

The Phase v11 adapter retargeted the runner used to create evidence. Its public
loader can also create fresh predecessor runners, so this successor retargets
the validator globals on every such runner before it reads durable evidence.
"""
from __future__ import annotations

import hashlib
import os
import stat
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
V10_PATH = HERE / "linux_replay_failure_v10.py"
V10_SHA256 = "f9c41aaaeec8ee45c8b62327f22dd4d5de03a8a00ac709adfd03e4217010e499"
PHASE_A_V11_PATH = HERE / "linux_phase_a_v11.py"
PHASE_A_V11_SHA256 = "8fcee2a45123ea635c06e358fd2c82feda17617ef89eed0faba9dac5d0a401bd"
PHASE_A_V10_PATH = HERE / "linux_phase_a_v10.py"
PHASE_A_V10_SHA256 = "15e1492607fcb43f14cd290eef9e0e3df6d4b4a19e5b4bbf278b69647853461b"
PHASE_SCHEMA = "hermternal.issue-397.phase-a-anchor-runner.v11"
PHASE_EVIDENCE_SCHEMA = "hermternal.issue-397.phase-a-anchor-evidence.v11"
PHASE_ROOT_NAME = "hermternal-issue397-phase-a-anchor-v11"
PHASE_EXTERNAL_ROOT = Path("/home/kayg/Developer") / PHASE_ROOT_NAME
SCHEMA = "hermternal.issue-397.replay-failure.v11"
DIRECTORY_NAME = "hermternal-issue397-replay-failure-v11"
WRAPPER_V6_SHA256 = "c8887fd0449ad6af3cfdebb721cf14ef9c91840f4d9b35e53f47b150f9821331"
WRAPPER_V7_SHA256 = "b192429bcb98b4a022d72ad7cf207a7da6c271b52b297168814f3d2007decce4"
V10_DISABLED_BOUNDARY = b'    wrapper.execute_and_publish = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("Phase A v10 authority is not installed"))\n'
V11_DISABLED_BOUNDARY = b'''    wrapper.execute_and_publish = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        RuntimeError("Phase A v11 authority is not installed")
    )
'''
DEPENDENCY_PINS = (
    ("forbidden_proof", "95009c152eb9dbd04cdef58a5c1dddcce8f79365b22a8aca60ab272266a100b6"),
    ("git_config_policy", "ecc9c1e8e3b98a989c19b15b4c9c8bce535d97a02d5c31b79d227785d7f057fa"),
    ("platform_profile", "b5a889fcd6ce7d55778f508e1cbd78d0b2e458a36ad48dd70a7d7ef250fed268"),
    ("section_anchor_metadata", "08ff4406943712d147f54a0bee1d27201109c5cad0eefeb9f23c5c64a6879d1c"),
    ("platform_successor", "a16184b163330b2f2cfbf5482ec78753264a87fcf37f35997af0513cff6bc9c4"),
    ("linux_anchor_authority_v2", "32d8e751a2398a0530213559ea185547f1fd8bbab51ad4bc3f1115825a23331f"),
    ("linux_parent_binding_authority_v3", "9afa3fff6f897bbaac8d3a004080688bf7bf3c5746bb7e266dbb8ce5660f1928"),
    ("linux_root_shape_authority_v4", "c6385587b52ba8477ced95fc9e2465dcd8716c76ec1ec3f77ec52e6d2c1ed4b3"),
    ("linux_retained_driver", "add9d9faad650f971a3f6c0dd00fda8188c849eb647dcdd8ff4df7cfca09b783"),
    ("linux_retained_driver_v2", "77f7fc5262b5f4eb3b9eff336ebc50b1ed1a6b46d124f42d91ff444ec0db03be"),
    ("linux_git_config_adapter", "fda4eb39c0b60f8f27aee17f6d9f5b755fd519283cb4979e33b0ad998f8d6479"),
    ("linux_retained_driver_v3", "b19072f9d6cbc6cb9e6fc271bf468ffe182c3e4b7e1f04b0f6f4c7a54fcc2de5"),
    ("linux_replay_wrapper_v2", "9c2ce8a191efe8dcefd427da5c4bde7353683e5787ce8d32b988d9106aa32e54"),
    ("linux_replay_wrapper_v3", "a357566dc7c451cf38e94be5fa4927b229807ef047d2f8d5fa8fc98bcb32ce8a"),
    ("linux_retained_driver_v4", "9a3f8dadbd1e013b5d663a72433c133cb12eede277ef677f04b620fab34d832d"),
    ("linux_replay_wrapper_v4", "cdc91d0761ba78afa53d8de5a0857b5b8e0851d5880b9e249945aa29ae63eb85"),
    ("linux_retained_driver_v5", "0510d5f7ff5e011cb1875378ede3649222c8383ecb702978af8d791a408400e7"),
    ("linux_replay_wrapper_v5", "83b9dd0fecb26889ddaa0de78a146ad1af22c3e991f4d4bcf56f7900b01c1968"),
    ("linux_phase_a_v8", "140be86d9f597ca529991c6e8755960ab5f83ee627044ae093b6d392c3b88a3f"),
    ("linux_retained_driver_v6", "4363f123a52863304f56eb6847c7e228fc43eae765eb1658d3c0cf521af88cde"),
    ("linux_replay_wrapper_v6", "c8887fd0449ad6af3cfdebb721cf14ef9c91840f4d9b35e53f47b150f9821331"),
    ("object_preservation", "1894901105a07fc925b7271bdb32b0cae92ffb80bd2cbbcd77c828a09819b57e"),
    ("linux_retained_driver_v7", "11adb45e1600717cb5b9cc91d99ea34d5d383320de6bc449cca1e10f0ad35476"),
    ("linux_replay_wrapper_v7", "b192429bcb98b4a022d72ad7cf207a7da6c271b52b297168814f3d2007decce4"),
    ("linux_phase_a_v10", PHASE_A_V10_SHA256),
)
SYNTHETIC_MODULE_NAMES = frozenset({
    "issue397_linux_phase_a_v11_failure_v11_verified",
    "issue397_linux_replay_failure_v11_base",
    "issue397_linux_phase_a_v3_base",
    "issue397_linux_phase_a_v3_wrapper_derivation",
    "issue397_linux_phase_a_v5_base",
    "issue397_linux_phase_a_v6_base",
    "issue397_linux_phase_a_v7_base",
    "issue397_linux_phase_a_v8_base",
    "issue397_linux_phase_a_v9_base",
    "issue397_linux_phase_a_v10_base",
    "issue397_linux_replay_failure_v2_base",
    "issue397_linux_replay_failure_v3_base",
    "issue397_linux_replay_failure_v4_base",
    "issue397_linux_replay_failure_v5_base",
    "issue397_linux_replay_failure_v6_base",
    "issue397_linux_replay_failure_v7_base",
    "issue397_linux_replay_failure_v8_base",
    "issue397_linux_replay_failure_v9_base",
    "issue397_linux_replay_failure_v10_base",
    "issue397_linux_git_config_base",
    "issue397_linux_replay_wrapper_v2_base",
    "issue397_linux_wrapper_base",
    "issue397_linux_driver_adapter_pin",
    "issue397_linux_retained_driver_v2_base",
    "issue397_linux_retained_driver_base",
    "issue397_linux_retained_driver_authority",
    "issue397_linux_git_authority",
    "candidate5_final_framing",
    "candidate5_frozen_git_reviewer_for_successor",
    "issue397_lifecycle_genuine_anchor",
    "issue397_lifecycle_genuine_phase_a",
    "issue397_lifecycle_genuine_phase_b",
    "issue397_phase_a_anchor_approved_lifecycle",
    "issue397_phase_a_anchor_final_tool",
    "issue397_phase_a_anchor_genuine_anchor",
    "issue397_phase_a_anchor_genuine_phase_a",
    "issue397_phase_a_anchor_git_hardening",
    "linux_profile_authority",
    "linux_profile_orchestrator",
    "linux_profile_publication",
    "linux_phase_a_v5",
    "linux_phase_a_v6",
    "linux_phase_a_v7",
})
TRACKED_MODULE_NAMES = frozenset(name for name, _digest in DEPENDENCY_PINS) | SYNTHETIC_MODULE_NAMES
_MISSING = object()


def _stable_bytes(path: Path, digest: str, label: str) -> bytes:
    """Read one stable, single-link file through its authenticated descriptor."""
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError(f"{label} is not a single-link regular file")
        raw = b""
        while len(raw) < before.st_size:
            block = os.read(descriptor, before.st_size - len(raw))
            if not block:
                raise RuntimeError(f"{label} read ended early")
            raw += block
        if os.read(descriptor, 1):
            raise RuntimeError(f"{label} grew during read")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = os.lstat(path)
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode,
        value.st_size, value.st_nlink, value.st_mtime_ns, value.st_ctime_ns,
    )
    if identity(before) != identity(after) or identity(before) != identity(current):
        raise RuntimeError(f"{label} changed during read")
    if hashlib.sha256(raw).hexdigest() != digest:
        raise RuntimeError(f"{label} SHA-256 differs")
    return raw


def _exec_verified(raw: bytes, path: Path, name: str) -> types.ModuleType:
    """Compile and execute only the buffer that the caller authenticated."""
    module = types.ModuleType(name)
    module.__file__ = os.fspath(path)
    sys.modules[name] = module
    exec(compile(raw, os.fspath(path), "exec", dont_inherit=True), module.__dict__)
    return module


def _is_local_module(name: str, value: object) -> bool:
    if name.startswith("issue397_"):
        return True
    path = getattr(value, "__file__", None)
    if path is None:
        return False
    try:
        return Path(path).resolve().is_relative_to(HERE.parent.resolve())
    except (OSError, RuntimeError, TypeError, ValueError):
        return False


def _with_verified_cache(modules: dict[str, types.ModuleType], function):
    """Run with one closed local cache, then restore every changed local name."""
    before = dict(sys.modules)
    result = None
    failure = None
    try:
        sys.modules.update(modules)
        result = function()
    except BaseException as error:  # Restore cache state before propagating.
        failure = error
    after = dict(sys.modules)
    changed = {
        name for name in before.keys() | after.keys()
        if before.get(name, _MISSING) is not after.get(name, _MISSING)
    }
    local_changed = {
        name for name in changed
        if name in TRACKED_MODULE_NAMES
        or _is_local_module(name, after.get(name, before.get(name)))
    }
    unexpected = sorted(local_changed - TRACKED_MODULE_NAMES)
    for name in local_changed:
        prior = before.get(name, _MISSING)
        if prior is _MISSING:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = prior
    if unexpected:
        raise RuntimeError(f"unexpected local module cache delta: {unexpected}") from failure
    if failure is not None:
        raise failure
    return result


def _retarget_runner(runner, dependencies: dict[str, types.ModuleType]):
    """Give creation and validation functions the same closed v11 identity."""
    runner.EXTERNAL_ROOT = PHASE_EXTERNAL_ROOT
    runner.SCHEMA = PHASE_SCHEMA
    runner.EVIDENCE_SCHEMA = PHASE_EVIDENCE_SCHEMA
    for name in ("phase_a", "anchor", "_parse_closed_record", "_validate_evidence"):
        function = getattr(runner, name)
        function.__globals__["SCHEMA"] = PHASE_SCHEMA
        function.__globals__["EVIDENCE_SCHEMA"] = PHASE_EVIDENCE_SCHEMA
    if hasattr(runner, "_owner_value"):
        owner_globals = runner._owner_value.__globals__
        owner_globals["V3_SCHEMA"] = PHASE_SCHEMA
        owner_globals["V3_EVIDENCE_SCHEMA"] = PHASE_EVIDENCE_SCHEMA
        owner_globals["V3_ROOT_NAME"] = PHASE_ROOT_NAME
    prior_load_modules = runner.load_modules

    def load_verified_modules(*args, **kwargs):
        return _with_verified_cache(
            dependencies, lambda: prior_load_modules(*args, **kwargs)
        )

    runner.load_modules = load_verified_modules
    for name in ("phase_a", "anchor"):
        prior_lifecycle = getattr(runner, name)

        def run_with_verified_dependencies(*args, lifecycle=prior_lifecycle, **kwargs):
            return _with_verified_cache(
                dependencies, lambda: lifecycle(*args, **kwargs)
            )

        setattr(runner, name, run_with_verified_dependencies)
    return runner


def _bind_v7_public_wrapper(
    module: types.ModuleType, dependencies: dict[str, types.ModuleType]
) -> None:
    """Bind the fresh v3 public boundary to the authenticated v7 wrapper.

    Phase v11 bound v7 for evidence creation, but the inherited public loader
    still closed over wrapper v6. Only the v3 boundary function contains this
    exact v10 disabled literal, so other lifecycle factories stay unchanged.
    """
    function = module.__dict__.get("load_approved_wrapper")
    if function is None:
        return
    constants = function.__code__.co_consts
    count = constants.count(V10_DISABLED_BOUNDARY)
    if count == 0:
        return
    if count != 1 or constants.count(V11_DISABLED_BOUNDARY) != 0:
        raise RuntimeError("Phase v11 public wrapper boundary differs")
    globals_value = function.__globals__
    if globals_value.get("LINUX_WRAPPER_ADAPTER_SHA256") != WRAPPER_V6_SHA256:
        raise RuntimeError("Phase v11 predecessor wrapper binding differs")
    globals_value["linux_replay_wrapper"] = dependencies["linux_replay_wrapper_v7"]
    globals_value["LINUX_WRAPPER_ADAPTER_SHA256"] = WRAPPER_V7_SHA256
    replaced = tuple(
        V11_DISABLED_BOUNDARY if value == V10_DISABLED_BOUNDARY else value
        for value in constants
    )
    module.load_approved_wrapper = types.FunctionType(
        function.__code__.replace(co_consts=replaced), globals_value,
        function.__name__, function.__defaults__, function.__closure__,
    )


def _retarget_phase_factory(
    module: types.ModuleType, dependencies: dict[str, types.ModuleType]
) -> types.ModuleType:
    """Retarget fresh nested modules made by the reviewed public loader."""
    _bind_v7_public_wrapper(module, dependencies)
    for name in tuple(module.__dict__):
        if name.endswith("_ROOT_NAME"):
            module.__dict__[name] = PHASE_ROOT_NAME
    if "load_runner" in module.__dict__:
        prior_load_runner = module.load_runner

        def load_v11_runner():
            runner = _with_verified_cache(dependencies, prior_load_runner)
            return _retarget_runner(runner, dependencies)

        module.load_runner = load_v11_runner
    for name in ("_load_v10", "_load_v8", "_load_v7", "_load_v3"):
        if name in module.__dict__:
            prior_factory = module.__dict__[name]

            def load_v11_factory(factory=prior_factory):
                value = _with_verified_cache(dependencies, factory)
                return _retarget_phase_factory(value, dependencies)

            module.__dict__[name] = load_v11_factory
    return module


def _inject_phase(module: types.ModuleType, phase: types.ModuleType) -> types.ModuleType:
    """Install the authenticated Phase module at the outer chain's real seam."""
    if "load_phase_a_adapter" in module.__dict__:
        module.PHASE_A_ADAPTER_PATH = PHASE_A_V11_PATH
        module.PHASE_A_ADAPTER_SHA256 = PHASE_A_V11_SHA256
        module.load_phase_a_adapter = lambda: phase
    for name in tuple(module.__dict__):
        if name.startswith("_load_v") and name[7:].isdigit():
            if name == "_load_v9" and any(
                key.startswith("PHASE_A_V") and key.endswith("_PATH")
                for key in module.__dict__
            ):
                module.__dict__[name] = lambda: phase
                continue
            prior_factory = module.__dict__[name]

            def load_injected(factory=prior_factory):
                return _inject_phase(factory(), phase)

            module.__dict__[name] = load_injected
    return module


def _load_authenticated() -> tuple[types.ModuleType, types.ModuleType]:
    """Authenticate both sources, then return the linked failure and Phase modules."""
    failure_raw = _stable_bytes(V10_PATH, V10_SHA256, "failure v10")
    phase_raw = _stable_bytes(PHASE_A_V11_PATH, PHASE_A_V11_SHA256, "Phase A v11 adapter")
    dependency_raw = {
        name: _stable_bytes(HERE / f"{name}.py", digest, name)
        for name, digest in DEPENDENCY_PINS
    }
    def bind_authenticated_modules():
        # This order is the closed local import graph, from leaves to Phase v10.
        # A poisoned prior cache entry cannot provide any imported dependency.
        dependencies = {}
        for name, _digest in DEPENDENCY_PINS:
            dependencies[name] = _exec_verified(
                dependency_raw[name], HERE / f"{name}.py", name
            )
        phase = _retarget_phase_factory(
            _exec_verified(
                phase_raw, PHASE_A_V11_PATH,
                "issue397_linux_phase_a_v11_failure_v11_verified",
            ),
            dependencies,
        )
        prior_phase_factory = phase._load_v10

        def load_with_verified_dependencies():
            return _with_verified_cache(dependencies, prior_phase_factory)

        phase._load_v10 = load_with_verified_dependencies
        module = _exec_verified(
            failure_raw, V10_PATH, "issue397_linux_replay_failure_v11_base"
        )
        predecessor_factory = module._load_v9

        def load_v11_mechanism():
            return _inject_phase(predecessor_factory(), phase)

        module._load_v9 = load_v11_mechanism
        module.__file__ = os.fspath(Path(__file__).resolve())
        module.SCHEMA = SCHEMA
        module.DIRECTORY_NAME = DIRECTORY_NAME
        prior_public_loader = module.load_approved_wrapper

        def load_with_verified_failure_dependencies(expected_anchor_sha256: str):
            return _with_verified_cache(
                dependencies,
                lambda: prior_public_loader(expected_anchor_sha256),
            )

        module.load_approved_wrapper = load_with_verified_failure_dependencies
        return module, phase

    return _with_verified_cache({}, bind_authenticated_modules)


def _load_v10() -> types.ModuleType:
    """Return the failure successor linked to authenticated Phase v11 bytes."""
    module, _phase = _load_authenticated()
    return module


def load_approved_wrapper(expected_anchor_sha256: str):
    """Authenticate the durable v11 anchor and return a disabled boundary."""
    return _load_v10().load_approved_wrapper(expected_anchor_sha256)


def __getattr__(name: str):
    return getattr(_load_v10(), name)
