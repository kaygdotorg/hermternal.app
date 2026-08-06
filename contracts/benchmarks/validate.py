#!/usr/bin/env python3
"""Validate the shared, offline benchmark evidence contract.

The format is the hand-off boundary for later web and Apple harnesses.  This
module intentionally uses only the Python standard library: it reads local JSON,
recomputes the recorded distribution, verifies artifact fingerprints, and emits
bounded diagnostics.  It never starts Hermes, opens a socket, runs a browser,
or contacts a service.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sys
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN, localcontext
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
EVIDENCE_PATH = ROOT / "benchmark-evidence.json"
BASELINE_PATH = ROOT / "validation-baseline.json"

SCHEMA = "hermternal.benchmark-evidence.v1"
BASELINE_EVIDENCE_ID = "validator-baseline"
PINNED_HERMES_SHA = "f5be9236e00ddf2f2a412697f267078fc4ee068e"
ERROR_CODE = "benchmark_evidence_validation_error"

MAX_JSON_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_INTEGER_DIGITS = 1000
MAX_JSON_NODES = 4096
MAX_OBJECT_KEYS = 64
MAX_ARRAY_LENGTH = 2048
MAX_STRING_LENGTH = 4096
MAX_ERROR_OUTPUT = 240
MAX_RUNS = 32
MAX_REPETITIONS = 10_000
MIN_REPETITIONS = 30

ROOT_KEYS = (
    "schema",
    "evidence_id",
    "revision",
    "metric",
    "method",
    "runs",
    "artifacts",
    "artifact_manifest_sha256",
    "redaction",
    "threshold",
    "budget",
)
REVISION_KEYS = (
    "commit_sha",
    "fixture_id",
    "fixture_version",
    "fixture_sha256",
    "hermes_source_sha",
)
METRIC_KEYS = ("name", "unit", "clock")
METHOD_KEYS = (
    "percentile_method",
    "position_formula",
    "rounding",
    "quantiles",
    "minimum_repetitions",
)
QUANTILE_KEYS = ("p50", "p95", "p99")
RUN_KEYS = (
    "id",
    "platform",
    "environment",
    "state",
    "build_mode",
    "optimization",
    "command",
    "repetitions",
    "raw_samples",
    "distribution",
)
ENVIRONMENT_KEYS = (
    "platform",
    "os",
    "architecture",
    "device",
    "runtime",
    "browser",
)
DISTRIBUTION_KEYS = ("min", "p50", "p95", "p99", "max", "mean")
ARTIFACT_KEYS = ("path", "bytes", "sha256")
REDACTION_KEYS = (
    "policy",
    "synthetic_only",
    "contains_credentials",
    "contains_tokens",
    "contains_user_data",
    "contains_live_hosts",
    "contains_transcripts",
)

PLATFORMS = frozenset({"shared", "web", "ios", "ipados", "macos"})
STATES = frozenset({"cold", "warm"})
BUILD_MODES = frozenset({"production", "release", "not_applicable"})
OPTIMIZATION_MODES = frozenset({"normal", "optimized", "not_applicable"})
METRIC_UNITS = frozenset({"ms", "bytes", "count"})

CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
IDENTIFIER_RE = re.compile(r"[a-z][a-z0-9._-]{1,63}\Z")
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
ARTIFACT_PATH_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}\Z")

SENSITIVE_KEY_PARTS = frozenset(
    {
        "authorization",
        "bearer",
        "cookie",
        "credential",
        "csrf",
        "email",
        "hostname",
        "nonce",
        "password",
        "pkce",
        "privatekey",
        "secret",
        "session",
        "ticket",
        "token",
        "transcript",
        "userdata",
        "useremail",
    }
)
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)(?:authorization|bearer|cookie|credential|csrf|nonce|password|pkce|secret|session|ticket|token)"
    r"\s*(?:[:=]|is)\s*[^\s,;]+"
)
PRIVATE_KEY_RE = re.compile(r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----")
EMAIL_RE = re.compile(r"(?i)\b[^\s@]+@[^\s@]+\.[A-Za-z]{2,}\b")
ABSOLUTE_PATH_RE = re.compile(r"(?:^|[\s=(])(?:/|[A-Za-z]:[\\/])")
HOSTNAME_RE = re.compile(
    r"(?i)(?:https?://|wss?://|\b[a-z0-9-]+\.(?:com|dev|internal|io|local|net|org|test)(?::[0-9]+)?(?:/|\b))"
)

BASELINE_COMMANDS = {
    "normal": "python3 contracts/benchmarks/validate.py --skip-baseline",
    "optimized": "python3 -O contracts/benchmarks/validate.py --skip-baseline",
}


class ValidationError(ValueError):
    """A controlled, non-sensitive contract validation failure."""


def require(condition: bool, message: str) -> None:
    """Raise an explicit exception so checks survive optimized Python runs."""

    if not condition:
        raise ValidationError(message)


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValidationError("duplicate JSON object key is not allowed")
    return dict(pairs)


def _reject_nonfinite_json_constant(value: str) -> Any:
    del value
    raise ValidationError("non-finite JSON number is not allowed")


def _parse_json_integer(value: str) -> int:
    digits = value.lstrip("-")
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise ValidationError("JSON integer digit limit exceeded")
    return int(value)


def load_json(path: Path) -> Any:
    """Read bounded UTF-8 JSON with duplicate-key and numeric checks."""

    try:
        raw = path.read_bytes()
    except OSError as error:
        del error
        raise ValidationError("input could not be read") from None
    require(len(raw) <= MAX_JSON_BYTES, "input exceeds the bounded byte limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValidationError("input is not valid UTF-8") from None
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonfinite_json_constant,
            parse_int=_parse_json_integer,
        )
    except (ValidationError, json.JSONDecodeError, RecursionError, ValueError):
        raise ValidationError("input is malformed JSON") from None
    validate_json_tree(value)
    return value


def validate_json_tree(value: Any, label: str = "input", depth: int = 0) -> int:
    """Apply portable bounds before the closed benchmark schema is inspected."""

    require(depth <= MAX_JSON_DEPTH, f"{label}: JSON depth exceeds the bounded limit")
    if isinstance(value, dict):
        require(len(value) <= MAX_OBJECT_KEYS, f"{label}: object has too many keys")
        nodes = 1
        for key, child in value.items():
            require(type(key) is str, f"{label}: object keys must be text")
            require(len(key) <= MAX_STRING_LENGTH, f"{label}: object key is too long")
            require(CONTROL_RE.search(key) is None, f"{label}: object key contains control characters")
            nodes += validate_json_tree(child, f"{label}.<field>", depth + 1)
            require(nodes <= MAX_JSON_NODES, f"{label}: JSON node count exceeds the bounded limit")
        return nodes
    if isinstance(value, list):
        require(len(value) <= MAX_ARRAY_LENGTH, f"{label}: array is too long")
        nodes = 1
        for child in value:
            nodes += validate_json_tree(child, f"{label}[]", depth + 1)
            require(nodes <= MAX_JSON_NODES, f"{label}: JSON node count exceeds the bounded limit")
        return nodes
    if type(value) is str:
        require(len(value) <= MAX_STRING_LENGTH, f"{label}: string is too long")
        require(CONTROL_RE.search(value) is None, f"{label}: control character is not allowed")
        return 1
    if type(value) is float:
        require(math.isfinite(value), f"{label}: non-finite JSON number is not allowed")
        return 1
    require(value is None or type(value) in {bool, int}, f"{label}: unsupported JSON value type")
    return 1


def _strict_keys(value: Any, expected: tuple[str, ...], label: str) -> dict[str, Any]:
    require(type(value) is dict, f"{label} must be an object")
    require(tuple(value.keys()) == expected, f"{label} keys or ordering changed")
    return value


def _text(value: Any, label: str, *, pattern: re.Pattern[str] | None = None) -> str:
    require(type(value) is str, f"{label} must be text")
    require(0 < len(value) <= MAX_STRING_LENGTH, f"{label} has an invalid length")
    require(CONTROL_RE.search(value) is None, f"{label} contains control characters")
    if pattern is not None:
        require(pattern.fullmatch(value) is not None, f"{label} has an invalid format")
    return value


def _bool(value: Any, label: str) -> bool:
    require(type(value) is bool, f"{label} must be boolean")
    return value


def _integer(value: Any, label: str, *, minimum: int | None = None, maximum: int | None = None) -> int:
    require(type(value) is int and type(value) is not bool, f"{label} must be an integer")
    if minimum is not None:
        require(value >= minimum, f"{label} is below the minimum")
    if maximum is not None:
        require(value <= maximum, f"{label} exceeds the maximum")
    return value


def _finite_decimal(value: Any, label: str, *, positive: bool = False) -> Decimal:
    require(type(value) in {int, float} and type(value) is not bool, f"{label} must be numeric")
    try:
        number = Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise ValidationError(f"{label} is not numeric") from None
    require(number.is_finite(), f"{label} must be finite")
    require(number > 0 if positive else number >= 0, f"{label} must be non-negative")
    return number


def _safe_marker(value: Any, label: str) -> str:
    text = _text(value, label)
    require(SENSITIVE_ASSIGNMENT_RE.search(text) is None, f"{label} contains sensitive material")
    require(PRIVATE_KEY_RE.search(text) is None, f"{label} contains key material")
    require(EMAIL_RE.search(text) is None, f"{label} contains an email address")
    require(ABSOLUTE_PATH_RE.search(text) is None, f"{label} contains an absolute path")
    require(HOSTNAME_RE.search(text) is None, f"{label} contains a host or URL")
    return text


def _normalize_sensitive_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def _walk_redaction(value: Any, path: str = "$") -> None:
    """Reject secret-shaped fields and values outside the redaction record."""

    if isinstance(value, dict):
        for key, child in value.items():
            if path == "$.redaction":
                continue
            normalized = _normalize_sensitive_key(key)
            require(
                normalized not in SENSITIVE_KEY_PARTS,
                f"{path}: sensitive field is not allowed",
            )
            _walk_redaction(child, f"{path}.<field>")
    elif isinstance(value, list):
        for child in value:
            _walk_redaction(child, f"{path}[]")
    elif type(value) is str:
        require(SENSITIVE_ASSIGNMENT_RE.search(value) is None, f"{path}: sensitive value is not allowed")
        require(PRIVATE_KEY_RE.search(value) is None, f"{path}: key material is not allowed")
        require(EMAIL_RE.search(value) is None, f"{path}: email value is not allowed")
        require(ABSOLUTE_PATH_RE.search(value) is None, f"{path}: absolute path is not allowed")
        require(HOSTNAME_RE.search(value) is None, f"{path}: host or URL is not allowed")


def validate_redaction(value: Any) -> None:
    redaction = _strict_keys(value, REDACTION_KEYS, "redaction")
    require(redaction["policy"] == "semantic_only", "redaction policy changed")
    require(_bool(redaction["synthetic_only"], "redaction.synthetic_only"), "redaction.synthetic_only must remain true")
    for key in REDACTION_KEYS[2:]:
        require(not _bool(redaction[key], f"redaction.{key}"), f"redaction.{key} must remain false")


def _validate_revision(value: Any) -> None:
    revision = _strict_keys(value, REVISION_KEYS, "revision")
    _text(revision["commit_sha"], "revision.commit_sha", pattern=COMMIT_RE)
    _text(revision["fixture_id"], "revision.fixture_id", pattern=IDENTIFIER_RE)
    _text(revision["fixture_version"], "revision.fixture_version", pattern=VERSION_RE)
    _text(revision["fixture_sha256"], "revision.fixture_sha256", pattern=SHA256_RE)
    require(revision["hermes_source_sha"] == PINNED_HERMES_SHA, "revision.hermes_source_sha changed")


def _validate_metric(value: Any) -> None:
    metric = _strict_keys(value, METRIC_KEYS, "metric")
    _text(metric["name"], "metric.name", pattern=IDENTIFIER_RE)
    _text(metric["unit"], "metric.unit")
    require(metric["unit"] in METRIC_UNITS, "metric.unit is unsupported")
    _text(metric["clock"], "metric.clock")
    if metric["unit"] == "ms":
        require(metric["clock"] == "monotonic", "duration metrics require a monotonic clock")
    else:
        require(metric["clock"] == "not_applicable", "non-duration metrics require no clock")


def _validate_method(value: Any) -> None:
    method = _strict_keys(value, METHOD_KEYS, "method")
    require(method["percentile_method"] == "inclusive_linear_interpolation_r7", "percentile method changed")
    require(method["position_formula"] == "(n - 1) * q", "percentile position formula changed")
    require(method["rounding"] == "half_even_to_3_decimal_places", "rounding method changed")
    quantiles = _strict_keys(method["quantiles"], QUANTILE_KEYS, "method.quantiles")
    expected = {"p50": Decimal("0.50"), "p95": Decimal("0.95"), "p99": Decimal("0.99")}
    for key, expected_value in expected.items():
        actual = _finite_decimal(quantiles[key], f"method.quantiles.{key}")
        require(actual == expected_value, f"method.quantiles.{key} changed")
    require(
        _integer(method["minimum_repetitions"], "method.minimum_repetitions", minimum=MIN_REPETITIONS)
        == MIN_REPETITIONS,
        "minimum repetition count changed",
    )


def _validate_environment(value: Any, label: str) -> None:
    environment = _strict_keys(value, ENVIRONMENT_KEYS, label)
    for key in ENVIRONMENT_KEYS:
        _safe_marker(environment[key], f"{label}.{key}")
    require(environment["browser"] == "not_applicable" or len(environment["browser"]) <= 128, f"{label}.browser is too long")


def _round_decimal(value: Decimal) -> Decimal:
    with localcontext() as context:
        context.prec = 50
        return value.quantize(Decimal("0.001"), rounding=ROUND_HALF_EVEN)


def _percentile(values: list[Decimal], quantile: Decimal) -> Decimal:
    ordered = sorted(values)
    position = Decimal(len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - Decimal(lower)
    interpolated = ordered[lower] + (ordered[upper] - ordered[lower]) * fraction
    return _round_decimal(interpolated)


def expected_distribution(samples: list[Any]) -> dict[str, Decimal]:
    values = [_finite_decimal(value, "raw sample", positive=True) for value in samples]
    require(values, "raw_samples must not be empty")
    with localcontext() as context:
        context.prec = 50
        mean = sum(values, Decimal("0")) / Decimal(len(values))
    return {
        "min": _round_decimal(min(values)),
        "p50": _percentile(values, Decimal("0.50")),
        "p95": _percentile(values, Decimal("0.95")),
        "p99": _percentile(values, Decimal("0.99")),
        "max": _round_decimal(max(values)),
        "mean": _round_decimal(mean),
    }


def _validate_distribution(value: Any, samples: list[Any], label: str) -> None:
    distribution = _strict_keys(value, DISTRIBUTION_KEYS, label)
    expected = expected_distribution(samples)
    for key in DISTRIBUTION_KEYS:
        actual = _finite_decimal(distribution[key], f"{label}.{key}")
        require(actual == expected[key], f"{label}.{key} does not match raw samples")
    require(
        expected["min"] <= expected["p50"] <= expected["p95"] <= expected["p99"] <= expected["max"],
        f"{label} quantile order is invalid",
    )


def _validate_run(value: Any, index: int) -> dict[str, Any]:
    label = f"runs[{index}]"
    run = _strict_keys(value, RUN_KEYS, label)
    _text(run["id"], f"{label}.id", pattern=IDENTIFIER_RE)
    _text(run["platform"], f"{label}.platform")
    require(run["platform"] in PLATFORMS, f"{label}.platform is unsupported")
    _validate_environment(run["environment"], f"{label}.environment")
    _text(run["state"], f"{label}.state")
    require(run["state"] in STATES, f"{label}.state is unsupported")
    _text(run["build_mode"], f"{label}.build_mode")
    require(run["build_mode"] in BUILD_MODES, f"{label}.build_mode is unsupported")
    _text(run["optimization"], f"{label}.optimization")
    require(run["optimization"] in OPTIMIZATION_MODES, f"{label}.optimization is unsupported")
    if run["platform"] == "shared":
        require(run["build_mode"] == "not_applicable", f"{label}.build_mode must be N/A for shared tooling")
    elif run["platform"] == "web":
        require(run["build_mode"] == "production", f"{label}.build_mode must be production for web")
    else:
        require(run["build_mode"] == "release", f"{label}.build_mode must be release for Apple")
    require(run["optimization"] == "not_applicable" or run["platform"] == "shared", f"{label}.optimization is not portable")
    _safe_marker(run["command"], f"{label}.command")
    repetitions = _integer(run["repetitions"], f"{label}.repetitions", minimum=MIN_REPETITIONS, maximum=MAX_REPETITIONS)
    require(type(run["raw_samples"]) is list, f"{label}.raw_samples must be an array")
    require(len(run["raw_samples"]) == repetitions, f"{label}.raw_samples count must equal repetitions")
    require(len(run["raw_samples"]) <= MAX_REPETITIONS, f"{label}.raw_samples is too long")
    for sample_index, sample in enumerate(run["raw_samples"]):
        _finite_decimal(sample, f"{label}.raw_samples[{sample_index}]", positive=True)
    _validate_distribution(run["distribution"], run["raw_samples"], f"{label}.distribution")
    return run


def artifact_manifest_digest(artifacts: list[dict[str, Any]]) -> str:
    """Hash only stable artifact metadata, not JSON whitespace or file paths."""

    payload = json.dumps(artifacts, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _validate_artifacts(value: Any, label: str) -> list[dict[str, Any]]:
    require(type(value) is list, f"{label} must be an array")
    require(0 < len(value) <= MAX_ARRAY_LENGTH, f"{label} has an invalid length")
    seen: set[str] = set()
    artifacts: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        artifact = _strict_keys(item, ARTIFACT_KEYS, f"{label}[{index}]")
        path = _text(artifact["path"], f"{label}[{index}].path", pattern=ARTIFACT_PATH_RE)
        parts = path.split("/")
        require(path not in seen, f"{label}[{index}].path is duplicated")
        require(not path.startswith("/") and "\\" not in path, f"{label}[{index}].path is not portable")
        require(".." not in parts and "" not in parts, f"{label}[{index}].path escapes its root")
        seen.add(path)
        _integer(artifact["bytes"], f"{label}[{index}].bytes", minimum=1, maximum=MAX_JSON_BYTES)
        _text(artifact["sha256"], f"{label}[{index}].sha256", pattern=SHA256_RE)
        artifacts.append(artifact)
    return artifacts


def _validate_local_artifacts(artifacts: list[dict[str, Any]], root: Path) -> None:
    resolved_root = root.resolve()
    for artifact in artifacts:
        candidate = (root / artifact["path"]).resolve()
        require(resolved_root in candidate.parents, "artifact path escapes the benchmark directory")
        require(candidate.is_file(), "recorded artifact is missing")
        try:
            raw = candidate.read_bytes()
        except OSError:
            raise ValidationError("recorded artifact could not be read") from None
        require(len(raw) == artifact["bytes"], "recorded artifact byte count changed")
        require(hashlib.sha256(raw).hexdigest() == artifact["sha256"], "recorded artifact hash changed")


def validate_evidence(
    value: Any,
    label: str = "evidence",
    *,
    root: Path = ROOT,
    verify_artifacts: bool = False,
    expected_id: str | None = None,
) -> dict[str, Any]:
    """Validate one portable evidence record and optionally its local files."""

    validate_json_tree(value, label)
    require(type(value) is dict, f"{label} must be an object")
    _walk_redaction(value)
    record = _strict_keys(value, ROOT_KEYS, label)
    require(record["schema"] == SCHEMA, f"{label}.schema changed")
    evidence_id = _text(record["evidence_id"], f"{label}.evidence_id", pattern=IDENTIFIER_RE)
    if expected_id is not None:
        require(evidence_id == expected_id, f"{label}.evidence_id is not the expected baseline")
    _validate_revision(record["revision"])
    _validate_metric(record["metric"])
    _validate_method(record["method"])
    require(type(record["runs"]) is list, f"{label}.runs must be an array")
    require(0 < len(record["runs"]) <= MAX_RUNS, f"{label}.runs has an invalid length")
    seen_runs: set[str] = set()
    for index, item in enumerate(record["runs"]):
        run = _validate_run(item, index)
        require(run["id"] not in seen_runs, f"{label}.runs[{index}].id is duplicated")
        seen_runs.add(run["id"])
    artifacts = _validate_artifacts(record["artifacts"], f"{label}.artifacts")
    require(
        record["artifact_manifest_sha256"] == artifact_manifest_digest(artifacts),
        f"{label}.artifact_manifest_sha256 does not match artifacts",
    )
    validate_redaction(record["redaction"])
    require(record["threshold"] is None, f"{label}.threshold must remain null until review")
    require(record["budget"] is None, f"{label}.budget must remain null until review")
    if verify_artifacts:
        _validate_local_artifacts(artifacts, root)
    return record


def validate_baseline(value: Any, root: Path = ROOT) -> dict[str, Any]:
    record = validate_evidence(
        value,
        "baseline",
        root=root,
        verify_artifacts=True,
        expected_id=BASELINE_EVIDENCE_ID,
    )
    require(record["metric"] == {"name": "validator_duration", "unit": "ms", "clock": "monotonic"}, "baseline metric changed")
    require(len(record["runs"]) == 2, "baseline must contain normal and optimized runs")
    modes: set[str] = set()
    for index, run in enumerate(record["runs"]):
        label = f"baseline.runs[{index}]"
        require(run["platform"] == "shared", f"{label}.platform must be shared")
        require(run["state"] == "cold", f"{label}.state must be cold")
        require(run["build_mode"] == "not_applicable", f"{label}.build_mode must be N/A")
        require(run["optimization"] in {"normal", "optimized"}, f"{label}.optimization is invalid")
        mode = run["optimization"]
        require(mode not in modes, "baseline optimization mode is duplicated")
        modes.add(mode)
        require(run["command"] == BASELINE_COMMANDS[mode], f"{label}.command is not reproducible")
        require(run["repetitions"] == MIN_REPETITIONS, f"{label}.repetitions must be {MIN_REPETITIONS}")
    require(modes == {"normal", "optimized"}, "baseline optimization modes are incomplete")
    return record


def _redacted_error(message: object) -> str:
    text = str(message)
    text = SENSITIVE_ASSIGNMENT_RE.sub("<redacted>", text)
    text = PRIVATE_KEY_RE.sub("<redacted>", text)
    text = EMAIL_RE.sub("<redacted>", text)
    text = ABSOLUTE_PATH_RE.sub("<redacted>", text)
    text = HOSTNAME_RE.sub("<redacted>", text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > MAX_ERROR_OUTPUT:
        return text[: MAX_ERROR_OUTPUT - 3] + "..."
    return text


def _parse_args(argv: list[str]) -> tuple[Path, Path, bool]:
    evidence_path = EVIDENCE_PATH
    baseline_path = BASELINE_PATH
    skip_baseline = False
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument == "--skip-baseline":
            skip_baseline = True
            index += 1
            continue
        if argument in {"--evidence", "--baseline"}:
            if index + 1 >= len(argv) or argv[index + 1].startswith("--"):
                raise ValidationError("option value is missing")
            target = Path(argv[index + 1])
            if argument == "--evidence":
                evidence_path = target
            else:
                baseline_path = target
            index += 2
            continue
        raise ValidationError("unknown command option")
    return evidence_path, baseline_path, skip_baseline


def main(argv: list[str] | None = None) -> int:
    try:
        evidence_path, baseline_path, skip_baseline = _parse_args(list(sys.argv[1:] if argv is None else argv))
        evidence = load_json(evidence_path)
        record = validate_evidence(evidence, root=ROOT)
        if not skip_baseline:
            validate_baseline(load_json(baseline_path), ROOT)
        result = {
            "ok": True,
            "schema": SCHEMA,
            "evidence_id": record["evidence_id"],
            "run_count": len(record["runs"]),
            "baseline_checked": not skip_baseline,
        }
        print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
        return 0
    except Exception as error:  # Keep the command boundary one-line and traceback-free.
        result = {"ok": False, "error": {"code": ERROR_CODE, "message": _redacted_error(error)}}
        print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
