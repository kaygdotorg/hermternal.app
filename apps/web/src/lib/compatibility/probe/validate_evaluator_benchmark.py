#!/usr/bin/env python3
"""Validate the checked-in evaluator benchmark without executing project code."""

from __future__ import annotations

import hashlib
import json
import math
import sys
from decimal import Decimal, ROUND_HALF_EVEN
from pathlib import Path
from typing import Any

DIRECTORY = Path(__file__).resolve().parent
DEFAULT_EVIDENCE = DIRECTORY / "evaluator-benchmark-evidence.json"
EVALUATOR = DIRECTORY / "behavioral-probe-gate.ts"
HARNESS = DIRECTORY / "behavioral-probe-gate.bench.ts"
MAX_BYTES = 1_000_000
EXPECTED_EVALUATOR_SHA256 = "87eefd918ed7b2506d38d4a05c31acc9f1d9bf39af90926836bed4194a964d84"
EXPECTED_HARNESS_SHA256 = "ffd652144660dea66c3019b8151f0d8e7627d9464acff47c6bdf0c85725f9a23"
EXPECTED_SAMPLE_SHA256 = {
    "canonical_success_normal": "0d32be9c429175726f6c671eec4aa902dc429c2fdbf2ba8683021fba30eefc85",
    "bounded_hostile_text_normal": "a677728a2f07a4698387d323d592a6ccc2b09a9ce834e367b27978428b5d35ad",
    "canonical_success_optimized": "179c3c466750bd81e99c18eda62e8a42796c35778ab727e1657ddfe5a4c7aafe",
    "bounded_hostile_text_optimized": "8699a09e4cec775be8e2a815d4952788afdfaa2ba69e03c2e23d1c1e4194b1cc",
}
EXPECTED_RUNS = {
    "canonical_success_normal": (
        "normal",
        "bun build behavioral-probe-gate.bench.ts --target=bun --outfile=<temp>/normal.mjs && bun <temp>/normal.mjs --worker normal",
        "bun-target-bun",
    ),
    "bounded_hostile_text_normal": (
        "normal",
        "bun build behavioral-probe-gate.bench.ts --target=bun --outfile=<temp>/normal.mjs && bun <temp>/normal.mjs --worker normal",
        "bun-target-bun",
    ),
    "canonical_success_optimized": (
        "optimized",
        "bun build behavioral-probe-gate.bench.ts --target=bun --minify --outfile=<temp>/optimized.mjs && bun <temp>/optimized.mjs --worker optimized",
        "bun-target-bun-minified",
    ),
    "bounded_hostile_text_optimized": (
        "optimized",
        "bun build behavioral-probe-gate.bench.ts --target=bun --minify --outfile=<temp>/optimized.mjs && bun <temp>/optimized.mjs --worker optimized",
        "bun-target-bun-minified",
    ),
}

class ValidationError(Exception):
    """A bounded semantic validation failure."""


def fail() -> None:
    raise ValidationError("invalid evaluator benchmark evidence")


def exact_keys(value: Any, expected: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or list(value) != expected:
        fail()
    return value


def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail()
        result[key] = value
    return result


def reject_constant(_value: str) -> None:
    fail()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rounded(value: Decimal) -> Decimal:
    return value.quantize(Decimal("0.001"), rounding=ROUND_HALF_EVEN)


def percentile(samples: list[Decimal], quantile: Decimal) -> Decimal:
    ordered = sorted(samples)
    position = Decimal(len(ordered) - 1) * quantile
    lower = int(position)
    fraction = position - lower
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def distribution(samples: list[Decimal]) -> dict[str, Decimal]:
    ordered = sorted(samples)
    return {
        "min": rounded(ordered[0]),
        "p50": rounded(percentile(samples, Decimal("0.50"))),
        "p95": rounded(percentile(samples, Decimal("0.95"))),
        "p99": rounded(percentile(samples, Decimal("0.99"))),
        "max": rounded(ordered[-1]),
        "mean": rounded(sum(samples) / Decimal(len(samples))),
    }


def validate_document(document: Any) -> None:
    root = exact_keys(document, [
        "schema", "revision", "metric", "method", "runs", "redaction", "threshold", "budget"
    ])
    if root["schema"] != "hermternal.web-behavioral-probe-benchmark.v1":
        fail()
    revision = exact_keys(root["revision"], [
        "source_base_commit", "evaluator_path", "evaluator_sha256", "benchmark_harness_path",
        "benchmark_harness_sha256", "fixture_id", "pinned_hermes_source_sha"
    ])
    if revision != {
        "source_base_commit": "7eb082509125ef3ffed8e141b200c4c5156cf631",
        "evaluator_path": "apps/web/src/lib/compatibility/probe/behavioral-probe-gate.ts",
        "evaluator_sha256": EXPECTED_EVALUATOR_SHA256,
        "benchmark_harness_path": "apps/web/src/lib/compatibility/probe/behavioral-probe-gate.bench.ts",
        "benchmark_harness_sha256": EXPECTED_HARNESS_SHA256,
        "fixture_id": "behavioral-probe-canonical-success-and-bounded-hostile-text-v1",
        "pinned_hermes_source_sha": "f5be9236e00ddf2f2a412697f267078fc4ee068e",
    }:
        fail()
    if sha256(EVALUATOR) != EXPECTED_EVALUATOR_SHA256 or sha256(HARNESS) != EXPECTED_HARNESS_SHA256:
        fail()
    if exact_keys(root["metric"], ["name", "unit", "clock"]) != {
        "name": "synchronous_evaluator_wall_time", "unit": "ms", "clock": "performance.now"
    }:
        fail()
    method = exact_keys(root["method"], [
        "percentile", "quantiles", "rounding", "warmups", "repetitions"
    ])
    if method != {
        "percentile": "inclusive-linear-r7",
        "quantiles": [Decimal("0.5"), Decimal("0.95"), Decimal("0.99")],
        "rounding": "decimal-half-even-to-three-places",
        "warmups": Decimal(5),
        "repetitions": Decimal(30),
    }:
        fail()
    runs = root["runs"]
    if not isinstance(runs, list) or len(runs) != 4 or [run.get("run_id") if isinstance(run, dict) else None for run in runs] != list(EXPECTED_RUNS):
        fail()
    seen: set[str] = set()
    for run in runs:
        item = exact_keys(run, [
            "run_id", "platform", "state", "build_mode", "optimization", "command",
            "environment", "repetitions", "raw_samples", "distribution"
        ])
        run_id = item["run_id"]
        if not isinstance(run_id, str) or run_id in seen or run_id not in EXPECTED_RUNS:
            fail()
        seen.add(run_id)
        optimization, command, build = EXPECTED_RUNS[run_id]
        if (item["platform"], item["state"], item["build_mode"], item["optimization"], item["command"]) != (
            "web", "warm", "production", optimization, command
        ):
            fail()
        environment = exact_keys(item["environment"], [
            "runtime", "platform", "arch", "cpu", "device", "os", "kernel", "build"
        ])
        if environment != {
            "runtime": "bun-1.3.14", "platform": "darwin", "arch": "arm64",
            "cpu": "Apple M2 Max", "device": "Mac14,6", "os": "macOS-26.5.2",
            "kernel": "Darwin-25.5.0", "build": build
        }:
            fail()
        samples = item["raw_samples"]
        if item["repetitions"] != Decimal(30) or not isinstance(samples, list) or len(samples) != 30:
            fail()
        if any(not isinstance(sample, Decimal) or not sample.is_finite() or sample <= 0 for sample in samples):
            fail()
        sample_bytes = ",".join(format(sample, "f") for sample in samples).encode("ascii")
        if hashlib.sha256(sample_bytes).hexdigest() != EXPECTED_SAMPLE_SHA256[run_id]:
            fail()
        reported = exact_keys(item["distribution"], ["min", "p50", "p95", "p99", "max", "mean"])
        if reported != distribution(samples):
            fail()
    if seen != set(EXPECTED_RUNS):
        fail()
    redaction = exact_keys(root["redaction"], [
        "synthetic_only", "network_access", "provider_access", "credentials",
        "cookies", "tickets", "hostnames", "user_data"
    ])
    if redaction != {
        "synthetic_only": True, "network_access": False, "provider_access": False,
        "credentials": False, "cookies": False, "tickets": False,
        "hostnames": False, "user_data": False
    }:
        fail()
    if root["threshold"] is not None or root["budget"] is not None:
        fail()


def load(path: Path) -> Any:
    raw = path.read_bytes()
    if len(raw) > MAX_BYTES:
        fail()
    try:
        text = raw.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=no_duplicates,
            parse_float=Decimal,
            parse_int=Decimal,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValidationError):
        fail()


def main() -> int:
    try:
        if len(sys.argv) > 2:
            fail()
        path = Path(sys.argv[1]) if len(sys.argv) == 2 else DEFAULT_EVIDENCE
        validate_document(load(path))
    except (OSError, ValidationError):
        print('{"error":"invalid evaluator benchmark evidence"}', file=sys.stderr)
        return 2
    print('{"valid":true,"runs":4,"samples_per_run":30,"threshold":null}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
