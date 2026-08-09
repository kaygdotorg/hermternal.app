# Apple release-build benchmark scaffold

**Roadmap operation:** B-04 (`#108`)

**Status:** offline, deterministic mock-workload scaffold only

This package defines the Apple side of the shared benchmark hand-off without
creating an Apple client. It measures pure Swift model work for:

- launch/setup state construction;
- streaming batch reduction;
- transcript diff and scroll-model work;
- scene restoration serialization; and
- Dynamic Type layout calculations.

The fixture uses a fixed seed, fixed operation inventory, fixed cold and warm
repetition counts, and no user or provider data. The runner uses
`DispatchTime.uptimeNanoseconds`, a monotonic clock, and records every positive
sample. Distributions use the B-01 R-7 inclusive interpolation method with
half-even rounding to three decimal places (`min`, `p50`, `p95`, `p99`, `max`,
and `mean`). The 30-sample minimum is a comparability rule from B-01, not a
performance threshold.

## Boundaries

This is a protocol and measurement scaffold. It does **not**:

- import SwiftUI or render views;
- start Hermes, contact a network, open a socket, or run a browser;
- use credentials, OAuth, Keychain, signing, provisioning, or live data;
- claim an iPhone, iPad, Mac, OS, compiler, or device performance result; or
- define a threshold or budget.

`device` is always `not_claimed`, `browser` is `not_applicable`, and the
redaction record requires synthetic-only evidence. The pinned Hermes SHA in the
revision record is an approved contract reference only; no Hermes behavior is
executed. The target platform labels (`ios`, `ipados`, and `macos`) describe
schema lanes for the same deterministic mock, not device runs.

A release-build record must be collected explicitly. The CLI checks the compiler's
actual debug-assert configuration, including an explicit `-Onone`, rather than
trusting only a `DEBUG` flag or claimed metadata. It fails closed when run from
a debug build or without a source commit SHA. Missing or malformed
workload/evidence data produces one bounded JSON error on stderr with exit code
`2`; raw paths, arguments, environment values, and decoder details are not
printed.

## Evidence format

The package owns these versioned records:

- `hermternal.apple-benchmark-fixture.v1` — `Sources/AppleBenchmarkHarness/Resources/workload.json`;
- `hermternal.apple-benchmark-trace.v1` — raw warm-up and measured samples;
- `hermternal.apple-benchmark-evidence.v1` — sanitized runs, release metadata,
  artifact identities, distributions, and `threshold: null` / `budget: null`;
- `hermternal.apple-benchmark-error.v1` — bounded failure output.

Evidence also carries `protocol_schema:
hermternal.benchmark-evidence.v1` and keeps the shared field names where they
apply. Workload bytes are pinned by SHA-256 in the package, and the validator
recomputes every run distribution from raw samples. Strict bounded decoding
rejects duplicate keys, malformed JSON, oversized input/output, excessive tree
shape, and empty distributions. The validator also binds the exact platform,
operation, cold/warm, repetition, trace, build, revision, and artifact matrix;
artifact paths, byte counts, hashes, and manifest identities are code-pinned.
Tests mutate the fixture, schema, sample list, distribution, redaction flags,
build metadata, artifact metadata, JSON bounds, and output policy to ensure
drift is visible.

Evidence that lists the raw trace must emit it. The CLI therefore requires
`--trace-output`, canonicalizes both destinations, rejects aliases or
collisions, writes the trace before evidence, and fails closed rather than
attesting to a missing file. Threshold and budget values remain explicit
`null` in scaffold output; if a caller supplies nonnil values, serialization
preserves them and validation rejects them until a reviewed contract exists.

The runner can write two files without putting machine paths into evidence:

```sh
swift run -c release --package-path benchmarks/apple apple-benchmark \
  --source-commit-sha "$(git rev-parse HEAD)" \
  --output /tmp/hermternal-apple-evidence.json \
  --trace-output /tmp/hermternal-apple-raw-trace.json
```

Use `--source-commit-sha not_collected` only for a deliberately incomplete
scaffold exercise. Do not attach that output as a baseline. A checked-in device
observation is intentionally absent: B-04 establishes the harness, while B-07
collects Apple observations and B-08/B-08A review and budget them.

## Build and test

Run from the repository root:

```sh
swift build --package-path benchmarks/apple
swift test --package-path benchmarks/apple
swift build -c release --package-path benchmarks/apple
swift test -c release --package-path benchmarks/apple
xcrun swift-format lint --strict --recursive benchmarks/apple/Sources benchmarks/apple/Tests
```

The package has no external dependencies and is intended for the local Apple
Swift toolchain. The release metadata is reported by the optimized executable;
`swift run` without `-c release` fails closed by design.

Accessibility is **N/A** for this non-UI artifact. It does not remove or prove
VoiceOver, Switch Control, Dynamic Type rendering, contrast, motion, or touch
behavior in a future client.
