# Performance benchmark evidence

**Roadmap operation:** B-01 ([#102](https://github.com/kaygdotorg/hermternal/issues/102))

**Status:** normative planning contract for deterministic, synthetic benchmark evidence

This document defines the workload coverage and review rules that sit above the
machine-readable format in [`contracts/benchmarks/README.md`](../../contracts/benchmarks/README.md).
It does not add a benchmark harness, run Hermes, open a browser, contact a
proxy, or report a product performance result. The checked-in JSON examples are
format fixtures only.

The words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are
normative.

## Scope and evidence boundary

B-01 defines how later workload, harness, baseline, and budget operations record
performance evidence. One evidence record describes one metric for one reviewed
workload identity. Repeat the record for another metric, device, browser, OS,
build, or state; do not pool unlike runs to make a distribution large enough.

Every record MUST remain synthetic or redacted and offline. It MUST NOT contain
credentials, cookies, bearer values, provider tokens, hostnames, IP addresses,
URLs, live Hermes traces, provider data, user data, or real transcripts. A
synthetic transcript, stream, terminal byte sequence, or scene transition is a
fixture, not a claim that the client or Hermes has been measured.

## Deterministic workload contract

A workload MUST be a versioned fixture with a stable `fixture_id`,
`fixture_version`, canonical bytes, and SHA-256 digest. It MUST define the
exact command, event order, payload sizes, chunking, viewport or terminal
geometry, input sequence, scroll positions, resize sequence, and scene or
lifecycle transitions needed by its operation. If a generator is used, its
algorithm and seed MUST be fixed in the fixture. Time-based randomness,
adaptive sample sizes, live network responses, and host-dependent data are not
valid workload inputs.

The harness MUST capture the workload identity before the first sample and bind
each run's command, environment, state, build mode, repetition count, and raw
samples to a provenance digest. Changing any of those inputs after capture MUST
invalidate the run rather than silently producing a mixed baseline.

### Required coverage matrix

The following matrix is a coverage contract for later B-02 through B-07
workloads. It names the required operation families; it does not claim that the
harnesses or measurements exist today. Each family is measured separately for
each applicable platform and state.

| Surface | Required synthetic operation families | Example recorded metric units |
| --- | --- | --- |
| Web chat | startup to the first usable state; chat prompt and stream rendering; long-transcript scroll; memory at defined checkpoints | duration in `ms`; memory in `bytes`; event or dropped-work counts in `count` |
| Web Terminal | first glyph; sustained output throughput; retained-output replay; interactive input echo; resize completion | first glyph, echo, and resize in `ms`; throughput in bytes or glyphs per second; replay in `ms` or bytes; memory in `bytes` |
| Apple: iOS, iPadOS, macOS | cold launch; warm resume; first and steady-state render; scene activation or restoration | launch, resume, and render in `ms`; scene completion in `ms` or event `count`; memory in `bytes` when the workload owns that checkpoint |

Metric names MUST describe the operation and unit without embedding a threshold.
For example, a later harness MAY use separate records for `startup_ready_ms`,
`chat_first_render_ms`, `terminal_first_glyph_ms`, or
`scene_restore_ms`; those names are examples of coverage labels, not approved
schema additions or budgets. Web Terminal remains web-only. Apple runs MUST be
reported separately for iOS, iPadOS, and macOS rather than treating them as one
device class.

## State and build mode

`state` is closed to `cold` and `warm`.

- **Cold** MUST begin from the workload's declared clean boundary: a newly
  launched process or app, a new browser context or profile where applicable,
  and no generated state that the workload says is excluded. The reset steps
  MUST be deterministic and MUST be recorded in the workload or trace.
- **Warm** MUST reuse only the resources explicitly declared by the workload,
  such as a process, page, app suspension, scene, terminal surface, or prepared
  fixture. A fixed priming action MAY be used, but its observation MUST be
  retained in the raw trace and excluded from the reported warm distribution.
  A warm series MUST NOT mix process reuse with a cold relaunch without marking
  a separate run.
- A later harness MUST state the exact cold or warm boundary. "Warm" MUST NOT
  mean an unspecified favorable cache state.

Final performance evidence MUST use these build modes:

- Web chat and web Terminal: `build_mode: "production"`.
- iOS, iPadOS, and macOS: `build_mode: "release"`.
- Shared validator or tooling observations: `build_mode: "not_applicable"`.

Development, debug, preview, and test builds MUST NOT be presented as final
client performance evidence. The separate `optimization` field describes a
shared tooling execution mode; it MUST NOT be used to disguise a debug client
build as a release result.

## Environment and provenance metadata

Every run MUST record the exact environment shape used by the shared schema:

- `platform` and platform version;
- `os`, including the OS version;
- `architecture`;
- `device`, including the model or simulator identity;
- `runtime`, including the runtime and version; and
- `browser`, including the browser and version for web runs, or
  `not_applicable` for Apple runs.

The record MUST also bind the reviewed source commit, fixture version and
fixture digest, pinned Hermes source SHA when Hermes contract context applies,
exact command, build mode, and cold or warm state. Values such as `unknown`,
`pending`, or an omitted version MUST NOT stand in for required metadata. A
browser version is required even when the browser is only the host for the web
Terminal. Environment values MUST be sanitized before retention and MUST not
contain a host, address, credential, token, or user identifier.

## Repetitions and distributions

Each accepted run MUST contain at least 30 positive finite raw samples, and
`repetitions` MUST equal the raw sample count. The raw list MUST be retained;
`min`, `p50`, `p95`, `p99`, `max`, and `mean` are derived values, not a
replacement for samples. Cold and warm runs, metrics, devices, browsers, OS
versions, and build modes MUST keep separate raw lists.

The distribution uses inclusive linear interpolation (R-7): sort `n` samples,
compute the zero-based position `(n - 1) * q`, and linearly interpolate when the
position is non-integral. Use `q = 0.50`, `0.95`, and `0.99` for p50, p95, and
p99. Round every reported statistic to three decimal places with decimal
half-even rounding. A p99 from 30 samples is an observed percentile, not a
confidence interval, guarantee, or budget.

The validator MUST recompute the distribution from `raw_samples` and reject a
record when arithmetic, sample count, provenance, or run identity differs. A
failed or excluded observation MUST NOT become a zero, a missing list entry, or
an unrecorded outlier.

## Raw artifacts, retention, and redaction

A valid evidence package MUST retain enough raw material to reproduce the
reported distribution and audit the run:

1. the canonical workload fixture and its digest;
2. the raw trace, including sample sequence, state, warm-up exclusions, and
   bounded failure records;
3. the complete run provenance and sanitized environment metadata; and
4. an ordered artifact manifest containing only approved relative paths, byte
   counts, and SHA-256 hashes.

Raw samples MUST remain available after summary generation. The trace MUST
retain every attempted sequence and identify whether it was accepted, excluded
by the declared warm-up rule, or failed. Generated output MAY be retained only
when its path and bytes are part of the reviewed artifact manifest. Artifact
metadata MUST be checked against the reviewed bytes; a record MUST NOT be able
to approve replacement bytes by recomputing its own hash or manifest.

Redaction MUST occur before an artifact is retained or emitted in diagnostics.
It MUST be semantic, not a lossy change to measured values. If redaction would
change the workload, sample, or provenance identity, the run MUST fail closed.
CLI failures MUST emit one bounded JSON diagnostic with exit status `2`, no
traceback, no usage dump, and no unredacted path, key, environment value, or
secret-shaped input.

## Failure and retry handling

The harness MUST fail closed for a missing or changed fixture, dirty or mutated
measured input, unsupported build or state, missing environment metadata,
non-finite sample, timeout, non-zero child exit, artifact mismatch, redaction
violation, or incomplete repetition count. It MUST stop or mark the evidence
invalid rather than publishing a partial baseline.

A failure record SHOULD include only a bounded run ID, sequence number, stage,
reason code, and whether the declared limit was reached. It MUST NOT include
raw child output or attacker-controlled values. A workload MAY declare a fixed
retry policy for infrastructure setup, but every attempt and retry MUST remain
in the raw trace. Retries MUST NOT depend on whether a value looks slow, and
failed attempts MUST NOT count toward `repetitions`. If the declared minimum
accepted samples cannot be reached without an undeclared retry or a state
change, the run is invalid and has no distribution.

A validator or harness failure MUST leave `threshold` and `budget` null. It MUST
not be repaired by deleting an outlier, substituting a summary, lowering the
repetition count, or claiming that an unrun metric passed.

## Baselines before budgets

Synthetic examples prove the format and method only. A baseline is valid only
after the later harness has produced measured, reviewed distributions for the
required workload, platform, device or simulator, OS, browser where relevant,
build mode, and cold or warm state. A single machine, a best run, a mean, a
synthetic sample, or an unrun operation MUST NOT establish a product threshold.

Until the applicable baseline review is complete, every evidence record MUST
keep `threshold: null` and `budget: null`. Budgets are frozen only after the
measured baselines have been reviewed in the roadmap's budget operation (the
web and Terminal mock review/budget sequence is `B-08W`/`B-08AW`; the shared
cross-platform sequence is `B-08`/`B-08A`). A later approved budget MUST identify
the baseline set and review decision that produced it. Budget enforcement is a
separate operation from collecting evidence.

This rule prevents a synthetic fixture, a debug run, a warm-cache accident, or
an unrun web, Terminal, iOS, iPadOS, or macOS metric from becoming an unsupported
performance claim.

## Existing format and proof paths

The machine-readable contract and statistical validator remain in
[`contracts/benchmarks/README.md`](../../contracts/benchmarks/README.md) and
[`contracts/benchmarks/validate.py`](../../contracts/benchmarks/validate.py).
The checked-in synthetic workload and trace are
[`synthetic/workload.json`](../../contracts/benchmarks/synthetic/workload.json)
and [`synthetic/trace.json`](../../contracts/benchmarks/synthetic/trace.json).
The existing web production-build harness documents one production-build
implementation at
[`apps/web/benchmarks/production-build/README.md`](../../apps/web/benchmarks/production-build/README.md).
Those artifacts do not claim that the workload matrix above has been measured.

Run the contract validator in both normal and optimized Python modes before
reviewing an evidence change. Keep the exact commands and resulting artifacts
with the review record. This document is non-UI benchmark planning evidence;
Paper and accessibility checks are not applicable unless a later benchmark
operation changes a user-facing surface.
