# Shared benchmark evidence format

**Roadmap operation:** B-01 (`#102`)

**Status:** deterministic synthetic evidence and offline validator only

This directory defines one machine-readable evidence format for later web and
Apple benchmark harnesses. It does not build a client, start Hermes, contact a
proxy, open a browser, or collect live device data. The checked-in samples are
synthetic observations that prove the format and statistical method.

## Contract

`benchmark-evidence.json` is a four-run example. It covers web and iOS cold and
warm states. `synthetic/workload.json` is the reviewed fixture for those runs;
`synthetic/trace.json` is the matching synthetic trace artifact. The same record
shape is used for every later harness run:

- `revision` records the reviewed source commit, fixture ID and version, fixture
  digest, and the pinned Hermes source SHA;
- `metric` records the metric name, unit, and clock. Duration uses a monotonic
  clock and milliseconds;
- `method` freezes the percentile and rounding rules;
- every `runs` entry records the platform, reviewed sanitized environment, cold
  or warm state, production or release build mode, normal or optimized execution
  mode, exact command, raw samples, repetition count, a sample-provenance
  digest, and distribution;
- `artifacts` records the exact permitted relative artifact paths, byte counts,
  and SHA-256 hashes. `artifact_manifest_sha256` hashes the ordered metadata
  list, and a separate code-pinned review anchor binds every non-validator
  artifact byte identity, including the synthetic trace; the validator rejects
  any path inventory or byte identity other than the reviewed set;
- `redaction` records the semantic-only, synthetic-only boundary; and
- `threshold` and `budget` are required to remain `null` until a later review
  approves a performance budget.

A run has at least 30 positive samples. `repetitions` must equal the raw sample
count. Samples are never replaced by only a summary: the raw list is the source
for every reported statistic.

## Statistical method

The format uses inclusive linear interpolation, also known as the R-7
percentile method:

1. sort the `n` raw samples in ascending order;
2. compute the zero-based position `(n - 1) * q`, where `q` is `0.50`, `0.95`,
   or `0.99`;
3. use the value at an integer position, or linearly interpolate between the
   surrounding values; and
4. round the result to three decimal places with decimal half-even rounding.

The record reports `min`, `p50`, `p95`, `p99`, `max`, and `mean` using the same
three-decimal rounding. The validator recomputes every value from
`raw_samples`. A p99 value is therefore defined for a 30-sample run, but it is
an observed percentile, not a confidence interval or a performance promise.
The repetition minimum makes later harness records comparable; it does not
approve a product threshold. A distribution is not accepted on arithmetic
coherence alone: each run's command, environment, repetitions, and raw samples
must exactly match its hashed provenance fixture.

Web uses `build_mode: "production"`; iOS, iPadOS, and macOS use
`build_mode: "release"`. Shared validator measurements use
`build_mode: "not_applicable"`. `state` is always `cold` or `warm`. The
`optimization` field is `normal`, `optimized`, or `not_applicable`, so an
interpreter validation run cannot be confused with a client build mode.

## Validation and redaction

`validate.py` uses only the Python standard library. It rejects duplicate JSON
keys, non-finite numbers, oversized integers, malformed UTF-8, control
characters, excessive nesting or node counts, unknown keys, reordered closed
schemas, wrong scalar types, invalid platform/build/state combinations,
repeated or unreviewed run IDs, source/environment/fixture identity drift,
sample-count drift, forged samples without matching provenance bytes,
distribution drift, missing or unreviewed artifact paths or byte identities,
invalid artifact hashes, non-null thresholds or budgets, and secret-shaped
values. The registered web production-build record additionally binds its exact
workload, raw trace, complete B-01 provenance, sandbox mode, resource limits,
resolved dependency and toolchain byte identities, and one generated artifact
identity. It independently recomputes the measured web `package.json`, `src`, and
`static` identity from the integrated checkout, so stale workload or trace
literals cannot stand in for the bytes actually measured. Local artifact reads
walk directory descriptors with `O_NOFOLLOW`, so root, intermediate, and file
symlinks fail before an external target is read.
The baseline's `validate.py` entry is locally checked but is excluded
from the code-pinned byte anchor to avoid a self-hash cycle. Hostnames,
IPv4/IPv6 addresses, `localhost`, URLs, bearer values, API-key assignments,
and provider-token shapes such as `ghp_…`, `sk-…`, and `xoxb-…` are outside the
redaction boundary. Explicit exceptions are used instead of
executable `assert` statements, so normal and optimized Python runs retain the
same checks.

Every CLI failure emits one bounded JSON object with exit status `2`, no
traceback, no argparse usage text, and no unredacted attacker-controlled path,
key, or value. Diagnostics redact credential-shaped assignments, bearer values, key markers,
email addresses, absolute paths, hosts, IP addresses, and URLs before applying
the output cap.

The artifact is non-UI. Accessibility verification is **N/A** because it has
no focus order, semantic control, screen-reader or VoiceOver surface, Switch
Control interaction, Dynamic Type or browser-zoom layout, contrast theme,
motion, transparency, or touch target. The validator only reads bytes and emits
semantic diagnostics; it does not remove the keyboard, semantic, screen-reader,
contrast, motion, or touch-target fields that downstream UI proof must retain.

## Reproduce the proof

Run from the repository root:

```sh
python3 contracts/benchmarks/validate.py
python3 -O contracts/benchmarks/validate.py
python3 contracts/benchmarks/validate.py --skip-baseline
python3 -O contracts/benchmarks/validate.py --skip-baseline
python3 contracts/benchmarks/validate.py --evidence apps/web/benchmarks/production-build/evidence/benchmark-evidence.json --skip-baseline
python3 -O contracts/benchmarks/validate.py --evidence apps/web/benchmarks/production-build/evidence/benchmark-evidence.json --skip-baseline
python3 contracts/benchmarks/test_validate.py
python3 -O contracts/benchmarks/test_validate.py
python3 -m unittest discover -s contracts/benchmarks -p 'test_*.py'
python3 -O -m unittest discover -s contracts/benchmarks -p 'test_*.py'
python3 -m py_compile \
  contracts/benchmarks/validate.py \
  contracts/benchmarks/test_validate.py
```

`validation-baseline.json` is itself a record in the same format. It contains
30 fresh subprocess samples for normal and optimized validator execution,
including the exact commands, sanitized environment, source commit, fixture
version, raw samples, recomputed distribution, sample-provenance digests, local
artifact byte counts and SHA-256 hashes, and a null threshold and budget.
`sample-provenance.json` is the checked-in canonical source for those two raw
sample sets. The baseline excludes itself from its local artifact manifest to
avoid a self-hash cycle, but includes the provenance fixture and every other
permitted benchmark artifact. A later source or documentation change must
regenerate the observed samples, provenance fixture, and fingerprints; the
measurements remain evidence, not a budget.

All values are synthetic or sanitized. No credentials, cookies, tickets,
tokens, hostnames, IP addresses, URLs, transcripts, provider data, user data,
or live Hermes traces belong in this directory.
