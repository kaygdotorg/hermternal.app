# Scripts

This directory contains small, deterministic repository tools. The roadmap
validator is a planning-only source check; it does not contact GitHub, Paper,
Hermes, or any other service.

## Roadmap template validator

Run it from the repository root:

```text
python3 scripts/validate_roadmap_template.py
```

Pass another local file when testing a mutation:

```text
python3 scripts/validate_roadmap_template.py path/to/roadmap.md
```

The command reads bytes, rejects invalid UTF-8, accepts a consistent LF or CRLF
style, and emits one JSON object. Invalid input exits non-zero and reports
stable error codes with one-based line numbers. The contract covers the exact
front matter, ten ordered H2 sections, required subsections and fields, the
canonical Paper URL, the `text` verification fence, and twelve ordered
unchecked definition-of-done items.

`test_validate_roadmap_template.py` runs the checked-in template plus 14
mutation families covering missing, duplicate, reordered, unknown, malformed,
checked, line-ending, and invalid-UTF-8 cases. It also proves that one stateful
Markdown scan ignores multiline HTML comments and arbitrary backtick or tilde
fences while retaining the visible section-8 command fence contract. Keep
fixtures synthetic and local. Do not add live Hermes calls, credentials,
cookies, WebSocket tickets, transcripts, provider data, secrets, hostnames,
user data, or deployment configuration to a script or test.

## Implementation proof-gate validator

Run the fail-closed implementation checklist validator from the repository root:

```text
python3 scripts/validate_proof_gates.py
```

The four-file proof-gate contract is owned by
`docs/product/implementation-proof-gates.md`, `scripts/validate_proof_gates.py`,
`scripts/test_validate_proof_gates.py`, and this README. The checklist maps the
M0 planning, source-audit, issue-template, route, fixture, Paper,
deployment/security, benchmark, accessibility, no-network, review, evidence,
and dev-integration requirements to their roadmap issues. Runtime, deployment,
live-adjacent, and release proofs remain later ordered gates; they are not M0
prerequisites.

The validator is standard-library-only and offline. It checks exact section and
subsection order, canonical roadmap keys and links, gate and evidence rows,
dependency direction, required fields, inline N/A rationales, the explicit
no-threshold statement, no live/production success claims, no-network command
shapes, and parity with the atomic issue-template contract. Measured evidence may
report observations, but target, budget, SLO, limit, and bound prose still fails
when embedded in the same value. Live claims are checked per punctuation and
conjunction clause, and preservation evidence must name a concrete accessibility
surface plus a non-circular mechanism or reason. Indented Markdown field
continuations are folded before field and semantic checks, including Unicode
numeric comparators; circular or generic reasons such as `because non-UI`
remain blocked. A single stateful Markdown scan hides multiline HTML comments
and arbitrary-length backtick or tilde fences, so hidden or fenced decoys
cannot satisfy a gate.

Success and every failure emit exactly one JSON object. Unknown CLI arguments,
invalid UTF-8, read errors, malformed input, checked or waived gates, and type
confusion fail closed without argparse usage or a traceback. The focused test
suite covers hidden/fenced content, duplicates, reorder, missing/unknown gates
and evidence, wrong issue links, stale blockers, waived status, N/A and
threshold mutations, line endings, invalid UTF-8, CLI failures, and input
boolean/type confusion. Keep all proof fixtures synthetic, redacted, local, and
free of credentials, cookies, tickets, transcripts, provider data, hostnames,
tokens, secrets, or user data.

## Accessibility evidence

- Accessibility is **N/A** for this non-UI command-line artifact: it has no
  focus order, semantic control names, screen-reader surface, VoiceOver,
  Switch Control, Dynamic Type, browser zoom, contrast theme, motion, or touch
  target to exercise.
- Preservation evidence: the validator reads the template bytes and emits
  diagnostics only; it never rewrites the template or removes the template's
  keyboard, semantic, screen-reader, contrast, reduced-motion, or touch-target
  fields. Structural failures remain fail-closed instead of silently accepting
  an inaccessible or incomplete issue contract.

## Reproducible benchmark evidence

This is artifact and local validator evidence, not a product performance budget.
No threshold is claimed.

- Environment: macOS-26.5.2-arm64-arm-64bit-Mach-O, Python 3.14.6.
- Build mode: N/A — this is a standard-library source script with no production
  or release build.
- Repetitions and distribution: 10 fresh subprocess runs; report min, median,
  and max validator duration in milliseconds.
- Artifact-size evidence from the same checkout: validator `38,208` bytes,
  tests `16,715` bytes, and this README `5,807` bytes.
- Validator-duration evidence from the same checkout: min `41.527` ms, median
  `42.870` ms, max `45.918` ms; every run returned the valid-template JSON result.
- Raw command:

```sh
python3 - <<'PY'
import json, platform, statistics, subprocess, sys, time
from pathlib import Path
paths = [Path('scripts/validate_roadmap_template.py'),
         Path('scripts/test_validate_roadmap_template.py'),
         Path('scripts/README.md')]
durations = []
for _ in range(10):
    start = time.perf_counter()
    result = subprocess.run(
        [sys.executable, 'scripts/validate_roadmap_template.py',
         '.github/ISSUE_TEMPLATE/roadmap.md'],
        check=False, capture_output=True)
    durations.append((time.perf_counter() - start) * 1000)
    assert result.returncode == 0
print(json.dumps({
    'environment': {'platform': platform.platform(),
                    'python': sys.version.split()[0]},
    'repetitions': 10,
    'distribution_ms': {'min': min(durations),
                        'median': statistics.median(durations),
                        'max': max(durations)},
    'artifact_size_bytes': {str(path): path.stat().st_size for path in paths},
}))
PY
```

Keep the product milestone `v0.0.1` separate from date-based git tags
`vYYYY.MM.DD.<patch-num>`.
