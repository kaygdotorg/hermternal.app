# Offline web dependency inventory

Status: focused planning/security inventory for R-07A / issue #192.

This unit reads only the web prototype's local dependency manifest and Bun
lockfile. It does not install packages, update versions, rewrite `bun.lock`,
contact a registry, call a vulnerability service, inspect a live proxy, or
claim that vulnerabilities are absent or that an online CVE audit ran.

## Scope and result contract

The harness is [`scripts/dependency_audit.py`](../../scripts/dependency_audit.py).
Its default inputs are:

- `apps/web/package.json`;
- `apps/web/bun.lock`.

The report is one compact, sorted JSON object. It uses the fixed schema
`hermternal.dependency-audit.v1`, emits only repository-relative logical input
labels, sanitizes variable strings, and never includes an absolute checkout
path or raw exception text. Input SHA-256 values bind the exact local bytes that
were inspected. Package names, requested ranges, resolved versions, dependency
counts, and integrity strings are reported in stable sorted order.

The status values are:

- `pass`: the local inventory completed with no finding;
- `review`: the inventory completed with no blocking pin/integrity/graph
  finding, but manual evidence is still required;
- `fail`: a bounded input, parse, pin, integrity, manifest/lock mismatch, or
  dependency-resolution check failed.

`ok` means that no blocking finding was present. The current repository is
expected to return exit code `0` with status `review`: the command is a completed
inventory, not a claim that every legal, privacy, or runtime review has already
been completed. A mutation that creates a blocking finding returns exit code
`1` while still emitting the structured report. If serialization itself exceeds
the output bound, the CLI emits one fixed sanitized `output-too-large` failure
report and returns exit code `1`; it never reports success for a truncated or
replaced result.

The lockfile `lockfileVersion` is accepted only as the exact integer `1`;
boolean `true` and float `1.0` lookalikes are rejected. `configVersion` is also
required to be a bounded non-negative integer and only that validated scalar is
emitted; malformed objects, strings, booleans, floats, and oversized values fail
closed without being copied into the report.

The report always states:

```json
{
  "offline": true,
  "network_access": false,
  "online_vulnerability_scan": "not_run",
  "claims": {
    "vulnerabilities": "not_assessed_offline",
    "online_cve_audit": "not_run"
  }
}
```

`not_assessed_offline` is deliberate: the local inventory does not establish
that vulnerabilities are absent. These fields are scope controls, not a
vulnerability assessment, and the report must not imply that an online CVE audit
ran when `online_cve_audit` is `not_run`.

## Inventory behavior

The harness compares the manifest's `dependencies`, `devDependencies`, and
`optionalDependencies` with the Bun workspace root, then resolves the bounded
local graph from all three roots. Optional root declarations are inventoried as a
separate direct role and use the same exact-pin requirement as runtime and dev
roots. The report separates:

- `inventory.direct.runtime`: direct runtime dependencies;
- `inventory.direct.dev`: direct development dependencies;
- `inventory.direct.optional`: direct optional dependencies;
- `inventory.transitive`: all other reachable lock records, including optional
  platform records and parent-scoped Bun virtual locators;
- `lockfile.unreachable`: lock records not reached from the runtime, development,
  or optional dependency roots.

Dependency, optional-dependency, and peer-dependency edges are counted across
the entire parsed lock graph, including records that are unreachable from the
workspace roots. Missing ordinary or optional edges are blocking. A required
peer edge is also blocking
when no local version satisfies it or when its specification is unsupported or
malformed; an explicitly optional peer may remain absent and is retained in the
`peer_dependency_gaps` diagnostics. Exact manifest versions and exact `npm:`
aliases are pinned. Every lock record must resolve to an exact semantic version
and carry a valid base64-encoded `sha1`, `sha256`, `sha384`, or `sha512`
integrity string whose decoded digest has the algorithm's required length. The
harness reports integrity values; it does not recompute registry payload hashes
because package payloads are intentionally outside this offline input scope.

Bun v1 virtual keys such as
`@testing-library/dom/aria-query` and `data-urls/whatwg-url` are supported.
When several local versions satisfy a range, a parent-scoped virtual key wins;
otherwise the highest locally resolved semantic version is selected. The matcher
never falls back to an unmatched local version: unsupported, malformed, or
unsatisfied transitive and peer specifications fail closed. Its bounded npm
subset requires canonical numeric components, rejects leading-zero and repeated
`v` forms, validates every union arm, and excludes prerelease candidates from
caret, tilde, comparator, and wildcard ranges unless the range arm explicitly
admits a prerelease. Comparator operands with omitted or wildcard components
use npm partial expansion: `>1` becomes `>=2.0.0`, `>1.2.x` becomes
`>=1.3.0`, and `<=1.2.x` becomes `<1.3.0`; comparator operands that are only a
wildcard are rejected. The same rules apply to required peer ranges. An `npm:`
alias must match both the dependency-name lock key and the descriptor's target
package name, then match its exact target version. Unsupported or ambiguous
shapes fail closed rather than inventing a network resolution.

## Current origin/dev baseline

The implementation branch starts at the exact `origin/dev` parent
`c59b5bcdaa1978d6e5c77cccaa31770ce0a82723`. On that input, the inventory
reports:

- 2 direct runtime dependencies;
- 16 direct development dependencies;
- 181 transitive dependencies;
- 199 locked package records, all reachable;
- 292 local dependency edges;
- 199 present and valid lockfile integrity strings;
- 0 missing-integrity entries;
- 0 invalid-integrity entries;
- 0 unpinned lock entries;
- `@wterm/dom@0.3.2` and `@wterm/ghostty@0.3.2` as exact direct runtime entries.

The current report is `review` for three bounded reasons:

1. the Bun lockfile does not contain complete license metadata for its 199
   package records;
2. `package.json` does not contain a machine-readable dependency privacy/data
   flow review register; and
3. an inventory of two files cannot prove source-level lazy loading or runtime
   disposal behavior.

The first two are evidence gaps, not statements that a package has an invalid
license or collects data. The third is an explicit boundary on what this unit
can prove. The existing terminal source contract and tests remain the source of
truth for lazy imports, accessibility normalization, bounded terminal state,
and lifecycle behavior.

## Web-only Terminal boundary

The two W-Term packages are assessed as one web-only Terminal boundary:

| Check | Result |
| --- | --- |
| Declaration | Both are direct `dependencies`, not `devDependencies`. |
| Pin | Both request exact `0.3.2`. |
| Lock resolution | Both resolve to `0.3.2`. |
| Integrity | Both have valid lockfile integrity strings. |
| Support package | `@wterm/core@0.3.2` is transitive and reachable. |
| Client scope | This unit covers `apps/web`; iOS, iPadOS, and macOS are excluded. |
| Source behavior | Not assessed by this two-file inventory. |

This is an allowed web runtime declaration, not permission to add W-Term or
Ghostty to an Apple client. The harness intentionally does not turn package
names into a claim that dynamic imports, WASM loading, or renderer cleanup are
correct. Those behaviors remain covered by the existing web Terminal boundary
artifacts under `apps/web/src/lib/terminal/`.

## License and privacy review gaps

Bun's lockfile records package resolution metadata and integrity strings, not
license notices or a legal review decision. The harness therefore counts locked
records with no local license metadata and emits a review finding. It does not
infer SPDX identifiers, compatibility, ownership, or legal approval.

The web manifest also has no machine-readable dependency privacy/data-flow
register. The harness emits a review finding because the local inputs do not
show which dependencies have been reviewed for network, telemetry, storage, or
user-data behavior. It does not claim that a dependency performs any of those
behaviors. A later review may add evidence without changing this inventory's
offline and no-registry contract.

## Bounds and deterministic operation

The script applies these fixed limits before or during traversal:

| Bound | Value |
| --- | ---: |
| Each input file | 1 MiB |
| Lock package records | 4,096 |
| Dependency edges | 65,536 |
| Sanitized output | 2 MiB |
| Audit wall-clock budget | 10 seconds |

The audit uses only Python's standard library. Input paths must remain inside
the repository root; each path component and the final file are opened through
no-follow descriptors, and only regular files are read. Symlinks, FIFOs, devices,
and other special-file races fail without waiting for a writer. The reader takes
at most one extra byte to detect an oversized file, rejects invalid UTF-8, rejects
duplicate JSON keys, and accepts only Bun's bounded JSON5 comments/trailing-comma
form. Bun's valid but broader JSON5 grammar—such as unquoted keys, single-quoted
strings, hexadecimal/leading-dot/trailing-dot numbers, and non-finite
constants—is rejected with a deterministic `*-json5-unsupported` finding
rather than silently rewritten. Unexpected failures map to stable codes without
a traceback. No
subprocess, socket, HTTP client, package manager, registry, or vulnerability API
is used.
The report omits runtime duration so repeated runs remain byte-for-byte stable
for identical input bytes.

## Reproducible commands

Run from the repository root:

```sh
python3 scripts/dependency_audit.py
python3 scripts/test_dependency_audit.py
python3 -O scripts/test_dependency_audit.py
python3 -m unittest scripts.test_dependency_audit
python3 -O -m unittest scripts.test_dependency_audit
python3 -m py_compile scripts/dependency_audit.py scripts/test_dependency_audit.py
```

The focused suite includes real checked-in manifest/lockfile assertions, stable
CLI JSON checks, virtual Bun locator coverage, transitive graph coverage, pin
and integrity mutations, invalid UTF-8 and size-bound mutations, and unknown
argument handling. Normal and optimized runs use only local synthetic bytes and
checked-in dependency artifacts.
