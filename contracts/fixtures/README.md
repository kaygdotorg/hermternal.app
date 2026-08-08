# Protocol fixtures

This directory contains synthetic, redacted request, response, WebSocket, Terminal, and recovery fixtures for both clients.

## Required coverage

Fixtures must represent:

- browser HttpOnly-cookie auth;
- native username/password provider auth, isolated `URLSession` cookies, and WebSocket tickets;
- one profile and provider-neutral discovery;
- session restore, long sessions, streaming, interruption, reconnect, loading, empty, success, and failure;
- approvals and clarification as separate pending actions;
- idle model switching, normal deferred switching, and deferred expensive-choice confirmation loss;
- images-only attachments;
- private deep links under `/v1/c/...`;
- the full web-only `/api/pty` Terminal on a POSIX or WSL host, plus an unsupported-host negative case;
- missing and mismatched deployment attestation;
- failed behavioral probes;
- missing, malformed, expired, and reused WebSocket tickets; and
- malformed JSON with a non-sensitive marker and verified upstream log controls.

Fixtures must identify the pinned Hermes revision `f5be9236e00ddf2f2a412697f267078fc4ee068e`, contract version, expected state transitions, and whether the fixture is web-only or shared. A native OAuth/OIDC provider that requires an unsupported callback transport is a negative fixture, not a fallback path.

Use synthetic data only. Do not commit credentials, cookies, WebSocket tickets, ticket fragments, live transcripts, hostnames, tokens, secrets, provider data, or user data. Invalid-ticket fixtures use non-secret markers and verify that the pinned source's bounded audit fragment is removed from retained logs. Fixtures describe behavior; they do not create a transcript mirror.

## C-19 authority migration

The legacy aggregate authority remains readable at
`scripts/fixture_registry_authority.json`. Its historical v1 contract was
introduced at `a96889c` and has the schema plus six legacy fields (seven total
keys): `validator_path`/`validator_size_bytes`/`validator_sha256` plus
`baseline_path`/`baseline_size_bytes`/`baseline_sha256` under the schema
`hermternal.fixture-registry-authority.v1`. Its bytes remain unchanged.

The `.v2.json` filename used by commits `3600975` and `70d5963` was a
filename-only rotation, and the corrected bootstrap at
`scripts/fixture_registry_authority.v2.json` remains preserved as the reviewed
external predecessor. The active final binding is the distinct
`scripts/fixture_registry_authority.v2.final.json` path with the explicit
schema `hermternal.fixture-registry-authority.v2` and role
`aggregate_predecessor`.

The standalone verifier authenticates that historical final path from its
exact protected Git binding object. The aggregate validator authenticates the
same historical record, then loads the distinct hardened path from its own
protected binding and source pins. Each authority records the exact source
commit and four artifact records for the combined checkout:
`contracts/fixtures/index.json`, `contracts/fixtures/validator/test_validate.py`,
`contracts/fixtures/validator/validate.py`, and
`contracts/fixtures/validator/validation-baseline.json`. The source commit must
be the authority binding commit's direct first parent, so the authority cannot
self-authorize scanner or baseline changes in the same commit. Both loaders
enforce exact key order, blob OIDs, byte sizes, SHA-256 digests,
`synthetic_only: true`, and `live_claim: false` before comparing checkout bytes.
The v1 and bootstrap v2 records remain historical compatibility evidence; they
are not fallbacks for either exact-pinned v2 trust root. The historical final
and active hardened bindings are independently pinned, so a restack may leave
their introduction objects on separate reviewed ancestry lines; the direct
first-parent rule still applies within each binding.

The active hardened pins are authenticated external CI inputs supplied through
`HERMTERNAL_FIXTURE_AUTHORITY_COMMIT` and
`HERMTERNAL_FIXTURE_AUTHORITY_SOURCE_COMMIT`. The checked-in
`scripts/fixture_registry_authority.v2.hardened.pin.json` file is test
provisioning data for the versioned offline bundle only; it is never a runtime
authority fallback. Missing or malformed protected environment pins fail closed.

The verifier's object repository must be a canonical absolute plain checkout,
not a linked worktree or a checkout with symlinked `.git`, `gitdir`,
`commondir`, object, ref, or config boundaries. Before any path-based Git
command, it opens `/` and every caller ancestor through a descriptor-relative
chain with no-follow flags, allowing only the explicit host aliases `/tmp`,
`/var`, `/var/folders`, and `/var/tmp`; it then opens the caller root and `.git`
directory from those held descriptors. It copies the complete Git metadata tree
into a private mode-700 temporary snapshot. The copy is chunked and
category-bounded: ordinary metadata and loose objects use
`MAX_SNAPSHOT_FILE_BYTES` (1 MiB), while every regular file under
`objects/pack` uses `MAX_SNAPSHOT_PACK_FILE_BYTES` (16 MiB) for legitimate pack,
index, reverse-index, bitmap, and related pack metadata. The aggregate cap is
`MAX_SNAPSHOT_TOTAL_BYTES` (32 MiB), with a `SNAPSHOT_TIMEOUT_SECONDS` (30
second) wall-clock deadline. The 16 MiB pack cap covers the checked-in authority
bundle's measured roughly 11 MiB macOS clone pack while keeping each individual
file bounded. The 1 MiB non-pack cap remains above the checked-in evidence and
metadata sizes. Snapshot entry count, directory count, file count, traversal
depth, retained path storage, aggregate bytes, and deadline are bounded
independently, so arbitrarily many zero-byte metadata entries cannot consume
CI before the byte limits run. It rejects symlinks/non-regular entries and
checks source metadata before and after each copy. Git then runs only against
 that snapshot,
so concurrent rename or symlink replacement of nested fanout/pack/ref paths,
config, or metadata cannot redirect reads. The snapshot also descriptor-walks
the full `objects` and `refs` trees with no-follow descriptors as a second
structural check. It fails closed on local grafts, shallow metadata, alternates
and HTTP alternates,
replacement refs, partial-clone/promisor settings, and local include or
URL-redirection config. Git is invoked only through validated `/usr/bin/git`
with fixed helper `PATH` `/usr/bin:/bin`; inherited Git redirects and
system/global config are removed. This is a trusted-host boundary for
synthetic local evidence, not a production attestation. Before object reads,
bounded `git fsck --full --strict` verifies compressed object contents against
their OIDs, including loose objects. Checkout artifact reads are bounded
nonblocking regular-file reads. Git stdout and stderr are streamed into
separate bounded buffers; reaching the cap, a timeout, or selector setup
failure kills the isolated child session and drains both pipes. All normal and
optimized failures remain one redacted `live_claim:false` JSON line.

## C-19 aggregate registry

[`index.json`](index.json) is the language-neutral registry consumed by later
TypeScript and Swift parity checks. [`schema.json`](schema.json) documents the
wire-neutral shape. Each ready fixture root lists every checked-in artifact,
its byte count, and its SHA-256 digest. The aggregate validator also rejects
unsafe paths, duplicate JSON keys, non-finite numbers, oversized input,
malformed UTF-8, credential-shaped values, live claims, `http`/`https`/`ws`/`wss`
live hosts, URL userinfo passwords, symlinks, unsupported registered extensions,
and unindexed artifacts. Credential routing covers `api_key`, `x-api-key`,
`access_token`, `refresh_token`, `client_secret`, and their reviewed normalized
aliases across text assignments, query strings, JSON redaction trees, and
Python AST names, keyword arguments, dictionary keys, and request-like
subscripts. C0/C1 controls and Unicode format characters are scanned in a
compact and boundary-preserving form; JSON keys containing them are rejected.
Registered Python artifacts are parsed and their retained string literals,
comments, and bounded source constructions are scanned. Flow joins keep a name
unknown after conflicting assignments, and dynamic Authorization schemes or
secrets receive a bounded probe instead of being treated as safe. Regex URL
hosts decode only bounded literal escapes and fail closed for escaped letters,
uncertain character classes, verbose whitespace, comments, or other recovery
gaps. Detector regex definitions and explicit domain negative-test markers are
not treated as retained credentials. Reviewed source markers and negative-test
samples use exact path/value allowances only. Reserved `.invalid` hosts are not
accepted by suffix; comma-joined URLs, IPv6/address canaries, malformed ports,
and backslash/bracket continuations are admitted only as exact raw URL tokens
in the reviewed artifact that owns the negative case. Unknown Python runtime
values use the exact synthetic host `synthetic.invalid` plus an explicit
Authorization probe, so dynamic credential checks do not widen the URL policy.
Domain validators remain authoritative for case semantics; the aggregate layer
does not run them and makes no network request.

The `--index`, `--schema`, and `--baseline` inputs are bound to their canonical
reviewed paths. The exact central-validator, validator-test, index, and baseline
bytes are pinned by the distinct v2 authority objects from immutable Git
objects, not from checkout constants: the historical final path is the
standalone verifier's trust input, and the hardened path is the aggregate
validator's active trust input. Each exact binding is checked against its own
first-parent source commit; the two v2 bindings are independently pinned and
do not require the active restack to preserve the historical binding as an
ancestor. Only the validator's own baseline-manifest digest and derived byte
total are normalized to avoid a self-reference. A schema-valid copy or
coordinated scanner, manifest, baseline, local anchor, and test-constant
replacement cannot rebind an immutable external authority.

Every ordinary file under a ready fixture root is inventoried, including hidden
files, cache contents, bytecode, and binary artifacts. Symlinks and special files
are rejected explicitly; unsupported extensions or unreviewed helpers are not
silently skipped. The central `validator/` directory has an exact artifact
allowlist. Ready-root metadata must name a supported executable Python validator
role (`validate.py` or `test_*.py`) and a real manifest; `README.md`, `cases.json`,
and arbitrary non-executable files are not validator roles. Coverage references
must be reciprocal, and every coverage platform and required state must be
supported by every referenced root. Ready coverage may reference only ready
fixture roots with named validators and real manifests. A registry can be
structurally valid while coverage remains `partial`. A `pending`, `empty`,
`failure`, `cancelled`, or `unknown` coverage row is never promoted to
successful evidence. The checked-in index inventories the C-05
connection-restoration, C-06 uncertain delivery, C-07 session persistence,
C-07A session search, C-07B session lineage, C-08 chat stream and completion,
C-14 image attachment lifecycle, C-16 deep-link resolution, C-18 PTY
detach-race, DEP-02 external method/path allowlist, DEP-03 Host/Origin mapping,
DEP-10M PTY local-adapter, and DEP-11 direct-port-denial artifacts. The merged
PR #260 compatibility-gate artifact manifests are also refreshed in this
aggregate registry.
`review-anchors/deep-link-resolution.sha256` is intentionally separate: it is
the C-16 domain validator's reviewed digest authority, not a canonical fixture
root. The aggregate permits that one exact path and still rejects any other
unindexed review-anchor artifact. The C-05 coverage and C-08 stream-dependent
coverage remain pending until their dependency gates complete; C-07 is connected
to the pending chat-stream coverage row. `live_claim` is always `false`; a
passing validator proves only synthetic artifact integrity and registry
consistency. The final combined tree has no stale
`source-audit/compatibility-gate` rows: all three pre-existing records match
mechanically derived bytes, and the twelve overlapping Caddy-owned records are
bound to the approved `5b923fd38e056c37bdb86766f05551cd83687b66` descendant.

The validator emits one bounded semantic JSON line. Failures do not echo
arguments, paths, keys, values, secrets, or tracebacks. The aggregate authority
also requires a separate canonical plain Git object repository; the checkout
being scanned must not be reused as that object repository. Supply the protected
active authority pins and the object repository for both CLI modes:

```sh
CHECKOUT="$PWD"
OBJECT_REPO=/absolute/path/to/separate/plain-clone
export HERMTERNAL_FIXTURE_AUTHORITY_COMMIT=<protected-authority-introduction>
export HERMTERNAL_FIXTURE_AUTHORITY_SOURCE_COMMIT=<protected-source-predecessor>
export PYTHONDONTWRITEBYTECODE=1
python3 -B contracts/fixtures/validator/validate.py \
  --repo-root "$CHECKOUT" --object-repo "$OBJECT_REPO"
python3 -O -B contracts/fixtures/validator/validate.py \
  --repo-root "$CHECKOUT" --object-repo "$OBJECT_REPO"
python3 -B contracts/fixtures/validator/test_validate.py
python3 -O -B contracts/fixtures/validator/test_validate.py
python3 -B -m unittest discover -s contracts/fixtures/validator -p 'test_*.py'
python3 -O -B -m unittest discover -s contracts/fixtures/validator -p 'test_*.py'
python3 -B -c 'from pathlib import Path; import sys; [compile(Path(path).read_text(encoding="utf-8"), path, "exec", optimize=0) for path in sys.argv[1:]]' \
  contracts/fixtures/validator/validate.py \
  contracts/fixtures/validator/test_validate.py
python3 -O -B -c 'from pathlib import Path; import sys; [compile(Path(path).read_text(encoding="utf-8"), path, "exec", optimize=1) for path in sys.argv[1:]]' \
  contracts/fixtures/validator/validate.py \
  contracts/fixtures/validator/test_validate.py
```

`-B` and `PYTHONDONTWRITEBYTECODE=1` are intentional. The central validator
rejects any unindexed `__pycache__` entry, and `py_compile` writes bytecode even
when `-B` is supplied. The two compile-only commands therefore call Python's
built-in `compile` without writing a cache.

The protected values are review/CI inputs, not values inferred from a branch,
tag, or the checkout. The plain clone must contain the exact protected
historical and active authority/source objects, must not be a linked worktree,
and must not use alternates, shallow or promisor metadata, replacement refs,
grafts, or redirecting Git configuration. A fresh single-head clone does not
necessarily retain those unreachable objects; seed all four protected OIDs into
local `refs/fixture-authority/*` refs before running either validator mode. The
aggregate and standalone suites consume the same explicit, offline,
repository-versioned source at `scripts/fixture_registry_authority.objects.bundle`.
Its 11,092,429 bytes are pinned by SHA-256
`0554da22401f197d1f8df9118de88342e895398d0b5b0df48df38fbb71023fa4`, and
`git bundle list-heads` is required to contain exactly these four refs:

```text
refs/fixture-authority/active-authority e8f09813bb87eb38dd03d4a3b4d59b0dbe0091e2
refs/fixture-authority/active-source f82d74224af050fc669273ac57dfff13f588f093
refs/fixture-authority/historical-authority 285acdcf9c11c049180a7844e689eee0f1490de4
refs/fixture-authority/historical-source 263cb75adcf153d6fe252636b064e5fbc3e3f877
```

The shared test helper verifies the bundle digest, complete-bundle status, exact
ref listing, and `commit` type/OID for each fetched object before installing the
refs. Its explicit offline provisioning shape is:

```sh
git -C "$OBJECT_REPO" fetch --no-tags --quiet \
  "$PWD/scripts/fixture_registry_authority.objects.bundle" \
  285acdcf9c11c049180a7844e689eee0f1490de4:refs/fixture-authority/historical-authority \
  263cb75adcf153d6fe252636b064e5fbc3e3f877:refs/fixture-authority/historical-source \
  e8f09813bb87eb38dd03d4a3b4d59b0dbe0091e2:refs/fixture-authority/active-authority \
  f82d74224af050fc669273ac57dfff13f588f093:refs/fixture-authority/active-source
```

The aggregate test classes assert that an unseeded clean clone is blocked before
a seeded clone is accepted. No test fetches a remote or uses the reviewed
checkout as authority.

The repository does not yet have a checked-in GitHub Actions workflow that
runs this aggregate validator, its test suite, and the `python -O` equivalents.
The local normal/optimized commands above are the required gates for this
fixture-only lane; no CI workflow is implied by passing them. The aggregate
registry does not own the Caddy binary proof gate: `scripts/test_caddy_proof.py`
is the separate PR #300 black-box lane and may skip when local Caddy or OpenSSL
dependencies are unavailable. The registry records only reviewed redacted
Caddy fixture bytes and approved source identities; a dependency skip cannot
be promoted to live proof here.

The validator is offline. It does not start Hermes, contact a proxy or
identity provider, open a socket, follow a referenced URL, or claim deployment
compatibility. `validator/validation-baseline.json` records 30 raw process
samples and their min/p50/p95/max/mean distributions for normal and optimized
runs. It is reproducibility evidence only: `threshold` is intentionally `null`
until the benchmark-method work defines an approved budget.

## P0-01 source review

The source-derived planning claims are reconciled by the local [P0-01 review record](source-audit/planning-reconciliation/planning_review.json). Reproduce it with the [validator](source-audit/planning-reconciliation/validate.py) against a local checkout of the pinned Hermes SHA. This evidence is source-only: it does not contact a live Dashboard or replace deployment attestation, behavioral probes, parity tests, or the focused source-audit units owned by issue `#200` and PRs `#216`, `#218`, `#219`, and `#220`.
