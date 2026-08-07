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
`hermternal.fixture-registry-authority.v1`.

The `.v2.json` filename used by commits `3600975` and `70d5963` was a
filename-only rotation: those historical documents still declared the v1
schema plus six legacy fields (seven total keys). The independent bootstrap commit `8dad73e` then
introduced a multi-artifact document at the legacy path while still claiming
v1. Its published Git object is not rewritten. The corrective bootstrap keeps
the legacy path readable and places the new multi-artifact authority at
`scripts/fixture_registry_authority.v2.json` with the explicit schema
`hermternal.fixture-registry-authority.v2`.

The standalone v2 verifier loads that separate path from its immutable Git
introduction object. It can read the legacy v1 shape for migration checks, but
it never treats the legacy path as a v2 fallback. The v2 trust root accepts
only the approved external predecessor
`abb6754bddd1cf18927b0172ed9fa3456235b035`; an arbitrary self-consistent
ancestor is rejected. The trust root remains independent of the
scanner-preparation change; after this authority is merged, that preparation
must rebase onto the merged external predecessor before regenerating the index,
baseline, and next authority.

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
`objects/pack` uses `MAX_SNAPSHOT_PACK_FILE_BYTES` (8 MiB) for legitimate pack,
index, reverse-index, bitmap, and related pack metadata. The aggregate cap is
`MAX_SNAPSHOT_TOTAL_BYTES` (32 MiB), with a `SNAPSHOT_TIMEOUT_SECONDS` (30
second) wall-clock deadline. The 8 MiB pack cap derives from the supported
repository's fresh single-branch remote-clone observation of a roughly 2.1 MiB
pack; it leaves measured growth headroom while keeping individual files
bounded. The 1 MiB non-pack cap remains above the checked-in evidence and
metadata sizes. It rejects symlinks/non-regular entries and checks source
metadata before and after each copy. Git then runs only against that snapshot,
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
samples use exact path/value allowances only. Domain validators remain
authoritative for case semantics; the aggregate layer does not run them and
makes no network request.

The `--index`, `--schema`, and `--baseline` inputs are bound to their canonical
reviewed paths. The exact central-validator and baseline bytes are pinned by
`scripts/fixture_registry_authority.v2.json` from an immutable Git object, not
from checkout constants. That object is a trust root only when its authority
rotation was reviewed before, and outside, the scanner change it authorizes: an
implementation commit must never introduce a weakened scanner and the authority
that approves it in the same change set. The v1 authority remains historical
evidence until an independently reviewed rotation establishes the v2 bytes;
therefore baseline and authority regeneration is blocked until that migration
exists. Only the validator's own baseline-manifest digest and derived byte total
are normalized to avoid a self-reference. A schema-valid copy or coordinated
scanner, manifest, baseline, local anchor, and test-constant replacement cannot
rebind an immutable external authority.

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
C-07A session search, C-07B session lineage, C-14 image attachment lifecycle,
C-16 deep-link resolution, C-18 PTY detach-race, DEP-02 external method/path
allowlist, DEP-10M PTY local-adapter, and DEP-11 direct-port-denial artifacts.
The merged PR #260 compatibility-gate artifact manifests are also refreshed in
this aggregate registry.
`review-anchors/deep-link-resolution.sha256` is intentionally separate: it is
the C-16 domain validator's reviewed digest authority, not a canonical fixture
root. The aggregate permits that one exact path and still rejects any other
unindexed review-anchor artifact. The C-05 coverage and C-08 stream-dependent
coverage remain pending until their dependency gates complete; C-07 is connected
to the pending chat-stream coverage row. `live_claim` is always `false`; a
passing validator proves only synthetic artifact integrity and registry
consistency. The current blocked aggregate evidence is caused by three stale
artifact records under `source-audit/compatibility-gate`; that current index
problem is distinct from the three future scanner-preparation blockers listed
in the authority migration document.

The validator emits one bounded semantic JSON line. Failures do not echo
arguments, paths, keys, values, secrets, or tracebacks. Normal and optimized
Python runs share the same checks:

```sh
python3 contracts/fixtures/validator/validate.py
python3 -O contracts/fixtures/validator/validate.py
python3 contracts/fixtures/validator/test_validate.py
python3 -O contracts/fixtures/validator/test_validate.py
python3 -m unittest discover -s contracts/fixtures/validator -p 'test_*.py'
python3 -O -m unittest discover -s contracts/fixtures/validator -p 'test_*.py'
python3 -m py_compile \
  contracts/fixtures/validator/validate.py \
  contracts/fixtures/validator/test_validate.py
```

The repository does not yet have a checked-in GitHub Actions workflow that
runs this aggregate validator, its test suite, and the `python -O` equivalents.
That missing normal/optimized CI check is intentional while the independent
v2 authority rotation is unresolved; it must be added only after the external
trust root and regenerated baseline are reviewed.

The validator is offline. It does not start Hermes, contact a proxy or
identity provider, open a socket, follow a referenced URL, or claim deployment
compatibility. `validator/validation-baseline.json` records 30 raw process
samples and their min/p50/p95/max/mean distributions for normal and optimized
runs. It is reproducibility evidence only: `threshold` is intentionally `null`
until the benchmark-method work defines an approved budget.

## P0-01 source review

The source-derived planning claims are reconciled by the local [P0-01 review record](source-audit/planning-reconciliation/planning_review.json). Reproduce it with the [validator](source-audit/planning-reconciliation/validate.py) against a local checkout of the pinned Hermes SHA. This evidence is source-only: it does not contact a live Dashboard or replace deployment attestation, behavioral probes, parity tests, or the focused source-audit units owned by issue `#200` and PRs `#216`, `#218`, `#219`, and `#220`.
