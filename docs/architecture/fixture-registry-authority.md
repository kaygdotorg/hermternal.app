# Aggregate fixture registry authority

## Purpose

The aggregate fixture registry has a staged trust boundary. The legacy v1
authority remains a readable compatibility record. The new multi-artifact
bootstrap is a separate v2 authority and is the only authority consumed by the
standalone verifier in this change. Neither format is a production attestation;
`live_claim` remains `false`.

## Version and path history

The legacy authority was established at commit `a96889c` with this exact path
and a schema plus six legacy fields (seven total keys):

- path: `scripts/fixture_registry_authority.json`;
- schema: `hermternal.fixture-registry-authority.v1`;
- six legacy fields: `validator_path`, `validator_size_bytes`,
  `validator_sha256`, `baseline_path`, `baseline_size_bytes`, and
  `baseline_sha256`.

Commit `3600975` introduced a `.v2.json` filename but retained the legacy v1
schema plus six legacy fields (seven total keys). That was a filename-only
rotation, not a real v2 schema. Scanner preparation commit `70d5963` carried that historical distinction
forward: it referred to the separate `.v2.json` path while leaving the authority,
index, and baseline rotation unresolved.

The independent bootstrap commit `8dad73e` introduced the new multi-artifact
shape at the legacy path while still claiming the v1 schema. Its Git object and
published history are preserved unchanged. This follow-up supersedes that
mislabelled stage without rewriting its history: the current legacy path is
restored to the readable v1 schema plus six legacy fields (seven total keys),
and the new multi-artifact authority is introduced at:

`scripts/fixture_registry_authority.v2.json`

The new document explicitly declares
`hermternal.fixture-registry-authority.v2`. It is anchored to the external
predecessor `abb6754bddd1cf18927b0172ed9fa3456235b035`, not to its own
implementation commit and not to the scanner-preparation change.

## Active v2 loading rule

The standalone verifier reads only the v2 authority path from the sole
first-parent Git commit that introduced that path. It does not use the visible
checkout copy as its authority source. It reads the v2 bytes from the local Git
object database, validates the schema and key order, and requires all of the
following:

- the declared predecessor is a distinct ancestor of the v2 authority
  introduction commit;
- the four declared paths resolve at that predecessor to the recorded Git blob
  object IDs;
- each predecessor object has the recorded byte length and SHA-256 digest; and
- the checkout copies of the v2 authority, index, validator tests, validator,
  and validation baseline exactly match those immutable predecessor records.

The legacy v1 path remains readable through the verifier's compatibility loader,
but it is not selected as the active v2 trust root. The v2 path selection is
therefore explicit and cannot silently fall back to a schema-incompatible v1
record.

The object-repository input is a canonical absolute plain checkout. The
verifier rejects a symlinked `.git`, a linked-worktree `.git` file, external or
symlinked `gitdir`/`commondir` metadata, and symlinked object/ref/config
boundaries. It descriptor-walks the complete `objects` and `refs` trees with
`O_NOFOLLOW`, so nested fanout, pack, and ref symlinks cannot redirect reads.
It also rejects local `info/grafts`, shallow metadata,
`objects/info/alternates`, `objects/info/http-alternates`, replacement refs,
partial-clone/promisor settings, and local include or URL-redirection config.
A disposable plain clone is therefore required when the caller is operating
from a Git worktree. The host's `/usr/bin/git` is checked as an absolute,
regular executable; Git helper lookup is fixed to `/usr/bin:/bin`, while
system/global config and inherited `GIT_*` redirect variables are removed.
These host paths are a trusted-host boundary for this synthetic fixture proof,
not a claim about production deployment security.

Checkout reads use descriptor-relative `O_NOFOLLOW | O_NONBLOCK` opens and
regular-file descriptor checks. They stop after `MAX_GIT_OUTPUT` bytes, so a
FIFO or oversized replacement fails promptly. Git stdout and stderr are also
collected incrementally; either stream reaching the cap terminates or kills
the child and drains both pipes without retaining unbounded output. Timeouts,
non-zero exits, and pipe failures use the same bounded error path. The
declared `source_commit` must be a Git `commit` object, not an annotated tag
object. Path resolution, Git executable, config, and subprocess failures are
converted to the same bounded redacted authority error.

Run the standalone verifier from a plain checkout with:

```sh
python3 scripts/verify_fixture_registry_authority.py
python3 -O scripts/verify_fixture_registry_authority.py
```

When the source and checkout roots differ, pass canonical absolute paths:

```sh
python3 scripts/verify_fixture_registry_authority.py \\
  --repo-root /absolute/plain/checkout \\
  --checkout-root /absolute/fixture/checkout
```

Both modes emit one bounded JSON line. A failure is redacted, has
`"live_claim":false`, and does not echo paths, arguments, keys, values, or a
traceback. No command fetches a remote or opens a network connection. Run the
focused regression suite in both interpreter modes:

```sh
python3 scripts/test_fixture_registry_authority.py
python3 -O scripts/test_fixture_registry_authority.py
python3 -m py_compile scripts/verify_fixture_registry_authority.py scripts/test_fixture_registry_authority.py
python3 -O -m py_compile scripts/verify_fixture_registry_authority.py scripts/test_fixture_registry_authority.py
```

## Rewrite resistance

The regression suite copies the legacy v1 record, v2 authority, and four v2
trust-input paths to a temporary directory. It proves that normal and optimized
verification:

- can still read the exact legacy v1 path and schema plus six legacy fields (seven total keys);
- selects v2 even when the temporary legacy path is rewritten;
- rejects a checkout-only rewrite of the v2 authority;
- rejects a checkout-only rewrite of the aggregate index; and
- rejects coordinated local rewrites of the v2 authority, index, baseline,
  validator, and validator-test files without creating a replacement Git
  repository or authority commit.

The same normal and optimized suite also rejects warning-suppressed grafts,
shallow histories, empty local object stores that use alternates, replacement
refs, nested fanout/pack/ref symlinks, symlinked or linked Git metadata, local
include/promisor/redirect configuration, annotated-tag source objects, FIFO
artifact paths, hostile Git `PATH`/global config, and checkout/object-root
resolution failures. It bounds oversized blob, stderr, and history output in
both interpreter modes without waiting for the helper process to finish. The
FIFO and output-cap cases assert prompt bounded exit rather than relying on a
post-timeout kill.

The real Git object database remains the source of truth throughout these
mutations. A local replacement authority therefore cannot authorize a matching
local scanner or baseline rewrite.

## Current aggregate sequencing

The current aggregate validator remains intentionally blocked in this bootstrap
change. The present blocked evidence is caused by three stale artifact records
under `source-audit/compatibility-gate` in the current aggregate index; those
records are not the future scanner-boundary blockers. Normal and optimized
validator runs have the same bounded result:

```json
{"compatible":false,"complete":false,"error":{"code":"fixture_index_invalid","message":"fixture registry input rejected"},"evidence_status":"blocked","live_claim":false,"ok":false}
```

The existing aggregate launcher remains 22 tests with two CLI failures and one
checked-in-registry error against the stale index/baseline state. No pending-root
exemption or scanner weakening is added here.

The exact three scanner blockers owned by the subsequent `70d5963`
preparation rebase are:

- `contracts/fixtures/chat-stream-completion/test_validate.py`
- `contracts/fixtures/deployment-security/external-allowlist/test_validate.py`
- `contracts/fixtures/uncertain-delivery/test_validate.py`

After this v2 authority bootstrap is independently reviewed and merged, the
scanner-preparation lane must rebase onto the merged external predecessor,
correct those three scanner cases without weakening aggregate trust, regenerate
the complete index and baseline, and create its next authority from that merged
external predecessor. The historical v1 path must remain readable while that
migration is reviewed.

## Scope and evidence

All authority fixtures and test mutations are synthetic and local. The verifier
proves only exact Git-object and checkout integrity. Passing it is not evidence
of Hermes availability, deployment compatibility, authentication, provider
behavior, or user data.
