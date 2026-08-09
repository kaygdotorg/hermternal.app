# Aggregate fixture registry authority

## Purpose

The aggregate fixture registry has a staged trust boundary. The legacy v1
authority remains a readable compatibility record, and the reviewed bootstrap
and final v2 authorities remain preserved historical evidence. The aggregate
validator uses a distinct hardened v2 path introduced after the corrected
aggregate predecessor and selects it through protected runtime pins. The
standalone verifier continues to authenticate the historical final v2 path;
the aggregate validator authenticates that verifier's bytes before loading the
hardened path. Neither format is a production attestation; `live_claim` remains
`false`.

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

The bootstrap document explicitly declares
`hermternal.fixture-registry-authority.v2` and remains byte-for-byte preserved
as historical predecessor evidence. The historical final aggregate binding is
preserved at:

`scripts/fixture_registry_authority.v2.final.json`

The active corrected aggregate binding is introduced at the distinct path:

`scripts/fixture_registry_authority.v2.hardened.json`

Both use the same v2 schema with role `aggregate_predecessor`. Each
`source_commit` is the exact aggregate predecessor for its pinned binding commit
and must equal that commit's first parent. This direct-parent rule keeps an
authority path out of the scanner/index/baseline commit it authorizes and avoids
a self-referential source hash inside `validate.py`. The historical final and
active hardened bindings are independently exact-pinned reviewed objects; the
active binding does not assume that a later restack preserves the historical
binding as an ancestor. Active binding and source commits are supplied through
protected runtime pins, not inferred from a branch or tag. Those pins are
authenticated external CI inputs supplied through
`HERMTERNAL_FIXTURE_AUTHORITY_COMMIT` and
`HERMTERNAL_FIXTURE_AUTHORITY_SOURCE_COMMIT`; missing or malformed values fail
closed. The checked-in `scripts/fixture_registry_authority.v2.hardened.pin.json`
is test provisioning data for the versioned offline bundle only and is never a
runtime fallback.

## Active v2 loading rule

The standalone verifier reads the historical
`scripts/fixture_registry_authority.v2.final.json` from its exact protected
binding commit. It does not use the visible checkout copy as its authority
source or infer a replacement from `HEAD`. The aggregate validator authenticates
the standalone verifier bytes, verifies that historical binding, then reads the
active `scripts/fixture_registry_authority.v2.hardened.json` from its exact
protected binding and source pins. Both paths are read from the local Git
object database, and each authority must satisfy all of the following:

- the declared `source_commit` is a commit object and exactly equals that
  authority binding commit's first parent;
- the four declared paths resolve at that predecessor to the recorded Git blob
  object IDs;
- each predecessor object has the recorded byte length and SHA-256 digest; and
- the checkout copies of the authority, index, validator tests, validator, and
  validation baseline exactly match those immutable predecessor records.

This is not a self-authenticating bootstrap root. The aggregate validator
captures `scripts/verify_fixture_registry_authority.py` and compares its SHA-256
with the binding stored in mutable `contracts/fixtures/validator/validate.py`;
active authority and source OIDs arrive through runtime pins and are checked
only for the reviewed shape. These values are consistency checks, not
independent custody. A trusted launcher or immutable external pin record must
protect the verifier digest, active authority/source OIDs, artifact and
manifest generation or digest, and rollback policy before launch; ordinary
environment variables alone do not establish that root. A checkout that can
rewrite the validator, helper, bindings, and pins together is outside this
fixture's claim. The external fixture-authority root and deterministic
authority-rotation tooling dependencies remain unresolved in this fixture lane.

The legacy v1 path and bootstrap v2 path remain readable historical records.
The final v2 path is the standalone verifier's historical trust input, while
the hardened v2 path is the aggregate validator's active trust input. Explicit
path and runtime-pin selection cannot silently fall back to a schema-incompatible
or stale predecessor record.

The object-repository input is a canonical absolute plain checkout. Before
running any path-based Git command, the verifier opens `/` and every caller
ancestor through a descriptor-relative chain, using `O_NOFOLLOW` except for the
explicit host aliases `/tmp`, `/var`, `/var/folders`, and `/var/tmp`. It then
opens the caller root and `.git` directory from the held descriptors and copies
the complete Git metadata tree into a private mode-700 temporary snapshot. The
copy is chunked and category-bounded: ordinary metadata and loose objects use
`MAX_SNAPSHOT_FILE_BYTES` (1 MiB), while every regular file under
`objects/pack` uses `MAX_SNAPSHOT_PACK_FILE_BYTES` (256 MiB) for legitimate pack,
index, reverse-index, bitmap, and related pack metadata. The aggregate cap is
`MAX_SNAPSHOT_TOTAL_BYTES` (384 MiB), and the copy has a
`SNAPSHOT_TIMEOUT_SECONDS` (30 second) wall-clock deadline. An exact remote
single-branch clone measured a 173,803,336-byte pack, leaving 94,632,120 bytes
under the finite per-pack cap. Its seeded snapshot total is 174,094,678 bytes,
leaving 228,558,506 bytes under the independent aggregate cap. Local clone pack
layout is not authoritative, and the 1 MiB non-pack cap remains unchanged. Snapshot entry,
directory, file, depth, and retained path-storage budgets remain independent of
those byte limits, so arbitrarily many zero-byte metadata entries cannot exhaust
CI before content accounting. Strict Git execution remains separately capped at
30 seconds; the measured seeded 96,034,354-byte snapshot completed strict fsck in 9.061
seconds on the fixture host, while a serial aggregate run showed 15 seconds was
marginal for its optimized seeded clone. It rejects symlinks/non-regular entries
and checks source metadata before and after each copy. Git is invoked only
against that snapshot,
so a concurrent rename or symlink replacement of the caller's `.git`, nested
fanout/pack/ref path, config, or metadata cannot redirect a later read. The
snapshot also uses a descriptor walk of the complete `objects` and `refs`
trees with `O_NOFOLLOW` as a second structural check.

The verifier rejects local `info/grafts`, shallow metadata,
`objects/info/alternates`, `objects/info/http-alternates`, replacement refs,
partial-clone/promisor settings, and local include or URL-redirection config.
A disposable plain clone is therefore required when the caller is operating
from a Git worktree. A fresh single-head clone can omit the unreachable
historical and active binding/source objects after a restack, so callers must
seed all four exact protected commit OIDs into local `refs/fixture-authority/*`
refs before verification; the verifier never infers a replacement from `HEAD`.
The aggregate and standalone regression suites consume the same explicit,
offline, repository-versioned source at
`scripts/fixture_registry_authority.objects.bundle`. Its 45,736,496 bytes are
pinned by SHA-256
`60be4d8ad08040c91d9960fc50a557f97d3987b43d4b59c5eef3d8b1341bce44`, and its
`git bundle list-heads` output is bounded to the four exact refs and OIDs:

```text
refs/fixture-authority/active-authority bb4c0af0af0f96af6c9867c64e8a009fb25e82ec
refs/fixture-authority/active-source 66680704bd0565d3f8fe06531d4abfa902639c78
refs/fixture-authority/historical-authority 285acdcf9c11c049180a7844e689eee0f1490de4
refs/fixture-authority/historical-source 263cb75adcf153d6fe252636b064e5fbc3e3f877
```

The shared test helper verifies the bundle digest, complete-bundle status, exact
ref listing, and `commit` type/OID for every fetched object before installing
those refs. It is the only provisioning source; no test fetches a remote or
uses the reviewed checkout as authority. The explicit offline fetch shape is:

```sh
git -C "$OBJECT_REPO" fetch --no-tags --quiet \
  "$PWD/scripts/fixture_registry_authority.objects.bundle" \
  285acdcf9c11c049180a7844e689eee0f1490de4:refs/fixture-authority/historical-authority \
  263cb75adcf153d6fe252636b064e5fbc3e3f877:refs/fixture-authority/historical-source \
  bb4c0af0af0f96af6c9867c64e8a009fb25e82ec:refs/fixture-authority/active-authority \
  66680704bd0565d3f8fe06531d4abfa902639c78:refs/fixture-authority/active-source
```

The host's `/usr/bin/git` is checked as an absolute, regular executable; Git
helper lookup is fixed to `/usr/bin:/bin`, while system/global config and
inherited `GIT_*` redirect variables are removed.
These host paths are a trusted-host boundary for this synthetic fixture proof,
not a claim about production deployment security.

Checkout reads use descriptor-relative `O_NOFOLLOW | O_NONBLOCK` opens and
regular-file descriptor checks. They stop after `MAX_GIT_OUTPUT` bytes, so a
FIFO or oversized replacement fails promptly. Before consuming any authority
or artifact object, the private snapshot runs bounded `git fsck --full
--strict` to verify compressed object contents match their OIDs; a corrupted
loose object under an existing filename is rejected. Git stdout and stderr are
also collected incrementally; either stream reaching the cap terminates or
kills the isolated child session and drains both pipes without retaining
unbounded output. `Popen`, selector creation, registration, collection, and
cleanup share one defensive boundary, so setup failures cannot strand a child
or an unregistered pipe. Timeouts, no-output hangs, non-zero exits, and pipe
failures use the same bounded error path. The declared `source_commit` must be a
Git `commit` object, not an annotated tag object. Path resolution, Git
executable, config, and subprocess failures are converted to the same bounded
redacted authority error.

Run the standalone verifier against a checkout of the historical final
predecessor with:

```sh
python3 -B scripts/verify_fixture_registry_authority.py
python3 -O -B scripts/verify_fixture_registry_authority.py
```

The current aggregate checkout is checked by the distinct hardened authority;
use `--checkout-root` when the plain object repository and historical
predecessor checkout are separate. Pass canonical absolute paths:

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
python3 -B scripts/test_fixture_registry_authority.py
python3 -O -B scripts/test_fixture_registry_authority.py
python3 -B -c 'from pathlib import Path; import sys; [compile(Path(path).read_text(encoding="utf-8"), path, "exec", optimize=0) for path in sys.argv[1:]]' \
  scripts/verify_fixture_registry_authority.py scripts/test_fixture_registry_authority.py
python3 -O -B -c 'from pathlib import Path; import sys; [compile(Path(path).read_text(encoding="utf-8"), path, "exec", optimize=1) for path in sys.argv[1:]]' \
  scripts/verify_fixture_registry_authority.py scripts/test_fixture_registry_authority.py
```

The `-B` flags keep these checks from creating rejected `__pycache__`
entries; the compile-only checks use `compile` rather than `py_compile`, which
writes bytecode even when `-B` is present.

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

The same normal and optimized suite also rejects a different valid synthetic
source commit, warning-suppressed grafts, shallow histories, empty local object
stores that use alternates, replacement refs, nested fanout/pack/ref symlinks,
symlinked or linked Git metadata, local include/promisor/redirect
configuration, annotated-tag source objects, FIFO artifact paths, hostile Git
`PATH`/global config, checkout/object-root resolution failures, source-path
replacement races after descriptor validation, deterministic ancestor
replacement during descriptor opening, corrupted loose objects under existing
OIDs, oversized loose-object, reflog, and metadata snapshot files, and an
oversized pack-directory file over the category-specific pack cap. A real
roughly 2.1 MiB pack in a fresh branch-only remote clone passes. It also rejects
an aggregate snapshot over the total byte budget before copying the next file
and a snapshot deadline overrun. It bounds oversized blob, stderr, and history output
in both interpreter modes, terminates no-output timeouts, cleans up selector
setup failures, and kills descendants that retain stdout or stderr pipes. The
FIFO and output-cap cases assert prompt bounded exit rather than relying on a
post-timeout kill.

The real Git object database remains the source of truth throughout these
mutations, but only after the external verifier and pin root are trusted. The
current coordinated helper/binding probe rejected in both interpreter modes
because f4 changed validator sources while the checked-in baseline and manifest
remained stale. That is defense in depth, not bootstrap authentication, and it
does not predict behavior after a coordinated baseline/manifest regeneration.
A local replacement authority therefore cannot authorize a matching scanner or
baseline rewrite within the tested boundary; the external fixture-authority
root and deterministic authority-rotation tooling dependencies remain required
for an enforced external root.

## Current aggregate sequencing

The final aggregate lane is bound to the combined tree after the approved Caddy
head `5b923fd38e056c37bdb86766f05551cd83687b66`. Registry records were generated
from actual Git-tree bytes: twelve overlapping Caddy-owned records were updated
mechanically, while the three pre-existing `source-audit/compatibility-gate`
records were checked and required no change. The final index validates as 30
fixture roots and 29 coverage rows, with C-08 still pending and no streaming
success claim.

The final baseline records the measured normal and optimized process samples,
its canonical digest, and the four-artifact predecessor manifest. The final v2
authority path is introduced in a separate descendant commit whose direct
first parent is the finalized scanner/index/test/baseline commit. When protected
aggregate test bytes change, advance that source commit, the hardened authority
commit, and the protected runtime pin in that order; never weaken the manifest
or infer a replacement from `HEAD`. The current aggregate test classes seed all
four historical/active authority/source objects from the exact checked-in bundle
and prove that an unseeded clean single-head clone is blocked before a seeded
clone succeeds. The standalone suite consumes that same bundle and checks the
same four commit objects and refs. Normal and optimized aggregate CLI and
discovery gates must remain equivalent; a passing result is still partial
synthetic registry evidence, not live Hermes, authentication, deployment,
streaming, or Terminal proof. This aggregate lane does not own the Caddy
binary proof gate: `scripts/test_caddy_proof.py` remains the separate PR #300
black-box lane and may skip when local Caddy or OpenSSL dependencies are
unavailable. The aggregate records bind only reviewed redacted Caddy fixture
bytes and approved source identities; a dependency skip cannot become live
proof through this registry.

DEP-03 Host/Origin remains web-only with `success` and `failure` states. Its
local pins are reproducibility checks, not a separate trust root, and the
fixture's default validator continues to fail closed on its intentionally stale
local pin until that fixture-local identity is independently refreshed. The
aggregate authority does not reinterpret unrelated browser-chat hashes as Caddy
metadata, and synthetic Caddy `421`/`403`/no-upstream evidence does not claim a
live `4403` or public-edge result.

## Scope and evidence

All authority fixtures and test mutations are synthetic and local. The verifier
proves only exact Git-object and checkout integrity. Passing it is not evidence
of Hermes availability, deployment compatibility, authentication, provider
behavior, or user data.
