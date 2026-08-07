# Aggregate fixture registry authority

## Purpose

The aggregate fixture registry has a two-stage trust boundary. The stage-one
bootstrap authority is a synthetic, offline trust anchor for the exact aggregate
inputs that existed at the reviewed predecessor commit. It is not a production
attestation and it never makes a live compatibility claim.

Stage one is deliberately separate from the scanner-preparation change. The
stage-one authority does not authorize later scanner, validator, index, or
baseline bytes. Stage two becomes trusted only after its exact head is
independently reviewed and merged into `dev`; the later scanner preparation must
then rebase onto that merged predecessor and generate its next authority from
that external commit.

## Immutable loading rule

[`scripts/fixture_registry_authority.json`](../../scripts/fixture_registry_authority.json)
is read from the sole first-parent Git commit that introduced that path. The
verifier does not trust the visible checkout copy as the authority source. It
reads the authority bytes from the local Git object database, validates the
schema and key order, and requires all of the following:

- the declared predecessor is a distinct ancestor of the authority-introduction
  commit;
- the four declared paths resolve at that predecessor to the recorded Git blob
  object IDs;
- each predecessor object has the recorded byte length and SHA-256 digest; and
- the checkout copies of the authority, index, validator tests, validator, and
  validation baseline exactly match those immutable predecessor records.

The standalone verifier is:

```sh
python3 scripts/verify_fixture_registry_authority.py
python3 -O scripts/verify_fixture_registry_authority.py
```

Both modes emit one bounded JSON line. A failure is redacted, has
`"live_claim":false`, and does not echo paths, arguments, keys, values, or a
traceback. No command fetches a remote or opens a network connection.

## Rewrite resistance

The regression suite copies only the authority and its four trust-input paths
to a temporary directory. It does not create a Git repository or a replacement
authority commit. It proves that normal and optimized verification both reject:

- a checkout-only rewrite of the visible authority;
- a checkout-only rewrite of the aggregate index; and
- coordinated local rewrites of the authority, index, baseline, validator, and
  validator-test files.

The real Git object database remains the source of truth throughout these
mutations. A local replacement authority therefore cannot authorize a matching
local scanner or baseline rewrite.

## Current aggregate sequencing

The current aggregate index and validation baseline remain intentionally blocked
in this bootstrap change. Registering every currently tracked root now would
cross into the scanner-preparation lane and would require unsafe exemptions or
self-authorization. The exact three scanner blockers for the subsequent
preparation rebase are:

- `contracts/fixtures/chat-stream-completion/test_validate.py`
- `contracts/fixtures/deployment-security/external-allowlist/test_validate.py`
- `contracts/fixtures/uncertain-delivery/test_validate.py`

The next lane must rebase scanner preparation onto the merged stage-one
predecessor, correct those scanner cases without weakening aggregate trust,
regenerate the complete index and baseline, and create a new authority from
that merged external predecessor. Stage one must remain unchanged while that
work is reviewed.

## Scope and evidence

All authority fixtures and test mutations are synthetic and local. The
verifier proves only exact Git-object and checkout integrity. `live_claim` is
always `false`; passing it is not evidence of Hermes availability, deployment
compatibility, authentication, provider behavior, or user data.
