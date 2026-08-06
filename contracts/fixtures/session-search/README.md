# C-07A session-search fixture

This directory contains the deterministic, offline session-search contract for
GitHub issue #56. Every identifier, metadata marker, query, cursor, error, and
timing sample is synthetic. The fixture does not call Hermes, open a gateway or
database, read a session, send a query over a network, or store a local
transcript mirror.

## Contract boundary

The contract consumes, but does not modify, the C-01 route allowlist and C-07
session-persistence fixtures. `cases.json` pins their reviewed artifact digests,
and the validator hashes the actual repository files before semantic success.
It also pins Hermes revision
`f5be9236e00ddf2f2a412697f267078fc4ee068e` and records the narrow source
observations used here:

- the authenticated `GET /api/sessions/search` route exists;
- a missing or Unicode-whitespace-only query returns an empty result;
- the upstream session-ID helper strips and lowercases its query, then ranks
  exact, prefix, and substring matches;
- the source bounds its helper limit; and
- the source route does not define a total result order or cursor contract.

Only the empty-query classification is normalization backed by the pinned
route. A nonempty query is not trimmed, lowercased, case-folded, decoded,
stemmed, locale-normalized, or otherwise rewritten. The upstream helper's
broader normalized ID ranking is not adopted: complete case-sensitive
`exact_id` equality is an intentional Hermternal privacy and identity policy.
Hermternal's subsequence rule, deterministic ordering, strict page-size
validation, and cursor are also client contract rules. They are not claims that
the pinned upstream route already implements them.

## Search behavior

Two language-neutral modes are defined:

- `exact_id` accepts one complete opaque ASCII session ID. Equality is exact.
  Prefixes, suffixes, changed case, surrounding whitespace, URL escapes, path
  decoding, and display abbreviations do not match.
- `literal_text` performs a case-sensitive Unicode scalar subsequence match over
  synthetic searchable metadata. It applies no language, locale, stemming, or
  tokenization rule. Redacted metadata is never searchable.

Queries are limited to 256 UTF-8 bytes. A whitespace-only query may contain
source-backed strip whitespace; other control characters are rejected. Page
sizes must be JSON integers from 1 through 50; booleans are rejected.
Results are ordered by descending synthetic `updated_ms`, then ascending ASCII
`session_id`. The response exposes only `session_id`, never title text, message
content, scores, counts, snippets, or transcript data.

The cursor is a non-semantic integrity token. It exposes no session identifier,
timestamp, query digest, or row marker. Its integrity calculation binds the
preserved query, mode, canonical digest of the actual catalog, and last returned
row. A forged token or a token used with another query, mode, or catalog fails
with the same fixed `invalid_cursor` result. No caller-supplied snapshot label
is trusted. No total count is exposed. Repeating the same request against the
same catalog produces byte-identical output.

## Privacy and recovery

Unavailable, deleted, unauthorized, and absent sessions all produce the same
no-result shape. Hidden rows do not change visible ordering, counts, or cursor
behavior. Redacted metadata cannot be used as a text-search oracle. Backend
failure and malformed requests use fixed controlled error codes and do not
include raw queries, identifiers, paths, payloads, existence details, or
sensitive values.

An interruption known to occur before a response advances no cursor and returns
an integrity-bound prior-request proof for an explicit retry of that same read.
An unknown response enters delivery uncertainty. The caller must provide both
the bound prior-request proof and a reconciliation proof for the same actual
catalog before retrying. String retry labels, forged evidence, catalog drift,
and automatic retry are rejected. Search never creates, modifies, deletes,
resumes, or prompts a session.

## Files and immutable evidence

- `cases.json` is the canonical closed document with 45 semantic cases.
- `validate.py` is a standard-library-only strict loader, validator, and reducer.
- `test_validate.py` covers semantics, adversarial JSON, redaction, binding, and
  normal/optimized parity.
- `baseline-evidence.json` contains 30 raw normal and 30 raw `-O` samples.
- `validation-baseline.json` binds the raw evidence and artifact identities.

The loader opens each caller-selected artifact once without following a final
symlink, requires a regular file, checks its declared size before allocation,
streams within the byte bound, and rejects descriptor mutation or pathname
replacement. The same immutable byte buffer is size-checked, parsed, and hashed.
It rejects duplicate keys, invalid UTF-8 (including lone surrogates), non-finite
numbers, numeric overflow, oversized integers, and byte, string, object, array,
node, and depth violations. Bounds traversal is iterative. Exact numeric fields
require built-in JSON integers, not booleans or numerically equal floats.
Argument and validator failures emit one stable redacted JSON line without
attacker-controlled argparse diagnostics.

The validator carries reviewed SHA-256 trust anchors for the external artifacts,
the baseline, and a normalized validator source identity. The baseline stores
that normalized validator identity to avoid a self-hash cycle. Coordinated edits
to a fixture and its manifest still fail unless the independent reviewed trust
anchors are deliberately reviewed and rebound.

## Validation

Run from the repository root:

```text
python3 contracts/fixtures/session-search/validate.py
python3 -O contracts/fixtures/session-search/validate.py
python3 -m unittest discover -s contracts/fixtures/session-search -p 'test_*.py'
python3 -m py_compile contracts/fixtures/session-search/validate.py contracts/fixtures/session-search/test_validate.py
```

`validation-baseline.json` records `build_mode: N/A`. Its `threshold` is `null`
because no approved performance budget exists. Distributions use B-01 R-7
inclusive linear interpolation at p50, p95, and p99, with Decimal arithmetic and
half-even rounding to three decimal places. The samples are local reproducibility
evidence, not a latency or production claim.

## Applicability

This is a non-UI shared protocol fixture. Paper, visual regression, keyboard,
VoiceOver, Switch Control, Dynamic Type, browser zoom, contrast, touch-target,
and reduced-motion checks are N/A. The fixture does not remove those duties from
any later web or Apple search UI.
