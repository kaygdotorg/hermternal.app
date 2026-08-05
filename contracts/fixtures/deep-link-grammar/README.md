# Private deep-link grammar fixtures

This directory freezes the v1 private deep-link grammar for Hermternal. It is
an offline protocol fixture and parser proof, not a client implementation and
not a live resolver.

The fixture set uses only the synthetic origin
`https://synthetic.hermternal.test` and synthetic IDs. It does not contact
Hermes, a Dashboard, DNS, a provider, a browser, an Apple API, or a network
service. It contains no credentials, cookies, tickets, tokens, transcripts,
host data, or user data.

## Canonical forms

```text
https://<configured-origin>/v1/c/<full-session-id>
https://<configured-origin>/v1/c/<full-session-id>/m/<full-message-id>
hermternal://open/v1/c/<full-session-id>
hermternal://open/v1/c/<full-session-id>/m/<full-message-id>
```

The web form must begin with the exact configured HTTPS origin. The native
form must use the exact lowercase `hermternal` scheme and `open` authority.
The path is exact: `v1`, `c`, and optional `m` are lowercase literals. The
message anchor is optional, but it is never a query or fragment.

IDs are opaque, full values. They use only ASCII URI `unreserved` characters
(`A-Z`, `a-z`, `0-9`, `-`, `.`, `_`, `~`) and have a 16-character minimum
fixture grammar floor. The parser does not infer UUID shape, decode values,
case-fold, truncate, or normalise them. It returns the exact ID text only for
a route that is otherwise syntactically usable.

The parser rejects every percent escape, backslash, C0/C1/DEL control,
non-ASCII character, query, fragment, trailing slash, empty segment, dot
traversal, path normalisation, wrong scheme, wrong native authority, changed
origin, unknown version, wrong path shape, non-unreserved ID character, and
short or visibly abbreviated ID. It never follows redirects or fetches a link.

## Stable failure reasons

`validate.py` returns all applicable reasons in this fixed order. The
`reason` property returns the first one; a valid result has `reason == "ok"`.

```text
type
control
non_ascii
percent_escape
backslash
query
fragment
trailing_slash
scheme
authority
origin
version
path
traversal
normalization
segment
id_character
full_id
```

Reason order is data in `cases.json`, not an incidental set or exception
ordering. A caller must fail closed when any reason is present.

## Diagnostic redaction

`redact_link()` returns a fixed semantic marker such as
`deep-link[web;session=present;message=present]`. It omits the configured
origin, every ID, query, fragment, and invalid suffix. The output is not a
hash or a shortened link, so it cannot be used to reconstruct the input or to
perform a lookup. Diagnostics must use this marker instead of the raw link.

## Strict fixture schema

`cases.json` has an exact root object with these fields:

- `schema` and `contract` pin the fixture contract;
- `synthetic` must be `true`;
- `configured_origin` and `id_policy` freeze the grammar boundary;
- `reason_order` freezes diagnostic ordering;
- `redaction` freezes the non-reversible policy; and
- `cases` contains the ordered, closed inventory of valid and negative cases.

Each case has exactly `id`, `synthetic`, `link`, and `expected`. Each expected
object has exactly `valid`, `kind`, `session_id`, `message_id`, `reasons`, and
`diagnostic`. Unknown keys, duplicate JSON keys, non-finite numbers, boolean
values in numeric positions, changed case order, changed expected outcomes,
and changes to the frozen link inventory fail closed. The validator also runs
an executable mutation inventory so changing both fixture data and metadata
cannot silently make a regression pass.

## Reproduce the proof

Run from the repository root:

```sh
python3 contracts/fixtures/deep-link-grammar/validate.py
python3 -O contracts/fixtures/deep-link-grammar/validate.py
python3 -m unittest discover \
  -s contracts/fixtures/deep-link-grammar \
  -p 'test_*.py'
python3 -O -m unittest discover \
  -s contracts/fixtures/deep-link-grammar \
  -p 'test_*.py'
python3 -m compileall -q contracts/fixtures/deep-link-grammar
```

The validator and tests use explicit exceptions rather than executable
`assert` statements, so the normal and optimised (`-O`) runs exercise the
same fail-closed checks. Downstream resolution, lineage, access, cold-launch,
and message-result fixtures belong to the dependent deep-link contract work;
this directory freezes only the grammar boundary.
