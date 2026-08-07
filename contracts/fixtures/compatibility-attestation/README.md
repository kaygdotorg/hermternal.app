# Out-of-band Hermes revision attestation

**Contract:** `hermternal.revision-attestation.v1`
**Operation:** `C-04`
**Dashboard contract:** `dashboard-v0.0.1`
**Pinned Hermes revision:** `f5be9236e00ddf2f2a412697f267078fc4ee068e`
**Status:** synthetic, offline fixture only
**Live integration:** none

## Purpose

This directory defines the detached evidence shape that a deployment or release
channel must provide before a Hermternal client can treat an authenticated
Dashboard connection as compatible. It does not contact Hermes, read a server
response, create a deployment, or claim that the synthetic identity is trusted.

The canonical record is [`revision_attestation.json`](revision_attestation.json).
It binds the full pinned Hermes commit to the reviewed Dashboard manifest, the
source-review record, and the reviewed proxy-proof policy. Those policy files
are checked as immutable Git blobs, not as mutable path contents, when the
validator runs in its default mode.

## Trust boundary

The Dashboard surface does not expose a trusted Hermes source SHA or a stable
Dashboard wire-protocol version. The client must not invent a response header,
query parameter, version endpoint, or compatibility negotiation step. The
blocked `/api/ssh/ownership` protocol version is not evidence for this
contract.

The detached record therefore requires:

- the exact 40-character Hermes source commit SHA;
- the `dashboard-v0.0.1` route-manifest revision and SHA-256 digest;
- the immutable source-review and proxy-proof policy digests; and
- a deployment identity and release-channel reference, represented here only
  by synthetic labels.

A missing, malformed, unknown, abbreviated, or mismatched revision blocks the
attestation. A matching attestation does not replace the independent
behavioral probe owned by C-04A/#52. The fixture records that live operation
remains blocked until that separate gate passes.

This fixture does not prescribe a signing algorithm or transport for a real
release channel. It defines the fields and immutable evidence that a later
release implementation must verify out of band. No cryptographic signature,
credential, hostname, or live deployment value is fabricated here.

## Synthetic cases

[`cases.json`](cases.json) covers deterministic states for:

- a matching attestation with no behavioral probe;
- a matching attestation with a separate probe result;
- missing, empty, and malformed attestation;
- abbreviated, unknown, and mismatched revisions;
- mismatched route-manifest, source-review, and proxy-proof evidence;
- unexpected server revision or wire-version metadata; and
- a failed behavioral probe that cannot be overridden by attestation.

The valid case with a matching probe is labelled `separate_probe_gate`, not
`enabled`: this directory never claims a live compatibility result.

## Strict offline validation

[`validate.py`](validate.py) uses only the Python standard library. It rejects:

- duplicate JSON object keys, `NaN`, `Infinity`, `-Infinity`, and exponent
  overflow such as `1e9999`;
- bounded streaming JSON input bytes, strings, arrays, object widths, total
  nodes, and redaction traversal, with control characters rejected; duplicate
  key errors never echo the rejected key and controlled CLI errors are capped;
- unknown keys, reordered keys, changed fixture IDs, wrong leaf types, and
  booleans where integers are required;
- missing, abbreviated, unknown, or mismatched Hermes revisions;
- absolute, Windows, traversal, or symlink-escaping evidence paths;
- changed SHA-256 digests or byte counts for the immutable policy evidence and
  measured baseline artifacts;
- server-shaped source-revision or protocol-version fields; and
- URLs, email addresses, host forms, password/token/authorization and
  secret/key assignments, bearer/basic values including short Basic values,
  cookie/ticket markers, raw operational material, or user data. Sensitive
  field aliases including `x_api_key` are normalized across case, hyphen,
  underscore, and separator variants.

The JSON and redaction limits are validator safety limits only; they are not
product protocol limits.

Run the default validator after the fixture is committed so the reviewed
fixture snapshot and executing validator bytes are read from immutable Git
objects:

```sh
python3 contracts/fixtures/compatibility-attestation/validate.py
```

For an uncommitted working tree, use the explicit mutable-worktree mode while
developing:

```sh
python3 contracts/fixtures/compatibility-attestation/validate.py --worktree
```

The default validator requires reviewed commit
`4c2c2bc5a91e0432f68ec841b6386ebe6b912f29` and tree
`b3d4ce3b3144c36f9972eb5a23ca354ac0fbf696`, requires commit/tree Git object
types, reads all three fixture JSON documents
and measured artifacts from that reviewed snapshot, and checks that the
executing `validate.py` bytes equal the current immutable `HEAD` blob. Its
successful result proves only the synthetic contract, executable case matrix,
immutable policy bindings, and recorded baseline evidence. It does not prove a
Hermes process, a proxy, a deployment identity, a behavioral probe, or live
compatibility. The baseline is developer-observed evidence, not independently
authenticated measurement; output therefore reports `measurement_authenticated`
as `false`. `--worktree` is a development-only mutable check: it reports
`fixture_valid` but never claims `attestation_verified`.

## Tests

Run the focused normal and optimized tests, plus standard-library discovery:

```sh
python3 contracts/fixtures/compatibility-attestation/test_validate.py
python3 -O contracts/fixtures/compatibility-attestation/test_validate.py
python3 -m unittest discover \
  -s contracts/fixtures/compatibility-attestation \
  -p 'test_*.py'
python3 -m py_compile \
  contracts/fixtures/compatibility-attestation/validate.py \
  contracts/fixtures/compatibility-attestation/test_validate.py
```

## Accessibility and Paper evidence

Accessibility and Paper evidence are **N/A** because C-04 produces no user
interface and changes no focus order, semantic name, VoiceOver, Switch
Control, Dynamic Type, browser zoom, contrast, motion, transparency, or touch
target. The fixture preserves the future accessibility boundary: a later UI
must still implement the platform-specific checks, and an incompatible
attestation must not be hidden behind an unreviewed fallback screen.

## Measurement baseline

This is an offline Python validator, so production or release build mode is
N/A. [`validation-baseline.json`](validation-baseline.json) records 30
validator repetitions, the measured artifact byte count, the environment, and
min/p50/p95/max/mean duration. These values and artifact hashes are
self-authored, developer-observed evidence rather than an independently signed
measurement trace. `threshold` is `null`; no performance budget is invented.
Re-run the measurement on the target machine before using it for a performance
decision.

## Security and redaction review

All values are synthetic or public repository metadata. The JSON fixtures
contain no credentials, cookies, bearer material, tickets or ticket fragments,
hosts, prompts, transcripts, PTY bytes, provider data, or user data. The
validator also scans for credential-shaped values and prohibited sensitive
field names.

This README is the focused protocol description for C-04. It is intentionally
kept beside the machine-readable fixtures so the contract remains within the
exclusive compatibility-attestation ownership boundary.
