# Images-only attachment policy fixtures

**Contract:** `dashboard-v0.0.1`  
**Pinned Hermes revision:** `f5be9236e00ddf2f2a412697f267078fc4ee068e`  
**Status:** deterministic protocol fixture and policy proof  
**Live integration:** none

This directory freezes the narrow attachment boundary for Hermternal. It is an
offline contract, not an upload client, proxy, file browser, or live Hermes
integration. All payloads are synthetic magic-byte markers. No fixture contains
an image, transcript, cookie, bearer value, WebSocket ticket, host path, or user
data.

## One selected route

The only selected upload operation is:

```text
POST /api/chat/image-upload
Content-Type: application/json
Body: {"data_url": "...", "filename": "..."}
```

`data_url` is required. `filename` is optional and may be omitted or `null`; both
forms use the server's `pasted-image` default. A non-string filename is rejected
rather than coerced into a path component.

The fixture policy is stricter than the pinned route's broad `image/` prefix: the
only accepted data URL headers are exactly:

```text
data:image/png;base64,<canonical-padded-base64>
data:image/jpeg;base64,<canonical-padded-base64>
data:image/gif;base64,<canonical-padded-base64>
data:image/webp;base64,<canonical-padded-base64>
data:image/bmp;base64,<canonical-padded-base64>
```

The header is case-sensitive and has no extra, repeated, or suffixed parameters.
The decoded bytes must re-encode to the identical padded base64 string, so
noncanonical pad bits are rejected. The declared MIME must agree with the
recognized byte format; a supported `image/*` declaration cannot relabel a
foreign format.

The pinned source decodes a base64 `data:` URL, rejects decoded payloads larger
than 25 MiB, and classifies the bytes with fixed signatures. A filename and
canonical declaration are not byte-format authority. The byte signature decides
the stored extension.

Accepted signatures are:

| Format | Signature | Stored extension |
| --- | --- | --- |
| PNG | `89 50 4e 47 0d 0a 1a 0a` | `.png` |
| JPEG | `ff d8 ff` | `.jpg` |
| GIF87a | `GIF87a` | `.gif` |
| GIF89a | `GIF89a` | `.gif` |
| WEBP | `RIFF` at byte 0 and `WEBP` at byte 8 | `.webp` |
| BMP | `BM` | `.bmp` |

The source keeps `.jpeg` in its extension allowlist, but its detector emits
`.jpg` for JPEG bytes. The fixture records that source behavior rather than
inventing a filename-driven conversion rule. The fixture policy is intentionally
stricter than the source's broad `image/*` prefix: only the five exact MIME
declarations above may pass, and each must agree with the detected byte format.

Successful source responses contain exactly these selected fields:

```text
ok, path, name, bytes, mime_type
```

Files are written below the server-owned `HERMES_HOME/images/` directory. The
basename contains server-generated time and nonce material plus a sanitized
stem and detected extension. The client must not construct or trust a local
filesystem path from a user filename.

## Fail-closed boundary

Reject the upload when any required boundary is absent or mismatched:

- no selected file: safe empty no-op;
- pending or interrupted evidence: never claim success;
- missing or malformed `data_url`;
- a non-string `filename` value (omitted or explicit `null` is valid and
  defaults to `pasted-image`);
- a non-`data:` URL or a data URL without the exact `base64` parameter;
- extra, repeated, suffixed, or wrong-case base64 parameters;
- invalid or noncanonical base64;
- an unsupported or content-mismatched image MIME declaration;
- decoded bytes larger than 25 MiB;
- an empty or unrecognised byte signature; or
- an obvious PDF, ZIP, or HTML polyglot at the image suffix/terminator boundary.
  Foreign-looking bytes inside a valid format-internal chunk are not rejected
  merely because the marker text exists;
- a content type other than the selected JSON envelope; or
- a missing or incompatible `dashboard-v0.0.1` / pinned-source proof.

Arbitrary files, shell paths, filesystem reads, audio, video, generic data URLs,
remote URL fetches, and direct `~/.hermes` access are outside this contract.
There is no attachment credential or expiry policy to invent here. Upload
cancellation, progress, retry, preprocessing, and UI lifecycle belong to the
dependent C-14 fixture issue; an unknown result remains safe and must preserve
the text draft.

A rejected attachment leaves the text draft intact and marks only the
attachment as failed. Image bytes are not written into a local transcript
mirror. Raw data URLs, base64 payloads, absolute server paths, and user
filenames must not be copied into retained diagnostics, history, or DOM-visible
errors. Use only semantic markers such as:

```text
attachment[accepted;format=png;bytes=8]
attachment[rejected;reason=unsupported_image_type]
attachment[pending]
attachment[interrupted]
attachment[blocked;reason=incompatible_contract]
```

## Fixture inventory

`cases.json` is an exact, ordered synthetic inventory. It covers:

- empty, pending, accepted, interrupted, and incompatible states;
- every pinned PNG, JPEG, GIF87a, GIF89a, WEBP, and BMP signature;
- exact supported MIME declarations, declaration/content mismatches, and
  noncanonical base64 pad bits;
- obvious PNG+PDF, JPEG+ZIP, and GIF/WEBP/BMP+HTML polyglots, without rejecting
  foreign-looking text inside a valid format-internal chunk;
- server-side filename sanitization plus omitted and explicit-null defaults;
- missing, non-data, non-base64, malformed-header, malformed-base64, non-image,
  unsupported-MIME, empty, mislabeled, oversized, wrong-envelope, and
  malformed-field inputs; and
- stable outcome, draft-preservation, storage, and diagnostic expectations.

The oversized case uses a synthetic decoded-size override rather than storing a
25 MiB payload. That override is fixture metadata only and is never sent to the
route.

`source_evidence` records the pinned source path, Git blob, file digest, tree,
and exact markers for the route, limit, format detector, decoder, and response.
With `--source-root`, the validator requires the supplied path to be the exact
non-bare checkout top level, then reads only immutable bytes from
`f5be9236e00ddf2f2a412697f267078fc4ee068e:path` with lazy fetch, replacement
objects, alternate object stores, inherited Git config, grafts, shallow-file
redirects, and implicit-work-tree overrides disabled. It does not trust a
mutable worktree copy for those claims. Structured failures use bounded semantic
messages and never echo the source path.

The loader rejects duplicate keys, parser overflow such as 5000-digit integers,
exponent overflow such as `1e309`, malformed UTF-8/syntax, excessive nesting,
and non-finite values. Retained case notes are bounded and reject raw data URLs,
base64 payloads, `file://` URLs, absolute POSIX/Windows paths, and filename/path
shapes; request fixtures themselves contain only the synthetic values needed to
exercise the boundary.

## Accessibility and Paper evidence

Accessibility and Paper evidence are **N/A** because this change is a
non-UI JSON policy, validator, and documentation fixture. It creates no
control, focus order, semantic label, motion, contrast, Dynamic Type,
VoiceOver, Switch Control, browser zoom, or touch-target behavior. This is a
scope statement, not a waiver. Future web and Apple clients must preserve their
existing accessibility contracts while carrying the accepted image boundary,
draft-preservation rule, and semantic redaction policy.

## Reproducible checks

Run from the repository root:

```sh
python3 contracts/fixtures/attachment-policy/validate.py
python3 -O contracts/fixtures/attachment-policy/validate.py
python3 -m unittest discover \
  -s contracts/fixtures/attachment-policy \
  -p 'test_*.py'
python3 -O -m unittest discover \
  -s contracts/fixtures/attachment-policy \
  -p 'test_*.py'
python3 -m py_compile contracts/fixtures/attachment-policy/validate.py
python3 contracts/fixtures/attachment-policy/validate.py \
  --source-root /path/to/hermes-agent
```

The unittest suite does not require that optional path: it builds temporary
synthetic Git repositories and always runs exact-root, wrong-root, object,
redirect-variable, replacement-ref, lazy-fetch, and truncated-output checks
offline. A caller-supplied real source root may be used only as an additional
manual attestation.

The validator uses explicit exceptions rather than executable `assert`
statements, so normal and optimised (`-O`) runs exercise the same fail-closed
checks. No latency or artifact-size threshold is invented.

### Benchmark evidence

The measured command launched the validator as a subprocess 30 times in each
mode, using `time.perf_counter_ns()`, suppressing successful stdout, and
capturing stderr. The raw commands were:

```sh
python3 contracts/fixtures/attachment-policy/validate.py
python3 -O contracts/fixtures/attachment-policy/validate.py
```

Environment:

```text
interpreter: /opt/homebrew/opt/python@3.14/bin/python3.14 (Python 3.14.6)
platform: Darwin 25.5.0 arm64
artifact bytes: 101342
repetitions per mode: 30
normal distribution (ms): min 42.992, median 44.644, max 45.732
optimized distribution (ms): min 43.244, median 45.565, max 47.432
```

Artifact bytes are the sum of the committed `README.md`, `cases.json`,
`validate.py`, and `test_attachment_policy.py` files; generated caches are not
included.
