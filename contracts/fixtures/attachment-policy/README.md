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

The pinned source decodes a base64 `data:` URL, requires the declared MIME to
start with `image/`, rejects decoded payloads larger than 25 MiB, and classifies
the bytes with fixed signatures. A filename and declared MIME are not format
authority. The byte signature decides the stored extension.

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
inventing a filename-driven conversion rule. An `image/*` declaration with a
recognized signature may pass even when the declaration is not the canonical
format MIME; the server returns the declared MIME while using the detected
extension.

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
- missing or malformed `data_url` or `filename`;
- a non-`data:` URL or a data URL without the exact `base64` parameter;
- invalid base64;
- a declared MIME that does not start with `image/`;
- decoded bytes larger than 25 MiB;
- an empty or unrecognised byte signature;
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
- recognized bytes with a non-canonical `image/*` declaration;
- server-side filename sanitization;
- missing, non-data, non-base64, malformed-base64, non-image, empty,
  mislabeled, oversized, wrong-envelope, and malformed-field inputs; and
- stable outcome, draft-preservation, storage, and diagnostic expectations.

The oversized case uses a synthetic decoded-size override rather than storing a
25 MiB payload. That override is fixture metadata only and is never sent to the
route.

`source_evidence` records the pinned source path, Git blob, file digest, tree,
and exact markers for the route, limit, format detector, decoder, and response.
With `--source-root`, the validator reads only immutable bytes from
`f5be9236e00ddf2f2a412697f267078fc4ee068e:path` with lazy fetch and replacement
objects disabled. It does not trust a mutable worktree copy for those claims.

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

The validator uses explicit exceptions rather than executable `assert`
statements, so normal and optimised (`-O`) runs exercise the same fail-closed
checks. No latency or artifact-size threshold is invented.

### Benchmark evidence

The measured command launched the validator as a subprocess 20 times in each
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
artifact bytes: 66634
repetitions per mode: 20
normal distribution (ms): min 38.625, median 39.944, max 41.196
optimized distribution (ms): min 38.605, median 40.254, max 41.348
```

Artifact bytes are the sum of the committed `README.md`, `cases.json`,
`validate.py`, and `test_attachment_policy.py` files; generated caches are not
included.
