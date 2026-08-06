# Image attachment lifecycle fixture

This directory freezes the C-14 image attachment lifecycle as an offline,
deterministic contract fixture. It is not an upload client, file picker,
filesystem reader, proxy, Hermes integration, or production API test.

All fixture inputs are semantic markers. The directory contains no image
bytes, data URLs, base64 payloads, paths, filenames, metadata values, hostnames,
credentials, prompts, transcripts, or user data. `validate.py` does not open,
decode, transform, retain, or transmit attachment material.

## Contract boundary

The fixture reuses the C-13 attachment-policy semantics by reference without
changing C-13. The pinned contract is `dashboard-v0.0.1`, the source evidence
is pinned to Hermes commit `f5be9236e00ddf2f2a412697f267078fc4ee068e`, and the
policy reference is `attachment-policy-c13-f5be9236`.

The root `c13_consistency` assertion binds C-13 case
`invalid-noncanonical-base64` to the C-14 `malformed-base64` lifecycle marker.
That marker must be rejected before upload, remain in the failed attachment
state, and retain only the semantic diagnostic
`attachment[rejected;reason=malformed_base64]`. No C-13 file is edited by this
fixture.

The inherited boundary is:

- images only, with the C-13 supported PNG, JPEG, GIF, WebP, and BMP families;
- declaration and detected content must agree;
- decoded payloads are capped at 25 MiB;
- preprocessing happens locally before upload;
- metadata is removed before upload and is never retained;
- rejected attachments preserve the text draft;
- diagnostics and transcript records use semantic markers or synthetic
  references only;
- a response that may have completed does not trigger a duplicate upload;
- an incompatible contract fails closed without a live compatibility probe.

This fixture owns lifecycle evidence only. It does not modify
`contracts/fixtures/attachment-policy/**`.

## Cases

`cases.json` contains sixteen ordered scenarios:

1. empty image selection;
2. local preprocessing with metadata removal;
3. monotonic preprocessing and upload progress;
4. cancellation before upload starts;
5. cancellation after upload starts;
6. safe retry after a state reread confirms no upload;
7. successful upload with a semantic transcript reference;
8. declaration and detected-content mismatch;
9. malformed base64 marker;
10. malformed data URL marker;
11. unsupported image format;
12. decoded size over the 25 MiB cap;
13. network interruption before upload starts;
14. network interruption after upload starts;
15. uncertain completion with no duplicate upload;
16. incompatible contract blocked before transport.

Each case records only bounded state: selection, format labels, preprocessing
flags, transport state, progress percentages, cancellation point, retry policy,
draft preservation, upload-attempt counts, and semantic diagnostics.

## Strict validation

`validate.py` uses only the Python standard library. Its loader rejects:

- duplicate object keys, including nested duplicates;
- non-finite constants and exponent overflow;
- integers beyond the bounded digit limit;
- malformed UTF-8 or JSON;
- oversized JSON input, strings, arrays, objects, node counts, or nesting;
- non-exact JSON value types at schema boundaries.

Schema failures are converted into a short redacted JSON error. Raw parser
messages, input values, keys, paths, and tracebacks are not emitted. Assertions
are implemented with explicit checks so optimized Python cannot remove the
contract guards.

The validator also checks semantic drift: the expected state must be derived
from the case timeline and input markers, not merely copied into the fixture.
It enforces preprocessing completion before upload, required preprocess and
upload progress phases, one upload start at most, zero duplicate uploads, draft
preservation, metadata removal, post-start state rereads before any retry
interpretation, safe retry rules, and the unknown-state no-automatic-retry rule.
Retained text rejects short, unpadded, lowercase, and digit-only base64-like
payloads, IPv4 addresses, `localhost`, auth and credential forms, and cookie
headers in addition to URLs, paths, hosts, and filenames.

The checked-in baseline is evidence, not a trust root. The validator pins the
SHA-256 and byte count of the README, cases, tests, and baseline outside the
mutable baseline object, and also hashes the canonical baseline content. A
coordinated artifact plus baseline rebinding therefore fails instead of
replacing the reviewed evidence.

## Verification commands

From the repository root, run the focused validator and tests in both Python
modes:

```text
python3 contracts/fixtures/image-attachment-lifecycle/validate.py
python3 -O contracts/fixtures/image-attachment-lifecycle/validate.py
python3 -m unittest discover -s contracts/fixtures/image-attachment-lifecycle -p 'test_validate.py' -v
python3 -O -m unittest discover -s contracts/fixtures/image-attachment-lifecycle -p 'test_validate.py' -v
```

Compile with an external cache so the fixture directory remains free of
`__pycache__` output:

```text
PYTHONPYCACHEPREFIX=/tmp/hermternal-image-lifecycle-pycache python3 -m py_compile contracts/fixtures/image-attachment-lifecycle/validate.py contracts/fixtures/image-attachment-lifecycle/test_validate.py
PYTHONPYCACHEPREFIX=/tmp/hermternal-image-lifecycle-pycache-opt python3 -O -m py_compile contracts/fixtures/image-attachment-lifecycle/validate.py contracts/fixtures/image-attachment-lifecycle/test_validate.py
```

`baseline.json` records thirty deterministic normal samples and thirty
optimized samples with min, median, p95, and max distributions. Its
`threshold` is intentionally `null`: this fixture records measured evidence
without inventing a performance budget for a non-production validator.

## Accessibility and design scope

Accessibility and Paper evidence are **not applicable** to this directory:
it contains no UI, interaction surface, runtime client, or visual artboard.
This is not a waiver of the web, iOS, iPadOS, or macOS accessibility
requirements for future attachment UI implementation. Runtime attachment UI
must separately provide accessible selection, progress, cancellation, retry,
error, focus, keyboard, Dynamic Type, VoiceOver, reduced-motion, and zoom
behavior.
