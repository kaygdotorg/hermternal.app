# C-16 deep-link resolution fixtures

This directory contains the deterministic proof for GitHub issue #66. The
proof is synthetic. It is offline. It does not contact Hermes, a Dashboard,
DNS, a browser, an Apple service, or any other network service.

The proof consumes the checked-in deep-link grammar and session-lineage
artifacts. It does not change them. Exact SHA-256 identities bind those inputs
to this proof.

## Resolver contract

The resolver uses this order:

1. Parse the link with the private grammar.
2. Keep only a valid target in process memory.
3. Require authentication.
4. Look up the exact full session ID.
5. Apply the reviewed latest-descendant rule when the caller requests it.
6. Open the exact session result.
7. Focus the exact message anchor when it exists.
8. Open the session with a `message_not_found` result when the message is
   absent.
9. Clear the pending target.

The resolver does not normalize, shorten, decode, or case-fold an ID. A denied
session and an unknown session return the same `session_not_found` result. This
rule prevents an authorization oracle.

The latest-descendant cases keep two identities. `requested_session_id` is the
exact ID from the link. `opened_session_id` is the reviewed descendant. The
opened result keeps the exact root and parent IDs from the pinned lineage
fixture.

## Pending target lifetime

A valid target can wait for authentication in process memory for 300 seconds.
The proof does not place the raw link in an OAuth or OIDC return URL. It clears
the pending target after success, failure, expiry, cancellation-equivalent
failure, or logout.

Reload and reopen are idempotent. An interrupted lookup can retry the same
validated target. The retry does not create a session or duplicate a prompt.

## Hard boundaries

Every trace keeps these values:

- `session_creations: 0`
- `shares: 0`
- `transcript_mirror: false`
- `network: false`

The proof does not create a session. It does not define user-facing sharing. It
does not store a local transcript mirror. Hermes remains the future source of
truth for session and message data.

The HTTPS form accepts only the configured synthetic origin. The native form
accepts only `hermternal://open`. The resolver rejects a changed origin or
native authority before lookup.

## Strict data handling

All fixture and baseline inputs are inert JSON. The loader rejects duplicate
keys and non-finite numbers. It applies exact JSON type checks. It rejects
integer and float overflow. It also applies byte, string, container, node, and
depth limits.

The bound walk is iterative. Deep JSON cannot force a recursive validation
walk. CLI failure output is always this fixed redacted value:

```json
{"error":{"code":"contract","message":"deep-link resolution fixture rejected"}}
```

The error does not include a path, link, ID, payload, exception, or traceback.

## Evidence files

- `cases.json` contains 15 synthetic resolver traces.
- `validate.py` contains the offline reducer and strict validator.
- `test_validate.py` contains normal and optimized regression tests.
- `baseline-evidence.json` contains 30 raw normal samples and 30 raw `-O`
  samples.
- `validation-baseline.json` binds the raw samples and exact artifact
  identities.

The baseline threshold is `null`. The repository has no approved performance
budget for this proof. The samples are measurements, not a speed claim.

The recorded environment is CPython 3.14.6 on macOS 26.5.2 arm64. Build mode
is N/A because this standard-library contract has no release build.

Recorded distributions in milliseconds:

```text
normal: min=147.280459 p50=242.687813 p95=629.299333 max=673.528459 mean=299.641703
-O:     min=92.498334 p50=151.238583 p95=225.883583 max=236.905208 mean=155.370844
```

Run these commands from the repository root:

```sh
python3 contracts/fixtures/deep-link-resolution/validate.py
python3 -O contracts/fixtures/deep-link-resolution/validate.py
python3 -m unittest discover \
  -s contracts/fixtures/deep-link-resolution \
  -p 'test_*.py'
python3 -O -m unittest discover \
  -s contracts/fixtures/deep-link-resolution \
  -p 'test_*.py'
python3 -m py_compile \
  contracts/fixtures/deep-link-resolution/validate.py \
  contracts/fixtures/deep-link-resolution/test_validate.py
```

## Accessibility

Accessibility checks are N/A for this fixture. It has no UI. It does not
change focus order, semantic labels, touch targets, VoiceOver, Dynamic Type,
zoom, contrast, reduced motion, reduced transparency, or Switch Control.
Future web and Apple clients must keep their accessibility contracts when they
implement these resolver results.
