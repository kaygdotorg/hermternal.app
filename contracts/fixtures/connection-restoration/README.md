# Connection and restoration fixture

This directory is the focused C-05 proof for the Hermternal Dashboard connection and restoration state machine. It is a deterministic, standard-library-only synthetic fixture. It does not open a WebSocket, call Hermes, contact an identity provider, use a proxy, read a live transcript, or claim deployment compatibility.

## Contract binding

- Dashboard contract: `dashboard-v0.0.1`
- Reviewed Hermes source SHA: `f5be9236e00ddf2f2a412697f267078fc4ee068e`
- Operation: `C-05`
- Validator: `validate.py`
- Canonical input and expected traces: `cases.json`
- Local regression tests: `test_validate.py`
- Measurement record: `validation-baseline.json`

The source SHA binds the planning contract to the reviewed manifest. It is not a dependency and this fixture does not verify a checkout or a deployment.

## What the fixture proves

`cases.json` contains a closed 42-case inventory. Each case has an initial state and safe local context, an ordered synthetic event sequence, and an expected result. `validate.py` keeps the case inventory and semantics in code, then requires the checked-in JSON to match those definitions exactly. This prevents a mutated fixture from changing both its input and its claimed result together.

The inventory covers every C-05 connection state:

- `offline`
- `auth_required`
- `connecting`
- `handshaking`
- `ready`
- `restoring`
- `reconnecting`
- `delivery_uncertain`
- `incompatible`
- `failed`
- `closing`

It also covers these ordering and recovery rules:

- the first application event is gated by `gateway.ready`;
- attestation and behavioral probe are separate compatibility gates;
- `ready` is allowed only after both gates pass;
- reconnect requires a fresh ticket generation;
- a new transport is not a new server session;
- the selected server session and local draft remain stable through transport loss and safe reconnect cancellation;
- server-owned session restoration is a barrier before an idempotent retry;
- only `session.resume`, `session.history`, `session.status`, and `model.options` are retryable read operations;
- `prompt.submit` is never automatically retried;
- a prompt transport loss enters `delivery_uncertain` and preserves the draft;
- the C-05 proof stops after the restore barrier and labels the resend choice `deferred_to_C-06`;
- cancellation and sign-out close cleanup without scheduling reconnect;
- sign-out clears the selected server-session reference while preserving a local draft;
- all manifest-known close codes are classified explicitly;
- unknown events and unknown close codes fail closed to `incompatible`.

The focused unknown-event rule is intentional. The broader manifest permits ignoring unknown additive non-interactive events, but this fixture must prove that this state-machine boundary does not promote an unrecognized event or close code into an unsafe recovery action.

## Strict input boundary

The validator uses only Python’s standard library and a bounded JSON loader. It rejects duplicate object keys, `NaN`, `Infinity`, exponent overflow, oversized integers, invalid UTF-8, excessive nesting, oversized objects or arrays, oversized strings, and excessive node counts. Root and nested object key order is closed. Required fields use exact built-in types, so booleans are not accepted where integers are required.

CLI failures are one redacted JSON line with a stable semantic message. They do not include paths, tickets, prompts, credentials, host names, transcript content, or malformed payloads. The fixture is synthetic-only and its redaction metadata is checked as part of validation.

## Commands

Run the validator from the repository root:

```text
python3 contracts/fixtures/connection-restoration/validate.py
python3 -O contracts/fixtures/connection-restoration/validate.py
```

Run the focused tests in either interpreter mode:

```text
python3 -m unittest discover -s contracts/fixtures/connection-restoration -p 'test_*.py'
python3 -O -m unittest discover -s contracts/fixtures/connection-restoration -p 'test_*.py'
```

Compile the implementation without importing or running a live service:

```text
python3 -m py_compile contracts/fixtures/connection-restoration/validate.py
```

The baseline records 30 normal and 30 optimized validator samples with raw samples and distributions. `threshold` is deliberately `null`; this planning fixture does not invent a performance budget.

## Scope boundary

This fixture does not decide whether an uncertain prompt is present in restored history, absent with no active turn, rejected, timed out, or safe to resend. Those detailed resend decisions belong to C-06 / issue #54. C-05 proves only entry into `delivery_uncertain`, preservation of the draft and selected session, reconnect and restore ordering, and the prohibition on automatic prompt resubmission.
