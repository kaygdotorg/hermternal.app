# Disposable Host and Origin mapping proof

**Operation:** DEP-03 — prove the source-compatible upstream Host and Origin mapping

**Contract:** `dashboard-v0.0.1`

**Hermes source:** `f5be9236e00ddf2f2a412697f267078fc4ee068e`

**Status:** deterministic synthetic fixture and offline validator only

This exclusive fixture models one public-to-private mapping boundary. It does
not start Hermes, a proxy, DNS, TLS, a browser, a socket, or a network service.
It contains no deployable proxy configuration, credential, ticket, cookie,
transcript, live request, live host, or private address. Passing evidence proves
only the checked-in disposable model.

## Raw request and mapping invariant

The source fixture carries bounded raw synthetic request values. The configured
public authority uses the reserved RFC 2606 `.invalid` namespace:

- scheme `https`;
- Host `chat.public.invalid`; and
- Origin `https://chat.public.invalid`.

These exact reserved values are structural fixture syntax, not live deployment
values. Host and Origin are arrays so the proof distinguishes one field from
missing or multiple header fields. The validator does not strip whitespace,
fold case, remove a trailing dot, infer a default port, decode escapes, or
otherwise normalize input into acceptance.

The edge derives each classification independently. It validates scheme, then
Host, then browser Origin. Only after all three exact checks pass does it write
the mapped upstream Host marker `fixed_private_non_loopback_9119` and Origin
marker `mapped_private_http_origin` from trusted configuration. Any non-null
request-supplied upstream override rejects. Request input never selects either
mapped value.

This order preserves the pinned Hermes source-compatible check while making the
edge, narrow route allowlist, private bind, and firewall the public-origin
controls described by the deployment proof matrix. The tradeoff is explicit:
Hermes sees the mapped private authority, not the public browser authority. This
fixture does not claim that Hermes independently validated the public Origin.

## Exact fail-closed coverage

The accepted browser WebSocket case records a forward decision and the two
configured mapping markers. It does not fabricate a live upgrade result.
Rejected cases and parser regressions cover:

- wrong, missing, empty, whitespace-bearing, control-bearing, or case-mutated
  scheme values;
- missing or multiple Host fields, comma-joined values, ports, case changes,
  trailing dots, whitespace, userinfo, scheme prefixes, paths, queries,
  fragments, escapes, malformed labels, IP literals, and non-ASCII values;
- missing or multiple Origin fields, comma-joined values, wrong or case-mutated
  schemes and hosts, explicit ports, trailing dots or slashes, paths, queries,
  fragments, whitespace, userinfo, malformed authorities, escapes, IP literals,
  non-ASCII values, `null`, and wildcard values;
- empty or populated request-supplied upstream Host and Origin overrides; and
- compound hostile inputs proving scheme, Host, Origin, host override, and
  origin override precedence.

Scheme and Host policy rejection uses synthetic edge status `421`. Origin policy
rejection uses `403`. Every rejection records `upstream_called: false` and no
mapped upstream markers. A status without the responding layer and upstream-call
result cannot pass.

## Bounded and redacted evidence

Retained case evidence is limited to nine reviewed semantic fields and 12288
canonical UTF-8 bytes. It never contains raw request scheme, Host, Origin, or
override values. Failure output is one JSON line capped at 240 characters and
never copies an attacker-controlled argument, key, header, or value.

The validator scans every retained artifact: `README.md`, `cases.json`,
`validate.py`, `test_validate.py`, and `validation-baseline.json`. It rejects
credential assignments, Basic or Bearer payloads, Cookie payloads, ticket
payloads, private-key material, URLs, hostnames, IPv4 and IPv6 addresses,
absolute filesystem paths, email addresses, user data, and transcript-shaped
material.

Exemptions are narrow and structural:

- exact reserved `.invalid` fixture authorities and their frozen mutation forms;
- the exact reviewed WebSocket route;
- exact artifact filenames and validator command paths; and
- complete detector-definition or explicit negative-test-canary source lines.

Prefix, suffix, alternate host, alternate URL, and adjacent content do not inherit
an exemption. Tests append each forbidden class to every artifact and require
rejection.

## Validation, mutation, and identity binding

`validate.py` uses only the Python standard library. It rejects duplicate JSON
keys, non-finite numbers, malformed UTF-8, excessive input, deep or wide JSON,
unknown keys, changed case order, changed mapping or policy, semantic outcome
mismatches, unsafe retained data, and changed benchmark evidence. Explicit
exceptions preserve the same checks under `python3 -O`.

The validator code-pins the canonical cases digest, a canonical semantic digest
over mapping, policy, evidence contract, raw requests, and independently
computed outcomes, plus the baseline digest. The baseline repeats the semantic
digest and binds the normalized README, cases, validator, and tests. Coordinated
fixture, expected-result, semantic, and baseline mutations fail unless an
independent reviewed root is also updated. Aggregate registration supplies that
independent five-file raw digest and size root after the aggregate owner releases
exclusive ownership.

Run from the repository root:

```sh
python3 contracts/fixtures/deployment-security/host-origin-mapping/validate.py
python3 -O contracts/fixtures/deployment-security/host-origin-mapping/validate.py
python3 contracts/fixtures/deployment-security/host-origin-mapping/test_validate.py
python3 -O contracts/fixtures/deployment-security/host-origin-mapping/test_validate.py
python3 -m unittest discover \
  -s contracts/fixtures/deployment-security/host-origin-mapping \
  -p 'test_*.py'
python3 -O -m unittest discover \
  -s contracts/fixtures/deployment-security/host-origin-mapping \
  -p 'test_*.py'
python3 -m py_compile \
  contracts/fixtures/deployment-security/host-origin-mapping/validate.py \
  contracts/fixtures/deployment-security/host-origin-mapping/test_validate.py
```

`validation-baseline.json` records 30 observed normal-process samples and 30
optimized-process samples. `threshold` is `null` because DEP-03 has no reviewed
latency budget. The observations are reproducibility evidence, not a performance
promise.

Accessibility is N/A. This non-UI fixture creates no controls, focus order,
semantic names, screen-reader or VoiceOver surface, Switch Control behavior,
Dynamic Type or browser-zoom layout, contrast, motion, transparency, or touch
targets. It removes no client accessibility requirement.

The fixture does not prove a live edge, Hermes behavior, proxy parity, TLS, DNS,
private reachability, firewall enforcement, authentication, or production
deployment. It does not broaden the DEP-02 allowlist. Aggregate registry edits
remain blocked until the active registry-owner lane merges and releases those
files.
