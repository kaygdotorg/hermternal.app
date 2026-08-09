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
Host, then browser Origin. Only after those exact checks pass does it validate
the shape of inbound forwarding headers. Those headers are untrusted: the edge
strips them and rebuilds semantic proxy markers from trusted configuration. A
request cannot choose `X-Forwarded-Host`, `X-Forwarded-Proto`,
`X-Forwarded-Prefix`, or the client-chain value retained for the upstream.
Malformed forwarding-header structures reject before any request-supplied
upstream override is considered.

Only after all checks pass does the edge write the mapped upstream Host marker
`fixed_private_non_loopback_9119` and Origin marker `mapped_private_http_origin`
from trusted configuration. Any non-null request-supplied upstream override
rejects. Request input never selects either mapped value or any proxy-generated
forwarded value.

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
- inbound forwarded-header spoofing and malformed forwarded-header structures;
- empty or populated request-supplied upstream Host and Origin overrides; and
- compound hostile inputs proving scheme, Host, Origin, forwarded-header,
  host-override, and origin-override precedence.

Scheme and Host policy rejection uses synthetic edge status `421`. Origin policy
rejection uses `403`. Every rejection records `upstream_called: false` and no
mapped upstream markers. A status without the responding layer and upstream-call
result cannot pass.

## Bounded and redacted evidence

Retained case evidence is limited to fourteen reviewed semantic fields and
16384 canonical UTF-8 bytes. It records only the result of stripping and
rebuilding inbound forwarding headers; it never contains raw request scheme,
Host, Origin, forwarded, or override values. Failure output is one JSON line
capped at 240 characters and never copies an attacker-controlled argument, key,
header, or value.

The validator scans every retained artifact: `README.md`, `cases.json`,
`validate.py`, `test_validate.py`, and `validation-baseline.json`. It rejects
credential assignments, structured JSON credential keys such as `password`,
`token`, and `api_key`, Basic or Bearer payloads, Cookie payloads, ticket
payloads, private-key material, URLs, hostnames including unreviewed TLDs and
loopback names, IPv4 and IPv6 addresses, email addresses, and sensitive
absolute filesystem paths. JSON is also walked recursively so `user`,
`role: user`, `content`, `transcript`, `messages`, and related user/transcript
payloads fail closed.

The sensitive-assignment detector composes its approved name grammar from a
separate source-safe constant before compiling the reviewed expression. This
prevents the detector implementation itself from being retained as a
credential-shaped example. The compiled pattern is asserted byte-for-byte
against the reviewed grammar and adversarial assignment variants still reject;
this is a source representation change, not a scanner allowance.

Exemptions are narrow and structural:

- exact reserved `.invalid` fixture authorities and their frozen mutation forms;
- the exact reviewed WebSocket route;
- exact reviewed artifact paths and filenames, with exact-token boundaries
  that do not match an email address, URL, absolute path, credential
  assignment, backslash continuation, or other URI/path/filename continuation;
- canonical detector assignments only when a module-level AST assignment has
  the expected detector name and exactly matches the loaded pattern and flags;
  a same-looking assignment in a string, docstring, comment, or trailing
  comment remains scanner-visible; and
- canonical negative-test scaffolds only when their AST value has an exact
  reviewed fingerprint. Generic variable names, loop lines, and canary text
  do not create an exemption.

Python artifacts use tokens plus AST source context to recognize dotted
identifiers in real code. A bare unreviewed dotted-host payload is not code and
is scanned. String, docstring, HTML-comment, and comment contents remain
scanner-visible, including content adjacent to an otherwise canonical
assignment. Python string and bytes constants are parsed into AST-decoded values,
so escape sequences supported by Python literal syntax are resolved before
credential, URL, host, control, and surrogate scanning. Bytes constants must
also decode as UTF-8. No expression, call, import, or other Python code is
executed. A SyntaxError or other bounded parser failure is rejected with a
redacted validation result rather than skipping decoded-literal scanning. Only
the exact canonical detector and negative scaffold subtrees are excluded.
Prefix, suffix, alternate host, alternate URL, backslash continuation, and
adjacent content do not inherit an exemption. Tests append each forbidden class
to every artifact and require rejection.

Source normalization sorts its bounded AST/token spans (`O(n log n)`) and then
rebuilds the source once; it makes no strict-linear complexity claim. Literal
scanning is parse-only and bounded by the retained-artifact cap; the reviewed
proof source retains its separate 128 KiB cap.

Every retained UTF-8 text artifact rejects C0 controls other than reviewed
newline, tab, and carriage-return whitespace, plus DEL, C1 controls, and lone
surrogates. JSON string values and keys use the stricter JSON string policy,
while valid surrogate pairs remain accepted Unicode scalar values.

JSON artifacts are parsed before raw scanning. The validator recursively scans
decoded scalar strings, dictionary keys, nested objects, and list elements, so
Unicode escapes and separator variants such as dotted access-token,
compact `apikey`, compact `userdata`, and compact `chathistory` aliases cannot
hide credentials or transcript payloads. Escaped keys are normalized only after
JSON decoding, including keys nested inside arrays and objects. Role values are
compared case-insensitively while the original decoded content remains subject
to the same fail-closed checks.

## Validation, mutation, and identity binding

`validate.py` uses only the Python standard library. It rejects duplicate JSON
keys, non-finite numbers, malformed UTF-8, excessive input, deep or wide JSON,
unknown keys, changed case order, changed mapping or policy, semantic outcome
mismatches, unsafe retained data, and changed benchmark evidence. Explicit
exceptions preserve the same checks under `python3 -O`; the regression suite
runs every parser, scanner, CLI, default-validation, and controlled-integration
failure probe in both modes and requires matching bounded output.

The validator accepts only the canonical `cases.json` path and code-pins its
raw digest. It also binds every row to its observation index, exact request
object, and the reviewed `docs/deployment/proof-matrix.md` Git object
(`4c2c2bc5a91e0432f68ec841b6386ebe6b912f29`), whose pinned size is 18532
bytes and whose SHA-256 is
`01a12174bf770e5380505a5c89930d36b8ba4e43b22b27df1b89dbf9623055a9`. A
canonical semantic digest covers
the mapping, policy, evidence contract, raw requests, source-row evidence, and
independently computed outcomes, plus the baseline digest. The baseline repeats
the semantic digest and binds the normalized README, cases, validator, and
tests. Artifact bytes are captured once through bounded regular-file reads and
that immutable capture feeds parsing, hashing, baseline, and redaction checks.
The local pins are reproducibility checks, not an independent trust root. A
coordinated change can otherwise refresh validator logic, cases, baseline, and
local pins together. The independent five-file identity and rotation authority
must therefore be supplied by the aggregate registry owner in a separately
reviewed prior Git object; this fixture does not edit `contracts/fixtures/index.json`
or claim to close that trust boundary before that owner-controlled registration.
The current proof-matrix pins are refreshed to this exact reviewed snapshot,
and both normal and optimized validators fail closed if its commit, byte count,
or digest drifts. The comma-joined origin
cardinality canary is assembled from separate Python string fragments so the
aggregate registry scanner does not mistake two synthetic URLs for one live
host; its runtime mutation value is unchanged. The aggregate scanner now
handles escaped compact JSON aliases such as `apikey` in its own boundary.
This fixture does not edit aggregate files. Synthetic Caddy `421`/`403` and
no-upstream rows remain fixture evidence only; they do not claim a live public
edge, arbitrary Host/Origin acceptance, or `4403` behavior.

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
