# Disposable Host and Origin mapping proof

**Operation:** DEP-03 — prove the source-compatible upstream Host and Origin mapping

**Contract:** `dashboard-v0.0.1`

**Hermes source:** `f5be9236e00ddf2f2a412697f267078fc4ee068e`

**Status:** deterministic synthetic fixture and offline validator only

This exclusive fixture models one public-to-private mapping boundary. It does not
start Hermes, a proxy, DNS, TLS, a browser, a socket, or a network service. It
contains no deployable Caddy or Traefik configuration, hostname, address,
credential, ticket, cookie, transcript, or live request. Passing evidence proves
only the checked-in disposable model.

## Mapping invariant

The model represents the exact configured public values with synthetic markers:

- public scheme: `https`;
- public Host: `configured_public_host`;
- browser Origin: `configured_public_https_origin`;
- mapped upstream Host: `fixed_private_non_loopback_9119`; and
- mapped upstream Origin: `mapped_private_http_origin`.

The edge first accepts only the exact configured public Host. It then accepts
only the exact configured browser Origin. Only after both checks pass does it
write the two mapped upstream values from trusted configuration. Request input
cannot select or override either mapped value. This order preserves the pinned
Hermes source-compatible check while making the edge, narrow route allowlist,
private bind, and firewall the public-origin controls described by
[`docs/deployment/proof-matrix.md`](../../../../docs/deployment/proof-matrix.md).

This tradeoff is explicit: Hermes sees the mapped private authority, not the
public browser authority. This fixture therefore does not claim that Hermes
independently validated the public Origin.

## Success and fail-closed cases

The accepted browser WebSocket case records a forward decision and the exact two
configured mapping markers. It does not fabricate a live `101` result. Rejected
cases cover:

- mismatched, hostile, and missing public Host values;
- mismatched, hostile, `null`, wildcard, and missing browser Origin values;
- request-supplied upstream Host or Origin overrides; and
- simultaneous hostile Host, hostile Origin, and override input, proving Host
  rejection occurs first.

Host rejection returns the synthetic edge status `421`. Origin rejection returns
`403`. Every rejection records `upstream_called: false` and retains no mapped
upstream values. A status without the responding layer and upstream-call result
cannot pass.

## Bounded and redacted evidence

Retained case evidence is limited to eight reviewed semantic fields and 4096
canonical UTF-8 bytes. Failure output is one JSON line capped at 240 characters.
The validator never copies an attacker-controlled key, path, header, or value
into diagnostics.

The source artifacts and retained evidence reject credential assignments,
Authorization, Cookie, ticket, private-key, URL, hostname, IP-address,
filesystem-path, email, user-data, and transcript-shaped material. Structural
fixture filenames, the reviewed route, and synthetic mapping markers are
validated before narrow scanner exemptions apply. The fixture stores semantic
input classes such as `hostile_host_syntax`; it does not retain hostile raw Host
or Origin bytes.

## Validation and mutation coverage

`validate.py` uses only the Python standard library. It rejects duplicate JSON
keys, non-finite numbers, malformed UTF-8, excessive input, deep or wide JSON,
unknown keys, changed case order, changed mapping or policy, semantic outcome
mismatches, unbounded evidence, unsafe retained data, and changed benchmark
evidence. Explicit exceptions preserve the same checks under `python3 -O`.

`test_validate.py` runs real normal and optimized validator processes. Mutation
tests change every mapping field, every request classification, accepted and
rejected expected results, evidence bounds, the baseline, duplicate keys,
encoding, and retained-data canaries. Normal and optimized failures must have the
same bounded semantic output and status `2`.

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

A temporary mutated fixture can be checked without requiring its benchmark to
match:

```sh
python3 contracts/fixtures/deployment-security/host-origin-mapping/validate.py \
  --cases <synthetic-temporary-file> --skip-baseline
```

## Baseline and scope limits

`validation-baseline.json` records 30 observed normal-process samples and 30
optimized-process samples, exact commands, the local environment, linear
interpolated distribution statistics, and a normalized SHA-256 digest over the
README, cases, validator, and tests. The validator code-pins the exact cases and
baseline identities. `threshold` is `null` because DEP-03 has no reviewed
latency budget. These measurements are reproducibility evidence, not a
performance promise.

Accessibility is N/A. This non-UI fixture creates no controls, focus order,
semantic names, screen-reader or VoiceOver surface, Switch Control behavior,
Dynamic Type or browser-zoom layout, contrast, motion, transparency, or touch
targets. It does not remove any client accessibility requirement.

The fixture does not prove a live edge, Hermes behavior, Caddy/Traefik parity,
TLS, DNS, private reachability, firewall enforcement, authentication, or a
production deployment. It does not broaden the DEP-02 allowlist and is not
registered in the aggregate fixture index by this issue; registry ownership
remains separate.
