# Private-network and firewall contract fixture

**Operation:** DEP-01 — freeze the private network and firewall contract
**Contract:** `dashboard-v0.0.1`
**Status:** deterministic synthetic fixture and offline validator only

This directory defines the reviewed deployment boundary without starting a proxy,
Hermes, a firewall, a browser, or a network service. It contains no deployable
Caddy or Traefik configuration, certificate, hostname, credential, private
address, firewall command, socket operation, or live deployment evidence.

A passing validator proves only that the checked-in synthetic topology remains
internally consistent. It does not prove that Caddy, Traefik, Hermes, a cloud
network, a host firewall, or a public HTTPS origin is configured correctly.

## Frozen topology

`cases.json` freezes one proxy-neutral topology:

- exactly one configured public HTTPS origin, represented by the symbolic marker
  `configured_public_https_origin`;
- the static client is served at `/` through that origin;
- only the reviewed Hermes API route set is forwarded through the proxy;
- Hermes is represented by the fixed symbolic bind
  `fixed_private_non_loopback_9119`, meaning a private non-loopback address on
  TCP port `9119`;
- the firewall default is deny and TCP `9119` is allowed only from the symbolic
  `approved_proxy_network_identity`;
- direct public and direct client access to the private bind is denied;
- loopback-only assumptions, public binds, wrong ports, broad firewall sources,
  additional origins, unknown network identities, unknown routes, and unknown
  topology states are rejected;
- management families such as `/api/config`, `/api/env`, `/api/system`,
  `/api/gateway`, `/api/ops`, `/api/logs`, and `/api/ssh` are not exposed by
  this client boundary; and
- Caddy and Traefik are equal proxy variants of the same contract. Their proofs
  are intentionally `not_run` here and are not implemented by this issue.

The reviewed route records are semantic markers only. They do not contain a
real host, IP address, cookie, token, credential, or network identity.

## Fail-closed cases

The ordered case inventory covers:

- approved static-client access at `/`;
- approved proxy-to-private Hermes access for reviewed chat and Terminal routes;
- direct public and direct client attempts to reach private Hermes;
- a second or wrong origin;
- loopback-only and public Hermes binds;
- a moved port;
- a broad or unknown firewall source;
- management and unknown routes;
- missing, malformed, or unknown topology evidence; and
- a missing firewall rule.

Every computed outcome is required to remain a synthetic result with no live
claim. Every allow case, including topology validation, static root delivery,
and reviewed Hermes routes, carries the configured public HTTPS origin, approved
topology state, exact fixed private non-loopback bind on TCP `9119`, and the
present narrow firewall rule for `approved_proxy_network_identity`. Unknown or
incomplete topology, unsafe origins, noncanonical binds, broad or missing rules,
direct client paths, and management exposure block before any upstream access.

## Strict validation and redaction

`validate.py` uses only the Python standard library. Its loader rejects
 duplicate JSON keys, `NaN`/`Infinity`, overflowing floats, integers over the
bounded digit limit, malformed UTF-8, excessive nesting, excessive node counts,
oversized objects and arrays, oversized strings, and control characters. Closed
schemas require exact key order and exact scalar types; booleans are not accepted
as integers. Explicit exceptions keep the same checks active under `python3 -O`.

Failures emit exactly one bounded JSON line with status `2`, no traceback, no
argparse usage text, and no unredacted attacker-controlled key or value. Error
messages are capped at 240 characters and redact credential-shaped assignments,
URLs, credential-header material, private-key markers, cookie/token/session/ticket
fields, and other secret-shaped text.

The fixture, README, validator, tests, and benchmark baseline contain only
synthetic markers. The redaction contract rejects credentials, hostnames, raw
private addresses, firewall commands, live URLs, and user data. The validator
never opens a socket, invokes a network or firewall command, starts Hermes, or
contacts a proxy.

## Baseline evidence

`validation-baseline.json` records 30 fresh normal and 30 fresh optimized
validator-process observations. It records the exact commands, environment,
raw samples, deterministic `min`, `p50`, `p95`, `p99`, `max`, and `mean`, and a
`null` threshold because this issue defines no performance budget. The baseline
also binds the reviewed artifact file set and digest.

`validation-baseline-sha256.txt` binds the canonical baseline JSON bytes so a
fabricated but internally consistent replacement trace is rejected. Re-run the
baseline commands on the target machine when the fixture or interpreter
changes; the measurements are observations, not a performance promise.

## Reproduce the proof

Run from the repository root:

```sh
python3 contracts/fixtures/deployment-security/private-network-firewall/validate.py
python3 -O contracts/fixtures/deployment-security/private-network-firewall/validate.py
python3 contracts/fixtures/deployment-security/private-network-firewall/test_validate.py
python3 -O contracts/fixtures/deployment-security/private-network-firewall/test_validate.py
python3 -m unittest discover \
  -s contracts/fixtures/deployment-security/private-network-firewall \
  -p 'test_*.py'
python3 -O -m unittest discover \
  -s contracts/fixtures/deployment-security/private-network-firewall \
  -p 'test_*.py'
python3 -m py_compile \
  contracts/fixtures/deployment-security/private-network-firewall/validate.py \
  contracts/fixtures/deployment-security/private-network-firewall/test_validate.py
```

All commands are offline. They do not prove proxy equivalence, public HTTPS,
firewall reachability, private routing, Hermes behavior, certificates, DNS,
credentials, or production deployment state. Those proofs remain blocked until
a later approved implementation records them separately.

## Accessibility applicability

N/A for this non-UI protocol and deployment fixture. It creates no control,
focus order, semantic name, screen-reader or VoiceOver surface, Switch Control
behavior, Dynamic Type or browser-zoom layout, contrast, motion, transparency,
or touch target. Later web and Apple clients must preserve their accessibility
contracts while respecting this blocked deployment state.
