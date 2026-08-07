# Direct-port denial synthetic proof

**Operation:** DEP-11 — prove direct-port denial
**Contract:** `dashboard-v0.0.1`
**Status:** bounded offline synthetic model only

This directory proves one narrow property inside a deterministic model: only the
exact configured proxy identity, proxy egress interface, private Hermes bind,
private-service interface, TCP port `9119`, single configured proxy hop, and
matching narrow firewall rule may be represented as allowed. Every direct or
mismatched path is represented as denied before an upstream call.

This proof does not start Hermes or a proxy. It does not open a socket, resolve a
host, use a real address, change a firewall, run a container, use credentials, or
contact live infrastructure. It is not a production firewall or reverse-proxy
configuration. A passing result does not prove real reachability or real denial.

## Raw synthetic evidence

Each case records exact synthetic request and rule fields rather than a trusted
classification label:

- transport;
- source identity and source interface;
- destination bind identity, destination interface, and destination port;
- ordered proxy-hop identities; and
- firewall presence, action, protocol, source fields, destination fields, and
  destination port.

The independent evaluator derives the result from those fields without trusting
the case kind, expected decision, or reason. Each row also records exact raw
`client_surface`, `network_path`, and `firewall_source` observations. The
validator derives those values from the DEP-01 fixture bytes at reviewed commit
`014c4b84789b0d14a4b024c4a670033146aed25a`. It also requires the exact protected
launcher, launcher tests, and launcher skill bytes at commit
`a9cbdab8ece2d4f43d10263d4292f2b82a7750cc`. The row position and reviewed DEP-01
case identity bind each observation to its source. Copying every local allow
field into a browser row therefore fails source-evidence validation in normal and
optimized Python. There is exactly one allow representation: the configured
proxy path. Its `upstream_call` value means only that the offline model may
represent a forward. The validator itself makes no upstream call.

The inventory denies direct public, browser, and client-network sources. It also
denies a wrong source interface, wrong destination interface, wrong port, broad
source rule, missing firewall evidence, wrong transport, unconfigured proxy,
missing or extra proxy hops, public bind, loopback bind, and unknown source.
Loopback is rejected because the current deployment proof matrix requires a
fixed private non-loopback bind; older loopback assumptions are not reused.

## Fail-closed and resource bounds

The strict loader rejects duplicate keys, malformed UTF-8, non-finite numbers,
float overflow, oversized integers, excessive input bytes, excessive depth,
excessive total nodes, oversized containers, oversized strings, control
characters, unknown keys, changed key order, wrong scalar types, and booleans in
integer fields. Structural, redaction, and equality walks are iterative. Retained
artifacts are opened once with no-follow and nonblocking semantics, then must
pass descriptor and current-path regular-file, device, inode, and size checks
before bounded reads. Nonblocking acquisition prevents a regular-file-to-FIFO
replacement between `lstat` and `open` from hanging before `fstat` rejects it.
Parsing, hashing, redaction, and identity checks consume the same captured bytes;
no phase reopens a canonical path. Symlinks, devices, FIFOs, file swaps during
capture, alternate CLI artifact paths, and reads beyond the remaining aggregate
byte budget fail closed. These checks use explicit exceptions and remain active
under optimized Python.

Malformed or incomplete evidence returns one bounded JSON line with status `2`.
It emits no traceback, usage text, raw command-line value, duplicate key, or
hostile retained value. Denied cases always use `drop_without_upstream`, set
`upstream_call` to false, and retain no hostile values.

## Redaction and immutable evidence

All six retained files are scanned under one total byte bound. Concrete URL,
address, host-canary, private-key, and credential-assignment values are rejected.
Parsed JSON also rejects credential-shaped keys and assignments. Tests mutate
every retained artifact independently with both a URL canary and the credential
assignment canary assembled as `token`, `=`, and `synthetic-secret-canary`; the
assembled hostile value is never retained in this proof.

The benchmark record contains 30 raw normal samples and 30 raw optimized samples
with deterministic distribution fields and a `null` threshold. These are local
validator-duration observations, not a budget or deployment claim. Canonical
baseline evidence, README, cases, tests, and normalized validator source keep
local reproducibility checks. The checksum file is also local reproducibility
metadata; it is not described as an immutable signature or custody claim.
Independent source/path authority instead comes from exact byte counts and
SHA-256 identities read from the pinned DEP-01 and protected-launcher Git
objects. The shared registry remains a separate integration trust root after
serialized ownership becomes available.

## Reproduce

Run from the repository root:

```sh
python3 contracts/fixtures/deployment-security/direct-port-denial/validate.py
python3 -O contracts/fixtures/deployment-security/direct-port-denial/validate.py
python3 contracts/fixtures/deployment-security/direct-port-denial/test_validate.py
python3 -O contracts/fixtures/deployment-security/direct-port-denial/test_validate.py
python3 -m unittest discover \
  -s contracts/fixtures/deployment-security/direct-port-denial \
  -p 'test_*.py'
python3 -O -m unittest discover \
  -s contracts/fixtures/deployment-security/direct-port-denial \
  -p 'test_*.py'
python3 -m py_compile \
  contracts/fixtures/deployment-security/direct-port-denial/validate.py \
  contracts/fixtures/deployment-security/direct-port-denial/test_validate.py
```

All commands are offline. Cleanup is N/A because the proof creates no network,
firewall, proxy, Hermes, container, credential, or persistent deployment state.

## Registration blocker

Shared fixture index, validator, and registry files are intentionally unchanged.
Registration must wait for serialized ownership after the active shared-registry
pull request completes.

## Accessibility

N/A. This is a non-UI contract fixture. It creates no controls, focus order,
screen-reader surface, motion, contrast, text sizing, or touch target. It does
not remove any accessibility requirement from later web or Apple clients.
