# Hermes gateway readiness fixture

This directory owns the synthetic R-02C readiness contract for one isolated
Hermes gateway probe. It is a planning and validation fixture, not a
production integration.

## Scope

The correctness executor is rootless Podman as account `hermternal-test` on the
`hermternal-dev` VM, reached through the direct SSH boundary
`hermternal-test@hermternal-dev`. Docker evidence is comparison-only and is not
accepted as the correctness executor.

The fixture freezes:

- Hermes commit `f5be9236e00ddf2f2a412697f267078fc4ee068e`.
- Hermes tree `886db5eb1150f819344d67fedc81aef0caab09ff`.
- Dockerfile SHA-256
  `a11fc9fc39eadcaffd99377d831b5ec2458f1e09a5f5d5312fd8adcec362b7fc`.
- Image tag `hermes-agent:hermternal-f5be9236`.
- Command `gateway run --no-supervise`.
- Exact readiness line `HERMES_BACKEND_READY port=<port>` on stdout.
- Rootless Podman, cgroup v2, netavark, and overlay as the executor policy.
- A generated internal network and named volume with no host ports.
- No host profile bind, socket mount, provider, browser auth, PTY, or live data.
- CPU, memory, PID, tmpfs, shared-memory, restart, capability, security, and
  bounded-log limits.
- Exact project-only teardown: `down --volumes --remove-orphans`.
- Zero leftover containers, networks, and volumes after teardown.

The checked-in fixture is synthetic-only and records `proof_status: not_run`.
The live runner fails closed while issue #250's reviewed minimal capability
policy is pending. It must not invent a capability addition to make startup
pass. No VM, Podman stack, port, provider, browser, or PTY is started by the
normal validator or its tests.

## Command and readiness evidence boundary

The pinned source parser at
`hermes_cli/subcommands/gateway.py` accepts `gateway run --no-supervise` and
its help text describes the foreground container behavior. That establishes
parser support for the command candidate only. It does not establish that an
ordinary gateway run emits the backend readiness marker.

The pinned source web-server path emits `HERMES_BACKEND_READY port=<actual-port>`
for the headless backend path. The fixture therefore records
`gateway run --no-supervise` as a harness candidate requiring review, not as a
source-proven readiness path. The runner accepts only the exact marker and
classifies a missing marker as timeout or exit-before-ready; it does not infer
readiness from container creation, an open port, a dashboard message, or a
successful `podman compose up` return code.

`evidence.json` is intentionally a redacted no-run record. It records the
candidate command, the source/readiness distinction, the pending capability
policy, and `not_run` for start, readiness, exit, teardown, and leftovers. It
contains no raw logs, credentials, host paths, provider values, browser data,
or live resource names.

## Files

- `cases.json` contains ordered synthetic policy and parser cases.
- `evidence.json` contains the bounded, redacted `not_run` evidence record.
- `validate.py` contains the strict JSON loader, redaction boundary,
  deterministic Compose renderer, pinned identity checks, readiness parser,
  timeout/exit classifier, bounded rootless runner, and exact cleanup checks.
- `test_validate.py` covers normal and optimized CLI execution, parser and
  classification regressions, synthetic fake-executor flow, redaction, strict
  JSON limits, identity, isolation, capability gating, and cleanup.

## Local checks

Run the validator in both interpreter modes:

```sh
python3 tests/integration/hermes-gateway-readiness/validate.py
python3 -O tests/integration/hermes-gateway-readiness/validate.py
```

Run the offline tests in both modes:

```sh
python3 -m unittest discover \
  -s tests/integration/hermes-gateway-readiness -p 'test_*.py'
python3 -O -m unittest discover \
  -s tests/integration/hermes-gateway-readiness -p 'test_*.py'
```

The optional live command requires both `--allow-live` and a checkout whose
source identity exactly matches the frozen values. It remains blocked by the
checked-in capability policy until issue #250 is reviewed and the operator
receives explicit clearance from main. Do not run it before that clearance.

```sh
ssh -T -o ClearAllForwardings=yes hermternal-test@hermternal-dev -- \
  python3 tests/integration/hermes-gateway-readiness/validate.py \
  --run --allow-live --source-root /path/to/pinned/hermes-agent-reference
```

A successful run would still be a bounded readiness result only. It would not
claim provider compatibility, browser-auth compatibility, Docker compatibility,
or production readiness.
