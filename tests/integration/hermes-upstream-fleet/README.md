# Official Hermes rootless upstream fleet

**Operation:** R-02C / issue #272

This fixture owns one reusable launcher for bounded upstream Hermes instances.
It is a deployment contract and test harness, not a product client. It uses
only the official Docker Hub image addressed by an immutable digest:

```text
docker.io/nousresearch/hermes-agent@sha256:9a515dbef568dc625b217a7e699128e1a9d5abc8f4f93fd743fc894b0e7b0ccb
```

The digest is the Docker Hub multi-platform `latest` manifest observed on
2026-08-06. The source page is
[Docker Hub: nousresearch/hermes-agent](https://hub.docker.com/r/nousresearch/hermes-agent).
The launcher does not use the `latest` tag, build an image, adapt a
Dockerfile, retag an image, or relabel image content.

## Boundary

`validate.py` creates one Compose project for each requested instance. Each
project gets deterministic names derived from a bounded fleet ID and instance
ID:

- `hermes-upstream-fleet-<fleet>-<instance>` project;
- a project-private internal network with a `-private` suffix;
- a project-scoped named data volume with a `-data` suffix;
- no `ports`, `network_mode: host`, `container_name`, host profile, host
  Hermes directory, Podman socket, Docker socket, or provider mount.

The service preserves the upstream image entrypoint and runs the reviewed
`gateway run --no-supervise` command. It uses the reviewed rootless-init
capabilities (`CAP_CHOWN`, `CAP_SETGID`, `CAP_SETUID`), drops all other
capabilities, enables `no-new-privileges`, and bounds logs to 1 MiB. Provider
auto-discovery is disabled inside the service. The host environment is copied
only after removing Docker, Compose, Hermes provider, and common provider
secret variables; the launcher then selects the `podman-compose` executable
explicitly. A Docker command or Docker Compose provider is rejected.

The four reviewed profiles reserve the following per-instance amounts:

| Profile | CPU | Memory | PIDs | Scope |
| --- | ---: | ---: | ---: | --- |
| `auth` | 0.75 | 2048 MiB | 512 | native and browser-auth boundary checks |
| `sessions-search` | 1.25 | 4096 MiB | 768 | session listing and search checks |
| `stream-reconnect` | 1.00 | 3072 MiB | 768 | stream interruption and reconnect checks |
| `image-pty` | 1.50 | 6144 MiB | 1024 | image attachment and PTY boundary checks |

The fleet rejects any reservation over **6.00 CPU / 18,432 MiB / 3,712
PIDs** before an engine command is started. Four one-of-each profiles reserve
4.50 CPU / 15,360 MiB / 3,072 PIDs.

## Commands

The state directory is local launcher state only. It is never mounted into a
container. Use a disposable directory for live work:

```sh
state_dir="$(mktemp -d)"

# Offline plan and deterministic Compose rendering.
python3 tests/integration/hermes-upstream-fleet/validate.py \
  plan --fleet-id smoke --count 2 --profile auth
python3 tests/integration/hermes-upstream-fleet/validate.py \
  render --fleet-id smoke \
  --instance auth:auth \
  --instance search:sessions-search \
  --state-dir "$state_dir"

# Rootless Podman + podman-compose live operations.
python3 tests/integration/hermes-upstream-fleet/validate.py \
  start --fleet-id smoke \
  --instance auth:auth \
  --instance search:sessions-search \
  --state-dir "$state_dir"
python3 tests/integration/hermes-upstream-fleet/validate.py \
  endpoint --fleet-id smoke --instance auth:auth
python3 tests/integration/hermes-upstream-fleet/validate.py \
  status --fleet-id smoke --state-dir "$state_dir"
python3 tests/integration/hermes-upstream-fleet/validate.py \
  readiness --fleet-id smoke --state-dir "$state_dir"

# Remove one project or every project recorded for the fleet. Repeating the
# whole-fleet command is a safe no-op after successful removal.
python3 tests/integration/hermes-upstream-fleet/validate.py \
  teardown --fleet-id smoke --instance auth --state-dir "$state_dir"
python3 tests/integration/hermes-upstream-fleet/validate.py \
  teardown --fleet-id smoke --all --state-dir "$state_dir"
```

`endpoint` returns `http://hermes:8000` with `scope=private_compose_network`
and `published=false`. It is an internal service address, not a host/public
endpoint. `readiness` reports only the process-level Compose state. A running
container is not evidence of Hermes chat behavior, browser authentication,
provider access, PTY correctness, or compatibility.

`start` renders every project before launching and starts them concurrently.
Any failed start, worker exception, or interruption invokes
`down --volumes --remove-orphans` for every planned project, including projects
that had not started. Teardown then checks only generated project labels and
the exact generated network and volume names. A cleanup result is successful
only when container, network, and volume leftovers are all zero. State files
are removed only after that proof. A per-instance teardown cannot target an
unrecognized project.

## Bounded evidence

Public command output is one compact JSON line capped at 16 KiB. It retains
stable statuses, exit codes, generated safe names, reviewed resource totals,
and the exact approved image digest. It never retains engine stdout/stderr,
URLs supplied by the caller, paths, environment values, credentials, cookies,
provider names, or transcript content. Diagnostic strings are separately
redacted and capped at 512 bytes for unit-level testing.

The checked-in `cases.json` is synthetic policy data. It records the expected
normal and optimized regressions for naming, concurrency, digest binding,
resource budgets, Docker/provider rejection, partial failure, interruption,
idempotent cleanup, zero leftovers, and process-only readiness. It does not
claim live readiness.

`vm-demo-evidence.json` is the one authorized VM observation. It retains the
exact official `RepoDigest`, rootless Podman and `podman-compose` identity,
deterministic project/network/volume names, the applied `auth` resource
profile, the private endpoint, the `not_ready` process classification, the
exact teardown command, and the three native `io.podman.compose.project`
zero-leftover listings. Its SHA-256 anchor is
`vm-demo-evidence-sha256.txt`. The artifact is bounded and redacted; it does
not retain engine output or claim client compatibility.

## Authorized no-provider VM demo

The only live demo is one `auth` instance on the dedicated authorized
rootless VM, using the official digest above and no provider configuration. Run
from the VM as the dedicated non-privileged account after confirming that
`podman info` reports rootless mode and that `podman-compose` is the selected
Compose executable:

```sh
export HERMTERNAL_UPSTREAM_FLEET_VM_DEMO=1
python3 tests/integration/hermes-upstream-fleet/validate.py \
  demo --state-dir "$(mktemp -d)"
```

Without the explicit authorization variable the command fails before any
engine call. The demo pulls or inspects only the immutable official reference,
records `digest_verified=true` in its bounded result, reports process-level
status, and always tears down its generated project and named resources in a
`finally` path. It does not enable a provider, browser login, model turn, or
public port. Preserve the one-line output as the VM observation only after
checking `zero_leftovers=true`; do not interpret it as chat or browser
compatibility evidence.

## Offline verification

```sh
python3 tests/integration/hermes-upstream-fleet/validate.py plan \
  --fleet-id checked --count 1 --profile auth
python3 -O tests/integration/hermes-upstream-fleet/validate.py plan \
  --fleet-id checked --count 1 --profile auth
python3 tests/integration/hermes-upstream-fleet/test_validate.py
python3 -O tests/integration/hermes-upstream-fleet/test_validate.py
python3 -m py_compile \
  tests/integration/hermes-upstream-fleet/validate.py \
  tests/integration/hermes-upstream-fleet/test_validate.py
```

This is a non-UI protocol fixture. Accessibility, Dynamic Type, browser zoom,
focus order, VoiceOver, Switch Control, contrast, motion, and touch targets
are not applicable because the launcher creates no user interface. Any later
client must preserve its own accessibility contract while using this
provider-free deployment boundary.
