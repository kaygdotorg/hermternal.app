# Isolated disposable Hermes harness

**Operation:** R-02A / issue #246

**Status:** deterministic synthetic renderer and validator; one approved VM
smoke lane is recorded separately and does not claim the blocked R-02 release
suite.

This directory owns the safe standalone Compose boundary for a disposable
Hermes stack. It uses only Python's standard library and synthetic policy
fixtures. The validator never starts Hermes, Podman, Docker, a provider, a
browser, a PTY, a proxy, or a network service. Browser and model lanes are
render-only policy fixtures. The only live lane allowed by this operation is
one no-provider startup smoke stack in the authorized VM.

## Pinned source and container findings

The VM source checkout is required to be exactly:

- Hermes commit `f5be9236e00ddf2f2a412697f267078fc4ee068e`;
- Hermes Git tree `886db5eb1150f819344d67fedc81aef0caab09ff`.

The pinned upstream Compose example is not reused as a deployment template. It
uses a fixed `container_name`, host networking, a host `~/.hermes` bind, and an
unbounded restart policy. Those choices would defeat disposable project,
network, volume, and cleanup isolation.

The pinned image uses its own entrypoint dispatcher, which preserves the s6
`/init` PID-1 path. The generated Compose service therefore omits `entrypoint`,
`init`, and `user` overrides. It starts as the image expects and passes explicit
`HERMES_UID` and `HERMES_GID` values instead of using arbitrary `--user` or
`--init` settings.

The image reference is the synthetic tag `hermes-agent:hermternal-f5be9236`.
The VM evidence records the built image digest separately; no mutable digest or
host-specific image output is checked into this fixture.

## Frozen Compose invariants

Every render creates a project-derived name, internal network, and named data
volume from the bounded stack ID and instance. The service has:

- no `container_name`, host networking, published ports, host profile bind, or
  host environment interpolation;
- the image's default entrypoint, explicit `HERMES_UID=10000` and
  `HERMES_GID=10000`, and `restart: "no"`;
- CPU `0.50`, memory `512m`, PID `256`, `/tmp` and `/run` tmpfs mounts, and
  `64m` shared memory;
- `cap_drop: ["ALL"]` and `no-new-privileges`;
- executor-specific bounded logs: Podman `k8s-file` with `max-size=1m`, or
  Docker `json-file` with `max-size=1m` and `max-file=2`;
- a disabled API server by default, disabled provider auto-discovery, and no
  PTY or public Dashboard exposure.

The generated teardown command is project-scoped and must be exactly
`down --volumes --remove-orphans`. The validator refuses an unrecognized
project name.

## Executor contract

Rootless Podman is the preferred executor for the VM smoke. Before starting it,
the VM lane records and checks the dedicated non-privileged account, rootless
user namespaces, subordinate UID/GID ranges, cgroup v2 delegation, overlay
storage, netavark networking, Compose config rendering, resource limits, no
published ports, named-volume isolation, and cleanup.

Docker is retained as one controlled compatibility lane. It renders the same
policy with Docker's `json-file` log options. The authorized root-only
observation started the prepared Docker project once, reached no readiness
state, exited 126, and completed exact project-only cleanup with zero leftovers.
The run is compatibility evidence only; it is not release proof. Docker and
Podman Compose semantics are not assumed equivalent, and the VM report records
the engine, provider, version, config status, bounded raw observations, mount
type, and cleanup result.

## VM smoke observation

The authorized VM verified the pinned source commit and Git tree before the
smoke. The stock pinned Dockerfile could not be parsed by Podman 5.4.2 because
it uses `COPY --link --chmod=a+rX,go-w`. The checkout stayed read-only. A
short-lived VM-only adapter changed only that instruction to `COPY . .` so the
same pinned source context could be built; it did not change application files,
the entrypoint dispatcher, s6 scripts, or runtime content. The adapter is not
stock-Dockerfile compatibility evidence. The Docker compatibility lane reused
the already identified pinned image and did not rebuild the stock Dockerfile.

The first `podman compose` invocation selected the external Docker Compose
provider. Its configuration rendered safely, but start was blocked because the
rootless Podman API socket was not configured. The approved native
`podman-compose` provider then started exactly one no-provider stack. It
published no ports, used the generated internal network and named volume, and
applied the rendered CPU, memory, PID, tmpfs, shared-memory, log, capability,
no-new-privileges, and `restart: "no"` limits. Readiness failed with exit 2
while the pinned s6 startup emitted bounded `supervise-perms` chown warnings.
The security policy was not relaxed and no replacement Podman stack was
started.

The separate authorized root-only Docker compatibility observation used the
same generated no-provider policy and exact project. Docker Compose config
passed with no ports, host bind, or host network. The container started,
reached no readiness state, exited 126, and was torn down with
`down --volumes --remove-orphans`; zero containers, networks, and volumes
remained. Its inspect evidence identifies the `/opt/data` mount as the exact
generated named volume with `type=volume` and no `type=bind`. Neither executor
result claims readiness or release proof.

The evidence file is strict-schema validated, redaction-checked, and pinned by
canonical JSON digest plus an anchor file. It includes Debian OS metadata,
Podman/Docker Compose engine/provider/version metadata, and bounded raw
observations for config, start, readiness, inspection, and cleanup. The Docker
inspection retains only an allowlisted `.Mounts` projection: exactly one
`type=volume` entry named `hermes-disposable-docker-078ac20d_data` at
`/opt/data`; host `type=bind` entries and host `Source` paths are rejected or
omitted. The redacted observation is retained in `vm-smoke-evidence.json`; it
is blocked readiness evidence, not a successful Hermes smoke or R-02 release
proof.

The canonical renderer is executor-selectable:

```text
python3 tests/integration/hermes-disposable/validate.py \
  --skip-baseline --render /tmp/synthetic-compose.yml \
  --stack-id smoke --instance one --lane no-provider --executor podman
```

The command writes only the requested synthetic Compose file. It does not read
`.env`, inherit the host environment, or create credentials.

## Lanes and evidence boundary

`cases.json` freezes three renderer lanes:

- `no-provider`: `sleep infinity`, no provider variables, Dashboard disabled;
- `browser`: internal-only Dashboard with deterministic disposable Basic-auth
  values, render-only and never used for the VM smoke;
- `model`: `synthetic-local` provider marker with auto-discovery disabled,
  render-only and never used for a model turn.

The fixture does not prove browser authentication, model turns, PTY behavior,
Dashboard behavior, API behavior, Caddy, Traefik, or release compatibility.
Those remain outside issue #246. No passwords, keys, cookies, tickets, session
content, transcripts, provider credentials, profiles, or user data are retained
in the repository or evidence.

## Strict validation and redacted failures

The JSON loader rejects duplicate keys, non-finite or overflowing numbers,
oversized integers, malformed UTF-8, excessive depth, node counts, container
width, array length, string length, and control characters. Exact key order and
scalar types are required, including under `python3 -O`.

CLI failures emit one bounded JSON line with no traceback or argparse usage
text. Diagnostics redact credential headers, Basic and Bearer values, cookies,
URLs and data URLs, hostnames and addresses, paths and filenames, private-key
markers, Base64-shaped payloads, and `api_key`/`access_key` assignments. Only
exactly pinned source/tree and image/artifact digests are retained; arbitrary
40- or 64-hex values are rejected. Hostile object keys are never echoed.

## Benchmark observations

`validation-baseline.json` contains 30 fresh normal and 30 fresh optimized
validator-process samples with raw traces, distributions, and the measured
fixture artifact digest. `threshold` is `null` because issue #246 does not
approve a performance budget. The values are observations, not a release
promise. The VM smoke records build, render/config, start, readiness, inspect,
and teardown observations separately, also with raw samples and a null
threshold.

## Offline verification

Run from the repository root:

```sh
python3 tests/integration/hermes-disposable/validate.py
python3 -O tests/integration/hermes-disposable/validate.py
python3 tests/integration/hermes-disposable/test_validate.py
python3 -O tests/integration/hermes-disposable/test_validate.py
python3 -m unittest discover \
  -s tests/integration/hermes-disposable -p 'test_*.py'
python3 -O -m unittest discover \
  -s tests/integration/hermes-disposable -p 'test_*.py'
python3 -m py_compile \
  tests/integration/hermes-disposable/validate.py \
  tests/integration/hermes-disposable/test_validate.py
```

All repository commands are offline and standard-library-only. The separate
VM smoke must run through the authorized account and must capture redacted
rendered config, source and image identity, resource/network/volume/port
inspection, readiness, and project-only teardown proof before removing the
stack and volume.

## Accessibility applicability

N/A for this non-UI protocol fixture. It creates no controls, focus order,
semantic names, screen-reader or VoiceOver surface, Switch Control behavior,
Dynamic Type or browser-zoom layout, contrast, motion, transparency, or touch
target. Later clients must preserve their accessibility contracts while
respecting this isolated deployment boundary.
