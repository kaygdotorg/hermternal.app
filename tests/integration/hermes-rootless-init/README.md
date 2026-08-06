# Pinned Hermes rootless-init diagnosis

**Operation:** R-02B / issue #250

This directory is an offline, synthetic diagnosis fixture. It does not start
Docker, Podman, Hermes, a provider, a browser, a PTY, or a network service.
`cases.json` records only bounded observations and a capability candidate
matrix. The matrix is not live proof and must not be used as an approved
runtime policy until an independent reviewer and the main coordinator approve
one bounded reproduction.

## Source-backed finding

The pinned source is fixed to:

- repository `NousResearch/hermes-agent`;
- commit `f5be9236e00ddf2f2a412697f267078fc4ee068e`;
- tree `886db5eb1150f819344d67fedc81aef0caab09ff`.

The source references and immutable blob IDs are frozen in `cases.json`.
The relevant startup contract is:

1. `Dockerfile` returns to `USER root` so bootstrap can remap the `hermes`
   UID/GID and prepare the data volume (`Dockerfile:298-311`).
2. `docker/stage2-hook.sh` calls `s6-setuidgid hermes` for startup work
   (`23-24`, `374-396`). The real command path repeats the drop in
   `docker/main-wrapper.sh:31`; an enabled dashboard repeats it in
   `docker/s6-rc.d/dashboard/run:53-56`.
3. A fresh named `/opt/data` volume starts with image ownership. The targeted
   ownership repair therefore needs `CAP_CHOWN` before the unprivileged
   directory creation can succeed. The pinned hook explicitly says rootless
   chown failure is non-fatal only when the mapped volume is already usable
   (`stage2-hook.sh:234-245`).
4. `s6-setuidgid` needs the ability to change the process UID and GID. The
   source calls are therefore source-justified evidence for `CAP_SETUID` and
   `CAP_SETGID`; `no-new-privileges` does not replace those capabilities.
5. `supervise-perms` chown warnings are not, by source, a fatal exit path.
   Both `015-supervise-perms:64-86` and the stage2 chown helpers handle chown
   failure and continue. A warning plus an exit code is evidence of a
   runtime boundary failure, not proof that the warning itself returned the
   exit code.

The new Docker comparison records exit 126 with `cap_drop=ALL` and
`no-new-privileges=true`. That is consistent with the pinned UID/GID-drop path
being unable to execute under the hardened capability set. The rootless
Podman observation records exit 2 with bounded `supervise-perms` warnings. It
is classified separately as a pinned rootless-init incompatibility because the
same safe boundary omits the capabilities required by the pinned startup path;
the fixture does not claim that rootless Podman alone is unsupported.

This result is **blocked readiness evidence**, not Hermes readiness or R-02
release proof.

## Candidate capability matrix

The smallest candidate set for a **fresh named volume** is recorded separately
for each executor:

| Executor | User namespace | Candidate caps | Preconditions |
| --- | --- | --- | --- |
| Docker | rootful | `CAP_CHOWN`, `CAP_SETGID`, `CAP_SETUID` | the image's root bootstrap remains PID 1 |
| Podman | rootless | `CAP_CHOWN`, `CAP_SETGID`, `CAP_SETUID` | rootless user namespace and subordinate UID/GID mappings include the target `hermes` IDs |

The validator requires exactly one Docker/rootful entry and exactly one
Podman/rootless entry. Entry order is not evidence identity: duplicates,
omissions, executor/namespace swaps, and Docker-only `preconditions` fields are
rejected. The matrix remains candidate-only and retains the exact three-capability
set; it is not a live approval.

`CAP_CHOWN` can be omitted only for a separately verified, already-owned
volume with no UID/GID remap. The checked-in case is a fresh named volume, so
the candidate includes it. The source does not justify adding
`CAP_DAC_OVERRIDE`, `CAP_FOWNER`, `CAP_NET_ADMIN`, `CAP_NET_RAW`, or
`CAP_SYS_ADMIN`; adding them would hide a fixture or runtime defect and is
rejected by the validator. No `privileged`, host-network, published-port,
host-profile-bind, arbitrary-user, or disabled-`no-new-privileges` workaround
is accepted.

### Proposed one-run configuration

This is the exact candidate configuration for independent review. It has not
been run by this fixture and is not an authorization to launch:

```text
executor: podman
compose_provider: podman-compose
account: hermternal-test
rootless: true
project: generated_hermes_rootless_init_candidate
image: hermes-agent:hermternal-f5be9236
command: sleep infinity
cap_drop: [ALL]
cap_add: [CAP_CHOWN, CAP_SETGID, CAP_SETUID]
security_opt: [no-new-privileges:true]
published_ports: []
binds: []
host_network: false
host_profile_bind: false
network: generated_internal_project_network
volume: generated_named_project_volume
limits: cpus=0.50 memory=512m pids=256 tmpfs=/tmp:64m,/run:16m shm=64m logs=1m
readiness: bounded redacted state and native inspect only
evidence: bounded_redacted_state, native_inspect, zero_leftover_counts
teardown: down --volumes --remove-orphans
```

This rootless Podman run must be reviewed before launch; the fixture has not
launched it. If approved, run only under `hermternal-test`, capture bounded
redacted state, and classify teardown as complete only when the recognized
generated project leaves zero containers, networks, and volumes. Docker exit
126 remains comparison evidence and is not the proposed verification run.

## Classification contract

The deterministic fixture distinguishes:

- `harness_defect`: the evidence checker treated a named volume in
  `HostConfig.Binds` as a host bind. Native mount type/source classification is
  required; a named volume is not a host profile bind.
- `pinned_boundary_incompatibility`: Docker exit 126 under the approved
  `cap_drop=ALL` boundary, where pinned source calls require UID/GID dropping
  and fresh-volume ownership.
- `pinned_rootless_incompatibility`: the bounded Podman exit-2 observation with
  `supervise-perms` warnings under the same missing-capability boundary.
- `unsafe_workaround_rejected`: privilege escalation, host networking,
  published ports, host profile data, arbitrary `--user`, or disabling
  `no-new-privileges`.
- `cleanup_complete`: a failed readiness attempt is still safely cleaned when
  the exact generated project is recognized and all leftover counts are zero.

For `unsafe_workaround_rejected`, reason codes are exact and mutation-bound:
capability escalation requires `privileged`, `capability_escalation`,
`host_network`, `published_port`, `host_profile_bind`, and
`no_new_privileges_disabled`; arbitrary-user override requires only
`arbitrary_user_override`. Wrong, reordered, missing, or extra codes fail.

The validator never echoes raw logs, paths, URLs, credentials, cookies,
headers, tokens, PTY bytes, or hostile JSON keys. The public redaction helper
also removes `Authorization: Token` and `Authorization=Bearer`, `X-API-Key`,
quoted JSON or assignment forms of `api_key`/`access_key`/`token`,
`password`/`client_secret`, Base64-shaped blobs including short URL-safe forms,
and POSIX, Windows, or UNC absolute paths even when path components contain
spaces. Errors are one bounded JSON line and remain redacted under normal and
optimized Python execution. Each case kind has an exact top-level schema;
fields from a runtime, harness, policy, or cleanup variant cannot be carried
into another variant. The approved-boundary object is schema-checked before
any nested key is indexed, so every key deletion returns the same bounded JSON
failure in both CLI modes.

## Offline verification

Run from the repository root:

```sh
python3 tests/integration/hermes-rootless-init/validate.py
python3 -O tests/integration/hermes-rootless-init/validate.py
python3 tests/integration/hermes-rootless-init/test_validate.py
python3 -O tests/integration/hermes-rootless-init/test_validate.py
python3 -m py_compile \
  tests/integration/hermes-rootless-init/validate.py \
  tests/integration/hermes-rootless-init/test_validate.py
```

The regression suite runs the real validator CLI in both normal and optimized
Python modes. Its table-driven nearby mutations cover duplicate or missing
Docker/Podman matrix entries, Docker-only fields, approved-boundary key
deletions, wrong/reordered/missing/extra policy reason codes, irrelevant
case-variant fields, unsafe live claims, and sensitive diagnostic shapes
including spaced paths, quoted credentials, Authorization assignments, and
short or URL-safe Base64.

This is a non-UI protocol fixture. Accessibility verification is N/A because
it creates no controls, focus order, semantic names, screen-reader or
VoiceOver surface, Switch Control behavior, Dynamic Type or browser-zoom
layout, contrast, motion, transparency, or touch target. Any later client
must preserve its accessibility contract while respecting this deployment
boundary.
