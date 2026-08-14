# Offline gates v3

This successor replaces the rejected #406 v2 design. It does not run replay,
Hermes, a network command, or a gate during its tests.

The tool accepts only the real Linux #405 `replay-result.json` and
`replay-completion.json`. `final-linux-pins.json` already pins the approved
shared Linux profile, #401 authority module, and Linux authority root. It
remains intentionally deferred for the final Phase A and #405 wrapper bytes
and expected `dev` base. The local toolchain digest is now pinned. It rejects
until the remaining final values are written. It has no macOS or `/private/tmp`
fallback.

After finalization, it loads and pins:

- the shared immutable Linux platform profile;
- the final Linux authority descriptor, provenance, and authority module;
- the final Linux Phase A and #405 wrapper modules;
- the pre-update `dev` base. `dev` must still equal that base, not the replay
  final head; #407 is the only later normal update to the final head.

It accepts a positive, unpadded version in the exact Phase A evidence schema
namespace. It then requires the anchor record to use the exact schema exported
by the hash-pinned Phase A module. It uses the actual #405 closed schemas,
completion bindings, and #404 anchor validator. It then repeats the complete
chain after the final gate and before the create-only report write. The report
has mode `0600`, uses `O_EXCL`, fsyncs the file and directory, and has three
stable no-follow rereads.

The current Linux replay adapters configure the final #405 wrapper only in
memory. No final source file currently exposes both that configured authority
and the closed #405 result API that this gate loads. Thus, the wrapper path and
digest stay null until the replay lane supplies one reviewed load boundary.

All executable gates are fixed in code. They run only in rootless Podman with
a locally staged image digest, `--pull=never`, `--network=none`, a read-only
repository bind, no host credential mounts, dropped capabilities, and
no-new-privileges. Podman image inspection must attest Bun 1.3.14, Node 26.7.0,
Playwright 1.62.1, and the exact locked dependency SHA-256. The image must
contain the browser and immutable dependency tree already; #406 never pulls or
installs them. It copies that tree from `/opt/hermternal/node_modules` into a
dedicated tmpfs. Separate tmpfs mounts cover `.svelte-kit`, `build`,
`test-results`, and `playwright-report`, so source stays read-only while build
and browser tooling can write. The report records stable privacy,
accessibility, click/Enter, input-clearing, and screenshot/DOM-redaction source
evidence before and after the gates. Those tracked source files use normal Git
mode `0644`; they are accepted only when owner-owned, single-link regular
files have stable bytes that match the exact `100644` blob in the replay final
tree. This is different from authority, replay, and report evidence, which
remains mode `0600`.

`toolchain/` now contains the exact Linux amd64 construction and staging
specification. The retained staging set binds the official Bun archive, the
Playwright Chromium headless-shell archive, the exact Node OCI child manifest,
the signed Debian 13 snapshot index, 114 exact Debian packages, and the Linux
dependency tree produced from the committed frozen lock. The dependency-tree
digest is final. An authorized rootless, network-disabled build produced local
image ID
`sha256:a834f2f05e84c441da304939d287f0598eececbe9e6855cfb7b7cc9ac957c695`
and repository digest
`sha256:a10cb9ee63acdd627824be448b3031bc788ee02992056fb44a9303f1904a98fc`.
These values identify the retained local image. They do not claim that the
image exists in an external registry.

The staging verifier reads only local files and the local Podman store. It
requires a private owner directory, rootless amd64 Podman, the exact base
RepoDigest, the signed Debian `InRelease`, all package hashes from its signed
`Packages.xz`, epoch-normalized context metadata, and the shared dependency
tree identity function. It runs its signature check in the pinned base with
`--pull=never`, `--network=none`, a read-only staging mount, dropped
capabilities, and a small tmpfs:

```sh
python3 -B handover/issue-397/task409-offline-gates-v2/toolchain/verify_staging.py \
  --root /tmp/<retained-private-staging-root>
```

The authorized deterministic build used this command:

```sh
podman build --pull=never --network=none --platform linux/amd64 \
  --timestamp=0 --omit-history --squash-all \
  --file handover/issue-397/task409-offline-gates-v2/toolchain/Containerfile \
  --tag localhost/hermternal-offline-gates:issue-406-v1 \
  /tmp/<retained-private-staging-root>
```

The tag is only the local inspection handle. The committed image reference uses
the exact `RepoDigest`, and the staging manifest records the separate immutable
image ID. Verify the image ID, every label, and the exact local `RepoDigest`
before any replay evidence is accepted:

```sh
python3 -B handover/issue-397/task409-offline-gates-v2/toolchain/verify_staging.py \
  --root /tmp/<retained-private-staging-root> \
  --image localhost/hermternal-offline-gates:issue-406-v1 \
  --repo-digest sha256:a10cb9ee63acdd627824be448b3031bc788ee02992056fb44a9303f1904a98fc
```

The minimal smoke check also uses `--pull=never`, `--network=none`, a read-only
root filesystem, no capabilities, no-new-privileges, and a bounded `/tmp`
tmpfs. It confirms Bun, Node, Playwright, Chromium, and `dpkg --audit` without
running an application gate.

Run only after independent review authorizes the real retained replay result:

```sh
python3 -B handover/issue-397/task409-offline-gates-v2/offline_gates_v2.py \
  --result /tmp/<approved-retained-run>/replay-root/replay-result.json \
  --completion /tmp/<approved-retained-run>/replay-root/replay-completion.json \
  --report /tmp/<approved-retained-run>/replay-root/offline-gates.json
```

Offline checks use a real controlled Git checkout, real hash-bound Linux and
#405 fixture modules, real parsers, semantic Git/blob evidence, and the real
create-only report writer. They replace only the Podman subprocess and image
discovery boundary:

```sh
python3 -m py_compile handover/issue-397/task409-offline-gates-v2/offline_gates_v2.py handover/issue-397/task409-offline-gates-v2/test_offline_gates_v2.py
python3 -B handover/issue-397/task409-offline-gates-v2/test_offline_gates_v2.py
python3 -O -B handover/issue-397/task409-offline-gates-v2/test_offline_gates_v2.py
python3 -B handover/issue-397/task409-offline-gates-v2/toolchain/test_toolchain_spec.py
python3 -O -B handover/issue-397/task409-offline-gates-v2/toolchain/test_toolchain_spec.py
```

This is not replay evidence or permission to update `dev` or `main`.
