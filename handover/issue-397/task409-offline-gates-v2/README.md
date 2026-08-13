# Offline gates v3

This successor replaces the rejected #406 v2 design. It does not run replay,
Hermes, a network command, or a gate during its tests.

The tool accepts only the real Linux #405 `replay-result.json` and
`replay-completion.json`. `final-linux-pins.json` already pins the approved
shared Linux profile and #401 authority module. It remains intentionally
deferred for the final Linux authority root, #404/#405 successor bytes,
expected `dev` base, and local toolchain digest. It rejects until those final
replay values are written. It has no macOS or `/private/tmp` fallback.

After finalization, it loads and pins:

- the shared immutable Linux platform profile;
- the final Linux authority descriptor, provenance, and authority module;
- the final Linux Phase A and #405 wrapper modules;
- the pre-update `dev` base. `dev` must still equal that base, not the replay
  final head; #407 is the only later normal update to the final head.

It uses the actual #405 closed schemas, completion bindings, and #404 anchor
validator. It then repeats the complete chain after the final gate and before
the create-only report write. The report has mode `0600`, uses `O_EXCL`, fsyncs
the file and directory, and has three stable no-follow rereads.

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
evidence before and after the gates.

Run only after independent review authorizes the real retained replay result:

```sh
python3 -B handover/issue-397/task409-offline-gates-v2/offline_gates_v2.py \
  --result /tmp/<approved-retained-run>/replay-root/replay-result.json \
  --completion /tmp/<approved-retained-run>/replay-root/replay-completion.json \
  --report /tmp/<approved-retained-run>/replay-root/offline-gates.json
```

Offline checks (these mock only the subprocess/container boundary and image
discovery; parsers, semantic evidence, and report writer are real):

```sh
python3 -m py_compile handover/issue-397/task409-offline-gates-v2/offline_gates_v2.py handover/issue-397/task409-offline-gates-v2/test_offline_gates_v2.py
python3 -B handover/issue-397/task409-offline-gates-v2/test_offline_gates_v2.py
python3 -O -B handover/issue-397/task409-offline-gates-v2/test_offline_gates_v2.py
```

This is not replay evidence or permission to update `dev` or `main`.
