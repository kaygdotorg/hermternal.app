# Offline gates v2

This successor replaces the rejected #406 speculative interlock design. It
does not run replay, Hermes, a network command, or a gate during its tests.

The tool accepts only the real #405 `replay-result.json` and
`replay-completion.json`. Before it creates a report, it loads and pins:

- #403 final authority descriptor and provenance at their fixed canonical path;
- #401 authority module SHA-256 `1eec1b59…a75c9bb9a8`;
- #404 v2 Phase A/anchor runner SHA-256 `fb11d840…999baaf84`;
- #405 retained wrapper SHA-256 `a8a00bab…3df0160be60`.

It uses the actual #405 closed schemas, completion bindings, and #404 anchor
validator. It then repeats the complete chain after the final gate and before
the create-only report write. The report has mode `0600`, uses `O_EXCL`, fsyncs
the file and directory, and has three stable no-follow rereads.

All executable gates are fixed in code. They run only in rootless Podman with
an image digest, `--pull=never`, `--network=none`, a read-only repository bind,
no host credential mounts, dropped capabilities, no-new-privileges, and a
small temporary filesystem. The image must already exist locally. The report
also records structured source evidence for privacy redaction, accessibility,
click and Enter activation, input clearing, and screenshot/DOM redaction.

Run only after independent review authorizes the real retained replay result:

```sh
python3 -B handover/issue-397/task409-offline-gates-v2/offline_gates_v2.py \
  --result /private/tmp/hermternal-task409-final-replay.<pid>/replay-root/replay-result.json \
  --completion /private/tmp/hermternal-task409-final-replay.<pid>/replay-root/replay-completion.json \
  --report /private/tmp/hermternal-task409-final-replay.<pid>/replay-root/offline-gates.json
```

Offline checks (these mock only the subprocess/container boundary and image
discovery; parsers, semantic evidence, and report writer are real):

```sh
python3 -m py_compile handover/issue-397/task409-offline-gates-v2/offline_gates_v2.py handover/issue-397/task409-offline-gates-v2/test_offline_gates_v2.py
python3 -B handover/issue-397/task409-offline-gates-v2/test_offline_gates_v2.py
python3 -O -B handover/issue-397/task409-offline-gates-v2/test_offline_gates_v2.py
```

This is not replay evidence or permission to update `dev` or `main`.
