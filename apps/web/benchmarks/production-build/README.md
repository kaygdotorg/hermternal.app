# Web production-build benchmark

**Roadmap operation:** B-03 (`#107`)

**Status:** deterministic, local, no-network benchmark harness with baseline-only evidence

This exclusive directory owns the web production-build benchmark. It does not change package scripts, the lockfile, routes, application styles, the shared fixture registry, or production runtime. It builds a bounded temporary copy of the reviewed static web scaffold with an immutable snapshot of installed local dependencies. It does not start Hermes, a browser, a preview server, or a live integration.

## Workload and states

`workload.json` fixes the workload identity, production build entrypoint, copied build inputs, cold and warm repetition counts, pinned Hermes source SHA, and resource limits.

- A **cold** sample uses a new temporary workspace. No generated SvelteKit state or production output survives from another sample.
- A **warm** series reuses one temporary workspace and one OS sandbox after one unmeasured priming build. Keeping the complete series inside one sandbox preserves Linux's quota tmpfs, generated SvelteKit state, Vite temporary state, and prior output between samples. The priming observation is retained in the raw trace but excluded from the warm distribution.
- Each checked-in evidence distribution contains 30 raw samples. The harness reports min, mean, p50, p95, p99, and max with B-01 R-7 interpolation and half-even three-decimal rounding.
- `threshold` and `budget` remain `null`. These local observations are not a performance promise. A threshold must wait for reviewed baselines under B-08A.

The benchmark requires the tracked `apps/web` tree to be clean at the reviewed commit before and after the run, captures those reviewed inputs into an immutable snapshot before the first sample, and verifies the live input identity did not change during capture. It creates writable workspaces from that snapshot. In the temporary copy only, it pins `kit.version.name`; SvelteKit otherwise uses a build timestamp and changes generated identities between equal runs. It redirects adapter output, SvelteKit intermediates, Vite temporary files, the temporary home, and `TMPDIR` below one quota mount. The source configuration is not edited; the deterministic generated configuration is bound by the reviewed runner bytes, workload fixture, and source inputs.

## Isolation and resource boundaries

The runner clones `node_modules` once into a benchmark-owned dependency snapshot, removes write permission, and binds packages into each workspace. Before any measured build, the snapshot, lockfile, package manifest, reviewed package trees, and platform runtime executables must match independent identities pinned in `workload.json`; a changed Vite byte under an unchanged lockfile fails closed. Vite receives a separate writable `.vite-temp` directory. Dependency and executable identities are checked again after all builds; mutation fails the run. Evidence binds the lockfile, complete resolved dependency bytes, Vite, SvelteKit, the Svelte Vite plugin, Svelte, TypeScript native package bytes, and Node, Bun, Python, and sandbox executable bytes. The recorded Vite version is read as plain JSON metadata from that immutable snapshot; no Vite package code executes for evidence collection.

The complete build descendant tree runs inside an operating-system network boundary:

- macOS launches the fixed `/usr/bin/sandbox-exec` path first, with `network*` denied;
- Linux launches fixed `/usr/bin/bwrap` first, with a separate network and PID namespace plus a read-only host root;
- only after that boundary exists does fixed `/usr/bin/python3 -I -S` import the reviewed supervisor helper;
- unsupported or unavailable absolute sandbox and interpreter paths fail closed.

The workload pins the supervisor and scanner SHA-256 identities. The runner verifies those local bytes and fixed executable identities before any measured build import or command runs. The boundary is inherited by direct sockets and children even if they clear `NODE_OPTIONS` or replace `PATH`. Offline package-manager flags remain defense in depth; no JavaScript patch is the security boundary.

A protected in-sandbox supervisor owns the complete process lifecycle. Linux runs it as PID 1 in a private PID namespace, so orphan adoption cannot race polling. macOS Seatbelt permits the supervisor to start the measured Node executable but denies `process-fork` when Node is the caller, so a fast detached daemon cannot be created between ancestry observations. Timeout, output overflow, SIGINT, and SIGTERM terminate descendants, wait a bounded grace period, escalate to `SIGKILL`, and reap the tree before returning. The outer runner bounds pipe draining and uses one absolute cleanup deadline. It registers each run root synchronously and publishes readiness only after dependency cloning and toolchain/helper verification. It reports signal completion only after registered filesystem cleanup finishes. Recorded build duration comes from the supervisor at direct-child exit; descendant cleanup, pipe draining, artifact scanning, and hashing are excluded.

The workload bounds repetitions, each build timeout, the aggregate series deadline, Node heap, captured stdout and stderr, copied input bytes, artifact file count, and artifact bytes. The in-sandbox supervisor enforces the per-build timeout for every child; the outer runner adds only a bounded cleanup grace period to the sum of those per-build limits. macOS exposes exactly one writable root backed by a quota-sized HFS+ sparse volume. Linux exposes exactly one writable root backed by a quota-sized bubblewrap tmpfs, and the warm series runs inside one namespace so that quota and generated state survive between samples. All build-writable paths resolve inside that root, so a transient output symlink cannot redirect writes to unquotaed workspace storage. The in-sandbox supervisor scans each final output before the private mount namespace is destroyed. This enforces aggregate peak writable capacity rather than relying on periodic or final-state sampling.

Artifact scanning opens the workspace and every descendant relative to directory file descriptors with `O_NOFOLLOW`. It rejects root, intermediate, and file symlinks and compares validated, opened, and final path identities. Each file is hashed over exactly one initial bounded extent, with reads limited to the remaining extent plus one rejection byte. Growth, shrinkage, same-size mutation, and path replacement all fail; reported bytes equal bytes actually hashed. An external symlink target is never read or hashed.

A limit violation or non-zero build fails closed. The CLI emits one bounded JSON error without raw child output, paths, URLs, environment values, or attacker-controlled arguments. Raw build output is counted but not stored.

## Evidence

`evidence/raw-trace.json` records every successful observation, the excluded warm-up, resource counts, complete B-01 provenance, environment metadata, the pre-sample immutable build-input identity, independently anchored dependency and runtime identities, toolchain byte identity, sandbox mode, source commit, fixture digest, and applied limits. A dirty tracked source tree, source commit change, or live input mutation detected before or after capture rejects the run. `evidence/benchmark-evidence.json` uses `hermternal.benchmark-evidence.v1`. It records raw cold and warm samples, recomputed distributions, sanitized environment metadata, and immutable anchors for the canonical workload, TypeScript runner, protected supervisor, stable artifact scanner, and raw trace. Threshold and budget remain null.

The canonical B-01 validator at `contracts/benchmarks/validate.py` validates checked-in evidence in normal and optimized Python modes. It enforces bounded strict JSON parsing, duplicate-key rejection, non-finite and exponent-overflow rejection, exact ordered keys and types, redaction, provenance canonicalization, and code-pinned workload, trace, run, and artifact identities.

All inputs are repository source, static assets, and synthetic prototype data. Evidence contains no credentials, cookies, tokens, user data, transcripts, live hosts, network traces, or provider data.

The checked-in observation used an Apple M2 Max with Bun 1.3.14, Node 26.7.0, and Vite 8.2.0. Cold p50/p95/p99 were `1759.434/2196.081/3147.994 ms`. Warm p50/p95/p99 were `1985.502/4302.615/4748.263 ms`. The excluded warm-up and all 60 measured builds produced artifact digest `78ae81588063c7327dcee1f04832d255f01bb8f48518777670d1c92ce2099cb9`. These observations from one local machine do not establish a regression threshold or approved budget.

## Run and verify

Install pinned web dependencies once from `apps/web/`:

```sh
bun install --frozen-lockfile
```

Run focused tests and TypeScript 7 from `apps/web/`:

```sh
bun test benchmarks/production-build/run.test.ts benchmarks/production-build/evidence.test.ts
bun x --package @typescript/native tsc --noEmit --pretty false -p tsconfig.json
```

Run canonical evidence validation from the repository root:

```sh
python3 contracts/benchmarks/validate.py --evidence apps/web/benchmarks/production-build/evidence/benchmark-evidence.json --skip-baseline
python3 -O contracts/benchmarks/validate.py --evidence apps/web/benchmarks/production-build/evidence/benchmark-evidence.json --skip-baseline
```

Run a short representative benchmark without changing checked-in evidence:

```sh
bun benchmarks/production-build/run.ts --cold 2 --warm 2
```

Collect review evidence with the B-01 minimum sample count:

```sh
bun benchmarks/production-build/run.ts --cold 30 --warm 30 --write-evidence
```

The evidence command refuses fewer than 30 cold or warm samples. Review raw samples and environment metadata as baseline observations only. Do not infer or add a threshold from one machine.

## Accessibility

Accessibility verification is **N/A**. This harness has no rendered UI, focus order, semantic controls, screen-reader surface, browser zoom layout, contrast theme, motion, transparency, or touch target. It does not change or remove accessibility behavior from the web scaffold.
