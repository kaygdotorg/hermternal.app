# Web production-build benchmark

**Roadmap operation:** B-03 (`#107`)

**Status:** deterministic, local, no-network benchmark harness with baseline-only evidence

This exclusive directory owns the web production-build benchmark. It does not change the web package scripts, lockfile, routes, application styles, shared fixture registry, or production runtime. It builds a bounded temporary copy of the reviewed static web scaffold with the installed local dependencies. It does not start Hermes, a browser, a preview server, or a live integration.

## Workload and states

`workload.json` fixes the workload identity, production build entrypoint, copied build inputs, cold and warm repetition counts, pinned Hermes source SHA, and resource limits.

- A **cold** sample uses a new temporary workspace. No generated SvelteKit state or production output survives from another sample.
- A **warm** sample reuses one temporary workspace after one unmeasured priming build. The priming observation is retained in the raw trace but excluded from the warm distribution.
- Each checked-in evidence distribution contains 30 raw samples. The harness reports min, mean, p50, p95, p99, and max with the B-01 R-7 interpolation and half-even three-decimal rounding method.
- `threshold` and `budget` remain `null`. These local observations are not a performance promise. A threshold must wait for reviewed baselines under B-08A.

The benchmark copies only `package.json`, Svelte/Vite/TypeScript configuration, `src/`, and `static/`. In the temporary copy only, it wraps the source Svelte config with the fixture-pinned `kit.version.name`; SvelteKit otherwise defaults that value to the build timestamp and changes generated asset identities between identical runs. The source config is not edited. The harness rejects symlinks and non-file inputs, and it requires one generated artifact digest across the warm-up and every measured sample. Every workspace is removed after use, including failure, timeout, or interruption handled by the runner.

## Determinism and resource boundaries

The build runs through the locally installed Vite entrypoint with a minimal fixed environment. `network-guard.mjs` is preloaded before Vite. It denies `fetch`, DNS, datagram, HTTP, HTTPS, TCP, and TLS entry points. Offline package-manager flags are also set. No dependency installation occurs inside a measured run.

The workload bounds:

- repetitions;
- build timeout;
- Node heap size;
- captured stdout and stderr;
- copied input bytes;
- generated artifact file count; and
- generated artifact bytes.

A limit violation or non-zero production build fails closed. The CLI emits one bounded JSON error with no raw child output, path, URL, environment value, or attacker-controlled argument. Raw build output is counted but is not stored in evidence.

## Evidence

`evidence/raw-trace.json` records every successful observation, the excluded warm-up, resource counts, input identity, environment metadata, source commit, fixture digest, and applied limits. `evidence/benchmark-evidence.json` uses `hermternal.benchmark-evidence.v1` from B-01. It records the raw samples and distributions for cold and warm production builds, sanitized environment metadata, artifact hashes, redaction declarations, and null threshold and budget fields.

All inputs are repository source, static assets, and synthetic prototype data. The evidence contains no credentials, cookies, tokens, user data, transcripts, live hosts, network traces, or provider data.

## Run and verify

Install the pinned web dependencies once from `apps/web/`:

```sh
bun install --frozen-lockfile
```

Run focused contract tests:

```sh
bun test benchmarks/production-build/run.test.ts
bun x --package @typescript/native tsc --noEmit --pretty false -p tsconfig.json
```

Run a short representative benchmark without changing checked-in evidence:

```sh
bun benchmarks/production-build/run.ts --cold 2 --warm 2
```

Collect review evidence with the B-01 minimum sample count:

```sh
bun benchmarks/production-build/run.ts --cold 30 --warm 30 --write-evidence
```

The evidence command intentionally refuses fewer than 30 cold or warm samples. Review raw samples and environment metadata as baseline observations only. Do not infer or add a threshold from one machine.

## Accessibility

Accessibility verification is **N/A**. This harness has no rendered UI, focus order, semantic controls, screen-reader surface, browser zoom layout, contrast theme, motion, transparency, or touch target. It does not change or remove any accessibility behavior from the web scaffold.
