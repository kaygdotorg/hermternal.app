# TypeScript contract parity

This directory owns the C-20 TypeScript parity checker. It consumes the checked-in
language-neutral registry at [`../fixtures/index.json`](../fixtures/index.json) and only reads
synthetic, redacted JSON fixtures. It never starts Hermes, opens a socket, calls
`fetch`, follows a URL, or makes a live compatibility claim.

## What is covered

The offline runner checks representative semantic outcomes for:

- browser cookie authentication, including a rejected CSRF callback;
- connection restoration and session persistence, while preserving the registry's
  pending gates;
- chat delivery uncertainty and automatic retry rejection as blocked evidence;
- empty, malformed, and accepted image attachment states;
- web-only PTY byte preservation and redaction, with Apple invocation blocked;
- valid and rejected private deep links; and
- matching and missing deployment attestation, plus the aggregate compatibility
  record's blocked status.

The registry remains authoritative for readiness. A `pending`, `empty`,
`failure`, `cancelled`, or `unknown` row is reported as `blocked`; it is never
promoted to a successful parity result. Pending roots must use `validator: null`
and `files: []`. A pending aggregate compatibility root returns bounded blocked
compatibility evidence without attempting to load an unregistered artifact. The
report uses semantic outcomes rather than platform-specific wire bytes, and it
returns a bounded JSON object suitable for CI logs. The CLI accepts only an
optional `--repo-root <path>` pair; unknown options, positional values, and
duplicate roots return bounded JSON errors instead of guessing.

Before representatives run, the checker validates the complete registry
inventory. Every ready root must have the exact sorted file manifest, every
registered digest and byte size must verify, and every non-metadata file under
`contracts/fixtures` must be indexed. An unindexed artifact blocks parity before
any representative can claim evidence.

## Input and output safety

Every artifact is opened descriptor-first with `O_NONBLOCK | O_NOFOLLOW`, then
checked as a regular file. The Bun reader walks every parent component from an
anchored directory descriptor with `openat` and `O_NOFOLLOW`; only the trusted
repository root is canonicalized, so a replaced fixture directory cannot redirect
the read through a symlink. Descriptor and pathname device/inode/size identities
are compared before and after the bounded read. Bytes are read synchronously from
the nonblocking descriptor under a fixed deadline, so there is no unresolved
`FileHandle.read` promise left behind when a read is rejected. The registry and
each registered artifact are capped at 256 KiB; the artifact must also match the
registry's exact `size_bytes` and lowercase SHA-256 digest before it is decoded or
semantically inspected. Symlinks, directories, special files, changed file
identities or sizes, stale manifests, and digest mismatches fail closed. The
Unix descriptor walk uses Bun's `bun:ffi` bindings for `openat`, `read`, and
`close`; if the native boundary is unavailable, the checker fails closed rather
than falling back to pathname-only reads.

The JSON reader is a bounded parser rather than `JSON.parse`. It rejects
duplicate object keys and enforces limits on depth, nodes, array items, object
keys, key length, and string length. Registry, artifact, case, expected-result,
and compatibility records use exact allowlisted key sets, so unknown or missing
fields do not become evidence. Report decisions and compatibility fields are
length-bounded. Contract error codes and messages are sanitized and bounded before
they reach stderr, including messages that contain nearly maximal registered paths.
The CLI therefore emits only small JSON errors on failure.

## TypeScript 7 and tool compatibility

The primary compiler is the pinned TypeScript 7 native alias:

```json
"@typescript/native": "npm:typescript@7.0.2"
```

`typecheck` and `compile` invoke `node_modules/@typescript/native/bin/tsc`
directly. Bun's own transpiler is used only to execute the test runner; it is not
the type-checking authority.

A measured compatibility probe on 2026-08-06 used Bun `1.3.14`, Svelte `5.56.8`,
and `svelte-check 4.7.4`:

- Bun installed and ran the TypeScript 7 native compiler successfully.
- The npm alias split with `@typescript/native` `7.0.2` and
  `typescript: npm:@typescript/typescript6@6.0.2` passed `svelte-check` with zero
  errors when installed by npm. `svelte-check` is the compatibility consumer
  because it imports the legacy compiler API.
- Bun's current alias/linker behavior resolved the TypeScript 6 compatibility
  package's `@typescript/old` dependency to a wrapper with no legacy `sys` API;
  `svelte-check` then failed before checking a file with
  `TypeError: ... sys.useCaseSensitiveFileNames`. This is an isolated Bun/Svelte
  compatibility blocker, not a reason to replace the TypeScript 7 primary
  compiler. The parity package therefore does not import `svelte-check` or add a
  TypeScript 6 fallback. A future Svelte app must keep this consumer in an
  explicitly isolated compatibility lane until the Bun resolver issue is fixed.

## Commands

Run from this directory or use `bun run --cwd contracts/typescript-parity`:

```sh
bun install
bun run typecheck
bun run test
bun run compile
bun run parity
```

`bun run parity` prints one JSON result when the registry inventory is complete.
The current worktree intentionally fails closed with bounded
`fixture_inventory_invalid` output because the unchanged aggregate registry has
unindexed `deployment-security/external-allowlist` artifacts. The test suite
also runs the same CLI against a complete temporary registry tree and proves 11
ready representative cases, blocked coverage, and zero network calls. No
network access is part of any command above.
