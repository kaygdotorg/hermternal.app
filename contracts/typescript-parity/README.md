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
and `files: []`. Fixture-to-coverage linkage is canonical and bidirectional; the
aggregate compatibility root must own the `compatibility-gate` row, so a pending
gate cannot be bypassed by relinking it to unrelated coverage. A pending aggregate
root returns bounded blocked compatibility evidence without attempting to load an
unregistered artifact. Before TypeScript projects a ready fixture, it executes that
root's checked-in Python validator against the same verified bytes. This preserves
canonical nested types, ranges, text bounds, ordered fields and cases, and
recomputed reducer outcomes instead of approximating them with key-set checks. The
report uses semantic outcomes rather than platform-specific wire bytes. Its exact
emitted UTF-8 line, including the final newline, is capped at 8 KiB for CI logs.
The CLI accepts only an optional `--repo-root <path>` pair; unknown options,
positional values, and duplicate roots return bounded JSON errors instead of
guessing.

Before representatives run, the checker validates the complete registry
inventory. Every ready root must have the exact sorted file manifest, every
registered digest and byte size must verify, and every non-metadata file under
`contracts/fixtures` must be indexed. An unindexed artifact blocks parity before
any representative can claim evidence. Before returning success, the checker also
verifies the pinned `schema.json` and aggregate
`validator/validation-baseline.json`. It checks the baseline's artifact manifest,
commands, sample counts, and recomputed distributions, so these aggregate records
cannot be skipped or silently replaced. Temporary tests that intentionally mutate
registry bytes therefore remain useful for focused loaders, but a complete parity
report correctly rejects those bytes unless the reviewed aggregate baseline also
attests them.

## Input and output safety

Every artifact is opened descriptor-first with `O_NONBLOCK | O_NOFOLLOW`, then
checked as a regular file. The Bun reader walks every parent component from an
anchored directory descriptor with `openat` and `O_NOFOLLOW`; only the trusted
repository root is canonicalized, so a replaced fixture directory cannot redirect
the read through a symlink. Inventory enumeration also stays descriptor-rooted: it
uses duplicated directory descriptors with `fdopendir`/`readdir`, opens every child
with relative `openat`, and enforces 32-level, 512-directory, and 512-file budgets.
A tiny native wrapper clears `errno`, calls `readdir`, and captures the resulting
`errno` in the same native call. `NULL` with a nonzero error is therefore rejected
as an incomplete inventory instead of being mistaken for EOF, including after a
valid prefix has already been enumerated. All directory streams, duplicated
handles, and native descriptors have checked cleanup paths. Descriptor and pathname
device/inode/size identities are compared
before and after each bounded artifact read. Bytes are read by a killable
subprocess that inherits only the already-secured nonblocking descriptor. Its
one-second wall-clock deadline can interrupt a blocked
kernel read, and the parent awaits process exit before closing its own descriptor,
so no unresolved read or inherited descriptor survives a rejection. The
registry and each registered artifact are capped at 256 KiB; the focused
compatibility record uses its canonical 128 KiB, 4,096-node, and UTF-8 string
budgets. Every artifact must also match the registry's exact integer-token
`size_bytes` and lowercase SHA-256 digest before it is decoded or semantically
inspected. Symlinks, directories, special files, changed identities or sizes,
stale manifests, and digest mismatches fail closed. The Unix descriptor boundary
uses Bun's `bun:ffi` bindings and platform-specific `AT_FDCWD` values (`-2` on
Darwin and `-100` on Linux); unsupported native boundaries fail closed rather than
falling back to pathname-only reads.

The JSON reader is a bounded parser rather than `JSON.parse`. It rejects
duplicate object keys and enforces limits on depth, nodes, array items, object
keys, key length, and string length. Registry identifiers and paths use the
canonical ASCII languages and lengths, registry numeric fields require lexical
integer tokens, and state, evidence-status, redaction, parity, and benchmark
metadata are retained and semantically checked. Compatibility integer fields also
require lexical JSON integers, so values such as PR number `221.0` are rejected
rather than normalized to `221`. The compatibility record pins its canonical
source and revision snapshots, merged PR sequence, artifact paths and manifest
digest, benchmark commands and recomputed distributions, status, redaction, and
blocker contracts before any evidence is projected. The checker reads every pinned
artifact directly from the reviewed merged and integration Git revisions. When it
runs against this repository, it also checks current `HEAD`, matching the normal
and `-O` Python validator's captured-snapshot decision. Report decisions and
compatibility fields are bounded. Contract error codes and messages normalize
controls and lone surrogates, then enforce their limit against serialized UTF-8
bytes rather than UTF-16 units. The CLI therefore emits one small JSON line on
failure and rejects an oversized complete success report before writing stdout.

Public runtime values are inert snapshots. Registry roots are module-authorized,
deep-cloned, and recursively frozen before use; fabricated, copied, proxy-backed,
hidden, symbol-keyed, or accessor-bearing caller values cannot become registry
authority. Cases return separate frozen `raw` and `expected` graphs, representative
IDs return a fresh frozen graph on every call, report and compatibility values are
frozen, and the exported platform list is frozen at runtime. Mutating a returned
registry digest therefore cannot authorize replacement fixture bytes.

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
