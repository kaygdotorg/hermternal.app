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

The registry remains authoritative for readiness. A `pending` row is reported as
`blocked`; it is never promoted to a successful parity result. The report uses
semantic outcomes rather than platform-specific wire bytes, and it returns a
bounded JSON object suitable for CI logs.

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

`bun run parity` prints one JSON result. In the current checked-in registry it
reports 11 proven representative cases and blocked coverage for
`chat-stream-and-completion`, `connection-restoration`, and the other registry
pending rows. No network access is part of any command above.
