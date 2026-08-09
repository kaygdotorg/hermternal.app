# Swift contract parity

This package owns the C-21 Swift parity gate for the supported `dashboard-v0.0.1`
surface. It reads the checked-in language-neutral registry and the selected,
synthetic JSON fixture artifacts directly from `contracts/fixtures/`.

The package is an offline proof tool. It never starts Hermes, sends a URL request,
opens a socket, imports a transport or authentication framework, reads Keychain
material, performs OAuth, signs an artifact, renders Apple UI, or loads Terminal
fixtures. It makes no live compatibility claim.

## Covered representative outcomes

The runner mirrors the C-20 representative semantic projection for:

- browser cookie authentication and a rejected CSRF callback;
- connection restoration and session persistence, while keeping pending coverage
  blocked;
- chat delivery uncertainty and automatic prompt retry rejection;
- empty, malformed, and accepted image attachment states;
- web-only PTY byte preservation and redaction, with Apple invocation blocked;
- valid and rejected private deep links; and
- matching and missing deployment attestation, plus the blocked aggregate
  compatibility record.

The result compares semantic `expected` outcomes, not platform-specific wire
bytes. The registry's `pending` rows become `blocked` results and can never be
promoted to proof. Unknown fixture roots, case selectors, platform values,
statuses, unsafe paths, and unregistered representative artifacts fail closed.

## Commands

Run from this directory:

```sh
swift test
swift run hermternal-swift-parity --repo-root ../..
```

The CLI emits one bounded JSON line. The current registry produces 11 proven
representative cases and blocked results for pending connection and chat
coverage. `networkCalls` is always zero and `liveClaim` is always false.

## Exact limitations

- This is a parity reader, not a runtime client and not an Apple application.
- It implements the reviewed representative projection only. It does not infer
  schemas for arbitrary JSON-RPC bodies or events that the Dashboard manifest
  intentionally leaves source-defined.
- It selects only the approved JSON artifacts used by the parity contract. It
  does not scan every registered artifact or treat an unindexed artifact as
  eligible evidence.
- The C-19 aggregate validator remains authoritative for duplicate-key checks,
  full registry schema validation, artifact digests, redaction scanning, and
  the complete unindexed-artifact inventory. This package independently checks
  its selected paths before decoding them but does not replace that validator.
- PTY is represented only by synthetic web evidence. Apple Terminal remains
  blocked by contract and no PTY bytes are read from a live process.
- A passing report proves synthetic fixture parity only. It does not attest a
  deployment, pass a behavioral probe, authorize authentication, or establish
  Hermes compatibility.

No files under `contracts/fixtures/validator/` are required or changed by this
package.
