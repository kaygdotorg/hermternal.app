# Terminal renderer boundary

`renderer.ts` owns the browser-only Terminal boundary for W-22. It does not import Chat, PTY transport, session coordination, credentials, or live Hermes code.

## Runtime contract

- `createTerminalRenderer()` returns a small `TerminalRenderer` interface with `mount`, `write`, `resize`, `focus`, and `dispose`.
- `createWTermGhosttyAdapter()` is the production adapter. It lazy-loads `@wterm/dom`, `@wterm/ghostty`, the W-Term stylesheet, and the Ghostty WASM only when `mount()` is first called.
- Output stays as raw `Uint8Array` until W-Term/Ghostty receives it. Writes made while WASM loads are copied into a bounded operation queue and flushed in call order. The queue fails closed when its byte or operation bound is exceeded.
- Ghostty scrollback is bounded to 64 KiB by default and clamped to 1 MiB. The renderer does not keep a transcript mirror, decode output for logging, or expose terminal bytes to diagnostics.
- W-Term supplies native DOM selection and its keyboard copy path. The renderer does not call `navigator.clipboard` or replace browser copy behavior.
- Single-line paste without control characters follows W-Term's normal native paste handling. Multiline or control-character paste is intercepted in the capture phase and requires the supplied `confirmPaste` callback. Confirmation is denied when no callback is supplied. Accepted paste uses W-Term's bracketed-paste mode and strips escape bytes before sending.
- WASM, module, and adapter failures render one accessible `role="alert"` state with stable copy. Raw exception text is not shown or logged.
- `dispose()` is idempotent and safe during an in-flight lazy load. If the terminal was focused before a safe remount, focus is restored after the new W-Term instance is ready.

The adapter lazy-loads `terminal.css` with the W-Term stylesheet, so selecting Terminal does not add terminal CSS to the initial shell. It uses the shared `--font-mono` token when present and falls back to Geist Mono plus a system monospace stack for this isolated scaffold. The current W-01 shell does not yet define `--font-mono`; adding that global token belongs to the shared design-token work, not this renderer boundary.

## Accessibility boundary

The host is a labelled `region`; W-Term keeps native selection and a hidden input for keyboard focus. The renderer verifies keyboard focus, native selection, copy event pass-through, screen-reader labelling, 200% zoom-equivalent layout, forced colors, reduced motion, and reduced transparency in the local prototype. W-Term's hidden input is intentionally `aria-hidden`; screen readers receive the rendered terminal DOM, but live cursor announcements and semantic command history are not synthesized by this boundary. That limitation is recorded rather than masked.

## Tests and workload

`renderer.test.ts` uses an injected renderer adapter with deterministic synthetic terminal state. It proves lazy initialization, ordered raw-byte delivery (including split UTF-8, combining marks, wide graphemes, ANSI, cursor, and alternate-screen workload fixtures), resize, native selection/copy pass-through, paste confirmation, remount/dispose, controlled initialization failure, bounded pending output, and the absence of byte logging. No test starts Hermes or a PTY transport.

`../../tests/bench/terminal-renderer.bench.ts` is a local-only Playwright workload harness. Run it with `GIT_COMMIT=$(git rev-parse HEAD) bun run benchmark:terminal` to emit raw samples and p50/p95/p99 distributions for cold mount, first glyph, sustained output, resize, 1 MiB replay, and repeated mount/dispose. It also records the production client chunk and emitted Ghostty WASM sizes and SHA-256 values, main-thread long-task entries, and heap samples when Chromium exposes `performance.memory`. Measurements are evidence only; this issue records no unreviewed performance threshold. The benchmark workload is synthetic and never starts Hermes or PTY transport.
