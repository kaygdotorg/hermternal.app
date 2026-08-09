# Privacy audit

## Status and scope

This is the R-07B / issue #193 static privacy audit. It is one documentation-only change on the isolated branch `issue/193-privacy-audit`, based on the exact current `origin/dev` commit `c59b5bcdaa1978d6e5c77cccaa31770ce0a82723`.

The audit reviews the browser and native storage boundaries, authentication and provider state, WebSocket tickets, session and transcript ownership, private URLs and deep links, service-worker routing, screenshots and other live-proof artifacts, and the disposable proof cleanup model. The pinned Hermes compatibility boundary is revision `f5be9236e00ddf2f2a412697f267078fc4ee068e` with dashboard contract `dashboard-v0.0.1`.

The repository is still in the planning and prototype phase. This document records static source, policy, and synthetic fixture evidence. It is not production security configuration, a deployment approval, or live compatibility proof. All fixture data used by the reviewed controls must remain synthetic or redacted.

This audit did not:

- start Hermes or a proxy;
- run credential-bearing live Playwright;
- inspect a credential file, password, cookie, token, ticket, transcript, or user data;
- access `~/.hermes` or use a filesystem fallback;
- claim that dynamic, deployment, browser, native, or live Hermes proof passed;
- change active live, recovery, screenshot, Paper, fixture, proxy, or shared-index files.

## Evidence classification

### Verified static controls

The following claims are supported by reviewed source, planning specifications, or offline synthetic fixtures:

- browser authentication uses server-issued protected `HttpOnly` cookies and same-origin requests;
- passwords and other reusable credentials are not designed for browser-readable storage;
- the browser does not maintain a local transcript mirror;
- WebSocket tickets are short-lived and restricted to an ephemeral upgrade handoff;
- provider discovery is same-origin, bounded, and fail closed;
- private deep-link parsing is strict and does not create a sharing or filesystem capability;
- live artifact handling has a separate credential-bearing policy with media capture disabled;
- native storage is separated from browser storage and uses an isolated cookie store or Keychain Services according to the credential type;
- the reviewed fixture validators and Python regression suites pass for the synthetic cases listed in [Evidence commands](#evidence-commands).

### Not proven by this audit

Static controls and synthetic fixtures do not prove live Hermes behavior, deployment identity, proxy parity, private-bind or firewall behavior, cookie attributes observed through a real Dashboard response, provider behavior, native callback behavior on a target Apple platform, ticket handling at a real edge, or safe handling of live user data. Missing or mismatched deployment attestation and failed behavioral evidence remain release blockers.

The current tree also does not contain the historical browser storage proof files `apps/web/tests/e2e/auth-proof.ts` and `apps/web/tests/e2e/auth-proof.spec.ts`. Their absence is material to the HMAC evidence gap below.

## Verified browser controls

### Protected cookies and transient password handling

The browser authentication implementation in [`browser-auth.ts`](../../apps/web/src/lib/auth-ui/browser-auth.ts) and [`browser-auth-session.ts`](../../apps/web/src/lib/auth-ui/browser-auth-session.ts) uses the Dashboard's same-origin provider flow. Browser requests use `credentials: 'same-origin'`; browser JavaScript does not read, copy, serialize, or export the protected cookie. A server-managed refresh value may remain inside that `HttpOnly` cookie, but it must not cross into JavaScript or a retained artifact.

The browser must not put a password, reusable credential, access token, refresh token, WebSocket ticket, provider state, callback material, or transcript in:

- `localStorage`;
- `sessionStorage`;
- IndexedDB;
- a navigable URL or fragment;
- browser history;
- diagnostics, fixtures, reports, or source control.

The password exists only at the transient form/request boundary. The auth preview clears password DOM values synchronously before submission callbacks. Successful password login has an identity barrier: the client must follow the login response with `/api/auth/me` before exposing authenticated content. Logout requires the reviewed `302 Location: /login` response and a follow-up unauthenticated identity check. Fixed semantic errors do not echo response bodies or credential material.

The reviewed browser auth and provider policies are [`authentication.md`](authentication.md), [`browser-auth.ts`](../../apps/web/src/lib/auth-ui/browser-auth.ts), [`browser-auth-session.ts`](../../apps/web/src/lib/auth-ui/browser-auth-session.ts), [`provider-discovery.ts`](../../apps/web/src/lib/auth-ui/provider-discovery.ts), and [`AuthPreview.svelte`](../../apps/web/src/lib/auth-ui/AuthPreview.svelte).

### Provider-state isolation

[`provider-discovery.ts`](../../apps/web/src/lib/auth-ui/provider-discovery.ts) fetches only from the configured same-origin Dashboard path with `credentials: 'same-origin'`, `cache: 'no-store'`, and `redirect: 'error'`. Its bounded parser rejects malformed, duplicate, oversized, unknown, unsafe, or incompatible provider data. `supports_password: false` is an unavailable capability, not permission to invent an OAuth or password route. Discovery data cannot redirect the client to an arbitrary origin.

Pending provider or callback state is scoped to the current server connection and is cleared on success, cancellation, failure, or logout. A provider or callback that is unknown, malformed, unsupported, or not covered by the compatibility record fails closed.

## No local transcript mirror

Hermes remains the source of truth for session history and messages. The browser transport and session coordinator retain only bounded opaque identifiers, lifecycle state, counters, owner markers, and active promise state. They do not retain prompt text, response text, credentials, cookies, WebSocket tickets, provider payloads, raw URLs, deep-link state, or an event-history copy.

Session restoration re-reads server-owned history. The client does not automatically replay a prompt after uncertain delivery. The session coordinator holds only one bounded opaque active session identity in memory. The application has no application-level transcript mirror or diagnostic byte store; renderer-local Ghostty scrollback is bounded to 64 KiB by default and clamped to a 1 MiB maximum. This boundary is documented in [`json-rpc-chat.md`](../../apps/web/src/lib/chat/json-rpc-chat.md), [`apps/web/src/lib/session/README.md`](../../apps/web/src/lib/session/README.md), and [`terminal/README.md`](../../apps/web/src/lib/terminal/README.md).

## Ephemeral WebSocket tickets

The browser ticket adapter in [`ws-ticket.ts`](../../apps/web/src/lib/chat/ws-ticket.ts) uses `/api/auth/ws-ticket` and requires the exact response shape `{ ticket, ttl_seconds: 30 }`. Each gated `/api/ws` or web-only `/api/pty` attempt obtains a fresh, single-use ticket. The ticket lifetime is exactly 30 seconds.

The ticket is placed only in an in-memory, same-origin upgrade URL such as `?ticket=<opaque-value>` for the WebSocket handoff. It is not a session credential and is not session-bound. It must not become application state, storage, DOM, page history, a bookmark, a log field, a fixture, a report, an error, a diagnostic, or user-visible text. Reconnect obtains a new ticket. Cancellation and late connector results are cleaned up with bounded, idempotent ownership.

REST calls use the protected provider cookie or an approved native bearer credential; they never use a WebSocket ticket. Deployment proof must remove the full ticket, upgrade URL, and any bounded invalid-ticket audit fragment before logs are retained. Missing, malformed, expired, or reused tickets must fail closed. Static fixture success does not prove these properties at a live edge.

## Private deep links and filesystem boundaries

The reviewed private web grammar is:

```text
https://<configured-origin>/v1/c/<full-session-id>
https://<configured-origin>/v1/c/<full-session-id>/m/<full-message-id>
```

The reviewed native grammar is:

```text
hermternal://open/v1/c/<full-session-id>
hermternal://open/v1/c/<full-session-id>/m/<full-message-id>
```

IDs are full opaque values with a 16-character minimum and ASCII URI-unreserved characters. The parser rejects altered origins, user information, queries, fragments, controls, non-ASCII values, percent escapes, backslashes, traversal, encoded separators, duplicate separators, trailing slashes, malformed targets, and abbreviated IDs. Raw links and IDs must not appear in logs, analytics, crash reports, notifications, clipboard history, OAuth return URLs, or user-facing errors.

A pending raw target may exist in process memory for no more than 300 seconds. It is erased after success, failure, cancellation, expiry, or logout. A deep link cannot create a session, act as a bearer credential, access the filesystem, read `~/.hermes`, create a sharing route, follow an external redirect, or create a transcript mirror. The policy and implementation are [`deep-links.md`](../architecture/deep-links.md) and [`static-route-grammar.mjs`](../../apps/web/src/lib/static-route-grammar.mjs).

The service worker and static route boundary also deny reserved API, authentication, WebSocket, PTY, unknown, and foreign-cache requests. Only same-origin exact-GET requests without query or hash are eligible for Hermternal-owned static interception. Only Hermternal-owned cache names may be deleted.

## Screenshots, traces, videos, and live cleanup

The credential-bearing live configuration is explicit opt-in and sets:

```ts
trace: 'off',
video: 'off',
screenshot: 'off',
preserveOutput: 'never'
```

It creates one unique OS-temporary run root with mode `0700`, an owner marker, and a random ownership token. Playwright output is a disposable child of that root. The safe reporter emits only redacted test titles and statuses. `PW_RUNNER_DEBUG` is rejected because it would bypass the IPC redaction boundary. The live IPC guard is preloaded before worker fixtures or test bodies and redacts worker IPC, errors, steps, attachments, stdio, environment fields, and response messages.

The guard structurally scrubs editable DOM values, serialized form markup, native errors, matcher results, logs, ARIA snapshots, and attachment bodies. Binary fields are bounded-decoded and replaced when they contain a captured credential encoding or a non-empty credential prefix. Malformed, oversized, unknown, trapped, cyclic, or over-budget values fail closed. Scrub failure is suppressed only when `page.isClosed()` is explicitly true; a generic `page crashed` message is not proof that sensitive state is gone.

Per-test cleanup validates every ancestor, rejects symlink replacement, and quarantines only strict descendants of the owned root. It never blindly recursively deletes an unknown or raced path. Global teardown owns complete-root removal through atomic quarantine and bounded non-recursive cleanup, rechecking device/inode identity and the owner marker. The shared root and owner marker are preserved until global teardown. Playwright's post-teardown `LastRunReporter` is redirected to `/dev/null` so it cannot recreate a markerless output directory.

The standard synthetic Playwright configuration is a separate no-network lane and may retain traces on failure. Checked-in visual snapshots from `live-workspace-visual.spec.ts` use synthetic fixtures and are not credential-bearing live evidence. A screenshot snapshot is therefore not evidence that a live credential or live transcript was handled safely.

The relevant policy files are [`live-artifact-policy.mjs`](../../apps/web/tests/live/live-artifact-policy.mjs), [`live-artifact-teardown.mjs`](../../apps/web/tests/live/live-artifact-teardown.mjs), [`live-ipc-guard.cjs`](../../apps/web/tests/live/live-ipc-guard.cjs), [`safe-reporter.mjs`](../../apps/web/tests/live/safe-reporter.mjs), and [`playwright.live.config.ts`](../../apps/web/playwright.live.config.ts).

## Native storage separation

[`apps/apple/README.md`](../../apps/apple/README.md) confirms that the Apple clients are planning and mock work only. There is no Xcode project, Swift package, signing setup, native runtime, native credential, or live Hermes call in the current tree.

The future native password-provider path uses an app-isolated protected `URLSession` cookie store. Browser cookies must never be shared with native code. Native passwords are transient and must not be persisted. A supported native OAuth/OIDC path keeps source-issued bearer access and refresh material in Keychain Services; it must not copy that material into cookies, URLs, links, fixtures, logs, or reports. Native clients do not maintain a local transcript mirror and must not invoke the web-only `/api/pty` route.

Native OAuth/OIDC remains blocked until both the pinned Hermes source accepts the callback transport and the target Apple platform has matching system authentication-session proof. An unsupported or unproven callback cannot be replaced by an embedded login, token interception, copied browser cookie, hidden relay, or provider-specific fallback.

## HMAC-only proof evidence

A retained privacy proof must emit only keyed, non-reversible HMAC evidence. The HMAC key must remain inside the proof process and must never be retained in a report, fixture, log, screenshot, trace, video, source file, or artifact. Raw cookies, credentials, tickets, storage values, and reversible hashes are not acceptable evidence.

This control is **unresolved on the exact audited `origin/dev`**. The current tree does not contain the historical browser storage proof files `apps/web/tests/e2e/auth-proof.ts` and `apps/web/tests/e2e/auth-proof.spec.ts`. A current repository search finds `HMAC` only in the synthetic session-search cursor implementation at [`contracts/fixtures/session-search/validate.py`](../../contracts/fixtures/session-search/validate.py). Current compatibility and behavioral artifacts primarily use unkeyed SHA-256 integrity digests, and the attestation documentation explicitly identifies some baseline evidence as not independently authenticated. Those digests are not a substitute for HMAC-only privacy evidence.

Until a current-origin proof adds keyed, non-reversible storage evidence with a proof-process-only key, the browser storage privacy gate is not complete.

## Retention and ownership boundaries

| Data or artifact | Allowed retention | Cleanup or expiry owner | Boundary |
| --- | --- | --- | --- |
| Browser session cookie | Browser protected cookie mechanism and the server-owned session | Browser and Dashboard | JavaScript never reads or copies it; its server-managed refresh material remains inside the protected cookie. |
| Browser password | Transient form/request boundary only | Auth form and request lifecycle | DOM values are cleared before callbacks; never persisted or logged. |
| Native password-provider cookie | App-isolated native `URLSession` cookie store | Native session/logout lifecycle | Never shared with the browser cookie store or copied into Keychain, URLs, logs, or fixtures. |
| Native OAuth/OIDC bearer and refresh material | Approved Keychain Services items only | Native authentication and account-removal lifecycle | Only source-approved native flows may create it; unsupported callback paths remain blocked. |
| WebSocket ticket | Adapter memory during one upgrade handoff; server TTL exactly 30 seconds | Dashboard ticket issuer and browser/native adapter | Fresh, single-use, ephemeral URL only; no application-state, storage, history, log, or report retention. |
| Session and transcript | Hermes-owned durable state | Hermes | Client retains bounded opaque IDs and view/lifecycle state only; no local transcript mirror. |
| Private deep-link target | Process memory for at most 300 seconds | Deep-link resolver | Erased on success, failure, cancellation, expiry, or logout; never a bearer, sharing route, or filesystem path. |
| Live credential | Launcher-owned credential file, then transient child environment `HERMES_TEST_PASSWORD` | Launcher teardown and child process | The wrapper validates and injects the value without printing or writing it. The wrapper does not delete the credential file; launcher cleanup ownership must be proven separately. |
| Live screenshots, traces, videos, reports, and test output | Disabled for the credential-bearing lane; synthetic artifacts remain in their own disposable lane | Safe reporter and live teardown | Unknown or raced replacements are retained rather than blindly deleted. |
| HMAC key | Proof-process memory only | Proof process | Never retained in evidence or source control. |

## Evidence commands

All commands below use synthetic, redacted, or repository-local static data. No command in this audit starts Hermes or reads a credential.

### Graph and policy checks

| Command | Result |
| --- | --- |
| `code-review-graph build` | Exit 0 before review; local graph built on `issue/193-privacy-audit` with 5,779 nodes, 84,855 edges, and 227 indexed files. Cloud embeddings were not enabled. |
| `python3 scripts/validate_proof_gates.py` | Exit 0; `{"errors": [], "ok": true}`. |

### Offline privacy and compatibility fixtures

| Command | Result |
| --- | --- |
| `python3 contracts/fixtures/deployment-security/browser-auth/validate.py` | Exit 0; 21 cases, `ok: true`. |
| `python3 contracts/fixtures/deployment-security/ws-ticket/validate.py` | Exit 0; 24 cases, 5 states, `ok: true`, `live_run: false`, `compatible: false`. The fixture is valid synthetic evidence, not live compatibility proof. |
| `python3 contracts/fixtures/deep-link-grammar/validate.py` | Exit 0; 31 cases and 15 mutation checks passed. |
| `python3 contracts/fixtures/deep-link-resolution/validate.py` | Exit 0; 26 cases and 20 mutation checks passed. |
| `python3 contracts/fixtures/session-search/validate.py` | Exit 0; 48 cases and 155195 synthetic artifacts validated. |
| `python3 contracts/fixtures/behavioral-probe/validate.py` | Exit 0; 64 cases, `ok: true`, `live_run: false`, `compatible: false`. This is offline fixture behavior only. |
| `python3 contracts/fixtures/compatibility-attestation/validate.py --worktree` | Exit 1; `attestation.proxy_proof.sha256 does not match immutable evidence`. The attestation is not verified and cannot authorize live operation. |
| `python3 apps/web/src/lib/compatibility/probe/validate_evaluator_benchmark.py` | Exit 2; `{"error":"invalid evaluator benchmark evidence"}`. |

### Python regression suites

| Command | Result |
| --- | --- |
| `python3 -m unittest discover -s contracts/fixtures/deployment-security/browser-auth -p 'test_*.py'` | Exit 0; 27 tests passed. |
| `python3 -m unittest discover -s contracts/fixtures/deployment-security/ws-ticket -p 'test_*.py'` | Exit 0; 28 tests passed. |
| `python3 -m unittest discover -s contracts/fixtures/deep-link-grammar -p 'test_*.py'` | Exit 0; 21 tests passed. |
| `python3 -m unittest discover -s contracts/fixtures/deep-link-resolution -p 'test_*.py'` | Exit 0; 22 tests passed. |
| `python3 -m unittest discover -s contracts/fixtures/session-search -p 'test_*.py'` | Exit 0; 18 tests passed. |

### Checks not available in this checkout

The attempted web Vitest, Svelte check, and Vite build commands could not start because the `apps/web` package binaries were not installed in this checkout (`vitest`, `svelte-check`, and `vite` were not found). The direct static-route assertion was also not treated as evidence: `node apps/web/tests/static/assert-static-routes.mjs` exited 1 because no built shell was available and `/` returned 404. No live or credential-bearing test was substituted for these unavailable local checks.

## Unresolved gaps and release blockers

This audit remains **not releasable**. The following are hard blockers for v0.0.1 privacy or live-operation approval:

1. **Missing HMAC-only browser storage evidence.** Current `origin/dev` does not contain the required current-origin HMAC proof. Unkeyed SHA-256 integrity digests and historical files do not satisfy this gate.
2. **Compatibility attestation mismatch.** `contracts/fixtures/compatibility-attestation/validate.py --worktree` fails because the recorded proxy-proof digest does not match immutable evidence. Missing or mismatched attestation must block live operation.
3. **Invalid evaluator benchmark evidence.** The evaluator benchmark validator exits 2. No performance or compatibility conclusion may be based on it.
4. **Deployment cookie attributes are not proven.** The local Caddy fixture emits no `Set-Cookie`; `HttpOnly`, `SameSite`, and `Path` remain explicitly unproven. A real reviewed Dashboard response must prove the exact cookie name or prefix and `Secure`, `HttpOnly`, `SameSite`, `Domain`, and `Path` behavior for both supported proxy choices.
5. **Live edge and Hermes behavior are unproven here.** Private bind, firewall, public-origin checks, proxy parity, ticket redaction, live auth, REST/session behavior, WebSocket lifecycle, and user-data handling require an authorized synthetic or redacted proof after the required attestation and behavioral gates pass. This audit did not run that proof.
6. **Native runtime and platform proof are absent.** The Apple tree contains planning documentation only. Native OAuth/OIDC remains blocked without source callback acceptance and target-platform proof; native password storage must remain isolated when implemented.
7. **Issue blockers remain active.** DEP-12 / issue #100, R-02 / issue #185, R-03 / issue #186, and R-04 / issue #187 remain release blockers named by issue #193. This document does not waive them.

The static controls in this document are necessary boundaries, not an authorization to add production authentication, credentials, deployment configuration, live integrations, or live user data. A future proof must fail closed when evidence is missing, stale, mismatched, unauthenticated, or contains a secret or transcript value.

## References

- [Security model](README.md)
- [Authentication specification](authentication.md)
- [Deep-link architecture](../architecture/deep-links.md)
- [Deployment topology](../deployment/README.md)
- [Deployment proof matrix](../deployment/proof-matrix.md)
- [Apple client boundary](../../apps/apple/README.md)
- [Live-proof policy](../../apps/web/tests/live/README.md)
- [Session ownership](../../apps/web/src/lib/session/README.md)
- [JSON-RPC transcript boundary](../../apps/web/src/lib/chat/json-rpc-chat.md)
- [WebSocket ticket boundary](../../apps/web/src/lib/chat/ws-ticket.md)
- [Static route grammar](../../apps/web/src/lib/static-route-grammar.mjs)
- [Compatibility attestation fixture](../../contracts/fixtures/compatibility-attestation/README.md)
- [Behavioral probe fixture](../../contracts/fixtures/behavioral-probe/README.md)
