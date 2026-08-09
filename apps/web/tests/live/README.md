# Official Hermes browser proof

## Deterministic screenshot capture

The live lane keeps Playwright's automatic screenshots, traces, videos, failure
output, HTML context, DOM snapshots, and unsafe reporters disabled for every
credential-bearing run. The only screenshot path is an explicit opt-in after
the stable Chat assertion in `official-hermes.spec.ts`:

```sh
HERMTERNAL_LIVE_SCREENSHOT_CAPTURE=1 \
HERMTERNAL_PAPER_PARITY_APPROVED=1 \
HERMTERNAL_LIVE_SCREENSHOT_CLIENT_SHA="$GITHUB_SHA" \
  bun run --cwd apps/web test:e2e:live
```

The capture helper rejects missing or short client SHAs, non-root routes, any
viewport other than `1440x960`, non-Chromium browser provenance, non-`en-US`
locale, non-1 DPR or zoom, unexpected theme or reduced-motion inputs, and UI
states outside the bounded `empty`/`ready` set. Ordinary Vitest remains
independent of the browser cache and Python child: only genuinely browser-
dependent tests are skipped, and filesystem publication tests inject the
controlled pinned provenance seam. Real-Chromium DOM/storage scrub tests first
navigate to an approved local HTTP origin before setting page content or
accessing origin-scoped browser state. The browser-dependent lane is explicit and
requires `HERMTERNAL_LIVE_SCREENSHOT_BROWSER_PREREQUISITE=1`; it is never
enabled by ordinary test commands. The opt-in live project forces headless mode
and resolves the regular Playwright Chromium executable from the exact
`playwright@1.62.1`, `@playwright/test@1.62.1`, and `playwright-core@1.62.1`
package and lockfile pins; the helper then proves the running browser is exactly
Chromium revision `1234`, browser version `151.0.7922.34`, the regular
executable path, and its SHA-256 before `emulateMedia`, DOM evaluation, or
capture. `PW_RUNNER_DEBUG` and `PWDEBUG` are rejected before workers start.

The official spec snapshots the ledger, runs the complete
`matchLiveProofLedger` assertion, and only then calls the capture helper. The
helper requires that fixed-shape assertion result, rather than independent
stable-state booleans; an incomplete official-Hermes chain fails before
retention preflight, page mutation, capture, or publication.

The credential-bearing worker uses a dynamic Playwright annotation channel with
only the fixed semantic phases `not-started`, `authenticated`,
`ready-no-submit`, `submitted`, `completed`, `history-reconciled`, `reconciled`,
and `uncertain`, plus delivery states `not-submitted`, `submitted`, `completed`,
`reconciled`, and `uncertain`. The phase is `ready-no-submit` immediately before
prompt submission, then `submitted` after the click, and advances only after the
completion and history assertions. The safe reporter emits this two-field
projection only for a failed test. Unknown, duplicate, extra, or free-form
status annotations are rejected and never reach reporter output; IDs, bodies,
URLs, errors, DOM, credentials, and other diagnostics are not a reporter
channel.

All live proof assertions finish before the capture-only page transform. The
transform replaces the live conversation timeline, session labels, conversation
title, provider/model metadata (`.header-model`), session counts
(`.group-count`), every duplicated desktop/mobile metadata node, composer model
controls/options, and composer values with bounded semantic placeholders. It
scrubs relevant `data-*`, `aria-*`, `title`, `value`, and both storage areas,
then checks metadata projections and serialized DOM for residual source values,
including one-character values. The sanitized source is cloned into an inert,
pointer-transparent, opaque fixed `1440x960` capture host; only the detached
capture locator is screenshotted, so later Svelte or WebSocket updates to the
mounted live tree cannot alter the PNG. It records only the fixed-key manifest,
the official Hermes image digest and source attestation, the exact safe test
command, and the SHA-256 of the returned PNG. It never attaches or writes
prompt text, transcripts, provider payloads, tickets, cookies, credentials,
WebSocket frames, PTY bytes, stdout/stderr, traces, or test results.

The live proof uses a bounded typed in-memory ledger. It retains only assertion-
local method, route, event, request/session identity, status, boolean-match,
and bounded-count projections. It requires login/auth/ticket/upgrade, one
server-first `gateway.ready`, session create/resume identity, exactly one prompt
and acknowledgement, correlated delta/completion, and a `200` REST history
response whose canonical `session_id` and exact user/assistant pair match. It
rejects duplicate sockets/events, wrong routes, missing ticket-only state,
request-ID-free completions, reordered events, status mismatches, and missing
canonical history identity. Logout is a separate same-context `302`/`401`
check followed by cookie, IndexedDB, Cache Storage, service-worker cache, and
Web Storage absence verification.

The default capture result stays in memory and is removed with the test
process. Repository retention is a separate manual gate:

```sh
HERMTERNAL_LIVE_SCREENSHOT_CAPTURE=1 \
HERMTERNAL_PAPER_PARITY_APPROVED=1 \
HERMTERNAL_LIVE_SCREENSHOT_CLIENT_SHA="$GITHUB_SHA" \
HERMTERNAL_LIVE_SCREENSHOT_RETAIN=1 \
HERMTERNAL_LIVE_SCREENSHOT_REVIEW=independent-approved \
HERMTERNAL_LIVE_SCREENSHOT_DESTINATION="$PWD/tests/integration/hermes-chat" \
  bun run --cwd apps/web test:e2e:live
```

Retention review and destination existence, directory type, symlink, canonical,
and device/inode checks happen before any page mutation or screenshot. The
retention directory must already exist and contain no symlinked ancestor. The
same destination identity is checked again after capture and immediately around
publication to close the capture-to-publish TOCTOU window.

The complete PNG and manifest are first written to a private 0700 staging
bundle below a trusted private staging parent. The parent system-root and
parent device/inode are captured before creation and revalidated through source
checks, publication, and cleanup. After destination and ancestor identity
checks, one exclusive atomic directory rename publishes
`hermternal-chat-proof.bundle/`, containing only `screenshot.png` and
`manifest.json`. No PNG or manifest is opened through its final public pathname,
and a replacement destination receives zero bundle bytes. Existing bundles are
never overwritten. The atomic child uses a fixed absolute trusted Python
executable, `-I -S`, and a minimal credential-free environment; macOS SDK
variables added by the system interpreter are not credential or path inputs.
Failed staging cleanup checks the original directory and file device/inode/size,
unlinks only known regular files, and uses non-recursive `rmdir`; source swaps,
parent swaps, replacement pathnames, quarantine remnants, and cleanup failures
are preserved and surfaced rather than followed or silently discarded. An
independent reviewer must inspect the PNG bytes and manifest together before
the bundle is copied into the repository. This is a tooling contract only:
deterministic unit tests use synthetic page metadata, controlled browser
provenance, and PNG bytes, while the opt-in Playwright lane is the only path
that can observe the real Hermes Chat state. No live Hermes run or retainable
live screenshot was performed for this change; credentials and VM access are
not required for the regression suite.

### Read-only reconciliation mode

A separate opt-in `reconcile-live-proof.spec.ts` resolves uncertain delivery without
submitting a prompt. Run it only with `HERMTERNAL_LIVE_RECONCILIATION=1` in the
authorized disposable lane; any other present value is rejected before Playwright
starts. The real `playwright.live.config.ts` then sets an exact `testMatch` for this
no-submit spec and ignores the official, shared, and capture prompt lanes. The
official spec also defensively skips itself whenever the exact reconciliation opt-in
is present. The selected lane performs a fresh password login, then reads one
bounded authoritative `/api/sessions?limit=100&offset=0` page and complete
`/messages?limit=500&offset=0` histories in memory. It never creates or resumes a
fallback session, selects a most-recent session, acquires a ticket, opens a
WebSocket, or sends a prompt; its live-proof ledger prompt count remains zero. A
list or history whose cap, identity, response shape, or pagination cannot prove
completeness fails closed.

The reconciler compares only the fixed proof prompt and assistant marker. It
prints one fixed line with `promptMatches=zero|one|multiple`,
`completedPairs=zero|one|multiple`, and exactly one of
`no-match-uncertain|delivery-observed|completion-observed|ambiguous`. Zero history
matches are still `no-match-uncertain`; a 200 response without a match is not
absence, and a 401, redirect, or read failure is never treated as absence.
Multiple matching prompts, pairs, or sessions are `ambiguous`. It preserves
`promptCount===0` and never prints IDs, timestamps, bodies, prompt/response text,
endpoints, headers, raw errors, or artifacts.

Finally it verifies logout and clears cookies, Web Storage, IndexedDB, Cache
Storage, and service workers. Cleanup failure fails closed. The live config keeps
`preserveOutput: 'never'`, trace/video/screenshot output disabled, and the
reconciliation mode mutually exclusive with screenshot capture. Do not run live
reconciliation as part of this correction; unit tests use synthetic bounded
histories only.

This lane serves the production static build and proxies only `/api/*`, `/auth/*`, `/api/ws`, and the exact `/api/pty` WebSocket upgrade to a disposable local HTTP target. `HERMES_LIVE_TARGET` is accepted only as a plain HTTP loopback URL: canonical IPv4 in `127.0.0.0/8`, `[::1]`, or `localhost`, with an explicit unambiguous decimal port and an optional root slash. Set it from the selected launcher `.result.endpoint` (or an approved tunnel URL whose remote side was selected from that endpoint); do not use a remembered or inferred port. Hermes and its Dashboard stay on the VM loopback interface.

The host rejects HTTPS, userinfo, non-loopback names, IPv4-mapped IPv6, decimal/octal/short IPv4 encodings, percent-encoded or backslash-containing authorities, ambiguous ports, and any path, query, or fragment before creating the proxy-capable server. This validation is the disposable proof boundary; it prevents auth traffic from being sent to a target that URL parsing could reinterpret.

`/api/pty` is an exact `GET` WebSocket route. Its raw query must contain one non-empty opaque `ticket` and one non-empty opaque `resume`, plus an optional non-empty opaque `attach`; unknown, duplicate, missing, encoded, malformed, or overlong keys and values fail closed before an upstream connection. The host forwards the raw upgrade target unchanged and connects the two sockets with bounded stream plumbing. It does not decode, stringify, log, snapshot, or retain PTY frames. Evidence for live checks is limited to method/path, query-key names, bounded lengths, frame counts/lengths/digests, and close codes. `/api/ws` keeps its existing Chat upgrade behavior.

The host is test-only. It is not a deployment server and does not add authentication, retries, transcript storage, or response logging. The live Playwright configuration creates one unique OS-temporary 0700 output root with an owner marker and token, sets `preserveOutput: 'never'`, disables traces, videos, and screenshots, and uses the safe status-only reporter. `tests/live/live-ipc-guard.cjs` is preloaded through `NODE_OPTIONS --require` before worker fixtures or test bodies. `PW_RUNNER_DEBUG` is incompatible with this lane: the live config and credential launcher reject any truthy value before a worker can start because Playwright otherwise inherits worker stderr directly. The guard captures immutable credential variants once at preload and pins `process.send`, never mutates `Object.prototype`, `Array.prototype`, or `testInfo.errors`, and detaches/redacts every worker-to-parent payload, including step, test-end, fatal, attachment, stdio, produced-environment, and response messages. The Node-side policy also captures every primordial it uses before test code runs—including object, reflection, array, string, regular-expression, Set/Map, and Buffer helpers—and invokes those references through captured `Reflect.apply`; the browser-realm DOM scrub remains a separate page-boundary operation. Playwright stdio buffers and attachment bodies are bounded-decoded from base64 and replaced when their bytes contain a captured credential encoding or end in any non-empty prefix of one; this closes split-write reconstruction across parent IPC messages while preserving buffers proven safe. Malformed or oversized binary fields fail closed. Unknown, trapped, or over-budget values are replaced or not forwarded, preventing Playwright's JSON fallback from serializing an unsafe source graph. The configured Playwright project output is a disposable child below the immutable run root because Playwright clears that project directory before a run; each worker adopts the inherited root only after validating its marker and token, so retries and sequential workers cannot create a second root. Per-test finalization validates every lstat/realpath ancestor from that root to the requested output directory and fails closed on a replaceable symlink ancestor before quarantine. Per-test finalization only accepts strict descendants of the owned root and quarantines those child directories; it never removes or recreates the shared root, owner marker, or root-level artifacts. The config routes Playwright's post-teardown `LastRunReporter` to the platform null sink, preventing it from recreating a markerless `.last-run.json` directory after teardown. Global teardown alone removes the complete root through atomic quarantine and bounded known-entry non-recursive `unlink`/`rmdir` operations. It rechecks device/inode identity and the owner marker at each handoff, preserves unrelated replacements and unknown/raced remnants, and never recursively deletes a replaceable pathname. Prefix-collision directories, descendants, unrelated output, and symlink roots are preserved. The live fixture scrubs input, textarea, select, and every editable DOM mode (`true`, empty, and `plaintext-only`) before page close. It builds detached, trusted plain snapshots for known synthetic credentials and serialized form values without mutating source diagnostics. Snapshot arrays retain normal Playwright push/map/iterator behavior and safe own serialization/species behavior. The bounded walk includes non-enumerable native Error message/stack/cause fields, the string `TestInfoError.errorContext`, matcher results, logs, and ARIA snapshots. Descriptor shape and observable read-back are checked, while incomplete, spoofed, stateful, or inconsistent properties, throwing accessors, own `toJSON` hooks, cycles, and over-budget values fail closed without retaining the source graph. Serialized contenteditable markup, raw-text textarea bodies, select/option nesting, and actual `value` attributes are parsed structurally; malformed text, comments, nested or mismatched form markup, unclosed containers, unknown markup, duplicate or ambiguous attributes, unknown editable modes, unquoted `value` attributes, and encoded credentials fail closed instead of allowing a later editable element to be skipped. Attachment references and safe temporary output cleanup run in `finally` even when redaction fails. A scrub evaluator failure is suppressed only when `page.isClosed()` returns `true`; generic error text such as `page crashed` is never treated as proof of termination. These layers are deliberate: a failed live assertion must not leave a password in a trace, screenshot, report, error context, DOM dump, or the repository's retained `test-results` directory. The spec records only HTTP method/path pairs and JSON-RPC method or event names. It never records the WebSocket ticket, credential value, prompt response, cookie, or raw frame payload.

Run the lane only against the authorized disposable VM. From the repository root,
parse the selected launcher result before starting Playwright:

```sh
INSTANCE="${HERMES_INSTANCE:?set the exact launcher instance name}"
# This separate status probe must report .result.status exactly "running".
python3 scripts/hermes_agent.py status --instance "$INSTANCE"
launcher_output="$(python3 scripts/hermes_agent.py endpoint --instance "$INSTANCE")"
endpoint="$(printf '%s' "$launcher_output" | python3 scripts/read_launcher_result.py endpoint)"
credential_file="$(printf '%s' "$launcher_output" | python3 scripts/read_launcher_result.py credential-file)"
HERMES_LIVE_TARGET="$endpoint" \
  python3 scripts/with_live_credential.py "$credential_file" -- \
  bun run --cwd apps/web test:e2e:live
```

A successful `start` result has `.result.status` `ready`; the separate `status`
probe must report `.result.status` exactly as `running` immediately before the
endpoint and credential-file values are used. A stopped, removed, or absent
instance must abort the handoff; retained endpoint metadata is not proof of a
live listener. This status probe is an operator check only, not liveness
enforcement. Issue #345 remains open.
`read_launcher_result.py` parses `.result.endpoint` and `.result.credential_file`
from the launcher output. The handoff strips only trailing CR/LF, validates
exactly 48 lowercase hexadecimal characters, and passes the value only as
transient `HERMES_TEST_PASSWORD` child-process environment state. It never
prints or writes the password, and invalid input fails before Playwright starts.
If the browser runs outside the VM, set `HERMES_LIVE_TARGET` to the approved
local tunnel URL selected from that endpoint; do not hard-code or infer a port.
Do not place the password in a command argument, repository file, fixture,
report, or terminal output. The default Vitest, Playwright, no-network, and
static lanes do not execute this live proof; the live Playwright configuration
is an explicit opt-in.

The implementation supports provider discovery, password login, `/api/auth/me`, session and message reads, one fresh ticket, the native WebSocket upgrade, server-first `gateway.ready`, `session.resume` or fresh `session.create`, one `prompt.submit`, streaming, completion, REST history reconciliation, and no automatic prompt replay. The historical issue-327 material in `tests/integration/hermes-chat` is synthetic-only fixture evidence and is not a live Hermes proof for this change. No live Hermes run, credential handoff, browser capture, or retainable screenshot was performed here, so no live completion, delta, or history result is claimed.

The legacy browser composition has no client-visible PTY attach identity, so its `/api/pty` upgrade sends no `attach` and cannot claim true reattach evidence. The host accepts the optional field for the reviewed future contract but does not invent or persist a handle. True reattach remains blocked until the reviewed client-visible identity work in issue #349.

A visible logout action is not part of the current approved Paper workspace. The live spec still verifies the reviewed same-origin logout boundary as raw `302 Location: /login`, then verifies the follow-up `/api/auth/me` `401`, without inventing an unapproved UI control. Add a visible action to this journey only after the matching Paper state is approved.
