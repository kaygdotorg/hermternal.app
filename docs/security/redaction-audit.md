# R-07C / #194 — Redaction audit

## Status and provenance

- **Status:** offline source audit; release decision is **blocked**, not approved.
- **Audit base:** exact `origin/dev` base `c59b5bcdaa1978d6e5c77cccaa31770ce0a82723`.
- **Review mode:** documentation and static source review only. No live service, provider, deployment proxy, credential, or user data was used.
- **Scope boundary:** this document describes controls present at the named base. It does not silently substitute the current worktree, a later fixture-registry commit, or a different deployment checkout.

R-07C is the redaction operation in `docs/product/roadmap.md`. Its listed dependencies are `DEP-12` (access, error, and malformed-message log redaction), R-02 (the pinned disposable integration suite), R-03 (the Caddy release deployment suite), and R-04 (the Traefik release deployment suite). The release gate in `docs/product/implementation-proof-gates.md` requires this audit and its evidence before release promotion.

The controls below are **static controls observed in source**. They are not a claim that the live lane, either deployment proxy, or an external CI runner was executed during this documentation-only task.

## Audit scope

The audit covers the points at which sensitive or user-derived data could enter retained proof:

- Playwright reporters, worker-to-parent output, test errors, exception causes, matcher results, logs, ARIA snapshots, and form diagnostics.
- Attachments, standard output, standard error, temporary output directories, and post-teardown runner metadata.
- Screenshots, traces, and videos, including the distinction between disabled live media and checked-in synthetic visual snapshots.
- Browser authentication and ticket boundaries, including URLs, history, DOM, storage, console observations, and error text.
- REST and WebSocket request or event logging, bounded response parsing, and fixed diagnostics.
- The disposable test proxy's authority and query validation, stream handling, and evidence minimization.
- PTY byte handling, including the rule that opaque bytes are not decoded, copied into application buffers, or logged.
- Synthetic fixture and browser evidence versus actual live Hermes and deployment evidence.

The audit does **not** reproduce or retain concrete runtime hosts, ports, endpoints, credentials, prompt or response bodies, WebSocket frames, DOM or HTML, provider data, raw errors, or unnecessary runtime identifiers from fixtures. Source paths and test names are used as references only.

## Non-retention rule

A value is sensitive when it can authenticate, identify, reconstruct, or disclose a user or provider interaction. This includes passwords, cookies, bearer material, short-lived tickets, URLs with sensitive query values, prompts, responses, transcripts, provider metadata, REST or WebSocket bodies, PTY bytes, form values, DOM snapshots, exception graphs, and raw error text.

The rule for R-07C is:

1. A sensitive value may exist transiently only at the boundary that needs it.
2. It must not enter a retained report, attachment, error, stack, snapshot, URL, browser history, storage, console, test result, proxy log, REST log, WebSocket log, screenshot, trace, video, or repository fixture.
3. Evidence may retain only the smallest structural fact needed to prove the boundary: test name and status, semantic error code, method and route class, message or event name, bounded lengths, counts, digests, close codes, or a Boolean assertion.
4. If a value cannot be inspected safely, the control must fail closed rather than serialize or forward the source object.
5. Cleanup must run in `finally` and must preserve unrelated or replaced paths. A failed scrub is not permission to retain the source artifact.

This is a **non-retention** design. Replacing a value after it has reached an uncontrolled reporter, proxy log, or external service is not equivalent to preventing it from being observed or retained there.

## Evidence taxonomy

| Class | Meaning | Acceptable evidence | What it cannot prove |
| --- | --- | --- | --- |
| **S0 — static control** | Source, configuration, comments, and checked-in test definitions at the audit base. | A bounded parser, safe reporter, disabled media setting, non-observing proxy, or ownership check is present in the reviewed source. | That the exact runner loaded the control, that a deployment used it, or that an external logger behaved safely. |
| **S1 — synthetic execution** | Offline unit, component, browser, or fixture tests using generated or named synthetic values. | Assertions that values are absent from DOM, history, storage, console, errors, attachments, or serialized diagnostics; negative controls and cleanup tests. | Live credentials, live provider data, gateway behavior, deployment logs, or production proxy configuration. |
| **L0 — live metadata** | An authorized live proof run whose output is deliberately reduced. | Status, method and route class, semantic event names, bounded counts and lengths, digests, and close codes with source pin and teardown proof. | The contents of any request, response, prompt, event, frame, or PTY stream. |
| **N0 — negative result** | A failed, incomplete, or blocked proof. | An explicit statement that a claim was not reached, a sanitizer failed closed, or a required artifact was absent. | A green status, a screenshot, or a copied claim that does not include the negative result. |
| **R0 — retained artifact** | A file or external record kept after the run. | Only reviewed, sanitized metadata with ownership and source binding. | Raw test output, media, error context, payloads, credentials, or opaque bytes. Any such artifact is a release blocker. |

A synthetic value is evidence of the synthetic path only. A live value is never required in a repository fixture or in this audit document.

## Verified static controls

### Reporters and test output

- `apps/web/tests/live/safe-reporter.mjs` is intentionally status-only. It emits a redacted test title and status, plus an overall status, and never emits Playwright error details, locator call logs, or DOM snippets.
- `apps/web/playwright.live.config.ts` selects that reporter instead of a standard failure reporter, sets output retention to never preserve, and sends Playwright's post-teardown last-run metadata to the null sink. Runner debug mode is rejected before a credential-bearing worker can start because inherited worker stderr would bypass the guard.
- `apps/web/tests/live/live-ipc-guard.cjs` is preloaded before the worker loads fixtures or test code. It pins the worker-to-parent send boundary so Playwright cannot fall back to serializing an unsafe message graph.
- The static policy test `pins the live config to no media artifacts, no retained output, and safe reporting` checks the configuration shape. `rejects Playwright debug mode before the live worker can start` and `rejects PW_RUNNER_DEBUG before a live worker can start` cover the debug bypass.

### Artifact policy and exception sanitization

- `apps/web/tests/live/live-artifact-policy.mjs` captures the relevant credential variants before test code can mutate them, then uses bounded detached snapshots rather than forwarding the source diagnostic graph.
- The bounded diagnostic walk covers native error message, stack, and cause fields, Playwright error context, matcher results, logs, ARIA snapshots, serialized form values, and known attachment or transport structures.
- Descriptor shape and observable read-back are checked. Accessors that throw, stateful or inconsistent properties, incomplete descriptors, hostile proxies, own `toJSON` hooks, cycles, unknown values, and over-budget graphs fail closed. Captured primordial methods are used instead of mutable test-realm methods.
- `redactTestErrors`, `redactLiveText`, and `redactLiveTransportMessage` are the relevant policy boundaries. `scrubLivePage` handles the browser page boundary before teardown, and `finalizeLiveTest` handles attachment and output cleanup.
- The corresponding tests in `apps/web/src/lib/live-artifact-policy.test.ts` include:
  - `redacts realistic Playwright error contexts, matcher results, and native Error causes`;
  - `structurally redacts textarea and select bodies and fails closed on malformed forms`;
  - `redacts nested serialized contenteditable markup with matching closing tags`;
  - `fails closed for malformed or mismatched serialized editable markup`;
  - `fails closed when malformed text precedes later editable markup, including encoded secrets`;
  - `checks descriptor read-back and fails closed for spoofed or incomplete descriptors`;
  - `detaches stateful Proxy diagnostics and suppresses unsafe toJSON hooks`;
  - `handles cycles and rejects bounded traversal overflow`; and
  - `replaces retained errors with trusted snapshots before cleanup`.

### Worker IPC, standard output, and standard error

- The guard and policy cover step, test-end, fatal, attachment, standard-output, standard-error, produced-environment, and response messages at the actual worker-to-parent boundary. This is earlier than `afterEach`; a later hook cannot be the only redaction point.
- Binary fields are bounded-decoded from base64. Bytes containing a captured credential encoding, or ending in a non-empty credential prefix, are replaced. This addresses a credential split across adjacent worker messages without retaining a concatenated reconstruction.
- Malformed or oversized binary fields, trapped values, unknown message shapes, and over-budget values are replaced or not forwarded. They are not handed to a generic JSON serializer.
- The static tests `protects Playwright worker-mapped IPC errors from inherited serializers`, `protects frozen read-only TestInfo errors at the actual Playwright IPC boundary`, `protects non-configurable hostile Object and Array serializers in a worker`, `protects IPC when Object.create is replaced before a failed step`, `protects step-end IPC emitted before afterEach runs`, `captures immutable credential values before worker test code can delete them`, `redacts binary worker stdio and attachment bodies while preserving safe bytes`, and `redacts every stdout and stderr credential split boundary in the real worker` exercise these cases.

### Attachments and cleanup

- The live lane uses a disposable owned root with an owner marker and token. The configured Playwright directory is a child below that root because Playwright may clear its project directory before a run; the shared root is not recreated by worker or retry cleanup.
- Per-test finalization accepts only strict descendants of the owned root, validates path ancestors, quarantines child output, and refuses replaceable symlink ancestors. Global teardown performs bounded, known-entry, non-recursive cleanup and rechecks ownership and device/inode identity. Unrelated, replaced, unknown, raced, or prefix-collision paths are preserved.
- Attachment references are cleared and safe output cleanup runs in `finally`, including when redaction throws. A generic page-crash string is not accepted as proof that a page has terminated; scrub failure is suppressed only when page termination is observed.
- `apps/web/tests/live/live-artifact-teardown.mjs` owns global teardown. The tests `runs attachment and output cleanup before propagating a redaction failure`, `binds cleanup to the owned inode across an initial replacement race`, `preserves a final tombstone replacement and never calls recursive rm`, `cleans an empty quarantine parent after verification fails closed`, `refuses per-test cleanup through a replaceable symlink ancestor`, `keeps live output outside retained test-results and removes the complete run root`, `preserves one owned run root across two Playwright tests and removes it globally`, and `preserves one run root across a retry and sequential worker tests until global teardown` document the retention and race boundaries.

### Screenshots, traces, and videos

- `apps/web/playwright.live.config.ts` turns screenshots, traces, and videos off for the credential-bearing lane. The no-media setting is part of the retention control, not an assertion that a media sanitizer exists.
- Checked-in visual snapshots used by `apps/web/tests/e2e/live-workspace-visual.spec.ts` are synthetic Paper-aligned presentation evidence. They are not live credential evidence and must not be used to claim that a live screenshot, trace, or video was scrubbed.
- If a future release needs live media, it requires a separate reviewed capture path with byte-level sanitization, ownership, retention, and failure cleanup. Re-enabling media in another config without that proof is a release blocker.

### URLs and browser boundaries

- `apps/web/src/lib/chat/ws-ticket.md` defines the browser ticket as ephemeral. The browser derives upgrade authority from its current origin, does not copy credential or ticket material into client state or errors, and discards the validated lifetime metadata before handing the ticket to the connector.
- `apps/web/src/lib/transport/live-rest-transport.md` requires same-origin requests or an explicitly validated matching origin, no-store behavior, bounded bodies, fatal decoding, duplicate-key rejection, reader cancellation, and fixed diagnostics. Response bodies are not echoed in errors.
- `apps/web/tests/e2e/ws-ticket.browser.spec.ts` contains the tests `real browser acquisition keeps the ticket only in the ephemeral upgrade URL`, `real browser cancellation does not create an upgrade or an automatic retry`, and `real browser retry is explicit and redacts an authentication response`. The tests assert that generated ticket material is absent from the DOM, browser history, storage, console observations, and error text.
- `apps/web/tests/e2e/live-rest-boundary.spec.ts` contains `executes the exported transport in the browser context` and `rejects forbidden origins and API roots before the transport fetcher runs`. These are synthetic browser-boundary tests; they do not prove a deployed origin or proxy.
- `apps/web/tests/live/live-host.mjs` validates the original target string and route/query grammar before opening the proxy. It rejects ambiguous authorities and malformed or duplicate query structure before forwarding. It retains structural key names and bounded lengths only; it does not log complete URLs or opaque query values.

### WebSocket and REST logging

- `apps/web/tests/live/official-hermes.spec.ts` records only HTTP method/path pairs and JSON-RPC method or event names. Its single combined test is `browser UI reaches the official Hermes gateway through completion`; that test retains the reviewed reconciliation and logout proof in one causal journey and is not permission to retain request bodies, response bodies, cookies, provider text, or frame payloads.
- The client-side REST and ticket boundaries use bounded parsing and fixed semantic errors. A non-success body, malformed body, redirect, cancellation, or timeout does not become a raw diagnostic.
- The live host is explicitly test-only and adds no response logging, transcript storage, retries, or authentication layer. A live proof may report that a method or event was observed, but not what it carried.

### Proxy redaction and PTY bytes

The proxy's primary safety property is **non-observation**, not post-hoc redaction:

- `apps/web/tests/live/live-host.mjs` validates the authority and raw query lexically, then forwards only an approved upgrade shape. It does not decode, stringify, snapshot, or retain opaque WebSocket payloads.
- PTY traffic is connected as bounded raw duplex streams. PTY frames are not decoded, copied into an application buffer, or written to a log. The permitted live metadata is limited to route class, query-key names, bounded lengths, frame counts or lengths, digests, and close codes.
- `apps/web/tests/e2e/live-workspace-terminal.spec.ts` is an offline synthetic browser test. It routes its own WebSocket behavior and proves workspace transitions; it does not prove a live PTY stream or authorize retention of PTY bytes.
- The static negative control is important: any proxy or test change that starts parsing, logging, or buffering PTY bytes must be reviewed as a new retention surface, even if a later redactor is added.

## Exact offline commands

Run these commands only from a checkout that contains the audited source tree. They inspect or exercise synthetic/static paths; none starts the credential-bearing live lane or contacts a provider. The base variable is deliberately pinned to the requested commit.

```sh
BASE=c59b5bcdaa1978d6e5c77cccaa31770ce0a82723

git show --no-patch --format='%H%n%P%n%s' "$BASE"
git grep -n -E 'redact|sanitize|attachment|trace|video|screenshot|WebSocket|REST|PTY' "$BASE" -- \
  apps/web/playwright.live.config.ts \
  apps/web/src/lib/live-artifact-policy.test.ts \
  apps/web/src/lib/chat \
  apps/web/src/lib/transport \
  apps/web/tests/e2e \
  apps/web/tests/live
```

Use the repository-pinned toolchain checks before the test commands:

```sh
test "$(bun --version)" = "1.3.14"
test "$(node --version)" = "v26.7.0"
```

Run the redaction and credential-boundary unit tests. These use synthetic values and local mocks:

```sh
bun run --cwd apps/web test -- \
  src/lib/live-artifact-policy.test.ts \
  src/lib/auth-ui/browser-auth-session.test.ts \
  src/lib/auth-ui/browser-auth.test.ts \
  src/lib/chat/ws-ticket.test.ts \
  src/lib/transport/live-rest-transport.test.ts
```

Run the browser-only synthetic boundary tests. The default Playwright configuration may start its local static test host; do not select the live configuration:

```sh
bun run --cwd apps/web test:e2e -- \
  tests/e2e/ws-ticket.browser.spec.ts \
  tests/e2e/live-rest-boundary.spec.ts \
  tests/e2e/live-workspace-terminal.spec.ts
```

Run the broader offline gates:

```sh
bun run --cwd apps/web test:static
bun run --cwd apps/web test:no-network
bun run --cwd apps/web check
bun run --cwd apps/web typecheck
```

These commands are a reproducible offline procedure, not results claimed by this document. The live command is intentionally absent. Do not infer a live result from a passing synthetic lane.

## Evidence limitations

1. Source review proves that the safe reporter, IPC guard, artifact policy, cleanup policy, browser boundaries, and proxy non-observation rules are present at the named base. It does not prove that an external runner used the exact configuration or that a deployment proxy used the test-only policy.
2. Synthetic tests use generated or named synthetic values. They do not exercise a real credential, provider response, deployment access log, reverse-proxy error log, or external artifact collector.
3. The base documentation describes a prior authorized live attempt as incomplete: it did not establish the full completion and history claims. This audit treats that statement as a limitation, not as fresh live evidence, and does not reproduce its runtime details.
4. R-03 and R-04 require separate Caddy and Traefik proof. This audit cannot infer redaction parity from the shared browser policy or from one proxy implementation.
5. `DEP-12` requires evidence for access, error, and malformed-message logging. The local policy prevents many values from reaching the test reporter, but it does not by itself prove what an upstream service, container runtime, reverse proxy, CI collector, or hosting platform retains.
6. Media is disabled in the credential-bearing configuration. That reduces retention risk but leaves no positive proof for sanitizing a permitted live screenshot, trace, or video.
7. PTY non-observation is a source property and a synthetic test boundary. It is not a byte-for-byte review of an external WebSocket implementation or a production observability pipeline.
8. A clean repository and an absent local artifact are negative observations only. They do not establish that an earlier run, alternate output directory, replaced path, or external collector did not retain data.
9. The source pin, fixture digest, runner configuration, and retained evidence must be bound together. A status copied from another commit is not evidence for this base.

## Missing proof

The following items remain open for R-07C:

- [ ] Execute R-02 against the pinned disposable integration environment with source identity, bounded metadata, and teardown evidence.
- [ ] Execute R-03 and R-04 and compare normalized redaction outcomes for both deployment proxies.
- [ ] Produce DEP-12 evidence covering access, error, malformed-message, authentication, REST, WebSocket, and PTY-related logs without retaining payloads.
- [ ] Verify the exact CI or review runner loads the safe reporter, preloads the IPC guard before worker code, rejects debug output, disables media, and routes post-teardown metadata away from retained output.
- [ ] Inspect the complete runner and proxy artifact directories after success, assertion failure, timeout, cancellation, worker crash, process termination, path replacement, and symlink races.
- [ ] Prove that external log collectors and deployment edge logs do not retain full URLs, query values, cookies, tickets, request or response bodies, WebSocket frames, or PTY bytes.
- [ ] If live visual evidence is required, approve and test a separate sanitized media path. The current live lane intentionally provides no live media.
- [ ] Bind every accepted evidence item to the exact audited source commit and record the negative result for every claim that was not reached.

Until these items are complete, R-07C is not complete and R-08/G-15 cannot use this document as a release approval.

## Threat cases and expected outcomes

| Threat case | Required outcome | Control or reference |
| --- | --- | --- |
| A hostile error object uses a getter, proxy, `toJSON`, cycle, mutable serializer, or oversized graph to reveal a secret. | Build a detached bounded snapshot, replace unsafe values, and fail closed without serializing the source graph. | `apps/web/tests/live/live-artifact-policy.mjs`; descriptor, proxy, serializer, cycle, and budget tests in `apps/web/src/lib/live-artifact-policy.test.ts`. |
| A credential is split across adjacent standard-output or standard-error messages. | Detect complete encodings and non-empty prefix suffixes at the binary transport boundary; never forward a reconstructable sequence. | `apps/web/tests/live/live-ipc-guard.cjs`; `redacts every stdout and stderr credential split boundary in the real worker`. |
| Playwright emits an attachment, response, fatal, step, or test-end payload before cleanup hooks run. | Guard the send boundary before test code, detach the payload, bound binary decoding, and replace or drop unsafe fields. | `live-ipc-guard.cjs`; `protects step-end IPC emitted before afterEach runs`; attachment tests. |
| Serialized form markup is malformed before a later editable control. | Reject the serialization rather than skipping the later control; scrub all supported editable modes before page teardown. | `scrubLivePage`; malformed markup and `scrubs every valid editable content mode before page teardown` tests. |
| A scrub fails during page close or teardown. | Run attachment and output cleanup in `finally`; suppress only an observed page-termination case; preserve the redaction failure otherwise. | `finalizeLiveTest`; `runs attachment and output cleanup before propagating a redaction failure`; `fails live scrub errors closed only when page termination is observed`. |
| A worker or teardown replaces the owned output path with a symlink, tombstone, or unrelated directory. | Check ancestry and identity, quarantine only owned descendants, never recursively remove a replaceable path, and preserve unrelated data. | `live-artifact-policy.mjs`, `live-artifact-teardown.mjs`, and the owned-root race tests. |
| A standard reporter or runner debug mode prints locator, DOM, or worker stderr data. | Use the status-only reporter and reject the bypass before worker creation. | `safe-reporter.mjs`, `playwright.live.config.ts`, and the debug-mode tests. |
| URL parsing normalizes an ambiguous authority or query before the proxy validates it. | Validate the original target string and raw query structure first; retain only structural metadata and no opaque values. | `apps/web/tests/live/live-host.mjs` and its README. |
| A REST or WebSocket failure body is copied into an exception or log. | Bound and cancel body reads, project only reviewed fields, and publish a fixed semantic diagnostic or event name. | `browser-auth.md`, `ws-ticket.md`, `live-rest-transport.md`, and `official-hermes.spec.ts`. |
| A proxy or test helper decodes or logs PTY frames. | Keep PTY traffic as opaque bounded duplex bytes and report only structural metadata. | `live-host.mjs`, `tests/live/README.md`, and the synthetic terminal browser test. |
| A synthetic fixture is mistaken for a live provider or deployment result. | Label it S1, keep it provider-free, and require L0 plus R-02/R-03/R-04 evidence for live claims. | `apps/web/README.md`, `apps/web/tests/live/README.md`, and this taxonomy. |

## Release blockers

Release promotion is blocked by any of the following:

- a raw sensitive value appears in a reporter, test result, error, attachment, standard-output or standard-error record, URL, REST or WebSocket log, proxy log, PTY buffer, screenshot, trace, video, or retained directory;
- a redaction or cleanup failure is converted into a green result, or a generic crash message is used as termination proof;
- a runner can bypass the IPC guard, use a standard reporter, inherit debug output, recreate post-teardown metadata, or write outside the owned root;
- a symlink, replacement, race, unknown entry, or ownership mismatch causes cleanup to recurse into an unowned path;
- a proxy records complete URLs, query values, request or response bodies, WebSocket frames, or PTY bytes;
- Caddy and Traefik do not produce equivalent normalized redaction outcomes;
- DEP-12, R-02, R-03, or R-04 evidence is absent, stale, bound to another source commit, or missing its negative result;
- live media is enabled without a reviewed sanitizer and retention proof; or
- synthetic green tests are presented as live proof.

A passing offline test is necessary evidence for the local controls but is not sufficient for R-07C. The release record must link the exact source pin, offline results, live metadata-only results, deployment proxy results, negative results, and final artifact inspection.

## Synthetic versus live: explicit distinction

**Synthetic/offline evidence** includes the unit tests in `apps/web/src/lib/live-artifact-policy.test.ts`, the browser tests in `apps/web/tests/e2e/ws-ticket.browser.spec.ts`, `apps/web/tests/e2e/live-rest-boundary.spec.ts`, and `apps/web/tests/e2e/live-workspace-terminal.spec.ts`, the mock REST and WebSocket fixtures, and the checked-in visual snapshots. These prove local state transitions, parser limits, non-retention assertions, and test-harness behavior. They do not contact Hermes, a provider, a deployment proxy, or a live user session.

**Live evidence** would be produced only by the opt-in lane documented in `apps/web/tests/live/README.md`, using `apps/web/playwright.live.config.ts`, `apps/web/tests/live/live-host.mjs`, `apps/web/tests/live/live-ipc-guard.cjs`, and `apps/web/tests/live/official-hermes.spec.ts`. That lane must use an authorized disposable environment and must retain only metadata. It is not run by this audit. A live attempt that stops before a claimed completion, stream, or history result must report the claim as unproven rather than converting the stop into success.

**Deployment evidence** for R-03 and R-04 is a separate class. Caddy or Traefik logs, edge behavior, upstream logging, and artifact teardown require their own source pin and normalized evidence. No synthetic fixture, browser snapshot, or test-only proxy observation can substitute for that proof.
