# Official Hermes browser proof

This lane serves the production static build and proxies only `/api/*`, `/auth/*`, `/api/ws`, and the exact `/api/pty` WebSocket upgrade to a disposable local HTTP target. `HERMES_LIVE_TARGET` is accepted only as a plain HTTP loopback URL: canonical IPv4 in `127.0.0.0/8`, `[::1]`, or `localhost`, with an explicit unambiguous decimal port and an optional root slash. Set it from the selected launcher `.result.endpoint` (or an approved tunnel URL whose remote side was selected from that endpoint); do not use a remembered or inferred port. Hermes and its Dashboard stay on the VM loopback interface.

The host rejects HTTPS, userinfo, non-loopback names, IPv4-mapped IPv6, decimal/octal/short IPv4 encodings, percent-encoded or backslash-containing authorities, ambiguous ports, and any path, query, or fragment before creating the proxy-capable server. This validation is the disposable proof boundary; it prevents auth traffic from being sent to a target that URL parsing could reinterpret.

`/api/pty` is an exact `GET` WebSocket route. Its raw query must contain one non-empty opaque `ticket` and one non-empty opaque `resume`, plus an optional non-empty opaque `attach`; unknown, duplicate, missing, encoded, malformed, or overlong keys and values fail closed before an upstream connection. The host forwards the raw upgrade target unchanged and connects the two sockets with bounded stream plumbing. It does not decode, stringify, log, snapshot, or retain PTY frames. Evidence for live checks is limited to method/path, query-key names, bounded lengths, frame counts/lengths/digests, and close codes. `/api/ws` keeps its existing Chat upgrade behavior.

The host is test-only. It is not a deployment server and does not add authentication, retries, transcript storage, or response logging. The live Playwright configuration creates one unique OS-temporary 0700 output root with an owner marker and token, sets `preserveOutput: 'never'`, disables traces, videos, automatic screenshots, and uses the safe status-only reporter. The only screenshot path is the explicit issue #353 capture helper after completion and REST reconciliation. It first writes raw pixels inside the owned temporary root, requires a separate scrub hook to create a new PNG, requires an independent human-visual review hook to approve that exact SHA-256, rejects ancillary PNG metadata, and only then publishes the approved 1440×960 and 390×844 files with their closed public manifest. `tests/live/live-ipc-guard.cjs` is preloaded through `NODE_OPTIONS --require` before worker fixtures or test bodies. `PW_RUNNER_DEBUG` is incompatible with this lane: the live config and credential launcher reject any truthy value before a worker can start because Playwright otherwise inherits worker stderr directly. The guard captures immutable credential variants once at preload and pins `process.send`, never mutates `Object.prototype`, `Array.prototype`, or `testInfo.errors`, and detaches/redacts every worker-to-parent payload, including step, test-end, fatal, attachment, stdio, produced-environment, and response messages. The Node-side policy also captures every primordial it uses before test code runs—including object, reflection, array, string, regular-expression, Set/Map, and Buffer helpers—and invokes those references through captured `Reflect.apply`; the browser-realm DOM scrub remains a separate page-boundary operation. Playwright stdio buffers and attachment bodies are bounded-decoded from base64 and replaced when their bytes contain a captured credential encoding or end in any non-empty prefix of one; this closes split-write reconstruction across parent IPC messages while preserving buffers proven safe. Malformed or oversized binary fields fail closed. Unknown, trapped, or over-budget values are replaced or not forwarded, preventing Playwright's JSON fallback from serializing an unsafe source graph. The configured Playwright project output is a disposable child below the immutable run root because Playwright clears that project directory before a run; each worker adopts the inherited root only after validating its marker and token, so retries and sequential workers cannot create a second root. Per-test finalization validates every lstat/realpath ancestor from that root to the requested output directory and fails closed on a replaceable symlink ancestor before quarantine. Per-test finalization only accepts strict descendants of the owned root and quarantines those child directories; it never removes or recreates the shared root, owner marker, or root-level artifacts. The config routes Playwright's post-teardown `LastRunReporter` to `/dev/null`, preventing it from recreating a markerless `.last-run.json` directory after teardown. Global teardown alone removes the complete root through atomic quarantine and bounded known-entry non-recursive `unlink`/`rmdir` operations. It rechecks device/inode identity and the owner marker at each handoff, preserves unrelated replacements and unknown/raced remnants, and never recursively deletes a replaceable pathname. Prefix-collision directories, descendants, unrelated output, and symlink roots are preserved. The live fixture scrubs input, textarea, select, and every editable DOM mode (`true`, empty, and `plaintext-only`) before page close. It builds detached, trusted plain snapshots for known synthetic credentials and serialized form values without mutating source diagnostics. Snapshot arrays retain normal Playwright push/map/iterator behavior and safe own serialization/species behavior. The bounded walk includes non-enumerable native Error message/stack/cause fields, the string `TestInfoError.errorContext`, matcher results, logs, and ARIA snapshots. Descriptor shape and observable read-back are checked, while incomplete, spoofed, stateful, or inconsistent properties, throwing accessors, own `toJSON` hooks, cycles, and over-budget values fail closed without retaining the source graph. Serialized contenteditable markup, raw-text textarea bodies, select/option nesting, and actual `value` attributes are parsed structurally; malformed text, comments, nested or mismatched form markup, unclosed containers, unknown markup, duplicate or ambiguous attributes, unknown editable modes, unquoted `value` attributes, and encoded credentials fail closed instead of allowing a later editable element to be skipped. Attachment references and safe temporary output cleanup run in `finally` even when redaction fails. A scrub evaluator failure is suppressed only when `page.isClosed()` returns `true`; generic error text such as `page crashed` is never treated as proof of termination. These layers are deliberate: a failed live assertion must not leave a password in a trace, screenshot, report, error context, DOM dump, or the repository's retained `test-results` directory. The spec records only HTTP method/path pairs and JSON-RPC method or event names. It never records the WebSocket ticket, credential value, prompt response, cookie, or raw frame payload.

The marker, launcher-result, and credential-handoff checks described here are
synthetic and mock-only when run offline. They use synthetic credential bytes,
local private files, fake Podman responses, and mocked process boundaries; they
do not start Hermes, contact a Dashboard, or read a real credential. The live
journey below is a separate explicit opt-in against the authorized disposable
VM.

Run the lane only against the authorized disposable VM. From the repository root,
create one existing private `0700` runs directory and provide one exact
canonical absolute marker path inside it. The launcher derives the live
credential, state, and private engine cidfile as siblings of that marker; `--credential-root` is a
legacy compatibility option and does not control live credential placement.
The launcher accepts container identity only from the private engine-emitted
cidfile read through the same held runs-directory descriptor; missing, malformed,
replaced, or foreign cidfiles fail closed and never fall back to detached stdout.
Each launcher operation captures the private runs-directory device, inode, and
`0700` mode at entry and revalidates that the exact marker pathname still names
that held directory around engine boundaries. Marker/state serialization is
capped before publication, and fixed cleanup/replacement quarantine slots are
bounded to 48 entries and 131,072 aggregate bytes; occupied or raced slots are
retained rather than deleted or replaced; quota exhaustion retains
`cleanup_failed` evidence through the already-owned marker/state descriptors.
The marker path is proof input. Parse that exact caller-selected marker result
before starting Playwright; never enumerate runs, copy a marker, infer recency,
or reuse a port:

```sh
RUNS_DIR="${HERMES_RUNS_DIR:?set an existing private 0700 runs directory}"
MARKER_PATH="${HERMES_MARKER_PATH:?set the exact absolute marker path under that directory}"
INSTANCE="${HERMES_INSTANCE:?set the exact launcher instance name}"
# This fail-closed selection gate freshly proves the immutable launcher
# container ID is running and owns the one explicit loopback Dashboard port.
launcher_output="$(python3 scripts/hermes_agent.py endpoint --marker "$MARKER_PATH")"
# Command substitution strips trailing LFs; restore exactly one for canonical parsing.
endpoint="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py endpoint)"
marker_path="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py marker-path)"
run_id="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py run-id)"
credential_file="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py credential-file)"
credential_identity="$(printf '%s\n' "$launcher_output" | python3 scripts/read_launcher_result.py credential-identity)"
HERMES_LIVE_TARGET="$endpoint" \
  python3 scripts/with_live_credential.py \
    --marker "$marker_path" \
    --run-id "$run_id" \
    --credential-file "$credential_file" \
    --credential-identity "$credential_identity" \
    -- \
    bun run --cwd apps/web test:e2e:live
```

A successful `start` result has `.result.status` `ready`; it is not a handoff
permit. Immediately before credential handoff, `endpoint` re-inspects the
persisted immutable launcher container ID, requires `running`, requires the
sole `127.0.0.1:<requested-port>:9119` mapping, and revalidates the
caller-selected marker plus credential inode, mode, size, link count, and
content generation. A stopped tombstone, missing or stale mapping, replacement,
launcher-ownership mismatch, rebound port, non-loopback publication, or changed
credential identity aborts before the credential file is read.
`read_launcher_result.py` accepts only the closed successful `endpoint` result
with `.result.status` `running` and exposes exactly five selectable fields:
`endpoint`, `marker-path`, `run-id`, `credential-file`, and
`credential-identity`. It never selects a run, reads a marker, infers a port,
or substitutes retained metadata. `run-id` is 64 lowercase hexadecimal
characters. `credential-identity` is compact JSON containing `device`, `inode`,
`mode`, `size`, `nlink`, and a 64-character lowercase hexadecimal `generation`.
The generation is a one-way SHA-256 of the bounded credential bytes, not the
credential value; it detects same-inode, same-size replacement.
`with_live_credential.py` requires the exact marker path, matching `run_id`,
matching credential path, and matching generation-bearing identity before
opening the credential. It revalidates the private parent and marker identity,
then reads through a pinned non-following non-blocking descriptor, strips only
trailing CR/LF, validates exactly 48 lowercase hexadecimal characters, and
passes the value only as transient `HERMES_TEST_PASSWORD` child-process
environment state. It never prints or writes the password, and invalid,
legacy identity-without-generation, or replaced input fails before Playwright
starts.
If the browser runs outside the VM, set `HERMES_LIVE_TARGET` to the approved
local tunnel URL selected from that endpoint; do not hard-code or infer a port.
Do not place the password in a command argument, repository file, fixture,
report, or terminal output. The default Vitest, Playwright, no-network, and
static lanes do not execute this live proof; the live Playwright configuration
is an explicit opt-in.

Marker publication is a copy/evidence protocol, not a race-free publication
claim. The writer stages bounded bytes on a held descriptor, then uses Darwin
`fclonefileat` on APFS when available; the fallback uses a direct destination
`O_EXCL` create and copy from that held descriptor. It syncs the complete bytes,
uses a short mode-`000` gate, changes the destination to `0600`, syncs again,
and reopens only for detection-only identity/content comparison. A destination
pathname can still be raced by a non-cooperating process; held descriptors,
exact identities, no-follow opens, and bounded quarantine preserve evidence or
fail closed, but they do not make the pathname race-free.

Normal launcher marker creation and cleanup publication use a new destination
inode. Existing marker, state, and credential entries are claimed into fixed
no-replace quarantine evidence; the launcher never unlinks a caller-selected
name by pathname alone, overwrites a replacement, or adopts a raced inode. Only
when the bounded quarantine quota is exhausted may cleanup use a held-descriptor
same-inode rewrite for its already-owned marker/state fallback. That fallback
also fails closed on replacement and never turns a foreign pathname into proof.

The private `0700` runs directory is the cooperating-process boundary, not a
privileged isolation boundary. It limits ordinary access by other users; it
does not make a same-user or privileged pathname writer harmless. Readers that
hit the transient mode-`000` marker, an incomplete copy, or a permission/open
error fail closed as invalid (`marker_invalid` or the operation-specific
credential/state error). They do not retry by scanning, infer a different run,
or treat the transient entry as proof; rerun the exact caller-selected
`endpoint` operation after publication settles.

Screenshot retention additionally requires two executable, absolute-path hooks:
`HERMES_SCREENSHOT_SCRUB_HOOK` receives raw and output PNG paths, while
`HERMES_SCREENSHOT_REVIEW_HOOK` receives the scrubbed PNG and a review-record
path. The latter must write the closed
`hermternal.independent-image-review.v1` approval for that exact image hash and
must represent an independent human visual review. Hook output is suppressed;
raw and rejected images remain in the disposable root and are removed. The
published `capture-manifest.json` pins `/`, Chromium, CSS viewport, DPR 1,
zoom 1, light appearance, reduced motion, `en-US`, UTC, the stable capture
state, exact client commit, official Hermes image digest, command, issue, hook
hashes, and image hashes. The narrow image is retained only if its independent
review also approves it; otherwise the whole publication fails closed.

The implementation supports provider discovery, password login, `/api/auth/me`, session and message reads, one fresh ticket, the native WebSocket upgrade, server-first `gateway.ready`, `session.resume` or fresh `session.create`, one `prompt.submit`, streaming, completion, REST history reconciliation, and no automatic prompt replay. The executed authorized live proof reached authentication, ticket acquisition, `/api/ws`, `gateway.ready`, session restoration/creation, and `prompt.submit`. The disposable instance had no authenticated inference provider, so it stopped at the source `error` event before `message.delta`/`message.complete`; REST history reconciliation is therefore unproven. These live claims are not mocked, and no completion, delta, or history result is claimed. A source `error` event is recorded only by event name and never retains its payload.

The legacy browser composition has no client-visible PTY attach identity, so its `/api/pty` upgrade sends no `attach` and cannot claim true reattach evidence. The host accepts the optional field for the reviewed future contract but does not invent or persist a handle. True reattach remains blocked until the reviewed client-visible identity work in issue #349.

A visible logout action is not part of the current approved Paper workspace. The live spec still verifies the reviewed same-origin logout boundary as raw `302 Location: /login`, then verifies the follow-up `/api/auth/me` `401`, without inventing an unapproved UI control. Add a visible action to this journey only after the matching Paper state is approved.
