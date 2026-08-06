# Private deep-link grammar

Status: normative planning contract for Hermternal v1 deep links.

Deep links identify Hermternal content. They do not identify a Hermes HTTP
route, carry authentication material, or create a session. The grammar is
versioned separately from the product release and the Hermes Dashboard
protocol. This document freezes the parse boundary and the synthetic resolver
contract. Runtime resolution and message-result boards remain later work.

The companion synthetic proof is
[`contracts/fixtures/deep-link-grammar/README.md`](../../contracts/fixtures/deep-link-grammar/README.md).
It does not make live calls, install Apple link associations, or implement a
client.

## Canonical grammar

The canonical web form is:

```text
https://<configured-origin>/v1/c/<full-session-id>
https://<configured-origin>/v1/c/<full-session-id>/m/<full-message-id>
```

The native fallback form is:

```text
hermternal://open/v1/c/<full-session-id>
hermternal://open/v1/c/<full-session-id>/m/<full-message-id>
```

The ABNF below describes the exact stable shape. `configured-origin` is one
preconfigured public HTTPS origin, written without a path, query, fragment,
user information, or trailing slash. The spelling is compared exactly; a
parser must not supply a default port or otherwise normalise it.

```abnf
web-link       = "https://" configured-origin "/v1/c/" session-id [ "/m/" message-id ]
native-link    = "hermternal://open/v1/c/" session-id [ "/m/" message-id ]
configured-origin = origin-host [ ":" port ]
origin-host    = 1*( ALPHA / DIGIT / "." / "-" )
port           = 1*5DIGIT
session-id     = id-segment
message-id     = id-segment
id-segment     = 16*unreserved
unreserved     = ALPHA / DIGIT / "-" / "." / "_" / "~"
```

The 16-character floor prevents a display prefix or short local label from
being treated as a full ID. It does not claim a UUID shape or prove server
lineage. IDs remain opaque and must be preserved byte-for-byte for the later
authenticated Dashboard lookup.

The parser MUST:

- accept only the exact lowercase `https://` web spelling and the exact
  configured origin;
- accept only the exact lowercase `hermternal://open` native spelling;
- accept only `/v1/c/<session-id>` with the optional exact `/m/<message-id>`
  suffix;
- accept only ASCII URI `unreserved` ID characters and the full-ID floor;
- preserve the original ID values without decoding, case folding, truncating,
  or normalising them; and
- return a stable, ordered failure reason before any fetch or lookup.

The parser MUST reject all percent escapes, including malformed escapes and
encoded slashes, backslashes, or dot segments. It MUST also reject unencoded
backslashes, C0/C1/DEL controls, all other non-ASCII characters, queries,
fragments, empty segments, a trailing slash, dot traversal, path
normalisation, changed origins, user information, wrong authorities, unknown
versions, wrong path shapes, non-unreserved ID characters, and short or
visibly abbreviated IDs. No invalid link may be accepted as an equivalent
normalised link.

## Stable preflight reasons

A parser reports every applicable reason in this fixed order. The first reason
is the primary diagnostic. A valid link reports no reasons and has an `ok`
primary result.

```text
type
control
non_ascii
percent_escape
backslash
query
fragment
trailing_slash
scheme
authority
origin
version
path
traversal
normalization
segment
id_character
full_id
```

This order is part of the contract. It must not depend on set iteration,
exception text, URL-library normalisation, or platform differences. Lexical
violations are terminal: a resolver must not partially decode or inspect a
candidate after one of those hard rejections.

## Non-reversible diagnostics

Raw links MUST NOT appear in proxy logs, analytics, crash reports,
notifications, clipboard history, OAuth/OIDC return URLs, or user-facing
errors. The proof harness uses semantic-only diagnostics such as:

```text
deep-link[web;session=present;message=present]
deep-link[native;session=present;message=absent]
deep-link[unknown;session=absent;message=absent]
```

These diagnostics omit the configured origin, every ID, query, fragment, and
invalid suffix. They are not hashes, shortened IDs, or reconstructible links.
A diagnostic must never permit a lookup or reveal whether a session exists.

## Resolution contract

The companion synthetic resolver proof is
[`contracts/fixtures/deep-link-resolution/README.md`](../../contracts/fixtures/deep-link-resolution/README.md).
It consumes the frozen grammar and session-lineage artifacts by exact SHA-256
identity. It does not change them. It makes no network call and does not claim
a live Hermes integration.

A resolver MUST process a candidate in this order:

1. Parse the URI without following redirects.
2. Apply the scheme, authority, exact-origin, path, ID, version, and lexical
   rejection rules above.
3. Require an authenticated client session. If authentication is needed, keep
   only the validated target in process memory; never place the raw link in an
   OAuth/OIDC return URL.
4. Resolve the exact full session ID through the authenticated Dashboard
   contract. Hermes remains the source of truth.
5. Open that session. If a valid message ID exists, focus or scroll to it. If
   it does not exist, open the session and show a clear **message not found**
   state.
6. Use the same safe **session not found** or **not available** result for an
   unknown or unauthorized target. Do not reveal another user's IDs.
7. Erase the pending raw link, session ID, message ID, and deadline after
   success, failure, cancellation, expiry, or logout.

A deep link MUST NOT create a session, select another server profile, read a
filesystem or local `~/.hermes` directory, act as a bearer credential, or
follow an external redirect. It MUST NOT create a sharing route or local
transcript mirror. Opening the same valid link twice is idempotent: it targets
the same full IDs and does not duplicate a session, prompt, or message.

A valid target may wait for authentication in process memory for at most 300
seconds. The resolver records the receive time and the exact receive-plus-300
second deadline. The receive time MUST leave room for the 300-second addition
inside the bounded integer range. An overflowing receive time fails closed.
Authentication, lookup, message focus, completion, interruption, recovery,
cancellation, and logout require `now < deadline`.
At exact second 300, every pending path expires before it can act. Success,
failure, cancellation, expiry, and logout erase the raw link and all target IDs.

A direct load and reload use the same steps. Before new resolution, reload MUST
erase the prior opened session ID, root ID, parent ID, focused message ID, and
focus state. Reload MUST then parse the link again, confirm authentication again,
and perform a new exact lookup. A later failure MUST NOT expose the prior success.
Reload MUST NOT reuse erased pending values. An interrupted lookup may recover only before its
recorded deadline. Recovery confirms authentication before an idempotent retry.

A latest-descendant lookup requires explicit bounded lineage ordering evidence.
Each node has an exact session ID, root ID, parent ID, and integer sequence. The
resolver walks parent links and selects one unique descendant with the highest
sequence. Every child sequence MUST be greater than its parent sequence. The
requested root is not its own latest descendant when descendants exist. The
resolver MUST prove the requested node, every supplied node, and every parent
edge against pinned canonical lineage. A parentless or self-rooted known branch
and a fabricated descendant fail closed. A tie, cycle, missing parent, wrong
root, duplicate node, decreasing sequence, or malformed sequence also fails
closed. The resolver MUST NOT use a hard-coded descendant,
rewrite lineage, or infer lineage from display IDs.

Unknown and unauthorized sessions return the same `session_not_found` result.
The result MUST NOT state whether the session exists. A missing message returns
`message_not_found` after the resolved session opens. The client then focuses
the session start or another stable session fallback. It does not create a
replacement session.

## Platform boundary

A same-origin HTTPS link may open the web client. An approved universal-link
association may open the native client first on iOS or iPadOS. The
`hermternal://` form is a native fallback; the web client must not treat it as
an authenticated web redirect. Native scene or window restoration and cold or
suspended launch handling must retain the same opaque IDs. These are platform
requirements for later implementation, not entitlements or registration in
this contract.

User-facing sharing is deferred to v0.0.2. Internal restoration, Spotlight
navigation, and window or scene restoration use this grammar without storing
raw links in shared persistence.

## Proof coverage and limits

The grammar proof covers valid web and native forms, exact origin and
authority checks, opaque full IDs, optional message anchors, stable failures,
and non-reversible diagnostics.

The resolver proof covers authenticated exact lookup, latest-descendant
selection, lineage preservation, authorization-safe session-not-found results,
message focus, message-not-found fallback, pending target cleanup, direct load,
reload, idempotent reopen, interruption, recovery, and empty input. It also
proves zero session creation, zero sharing, zero transcript mirroring, and zero
network use for every synthetic trace.

Both proofs use strict bounded JSON validation. They reject duplicate keys,
non-finite values, overflow, wrong exact types, oversized strings or
containers, excessive nodes, and excessive depth. The bounded walk is iterative.

The resolver proof streams each regular non-symlink artifact once. It enforces
the byte limit before full allocation. It hashes and parses the same immutable
bytes. It rejects a symlink or special file before a blocking open. It also
rejects replacement or metadata changes during a read. An independent review
root binds cases, tests, exact validator source, evidence, baseline,
documentation, and dependencies. Its digest anchor is outside the mutable local
proof set. Cases, baselines, source, and local root copies cannot authorize a
coordinated replacement.

Argument parsing is inside the fixed redaction boundary. Unknown arguments that
contain links or IDs return one fixed JSON error on standard output and no raw
standard-error text. Performance evidence uses inclusive linear interpolation
R-7 and has a null threshold.

The proofs do not authenticate a user, prove ownership, inspect Hermes, call a
network, create universal-link entitlements, or implement web, iOS, iPadOS, or
macOS routing. Runtime clients and result boards remain later platform work.

## Non-UI accessibility evidence

Accessibility verification is **N/A** for this grammar contract because it
renders no UI and changes no focus order, semantic names, touch targets,
VoiceOver, Dynamic Type, contrast, reduced-motion, reduced-transparency, or
Switch Control behavior. This is an explicit boundary, not a waiver. Later
web and Apple implementations must preserve their platform accessibility
contracts while retaining the exact opaque IDs, fail-closed parsing, and
non-reversible diagnostics specified here.
