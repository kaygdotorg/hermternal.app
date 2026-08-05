# Private deep-link grammar

Status: normative planning contract for Hermternal v1 deep links.

Deep links identify Hermternal content. They do not identify a Hermes HTTP
route, carry authentication material, or create a session. The grammar is
versioned separately from the product release and the Hermes Dashboard
protocol. This document freezes the parse boundary only; resolution, access
results, lineage, and message-result boards belong to dependent contract work.

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

## Resolution boundary

A later resolver MUST process a candidate in this order:

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
   unknown or unauthorised target. Do not reveal another user's IDs.
7. Remove the pending target from memory after success, failure, cancellation,
   expiry, or logout.

A deep link MUST NOT create a session, select another server profile, read a
filesystem or local `~/.hermes` directory, act as a bearer credential, or
follow an external redirect. Opening the same valid link twice is idempotent:
it targets the same full IDs and does not duplicate a session, prompt, or
message.

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

The synthetic fixture proof covers valid web/native session links, optional
message anchors, exact origin and authority checks, wrong schemes and
versions, wrong paths, traversal and normalisation, trailing forms, empty and
short IDs, all lexical rejection classes, stable reason order, strict
recursive JSON shape, mutation regressions, and non-reversible diagnostics.

It does not resolve a session, test authentication, prove ownership, inspect
Hermes, call a network, create universal-link entitlements, implement iOS,
iPadOS, or macOS routing, or define unknown-session/message result boards.
Those behaviors require the approved downstream fixtures and platform work.

## Non-UI accessibility evidence

Accessibility verification is **N/A** for this grammar contract because it
renders no UI and changes no focus order, semantic names, touch targets,
VoiceOver, Dynamic Type, contrast, reduced-motion, reduced-transparency, or
Switch Control behavior. This is an explicit boundary, not a waiver. Later
web and Apple implementations must preserve their platform accessibility
contracts while retaining the exact opaque IDs, fail-closed parsing, and
non-reversible diagnostics specified here.
