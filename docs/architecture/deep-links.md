# Deep-link specification

Status: normative planning specification.

Deep links identify Hermternal content. They do not identify a Hermes HTTP route. The link grammar is versioned separately from the product release and the Hermes Dashboard protocol. These rules apply to web, iOS, iPadOS, and macOS.

These documents and their disposable proofs are not production credentials, production configuration, or a live link service.

## Canonical grammar

The canonical web content form is:

```text
https://<configured-origin>/v1/c/<full-session-id>[/m/<message-id>]
```

The native fallback form is:

```text
hermternal://open/v1/c/<full-session-id>[/m/<message-id>]
```

The following ABNF describes the stable shape. `origin` is the configured public HTTPS origin without a path, query, fragment, user information, or trailing slash.

```abnf
web-link     = "https://" origin "/v1/c/" session-id [ "/m/" message-id ]
native-link  = "hermternal://open/v1/c/" session-id [ "/m/" message-id ]
origin       = configured-origin
session-id   = id-segment
message-id   = id-segment
id-segment   = 1*unreserved
```

The resolver MUST apply these rules:

- `v1` is the deep-link grammar version. It is not a Hermes protocol version and is not inferred from the Dashboard.
- `session-id` and `message-id` are full, stable IDs. A short ID, display name, prefix, local array index, or compression-lineage suffix is invalid.
- Each ID occupies one path segment and uses only URI `unreserved` characters. Encoded or unencoded slashes, encoded or unencoded backslashes, encoded dot segments, control characters, malformed percent escapes, empty segments, queries, and fragments are invalid.
- The canonical form has no trailing slash. A resolver MAY accept a clearly equivalent trailing slash only to show an invalid-link result; it MUST NOT silently create a different target.
- The resolver MUST preserve the ID value used for the authenticated lookup. It MUST not case-fold, truncate, or normalise an opaque ID.
- The web form MUST use the configured HTTPS origin. An arbitrary origin is not a valid Hermternal content link.
- The native form MUST use the exact `hermternal` scheme and `open` authority. Other custom schemes or authorities are invalid.

The exact Dashboard route used to resolve a session or message is owned by [`contracts/hermes-dashboard/manifest.md`](../../contracts/hermes-dashboard/manifest.md). This document does not invent a route name for that lookup.

## Link resolution

A resolver MUST process a link in this order:

1. Parse the URI without following redirects.
2. Check the scheme, authority, configured origin, path grammar, and ID segments.
3. Check the deep-link grammar version. An unknown version is blocked. The resolver does not guess a newer or older grammar.
4. Require an authenticated client session. If authentication is needed, keep only the validated link in process memory while the approved authentication flow runs. Do not put the raw link into an OAuth or OIDC return URL.
5. Resolve the full session ID through the authenticated Dashboard contract. Hermes remains the source of truth.
6. Open the session. If `message-id` is present and exists, focus or scroll to that message. If it does not exist, open the session and show a clear **message not found** state.
7. If the session does not exist or the user is not allowed to access it, show a clear **session not found** or **not available** state. Do not reveal whether another user owns the ID.
8. Remove the pending link from memory after success, failure, cancellation, or logout.

A link MUST NOT cause a session to be created. A link MUST NOT select a different server profile. A link MUST NOT read the filesystem or a local `~/.hermes` directory.

The resolver MUST be idempotent. Opening the same link twice targets the same full IDs and does not duplicate a session, prompt, or message.

## Platform behavior

- A same-origin HTTPS link MAY open the web client. On iOS and iPadOS, an approved universal-link association MAY open the native client first.
- The `hermternal://` form is a native fallback. The web client MUST NOT treat it as an authenticated web redirect.
- iOS, iPadOS, and macOS MUST use the system link association and native scene or window restoration. They MUST retain the same full IDs.
- If native association is unavailable, the HTTPS form remains the portable form. It MUST still pass origin, grammar, authentication, and access checks.
- Deep-link handling MUST remain available after a cold launch and after a suspended scene resumes.

## Privacy and security rules

Deep links can reveal access patterns even when the IDs are opaque. The clients and proof harness MUST apply these rules:

- Never put passwords, username/password provider credentials, access tokens, refresh tokens, cookies, WebSocket tickets, provider state, provider nonce values, or transcript text in a link.
- Never put a raw deep link in proxy logs, analytics, crash reports, notification text, clipboard history, or an error URL. Redact IDs when a diagnostic record needs to identify a case.
- Do not accept an arbitrary `return_to`, redirect, or origin from a link. Authentication returns to the validated in-process target only.
- Do not fetch a link before validating the origin and grammar. Do not follow an external redirect as part of resolution.
- Do not expose the existence of a session or message to an unauthorised caller. Use the same safe not-available result for unknown and unauthorised targets.
- Do not use a link as a bearer credential. Access remains controlled by the current Dashboard session.
- Keep a pending link in process memory where possible. If the app terminates, discard the pending link rather than writing a secret-bearing or access-sensitive link to shared storage.
- User-facing sharing is deferred to v0.0.2. Internal restoration, Spotlight navigation, and window or scene restoration still use this grammar.

## Required proof cases

The web, iOS, iPadOS, and macOS test suites MUST cover the same cases:

- valid session link with and without a message ID;
- cold launch, warm launch, suspended scene, and duplicate open;
- invalid scheme, authority, origin, version, segment, percent escape, query, fragment, and trailing form;
- unknown deep-link version, unknown session, missing message, and unauthorised target;
- authentication interruption, cancellation, expiry, and logout while a link is pending;
- no duplicate session or prompt creation;
- no secret, transcript, or full-link value in captured logs;
- web HTTPS resolution and native custom-scheme fallback;
- the same full IDs and safe error states on web and Apple platforms.

This file is a specification and a disposable-proof contract. It does not create a universal-link entitlement, a production association file, a custom-scheme registration, or a live credential.
