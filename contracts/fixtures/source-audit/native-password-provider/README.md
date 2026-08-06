# Native password-provider cookie and ticket fixtures

**Operation:** C-03 — freeze native password-provider cookie and WebSocket ticket behavior.

**Contract:** `dashboard-v0.0.1`

**Pinned Hermes revision:** `f5be9236e00ddf2f2a412697f267078fc4ee068e`

**Scope:** synthetic, offline protocol evidence only.

This fixture closes the gap between the merged provider-discovery, route-allowlist,
and native-bearer audits. Those artifacts prove that a password route exists and
that `/api/auth/ws-ticket` accepts a reviewed native bearer or browser cookie.
They do not prove the native password-provider cookie lifecycle or a ticket minted
from a native password cookie. This fixture freezes those client obligations
without implementing Apple networking or contacting Hermes.

## Source observations

The pinned source records these facts:

- `BasicAuthProvider` advertises `supports_password: true`, rejects wrong
  credentials generically, and returns a session containing access and refresh
  material. It is password-only; it does not implement an OAuth redirect.
- `POST /auth/password-login` accepts the provider, username, and password,
  returns JSON success on valid credentials, and calls the shared session-cookie
  setter. Invalid credentials, unknown providers, provider failures, and rate
  limits fail with 401, 404, 503, and 429 respectively; failures do not issue a
  session cookie.
- The shared cookie helper writes the access, refresh, and provider-hint cookies
  with `HttpOnly`, `SameSite=Lax`, the deployment `Path`, and `Secure` for HTTPS.
  Direct HTTPS uses `__Host-` names; a non-root prefix uses `__Secure-` names;
  deletion emits `Max-Age=0` for every name variant.
- `POST /api/auth/ws-ticket` requires an authenticated session and mints a
  ticket for that session. The ticket store gives tickets a 30-second lifetime,
  consumes them once, and rejects missing, expired, or reused values. Gated
  WebSocket upgrades accept the ephemeral `?ticket=` value and reject the legacy
  query-token path.

The source audit does **not** claim that Hermes implements an Apple
`URLSession` store. The native isolation rules below are Hermternal client policy
that must be proven by later native implementation work:

- use an app-isolated protected cookie store; never share browser cookies;
- never persist or log the password, cookie contents, refresh material, or ticket;
- use the authenticated native password cookie for reviewed REST calls;
- mint a fresh ticket for each gated WebSocket upgrade and place it only in the
  ephemeral upgrade URL; never send the cookie directly on the WebSocket;
- clear the cookie store on logout or unrecoverable expiry.

## Fixture coverage

`cases.json` covers:

- valid, wrong-password, unknown-provider, provider-unreachable, and rate-limited
  password login outcomes;
- HTTPS cookie names, attributes, path isolation, refresh-cookie lifetime, and
  logout deletion across direct and prefixed deployments;
- native app-isolated cookie storage and no password persistence;
- expired-session recovery and logout cleanup;
- WebSocket ticket minting from a native password cookie;
- missing, malformed, expired, reused, and gated legacy-token ticket failures;
- fresh-ticket retry behavior and the rule that the cookie is not sent directly
  on the gated WebSocket; and
- synthetic redaction and no-retention invariants.

The validator evaluates every row semantically and applies mutation regressions.
It can optionally verify the five pinned source files from a local checkout:

```text
python3 contracts/fixtures/source-audit/native-password-provider/validate.py
python3 contracts/fixtures/source-audit/native-password-provider/validate.py --source-root /path/to/hermes-agent
python3 contracts/fixtures/source-audit/native-password-provider/test_native_password_provider.py
python3 -O contracts/fixtures/source-audit/native-password-provider/test_native_password_provider.py
python3 -m unittest discover -s contracts/fixtures/source-audit/native-password-provider -p 'test_*.py'
python3 -m py_compile contracts/fixtures/source-audit/native-password-provider/validate.py contracts/fixtures/source-audit/native-password-provider/test_native_password_provider.py
```

A Git source root must have `HEAD` equal to the pinned revision and is reported
as `git_checkout_verified`. A source directory without Git metadata is reported
as `content_only_snapshot`; it never claims checkout verification.

## Safety, accessibility, and limits

All case values are synthetic classifications or public repository metadata. No
password, cookie, bearer, refresh token, WebSocket ticket, ticket fragment,
provider data, hostname, transcript, PTY bytes, or user data is present. The
fixture never imports Hermes, opens a socket, contacts a provider, or changes
production authentication.

Paper and accessibility evidence are **N/A** because this is a non-UI source-
audit artifact. No focus order, semantic label, VoiceOver, Switch Control,
Dynamic Type, browser zoom, contrast, motion, transparency, or touch target is
changed. Later web and Apple clients must preserve their existing accessibility
contracts.

The baseline in `source_audit.json` records normal and optimized validator
samples, hashes and sizes for the independent fixture artifacts, and
`threshold: null`. These are self-authored developer observations, not an
authenticated performance gate or live compatibility proof.

This contract does not prove a Hermes process, an Apple implementation, provider
identity, deployment identity, cryptographic signing, live cookie attributes at a
deployed edge, or a successful live WebSocket. It freezes the evidence and the
fail-closed client obligations needed before those later proofs can be attempted.
