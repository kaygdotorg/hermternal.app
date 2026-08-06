# Browser authentication boundary

`browser-auth.ts` implements the reviewed browser-cookie operations for W-04:

- `POST /auth/password-login` with the selected password provider;
- `GET /api/auth/me` as the required identity-verification barrier; and
- `POST /auth/logout`, followed by `GET /api/auth/me` to prove the server session is gone.

The implementation uses relative same-origin paths, `credentials: same-origin`, no-store requests, bounded response bodies, fatal UTF-8 decoding, duplicate-key-rejecting JSON, fixed diagnostics, and explicit cancellation. Password login rejects duplicate actions. Logout coalesces duplicate actions and treats the identity probe—not the redirect response—as the authority for completion.

A password exists only in the transient request input and JSON request body. The boundary does not place passwords, cookies, refresh material, provider response details, or identity tokens in storage, URLs, errors, diagnostics, fixtures, or retained output. Hermes owns the protected session cookies. The browser never reads their values.

Password login success is not enough to enable chat. The exact `GET /api/auth/me` response must pass the existing strict REST identity projection first. A failed or malformed identity probe returns `identity-unverified`. Callers must remain outside the authenticated chat state.

Hermes logout returns a redirect to its login page. The client requests that response with manual redirect handling and then probes `/api/auth/me`. A `401` proves logout. A still-valid identity returns `logout-failed`; an unavailable or malformed probe returns `logout-unverified`. This prevents an ambiguous POST result from being presented as confirmed logout.

The current file is the transport boundary only. UI state wiring, local session-reference clearing, WebSocket shutdown, and the full browser-to-Hermes Playwright journey remain part of the same W-04/web integration stack and must be completed before the feature is merged.
