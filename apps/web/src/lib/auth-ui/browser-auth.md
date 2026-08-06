# Browser authentication boundary

`browser-auth.ts` implements the reviewed browser-cookie operations for W-04:

- `POST /auth/password-login` with the selected password provider;
- `GET /api/auth/me` as the required identity-verification barrier; and
- `POST /auth/logout`, followed by `GET /api/auth/me` to prove the server session is gone.

The implementation uses relative same-origin paths, `credentials: same-origin`, no-store requests, bounded response bodies, fatal UTF-8 decoding, duplicate-key-rejecting JSON, fixed diagnostics, and explicit cancellation. Password login rejects duplicate actions. Logout coalesces duplicate actions and treats the identity probe—not the redirect response—as the authority for completion.

A password exists only in the transient request input and JSON request body. The boundary does not place passwords, cookies, refresh material, provider response details, or identity tokens in storage, URLs, errors, diagnostics, fixtures, or retained output. Hermes owns the protected session cookies. The browser never reads their values.

Password login success is not enough to enable chat. The exact `GET /api/auth/me` response must pass the existing strict REST identity projection first. A failed or malformed identity probe returns `identity-unverified`. Callers must remain outside the authenticated chat state.

Hermes logout returns a redirect to its login page. The client requests that response with manual redirect handling and then probes `/api/auth/me`. A `401` proves logout. A still-valid identity returns `logout-failed`; an unavailable or malformed probe returns `logout-unverified`. This prevents an ambiguous POST result from being presented as confirmed logout.

`browser-auth-session.ts` coordinates this boundary with the reviewed authentication state model. It verifies identity before provider discovery, rejects stale async completions by generation, suppresses duplicate password submission, and never copies a username or password into its observable snapshot. Logout and expiry call the supplied local invalidation hook before publishing any later state. The application uses that hook to close the active WebSocket and clear client-side session references.

`BrowserAuthView.svelte` binds the lifecycle to the reviewed authentication presentation. It starts with the identity barrier, then exposes password providers only after unauthenticated provider discovery succeeds. Live username and password values travel through a dedicated transient callback, bypass the credential-free `AuthAction` channel, and are removed from the DOM form immediately after submission. The view publishes authenticated content only after the session owns a verified identity, and renders only fixed local error messages and codes.

The normal product route, logout control, live workspace transport, and full browser-to-Hermes Playwright journey remain part of the same W-04/web integration stack. The product route must preserve the existing deterministic no-network fixture lane rather than weakening that proof. A visible logout control must first have a matching approved Paper state.
