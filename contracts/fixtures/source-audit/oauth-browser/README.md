# Browser OAuth source-audit fixtures

Status: deterministic synthetic proof for issue #199 (`C-02B`).

These fixtures freeze the browser OAuth state and PKCE behavior observed at Hermes revision `f5be9236e00ddf2f2a412697f267078fc4ee068e`. They do not call Hermes, an identity provider, a network service, an Apple API, or a real browser. The cases use synthetic cookie-shaped values and the audit records public commit-pinned GitHub source URLs; neither is live authentication material.

The fixtures contain no live credentials, access tokens, refresh tokens, cookie contents, deployment host data, provider data, transcripts, or user data.

## Pinned observations

The audit records typed source observations for the pinned revision:

- `hermes_cli/dashboard_auth/routes.py:auth_login` short-circuits a provider with `supports_password: true` before calling `start_login`. PKCE therefore applies to the reviewed OAuth or OIDC browser path, not to the pinned `BasicAuthProvider` password form.
- `hermes_cli/dashboard_auth/routes.py:auth_callback` rejects a missing PKCE cookie, provider cancellation/error, and missing or mismatched callback state. It passes the stored verifier to `complete_login` and issues session cookies only after the provider exchange succeeds.
- `plugins/dashboard_auth/nous/__init__.py:NousDashboardAuthProvider.start_login` builds a nested authorization parameter map containing `state`, `code_challenge`, and `code_challenge_method=S256`. Its cookie payload contains `state` and `verifier`; `complete_login` sends `code_verifier` to the token endpoint.
- The pinned Nous browser flow does not include an OAuth/OIDC `nonce` authorization parameter. This no-nonce statement is scoped to the pinned Nous flow. A separately reviewed OIDC provider MAY require and validate nonce when its compatibility record says so.
- `hermes_cli/dashboard_auth/cookies.py` calls the state value a CSRF nonce in a source comment. That label is not a provider `nonce` parameter and does not expand the pinned Nous browser contract.

The source observations are checked against the supplied immutable excerpts in [`source_excerpts/`](source_excerpts/) and their commit-pinned SHA-256 values. The validator does not treat `source_audit.json` metadata alone as source evidence.

## Fixture cases

[`cases.json`](cases.json) covers exactly these callback outcomes for a reviewed OAuth browser provider:

- success with matching callback state, matching outbound authorization state, and valid PKCE;
- state mismatch;
- missing callback state;
- provider rejection of the code or PKCE verifier;
- provider cancellation; and
- a malformed callback with an empty code.

The authorization parameters are nested under `authorization_request.params` to mirror the provider's outbound query map. The provider exchange records the exact `code_verifier` passed by the callback route. Mutation regressions reject a wrong nested state, a wrong exchange verifier, a nested nonce, or a false source observation.

Failure cases fail closed: no session cookie is issued and the provider exchange is not treated as successful. The source clears the short-lived PKCE cookie on success; rejected callbacks do not create a session and require a fresh login attempt.

## Validation

Run the standard-library test directly from the repository root:

```text
python3 contracts/fixtures/source-audit/oauth-browser/test_oauth_browser.py
```

The test prints the measured fixture-validation duration and JSON artifact size as baseline evidence. These values are observations only; this issue does not define a performance threshold. The test is offline and deterministic apart from the reported wall-clock duration.

This fixture set is source-audit evidence, not production authentication code. Do not add live integration, Apple-specific behavior, `.superdesign/` output, or real provider material here.
