# Browser OAuth source-audit fixtures

Status: deterministic synthetic proof for issue #199 (`C-02B`).

These fixtures freeze the browser OAuth state and PKCE behavior observed at Hermes revision `f5be9236e00ddf2f2a412697f267078fc4ee068e`. They do not call Hermes, an identity provider, a network service, an Apple API, or a real browser. They contain no credentials, cookies, access tokens, refresh tokens, provider data, hostnames, transcripts, or user data.

## Pinned observations

The audit records these source facts:

- `hermes_cli/dashboard_auth/routes.py:auth_login` calls `start_login`, stores the provider, state, and PKCE verifier in the short-lived `hermes_session_pkce` cookie, and redirects to the provider.
- `hermes_cli/dashboard_auth/routes.py:auth_callback` rejects a missing PKCE cookie, provider cancellation/error, and missing or mismatched callback state. It passes the stored `code_verifier` to `complete_login` and does not issue a session cookie when the provider rejects the code or verifier.
- `plugins/dashboard_auth/nous/__init__.py:NousDashboardAuthProvider.start_login` sends `state`, `code_challenge`, and `code_challenge_method=S256`. Its cookie payload contains `state` and `verifier`; `complete_login` sends `code_verifier` to the token endpoint.
- The pinned browser flow does not expose or require a separate nonce. Hermternal must not invent a nonce requirement for this flow.

Source links are commit-pinned in [`source_audit.json`](source_audit.json); the fixture does not fetch them during validation.

## Fixture cases

[`cases.json`](cases.json) covers exactly these callback outcomes:

- success with matching state and valid PKCE;
- state mismatch;
- missing callback state;
- provider rejection of the code or PKCE verifier;
- provider cancellation; and
- a malformed callback with an empty code.

Failure cases fail closed: no session cookie is issued and the provider exchange is not treated as successful. The source clears the short-lived PKCE cookie on success; rejected callbacks do not create a session and require a fresh login attempt.

## Validation

Run the standard-library test directly from the repository root:

```text
python3 contracts/fixtures/source-audit/oauth-browser/test_oauth_browser.py
```

The test prints the measured fixture-validation duration and JSON artifact size as baseline evidence. These values are observations only; this issue does not define a performance threshold. The test is offline and deterministic apart from the reported wall-clock duration.

This fixture set is source-audit evidence, not production authentication code. Do not add live integration, Apple-specific behavior, `.superdesign/` output, or real provider material here.
